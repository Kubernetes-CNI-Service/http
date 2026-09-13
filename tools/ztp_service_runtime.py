#!/usr/bin/env python3
"""Plan scoped ZTP service listeners and select an explicit service backend.

The planner is deliberately side-effect free.  It consumes one coherent pair
of ``ip -j link``/``ip -j -4 address`` snapshots and existing DHCP subnet CSV
data, then returns the exact logical interfaces which a caller may pass to
ISC DHCP.  Linux interface identity is the current-boot ifindex; names are
retained only because dhcpd's command-line interface accepts names.
"""

import csv
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import tempfile
import time
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence, Tuple


RUNTIME_BACKEND_ENV = "HTTP_ZTP_RUNTIME_BACKEND"
SUPPORTED_BACKENDS = frozenset({"systemd", "supervisor"})
SAFE_INTERFACE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
DEFAULT_SUPERVISOR_DHCP_LOG = Path("/var/log/http-ztp/dhcpd.log")
DEFAULT_SUPERVISOR_DHCP_PID = Path("/run/http-ztp/dhcpd.pid")
DEFAULT_SUPERVISOR_LOG_BYTES = 1024 * 1024
MAX_SUPERVISOR_LOG_BYTES = 20 * 1024 * 1024
REQUIRED_SUBNET_COLUMNS = frozenset({
    "shared_network", "subnet", "netmask", "ztp_service_ip",
    "cumulus_profile", "nvos_ztp",
})


class RuntimeContractError(RuntimeError):
    """A runtime selection is unsafe, ambiguous, or unsupported."""


@contextmanager
def monitor_pid_lock(pid_file: Path):
    """Hold the persistent private lock shared by supported monitor writers."""
    lock_file = pid_file.with_name(f".{pid_file.name}.lock")
    descriptor = -1
    created = False
    entered = False
    base_flags = (
        os.O_RDWR
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        try:
            descriptor = os.open(
                lock_file, base_flags | os.O_CREAT | os.O_EXCL, 0o600,
            )
            created = True
        except FileExistsError:
            descriptor = os.open(lock_file, base_flags)
        if created:
            os.fchmod(descriptor, 0o600)
        held = os.fstat(descriptor)
        named = lock_file.lstat()
        expected = (held.st_dev, held.st_ino)
        if (
            not stat.S_ISREG(held.st_mode)
            or held.st_nlink != 1
            or held.st_uid != os.geteuid()
            or stat.S_IMODE(held.st_mode) != 0o600
            or not stat.S_ISREG(named.st_mode)
            or named.st_nlink != 1
            or named.st_uid != os.geteuid()
            or stat.S_IMODE(named.st_mode) != 0o600
            or (named.st_dev, named.st_ino) != expected
        ):
            raise RuntimeContractError(
                f"unsafe ZTP monitor PID lock authority: {lock_file}"
            )
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        held_after = os.fstat(descriptor)
        named_after = lock_file.lstat()
        if (
            (held_after.st_dev, held_after.st_ino) != expected
            or not stat.S_ISREG(held_after.st_mode)
            or held_after.st_nlink != 1
            or held_after.st_uid != os.geteuid()
            or stat.S_IMODE(held_after.st_mode) != 0o600
            or (named_after.st_dev, named_after.st_ino) != expected
            or not stat.S_ISREG(named_after.st_mode)
            or named_after.st_nlink != 1
            or named_after.st_uid != os.geteuid()
            or stat.S_IMODE(named_after.st_mode) != 0o600
        ):
            raise RuntimeContractError(
                f"ZTP monitor PID lock identity changed: {lock_file}"
            )
        entered = True
        yield
    except OSError as exc:
        if entered:
            raise
        raise RuntimeContractError(
            f"cannot acquire ZTP monitor PID lock {lock_file}: {exc}"
        ) from exc
    finally:
        if descriptor >= 0:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(descriptor)


def write_monitor_pid_record_locked(pid_file: Path, pid: int) -> None:
    """Atomically publish one PID while the caller holds monitor_pid_lock."""
    payload = f"{int(pid)}\n".encode("ascii")
    previous: bytes | None = None
    if pid_file.exists() or pid_file.is_symlink():
        before = pid_file.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > _MAX_NATIVE_MONITOR_PID_BYTES
        ):
            raise RuntimeContractError(f"unsafe existing monitor PID file: {pid_file}")
        previous = pid_file.read_bytes()
        after = pid_file.lstat()
        if (
            (before.st_dev, before.st_ino, before.st_size)
            != (after.st_dev, after.st_ino, after.st_size)
        ):
            raise RuntimeContractError(f"monitor PID file changed while reading: {pid_file}")
    descriptor = -1
    temporary: Path | None = None
    directory_descriptor = -1
    published_identity: tuple[int, int] | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{pid_file.name}.", suffix=".tmp", dir=pid_file.parent,
        )
        temporary = Path(temporary_name)
        os.fchmod(descriptor, 0o644)
        written = 0
        while written < len(payload):
            written += os.write(descriptor, payload[written:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        temporary_metadata = temporary.lstat()
        os.replace(temporary, pid_file)
        published_identity = (
            temporary_metadata.st_dev, temporary_metadata.st_ino,
        )
        temporary = None
        directory_descriptor = os.open(
            pid_file.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        os.fsync(directory_descriptor)
    except BaseException:
        if published_identity is not None:
            try:
                current = pid_file.lstat()
                same_publication = (
                    stat.S_ISREG(current.st_mode)
                    and current.st_nlink == 1
                    and (current.st_dev, current.st_ino) == published_identity
                    and pid_file.read_bytes() == payload
                )
                confirmed = pid_file.lstat()
                same_publication = same_publication and (
                    (confirmed.st_dev, confirmed.st_ino) == published_identity
                    and stat.S_ISREG(confirmed.st_mode)
                    and confirmed.st_nlink == 1
                )
                if same_publication:
                    if directory_descriptor >= 0:
                        os.close(directory_descriptor)
                        directory_descriptor = -1
                    if previous is None:
                        pid_file.unlink()
                    else:
                        rollback_descriptor, rollback_name = tempfile.mkstemp(
                            prefix=f".{pid_file.name}.", suffix=".rollback",
                            dir=pid_file.parent,
                        )
                        rollback = Path(rollback_name)
                        try:
                            os.fchmod(rollback_descriptor, 0o644)
                            offset = 0
                            while offset < len(previous):
                                offset += os.write(
                                    rollback_descriptor, previous[offset:],
                                )
                            os.fsync(rollback_descriptor)
                            os.close(rollback_descriptor)
                            rollback_descriptor = -1
                            os.replace(rollback, pid_file)
                            rollback = None
                        finally:
                            if rollback_descriptor >= 0:
                                os.close(rollback_descriptor)
                            if rollback is not None:
                                rollback.unlink(missing_ok=True)
                    rollback_directory = os.open(
                        pid_file.parent,
                        os.O_RDONLY
                        | getattr(os, "O_DIRECTORY", 0)
                        | getattr(os, "O_CLOEXEC", 0),
                    )
                    try:
                        os.fsync(rollback_directory)
                    finally:
                        os.close(rollback_directory)
            except OSError:
                pass
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if directory_descriptor >= 0:
            os.close(directory_descriptor)
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass


@dataclass(frozen=True)
class _NativeMonitorProcess:
    pid: int
    proc_device: int
    proc_inode: int
    cmdline: Tuple[str, ...]


@dataclass(frozen=True)
class _NativeMonitorPidFile:
    path: Path
    device: int
    inode: int
    content: bytes
    pid: int


_MAX_NATIVE_MONITOR_PROCESSES = 131072
_MAX_NATIVE_MONITOR_PROJECTS = 4096
_MAX_NATIVE_MONITOR_CMDLINE_BYTES = 64 * 1024
_MAX_NATIVE_MONITOR_PID_BYTES = 64
NATIVE_MONITOR_QUIESCE_CONTRACT = (
    "MONITOR-WRITER-QUIESCE-R1",
    "direct-project-only",
    "fixed-monitor-argv-grammar",
    "single-regular-pid-authority",
    "bounded-complete-proc-scan",
    "all-identities-before-first-signal",
    "sigterm-only",
    "bounded-confirmed-exit",
    "identity-bound-pid-cleanup",
)


def _bounded_nofollow_read(
    path: Path, maximum: int, label: str,
) -> Tuple[bytes, os.stat_result]:
    flags = (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(os.fspath(path), flags)
    except OSError as exc:
        raise RuntimeContractError(f"cannot read {label} {path}: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        data = os.read(descriptor, maximum + 1)
    except OSError as exc:
        raise RuntimeContractError(f"cannot read {label} {path}: {exc}") from exc
    finally:
        os.close(descriptor)
    if len(data) > maximum:
        raise RuntimeContractError(f"{label} exceeds {maximum} bytes: {path}")
    return data, opened


def _native_monitor_pid_files(
    http_root: Path,
) -> Tuple[_NativeMonitorPidFile, ...]:
    day0 = http_root / "DAY0-Prepare"
    try:
        entries = sorted(day0.iterdir(), key=lambda item: item.name)
    except FileNotFoundError:
        return ()
    except OSError as exc:
        raise RuntimeContractError(
            f"cannot enumerate Native monitor projects: {exc}"
        ) from exc
    if len(entries) > _MAX_NATIVE_MONITOR_PROJECTS:
        raise RuntimeContractError(
            "too many DAY0 project entries to prove Monitor quiescence"
        )
    result = []
    for project in entries:
        try:
            project_status = project.lstat()
        except OSError as exc:
            raise RuntimeContractError(
                f"cannot inspect DAY0 project entry {project}: {exc}"
            ) from exc
        if not stat.S_ISDIR(project_status.st_mode):
            continue
        pid_path = project / "99-output-ztp/ztp-monitor.pid"
        try:
            pid_status = pid_path.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise RuntimeContractError(
                f"cannot inspect Native Monitor PID file {pid_path}: {exc}"
            ) from exc
        if (not stat.S_ISREG(pid_status.st_mode)
                or pid_status.st_nlink != 1):
            raise RuntimeContractError(
                "Native Monitor PID authority is not a single regular file: "
                f"{pid_path}"
            )
        content, opened = _bounded_nofollow_read(
            pid_path, _MAX_NATIVE_MONITOR_PID_BYTES,
            "Native Monitor PID file",
        )
        if (opened.st_dev, opened.st_ino) != (
            pid_status.st_dev, pid_status.st_ino,
        ):
            raise RuntimeContractError(
                f"Native Monitor PID file changed while opening: {pid_path}"
            )
        try:
            rendered = content.decode("ascii").strip()
            pid = int(rendered)
        except (UnicodeDecodeError, ValueError) as exc:
            raise RuntimeContractError(
                f"Native Monitor PID file has invalid PID: {pid_path}"
            ) from exc
        if not rendered.isdigit() or pid <= 1:
            raise RuntimeContractError(
                f"Native Monitor PID file has invalid PID: {pid_path}"
            )
        result.append(_NativeMonitorPidFile(
            path=pid_path,
            device=pid_status.st_dev,
            inode=pid_status.st_ino,
            content=content,
            pid=pid,
        ))
    return tuple(result)


def _read_native_monitor_process(
    pid: int,
    proc_root: Path,
    http_root: Path,
    *,
    referenced: bool,
) -> Optional[_NativeMonitorProcess]:
    process_path = proc_root / str(pid)
    try:
        process_status = process_path.stat()
    except FileNotFoundError:
        if referenced:
            raise RuntimeContractError(
                f"Native Monitor PID {pid} is stale or unreadable"
            )
        return None
    except OSError as exc:
        raise RuntimeContractError(
            f"cannot inspect Native Monitor PID {pid}: {exc}"
        ) from exc
    try:
        content, _opened = _bounded_nofollow_read(
            process_path / "cmdline",
            _MAX_NATIVE_MONITOR_CMDLINE_BYTES,
            f"process {pid} cmdline",
        )
    except RuntimeContractError:
        if referenced:
            raise
        # An unreadable process cannot safely be excluded from the set of
        # detached monitors, so a complete scan remains fail closed.
        raise
    if not content:
        if referenced:
            raise RuntimeContractError(
                f"Native Monitor PID {pid} has an empty cmdline"
            )
        return None
    try:
        cmdline = tuple(
            token.decode("utf-8")
            for token in content.rstrip(b"\0").split(b"\0")
        )
    except UnicodeDecodeError as exc:
        raise RuntimeContractError(
            f"Native Monitor PID {pid} cmdline is not UTF-8"
        ) from exc
    expected_script = (
        http_root / "DAY0-Prepare/12-ztp-monitor.py"
    ).resolve(strict=False)
    project_token = _native_monitor_project_from_argv(cmdline, expected_script)
    if project_token is None:
        if referenced:
            raise RuntimeContractError(
                f"Native Monitor PID {pid} cmdline identity does not match"
            )
        return None
    project = Path(project_token)
    expected_parent = http_root / "DAY0-Prepare"
    try:
        project = project.resolve(strict=True)
    except OSError as exc:
        if referenced:
            raise RuntimeContractError(
                f"Native Monitor PID {pid} project identity is unreadable"
            ) from exc
        return None
    if project.parent != expected_parent or project.name in {"", "template"}:
        if referenced:
            raise RuntimeContractError(
                f"Native Monitor PID {pid} project is outside direct project scope"
            )
        return None
    return _NativeMonitorProcess(
        pid=pid,
        proc_device=process_status.st_dev,
        proc_inode=process_status.st_ino,
        cmdline=cmdline,
    )


def _native_monitor_project_from_argv(cmdline, expected_script):
    """Return the sole project from the supported detached-monitor grammar."""
    if not cmdline:
        return None
    executable_name = Path(cmdline[0]).name
    if not (
        executable_name in {"python", "python3"}
        or (
            executable_name.startswith("python3.")
            and executable_name[len("python3."):].isdigit()
        )
    ):
        return None
    script_index = 1
    if len(cmdline) > 1 and cmdline[1] in {"-u", "-B"}:
        script_index = 2
    if script_index >= len(cmdline):
        return None

    def is_expected_script(token):
        try:
            return Path(token).resolve(strict=False) == expected_script
        except (OSError, RuntimeError):
            return False

    script_indexes = tuple(
        index for index, token in enumerate(cmdline)
        if is_expected_script(token)
    )
    if script_indexes != (script_index,):
        return None

    value_options = {
        "--since": "integer",
        "--watch": "positive-integer",
        "--stall-warning-minutes": "positive-integer",
        "--output-dir": "path",
        "--apache-log": "path",
        "--dhcp-log": "path",
        "--dhcp-leases": "path",
        "--air-json": "path",
        "--ssh-timeout": "integer",
        "--jobs": "integer",
        "--scope": "scope",
        "--type": "scope",
        "--identity": "path",
        "--known-hosts": "path",
        "--html-script": "path",
        "--collector-timeout": "integer",
    }
    flag_options = {
        "--offline", "--no-ssh", "--air", "--prod", "--generate-html",
        "--collect-on-complete", "--exit-on-complete",
    }
    environment_options = {"--scope", "--type", "--air", "--prod"}
    seen = set()
    selected_environment = None
    positionals = []
    arguments = cmdline[script_index + 1:]
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if not token.startswith("--"):
            positionals.append(token)
            index += 1
            continue
        option, separator, attached_value = token.partition("=")
        if option in seen:
            return None
        if option in environment_options:
            if selected_environment is not None:
                return None
            selected_environment = option
        if option in flag_options:
            if separator:
                return None
            seen.add(option)
            index += 1
            continue
        kind = value_options.get(option)
        if kind is None:
            return None
        if separator:
            value = attached_value
        else:
            index += 1
            if index >= len(arguments) or arguments[index].startswith("--"):
                return None
            value = arguments[index]
        if not value:
            return None
        if kind in {"integer", "positive-integer"}:
            try:
                parsed = int(value)
            except ValueError:
                return None
            if kind == "positive-integer" and parsed <= 0:
                return None
        elif kind == "scope" and value not in {"all", "prod", "air"}:
            return None
        seen.add(option)
        index += 1
    if seen.intersection({"--watch"}) != {"--watch"}:
        return None
    if len(positionals) != 1:
        return None
    return positionals[0]


def _same_native_monitor_pid_file(record: _NativeMonitorPidFile) -> bool:
    try:
        status_now = record.path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise RuntimeContractError(
            f"cannot revalidate Native Monitor PID file {record.path}: {exc}"
        ) from exc
    if (status_now.st_dev, status_now.st_ino) != (
        record.device, record.inode,
    ):
        return False
    content_now, opened = _bounded_nofollow_read(
        record.path,
        _MAX_NATIVE_MONITOR_PID_BYTES,
        "Native Monitor PID file",
    )
    return (
        (opened.st_dev, opened.st_ino) == (record.device, record.inode)
        and content_now == record.content
    )


def _native_monitor_still_running(
    process: _NativeMonitorProcess,
    proc_root: Path,
    http_root: Path,
) -> bool:
    process_path = proc_root / str(process.pid)
    try:
        status_now = process_path.stat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise RuntimeContractError(
            f"cannot confirm Native Monitor PID {process.pid} exit: {exc}"
        ) from exc
    if (status_now.st_dev, status_now.st_ino) != (
        process.proc_device, process.proc_inode,
    ):
        return False
    current = _read_native_monitor_process(
        process.pid, proc_root, http_root, referenced=True,
    )
    return current is not None and current.cmdline == process.cmdline


def _cleanup_native_monitor_pid_file(record: _NativeMonitorPidFile) -> None:
    if not _same_native_monitor_pid_file(record):
        return
    try:
        record.path.unlink()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise RuntimeContractError(
            f"cannot remove stopped Monitor PID file: {exc}"
        ) from exc


def stop_native_ztp_monitors(
    http_root,
    *,
    proc_root=Path("/proc"),
    timeout: float = 5.0,
    kill: Callable[[int, int], None] = os.kill,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    _before_signal: Optional[Callable[[], None]] = None,
) -> Tuple[int, ...]:
    """Stop and confirm every exact detached Native ZTP Monitor.

    PID files are authorities: malformed, stale, unreadable, special, rebound,
    or identity-mismatched references abort before any process is signalled. A
    bounded ``/proc`` scan also finds matching monitors whose PID file was lost.
    """
    try:
        root = Path(http_root).resolve(strict=True)
    except OSError as exc:
        raise RuntimeContractError(
            f"Native Monitor HTTP root is unreadable: {exc}"
        ) from exc
    proc = Path(proc_root)
    if timeout <= 0 or timeout > 60:
        raise RuntimeContractError(
            "Native Monitor stop timeout must be in (0, 60] seconds"
        )
    pid_files = _native_monitor_pid_files(root)
    if not proc.is_dir():
        if pid_files:
            raise RuntimeContractError(
                "cannot validate Native Monitor PID authority without /proc"
            )
        return ()

    processes = {}
    for record in pid_files:
        candidate = _read_native_monitor_process(
            record.pid, proc, root, referenced=True,
        )
        assert candidate is not None
        processes[candidate.pid] = candidate

    try:
        numeric_entries = [
            entry for entry in proc.iterdir() if entry.name.isdigit()
        ]
    except OSError as exc:
        raise RuntimeContractError(
            f"cannot enumerate /proc for Native Monitors: {exc}"
        ) from exc
    if len(numeric_entries) > _MAX_NATIVE_MONITOR_PROCESSES:
        raise RuntimeContractError(
            "too many process entries to prove Monitor quiescence"
        )
    for entry in sorted(numeric_entries, key=lambda item: int(item.name)):
        pid = int(entry.name)
        if pid in processes:
            continue
        candidate = _read_native_monitor_process(
            pid, proc, root, referenced=False,
        )
        if candidate is not None:
            processes[pid] = candidate

    ordered = tuple(processes[pid] for pid in sorted(processes))
    if _before_signal is not None:
        _before_signal()
    # Revalidate the complete batch and every PID-file authority before the
    # first signal. This prevents a reused PID or rebound file from causing a
    # partial stop followed by an unsafe writer mutation.
    for record in pid_files:
        if not _same_native_monitor_pid_file(record):
            raise RuntimeContractError(
                f"Native Monitor PID authority changed before SIGTERM: {record.path}"
            )
    for process in ordered:
        current = _read_native_monitor_process(
            process.pid, proc, root, referenced=True,
        )
        if current != process:
            raise RuntimeContractError(
                f"Native Monitor PID {process.pid} identity changed before SIGTERM"
            )
    for process in ordered:
        try:
            kill(process.pid, signal.SIGTERM)
        except OSError as exc:
            raise RuntimeContractError(
                f"cannot signal Native Monitor PID {process.pid}: {exc}"
            ) from exc

    deadline = monotonic() + timeout
    remaining = {process.pid: process for process in ordered}
    while remaining:
        for pid, process in tuple(remaining.items()):
            if not _native_monitor_still_running(process, proc, root):
                remaining.pop(pid)
        if not remaining:
            break
        if monotonic() >= deadline:
            raise RuntimeContractError(
                "Native Monitor exit timeout for PID(s): "
                + ", ".join(str(pid) for pid in sorted(remaining))
            )
        sleep(min(0.05, max(0.0, deadline - monotonic())))

    for record in pid_files:
        if record.pid in processes:
            _cleanup_native_monitor_pid_file(record)
    return tuple(process.pid for process in ordered)


@dataclass(frozen=True)
class DhcpNetwork:
    order: int
    shared_network: str
    network: ipaddress.IPv4Network
    service_ip: Optional[ipaddress.IPv4Address]
    endpoint_enabled: bool

    @property
    def on_link(self) -> bool:
        return (
            self.endpoint_enabled
            and self.service_ip is not None
            and self.service_ip in self.network
        )


@dataclass(frozen=True)
class LogicalInterface:
    ifindex: int
    ifname: str
    addresses: Tuple[ipaddress.IPv4Interface, ...]
    is_up: bool
    flags: Tuple[str, ...]
    link_type: str
    lower_ifindex: Optional[int] = None
    link_kind: Optional[str] = None


@dataclass(frozen=True)
class DhcpRuntimePlan:
    listener_names: Tuple[str, ...]
    listener_ifindexes: Tuple[int, ...]
    direct_shared_networks: Tuple[str, ...]
    relay_shared_networks: Tuple[str, ...]
    dhcp_only_shared_networks: Tuple[str, ...]
    endpoint_ips: Tuple[str, ...]


def _json_records(value: Any, label: str) -> Tuple[Mapping[str, Any], ...]:
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RuntimeContractError(f"{label} is not UTF-8 JSON") from exc
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise RuntimeContractError(f"invalid {label} JSON: {exc}") from exc
    if not isinstance(value, (list, tuple)):
        raise RuntimeContractError(f"{label} must be a JSON array")
    records = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            raise RuntimeContractError(f"{label}[{index}] must be an object")
        records.append(item)
    return tuple(records)


def _positive_ifindex(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise RuntimeContractError(f"{label} has invalid ifindex: {value!r}")
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise RuntimeContractError(f"{label} has invalid ifindex: {value!r}") from exc
    if result <= 0:
        raise RuntimeContractError(f"{label} has invalid ifindex: {value!r}")
    return result


def _interface_name(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SAFE_INTERFACE_NAME.fullmatch(value):
        raise RuntimeContractError(f"{label} has unsafe interface name: {value!r}")
    return value


def _usable_address(record: Mapping[str, Any]) -> bool:
    if str(record.get("family") or "").casefold() != "inet":
        return False
    if str(record.get("scope") or "global").casefold() not in {"global", "site"}:
        return False
    raw_flags = record.get("flags") or ()
    if not isinstance(raw_flags, (list, tuple)):
        raise RuntimeContractError("IPv4 address flags must be an array")
    flags = {
        str(value).casefold()
        for value in raw_flags
        if isinstance(value, str)
    }
    if flags.intersection({"tentative", "dadfailed", "deprecated"}):
        return False
    preferred = record.get("preferred_life_time")
    if preferred in {0, "0"}:
        return False
    valid = record.get("valid_life_time")
    if valid in {0, "0"}:
        return False
    return True


def _logical_interfaces(
    link_snapshot: Any, address_snapshot: Any,
) -> Tuple[LogicalInterface, ...]:
    links = _json_records(link_snapshot, "link snapshot")
    address_records = _json_records(address_snapshot, "address snapshot")

    link_by_index = {}
    name_to_index = {}
    for position, record in enumerate(links):
        label = f"link snapshot[{position}]"
        ifindex = _positive_ifindex(record.get("ifindex"), label)
        ifname = _interface_name(record.get("ifname"), label)
        raw_flags = record.get("flags") or ()
        if not isinstance(raw_flags, (list, tuple)):
            raise RuntimeContractError(f"{label}.flags must be an array")
        raw_link_type = record.get("link_type")
        if not isinstance(raw_link_type, str) or not raw_link_type.strip():
            raise RuntimeContractError(f"{label} has invalid link_type")
        if ifindex in link_by_index:
            raise RuntimeContractError(f"duplicate link ifindex {ifindex}")
        previous = name_to_index.get(ifname)
        if previous is not None and previous != ifindex:
            raise RuntimeContractError(
                f"interface name {ifname} maps to ifindexes {previous} and {ifindex}"
            )
        link_by_index[ifindex] = record
        name_to_index[ifname] = ifindex

    addresses_by_index = {ifindex: [] for ifindex in link_by_index}
    for position, record in enumerate(address_records):
        label = f"address snapshot[{position}]"
        ifindex = _positive_ifindex(record.get("ifindex"), label)
        ifname = _interface_name(record.get("ifname"), label)
        link_record = link_by_index.get(ifindex)
        if link_record is None:
            raise RuntimeContractError(
                f"address snapshot references unknown ifindex {ifindex} ({ifname})"
            )
        canonical = str(link_record["ifname"])
        if ifname != canonical:
            raise RuntimeContractError(
                f"ifindex {ifindex} name mismatch: link={canonical}, address={ifname}"
            )
        raw_addr_info = record.get("addr_info") or ()
        if not isinstance(raw_addr_info, (list, tuple)):
            raise RuntimeContractError(f"{label}.addr_info must be an array")
        for addr_position, addr_record in enumerate(raw_addr_info):
            if not isinstance(addr_record, Mapping):
                raise RuntimeContractError(
                    f"{label}.addr_info[{addr_position}] must be an object"
                )
            if not _usable_address(addr_record):
                continue
            raw_local = addr_record.get("local")
            raw_prefix = addr_record.get("prefixlen")
            try:
                address = ipaddress.IPv4Interface(f"{raw_local}/{raw_prefix}")
            except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as exc:
                raise RuntimeContractError(
                    f"{label} has invalid IPv4 address {raw_local!r}/{raw_prefix!r}"
                ) from exc
            if address not in addresses_by_index[ifindex]:
                addresses_by_index[ifindex].append(address)

    interfaces = []
    for ifindex, record in link_by_index.items():
        raw_flags = record.get("flags") or ()
        flags = tuple(
            dict.fromkeys(
                str(value).upper() for value in raw_flags
                if isinstance(value, str)
            )
        )
        operstate = str(record.get("operstate") or "UNKNOWN").upper()
        is_up = "UP" in flags and operstate in {"UP", "UNKNOWN"}
        lower = record.get("link_index")
        lower_ifindex = None
        if lower is not None:
            lower_ifindex = _positive_ifindex(
                lower, f"link snapshot ifindex {ifindex} link_index",
            )
        linkinfo = record.get("linkinfo") or {}
        if not isinstance(linkinfo, Mapping):
            raise RuntimeContractError(
                f"link snapshot ifindex {ifindex} has invalid linkinfo"
            )
        link_kind = None
        if linkinfo.get("info_kind") is not None:
            link_kind = str(linkinfo["info_kind"]).strip().casefold()
            if not link_kind:
                raise RuntimeContractError(
                    f"link snapshot ifindex {ifindex} has empty info_kind"
                )
        interfaces.append(LogicalInterface(
            ifindex=ifindex,
            ifname=str(record["ifname"]),
            addresses=tuple(addresses_by_index[ifindex]),
            is_up=is_up,
            flags=flags,
            link_type=str(record["link_type"]).strip().casefold(),
            lower_ifindex=lower_ifindex,
            link_kind=link_kind,
        ))
    return tuple(interfaces)


def _read_dhcp_networks(subnet_csv: Path) -> Tuple[DhcpNetwork, ...]:
    path = Path(subnet_csv)
    try:
        stream = path.open(newline="", encoding="utf-8-sig")
    except OSError as exc:
        raise RuntimeContractError(f"cannot read DHCP subnet CSV {path}: {exc}") from exc
    with stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames is None:
            raise RuntimeContractError("DHCP subnet CSV has no header")
        missing = sorted(REQUIRED_SUBNET_COLUMNS - set(reader.fieldnames))
        if missing:
            raise RuntimeContractError(
                "DHCP subnet CSV missing columns: " + ", ".join(missing)
            )
        result = []
        shared_lines = {}
        for lineno, row in enumerate(reader, 2):
            if not any(str(value or "").strip() for value in row.values()):
                continue
            profile = str(row.get("cumulus_profile") or "").strip().casefold()
            nvos_ztp = str(row.get("nvos_ztp") or "").strip().casefold()
            if profile not in {"oob", "oobofoob", "none"}:
                raise RuntimeContractError(
                    f"DHCP subnet CSV line {lineno} has invalid "
                    f"cumulus_profile={profile!r}"
                )
            if nvos_ztp not in {"yes", "no"}:
                raise RuntimeContractError(
                    f"DHCP subnet CSV line {lineno} has invalid "
                    f"nvos_ztp={nvos_ztp!r}"
                )
            endpoint_enabled = profile in {"oob", "oobofoob"} or nvos_ztp == "yes"
            raw_service_ip = str(row.get("ztp_service_ip") or "").strip()
            if endpoint_enabled and not raw_service_ip:
                raise RuntimeContractError(
                    f"DHCP subnet CSV line {lineno} enables ZTP but has no "
                    "ztp_service_ip"
                )
            if not endpoint_enabled and raw_service_ip:
                raise RuntimeContractError(
                    f"DHCP subnet CSV line {lineno} has ztp_service_ip but no "
                    "enabled platform ZTP"
                )
            shared = str(row.get("shared_network") or "").strip()
            if not shared:
                raise RuntimeContractError(
                    f"DHCP subnet CSV line {lineno} has empty shared_network"
                )
            previous = shared_lines.get(shared)
            if previous is not None:
                raise RuntimeContractError(
                    f"DHCP shared_network {shared!r} repeats on lines "
                    f"{previous} and {lineno}"
                )
            shared_lines[shared] = lineno
            try:
                network = ipaddress.IPv4Network(
                    f"{str(row.get('subnet') or '').strip()}/"
                    f"{str(row.get('netmask') or '').strip()}",
                    strict=False,
                )
            except ValueError as exc:
                raise RuntimeContractError(
                    f"DHCP subnet CSV line {lineno} is invalid: {exc}"
                ) from exc
            service_ip = None
            if raw_service_ip:
                try:
                    service_ip = ipaddress.IPv4Address(raw_service_ip)
                except ipaddress.AddressValueError as exc:
                    raise RuntimeContractError(
                        f"DHCP subnet CSV line {lineno} has invalid "
                        f"ztp_service_ip={raw_service_ip!r}"
                    ) from exc
            result.append(DhcpNetwork(
                order=len(result),
                shared_network=shared,
                network=network,
                service_ip=service_ip,
                endpoint_enabled=endpoint_enabled,
            ))
    return tuple(result)


def _ordered_names(values: Iterable[str], label: str) -> Tuple[str, ...]:
    ordered = []
    for raw_value in values:
        value = _interface_name(raw_value, label)
        if value in ordered:
            raise RuntimeContractError(f"duplicate {label}: {value}")
        ordered.append(value)
    return tuple(ordered)


def _listener_link_problem(
    interface: LogicalInterface,
    by_index: Mapping[int, LogicalInterface],
    *,
    ancestry: Tuple[int, ...] = (),
) -> Optional[str]:
    """Return why an interface is unsafe for DHCP, or ``None`` when allowed.

    The automatic production contract intentionally supports only real
    Ethernet links, bond masters, and VLANs whose complete lower-link chain
    ends at a supported physical Ethernet or bond.  Docker bridges/veths and
    other virtual devices must never become listeners merely because an
    address happens to match project data.
    """
    if interface.ifindex in ancestry:
        return "VLAN parent chain contains a cycle"
    if not interface.is_up:
        return "interface is not up"
    flags = set(interface.flags)
    missing = sorted({"BROADCAST", "UP", "LOWER_UP"} - flags)
    if missing:
        return "interface lacks required flags: " + ", ".join(missing)
    forbidden = sorted({"LOOPBACK", "POINTOPOINT", "NOARP", "SLAVE"} & flags)
    if forbidden:
        return "unsafe link flags: " + ", ".join(forbidden)
    if interface.link_type != "ether":
        return f"unsafe link_type={interface.link_type!r}"

    kind = interface.link_kind
    if kind is None:
        return None
    if kind == "bond":
        if "MASTER" not in flags:
            return "bond listener is not a MASTER"
        return None
    if kind != "vlan":
        return f"unsafe link kind={kind!r}"
    if interface.lower_ifindex is None:
        return "VLAN has no parent ifindex"
    parent = by_index.get(interface.lower_ifindex)
    if parent is None:
        return f"VLAN parent ifindex {interface.lower_ifindex} is absent"
    problem = _listener_link_problem(
        parent, by_index, ancestry=ancestry + (interface.ifindex,),
    )
    if problem:
        return f"VLAN parent {parent.ifname} is not eligible: {problem}"
    return None


def _require_listener_link(
    interface: LogicalInterface,
    by_index: Mapping[int, LogicalInterface],
    *,
    label: str,
) -> None:
    problem = _listener_link_problem(interface, by_index)
    if problem:
        raise RuntimeContractError(
            f"{label} expected an eligible interface; "
            f"{interface.ifname} ifindex {interface.ifindex} is not eligible: "
            f"{problem}"
        )


def _require_unique_endpoint_assignments(
    networks: Sequence[DhcpNetwork],
    interfaces: Sequence[LogicalInterface],
) -> Mapping[str, LogicalInterface]:
    endpoint_interfaces = {}
    for endpoint in dict.fromkeys(
        str(item.service_ip)
        for item in networks
        if item.endpoint_enabled and item.service_ip is not None
    ):
        matches = [
            interface for interface in interfaces
            if any(str(address.ip) == endpoint for address in interface.addresses)
        ]
        if len(matches) != 1:
            raise RuntimeContractError(
                f"service endpoint {endpoint} expected exactly one eligible interface; "
                f"found {[item.ifname for item in matches]}"
            )
        endpoint_interfaces[endpoint] = matches[0]
    return endpoint_interfaces


def _validate_selected_interface_networks(
    selected: Sequence[LogicalInterface], networks: Sequence[DhcpNetwork],
) -> None:
    for interface in selected:
        matches = {
            network.shared_network
            for address in interface.addresses
            for network in networks
            if address.ip in network.network
        }
        if len(matches) > 1:
            raise RuntimeContractError(
                f"Interface {interface.ifname} ifindex {interface.ifindex} "
                "matches multiple shared networks: " + ", ".join(sorted(matches))
            )


def plan_dhcp_runtime(
    subnet_csv: Path,
    *,
    link_snapshot: Any,
    address_snapshot: Any,
    allowlist: Iterable[str] = (),
    relay_ingress: Iterable[str] = (),
) -> DhcpRuntimePlan:
    """Return the exact ordered Linux interfaces allowed to run dhcpd.

    On-link requirements are inferred only when an enabled row's service IP is
    inside that row's subnet.  Off-link rows do not add one interface per pool;
    a relay-only deployment instead requires explicitly scoped ingress names.
    """
    networks = _read_dhcp_networks(Path(subnet_csv))
    interfaces = _logical_interfaces(link_snapshot, address_snapshot)
    by_name = {interface.ifname: interface for interface in interfaces}
    by_index = {interface.ifindex: interface for interface in interfaces}

    allowed_names = _ordered_names(allowlist, "allowlist interface")
    ingress_names = _ordered_names(relay_ingress, "relay ingress interface")
    unknown_allowed = sorted(set(allowed_names) - set(by_name))
    if unknown_allowed:
        raise RuntimeContractError(
            "unknown allowlist interfaces: " + ", ".join(unknown_allowed)
        )
    unknown_ingress = sorted(set(ingress_names) - set(by_name))
    if unknown_ingress:
        raise RuntimeContractError(
            "unknown relay ingress interfaces: " + ", ".join(unknown_ingress)
        )
    if allowed_names:
        outside = sorted(set(ingress_names) - set(allowed_names))
        if outside:
            raise RuntimeContractError(
                "relay ingress outside interface allowlist: " + ", ".join(outside)
            )

    if not networks and ingress_names:
        raise RuntimeContractError(
            "no DHCP networks are configured; refuse non-empty relay ingress"
        )

    endpoint_networks = tuple(item for item in networks if item.endpoint_enabled)
    dhcp_only_networks = tuple(
        item for item in networks if not item.endpoint_enabled
    )

    # Endpoint uniqueness is a host-global invariant.  The allowlist is only a
    # ceiling and therefore must not hide a duplicate assignment on a second
    # ifindex (including a virtual or currently down link).
    endpoints = _require_unique_endpoint_assignments(
        endpoint_networks, interfaces,
    )
    for endpoint, interface in endpoints.items():
        _require_listener_link(
            interface, by_index, label=f"service endpoint {endpoint}",
        )
        if allowed_names and interface.ifname not in allowed_names:
            raise RuntimeContractError(
                f"service endpoint {endpoint} interface {interface.ifname} "
                "is outside interface allowlist"
            )

    ingress_interfaces = {}
    for name in ingress_names:
        interface = by_name[name]
        _require_listener_link(
            interface, by_index, label=f"relay ingress {name}",
        )
        if not interface.addresses:
            raise RuntimeContractError(
                f"relay ingress {name} has no usable global IPv4 address"
            )
        ingress_interfaces[name] = interface

    direct_networks = tuple(item for item in endpoint_networks if item.on_link)
    relayed_networks = tuple(item for item in endpoint_networks if not item.on_link)

    selected_by_shared = {}
    for network in direct_networks:
        expected = ipaddress.IPv4Interface(
            f"{network.service_ip}/{network.network.prefixlen}"
        )
        interface = endpoints[str(network.service_ip)]
        if expected not in interface.addresses:
            raise RuntimeContractError(
                f"shared_network {network.shared_network} expected exactly one "
                f"eligible interface for {expected}; found "
                f"{[interface.ifname]} with "
                f"{[str(item) for item in interface.addresses]}"
            )
        selected_by_shared[network.shared_network] = interface

    if endpoint_networks and not direct_networks and not ingress_names:
        raise RuntimeContractError(
            "relay-only DHCP configuration requires explicit relay ingress interfaces"
        )

    # A relay-only endpoint which is not already attached to a direct listener
    # must be reached through an explicitly named ingress interface.  Merely
    # finding its address elsewhere is not authority to expose DHCP there.
    direct_ifindexes = {
        interface.ifindex for interface in selected_by_shared.values()
    }
    ingress_ifindexes = {
        ingress_interfaces[name].ifindex for name in ingress_names
    }
    for endpoint, interface in endpoints.items():
        if interface.ifindex in direct_ifindexes:
            continue
        if interface.ifindex not in ingress_ifindexes:
            raise RuntimeContractError(
                f"relay endpoint {endpoint} requires its interface "
                f"{interface.ifname} in explicit relay ingress"
            )

    shared_by_ifindex = {}
    for shared, interface in selected_by_shared.items():
        shared_by_ifindex.setdefault(interface.ifindex, set()).add(shared)
    conflicts = {
        ifindex: names for ifindex, names in shared_by_ifindex.items()
        if len(names) > 1
    }
    if conflicts:
        ifindex = next(iter(conflicts))
        interface = by_index[ifindex]
        raise RuntimeContractError(
            f"Interface {interface.ifname} ifindex {ifindex} matches multiple "
            "shared networks: " + ", ".join(sorted(conflicts[ifindex]))
        )

    selected = []
    seen_ifindexes = set()
    for network in direct_networks:
        interface = selected_by_shared[network.shared_network]
        if interface.ifindex not in seen_ifindexes:
            selected.append(interface)
            seen_ifindexes.add(interface.ifindex)
    for name in ingress_names:
        interface = ingress_interfaces[name]
        if interface.ifindex not in seen_ifindexes:
            selected.append(interface)
            seen_ifindexes.add(interface.ifindex)

    _validate_selected_interface_networks(selected, networks)
    if dhcp_only_networks and not ingress_names:
        raise RuntimeContractError(
            "DHCP-only shared networks require explicit relay ingress interfaces: "
            + ", ".join(item.shared_network for item in dhcp_only_networks)
        )
    return DhcpRuntimePlan(
        listener_names=tuple(item.ifname for item in selected),
        listener_ifindexes=tuple(item.ifindex for item in selected),
        direct_shared_networks=tuple(
            item.shared_network for item in direct_networks
        ),
        relay_shared_networks=tuple(
            item.shared_network for item in relayed_networks
        ),
        dhcp_only_shared_networks=tuple(
            item.shared_network for item in dhcp_only_networks
        ),
        endpoint_ips=tuple(dict.fromkeys(
            str(item.service_ip) for item in endpoint_networks
            if item.service_ip is not None
        )),
    )


def revalidate_dhcp_runtime_plan(
    expected_plan: DhcpRuntimePlan,
    subnet_csv: Path,
    *,
    link_snapshot: Any,
    address_snapshot: Any,
    allowlist: Iterable[str] = (),
    relay_ingress: Iterable[str] = (),
) -> DhcpRuntimePlan:
    """Re-plan immediately before exec and reject interface identity changes.

    A persisted activation marker may intentionally be re-planned after a
    reboot, but a single start transaction must not turn a checked ifindex into
    an unchecked interface name.  Re-running the full planner also revalidates
    every direct endpoint prefix and secondary-address shared-network guard.
    """
    current = plan_dhcp_runtime(
        subnet_csv,
        link_snapshot=link_snapshot,
        address_snapshot=address_snapshot,
        allowlist=allowlist,
        relay_ingress=relay_ingress,
    )
    fields = (
        "listener_names", "listener_ifindexes", "direct_shared_networks",
        "relay_shared_networks", "dhcp_only_shared_networks", "endpoint_ips",
    )
    for field in fields:
        try:
            expected_value = tuple(getattr(expected_plan, field))
        except (AttributeError, TypeError) as exc:
            raise RuntimeContractError(
                f"expected DHCP runtime plan has invalid {field}"
            ) from exc
        current_value = tuple(getattr(current, field))
        if expected_value != current_value:
            raise RuntimeContractError(
                "DHCP runtime plan changed before exec: "
                f"{field} expected={expected_value!r}, current={current_value!r}"
            )
    return current


def build_dhcpd_argv(
    listener_names: Iterable[str],
    *,
    config: str = "/etc/dhcp/dhcpd.conf",
    leases: str = "/var/lib/dhcp/dhcpd.leases",
) -> Tuple[str, ...]:
    """Build a fixed foreground dhcpd argv with private runtime files."""
    names = _ordered_names(listener_names, "DHCP interface")
    if not names:
        raise RuntimeContractError(
            "refuse empty interface argv because dhcpd would listen broadly"
        )
    return (
        "/usr/sbin/dhcpd", "-4", "-f",
        "-cf", os.fspath(config),
        "-lf", os.fspath(leases),
        "-pf", os.fspath(DEFAULT_SUPERVISOR_DHCP_PID),
        *names,
    )


CommandRunner = Callable[..., Any]


def _exit_detail(returncode: Any, stderr: Any) -> str:
    detail = f"(exit={returncode})"
    message = str(stderr or "").strip()
    return detail + (f": {message}" if message else "")


def _bounded_regular_file_tail(path: Path, max_bytes: int) -> str:
    """Read at most ``max_bytes`` from a non-symlink regular log file."""
    try:
        before = path.lstat()
    except OSError as exc:
        raise RuntimeContractError(f"cannot inspect runtime log {path}: {exc}") from exc
    if not stat.S_ISREG(before.st_mode):
        kind = "symlink" if stat.S_ISLNK(before.st_mode) else "non-regular file"
        raise RuntimeContractError(
            f"runtime log must be a regular file, not {kind}: {path}"
        )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RuntimeContractError(f"cannot open runtime log {path}: {exc}") from exc
    try:
        current = os.fstat(descriptor)
        if not stat.S_ISREG(current.st_mode):
            raise RuntimeContractError(f"runtime log is not a regular file: {path}")
        if (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
            raise RuntimeContractError(f"runtime log changed while opening: {path}")
        offset = max(0, current.st_size - max_bytes)
        os.lseek(descriptor, offset, os.SEEK_SET)
        chunks = []
        remaining = max_bytes
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    except OSError as exc:
        raise RuntimeContractError(f"cannot read runtime log {path}: {exc}") from exc
    finally:
        os.close(descriptor)
    payload = b"".join(chunks)
    if offset:
        separator = payload.find(b"\n")
        payload = payload[separator + 1:] if separator >= 0 else b""
    return payload.decode("utf-8", errors="replace")


class ServiceRuntimeBackend:
    """Small command boundary shared by systemd and container runtimes."""

    name = ""

    def __init__(self, command_runner: Optional[CommandRunner] = None):
        self._command_runner = command_runner or subprocess.run

    def _invoke(self, command: Sequence[str]) -> Any:
        return self._command_runner(
            list(command), capture_output=True, text=True, check=False,
        )

    def _run(self, command: Sequence[str]) -> Any:
        result = self._invoke(command)
        returncode = getattr(result, "returncode", 0)
        if returncode != 0:
            raise RuntimeContractError(
                f"{self.name} backend command failed "
                + _exit_detail(returncode, getattr(result, "stderr", ""))
                + ": " + " ".join(command)
            )
        return result

    @staticmethod
    def _service(value: str) -> str:
        if not isinstance(value, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}", value,
        ):
            raise RuntimeContractError(f"unsafe service name: {value!r}")
        return value

    def start(self, service: str) -> Any:
        raise NotImplementedError

    def stop(self, service: str) -> Any:
        raise NotImplementedError

    def restart(self, service: str) -> Any:
        raise NotImplementedError

    def reload(self, service: str) -> Any:
        raise NotImplementedError

    def status(self, service: str) -> Any:
        raise NotImplementedError

    def is_active(self, service: str) -> bool:
        raise NotImplementedError

    def is_enabled(self, service: str) -> Optional[bool]:
        """Return system boot enablement, or None when the backend has no bit."""
        return None

    def read_log(self, service: str) -> str:
        raise NotImplementedError


class SystemdRuntimeBackend(ServiceRuntimeBackend):
    name = "systemd"

    def _systemctl(self, action: str, service: str) -> Any:
        return self._run(("systemctl", action, self._service(service)))

    def start(self, service: str) -> Any:
        return self._systemctl("start", service)

    def stop(self, service: str) -> Any:
        return self._systemctl("stop", service)

    def restart(self, service: str) -> Any:
        return self._systemctl("restart", service)

    def reload(self, service: str) -> Any:
        return self._systemctl("reload", service)

    def status(self, service: str) -> Any:
        return self._systemctl("status", service)

    def is_active(self, service: str) -> bool:
        command = ("systemctl", "is-active", "--quiet", self._service(service))
        result = self._invoke(command)
        returncode = getattr(result, "returncode", 0)
        if returncode == 0:
            return True
        if returncode == 3:
            return False
        raise RuntimeContractError(
            f"systemd backend cannot determine active status for {service!r} "
            + _exit_detail(returncode, getattr(result, "stderr", ""))
        )

    def is_enabled(self, service: str) -> bool:
        command = ("systemctl", "is-enabled", "--quiet", self._service(service))
        result = self._invoke(command)
        returncode = getattr(result, "returncode", 0)
        if returncode == 0:
            return True
        if returncode == 1:
            return False
        raise RuntimeContractError(
            f"systemd backend cannot determine enabled status for {service!r} "
            + _exit_detail(returncode, getattr(result, "stderr", ""))
        )

    def read_log(self, service: str) -> str:
        result = self._run((
            "journalctl", "-u", self._service(service), "--no-pager", "-n", "200",
        ))
        return str(getattr(result, "stdout", "") or "")


class SupervisorRuntimeBackend(ServiceRuntimeBackend):
    name = "supervisor"
    _PROGRAM_NAMES = {
        "apache2": "apache2",
        "isc-dhcp-server": "dhcpd",
        "dhcpd": "dhcpd",
        "ztp-monitor": "ztp-monitor",
        "switch-collection": "switch-collection",
        "manual-ztp": "manual-ztp",
    }

    def __init__(
        self,
        command_runner: Optional[CommandRunner] = None,
        *,
        dhcp_log_path: Path = DEFAULT_SUPERVISOR_DHCP_LOG,
        max_log_bytes: int = DEFAULT_SUPERVISOR_LOG_BYTES,
    ):
        super().__init__(command_runner)
        if isinstance(max_log_bytes, bool) or not isinstance(max_log_bytes, int):
            raise RuntimeContractError("Supervisor log byte limit must be an integer")
        if max_log_bytes <= 0 or max_log_bytes > MAX_SUPERVISOR_LOG_BYTES:
            raise RuntimeContractError(
                "Supervisor log byte limit must be between 1 and "
                f"{MAX_SUPERVISOR_LOG_BYTES}"
            )
        self._dhcp_log_path = Path(dhcp_log_path)
        self._max_log_bytes = max_log_bytes

    def _program(self, service: str) -> str:
        service = self._service(service)
        try:
            return self._PROGRAM_NAMES[service]
        except KeyError as exc:
            raise RuntimeContractError(
                f"service {service!r} is not managed by supervisor backend"
            ) from exc

    def _supervisorctl(self, action: str, service: str) -> Any:
        return self._run(("supervisorctl", action, self._program(service)))

    def start(self, service: str) -> Any:
        return self._supervisorctl("start", service)

    def stop(self, service: str) -> Any:
        return self._supervisorctl("stop", service)

    def restart(self, service: str) -> Any:
        return self._supervisorctl("restart", service)

    def reload(self, service: str) -> Any:
        return self._run((
            "supervisorctl", "signal", "HUP", self._program(service),
        ))

    def status(self, service: str) -> Any:
        return self._supervisorctl("status", service)

    def is_active(self, service: str) -> bool:
        program = self._program(service)
        command = ("supervisorctl", "status", program)
        result = self._invoke(command)
        returncode = getattr(result, "returncode", 0)
        if returncode not in {0, 3}:
            raise RuntimeContractError(
                f"supervisor backend cannot read status for {program!r} "
                + _exit_detail(returncode, getattr(result, "stderr", ""))
            )
        stdout = str(getattr(result, "stdout", "") or "").strip()
        fields = stdout.split()
        if len(fields) < 2 or fields[0] != program:
            raise RuntimeContractError(
                f"supervisor backend returned invalid status for {program!r}: "
                f"{stdout!r}"
            )
        state = fields[1].upper()
        if state == "RUNNING":
            if returncode != 0:
                raise RuntimeContractError(
                    f"supervisor status for {program!r} is inconsistent: "
                    f"RUNNING with exit={returncode}"
                )
            return True
        if state in {
            "STOPPED", "STARTING", "STOPPING", "EXITED", "BACKOFF", "FATAL",
        }:
            return False
        raise RuntimeContractError(
            f"supervisor backend returned unknown status for {program!r}: {state}"
        )

    def read_log(self, service: str) -> str:
        if self._program(service) == "dhcpd":
            return _bounded_regular_file_tail(
                self._dhcp_log_path, self._max_log_bytes,
            )
        result = self._run((
            "supervisorctl", "tail", f"-{self._max_log_bytes}",
            self._program(service), "stdout",
        ))
        return str(getattr(result, "stdout", "") or "")


def runtime_backend_from_environment(
    environment: Mapping[str, str],
    *,
    command_runner: Optional[CommandRunner] = None,
) -> ServiceRuntimeBackend:
    """Select exactly ``systemd`` or ``supervisor``; never auto-fallback."""
    raw_value = environment.get(RUNTIME_BACKEND_ENV, "systemd")
    value = str(raw_value).strip().casefold()
    if value not in SUPPORTED_BACKENDS:
        raise RuntimeContractError(
            f"unsupported service runtime backend {raw_value!r}; expected "
            "systemd or supervisor"
        )
    if value == "supervisor":
        return SupervisorRuntimeBackend(command_runner)
    return SystemdRuntimeBackend(command_runner)
