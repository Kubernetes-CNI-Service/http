#!/usr/bin/env python3
"""Independent root worker for fixed Switch Status collection requests."""

from __future__ import annotations

import argparse
from datetime import datetime
import fcntl
import grp
import json
import math
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import traceback

from switch_collection_gate import (
    CollectionGate,
    CollectionGateCancelled,
    CollectionGateError,
    active_project_identity,
    collection_keys_for_scope,
)


HTTP_ROOT = Path(__file__).resolve().parent.parent
STATUS_DIR = HTTP_ROOT / "monitor/status"
REQUEST_FILE = STATUS_DIR / "switch-collection.request"
STATUS_FILE = STATUS_DIR / "switch-collection.status.json"
PID_FILE = STATUS_DIR / "switch-collection.pid"
YAML_BACKUP_STATUS_FILE = STATUS_DIR / "yaml-backup.status.json"
CONTINUOUS_STATUS_FILE = STATUS_DIR / "continuous-collection.status.json"
CONTINUOUS_BACKUP_STATUS_FILE = STATUS_DIR / "continuous-backup.status.json"
YAML_BACKUP_SOCKET = STATUS_DIR / ".yaml-backup.sock"
YAML_BACKUP_SCRIPT = HTTP_ROOT / "ztp/backup/yaml-collect.py"
YAML_BACKUP_COOLDOWN_SECONDS = 10 * 60
MIN_CONTINUOUS_INTERVAL_MINUTES = 10
MAX_CONTINUOUS_INTERVAL_MINUTES = 24 * 60
MAX_PASSWORD_BYTES = 1024
MAX_MEMORY_REQUEST_BYTES = 2048
TASK_RESULT_PREFIX = "[HTTP_ZTP_TASK_RESULT] "
MAX_TASK_RESULT_DEVICES = 10000
MAX_TASK_RESULT_TEXT_BYTES = 1024
HTML_SCRIPT = HTTP_ROOT / "monitor/generate-monitor-html.py"
SCRIPTS = {
    "ethernet": HTTP_ROOT / "ethernet/monitor/cron.sh",
    "infiniband": HTTP_ROOT / "infiniband/monitor/cron.sh",
    "nvlink": HTTP_ROOT / "nvlink/monitor/cron.sh",
}
COLLECTOR_TERM_GRACE_SECONDS = 5.0
COLLECTOR_KILL_GRACE_SECONDS = 2.0
COLLECTOR_EXIT_POLL_SECONDS = 0.05

COLLECTION_LANE = "collection"
BACKUP_LANE = "backup"
VALID_LANES = frozenset((COLLECTION_LANE, BACKUP_LANE))

_ACTIVE_COLLECTORS = {COLLECTION_LANE: None, BACKUP_LANE: None}
_ACTIVE_COLLECTOR_LOCK = threading.RLock()
_LANE_TASKS = {COLLECTION_LANE: None, BACKUP_LANE: None}
_LANE_TASK_ORIGINS = {COLLECTION_LANE: None, BACKUP_LANE: None}
_LANE_TASK_LOCK = threading.RLock()
_LANE_CANCEL = {
    COLLECTION_LANE: threading.Event(), BACKUP_LANE: threading.Event(),
}
_CONTINUOUS_STATE_LOCK = threading.RLock()
_SHUTDOWN_SIGNAL = None
_CONTINUOUS_COLLECTION_INTERVAL_SECONDS = 0
_CONTINUOUS_COLLECTION_NEXT_RUN = 0.0
_CONTINUOUS_COLLECTION_STOP_REQUESTED = False
_CONTINUOUS_BACKUP_PASSWORD = None
_CONTINUOUS_BACKUP_INTERVAL_SECONDS = 0
_CONTINUOUS_BACKUP_NEXT_RUN = 0.0
_CONTINUOUS_BACKUP_STOP_REQUESTED = False

_COOLDOWN_STATUS_FIELDS = (
    "cooldown_seconds", "last_success_at", "next_allowed_epoch",
    "next_allowed_at",
)


def timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _write_status_file(path: Path, prefix: str, state: str, **extra) -> None:
    STATUS_DIR.mkdir(parents=True, exist_ok=True)
    payload = {"state": state, "updated_at": timestamp(), **extra}
    descriptor, temporary = tempfile.mkstemp(prefix=prefix, dir=STATUS_DIR)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _active_cooldown_fields(path: Path) -> dict:
    """Preserve an unexpired cooldown while a status moves through other states."""
    descriptor = -1
    try:
        flags = (
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > 64 * 1024
        ):
            return {}
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            descriptor = -1
            payload = json.load(stream)
        if not isinstance(payload, dict):
            return {}
        next_epoch = payload.get("next_allowed_epoch")
        if (
            isinstance(next_epoch, bool)
            or not isinstance(next_epoch, (int, float))
            or not math.isfinite(float(next_epoch))
            or float(next_epoch) <= time.time()
        ):
            return {}
        return {
            name: payload[name]
            for name in _COOLDOWN_STATUS_FIELDS if name in payload
        }
    except (OSError, OverflowError, TypeError, ValueError, json.JSONDecodeError):
        return {}
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def write_status(state: str, **extra) -> None:
    retained = _active_cooldown_fields(STATUS_FILE)
    retained.update(extra)
    _write_status_file(STATUS_FILE, ".switch-collection.", state, **retained)


def write_yaml_backup_status(state: str, **extra) -> None:
    retained = _active_cooldown_fields(YAML_BACKUP_STATUS_FILE)
    retained.update(extra)
    _write_status_file(YAML_BACKUP_STATUS_FILE, ".yaml-backup.", state, **retained)


def write_continuous_status(state: str, **extra) -> None:
    _write_status_file(
        CONTINUOUS_STATUS_FILE, ".continuous-collection.", state, **extra,
    )


def write_continuous_backup_status(state: str, **extra) -> None:
    _write_status_file(
        CONTINUOUS_BACKUP_STATUS_FILE, ".continuous-backup.", state, **extra,
    )


def _validated_password(value) -> str:
    if not isinstance(value, str):
        raise ValueError("password must be text")
    payload = value.encode("utf-8")
    if len(payload) > MAX_PASSWORD_BYTES:
        raise ValueError("password exceeds 1024 bytes")
    if any(marker in value for marker in ("\x00", "\r", "\n")):
        raise ValueError("password contains a forbidden control character")
    return value


def decode_yaml_backup_request(payload: bytes) -> dict:
    """Decode one strict in-memory CGI request without logging its secret."""
    if not isinstance(payload, bytes) or len(payload) > MAX_MEMORY_REQUEST_BYTES:
        raise ValueError("invalid YAML backup request size")
    try:
        message = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid YAML backup request JSON") from exc
    if not isinstance(message, dict) or not isinstance(message.get("action"), str):
        raise ValueError("invalid YAML backup request schema")
    action = message["action"]
    if action == "yaml_backup":
        if set(message) != {"action", "password"}:
            raise ValueError("invalid YAML backup request schema")
        return {"action": action, "password": _validated_password(message["password"])}
    if action == "continuous_collection_start":
        if set(message) != {"action", "interval_minutes"}:
            raise ValueError("invalid continuous collection request schema")
        interval = message["interval_minutes"]
        if (
            isinstance(interval, bool) or not isinstance(interval, int)
            or not MIN_CONTINUOUS_INTERVAL_MINUTES
            <= interval <= MAX_CONTINUOUS_INTERVAL_MINUTES
        ):
            raise ValueError("invalid continuous collection interval")
        return {
            "action": action,
            "interval_minutes": interval,
        }
    if action == "continuous_backup_start":
        if set(message) != {"action", "password", "interval_minutes"}:
            raise ValueError("invalid continuous backup request schema")
        interval = message["interval_minutes"]
        if (
            isinstance(interval, bool) or not isinstance(interval, int)
            or not MIN_CONTINUOUS_INTERVAL_MINUTES
            <= interval <= MAX_CONTINUOUS_INTERVAL_MINUTES
        ):
            raise ValueError("invalid continuous backup interval")
        return {
            "action": action,
            "password": _validated_password(message["password"]),
            "interval_minutes": interval,
        }
    if action in {
        "continuous_collection_stop", "continuous_backup_stop",
    } and set(message) == {"action"}:
        return {"action": action}
    raise ValueError("unsupported YAML backup request action")


def open_memory_socket(path: Path = YAML_BACKUP_SOCKET):
    """Bind the root worker's private datagram endpoint for the CGI."""
    if sys.platform == "darwin" and os.geteuid() != 0:
        # macOS is configuration-generation/test mode only; its sandbox can
        # reject filesystem AF_UNIX binds.  Keep the worker lifecycle testable
        # without publishing a control endpoint that cannot be served there.
        class DisabledMemorySocket:
            def recv(self, _size):
                raise BlockingIOError()

            def close(self):
                return None

        return DisabledMemorySocket(), None
    path = Path(path)
    if os.path.lexists(path):
        metadata = os.lstat(path)
        if (
            not stat.S_ISSOCK(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
        ):
            raise OSError(f"unsafe existing YAML backup socket: {path}")
        path.unlink()
    endpoint = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        endpoint.bind(str(path))
        os.chmod(path, 0o660)
        if os.geteuid() == 0:
            os.chown(path, 0, grp.getgrnam("www-data").gr_gid)
        elif sys.platform != "darwin":
            raise PermissionError("YAML backup socket worker must run as root")
        metadata = os.lstat(path)
        if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_nlink != 1:
            raise OSError(f"invalid YAML backup socket: {path}")
        endpoint.setblocking(False)
        return endpoint, (metadata.st_dev, metadata.st_ino)
    except Exception:
        endpoint.close()
        try:
            path.unlink()
        except OSError:
            pass
        raise


def close_memory_socket(endpoint, identity, path: Path = YAML_BACKUP_SOCKET) -> None:
    endpoint.close()
    if identity is None:
        return
    try:
        metadata = os.lstat(path)
        if (
            stat.S_ISSOCK(metadata.st_mode)
            and (metadata.st_dev, metadata.st_ino) == identity
        ):
            Path(path).unlink()
    except OSError:
        pass


def receive_memory_requests(endpoint) -> list[dict]:
    requests = []
    while True:
        try:
            payload = endpoint.recv(MAX_MEMORY_REQUEST_BYTES + 1)
        except BlockingIOError:
            return requests
        requests.append(decode_yaml_backup_request(payload))


def read_request() -> str:
    """Compatibility read helper using the same safe file contract as claim."""
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(REQUEST_FILE, flags)
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_SH)
            metadata = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_size > 64
            ):
                return ""
            value = stream.read(64).strip()
            return value if value == "collect" else ""
    except OSError:
        return ""


def claim_request(expected: str = "") -> str:
    """Atomically consume one exact request without erasing a newer action."""
    if expected and expected != "collect":
        return ""
    try:
        flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(REQUEST_FILE, flags)
        with os.fdopen(descriptor, "r+", encoding="utf-8") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            metadata = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_size > 64
            ):
                return ""
            current = stream.read().strip()
            if current != "collect" or (expected and current != expected):
                return ""
            stream.seek(0)
            stream.write("idle\n")
            stream.truncate()
            stream.flush()
            os.fsync(stream.fileno())
            return current
    except OSError as exc:
        print(f"[{timestamp()}] [WARN] cannot claim request: {exc}", flush=True)
        return ""


def commands_for_scope(scope: str, lock_wait: int = 600) -> list[list[str]]:
    commands = []
    wait_args = ["--wait-lock", str(max(lock_wait, 0))]
    if scope in {"air", "all"}:
        commands.append(["bash", str(SCRIPTS["ethernet"]), *wait_args, "--air"])
    if scope in {"prod", "all"}:
        commands.extend([
            ["bash", str(SCRIPTS["ethernet"]), *wait_args, "--prod"],
            ["bash", str(SCRIPTS["infiniband"]), *wait_args],
            ["bash", str(SCRIPTS["nvlink"]), *wait_args],
        ])
    return commands


def collection_process_ids(proc_root: Path = Path("/proc")) -> set[int]:
    """Find only processes whose argv contains one of our exact cron.sh paths."""
    if not proc_root.is_dir():
        return set()
    # argv preserves the path used to invoke a script.  IB and NVLink cron.sh
    # are deployment aliases of the Ethernet implementation, so resolving the
    # three paths would collapse them to one canonical filename and make stop
    # miss processes started through either alias.
    scripts = {str(path) for path in SCRIPTS.values()}
    scripts.update(str(path.resolve()) for path in SCRIPTS.values())
    parents: dict[int, int] = {}
    targets: set[int] = set()
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            argv = [item.decode("utf-8", errors="replace") for item in
                    (entry / "cmdline").read_bytes().split(b"\0") if item]
            stat_fields = (entry / "stat").read_text(encoding="utf-8").split(") ", 1)[1].split()
            parents[pid] = int(stat_fields[1])
        except (OSError, ValueError, IndexError):
            continue
        if any(argument in scripts for argument in argv):
            targets.add(pid)
    # Include SSH/SCP/sleep descendants belonging to those exact collectors.
    changed = True
    while changed:
        changed = False
        for pid, parent in parents.items():
            if parent in targets and pid not in targets:
                targets.add(pid)
                changed = True
    targets.discard(os.getpid())
    return targets


def _process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # Treat a group we cannot inspect as live so the shutdown contract
        # fails closed and still attempts the configured escalation.
        return True


def _signal_collector_group(process: subprocess.Popen, sig: int) -> bool:
    """Signal the private session created for one collector invocation."""
    try:
        os.killpg(process.pid, sig)
        return True
    except ProcessLookupError:
        return False
    except PermissionError as exc:
        print(
            f"[{timestamp()}] [WARN] cannot signal collector process group "
            f"{process.pid}: {exc}",
            file=sys.stderr, flush=True,
        )
        return False


def _wait_for_collector_group_exit(
    process: subprocess.Popen, timeout: float,
) -> bool:
    deadline = time.monotonic() + max(float(timeout), 0.0)
    while True:
        # poll() reaps the direct child while killpg(..., 0) also accounts for
        # descendants that remain after their group leader has exited.
        process.poll()
        if not _process_group_exists(process.pid):
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(COLLECTOR_EXIT_POLL_SECONDS, remaining))


def terminate_collector_process(
    process: subprocess.Popen,
    *,
    term_grace_seconds: float = COLLECTOR_TERM_GRACE_SECONDS,
    kill_grace_seconds: float = COLLECTOR_KILL_GRACE_SECONDS,
) -> bool:
    """Stop one collector session, escalating from TERM to KILL if needed."""
    if _process_group_exists(process.pid):
        _signal_collector_group(process, signal.SIGTERM)
    stopped = _wait_for_collector_group_exit(process, term_grace_seconds)
    if not stopped:
        _signal_collector_group(process, signal.SIGKILL)
        stopped = _wait_for_collector_group_exit(process, kill_grace_seconds)
    process.poll()
    return stopped


def _validate_lane(lane: str) -> str:
    if lane not in VALID_LANES:
        raise ValueError(f"invalid collection lane: {lane}")
    return lane


def _set_active_collector(
    process: subprocess.Popen, lane: str = COLLECTION_LANE,
) -> None:
    lane = _validate_lane(lane)
    with _ACTIVE_COLLECTOR_LOCK:
        if _ACTIVE_COLLECTORS[lane] is not None:
            raise RuntimeError(f"another {lane} process is already active")
        _ACTIVE_COLLECTORS[lane] = process


def _clear_active_collector(
    process: subprocess.Popen, lane: str = COLLECTION_LANE,
) -> None:
    lane = _validate_lane(lane)
    with _ACTIVE_COLLECTOR_LOCK:
        if _ACTIVE_COLLECTORS[lane] is process:
            _ACTIVE_COLLECTORS[lane] = None


def lane_cancelled(lane: str) -> bool:
    return _LANE_CANCEL[_validate_lane(lane)].is_set()


def lane_busy(lane: str, *, origin: str | None = None) -> bool:
    lane = _validate_lane(lane)
    with _LANE_TASK_LOCK:
        task = _LANE_TASKS[lane]
        return (
            task is not None and task.is_alive()
            and (origin is None or _LANE_TASK_ORIGINS[lane] == origin)
        )


def start_lane_task(lane: str, origin: str, target, *args) -> bool:
    """Start one lane task without serializing the other operation type."""
    lane = _validate_lane(lane)
    if origin not in {"manual", "continuous"} or not callable(target):
        raise ValueError("invalid lane task")

    def run() -> None:
        try:
            target(*args)
        except Exception as exc:  # defensive boundary for a persistent worker
            print(
                f"[{timestamp()}] [ERROR] unexpected {lane} task failure: "
                f"{type(exc).__name__}: {exc}", file=sys.stderr, flush=True,
            )
            traceback.print_exc()
        finally:
            if origin == "continuous":
                _finalize_continuous_stop_if_requested(lane)
            current = threading.current_thread()
            with _LANE_TASK_LOCK:
                if _LANE_TASKS[lane] is current:
                    _LANE_TASKS[lane] = None
                    _LANE_TASK_ORIGINS[lane] = None
                    _LANE_CANCEL[lane].clear()

    with _LANE_TASK_LOCK:
        current = _LANE_TASKS[lane]
        if current is not None and current.is_alive():
            return False
        _LANE_CANCEL[lane].clear()
        task = threading.Thread(
            target=run, name=f"switch-worker-{lane}-{origin}", daemon=False,
        )
        _LANE_TASKS[lane] = task
        _LANE_TASK_ORIGINS[lane] = origin
        task.start()
    return True


def request_lane_stop(lane: str, *, origin: str | None = None) -> bool:
    """Cancel only a matching active lane task; never cross operation types."""
    lane = _validate_lane(lane)
    with _LANE_TASK_LOCK:
        task = _LANE_TASKS[lane]
        if task is None or not task.is_alive():
            return False
        if origin is not None and _LANE_TASK_ORIGINS[lane] != origin:
            return False
        _LANE_CANCEL[lane].set()
    with _ACTIVE_COLLECTOR_LOCK:
        process = _ACTIVE_COLLECTORS[lane]
    if process is not None:
        _signal_collector_group(process, signal.SIGTERM)
    return True


def join_lane_tasks(timeout: float | None = None) -> None:
    deadline = None if timeout is None else time.monotonic() + max(timeout, 0.0)
    for lane in (COLLECTION_LANE, BACKUP_LANE):
        with _LANE_TASK_LOCK:
            task = _LANE_TASKS[lane]
        if task is None or task is threading.current_thread():
            continue
        remaining = None if deadline is None else max(0.0, deadline - time.monotonic())
        task.join(remaining)


def _request_shutdown(signum: int, _frame) -> None:
    """Record service shutdown and promptly TERM both detached child sessions."""
    global _SHUTDOWN_SIGNAL
    if _SHUTDOWN_SIGNAL is None:
        _SHUTDOWN_SIGNAL = int(signum)
    for lane in VALID_LANES:
        _LANE_CANCEL[lane].set()
        process = _ACTIVE_COLLECTORS[lane]
        if process is not None:
            _signal_collector_group(process, signal.SIGTERM)


def _shutdown_requested() -> bool:
    return _SHUTDOWN_SIGNAL is not None


def stop_all_collectors() -> list[int]:
    targets = collection_process_ids()
    for lane in VALID_LANES:
        _LANE_CANCEL[lane].set()
        process = _ACTIVE_COLLECTORS[lane]
        if process is not None:
            targets.add(process.pid)
            terminate_collector_process(process)
    targets.update(collection_process_ids())
    for sig in (signal.SIGTERM, signal.SIGKILL):
        for pid in sorted(targets, reverse=True):
            try:
                os.kill(pid, sig)
            except (OSError, ProcessLookupError):
                pass
        if sig == signal.SIGTERM and targets:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if not any((Path("/proc") / str(pid)).exists() for pid in targets):
                    return sorted(targets)
                time.sleep(0.2)
    return sorted(targets)


def run_interruptible(
    command: list[str], cwd: Path, timeout: int, *, pass_fds: tuple[int, ...] = (),
    lane: str = COLLECTION_LANE,
) -> tuple[dict, bool]:
    """Run one child while servicing only its lane's stop request."""
    lane = _validate_lane(lane)
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stdout_file, \
            tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stderr_file:
        if _shutdown_requested():
            return {
                "returncode": 128 + int(_SHUTDOWN_SIGNAL),
                "stdout": "", "stderr": "worker shutdown requested",
            }, True
        process = subprocess.Popen(
            command, cwd=cwd, text=True, stdout=stdout_file, stderr=stderr_file,
            stdin=subprocess.DEVNULL, start_new_session=True, pass_fds=pass_fds,
        )
        try:
            _set_active_collector(process, lane)
        except Exception:
            terminate_collector_process(process)
            raise
        deadline = time.monotonic() + timeout
        cancelled = False
        cleanup_succeeded = True
        try:
            while process.poll() is None:
                if _shutdown_requested() or lane_cancelled(lane):
                    cancelled = True
                    terminate_collector_process(process)
                    break
                if time.monotonic() >= deadline:
                    terminate_collector_process(process)
                    return {
                        "returncode": 124, "stdout": "",
                        "stderr": f"timeout after {timeout}s",
                    }, False
                time.sleep(0.2)
        finally:
            # This also handles exceptions in request processing and prevents
            # a detached session from surviving an unexpected worker failure.
            try:
                if _process_group_exists(process.pid):
                    cleanup_succeeded = terminate_collector_process(process)
            finally:
                _clear_active_collector(process, lane)
        if not cleanup_succeeded:
            raise RuntimeError(
                f"collector process group {process.pid} did not stop after escalation"
            )
        process.wait()
        stdout_file.seek(0)
        stderr_file.seek(0)
        return {"returncode": process.returncode,
                "stdout": stdout_file.read(), "stderr": stderr_file.read()}, cancelled


def _yaml_backup_scope(scope: str) -> str:
    return scope if scope in {"air", "prod"} else "auto"


def parse_task_result(output: str, expected_task: str) -> dict:
    """Validate one collector-owned machine result without trusting log text."""
    if expected_task not in {"switch_collection", "yaml_backup"}:
        raise ValueError("unsupported task result type")
    if not isinstance(output, str):
        raise ValueError("task output must be text")
    markers = [
        line[len(TASK_RESULT_PREFIX):]
        for line in output.splitlines()
        if line.startswith(TASK_RESULT_PREFIX)
    ]
    if len(markers) != 1:
        raise ValueError("task output must contain exactly one result marker")
    try:
        payload = json.loads(markers[0])
    except json.JSONDecodeError as exc:
        raise ValueError("task result is not valid JSON") from exc
    required = {
        "schema_version", "task", "state", "planned", "succeeded",
        "failed_count", "failed_devices",
    }
    if not isinstance(payload, dict) or set(payload) != required:
        raise ValueError("invalid task result schema")
    if payload["schema_version"] != 1 or payload["task"] != expected_task:
        raise ValueError("task result identity mismatch")
    if payload["state"] not in {"success", "partial", "failed"}:
        raise ValueError("invalid task result state")
    for name in ("planned", "succeeded", "failed_count"):
        value = payload[name]
        if (
            isinstance(value, bool) or not isinstance(value, int)
            or value < 0 or value > MAX_TASK_RESULT_DEVICES
        ):
            raise ValueError(f"invalid {name}")
    failures = payload["failed_devices"]
    if not isinstance(failures, list) or len(failures) > MAX_TASK_RESULT_DEVICES:
        raise ValueError("invalid failed_devices")
    seen = set()
    for item in failures:
        if not isinstance(item, dict) or set(item) != {
            "hostname", "operation", "reason",
        }:
            raise ValueError("invalid failed_devices entry")
        for name in ("hostname", "operation", "reason"):
            value = item[name]
            if (
                not isinstance(value, str) or not value.strip()
                or len(value.encode("utf-8")) > MAX_TASK_RESULT_TEXT_BYTES
                or any(marker in value for marker in ("\x00", "\r", "\n"))
            ):
                raise ValueError(f"invalid failed_devices {name}")
        folded = item["hostname"].casefold()
        if folded in seen:
            raise ValueError("duplicate failed device")
        seen.add(folded)
    if payload["failed_count"] != len(failures):
        raise ValueError("failed_count does not match failed_devices")
    if payload["succeeded"] + payload["failed_count"] != payload["planned"]:
        raise ValueError("task result counts do not match planned")
    state = payload["state"]
    if state == "success" and payload["failed_count"] != 0:
        raise ValueError("success task result contains failures")
    if state == "partial" and not (
        payload["succeeded"] > 0 and payload["failed_count"] > 0
    ):
        raise ValueError("partial task result requires success and failure")
    if state == "failed" and payload["succeeded"] != 0:
        raise ValueError("failed task result contains successes")
    return payload


def _task_result_status_fields(result: dict) -> dict:
    if result["state"] == "failed":
        summary = f"all {result['failed_count']} selected device(s) failed"
    else:
        summary = (
            f"completed with warnings: {result['failed_count']} device(s) failed"
        )
    return {
        "planned": result["planned"],
        "succeeded": result["succeeded"],
        "failed_count": result["failed_count"],
        "failed_devices": result["failed_devices"],
        "summary": summary,
    }


def run_yaml_backup(password: str, scope: str, timeout: int, lock_wait: int) -> bool:
    """Run the existing YAML collector with a shared password on an anonymous FD."""
    started_at = timestamp()
    write_yaml_backup_status("collecting", scope=scope, started_at=started_at)
    try:
        project = active_project_identity(HTTP_ROOT)
        with CollectionGate(
            project, scope, collection_keys=("yaml-backup",),
            status_dir=STATUS_DIR,
            cooldown_seconds=YAML_BACKUP_COOLDOWN_SECONDS,
            lock_wait_seconds=lock_wait,
            cancel_check=lambda: lane_cancelled(BACKUP_LANE),
            lane=BACKUP_LANE,
        ) as gate:
            if not gate.decision.allowed:
                finished_at = timestamp()
                if gate.decision.reason == "cooldown":
                    write_yaml_backup_status(
                        "success", scope=scope, started_at=started_at,
                        finished_at=finished_at, cooldown_skipped=True,
                        cooldown_seconds=gate.cooldown_seconds,
                        last_success_at=gate.decision.last_success_at,
                        next_allowed_at=gate.decision.next_allowed_at,
                        remaining_seconds=gate.decision.remaining_seconds,
                    )
                    return True
                write_yaml_backup_status(
                    "failed", scope=scope, started_at=started_at,
                    finished_at=finished_at,
                    reason="another managed collection is already running",
                )
                return False
            if not YAML_BACKUP_SCRIPT.is_file():
                write_yaml_backup_status(
                    "failed", scope=scope, started_at=started_at,
                    finished_at=timestamp(), reason="yaml-collect.py is missing",
                )
                return False
            password = _validated_password(password)
            read_fd, write_fd = os.pipe()
            try:
                try:
                    encoded = password.encode("utf-8")
                    view = memoryview(encoded)
                    while view:
                        written = os.write(write_fd, view)
                        view = view[written:]
                finally:
                    os.close(write_fd)
                command = [
                    sys.executable, str(YAML_BACKUP_SCRIPT), "-y", "--type",
                    _yaml_backup_scope(scope), "--password-fd", str(read_fd),
                ]
                result, cancelled = run_interruptible(
                    command, YAML_BACKUP_SCRIPT.parent, timeout,
                    pass_fds=(read_fd,),
                    lane=BACKUP_LANE,
                )
            finally:
                os.close(read_fd)
            if cancelled:
                write_yaml_backup_status(
                    "idle", scope=scope, stopped_at=timestamp(),
                )
                return False
            if result["stdout"]:
                print(
                    result["stdout"],
                    end="" if result["stdout"].endswith("\n") else "\n",
                    flush=True,
                )
            if result["stderr"]:
                print(
                    result["stderr"],
                    end="" if result["stderr"].endswith("\n") else "\n",
                    file=sys.stderr, flush=True,
                )
            task_result = parse_task_result(result["stdout"], "yaml_backup")
            if task_result["state"] == "failed":
                write_yaml_backup_status(
                    "failed", scope=scope, started_at=started_at,
                    finished_at=timestamp(),
                    reason="all selected devices failed",
                    **_task_result_status_fields(task_result),
                )
                return False
            if result["returncode"]:
                write_yaml_backup_status(
                    "failed", scope=scope, started_at=started_at,
                    finished_at=timestamp(),
                    reason=f"yaml-collect.py exit={result['returncode']}",
                )
                return False
            successful_at = gate.mark_success()
            next_epoch = time.time() + gate.cooldown_seconds
            write_yaml_backup_status(
                task_result["state"], scope=scope, started_at=started_at,
                finished_at=timestamp(), cooldown_seconds=gate.cooldown_seconds,
                last_success_at=successful_at, next_allowed_epoch=next_epoch,
                next_allowed_at=(
                    datetime.fromtimestamp(next_epoch).astimezone()
                    .isoformat(timespec="seconds")
                ),
                **(
                    _task_result_status_fields(task_result)
                    if task_result["state"] == "partial" else {}
                ),
            )
            return True
    except CollectionGateCancelled:
        write_yaml_backup_status("idle", scope=scope, stopped_at=timestamp())
        return False
    except (CollectionGateError, OSError, ValueError) as exc:
        write_yaml_backup_status(
            "failed", scope=scope, started_at=started_at,
            finished_at=timestamp(), reason=f"YAML backup failed: {type(exc).__name__}",
        )
        return False


def run_yaml_backup_safely(
    password: str, scope: str, timeout: int, lock_wait: int,
) -> bool:
    """Keep the persistent scheduler alive after an unexpected backup failure."""
    try:
        return run_yaml_backup(password, scope, timeout, lock_wait)
    except Exception as exc:  # defensive boundary for the long-running worker
        finished_at = timestamp()
        detail = f"{type(exc).__name__}: {exc}"
        write_yaml_backup_status(
            "failed", scope=scope, finished_at=finished_at,
            reason=f"unexpected YAML backup failure: {type(exc).__name__}",
        )
        print(
            f"[{finished_at}] [ERROR] unexpected YAML backup failure: {detail}",
            file=sys.stderr, flush=True,
        )
        traceback.print_exc()
        return False


def _validated_interval(message: dict, action: str) -> int:
    if message.get("action") != action:
        raise ValueError(f"{action} request required")
    interval = message.get("interval_minutes")
    if (
        isinstance(interval, bool) or not isinstance(interval, int)
        or not MIN_CONTINUOUS_INTERVAL_MINUTES
        <= interval <= MAX_CONTINUOUS_INTERVAL_MINUTES
    ):
        raise ValueError("invalid continuous interval")
    return interval


def continuous_collection_enabled() -> bool:
    with _CONTINUOUS_STATE_LOCK:
        return (
            _CONTINUOUS_COLLECTION_INTERVAL_SECONDS > 0
            or _CONTINUOUS_COLLECTION_STOP_REQUESTED
        )


def continuous_backup_enabled() -> bool:
    with _CONTINUOUS_STATE_LOCK:
        return (
            _CONTINUOUS_BACKUP_PASSWORD is not None
            or _CONTINUOUS_BACKUP_STOP_REQUESTED
        )


def continuous_collection_scheduled() -> bool:
    with _CONTINUOUS_STATE_LOCK:
        return (
            _CONTINUOUS_COLLECTION_INTERVAL_SECONDS > 0
            and not _CONTINUOUS_COLLECTION_STOP_REQUESTED
        )


def continuous_backup_scheduled() -> bool:
    with _CONTINUOUS_STATE_LOCK:
        return (
            _CONTINUOUS_BACKUP_PASSWORD is not None
            and not _CONTINUOUS_BACKUP_STOP_REQUESTED
        )


def configure_continuous_collection(message: dict) -> None:
    global _CONTINUOUS_COLLECTION_INTERVAL_SECONDS
    global _CONTINUOUS_COLLECTION_NEXT_RUN
    global _CONTINUOUS_COLLECTION_STOP_REQUESTED
    interval = _validated_interval(message, "continuous_collection_start")
    next_run = time.monotonic()
    with _CONTINUOUS_STATE_LOCK:
        write_continuous_status(
            "scheduled", enabled=True, interval_minutes=interval,
            message="continuous collection uses the collection cooldown only",
        )
        _CONTINUOUS_COLLECTION_INTERVAL_SECONDS = interval * 60
        _CONTINUOUS_COLLECTION_NEXT_RUN = next_run
        _CONTINUOUS_COLLECTION_STOP_REQUESTED = False


def configure_continuous_backup(message: dict) -> None:
    global _CONTINUOUS_BACKUP_PASSWORD, _CONTINUOUS_BACKUP_INTERVAL_SECONDS
    global _CONTINUOUS_BACKUP_NEXT_RUN
    global _CONTINUOUS_BACKUP_STOP_REQUESTED
    interval = _validated_interval(message, "continuous_backup_start")
    password = _validated_password(message.get("password"))
    next_run = time.monotonic()
    with _CONTINUOUS_STATE_LOCK:
        write_continuous_backup_status(
            "scheduled", enabled=True, interval_minutes=interval,
            message="password is held only in worker memory",
        )
        _CONTINUOUS_BACKUP_PASSWORD = password
        _CONTINUOUS_BACKUP_INTERVAL_SECONDS = interval * 60
        _CONTINUOUS_BACKUP_NEXT_RUN = next_run
        _CONTINUOUS_BACKUP_STOP_REQUESTED = False


def stop_continuous_collection_mode(reason: str) -> None:
    global _CONTINUOUS_COLLECTION_INTERVAL_SECONDS
    global _CONTINUOUS_COLLECTION_NEXT_RUN
    global _CONTINUOUS_COLLECTION_STOP_REQUESTED
    with _CONTINUOUS_STATE_LOCK:
        was_enabled = (
            _CONTINUOUS_COLLECTION_INTERVAL_SECONDS > 0
            or _CONTINUOUS_COLLECTION_STOP_REQUESTED
        )
        _CONTINUOUS_COLLECTION_INTERVAL_SECONDS = 0
        _CONTINUOUS_COLLECTION_NEXT_RUN = 0.0
        if was_enabled and lane_busy(COLLECTION_LANE, origin="continuous"):
            _CONTINUOUS_COLLECTION_STOP_REQUESTED = True
            write_continuous_status(
                "stopping", enabled=True, reason=reason,
                message="waiting for the current collection task to finish",
            )
        else:
            _CONTINUOUS_COLLECTION_STOP_REQUESTED = False
            write_continuous_status("stopped", enabled=False, reason=reason)


def stop_continuous_backup_mode(reason: str) -> None:
    global _CONTINUOUS_BACKUP_PASSWORD, _CONTINUOUS_BACKUP_INTERVAL_SECONDS
    global _CONTINUOUS_BACKUP_NEXT_RUN
    global _CONTINUOUS_BACKUP_STOP_REQUESTED
    with _CONTINUOUS_STATE_LOCK:
        was_enabled = (
            _CONTINUOUS_BACKUP_PASSWORD is not None
            or _CONTINUOUS_BACKUP_STOP_REQUESTED
        )
        _CONTINUOUS_BACKUP_PASSWORD = None
        _CONTINUOUS_BACKUP_INTERVAL_SECONDS = 0
        _CONTINUOUS_BACKUP_NEXT_RUN = 0.0
        if was_enabled and lane_busy(BACKUP_LANE, origin="continuous"):
            _CONTINUOUS_BACKUP_STOP_REQUESTED = True
            write_continuous_backup_status(
                "stopping", enabled=True, reason=reason,
                message="waiting for the current backup task to finish",
            )
        else:
            _CONTINUOUS_BACKUP_STOP_REQUESTED = False
            write_continuous_backup_status("stopped", enabled=False, reason=reason)


def _finalize_continuous_stop_if_requested(lane: str) -> bool:
    """Publish stopped only after the selected continuous task has drained."""
    global _CONTINUOUS_COLLECTION_STOP_REQUESTED
    global _CONTINUOUS_BACKUP_STOP_REQUESTED
    lane = _validate_lane(lane)
    with _CONTINUOUS_STATE_LOCK:
        if lane == COLLECTION_LANE and _CONTINUOUS_COLLECTION_STOP_REQUESTED:
            _CONTINUOUS_COLLECTION_STOP_REQUESTED = False
            write_continuous_status(
                "stopped", enabled=False, reason="current collection task finished",
            )
            return True
        if lane == BACKUP_LANE and _CONTINUOUS_BACKUP_STOP_REQUESTED:
            _CONTINUOUS_BACKUP_STOP_REQUESTED = False
            write_continuous_backup_status(
                "stopped", enabled=False, reason="current backup task finished",
            )
            return True
    return False


def continuous_cooldown_wait(scope: str, lane: str) -> dict:
    """Read only the selected lane's manual/continuous shared cooldown."""
    lane = _validate_lane(lane)
    project = active_project_identity(HTTP_ROOT)
    keys = (
        collection_keys_for_scope(scope)
        if lane == COLLECTION_LANE else ("yaml-backup",)
    )
    with CollectionGate(
        project, scope, collection_keys=keys, status_dir=STATUS_DIR,
        cooldown_seconds=YAML_BACKUP_COOLDOWN_SECONDS,
        lock_wait_seconds=0, clock=time.time, lane=lane,
    ) as gate:
        decision = gate.decision
    if decision.allowed:
        return {}
    if decision.reason == "busy":
        return {
            "remaining_seconds": 1,
            "wait_reason": f"active {lane} task",
            "next_allowed_at": "",
        }
    if decision.reason == "cooldown":
        return {
            "remaining_seconds": decision.remaining_seconds,
            "wait_reason": f"{lane} cooldown",
            "next_allowed_at": decision.next_allowed_at or "",
        }
    raise CollectionGateError(
        f"unexpected continuous {lane} cooldown decision: {decision.reason}"
    )


def _schedule_after_wait(write_status_fn, interval_minutes: int, wait: dict) -> int:
    remaining = max(1, int(wait["remaining_seconds"]))
    next_epoch = time.time() + remaining
    write_status_fn(
        "waiting", enabled=True, interval_minutes=interval_minutes,
        remaining_seconds=remaining, wait_reason=wait["wait_reason"],
        next_run_at=(
            wait.get("next_allowed_at")
            or datetime.fromtimestamp(next_epoch).astimezone()
            .isoformat(timespec="seconds")
        ),
    )
    return remaining


def run_continuous_collection_cycle(
    scope: str, timeout: int, lock_wait: int,
) -> bool:
    global _CONTINUOUS_COLLECTION_NEXT_RUN
    with _CONTINUOUS_STATE_LOCK:
        if _CONTINUOUS_COLLECTION_INTERVAL_SECONDS <= 0:
            return False
        interval_seconds = _CONTINUOUS_COLLECTION_INTERVAL_SECONDS
        interval_minutes = interval_seconds // 60
    try:
        wait = continuous_cooldown_wait(scope, COLLECTION_LANE)
    except CollectionGateError as exc:
        stop_continuous_collection_mode("cooldown gate failed")
        write_continuous_status(
            "failed", enabled=False, interval_minutes=interval_minutes,
            reason=f"continuous collection cooldown gate: {type(exc).__name__}",
        )
        return False
    if wait:
        with _CONTINUOUS_STATE_LOCK:
            if _CONTINUOUS_COLLECTION_STOP_REQUESTED:
                _finalize_continuous_stop_if_requested(COLLECTION_LANE)
                return False
            if _CONTINUOUS_COLLECTION_INTERVAL_SECONDS <= 0:
                return False
            _CONTINUOUS_COLLECTION_NEXT_RUN = (
                time.monotonic()
                + _schedule_after_wait(
                    write_continuous_status, interval_minutes, wait,
                )
            )
        return True
    with _CONTINUOUS_STATE_LOCK:
        if _CONTINUOUS_COLLECTION_STOP_REQUESTED:
            _finalize_continuous_stop_if_requested(COLLECTION_LANE)
            return False
        if _CONTINUOUS_COLLECTION_INTERVAL_SECONDS <= 0:
            return False
        write_continuous_status(
            "running", enabled=True, interval_minutes=interval_minutes,
            started_at=timestamp(),
        )
    result = collect_safely(scope, timeout, lock_wait)
    with _CONTINUOUS_STATE_LOCK:
        if _CONTINUOUS_COLLECTION_STOP_REQUESTED:
            _finalize_continuous_stop_if_requested(COLLECTION_LANE)
            return result
        if _CONTINUOUS_COLLECTION_INTERVAL_SECONDS <= 0:
            return False
        _CONTINUOUS_COLLECTION_NEXT_RUN = time.monotonic() + interval_seconds
        next_epoch = time.time() + interval_seconds
        write_continuous_status(
            "scheduled", enabled=True, interval_minutes=interval_minutes,
            finished_at=timestamp(), collection_ok=result,
            next_run_at=datetime.fromtimestamp(next_epoch).astimezone().isoformat(
                timespec="seconds"
            ),
        )
    return result


def run_continuous_backup_cycle(
    scope: str, timeout: int, lock_wait: int,
) -> bool:
    global _CONTINUOUS_BACKUP_NEXT_RUN
    with _CONTINUOUS_STATE_LOCK:
        password = _CONTINUOUS_BACKUP_PASSWORD
        if password is None:
            return False
        interval_seconds = _CONTINUOUS_BACKUP_INTERVAL_SECONDS
        interval_minutes = interval_seconds // 60
    try:
        wait = continuous_cooldown_wait(scope, BACKUP_LANE)
    except CollectionGateError as exc:
        stop_continuous_backup_mode("cooldown gate failed")
        write_continuous_backup_status(
            "failed", enabled=False, interval_minutes=interval_minutes,
            reason=f"continuous backup cooldown gate: {type(exc).__name__}",
        )
        return False
    if wait:
        with _CONTINUOUS_STATE_LOCK:
            if _CONTINUOUS_BACKUP_STOP_REQUESTED:
                _finalize_continuous_stop_if_requested(BACKUP_LANE)
                return False
            if _CONTINUOUS_BACKUP_PASSWORD is None:
                return False
            _CONTINUOUS_BACKUP_NEXT_RUN = (
                time.monotonic()
                + _schedule_after_wait(
                    write_continuous_backup_status, interval_minutes, wait,
                )
            )
        return True
    with _CONTINUOUS_STATE_LOCK:
        if _CONTINUOUS_BACKUP_STOP_REQUESTED:
            _finalize_continuous_stop_if_requested(BACKUP_LANE)
            return False
        if _CONTINUOUS_BACKUP_PASSWORD is None:
            return False
        write_continuous_backup_status(
            "running", enabled=True, interval_minutes=interval_minutes,
            started_at=timestamp(),
        )
    result = run_yaml_backup_safely(password, scope, timeout, lock_wait)
    with _CONTINUOUS_STATE_LOCK:
        if _CONTINUOUS_BACKUP_STOP_REQUESTED:
            _finalize_continuous_stop_if_requested(BACKUP_LANE)
            return result
        if _CONTINUOUS_BACKUP_PASSWORD is None:
            return False
        _CONTINUOUS_BACKUP_NEXT_RUN = time.monotonic() + interval_seconds
        next_epoch = time.time() + interval_seconds
        write_continuous_backup_status(
            "scheduled", enabled=True, interval_minutes=interval_minutes,
            finished_at=timestamp(), backup_ok=result,
            next_run_at=datetime.fromtimestamp(next_epoch).astimezone().isoformat(
                timespec="seconds"
            ),
        )
    return result


def collect(scope: str, timeout: int, lock_wait: int) -> bool:
    started_at = timestamp()
    write_status("collecting", scope=scope, started_at=started_at)
    try:
        project = active_project_identity(HTTP_ROOT)
        with CollectionGate(
            project, scope, collection_keys=collection_keys_for_scope(scope),
            status_dir=STATUS_DIR, lock_wait_seconds=lock_wait,
            cancel_check=lambda: lane_cancelled(COLLECTION_LANE),
            lane=COLLECTION_LANE,
        ) as gate:
            decision = gate.decision
            if not decision.allowed:
                finished_at = timestamp()
                if decision.reason == "cooldown":
                    print(
                        f"[{finished_at}] [COOLDOWN] skipped; "
                        f"next collection allowed at {decision.next_allowed_at}",
                        flush=True,
                    )
                    write_status(
                        "success", scope=scope, started_at=started_at,
                        finished_at=finished_at, cooldown_skipped=True,
                        last_success_at=decision.last_success_at,
                        next_allowed_at=decision.next_allowed_at,
                        remaining_seconds=decision.remaining_seconds,
                    )
                    return True
                write_status(
                    "failed", scope=scope, started_at=started_at,
                    finished_at=finished_at,
                    reason="another managed Switch collection is already running",
                )
                return False

            errors = []
            task_results = []
            for command in commands_for_scope(scope, lock_wait):
                if lane_cancelled(COLLECTION_LANE):
                    write_status("idle", scope=scope, stopped_at=timestamp(),
                                 stopped_pids=[])
                    return False
                script = Path(command[1])
                if not script.is_file():
                    errors.append(f"script not found: {script}")
                    continue
                print(f"[{timestamp()}] [RUN] {' '.join(command)}", flush=True)
                result, cancelled = run_interruptible(
                    command, script.parent, timeout, lane=COLLECTION_LANE,
                )
                if cancelled:
                    write_status("idle", scope=scope, stopped_at=timestamp())
                    return False
                if result["stdout"]:
                    print(
                        result["stdout"],
                        end="" if result["stdout"].endswith("\n") else "\n",
                        flush=True,
                    )
                if result["stderr"]:
                    print(
                        result["stderr"],
                        end="" if result["stderr"].endswith("\n") else "\n",
                        file=sys.stderr, flush=True,
                    )
                try:
                    task_result = parse_task_result(
                        result["stdout"], "switch_collection",
                    )
                except ValueError as exc:
                    if result["returncode"]:
                        detail = (
                            result["stderr"].strip()
                            or result["stdout"].strip()
                            or "no detail"
                        )[-2000:]
                        errors.append(
                            f"{script.name} exit={result['returncode']}: {detail}"
                        )
                    else:
                        errors.append(f"{script.name}: {exc}")
                    continue
                if result["returncode"] and task_result["state"] != "failed":
                    errors.append(
                        f"{script.name} exit={result['returncode']} conflicts with "
                        f"task state={task_result['state']}"
                    )
                    continue
                task_results.append(task_result)

            failed_devices = []
            seen_failures = set()
            for task_result in task_results:
                for failure in task_result["failed_devices"]:
                    key = failure["hostname"].casefold()
                    if key not in seen_failures:
                        seen_failures.add(key)
                        failed_devices.append(failure)
            failed_devices.sort(key=lambda item: item["hostname"].casefold())
            planned = sum(task_result["planned"] for task_result in task_results)
            succeeded = sum(task_result["succeeded"] for task_result in task_results)
            failed_count = len(failed_devices)
            finished_at = timestamp()
            if not errors and planned > 0 and succeeded == 0:
                write_status(
                    "failed", scope=scope, started_at=started_at,
                    finished_at=finished_at,
                    reason="all selected devices failed",
                    planned=planned, succeeded=0, failed_count=failed_count,
                    failed_devices=failed_devices,
                    summary=f"all {failed_count} selected device(s) failed",
                )
                return False

            html_command = [sys.executable, str(HTML_SCRIPT)]
            if scope in {"air", "prod"}:
                html_command += ["--type", scope]
            if not errors:
                result = subprocess.run(
                    html_command, cwd=HTTP_ROOT, text=True,
                    capture_output=True, timeout=180, check=False,
                )
                if result.returncode:
                    errors.append(
                        (result.stderr.strip() or result.stdout.strip()
                         or "monitor.html generation failed")[-2000:]
                    )
            finished_at = timestamp()
            if errors:
                write_status(
                    "failed", scope=scope, started_at=started_at,
                    finished_at=finished_at, reason=" | ".join(errors),
                )
                return False
            successful_at = gate.mark_success()
            next_epoch = time.time() + gate.cooldown_seconds
            final_state = "partial" if failed_devices else "success"
            write_status(
                final_state, scope=scope, started_at=started_at,
                finished_at=finished_at, cooldown_seconds=gate.cooldown_seconds,
                last_success_at=successful_at,
                next_allowed_epoch=next_epoch,
                next_allowed_at=(
                    datetime.fromtimestamp(next_epoch).astimezone()
                    .isoformat(timespec="seconds")
                ),
                **(
                    {
                        "planned": planned,
                        "succeeded": succeeded,
                        "failed_count": failed_count,
                        "failed_devices": failed_devices,
                        "summary": (
                            f"completed with warnings: {failed_count} device(s) failed"
                        ),
                    }
                    if final_state == "partial" else {}
                ),
            )
            return True
    except CollectionGateCancelled:
        write_status(
            "idle", scope=scope, stopped_at=timestamp(), stopped_pids=[],
        )
        return False
    except CollectionGateError as exc:
        finished_at = timestamp()
        write_status(
            "failed", scope=scope, started_at=started_at,
            finished_at=finished_at, reason=f"collection cooldown gate: {exc}",
        )
        return False


def collect_safely(scope: str, timeout: int, lock_wait: int) -> bool:
    """Keep the persistent worker alive if one collection has an internal error."""
    try:
        return collect(scope, timeout, lock_wait)
    except Exception as exc:  # defensive boundary for the long-running worker
        finished_at = timestamp()
        detail = f"{type(exc).__name__}: {exc}"
        write_status("failed", scope=scope, finished_at=finished_at, reason=detail)
        print(f"[{finished_at}] [ERROR] unexpected collection failure: {detail}",
              file=sys.stderr, flush=True)
        traceback.print_exc()
        return False


def handle_memory_request(message: dict, scope: str, timeout: int, lock_wait: int) -> None:
    action = message["action"]
    if action == "yaml_backup":
        if continuous_backup_enabled():
            raise ValueError("manual YAML backup is disabled during continuous backup")
        write_yaml_backup_status("queued", scope=scope, queued_at=timestamp())
        if not start_lane_task(
            BACKUP_LANE, "manual", run_yaml_backup_safely,
            message["password"], scope, timeout, lock_wait,
        ):
            raise ValueError("another backup task is already running")
    elif action == "continuous_collection_start":
        if continuous_collection_enabled():
            raise ValueError("continuous collection is already enabled")
        if lane_busy(COLLECTION_LANE):
            raise ValueError("another collection task is already running")
        configure_continuous_collection(message)
    elif action == "continuous_backup_start":
        if continuous_backup_enabled():
            raise ValueError("continuous backup is already enabled")
        if lane_busy(BACKUP_LANE):
            raise ValueError("another backup task is already running")
        configure_continuous_backup(message)
    elif action == "continuous_collection_stop":
        stop_continuous_collection_mode("operator")
    elif action == "continuous_backup_stop":
        stop_continuous_backup_mode("operator")
    else:
        raise ValueError("unsupported memory request")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Switch Status independent collection worker")
    result.add_argument("--scope", choices=("air", "prod", "all"), required=True)
    result.add_argument("--poll", type=int, default=2)
    result.add_argument("--timeout", type=int, default=3600)
    result.add_argument("--lock-wait", type=int, default=600)
    return result


def main() -> int:
    global _SHUTDOWN_SIGNAL
    _SHUTDOWN_SIGNAL = None
    signal.signal(signal.SIGTERM, _request_shutdown)
    signal.signal(signal.SIGINT, _request_shutdown)
    args = parser().parse_args()
    STATUS_DIR.mkdir(parents=True, exist_ok=True)
    write_status("idle", scope=args.scope)
    write_yaml_backup_status("idle", scope=args.scope)
    stop_continuous_collection_mode("worker started")
    stop_continuous_backup_mode("worker started")
    memory_socket, socket_identity = open_memory_socket()
    try:
        while not _shutdown_requested():
            try:
                messages = receive_memory_requests(memory_socket)
            except ValueError as exc:
                write_yaml_backup_status(
                    "failed", scope=args.scope, finished_at=timestamp(),
                    reason=f"invalid in-memory request: {type(exc).__name__}",
                )
                messages = []
            for message in messages:
                try:
                    handle_memory_request(
                        message, args.scope, max(args.timeout, 60),
                        max(args.lock_wait, 0),
                    )
                except Exception as exc:
                    write_yaml_backup_status(
                        "failed", scope=args.scope, finished_at=timestamp(),
                        reason=f"memory request failed: {type(exc).__name__}",
                    )
                finally:
                    if "password" in message:
                        message["password"] = ""
            action = claim_request()
            if action == "collect":
                if continuous_collection_enabled():
                    write_status(
                        "failed", scope=args.scope, finished_at=timestamp(),
                        reason="manual collection is disabled during continuous collection",
                    )
                else:
                    write_status("queued", scope=args.scope, queued_at=timestamp())
                    if not start_lane_task(
                        COLLECTION_LANE, "manual", collect_safely,
                        args.scope, max(args.timeout, 60), max(args.lock_wait, 0),
                    ):
                        write_status(
                            "failed", scope=args.scope, finished_at=timestamp(),
                            reason="another collection task is already running",
                        )
            if (
                continuous_collection_scheduled()
                and time.monotonic() >= _CONTINUOUS_COLLECTION_NEXT_RUN
                and not lane_busy(COLLECTION_LANE)
                and not _shutdown_requested()
            ):
                start_lane_task(
                    COLLECTION_LANE, "continuous", run_continuous_collection_cycle,
                    args.scope, max(args.timeout, 60), max(args.lock_wait, 0),
                )
            if (
                continuous_backup_scheduled()
                and time.monotonic() >= _CONTINUOUS_BACKUP_NEXT_RUN
                and not lane_busy(BACKUP_LANE)
                and not _shutdown_requested()
            ):
                start_lane_task(
                    BACKUP_LANE, "continuous", run_continuous_backup_cycle,
                    args.scope, max(args.timeout, 60), max(args.lock_wait, 0),
                )
            time.sleep(max(args.poll, 1))
    finally:
        stop_continuous_collection_mode("worker stopped")
        stop_continuous_backup_mode("worker stopped")
        stop_all_collectors()
        join_lane_tasks(timeout=COLLECTOR_TERM_GRACE_SECONDS + COLLECTOR_KILL_GRACE_SECONDS)
        close_memory_socket(memory_socket, socket_identity)
        try:
            if int(PID_FILE.read_text().strip()) == os.getpid():
                PID_FILE.unlink(missing_ok=True)
        except (OSError, ValueError):
            pass
    if _SHUTDOWN_SIGNAL is not None:
        return 128 + int(_SHUTDOWN_SIGNAL)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
