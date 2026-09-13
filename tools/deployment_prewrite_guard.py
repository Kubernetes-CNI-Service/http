#!/usr/bin/env python3
"""Safely serialize a remote source-tree writer with the ZTP container.

The caller embeds these exact source bytes in the SSH command.  Consequently
an initial deployment and an upgrade from an older checkout do not execute a
possibly stale helper from the destination tree before overwriting it.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import signal
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from typing import Iterator, Optional, Sequence


CONTAINER_NAME = "http-ztp"
MANAGED_LABEL = "com.nvidia.http-ztp.managed"
HTTP_ROOT_LABEL = "com.nvidia.http-ztp.http-root"
DEFAULT_STATE_ROOT = Path("/var/lib/http-ztp-container/runtime")
ACTIVATION_NAME = "activation.json"
REBUILD_REQUIRED_NAME = "rebuild-required.json"
DEPLOYMENT_OWNER_NAME = "deployment-owner.json"
PENDING_SOURCE_UPDATE_NAME = "pending-source-update.json"
SYNC_MARKER_NAME = ".sync-code-in-progress"
SOURCE_MANIFEST_NAME = "infra/docker/deployment-source-manifest.json"
DEFAULT_DEPLOYMENT_LOCK_NAME = ".deployment.lock"
GUARD_CONTROL_ROOT_PATHS = frozenset({
    (DEFAULT_DEPLOYMENT_LOCK_NAME,),
    (SYNC_MARKER_NAME,),
})
SOURCE_SCAN_ROOTS = frozenset({
    "infra", "monitor", "ethernet", "infiniband", "nvlink", "ztp", "tools",
})
LOCK_READY = "DEPLOYMENT_LOCK_READY"
PREWRITE_REQUEST = "HTTP_ZTP_PREWRITE"
PREWRITE_READY = "HTTP_ZTP_PREWRITE_READY"
COMMIT_REQUEST = "HTTP_ZTP_COMMIT"
COMMIT_READY = "HTTP_ZTP_COMMIT_READY"
DOCKER_REBUILD_REQUIRED = "HTTP_ZTP_DOCKER_REBUILD_REQUIRED"
NO_MANAGED_DOCKER = "HTTP_ZTP_NO_MANAGED_DOCKER"
MAX_DEPLOYMENT_EXPANDED_BYTES = 64 * 1024 * 1024 * 1024
DEPLOYMENT_STAGING_RESERVE_BYTES = 64 * 1024 * 1024
MAX_TRANSACTION_PARENT_DIRECTORIES = 4096
DEPLOYMENT_NAMESPACE_MINIMUM_BYTES = 16 * 1024
_TEST_AFTER_STALE_VERIFY = None
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


class GuardError(RuntimeError):
    """The shared lock, container identity, or quiesce operation is unsafe."""


class GuardBusy(GuardError):
    """Another cooperating deployment transaction currently owns the lock."""


class _RootBootstrapJournal:
    """Identity-bound rollback authority for newly created root components."""

    def __init__(self) -> None:
        self.entries: list[tuple[int, str, tuple[int, int], str]] = []
        self.committed = False
        self.closed = False

    def record(
        self,
        parent_fd: int,
        name: str,
        identity: tuple[int, int],
        label: str,
    ) -> None:
        if self.committed or self.closed:
            raise GuardError("deployment root bootstrap journal is closed")
        self.entries.append((os.dup(parent_fd), name, identity, label))

    def _close(self) -> None:
        if self.closed:
            return
        errors = []
        for parent_fd, _name, _identity, _label in self.entries:
            try:
                os.close(parent_fd)
            except OSError as exc:
                errors.append(exc)
        self.closed = True
        if errors:
            raise GuardError(
                "cannot close deployment root bootstrap journal: "
                + "; ".join(str(error) for error in errors)
            )

    def commit(self) -> None:
        self._close()
        self.committed = True

    def rollback(self) -> None:
        if self.committed or self.closed:
            return
        errors = []
        try:
            for parent_fd, name, identity, label in reversed(self.entries):
                try:
                    _remove_unjournaled_created_directory(
                        parent_fd, name, identity, label,
                    )
                except GuardError as exc:
                    errors.append(exc)
        finally:
            try:
                self._close()
            except GuardError as exc:
                errors.append(exc)
        if errors:
            raise GuardError(
                "cannot completely roll back deployment root bootstrap: "
                + "; ".join(str(error) for error in errors)
            )


def ensure_deployment_root(http_root: Path) -> _RootBootstrapJournal:
    """Bootstrap missing root components without ever traversing a symlink."""
    if not http_root.is_absolute():
        raise GuardError("deployment root must be absolute")
    missing = []
    cursor = http_root
    while True:
        try:
            metadata = cursor.lstat()
            break
        except FileNotFoundError:
            missing.append(cursor)
            parent = cursor.parent
            if parent == cursor:
                raise GuardError("deployment root has no existing real ancestor")
            cursor = parent
        except OSError as exc:
            raise GuardError(f"cannot inspect deployment root ancestor: {exc}") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise GuardError("deployment root ancestor must be one real directory")
    try:
        if cursor.resolve(strict=True) != cursor:
            raise GuardError("deployment root ancestor must be canonical")
    except (OSError, RuntimeError) as exc:
        raise GuardError(f"cannot resolve deployment root ancestor: {exc}") from exc
    journal = _RootBootstrapJournal()
    descriptor = -1
    try:
        descriptor, ancestor_identity = _open_held_directory(
            cursor, "deployment root ancestor",
        )
        _assert_held_directory_path(
            cursor, descriptor, ancestor_identity, "deployment root ancestor",
        )
        for path in reversed(missing):
            component = path.name
            created_here = False
            created_identity: Optional[tuple[int, int]] = None
            try:
                os.mkdir(component, 0o755, dir_fd=descriptor)
                created_here = True
            except FileExistsError:
                pass
            except OSError as exc:
                raise GuardError(
                    f"cannot create deployment root component {path}: {exc}"
                ) from exc
            if created_here:
                created_identity = _bind_created_directory_or_roll_back(
                    descriptor, component,
                    f"created deployment root component {path}",
                )
                try:
                    journal.record(
                        descriptor, component, created_identity,
                        f"created deployment root component {path}",
                    )
                except BaseException as exc:
                    try:
                        _remove_unjournaled_created_directory(
                            descriptor, component, created_identity,
                            f"created deployment root component {path}",
                        )
                    except GuardError as cleanup_error:
                        raise GuardError(
                            f"cannot journal deployment root component {path} "
                            f"({exc}); rollback is incomplete: {cleanup_error}"
                        ) from exc
                    raise
                try:
                    os.fsync(descriptor)
                except OSError as exc:
                    raise GuardError(
                        f"cannot sync deployment root component {path}: {exc}"
                    ) from exc
            try:
                child = os.open(
                    component, _DIRECTORY_OPEN_FLAGS, dir_fd=descriptor,
                )
            except OSError as exc:
                raise GuardError(
                    f"cannot open deployment root component {path}: {exc}"
                ) from exc
            child_status = os.fstat(child)
            if (
                not stat.S_ISDIR(child_status.st_mode)
                or (
                    created_identity is not None
                    and (child_status.st_dev, child_status.st_ino)
                    != created_identity
                )
            ):
                os.close(child)
                raise GuardError(
                    f"deployment root component identity changed: {path}"
                )
            os.close(descriptor)
            descriptor = child
        final_status = os.fstat(descriptor)
        final_identity = (final_status.st_dev, final_status.st_ino)
        _assert_held_directory_path(
            http_root, descriptor, final_identity, "deployment root",
        )
        os.close(descriptor)
        descriptor = -1
        return journal
    except BaseException as exc:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            journal.rollback()
        except GuardError as rollback_error:
            raise GuardError(
                f"deployment root bootstrap failed ({exc}); {rollback_error}"
            ) from exc
        if isinstance(exc, GuardError):
            raise
        if isinstance(exc, OSError):
            raise GuardError(f"cannot bootstrap deployment root: {exc}") from exc
        raise


@contextmanager
def safe_lock(
    lock_path: Path, *, wait_seconds: float = 0,
) -> Iterator[int]:
    flags = os.O_RDWR | os.O_CREAT
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o644)
    except OSError as exc:
        raise GuardError(f"cannot open safe deployment lock: {exc}") from exc
    locked = False
    body_error: Optional[BaseException] = None
    try:
        try:
            descriptor_status = os.fstat(descriptor)
            path_status = os.lstat(lock_path)
        except OSError as exc:
            raise GuardError(f"cannot validate deployment lock: {exc}") from exc
        if (
            not stat.S_ISREG(descriptor_status.st_mode)
            or not stat.S_ISREG(path_status.st_mode)
            or descriptor_status.st_nlink != 1
            or path_status.st_nlink != 1
            or (descriptor_status.st_dev, descriptor_status.st_ino)
            != (path_status.st_dev, path_status.st_ino)
        ):
            raise GuardError("deployment lock must be one stable regular file")
        deadline = time.monotonic() + max(0.0, float(wait_seconds))
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                # Recheck after flock: a rename between open and acquisition
                # must not create a private split-lock inode.
                descriptor_status = os.fstat(descriptor)
                path_status = os.lstat(lock_path)
                if (
                    not stat.S_ISREG(path_status.st_mode)
                    or path_status.st_nlink != 1
                    or descriptor_status.st_nlink != 1
                    or (descriptor_status.st_dev, descriptor_status.st_ino)
                    != (path_status.st_dev, path_status.st_ino)
                ):
                    raise GuardError(
                        "deployment lock changed during acquisition"
                    )
                break
            except BlockingIOError as exc:
                if time.monotonic() >= deadline:
                    raise GuardBusy("deployment lock is busy") from exc
                time.sleep(0.1)
            except OSError as exc:
                raise GuardError(f"cannot acquire deployment lock: {exc}") from exc
        try:
            yield descriptor
        except BaseException as exc:
            body_error = exc
            raise
    finally:
        release_error = None
        if locked:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError as exc:
                release_error = GuardError(
                    f"cannot release deployment lock: {exc}"
                )
        try:
            os.close(descriptor)
        except OSError as exc:
            if release_error is None:
                release_error = GuardError(
                    f"cannot close deployment lock: {exc}"
                )
        if release_error is not None:
            if body_error is None:
                raise release_error
            print(
                f"[ERROR] {release_error}; original operation also failed: "
                f"{body_error}", file=sys.stderr, flush=True,
            )


def _safe_unlink(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise GuardError(f"cannot inspect {label}: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise GuardError(f"{label} must be one regular file")
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            current = os.fstat(descriptor)
            if (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise GuardError(f"{label} changed during validation")
        finally:
            os.close(descriptor)
        path.unlink()
    except OSError as exc:
        raise GuardError(f"cannot clear {label}: {exc}") from exc


def _read_stable_regular_bytes(
    path: Path, label: str, *, maximum_size: int = 16 * 1024 * 1024,
) -> bytes:
    """Read one bounded, single-link regular file through one no-follow fd."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        before = path.lstat()
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise GuardError(f"cannot open {label}: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or before.st_nlink != 1
            or opened.st_nlink != 1
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
            or opened.st_size < 0
            or opened.st_size > maximum_size
        ):
            raise GuardError(f"{label} must be one bounded stable regular file")
        chunks = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise GuardError(f"{label} was truncated while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise GuardError(f"{label} grew while reading")
        after = os.fstat(descriptor)
        if (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ) != (
            opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns
        ):
            raise GuardError(f"{label} changed while reading")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, payload: bytes, label: str) -> None:
    """Write all bytes even when the kernel reports a short write."""
    view = memoryview(payload)
    while view:
        try:
            written = os.write(descriptor, view)
        except OSError as exc:
            raise GuardError(f"cannot write {label}: {exc}") from exc
        if written <= 0:
            raise GuardError(f"cannot write {label}: zero-length write")
        view = view[written:]


def clear_activation_marker(path: Path) -> None:
    _safe_unlink(path, "container activation marker")


def write_rebuild_required(path: Path, reason: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        parent = path.parent.resolve(strict=True)
        if parent != path.parent:
            raise GuardError("container runtime state directory must be canonical")
        if os.path.lexists(path):
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise GuardError("rebuild-required marker must be one regular file")
        payload = json.dumps({
            "schema_version": 1,
            "required_at": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
        }, ensure_ascii=False, sort_keys=True) + "\n"
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", dir=path.parent,
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    except GuardError:
        raise
    except OSError as exc:
        raise GuardError(f"cannot publish rebuild-required marker: {exc}") from exc


def _read_deployment_owner_record(path: Path, http_root: Path) -> Optional[dict]:
    """Read the persistent Docker owner and its trusted source receipt digest."""
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise GuardError(f"cannot inspect Docker deployment owner: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise GuardError("Docker deployment owner must be one regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            current = os.fstat(descriptor)
            if (
                not stat.S_ISREG(current.st_mode)
                or current.st_nlink != 1
                or (current.st_dev, current.st_ino)
                != (metadata.st_dev, metadata.st_ino)
                or current.st_size > 4096
            ):
                raise GuardError("Docker deployment owner changed during validation")
            payload = os.read(descriptor, 4097)
            final = os.fstat(descriptor)
            if (
                (final.st_dev, final.st_ino, final.st_size)
                != (current.st_dev, current.st_ino, current.st_size)
            ):
                raise GuardError("Docker deployment owner changed while reading")
        finally:
            os.close(descriptor)
        value = json.loads(payload.decode("utf-8"))
    except GuardError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise GuardError(f"Docker deployment owner is unreadable: {exc}") from exc
    legacy = {
        "schema_version": 1, "runtime": "docker",
        "http_root": os.fspath(http_root),
    }
    if value == legacy:
        return {**legacy, "schema_version": 2, "source_manifest_sha256": None}
    if (
        not isinstance(value, dict)
        or set(value) != {
            "schema_version", "runtime", "http_root", "source_manifest_sha256",
        }
        or value.get("schema_version") != 2
        or value.get("runtime") != "docker"
        or value.get("http_root") != os.fspath(http_root)
        or (
            value.get("source_manifest_sha256") is not None
            and not __import__("re").fullmatch(
                r"[0-9a-f]{64}", str(value.get("source_manifest_sha256") or ""),
            )
        )
    ):
        raise GuardError("Docker deployment owner does not match this HTTP root")
    return value


def _read_deployment_owner(path: Path, http_root: Path) -> bool:
    return _read_deployment_owner_record(path, http_root) is not None


def write_deployment_owner(
    path: Path, http_root: Path, *,
    source_manifest_sha256: Optional[str] = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        if path.parent.resolve(strict=True) != path.parent:
            raise GuardError("container runtime state directory must be canonical")
        existing = (
            _read_deployment_owner_record(path, http_root)
            if os.path.lexists(path) else None
        )
        if source_manifest_sha256 is None and existing is not None:
            source_manifest_sha256 = existing.get("source_manifest_sha256")
        if source_manifest_sha256 is not None and not __import__("re").fullmatch(
            r"[0-9a-f]{64}", source_manifest_sha256,
        ):
            raise GuardError("Docker owner source manifest digest is invalid")
        expected = {
            "schema_version": 2,
            "runtime": "docker",
            "http_root": os.fspath(http_root),
            "source_manifest_sha256": source_manifest_sha256,
        }
        if existing == expected:
            return
        payload = json.dumps(
            expected, ensure_ascii=False, sort_keys=True,
        ) + "\n"
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", dir=path.parent,
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    except GuardError:
        raise
    except OSError as exc:
        raise GuardError(f"cannot publish Docker deployment owner: {exc}") from exc


def _inspect_container(runner, identifier: str = CONTAINER_NAME) -> Optional[dict]:
    try:
        result = runner(
            ["docker", "container", "inspect", identifier],
            capture_output=True, text=True, check=False, timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise GuardError(f"cannot inspect Docker container: {exc}") from exc
    if result.returncode != 0:
        detail = str(result.stderr or result.stdout or "").strip()
        if re_no_such_container(detail):
            return None
        raise GuardError(
            "cannot inspect Docker container"
            + (f": {detail}" if detail else f" (exit={result.returncode})")
        )
    try:
        payload = json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError) as exc:
        raise GuardError(f"Docker inspect returned invalid JSON: {exc}") from exc
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
        raise GuardError("Docker inspect returned an unexpected container set")
    return payload[0]


def re_no_such_container(detail: str) -> bool:
    lowered = str(detail).casefold()
    return (
        "no such object" in lowered or "no such container" in lowered
    ) and CONTAINER_NAME in lowered


def _container_unsafe_state(record: dict) -> bool:
    state = record.get("State")
    if not isinstance(state, dict):
        raise GuardError("Docker inspect is missing container state")
    return any(state.get(key) is True for key in ("Running", "Restarting", "Paused"))


def _validate_container_identity(record: dict, http_root: Path) -> None:
    identifier = str(record.get("Id") or "")
    if len(identifier) != 64 or any(character not in "0123456789abcdef" for character in identifier):
        raise GuardError("Docker container immutable ID is invalid")
    if record.get("Name") != f"/{CONTAINER_NAME}":
        raise GuardError("Docker container name identity is unexpected")
    config = record.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    if not isinstance(labels, dict):
        raise GuardError("Docker container ownership labels are missing")
    if labels.get(MANAGED_LABEL) != "true":
        raise GuardError("Docker managed ownership label does not match")
    if labels.get(HTTP_ROOT_LABEL) != os.fspath(http_root):
        raise GuardError("Docker HTTP-root ownership label does not match")
    mounts = record.get("Mounts")
    if not isinstance(mounts, list) or not any(
        isinstance(mount, dict)
        and mount.get("Type") == "bind"
        and mount.get("Source") == os.fspath(http_root)
        and mount.get("Destination") == os.fspath(http_root)
        and mount.get("RW") is True
        for mount in mounts
    ):
        raise GuardError(
            "Docker container must own the exact read-write /var/www/html bind"
        )


def _native_monitor_read(path: Path, maximum: int, label: str):
    flags = (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(os.fspath(path), flags)
    except OSError as exc:
        raise GuardError(f"cannot read {label} {path}: {exc}") from exc
    try:
        status = os.fstat(descriptor)
        content = os.read(descriptor, maximum + 1)
    finally:
        os.close(descriptor)
    if len(content) > maximum:
        raise GuardError(f"{label} is too large: {path}")
    return content, status


def _native_monitor_pid_authorities(http_root: Path):
    day0 = http_root / "DAY0-Prepare"
    try:
        projects = sorted(day0.iterdir(), key=lambda item: item.name)
    except FileNotFoundError:
        return ()
    except OSError as exc:
        raise GuardError(f"cannot enumerate Native Monitor projects: {exc}") from exc
    if len(projects) > 4096:
        raise GuardError("too many DAY0 entries to prove Native Monitor quiescence")
    records = []
    for project in projects:
        try:
            project_status = project.lstat()
        except OSError as exc:
            raise GuardError(f"cannot inspect DAY0 entry {project}: {exc}") from exc
        if not stat.S_ISDIR(project_status.st_mode):
            continue
        pid_path = project / "99-output-ztp/ztp-monitor.pid"
        try:
            path_status = pid_path.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise GuardError(f"cannot inspect Native Monitor PID file: {exc}") from exc
        if (not stat.S_ISREG(path_status.st_mode)
                or path_status.st_nlink != 1):
            raise GuardError(
                f"Native Monitor PID authority is unsafe: {pid_path}"
            )
        content, opened = _native_monitor_read(
            pid_path, 64, "Native Monitor PID file",
        )
        if (opened.st_dev, opened.st_ino) != (
            path_status.st_dev, path_status.st_ino,
        ):
            raise GuardError(f"Native Monitor PID authority changed: {pid_path}")
        try:
            rendered = content.decode("ascii").strip()
            pid = int(rendered)
        except (UnicodeDecodeError, ValueError) as exc:
            raise GuardError(f"Native Monitor PID is invalid: {pid_path}") from exc
        if not rendered.isdigit() or pid <= 1:
            raise GuardError(f"Native Monitor PID is invalid: {pid_path}")
        records.append((pid_path, path_status.st_dev, path_status.st_ino, content, pid))
    return tuple(records)


def _native_monitor_process(
    pid: int, http_root: Path, proc_root: Path, *, referenced: bool,
):
    process_path = proc_root / str(pid)
    try:
        process_status = process_path.stat()
    except FileNotFoundError:
        if referenced:
            raise GuardError(f"Native Monitor PID {pid} is stale")
        return None
    except OSError as exc:
        raise GuardError(f"cannot inspect Native Monitor PID {pid}: {exc}") from exc
    content, _opened = _native_monitor_read(
        process_path / "cmdline", 64 * 1024, f"process {pid} cmdline",
    )
    if not content:
        if referenced:
            raise GuardError(f"Native Monitor PID {pid} has empty cmdline")
        return None
    try:
        cmdline = tuple(
            token.decode("utf-8")
            for token in content.rstrip(b"\0").split(b"\0")
        )
    except UnicodeDecodeError as exc:
        raise GuardError(f"Native Monitor PID {pid} cmdline is invalid") from exc
    expected_script = (
        http_root / "DAY0-Prepare/12-ztp-monitor.py"
    ).resolve(strict=False)
    project_token = _native_monitor_project_from_argv(cmdline, expected_script)
    if project_token is None:
        if referenced:
            raise GuardError(f"Native Monitor PID {pid} identity mismatch")
        return None
    try:
        project = Path(project_token).resolve(strict=True)
    except OSError as exc:
        if referenced:
            raise GuardError(f"Native Monitor PID {pid} project is unreadable") from exc
        return None
    if (project.parent != http_root / "DAY0-Prepare"
            or project.name in {"", "template"}):
        if referenced:
            raise GuardError(f"Native Monitor PID {pid} project is out of scope")
        return None
    return (pid, process_status.st_dev, process_status.st_ino, cmdline)


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


def _same_native_pid_authority(record) -> bool:
    path, device, inode, content, _pid = record
    try:
        status = path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise GuardError(f"cannot revalidate Native Monitor PID file: {exc}") from exc
    if (status.st_dev, status.st_ino) != (device, inode):
        return False
    current, opened = _native_monitor_read(path, 64, "Native Monitor PID file")
    return (
        (opened.st_dev, opened.st_ino) == (device, inode)
        and current == content
    )


def stop_native_ztp_monitors(
    http_root: Path,
    *,
    proc_root=Path("/proc"),
    timeout: float = 5.0,
    kill=os.kill,
    monotonic=time.monotonic,
    sleep=time.sleep,
):
    """Embedded fail-closed Native Monitor stop for remote source writers."""
    root = http_root.resolve(strict=True)
    authorities = _native_monitor_pid_authorities(root)
    proc_root = Path(proc_root)
    if timeout <= 0 or timeout > 60:
        raise GuardError(
            "Native Monitor stop timeout must be in (0, 60] seconds"
        )
    if not proc_root.is_dir():
        if authorities:
            raise GuardError("cannot validate Native Monitor PID without /proc")
        return ()
    processes = {}
    for authority in authorities:
        process = _native_monitor_process(
            authority[4], root, proc_root, referenced=True,
        )
        processes[authority[4]] = process
    try:
        entries = [entry for entry in proc_root.iterdir() if entry.name.isdigit()]
    except OSError as exc:
        raise GuardError(f"cannot enumerate /proc for Native Monitor: {exc}") from exc
    if len(entries) > 131072:
        raise GuardError("too many processes to prove Native Monitor quiescence")
    for entry in sorted(entries, key=lambda item: int(item.name)):
        pid = int(entry.name)
        if pid in processes:
            continue
        process = _native_monitor_process(
            pid, root, proc_root, referenced=False,
        )
        if process is not None:
            processes[pid] = process
    ordered = tuple(processes[pid] for pid in sorted(processes))
    for authority in authorities:
        if not _same_native_pid_authority(authority):
            raise GuardError("Native Monitor PID authority changed before SIGTERM")
    for expected in ordered:
        if _native_monitor_process(
            expected[0], root, proc_root, referenced=True,
        ) != expected:
            raise GuardError(
                f"Native Monitor PID {expected[0]} changed before SIGTERM"
            )
    for process in ordered:
        try:
            kill(process[0], signal.SIGTERM)
        except OSError as exc:
            raise GuardError(
                f"cannot signal Native Monitor PID {process[0]}: {exc}"
            ) from exc
    deadline = monotonic() + timeout
    remaining = {process[0]: process for process in ordered}
    while remaining:
        for pid, expected in tuple(remaining.items()):
            try:
                status = (proc_root / str(pid)).stat()
            except FileNotFoundError:
                remaining.pop(pid)
                continue
            except OSError as exc:
                raise GuardError(f"cannot confirm Monitor PID {pid} exit: {exc}") from exc
            if (status.st_dev, status.st_ino) != (expected[1], expected[2]):
                remaining.pop(pid)
                continue
            current = _native_monitor_process(
                pid, root, proc_root, referenced=True,
            )
            if current != expected:
                remaining.pop(pid)
        if not remaining:
            break
        if monotonic() >= deadline:
            raise GuardError(
                "Native Monitor exit timeout: "
                + ", ".join(str(pid) for pid in sorted(remaining))
            )
        sleep(0.05)
    for authority in authorities:
        if authority[4] in processes and _same_native_pid_authority(authority):
            try:
                authority[0].unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise GuardError(f"cannot remove stopped Monitor PID file: {exc}") from exc
    return tuple(process[0] for process in ordered)


def quiesce_for_source_update(
    http_root: Path,
    *,
    state_root: Path = DEFAULT_STATE_ROOT,
    runner=subprocess.run,
    which=shutil.which,
    docker_requested: bool = False,
    native_requested: bool = False,
) -> bool:
    """Stop one owned container before source bytes can be replaced."""
    if native_requested:
        stop_native_ztp_monitors(http_root)
    owner_path = state_root / DEPLOYMENT_OWNER_NAME
    persistent_owner = _read_deployment_owner(owner_path, http_root)
    if which("docker") is None:
        if persistent_owner:
            raise GuardError(
                "Docker CLI is unavailable for a persistent Docker deployment"
            )
        if not docker_requested:
            return False
        clear_activation_marker(state_root / ACTIVATION_NAME)
        write_deployment_owner(owner_path, http_root)
        write_rebuild_required(
            state_root / REBUILD_REQUIRED_NAME,
            "Docker deployment requested; build and transaction load are required",
        )
        return True
    record = _inspect_container(runner)
    if record is None:
        if not (persistent_owner or docker_requested):
            return False
        clear_activation_marker(state_root / ACTIVATION_NAME)
        write_deployment_owner(owner_path, http_root)
        write_rebuild_required(
            state_root / REBUILD_REQUIRED_NAME,
            "Docker deployment is absent; build and transaction load are required",
        )
        return True
    _validate_container_identity(record, http_root)
    container_id = str(record["Id"])
    if _container_unsafe_state(record):
        try:
            result = runner(
                ["docker", "stop", "--time", "30", container_id],
                capture_output=True, text=True, check=False, timeout=45,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise GuardError(f"Docker stop failed: {exc}") from exc
        if result.returncode != 0:
            detail = str(result.stderr or result.stdout or "").strip()
            raise GuardError(
                "Docker stop failed"
                + (f": {detail}" if detail else f" (exit={result.returncode})")
            )
        record = _inspect_container(runner, container_id)
        if record is None:
            raise GuardError("owned Docker container vanished during stop")
        _validate_container_identity(record, http_root)
        if record.get("Id") != container_id:
            raise GuardError("Docker container identity changed during stop")
    if _container_unsafe_state(record):
        raise GuardError("Docker container did not reach a stable stopped state")
    status = str(record.get("State", {}).get("Status") or "").casefold()
    if status not in {"exited", "created"}:
        raise GuardError(f"Docker container stopped in unsafe state: {status or 'missing'}")
    state = record["State"]
    try:
        pid = int(state.get("Pid", 0))
    except (TypeError, ValueError) as exc:
        raise GuardError("Docker container stopped with invalid PID state") from exc
    if pid != 0 or state.get("Dead") is True:
        raise GuardError("Docker container did not reach a dead-free PID-zero state")
    clear_activation_marker(state_root / ACTIVATION_NAME)
    write_deployment_owner(owner_path, http_root)
    write_rebuild_required(
        state_root / REBUILD_REQUIRED_NAME,
        "repository source update requires a rebuilt http-ztp image",
    )
    return True


def _normalized_archive_parts(path: str) -> tuple[str, ...]:
    raw = PurePosixPath(path)
    if raw.is_absolute():
        raise GuardError(f"archive member is absolute: {path!r}")
    normalized = []
    for part in raw.parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not normalized:
                raise GuardError(f"archive member escapes root: {path!r}")
            normalized.pop()
        else:
            normalized.append(part)
    if not normalized:
        raise GuardError(f"archive member has an empty path: {path!r}")
    return tuple(normalized)


def _archive_member_parts(path: str) -> tuple[str, ...]:
    if any(component == ".." for component in path.split("/")):
        raise GuardError(
            f"archive member contains a raw traversal component: {path!r}"
        )
    return _normalized_archive_parts(path)


def lock_parts_within_root(
    http_root: Path, lock_path: Path,
) -> Optional[tuple[str, ...]]:
    """Return the caller's lexical lock path inside root, if it is inside."""
    root_absolute = Path(os.path.abspath(os.fspath(http_root)))
    lock_absolute = Path(os.path.abspath(os.fspath(lock_path)))
    try:
        relative = lock_absolute.relative_to(root_absolute)
    except ValueError:
        return None
    if not relative.parts:
        raise GuardError("deployment lock cannot be the deployment root")
    return _normalized_archive_parts(relative.as_posix())


def _is_private_guard_leaf(name: str) -> bool:
    return bool(__import__("re").fullmatch(
        r"\..+\.http-ztp-(?:new|old|stale)-[0-9a-f]{24}", name,
    ))


def _validate_archive_control_paths(
    members: list, *, lock_parts: Optional[tuple[str, ...]] = None,
) -> None:
    """Reject names whose inode or lifecycle belongs exclusively to this guard."""
    reserved_paths = GUARD_CONTROL_ROOT_PATHS | (
        frozenset({lock_parts}) if lock_parts is not None else frozenset()
    )
    for _member, parts, _kind in members:
        if (
            any(parts[:len(reserved)] == reserved for reserved in reserved_paths)
            or any(_is_private_guard_leaf(part) for part in parts)
        ):
            raise GuardError(
                "deployment archive contains a reserved guard control path: "
                + "/".join(parts)
            )


def _validated_archive_members(
    archive: tarfile.TarFile, *,
    lock_parts: Optional[tuple[str, ...]] = None,
):
    try:
        members = archive.getmembers()
    except tarfile.TarError as exc:
        raise GuardError(f"cannot enumerate deployment archive: {exc}") from exc
    if not members or len(members) > 200000:
        raise GuardError("deployment archive member count is unsafe")
    seen = {}
    expanded = 0
    result = []
    for member in members:
        parts = _archive_member_parts(member.name)
        if parts in seen:
            raise GuardError(f"duplicate archive member: {member.name!r}")
        if not (member.isdir() or member.isfile() or member.issym()):
            raise GuardError(f"unsupported archive member type: {member.name!r}")
        if member.size < 0:
            raise GuardError(f"archive member has an invalid size: {member.name!r}")
        if member.isfile():
            expanded += member.size
            if expanded > MAX_DEPLOYMENT_EXPANDED_BYTES:
                raise GuardError("deployment archive expanded size is unsafe")
        if member.issym():
            target = PurePosixPath(member.linkname)
            if not member.linkname or target.is_absolute():
                raise GuardError(f"archive symlink target is unsafe: {member.name!r}")
            _normalized_archive_parts(
                PurePosixPath(*parts[:-1], member.linkname).as_posix()
            )
        kind = "dir" if member.isdir() else "file" if member.isfile() else "symlink"
        seen[parts] = kind
        result.append((member, parts, kind))
    for _member, parts, _kind in result:
        for length in range(1, len(parts)):
            ancestor_kind = seen.get(parts[:length])
            if ancestor_kind is not None and ancestor_kind != "dir":
                raise GuardError(
                    "archive member has a non-directory ancestor: "
                    + "/".join(parts[:length])
                )
    _validate_archive_control_paths(result, lock_parts=lock_parts)
    return result


def _archive_stable_fields(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev, value.st_ino, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    )


def _hash_archive_descriptor(
    descriptor: int, expected_status: os.stat_result,
) -> str:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        remaining = expected_status.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise GuardError("deployment archive was truncated while hashing")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise GuardError("deployment archive grew while hashing")
        after = os.fstat(descriptor)
    except OSError as exc:
        raise GuardError(f"cannot hash deployment archive descriptor: {exc}") from exc
    if _archive_stable_fields(after) != _archive_stable_fields(expected_status):
        raise GuardError("deployment archive changed while hashing")
    return digest.hexdigest()


def _validated_archive_descriptor(
    descriptor: int, expected_sha256: str,
) -> os.stat_result:
    if not __import__("re").fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise GuardError("deployment archive SHA-256 is invalid")
    try:
        opened = os.fstat(descriptor)
    except OSError as exc:
        raise GuardError(f"cannot inspect deployment archive descriptor: {exc}") from exc
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_nlink != 1
        or opened.st_size < 0
    ):
        raise GuardError("deployment archive descriptor must be one stable regular file")
    if _hash_archive_descriptor(descriptor, opened) != expected_sha256:
        raise GuardError("deployment archive SHA-256 does not match")
    return opened


def _assert_archive_descriptor(
    descriptor: int, expected_status: os.stat_result, expected_sha256: str,
) -> None:
    try:
        current = os.fstat(descriptor)
    except OSError as exc:
        raise GuardError(f"deployment archive descriptor changed: {exc}") from exc
    if (
        not stat.S_ISREG(current.st_mode)
        or current.st_nlink != 1
        or _archive_stable_fields(current) != _archive_stable_fields(expected_status)
    ):
        raise GuardError("deployment archive descriptor identity changed")
    if _hash_archive_descriptor(descriptor, expected_status) != expected_sha256:
        raise GuardError("deployment archive descriptor digest changed")


def _archive_payload_nodes(members: list) -> int:
    nodes = set()
    for _member, parts, _kind in members:
        for length in range(1, len(parts) + 1):
            nodes.add(parts[:length])
    return len(nodes)


def _deployment_capacity_budget(
    members: list, fragment_size: int, *, extra_nodes: int = 0,
) -> tuple[int, int]:
    if type(fragment_size) is not int or fragment_size <= 0:
        raise GuardError("deployment capacity fragment size is unsafe")
    if type(extra_nodes) is not int or extra_nodes < 0:
        raise GuardError("deployment capacity node allowance is unsafe")
    payload_nodes = _archive_payload_nodes(members) + extra_nodes
    allocated_file_bytes = sum(
        ((member.size + fragment_size - 1) // fragment_size) * fragment_size
        for member, _parts, kind in members
        if kind == "file"
    )
    required_bytes = (
        allocated_file_bytes
        + payload_nodes * max(fragment_size, DEPLOYMENT_NAMESPACE_MINIMUM_BYTES)
        + DEPLOYMENT_STAGING_RESERVE_BYTES
    )
    return required_bytes, payload_nodes + MAX_TRANSACTION_PARENT_DIRECTORIES


def _enforce_deployment_capacity(
    descriptor: int, members: list, *, extra_nodes: int, label: str,
) -> None:
    try:
        filesystem = os.fstatvfs(descriptor)
    except OSError as exc:
        raise GuardError(f"cannot inspect {label} capacity: {exc}") from exc
    fields = (
        getattr(filesystem, "f_bavail", None),
        getattr(filesystem, "f_frsize", None),
        getattr(filesystem, "f_files", None),
        getattr(filesystem, "f_favail", None),
    )
    available_blocks, fragment_size, total_inodes, available_inodes = fields
    if (
        any(type(value) is not int for value in fields)
        or available_blocks < 0
        or fragment_size <= 0
        or total_inodes < 0
        or available_inodes < 0
        or (total_inodes == 0 and available_inodes != 0)
        or (total_inodes > 0 and available_inodes > total_inodes)
    ):
        raise GuardError(f"{label} capacity metadata is unsafe")
    required_bytes, required_inodes = _deployment_capacity_budget(
        members, fragment_size, extra_nodes=extra_nodes,
    )
    available_bytes = available_blocks * fragment_size
    if available_bytes < required_bytes:
        raise GuardError(
            f"{label} capacity lacks blocks: required={required_bytes} "
            f"available={available_bytes}"
        )
    if total_inodes == 0 and available_inodes == 0:
        print(
            f"[INFO] {label} inode budget skipped: filesystem reports "
            "unreported/dynamic inode limits (f_files=0, f_favail=0)",
            flush=True,
        )
    elif available_inodes < required_inodes:
        raise GuardError(
            f"{label} capacity lacks inodes: required={required_inodes} "
            f"available={available_inodes}"
        )


def _remove_archive_staging(staging: Path) -> None:
    try:
        shutil.rmtree(staging)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise GuardError(f"cannot clean deployment archive staging: {exc}") from exc


def _extract_archive_staging_descriptor(
    descriptor: int,
    expected_sha256: str,
    *,
    lock_parts: Optional[tuple[str, ...]] = None,
) -> tuple[Path, list]:
    opened = _validated_archive_descriptor(descriptor, expected_sha256)
    staging = None
    staging_parent_fd = -1
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            try:
                with tarfile.open(fileobj=stream, mode="r:gz") as archive:
                    members = _validated_archive_members(
                        archive, lock_parts=lock_parts,
                    )
                    explicit_directories = sum(
                        1 for _member, _parts, kind in members if kind == "dir"
                    )
                    if explicit_directories > MAX_TRANSACTION_PARENT_DIRECTORIES:
                        raise GuardError(
                            "deployment transaction has too many explicit directories"
                        )
                    _validate_transaction_parent_budget(
                        parts for _member, parts, _kind in members
                    )
                    staging_parent = Path(tempfile.gettempdir()).resolve(strict=True)
                    staging_parent_fd, staging_parent_identity = _open_held_directory(
                        staging_parent, "deployment extraction staging parent",
                    )
                    _enforce_deployment_capacity(
                        staging_parent_fd, members, extra_nodes=1,
                        label="deployment expanded staging",
                    )
                    _assert_held_directory_path(
                        staging_parent, staging_parent_fd, staging_parent_identity,
                        "deployment extraction staging parent",
                    )
                    staging = Path(tempfile.mkdtemp(
                        prefix="http-deployment-overlay.",
                        dir=os.fspath(staging_parent),
                    )).resolve(strict=True)
                    if staging.parent != staging_parent:
                        raise GuardError("deployment extraction staging escaped its parent")
                    os.chmod(staging, 0o700)
                    staging_descriptor, staging_identity = _open_held_directory(
                        staging, "deployment extraction staging root",
                    )
                    try:
                        _assert_held_directory_path(
                            staging, staging_descriptor, staging_identity,
                            "deployment extraction staging root",
                        )
                    finally:
                        os.close(staging_descriptor)
                    for member, parts, kind in sorted(
                        members, key=lambda item: (len(item[1]), item[1]),
                    ):
                        destination = staging.joinpath(*parts)
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        if kind == "dir":
                            # Keep extraction directories traversable inside the
                            # private stage.  The requested mode is applied by
                            # the transactional live promotion, not trusted for
                            # staging lifecycle or cleanup.
                            destination.mkdir(mode=0o700, exist_ok=True)
                            os.chmod(destination, 0o700)
                        elif kind == "file":
                            source = archive.extractfile(member)
                            if source is None:
                                raise GuardError(
                                    f"archive member is unreadable: {member.name!r}"
                                )
                            output = os.open(
                                destination,
                                os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                | getattr(os, "O_CLOEXEC", 0)
                                | getattr(os, "O_NOFOLLOW", 0),
                                0o600,
                            )
                            try:
                                remaining = member.size
                                while remaining:
                                    chunk = source.read(min(remaining, 1024 * 1024))
                                    if not chunk:
                                        raise GuardError(
                                            f"archive member is truncated: {member.name!r}"
                                        )
                                    _write_all(
                                        output, chunk,
                                        f"archive member {member.name!r}",
                                    )
                                    remaining -= len(chunk)
                                if source.read(1):
                                    raise GuardError(
                                        f"archive member grew while reading: {member.name!r}"
                                    )
                                os.fchmod(output, member.mode & 0o777)
                                os.fsync(output)
                            finally:
                                os.close(output)
                        else:
                            os.symlink(member.linkname, destination)
            except (OSError, tarfile.TarError) as exc:
                if isinstance(exc, GuardError):
                    raise
                raise GuardError(f"cannot stage deployment archive: {exc}") from exc
        _assert_archive_descriptor(descriptor, opened, expected_sha256)
        return staging, members
    except BaseException as exc:
        if staging is not None:
            try:
                _remove_archive_staging(staging)
            except GuardError as cleanup_error:
                raise GuardError(
                    f"deployment archive staging failed ({exc}); {cleanup_error}"
                ) from exc
        raise
    finally:
        if staging_parent_fd >= 0:
            os.close(staging_parent_fd)


def _extract_archive_staging(
    archive_path: Path,
    expected_sha256: str,
    *,
    lock_parts: Optional[tuple[str, ...]] = None,
) -> tuple[Path, list]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        metadata = archive_path.lstat()
        descriptor = os.open(archive_path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or (metadata.st_dev, metadata.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise GuardError("deployment archive must be one stable regular file")
        result = _extract_archive_staging_descriptor(
            descriptor, expected_sha256, lock_parts=lock_parts,
        )
        current = archive_path.lstat()
        if (
            (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
            or current.st_nlink != 1
        ):
            staging, _members = result
            _remove_archive_staging(staging)
            raise GuardError("deployment archive path changed during extraction")
        return result
    except GuardError:
        raise
    except OSError as exc:
        raise GuardError(f"cannot open deployment archive: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _manifest_records_from_bytes(manifest_bytes: bytes, label: str) -> dict[str, dict]:
    try:
        payload = json.loads(manifest_bytes.decode("ascii"))
        if (
            not isinstance(payload, dict)
            or set(payload) != {"schema_version", "files"}
            or payload.get("schema_version") != 1
            or not isinstance(payload.get("files"), list)
        ):
            raise GuardError(f"source manifest has an invalid schema: {label}")
        values = payload["files"]
    except GuardError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise GuardError(f"source manifest is unreadable: {label}: {exc}") from exc
    return _validated_source_records(values, label)


def _validated_source_records(
    values, label: str, *, allow_empty: bool = False,
) -> dict[str, dict]:
    if not isinstance(values, list) or (not values and not allow_empty):
        raise GuardError(f"source manifest membership is empty: {label}")
    records = {}
    for record in values:
        if (
            not isinstance(record, dict)
            or set(record) != {"path", "type", "target", "sha256"}
            or record.get("type") not in {"file", "symlink"}
            or not isinstance(record.get("path"), str)
            or record["path"] in records
            or not __import__("re").fullmatch(
                r"[0-9a-f]{64}", str(record.get("sha256") or ""),
            )
            or (record.get("type") == "file" and record.get("target") is not None)
            or (
                record.get("type") == "symlink"
                and (
                    not isinstance(record.get("target"), str)
                    or not record.get("target")
                    or PurePosixPath(record["target"]).is_absolute()
                )
            )
        ):
            raise GuardError(f"source manifest has an invalid record: {label}")
        parts = _normalized_archive_parts(record["path"])
        if "/".join(parts) != record["path"]:
            raise GuardError(f"source manifest path is not canonical: {label}")
        records[record["path"]] = dict(record)
    return records


def _open_manifest_parent(root: Path, parts: tuple[str, ...]) -> int:
    """Open a manifest member's real parent without following any symlink."""
    flags = (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0)
    )
    try:
        descriptor = os.open(root, flags)
    except OSError as exc:
        raise GuardError(f"cannot open source root safely: {exc}") from exc
    try:
        opened_root = os.fstat(descriptor)
        if not stat.S_ISDIR(opened_root.st_mode):
            raise GuardError("source root must be one real directory")
        for component in parts[:-1]:
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except OSError as exc:
                raise GuardError(
                    f"source manifest parent is not a real directory: {component}: {exc}"
                ) from exc
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _normalize_owned_manifest_path(
    root: Path,
    relative: str,
    *,
    record_type: str,
    target: Optional[str],
    target_uid: int,
    target_gid: int,
) -> None:
    """Normalize one exact manifest path through no-follow descriptors."""
    parts = _normalized_archive_parts(relative)
    parent_fd = _open_manifest_parent(root, parts)
    name = parts[-1]
    try:
        try:
            before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise GuardError(
                f"cannot inspect source ownership for {relative}: {exc}"
            ) from exc
        if before.st_nlink != 1:
            raise GuardError(f"source ownership path has unsafe hard links: {relative}")
        if record_type == "file":
            if not stat.S_ISREG(before.st_mode):
                raise GuardError(f"source ownership path is not regular: {relative}")
            flags = (
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                descriptor = os.open(name, flags, dir_fd=parent_fd)
            except OSError as exc:
                raise GuardError(
                    f"cannot open source ownership path {relative}: {exc}"
                ) from exc
            try:
                opened = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or opened.st_nlink != 1
                    or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                ):
                    raise GuardError(f"source ownership path changed: {relative}")
                if (opened.st_uid, opened.st_gid) != (target_uid, target_gid):
                    os.fchown(descriptor, target_uid, target_gid)
                after = os.fstat(descriptor)
            except OSError as exc:
                raise GuardError(
                    f"cannot normalize source ownership for {relative}: {exc}"
                ) from exc
            finally:
                os.close(descriptor)
        elif record_type == "symlink":
            if not stat.S_ISLNK(before.st_mode):
                raise GuardError(f"source ownership path is not a symlink: {relative}")
            try:
                before_target = os.readlink(name, dir_fd=parent_fd)
                if before_target != target:
                    raise GuardError(f"source ownership symlink changed: {relative}")
                if (before.st_uid, before.st_gid) != (target_uid, target_gid):
                    os.chown(
                        name, target_uid, target_gid,
                        dir_fd=parent_fd, follow_symlinks=False,
                    )
                after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                after_target = os.readlink(name, dir_fd=parent_fd)
            except OSError as exc:
                raise GuardError(
                    f"cannot normalize source symlink ownership for {relative}: {exc}"
                ) from exc
            if after_target != target:
                raise GuardError(f"source ownership symlink changed: {relative}")
        else:
            raise GuardError(f"source ownership record type is invalid: {relative}")
        try:
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise GuardError(
                f"cannot recheck source ownership for {relative}: {exc}"
            ) from exc
        if (
            (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino)
            or (current.st_uid, current.st_gid) != (target_uid, target_gid)
            or current.st_nlink != 1
        ):
            raise GuardError(f"source ownership did not converge safely: {relative}")
    finally:
        os.close(parent_fd)


def _normalize_manifest_tree_ownership(
    root: Path,
    records: dict[str, dict],
    *,
    target_uid: int = 0,
    target_gid: int = 0,
) -> None:
    """Make the exact Docker source authority root-owned before receipt."""
    if target_uid < 0 or target_gid < 0:
        raise GuardError("source ownership target is invalid")
    entries = {
        SOURCE_MANIFEST_NAME: {"type": "file", "target": None},
        **records,
    }
    for relative in sorted(entries):
        record = entries[relative]
        _normalize_owned_manifest_path(
            root, relative,
            record_type=record["type"], target=record.get("target"),
            target_uid=target_uid, target_gid=target_gid,
        )


def _verify_manifest_tree(
    root: Path,
    records: dict[str, dict],
    *,
    required_owner: Optional[tuple[int, int]] = None,
) -> None:
    canonical_root = root.resolve(strict=True)
    for relative, record in records.items():
        path = root.joinpath(*_normalized_archive_parts(relative))
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise GuardError(f"source manifest member is missing: {relative}: {exc}") from exc
        if metadata.st_nlink != 1:
            raise GuardError(f"source manifest member has unsafe hard links: {relative}")
        if required_owner is not None and (
            metadata.st_uid, metadata.st_gid
        ) != required_owner:
            raise GuardError(f"source manifest member has wrong ownership: {relative}")
        if record["type"] == "file":
            if not stat.S_ISREG(metadata.st_mode):
                raise GuardError(f"source manifest member type changed: {relative}")
            resolved = path
        else:
            if (
                not stat.S_ISLNK(metadata.st_mode)
                or os.readlink(path) != record["target"]
            ):
                raise GuardError(f"source manifest symlink changed: {relative}")
            try:
                resolved = path.resolve(strict=True)
                resolved.relative_to(canonical_root)
            except (OSError, RuntimeError, ValueError) as exc:
                raise GuardError(
                    f"source manifest symlink escapes root: {relative}: {exc}"
                ) from exc
        if not resolved.is_file():
            raise GuardError(f"source manifest target is not regular: {relative}")
        content = _read_stable_regular_bytes(
            resolved, f"source manifest member {relative}",
            maximum_size=1024 * 1024 * 1024,
        )
        if hashlib.sha256(content).hexdigest() != record["sha256"]:
            raise GuardError(f"source manifest member hash changed: {relative}")


def _validate_incoming_symlinks(http_root: Path, staging: Path, members: list) -> None:
    root = http_root.resolve(strict=True)
    staged_root = staging.resolve(strict=True)
    for _member, parts, kind in members:
        if kind != "symlink":
            continue
        staged_link = staging.joinpath(*parts)
        target_parts = _normalized_archive_parts(
            PurePosixPath(*parts[:-1], os.readlink(staged_link)).as_posix()
        )
        staged_target = staging.joinpath(*target_parts)
        try:
            if os.path.lexists(staged_target):
                staged_target.resolve(strict=True).relative_to(staged_root)
            else:
                http_root.joinpath(*target_parts).resolve(strict=False).relative_to(root)
        except (OSError, RuntimeError, ValueError) as exc:
            raise GuardError(
                "incoming archive symlink resolves outside deployment root: "
                + "/".join(parts)
            ) from exc


def _preflight_live_overlay(http_root: Path, members: list) -> None:
    try:
        root_metadata = http_root.lstat()
    except OSError as exc:
        raise GuardError(f"deployment root is unavailable: {exc}") from exc
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise GuardError("deployment root must be one real directory")
    for _member, parts, kind in members:
        for length in range(1, len(parts)):
            ancestor = http_root.joinpath(*parts[:length])
            try:
                metadata = ancestor.lstat()
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise GuardError(f"cannot inspect live ancestor {ancestor}: {exc}") from exc
            if not stat.S_ISDIR(metadata.st_mode):
                raise GuardError(f"live ancestor must be a real directory, not symlink: {ancestor}")
        destination = http_root.joinpath(*parts)
        try:
            metadata = destination.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise GuardError(f"cannot inspect live destination {destination}: {exc}") from exc
        if kind == "dir":
            if not stat.S_ISDIR(metadata.st_mode):
                raise GuardError(f"incoming directory conflicts with live path: {destination}")
        elif metadata.st_nlink != 1 or not (
            stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
        ):
            raise GuardError(f"incoming file conflicts with unsafe live path: {destination}")


def _verify_old_source(http_root: Path, relative: str, record: dict) -> Path:
    parts = _normalized_archive_parts(relative)
    if not (
        parts[0] in SOURCE_SCAN_ROOTS
        or (
            parts[0] == "DAY0-Prepare"
            and len(parts) >= 2
            and (
                parts[1] == "template"
                or (len(parts) == 2 and PurePosixPath(parts[1]).suffix == ".py")
            )
        )
    ):
        raise GuardError(f"stale source is outside managed source roots: {relative}")
    path = http_root.joinpath(*parts)
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return path
    except OSError as exc:
        raise GuardError(f"cannot inspect stale source {relative}: {exc}") from exc
    if metadata.st_nlink != 1:
        raise GuardError(f"stale source has unsafe hard links: {relative}")
    if record.get("type") == "file":
        if not stat.S_ISREG(metadata.st_mode):
            raise GuardError(f"stale source type changed: {relative}")
        resolved = path
    else:
        if not stat.S_ISLNK(metadata.st_mode) or os.readlink(path) != record.get("target"):
            raise GuardError(f"stale source symlink changed: {relative}")
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(http_root.resolve(strict=True))
        except (OSError, RuntimeError, ValueError) as exc:
            raise GuardError(f"stale source escapes deployment root: {relative}: {exc}") from exc
    if hashlib.sha256(resolved.read_bytes()).hexdigest() != record.get("sha256"):
        raise GuardError(f"stale source content changed: {relative}")
    return path


def _trusted_old_source_records(
    http_root: Path, state_root: Path,
) -> tuple[dict[str, dict], Optional[str]]:
    """Authenticate the old live receipt through persistent root-owned state."""
    owner = _read_deployment_owner_record(
        state_root / DEPLOYMENT_OWNER_NAME, http_root,
    )
    if owner is None or owner.get("source_manifest_sha256") is None:
        return {}, None
    expected = owner["source_manifest_sha256"]
    root_fd = -1
    manifest_parent_fd = -1
    manifest_fd = -1
    try:
        root_fd, root_identity = _open_held_directory(
            http_root, "trusted old deployment root",
        )
        (
            manifest_parent_fd,
            manifest_fd,
            manifest_identity,
            manifest_bytes,
        ) = _open_held_manifest_authority(root_fd)
        if hashlib.sha256(manifest_bytes).hexdigest() != expected:
            raise GuardError("old source manifest digest does not match trusted owner")
        records = _manifest_records_from_bytes(
            manifest_bytes, SOURCE_MANIFEST_NAME,
        )
        _assert_held_directory_path(
            http_root, root_fd, root_identity, "trusted old deployment root",
        )
        _assert_held_manifest_authority(
            root_fd, manifest_parent_fd, manifest_fd,
            manifest_identity, manifest_bytes,
        )
        return records, expected
    finally:
        if manifest_fd >= 0:
            os.close(manifest_fd)
        if manifest_parent_fd >= 0:
            os.close(manifest_parent_fd)
        if root_fd >= 0:
            os.close(root_fd)


def _atomic_state_json(path: Path, payload: dict, label: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        if path.parent.resolve(strict=True) != path.parent:
            raise GuardError(f"{label} parent must be canonical")
        if os.path.lexists(path):
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise GuardError(f"{label} must be one regular file")
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", dir=path.parent,
        )
        temporary = Path(temporary_name)
        try:
            encoded = (
                json.dumps(payload, ensure_ascii=True, sort_keys=True) + "\n"
            ).encode("ascii")
            _write_all(descriptor, encoded, label)
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o600)
            os.close(descriptor)
            descriptor = -1
            os.replace(temporary, path)
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    except GuardError:
        raise
    except OSError as exc:
        raise GuardError(f"cannot publish {label}: {exc}") from exc


def _read_pending_source_update(path: Path, http_root: Path) -> Optional[dict]:
    if not os.path.lexists(path):
        return None
    try:
        payload = json.loads(
            _read_stable_regular_bytes(
                path, "pending source authority", maximum_size=16 * 1024 * 1024,
            ).decode("ascii")
        )
    except GuardError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise GuardError(f"pending source authority is unreadable: {exc}") from exc
    if (
        not isinstance(payload, dict)
        or set(payload) != {
            "schema_version", "runtime", "http_root",
            "old_source_manifest_sha256", "new_source_manifest_sha256", "files",
        }
        or payload.get("schema_version") != 1
        or payload.get("runtime") != "docker"
        or payload.get("http_root") != os.fspath(http_root)
        or (
            payload.get("old_source_manifest_sha256") is not None
            and not __import__("re").fullmatch(
                r"[0-9a-f]{64}", str(payload.get("old_source_manifest_sha256") or ""),
            )
        )
        or not __import__("re").fullmatch(
            r"[0-9a-f]{64}", str(payload.get("new_source_manifest_sha256") or ""),
        )
    ):
        raise GuardError("pending source authority has an invalid schema")
    payload["records"] = _validated_source_records(
        payload["files"], "pending source authority", allow_empty=True,
    )
    return payload


def begin_source_update(
    http_root: Path, state_root: Path, expected_new_manifest_sha256: str,
) -> dict[str, dict]:
    """Persist old prune authority before any source byte can be replaced."""
    if not __import__("re").fullmatch(
        r"[0-9a-f]{64}", expected_new_manifest_sha256,
    ):
        raise GuardError("expected source manifest digest is invalid")
    pending_path = state_root / PENDING_SOURCE_UPDATE_NAME
    pending = _read_pending_source_update(pending_path, http_root)
    owner = _read_deployment_owner_record(
        state_root / DEPLOYMENT_OWNER_NAME, http_root,
    )
    if owner is None:
        # The normal quiesce path creates this first.  Keep the transaction
        # primitive complete for a fresh, explicitly requested Docker deploy
        # and for recovery tests that replace the Docker inspection boundary.
        write_deployment_owner(
            state_root / DEPLOYMENT_OWNER_NAME, http_root,
            source_manifest_sha256=None,
        )
        owner = _read_deployment_owner_record(
            state_root / DEPLOYMENT_OWNER_NAME, http_root,
        )
        if owner is None:
            raise GuardError("Docker source update has no persistent deployment owner")
    if pending is not None:
        if pending["new_source_manifest_sha256"] != expected_new_manifest_sha256:
            raise GuardError(
                "a different Docker source update is already pending; retry its exact release"
            )
        if owner.get("source_manifest_sha256") not in {
            pending["old_source_manifest_sha256"],
            pending["new_source_manifest_sha256"],
        }:
            raise GuardError("pending source authority does not match Docker owner")
        return pending["records"]
    old_records, old_digest = _trusted_old_source_records(http_root, state_root)
    _atomic_state_json(pending_path, {
        "schema_version": 1,
        "runtime": "docker",
        "http_root": os.fspath(http_root),
        "old_source_manifest_sha256": old_digest,
        "new_source_manifest_sha256": expected_new_manifest_sha256,
        "files": [old_records[name] for name in sorted(old_records)],
    }, "pending source authority")
    return old_records


def finalize_source_update(
    http_root: Path,
    state_root: Path,
    old_records: dict[str, dict],
    *,
    expected_new_manifest_sha256: str,
    docker_managed: bool,
    _ownership_target: tuple[int, int] = (0, 0),
) -> None:
    """Validate/prune the new tree, bind its owner, then clear pending state."""
    root_fd, root_identity = _open_held_directory(http_root, "deployment root")
    try:
        pending_path = state_root / PENDING_SOURCE_UPDATE_NAME
        if docker_managed:
            pending = _read_pending_source_update(pending_path, http_root)
            if pending is None:
                raise GuardError("pending source authority is missing")
            if pending["new_source_manifest_sha256"] != expected_new_manifest_sha256:
                raise GuardError("pending source authority digest changed")
            if pending["records"] != old_records:
                raise GuardError("pending source prune authority changed")
        _assert_held_directory_path(
            http_root, root_fd, root_identity, "deployment root",
        )
        manifest_bytes = _held_manifest_bytes(root_fd)
        manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
        if manifest_digest != expected_new_manifest_sha256:
            raise GuardError("new source manifest digest does not match local authority")
        _finalize_live_source_update(
            http_root, state_root, old_records, docker_managed=docker_managed,
            _ownership_target=_ownership_target,
            _root_authority=(root_fd, root_identity),
            _manifest_authority=(manifest_bytes, manifest_digest),
        )
        _assert_held_directory_path(
            http_root, root_fd, root_identity, "deployment root",
        )
        if docker_managed:
            _safe_unlink(pending_path, "pending source authority")
    finally:
        os.close(root_fd)


def _finalize_live_source_update(
    http_root: Path,
    state_root: Path,
    old_records: dict[str, dict],
    *,
    docker_managed: bool,
    _ownership_target: tuple[int, int] = (0, 0),
    _root_authority: Optional[tuple[int, tuple[int, int]]] = None,
    _manifest_authority: Optional[tuple[bytes, str]] = None,
) -> None:
    """Validate the transferred authority, prune authenticated stale source, bind owner."""
    own_root_fd = _root_authority is None
    if own_root_fd:
        root_fd, root_identity = _open_held_directory(http_root, "deployment root")
    else:
        root_fd, root_identity = _root_authority
    transaction: Optional[_OverlayTransaction] = None
    manifest_parent_fd = -1
    manifest_fd = -1
    try:
        _assert_held_directory_path(
            http_root, root_fd, root_identity, "deployment root",
        )
        (
            manifest_parent_fd,
            manifest_fd,
            manifest_identity,
            held_manifest_bytes,
        ) = _open_held_manifest_authority(root_fd)
        if _manifest_authority is not None:
            expected_manifest_bytes, expected_manifest_digest = _manifest_authority
            if (
                held_manifest_bytes != expected_manifest_bytes
                or hashlib.sha256(expected_manifest_bytes).hexdigest()
                != expected_manifest_digest
            ):
                raise GuardError("source manifest authority bytes changed")
        manifest_bytes = held_manifest_bytes
        manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
        new_records = _manifest_records_from_bytes(
            manifest_bytes, SOURCE_MANIFEST_NAME,
        )
        if docker_managed:
            _normalize_manifest_tree_ownership_held(
                root_fd, new_records,
                target_uid=_ownership_target[0], target_gid=_ownership_target[1],
            )
        _assert_held_directory_path(
            http_root, root_fd, root_identity, "deployment root",
        )
        _assert_held_manifest_authority(
            root_fd, manifest_parent_fd, manifest_fd, manifest_identity, manifest_bytes,
        )
        _verify_manifest_tree_held(
            root_fd, new_records,
            required_owner=_ownership_target if docker_managed else None,
        )
        stale_relatives = sorted(set(old_records) - set(new_records), reverse=True)
        _validate_transaction_parent_budget(
            _normalized_archive_parts(relative) for relative in stale_relatives
        )
        transaction = _OverlayTransaction(http_root, root_fd, root_identity)
        for relative in stale_relatives:
            _prune_verified_stale_member(
                http_root, root_fd, root_identity, relative,
                old_records[relative], transaction,
            )
        _assert_held_manifest_authority(
            root_fd, manifest_parent_fd, manifest_fd, manifest_identity, manifest_bytes,
        )
        _verify_manifest_tree_held(
            root_fd, new_records,
            required_owner=_ownership_target if docker_managed else None,
        )
        _assert_held_manifest_authority(
            root_fd, manifest_parent_fd, manifest_fd, manifest_identity, manifest_bytes,
        )
        transaction.commit()
        _assert_held_directory_path(
            http_root, root_fd, root_identity, "deployment root",
        )
        _assert_held_manifest_authority(
            root_fd, manifest_parent_fd, manifest_fd, manifest_identity, manifest_bytes,
        )
        _verify_manifest_tree_held(
            root_fd, new_records,
            required_owner=_ownership_target if docker_managed else None,
        )
        _assert_held_manifest_authority(
            root_fd, manifest_parent_fd, manifest_fd, manifest_identity, manifest_bytes,
        )
        if docker_managed:
            write_deployment_owner(
                state_root / DEPLOYMENT_OWNER_NAME, http_root,
                source_manifest_sha256=manifest_digest,
            )
            _assert_held_manifest_authority(
                root_fd, manifest_parent_fd, manifest_fd, manifest_identity, manifest_bytes,
            )
            _assert_held_directory_path(
                http_root, root_fd, root_identity, "deployment root",
            )
            _verify_manifest_tree_held(
                root_fd, new_records, required_owner=_ownership_target,
            )
            _assert_held_manifest_authority(
                root_fd, manifest_parent_fd, manifest_fd, manifest_identity, manifest_bytes,
            )
    except BaseException as exc:
        if transaction is not None and not transaction.committed:
            try:
                transaction.rollback()
            except GuardError as rollback_error:
                raise GuardError(
                    f"source finalize failed ({exc}); {rollback_error}"
                ) from exc
        if isinstance(exc, GuardError):
            raise
        if isinstance(exc, OSError):
            raise GuardError(f"cannot finalize source update: {exc}") from exc
        raise
    finally:
        if transaction is not None:
            transaction.close()
        if manifest_fd >= 0:
            os.close(manifest_fd)
        if manifest_parent_fd >= 0:
            os.close(manifest_parent_fd)
        if own_root_fd:
            os.close(root_fd)


_DIRECTORY_OPEN_FLAGS = (
    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0)
)


def _open_held_directory(path: Path, label: str) -> tuple[int, tuple[int, int]]:
    """Open one named real directory and bind its pathname to that descriptor."""
    if not path.is_absolute():
        raise GuardError(f"{label} must be absolute")
    descriptor = -1
    try:
        before = path.lstat()
        descriptor = os.open("/", _DIRECTORY_OPEN_FLAGS)
        for component in path.parts[1:]:
            child = os.open(
                component, _DIRECTORY_OPEN_FLAGS, dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
        opened = os.fstat(descriptor)
        after = path.lstat()
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise GuardError(f"cannot open {label} safely: {exc}") from exc
    identity = (opened.st_dev, opened.st_ino)
    if (
        not stat.S_ISDIR(before.st_mode)
        or not stat.S_ISDIR(opened.st_mode)
        or not stat.S_ISDIR(after.st_mode)
        or (before.st_dev, before.st_ino) != identity
        or (after.st_dev, after.st_ino) != identity
    ):
        os.close(descriptor)
        raise GuardError(f"{label} identity changed while opening")
    return descriptor, identity


def _assert_held_directory_path(
    path: Path,
    descriptor: int,
    identity: tuple[int, int],
    label: str,
) -> None:
    try:
        opened = os.fstat(descriptor)
        current = path.lstat()
    except OSError as exc:
        raise GuardError(f"{label} identity changed: {exc}") from exc
    if (
        not stat.S_ISDIR(opened.st_mode)
        or not stat.S_ISDIR(current.st_mode)
        or (opened.st_dev, opened.st_ino) != identity
        or (current.st_dev, current.st_ino) != identity
    ):
        raise GuardError(f"{label} identity changed")


def _live_capacity_authority(
    http_root: Path, members: list,
) -> tuple[Path, int, tuple[int, int], int]:
    """Hold and check the live root or its nearest existing real ancestor."""
    root = Path(os.path.abspath(os.fspath(http_root)))
    cursor = root
    missing_components = 0
    while True:
        try:
            metadata = cursor.lstat()
            break
        except FileNotFoundError:
            parent = cursor.parent
            if parent == cursor:
                raise GuardError("deployment root has no existing capacity authority")
            cursor = parent
            missing_components += 1
        except OSError as exc:
            raise GuardError(f"cannot inspect live capacity authority: {exc}") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise GuardError("live capacity authority must be one real directory")
    try:
        if cursor.resolve(strict=True) != cursor:
            raise GuardError("live capacity authority must be canonical")
    except (OSError, RuntimeError) as exc:
        raise GuardError(f"cannot resolve live capacity authority: {exc}") from exc
    descriptor, identity = _open_held_directory(
        cursor, "live deployment capacity authority",
    )
    try:
        _enforce_deployment_capacity(
            descriptor, members, extra_nodes=missing_components,
            label="deployment live-root",
        )
        _assert_held_directory_path(
            cursor, descriptor, identity, "live deployment capacity authority",
        )
        return cursor, descriptor, identity, missing_components
    except BaseException:
        os.close(descriptor)
        raise


def _close_live_capacity_authority(
    authority: Optional[tuple[Path, int, tuple[int, int], int]],
) -> None:
    if authority is not None:
        os.close(authority[1])


def _recheck_live_capacity_after_root_creation(
    http_root: Path,
    authority: tuple[Path, int, tuple[int, int], int],
    members: list,
) -> None:
    """Repeat admission if a newly available root is on another device."""
    measured_path, measured_fd, measured_identity, missing_components = authority
    _assert_held_directory_path(
        measured_path, measured_fd, measured_identity,
        "live deployment capacity authority",
    )
    root_fd, root_identity = _open_held_directory(http_root, "deployment root")
    try:
        root_status = os.fstat(root_fd)
        if root_status.st_dev != measured_identity[0]:
            _enforce_deployment_capacity(
                root_fd, members, extra_nodes=missing_components,
                label="deployment live-root device recheck",
            )
        _assert_held_directory_path(
            http_root, root_fd, root_identity, "deployment root",
        )
    finally:
        os.close(root_fd)


def _remove_unjournaled_created_directory(
    parent_fd: int,
    name: str,
    identity: tuple[int, int],
    label: str,
) -> None:
    """Undo a mkdir that failed before the transaction could retain it."""
    try:
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(current.st_mode)
            or (current.st_dev, current.st_ino) != identity
        ):
            raise GuardError(f"{label} changed before local rollback")
        os.rmdir(name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise GuardError(f"cannot roll back {label}: {exc}") from exc


def _bind_created_directory_or_roll_back(
    parent_fd: int,
    name: str,
    label: str,
) -> tuple[int, int]:
    """Bind a just-created directory or remove it after a binding error."""
    try:
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except BaseException as exc:
        try:
            recovery = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if not stat.S_ISDIR(recovery.st_mode):
                raise GuardError(f"{label} changed before rollback")
            identity = (recovery.st_dev, recovery.st_ino)
            _remove_unjournaled_created_directory(
                parent_fd, name, identity, label,
            )
        except BaseException as cleanup_error:
            raise GuardError(
                f"{label} identity inspection failed ({exc}); "
                f"rollback is incomplete: {cleanup_error}"
            ) from exc
        raise GuardError(
            f"{label} identity stat failed after mkdir; directory was rolled back: {exc}"
        ) from exc
    if not stat.S_ISDIR(current.st_mode):
        raise GuardError(f"{label} changed before authority binding")
    return current.st_dev, current.st_ino


def _open_relative_parent(
    root_fd: int,
    parts: tuple[str, ...],
    *,
    create: bool,
    transaction=None,
) -> tuple[int, list[tuple[str, ...]]]:
    """Open a member parent below a held root without following components."""
    descriptor = os.dup(root_fd)
    created: list[tuple[str, ...]] = []
    prefix: list[str] = []
    try:
        for component in parts[:-1]:
            prefix.append(component)
            created_component = False
            created_identity: Optional[tuple[int, int]] = None
            try:
                child = os.open(component, _DIRECTORY_OPEN_FLAGS, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise GuardError(
                        "deployment member parent is missing: " + "/".join(prefix)
                    )
                try:
                    os.mkdir(component, 0o755, dir_fd=descriptor)
                    created.append(tuple(prefix))
                    created_component = True
                except FileExistsError:
                    pass
                if created_component:
                    created_identity = _bind_created_directory_or_roll_back(
                        descriptor,
                        component,
                        "created deployment parent " + "/".join(prefix),
                    )
                    try:
                        child = os.open(
                            component, _DIRECTORY_OPEN_FLAGS, dir_fd=descriptor,
                        )
                    except BaseException as exc:
                        try:
                            _remove_unjournaled_created_directory(
                                descriptor, component, created_identity,
                                "created deployment parent " + "/".join(prefix),
                            )
                        except GuardError as cleanup_error:
                            raise GuardError(
                                f"deployment parent setup failed ({exc}); {cleanup_error}"
                            ) from exc
                        raise
                else:
                    child = os.open(
                        component, _DIRECTORY_OPEN_FLAGS, dir_fd=descriptor,
                    )
            except OSError as exc:
                raise GuardError(
                    "deployment member parent is not a real directory: "
                    + "/".join(prefix)
                    + f": {exc}"
                ) from exc
            child_status = os.fstat(child)
            if not stat.S_ISDIR(child_status.st_mode):
                os.close(child)
                raise GuardError(
                    "deployment member parent is not a real directory: "
                    + "/".join(prefix)
                )
            if created_identity is not None and (
                child_status.st_dev, child_status.st_ino
            ) != created_identity:
                os.close(child)
                try:
                    _remove_unjournaled_created_directory(
                        descriptor, component, created_identity,
                        "created deployment parent " + "/".join(prefix),
                    )
                except GuardError as cleanup_error:
                    raise GuardError(
                        "created deployment parent identity changed; "
                        + str(cleanup_error)
                    ) from cleanup_error
                raise GuardError(
                    "created deployment parent identity changed: "
                    + "/".join(prefix)
                )
            if created_component and transaction is not None:
                try:
                    transaction.record_created_directory(
                        descriptor, component, tuple(prefix),
                        (child_status.st_dev, child_status.st_ino),
                    )
                except BaseException:
                    os.close(child)
                    try:
                        _remove_unjournaled_created_directory(
                            descriptor, component,
                            (child_status.st_dev, child_status.st_ino),
                            "created deployment parent " + "/".join(prefix),
                        )
                    except GuardError:
                        raise
                    raise
                try:
                    os.fsync(descriptor)
                except BaseException:
                    os.close(child)
                    raise
            os.close(descriptor)
            descriptor = child
        return descriptor, created
    except BaseException:
        os.close(descriptor)
        raise


def _open_existing_relative_parent(
    root_fd: int, parts: tuple[str, ...],
) -> Optional[int]:
    """Open a real existing parent, returning None when its path is absent."""
    descriptor = os.dup(root_fd)
    prefix = []
    try:
        for component in parts[:-1]:
            prefix.append(component)
            try:
                child = os.open(component, _DIRECTORY_OPEN_FLAGS, dir_fd=descriptor)
            except FileNotFoundError:
                os.close(descriptor)
                return None
            except OSError as exc:
                raise GuardError(
                    "deployment member parent is not a real directory: "
                    + "/".join(prefix) + f": {exc}"
                ) from exc
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _assert_relative_parent_identity(
    root_fd: int,
    parts: tuple[str, ...],
    held_parent_fd: int,
) -> None:
    current_fd, _created = _open_relative_parent(root_fd, parts, create=False)
    try:
        held = os.fstat(held_parent_fd)
        current = os.fstat(current_fd)
        if (
            not stat.S_ISDIR(held.st_mode)
            or not stat.S_ISDIR(current.st_mode)
            or (held.st_dev, held.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise GuardError(
                "deployment member parent identity changed: " + "/".join(parts[:-1])
            )
    finally:
        os.close(current_fd)


def _read_stable_regular_at(
    parent_fd: int,
    name: str,
    label: str,
    *,
    maximum_size: int,
    required_owner: Optional[tuple[int, int]] = None,
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise GuardError(f"cannot open {label} safely: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        identity = (opened.st_dev, opened.st_ino)
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or before.st_nlink != 1
            or opened.st_nlink != 1
            or (before.st_dev, before.st_ino) != identity
            or opened.st_size < 0
            or opened.st_size > maximum_size
            or (
                required_owner is not None
                and (opened.st_uid, opened.st_gid) != required_owner
            )
        ):
            raise GuardError(f"{label} is not one bounded trusted regular file")
        output = bytearray()
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum_size + 1 - len(output)))
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > maximum_size:
                raise GuardError(f"{label} exceeds the safe size limit")
        after = os.fstat(descriptor)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            (current.st_dev, current.st_ino) != identity
            or current.st_nlink != 1
            or (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
            ) != (
                opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns
            )
            or len(output) != opened.st_size
        ):
            raise GuardError(f"{label} changed while reading")
        return bytes(output)
    finally:
        os.close(descriptor)


def _held_manifest_bytes(root_fd: int) -> bytes:
    parts = tuple(PurePosixPath(SOURCE_MANIFEST_NAME).parts)
    parent_fd, _created = _open_relative_parent(root_fd, parts, create=False)
    try:
        return _read_stable_regular_at(
            parent_fd, parts[-1], "source manifest",
            maximum_size=16 * 1024 * 1024,
        )
    finally:
        os.close(parent_fd)


def _open_held_manifest_authority(
    root_fd: int,
) -> tuple[int, int, tuple[int, int], bytes]:
    parts = tuple(PurePosixPath(SOURCE_MANIFEST_NAME).parts)
    parent_fd, _created = _open_relative_parent(root_fd, parts, create=False)
    descriptor = -1
    try:
        before = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        descriptor = os.open(
            parts[-1],
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
        opened = os.fstat(descriptor)
        identity = (opened.st_dev, opened.st_ino)
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or before.st_nlink != 1
            or opened.st_nlink != 1
            or (before.st_dev, before.st_ino) != identity
            or opened.st_size < 0
            or opened.st_size > 16 * 1024 * 1024
        ):
            raise GuardError("source manifest is not one bounded regular file")
        output = bytearray()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > 16 * 1024 * 1024:
                raise GuardError("source manifest exceeds the safe size limit")
        after = os.fstat(descriptor)
        current = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        if (
            (current.st_dev, current.st_ino) != identity
            or current.st_nlink != 1
            or (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
            ) != (
                opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns
            )
            or len(output) != opened.st_size
        ):
            raise GuardError("source manifest changed while binding authority")
        _assert_relative_parent_identity(root_fd, parts, parent_fd)
        os.lseek(descriptor, 0, os.SEEK_SET)
        return parent_fd, descriptor, identity, bytes(output)
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_fd)
        raise


def _assert_held_manifest_authority(
    root_fd: int,
    parent_fd: int,
    descriptor: int,
    identity: tuple[int, int],
    expected_bytes: bytes,
) -> None:
    parts = tuple(PurePosixPath(SOURCE_MANIFEST_NAME).parts)
    _assert_relative_parent_identity(root_fd, parts, parent_fd)
    try:
        opened = os.fstat(descriptor)
        current = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise GuardError(f"source manifest authority changed: {exc}") from exc
    if (
        not stat.S_ISREG(opened.st_mode)
        or not stat.S_ISREG(current.st_mode)
        or opened.st_nlink != 1
        or current.st_nlink != 1
        or (opened.st_dev, opened.st_ino) != identity
        or (current.st_dev, current.st_ino) != identity
        or opened.st_size != len(expected_bytes)
    ):
        raise GuardError("source manifest authority identity changed")
    output = bytearray()
    offset = 0
    try:
        while offset < len(expected_bytes) + 1:
            chunk = os.pread(
                descriptor,
                min(1024 * 1024, len(expected_bytes) + 1 - offset),
                offset,
            )
            if not chunk:
                break
            output.extend(chunk)
            offset += len(chunk)
        after = os.fstat(descriptor)
        named_after = os.stat(
            parts[-1], dir_fd=parent_fd, follow_symlinks=False,
        )
    except OSError as exc:
        raise GuardError(f"source manifest authority changed: {exc}") from exc
    if (
        bytes(output) != expected_bytes
        or (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ) != (
            opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns
        )
        or (named_after.st_dev, named_after.st_ino) != identity
        or named_after.st_nlink != 1
    ):
        raise GuardError("source manifest authority content changed")


def _normalize_manifest_tree_ownership_held(
    root_fd: int,
    records: dict[str, dict],
    *,
    target_uid: int,
    target_gid: int,
) -> None:
    if target_uid < 0 or target_gid < 0:
        raise GuardError("source ownership target is invalid")
    entries = {
        SOURCE_MANIFEST_NAME: {"type": "file", "target": None},
        **records,
    }
    for relative in sorted(entries):
        parts = _normalized_archive_parts(relative)
        parent_fd, _created = _open_relative_parent(root_fd, parts, create=False)
        try:
            name = parts[-1]
            before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if before.st_nlink != 1:
                raise GuardError(f"source ownership path has unsafe hard links: {relative}")
            record = entries[relative]
            if record["type"] == "file":
                descriptor = os.open(
                    name,
                    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=parent_fd,
                )
                try:
                    opened = os.fstat(descriptor)
                    if (
                        not stat.S_ISREG(opened.st_mode)
                        or opened.st_nlink != 1
                        or (opened.st_dev, opened.st_ino)
                        != (before.st_dev, before.st_ino)
                    ):
                        raise GuardError(f"source ownership path changed: {relative}")
                    if (opened.st_uid, opened.st_gid) != (target_uid, target_gid):
                        os.fchown(descriptor, target_uid, target_gid)
                    after = os.fstat(descriptor)
                finally:
                    os.close(descriptor)
            else:
                if (
                    not stat.S_ISLNK(before.st_mode)
                    or os.readlink(name, dir_fd=parent_fd) != record.get("target")
                ):
                    raise GuardError(f"source ownership symlink changed: {relative}")
                if (before.st_uid, before.st_gid) != (target_uid, target_gid):
                    os.chown(
                        name, target_uid, target_gid,
                        dir_fd=parent_fd, follow_symlinks=False,
                    )
                after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
                or after.st_nlink != 1
                or (after.st_uid, after.st_gid) != (target_uid, target_gid)
            ):
                raise GuardError(f"source ownership did not converge safely: {relative}")
        except OSError as exc:
            raise GuardError(f"cannot normalize source ownership for {relative}: {exc}") from exc
        finally:
            os.close(parent_fd)


def _read_resolved_record_target_held(
    root_fd: int, parts: tuple[str, ...], *, label: str,
) -> bytes:
    pending = parts
    for _hop in range(40):
        parent_fd, _created = _open_relative_parent(root_fd, pending, create=False)
        try:
            metadata = os.stat(
                pending[-1], dir_fd=parent_fd, follow_symlinks=False,
            )
            if stat.S_ISREG(metadata.st_mode):
                return _read_stable_regular_at(
                    parent_fd, pending[-1], label,
                    maximum_size=1024 * 1024 * 1024,
                )
            if not stat.S_ISLNK(metadata.st_mode) or metadata.st_nlink != 1:
                raise GuardError(f"{label} does not resolve to one regular file")
            target = os.readlink(pending[-1], dir_fd=parent_fd)
        finally:
            os.close(parent_fd)
        pending = _normalized_archive_parts(
            PurePosixPath(*pending[:-1], target).as_posix()
        )
    raise GuardError(f"{label} has too many symlink hops")


def _verify_manifest_tree_held(
    root_fd: int,
    records: dict[str, dict],
    *,
    required_owner: Optional[tuple[int, int]],
) -> None:
    for relative, record in records.items():
        parts = _normalized_archive_parts(relative)
        parent_fd, _created = _open_relative_parent(root_fd, parts, create=False)
        try:
            metadata = os.stat(
                parts[-1], dir_fd=parent_fd, follow_symlinks=False,
            )
            if metadata.st_nlink != 1:
                raise GuardError(f"source manifest member has unsafe hard links: {relative}")
            if required_owner is not None and (
                metadata.st_uid, metadata.st_gid
            ) != required_owner:
                raise GuardError(f"source manifest member has wrong ownership: {relative}")
            if record["type"] == "file":
                content = _read_stable_regular_at(
                    parent_fd, parts[-1], f"source manifest member {relative}",
                    maximum_size=1024 * 1024 * 1024,
                    required_owner=required_owner,
                )
            else:
                if (
                    not stat.S_ISLNK(metadata.st_mode)
                    or os.readlink(parts[-1], dir_fd=parent_fd) != record["target"]
                ):
                    raise GuardError(f"source manifest symlink changed: {relative}")
                target_parts = _normalized_archive_parts(
                    PurePosixPath(*parts[:-1], record["target"]).as_posix()
                )
                content = _read_resolved_record_target_held(
                    root_fd, target_parts,
                    label=f"source manifest target {relative}",
                )
        except OSError as exc:
            raise GuardError(f"cannot verify source manifest member {relative}: {exc}") from exc
        finally:
            os.close(parent_fd)
        if hashlib.sha256(content).hexdigest() != record["sha256"]:
            raise GuardError(f"source manifest member hash changed: {relative}")


def _unused_leaf_name(parent_fd: int, destination_name: str, role: str) -> str:
    for _attempt in range(128):
        candidate = f".{destination_name}.http-ztp-{role}-{os.urandom(12).hex()}"
        try:
            os.stat(candidate, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return candidate
        except OSError as exc:
            raise GuardError(f"cannot inspect private deployment leaf: {exc}") from exc
    raise GuardError("cannot allocate a private deployment leaf")


def _unlink_leaf_if_present(parent_fd: int, name: Optional[str]) -> None:
    if name is None:
        return
    try:
        os.unlink(name, dir_fd=parent_fd)
    except FileNotFoundError:
        pass


def _validate_transaction_parent_budget(paths) -> None:
    parents = set()
    for parts in paths:
        for length in range(len(parts)):
            parents.add(parts[:length])
            if len(parents) > MAX_TRANSACTION_PARENT_DIRECTORIES:
                raise GuardError(
                    "deployment transaction has too many distinct live parent directories"
                )


class _OverlayTransaction:
    """In-process rollback authority for one complete live-tree overlay."""

    def __init__(
        self, http_root: Path, root_fd: int, root_identity: tuple[int, int],
    ) -> None:
        self.http_root = http_root
        self.root_fd = root_fd
        self.root_identity = root_identity
        self.entries: list[dict] = []
        self.parent_fds: dict[tuple[str, ...], int] = {}
        self.entry_fds: list[int] = []
        self.committed = False
        self.closed = False

    def _hold_parent(
        self, parent_fd: int, parts: tuple[str, ...],
    ) -> int:
        key = parts[:-1]
        held = self.parent_fds.get(key)
        if held is None:
            held = os.dup(parent_fd)
            self.parent_fds[key] = held
        else:
            current = os.fstat(parent_fd)
            retained = os.fstat(held)
            if (current.st_dev, current.st_ino) != (retained.st_dev, retained.st_ino):
                raise GuardError(
                    "deployment transaction parent identity changed: "
                    + "/".join(key)
                )
        return held

    def record_created_directory(
        self,
        parent_fd: int,
        name: str,
        parts: tuple[str, ...],
        identity: tuple[int, int],
    ) -> dict:
        entry = {
            "kind": "created-directory",
            "parent_fd": self._hold_parent(parent_fd, parts),
            "parts": parts,
            "name": name,
            "identity": identity,
        }
        self.entries.append(entry)
        return entry

    def record_directory_mode(
        self,
        parent_fd: int,
        directory_fd: int,
        name: str,
        parts: tuple[str, ...],
        identity: tuple[int, int],
        previous_mode: int,
    ) -> dict:
        if len(self.entry_fds) >= MAX_TRANSACTION_PARENT_DIRECTORIES:
            raise GuardError(
                "deployment transaction has too many retained directory authorities"
            )
        held_directory_fd = os.dup(directory_fd)
        self.entry_fds.append(held_directory_fd)
        entry = {
            "kind": "directory-mode",
            "parent_fd": self._hold_parent(parent_fd, parts),
            "parts": parts,
            "name": name,
            "identity": identity,
            "previous_mode": previous_mode,
            "directory_fd": held_directory_fd,
        }
        self.entries.append(entry)
        return entry

    def record_leaf(
        self,
        parent_fd: int,
        parts: tuple[str, ...],
        backup_name: Optional[str],
        original_identity: Optional[tuple[int, int]],
        published_identity: tuple[int, int],
    ) -> dict:
        entry = {
            "kind": "leaf",
            "parent_fd": self._hold_parent(parent_fd, parts),
            "parts": parts,
            "name": parts[-1],
            "backup_name": backup_name,
            "original_identity": original_identity,
            "backed_up": False,
            "published_identity": published_identity,
            "published": False,
        }
        self.entries.append(entry)
        return entry

    def record_stale(
        self,
        parent_fd: int,
        parts: tuple[str, ...],
        backup_name: str,
        original_identity: tuple[int, int],
    ) -> dict:
        entry = {
            "kind": "stale",
            "parent_fd": self._hold_parent(parent_fd, parts),
            "parts": parts,
            "name": parts[-1],
            "backup_name": backup_name,
            "original_identity": original_identity,
            "moved": False,
        }
        self.entries.append(entry)
        return entry

    def _assert_authority(self) -> None:
        _assert_held_directory_path(
            self.http_root, self.root_fd, self.root_identity, "deployment root",
        )
        for parent_parts, descriptor in self.parent_fds.items():
            _assert_relative_parent_identity(
                self.root_fd, parent_parts + ("__transaction_leaf__",), descriptor,
            )
        for entry in self.entries:
            kind = entry["kind"]
            if kind in {"created-directory", "directory-mode"}:
                try:
                    current = os.stat(
                        entry["name"], dir_fd=entry["parent_fd"],
                        follow_symlinks=False,
                    )
                except OSError as exc:
                    raise GuardError(
                        "deployment transaction directory authority changed: "
                        + "/".join(entry["parts"])
                        + f": {exc}"
                    ) from exc
                if (
                    not stat.S_ISDIR(current.st_mode)
                    or (current.st_dev, current.st_ino) != entry["identity"]
                ):
                    raise GuardError(
                        "deployment transaction directory authority changed: "
                        + "/".join(entry["parts"])
                    )
            elif kind == "leaf":
                if (
                    not entry["published"]
                    or self._entry_current_identity(entry)
                    != entry["published_identity"]
                ):
                    raise GuardError(
                        "deployment transaction published leaf changed: "
                        + "/".join(entry["parts"])
                    )
                if entry["backed_up"]:
                    try:
                        backup = os.stat(
                            entry["backup_name"], dir_fd=entry["parent_fd"],
                            follow_symlinks=False,
                        )
                    except OSError as exc:
                        raise GuardError(
                            "deployment transaction backup authority changed: "
                            + "/".join(entry["parts"])
                            + f": {exc}"
                        ) from exc
                    if (backup.st_dev, backup.st_ino) != entry["original_identity"]:
                        raise GuardError(
                            "deployment transaction backup authority changed: "
                            + "/".join(entry["parts"])
                        )
            elif kind == "stale" and entry["moved"]:
                if self._entry_current_identity(entry) is not None:
                    raise GuardError(
                        "stale deployment destination reappeared before commit: "
                        + "/".join(entry["parts"])
                    )
                try:
                    backup = os.stat(
                        entry["backup_name"], dir_fd=entry["parent_fd"],
                        follow_symlinks=False,
                    )
                except OSError as exc:
                    raise GuardError(
                        "stale deployment backup authority changed: "
                        + "/".join(entry["parts"])
                        + f": {exc}"
                    ) from exc
                if (backup.st_dev, backup.st_ino) != entry["original_identity"]:
                    raise GuardError(
                        "stale deployment backup authority changed: "
                        + "/".join(entry["parts"])
                    )

    @staticmethod
    def _entry_current_identity(entry: dict) -> Optional[tuple[int, int]]:
        try:
            current = os.stat(
                entry["name"], dir_fd=entry["parent_fd"], follow_symlinks=False,
            )
        except FileNotFoundError:
            return None
        return current.st_dev, current.st_ino

    def rollback(self) -> None:
        if self.committed:
            raise GuardError("cannot roll back a committed deployment overlay")
        errors = []
        touched = set()
        for entry in reversed(self.entries):
            parent_fd = entry["parent_fd"]
            touched.add(parent_fd)
            try:
                if entry["kind"] == "leaf":
                    current_identity = self._entry_current_identity(entry)
                    backup_present = False
                    if entry["backup_name"] is not None:
                        try:
                            backup = os.stat(
                                entry["backup_name"], dir_fd=parent_fd,
                                follow_symlinks=False,
                            )
                        except FileNotFoundError:
                            backup = None
                        if backup is not None:
                            if (backup.st_dev, backup.st_ino) != entry["original_identity"]:
                                raise GuardError(
                                    "deployment backup changed before transaction rollback"
                                )
                            backup_present = True
                    if entry["backed_up"] and not backup_present:
                        raise GuardError(
                            "deployment backup disappeared before transaction rollback"
                        )
                    if current_identity == entry["published_identity"]:
                        os.unlink(entry["name"], dir_fd=parent_fd)
                        current_identity = None
                    elif current_identity is not None and not (
                        current_identity == entry["original_identity"]
                        and not backup_present
                        and not entry["published"]
                    ):
                        raise GuardError(
                            "published deployment leaf changed before transaction rollback: "
                            + "/".join(entry["parts"])
                        )
                    if backup_present:
                        if current_identity is not None:
                            raise GuardError(
                                "deployment destination reappeared before backup restore"
                            )
                        os.replace(
                            entry["backup_name"], entry["name"],
                            src_dir_fd=parent_fd, dst_dir_fd=parent_fd,
                        )
                    entry["backed_up"] = False
                elif entry["kind"] == "stale":
                    try:
                        backup = os.stat(
                            entry["backup_name"], dir_fd=parent_fd,
                            follow_symlinks=False,
                        )
                    except FileNotFoundError:
                        backup = None
                    if backup is not None:
                        if (backup.st_dev, backup.st_ino) != entry["original_identity"]:
                            raise GuardError(
                                "stale deployment backup changed before transaction rollback"
                            )
                        if self._entry_current_identity(entry) is not None:
                            raise GuardError(
                                "stale destination reappeared before transaction rollback: "
                                + "/".join(entry["parts"])
                            )
                        os.replace(
                            entry["backup_name"], entry["name"],
                            src_dir_fd=parent_fd, dst_dir_fd=parent_fd,
                        )
                        entry["moved"] = False
                    elif entry["moved"]:
                        raise GuardError(
                            "stale deployment backup disappeared before transaction rollback"
                        )
                elif entry["kind"] == "directory-mode":
                    child = entry["directory_fd"]
                    current = os.fstat(child)
                    named = os.stat(
                        entry["name"], dir_fd=parent_fd, follow_symlinks=False,
                    )
                    if (
                        not stat.S_ISDIR(named.st_mode)
                        or (current.st_dev, current.st_ino) != entry["identity"]
                        or (named.st_dev, named.st_ino) != entry["identity"]
                    ):
                        raise GuardError(
                            "deployment directory name changed before transaction rollback"
                        )
                    os.fchmod(child, entry["previous_mode"])
                    os.fsync(child)
                elif entry["kind"] == "created-directory":
                    current = os.stat(
                        entry["name"], dir_fd=parent_fd, follow_symlinks=False,
                    )
                    if (
                        not stat.S_ISDIR(current.st_mode)
                        or (current.st_dev, current.st_ino) != entry["identity"]
                    ):
                        raise GuardError(
                            "created deployment directory changed before rollback"
                        )
                    os.rmdir(entry["name"], dir_fd=parent_fd)
            except FileNotFoundError:
                if entry["kind"] not in {"created-directory"}:
                    errors.append(
                        GuardError(
                            "deployment rollback authority disappeared: "
                            + "/".join(entry["parts"])
                        )
                    )
            except (OSError, GuardError) as exc:
                errors.append(exc)
        for descriptor in touched:
            try:
                os.fsync(descriptor)
            except OSError as exc:
                errors.append(exc)
        if errors:
            raise GuardError(
                "cannot completely roll back deployment transaction: "
                + "; ".join(str(error) for error in errors)
            )

    def commit(self) -> None:
        """Cross the durable commit boundary, then best-effort-remove old backups."""
        self._assert_authority()
        self.committed = True
        cleanup_errors = []
        touched = set()
        for entry in self.entries:
            backup_name = entry.get("backup_name")
            active = entry.get("backed_up") or entry.get("moved")
            if not backup_name or not active:
                continue
            parent_fd = entry["parent_fd"]
            try:
                backup = os.stat(
                    backup_name, dir_fd=parent_fd, follow_symlinks=False,
                )
                if (backup.st_dev, backup.st_ino) != entry["original_identity"]:
                    raise GuardError(
                        "deployment backup changed before committed cleanup"
                    )
                os.unlink(backup_name, dir_fd=parent_fd)
                if entry["kind"] == "leaf":
                    entry["backed_up"] = False
                else:
                    entry["moved"] = False
                touched.add(parent_fd)
            except (OSError, GuardError) as exc:
                cleanup_errors.append(exc)
        for descriptor in touched:
            try:
                os.fsync(descriptor)
            except OSError as exc:
                cleanup_errors.append(exc)
        if cleanup_errors:
            raise GuardError(
                "deployment overlay committed but backup cleanup durability is incomplete: "
                + "; ".join(str(error) for error in cleanup_errors)
            )

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        for descriptor in self.parent_fds.values():
            os.close(descriptor)
        self.parent_fds.clear()
        for descriptor in self.entry_fds:
            os.close(descriptor)
        self.entry_fds.clear()


def _restore_unexpected_stale_move(
    parent_fd: int,
    destination_name: str,
    backup_name: str,
    moved_identity: tuple[int, int],
    relative: str,
) -> None:
    """Restore the exact leaf moved by a stale-prune identity race."""
    try:
        try:
            destination = os.stat(
                destination_name, dir_fd=parent_fd, follow_symlinks=False,
            )
        except FileNotFoundError:
            destination = None
        if destination is not None:
            raise GuardError(
                f"stale source recovery destination reappeared: {relative}"
            )
        backup = os.stat(
            backup_name, dir_fd=parent_fd, follow_symlinks=False,
        )
        if (backup.st_dev, backup.st_ino) != moved_identity:
            raise GuardError(
                f"stale source recovery authority changed: {relative}"
            )
        os.replace(
            backup_name,
            destination_name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        restored = os.stat(
            destination_name, dir_fd=parent_fd, follow_symlinks=False,
        )
        if (restored.st_dev, restored.st_ino) != moved_identity:
            raise GuardError(
                f"stale source recovery identity changed: {relative}"
            )
        os.fsync(parent_fd)
    except GuardError:
        raise
    except OSError as exc:
        raise GuardError(
            f"cannot recover stale source identity race {relative}: {exc}"
        ) from exc


def _prune_verified_stale_member(
    http_root: Path,
    root_fd: int,
    root_identity: tuple[int, int],
    relative: str,
    record: dict,
    transaction: _OverlayTransaction,
) -> None:
    """Remove one receipt-bound stale leaf through its held real parent."""
    parts = _normalized_archive_parts(relative)
    if not (
        parts[0] in SOURCE_SCAN_ROOTS
        or (
            parts[0] == "DAY0-Prepare"
            and len(parts) >= 2
            and (
                parts[1] == "template"
                or (len(parts) == 2 and PurePosixPath(parts[1]).suffix == ".py")
            )
        )
    ):
        raise GuardError(f"stale source is outside managed source roots: {relative}")
    parent_fd = _open_existing_relative_parent(root_fd, parts)
    if parent_fd is None:
        _assert_held_directory_path(
            http_root, root_fd, root_identity, "deployment root",
        )
        return
    try:
        name = parts[-1]
        try:
            before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if before.st_nlink != 1:
            raise GuardError(f"stale source has unsafe hard links: {relative}")
        if record.get("type") == "file":
            if not stat.S_ISREG(before.st_mode):
                raise GuardError(f"stale source type changed: {relative}")
            content = _read_stable_regular_at(
                parent_fd, name, f"stale source {relative}",
                maximum_size=1024 * 1024 * 1024,
            )
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino)
                or hashlib.sha256(content).hexdigest() != record.get("sha256")
            ):
                raise GuardError(f"stale source changed: {relative}")
        else:
            if (
                not stat.S_ISLNK(before.st_mode)
                or os.readlink(name, dir_fd=parent_fd) != record.get("target")
            ):
                raise GuardError(f"stale source symlink changed: {relative}")
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
                raise GuardError(f"stale source symlink changed: {relative}")
            target_parts = _normalized_archive_parts(
                PurePosixPath(*parts[:-1], record["target"]).as_posix()
            )
            content = _read_resolved_record_target_held(
                root_fd, target_parts, label=f"stale source target {relative}",
            )
            if hashlib.sha256(content).hexdigest() != record.get("sha256"):
                raise GuardError(f"stale source content changed: {relative}")

        hook = _TEST_AFTER_STALE_VERIFY
        if hook is not None:
            hook()

        _assert_held_directory_path(
            http_root, root_fd, root_identity, "deployment root",
        )
        _assert_relative_parent_identity(root_fd, parts, parent_fd)
        candidate = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        original_identity = (before.st_dev, before.st_ino)
        if (candidate.st_dev, candidate.st_ino) != original_identity:
            raise GuardError(f"stale source changed before removal: {relative}")
        backup_name = _unused_leaf_name(parent_fd, name, "stale")
        entry = transaction.record_stale(
            parent_fd, parts, backup_name, original_identity,
        )
        try:
            os.replace(
                name,
                backup_name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
        except BaseException as move_error:
            try:
                moved = os.stat(
                    backup_name, dir_fd=parent_fd, follow_symlinks=False,
                )
            except FileNotFoundError:
                raise
            moved_identity = (moved.st_dev, moved.st_ino)
            if moved_identity != original_identity:
                try:
                    _restore_unexpected_stale_move(
                        parent_fd, name, backup_name, moved_identity, relative,
                    )
                except GuardError as recovery_error:
                    raise GuardError(
                        f"stale source move failed ({move_error}); "
                        f"rollback is incomplete: {recovery_error}"
                    ) from move_error
                raise GuardError(
                    f"stale source changed during failed removal and was restored: {relative}"
                ) from move_error
            entry["moved"] = True
            raise
        moved = os.stat(
            backup_name, dir_fd=parent_fd, follow_symlinks=False,
        )
        moved_identity = (moved.st_dev, moved.st_ino)
        if moved_identity != original_identity:
            try:
                _restore_unexpected_stale_move(
                    parent_fd, name, backup_name, moved_identity, relative,
                )
            except GuardError as recovery_error:
                raise GuardError(
                    "stale source changed during removal; rollback is incomplete: "
                    + str(recovery_error)
                ) from recovery_error
            raise GuardError(
                f"stale source changed during removal and was restored: {relative}"
            )
        entry["moved"] = True
        _assert_held_directory_path(
            http_root, root_fd, root_identity, "deployment root",
        )
        _assert_relative_parent_identity(root_fd, parts, parent_fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _promote_staged_member(
    http_root: Path,
    root_fd: int,
    root_identity: tuple[int, int],
    staging: Path,
    staging_fd: int,
    staging_identity: tuple[int, int],
    item,
    transaction: _OverlayTransaction,
) -> None:
    member, parts, kind = item
    destination_name = parts[-1]
    destination_parent_fd, _created = _open_relative_parent(
        root_fd, parts, create=True, transaction=transaction,
    )
    source_parent_fd: Optional[int] = None
    temporary_name: Optional[str] = None
    temporary_identity: Optional[tuple[int, int]] = None
    try:
        _assert_held_directory_path(http_root, root_fd, root_identity, "deployment root")
        _assert_relative_parent_identity(root_fd, parts, destination_parent_fd)
        if kind == "dir":
            created_directory = False
            created_identity: Optional[tuple[int, int]] = None
            journaled = False
            try:
                try:
                    before = os.stat(
                        destination_name,
                        dir_fd=destination_parent_fd,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    os.mkdir(
                        destination_name, 0o755,
                        dir_fd=destination_parent_fd,
                    )
                    created_directory = True
                    created_identity = _bind_created_directory_or_roll_back(
                        destination_parent_fd,
                        destination_name,
                        "created deployment directory " + "/".join(parts),
                    )
                else:
                    if not stat.S_ISDIR(before.st_mode):
                        raise GuardError(
                            "incoming directory conflicts with live path: "
                            + "/".join(parts)
                        )
                child = os.open(
                    destination_name,
                    _DIRECTORY_OPEN_FLAGS,
                    dir_fd=destination_parent_fd,
                )
                try:
                    opened = os.fstat(child)
                    identity = (opened.st_dev, opened.st_ino)
                    if created_directory:
                        if identity != created_identity:
                            raise GuardError(
                                "created deployment directory identity changed: "
                                + "/".join(parts)
                            )
                        transaction.record_created_directory(
                            destination_parent_fd, destination_name, parts, identity,
                        )
                        journaled = True
                    else:
                        transaction.record_directory_mode(
                            destination_parent_fd, child, destination_name, parts, identity,
                            stat.S_IMODE(before.st_mode),
                        )
                    os.fchmod(child, member.mode & 0o777)
                    os.fsync(child)
                finally:
                    os.close(child)
                if created_directory:
                    os.fsync(destination_parent_fd)
                _assert_held_directory_path(
                    http_root, root_fd, root_identity, "deployment root",
                )
                _assert_relative_parent_identity(root_fd, parts, destination_parent_fd)
            except BaseException as exc:
                if (
                    created_directory
                    and not journaled
                    and created_identity is not None
                ):
                    try:
                        _remove_unjournaled_created_directory(
                            destination_parent_fd,
                            destination_name,
                            created_identity,
                            "created deployment directory " + "/".join(parts),
                        )
                    except GuardError as cleanup_error:
                        raise GuardError(
                            f"deployment directory setup failed ({exc}); {cleanup_error}"
                        ) from exc
                raise
            return

        source_parent_fd, _unused = _open_relative_parent(
            staging_fd, parts, create=False,
        )
        _assert_held_directory_path(
            staging, staging_fd, staging_identity, "deployment staging root",
        )
        if kind == "file":
            source_fd = os.open(
                destination_name,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=source_parent_fd,
            )
            try:
                source_before = os.fstat(source_fd)
                if not stat.S_ISREG(source_before.st_mode) or source_before.st_nlink != 1:
                    raise GuardError(
                        "staged deployment source is not one regular file: "
                        + "/".join(parts)
                    )
                temporary_name = _unused_leaf_name(
                    destination_parent_fd, destination_name, "new",
                )
                output_fd = os.open(
                    temporary_name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=destination_parent_fd,
                )
                try:
                    while True:
                        chunk = os.read(source_fd, 1024 * 1024)
                        if not chunk:
                            break
                        _write_all(output_fd, chunk, "deployment archive member")
                    os.fchmod(output_fd, member.mode & 0o777)
                    os.fsync(output_fd)
                finally:
                    os.close(output_fd)
                source_after = os.fstat(source_fd)
                if (
                    source_after.st_dev,
                    source_after.st_ino,
                    source_after.st_size,
                    source_after.st_mtime_ns,
                ) != (
                    source_before.st_dev,
                    source_before.st_ino,
                    source_before.st_size,
                    source_before.st_mtime_ns,
                ):
                    raise GuardError("staged deployment source changed while copying")
                temporary_status = os.stat(
                    temporary_name,
                    dir_fd=destination_parent_fd,
                    follow_symlinks=False,
                )
                temporary_identity = (
                    temporary_status.st_dev,
                    temporary_status.st_ino,
                )
            finally:
                os.close(source_fd)
        else:
            target = os.readlink(destination_name, dir_fd=source_parent_fd)
            temporary_name = _unused_leaf_name(
                destination_parent_fd, destination_name, "new",
            )
            os.symlink(target, temporary_name, dir_fd=destination_parent_fd)
            temporary_status = os.stat(
                temporary_name,
                dir_fd=destination_parent_fd,
                follow_symlinks=False,
            )
            temporary_identity = (
                temporary_status.st_dev,
                temporary_status.st_ino,
            )

        try:
            existing = os.stat(
                destination_name,
                dir_fd=destination_parent_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            existing = None
        backup_name: Optional[str] = None
        if existing is not None:
            if existing.st_nlink != 1 or not (
                stat.S_ISREG(existing.st_mode) or stat.S_ISLNK(existing.st_mode)
            ):
                raise GuardError(
                    "incoming file conflicts with unsafe live path: " + "/".join(parts)
                )
            backup_name = _unused_leaf_name(
                destination_parent_fd, destination_name, "old",
            )
        entry = transaction.record_leaf(
            destination_parent_fd, parts, backup_name,
            (
                (existing.st_dev, existing.st_ino)
                if existing is not None else None
            ),
            temporary_identity,
        )
        if backup_name is not None:
            os.replace(
                destination_name,
                backup_name,
                src_dir_fd=destination_parent_fd,
                dst_dir_fd=destination_parent_fd,
            )
            entry["backed_up"] = True

        _assert_held_directory_path(http_root, root_fd, root_identity, "deployment root")
        _assert_relative_parent_identity(root_fd, parts, destination_parent_fd)
        os.replace(
            temporary_name,
            destination_name,
            src_dir_fd=destination_parent_fd,
            dst_dir_fd=destination_parent_fd,
        )
        temporary_name = None
        entry["published"] = True
        published = os.stat(
            destination_name,
            dir_fd=destination_parent_fd,
            follow_symlinks=False,
        )
        if (published.st_dev, published.st_ino) != temporary_identity:
            raise GuardError("published deployment leaf identity changed")
        _assert_held_directory_path(
            http_root, root_fd, root_identity, "deployment root",
        )
        _assert_relative_parent_identity(root_fd, parts, destination_parent_fd)
        os.fsync(destination_parent_fd)
    finally:
        _unlink_leaf_if_present(destination_parent_fd, temporary_name)
        if source_parent_fd is not None:
            os.close(source_parent_fd)
        os.close(destination_parent_fd)


def _apply_prepared_archive_overlay(
    http_root: Path, staging: Path, members: list, *,
    trusted_old_manifest_sha256: Optional[str] = None,
    expected_new_manifest_sha256: Optional[str] = None,
) -> None:
    """Apply one already authenticated/staged archive as a rollbackable batch."""
    root_fd: Optional[int] = None
    staging_fd: Optional[int] = None
    transaction: Optional[_OverlayTransaction] = None
    try:
        root_fd, root_identity = _open_held_directory(
            http_root, "deployment root",
        )
        transaction = _OverlayTransaction(http_root, root_fd, root_identity)
        staging_fd, staging_identity = _open_held_directory(
            staging, "deployment staging root",
        )
        _preflight_live_overlay(http_root, members)
        _validate_incoming_symlinks(http_root, staging, members)
        _assert_held_directory_path(
            http_root, root_fd, root_identity, "deployment root",
        )
        _assert_held_directory_path(
            staging, staging_fd, staging_identity, "deployment staging root",
        )
        new_manifest_path = staging / SOURCE_MANIFEST_NAME
        new_manifest_bytes = _read_stable_regular_bytes(
            new_manifest_path, "source manifest", maximum_size=16 * 1024 * 1024,
        )
        new_manifest_digest = hashlib.sha256(new_manifest_bytes).hexdigest()
        if expected_new_manifest_sha256 is not None:
            if not __import__("re").fullmatch(
                r"[0-9a-f]{64}", expected_new_manifest_sha256,
            ):
                raise GuardError("expected new source manifest digest is invalid")
            if new_manifest_digest != expected_new_manifest_sha256:
                raise GuardError("new source manifest digest does not match local authority")
        new_records = _manifest_records_from_bytes(
            new_manifest_bytes, os.fspath(new_manifest_path),
        )
        _verify_manifest_tree(staging, new_records)
        old_manifest_path = http_root / SOURCE_MANIFEST_NAME
        old_records = {}
        if trusted_old_manifest_sha256 is not None:
            if not __import__("re").fullmatch(
                r"[0-9a-f]{64}", trusted_old_manifest_sha256,
            ):
                raise GuardError("trusted old source manifest digest is invalid")
            old_manifest_bytes = _held_manifest_bytes(root_fd)
            if hashlib.sha256(old_manifest_bytes).hexdigest() != trusted_old_manifest_sha256:
                raise GuardError("old source manifest digest does not match trusted owner")
            old_records = _manifest_records_from_bytes(
                old_manifest_bytes, os.fspath(old_manifest_path),
            )
        stale = sorted(set(old_records) - set(new_records), reverse=True)
        if sum(1 for _member, _parts, kind in members if kind == "dir") > (
            MAX_TRANSACTION_PARENT_DIRECTORIES
        ):
            raise GuardError(
                "deployment transaction has too many explicit directories"
            )
        _validate_transaction_parent_budget([
            *(parts for _member, parts, _kind in members),
            *(_normalized_archive_parts(relative) for relative in stale),
        ])
        for relative in stale:
            _prune_verified_stale_member(
                http_root,
                root_fd,
                root_identity,
                relative,
                old_records[relative],
                transaction,
            )
        manifest_parts = tuple(PurePosixPath(SOURCE_MANIFEST_NAME).parts)
        ordered = sorted(
            members,
            key=lambda item: (
                item[1] == manifest_parts,
                len(item[1]), item[1],
            ),
        )
        for item in ordered:
            _promote_staged_member(
                http_root,
                root_fd,
                root_identity,
                staging,
                staging_fd,
                staging_identity,
                item,
                transaction,
            )
        _assert_held_directory_path(
            http_root, root_fd, root_identity, "deployment root",
        )
        _assert_held_directory_path(
            staging, staging_fd, staging_identity, "deployment staging root",
        )
        transaction.commit()
    except BaseException as exc:
        if transaction is not None and not transaction.committed:
            try:
                transaction.rollback()
            except GuardError as rollback_error:
                raise GuardError(
                    f"deployment overlay failed ({exc}); {rollback_error}"
                ) from exc
        if isinstance(exc, GuardError):
            raise
        if isinstance(exc, OSError):
            raise GuardError(f"cannot promote deployment archive: {exc}") from exc
        raise
    finally:
        if transaction is not None:
            transaction.close()
        if staging_fd is not None:
            os.close(staging_fd)
        if root_fd is not None:
            os.close(root_fd)


def apply_archive_overlay(
    http_root: Path, archive_path: Path, expected_sha256: str, *,
    lock_path: Path,
    trusted_old_manifest_sha256: Optional[str] = None,
    expected_new_manifest_sha256: Optional[str] = None,
) -> None:
    """Validate, stage, prune prior receipt-owned source, and promote safely."""
    lock_parts = lock_parts_within_root(http_root, lock_path)
    staging, members = _extract_archive_staging(
        archive_path, expected_sha256, lock_parts=lock_parts,
    )
    live_capacity = None
    try:
        live_capacity = _live_capacity_authority(http_root, members)
        _recheck_live_capacity_after_root_creation(
            http_root, live_capacity, members,
        )
        _apply_prepared_archive_overlay(
            http_root, staging, members,
            trusted_old_manifest_sha256=trusted_old_manifest_sha256,
            expected_new_manifest_sha256=expected_new_manifest_sha256,
        )
    finally:
        _close_live_capacity_authority(live_capacity)
        _remove_archive_staging(staging)


def _write_sync_marker(path: Path) -> None:
    _safe_unlink(path, "source deployment marker")
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            0o644,
        )
        os.fsync(descriptor)
        os.close(descriptor)
    except OSError as exc:
        raise GuardError(f"cannot publish source deployment marker: {exc}") from exc


def run_locked_archive(
    lock_path: Path,
    http_root: Path,
    archive_path: Optional[Path],
    expected_sha256: str,
    expected_source_manifest_sha256: str,
    *,
    runtime: str = "native",
    wait_seconds: float = 0,
    state_root: Path = DEFAULT_STATE_ROOT,
    _ownership_target: tuple[int, int] = (0, 0),
    _archive_fd: Optional[int] = None,
) -> int:
    # Parse, authenticate, capacity-check, and stage before creating the live
    # root or disrupting its runtime.  The staged tree is the immutable input
    # used after lock acquisition.
    lock_parts = lock_parts_within_root(http_root, lock_path)
    if _archive_fd is None:
        if archive_path is None:
            raise GuardError("archive path authority is missing")
        staging, members = _extract_archive_staging(
            archive_path, expected_sha256, lock_parts=lock_parts,
        )
    else:
        if archive_path is not None:
            raise GuardError("archive path and descriptor authority are mutually exclusive")
        staging, members = _extract_archive_staging_descriptor(
            _archive_fd, expected_sha256, lock_parts=lock_parts,
        )
    live_capacity = None
    root_bootstrap = None
    try:
        live_capacity = _live_capacity_authority(http_root, members)
        root_bootstrap = ensure_deployment_root(http_root)
        _recheck_live_capacity_after_root_creation(
            http_root, live_capacity, members,
        )
        root_bootstrap.commit()
        root_bootstrap = None
        with safe_lock(lock_path, wait_seconds=wait_seconds):
            changed = quiesce_for_source_update(
                http_root, state_root=state_root,
                docker_requested=runtime == "docker",
                native_requested=runtime == "native",
            )
            old_records = (
                begin_source_update(
                    http_root, state_root, expected_source_manifest_sha256,
                )
                if changed else {}
            )
            print(DOCKER_REBUILD_REQUIRED if changed else NO_MANAGED_DOCKER, flush=True)
            marker = http_root / SYNC_MARKER_NAME
            _write_sync_marker(marker)
            _apply_prepared_archive_overlay(
                http_root, staging, members,
                expected_new_manifest_sha256=expected_source_manifest_sha256,
            )
            finalize_source_update(
                http_root, state_root, old_records,
                expected_new_manifest_sha256=expected_source_manifest_sha256,
                docker_managed=changed,
                _ownership_target=_ownership_target,
            )
            _safe_unlink(marker, "source deployment marker")
    finally:
        try:
            if root_bootstrap is not None:
                root_bootstrap.rollback()
        finally:
            try:
                _close_live_capacity_authority(live_capacity)
            finally:
                _remove_archive_staging(staging)
    return 0


def run_locked_payload(
    lock_path: Path,
    http_root: Path,
    payload: str,
    *,
    protect_docker: bool = False,
    runtime: str = "native",
    wait_seconds: float = 0,
) -> int:
    if not payload:
        raise GuardError("protected payload is empty")
    with safe_lock(lock_path, wait_seconds=wait_seconds):
        if protect_docker:
            changed = quiesce_for_source_update(
                http_root,
                docker_requested=runtime == "docker",
                native_requested=runtime == "native",
            )
            print(
                DOCKER_REBUILD_REQUIRED if changed else NO_MANAGED_DOCKER,
                flush=True,
            )
        result = subprocess.run(
            ["/bin/sh", "-c", payload], check=False,
        )
        if result.returncode != 0:
            raise GuardError(f"protected payload failed (exit={result.returncode})")
        return 0


def run_lock_holder(
    lock_path: Path,
    http_root: Path,
    *,
    runtime: str = "native",
    wait_seconds: float = 0,
    state_root: Path = DEFAULT_STATE_ROOT,
    expected_source_manifest_sha256: str = "",
) -> int:
    """Hold a lock, defer disruption until the writer confirms a real write."""
    with safe_lock(lock_path, wait_seconds=wait_seconds):
        print(LOCK_READY, flush=True)
        request = sys.stdin.readline().strip()
        if not request:
            return 0
        if request != PREWRITE_REQUEST:
            raise GuardError("invalid prewrite holder request")
        changed = quiesce_for_source_update(
            http_root, state_root=state_root,
            docker_requested=runtime == "docker",
            native_requested=runtime == "native",
        )
        old_records = (
            begin_source_update(
                http_root, state_root, expected_source_manifest_sha256,
            )
            if changed else {}
        )
        # One newline-delimited frame avoids a TextIO/select race in the
        # caller: readline() may pre-buffer both formerly separate lines,
        # leaving the file descriptor itself no longer readable for a second
        # select() even though the second line is already in Python's buffer.
        print(
            f"{DOCKER_REBUILD_REQUIRED if changed else NO_MANAGED_DOCKER} "
            f"{PREWRITE_READY}",
            flush=True,
        )
        # EOF without COMMIT is an aborted writer; its persistent sync marker
        # remains.  Only an explicit commit validates/prunes/binds the new
        # receipt and clears that marker while this same lock is held.
        committed = False
        for incoming in sys.stdin:
            request = incoming.strip()
            if not request:
                continue
            if request != COMMIT_REQUEST or committed:
                raise GuardError("unexpected prewrite holder input")
            try:
                if not __import__("re").fullmatch(
                    r"[0-9a-f]{64}", expected_source_manifest_sha256,
                ):
                    raise GuardError("expected source manifest digest is invalid")
                finalize_source_update(
                    http_root, state_root, old_records,
                    expected_new_manifest_sha256=expected_source_manifest_sha256,
                    docker_managed=changed,
                )
                _safe_unlink(
                    http_root / SYNC_MARKER_NAME, "source deployment marker",
                )
            except BaseException:
                try:
                    _write_sync_marker(http_root / SYNC_MARKER_NAME)
                except GuardError as marker_error:
                    print(
                        f"[ERROR] cannot preserve failed source marker: {marker_error}",
                        file=sys.stderr, flush=True,
                    )
                raise
            committed = True
            print(COMMIT_READY, flush=True)
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--lock", type=Path, required=True)
    result.add_argument("--root", type=Path, required=True)
    result.add_argument("--wait", type=float, default=0)
    result.add_argument("--protect-docker", action="store_true")
    result.add_argument("--holder", action="store_true")
    result.add_argument("--runtime", choices=("native", "docker"), default="native")
    archive_authority = result.add_mutually_exclusive_group()
    archive_authority.add_argument("--archive", type=Path)
    archive_authority.add_argument("--archive-fd", type=int, help=argparse.SUPPRESS)
    result.add_argument("--archive-sha256", default="")
    result.add_argument("--source-manifest-sha256", default="")
    result.add_argument("payload", nargs="?", default="")
    return result


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.archive is not None or args.archive_fd is not None:
            if args.holder or args.payload or args.protect_docker:
                raise GuardError("archive mode cannot be combined with holder/payload mode")
            if not args.archive_sha256:
                raise GuardError("archive mode requires --archive-sha256")
            if not args.source_manifest_sha256:
                raise GuardError("archive mode requires --source-manifest-sha256")
            return run_locked_archive(
                args.lock, args.root, args.archive, args.archive_sha256,
                args.source_manifest_sha256,
                runtime=args.runtime, wait_seconds=args.wait,
                _archive_fd=args.archive_fd,
            )
        if args.holder:
            if args.payload:
                raise GuardError("lock holder does not accept a shell payload")
            return run_lock_holder(
                args.lock, args.root, runtime=args.runtime,
                wait_seconds=args.wait,
                expected_source_manifest_sha256=args.source_manifest_sha256,
            )
        return run_locked_payload(
            args.lock, args.root, args.payload,
            protect_docker=args.protect_docker, runtime=args.runtime,
            wait_seconds=args.wait,
        )
    except GuardBusy as exc:
        print(f"[BUSY] {exc}", file=sys.stderr)
        return 75
    except (GuardError, OSError, ValueError) as exc:
        print(f"[ERROR] source update guard refused: {exc}", file=sys.stderr)
        return 74


if __name__ == "__main__":
    raise SystemExit(main())
