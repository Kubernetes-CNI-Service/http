#!/usr/bin/env python3
"""Run one host lifecycle command under the validated deployment lock."""

from __future__ import annotations

import argparse
from contextlib import contextmanager, nullcontext, redirect_stderr
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
import types
from typing import Iterator, Mapping, Optional, Sequence


HERE = Path(__file__).resolve().parent
DEFAULT_LOCK = Path("/var/www/html/.deployment.lock")
ACTIVATION_MARKER = Path(
    "/var/lib/http-ztp-container/runtime/activation.json"
)
CONTAINER_NAME = "http-ztp"
MANAGED_LABEL = "com.nvidia.http-ztp.managed"
HTTP_ROOT_LABEL = "com.nvidia.http-ztp.http-root"
HTTP_ROOT = Path("/var/www/html")
CONTROL_AUTH_SOURCE = HERE.parents[1] / "tools/control-auth.py"
CONTROL_AUTH_HOST_DIRECTORY = Path("/var/lib/http-ztp-container/control-auth")
CONTROL_AUTH_HOST_FILE = CONTROL_AUTH_HOST_DIRECTORY / "control-users.htpasswd"
CONTROL_AUTH_CONTAINER_DIRECTORY = Path("/etc/http-ztp")
CONTROL_AUTH_CONTAINER_HELPER = Path("/opt/http-ztp/control-auth.py")
MONITOR_AUTHORITY_HOST_ROOT = Path(
    "/var/lib/http-ztp-container/monitor-auth"
)
MONITOR_AUTHORITY_CONTAINER_ROOT = Path("/var/lib/http-ztp-monitor-auth")
CONTROL_AUTH_UID = 0
CONTROL_AUTH_GID = 33
CONTROL_AUTH_SOURCE_MODE = 0o755
CONTROL_AUTH_SOURCE_PARENT_MODE = 0o755
CONTROL_AUTH_SOURCE_LIMIT = 256 * 1024
CONTROL_AUTH_REQUIRED_APIS = (
    "ensure_auth_file",
    "validate_auth_file",
    "status_auth_file",
    "rotate_auth_file",
    "provision_monitor_authority",
    "attest_monitor_authority",
    "recover_monitor_authority",
    "monitor_authority_recovery_decision",
)
IMAGE_ID_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
IMAGE_LABELS = {
    "com.nvidia.http-ztp.image": "true",
    "com.nvidia.http-ztp.image-contract": "3",
    "com.nvidia.http-ztp.base-os": "ubuntu-24.04",
}
LEGACY_CLEANUP_IMAGE_CONTRACT = "2"
IMAGE_FLAVOR_LABEL = "com.nvidia.http-ztp.image-flavor"
PROJECT_IMAGE_LABEL = "com.nvidia.http-ztp.project"
PROJECT_UPLOAD_LABEL = "com.nvidia.http-ztp.upload-sha256"
PROJECT_SOURCE_LABEL = "com.nvidia.http-ztp.source-manifest-sha256"
PROJECT_SHARED_LABEL = "com.nvidia.http-ztp.shared-artifacts-sha256"
PROJECT_UPGRADE_POLICY_LABEL = "com.nvidia.http-ztp.upgrade-policy"
PROJECT_BOOTSTRAP_LABELS = {
    "package-project-image.py": (
        "com.nvidia.http-ztp.project-bootstrap-package-sha256"
    ),
    "deploy-upload-archive.py": (
        "com.nvidia.http-ztp.project-bootstrap-upload-sha256"
    ),
    "deploy-shared-artifacts.py": (
        "com.nvidia.http-ztp.project-bootstrap-shared-sha256"
    ),
}
SAFE_PROJECT_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
IMAGE_ENTRYPOINT = ["/opt/http-ztp/entrypoint.py"]
IMAGE_COMMAND = ["serve"]
IMAGE_ENVIRONMENT = [
    "PATH=/opt/http-ztp/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "PYTHONDONTWRITEBYTECODE=1",
]
IMAGE_HEALTHCHECK = {
    "Test": ["CMD", "/opt/http-ztp/healthcheck.py"],
    "Interval": 30_000_000_000,
    "Timeout": 15_000_000_000,
    "StartPeriod": 30_000_000_000,
    "Retries": 3,
}
PRELOADED_PROBE_OUTPUT_LIMIT = 64 * 1024
PRELOADED_PROBE_LIMITS = (
    "--memory", "256m",
    "--memory-swap", "256m",
    "--pids-limit", "128",
    "--cpus", "1",
    "--log-driver", "local",
    "--log-opt", "max-size=64k",
    "--log-opt", "max-file=1",
)


class HostLockError(RuntimeError):
    """The host lifecycle lock or protected command is unsafe."""


class HostLockBusy(HostLockError):
    """A cooperating writer currently owns the deployment lock."""


class HostLockUnsafe(HostLockError):
    """The deployment lock inode or operating-system lock is unsafe."""


def _source_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        getattr(
            metadata, "st_mtime_ns",
            int(metadata.st_mtime * 1_000_000_000),
        ),
        getattr(
            metadata, "st_ctime_ns",
            int(metadata.st_ctime * 1_000_000_000),
        ),
    )


def _source_parent_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )


def _validate_control_auth_parent(
    metadata: os.stat_result, *, required_uid: int, required_gid: int,
) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        raise HostLockError("Monitor control auth helper parent must be a directory")
    if metadata.st_uid != required_uid or metadata.st_gid != required_gid:
        raise HostLockError("Monitor control auth helper parent ownership is unsafe")
    if stat.S_IMODE(metadata.st_mode) != CONTROL_AUTH_SOURCE_PARENT_MODE:
        raise HostLockError("Monitor control auth helper parent mode must be 0755")


def _validate_control_auth_source(
    metadata: os.stat_result, *, required_uid: int, required_gid: int,
) -> None:
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise HostLockError(
            "Monitor control auth helper must be one regular file"
        )
    if metadata.st_uid != required_uid or metadata.st_gid != required_gid:
        raise HostLockError("Monitor control auth helper ownership is unsafe")
    if stat.S_IMODE(metadata.st_mode) != CONTROL_AUTH_SOURCE_MODE:
        raise HostLockError("Monitor control auth helper mode must be 0755")
    if metadata.st_size <= 0:
        raise HostLockError("Monitor control auth helper is empty")
    if metadata.st_size > CONTROL_AUTH_SOURCE_LIMIT:
        raise HostLockError("Monitor control auth helper is too large")


def _open_control_auth_parent(path: Path) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None:
        raise HostLockError(
            "Monitor control auth helper requires O_NOFOLLOW and O_DIRECTORY"
        )
    if not path.is_absolute() or path.name != "control-auth.py":
        raise HostLockError("Monitor control auth helper path is not canonical")
    parts = path.parent.parts
    if not parts or parts[0] != os.sep or any(
        part in {"", ".", ".."} for part in parts[1:]
    ):
        raise HostLockError("Monitor control auth helper path is not canonical")
    flags = os.O_RDONLY | directory | nofollow | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(os.sep, flags)
    except OSError as exc:
        raise HostLockError(
            f"cannot open Monitor control auth helper root: {exc}"
        ) from exc
    try:
        for component in parts[1:]:
            try:
                next_descriptor = os.open(component, flags, dir_fd=descriptor)
            except OSError as exc:
                raise HostLockError(
                    "cannot open Monitor control auth helper parent component"
                ) from exc
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_control_auth_source(
    descriptor: int, initial: os.stat_result,
) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        allowance = CONTROL_AUTH_SOURCE_LIMIT + 1 - total
        if allowance <= 0:
            raise HostLockError("Monitor control auth helper is too large")
        try:
            chunk = os.read(descriptor, min(64 * 1024, allowance))
        except InterruptedError:
            continue
        except OSError as exc:
            raise HostLockError(
                f"cannot read Monitor control auth helper: {exc}"
            ) from exc
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > CONTROL_AUTH_SOURCE_LIMIT:
            raise HostLockError("Monitor control auth helper is too large")
    try:
        final = os.fstat(descriptor)
    except OSError as exc:
        raise HostLockError(
            f"cannot recheck Monitor control auth helper: {exc}"
        ) from exc
    if _source_identity(final) != _source_identity(initial) or total != initial.st_size:
        raise HostLockError("Monitor control auth helper changed while being read")
    return b"".join(chunks)


def _assert_control_auth_source_binding(
    path: Path,
    parent_descriptor: int,
    parent_identity: tuple[int, ...],
    source_descriptor: int,
    source_identity: tuple[int, ...],
    *,
    required_uid: int,
    required_gid: int,
) -> None:
    try:
        held_parent = os.fstat(parent_descriptor)
        held_source = os.fstat(source_descriptor)
    except OSError as exc:
        raise HostLockError(
            f"cannot recheck Monitor control auth helper binding: {exc}"
        ) from exc
    _validate_control_auth_parent(
        held_parent, required_uid=required_uid, required_gid=required_gid,
    )
    _validate_control_auth_source(
        held_source, required_uid=required_uid, required_gid=required_gid,
    )
    if (
        _source_parent_identity(held_parent) != parent_identity
        or _source_identity(held_source) != source_identity
    ):
        raise HostLockError("Monitor control auth helper held identity changed")

    rebound_parent = _open_control_auth_parent(path)
    try:
        rebound_parent_metadata = os.fstat(rebound_parent)
        try:
            rebound_source = os.stat(
                path.name, dir_fd=rebound_parent, follow_symlinks=False,
            )
        except OSError as exc:
            raise HostLockError(
                f"cannot rebind Monitor control auth helper source: {exc}"
            ) from exc
        _validate_control_auth_parent(
            rebound_parent_metadata,
            required_uid=required_uid,
            required_gid=required_gid,
        )
        _validate_control_auth_source(
            rebound_source, required_uid=required_uid, required_gid=required_gid,
        )
        if (
            _source_parent_identity(rebound_parent_metadata) != parent_identity
            or _source_identity(rebound_source) != source_identity
        ):
            raise HostLockError("Monitor control auth helper path binding changed")
    finally:
        os.close(rebound_parent)


def _load_control_auth(
    path: Path = CONTROL_AUTH_SOURCE,
    *,
    required_uid: Optional[int] = None,
    required_gid: Optional[int] = None,
):
    """Execute one bounded held helper snapshot without a pathname loader."""
    path = Path(path)
    uid = os.geteuid() if required_uid is None else required_uid
    gid = os.getegid() if required_gid is None else required_gid
    parent_descriptor = _open_control_auth_parent(path)
    source_descriptor = -1
    try:
        try:
            parent_metadata = os.fstat(parent_descriptor)
        except OSError as exc:
            raise HostLockError(
                f"cannot inspect Monitor control auth helper parent: {exc}"
            ) from exc
        _validate_control_auth_parent(
            parent_metadata, required_uid=uid, required_gid=gid,
        )
        parent_identity = _source_parent_identity(parent_metadata)

        nofollow = getattr(os, "O_NOFOLLOW", None)
        if nofollow is None:
            raise HostLockError("Monitor control auth helper requires O_NOFOLLOW")
        flags = (
            os.O_RDONLY
            | nofollow
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        try:
            source_descriptor = os.open(
                path.name, flags, dir_fd=parent_descriptor,
            )
        except OSError as exc:
            raise HostLockError(
                f"cannot open Monitor control auth helper: {exc}"
            ) from exc
        try:
            source_metadata = os.fstat(source_descriptor)
        except OSError as exc:
            raise HostLockError(
                f"cannot inspect Monitor control auth helper: {exc}"
            ) from exc
        _validate_control_auth_source(
            source_metadata, required_uid=uid, required_gid=gid,
        )
        source_identity = _source_identity(source_metadata)
        source_bytes = _read_control_auth_source(
            source_descriptor, source_metadata,
        )
        _assert_control_auth_source_binding(
            path, parent_descriptor, parent_identity,
            source_descriptor, source_identity,
            required_uid=uid, required_gid=gid,
        )

        try:
            source_text = source_bytes.decode("utf-8")
            code = compile(source_text, os.fspath(path), "exec", dont_inherit=True)
        except (SyntaxError, UnicodeError, ValueError) as exc:
            raise HostLockError(
                f"cannot compile Monitor control auth helper: {exc}"
            ) from exc
        while True:
            module_name = (
                "_http_ztp_host_control_auth_" + secrets.token_hex(16)
            )
            if module_name not in sys.modules:
                break
        module = types.ModuleType(module_name)
        module.__file__ = os.fspath(path)
        module.__package__ = ""
        module.__loader__ = None
        module.__spec__ = None
        sys.modules[module_name] = module
        try:
            try:
                exec(code, module.__dict__)
            except BaseException as exc:
                raise HostLockError(
                    f"cannot execute Monitor control auth helper: {exc}"
                ) from exc
        finally:
            if sys.modules.get(module_name) is module:
                sys.modules.pop(module_name, None)
        missing = [
            name for name in CONTROL_AUTH_REQUIRED_APIS
            if not callable(getattr(module, name, None))
        ]
        if missing:
            raise HostLockError(
                "Monitor control auth helper API is incomplete: "
                + ", ".join(missing)
            )
        module._CONTROL_AUTH_SOURCE_SHA256 = hashlib.sha256(source_bytes).hexdigest()
        _assert_control_auth_source_binding(
            path, parent_descriptor, parent_identity,
            source_descriptor, source_identity,
            required_uid=uid, required_gid=gid,
        )
        return module
    finally:
        if source_descriptor >= 0:
            os.close(source_descriptor)
        os.close(parent_descriptor)


def _control_auth_status(module) -> dict[str, bool]:
    try:
        module.validate_auth_file(
            CONTROL_AUTH_HOST_FILE,
            required_uid=CONTROL_AUTH_UID,
            required_gid=CONTROL_AUTH_GID,
        )
        payload = module.status_auth_file(
            CONTROL_AUTH_HOST_FILE,
            required_uid=CONTROL_AUTH_UID,
            required_gid=CONTROL_AUTH_GID,
        )
    except Exception as exc:
        raise HostLockError(
            f"Monitor control credential validation failed: {exc}"
        ) from exc
    if (
        not isinstance(payload, dict)
        or set(payload) != {"valid", "factory_records_active"}
        or payload.get("valid") is not True
        or type(payload.get("factory_records_active")) is not bool
    ):
        raise HostLockError("Monitor control credential status is invalid")
    return {
        "valid": True,
        "factory_records_active": payload["factory_records_active"],
    }


def _monitor_authority_failure(exc: BaseException, operation: str) -> HostLockError:
    classification = getattr(exc, "classification", None)
    recovery = "sudo ./infra/docker/deploy.sh recover-monitor-authority"
    if classification == "recovery-committed-cleanup-pending":
        return HostLockError(
            "classification=recovery-committed-cleanup-pending; previous Monitor "
            "authority recovery COMPLETED and the repaired authority itself is not "
            f"in question; rerun `{recovery}` to reattest and finish marker cleanup"
        )
    if classification == "recovery-in-progress":
        return HostLockError(
            "classification=recovery-in-progress; Monitor authority recovery did "
            f"not commit; keep the container stopped and rerun `{recovery}`"
        )
    return HostLockError(f"Monitor cache authority {operation} failed: {exc}")


def _validated_monitor_recovery_result(payload: object) -> dict[str, object]:
    if (
        not isinstance(payload, dict)
        or set(payload) != {
            "cleanup", "recovery_committed", "restart_allowed",
        }
        or payload.get("recovery_committed") is not True
        or type(payload.get("restart_allowed")) is not bool
        or payload.get("cleanup") not in {
            "complete", "marker-retained",
            "marker-removal-durability-unknown", "marker-authority-uncertain",
        }
    ):
        raise HostLockError("Monitor authority recovery result is invalid")
    if (payload["cleanup"] in {
        "complete", "marker-removal-durability-unknown",
    }) != payload["restart_allowed"]:
        raise HostLockError("Monitor authority recovery restart result is invalid")
    return {
        "cleanup": payload["cleanup"],
        "recovery_committed": True,
        "restart_allowed": payload["restart_allowed"],
    }


def prepare_control_auth(
    *,
    lock_path: Path = DEFAULT_LOCK,
    wait_seconds: float = 600,
) -> dict[str, bool]:
    """Initialize once and then preserve/validate the persistent host bytes."""
    with safe_lock(lock_path, wait_seconds):
        module = _load_control_auth()
        try:
            module.ensure_auth_file(
                CONTROL_AUTH_HOST_FILE,
                required_uid=CONTROL_AUTH_UID,
                required_gid=CONTROL_AUTH_GID,
            )
        except Exception as exc:
            raise HostLockError(
                f"Monitor control credential preparation failed: {exc}"
            ) from exc
        return _control_auth_status(module)


def prepare_monitor_authority(
    *,
    lock_path: Path = DEFAULT_LOCK,
    wait_seconds: float = 600,
) -> dict[str, bool]:
    """Provision once and re-attest the persistent fixed-path cache anchor."""
    with safe_lock(lock_path, wait_seconds):
        module = _load_control_auth()
        options = {
            "authority_boundary": Path("/"),
            "required_root_uid": 0,
            "required_root_gid": 0,
            "expected_helper_sha256": module._CONTROL_AUTH_SOURCE_SHA256,
        }
        try:
            module.provision_monitor_authority(
                MONITOR_AUTHORITY_HOST_ROOT, **options,
            )
            module.attest_monitor_authority(
                MONITOR_AUTHORITY_HOST_ROOT, **options,
            )
        except Exception as exc:
            raise _monitor_authority_failure(exc, "preparation") from exc
        return {"valid": True}


def attest_monitor_authority(
    *,
    lock_path: Path = DEFAULT_LOCK,
    wait_seconds: float = 600,
) -> dict[str, bool]:
    """Read-only host attestation; diagnostics never provision or repair."""
    with safe_lock(lock_path, wait_seconds):
        module = _load_control_auth()
        try:
            module.attest_monitor_authority(
                MONITOR_AUTHORITY_HOST_ROOT,
                authority_boundary=Path("/"),
                required_root_uid=0,
                required_root_gid=0,
                expected_helper_sha256=module._CONTROL_AUTH_SOURCE_SHA256,
            )
        except Exception as exc:
            raise _monitor_authority_failure(exc, "attestation") from exc
        return {"valid": True}


@contextmanager
def safe_lock(lock_path: Path, wait_seconds: float) -> Iterator[int]:
    flags = os.O_RDWR | os.O_CREAT
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o644)
    except OSError as exc:
        raise HostLockUnsafe(f"cannot open regular deployment lock: {exc}") from exc
    locked = False
    body_error: Optional[BaseException] = None
    try:
        try:
            descriptor_status = os.fstat(descriptor)
            path_status = os.lstat(lock_path)
        except OSError as exc:
            raise HostLockUnsafe(f"cannot inspect deployment lock: {exc}") from exc
        if (
            not stat.S_ISREG(descriptor_status.st_mode)
            or not stat.S_ISREG(path_status.st_mode)
            or descriptor_status.st_nlink != 1
            or path_status.st_nlink != 1
            or (descriptor_status.st_dev, descriptor_status.st_ino)
            != (path_status.st_dev, path_status.st_ino)
        ):
            raise HostLockUnsafe("deployment lock must be one regular file")
        deadline = time.monotonic() + max(0, wait_seconds)
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                descriptor_status = os.fstat(descriptor)
                path_status = os.lstat(lock_path)
                if (
                    not stat.S_ISREG(path_status.st_mode)
                    or descriptor_status.st_nlink != 1
                    or path_status.st_nlink != 1
                    or (descriptor_status.st_dev, descriptor_status.st_ino)
                    != (path_status.st_dev, path_status.st_ino)
                ):
                    raise HostLockUnsafe(
                        "deployment lock changed during acquisition"
                    )
                break
            except BlockingIOError as exc:
                if time.monotonic() >= deadline:
                    raise HostLockBusy(
                        "timed out waiting for shared deployment lock"
                    ) from exc
                time.sleep(0.1)
            except OSError as exc:
                raise HostLockUnsafe(
                    f"cannot acquire deployment lock: {exc}"
                ) from exc
        try:
            yield descriptor
        except BaseException as exc:
            body_error = exc
            raise
    finally:
        release_error = None
        try:
            if locked:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        except OSError as exc:
            release_error = HostLockUnsafe(
                f"cannot release deployment lock: {exc}"
            )
        try:
            os.close(descriptor)
        except OSError as exc:
            if release_error is None:
                release_error = HostLockUnsafe(
                    f"cannot close deployment lock: {exc}"
                )
        if release_error is not None:
            if body_error is None:
                raise release_error
            print(
                f"[ERROR] {release_error}; original operation also failed: "
                f"{body_error}", file=sys.stderr,
            )


def inherited_lock_subprocess_kwargs(descriptor: int) -> dict[str, object]:
    environment = os.environ.copy()
    environment["HTTP_DEPLOYMENT_LOCK_FD"] = str(descriptor)
    return {"env": environment, "pass_fds": (descriptor,)}


def clear_activation_marker(path: Path) -> None:
    if path != ACTIVATION_MARKER:
        raise HostLockError(f"refuse unexpected activation marker path: {path}")
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise HostLockError(f"cannot inspect activation marker: {exc}") from exc
    if stat.S_ISDIR(metadata.st_mode):
        raise HostLockError("activation marker must not be a directory")
    try:
        path.unlink()
        descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise HostLockError(f"cannot clear activation marker: {exc}") from exc


def _no_such_container(detail: str) -> bool:
    lowered = str(detail).casefold()
    return (
        ("no such object" in lowered or "no such container" in lowered)
        and CONTAINER_NAME in lowered
    )


def inspect_owned_container(
    runner=subprocess.run,
    identifier: str = CONTAINER_NAME,
    *,
    expected_environment: Optional[Mapping[str, str]] = None,
    allow_legacy_cleanup: bool = False,
) -> Optional[dict]:
    try:
        result = runner(
            ["docker", "container", "inspect", identifier],
            capture_output=True, text=True, check=False, timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise HostLockError(f"cannot inspect Docker container ownership: {exc}") from exc
    if result.returncode != 0:
        detail = str(result.stderr or result.stdout or "").strip()
        if _no_such_container(detail):
            return None
        raise HostLockError(
            "cannot inspect Docker container ownership"
            + (f": {detail}" if detail else f" (exit={result.returncode})")
        )
    try:
        payload = json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError) as exc:
        raise HostLockError(f"Docker inspect returned invalid JSON: {exc}") from exc
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
        raise HostLockError("Docker inspect returned an unexpected container set")
    record = payload[0]
    immutable_id = str(record.get("Id") or "")
    if len(immutable_id) != 64 or any(
        character not in "0123456789abcdef" for character in immutable_id
    ):
        raise HostLockError("Docker container immutable identity is invalid")
    if identifier != CONTAINER_NAME and immutable_id != identifier:
        raise HostLockError("Docker container immutable identity changed")
    if record.get("Name") != f"/{CONTAINER_NAME}":
        raise HostLockError("Docker fixed-name ownership identity is invalid")
    config = record.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    if not isinstance(labels, dict) or labels.get(MANAGED_LABEL) != "true":
        raise HostLockError("Docker container ownership label does not match")
    if labels.get(HTTP_ROOT_LABEL) != os.fspath(HTTP_ROOT):
        raise HostLockError("Docker container HTTP-root ownership label does not match")
    image_id = str(record.get("Image") or "")
    if not IMAGE_ID_PATTERN.fullmatch(image_id):
        raise HostLockError("Docker container image immutable identity is invalid")
    if (
        labels.get("com.nvidia.http-ztp.image") != "true"
        or labels.get("com.nvidia.http-ztp.base-os") != "ubuntu-24.04"
    ):
        raise HostLockError("Docker container image ownership labels do not match")
    image_contract = labels.get("com.nvidia.http-ztp.image-contract")
    if image_contract == LEGACY_CLEANUP_IMAGE_CONTRACT:
        if not allow_legacy_cleanup:
            raise HostLockError(
                "legacy image contract 2 is cleanup-only; rebuild or re-export "
                "a contract 3 image before any lifecycle operation"
            )
    elif image_contract != IMAGE_LABELS["com.nvidia.http-ztp.image-contract"]:
        raise HostLockError("Docker container image contract label does not match")
    mounts = record.get("Mounts")
    if not isinstance(mounts, list) or any(
        not isinstance(mount, dict) for mount in mounts
    ):
        raise HostLockError("Docker container mount set is invalid")

    def related_mounts(source: Path, destination: Path) -> list[dict]:
        source_text = os.fspath(source)
        destination_text = os.fspath(destination)

        def overlaps(actual: object, protected: str) -> bool:
            value = str(actual or "")
            if not value:
                return False
            value_prefix = value.rstrip("/") + "/"
            protected_prefix = protected.rstrip("/") + "/"
            return (
                value == protected
                or value.startswith(protected_prefix)
                or protected.startswith(value_prefix)
            )

        return [
            mount for mount in mounts
            if (
                overlaps(mount.get("Source"), source_text)
                or overlaps(mount.get("Destination"), destination_text)
            )
        ]

    http_mounts = related_mounts(HTTP_ROOT, HTTP_ROOT)
    if len(http_mounts) != 1 or not (
        http_mounts[0].get("Type") == "bind"
        and http_mounts[0].get("Source") == os.fspath(HTTP_ROOT)
        and http_mounts[0].get("Destination") == os.fspath(HTTP_ROOT)
        and http_mounts[0].get("RW") is True
    ):
        raise HostLockError(
            "Docker container requires one exact /var/www/html RW bind"
        )
    auth_mounts = related_mounts(
        CONTROL_AUTH_HOST_DIRECTORY, CONTROL_AUTH_CONTAINER_DIRECTORY,
    )
    if image_contract == LEGACY_CLEANUP_IMAGE_CONTRACT:
        if auth_mounts:
            raise HostLockError(
                "legacy image contract 2 has a non-canonical control-auth bind"
            )
    elif len(auth_mounts) != 1 or not (
        auth_mounts[0].get("Type") == "bind"
        and auth_mounts[0].get("Source")
        == os.fspath(CONTROL_AUTH_HOST_DIRECTORY)
        and auth_mounts[0].get("Destination")
        == os.fspath(CONTROL_AUTH_CONTAINER_DIRECTORY)
        and auth_mounts[0].get("RW") is False
    ):
        raise HostLockError(
            "Docker container requires one exact control-auth directory RO bind "
            "at /etc/http-ztp"
        )
    monitor_authority_mounts = related_mounts(
        MONITOR_AUTHORITY_HOST_ROOT, MONITOR_AUTHORITY_CONTAINER_ROOT,
    )
    if image_contract == LEGACY_CLEANUP_IMAGE_CONTRACT:
        if monitor_authority_mounts:
            raise HostLockError(
                "legacy image contract 2 has a non-canonical Monitor authority bind"
            )
    elif len(monitor_authority_mounts) != 1 or not (
        monitor_authority_mounts[0].get("Type") == "bind"
        and monitor_authority_mounts[0].get("Source")
        == os.fspath(MONITOR_AUTHORITY_HOST_ROOT)
        and monitor_authority_mounts[0].get("Destination")
        == os.fspath(MONITOR_AUTHORITY_CONTAINER_ROOT)
        and monitor_authority_mounts[0].get("RW") is True
    ):
        raise HostLockError(
            "Docker container requires one exact persistent Monitor authority "
            "RW bind at /var/lib/http-ztp-monitor-auth"
        )
    if expected_environment is not None:
        raw_environment = config.get("Env") if isinstance(config, dict) else None
        if not isinstance(raw_environment, list):
            raise HostLockError(
                "Docker runtime configuration drift; run deploy"
            )
        actual_environment: dict[str, str] = {}
        duplicate_keys = set()
        for item in raw_environment:
            if not isinstance(item, str) or "=" not in item:
                raise HostLockError(
                    "Docker runtime configuration drift; run deploy"
                )
            key, value = item.split("=", 1)
            if key in actual_environment:
                duplicate_keys.add(key)
            actual_environment[key] = value
        mismatches = sorted(
            key for key, value in expected_environment.items()
            if actual_environment.get(key) != value or key in duplicate_keys
        )
        if mismatches:
            raise HostLockError(
                "Docker runtime configuration drift; run deploy "
                "(mismatched keys: " + ", ".join(mismatches) + ")"
            )
    return record


def capture_owned_container_id(
    *,
    lock_path: Path = DEFAULT_LOCK,
    wait_seconds: float = 600,
    require_running: bool = False,
    allow_absent: bool = False,
    expected_environment: Optional[Mapping[str, str]] = None,
    runner=subprocess.run,
) -> Optional[str]:
    """Validate the fixed-name container under lock and return its stable ID.

    The deployment lock is deliberately released before the caller invokes
    ``docker exec`` or ``docker logs``.  An immutable ID cannot be redirected
    to a later foreign container that reuses the public name.
    """

    with safe_lock(lock_path, wait_seconds):
        record = inspect_owned_container(
            runner, expected_environment=expected_environment,
        )
        if record is None:
            if allow_absent:
                return None
            raise HostLockError(f"Docker container {CONTAINER_NAME} does not exist")
        if require_running:
            state = record.get("State")
            if not isinstance(state, dict) or state.get("Running") is not True:
                raise HostLockError(
                    f"Docker container {CONTAINER_NAME} is not running"
                )
            if state.get("Restarting") is True or state.get("Paused") is True:
                raise HostLockError(
                    f"Docker container {CONTAINER_NAME} is not stably running"
                )
        return str(record["Id"])


def _docker_result(
    runner, command: Sequence[str], purpose: str,
) -> subprocess.CompletedProcess:
    try:
        result = runner(
            list(command), capture_output=True, text=True, check=False, timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise HostLockError(f"cannot validate local rootful Docker ({purpose}): {exc}") from exc
    if result.returncode != 0:
        detail = str(result.stderr or result.stdout or "").strip()
        raise HostLockError(
            f"cannot validate local rootful Docker ({purpose})"
            + (f": {detail}" if detail else f" (exit={result.returncode})")
        )
    return result


def validate_local_rootful_docker(
    *,
    runner=subprocess.run,
    environ: Optional[Mapping[str, str]] = None,
    socket_path: Path = Path("/var/run/docker.sock"),
    expected_socket_uid: int = 0,
) -> None:
    """Reject remote contexts/endpoints and rootless Docker daemons."""

    environment = os.environ if environ is None else environ
    docker_host = str(environment.get("DOCKER_HOST") or "").strip()
    docker_context = str(environment.get("DOCKER_CONTEXT") or "").strip()
    if docker_host not in {"", "unix:///var/run/docker.sock"}:
        raise HostLockError(
            "remote DOCKER_HOST is forbidden; require local rootful Docker"
        )
    if docker_context not in {"", "default"}:
        raise HostLockError(
            "remote Docker context is forbidden; require local rootful Docker"
        )
    if any(
        str(environment.get(key) or "").strip()
        for key in ("DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH")
    ):
        raise HostLockError(
            "remote Docker TLS selection is forbidden; require local rootful Docker"
        )

    context = _docker_result(
        runner, ("docker", "context", "show"), "context selection",
    ).stdout.strip()
    if context != "default":
        raise HostLockError(
            "remote Docker context is forbidden; require local rootful Docker"
        )
    context_payload = _docker_result(
        runner, ("docker", "context", "inspect", context), "context endpoint",
    ).stdout
    try:
        context_records = json.loads(context_payload)
        endpoint = context_records[0]["Endpoints"]["docker"]
    except (IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise HostLockError(
            "cannot validate local rootful Docker context endpoint"
        ) from exc
    if not isinstance(endpoint, dict) or (
        endpoint.get("Host") != "unix:///var/run/docker.sock"
        or endpoint.get("SkipTLSVerify") is True
    ):
        raise HostLockError(
            "remote Docker endpoint is forbidden; require local rootful Docker"
        )

    try:
        socket_status = os.lstat(socket_path)
    except OSError as exc:
        raise HostLockError(
            f"cannot validate local rootful Docker socket: {exc}"
        ) from exc
    if (
        not stat.S_ISSOCK(socket_status.st_mode)
        or socket_status.st_uid != expected_socket_uid
    ):
        raise HostLockError(
            "local Docker socket must be a root-owned Unix socket"
        )

    info_payload = _docker_result(
        runner, ("docker", "info", "--format", "{{json .}}"), "daemon info",
    ).stdout
    try:
        info = json.loads(info_payload)
    except (TypeError, json.JSONDecodeError) as exc:
        raise HostLockError("Docker daemon info is not valid JSON") from exc
    if not isinstance(info, dict) or info.get("OSType") != "linux":
        raise HostLockError("local rootful Docker daemon must have Linux OSType")
    security_options = info.get("SecurityOptions")
    if not isinstance(security_options, list):
        raise HostLockError("Docker daemon security options are missing")
    if any("rootless" in str(option).casefold() for option in security_options):
        raise HostLockError("rootless Docker daemon is unsupported")


def _preloaded_failure_detail(result: object) -> str:
    detail = str(
        getattr(result, "stderr", "") or getattr(result, "stdout", "") or ""
    ).strip().replace("\x00", "")
    return detail[:2048]


def _require_bounded_probe_result(result: object, label: str) -> None:
    for stream_name in ("stdout", "stderr"):
        value = getattr(result, stream_name, "") or ""
        if len(str(value).encode("utf-8", errors="replace")) > PRELOADED_PROBE_OUTPUT_LIMIT:
            raise HostLockError(
                f"{label} {stream_name} exceeds the bounded probe output limit"
            )


def _run_preloaded_probe(
    runner, create_command: Sequence[str], *, label: str, run_timeout: int,
) -> str:
    command = list(create_command)
    if command[:2] != ["docker", "create"] or "--name" in command:
        raise HostLockError(f"{label} container creation command is unsafe")
    probe_name = "http-ztp-preloaded-probe-" + secrets.token_hex(16)
    command[2:2] = ["--name", probe_name]
    cleanup_target = probe_name
    probe_error: Optional[BaseException] = None
    output = ""
    try:
        try:
            created = runner(
                command,
                capture_output=True, text=True, check=False, timeout=30,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise HostLockError(
                f"{label} container could not be created: {exc}"
            ) from exc
        if created.returncode != 0:
            detail = _preloaded_failure_detail(created)
            raise HostLockError(
                f"{label} container creation failed"
                + (f": {detail}" if detail else f" (exit={created.returncode})")
            )
        _require_bounded_probe_result(created, f"{label} container creation")
        probe_id = str(created.stdout or "").strip()
        if not re.fullmatch(r"[0-9a-f]{64}", probe_id):
            raise HostLockError(f"{label} container identity is invalid")
        cleanup_target = probe_id

        try:
            started = runner(
                ["docker", "start", probe_id],
                capture_output=True, text=True, check=False, timeout=30,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise HostLockError(f"{label} could not start: {exc}") from exc
        _require_bounded_probe_result(started, f"{label} start")
        if started.returncode != 0:
            detail = _preloaded_failure_detail(started)
            raise HostLockError(
                f"{label} could not start"
                + (f": {detail}" if detail else f" (exit={started.returncode})")
            )

        try:
            waited = runner(
                ["docker", "wait", probe_id],
                capture_output=True, text=True, check=False, timeout=run_timeout,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise HostLockError(f"{label} could not wait: {exc}") from exc
        _require_bounded_probe_result(waited, f"{label} wait")
        if waited.returncode != 0:
            detail = _preloaded_failure_detail(waited)
            raise HostLockError(
                f"{label} wait failed"
                + (f": {detail}" if detail else f" (exit={waited.returncode})")
            )
        status_text = str(waited.stdout or "").strip()
        if not re.fullmatch(r"[0-9]{1,3}", status_text) or int(status_text) > 255:
            raise HostLockError(f"{label} returned an invalid container exit status")
        container_status = int(status_text)

        try:
            logged = runner(
                ["docker", "logs", "--tail", "1", probe_id],
                capture_output=True, text=True, check=False, timeout=30,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise HostLockError(f"{label} logs could not be read: {exc}") from exc
        _require_bounded_probe_result(logged, f"{label} logs")
        if logged.returncode != 0:
            detail = _preloaded_failure_detail(logged)
            raise HostLockError(
                f"{label} logs could not be read"
                + (f": {detail}" if detail else f" (exit={logged.returncode})")
            )
        if container_status != 0:
            detail = _preloaded_failure_detail(logged)
            raise HostLockError(
                f"{label} failed"
                + (f": {detail}" if detail else f" (exit={container_status})")
            )
        if str(logged.stderr or ""):
            raise HostLockError(f"{label} emitted unexpected stderr")
        output = str(logged.stdout or "")
    except BaseException as exc:
        probe_error = exc

    cleanup_error = None
    try:
        removed = runner(
            ["docker", "rm", "--force", cleanup_target],
            capture_output=True, text=True, check=False, timeout=30,
        )
        _require_bounded_probe_result(removed, f"{label} cleanup")
        if removed.returncode != 0:
            detail = _preloaded_failure_detail(removed)
            cleanup_error = HostLockError(
                f"cannot remove {label} container"
                + (f": {detail}" if detail else f" (exit={removed.returncode})")
            )
    except HostLockError as exc:
        cleanup_error = exc
    except (OSError, subprocess.SubprocessError) as exc:
        cleanup_error = HostLockError(f"cannot remove {label} container: {exc}")
    if cleanup_error is not None:
        if probe_error is not None:
            raise HostLockError(
                f"{probe_error}; cleanup also failed: {cleanup_error}"
            ) from probe_error
        raise cleanup_error
    if probe_error is not None:
        raise probe_error
    return output


def verify_preloaded_image(
    image_id: str,
    expected_architecture: str,
    *,
    expected_flavor: str = "generic",
    expected_project: Optional[str] = None,
    expected_upgrade_policy: Optional[str] = None,
    lock_path: Path = DEFAULT_LOCK,
    wait_seconds: float = 600,
    runner=subprocess.run,
) -> str:
    """Verify one immutable, already-loaded image and its live source receipt."""

    if not IMAGE_ID_PATTERN.fullmatch(str(image_id)):
        raise HostLockError(
            "preloaded deployment requires one full lowercase sha256 immutable image ID"
        )
    if expected_architecture not in {"arm64", "amd64"}:
        raise HostLockError("preloaded image expected architecture is unsupported")
    if expected_flavor not in {"generic", "project"}:
        raise HostLockError("preloaded image expected flavor is unsupported")
    if expected_flavor == "generic" and expected_project is not None:
        raise HostLockError("generic image verification cannot select a project")
    if expected_flavor == "generic" and expected_upgrade_policy is not None:
        raise HostLockError(
            "generic image verification cannot select an upgrade policy"
        )
    if expected_flavor == "project" and (
        not isinstance(expected_project, str)
        or not SAFE_PROJECT_NAME.fullmatch(expected_project)
    ):
        raise HostLockError("project image verification requires one safe project name")
    if expected_flavor == "project" and expected_upgrade_policy not in {
        "enabled", "disabled",
    }:
        raise HostLockError(
            "project image verification requires an explicit upgrade policy"
        )

    with safe_lock(lock_path, wait_seconds):
        try:
            inspected = runner(
                ["docker", "image", "inspect", image_id],
                capture_output=True, text=True, check=False, timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise HostLockError(f"cannot inspect preloaded Docker image: {exc}") from exc
        if inspected.returncode != 0:
            detail = _preloaded_failure_detail(inspected)
            raise HostLockError(
                "cannot inspect preloaded Docker image"
                + (f": {detail}" if detail else f" (exit={inspected.returncode})")
            )
        try:
            payload = json.loads(inspected.stdout)
        except (TypeError, json.JSONDecodeError) as exc:
            raise HostLockError("preloaded Docker image inspect returned invalid JSON") from exc
        if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
            raise HostLockError("preloaded Docker image inspect returned an unexpected image set")
        record = payload[0]
        if record.get("Id") != image_id:
            raise HostLockError("preloaded Docker image immutable identity changed")
        if record.get("Os") != "linux":
            raise HostLockError("preloaded Docker image must use Linux")
        if record.get("Architecture") != expected_architecture:
            raise HostLockError(
                "preloaded Docker image architecture does not match this host"
            )
        config = record.get("Config")
        if not isinstance(config, dict):
            raise HostLockError("preloaded Docker image configuration is missing")
        labels = config.get("Labels")
        if not isinstance(labels, dict):
            raise HostLockError("preloaded Docker image contract labels are missing")
        if labels.get("com.nvidia.http-ztp.image-contract") == (
            LEGACY_CLEANUP_IMAGE_CONTRACT
        ):
            raise HostLockError(
                "preloaded image contract 2 is cleanup-only and cannot be probed "
                "or reused; rebuild or re-export a contract 3 image"
            )
        for key, expected in IMAGE_LABELS.items():
            if labels.get(key) != expected:
                label = "base OS label" if key.endswith("base-os") else "image contract label"
                raise HostLockError(f"preloaded Docker image {label} does not match")
        actual_flavor = labels.get(IMAGE_FLAVOR_LABEL)
        if actual_flavor != expected_flavor:
            raise HostLockError(
                "preloaded Docker image flavor does not match the requested lifecycle"
            )
        project_only = {
            PROJECT_IMAGE_LABEL,
            PROJECT_UPLOAD_LABEL,
            PROJECT_SOURCE_LABEL,
            PROJECT_SHARED_LABEL,
            PROJECT_UPGRADE_POLICY_LABEL,
            *PROJECT_BOOTSTRAP_LABELS.values(),
        }
        if expected_flavor == "generic":
            if any(key in labels for key in project_only):
                raise HostLockError(
                    "generic preloaded image carries forbidden project labels"
                )
        else:
            if labels.get(PROJECT_IMAGE_LABEL) != expected_project:
                raise HostLockError("preloaded project image project does not match")
            for key in (PROJECT_UPLOAD_LABEL, PROJECT_SOURCE_LABEL):
                value = labels.get(key)
                if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
                    raise HostLockError(
                        "preloaded project image authority labels do not match"
                    )
            shared = labels.get(PROJECT_SHARED_LABEL)
            if shared is not None and (
                not isinstance(shared, str)
                or not re.fullmatch(r"[0-9a-f]{64}", shared)
            ):
                raise HostLockError(
                    "preloaded project image shared-artifact label does not match"
                )
            if labels.get(PROJECT_UPGRADE_POLICY_LABEL) != expected_upgrade_policy:
                raise HostLockError(
                    "preloaded project image upgrade policy does not match"
                )
            for tool_name, key in PROJECT_BOOTSTRAP_LABELS.items():
                value = labels.get(key)
                if not isinstance(value, str) or not re.fullmatch(
                    r"[0-9a-f]{64}", value,
                ):
                    raise HostLockError(
                        "preloaded project image bootstrap tool label does not match: "
                        + tool_name
                    )
        if config.get("Entrypoint") != IMAGE_ENTRYPOINT:
            raise HostLockError("preloaded Docker image entrypoint does not match")
        if config.get("Cmd") != IMAGE_COMMAND:
            raise HostLockError("preloaded Docker image command does not match")
        if config.get("User") != "root":
            raise HostLockError("preloaded Docker image must declare the root user")
        if config.get("WorkingDir") != os.fspath(HTTP_ROOT):
            raise HostLockError("preloaded Docker image working directory does not match")
        raw_environment = config.get("Env")
        if raw_environment != IMAGE_ENVIRONMENT:
            if isinstance(raw_environment, list):
                if any(
                    not isinstance(item, str) or "=" not in item
                    for item in raw_environment
                ):
                    raise HostLockError(
                        "preloaded Docker image environment value does not match"
                    )
                keys = [
                    item.split("=", 1)[0]
                    for item in raw_environment
                ]
                if any(key not in {"PATH", "PYTHONDONTWRITEBYTECODE"} for key in keys):
                    raise HostLockError(
                        "preloaded Docker image environment injection is forbidden"
                    )
                if any(
                    isinstance(item, str) and item.startswith("PATH=")
                    and item != IMAGE_ENVIRONMENT[0]
                    for item in raw_environment
                ):
                    raise HostLockError(
                        "preloaded Docker image environment PATH does not match"
                    )
                if all(isinstance(item, str) for item in raw_environment) and (
                    sorted(raw_environment) == sorted(IMAGE_ENVIRONMENT)
                ):
                    raise HostLockError(
                        "preloaded Docker image environment order does not match"
                    )
            raise HostLockError("preloaded Docker image environment does not match")
        healthcheck = config.get("Healthcheck")
        if not isinstance(healthcheck, dict) or any(
            healthcheck.get(key) != value for key, value in IMAGE_HEALTHCHECK.items()
        ):
            raise HostLockError("preloaded Docker image healthcheck does not match")

        probe_command = [
            "docker", "create",
            *PRELOADED_PROBE_LIMITS,
            "--network", "none",
            "--read-only",
            "--no-healthcheck",
            "--user", "0:0",
            "--env", "PYTHONDONTWRITEBYTECODE=1",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true",
            "--mount", "type=bind,src=/var/www/html,dst=/var/www/html,readonly",
            "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=16m",
            "--entrypoint", "/opt/http-ztp/activate.py",
            image_id,
            "verify-deployment-image",
            "--source-root", "/var/www/html",
            "--manifest", "/opt/http-ztp/image-source.sha256",
        ]
        try:
            verification = json.loads(_run_preloaded_probe(
                runner, probe_command,
                label="preloaded image source verification", run_timeout=600,
            ))
        except (TypeError, json.JSONDecodeError) as exc:
            raise HostLockError(
                "preloaded image source verification result is invalid"
            ) from exc
        if not (
            isinstance(verification, dict)
            and set(verification) == {"verified", "files", "os", "version"}
            and verification.get("verified") is True
            and type(verification.get("files")) is int
            and verification["files"] > 0
            and verification.get("os") == "ubuntu"
            and verification.get("version") == "24.04"
        ):
            raise HostLockError(
                "preloaded image source verification result is invalid"
            )

        if expected_flavor == "project":
            payload_command = [
                "docker", "create",
                *PRELOADED_PROBE_LIMITS,
                "--network", "none",
                "--read-only",
                "--no-healthcheck",
                "--user", "0:0",
                "--env", "PYTHONDONTWRITEBYTECODE=1",
                "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges:true",
                "--mount", "type=bind,src=/var/www/html,dst=/var/www/html,readonly",
                "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=16m",
                "--entrypoint", "/usr/bin/python3",
                image_id,
                "/opt/http-ztp/project-bootstrap/tools/package-project-image.py",
                "install",
                "--root", "/var/www/html",
                "--verify-only",
                "--machine-readable",
            ]
            try:
                payload = json.loads(_run_preloaded_probe(
                    runner, payload_command,
                    label="preloaded image embedded project payload verification",
                    run_timeout=600,
                ))
            except (TypeError, json.JSONDecodeError) as exc:
                raise HostLockError(
                    "preloaded image embedded project payload verification result is invalid"
                ) from exc
            expected_payload = {
                "bootstrap_tools": {
                    name: labels.get(key)
                    for name, key in PROJECT_BOOTSTRAP_LABELS.items()
                },
                "image_contract": "3",
                "project": expected_project,
                "shared_archive_sha256": labels.get(PROJECT_SHARED_LABEL),
                "source_manifest_sha256": labels.get(PROJECT_SOURCE_LABEL),
                "upload_archive_sha256": labels.get(PROJECT_UPLOAD_LABEL),
                "upgrade_policy": expected_upgrade_policy,
                "verified": True,
            }
            if payload != expected_payload:
                raise HostLockError(
                    "preloaded image embedded project payload does not match labels"
                )
    return image_id


def _validate_rotation_image(
    image_id: str, *, runner=subprocess.run,
) -> None:
    if not IMAGE_ID_PATTERN.fullmatch(image_id):
        raise HostLockError("owned Docker image immutable identity is invalid")
    try:
        inspected = runner(
            ["docker", "image", "inspect", image_id],
            capture_output=True, text=True, check=False, timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise HostLockError(
            f"cannot inspect immutable image for credential rotation: {exc}"
        ) from exc
    if inspected.returncode != 0:
        raise HostLockError(
            "cannot inspect immutable image for credential rotation"
        )
    try:
        payload = json.loads(inspected.stdout)
    except (TypeError, json.JSONDecodeError) as exc:
        raise HostLockError(
            "credential rotation image inspect returned invalid JSON"
        ) from exc
    if (
        not isinstance(payload, list)
        or len(payload) != 1
        or not isinstance(payload[0], dict)
        or payload[0].get("Id") != image_id
    ):
        raise HostLockError("credential rotation image identity changed")
    config = payload[0].get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    if not isinstance(labels, dict) or any(
        labels.get(key) != value for key, value in IMAGE_LABELS.items()
    ):
        actual_contract = (
            labels.get("com.nvidia.http-ztp.image-contract")
            if isinstance(labels, dict) else None
        )
        if actual_contract == LEGACY_CLEANUP_IMAGE_CONTRACT:
            raise HostLockError(
                "image contract 2 is cleanup-only; credential rotation requires "
                "a contract 3 image"
            )
        raise HostLockError(
            "credential rotation requires an immutable contract 3 image"
        )


@contextmanager
def _validated_rotation_terminal() -> Iterator[int]:
    """Hold the exact human terminal used only by one rotation one-shot."""
    flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open("/dev/tty", flags)
    except OSError as exc:
        raise HostLockError(
            "credential rotation requires a human at an interactive terminal "
            "on the management server; cannot safely open /dev/tty"
        ) from exc
    operation_error: Optional[BaseException] = None
    try:
        try:
            metadata = os.fstat(descriptor)
            terminal = os.isatty(descriptor)
        except OSError as exc:
            raise HostLockError(
                "credential rotation requires a human at an interactive terminal "
                "on the management server; cannot validate /dev/tty"
            ) from exc
        if not stat.S_ISCHR(metadata.st_mode) or not terminal:
            raise HostLockError(
                "credential rotation requires a human at an interactive terminal "
                "on the management server; /dev/tty is not a usable character TTY"
            )
        yield descriptor
    except BaseException as exc:
        operation_error = exc
        raise
    finally:
        try:
            os.close(descriptor)
        except OSError as exc:
            if operation_error is None:
                raise HostLockError(
                    "cannot close the credential rotation terminal authority"
                ) from exc


def rotate_control_auth(
    user: str,
    *,
    lock_path: Path = DEFAULT_LOCK,
    wait_seconds: float = 600,
    runner=subprocess.run,
) -> dict[str, bool]:
    """Rotate one record in a bounded, offline one-shot image process."""
    if user not in {"nvis", "cumulus"}:
        raise HostLockError("control auth user must be exactly nvis or cumulus")
    # Open and validate the exact host terminal before the first Docker
    # subprocess.  Its three streams go only to the interactive one-shot;
    # hostlock keeps its own stdout exclusively for post-validation JSON.
    with _validated_rotation_terminal() as terminal_descriptor:
        with safe_lock(lock_path, wait_seconds):
            module = _load_control_auth()
            _control_auth_status(module)
            record = inspect_owned_container(runner)
            if record is None:
                raise HostLockError(
                    "credential rotation requires an owned contract 3 container"
                )
            image_id = str(record.get("Image") or "")
            _validate_rotation_image(image_id, runner=runner)
            command = [
                "docker", "run", "--rm", "--interactive", "--tty",
                "--network", "none",
                "--read-only",
                # Creating the replacement with primary gid 33 avoids needing
                # CAP_CHOWN while still producing the required root:www-data file.
                "--user", "0:33",
                "--memory", "128m",
                "--memory-swap", "128m",
                "--pids-limit", "64",
                "--cpus", "1",
                "--log-driver", "none",
                "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges:true",
                "--mount",
                (
                    "type=bind,src=" + os.fspath(CONTROL_AUTH_HOST_DIRECTORY)
                    + ",dst=" + os.fspath(CONTROL_AUTH_CONTAINER_DIRECTORY)
                ),
                "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=16m",
                "--entrypoint", os.fspath(CONTROL_AUTH_CONTAINER_HELPER),
                image_id,
                "rotate", "--user", user,
            ]
            transport_error: Optional[BaseException] = None
            returncode: Optional[int] = None
            try:
                completed = runner(
                    command,
                    stdin=terminal_descriptor,
                    stdout=terminal_descriptor,
                    stderr=terminal_descriptor,
                    close_fds=True,
                    check=False,
                )
                returncode = int(getattr(completed, "returncode", 1))
            except (
                OSError, subprocess.SubprocessError, TypeError, ValueError,
            ) as exc:
                transport_error = exc

            # A nonzero/transport result is not rollback authority: the helper may
            # already have replaced the record before reporting a durability or
            # cleanup failure.  Always attest the host bytes once, never retry the
            # one-shot automatically, and never guess which password is active.
            try:
                post_status = _control_auth_status(module)
            except HostLockError as exc:
                raise HostLockError(
                    "credential rotation outcome is indeterminate because host "
                    "post-validation failed; do not blindly retry or assume which "
                    "password is active"
                ) from exc
            if transport_error is not None or returncode != 0:
                factory = str(post_status["factory_records_active"]).lower()
                raise HostLockError(
                    "credential rotation did not return success; "
                    "control_auth.valid=true, "
                    f"control_auth.factory_records_active={factory}, but commit "
                    "or durability is unknown; do not blindly retry or assume "
                    "which password is active"
                ) from transport_error
            return post_status


def _container_is_live(record: dict) -> bool:
    state = record.get("State")
    if not isinstance(state, dict):
        raise HostLockError("Docker container state is missing")
    return any(state.get(key) is True for key in ("Running", "Restarting", "Paused"))


def _require_stably_stopped(record: dict, identifier: str) -> None:
    if record.get("Id") != identifier or _container_is_live(record):
        raise HostLockError("Docker container did not stop with stable identity")
    state = record.get("State", {})
    if str(state.get("Status") or "").casefold() not in {"created", "exited"}:
        raise HostLockError("Docker container stopped in an unsafe state")
    try:
        pid = int(state.get("Pid", 0))
    except (TypeError, ValueError) as exc:
        raise HostLockError("Docker container has an invalid stopped PID") from exc
    if pid != 0 or state.get("Dead") is True:
        raise HostLockError("Docker container stopped state is not PID-zero/dead-free")


def _stop_remove_owned_container_locked(
    *, expected_owned_id: Optional[str] = None, runner=subprocess.run,
) -> None:
    """Stop/remove the validated fixed-name writer while the caller holds lock."""
    record = inspect_owned_container(runner, allow_legacy_cleanup=True)
    if record is None:
        if expected_owned_id is not None:
            raise HostLockError(
                "expected owned Docker container is absent; refusing cleanup"
            )
        return
    identifier = str(record["Id"])
    if expected_owned_id is not None and identifier != expected_owned_id:
        raise HostLockError(
            "owned Docker container identity changed after confirmation"
        )
    if _container_is_live(record):
        result = runner(
            ["docker", "stop", "--time", "30", identifier],
            capture_output=True, text=True, check=False, timeout=45,
        )
        if result.returncode != 0:
            raise HostLockError(
                "cannot stop owned Docker container: "
                + str(result.stderr or result.stdout or "").strip()
            )
        record = inspect_owned_container(
            runner, identifier, allow_legacy_cleanup=True,
        )
        if record is None:
            raise HostLockError("owned Docker container vanished during stop")
    _require_stably_stopped(record, identifier)
    result = runner(
        ["docker", "rm", identifier], capture_output=True, text=True,
        check=False, timeout=30,
    )
    if result.returncode != 0:
        raise HostLockError(
            "cannot remove owned Docker container: "
            + str(result.stderr or result.stdout or "").strip()
        )


def run_owned_container_action(
    action: str,
    *,
    lock_path: Path = DEFAULT_LOCK,
    wait_seconds: float = 600,
    activation_marker: Path = ACTIVATION_MARKER,
    expected_owned_id: Optional[str] = None,
    runner=subprocess.run,
) -> int:
    if action != "remove-clear":
        raise HostLockError(f"unsupported owned container action: {action}")
    if expected_owned_id is not None and not re.fullmatch(
        r"[0-9a-f]{64}", expected_owned_id,
    ):
        raise HostLockError("expected owned Docker container ID is invalid")
    with safe_lock(lock_path, wait_seconds):
        _stop_remove_owned_container_locked(
            expected_owned_id=expected_owned_id, runner=runner,
        )
        clear_activation_marker(activation_marker)
    return 0


def recover_monitor_authority_transaction(
    *,
    lock_path: Path = DEFAULT_LOCK,
    wait_seconds: float = 600,
    activation_marker: Path = ACTIVATION_MARKER,
    runner=subprocess.run,
    decision: bool = False,
) -> object:
    """Stop the sole writer, validate credentials, then explicitly recover."""
    with safe_lock(lock_path, wait_seconds):
        _stop_remove_owned_container_locked(runner=runner)
        clear_activation_marker(activation_marker)
        module = _load_control_auth()
        _control_auth_status(module)
        options = {
            "authority_boundary": Path("/"),
            "required_root_uid": 0,
            "required_root_gid": 0,
            "expected_helper_sha256": module._CONTROL_AUTH_SOURCE_SHA256,
        }
        diagnostics = io.StringIO() if decision else None
        try:
            with (
                redirect_stderr(diagnostics)
                if diagnostics is not None else nullcontext()
            ):
                recovery = _validated_monitor_recovery_result(
                    module.recover_monitor_authority(
                        MONITOR_AUTHORITY_HOST_ROOT, **options,
                    )
                )
            if not recovery["restart_allowed"]:
                if diagnostics is not None:
                    return module.monitor_authority_recovery_decision(
                        recovery, diagnostics.getvalue(),
                    )
                return recovery
            module.attest_monitor_authority(
                MONITOR_AUTHORITY_HOST_ROOT, **options,
            )
        except Exception as exc:
            raise HostLockError(
                f"explicit Monitor cache authority recovery failed: {exc}"
            ) from exc
        if diagnostics is not None:
            return module.monitor_authority_recovery_decision(
                recovery, diagnostics.getvalue(),
            )
        return recovery


def run_locked(
    command: Sequence[str],
    *,
    lock_path: Path = DEFAULT_LOCK,
    wait_seconds: int = 600,
    clear_activation: Optional[Path] = None,
    require_owned_or_absent: bool = False,
    runner=subprocess.run,
) -> int:
    if not command or not str(command[0]).strip():
        raise HostLockError("protected command is empty")
    with safe_lock(lock_path, wait_seconds):
        if require_owned_or_absent:
            inspect_owned_container(runner)
        command_error = None
        returncode = 2
        try:
            result = runner(list(command), check=False)
            returncode = int(result.returncode)
        except BaseException as exc:
            command_error = exc
        cleanup_error = None
        if clear_activation is not None:
            try:
                clear_activation_marker(clear_activation)
            except BaseException as exc:
                cleanup_error = exc
        if command_error is not None or cleanup_error is not None:
            details = []
            if command_error is not None:
                details.append(f"protected command failed: {command_error}")
            if cleanup_error is not None:
                details.append(f"activation cleanup failed: {cleanup_error}")
            raise HostLockError("; ".join(details)) from command_error
        if returncode == 0 and require_owned_or_absent:
            created = inspect_owned_container(runner)
            if created is None:
                raise HostLockError("protected Docker start did not create http-ztp")
        return returncode


def _expected_owned_id_argument(value: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise argparse.ArgumentTypeError(
            "expected owned container ID must be 64 lowercase hex characters"
        )
    return value


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    result.add_argument("--wait", type=int, default=600)
    result.add_argument("--clear-activation", action="store_true")
    result.add_argument("--require-owned-or-absent", action="store_true")
    result.add_argument("--owned-action", choices=("remove-clear",))
    result.add_argument("--expected-owned-id", type=_expected_owned_id_argument)
    result.add_argument("--expect-owned-or-absent", action="store_true")
    result.add_argument("--inspect-owned-id", action="store_true")
    result.add_argument("--allow-absent", action="store_true")
    result.add_argument("--require-running", action="store_true")
    result.add_argument("--expect-env", action="append", default=[])
    result.add_argument("--validate-local-daemon", action="store_true")
    result.add_argument("--prepare-control-auth", action="store_true")
    result.add_argument("--prepare-monitor-authority", action="store_true")
    result.add_argument("--attest-monitor-authority", action="store_true")
    result.add_argument("--recover-monitor-authority", action="store_true")
    result.add_argument(
        "--recover-monitor-authority-decision", action="store_true",
    )
    result.add_argument(
        "--rotate-control-auth", choices=("nvis", "cumulus"),
    )
    result.add_argument("--verify-preloaded-image")
    result.add_argument("--expected-architecture", choices=("arm64", "amd64"))
    result.add_argument("--expected-image-flavor", choices=("generic", "project"))
    result.add_argument("--expected-project")
    result.add_argument(
        "--expected-upgrade-policy", choices=("enabled", "disabled"),
    )
    result.add_argument("command", nargs=argparse.REMAINDER)
    return result


def _expected_environment(items: Sequence[str]) -> dict[str, str]:
    expected: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise HostLockError("expected runtime environment must be KEY=VALUE")
        key, value = item.split("=", 1)
        if not key or key in expected:
            raise HostLockError("expected runtime environment has an invalid key")
        expected[key] = value
    return expected


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parser().parse_args(argv)
    command = list(args.command)
    if command[:1] == ["--"]:
        command.pop(0)
    try:
        selected_modes = sum(bool(value) for value in (
            args.owned_action, args.inspect_owned_id, args.validate_local_daemon,
            args.prepare_control_auth, args.prepare_monitor_authority,
            args.attest_monitor_authority, args.recover_monitor_authority,
            args.recover_monitor_authority_decision,
            args.rotate_control_auth,
            args.verify_preloaded_image,
        ))
        if selected_modes > 1:
            raise HostLockError("choose only one host lifecycle action")
        if (args.expected_owned_id or args.expect_owned_or_absent) and not args.owned_action:
            raise HostLockError(
                "owned identity expectation requires --owned-action"
            )
        if args.expected_architecture and not args.verify_preloaded_image:
            raise HostLockError(
                "expected architecture is only valid for preloaded image verification"
            )
        if (
            args.expected_image_flavor
            or args.expected_project
            or args.expected_upgrade_policy
        ) and not args.verify_preloaded_image:
            raise HostLockError(
                "expected image flavor/project/upgrade policy is only valid for "
                "preloaded image verification"
            )
        if args.validate_local_daemon:
            if (
                command or args.expect_env or args.allow_absent or args.require_running
                or args.expected_architecture
                or args.expected_image_flavor or args.expected_project
                or args.expected_upgrade_policy
            ):
                raise HostLockError("local Docker validation takes no lifecycle options")
            validate_local_rootful_docker()
            return 0
        if args.prepare_control_auth:
            if (
                command or args.expect_env or args.allow_absent
                or args.require_running or args.expected_architecture
                or args.expected_image_flavor or args.expected_project
                or args.expected_upgrade_policy
            ):
                raise HostLockError(
                    "control auth preparation takes no lifecycle options"
                )
            print(json.dumps(
                prepare_control_auth(
                    lock_path=args.lock, wait_seconds=args.wait,
                ),
                sort_keys=True, separators=(",", ":"),
            ))
            return 0
        if args.prepare_monitor_authority:
            if (
                command or args.expect_env or args.allow_absent
                or args.require_running or args.expected_architecture
                or args.expected_image_flavor or args.expected_project
                or args.expected_upgrade_policy
            ):
                raise HostLockError(
                    "Monitor authority preparation takes no lifecycle options"
                )
            print(json.dumps(
                prepare_monitor_authority(
                    lock_path=args.lock, wait_seconds=args.wait,
                ),
                sort_keys=True, separators=(",", ":"),
            ))
            return 0
        if args.attest_monitor_authority:
            if (
                command or args.expect_env or args.allow_absent
                or args.require_running or args.expected_architecture
                or args.expected_image_flavor or args.expected_project
                or args.expected_upgrade_policy
            ):
                raise HostLockError(
                    "Monitor authority attestation takes no lifecycle options"
                )
            print(json.dumps(
                attest_monitor_authority(
                    lock_path=args.lock, wait_seconds=args.wait,
                ),
                sort_keys=True, separators=(",", ":"),
            ))
            return 0
        if args.recover_monitor_authority:
            if (
                command or args.expect_env or args.allow_absent
                or args.require_running or args.expected_architecture
                or args.expected_image_flavor or args.expected_project
                or args.expected_upgrade_policy
            ):
                raise HostLockError(
                    "Monitor authority recovery takes no lifecycle options"
                )
            recovery = recover_monitor_authority_transaction(
                lock_path=args.lock, wait_seconds=args.wait,
            )
            print(json.dumps(
                recovery, sort_keys=True, separators=(",", ":"),
            ))
            return 0 if recovery["restart_allowed"] else 2
        if args.recover_monitor_authority_decision:
            if (
                command or args.expect_env or args.allow_absent
                or args.require_running or args.expected_architecture
                or args.expected_image_flavor or args.expected_project
                or args.expected_upgrade_policy
            ):
                raise HostLockError(
                    "Monitor authority recovery decision takes no lifecycle options"
                )
            decision = recover_monitor_authority_transaction(
                lock_path=args.lock, wait_seconds=args.wait, decision=True,
            )
            if type(decision) is not str:
                raise HostLockError("Monitor authority decision is not text")
            sys.stdout.write(decision)
            return 0
        if args.rotate_control_auth:
            if (
                command or args.expect_env or args.allow_absent
                or args.require_running or args.expected_architecture
                or args.expected_image_flavor or args.expected_project
                or args.expected_upgrade_policy
            ):
                raise HostLockError(
                    "control auth rotation takes only one exact user"
                )
            print(json.dumps(
                rotate_control_auth(
                    args.rotate_control_auth,
                    lock_path=args.lock, wait_seconds=args.wait,
                ),
                sort_keys=True, separators=(",", ":"),
            ))
            return 0
        if args.verify_preloaded_image:
            if (
                command or args.expect_env or args.allow_absent or args.require_running
                or not args.expected_architecture
            ):
                raise HostLockError(
                    "preloaded image verification requires only its architecture"
                )
            identifier = verify_preloaded_image(
                args.verify_preloaded_image,
                args.expected_architecture,
                expected_flavor=args.expected_image_flavor or "generic",
                expected_project=args.expected_project,
                expected_upgrade_policy=args.expected_upgrade_policy,
                lock_path=args.lock,
                wait_seconds=args.wait,
            )
            print(identifier)
            return 0
        if args.inspect_owned_id:
            if command:
                raise HostLockError("owned container inspection takes no command")
            identifier = capture_owned_container_id(
                lock_path=args.lock,
                wait_seconds=args.wait,
                require_running=args.require_running,
                allow_absent=args.allow_absent,
                expected_environment=_expected_environment(args.expect_env),
            )
            if identifier is not None:
                print(identifier)
            return 0
        if args.owned_action:
            if command or args.expect_env or args.allow_absent or args.require_running:
                raise HostLockError("owned container action takes no command")
            if args.expected_owned_id is None and not args.expect_owned_or_absent:
                raise HostLockError(
                    "owned container action requires one expected identity"
                )
            if args.expected_owned_id is not None and args.expect_owned_or_absent:
                raise HostLockError(
                    "choose one owned container identity expectation"
                )
            if args.expected_owned_id is not None:
                return run_owned_container_action(
                    args.owned_action,
                    expected_owned_id=args.expected_owned_id,
                    lock_path=args.lock, wait_seconds=args.wait,
                )
            return run_owned_container_action(
                args.owned_action, lock_path=args.lock, wait_seconds=args.wait,
            )
        if args.expect_env or args.allow_absent or args.require_running:
            raise HostLockError("owned inspection options require --inspect-owned-id")
        return run_locked(
            command,
            lock_path=args.lock,
            wait_seconds=args.wait,
            clear_activation=(ACTIVATION_MARKER if args.clear_activation else None),
            require_owned_or_absent=args.require_owned_or_absent,
        )
    except (HostLockError, OSError, ValueError) as exc:
        print(f"[ERROR] safe host lifecycle refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
