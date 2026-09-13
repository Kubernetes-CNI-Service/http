#!/usr/bin/env python3
"""Safely initialize, validate, inspect, and rotate Monitor control users."""

from __future__ import annotations

import argparse
from contextlib import contextmanager, redirect_stderr
from dataclasses import dataclass
import fcntl
import getpass
import grp
import hmac
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import stat
import subprocess
import sys
from typing import Callable, Iterator, Sequence


AUTH_FILE = Path("/etc/http-ztp/control-users.htpasswd")
AUTH_DIRECTORY_MODE = 0o750
AUTH_FILE_MODE = 0o640
DIRECTORY_CREATE_MODE = 0o700
TEMP_FILE_MODE = 0o600
REQUIRED_UID = 0
REQUIRED_GID = 33
MAX_AUTH_FILE_SIZE = 4096
MAX_HTPASSWD_OUTPUT = 256
USERS = ("nvis", "cumulus")
HTPASSWD_PROGRAM = "/usr/bin/htpasswd"
FACTORY_RECORDS = (
    b"nvis:$2y$12$RyAe0IB4w1DkmGhdXsEcO.NqV7Of5hg1jIO9C9WiDOWRvYtdj3uVm\n"
    b"cumulus:$2y$12$O7a9ERzbhM6m5kdP5F4xZueHVne3U6lyVFxmL8fU1cvOVITEiIH0.\n"
)
_BCRYPT_RECORD = re.compile(r"^\$2y\$(\d\d)\$[./A-Za-z0-9]{53}$")
_SAFE_SUBPROCESS_ENV = {
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
}
_CANDIDATE_PREFIX = ".control-users.candidate."
_RECOVERY_PREFIX = ".control-users.recovery."
MONITOR_AUTHORITY_ROOT = Path("/var/lib/http-ztp-monitor-auth")
MONITOR_AUTHORITY_LOCK_NAME = "status.lock"
MONITOR_AUTHORITY_CACHE_NAME = "monitor-auth"
MONITOR_AUTHORITY_ROOT_MODE = 0o755
MONITOR_AUTHORITY_LOCK_MODE = 0o660
MONITOR_AUTHORITY_CACHE_MODE = 0o700
MONITOR_AUTHORITY_PRIVATE_MODE = 0o600
MONITOR_AUTHORITY_BREAKER_MAX_BYTES = 256
MONITOR_AUTHORITY_CACHE_MAX_BYTES = 512
MONITOR_AUTHORITY_BREAKER_SCHEMA = 1
MONITOR_AUTHORITY_CACHE_SCHEMA = 1
MONITOR_AUTHORITY_BREAKER_THRESHOLD = 3
MONITOR_AUTHORITY_FINAL_NAME = "factory-status.json"
MONITOR_AUTHORITY_RECOVERY_SCHEMA = 1
MONITOR_AUTHORITY_RECOVERY_PHASES = (
    "recovery-in-progress",
    "recovery-committed-cleanup-pending",
)
MONITOR_AUTHORITY_WWW_UID = 33
MONITOR_AUTHORITY_WWW_GID = 33
_MONITOR_CANDIDATE = re.compile(r"^\.factory-status\.[0-9a-f]{32}\.tmp$")
MONITOR_AUTHORITY_RECOVERY_WARNING = (
    "WARNING: explicit Monitor authority recovery reset invalid cache state; "
    "review the accepted www-data denial residual."
)
MONITOR_AUTHORITY_CLEANUP_DURABILITY_WARNING = (
    "WARNING: Monitor authority recovery committed, but marker cleanup "
    "durability is unknown; a stale completed marker may reappear after crash."
)
MONITOR_AUTHORITY_DECISION_TOKENS = (
    "attest-valid",
    "recovery-in-progress",
    "recovery-committed-cleanup-pending",
    "restart-allowed:complete;reset-invalid-cache=false",
    "restart-allowed:complete;reset-invalid-cache=true",
    "restart-allowed:marker-removal-durability-unknown;reset-invalid-cache=false",
    "restart-allowed:marker-removal-durability-unknown;reset-invalid-cache=true",
    "restart-blocked:marker-retained;reset-invalid-cache=false",
    "restart-blocked:marker-retained;reset-invalid-cache=true",
    "restart-blocked:marker-authority-uncertain;reset-invalid-cache=false",
    "restart-blocked:marker-authority-uncertain;reset-invalid-cache=true",
)
MONITOR_AUTHORITY_RECOVERY_CHECKPOINTS = (
    "marker-in-progress-write", "marker-in-progress-fsync",
    "marker-in-progress-rebind", "marker-in-progress-directory-fsync",
    "directory-fsync-before", "leaf-remove", "breaker-truncate",
    "breaker-fsync", "directory-fsync-after", "final-directory-fsync",
    "final-rebind", "final-attest",
    "marker-committed-truncate", "marker-committed-write",
    "marker-committed-fsync",
    "marker-committed-rebind", "marker-committed-directory-fsync",
    "marker-committed-attest",
)


class ControlAuthError(RuntimeError):
    """The credential state or requested operation is unsafe."""


class MonitorAuthorityMarkerError(ControlAuthError):
    """A canonical recovery phase blocks every routine authority reader."""

    def __init__(self, classification: str) -> None:
        if classification not in MONITOR_AUTHORITY_RECOVERY_PHASES:
            raise ValueError("invalid Monitor recovery marker classification")
        super().__init__(classification)
        self.classification = classification


class ControlAuthCommittedError(ControlAuthError):
    """A valid new target was selected, but the operation did not finish."""

    def __init__(
        self,
        message: str,
        *,
        durable: bool | None,
        valid: bool | None,
        recovery_name: str | None = None,
    ) -> None:
        super().__init__(message)
        self.committed = True
        self.durable = durable
        self.valid = valid
        self.recovery_name = _safe_recovery_basename(recovery_name)


class ControlAuthIndeterminateError(ControlAuthError):
    """Publication state cannot be stated safely after a detected conflict."""

    def __init__(
        self,
        message: str,
        *,
        committed: bool | None,
        durable: bool | None,
        valid: bool | None,
        recovery_name: str | None = None,
    ) -> None:
        super().__init__(message)
        self.committed = committed
        self.durable = durable
        self.valid = valid
        self.recovery_name = _safe_recovery_basename(recovery_name)


class _MissingAuthFile(ControlAuthError):
    """The credential file does not exist in an otherwise valid directory."""


@dataclass(frozen=True)
class AuthSnapshot:
    """One stable, validated read of the credential file."""

    data: bytes
    metadata: os.stat_result
    records: dict[str, str]


@dataclass(frozen=True)
class DirectoryBinding:
    """Stable authority for the opened canonical credential directory."""

    metadata: tuple[int, int, int, int, int]


@dataclass
class Candidate:
    """A private candidate whose descriptor remains held through publication."""

    descriptor: int
    name: str
    data: bytes
    metadata: os.stat_result


def _safe_recovery_basename(name: str | None) -> str | None:
    if name is None:
        return None
    if Path(name).name != name or not name.startswith(_RECOVERY_PREFIX):
        raise ValueError("unsafe recovery basename")
    return name


def _require_no_follow() -> int:
    value = getattr(os, "O_NOFOLLOW", None)
    if value is None:
        raise ControlAuthError("O_NOFOLLOW support is required")
    return value


def _directory_flags() -> int:
    directory = getattr(os, "O_DIRECTORY", None)
    if directory is None:
        raise ControlAuthError("O_DIRECTORY support is required")
    return (
        os.O_RDONLY
        | directory
        | _require_no_follow()
        | getattr(os, "O_CLOEXEC", 0)
    )


def _file_flags(*, writable: bool = False) -> int:
    access = os.O_RDWR if writable else os.O_RDONLY
    return (
        access
        | _require_no_follow()
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )


def _monitor_path_parts(
    authority_root: Path | str, authority_boundary: Path | str,
) -> tuple[Path, Path, tuple[str, ...]]:
    root = Path(authority_root)
    boundary = Path(authority_boundary)
    if not root.is_absolute() or not boundary.is_absolute():
        raise ControlAuthError("Monitor authority paths must be absolute")
    root_parts = root.parts
    boundary_parts = boundary.parts
    if (
        root == boundary
        or len(root_parts) <= len(boundary_parts)
        or root_parts[:len(boundary_parts)] != boundary_parts
        or any(part in {"", ".", ".."} for part in root_parts[1:])
        or any(part in {"", ".", ".."} for part in boundary_parts[1:])
    ):
        raise ControlAuthError("Monitor authority root is outside its boundary")
    return root, boundary, tuple(root_parts[len(boundary_parts):])


def _monitor_directory_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode),
        stat.S_IMODE(metadata.st_mode), metadata.st_uid, metadata.st_gid,
    )


def _validate_monitor_ancestor(
    metadata: os.stat_result, *, required_root_uid: int,
) -> None:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != required_root_uid
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise ControlAuthError(
            "Monitor authority ancestor must be root-owned and not writable "
            "by group or other"
        )


def _validate_monitor_root(
    metadata: os.stat_result, *, required_root_uid: int,
    required_root_gid: int,
) -> None:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != required_root_uid
        or metadata.st_gid != required_root_gid
        or stat.S_IMODE(metadata.st_mode) != MONITOR_AUTHORITY_ROOT_MODE
    ):
        raise ControlAuthError(
            "Monitor authority root must be root:root mode 0755"
        )


def _validate_monitor_lock(
    metadata: os.stat_result, *, required_root_uid: int,
    required_web_gid: int,
) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != required_root_uid
        or metadata.st_gid != required_web_gid
        or stat.S_IMODE(metadata.st_mode) != MONITOR_AUTHORITY_LOCK_MODE
        or metadata.st_size < 0
        or metadata.st_size > MONITOR_AUTHORITY_BREAKER_MAX_BYTES
    ):
        raise ControlAuthError(
            "Monitor authority lock must be one root:www-data regular file "
            "with mode 0660"
        )


def _validate_monitor_cache_directory(
    metadata: os.stat_result, *, required_web_uid: int,
    required_web_gid: int,
) -> None:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != required_web_uid
        or metadata.st_gid != required_web_gid
        or stat.S_IMODE(metadata.st_mode) != MONITOR_AUTHORITY_CACHE_MODE
    ):
        raise ControlAuthError(
            "Monitor cache directory must be www-data:www-data mode 0700"
        )


def _validate_monitor_private_leaf(
    metadata: os.stat_result, *, required_web_uid: int,
    required_web_gid: int,
) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != required_web_uid
        or metadata.st_gid != required_web_gid
        or stat.S_IMODE(metadata.st_mode) != MONITOR_AUTHORITY_PRIVATE_MODE
        or metadata.st_size < 0
        or metadata.st_size > MONITOR_AUTHORITY_CACHE_MAX_BYTES
    ):
        raise ControlAuthError(
            "Monitor cache leaf must be one private www-data regular file"
        )


def _canonical_monitor_payload(payload: dict[str, object]) -> bytes:
    try:
        rendered = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        )
        return (rendered + "\n").encode("ascii")
    except (TypeError, UnicodeError, ValueError) as exc:
        raise ControlAuthError("Monitor authority payload is not canonical") from exc


def parse_monitor_authority_breaker(data: bytes) -> dict[str, int] | None:
    """Validate the sole canonical breaker grammar shared with the CGI."""
    if type(data) is not bytes or len(data) > MONITOR_AUTHORITY_BREAKER_MAX_BYTES:
        raise ControlAuthError("Monitor authority breaker payload is invalid")
    if not data:
        return None
    try:
        payload = json.loads(data.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ControlAuthError("Monitor authority breaker payload is invalid") from exc
    expected_keys = {
        "schema_version", "contaminant_dev", "contaminant_ino", "failure_count",
    }
    if (
        not isinstance(payload, dict)
        or set(payload) != expected_keys
        or type(payload.get("schema_version")) is not int
        or payload["schema_version"] != MONITOR_AUTHORITY_BREAKER_SCHEMA
        or type(payload.get("contaminant_dev")) is not int
        or payload["contaminant_dev"] < 0
        or type(payload.get("contaminant_ino")) is not int
        or payload["contaminant_ino"] <= 0
        or type(payload.get("failure_count")) is not int
        or not 1 <= payload["failure_count"] <= MONITOR_AUTHORITY_BREAKER_THRESHOLD
        or data != _canonical_monitor_payload(payload)
    ):
        raise ControlAuthError("Monitor authority breaker payload is invalid")
    return payload


def build_monitor_authority_breaker(
    *, contaminant_dev: int, contaminant_ino: int, failure_count: int,
) -> bytes:
    """Build only the canonical breaker grammar accepted by the shared parser."""
    data = _canonical_monitor_payload({
        "schema_version": MONITOR_AUTHORITY_BREAKER_SCHEMA,
        "contaminant_dev": contaminant_dev,
        "contaminant_ino": contaminant_ino,
        "failure_count": failure_count,
    })
    parse_monitor_authority_breaker(data)
    return data


def _validated_monitor_helper_digest(expected_helper_sha256: str) -> str:
    if (
        type(expected_helper_sha256) is not str
        or len(expected_helper_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_helper_sha256)
    ):
        raise ControlAuthError("Monitor helper digest is invalid")
    return expected_helper_sha256


def parse_monitor_authority_cache(
    data: bytes, *, expected_helper_sha256: str,
) -> bool:
    """Validate one nonempty canonical schema-1 helper-bound cache record."""
    digest = _validated_monitor_helper_digest(expected_helper_sha256)
    if (
        type(data) is not bytes
        or not data
        or len(data) > MONITOR_AUTHORITY_CACHE_MAX_BYTES
    ):
        raise ControlAuthError("Monitor authority cache payload is invalid")
    try:
        payload = json.loads(data.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ControlAuthError("Monitor authority cache payload is invalid") from exc
    if (
        not isinstance(payload, dict)
        or set(payload) != {
            "schema_version", "factory_records_active", "helper_sha256",
        }
        or type(payload.get("schema_version")) is not int
        or payload["schema_version"] != MONITOR_AUTHORITY_CACHE_SCHEMA
        or type(payload.get("factory_records_active")) is not bool
        or payload.get("helper_sha256") != digest
        or data != _canonical_monitor_payload(payload)
    ):
        raise ControlAuthError("Monitor authority cache payload is invalid")
    return payload["factory_records_active"]


def build_monitor_authority_cache(
    factory_records_active: bool, *, expected_helper_sha256: str,
) -> bytes:
    """Build only the canonical helper-bound cache grammar accepted above."""
    if type(factory_records_active) is not bool:
        raise ControlAuthError("Monitor authority cache value is invalid")
    digest = _validated_monitor_helper_digest(expected_helper_sha256)
    data = _canonical_monitor_payload({
        "schema_version": MONITOR_AUTHORITY_CACHE_SCHEMA,
        "factory_records_active": factory_records_active,
        "helper_sha256": digest,
    })
    parse_monitor_authority_cache(data, expected_helper_sha256=digest)
    return data


def parse_monitor_authority_recovery_marker(data: bytes) -> dict[str, object]:
    """Parse one exact non-secret recovery phase record."""
    if (
        type(data) is not bytes
        or not data
        or len(data) > MONITOR_AUTHORITY_CACHE_MAX_BYTES
    ):
        raise ControlAuthError("Monitor authority recovery marker is invalid")
    try:
        payload = json.loads(data.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ControlAuthError("Monitor authority recovery marker is invalid") from exc
    if (
        not isinstance(payload, dict)
        or set(payload) != {"phase", "schema_version"}
        or type(payload.get("schema_version")) is not int
        or payload["schema_version"] != MONITOR_AUTHORITY_RECOVERY_SCHEMA
        or type(payload.get("phase")) is not str
        or payload["phase"] not in MONITOR_AUTHORITY_RECOVERY_PHASES
        or data != _canonical_monitor_payload(payload)
    ):
        raise ControlAuthError("Monitor authority recovery marker is invalid")
    return payload


def build_monitor_authority_recovery_marker(phase: str) -> bytes:
    """Build a canonical recovery marker owned by the shared semantic API."""
    if type(phase) is not str or phase not in MONITOR_AUTHORITY_RECOVERY_PHASES:
        raise ControlAuthError("Monitor authority recovery phase is invalid")
    data = _canonical_monitor_payload({
        "phase": phase,
        "schema_version": MONITOR_AUTHORITY_RECOVERY_SCHEMA,
    })
    parse_monitor_authority_recovery_marker(data)
    return data


def _monitor_stable_file_metadata(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid,
        metadata.st_gid, metadata.st_nlink, metadata.st_size,
        getattr(metadata, "st_mtime_ns", int(metadata.st_mtime * 1_000_000_000)),
        getattr(metadata, "st_ctime_ns", int(metadata.st_ctime * 1_000_000_000)),
    )


def _read_monitor_descriptor(
    descriptor: int, *, maximum: int, label: str,
) -> tuple[bytes, os.stat_result]:
    try:
        before = os.fstat(descriptor)
        if before.st_size < 0 or before.st_size > maximum:
            raise ControlAuthError(f"Monitor authority {label} size is invalid")
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                raise ControlAuthError(
                    f"Monitor authority {label} changed while being read"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ControlAuthError(
                f"Monitor authority {label} grew while being read"
            )
        after = os.fstat(descriptor)
    except ControlAuthError:
        raise
    except OSError as exc:
        raise ControlAuthError(f"cannot read Monitor authority {label}") from exc
    if _monitor_stable_file_metadata(before) != _monitor_stable_file_metadata(after):
        raise ControlAuthError(f"Monitor authority {label} identity changed")
    return b"".join(chunks), after


def _monitor_bound_metadata(
    parent_descriptor: int, name: str, descriptor: int,
) -> os.stat_result:
    try:
        held = os.fstat(descriptor)
        named = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except OSError as exc:
        raise ControlAuthError("Monitor authority canonical leaf is unavailable") from exc
    if (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino):
        raise ControlAuthError("Monitor authority canonical leaf binding changed")
    return held


def _read_monitor_named_private_leaf(
    directory_descriptor: int, name: str, *, required_web_uid: int,
    required_web_gid: int,
) -> bytes:
    descriptor = -1
    try:
        descriptor = os.open(name, _file_flags(), dir_fd=directory_descriptor)
        metadata = _monitor_bound_metadata(directory_descriptor, name, descriptor)
        _validate_monitor_private_leaf(
            metadata,
            required_web_uid=required_web_uid,
            required_web_gid=required_web_gid,
        )
        data, after = _read_monitor_descriptor(
            descriptor, maximum=MONITOR_AUTHORITY_CACHE_MAX_BYTES, label="cache leaf",
        )
        rebound = _monitor_bound_metadata(directory_descriptor, name, descriptor)
        if _monitor_stable_file_metadata(after) != _monitor_stable_file_metadata(rebound):
            raise ControlAuthError("Monitor authority cache leaf changed after read")
        return data
    except OSError as exc:
        raise ControlAuthError("cannot open Monitor authority cache leaf") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _monitor_current_helper_sha256() -> str:
    """Digest the running helper through one no-follow, rebound held descriptor."""
    import hashlib

    path = Path(os.path.abspath(__file__))
    descriptor = -1
    try:
        descriptor = os.open(os.fspath(path), _file_flags())
        before = os.fstat(descriptor)
        named = os.stat(path, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino)
            or before.st_size <= 0
            or before.st_size > 256 * 1024
        ):
            raise ControlAuthError("running Monitor helper authority is invalid")
        data, after = _read_monitor_descriptor(
            descriptor, maximum=256 * 1024, label="helper source",
        )
        rebound = os.stat(path, follow_symlinks=False)
        if (
            _monitor_stable_file_metadata(after)
            != _monitor_stable_file_metadata(rebound)
        ):
            raise ControlAuthError("running Monitor helper binding changed")
        return hashlib.sha256(data).hexdigest()
    except ControlAuthError:
        raise
    except OSError as exc:
        raise ControlAuthError("cannot bind running Monitor helper") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def monitor_web_identity() -> tuple[int, int]:
    """Return the exact Ubuntu www-data identity; never guess a group id."""
    try:
        account = pwd.getpwnam("www-data")
        group = grp.getgrnam("www-data")
    except KeyError as exc:
        raise ControlAuthError("Ubuntu www-data account/group is missing") from exc
    if (
        account.pw_uid != MONITOR_AUTHORITY_WWW_UID
        or account.pw_gid != MONITOR_AUTHORITY_WWW_GID
        or group.gr_gid != MONITOR_AUTHORITY_WWW_GID
    ):
        raise ControlAuthError(
            "Ubuntu www-data uid/gid must both be exactly 33"
        )
    return account.pw_uid, group.gr_gid


def _open_monitor_authority_chain(
    authority_root: Path | str,
    *,
    authority_boundary: Path | str,
    required_root_uid: int,
    required_root_gid: int,
    create_root: bool,
) -> tuple[Path, list[int], list[tuple[int, ...]]]:
    root, boundary, components = _monitor_path_parts(
        authority_root, authority_boundary,
    )
    descriptors: list[int] = []
    identities: list[tuple[int, ...]] = []
    try:
        try:
            current = os.open(os.fspath(boundary), _directory_flags())
        except OSError as exc:
            raise ControlAuthError("cannot open Monitor authority boundary") from exc
        descriptors.append(current)
        metadata = os.fstat(current)
        _validate_monitor_ancestor(
            metadata, required_root_uid=required_root_uid,
        )
        identities.append(_monitor_directory_identity(metadata))

        for index, component in enumerate(components):
            final = index == len(components) - 1
            created = False
            try:
                opened = os.open(component, _directory_flags(), dir_fd=current)
            except FileNotFoundError as exc:
                if not (create_root and final):
                    raise ControlAuthError("Monitor authority root is missing") from exc
                try:
                    os.mkdir(component, 0o700, dir_fd=current)
                    created = True
                    opened = os.open(component, _directory_flags(), dir_fd=current)
                    os.fchown(opened, required_root_uid, required_root_gid)
                    os.fchmod(opened, MONITOR_AUTHORITY_ROOT_MODE)
                    os.fsync(opened)
                    os.fsync(current)
                except OSError as create_exc:
                    raise ControlAuthError(
                        "cannot create Monitor authority root"
                    ) from create_exc
            except OSError as exc:
                raise ControlAuthError(
                    "cannot open Monitor authority path component"
                ) from exc
            descriptors.append(opened)
            metadata = os.fstat(opened)
            if final:
                _validate_monitor_root(
                    metadata,
                    required_root_uid=required_root_uid,
                    required_root_gid=required_root_gid,
                )
            else:
                _validate_monitor_ancestor(
                    metadata, required_root_uid=required_root_uid,
                )
            identities.append(_monitor_directory_identity(metadata))
            current = opened
        return root, descriptors, identities
    except BaseException:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise


def _recheck_monitor_authority_chain(
    root: Path, descriptors: Sequence[int], identities: Sequence[tuple[int, ...]],
    *, authority_boundary: Path | str,
) -> None:
    _unused, _boundary, components = _monitor_path_parts(root, authority_boundary)
    if len(descriptors) != len(identities) or len(descriptors) != len(components) + 1:
        raise ControlAuthError("Monitor authority descriptor chain is incomplete")
    for descriptor, expected in zip(descriptors, identities):
        if _monitor_directory_identity(os.fstat(descriptor)) != expected:
            raise ControlAuthError("Monitor authority held identity changed")
    for index, component in enumerate(components, start=1):
        named = os.stat(
            component, dir_fd=descriptors[index - 1], follow_symlinks=False,
        )
        if _monitor_directory_identity(named) != identities[index]:
            raise ControlAuthError("Monitor authority canonical binding changed")


def _open_monitor_lock(root_descriptor: int) -> int:
    flags = _file_flags(writable=True)
    try:
        return os.open(MONITOR_AUTHORITY_LOCK_NAME, flags, dir_fd=root_descriptor)
    except OSError as exc:
        raise ControlAuthError("cannot open Monitor authority lock") from exc


def _open_monitor_cache(root_descriptor: int) -> int:
    try:
        return os.open(
            MONITOR_AUTHORITY_CACHE_NAME, _directory_flags(), dir_fd=root_descriptor,
        )
    except OSError as exc:
        raise ControlAuthError("cannot open Monitor cache directory") from exc


def _validate_monitor_children(
    root_descriptor: int, lock_descriptor: int, cache_descriptor: int,
    *, required_root_uid: int, required_web_uid: int, required_web_gid: int,
    expected_helper_sha256: str | None,
    ignored_recovery_candidate: str | None = None,
) -> None:
    lock_metadata = os.fstat(lock_descriptor)
    lock_named = os.stat(
        MONITOR_AUTHORITY_LOCK_NAME,
        dir_fd=root_descriptor,
        follow_symlinks=False,
    )
    _validate_monitor_lock(
        lock_metadata,
        required_root_uid=required_root_uid,
        required_web_gid=required_web_gid,
    )
    _validate_monitor_lock(
        lock_named,
        required_root_uid=required_root_uid,
        required_web_gid=required_web_gid,
    )
    if _identity(lock_metadata) != _identity(lock_named):
        raise ControlAuthError("Monitor authority lock binding changed")
    lock_data, lock_after = _read_monitor_descriptor(
        lock_descriptor,
        maximum=MONITOR_AUTHORITY_BREAKER_MAX_BYTES,
        label="breaker",
    )
    lock_rebound = _monitor_bound_metadata(
        root_descriptor, MONITOR_AUTHORITY_LOCK_NAME, lock_descriptor,
    )
    if _monitor_stable_file_metadata(lock_after) != _monitor_stable_file_metadata(
        lock_rebound
    ):
        raise ControlAuthError("Monitor authority lock changed after read")
    parse_monitor_authority_breaker(lock_data)

    cache_metadata = os.fstat(cache_descriptor)
    cache_named = os.stat(
        MONITOR_AUTHORITY_CACHE_NAME,
        dir_fd=root_descriptor,
        follow_symlinks=False,
    )
    _validate_monitor_cache_directory(
        cache_metadata,
        required_web_uid=required_web_uid,
        required_web_gid=required_web_gid,
    )
    _validate_monitor_cache_directory(
        cache_named,
        required_web_uid=required_web_uid,
        required_web_gid=required_web_gid,
    )
    if _identity(cache_metadata) != _identity(cache_named):
        raise ControlAuthError("Monitor cache directory binding changed")

    if set(os.listdir(root_descriptor)) != {
        MONITOR_AUTHORITY_LOCK_NAME, MONITOR_AUTHORITY_CACHE_NAME,
    }:
        raise ControlAuthError("Monitor authority root contains an unknown entry")
    recovery_phases: list[str] = []
    unknown_candidate = False
    for name in os.listdir(cache_descriptor):
        if name != MONITOR_AUTHORITY_FINAL_NAME and _MONITOR_CANDIDATE.fullmatch(name) is None:
            raise ControlAuthError("Monitor cache directory contains an unknown entry")
        leaf = os.stat(name, dir_fd=cache_descriptor, follow_symlinks=False)
        _validate_monitor_private_leaf(
            leaf,
            required_web_uid=required_web_uid,
            required_web_gid=required_web_gid,
        )
        if name == MONITOR_AUTHORITY_FINAL_NAME:
            if expected_helper_sha256 is None:
                raise ControlAuthError(
                    "Monitor helper digest is required for cached authority"
                )
            data = _read_monitor_named_private_leaf(
                cache_descriptor, name,
                required_web_uid=required_web_uid,
                required_web_gid=required_web_gid,
            )
            parse_monitor_authority_cache(
                data, expected_helper_sha256=expected_helper_sha256,
            )
        elif name != ignored_recovery_candidate:
            data = _read_monitor_named_private_leaf(
                cache_descriptor, name,
                required_web_uid=required_web_uid,
                required_web_gid=required_web_gid,
            )
            try:
                marker = parse_monitor_authority_recovery_marker(data)
            except ControlAuthError:
                unknown_candidate = True
            else:
                recovery_phases.append(str(marker["phase"]))
    if unknown_candidate or len(recovery_phases) > 1:
        raise ControlAuthError(
            "Monitor cache directory contains incomplete recovery state"
        )
    if recovery_phases:
        raise MonitorAuthorityMarkerError(recovery_phases[0])


def _monitor_authority_operation(
    authority_root: Path | str,
    *,
    authority_boundary: Path | str,
    required_root_uid: int,
    required_root_gid: int,
    required_web_uid: int,
    required_web_gid: int,
    expected_helper_sha256: str | None,
    provision: bool,
) -> None:
    if min(
        required_root_uid, required_root_gid, required_web_uid, required_web_gid,
    ) < 0:
        raise ControlAuthError("Monitor authority ids must be non-negative")
    if provision and os.geteuid() != required_root_uid:
        raise ControlAuthError("Monitor authority provisioning requires root identity")
    root, descriptors, identities = _open_monitor_authority_chain(
        authority_root,
        authority_boundary=authority_boundary,
        required_root_uid=required_root_uid,
        required_root_gid=required_root_gid,
        create_root=provision,
    )
    root_descriptor = descriptors[-1]
    lock_descriptor = cache_descriptor = -1
    locked = False
    try:
        if provision:
            lock_created = False
            try:
                lock_descriptor = os.open(
                    MONITOR_AUTHORITY_LOCK_NAME,
                    _file_flags(writable=True) | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=root_descriptor,
                )
                lock_created = True
            except FileExistsError:
                lock_descriptor = _open_monitor_lock(root_descriptor)
            except OSError as exc:
                raise ControlAuthError("cannot create Monitor authority lock") from exc
            initial_lock = os.fstat(lock_descriptor)
            if not stat.S_ISREG(initial_lock.st_mode) or initial_lock.st_nlink != 1:
                raise ControlAuthError("unsafe Monitor authority lock cannot be repaired")
            if lock_created:
                try:
                    os.fchown(lock_descriptor, required_root_uid, required_web_gid)
                    os.fchmod(lock_descriptor, MONITOR_AUTHORITY_LOCK_MODE)
                    os.fsync(lock_descriptor)
                except OSError as exc:
                    raise ControlAuthError("cannot secure Monitor authority lock") from exc
            else:
                _validate_monitor_lock(
                    initial_lock,
                    required_root_uid=required_root_uid,
                    required_web_gid=required_web_gid,
                )

            try:
                os.mkdir(
                    MONITOR_AUTHORITY_CACHE_NAME, 0o700, dir_fd=root_descriptor,
                )
                cache_created = True
            except FileExistsError:
                cache_created = False
            except OSError as exc:
                raise ControlAuthError("cannot create Monitor cache directory") from exc
            cache_descriptor = _open_monitor_cache(root_descriptor)
            initial_cache = os.fstat(cache_descriptor)
            if not stat.S_ISDIR(initial_cache.st_mode):
                raise ControlAuthError(
                    "unsafe Monitor cache directory cannot be repaired"
                )
            if cache_created:
                try:
                    os.fchown(cache_descriptor, required_web_uid, required_web_gid)
                    os.fchmod(cache_descriptor, MONITOR_AUTHORITY_CACHE_MODE)
                    os.fsync(cache_descriptor)
                    os.fsync(root_descriptor)
                except OSError as exc:
                    raise ControlAuthError("cannot secure Monitor cache directory") from exc
            else:
                _validate_monitor_cache_directory(
                    initial_cache,
                    required_web_uid=required_web_uid,
                    required_web_gid=required_web_gid,
                )
        else:
            lock_descriptor = _open_monitor_lock(root_descriptor)
            cache_descriptor = _open_monitor_cache(root_descriptor)

        try:
            fcntl.flock(
                lock_descriptor, fcntl.LOCK_EX if provision else fcntl.LOCK_SH,
            )
            locked = True
        except OSError as exc:
            raise ControlAuthError("cannot lock Monitor authority") from exc
        _validate_monitor_children(
            root_descriptor, lock_descriptor, cache_descriptor,
            required_root_uid=required_root_uid,
            required_web_uid=required_web_uid,
            required_web_gid=required_web_gid,
            expected_helper_sha256=expected_helper_sha256,
        )
        _recheck_monitor_authority_chain(
            root, descriptors, identities,
            authority_boundary=authority_boundary,
        )
    except (OSError, ValueError) as exc:
        raise ControlAuthError("Monitor authority attestation failed") from exc
    finally:
        if locked:
            try:
                fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
        if cache_descriptor >= 0:
            os.close(cache_descriptor)
        if lock_descriptor >= 0:
            os.close(lock_descriptor)
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _validate_monitor_structure(
    root_descriptor: int, lock_descriptor: int, cache_descriptor: int,
    *, required_root_uid: int, required_web_uid: int, required_web_gid: int,
) -> list[str]:
    lock_metadata = _monitor_bound_metadata(
        root_descriptor, MONITOR_AUTHORITY_LOCK_NAME, lock_descriptor,
    )
    _validate_monitor_lock(
        lock_metadata,
        required_root_uid=required_root_uid,
        required_web_gid=required_web_gid,
    )
    cache_metadata = os.fstat(cache_descriptor)
    cache_named = os.stat(
        MONITOR_AUTHORITY_CACHE_NAME,
        dir_fd=root_descriptor,
        follow_symlinks=False,
    )
    _validate_monitor_cache_directory(
        cache_metadata,
        required_web_uid=required_web_uid,
        required_web_gid=required_web_gid,
    )
    _validate_monitor_cache_directory(
        cache_named,
        required_web_uid=required_web_uid,
        required_web_gid=required_web_gid,
    )
    if _identity(cache_metadata) != _identity(cache_named):
        raise ControlAuthError("Monitor cache directory binding changed")
    if set(os.listdir(root_descriptor)) != {
        MONITOR_AUTHORITY_LOCK_NAME, MONITOR_AUTHORITY_CACHE_NAME,
    }:
        raise ControlAuthError("Monitor authority root contains an unknown entry")
    entries = sorted(os.listdir(cache_descriptor))
    for name in entries:
        if name != MONITOR_AUTHORITY_FINAL_NAME and _MONITOR_CANDIDATE.fullmatch(name) is None:
            raise ControlAuthError("Monitor cache directory contains an unknown entry")
        metadata = os.stat(name, dir_fd=cache_descriptor, follow_symlinks=False)
        _validate_monitor_private_leaf(
            metadata,
            required_web_uid=required_web_uid,
            required_web_gid=required_web_gid,
        )
    return entries


def _monitor_recovery_plan(
    root_descriptor: int, lock_descriptor: int, cache_descriptor: int,
    entries: Sequence[str], *, required_root_uid: int, required_web_uid: int,
    required_web_gid: int, expected_helper_sha256: str,
    protected_marker_name: str | None = None,
) -> tuple[bool, list[str]]:
    lock_data, lock_after = _read_monitor_descriptor(
        lock_descriptor,
        maximum=MONITOR_AUTHORITY_BREAKER_MAX_BYTES,
        label="breaker",
    )
    rebound = _monitor_bound_metadata(
        root_descriptor, MONITOR_AUTHORITY_LOCK_NAME, lock_descriptor,
    )
    if _monitor_stable_file_metadata(lock_after) != _monitor_stable_file_metadata(
        rebound
    ):
        raise ControlAuthError("Monitor authority breaker changed after read")
    try:
        parse_monitor_authority_breaker(lock_data)
        reset_breaker = False
    except ControlAuthError:
        reset_breaker = True

    removals: list[str] = []
    for name in entries:
        if name == protected_marker_name:
            continue
        if name != MONITOR_AUTHORITY_FINAL_NAME:
            removals.append(name)
            continue
        try:
            data = _read_monitor_named_private_leaf(
                cache_descriptor, name,
                required_web_uid=required_web_uid,
                required_web_gid=required_web_gid,
            )
            parse_monitor_authority_cache(
                data, expected_helper_sha256=expected_helper_sha256,
            )
        except ControlAuthError:
            removals.append(name)
    return reset_breaker, removals


def _monitor_recovery_checkpoint(_name: str) -> None:
    """A no-op fault boundary used to prove recovery remains fail closed."""


def _create_monitor_recovery_marker(
    cache_descriptor: int, *, required_web_uid: int, required_web_gid: int,
    phase: str = "recovery-in-progress",
) -> tuple[str, int]:
    checkpoint = (
        "in-progress" if phase == "recovery-in-progress" else "committed"
    )
    name = ".factory-status." + secrets.token_hex(16) + ".tmp"
    descriptor = -1
    try:
        descriptor = os.open(
            name, _file_flags(writable=True) | os.O_CREAT | os.O_EXCL,
            0o600, dir_fd=cache_descriptor,
        )
        os.fchown(descriptor, required_web_uid, required_web_gid)
        os.fchmod(descriptor, MONITOR_AUTHORITY_PRIVATE_MODE)
        marker = build_monitor_authority_recovery_marker(phase)
        offset = 0
        while offset < len(marker):
            written = os.write(descriptor, marker[offset:])
            if written <= 0:
                raise OSError("short Monitor recovery marker write")
            offset += written
        _monitor_recovery_checkpoint(f"marker-{checkpoint}-write")
        os.fsync(descriptor)
        _monitor_recovery_checkpoint(f"marker-{checkpoint}-fsync")
        metadata = _monitor_bound_metadata(cache_descriptor, name, descriptor)
        _validate_monitor_private_leaf(
            metadata,
            required_web_uid=required_web_uid,
            required_web_gid=required_web_gid,
        )
        data, after = _read_monitor_descriptor(
            descriptor,
            maximum=MONITOR_AUTHORITY_CACHE_MAX_BYTES,
            label="recovery marker",
        )
        rebound = _monitor_bound_metadata(cache_descriptor, name, descriptor)
        if _monitor_stable_file_metadata(after) != _monitor_stable_file_metadata(
            rebound
        ):
            raise ControlAuthError("Monitor recovery marker changed after write")
        parsed = parse_monitor_authority_recovery_marker(data)
        if parsed["phase"] != phase:
            raise ControlAuthError("Monitor recovery marker phase changed")
        _monitor_recovery_checkpoint(f"marker-{checkpoint}-rebind")
        os.fsync(cache_descriptor)
        _monitor_recovery_checkpoint(
            f"marker-{checkpoint}-directory-fsync"
        )
        return name, descriptor
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def _unlink_bound_monitor_leaf(
    cache_descriptor: int, name: str, *, required_web_uid: int,
    required_web_gid: int,
) -> None:
    descriptor = -1
    try:
        descriptor = os.open(name, _file_flags(), dir_fd=cache_descriptor)
        metadata = _monitor_bound_metadata(cache_descriptor, name, descriptor)
        _validate_monitor_private_leaf(
            metadata,
            required_web_uid=required_web_uid,
            required_web_gid=required_web_gid,
        )
        os.unlink(name, dir_fd=cache_descriptor)
        if os.fstat(descriptor).st_nlink != 0:
            raise ControlAuthError("Monitor recovery leaf unlink was not bound")
        os.fsync(cache_descriptor)
    except ControlAuthError:
        raise
    except OSError as exc:
        raise ControlAuthError("cannot remove invalid Monitor cache leaf") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _monitor_recovery_marker_inventory(
    cache_descriptor: int, entries: Sequence[str], *, required_web_uid: int,
    required_web_gid: int,
) -> tuple[list[tuple[str, str]], list[str]]:
    markers: list[tuple[str, str]] = []
    other_candidates: list[str] = []
    for name in entries:
        if name == MONITOR_AUTHORITY_FINAL_NAME:
            continue
        data = _read_monitor_named_private_leaf(
            cache_descriptor, name,
            required_web_uid=required_web_uid,
            required_web_gid=required_web_gid,
        )
        try:
            payload = parse_monitor_authority_recovery_marker(data)
        except ControlAuthError:
            other_candidates.append(name)
        else:
            markers.append((name, str(payload["phase"])))
    return markers, other_candidates


def _open_monitor_recovery_marker(
    cache_descriptor: int, name: str, phase: str, *, required_web_uid: int,
    required_web_gid: int,
) -> int:
    descriptor = -1
    try:
        descriptor = os.open(
            name, _file_flags(writable=True), dir_fd=cache_descriptor,
        )
        metadata = _monitor_bound_metadata(cache_descriptor, name, descriptor)
        _validate_monitor_private_leaf(
            metadata,
            required_web_uid=required_web_uid,
            required_web_gid=required_web_gid,
        )
        data, after = _read_monitor_descriptor(
            descriptor,
            maximum=MONITOR_AUTHORITY_CACHE_MAX_BYTES,
            label="recovery marker",
        )
        rebound = _monitor_bound_metadata(cache_descriptor, name, descriptor)
        if _monitor_stable_file_metadata(after) != _monitor_stable_file_metadata(
            rebound
        ):
            raise ControlAuthError("Monitor recovery marker identity changed")
        payload = parse_monitor_authority_recovery_marker(data)
        if payload["phase"] != phase:
            raise ControlAuthError("Monitor recovery marker phase changed")
        return descriptor
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def _write_monitor_recovery_marker_phase(
    cache_descriptor: int, name: str, descriptor: int, phase: str,
    *, required_web_uid: int, required_web_gid: int,
) -> None:
    data = build_monitor_authority_recovery_marker(phase)
    checkpoint = (
        "in-progress" if phase == "recovery-in-progress" else "committed"
    )
    try:
        before = _monitor_bound_metadata(cache_descriptor, name, descriptor)
        _validate_monitor_private_leaf(
            before,
            required_web_uid=required_web_uid,
            required_web_gid=required_web_gid,
        )
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.ftruncate(descriptor, 0)
        _monitor_recovery_checkpoint(f"marker-{checkpoint}-truncate")
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise OSError("short Monitor recovery phase write")
            offset += written
        _monitor_recovery_checkpoint(f"marker-{checkpoint}-write")
        os.fsync(descriptor)
        _monitor_recovery_checkpoint(f"marker-{checkpoint}-fsync")
        persisted, after = _read_monitor_descriptor(
            descriptor,
            maximum=MONITOR_AUTHORITY_CACHE_MAX_BYTES,
            label="recovery marker",
        )
        rebound = _monitor_bound_metadata(cache_descriptor, name, descriptor)
    except ControlAuthError:
        raise
    except OSError as exc:
        raise ControlAuthError("cannot publish Monitor recovery phase") from exc
    if (
        _identity(before) != _identity(after)
        or _monitor_stable_file_metadata(after) != _monitor_stable_file_metadata(
            rebound
        )
        or persisted != data
        or parse_monitor_authority_recovery_marker(persisted)["phase"] != phase
    ):
        raise ControlAuthError("Monitor recovery phase publication changed")
    _monitor_recovery_checkpoint(f"marker-{checkpoint}-rebind")
    try:
        os.fsync(cache_descriptor)
    except OSError as exc:
        raise ControlAuthError(
            "cannot persist Monitor recovery phase namespace"
        ) from exc
    _monitor_recovery_checkpoint(f"marker-{checkpoint}-directory-fsync")


def _monitor_marker_unlink(cache_descriptor: int, name: str) -> None:
    os.unlink(name, dir_fd=cache_descriptor)


def _monitor_marker_parent_fsync(cache_descriptor: int) -> None:
    os.fsync(cache_descriptor)


def _monitor_recovery_result(
    cleanup: str, *, restart_allowed: bool,
) -> dict[str, object]:
    if cleanup not in {
        "complete", "marker-retained", "marker-removal-durability-unknown",
        "marker-authority-uncertain",
    } or type(restart_allowed) is not bool:
        raise ControlAuthError("invalid Monitor recovery result")
    return {
        "cleanup": cleanup,
        "recovery_committed": True,
        "restart_allowed": restart_allowed,
    }


def monitor_authority_recovery_decision(
    payload: object, diagnostics: str,
) -> str:
    """Map one exact structured result plus exact diagnostics to a fixed token."""
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
        raise ControlAuthError("invalid Monitor recovery decision payload")
    cleanup = str(payload["cleanup"])
    restart_allowed = payload["restart_allowed"]
    if (cleanup in {
        "complete", "marker-removal-durability-unknown",
    }) is not restart_allowed:
        raise ControlAuthError("invalid Monitor recovery restart decision")
    recovery_warning = MONITOR_AUTHORITY_RECOVERY_WARNING + "\n"
    cleanup_warning = MONITOR_AUTHORITY_CLEANUP_DURABILITY_WARNING + "\n"
    if type(diagnostics) is not str:
        raise ControlAuthError("invalid Monitor recovery diagnostics")
    reset_invalid_cache = diagnostics.startswith(recovery_warning)
    expected_diagnostics = recovery_warning if reset_invalid_cache else ""
    if cleanup == "marker-removal-durability-unknown":
        expected_diagnostics += cleanup_warning
    if diagnostics != expected_diagnostics:
        raise ControlAuthError("invalid Monitor recovery diagnostics")
    if restart_allowed:
        token = f"restart-allowed:{cleanup}"
    else:
        token = f"restart-blocked:{cleanup}"
    token += ";reset-invalid-cache=" + (
        "true" if reset_invalid_cache else "false"
    )
    if token not in MONITOR_AUTHORITY_DECISION_TOKENS:
        raise ControlAuthError("invalid Monitor recovery decision token")
    return token


def _cleanup_monitor_recovery_marker(
    cache_descriptor: int, marker_name: str, marker_descriptor: int,
    *, required_web_uid: int, required_web_gid: int,
) -> dict[str, object]:
    """Classify cleanup by held identity; never compensate after unlink."""
    try:
        before = _monitor_bound_metadata(
            cache_descriptor, marker_name, marker_descriptor,
        )
        _validate_monitor_private_leaf(
            before,
            required_web_uid=required_web_uid,
            required_web_gid=required_web_gid,
        )
        marker_data, stable = _read_monitor_descriptor(
            marker_descriptor,
            maximum=MONITOR_AUTHORITY_CACHE_MAX_BYTES,
            label="recovery marker",
        )
        if parse_monitor_authority_recovery_marker(marker_data)["phase"] != (
            "recovery-committed-cleanup-pending"
        ):
            return _monitor_recovery_result(
                "marker-authority-uncertain", restart_allowed=False,
            )
        rebound = _monitor_bound_metadata(
            cache_descriptor, marker_name, marker_descriptor,
        )
        if _monitor_stable_file_metadata(stable) != _monitor_stable_file_metadata(
            rebound
        ):
            return _monitor_recovery_result(
                "marker-authority-uncertain", restart_allowed=False,
            )
    except (OSError, ControlAuthError):
        return _monitor_recovery_result(
            "marker-authority-uncertain", restart_allowed=False,
        )

    try:
        _monitor_marker_unlink(cache_descriptor, marker_name)
    except OSError:
        pass

    try:
        held = os.fstat(marker_descriptor)
    except OSError:
        return _monitor_recovery_result(
            "marker-authority-uncertain", restart_allowed=False,
        )
    try:
        named = os.stat(
            marker_name, dir_fd=cache_descriptor, follow_symlinks=False,
        )
    except FileNotFoundError:
        named = None
    except OSError:
        return _monitor_recovery_result(
            "marker-authority-uncertain", restart_allowed=False,
        )
    if (
        held.st_nlink == 1
        and named is not None
        and _identity(held) == _identity(named) == _identity(before)
    ):
        return _monitor_recovery_result(
            "marker-retained", restart_allowed=False,
        )
    if held.st_nlink != 0 or named is not None:
        return _monitor_recovery_result(
            "marker-authority-uncertain", restart_allowed=False,
        )
    try:
        _monitor_marker_parent_fsync(cache_descriptor)
    except OSError:
        print(MONITOR_AUTHORITY_CLEANUP_DURABILITY_WARNING, file=sys.stderr)
        return _monitor_recovery_result(
            "marker-removal-durability-unknown", restart_allowed=True,
        )
    return _monitor_recovery_result("complete", restart_allowed=True)


def recover_monitor_authority(
    authority_root: Path | str = MONITOR_AUTHORITY_ROOT,
    *,
    authority_boundary: Path | str = Path("/"),
    required_root_uid: int = 0,
    required_root_gid: int = 0,
    required_web_uid: int | None = None,
    required_web_gid: int | None = None,
    expected_helper_sha256: str | None = None,
) -> dict[str, object]:
    """Explicit privileged repair; callers must stop every CGI writer first."""
    if os.geteuid() != required_root_uid:
        raise ControlAuthError("Monitor authority recovery requires root identity")
    if expected_helper_sha256 is None:
        expected_helper_sha256 = _monitor_current_helper_sha256()
    else:
        expected_helper_sha256 = _validated_monitor_helper_digest(
            expected_helper_sha256
        )
    if required_web_uid is None or required_web_gid is None:
        web_uid, web_gid = monitor_web_identity()
        required_web_uid = web_uid if required_web_uid is None else required_web_uid
        required_web_gid = web_gid if required_web_gid is None else required_web_gid
    root, descriptors, identities = _open_monitor_authority_chain(
        authority_root,
        authority_boundary=authority_boundary,
        required_root_uid=required_root_uid,
        required_root_gid=required_root_gid,
        create_root=False,
    )
    root_descriptor = descriptors[-1]
    lock_descriptor = cache_descriptor = marker_descriptor = -1
    marker_name: str | None = None
    locked = False
    try:
        lock_descriptor = _open_monitor_lock(root_descriptor)
        cache_descriptor = _open_monitor_cache(root_descriptor)
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        locked = True
        entries = _validate_monitor_structure(
            root_descriptor, lock_descriptor, cache_descriptor,
            required_root_uid=required_root_uid,
            required_web_uid=required_web_uid,
            required_web_gid=required_web_gid,
        )
        markers, other_candidates = _monitor_recovery_marker_inventory(
            cache_descriptor, entries,
            required_web_uid=required_web_uid,
            required_web_gid=required_web_gid,
        )
        if len(markers) > 1:
            raise ControlAuthError("Monitor recovery marker phase is ambiguous")
        if markers:
            marker_name, marker_phase = markers[0]
            marker_descriptor = _open_monitor_recovery_marker(
                cache_descriptor, marker_name, marker_phase,
                required_web_uid=required_web_uid,
                required_web_gid=required_web_gid,
            )
            if marker_phase == "recovery-committed-cleanup-pending":
                if other_candidates:
                    return _monitor_recovery_result(
                        "marker-authority-uncertain", restart_allowed=False,
                    )
                _validate_monitor_children(
                    root_descriptor, lock_descriptor, cache_descriptor,
                    required_root_uid=required_root_uid,
                    required_web_uid=required_web_uid,
                    required_web_gid=required_web_gid,
                    expected_helper_sha256=expected_helper_sha256,
                    ignored_recovery_candidate=marker_name,
                )
                _recheck_monitor_authority_chain(
                    root, descriptors, identities,
                    authority_boundary=authority_boundary,
                )
                os.fsync(marker_descriptor)
                os.fsync(cache_descriptor)
                return _cleanup_monitor_recovery_marker(
                    cache_descriptor, marker_name, marker_descriptor,
                    required_web_uid=required_web_uid,
                    required_web_gid=required_web_gid,
                )
        else:
            marker_phase = None
        reset_breaker, removals = _monitor_recovery_plan(
            root_descriptor, lock_descriptor, cache_descriptor, entries,
            required_root_uid=required_root_uid,
            required_web_uid=required_web_uid,
            required_web_gid=required_web_gid,
            expected_helper_sha256=expected_helper_sha256,
            protected_marker_name=marker_name,
        )
        if marker_phase is None and not reset_breaker and not removals:
            _validate_monitor_children(
                root_descriptor, lock_descriptor, cache_descriptor,
                required_root_uid=required_root_uid,
                required_web_uid=required_web_uid,
                required_web_gid=required_web_gid,
                expected_helper_sha256=expected_helper_sha256,
            )
            _recheck_monitor_authority_chain(
                root, descriptors, identities,
                authority_boundary=authority_boundary,
            )
            return _monitor_recovery_result("complete", restart_allowed=True)

        print(MONITOR_AUTHORITY_RECOVERY_WARNING, file=sys.stderr)
        if marker_phase is None:
            marker_name, marker_descriptor = _create_monitor_recovery_marker(
                cache_descriptor,
                required_web_uid=required_web_uid,
                required_web_gid=required_web_gid,
            )
        _monitor_recovery_checkpoint("directory-fsync-before")
        for name in removals:
            _unlink_bound_monitor_leaf(
                cache_descriptor, name,
                required_web_uid=required_web_uid,
                required_web_gid=required_web_gid,
            )
            _monitor_recovery_checkpoint("leaf-remove")
        if reset_breaker:
            os.ftruncate(lock_descriptor, 0)
            _monitor_recovery_checkpoint("breaker-truncate")
            os.fsync(lock_descriptor)
            _monitor_recovery_checkpoint("breaker-fsync")
        os.fsync(cache_descriptor)
        _monitor_recovery_checkpoint("directory-fsync-after")
        _validate_monitor_children(
            root_descriptor, lock_descriptor, cache_descriptor,
            required_root_uid=required_root_uid,
            required_web_uid=required_web_uid,
            required_web_gid=required_web_gid,
            expected_helper_sha256=expected_helper_sha256,
            ignored_recovery_candidate=marker_name,
        )
        os.fsync(cache_descriptor)
        _monitor_recovery_checkpoint("final-directory-fsync")
        _recheck_monitor_authority_chain(
            root, descriptors, identities,
            authority_boundary=authority_boundary,
        )
        _monitor_recovery_checkpoint("final-rebind")
        _validate_monitor_children(
            root_descriptor, lock_descriptor, cache_descriptor,
            required_root_uid=required_root_uid,
            required_web_uid=required_web_uid,
            required_web_gid=required_web_gid,
            expected_helper_sha256=expected_helper_sha256,
            ignored_recovery_candidate=marker_name,
        )
        _monitor_recovery_checkpoint("final-attest")
        _write_monitor_recovery_marker_phase(
            cache_descriptor, marker_name, marker_descriptor,
            "recovery-committed-cleanup-pending",
            required_web_uid=required_web_uid,
            required_web_gid=required_web_gid,
        )
        _validate_monitor_children(
            root_descriptor, lock_descriptor, cache_descriptor,
            required_root_uid=required_root_uid,
            required_web_uid=required_web_uid,
            required_web_gid=required_web_gid,
            expected_helper_sha256=expected_helper_sha256,
            ignored_recovery_candidate=marker_name,
        )
        _recheck_monitor_authority_chain(
            root, descriptors, identities,
            authority_boundary=authority_boundary,
        )
        _monitor_recovery_checkpoint("marker-committed-attest")
        return _cleanup_monitor_recovery_marker(
            cache_descriptor, marker_name, marker_descriptor,
            required_web_uid=required_web_uid,
            required_web_gid=required_web_gid,
        )
    except BaseException as exc:
        if isinstance(exc, ControlAuthError):
            raise
        raise ControlAuthError("Monitor authority recovery was interrupted") from exc
    finally:
        if marker_descriptor >= 0:
            os.close(marker_descriptor)
        if locked:
            try:
                fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
        if cache_descriptor >= 0:
            os.close(cache_descriptor)
        if lock_descriptor >= 0:
            os.close(lock_descriptor)
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def provision_monitor_authority(
    authority_root: Path | str = MONITOR_AUTHORITY_ROOT,
    *,
    authority_boundary: Path | str = Path("/"),
    required_root_uid: int = 0,
    required_root_gid: int = 0,
    required_web_uid: int | None = None,
    required_web_gid: int | None = None,
    expected_helper_sha256: str | None = None,
) -> None:
    """Privileged lifecycle provisioning; preserve an existing lock payload."""
    if expected_helper_sha256 is None:
        expected_helper_sha256 = _monitor_current_helper_sha256()
    else:
        expected_helper_sha256 = _validated_monitor_helper_digest(
            expected_helper_sha256
        )
    if required_web_uid is None or required_web_gid is None:
        web_uid, web_gid = monitor_web_identity()
        required_web_uid = web_uid if required_web_uid is None else required_web_uid
        required_web_gid = web_gid if required_web_gid is None else required_web_gid
    _monitor_authority_operation(
        authority_root,
        authority_boundary=authority_boundary,
        required_root_uid=required_root_uid,
        required_root_gid=required_root_gid,
        required_web_uid=required_web_uid,
        required_web_gid=required_web_gid,
        expected_helper_sha256=expected_helper_sha256,
        provision=True,
    )


def attest_monitor_authority(
    authority_root: Path | str = MONITOR_AUTHORITY_ROOT,
    *,
    authority_boundary: Path | str = Path("/"),
    required_root_uid: int = 0,
    required_root_gid: int = 0,
    required_web_uid: int | None = None,
    required_web_gid: int | None = None,
    expected_helper_sha256: str | None = None,
) -> None:
    """Read-only fail-closed attestation used before every Apache path."""
    if expected_helper_sha256 is None:
        expected_helper_sha256 = _monitor_current_helper_sha256()
    else:
        expected_helper_sha256 = _validated_monitor_helper_digest(
            expected_helper_sha256
        )
    if required_web_uid is None or required_web_gid is None:
        web_uid, web_gid = monitor_web_identity()
        required_web_uid = web_uid if required_web_uid is None else required_web_uid
        required_web_gid = web_gid if required_web_gid is None else required_web_gid
    _monitor_authority_operation(
        authority_root,
        authority_boundary=authority_boundary,
        required_root_uid=required_root_uid,
        required_root_gid=required_root_gid,
        required_web_uid=required_web_uid,
        required_web_gid=required_web_gid,
        expected_helper_sha256=expected_helper_sha256,
        provision=False,
    )


def _validate_call_contract(
    auth_path: Path | str, required_uid: int, required_gid: int
) -> Path:
    path = Path(auth_path)
    if not path.is_absolute():
        raise ControlAuthError("credential path must be absolute")
    if path.name != AUTH_FILE.name or path.parent == path:
        raise ControlAuthError("credential path must name control-users.htpasswd")
    if required_uid < 0 or required_gid < 0:
        raise ControlAuthError("required owner and group ids must be non-negative")
    return path


def _mode(metadata: os.stat_result) -> int:
    return stat.S_IMODE(metadata.st_mode)


def _identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _directory_metadata(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )


def _file_authority(metadata: os.stat_result) -> tuple[int, ...]:
    """Fields that must survive a same-directory rename unchanged.

    Link count and ctime deliberately are not included: creating the recovery
    link and renaming a candidate legitimately changes them.  Identity,
    contents, type, permissions, ownership, size and mtime remain bound.
    """
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        getattr(metadata, "st_mtime_ns", int(metadata.st_mtime * 1_000_000_000)),
    )


def _stable_metadata(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        *_file_authority(metadata),
        metadata.st_nlink,
        getattr(metadata, "st_ctime_ns", int(metadata.st_ctime * 1_000_000_000)),
    )


def _validate_directory_metadata(
    metadata: os.stat_result, *, required_uid: int, required_gid: int
) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        raise ControlAuthError("credential parent must be a directory")
    if metadata.st_uid != required_uid:
        raise ControlAuthError(
            f"credential directory owner uid must be {required_uid}"
        )
    if metadata.st_gid != required_gid:
        raise ControlAuthError(
            f"credential directory group gid must be {required_gid}"
        )
    if _mode(metadata) != AUTH_DIRECTORY_MODE:
        raise ControlAuthError("credential directory mode must be 0750")


def _validate_regular_metadata(
    metadata: os.stat_result,
    *,
    required_uid: int,
    required_gid: int,
    link_count: int = 1,
) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise ControlAuthError("credential target must be a regular file")
    if metadata.st_nlink != link_count:
        raise ControlAuthError(
            f"credential file link count must be exactly {link_count}"
        )
    if metadata.st_uid != required_uid:
        raise ControlAuthError(f"credential file owner uid must be {required_uid}")
    if metadata.st_gid != required_gid:
        raise ControlAuthError(f"credential file group gid must be {required_gid}")
    if _mode(metadata) != AUTH_FILE_MODE:
        raise ControlAuthError("credential file mode must be 0640")
    if metadata.st_size == 0:
        raise ControlAuthError("credential file is empty")
    if metadata.st_size > MAX_AUTH_FILE_SIZE:
        raise ControlAuthError("credential file is too large")


def _open_parent_for_fsync(path: Path) -> int:
    try:
        return os.open(str(path), _directory_flags())
    except OSError as exc:
        raise ControlAuthError("cannot open parent of credential directory") from exc


def _open_auth_directory(
    auth_path: Path,
    *,
    required_uid: int,
    required_gid: int,
    create: bool,
) -> int:
    directory = auth_path.parent
    created = False
    try:
        descriptor = os.open(str(directory), _directory_flags())
    except FileNotFoundError as exc:
        if not create:
            raise ControlAuthError("credential directory is missing") from exc
        parent_descriptor = _open_parent_for_fsync(directory.parent)
        try:
            try:
                os.mkdir(
                    directory.name,
                    DIRECTORY_CREATE_MODE,
                    dir_fd=parent_descriptor,
                )
                created = True
            except FileExistsError:
                pass
            try:
                descriptor = os.open(
                    directory.name,
                    _directory_flags(),
                    dir_fd=parent_descriptor,
                )
            except OSError as open_exc:
                raise ControlAuthError(
                    "cannot open newly created credential directory"
                ) from open_exc
            if created:
                try:
                    current = os.fstat(descriptor)
                    if current.st_uid != required_uid or current.st_gid != required_gid:
                        os.fchown(descriptor, required_uid, required_gid)
                    os.fchmod(descriptor, AUTH_DIRECTORY_MODE)
                    os.fsync(descriptor)
                    os.fsync(parent_descriptor)
                except OSError as metadata_exc:
                    os.close(descriptor)
                    raise ControlAuthError(
                        "cannot secure newly created credential directory"
                    ) from metadata_exc
        finally:
            os.close(parent_descriptor)
    except OSError as exc:
        raise ControlAuthError("cannot open credential directory") from exc

    try:
        _validate_directory_metadata(
            os.fstat(descriptor),
            required_uid=required_uid,
            required_gid=required_gid,
        )
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def _bind_directory(
    auth_path: Path,
    directory_descriptor: int,
    *,
    required_uid: int,
    required_gid: int,
) -> DirectoryBinding:
    metadata = os.fstat(directory_descriptor)
    _validate_directory_metadata(
        metadata, required_uid=required_uid, required_gid=required_gid
    )
    binding = DirectoryBinding(_directory_metadata(metadata))
    _assert_directory_binding(
        auth_path,
        directory_descriptor,
        binding,
        required_uid=required_uid,
        required_gid=required_gid,
    )
    return binding


def _assert_directory_binding(
    auth_path: Path,
    directory_descriptor: int,
    binding: DirectoryBinding,
    *,
    required_uid: int,
    required_gid: int,
) -> None:
    try:
        held = os.fstat(directory_descriptor)
        _validate_directory_metadata(
            held, required_uid=required_uid, required_gid=required_gid
        )
        reopened_descriptor = os.open(str(auth_path.parent), _directory_flags())
        try:
            reopened = os.fstat(reopened_descriptor)
            _validate_directory_metadata(
                reopened, required_uid=required_uid, required_gid=required_gid
            )
        finally:
            os.close(reopened_descriptor)
    except (OSError, ControlAuthError) as exc:
        raise ControlAuthError("credential directory binding changed") from exc
    if (
        _directory_metadata(held) != binding.metadata
        or _directory_metadata(reopened) != binding.metadata
    ):
        raise ControlAuthError("credential directory binding changed")


@contextmanager
def _directory_lock(
    directory_descriptor: int, *, exclusive: bool
) -> Iterator[None]:
    operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
    try:
        fcntl.flock(directory_descriptor, operation)
    except OSError as exc:
        raise ControlAuthError("cannot lock credential directory") from exc
    try:
        yield
    finally:
        try:
            fcntl.flock(directory_descriptor, fcntl.LOCK_UN)
        except OSError:
            # Closing the held descriptor also releases the lock.  Never mask
            # a more precise publication exception with an unlock diagnostic.
            pass


def _read_once(descriptor: int) -> bytes:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
    except OSError as exc:
        raise ControlAuthError("credential target is not seekable") from exc
    chunks: list[bytes] = []
    total = 0
    while True:
        try:
            chunk = os.read(
                descriptor,
                min(65536, MAX_AUTH_FILE_SIZE + 1 - total),
            )
        except InterruptedError:
            continue
        except OSError as exc:
            raise ControlAuthError("cannot read credential file") from exc
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > MAX_AUTH_FILE_SIZE:
            raise ControlAuthError("credential file is too large")
    return b"".join(chunks)


def _parse_records(data: bytes) -> dict[str, str]:
    if not data:
        raise ControlAuthError("credential file is empty")
    if len(data) > MAX_AUTH_FILE_SIZE:
        raise ControlAuthError("credential file is too large")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ControlAuthError("credential file must contain ASCII only") from exc
    if not text.endswith("\n") or text.endswith("\n\n"):
        raise ControlAuthError("credential file must have one final newline")

    records: dict[str, str] = {}
    for line in text[:-1].split("\n"):
        username, separator, password_hash = line.partition(":")
        if not separator:
            raise ControlAuthError("credential record must contain one separator")
        if username in records:
            raise ControlAuthError(f"duplicate credential user: {username}")
        records[username] = password_hash

    if set(records) != set(USERS) or len(records) != len(USERS):
        raise ControlAuthError("credential users must be exactly nvis and cumulus")
    for username in USERS:
        password_hash = records[username]
        match = _BCRYPT_RECORD.fullmatch(password_hash)
        if match is None:
            if password_hash.startswith("$2y$"):
                raise ControlAuthError(
                    f"credential bcrypt record for {username} is malformed"
                )
            raise ControlAuthError(
                f"credential record for {username} must use bcrypt $2y$"
            )
        if match.group(1) != "12":
            raise ControlAuthError(
                f"credential bcrypt record for {username} must use cost 12"
            )
    return records


def _open_and_read(
    directory_descriptor: int,
    filename: str,
    *,
    required_uid: int,
    required_gid: int,
) -> AuthSnapshot:
    try:
        descriptor = os.open(
            filename,
            _file_flags(),
            dir_fd=directory_descriptor,
        )
    except FileNotFoundError as exc:
        raise _MissingAuthFile("credential file is missing") from exc
    except OSError as exc:
        raise ControlAuthError("cannot safely open credential file") from exc

    try:
        before = os.fstat(descriptor)
        _validate_regular_metadata(
            before, required_uid=required_uid, required_gid=required_gid
        )
        first = _read_once(descriptor)
        middle = os.fstat(descriptor)
        second = _read_once(descriptor)
        after = os.fstat(descriptor)
        if not (
            _stable_metadata(before)
            == _stable_metadata(middle)
            == _stable_metadata(after)
        ) or first != second:
            raise ControlAuthError("credential file changed while being read")
        if len(first) != after.st_size:
            raise ControlAuthError("credential file changed while being read")
        _validate_regular_metadata(
            after, required_uid=required_uid, required_gid=required_gid
        )
        records = _parse_records(first)
        try:
            named = os.stat(
                filename,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise ControlAuthError("credential file changed while being read") from exc
        if _stable_metadata(named) != _stable_metadata(after):
            raise ControlAuthError("credential file changed while being read")
        return AuthSnapshot(data=first, metadata=after, records=records)
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    written = 0
    while written < len(view):
        try:
            count = os.write(descriptor, view[written:])
        except InterruptedError:
            continue
        except OSError as exc:
            raise ControlAuthError("cannot write credential candidate") from exc
        if count <= 0:
            raise ControlAuthError("short write to credential candidate")
        written += count


def _private_name(prefix: str) -> str:
    return f"{prefix}{os.getpid()}.{secrets.token_hex(16)}"


def _temporary_name() -> str:
    """Compatibility name for tests and callers that inspect private entries."""
    return _private_name(_CANDIDATE_PREFIX)


def _named_metadata(directory_descriptor: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ControlAuthError("cannot inspect credential entry") from exc


def _unlink_if_identity(
    directory_descriptor: int, name: str, identity: tuple[int, int]
) -> bool:
    metadata = _named_metadata(directory_descriptor, name)
    if metadata is None:
        return True
    if _identity(metadata) != identity:
        return False
    try:
        os.unlink(name, dir_fd=directory_descriptor)
    except FileNotFoundError:
        return True
    except OSError as exc:
        raise ControlAuthError("cannot remove helper-owned credential entry") from exc
    return True


def _read_bound_descriptor(
    descriptor: int,
    expected: os.stat_result,
    expected_data: bytes,
    *,
    required_uid: int,
    required_gid: int,
    link_count: int,
) -> os.stat_result:
    before = os.fstat(descriptor)
    _validate_regular_metadata(
        before,
        required_uid=required_uid,
        required_gid=required_gid,
        link_count=link_count,
    )
    first = _read_once(descriptor)
    middle = os.fstat(descriptor)
    second = _read_once(descriptor)
    after = os.fstat(descriptor)
    if (
        _file_authority(before) != _file_authority(expected)
        or _file_authority(middle) != _file_authority(expected)
        or _file_authority(after) != _file_authority(expected)
        or first != expected_data
        or second != expected_data
    ):
        raise ControlAuthError("credential candidate identity or bytes changed")
    return after


def _assert_candidate_named(
    directory_descriptor: int,
    candidate: Candidate,
    name: str,
    *,
    required_uid: int,
    required_gid: int,
    link_count: int = 1,
) -> None:
    held = _read_bound_descriptor(
        candidate.descriptor,
        candidate.metadata,
        candidate.data,
        required_uid=required_uid,
        required_gid=required_gid,
        link_count=link_count,
    )
    named = _named_metadata(directory_descriptor, name)
    if named is None:
        raise ControlAuthError("credential candidate name disappeared")
    _validate_regular_metadata(
        named,
        required_uid=required_uid,
        required_gid=required_gid,
        link_count=link_count,
    )
    if _file_authority(named) != _file_authority(held):
        raise ControlAuthError("credential candidate name or inode changed")


def _create_candidate(
    directory_descriptor: int,
    data: bytes,
    *,
    required_uid: int,
    required_gid: int,
) -> Candidate:
    _parse_records(data)
    name = _temporary_name()
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | _require_no_follow()
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = -1
    identity: tuple[int, int] | None = None
    try:
        try:
            descriptor = os.open(
                name,
                flags,
                TEMP_FILE_MODE,
                dir_fd=directory_descriptor,
            )
        except OSError as exc:
            raise ControlAuthError("cannot create credential candidate") from exc
        opened = os.fstat(descriptor)
        identity = _identity(opened)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or _mode(opened) != TEMP_FILE_MODE
        ):
            raise ControlAuthError("credential candidate is unsafe")
        _write_all(descriptor, data)
        try:
            os.fsync(descriptor)
            current = os.fstat(descriptor)
            if current.st_uid != required_uid or current.st_gid != required_gid:
                os.fchown(descriptor, required_uid, required_gid)
            os.fchmod(descriptor, AUTH_FILE_MODE)
            os.fsync(descriptor)
        except OSError as exc:
            raise ControlAuthError("cannot secure credential candidate") from exc
        metadata = os.fstat(descriptor)
        _validate_regular_metadata(
            metadata, required_uid=required_uid, required_gid=required_gid
        )
        candidate = Candidate(descriptor, name, data, metadata)
        _assert_candidate_named(
            directory_descriptor,
            candidate,
            name,
            required_uid=required_uid,
            required_gid=required_gid,
        )
        return candidate
    except Exception as original_exc:
        cleanup_exc: Exception | None = None
        if identity is not None:
            try:
                if not _unlink_if_identity(directory_descriptor, name, identity):
                    raise ControlAuthError(
                        "credential candidate name changed during cleanup"
                    )
                os.fsync(directory_descriptor)
            except (OSError, ControlAuthError) as exc:
                cleanup_exc = exc
        if descriptor >= 0:
            os.close(descriptor)
        if cleanup_exc is not None:
            raise ControlAuthIndeterminateError(
                "credential candidate cleanup durability is uncertain",
                committed=False,
                durable=None,
                valid=None,
            ) from cleanup_exc
        if isinstance(original_exc, OSError):
            raise ControlAuthError("cannot prepare credential candidate") from original_exc
        raise


def _close_candidate(candidate: Candidate) -> None:
    try:
        os.close(candidate.descriptor)
    except OSError:
        pass


def _same_snapshot(before: AuthSnapshot, current: AuthSnapshot) -> bool:
    return (
        before.data == current.data
        and _stable_metadata(before.metadata) == _stable_metadata(current.metadata)
    )


def _assert_snapshot_named(
    directory_descriptor: int,
    target_name: str,
    snapshot: AuthSnapshot,
    *,
    required_uid: int,
    required_gid: int,
    link_count: int,
) -> None:
    metadata = _named_metadata(directory_descriptor, target_name)
    if metadata is None:
        raise ControlAuthError("credential target disappeared")
    _validate_regular_metadata(
        metadata,
        required_uid=required_uid,
        required_gid=required_gid,
        link_count=link_count,
    )
    if _file_authority(metadata) != _file_authority(snapshot.metadata):
        raise ControlAuthError("credential target identity changed")
    try:
        descriptor = os.open(
            target_name, _file_flags(), dir_fd=directory_descriptor
        )
    except OSError as exc:
        raise ControlAuthError("cannot re-open credential target") from exc
    try:
        _read_bound_descriptor(
            descriptor,
            snapshot.metadata,
            snapshot.data,
            required_uid=required_uid,
            required_gid=required_gid,
            link_count=link_count,
        )
    finally:
        os.close(descriptor)


def _recovery_entries(directory_descriptor: int) -> list[str]:
    try:
        names = os.listdir(directory_descriptor)
    except OSError as exc:
        raise ControlAuthError("cannot inspect credential recovery state") from exc
    return sorted(name for name in names if name.startswith(_RECOVERY_PREFIX))


def _probe_valid_target(
    directory_descriptor: int,
    target_name: str,
    *,
    required_uid: int,
    required_gid: int,
) -> bool | None:
    try:
        _open_and_read(
            directory_descriptor,
            target_name,
            required_uid=required_uid,
            required_gid=required_gid,
        )
        return True
    except _MissingAuthFile:
        return False
    except ControlAuthError:
        return None


def _sync_after_precommit_cleanup(directory_descriptor: int) -> None:
    try:
        os.fsync(directory_descriptor)
    except OSError as exc:
        raise ControlAuthIndeterminateError(
            "credential cleanup durability is unknown",
            committed=False,
            durable=None,
            valid=None,
        ) from exc


def _publish_initial(
    auth_path: Path,
    directory_descriptor: int,
    binding: DirectoryBinding,
    candidate: Candidate,
    *,
    required_uid: int,
    required_gid: int,
) -> None:
    target_name = auth_path.name
    published = False
    try:
        _assert_directory_binding(
            auth_path,
            directory_descriptor,
            binding,
            required_uid=required_uid,
            required_gid=required_gid,
        )
        _assert_candidate_named(
            directory_descriptor,
            candidate,
            candidate.name,
            required_uid=required_uid,
            required_gid=required_gid,
        )
        try:
            os.link(
                candidate.name,
                target_name,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            published = True
        except FileExistsError as exc:
            raise ControlAuthError(
                "credential file appeared during initialization"
            ) from exc
        except OSError as exc:
            raise ControlAuthError("cannot publish credential file atomically") from exc

        try:
            _assert_candidate_named(
                directory_descriptor,
                candidate,
                candidate.name,
                required_uid=required_uid,
                required_gid=required_gid,
                link_count=2,
            )
            _assert_candidate_named(
                directory_descriptor,
                candidate,
                target_name,
                required_uid=required_uid,
                required_gid=required_gid,
                link_count=2,
            )
            _assert_directory_binding(
                auth_path,
                directory_descriptor,
                binding,
                required_uid=required_uid,
                required_gid=required_gid,
            )
            os.fsync(directory_descriptor)
        except Exception as exc:
            target = _named_metadata(directory_descriptor, target_name)
            if target is not None and _identity(target) == _identity(candidate.metadata):
                try:
                    os.unlink(target_name, dir_fd=directory_descriptor)
                    if not _unlink_if_identity(
                        directory_descriptor,
                        candidate.name,
                        _identity(candidate.metadata),
                    ):
                        raise ControlAuthError(
                            "credential candidate changed during rollback"
                        )
                    os.fsync(directory_descriptor)
                    published = False
                except (OSError, ControlAuthError) as rollback_exc:
                    raise ControlAuthIndeterminateError(
                        "initial credential publication rollback is uncertain",
                        committed=None,
                        durable=None,
                        valid=_probe_valid_target(
                            directory_descriptor,
                            target_name,
                            required_uid=required_uid,
                            required_gid=required_gid,
                        ),
                    ) from rollback_exc
                raise ControlAuthError(
                    "initial credential publication was rolled back"
                ) from exc
            try:
                if not _unlink_if_identity(
                    directory_descriptor,
                    candidate.name,
                    _identity(candidate.metadata),
                ):
                    raise ControlAuthError(
                        "credential candidate changed during conflict cleanup"
                    )
                os.fsync(directory_descriptor)
                published = False
            except (OSError, ControlAuthError) as cleanup_exc:
                raise ControlAuthIndeterminateError(
                    "initial credential conflict cleanup is uncertain",
                    committed=None,
                    durable=None,
                    valid=_probe_valid_target(
                        directory_descriptor,
                        target_name,
                        required_uid=required_uid,
                        required_gid=required_gid,
                    ),
                ) from cleanup_exc
            raise ControlAuthIndeterminateError(
                "initial credential publication identity became uncertain",
                committed=None,
                durable=None,
                valid=_probe_valid_target(
                    directory_descriptor,
                    target_name,
                    required_uid=required_uid,
                    required_gid=required_gid,
                ),
            ) from exc

        if not _unlink_if_identity(
            directory_descriptor, candidate.name, _identity(candidate.metadata)
        ):
            raise ControlAuthCommittedError(
                "credential was committed but candidate cleanup conflicted",
                durable=True,
                valid=True,
                recovery_name=None,
            )
        try:
            os.fsync(directory_descriptor)
        except OSError as exc:
            raise ControlAuthCommittedError(
                "credential was committed but cleanup durability is unknown",
                durable=True,
                valid=True,
                recovery_name=None,
            ) from exc
        try:
            _assert_candidate_named(
                directory_descriptor,
                candidate,
                target_name,
                required_uid=required_uid,
                required_gid=required_gid,
            )
            _assert_directory_binding(
                auth_path,
                directory_descriptor,
                binding,
                required_uid=required_uid,
                required_gid=required_gid,
            )
        except ControlAuthError as exc:
            raise ControlAuthCommittedError(
                "credential committed but final identity verification failed",
                durable=True,
                valid=_probe_valid_target(
                    directory_descriptor,
                    target_name,
                    required_uid=required_uid,
                    required_gid=required_gid,
                ),
            ) from exc
    finally:
        if not published:
            try:
                if not _unlink_if_identity(
                    directory_descriptor,
                    candidate.name,
                    _identity(candidate.metadata),
                ):
                    raise ControlAuthError(
                        "helper candidate name was replaced during cleanup"
                    )
                os.fsync(directory_descriptor)
            except (OSError, ControlAuthError) as cleanup_exc:
                raise ControlAuthIndeterminateError(
                    "helper candidate cleanup durability is uncertain",
                    committed=False,
                    durable=None,
                    valid=None,
                ) from cleanup_exc


def _read_new_password(
    user: str,
    password_reader: Callable[[str], str],
) -> bytes:
    first = password_reader(f"New Monitor control password for {user}: ")
    second = password_reader("Confirm new Monitor control password: ")
    if not isinstance(first, str) or not isinstance(second, str):
        raise ControlAuthError("password input must be text")
    try:
        first_bytes = first.encode("ascii")
        second_bytes = second.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ControlAuthError("password must contain printable ASCII only") from exc
    if not hmac.compare_digest(first_bytes, second_bytes):
        raise ControlAuthError("password confirmation does not match")
    if not 12 <= len(first_bytes) <= 72:
        raise ControlAuthError("password length must be between 12 and 72 bytes")
    if any(value < 0x20 or value > 0x7E for value in first_bytes):
        raise ControlAuthError("password must contain printable ASCII only")
    return first_bytes


def _generated_record(
    user: str,
    password: bytes,
    *,
    runner: Callable[..., object],
    htpasswd_program: str,
) -> str:
    argv = (htpasswd_program, "-niB", "-C", "12", user)
    try:
        completed = runner(
            argv,
            input=password + b"\n",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(_SAFE_SUBPROCESS_ENV),
            check=False,
            timeout=30,
        )
    except Exception:
        # The subprocess exception may include attacker-controlled text.  Do
        # not retain it as a cause where diagnostics could reveal the secret.
        raise ControlAuthError("htpasswd execution failed") from None
    if getattr(completed, "returncode", None) != 0:
        raise ControlAuthError("htpasswd rejected the password update")
    output = getattr(completed, "stdout", None)
    if not isinstance(output, bytes):
        raise ControlAuthError("htpasswd returned an invalid record")
    if len(output) > MAX_HTPASSWD_OUTPUT:
        raise ControlAuthError("htpasswd record output is too large")
    # Apache's Darwin build writes one additional blank line after reading the
    # password from stdin; Linux builds normally emit only the record newline.
    # Accept those two exact transport shapes, never another record/whitespace.
    record_output = output[:-1] if output.endswith(b"\n\n") else output
    if not record_output.endswith(b"\n") or record_output.count(b"\n") != 1:
        raise ControlAuthError("htpasswd must return one final-newline record")
    try:
        line = record_output[:-1].decode("ascii")
    except UnicodeDecodeError as exc:
        raise ControlAuthError("htpasswd record must contain ASCII only") from exc
    generated_user, separator, password_hash = line.partition(":")
    if not separator or generated_user != user:
        raise ControlAuthError("htpasswd output must name the selected user")
    match = _BCRYPT_RECORD.fullmatch(password_hash)
    if match is None or match.group(1) != "12":
        raise ControlAuthError("htpasswd output must be one bcrypt cost-12 record")
    return password_hash


def _merge_record(snapshot: AuthSnapshot, user: str, password_hash: str) -> bytes:
    if snapshot.records[user] == password_hash:
        raise ControlAuthError("htpasswd did not change the selected user")
    output: list[bytes] = []
    for line in snapshot.data[:-1].split(b"\n"):
        username = line.split(b":", 1)[0].decode("ascii")
        if username == user:
            output.append(f"{user}:{password_hash}".encode("ascii"))
        else:
            output.append(line)
    merged = b"\n".join(output) + b"\n"
    _parse_records(merged)
    return merged


def _cleanup_rotation_precommit(
    directory_descriptor: int,
    candidate: Candidate,
    recovery_name: str | None,
    original: AuthSnapshot,
) -> None:
    if recovery_name is not None:
        if not _unlink_if_identity(
            directory_descriptor, recovery_name, _identity(original.metadata)
        ):
            raise ControlAuthIndeterminateError(
                "credential recovery name was replaced before publication",
                committed=False,
                durable=None,
                valid=True,
            )
    if not _unlink_if_identity(
        directory_descriptor, candidate.name, _identity(candidate.metadata)
    ):
        raise ControlAuthIndeterminateError(
            "credential candidate name was replaced before publication",
            committed=False,
            durable=None,
            valid=True,
        )
    _sync_after_precommit_cleanup(directory_descriptor)


def _rollback_rotation(
    auth_path: Path,
    directory_descriptor: int,
    binding: DirectoryBinding,
    candidate: Candidate,
    original: AuthSnapshot,
    recovery_name: str,
    *,
    required_uid: int,
    required_gid: int,
) -> bool:
    try:
        _assert_candidate_named(
            directory_descriptor,
            candidate,
            auth_path.name,
            required_uid=required_uid,
            required_gid=required_gid,
        )
        _assert_snapshot_named(
            directory_descriptor,
            recovery_name,
            original,
            required_uid=required_uid,
            required_gid=required_gid,
            link_count=1,
        )
        _assert_directory_binding(
            auth_path,
            directory_descriptor,
            binding,
            required_uid=required_uid,
            required_gid=required_gid,
        )
        os.replace(
            recovery_name,
            auth_path.name,
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
        )
        os.fsync(directory_descriptor)
        _assert_snapshot_named(
            directory_descriptor,
            auth_path.name,
            original,
            required_uid=required_uid,
            required_gid=required_gid,
            link_count=1,
        )
        _assert_directory_binding(
            auth_path,
            directory_descriptor,
            binding,
            required_uid=required_uid,
            required_gid=required_gid,
        )
        return True
    except (OSError, ControlAuthError):
        return False


def _publish_rotation(
    auth_path: Path,
    directory_descriptor: int,
    binding: DirectoryBinding,
    candidate: Candidate,
    original: AuthSnapshot,
    *,
    required_uid: int,
    required_gid: int,
) -> None:
    target_name = auth_path.name
    recovery_name = _private_name(_RECOVERY_PREFIX)
    recovery_linked = False
    published = False

    try:
        current = _open_and_read(
            directory_descriptor,
            target_name,
            required_uid=required_uid,
            required_gid=required_gid,
        )
        if not _same_snapshot(original, current):
            raise ControlAuthError("credential file changed before publication")
        _assert_candidate_named(
            directory_descriptor,
            candidate,
            candidate.name,
            required_uid=required_uid,
            required_gid=required_gid,
        )
        _assert_directory_binding(
            auth_path,
            directory_descriptor,
            binding,
            required_uid=required_uid,
            required_gid=required_gid,
        )
        try:
            os.link(
                target_name,
                recovery_name,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            recovery_linked = True
        except OSError as exc:
            raise ControlAuthError("cannot create credential recovery link") from exc
        try:
            _assert_snapshot_named(
                directory_descriptor,
                target_name,
                original,
                required_uid=required_uid,
                required_gid=required_gid,
                link_count=2,
            )
            _assert_snapshot_named(
                directory_descriptor,
                recovery_name,
                original,
                required_uid=required_uid,
                required_gid=required_gid,
                link_count=2,
            )
            _assert_candidate_named(
                directory_descriptor,
                candidate,
                candidate.name,
                required_uid=required_uid,
                required_gid=required_gid,
            )
            _assert_directory_binding(
                auth_path,
                directory_descriptor,
                binding,
                required_uid=required_uid,
                required_gid=required_gid,
            )
            os.fsync(directory_descriptor)
        except Exception as exc:
            _cleanup_rotation_precommit(
                directory_descriptor, candidate, recovery_name, original
            )
            recovery_linked = False
            raise ControlAuthError(
                "credential publication preparation failed"
            ) from exc

        # Standard-library fd-relative replace is the selected publication
        # primitive.  The exclusive directory flock excludes all cooperating
        # writers; an omnipotent continuing root writer remains out of scope.
        try:
            os.replace(
                candidate.name,
                target_name,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
            )
            published = True
        except OSError as exc:
            _cleanup_rotation_precommit(
                directory_descriptor, candidate, recovery_name, original
            )
            recovery_linked = False
            raise ControlAuthError("atomic credential replace failed") from exc

        try:
            _assert_candidate_named(
                directory_descriptor,
                candidate,
                target_name,
                required_uid=required_uid,
                required_gid=required_gid,
            )
            _assert_snapshot_named(
                directory_descriptor,
                recovery_name,
                original,
                required_uid=required_uid,
                required_gid=required_gid,
                link_count=1,
            )
            _assert_directory_binding(
                auth_path,
                directory_descriptor,
                binding,
                required_uid=required_uid,
                required_gid=required_gid,
            )
        except ControlAuthError as exc:
            raise ControlAuthIndeterminateError(
                "credential publication identity became uncertain",
                committed=None,
                durable=None,
                valid=_probe_valid_target(
                    directory_descriptor,
                    target_name,
                    required_uid=required_uid,
                    required_gid=required_gid,
                ),
                recovery_name=recovery_name,
            ) from exc

        try:
            os.fsync(directory_descriptor)
        except OSError as exc:
            if _rollback_rotation(
                auth_path,
                directory_descriptor,
                binding,
                candidate,
                original,
                recovery_name,
                required_uid=required_uid,
                required_gid=required_gid,
            ):
                recovery_linked = False
                raise ControlAuthError(
                    "credential update was rolled back after durability failure"
                ) from exc
            raise ControlAuthCommittedError(
                "credential update selected but durability failed",
                durable=False,
                valid=_probe_valid_target(
                    directory_descriptor,
                    target_name,
                    required_uid=required_uid,
                    required_gid=required_gid,
                ),
                recovery_name=recovery_name,
            ) from exc

        try:
            recovery_removed = _unlink_if_identity(
                directory_descriptor,
                recovery_name,
                _identity(original.metadata),
            )
        except ControlAuthError as exc:
            raise ControlAuthCommittedError(
                "credential committed but recovery cleanup failed",
                durable=True,
                valid=True,
                recovery_name=recovery_name,
            ) from exc
        if not recovery_removed:
            raise ControlAuthCommittedError(
                "credential committed but recovery cleanup conflicted",
                durable=True,
                valid=True,
                recovery_name=recovery_name,
            )
        recovery_linked = False
        try:
            os.fsync(directory_descriptor)
        except OSError as exc:
            raise ControlAuthCommittedError(
                "credential committed but recovery cleanup durability failed",
                durable=True,
                valid=True,
                recovery_name=recovery_name,
            ) from exc
        try:
            _assert_candidate_named(
                directory_descriptor,
                candidate,
                target_name,
                required_uid=required_uid,
                required_gid=required_gid,
            )
            _assert_directory_binding(
                auth_path,
                directory_descriptor,
                binding,
                required_uid=required_uid,
                required_gid=required_gid,
            )
        except ControlAuthError as exc:
            raise ControlAuthCommittedError(
                "credential committed but final identity verification failed",
                durable=True,
                valid=_probe_valid_target(
                    directory_descriptor,
                    target_name,
                    required_uid=required_uid,
                    required_gid=required_gid,
                ),
            ) from exc
    finally:
        if not published:
            try:
                if recovery_linked and not _unlink_if_identity(
                    directory_descriptor,
                    recovery_name,
                    _identity(original.metadata),
                ):
                    raise ControlAuthError(
                        "credential recovery name changed during cleanup"
                    )
                if not _unlink_if_identity(
                    directory_descriptor,
                    candidate.name,
                    _identity(candidate.metadata),
                ):
                    raise ControlAuthError(
                        "credential candidate name changed during cleanup"
                    )
                os.fsync(directory_descriptor)
            except (OSError, ControlAuthError) as cleanup_exc:
                raise ControlAuthIndeterminateError(
                    "prepublication credential cleanup durability is uncertain",
                    committed=False,
                    durable=None,
                    valid=None,
                ) from cleanup_exc


def validate_auth_file(
    auth_path: Path | str = AUTH_FILE,
    *,
    required_uid: int = REQUIRED_UID,
    required_gid: int = REQUIRED_GID,
) -> AuthSnapshot:
    """Validate directory, metadata, contents, read stability and binding."""
    path = _validate_call_contract(auth_path, required_uid, required_gid)
    directory_descriptor = _open_auth_directory(
        path,
        required_uid=required_uid,
        required_gid=required_gid,
        create=False,
    )
    try:
        binding = _bind_directory(
            path,
            directory_descriptor,
            required_uid=required_uid,
            required_gid=required_gid,
        )
        with _directory_lock(directory_descriptor, exclusive=False):
            _assert_directory_binding(
                path,
                directory_descriptor,
                binding,
                required_uid=required_uid,
                required_gid=required_gid,
            )
            snapshot = _open_and_read(
                directory_descriptor,
                path.name,
                required_uid=required_uid,
                required_gid=required_gid,
            )
            _assert_directory_binding(
                path,
                directory_descriptor,
                binding,
                required_uid=required_uid,
                required_gid=required_gid,
            )
            return snapshot
    finally:
        os.close(directory_descriptor)


def ensure_auth_file(
    auth_path: Path | str = AUTH_FILE,
    *,
    required_uid: int = REQUIRED_UID,
    required_gid: int = REQUIRED_GID,
) -> bool:
    """Create the factory file only when absent; preserve valid existing bytes."""
    path = _validate_call_contract(auth_path, required_uid, required_gid)
    _parse_records(FACTORY_RECORDS)
    directory_descriptor = _open_auth_directory(
        path,
        required_uid=required_uid,
        required_gid=required_gid,
        create=True,
    )
    try:
        binding = _bind_directory(
            path,
            directory_descriptor,
            required_uid=required_uid,
            required_gid=required_gid,
        )
        with _directory_lock(directory_descriptor, exclusive=True):
            _assert_directory_binding(
                path,
                directory_descriptor,
                binding,
                required_uid=required_uid,
                required_gid=required_gid,
            )
            if _recovery_entries(directory_descriptor):
                raise ControlAuthError(
                    "unresolved credential recovery evidence blocks initialization"
                )
            try:
                _open_and_read(
                    directory_descriptor,
                    path.name,
                    required_uid=required_uid,
                    required_gid=required_gid,
                )
                _assert_directory_binding(
                    path,
                    directory_descriptor,
                    binding,
                    required_uid=required_uid,
                    required_gid=required_gid,
                )
                return False
            except _MissingAuthFile:
                pass
            candidate = _create_candidate(
                directory_descriptor,
                FACTORY_RECORDS,
                required_uid=required_uid,
                required_gid=required_gid,
            )
            try:
                _publish_initial(
                    path,
                    directory_descriptor,
                    binding,
                    candidate,
                    required_uid=required_uid,
                    required_gid=required_gid,
                )
                try:
                    final = _open_and_read(
                        directory_descriptor,
                        path.name,
                        required_uid=required_uid,
                        required_gid=required_gid,
                    )
                    if not hmac.compare_digest(final.data, FACTORY_RECORDS):
                        raise ControlAuthError(
                            "initialized credential bytes changed before success"
                        )
                    _assert_directory_binding(
                        path,
                        directory_descriptor,
                        binding,
                        required_uid=required_uid,
                        required_gid=required_gid,
                    )
                except ControlAuthError as exc:
                    raise ControlAuthCommittedError(
                        "credential committed but final validation failed",
                        durable=True,
                        valid=_probe_valid_target(
                            directory_descriptor,
                            path.name,
                            required_uid=required_uid,
                            required_gid=required_gid,
                        ),
                    ) from exc
                return True
            finally:
                _close_candidate(candidate)
    finally:
        os.close(directory_descriptor)


def status_auth_file(
    auth_path: Path | str = AUTH_FILE,
    *,
    required_uid: int = REQUIRED_UID,
    required_gid: int = REQUIRED_GID,
) -> dict[str, bool]:
    """Return exact machine status; false does not attest password rotation."""
    try:
        snapshot = validate_auth_file(
            auth_path,
            required_uid=required_uid,
            required_gid=required_gid,
        )
    except ControlAuthError:
        return {"valid": False, "factory_records_active": False}
    return {
        "valid": True,
        "factory_records_active": hmac.compare_digest(
            snapshot.data, FACTORY_RECORDS
        ),
    }


def rotate_auth_file(
    auth_path: Path | str = AUTH_FILE,
    *,
    user: str,
    required_uid: int = REQUIRED_UID,
    required_gid: int = REQUIRED_GID,
    password_reader: Callable[[str], str] = getpass.getpass,
    runner: Callable[..., object] = subprocess.run,
    htpasswd_program: str = HTPASSWD_PROGRAM,
) -> dict[str, bool]:
    """Rotate one exact user with the secret transported through stdin only."""
    if user not in USERS:
        raise ControlAuthError("user must be exactly nvis or cumulus")
    if not htpasswd_program.startswith("/"):
        raise ControlAuthError("htpasswd program path must be absolute")
    path = _validate_call_contract(auth_path, required_uid, required_gid)
    directory_descriptor = _open_auth_directory(
        path,
        required_uid=required_uid,
        required_gid=required_gid,
        create=False,
    )
    try:
        binding = _bind_directory(
            path,
            directory_descriptor,
            required_uid=required_uid,
            required_gid=required_gid,
        )
        with _directory_lock(directory_descriptor, exclusive=False):
            _assert_directory_binding(
                path,
                directory_descriptor,
                binding,
                required_uid=required_uid,
                required_gid=required_gid,
            )
            if _recovery_entries(directory_descriptor):
                raise ControlAuthError(
                    "unresolved credential recovery evidence blocks rotation"
                )
            _open_and_read(
                directory_descriptor,
                path.name,
                required_uid=required_uid,
                required_gid=required_gid,
            )
            _assert_directory_binding(
                path,
                directory_descriptor,
                binding,
                required_uid=required_uid,
                required_gid=required_gid,
            )

        # Interactive input and bcrypt generation intentionally occur outside
        # the exclusive lock.  Health readers and another operator's prompts
        # remain unblocked; the current file is re-snapshotted under LOCK_EX.
        password = _read_new_password(user, password_reader)
        _assert_directory_binding(
            path,
            directory_descriptor,
            binding,
            required_uid=required_uid,
            required_gid=required_gid,
        )
        password_hash = _generated_record(
            user,
            password,
            runner=runner,
            htpasswd_program=htpasswd_program,
        )
        _assert_directory_binding(
            path,
            directory_descriptor,
            binding,
            required_uid=required_uid,
            required_gid=required_gid,
        )

        with _directory_lock(directory_descriptor, exclusive=True):
            _assert_directory_binding(
                path,
                directory_descriptor,
                binding,
                required_uid=required_uid,
                required_gid=required_gid,
            )
            if _recovery_entries(directory_descriptor):
                raise ControlAuthError(
                    "unresolved credential recovery evidence blocks rotation"
                )
            current = _open_and_read(
                directory_descriptor,
                path.name,
                required_uid=required_uid,
                required_gid=required_gid,
            )
            _assert_directory_binding(
                path,
                directory_descriptor,
                binding,
                required_uid=required_uid,
                required_gid=required_gid,
            )
            merged = _merge_record(current, user, password_hash)
            candidate = _create_candidate(
                directory_descriptor,
                merged,
                required_uid=required_uid,
                required_gid=required_gid,
            )
            try:
                _publish_rotation(
                    path,
                    directory_descriptor,
                    binding,
                    candidate,
                    current,
                    required_uid=required_uid,
                    required_gid=required_gid,
                )
                try:
                    final = _open_and_read(
                        directory_descriptor,
                        path.name,
                        required_uid=required_uid,
                        required_gid=required_gid,
                    )
                    if not hmac.compare_digest(final.data, merged):
                        raise ControlAuthError(
                            "credential bytes changed before success"
                        )
                    _assert_directory_binding(
                        path,
                        directory_descriptor,
                        binding,
                        required_uid=required_uid,
                        required_gid=required_gid,
                    )
                except ControlAuthError as exc:
                    raise ControlAuthCommittedError(
                        "credential committed but final validation failed",
                        durable=True,
                        valid=_probe_valid_target(
                            directory_descriptor,
                            path.name,
                            required_uid=required_uid,
                            required_gid=required_gid,
                        ),
                    ) from exc
                return {
                    "valid": True,
                    "factory_records_active": hmac.compare_digest(
                        final.data, FACTORY_RECORDS
                    ),
                }
            finally:
                _close_candidate(candidate)
    finally:
        os.close(directory_descriptor)


def _warn_factory() -> None:
    # The two stored bcrypt values are deliberately public bootstrap verifiers
    # for deliberately public defaults.  They are never evidence that the
    # installation is secure; this warning remains until exact bytes differ.
    print(
        "WARNING: factory Monitor control credentials are active; "
        "rotate both users immediately after first login.",
        file=sys.stderr,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Manage the Monitor control credential file safely.",
        epilog=(
            "Rotation requires a human at a terminal on the management server "
            "by design; it cannot be automated or run unattended."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser(
        "monitor-authority-provision",
        help="provision and attest the fixed Monitor cache authority",
    )
    subparsers.add_parser(
        "monitor-authority-attest",
        help="attest the fixed Monitor cache authority without changing it",
    )
    subparsers.add_parser(
        "monitor-authority-recover",
        help="explicitly recover invalid fixed Monitor cache content",
    )
    subparsers.add_parser(
        "monitor-authority-provision-decision",
        help=argparse.SUPPRESS,
    )
    subparsers.add_parser(
        "monitor-authority-attest-decision",
        help=argparse.SUPPRESS,
    )
    subparsers.add_parser(
        "monitor-authority-recover-decision",
        help=argparse.SUPPRESS,
    )
    subparsers.add_parser("ensure", help="initialize only when missing")
    subparsers.add_parser("validate", help="validate the complete state")
    subparsers.add_parser("status", help="print exact machine JSON")
    rotate = subparsers.add_parser("rotate", help="rotate one control user")
    rotate.add_argument("--user", required=True, choices=USERS)
    return parser


def _state_word(value: bool | None) -> str:
    if value is None:
        return "unknown"
    return "true" if value else "false"


def _print_transaction_error(kind: str, exc: ControlAuthError) -> None:
    committed = _state_word(getattr(exc, "committed", None))
    durable = _state_word(getattr(exc, "durable", None))
    valid = _state_word(getattr(exc, "valid", None))
    recovery = getattr(exc, "recovery_name", None)
    recovery_text = f" recovery={recovery}" if recovery else ""
    print(
        f"control-auth: {kind}: committed={committed} durable={durable} "
        f"valid={valid}{recovery_text}; validate/status the canonical file "
        "and do not blindly retry",
        file=sys.stderr,
    )


def main(
    argv: Sequence[str] | None = None,
    *,
    auth_path: Path | str = AUTH_FILE,
    required_uid: int = REQUIRED_UID,
    required_gid: int = REQUIRED_GID,
    password_reader: Callable[[str], str] = getpass.getpass,
    runner: Callable[..., object] = subprocess.run,
) -> int:
    args = _parser().parse_args(argv)
    if args.command == "status":
        status_result = status_auth_file(
            auth_path,
            required_uid=required_uid,
            required_gid=required_gid,
        )
        print(json.dumps(status_result, sort_keys=True, separators=(",", ":")))
        return 0 if status_result["valid"] else 1

    try:
        if args.command in {
            "monitor-authority-provision",
            "monitor-authority-provision-decision",
        }:
            provision_monitor_authority()
            if args.command.endswith("-decision"):
                sys.stdout.write("attest-valid")
                return 0
        elif args.command in {
            "monitor-authority-attest",
            "monitor-authority-attest-decision",
        }:
            attest_monitor_authority()
            if args.command.endswith("-decision"):
                sys.stdout.write("attest-valid")
                return 0
        elif args.command == "monitor-authority-recover":
            recovery = recover_monitor_authority()
            print(json.dumps(recovery, sort_keys=True, separators=(",", ":")))
            return 0 if recovery["restart_allowed"] else 2
        elif args.command == "monitor-authority-recover-decision":
            from io import StringIO

            diagnostics = StringIO()
            with redirect_stderr(diagnostics):
                recovery = recover_monitor_authority()
            sys.stdout.write(monitor_authority_recovery_decision(
                recovery, diagnostics.getvalue(),
            ))
            return 0
        elif args.command == "ensure":
            ensure_auth_file(
                auth_path,
                required_uid=required_uid,
                required_gid=required_gid,
            )
            result = status_auth_file(
                auth_path,
                required_uid=required_uid,
                required_gid=required_gid,
            )
            if result["factory_records_active"]:
                _warn_factory()
        elif args.command == "validate":
            validate_auth_file(
                auth_path,
                required_uid=required_uid,
                required_gid=required_gid,
            )
        elif args.command == "rotate":
            rotate_auth_file(
                auth_path,
                user=args.user,
                required_uid=required_uid,
                required_gid=required_gid,
                password_reader=password_reader,
                runner=runner,
            )
        else:
            raise ControlAuthError("unsupported command")
    except MonitorAuthorityMarkerError as exc:
        if args.command in {
            "monitor-authority-provision-decision",
            "monitor-authority-attest-decision",
        }:
            sys.stdout.write(exc.classification)
            return 0
        print(json.dumps(
            {"classification": exc.classification, "valid": False},
            sort_keys=True, separators=(",", ":"),
        ))
        if exc.classification == "recovery-committed-cleanup-pending":
            print(
                "control-auth: previous Monitor authority recovery COMPLETED; "
                "repaired authority is valid but marker cleanup is pending",
                file=sys.stderr,
            )
        else:
            print(
                "control-auth: Monitor authority recovery is still in progress",
                file=sys.stderr,
            )
        return 4
    except ControlAuthCommittedError as exc:
        _print_transaction_error("committed", exc)
        return 2
    except ControlAuthIndeterminateError as exc:
        _print_transaction_error("indeterminate", exc)
        return 3
    except ControlAuthError as exc:
        print(f"control-auth: error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
