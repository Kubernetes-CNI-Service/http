#!/usr/bin/env python3
"""Restricted CGI endpoint for pausing/resuming the persistent ZTP monitor."""

import errno
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import stat
import subprocess
import sys
import time
import types
from urllib.parse import parse_qs


STATUS_DIR = Path("/var/www/html/ztp/status")
CONTROL_FILE = STATUS_DIR / "ztp-monitor.control"
PID_FILE = STATUS_DIR / "ztp-monitor.pid"
CONTROL_USERS = frozenset(("nvis", "cumulus"))
CONTROL_SCRIPT_NAMES = frozenset((
    "/monitor/control/ztp-monitor",
    "/cgi-bin/ztp-monitor-control",
))
CONTROL_AUTH_HELPER = Path("/usr/local/lib/http-ztp/control-auth.py")
CONTROL_AUTH_PYTHON = Path("/usr/bin/python3")
CONTROL_AUTH_HELPER_SHA256 = (
    "5a133a353cb7ac7af5be0be71b4ef85b41345716103d6e28590140638ee11038"
)
CONTROL_AUTH_HELPER_MAX_BYTES = 256 * 1024
CONTROL_AUTH_OUTPUT_LIMIT = 256
CONTROL_AUTH_TIMEOUT_SECONDS = 3.0
CONTROL_AUTH_SAFE_ENV = {
    "HOME": "/var/empty",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "PYTHONDONTWRITEBYTECODE": "1",
    "TMPDIR": "/tmp",
}
CONTROL_AUTH_CACHE_ROOT = Path("/var/lib/http-ztp-monitor-auth")
CONTROL_AUTH_CACHE_DIRECTORY_NAME = "monitor-auth"
CONTROL_AUTH_CACHE_LOCK_NAME = "status.lock"
CONTROL_AUTH_CACHE_FILE_NAME = "factory-status.json"
CONTROL_AUTH_CACHE_MAX_BYTES = 512
CONTROL_AUTH_CACHE_TTL_NS = 45_000_000_000
CONTROL_AUTH_CACHE_BREAKER_MAX_BYTES = 256
CONTROL_AUTH_RECOVERY_CANDIDATE = re.compile(
    r"^\.factory-status\.[0-9a-f]{32}\.tmp$"
)
CONTROL_AUTH_HELD_LAUNCH_MAX_BYTES = 16384
CONTROL_AUTH_HELD_LAUNCH_V1 = """import builtins,hashlib,os,sys
try:
 fd=int(sys.argv[1]); size=int(sys.argv[2]); digest=sys.argv[3]; display=sys.argv[4]
 if fd < 0 or size <= 0 or size > 262144 or len(digest) != 64: raise ValueError()
 os.lseek(fd,0,os.SEEK_SET); chunks=[]; remaining=size
 while remaining:
  chunk=os.read(fd,min(65536,remaining))
  if not chunk: raise ValueError()
  chunks.append(chunk); remaining-=len(chunk)
 source=b''.join(chunks)
 if os.read(fd,1) or hashlib.sha256(source).hexdigest()!=digest: raise ValueError()
 code=compile(source,display,'exec',dont_inherit=True)
except BaseException:
 os._exit(120)
sys.argv=[display,'status']
scope={'__name__':'__main__','__file__':display,'__package__':None,'__cached__':None,'__builtins__':builtins.__dict__}
try:
 exec(code,scope,scope)
except SystemExit:
 raise
except BaseException:
 os._exit(121)
"""
CONTROL_AUTH_FAILURE_CATEGORIES = frozenset((
    "cache-authority",
    "cache-io",
    "helper-authority",
    "helper-digest",
    "helper-rebind",
    "helper-timeout",
    "output-overflow",
    "helper-protocol",
    "credential-state-invalid",
    "recovery-in-progress",
    "recovery-committed-cleanup-pending",
))
_VALID_FACTORY_ACTIVE = (
    b'{"factory_records_active":true,"valid":true}\n'
)
_VALID_FACTORY_INACTIVE = (
    b'{"factory_records_active":false,"valid":true}\n'
)
_INVALID_CREDENTIAL_STATE = (
    b'{"factory_records_active":false,"valid":false}\n'
)


class ControlAuthStatusError(RuntimeError):
    """One bounded, non-sensitive Monitor authentication status failure."""

    def __init__(self, category):
        if category not in CONTROL_AUTH_FAILURE_CATEGORIES:
            category = "helper-protocol"
        super().__init__(category)
        self.category = category


class _CachePublicationFailure(ControlAuthStatusError):
    """Internal publication failure carrying only a no-follow final identity."""

    def __init__(self, contaminant_identity=None):
        super().__init__("cache-authority")
        self.contaminant_identity = contaminant_identity


def _require_flag(name, category):
    value = getattr(os, name, None)
    if value is None:
        raise ControlAuthStatusError(category)
    return value


def _directory_flags(category):
    return (
        os.O_RDONLY
        | _require_flag("O_DIRECTORY", category)
        | _require_flag("O_NOFOLLOW", category)
        | getattr(os, "O_CLOEXEC", 0)
    )


def _file_flags(category, *, writable=False, create=False, exclusive=False):
    flags = os.O_RDWR if writable else os.O_RDONLY
    flags |= _require_flag("O_NOFOLLOW", category)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    if create:
        flags |= os.O_CREAT
    if exclusive:
        flags |= os.O_EXCL
    return flags


def _identity(metadata):
    return metadata.st_dev, metadata.st_ino


def _stable_file_metadata(metadata):
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        getattr(metadata, "st_mtime_ns", None),
        getattr(metadata, "st_ctime_ns", None),
    )


def _close_descriptors(*descriptors):
    for descriptor in descriptors:
        if descriptor is None or descriptor < 0:
            continue
        try:
            os.close(descriptor)
        except OSError:
            pass


def _stat_bound_name(parent_descriptor, name, descriptor, category):
    try:
        held = os.fstat(descriptor)
        named = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except OSError as exc:
        raise ControlAuthStatusError(category) from exc
    if _identity(held) != _identity(named):
        raise ControlAuthStatusError(category)
    return held


def _validate_cache_ancestor(metadata, required_uid):
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != required_uid
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise ControlAuthStatusError("cache-authority")


def _validate_cache_root(metadata, required_uid, required_gid):
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != required_uid
        or metadata.st_gid != required_gid
        or stat.S_IMODE(metadata.st_mode) != 0o755
    ):
        raise ControlAuthStatusError("cache-authority")


def _validate_cache_directory(metadata, required_uid, required_gid):
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != required_uid
        or metadata.st_gid != required_gid
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ControlAuthStatusError("cache-authority")


def _validate_private_file(metadata, *, required_uid, required_gid, maximum):
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != required_uid
        or metadata.st_gid != required_gid
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size < 0
        or metadata.st_size > maximum
    ):
        raise ControlAuthStatusError("cache-authority")


def _validate_cache_lock(metadata, *, required_uid, required_gid, held=False):
    permitted_links = {0, 1} if held else {1}
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink not in permitted_links
        or metadata.st_uid != required_uid
        or metadata.st_gid != required_gid
        or stat.S_IMODE(metadata.st_mode) != 0o660
        or metadata.st_size < 0
        or metadata.st_size > CONTROL_AUTH_CACHE_BREAKER_MAX_BYTES
    ):
        raise ControlAuthStatusError("cache-authority")


def _cache_path_parts(cache_root, authority_boundary):
    root = Path(cache_root)
    boundary = Path(authority_boundary)
    if not root.is_absolute() or not boundary.is_absolute():
        raise ControlAuthStatusError("cache-authority")
    root_parts = root.parts
    boundary_parts = boundary.parts
    if (
        root == boundary
        or len(root_parts) <= len(boundary_parts)
        or root_parts[:len(boundary_parts)] != boundary_parts
        or any(part in {"", ".", ".."} for part in root_parts[1:])
        or any(part in {"", ".", ".."} for part in boundary_parts[1:])
    ):
        raise ControlAuthStatusError("cache-authority")
    return root, boundary, tuple(root_parts[len(boundary_parts):])


def _open_fixed_cache_root(
    cache_root, authority_boundary, parent_uid, parent_gid,
):
    root, boundary, components = _cache_path_parts(
        cache_root, authority_boundary,
    )
    descriptor = None
    try:
        descriptor = os.open(
            os.fspath(boundary), _directory_flags("cache-authority")
        )
        _validate_cache_ancestor(os.fstat(descriptor), parent_uid)
        for index, component in enumerate(components):
            opened = os.open(
                component,
                _directory_flags("cache-authority"),
                dir_fd=descriptor,
            )
            metadata = _stat_bound_name(
                descriptor, component, opened, "cache-authority",
            )
            if index == len(components) - 1:
                _validate_cache_root(metadata, parent_uid, parent_gid)
            else:
                _validate_cache_ancestor(metadata, parent_uid)
            os.close(descriptor)
            descriptor = opened
        return root, descriptor
    except (OSError, ControlAuthStatusError) as exc:
        _close_descriptors(descriptor)
        if isinstance(exc, ControlAuthStatusError):
            raise
        raise ControlAuthStatusError("cache-authority") from exc


def _open_cache_handles(
    cache_root, parent_uid, cache_euid, cache_egid, *,
    authority_boundary=Path("/"), parent_gid=0,
):
    root_descriptor = directory_descriptor = lock_descriptor = None
    try:
        _root, root_descriptor = _open_fixed_cache_root(
            cache_root, authority_boundary, parent_uid, parent_gid,
        )
        try:
            directory_descriptor = os.open(
                CONTROL_AUTH_CACHE_DIRECTORY_NAME,
                _directory_flags("cache-authority"),
                dir_fd=root_descriptor,
            )
        except OSError as exc:
            raise ControlAuthStatusError("cache-authority") from exc
        directory_metadata = _stat_bound_name(
            root_descriptor,
            CONTROL_AUTH_CACHE_DIRECTORY_NAME,
            directory_descriptor,
            "cache-authority",
        )
        _validate_cache_directory(directory_metadata, cache_euid, cache_egid)

        try:
            lock_descriptor = os.open(
                CONTROL_AUTH_CACHE_LOCK_NAME,
                _file_flags("cache-authority", writable=True),
                dir_fd=root_descriptor,
            )
        except OSError as exc:
            raise ControlAuthStatusError("cache-authority") from exc
        lock_metadata = _stat_bound_name(
            root_descriptor,
            CONTROL_AUTH_CACHE_LOCK_NAME,
            lock_descriptor,
            "cache-authority",
        )
        _validate_cache_lock(
            lock_metadata,
            required_uid=parent_uid,
            required_gid=cache_egid,
        )
        return root_descriptor, directory_descriptor, lock_descriptor
    except Exception:
        _close_descriptors(lock_descriptor, directory_descriptor, root_descriptor)
        raise


def _read_all(descriptor, size, category):
    chunks = []
    total = 0
    try:
        while total < size:
            chunk = os.read(descriptor, min(65536, size - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        overflow = os.read(descriptor, 1)
    except OSError as exc:
        raise ControlAuthStatusError(category) from exc
    data = b"".join(chunks)
    if len(data) != size or overflow:
        raise ControlAuthStatusError(category)
    return data


def _validate_cache_breaker_metadata(metadata, required_uid, required_gid):
    # Named lock authority (including nlink=1) is checked separately through
    # the held directory.  Allow nlink=0 here so an already-held descriptor can
    # still be read after unlink without ever reopening the replacement name.
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink not in {0, 1}
        or metadata.st_uid != required_uid
        or metadata.st_gid != required_gid
        or stat.S_IMODE(metadata.st_mode) != 0o660
        or metadata.st_size < 0
        or metadata.st_size > CONTROL_AUTH_CACHE_BREAKER_MAX_BYTES
    ):
        raise ControlAuthStatusError("cache-authority")


def _read_cache_breaker(
    lock_descriptor, *, required_uid, required_gid, semantic_api,
):
    """Read only the already-held lock inode; never reopen its pathname."""
    try:
        before = os.fstat(lock_descriptor)
        _validate_cache_breaker_metadata(before, required_uid, required_gid)
        os.lseek(lock_descriptor, 0, os.SEEK_SET)
        data = _read_all(lock_descriptor, before.st_size, "cache-io")
        after = os.fstat(lock_descriptor)
    except ControlAuthStatusError:
        raise
    except OSError as exc:
        raise ControlAuthStatusError("cache-io") from exc
    _validate_cache_breaker_metadata(after, required_uid, required_gid)
    if _stable_file_metadata(before) != _stable_file_metadata(after):
        raise ControlAuthStatusError("cache-authority")
    try:
        return semantic_api.parse_monitor_authority_breaker(data)
    except Exception as exc:
        raise ControlAuthStatusError("cache-authority") from exc


def _write_cache_breaker(
    lock_descriptor, state, *, required_uid, required_gid, semantic_api,
):
    try:
        data = semantic_api.build_monitor_authority_breaker(
            contaminant_dev=state["contaminant_dev"],
            contaminant_ino=state["contaminant_ino"],
            failure_count=state["failure_count"],
        )
    except Exception as exc:
        raise ControlAuthStatusError("cache-authority") from exc
    if len(data) > CONTROL_AUTH_CACHE_BREAKER_MAX_BYTES:
        raise ControlAuthStatusError("cache-authority")
    try:
        before = os.fstat(lock_descriptor)
        _validate_cache_breaker_metadata(before, required_uid, required_gid)
        os.lseek(lock_descriptor, 0, os.SEEK_SET)
        os.ftruncate(lock_descriptor, 0)
        _write_all(lock_descriptor, data)
        os.fsync(lock_descriptor)
        after = os.fstat(lock_descriptor)
        os.lseek(lock_descriptor, 0, os.SEEK_SET)
        persisted = _read_all(lock_descriptor, after.st_size, "cache-io")
        final = os.fstat(lock_descriptor)
    except ControlAuthStatusError:
        raise
    except OSError as exc:
        raise ControlAuthStatusError("cache-io") from exc
    _validate_cache_breaker_metadata(after, required_uid, required_gid)
    _validate_cache_breaker_metadata(final, required_uid, required_gid)
    if (
        _identity(before) != _identity(after)
        or after.st_size != len(data)
        or _stable_file_metadata(after) != _stable_file_metadata(final)
        or persisted != data
    ):
        raise ControlAuthStatusError("cache-authority")
    try:
        semantic_api.parse_monitor_authority_breaker(persisted)
    except Exception as exc:
        raise ControlAuthStatusError("cache-authority") from exc


def _clear_cache_breaker(
    lock_descriptor, *, required_uid, required_gid, semantic_api,
):
    try:
        before = os.fstat(lock_descriptor)
        _validate_cache_breaker_metadata(before, required_uid, required_gid)
        os.lseek(lock_descriptor, 0, os.SEEK_SET)
        os.ftruncate(lock_descriptor, 0)
        os.fsync(lock_descriptor)
        after = os.fstat(lock_descriptor)
    except ControlAuthStatusError:
        raise
    except OSError as exc:
        raise ControlAuthStatusError("cache-io") from exc
    _validate_cache_breaker_metadata(after, required_uid, required_gid)
    if _identity(before) != _identity(after) or after.st_size != 0:
        raise ControlAuthStatusError("cache-authority")
    try:
        semantic_api.parse_monitor_authority_breaker(b"")
    except Exception as exc:
        raise ControlAuthStatusError("cache-authority") from exc


def _observed_cache_identity(directory_descriptor):
    try:
        metadata = os.stat(
            CONTROL_AUTH_CACHE_FILE_NAME,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ControlAuthStatusError("cache-authority") from exc
    return _identity(metadata)


def _breaker_identity(state):
    if state is None:
        return None
    return state["contaminant_dev"], state["contaminant_ino"]


def _read_cache_file(
    directory_descriptor,
    *,
    required_uid,
    required_gid,
    expected_helper_sha256,
    clock_ns,
    semantic_api,
):
    descriptor = None
    try:
        try:
            descriptor = os.open(
                CONTROL_AUTH_CACHE_FILE_NAME,
                _file_flags("cache-authority"),
                dir_fd=directory_descriptor,
            )
        except FileNotFoundError:
            return {"value": None, "identity": None}
        except OSError as exc:
            raise ControlAuthStatusError("cache-authority") from exc
        before = _stat_bound_name(
            directory_descriptor,
            CONTROL_AUTH_CACHE_FILE_NAME,
            descriptor,
            "cache-authority",
        )
        _validate_private_file(
            before,
            required_uid=required_uid,
            required_gid=required_gid,
            maximum=CONTROL_AUTH_CACHE_MAX_BYTES,
        )
        if before.st_size == 0:
            raise ControlAuthStatusError("cache-authority")
        data = _read_all(descriptor, before.st_size, "cache-io")
        try:
            after = os.fstat(descriptor)
        except OSError as exc:
            raise ControlAuthStatusError("cache-io") from exc
        _validate_private_file(
            after,
            required_uid=required_uid,
            required_gid=required_gid,
            maximum=CONTROL_AUTH_CACHE_MAX_BYTES,
        )
        identity = _identity(after)
        try:
            named_after = os.stat(
                CONTROL_AUTH_CACHE_FILE_NAME,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return {"value": None, "identity": None}
        except OSError as exc:
            raise ControlAuthStatusError("cache-authority") from exc
        _validate_private_file(
            named_after,
            required_uid=required_uid,
            required_gid=required_gid,
            maximum=CONTROL_AUTH_CACHE_MAX_BYTES,
        )
        if _identity(named_after) != identity:
            return {"value": None, "identity": _identity(named_after)}
        timestamp = getattr(after, "st_mtime_ns", None)
        changed = _stable_file_metadata(before) != _stable_file_metadata(after)
        if timestamp is None or changed:
            return {"value": None, "identity": identity}
        try:
            age_ns = int(clock_ns()) - int(timestamp)
        except (AttributeError, TypeError, ValueError, OverflowError):
            return {"value": None, "identity": identity}
        if age_ns < 0 or age_ns > CONTROL_AUTH_CACHE_TTL_NS:
            return {"value": None, "identity": identity}
        try:
            value = semantic_api.parse_monitor_authority_cache(
                data, expected_helper_sha256=expected_helper_sha256,
            )
        except Exception as exc:
            raise ControlAuthStatusError("cache-authority") from exc
        return {
            "value": value,
            "identity": identity,
        }
    finally:
        _close_descriptors(descriptor)


def _current_cache_identity(
    directory_descriptor, *, required_uid, required_gid,
):
    try:
        metadata = os.stat(
            CONTROL_AUTH_CACHE_FILE_NAME,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ControlAuthStatusError("cache-authority") from exc
    _validate_private_file(
        metadata,
        required_uid=required_uid,
        required_gid=required_gid,
        maximum=CONTROL_AUTH_CACHE_MAX_BYTES,
    )
    return _identity(metadata)


def _write_all(descriptor, data):
    offset = 0
    try:
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise OSError(errno.EIO, "short cache write")
            offset += written
    except OSError as exc:
        raise ControlAuthStatusError("cache-io") from exc


def _remove_bound_cache_contaminant(
    directory_descriptor, *, required_uid, required_gid,
):
    """Remove only a final regular object held and rebound to the same inode."""
    try:
        observed = os.stat(
            CONTROL_AUTH_CACHE_FILE_NAME,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return None
    except OSError:
        return None
    observed_identity = _identity(observed)
    descriptor = None
    try:
        try:
            descriptor = os.open(
                CONTROL_AUTH_CACHE_FILE_NAME,
                _file_flags("cache-authority"),
                dir_fd=directory_descriptor,
            )
        except OSError:
            return observed_identity
        held = _stat_bound_name(
            directory_descriptor,
            CONTROL_AUTH_CACHE_FILE_NAME,
            descriptor,
            "cache-authority",
        )
        _validate_private_file(
            held,
            required_uid=required_uid,
            required_gid=required_gid,
            maximum=CONTROL_AUTH_CACHE_MAX_BYTES,
        )
        if _identity(held) != observed_identity:
            return _observed_cache_identity(directory_descriptor)
        try:
            os.unlink(
                CONTROL_AUTH_CACHE_FILE_NAME,
                dir_fd=directory_descriptor,
            )
            os.fsync(directory_descriptor)
        except OSError:
            return _observed_cache_identity(directory_descriptor)
        return _observed_cache_identity(directory_descriptor)
    except ControlAuthStatusError:
        return observed_identity
    finally:
        _close_descriptors(descriptor)


def _publish_cache_file(
    directory_descriptor,
    *,
    value,
    expected_identity,
    required_uid,
    required_gid,
    expected_helper_sha256,
    authority_check,
    semantic_api,
):
    try:
        data = semantic_api.build_monitor_authority_cache(
            value, expected_helper_sha256=expected_helper_sha256,
        )
    except Exception as exc:
        raise ControlAuthStatusError("cache-authority") from exc
    if len(data) > CONTROL_AUTH_CACHE_MAX_BYTES:
        raise ControlAuthStatusError("cache-io")
    candidate_name = ".factory-status.%s.tmp" % secrets.token_hex(16)
    candidate_descriptor = None
    replaced = False
    verified = False
    candidate_identity = None
    try:
        try:
            candidate_descriptor = os.open(
                candidate_name,
                _file_flags(
                    "cache-authority", writable=True, create=True, exclusive=True
                ),
                0o600,
                dir_fd=directory_descriptor,
            )
        except OSError as exc:
            raise ControlAuthStatusError("cache-io") from exc
        candidate_metadata = _stat_bound_name(
            directory_descriptor,
            candidate_name,
            candidate_descriptor,
            "cache-authority",
        )
        _validate_private_file(
            candidate_metadata,
            required_uid=required_uid,
            required_gid=required_gid,
            maximum=CONTROL_AUTH_CACHE_MAX_BYTES,
        )
        candidate_identity = _identity(candidate_metadata)
        _write_all(candidate_descriptor, data)
        try:
            os.fsync(candidate_descriptor)
            final_candidate = os.fstat(candidate_descriptor)
        except OSError as exc:
            raise ControlAuthStatusError("cache-io") from exc
        _validate_private_file(
            final_candidate,
            required_uid=required_uid,
            required_gid=required_gid,
            maximum=CONTROL_AUTH_CACHE_MAX_BYTES,
        )
        if (
            final_candidate.st_size != len(data)
            or _identity(final_candidate) != candidate_identity
        ):
            raise ControlAuthStatusError("cache-authority")
        _stat_bound_name(
            directory_descriptor,
            candidate_name,
            candidate_descriptor,
            "cache-authority",
        )
        current_identity = _current_cache_identity(
            directory_descriptor,
            required_uid=required_uid,
            required_gid=required_gid,
        )
        if current_identity != expected_identity:
            raise ControlAuthStatusError("cache-authority")
        try:
            os.replace(
                candidate_name,
                CONTROL_AUTH_CACHE_FILE_NAME,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
            )
            replaced = True
            os.fsync(directory_descriptor)
        except OSError as exc:
            raise ControlAuthStatusError("cache-io") from exc

        installed_before = _stat_bound_name(
            directory_descriptor,
            CONTROL_AUTH_CACHE_FILE_NAME,
            candidate_descriptor,
            "cache-authority",
        )
        _validate_private_file(
            installed_before,
            required_uid=required_uid,
            required_gid=required_gid,
            maximum=CONTROL_AUTH_CACHE_MAX_BYTES,
        )
        try:
            os.lseek(candidate_descriptor, 0, os.SEEK_SET)
        except OSError as exc:
            raise ControlAuthStatusError("cache-io") from exc
        installed_data = _read_all(
            candidate_descriptor, installed_before.st_size, "cache-io",
        )
        installed_after = _stat_bound_name(
            directory_descriptor,
            CONTROL_AUTH_CACHE_FILE_NAME,
            candidate_descriptor,
            "cache-authority",
        )
        _validate_private_file(
            installed_after,
            required_uid=required_uid,
            required_gid=required_gid,
            maximum=CONTROL_AUTH_CACHE_MAX_BYTES,
        )
        if (
            installed_data != data
            or _stable_file_metadata(installed_before)
            != _stable_file_metadata(installed_after)
        ):
            raise ControlAuthStatusError("cache-authority")
        try:
            semantic_api.parse_monitor_authority_cache(
                installed_data,
                expected_helper_sha256=expected_helper_sha256,
            )
        except Exception as exc:
            raise ControlAuthStatusError("cache-authority") from exc
        authority_check()
        verified = True
    except _CachePublicationFailure:
        raise
    except ControlAuthStatusError as exc:
        if replaced:
            contaminant = _remove_bound_cache_contaminant(
                directory_descriptor,
                required_uid=required_uid,
                required_gid=required_gid,
            )
            raise _CachePublicationFailure(contaminant) from exc
        try:
            observed_identity = _observed_cache_identity(directory_descriptor)
        except ControlAuthStatusError:
            raise _CachePublicationFailure(None) from exc
        if observed_identity is None and expected_identity is None:
            raise
        contaminant = observed_identity
        if (
            observed_identity is not None
            and observed_identity != expected_identity
        ):
            contaminant = _remove_bound_cache_contaminant(
                directory_descriptor,
                required_uid=required_uid,
                required_gid=required_gid,
            )
        raise _CachePublicationFailure(contaminant) from exc
    finally:
        if not verified and candidate_identity is not None:
            try:
                named = os.stat(
                    candidate_name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
                held = os.fstat(candidate_descriptor)
                if _identity(named) == candidate_identity == _identity(held):
                    os.unlink(candidate_name, dir_fd=directory_descriptor)
                    os.fsync(directory_descriptor)
            except OSError:
                pass
        _close_descriptors(candidate_descriptor)


def _assert_cache_handles(
    cache_root,
    root_descriptor,
    directory_descriptor,
    lock_descriptor,
    *,
    authority_boundary,
    parent_uid,
    parent_gid,
    cache_euid,
    cache_egid,
    semantic_api,
):
    reopened_root = None
    try:
        root_metadata = os.fstat(root_descriptor)
        _root, reopened_root = _open_fixed_cache_root(
            cache_root, authority_boundary, parent_uid, parent_gid,
        )
        root_named = os.fstat(reopened_root)
    except (OSError, ControlAuthStatusError) as exc:
        raise ControlAuthStatusError("cache-authority") from exc
    finally:
        _close_descriptors(reopened_root)
    _validate_cache_root(root_metadata, parent_uid, parent_gid)
    if _identity(root_metadata) != _identity(root_named):
        raise ControlAuthStatusError("cache-authority")
    try:
        directory_metadata = _stat_bound_name(
            root_descriptor,
            CONTROL_AUTH_CACHE_DIRECTORY_NAME,
            directory_descriptor,
            "cache-authority",
        )
        _validate_cache_directory(directory_metadata, cache_euid, cache_egid)
        lock_metadata = _stat_bound_name(
            root_descriptor,
            CONTROL_AUTH_CACHE_LOCK_NAME,
            lock_descriptor,
            "cache-authority",
        )
        _validate_cache_lock(
            lock_metadata,
            required_uid=parent_uid,
            required_gid=cache_egid,
        )
    except OSError as exc:
        raise ControlAuthStatusError("cache-authority") from exc
    phases = []
    unknown = False
    try:
        entries = os.listdir(directory_descriptor)
    except OSError as exc:
        raise ControlAuthStatusError("cache-authority") from exc
    for name in entries:
        if name == CONTROL_AUTH_CACHE_FILE_NAME:
            continue
        if CONTROL_AUTH_RECOVERY_CANDIDATE.fullmatch(name) is None:
            raise ControlAuthStatusError("cache-authority")
        descriptor = None
        try:
            descriptor = os.open(
                name, _file_flags("cache-authority"),
                dir_fd=directory_descriptor,
            )
            before = _stat_bound_name(
                directory_descriptor, name, descriptor, "cache-authority",
            )
            _validate_private_file(
                before,
                required_uid=cache_euid,
                required_gid=cache_egid,
                maximum=CONTROL_AUTH_CACHE_MAX_BYTES,
            )
            data = _read_all(descriptor, before.st_size, "cache-io")
            after = _stat_bound_name(
                directory_descriptor, name, descriptor, "cache-authority",
            )
            _validate_private_file(
                after,
                required_uid=cache_euid,
                required_gid=cache_egid,
                maximum=CONTROL_AUTH_CACHE_MAX_BYTES,
            )
            if _stable_file_metadata(before) != _stable_file_metadata(after):
                raise ControlAuthStatusError("cache-authority")
            try:
                marker = semantic_api.parse_monitor_authority_recovery_marker(data)
            except Exception:
                unknown = True
            else:
                phases.append(marker.get("phase"))
        finally:
            _close_descriptors(descriptor)
    if unknown or len(phases) > 1:
        raise ControlAuthStatusError("cache-authority")
    if phases:
        raise ControlAuthStatusError(phases[0])


def _cached_control_auth_status(
    *,
    cache_root,
    authority_boundary=Path("/"),
    cache_parent_uid,
    cache_parent_gid=0,
    cache_euid,
    cache_egid,
    expected_helper_sha256,
    refresher,
    clock_ns=time.time_ns,
    semantic_api=None,
):
    if (
        not isinstance(expected_helper_sha256, str)
        or len(expected_helper_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_helper_sha256)
    ):
        raise ControlAuthStatusError("cache-authority")
    if semantic_api is None:
        semantic_api = _load_control_auth_semantic_api(
            expected_helper_sha256=expected_helper_sha256,
        )
    breaker_threshold = getattr(
        semantic_api, "MONITOR_AUTHORITY_BREAKER_THRESHOLD", None,
    )
    breaker_schema = getattr(
        semantic_api, "MONITOR_AUTHORITY_BREAKER_SCHEMA", None,
    )
    cache_schema = getattr(
        semantic_api, "MONITOR_AUTHORITY_CACHE_SCHEMA", None,
    )
    if (
        type(breaker_threshold) is not int
        or breaker_threshold < 1
        or type(breaker_schema) is not int
        or breaker_schema < 1
        or type(cache_schema) is not int
        or cache_schema < 1
        or not callable(getattr(
            semantic_api, "parse_monitor_authority_recovery_marker", None,
        ))
        or not callable(getattr(
            semantic_api, "build_monitor_authority_breaker", None,
        ))
        or not callable(getattr(
            semantic_api, "build_monitor_authority_cache", None,
        ))
    ):
        raise ControlAuthStatusError("cache-authority")
    root_descriptor, directory_descriptor, lock_descriptor = _open_cache_handles(
        Path(cache_root), cache_parent_uid, cache_euid, cache_egid,
        authority_boundary=authority_boundary, parent_gid=cache_parent_gid,
    )
    locked = False
    try:
        try:
            fcntl.flock(lock_descriptor, fcntl.LOCK_SH)
            locked = True
        except OSError as exc:
            raise ControlAuthStatusError("cache-io") from exc
        _assert_cache_handles(
            Path(cache_root), root_descriptor, directory_descriptor,
            lock_descriptor, authority_boundary=authority_boundary,
            parent_uid=cache_parent_uid, parent_gid=cache_parent_gid,
            cache_euid=cache_euid, cache_egid=cache_egid,
            semantic_api=semantic_api,
        )
        breaker = _read_cache_breaker(
            lock_descriptor,
            required_uid=cache_parent_uid, required_gid=cache_egid,
            semantic_api=semantic_api,
        )
        observed_identity = (
            _observed_cache_identity(directory_descriptor)
            if breaker is not None else None
        )
        if breaker is not None and observed_identity == _breaker_identity(breaker):
            if breaker["failure_count"] >= breaker_threshold:
                raise ControlAuthStatusError("cache-authority")
        elif breaker is None:
            cached = _read_cache_file(
                directory_descriptor,
                required_uid=cache_euid,
                required_gid=cache_egid,
                expected_helper_sha256=expected_helper_sha256,
                clock_ns=clock_ns,
                semantic_api=semantic_api,
            )
            if cached["value"] is not None:
                _assert_cache_handles(
                    Path(cache_root), root_descriptor, directory_descriptor,
                    lock_descriptor, authority_boundary=authority_boundary,
                    parent_uid=cache_parent_uid, parent_gid=cache_parent_gid,
                    cache_euid=cache_euid, cache_egid=cache_egid,
                    semantic_api=semantic_api,
                )
                return cached["value"]

        try:
            fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
            locked = False
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
            locked = True
        except OSError as exc:
            raise ControlAuthStatusError("cache-io") from exc
        _assert_cache_handles(
            Path(cache_root), root_descriptor, directory_descriptor,
            lock_descriptor, authority_boundary=authority_boundary,
            parent_uid=cache_parent_uid, parent_gid=cache_parent_gid,
            cache_euid=cache_euid, cache_egid=cache_egid,
            semantic_api=semantic_api,
        )
        breaker = _read_cache_breaker(
            lock_descriptor,
            required_uid=cache_parent_uid, required_gid=cache_egid,
            semantic_api=semantic_api,
        )
        observed_identity = _observed_cache_identity(directory_descriptor)
        force_refresh = False
        if breaker is not None:
            if observed_identity == _breaker_identity(breaker):
                if breaker["failure_count"] >= breaker_threshold:
                    raise ControlAuthStatusError("cache-authority")
                force_refresh = True
            else:
                _clear_cache_breaker(
                    lock_descriptor,
                    required_uid=cache_parent_uid, required_gid=cache_egid,
                    semantic_api=semantic_api,
                )
                breaker = None
                force_refresh = True

        if force_refresh:
            expected_identity = observed_identity
        else:
            cached = _read_cache_file(
                directory_descriptor,
                required_uid=cache_euid,
                required_gid=cache_egid,
                expected_helper_sha256=expected_helper_sha256,
                clock_ns=clock_ns,
                semantic_api=semantic_api,
            )
            if cached["value"] is not None:
                _assert_cache_handles(
                    Path(cache_root), root_descriptor, directory_descriptor,
                    lock_descriptor, authority_boundary=authority_boundary,
                    parent_uid=cache_parent_uid, parent_gid=cache_parent_gid,
                    cache_euid=cache_euid, cache_egid=cache_egid,
                    semantic_api=semantic_api,
                )
                return cached["value"]
            expected_identity = cached["identity"]

        value = refresher()
        if type(value) is not bool:
            raise ControlAuthStatusError("helper-protocol")
        try:
            _publish_cache_file(
                directory_descriptor,
                value=value,
                expected_identity=expected_identity,
                required_uid=cache_euid,
                required_gid=cache_egid,
                expected_helper_sha256=expected_helper_sha256,
                authority_check=lambda: _assert_cache_handles(
                    Path(cache_root), root_descriptor, directory_descriptor,
                    lock_descriptor, authority_boundary=authority_boundary,
                    parent_uid=cache_parent_uid, parent_gid=cache_parent_gid,
                    cache_euid=cache_euid, cache_egid=cache_egid,
                    semantic_api=semantic_api,
                ),
                semantic_api=semantic_api,
            )
        except _CachePublicationFailure as exc:
            contaminant = exc.contaminant_identity
            if contaminant is None:
                _clear_cache_breaker(
                    lock_descriptor,
                    required_uid=cache_parent_uid, required_gid=cache_egid,
                    semantic_api=semantic_api,
                )
            else:
                previous = _read_cache_breaker(
                    lock_descriptor,
                    required_uid=cache_parent_uid, required_gid=cache_egid,
                    semantic_api=semantic_api,
                )
                failure_count = 1
                if previous is not None and _breaker_identity(previous) == contaminant:
                    failure_count = min(
                        breaker_threshold,
                        previous["failure_count"] + 1,
                    )
                _write_cache_breaker(
                    lock_descriptor,
                    {
                        "schema_version": breaker_schema,
                        "contaminant_dev": contaminant[0],
                        "contaminant_ino": contaminant[1],
                        "failure_count": failure_count,
                    },
                    required_uid=cache_parent_uid, required_gid=cache_egid,
                    semantic_api=semantic_api,
                )
            raise ControlAuthStatusError("cache-authority") from exc
        if breaker is not None:
            _clear_cache_breaker(
                lock_descriptor,
                required_uid=cache_parent_uid, required_gid=cache_egid,
                semantic_api=semantic_api,
            )
        _assert_cache_handles(
            Path(cache_root), root_descriptor, directory_descriptor,
            lock_descriptor, authority_boundary=authority_boundary,
            parent_uid=cache_parent_uid, parent_gid=cache_parent_gid,
            cache_euid=cache_euid, cache_egid=cache_egid,
            semantic_api=semantic_api,
        )
        return value
    finally:
        if locked:
            try:
                fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
        _close_descriptors(lock_descriptor, directory_descriptor, root_descriptor)


def _validate_helper_directory(metadata, required_uid, required_gid):
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != required_uid
        or metadata.st_gid != required_gid
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise ControlAuthStatusError("helper-authority")


def _validate_helper_file(metadata, required_uid, required_gid):
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != required_uid
        or metadata.st_gid != required_gid
        or stat.S_IMODE(metadata.st_mode) != 0o755
        or metadata.st_size <= 0
        or metadata.st_size > CONTROL_AUTH_HELPER_MAX_BYTES
    ):
        raise ControlAuthStatusError("helper-authority")


def _open_helper_snapshot(
    helper_path, authority_root, required_uid, required_gid,
):
    root_descriptor = parent_descriptor = helper_descriptor = None
    try:
        authority_root = Path(authority_root)
        helper_path = Path(helper_path)
        try:
            relative = helper_path.relative_to(authority_root)
        except ValueError as exc:
            raise ControlAuthStatusError("helper-authority") from exc
        if not relative.parts or relative.name != "control-auth.py":
            raise ControlAuthStatusError("helper-authority")
        try:
            root_descriptor = os.open(
                os.fspath(authority_root), _directory_flags("helper-authority")
            )
            root_metadata = os.fstat(root_descriptor)
            root_named = os.stat(authority_root, follow_symlinks=False)
        except OSError as exc:
            raise ControlAuthStatusError("helper-authority") from exc
        _validate_helper_directory(root_metadata, required_uid, required_gid)
        if _identity(root_metadata) != _identity(root_named):
            raise ControlAuthStatusError("helper-authority")
        parent_descriptor = root_descriptor
        root_descriptor = None
        for component in relative.parts[:-1]:
            try:
                opened = os.open(
                    component,
                    _directory_flags("helper-authority"),
                    dir_fd=parent_descriptor,
                )
            except OSError as exc:
                raise ControlAuthStatusError("helper-authority") from exc
            metadata = _stat_bound_name(
                parent_descriptor, component, opened, "helper-authority"
            )
            _validate_helper_directory(metadata, required_uid, required_gid)
            _close_descriptors(parent_descriptor)
            parent_descriptor = opened
        try:
            helper_descriptor = os.open(
                relative.name,
                _file_flags("helper-authority"),
                dir_fd=parent_descriptor,
            )
        except OSError as exc:
            raise ControlAuthStatusError("helper-authority") from exc
        before = _stat_bound_name(
            parent_descriptor,
            relative.name,
            helper_descriptor,
            "helper-authority",
        )
        _validate_helper_file(before, required_uid, required_gid)
        data = _read_all(helper_descriptor, before.st_size, "helper-rebind")
        try:
            after = os.fstat(helper_descriptor)
        except OSError as exc:
            raise ControlAuthStatusError("helper-rebind") from exc
        _validate_helper_file(after, required_uid, required_gid)
        if _stable_file_metadata(before) != _stable_file_metadata(after):
            raise ControlAuthStatusError("helper-rebind")
        rebound = _stat_bound_name(
            parent_descriptor,
            relative.name,
            helper_descriptor,
            "helper-rebind",
        )
        return {
            "parent_descriptor": parent_descriptor,
            "helper_descriptor": helper_descriptor,
            "identity": _identity(rebound),
            "digest": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "metadata": _stable_file_metadata(rebound),
            "source": data,
        }
    except Exception:
        _close_descriptors(helper_descriptor, parent_descriptor, root_descriptor)
        raise


def _close_helper_snapshot(snapshot):
    if snapshot is None:
        return
    _close_descriptors(
        snapshot.get("helper_descriptor"), snapshot.get("parent_descriptor")
    )


def _load_control_auth_semantic_api(
    *, helper_path=CONTROL_AUTH_HELPER, authority_root=Path("/"),
    required_uid=0, required_gid=0,
    expected_helper_sha256=CONTROL_AUTH_HELPER_SHA256,
):
    """Load the parser API from one held, pinned helper snapshot in-process."""
    initial = replacement = None
    module = None
    try:
        initial = _open_helper_snapshot(
            helper_path, authority_root, required_uid, required_gid,
        )
        if initial["digest"] != expected_helper_sha256:
            raise ControlAuthStatusError("helper-digest")
        try:
            source = initial["source"].decode("utf-8")
            code = compile(source, os.fspath(helper_path), "exec", dont_inherit=True)
        except (SyntaxError, UnicodeError, ValueError) as exc:
            raise ControlAuthStatusError("helper-authority") from exc
        name = "_http_ztp_cgi_control_auth_" + secrets.token_hex(16)
        module = types.ModuleType(name)
        module.__file__ = os.fspath(helper_path)
        module.__package__ = ""
        module.__loader__ = None
        module.__spec__ = None
        sys.modules[name] = module
        try:
            exec(code, module.__dict__)
        except BaseException as exc:
            raise ControlAuthStatusError("helper-authority") from exc
        finally:
            if sys.modules.get(name) is module:
                sys.modules.pop(name, None)
        required = (
            "parse_monitor_authority_breaker", "parse_monitor_authority_cache",
            "parse_monitor_authority_recovery_marker",
            "build_monitor_authority_breaker", "build_monitor_authority_cache",
            "MONITOR_AUTHORITY_BREAKER_SCHEMA", "MONITOR_AUTHORITY_CACHE_SCHEMA",
            "MONITOR_AUTHORITY_BREAKER_THRESHOLD",
        )
        if any(not callable(getattr(module, item, None)) for item in required[:5]) or any(
            not isinstance(getattr(module, item, None), int) for item in required[5:]
        ):
            raise ControlAuthStatusError("helper-authority")
        replacement = _open_helper_snapshot(
            helper_path, authority_root, required_uid, required_gid,
        )
        if (
            replacement["identity"] != initial["identity"]
            or replacement["digest"] != expected_helper_sha256
            or replacement["metadata"] != initial["metadata"]
            or _stable_file_metadata(os.fstat(initial["helper_descriptor"]))
            != initial["metadata"]
        ):
            raise ControlAuthStatusError("helper-rebind")
        return module
    except ControlAuthStatusError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise ControlAuthStatusError("helper-rebind") from exc
    finally:
        _close_helper_snapshot(replacement)
        _close_helper_snapshot(initial)


def _stop_process(process):
    try:
        if process.poll() is None:
            process.kill()
    except OSError:
        pass
    for stream in (getattr(process, "stdout", None), getattr(process, "stderr", None)):
        try:
            if stream is not None:
                stream.close()
        except OSError:
            pass
    try:
        process.wait(timeout=1)
    except (OSError, subprocess.SubprocessError):
        pass


def _run_status_process(snapshot, timeout_seconds):
    capsule = CONTROL_AUTH_HELD_LAUNCH_V1
    if len(capsule.encode("utf-8")) > CONTROL_AUTH_HELD_LAUNCH_MAX_BYTES:
        raise ControlAuthStatusError("helper-protocol")
    helper_descriptor = snapshot["helper_descriptor"]
    command = [
        os.fspath(CONTROL_AUTH_PYTHON), "-I", "-B", "-c", capsule,
        str(helper_descriptor), str(snapshot["size"]), snapshot["digest"],
        os.fspath(CONTROL_AUTH_HELPER),
    ]
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(CONTROL_AUTH_SAFE_ENV),
            close_fds=True,
            pass_fds=(helper_descriptor,),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ControlAuthStatusError("helper-protocol") from exc
    output = {"stdout": bytearray(), "stderr": bytearray()}
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + timeout_seconds
    failed = None
    try:
        for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            if stream is None:
                raise ControlAuthStatusError("helper-protocol")
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ControlAuthStatusError("helper-timeout")
            events = selector.select(remaining)
            if not events:
                raise ControlAuthStatusError("helper-timeout")
            for key, _mask in events:
                name = key.data
                allowance = CONTROL_AUTH_OUTPUT_LIMIT + 1 - len(output[name])
                try:
                    chunk = os.read(key.fd, max(1, min(4096, allowance)))
                except OSError as exc:
                    raise ControlAuthStatusError("helper-protocol") from exc
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                output[name].extend(chunk)
                if len(output[name]) > CONTROL_AUTH_OUTPUT_LIMIT:
                    raise ControlAuthStatusError("output-overflow")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ControlAuthStatusError("helper-timeout")
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise ControlAuthStatusError("helper-timeout") from exc
        return returncode, bytes(output["stdout"]), bytes(output["stderr"])
    except ControlAuthStatusError as exc:
        failed = exc
        raise
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        failed = ControlAuthStatusError("helper-protocol")
        raise failed from exc
    finally:
        selector.close()
        if failed is not None:
            _stop_process(process)
        else:
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()


def _refresh_control_auth_status(
    *,
    helper_path=CONTROL_AUTH_HELPER,
    authority_root=Path("/"),
    required_uid=0,
    required_gid=0,
    expected_helper_sha256=CONTROL_AUTH_HELPER_SHA256,
    timeout_seconds=CONTROL_AUTH_TIMEOUT_SECONDS,
):
    initial = replacement = None
    process_error = None
    result = None
    try:
        initial = _open_helper_snapshot(
            helper_path, authority_root, required_uid, required_gid
        )
        if initial["digest"] != expected_helper_sha256:
            raise ControlAuthStatusError("helper-digest")
        try:
            result = _run_status_process(initial, timeout_seconds)
        except ControlAuthStatusError as exc:
            process_error = exc
        try:
            replacement = _open_helper_snapshot(
                helper_path, authority_root, required_uid, required_gid
            )
        except ControlAuthStatusError as exc:
            raise ControlAuthStatusError("helper-rebind") from exc
        if (
            replacement["identity"] != initial["identity"]
            or replacement["digest"] != expected_helper_sha256
            or _identity(os.fstat(initial["helper_descriptor"])) != initial["identity"]
            or _stable_file_metadata(os.fstat(initial["helper_descriptor"]))
            != initial["metadata"]
        ):
            raise ControlAuthStatusError("helper-rebind")
        if process_error is not None:
            raise process_error
        returncode, stdout, stderr = result
        if returncode == 1 and stdout == _INVALID_CREDENTIAL_STATE and not stderr:
            raise ControlAuthStatusError("credential-state-invalid")
        if returncode != 0 or stderr:
            raise ControlAuthStatusError("helper-protocol")
        if stdout == _VALID_FACTORY_ACTIVE:
            return True
        if stdout == _VALID_FACTORY_INACTIVE:
            return False
        raise ControlAuthStatusError("helper-protocol")
    except ControlAuthStatusError:
        raise
    except (OSError, ValueError, TypeError, subprocess.SubprocessError) as exc:
        raise ControlAuthStatusError("helper-rebind") from exc
    finally:
        _close_helper_snapshot(replacement)
        _close_helper_snapshot(initial)


def control_auth_status():
    """Return the cached exact helper status without exposing credential bytes."""
    return _cached_control_auth_status(
        cache_root=CONTROL_AUTH_CACHE_ROOT,
        authority_boundary=Path("/"),
        cache_parent_uid=0,
        cache_parent_gid=0,
        cache_euid=os.geteuid(),
        cache_egid=os.getegid(),
        expected_helper_sha256=CONTROL_AUTH_HELPER_SHA256,
        refresher=_refresh_control_auth_status,
    )


def control_request_guard():
    """Require exact upstream authentication and routing for every request."""
    if os.environ.get("CONTROL_REQUIRE_AUTH") != "1":
        return False, "control authentication is not enforced"
    if os.environ.get("AUTH_TYPE") != "Basic":
        return False, "invalid authentication type"
    if os.environ.get("REMOTE_USER") not in CONTROL_USERS:
        return False, "invalid control user"
    if os.environ.get("PATH_INFO", "") != "":
        return False, "path info is not allowed"
    if os.environ.get("SCRIPT_NAME") not in CONTROL_SCRIPT_NAMES:
        return False, "invalid control route"
    return True, ""


def post_control_guard():
    """Bind POST to the exact Apache HTTP service-IPv4 authority."""
    server_addr = os.environ.get("SERVER_ADDR", "")
    try:
        address = ipaddress.IPv4Address(server_addr)
    except ipaddress.AddressValueError:
        return False, "invalid service address"
    canonical = str(address)
    if (
        server_addr != canonical
        or address.is_unspecified
        or address.is_multicast
        or int(address) == 0xFFFFFFFF
    ):
        return False, "invalid service address"
    if os.environ.get("SERVER_PORT") != "80":
        return False, "invalid service port"
    if os.environ.get("REQUEST_SCHEME") != "http":
        return False, "invalid request scheme"
    if os.environ.get("HTTPS") not in {None, "off"}:
        return False, "TLS is not enabled on the control listener"
    host = os.environ.get("HTTP_HOST", "")
    if host not in {canonical, f"{canonical}:80"}:
        return False, "invalid Host header"
    origin = os.environ.get("HTTP_ORIGIN", "")
    fetch_site = os.environ.get("HTTP_SEC_FETCH_SITE", "").strip().casefold()
    if origin not in {f"http://{canonical}", f"http://{canonical}:80"}:
        return False, "same-origin POST is required"
    if fetch_site and fetch_site != "same-origin":
        return False, "cross-site control request rejected"
    return True, ""


def process_state():
    try:
        pid = int(PID_FILE.read_text(encoding="utf-8").strip())
        os.kill(pid, 0)
        return True, pid
    except PermissionError:
        return True, locals().get("pid")
    except (OSError, ValueError):
        return False, None


def control_state():
    try:
        value = CONTROL_FILE.read_text(encoding="utf-8").strip()
        if value == "paused":
            return "paused"
        return "running"
    except OSError:
        return "running"


def write_control(value):
    flags = (
        os.O_WRONLY | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(CONTROL_FILE, flags)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise OSError(errno.EINVAL, "control target is not a regular file")
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.ftruncate(descriptor, 0)
        os.write(descriptor, (value + "\n").encode("ascii"))
        os.fsync(descriptor)
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def respond(payload, status="200 OK"):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    print(f"Status: {status}\r")
    print("Content-Type: application/json; charset=utf-8\r")
    print("Cache-Control: no-store\r")
    print(f"Content-Length: {len(body)}\r")
    print("\r")
    sys.stdout.flush()
    sys.stdout.buffer.write(body)


def main():
    allowed, _reason = control_request_guard()
    if not allowed:
        respond({"error": "forbidden"}, "403 Forbidden")
        return
    try:
        factory_records_active = control_auth_status()
    except ControlAuthStatusError as exc:
        print(f"monitor-control-auth: {exc.category}", file=sys.stderr)
        respond(
            {"error": "control authentication state unavailable"},
            "503 Service Unavailable",
        )
        return
    except Exception:
        print("monitor-control-auth: cache-io", file=sys.stderr)
        respond(
            {"error": "control authentication state unavailable"},
            "503 Service Unavailable",
        )
        return

    def authenticated(payload):
        return {
            **payload,
            "control_auth": {
                "factory_records_active": factory_records_active,
            },
        }

    method = os.environ.get("REQUEST_METHOD", "GET").upper()
    if method == "POST":
        if os.environ.get("HTTP_X_REQUESTED_WITH") != "ZTPMonitorControl":
            respond(
                authenticated({"error": "missing control request header"}),
                "403 Forbidden",
            )
            return
        allowed, reason = post_control_guard()
        if not allowed:
            respond(authenticated({"error": reason}), "403 Forbidden")
            return
    elif method != "GET":
        respond(
            authenticated({"error": "method not allowed"}),
            "405 Method Not Allowed",
        )
        return
    alive, pid = process_state()
    if method == "GET":
        respond(authenticated({
            "state": control_state(), "process_alive": alive,
        }))
        return
    try:
        length = max(0, min(int(os.environ.get("CONTENT_LENGTH", "0")), 1024))
    except ValueError:
        length = 0
    action = parse_qs(sys.stdin.read(length)).get("action", [""])[0]
    if action not in {"start", "stop"}:
        respond(
            authenticated({"error": "action must be start or stop"}),
            "400 Bad Request",
        )
        return
    if action == "start" and not alive:
        respond(authenticated({
            "error": (
                "monitor process is not running；请按当前后端恢复：Native/systemd 执行 "
                "sudo python3 DAY0-Prepare/11-load.py DAY0-Prepare/<project> "
                "--start-ztp-monitor；Docker/Supervisor 如有 source write，执行 "
                "infra/docker/deploy.sh deploy，或对与 live 来源身份链匹配且经验证的"
                "镜像执行 infra/docker/deploy.sh deploy-preloaded <IMAGE_ID>；仅在没有 "
                "source write 且已有运行中的 inactive 控制容器时执行 "
                "infra/docker/deploy.sh load"
            ),
            "state": "stopped", "process_alive": False,
        }), "409 Conflict")
        return
    try:
        value = {"start": "running", "stop": "paused"}[action]
        write_control(value)
    except OSError as exc:
        respond(
            authenticated({"error": str(exc)}), "500 Internal Server Error",
        )
        return
    respond(authenticated({
        "state": control_state(), "process_alive": alive,
        "message": {
            "start": "ZTP monitoring resumed",
            "stop": "ZTP monitoring paused",
        }[action],
    }))


if __name__ == "__main__":
    main()
