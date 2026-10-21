"""Uninstalled single-host spreadsheet lock, not an online send capability.

All projects use one fixed root-only state directory. The directory must
already be provisioned by an independently authorized deployment; acquisition
never creates/repairs ancestors. Empty persistent locks are retained forever,
not journals or resolution evidence. UNKNOWN/FIFO/reservations, fresh admission
and a fixed audited child launcher remain separate requirements.

The borrowed lock FD may only be passed by that trusted launcher to its owned
child. Context exit REVOKES first and CLOSES, never explicitly unlocks: an
inherited open-file description must retain exclusion until its last holder
closes. No PID signalling, expiry takeover, path/UID override or network here.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import os
import re
import stat
import threading

_ACTIVE = {}
_GUARD = threading.RLock()
_ID = re.compile(r'[A-Za-z0-9_-]{20,4096}\Z')
_SHA = re.compile(r'[0-9a-f]{64}\Z')


class SpreadsheetOwnerHold(ValueError):
    def __init__(self): super().__init__('req7_spreadsheet_owner_denied')


@dataclass
class _Owner:
    pid: int
    binding: object
    descriptors: tuple
    directories: tuple
    edges: tuple
    lock_fd: int
    lock_name: str
    lock_identity: tuple


def _binding(value):
    from monitor.issue_tracker_online_target import OnlineTargetBinding
    if (type(value) is not OnlineTargetBinding or type(value.spreadsheet_id) is not str
            or _ID.fullmatch(value.spreadsheet_id) is None
            or any(type(digest) is not str or _SHA.fullmatch(digest) is None
                   for digest in (value.allowlist_sha256, value.policy_sha256))):
        raise SpreadsheetOwnerHold()
    return hashlib.sha256(value.spreadsheet_id.encode('ascii')).hexdigest() + '.lock'


def _identity(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def _directory(info, private):
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
            or (private and stat.S_IMODE(info.st_mode) != 0o700)):
        raise SpreadsheetOwnerHold()


def _lock(info):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size != 0):
        raise SpreadsheetOwnerHold()


def _validate(owner):
    if owner.pid != os.getpid() or os.geteuid() != 0: raise SpreadsheetOwnerHold()
    for fd, before, private in owner.directories:
        after = os.fstat(fd); _directory(after, private)
        if _identity(before) != _identity(after): raise SpreadsheetOwnerHold()
    for parent, name, before in owner.edges:
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if _identity(named) != _identity(before): raise SpreadsheetOwnerHold()
    held = os.fstat(owner.lock_fd); _lock(held)
    named = os.stat(owner.lock_name, dir_fd=owner.directories[-1][0], follow_symlinks=False)
    _lock(named)
    if _identity(held) != owner.lock_identity or _identity(named) != owner.lock_identity:
        raise SpreadsheetOwnerHold()


def _acquire(binding, name, descriptors):
    """All descriptors append to the caller's already-active cleanup scope."""
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    directories = []; edges = []
    parent = os.open('/', directory_flags); descriptors.append(parent)
    info = os.fstat(parent); _directory(info, False); directories.append((parent, info, False))
    for component in ('var', 'lib', 'http-ztp-container', 'issue-tracker'):
        child = os.open(component, directory_flags, dir_fd=parent); descriptors.append(child)
        info = os.fstat(child); private = component == 'issue-tracker'; _directory(info, private)
        directories.append((child, info, private)); edges.append((parent, component, info)); parent = child
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    created = False
    try:
        fd = os.open(name, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent); created = True
    except FileExistsError:
        fd = os.open(name, flags, dir_fd=parent)
    descriptors.append(fd); info = os.fstat(fd); _lock(info)
    # No waiting or stale-lock fallback; independent opens contend even
    # within one process. The namespace key deliberately excludes project,
    # target sheet, policy digest, generation and local publication root.
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    owner = _Owner(os.getpid(), binding, tuple(descriptors), tuple(directories),
                   tuple(edges), fd, name, _identity(info))
    _validate(owner)
    if created:
        os.fsync(fd); os.fsync(parent)
    _validate(owner)
    return owner


@contextmanager
def spreadsheet_owner(binding):
    """Nonblocking same-spreadsheet exclusion; typed binding is NOT admission."""
    name = _binding(binding)
    if os.geteuid() != 0: raise SpreadsheetOwnerHold()
    if any(not hasattr(os, flag) for flag in ('O_NOFOLLOW', 'O_CLOEXEC', 'O_DIRECTORY', 'O_NONBLOCK')):
        raise SpreadsheetOwnerHold()
    descriptors = []; token = object(); failed = False
    primary = None
    try:
        try:
            owner = _acquire(binding, name, descriptors)
            with _GUARD: _ACTIVE[token] = owner
        except (OSError, ValueError, TypeError, OverflowError):
            failed = True
        if failed: raise SpreadsheetOwnerHold()
        yield token
    except BaseException as error:
        primary = error
        raise
    finally:
        with _GUARD: _ACTIVE.pop(token, None)  # revoke strictly BEFORE close
        cleanup_error = None
        for fd in reversed(descriptors):
            try: os.close(fd)  # NEVER LOCK_UN; children may share this description.
            except BaseException as error:
                if (cleanup_error is None or (isinstance(cleanup_error, Exception)
                        and not isinstance(error, Exception))
                        or (isinstance(cleanup_error, OSError) and isinstance(error, Exception)
                            and not isinstance(error, OSError))):
                    cleanup_error = error
        if (cleanup_error is not None
                and (primary is None or isinstance(primary, Exception))):
            if isinstance(cleanup_error, OSError):
                raise SpreadsheetOwnerHold()
            raise cleanup_error  # No cause replacement or numeric close retry.


def _validated_owner(token, binding):
    """Internal fresh root/state binding; callers cannot select another path."""
    failed = False
    try:
        _binding(binding)
        with _GUARD: owner = _ACTIVE[token]
        if owner.binding != binding: raise SpreadsheetOwnerHold()
        _validate(owner)
        result = owner
    except (KeyError, OSError, ValueError, TypeError, OverflowError):
        failed = True
    if failed: raise SpreadsheetOwnerHold()
    return result


def owner_lock_fd(token, binding):
    """Borrow a freshly checked CLOEXEC fd; trusted launcher uses pass_fds only."""
    return _validated_owner(token, binding).lock_fd
