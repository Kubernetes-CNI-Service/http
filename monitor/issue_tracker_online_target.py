"""REQ7 C-2/C-7 target checks and locked current-input observation, not send.

The file format is an exact top-level JSON array of spreadsheet ID strings.
The pure parser/binder cannot establish file provenance. The separate current
project observation consumes the existing C-1/C-11 fixed-path root-only FD
reader and actual ACTIVE project owner; native root/RO-bind remains REAL_ENV.
No authentication SDK import, connection or online activation. Hashes alone
never establish provenance or authorize a wire attempt.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
import hashlib
import json
import os
import re
import stat


_ID = re.compile(r"[A-Za-z0-9_-]{20,}\Z")
_MAX_ALLOWLIST_BYTES = 65536
_HELD_CURRENT_TARGET = ContextVar('req7_held_current_target', default=None)


class OnlineTargetHold(ValueError):
    """Sanitized machine reason; never echo file contents or target IDs."""

    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class TargetAllowlistSnapshot:
    spreadsheet_ids: tuple[str, ...] = field(repr=False)
    source_bytes: bytes = field(repr=False)
    sha256: str


@dataclass(frozen=True)
class OnlineTargetBinding:
    spreadsheet_id: str = field(repr=False)
    allowlist_sha256: str
    policy_sha256: str


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise OnlineTargetHold("invalid_target_allowlist")
        result[key] = value
    return result


def _constant(_value):
    raise OnlineTargetHold("invalid_target_allowlist")


def freeze_target_allowlist(source_bytes):
    """Freeze the original bounded enumeration, without deriving or normalizing."""
    if (type(source_bytes) is not bytes
            or not 1 <= len(source_bytes) <= _MAX_ALLOWLIST_BYTES):
        raise OnlineTargetHold("invalid_target_allowlist")
    try:
        values = json.loads(source_bytes.decode("utf-8", "strict"),
                            object_pairs_hook=_pairs, parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise OnlineTargetHold("invalid_target_allowlist") from None
    if (type(values) is not list
            or any(type(value) is not str or _ID.fullmatch(value) is None for value in values)
            or len(set(values)) != len(values)):
        raise OnlineTargetHold("invalid_target_allowlist")
    return TargetAllowlistSnapshot(tuple(values), source_bytes,
                                   hashlib.sha256(source_bytes).hexdigest())


def bind_online_target(global_document, allowlist, *, expected=None):
    """Check current policy and enumeration afresh; return a binding, not a permit.

    A prior binding is never silently retargeted. Disabled/revoked policy
    remains stopped; changes to target, enumeration bytes or policy are stale.
    No operation here reads secrets, writes a journal or alters local work.
    """
    from tools.project_contract import normalize_issue_tracker_policy

    try:
        policy = normalize_issue_tracker_policy(global_document)
    except (ValueError, TypeError, RecursionError):
        raise OnlineTargetHold("invalid_online_policy") from None
    if policy["status"] != "enabled":
        raise OnlineTargetHold("online_disabled_" + policy["presence"])
    if (type(allowlist) is not TargetAllowlistSnapshot
            or freeze_target_allowlist(allowlist.source_bytes) != allowlist):
        raise OnlineTargetHold("invalid_target_allowlist")
    if expected is not None and type(expected) is not OnlineTargetBinding:
        raise OnlineTargetHold("invalid_target_binding")
    target = policy["spreadsheet_id"]
    digest = hashlib.sha256((json.dumps(policy, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")).hexdigest()
    current = OnlineTargetBinding(target, allowlist.sha256, digest)
    if expected is not None and current != expected:
        raise OnlineTargetHold("stale_target_binding")
    if not allowlist.spreadsheet_ids:
        raise OnlineTargetHold("denied_empty_allowlist")
    if target not in allowlist.spreadsheet_ids:
        raise OnlineTargetHold("target_not_allowlisted")
    return current


def bind_current_project_online_target(writer_token):
    """Initial binding from the actual project owner and fixed root inputs.

    No caller document, path, target or previous binding enters this API.
    This supplies a typed locator only, never admission or send permission.
    Every downstream use still owes current exact-binding revalidation.
    """
    return _inspect_project_online_target(writer_token, None)


def inspect_project_online_target(writer_token, expected):
    """Revalidate an exact previous binding; never silently initialize it."""
    if type(expected) is not OnlineTargetBinding:
        raise OnlineTargetHold('current_target_binding_unproved')
    return _inspect_project_online_target(writer_token, expected)


def _inspect_project_online_target(writer_token, expected):
    """Reopen current project policy and the fixed root-only enumeration.

    The actual ACTIVE project owner supplies the held project FD, never a
    caller path/document. Read 01-global.yaml once, recheck held/named metadata
    and ownership after the independent fixed allowlist reader. No retarget,
    fallback, repair, credential read or network. This observation is necessary
    but NOT sufficient for fresh admission, W1/template/nonce continuity,
    cadence, an inherited-lock launcher, a send capability or COMPLETE.
    """
    from monitor.issue_tracker_local_commit import _owner
    from monitor.issue_tracker_credential_shape import read_target_allowlist
    from tools.project_contract import safe_load_global_yaml

    active = _HELD_CURRENT_TARGET.get()
    if active is not None:
        if active[0] is not writer_token or _owner(writer_token) is not active[3]:
            raise OnlineTargetHold('current_target_binding_unproved')
        active[2]()
        if expected is not None and active[1] != expected:
            raise OnlineTargetHold('stale_target_binding')
        active[2]()
        return active[1]

    fd = None; failed = False
    def identity(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    try:
        if ((expected is not None and type(expected) is not OnlineTargetBinding) or os.geteuid() != 0
                or any(not hasattr(os, flag) for flag in ('O_NOFOLLOW', 'O_CLOEXEC', 'O_NONBLOCK'))):
            raise OnlineTargetHold('current_target_binding_unproved')
        owner = _owner(writer_token)
        fd = os.open('01-global.yaml', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            dir_fd=owner.project_fd)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_mode & 0o022
                or before.st_nlink != 1 or not 1 <= before.st_size <= 1024*1024):
            raise OnlineTargetHold('current_target_binding_unproved')
        raw = os.read(fd, 1024*1024+1)
        if len(raw) != before.st_size: raise OnlineTargetHold('current_target_binding_unproved')
        document = safe_load_global_yaml(raw.decode('utf-8', 'strict'))
        result = bind_online_target(document, read_target_allowlist(), expected=expected)
        if (identity(os.fstat(fd)) != identity(before)
                or identity(os.stat('01-global.yaml', dir_fd=owner.project_fd, follow_symlinks=False)) != identity(before)
                or _owner(writer_token) is not owner):
            raise OnlineTargetHold('current_target_binding_unproved')
    except Exception: failed = True
    finally:
        if fd is not None:
            try: os.close(fd)
            except OSError: failed = True
    if failed: raise OnlineTargetHold('current_target_binding_unproved')
    return result


def _require_held_current_project_online_target(writer_token, binding):
    """Only the native scope supplies its actual writer/binding/originals."""
    from monitor.issue_tracker_local_commit import _owner
    active = _HELD_CURRENT_TARGET.get()
    if (active is None or active[0] is not writer_token or active[1] is not binding
            or _owner(writer_token) is not active[3]):
        raise OnlineTargetHold('current_target_binding_unproved')
    active[2]()


@contextmanager
def _hold_current_project_online_target(writer_token):
    """Pin actual fixed config and allowlist until sensitive finalizers finish.

    No caller config/path/binding/checker. Public revalidation inside this scope
    checks these originals instead of accepting a same-byte replacement inode.
    """
    from monitor import issue_tracker_local_commit as local
    from monitor.issue_tracker_credential_shape import _hold_private_file
    from tools.project_contract import safe_load_global_yaml

    def identity(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    fd = None; key = None; failed = False; project_fds = []; project_edges = []
    primary = None
    try:
        if (_HELD_CURRENT_TARGET.get() is not None or os.geteuid() != 0
                or any(not hasattr(os, flag) for flag in ('O_NOFOLLOW', 'O_CLOEXEC', 'O_NONBLOCK'))):
            raise OnlineTargetHold('current_target_binding_unproved')
        owner = local._owner(writer_token)
        # Independently owned no-follow ancestor FDs overlap the actual owner
        # BEFORE its revoke/close. These are read-only originals, not an ACTIVE
        # token extension; every public/driver use still validates that token.
        parent = local.os.open('/', local._flags(directory=True)); project_fds.append(parent)
        root_identity = identity(os.fstat(parent))[:5]
        for name in owner.project.parts[1:]:
            child = local.os.open(name, local._flags(directory=True), dir_fd=parent)
            project_fds.append(child)
            project_edges.append((parent, name, child, identity(os.fstat(child))[:5]))
            parent = child
        project_fd = parent
        if identity(os.fstat(project_fd))[:2] != identity(os.fstat(owner.project_fd))[:2]:
            raise OnlineTargetHold('current_target_binding_unproved')
        fd = os.open('01-global.yaml', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            dir_fd=project_fd)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_mode & 0o022
                or before.st_nlink != 1 or not 1 <= before.st_size <= 1024*1024):
            raise OnlineTargetHold('current_target_binding_unproved')
        raw = os.read(fd, 1024*1024+1)
        if len(raw) != before.st_size:
            raise OnlineTargetHold('current_target_binding_unproved')
        document = safe_load_global_yaml(raw.decode('utf-8', 'strict'))
        with _hold_private_file('issue-tracker-spreadsheet-whitelist.json') as (allowlist, check_allowlist):
            binding = bind_online_target(document, freeze_target_allowlist(allowlist))
            def verify():
                if (os.geteuid() != 0
                        or identity(os.fstat(project_fds[0]))[:5] != root_identity
                        or identity(os.fstat(fd)) != identity(before)
                        or identity(os.stat('01-global.yaml', dir_fd=project_fd,
                            follow_symlinks=False)) != identity(before)):
                    raise OnlineTargetHold('current_target_binding_unproved')
                for ancestor, name, child, original in project_edges:
                    if (identity(os.fstat(child))[:5] != original
                            or identity(os.stat(name, dir_fd=ancestor, follow_symlinks=False))[:5] != original):
                        raise OnlineTargetHold('current_target_binding_unproved')
                check_allowlist()
            verify()
            if local._owner(writer_token) is not owner:
                raise OnlineTargetHold('current_target_binding_unproved')
            key = _HELD_CURRENT_TARGET.set((writer_token, binding, verify, owner))
            try:
                yield binding
                verify()
            finally:
                _HELD_CURRENT_TARGET.reset(key); key = None
    except Exception:
        failed = True
    except BaseException as error:
        primary = error
        raise
    finally:
        cleanup_error = None
        if fd is not None:
            try: os.close(fd)
            except BaseException as error:
                if isinstance(error, OSError): failed = True
                else: cleanup_error = error
        for descriptor in reversed(project_fds):
            try: local.os.close(descriptor)
            except BaseException as error:
                if isinstance(error, OSError):
                    failed = True
                elif (cleanup_error is None or (isinstance(cleanup_error, Exception)
                        and not isinstance(error, Exception))):
                    cleanup_error = error
        if (cleanup_error is not None
                and (primary is None or isinstance(primary, Exception))):
            raise cleanup_error  # Registration was revoked before these critical closes.
    if failed:
        raise OnlineTargetHold('current_target_binding_unproved')
