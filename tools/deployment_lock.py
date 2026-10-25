#!/usr/bin/env python3
"""Shared fail-fast deployment lock with safe parent-to-child inheritance."""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import platform
import re
import select
import stat
import struct
import sys
from typing import Iterator

if __package__:
    from .finished_project_state import FinishStateError, assert_writer_allowed
else:  # direct script import from the tools directory
    from finished_project_state import FinishStateError, assert_writer_allowed


LOCK_FD_ENV = "HTTP_DEPLOYMENT_LOCK_FD"


class DeploymentLockError(RuntimeError):
    """The deployment lock is unsafe, invalid, or already held."""


def _busy_lock_message(lock_path: Path) -> str:
    """Return actionable diagnostics without claiming a possibly stale owner."""
    return (
        "another load/setup/unsetup/unload or deployment operation is active; "
        f"lock={lock_path}; inspect without modifying it: "
        f"lsof {lock_path} || fuser {lock_path}"
    )


def _validate_regular_fd(descriptor: int, lock_path: Path) -> None:
    try:
        descriptor_stat = os.fstat(descriptor)
        path_stat = os.lstat(lock_path)
    except (OSError, ValueError) as exc:
        raise DeploymentLockError(
            f"invalid inherited deployment lock descriptor: {exc}"
        ) from exc
    if not stat.S_ISREG(descriptor_stat.st_mode) or not stat.S_ISREG(path_stat.st_mode):
        raise DeploymentLockError("deployment lock must be a regular file")
    if descriptor_stat.st_nlink != 1 or path_stat.st_nlink != 1:
        raise DeploymentLockError("deployment lock must have exactly one hard link")
    if (descriptor_stat.st_dev, descriptor_stat.st_ino) != (
        path_stat.st_dev, path_stat.st_ino,
    ):
        raise DeploymentLockError(
            "inherited deployment lock does not refer to .deployment.lock"
        )


def _open_lock(lock_path: Path, *, create: bool) -> int:
    flags = os.O_RDWR
    if create:
        flags |= os.O_CREAT
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(lock_path, flags, 0o644)
    except OSError as exc:
        raise DeploymentLockError(
            f"cannot open deployment lock {lock_path}: {exc}"
        ) from exc
    try:
        _validate_regular_fd(descriptor, lock_path)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _inherited_descriptor(lock_path: Path) -> int | None:
    raw = os.environ.get(LOCK_FD_ENV)
    if raw is None:
        return None
    try:
        descriptor = int(raw, 10)
    except ValueError as exc:
        raise DeploymentLockError(
            f"{LOCK_FD_ENV} must be a decimal file descriptor"
        ) from exc
    if descriptor < 3:
        raise DeploymentLockError(f"{LOCK_FD_ENV} must be at least 3")
    _validate_regular_fd(descriptor, lock_path)
    return descriptor


def acquire_lock_path_descriptor(
    lock_path: str | Path, *, exclusive: bool = True, create: bool = True,
) -> int:
    """Acquire one exact validated lock path without waiting."""
    lock_path = Path(lock_path)
    descriptor = _open_lock(lock_path, create=create)
    operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
    try:
        fcntl.flock(descriptor, operation | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        os.close(descriptor)
        raise DeploymentLockError(_busy_lock_message(lock_path)) from exc
    return descriptor


def acquire_lock_descriptor(
    http_root: str | Path, *, exclusive: bool = True, create: bool = True,
) -> int:
    """Acquire a workspace's validated ``.deployment.lock`` descriptor."""
    return acquire_lock_path_descriptor(
        Path(http_root) / ".deployment.lock",
        exclusive=exclusive, create=create,
    )


def release_lock_descriptor(descriptor: int | None) -> None:
    if descriptor is None:
        return
    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


@contextmanager
def deployment_lock(
    http_root: str | Path, *, dry_run: bool = False,
    finish_transaction_id: str | None = None,
) -> Iterator[int | None]:
    """Hold the workspace lock, reusing only a validated inherited lock FD.

    Re-locking an inherited descriptor is the security check: a forged
    environment value cannot bypass exclusion.  It either acquires the lock
    itself or fails against the real owner's independent open description.
    """
    lock_path = Path(http_root) / ".deployment.lock"
    descriptor: int | None = None
    inherited = False
    if dry_run and not os.path.lexists(lock_path):
        # A read-only preview must not create workspace state.
        yield None
        return
    if not dry_run:
        descriptor = _inherited_descriptor(lock_path)
        inherited = descriptor is not None
    if descriptor is None:
        descriptor = acquire_lock_descriptor(
            http_root, exclusive=not dry_run, create=not dry_run,
        )
    else:
        # Darwin: a description rejected after an ambiguous EX re-assertion
        # stays rejected for every reference, including this inherited copy,
        # and a reserved or foreign offset is refused too (2026-10-24
        # revision, clause 6); never re-lock it.
        require_clean_lock_description(descriptor)
        operation = fcntl.LOCK_SH if dry_run else fcntl.LOCK_EX
        try:
            fcntl.flock(descriptor, operation | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise DeploymentLockError(_busy_lock_message(lock_path)) from exc
    try:
        if not dry_run:
            try:
                assert_writer_allowed(
                    finish_transaction_id=finish_transaction_id,
                )
            except FinishStateError as exc:
                raise DeploymentLockError(str(exc)) from exc
        yield descriptor
    finally:
        if inherited:
            # LOCK_UN would unlock the parent's shared open-file description.
            # Closing only the child's copy leaves the parent's copy and lock.
            os.close(descriptor)
        else:
            release_lock_descriptor(descriptor)


def inherited_lock_subprocess_kwargs(descriptor: int | None) -> dict[str, object]:
    """Return the env/pass_fds pair required for a cooperating child."""
    if descriptor is None:
        return {}
    environment = os.environ.copy()
    environment[LOCK_FD_ENV] = str(descriptor)
    return {"env": environment, "pass_fds": (descriptor,)}


# --- Darwin kernel unlock witness (KWV) ------------------------------------
# Darwin has no read-only query that attributes a BSD flock to one open file
# description: F_GETLK(7), F_GETLKPID(66), F_OFD_GETLK(92) and
# F_OFD_GETLKPID(94) return the same answer for "this OFD holds EX" and "a
# foreign OFD holds EX", and F_GETFL keeps a sticky flag (native mechanism
# probes of 2026-10-23).  The witness instead records, in the kernel, every
# flock release/rename/revoke on the exact lock vnode during one check, so a
# foreign release between the independent SH probe and the caller's EX
# re-assertion is a rejection without touching the caller.
#
# Public ABI literals (macOS SDK, independent of this module's behaviour):
#   usr/include/sys/event.h  NOTE_FUNLOCK 0x00000100 "vnode was unlocked by
#       flock(2)"; kqueue(2): "unlocked by calling flock(2) or close(2)".
#   usr/include/sys/fcntl.h  O_EVTONLY 0x00008000.
# FWASLOCKED 0x00004000 is XNU's sticky "has or has had an advisory lock"
# description flag (F_GETFL).  It is used ONLY as the negative fact "this
# description never held a flock, so it cannot hold the current EX".
_DARWIN_NOTE_FUNLOCK = 0x00000100
_DARWIN_O_EVTONLY = 0x00008000
_DARWIN_FWASLOCKED = 0x00004000
_DARWIN_WITNESS_API = (
    "kqueue", "kevent", "KQ_FILTER_VNODE", "KQ_EV_ADD", "KQ_EV_CLEAR",
    "KQ_EV_ERROR", "KQ_NOTE_DELETE", "KQ_NOTE_RENAME", "KQ_NOTE_REVOKE",
)
# Mode/uid/gid/nlink are re-checked through fstat/lstat identity exactly as
# before; NOTE_ATTRIB/NOTE_LINK are not watched so an unrelated atime or
# metadata touch cannot spuriously abort a running load (native item N9).


class _DarwinUnlockWitness:
    """Handles of one registered kernel witness; carries no authority."""

    __slots__ = ("watch", "queue")

    def __init__(self, watch: int, queue) -> None:
        self.watch = watch
        self.queue = queue


def _open_darwin_unlock_witness(lock_path, fields, identity) -> _DarwinUnlockWitness:
    """Register the witness on the exact vnode BEFORE any probe or EX attempt."""
    if sys.platform != "darwin" or not all(hasattr(select, name) for name in _DARWIN_WITNESS_API):
        raise DeploymentLockError("deployment lock kernel unlock witness is unavailable; HOLD")
    watch = os.open(lock_path, _DARWIN_O_EVTONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    queue = None
    try:
        if tuple(getattr(os.fstat(watch), name) for name in fields) != identity:
            raise DeploymentLockError("deployment lock changed before kernel witness registration; HOLD")
        queue = select.kqueue()
        registration = select.kevent(
            watch, filter=select.KQ_FILTER_VNODE,
            flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
            fflags=(_DARWIN_NOTE_FUNLOCK | select.KQ_NOTE_DELETE | select.KQ_NOTE_RENAME
                    | select.KQ_NOTE_REVOKE),
        )
        if queue.control([registration], 1, 0):
            # An EV_ERROR receipt or an immediate vnode event: fail closed.
            raise DeploymentLockError("deployment lock changed during kernel witness registration; HOLD")
        return _DarwinUnlockWitness(watch, queue)
    except BaseException:
        try:
            if queue is not None:
                queue.close()
        finally:
            os.close(watch)
        raise


def _darwin_witness_disturbed(witness) -> bool:
    """Return whether any release/rename/revoke was recorded; never blocks."""
    events = witness.queue.control(None, 16, 0)
    for event in events:
        if (event.ident != witness.watch or event.filter != select.KQ_FILTER_VNODE
                or event.flags & select.KQ_EV_ERROR):
            raise DeploymentLockError("deployment lock kernel witness returned an invalid event; HOLD")
    return bool(events)


def _close_darwin_unlock_witness(witness) -> None:
    try:
        witness.queue.close()
    finally:
        os.close(witness.watch)


def _darwin_never_flocked(descriptor: int) -> bool:
    return not fcntl.fcntl(descriptor, fcntl.F_GETFL) & _DARWIN_FWASLOCKED


_DARWIN_FLOCK_STRUCT = "qqihh"  # l_start, l_len, l_pid, l_type, l_whence (24 bytes)


def _darwin_blocking_lock(descriptor: int):
    """Read-only F_GETLK seen from ``descriptor``: (l_type, l_pid) of a blocker.

    On Darwin a BSD flock blocker reports l_pid == -1 (owner not attributable),
    while a POSIX record lock reports its owning PID (2026-10-23 native probe,
    item N12).  A POSIX blocker can never be the caller's flock, and its
    release would not post NOTE_FUNLOCK, so it is rejected before any EX call.
    """
    request = struct.pack(_DARWIN_FLOCK_STRUCT, 0, 0, 0, fcntl.F_WRLCK, os.SEEK_SET)
    reply = struct.unpack(_DARWIN_FLOCK_STRUCT, fcntl.fcntl(descriptor, fcntl.F_GETLK, request))
    return reply[3], reply[2]


# --- Darwin rejected-description taint (2026-10-24 owner-confirmed revision,
# "同意 1"; test_cases/PERFORMANCE_VALIDATION_HANDOVER.md) -------------------
# A rejection that happens after the caller's EX re-assertion succeeded cannot
# tell "genuine holder + unrelated release" from "a foreign holder released and
# the re-assertion converted this description" (residual R-alpha: no read-only
# Darwin query attributes a flock to one description, native probes TR-1 and
# TR-1b).  The rejection therefore marks the description itself by moving its
# shared file offset to a reserved value.  The offset travels with every dup,
# fork and exec reference of that description (dup(2), fork(2), execve(2)) and
# vanishes with it, so every later verification through the description is
# rejected before any probe or EX call; closing every reference and acquiring
# anew is the only recovery (fail closed).
# Invariant (static guard test): no code reads, writes or seeks a deployment
# lock descriptor, so a clean description keeps offset 0.  Seeking past EOF
# does not extend the empty lock file (lseek(2); native TR-1c O3).
# Cooperating code only: this guards misuse, not a malicious same-UID process.
# Exact offset partition (refinement of clause 6): 0 clean; >= 2^44 tainted;
# [2^40, 2^44) reserved for Phase 2 transaction signatures and refused as
# "not enabled" until Phase 2 lands; 0 < offset < 2^40 violates clause 7.
_LOCK_DESCRIPTION_CLEAN_OFFSET = 0
_LOCK_DESCRIPTION_RESERVED_START = 1 << 40
_LOCK_DESCRIPTION_TAINT_OFFSET = 1 << 44


def _lock_description_offset(descriptor: int) -> int:
    """Read-only: the description's current offset (lseek by 0 from SEEK_CUR)."""
    return os.lseek(descriptor, 0, os.SEEK_CUR)


def _taint_lock_description(descriptor: int) -> bool:
    """Mark a description rejected after a possibly converting EX re-assertion."""
    try:
        return (os.lseek(descriptor, _LOCK_DESCRIPTION_TAINT_OFFSET, os.SEEK_SET)
                == _LOCK_DESCRIPTION_TAINT_OFFSET)
    except OSError:
        return False


def _require_clean_lock_description(descriptor: int, error_type) -> None:
    """Apply the exact offset partition; raise ``error_type`` for every non-clean interval."""
    try:
        offset = _lock_description_offset(descriptor)
    except OSError as exc:
        raise error_type(f"deployment lock description offset is unavailable; HOLD: {exc}") from exc
    if offset == _LOCK_DESCRIPTION_CLEAN_OFFSET:
        return
    if offset >= _LOCK_DESCRIPTION_TAINT_OFFSET:
        raise error_type(
            "deployment lock description is tainted by an earlier ambiguous rejection "
            f"(offset {offset} >= 2^44); close every reference and acquire a new deployment lock; HOLD"
        )
    if offset >= _LOCK_DESCRIPTION_RESERVED_START:
        raise error_type(
            f"deployment lock description offset {offset} is in the reserved Phase 2 signature "
            "range [2^40, 2^44), which is not enabled; HOLD"
        )
    raise error_type(
        f"deployment lock description offset {offset} violates the invariant that no code "
        "reads, writes or seeks a deployment lock descriptor; HOLD"
    )


def require_clean_lock_description(descriptor: int, error_type=DeploymentLockError) -> None:
    """Darwin: offset partition check of a held lock descriptor before any re-lock.

    The taint is a Darwin-only mechanism; on other platforms this is a no-op
    and the Linux /proc current-FD contract is unchanged.
    """
    if sys.platform == "darwin":
        _require_clean_lock_description(descriptor, error_type)


_CURRENT_LOCK_FDINFO_ROOT = Path("/proc/self/fdinfo")
_CURRENT_LOCK_FDINFO_LIMIT = 65536


def _read_current_lock_fdinfo(descriptor: int) -> bytes:
    """Read only the current process's exact FD, never an inode-global lock list."""
    flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0))
    opened = os.open(_CURRENT_LOCK_FDINFO_ROOT / str(descriptor), flags)
    try:
        if not stat.S_ISREG(os.fstat(opened).st_mode):
            raise DeploymentLockError("runtime rollback deployment lock fdinfo is not regular; HOLD")
        payload = bytearray()
        while True:
            block = os.read(opened, _CURRENT_LOCK_FDINFO_LIMIT + 1 - len(payload))
            if not block:
                return bytes(payload)
            payload.extend(block)
            if len(payload) > _CURRENT_LOCK_FDINFO_LIMIT:
                raise DeploymentLockError("runtime rollback deployment lock fdinfo exceeds bounded read; HOLD")
    finally:
        os.close(opened)


def _require_current_fdinfo_exclusive(payload: bytes, metadata) -> None:
    """Require one current-OFD, whole-file Linux BSD-flock EX row."""
    error = "runtime rollback deployment lock fdinfo lacks exact current exclusive authority; HOLD"
    if (not isinstance(payload, bytes) or not payload or len(payload) > _CURRENT_LOCK_FDINFO_LIMIT
            or not payload.endswith(b"\n") or b"\0" in payload or b"\r" in payload):
        raise DeploymentLockError(error)
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise DeploymentLockError(error) from exc
    headers, locks = {}, []
    patterns = {"pos": r"[0-9]+", "flags": r"[0-7]+", "mnt_id": r"[0-9]+", "ino": r"[0-9]+"}
    lock_pattern = (r"lock:[ \t]+([1-9][0-9]*):[ \t]+FLOCK[ \t]+ADVISORY[ \t]+WRITE[ \t]+"
                    r"(-?[0-9]+)[ \t]+([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9]+)[ \t]+0[ \t]+EOF")
    for line in lines:
        if line.startswith("lock:"):
            match = re.fullmatch(lock_pattern, line)
            if match is None:
                raise DeploymentLockError(error)
            locks.append(match)
        else:
            name, separator, value = line.partition(":")
            if (not separator or name not in patterns or name in headers
                    or re.fullmatch("[ \\t]+" + patterns[name], value) is None):
                raise DeploymentLockError(error)
            headers[name] = value.strip()
    if set(headers) != set(patterns) or len(locks) != 1:
        raise DeploymentLockError(error)
    row = locks[0]
    if (int(headers["ino"]) != metadata.st_ino
            or int(row.group(3), 16) != os.major(metadata.st_dev)
            or int(row.group(4), 16) != os.minor(metadata.st_dev)
            or int(row.group(5), 10) != metadata.st_ino):
        raise DeploymentLockError(error)
    # The original creator PID can survive dup/fork/exec; it is not the
    # authority. The kernel's current-FD file-description filter is.


def require_current_exclusive_lock_descriptor(lock_path, descriptor) -> None:
    """Check an exact lock's current exclusive FD; no acquisition or finish authority.

    The legacy runtime-rollback diagnostics are retained for mechanical
    comparison. No existing LOAD caller delegates to this new helper yet.
    """
    if type(descriptor) is not int or descriptor < 3:
        raise DeploymentLockError("runtime rollback deployment lock descriptor is invalid")
    try:
        lock_path = Path(lock_path)
    except (TypeError, ValueError) as exc:
        raise DeploymentLockError("deployment lock path is invalid") from exc
    try:
        descriptor_stat = os.fstat(descriptor)
        lock_stat = lock_path.lstat()
    except (OSError, ValueError) as exc:
        raise DeploymentLockError(f"runtime rollback deployment lock is invalid: {exc}") from exc
    if (not stat.S_ISREG(descriptor_stat.st_mode)
            or not stat.S_ISREG(lock_stat.st_mode)
            or descriptor_stat.st_nlink != 1 or lock_stat.st_nlink != 1
            or (descriptor_stat.st_dev, descriptor_stat.st_ino)
            != (lock_stat.st_dev, lock_stat.st_ino)):
        raise DeploymentLockError("runtime rollback deployment lock identity is invalid")
    fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink")
    identity = tuple(getattr(descriptor_stat, name) for name in fields)
    if identity != tuple(getattr(lock_stat, name) for name in fields):
        raise DeploymentLockError("runtime rollback deployment lock metadata is invalid")
    operating_system = platform.system().casefold()
    if operating_system == "linux":
        try:
            for _ in range(2):
                _require_current_fdinfo_exclusive(
                    _read_current_lock_fdinfo(descriptor), descriptor_stat,
                )
                if (tuple(getattr(os.fstat(descriptor), name) for name in fields) != identity
                        or tuple(getattr(lock_path.lstat(), name) for name in fields) != identity):
                    raise DeploymentLockError("runtime rollback deployment lock changed during current-FD check; HOLD")
        except (OSError, ValueError) as exc:
            raise DeploymentLockError(f"runtime rollback deployment lock fdinfo unavailable; HOLD: {exc}") from exc
        return
    if operating_system != "darwin":
        raise DeploymentLockError("deployment lock current-FD protocol is unsupported; HOLD")
    _require_darwin_witnessed_current_exclusive(
        lock_path, descriptor, fields, identity, DeploymentLockError,
    )


def _require_darwin_witnessed_current_exclusive(lock_path, descriptor, fields, identity, error_type) -> None:
    """Darwin VERIFY_PREHELD (KWV); shared by this helper and the LOAD guard.

    Accept only when, inside one kernel witness window registered before the
    first probe: an independent SH probe is blocked (some EX holder exists),
    no flock release/rename/revoke happened on the vnode, the caller's
    description has held a flock at some time, and the caller's idempotent EX
    re-assertion did not block.  If a foreign holder X existed at the probe
    and is not the caller, X can only stop holding by an F_UNLCK (witnessed),
    so with no witnessed event X would still block the caller's assertion.
    The EX call is therefore never accepted on its own (contract D1); a
    witnessed event at any step rejects.  Residual windows (R-beta/gamma) are
    documented in W2 REPORT.md.  R-alpha follows the 2026-10-24 owner-confirmed
    revision: a rejection after the EX re-assertion taints the description, and
    a tainted description is rejected here before any probe or EX call.
    """
    _require_clean_lock_description(descriptor, error_type)
    try:
        witness = _open_darwin_unlock_witness(lock_path, fields, identity)
    except DeploymentLockError as exc:
        raise error_type(f"runtime rollback deployment lock kernel witness unavailable; HOLD: {exc}") from exc
    except OSError as exc:
        raise error_type(f"runtime rollback deployment lock kernel witness unavailable; HOLD: {exc}") from exc
    probe = None
    owned_probe = True
    reasserted = accepted = False
    try:
        probe = os.open(lock_path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
        if tuple(getattr(os.fstat(probe), name) for name in fields) != identity:
            raise error_type("runtime rollback deployment lock changed before probe")
        try:
            # An independent shared probe distinguishes EX from SH without
            # converting the caller's original open-file-description lock.
            fcntl.flock(probe, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            pass
        else:
            fcntl.flock(probe, fcntl.LOCK_UN)
            raise error_type("runtime rollback deployment lock is not held exclusively")
        blocker_type, blocker_pid = _darwin_blocking_lock(probe)
        if blocker_type != fcntl.F_WRLCK or blocker_pid != -1:
            raise error_type(
                "runtime rollback deployment lock belongs to another descriptor: the "
                "exclusive blocker is not an unattributed flock description"
            )
        if _darwin_witness_disturbed(witness):
            raise error_type(
                "runtime rollback deployment lock changed during ownership check: kernel "
                "witness observed a release, rename or revoke before EX re-assertion; HOLD"
            )
        if _darwin_never_flocked(descriptor):
            raise error_type(
                "runtime rollback deployment lock belongs to another descriptor: "
                "this description never held a flock"
            )
        try:
            # Idempotent for the genuine holder; blocked for anybody else while
            # the witness shows no release.  Never accepted without the witness.
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise error_type("runtime rollback deployment lock belongs to another descriptor") from exc
        reasserted = True
        if _darwin_witness_disturbed(witness):
            raise error_type(
                "runtime rollback deployment lock changed during ownership check: kernel "
                "witness observed a release around EX re-assertion; descriptor authority "
                "is ambiguous; HOLD"
            )
        if (tuple(getattr(os.fstat(descriptor), name) for name in fields) != identity
                or tuple(getattr(Path(lock_path).lstat(), name) for name in fields) != identity):
            raise error_type("runtime rollback deployment lock changed during ownership check")
        # A sharer of this description may have tainted it during the check.
        _require_clean_lock_description(descriptor, error_type)
        accepted = True
    except DeploymentLockError as exc:
        if error_type is DeploymentLockError:
            raise
        raise error_type(str(exc)) from exc
    except OSError as exc:
        raise error_type(f"runtime rollback deployment lock check unavailable: {exc}") from exc
    finally:
        # Revision clause 6: any rejection after the EX re-assertion marks the
        # description before the witness and probe are closed.
        taint_failed = reasserted and not accepted and not _taint_lock_description(descriptor)
        try:
            _close_darwin_unlock_witness(witness)
        finally:
            if owned_probe and probe is not None:
                os.close(probe)
        if taint_failed:
            raise error_type(
                "runtime rollback deployment lock was rejected after EX re-assertion and the "
                "description could not be marked; close every reference; HOLD"
            )
