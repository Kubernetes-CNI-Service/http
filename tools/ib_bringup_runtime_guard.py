"""Host-local IB initialization/upgrade guard; frozen2.25 algorithm source proposal."""
import errno
import fcntl
import os
from pathlib import Path
import stat
from contextlib import contextmanager

_RUNTIME_GUARD_PATH = Path('/tmp/http-ib-bringup.runtime.lock')

class _InstanceGuardError(RuntimeError):
    def __init__(self, code, detail):
        super().__init__(detail)
        self.code = code

@contextmanager
def _runtime_instance_guard():
    """Nonblocking kernel lock, not a PID/sentinel or deployment prerequisite.

    The persistent empty regular inode is intentional: never unlink it when
    releasing, which would allow two processes to lock different generations.
    Existing files are opened read-only so another UID, including root, can
    participate without rewriting/chmodding the original creator's file.
    """
    descriptor = None
    try:
        flags = os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        try:
            descriptor = os.open(_RUNTIME_GUARD_PATH,
                                 os.O_RDWR | os.O_CREAT | os.O_EXCL | flags, 0o644)
            os.fchmod(descriptor, 0o644)
        except FileExistsError:
            descriptor = os.open(_RUNTIME_GUARD_PATH, os.O_RDONLY | flags)
        os.set_inheritable(descriptor, False)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o022:
            raise _InstanceGuardError('INSTANCE_GUARD_UNAVAILABLE',
                'Unsafe runtime guard type, links or permissions. No operations started. '
                'Ask the administrator to inspect ' + str(_RUNTIME_GUARD_PATH))
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            if error.errno not in (errno.EAGAIN, errno.EACCES):
                raise
            raise _InstanceGuardError('ALREADY_RUNNING',
                'Another initialization or upgrade process is running on this management host. '
                'No operations started. Wait for it to finish; do not delete the runtime guard: '
                + str(_RUNTIME_GUARD_PATH)) from None
        current = os.stat(_RUNTIME_GUARD_PATH, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            raise _InstanceGuardError('INSTANCE_GUARD_UNAVAILABLE',
                'Runtime guard changed while opening. No operations started. '
                'Ask the administrator to inspect ' + str(_RUNTIME_GUARD_PATH))
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
            descriptor = None
        raise _InstanceGuardError('INSTANCE_GUARD_UNAVAILABLE',
            'Cannot safely acquire the runtime guard (errno=' + str(error.errno) + '). '
            'No operations started. Ask the administrator to inspect '
            + str(_RUNTIME_GUARD_PATH)) from None
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        raise
    primary = None
    try:
        yield descriptor
    except BaseException as exc:
        primary = exc
        raise
    finally:
        # Close, never LOCK_UN: retain the original owned-FD protocol.
        try:
            os.close(descriptor)
        except BaseException as cleanup:
            if primary is None or (
                isinstance(primary, Exception) and not isinstance(cleanup, Exception)
            ):
                raise
