#!/usr/bin/env python3
"""Shared fail-fast deployment lock with safe parent-to-child inheritance."""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import stat
from typing import Iterator


LOCK_FD_ENV = "HTTP_DEPLOYMENT_LOCK_FD"


class DeploymentLockError(RuntimeError):
    """The deployment lock is unsafe, invalid, or already held."""


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
        raise DeploymentLockError(
            "another load/setup/unsetup/unload or deployment operation is active"
        ) from exc
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
        operation = fcntl.LOCK_SH if dry_run else fcntl.LOCK_EX
        try:
            fcntl.flock(descriptor, operation | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise DeploymentLockError(
                "another load/setup/unsetup/unload or deployment operation is active"
            ) from exc
    try:
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
