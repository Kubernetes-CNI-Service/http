#!/usr/bin/env python3
"""D-70 UFM-local collection producer; final archive names are completion signals.

The callable permits injected local directories and a synthetic runner for tests.
The CLI uses only canonical UFM paths; it does not discover a remote node or
prove deployment-side SSH, lease, licence, or HA identity.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import sys
from typing import Callable

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
from tools.ufm_collection_contract import (
    CollectionError, CollectionPlan, _open_held_leaf, _still_bound,
    _validated_plan, collection_plan,
    publish_local_archive,
)


class AgentError(RuntimeError):
    """No complete artifact was produced on this attempt."""


@dataclass(frozen=True)
class InvocationResult:
    returncode: int
    stdout: bytes
    stderr: bytes


Runner = Callable[[list[str]], InvocationResult]
_MAX_IBLINKINFO_BYTES = 32 * 1024 * 1024
_SAFE_HOSTNAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,252}\Z")


def _invoke(argv: list[str]) -> InvocationResult:
    try:
        result = subprocess.run(argv, capture_output=True, check=False, timeout=600)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AgentError(f"UFM vendor command failed ({type(exc).__name__})") from None
    return InvocationResult(result.returncode, result.stdout, result.stderr)


def _require_safe_local_hostname() -> None:
    """Match sw-info.sh's local-hostname gate before any collector side effect."""
    try:
        name = socket.gethostname()
    except OSError:
        raise AgentError("UFM local hostname is unavailable") from None
    if type(name) is not str or _SAFE_HOSTNAME.fullmatch(name) is None:
        raise AgentError("UFM local hostname is unsafe")


def _real_directory(path: Path, *, label: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts:
        raise AgentError(f"{label} must be an absolute directory without traversal")
    directory_flag = getattr(os, "O_DIRECTORY", None)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if (type(directory_flag) is not int or not directory_flag
            or type(nofollow) is not int or not nofollow):
        raise AgentError(f"{label} cannot be checked without no-follow support")
    current: int | None = None
    try:
        current = os.open("/", os.O_RDONLY | directory_flag)
        for part in path.parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | directory_flag | nofollow,
                              dir_fd=current)
            os.close(current)
            current = next_fd
    except OSError:
        raise AgentError(f"{label} is unavailable") from None
    finally:
        if current is not None:
            os.close(current)
    return path


def _run(runner: Runner, argv: list[str]) -> InvocationResult:
    try:
        result = runner(argv)
    except Exception as exc:
        raise AgentError(f"UFM vendor invocation failed ({type(exc).__name__})") from None
    if type(result) is not InvocationResult or type(result.returncode) is not int:
        raise AgentError("UFM vendor returned an invalid result")
    if result.returncode != 0:
        # Vendor diagnostics may contain licence or other private values.
        raise AgentError(f"UFM vendor exited nonzero ({result.returncode})")
    if type(result.stdout) is not bytes or type(result.stderr) is not bytes:
        raise AgentError("UFM vendor returned non-byte diagnostics")
    return result


def _write_exclusive_at(directory_fd: int, name: str, payload: bytes) -> None:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if type(nofollow) is not int or not nofollow:
        raise AgentError("UFM local source write requires no-follow support")
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow,
                 0o600, dir_fd=directory_fd)
    try:
        view = memoryview(payload)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise AgentError("short UFM local source write")
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _require_lock_capabilities() -> None:
    dirfd = {item.__name__ for item in os.supports_dir_fd}
    fd = {item.__name__ for item in os.supports_fd}
    nofollow = {item.__name__ for item in os.supports_follow_symlinks}
    if (not {"mkdir", "rmdir", "open", "unlink", "stat"}.issubset(dirfd)
            or "listdir" not in fd or "stat" not in nofollow):
        raise AgentError("UFM lock requires fd-relative no-follow operations")


def _named_inode_matches(name: str, parent_fd: int, held_fd: int) -> bool:
    try:
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        held = os.fstat(held_fd)
    except FileNotFoundError:
        return False
    return (named.st_dev, named.st_ino) == (held.st_dev, held.st_ino)


def _remove_private_scratch_members(directory_fd: int) -> None:
    """Remove only descendants of this held, randomly named private scratch."""
    for name in os.listdir(directory_fd):
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(before.st_mode):
            child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                               dir_fd=directory_fd)
            try:
                if not _named_inode_matches(name, directory_fd, child_fd):
                    raise AgentError("UFM scratch child changed during cleanup")
                _remove_private_scratch_members(child_fd)
                if not _named_inode_matches(name, directory_fd, child_fd):
                    raise AgentError("UFM scratch child changed during cleanup")
                os.rmdir(name, dir_fd=directory_fd)
            finally:
                os.close(child_fd)
        elif stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
            current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
                raise AgentError("UFM scratch member changed during cleanup")
            os.unlink(name, dir_fd=directory_fd)
        else:
            raise AgentError("UFM scratch contains an unsupported member")


@contextmanager
def _private_scratch(parent_fd: int, parent_path: Path, parent_stat: os.stat_result):
    """Create and remove scratch relative to one held directory, never a path alias."""
    name = ".ufm-collect-" + secrets.token_hex(12)
    os.mkdir(name, mode=0o700, dir_fd=parent_fd)
    scratch_fd = None
    try:
        scratch_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                             dir_fd=parent_fd)
        scratch_stat = os.fstat(scratch_fd)
        if (not _named_inode_matches(name, parent_fd, scratch_fd)
                or scratch_stat.st_uid != os.geteuid()
                or stat.S_IMODE(scratch_stat.st_mode) != 0o700
                or not _still_bound(parent_path, parent_stat)):
            raise AgentError("UFM scratch parent changed before use")
        yield parent_path / name, scratch_fd
    finally:
        try:
            if scratch_fd is None:
                raise AgentError("UFM scratch could not be safely opened")
            if not _named_inode_matches(name, parent_fd, scratch_fd):
                raise AgentError("UFM scratch name changed before cleanup")
            _remove_private_scratch_members(scratch_fd)
            if not _named_inode_matches(name, parent_fd, scratch_fd):
                raise AgentError("UFM scratch name changed before cleanup")
            os.rmdir(name, dir_fd=parent_fd)
        finally:
            if scratch_fd is not None:
                os.close(scratch_fd)


def _reclaim_exact_dead_lock(destination_fd: int, lock_name: str,
                             directory_flag: int, nofollow: int) -> None:
    """Recover only one same-owner, private, exact-shape dead-PID lock."""
    try:
        lock_fd = os.open(lock_name, os.O_RDONLY | directory_flag | nofollow,
                          dir_fd=destination_fd)
    except OSError:
        raise AgentError("UFM collection lock is unavailable or busy") from None
    try:
        lock_stat = os.fstat(lock_fd)
        if (not stat.S_ISDIR(lock_stat.st_mode)
                or lock_stat.st_uid != os.geteuid()
                or stat.S_IMODE(lock_stat.st_mode) != 0o700
                or os.listdir(lock_fd) != ["pid"]):
            raise AgentError("UFM collection lock has unknown ownership or shape")
        try:
            pid_fd = os.open("pid", os.O_RDONLY | nofollow, dir_fd=lock_fd)
        except OSError:
            raise AgentError("UFM collection lock PID is unavailable") from None
        try:
            pid_stat = os.fstat(pid_fd)
            if (not stat.S_ISREG(pid_stat.st_mode)
                    or pid_stat.st_uid != os.geteuid()
                    or stat.S_IMODE(pid_stat.st_mode) != 0o600
                    or pid_stat.st_nlink != 1
                    or pid_stat.st_size > 16):
                raise AgentError("UFM collection lock PID has unsafe identity")
            raw = os.read(pid_fd, 17)
            if (len(raw) != pid_stat.st_size
                    or re.fullmatch(rb"[1-9][0-9]{0,9}\n", raw) is None):
                raise AgentError("UFM collection lock PID is malformed")
            owner_pid = int(raw[:-1])
            if owner_pid > (1 << 31) - 1:
                raise AgentError("UFM collection lock PID is out of range")
            try:
                os.kill(owner_pid, 0)
            except ProcessLookupError:
                pass
            except OSError:
                raise AgentError("UFM collection lock PID cannot be proven dead") from None
            else:
                raise AgentError("UFM collection lock owner is still running")
            os.lseek(pid_fd, 0, os.SEEK_SET)
            current_raw = os.read(pid_fd, 17)
            current_pid_stat = os.fstat(pid_fd)
            if (not _named_inode_matches(lock_name, destination_fd, lock_fd)
                    or not _named_inode_matches("pid", lock_fd, pid_fd)
                    or os.listdir(lock_fd) != ["pid"]
                    or current_raw != raw
                    or (current_pid_stat.st_size, current_pid_stat.st_mtime_ns,
                        current_pid_stat.st_ctime_ns)
                    != (pid_stat.st_size, pid_stat.st_mtime_ns,
                        pid_stat.st_ctime_ns)):
                raise AgentError("UFM collection lock changed during stale check")
            os.unlink("pid", dir_fd=lock_fd)
            if not _named_inode_matches(lock_name, destination_fd, lock_fd):
                raise AgentError("UFM collection lock changed during recovery")
            os.rmdir(lock_name, dir_fd=destination_fd)
        finally:
            os.close(pid_fd)
    finally:
        os.close(lock_fd)


@contextmanager
def _collection_lock(destination_fd: int, kind: str):
    """Hold an exact private PID lock; never remove an unknown replacement."""
    _require_lock_capabilities()
    directory_flag = os.O_DIRECTORY
    nofollow = os.O_NOFOLLOW
    lock_name = f".ufm-{kind}.lock"
    try:
        os.mkdir(lock_name, mode=0o700, dir_fd=destination_fd)
    except FileExistsError:
        _reclaim_exact_dead_lock(destination_fd, lock_name, directory_flag, nofollow)
        try:
            os.mkdir(lock_name, mode=0o700, dir_fd=destination_fd)
        except OSError:
            raise AgentError("UFM collection lock is unavailable or busy") from None
    except OSError:
        raise AgentError("UFM collection lock is unavailable or busy") from None
    created_stat = os.stat(lock_name, dir_fd=destination_fd, follow_symlinks=False)
    lock_fd = None
    pid_fd = None
    pid_stat_after_write = None
    payload = f"{os.getpid()}\n".encode("ascii")
    try:
        lock_fd = os.open(lock_name, os.O_RDONLY | directory_flag | nofollow,
                          dir_fd=destination_fd)
        held_stat = os.fstat(lock_fd)
        if (not _named_inode_matches(lock_name, destination_fd, lock_fd)
                or (held_stat.st_dev, held_stat.st_ino)
                != (created_stat.st_dev, created_stat.st_ino)
                or held_stat.st_uid != os.geteuid()
                or stat.S_IMODE(held_stat.st_mode) != 0o700):
            raise AgentError("UFM collection lock changed during acquisition")
        pid_fd = os.open("pid", os.O_RDWR | os.O_CREAT | os.O_EXCL | nofollow,
                         0o600, dir_fd=lock_fd)
        if os.write(pid_fd, payload) != len(payload):
            raise AgentError("UFM collection lock PID write was short")
        os.fsync(pid_fd)
        pid_stat_after_write = os.fstat(pid_fd)
        if (not _named_inode_matches("pid", lock_fd, pid_fd)
                or not _named_inode_matches(lock_name, destination_fd, lock_fd)):
            raise AgentError("UFM collection lock changed during acquisition")
        yield
    finally:
        try:
            if lock_fd is not None:
                if pid_fd is not None:
                    if not _named_inode_matches("pid", lock_fd, pid_fd):
                        raise AgentError("UFM collection lock PID changed before cleanup")
                    if pid_stat_after_write is not None:
                        os.lseek(pid_fd, 0, os.SEEK_SET)
                        current_payload = os.read(pid_fd, len(payload) + 1)
                        current_stat = os.fstat(pid_fd)
                        if (current_payload != payload
                                or (current_stat.st_size, current_stat.st_mtime_ns,
                                    current_stat.st_ctime_ns)
                                != (pid_stat_after_write.st_size,
                                    pid_stat_after_write.st_mtime_ns,
                                    pid_stat_after_write.st_ctime_ns)):
                            raise AgentError("UFM collection lock PID changed before cleanup")
                    os.unlink("pid", dir_fd=lock_fd)
                if not _named_inode_matches(lock_name, destination_fd, lock_fd):
                    raise AgentError("UFM collection lock changed before cleanup")
                os.rmdir(lock_name, dir_fd=destination_fd)
        except OSError:
            raise AgentError("UFM collection lock cleanup failed") from None
        finally:
            if pid_fd is not None:
                os.close(pid_fd)
            if lock_fd is not None:
                os.close(lock_fd)


def collect_local(
    plan: CollectionPlan,
    destination_dir: Path,
    *,
    runner: Runner = _invoke,
    staging_dir: Path | None = None,
) -> Path:
    """Run one exact vendor command and publish a verified local archive.

    A busy/stale lock fails closed. Live stale-lock recovery and same-UID
    non-cooperating writers remain real-environment gates.
    """
    try:
        _validated_plan(plan)
    except CollectionError as exc:
        raise AgentError("noncanonical UFM collection plan") from exc
    _require_safe_local_hostname()
    destination_dir = _real_directory(destination_dir, label="UFM output")
    if staging_dir is not None:
        staging_dir = _real_directory(staging_dir, label="UFM staging")
    if plan.kind == "ibdiagnet" and staging_dir is None:
        staging_dir = _real_directory(Path(plan.ufm_staging_path), label="UFM staging")
    final = destination_dir / plan.archive_name
    part = destination_dir / plan.part_name
    if os.path.lexists(final) or os.path.lexists(part):
        raise AgentError("UFM exact archive name already exists")
    _require_lock_capabilities()
    destination_fd = None
    staging_fd = None
    try:
        destination_fd = _open_held_leaf(destination_dir, os.O_RDONLY | os.O_DIRECTORY)
        destination_stat = os.fstat(destination_fd)
        if staging_dir is not None:
            staging_fd = _open_held_leaf(staging_dir, os.O_RDONLY | os.O_DIRECTORY)
            staging_stat = os.fstat(staging_fd)
        with _collection_lock(destination_fd, plan.kind):
            if os.path.lexists(final) or os.path.lexists(part):
                raise AgentError("UFM exact archive name appeared after locking")
            if plan.kind == "ibdiagnet":
                # Existing container output could be from an earlier run. Reject
                # rather than silently archiving it or deleting live UFM data.
                _run(runner, ["docker", "exec", "ufm", "test", "!", "-e",
                              "/var/tmp/ibdiagnet2"])
            vendor = (["docker", "exec", "ufm", *plan.vendor_argv]
                      if plan.kind == "ibdiagnet" else list(plan.vendor_argv))
            produced = _run(runner, vendor)
            if (not _still_bound(destination_dir, destination_stat)
                    or (staging_fd is not None
                        and not _still_bound(staging_dir, staging_stat))):
                raise AgentError("UFM local collection directory changed before staging")
            scratch_parent = staging_dir if plan.kind == "ibdiagnet" else destination_dir
            scratch_parent_fd = staging_fd if plan.kind == "ibdiagnet" else destination_fd
            scratch_parent_stat = staging_stat if plan.kind == "ibdiagnet" else destination_stat
            assert scratch_parent is not None and scratch_parent_fd is not None
            with _private_scratch(scratch_parent_fd, scratch_parent,
                                  scratch_parent_stat) as (scratch, scratch_fd):
                if plan.kind == "ibdiagnet":
                    source = scratch / "artifact"
                    if (not _still_bound(scratch_parent, scratch_parent_stat)
                            or not _still_bound(scratch, os.fstat(scratch_fd))):
                        raise AgentError("UFM scratch changed before docker copy")
                    _run(runner, ["docker", "cp", "ufm:/var/tmp/ibdiagnet2", str(source)])
                    if not source.exists() or source.is_symlink():
                        raise AgentError("UFM ibdiagnet container copy has no real source")
                else:
                    # The first invocation's bytes, not a second vendor run, are
                    # authoritative for this exact run-id.
                    # Keep raw text inside a private scratch directory only.
                    source = scratch / "iblinkinfo.log"
                    if not produced.stdout or len(produced.stdout) > _MAX_IBLINKINFO_BYTES:
                        raise AgentError("UFM iblinkinfo result is empty or too large")
                    _write_exclusive_at(scratch_fd, "iblinkinfo.log", produced.stdout)
                return publish_local_archive(plan, source, destination_dir)
    except (CollectionError, OSError) as exc:
        raise AgentError(f"UFM local archive was not published ({type(exc).__name__})") from None
    finally:
        if staging_fd is not None:
            os.close(staging_fd)
        if destination_fd is not None:
            os.close(destination_fd)


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect one UFM-local D-70 artifact")
    parser.add_argument("--kind", choices=("ibdiagnet", "iblinkinfo"), required=True,
                        help="UFM-local artifact to collect for this run")
    parser.add_argument("--run-id", required=True,
                        help="Validated run identifier used in the exact archive filename")
    args = parser.parse_args()
    plan = collection_plan(args.kind, args.run_id)
    collect_local(plan, Path(plan.ufm_final_directory))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
