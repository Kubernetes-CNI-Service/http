#!/usr/bin/env python3
"""D-70 UFM collection planning and local artifact boundary."""

from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import os
from pathlib import Path
import re
import secrets
import stat
import tarfile


class CollectionError(ValueError):
    """A collection plan or local publication was unsafe or incomplete."""


_RUN_ID_RE = re.compile(r"^([0-9]{8}-[0-9]{4})-(prod|air)-([0-9a-f]{16})$")
_NODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
_IBDIAGNET_ARGV = (
    "/opt/ufm/opensm/bin/ibdiagnet", "--sc", "--extended_speeds", "all",
    "-P", "all=1", "--pm_per_lane", "--get_cable_info",
    "--cable_info_disconnected", "--get_phy_info", "--routing",
    "--sharp", "--phy_cable_disconnected", "--rail_validation",
)


@dataclass(frozen=True)
class CollectionPlan:
    kind: str
    run_id: str
    archive_name: str
    part_name: str
    ufm_source_path: str | None
    ufm_staging_path: str | None
    ufm_final_directory: str
    vendor_argv: tuple[str, ...]

    @property
    def ufm_remote_path(self) -> str:
        _validated_plan(self)
        return f"{self.ufm_final_directory}/{self.archive_name}"


def make_run_id(when: dt.datetime, environment: str, nonce: str | None = None) -> str:
    """Create one deployment-server ID; callers pass it unchanged to the UFM."""
    if not isinstance(when, dt.datetime) or when.tzinfo is None or when.utcoffset() is None:
        raise CollectionError("run-id time must be timezone-aware")
    if environment not in {"prod", "air"}:
        raise CollectionError("run-id environment is unsupported")
    if nonce is None:
        nonce = secrets.token_hex(8)
    if type(nonce) is not str or re.fullmatch(r"[0-9a-f]{16}", nonce) is None:
        raise CollectionError("run-id nonce must be 16 lowercase hex characters")
    return f"{when.astimezone(dt.timezone.utc):%Y%m%d-%H%M}-{environment}-{nonce}"


def _run_id(value: object) -> str:
    if type(value) is not str or (match := _RUN_ID_RE.fullmatch(value)) is None:
        raise CollectionError("invalid UFM collection run-id")
    try:
        dt.datetime.strptime(match.group(1), "%Y%m%d-%H%M")
    except ValueError as exc:
        raise CollectionError("invalid UFM collection run-id time") from exc
    return value


def collection_plan(kind: str, run_id: str) -> CollectionPlan:
    run_id = _run_id(run_id)
    if kind == "ibdiagnet":
        return CollectionPlan(
            kind, run_id, f"ibdiagnet2_{run_id}.tar.gz",
            f"ibdiagnet2_{run_id}.tar.gz.part", "/var/tmp/ibdiagnet2",
            "/opt/ufm/files", "/root/monitor/ibdiagnet", _IBDIAGNET_ARGV,
        )
    if kind == "iblinkinfo":
        return CollectionPlan(
            kind, run_id, f"iblinkinfo_{run_id}.tar.gz",
            f"iblinkinfo_{run_id}.tar.gz.part", None, None,
            "/root/monitor/iblinkinfo", ("/opt/ufm/opensm/sbin/iblinkinfo",),
        )
    raise CollectionError("unsupported UFM collection kind")


def _validated_plan(plan: CollectionPlan) -> CollectionPlan:
    if type(plan) is not CollectionPlan:
        raise CollectionError("invalid UFM collection plan")
    if plan != collection_plan(plan.kind, plan.run_id):
        raise CollectionError("UFM collection plan does not match canonical paths")
    return plan


def _absolute_path(path: Path, *, label: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts:
        raise CollectionError(f"{label} must be an absolute path without traversal")
    return path


def _no_follow_flags() -> tuple[int, int]:
    directory_flag = getattr(os, "O_DIRECTORY", None)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if (type(directory_flag) is not int or not directory_flag
            or type(nofollow) is not int or not nofollow):
        raise CollectionError("platform cannot enforce no-follow collection paths")
    return directory_flag, nofollow


def _require_fd_publication_support() -> None:
    dirfd_names = {item.__name__ for item in os.supports_dir_fd}
    fd_names = {item.__name__ for item in os.supports_fd}
    nofollow_names = {item.__name__ for item in os.supports_follow_symlinks}
    if (not {"open", "link", "unlink", "stat"}.issubset(dirfd_names)
            or "listdir" not in fd_names
            or not {"link", "stat"}.issubset(nofollow_names)):
        raise CollectionError("platform cannot enforce fd-relative publication")


def _no_follow_stat(path: Path, directory_flag: int, nofollow: int) -> os.stat_result:
    current = os.open("/", os.O_RDONLY | directory_flag)
    try:
        for part in path.parts[1:-1]:
            next_fd = os.open(part, os.O_RDONLY | directory_flag | nofollow,
                              dir_fd=current)
            os.close(current)
            current = next_fd
        leaf_fd = os.open(path.name, os.O_RDONLY | os.O_NONBLOCK | nofollow,
                          dir_fd=current)
        try:
            return os.fstat(leaf_fd)
        finally:
            os.close(leaf_fd)
    finally:
        os.close(current)


def _open_held_leaf(path: Path, leaf_flags: int) -> int:
    """Open an absolute leaf relative to a no-follow ancestor chain."""
    directory_flag, nofollow = _no_follow_flags()
    current = os.open("/", os.O_RDONLY | directory_flag)
    try:
        for part in path.parts[1:-1]:
            next_fd = os.open(part, os.O_RDONLY | directory_flag | nofollow,
                              dir_fd=current)
            os.close(current)
            current = next_fd
        return os.open(path.name, leaf_flags | nofollow, dir_fd=current)
    finally:
        os.close(current)


def _still_bound(path: Path, held: os.stat_result) -> bool:
    """A final pathname is usable only while it still names the held inode."""
    directory_flag, nofollow = _no_follow_flags()
    try:
        current = _no_follow_stat(path, directory_flag, nofollow)
    except OSError:
        return False
    return (current.st_dev, current.st_ino) == (held.st_dev, held.st_ino)


def _name_is_held_file(name: str, directory_fd: int, held_fd: int) -> bool:
    """Check the current name without following it before cleanup or handoff."""
    try:
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        held = os.fstat(held_fd)
    except FileNotFoundError:
        return False
    return (stat.S_ISREG(named.st_mode)
            and (named.st_dev, named.st_ino) == (held.st_dev, held.st_ino))


def _archive_held_source(archive: tarfile.TarFile, fd: int, name: str) -> int:
    """Archive only fd-opened regular files and directories, never path rebinding."""
    before = os.fstat(fd)
    info = tarfile.TarInfo(name)
    info.mode = stat.S_IMODE(before.st_mode)
    info.mtime = int(before.st_mtime)
    if stat.S_ISREG(before.st_mode):
        info.size = before.st_size
        with os.fdopen(os.dup(fd), "rb") as stream:
            archive.addfile(info, stream)
        count = int(before.st_size > 0)
    elif stat.S_ISDIR(before.st_mode):
        info.type = tarfile.DIRTYPE
        info.name = name.rstrip("/") + "/"
        archive.addfile(info)
        count = 0
        _, nofollow = _no_follow_flags()
        for child in sorted(os.listdir(fd)):
            if child in ("", ".", "..") or "/" in child or "\x00" in child:
                raise CollectionError("collection source has an unsafe member name")
            child_fd = os.open(child, os.O_RDONLY | os.O_NONBLOCK | nofollow,
                               dir_fd=fd)
            try:
                count += _archive_held_source(archive, child_fd, name + "/" + child)
            finally:
                os.close(child_fd)
    else:
        raise CollectionError("collection source contains an unsupported member")
    after = os.fstat(fd)
    if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
        raise CollectionError("collection source changed during archival")
    return count


def _fsync_directory(path: Path) -> None:
    directory_flag, nofollow = _no_follow_flags()
    fd = os.open(path, os.O_RDONLY | directory_flag | nofollow)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _verify_archive(fd: int) -> None:
    """Read every member before the final name becomes a completion signal."""
    nonempty_files = 0
    with os.fdopen(os.dup(fd), "rb") as stream, tarfile.open(
        fileobj=stream, mode="r:gz"
    ) as archive:
        for member in archive.getmembers():
            if member.name != "artifact" and not member.name.startswith("artifact/"):
                raise CollectionError("collection archive contains an unexpected path")
            if not (member.isfile() or member.isdir()):
                raise CollectionError("collection archive contains an unsupported member")
            if member.isfile():
                content = archive.extractfile(member)
                if content is None:
                    raise CollectionError("collection archive member cannot be read")
                size = 0
                with content:
                    while chunk := content.read(1024 * 1024):
                        size += len(chunk)
                if size != member.size:
                    raise CollectionError("collection archive member has wrong size")
                if size:
                    nonempty_files += 1
    if not nonempty_files:
        raise CollectionError("collection archive has no nonempty regular artifact")


def publish_local_archive(plan: CollectionPlan, source: Path, destination_dir: Path) -> Path:
    """Exercise an exact, no-overwrite local archive contract on staged input.

    This does not execute either vendor command, copy across the jump, or prove
    a live UFM filesystem is free of non-cooperating same-UID path races.
    """
    _validated_plan(plan)
    source = _absolute_path(source, label="collection source")
    destination_dir = _absolute_path(destination_dir, label="collection directory")
    _require_fd_publication_support()
    directory_flag, nofollow = _no_follow_flags()
    source_fd = None
    try:
        source_fd = _open_held_leaf(source, os.O_RDONLY | os.O_NONBLOCK)
        destination_fd = _open_held_leaf(destination_dir,
                                         os.O_RDONLY | directory_flag)
    except OSError as exc:
        if source_fd is not None:
            os.close(source_fd)
        raise CollectionError("collection source or destination is unavailable") from exc
    part_created = False
    final_created = False
    completed = False
    part_fd = None
    try:
        source_stat = os.fstat(source_fd)
        destination_stat = os.fstat(destination_fd)
        if not (stat.S_ISREG(source_stat.st_mode) or stat.S_ISDIR(source_stat.st_mode)):
            raise CollectionError("collection source must be a regular file or directory")
        if not stat.S_ISDIR(destination_stat.st_mode):
            raise CollectionError("collection destination must be a real directory")
        part_fd = os.open(plan.part_name,
                          os.O_RDWR | os.O_CREAT | os.O_EXCL | nofollow,
                          0o600, dir_fd=destination_fd)
        part_created = True
        with os.fdopen(os.dup(part_fd), "wb") as stream:
            with tarfile.open(fileobj=stream, mode="w:gz") as archive:
                nonempty_files = _archive_held_source(archive, source_fd, "artifact")
            stream.flush()
            os.fsync(stream.fileno())
        if not _name_is_held_file(plan.part_name, destination_fd, part_fd):
            raise CollectionError("collection part name was replaced")
        if nonempty_files == 0 or os.fstat(part_fd).st_size == 0:
            raise CollectionError("collection archive has no nonempty regular artifact")
        os.lseek(part_fd, 0, os.SEEK_SET)
        _verify_archive(part_fd)
        if not (_still_bound(source, source_stat)
                and _still_bound(destination_dir, destination_stat)):
            raise CollectionError("collection source or destination was rebound")
        if not _name_is_held_file(plan.part_name, destination_fd, part_fd):
            raise CollectionError("collection part name was replaced")
        try:
            os.link(plan.part_name, plan.archive_name,
                    src_dir_fd=destination_fd, dst_dir_fd=destination_fd,
                    follow_symlinks=False)
        except FileExistsError as exc:
            raise CollectionError("collection final name appeared before publication") from exc
        final_created = True
        if not (_name_is_held_file(plan.part_name, destination_fd, part_fd)
                and _name_is_held_file(plan.archive_name, destination_fd, part_fd)):
            raise CollectionError("collection published name does not match the held archive")
        os.fsync(destination_fd)
        if not (_name_is_held_file(plan.part_name, destination_fd, part_fd)
                and _name_is_held_file(plan.archive_name, destination_fd, part_fd)):
            raise CollectionError("collection published name was replaced")
        os.unlink(plan.part_name, dir_fd=destination_fd)
        part_created = False
        os.fsync(destination_fd)
        if not _name_is_held_file(plan.archive_name, destination_fd, part_fd):
            raise CollectionError("collection final name was replaced")
        if not (_still_bound(source, source_stat)
                and _still_bound(destination_dir, destination_stat)):
            raise CollectionError("collection source or destination was rebound")
        completed = True
        return destination_dir / plan.archive_name
    except (OSError, tarfile.TarError) as exc:
        raise CollectionError("collection archive publication failed") from exc
    finally:
        try:
            if part_created and part_fd is not None and _name_is_held_file(
                    plan.part_name, destination_fd, part_fd):
                try:
                    os.unlink(plan.part_name, dir_fd=destination_fd)
                except FileNotFoundError:
                    pass
            if final_created and not completed and part_fd is not None and _name_is_held_file(
                    plan.archive_name, destination_fd, part_fd):
                try:
                    os.unlink(plan.archive_name, dir_fd=destination_fd)
                    os.fsync(destination_fd)
                except FileNotFoundError:
                    pass
        finally:
            if part_fd is not None:
                os.close(part_fd)
            os.close(source_fd)
            os.close(destination_fd)


def project_copy_path(project: Path, plan: CollectionPlan, node: str) -> Path:
    project = _absolute_path(project, label="project root")
    _validated_plan(plan)
    if type(node) is not str or not _NODE_RE.fullmatch(node):
        raise CollectionError("invalid UFM collection node or plan")
    return project / "99-output-ufm" / "runs" / plan.run_id / node / plan.archive_name
