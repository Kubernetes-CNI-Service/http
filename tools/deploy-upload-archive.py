#!/usr/bin/env python3
"""Verify and safely apply one relayed HTTP ZTP upload archive on a server."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import selectors
import stat
import subprocess
import sys
import tarfile
import time
from typing import Iterator, Optional, Sequence


INSTALLER_MEMBER = "tools/deploy-upload-archive.py"
GUARD_MEMBER = "tools/deployment_prewrite_guard.py"
MANIFEST_MEMBER = "infra/docker/deployment-source-manifest.json"
CORE_INPUTS = (
    "01-global.yaml", "02-devices_config.csv", "02-dhcp-subnet_config.csv",
)
RESERVED_PROJECTS = frozenset({"template", "tests", "test_cases"})
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024 * 1024
MAX_MEMBER_BYTES = 8 * 1024 * 1024 * 1024
MAX_EXPANDED_BYTES = 64 * 1024 * 1024 * 1024
STAGING_RESERVE_BYTES = 64 * 1024 * 1024
NAMESPACE_MINIMUM_BYTES = 16 * 1024
INODE_RESERVE = 4096
MAX_MEMBER_COUNT = 200_000
MAX_AUTHORITY_BYTES = 16 * 1024 * 1024
MAX_GUARD_OUTPUT = 1024 * 1024
GUARD_TIMEOUT = 900
DOCKER_REBUILD_REQUIRED = b"HTTP_ZTP_DOCKER_REBUILD_REQUIRED"


class InstallError(RuntimeError):
    """The relayed archive cannot be authenticated or safely applied."""


@dataclass(frozen=True)
class MemberRecord:
    member: tarfile.TarInfo
    parts: tuple[str, ...]
    kind: str


@dataclass(frozen=True)
class Verification:
    archive_path: Path
    archive_size: int
    expanded_size: int
    archive_sha256: str
    source_manifest_sha256: str
    project: str
    guard_source: str
    members: tuple[MemberRecord, ...]


@dataclass(frozen=True)
class DeployResult:
    project: str
    runtime: str
    next_runtime: Optional[str]
    archive_size: int
    archive_sha256: str
    source_manifest_sha256: str
    guard_stdout: bytes = b""
    guard_stderr: bytes = b""


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description=(
            "Verify and safely apply one explicitly selected upload archive; "
            "never manually extract an upload tar into the live HTTP root."
        ),
    )
    result.add_argument("archive", type=Path, metavar="ARCHIVE")
    result.add_argument("--root", type=Path, default=Path("/var/www/html"))
    result.add_argument(
        "--runtime", choices=("native", "docker"), default="native",
    )
    result.add_argument("--verify-only", action="store_true")
    return result


def _absolute_unresolved(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _stable_fields(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev, value.st_ino, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    )


def _open_directory_nofollow(
    path: Path, label: str,
) -> tuple[int, os.stat_result]:
    path = _absolute_unresolved(path)
    flags = (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    success = False
    try:
        descriptor = os.open("/", flags)
        for component in path.parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        opened = os.fstat(descriptor)
        current = path.lstat()
        if (
            not stat.S_ISDIR(opened.st_mode)
            or not stat.S_ISDIR(current.st_mode)
            or opened.st_nlink < 2 or current.st_nlink < 2
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise InstallError(f"{label} is not one NOFOLLOW directory identity")
        success = True
        return descriptor, opened
    except InstallError:
        raise
    except OSError as exc:
        raise InstallError(f"cannot safely open {label}: {exc}") from exc
    finally:
        if descriptor >= 0 and not success:
            os.close(descriptor)


def _assert_open_directory_path(
    path: Path, descriptor: int, expected: os.stat_result, label: str,
    required_uid: int, *, exact_mode: Optional[int] = None,
) -> None:
    try:
        opened = os.fstat(descriptor)
        current = path.lstat()
    except OSError as exc:
        raise InstallError(f"{label} path changed or disappeared: {exc}") from exc
    if (
        not stat.S_ISDIR(opened.st_mode)
        or not stat.S_ISDIR(current.st_mode)
        or opened.st_nlink < 2 or current.st_nlink < 2
        or (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino)
        or (current.st_dev, current.st_ino) != (expected.st_dev, expected.st_ino)
        or opened.st_uid != required_uid or current.st_uid != required_uid
        or opened.st_mode & 0o022 or current.st_mode & 0o022
        or exact_mode is not None and (
            stat.S_IMODE(opened.st_mode) != exact_mode
            or stat.S_IMODE(current.st_mode) != exact_mode
        )
    ):
        raise InstallError(f"{label} identity or permissions changed")


def _make_private_staging(
    parent_descriptor: int, *, prefix: str, required_uid: int,
) -> tuple[str, int, os.stat_result]:
    flags = (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    for _attempt in range(128):
        name = prefix + secrets.token_hex(12)
        try:
            os.mkdir(name, 0o700, dir_fd=parent_descriptor)
        except FileExistsError:
            continue
        descriptor = -1
        try:
            descriptor = os.open(name, flags, dir_fd=parent_descriptor)
            opened = os.fstat(descriptor)
            named = os.stat(
                name, dir_fd=parent_descriptor, follow_symlinks=False,
            )
            if (
                not stat.S_ISDIR(opened.st_mode)
                or not stat.S_ISDIR(named.st_mode)
                or opened.st_nlink < 2 or named.st_nlink < 2
                or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
                or opened.st_uid != required_uid or named.st_uid != required_uid
                or stat.S_IMODE(opened.st_mode) != 0o700
                or stat.S_IMODE(named.st_mode) != 0o700
            ):
                raise InstallError("private staging identity is unsafe")
            return name, descriptor, opened
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.rmdir(name, dir_fd=parent_descriptor)
            except OSError:
                pass
            raise
    raise InstallError("cannot allocate one unique private staging directory")


def _clear_private_directory(descriptor: int) -> None:
    for name in os.listdir(descriptor):
        try:
            metadata = os.stat(
                name, dir_fd=descriptor, follow_symlinks=False,
            )
        except FileNotFoundError:
            continue
        if stat.S_ISDIR(metadata.st_mode):
            flags = (
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            child = os.open(name, flags, dir_fd=descriptor)
            try:
                opened = os.fstat(child)
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or (opened.st_dev, opened.st_ino)
                    != (metadata.st_dev, metadata.st_ino)
                ):
                    raise InstallError(
                        "private staging child identity changed during cleanup"
                    )
                _clear_private_directory(child)
                current = os.stat(
                    name, dir_fd=descriptor, follow_symlinks=False,
                )
                if (
                    not stat.S_ISDIR(current.st_mode)
                    or (current.st_dev, current.st_ino)
                    != (opened.st_dev, opened.st_ino)
                ):
                    raise InstallError(
                        "private staging child identity changed during cleanup"
                    )
            finally:
                os.close(child)
            os.rmdir(name, dir_fd=descriptor)
        else:
            os.unlink(name, dir_fd=descriptor)


def _remove_staging(
    parent_descriptor: int, staging_name: str, staging_descriptor: int,
    expected: os.stat_result,
) -> None:
    opened = os.fstat(staging_descriptor)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino)
        or opened.st_uid != expected.st_uid
    ):
        raise InstallError("private staging descriptor identity changed")
    _clear_private_directory(staging_descriptor)
    os.fsync(staging_descriptor)
    try:
        named = os.stat(
            staging_name, dir_fd=parent_descriptor, follow_symlinks=False,
        )
    except FileNotFoundError as exc:
        raise InstallError(
            "private staging identity changed; opened contents were cleared"
        ) from exc
    if (
        not stat.S_ISDIR(named.st_mode)
        or (named.st_dev, named.st_ino) != (expected.st_dev, expected.st_ino)
    ):
        raise InstallError(
            "private staging identity changed; replacement was not touched"
        )
    os.rmdir(staging_name, dir_fd=parent_descriptor)
    os.fsync(parent_descriptor)


@contextmanager
def _open_stable_regular(
    path: Path, label: str, *, required_uid: int, maximum_size: int,
) -> Iterator[tuple[int, os.stat_result]]:
    path = _absolute_unresolved(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        before_path = path.lstat()
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before_path.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or before_path.st_nlink != 1
            or opened.st_nlink != 1
            or (before_path.st_dev, before_path.st_ino)
            != (opened.st_dev, opened.st_ino)
            or opened.st_uid != required_uid
            or opened.st_mode & 0o022
            or opened.st_size <= 0
            or opened.st_size > maximum_size
        ):
            raise InstallError(
                f"{label} must be a bounded, owner-controlled, single-link regular file"
            )
        try:
            yield descriptor, opened
        finally:
            after = os.fstat(descriptor)
            current = path.lstat()
            if _stable_fields(after) != _stable_fields(opened):
                raise InstallError(f"{label} changed while being read")
            if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                raise InstallError(f"{label} path was replaced while being read")
    except InstallError:
        raise
    except OSError as exc:
        raise InstallError(f"cannot open or verify {label}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_descriptor(descriptor: int, size: int, label: str) -> bytes:
    if size > MAX_AUTHORITY_BYTES:
        raise InstallError(f"{label} is too large")
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        block = os.read(descriptor, min(remaining, 1024 * 1024))
        if not block:
            raise InstallError(f"{label} was truncated while reading")
        chunks.append(block)
        remaining -= len(block)
    if os.read(descriptor, 1):
        raise InstallError(f"{label} grew while reading")
    return b"".join(chunks)


def _hash_descriptor(descriptor: int, size: int, label: str) -> str:
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    remaining = size
    while remaining:
        block = os.read(descriptor, min(remaining, 4 * 1024 * 1024))
        if not block:
            raise InstallError(f"{label} was truncated while hashing")
        digest.update(block)
        remaining -= len(block)
    if os.read(descriptor, 1):
        raise InstallError(f"{label} grew while hashing")
    return digest.hexdigest()


def _member_parts(name: str) -> tuple[str, ...]:
    if not name or any(ord(character) < 32 or ord(character) == 127 for character in name):
        raise InstallError(f"archive member has an unsafe name: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or "\\" in name:
        raise InstallError(f"archive member path is unsafe: {name!r}")
    parts = tuple(part for part in path.parts if part not in {"", "."})
    if not parts or any(part in {".", ".."} for part in parts):
        raise InstallError(f"archive member path is empty or non-canonical: {name!r}")
    canonical = "/".join(parts)
    if name not in {canonical, "./" + canonical, canonical + "/", "./" + canonical + "/"}:
        raise InstallError(f"archive member path is non-canonical: {name!r}")
    return parts


def _validated_members(archive: tarfile.TarFile) -> tuple[MemberRecord, ...]:
    try:
        raw = archive.getmembers()
    except tarfile.TarError as exc:
        raise InstallError(f"cannot enumerate archive: {exc}") from exc
    if not raw or len(raw) > MAX_MEMBER_COUNT:
        raise InstallError("archive member count is unsafe")
    seen: dict[tuple[str, ...], str] = {}
    records: list[MemberRecord] = []
    expanded = 0
    for member in raw:
        parts = _member_parts(member.name)
        if parts in seen:
            raise InstallError(f"duplicate archive member: {member.name!r}")
        if member.mode < 0 or member.mode & ~0o777:
            raise InstallError(f"archive member mode is unsafe: {member.name!r}")
        if member.isdir():
            kind = "dir"
        elif member.isfile():
            kind = "file"
            if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                raise InstallError(f"archive member size is unsafe: {member.name!r}")
            expanded += member.size
            if expanded > MAX_EXPANDED_BYTES:
                raise InstallError("archive expanded size is unsafe")
        elif member.issym():
            kind = "symlink"
            target = PurePosixPath(member.linkname)
            if not member.linkname or target.is_absolute():
                raise InstallError(f"archive symlink target is unsafe: {member.name!r}")
        else:
            raise InstallError(f"archive member type is unsupported: {member.name!r}")
        seen[parts] = kind
        records.append(MemberRecord(member, parts, kind))
    for record in records:
        for length in range(1, len(record.parts)):
            parent_kind = seen.get(record.parts[:length])
            if parent_kind is not None and parent_kind != "dir":
                raise InstallError(
                    "archive member has a non-directory ancestor: "
                    + "/".join(record.parts[:length])
                )
    by_parts = {record.parts: record for record in records}
    for record in records:
        if record.kind == "symlink":
            _resolve_archive_target(record.parts, by_parts, set())
    return tuple(records)


def _resolve_archive_target(
    parts: tuple[str, ...], members: dict[tuple[str, ...], MemberRecord],
    visited: set[tuple[str, ...]],
) -> MemberRecord:
    if parts in visited:
        raise InstallError("archive symlink cycle is unsafe")
    record = members.get(parts)
    if record is None:
        raise InstallError("archive symlink target is missing")
    if record.kind in {"file", "dir"}:
        return record
    if record.kind != "symlink":
        raise InstallError("archive symlink target is not a supported member")
    target = PurePosixPath(record.member.linkname)
    target_parts = list(record.parts[:-1])
    for part in target.parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not target_parts:
                raise InstallError("archive symlink target escapes the archive root")
            target_parts.pop()
        else:
            target_parts.append(part)
    if not target_parts:
        raise InstallError("archive symlink target is unsafe")
    return _resolve_archive_target(tuple(target_parts), members, visited | {parts})


def _extract_bytes(
    archive: tarfile.TarFile, record: MemberRecord, label: str,
    *, maximum_size: int = MAX_AUTHORITY_BYTES, allow_empty: bool = False,
) -> bytes:
    if (
        record.kind != "file"
        or record.member.size < 0
        or (not allow_empty and record.member.size == 0)
        or record.member.size > maximum_size
    ):
        requirement = "bounded regular member" if allow_empty else "non-empty bounded regular member"
        raise InstallError(f"{label} must be one {requirement}")
    stream = archive.extractfile(record.member)
    if stream is None:
        raise InstallError(f"{label} is unreadable")
    try:
        payload = stream.read(record.member.size + 1)
    except (MemoryError, OverflowError) as exc:
        raise InstallError(f"cannot read {label} within the memory bound") from exc
    if len(payload) != record.member.size or len(payload) > maximum_size:
        raise InstallError(f"{label} changed or exceeds its bound")
    return payload


def _hash_member(
    archive: tarfile.TarFile, record: MemberRecord, label: str,
    *, maximum_size: int = MAX_MEMBER_BYTES, allow_empty: bool = False,
) -> str:
    """Hash one declared member without allocating its global size ceiling."""
    if (
        record.kind != "file"
        or record.member.size < 0
        or (not allow_empty and record.member.size == 0)
        or record.member.size > maximum_size
    ):
        requirement = "bounded regular member" if allow_empty else "non-empty bounded regular member"
        raise InstallError(f"{label} must be one {requirement}")
    stream = archive.extractfile(record.member)
    if stream is None:
        raise InstallError(f"{label} is unreadable")
    digest = hashlib.sha256()
    remaining = record.member.size
    try:
        while remaining:
            block = stream.read(min(remaining, 1024 * 1024))
            if not block:
                raise InstallError(f"{label} was truncated while hashing")
            if len(block) > remaining:
                raise InstallError(f"{label} exceeds its declared size")
            digest.update(block)
            remaining -= len(block)
        if stream.read(1):
            raise InstallError(f"{label} exceeds its declared size")
    except (MemoryError, OverflowError) as exc:
        raise InstallError(f"cannot hash {label} within the memory bound") from exc
    return digest.hexdigest()


def _manifest_records(payload: bytes) -> dict[str, dict]:
    try:
        value = json.loads(payload.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise InstallError(f"source manifest is invalid: {exc}") from exc
    if (
        not isinstance(value, dict) or set(value) != {"schema_version", "files"}
        or value.get("schema_version") != 1 or not isinstance(value.get("files"), list)
    ):
        raise InstallError("source manifest schema is invalid")
    result: dict[str, dict] = {}
    for record in value["files"]:
        if (
            not isinstance(record, dict)
            or set(record) != {"path", "type", "target", "sha256"}
            or not isinstance(record.get("path"), str)
            or record["path"] in result
            or record.get("type") not in {"file", "symlink"}
            or not isinstance(record.get("sha256"), str)
            or len(record["sha256"]) != 64
            or any(character not in "0123456789abcdef" for character in record["sha256"])
            or (record["type"] == "file" and record.get("target") is not None)
            or (record["type"] == "symlink" and not isinstance(record.get("target"), str))
        ):
            raise InstallError("source manifest contains an invalid or duplicate record")
        if "/".join(_member_parts(record["path"])) != record["path"]:
            raise InstallError("source manifest path is not canonical")
        result[record["path"]] = record
    return result


def _project_name(members: dict[tuple[str, ...], MemberRecord]) -> str:
    projects: list[str] = []
    for parts, record in members.items():
        if len(parts) != 3 or parts[0] != "DAY0-Prepare" or parts[1] in RESERVED_PROJECTS:
            continue
        if parts[2] == CORE_INPUTS[0] and record.kind == "file":
            project = parts[1]
            if all(
                ("DAY0-Prepare", project, name) in members
                and members[("DAY0-Prepare", project, name)].kind == "file"
                and members[("DAY0-Prepare", project, name)].member.size > 0
                for name in CORE_INPUTS
            ):
                projects.append(project)
    projects = sorted(set(projects))
    if len(projects) != 1:
        raise InstallError("archive must contain exactly one deployable DAY0 project")
    return projects[0]


def _inspect_open_archive(
    descriptor: int, archive_path: Path, archive_size: int,
    archive_sha256: str, installer_bytes: bytes,
) -> Verification:
    os.lseek(descriptor, 0, os.SEEK_SET)
    try:
        with os.fdopen(os.dup(descriptor), "rb") as stream, \
                tarfile.open(fileobj=stream, mode="r:gz") as archive:
            members = _validated_members(archive)
            by_parts = {record.parts: record for record in members}
            required = {
                INSTALLER_MEMBER: "installer", GUARD_MEMBER: "guard",
                MANIFEST_MEMBER: "source manifest",
            }
            extracted = {}
            for name, label in required.items():
                record = by_parts.get(tuple(name.split("/")))
                if record is None:
                    raise InstallError(f"archive is missing {label}")
                extracted[name] = _extract_bytes(archive, record, label)
            if extracted[INSTALLER_MEMBER] != installer_bytes:
                raise InstallError("running installer does not match archive installer")
            manifest_bytes = extracted[MANIFEST_MEMBER]
            manifest = _manifest_records(manifest_bytes)
            for authority in (INSTALLER_MEMBER, GUARD_MEMBER):
                matches = [record for path, record in manifest.items() if path == authority]
                if len(matches) != 1 or matches[0]["type"] != "file":
                    raise InstallError(f"source manifest does not bind exactly one {authority}")
                if hashlib.sha256(extracted[authority]).hexdigest() != matches[0]["sha256"]:
                    raise InstallError(f"source manifest hash mismatch for {authority}")
            for relative, expected in manifest.items():
                archived = by_parts.get(tuple(relative.split("/")))
                if archived is None or archived.kind != expected["type"]:
                    raise InstallError(f"source manifest member is missing or changed: {relative}")
                payload_record = archived
                if archived.kind == "symlink":
                    if archived.member.linkname != expected["target"]:
                        raise InstallError(f"source manifest symlink changed: {relative}")
                    payload_record = _resolve_archive_target(archived.parts, by_parts, set())
                digest = _hash_member(
                    archive, payload_record, f"source manifest member {relative}",
                    maximum_size=MAX_MEMBER_BYTES, allow_empty=True,
                )
                if digest != expected["sha256"]:
                    raise InstallError(f"source manifest member hash mismatch: {relative}")
            try:
                guard_source = extracted[GUARD_MEMBER].decode("utf-8")
            except UnicodeError as exc:
                raise InstallError(f"embedded guard is not UTF-8: {exc}") from exc
            project = _project_name(by_parts)
    except InstallError:
        raise
    except (OSError, tarfile.TarError) as exc:
        raise InstallError(f"archive is unreadable: {exc}") from exc
    return Verification(
        archive_path=archive_path, archive_size=archive_size,
        expanded_size=sum(
            record.member.size for record in members if record.kind == "file"
        ),
        archive_sha256=archive_sha256,
        source_manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        project=project, guard_source=guard_source, members=members,
    )


@contextmanager
def _verified_open_inputs(
    archive_path: Path, installer_path: Path, *, required_uid: int,
) -> Iterator[tuple[Verification, int, os.stat_result]]:
    with _open_stable_regular(
        installer_path, "installer", required_uid=required_uid,
        maximum_size=MAX_AUTHORITY_BYTES,
    ) as (installer_fd, installer_stat):
        installer_bytes = _read_descriptor(
            installer_fd, installer_stat.st_size, "installer",
        )
        with _open_stable_regular(
            archive_path, "upload archive", required_uid=required_uid,
            maximum_size=MAX_ARCHIVE_BYTES,
        ) as (archive_fd, archive_stat):
            archive_digest = _hash_descriptor(
                archive_fd, archive_stat.st_size, "upload archive",
            )
            verified = _inspect_open_archive(
                archive_fd, _absolute_unresolved(archive_path),
                archive_stat.st_size, archive_digest, installer_bytes,
            )
            yield verified, archive_fd, archive_stat


def verify_inputs(
    archive_path: Path, installer_path: Path, *, required_uid: int = 0,
) -> Verification:
    with _verified_open_inputs(
        archive_path, installer_path, required_uid=required_uid,
    ) as (verified, _descriptor, _status):
        return verified


def _preflight_live_root(
    root: Path, members: tuple[MemberRecord, ...],
) -> os.stat_result:
    root = _absolute_unresolved(root)
    if not root.is_absolute():
        raise InstallError("deployment root must be absolute")
    try:
        root_status = root.lstat()
        if not stat.S_ISDIR(root_status.st_mode) or root.resolve(strict=True) != root:
            raise InstallError("deployment root must be one canonical real directory")
    except (OSError, RuntimeError) as exc:
        raise InstallError(f"deployment root is unsafe: {exc}") from exc
    for record in members:
        for length in range(1, len(record.parts)):
            ancestor = root.joinpath(*record.parts[:length])
            try:
                metadata = ancestor.lstat()
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise InstallError(f"cannot inspect live ancestor {ancestor}: {exc}") from exc
            if not stat.S_ISDIR(metadata.st_mode):
                raise InstallError(f"live ancestor is not a real directory: {ancestor}")
        destination = root.joinpath(*record.parts)
        try:
            metadata = destination.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise InstallError(f"cannot inspect live destination {destination}: {exc}") from exc
        if record.kind == "dir":
            if not stat.S_ISDIR(metadata.st_mode):
                raise InstallError(f"incoming directory conflicts with live path: {destination}")
        elif metadata.st_nlink != 1 or not (
            stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
        ):
            raise InstallError(f"incoming file conflicts with unsafe live path: {destination}")
    try:
        current = root.lstat()
    except OSError as exc:
        raise InstallError(f"deployment root changed during preflight: {exc}") from exc
    if (
        not stat.S_ISDIR(current.st_mode)
        or (current.st_dev, current.st_ino)
        != (root_status.st_dev, root_status.st_ino)
    ):
        raise InstallError("deployment root changed during preflight")
    return root_status


def guard_argv(
    verified: Verification, archive_fd: int, root: Path, runtime: str,
    *, python_executable: str = "/usr/bin/python3",
) -> list[str]:
    return [
        python_executable, "-c", verified.guard_source,
        "--lock", os.fspath(root / ".deployment.lock"),
        "--root", os.fspath(root), "--runtime", runtime,
        "--archive-fd", str(archive_fd),
        "--archive-sha256", verified.archive_sha256,
        "--source-manifest-sha256", verified.source_manifest_sha256,
    ]


def _guard_archive_fd(
    command: Sequence[str], explicit_fd: Optional[int],
) -> Optional[int]:
    declared = []
    for index, argument in enumerate(command):
        if argument == "--archive-fd":
            if index + 1 >= len(command):
                raise InstallError("embedded guard --archive-fd is missing its value")
            declared.append(command[index + 1])
        elif isinstance(argument, str) and argument.startswith("--archive-fd="):
            declared.append(argument.partition("=")[2])
    if len(declared) > 1:
        raise InstallError("embedded guard declares more than one archive descriptor")
    declared_fd = None
    if declared:
        raw = declared[0]
        if (
            not isinstance(raw, str)
            or not raw
            or any(character < "0" or character > "9" for character in raw)
        ):
            raise InstallError("embedded guard --archive-fd is invalid")
        declared_fd = int(raw)
    if explicit_fd is not None and (
        isinstance(explicit_fd, bool)
        or not isinstance(explicit_fd, int)
        or explicit_fd < 0
    ):
        raise InstallError("embedded guard archive descriptor is invalid")
    if (
        declared_fd is not None
        and explicit_fd is not None
        and declared_fd != explicit_fd
    ):
        raise InstallError(
            "embedded guard declared archive descriptor does not match "
            "the inherited descriptor"
        )
    return explicit_fd if explicit_fd is not None else declared_fd


def run_guard(
    command: Sequence[str], *, timeout: int = GUARD_TIMEOUT,
    env: Optional[dict[str, str]] = None,
    archive_fd: Optional[int] = None,
):
    argv = list(command)
    inherited_fd = _guard_archive_fd(argv, archive_fd)
    pass_fds = () if inherited_fd is None else (inherited_fd,)
    try:
        process = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            shell=False, bufsize=0, env=env, pass_fds=pass_fds,
        )
    except OSError as exc:
        raise InstallError(f"cannot start embedded deployment guard: {exc}") from exc
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.kill()
                process.wait()
                raise InstallError("embedded deployment guard timed out")
            events = selector.select(min(remaining, 0.25))
            if not events and process.poll() is not None:
                events = [(key, selectors.EVENT_READ) for key in selector.get_map().values()]
            for key, _mask in events:
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                bucket = captured[key.data]
                bucket.extend(chunk)
                if len(bucket) > MAX_GUARD_OUTPUT:
                    process.kill()
                    process.wait()
                    raise InstallError(f"embedded deployment guard {key.data} exceeded its bound")
        returncode = process.wait(timeout=max(0.0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.wait()
        raise InstallError("embedded deployment guard timed out") from exc
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    return subprocess.CompletedProcess(
        argv, returncode, bytes(captured["stdout"]), bytes(captured["stderr"]),
    )


@contextmanager
def _private_archive_snapshot(
    descriptor: int, verified: Verification, *, staging_parent: Optional[Path],
    live_root: Path, live_root_status: os.stat_result, required_uid: int,
) -> Iterator[int]:
    parent = _absolute_unresolved(staging_parent or live_root)
    parent_descriptor, parent_status = _open_directory_nofollow(
        parent, "private staging parent",
    )
    if (
        parent_status.st_dev != live_root_status.st_dev
        or parent_status.st_uid != required_uid
        or parent_status.st_mode & 0o022
        or parent_status.st_nlink < 2
    ):
        os.close(parent_descriptor)
        raise InstallError(
            "private staging must be an owner-controlled real directory "
            "on the live filesystem"
        )
    try:
        filesystem = os.fstatvfs(parent_descriptor)
    except OSError as exc:
        os.close(parent_descriptor)
        raise InstallError(f"cannot inspect private staging capacity: {exc}") from exc
    available_blocks = getattr(filesystem, "f_bavail", None)
    fragment_size = getattr(filesystem, "f_frsize", None)
    total_inodes = getattr(filesystem, "f_files", None)
    available_inodes = getattr(filesystem, "f_favail", None)
    if (
        any(type(value) is not int for value in (
            available_blocks, fragment_size, total_inodes, available_inodes,
        ))
        or available_blocks < 0
        or fragment_size <= 0
        or total_inodes < 0
        or available_inodes < 0
        or (total_inodes == 0 and available_inodes != 0)
        or (total_inodes > 0 and available_inodes > total_inodes)
    ):
        os.close(parent_descriptor)
        raise InstallError("private staging capacity metadata is unsafe")
    available_bytes = available_blocks * fragment_size
    required_bytes = (
        ((verified.archive_size + fragment_size - 1) // fragment_size) * fragment_size
        + 2 * max(fragment_size, NAMESPACE_MINIMUM_BYTES)
        + STAGING_RESERVE_BYTES
    )
    if available_bytes < required_bytes:
        os.close(parent_descriptor)
        raise InstallError(
            "private staging filesystem lacks space for the compressed snapshot "
            "and its namespace reserve"
        )
    required_inodes = 2 + INODE_RESERVE
    if total_inodes == 0 and available_inodes == 0:
        print(
            "[INFO] private staging inode budget skipped: filesystem reports "
            "unreported/dynamic inode limits (f_files=0, f_favail=0)",
            flush=True,
        )
    elif available_inodes < required_inodes:
        os.close(parent_descriptor)
        raise InstallError(
            "private staging filesystem lacks inodes: "
            f"required={required_inodes} available={available_inodes}"
        )
    staging_descriptor = -1
    output = -1
    staging_name = ""
    staging_status: Optional[os.stat_result] = None
    try:
        staging_name, staging_descriptor, staging_status = _make_private_staging(
            parent_descriptor, prefix="http-upload-archive.",
            required_uid=required_uid,
        )
        directory = parent / staging_name
        destination = directory / "upload.tar.gz"
        _assert_open_directory_path(
            parent, parent_descriptor, parent_status,
            "private staging parent", required_uid,
        )
        _assert_open_directory_path(
            directory, staging_descriptor, staging_status,
            "private staging", required_uid, exact_mode=0o700,
        )
        output = os.open(
            "upload.tar.gz",
            os.O_RDWR | os.O_CREAT | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            0o600, dir_fd=staging_descriptor,
        )
        os.lseek(descriptor, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        remaining = verified.archive_size
        while remaining:
            block = os.read(descriptor, min(remaining, 4 * 1024 * 1024))
            if not block:
                raise InstallError("upload archive was truncated while staging")
            view = memoryview(block)
            while view:
                written = os.write(output, view)
                if written <= 0:
                    raise InstallError("short write while staging upload archive")
                view = view[written:]
            digest.update(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise InstallError("upload archive grew while staging")
        os.fchmod(output, 0o600)
        os.fsync(output)
        opened = os.fstat(output)
        named = os.stat(
            "upload.tar.gz", dir_fd=staging_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(named.st_mode)
            or opened.st_nlink != 1 or named.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
            or opened.st_uid != required_uid or named.st_uid != required_uid
            or stat.S_IMODE(opened.st_mode) != 0o600
            or stat.S_IMODE(named.st_mode) != 0o600
            or opened.st_size != verified.archive_size
            or named.st_size != verified.archive_size
        ):
            raise InstallError("private archive snapshot identity is unsafe")
        if digest.hexdigest() != verified.archive_sha256:
            raise InstallError("private archive snapshot digest mismatch")
        os.fsync(staging_descriptor)
        _assert_open_directory_path(
            parent, parent_descriptor, parent_status,
            "private staging parent", required_uid,
        )
        _assert_open_directory_path(
            directory, staging_descriptor, staging_status,
            "private staging", required_uid, exact_mode=0o700,
        )
        # This is an intentional digest-bound trust transfer from the original
        # upload fd to one private snapshot fd.  Snapshot-copy admission is a
        # wrapper-only concern; expansion and live-copy admission belong to the
        # embedded guard.
        os.lseek(output, 0, os.SEEK_SET)
        yield output
        after_guard = os.fstat(output)
        named_after_guard = os.stat(
            "upload.tar.gz", dir_fd=staging_descriptor,
            follow_symlinks=False,
        )
        if (
            _stable_fields(after_guard) != _stable_fields(opened)
            or (named_after_guard.st_dev, named_after_guard.st_ino)
            != (opened.st_dev, opened.st_ino)
            or named_after_guard.st_nlink != 1
            or stat.S_IMODE(named_after_guard.st_mode) != 0o600
            or _hash_descriptor(
                output, verified.archive_size, "private archive snapshot",
            ) != verified.archive_sha256
        ):
            raise InstallError("private archive snapshot changed during guard execution")
    except InstallError:
        raise
    except OSError as exc:
        raise InstallError(
            f"cannot allocate or validate private archive snapshot: {exc}"
        ) from exc
    finally:
        if output >= 0:
            os.close(output)
        validation_error = None
        cleanup_error = None
        if staging_descriptor >= 0 and staging_status is not None:
            directory = parent / staging_name
            try:
                _assert_open_directory_path(
                    parent, parent_descriptor, parent_status,
                    "private staging parent", required_uid,
                )
                _assert_open_directory_path(
                    directory, staging_descriptor, staging_status,
                    "private staging", required_uid, exact_mode=0o700,
                )
            except BaseException as exc:
                validation_error = exc
            try:
                _remove_staging(
                    parent_descriptor, staging_name, staging_descriptor,
                    staging_status,
                )
            except BaseException as exc:
                cleanup_error = exc
            os.close(staging_descriptor)
        os.close(parent_descriptor)
        if cleanup_error is not None:
            raise cleanup_error
        if validation_error is not None:
            raise validation_error


def deploy_archive(
    archive: Path, *, root: Path, runtime: str, verify_only: bool,
    installer_path: Optional[Path] = None, required_uid: int = 0,
    python_executable: str = "/usr/bin/python3",
    staging_parent: Optional[Path] = None,
    guard_environment: Optional[dict[str, str]] = None,
) -> DeployResult:
    if runtime not in {"native", "docker"}:
        raise InstallError(f"unsupported runtime: {runtime}")
    if installer_path is None:
        installer_path = Path(os.path.abspath(__file__))
    root = _absolute_unresolved(root)
    with _verified_open_inputs(
        archive, installer_path, required_uid=required_uid,
    ) as (verified, archive_fd, _archive_status):
        live_root_status = _preflight_live_root(root, verified.members)
        if verify_only:
            return DeployResult(
                verified.project, runtime, None,
                verified.archive_size,
                verified.archive_sha256, verified.source_manifest_sha256,
            )
        with _private_archive_snapshot(
            archive_fd, verified, staging_parent=staging_parent,
            live_root=root, live_root_status=live_root_status,
            required_uid=required_uid,
        ) as snapshot_fd:
            completed = run_guard(
                guard_argv(
                    verified, snapshot_fd, root, runtime,
                    python_executable=python_executable,
                ),
                env=guard_environment,
                archive_fd=snapshot_fd,
            )
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).decode(
                "utf-8", errors="replace",
            ).strip()
            raise InstallError(
                f"embedded deployment guard failed (exit={completed.returncode})"
                + (f": {detail}" if detail else "")
            )
        next_runtime = (
            "docker" if runtime == "docker"
            or DOCKER_REBUILD_REQUIRED in completed.stdout else "native"
        )
        return DeployResult(
            verified.project, runtime, next_runtime,
            verified.archive_size,
            verified.archive_sha256, verified.source_manifest_sha256,
            completed.stdout, completed.stderr,
        )


def next_commands(result: DeployResult, root: Path) -> tuple[str, str]:
    root_text = os.fspath(root)
    if result.next_runtime == "docker":
        return (f"cd {root_text}", "sudo ./infra/docker/deploy.sh deploy")
    return (
        f"cd {root_text}",
        "sudo python3 DAY0-Prepare/11-load.py "
        f"DAY0-Prepare/{result.project}",
    )


def _replay(label: str, payload: bytes, stream) -> None:
    if not payload:
        return
    text = payload.decode("utf-8", errors="replace").rstrip("\n")
    if text:
        print(f"[{label}]", file=stream)
        print(text, file=stream)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parser().parse_args(argv)
    if os.geteuid() != 0:
        print("[ERROR] run deploy-upload-archive.py as root", file=sys.stderr)
        return 1
    try:
        result = deploy_archive(
            args.archive, root=args.root, runtime=args.runtime,
            verify_only=args.verify_only,
        )
        print(f"[OK] archive: {_absolute_unresolved(args.archive)}")
        print(f"[OK] archive bytes: {result.archive_size}")
        print(f"[OK] archive SHA-256: {result.archive_sha256}")
        print(f"[OK] source manifest SHA-256: {result.source_manifest_sha256}")
        print("[OK] installer and embedded guard match the source manifest")
        print(f"[OK] project: {result.project}")
        print(f"[OK] requested runtime: {result.runtime}")
        if args.verify_only:
            print("[OK] verify-only completed; no lock, quiesce, or live write occurred")
            return 0
        _replay("GUARD STDOUT", result.guard_stdout, sys.stdout)
        _replay("GUARD STDERR", result.guard_stderr, sys.stderr)
        print(f"[OK] source overlay completed; next runtime: {result.next_runtime}")
        print("[NEXT] Run these commands; this installer does not execute them:")
        for command in next_commands(result, _absolute_unresolved(args.root)):
            print(f"       {command}")
        return 0
    except (InstallError, OSError, tarfile.TarError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
