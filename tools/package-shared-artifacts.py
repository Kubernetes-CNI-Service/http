#!/usr/bin/env python3
"""Build one independent, project-derived shared-artifact transport bundle.

The bundle intentionally contains only large/runtime payloads which are not
part of either the generic Docker image or a project upload release.  Switch
images are derived with the production ``11-load.py`` parser; offline APT
repositories and firmware are included only when explicitly selected.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
from dataclasses import dataclass
from datetime import datetime
import errno
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
import tempfile
from types import ModuleType, SimpleNamespace
from typing import Iterator, Optional, Sequence


ROOT = Path(__file__).resolve().parents[1]
DAY0 = ROOT / "DAY0-Prepare"
LOAD_SCRIPT = DAY0 / "11-load.py"
UPLOAD_SCRIPT = ROOT / "tools/tar-for-upload.py"
INSTALLER = ROOT / "tools/deploy-shared-artifacts.py"
DEFAULT_MINI = "04-air-mini-devices.txt"
ARCHIVE_NAME = "shared-artifacts.tar.gz"
INSTALLER_NAME = "deploy-shared-artifacts.py"
METADATA_NAME = "artifact-metadata.json"
SUMS_NAME = "SHA256SUMS"
MAX_CONTROL_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024 * 1024
MAX_MEMBER_BYTES = 16 * 1024 * 1024 * 1024
MAX_ARTIFACT_BYTES = MAX_MEMBER_BYTES
MAX_EXPANDED_BYTES = 64 * 1024 * 1024 * 1024
MAX_MEMBER_COUNT = 10_000
MAX_MEMBER_NAME_BYTES = 1024
MAX_PAX_BYTES = 16 * 1024
VALID_APPS_PLATFORMS = frozenset({
    "ubuntu-22.04/amd64", "ubuntu-22.04/arm64",
    "ubuntu-24.04/amd64", "ubuntu-24.04/arm64",
})
REQUIRED_OFFLINE_PACKAGES = frozenset({
    "wget", "lldpd", "tzdata", "ipmitool", "sshpass", "docker.io",
    "unzip", "nfs-common", "arping", "python3", "python3-yaml",
    "python3-jinja2", "python3-openpyxl", "python3-pandas",
    "python3-xlsxwriter", "openssh-client", "curl", "apache2",
    "ssl-cert", "isc-dhcp-server", "jq",
})
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class PackageError(RuntimeError):
    """The requested bundle cannot be derived or safely frozen."""


@dataclass(frozen=True)
class FileIdentity:
    path: Path
    device: int
    inode: int
    size: int
    mtime_ns: int
    ctime_ns: int
    nlink: int
    sha256: str


@dataclass(frozen=True)
class Artifact:
    source: Path
    target: str
    kind: str
    size: int
    sha256: str
    mode: int = 0o644
    consumers: tuple[tuple[str, str], ...] = ()
    platform: Optional[str] = None
    source_nlink: int = 1

    def metadata_record(self) -> dict[str, object]:
        return {
            "consumers": [
                {"family": family, "version": version}
                for family, version in self.consumers
            ],
            "kind": self.kind,
            "mode": self.mode,
            "platform": self.platform,
            "sha256": self.sha256,
            "size": self.size,
            "source": self.target,
            "target": self.target,
        }


@dataclass(frozen=True)
class PackageResult:
    created: bool
    output: Path
    archive: Path
    installer: Path
    metadata: Path
    sums: Path
    artifacts: tuple[Artifact, ...]


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description=(
            "Derive exact switch images from a DAY0 project and package only "
            "explicitly required shared payloads."
        ),
        allow_abbrev=False,
    )
    result.add_argument("project", metavar="PROJECT")
    result.add_argument(
        "--deployment-scope", choices=("all", "prod", "air"), default="all",
    )
    result.add_argument(
        "--switch", dest="switch_scope", choices=("all", "eth", "ib", "nvl"),
    )
    result.add_argument(
        "--mini", nargs="?", const=DEFAULT_MINI, metavar="DEVICES.txt",
        help="select AIR/eth and bind the project mini-device list",
    )
    result.add_argument(
        "--no-upgrade", action="store_true",
        help="do not require or package any switch software image",
    )
    result.add_argument(
        "--apps-platform", action="append", default=[],
        choices=tuple(sorted(VALID_APPS_PLATFORMS)),
        help="explicit offline APT repository to include; repeat as needed",
    )
    result.add_argument(
        "--firmware", action="append", default=[], type=Path, metavar="FILE",
        help="explicit file below firmware/ to include; repeat as needed",
    )
    result.add_argument("--output", type=Path, metavar="DIRECTORY")
    return result


def _absolute_unresolved(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _stable_fields(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev, value.st_ino, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    )


@contextmanager
def _open_stable_regular(
    path: Path, label: str, *, allow_empty: bool = False,
    maximum_size: int = MAX_ARTIFACT_BYTES, expected_nlink: int = 1,
) -> Iterator[tuple[int, os.stat_result]]:
    path = _absolute_unresolved(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        before = path.lstat()
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or before.st_nlink != expected_nlink
            or opened.st_nlink != expected_nlink
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            link_label = "single-link" if expected_nlink == 1 else f"exactly {expected_nlink}-link"
            raise PackageError(f"{label} must be one NOFOLLOW {link_label} regular file")
        if opened.st_mode & 0o022:
            raise PackageError(f"{label} must not be group/world writable")
        if (not allow_empty and opened.st_size == 0) or opened.st_size > maximum_size:
            raise PackageError(f"{label} has an unsafe size: {opened.st_size}")
        yield descriptor, opened
        after = os.fstat(descriptor)
        current = path.lstat()
        if _stable_fields(after) != _stable_fields(opened):
            raise PackageError(f"{label} changed while being read")
        if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
            raise PackageError(f"{label} path changed while being read")
        if current.st_nlink != expected_nlink:
            raise PackageError(f"{label} hardlink identity changed while being read")
    except PackageError:
        raise
    except OSError as exc:
        raise PackageError(f"cannot safely open {label}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _hash_descriptor(descriptor: int, size: int, label: str) -> str:
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    remaining = size
    while remaining:
        block = os.read(descriptor, min(remaining, 4 * 1024 * 1024))
        if not block:
            raise PackageError(f"{label} was truncated while hashing")
        digest.update(block)
        remaining -= len(block)
    if os.read(descriptor, 1):
        raise PackageError(f"{label} grew while hashing")
    return digest.hexdigest()


def _identity(
    path: Path, label: str, *, allow_empty: bool = False,
    maximum_size: int = MAX_ARTIFACT_BYTES, expected_nlink: int = 1,
) -> FileIdentity:
    absolute = _absolute_unresolved(path)
    with _open_stable_regular(
        absolute, label, allow_empty=allow_empty, maximum_size=maximum_size,
        expected_nlink=expected_nlink,
    ) as (descriptor, metadata):
        digest = _hash_descriptor(descriptor, metadata.st_size, label)
    return FileIdentity(
        absolute, metadata.st_dev, metadata.st_ino, metadata.st_size,
        metadata.st_mtime_ns, metadata.st_ctime_ns, metadata.st_nlink, digest,
    )


def _assert_identity(identity: FileIdentity, label: str) -> None:
    current = _identity(
        identity.path, label, allow_empty=identity.size == 0,
        maximum_size=max(identity.size, 1), expected_nlink=identity.nlink,
    )
    if current != identity:
        raise PackageError(f"{label} changed after artifact selection")


def _read_small(
    path: Path, label: str, *, allow_empty: bool = False,
    expected_nlink: int = 1,
) -> bytes:
    with _open_stable_regular(
        path, label, allow_empty=allow_empty, maximum_size=MAX_CONTROL_BYTES,
        expected_nlink=expected_nlink,
    ) as (descriptor, metadata):
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            block = os.read(descriptor, min(remaining, 1024 * 1024))
            if not block:
                raise PackageError(f"{label} was truncated while reading")
            chunks.append(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise PackageError(f"{label} grew while reading")
        return b"".join(chunks)


def _copy_input_snapshot(source: Path, destination: Path, label: str) -> FileIdentity:
    identity = _identity(source, label, maximum_size=MAX_CONTROL_BYTES)
    destination.parent.mkdir(parents=True, exist_ok=True)
    flags = (
        os.O_WRONLY | os.O_CREAT | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    output = os.open(destination, flags, 0o600)
    try:
        with _open_stable_regular(
            source, label, maximum_size=MAX_CONTROL_BYTES,
        ) as (descriptor, metadata):
            if _stable_fields(metadata) != (
                identity.device, identity.inode, identity.size,
                identity.mtime_ns, identity.ctime_ns,
            ):
                raise PackageError(f"{label} changed before snapshot")
            os.lseek(descriptor, 0, os.SEEK_SET)
            remaining = metadata.st_size
            while remaining:
                block = os.read(descriptor, min(remaining, 1024 * 1024))
                if not block:
                    raise PackageError(f"{label} was truncated while snapshotting")
                view = memoryview(block)
                while view:
                    written = os.write(output, view)
                    if written <= 0:
                        raise PackageError(f"short write while snapshotting {label}")
                    view = view[written:]
                remaining -= len(block)
            os.fsync(output)
    finally:
        os.close(output)
    if _identity(destination, f"private snapshot of {label}").sha256 != identity.sha256:
        raise PackageError(f"private snapshot digest mismatch for {label}")
    return identity


def _load_script(path: Path) -> ModuleType:
    path = _absolute_unresolved(path)
    if not path.is_file():
        raise PackageError(f"production parser is missing: {path}")
    name = "http_ztp_shared_artifact_" + path.name.replace("-", "_").replace(".", "_")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise PackageError(f"cannot load production parser: {path}")
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException as exc:
        raise PackageError(f"cannot load production parser: {exc}") from exc
    finally:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
    return module


def resolve_project(value: str | Path, *, repository_root: Path = ROOT) -> Path:
    try:
        root = _absolute_unresolved(repository_root).resolve(strict=True)
    except OSError as exc:
        raise PackageError(f"repository root is missing or unsafe: {exc}") from exc
    day0 = root / "DAY0-Prepare"
    raw = Path(value)
    if raw.is_absolute():
        candidate = _absolute_unresolved(raw)
    elif len(raw.parts) == 1:
        candidate = day0 / raw
    else:
        candidate = _absolute_unresolved(root / raw)
    if candidate.parent != day0 or candidate.name in {"", ".", "template", "tests", "test_cases"}:
        raise PackageError("PROJECT must name one direct deployment directory below DAY0-Prepare")
    try:
        metadata = candidate.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or candidate.resolve(strict=True) != candidate:
            raise PackageError("PROJECT must be one canonical real directory")
    except OSError as exc:
        raise PackageError(f"deployment project does not exist or is unsafe: {candidate}: {exc}") from exc
    return candidate


def _safe_relative(value: str, label: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if (
        not value or path.is_absolute() or "\\" in value
        or any(part in {"", ".", ".."} for part in path.parts)
        or "/".join(path.parts) != value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise PackageError(f"{label} is not a safe relative path: {value!r}")
    return path


def _require_real_directory(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise PackageError(f"{label} is missing or unreadable: {exc}") from exc
    if not stat.S_ISDIR(metadata.st_mode) or path.resolve(strict=True) != path:
        raise PackageError(f"{label} must be one canonical real directory")


def _reject_symlink_ancestors(path: Path, allowed_root: Path, label: str) -> None:
    try:
        relative = path.relative_to(allowed_root)
    except ValueError as exc:
        raise PackageError(f"{label} escapes its allowed source root") from exc
    _require_real_directory(allowed_root, f"{label} source root")
    current = allowed_root
    for part in relative.parts[:-1]:
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise PackageError(f"cannot inspect {label} ancestor {current}: {exc}") from exc
        if not stat.S_ISDIR(metadata.st_mode):
            raise PackageError(f"{label} ancestor must not be a symlink: {current}")


def _artifact(
    source: Path, target: str, kind: str, *,
    consumers: tuple[tuple[str, str], ...] = (),
    platform: Optional[str] = None, source_nlink: int = 1,
) -> Artifact:
    _safe_relative(target, "artifact target")
    identity = _identity(
        source, f"artifact {target}", expected_nlink=source_nlink,
    )
    return Artifact(
        source=identity.path, target=target, kind=kind, size=identity.size,
        sha256=identity.sha256, consumers=tuple(sorted(set(consumers))),
        platform=platform, source_nlink=source_nlink,
    )


def _select_image(
    load: ModuleType, project: Path, repository_root: Path,
    family: str, expected_name: str, version: str,
) -> Artifact:
    candidate_names = tuple(load._image_filename_candidates(expected_name))
    found: list[tuple[int, int, Path, FileIdentity]] = []
    for name_index, candidate in enumerate(candidate_names):
        for root_index, root in enumerate((repository_root / "image", project)):
            if os.path.lexists(root):
                _require_real_directory(root, f"{family} image source root")
            path = root / candidate
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise PackageError(f"cannot inspect {family} image candidate {path}: {exc}") from exc
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise PackageError(
                    f"{family} image candidate must be a NOFOLLOW single-link regular file: {path}"
                )
            if metadata.st_size == 0:
                continue
            identity = _identity(path, f"{family} image {candidate}")
            try:
                load.validate_image(path, candidate)
            except Exception as exc:
                raise PackageError(str(exc)) from exc
            # The production validator supplies the file-name/version policy.
            # Repeat only its byte-header assertion on our held NOFOLLOW FD so
            # a pathname race cannot make a different inode satisfy it.
            with _open_stable_regular(
                path, f"{family} image {candidate}",
            ) as (descriptor, opened):
                if opened.st_size != identity.size:
                    raise PackageError(f"{family} image changed during validation: {path}")
                if os.read(descriptor, 9) != b"#!/bin/sh":
                    raise PackageError(
                        f"invalid self-extracting image header for {family}: {path}"
                    )
            _assert_identity(identity, f"{family} image {candidate}")
            found.append((name_index, root_index, path, identity))
    if not found:
        aliases = " or ".join(candidate_names)
        raise PackageError(
            f"missing {family} switch image ({aliases}) in {repository_root / 'image'} or {project}"
        )
    fingerprints = {(item.size, item.sha256) for *_prefix, item in found}
    if len(fingerprints) != 1:
        paths = ", ".join(os.fspath(item[2]) for item in found)
        raise PackageError(f"{family} image aliases have different content: {paths}")
    _name_index, _root_index, selected, identity = min(found, key=lambda item: (item[0], item[1]))
    return Artifact(
        source=identity.path, target=f"image/{selected.name}", kind="switch-image",
        size=identity.size, sha256=identity.sha256,
        consumers=((family, version),),
    )


def _walk_regular_files(
    root: Path, label: str, *, allow_internal_hardlinks: bool = False,
) -> tuple[Path, ...]:
    try:
        metadata = root.lstat()
    except OSError as exc:
        raise PackageError(f"{label} is missing or unreadable: {exc}") from exc
    if not stat.S_ISDIR(metadata.st_mode) or root.resolve(strict=True) != root:
        raise PackageError(f"{label} must be one canonical real directory")
    result: list[Path] = []
    def walk_error(error: OSError) -> None:
        raise PackageError(f"cannot enumerate {label}: {error}")

    for current, directory_names, file_names in os.walk(
        root, followlinks=False, onerror=walk_error,
    ):
        current_path = Path(current)
        for name in sorted(directory_names):
            path = current_path / name
            item = path.lstat()
            if not stat.S_ISDIR(item.st_mode):
                raise PackageError(f"{label} contains a non-directory or symlink: {path}")
        for name in sorted(file_names):
            path = current_path / name
            item = path.lstat()
            if not stat.S_ISREG(item.st_mode):
                raise PackageError(f"{label} contains a non-regular file: {path}")
            if item.st_nlink != 1 and not allow_internal_hardlinks:
                raise PackageError(f"{label} contains an unsafe non-single-link file: {path}")
            result.append(path)
    if not result:
        raise PackageError(f"{label} contains no regular files")
    return tuple(sorted(result))


def _read_gzip_bounded(path: Path, label: str, *, expected_nlink: int = 1) -> bytes:
    payload = _read_small(path, label, expected_nlink=expected_nlink)
    try:
        with gzip.GzipFile(fileobj=__import__("io").BytesIO(payload), mode="rb") as stream:
            value = stream.read(MAX_CONTROL_BYTES + 1)
    except (OSError, EOFError) as exc:
        raise PackageError(f"{label} is not a valid gzip stream: {exc}") from exc
    if len(value) > MAX_CONTROL_BYTES:
        raise PackageError(f"{label} expands beyond its safety bound")
    return value


def _parse_deb822(payload: bytes, label: str) -> tuple[dict[str, str], ...]:
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise PackageError(f"{label} is not UTF-8: {exc}") from exc
    records: list[dict[str, str]] = []
    for stanza in re.split(r"\n\s*\n", text.strip()):
        if not stanza:
            continue
        record: dict[str, str] = {}
        previous_key: Optional[str] = None
        for line in stanza.splitlines():
            if line[:1].isspace():
                if previous_key is None:
                    raise PackageError(f"{label} contains an orphan continuation line")
                record[previous_key] += "\n" + line
                continue
            key, separator, value = line.partition(":")
            if not separator or not key.strip() or key.strip() in record:
                raise PackageError(f"{label} contains an invalid or duplicate field")
            previous_key = key.strip()
            record[previous_key] = value.strip()
        records.append(record)
    if not records:
        raise PackageError(f"{label} contains no package records")
    return tuple(records)


def _internal_apps_link_counts(
    apps_root: Path, selected: tuple[Path, ...], platform: str,
) -> dict[Path, int]:
    """Permit only hardlinks whose complete alias set is inside canonical apps/."""
    all_files = _walk_regular_files(
        apps_root, "apps source root", allow_internal_hardlinks=True,
    )
    aliases: dict[tuple[int, int], list[tuple[Path, os.stat_result]]] = {}
    for path in all_files:
        metadata = path.lstat()
        aliases.setdefault((metadata.st_dev, metadata.st_ino), []).append((path, metadata))
    result: dict[Path, int] = {}
    for path in selected:
        metadata = path.lstat()
        same_inode = aliases.get((metadata.st_dev, metadata.st_ino), [])
        if len(same_inode) != metadata.st_nlink:
            raise PackageError(
                f"apps/{platform} hardlink alias escapes canonical apps/: {path}"
            )
        for alias, alias_status in same_inode:
            if (
                not stat.S_ISREG(alias_status.st_mode)
                or alias_status.st_uid != metadata.st_uid
                or stat.S_IMODE(alias_status.st_mode) != stat.S_IMODE(metadata.st_mode)
                or alias_status.st_nlink != metadata.st_nlink
            ):
                raise PackageError(
                    f"apps/{platform} has inconsistent internal hardlink alias: {alias}"
                )
        result[path] = metadata.st_nlink
    return result


def _validate_apps_repository(
    repository: Path, platform: str, apps_root: Path,
) -> tuple[tuple[Path, int], ...]:
    files = _walk_regular_files(
        repository, f"apps/{platform}", allow_internal_hardlinks=True,
    )
    link_counts = _internal_apps_link_counts(apps_root, files, platform)
    by_relative = {path.relative_to(repository).as_posix(): path for path in files}
    required = {"Packages", "Packages.gz", "repository.meta"}
    missing = sorted(required - set(by_relative))
    if missing:
        raise PackageError(f"apps/{platform} is missing: {', '.join(missing)}")
    packages = _read_small(
        by_relative["Packages"], f"apps/{platform}/Packages",
        expected_nlink=link_counts[by_relative["Packages"]],
    )
    compressed = _read_gzip_bounded(
        by_relative["Packages.gz"], f"apps/{platform}/Packages.gz",
        expected_nlink=link_counts[by_relative["Packages.gz"]],
    )
    if compressed != packages:
        raise PackageError(f"apps/{platform} Packages and Packages.gz differ")
    expected_os, expected_arch = platform.split("/", 1)
    expected_meta = {
        "schema_version": "1", "os_id": "ubuntu",
        "os_version": expected_os.removeprefix("ubuntu-"),
        "architecture": expected_arch,
    }
    metadata: dict[str, str] = {}
    for line in _read_small(
        by_relative["repository.meta"], f"apps/{platform}/repository.meta",
        expected_nlink=link_counts[by_relative["repository.meta"]],
    ).decode("ascii", errors="strict").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            metadata[key.strip()] = value.strip()
    if any(metadata.get(key) != value for key, value in expected_meta.items()):
        raise PackageError(f"apps/{platform}/repository.meta does not match the selected platform")
    referenced: set[str] = set()
    package_names: set[str] = set()
    for record in _parse_deb822(packages, f"apps/{platform}/Packages"):
        package_name = record.get("Package", "")
        if not package_name:
            raise PackageError(f"apps/{platform} has a record without Package")
        package_names.add(package_name)
        filename = record.get("Filename", "").removeprefix("./")
        relative = _safe_relative(filename, "APT Filename").as_posix()
        if relative in referenced:
            raise PackageError(f"apps/{platform} repeats APT payload {relative}")
        referenced.add(relative)
        source = by_relative.get(relative)
        if source is None:
            raise PackageError(f"apps/{platform} is missing indexed payload {relative}")
        try:
            expected_size = int(record.get("Size", ""), 10)
        except ValueError as exc:
            raise PackageError(f"apps/{platform} has invalid Size for {relative}") from exc
        expected_hash = record.get("SHA256", "")
        if not HEX64.fullmatch(expected_hash):
            raise PackageError(f"apps/{platform} has invalid SHA256 for {relative}")
        architecture = record.get("Architecture", "")
        if architecture not in {expected_arch, "all"}:
            raise PackageError(f"apps/{platform} has wrong architecture for {relative}")
        identity = _identity(
            source, f"apps/{platform}/{relative}",
            expected_nlink=link_counts[source],
        )
        if identity.size != expected_size or identity.sha256 != expected_hash:
            raise PackageError(f"apps/{platform} indexed identity mismatch for {relative}")
    indexed_debs = {name for name in by_relative if name.casefold().endswith(".deb")}
    if indexed_debs != referenced:
        raise PackageError(f"apps/{platform} contains unindexed or non-deb package payloads")
    missing_packages = sorted(REQUIRED_OFFLINE_PACKAGES - package_names)
    if missing_packages:
        raise PackageError(
            f"apps/{platform} is missing required offline packages: "
            + ", ".join(missing_packages)
        )
    allowed = required | referenced
    extras = sorted(set(by_relative) - allowed)
    if extras:
        raise PackageError(
            f"apps/{platform} contains undeclared regular files: "
            + ", ".join(extras[:5])
        )
    # Keep the shared-bundle contract aligned with the upload workflow's
    # production definition of a complete management-server repository.
    upload = _load_script(UPLOAD_SCRIPT)
    try:
        upload.validate_flat_apt_repository(repository, platform)
    except Exception as exc:
        raise PackageError(str(exc)) from exc
    return tuple((path, link_counts[path]) for path in files)


def _firmware_path(value: Path, repository_root: Path) -> Path:
    firmware_root = repository_root / "firmware"
    if value.is_absolute():
        candidate = _absolute_unresolved(value)
    elif value.parts and value.parts[0] == "firmware":
        candidate = _absolute_unresolved(repository_root / value)
    else:
        candidate = _absolute_unresolved(firmware_root / value)
    try:
        candidate.relative_to(firmware_root)
    except ValueError as exc:
        raise PackageError("--firmware must resolve below the repository firmware/ directory") from exc
    _reject_symlink_ancestors(candidate, firmware_root, "firmware")
    return candidate


def _add_directory(archive: tarfile.TarFile, name: str) -> None:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    info.mtime = 0
    archive.addfile(info)


def _add_bytes(archive: tarfile.TarFile, name: str, payload: bytes, mode: int) -> None:
    import io
    info = tarfile.TarInfo(name)
    info.size = len(payload)
    info.mode = mode
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    info.mtime = 0
    archive.addfile(info, io.BytesIO(payload))


def _add_artifact(archive: tarfile.TarFile, artifact: Artifact) -> None:
    with _open_stable_regular(
        artifact.source, f"artifact {artifact.target}", maximum_size=MAX_ARTIFACT_BYTES,
        expected_nlink=artifact.source_nlink,
    ) as (descriptor, metadata):
        if metadata.st_size != artifact.size:
            raise PackageError(f"artifact changed before archive write: {artifact.target}")
        info = tarfile.TarInfo("payload/" + artifact.target)
        info.size = artifact.size
        info.mode = artifact.mode
        info.uid = info.gid = 0
        info.uname = info.gname = "root"
        info.mtime = 0
        os.lseek(descriptor, 0, os.SEEK_SET)
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            archive.addfile(info, stream)
        os.lseek(descriptor, 0, os.SEEK_SET)
        if _hash_descriptor(descriptor, metadata.st_size, f"artifact {artifact.target}") != artifact.sha256:
            raise PackageError(f"artifact digest changed during archive write: {artifact.target}")


def _validate_archive_layout(
    artifacts: tuple[Artifact, ...], metadata_bytes: bytes,
    installer_bytes: bytes,
) -> tuple[str, ...]:
    """Mirror every aggregate/member bound enforced by this installer."""
    directories = {"payload"}
    for artifact in artifacts:
        parts = PurePosixPath("payload", artifact.target).parts
        directories.update(
            "/".join(parts[:length]) for length in range(1, len(parts))
        )
    member_names = (
        set(directories)
        | {METADATA_NAME, INSTALLER_NAME}
        | {"payload/" + artifact.target for artifact in artifacts}
    )
    # deploy-shared-artifacts.py checks the bound before asking tarfile for
    # the next member, so a valid bundle must remain strictly below it.
    if len(member_names) >= MAX_MEMBER_COUNT:
        raise PackageError(
            f"artifact archive member count is unsafe: {len(member_names)} "
            f"(must be below {MAX_MEMBER_COUNT})"
        )
    for name in member_names:
        encoded = name.encode("utf-8", errors="surrogatepass")
        if len(encoded) > MAX_MEMBER_NAME_BYTES:
            raise PackageError(f"artifact archive member name is too long: {name}")
        # PAX_FORMAT may encode a long path in the `path` extended header.
        # This is the only dynamic PAX value emitted by our fixed metadata.
        if len(b"path") + len(encoded) > MAX_PAX_BYTES:
            raise PackageError(f"artifact archive PAX metadata is too large: {name}")
    if (
        not metadata_bytes or len(metadata_bytes) > MAX_CONTROL_BYTES
        or not installer_bytes or len(installer_bytes) > MAX_CONTROL_BYTES
    ):
        raise PackageError("artifact archive control member size is unsafe")
    expanded_size = (
        len(metadata_bytes) + len(installer_bytes)
        + sum(artifact.size for artifact in artifacts)
    )
    if expanded_size > MAX_EXPANDED_BYTES:
        raise PackageError(
            f"artifact archive expanded size is unsafe: {expanded_size}"
        )
    return tuple(sorted(
        directories, key=lambda item: (item.count("/"), item),
    ))


def _write_file(path: Path, payload: bytes, mode: int) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise PackageError(f"short write while publishing {path.name}")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _hash_path(path: Path) -> str:
    return _identity(path, path.name).sha256


def _directory_open_flags() -> int:
    return (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )


def _open_output_parent(
    parent: Path, *, required_uid: Optional[int], create: bool,
) -> Optional[tuple[int, os.stat_result]]:
    """Walk an absolute parent without following a pathname component."""
    absolute = _absolute_unresolved(parent)
    descriptor = -1
    try:
        descriptor = os.open(absolute.anchor, _directory_open_flags())
        for part in absolute.parts[1:]:
            while True:
                try:
                    before = os.stat(
                        part, dir_fd=descriptor, follow_symlinks=False,
                    )
                except FileNotFoundError:
                    if not create:
                        os.close(descriptor)
                        descriptor = -1
                        return None
                    try:
                        os.mkdir(part, 0o700, dir_fd=descriptor)
                    except FileExistsError:
                        continue
                    before = os.stat(
                        part, dir_fd=descriptor, follow_symlinks=False,
                    )
                if not stat.S_ISDIR(before.st_mode):
                    raise PackageError(
                        f"output parent has a symlink or unsafe ancestor: {absolute}"
                    )
                try:
                    child = os.open(part, _directory_open_flags(), dir_fd=descriptor)
                except OSError as exc:
                    raise PackageError(
                        f"output parent has a symlink or unsafe ancestor: {absolute}: {exc}"
                    ) from exc
                opened = os.fstat(child)
                after = os.stat(
                    part, dir_fd=descriptor, follow_symlinks=False,
                )
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or not stat.S_ISDIR(after.st_mode)
                    or (before.st_dev, before.st_ino)
                    != (opened.st_dev, opened.st_ino)
                    or (after.st_dev, after.st_ino)
                    != (opened.st_dev, opened.st_ino)
                ):
                    os.close(child)
                    raise PackageError(
                        f"output parent ancestor changed while opening: {absolute}"
                    )
                os.close(descriptor)
                descriptor = child
                break
        opened_parent = os.fstat(descriptor)
        named_parent = absolute.lstat()
        if (
            not stat.S_ISDIR(opened_parent.st_mode)
            or not stat.S_ISDIR(named_parent.st_mode)
            or (opened_parent.st_dev, opened_parent.st_ino)
            != (named_parent.st_dev, named_parent.st_ino)
        ):
            raise PackageError("output parent identity changed while opening")
        if required_uid is not None and (
            opened_parent.st_uid != required_uid
            or opened_parent.st_mode & 0o022
        ):
            raise PackageError(
                "output parent must be one owner-controlled canonical directory"
            )
        result = descriptor, opened_parent
        descriptor = -1
        return result
    except PackageError:
        raise
    except OSError as exc:
        raise PackageError(f"cannot safely open output parent {absolute}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _require_output_parent_identity(
    parent: Path, descriptor: int, expected: os.stat_result,
    *, required_uid: int,
) -> None:
    try:
        opened = os.fstat(descriptor)
        named = parent.lstat()
    except OSError as exc:
        raise PackageError(f"output parent changed during publication: {exc}") from exc
    if (
        not stat.S_ISDIR(opened.st_mode)
        or not stat.S_ISDIR(named.st_mode)
        or opened.st_uid != required_uid
        or opened.st_mode & 0o022
        or (opened.st_dev, opened.st_ino)
        != (expected.st_dev, expected.st_ino)
        or (named.st_dev, named.st_ino)
        != (expected.st_dev, expected.st_ino)
    ):
        raise PackageError("output parent changed during publication")


def _stat_at(descriptor: int, name: str) -> Optional[os.stat_result]:
    try:
        return os.stat(name, dir_fd=descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise PackageError(f"cannot inspect output member {name}: {exc}") from exc


def _create_staging_directory(
    parent_descriptor: int, destination_name: str, *, required_uid: int,
) -> tuple[str, int, os.stat_result]:
    prefix = f".{destination_name}.tmp."
    for _attempt in range(128):
        name = prefix + os.urandom(8).hex()
        try:
            os.mkdir(name, 0o700, dir_fd=parent_descriptor)
        except FileExistsError:
            continue
        except OSError as exc:
            raise PackageError(f"cannot create private output staging directory: {exc}") from exc
        descriptor = -1
        try:
            descriptor = os.open(
                name, _directory_open_flags(), dir_fd=parent_descriptor,
            )
            os.fchmod(descriptor, 0o700)
            opened = os.fstat(descriptor)
            named = os.stat(
                name, dir_fd=parent_descriptor, follow_symlinks=False,
            )
            if (
                not stat.S_ISDIR(opened.st_mode)
                or opened.st_uid != required_uid
                or stat.S_IMODE(opened.st_mode) != 0o700
                or (opened.st_dev, opened.st_ino)
                != (named.st_dev, named.st_ino)
            ):
                raise PackageError("private output staging directory is unsafe")
            return name, descriptor, opened
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.rmdir(name, dir_fd=parent_descriptor)
            except OSError:
                pass
            raise
    raise PackageError("cannot allocate a unique private output staging directory")


def _open_new_staged_file(
    directory_descriptor: int, name: str, mode: int,
) -> int:
    try:
        return os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            mode, dir_fd=directory_descriptor,
        )
    except OSError as exc:
        raise PackageError(f"cannot create private staged file {name}: {exc}") from exc


def _write_staged_file(
    directory_descriptor: int, name: str, payload: bytes, mode: int,
) -> None:
    descriptor = _open_new_staged_file(directory_descriptor, name, mode)
    try:
        os.fchmod(descriptor, mode)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise PackageError(f"short write while publishing {name}")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _hash_staged_file(directory_descriptor: int, name: str) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        before = os.stat(
            name, dir_fd=directory_descriptor, follow_symlinks=False,
        )
        descriptor = os.open(name, flags, dir_fd=directory_descriptor)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or before.st_nlink != 1
            or opened.st_nlink != 1
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise PackageError(f"private staged file identity is unsafe: {name}")
        digest = _hash_descriptor(descriptor, opened.st_size, name)
        after = os.fstat(descriptor)
        current = os.stat(
            name, dir_fd=directory_descriptor, follow_symlinks=False,
        )
        if (
            _stable_fields(after) != _stable_fields(opened)
            or (current.st_dev, current.st_ino)
            != (opened.st_dev, opened.st_ino)
        ):
            raise PackageError(f"private staged file changed while hashing: {name}")
        return digest
    except PackageError:
        raise
    except OSError as exc:
        raise PackageError(f"cannot hash private staged file {name}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


@contextmanager
def _held_verified_staged_files(
    directory_descriptor: int,
    expected: dict[str, tuple[int, int, str]],
    required_uid: int,
) -> Iterator[None]:
    """Hold the exact frozen output inodes through atomic publication."""
    try:
        actual = set(os.listdir(directory_descriptor))
    except OSError as exc:
        raise PackageError(f"cannot enumerate private staged output: {exc}") from exc
    if actual != set(expected):
        raise PackageError("private staged output contents changed before publish")
    opened_files: dict[str, tuple[int, os.stat_result]] = {}
    flags = (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        for name in sorted(expected):
            expected_mode, expected_size, expected_sha256 = expected[name]
            try:
                named = os.stat(
                    name, dir_fd=directory_descriptor, follow_symlinks=False,
                )
                descriptor = os.open(name, flags, dir_fd=directory_descriptor)
            except OSError as exc:
                raise PackageError(
                    f"cannot open private staged output {name}: {exc}"
                ) from exc
            opened_files[name] = (descriptor, os.fstat(descriptor))
            opened = opened_files[name][1]
            if (
                not stat.S_ISREG(named.st_mode)
                or not stat.S_ISREG(opened.st_mode)
                or named.st_nlink != 1 or opened.st_nlink != 1
                or named.st_uid != required_uid or opened.st_uid != required_uid
                or stat.S_IMODE(named.st_mode) != expected_mode
                or stat.S_IMODE(opened.st_mode) != expected_mode
                or named.st_size != expected_size or opened.st_size != expected_size
                or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
            ):
                raise PackageError(
                    f"private staged output identity changed: {name}"
                )
            if _hash_descriptor(descriptor, expected_size, name) != expected_sha256:
                raise PackageError(f"private staged output hash changed: {name}")
        yield
        if set(os.listdir(directory_descriptor)) != set(expected):
            raise PackageError("published output contents changed during publication")
        for name in sorted(expected):
            expected_mode, expected_size, expected_sha256 = expected[name]
            descriptor, before = opened_files[name]
            after = os.fstat(descriptor)
            current = os.stat(
                name, dir_fd=directory_descriptor, follow_symlinks=False,
            )
            if (
                _stable_fields(after) != _stable_fields(before)
                or (current.st_dev, current.st_ino)
                != (before.st_dev, before.st_ino)
                or current.st_nlink != 1
                or current.st_uid != required_uid
                or stat.S_IMODE(current.st_mode) != expected_mode
                or current.st_size != expected_size
            ):
                raise PackageError(
                    f"published output identity changed during publication: {name}"
                )
            if _hash_descriptor(descriptor, expected_size, name) != expected_sha256:
                raise PackageError(
                    f"published output hash changed during publication: {name}"
                )
            final = os.fstat(descriptor)
            final_named = os.stat(
                name, dir_fd=directory_descriptor, follow_symlinks=False,
            )
            if (
                _stable_fields(final) != _stable_fields(before)
                or (final_named.st_dev, final_named.st_ino)
                != (before.st_dev, before.st_ino)
            ):
                raise PackageError(
                    f"published output changed during final hash: {name}"
                )
    finally:
        for descriptor, _metadata in opened_files.values():
            os.close(descriptor)


def _remove_private_directory_at(
    parent_descriptor: int, name: str,
    expected: tuple[int, int],
) -> None:
    """Remove only the exact private directory reachable through its held parent."""
    try:
        descriptor = os.open(
            name, _directory_open_flags(), dir_fd=parent_descriptor,
        )
    except FileNotFoundError:
        return
    except OSError as exc:
        raise PackageError(f"cannot open output staging for cleanup: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        named = os.stat(
            name, dir_fd=parent_descriptor, follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != expected
            or (named.st_dev, named.st_ino) != expected
        ):
            raise PackageError("refusing to clean a changed output staging directory")
        for child in os.listdir(descriptor):
            child_status = os.stat(
                child, dir_fd=descriptor, follow_symlinks=False,
            )
            if stat.S_ISDIR(child_status.st_mode):
                raise PackageError(
                    "refusing to recurse into an unexpected staging directory"
                )
            os.unlink(child, dir_fd=descriptor)
        os.fsync(descriptor)
    except PackageError:
        raise
    except OSError as exc:
        raise PackageError(f"cannot safely clean output staging directory: {exc}") from exc
    finally:
        os.close(descriptor)
    try:
        current = os.stat(
            name, dir_fd=parent_descriptor, follow_symlinks=False,
        )
        if (current.st_dev, current.st_ino) != expected:
            raise PackageError("output staging directory changed before removal")
        os.rmdir(name, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
    except PackageError:
        raise
    except OSError as exc:
        raise PackageError(f"cannot remove output staging directory: {exc}") from exc


def _remove_private_tree(directory: Path) -> None:
    if not directory.exists():
        return
    for current, directory_names, file_names in os.walk(directory, topdown=False):
        current_path = Path(current)
        for name in file_names:
            (current_path / name).unlink(missing_ok=True)
        for name in directory_names:
            (current_path / name).rmdir()
    directory.rmdir()


def _rename_directory_noreplace(
    source: Path, destination: Path, *, directory_fd: Optional[int] = None,
) -> None:
    """Publish a complete private directory without clobbering a race."""
    encoded_source = os.fsencode(source.name if directory_fd is not None else source)
    encoded_destination = os.fsencode(
        destination.name if directory_fd is not None else destination
    )
    descriptor = -100 if directory_fd is None else directory_fd
    libc = ctypes.CDLL(None, use_errno=True)
    result: Optional[int] = None
    if sys.platform.startswith("linux"):
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is not None:
            renameat2.argtypes = (
                ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
                ctypes.c_uint,
            )
            renameat2.restype = ctypes.c_int
            result = renameat2(
                descriptor, encoded_source, descriptor, encoded_destination, 1,
            )
    elif sys.platform == "darwin":
        renamex = getattr(
            libc, "renameatx_np" if directory_fd is not None else "renamex_np",
            None,
        )
        if renamex is not None:
            if directory_fd is None:
                renamex.argtypes = (
                    ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint,
                )
                arguments = (encoded_source, encoded_destination, 0x00000004)
            else:
                renamex.argtypes = (
                    ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                    ctypes.c_char_p, ctypes.c_uint,
                )
                arguments = (
                    descriptor, encoded_source, descriptor,
                    encoded_destination, 0x00000004,
                )
            renamex.restype = ctypes.c_int
            result = renamex(*arguments)
    if result is None:
        raise PackageError("atomic no-clobber directory publication is unsupported")
    if result != 0:
        number = ctypes.get_errno()
        if number in {errno.EEXIST, errno.ENOTEMPTY}:
            raise PackageError(f"output appeared during publication: {destination}")
        raise PackageError(
            f"cannot atomically publish output: {os.strerror(number)}"
        )


_TEST_BEFORE_OUTPUT_PUBLISH = None


def _publish_staging_directory(
    parent_descriptor: int, parent: Path, parent_status: os.stat_result,
    staging_name: str, staging_descriptor: int,
    staging_status: os.stat_result, destination: Path, *, required_uid: int,
    expected_files: dict[str, tuple[int, int, str]],
) -> None:
    expected_stage = (staging_status.st_dev, staging_status.st_ino)
    _require_output_parent_identity(
        parent, parent_descriptor, parent_status, required_uid=required_uid,
    )
    current_stage = _stat_at(parent_descriptor, staging_name)
    if (
        current_stage is None
        or not stat.S_ISDIR(current_stage.st_mode)
        or current_stage.st_uid != required_uid
        or stat.S_IMODE(current_stage.st_mode) != 0o700
        or (current_stage.st_dev, current_stage.st_ino) != expected_stage
    ):
        raise PackageError("private output staging directory changed before publish")
    if _stat_at(parent_descriptor, destination.name) is not None:
        raise PackageError(
            f"output already exists; refusing to overwrite: {destination}"
        )
    hook = _TEST_BEFORE_OUTPUT_PUBLISH
    if hook is not None:
        hook()
    _require_output_parent_identity(
        parent, parent_descriptor, parent_status, required_uid=required_uid,
    )
    current_stage = _stat_at(parent_descriptor, staging_name)
    if (
        current_stage is None
        or (current_stage.st_dev, current_stage.st_ino) != expected_stage
    ):
        raise PackageError("private output staging directory changed before publish")

    published = False
    try:
        with _held_verified_staged_files(
            staging_descriptor, expected_files, required_uid,
        ):
            _rename_directory_noreplace(
                Path(staging_name), Path(destination.name),
                directory_fd=parent_descriptor,
            )
            published = True
            current = _stat_at(parent_descriptor, destination.name)
            if (
                current is None
                or not stat.S_ISDIR(current.st_mode)
                or current.st_uid != required_uid
                or stat.S_IMODE(current.st_mode) != 0o700
                or (current.st_dev, current.st_ino) != expected_stage
            ):
                raise PackageError("published output directory identity is unsafe")
            _require_output_parent_identity(
                parent, parent_descriptor, parent_status,
                required_uid=required_uid,
            )
            os.fsync(parent_descriptor)
    except BaseException:
        if published:
            rollback_error: Optional[BaseException] = None
            try:
                current = _stat_at(parent_descriptor, destination.name)
                if current is None or (
                    current.st_dev, current.st_ino
                ) != expected_stage:
                    raise PackageError(
                        "published output changed before rollback"
                    )
                _rename_directory_noreplace(
                    Path(destination.name), Path(staging_name),
                    directory_fd=parent_descriptor,
                )
                os.fsync(parent_descriptor)
                published = False
            except BaseException as exc:
                rollback_error = exc
            if rollback_error is not None:
                raise PackageError(
                    "output publication failed and safe rollback was impossible"
                ) from rollback_error
        raise


def _default_output(repository_root: Path, project: Path) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return repository_root / "outputs/artifact-bundles" / f"{project.name}-{stamp}"


def build_bundle(
    project: str | Path, *, output: Optional[Path] = None,
    repository_root: Path = ROOT, deployment_scope: str = "all",
    switch_scope: Optional[str] = None, mini: bool | str | Path = False,
    no_upgrade: bool = False, apps_platforms: Sequence[str] = (),
    firmware: Sequence[Path] = (), installer_path: Path = INSTALLER,
    load_script_path: Path = LOAD_SCRIPT,
) -> PackageResult:
    repository_request = _absolute_unresolved(repository_root)
    try:
        repository_root = repository_request.resolve(strict=True)
    except OSError as exc:
        raise PackageError(f"repository root is missing or unsafe: {exc}") from exc
    project_path = resolve_project(project, repository_root=repository_root)
    load = _load_script(load_script_path)
    mini_value: Optional[str]
    if mini is True:
        mini_value = DEFAULT_MINI
    elif mini:
        mini_value = os.fspath(mini)
    else:
        mini_value = None
    arguments = SimpleNamespace(
        deployment_scope=deployment_scope, switch_scope=switch_scope,
        mini=mini_value, ztp_monitor_scope="auto",
    )
    try:
        effective_scope = load.validate_deployment_scope_options(arguments)
        effective_switch = load.validate_switch_scope_options(arguments, effective_scope)
    except Exception as exc:
        raise PackageError(str(exc)) from exc

    input_identities: dict[str, FileIdentity] = {}
    mini_name: Optional[str] = None
    snapshot_parent = Path(tempfile.mkdtemp(prefix="http-ztp-artifact-inputs."))
    os.chmod(snapshot_parent, 0o700)
    try:
        snapshot_project = snapshot_parent / project_path.name
        snapshot_project.mkdir(mode=0o700)
        for name in ("01-global.yaml", "02-devices_config.csv"):
            source = project_path / name
            input_identities[name] = _copy_input_snapshot(
                source, snapshot_project / name, f"project input {name}",
            )
        if mini_value is not None:
            try:
                mini_source, _canonical = load.project_mini_air_devices(project_path, mini_value)
            except Exception as exc:
                raise PackageError(str(exc)) from exc
            if mini_source is None:
                raise PackageError("--mini did not resolve a device list")
            # 11-load permits one exact relative alias to its canonical mini
            # list.  The packager freezes the validated target itself instead
            # of following the alias through the trusted-reader boundary.
            if stat.S_ISLNK(mini_source.lstat().st_mode):
                mini_source = project_path / DEFAULT_MINI
            mini_name = mini_source.name
            input_identities[mini_name] = _copy_input_snapshot(
                mini_source, snapshot_project / mini_name,
                f"project input {mini_name}",
            )
        try:
            settings = load.load_global(snapshot_project / "01-global.yaml")
            device_types = load.load_device_types(
                snapshot_project / "02-devices_config.csv",
                settings.schema_version, switch_scope=effective_switch,
            )
            expected = {}
            if not no_upgrade:
                expected = load.expected_images(
                    settings, device_types, deployment_scope=effective_scope,
                    switch_scope=effective_switch,
                )
        except Exception as exc:
            raise PackageError(str(exc)) from exc
    finally:
        _remove_private_tree(snapshot_parent)

    artifacts: list[Artifact] = []
    if not no_upgrade:
        # Reuse the production dry-run gate as well as its derivation helpers.
        # This preserves rejection of non-empty unexpected project images and
        # conflicting modern/legacy aliases.  Our subsequent selection adds
        # the stronger held-FD/single-link requirements needed for packaging.
        original_image_dir = load.IMAGE_DIR
        load.IMAGE_DIR = repository_root / "image"
        try:
            load.prepare_images(
                project_path, expected, dry_run=True, quiet=True,
            )
        except Exception as exc:
            raise PackageError(str(exc)) from exc
        finally:
            load.IMAGE_DIR = original_image_dir
        for family, expected_name in sorted(expected.items()):
            artifacts.append(_select_image(
                load, project_path, repository_root, family, expected_name,
                settings.versions[family],
            ))

    selected_platforms = tuple(sorted(set(apps_platforms)))
    invalid_platforms = sorted(set(selected_platforms) - VALID_APPS_PLATFORMS)
    if invalid_platforms:
        raise PackageError(f"unsupported --apps-platform: {', '.join(invalid_platforms)}")
    for platform_name in selected_platforms:
        repository = repository_root / "apps" / platform_name
        for source, source_nlink in _validate_apps_repository(
            repository, platform_name, repository_root / "apps",
        ):
            relative = source.relative_to(repository_root).as_posix()
            artifacts.append(_artifact(
                source, relative, "apps", platform=platform_name,
                source_nlink=source_nlink,
            ))

    for value in firmware:
        source = _firmware_path(Path(value), repository_root)
        relative = source.relative_to(repository_root).as_posix()
        artifacts.append(_artifact(source, relative, "firmware"))

    by_target: dict[str, Artifact] = {}
    for artifact in artifacts:
        previous = by_target.get(artifact.target)
        if previous is None:
            by_target[artifact.target] = artifact
            continue
        if (
            previous.source != artifact.source
            or previous.kind != artifact.kind
            or previous.size != artifact.size
            or previous.sha256 != artifact.sha256
            or previous.mode != artifact.mode
            or previous.platform != artifact.platform
            or previous.source_nlink != artifact.source_nlink
        ):
            raise PackageError(f"multiple conflicting artifacts map to {artifact.target}")
        by_target[artifact.target] = Artifact(
            source=previous.source, target=previous.target, kind=previous.kind,
            size=previous.size, sha256=previous.sha256, mode=previous.mode,
            consumers=tuple(sorted(set(previous.consumers + artifact.consumers))),
            platform=previous.platform, source_nlink=previous.source_nlink,
        )
    frozen_artifacts = tuple(by_target[name] for name in sorted(by_target))
    requested_output = _absolute_unresolved(
        output if output is not None else _default_output(repository_root, project_path)
    )
    try:
        repository_relative_output = requested_output.relative_to(repository_request)
    except ValueError:
        destination = requested_output
    else:
        destination = repository_root / repository_relative_output
    if destination.name in {"", ".", ".."}:
        raise PackageError("output must name one directory below its parent")
    empty_result = PackageResult(
        False, destination, destination / ARCHIVE_NAME,
        destination / INSTALLER_NAME, destination / METADATA_NAME,
        destination / SUMS_NAME, (),
    )
    inspected_parent = _open_output_parent(
        destination.parent, required_uid=None, create=False,
    )
    if inspected_parent is not None:
        inspected_descriptor, _inspected_status = inspected_parent
        try:
            if _stat_at(inspected_descriptor, destination.name) is not None:
                raise PackageError(
                    f"output already exists; refusing to overwrite: {destination}"
                )
        finally:
            os.close(inspected_descriptor)
    if not frozen_artifacts:
        for name, identity in input_identities.items():
            _assert_identity(identity, f"project input {name}")
        return empty_result

    installer_identity = _identity(
        installer_path, "shared artifact installer", maximum_size=MAX_CONTROL_BYTES,
    )
    installer_bytes = _read_small(installer_path, "shared artifact installer")
    if (
        len(installer_bytes) != installer_identity.size
        or hashlib.sha256(installer_bytes).hexdigest() != installer_identity.sha256
    ):
        raise PackageError("shared artifact installer changed while being frozen")
    metadata_value = {
        "artifact_type": "http-ztp-shared-artifacts",
        "artifacts": [item.metadata_record() for item in frozen_artifacts],
        "deployment_scope": effective_scope,
        "inputs": {
            name: {"sha256": item.sha256, "size": item.size}
            for name, item in sorted(input_identities.items())
        },
        "installer": {
            "name": INSTALLER_NAME,
            "sha256": installer_identity.sha256,
            "size": installer_identity.size,
        },
        "mini": mini_value is not None,
        "mini_input": mini_name,
        "project": project_path.name,
        "schema_version": 1,
        "switch_scope": effective_switch,
        "upgrade_policy": "disabled" if no_upgrade else "enabled",
    }
    metadata_bytes = json.dumps(
        metadata_value, ensure_ascii=True, indent=2, sort_keys=True,
    ).encode("ascii") + b"\n"
    archive_directories = _validate_archive_layout(
        frozen_artifacts, metadata_bytes, installer_bytes,
    )

    required_uid = os.geteuid()
    opened_parent = _open_output_parent(
        destination.parent, required_uid=required_uid, create=True,
    )
    if opened_parent is None:
        raise PackageError("output parent could not be created")
    parent_descriptor, parent_status = opened_parent
    staging_name: Optional[str] = None
    staging_descriptor = -1
    staging_status: Optional[os.stat_result] = None
    completed = False
    try:
        _require_output_parent_identity(
            destination.parent, parent_descriptor, parent_status,
            required_uid=required_uid,
        )
        if _stat_at(parent_descriptor, destination.name) is not None:
            raise PackageError(
                f"output already exists; refusing to overwrite: {destination}"
            )
        staging_name, staging_descriptor, staging_status = _create_staging_directory(
            parent_descriptor, destination.name, required_uid=required_uid,
        )
        archive_descriptor = _open_new_staged_file(
            staging_descriptor, ARCHIVE_NAME, 0o600,
        )
        try:
            os.fchmod(archive_descriptor, 0o600)
            with os.fdopen(archive_descriptor, "wb") as stream:
                archive_descriptor = -1
                with tarfile.open(
                    ARCHIVE_NAME, "w:gz", fileobj=stream,
                    format=tarfile.PAX_FORMAT,
                ) as archive:
                    for name in archive_directories:
                        _add_directory(archive, name)
                    _add_bytes(archive, METADATA_NAME, metadata_bytes, 0o600)
                    _add_bytes(archive, INSTALLER_NAME, installer_bytes, 0o500)
                    for artifact in frozen_artifacts:
                        _add_artifact(archive, artifact)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            if archive_descriptor >= 0:
                os.close(archive_descriptor)
        _write_staged_file(
            staging_descriptor, INSTALLER_NAME, installer_bytes, 0o500,
        )
        _write_staged_file(
            staging_descriptor, METADATA_NAME, metadata_bytes, 0o600,
        )
        archive_status = os.stat(
            ARCHIVE_NAME, dir_fd=staging_descriptor, follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(archive_status.st_mode)
            or archive_status.st_size <= 0
            or archive_status.st_size > MAX_ARCHIVE_BYTES
        ):
            raise PackageError(
                f"artifact archive compressed size is unsafe: "
                f"{archive_status.st_size}"
            )
        staged_hashes = {
            name: _hash_staged_file(staging_descriptor, name)
            for name in (ARCHIVE_NAME, INSTALLER_NAME, METADATA_NAME)
        }
        sums = "".join(
            f"{staged_hashes[name]}  {name}\n"
            for name in (ARCHIVE_NAME, INSTALLER_NAME, METADATA_NAME)
        ).encode("ascii")
        _write_staged_file(staging_descriptor, SUMS_NAME, sums, 0o600)
        expected_files = {
            ARCHIVE_NAME: (0o600, archive_status.st_size, staged_hashes[ARCHIVE_NAME]),
            INSTALLER_NAME: (0o500, len(installer_bytes), staged_hashes[INSTALLER_NAME]),
            METADATA_NAME: (0o600, len(metadata_bytes), staged_hashes[METADATA_NAME]),
            SUMS_NAME: (0o600, len(sums), hashlib.sha256(sums).hexdigest()),
        }
        for name, identity in input_identities.items():
            _assert_identity(identity, f"project input {name}")
        _assert_identity(installer_identity, "shared artifact installer")
        for artifact in frozen_artifacts:
            current = _identity(
                artifact.source, f"artifact {artifact.target}",
                expected_nlink=artifact.source_nlink,
            )
            if current.size != artifact.size or current.sha256 != artifact.sha256:
                raise PackageError(f"artifact changed after bundle creation: {artifact.target}")
        os.fsync(staging_descriptor)
        _publish_staging_directory(
            parent_descriptor, destination.parent, parent_status,
            staging_name, staging_descriptor, staging_status, destination,
            required_uid=required_uid, expected_files=expected_files,
        )
        os.close(staging_descriptor)
        staging_descriptor = -1
        completed = True
    except BaseException as original:
        if staging_descriptor >= 0:
            os.close(staging_descriptor)
            staging_descriptor = -1
        if staging_name is not None and staging_status is not None:
            current_stage = _stat_at(parent_descriptor, staging_name)
            if current_stage is not None:
                expected_stage = (staging_status.st_dev, staging_status.st_ino)
                if (current_stage.st_dev, current_stage.st_ino) != expected_stage:
                    raise PackageError(
                        "output staging identity changed; refusing unsafe cleanup"
                    ) from original
                try:
                    _remove_private_directory_at(
                        parent_descriptor, staging_name, expected_stage,
                    )
                except PackageError as cleanup_error:
                    raise PackageError(
                        "output publication failed and safe staging cleanup failed"
                    ) from cleanup_error
        raise
    finally:
        if staging_descriptor >= 0:
            os.close(staging_descriptor)
        os.close(parent_descriptor)
    if not completed:
        raise PackageError("output publication did not complete")
    return PackageResult(
        True, destination, destination / ARCHIVE_NAME,
        destination / INSTALLER_NAME, destination / METADATA_NAME,
        destination / SUMS_NAME, frozen_artifacts,
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parser().parse_args(argv)
    try:
        result = build_bundle(
            args.project, output=args.output,
            deployment_scope=args.deployment_scope,
            switch_scope=args.switch_scope, mini=args.mini or False,
            no_upgrade=args.no_upgrade,
            apps_platforms=args.apps_platform,
            firmware=args.firmware,
        )
        if not result.created:
            print("[OK] no shared artifacts are required; no empty bundle was created")
            if args.no_upgrade:
                print("[SKIP] switch images: --no-upgrade")
            if not args.apps_platform:
                print("[SKIP] apps: no offline platform requested")
            if not args.firmware:
                print("[SKIP] firmware: none requested")
            return 0
        print(f"[OK] shared artifact bundle: {result.output}")
        print(f"[OK] artifacts: {len(result.artifacts)}")
        for artifact in result.artifacts:
            print(
                f"[ARTIFACT] {artifact.kind} {artifact.target} "
                f"bytes={artifact.size} sha256={artifact.sha256}"
            )
        print(f"[OK] archive SHA-256: {_hash_path(result.archive)}")
        print("[NEXT] copy the whole directory, run SHA256SUMS, then use deploy-shared-artifacts.py")
        return 0
    except (PackageError, OSError, tarfile.TarError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
