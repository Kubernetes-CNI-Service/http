#!/usr/bin/env python3
"""Internal shared archive implementation for tar-for-upload/download.

This module is deliberately not a command-line entry point.  User-facing
packaging workflows live in tools/tar-for-upload.py and tools/tar-for-download.py.
"""

from __future__ import annotations

import argparse
import fnmatch
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import stat
import subprocess
import sys
import tarfile
import tempfile
import xml.etree.ElementTree as ET
import zipfile

from project_contract import (
    is_manual_backup_name,
    is_tools_deployable_file,
    path_disposition,
    transfer_exclude_reason,
    ztp_prefix_publication_relative,
)


TOOLS_DIR = Path(__file__).resolve().parent
ROOT = TOOLS_DIR.parent
DAY0 = ROOT / "DAY0-Prepare"
MANIFEST = ROOT / "ztp/.setup_manifest"
STATIC_SETUP_MANAGED_LINKS = frozenset({
    "ethernet/monitor/eth.csv",
    "infiniband/monitor/ib.csv",
    "nvlink/monitor/nvsw.csv",
    "infiniband/bringup/xdr-upgrade/ib.csv",
    "infiniband/bringup/xdr-initial-setup/ib.csv",
})
DEPLOYMENT_PREWRITE_GUARD = TOOLS_DIR / "deployment_prewrite_guard.py"
DEPLOYMENT_SOURCE_MANIFEST_RELATIVE = PurePosixPath(
    "infra/docker/deployment-source-manifest.json"
)
DEPLOYMENT_AUTHORITY_RELATIVES = frozenset({
    DEPLOYMENT_SOURCE_MANIFEST_RELATIVE,
    PurePosixPath("tools/deployment_prewrite_guard.py"),
    PurePosixPath("tools/deploy-upload-archive.py"),
})
ARTIFACT_KINDS = frozenset({"upload", "preview", "download"})
CONTAINER_TOPLEVEL_LOCK_RELATIVE = PurePosixPath(
    "requirements-container-top-level.lock"
)
DEPLOYMENT_SOURCE_MANIFEST_BUILDER = ROOT / "infra/docker/activate.py"
DEFAULT_MAX_FILE_MIB = 50
MANAGEMENT_PUBKEY_MARKER = ".management-pubkeys"
PROJECT_RESULT_PREFIX = "99-output-"
PROJECT_RESULT_DIRS = {"99-backup-all"}
PROJECT_LEGACY_DIRS = {"old", "staging"}
CODE_TREE_NAMES = {"infra", "ztp", "monitor", "ethernet", "infiniband", "nvlink"}
PROJECT_DEPLOYMENT_INPUTS = {
    "01-global.yaml",
    "02-devices_config.csv",
    "02-dhcp-subnet_config.csv",
}
AIR_TOPOLOGY_POLICY_NAME = "03-air-topology-policy.json"
MINI_AIR_DEVICES_NAME = "04-air-mini-devices.txt"
REPRODUCIBLE_ARCHIVE_MTIME = 0


def _reproducible_tarinfo(info: tarfile.TarInfo) -> tarfile.TarInfo:
    """Remove host- and clock-specific metadata from one archive member."""
    info.mtime = REPRODUCIBLE_ARCHIVE_MTIME
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    if info.islnk():
        # A tar hardlink is an inode-layout optimization, not source content
        # authority.  Emit the member as an independent regular file so two
        # byte-identical trees do not produce different archives merely
        # because one filesystem happened to share an inode.
        info.type = tarfile.REGTYPE
        info.linkname = ""
        info.mode = 0o755 if info.mode & 0o111 else 0o644
    elif info.isdir():
        info.mode = 0o755
    elif info.issym():
        info.mode = 0o777
    elif info.isfile():
        # Preserve the semantic executable bit, not host umask particulars.
        info.mode = 0o755 if info.mode & 0o111 else 0o644
    else:
        raise ValueError(f"unsupported archive source type: {info.name!r}")
    return info


def _materialize_reproducible_tarinfo(
    info: tarfile.TarInfo, metadata: os.stat_result,
) -> tarfile.TarInfo:
    """Materialize a held regular source independently of host inode layout."""
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(
            f"archive source is not a regular file: {info.name!r}",
        )
    if info.islnk():
        info.type = tarfile.REGTYPE
        info.linkname = ""
    elif not info.isfile():
        raise ValueError(
            f"archive source type changed before read: {info.name!r}",
        )
    info.size = metadata.st_size
    info.mode = metadata.st_mode
    return _reproducible_tarinfo(info)


def _source_identity(metadata: os.stat_result) -> tuple[int, ...]:
    """Return the fields that bind one selected source filesystem object."""
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _require_source_identity(
    source: Path, expected: os.stat_result, *, label: str,
) -> os.stat_result:
    """Require the lexical source still names the exact expected object."""
    try:
        current = source.lstat()
    except OSError as exc:
        raise ValueError(
            f"archive source changed {label}: {source}",
        ) from exc
    if _source_identity(current) != _source_identity(expected):
        raise ValueError(f"archive source changed {label}: {source}")
    return current


def _entry_lstat(
    source: Path, *, parent_fd: int | None, entry_name: str | None,
) -> os.stat_result:
    """Inspect an entry without following it or falling back from a dirfd."""
    if parent_fd is None:
        return source.lstat()
    if not entry_name:
        raise ValueError(f"archive child name is missing: {source}")
    return os.stat(entry_name, dir_fd=parent_fd, follow_symlinks=False)


def _require_entry_identity(
    source: Path,
    expected: os.stat_result,
    *,
    parent_fd: int | None,
    entry_name: str | None,
    label: str,
) -> os.stat_result:
    """Require the same entry through its held parent authority."""
    try:
        current = _entry_lstat(
            source, parent_fd=parent_fd, entry_name=entry_name,
        )
    except OSError as exc:
        raise ValueError(
            f"archive source changed {label}: {source}",
        ) from exc
    if _source_identity(current) != _source_identity(expected):
        raise ValueError(f"archive source changed {label}: {source}")
    return current


def _entry_open(
    source: Path,
    flags: int,
    *,
    parent_fd: int | None,
    entry_name: str | None,
) -> int:
    """Open a top-level path or a child relative to its held parent."""
    if parent_fd is None:
        return os.open(source, flags)
    if not entry_name:
        raise ValueError(f"archive child name is missing: {source}")
    return os.open(entry_name, flags, dir_fd=parent_fd)


def _entry_readlink(
    source: Path, *, parent_fd: int | None, entry_name: str | None,
) -> str:
    """Read a symlink only through the same authority used for lstat."""
    if parent_fd is None:
        return os.readlink(source)
    if not entry_name:
        raise ValueError(f"archive child name is missing: {source}")
    return os.readlink(entry_name, dir_fd=parent_fd)


def _tarinfo_from_metadata(
    metadata: os.stat_result, arcname: str, *, linkname: str = "",
) -> tarfile.TarInfo:
    """Build one TarInfo solely from metadata bound by lstat/fstat."""
    info = tarfile.TarInfo(arcname)
    info.mode = metadata.st_mode
    info.uid = metadata.st_uid
    info.gid = metadata.st_gid
    info.mtime = metadata.st_mtime
    if stat.S_ISREG(metadata.st_mode):
        info.type = tarfile.REGTYPE
        info.size = metadata.st_size
    elif stat.S_ISDIR(metadata.st_mode):
        info.type = tarfile.DIRTYPE
    elif stat.S_ISLNK(metadata.st_mode):
        info.type = tarfile.SYMTYPE
        info.linkname = linkname
    elif stat.S_ISFIFO(metadata.st_mode):
        info.type = tarfile.FIFOTYPE
    elif stat.S_ISCHR(metadata.st_mode):
        info.type = tarfile.CHRTYPE
    elif stat.S_ISBLK(metadata.st_mode):
        info.type = tarfile.BLKTYPE
    else:
        raise ValueError(f"unsupported archive source type: {arcname!r}")
    return info


def _digest_held_regular(stream, expected_size: int) -> tuple[int, str]:
    """Hash exactly one bounded held-file snapshot without buffering it."""
    if expected_size < 0:
        raise ValueError("archive source size cannot be negative")
    stream.seek(0)
    digest = hashlib.sha256()
    total = 0
    while total < expected_size:
        chunk = stream.read(min(1024 * 1024, expected_size - total))
        if not chunk:
            raise ValueError("archive source ended before its bound size")
        total += len(chunk)
        digest.update(chunk)
    if stream.read(1):
        raise ValueError("archive source exceeded its bound size")
    return total, digest.hexdigest()


class _HashingBoundedReader:
    """Expose at most the bound bytes while hashing what tar actually reads."""

    def __init__(self, stream, expected_size: int) -> None:
        self._stream = stream
        self._expected_size = expected_size
        self._total = 0
        self._digest = hashlib.sha256()

    def fileno(self) -> int:
        return self._stream.fileno()

    def read(self, size: int = -1) -> bytes:
        remaining = self._expected_size - self._total
        if remaining <= 0:
            return b""
        if size is None or size < 0:
            bounded_size = remaining
        else:
            bounded_size = min(size, remaining)
        chunk = self._stream.read(bounded_size)
        if len(chunk) > bounded_size:
            raise ValueError("archive source reader exceeded its bound")
        self._total += len(chunk)
        self._digest.update(chunk)
        return chunk

    @property
    def result(self) -> tuple[int, str]:
        return self._total, self._digest.hexdigest()


def _add_reproducible_source(
    archive: tarfile.TarFile,
    source: Path,
    arcname: str,
    package_filter: "PackageFilter",
    *,
    recursive: bool = True,
    parent_fd: int | None = None,
    entry_name: str | None = None,
) -> None:
    """Add one entry while retaining its parent/entry filesystem authority."""
    try:
        initial = _entry_lstat(
            source, parent_fd=parent_fd, entry_name=entry_name,
        )
    except OSError as exc:
        raise ValueError(f"cannot inspect archive source: {source}") from exc
    linkname = ""
    if stat.S_ISLNK(initial.st_mode):
        try:
            linkname = _entry_readlink(
                source, parent_fd=parent_fd, entry_name=entry_name,
            )
        except OSError as exc:
            raise ValueError(f"cannot inspect archive symlink: {source}") from exc
    _require_entry_identity(
        source, initial, parent_fd=parent_fd, entry_name=entry_name,
        label="during inspection",
    )
    info = _tarinfo_from_metadata(initial, arcname, linkname=linkname)
    selected = package_filter(info)
    if selected is None:
        return

    if stat.S_ISREG(initial.st_mode):
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        try:
            descriptor = _entry_open(
                source, flags, parent_fd=parent_fd, entry_name=entry_name,
            )
        except OSError as exc:
            raise ValueError(f"cannot bind archive source: {source}") from exc
        try:
            stream = os.fdopen(descriptor, "rb", closefd=True)
        except BaseException:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise
        with stream:
            opened = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or _source_identity(opened) != _source_identity(initial)
            ):
                raise ValueError(
                    f"archive source changed before read: {source}",
                )
            _require_entry_identity(
                source, opened,
                parent_fd=parent_fd, entry_name=entry_name,
                label="before read",
            )
            before_digest = _digest_held_regular(
                stream, opened.st_size,
            )
            before_add = os.fstat(stream.fileno())
            if _source_identity(before_add) != _source_identity(opened):
                raise ValueError(
                    f"archive source changed during pre-read: {source}",
                )
            _require_entry_identity(
                source, before_add,
                parent_fd=parent_fd, entry_name=entry_name,
                label="after pre-read",
            )
            stream.seek(0)
            held_info = _tarinfo_from_metadata(opened, arcname)
            held_info = _materialize_reproducible_tarinfo(held_info, opened)
            selected_held = package_filter(held_info)
            if selected_held is None:
                return

            archive_reader = _HashingBoundedReader(
                stream, opened.st_size,
            )
            archive.addfile(selected_held, fileobj=archive_reader)
            if archive_reader.result != before_digest:
                raise ValueError(
                    f"archive source content changed during read: {source}",
                )
            after_read = os.fstat(stream.fileno())
            if _source_identity(after_read) != _source_identity(opened):
                raise ValueError(
                    f"archive source changed during read: {source}",
                )
            _require_entry_identity(
                source, after_read,
                parent_fd=parent_fd, entry_name=entry_name,
                label="after read",
            )
            after_digest = _digest_held_regular(
                stream, opened.st_size,
            )
            final = os.fstat(stream.fileno())
            if (
                after_digest != before_digest
                or _source_identity(final) != _source_identity(opened)
            ):
                raise ValueError(
                    f"archive source changed during verification: {source}",
                )
            _require_entry_identity(
                source, final,
                parent_fd=parent_fd, entry_name=entry_name,
                label="after verification",
            )
        return

    normalized = _reproducible_tarinfo(selected)
    if normalized.isdir():
        flags = (
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
            | os.O_NOFOLLOW | os.O_NONBLOCK
        )
        try:
            descriptor = _entry_open(
                source, flags, parent_fd=parent_fd, entry_name=entry_name,
            )
        except OSError as exc:
            raise ValueError(
                f"cannot bind archive source directory: {source}",
            ) from exc
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or _source_identity(opened) != _source_identity(initial)
            ):
                raise ValueError(
                    f"archive source directory changed before read: {source}",
                )
            _require_entry_identity(
                source, opened,
                parent_fd=parent_fd, entry_name=entry_name,
                label="before directory read",
            )
            archive.addfile(normalized)
            _require_entry_identity(
                source, opened,
                parent_fd=parent_fd, entry_name=entry_name,
                label="after directory header",
            )
            if recursive:
                try:
                    children = sorted(os.listdir(descriptor))
                except OSError as exc:
                    raise ValueError(
                        f"cannot enumerate archive source directory: {source}",
                    ) from exc
                for child in children:
                    _add_reproducible_source(
                        archive,
                        source / child,
                        os.path.join(arcname, child),
                        package_filter,
                        recursive=True,
                        parent_fd=descriptor,
                        entry_name=child,
                    )
            after = os.fstat(descriptor)
            if _source_identity(after) != _source_identity(opened):
                raise ValueError(
                    f"archive source directory changed during read: {source}",
                )
            _require_entry_identity(
                source, after,
                parent_fd=parent_fd, entry_name=entry_name,
                label="after directory read",
            )
        finally:
            try:
                os.close(descriptor)
            except OSError:
                pass
        return

    archive.addfile(normalized)
    _require_entry_identity(
        source, initial, parent_fd=parent_fd, entry_name=entry_name,
        label="after symlink read",
    )
    if normalized.issym():
        try:
            final_linkname = _entry_readlink(
                source, parent_fd=parent_fd, entry_name=entry_name,
            )
        except OSError as exc:
            raise ValueError(f"archive symlink changed: {source}") from exc
        if final_linkname != linkname:
            raise ValueError(f"archive symlink changed: {source}")


def _special_tarinfo(relative: str, metadata: os.stat_result) -> tarfile.TarInfo:
    """Build the minimal filter input for a non-regular filesystem object."""
    info = tarfile.TarInfo(f"./{relative}")
    info.mode = stat.S_IMODE(metadata.st_mode)
    info.size = metadata.st_size
    if stat.S_ISFIFO(metadata.st_mode):
        info.type = tarfile.FIFOTYPE
    elif stat.S_ISCHR(metadata.st_mode):
        info.type = tarfile.CHRTYPE
    elif stat.S_ISBLK(metadata.st_mode):
        info.type = tarfile.BLKTYPE
    else:
        info.type = b"?"
    return info


def _reject_selected_special_sources(package_filter: "PackageFilter") -> None:
    """Fail before creating an archive temp when policy selects a special node."""
    root = ROOT.resolve(strict=True)

    def walk_error(exc: OSError) -> None:
        raise ValueError(f"cannot inspect archive source tree: {exc}") from exc

    for directory, dirnames, filenames in os.walk(
        root, topdown=True, followlinks=False, onerror=walk_error,
    ):
        dirnames.sort()
        filenames.sort()
        parent = Path(directory)
        for name in (*dirnames, *filenames):
            source = parent / name
            try:
                metadata = source.lstat()
            except OSError as exc:
                raise ValueError(
                    f"cannot inspect archive source: {source}",
                ) from exc
            if (
                stat.S_ISREG(metadata.st_mode)
                or stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
            ):
                continue
            relative = source.relative_to(root).as_posix()
            info = _special_tarinfo(relative, metadata)
            prior_files = package_filter.excluded_files
            prior_bytes = package_filter.excluded_bytes
            prior_reasons = dict(package_filter.reasons)
            try:
                selected = package_filter(info)
            finally:
                package_filter.excluded_files = prior_files
                package_filter.excluded_bytes = prior_bytes
                package_filter.reasons = prior_reasons
            if selected is not None:
                raise ValueError(
                    f"unsupported selected archive source type: {relative}",
                )


def _package_uses_stored_gzip(
    args: argparse.Namespace, project: Path, *, day0_all: bool,
) -> bool:
    """Return whether an included already-compressed payload forbids deflate.

    A gzip container with level-zero stored blocks preserves the established
    ``.tar.gz`` transport contract while avoiding minutes of futile deflate
    work for switch images, firmware, offline packages, and project ``.bin``
    images.
    """
    if args.include_images or args.include_apps or args.include_firmware:
        return True
    if getattr(args, "exclude_project_images", False):
        return False
    projects = (
        (item for item in DAY0.iterdir() if item.is_dir())
        if day0_all else (project,)
    )
    return any(
        any(
            candidate.is_file() and candidate.stat().st_size > 0
            for candidate in item.glob("*.bin")
        )
        for item in projects
    )


def _read_frozen_regular_bytes(
    path: Path, label: str, *, maximum_size: int = 4 * 1024 * 1024,
) -> bytes:
    """Read one local authority file from a single no-follow descriptor."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        before_path = path.lstat()
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"cannot open {label}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before_path.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before_path.st_nlink != 1
            or before.st_nlink != 1
            or (before_path.st_dev, before_path.st_ino)
            != (before.st_dev, before.st_ino)
            or before.st_size <= 0
            or before.st_size > maximum_size
        ):
            raise ValueError(f"{label} must be one bounded regular file")
        chunks = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                raise ValueError(f"{label} changed while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError(f"{label} grew while reading")
        after = os.fstat(descriptor)
        if (
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        ):
            raise ValueError(f"{label} changed while reading")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def deployment_prewrite_guard_source(authority_manifest: Path) -> str:
    """Freeze the guard bytes and verify them against the release authority."""
    manifest_bytes = _read_frozen_regular_bytes(
        authority_manifest, "deployment source manifest",
    )
    try:
        payload = json.loads(manifest_bytes.decode("ascii"))
        records = payload["files"]
    except (UnicodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ValueError(f"deployment source manifest is invalid: {exc}") from exc
    matches = [
        record for record in records
        if isinstance(record, dict)
        and record.get("path") == "tools/deployment_prewrite_guard.py"
    ]
    if len(matches) != 1 or matches[0].get("type") != "file":
        raise ValueError("deployment source manifest does not bind the prewrite guard")
    source = _read_frozen_regular_bytes(
        DEPLOYMENT_PREWRITE_GUARD, "deployment prewrite guard",
    )
    if hashlib.sha256(source).hexdigest() != matches[0].get("sha256"):
        raise ValueError(
            "deployment prewrite guard changed after source manifest generation"
        )
    try:
        return source.decode("utf-8")
    except UnicodeError as exc:
        raise ValueError(f"deployment prewrite guard is not UTF-8: {exc}") from exc

RELATIONSHIP_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
OFFICE_REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
DRAWING_NS = "http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing"
VML_NS = "urn:schemas-microsoft-com:vml"


def write_deployment_source_manifest(destination: Path) -> Path:
    """Generate the local authority receipt that a remote image may verify.

    The remote overlay must never generate this receipt for itself: stale
    dynamically discovered source would otherwise become trusted at build
    time.  Both sync and tar call this helper before contacting the server.
    """
    if not DEPLOYMENT_SOURCE_MANIFEST_BUILDER.is_file():
        raise RuntimeError(
            f"deployment source manifest builder missing: "
            f"{DEPLOYMENT_SOURCE_MANIFEST_BUILDER}"
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [
            sys.executable, "-B", os.fspath(DEPLOYMENT_SOURCE_MANIFEST_BUILDER),
            "build-source-manifest", "--source-root", os.fspath(ROOT),
            "--manifest", os.fspath(destination),
        ],
        cwd=ROOT, capture_output=True, text=True, check=False,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    if result.returncode != 0:
        detail = str(result.stderr or result.stdout or "").strip()
        raise RuntimeError(
            "cannot generate local deployment source manifest"
            + (f": {detail}" if detail else f" (exit={result.returncode})")
        )
    try:
        metadata = destination.lstat()
    except OSError as exc:
        raise RuntimeError(f"deployment source manifest was not created: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size == 0:
        raise RuntimeError("deployment source manifest must be one non-empty regular file")
    return destination


def is_transport_archive_name(name: str) -> bool:
    return any(fnmatch.fnmatch(name, pattern) for pattern in (
        "http-air-simulation-*.tar.gz",
        "http-air-upload-*.tar.gz",
        "http-air-download-*.tar.gz",
        "*-????????-??????-upload.tar.gz",
        "*-????????-??????-download.tar.gz",
    ))


def classify_project_entry(relative: PurePosixPath | str) -> str:
    """Classify a path below one DAY0 project using the shared data contract."""
    path = PurePosixPath(relative)
    if not path.parts:
        return "project-root"
    if any(part == ".DS_Store" or part.startswith("._") for part in path.parts):
        return "metadata"
    if path.parts[0] in PROJECT_LEGACY_DIRS:
        return "legacy"
    if path.name == MANAGEMENT_PUBKEY_MARKER:
        return "runtime-security"
    if is_transport_archive_name(path.name):
        return "transport-artifact"
    if path.parts[0].startswith(PROJECT_RESULT_PREFIX) or path.parts[0] in PROJECT_RESULT_DIRS:
        return "result-data"
    return "planning-input"


def project_directories() -> list[Path]:
    """Return real DAY0 project directories, excluding templates/tests/dumps."""
    return sorted(
        item for item in DAY0.iterdir()
        if item.is_dir() and not item.is_symlink()
        and item.name not in {"template", "tests", "test_cases", "dumps"}
        and not item.name.startswith(".")
        and (item / "01-global.yaml").is_file()
        and (item / "02-devices_config.csv").is_file()
    )


def setup_managed_links() -> set[str]:
    """Return manifest-owned and detectable project-runtime links."""
    result: set[str] = set(STATIC_SETUP_MANAGED_LINKS)
    root = ROOT.resolve()
    if MANIFEST.is_file():
        for line in MANIFEST.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines():
            if not line or line.startswith("#"):
                continue
            try:
                candidate = Path(line)
                if not candidate.is_absolute():
                    candidate = root / candidate
                result.add(candidate.relative_to(root).as_posix())
            except (OSError, ValueError):
                continue
    # A custom common.mgmt.ztp.ztp_url_prefix is published by load as a
    # host-owned symlink.  Validate its ownership marker even when a setup
    # manifest was found; otherwise the early return below could package or
    # sync this management-server runtime path.
    prefix_link = ztp_prefix_publication_relative(root)
    if prefix_link is not None:
        result.add(prefix_link.as_posix())
    if result:
        return result
    day0 = DAY0.resolve()
    for name in CODE_TREE_NAMES:
        code_root = ROOT / name
        if not code_root.is_dir():
            continue
        for candidate in code_root.rglob("*"):
            if not candidate.is_symlink():
                continue
            try:
                candidate.resolve().relative_to(day0)
                result.add(candidate.relative_to(ROOT).as_posix())
            except (OSError, ValueError):
                continue
    return result


def managed_pubkey_paths(projects: list[Path]) -> set[Path]:
    """Return runtime-injected public keys that must never enter an archive."""
    paths: set[Path] = set()
    for project in projects:
        marker = project / MANAGEMENT_PUBKEY_MARKER
        if not marker.is_file():
            continue
        for line in marker.read_text(encoding="utf-8", errors="replace").splitlines():
            name = line.strip()
            if name.endswith(".pub") and Path(name).name == name:
                paths.add(project / name)
    return paths


def human_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def select_upload_p2p(project: Path) -> Path:
    """Select the same deployable P2P workbook used by setup/load.

    A setup-managed ``p2p.xlsx`` symlink is resolved to its real project file,
    because runtime links are deliberately excluded from upload archives.  The
    selected source must remain in the project root or its ``p2p/`` directory.
    """
    project = project.resolve()
    canonical = project / "p2p.xlsx"
    if canonical.is_file() and canonical.stat().st_size > 0:
        selected = canonical.resolve()
    else:
        version_dir = project / "p2p"
        version_candidates = [
            item for item in version_dir.iterdir()
            if item.is_file()
            and not item.name.startswith(("~$", "._"))
            and item.name.casefold().endswith(".xlsx")
            and "p2p" in item.name.casefold()
            and item.stat().st_size > 0
        ] if version_dir.is_dir() else []
        if version_candidates:
            selected = max(
                version_candidates,
                key=lambda item: (item.stat().st_mtime_ns, item.name.casefold()),
            ).resolve()
        else:
            candidates = [
                item.resolve() for item in sorted(project.iterdir())
                if item.is_file()
                and not item.name.startswith(("~$", "._"))
                and item.name.casefold().endswith(".xlsx")
                and "p2p" in item.name.casefold()
                and item.stat().st_size > 0
            ]
            if len(candidates) != 1:
                names = ", ".join(item.name for item in candidates) or "none"
                raise ValueError(
                    "upload requires one non-empty P2P XLSX; "
                    f"candidates: {names}"
                )
            selected = candidates[0]
    if selected.parent not in {project, project / "p2p"}:
        raise ValueError(f"selected P2P workbook is outside the project input roots: {selected}")
    if selected.suffix.casefold() != ".xlsx" or not zipfile.is_zipfile(selected):
        raise ValueError(f"selected P2P input is not a valid XLSX: {selected}")
    with zipfile.ZipFile(selected) as archive:
        if archive.testzip() is not None or "xl/workbook.xml" not in archive.namelist():
            raise ValueError(f"selected P2P XLSX is corrupt or incomplete: {selected}")
    return selected


def optional_air_topology_policy(project: Path) -> Path | None:
    """Return the optional deployable AIR policy without following aliases."""
    policy = project / AIR_TOPOLOGY_POLICY_NAME
    try:
        mode = policy.lstat().st_mode
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ValueError(f"cannot inspect {AIR_TOPOLOGY_POLICY_NAME}: {exc}") from exc
    if not stat.S_ISREG(mode):
        raise ValueError(
            f"{AIR_TOPOLOGY_POLICY_NAME} must be a regular file: {policy}"
        )
    return policy


def optional_mini_air_devices(project: Path) -> Path | None:
    """Return the optional canonical mini AIR list without following aliases."""
    devices = project / MINI_AIR_DEVICES_NAME
    try:
        metadata = devices.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ValueError(f"cannot inspect {MINI_AIR_DEVICES_NAME}: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError(
            f"{MINI_AIR_DEVICES_NAME} must be a single-link regular file: {devices}"
        )
    if metadata.st_size == 0:
        raise ValueError(f"{MINI_AIR_DEVICES_NAME} must not be empty: {devices}")
    return devices


def _relationship_owner(name: str) -> str:
    """Map an OPC ``_rels/<part>.rels`` name to the owning part."""
    path = PurePosixPath(name)
    if path.parent.name != "_rels" or not path.name.endswith(".rels"):
        raise ValueError(f"unsupported XLSX relationship path: {name}")
    return (path.parent.parent / path.name.removesuffix(".rels")).as_posix()


def _has_relationship_id(element: ET.Element, relationship_ids: set[str]) -> bool:
    relationship_prefix = "{" + OFFICE_REL_NS + "}"
    return any(
        key.startswith(relationship_prefix) and value in relationship_ids
        for node in element.iter() for key, value in node.attrib.items()
    )


def _remove_image_nodes(owner_name: str, payload: bytes, relationship_ids: set[str]) -> tuple[bytes, int]:
    """Remove drawing anchors/VML shapes that reference deleted images."""
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise ValueError(f"cannot parse XLSX drawing part {owner_name}: {exc}") from exc
    removed = 0
    if owner_name.startswith("xl/drawings/") and owner_name.endswith(".xml"):
        allowed = {
            f"{{{DRAWING_NS}}}oneCellAnchor",
            f"{{{DRAWING_NS}}}twoCellAnchor",
            f"{{{DRAWING_NS}}}absoluteAnchor",
        }
        for child in list(root):
            if child.tag in allowed and _has_relationship_id(child, relationship_ids):
                root.remove(child)
                removed += 1
    elif owner_name.endswith(".vml"):
        shape_tag = f"{{{VML_NS}}}shape"
        for parent in root.iter():
            for child in list(parent):
                if child.tag == shape_tag and _has_relationship_id(child, relationship_ids):
                    parent.remove(child)
                    removed += 1
    else:
        raise ValueError(
            "XLSX image relationship belongs to an unsupported part; "
            f"refusing to create a broken workbook: {owner_name}"
        )
    if removed == 0:
        raise ValueError(
            f"XLSX image relationships are not referenced by removable nodes: {owner_name}"
        )
    return ET.tostring(root, encoding="utf-8", xml_declaration=True), removed


def strip_xlsx_images(source: Path, destination: Path) -> dict[str, int]:
    """Write an image-free XLSX copy without modifying *source*.

    Image payloads, their OPC relationships, and the corresponding spreadsheet
    drawing anchors are removed together.  Unsupported image owners fail closed
    instead of producing a workbook with dangling relationships.
    """
    source = source.resolve(strict=True)
    source_digest = sha256(source)
    transformed: dict[str, bytes] = {}
    image_files: set[str] = set()
    removed_relationships = 0
    removed_nodes = 0
    with zipfile.ZipFile(source, "r") as input_archive:
        names = input_archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError(f"XLSX contains duplicate ZIP members: {source}")
        if input_archive.testzip() is not None or "xl/workbook.xml" not in names:
            raise ValueError(f"XLSX is corrupt or missing xl/workbook.xml: {source}")
        image_files = {name for name in names if name.startswith("xl/media/") and not name.endswith("/")}
        for relation_name in (name for name in names if name.endswith(".rels")):
            payload = input_archive.read(relation_name)
            try:
                root = ET.fromstring(payload)
            except ET.ParseError as exc:
                raise ValueError(f"cannot parse XLSX relationships {relation_name}: {exc}") from exc
            removed_ids: set[str] = set()
            for relationship in list(root):
                rel_type = relationship.attrib.get("Type", "")
                target = relationship.attrib.get("Target", "")
                owner = _relationship_owner(relation_name)
                resolved_target = posixpath.normpath(
                    posixpath.join(posixpath.dirname(owner), target)
                )
                if rel_type.endswith("/image") or resolved_target.startswith("xl/media/"):
                    rel_id = relationship.attrib.get("Id")
                    if not rel_id:
                        raise ValueError(f"image relationship has no Id: {relation_name}")
                    removed_ids.add(rel_id)
                    root.remove(relationship)
            if not removed_ids:
                continue
            removed_relationships += len(removed_ids)
            owner_name = _relationship_owner(relation_name)
            if owner_name not in names:
                raise ValueError(f"XLSX image relationship owner is missing: {owner_name}")
            owner_payload, count = _remove_image_nodes(
                owner_name, input_archive.read(owner_name), removed_ids,
            )
            if owner_name in transformed:
                raise ValueError(f"multiple image relationship parts target one owner: {owner_name}")
            transformed[owner_name] = owner_payload
            transformed[relation_name] = ET.tostring(
                root, encoding="utf-8", xml_declaration=True,
            )
            removed_nodes += count

        destination.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(destination, "w", allowZip64=True) as output_archive:
            for info in input_archive.infolist():
                if info.filename in image_files:
                    continue
                output_archive.writestr(info, transformed.get(info.filename, input_archive.read(info.filename)))
    destination.chmod(0o600)

    if sha256(source) != source_digest:
        raise RuntimeError(f"source P2P workbook changed while packaging: {source}")
    with zipfile.ZipFile(destination, "r") as verification:
        bad = verification.testzip()
        if bad is not None:
            raise RuntimeError(f"image-free P2P workbook failed ZIP verification at {bad}")
        if "xl/workbook.xml" not in verification.namelist():
            raise RuntimeError("image-free P2P workbook is missing xl/workbook.xml")
        if any(name.startswith("xl/media/") for name in verification.namelist()):
            raise RuntimeError("image-free P2P workbook still contains xl/media entries")
        for name in (item for item in verification.namelist() if item.endswith(".rels")):
            root = ET.fromstring(verification.read(name))
            if any(child.attrib.get("Type", "").endswith("/image") for child in root):
                raise RuntimeError(f"image-free P2P workbook still contains image relationships: {name}")
    return {
        "images": len(image_files),
        "relationships": removed_relationships,
        "drawing_nodes": removed_nodes,
        "source_size": source.stat().st_size,
        "output_size": destination.stat().st_size,
    }


def active_project() -> Path | None:
    if not MANIFEST.is_file():
        return None
    first = MANIFEST.read_text(encoding="utf-8", errors="replace").splitlines()[:1]
    if not first or "proj:" not in first[0]:
        return None
    candidate = Path(first[0].split("proj:", 1)[1].strip()).expanduser()
    try:
        candidate = candidate.resolve()
        candidate.relative_to(DAY0.resolve())
    except (OSError, ValueError):
        return None
    return candidate if candidate.is_dir() else None


def resolve_project(value: str | None) -> Path:
    if value:
        project = Path(value).expanduser()
        if not project.is_absolute():
            direct = (ROOT / project).resolve()
            project = direct if direct.is_dir() else (DAY0 / project).resolve()
        else:
            project = project.resolve()
    else:
        project = active_project()
        if project is None:
            candidates = project_directories()
            if len(candidates) != 1:
                names = ", ".join(item.name for item in candidates) or "none"
                raise ValueError(
                    "cannot determine the project without a valid setup manifest; "
                    f"use --project (candidates: {names})"
                )
            project = candidates[0]
    try:
        project.relative_to(DAY0.resolve())
    except ValueError as exc:
        raise ValueError(f"project must be under {DAY0}: {project}") from exc
    if not project.is_dir() or project == DAY0:
        raise ValueError(f"deployment project does not exist: {project}")
    return project


def directory_size(root: Path) -> int:
    total = 0
    for path in root.rglob("*"):
        try:
            if path.is_file() and not path.is_symlink():
                total += path.stat().st_size
        except OSError:
            pass
    return total


def deployment_archive_source_paths(source_root: Path) -> tuple[str, ...]:
    """Return deployable source paths selected specifically by archive policy."""
    try:
        root = source_root.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"cannot inspect archive source root: {exc}") from exc
    selected: set[str] = set()
    tools_root = root / "tools"
    if not tools_root.is_dir():
        raise ValueError("archive source tree is incomplete: tools")
    for candidate in tools_root.rglob("*"):
        if not candidate.is_file() or candidate.is_symlink():
            continue
        relative = candidate.relative_to(root)
        if transfer_exclude_reason(relative) is None and is_tools_deployable_file(relative):
            selected.add(relative.as_posix())
    return tuple(sorted(selected))


class PackageFilter:
    def __init__(
        self,
        project: Path,
        output: Path,
        *,
        include_images: bool,
        include_apps: bool,
        apps_platform: str | None = None,
        apps_platforms: set[str] | None = None,
        include_firmware: bool,
        max_file_size: int,
        day0_all: bool = True,
        selected_p2p_relative: PurePosixPath | None = None,
        exclude_project_images: bool = False,
        artifact_kind: str = "upload",
    ) -> None:
        self.project_rel = project.relative_to(ROOT).as_posix()
        self.output = output.resolve()
        self.excluded_paths = {self.output}
        self.include_images = include_images
        self.include_apps = include_apps
        self.apps_platforms = set(apps_platforms or ())
        if apps_platform:
            self.apps_platforms.add(apps_platform)
        self.include_firmware = include_firmware
        self.max_file_size = max_file_size
        self.day0_all = day0_all
        self.selected_p2p_relative = selected_p2p_relative
        self.exclude_project_images = exclude_project_images
        self.artifact_kind = artifact_kind
        projects = [
            item for item in DAY0.iterdir() if item.is_dir()
        ] if day0_all else [project]
        self.managed_pubkeys = {
            item.relative_to(ROOT).as_posix()
            for item in managed_pubkey_paths(projects)
        }
        self.runtime_setup_links = setup_managed_links()
        self.excluded_files = 0
        self.excluded_bytes = 0
        self.reasons: dict[str, int] = {}

    def reject(self, info: tarfile.TarInfo, reason: str) -> None:
        self.excluded_files += 1 if info.isfile() else 0
        self.excluded_bytes += info.size if info.isfile() else 0
        self.reasons[reason] = self.reasons.get(reason, 0) + 1

    def __call__(self, info: tarfile.TarInfo) -> tarfile.TarInfo | None:
        name = info.name.removeprefix("./")
        path = PurePosixPath(name)
        parts = path.parts
        source_path = ROOT / name

        try:
            if source_path.resolve() in self.excluded_paths:
                self.reject(info, "output archive")
                return None
        except OSError:
            pass

        if not name:
            return info

        disposition = path_disposition(path)
        if disposition != "production":
            self.reject(
                info,
                "reference-only input"
                if disposition == "reference-only"
                else "test/development data",
            )
            return None

        if path == DEPLOYMENT_SOURCE_MANIFEST_RELATIVE:
            # A possibly stale worktree copy is never authoritative.  The
            # freshly generated local receipt is injected exactly once below.
            self.reject(info, "generated deployment source manifest")
            return None

        if (
            self.artifact_kind != "upload"
            and path in DEPLOYMENT_AUTHORITY_RELATIVES
        ):
            self.reject(info, "deployment authority reserved for upload")
            return None

        if not self.day0_all and (
            path.suffix.casefold() == ".md"
            or path.name.casefold().startswith("readme")
            or path.name == "USER_MANUAL.md"
        ):
            self.reject(info, "documentation not consumed at runtime")
            return None
        if not self.day0_all and name == ".deployment.lock":
            self.reject(info, "host runtime lock")
            return None
        if path == CONTAINER_TOPLEVEL_LOCK_RELATIVE:
            if info.isfile() and 0 < info.size <= 64 * 1024:
                return info
            self.reject(info, "unsafe container top-level lock")
            return None
        if path.suffix.casefold() == ".lock":
            self.reject(info, "host runtime lock")
            return None

        # Apply the shared metadata/development boundary before any subtree
        # allowlist returns early. In particular, deployable tool subtrees
        # must never carry a nested .git/.codex/.agents/Codex scratch tree.
        shared_reason = transfer_exclude_reason(path)
        if shared_reason:
            self.reject(info, shared_reason)
            return None

        # tools/ normally contributes only top-level runtime source files.
        # README files are excluded by the shared transfer contract.
        # lldp-analyze-tool is the exception because Ethernet cron invokes it
        # on the management server.  Keep its small source/dependency manifest,
        # but never package node_modules, setup links, or generated reports.
        if parts and parts[0] == "tools":
            if name == "tools":
                return info
            if len(parts) >= 2 and parts[1] == "lldp-analyze-tool":
                if len(parts) == 2 and info.isdir():
                    return info
                if any(part in {"node_modules", "99-output-p2p", "99-output-monitor"}
                       for part in parts[2:]):
                    self.reject(info, "lldp analyzer runtime/output")
                    return None
                if (
                    path == PurePosixPath(
                        "tools/lldp-analyze-tool/04-lldp-device-aliases.json"
                    )
                    and info.isfile()
                ):
                    return info
                if info.isdir() or (info.isfile() and is_tools_deployable_file(path)):
                    return info
                self.reject(info, "non-deployable lldp analyzer content")
                return None
            if len(parts) == 2 and info.isfile() and is_tools_deployable_file(path):
                return info
            self.reject(info, "non-deployable tools content")
            return None

        if name in {
            "ztp/ztp-bootstrap_oob.sh",
            "ztp/ztp-bootstrap_oobofoob.sh",
            "ztp/ztp.json",
        }:
            self.reject(info, "load-rendered ZTP runtime")
            return None

        # Manual planning-file copies are useful in a downloaded project
        # archive, but are not inputs consumed by a management-server deploy.
        if not self.day0_all and is_manual_backup_name(path.name):
            self.reject(info, "manual project backup")
            return None

        if name in self.managed_pubkeys:
            self.reject(info, "management-server public key")
            return None

        if info.issym() and name in self.runtime_setup_links:
            self.reject(info, "setup-managed runtime link")
            return None

        # DAY0-Prepare is the download/archive data boundary. Keep complete
        # project history and internal result links, but omit rebuildable
        # 99-output-*/latest control links so a live writer cannot publish a
        # target that was not fully captured in the archive.
        if self.day0_all and (name == "DAY0-Prepare" or name.startswith("DAY0-Prepare/")):
            if name == "DAY0-Prepare/dumps" or name.startswith("DAY0-Prepare/dumps/"):
                self.reject(info, "transport archive directory")
                return None
            if classify_project_entry(PurePosixPath(name).name) in {
                "metadata", "runtime-security", "transport-artifact",
            }:
                self.reject(info, "project metadata/transport artifact")
                return None
            if (info.issym() and path.name == "latest"
                    and any(part.startswith("99-output-") for part in parts)):
                self.reject(info, "rebuildable latest link")
                return None
            return info

        if name == "package-imports" or name.startswith("package-imports/"):
            self.reject(info, "local package import review")
            return None
        if path.name.endswith(".bak"):
            self.reject(info, "cache/backup file")
            return None
        if is_transport_archive_name(path.name):
            self.reject(info, "previous package")
            return None

        if name == "ztp/.setup_manifest":
            self.reject(info, "host-specific setup manifest")
            return None
        if name == "ztp/old" or name.startswith("ztp/old/"):
            self.reject(info, "legacy ZTP tree")
            return None
        if name == "ztp/optimize" or name.startswith("ztp/optimize/"):
            # optimize is production code, but its *-sample directories,
            # reports and issue-tracker material are runtime/development data.
            # Keep production Python/Shell source while omitting tests and
            # non-code/runtime data through the shared exclusion contract.
            optimize_parts = parts[2:]
            if (
                any(part.casefold().endswith("-sample") for part in optimize_parts)
                or (optimize_parts and optimize_parts[0] == "issue-tracker")
            ):
                self.reject(info, "optimize non-code/runtime data")
                return None
            if info.isdir() or (
                info.isfile() and path.suffix.casefold() in {".py", ".sh"}
            ):
                return info
            self.reject(info, "optimize non-code/runtime data")
            return None
        if (
            name in {"test", "tests", "test_cases"}
            or name.startswith(("test/", "tests/", "test_cases/"))
        ):
            self.reject(info, "local integration artifact")
            return None
        if name == "monitor/monitor.html":
            self.reject(info, "generated monitor page")
            return None
        if path.name in {"cronjob.log", "generate-monitor.log"}:
            self.reject(info, "runtime monitor log")
            return None
        if not self.include_apps and (name == "apps" or name.startswith("apps/")):
            if name != "apps":
                self.reject(info, "offline APT cache")
                return None
        if self.include_apps and self.apps_platforms and name.startswith("apps/"):
            selected_paths = [
                PurePosixPath("apps") / platform
                for platform in self.apps_platforms
            ]
            if not any(
                parts == ("apps",)
                or parts == selected.parts[:len(parts)]
                or parts[:len(selected.parts)] == selected.parts
                for selected in selected_paths
            ):
                self.reject(info, "other OS/architecture APT cache")
                return None
        if not self.include_images and (
            name.startswith("image/") or name.startswith("ztp/image/")
        ):
            self.reject(info, "switch image")
            return None
        if not self.include_firmware and name.startswith("firmware/"):
            self.reject(info, "firmware payload")
            return None

        large_sample_prefixes = (
            "ztp/config/nvos/template/P2P/ib-tool-Jie/var/tmp/",
            "ztp/config/nvos/template/P2P/ibdiagnet-analyze-tool/test-results/",
        )
        if name.startswith(large_sample_prefixes):
            self.reject(info, "analysis sample/result")
            return None
        if name.startswith("infra/logs/") or name.startswith("infra/collected/"):
            self.reject(info, "infra runtime output")
            return None

        # Upload packages are executable deployment inputs, not workstation
        # archives.  Exclude bulky reference captures from otherwise deployable
        # code trees; source/template formats continue through. README files
        # have already been rejected by the shared transfer contract.
        if (
            not self.day0_all and parts and parts[0] in CODE_TREE_NAMES
            and (
                ".claude" in parts
                or path.suffix.casefold() in {".docx", ".pdf", ".xlsx"}
                or (
                    path.suffix.casefold() == ".log"
                    and name.startswith("infiniband/bringup/ndr/")
                )
            )
        ):
            self.reject(info, "non-code reference artifact")
            return None

        # Upload/deployment packages retain only the selected DAY0 project and
        # omit every generated 99-output-* payload. Download/archive packages returned above
        # before reaching these rules and therefore keep the complete DAY0 tree.
        if len(parts) == 2 and parts[0] == "DAY0-Prepare" and info.isdir():
            candidate = "/".join(parts[:2])
            project_name = parts[1]
            if (
                project_name not in {"template", "tests", "test_cases"}
                and candidate != self.project_rel
            ):
                self.reject(info, "other deployment project")
                return None

        # Topology analyzers create convenience symlinks in 99-output-p2p that
        # point back into monitor history.  Upload packages deliberately omit
        # that history, so retaining these links would create guaranteed broken
        # paths on the management server.  Reports and generated files remain.
        if (
            not self.day0_all and info.issym()
            and name.startswith(f"{self.project_rel}/99-output-p2p/")
        ):
            self.reject(info, "runtime topology input link")
            return None

        project_parts = PurePosixPath(self.project_rel).parts
        project_relative = PurePosixPath(*parts[len(project_parts):])
        if (
            len(parts) > len(project_parts) + 1
            and parts[:len(project_parts)] == project_parts
            and classify_project_entry(project_relative) == "result-data"
        ):
            self.reject(info, "runtime/historical project output")
            return None
        if (
            parts[:len(project_parts)] == project_parts
            and classify_project_entry(project_relative) in {
                "metadata", "legacy", "runtime-security", "transport-artifact",
            }
        ):
            self.reject(info, "non-deployable project entry")
            return None

        # A deploy upload keeps only files consumed by setup/load.  Arbitrary
        # planning attachments and alternate XLSX workbooks do not belong on
        # the management server.  The selected P2P workbook is injected later
        # as an image-free temporary copy at its original project path.
        if not self.day0_all and parts[:len(project_parts)] == project_parts:
            if info.isdir():
                return info
            if info.issym():
                self.reject(info, "non-deployable project link")
                return None
            if project_relative == self.selected_p2p_relative:
                self.reject(info, "P2P source replaced without images")
                return None
            if len(project_relative.parts) == 1:
                filename = project_relative.name
                if (
                    filename in PROJECT_DEPLOYMENT_INPUTS
                    or filename == AIR_TOPOLOGY_POLICY_NAME
                    or filename == MINI_AIR_DEVICES_NAME
                ):
                    return info
                if filename.casefold().endswith(".pub"):
                    return info
                if filename.casefold().endswith(".bin"):
                    if self.exclude_project_images:
                        self.reject(info, "shared switch image externalized")
                        return None
                    return info
            self.reject(info, "unused project planning attachment")
            return None

        explicitly_included_large_tree = (
            self.include_apps and name.startswith("apps/")
        ) or (
            self.include_images
            and (name.startswith("image/") or name.startswith("ztp/image/"))
        ) or (
            self.include_firmware and name.startswith("firmware/")
        )
        if (
            info.isfile() and self.max_file_size > 0
            and info.size > self.max_file_size
            and not explicitly_included_large_tree
        ):
            self.reject(info, "generic large file")
            return None
        return info


def _normalized_archive_parts(path: PurePosixPath) -> tuple[str, ...] | None:
    """Lexically normalize one archive path, returning None on root escape."""
    normalized: list[str] = []
    for part in path.parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not normalized:
                return None
            normalized.pop()
        else:
            normalized.append(part)
    return tuple(normalized)


def validate_deployment_archive_members(members: list[tarfile.TarInfo]) -> None:
    """Reject payloads that root extraction must never be asked to consume."""
    seen: set[tuple[str, ...]] = set()
    for member in members:
        member_path = PurePosixPath(member.name)
        if member_path.is_absolute() or ".." in member_path.parts:
            raise RuntimeError(f"unsafe archive member path: {member.name!r}")
        normalized = _normalized_archive_parts(member_path)
        if not normalized:
            raise RuntimeError(f"empty archive member path: {member.name!r}")
        if normalized in seen:
            raise RuntimeError(f"duplicate archive member path: {member.name!r}")
        seen.add(normalized)
        if not (member.isdir() or member.isfile() or member.issym()):
            raise RuntimeError(
                f"unsupported archive member type: {member.name!r}"
            )
        if not member.issym():
            continue
        target = PurePosixPath(member.linkname)
        if not member.linkname or target.is_absolute():
            raise RuntimeError(
                f"unsafe archive symlink target: {member.name!r} -> "
                f"{member.linkname!r}"
            )
        resolved_target = _normalized_archive_parts(member_path.parent / target)
        if not resolved_target:
            raise RuntimeError(
                f"archive symlink escapes payload: {member.name!r} -> "
                f"{member.linkname!r}"
            )


def remote_locked_shell_argv(
    lock_path: str, script: str, *, use_sudo: bool,
    http_root: str | None = None, protect_docker: bool = False,
    runtime: str = "native", guard_source: str | None = None,
) -> list[str]:
    """Run a payload under the embedded, no-follow deployment-lock helper.

    The helper source travels inside the already quoted SSH argv rather than
    being loaded from the destination tree.  This permits a safe first deploy
    and prevents an older/drifted remote helper from authorizing its own
    replacement.  Docker protection runs after lock acquisition and before
    the first byte of the shell payload.
    """
    if protect_docker and http_root is None:
        raise ValueError("Docker-protected remote writer requires http_root")
    if runtime not in {"native", "docker"}:
        raise ValueError(f"unsupported runtime backend: {runtime!r}")
    helper_source = guard_source
    if helper_source is None:
        helper_source = _read_frozen_regular_bytes(
            DEPLOYMENT_PREWRITE_GUARD, "deployment prewrite guard",
        ).decode("utf-8")
    root = http_root or posixpath.dirname(lock_path.rstrip("/")) or "/"
    command = ([] if not use_sudo else ["sudo", "-n"]) + [
        "python3", "-c", helper_source,
        "--lock", lock_path, "--root", root,
    ]
    if protect_docker:
        command.append("--protect-docker")
    command += ["--runtime", runtime]
    command.append(script)
    return command


def remote_lock_holder_argv(
    lock_path: str, *, http_root: str, use_sudo: bool,
    runtime: str = "native", guard_source: str | None = None,
    source_manifest_sha256: str = "",
) -> list[str]:
    """Start the embedded two-phase holder used by multi-SSH rsync."""
    if runtime not in {"native", "docker"}:
        raise ValueError(f"unsupported runtime backend: {runtime!r}")
    helper_source = guard_source
    if helper_source is None:
        helper_source = _read_frozen_regular_bytes(
            DEPLOYMENT_PREWRITE_GUARD, "deployment prewrite guard",
        ).decode("utf-8")
    if not __import__("re").fullmatch(r"[0-9a-f]{64}", source_manifest_sha256):
        raise ValueError("verified source manifest SHA-256 is required")
    return ([] if not use_sudo else ["sudo", "-n"]) + [
        "python3", "-c", helper_source,
        "--lock", lock_path, "--root", http_root, "--holder",
        "--runtime", runtime,
        "--source-manifest-sha256", source_manifest_sha256,
    ]


def remote_locked_archive_argv(
    lock_path: str, archive_path: str, expected_sha256: str, *,
    use_sudo: bool, http_root: str, runtime: str,
    guard_source: str, source_manifest_sha256: str,
) -> list[str]:
    """Apply one verified archive through the embedded safe overlay engine."""
    if runtime not in {"native", "docker"}:
        raise ValueError(f"unsupported runtime backend: {runtime!r}")
    if not __import__("re").fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise ValueError("expected archive SHA-256 must contain 64 lowercase hex digits")
    if not guard_source:
        raise ValueError("verified archive deployment guard source is required")
    if not __import__("re").fullmatch(r"[0-9a-f]{64}", source_manifest_sha256):
        raise ValueError("verified source manifest SHA-256 is required")
    return ([] if not use_sudo else ["sudo", "-n"]) + [
        "python3", "-c", guard_source,
        "--lock", lock_path, "--root", http_root,
        "--runtime", runtime,
        "--archive", archive_path,
        "--archive-sha256", expected_sha256,
        "--source-manifest-sha256", source_manifest_sha256,
    ]


def create_package(
    args: argparse.Namespace, *, day0_all: bool = True, artifact_kind: str,
) -> Path:
    if artifact_kind not in ARTIFACT_KINDS:
        raise ValueError(f"unsupported artifact kind: {artifact_kind!r}")
    project = resolve_project(args.project)
    selected_p2p = select_upload_p2p(project) if not day0_all else None
    air_topology_policy = (
        optional_air_topology_policy(project) if not day0_all else None
    )
    mini_air_devices = (
        optional_mini_air_devices(project) if not day0_all else None
    )
    selected_p2p_relative = (
        PurePosixPath(selected_p2p.relative_to(project).as_posix())
        if selected_p2p is not None else None
    )
    raw_output = args.output.expanduser()
    if not raw_output.is_absolute():
        raw_output = Path.cwd() / raw_output
    output = raw_output.parent.resolve() / raw_output.name
    if output.is_symlink():
        raise ValueError(f"output archive cannot be a symlink: {output}")
    if output.exists() and not args.force:
        raise FileExistsError(f"output exists; use --force to replace it: {output}")
    if output.exists() and not output.is_file():
        raise ValueError(f"output must be a regular file: {output}")
    if args.max_file_size_mib < 0:
        raise ValueError("--max-file-size-mib cannot be negative")

    package_filter = PackageFilter(
        project,
        output,
        include_images=args.include_images,
        include_apps=args.include_apps,
        apps_platform=getattr(args, "apps_platform", None),
        apps_platforms=getattr(args, "apps_platforms", None),
        include_firmware=args.include_firmware,
        max_file_size=args.max_file_size_mib * 1024 * 1024,
        day0_all=day0_all,
        selected_p2p_relative=selected_p2p_relative,
        exclude_project_images=getattr(args, "exclude_project_images", False),
        artifact_kind=artifact_kind,
    )
    _reject_selected_special_sources(package_filter)
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".http-air-package-", suffix=".tar.gz", dir=output.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    package_filter.excluded_paths.add(temporary.resolve())
    p2p_stats: dict[str, int] | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="http-air-p2p-") as p2p_stage_name:
            p2p_staged = Path(p2p_stage_name) / "p2p-image-free.xlsx"
            deployment_manifest = None
            if artifact_kind == "upload":
                deployment_manifest = write_deployment_source_manifest(
                    Path(p2p_stage_name) / DEPLOYMENT_SOURCE_MANIFEST_RELATIVE.name,
                )
            if selected_p2p is not None:
                p2p_stats = strip_xlsx_images(selected_p2p, p2p_staged)
                if (
                    package_filter.max_file_size > 0
                    and p2p_staged.stat().st_size > package_filter.max_file_size
                ):
                    raise ValueError(
                        "image-free P2P workbook exceeds --max-file-size-mib: "
                        f"{human_size(p2p_staged.stat().st_size)}"
                    )
            compression_level = (
                0 if _package_uses_stored_gzip(
                    args, project, day0_all=day0_all,
                ) else 6
            )
            with temporary.open("wb") as raw_archive, gzip.GzipFile(
                filename="", mode="wb", fileobj=raw_archive,
                compresslevel=compression_level,
                mtime=REPRODUCIBLE_ARCHIVE_MTIME,
            ) as compressed_archive, tarfile.open(
                fileobj=compressed_archive, mode="w", dereference=False,
                format=tarfile.PAX_FORMAT,
            ) as archive:
                # Add workspace children, not ROOT itself. Archiving a top-level "."
                # entry preserves the local directory owner/mode and root extraction
                # can then change /var/www/html itself (for example to macOS UID 501
                # and mode 0700). Child-only archives never alter target-root metadata.
                for source in sorted(ROOT.iterdir(), key=lambda item: item.name):
                    _add_reproducible_source(
                        archive,
                        source,
                        arcname=f"./{source.name}",
                        package_filter=package_filter,
                        recursive=True,
                    )
                if deployment_manifest is not None:
                    manifest_info = archive.gettarinfo(
                        os.fspath(deployment_manifest),
                        arcname=f"./{DEPLOYMENT_SOURCE_MANIFEST_RELATIVE.as_posix()}",
                    )
                    manifest_info.mode = 0o644
                    _reproducible_tarinfo(manifest_info)
                    with deployment_manifest.open("rb") as stream:
                        archive.addfile(manifest_info, stream)
                if selected_p2p is not None and selected_p2p_relative is not None:
                    archive_name = (
                        f"./{package_filter.project_rel}/"
                        f"{selected_p2p_relative.as_posix()}"
                    )
                    info = archive.gettarinfo(str(p2p_staged), arcname=archive_name)
                    info.mode = selected_p2p.stat().st_mode & 0o777
                    _reproducible_tarinfo(info)
                    with p2p_staged.open("rb") as stream:
                        archive.addfile(info, stream)
                # Preserve the project contract as an empty placeholder while never
                # exporting the management server's runtime key material.
                for relative in sorted(package_filter.managed_pubkeys):
                    placeholder = tarfile.TarInfo(f"./{relative}")
                    placeholder.mode = 0o644
                    placeholder.size = 0
                    archive.addfile(_reproducible_tarinfo(placeholder))
        # Reopen the result so a truncated/corrupt archive is never published.
        with tarfile.open(temporary, "r:gz") as archive:
            members = archive.getmembers()
            validate_deployment_archive_members(members)
            names = {member.name for member in members}
            required = {
                "./.dockerignore",
                "./infra/docker/Dockerfile",
                "./infra/docker/Dockerfile.dockerignore",
                "./infra/docker/compose.yaml",
                "./infra/docker/activate.py",
                "./infra/docker/entrypoint.py",
                "./infra/docker/healthcheck.py",
                "./infra/docker/hostctl.py",
                "./infra/docker/hostlock.py",
                "./infra/docker/management_ssh_key.py",
                "./infra/docker/deploy.sh",
                "./infra/docker/supervisord.conf",
                "./infra/docker/apache-ztp.conf",
                "./infra/docker/rsyslog-dhcp.conf",
                "./infra/docker/logrotate-http-ztp.conf",
                "./infra/docker/container.env.example",
                "./tools/_package_common.py",
                "./tools/deployment_lock.py",
                "./tools/tar-for-upload.py",
                "./tools/tar-for-download.py",
                "./tools/sync-code.py",
                "./tools/password-update.py",
                "./DAY0-Prepare/11-load.py",
                "./DAY0-Prepare/12-ztp-monitor.py",
                "./DAY0-Prepare/13-unload.py",
                "./ztp/nvue_normalizer.py",
                "./ztp/optimize/feedback.py",
                "./ztp/optimize/sample_links.py",
                "./ztp/templates/ztp-bootstrap.sh",
                "./ztp/templates/ztp.json",
                f"./{package_filter.project_rel}/01-global.yaml",
                f"./{package_filter.project_rel}/02-devices_config.csv",
                f"./{package_filter.project_rel}/02-dhcp-subnet_config.csv",
            }
            if artifact_kind == "upload":
                required.update(
                    f"./{relative.as_posix()}"
                    for relative in DEPLOYMENT_AUTHORITY_RELATIVES
                )
            if selected_p2p_relative is not None:
                required.add(
                    f"./{package_filter.project_rel}/{selected_p2p_relative.as_posix()}"
                )
            policy_member_name = None
            if air_topology_policy is not None:
                policy_member_name = (
                    f"./{package_filter.project_rel}/{AIR_TOPOLOGY_POLICY_NAME}"
                )
                required.add(policy_member_name)
            mini_member_name = None
            if mini_air_devices is not None:
                mini_member_name = (
                    f"./{package_filter.project_rel}/{MINI_AIR_DEVICES_NAME}"
                )
                required.add(mini_member_name)
            missing = sorted(required - names)
            if missing:
                raise RuntimeError("package verification missing: " + ", ".join(missing))
            if policy_member_name is not None:
                policy_member = archive.getmember(policy_member_name)
                if not policy_member.isfile():
                    raise RuntimeError(
                        "packaged AIR topology policy is not a regular file: "
                        f"{policy_member_name}"
                    )
            if mini_member_name is not None:
                mini_member = archive.getmember(mini_member_name)
                if not mini_member.isfile() or mini_member.size == 0:
                    raise RuntimeError(
                        "packaged mini AIR device list is not a non-empty regular file: "
                        f"{mini_member_name}"
                    )
            if selected_p2p_relative is not None:
                member_name = (
                    f"./{package_filter.project_rel}/{selected_p2p_relative.as_posix()}"
                )
                extracted = archive.extractfile(member_name)
                if extracted is None:
                    raise RuntimeError(f"cannot verify packaged P2P workbook: {member_name}")
                with zipfile.ZipFile(io.BytesIO(extracted.read())) as workbook:
                    if workbook.testzip() is not None or "xl/workbook.xml" not in workbook.namelist():
                        raise RuntimeError("packaged P2P workbook is corrupt")
                    if any(name.startswith("xl/media/") for name in workbook.namelist()):
                        raise RuntimeError("packaged P2P workbook still contains images")
        os.replace(temporary, output)
        output.chmod(0o600)
    finally:
        if temporary.exists():
            temporary.unlink()

    original_size = directory_size(ROOT) - output.stat().st_size
    print(f"[OK] Project retained : {project}")
    if selected_p2p is not None and p2p_stats is not None:
        print(f"[OK] P2P source       : {selected_p2p}")
        print(
            "[OK] P2P images removed: "
            f"{p2p_stats['images']} media / {p2p_stats['drawing_nodes']} anchors; "
            f"{human_size(p2p_stats['source_size'])} -> "
            f"{human_size(p2p_stats['output_size'])}"
        )
    print(f"[OK] Archive          : {output}")
    print(f"[OK] Workspace size   : {human_size(max(0, original_size))}")
    print(f"[OK] Archive size     : {human_size(output.stat().st_size)}")
    print(f"[OK] Excluded files   : {package_filter.excluded_files}")
    print(f"[OK] Excluded bytes   : {human_size(package_filter.excluded_bytes)}")
    for reason, count in sorted(package_filter.reasons.items()):
        print(f"     {reason:<32} {count}")
    print(f"[OK] SHA-256          : {sha256(output)}")
    return output
