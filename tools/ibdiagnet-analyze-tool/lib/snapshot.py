"""Safe access to ibdiagnet snapshots stored in a directory or archive."""

from __future__ import annotations

import os
import re
import shutil
import tarfile
import tempfile
import zipfile
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Iterator


ARCHIVE_SUFFIXES = (".tgz", ".tar.gz", ".tar", ".zip")
MAX_MEMBERS = 20_000
MAX_UNCOMPRESSED_BYTES = 20 * 1024 * 1024 * 1024
TIMESTAMP_PATTERNS = (
    re.compile(r"(?<!\d)(\d{4}[-_]\d{2}[-_]\d{2}[-_]\d{2}(?:\d{2})?)(?!\d)"),
    re.compile(r"(?<!\d)(\d{4}[-_]\d{4}[-_]\d{4})(?!\d)"),
    re.compile(r"(?<!\d)(\d{8}(?:[-_]\d{2}(?:\d{2})?)?)(?!\d)"),
)


def is_supported_archive(path: Path) -> bool:
    name = path.name.casefold()
    return any(name.endswith(suffix) for suffix in ARCHIVE_SUFFIXES)


def archive_stem(path: Path) -> str:
    name = path.name
    lower = name.casefold()
    for suffix in sorted(ARCHIVE_SUFFIXES, key=len, reverse=True):
        if lower.endswith(suffix):
            return name[: -len(suffix)]
    return path.stem


def timestamp_first_stem(stem: str) -> str:
    """Move a timestamp embedded in an input stem to the filename front."""
    for pattern in TIMESTAMP_PATTERNS:
        match = pattern.search(stem)
        if match is None:
            continue
        timestamp = match.group(1)
        label = f"{stem[:match.start()]}-{stem[match.end():]}"
        label = re.sub(r"[\s._-]+", "-", label).strip("-")
        return f"{timestamp}-{label}" if label else timestamp
    return stem


def default_report_path(snapshot: Path) -> Path:
    """Choose a topology-report path without overwriting the input."""
    if snapshot.is_dir():
        input_stem = snapshot.name
    else:
        input_stem = archive_stem(snapshot)
    report_stem = timestamp_first_stem(input_stem)
    return snapshot.parent / f"{report_stem}-topology-validation.xlsx"


def _safe_member_name(raw_name: str) -> Path:
    normalized = raw_name.replace("\\", "/")
    pure = PurePosixPath(normalized)
    if pure.is_absolute() or ".." in pure.parts:
        raise ValueError(f"unsafe archive member path: {raw_name!r}")
    parts = [part for part in pure.parts if part not in ("", ".")]
    if not parts:
        return Path()
    return Path(*parts)


def _validate_archive_totals(count: int, total_size: int) -> None:
    if count > MAX_MEMBERS:
        raise ValueError(f"archive contains too many entries: {count} > {MAX_MEMBERS}")
    if total_size > MAX_UNCOMPRESSED_BYTES:
        gib = total_size / (1024 ** 3)
        raise ValueError(f"archive expands to {gib:.1f} GiB; safety limit is 20 GiB")


def _extract_tar(path: Path, destination: Path) -> None:
    with tarfile.open(path, mode="r:*") as archive:
        members = archive.getmembers()
        _validate_archive_totals(len(members), sum(max(0, member.size) for member in members))
        for member in members:
            relative = _safe_member_name(member.name)
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                raise ValueError(f"unsupported archive member type: {member.name!r}")
            target = destination / relative
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                raise ValueError(f"could not read archive member: {member.name!r}")
            with source, target.open("wb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)


def _extract_zip(path: Path, destination: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        _validate_archive_totals(len(members), sum(max(0, member.file_size) for member in members))
        for member in members:
            relative = _safe_member_name(member.filename)
            mode = member.external_attr >> 16
            if os.path.islink(destination / relative) or (mode & 0o170000) == 0o120000:
                raise ValueError(f"symbolic links are not allowed in archives: {member.filename!r}")
            target = destination / relative
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as source, target.open("wb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)


def _find_ibdiagnet_dir(root: Path) -> Path:
    matches = sorted(path.parent for path in root.rglob("ibdiagnet2.net_dump"))
    if not matches:
        raise ValueError("archive does not contain ibdiagnet2.net_dump")
    unique = list(dict.fromkeys(path.resolve() for path in matches))
    if len(unique) != 1:
        formatted = ", ".join(str(path.relative_to(root.resolve())) for path in unique)
        raise ValueError(f"archive contains multiple ibdiagnet snapshots: {formatted}")
    return unique[0]


@contextmanager
def open_snapshot(snapshot: Path) -> Iterator[Path]:
    """Yield an ibdiagnet directory, extracting an archive temporarily if needed."""
    snapshot = snapshot.expanduser().resolve()
    if snapshot.is_dir():
        if not (snapshot / "ibdiagnet2.net_dump").is_file():
            raise ValueError(f"ibdiagnet2.net_dump not found in directory: {snapshot}")
        yield snapshot
        return
    if not snapshot.is_file():
        raise ValueError(f"ibdiagnet input not found: {snapshot}")
    if not is_supported_archive(snapshot):
        raise ValueError(
            f"unsupported ibdiagnet archive: {snapshot.name}; "
            "supported suffixes: .tgz, .tar.gz, .tar, .zip"
        )
    with tempfile.TemporaryDirectory(prefix="ibdiagnet-analyze-") as temp:
        root = Path(temp)
        if zipfile.is_zipfile(snapshot):
            _extract_zip(snapshot, root)
        elif tarfile.is_tarfile(snapshot):
            _extract_tar(snapshot, root)
        else:
            raise ValueError(f"invalid or unreadable archive: {snapshot}")
        yield _find_ibdiagnet_dir(root)
