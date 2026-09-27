"""Byte-bound IB CVT and validation-report provenance for REQ7 Stage L.

The CVT workbook, not a whole release ID, is the expected-topology authority.
These records attest local producer inputs; they do not authorize publishing.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
from contextlib import contextmanager
from typing import Mapping
from xml.etree import ElementTree as ET
import zipfile


CVT_ROLES = frozenset({
    "p2p", "inventory", "port_map", "splitter", "converter", "topology_rules",
})
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
REQUIRED_IB_REPORT_SHEETS = frozenset({"Summary", "Missing_Links", "Miswired_Links"})
WORKBOOK_NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"


class ProvenanceError(ValueError):
    """A required IB source or its byte identity cannot be verified."""


def sidecar_path(artifact: Path) -> Path:
    return artifact.with_name(artifact.name + ".provenance.json")


@contextmanager
def _bound_parent(path: Path):
    directory = path.parent
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory_flag:
        raise ProvenanceError("IB provenance requires no-follow directory access")
    try:
        before = directory.lstat()
        if not stat.S_ISDIR(before.st_mode):
            raise ProvenanceError(f"source parent is not a directory: {directory}")
        parent_fd = os.open(directory, os.O_RDONLY | directory_flag | nofollow)
    except OSError as exc:
        raise ProvenanceError(f"source parent cannot be opened: {directory}: {exc}") from exc
    try:
        opened = os.fstat(parent_fd)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ProvenanceError(f"source parent changed before access: {directory}")
        yield parent_fd
        after = directory.lstat()
        if not stat.S_ISDIR(after.st_mode) or (
            after.st_dev, after.st_ino
        ) != (opened.st_dev, opened.st_ino):
            raise ProvenanceError(f"source parent changed during access: {directory}")
    except OSError as exc:
        raise ProvenanceError(f"source parent access failed: {directory}: {exc}") from exc
    finally:
        os.close(parent_fd)


def _regular_digest(path: Path) -> str:
    try:
        with _bound_parent(path) as parent_fd:
            nofollow = getattr(os, "O_NOFOLLOW", 0)
            before_name = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            if not stat.S_ISREG(before_name.st_mode):
                raise ProvenanceError(f"source is not a regular file: {path}")
            source_fd = os.open(path.name, os.O_RDONLY | nofollow, dir_fd=parent_fd)
            try:
                before_fd = os.fstat(source_fd)
                if (before_name.st_dev, before_name.st_ino) != (
                    before_fd.st_dev, before_fd.st_ino
                ):
                    raise ProvenanceError(f"source changed before read: {path}")
                digest = hashlib.sha256()
                while True:
                    chunk = os.read(source_fd, 1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                after_fd = os.fstat(source_fd)
                after_name = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
                for after in (after_fd, after_name):
                    if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                        after.st_ctime_ns) != (
                        before_fd.st_dev, before_fd.st_ino, before_fd.st_size,
                        before_fd.st_mtime_ns, before_fd.st_ctime_ns,
                    ):
                        raise ProvenanceError(f"source changed during read: {path}")
                return digest.hexdigest()
            finally:
                os.close(source_fd)
    except OSError as exc:
        raise ProvenanceError(f"source cannot be read: {path}: {exc}") from exc


def _directory_digest(root: Path) -> str:
    digest = hashlib.sha256(b"ib-actual-directory-v1\0")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_flag = getattr(os, "O_DIRECTORY", 0)

    def visit(parent_fd: int, prefix: str) -> None:
        with os.scandir(parent_fd) as iterator:
            names = sorted(entry.name for entry in iterator)
        for name in names:
            metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            relative = f"{prefix}{name}".encode("utf-8")
            if stat.S_ISDIR(metadata.st_mode):
                child_fd = os.open(
                    name, os.O_RDONLY | directory_flag | nofollow,
                    dir_fd=parent_fd,
                )
                try:
                    opened = os.fstat(child_fd)
                    if (metadata.st_dev, metadata.st_ino) != (
                        opened.st_dev, opened.st_ino
                    ):
                        raise ProvenanceError("actual snapshot directory changed")
                    digest.update(b"d" + len(relative).to_bytes(4, "big") + relative)
                    visit(child_fd, f"{prefix}{name}/")
                    after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                    if (after.st_dev, after.st_ino) != (
                        opened.st_dev, opened.st_ino
                    ):
                        raise ProvenanceError("actual snapshot directory changed")
                finally:
                    os.close(child_fd)
            elif stat.S_ISREG(metadata.st_mode):
                file_fd = os.open(name, os.O_RDONLY | nofollow, dir_fd=parent_fd)
                try:
                    opened = os.fstat(file_fd)
                    if (metadata.st_dev, metadata.st_ino) != (
                        opened.st_dev, opened.st_ino
                    ):
                        raise ProvenanceError("actual snapshot file changed")
                    file_hash = hashlib.sha256()
                    while True:
                        chunk = os.read(file_fd, 1024 * 1024)
                        if not chunk:
                            break
                        file_hash.update(chunk)
                    after_fd = os.fstat(file_fd)
                    after_name = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                    for after in (after_fd, after_name):
                        if (after.st_dev, after.st_ino, after.st_size,
                            after.st_mtime_ns, after.st_ctime_ns) != (
                            opened.st_dev, opened.st_ino, opened.st_size,
                            opened.st_mtime_ns, opened.st_ctime_ns,
                        ):
                            raise ProvenanceError("actual snapshot file changed")
                    digest.update(
                        b"f" + len(relative).to_bytes(4, "big") + relative
                        + file_hash.digest()
                    )
                finally:
                    os.close(file_fd)
            else:
                raise ProvenanceError("actual snapshot contains a symlink or special file")

    try:
        with _bound_parent(root) as parent_fd:
            before = os.stat(root.name, dir_fd=parent_fd, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode):
                raise ProvenanceError("actual snapshot root is not a directory")
            root_fd = os.open(
                root.name, os.O_RDONLY | directory_flag | nofollow,
                dir_fd=parent_fd,
            )
            try:
                opened = os.fstat(root_fd)
                if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                    raise ProvenanceError("actual snapshot root changed")
                visit(root_fd, "")
                after = os.stat(root.name, dir_fd=parent_fd, follow_symlinks=False)
                if (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino):
                    raise ProvenanceError("actual snapshot root changed")
            finally:
                os.close(root_fd)
    except OSError as exc:
        raise ProvenanceError(f"actual snapshot directory cannot be read: {exc}") from exc
    return digest.hexdigest()


def _identity(path: Path, *, allow_directory: bool = False) -> dict[str, str]:
    try:
        lexical = Path(os.path.abspath(path.expanduser()))
        canonical = lexical.resolve(strict=True)
    except OSError as exc:
        raise ProvenanceError(f"source cannot be resolved: {path}: {exc}") from exc
    if canonical.is_dir():
        if not allow_directory:
            raise ProvenanceError(f"source is not a regular file: {path}")
        kind, digest = "directory", _directory_digest(canonical)
    else:
        kind, digest = "file", _regular_digest(canonical)
    try:
        if lexical.resolve(strict=True) != canonical:
            raise ProvenanceError(f"source path changed during read: {path}")
    except OSError as exc:
        raise ProvenanceError(f"source path changed during read: {path}: {exc}") from exc
    return {
        "path": str(lexical), "resolved_path": str(canonical),
        "kind": kind, "sha256": digest,
    }


def _same_file_identity(identity: object, label: str, *, allow_directory: bool = False) -> str:
    if not isinstance(identity, dict) or set(identity) != {"path", "resolved_path", "kind", "sha256"}:
        raise ProvenanceError(f"invalid {label} identity")
    path, expected = identity["path"], identity["sha256"]
    if not isinstance(path, str) or not Path(path).is_absolute():
        raise ProvenanceError(f"invalid {label} path")
    if not isinstance(identity["resolved_path"], str) or not Path(identity["resolved_path"]).is_absolute():
        raise ProvenanceError(f"invalid {label} resolved path")
    if not isinstance(expected, str) or not SHA256_RE.fullmatch(expected):
        raise ProvenanceError(f"invalid {label} digest")
    if identity["kind"] not in ({"file", "directory"} if allow_directory else {"file"}):
        raise ProvenanceError(f"invalid {label} source kind")
    actual = _identity(Path(path), allow_directory=allow_directory)
    if actual != identity:
        raise ProvenanceError(f"{label} source bytes changed")
    return expected


def _object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ProvenanceError(f"duplicate provenance key: {key}")
        result[key] = value
    return result


def _load(path: Path) -> dict[str, object]:
    try:
        with _bound_parent(path) as parent_fd:
            before = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            if not stat.S_ISREG(before.st_mode):
                raise ProvenanceError("provenance sidecar is not a regular file")
            source_fd = os.open(
                path.name, os.O_RDONLY | getattr(os, "O_NOFOLLOW"),
                dir_fd=parent_fd,
            )
            try:
                opened = os.fstat(source_fd)
                if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                    raise ProvenanceError("provenance sidecar changed before read")
                raw = os.read(source_fd, 16385)
                after = os.fstat(source_fd)
                named = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
                for current in (after, named):
                    if (current.st_dev, current.st_ino, current.st_size,
                        current.st_mtime_ns, current.st_ctime_ns) != (
                        opened.st_dev, opened.st_ino, opened.st_size,
                        opened.st_mtime_ns, opened.st_ctime_ns,
                    ):
                        raise ProvenanceError("provenance sidecar changed during read")
            finally:
                os.close(source_fd)
        if len(raw) > 16384:
            raise ProvenanceError("provenance sidecar is too large")
        value = json.loads(raw, object_pairs_hook=_object_pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProvenanceError(f"missing or invalid provenance sidecar: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ProvenanceError("provenance sidecar must be an object")
    return value


def _publish(path: Path, value: dict[str, object], parent_fd: int) -> None:
    data = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    temporary = f".{path.name}.{os.urandom(16).hex()}.tmp"
    temporary_fd = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW"),
        0o600, dir_fd=parent_fd,
    )
    try:
        temporary_stat = os.fstat(temporary_fd)
        with os.fdopen(temporary_fd, "wb") as target:
            target.write(data)
            target.flush()
            os.fsync(target.fileno())
        named_stat = os.stat(temporary, dir_fd=parent_fd, follow_symlinks=False)
        if (named_stat.st_dev, named_stat.st_ino) != (
            temporary_stat.st_dev, temporary_stat.st_ino
        ):
            raise ProvenanceError("provenance temporary file was replaced")
        # The caller holds this parent FD from before source attestation. Both
        # names stay bound to it even if the lexical parent becomes a new dir.
        os.replace(
            temporary, path.name,
            src_dir_fd=parent_fd, dst_dir_fd=parent_fd,
        )
        published = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (published.st_dev, published.st_ino) != (
            temporary_stat.st_dev, temporary_stat.st_ino
        ):
            raise ProvenanceError("published provenance file was replaced")
        os.fsync(parent_fd)
    finally:
        try:
            leftover = os.stat(temporary, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            leftover = None
        if leftover is not None and (leftover.st_dev, leftover.st_ino) == (
            temporary_stat.st_dev, temporary_stat.st_ino
        ):
            os.unlink(temporary, dir_fd=parent_fd)


def _check_report_sheets(report: Path) -> None:
    try:
        with _bound_parent(report) as parent_fd:
            before = os.stat(report.name, dir_fd=parent_fd, follow_symlinks=False)
            if not stat.S_ISREG(before.st_mode):
                raise ProvenanceError("IB report is not a regular file")
            report_fd = os.open(
                report.name, os.O_RDONLY | getattr(os, "O_NOFOLLOW"),
                dir_fd=parent_fd,
            )
            with os.fdopen(report_fd, "rb") as report_stream:
                opened = os.fstat(report_stream.fileno())
                if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                    raise ProvenanceError("IB report changed before sheet read")
                with zipfile.ZipFile(report_stream) as archive:
                    if archive.testzip() is not None:
                        raise ProvenanceError("IB report contains a corrupt ZIP member")
                    workbook = ET.fromstring(archive.read("xl/workbook.xml"))
                    sheet_names = [
                        sheet.attrib.get("name", "")
                        for sheet in workbook.findall(f"{WORKBOOK_NS}sheets/{WORKBOOK_NS}sheet")
                    ]
                after_fd = os.fstat(report_stream.fileno())
                after_name = os.stat(report.name, dir_fd=parent_fd, follow_symlinks=False)
                for current in (after_fd, after_name):
                    if (current.st_dev, current.st_ino, current.st_size,
                        current.st_mtime_ns, current.st_ctime_ns) != (
                        opened.st_dev, opened.st_ino, opened.st_size,
                        opened.st_mtime_ns, opened.st_ctime_ns,
                    ):
                        raise ProvenanceError("IB report changed during sheet read")
    except (OSError, KeyError, zipfile.BadZipFile, ET.ParseError) as exc:
        raise ProvenanceError(f"invalid IB report workbook: {exc}") from exc
    if len(sheet_names) != len(set(sheet_names)):
        raise ProvenanceError("IB report has duplicate worksheet names")
    missing = REQUIRED_IB_REPORT_SHEETS - set(sheet_names)
    if missing:
        raise ProvenanceError(f"IB report is missing required sheets: {sorted(missing)}")


def capture_sources(sources: Mapping[str, Path]) -> dict[str, dict[str, str]]:
    if set(sources) != CVT_ROLES:
        raise ProvenanceError("CVT provenance requires exactly six named source roles")
    return {role: _identity(Path(sources[role])) for role in sorted(CVT_ROLES)}


def write_cvt_provenance(
    cvt: Path, sources: Mapping[str, Path],
    *, expected_sources: Mapping[str, dict[str, str]] | None = None,
) -> dict[str, object]:
    with _bound_parent(cvt) as parent_fd:
        captured = capture_sources(sources)
        if expected_sources is not None and captured != expected_sources:
            raise ProvenanceError("CVT sources changed during conversion")
        record: dict[str, object] = {
            "schema": "ib-cvt-provenance-v1",
            "cvt": _identity(cvt),
            "sources": captured,
        }
        record["cvt_sha256"] = record["cvt"]["sha256"]
        _publish(sidecar_path(cvt), record, parent_fd)
        return record


def read_cvt_provenance(cvt: Path) -> dict[str, object]:
    record = _load(sidecar_path(cvt))
    if set(record) != {"schema", "cvt", "cvt_sha256", "sources"} or record["schema"] != "ib-cvt-provenance-v1":
        raise ProvenanceError("invalid CVT provenance schema")
    identity = record["cvt"]
    if _same_file_identity(identity, "CVT") != record["cvt_sha256"]:
        raise ProvenanceError("CVT summary digest differs from source identity")
    if _identity(cvt)["resolved_path"] != identity["resolved_path"]:
        raise ProvenanceError("CVT provenance belongs to another path")
    sources = record["sources"]
    if not isinstance(sources, dict) or set(sources) != CVT_ROLES:
        raise ProvenanceError("invalid CVT source roles")
    for role in sorted(CVT_ROLES):
        _same_file_identity(sources[role], role)
    return record


def capture_report_inputs(actual: Path, profile: Path) -> dict[str, dict[str, str]]:
    return {"actual": _identity(actual, allow_directory=True), "profile": _identity(profile)}


def write_report_provenance(
    report: Path, cvt: Path, actual: Path, profile: Path,
    *, expected_inputs: Mapping[str, dict[str, str]] | None = None,
) -> dict[str, object]:
    with _bound_parent(report) as parent_fd:
        cvt_record = read_cvt_provenance(cvt)
        _check_report_sheets(report)
        inputs = capture_report_inputs(actual, profile)
        if expected_inputs is not None and inputs != expected_inputs:
            raise ProvenanceError("IB report inputs changed during validation")
        record: dict[str, object] = {
            "schema": "ib-report-provenance-v1",
            "report": _identity(report),
            "cvt": cvt_record["cvt"],
            "expected_topology_sha256": cvt_record["cvt"]["sha256"],
            "cvt_provenance_sha256": _regular_digest(sidecar_path(cvt)),
            "actual": inputs["actual"],
            "profile": inputs["profile"],
        }
        _publish(sidecar_path(report), record, parent_fd)
        return record


def read_report_provenance(report: Path) -> dict[str, object]:
    record = _load(sidecar_path(report))
    required = {
        "schema", "report", "cvt", "expected_topology_sha256",
        "cvt_provenance_sha256", "actual", "profile",
    }
    if set(record) != required or record["schema"] != "ib-report-provenance-v1":
        raise ProvenanceError("invalid IB report provenance schema")
    _same_file_identity(record["report"], "report")
    _check_report_sheets(report)
    if _identity(report)["resolved_path"] != record["report"]["resolved_path"]:
        raise ProvenanceError("report provenance belongs to another path")
    cvt_identity = record["cvt"]
    cvt_digest = _same_file_identity(cvt_identity, "CVT")
    if record["expected_topology_sha256"] != cvt_digest:
        raise ProvenanceError("expected topology digest does not match CVT bytes")
    cvt_path = Path(cvt_identity["path"])
    cvt_record = read_cvt_provenance(cvt_path)
    if cvt_record["cvt"] != cvt_identity:
        raise ProvenanceError("report CVT identity does not match producer")
    if _regular_digest(sidecar_path(cvt_path)) != record["cvt_provenance_sha256"]:
        raise ProvenanceError("CVT provenance changed after report")
    _same_file_identity(record["actual"], "actual", allow_directory=True)
    _same_file_identity(record["profile"], "profile")
    return record
