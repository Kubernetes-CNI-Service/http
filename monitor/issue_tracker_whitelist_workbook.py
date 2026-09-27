"""Read a C-24 Whitelist from one bounded, held local workbook snapshot.

This is a local, read-only precondition. It neither qualifies operations nor
permits online work. The pure rule authority remains issue_tracker_whitelist.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from io import BytesIO
import os
import posixpath
import re
import stat
import xml.etree.ElementTree as ET
import zipfile

from monitor.issue_tracker_whitelist import (
    WhitelistHoldError, WhitelistSnapshot, freeze_whitelist_sheet,
)


_SHEETS = (
    "GPU Server", "ETH&IB Switch", "ETH Cabling", "IB Cabling", "Dashboard",
    "Update_History", "Inventory", "ServerProfile", "PortProfile", "CVT_SUM",
    "CVT_Import", "Agent_status", "Whitelist", "BasicData",
)
_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_DOC_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_PKG_REL = "http://schemas.openxmlformats.org/package/2006/relationships"
_WORKSHEET_REL = _DOC_REL + "/worksheet"
_MAX_FILE_BYTES = 32 * 1024 * 1024
_MAX_ZIP_MEMBERS = 256
_MAX_MEMBER_BYTES = 64 * 1024 * 1024
_MAX_EXPANDED_BYTES = 128 * 1024 * 1024
_MAX_WHITELIST_ROWS = 10000
_CELL_RE = re.compile(r"^([A-Z]+)([1-9][0-9]*)$")


@dataclass(frozen=True)
class WorkbookWhitelistSnapshot:
    whitelist: WhitelistSnapshot
    workbook_sha256: str
    workbook_size: int
    device: int
    inode: int


def _held_identity(st):
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns


def _read_held_bytes(fd, size):
    os.lseek(fd, 0, os.SEEK_SET)
    pieces = []
    remaining = size
    while remaining:
        chunk = os.read(fd, min(remaining, 1024 * 1024))
        if not chunk:
            raise WhitelistHoldError("workbook shortened during read")
        pieces.append(chunk)
        remaining -= len(chunk)
    if os.read(fd, 1):
        raise WhitelistHoldError("workbook grew during read")
    return b"".join(pieces)


def _safe_xml(raw, what):
    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise WhitelistHoldError(f"{what} contains prohibited XML declaration")
    try:
        return ET.fromstring(raw)
    except ET.ParseError as exc:
        raise WhitelistHoldError(f"{what} is malformed XML") from exc


def _get_member(archive, names, member):
    if member not in names:
        raise WhitelistHoldError(f"workbook is missing {member}")
    try:
        raw = archive.read(member)
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise WhitelistHoldError(f"workbook member {member} cannot be read") from exc
    if len(raw) > _MAX_MEMBER_BYTES:
        raise WhitelistHoldError(f"workbook member {member} is oversized")
    return raw


def _shared_strings(archive, names):
    if "xl/sharedStrings.xml" not in names:
        return None
    root = _safe_xml(_get_member(archive, names, "xl/sharedStrings.xml"), "shared strings")
    if root.tag != f"{{{_MAIN}}}sst":
        raise WhitelistHoldError("shared strings root is malformed")
    values = []
    for entry in root.findall(f"{{{_MAIN}}}si"):
        values.append("".join(node.text or "" for node in entry.iter(f"{{{_MAIN}}}t")))
    return values


def _worksheet_path(archive, names):
    workbook = _safe_xml(_get_member(archive, names, "xl/workbook.xml"), "workbook")
    if workbook.tag != f"{{{_MAIN}}}workbook":
        raise WhitelistHoldError("workbook root is malformed")
    sheets = workbook.find(f"{{{_MAIN}}}sheets")
    if sheets is None:
        raise WhitelistHoldError("workbook sheet list is missing")
    entries = sheets.findall(f"{{{_MAIN}}}sheet")
    if tuple(entry.get("name") for entry in entries) != _SHEETS:
        raise WhitelistHoldError("workbook does not match the 14-sheet template")
    rel_id = entries[12].get(f"{{{_DOC_REL}}}id")
    if not rel_id:
        raise WhitelistHoldError("Whitelist sheet relationship is missing")
    relationships = _safe_xml(
        _get_member(archive, names, "xl/_rels/workbook.xml.rels"), "workbook relationships",
    )
    if relationships.tag != f"{{{_PKG_REL}}}Relationships":
        raise WhitelistHoldError("workbook relationships root is malformed")
    matches = [rel for rel in relationships.findall(f"{{{_PKG_REL}}}Relationship")
               if rel.get("Id") == rel_id]
    if len(matches) != 1 or matches[0].get("Type") != _WORKSHEET_REL:
        raise WhitelistHoldError("Whitelist relationship is invalid")
    target = matches[0].get("Target")
    if not target or "\\" in target or ":" in target or ".." in target.split("/"):
        raise WhitelistHoldError("Whitelist relationship target is unsafe")
    member = (target.lstrip("/") if target.startswith("/")
              else posixpath.normpath(posixpath.join("xl", target)))
    if not member.startswith("xl/worksheets/") or member not in names:
        raise WhitelistHoldError("Whitelist worksheet member is missing")
    return member


def _cell_text(cell, strings):
    if cell.find(f"{{{_MAIN}}}f") is not None:
        raise WhitelistHoldError("Whitelist formula cell is not a frozen value")
    kind = cell.get("t")
    value = cell.find(f"{{{_MAIN}}}v")
    if kind == "inlineStr":
        inline = cell.find(f"{{{_MAIN}}}is")
        if inline is None:
            raise WhitelistHoldError("Whitelist inline text is malformed")
        return "".join(node.text or "" for node in inline.iter(f"{{{_MAIN}}}t"))
    if value is None:
        return None
    if kind == "s":
        if strings is None or value.text is None:
            raise WhitelistHoldError("Whitelist shared string table is missing")
        try:
            index = int(value.text)
            if index < 0:
                raise IndexError
            return strings[index]
        except (ValueError, IndexError) as exc:
            raise WhitelistHoldError("Whitelist shared string index is invalid") from exc
    if kind in (None, "str", "n"):
        return value.text or ""
    raise WhitelistHoldError("Whitelist cell type is unsupported")


def _rows(archive, names, member):
    root = _safe_xml(_get_member(archive, names, member), "Whitelist worksheet")
    if root.tag != f"{{{_MAIN}}}worksheet":
        raise WhitelistHoldError("Whitelist worksheet root is malformed")
    sheet_data = root.find(f"{{{_MAIN}}}sheetData")
    if sheet_data is None:
        raise WhitelistHoldError("Whitelist sheet data is missing")
    strings = _shared_strings(archive, names)
    parsed = {}
    for row in sheet_data.findall(f"{{{_MAIN}}}row"):
        raw_number = row.get("r")
        try:
            number = int(raw_number)
        except (TypeError, ValueError) as exc:
            raise WhitelistHoldError("Whitelist row index is invalid") from exc
        if number < 1 or number > _MAX_WHITELIST_ROWS or number in parsed:
            raise WhitelistHoldError("Whitelist row index is duplicated or out of bounds")
        cells = [None] * 6
        occupied = set()
        for cell in row.findall(f"{{{_MAIN}}}c"):
            match = _CELL_RE.fullmatch(cell.get("r", ""))
            if not match or int(match.group(2)) != number:
                raise WhitelistHoldError("Whitelist cell address is invalid")
            column = match.group(1)
            if column in occupied:
                raise WhitelistHoldError("Whitelist cell address is duplicated")
            occupied.add(column)
            text = _cell_text(cell, strings)
            if len(column) != 1 or column not in "ABCDEF":
                if text not in (None, ""):
                    raise WhitelistHoldError("Whitelist row has an unexpected populated column")
            else:
                cells[ord(column) - 65] = text
        parsed[number] = cells
    if 1 not in parsed:
        raise WhitelistHoldError("Whitelist header row is missing")
    return [parsed.get(number, [None] * 6) for number in range(1, max(parsed) + 1)]


def _parse_xlsx_bytes(raw):
    try:
        with zipfile.ZipFile(BytesIO(raw)) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if (len(infos) > _MAX_ZIP_MEMBERS or len(names) != len(set(names)) or
                    any(info.file_size > _MAX_MEMBER_BYTES for info in infos) or
                    sum(info.file_size for info in infos) > _MAX_EXPANDED_BYTES):
                raise WhitelistHoldError("workbook ZIP structure exceeds safe bounds")
            if any(name.startswith("/") or ".." in name.split("/") or "\\" in name
                   for name in names):
                raise WhitelistHoldError("workbook ZIP member path is unsafe")
            member = _worksheet_path(archive, set(names))
            return freeze_whitelist_sheet(_rows(archive, set(names), member))
    except (zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise WhitelistHoldError("workbook is not a valid bounded XLSX") from exc


def read_whitelist_workbook(path):
    """Return exact held-workbook and normalized Whitelist digests or HOLD."""
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        fd = os.open(os.fspath(path), flags)
    except OSError as exc:
        raise WhitelistHoldError("local workbook cannot be opened without following links") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= _MAX_FILE_BYTES:
            raise WhitelistHoldError("local workbook is not a bounded regular file")
        raw = _read_held_bytes(fd, before.st_size)
        first_digest = hashlib.sha256(raw).hexdigest()
        whitelist = _parse_xlsx_bytes(raw)
        after = os.fstat(fd)
        if _held_identity(before) != _held_identity(after):
            raise WhitelistHoldError("local workbook changed while reading")
        if hashlib.sha256(_read_held_bytes(fd, before.st_size)).hexdigest() != first_digest:
            raise WhitelistHoldError("local workbook bytes changed while reading")
        try:
            at_path = os.stat(os.fspath(path), follow_symlinks=False)
        except OSError as exc:
            raise WhitelistHoldError("local workbook path vanished while reading") from exc
        if _held_identity(before) != _held_identity(at_path):
            raise WhitelistHoldError("local workbook path changed while reading")
        return WorkbookWhitelistSnapshot(
            whitelist, first_digest, before.st_size, before.st_dev, before.st_ino,
        )
    except OSError as exc:
        raise WhitelistHoldError("local workbook read failed") from exc
    finally:
        os.close(fd)
