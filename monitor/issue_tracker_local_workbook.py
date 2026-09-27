"""Pure, bounded Stage-L workbook image projections without publication.

The fake C-5 fixture path stays separate from protected production source-row
and W1 skip-history projections. No helper here persists, sends, allocates an
online ID, or confers publication eligibility; C-6 owns the durable commit.
"""

from __future__ import annotations

from dataclasses import dataclass
from copy import deepcopy
from datetime import datetime
import hashlib
from io import BytesIO
import json
import os
import posixpath
import re
import stat
import xml.etree.ElementTree as ET
import zipfile

from monitor.issue_tracker_manifest import freeze_qualified_manifest, _runtime_skip
from monitor.issue_tracker_qualification import QualifiedSet, _canonical_json, _operation
from monitor.issue_tracker_whitelist import WhitelistHoldError, evaluate_whitelist
from monitor.issue_tracker_whitelist_workbook import (
    _DOC_REL, _MAIN, _PKG_REL, _SHEETS, _WORKSHEET_REL,
    _MAX_FILE_BYTES, _MAX_ZIP_MEMBERS, _MAX_MEMBER_BYTES, _MAX_EXPANDED_BYTES,
    _cell_text, _get_member, _safe_xml, _shared_strings, read_whitelist_workbook,
)


class LocalWorkbookHold(ValueError):
    """No bytes may be treated as prepared after an unproved precondition."""


@dataclass(frozen=True)
class SwitchDescriptionEdit:
    operation_id: str
    activity_key: tuple[str, str, str, str]
    expected_description: str
    new_description: str


@dataclass(frozen=True)
class SwitchRowInsert:
    """Fixture-only typed values; C-5 does not attest these as runtime data."""

    operation_id: str
    activity_key: tuple[str, str, str, str]
    submit_date: str
    submitter: str
    fabric: str
    priority: str
    description: str


@dataclass(frozen=True)
class HistoryAppend:
    """Fixture-only history value bound to one accepted operation."""

    operation_id: str
    activity_key: tuple[str, str, str, str]
    timestamp_utc: str
    details: str


@dataclass(frozen=True)
class CablingRowEdit:
    """Explicitly held until C-5 supplies source-bound A/Z and IB authority."""

    operation_id: str
    activity_key: tuple[str, str, str, str]
    sheet: str
    action: str


@dataclass(frozen=True)
class CablingSourceRow:
    """Typed source values for a pure image; qualification belongs to the caller."""

    sheet: str
    activity_key: tuple[str, str, str, str]
    expected_endpoints: tuple[str, str, str, str]
    actual_endpoints: tuple[str, str, str, str] | tuple[()]
    source_status: str
    evidence_description: str
    recorded_at_utc: str


@dataclass(frozen=True)
class SwitchSourceWorkbookRow:
    """Typed Switch values; this image helper never grants commit authority."""

    activity_key: tuple[str, str, str, str]
    evidence_description: str
    fabric: str
    fabric_source: str
    priority: str
    recorded_at_utc: str


@dataclass(frozen=True)
class PreparedLocalWorkbook:
    xlsx_bytes: bytes
    sha256: str
    source_sha256: str
    manifest_id: str
    changed_cells: tuple[tuple[str, str], ...]


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_COMPONENT = re.compile(r"[A-Za-z0-9_.-]+\Z")
_SWITCH_COMPONENT = re.compile(r"[A-Za-z0-9_.:/-]+\Z")
_CELL = re.compile(r"[A-Z]+[1-9][0-9]*\Z")
_RESERVED_SWITCH_ID = re.compile(r"NV[0-9]{5}\Z")
_CABLING_ID = re.compile(r"NV[0-9]{5}\Z")
_ISO_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")
_UTC_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_SWITCH_HEADERS = (
    "Issue#", "Submit Date", "Submitor", "Rack", "RU", "Host Name",
    "OOB IP", "SN", "Model", "Fabric", "Priority", "Issue Description",
    "NVEX Case ID", "Status", "Owner", "Action Description", "P-Status",
    "Replacement SN", "Replacement ETH0 MAC", "Remark \n(Partner)", "Remark\n(NV)",
)
_CABLING_HEADERS = (
    "Fault ID", "Source", "Requested by", "Date opened", "Link Type",
    "Issue Type", "Issue Desc", "A-SU", "A-Rack", "A-RU", "A-Node",
    "A-Port", "A Actual Node", "A Actual Port", "Z-Rack", "Z-RU",
    "Z-Node", "Z-Port", "Z Actual Node", "Z Actual Port", "Status",
    "Notes", "AI Recommendation (Refer only)", "NV Comments",
    "Assigned to", "Engineer Assigned", "Action Description", "P-status", "CVT",
)
_HISTORY_HEADERS = ("Timestamp (UTC)", "Sheet", "Action", "Key", "Details")
_EXPECTED_HEADERS = {
    "ETH&IB Switch": _SWITCH_HEADERS,
    "ETH Cabling": _CABLING_HEADERS,
    "IB Cabling": _CABLING_HEADERS,
    "Update_History": _HISTORY_HEADERS,
}


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise LocalWorkbookHold("duplicate manifest field")
        result[key] = value
    return result


def _reject_nonfinite(value):
    raise LocalWorkbookHold(f"nonfinite manifest value: {value}")


def _manifest_operations(body, expected_digest, whitelist_digest):
    if not isinstance(body, bytes) or not body.endswith(b"\n"):
        raise LocalWorkbookHold("manifest must be canonical bytes with one LF")
    try:
        parsed = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_pairs,
                            parse_constant=_reject_nonfinite)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LocalWorkbookHold("manifest is not valid JSON") from exc
    required = {
        "project_id", "schema_version", "producer_version", "template_contract_version",
        "template_sha256", "operations", "qualified_source",
    }
    if not isinstance(parsed, dict) or set(parsed) != required or body != _canonical_json(parsed) + b"\n":
        raise LocalWorkbookHold("manifest is not exact canonical C-5 body")
    source = parsed["qualified_source"]
    if (not isinstance(source, dict) or source.get("mode") != "synthetic-local-fixture" or
            source.get("whitelist_sha256") != whitelist_digest or
            isinstance(source.get("k"), bool) or not isinstance(source.get("k"), int) or
            source["k"] < 1):
        raise LocalWorkbookHold("manifest is not a bound local fixture")
    if parsed["template_sha256"] != expected_digest or not isinstance(parsed["operations"], list):
        raise LocalWorkbookHold("manifest template or operations mismatch")
    operations = {}
    keys = set()
    for raw in parsed["operations"]:
        try:
            op = _operation(raw)
        except ValueError as exc:
            raise LocalWorkbookHold("manifest operation is invalid") from exc
        key = tuple(op["activity_key"])
        identity = op["operation_id"]
        if identity in operations or key in keys:
            raise LocalWorkbookHold("manifest operations are ambiguous")
        operations[identity] = op
        keys.add(key)
    return operations, hashlib.sha256(body).hexdigest()


def _bound_nonempty_switch(snapshot, qualified_set, body, manifest_id,
                           expected_manifest_id, edit):
    """Recheck the real C-5 freezer and the same held W1 before fake preparation."""
    if (not isinstance(qualified_set, QualifiedSet) or
            qualified_set.whitelist_snapshot != snapshot or
            not isinstance(expected_manifest_id, str) or
            not _SHA.fullmatch(expected_manifest_id)):
        raise LocalWorkbookHold("nonempty Whitelist lacks exact held C-5 authority")
    metadata = {key: json.loads(body)[key] for key in (
        "project_id", "schema_version", "producer_version",
        "template_contract_version", "template_sha256",
    )}
    try:
        frozen_body, frozen_id = freeze_qualified_manifest(
            qualified_set, metadata=metadata,
            expected_template_sha256=snapshot.workbook_sha256,
        )
    except (TypeError, ValueError, WhitelistHoldError) as exc:
        raise LocalWorkbookHold("nonempty Whitelist C-5 freeze no longer proves intent") from exc
    if (body != frozen_body or manifest_id != frozen_id or
            expected_manifest_id != frozen_id):
        raise LocalWorkbookHold("nonempty Whitelist frozen manifest drifted")
    if (not isinstance(edit.activity_key, tuple) or len(edit.activity_key) != 4 or
            edit.activity_key[0] != "switch"):
        raise LocalWorkbookHold("nonempty Whitelist supports only a switch fixture")
    try:
        decision = evaluate_whitelist(
            snapshot.whitelist,
            [{"record_id": edit.operation_id, "source": "Switch",
              "hostname": edit.activity_key[1]}],
        ).decisions[0]
    except WhitelistHoldError as exc:
        raise LocalWorkbookHold("nonempty Whitelist cannot evaluate switch") from exc
    if decision.skipped:
        raise LocalWorkbookHold("switch is skipped by the frozen Whitelist")


def _identity(st):
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns


def _read_bound_source(path, snapshot):
    try:
        fd = os.open(os.fspath(path), os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise LocalWorkbookHold("template path cannot be opened without following links") from exc
    try:
        first = os.fstat(fd)
        if (not stat.S_ISREG(first.st_mode) or first.st_size != snapshot.workbook_size or
                (first.st_dev, first.st_ino) != (snapshot.device, snapshot.inode)):
            raise LocalWorkbookHold("template identity changed after whitelist read")
        chunks = []
        remaining = first.st_size
        while remaining:
            chunk = os.read(fd, min(remaining, 1024 * 1024))
            if not chunk:
                raise LocalWorkbookHold("template shortened during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(fd, 1):
            raise LocalWorkbookHold("template grew during read")
        raw = b"".join(chunks)
        if (hashlib.sha256(raw).hexdigest() != snapshot.workbook_sha256 or
                _identity(first) != _identity(os.fstat(fd)) or
                _identity(first) != _identity(os.stat(os.fspath(path), follow_symlinks=False))):
            raise LocalWorkbookHold("template source changed during preparation")
        return raw
    except OSError as exc:
        raise LocalWorkbookHold("template source read failed") from exc
    finally:
        os.close(fd)


def _sheet_paths(archive, names):
    workbook = _safe_xml(_get_member(archive, names, "xl/workbook.xml"), "workbook")
    sheets = workbook.find(f"{{{_MAIN}}}sheets")
    if workbook.tag != f"{{{_MAIN}}}workbook" or sheets is None:
        raise LocalWorkbookHold("invalid workbook sheet directory")
    entries = sheets.findall(f"{{{_MAIN}}}sheet")
    if tuple(entry.get("name") for entry in entries) != _SHEETS:
        raise LocalWorkbookHold("template 14-sheet order changed")
    rels = _safe_xml(_get_member(archive, names, "xl/_rels/workbook.xml.rels"), "relationships")
    if rels.tag != f"{{{_PKG_REL}}}Relationships":
        raise LocalWorkbookHold("invalid workbook relationships")
    by_id = {}
    for rel in rels.findall(f"{{{_PKG_REL}}}Relationship"):
        rid = rel.get("Id")
        if not rid or rid in by_id:
            raise LocalWorkbookHold("ambiguous workbook relationship")
        by_id[rid] = rel
    result = {}
    used = set()
    for entry in entries:
        rel = by_id.get(entry.get(f"{{{_DOC_REL}}}id"))
        if rel is None or rel.get("Type") != _WORKSHEET_REL or rel.get("TargetMode"):
            raise LocalWorkbookHold("sheet relationship is not a local worksheet")
        target = rel.get("Target")
        if not target or "\\" in target or ":" in target or ".." in target.split("/"):
            raise LocalWorkbookHold("unsafe sheet relationship target")
        member = (target.lstrip("/") if target.startswith("/") else
                  posixpath.normpath(posixpath.join("xl", target)))
        if member not in names or not member.startswith("xl/worksheets/") or member in used:
            raise LocalWorkbookHold("sheet relationship is missing or aliased")
        used.add(member)
        result[entry.get("name")] = member
    return result


def _cells_by_address(row):
    result = {}
    for cell in row.findall(f"{{{_MAIN}}}c"):
        address = cell.get("r", "")
        if not _CELL.fullmatch(address) or address in result:
            raise LocalWorkbookHold("duplicate or invalid worksheet cell address")
        result[address] = cell
    return result


def _rows(archive, names, member):
    root = _safe_xml(_get_member(archive, names, member), "worksheet")
    data = root.find(f"{{{_MAIN}}}sheetData")
    if root.tag != f"{{{_MAIN}}}worksheet" or data is None:
        raise LocalWorkbookHold("worksheet lacks sheetData")
    result = {}
    for row in data.findall(f"{{{_MAIN}}}row"):
        number = row.get("r")
        if not number or not number.isdecimal() or int(number) < 1 or int(number) in result:
            raise LocalWorkbookHold("duplicate or invalid worksheet row")
        result[int(number)] = (row, _cells_by_address(row))
    return root, result


def _column(number):
    result = ""
    while number:
        number, remainder = divmod(number - 1, 26)
        result = chr(65 + remainder) + result
    return result


def _column_index(address):
    letters = address.rstrip("0123456789")
    number = 0
    for letter in letters:
        number = number * 26 + ord(letter) - 64
    return number


def _literal(value, field, *, limit=1024):
    if (not isinstance(value, str) or not value or len(value) > limit or
            any(char in value for char in "\x00\r\n")):
        raise LocalWorkbookHold(f"{field} is not bounded literal fixture text")
    return value


def _set_literal_cell(row, cells, address, value):
    cell = cells.get(address)
    if cell is None:
        cell = ET.Element(f"{{{_MAIN}}}c", {"r": address})
        position = next(
            (index for index, existing in enumerate(row)
             if existing.tag == f"{{{_MAIN}}}c" and
             _column_index(existing.get("r", "")) > _column_index(address)),
            len(row),
        )
        row.insert(position, cell)
        cells[address] = cell
    elif cell.find(f"{{{_MAIN}}}f") is not None:
        raise LocalWorkbookHold("target cell contains a formula")
    for child in list(cell):
        cell.remove(child)
    cell.set("t", "inlineStr")
    inline = ET.SubElement(cell, f"{{{_MAIN}}}is")
    ET.SubElement(inline, f"{{{_MAIN}}}t").text = value


def _clear_literal_cell(cells, address):
    cell = cells.get(address)
    if cell is None:
        return
    if cell.find(f"{{{_MAIN}}}f") is not None:
        raise LocalWorkbookHold("monitor actual cell contains a formula")
    for child in list(cell):
        cell.remove(child)
    cell.attrib.pop("t", None)


def _is_empty_cell(cell, strings):
    if cell is None:
        return True
    if cell.find(f"{{{_MAIN}}}f") is not None:
        return False
    return _cell_text(cell, strings) in (None, "")


def _apply_switch_insert(rows, strings, edit):
    key = edit.activity_key
    if (not isinstance(key, tuple) or len(key) != 4 or key[0] != "switch" or
            any(not isinstance(part, str) or not _COMPONENT.fullmatch(part) for part in key[1:3]) or
            not isinstance(key[3], str) or not _SWITCH_COMPONENT.fullmatch(key[3])):
        raise LocalWorkbookHold("switch insert activity key is invalid")
    for field in ("submit_date", "submitter", "fabric", "priority", "description"):
        _literal(getattr(edit, field), field)
    if not _ISO_DATE.fullmatch(edit.submit_date):
        raise LocalWorkbookHold("submit date must be an ISO fixture date")
    try:
        datetime.strptime(edit.submit_date, "%Y-%m-%d")
    except ValueError as exc:
        raise LocalWorkbookHold("submit date is not a calendar date") from exc
    prefix = f"[MONITOR][{key[2]}][{key[3]}]"
    if not edit.description.startswith(prefix):
        raise LocalWorkbookHold("switch description does not preserve its activity key")
    for number, (_, cells) in rows.items():
        if number <= 2:
            continue
        host, description = cells.get(f"F{number}"), cells.get(f"L{number}")
        if (host is not None and description is not None and
                _cell_text(host, strings) == key[1] and
                (_cell_text(description, strings) or "").startswith(prefix)):
            status = cells.get(f"N{number}")
            if status is None or _cell_text(status, strings) != "Closed":
                raise LocalWorkbookHold("switch has a duplicate active activity key")
    candidates = []
    seen_ids = set()
    for number in sorted(rows):
        if number < 3 or number > 5002:
            continue
        row, cells = rows[number]
        id_cell = cells.get(f"A{number}")
        issue_id = _cell_text(id_cell, strings) if id_cell is not None else None
        if issue_id is None:
            continue
        if not _RESERVED_SWITCH_ID.fullmatch(issue_id) or issue_id in seen_ids:
            raise LocalWorkbookHold("switch reserved IDs are malformed or duplicate")
        seen_ids.add(issue_id)
        if number < 4:
            continue
        if (all(_is_empty_cell(cells.get(f"{column}{number}"), strings)
                for column in ("F", "B", "C", *"JKLMNOPQRSTU"))):
            candidates.append((number, issue_id, row, cells))
    if not candidates:
        raise LocalWorkbookHold("no unoccupied switch reserved row")
    number, issue_id, row, cells = candidates[0]
    if any(
        cells.get(f"{column}{number}") is None or
        cells[f"{column}{number}"].find(f"{{{_MAIN}}}f") is None or
        not cells[f"{column}{number}"].find(f"{{{_MAIN}}}f").text
        for column in "DEGH"
    ) or not _is_empty_cell(cells.get(f"I{number}"), strings):
        raise LocalWorkbookHold("switch reserved row formula headroom changed")
    values = {
        "B": edit.submit_date, "C": edit.submitter, "F": key[1],
        "J": edit.fabric, "K": edit.priority, "L": edit.description, "N": "New",
    }
    for column, value in values.items():
        _set_literal_cell(row, cells, f"{column}{number}", value)
    return issue_id, tuple(f"{column}{number}" for column in values)


def _append_history(root, rows, strings, history, issue_id):
    _literal(history.details, "history details")
    if not isinstance(history.timestamp_utc, str) or not _UTC_TIMESTAMP.fullmatch(history.timestamp_utc):
        raise LocalWorkbookHold("history timestamp is not canonical UTC")
    try:
        datetime.strptime(history.timestamp_utc, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise LocalWorkbookHold("history timestamp is not a calendar instant") from exc
    last_data = 2
    for number, (_, cells) in rows.items():
        if number > 2 and any(not _is_empty_cell(cell, strings) for cell in cells.values()):
            last_data = max(last_data, number)
    number = last_data + 1
    if number > 1048576:
        raise LocalWorkbookHold("history sheet has no remaining row")
    existing = rows.get(number)
    if existing is None:
        data = root.find(f"{{{_MAIN}}}sheetData")
        row = ET.Element(f"{{{_MAIN}}}row", {"r": str(number)})
        position = next((index for index, item in enumerate(data)
                         if int(item.get("r", "0")) > number), len(data))
        data.insert(position, row)
        cells = {}
    else:
        row, cells = existing
        if any(not _is_empty_cell(cell, strings) for cell in cells.values()):
            raise LocalWorkbookHold("history append row is occupied")
    values = (history.timestamp_utc, "ETH&IB Switch", "Insert", issue_id, history.details)
    for column, value in zip("ABCDE", values):
        _set_literal_cell(row, cells, f"{column}{number}", value)
    return tuple(f"{column}{number}" for column in "ABCDE")


def _append_source_history(root, rows, strings, *, sheet, action, issue_id,
                           recorded_at_utc, source_status, evidence_description):
    last = max((number for number, (_, cells) in rows.items()
                if number > 2 and any(not _is_empty_cell(cell, strings)
                                      for cell in cells.values())), default=2)
    number = last + 1
    if number > 1048576:
        raise LocalWorkbookHold("history sheet is full")
    target = rows.get(number)
    if target is None:
        data = root.find(f"{{{_MAIN}}}sheetData")
        item = ET.Element(f"{{{_MAIN}}}row", {"r": str(number)})
        position = next((i for i, old in enumerate(data)
                         if old.tag == f"{{{_MAIN}}}row" and
                         int(old.get("r", "0")) > number), len(data))
        data.insert(position, item)
        cells = {}
    else:
        item, cells = target
        if any(not _is_empty_cell(cell, strings) for cell in cells.values()):
            raise LocalWorkbookHold("history append row is occupied")
    values = {
        "A": recorded_at_utc, "B": sheet, "C": action, "D": issue_id,
        "E": "[MONITOR] " + source_status + ": " + evidence_description,
    }
    for column, value in values.items():
        _set_literal_cell(item, cells, f"{column}{number}", value)
    rows[number] = (item, cells)


def project_whitelist_skip_history_image(raw, skips, *, recorded_at_utc,
                                         manifest_id):
    """Project protected W1 skips into local history without business-row edits.

    The source-specific identity and matched rule come from the qualified set;
    the C-5 manifest identity binds this audit row to one frozen decision.
    """
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_FILE_BYTES:
        raise LocalWorkbookHold("skip history source workbook is invalid")
    if (type(skips) is not tuple or len(skips) > 1000
            or type(manifest_id) is not str or not _SHA.fullmatch(manifest_id)
            or type(recorded_at_utc) is not str
            or not _UTC_TIMESTAMP.fullmatch(recorded_at_utc)):
        raise LocalWorkbookHold("skip history binding is invalid")
    try:
        datetime.strptime(recorded_at_utc, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise LocalWorkbookHold("skip history timestamp is not a calendar instant") from exc
    expected = []
    for skip in skips:
        try:
            item = _runtime_skip(skip)
        except ValueError as exc:
            raise LocalWorkbookHold("skip history has unqualified identity") from exc
        source = item.pop("source")
        rule = item.pop("matched_rule")
        sheet = {"ib_cabling": "IB Cabling", "eth_cabling": "ETH Cabling",
                 "switch": "ETH&IB Switch"}[source]
        key = _canonical_json({"source": source, **item}).decode("utf-8")
        detail = "[MONITOR] Whitelist Skip: manifest_id=" + manifest_id + "; matched_rule=" + rule
        _literal(key, "skip history key")
        _literal(detail, "skip history detail")
        expected.append((recorded_at_utc, sheet, "Whitelist Skip", key, detail))
    if len(set(expected)) != len(expected):
        raise LocalWorkbookHold("duplicate qualified skip history identity")
    if not expected:
        return raw
    try:
        with zipfile.ZipFile(BytesIO(raw)) as source:
            infos, names = _bounded_projectable_archive(source)
            paths = _sheet_paths(source, names)
            strings = _shared_strings(source, names)
            parsed = _validate_headers(source, names, paths, strings)
            history_root, history_rows = parsed["Update_History"]
            existing = []
            for number, (_, cells) in history_rows.items():
                detail = _cell_text(cells.get(f"E{number}"), strings)
                if (type(detail) is str and detail.startswith("[MONITOR] Whitelist Skip: ")
                        and "manifest_id=" + manifest_id + ";" in detail):
                    existing.append(tuple(_cell_text(cells.get(f"{column}{number}"), strings)
                                          for column in "ABCDE"))
            if existing:
                if tuple(sorted(existing)) != tuple(sorted(expected)):
                    raise LocalWorkbookHold("prior skip history differs from frozen manifest")
                return raw
            for timestamp, sheet, action, key, detail in expected:
                _append_source_history(
                    history_root, history_rows, strings, sheet=sheet,
                    action=action, issue_id=key, recorded_at_utc=timestamp,
                    source_status="Whitelist Skip",
                    evidence_description=detail.removeprefix("[MONITOR] Whitelist Skip: "),
                )
            return _repack_projected(source, infos, {
                paths["Update_History"]: ET.tostring(
                    history_root, encoding="utf-8", xml_declaration=True),
            })
    except (zipfile.BadZipFile, zipfile.LargeZipFile, ET.ParseError, OSError,
            ValueError, KeyError, IndexError) as exc:
        if isinstance(exc, LocalWorkbookHold):
            raise
        raise LocalWorkbookHold("skip history image could not prove preservation") from exc


def _validate_cabling_source_row(row):
    if type(row) is not CablingSourceRow:
        raise LocalWorkbookHold("cabling projection requires typed source values")
    if row.sheet not in ("ETH Cabling", "IB Cabling"):
        raise LocalWorkbookHold("unknown cabling sheet")
    family = "eth_cabling" if row.sheet == "ETH Cabling" else "ib_cabling"
    key = row.activity_key
    if (not isinstance(key, tuple) or len(key) != 4 or key[0] != family or
            key[3] not in ("Link Down", "Mis-wiring") or
            any(not isinstance(part, str) or not part or len(part) > 255 or
                any(char in part for char in "\x00\r\n") for part in key)):
        raise LocalWorkbookHold("cabling activity key is invalid")
    expected = row.expected_endpoints
    actual = row.actual_endpoints
    if (not isinstance(expected, tuple) or len(expected) != 4 or
            expected[:2] != key[1:3] or
            any(not isinstance(part, str) or not part or len(part) > 255 or
                any(char in part for char in "\x00\r\n") for part in expected)):
        raise LocalWorkbookHold("cabling expected endpoints are not bound to key")
    if not isinstance(actual, tuple) or len(actual) not in (0, 4):
        raise LocalWorkbookHold("cabling actual endpoints have invalid shape")
    if row.sheet == "IB Cabling" and key[3] == "Link Down" and actual:
        raise LocalWorkbookHold("IB Missing has no actual-side authority")
    if actual and any(not isinstance(part, str) or len(part) > 255 or
                      any(char in part for char in "\x00\r\n") for part in actual):
        raise LocalWorkbookHold("cabling actual endpoint is invalid")
    _literal(row.source_status, "source status", limit=80)
    _literal(row.evidence_description, "source evidence", limit=800)
    if not isinstance(row.recorded_at_utc, str) or not _UTC_TIMESTAMP.fullmatch(row.recorded_at_utc):
        raise LocalWorkbookHold("cabling action time is not canonical UTC")
    try:
        datetime.strptime(row.recorded_at_utc, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise LocalWorkbookHold("cabling action time is invalid") from exc
    return hashlib.sha256(_canonical_json(key)).hexdigest()[:16]


def _cabling_ids(parsed, strings):
    seen = set()
    highest = 30000
    for sheet in ("ETH Cabling", "IB Cabling"):
        for number, (_, cells) in parsed[sheet][1].items():
            if number <= 2:
                continue
            cell = cells.get(f"A{number}")
            value = _cell_text(cell, strings) if cell is not None else None
            if not value:
                continue
            if not _CABLING_ID.fullmatch(value) or value in seen:
                raise LocalWorkbookHold("cabling IDs are malformed or duplicated")
            seen.add(value)
            highest = max(highest, int(value[2:]))
    return seen, highest


def _cabling_active_row(rows, strings, row, prefix):
    matches = []
    for number, (_, cells) in rows.items():
        if number <= 2:
            continue
        def value(column):
            cell = cells.get(f"{column}{number}")
            return _cell_text(cell, strings) if cell is not None else None
        if (value("K"), value("L"), value("F")) != (
                row.activity_key[1], row.activity_key[2], row.activity_key[3]):
            continue
        if value("U") == "Closed":
            continue
        if not (value("G") or "").startswith(prefix):
            raise LocalWorkbookHold("matching active cabling row is not monitor-owned")
        matches.append(number)
    if len(matches) > 1:
        raise LocalWorkbookHold("duplicate active cabling activity key")
    return matches[0] if matches else None


def _cabling_blank_row(root, rows, strings):
    for number in sorted(rows):
        if number <= 2:
            continue
        item, cells = rows[number]
        if all(_is_empty_cell(cell, strings) for cell in cells.values()):
            return number, item, cells
    number = max(rows, default=2) + 1
    if number > 1048576:
        raise LocalWorkbookHold("cabling sheet has no free row")
    data = root.find(f"{{{_MAIN}}}sheetData")
    item = ET.Element(f"{{{_MAIN}}}row", {"r": str(number)})
    data.append(item)
    cells = {}
    rows[number] = (item, cells)
    return number, item, cells


def _bounded_projectable_archive(source):
    infos = source.infolist()
    names = set(source.namelist())
    if (len(infos) > _MAX_ZIP_MEMBERS or len(names) != len(infos) or
            any(info.file_size > _MAX_MEMBER_BYTES for info in infos) or
            sum(info.file_size for info in infos) > _MAX_EXPANDED_BYTES):
        raise LocalWorkbookHold("source workbook ZIP bounds or member identity changed")
    return infos, names


def _repack_projected(source, infos, changed):
    output = BytesIO()
    with zipfile.ZipFile(output, "w") as target:
        target.comment = source.comment
        for member in infos:
            # writestr mutates ZipInfo's CRC/size; a source member must remain
            # readable for the postimage check and for any caller-held archive.
            target.writestr(deepcopy(member),
                            changed.get(member.filename, source.read(member.filename)))
    result = output.getvalue()
    if len(result) > _MAX_FILE_BYTES:
        raise LocalWorkbookHold("projected workbook exceeds local commit bound")
    return result


def project_cabling_workbook_image(raw, source_rows):
    """Pure ETH/IB business-row image; typed rows never prove source or commit."""
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_FILE_BYTES:
        raise LocalWorkbookHold("source workbook bytes are invalid or oversized")
    if not isinstance(source_rows, (tuple, list)) or len(source_rows) > 10000:
        raise LocalWorkbookHold("cabling source rows are not bounded")
    seen_keys = set()
    pairs = []
    for row in source_rows:
        digest = _validate_cabling_source_row(row)
        if row.activity_key in seen_keys:
            raise LocalWorkbookHold("duplicate cabling source activity key")
        seen_keys.add(row.activity_key)
        pairs.append((row, f"[MONITOR][{row.activity_key[0]}][{digest}]"))
    pairs.sort(key=lambda item: item[0].activity_key)
    try:
        with zipfile.ZipFile(BytesIO(raw)) as source:
            infos, names = _bounded_projectable_archive(source)
            paths = _sheet_paths(source, names)
            strings = _shared_strings(source, names)
            parsed = _validate_headers(source, names, paths, strings)
            ids, highest = _cabling_ids(parsed, strings)
            history_root, history_rows = parsed["Update_History"]
            touched = set()
            for row, prefix in pairs:
                root, rows = parsed[row.sheet]
                number = _cabling_active_row(rows, strings, row, prefix)
                insert = number is None
                description = prefix + " " + row.source_status + ": " + row.evidence_description
                _literal(description, "cabling description")
                if not insert:
                    _, existing_cells = rows[number]
                    def existing(column):
                        cell = existing_cells.get(f"{column}{number}")
                        return _cell_text(cell, strings) if cell is not None else None
                    actual = row.actual_endpoints or ("", "", "", "")
                    if (existing("G") == description and
                            all((existing(column) or "") == value for column, value in
                                zip(("M", "N", "S", "T"), actual))):
                        continue
                if insert:
                    if highest >= 99999:
                        raise LocalWorkbookHold("shared NV sequence is exhausted")
                    highest += 1
                    issue_id = f"NV{highest:05d}"
                    if issue_id in ids:
                        raise LocalWorkbookHold("shared NV sequence collided")
                    ids.add(issue_id)
                    number, target, cells = _cabling_blank_row(root, rows, strings)
                    values = {
                        "A": issue_id, "B": "ZTP Monitor", "C": "ZTP Monitor",
                        "D": row.recorded_at_utc[:10],
                        "E": "ETH" if row.sheet == "ETH Cabling" else "IB",
                        "F": row.activity_key[3], "G": description,
                        "K": row.expected_endpoints[0], "L": row.expected_endpoints[1],
                        "Q": row.expected_endpoints[2], "R": row.expected_endpoints[3],
                        "U": "New",
                    }
                else:
                    target, cells = rows[number]
                    issue_id = _cell_text(cells[f"A{number}"], strings)
                    values = {"G": description}
                if row.actual_endpoints:
                    values.update(zip(("M", "N", "S", "T"), row.actual_endpoints))
                for column, value in values.items():
                    if value:
                        _set_literal_cell(target, cells, f"{column}{number}", value)
                for column, value in zip(("M", "N", "S", "T"),
                                         row.actual_endpoints or ("", "", "", "")):
                    if not value:
                        _clear_literal_cell(cells, f"{column}{number}")
                _append_source_history(
                    history_root, history_rows, strings, sheet=row.sheet,
                    action="Insert" if insert else "Update", issue_id=issue_id,
                    recorded_at_utc=row.recorded_at_utc,
                    source_status=row.source_status,
                    evidence_description=row.evidence_description,
                )
                touched.add(row.sheet)
            if not touched:
                return raw
            touched.add("Update_History")
            changed = {paths[sheet]: ET.tostring(parsed[sheet][0], encoding="utf-8", xml_declaration=True)
                       for sheet in touched}
            return _repack_projected(source, infos, changed)
    except (zipfile.BadZipFile, zipfile.LargeZipFile, ET.ParseError, OSError,
            ValueError, KeyError, IndexError) as exc:
        if isinstance(exc, LocalWorkbookHold):
            raise
        raise LocalWorkbookHold("cabling image projection could not prove preservation") from exc


def _validate_switch_source_row(row):
    if type(row) is not SwitchSourceWorkbookRow:
        raise LocalWorkbookHold("switch projection requires typed source values")
    key = row.activity_key
    if (not isinstance(key, tuple) or len(key) != 4 or key[0] != "switch" or
            any(not isinstance(part, str) or not _COMPONENT.fullmatch(part)
                for part in key[1:3]) or
            not isinstance(key[3], str) or not _SWITCH_COMPONENT.fullmatch(key[3])):
        raise LocalWorkbookHold("switch source activity key is invalid")
    if row.fabric not in ("Compute", "OOB", "Inband") or row.fabric_source not in (
            "type", "template", "hostname-fallback"):
        raise LocalWorkbookHold("switch fabric classification is not sourced")
    _literal(row.priority, "switch priority", limit=40)
    _literal(row.evidence_description, "switch evidence", limit=800)
    if not isinstance(row.recorded_at_utc, str) or not _UTC_TIMESTAMP.fullmatch(row.recorded_at_utc):
        raise LocalWorkbookHold("switch action time is not canonical UTC")
    try:
        datetime.strptime(row.recorded_at_utc, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise LocalWorkbookHold("switch action time is invalid") from exc


def _switch_active_source_row(rows, strings, row):
    key = row.activity_key
    prefix = f"[MONITOR][{key[2]}][{key[3]}]"
    matches = []
    for number, (_, cells) in rows.items():
        if number <= 2:
            continue
        host = cells.get(f"F{number}")
        description = cells.get(f"L{number}")
        if host is None or description is None:
            continue
        if (_cell_text(host, strings) == key[1] and
                (_cell_text(description, strings) or "").startswith(prefix)):
            status = cells.get(f"N{number}")
            if status is not None and _cell_text(status, strings) == "Closed":
                continue
            matches.append(number)
    if len(matches) > 1:
        raise LocalWorkbookHold("duplicate active switch source key")
    return matches[0] if matches else None


def _assert_switch_formula_postimage(source, source_names, source_path, result, row_numbers):
    """Re-read the produced package and pin every touched row's lookup formulas."""
    old_root, old_rows = _rows(source, source_names, source_path)
    del old_root
    with zipfile.ZipFile(BytesIO(result)) as projected:
        _, new_names = _bounded_projectable_archive(projected)
        new_paths = _sheet_paths(projected, new_names)
        if new_paths["ETH&IB Switch"] != source_path:
            raise LocalWorkbookHold("switch postimage changed the sheet identity")
        _, new_rows = _rows(projected, new_names, source_path)
        strings = _shared_strings(projected, new_names)
        for number in row_numbers:
            before, after = old_rows.get(number), new_rows.get(number)
            if before is None or after is None:
                raise LocalWorkbookHold("switch postimage lost a touched row")
            for column in "DEGHI":
                old_cell = before[1].get(f"{column}{number}")
                new_cell = after[1].get(f"{column}{number}")
                if ((ET.tostring(old_cell) if old_cell is not None else None) !=
                        (ET.tostring(new_cell) if new_cell is not None else None)):
                    raise LocalWorkbookHold("switch postimage changed a lookup cell")
                if column in "DEGH":
                    formula = new_cell.find(f"{{{_MAIN}}}f") if new_cell is not None else None
                    if formula is None or not formula.text:
                        raise LocalWorkbookHold("switch postimage lost a lookup formula")
                elif number >= 4 and not _is_empty_cell(new_cell, strings):
                    raise LocalWorkbookHold("switch postimage filled a reserved Model cell")


def project_switch_workbook_image(raw, source_rows):
    """Pure Switch Status row projection, with no manifest or commit authority."""
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_FILE_BYTES:
        raise LocalWorkbookHold("switch source workbook is invalid or oversized")
    if not isinstance(source_rows, (tuple, list)) or len(source_rows) > 10000:
        raise LocalWorkbookHold("switch source rows are not bounded")
    seen = set()
    for row in source_rows:
        _validate_switch_source_row(row)
        if row.activity_key in seen:
            raise LocalWorkbookHold("duplicate switch source activity key")
        seen.add(row.activity_key)
    try:
        with zipfile.ZipFile(BytesIO(raw)) as source:
            infos, names = _bounded_projectable_archive(source)
            paths = _sheet_paths(source, names)
            strings = _shared_strings(source, names)
            parsed = _validate_headers(source, names, paths, strings)
            switch_root, switch_rows = parsed["ETH&IB Switch"]
            history_root, history_rows = parsed["Update_History"]
            changed_any = False
            touched_rows = set()
            for row in sorted(source_rows, key=lambda item: item.activity_key):
                key = row.activity_key
                description = (f"[MONITOR][{key[2]}][{key[3]}] "
                               f"[fabric_source={row.fabric_source}] "
                               f"{row.evidence_description}")
                _literal(description, "switch description")
                number = _switch_active_source_row(switch_rows, strings, row)
                insert = number is None
                if not insert:
                    _, cells = switch_rows[number]
                    current = cells.get(f"L{number}")
                    if _cell_text(current, strings) == description:
                        continue
                if insert:
                    edit = SwitchRowInsert(
                        operation_id="source-image-only", activity_key=key,
                        submit_date=row.recorded_at_utc[:10], submitter="ZTP Monitor",
                        fabric=row.fabric, priority=row.priority,
                        description=description,
                    )
                    issue_id, addresses = _apply_switch_insert(switch_rows, strings, edit)
                    number = int(addresses[0].lstrip("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
                else:
                    target, cells = switch_rows[number]
                    issue_id = _cell_text(cells[f"A{number}"], strings)
                    if not isinstance(issue_id, str) or not _RESERVED_SWITCH_ID.fullmatch(issue_id):
                        raise LocalWorkbookHold("active switch source row lacks reserved Issue ID")
                    _set_literal_cell(target, cells, f"L{number}", description)
                touched_rows.add(number)
                _append_source_history(
                    history_root, history_rows, strings, sheet="ETH&IB Switch",
                    action="Insert" if insert else "Update", issue_id=issue_id,
                    recorded_at_utc=row.recorded_at_utc,
                    source_status=key[2], evidence_description=row.evidence_description,
                )
                changed_any = True
            if not changed_any:
                return raw
            changed = {
                paths["ETH&IB Switch"]: ET.tostring(switch_root, encoding="utf-8", xml_declaration=True),
                paths["Update_History"]: ET.tostring(history_root, encoding="utf-8", xml_declaration=True),
            }
            result = _repack_projected(source, infos, changed)
            _assert_switch_formula_postimage(
                source, names, paths["ETH&IB Switch"], result, touched_rows)
            return result
    except (zipfile.BadZipFile, zipfile.LargeZipFile, ET.ParseError, OSError,
            ValueError, KeyError, IndexError) as exc:
        if isinstance(exc, LocalWorkbookHold):
            raise
        raise LocalWorkbookHold("switch image projection could not prove preservation") from exc


def _validate_headers(archive, names, paths, strings):
    parsed = {}
    for sheet, expected in _EXPECTED_HEADERS.items():
        root, rows = _rows(archive, names, paths[sheet])
        if 2 not in rows:
            raise LocalWorkbookHold(f"{sheet} row-2 header is missing")
        header_cells = rows[2][1]
        if (len(header_cells) != len(expected) or
                tuple(_cell_text(header_cells.get(f"{_column(i)}2"), strings)
                      if header_cells.get(f"{_column(i)}2") is not None else None
                      for i in range(1, len(expected) + 1)) != expected):
            raise LocalWorkbookHold(f"{sheet} row-2 header changed")
        parsed[sheet] = (root, rows)
    return parsed


def _operator_addresses(parsed, paths, strings):
    allowed = {}
    for sheet, columns in (
            ("ETH&IB Switch", ("M", "N", "O", "P", "Q", "R", "S", "T", "U")),
            ("ETH Cabling", ("U", "V", "W", "X", "Y", "Z", "AA", "AB")),
            ("IB Cabling", ("U", "V", "W", "X", "Y", "Z", "AA", "AB"))):
        addresses = set()
        for number, (_, cells) in parsed[sheet][1].items():
            if number <= 2:
                continue
            id_cell = cells.get(f"A{number}")
            evidence_cell = cells.get(f"{'L' if sheet == 'ETH&IB Switch' else 'G'}{number}")
            issue_id = _cell_text(id_cell, strings) if id_cell is not None else None
            evidence = _cell_text(evidence_cell, strings) if evidence_cell is not None else None
            if (isinstance(issue_id, str) and _CABLING_ID.fullmatch(issue_id) and
                    isinstance(evidence, str) and evidence.startswith("[MONITOR]")):
                addresses.update(f"{column}{number}" for column in columns)
        allowed[paths[sheet]] = addresses
    return allowed


def validate_operator_edited_workbook(source, edited, *, disallow_unproved_closure=False):
    """Narrow same-generation import of operator literal cells, never a publish permit."""
    if (type(source) is not bytes or type(edited) is not bytes or
            not 0 < len(source) <= _MAX_FILE_BYTES or
            not 0 < len(edited) <= _MAX_FILE_BYTES):
        raise LocalWorkbookHold("operator workbook bytes are invalid or oversized")
    try:
        with zipfile.ZipFile(BytesIO(source)) as before, zipfile.ZipFile(BytesIO(edited)) as after:
            old_infos, old_names = _bounded_projectable_archive(before)
            new_infos, new_names = _bounded_projectable_archive(after)
            if ([item.filename for item in old_infos] !=
                    [item.filename for item in new_infos] or before.comment != after.comment):
                raise LocalWorkbookHold("operator workbook package identity changed")
            for old, new in zip(old_infos, new_infos):
                if (old.filename, old.date_time, old.compress_type, old.comment,
                        old.extra, old.create_system, old.external_attr,
                        old.internal_attr, old.flag_bits) != (
                        new.filename, new.date_time, new.compress_type, new.comment,
                        new.extra, new.create_system, new.external_attr,
                        new.internal_attr, new.flag_bits):
                    raise LocalWorkbookHold("operator workbook ZIP metadata changed")
            old_paths, new_paths = _sheet_paths(before, old_names), _sheet_paths(after, new_names)
            if old_paths != new_paths:
                raise LocalWorkbookHold("operator workbook sheet identity changed")
            old_strings, new_strings = (_shared_strings(before, old_names),
                                        _shared_strings(after, new_names))
            old_parsed = _validate_headers(before, old_names, old_paths, old_strings)
            new_parsed = _validate_headers(after, new_names, new_paths, new_strings)
            allowed_by_member = _operator_addresses(old_parsed, old_paths, old_strings)
            changes = 0
            for old, new in zip(old_infos, new_infos):
                old_body, new_body = before.read(old.filename), after.read(new.filename)
                if old_body == new_body:
                    continue
                addresses = allowed_by_member.get(old.filename)
                if not addresses:
                    raise LocalWorkbookHold("operator workbook changed a non-operator member")
                sheet = next(name for name, path in old_paths.items() if path == old.filename)
                old_root, old_rows = old_parsed[sheet]
                new_root, new_rows = new_parsed[sheet]
                for address in sorted(addresses):
                    number = int(address.lstrip("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
                    old_entry, new_entry = old_rows.get(number), new_rows.get(number)
                    old_cell = old_entry[1].get(address) if old_entry else None
                    new_cell = new_entry[1].get(address) if new_entry else None
                    if new_cell is None and old_cell is not None:
                        raise LocalWorkbookHold("operator edit removed a cell or its style")
                    if old_cell is None and new_cell is None:
                        continue
                    if ((old_cell is not None and old_cell.find(f"{{{_MAIN}}}f") is not None) or
                            (new_cell is not None and new_cell.find(f"{{{_MAIN}}}f") is not None)):
                        raise LocalWorkbookHold("operator edit touched a formula")
                    if (old_cell is not None and new_cell is not None and
                            ET.tostring(old_cell) == ET.tostring(new_cell)):
                        continue
                    old_attrs = ({key: value for key, value in old_cell.attrib.items() if key != "t"}
                                 if old_cell is not None else {"r": address})
                    new_attrs = {key: value for key, value in new_cell.attrib.items() if key != "t"}
                    inline = new_cell.find(f"{{{_MAIN}}}is")
                    if (old_attrs != new_attrs or new_cell.get("t") != "inlineStr" or
                            len(new_cell) != 1 or inline is None or len(inline) != 1 or
                            inline[0].tag != f"{{{_MAIN}}}t" or inline.attrib or
                            inline[0].attrib or inline[0].text is None or
                            len(inline[0].text) > 1024 or
                            any(char in inline[0].text for char in "\x00\r\n")):
                        raise LocalWorkbookHold("operator edit is not a bounded literal value")
                    status_cell = (
                        sheet == "ETH&IB Switch" and address.startswith("N") or
                        sheet in ("ETH Cabling", "IB Cabling") and address.startswith("U")
                    )
                    if (disallow_unproved_closure and status_cell and
                            inline[0].text.strip().casefold() == "closed"):
                        raise LocalWorkbookHold("Closed recurrence requires independent post-closure K proof")
                    changes += 1
                old_copy, new_copy = deepcopy(old_root), deepcopy(new_root)
                for root in (old_copy, new_copy):
                    data = root.find(f"{{{_MAIN}}}sheetData")
                    for row in data.findall(f"{{{_MAIN}}}row"):
                        for cell in tuple(row.findall(f"{{{_MAIN}}}c")):
                            if cell.get("r") in addresses:
                                row.remove(cell)
                if ET.tostring(old_copy) != ET.tostring(new_copy):
                    raise LocalWorkbookHold("operator edit changed workbook structure or source cells")
            if source != edited and not changes:
                raise LocalWorkbookHold("operator workbook changed bytes without a permitted edit")
            return edited
    except (zipfile.BadZipFile, zipfile.LargeZipFile, ET.ParseError, OSError,
            ValueError, KeyError, IndexError) as exc:
        if isinstance(exc, LocalWorkbookHold):
            raise
        raise LocalWorkbookHold("operator workbook edit could not be validated") from exc


def _apply_switch_edit(root, rows, strings, edit):
    key = edit.activity_key
    if (not isinstance(key, tuple) or len(key) != 4 or key[0] != "switch" or
            any(not isinstance(part, str) or not _COMPONENT.fullmatch(part) for part in key[1:]) or
            not isinstance(edit.expected_description, str) or
            not isinstance(edit.new_description, str)):
        raise LocalWorkbookHold("only a typed, bounded fake switch edit is supported")
    prefix = f"[MONITOR][{key[2]}][{key[3]}]"
    if (not edit.expected_description.startswith(prefix) or
            not edit.new_description.startswith(prefix) or
            edit.expected_description == edit.new_description or
            any(char in edit.new_description for char in "\x00\r\n")):
        raise LocalWorkbookHold("switch description does not preserve its activity key")
    matches = []
    for number, (_, cells) in rows.items():
        if number <= 2:
            continue
        host = cells.get(f"F{number}")
        description = cells.get(f"L{number}")
        if host is None or description is None:
            continue
        if _cell_text(host, strings) == key[1] and (_cell_text(description, strings) or "").startswith(prefix):
            status = cells.get(f"N{number}")
            if status is None or _cell_text(status, strings) != "Open":
                raise LocalWorkbookHold("matching switch row is not an open fake fixture")
            matches.append((number, description))
    if len(matches) != 1:
        raise LocalWorkbookHold("switch activity key is missing or duplicated")
    number, cell = matches[0]
    if _cell_text(cell, strings) != edit.expected_description or cell.find(f"{{{_MAIN}}}f") is not None:
        raise LocalWorkbookHold("switch row has stale or formula description")
    for child in list(cell):
        cell.remove(child)
    cell.set("t", "inlineStr")
    inline = ET.SubElement(cell, f"{{{_MAIN}}}is")
    ET.SubElement(inline, f"{{{_MAIN}}}t").text = edit.new_description
    return f"L{number}"


def prepare_fake_local_workbook(template_path, manifest_body, edits, *,
                                expected_template_sha256, qualified_set=None,
                                expected_manifest_id=None):
    """Return an in-memory fake workbook image or HOLD, never write a path."""
    if not isinstance(expected_template_sha256, str) or not _SHA.fullmatch(expected_template_sha256):
        raise LocalWorkbookHold("expected template digest is invalid")
    if not isinstance(edits, (tuple, list)):
        raise LocalWorkbookHold("fake workbook edits must be a bounded sequence")
    if len(edits) == 1 and isinstance(edits[0], CablingRowEdit):
        if edits[0].sheet == "IB Cabling":
            raise LocalWorkbookHold("IB authority is not available in C-5")
        raise LocalWorkbookHold("source-bound A/Z endpoint authority is not available in C-5")
    switch_update = len(edits) == 1 and isinstance(edits[0], SwitchDescriptionEdit)
    switch_insert = (len(edits) == 2 and isinstance(edits[0], SwitchRowInsert) and
                     isinstance(edits[1], HistoryAppend))
    if not (switch_update or switch_insert):
        raise LocalWorkbookHold("only one fake switch update or insert with history is supported")
    try:
        snapshot = read_whitelist_workbook(template_path)
    except WhitelistHoldError as exc:
        raise LocalWorkbookHold("template whitelist or package is invalid") from exc
    if snapshot.workbook_sha256 != expected_template_sha256:
        raise LocalWorkbookHold("template digest mismatch")
    operations, manifest_id = _manifest_operations(
        manifest_body, expected_template_sha256, snapshot.whitelist.sha256,
    )
    edit = edits[0]
    if snapshot.whitelist.rules:
        _bound_nonempty_switch(snapshot, qualified_set, manifest_body, manifest_id,
                               expected_manifest_id, edit)
    elif qualified_set is not None or expected_manifest_id is not None:
        raise LocalWorkbookHold("empty fixture cannot claim a nonempty Whitelist authority")
    operation = operations.get(edit.operation_id)
    if operation is None or tuple(operation["activity_key"]) != edit.activity_key or operation["action"] != "upsert":
        raise LocalWorkbookHold("typed edit does not match frozen operation identity")
    if switch_insert and (edits[1].operation_id != edit.operation_id or
                          edits[1].activity_key != edit.activity_key):
        raise LocalWorkbookHold("history does not match frozen operation identity")
    raw = _read_bound_source(template_path, snapshot)
    try:
        with zipfile.ZipFile(BytesIO(raw)) as source:
            names = set(source.namelist())
            paths = _sheet_paths(source, names)
            strings = _shared_strings(source, names)
            parsed = _validate_headers(source, names, paths, strings)
            switch_root, switch_rows = parsed["ETH&IB Switch"]
            changed = {}
            if switch_update:
                address = _apply_switch_edit(switch_root, switch_rows, strings, edit)
                changed_cells = (("ETH&IB Switch", address),)
            else:
                issue_id, addresses = _apply_switch_insert(switch_rows, strings, edit)
                history_root, history_rows = parsed["Update_History"]
                history_addresses = _append_history(history_root, history_rows, strings, edits[1], issue_id)
                changed[paths["Update_History"]] = ET.tostring(
                    history_root, encoding="utf-8", xml_declaration=True,
                )
                changed_cells = (tuple(("ETH&IB Switch", address) for address in addresses) +
                                 tuple(("Update_History", address) for address in history_addresses))
            changed[paths["ETH&IB Switch"]] = ET.tostring(
                switch_root, encoding="utf-8", xml_declaration=True,
            )
            output = BytesIO()
            with zipfile.ZipFile(output, "w") as target:
                target.comment = source.comment
                for member in source.infolist():
                    target.writestr(member, changed.get(member.filename, source.read(member.filename)))
    except (WhitelistHoldError, zipfile.BadZipFile, zipfile.LargeZipFile, ET.ParseError,
            OSError, ValueError) as exc:
        if isinstance(exc, LocalWorkbookHold):
            raise
        raise LocalWorkbookHold("workbook preparation could not prove preservation") from exc
    data = output.getvalue()
    return PreparedLocalWorkbook(
        data, hashlib.sha256(data).hexdigest(), snapshot.workbook_sha256,
        manifest_id, changed_cells,
    )
