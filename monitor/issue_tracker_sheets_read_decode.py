"""Pure exact-grid read decoding, never publication or mutation authority.

Google's spreadsheets.get field-mask/range contract and GridData startRow /
startColumn bind the HTTP projection; only userEnteredValue is requested.
https://developers.google.com/workspace/sheets/api/reference/rest/v4/spreadsheets/get
https://developers.google.com/workspace/sheets/api/reference/rest/v4/spreadsheets/sheets
Omitted empty repeated fields are projected only inside a complete, explicitly
matched requested grid. Missing grids, foreign coordinates or extra fields HOLD.
This does not establish live source/target authority, template or key continuity,
read freshness, compare-and-swap, History/fence resolution or any send permit.
"""
from dataclasses import dataclass, field
import hashlib
import json
import math
import re
from urllib.parse import parse_qsl, urlencode, urlsplit


class SheetsDecodeHold(ValueError):
    def __init__(self): super().__init__("req7_sheets_read_unproved")


@dataclass(frozen=True)
class ObservedSheetsGrid:
    sheet_id: int
    sheet_title: str
    cells: tuple = field(repr=False)
    source_sha256: str


@dataclass(frozen=True)
class ObservedTemplateIdentity:
    spreadsheet_id: str = field(repr=False)
    sheet_ids: tuple
    source_sha256: str


@dataclass(frozen=True)
class ObservedTemplateHeaders:
    checked_headers: tuple
    identity_sha256: str
    headers_sha256: str


_TEMPLATE_SHEETS = ("GPU Server", "ETH&IB Switch", "ETH Cabling", "IB Cabling", "Dashboard", "Update_History",
                    "Inventory", "ServerProfile", "PortProfile", "CVT_SUM", "CVT_Import", "Agent_status", "Whitelist", "BasicData")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise SheetsDecodeHold()
        result[key] = value
    return result


def _nonfinite(value): raise SheetsDecodeHold()


def _column(name):
    result = 0
    for char in name: result = result * 26 + ord(char) - 64
    return result - 1


def _letter(index):
    result = ""; index += 1
    while index:
        index, value = divmod(index - 1, 26); result = chr(65 + value) + result
    return result


def _geometry(plan):
    from monitor.issue_tracker_sheets_read_plan import PreparedSheetsRead, _FIELDS
    if (type(plan) is not PreparedSheetsRead or type(plan.host) is not str or plan.host != "sheets.googleapis.com"
            or type(plan.method) is not str or plan.method != "GET" or type(plan.path) is not str
            or len(plan.path) > 16384 or type(plan.body) is not bytes or plan.body != b""
            or type(plan.budget_seconds) is not float or plan.budget_seconds != 30.0):
        raise SheetsDecodeHold()
    parsed = urlsplit(plan.path)
    match = re.fullmatch(r"/v4/spreadsheets/([A-Za-z0-9_-]{20,4096})", parsed.path)
    if parsed.scheme or parsed.netloc or parsed.fragment or match is None: raise SheetsDecodeHold()
    query = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    if (len(query) not in (3, 5, 9) or query[:2] != [("includeGridData", "true"), ("fields", _FIELDS)]
            or any(key != "ranges" for key, value in query[2:])
            or plan.path != parsed.path + "?" + urlencode(query)):
        raise SheetsDecodeHold()
    geometries = []; title = None
    for _key, value in query[2:]:
        found = re.fullmatch(r"'(ETH&IB Switch|ETH Cabling|IB Cabling)'!([A-Z]{1,2})([1-9][0-9]{0,9}):([A-Z]{1,2})([1-9][0-9]{0,9})", value)
        if found is None: raise SheetsDecodeHold()
        current, first_column, first_row, last_column, last_row = found.groups()
        if title is not None and current != title: raise SheetsDecodeHold()
        title = current; first, last = int(first_row) - 1, int(last_row) - 1
        start, end = _column(first_column), _column(last_column)
        maximum = 5001 if title == "ETH&IB Switch" else 2147483646
        if not 2 <= first <= last <= maximum or last - first + 1 > 5000: raise SheetsDecodeHold()
        geometries.append((first, start, last, end))
    if len(geometries) == 1:
        first, start, last, end = geometries[0]
        if first != last or start != 0 or end != (20 if title == "ETH&IB Switch" else 28): raise SheetsDecodeHold()
    else:
        columns = (0, 5, 11) if title == "ETH&IB Switch" else (0, 5, 6, 10, 11, 16, 17)
        if (tuple(value[1] for value in geometries) != columns or any(value[1] != value[3] for value in geometries)
                or len({(value[0], value[2]) for value in geometries}) != 1):
            raise SheetsDecodeHold()
    return match.group(1), title, {(first, start): (last, end) for first, start, last, end in geometries}


def _cell(value):
    if type(value) is not dict or not set(value) <= {"userEnteredValue"}: raise SheetsDecodeHold()
    entered = value.get("userEnteredValue", {})
    if type(entered) is not dict or len(entered) > 1: raise SheetsDecodeHold()
    if not entered: return ()
    key, data = next(iter(entered.items()))
    if key in ("stringValue", "formulaValue"):
        if type(data) is not str or len(data) > 32768 or "\x00" in data or (key == "formulaValue" and not data):
            raise SheetsDecodeHold()
        data.encode("utf-8", "strict")
    elif key == "boolValue":
        if type(data) is not bool: raise SheetsDecodeHold()
    elif key == "numberValue":
        if type(data) not in (int, float) or not math.isfinite(data): raise SheetsDecodeHold()
    else: raise SheetsDecodeHold()
    return ((key, data),)


def decode_sheets_read(plan, response):
    """A strict immutable necessary read image, never APPLIED or send eligibility."""
    failed = False
    try:
        target, title, expected = _geometry(plan)
        status, complete, source = response.status, response.complete, response.data
        if (type(status) is not int or status != 200 or complete is not True
                or type(source) is not bytes or not 1 <= len(source) <= 2 * 1024 * 1024):
            raise SheetsDecodeHold()
        document = json.loads(source.decode("utf-8", "strict"), object_pairs_hook=_pairs, parse_constant=_nonfinite)
        if (type(document) is not dict or set(document) != {"spreadsheetId", "sheets"}
                or type(document["spreadsheetId"]) is not str or document["spreadsheetId"] != target
                or type(document["sheets"]) is not list or len(document["sheets"]) != 1):
            raise SheetsDecodeHold()
        sheet = document["sheets"][0]
        if type(sheet) is not dict or set(sheet) != {"properties", "data"}: raise SheetsDecodeHold()
        props, grids = sheet["properties"], sheet["data"]
        if (type(props) is not dict or set(props) != {"sheetId", "title"}
                or type(props["sheetId"]) is not int or not 0 <= props["sheetId"] <= 2147483647
                or type(props["title"]) is not str or props["title"] != title
                or type(grids) is not list or len(grids) != len(expected)):
            raise SheetsDecodeHold()
        seen = set(); cells = []
        for grid in grids:
            if type(grid) is not dict or not {"startRow"} <= set(grid) <= {"startRow", "startColumn", "rowData"}:
                raise SheetsDecodeHold()
            first, start = grid["startRow"], grid.get("startColumn", 0)
            if (type(first) is not int or type(start) is not int
                    or (first, start) not in expected or (first, start) in seen):
                raise SheetsDecodeHold()
            seen.add((first, start)); last, end = expected[(first, start)]
            rows = grid.get("rowData", [])
            if type(rows) is not list or len(rows) > last - first + 1: raise SheetsDecodeHold()
            for offset in range(last - first + 1):
                row = rows[offset] if offset < len(rows) else {}
                if type(row) is not dict or not set(row) <= {"values"}: raise SheetsDecodeHold()
                values = row.get("values", [])
                if type(values) is not list or len(values) > end - start + 1: raise SheetsDecodeHold()
                for column in range(start, end + 1):
                    value = values[column - start] if column - start < len(values) else {}
                    cells.append((first + offset, column, _cell(value)))
        if seen != set(expected): raise SheetsDecodeHold()
        frozen = tuple((row, _letter(column), value) for row, column, value in sorted(cells))
        result = ObservedSheetsGrid(props["sheetId"], title, frozen, hashlib.sha256(source).hexdigest())
    except Exception:
        failed = True
    if failed: raise SheetsDecodeHold()
    return result


def _template_target(plan, *, headers):
    from monitor.issue_tracker_sheets_read_plan import PreparedSheetsRead, _FIELDS, _TEMPLATE_ID_FIELDS, _TEMPLATE_HEADER_RANGES
    if (type(plan) is not PreparedSheetsRead or type(plan.host) is not str or plan.host != "sheets.googleapis.com"
            or type(plan.method) is not str or plan.method != "GET" or type(plan.path) is not str
            or len(plan.path) > 16384 or type(plan.body) is not bytes or plan.body != b""
            or type(plan.budget_seconds) is not float or plan.budget_seconds != 30.0):
        raise SheetsDecodeHold()
    parsed = urlsplit(plan.path)
    match = re.fullmatch(r"/v4/spreadsheets/([A-Za-z0-9_-]{20,4096})", parsed.path)
    query = ([("includeGridData", "true"), ("fields", _FIELDS),
              *(("ranges", value) for value in _TEMPLATE_HEADER_RANGES)] if headers else
             [("includeGridData", "false"), ("fields", _TEMPLATE_ID_FIELDS)])
    if (parsed.scheme or parsed.netloc or parsed.fragment or match is None
            or plan.path != parsed.path + "?" + urlencode(query)):
        raise SheetsDecodeHold()
    return match.group(1)


def _template_document(response, target):
    status, complete, source = response.status, response.complete, response.data
    if (type(status) is not int or status != 200 or complete is not True
            or type(source) is not bytes or not 1 <= len(source) <= 2 * 1024 * 1024):
        raise SheetsDecodeHold()
    document = json.loads(source.decode("utf-8", "strict"), object_pairs_hook=_pairs, parse_constant=_nonfinite)
    if (type(document) is not dict or set(document) != {"spreadsheetId", "sheets"}
            or type(document["spreadsheetId"]) is not str or document["spreadsheetId"] != target
            or type(document["sheets"]) is not list):
        raise SheetsDecodeHold()
    return document["sheets"], hashlib.sha256(source).hexdigest()


def _template_property(properties):
    if (type(properties) is not dict or set(properties) != {"sheetId", "title"}
            or type(properties["sheetId"]) is not int or not 0 <= properties["sheetId"] <= 2147483647
            or type(properties["title"]) is not str):
        raise SheetsDecodeHold()
    return properties["title"], properties["sheetId"]


def decode_template_identity(plan, response):
    """Complete fourteen unique titles and numeric IDs; not live enrollment."""
    failed = False
    try:
        target = _template_target(plan, headers=False)
        sheets, digest = _template_document(response, target)
        if len(sheets) != len(_TEMPLATE_SHEETS): raise SheetsDecodeHold()
        found = {}; ids = set()
        for sheet in sheets:
            if type(sheet) is not dict or set(sheet) != {"properties"}: raise SheetsDecodeHold()
            title, sheet_id = _template_property(sheet["properties"])
            if title not in _TEMPLATE_SHEETS or title in found or sheet_id in ids: raise SheetsDecodeHold()
            found[title] = sheet_id; ids.add(sheet_id)
        result = ObservedTemplateIdentity(target, tuple((title, found[title]) for title in _TEMPLATE_SHEETS), digest)
    except Exception:
        failed = True
    if failed: raise SheetsDecodeHold()
    return result


def decode_template_headers(plan, response, identity):
    """Strict row-2 tracker headers bound to the previous complete identity.

    Public dataclasses/digests are API discipline, not authority. Two reads do
    not prove continuity, freshness, before/after CAS or mutation eligibility.
    """
    from monitor.issue_tracker_local_workbook import _EXPECTED_HEADERS
    failed = False
    try:
        target = _template_target(plan, headers=True)
        if (type(identity) is not ObservedTemplateIdentity or identity.spreadsheet_id != target
                or type(identity.sheet_ids) is not tuple or len(identity.sheet_ids) != 14
                or type(identity.source_sha256) is not str or re.fullmatch(r"[0-9a-f]{64}", identity.source_sha256) is None):
            raise SheetsDecodeHold()
        expected_ids = {}; unique = set()
        for pair, title in zip(identity.sheet_ids, _TEMPLATE_SHEETS):
            if (type(pair) is not tuple or len(pair) != 2 or type(pair[0]) is not str or pair[0] != title
                    or type(pair[1]) is not int or not 0 <= pair[1] <= 2147483647 or pair[1] in unique):
                raise SheetsDecodeHold()
            expected_ids[title] = pair[1]; unique.add(pair[1])
        sheets, digest = _template_document(response, target)
        if len(sheets) != 4: raise SheetsDecodeHold()
        seen = set()
        for sheet in sheets:
            if type(sheet) is not dict or set(sheet) != {"properties", "data"}: raise SheetsDecodeHold()
            title, sheet_id = _template_property(sheet["properties"])
            if title not in _EXPECTED_HEADERS or title in seen or sheet_id != expected_ids[title]: raise SheetsDecodeHold()
            seen.add(title); grids = sheet["data"]
            if type(grids) is not list or len(grids) != 1: raise SheetsDecodeHold()
            grid = grids[0]
            if (type(grid) is not dict or not {"startRow", "rowData"} <= set(grid) <= {"startRow", "startColumn", "rowData"}
                    or type(grid["startRow"]) is not int or grid["startRow"] != 1
                    or type(grid.get("startColumn", 0)) is not int or grid.get("startColumn", 0) != 0):
                raise SheetsDecodeHold()
            rows = grid["rowData"]
            if type(rows) is not list or len(rows) != 1 or type(rows[0]) is not dict or set(rows[0]) != {"values"}: raise SheetsDecodeHold()
            values = rows[0]["values"]; header = _EXPECTED_HEADERS[title]
            if type(values) is not list or len(values) != len(header): raise SheetsDecodeHold()
            for cell, expected in zip(values, header):
                if _cell(cell) != (("stringValue", expected),): raise SheetsDecodeHold()
        if seen != set(_EXPECTED_HEADERS): raise SheetsDecodeHold()
        result = ObservedTemplateHeaders(tuple((title, len(header)) for title, header in _EXPECTED_HEADERS.items()),
                                         identity.source_sha256, digest)
    except Exception:
        failed = True
    if failed: raise SheetsDecodeHold()
    return result
