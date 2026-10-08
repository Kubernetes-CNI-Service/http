"""Pure C-8 bounded business-sheet read shapes, NOT authority or a sender.

No URL, arbitrary A1 range, fields mask, header or timeout override is accepted.
Typed token and target objects are API discipline only: fixed-FD authentication,
fresh policy/allowlist/continuity and supervised one-shot send must dominate a
future network unit. Separate fixed template identity/four-header and Whitelist
shapes are necessary observations only. Complete format authority, enrollments
and History proofs are not inferred here. No mutation permission, state, journal
or socket is created.
"""
from dataclasses import dataclass, field
import math
import re
import sys
import time
from urllib.parse import urlencode

_SHEETS = frozenset(("ETH&IB Switch", "ETH Cabling", "IB Cabling"))
_FIELDS = "spreadsheetId,sheets(properties(sheetId,title),data(startRow,startColumn,rowData(values(userEnteredValue))))"
_WL_FIELDS = "spreadsheetId,sheets(properties(sheetId,title,gridProperties(rowCount,columnCount)),data(startRow,startColumn,rowData(values(userEnteredValue))))"
_TEMPLATE_ID_FIELDS = "spreadsheetId,sheets(properties(sheetId,title))"
_HISTORY_TAIL_FIELDS = "spreadsheetId,sheets(properties(sheetId,title,sheetType,gridProperties(rowCount,columnCount)),data(startRow,startColumn,rowData(values(userEnteredValue))))"
_TEMPLATE_HEADER_RANGES = ("'ETH&IB Switch'!A2:U2", "'ETH Cabling'!A2:AC2", "'IB Cabling'!A2:AC2", "'Update_History'!A2:E2")
_INSERT_COLUMNS = {
    'ETH&IB Switch': ('A', 'B', 'C', 'F', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U'),
    'ETH Cabling': tuple(chr(65 + index) for index in range(26)) + ('AA', 'AB', 'AC'),
    'IB Cabling': tuple(chr(65 + index) for index in range(26)) + ('AA', 'AB', 'AC'),
}


class SheetsReadHold(ValueError):
    def __init__(self): super().__init__("req7_sheets_read_denied")


@dataclass(frozen=True)
class PreparedSheetsRead:
    host: str
    path: str = field(repr=False)
    method: str
    headers: tuple = field(repr=False)
    body: bytes = field(repr=False)
    budget_seconds: float = 30.0


@dataclass(frozen=True)
class PreparedSheetsMutation:
    """Fixed shape only, NOT admission/permit. Keep read-child imports stdlib-only.

    The separate original composer creates and validates this necessary
    whole-batch projection. Read/token children never import that heavy graph.
    """
    host: str
    path: str = field(repr=False)
    method: str
    body: bytes = field(repr=False)
    headers: tuple = field(repr=False)
    wire_sha256: str
    binding: object = field(repr=False)
    token: object = field(repr=False)
    unit: object = field(repr=False)
    budget_seconds: float = 60.0


def prepare_sheets_read(binding, token, *, mode, sheet, first_row, last_row=None):
    """Exact columns or one exact row; discovery windows have a finite 5000-row cap.

    A finite read window is not a complete discovery proof, and no automatic
    paging/chunking occurs. Only original userEnteredValue is requested, so a
    formula or numeric/bool value cannot become a formatted literal by accident.
    HTTP grid coordinates do not establish business-key or live-row identity.
    """
    from monitor.issue_tracker_online_target import OnlineTargetBinding
    from monitor.issue_tracker_sdk_authentication import AuthenticatedToken
    failed = False
    try:
        if (type(binding) is not OnlineTargetBinding or type(binding.spreadsheet_id) is not str
                or re.fullmatch(r"[A-Za-z0-9_-]{20,4096}", binding.spreadsheet_id) is None
                or any(type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                       for digest in (binding.policy_sha256, binding.allowlist_sha256))
                or type(token) is not AuthenticatedToken or type(token.value) is not str
                or not 1 <= len(token.value) <= 8192 or re.fullmatch(r"[A-Za-z0-9._~+/\-]+=*", token.value) is None
                or type(token.expires_at) not in (int, float)
                or not time.time() < token.expires_at <= sys.float_info.max or not math.isfinite(token.expires_at)
                or type(mode) is not str or mode not in ("discovery", "row_rectangle")
                or type(sheet) is not str or sheet not in _SHEETS
                or type(first_row) is not int or not 3 <= first_row <= 2147483647):
            raise SheetsReadHold()
        maximum = 5002 if sheet == "ETH&IB Switch" else 2147483647
        if first_row > maximum: raise SheetsReadHold()
        quoted = "'" + sheet + "'!"
        if mode == "discovery":
            if (type(last_row) is not int or not first_row <= last_row <= maximum
                    or last_row - first_row + 1 > 5000):
                raise SheetsReadHold()
            # Status is part of active/Closed discovery, never inferred from
            # the description, an absent grid or a formatted formula result.
            columns = ("A", "F", "L", "N") if sheet == "ETH&IB Switch" else ("A", "F", "G", "K", "L", "Q", "R", "U")
            ranges = [quoted + "%s%d:%s%d" % (column, first_row, column, last_row) for column in columns]
        else:
            if last_row is not None and (type(last_row) is not int or last_row != first_row): raise SheetsReadHold()
            final_column = "U" if sheet == "ETH&IB Switch" else "AC"
            ranges = [quoted + "A%d:%s%d" % (first_row, final_column, first_row)]
        query = urlencode([("includeGridData", "true"), ("fields", _FIELDS), *(("ranges", value) for value in ranges)])
        path = "/v4/spreadsheets/" + binding.spreadsheet_id + "?" + query
        if len(path.encode("ascii")) > 16384: raise SheetsReadHold()
        result = PreparedSheetsRead("sheets.googleapis.com", path, "GET",
                                    (("Accept", "application/json"), ("Authorization", "Bearer " + token.value)), b"")
    except Exception:
        failed = True
    if failed: raise SheetsReadHold()
    return result


def prepare_online_whitelist_read(binding, token):
    """Read the fixed six columns and capacity, not arbitrary sheet/range input.

    The complete decoder refuses rowCount above the local 10000-row limit,
    rather than accepting a truncated rule window or silently paging. This
    necessary observation is not fresh admission or a local re-filter permit.
    """
    base = prepare_sheets_read(binding, token, mode="row_rectangle", sheet="ETH&IB Switch", first_row=3)
    query = urlencode([("includeGridData", "true"), ("fields", _WL_FIELDS), ("ranges", "'Whitelist'!A1:F10000")])
    path = "/v4/spreadsheets/" + binding.spreadsheet_id + "?" + query
    if len(path.encode("ascii")) > 16384: raise SheetsReadHold()
    return PreparedSheetsRead(base.host, path, base.method, base.headers, base.body)


def prepare_template_identity_read(binding, token):
    """All sheet identities only, no grid payload and no arbitrary fields.

    Identity and header reads remain separate observations, never an atomic
    snapshot, enrollment or send authority. The metadata-only GET does not use
    ranges: range selection must not silently limit fourteen-sheet discovery.
    https://developers.google.com/workspace/sheets/api/guides/field-masks
    """
    base = prepare_sheets_read(binding, token, mode="row_rectangle", sheet="ETH&IB Switch", first_row=3)
    query = urlencode([("includeGridData", "false"), ("fields", _TEMPLATE_ID_FIELDS)])
    return PreparedSheetsRead(base.host, "/v4/spreadsheets/" + binding.spreadsheet_id + "?" + query,
                              base.method, base.headers, base.body)


def prepare_template_header_read(binding, token):
    """Four tracker-owned row-2 headers, exact multiline literals checked later.

    This does not read row 2 of unrelated reference sheets as a header (for
    example Whitelist's actual format has its header at row 1). The independent
    Whitelist read and complete template/continuity/admission remain necessary.
    """
    base = prepare_sheets_read(binding, token, mode="row_rectangle", sheet="ETH&IB Switch", first_row=3)
    query = urlencode([("includeGridData", "true"), ("fields", _FIELDS),
                       *(("ranges", value) for value in _TEMPLATE_HEADER_RANGES)])
    return PreparedSheetsRead(base.host, "/v4/spreadsheets/" + binding.spreadsheet_id + "?" + query,
                              base.method, base.headers, base.body)


def prepare_history_read(binding, token, *, first_row, last_row):
    """One fixed five-column finite rectangle, not complete History evidence.

    The authenticated caller must separately prove the journal's before-row and
    the current tail boundary. Never silently truncate/page a larger tail or
    infer absent/duplicate unit rows from this partial observation alone.
    """
    base = prepare_sheets_read(binding, token, mode="row_rectangle", sheet="ETH&IB Switch", first_row=3)
    if (type(first_row) is not int or type(last_row) is not int
            or not 3 <= first_row <= last_row <= 2147483647 or last_row - first_row + 1 > 5000):
        raise SheetsReadHold()
    query = urlencode([("includeGridData", "true"), ("fields", _FIELDS),
                       ("ranges", "'Update_History'!A%d:E%d" % (first_row, last_row))])
    return PreparedSheetsRead(base.host, "/v4/spreadsheets/" + binding.spreadsheet_id + "?" + query,
                              base.method, base.headers, base.body)


def prepare_history_tail_read(binding, token):
    """Fixed bounded full-body observation, capacity and raw cells in ONE GET.

    The decoder refuses rowCount > 5002 instead of accepting a partial tail.
    This is not a transactional snapshot, fresh admission or COMPLETE proof;
    subsequent appends and changes still require journal-bound reconciliation.
    """
    base = prepare_sheets_read(binding, token, mode="row_rectangle", sheet="ETH&IB Switch", first_row=3)
    query = urlencode([("includeGridData", "true"), ("fields", _HISTORY_TAIL_FIELDS),
                       ("ranges", "'Update_History'!A3:E5002")])
    return PreparedSheetsRead(base.host, "/v4/spreadsheets/" + binding.spreadsheet_id + "?" + query,
                              base.method, base.headers, base.body)


def prepare_activity_sheet_read(binding, token, *, sheet):
    """One capacity-bearing explicit-column GET, not a caller-sized window.

    Actual rowCount above 5002 is rejected by the decoder rather than silently
    paging/truncating. Full observed coverage is not live continuity, CAS,
    source/admission authority or an allocation/mutation permit.
    """
    base = prepare_sheets_read(binding, token, mode='discovery', sheet=sheet, first_row=3, last_row=5002)
    parsed_query = base.path.split('?', 1)[1]
    from urllib.parse import parse_qsl
    query = parse_qsl(parsed_query, strict_parsing=True)
    query[1] = ('fields', _HISTORY_TAIL_FIELDS)
    return PreparedSheetsRead(base.host, '/v4/spreadsheets/' + binding.spreadsheet_id + '?' + urlencode(query),
                              base.method, base.headers, base.body)


def prepare_insertion_sheet_read(binding, token, *, sheet):
    """Fixed explicit occupancy columns and original capacity in one GET.

    Switch lookup-only columns are checked in a subsequent exact row, not
    treated as occupation. ALL Cabling columns, including operator columns,
    contribute to the original append tail. Bounded at 5002 rows/2 MiB; no
    silent paging, arbitrary window, allocation, reservation or send authority.
    """
    base = prepare_sheets_read(binding, token, mode='discovery', sheet=sheet, first_row=3, last_row=5002)
    query = [('includeGridData', 'true'), ('fields', _HISTORY_TAIL_FIELDS),
             *(('ranges', "'%s'!%s3:%s5002" % (sheet, letter, letter)) for letter in _INSERT_COLUMNS[sheet])]
    path = '/v4/spreadsheets/' + binding.spreadsheet_id + '?' + urlencode(query)
    if len(path.encode('ascii')) > 16384: raise SheetsReadHold()
    return PreparedSheetsRead(base.host, path, base.method, base.headers, base.body)
