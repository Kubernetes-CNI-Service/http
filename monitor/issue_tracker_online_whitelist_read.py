"""Pure C-24 complete online rule comparison, NOT live admission or a sender.

The caller must obtain this new read before every governed online unit and
revalidate current sources, policy, credential/allowlist, template, continuity
and recovery independently. The result never changes the frozen local manifest
or its qualification decisions. A finite window is complete only when the
observed sheet capacity fits; larger/unreadable/changed sheets HOLD, no paging.
"""
from dataclasses import dataclass
import hashlib
import json
import re
from urllib.parse import urlencode, urlsplit

from monitor.issue_tracker_whitelist import _validate_snapshot, freeze_whitelist_sheet


class OnlineWhitelistReadHold(ValueError):
    def __init__(self): super().__init__("req7_online_whitelist_unproved")


@dataclass(frozen=True)
class ObservedOnlineWhitelist:
    sheet_id: int
    row_count: int
    rules_sha256: str
    source_sha256: str


def compare_online_whitelist_read(plan, response, frozen_local_snapshot):
    """Necessary complete same-rule evidence only; no refilter or send permit."""
    from monitor.issue_tracker_sheets_read_plan import PreparedSheetsRead, _WL_FIELDS
    from monitor.issue_tracker_sheets_read_decode import _pairs, _nonfinite, _cell
    failed = False
    try:
        _validate_snapshot(frozen_local_snapshot)
        if (type(plan) is not PreparedSheetsRead or plan.host != "sheets.googleapis.com"
                or plan.method != "GET" or type(plan.path) is not str or len(plan.path) > 16384
                or type(plan.body) is not bytes or plan.body != b""
                or type(plan.budget_seconds) is not float or plan.budget_seconds != 30.0):
            raise OnlineWhitelistReadHold()
        parsed = urlsplit(plan.path)
        found = re.fullmatch(r"/v4/spreadsheets/([A-Za-z0-9_-]{20,4096})", parsed.path)
        query = urlencode([("includeGridData", "true"), ("fields", _WL_FIELDS), ("ranges", "'Whitelist'!A1:F10000")])
        if (found is None or parsed.scheme or parsed.netloc or parsed.fragment
                or plan.path != parsed.path + "?" + query):
            raise OnlineWhitelistReadHold()
        status, complete, source = response.status, response.complete, response.data
        if (type(status) is not int or status != 200 or complete is not True
                or type(source) is not bytes or not 1 <= len(source) <= 2 * 1024 * 1024):
            raise OnlineWhitelistReadHold()
        document = json.loads(source.decode("utf-8", "strict"), object_pairs_hook=_pairs, parse_constant=_nonfinite)
        if (type(document) is not dict or set(document) != {"spreadsheetId", "sheets"}
                or type(document["spreadsheetId"]) is not str or document["spreadsheetId"] != found.group(1)
                or type(document["sheets"]) is not list or len(document["sheets"]) != 1):
            raise OnlineWhitelistReadHold()
        sheet = document["sheets"][0]
        if type(sheet) is not dict or set(sheet) != {"properties", "data"}: raise OnlineWhitelistReadHold()
        props = sheet["properties"]
        if (type(props) is not dict or set(props) != {"sheetId", "title", "gridProperties"}
                or type(props["sheetId"]) is not int or not 0 <= props["sheetId"] <= 2147483647
                or type(props["title"]) is not str or props["title"] != "Whitelist"):
            raise OnlineWhitelistReadHold()
        capacity = props["gridProperties"]
        if (type(capacity) is not dict or set(capacity) != {"rowCount", "columnCount"}
                or type(capacity["rowCount"]) is not int or not 1 <= capacity["rowCount"] <= 10000
                or type(capacity["columnCount"]) is not int or not 6 <= capacity["columnCount"] <= 18278):
            raise OnlineWhitelistReadHold()
        grids = sheet["data"]
        if type(grids) is not list or len(grids) != 1: raise OnlineWhitelistReadHold()
        grid = grids[0]
        if type(grid) is not dict or not set(grid) <= {"startRow", "startColumn", "rowData"}: raise OnlineWhitelistReadHold()
        for field in ("startRow", "startColumn"):
            if type(grid.get(field, 0)) is not int or grid.get(field, 0) != 0: raise OnlineWhitelistReadHold()
        rows = grid.get("rowData", [])
        if type(rows) is not list or not 1 <= len(rows) <= capacity["rowCount"]: raise OnlineWhitelistReadHold()
        literal_rows = []
        for row in rows:
            if type(row) is not dict or not set(row) <= {"values"}: raise OnlineWhitelistReadHold()
            values = row.get("values", [])
            if type(values) is not list or len(values) > 6: raise OnlineWhitelistReadHold()
            literal = []
            for offset in range(6):
                entered = dict(_cell(values[offset] if offset < len(values) else {}))
                if entered and set(entered) != {"stringValue"}: raise OnlineWhitelistReadHold()
                literal.append(entered.get("stringValue"))
            literal_rows.append(literal)
        # Omitted trailing empty rows cannot change normalized rules. The row
        # capacity and complete explicit range prevent unseen rules after 10000.
        observed = freeze_whitelist_sheet(literal_rows)
        if (observed.rules != frozen_local_snapshot.rules
                or observed.canonical_bytes != frozen_local_snapshot.canonical_bytes
                or observed.sha256 != frozen_local_snapshot.sha256):
            raise OnlineWhitelistReadHold()
        result = ObservedOnlineWhitelist(props["sheetId"], capacity["rowCount"],
                                         observed.sha256, hashlib.sha256(source).hexdigest())
    except Exception:
        failed = True
    if failed: raise OnlineWhitelistReadHold()
    return result
