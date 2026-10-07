"""G1 bounded visible metadata/reservation accounting, not online admission.

Google's documented pools are 30000 key/value characters per sheet, plus a
separate 30000-character spreadsheet pool. UTF-8 byte charging conservatively
overestimates Unicode characters/code units instead of assuming a lifetime.
https://developers.google.com/workspace/sheets/api/guides/metadata

Search without a visibility filter still cannot see another Cloud project's
PROJECT metadata. Thus a complete HTTP response does NOT establish a complete
global inventory. Every non-overflow result stays VISIBLE_ONLY_UNPROVED, never
GO/send permission. Hidden usage, enrollment authority and fresh durable
reservation domination must be resolved by the eventual admission integration.
No marker is deleted, no reservation settled, no state written or retry issued.
The uninstalled native read is for owned local fake-service tests only.
"""
from dataclasses import dataclass, field
import hashlib
import json
import re
import threading
from urllib.parse import urlencode

_FIELDS = "matchedDeveloperMetadata(developerMetadata(metadataId,metadataKey,metadataValue,location,visibility))"
_BODY = b'{"dataFilters":[{"developerMetadataLookup":{}}]}'
_LIMIT = 30000


class MetadataCapacityHold(ValueError):
    def __init__(self): super().__init__("req7_metadata_capacity_unproved")


@dataclass(frozen=True)
class PreparedMetadataRead:
    host: str
    path: str = field(repr=False)
    method: str
    headers: tuple = field(repr=False)
    body: bytes = field(repr=False)
    budget_seconds: float = 30.0


@dataclass(frozen=True)
class VisibleMetadataBudget:
    outcome: str
    pools: tuple
    outstanding_reservations: int
    source_sha256: str
    identity_sha256: str
    inventory_complete: bool = False
    counting: str = "utf8_bytes_conservative"


def prepare_metadata_capacity_read(binding, token):
    from monitor.issue_tracker_sheets_read_plan import prepare_sheets_read
    # Reuse the fixed target/token validation; never accept caller URL/filter.
    base = prepare_sheets_read(binding, token, mode="row_rectangle", sheet="ETH&IB Switch", first_row=3)
    return PreparedMetadataRead(base.host, "/v4/spreadsheets/" + binding.spreadsheet_id +
                                "/developerMetadata:search?" + urlencode({"fields": _FIELDS}), "POST",
                                base.headers + (("Content-Type", "application/json"),), _BODY)


def _validate_plan(plan):
    if (type(plan) is not PreparedMetadataRead or plan.host != "sheets.googleapis.com" or plan.method != "POST"
            or type(plan.path) is not str or type(plan.body) is not bytes or plan.body != _BODY
            or type(plan.budget_seconds) is not float or plan.budget_seconds != 30.0
            or type(plan.headers) is not tuple or len(plan.headers) != 3
            or plan.headers[0] != ("Accept", "application/json")
            or plan.headers[2] != ("Content-Type", "application/json")
            or type(plan.headers[1]) is not tuple or len(plan.headers[1]) != 2
            or plan.headers[1][0] != "Authorization" or type(plan.headers[1][1]) is not str
            or not 8 <= len(plan.headers[1][1]) <= 8199
            or re.fullmatch(r"Bearer [A-Za-z0-9._~+/\-]{1,8192}=*", plan.headers[1][1]) is None):
        raise MetadataCapacityHold()
    found = re.fullmatch(r"/v4/spreadsheets/([A-Za-z0-9_-]{20,4096})/developerMetadata:search\?" +
                        re.escape(urlencode({"fields": _FIELDS})), plan.path)
    if found is None: raise MetadataCapacityHold()
    return found.group(1)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise MetadataCapacityHold()
        result[key] = value
    return result


def _nonfinite(_value): raise MetadataCapacityHold()


def _entry(value, sheet_ids):
    if (type(value) is not dict or not {"metadataId", "metadataKey", "location", "visibility"} <= set(value)
            <= {"metadataId", "metadataKey", "metadataValue", "location", "visibility"}
            or type(value["metadataId"]) is not int or not 1 <= value["metadataId"] <= 2147483647
            or type(value["metadataKey"]) is not str or not 1 <= len(value["metadataKey"]) <= _LIMIT
            or type(value.get("metadataValue", "")) is not str or len(value.get("metadataValue", "")) > _LIMIT
            or type(value["visibility"]) is not str or value["visibility"] not in ("DOCUMENT", "PROJECT")):
        raise MetadataCapacityHold()
    key, data = value["metadataKey"], value.get("metadataValue", "")
    size = len(key.encode("utf-8", "strict")) + len(data.encode("utf-8", "strict"))
    location = value["location"]
    if type(location) is not dict: raise MetadataCapacityHold()
    kind = location.get("locationType")
    if kind == "SPREADSHEET":
        if set(location) != {"locationType", "spreadsheet"} or location["spreadsheet"] is not True:
            raise MetadataCapacityHold()
        pool = None; coordinate = None
    elif kind == "SHEET":
        if set(location) != {"locationType", "sheetId"}: raise MetadataCapacityHold()
        pool = location["sheetId"]; coordinate = None
    elif kind in ("ROW", "COLUMN"):
        if set(location) != {"locationType", "dimensionRange"}: raise MetadataCapacityHold()
        dimension = location["dimensionRange"]
        if (type(dimension) is not dict or set(dimension) != {"sheetId", "dimension", "startIndex", "endIndex"}
                or dimension["dimension"] != ("ROWS" if kind == "ROW" else "COLUMNS")
                or type(dimension["startIndex"]) is not int or type(dimension["endIndex"]) is not int
                or not 0 <= dimension["startIndex"] < dimension["endIndex"] <= 2147483647
                or dimension["endIndex"] != dimension["startIndex"] + 1):
            raise MetadataCapacityHold()
        pool = dimension["sheetId"]; coordinate = dimension["startIndex"]
    else: raise MetadataCapacityHold()
    if pool is not None and (type(pool) is not int or pool not in sheet_ids): raise MetadataCapacityHold()
    return value["metadataId"], pool, size, (key, data, value["visibility"], kind, pool, coordinate)


def observe_metadata_capacity(plan, response, identity, *, reservations):
    """Finite accounting of visible entries and supplied retained reservations.

    The arithmetic remaining value is relative ONLY to that visible inventory
    and these reservations, not authoritative globally available quota. A
    matching visible reservation avoids double charging but stays outstanding;
    it never proves COMPLETE or permits reservation reclamation.
    """
    failed = False
    try:
        from monitor.issue_tracker_sheets_read_decode import ObservedTemplateIdentity
        target = _validate_plan(plan)
        if (type(identity) is not ObservedTemplateIdentity or identity.spreadsheet_id != target
                or type(identity.sheet_ids) is not tuple or len(identity.sheet_ids) != 14
                or type(identity.source_sha256) is not str or re.fullmatch(r"[0-9a-f]{64}", identity.source_sha256) is None
                or type(reservations) is not tuple or len(reservations) > 15000
                or type(response.status) is not int or response.status != 200 or response.complete is not True
                or type(response.data) is not bytes or not 1 <= len(response.data) <= 2 * 1024 * 1024):
            raise MetadataCapacityHold()
        sheet_ids = []
        for title, identifier in identity.sheet_ids:
            if type(title) is not str or type(identifier) is not int or not 0 <= identifier <= 2147483647:
                raise MetadataCapacityHold()
            sheet_ids.append(identifier)
        if len(set(sheet_ids)) != 14: raise MetadataCapacityHold()
        document = json.loads(response.data.decode("utf-8", "strict"), object_pairs_hook=_pairs, parse_constant=_nonfinite)
        if type(document) is not dict or not set(document) <= {"matchedDeveloperMetadata"}: raise MetadataCapacityHold()
        items = document.get("matchedDeveloperMetadata", [])
        if type(items) is not list or len(items) > 30000: raise MetadataCapacityHold()
        usage = {pool: [0, 0] for pool in (None, *sheet_ids)}; observed = {}; reserved_ids = set()
        for item in items:
            if type(item) is not dict or set(item) != {"developerMetadata"}: raise MetadataCapacityHold()
            identifier, pool, size, image = _entry(item["developerMetadata"], sheet_ids)
            if identifier in observed: raise MetadataCapacityHold()
            observed[identifier] = image; usage[pool][0] += size
        for reservation in reservations:
            identifier, pool, size, image = _entry(reservation, sheet_ids)
            if identifier in reserved_ids: raise MetadataCapacityHold()
            reserved_ids.add(identifier)
            if identifier in observed:
                if observed[identifier] != image: raise MetadataCapacityHold()
            else: usage[pool][1] += size
        pools = tuple((pool, values[0], values[1], _LIMIT - sum(values)) for pool, values in usage.items())
        result = VisibleMetadataBudget("STOP_CAPACITY" if any(row[3] < 0 for row in pools) else "VISIBLE_ONLY_UNPROVED",
                                       pools, len(reservations), hashlib.sha256(response.data).hexdigest(), identity.source_sha256)
    except Exception:
        failed = True
    if failed: raise MetadataCapacityHold()
    return result


class NativeMetadataCapacityReadUnit:
    """Uninstalled one fixed read-only search; no batchUpdate or replay API."""
    def __init__(self, binding, token):
        self._plan = prepare_metadata_capacity_read(binding, token)
        self._called = False; self._lock = threading.Lock()

    def send_once(self):
        failed = False
        with self._lock:
            used = self._called; self._called = True
        if used: raise MetadataCapacityHold()
        try:
            from monitor.issue_tracker_tls_inputs import _native_complete_read
            _validate_plan(self._plan)
            result = _native_complete_read(self._plan)
        except Exception: failed = True
        if failed: raise MetadataCapacityHold()
        return result
