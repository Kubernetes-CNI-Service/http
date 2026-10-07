"""Uninstalled C-19 immutable batch composer, NOT an online send/admission API.

Caller-supplied manifests, coordinates, observations, nonces and occupied IDs
are bound, NOT authenticated as protected qualification/enrollment or global
capacity. No network, credential, permit, COMPLETE, reservation or receipt.
An eventual fixed launcher must be dominated by fresh admission and the
spreadsheet-wide owner; opaque local intent counting still does not bound sends.
The 31-bit explicit fence projection can collide: collision means HOLD, never
choose a different ID or infer that an existing fence proves this unit COMPLETE.
"""
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import json
import re

from monitor.issue_tracker_online_cells import encode_tool_cells
from monitor.issue_tracker_manifest import _runtime_operation, _validated_operations

_FAMILY = {"ETH&IB Switch": "switch", "ETH Cabling": "eth_cabling", "IB Cabling": "ib_cabling"}
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_MAX_BODY = 1024 * 1024
_MAX_REQUESTS = 1000


class SendUnitHold(ValueError):
    def __init__(self): super().__init__("req7_send_unit_unproved")


@dataclass(frozen=True)
class FrozenSendUnit:
    unit_id: str
    wire_bytes: bytes = field(repr=False)
    wire_sha256: str
    action_preimage: bytes = field(repr=False)
    action_digest: str
    outcomes: tuple
    outcome_mapping_sha256: str
    fence_metadata_id: object
    history_rows_expected: int
    pending_audit_ids: tuple
    outcome: str


def _canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8", "strict")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise SendUnitHold()
        result[key] = value
    return result


def _nonfinite(_value): raise SendUnitHold()


def _digest(value):
    if type(value) is not str or _SHA.fullmatch(value) is None: raise SendUnitHold()
    return value


def _text(value):
    if type(value) is not str or not 1 <= len(value) <= 32768 or "\x00" in value: raise SendUnitHold()
    value.encode("utf-8", "strict")
    return value


def _timestamp(value):
    if type(value) is not str or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value) is None:
        raise SendUnitHold()
    datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    return value


def _identifier(value):
    if type(value) is not int or not 0 <= value <= 2147483647: raise SendUnitHold()
    return value


def freeze_send_unit(*, manifest, manifest_id, generation_id, publish_id,
                     spreadsheet_id, sheet, sheet_id, history_sheet_id,
                     target_nonce, history_nonce, preread_sha256,
                     business, audits, occupied_metadata_ids):
    """Freeze one finite batch, without silently selecting/chunking operations.

Every target-family manifest operation must have one ordered business input.
Real C-8 encoding determines NOOP, not a caller assertion. Audit rows piggyback
only when actual business requests exist. The action digest preimage excludes
History and its own digest, while binding ALL outcomes and ALL assigned audits.
Returned byte strings cannot track later mutation of supplied dictionaries.
"""
    failed = False
    try:
        result = _freeze(manifest, manifest_id, generation_id, publish_id, spreadsheet_id,
                         sheet, sheet_id, history_sheet_id, target_nonce, history_nonce,
                         preread_sha256, business, audits, occupied_metadata_ids)
    except Exception:
        failed = True
    if failed: raise SendUnitHold()
    return result


def _freeze(manifest, manifest_id, generation_id, publish_id, spreadsheet_id,
            sheet, sheet_id, history_sheet_id, target_nonce, history_nonce,
            preread_sha256, business, audits, occupied_metadata_ids):
    if (type(manifest) is not bytes or not 1 <= len(manifest) <= _MAX_BODY
            or hashlib.sha256(manifest).hexdigest() != _digest(manifest_id)
            or type(spreadsheet_id) is not str or re.fullmatch(r"[A-Za-z0-9_-]{20,4096}", spreadsheet_id) is None
            or type(sheet) is not str or sheet not in _FAMILY
            or _identifier(sheet_id) == _identifier(history_sheet_id)
            or type(business) is not tuple or len(business) > 1000
            or type(audits) is not tuple or len(audits) > 1000
            or type(occupied_metadata_ids) is not tuple or len(occupied_metadata_ids) > 30000):
        raise SendUnitHold()
    for digest in (generation_id, publish_id, target_nonce, history_nonce, preread_sha256): _digest(digest)
    occupied = set()
    for identifier in occupied_metadata_ids:
        if _identifier(identifier) == 0 or identifier in occupied: raise SendUnitHold()
        occupied.add(identifier)
    document = json.loads(manifest.decode("utf-8", "strict"), object_pairs_hook=_pairs, parse_constant=_nonfinite)
    if type(document) is not dict or document.get("schema_version") != 1 or type(document.get("schema_version")) is not int:
        raise SendUnitHold()
    if _canonical(document) != manifest or type(document.get("operations")) is not list: raise SendUnitHold()
    if len(document["operations"]) > 1000: raise SendUnitHold()
    all_operations = _validated_operations(document["operations"], "send-unit manifest", validator=_runtime_operation)
    operations = [op for op in all_operations if op["activity_key"][0] == _FAMILY[sheet]]
    if len(operations) != len(business): raise SendUnitHold()
    identity = {"schema_version": 1, "generation_id": generation_id, "publish_id": publish_id,
                "spreadsheet_id": spreadsheet_id, "sheet": sheet, "sheet_id": sheet_id}
    unit_id = hashlib.sha256(_canonical(identity)).hexdigest()
    fence_id = (int(unit_id[:8], 16) & 0x7fffffff) or 1
    requests = []; sent = []; outcomes = []; decisions = []; coordinates = set()
    for operation, item in zip(operations, business):
        if (type(item) is not dict or set(item) != {"operation_id", "action", "row_index", "values", "observed_values", "recorded_at_utc"}
                or type(item["operation_id"]) is not str or item["operation_id"] != operation["operation_id"]
                or type(item["action"]) is not str or item["action"] not in ("insert", "update")):
            raise SendUnitHold()
        _timestamp(item["recorded_at_utc"])
        candidate = encode_tool_cells(sheet, sheet_id, item["action"], item["values"],
                                      row_index=item["row_index"], observed_values=item["observed_values"])
        if item["row_index"] is not None:
            if item["row_index"] in coordinates: raise SendUnitHold()
            coordinates.add(item["row_index"])
        outcomes.append((item["operation_id"], candidate.outcome))
        # NOOP intent hashes remain bound too; observation is not deletion of
        # a manifest operation and must not lose its intended literal image.
        decisions.append({"operation_id": item["operation_id"], "outcome": candidate.outcome,
                          "intended_sha256": candidate.intended_sha256})
        if candidate.outcome == "WIRE-CANDIDATE":
            objects = json.loads(candidate.requests_json)
            requests.extend(objects)
            sent.append({"operation_id": item["operation_id"], "activity_key": operation["activity_key"],
                         "action": item["action"], "recorded_at_utc": item["recorded_at_utc"],
                         "intended_sha256": candidate.intended_sha256, "requests": objects})
    audit_images = []; audit_ids = set()
    for item in audits:
        if type(item) is not dict or set(item) != {"event_id", "recorded_at_utc", "details"}: raise SendUnitHold()
        _text(item["event_id"]); _text(item["details"]); _timestamp(item["recorded_at_utc"])
        if item["event_id"] in audit_ids or item["event_id"] in {op["operation_id"] for op in all_operations}:
            raise SendUnitHold()
        audit_ids.add(item["event_id"])
        audit_images.append(dict(item))
    mapping_sha = hashlib.sha256(_canonical([list(row) for row in outcomes])).hexdigest()
    preimage = _canonical({"identity": identity, "manifest_id": manifest_id, "history_sheet_id": history_sheet_id,
                          "target_nonce": target_nonce, "history_nonce": history_nonce, "preread_sha256": preread_sha256,
                          "business": sent, "audits": audit_images, "outcomes": [list(row) for row in outcomes],
                          "decisions": decisions})
    if len(preimage) > _MAX_BODY: raise SendUnitHold()
    action_digest = hashlib.sha256(preimage).hexdigest()
    if not requests:
        return FrozenSendUnit(unit_id, b"", hashlib.sha256(b"").hexdigest(), preimage, action_digest,
                              tuple(outcomes), mapping_sha, None, 0, tuple(item["event_id"] for item in audit_images), "NO_SEND")
    if fence_id in occupied: raise SendUnitHold()
    common = {"schema_version": 1, "unit_id": unit_id, "manifest_id": manifest_id,
              "generation_id": generation_id, "publish_id": publish_id, "action_digest": action_digest,
              "outcome_mapping_sha256": mapping_sha, "target_nonce": target_nonce, "history_nonce": history_nonce,
              "preread_sha256": preread_sha256}
    history = []
    for item in sent:
        details = _canonical({**common, "operation_id": item["operation_id"], "intended_sha256": item["intended_sha256"]}).decode().rstrip("\n")
        history.append((item["recorded_at_utc"], sheet, item["action"], item["operation_id"], details))
    for item in audit_images:
        details = _canonical({**common, "event_id": item["event_id"], "event_details": item["details"]}).decode().rstrip("\n")
        history.append((item["recorded_at_utc"], sheet, "settings-audit", item["event_id"], details))
    requests.append({"appendCells": {"sheetId": history_sheet_id, "fields": "userEnteredValue", "rows": [
        {"values": [{"userEnteredValue": {"stringValue": text}} for text in row]} for row in history]}})
    requests.append({"createDeveloperMetadata": {"developerMetadata": {
        "metadataId": fence_id, "metadataKey": "z", "metadataValue": "1", "visibility": "DOCUMENT", "location": {"sheetId": sheet_id}}}})
    wire = _canonical({"requests": requests, "includeSpreadsheetInResponse": False})
    if len(requests) > _MAX_REQUESTS or len(wire) > _MAX_BODY: raise SendUnitHold()
    return FrozenSendUnit(unit_id, wire, hashlib.sha256(wire).hexdigest(), preimage, action_digest,
                          tuple(outcomes), mapping_sha, fence_id, len(history), (), "WIRE-CANDIDATE")
