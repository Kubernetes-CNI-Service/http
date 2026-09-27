"""Fail-closed, local-fixture-only qualified-operation projection for REQ7 C-5.

This seam deliberately has no runtime collector, whitelist, or IB authority.
It cannot authorize issue-tracker publication.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re

from tools.project_contract import validate_collection_cycle_identity
from monitor.issue_tracker_whitelist import _validate_snapshot, evaluate_whitelist
from monitor.issue_tracker_whitelist_workbook import WorkbookWhitelistSnapshot


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_EMPTY_WHITELIST_SHA256 = hashlib.sha256(b"[]\n").hexdigest()
_CYCLE_KEYS = {
    "identity", "fresh", "qualifying", "source_mode", "authority_sha256",
    "observations_sha256", "active_operations",
}
_OPERATION_KEYS = {"operation_id", "activity_key", "action"}
_LOCAL_MODE = "synthetic-local-fixture"


def _digest(value, field):
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _canonical_json(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _operation(value):
    if not isinstance(value, dict) or set(value) != _OPERATION_KEYS:
        raise ValueError("operation must have exact intent-only keys")
    operation_id = value["operation_id"]
    key = value["activity_key"]
    if not isinstance(operation_id, str) or not operation_id or any(
        char in operation_id for char in "\x00\r\n"
    ):
        raise ValueError("invalid operation_id")
    if not isinstance(key, (list, tuple)) or len(key) != 4 or not all(
        isinstance(part, str) and part and "\x00" not in part for part in key
    ):
        raise ValueError("activity_key must have four nonempty text components")
    if key[0] not in {"switch", "eth_cabling"}:
        raise ValueError("IB and unknown operation authorities are unavailable")
    if value["action"] != "upsert":
        raise ValueError("only local upsert intent is implemented")
    return {"operation_id": operation_id, "activity_key": list(key), "action": "upsert"}


@dataclass(frozen=True)
class QualifiedSet:
    """Typed C-5 input; never a local change projection or send authority."""

    operations_json: bytes
    cycle_ids: tuple
    source_authority_sha256: str
    observations_sha256: str
    whitelist_sha256: str
    template_sha256: str
    project_key: str
    scope: str
    k: int
    mode: str
    whitelist_snapshot: WorkbookWhitelistSnapshot | None = None
    whitelist_skips_json: bytes = b"[]"
    pre_filter_operations_json: bytes = b"[]"


def _bound_whitelist_snapshot(snapshot, rules, whitelist_sha256, template_sha256):
    """Bind a held C-24 snapshot to the same local template and frozen rules."""
    if not isinstance(snapshot, WorkbookWhitelistSnapshot):
        raise ValueError("nonempty Whitelist requires a held workbook snapshot")
    _validate_snapshot(snapshot.whitelist)
    if (type(snapshot.workbook_size) is not int or snapshot.workbook_size < 1 or
            type(snapshot.device) is not int or snapshot.device < 1 or
            type(snapshot.inode) is not int or snapshot.inode < 1):
        raise ValueError("Whitelist workbook identity is invalid")
    if _digest(snapshot.workbook_sha256, "workbook_sha256") != template_sha256:
        raise ValueError("Whitelist workbook/template digest mismatch")
    if (not isinstance(rules, list) or rules != list(snapshot.whitelist.rules) or
            snapshot.whitelist.sha256 != whitelist_sha256):
        raise ValueError("Whitelist rules or digest differ from held snapshot")
    return snapshot


def qualify_stage_l(cycles, *, k, whitelist_rules, whitelist_sha256, template_sha256,
                    whitelist_snapshot=None):
    """Intersect K consecutive eligible *synthetic* cycles, refusing all runtime sources.

    C-23 identity validation is real; collector artifact and durable K evidence
    are not yet bound. These fixtures may only be used to test canonical C-5.
    """
    if isinstance(k, bool) or not isinstance(k, int) or k < 1:
        raise ValueError("K must be a positive integer")
    if not isinstance(cycles, (list, tuple)) or len(cycles) != k:
        raise ValueError("exactly K cycles are required")
    _digest(whitelist_sha256, "whitelist_sha256")
    _digest(template_sha256, "template_sha256")
    if whitelist_snapshot is None:
        if whitelist_rules != [] or whitelist_sha256 != _EMPTY_WHITELIST_SHA256:
            raise ValueError("only the explicit empty local whitelist fixture is implemented")
        nonempty = False
    else:
        _bound_whitelist_snapshot(
            whitelist_snapshot, whitelist_rules, whitelist_sha256, template_sha256,
        )
        nonempty = bool(whitelist_snapshot.whitelist.rules)

    normalized = []
    seen_cycles = set()
    project_key = scope = authority = None
    previous_sequence = None
    for cycle in cycles:
        if not isinstance(cycle, dict) or set(cycle) != _CYCLE_KEYS:
            raise ValueError("cycle must have exact local fixture keys")
        if cycle["source_mode"] != _LOCAL_MODE:
            raise ValueError("runtime collector authority is not implemented")
        if cycle["fresh"] is not True or cycle["qualifying"] is not True:
            raise ValueError("stale or nonqualifying cycle")
        identity = validate_collection_cycle_identity(cycle["identity"])
        if identity["cycle_id"] in seen_cycles:
            raise ValueError("duplicate cycle identity")
        seen_cycles.add(identity["cycle_id"])
        if previous_sequence is not None and identity["sequence"] != previous_sequence + 1:
            raise ValueError("cycle sequence is not consecutive")
        previous_sequence = identity["sequence"]
        if project_key is None:
            project_key, scope = identity["project_key"], identity["scope"]
            authority = _digest(cycle["authority_sha256"], "authority_sha256")
        elif (identity["project_key"], identity["scope"], cycle["authority_sha256"]) != (project_key, scope, authority):
            raise ValueError("cycle source authority changed")
        _digest(cycle["observations_sha256"], "observations_sha256")
        values = cycle["active_operations"]
        if not isinstance(values, (list, tuple)):
            raise ValueError("active operations must be a sequence")
        by_key = {}
        by_id = set()
        for raw in values:
            op = _operation(raw)
            key = tuple(op["activity_key"])
            if key in by_key or op["operation_id"] in by_id:
                raise ValueError("duplicate activity key or operation id")
            by_key[key] = op
            by_id.add(op["operation_id"])
        normalized.append((identity, cycle["observations_sha256"], by_key))

    intersection = set(normalized[0][2])
    for _, _, operations in normalized[1:]:
        intersection.intersection_update(operations)
    latest = normalized[-1][2]
    for key in intersection:
        if len({operations[key]["operation_id"] for _, _, operations in normalized}) != 1:
            raise ValueError("qualified activity changed operation identity within K")
    operations = sorted((latest[key] for key in intersection), key=lambda op: op["operation_id"])
    if len({op["operation_id"] for op in operations}) != len(operations):
        raise ValueError("qualified operation identities collided")
    pre_filter_operations_json = _canonical_json(operations) if nonempty else b"[]"
    skips = []
    if nonempty:
        # The four-component synthetic cabling key names only A/port/issue.
        # Never infer Z from it, even if the operation would not intersect K.
        if any(key[0] == "eth_cabling" for _, _, values in normalized for key in values):
            raise ValueError("Cabling Whitelist requires source-bound A/Z endpoints")
        evaluation = evaluate_whitelist(
            whitelist_snapshot.whitelist,
            [{"record_id": op["operation_id"], "source": "Switch",
              "hostname": op["activity_key"][1]} for op in operations],
        )
        kept = []
        for op, decision in zip(operations, evaluation.decisions):
            if decision.skipped:
                skips.append({"operation_id": op["operation_id"],
                              "activity_key": op["activity_key"],
                              "matched_rule": decision.matched_rule})
            else:
                kept.append(op)
        operations = kept
    digest_body = _canonical_json([item[1] for item in normalized]) + b"\n"
    return QualifiedSet(
        operations_json=_canonical_json(operations),
        cycle_ids=tuple(item[0]["cycle_id"] for item in normalized),
        source_authority_sha256=authority,
        observations_sha256=hashlib.sha256(digest_body).hexdigest(),
        whitelist_sha256=whitelist_sha256,
        template_sha256=template_sha256,
        project_key=project_key,
        scope=scope,
        k=k,
        mode=_LOCAL_MODE,
        whitelist_snapshot=whitelist_snapshot,
        whitelist_skips_json=_canonical_json(skips),
        pre_filter_operations_json=pre_filter_operations_json,
    )
