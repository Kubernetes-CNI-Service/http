"""Canonical, intent-only C-5 manifest freezers for distinct source types.

The runtime path replays protected qualification before freezing; neither
path grants a network send, durable local journal, or publication receipt.
"""

from datetime import datetime
import hashlib
import json
import re

from monitor.issue_tracker_qualification import (
    QualifiedSet, _EMPTY_WHITELIST_SHA256, _LOCAL_MODE, _bound_whitelist_snapshot,
    _canonical_json, _digest, _operation,
)
from monitor.issue_tracker_whitelist import evaluate_whitelist
from tools.project_contract import collection_cycle_project_key, collection_cycle_source_slots


_METADATA_KEYS = {
    "project_id", "schema_version", "producer_version",
    "template_contract_version", "template_sha256",
}


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _nonfinite(value):
    raise ValueError(f"nonfinite JSON scalar: {value}")


def _canonical_array(raw, field):
    if not isinstance(raw, bytes):
        raise ValueError(f"{field} must be canonical bytes")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs,
                           parse_constant=_nonfinite)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid {field} JSON") from exc
    if not isinstance(value, list) or raw != _canonical_json(value):
        raise ValueError(f"{field} must be a canonical array")
    return value


def _runtime_operation(value):
    """Validate the three-panel shape only after protected source replay.

    The synthetic `_operation` contract intentionally stays narrower and
    cannot manufacture IB authority from an arbitrary local fixture.
    """
    if not isinstance(value, dict) or set(value) != {
            "operation_id", "activity_key", "action"}:
        raise ValueError("runtime operation must have exact intent-only keys")
    identity = value["operation_id"]
    key = value["activity_key"]
    if (type(identity) is not str or not identity
            or any(char in identity for char in "\x00\r\n")
            or not isinstance(key, (list, tuple)) or len(key) != 4
            or not all(type(part) is str and part
                       and not any(char in part for char in "\x00\r\n")
                       for part in key)
            or key[0] not in {"switch", "eth_cabling", "ib_cabling"}
            or value["action"] != "upsert"):
        raise ValueError("runtime operation has invalid identity or action")
    return {"operation_id": identity, "activity_key": list(key),
            "action": "upsert"}


def _runtime_skip(item):
    """Preserve each protected W1 decision's real, source-specific identity."""
    from monitor.issue_tracker_stage_l_consumer import StageLQualifiedSkip

    if type(item) is not StageLQualifiedSkip:
        raise ValueError("runtime skip has invalid type")
    if (type(item.matched_rule) is not str or not item.matched_rule
            or any(char in item.matched_rule for char in "\x00\r\n")):
        raise ValueError("runtime skip has invalid matched rule")
    result = {"source": item.source, "matched_rule": item.matched_rule}
    if item.source == "ib_cabling":
        key = item.activity_key
        if (item.endpoints is not None or item.record_id is not None
                or type(key) is not tuple or len(key) != 4
                or key[0] != "ib_cabling"
                or not all(type(part) is str and part
                           and not any(char in part for char in "\x00\r\n")
                           for part in key)):
            raise ValueError("runtime IB skip has invalid activity identity")
        result["activity_key"] = list(key)
    elif item.source == "eth_cabling":
        endpoints = item.endpoints
        if (item.activity_key is not None or item.record_id is not None
                or type(endpoints) is not tuple or len(endpoints) != 4
                or not all(type(part) is str and part
                           and not any(char in part for char in "\x00\r\n")
                           for part in endpoints)):
            raise ValueError("runtime ETH skip has invalid endpoint identity")
        result["endpoints"] = list(endpoints)
    elif item.source == "switch":
        record_id = item.record_id
        if (item.activity_key is not None or item.endpoints is not None
                or type(record_id) is not str
                or not record_id.startswith("switch:") or not record_id[7:]
                or any(char in record_id for char in "\x00\r\n")):
            raise ValueError("runtime Switch skip has invalid record identity")
        result["record_id"] = record_id
    else:
        raise ValueError("runtime skip source is invalid")
    return result


def _runtime_recorded_at(value):
    if (type(value) is not str
            or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
                            value) is None):
        raise ValueError("runtime source timestamp must be exact UTC")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ValueError("runtime source timestamp is not a calendar instant") from exc
    return value


def _validated_operations(values, field, *, validator=_operation):
    result = []
    ids = set()
    keys = set()
    previous_id = None
    for raw in values:
        op = validator(raw)
        key = tuple(op["activity_key"])
        identity = op["operation_id"]
        if identity in ids or key in keys:
            raise ValueError(f"duplicate {field} identity or activity key")
        if previous_id is not None and identity <= previous_id:
            raise ValueError(f"{field} must be sorted by operation_id")
        ids.add(identity)
        keys.add(key)
        previous_id = identity
        result.append(op)
    return result


def freeze_qualified_manifest(qualified, *, metadata, expected_template_sha256):
    """Return (one-LF canonical body, SHA-256 manifest_id), never an outcome.

    ``qualified`` must be a validated typed projection, not an incremental
    local diff. Its synthetic marker prevents this foundation being mistaken
    for production collector authority.
    """
    if not isinstance(qualified, QualifiedSet):
        raise TypeError("only a typed qualified operation set may be frozen")
    if not isinstance(metadata, dict) or set(metadata) != _METADATA_KEYS:
        raise ValueError("metadata must have exact C-5 keys")
    if not isinstance(metadata["project_id"], str) or not metadata["project_id"]:
        raise ValueError("project_id must be nonempty text")
    if metadata["schema_version"] != 1 or isinstance(metadata["schema_version"], bool):
        raise ValueError("unsupported schema_version")
    for field in ("producer_version", "template_contract_version"):
        if not isinstance(metadata[field], str) or not metadata[field]:
            raise ValueError(f"{field} must be nonempty text")
    template_digest = _digest(metadata["template_sha256"], "template_sha256")
    if template_digest != _digest(expected_template_sha256, "expected_template_sha256") or template_digest != _digest(qualified.template_sha256, "qualified.template_sha256"):
        raise ValueError("template contract digest mismatch")
    if qualified.mode != _LOCAL_MODE:
        raise ValueError("runtime qualified-set authority is not implemented")
    if isinstance(qualified.k, bool) or not isinstance(qualified.k, int) or qualified.k < 1:
        raise ValueError("invalid K")
    if not isinstance(qualified.cycle_ids, tuple) or len(qualified.cycle_ids) != qualified.k:
        raise ValueError("qualified cycle count mismatch")
    for cycle_id in qualified.cycle_ids:
        _digest(cycle_id, "cycle_id")
    if len(set(qualified.cycle_ids)) != len(qualified.cycle_ids):
        raise ValueError("duplicate qualified cycle")
    for field in (
        "source_authority_sha256", "observations_sha256", "whitelist_sha256",
        "project_key",
    ):
        _digest(getattr(qualified, field), field)
    collection_cycle_source_slots(qualified.scope)
    if qualified.project_key != collection_cycle_project_key(metadata["project_id"]):
        raise ValueError("qualified project identity does not match metadata")
    operations = _validated_operations(
        _canonical_array(qualified.operations_json, "qualified operations"), "operations",
    )
    skips = None
    if qualified.whitelist_sha256 == _EMPTY_WHITELIST_SHA256:
        if qualified.whitelist_snapshot is not None:
            _bound_whitelist_snapshot(
                qualified.whitelist_snapshot, [], qualified.whitelist_sha256, template_digest,
            )
        if qualified.whitelist_skips_json != b"[]" or qualified.pre_filter_operations_json != b"[]":
            raise ValueError("empty Whitelist cannot carry filter provenance")
    else:
        snapshot = qualified.whitelist_snapshot
        if snapshot is None:
            raise ValueError("nonempty Whitelist has no held workbook snapshot")
        _bound_whitelist_snapshot(
            snapshot, list(snapshot.whitelist.rules), qualified.whitelist_sha256,
            template_digest,
        )
        if not snapshot.whitelist.rules:
            raise ValueError("nonempty Whitelist digest has empty rules")
        originals = _validated_operations(
            _canonical_array(qualified.pre_filter_operations_json,
                             "pre-filter operations"), "pre-filter operations",
        )
        if any(op["activity_key"][0] != "switch" for op in originals):
            raise ValueError("Cabling Whitelist requires source-bound A/Z endpoints")
        evaluation = evaluate_whitelist(
            snapshot.whitelist,
            [{"record_id": op["operation_id"], "source": "Switch",
              "hostname": op["activity_key"][1]} for op in originals],
        )
        expected_kept = []
        expected_skips = []
        for op, decision in zip(originals, evaluation.decisions):
            if decision.skipped:
                expected_skips.append({"operation_id": op["operation_id"],
                                       "activity_key": op["activity_key"],
                                       "matched_rule": decision.matched_rule})
            else:
                expected_kept.append(op)
        if operations != expected_kept or qualified.whitelist_skips_json != _canonical_json(expected_skips):
            raise ValueError("qualified Whitelist filter provenance mismatch")
        skips = expected_skips
    qualified_source = {
        "cycle_ids": list(qualified.cycle_ids),
        "k": qualified.k,
        "mode": qualified.mode,
        "observations_sha256": qualified.observations_sha256,
        "project_key": qualified.project_key,
        "scope": qualified.scope,
        "source_authority_sha256": qualified.source_authority_sha256,
        "whitelist_sha256": qualified.whitelist_sha256,
    }
    if skips is not None:
        qualified_source["whitelist_skips"] = skips
    body = _canonical_json({**metadata, "operations": operations, "qualified_source": qualified_source}) + b"\n"
    return body, hashlib.sha256(body).hexdigest()


def freeze_prod_stage_l_manifest(
    qualified, store, *, http_root, settings, whitelist_snapshot,
    whitelist_path, metadata, expected_template_sha256, writer_token=None,
):
    """Freeze a protected runtime C-5 intent only after replaying its sources.

    This never grants a local workbook write, receipt, or online-send permit.
    The synthetic fixture path above remains a separate, non-runtime contract.
    """
    if (type(qualified).__module__, type(qualified).__name__) != (
        "monitor.issue_tracker_stage_l_consumer", "ProdStageLQualifiedSet",
    ):
        raise ValueError("runtime qualified-set type is invalid")
    from monitor.issue_tracker_stage_l_consumer import (
        ProdStageLQualifiedSet, qualify_prod_stage_l,
    )

    if (type(qualified) is not ProdStageLQualifiedSet
            or qualified.qualified is not True
            or qualified.mode != "prod-runtime-protected-v1"):
        raise ValueError("runtime qualified-set mode or authority is invalid")
    if not isinstance(metadata, dict) or set(metadata) != _METADATA_KEYS:
        raise ValueError("metadata must have exact C-5 keys")
    if (type(metadata["project_id"]) is not str or not metadata["project_id"]
            or type(metadata["schema_version"]) is not int
            or metadata["schema_version"] != 1
            or any(type(metadata[key]) is not str or not metadata[key]
                   for key in ("producer_version", "template_contract_version"))):
        raise ValueError("runtime C-5 metadata is invalid")
    template_digest = _digest(metadata["template_sha256"], "template_sha256")
    if (template_digest != _digest(expected_template_sha256,
                                   "expected_template_sha256")
            or template_digest != qualified.template_sha256
            or qualified.project_key != collection_cycle_project_key(
                metadata["project_id"]
            )):
        raise ValueError("runtime template or project differs from qualification")

    def replay():
        return qualify_prod_stage_l(
            store, http_root=http_root, settings=settings,
            whitelist_snapshot=whitelist_snapshot,
            whitelist_path=whitelist_path, writer_token=writer_token,
        )

    actual = replay()
    if actual != qualified:
        raise ValueError("runtime qualified set changed before C-5 freeze")
    operations = _validated_operations(
        _canonical_array(actual.operations_json, "runtime operations"),
        "runtime operations", validator=_runtime_operation,
    )
    if (len(operations) != len(actual.candidates)
            or len(operations) > 1000
            or [item["operation_id"] for item in operations]
            != [item.operation_id for item in actual.candidates]):
        raise ValueError("runtime operation set or order is invalid")
    for operation, candidate in zip(operations, actual.candidates):
        if operation != {
            "operation_id": candidate.operation_id,
            "activity_key": list(candidate.activity_key),
            "action": "upsert",
        }:
            raise ValueError("runtime operation differs from reverified source")
    skips = [_runtime_skip(item) for item in actual.whitelist_skips]
    qualified_source = {
        "cycle_ids": list(actual.cycle_ids), "k": actual.k,
        "mode": actual.mode, "scope": actual.scope,
        "project_key": actual.project_key,
        "source_authority_sha256": actual.source_authority_sha256,
        "observations_sha256": actual.observations_sha256,
        "whitelist_sha256": actual.whitelist_sha256,
        "k_event_sha256": actual.k_event_sha256,
        "completion_sha256": list(actual.completion_sha256),
        "recorded_at_utc": _runtime_recorded_at(actual.recorded_at_utc),
        "whitelist_skips": skips,
    }
    body = _canonical_json({
        **metadata, "operations": operations,
        "qualified_source": qualified_source,
    }) + b"\n"
    if len(body) > 1024 * 1024 or replay() != actual:
        raise ValueError("runtime C-5 body too large or source changed during freeze")
    return body, hashlib.sha256(body).hexdigest()
