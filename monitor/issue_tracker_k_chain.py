"""Pure, fail-closed C-25 settings-chain snapshot validator.

The caller must separately prove immutable durable files, held project lock,
trusted actor/initialization provenance, outbox and delivery state. This module
never reads or writes a settings path and never authorizes publication.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import re

from monitor.issue_tracker_cycle_source import CycleEvidence


_SHA = re.compile(r"[0-9a-f]{64}\Z")
# C-25 names an opaque Token, not a UUIDv4; revision zero uses an acquisition ID.
_TOKEN = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_EVENT_KEYS = {
    "schema_version", "revision", "type", "old_k", "new_k", "actor",
    "recorded_at", "request_id", "payload_sha256", "predecessor_sha256",
}
_CURRENT_KEYS = {"schema_version", "revision", "event_sha256"}
_INITIALIZED_KEYS = {"schema_version", "event0_sha256", "initialized_at"}


class KChainHoldError(ValueError):
    """Never fall back to a historical K when its chain cannot be proven."""


@dataclass(frozen=True)
class KChainState:
    revision: int
    k: int
    event_sha256: str


@dataclass(frozen=True)
class KWindow:
    status: str
    reason: str
    observed: int
    required: int


def _canonical_line(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def _pairs(pairs):
    output = {}
    for key, value in pairs:
        if key in output:
            raise KChainHoldError("duplicate settings JSON key")
        output[key] = value
    return output


def _nonfinite(value):
    raise KChainHoldError(f"nonfinite settings scalar: {value}")


def _parse(raw, keys):
    if not isinstance(raw, bytes):
        raise KChainHoldError("settings document must be immutable bytes")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=_nonfinite)
        if not isinstance(value, dict) or set(value) != keys or _canonical_line(value) != raw:
            raise KChainHoldError("settings document is not exact canonical JSON")
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        if isinstance(exc, KChainHoldError):
            raise
        raise KChainHoldError("invalid settings document") from exc
    return value


def _sha(value):
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise KChainHoldError("invalid settings digest")
    return value


def _positive_int(value):
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise KChainHoldError("K must be a positive non-boolean integer")
    return value


def _revision(value):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise KChainHoldError("invalid settings revision")
    return value


def _time(value):
    if not isinstance(value, str) or _TIME.fullmatch(value) is None:
        raise KChainHoldError("invalid settings UTC timestamp")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise KChainHoldError("invalid settings UTC timestamp") from exc
    return value


def _actor(value):
    if (not isinstance(value, str) or not value
            or len(value.encode("utf-8")) > 64
            or any(ord(char) < 32 for char in value)):
        raise KChainHoldError("invalid settings actor")
    return value


def _request_id(value):
    if not isinstance(value, str) or _TOKEN.fullmatch(value) is None:
        raise KChainHoldError("invalid settings request ID")
    return value


def validate_k_chain_snapshot(events, current, initialized):
    """Validate caller-supplied committed event bytes and highest-current binding.

    This pure seam intentionally cannot infer whether any filesystem event was
    durably committed; future I/O authority must supply that proof separately.
    """
    if not isinstance(events, dict) or not events:
        raise KChainHoldError("initialized settings event chain is missing")
    if any(isinstance(key, bool) or not isinstance(key, int) or key < 0 for key in events):
        raise KChainHoldError("settings event indices are invalid")
    if sorted(events) != list(range(len(events))):
        raise KChainHoldError("settings event revision gap")
    witness = _parse(initialized, _INITIALIZED_KEYS)
    pointer = _parse(current, _CURRENT_KEYS)
    if type(witness["schema_version"]) is not int or witness["schema_version"] != 1:
        raise KChainHoldError("unsupported INITIALIZED schema")
    if type(pointer["schema_version"]) is not int or pointer["schema_version"] != 1:
        raise KChainHoldError("unsupported current schema")
    _time(witness["initialized_at"])
    if _revision(pointer["revision"]) != len(events) - 1:
        raise KChainHoldError("current pointer is not highest committed event")
    _sha(pointer["event_sha256"])
    _sha(witness["event0_sha256"])

    previous_digest = None
    previous_k = None
    seen_requests = set()
    for revision in range(len(events)):
        raw = events[revision]
        event = _parse(raw, _EVENT_KEYS)
        digest = hashlib.sha256(raw).hexdigest()
        if type(event["schema_version"]) is not int or event["schema_version"] != 1:
            raise KChainHoldError("unsupported event schema")
        if _revision(event["revision"]) != revision:
            raise KChainHoldError("event filename/revision mismatch")
        k = _positive_int(event["new_k"])
        actor = _actor(event["actor"])
        _time(event["recorded_at"])
        request_id = _request_id(event["request_id"])
        if request_id in seen_requests:
            raise KChainHoldError("duplicate settings request ID")
        seen_requests.add(request_id)
        _sha(event["payload_sha256"])
        expected_request = {
            "new_k": k, "actor": actor,
            "expected_revision": None if revision == 0 else revision - 1,
            "request_id": request_id,
        }
        if event["payload_sha256"] != hashlib.sha256(_canonical_line(expected_request)).hexdigest():
            raise KChainHoldError("settings request payload binding mismatch")
        if revision == 0:
            if (event["type"] != "init" or event["old_k"] is not None
                    or k != 3 or actor != "system:default"
                    or event["predecessor_sha256"] is not None
                    or witness["event0_sha256"] != digest):
                raise KChainHoldError("invalid initial K authority")
        else:
            if (event["type"] != "set_k" or _positive_int(event["old_k"]) != previous_k
                    or _sha(event["predecessor_sha256"]) != previous_digest):
                raise KChainHoldError("settings chain predecessor mismatch")
        previous_k = k
        previous_digest = digest
    if pointer["event_sha256"] != previous_digest:
        raise KChainHoldError("current pointer digest mismatch")
    return KChainState(revision=len(events) - 1, k=previous_k,
                       event_sha256=previous_digest)


def assess_k_window(cycles, settings):
    """Report history sufficiency only; never assert per-activity qualification."""
    if not isinstance(settings, KChainState) or not isinstance(cycles, (tuple, list)):
        raise KChainHoldError("unverified K or cycle evidence")
    if any(not isinstance(cycle, CycleEvidence) for cycle in cycles):
        raise KChainHoldError("cycle evidence has wrong type")
    if cycles:
        project_key = cycles[0].project_key
        scope = cycles[0].scope
        source_slots = cycles[0].source_slots
        seen_ids = set()
        previous_sequence = None
        for cycle in cycles:
            if (not cycle.cycle_id or cycle.cycle_id in seen_ids
                    or isinstance(cycle.sequence, bool)
                    or not isinstance(cycle.sequence, int) or cycle.sequence < 1
                    or (previous_sequence is not None
                        and cycle.sequence != previous_sequence + 1)
                    or cycle.project_key != project_key or cycle.scope != scope
                    or cycle.source_slots != source_slots):
                raise KChainHoldError("cycle history is duplicate, gapped, or mixed")
            seen_ids.add(cycle.cycle_id)
            previous_sequence = cycle.sequence
    if len(cycles) < settings.k:
        return KWindow("pending", "cold_start", len(cycles), settings.k)
    tail = cycles[-settings.k:]
    if any(not cycle.qualifying for cycle in tail):
        return KWindow("pending", "nonqualifying_cycle", sum(cycle.qualifying for cycle in tail), settings.k)
    return KWindow("history_sufficient", "activity_not_evaluated", settings.k, settings.k)
