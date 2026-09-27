"""Pure, fail-closed C-24 local Whitelist snapshot and skip decisions.

This module does not read workbooks, write local issue tables, or authorize
online work. The caller must provide the Whitelist sheet values from the
same local workbook/template snapshot used for its manifest.
"""

from __future__ import annotations

from dataclasses import dataclass
import fnmatch
import hashlib
import json
import re


_HEADER = (
    "Submit Date", "Submitor", "Datahalll", "Rack", "Device Name", "Comments",
)


class WhitelistHoldError(ValueError):
    """The local Whitelist authority is missing, malformed, or unbound."""


@dataclass(frozen=True)
class WhitelistSnapshot:
    rules: tuple[str, ...]
    canonical_bytes: bytes
    sha256: str


@dataclass(frozen=True)
class WhitelistDecision:
    record_id: str
    source: str
    skipped: bool
    matched_rule: str | None
    snapshot_sha256: str


@dataclass(frozen=True)
class WhitelistEvaluation:
    decisions: tuple[WhitelistDecision, ...]
    skipped_switches: int
    skipped_cabling: int
    skipped_keys: tuple[str, ...]
    snapshot_sha256: str


def _normalize_rule(raw):
    if not isinstance(raw, str) or not raw.strip():
        raise WhitelistHoldError("Whitelist rule must be nonempty text")
    rule = raw.strip()
    if rule.casefold().startswith("re:"):
        rule = "re:" + rule[3:]
        try:
            re.compile(rule[3:], re.IGNORECASE)
        except re.error as exc:
            raise WhitelistHoldError("invalid Whitelist regex") from exc
        return rule
    return rule.casefold()


def _canonical_rules(rules):
    return (json.dumps(
        rules, ensure_ascii=False, separators=(",", ":"), allow_nan=False,
    ) + "\n").encode("utf-8")


def freeze_whitelist_sheet(rows):
    """Freeze exact six-column template sheet values; blank header-only is legal.

    A missing sheet is ``None``. It must never be interpreted as an empty
    rule set. Unexpected populated rows without Device Name are malformed.
    """
    if not isinstance(rows, (tuple, list)) or not rows:
        raise WhitelistHoldError("Whitelist sheet is missing")
    header = rows[0]
    if not isinstance(header, (tuple, list)) or tuple(header) != _HEADER:
        raise WhitelistHoldError("Whitelist header does not match template")
    normalized = set()
    for number, row in enumerate(rows[1:], 2):
        if not isinstance(row, (tuple, list)) or len(row) != len(_HEADER):
            raise WhitelistHoldError(f"Whitelist row {number} has wrong shape")
        raw = row[4]
        if raw is None or raw == "":
            if any(value not in (None, "") for value in row):
                raise WhitelistHoldError(f"Whitelist row {number} lacks Device Name")
            continue
        normalized.add(_normalize_rule(raw))
    rules = tuple(sorted(normalized))
    body = _canonical_rules(rules)
    return WhitelistSnapshot(rules, body, hashlib.sha256(body).hexdigest())


def _validate_snapshot(snapshot):
    if not isinstance(snapshot, WhitelistSnapshot) or not isinstance(snapshot.rules, tuple):
        raise WhitelistHoldError("Whitelist snapshot is not frozen")
    if any(_normalize_rule(rule) != rule for rule in snapshot.rules):
        raise WhitelistHoldError("Whitelist snapshot has noncanonical rule")
    if snapshot.rules != tuple(sorted(set(snapshot.rules))):
        raise WhitelistHoldError("Whitelist snapshot rule order is invalid")
    body = _canonical_rules(snapshot.rules)
    if snapshot.canonical_bytes != body or snapshot.sha256 != hashlib.sha256(body).hexdigest():
        raise WhitelistHoldError("Whitelist snapshot digest mismatch")


def _matches(node, rule):
    if rule.startswith("re:"):
        return re.search(rule[3:], node, re.IGNORECASE) is not None
    if any(char in rule for char in "*?["):
        return fnmatch.fnmatchcase(node.casefold(), rule)
    return node.casefold() == rule


def _nodes(record):
    if not isinstance(record, dict):
        raise WhitelistHoldError("Whitelist record must be a mapping")
    source = record.get("source")
    if source == "Switch" and set(record) == {"record_id", "source", "hostname"}:
        values = (record["hostname"],)
    elif source == "Cabling" and set(record) == {"record_id", "source", "a_node", "z_node"}:
        values = (record["a_node"], record["z_node"])
    else:
        raise WhitelistHoldError("unsupported Whitelist record shape or source")
    record_id = record["record_id"]
    if not isinstance(record_id, str) or not record_id.strip():
        raise WhitelistHoldError("record_id must be nonempty text")
    if not all(value is None or isinstance(value, str) for value in values):
        raise WhitelistHoldError("Whitelist endpoint must be text")
    nodes = tuple(value.strip() for value in values if isinstance(value, str) and value.strip())
    if not nodes:
        raise WhitelistHoldError("Whitelist record has no endpoint")
    return record_id, source, nodes


def evaluate_whitelist(snapshot, records):
    """Return stable per-record skip provenance; never mutate input records."""
    _validate_snapshot(snapshot)
    if not isinstance(records, (tuple, list)):
        raise WhitelistHoldError("Whitelist records must be a sequence")
    decisions = []
    seen = set()
    switch_count = cabling_count = 0
    for record in records:
        record_id, source, nodes = _nodes(record)
        if record_id in seen:
            raise WhitelistHoldError("duplicate Whitelist record_id")
        seen.add(record_id)
        matched = next((rule for rule in snapshot.rules
                        if any(_matches(node, rule) for node in nodes)), None)
        skipped = matched is not None
        if skipped and source == "Switch":
            switch_count += 1
        elif skipped:
            cabling_count += 1
        decisions.append(WhitelistDecision(
            record_id, source, skipped, matched, snapshot.sha256,
        ))
    return WhitelistEvaluation(
        tuple(decisions), switch_count, cabling_count,
        tuple(item.record_id for item in decisions if item.skipped), snapshot.sha256,
    )
