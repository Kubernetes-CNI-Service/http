"""Pure REQ7 C-2/C-7 target checks; neither file authority nor send permission.

The file format is an exact top-level JSON array of spreadsheet ID strings.
Bytes must eventually come from the C-1/C-11 fixed-path, root-only held-FD
reader. This module does not implement that reader, import authentication
SDKs, open a connection, or activate online publication. Hashes bind bytes;
they do not establish their provenance or authorize a wire attempt.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import re


_ID = re.compile(r"[A-Za-z0-9_-]{20,}\Z")
_MAX_ALLOWLIST_BYTES = 65536


class OnlineTargetHold(ValueError):
    """Sanitized machine reason; never echo file contents or target IDs."""

    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class TargetAllowlistSnapshot:
    spreadsheet_ids: tuple[str, ...] = field(repr=False)
    source_bytes: bytes = field(repr=False)
    sha256: str


@dataclass(frozen=True)
class OnlineTargetBinding:
    spreadsheet_id: str = field(repr=False)
    allowlist_sha256: str
    policy_sha256: str


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise OnlineTargetHold("invalid_target_allowlist")
        result[key] = value
    return result


def _constant(_value):
    raise OnlineTargetHold("invalid_target_allowlist")


def freeze_target_allowlist(source_bytes):
    """Freeze the original bounded enumeration, without deriving or normalizing."""
    if (type(source_bytes) is not bytes
            or not 1 <= len(source_bytes) <= _MAX_ALLOWLIST_BYTES):
        raise OnlineTargetHold("invalid_target_allowlist")
    try:
        values = json.loads(source_bytes.decode("utf-8", "strict"),
                            object_pairs_hook=_pairs, parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise OnlineTargetHold("invalid_target_allowlist") from None
    if (type(values) is not list
            or any(type(value) is not str or _ID.fullmatch(value) is None for value in values)
            or len(set(values)) != len(values)):
        raise OnlineTargetHold("invalid_target_allowlist")
    return TargetAllowlistSnapshot(tuple(values), source_bytes,
                                   hashlib.sha256(source_bytes).hexdigest())


def bind_online_target(global_document, allowlist, *, expected=None):
    """Check current policy and enumeration afresh; return a binding, not a permit.

    A prior binding is never silently retargeted. Disabled/revoked policy
    remains stopped; changes to target, enumeration bytes or policy are stale.
    No operation here reads secrets, writes a journal or alters local work.
    """
    from tools.project_contract import normalize_issue_tracker_policy

    try:
        policy = normalize_issue_tracker_policy(global_document)
    except (ValueError, TypeError, RecursionError):
        raise OnlineTargetHold("invalid_online_policy") from None
    if policy["status"] != "enabled":
        raise OnlineTargetHold("online_disabled_" + policy["presence"])
    if (type(allowlist) is not TargetAllowlistSnapshot
            or freeze_target_allowlist(allowlist.source_bytes) != allowlist):
        raise OnlineTargetHold("invalid_target_allowlist")
    if expected is not None and type(expected) is not OnlineTargetBinding:
        raise OnlineTargetHold("invalid_target_binding")
    target = policy["spreadsheet_id"]
    digest = hashlib.sha256((json.dumps(policy, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")).hexdigest()
    current = OnlineTargetBinding(target, allowlist.sha256, digest)
    if expected is not None and current != expected:
        raise OnlineTargetHold("stale_target_binding")
    if not allowlist.spreadsheet_ids:
        raise OnlineTargetHold("denied_empty_allowlist")
    if target not in allowlist.spreadsheet_ids:
        raise OnlineTargetHold("target_not_allowlisted")
    return current
