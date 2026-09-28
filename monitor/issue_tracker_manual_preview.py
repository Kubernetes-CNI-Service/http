"""Worker-side REQ7 local manual preview and single-use confirmation core.

The worker supplies a protected Stage L reader and a C6 writer which must
requalify the exact preview fingerprint under its own publication lock.
This module issues no online permit and accepts no browser-supplied rows.
"""

from __future__ import annotations

import secrets
import time


class ManualPreviewHold(ValueError):
    """Manual local publication lacks one of its explicit authorities."""


_SHEETS = {"Switch Status": "ETH&IB Switch",
           "Eth Link Validation": "ETH Cabling",
           "IB Link Validation": "IB Cabling"}
_PRINCIPALS = frozenset(("nvis", "cumulus"))
_FINGERPRINT = (
    "project_key", "scope", "k", "k_revision", "latest_cycle_id",
    "window_cycle_ids", "whitelist_sha256", "template_sha256",
    "source_authority_sha256", "observations_sha256",
)
_MAX_PENDING = 128
_TTL_SECONDS = 120


def _bound_status(status, panel):
    if (type(status) is not dict or status.get("state") != "qualified"
            or status.get("online") != "disabled_no_send_authority"
            or type(status.get("panels")) is not dict
            or type(status["panels"].get(panel)) is not dict
            or status["panels"][panel].get("state") != "qualified"):
        raise ManualPreviewHold("Stage L is not locally qualified")
    bound = {key: status.get(key) for key in _FINGERPRINT}
    hashes = ("whitelist_sha256", "template_sha256",
              "source_authority_sha256", "observations_sha256")
    if (type(bound["project_key"]) is not str or not bound["project_key"]
            or bound["scope"] != "prod"
            or type(bound["k"]) is not int or bound["k"] < 1
            or type(bound["k_revision"]) is not int or bound["k_revision"] < 0
            or type(bound["latest_cycle_id"]) is not str
            or not bound["latest_cycle_id"]
            or type(bound["window_cycle_ids"]) is not list
            or len(bound["window_cycle_ids"]) != bound["k"]
            or any(type(item) is not str or not item
                   for item in bound["window_cycle_ids"])
            or len(set(bound["window_cycle_ids"])) != bound["k"]
            or bound["window_cycle_ids"][-1] != bound["latest_cycle_id"]
            or any(type(bound[key]) is not str or len(bound[key]) != 64
                   or any(char not in "0123456789abcdef" for char in bound[key])
                   for key in hashes)):
        raise ManualPreviewHold("Stage L preview identity is incomplete")
    bound["window_cycle_ids"] = tuple(bound["window_cycle_ids"])
    for count in ("qualified_operation_count", "whitelist_skip_count"):
        if type(status.get(count)) is not int or status[count] < 0:
            raise ManualPreviewHold("Stage L preview counts are incomplete")
    return bound


class ManualPreviewBroker:
    """One worker-lifetime token store; restart or expiry revokes previews."""

    def __init__(self, read_status, commit_local, *, clock=time.monotonic):
        self._read_status = read_status
        self._commit_local = commit_local
        self._clock = clock
        self._pending = {}

    @property
    def pending_count(self):
        return len(self._pending)

    def _validate_request(self, principal, panel):
        if (type(principal) is not str or principal not in _PRINCIPALS
                or type(panel) is not str or panel not in _SHEETS):
            raise ManualPreviewHold("manual request authority is invalid")

    def _expire(self, now):
        for key, entry in tuple(self._pending.items()):
            if now >= entry[3]:
                del self._pending[key]

    def preview(self, principal, panel):
        self._validate_request(principal, panel)
        now = self._clock()
        self._expire(now)
        if len(self._pending) >= _MAX_PENDING:
            raise ManualPreviewHold("manual preview capacity exhausted")
        status = self._read_status()
        fingerprint = _bound_status(status, panel)
        token = secrets.token_urlsafe(32)
        self._pending[token] = (principal, panel, fingerprint,
                                now + _TTL_SECONDS)
        return {
            "token": token, "expires_in_seconds": _TTL_SECONDS,
            "panel": panel, "target_sheet": _SHEETS[panel],
            "source_authority_sha256": fingerprint["source_authority_sha256"],
            "observations_sha256": fingerprint["observations_sha256"],
            "latest_cycle_id": fingerprint["latest_cycle_id"],
            "qualified_operation_count": status["qualified_operation_count"],
            "whitelist_skip_count": status["whitelist_skip_count"],
            "online": "disabled_no_send_authority",
        }

    def confirm(self, principal, panel, token, *, confirmation):
        self._validate_request(principal, panel)
        if (type(token) is not str or len(token) != 43
                or any(char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
                       for char in token)):
            raise ManualPreviewHold("manual preview token is invalid")
        entry = self._pending.get(token)
        if entry is None or entry[0] != principal or entry[1] != panel:
            raise ManualPreviewHold("manual preview token is not owned by this request")
        del self._pending[token]  # one-use before status refresh or C6 attempt
        if confirmation != "publish_local" or self._clock() >= entry[3]:
            raise ManualPreviewHold("manual second confirmation is absent or expired")
        current = _bound_status(self._read_status(), panel)
        if current != entry[2]:
            raise ManualPreviewHold("manual preview source changed; preview again")
        return self._commit_local(panel, current)
