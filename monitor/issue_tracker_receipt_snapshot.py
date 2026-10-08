"""Read-only, cycle-bound local C6 publication facts for Stage L status.

This is not online eligibility. The caller must hold the per-project LK-P token;
the function neither creates a generation nor repairs incomplete evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re

from monitor.issue_tracker_admission import (
    AdmissionHold, _EVENT_FIELDS, _ADMISSION, _RETRY, read_shared_local_admission,
)
from monitor.issue_tracker_cycle_source import (
    CycleSourceHoldError, read_completed_cycle_evidence,
)
from monitor.issue_tracker_local_commit import (
    LocalCommitHold, _directory, _json, _owner, _read,
)
from monitor.issue_tracker_local_workbook_commit import _latest_receipted_prod_xlsx
from monitor.issue_tracker_state_owner import TrackerStateHold, current_k


class LocalReceiptSnapshotHold(ValueError):
    """The current-cycle local SEND UNIT count is not provable."""


@dataclass(frozen=True)
class CurrentCycleLocalReceipts:
    cycle_id: str | None
    published: int
    generation_ids: tuple[str, ...]


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_GEN = re.compile(r"gen-([0-9]{20})-([0-9a-f]{32})\Z")
_SOURCE_FIELDS = {
    "cycle_ids", "completion_sha256", "k", "mode", "scope", "project_key",
    "source_authority_sha256", "observations_sha256", "whitelist_sha256",
    "k_event_sha256", "recorded_at_utc", "whitelist_skips",
}


def _events(owner):
    """Read the exact journal again after the shared-chain validator succeeds."""
    try:
        directory = _directory(owner.root_fd, "admissions")
    except FileNotFoundError:
        return ()
    try:
        names = os.listdir(directory)
        publication_names={name for name in names if _ADMISSION.fullmatch(name)}
        expected = {f"admission-{number:020d}.json"
                    for number in range(1, len(publication_names) + 1)}
        if (not publication_names or publication_names != expected
                or any(_ADMISSION.fullmatch(name) is None and _RETRY.fullmatch(name) is None for name in names)):
            raise LocalReceiptSnapshotHold("shared admission sequence is incomplete")
        return tuple(_json(_read(directory, name)[0], _EVENT_FIELDS)
                     for name in sorted(expected))
    finally:
        os.close(directory)


def _k_events(owner):
    settings = _directory(owner.root_fd, "settings")
    try:
        directory = _directory(settings, "events")
        try:
            result = {}
            for name in os.listdir(directory):
                if not re.fullmatch(r"(0|[1-9][0-9]*)\.json", name):
                    raise LocalReceiptSnapshotHold("settings event name is unsafe")
                raw = _read(directory, name)[0]
                event = _json(raw)
                digest = hashlib.sha256(raw).hexdigest()
                if (type(event.get("revision")) is not int
                        or name != f'{event["revision"]}.json'
                        or type(event.get("new_k")) is not int
                        or event["new_k"] < 1):
                    raise LocalReceiptSnapshotHold("settings event is invalid")
                result[digest] = event["new_k"]
            return result
        finally:
            os.close(directory)
    finally:
        os.close(settings)


def _manifest_source(owner, generation_id):
    if type(generation_id) is not str or _GEN.fullmatch(generation_id) is None:
        raise LocalReceiptSnapshotHold("generation identity is invalid")
    generations = _directory(owner.root_fd, "generations")
    try:
        generation = _directory(generations, generation_id)
        try:
            manifest = _json(_read(generation, "MANIFEST", 1024 * 1024)[0])
            return manifest.get("template_sha256"), manifest.get("qualified_source")
        finally:
            os.close(generation)
    finally:
        os.close(generations)


def _validate_source(source, event, cycles, k_events, *, template_sha256,
                     expected_template_sha256, settings, whitelist_sha256,
                     qualified_source):
    if (template_sha256 != expected_template_sha256
            or type(source) is not dict
            or not _SOURCE_FIELDS.issubset(source)
            or set(source) - _SOURCE_FIELDS
               not in (set(), {"selected_panel", "panel_evaluation"})
            or source["mode"] != "prod-runtime-protected-v1"
            or source["project_key"] != event["project_key"]
            or source["scope"] != event["scope"]
            or type(source["k"]) is not int or source["k"] < 1
            or type(source["cycle_ids"]) is not list
            or type(source["completion_sha256"]) is not list
            or len(source["cycle_ids"]) != source["k"]
            or len(source["completion_sha256"]) != source["k"]
            or any(type(source[key]) is not str or _SHA.fullmatch(source[key]) is None
                   for key in ("source_authority_sha256", "observations_sha256",
                               "whitelist_sha256", "k_event_sha256"))
            or k_events.get(source["k_event_sha256"]) != source["k"]):
        raise LocalReceiptSnapshotHold("C6 manifest source or K identity is invalid")
    # Keep physical completion order. Filtering out failed/nonqualifying
    # observations would manufacture a consecutive K window across a gap.
    ids = tuple(cycle.cycle_id for cycle in cycles)
    if event["cycle_id"] not in ids:
        raise LocalReceiptSnapshotHold("C6 cycle is no longer qualified")
    position = ids.index(event["cycle_id"])
    start = position + 1 - source["k"]
    window = cycles[start:position + 1] if start >= 0 else ()
    if (start < 0
            or any(item.qualifying is not True for item in window)
            or any(right.sequence != left.sequence + 1
                   for left, right in zip(window, window[1:]))
            or source["cycle_ids"] != list(ids[start:position + 1])
            or source["completion_sha256"] != [
                item.completion_sha256 for item in window
            ]
            or source["completion_sha256"][-1]
               != event["cycle_completion_sha256"]):
        raise LocalReceiptSnapshotHold("C6 manifest differs from admitted cycle window")
    if cycles and event["cycle_id"] == cycles[-1].cycle_id:
        from monitor.issue_tracker_stage_l_consumer import ProdStageLQualifiedSet

        if (source["k"] != settings.k
                or source["k_event_sha256"] != settings.event_sha256
                or source["whitelist_sha256"] != whitelist_sha256
                or type(qualified_source) is not ProdStageLQualifiedSet
                or qualified_source.qualified is not True
                or qualified_source.mode != "prod-runtime-protected-v1"
                or qualified_source.project_key != event["project_key"]
                or qualified_source.scope != event["scope"]
                or qualified_source.template_sha256 != expected_template_sha256):
            raise LocalReceiptSnapshotHold("current C6 K/W1/source replay is absent")
        for field, expected in (
            ("cycle_ids", list(qualified_source.cycle_ids)),
            ("completion_sha256", list(qualified_source.completion_sha256)),
            ("source_authority_sha256", qualified_source.source_authority_sha256),
            ("observations_sha256", qualified_source.observations_sha256),
            ("whitelist_sha256", qualified_source.whitelist_sha256),
            ("k_event_sha256", qualified_source.k_event_sha256),
            ("k", qualified_source.k),
        ):
            if source[field] != expected:
                raise LocalReceiptSnapshotHold(
                    "current C6 manifest differs from protected source replay")


def read_current_cycle_local_receipts(
    token, store, *, expected_template_sha256, settings, whitelist_sha256,
    qualified_source=None,
) -> CurrentCycleLocalReceipts:
    """Count only fully receipted/admitted local units of the latest cycle.

    A prior cycle's image never proves publication of the latest cycle. A
    current-cycle unit additionally requires independent protected C5 replay.
    """
    try:
        if (type(expected_template_sha256) is not str
                or _SHA.fullmatch(expected_template_sha256) is None
                or type(whitelist_sha256) is not str
                or _SHA.fullmatch(whitelist_sha256) is None):
            raise LocalReceiptSnapshotHold("template or W1 identity is invalid")
        owner = _owner(token)
        if (owner.project != Path(store.project_identity)
                or store.scope != "prod"
                or current_k(token) != settings):
            raise LocalReceiptSnapshotHold("C6 owner or K identity changed")
        cycles = read_completed_cycle_evidence(store)
        image = _latest_receipted_prod_xlsx(token, expected_template_sha256)
        latest = read_shared_local_admission(token, store, image)
        events = _events(owner)
        if (latest is None) != (not events):
            raise LocalReceiptSnapshotHold("C6 admission visibility changed")
        if latest is not None and any(events[-1][field]!=latest[field] for field in (
                'generation_id','published_sha256','project_key','scope','policy_sha256','publish_every_cycles')):
            raise LocalReceiptSnapshotHold("C6 admission changed during read")
        k_events = _k_events(owner)
        for event in events:
            template, source = _manifest_source(owner, event["generation_id"])
            _validate_source(
                source, event, cycles, k_events,
                template_sha256=template,
                expected_template_sha256=expected_template_sha256,
                settings=settings, whitelist_sha256=whitelist_sha256,
                qualified_source=qualified_source,
            )
        if (read_completed_cycle_evidence(store) != cycles or current_k(token) != settings
                or _events(owner)!=events or read_shared_local_admission(token,store,image)!=latest):
            raise LocalReceiptSnapshotHold("protected cycle or K changed during read")
        cycle_id = cycles[-1].cycle_id if cycles else None
        generations = tuple(event["generation_id"] for event in events
                            if event["cycle_id"] == cycle_id)
        return CurrentCycleLocalReceipts(cycle_id, len(generations), generations)
    except (OSError, TypeError, AttributeError, KeyError, IndexError, ValueError,
            LocalCommitHold, AdmissionHold, CycleSourceHoldError,
            TrackerStateHold) as exc:
        if isinstance(exc, LocalReceiptSnapshotHold):
            raise
        raise LocalReceiptSnapshotHold("current-cycle local receipt is unsafe") from exc
