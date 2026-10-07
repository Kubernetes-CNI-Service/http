"""Read-only Switch per-key continuity from protected prod cycle sources.

This is a source diagnostic, not a three-panel qualification, Whitelist
decision, publication manifest, UI status, or an online execution permit.
Only the I/O entrypoint establishes worker/emitter source provenance.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

from monitor.issue_tracker_cycle_source import CycleEvidence, read_completed_cycle_evidence
from monitor.issue_tracker_k_chain import KChainState, assess_k_window, assess_per_key_window
from monitor.issue_tracker_local_commit import _owner
from monitor.issue_tracker_state_owner import current_k
from monitor.issue_tracker_switch_info_source import map_switch_source_rows
from monitor.issue_tracker_switch_runtime import (
    ProdSwitchCycleSource, read_prod_switch_cycle_source,
    validate_prod_switch_cycle_source,
)


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_SLOTS = frozenset(("ethernet/prod", "nvlink/prod"))


class SwitchPerKeySourceHold(ValueError):
    """Protected Switch source cannot support even local per-key progress."""


@dataclass(frozen=True)
class SwitchPerKeySourceStatus:
    state: str
    reason: str
    observed: int
    required: int
    key: tuple[str, str, str, str]
    source_slot: str
    cycle_ids: tuple[str, ...]
    completion_sha256: tuple[str, ...]
    archive_sha256: tuple[str, ...]
    k_event_sha256: str
    qualified: bool = False


def reduce_switch_per_key_sources(cycles, sources, settings, key, *, source_slot):
    """Reduce typed source fixtures; this alone does not establish trust."""
    try:
        if (type(settings) is not KChainState
                or type(settings.k) is not int or settings.k < 1
                or type(cycles) is not tuple
                or not cycles or type(sources) is not tuple
                or len(sources) != len(cycles) or len(cycles) > settings.k
                or type(source_slot) is not str or source_slot not in _SLOTS
                or type(key) is not tuple or len(key) != 4
                or key[0] != "switch" or any(type(part) is not str or not part
                                               or "\x00" in part for part in key)):
            raise SwitchPerKeySourceHold("Switch per-key source shape is invalid")
        assess_k_window(cycles, settings)
        hosts = None
        archives = set()
        observed = {}
        for cycle, source in zip(cycles, sources):
            if (type(cycle) is not CycleEvidence or cycle.qualifying is not True
                    or type(source) is not ProdSwitchCycleSource
                    or source.qualified is not False
                    or source.cycle_id != cycle.cycle_id
                    or source.sequence != cycle.sequence
                    or source.completion_sha256 != cycle.completion_sha256
                    or source.preview.source_slot != source_slot
                    or source.preview.qualified is not False
                    or type(source.preview.archive_sha256) is not str
                    or _SHA.fullmatch(source.preview.archive_sha256) is None
                    or source.preview.archive_sha256 in archives):
                raise SwitchPerKeySourceHold("Switch source missing, replayed, or rebound")
            expected_rows = map_switch_source_rows(source.preview)
            if (source.rows != expected_rows
                    or any(row.qualified is not False for row in source.rows)):
                raise SwitchPerKeySourceHold("Switch source rows changed")
            if hosts is not None and source.preview.selected_hosts != hosts:
                raise SwitchPerKeySourceHold("Switch selected hosts changed within K")
            hosts = source.preview.selected_hosts
            archives.add(source.preview.archive_sha256)
            observed[cycle.cycle_id] = frozenset(
                ("switch", row.hostname, row.category, row.component_or_sensor)
                for row in source.rows
            )
        window = assess_per_key_window(cycles, observed, settings, key)
        return SwitchPerKeySourceStatus(
            state=("source_window_complete" if window.status == "qualified"
                   else "pending"),
            reason=window.reason, observed=window.observed,
            required=window.required, key=key, source_slot=source_slot,
            cycle_ids=tuple(cycle.cycle_id for cycle in cycles),
            completion_sha256=tuple(cycle.completion_sha256 for cycle in cycles),
            archive_sha256=tuple(source.preview.archive_sha256 for source in sources),
            k_event_sha256=settings.event_sha256,
        )
    except (OSError, TypeError, KeyError, AttributeError, RuntimeError,
            ValueError) as exc:
        if isinstance(exc, SwitchPerKeySourceHold):
            raise
        raise SwitchPerKeySourceHold("Switch per-key source evidence is unsafe") from exc


def read_prod_switch_per_key_source(store, *, http_root, settings, key,
                                    source_slot, writer_token):
    """Reopen worker/emitter Switch roles under a held project writer lock."""
    try:
        root = Path(http_root).resolve(strict=True)
        owner = _owner(writer_token)
        project = Path(store.project_identity)
        if (store.scope != "prod" or project != owner.project
                or owner.publication != project / "99-output-monitor"
                or Path(store.root_status_dir) != root / "monitor/status"
                or current_k(writer_token) != settings
                or type(settings) is not KChainState
                or type(source_slot) is not str or source_slot not in _SLOTS):
            raise SwitchPerKeySourceHold("Switch per-key worker/K owner differs")
        cycles = read_completed_cycle_evidence(store)
        if not cycles:
            raise SwitchPerKeySourceHold("Switch per-key cycle source is absent")
        tail = cycles[-settings.k:]
        sources = tuple(read_prod_switch_cycle_source(
            store, http_root=root, sequence=cycle.sequence,
            source_slot=source_slot,
        ) for cycle in tail)
        result = reduce_switch_per_key_sources(
            tail, sources, settings, key, source_slot=source_slot,
        )
        if (current_k(writer_token) != settings
                or read_completed_cycle_evidence(store) != cycles
                or any(validate_prod_switch_cycle_source(
                    source, store, http_root=root,
                ) != source for source in sources)):
            raise SwitchPerKeySourceHold("Switch source changed before readback")
        return result
    except (OSError, TypeError, KeyError, AttributeError, RuntimeError,
            ValueError) as exc:
        if isinstance(exc, SwitchPerKeySourceHold):
            raise
        raise SwitchPerKeySourceHold("Switch per-key protected source is unsafe") from exc
