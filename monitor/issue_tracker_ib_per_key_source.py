"""Read-only IB per-key continuity from protected completed-cycle reports.

This is an IB-only source diagnostic. It does not bind Whitelist, the other
two panels, C5 qualification, status/UI, or a publication/write permit.
Typed reducer fixtures have no authority; the I/O entrypoint reopens real
producer, worker, and emitter evidence under the held project writer lock.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import re

from monitor.issue_tracker_cycle_source import CycleEvidence, read_completed_cycle_evidence
from monitor.issue_tracker_ib_runtime import (
    IbBoundCycleReport, IbReportLink, intersect_ib_report_rows,
    read_completed_ib_cycle_report,
)
from monitor.issue_tracker_k_chain import KChainState, assess_k_window, assess_per_key_window
from monitor.issue_tracker_local_commit import _owner
from monitor.issue_tracker_state_owner import current_k


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_PRODUCER_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:00Z\Z")


class IbPerKeySourceHold(ValueError):
    """Protected IB source cannot support even local per-key progress."""


class IbSourceAuthorityChanged(IbPerKeySourceHold):
    """Validated completed sources disagree on expected input authority."""


@dataclass(frozen=True)
class IbPerKeySourceStatus:
    state: str
    reason: str
    observed: int
    required: int
    key: tuple[str, str, str, str]
    cycle_ids: tuple[str, ...]
    completion_sha256: tuple[str, ...]
    report_sha256: tuple[str, ...]
    expected_topology_sha256: str
    k_event_sha256: str
    qualified: bool = False


def _row_key(row: IbReportLink):
    return ("ib_cabling", row.expected_endpoints[0],
            row.expected_endpoints[1], row.issue_type)


def reduce_ib_per_key_reports(cycles, reports, settings, key):
    """Reduce exact typed source fixtures, without granting provenance."""
    try:
        if (type(settings) is not KChainState
                or type(settings.k) is not int or settings.k < 1
                or type(cycles) is not tuple
                or not cycles or type(reports) is not tuple
                or len(reports) != len(cycles) or len(cycles) > settings.k
                or type(key) is not tuple or len(key) != 4
                or key[0] != "ib_cabling" or key[3] not in ("Link Down", "Mis-wiring")
                or any(type(part) is not str or not part or "\x00" in part
                       for part in key)):
            raise IbPerKeySourceHold("IB per-key source shape is invalid")
        assess_k_window(cycles, settings)
        topology = None
        report_hashes = set()
        expected_by_key = {}
        observed = {}
        authority_changed = False
        for cycle, report in zip(cycles, reports):
            if (type(cycle) is not CycleEvidence or cycle.qualifying is not True
                    or type(report) is not IbBoundCycleReport
                    or report.qualified is not False
                    or report.cycle_id != cycle.cycle_id
                    or report.sequence != cycle.sequence
                    or report.completion_sha256 != cycle.completion_sha256
                    or type(report.report_sha256) is not str
                    or _SHA.fullmatch(report.report_sha256) is None
                    or report.report_sha256 in report_hashes
                    or type(report.expected_topology_sha256) is not str
                    or _SHA.fullmatch(report.expected_topology_sha256) is None
                    or type(report.recorded_at_utc) is not str
                    or _PRODUCER_TIME.fullmatch(report.recorded_at_utc) is None):
                raise IbPerKeySourceHold("IB report missing, replayed, or rebound")
            # A lexical timestamp alone cannot establish a valid producer time.
            datetime.strptime(report.recorded_at_utc, "%Y-%m-%dT%H:%M:00Z")
            if topology is not None and report.expected_topology_sha256 != topology:
                authority_changed = True
            topology = report.expected_topology_sha256
            report_hashes.add(report.report_sha256)
            # The established IB reducer validates literal row shape, issue
            # type/sheet pairing, and duplicate normalized keys for each cycle.
            intersect_ib_report_rows((report.rows,), (topology,))
            keys = set()
            for row in report.rows:
                row_key = _row_key(row)
                previous = expected_by_key.get(row_key)
                if (previous is not None
                        and previous != row.expected_endpoints):
                    authority_changed = True
                expected_by_key[row_key] = row.expected_endpoints
                keys.add(row_key)
            observed[cycle.cycle_id] = frozenset(keys)
        # Validate every report first: malformed/rebound evidence must not be
        # promoted to a verified input-change diagnosis merely because some
        # other report also changed its expected topology or endpoint.
        if authority_changed:
            raise IbSourceAuthorityChanged("IB expected input changed within K")
        window = assess_per_key_window(cycles, observed, settings, key)
        return IbPerKeySourceStatus(
            state=("source_window_complete" if window.status == "qualified"
                   else "pending"),
            reason=window.reason, observed=window.observed,
            required=window.required, key=key,
            cycle_ids=tuple(cycle.cycle_id for cycle in cycles),
            completion_sha256=tuple(cycle.completion_sha256 for cycle in cycles),
            report_sha256=tuple(report.report_sha256 for report in reports),
            expected_topology_sha256=topology,
            k_event_sha256=settings.event_sha256,
        )
    except (OSError, TypeError, KeyError, AttributeError, RuntimeError,
            ValueError) as exc:
        if isinstance(exc, IbPerKeySourceHold):
            raise
        raise IbPerKeySourceHold("IB per-key source evidence is unsafe") from exc


def read_prod_ib_per_key_source(store, *, http_root, settings, key, writer_token):
    """Read every selected protected nine-role report and reread before return."""
    try:
        root = Path(http_root).resolve(strict=True)
        owner = _owner(writer_token)
        project = Path(store.project_identity)
        if (store.scope != "prod" or project != owner.project
                or owner.publication != project / "99-output-monitor"
                or Path(store.root_status_dir) != root / "monitor/status"
                or current_k(writer_token) != settings
                or type(settings) is not KChainState):
            raise IbPerKeySourceHold("IB per-key worker/K owner differs")
        cycles = read_completed_cycle_evidence(store)
        if not cycles:
            raise IbPerKeySourceHold("IB per-key cycle source is absent")
        tail = cycles[-settings.k:]
        reports = tuple(read_completed_ib_cycle_report(
            store, http_root=root, sequence=cycle.sequence,
        ) for cycle in tail)
        result = reduce_ib_per_key_reports(tail, reports, settings, key)
        if (current_k(writer_token) != settings
                or read_completed_cycle_evidence(store) != cycles
                or any(read_completed_ib_cycle_report(
                    store, http_root=root, sequence=report.sequence,
                ) != report for report in reports)):
            raise IbPerKeySourceHold("IB report changed before readback")
        return result
    except (OSError, TypeError, KeyError, AttributeError, RuntimeError,
            ValueError) as exc:
        if isinstance(exc, IbPerKeySourceHold):
            raise
        raise IbPerKeySourceHold("IB per-key protected source is unsafe") from exc
