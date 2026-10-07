"""REQ7 Stage-L status and protected local-only C5-to-C6 entrypoint.

Qualification is not a browser confirmation, local RECEIPT, or online permit.
The root worker owns the trigger; this module never sends to Google.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
import os
from pathlib import Path

from monitor.issue_tracker_cycle_source import (
    CycleSequenceGap, CycleSourceHoldError, read_completed_cycle_evidence,
)
from monitor.issue_tracker_k_chain import KChainHoldError, assess_k_window
from monitor.issue_tracker_manifest import (
    _runtime_skip, selected_panel_decision_sha256,
)
from monitor.issue_tracker_state_owner import (
    TrackerStateHold, current_k, tracker_writer,
)
from monitor.issue_tracker_switch_runtime import (
    SwitchRuntimeHoldError, read_switch_runtime_window,
)
from monitor.issue_tracker_whitelist_workbook import (
    WhitelistHoldError, read_whitelist_workbook,
)
from tools.project_contract import MIN_CONTINUOUS_INTERVAL_MINUTES


class StageLHold(ValueError):
    """No local admission or publication authority can be inferred."""


class AutoLocalCollectorAnomaly(StageLHold):
    """Enough fresh cycles appeared before the shared publication floor."""


class TerminalC6AdmissionHold(StageLHold):
    """The current project has a RECEIPT without matching admission."""


@dataclass(frozen=True)
class AutoLocalNotDue:
    """A held source with no C23 automatic publication admission yet."""

    reason: str


def _validate_auto_clock(boot_id, monotonic_ns):
    if (type(boot_id) is not str or not boot_id
            or len(boot_id) > 128 or any(char.isspace() for char in boot_id)
            or type(monotonic_ns) is not int or monotonic_ns < 1):
        raise StageLHold("automatic admission clock provenance is invalid")


# The C6 bridge and runtime both read the same durable local event sequence.
# Keep this three-argument entry for existing runtime consumers while the
# journal implementation itself lives in the leaf admission module.
def read_auto_local_admission(token, store, expected_template_sha256):
    from monitor.issue_tracker_admission import (
        AdmissionHold, AdmissionTerminalOrphan, read_shared_local_admission,
    )
    from monitor.issue_tracker_local_workbook_commit import (
        _latest_receipted_prod_xlsx,
    )

    prior_image = _latest_receipted_prod_xlsx(
        token, expected_template_sha256)
    try:
        return read_shared_local_admission(token, store, prior_image)
    except AdmissionTerminalOrphan as exc:
        raise TerminalC6AdmissionHold(str(exc)) from exc
    except AdmissionHold as exc:
        raise StageLHold(str(exc)) from exc


def assess_auto_local_due(
    cycle_ids, *, interval, last_admitted_cycle_id,
    elapsed_seconds, minimum_seconds,
):
    """Evaluate C-23's relative event count and shared time floor.

    The caller must supply a validated durable admission witness and a
    trustworthy elapsed interval; this pure check never creates that witness.
    """
    if (type(cycle_ids) is not tuple or not cycle_ids
            or any(type(item) is not str or not item for item in cycle_ids)
            or len(set(cycle_ids)) != len(cycle_ids)
            or type(interval) is not int or interval < 1
            or type(minimum_seconds) is not int or minimum_seconds < 1):
        raise StageLHold("automatic local cadence input is invalid")
    if last_admitted_cycle_id is None:
        if elapsed_seconds is not None:
            raise StageLHold("first admission has unexpected prior time")
        return len(cycle_ids) >= interval
    if (type(last_admitted_cycle_id) is not str
            or last_admitted_cycle_id not in cycle_ids
            or type(elapsed_seconds) not in (int, float)
            or elapsed_seconds < 0):
        raise StageLHold("prior admission identity or time is unverifiable")
    try:
        finite_elapsed = math.isfinite(elapsed_seconds)
    except OverflowError as exc:
        raise StageLHold("prior admission elapsed time overflows") from exc
    if not finite_elapsed:
        raise StageLHold("prior admission elapsed time is nonfinite")
    after = len(cycle_ids) - cycle_ids.index(last_admitted_cycle_id) - 1
    if after < interval:
        return False
    if elapsed_seconds < minimum_seconds:
        raise AutoLocalCollectorAnomaly("collector_interval_below_minimum")
    return True


_PANELS = ("Switch Status", "Eth Link Validation", "IB Link Validation")
_NO_SEND = "disabled_no_send_authority"


def _panel(state, reason):
    return {"state": state, "reason": reason}


def local_publish_interval(project):
    """Retain the runtime API while the leaf owns policy and admission."""
    from monitor.issue_tracker_admission import (
        AdmissionHold, local_publish_interval as leaf_interval,
    )
    try:
        return leaf_interval(project)
    except AdmissionHold as exc:
        raise StageLHold(str(exc)) from exc


def _paths(store, http_root, project, publication, template_path):
    root = Path(http_root).resolve(strict=True)
    project = Path(project)
    publication = Path(publication)
    template = Path(template_path)
    if (not root.is_dir() or not project.is_absolute() or project.is_symlink()
            or publication != project / "99-output-monitor"
            or template.is_symlink() or not template.is_absolute()
            or Path(store.project_identity) != project
            or Path(store.root_status_dir) != root / "monitor/status"):
        raise StageLHold("Stage L path or collector authority mismatch")
    return root, project, publication, template


def _qualified_key_progress_matches(required_keys, panels, k):
    """Pure consistency check; a true result is never source or write authority."""
    if (type(k) is not int or k < 1 or type(required_keys) is not tuple
            or type(panels) is not dict or set(panels) != set(_PANELS)):
        return False
    observed = {}
    for name, panel in panels.items():
        if (type(panel) is not dict or panel.get("state") == "hold"
                or type(panel.get("per_key")) is not list):
            return False
        for item in panel["per_key"]:
            if (type(item) is not dict or type(item.get("activity_key")) is not list
                    or len(item["activity_key"]) != 4
                    or any(type(part) is not str or not part or chr(0) in part
                           for part in item["activity_key"])
                    or type(item.get("observed")) is not int
                    or not 0 <= item["observed"] <= k
                    or type(item.get("required")) is not int
                    or item["required"] != k
                    or item.get("state") not in ("pending", "source_window_complete")):
                return False
            key = (name, tuple(item["activity_key"]))
            if key in observed:
                return False
            observed[key] = item
    for panel_key in required_keys:
        if (type(panel_key) is not tuple or len(panel_key) != 2
                or type(panel_key[0]) is not str or panel_key[0] not in _PANELS
                or type(panel_key[1]) is not tuple):
            return False
        row = observed.get(panel_key)
        if (row is None or row["state"] != "source_window_complete"
                or row["observed"] != k):
            return False
    # Other pending/inactive keys do not erase the independently qualified subset.
    return True


def _qualified_panel_status(panel, k):
    """Render a previously proven source subset, not a qualification decision."""
    pending = [item for item in panel["per_key"]
               if 0 < item["observed"] < item["required"]]
    progress = (f"qualified subset; pending {min(item['observed'] for item in pending)}/{k}"
                if pending else f"qualified {k}/{k}")
    return {**panel, "state": "qualified",
            "reason": "source_set_qualified_no_local_receipt",
            "progress_text": progress,
            "per_key": [
                {**item, "progress_text":
                 (f"source complete {item['observed']}/{item['required']}"
                  if item["state"] == "source_window_complete"
                  else item["progress_text"])}
                for item in panel["per_key"]]}


def _stage_l_per_key_panels(store, root, settings, cycles, token):
    """Local diagnostics only; every key comes from reopened protected roles."""
    from monitor.issue_tracker_ib_per_key_source import (
        IbPerKeySourceHold, IbSourceAuthorityChanged, _row_key, read_prod_ib_per_key_source,
    )
    from monitor.issue_tracker_ib_runtime import (
        IbRuntimeHoldError, IbRuntimeInputChanged, read_completed_ib_cycle_report,
    )
    from monitor.issue_tracker_per_key_source import (
        EthSourceAuthorityChanged, PerKeySourceHold, _key_for_link,
        read_prod_eth_per_key_source,
    )
    from monitor.issue_tracker_switch_per_key_source import (
        SwitchPerKeySourceHold, read_prod_switch_per_key_source,
    )
    from monitor.issue_tracker_switch_runtime import (
        read_prod_eth_activity_cycle_source, read_prod_switch_cycle_source,
    )

    def pending(reason):
        return {**_panel("pending", reason), "per_key": [],
                "progress_text": f"pending 0/{settings.k}"}

    def held(reason):
        return {**_panel("hold", reason), "per_key": [],
                "progress_text": None}

    def entries(keys, reader, key_of=lambda item: item):
        rows = []
        for item in sorted(keys):
            key = key_of(item)
            result = reader(item)
            if (result.qualified is not False or result.key != key
                    or result.k_event_sha256 != settings.event_sha256):
                raise StageLHold("per-key source tried to grant authority")
            rows.append({
                "activity_key": list(key), "state": result.state,
                "observed": result.observed, "required": result.required, "reason": result.reason,
                "progress_text": ("inactive in latest cycle"
                    if result.reason == "latest_absent" else
                    f"pending {result.observed}/{result.required}"),
            })
        return rows

    def panel(rows):
        observed = min((item["observed"] for item in rows), default=0)
        return {**_panel("pending", "per_key_source_only"), "per_key": rows,
                "progress_text": f"pending {observed}/{settings.k}"}

    panels = {name: pending("cold_start") for name in _PANELS}
    if not cycles:
        return panels
    tail = cycles[-settings.k:]
    if any(cycle.qualifying is not True for cycle in tail):
        return {name: held("nonqualifying_cycle") for name in _PANELS}
    try:
        switch_keys = set()
        for cycle in tail:
            for slot in ("ethernet/prod", "nvlink/prod"):
                source = read_prod_switch_cycle_source(
                    store, http_root=root, sequence=cycle.sequence,
                    source_slot=slot,
                )
                switch_keys.update((
                    slot, ("switch", row.hostname, row.category,
                           row.component_or_sensor),
                ) for row in source.rows)
        switch_rows = entries(switch_keys, lambda item:
            read_prod_switch_per_key_source(
                store, http_root=root, settings=settings, key=item[1],
                source_slot=item[0], writer_token=token,
            ), key_of=lambda item: item[1])
        panels["Switch Status"] = panel(switch_rows)
    except (SwitchRuntimeHoldError, SwitchPerKeySourceHold, StageLHold):
        panels["Switch Status"] = held("source_evidence_incomplete")
    try:
        eth_keys = set()
        for cycle in tail:
            source = read_prod_eth_activity_cycle_source(
                store, http_root=root, sequence=cycle.sequence,
            )
            eth_keys.update(key for link in source.links
                            if (key := _key_for_link(link)) is not None)
        panels["Eth Link Validation"] = panel(entries(
            eth_keys, lambda key: read_prod_eth_per_key_source(
                store, http_root=root, settings=settings, key=key,
                writer_token=token,
            ),
        ))
    except EthSourceAuthorityChanged:
        # Keep the O-4 operator action distinct from waiting for first use or
        # investigating missing roles. Never expose raw source paths/errors
        # or invent an observation count across two different authorities.
        panels["Eth Link Validation"] = {
            **held("source_authority_changed"),
            "progress_text": "unknown — source authority changed; confirm input change",
        }
    except (SwitchRuntimeHoldError, PerKeySourceHold, StageLHold):
        panels["Eth Link Validation"] = held("source_evidence_incomplete")
    try:
        ib_keys = set()
        for cycle in tail:
            report = read_completed_ib_cycle_report(
                store, http_root=root, sequence=cycle.sequence,
            )
            ib_keys.update(_row_key(row) for row in report.rows)
        panels["IB Link Validation"] = panel(entries(
            ib_keys, lambda key: read_prod_ib_per_key_source(
                store, http_root=root, settings=settings, key=key,
                writer_token=token,
            ),
        ))
    except (IbSourceAuthorityChanged, IbRuntimeInputChanged):
        panels["IB Link Validation"] = {
            **held("source_authority_changed"),
            "progress_text": "unknown — source authority changed; confirm input change",
        }
    except (IbRuntimeHoldError, IbPerKeySourceHold, StageLHold):
        panels["IB Link Validation"] = held(
            "ib_report_not_bound_to_completed_cycle")
    return panels


def inspect_stage_l(store, *, http_root, project, publication, template_path):
    """Expose pending/hold/qualified source state, never APPLIED or online GO."""
    from monitor.issue_tracker_admission import AdmissionTerminalOrphan
    from monitor.issue_tracker_receipt_snapshot import LocalReceiptSnapshotHold

    try:
        root, project, publication, template = _paths(
            store, http_root, project, publication, template_path)
        if store.scope == "air":
            # AIR's read-only preview acquires LK-P itself. Preserve that
            # existing lock boundary; the shared snapshot below is prod only.
            with tracker_writer(project, publication) as token:
                settings = current_k(token)
            snapshot = read_whitelist_workbook(template)
            cycles = read_completed_cycle_evidence(store)
            window = assess_k_window(cycles, settings)
            status = {
                "schema_version": 1, "state": "pending",
                "project_key": store.project_key, "scope": store.scope,
                "latest_cycle_id": cycles[-1].cycle_id if cycles else None,
                "completed_cycles": len(cycles),
                "window_cycle_ids": [item.cycle_id for item in cycles[-settings.k:]],
                "k": settings.k, "k_revision": settings.revision,
                "whitelist_sha256": snapshot.whitelist.sha256,
                "online": _NO_SEND,
            }
            if window.status != "history_sufficient":
                status["panels"] = {
                    name: _panel("pending", window.reason)
                    for name in _PANELS}
                return status
            panels = {name: _panel("hold", "source_contract_unimplemented")
                      for name in _PANELS}
            try:
                preview = read_switch_runtime_window(
                    store, http_root=root, settings=settings,
                    whitelist_snapshot=snapshot, whitelist_path=template)
            except SwitchRuntimeHoldError:
                panels["Switch Status"] = _panel(
                    "hold", "source_evidence_incomplete")
            else:
                if preview.qualified is not False:
                    raise StageLHold("preview unexpectedly granted authority")
                panels["Switch Status"] = _panel(
                    "hold", "preview_is_not_qualification")
            status["state"] = "hold"
            status["panels"] = panels
            return status
        if store.scope != "prod":
            raise StageLHold("Stage L scope is unsupported")
        with tracker_writer(project, publication) as token:
            settings = current_k(token)
            snapshot = read_whitelist_workbook(template)
            try:
                cycles = read_completed_cycle_evidence(store)
            except CycleSequenceGap:
                # No readable complete chain means no provable count or
                # source window. Keep the cause distinct from legitimate
                # first use, without granting qualification or repairing it.
                if (current_k(token) != settings
                        or read_whitelist_workbook(template) != snapshot):
                    raise StageLHold("gap status K/W1 authority changed")
                return {
                    "schema_version": 1, "state": "hold",
                    "reason": "archive_sequence_gap",
                    "project_key": store.project_key, "scope": store.scope,
                    "latest_cycle_id": None, "completed_cycles": None,
                    "window_cycle_ids": [], "k": settings.k,
                    "k_revision": settings.revision,
                    "whitelist_sha256": snapshot.whitelist.sha256,
                    "panels": {name: {
                        **_panel("hold", "archive_sequence_gap"), "per_key": [],
                        "progress_text": f"pending ?/{settings.k} — archive sequence gap",
                    } for name in _PANELS},
                    "cycle_summary": {"published": None, "skipped": None,
                                      "pending": None, "pending_count_complete": False},
                    "online": _NO_SEND,
                }
            window = assess_k_window(cycles, settings)
            status = {
                "schema_version": 1, "state": "pending",
                "project_key": store.project_key, "scope": store.scope,
                "latest_cycle_id": cycles[-1].cycle_id if cycles else None,
                "completed_cycles": len(cycles),
                "window_cycle_ids": [item.cycle_id for item in cycles[-settings.k:]],
                "k": settings.k, "k_revision": settings.revision,
                "whitelist_sha256": snapshot.whitelist.sha256,
                "online": _NO_SEND,
            }
            qualified = None
            if store.scope == "prod":
                from monitor.issue_tracker_receipt_snapshot import (
                    read_current_cycle_local_receipts,
                )
                from monitor.issue_tracker_stage_l_consumer import (
                    ProdStageLQualifiedSet, StageLConsumerHold,
                    inspect_prod_stage_l_composed_sources, qualify_prod_stage_l,
                )
                panels = _stage_l_per_key_panels(
                    store, root, settings, cycles, token)
                if window.status == "history_sufficient":
                    try:
                        source = inspect_prod_stage_l_composed_sources(
                            store, http_root=root, settings=settings,
                            whitelist_snapshot=snapshot, whitelist_path=template,
                            writer_token=token)
                    except StageLConsumerHold:
                        status["reason"] = "prod_source_evidence_incomplete"
                    else:
                        if (source.qualified is not False
                                or source.switch_ib_source.switch_source.cycle_ids
                                != tuple(status["window_cycle_ids"])):
                            raise StageLHold("prod preview attempted to grant authority")
                        status["reason"] = source.reason
                        try:
                            qualified = qualify_prod_stage_l(
                                store, http_root=root, settings=settings,
                                whitelist_snapshot=snapshot,
                                whitelist_path=template, writer_token=token)
                        except StageLConsumerHold:
                            pass
                        else:
                            if (type(qualified) is not ProdStageLQualifiedSet
                                    or qualified.qualified is not True
                                    or qualified.cycle_ids
                                    != tuple(status["window_cycle_ids"])
                                    or qualified.project_key != store.project_key
                                    or qualified.scope != store.scope
                                    or qualified.k != settings.k
                                    or qualified.template_sha256
                                    != snapshot.workbook_sha256
                                    or qualified.whitelist_sha256
                                    != snapshot.whitelist.sha256):
                                raise StageLHold(
                                    "prod qualification differs from worker authority")
                            if not _qualified_key_progress_matches(
                                tuple((item.panel, item.activity_key)
                                      for item in qualified.candidates),
                                panels, settings.k,
                            ):
                                status["reason"] = "per_key_source_evidence_incomplete"
                            else:
                                status.update({
                                    "state": "qualified",
                                    "reason": "source_set_qualified_no_local_receipt",
                                    "qualified_operation_count": len(qualified.candidates),
                                    "whitelist_skip_count": len(qualified.whitelist_skips),
                                    "whitelist_skips": [
                                        _runtime_skip(item)
                                        for item in qualified.whitelist_skips],
                                    "template_sha256": qualified.template_sha256,
                                    "source_authority_sha256":
                                        qualified.source_authority_sha256,
                                    "observations_sha256": qualified.observations_sha256,
                                    "selected_decision_sha256": {
                                        panel: selected_panel_decision_sha256(
                                            qualified, panel)
                                        for panel in _PANELS
                                    },
                                })
                                panels = {
                                    name: _qualified_panel_status(panel, settings.k)
                                    for name, panel in panels.items()
                                }
                receipt = read_current_cycle_local_receipts(
                    token, store,
                    expected_template_sha256=snapshot.workbook_sha256,
                    settings=settings,
                    whitelist_sha256=snapshot.whitelist.sha256,
                    qualified_source=qualified)
                if status["state"] == "qualified" and receipt.published:
                    status["reason"] = "source_set_qualified_local_receipt"
                    for panel in panels.values():
                        panel["reason"] = status["reason"]
                status["cycle_summary"] = {
                    "published": receipt.published,
                    "skipped": (len(qualified.whitelist_skips)
                                if status["state"] == "qualified" else None),
                    "pending": sum(
                        0 < item["observed"] < item["required"]
                        for panel in panels.values()
                        for item in panel["per_key"]),
                    # A numeric zero with a held or cold panel is only a
                    # lower bound: its keys have not all been proven readable.
                    "pending_count_complete": all(
                        panel["state"] == "qualified"
                        for panel in panels.values()),
                }
                if (window.status != "history_sufficient"
                        and all(panels[name]["state"] == "pending"
                                for name in _PANELS[:2])):
                    status["state"] = "pending"
                elif status["state"] != "qualified":
                    status["state"] = "hold"
                status["panels"] = panels
            else:
                raise StageLHold("Stage L scope is unsupported")
            if (current_k(token) != settings
                    or read_completed_cycle_evidence(store) != cycles
                    or read_whitelist_workbook(template).workbook_sha256
                       != snapshot.workbook_sha256):
                raise StageLHold("Stage L snapshot changed during inspection")
            return status
    except (OSError, TypeError, AttributeError, RuntimeError, ValueError,
            CycleSourceHoldError, KChainHoldError, TrackerStateHold,
            WhitelistHoldError) as exc:
        if isinstance(exc, StageLHold):
            raise
        if (isinstance(exc, LocalReceiptSnapshotHold)
                and isinstance(exc.__cause__, AdmissionTerminalOrphan)):
            raise TerminalC6AdmissionHold(str(exc.__cause__)) from exc
        raise StageLHold("Stage L authority is incomplete or unsafe") from exc


def commit_qualified_prod_local(
    store, *, http_root, project, publication, template_path,
    refuse_prior_without_admission=False, auto_admission=None,
    manual_admission=None, expected_manual_preview=None,
    selected_panel=None,
):
    """Requalify protected prod sources under one writer and commit C6 only."""
    from monitor.issue_tracker_local_commit import LocalCommitHold
    from monitor.issue_tracker_local_workbook import LocalWorkbookHold
    from monitor.issue_tracker_local_workbook_commit import commit_prod_stage_l_workbook
    from monitor.issue_tracker_stage_l_consumer import (
        StageLConsumerHold, qualify_prod_stage_l,
    )

    try:
        root, project, publication, template = _paths(
            store, http_root, project, publication, template_path)
        if (store.scope != "prod"
                or template != root / "monitor/Issue_Tracker_Template_v1.xlsx"):
            raise StageLHold("C5-to-C6 template or scope is unbound")
        if type(refuse_prior_without_admission) is not bool:
            raise StageLHold("automatic admission guard must be explicit")
        if refuse_prior_without_admission != (auto_admission is not None):
            raise StageLHold("automatic admission witness must be explicit")
        if auto_admission is not None and (
                type(auto_admission) is not tuple or len(auto_admission) != 4):
            raise StageLHold("automatic admission witness shape is invalid")
        if manual_admission is not None and (
                auto_admission is not None or type(manual_admission) is not tuple
                or len(manual_admission) != 4):
            raise StageLHold("manual admission witness shape is invalid")
        if expected_manual_preview is not None and (
                manual_admission is None or type(expected_manual_preview) is not dict):
            raise StageLHold("manual preview requires a manual admission witness")
        if (expected_manual_preview is None) != (selected_panel is None):
            raise StageLHold("manual preview and one selected panel must be bound together")
        if selected_panel is not None and (
                type(selected_panel) is not str or selected_panel not in _PANELS):
            raise StageLHold("manual selected panel is invalid")
        with tracker_writer(project, publication) as token:
            settings = current_k(token)
            snapshot = read_whitelist_workbook(template)
            if auto_admission is None and manual_admission is None:
                # The manual/ retry UI has not supplied a shared-domain
                # admission witness yet. It cannot create a new C6 generation
                # after an automatic event and bypass that event's limiter.
                from monitor.issue_tracker_local_commit import _owner
                try:
                    os.stat("admissions", dir_fd=_owner(token).root_fd,
                            follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    # Validate the existing chain before HOLD; a corrupt
                    # record must retain its specific failure evidence.
                    # A witness-bearing manual C6 uses the shared admission
                    # journal and floor in the C6 bridge. This no-witness
                    # entry stays HOLD; Stage O retry remains unimplemented.
                    read_auto_local_admission(
                        token, store, snapshot.workbook_sha256,
                    )
                    raise StageLHold(
                        "manual C6 lacks shared admission witness"
                    )
            if auto_admission is not None:
                policy_sha, interval, boot_id, now_ns = auto_admission
                if local_publish_interval(project) != (interval, policy_sha):
                    raise StageLHold("automatic local policy changed before C6")
                _validate_auto_clock(boot_id, now_ns)
                prior_admission = read_auto_local_admission(
                    token, store, snapshot.workbook_sha256,
                )
                if prior_admission is not None:
                    if (prior_admission["boot_id"] != boot_id
                            or now_ns < prior_admission["monotonic_ns"]):
                        raise StageLHold(
                            "automatic admission restart interval is unverifiable"
                        )
                    cycles = read_completed_cycle_evidence(store)
                    cycle_ids = tuple(cycle.cycle_id for cycle in cycles
                                      if cycle.qualifying)
                    due = assess_auto_local_due(
                        cycle_ids, interval=interval,
                        last_admitted_cycle_id=prior_admission["cycle_id"],
                        elapsed_seconds=(
                            now_ns - prior_admission["monotonic_ns"]
                        ) / 1_000_000_000,
                        minimum_seconds=MIN_CONTINUOUS_INTERVAL_MINUTES * 60,
                    )
                    if not due:
                        return AutoLocalNotDue("awaiting_new_cycle_or_time_floor")
            qualified = qualify_prod_stage_l(
                store, http_root=root, settings=settings,
                whitelist_snapshot=snapshot, whitelist_path=template,
                writer_token=token,
            )
            if expected_manual_preview is not None:
                # This comparison remains inside LK-P and follows a fresh
                # protected-source qualification.  A browser token alone can
                # never authorize the subsequent C6 generation.
                actual_preview = {
                    "project_key": qualified.project_key,
                    "scope": qualified.scope, "k": qualified.k,
                    "k_revision": settings.revision,
                    "latest_cycle_id": qualified.cycle_ids[-1]
                    if qualified.cycle_ids else None,
                    "window_cycle_ids": qualified.cycle_ids,
                    "whitelist_sha256": qualified.whitelist_sha256,
                    "template_sha256": qualified.template_sha256,
                    "source_authority_sha256": qualified.source_authority_sha256,
                    "observations_sha256": qualified.observations_sha256,
                    "selected_decision_sha256": selected_panel_decision_sha256(
                        qualified, selected_panel),
                }
                if expected_manual_preview != actual_preview:
                    raise StageLHold("manual preview source changed before C6")
            metadata = {
                "project_id": str(project), "schema_version": 1,
                "producer_version": "stage-l-runtime-v1",
                "template_contract_version": "local-xlsx-v1",
                "template_sha256": snapshot.workbook_sha256,
            }
            result = commit_prod_stage_l_workbook(
                token, qualified, store, http_root=root, settings=settings,
                whitelist_snapshot=snapshot, whitelist_path=template,
                template_path=template, metadata=metadata,
                expected_template_sha256=snapshot.workbook_sha256,
                auto_admission=auto_admission,
                manual_admission=manual_admission,
                selected_panel=selected_panel,
            )
            return result
    except (OSError, TypeError, AttributeError, RuntimeError, ValueError,
            LocalCommitHold, LocalWorkbookHold, StageLConsumerHold,
            TrackerStateHold, WhitelistHoldError) as exc:
        if isinstance(exc, StageLHold):
            raise
        from monitor.issue_tracker_admission import (
            AdmissionCollectorAnomaly, AdmissionTerminalOrphan,
        )
        if isinstance(exc, AdmissionTerminalOrphan):
            raise TerminalC6AdmissionHold(str(exc)) from exc
        if isinstance(exc, AdmissionCollectorAnomaly):
            raise AutoLocalCollectorAnomaly(str(exc)) from exc
        raise StageLHold("C5-to-C6 local authority is incomplete or unsafe") from exc
