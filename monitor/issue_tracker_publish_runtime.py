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
    CycleSourceHoldError, read_completed_cycle_evidence,
)
from monitor.issue_tracker_k_chain import KChainHoldError, assess_k_window
from monitor.issue_tracker_manifest import _runtime_skip
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


def inspect_stage_l(store, *, http_root, project, publication, template_path):
    """Expose pending/hold/qualified source state, never APPLIED or online GO."""
    try:
        root, project, publication, template = _paths(
            store, http_root, project, publication, template_path)
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
            status["panels"] = {name: _panel("pending", window.reason)
                                for name in _PANELS}
            return status
        panels = {name: _panel("hold", "source_contract_unimplemented")
                  for name in _PANELS}
        if store.scope == "air":
            try:
                preview = read_switch_runtime_window(
                    store, http_root=root, settings=settings,
                    whitelist_snapshot=snapshot, whitelist_path=template)
            except SwitchRuntimeHoldError:
                panels["Switch Status"] = _panel("hold", "source_evidence_incomplete")
            else:
                if preview.qualified is not False:
                    raise StageLHold("preview unexpectedly granted authority")
                panels["Switch Status"] = _panel("hold", "preview_is_not_qualification")
        elif store.scope == "prod":
            from monitor.issue_tracker_stage_l_consumer import (
                ProdStageLQualifiedSet, StageLConsumerHold,
                inspect_prod_stage_l_composed_sources, qualify_prod_stage_l,
            )
            try:
                source = inspect_prod_stage_l_composed_sources(
                    store, http_root=root, settings=settings,
                    whitelist_snapshot=snapshot, whitelist_path=template)
            except StageLConsumerHold:
                panels = {name: _panel("hold", "source_evidence_incomplete")
                          for name in _PANELS}
                status["reason"] = "prod_source_evidence_incomplete"
            else:
                if (source.qualified is not False
                        or source.switch_ib_source.switch_source.cycle_ids
                        != tuple(status["window_cycle_ids"])):
                    raise StageLHold("prod preview attempted to grant authority")
                panels = {
                    "Switch Status": _panel("hold", "source_observed_not_qualified"),
                    "Eth Link Validation": _panel("hold", "source_observed_not_qualified"),
                    "IB Link Validation": _panel("hold", source.reason),
                }
                status["reason"] = source.reason
                try:
                    qualified = qualify_prod_stage_l(
                        store, http_root=root, settings=settings,
                        whitelist_snapshot=snapshot, whitelist_path=template)
                except StageLConsumerHold:
                    pass
                else:
                    if (type(qualified) is not ProdStageLQualifiedSet
                            or qualified.qualified is not True
                            or qualified.cycle_ids != tuple(status["window_cycle_ids"])
                            or qualified.project_key != store.project_key
                            or qualified.scope != store.scope or qualified.k != settings.k
                            or qualified.template_sha256 != snapshot.workbook_sha256
                            or qualified.whitelist_sha256 != snapshot.whitelist.sha256):
                        raise StageLHold("prod qualification differs from worker authority")
                    status.update({
                        "state": "qualified", "reason": "source_set_qualified_no_local_receipt",
                        "panels": {name: _panel("qualified", "source_set_qualified_no_local_receipt")
                                   for name in _PANELS},
                        "qualified_operation_count": len(qualified.candidates),
                        "whitelist_skip_count": len(qualified.whitelist_skips),
                        "whitelist_skips": [_runtime_skip(item)
                                            for item in qualified.whitelist_skips],
                        "source_authority_sha256": qualified.source_authority_sha256,
                        "observations_sha256": qualified.observations_sha256,
                    })
                    return status
        else:
            raise StageLHold("Stage L scope is unsupported")
        status["state"] = "hold"
        status["panels"] = panels
        return status
    except (OSError, TypeError, AttributeError, RuntimeError, ValueError,
            CycleSourceHoldError, KChainHoldError, TrackerStateHold,
            WhitelistHoldError) as exc:
        if isinstance(exc, StageLHold):
            raise
        raise StageLHold("Stage L authority is incomplete or unsafe") from exc


def commit_qualified_prod_local(
    store, *, http_root, project, publication, template_path,
    refuse_prior_without_admission=False, auto_admission=None,
    manual_admission=None,
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
