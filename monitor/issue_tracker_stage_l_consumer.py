"""REQ7 Stage L protected source projection and local qualified intent.

ETH/NVL, IB, and ETH link source readers can be combined against one completed
K window. Source snapshots remain HOLD. Qualification additionally replays a
protected IB producer and all three source readers before building C5 intent;
this module does not create a manifest, workbook, generation, RECEIPT, or
online send permit.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
from pathlib import Path

from monitor.issue_tracker_cycle_source import read_completed_cycle_evidence
from monitor.issue_tracker_ib_runtime import (
    IbWhitelistedKWindow, read_prod_ib_k_window,
    read_whitelisted_ib_k_window, validate_prod_ib_k_window,
)
from monitor.issue_tracker_k_chain import KChainState
from monitor.issue_tracker_local_commit import _owner
from monitor.issue_tracker_qualification import _canonical_json
from monitor.issue_tracker_state_owner import current_k, tracker_writer
from monitor.issue_tracker_switch_info_source import SwitchSourceRow
from monitor.issue_tracker_switch_runtime import (
    ProdEthActivityKWindow, ProdEthIssueSourceRow, ProdSwitchKWindow,
    classify_prod_eth_activity_k_window, read_prod_eth_activity_k_window,
    read_prod_switch_cycle_source,
    read_prod_switch_k_window,
)
from monitor.issue_tracker_whitelist_workbook import WorkbookWhitelistSnapshot


class StageLConsumerHold(ValueError):
    """Source or publication authority is missing; no mutation is permitted."""


@dataclass(frozen=True)
class ProdStageLSourceSnapshot:
    """Real ETH/NVL source evidence, explicitly not a three-panel result."""

    cycle_ids: tuple[str, ...]
    completion_sha256: tuple[str, ...]
    k_event_sha256: str
    whitelist_sha256: str
    template_sha256: str
    switch_rows: tuple[SwitchSourceRow, ...]
    switch_identities: tuple[tuple[str, str, str, str], ...] = ()
    state: str = "hold"
    reason: str = "ib_report_not_bound_to_completed_cycle"
    qualified: bool = False


@dataclass(frozen=True)
class ProdStageLBoundSourceSnapshot:
    """Two Switch families plus IB bound to K; ETH Cabling and C5/C6 absent."""

    switch_source: ProdStageLSourceSnapshot
    ib_source: IbWhitelistedKWindow
    state: str = "hold"
    reason: str = "qualification_not_implemented"
    qualified: bool = False


@dataclass(frozen=True)
class ProdStageLComposedSourceSnapshot:
    """Three source domains on one K, still no issue or publish authority."""

    switch_ib_source: ProdStageLBoundSourceSnapshot
    eth_link_source: ProdEthActivityKWindow
    eth_issue_rows: tuple[ProdEthIssueSourceRow, ...]
    state: str = "hold"
    reason: str = "qualification_not_implemented"
    qualified: bool = False


@dataclass(frozen=True)
class StageLSourceCandidate:
    """One literal panel value; it is not a C5 operation or write permit."""

    operation_id: str
    activity_key: tuple[str, str, str, str]
    panel: str
    source_sheet: str
    issue_type: str
    source_status: str
    evidence_description: str
    expected_endpoints: tuple[str, str, str, str] = ()
    actual_endpoints: tuple[str, str, str, str] = ()
    fabric: str | None = None
    fabric_source: str | None = None
    recorded_at_utc: str = ""
    qualified: bool = False


@dataclass(frozen=True)
class StageLSourceSkip:
    """A W1 exclusion preserved in the preview, not an accepted issue."""

    source: str
    endpoints: tuple[str, str, str, str] | None
    matched_rule: str | None
    record_id: str | None = None


@dataclass(frozen=True)
class ProdStageLSourceProjection:
    """Three-panel source values with unresolved Fabric and no authority."""

    cycle_ids: tuple[str, ...]
    completion_sha256: tuple[str, ...]
    k_event_sha256: str
    whitelist_sha256: str
    template_sha256: str
    candidates: tuple[StageLSourceCandidate, ...]
    whitelist_skips: tuple[StageLSourceSkip, ...]
    hostname_fallback_count: int = 0
    state: str = "hold"
    reason: str = "fabric_identity_unresolved"
    qualified: bool = False


@dataclass(frozen=True)
class StageLQualifiedSkip:
    source: str
    matched_rule: str
    activity_key: tuple[str, str, str, str] | None = None
    endpoints: tuple[str, str, str, str] | None = None
    record_id: str | None = None


@dataclass(frozen=True)
class ProdStageLQualifiedSet:
    """C5 intent from real protected sources, never a write/send permit."""

    operations_json: bytes
    candidates: tuple[StageLSourceCandidate, ...]
    whitelist_skips: tuple[StageLQualifiedSkip, ...]
    cycle_ids: tuple[str, ...]
    completion_sha256: tuple[str, ...]
    source_authority_sha256: str
    observations_sha256: str
    k_event_sha256: str
    whitelist_sha256: str
    template_sha256: str
    project_key: str
    scope: str
    k: int
    recorded_at_utc: str
    mode: str = "prod-runtime-protected-v1"
    qualified: bool = True


_FABRIC_WORDS = (("OOB", ("border", "oob")),
                 ("Inband", ("tan",)))


def _operation_id(key: tuple[str, str, str, str]) -> str:
    return "stl-" + hashlib.sha256(_canonical_json(key)).hexdigest()


def classify_stage_l_fabric(
    device_type: str, template: str, hostname: str,
) -> tuple[str, str]:
    """D-15: one vocabulary, strictly type then template then host fallback."""
    if any(type(value) is not str or any(char in value for char in "\x00\r\n")
           for value in (device_type, template, hostname)):
        raise StageLConsumerHold("Fabric identity is malformed")
    if device_type.strip().casefold() in {"ib", "nvl", "eth_spx"}:
        return "Compute", "type"
    for source, value in (("template", template),
                          ("hostname-fallback", hostname)):
        folded = value.casefold()
        for fabric, words in _FABRIC_WORDS:
            if any(word in folded for word in words):
                return fabric, source
    raise StageLConsumerHold("Fabric is unresolved in frozen device identity")


def _latest_rows(
    window: ProdSwitchKWindow, store, root: Path, sequence: int,
) -> tuple[tuple[SwitchSourceRow, ...],
           tuple[tuple[str, str, str, str], ...]]:
    latest = read_prod_switch_cycle_source(
        store, http_root=root, sequence=sequence,
        source_slot=window.source_slot,
    )
    if (latest.cycle_id != window.cycle_ids[-1]
            or latest.completion_sha256 != window.completion_sha256[-1]
            or latest.preview.archive_sha256 != window.archive_sha256[-1]):
        raise StageLConsumerHold("latest switch source differs from completed K window")
    allowed = set(window.persistent_keys)
    skipped = set(window.whitelist_skips)
    identities = tuple((host, device_type, template, window.source_slot)
                       for host, device_type, template
                       in latest.fabric_identities)
    if (len({item[0].casefold() for item in identities}) != len(identities)
            or {item[0] for item in identities}
            != set(latest.preview.selected_hosts)):
        raise StageLConsumerHold("frozen Fabric identities do not cover selected hosts")
    rows = tuple(row for row in latest.rows
                 if (row.hostname, row.category, row.component_or_sensor) in allowed
                 and "switch:" + row.hostname not in skipped)
    return rows, identities


def inspect_prod_stage_l_sources(
    store, *, http_root: Path | str, settings: KChainState,
    whitelist_snapshot: WorkbookWhitelistSnapshot,
    whitelist_path: Path | str, writer_token=None,
) -> ProdStageLSourceSnapshot:
    """Bind two real Switch families to the same completed prod K-window.

    A complete ETH/NVL source is useful for diagnosing the missing IB role,
    but never a substitute for that role or for a local issue transaction.
    """
    try:
        root = Path(http_root).resolve(strict=True)
        if (store.scope != "prod" or not root.is_dir()
                or not isinstance(settings, KChainState)
                or not isinstance(whitelist_snapshot, WorkbookWhitelistSnapshot)):
            raise StageLConsumerHold("prod Stage L source authority is unsupported")
        cycles = read_completed_cycle_evidence(store)
        windows = tuple(read_prod_switch_k_window(
            store, http_root=root, settings=settings,
            whitelist_snapshot=whitelist_snapshot,
            whitelist_path=whitelist_path, source_slot=slot,
            writer_token=writer_token,
        ) for slot in ("ethernet/prod", "nvlink/prod"))
        eth, nvl = windows
        if (eth.cycle_ids != nvl.cycle_ids
                or eth.completion_sha256 != nvl.completion_sha256
                or eth.k_event_sha256 != nvl.k_event_sha256
                or eth.whitelist_sha256 != nvl.whitelist_sha256
                or eth.template_sha256 != nvl.template_sha256
                or tuple(item.cycle_id for item in cycles[-settings.k:]) != eth.cycle_ids
                or any(window.qualified is not False for window in windows)):
            raise StageLConsumerHold("three-panel source cycles or policy disagree")
        eth_rows, eth_identities = _latest_rows(
            eth, store, root, cycles[-1].sequence)
        nvl_rows, nvl_identities = _latest_rows(
            nvl, store, root, cycles[-1].sequence)
        rows = eth_rows + nvl_rows
        identities = eth_identities + nvl_identities
        if len({item[0].casefold() for item in identities}) != len(identities):
            raise StageLConsumerHold("frozen Fabric host identities collide")
        keys = tuple((row.hostname, row.category, row.component_or_sensor)
                     for row in rows)
        if len(set(keys)) != len(keys):
            raise StageLConsumerHold("ETH and NVL Switch source keys collide")
        again = tuple(read_prod_switch_k_window(
            store, http_root=root, settings=settings,
            whitelist_snapshot=whitelist_snapshot,
            whitelist_path=whitelist_path, source_slot=slot,
            writer_token=writer_token,
        ) for slot in ("ethernet/prod", "nvlink/prod"))
        if again != windows or read_completed_cycle_evidence(store) != cycles:
            raise StageLConsumerHold("prod Stage L source changed during read")
        return ProdStageLSourceSnapshot(
            cycle_ids=eth.cycle_ids,
            completion_sha256=eth.completion_sha256,
            k_event_sha256=eth.k_event_sha256,
            whitelist_sha256=eth.whitelist_sha256,
            template_sha256=eth.template_sha256,
            switch_rows=tuple(sorted(rows, key=lambda row: (
                row.hostname, row.category, row.component_or_sensor,
            ))),
            switch_identities=tuple(sorted(identities)),
        )
    except (OSError, TypeError, AttributeError, RuntimeError, ValueError) as exc:
        if isinstance(exc, StageLConsumerHold):
            raise
        raise StageLConsumerHold("prod Stage L source evidence is unsafe") from exc


def validate_prod_stage_l_sources(
    witness: ProdStageLSourceSnapshot, store, *, http_root: Path | str,
    settings: KChainState, whitelist_snapshot: WorkbookWhitelistSnapshot,
    whitelist_path: Path | str, writer_token=None,
) -> ProdStageLSourceSnapshot:
    """Reread all sources; a copied Python object is not a publication token."""
    if (type(witness) is not ProdStageLSourceSnapshot
            or witness.qualified is not False
            or witness.state != "hold"
            or witness.reason != "ib_report_not_bound_to_completed_cycle"):
        raise StageLConsumerHold("prod source snapshot claims unearned authority")
    actual = inspect_prod_stage_l_sources(
        store, http_root=http_root, settings=settings,
        whitelist_snapshot=whitelist_snapshot, whitelist_path=whitelist_path,
        writer_token=writer_token,
    )
    if actual != witness:
        raise StageLConsumerHold("prod source snapshot changed before freeze")
    return actual


def inspect_prod_stage_l_bound_sources(
    store, *, http_root: Path | str, settings: KChainState,
    whitelist_snapshot: WorkbookWhitelistSnapshot,
    whitelist_path: Path | str, writer_token=None,
) -> ProdStageLBoundSourceSnapshot:
    """Read protected IB K source with ETH/NVL Switch K and W1, not ETH Cabling.

    A patched report reader can exercise composition in tests, but this API
    cannot promote such a witness or any other source into a qualified set.
    """
    try:
        root = Path(http_root).resolve(strict=True)
        source = inspect_prod_stage_l_sources(
            store, http_root=root, settings=settings,
            whitelist_snapshot=whitelist_snapshot, whitelist_path=whitelist_path,
            writer_token=writer_token,
        )
        project = Path(store.project_identity)
        if not project.is_absolute() or project.is_symlink():
            raise StageLConsumerHold("prod tracker project identity is unsafe")
        publication = project / "99-output-monitor"

        def observe_ib(token) -> IbWhitelistedKWindow:
            owner = _owner(token)
            if owner.project != project or owner.publication != publication:
                raise StageLConsumerHold("IB writer token does not own Stage L publication")
            if current_k(token) != settings:
                raise StageLConsumerHold("prod K changed before IB read")
            result = read_whitelisted_ib_k_window(
                store, http_root=root, token=token,
                workbook_path=whitelist_path,
            )
            if current_k(token) != settings:
                raise StageLConsumerHold("prod K changed during IB read")
            return result

        def read_ib() -> IbWhitelistedKWindow:
            if writer_token is not None:
                return observe_ib(writer_token)
            with tracker_writer(project, publication) as token:
                return observe_ib(token)

        ib = read_ib()
        if (ib.qualified is not False or ib.window.qualified is not False
                or ib.window.status != "history_sufficient"
                or ib.window.required != settings.k
                or ib.window.cycle_ids != source.cycle_ids
                or len(ib.window.report_sha256s) != settings.k
                or ib.window.expected_topology_sha256 is None
                or ib.whitelist_sha256 != source.whitelist_sha256
                or ib.workbook_sha256 != source.template_sha256):
            raise StageLConsumerHold("IB and Switch completed K sources disagree")
        if (read_ib() != ib
                or validate_prod_stage_l_sources(
                    source, store, http_root=root, settings=settings,
                    whitelist_snapshot=whitelist_snapshot,
                    whitelist_path=whitelist_path, writer_token=writer_token,
                ) != source):
            raise StageLConsumerHold("prod Switch/IB source changed during read")
        return ProdStageLBoundSourceSnapshot(source, ib)
    except (OSError, TypeError, AttributeError, RuntimeError, ValueError) as exc:
        if isinstance(exc, StageLConsumerHold):
            raise
        raise StageLConsumerHold("prod Switch/IB source evidence is unsafe") from exc


def validate_prod_stage_l_bound_sources(
    witness: ProdStageLBoundSourceSnapshot, store, *, http_root: Path | str,
    settings: KChainState, whitelist_snapshot: WorkbookWhitelistSnapshot,
    whitelist_path: Path | str, writer_token=None,
) -> ProdStageLBoundSourceSnapshot:
    """Reread Switch-family and IB sources without write authority."""
    if (type(witness) is not ProdStageLBoundSourceSnapshot
            or witness.qualified is not False or witness.state != "hold"
            or witness.reason != "qualification_not_implemented"):
        raise StageLConsumerHold("prod Switch/IB snapshot claims unearned authority")
    actual = inspect_prod_stage_l_bound_sources(
        store, http_root=http_root, settings=settings,
        whitelist_snapshot=whitelist_snapshot, whitelist_path=whitelist_path,
        writer_token=writer_token,
    )
    if actual != witness:
        raise StageLConsumerHold("prod Switch/IB snapshot changed before freeze")
    return actual


def inspect_prod_stage_l_composed_sources(
    store, *, http_root: Path | str, settings: KChainState,
    whitelist_snapshot: WorkbookWhitelistSnapshot,
    whitelist_path: Path | str, writer_token=None,
) -> ProdStageLComposedSourceSnapshot:
    """Bind Switch, ETH link and protected IB source readers to one K/W1.

    The result is a HOLD-only diagnostic: observed ETH link statuses have only
    source-level sheet/type labels, not issue operations or C5/C6 proof.
    """
    try:
        root = Path(http_root).resolve(strict=True)
        cycles = read_completed_cycle_evidence(store)
        switch_ib = inspect_prod_stage_l_bound_sources(
            store, http_root=root, settings=settings,
            whitelist_snapshot=whitelist_snapshot,
            whitelist_path=whitelist_path, writer_token=writer_token,
        )
        eth_link = read_prod_eth_activity_k_window(
            store, http_root=root, settings=settings,
            whitelist_snapshot=whitelist_snapshot,
            whitelist_path=whitelist_path, writer_token=writer_token,
        )
        switch = switch_ib.switch_source
        if (switch_ib.qualified is not False
                or eth_link.qualified is not False
                or switch.cycle_ids != eth_link.cycle_ids
                or switch.completion_sha256 != eth_link.completion_sha256
                or switch.k_event_sha256 != eth_link.k_event_sha256
                or switch.whitelist_sha256 != eth_link.whitelist_sha256
                or switch.template_sha256 != eth_link.template_sha256
                or switch_ib.ib_source.window.cycle_ids != eth_link.cycle_ids
                or read_completed_cycle_evidence(store) != cycles):
            raise StageLConsumerHold("three source domains disagree on K/W1")
        if (inspect_prod_stage_l_bound_sources(
                store, http_root=root, settings=settings,
                whitelist_snapshot=whitelist_snapshot,
                whitelist_path=whitelist_path, writer_token=writer_token,
            ) != switch_ib or read_prod_eth_activity_k_window(
                store, http_root=root, settings=settings,
                whitelist_snapshot=whitelist_snapshot,
                whitelist_path=whitelist_path, writer_token=writer_token,
            ) != eth_link):
            raise StageLConsumerHold("three source domains changed during read")
        return ProdStageLComposedSourceSnapshot(
            switch_ib, eth_link, classify_prod_eth_activity_k_window(eth_link),
        )
    except (OSError, TypeError, AttributeError, RuntimeError, ValueError) as exc:
        if isinstance(exc, StageLConsumerHold):
            raise
        raise StageLConsumerHold("composed Stage L source evidence is unsafe") from exc


def validate_prod_stage_l_composed_sources(
    witness: ProdStageLComposedSourceSnapshot, store, *, http_root: Path | str,
    settings: KChainState, whitelist_snapshot: WorkbookWhitelistSnapshot,
    whitelist_path: Path | str, writer_token=None,
) -> ProdStageLComposedSourceSnapshot:
    """Reread all three source domains; this is not a publication permit."""
    if (type(witness) is not ProdStageLComposedSourceSnapshot
            or witness.qualified is not False or witness.state != "hold"
            or witness.reason != "qualification_not_implemented"):
        raise StageLConsumerHold("composed Stage L source claims unearned authority")
    actual = inspect_prod_stage_l_composed_sources(
        store, http_root=http_root, settings=settings,
        whitelist_snapshot=whitelist_snapshot,
        whitelist_path=whitelist_path, writer_token=writer_token,
    )
    if actual != witness:
        raise StageLConsumerHold("composed Stage L source changed before freeze")
    return actual


def project_prod_stage_l_source_candidates(
    witness: ProdStageLComposedSourceSnapshot, store, *,
    http_root: Path | str, settings: KChainState,
    whitelist_snapshot: WorkbookWhitelistSnapshot,
    whitelist_path: Path | str, writer_token=None,
) -> ProdStageLSourceProjection:
    """Reread the same K/W1 and show three panels without promoting them.

    Frozen Switch type/template and exact source-level W1 matched rules are
    shown when available. A preview is still never a C5 issue operation.
    """
    source = validate_prod_stage_l_composed_sources(
        witness, store, http_root=http_root, settings=settings,
        whitelist_snapshot=whitelist_snapshot,
        whitelist_path=whitelist_path, writer_token=writer_token,
    )
    switch = source.switch_ib_source.switch_source
    ib = source.switch_ib_source.ib_source
    recorded_at_utc = ib.window.recorded_at_utc
    candidates = []
    identities = {(host, slot): (device_type, template)
                  for host, device_type, template, slot
                  in switch.switch_identities}
    unresolved_fabric = False
    for row in switch.switch_rows:
        if (type(row) is not SwitchSourceRow or row.qualified is not False
                or row.category not in {"fan", "psu", "asic_temp", "psu_temp"}
                or any(type(part) is not str or not part or "\x00" in part
                       for part in (row.hostname, row.category,
                                    row.component_or_sensor))):
            raise StageLConsumerHold("Switch source row cannot be projected")
        identity = identities.get((row.hostname, row.source_slot))
        if identity is None:
            raise StageLConsumerHold("Switch row has no frozen Fabric identity")
        try:
            fabric, fabric_source = classify_stage_l_fabric(
                identity[0], identity[1], row.hostname,
            )
        except StageLConsumerHold as exc:
            if str(exc) != "Fabric is unresolved in frozen device identity":
                raise
            fabric = fabric_source = None
            unresolved_fabric = True
        key = ("switch", row.hostname, row.category,
               row.component_or_sensor)
        candidates.append(StageLSourceCandidate(
            operation_id=_operation_id(key), activity_key=key,
            panel="Switch Status", source_sheet="ETH&IB Switch",
            issue_type="", source_status=row.value.state,
            evidence_description=row.value.evidence_description,
            fabric=fabric, fabric_source=fabric_source,
            recorded_at_utc=recorded_at_utc,
        ))
    for row in source.eth_issue_rows:
        if (type(row) is not ProdEthIssueSourceRow or row.qualified is not False
                or (row.source_sheet, row.issue_type) not in {
                    ("Missing_Links", "Link Down"),
                    ("Miswired_Links", "Mis-wiring"),
                }):
            raise StageLConsumerHold("ETH issue source row cannot be projected")
        link = row.observation
        expected = (link.device_a, link.interface_a,
                    link.device_b, link.interface_b)
        actual = (link.observation_a.remote_host,
                  link.observation_a.remote_port,
                  link.observation_b.remote_host,
                  link.observation_b.remote_port)
        key = ("eth_cabling", link.device_a,
               link.interface_a, row.issue_type)
        candidates.append(StageLSourceCandidate(
            operation_id=_operation_id(key), activity_key=key,
            panel="Eth Link Validation", source_sheet=row.source_sheet,
            issue_type=row.issue_type, source_status=link.status,
            evidence_description=(f"{row.source_sheet}: "
                                  f"{link.device_a}:{link.interface_a}"
                                  f" -> {link.device_b}:{link.interface_b}"),
            expected_endpoints=expected, actual_endpoints=actual,
            recorded_at_utc=recorded_at_utc,
        ))
    for row in ib.kept_rows:
        if (row.source_sheet, row.issue_type) not in {
                ("Missing_Links", "Link Down"),
                ("Miswired_Links", "Mis-wiring"),
        }:
            raise StageLConsumerHold("IB issue source row cannot be projected")
        expected = row.expected_endpoints
        actual = (("", "", "", "") if row.issue_type == "Link Down" else
                  (expected[0], expected[1], *row.actual_destination))
        key = ("ib_cabling", expected[0], expected[1], row.issue_type)
        candidates.append(StageLSourceCandidate(
            operation_id=_operation_id(key), activity_key=key,
            panel="IB Link Validation", source_sheet=row.source_sheet,
            issue_type=row.issue_type, source_status=row.issue_type,
            evidence_description=(f"{row.source_sheet}!{row.report_row}: "
                                  f"{expected[0]}:{expected[1]}"
                                  f" -> {expected[2]}:{expected[3]}"),
            expected_endpoints=expected, actual_endpoints=actual,
            recorded_at_utc=recorded_at_utc,
        ))
    keys = tuple(item.activity_key for item in candidates)
    if (len(keys) != len(set(keys))
            or len({item.operation_id for item in candidates}) != len(candidates)
            or any(item.qualified is not False for item in candidates)):
        raise StageLConsumerHold("Stage L source candidate identities collide")
    skips = []
    for slot in ("ethernet/prod", "nvlink/prod"):
        window = read_prod_switch_k_window(
            store, http_root=http_root, settings=settings,
            whitelist_snapshot=whitelist_snapshot,
            whitelist_path=whitelist_path, source_slot=slot,
            writer_token=writer_token,
        )
        if (window.cycle_ids != switch.cycle_ids
                or window.completion_sha256 != switch.completion_sha256
                or window.k_event_sha256 != switch.k_event_sha256
                or window.whitelist_sha256 != switch.whitelist_sha256
                or window.template_sha256 != switch.template_sha256
                or tuple(record_id for record_id, _ in window.whitelist_skip_matches)
                != window.whitelist_skips):
            raise StageLConsumerHold("Switch W1 skip source disagrees with K/W1")
        for record_id, rule in window.whitelist_skip_matches:
            if (type(record_id) is not str
                    or not record_id.startswith("switch:")
                    or record_id[7:] not in window.selected_hosts
                    or type(rule) is not str or not rule):
                raise StageLConsumerHold("Switch W1 matched-rule provenance is incomplete")
            skips.append(StageLSourceSkip(
                "switch", None, rule, record_id=record_id,
            ))
    eth_skips = source.eth_link_source.whitelist_skips
    eth_matches = source.eth_link_source.whitelist_skip_matches
    if (tuple(key for key, _ in eth_matches) != eth_skips
            or any(type(rule) is not str or not rule for _, rule in eth_matches)):
        raise StageLConsumerHold("ETH W1 matched-rule provenance is incomplete")
    for endpoints, rule in eth_matches:
        if type(endpoints) is not tuple or len(endpoints) != 4:
            raise StageLConsumerHold("ETH W1 skip is malformed")
        skips.append(StageLSourceSkip("eth_cabling", endpoints, rule))
    for skip in ib.skips:
        skips.append(StageLSourceSkip(
            "ib_cabling", skip.row.expected_endpoints, skip.matched_rule,
        ))
    return ProdStageLSourceProjection(
        cycle_ids=switch.cycle_ids,
        completion_sha256=switch.completion_sha256,
        k_event_sha256=switch.k_event_sha256,
        whitelist_sha256=switch.whitelist_sha256,
        template_sha256=switch.template_sha256,
        candidates=tuple(sorted(candidates, key=lambda item: item.activity_key)),
        whitelist_skips=tuple(sorted(skips, key=lambda item: (
            item.source, item.endpoints or (), item.record_id or "",
        ))),
        hostname_fallback_count=sum(
            item.fabric_source == "hostname-fallback" for item in candidates
        ),
        reason=("fabric_identity_unresolved" if unresolved_fabric
                else "qualification_not_implemented"),
    )


def validate_prod_stage_l_source_projection(
    witness: ProdStageLSourceProjection,
    source: ProdStageLComposedSourceSnapshot, store, *,
    http_root: Path | str, settings: KChainState,
    whitelist_snapshot: WorkbookWhitelistSnapshot,
    whitelist_path: Path | str, writer_token=None,
) -> ProdStageLSourceProjection:
    """Reopen every source; a copied preview is never a C5 freeze token."""
    if (type(witness) is not ProdStageLSourceProjection
            or witness.qualified is not False
            or witness.state != "hold"
            or witness.reason not in {
                "fabric_identity_unresolved", "qualification_not_implemented",
            }):
        raise StageLConsumerHold("Stage L source projection claims authority")
    actual = project_prod_stage_l_source_candidates(
        source, store, http_root=http_root, settings=settings,
        whitelist_snapshot=whitelist_snapshot,
        whitelist_path=whitelist_path, writer_token=writer_token,
    )
    if actual != witness:
        raise StageLConsumerHold("Stage L source projection changed before freeze")
    return actual


def qualify_prod_stage_l(
    store, *, http_root: Path | str, settings: KChainState,
    whitelist_snapshot: WorkbookWhitelistSnapshot,
    whitelist_path: Path | str, writer_token=None,
) -> ProdStageLQualifiedSet:
    """Build an intent-only C5 set after replaying all real prod sources."""
    try:
        root = Path(http_root).resolve(strict=True)
        source = inspect_prod_stage_l_composed_sources(
            store, http_root=root, settings=settings,
            whitelist_snapshot=whitelist_snapshot,
            whitelist_path=whitelist_path, writer_token=writer_token,
        )
        projection = project_prod_stage_l_source_candidates(
            source, store, http_root=root, settings=settings,
            whitelist_snapshot=whitelist_snapshot,
            whitelist_path=whitelist_path, writer_token=writer_token,
        )
        if (projection.qualified is not False
                or any(item.fabric is None or item.fabric_source is None
                       for item in projection.candidates
                       if item.panel == "Switch Status")
                or any(type(skip.matched_rule) is not str
                       or not skip.matched_rule
                       for skip in projection.whitelist_skips)):
            raise StageLConsumerHold("Fabric or W1 matched-rule provenance is incomplete")
        ib = read_prod_ib_k_window(
            store, http_root=root, settings=settings,
            whitelist_snapshot=whitelist_snapshot,
            whitelist_path=whitelist_path, writer_token=writer_token,
        )
        bound_ib = source.switch_ib_source.ib_source
        switch = source.switch_ib_source.switch_source
        eth = source.eth_link_source
        if (ib.qualified is not False
                or ib.cycle_ids != switch.cycle_ids
                or ib.completion_sha256 != switch.completion_sha256
                or ib.cycle_ids != eth.cycle_ids
                or ib.k_event_sha256 != switch.k_event_sha256
                or ib.whitelist_sha256 != switch.whitelist_sha256
                or ib.template_sha256 != switch.template_sha256
                or ib.expected_topology_sha256
                != bound_ib.window.expected_topology_sha256
                or ib.report_sha256 != bound_ib.window.report_sha256s
                or ib.rows != bound_ib.kept_rows
                or not ib.recorded_at_utc
                or any(item.recorded_at_utc != ib.recorded_at_utc
                       for item in projection.candidates)):
            raise StageLConsumerHold("protected IB and three-panel K sources disagree")
        old_ib_skips = tuple(sorted((
            ("ib_cabling", skip.row.expected_endpoints[0],
             skip.row.expected_endpoints[1], skip.row.issue_type),
            skip.matched_rule,
        ) for skip in bound_ib.skips))
        if tuple(sorted(ib.whitelist_skips)) != old_ib_skips:
            raise StageLConsumerHold("protected IB W1 decisions disagree")
        projected_ib_skips = tuple(sorted(
            (skip.endpoints, skip.matched_rule)
            for skip in projection.whitelist_skips if skip.source == "ib_cabling"
        ))
        bound_ib_skips = tuple(sorted(
            (skip.row.expected_endpoints, skip.matched_rule)
            for skip in bound_ib.skips
        ))
        if projected_ib_skips != bound_ib_skips:
            raise StageLConsumerHold("projected IB W1 matched rules disagree")
        switch_windows = tuple(read_prod_switch_k_window(
            store, http_root=root, settings=settings,
            whitelist_snapshot=whitelist_snapshot,
            whitelist_path=whitelist_path, source_slot=slot,
            writer_token=writer_token,
        ) for slot in ("ethernet/prod", "nvlink/prod"))
        projected_switch_skips = tuple(sorted(
            (skip.record_id, skip.matched_rule)
            for skip in projection.whitelist_skips if skip.source == "switch"
        ))
        switch_skip_matches = tuple(sorted(
            item for window in switch_windows
            for item in window.whitelist_skip_matches
        ))
        if projected_switch_skips != switch_skip_matches:
            raise StageLConsumerHold("projected Switch W1 matched rules disagree")
        projected_eth_skips = tuple(sorted(
            (skip.endpoints, skip.matched_rule)
            for skip in projection.whitelist_skips if skip.source == "eth_cabling"
        ))
        if projected_eth_skips != tuple(sorted(eth.whitelist_skip_matches)):
            raise StageLConsumerHold("projected ETH W1 matched rules disagree")
        cycles = read_completed_cycle_evidence(store)
        tail = cycles[-settings.k:]
        if (len(tail) != settings.k
                or tuple(item.cycle_id for item in tail) != switch.cycle_ids
                or len({item.project_key for item in tail}) != 1):
            raise StageLConsumerHold("Stage L project or K window changed")
        candidates = tuple(sorted(projection.candidates,
                                  key=lambda item: item.operation_id))
        skips = tuple(sorted(
            (StageLQualifiedSkip("ib_cabling", rule, activity_key=key)
             for key, rule in ib.whitelist_skips),
            key=lambda item: item.activity_key,
        )) + tuple(
            StageLQualifiedSkip("eth_cabling", rule, endpoints=endpoints)
            for endpoints, rule in projected_eth_skips
        ) + tuple(
            StageLQualifiedSkip("switch", rule, record_id=record_id)
            for record_id, rule in projected_switch_skips
        )
        operations = [{
            "operation_id": item.operation_id,
            "activity_key": list(item.activity_key),
            "action": "upsert",
        } for item in candidates]
        source_body = _canonical_json({
            "cycle_ids": switch.cycle_ids,
            "completion_sha256": switch.completion_sha256,
            "switch_archive_sha256": tuple(
                window.archive_sha256 for window in switch_windows),
            "eth_activity_sha256": eth.activity_sha256,
            "ib_report_sha256": ib.report_sha256,
            "ib_topology_sha256": ib.expected_topology_sha256,
            "k_event_sha256": switch.k_event_sha256,
            "whitelist_sha256": switch.whitelist_sha256,
            "template_sha256": switch.template_sha256,
            "switch_fabric_identities": switch.switch_identities,
        }) + b"\n"
        observations_body = _canonical_json({
            "candidates": [asdict(item) for item in candidates],
            "whitelist_skips": [asdict(item) for item in skips],
            "hostname_fallback_count": projection.hostname_fallback_count,
            "recorded_at_utc": ib.recorded_at_utc,
        }) + b"\n"
        result = ProdStageLQualifiedSet(
            operations_json=_canonical_json(operations),
            candidates=candidates, whitelist_skips=skips,
            cycle_ids=switch.cycle_ids,
            completion_sha256=switch.completion_sha256,
            source_authority_sha256=hashlib.sha256(source_body).hexdigest(),
            observations_sha256=hashlib.sha256(observations_body).hexdigest(),
            k_event_sha256=switch.k_event_sha256,
            whitelist_sha256=switch.whitelist_sha256,
            template_sha256=switch.template_sha256,
            project_key=tail[0].project_key, scope="prod", k=settings.k,
            recorded_at_utc=ib.recorded_at_utc,
        )
        if (validate_prod_stage_l_source_projection(
                projection, source, store, http_root=root, settings=settings,
                whitelist_snapshot=whitelist_snapshot,
                whitelist_path=whitelist_path, writer_token=writer_token,
            ) != projection
                or validate_prod_ib_k_window(
                    ib, store, http_root=root, settings=settings,
                    whitelist_snapshot=whitelist_snapshot,
                    whitelist_path=whitelist_path, writer_token=writer_token,
                ) != ib
                or read_completed_cycle_evidence(store) != cycles):
            raise StageLConsumerHold("Stage L sources changed before qualification")
        return result
    except (OSError, TypeError, KeyError, AttributeError, RuntimeError,
            ValueError) as exc:
        if isinstance(exc, StageLConsumerHold):
            raise
        raise StageLConsumerHold("prod Stage L qualification is unsafe") from exc


def require_complete_stage_l_sources(
    witness: ProdStageLSourceSnapshot, store, *, http_root: Path | str,
    settings: KChainState, whitelist_snapshot: WorkbookWhitelistSnapshot,
    whitelist_path: Path | str, writer_token=None,
) -> None:
    """Do not manufacture an IB receipt from a standalone local report."""
    validate_prod_stage_l_sources(
        witness, store, http_root=http_root, settings=settings,
        whitelist_snapshot=whitelist_snapshot, whitelist_path=whitelist_path,
        writer_token=writer_token,
    )
    raise StageLConsumerHold("IB report is not bound to the completed cycle")
