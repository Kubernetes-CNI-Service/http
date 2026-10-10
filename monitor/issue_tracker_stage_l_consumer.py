"""REQ7 Stage L protected source projection and local qualified intent.

ETH/NVL, IB, and ETH link source readers can be combined against one completed
K window. Source snapshots remain HOLD. Qualification additionally replays a
protected IB producer and all three source readers before building C5 intent;
this module does not create a manifest, workbook, generation, RECEIPT, or
online send permit.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from contextlib import contextmanager, ExitStack
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import stat

from monitor.issue_tracker_cycle_source import read_completed_cycle_evidence
from monitor.issue_tracker_ib_runtime import (
    IbWhitelistedKWindow, ProdIbKWindow, read_prod_ib_k_window,
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


@dataclass(frozen=True)
class StageLSourceFileIdentity:
    """One reopened protected source file, not browser or publish authority."""

    path: str
    recorded_at_utc: str
    sha256: str
    size_bytes: int
    device: int
    inode: int
    mtime_ns: int
    ctime_ns: int


_PANEL_SOURCE_SLOTS = {
    "Switch Status": ("ethernet/prod", "nvlink/prod"),
    "Eth Link Validation": ("ethernet/prod",),
    "IB Link Validation": ("infiniband/prod",),
}


def _bound_source_file(root, relative, expected_sha256):
    """Read exact role bytes and a stable name/FD identity without symlinks."""
    from monitor.issue_tracker_switch_runtime import (
        SwitchRuntimeHoldError, _read_bound, _safe_child,
    )

    if (type(relative) is not str or type(expected_sha256) is not str
            or len(expected_sha256) != 64
            or any(char not in "0123456789abcdef" for char in expected_sha256)):
        raise StageLConsumerHold("protected source role identity is incomplete")
    try:
        path = _safe_child(root, relative)
    except SwitchRuntimeHoldError as exc:
        raise StageLConsumerHold("protected source path is unsafe") from exc
    before = os.stat(path, follow_symlinks=False)
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_size <= 0 or before.st_size > 64 * 1024 * 1024):
        raise StageLConsumerHold("protected source is not a bounded regular file")
    try:
        raw = _read_bound(root, path, maximum=64 * 1024 * 1024)
    except SwitchRuntimeHoldError as exc:
        raise StageLConsumerHold("protected source bytes are unsafe") from exc
    after = os.stat(path, follow_symlinks=False)
    identity = lambda item: (item.st_dev, item.st_ino, item.st_size,
                             item.st_mtime_ns, item.st_ctime_ns)
    if (identity(before) != identity(after)
            or hashlib.sha256(raw).hexdigest() != expected_sha256):
        raise StageLConsumerHold("protected source changed during identity read")
    return StageLSourceFileIdentity(
        relative,
        datetime.fromtimestamp(before.st_mtime, timezone.utc).isoformat(
            timespec="microseconds").replace("+00:00", "Z"),
        expected_sha256, before.st_size, before.st_dev, before.st_ino,
        before.st_mtime_ns, before.st_ctime_ns,
    )


def read_prod_stage_l_panel_source_files(
    qualified, store, *, panel, http_root, settings,
    whitelist_snapshot, whitelist_path, writer_token=None,
):
    """Reopen the selected panel's completed K source roles or HOLD.

    The result is an internal prerequisite only.  It omits workbook
    new/update/skip classification and must not be surfaced as a complete
    manual preview or used to enable confirmation.
    """
    from monitor.collection_ib_cycle_binding import (
        inspect_completed_ib_cycle_roles,
    )
    from monitor.issue_tracker_ib_runtime import read_completed_ib_cycle_report
    from monitor.issue_tracker_switch_runtime import (
        _private_json, read_prod_eth_activity_cycle_source,
        read_prod_switch_cycle_source,
    )

    try:
        if (type(qualified) is not ProdStageLQualifiedSet
                or qualified.qualified is not True
                or type(panel) is not str or panel not in _PANEL_SOURCE_SLOTS):
            raise StageLConsumerHold("selected panel has no protected source authority")
        root = Path(http_root).resolve(strict=True)
        arguments = dict(http_root=root, settings=settings,
                         whitelist_snapshot=whitelist_snapshot,
                         whitelist_path=whitelist_path,
                         writer_token=writer_token)
        if qualify_prod_stage_l(store, **arguments) != qualified:
            raise StageLConsumerHold("selected panel qualification changed before source read")
        cycles = read_completed_cycle_evidence(store)
        tail = cycles[-settings.k:]
        if (len(tail) != settings.k
                or tuple(item.cycle_id for item in tail) != qualified.cycle_ids):
            raise StageLConsumerHold("selected panel K source identity changed")
        result = []
        for cycle in tail:
            area = (root / "monitor/status/collection-cycles" / cycle.project_key
                    / "prod/switch_collection/artifacts" / f"{cycle.sequence:020d}")
            if panel == "Switch Status":
                for slot in _PANEL_SOURCE_SLOTS[panel]:
                    source = read_prod_switch_cycle_source(
                        store, http_root=root, sequence=cycle.sequence,
                        source_slot=slot,
                    )
                    evidence, _ = _private_json(
                        root, area / slot.replace("/", "-") /
                        "evidence-manifest.json",
                    )
                    roles = evidence.get("roles")
                    role = roles[0] if type(roles) is list and roles else None
                    if (type(role) is not dict or role.get("role") != "info_archive"
                            or role.get("state") != "present"
                            or role.get("sha256") != source.preview.archive_sha256):
                        raise StageLConsumerHold("Switch info role differs from protected reader")
                    result.append(_bound_source_file(
                        root, role.get("relative_path"), role["sha256"],
                    ))
                    if read_prod_switch_cycle_source(
                            store, http_root=root, sequence=cycle.sequence,
                            source_slot=slot) != source:
                        raise StageLConsumerHold("Switch source changed after file read")
            elif panel == "Eth Link Validation":
                source = read_prod_eth_activity_cycle_source(
                    store, http_root=root, sequence=cycle.sequence,
                )
                relative = (area / "ethernet-prod/activity-observation.json"
                            ).relative_to(root).as_posix()
                result.append(_bound_source_file(
                    root, relative, source.activity_sha256,
                ))
                if read_prod_eth_activity_cycle_source(
                        store, http_root=root, sequence=cycle.sequence) != source:
                    raise StageLConsumerHold("ETH activity changed after file read")
            else:
                role = inspect_completed_ib_cycle_roles(
                    store, http_root=root, sequence=cycle.sequence,
                )
                source = read_completed_ib_cycle_report(
                    store, http_root=root, sequence=cycle.sequence,
                )
                if (role.report_sha256 != source.report_sha256
                        or role.cycle_id != cycle.cycle_id):
                    raise StageLConsumerHold("IB report role differs from protected reader")
                result.append(_bound_source_file(
                    root, role.report_relative_path, role.report_sha256,
                ))
                if (inspect_completed_ib_cycle_roles(
                        store, http_root=root, sequence=cycle.sequence) != role
                        or read_completed_ib_cycle_report(
                            store, http_root=root, sequence=cycle.sequence) != source):
                    raise StageLConsumerHold("IB source changed after file read")
        if (not result or len({item.path for item in result}) != len(result)
                or qualify_prod_stage_l(store, **arguments) != qualified
                or read_completed_cycle_evidence(store) != cycles):
            raise StageLConsumerHold("selected panel source changed before readback")
        return tuple(result)
    except (OSError, TypeError, KeyError, AttributeError, RuntimeError,
            ValueError) as exc:
        if isinstance(exc, StageLConsumerHold):
            raise
        raise StageLConsumerHold("selected panel source identity is unsafe") from exc


def validate_prod_stage_l_panel_source_files(
    witness, qualified, store, *, panel, http_root, settings,
    whitelist_snapshot, whitelist_path, writer_token=None,
):
    """Require byte, path and timestamp identity on a fresh protected read."""
    if (type(witness) is not tuple or not witness
            or any(type(item) is not StageLSourceFileIdentity for item in witness)):
        raise StageLConsumerHold("selected panel source witness is invalid")
    actual = read_prod_stage_l_panel_source_files(
        qualified, store, panel=panel, http_root=http_root, settings=settings,
        whitelist_snapshot=whitelist_snapshot, whitelist_path=whitelist_path,
        writer_token=writer_token,
    )
    if actual != witness:
        raise StageLConsumerHold("selected panel source file changed; preview again")
    return actual


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


def _observe_prod_stage_l_switch_sources(
    store, *, http_root: Path | str, settings: KChainState,
    whitelist_snapshot: WorkbookWhitelistSnapshot,
    whitelist_path: Path | str, writer_token=None,
) -> ProdStageLSourceSnapshot:
    """Observe one fresh, HOLD-only leg for both real Switch families.

    The enclosing inspector must reopen this leg after its other domains.
    No file bytes or caller-supplied freshness witness are reused here.
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
        if read_completed_cycle_evidence(store) != cycles:
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


def inspect_prod_stage_l_sources(
    store, *, http_root: Path | str, settings: KChainState,
    whitelist_snapshot: WorkbookWhitelistSnapshot,
    whitelist_path: Path | str, writer_token=None,
) -> ProdStageLSourceSnapshot:
    """Compare two independently reopened Switch-family legs, still HOLD.

    Standalone inspection retains its own start/end boundary. Composition
    places these same fresh observations around the other real domains.
    """
    args = dict(http_root=http_root, settings=settings,
                whitelist_snapshot=whitelist_snapshot,
                whitelist_path=whitelist_path, writer_token=writer_token)
    source = _observe_prod_stage_l_switch_sources(store, **args)
    if _observe_prod_stage_l_switch_sources(store, **args) != source:
        raise StageLConsumerHold("prod Stage L source changed during read")
    return source


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


def _observe_prod_stage_l_bound_sources(
    store, *, http_root: Path | str, settings: KChainState,
    whitelist_snapshot: WorkbookWhitelistSnapshot,
    whitelist_path: Path | str, writer_token=None,
) -> ProdStageLBoundSourceSnapshot:
    """One fresh, HOLD-only Switch/IB leg, not a validated composite.

    The enclosing inspector must observe this leg again after its other
    domains. No file, semantic result or caller witness is reused here.
    """
    try:
        root = Path(http_root).resolve(strict=True)
        source = _observe_prod_stage_l_switch_sources(
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
        return ProdStageLBoundSourceSnapshot(source, ib)
    except (OSError, TypeError, AttributeError, RuntimeError, ValueError) as exc:
        if isinstance(exc, StageLConsumerHold):
            raise
        raise StageLConsumerHold("prod Switch/IB source evidence is unsafe") from exc


def inspect_prod_stage_l_bound_sources(
    store, *, http_root: Path | str, settings: KChainState,
    whitelist_snapshot: WorkbookWhitelistSnapshot,
    whitelist_path: Path | str, writer_token=None,
) -> ProdStageLBoundSourceSnapshot:
    """Reopen Switch/IB on both sides of a standalone binding inspection.

    Composition instead places these same two fresh legs around ETH; calling
    this complete two-leg inspector inside each leg recursively duplicates
    the entire observation without adding a cross-domain boundary.
    """
    args = dict(http_root=http_root, settings=settings,
                whitelist_snapshot=whitelist_snapshot,
                whitelist_path=whitelist_path, writer_token=writer_token)
    source = _observe_prod_stage_l_bound_sources(store, **args)
    if _observe_prod_stage_l_bound_sources(store, **args) != source:
        raise StageLConsumerHold("prod Switch/IB source changed during read")
    return source


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
        switch_ib = _observe_prod_stage_l_bound_sources(
            store, http_root=root, settings=settings,
            whitelist_snapshot=whitelist_snapshot,
            whitelist_path=whitelist_path, writer_token=writer_token,
        )
        eth_link = read_prod_eth_activity_k_window(
            store, http_root=root, settings=settings,
            whitelist_snapshot=whitelist_snapshot,
            whitelist_path=whitelist_path, writer_token=writer_token,
            normalized_active_keys=True,
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
        if (_observe_prod_stage_l_bound_sources(
                store, http_root=root, settings=settings,
                whitelist_snapshot=whitelist_snapshot,
                whitelist_path=whitelist_path, writer_token=writer_token,
            ) != switch_ib or read_prod_eth_activity_k_window(
                store, http_root=root, settings=settings,
                whitelist_snapshot=whitelist_snapshot,
                whitelist_path=whitelist_path, writer_token=writer_token,
                normalized_active_keys=True,
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
    return _project_observed_stage_l_source_candidates(
        source, store, http_root=http_root, settings=settings,
        whitelist_snapshot=whitelist_snapshot, whitelist_path=whitelist_path,
        writer_token=writer_token,
    )


def _project_observed_stage_l_source_candidates(
    source, store, *, http_root, settings, whitelist_snapshot,
    whitelist_path, writer_token=None,
):
    """Project an observed HOLD snapshot, not provenance or qualification.

    The public preview still reopens its caller's sources. Native qualification
    instead uses its own just-observed snapshot and retains the full public
    projection/source replay at its final boundary. This removes a redundant
    recursive walk, without caching paths, accepting a caller witness as C5,
    relaxing read freshness, or omitting the final IB and cycle-chain checks.
    Switch matched-rule inputs below are still reopened and compared.
    """
    if (type(source) is not ProdStageLComposedSourceSnapshot
            or source.qualified is not False or source.state != 'hold'
            or source.reason != 'qualification_not_implemented'):
        raise StageLConsumerHold('observed projection has no HOLD source snapshot')
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
        projection = _project_observed_stage_l_source_candidates(
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
        bound_ib = source.switch_ib_source.ib_source
        switch = source.switch_ib_source.switch_source
        eth = source.eth_link_source
        # The native composed inspector has just reopened protected IB/W1 on
        # both sides of ETH. Project that actual observation here rather than
        # recursively rereading the same intermediate window. This is not a
        # caller witness or a cached qualification: the independent public
        # IB validator, full projection replay and cycle checks below remain
        # the last return boundary, including drift and original deadlines.
        ib = ProdIbKWindow(
            cycle_ids=bound_ib.window.cycle_ids,
            completion_sha256=switch.completion_sha256,
            report_sha256=bound_ib.window.report_sha256s,
            expected_topology_sha256=bound_ib.window.expected_topology_sha256,
            rows=bound_ib.kept_rows,
            whitelist_skips=tuple((
                ('ib_cabling', skip.row.expected_endpoints[0],
                 skip.row.expected_endpoints[1], skip.row.issue_type),
                skip.matched_rule,
            ) for skip in bound_ib.skips),
            k_event_sha256=switch.k_event_sha256,
            whitelist_sha256=bound_ib.whitelist_sha256,
            template_sha256=bound_ib.workbook_sha256,
            recorded_at_utc=bound_ib.window.recorded_at_utc,
        )
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


@contextmanager
def _hold_original_replay_inputs(store, project, whitelist_path):
    """Hold the FULL current worker chain and fixed policy/W1 input names.

    Historical projection does not exempt later cycles or accept same-byte
    replacement. Reopen each absolute parent without aliases, and retain the
    original descriptor, stat and bytes through the entire native replay.
    """
    from monitor.issue_tracker_local_commit import _flags, _open_absolute_directory, _check
    from monitor.issue_tracker_attempt_journal import _identity

    with ExitStack() as stack:
        parents, files = {}, []
        records = Path(store.records_dir)

        def directory_identity(info):
            return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)

        # Pin the directory BEFORE observing its namespace. A path-based first
        # list followed by a reopen could silently adopt a same-byte replacement.
        record_parent = _open_absolute_directory(records)
        stack.callback(os.close, record_parent)
        record_info = _check(record_parent, directory=True, private=False)
        parents[records] = (record_parent, directory_identity(record_info))
        record_identity = _identity(record_info)
        record_names = frozenset(os.listdir(record_parent))
        paths = [(Path(store.witness_path), 16 * 1024 * 1024)]
        paths += [(records / name, 16 * 1024 * 1024) for name in sorted(record_names)]
        paths += [(project / '01-global.yaml', 1024 * 1024),
                  (Path(whitelist_path), 32 * 1024 * 1024)]

        for path, limit in paths:
            if path.parent not in parents:
                parent = _open_absolute_directory(path.parent)
                stack.callback(os.close, parent)
                info = _check(parent, directory=True, private=False)
                parents[path.parent] = (parent, directory_identity(info))
            parent = parents[path.parent][0]
            fd = os.open(path.name, _flags(), dir_fd=parent)
            stack.callback(os.close, fd)
            info = _check(fd, directory=False, private=False)
            if not 0 < info.st_size <= limit:
                raise StageLConsumerHold('original replay input exceeds its bounded contract')
            raw = os.pread(fd, limit + 1, 0)
            if len(raw) != info.st_size:
                raise StageLConsumerHold('original replay input changed during read')
            files.append((parent, path.name, fd, _identity(info), raw))

        def verify():
            store._require_gate()
            for path, (fd, identity) in parents.items():
                current = _open_absolute_directory(path)
                try:
                    if (directory_identity(os.fstat(fd)) != identity
                            or directory_identity(os.fstat(current)) != identity):
                        raise StageLConsumerHold('original replay input parent was replaced')
                finally:
                    os.close(current)
            if frozenset(os.listdir(parents[records][0])) != record_names:
                raise StageLConsumerHold('current worker record namespace changed')
            if _identity(os.fstat(record_parent)) != record_identity:
                raise StageLConsumerHold('current worker record namespace changed and was restored')
            for parent, name, fd, identity, raw in files:
                if (_identity(os.fstat(fd)) != identity
                        or _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != identity
                        or os.pread(fd, len(raw) + 1, 0) != raw):
                    raise StageLConsumerHold('original replay input identity or bytes changed')
            store._require_gate()

        verify()
        yield verify
        verify()


def _require_original_source_projection(source, qualified):
    """Exact C5 projection only; callers must first replay the real native source.

    Manual C6 preserves all protected source digests, but its W1 decisions and
    evaluation labels belong only to the selected panel. Never filter or mint
    a native qualified set here; this comparison grants no receipt or permit.
    """
    from monitor.issue_tracker_manifest import _runtime_skip, _RUNTIME_PANELS
    try:
        if (type(source) is not dict or type(qualified) is not ProdStageLQualifiedSet
                or qualified.qualified is not True
                or qualified.mode != 'prod-runtime-protected-v1'):
            raise StageLConsumerHold('original native source projection is invalid')
        skips = [_runtime_skip(item) for item in qualified.whitelist_skips]
        panel = source.get('selected_panel')
        if 'selected_panel' in source:
            if type(panel) is not str or panel not in _RUNTIME_PANELS.values():
                raise StageLConsumerHold('original manual panel is invalid')
            skips = [item for item in skips if _RUNTIME_PANELS[item['source']] == panel]
        expected = {
            'cycle_ids':list(qualified.cycle_ids),
            'completion_sha256':list(qualified.completion_sha256),
            'source_authority_sha256':qualified.source_authority_sha256,
            'observations_sha256':qualified.observations_sha256,
            'k_event_sha256':qualified.k_event_sha256,
            'whitelist_sha256':qualified.whitelist_sha256,
            'project_key':qualified.project_key, 'scope':qualified.scope,
            'mode':qualified.mode, 'k':qualified.k,
            'recorded_at_utc':qualified.recorded_at_utc, 'whitelist_skips':skips,
        }
        if 'selected_panel' in source:
            expected['selected_panel'] = panel
            expected['panel_evaluation'] = {
                name: ({'state':'evaluated','whitelist_skips':
                    'skips-present' if skips else 'no-skips'} if name == panel
                    else {'state':'not-evaluated-in-this-manifest'})
                for name in _RUNTIME_PANELS.values()}
        if type(source.get('k')) is not int or source != expected:
            raise StageLConsumerHold('native replay differs from original C6 source projection')
    except (TypeError, KeyError, AttributeError, ValueError) as exc:
        if isinstance(exc, StageLConsumerHold):
            raise
        raise StageLConsumerHold('original source projection is unsafe') from exc


def replay_original_receipted_prod_source(
    store, *, http_root, settings, whitelist_snapshot, whitelist_path,
    expected_template_sha256, local_generation_id, writer_token,
) -> ProdStageLQualifiedSet:
    """Requalify ONE actual older admitted C6 against its original K window.

    No caller cutoff or historical source snapshot is accepted. The private
    revoked store view is used only for native C5 requalification; history,
    recovery and current cadence always consume the complete real store. This
    returns intent, not R2 eligibility, a retry count, a new receipt or a permit.
    """
    from monitor import issue_tracker_receipt_snapshot as receipts
    from monitor.issue_tracker_whitelist_workbook import read_whitelist_workbook
    from tools.project_contract import collection_cycle_project_key

    active = False
    try:
        owner = _owner(writer_token)
        project = Path(store.project_identity)
        root = Path(http_root)
        key = collection_cycle_project_key(str(project))
        status = root / 'monitor/status'
        cycle_dir = status / 'collection-cycles' / key / 'prod/switch_collection'
        if (not root.is_absolute() or root.resolve(strict=True) != root
                or owner.project != project
                or owner.publication != project / '99-output-monitor'
                or store.scope != 'prod' or store.project_key != key
                or Path(store.root_status_dir) != status
                or Path(store.records_dir) != cycle_dir / 'records'
                or Path(store.witness_path) != cycle_dir / 'high-water.json'
                or type(settings) is not KChainState or current_k(writer_token) != settings
                or type(whitelist_snapshot) is not WorkbookWhitelistSnapshot
                or expected_template_sha256 != whitelist_snapshot.workbook_sha256
                or read_whitelist_workbook(whitelist_path) != whitelist_snapshot
                or type(local_generation_id) is not str
                or receipts._GEN.fullmatch(local_generation_id) is None):
            raise StageLConsumerHold('original replay owner, path, K or W1 is unproved')
        arguments = dict(http_root=root, settings=settings,
                         whitelist_snapshot=whitelist_snapshot,
                         whitelist_path=whitelist_path, writer_token=writer_token)
        with receipts._hold_history_originals(writer_token) as original_guard:
            with _hold_original_replay_inputs(store, project, whitelist_path) as input_guard:
                cycles = read_completed_cycle_evidence(store)
                events = receipts._events(owner)
                selected = tuple(e for e in events if e['generation_id'] == local_generation_id)
                if len(selected) != 1:
                    raise StageLConsumerHold('original C6 has no unique actual admission')
                event = selected[0]
                template, source = receipts._manifest_source(owner, local_generation_id)
                receipts._validate_source(source, event, cycles, receipts._k_events(owner),
                    template_sha256=template, expected_template_sha256=expected_template_sha256,
                    settings=settings, whitelist_sha256=whitelist_snapshot.whitelist.sha256,
                    qualified_source=None)
                if (not cycles or event['cycle_id'] == cycles[-1].cycle_id
                        or source['k'] != settings.k
                        or source['k_event_sha256'] != settings.event_sha256
                        or source['whitelist_sha256'] != whitelist_snapshot.whitelist.sha256):
                    raise StageLConsumerHold('older C6 does not match the current K/W1 contract')
                cutoff = next(c.sequence for c in cycles if c.cycle_id == event['cycle_id'])
                groups = store._record_groups()
                history_context = dict(expected_template_sha256=expected_template_sha256,
                    settings=settings, whitelist_sha256=whitelist_snapshot.whitelist.sha256)
                # A later current-cycle C6 still needs its own native replay.
                if any(e['cycle_id'] == cycles[-1].cycle_id for e in events):
                    history_context['qualified_source'] = qualify_prod_stage_l(store, **arguments)
                history = receipts.read_local_receipt_history(writer_token, store, **history_context)
                if sum(r.generation_id == local_generation_id for r in history.receipts) != 1:
                    raise StageLConsumerHold('original C6 recovery is unproved')
                original_guard()
                input_guard()
                active = True

                def guard():
                    if not active:
                        raise StageLConsumerHold('original replay view has expired')
                    if _owner(writer_token) is not owner:
                        raise StageLConsumerHold('original replay owner changed')
                    store._require_gate()
                    # Full settings/worker/W1 originals remain descriptor-pinned
                    # across this synchronous native walk. Reparse K and verify
                    # every original at its return boundary, not for each of the
                    # thousands of internal record-access calls. Native source
                    # readers still re-read and validate their actual bytes.

                class OriginalWindow:
                    project_identity = store.project_identity
                    project_key = store.project_key
                    scope = store.scope
                    root_status_dir = store.root_status_dir
                    records_dir = store.records_dir

                    def _require_gate(self):
                        guard()

                    def _read_witness(self):
                        guard()
                        return cutoff

                    def _record_groups(self):
                        guard()
                        return {n: dict(groups[n]) for n in range(1, cutoff + 1)}

                    def _path(self, sequence, kind):
                        guard()
                        if type(sequence) is not int or not 1 <= sequence <= cutoff:
                            raise StageLConsumerHold('sequence is outside the original admitted window')
                        return groups[sequence][kind]

                    def start_path(self, sequence):
                        return self._path(sequence, 'start')

                    def launch_path(self, sequence):
                        return self._path(sequence, 'launch')

                    def completion_path(self, sequence):
                        return self._path(sequence, 'completion')

                    def _validate_start_record(self, *args):
                        guard()
                        return store._validate_start_record(*args)

                    def _validate_launch_record(self, *args):
                        guard()
                        return store._validate_launch_record(*args)

                    def _validate_completion_record(self, *args):
                        guard()
                        return store._validate_completion_record(*args)

                try:
                    input_guard()
                    original_guard()
                    window = OriginalWindow()
                    from monitor import issue_tracker_cycle_source as cycle_source
                    held = cycle_source._HELD_CYCLE_REPLAY.get()
                    window_key = None
                    try:
                        if held is not None and held[0] is store:
                            # The cutoff comes only from the actual admitted C6.
                            # Reuse only inside this synchronous private native
                            # walk, backed by the complete current worker scope.
                            def verify_window():
                                guard()
                                held[1]()
                            verify_window()
                            original_cycles = cycle_source._read_completed_cycle_evidence(window)
                            verify_window()
                            expected_cycles = tuple(c for c in cycles if c.sequence <= cutoff)
                            if held[2] != cycles or original_cycles != expected_cycles:
                                raise StageLConsumerHold('private original window differs from held worker chain')
                            window_key = cycle_source._HELD_CYCLE_REPLAY.set(
                                (window, verify_window, original_cycles))
                        result = qualify_prod_stage_l(window, **arguments)
                    finally:
                        # Restore the full current chain before history/recovery
                        # checks. No prefix escapes or survives this native call.
                        if window_key is not None:
                            cycle_source._HELD_CYCLE_REPLAY.reset(window_key)
                    _require_original_source_projection(source, result)
                    if (type(result) is not ProdStageLQualifiedSet or result.qualified is not True
                            or result.template_sha256 != template
                            or read_completed_cycle_evidence(store) != cycles
                            or receipts.read_local_receipt_history(writer_token, store, **history_context) != history
                            or read_whitelist_workbook(whitelist_path) != whitelist_snapshot):
                        raise StageLConsumerHold('original replay chain changed before return')
                    guard()
                    if current_k(writer_token) != settings:
                        raise StageLConsumerHold('original replay K changed before return')
                    input_guard()
                    original_guard()
                finally:
                    active = False
        return result
    except (OSError, TypeError, KeyError, IndexError, AttributeError, RuntimeError, ValueError) as exc:
        if isinstance(exc, StageLConsumerHold):
            raise
        raise StageLConsumerHold('original receipted source replay is unsafe') from exc
    finally:
        active = False


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
