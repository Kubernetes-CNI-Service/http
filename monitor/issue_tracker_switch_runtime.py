"""Fail-closed, read-only ETH Switch status window from worker-owned cycles.

This Stage-L preview never constructs a QualifiedSet, a workbook mutation, or
an online send authority. A missing dynamic selected-target witness is a HOLD.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

from monitor.issue_tracker_cycle_source import (
    CycleSourceHoldError, _read_record, read_completed_cycle_evidence,
)
from monitor.issue_tracker_activity_source import (
    EthActivityEvidence, EthLinkObservation, load_eth_activity_evidence,
    validate_worker_eth_activity_context,
)
from monitor.issue_tracker_topology_derivation import (
    TopologyDerivationWitness, verify_lldpq_derivation,
)
from monitor.issue_tracker_k_chain import KChainState, assess_k_window
from monitor.issue_tracker_local_commit import _owner
from monitor.issue_tracker_state_owner import current_k, tracker_writer
from monitor.issue_tracker_switch_info_source import (
    SwitchInfoPreview, SwitchSourceRow, map_switch_source_rows,
    read_switch_info_preview,
)
from monitor.issue_tracker_whitelist import evaluate_whitelist
from monitor.issue_tracker_whitelist_workbook import (
    WorkbookWhitelistSnapshot, read_whitelist_workbook,
)


class SwitchRuntimeHoldError(ValueError):
    """A worker cycle cannot establish this bounded Switch status preview."""


def _require_prod_k(project, settings, writer_token):
    """Read K under the caller's active LK-P token or one short owned lock."""
    publication = project / "99-output-monitor"
    if writer_token is None:
        with tracker_writer(project, publication) as token:
            actual = current_k(token)
    else:
        owner = _owner(writer_token)
        if owner.project != project or owner.publication != publication:
            raise SwitchRuntimeHoldError("prod K writer does not own this project")
        actual = current_k(writer_token)
    if actual != settings:
        raise SwitchRuntimeHoldError("prod K setting drifted")


@dataclass(frozen=True)
class SwitchRuntimeWindow:
    cycle_ids: tuple[str, ...]
    persistent_keys: tuple[tuple[str, str, str], ...]
    qualified: bool = False


@dataclass(frozen=True)
class SwitchRuntimeSourceWitness:
    """Source-bound Stage-L input, never itself a publication authority.

    The caller must revalidate this witness at the operation freeze.  Its
    digests and mode cannot be supplied by an operator as qualification.
    """

    cycle_ids: tuple[str, ...]
    project_key: str
    source_slots: tuple[str, ...]
    completion_sha256: tuple[str, ...]
    info_sha256: tuple[str, ...]
    activity_sha256: tuple[str, ...]
    switch_persistent_keys: tuple[tuple[str, str, str], ...]
    eth_links_by_cycle: tuple[tuple[EthLinkObservation, ...], ...]
    eth_endpoints: tuple[tuple[str, str, str, str], ...]
    eth_whitelist_skips: tuple[tuple[str, str, str, str], ...]
    eth_whitelist_matches: tuple[tuple[tuple[str, str, str, str], str], ...]
    k_event_sha256: str
    whitelist_sha256: str
    template_sha256: str
    qualified: bool = False


@dataclass(frozen=True)
class ProdSwitchCycleSource:
    """One real prod worker/emitter Switch source, never a K-qualified set."""

    cycle_id: str
    sequence: int
    completion_sha256: str
    preview: SwitchInfoPreview
    rows: tuple[SwitchSourceRow, ...]
    qualified: bool = False
    fabric_identities: tuple[tuple[str, str, str], ...] = ()


@dataclass(frozen=True)
class ProdEthActivityCycleSource:
    """One prod ETH link source; no K, C5/C6 or publication authority."""

    cycle_id: str
    sequence: int
    completion_sha256: str
    activity_sha256: str
    links: tuple[EthLinkObservation, ...]
    derivation: TopologyDerivationWitness | None
    qualified: bool = False


@dataclass(frozen=True)
class ProdEthActivityKWindow:
    """Per-value ETH activity intersection with local W1; not an issue set."""

    cycle_ids: tuple[str, ...]
    completion_sha256: tuple[str, ...]
    activity_sha256: tuple[str, ...]
    persistent_links: tuple[EthLinkObservation, ...]
    whitelist_skips: tuple[tuple[str, str, str, str], ...]
    k_event_sha256: str
    whitelist_sha256: str
    template_sha256: str
    qualified: bool = False
    whitelist_skip_matches: tuple[tuple[tuple[str, str, str, str], str], ...] = ()


@dataclass(frozen=True)
class ProdEthIssueSourceRow:
    """Typed analyzer-sheet interpretation, never a C5 operation."""

    observation: EthLinkObservation
    source_sheet: str
    issue_type: str
    qualified: bool = False


@dataclass(frozen=True)
class ProdSwitchKWindow:
    """Bound ETH or NVL source intersection, not a publication QualifiedSet.

    IB and per-value issue evidence are not yet represented here. Even a full
    window is only an observed source; it cannot create a manifest or receipt.
    """

    source_slot: str
    cycle_ids: tuple[str, ...]
    completion_sha256: tuple[str, ...]
    selected_hosts: tuple[str, ...]
    persistent_keys: tuple[tuple[str, str, str], ...]
    archive_sha256: tuple[str, ...]
    whitelist_skips: tuple[str, ...]
    k_event_sha256: str
    whitelist_sha256: str
    template_sha256: str
    qualified: bool = False
    whitelist_skip_matches: tuple[tuple[str, str], ...] = ()


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def _pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise SwitchRuntimeHoldError("duplicate sidecar JSON key")
        value[key] = item
    return value


def _safe_child(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise SwitchRuntimeHoldError("artifact path is not canonical relative")
    pure = PurePosixPath(relative)
    if (pure.is_absolute() or str(pure) != relative
            or any(part in {"", ".", ".."} for part in relative.split("/"))):
        raise SwitchRuntimeHoldError("artifact path is not canonical relative")
    path = root
    for part in pure.parts:
        path = path / part
        if path.is_symlink():
            raise SwitchRuntimeHoldError("artifact path crosses a symlink")
    return path


def _read_bound(root: Path, path: Path, *, maximum: int) -> bytes:
    try:
        relative = path.relative_to(root).as_posix()
        path = _safe_child(root, relative)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                             | getattr(os, "O_NOFOLLOW", 0))
        try:
            before = os.fstat(descriptor)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_size < 0 or before.st_size > maximum):
                raise SwitchRuntimeHoldError("artifact is not a bounded regular file")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                raw = stream.read(maximum + 1)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        named = os.stat(path, follow_symlinks=False)
        identity = lambda st: (st.st_dev, st.st_ino, st.st_size,
                               st.st_mtime_ns, st.st_ctime_ns)
        if (len(raw) != before.st_size or len(raw) > maximum
                or identity(before) != identity(after)
                or identity(before) != identity(named)):
            raise SwitchRuntimeHoldError("artifact changed while read")
        return raw
    except (OSError, ValueError) as exc:
        if isinstance(exc, SwitchRuntimeHoldError):
            raise
        raise SwitchRuntimeHoldError("artifact is unreadable or outside the root") from exc


def _private_json(root: Path, path: Path) -> tuple[dict, bytes]:
    raw = _read_bound(root, path, maximum=1024 * 1024)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=lambda _value: (_ for _ in ()).throw(
                               SwitchRuntimeHoldError("nonfinite sidecar scalar")))
        if not isinstance(value, dict) or raw != _canonical(value):
            raise SwitchRuntimeHoldError("sidecar is not canonical JSON")
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        if isinstance(exc, SwitchRuntimeHoldError):
            raise
        raise SwitchRuntimeHoldError("sidecar JSON is invalid") from exc
    return value, raw


def _digest(raw: bytes) -> dict[str, object]:
    return {"sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)}


def _static_air_hosts(inventory: bytes) -> tuple[tuple[str, ...], dict, str]:
    try:
        text = inventory.decode("utf-8")
        reader = csv.DictReader(io.StringIO(text), strict=True)
        header = reader.fieldnames
        if (header is None or len(header) != len(set(header))
                or not {"hostname", "type", "eth0_ip"}.issubset(header)):
            raise SwitchRuntimeHoldError("frozen inventory header is invalid")
        selected = []
        for row in reader:
            if None in row or any(value is None for value in row.values()):
                raise SwitchRuntimeHoldError("frozen inventory row is malformed")
            if row["type"].strip().casefold() != "air":
                continue
            host, ip = row["hostname"].strip(), row["eth0_ip"].strip()
            if not _HOST.fullmatch(host) or not ip:
                raise SwitchRuntimeHoldError("frozen selected host is invalid")
            ipaddress.IPv4Address(ip)
            selected.append((host, ip))
        names = tuple(host for host, _ip in selected)
        if not names or len({name.casefold() for name in names}) != len(names):
            raise SwitchRuntimeHoldError("frozen selected host set is empty or ambiguous")
        plan = {"eth": [f"{host}|{ip}" for host, ip in selected],
                "spx": [], "ib": [], "nv": [], "dynamic_identities": []}
        return names, plan, hashlib.sha256(_canonical(plan)).hexdigest()
    except (csv.Error, UnicodeError, TypeError, ValueError) as exc:
        if isinstance(exc, SwitchRuntimeHoldError):
            raise
        raise SwitchRuntimeHoldError("frozen static AIR selection is invalid") from exc


def _fourth_activity(
    root: Path, area: Path, slot: Path, identity: dict,
    inventory_sha: str, plan: dict, static_plan_sha: str,
    info: dict, envelope: dict, role: dict,
) -> EthActivityEvidence:
    """Rebuild the one static worker context; caller context is never trusted."""
    expected_relative = (slot / "activity-observation.json").relative_to(root).as_posix()
    if (not isinstance(role, dict) or set(role) != {
            "role", "state", "relative_path", "sha256", "size_bytes"
        } or role["role"] != "activity_observation" or role["state"] != "present"
            or role["relative_path"] != expected_relative
            or not isinstance(role["sha256"], str) or not _SHA.fullmatch(role["sha256"])
            or isinstance(role["size_bytes"], bool)
            or not isinstance(role["size_bytes"], int)
            or role["size_bytes"] <= 0 or role["size_bytes"] > 16 * 1024 * 1024):
        raise SwitchRuntimeHoldError("fourth role is not the private activity sidecar")
    private = _safe_child(root, expected_relative)
    if _digest(_read_bound(root, private, maximum=16 * 1024 * 1024)) != {
        "sha256": role["sha256"], "size_bytes": role["size_bytes"],
    }:
        raise SwitchRuntimeHoldError("fourth role bytes disagree with worker role")
    inputs = area / "inputs"
    frozen = {
        "topology": ("p2p.xlsx", 64 * 1024 * 1024),
        "dot": ("dot", 16 * 1024 * 1024),
        "inventory": ("lldp-inventory.log", 4 * 1024 * 1024),
        "device_aliases": ("aliases.json", 4 * 1024 * 1024),
    }
    sources = {}
    for name, (suffix, limit) in frozen.items():
        path = inputs / f"ethernet-air.{suffix}"
        sources[name] = {
            "path": str(path),
            "sha256": hashlib.sha256(_read_bound(root, path, maximum=limit)).hexdigest(),
        }
    activity = {
        "schema_version": 1, "source_slot": "ethernet/air",
        "topology": sources["topology"],
        "sources": {name: sources[name] for name in (
            "dot", "inventory", "device_aliases")},
        "sidecar_path": str(inputs / "ethernet-air.activity.json"),
    }
    context = {
        "identity": identity, "source_slot": "ethernet/air",
        "artifacts": {
            "evidence": str(slot / "evidence-manifest.json"),
            "envelope": str(slot / "identity-envelope.json"),
            "input_inventory": str(inputs / "ethernet-air.csv"),
        },
        "input_inventory_sha256": inventory_sha,
        "air_dynamic_rows": [], "prod_runtime_rows": [],
        "runtime_input_hashes": {},
        "target_plan": plan, "target_plan_sha256": static_plan_sha,
        "activity": activity,
    }
    binding = validate_worker_eth_activity_context(context)
    if (binding["context_sha256"] != envelope["activity_context_sha256"]
            or binding["identity"] != identity
            or binding["source_slot"] != "ethernet/air"):
        raise SwitchRuntimeHoldError("activity context cannot be rebuilt from frozen files")
    archive = _safe_child(root, info["relative_path"])
    report = (root / "tools/lldp-analyze-tool/99-output-p2p"
              / (archive.name.removesuffix(".tar.gz")
                 + "-ethernet-topology-validation.xlsx"))
    report = _safe_child(root, report.relative_to(root).as_posix())
    evidence = load_eth_activity_evidence(
        private,
        sources={
            "dot": Path(sources["dot"]["path"]),
            "inventory": Path(sources["inventory"]["path"]),
            "device_aliases": Path(sources["device_aliases"]["path"]),
            "archive": archive,
        },
        report_path=report, expected_evidence_sha256=role["sha256"],
        expected_cycle_binding=binding,
    )
    if evidence.qualified:
        raise SwitchRuntimeHoldError("activity reader unexpectedly granted qualification")
    return evidence


def _cycle_preview(store, root: Path, evidence):
    completion, completion_sha = _read_record(store.completion_path(evidence.sequence))
    if completion_sha != evidence.completion_sha256:
        raise SwitchRuntimeHoldError("cycle completion changed after validation")
    identity = store._validate_start_record(
        _read_record(store.start_path(evidence.sequence))[0], evidence.sequence)
    store._validate_launch_record(
        _read_record(store.launch_path(evidence.sequence))[0], identity)
    validated = store._validate_completion_record(completion, identity)
    if (identity["cycle_id"] != evidence.cycle_id
            or validated["outcome"] != "cycle_completed"
            or validated["run_result"] is None):
        raise SwitchRuntimeHoldError("cycle identity or terminal outcome changed")
    outcomes = validated["run_result"]["outcomes"]
    if len(outcomes) != 1 or outcomes[0]["outcome"] != "accepted":
        raise SwitchRuntimeHoldError("ETH AIR child was not accepted")
    child = outcomes[0]["child_result"]
    if (child["source_slot"] != "ethernet/air" or child["state"] != "success"
            or child["failed_count"] != 0 or child["planned"] != child["succeeded"]):
        raise SwitchRuntimeHoldError("ETH AIR child is not complete")
    area = (root / "monitor/status/collection-cycles" / identity["project_key"]
            / "air/switch_collection/artifacts" / f"{evidence.sequence:020d}")
    slot = area / "ethernet-air"
    inventory = _read_bound(root, area / "inputs/ethernet-air.csv", maximum=1024 * 1024)
    if _digest(inventory)["sha256"] != child["input_inventory_sha256"]:
        raise SwitchRuntimeHoldError("frozen inventory disagrees with child")
    names, plan, static_plan_sha = _static_air_hosts(inventory)
    manifest, manifest_raw = _private_json(root, slot / "evidence-manifest.json")
    envelope, envelope_raw = _private_json(root, slot / "identity-envelope.json")
    if (_digest(manifest_raw) != child["evidence"]
            or _digest(envelope_raw) != child["envelope"]):
        raise SwitchRuntimeHoldError("private role digests disagree with completion")
    expected_identity = {key: identity[key] for key in (
        "project_key", "run_token", "scope", "sequence", "source", "cycle_id")}
    if (envelope.get("identity") != expected_identity
            or envelope.get("source_slot") != "ethernet/air"
            or envelope.get("state") != "success"
            or envelope.get("planned") != len(names)
            or envelope.get("succeeded") != len(names)
            or envelope.get("failed_count") != 0
            or envelope.get("input_inventory_sha256") != _digest(inventory)["sha256"]
            or envelope.get("evidence") != _digest(manifest_raw)
            or envelope.get("target_plan_sha256") != static_plan_sha
            or envelope.get("runtime_input_hashes") != {}):
        raise SwitchRuntimeHoldError("target plan or envelope is not static-bound")
    has_activity = "activity_context_sha256" in envelope
    expected_envelope_keys = {
        "identity", "source_slot", "state", "planned", "succeeded",
        "failed_count", "input_inventory_sha256", "evidence",
        "target_plan_sha256", "runtime_input_hashes",
    }
    if has_activity:
        expected_envelope_keys.add("activity_context_sha256")
    if set(envelope) != expected_envelope_keys:
        raise SwitchRuntimeHoldError("envelope has unvalidated extra authority")
    roles = manifest.get("roles")
    expected_roles = ["info_archive", "link_archive", "link_csv"]
    if has_activity:
        expected_roles.append("activity_observation")
    if (not isinstance(roles, list) or len(roles) != len(expected_roles)
            or [role.get("role") if isinstance(role, dict) else None
                for role in roles] != expected_roles):
        raise SwitchRuntimeHoldError("private role inventory is unexpected")
    for role, name in zip(roles[1:], ("link_archive", "link_csv")):
        if role != {
            "role": name, "state": "not_applicable", "relative_path": None,
            "sha256": None, "size_bytes": None,
        }:
            raise SwitchRuntimeHoldError("static AIR cannot claim a link role")
    info = roles[0]
    if (set(info) != {"role", "state", "relative_path", "sha256", "size_bytes"}
            or info["state"] != "present" or not isinstance(info["relative_path"], str)
            or not info["relative_path"].startswith("ethernet/monitor/eth-info/")
            or not isinstance(info["sha256"], str) or not _SHA.fullmatch(info["sha256"])
            or isinstance(info["size_bytes"], bool)
            or not isinstance(info["size_bytes"], int)):
        raise SwitchRuntimeHoldError("ETH info role is invalid")
    archive = _safe_child(root, info["relative_path"])
    if _digest(_read_bound(root, archive, maximum=8 * 1024 * 1024)) != {
        "sha256": info["sha256"], "size_bytes": info["size_bytes"]
    }:
        raise SwitchRuntimeHoldError("ETH info archive disagrees with private role")
    preview = read_switch_info_preview(
        archive, expected_sha256=info["sha256"],
        expected_size_bytes=info["size_bytes"], source_slot="ethernet/air",
        selected_hosts=names,
    )
    if preview.qualified or preview.selected_hosts != names:
        raise SwitchRuntimeHoldError("Switch info preview has unexpected authority")
    activity_evidence = None
    if has_activity:
        activity_evidence = _fourth_activity(
            root, area, slot, identity, child["input_inventory_sha256"],
            plan, static_plan_sha, info, envelope, roles[3],
        )
    return (names, str(archive), set(preview.abnormal_keys),
            info["sha256"], activity_evidence)


def read_switch_runtime_window(
    store, *, http_root: Path | str, settings: KChainState,
    whitelist_snapshot: WorkbookWhitelistSnapshot,
    whitelist_path: Path | str,
) -> SwitchRuntimeWindow:
    """Inspect a complete static AIR K-window; report no eligibility."""
    try:
        root = Path(http_root).resolve(strict=True)
        if (not root.is_dir() or Path(store.root_status_dir) != root / "monitor/status"
                or store.scope != "air" or not isinstance(settings, KChainState)):
            raise SwitchRuntimeHoldError("runtime source or K type is unsupported")
        project = Path(store.project_identity)
        if not project.is_absolute() or project.is_symlink():
            raise SwitchRuntimeHoldError("tracker project identity is unsafe")
        with tracker_writer(project, project / "99-output-monitor") as token:
            if current_k(token) != settings:
                raise SwitchRuntimeHoldError("K setting is not the current durable chain")
        if not isinstance(whitelist_snapshot, WorkbookWhitelistSnapshot):
            raise SwitchRuntimeHoldError("C24 local Whitelist snapshot is missing")
        if read_whitelist_workbook(whitelist_path) != whitelist_snapshot:
            raise SwitchRuntimeHoldError("C24 local Whitelist snapshot drifted")
        cycles = read_completed_cycle_evidence(store)
        window = assess_k_window(cycles, settings)
        if window.status != "history_sufficient":
            raise SwitchRuntimeHoldError("K-window is cold or nonqualifying")
        tail = cycles[-settings.k:]
        all_keys = None
        selected = None
        archives: set[str] = set()
        for cycle in tail:
            names, archive, abnormal, _info_sha, _activity = _cycle_preview(
                store, root, cycle,
            )
            if selected is not None and names != selected:
                raise SwitchRuntimeHoldError("selected host set changed within K-window")
            if archive in archives:
                raise SwitchRuntimeHoldError("info archive was replayed across cycles")
            archives.add(archive)
            selected = names
            all_keys = abnormal if all_keys is None else all_keys & abnormal
        records = tuple({"record_id": "switch:" + name, "source": "Switch",
                         "hostname": name} for name in selected)
        if any(item.skipped for item in evaluate_whitelist(
            whitelist_snapshot.whitelist, records).decisions):
            raise SwitchRuntimeHoldError("selected Switch matches local Whitelist")
        return SwitchRuntimeWindow(tuple(cycle.cycle_id for cycle in tail),
                                   tuple(sorted(all_keys)), qualified=False)
    except (OSError, TypeError, KeyError, AttributeError, RuntimeError,
            ValueError, CycleSourceHoldError) as exc:
        if isinstance(exc, SwitchRuntimeHoldError):
            raise
        raise SwitchRuntimeHoldError("Switch runtime evidence is incomplete") from exc


def read_switch_runtime_source_witness(
    store, *, http_root: Path | str, settings: KChainState,
    whitelist_snapshot: WorkbookWhitelistSnapshot, whitelist_path: Path | str,
) -> SwitchRuntimeSourceWitness:
    """Bind static AIR Switch and ETH endpoint sources to the real final K.

    This is a bounded first slice.  Production ETH, IB and NVLink source
    parsers are not inferred from AIR fixtures; they remain fail-closed.
    """
    try:
        preview = read_switch_runtime_window(
            store, http_root=http_root, settings=settings,
            whitelist_snapshot=whitelist_snapshot, whitelist_path=whitelist_path,
        )
        root = Path(http_root).resolve(strict=True)
        cycles = read_completed_cycle_evidence(store)
        if assess_k_window(cycles, settings).status != "history_sufficient":
            raise SwitchRuntimeHoldError("final K-window is no longer sufficient")
        tail = cycles[-settings.k:]
        if tuple(cycle.cycle_id for cycle in tail) != preview.cycle_ids:
            raise SwitchRuntimeHoldError("cycle window changed during source binding")
        info_hashes = []
        activity_hashes = []
        links_by_cycle = []
        endpoints = None
        second_switch_keys = None
        selected = None
        archives = set()
        for cycle in tail:
            names, archive, abnormal, info_sha, activity = _cycle_preview(
                store, root, cycle,
            )
            if selected is not None and names != selected:
                raise SwitchRuntimeHoldError("selected host set changed during source binding")
            if archive in archives:
                raise SwitchRuntimeHoldError("info archive was replayed during source binding")
            selected = names
            archives.add(archive)
            second_switch_keys = (
                abnormal if second_switch_keys is None
                else second_switch_keys & abnormal
            )
            if activity is None:
                raise SwitchRuntimeHoldError("ETH activity lacks a worker-bound fourth role")
            current = {
                (link.device_a, link.interface_a, link.device_b, link.interface_b)
                for link in activity.links
            }
            if len(current) != len(activity.links):
                raise SwitchRuntimeHoldError("duplicate ETH A/Z activity source")
            endpoints = current if endpoints is None else endpoints & current
            info_hashes.append(info_sha)
            activity_hashes.append(activity.evidence_sha256)
            links_by_cycle.append(activity.links)
        if tuple(sorted(second_switch_keys)) != preview.persistent_keys:
            raise SwitchRuntimeHoldError("Switch observation changed during source binding")
        with tracker_writer(Path(store.project_identity),
                            Path(store.project_identity) / "99-output-monitor") as token:
            if current_k(token) != settings:
                raise SwitchRuntimeHoldError("K setting changed during source binding")
        if read_whitelist_workbook(whitelist_path) != whitelist_snapshot:
            raise SwitchRuntimeHoldError("Whitelist changed during source binding")
        if read_completed_cycle_evidence(store) != cycles:
            raise SwitchRuntimeHoldError("cycle records changed during source binding")
        persistent = tuple(sorted(endpoints))
        records = [{
            "record_id": f"eth:{index}", "source": "Cabling",
            "a_node": item[0], "z_node": item[2],
        } for index, item in enumerate(persistent)]
        decisions = evaluate_whitelist(whitelist_snapshot.whitelist, records).decisions
        return SwitchRuntimeSourceWitness(
            cycle_ids=preview.cycle_ids,
            project_key=tail[0].project_key,
            source_slots=("ethernet/air",),
            completion_sha256=tuple(cycle.completion_sha256 for cycle in tail),
            info_sha256=tuple(info_hashes),
            activity_sha256=tuple(activity_hashes),
            switch_persistent_keys=preview.persistent_keys,
            eth_links_by_cycle=tuple(links_by_cycle),
            eth_endpoints=persistent,
            eth_whitelist_skips=tuple(item for item, decision in zip(
                persistent, decisions,
            ) if decision.skipped),
            eth_whitelist_matches=tuple(
                (item, decision.matched_rule)
                for item, decision in zip(persistent, decisions)
                if decision.skipped
            ),
            k_event_sha256=settings.event_sha256,
            whitelist_sha256=whitelist_snapshot.whitelist.sha256,
            template_sha256=whitelist_snapshot.workbook_sha256,
        )
    except (OSError, TypeError, KeyError, AttributeError, RuntimeError,
            ValueError, CycleSourceHoldError) as exc:
        if isinstance(exc, SwitchRuntimeHoldError):
            raise
        raise SwitchRuntimeHoldError("runtime source witness is incomplete") from exc


def validate_switch_runtime_source_witness(
    witness: SwitchRuntimeSourceWitness, store, *, http_root: Path | str,
    settings: KChainState, whitelist_snapshot: WorkbookWhitelistSnapshot,
    whitelist_path: Path | str,
) -> SwitchRuntimeSourceWitness:
    """Freeze-time reread; a copied or hand-built object carries no authority."""
    if type(witness) is not SwitchRuntimeSourceWitness or witness.qualified is not False:
        raise SwitchRuntimeHoldError("runtime witness type or authority is invalid")
    actual = read_switch_runtime_source_witness(
        store, http_root=http_root, settings=settings,
        whitelist_snapshot=whitelist_snapshot, whitelist_path=whitelist_path,
    )
    if actual != witness:
        raise SwitchRuntimeHoldError("runtime source witness changed before freeze")
    return actual


def _static_prod_plan(inventory: bytes, source_slot: str) -> tuple[tuple[str, ...], dict]:
    """Recreate inventory-declared targets before adding frozen runtime rows."""
    try:
        reader = csv.DictReader(io.StringIO(inventory.decode("utf-8")), strict=True)
        header = reader.fieldnames
        if (header is None or len(header) != len(set(header))
                or not {"hostname", "type", "eth0_ip"}.issubset(header)):
            raise SwitchRuntimeHoldError("prod frozen inventory header is invalid")
        family = source_slot.split("/", 1)[0]
        accepted = {"ethernet": {"eth", "eth_spx", "spx"},
                    "nvlink": {"nvl"}}[family]
        selected: list[tuple[str, str, str]] = []
        for row in reader:
            if None in row or any(value is None for value in row.values()):
                raise SwitchRuntimeHoldError("prod frozen inventory row is malformed")
            kind = row["type"].strip().casefold()
            if kind not in accepted:
                continue
            host, ip = row["hostname"].strip(), row["eth0_ip"].strip()
            if not _HOST.fullmatch(host):
                raise SwitchRuntimeHoldError("prod selected host is invalid")
            ipaddress.IPv4Address(ip)
            selected.append((host, ip, kind))
        hosts = tuple(row[0] for row in selected)
        if not hosts or len({host.casefold() for host in hosts}) != len(hosts):
            raise SwitchRuntimeHoldError("prod selected host set is empty or ambiguous")
        plan = {"eth": [], "spx": [], "ib": [], "nv": [],
                "dynamic_identities": []}
        key = "eth" if family == "ethernet" else "nv"
        plan[key] = [f"{host}|{ip}" for host, ip, _kind in selected]
        if family == "ethernet":
            plan["spx"] = [f"{host}|{ip}" for host, ip, kind in selected
                           if kind in {"eth_spx", "spx"}]
        return hosts, plan
    except (csv.Error, UnicodeError, TypeError, ValueError, KeyError) as exc:
        if isinstance(exc, SwitchRuntimeHoldError):
            raise
        raise SwitchRuntimeHoldError("static prod selection cannot be rebuilt") from exc


def _prod_fabric_identities(
    inventory: bytes, source_slot: str,
) -> tuple[tuple[str, str, str], ...]:
    """Retain only the selected hosts' frozen type/template for D-15.

    A missing template is represented as empty, never inferred from the host.
    Dynamic hosts have no inventory identity and must not be qualified through
    this static-only witness.
    """
    hosts, _plan = _static_prod_plan(inventory, source_slot)
    try:
        reader = csv.DictReader(io.StringIO(inventory.decode("utf-8")), strict=True)
        header = reader.fieldnames
        if header is None or len(header) != len(set(header)):
            raise SwitchRuntimeHoldError("prod fabric inventory header is ambiguous")
        wanted = set(hosts)
        identities = []
        for row in reader:
            if None in row or any(value is None for value in row.values()):
                raise SwitchRuntimeHoldError("prod fabric inventory row is malformed")
            host = row["hostname"].strip()
            template = row.get("template", "").strip()
            if (any(char in template for char in "\x00\r\n")
                    or len(template) > 255):
                raise SwitchRuntimeHoldError("prod fabric template is unsafe")
            if host in wanted:
                identities.append((host, row["type"].strip().casefold(), template))
        if tuple(item[0] for item in identities) != hosts:
            raise SwitchRuntimeHoldError("prod fabric identities differ from frozen plan")
        return tuple(identities)
    except (csv.Error, UnicodeError, TypeError, KeyError, ValueError) as exc:
        if isinstance(exc, SwitchRuntimeHoldError):
            raise
        raise SwitchRuntimeHoldError("prod fabric inventory cannot be decoded") from exc


def _prod_runtime_inputs(root: Path, area: Path, slot_name: str,
                         hashes: dict, source_slot: str) -> tuple[str, ...]:
    if not isinstance(hashes, dict) or not set(hashes).issubset({
        "leases", "dhcp_log", "air_json", "journal_derived_rows",
    }):
        raise SwitchRuntimeHoldError("prod runtime input hashes are invalid")
    if "air_json" in hashes:
        raise SwitchRuntimeHoldError("AIR runtime input cannot bind prod source")
    if source_slot == "nvlink/prod" and hashes:
        raise SwitchRuntimeHoldError("NVLink cannot claim Ethernet runtime rows")
    for role, suffix in (("leases", ".leases"), ("dhcp_log", ".dhcp.log")):
        if role in hashes:
            path = area / "inputs" / (slot_name + suffix)
            if hashlib.sha256(_read_bound(root, path, maximum=32 * 1024 * 1024)).hexdigest() != hashes[role]:
                raise SwitchRuntimeHoldError("prod runtime snapshot changed")
    if source_slot != "ethernet/prod":
        return ()
    rows_path = area / "inputs" / (slot_name + ".runtime-derived-rows.json")
    raw = _read_bound(root, rows_path, maximum=1024 * 1024)
    try:
        rows = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                          parse_constant=lambda _value: (_ for _ in ()).throw(
                              SwitchRuntimeHoldError("nonfinite runtime row")))
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        if isinstance(exc, SwitchRuntimeHoldError):
            raise
        raise SwitchRuntimeHoldError("prod runtime rows are malformed") from exc
    if (not isinstance(rows, list) or len(rows) > 10000
            or any(not isinstance(row, str) for row in rows)
            or raw != _canonical(rows)):
        raise SwitchRuntimeHoldError("prod runtime rows are not canonical")
    if ("journal_derived_rows" in hashes
            and hashes["journal_derived_rows"] != hashlib.sha256(raw).hexdigest()):
        raise SwitchRuntimeHoldError("prod runtime row hash changed")
    if "journal_derived_rows" not in hashes and rows:
        raise SwitchRuntimeHoldError("prod runtime rows lack a source hash")
    return tuple(rows)


def _prod_plan_from_rows(static_plan: dict, rows: tuple[str, ...]) -> dict:
    """Rebuild the worker's dynamic Cumulus selection from frozen row bytes."""
    plan = {key: list(value) for key, value in static_plan.items()}
    used_ips = {item.split("|", 1)[1] for item in plan["eth"]}
    known_names = {item.split("|", 1)[0].casefold() for item in plan["eth"]}
    for raw in rows:
        pieces = raw.split("|")
        if len(pieces) != 4:
            raise SwitchRuntimeHoldError("prod runtime row shape is invalid")
        mac, ip, platform, lease_state = pieces
        if platform != "cumulus" or lease_state not in {"active", "observed"}:
            continue
        normalized = re.sub(r"[^0-9a-f]", "", mac.casefold())
        if len(normalized) != 12 or any(char not in "0123456789abcdef"
                                         for char in normalized) or not ip:
            continue
        ipaddress.IPv4Address(ip)
        name = "DISCOVERED-CUMULUS-" + normalized.upper()
        if ip in used_ips or name.casefold() in known_names:
            continue
        plan["eth"].append(f"{name}|{ip}")
        plan["dynamic_identities"].append(
            f"{name}|{mac}|dhcp-unbound-cumulus"
        )
        used_ips.add(ip)
        known_names.add(name.casefold())
    return plan


def read_prod_switch_cycle_source(
    store, *, http_root: Path | str, sequence: int, source_slot: str,
) -> ProdSwitchCycleSource:
    """Bind a static ETH/NVL Switch preview to one completed real prod cycle.

    This source-only bridge never grants K, whitelist, IB, or manifest authority.
    Dynamic ETH is accepted only as a source preview when the real worker
    persisted its exact plan and derived rows; IB/global eligibility remains HOLD.
    """
    try:
        if source_slot not in {"ethernet/prod", "nvlink/prod"}:
            raise SwitchRuntimeHoldError("only ETH/NVL Switch prod sources are implemented")
        if type(sequence) is not int or sequence < 1:
            raise SwitchRuntimeHoldError("prod cycle sequence is invalid")
        root = Path(http_root).resolve(strict=True)
        if (not root.is_dir() or Path(store.root_status_dir) != root / "monitor/status"
                or store.scope != "prod"):
            raise SwitchRuntimeHoldError("prod worker store is not bound to HTTP root")
        cycles = read_completed_cycle_evidence(store)
        cycle = next((item for item in cycles if item.sequence == sequence), None)
        if (cycle is None or not cycle.qualifying or cycle.scope != "prod"
                or cycle.source_slots != (
                    "ethernet/prod", "infiniband/prod", "nvlink/prod",
                )):
            raise SwitchRuntimeHoldError("prod cycle is not complete across source slots")
        completion, completion_sha = _read_record(store.completion_path(sequence))
        if completion_sha != cycle.completion_sha256:
            raise SwitchRuntimeHoldError("prod cycle completion changed")
        identity = store._validate_start_record(
            _read_record(store.start_path(sequence))[0], sequence,
        )
        store._validate_launch_record(
            _read_record(store.launch_path(sequence))[0], identity,
        )
        validated = store._validate_completion_record(completion, identity)
        if (validated["outcome"] != "cycle_completed"
                or identity["cycle_id"] != cycle.cycle_id):
            raise SwitchRuntimeHoldError("prod cycle identity or outcome changed")
        outcomes = validated["run_result"]["outcomes"]
        if (len(outcomes) != 3 or tuple(item["source_slot"] for item in outcomes)
                != cycle.source_slots or any(item["outcome"] != "accepted"
                                             for item in outcomes)):
            raise SwitchRuntimeHoldError("prod cycle has incomplete child outcomes")
        child = next(item["child_result"] for item in outcomes
                     if item["source_slot"] == source_slot)
        if (child["source_slot"] != source_slot or child["state"] != "success"
                or child["failed_count"] != 0
                or child["planned"] != child["succeeded"]):
            raise SwitchRuntimeHoldError("prod child is incomplete")
        area = (root / "monitor/status/collection-cycles" / identity["project_key"]
                / "prod/switch_collection/artifacts" / f"{sequence:020d}")
        slot_name = source_slot.replace("/", "-")
        private = area / slot_name
        inventory = _read_bound(root, area / "inputs" / (slot_name + ".csv"),
                                maximum=1024 * 1024)
        if _digest(inventory)["sha256"] != child["input_inventory_sha256"]:
            raise SwitchRuntimeHoldError("prod frozen inventory changed")
        static_hosts, static_plan = _static_prod_plan(inventory, source_slot)
        fabric_identities = _prod_fabric_identities(inventory, source_slot)
        evidence, evidence_raw = _private_json(root, private / "evidence-manifest.json")
        envelope, envelope_raw = _private_json(root, private / "identity-envelope.json")
        if (_digest(evidence_raw) != child["evidence"]
                or _digest(envelope_raw) != child["envelope"]):
            raise SwitchRuntimeHoldError("prod private role digest changed")
        expected_identity = {key: identity[key] for key in (
            "project_key", "run_token", "scope", "sequence", "source", "cycle_id",
        )}
        hashes = envelope.get("runtime_input_hashes")
        runtime_rows = _prod_runtime_inputs(root, area, slot_name, hashes,
                                            source_slot)
        plan = (_prod_plan_from_rows(static_plan, runtime_rows)
                if source_slot == "ethernet/prod" else static_plan)
        fixed_plan, fixed_plan_raw = _private_json(
            root, area / "inputs" / (slot_name + ".target-plan.json"),
        )
        if fixed_plan != plan:
            raise SwitchRuntimeHoldError("frozen target plan disagrees with source rows")
        hosts = tuple(item.split("|", 1)[0] for item in plan[
            "eth" if source_slot == "ethernet/prod" else "nv"
        ])
        if hosts[:len(static_hosts)] != static_hosts:
            raise SwitchRuntimeHoldError("prod static host prefix changed")
        if (envelope.get("identity") != expected_identity
                or envelope.get("source_slot") != source_slot
                or envelope.get("state") != "success"
                or envelope.get("planned") != len(hosts)
                or envelope.get("succeeded") != len(hosts)
                or envelope.get("failed_count") != 0
                or envelope.get("input_inventory_sha256") != _digest(inventory)["sha256"]
                or envelope.get("evidence") != _digest(evidence_raw)
                or envelope.get("target_plan_sha256") != hashlib.sha256(fixed_plan_raw).hexdigest()):
            raise SwitchRuntimeHoldError("prod envelope does not bind frozen plan")
        expected_keys = {
            "identity", "source_slot", "state", "planned", "succeeded",
            "failed_count", "input_inventory_sha256", "evidence",
            "target_plan_sha256", "runtime_input_hashes",
        }
        if source_slot == "ethernet/prod" and "activity_context_sha256" in envelope:
            expected_keys.add("activity_context_sha256")
        if set(envelope) != expected_keys:
            raise SwitchRuntimeHoldError("prod envelope has unvalidated fields")
        roles = evidence.get("roles")
        if (not isinstance(roles, list) or len(roles) not in (3, 4)
                or [item.get("role") if isinstance(item, dict) else None
                    for item in roles[:3]] != [
                    "info_archive", "link_archive", "link_csv",
                ] or (len(roles) == 4 and (
                    source_slot != "ethernet/prod"
                    or roles[3].get("role") != "activity_observation"
                    or "activity_context_sha256" not in envelope
                ))):
            raise SwitchRuntimeHoldError("prod role inventory is invalid")
        if ("activity_context_sha256" in envelope) != (len(roles) == 4):
            raise SwitchRuntimeHoldError("prod activity role is incomplete")
        link_expected = source_slot == "nvlink/prod" or bool(plan["spx"])
        link_prefix = ("ethernet/monitor/spx-link/" if source_slot == "ethernet/prod"
                       else "nvlink/monitor/nvsw-link/")
        for index, label, suffix in ((1, "link_archive", ".tar.gz"),
                                     (2, "link_csv", ".csv")):
            role = roles[index]
            if not isinstance(role, dict) or set(role) != {
                "role", "state", "relative_path", "sha256", "size_bytes",
            } or role["role"] != label:
                raise SwitchRuntimeHoldError("prod link role shape is invalid")
            if not link_expected:
                if role != {
                    "role": label, "state": "not_applicable", "relative_path": None,
                    "sha256": None, "size_bytes": None,
                }:
                    raise SwitchRuntimeHoldError("inapplicable prod link role changed")
                continue
            relative = role["relative_path"]
            if (role["state"] != "present" or not isinstance(relative, str)
                    or not relative.startswith(link_prefix)
                    or not relative.endswith(suffix)
                    or not isinstance(role["sha256"], str)
                    or not _SHA.fullmatch(role["sha256"])
                    or type(role["size_bytes"]) is not int
                    or role["size_bytes"] <= 0):
                raise SwitchRuntimeHoldError("prod link role is incomplete")
            path = _safe_child(root, relative)
            if _digest(_read_bound(root, path, maximum=64 * 1024 * 1024)) != {
                "sha256": role["sha256"], "size_bytes": role["size_bytes"],
            }:
                raise SwitchRuntimeHoldError("prod link role bytes changed")
        if link_expected and (Path(roles[1]["relative_path"]).name.removesuffix(".tar.gz")
                              != Path(roles[2]["relative_path"]).name.removesuffix(".csv")):
            raise SwitchRuntimeHoldError("prod link archive and CSV disagree")
        if len(roles) == 4:
            activity = roles[3]
            expected_relative = (private / "activity-observation.json").relative_to(root).as_posix()
            if (not isinstance(activity, dict) or set(activity) != {
                "role", "state", "relative_path", "sha256", "size_bytes",
            } or activity["state"] != "present"
                    or activity["relative_path"] != expected_relative
                    or not isinstance(activity["sha256"], str)
                    or not _SHA.fullmatch(activity["sha256"])
                    or type(activity["size_bytes"]) is not int
                    or activity["size_bytes"] <= 0):
                raise SwitchRuntimeHoldError("prod activity role is incomplete")
            if _digest(_read_bound(root, _safe_child(root, expected_relative),
                                   maximum=16 * 1024 * 1024)) != {
                "sha256": activity["sha256"], "size_bytes": activity["size_bytes"],
            }:
                raise SwitchRuntimeHoldError("prod activity role bytes changed")
        prefix = ("ethernet/monitor/eth-info/" if source_slot == "ethernet/prod"
                  else "nvlink/monitor/nvsw-info/")
        info = roles[0]
        if (not isinstance(info, dict) or set(info) != {
            "role", "state", "relative_path", "sha256", "size_bytes",
        } or info["state"] != "present"
                or not isinstance(info["relative_path"], str)
                or not info["relative_path"].startswith(prefix)):
            raise SwitchRuntimeHoldError("prod info role is invalid")
        info_path = _safe_child(root, info["relative_path"])
        preview = read_switch_info_preview(
            info_path, expected_sha256=info["sha256"],
            expected_size_bytes=info["size_bytes"], source_slot=source_slot,
            selected_hosts=hosts,
        )
        # Preserve only a typed source-to-row mapping, not an issue operation.
        rows = map_switch_source_rows(preview)
        if read_completed_cycle_evidence(store) != cycles:
            raise SwitchRuntimeHoldError("prod cycle changed during source read")
        return ProdSwitchCycleSource(
            cycle_id=cycle.cycle_id, sequence=sequence,
            completion_sha256=completion_sha, preview=preview, rows=rows,
            fabric_identities=fabric_identities,
        )
    except (OSError, TypeError, KeyError, AttributeError, RuntimeError,
            ValueError, CycleSourceHoldError) as exc:
        if isinstance(exc, SwitchRuntimeHoldError):
            raise
        raise SwitchRuntimeHoldError("prod Switch source is incomplete") from exc


def validate_prod_switch_cycle_source(
    witness: ProdSwitchCycleSource, store, *, http_root: Path | str,
) -> ProdSwitchCycleSource:
    """Freeze-time reread; typed object or copied hashes alone are no authority."""
    if type(witness) is not ProdSwitchCycleSource or witness.qualified is not False:
        raise SwitchRuntimeHoldError("prod source witness has invalid authority")
    actual = read_prod_switch_cycle_source(
        store, http_root=http_root, sequence=witness.sequence,
        source_slot=witness.preview.source_slot,
    )
    if actual != witness:
        raise SwitchRuntimeHoldError("prod source changed before freeze")
    return actual


def read_prod_eth_activity_cycle_source(
    store, *, http_root: Path | str, sequence: int,
) -> ProdEthActivityCycleSource:
    """Rebuild one completed prod ETH fourth role from frozen worker inputs.

    A present but unverified P2P derivation never becomes an ETH Cabling
    operation. An old activity role without derivation remains source-only.
    """
    try:
        root = Path(http_root).resolve(strict=True)
        switch = read_prod_switch_cycle_source(
            store, http_root=root, sequence=sequence,
            source_slot="ethernet/prod",
        )
        cycles = read_completed_cycle_evidence(store)
        cycle = next((item for item in cycles if item.sequence == sequence), None)
        if cycle is None or cycle.cycle_id != switch.cycle_id:
            raise SwitchRuntimeHoldError("prod ETH activity cycle changed")
        area = (root / "monitor/status/collection-cycles" / cycle.project_key
                / "prod/switch_collection/artifacts" / f"{sequence:020d}")
        stem = "ethernet-prod"
        slot = area / stem
        inputs = area / "inputs"
        evidence, evidence_raw = _private_json(root, slot / "evidence-manifest.json")
        envelope, _ = _private_json(root, slot / "identity-envelope.json")
        roles = evidence.get("roles")
        if (not isinstance(roles, list) or len(roles) != 4
                or "activity_context_sha256" not in envelope):
            raise SwitchRuntimeHoldError("prod ETH fourth role is absent")
        activity_role = roles[3]
        expected_relative = (slot / "activity-observation.json").relative_to(root).as_posix()
        if (not isinstance(activity_role, dict)
                or activity_role.get("role") != "activity_observation"
                or activity_role.get("state") != "present"
                or activity_role.get("relative_path") != expected_relative):
            raise SwitchRuntimeHoldError("prod ETH fourth role path is invalid")
        activity_path = _safe_child(root, expected_relative)
        raw_activity = _read_bound(root, activity_path, maximum=16 * 1024 * 1024)
        if _digest(raw_activity) != {
            "sha256": activity_role.get("sha256"),
            "size_bytes": activity_role.get("size_bytes"),
        }:
            raise SwitchRuntimeHoldError("prod ETH fourth role bytes changed")
        inventory = _read_bound(root, inputs / (stem + ".csv"), maximum=1024 * 1024)
        plan, plan_raw = _private_json(root, inputs / (stem + ".target-plan.json"))
        hashes = envelope["runtime_input_hashes"]
        runtime_rows = _prod_runtime_inputs(root, area, stem, hashes, "ethernet/prod")
        frozen = {}
        for role, suffix, maximum in (
            ("topology", "p2p.xlsx", 64 * 1024 * 1024),
            ("dot", "dot", 16 * 1024 * 1024),
            ("inventory", "lldp-inventory.log", 4 * 1024 * 1024),
            ("device_aliases", "aliases.json", 4 * 1024 * 1024),
        ):
            path = _safe_child(root, (inputs / f"{stem}.{suffix}").relative_to(root).as_posix())
            frozen[role] = {"path": str(path),
                            "sha256": hashlib.sha256(_read_bound(
                                root, path, maximum=maximum,
                            )).hexdigest()}
        activity = {
            "schema_version": 1, "source_slot": "ethernet/prod",
            "topology": frozen["topology"],
            "sources": {role: frozen[role] for role in (
                "dot", "inventory", "device_aliases")},
            "sidecar_path": str(inputs / f"{stem}.activity.json"),
        }
        derivation_paths = {
            "port_mapping": inputs / f"{stem}.port-mapping.log",
            "splitter_profiles": inputs / f"{stem}.splitter-profiles.json",
        }
        present = tuple(path.exists() or path.is_symlink()
                        for path in derivation_paths.values())
        if any(present) and not all(present):
            raise SwitchRuntimeHoldError("prod ETH P2P derivation roles are partial")
        selected_name = None
        if all(present):
            for role, path in derivation_paths.items():
                path = _safe_child(root, path.relative_to(root).as_posix())
                frozen[role] = {"path": str(path),
                                "sha256": hashlib.sha256(_read_bound(
                                    root, path, maximum=4 * 1024 * 1024,
                                )).hexdigest()}
            profile_raw = _read_bound(
                root, derivation_paths["splitter_profiles"], maximum=4 * 1024 * 1024,
            )
            profile = json.loads(profile_raw.decode("utf-8"), object_pairs_hook=_pairs)
            if not isinstance(profile, dict) or type(profile.get("source_workbook")) is not str:
                raise SwitchRuntimeHoldError("prod ETH selected workbook name is absent")
            selected_name = profile["source_workbook"]
            activity["derivation_sources"] = {
                role: frozen[role] for role in ("port_mapping", "splitter_profiles")
            }
            activity["selected_workbook_name"] = selected_name
        identity = store._validate_start_record(
            _read_record(store.start_path(sequence))[0], sequence,
        )
        context = {
            "identity": identity, "source_slot": "ethernet/prod",
            "artifacts": {
                "evidence": str(slot / "evidence-manifest.json"),
                "envelope": str(slot / "identity-envelope.json"),
                "input_inventory": str(inputs / (stem + ".csv")),
            },
            "input_inventory_sha256": hashlib.sha256(inventory).hexdigest(),
            "air_dynamic_rows": [], "prod_runtime_rows": list(runtime_rows),
            "runtime_input_hashes": hashes,
            "target_plan": plan,
            "target_plan_sha256": hashlib.sha256(plan_raw).hexdigest(),
            "activity": activity,
        }
        binding = validate_worker_eth_activity_context(context)
        if (binding["context_sha256"] != envelope["activity_context_sha256"]
                or _digest(evidence_raw) != envelope["evidence"]):
            raise SwitchRuntimeHoldError("prod ETH activity context differs from completion")
        derivation = None
        if selected_name is not None:
            source_roles = {
                "topology": frozen["topology"],
                "inventory": frozen["inventory"],
                "port_mapping": frozen["port_mapping"],
                "lldpq": frozen["dot"],
                "splitter_profiles": frozen["splitter_profiles"],
            }
            derivation = verify_lldpq_derivation(
                sources={role: Path(value["path"]) for role, value in source_roles.items()},
                expected_sha256={role: value["sha256"] for role, value in source_roles.items()},
                selected_workbook_name=selected_name,
            )
        info = roles[0]
        archive = _safe_child(root, info["relative_path"])
        report = _safe_child(root, (
            Path("tools/lldp-analyze-tool/99-output-p2p")
            / (archive.name.removesuffix(".tar.gz")
               + "-ethernet-topology-validation.xlsx")
        ).as_posix())
        source_paths = {role: Path(frozen[role]["path"])
                        for role in ("dot", "inventory", "device_aliases")}
        source_paths["archive"] = archive
        observation = load_eth_activity_evidence(
            activity_path, sources=source_paths, report_path=report,
            expected_evidence_sha256=activity_role["sha256"],
            expected_cycle_binding=binding,
        )
        if (read_prod_switch_cycle_source(
                store, http_root=root, sequence=sequence,
                source_slot="ethernet/prod",
            ) != switch or read_completed_cycle_evidence(store) != cycles):
            raise SwitchRuntimeHoldError("prod ETH activity source changed during read")
        return ProdEthActivityCycleSource(
            switch.cycle_id, sequence, switch.completion_sha256,
            observation.evidence_sha256, observation.links, derivation,
        )
    except (OSError, TypeError, KeyError, AttributeError, RuntimeError,
            ValueError, CycleSourceHoldError) as exc:
        if isinstance(exc, SwitchRuntimeHoldError):
            raise
        raise SwitchRuntimeHoldError("prod ETH activity source is incomplete") from exc


def validate_prod_eth_activity_cycle_source(
    witness: ProdEthActivityCycleSource, store, *, http_root: Path | str,
) -> ProdEthActivityCycleSource:
    """Reread the completed prod ETH link source before any later K reduction."""
    if type(witness) is not ProdEthActivityCycleSource or witness.qualified is not False:
        raise SwitchRuntimeHoldError("prod ETH activity witness is not read-only")
    actual = read_prod_eth_activity_cycle_source(
        store, http_root=http_root, sequence=witness.sequence,
    )
    if actual != witness:
        raise SwitchRuntimeHoldError("prod ETH activity source changed before freeze")
    return actual


def read_prod_eth_activity_k_window(
    store, *, http_root: Path | str, settings: KChainState,
    whitelist_snapshot: WorkbookWhitelistSnapshot,
    whitelist_path: Path | str, writer_token=None,
) -> ProdEthActivityKWindow:
    """Bind one completed prod ETH per-value K source to durable K and W1.

    This excludes W1-matched endpoints but grants no C5/C6, IB or publication
    authority. A full workbook-to-LLDPQ derivation is mandatory for this view.
    """
    try:
        root = Path(http_root).resolve(strict=True)
        if (not root.is_dir() or store.scope != "prod"
                or Path(store.root_status_dir) != root / "monitor/status"
                or not isinstance(settings, KChainState)
                or not isinstance(whitelist_snapshot, WorkbookWhitelistSnapshot)):
            raise SwitchRuntimeHoldError("prod ETH K authority is unsupported")
        project = Path(store.project_identity)
        if not project.is_absolute() or project.is_symlink():
            raise SwitchRuntimeHoldError("prod ETH K project identity is unsafe")
        _require_prod_k(project, settings, writer_token)
        if read_whitelist_workbook(whitelist_path) != whitelist_snapshot:
            raise SwitchRuntimeHoldError("prod ETH Whitelist snapshot drifted")
        cycles = read_completed_cycle_evidence(store)
        if assess_k_window(cycles, settings).status != "history_sufficient":
            raise SwitchRuntimeHoldError("prod ETH K window is cold or nonqualifying")
        tail = cycles[-settings.k:]
        sources = tuple(read_prod_eth_activity_cycle_source(
            store, http_root=root, sequence=cycle.sequence,
        ) for cycle in tail)
        if (tuple(source.cycle_id for source in sources)
                != tuple(cycle.cycle_id for cycle in tail)
                or tuple(source.completion_sha256 for source in sources)
                != tuple(cycle.completion_sha256 for cycle in tail)):
            raise SwitchRuntimeHoldError("prod ETH K cycle identity changed")
        topology = None
        persistent = None
        archives = set()
        for source in sources:
            if source.derivation is None or source.qualified is not False:
                raise SwitchRuntimeHoldError("prod ETH K lacks P2P derivation")
            if topology is not None and source.derivation.source_sha256 != topology:
                raise SwitchRuntimeHoldError("prod ETH K topology changed")
            topology = source.derivation.source_sha256
            switch = read_prod_switch_cycle_source(
                store, http_root=root, sequence=source.sequence,
                source_slot="ethernet/prod",
            )
            if (switch.cycle_id != source.cycle_id
                    or switch.completion_sha256 != source.completion_sha256
                    or switch.preview.archive_sha256 in archives):
                raise SwitchRuntimeHoldError("prod ETH K archive replayed")
            archives.add(switch.preview.archive_sha256)
            endpoints = [(
                link.device_a, link.interface_a, link.device_b, link.interface_b,
            ) for link in source.links]
            if len(endpoints) != len(set(endpoints)):
                raise SwitchRuntimeHoldError("prod ETH K has duplicate endpoints")
            current = set(source.links)
            persistent = current if persistent is None else persistent & current
        candidates = tuple(sorted(persistent, key=lambda link: (
            link.device_a, link.interface_a, link.device_b, link.interface_b,
            link.status, link.observation_a.remote_host,
            link.observation_a.remote_port,
            link.observation_b.remote_host, link.observation_b.remote_port,
        )))
        records = [{
            "record_id": f"eth:{index}", "source": "Cabling",
            "a_node": link.device_a, "z_node": link.device_b,
        } for index, link in enumerate(candidates)]
        decisions = evaluate_whitelist(
            whitelist_snapshot.whitelist, records,
        ).decisions
        if any(decision.skipped and
               (type(decision.matched_rule) is not str or not decision.matched_rule)
               for decision in decisions):
            raise SwitchRuntimeHoldError("prod ETH W1 skip has no matched rule")
        _require_prod_k(project, settings, writer_token)
        if (read_whitelist_workbook(whitelist_path) != whitelist_snapshot
                or read_completed_cycle_evidence(store) != cycles):
            raise SwitchRuntimeHoldError("prod ETH K source authority changed")
        for source in sources:
            validate_prod_eth_activity_cycle_source(
                source, store, http_root=root,
            )
        return ProdEthActivityKWindow(
            cycle_ids=tuple(source.cycle_id for source in sources),
            completion_sha256=tuple(source.completion_sha256 for source in sources),
            activity_sha256=tuple(source.activity_sha256 for source in sources),
            persistent_links=tuple(link for link, decision in zip(
                candidates, decisions,
            ) if not decision.skipped),
            whitelist_skips=tuple((link.device_a, link.interface_a,
                                   link.device_b, link.interface_b)
                                  for link, decision in zip(candidates, decisions)
                                  if decision.skipped),
            whitelist_skip_matches=tuple((
                (link.device_a, link.interface_a, link.device_b, link.interface_b),
                decision.matched_rule,
            ) for link, decision in zip(candidates, decisions) if decision.skipped),
            k_event_sha256=settings.event_sha256,
            whitelist_sha256=whitelist_snapshot.whitelist.sha256,
            template_sha256=whitelist_snapshot.workbook_sha256,
        )
    except (OSError, TypeError, KeyError, AttributeError, RuntimeError,
            ValueError, CycleSourceHoldError) as exc:
        if isinstance(exc, SwitchRuntimeHoldError):
            raise
        raise SwitchRuntimeHoldError("prod ETH K source evidence is incomplete") from exc


def validate_prod_eth_activity_k_window(
    witness: ProdEthActivityKWindow, store, *, http_root: Path | str,
    settings: KChainState, whitelist_snapshot: WorkbookWhitelistSnapshot,
    whitelist_path: Path | str, writer_token=None,
) -> ProdEthActivityKWindow:
    """Reread complete ETH K source at a future freeze boundary."""
    if type(witness) is not ProdEthActivityKWindow or witness.qualified is not False:
        raise SwitchRuntimeHoldError("prod ETH K witness has invalid authority")
    actual = read_prod_eth_activity_k_window(
        store, http_root=http_root, settings=settings,
        whitelist_snapshot=whitelist_snapshot,
        whitelist_path=whitelist_path, writer_token=writer_token,
    )
    if actual != witness:
        raise SwitchRuntimeHoldError("prod ETH K witness changed before freeze")
    return actual


def classify_prod_eth_activity_k_window(
    window: ProdEthActivityKWindow,
) -> tuple[ProdEthIssueSourceRow, ...]:
    """Map held ETH statuses using the analyzer's sheet partition.

    The result is source interpretation only. Callers must independently
    reread the K witness; neither this function nor its rows grant C5/C6.
    """
    if type(window) is not ProdEthActivityKWindow or window.qualified is not False:
        raise SwitchRuntimeHoldError("ETH issue source window lacks read-only type")
    miswired = {"WRONG_PEER", "SW_LLDP_PRESENT", "NO_LLDP"}
    missing = {"DOWN", "MISSING_DEVICE", "MISSING_INTERFACE"}
    confirmed = {"CONFIRMED_BOTH_SIDE", "CONFIRMED_SW_SIDE"}
    skipped = set(window.whitelist_skips)
    seen = set()
    rows = []
    for link in window.persistent_links:
        if type(link) is not EthLinkObservation or link.status not in (
            miswired | missing | confirmed
        ):
            raise SwitchRuntimeHoldError("ETH issue source status is unsupported")
        endpoints = (
            link.device_a, link.interface_a, link.device_b, link.interface_b,
        )
        if not all(isinstance(part, str) and part.strip() for part in endpoints):
            raise SwitchRuntimeHoldError("ETH issue source endpoint is invalid")
        key = tuple(part.casefold() for part in endpoints)
        if key in seen or endpoints in skipped:
            raise SwitchRuntimeHoldError("ETH issue source endpoint is ambiguous")
        seen.add(key)
        if link.status in miswired:
            rows.append(ProdEthIssueSourceRow(
                link, "Miswired_Links", "Mis-wiring",
            ))
        elif link.status in missing:
            rows.append(ProdEthIssueSourceRow(
                link, "Missing_Links", "Link Down",
            ))
    return tuple(rows)


def intersect_prod_switch_sources(
    sources: tuple[ProdSwitchCycleSource, ...], *, source_slot: str,
) -> ProdSwitchKWindow:
    """Intersect source-only rows across a consecutive real prod sequence.

    This pure reducer intentionally lacks K/settings/Whitelist authority. The
    I/O entrypoint below supplies those bindings and still returns HOLD-only
    source evidence, never a QualifiedSet.
    """
    if (source_slot not in {"ethernet/prod", "nvlink/prod"}
            or not isinstance(sources, tuple) or not sources):
        raise SwitchRuntimeHoldError("prod source window shape is invalid")
    selected = None
    keys = None
    ids = set()
    completions = []
    previous_sequence = None
    for source in sources:
        if (type(source) is not ProdSwitchCycleSource or source.qualified is not False
                or source.preview.source_slot != source_slot
                or source.preview.qualified is not False
                or not _SHA.fullmatch(source.cycle_id)
                or not _SHA.fullmatch(source.completion_sha256)
                or not _SHA.fullmatch(source.preview.archive_sha256)
                or source.cycle_id in ids
                or (previous_sequence is not None
                    and source.sequence != previous_sequence + 1)
                or type(source.sequence) is not int or source.sequence < 1):
            raise SwitchRuntimeHoldError("prod source window contains replay or drift")
        try:
            expected_rows = map_switch_source_rows(source.preview)
        except ValueError as exc:
            raise SwitchRuntimeHoldError("prod source preview is inconsistent") from exc
        if source.rows != expected_rows or any(row.qualified is not False
                                               for row in source.rows):
            raise SwitchRuntimeHoldError("prod source rows were replaced")
        hosts = source.preview.selected_hosts
        if selected is not None and hosts != selected:
            raise SwitchRuntimeHoldError("prod selected hosts changed within K")
        selected = hosts
        current = {(row.hostname, row.category, row.component_or_sensor)
                   for row in source.rows}
        keys = current if keys is None else keys & current
        ids.add(source.cycle_id)
        completions.append(source.completion_sha256)
        previous_sequence = source.sequence
    return ProdSwitchKWindow(
        source_slot=source_slot,
        cycle_ids=tuple(source.cycle_id for source in sources),
        completion_sha256=tuple(completions),
        selected_hosts=selected,
        persistent_keys=tuple(sorted(keys)),
        archive_sha256=tuple(source.preview.archive_sha256 for source in sources),
        whitelist_skips=(), k_event_sha256="", whitelist_sha256="",
        template_sha256="",
    )


def read_prod_switch_k_window(
    store, *, http_root: Path | str, settings: KChainState,
    whitelist_snapshot: WorkbookWhitelistSnapshot,
    whitelist_path: Path | str, source_slot: str, writer_token=None,
) -> ProdSwitchKWindow:
    """Bind K, real worker/emitter ETH/NVL sources and C-24 W1 to one window.

    This does not interpret IB or issue values, so qualified remains False.
    A later publication freeze must reread and compare the entire witness.
    """
    try:
        root = Path(http_root).resolve(strict=True)
        if (source_slot not in {"ethernet/prod", "nvlink/prod"}
                or not root.is_dir() or store.scope != "prod"
                or Path(store.root_status_dir) != root / "monitor/status"
                or not isinstance(settings, KChainState)
                or not isinstance(whitelist_snapshot, WorkbookWhitelistSnapshot)):
            raise SwitchRuntimeHoldError("prod K source authority is unsupported")
        project = Path(store.project_identity)
        if not project.is_absolute() or project.is_symlink():
            raise SwitchRuntimeHoldError("prod project identity is unsafe")
        _require_prod_k(project, settings, writer_token)
        if read_whitelist_workbook(whitelist_path) != whitelist_snapshot:
            raise SwitchRuntimeHoldError("prod Whitelist snapshot drifted")
        cycles = read_completed_cycle_evidence(store)
        if assess_k_window(cycles, settings).status != "history_sufficient":
            raise SwitchRuntimeHoldError("prod K window is cold or nonqualifying")
        tail = cycles[-settings.k:]
        sources = tuple(read_prod_switch_cycle_source(
            store, http_root=root, sequence=cycle.sequence,
            source_slot=source_slot,
        ) for cycle in tail)
        source_window = intersect_prod_switch_sources(
            sources, source_slot=source_slot,
        )
        if (source_window.cycle_ids != tuple(cycle.cycle_id for cycle in tail)
                or source_window.completion_sha256 != tuple(
                    cycle.completion_sha256 for cycle in tail)):
            raise SwitchRuntimeHoldError("prod K source cycle changed")
        records = [
            {"record_id": "switch:" + name, "source": "Switch", "hostname": name}
            for name in source_window.selected_hosts
        ]
        decisions = evaluate_whitelist(
            whitelist_snapshot.whitelist, records,
        ).decisions
        if any(decision.skipped and
               (type(decision.matched_rule) is not str or not decision.matched_rule)
               for decision in decisions):
            raise SwitchRuntimeHoldError("prod Switch W1 skip has no matched rule")
        _require_prod_k(project, settings, writer_token)
        if (read_whitelist_workbook(whitelist_path) != whitelist_snapshot
                or read_completed_cycle_evidence(store) != cycles):
            raise SwitchRuntimeHoldError("prod source authority changed during read")
        for source in sources:
            validate_prod_switch_cycle_source(
                source, store, http_root=root,
            )
        return ProdSwitchKWindow(
            source_slot=source_slot, cycle_ids=source_window.cycle_ids,
            completion_sha256=source_window.completion_sha256,
            selected_hosts=source_window.selected_hosts,
            persistent_keys=source_window.persistent_keys,
            archive_sha256=source_window.archive_sha256,
            whitelist_skips=tuple(decision.record_id for decision in decisions
                                  if decision.skipped),
            whitelist_skip_matches=tuple((decision.record_id,
                                          decision.matched_rule)
                                         for decision in decisions
                                         if decision.skipped),
            k_event_sha256=settings.event_sha256,
            whitelist_sha256=whitelist_snapshot.whitelist.sha256,
            template_sha256=whitelist_snapshot.workbook_sha256,
        )
    except (OSError, TypeError, KeyError, AttributeError, RuntimeError,
            ValueError, CycleSourceHoldError) as exc:
        if isinstance(exc, SwitchRuntimeHoldError):
            raise
        raise SwitchRuntimeHoldError("prod K source evidence is incomplete") from exc


def validate_prod_switch_k_window(
    witness: ProdSwitchKWindow, store, *, http_root: Path | str,
    settings: KChainState, whitelist_snapshot: WorkbookWhitelistSnapshot,
    whitelist_path: Path | str, writer_token=None,
) -> ProdSwitchKWindow:
    """Reread before a future freeze; copied hashes confer no authority."""
    if type(witness) is not ProdSwitchKWindow or witness.qualified is not False:
        raise SwitchRuntimeHoldError("prod K witness has invalid authority")
    actual = read_prod_switch_k_window(
        store, http_root=http_root, settings=settings,
        whitelist_snapshot=whitelist_snapshot,
        whitelist_path=whitelist_path, source_slot=witness.source_slot,
        writer_token=writer_token,
    )
    if actual != witness:
        raise SwitchRuntimeHoldError("prod K source changed before freeze")
    return actual
