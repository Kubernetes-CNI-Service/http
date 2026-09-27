"""Read-only IB role replay in a real completed prod cycle.

The three base roles remain a diagnostic gap. Nine-role cycles must independently
replay the root-protected UFM attestation before exposing a nonqualifying source;
neither shape grants Stage L or publication authority by itself.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import re
from pathlib import Path

from monitor.collection_v2_emitter import canonical
from monitor.issue_tracker_cycle_source import (
    _read_record, read_completed_cycle_evidence,
)
from monitor.issue_tracker_switch_runtime import (
    SwitchRuntimeHoldError, _digest, _private_json, _read_bound, _safe_child,
)


class IbCycleRoleHold(ValueError):
    """The requested worker cycle or its IB role provenance is not sound."""


_BASE_ROLES = ("info_archive", "link_archive", "link_csv")
_MISSING_ROLES = (
    "ufm_actual_archive", "ufm_actual_log", "expected_cvt",
    "validation_report", "report_provenance", "ufm_completion_receipt",
)
_ROLE_PREFIXES = ("ib-info", "ib-link", "ib-link")
_HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,252}")
_HEX = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class IbCycleRoleGap:
    """Diagnostic only; ``qualified`` is intentionally always false."""

    cycle_id: str
    sequence: int
    completion_sha256: str
    evidence_sha256: str
    roles: tuple[str, ...]
    missing_roles: tuple[str, ...]
    qualified: bool = False


@dataclass(frozen=True)
class IbCycleRoleSource:
    """Completed and protected IB report source, never a publish permit."""

    cycle_id: str
    sequence: int
    completion_sha256: str
    evidence_sha256: str
    roles: tuple[str, ...]
    report_relative_path: str
    report_sha256: str
    expected_topology_sha256: str
    attestation_sha256: str
    qualified: bool = False


def _ib_inventory(raw: bytes) -> tuple[str, ...]:
    """Rebuild the selected IB hosts without trusting a caller's target plan."""
    import csv
    import io

    try:
        reader = csv.DictReader(io.StringIO(raw.decode("utf-8")), strict=True)
        header = reader.fieldnames
        if (header is None or len(header) != len(set(header))
                or not {"hostname", "type", "eth0_ip"}.issubset(header)):
            raise IbCycleRoleHold("IB frozen inventory header is invalid")
        selected = []
        for row in reader:
            if None in row or any(value is None for value in row.values()):
                raise IbCycleRoleHold("IB frozen inventory row is malformed")
            if row["type"].strip().casefold() != "ib":
                continue
            host, ip = row["hostname"].strip(), row["eth0_ip"].strip()
            if not _HOST.fullmatch(host):
                raise IbCycleRoleHold("IB selected host is invalid")
            ipaddress.IPv4Address(ip)
            selected.append(f"{host}|{ip}")
        names = [entry.split("|", 1)[0].casefold() for entry in selected]
        if not selected or len(names) != len(set(names)):
            raise IbCycleRoleHold("IB selected host set is empty or ambiguous")
        return tuple(selected)
    except (csv.Error, UnicodeError, TypeError, ValueError) as exc:
        if isinstance(exc, IbCycleRoleHold):
            raise
        raise IbCycleRoleHold("IB frozen inventory cannot be rebuilt") from exc


def _bound_base_roles(root: Path, roles: object) -> tuple[str, ...]:
    if (not isinstance(roles, list) or len(roles) != len(_BASE_ROLES)
            or tuple(item.get("role") if isinstance(item, dict) else None
                     for item in roles) != _BASE_ROLES):
        raise IbCycleRoleHold("IB producer did not publish the known role schema")
    for index, role in enumerate(roles):
        if (set(role) != {"role", "state", "relative_path", "sha256", "size_bytes"}
                or role["state"] != "present"
                or type(role["size_bytes"]) is not int
                or role["size_bytes"] < 0
                or not isinstance(role["sha256"], str)
                or not _HEX.fullmatch(role["sha256"])):
            raise IbCycleRoleHold("IB base role is malformed")
        relative = role["relative_path"]
        if (not isinstance(relative, str)
                or not relative.startswith(f"infiniband/monitor/{_ROLE_PREFIXES[index]}/")):
            raise IbCycleRoleHold("IB base role path is outside its producer namespace")
        path = _safe_child(root, relative)
        suffix = ".csv" if index == 2 else ".tar.gz"
        if not re.fullmatch(r"[0-9]{8}-[0-9]{4}(?:-(?:air|prod))?" + re.escape(suffix), path.name):
            raise IbCycleRoleHold("IB base role filename is invalid")
        raw = _read_bound(root, path, maximum=512 * 1024 * 1024)
        if _digest(raw) != {"sha256": role["sha256"], "size_bytes": role["size_bytes"]}:
            raise IbCycleRoleHold("IB base role bytes changed")
    if (Path(roles[1]["relative_path"]).name.removesuffix(".tar.gz")
            != Path(roles[2]["relative_path"]).name.removesuffix(".csv")):
        raise IbCycleRoleHold("IB link archive and CSV name disagree")
    return _BASE_ROLES


def inspect_completed_ib_cycle_roles(
    store, *, http_root: Path | str, sequence: int,
) -> IbCycleRoleGap | IbCycleRoleSource:
    """Replay the completed IB child, preserving HOLD on absent producer roles."""
    try:
        if type(sequence) is not int or sequence < 1:
            raise IbCycleRoleHold("IB cycle sequence is invalid")
        if (not isinstance(http_root, (str, Path)) or not str(http_root)
                or not Path(http_root).is_absolute()):
            raise IbCycleRoleHold("IB HTTP root is not absolute")
        root = Path(http_root).resolve(strict=True)
        if (not root.is_dir() or Path(store.root_status_dir) != root / "monitor/status"
                or store.scope != "prod"):
            raise IbCycleRoleHold("IB store is not bound to this prod HTTP root")
        cycles = read_completed_cycle_evidence(store)
        cycle = next((item for item in cycles if item.sequence == sequence), None)
        if (cycle is None or not cycle.qualifying or cycle.scope != "prod"
                or cycle.source_slots != (
                    "ethernet/prod", "infiniband/prod", "nvlink/prod",
                )):
            raise IbCycleRoleHold("IB cycle is not a complete prod collector cycle")
        completion, completion_sha = _read_record(store.completion_path(sequence))
        if completion_sha != cycle.completion_sha256:
            raise IbCycleRoleHold("IB completion changed during inspection")
        identity = store._validate_start_record(
            _read_record(store.start_path(sequence))[0], sequence,
        )
        store._validate_launch_record(
            _read_record(store.launch_path(sequence))[0], identity,
        )
        validated = store._validate_completion_record(completion, identity)
        if (validated["outcome"] != "cycle_completed"
                or identity["cycle_id"] != cycle.cycle_id
                or identity["project_key"] != cycle.project_key):
            raise IbCycleRoleHold("IB cycle identity or outcome changed")
        outcomes = validated["run_result"]["outcomes"]
        if (len(outcomes) != 3 or tuple(item["source_slot"] for item in outcomes)
                != cycle.source_slots or any(item["outcome"] != "accepted"
                                             for item in outcomes)):
            raise IbCycleRoleHold("IB collector has incomplete child outcomes")
        child = outcomes[1]["child_result"]
        if (child["source_slot"] != "infiniband/prod"
                or child["state"] != "success" or child["failed_count"] != 0
                or child["planned"] != child["succeeded"]):
            raise IbCycleRoleHold("IB child is incomplete")
        area = (root / "monitor/status/collection-cycles" / identity["project_key"]
                / "prod/switch_collection/artifacts" / f"{sequence:020d}")
        private = area / "infiniband-prod"
        inventory = _read_bound(
            root, area / "inputs/infiniband-prod.csv", maximum=1024 * 1024,
        )
        selected = _ib_inventory(inventory)
        if (len(selected) != child["planned"]
                or hashlib.sha256(inventory).hexdigest()
                != child["input_inventory_sha256"]):
            raise IbCycleRoleHold("IB frozen inventory disagrees with child")
        # This worker version records the plan digest in the completion-bound
        # envelope, not a separate plan file. Rebuild its static IB-only shape
        # from the frozen inventory rather than trusting a caller-supplied plan.
        plan_raw = canonical({
            "eth": [], "spx": [], "ib": list(selected), "nv": [],
            "dynamic_identities": [],
        })
        evidence, evidence_raw = _private_json(
            root, private / "evidence-manifest.json",
        )
        envelope, envelope_raw = _private_json(
            root, private / "identity-envelope.json",
        )
        if (_digest(evidence_raw) != child["evidence"]
                or _digest(envelope_raw) != child["envelope"]):
            raise IbCycleRoleHold("IB sidecar digest is not completion-bound")
        expected_identity = {key: identity[key] for key in (
            "project_key", "run_token", "scope", "sequence", "source", "cycle_id",
        )}
        base_envelope = {
            "identity": expected_identity, "source_slot": "infiniband/prod",
            "state": "success", "planned": len(selected),
            "succeeded": len(selected), "failed_count": 0,
            "input_inventory_sha256": hashlib.sha256(inventory).hexdigest(),
            "evidence": _digest(evidence_raw),
            "target_plan_sha256": hashlib.sha256(plan_raw).hexdigest(),
            "runtime_input_hashes": {},
        }
        protected = "ib_analysis_binding" in envelope
        expected_keys = set(base_envelope)
        if protected:
            expected_keys.update(("ib_analysis_binding", "ib_analysis_context_sha256"))
        if (set(envelope) != expected_keys
                or any(envelope[key] != value for key, value in base_envelope.items())):
            raise IbCycleRoleHold("IB envelope does not bind this worker cycle")
        if protected and (not isinstance(envelope["ib_analysis_context_sha256"], str)
                          or _HEX.fullmatch(envelope["ib_analysis_context_sha256"]) is None):
            raise IbCycleRoleHold("IB protected context digest is malformed")
        all_roles = evidence.get("roles") if set(evidence) == {"roles"} else None
        if not isinstance(all_roles, list):
            raise IbCycleRoleHold("IB role inventory is malformed")
        roles = _bound_base_roles(root, all_roles[:3] if protected else all_roles)
        source = None
        if protected:
            from monitor.collection_ib_producer import (
                IB_ROLE_NAMES, validate_ib_completion_attestation,
            )
            metadata = envelope["ib_analysis_binding"]
            required = {
                "run_id", "node", "authority_sha256",
                "expected_topology_sha256", "attestation_sha256",
            }
            if (type(metadata) is not dict or set(metadata) != required
                    or len(all_roles) != 3 + len(IB_ROLE_NAMES)
                    or tuple(item.get("role") if type(item) is dict else None
                             for item in all_roles[3:]) != IB_ROLE_NAMES
                    or any(type(metadata[key]) is not str for key in required)
                    or any(_HEX.fullmatch(metadata[key]) is None for key in (
                        "authority_sha256", "expected_topology_sha256",
                        "attestation_sha256",
                    ))):
                raise IbCycleRoleHold("IB protected role binding is malformed")
            binding = {**metadata, "roles": all_roles[3:]}
            observed = validate_ib_completion_attestation(
                identity, binding, http_root=root,
            )
            if observed != all_roles[3:]:
                raise IbCycleRoleHold("IB protected replay differs from worker evidence")
            for role in observed:
                relative = role["relative_path"]
                raw = _read_bound(root, _safe_child(root, relative),
                                  maximum=512 * 1024 * 1024)
                if _digest(raw) != {
                    "sha256": role["sha256"], "size_bytes": role["size_bytes"],
                }:
                    raise IbCycleRoleHold("IB protected role bytes changed after replay")
            source = IbCycleRoleSource(
                cycle_id=cycle.cycle_id, sequence=sequence,
                completion_sha256=completion_sha,
                evidence_sha256=hashlib.sha256(evidence_raw).hexdigest(),
                roles=roles + IB_ROLE_NAMES,
                report_relative_path=observed[3]["relative_path"],
                report_sha256=observed[3]["sha256"],
                expected_topology_sha256=metadata["expected_topology_sha256"],
                attestation_sha256=metadata["attestation_sha256"],
            )
        # Verify the chain and sidecar identity again before returning a preview.
        later = read_completed_cycle_evidence(store)
        same = next((item for item in later if item.sequence == sequence), None)
        if (same != cycle or _read_record(store.completion_path(sequence))[1] != completion_sha
                or _digest(_private_json(root, private / "evidence-manifest.json")[1])
                != _digest(evidence_raw)
                or _digest(_private_json(root, private / "identity-envelope.json")[1])
                != _digest(envelope_raw)):
            raise IbCycleRoleHold("IB source changed during inspection")
        if source is not None:
            validate_ib_completion_attestation(identity, binding, http_root=root)
            return source
        return IbCycleRoleGap(
            cycle_id=cycle.cycle_id, sequence=sequence,
            completion_sha256=completion_sha,
            evidence_sha256=hashlib.sha256(evidence_raw).hexdigest(),
            roles=roles, missing_roles=_MISSING_ROLES,
        )
    except (OSError, TypeError, AttributeError, KeyError, ValueError) as exc:
        if isinstance(exc, IbCycleRoleHold):
            raise
        raise IbCycleRoleHold("IB cycle role source is not safe") from exc
