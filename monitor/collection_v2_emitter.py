#!/usr/bin/env python3
"""Publish one worker-bound Switch collection child from exact run artifacts.

This helper receives only paths; the cycle identity is read from a private
context file copied from an anonymous worker descriptor by the real cron.
The sidecar pair is prepared in one private directory and made visible with
one directory rename. No legacy marker is upgraded by the worker.
"""

from __future__ import annotations

import argparse
import csv
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))
from project_contract import (  # noqa: E402
    _validate_collection_cycle_legacy_result,
    validate_collection_cycle_identity,
    validate_collection_cycle_result,
)

PREFIX = "[HTTP_ZTP_TASK_RESULT] "
ROLE_NAMES = ("info_archive", "link_archive", "link_csv")
SOURCE = {
    "ethernet": ("eth-info", "spx-link", "spx-link"),
    "infiniband": ("ib-info", "ib-link", "ib-link"),
    "nvlink": ("nvsw-info", "nvsw-link", "nvsw-link"),
}


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def digest(content: bytes) -> dict[str, object]:
    return {"sha256": hashlib.sha256(content).hexdigest(), "size_bytes": len(content)}


def regular_member(path: Path, area: str, stem: str, suffix: str) -> tuple[str, bytes]:
    relative = path.relative_to(ROOT).as_posix()
    pure = PurePosixPath(relative)
    if (pure.is_absolute() or str(pure) != relative
            or any(part in {"", ".", ".."} for part in relative.split("/"))
            or not relative.startswith(f"{area}/monitor/{stem}/")
            or not re.fullmatch(r"[0-9]{8}-[0-9]{4}(?:-(?:air|prod))?" + re.escape(suffix), path.name)):
        raise ValueError("collection artifact location is invalid")
    current = ROOT
    for part in pure.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("collection artifact traverses a symlink")
    if not current.is_file():
        raise ValueError("collection artifact is missing")
    return relative, current.read_bytes()


def inventory_selection(content: bytes, slot: str) -> tuple[tuple[str, ...], bool]:
    rows = list(csv.DictReader(io.StringIO(content.decode("utf-8"))))
    if not rows or not {"hostname", "type", "eth0_ip"}.issubset(rows[0]):
        raise ValueError("frozen inventory schema is invalid")
    area, scope = slot.split("/", 1)
    selected_types = {
        "ethernet": {"air"} if scope == "air" else {"eth", "eth_spx", "spx"},
        "infiniband": {"ib"}, "nvlink": {"nvl"},
    }[area]
    selected = [row for row in rows if row["type"].strip().lower() in selected_types]
    names = tuple(row["hostname"].strip() for row in selected)
    if (not names or any(not name or not row["eth0_ip"].strip()
                         for name, row in zip(names, selected))
            or len({name.casefold() for name in names}) != len(names)):
        raise ValueError("frozen inventory selected zero or invalid targets")
    link_selected = area != "ethernet" or any(
        row["type"].strip().lower() in {"eth_spx", "spx"} for row in selected
    )
    return names, link_selected


def verify_runtime_snapshots(context: dict, inventory_path: Path) -> None:
    hashes = context["runtime_input_hashes"]
    if not isinstance(hashes, dict):
        raise ValueError("runtime source hashes are invalid")
    allowed = {"leases": ".leases", "air_json": ".air.json",
               "dhcp_log": ".dhcp.log"}
    if not set(hashes).issubset(set(allowed) | {"journal_derived_rows"}):
        raise ValueError("runtime source hash keys are invalid")
    for key, suffix in allowed.items():
        if key not in hashes:
            continue
        path = inventory_path.with_suffix(suffix)
        if path.is_symlink() or not path.is_file():
            raise ValueError("runtime source snapshot is not a regular file")
        if hashlib.sha256(path.read_bytes()).hexdigest() != hashes[key]:
            raise ValueError("runtime source changed after worker snapshot")
    if "journal_derived_rows" in hashes and hashlib.sha256(
        canonical(context["prod_runtime_rows"])
    ).hexdigest() != hashes["journal_derived_rows"]:
        raise ValueError("journal-derived rows changed after worker snapshot")


def build_result(args: argparse.Namespace) -> tuple[dict, bytes, bytes, Path]:
    context = json.loads(args.context_file.read_text(encoding="utf-8"))
    shapes = ({
        "identity", "source_slot", "artifacts", "input_inventory_sha256"
    }, {
        "identity", "source_slot", "artifacts", "input_inventory_sha256",
        "target_plan", "target_plan_sha256", "air_dynamic_rows",
        "prod_runtime_rows", "runtime_input_hashes"
    })
    optional_shapes = (
        *shapes, *(shape | {"activity"} for shape in shapes),
        *(shape | {"ib_analysis"} for shape in shapes),
    )
    if not isinstance(context, dict) or set(context) not in optional_shapes:
        raise ValueError("worker context shape is invalid")
    identity = validate_collection_cycle_identity(context["identity"])
    slot = context["source_slot"]
    if slot not in {"ethernet/air", "ethernet/prod", "infiniband/prod", "nvlink/prod"}:
        raise ValueError("collection source slot is invalid")
    area, scope = slot.split("/", 1)
    if scope != identity["scope"] and identity["scope"] != "all":
        raise ValueError("collection slot scope disagrees with cycle")
    paths = context["artifacts"]
    if not isinstance(paths, dict) or set(paths) != {
        "evidence", "envelope", "input_inventory"
    }:
        raise ValueError("artifact binding shape is invalid")
    slot_dir = (ROOT / "monitor/status/collection-cycles" / identity["project_key"]
                / identity["scope"] / "switch_collection" / "artifacts"
                / f"{identity['sequence']:020d}" / slot.replace("/", "-"))
    expected = {
        "evidence": str(slot_dir / "evidence-manifest.json"),
        "envelope": str(slot_dir / "identity-envelope.json"),
        "input_inventory": str(slot_dir.parent / "inputs" /
                               f"{slot.replace('/', '-')}.csv"),
    }
    if paths != expected:
        raise ValueError("artifact bindings do not match private slot")
    frozen = Path(paths["input_inventory"]).read_bytes()
    if hashlib.sha256(frozen).hexdigest() != context["input_inventory_sha256"]:
        raise ValueError("frozen inventory changed after worker allocation")
    if "runtime_input_hashes" in context:
        verify_runtime_snapshots(context, Path(paths["input_inventory"]))
    static_selected, static_link_selected = inventory_selection(frozen, slot)
    if "target_plan" in context:
        plan = context["target_plan"]
        if not isinstance(plan, dict) or set(plan) != {
            "eth", "spx", "ib", "nv", "dynamic_identities"
        } or digest(canonical(plan))["sha256"] != context["target_plan_sha256"]:
            raise ValueError("frozen target plan is invalid")
        active_key = {"ethernet": "eth", "infiniband": "ib", "nvlink": "nv"}[area]
        entries = plan[active_key]
        if not isinstance(entries, list) or any(not isinstance(row, str) or "|" not in row
                                                 for row in entries):
            raise ValueError("frozen target plan entries are invalid")
        selected = tuple(row.split("|", 1)[0] for row in entries)
        if (not selected or len(set(name.casefold() for name in selected)) != len(selected)
                or not set(static_selected).issubset(set(selected))):
            raise ValueError("frozen target plan disagrees with static inventory")
        link_selected = area != "ethernet" or bool(plan["spx"])
        if area == "ethernet" and static_link_selected != link_selected:
            raise ValueError("frozen target plan link applicability changed")
    else:
        selected, link_selected = static_selected, static_link_selected
    planned = tuple(line.strip() for line in args.planned_file.read_text(
        encoding="utf-8").splitlines() if line.strip())
    if planned != selected:
        raise ValueError("collector target set differs from frozen worker selection")
    markers = [line.removeprefix(PREFIX) for line in args.legacy_result_file.read_text(
        encoding="utf-8").splitlines() if line.startswith(PREFIX)]
    if len(markers) != 1:
        raise ValueError("legacy collector result is missing or duplicated")
    legacy = _validate_collection_cycle_legacy_result(json.loads(markers[0]))
    if legacy["state"] == "failed" or legacy["planned"] != len(selected):
        raise ValueError("failed or inconsistent collector cannot publish v2")

    supplied = (args.info, args.link, args.csv)
    roles: list[dict[str, object]] = []
    for index, role in enumerate(ROLE_NAMES):
        applicable = index == 0 or link_selected
        if not applicable:
            if supplied[index] is not None:
                raise ValueError("unexpected inapplicable artifact")
            roles.append({"role": role, "state": "not_applicable",
                          "relative_path": None, "sha256": None, "size_bytes": None})
            continue
        if supplied[index] is None:
            raise ValueError("required archive or CSV is missing")
        suffix = ".csv" if index == 2 else ".tar.gz"
        relative, content = regular_member(
            supplied[index], area, SOURCE[area][index], suffix,
        )
        roles.append({"role": role, "state": "present", "relative_path": relative,
                      **digest(content)})
    if roles[1]["state"] == "present":
        if (Path(roles[1]["relative_path"]).name.removesuffix(".tar.gz") !=
                Path(roles[2]["relative_path"]).name.removesuffix(".csv")):
            raise ValueError("link archive and CSV timestamps disagree")
    activity_binding = None
    activity_path = getattr(args, "activity", None)
    if "activity" in context:
        if area != "ethernet" or activity_path is None or str(activity_path) != context["activity"].get("sidecar_path"):
            raise ValueError("Ethernet activity sidecar does not match worker context")
        from monitor.issue_tracker_activity_source import (  # noqa: E402
            load_eth_activity_evidence, validate_worker_eth_activity_context,
        )
        activity_binding = validate_worker_eth_activity_context(context)
        archive = roles[0]
        if archive["state"] != "present":
            raise ValueError("Ethernet activity archive is absent")
        sources = {
            role: Path(context["activity"]["sources"][role]["path"])
            for role in ("dot", "inventory", "device_aliases")
        }
        sources["archive"] = ROOT / archive["relative_path"]
        raw_activity = activity_path.read_bytes()
        payload = json.loads(raw_activity)
        report_path = Path(payload["report"]["path"])
        expected_report = (
            ROOT / "tools/lldp-analyze-tool/99-output-p2p"
            / (sources["archive"].name.removesuffix(".tar.gz")
               + "-ethernet-topology-validation.xlsx")
        ).resolve()
        if report_path != expected_report:
            raise ValueError("Ethernet activity report is not the exact archive output")
        load_eth_activity_evidence(
            activity_path, sources=sources, report_path=report_path,
            expected_evidence_sha256=hashlib.sha256(raw_activity).hexdigest(),
            expected_cycle_binding=activity_binding,
        )
        if (payload["sources"]["archive"] != {
                "path": str(sources["archive"]), "sha256": archive["sha256"]
        } or digest(sources["archive"].read_bytes()) != {
                "sha256": archive["sha256"], "size_bytes": archive["size_bytes"]
        }):
            raise ValueError("Ethernet activity archive disagrees with info role")
        roles.append({
            "role": "activity_observation", "state": "present",
            "relative_path": (slot_dir / "activity-observation.json").relative_to(ROOT).as_posix(),
            **digest(raw_activity),
        })
    elif activity_path is not None:
        raise ValueError("unexpected Ethernet activity sidecar")
    ib_analysis = context.get("ib_analysis")
    if ib_analysis is not None:
        if slot != "infiniband/prod" or activity_binding is not None:
            raise ValueError("IB analysis is outside prod IB slot")
        from monitor.collection_ib_producer import validate_ib_completion_attestation
        roles.extend(validate_ib_completion_attestation(
            identity, ib_analysis, http_root=ROOT,
        ))
    evidence = canonical({"roles": roles})
    envelope_body = {
        "identity": identity, "source_slot": slot, "state": legacy["state"],
        "planned": legacy["planned"], "succeeded": legacy["succeeded"],
        "failed_count": legacy["failed_count"],
        "input_inventory_sha256": hashlib.sha256(frozen).hexdigest(),
        "evidence": digest(evidence),
    }
    if "target_plan_sha256" in context:
        envelope_body["target_plan_sha256"] = context["target_plan_sha256"]
        envelope_body["runtime_input_hashes"] = context["runtime_input_hashes"]
    if activity_binding is not None:
        envelope_body["activity_context_sha256"] = activity_binding["context_sha256"]
    if ib_analysis is not None:
        envelope_body["ib_analysis_context_sha256"] = digest(canonical(context))["sha256"]
        envelope_body["ib_analysis_binding"] = {
            key: ib_analysis[key] for key in (
                "run_id", "node", "authority_sha256", "expected_topology_sha256",
                "attestation_sha256",
            )
        }
    envelope = canonical(envelope_body)
    child = {
        **legacy, **identity, "schema_version": 2, "source_slot": slot,
        "evidence": digest(evidence), "envelope": digest(envelope),
        "input_inventory_sha256": hashlib.sha256(frozen).hexdigest(),
    }
    validate_collection_cycle_result(child, expected_identity=identity,
                                     expected_slot=slot)
    return child, evidence, envelope, slot_dir


def _publication_parent(
    sidecar_dir: Path, *, create_missing: bool = True,
) -> tuple[int, str]:
    """Open the canonical status ancestry without following a swapped component."""
    try:
        parts = sidecar_dir.relative_to(ROOT).parts
    except ValueError as exc:
        raise ValueError("collection sidecar is outside the project") from exc
    if (
        len(parts) != 9
        or parts[:3] != ("monitor", "status", "collection-cycles")
        or re.fullmatch(r"[0-9a-f]{64}", parts[3]) is None
        or parts[4] not in {"air", "prod", "all"}
        or parts[5:7] != ("switch_collection", "artifacts")
        or re.fullmatch(r"[0-9]{20}", parts[7]) is None
        or parts[8] not in {
            "ethernet-air", "ethernet-prod", "infiniband-prod", "nvlink-prod"
        }
    ):
        raise ValueError("collection sidecar slot is not canonical")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise OSError("platform lacks no-follow directory publication")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent_fd = os.open(ROOT, flags)
    try:
        for part in parts[:-1]:
            try:
                child_fd = os.open(part, flags, dir_fd=parent_fd)
            except FileNotFoundError:
                if not create_missing:
                    raise
                os.mkdir(part, mode=0o700, dir_fd=parent_fd)
                child_fd = os.open(part, flags, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = child_fd
        return parent_fd, parts[-1]
    except BaseException:
        os.close(parent_fd)
        raise


def _assert_publication_parent_bound(sidecar_dir: Path, parent_fd: int) -> None:
    """Detect a visible rebind; not exclusion against a noncooperating rename."""
    current_fd, _leaf = _publication_parent(sidecar_dir, create_missing=False)
    try:
        held = os.fstat(parent_fd)
        current = os.fstat(current_fd)
        if (held.st_dev, held.st_ino) != (current.st_dev, current.st_ino):
            raise ValueError("collection publication status ancestry changed")
    finally:
        os.close(current_fd)


def _activity_bytes(parent_fd: int, leaf: str) -> bytes:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    inputs_fd = os.open("inputs", flags, dir_fd=parent_fd)
    try:
        source_fd = os.open(
            f"{leaf}.activity.json", os.O_RDONLY | os.O_NOFOLLOW,
            dir_fd=inputs_fd,
        )
        try:
            source = os.fstat(source_fd)
            if not stat.S_ISREG(source.st_mode) or source.st_nlink != 1:
                raise ValueError("Ethernet activity sidecar is not single-link regular")
            with os.fdopen(source_fd, "rb", closefd=False) as stream:
                return stream.read()
        finally:
            os.close(source_fd)
    finally:
        os.close(inputs_fd)


def publish(sidecar_dir: Path, evidence: bytes, envelope: bytes) -> None:
    parent_fd, leaf = _publication_parent(sidecar_dir)
    stage_name: str | None = None
    stage_fd: int | None = None
    published = False
    renamed = False
    members = [("evidence-manifest.json", evidence),
               ("identity-envelope.json", envelope)]
    try:
        _assert_publication_parent_bound(sidecar_dir, parent_fd)
        for _attempt in range(16):
            candidate = ".v2-evidence-" + secrets.token_hex(16)
            try:
                os.mkdir(candidate, mode=0o700, dir_fd=parent_fd)
                stage_name = candidate
                break
            except FileExistsError:
                continue
        if stage_name is None:
            raise OSError("cannot reserve a private collection evidence stage")
        stage_fd = os.open(
            stage_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        roles = json.loads(evidence)["roles"]
        if len(roles) == 4:
            role = roles[3]
            if role["role"] != "activity_observation" or role["state"] != "present":
                raise ValueError("Ethernet activity role is invalid")
            raw = _activity_bytes(parent_fd, leaf)
            if digest(raw) != {"sha256": role["sha256"],
                               "size_bytes": role["size_bytes"]}:
                raise ValueError("Ethernet activity sidecar changed before publication")
            members.append(("activity-observation.json", raw))
        elif len(roles) == 9:
            from monitor.collection_ib_producer import (
                IB_ROLE_NAMES, validate_ib_completion_attestation,
            )
            if [item.get("role") for item in roles[3:]] != list(IB_ROLE_NAMES):
                raise ValueError("IB analysis roles are not exact")
            bound_envelope = json.loads(envelope)
            metadata = bound_envelope.get("ib_analysis_binding")
            if not isinstance(metadata, dict):
                raise ValueError("IB analysis binding is missing from envelope")
            binding = {**metadata, "roles": roles[3:]}
            validate_ib_completion_attestation(
                bound_envelope["identity"], binding, http_root=ROOT,
            )
        elif len(roles) != 3:
            raise ValueError("collection evidence role count is invalid")
        for name, content in members:
            descriptor = os.open(
                name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600, dir_fd=stage_fd,
            )
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
        os.fsync(stage_fd)
        lock_fd = os.open(
            ".publish.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
            0o600, dir_fd=parent_fd,
        )
        try:
            lock_stat = os.fstat(lock_fd)
            if not stat.S_ISREG(lock_stat.st_mode) or lock_stat.st_nlink != 1:
                raise ValueError("collection publication lock is not single-link regular")
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            try:
                os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ValueError("collection sidecar slot already exists")
            _assert_publication_parent_bound(sidecar_dir, parent_fd)
            # The directory FDs, not the path recheck, guard this rename from
            # following a rebound status path; keep both fd arguments.
            os.rename(
                stage_name, leaf,
                src_dir_fd=parent_fd, dst_dir_fd=parent_fd,
            )
            renamed = True
            os.fsync(parent_fd)
            _assert_publication_parent_bound(sidecar_dir, parent_fd)
            published = True
        finally:
            os.close(lock_fd)
    finally:
        try:
            try:
                if not published and stage_fd is not None:
                    for name, _content in members:
                        try:
                            os.unlink(name, dir_fd=stage_fd)
                        except FileNotFoundError:
                            pass
            finally:
                if stage_fd is not None:
                    os.close(stage_fd)
            if not published and stage_name is not None:
                os.rmdir(leaf if renamed else stage_name, dir_fd=parent_fd)
        finally:
            os.close(parent_fd)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--context-file", type=Path, required=True,
                        help="Worker-bound collection cycle context JSON path.")
    parser.add_argument("--legacy-result-file", type=Path, required=True,
                        help="Collector output containing its legacy result marker.")
    parser.add_argument("--planned-file", type=Path, required=True,
                        help="Newline-delimited frozen collector target list.")
    parser.add_argument("--info", type=Path,
                        help="Collector info archive path for the source slot.")
    parser.add_argument("--link", type=Path,
                        help="Collector link archive path when applicable.")
    parser.add_argument("--csv", type=Path,
                        help="Collector link CSV path when applicable.")
    parser.add_argument("--activity", type=Path,
                        help="Worker-bound Ethernet activity sidecar when applicable.")
    args = parser.parse_args()
    try:
        child, evidence, envelope, sidecar_dir = build_result(args)
        publish(sidecar_dir, evidence, envelope)
    except (OSError, ValueError, KeyError, TypeError, UnicodeError,
            json.JSONDecodeError) as exc:
        print(f"v2 evidence publication failed: {type(exc).__name__}", file=sys.stderr)
        return 1
    print(PREFIX + canonical(child).decode("utf-8").rstrip("\n"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
