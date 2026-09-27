"""Fail-closed, local Ethernet report observation; not a collection cycle.

The LLDP analyzer can publish this sidecar from four frozen inputs.  A local
reader may inspect it, but only a future collector completion can bind its
digest into a governed cycle.  Nothing here grants issue-tracker qualification.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from dataclasses import dataclass
from typing import Mapping, Sequence

from tools.project_contract import (
    collection_cycle_source_slots,
    validate_collection_cycle_identity,
)


ROLES = frozenset({"dot", "archive", "inventory", "device_aliases"})
STATUSES = frozenset({
    "CONFIRMED_BOTH_SIDE", "CONFIRMED_SW_SIDE", "WRONG_PEER",
    "SW_LLDP_PRESENT", "NO_LLDP", "DOWN", "MISSING_DEVICE",
    "MISSING_INTERFACE",
})
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_DOT_EDGE = re.compile(
    r'^\s*"([^"]+)"\s*:\s*"([^"]+)"\s*--\s*'
    r'"([^"]+)"\s*:\s*"([^"]+)"'
)


class ActivitySourceHoldError(ValueError):
    """The supplied observation cannot be used even as a bound local view."""


@dataclass(frozen=True)
class EndpointObservation:
    remote_host: str
    remote_port: str


@dataclass(frozen=True)
class EthLinkObservation:
    device_a: str
    interface_a: str
    device_b: str
    interface_b: str
    status: str
    dot_line: int
    observation_a: EndpointObservation
    observation_b: EndpointObservation


@dataclass(frozen=True)
class EthActivityEvidence:
    source_sha256: dict[str, str]
    report_sha256: str
    evidence_sha256: str
    links: tuple[EthLinkObservation, ...]

    @property
    def qualified(self) -> bool:
        return False


def _hold(message: str) -> ActivitySourceHoldError:
    return ActivitySourceHoldError(message)


def _pairs_unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _hold(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str):
    raise _hold(f"invalid JSON constant: {value}")


def _regular_bytes(path: Path, *, maximum: int) -> bytes:
    try:
        named = path.lstat()
        if not stat.S_ISREG(named.st_mode) or named.st_nlink != 1:
            raise _hold("source must be a single-link regular file")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            before = os.fstat(descriptor)
            if (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino):
                raise _hold("source identity changed before read")
            if before.st_size < 0 or before.st_size > maximum:
                raise _hold("source exceeds bounded read")
            remaining = before.st_size
            parts = []
            while remaining:
                part = os.read(descriptor, min(remaining, 1024 * 1024))
                if not part:
                    raise _hold("source shortened during read")
                parts.append(part)
                remaining -= len(part)
            if os.read(descriptor, 1):
                raise _hold("source grew during read")
            after = os.fstat(descriptor)
            named_after = path.lstat()
            if (
                before.st_dev, before.st_ino, before.st_size,
                before.st_mtime_ns, before.st_ctime_ns,
            ) != (
                after.st_dev, after.st_ino, after.st_size,
                after.st_mtime_ns, after.st_ctime_ns,
            ) or (
                after.st_dev, after.st_ino, after.st_size,
                after.st_mtime_ns, after.st_ctime_ns,
            ) != (
                named_after.st_dev, named_after.st_ino, named_after.st_size,
                named_after.st_mtime_ns, named_after.st_ctime_ns,
            ):
                raise _hold("source changed during read")
            return b"".join(parts)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise _hold(f"source read failed: {exc}") from exc


def _regular_sha256(path: Path) -> str:
    # Archives can be large; hash them in bounded memory while holding one fd.
    try:
        named = path.lstat()
        if not stat.S_ISREG(named.st_mode) or named.st_nlink != 1:
            raise _hold("source must be a single-link regular file")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            before = os.fstat(descriptor)
            if (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino):
                raise _hold("source identity changed before hash")
            digest = hashlib.sha256()
            count = 0
            while True:
                part = os.read(descriptor, 1024 * 1024)
                if not part:
                    break
                digest.update(part)
                count += len(part)
            after = os.fstat(descriptor)
            named_after = path.lstat()
            if count != before.st_size or (
                before.st_dev, before.st_ino, before.st_size,
                before.st_mtime_ns, before.st_ctime_ns,
            ) != (
                after.st_dev, after.st_ino, after.st_size,
                after.st_mtime_ns, after.st_ctime_ns,
            ) or (
                after.st_dev, after.st_ino, after.st_size,
                after.st_mtime_ns, after.st_ctime_ns,
            ) != (
                named_after.st_dev, named_after.st_ino, named_after.st_size,
                named_after.st_mtime_ns, named_after.st_ctime_ns,
            ):
                raise _hold("source changed during hash")
            return digest.hexdigest()
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise _hold(f"source hash failed: {exc}") from exc


def _dot_links(raw: bytes) -> dict[frozenset[tuple[str, str]], int]:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError as exc:
        raise _hold("DOT is not UTF-8") from exc
    links = {}
    for lineno, line in enumerate(lines, 1):
        match = _DOT_EDGE.match(line)
        if match is None:
            continue
        endpoints = frozenset((
            (match.group(1).strip().casefold(), match.group(2).strip().casefold()),
            (match.group(3).strip().casefold(), match.group(4).strip().casefold()),
        ))
        if len(endpoints) != 2 or endpoints in links:
            raise _hold("DOT has duplicate or degenerate edge")
        links[endpoints] = lineno
    if not links:
        raise _hold("DOT has no endpoint edges")
    return links


def _sha_string(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise _hold(f"invalid {label} SHA256")
    return value


def validate_eth_cycle_binding(value: object) -> dict:
    """Validate an ETH slot claim; the worker chain remains the authority."""
    if not isinstance(value, dict) or set(value) != {
        "identity", "source_slot", "context_sha256"
    }:
        raise _hold("invalid Ethernet cycle binding")
    try:
        identity = validate_collection_cycle_identity(value["identity"])
        slots = collection_cycle_source_slots(identity["scope"])
    except ValueError as exc:
        raise _hold("invalid Ethernet cycle identity") from exc
    slot = value["source_slot"]
    if slot not in slots or slot not in {"ethernet/air", "ethernet/prod"}:
        raise _hold("Ethernet source slot disagrees with cycle")
    return {
        "identity": identity,
        "source_slot": slot,
        "context_sha256": _sha_string(value["context_sha256"], "worker context"),
    }


def validate_worker_eth_activity_context(context: object) -> dict:
    """Validate worker-issued ETH input names and exact frozen bytes.

    This validates a context's *shape and contents*, not its durable origin.
    Only the worker start/launch/completion chain can establish that origin.
    """
    if not isinstance(context, dict) or not {
        "identity", "source_slot", "artifacts", "activity"
    }.issubset(context):
        raise _hold("worker Ethernet activity context is incomplete")
    activity = context["activity"]
    base_keys = {
        "schema_version", "source_slot", "topology", "sources", "sidecar_path"
    }
    if not isinstance(activity, dict) or set(activity) not in (
        base_keys, base_keys | {"derivation_sources", "selected_workbook_name"}
    ) or type(activity["schema_version"]) is not int \
            or activity["schema_version"] != 1:
        raise _hold("worker Ethernet activity shape is invalid")
    identity = validate_eth_cycle_binding({
        "identity": context["identity"],
        "source_slot": context["source_slot"],
        "context_sha256": hashlib.sha256(_canonical_context(context)).hexdigest(),
    })["identity"]
    if activity["source_slot"] != context["source_slot"]:
        raise _hold("worker Ethernet activity slot changed")
    artifacts = context["artifacts"]
    if not isinstance(artifacts, dict) or set(artifacts) != {
        "evidence", "envelope", "input_inventory"
    }:
        raise _hold("worker Ethernet artifact bindings are invalid")
    private = Path(artifacts["input_inventory"]).parent
    stem = context["source_slot"].replace("/", "-")
    expected = {
        "topology": private / f"{stem}.p2p.xlsx",
        "dot": private / f"{stem}.dot",
        "inventory": private / f"{stem}.lldp-inventory.log",
        "device_aliases": private / f"{stem}.aliases.json",
    }
    sources = activity["sources"]
    if not isinstance(sources, dict) or set(sources) != {
        "dot", "inventory", "device_aliases"
    } or activity["sidecar_path"] != str(private / f"{stem}.activity.json"):
        raise _hold("worker Ethernet source bindings are invalid")
    derivation = activity.get("derivation_sources", {})
    if "derivation_sources" in activity:
        selected_name = activity["selected_workbook_name"]
        if context["source_slot"] != "ethernet/prod" \
                or not isinstance(selected_name, str) \
                or not selected_name.lower().endswith(".xlsx") \
                or Path(selected_name).name != selected_name \
                or not isinstance(derivation, dict) or set(derivation) != {
                    "port_mapping", "splitter_profiles"
                }:
            raise _hold("worker P2P derivation bindings are invalid")
        expected.update({
            "port_mapping": private / f"{stem}.port-mapping.log",
            "splitter_profiles": private / f"{stem}.splitter-profiles.json",
        })
    for role, entry in {**sources, **derivation, "topology": activity["topology"]}.items():
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"} \
                or entry["path"] != str(expected[role]) \
                or _regular_sha256(expected[role]) != _sha_string(entry["sha256"], role):
            raise _hold(f"worker Ethernet {role} frozen source changed")
    return {
        "identity": identity,
        "source_slot": context["source_slot"],
        "context_sha256": hashlib.sha256(_canonical_context(context)).hexdigest(),
    }


def _canonical_context(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def read_worker_eth_activity_context_fd(descriptor: int) -> tuple[dict, dict]:
    """Read an inherited anonymous regular FD without changing its offset."""
    try:
        if isinstance(descriptor, bool) or not isinstance(descriptor, int) \
                or descriptor < 0:
            raise _hold("worker context descriptor is invalid")
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 1024 * 1024:
            raise _hold("worker context descriptor is not bounded regular data")
        raw = os.pread(descriptor, before.st_size + 1, 0)
        after = os.fstat(descriptor)
        if len(raw) != before.st_size or (
            before.st_dev, before.st_ino, before.st_size,
            before.st_mtime_ns, before.st_ctime_ns,
        ) != (
            after.st_dev, after.st_ino, after.st_size,
            after.st_mtime_ns, after.st_ctime_ns,
        ):
            raise _hold("worker context changed during FD read")
        context = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs_unique,
                             parse_constant=_reject_constant)
        if raw != _canonical_context(context):
            raise _hold("worker context is not canonical")
        return context, validate_worker_eth_activity_context(context)
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        if isinstance(exc, ActivitySourceHoldError):
            raise
        raise _hold("worker context FD is unusable") from exc


def _observation(value: object) -> EndpointObservation:
    if not isinstance(value, dict) or set(value) != {"remote_host", "remote_port"}:
        raise _hold("invalid endpoint observation")
    if any(not isinstance(value[key], str) for key in value):
        raise _hold("endpoint observation fields must be strings")
    return EndpointObservation(value["remote_host"], value["remote_port"])


def load_eth_activity_evidence(
    evidence_path: Path,
    *,
    sources: Mapping[str, Path],
    report_path: Path,
    expected_evidence_sha256: str | None = None,
    expected_cycle_completion_sha256: str | None = None,
    expected_network: str = "eth",
    expected_cycle_binding: Mapping[str, object] | None = None,
) -> EthActivityEvidence:
    """Read a frozen local observation without promoting it to a cycle."""
    if expected_network != "eth" or expected_cycle_completion_sha256 is not None:
        raise _hold("IB or collection-cycle qualification is not bound")
    if set(sources) != ROLES:
        raise _hold("exact four Ethernet source roles required")
    raw = _regular_bytes(Path(evidence_path), maximum=16 * 1024 * 1024)
    evidence_sha = hashlib.sha256(raw).hexdigest()
    if expected_evidence_sha256 is not None and (
        _sha_string(expected_evidence_sha256, "expected evidence") != evidence_sha
    ):
        raise _hold("evidence digest changed")
    try:
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs_unique,
                             parse_constant=_reject_constant)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise _hold("invalid evidence JSON") from exc
    required = {"schema_version", "kind", "sources", "report", "links"}
    if expected_cycle_binding is not None:
        required.add("cycle_binding")
    if not isinstance(payload, dict) or set(payload) != required \
            or type(payload["schema_version"]) is not int \
            or payload["schema_version"] != (2 if expected_cycle_binding is not None else 1) \
            or payload["kind"] != "eth_lldp_report_observation":
        raise _hold("invalid Ethernet evidence schema")
    if expected_cycle_binding is not None and (
        validate_eth_cycle_binding(payload["cycle_binding"])
        != validate_eth_cycle_binding(dict(expected_cycle_binding))
    ):
        raise _hold("Ethernet evidence cycle binding mismatch")
    described = payload["sources"]
    if not isinstance(described, dict) or set(described) != ROLES:
        raise _hold("incomplete Ethernet source roles")
    actual_sha = {}
    dot_raw: bytes | None = None
    for role in sorted(ROLES):
        entry = described[role]
        path = Path(sources[role])
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"} \
                or entry["path"] != str(path):
            raise _hold(f"{role} source path is not explicitly bound")
        expected = _sha_string(entry["sha256"], role)
        if role == "dot":
            dot_raw = _regular_bytes(path, maximum=16 * 1024 * 1024)
            actual = hashlib.sha256(dot_raw).hexdigest()
        else:
            actual = _regular_sha256(path)
        if actual != expected:
            raise _hold(f"{role} source digest changed")
        actual_sha[role] = actual
    report = payload["report"]
    if not isinstance(report, dict) or set(report) != {"path", "sha256"} \
            or report["path"] != str(report_path):
        raise _hold("report path is not explicitly bound")
    expected_report = _sha_string(report["sha256"], "report")
    if _regular_sha256(Path(report_path)) != expected_report:
        raise _hold("report digest changed")
    if dot_raw is None:
        raise _hold("DOT source bytes were not captured")
    dot_edges = _dot_links(dot_raw)
    rows = payload["links"]
    if not isinstance(rows, list):
        raise _hold("links must be a list")
    links = []
    observed_edges = set()
    for row in rows:
        required = {
            "device_a", "interface_a", "device_b", "interface_b", "status",
            "dot_line", "observation_a", "observation_b",
        }
        if not isinstance(row, dict) or set(row) != required:
            raise _hold("invalid link record")
        if any(not isinstance(row[key], str) or not row[key].strip()
               for key in ("device_a", "interface_a", "device_b", "interface_b")):
            raise _hold("missing endpoint identity")
        if row["status"] not in STATUSES or type(row["dot_line"]) is not int:
            raise _hold("invalid link status or DOT line")
        endpoints = frozenset((
            (row["device_a"].strip().casefold(), row["interface_a"].strip().casefold()),
            (row["device_b"].strip().casefold(), row["interface_b"].strip().casefold()),
        ))
        if endpoints not in dot_edges or endpoints in observed_edges \
                or dot_edges[endpoints] != row["dot_line"]:
            raise _hold("link endpoint is not one unique DOT edge")
        observed_edges.add(endpoints)
        links.append(EthLinkObservation(
            row["device_a"], row["interface_a"], row["device_b"],
            row["interface_b"], row["status"], row["dot_line"],
            _observation(row["observation_a"]),
            _observation(row["observation_b"]),
        ))
    for role in sorted(ROLES):
        if _regular_sha256(Path(sources[role])) != actual_sha[role]:
            raise _hold(f"{role} source changed during edge validation")
    if _regular_sha256(Path(report_path)) != expected_report:
        raise _hold("report changed during edge validation")
    return EthActivityEvidence(actual_sha, expected_report, evidence_sha, tuple(links))


def write_eth_activity_evidence(
    evidence_path: Path,
    *,
    sources: Mapping[str, Path],
    source_sha256: Mapping[str, str],
    report_path: Path,
    result_records: Sequence[dict],
    cycle_binding: Mapping[str, object] | None = None,
) -> None:
    """Publish an opt-in local sidecar after a real LLDP report exists."""
    if set(sources) != ROLES or set(source_sha256) != ROLES:
        raise _hold("exact four Ethernet source roles required")
    for role in sorted(ROLES):
        expected = _sha_string(source_sha256[role], role)
        if _regular_sha256(Path(sources[role])) != expected:
            raise _hold(f"{role} source changed before evidence publication")
    links = []
    fields = (
        "device_a", "interface_a", "device_b", "interface_b", "status",
        "dot_line", "observation_a", "observation_b",
    )
    for record in result_records:
        links.append({
            key: (
                {subkey: record[key][subkey] for subkey in ("remote_host", "remote_port")}
                if key.startswith("observation_") else record[key]
            )
            for key in fields
        })
    payload = {
        "schema_version": 2 if cycle_binding is not None else 1,
        "kind": "eth_lldp_report_observation",
        "sources": {
            role: {
                "path": str(sources[role]),
                "sha256": _sha_string(source_sha256[role], role),
            }
            for role in sorted(ROLES)
        },
        "report": {
            "path": str(report_path),
            "sha256": _regular_sha256(Path(report_path)),
        },
        "links": links,
    }
    if cycle_binding is not None:
        payload["cycle_binding"] = validate_eth_cycle_binding(dict(cycle_binding))
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False).encode("utf-8")
    target = Path(evidence_path)
    if target.exists() or target.is_symlink() or not target.parent.is_dir() \
            or target.parent.is_symlink():
        raise _hold("evidence output must be a new file in a real directory")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=target.parent, prefix=".eth-evidence-",
                                         suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, target)
        temporary.unlink()
        temporary = None
        directory_flags = (
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        directory_fd = os.open(target.parent, directory_flags)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        # Once linked, a failed durability barrier leaves an uncertain target.
        # Even an inode check before unlink would race another same-UID writer
        # replacing that name.  Return HOLD and preserve it for recovery.
        raise _hold(f"evidence publication failed: {exc}") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
