"""Fail-closed deployment-owned authority prerequisite for prod IB analysis.

This module cannot run UFM or issue an IB role. A root-owned installation
record only permits a future worker to *attempt* a real same-cycle handoff;
remote-final-observed, a local report, or a caller callback never suffice.
"""

from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys

_HTTP_ROOT = Path(__file__).resolve().parent.parent
_TOOLS_ROOT = _HTTP_ROOT / "tools"
if str(_TOOLS_ROOT) not in sys.path:
    sys.path.insert(0, str(_TOOLS_ROOT))
_CONFIG_ROOT = _HTTP_ROOT / "ztp/config"
if str(_CONFIG_ROOT) not in sys.path:
    sys.path.insert(0, str(_CONFIG_ROOT))

from infra.ufm_jump_transport import BoundFarEndpoint, JumpEndpoint
from ib_topology_provenance import (
    _regular_digest, read_cvt_provenance, sidecar_path,
)
from tools.ufm_remote_producer import RemoteAgentInstall, _install
from tools.project_contract import (
    canonical_collection_cycle_json, validate_collection_cycle_identity,
)
from tools.ufm_collection_contract import collection_plan, make_run_id
from tools.ufm_collection_pipeline import run_local_iblinkinfo, validated_receipts
from tools.ufm_remote_producer import (
    VerifiedRetrievedObservation, _local_bound_digest,
    observe_and_retrieve_remote_producer,
)
from infra.ufm_jump_transport import _default_runner
from ib_topology_provenance import read_report_provenance


class IbProducerHold(ValueError):
    """A protected, exact project-bound IB producer authority is unavailable."""


_AUTHORITY_DIR = Path("/var/lib/http-ztp-container/ib-producer-authority")
_ATTESTATION_DIR = Path("/var/lib/http-ztp-container/ib-producer-attestations")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_MAX_RECORD = 16 * 1024
_ROOT_UID = 0


@dataclass(frozen=True)
class IbProducerAuthority:
    project_key: str
    project_root: Path
    lease_path: Path
    known_hosts_pin: str
    jump: JumpEndpoint
    far: BoundFarEndpoint
    install: RemoteAgentInstall
    timeout_seconds: int
    retrieval_dir: Path
    p2p_sha256: str
    cvt_sha256: str
    cvt_provenance_sha256: str


@dataclass(frozen=True)
class IbProducerAuthoritySnapshot:
    """Held source identity for a pre/post-run comparison, not completion."""

    authority: IbProducerAuthority
    sha256: str
    file_identity: tuple[int, ...]


@dataclass(frozen=True)
class IbCvtSourceObservation:
    """Source bytes only; no cycle, report role or completion authority."""

    selected_p2p: Path
    cvt: Path
    expected_topology_sha256: str
    provenance_sha256: str


def derive_ib_cycle_run_id(identity: object, *, when: dt.datetime) -> str:
    """Derive the UFM nonce from the exact worker cycle, never child input."""
    try:
        cycle = validate_collection_cycle_identity(identity)
        if cycle["scope"] not in {"prod", "all"}:
            raise IbProducerHold("IB UFM cycle is not production")
        nonce = hashlib.sha256(
            b"ib-ufm-worker-cycle-v1\0" + canonical_collection_cycle_json(cycle)
        ).hexdigest()[:16]
        return make_run_id(when, "prod", nonce)
    except (TypeError, ValueError) as exc:
        if isinstance(exc, IbProducerHold):
            raise
        raise IbProducerHold("IB UFM run-id cannot bind worker cycle") from exc


def _absolute_path(value: object) -> Path:
    if (type(value) is not str or not value.startswith("/")
            or value == "/" or "\x00" in value
            or any(part in {"", ".", ".."} for part in value[1:].split("/"))):
        raise IbProducerHold("IB authority path is not canonical absolute")
    return Path(value)


def _digest(value: object) -> str:
    if type(value) is not str or _HEX.fullmatch(value) is None:
        raise IbProducerHold("IB authority digest is invalid")
    return value


def _keys(value: object, expected: set[str]) -> dict:
    if type(value) is not dict or set(value) != expected:
        raise IbProducerHold("IB authority record schema is invalid")
    return value


def parse_ib_producer_authority(
    value: object, *, project_key: str, project_root: Path,
) -> IbProducerAuthority:
    """Parse exact owner intent; this alone grants no filesystem/remote trust."""
    try:
        if (_digest(project_key) != project_key or not isinstance(project_root, Path)
                or not project_root.is_absolute() or ".." in project_root.parts):
            raise IbProducerHold("IB worker project identity is invalid")
        record = _keys(value, {
            "schema_version", "project_key", "project_root", "lease_path",
            "known_hosts_pin", "jump", "far", "install", "timeout_seconds",
            "retrieval_dir", "p2p_sha256", "cvt_sha256",
            "cvt_provenance_sha256",
        })
        if (type(record["schema_version"]) is not int
                or record["schema_version"] != 1
                or record["project_key"] != project_key
                or _absolute_path(record["project_root"]) != project_root):
            raise IbProducerHold("IB authority is not bound to this project")
        jump_record = _keys(record["jump"], {
            "host", "user", "known_hosts", "identity",
        })
        far_record = _keys(record["far"], {
            "host", "user", "identity_evidence", "bind_interface",
        })
        install_record = _keys(record["install"], {
            "root", "python_path", "agent_sha256", "contract_sha256",
            "python_sha256",
        })
        if (type(jump_record["identity"]) is not str
                or type(far_record["identity_evidence"]) is not str
                or not far_record["identity_evidence"]):
            raise IbProducerHold("IB SSH identity selection is missing")
        jump = JumpEndpoint(
            host=jump_record["host"], user=jump_record["user"],
            known_hosts=_absolute_path(jump_record["known_hosts"]),
            identity=_absolute_path(jump_record["identity"]),
        )
        far = BoundFarEndpoint(
            host=far_record["host"], user=far_record["user"],
            identity_evidence=far_record["identity_evidence"], jump=jump,
            bind_interface=far_record["bind_interface"],
        )
        install = _install(RemoteAgentInstall(
            root=install_record["root"],
            python_path=install_record["python_path"],
            agent_sha256=install_record["agent_sha256"],
            contract_sha256=install_record["contract_sha256"],
            python_sha256=install_record["python_sha256"],
        ))
        timeout = record["timeout_seconds"]
        if type(timeout) is not int or not 1 <= timeout <= 300:
            raise IbProducerHold("IB producer timeout is invalid")
        return IbProducerAuthority(
            project_key=project_key, project_root=project_root,
            lease_path=_absolute_path(record["lease_path"]),
            known_hosts_pin=_digest(record["known_hosts_pin"]),
            jump=jump, far=far, install=install,
            timeout_seconds=timeout,
            retrieval_dir=_absolute_path(record["retrieval_dir"]),
            p2p_sha256=_digest(record["p2p_sha256"]),
            cvt_sha256=_digest(record["cvt_sha256"]),
            cvt_provenance_sha256=_digest(record["cvt_provenance_sha256"]),
        )
    except (TypeError, ValueError) as exc:
        if isinstance(exc, IbProducerHold):
            raise
        raise IbProducerHold("IB producer authority is malformed") from exc


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_nlink,
        metadata.st_uid, metadata.st_size, metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_root_owned_record(project_key: str) -> tuple[bytes, tuple[int, ...]]:
    """Open the fixed absolute ancestry with no-follow dirfds and no writes."""
    if _HEX.fullmatch(project_key) is None or not _AUTHORITY_DIR.is_absolute():
        raise IbProducerHold("IB authority selector is invalid")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) \
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    if not getattr(os, "O_DIRECTORY", 0) or not getattr(os, "O_NOFOLLOW", 0):
        raise IbProducerHold("platform cannot protect IB authority lookup")
    current = None
    try:
        current = os.open("/", directory_flags)
        for part in _AUTHORITY_DIR.parts[1:]:
            metadata = os.fstat(current)
            if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0
                    or metadata.st_mode & 0o022):
                raise IbProducerHold("IB authority parent is not root protected")
            next_fd = os.open(part, directory_flags, dir_fd=current)
            os.close(current)
            current = next_fd
        metadata = os.fstat(current)
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0
                or metadata.st_mode & 0o022):
            raise IbProducerHold("IB authority directory is not root protected")
        name = f"{project_key}.json"
        descriptor = os.open(
            name, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW,
            dir_fd=current,
        )
        try:
            before = os.fstat(descriptor)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0
                    or stat.S_IMODE(before.st_mode) != 0o600
                    or before.st_nlink != 1 or not 0 < before.st_size <= _MAX_RECORD):
                raise IbProducerHold("IB authority file is not root-owned 0600 data")
            raw = os.read(descriptor, _MAX_RECORD + 1)
            after = os.fstat(descriptor)
            named = os.stat(name, dir_fd=current, follow_symlinks=False)
            if (len(raw) != before.st_size or len(raw) > _MAX_RECORD
                    or _identity(before) != _identity(after)
                    or _identity(before) != _identity(named)):
                raise IbProducerHold("IB authority file changed during read")
            return raw, _identity(before)
        finally:
            os.close(descriptor)
    except (OSError, TypeError, ValueError) as exc:
        if isinstance(exc, IbProducerHold):
            raise
        raise IbProducerHold("protected IB authority record is unavailable") from exc
    finally:
        if current is not None:
            os.close(current)


def _pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise IbProducerHold("duplicate IB authority JSON key")
        value[key] = item
    return value


def _parse_record(raw: bytes) -> object:
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                IbProducerHold("nonfinite IB authority value")
            ),
        )
        expected = (json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            allow_nan=False,
        ) + "\n").encode("utf-8")
        if raw != expected:
            raise IbProducerHold("IB authority record is not canonical JSON")
        return value
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        if isinstance(exc, IbProducerHold):
            raise
        raise IbProducerHold("IB authority JSON is invalid") from exc


def _canonical(value: object, *, newline: bool = False) -> bytes:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True,
                     separators=(",", ":"), allow_nan=False).encode("utf-8")
    return raw + (b"\n" if newline else b"")


def load_ib_producer_authority(
    *, project_key: str, project_root: Path,
) -> IbProducerAuthoritySnapshot:
    """Load one fixed root-only record; no path override or success capability."""
    try:
        if (_digest(project_key) != project_key or not isinstance(project_root, Path)
                or not project_root.is_absolute() or ".." in project_root.parts):
            raise IbProducerHold("IB worker project identity is invalid")
        if not project_root.is_dir() or project_root.resolve(strict=True) != project_root:
            raise IbProducerHold("IB project root is not a fixed real directory")
        raw, identity = _read_root_owned_record(project_key)
        authority = parse_ib_producer_authority(
            _parse_record(raw), project_key=project_key,
            project_root=project_root,
        )
        return IbProducerAuthoritySnapshot(
            authority=authority, sha256=hashlib.sha256(raw).hexdigest(),
            file_identity=identity,
        )
    except (OSError, ValueError) as exc:
        if isinstance(exc, IbProducerHold):
            raise
        raise IbProducerHold("IB producer authority is not safely bound") from exc


def recheck_ib_producer_authority(snapshot: IbProducerAuthoritySnapshot) -> None:
    """Refuse a same-path metadata/byte swap before completion publication."""
    if type(snapshot) is not IbProducerAuthoritySnapshot:
        raise IbProducerHold("IB producer authority snapshot is invalid")
    raw, identity = _read_root_owned_record(snapshot.authority.project_key)
    if (identity != snapshot.file_identity
            or hashlib.sha256(raw).hexdigest() != snapshot.sha256
            or parse_ib_producer_authority(
                _parse_record(raw), project_key=snapshot.authority.project_key,
                project_root=snapshot.authority.project_root,
            ) != snapshot.authority):
        raise IbProducerHold("IB producer authority changed during run")


def _link_identity(path: Path) -> tuple[tuple[int, ...], str]:
    before = path.lstat()
    if not stat.S_ISLNK(before.st_mode) or before.st_nlink != 1:
        raise IbProducerHold("IB setup P2P selection is not one symlink")
    value = os.readlink(path)
    after = path.lstat()
    if _identity(before) != _identity(after):
        raise IbProducerHold("IB setup P2P selection changed during read")
    return _identity(after), value


def observe_ib_cvt_source(
    authority: IbProducerAuthority, *, http_root: Path,
) -> IbCvtSourceObservation:
    """Recheck the setup-selected actual P2P and real CVT sidecar, never qualify.

    This is only a read-only prerequisite. The worker must still freeze these
    inputs, run and retrieve the actual UFM producer, produce a report and bind
    every role to its own completed cycle before Stage L can consume anything.
    """
    try:
        if (type(authority) is not IbProducerAuthority
                or not isinstance(http_root, Path) or not http_root.is_absolute()
                or http_root.resolve(strict=True) != http_root):
            raise IbProducerHold("IB source root is not fixed")
        projects = http_root / "DAY0-Prepare"
        project = authority.project_root
        if (project.parent != projects or project.name in {"", ".", ".."}
                or project.resolve(strict=True) != project):
            raise IbProducerHold("IB CVT source project differs from worker")
        setup = http_root / "ztp/config/nvos/template/P2P"
        if setup.resolve(strict=True) != setup:
            raise IbProducerHold("IB setup P2P directory is not fixed")
        fixed = setup / "p2p.xlsx"
        outer = _link_identity(fixed)
        if (not outer[1] or os.path.isabs(outer[1])
                or Path(os.path.abspath(setup / outer[1])) != project / "p2p.xlsx"):
            raise IbProducerHold("IB fixed P2P link points outside selected project")
        selected_link = project / "p2p.xlsx"
        inner = _link_identity(selected_link)
        name = inner[1]
        if (not name or name in {".", "..", "p2p.xlsx"}
                or os.path.isabs(name) or os.path.basename(name) != name
                or not name.lower().endswith(".xlsx")):
            raise IbProducerHold("IB selected P2P workbook name is invalid")
        selected = project / name
        selected_stat = selected.lstat()
        if not stat.S_ISREG(selected_stat.st_mode) or selected_stat.st_nlink != 1:
            raise IbProducerHold("IB selected P2P workbook is not one regular file")
        output = setup / "output-p2p"
        if output.resolve(strict=True) != output:
            raise IbProducerHold("IB CVT output directory is not fixed")
        cvt = output / f"{selected.stem}-cvt.xlsx"
        cvt_stat = cvt.lstat()
        if not stat.S_ISREG(cvt_stat.st_mode) or cvt_stat.st_nlink != 1:
            raise IbProducerHold("IB selected CVT is not one regular file")
        record = read_cvt_provenance(cvt)
        p2p = record["sources"]["p2p"]
        if (p2p["path"] != str(fixed)
                or p2p["resolved_path"] != str(selected)
                or p2p["sha256"] != authority.p2p_sha256
                or record["cvt_sha256"] != authority.cvt_sha256):
            raise IbProducerHold("IB CVT provenance differs from selected P2P authority")
        provenance_sha256 = _regular_digest(sidecar_path(cvt))
        if provenance_sha256 != authority.cvt_provenance_sha256:
            raise IbProducerHold("IB CVT sidecar differs from installed authority")
        if (_link_identity(fixed) != outer or _link_identity(selected_link) != inner
                or _identity(selected.lstat()) != _identity(selected_stat)
                or _identity(cvt.lstat()) != _identity(cvt_stat)):
            raise IbProducerHold("IB P2P/CVT identity changed during observation")
        return IbCvtSourceObservation(
            selected_p2p=selected, cvt=cvt,
            expected_topology_sha256=authority.cvt_sha256,
            provenance_sha256=provenance_sha256,
        )
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
        if isinstance(exc, IbProducerHold):
            raise
        raise IbProducerHold("IB CVT source authority is unavailable") from exc


IB_ROLE_NAMES = (
    "ufm_actual_archive", "ufm_actual_log", "expected_cvt",
    "validation_report", "report_provenance", "ufm_completion_receipt",
)


def _role(path: Path, root: Path, name: str) -> dict[str, object]:
    relative = path.relative_to(root).as_posix()
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size <= 0:
        raise IbProducerHold("IB role is not one nonempty regular file")
    sha256 = _regular_digest(path)
    after = path.lstat()
    if _identity(before) != _identity(after):
        raise IbProducerHold("IB role changed during evidence capture")
    return {
        "role": name, "state": "present", "relative_path": relative,
        "sha256": sha256, "size_bytes": before.st_size,
    }


def verify_ib_completed_result(
    identity: object, *, snapshot: IbProducerAuthoritySnapshot,
    source: IbCvtSourceObservation, retrieved: VerifiedRetrievedObservation,
    final: Path, run_id: str, http_root: Path,
) -> dict[str, object]:
    """Bind actual UFM bytes, CVT, analyzer output and receipt to one cycle.

    Only the worker may call this after a protected authority observation and
    real retrieval/handoff. This function neither creates a receipt nor lets a
    caller-provided role list substitute for those independently read bytes.
    """
    try:
        cycle = validate_collection_cycle_identity(identity)
        if (type(snapshot) is not IbProducerAuthoritySnapshot
                or type(source) is not IbCvtSourceObservation
                or type(retrieved) is not VerifiedRetrievedObservation
                or type(run_id) is not str or not isinstance(final, Path)
                or not isinstance(http_root, Path) or not http_root.is_absolute()):
            raise IbProducerHold("IB completion inputs are malformed")
        timestamp = dt.datetime.strptime(run_id[:13], "%Y%m%d-%H%M").replace(
            tzinfo=dt.timezone.utc,
        )
        if run_id != derive_ib_cycle_run_id(cycle, when=timestamp):
            raise IbProducerHold("IB UFM run-id differs from worker cycle")
        authority = snapshot.authority
        project = authority.project_root
        if (cycle["project_key"] != authority.project_key
                or project.parent != http_root / "DAY0-Prepare"
                or authority.retrieval_dir != project / "99-output-ufm/incoming"):
            raise IbProducerHold("IB completion project or retrieval root differs")
        refreshed = observe_ib_cvt_source(authority, http_root=http_root)
        if refreshed != source:
            raise IbProducerHold("IB CVT source changed after producer observation")
        remote = retrieved.remote
        if (retrieved.state != "verified-retrieved"
                or remote.state != "remote-final-observed"
                or remote.kind != "iblinkinfo" or remote.run_id != run_id
                or remote.archive_path != collection_plan("iblinkinfo", run_id).ufm_remote_path
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}", remote.node)
                or type(retrieved.local_sha256) is not str
                or retrieved.local_sha256 != remote.remote_sha256):
            raise IbProducerHold("IB retrieved archive is not the worker run")
        archive_name = f"iblinkinfo_{run_id}.tar.gz"
        expected_retrieval = authority.retrieval_dir / archive_name
        expected_final = project / "99-output-ufm/runs" / run_id / remote.node
        if (retrieved.local_path != expected_retrieval or final != expected_final
                or _local_bound_digest(retrieved.local_path) != remote.remote_sha256):
            raise IbProducerHold("IB retrieved/final path or bytes are not exact")
        archive = final / archive_name
        log = final / f"iblinkinfo_{run_id}.log"
        report = final / f"iblinkinfo_{run_id}-topology-validation.xlsx"
        provenance = sidecar_path(report)
        receipt = final / "receipt.json"
        if _regular_digest(archive) != remote.remote_sha256:
            raise IbProducerHold("IB final archive differs from retrieved source")
        attestation = read_report_provenance(report)
        if (attestation["actual"]["resolved_path"] != str(log)
                or attestation["cvt"]["resolved_path"] != str(source.cvt)
                or attestation["expected_topology_sha256"]
                != source.expected_topology_sha256
                or attestation["cvt_provenance_sha256"] != source.provenance_sha256):
            raise IbProducerHold("IB analyzer report uses a different source")
        matching = [row for row in validated_receipts(project, "prod")
                    if row.get("run_id") == run_id and row.get("node") == remote.node]
        if len(matching) != 1 or _regular_digest(receipt) != hashlib.sha256(
            (json.dumps(matching[0], sort_keys=True, separators=(",", ":")) + "\n")
            .encode("utf-8")
        ).hexdigest():
            raise IbProducerHold("IB analyzer receipt is not a completed exact result")
        paths = (archive, log, source.cvt, report, provenance, receipt)
        roles = [_role(path, http_root, name)
                 for path, name in zip(paths, IB_ROLE_NAMES)]
        if (roles[0]["sha256"] != remote.remote_sha256
                or roles[2]["sha256"] != source.expected_topology_sha256):
            raise IbProducerHold("IB role bytes differ from producer inputs")
        binding = {
            "run_id": run_id, "node": remote.node,
            "authority_sha256": snapshot.sha256,
            "expected_topology_sha256": source.expected_topology_sha256,
            "roles": roles,
        }
        validate_ib_role_binding(cycle, binding, http_root=http_root)
        return binding
    except (OSError, ValueError, TypeError, KeyError, RuntimeError) as exc:
        if isinstance(exc, IbProducerHold):
            raise
        raise IbProducerHold("IB completed result cannot be independently bound") from exc


def validate_ib_role_binding(
    identity: object, binding: object, *, http_root: Path,
) -> list[dict[str, object]]:
    """Replay the persisted six-role evidence without accepting listed hashes.

    This establishes local source consistency, not that an install existed or
    an actual remote UFM ran. The worker separately holds/rechecks its protected
    authority and verified F01 retrieval when it mints this binding.
    """
    try:
        cycle = validate_collection_cycle_identity(identity)
        if (type(binding) is not dict or set(binding) != {
                "run_id", "node", "authority_sha256",
                "expected_topology_sha256", "roles",
            } or not isinstance(http_root, Path) or not http_root.is_absolute()
                or _HEX.fullmatch(binding["authority_sha256"]) is None
                or _HEX.fullmatch(binding["expected_topology_sha256"]) is None):
            raise IbProducerHold("IB role binding schema is invalid")
        run_id = binding["run_id"]
        node = binding["node"]
        if (type(run_id) is not str or type(node) is not str
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}", node) is None):
            raise IbProducerHold("IB role binding run/node is invalid")
        timestamp = dt.datetime.strptime(run_id[:13], "%Y%m%d-%H%M").replace(
            tzinfo=dt.timezone.utc,
        )
        if run_id != derive_ib_cycle_run_id(cycle, when=timestamp):
            raise IbProducerHold("IB replay run-id differs from cycle")
        supplied = binding["roles"]
        if (type(supplied) is not list or len(supplied) != 6
                or [item.get("role") if type(item) is dict else None
                    for item in supplied] != list(IB_ROLE_NAMES)):
            raise IbProducerHold("IB role sequence is invalid")
        archive_relative = supplied[0]["relative_path"]
        archive_parts = Path(archive_relative).parts
        if (type(archive_relative) is not str or len(archive_parts) != 7
                or archive_parts[0] != "DAY0-Prepare"
                or archive_parts[2:5] != ("99-output-ufm", "runs", run_id)
                or archive_parts[5] != node
                or archive_parts[6] != f"iblinkinfo_{run_id}.tar.gz"
                or archive_parts[1] in {"", ".", ".."}):
            raise IbProducerHold("IB UFM archive role is outside one project run")
        project = http_root / "DAY0-Prepare" / archive_parts[1]
        if (project.resolve(strict=True) != project
                or hashlib.sha256(str(project).encode()).hexdigest()
                != cycle["project_key"]):
            raise IbProducerHold("IB role project differs from cycle")
        final = project / "99-output-ufm/runs" / run_id / node
        setup = http_root / "ztp/config/nvos/template/P2P"
        fixed = setup / "p2p.xlsx"
        outer = _link_identity(fixed)
        if (not outer[1] or os.path.isabs(outer[1])
                or Path(os.path.abspath(setup / outer[1])) != project / "p2p.xlsx"):
            raise IbProducerHold("IB replay P2P selection differs from project")
        inner = _link_identity(project / "p2p.xlsx")
        selected_name = inner[1]
        if (not selected_name or os.path.basename(selected_name) != selected_name
                or not selected_name.lower().endswith(".xlsx")):
            raise IbProducerHold("IB replay selected P2P name is invalid")
        selected = project / selected_name
        cvt = setup / "output-p2p" / f"{selected.stem}-cvt.xlsx"
        expected_paths = (
            final / f"iblinkinfo_{run_id}.tar.gz",
            final / f"iblinkinfo_{run_id}.log",
            cvt,
            final / f"iblinkinfo_{run_id}-topology-validation.xlsx",
        )
        expected_paths += (sidecar_path(expected_paths[3]), final / "receipt.json")
        cvt_record = read_cvt_provenance(cvt)
        p2p = cvt_record["sources"]["p2p"]
        if (p2p["path"] != str(fixed)
                or p2p["resolved_path"] != str(selected)
                or cvt_record["cvt_sha256"] != binding["expected_topology_sha256"]
                or _link_identity(fixed) != outer
                or _link_identity(project / "p2p.xlsx") != inner):
            raise IbProducerHold("IB replay CVT source differs from active selection")
        report_record = read_report_provenance(expected_paths[3])
        if (report_record["actual"]["resolved_path"] != str(expected_paths[1])
                or report_record["cvt"]["resolved_path"] != str(cvt)
                or report_record["expected_topology_sha256"]
                != binding["expected_topology_sha256"]
                or report_record["cvt_provenance_sha256"]
                != _regular_digest(sidecar_path(cvt))):
            raise IbProducerHold("IB replay report attests different inputs")
        receipts = [row for row in validated_receipts(project, "prod")
                    if row.get("run_id") == run_id and row.get("node") == node]
        if len(receipts) != 1 or receipts[0]["archive_sha256"] != _regular_digest(
            expected_paths[0]
        ) or receipts[0]["report_sha256"] != _regular_digest(expected_paths[3]) \
                or _regular_digest(expected_paths[5]) != hashlib.sha256(
                    (json.dumps(receipts[0], sort_keys=True, separators=(",", ":")) + "\n")
                    .encode("utf-8")
                ).hexdigest():
            raise IbProducerHold("IB replay receipt is unavailable or mismatched")
        observed = [_role(path, http_root, name)
                    for path, name in zip(expected_paths, IB_ROLE_NAMES)]
        if observed != supplied:
            raise IbProducerHold("IB replay role bytes differ from evidence")
        return observed
    except (OSError, ValueError, TypeError, KeyError, RuntimeError) as exc:
        if isinstance(exc, IbProducerHold):
            raise
        raise IbProducerHold("IB role evidence cannot be replayed") from exc


def _open_protected_attestation_dir(project_key: str) -> int:
    """Return a held root-only 0700 per-project directory, without symlinks."""
    if _HEX.fullmatch(project_key) is None:
        raise IbProducerHold("IB attestation project selector is invalid")
    directory = _ATTESTATION_DIR / project_key
    flags = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
             | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    if not getattr(os, "O_DIRECTORY", 0) or not getattr(os, "O_NOFOLLOW", 0):
        raise IbProducerHold("platform cannot protect IB attestation directory")
    descriptor = None
    try:
        descriptor = os.open("/", flags)
        for index, part in enumerate(directory.parts[1:]):
            current = os.fstat(descriptor)
            if (not stat.S_ISDIR(current.st_mode) or current.st_uid != _ROOT_UID
                    or current.st_mode & 0o022):
                raise IbProducerHold("IB attestation ancestry is not root protected")
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
            current = os.fstat(descriptor)
            if (not stat.S_ISDIR(current.st_mode) or current.st_uid != _ROOT_UID
                    or current.st_mode & 0o022
                    or (index >= len(directory.parts) - 3
                        and stat.S_IMODE(current.st_mode) != 0o700)):
                raise IbProducerHold("IB attestation directory is not root-owned 0700")
        result, descriptor = descriptor, None
        return result
    except (OSError, ValueError, TypeError) as exc:
        if isinstance(exc, IbProducerHold):
            raise
        raise IbProducerHold("protected IB attestation directory is unavailable") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _attestation_name(cycle_id: str) -> str:
    if type(cycle_id) is not str or _HEX.fullmatch(cycle_id) is None:
        raise IbProducerHold("IB attestation cycle selector is invalid")
    return f"{cycle_id}.json"


def _preflight_protected_attestation(project_key: str, cycle_id: str) -> None:
    """Require the protected publication slot before any remote UFM action."""
    parent = _open_protected_attestation_dir(project_key)
    try:
        try:
            os.stat(_attestation_name(cycle_id), dir_fd=parent,
                    follow_symlinks=False)
        except FileNotFoundError:
            return
        raise IbProducerHold("IB cycle attestation already exists")
    except (OSError, ValueError, TypeError) as exc:
        if isinstance(exc, IbProducerHold):
            raise
        raise IbProducerHold("IB attestation target cannot be safely reserved") from exc
    finally:
        os.close(parent)


def _read_protected_attestation(project_key: str, cycle_id: str) -> bytes:
    parent = _open_protected_attestation_dir(project_key)
    try:
        name = _attestation_name(cycle_id)
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW,
                             dir_fd=parent)
        try:
            before = os.fstat(descriptor)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != _ROOT_UID
                    or stat.S_IMODE(before.st_mode) != 0o600
                    or before.st_nlink != 1 or not 0 < before.st_size <= _MAX_RECORD):
                raise IbProducerHold("IB attestation is not root-owned 0600 data")
            raw = os.read(descriptor, _MAX_RECORD + 1)
            after = os.fstat(descriptor)
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (len(raw) != before.st_size or _identity(before) != _identity(after)
                    or _identity(before) != _identity(named)):
                raise IbProducerHold("IB attestation changed during read")
            return raw
        finally:
            os.close(descriptor)
    except (OSError, ValueError, TypeError) as exc:
        if isinstance(exc, IbProducerHold):
            raise
        raise IbProducerHold("protected IB attestation is unavailable") from exc
    finally:
        os.close(parent)


def _publish_protected_attestation(
    project_key: str, cycle_id: str, record: dict[str, object],
) -> str:
    """No-overwrite, durable root-only publication; failure grants no role."""
    raw = _canonical(record, newline=True)
    if not 0 < len(raw) <= _MAX_RECORD:
        raise IbProducerHold("IB attestation exceeds its byte limit")
    parent = _open_protected_attestation_dir(project_key)
    staged = f".ib-{secrets.token_hex(12)}.part"
    try:
        name = _attestation_name(cycle_id)
        descriptor = os.open(
            staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600, dir_fd=parent,
        )
        try:
            metadata = os.fstat(descriptor)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != _ROOT_UID
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                    or metadata.st_nlink != 1):
                raise IbProducerHold("IB attestation stage is not root-owned 0600")
            offset = 0
            while offset < len(raw):
                offset += os.write(descriptor, raw[offset:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.link(staged, name, src_dir_fd=parent, dst_dir_fd=parent,
                follow_symlinks=False)
        os.unlink(staged, dir_fd=parent)
        os.fsync(parent)
    except (OSError, ValueError, TypeError) as exc:
        if isinstance(exc, IbProducerHold):
            raise
        raise IbProducerHold("IB attestation could not be durably published") from exc
    finally:
        try:
            os.unlink(staged, dir_fd=parent)
        except FileNotFoundError:
            pass
        os.close(parent)
    if _read_protected_attestation(project_key, cycle_id) != raw:
        raise IbProducerHold("IB attestation publication cannot be replayed")
    return hashlib.sha256(raw).hexdigest()


def _attestation_record(
    identity: dict[str, object], binding: dict[str, object],
    snapshot: IbProducerAuthoritySnapshot, retrieved: VerifiedRetrievedObservation,
    *, http_root: Path,
) -> dict[str, object]:
    """Derive a bounded witness solely from the verified worker inputs."""
    authority = snapshot.authority
    remote = retrieved.remote
    roles = binding["roles"]
    archive_sha = roles[0]["sha256"]
    if (type(retrieved) is not VerifiedRetrievedObservation
            or remote.run_id != binding["run_id"] or remote.node != binding["node"]
            or remote.remote_sha256 != archive_sha
            or retrieved.local_sha256 != archive_sha
            or retrieved.remote_sha256_before != archive_sha
            or retrieved.remote_sha256_after != archive_sha
            or _HEX.fullmatch(retrieved.identity_before_sha256) is None
            or retrieved.identity_before_sha256 != retrieved.identity_after_sha256
            or _local_bound_digest(retrieved.local_path) != archive_sha):
        raise IbProducerHold("IB F01 retrieval observations are not identical")
    return {
        "schema_version": 1,
        "project_key": identity["project_key"],
        "cycle_id": identity["cycle_id"],
        "run_token": identity["run_token"],
        "run_id": binding["run_id"], "node": binding["node"],
        "authority_sha256": snapshot.sha256,
        "project_root": str(authority.project_root),
        "lease_path": str(authority.lease_path),
        "known_hosts_pin": authority.known_hosts_pin,
        "jump_host": authority.jump.host,
        "far_host": authority.far.host,
        "install_agent_sha256": authority.install.agent_sha256,
        "install_contract_sha256": authority.install.contract_sha256,
        "install_python_sha256": authority.install.python_sha256,
        "expected_topology_sha256": binding["expected_topology_sha256"],
        "remote_archive_path": remote.archive_path,
        "remote_sha256_before": retrieved.remote_sha256_before,
        "remote_sha256_after": retrieved.remote_sha256_after,
        "identity_before_sha256": retrieved.identity_before_sha256,
        "identity_after_sha256": retrieved.identity_after_sha256,
        "retrieved_archive_relative_path": retrieved.local_path.relative_to(http_root).as_posix(),
        "retrieved_sha256": retrieved.local_sha256,
        "final_archive_relative_path": roles[0]["relative_path"],
        "final_sha256": archive_sha,
        "roles_sha256": hashlib.sha256(_canonical(roles)).hexdigest(),
    }


def validate_ib_completion_attestation(
    identity: object, binding: object, *, http_root: Path,
) -> list[dict[str, object]]:
    """Replay worker-owned root witness and all six local role bytes."""
    try:
        cycle = validate_collection_cycle_identity(identity)
        if (type(binding) is not dict or set(binding) != {
                "run_id", "node", "authority_sha256",
                "expected_topology_sha256", "roles", "attestation_sha256",
            } or _HEX.fullmatch(binding["attestation_sha256"]) is None):
            raise IbProducerHold("IB completion attestation binding is incomplete")
        local = {key: value for key, value in binding.items()
                 if key != "attestation_sha256"}
        observed = validate_ib_role_binding(cycle, local, http_root=http_root)
        project_name = Path(observed[0]["relative_path"]).parts[1]
        project_root = http_root / "DAY0-Prepare" / project_name
        snapshot = load_ib_producer_authority(
            project_key=cycle["project_key"], project_root=project_root,
        )
        raw = _read_protected_attestation(cycle["project_key"], cycle["cycle_id"])
        if hashlib.sha256(raw).hexdigest() != binding["attestation_sha256"]:
            raise IbProducerHold("IB protected attestation digest differs")
        record = _parse_record(raw)
        authority = snapshot.authority
        expected = {
            "schema_version": 1,
            "project_key": cycle["project_key"],
            "cycle_id": cycle["cycle_id"],
            "run_token": cycle["run_token"],
            "run_id": binding["run_id"], "node": binding["node"],
            "authority_sha256": snapshot.sha256,
            "project_root": str(project_root),
            "lease_path": str(authority.lease_path),
            "known_hosts_pin": authority.known_hosts_pin,
            "jump_host": authority.jump.host,
            "far_host": authority.far.host,
            "install_agent_sha256": authority.install.agent_sha256,
            "install_contract_sha256": authority.install.contract_sha256,
            "install_python_sha256": authority.install.python_sha256,
            "expected_topology_sha256": binding["expected_topology_sha256"],
            "remote_archive_path": collection_plan(
                "iblinkinfo", binding["run_id"],
            ).ufm_remote_path,
            "remote_sha256_before": observed[0]["sha256"],
            "remote_sha256_after": observed[0]["sha256"],
            "retrieved_archive_relative_path": (
                authority.retrieval_dir / f"iblinkinfo_{binding['run_id']}.tar.gz"
            ).relative_to(http_root).as_posix(),
            "retrieved_sha256": observed[0]["sha256"],
            "final_archive_relative_path": observed[0]["relative_path"],
            "final_sha256": observed[0]["sha256"],
            "roles_sha256": hashlib.sha256(_canonical(observed)).hexdigest(),
        }
        if (type(record) is not dict or set(record) != set(expected) | {
                "identity_before_sha256", "identity_after_sha256",
            } or any(record[key] != value for key, value in expected.items())
                or type(record["identity_before_sha256"]) is not str
                or _HEX.fullmatch(record["identity_before_sha256"]) is None
                or record["identity_before_sha256"]
                != record["identity_after_sha256"]):
            raise IbProducerHold("IB protected completion attests another source")
        if _local_bound_digest(http_root / record["retrieved_archive_relative_path"]) \
                != observed[0]["sha256"]:
            raise IbProducerHold("IB retrieved archive changed after completion")
        recheck_ib_producer_authority(snapshot)
        return observed
    except (OSError, ValueError, TypeError, KeyError, RuntimeError) as exc:
        if isinstance(exc, IbProducerHold):
            raise
        raise IbProducerHold("IB protected completion cannot be replayed") from exc


def produce_worker_ib_analysis(
    identity: object, *, project_root: Path, http_root: Path,
    clock=None, runner=None,
) -> dict[str, object]:
    """Run the approved UFM producer and local analyzer under a worker cycle.

    The worker must be the sole production caller and must never pass a child,
    CGI or sidecar value as `clock`, `runner`, project or install authority.
    Synthetic runners are solely a deterministic test seam.
    """
    if clock is None:
        clock = lambda: dt.datetime.now(dt.timezone.utc)
    if runner is None:
        runner = _default_runner
    try:
        cycle = validate_collection_cycle_identity(identity)
        if (not isinstance(project_root, Path) or not isinstance(http_root, Path)
                or not callable(clock) or not callable(runner)
                or project_root.parent != http_root / "DAY0-Prepare"
                or hashlib.sha256(str(project_root).encode()).hexdigest()
                != cycle["project_key"]):
            raise IbProducerHold("IB worker project or execution authority is invalid")
        snapshot = load_ib_producer_authority(
            project_key=cycle["project_key"], project_root=project_root,
        )
        _preflight_protected_attestation(cycle["project_key"], cycle["cycle_id"])
        authority = snapshot.authority
        if authority.retrieval_dir != project_root / "99-output-ufm/incoming":
            raise IbProducerHold("IB incoming archive directory differs from fixed project")
        incoming = authority.retrieval_dir
        incoming_stat = incoming.lstat()
        if not stat.S_ISDIR(incoming_stat.st_mode):
            raise IbProducerHold("IB incoming archive directory is unavailable")
        source = observe_ib_cvt_source(authority, http_root=http_root)
        run_id = derive_ib_cycle_run_id(cycle, when=clock())
        plan = collection_plan("iblinkinfo", run_id)
        destination = incoming / plan.archive_name
        if destination.exists() or destination.is_symlink():
            raise IbProducerHold("IB exact incoming archive already exists")
        recheck_ib_producer_authority(snapshot)
        retrieved = observe_and_retrieve_remote_producer(
            plan, install=authority.install, project=project_root,
            lease_path=authority.lease_path, jump=authority.jump,
            far=authority.far, known_hosts_pin=authority.known_hosts_pin,
            destination=destination, timeout=authority.timeout_seconds,
            clock=clock, runner=runner,
        )
        if (type(retrieved) is not VerifiedRetrievedObservation
                or retrieved.remote.run_id != run_id
                or retrieved.local_path != destination):
            raise IbProducerHold("IB UFM retrieval returned a different worker run")

        def before_receipt() -> None:
            recheck_ib_producer_authority(snapshot)
            if observe_ib_cvt_source(authority, http_root=http_root) != source:
                raise IbProducerHold("IB CVT source changed before receipt")
            if (_local_bound_digest(destination) != retrieved.local_sha256
                    or retrieved.local_sha256 != retrieved.remote.remote_sha256):
                raise IbProducerHold("IB UFM source changed before receipt")

        final = run_local_iblinkinfo(
            plan, retrieved.remote.node, destination, source.cvt, project_root,
            before_receipt=before_receipt,
        )
        before_receipt()
        result = verify_ib_completed_result(
            cycle, snapshot=snapshot, source=source, retrieved=retrieved,
            final=final, run_id=run_id, http_root=http_root,
        )
        recheck_ib_producer_authority(snapshot)
        witness = _attestation_record(
            cycle, result, snapshot, retrieved, http_root=http_root,
        )
        attestation_sha256 = _publish_protected_attestation(
            cycle["project_key"], cycle["cycle_id"], witness,
        )
        completed = {**result, "attestation_sha256": attestation_sha256}
        validate_ib_completion_attestation(cycle, completed, http_root=http_root)
        return completed
    except (OSError, ValueError, TypeError, KeyError, RuntimeError) as exc:
        if isinstance(exc, IbProducerHold):
            raise
        raise IbProducerHold("IB worker producer could not complete exact cycle") from exc
