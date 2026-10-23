"""Bind one worker cycle's UFM IB analysis (the cron.sh UFM lane) into the IB slot evidence.

The UFM lane of ``ethernet/monitor/cron.sh`` writes a run record (``ufm-ib-run-record-v1``) beside the
input it fetched into the project's ``99-output-monitor/infiniband/ufm-ibdiagnet/``; when the IB closed
loop (``infiniband/monitor/post-collect.py``) published a report, its receipt
(``ufm-ib-report-receipt-v1``) sits beside the report in the project's ``99-output-p2p/``
(infiniband/monitor/UFM-MONITOR.md 13, 14.6; REQ7 R1, 2026-10-23).

``derive_ufm_run_roles`` is the single check shared by the collection emitter, the worker and REQ7's
completed-cycle reader. It binds a run only when the record names exactly this worker cycle and the UFM
run and its analysis succeeded, and it reopens every file the record and the receipt name:

    run record -> .done, input -> receipt -> report, report provenance, CVT

A run that is not bindable raises ``UfmRunBindingHold``; the emitter then keeps the three base IB roles
(a UFM problem never changes the switch result), while a replay of recorded evidence fails closed.
Every path is the real path below the HTTP root, never through a setup link.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

from project_contract import (  # noqa: E402
    collection_cycle_project_key, validate_collection_cycle_identity,
)

UFM_RUN_ROLE_NAMES = (
    "ufm_run_record", "ufm_done", "ufm_input", "validation_report",
    "report_provenance", "report_receipt", "expected_cvt",
)
UFM_RUN_BINDING_KEYS = (
    "run_id", "node", "kind", "degraded", "run_record_sha256", "receipt_sha256",
    "expected_topology_sha256",
)
RUN_RECORD_SCHEMA = "ufm-ib-run-record-v1"
RECEIPT_SCHEMA = "ufm-ib-report-receipt-v1"
_RUN_ID = re.compile(r"[0-9]{8}-[0-9]{4}-prod-[0-9a-f]{16}")
_NODE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}")
_HEX = re.compile(r"[0-9a-f]{64}")
_INPUT_SUFFIX = {"ibdiagnet": "ibdiagnet2.tgz", "iblinkinfo": "iblinkinfo.log"}
_MAXIMUM = 512 * 1024 * 1024


class UfmRunBindingHold(ValueError):
    """The UFM run cannot be bound to this cycle, or its recorded binding no longer replays."""


def _safe_child(root: Path, relative: str) -> Path:
    """A canonical relative path below root that crosses no symlink (as the switch evidence readers)."""
    pure = PurePosixPath(relative) if isinstance(relative, str) else None
    if (pure is None or not relative or "\\" in relative or pure.is_absolute() or str(pure) != relative
            or any(part in {"", ".", ".."} for part in relative.split("/"))):
        raise UfmRunBindingHold(f"UFM role path is unsafe: {relative!r}")
    path = root
    for part in pure.parts:
        path = path / part
        if path.is_symlink():
            raise UfmRunBindingHold(f"UFM role path is unsafe: {relative}")
    return path


def _read(root: Path, relative: str) -> bytes:
    """The bytes of one single-link regular file, refused when it changes while read."""
    path = _safe_child(root, relative)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > _MAXIMUM:
            raise UfmRunBindingHold(f"UFM role is not a bounded regular file: {relative}")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(_MAXIMUM + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    named = os.stat(path, follow_symlinks=False)

    def identity(item):
        return item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns
    if (len(raw) != before.st_size or identity(before) != identity(after)
            or identity(before) != identity(named)):
        raise UfmRunBindingHold(f"UFM role changed while read: {relative}")
    return raw


def _role(name: str, relative: str, raw: bytes) -> dict:
    return {"role": name, "state": "present", "relative_path": relative,
            "sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)}


def _named(document: object, field: str, *, sized: bool) -> dict:
    keys = {"name", "sha256", "size"} if sized else {"name", "sha256"}
    if (type(document) is not dict or set(document) != keys
            or type(document["name"]) is not str or not document["name"]
            or "/" in document["name"] or type(document["sha256"]) is not str
            or _HEX.fullmatch(document["sha256"]) is None
            or (sized and (type(document["size"]) is not int or document["size"] < 0))):
        raise UfmRunBindingHold(f"UFM {field} identity is malformed")
    return document


def _same(raw: bytes, named: dict, field: str) -> None:
    if hashlib.sha256(raw).hexdigest() != named["sha256"] or (
            "size" in named and len(raw) != named["size"]):
        raise UfmRunBindingHold(f"UFM {field} bytes differ from their record")


def derive_ufm_run_roles(identity: object, record_path: Path | str, *,
                         http_root: Path | str) -> tuple[list[dict], dict]:
    """Return (the seven UFM roles in UFM_RUN_ROLE_NAMES order, the envelope binding) or HOLD."""
    try:
        cycle = validate_collection_cycle_identity(identity)
        if cycle["scope"] not in {"prod", "all"}:
            raise UfmRunBindingHold("UFM IB analysis only binds a prod cycle")
        root = Path(http_root).resolve(strict=True)
        record_file = Path(record_path).resolve(strict=True)
        parts = record_file.relative_to(root).parts
        if (len(parts) != 6 or parts[0] != "DAY0-Prepare"
                or parts[2:5] != ("99-output-monitor", "infiniband", "ufm-ibdiagnet")
                or not parts[5].endswith(".ufm-run.json")):
            raise UfmRunBindingHold("UFM run record is not in a project's ufm-ibdiagnet directory")
        project = root / "DAY0-Prepare" / parts[1]
        if collection_cycle_project_key(str(project)) != cycle["project_key"]:
            raise UfmRunBindingHold("UFM run record belongs to another project")
        record_relative = "/".join(parts)
        record_raw = _read(root, record_relative)
        record = json.loads(record_raw.decode("utf-8"))
        if type(record) is not dict or record.get("schema") != RUN_RECORD_SCHEMA:
            raise UfmRunBindingHold("UFM run record schema is unknown")
        if record.get("cycle") != cycle:
            raise UfmRunBindingHold("UFM run record does not name this worker cycle")
        if record.get("outcome") != "ok" or record.get("analysis") != "ok":
            raise UfmRunBindingHold("UFM run or its IB analysis did not succeed")
        run_id, node, kind = record.get("run_id"), record.get("node"), record.get("kind")
        if (type(run_id) is not str or _RUN_ID.fullmatch(run_id) is None
                or parts[5] != f"{run_id}.ufm-run.json"
                or type(node) is not str or _NODE.fullmatch(node) is None
                or kind not in _INPUT_SUFFIX):
            raise UfmRunBindingHold("UFM run record names are malformed")
        suffix = _INPUT_SUFFIX[kind]
        stem = f"{run_id}_{node}-{kind}-topology-validation"
        expected_names = {
            "done": f"{run_id}_{node}_{suffix.rsplit('.', 1)[0]}.done",
            "input": f"{run_id}_{node}_{suffix}",
            "report": f"{stem}.xlsx",
            "receipt": f"{stem}.receipt.json",
        }
        named = {field: _named(record.get(field), field, sized=True) for field in expected_names}
        if any(named[field]["name"] != name for field, name in expected_names.items()):
            raise UfmRunBindingHold("UFM run record names other files than this run's")

        collected = "/".join(parts[:5])
        reports = f"DAY0-Prepare/{parts[1]}/99-output-p2p"
        raws = {
            "done": _read(root, f"{collected}/{expected_names['done']}"),
            "input": _read(root, f"{collected}/{expected_names['input']}"),
            "report": _read(root, f"{reports}/{expected_names['report']}"),
            "receipt": _read(root, f"{reports}/{expected_names['receipt']}"),
        }
        for field, raw in raws.items():
            _same(raw, named[field], field)
        receipt = json.loads(raws["receipt"].decode("utf-8"))
        if (type(receipt) is not dict or receipt.get("schema") != RECEIPT_SCHEMA
                or receipt.get("run_id") != run_id or receipt.get("node") != node
                or receipt.get("kind") != kind or receipt.get("degraded") is not (kind == "iblinkinfo")):
            raise UfmRunBindingHold("UFM report receipt does not describe this run")
        receipt_named = {field: _named(receipt.get(field), f"receipt {field}", sized=False)
                         for field in ("done", "input", "report", "provenance", "cvt")}
        for field in ("done", "input", "report"):
            if receipt_named[field] != {"name": named[field]["name"], "sha256": named[field]["sha256"]}:
                raise UfmRunBindingHold(f"UFM report receipt names another {field}")

        from ztp.config.ib_topology_provenance import (
            ProvenanceError, read_report_provenance, sidecar_path,
        )
        report_path = _safe_child(root, f"{reports}/{expected_names['report']}")
        provenance_name = sidecar_path(report_path).name
        if receipt_named["provenance"]["name"] != provenance_name:
            raise UfmRunBindingHold("UFM report receipt names another provenance")
        cvt_name = receipt_named["cvt"]["name"]
        if not cvt_name.endswith("-cvt.xlsx"):
            raise UfmRunBindingHold("UFM report receipt CVT is not a CVT workbook")
        raws["provenance"] = _read(root, f"{reports}/{provenance_name}")
        raws["cvt"] = _read(root, f"{reports}/{cvt_name}")
        for field in ("provenance", "cvt"):
            _same(raws[field], receipt_named[field], f"receipt {field}")
        try:
            provenance = read_report_provenance(report_path)
        except (OSError, ValueError, ProvenanceError) as exc:
            raise UfmRunBindingHold("UFM report provenance does not replay") from exc
        input_path = _safe_child(root, f"{collected}/{expected_names['input']}")
        cvt_path = _safe_child(root, f"{reports}/{cvt_name}")
        if (provenance["report"]["sha256"] != named["report"]["sha256"]
                or provenance["expected_topology_sha256"] != receipt_named["cvt"]["sha256"]
                or provenance["actual"].get("resolved_path") != str(input_path)
                or provenance["actual"].get("sha256") != named["input"]["sha256"]
                or Path(provenance["cvt"]["path"]).resolve(strict=True) != cvt_path):
            raise UfmRunBindingHold("UFM report provenance names other inputs than the receipt")

        roles = [
            _role("ufm_run_record", record_relative, record_raw),
            _role("ufm_done", f"{collected}/{expected_names['done']}", raws["done"]),
            _role("ufm_input", f"{collected}/{expected_names['input']}", raws["input"]),
            _role("validation_report", f"{reports}/{expected_names['report']}", raws["report"]),
            _role("report_provenance", f"{reports}/{provenance_name}", raws["provenance"]),
            _role("report_receipt", f"{reports}/{expected_names['receipt']}", raws["receipt"]),
            _role("expected_cvt", f"{reports}/{cvt_name}", raws["cvt"]),
        ]
        binding = {
            "run_id": run_id, "node": node, "kind": kind, "degraded": kind == "iblinkinfo",
            "run_record_sha256": roles[0]["sha256"], "receipt_sha256": roles[5]["sha256"],
            "expected_topology_sha256": receipt_named["cvt"]["sha256"],
        }
        return roles, binding
    except UfmRunBindingHold:
        raise
    except (OSError, RuntimeError, TypeError, KeyError, AttributeError, ValueError, ImportError) as exc:
        raise UfmRunBindingHold(f"UFM run binding is not safe: {type(exc).__name__}") from exc


def validate_ufm_run_binding(identity: object, binding: object, roles: object, *,
                             http_root: Path | str) -> list[dict]:
    """Replay recorded UFM evidence: the record named by the first role must derive exactly these roles."""
    if (type(binding) is not dict or tuple(sorted(binding)) != tuple(sorted(UFM_RUN_BINDING_KEYS))
            or type(roles) is not list or len(roles) != len(UFM_RUN_ROLE_NAMES)
            or [item.get("role") if type(item) is dict else None for item in roles]
            != list(UFM_RUN_ROLE_NAMES)):
        raise UfmRunBindingHold("UFM run evidence shape is malformed")
    relative = roles[0].get("relative_path")
    if type(relative) is not str:
        raise UfmRunBindingHold("UFM run record role has no path")
    root = Path(http_root).resolve(strict=True)
    derived_roles, derived_binding = derive_ufm_run_roles(
        identity, _safe_child(root, relative), http_root=root,
    )
    if derived_roles != roles or derived_binding != binding:
        raise UfmRunBindingHold("UFM run evidence differs from its replay")
    return derived_roles
