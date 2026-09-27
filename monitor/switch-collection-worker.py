#!/usr/bin/env python3
"""Independent root worker for fixed Switch Status collection requests."""

from __future__ import annotations

import argparse
import csv
import ctypes
from datetime import datetime
import fcntl
import grp
import hashlib
import io
import ipaddress
import json
import math
import os
from pathlib import Path, PurePosixPath
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import uuid
import re

from switch_collection_gate import (
    CollectionGate,
    CollectionGateCancelled,
    CollectionGateError,
    active_project_identity,
    collection_keys_for_scope,
    project_inventory_targets,
)

HTTP_ROOT = Path(__file__).resolve().parent.parent
if str(HTTP_ROOT) not in sys.path:
    sys.path.insert(0, str(HTTP_ROOT))
TOOLS_ROOT = HTTP_ROOT / "tools"
if str(TOOLS_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOLS_ROOT))

from project_contract import (
    MIN_CONTINUOUS_INTERVAL_MINUTES,
    MAX_CONTINUOUS_INTERVAL_MINUTES,
    MIN_CONTINUOUS_BACKUP_INTERVAL_MINUTES,
    MAX_CONTINUOUS_BACKUP_INTERVAL_MINUTES,
    COLLECTION_CYCLE_FAILED_DEVICE_OPERATIONS,
    COLLECTION_CYCLE_MAX_SEQUENCE,
    COLLECTION_CYCLE_MAX_FAILED_DEVICES,
    COLLECTION_CYCLE_MAX_FAILED_DEVICE_TEXT_BYTES,
    YAML_BACKUP_FAILED_DEVICE_OPERATIONS,
    _validate_collection_cycle_legacy_result,
    build_collection_cycle_identity,
    canonical_collection_cycle_json,
    collection_cycle_project_key,
    collection_cycle_source_slots,
    summarize_collection_cycle_results,
    validate_collection_cycle_sequence,
    validate_collection_cycle_identity,
    validate_collection_cycle_result,
)


STATUS_DIR = HTTP_ROOT / "monitor/status"
REQUEST_FILE = STATUS_DIR / "switch-collection.request"
STATUS_FILE = STATUS_DIR / "switch-collection.status.json"
PID_FILE = STATUS_DIR / "switch-collection.pid"
YAML_BACKUP_STATUS_FILE = STATUS_DIR / "yaml-backup.status.json"
CONTINUOUS_STATUS_FILE = STATUS_DIR / "continuous-collection.status.json"
CONTINUOUS_BACKUP_STATUS_FILE = STATUS_DIR / "continuous-backup.status.json"
ISSUE_TRACKER_STAGE_L_STATUS_FILE = STATUS_DIR / "issue-tracker-stage-l.status.json"
YAML_BACKUP_SOCKET = STATUS_DIR / ".yaml-backup.sock"
YAML_BACKUP_SCRIPT = HTTP_ROOT / "ztp/backup/yaml-collect.py"
YAML_BACKUP_COOLDOWN_SECONDS = 10 * 60
MAX_PASSWORD_BYTES = 1024
MAX_MEMORY_REQUEST_BYTES = 2048
TASK_RESULT_PREFIX = "[HTTP_ZTP_TASK_RESULT] "
MAX_TASK_RESULT_DEVICES = COLLECTION_CYCLE_MAX_FAILED_DEVICES
MAX_TASK_RESULT_TEXT_BYTES = COLLECTION_CYCLE_MAX_FAILED_DEVICE_TEXT_BYTES
HTML_SCRIPT = HTTP_ROOT / "monitor/generate-monitor-html.py"
SCRIPTS = {
    "ethernet": HTTP_ROOT / "ethernet/monitor/cron.sh",
    "infiniband": HTTP_ROOT / "infiniband/monitor/cron.sh",
    "nvlink": HTTP_ROOT / "nvlink/monitor/cron.sh",
}
COLLECTOR_TERM_GRACE_SECONDS = 5.0
COLLECTOR_KILL_GRACE_SECONDS = 2.0
COLLECTOR_EXIT_POLL_SECONDS = 0.05

# Child task states and worker-owned terminal lifecycle outcomes are separate
# closed vocabularies.  A child may never assert a lifecycle outcome.
COLLECTION_SLOT_CHILD_STATES = ("success", "partial", "failed")
COLLECTION_SLOT_TERMINAL_OUTCOMES = (
    "accepted",
    "cancelled",
    "crashed",
    "worker_error",
    "missing_marker",
    "malformed_marker",
    "duplicate_marker",
    "extra_marker",
    "returncode_conflict",
    "artifact_mismatch",
    "identity_mismatch",
)
COLLECTION_CYCLE_COMPLETION_OUTCOMES = (
    "cycle_completed",
    "cycle_crashed",
)
assert not set(COLLECTION_SLOT_CHILD_STATES) & set(
    COLLECTION_SLOT_TERMINAL_OUTCOMES
)
assert not set(COLLECTION_CYCLE_COMPLETION_OUTCOMES) & set(
    COLLECTION_SLOT_CHILD_STATES
)
assert not set(COLLECTION_CYCLE_COMPLETION_OUTCOMES) & set(
    COLLECTION_SLOT_TERMINAL_OUTCOMES
)

COLLECTION_LANE = "collection"
BACKUP_LANE = "backup"
VALID_LANES = frozenset((COLLECTION_LANE, BACKUP_LANE))

_ACTIVE_COLLECTORS = {COLLECTION_LANE: None, BACKUP_LANE: None}
_ACTIVE_COLLECTOR_LOCK = threading.RLock()
_LANE_TASKS = {COLLECTION_LANE: None, BACKUP_LANE: None}
_LANE_TASK_ORIGINS = {COLLECTION_LANE: None, BACKUP_LANE: None}
_LANE_TASK_LOCK = threading.RLock()
_LANE_CANCEL = {
    COLLECTION_LANE: threading.Event(), BACKUP_LANE: threading.Event(),
}
_CONTINUOUS_STATE_LOCK = threading.RLock()
_SHUTDOWN_SIGNAL = None
_CONTINUOUS_COLLECTION_INTERVAL_SECONDS = 0
_CONTINUOUS_COLLECTION_NEXT_RUN = 0.0
_CONTINUOUS_COLLECTION_STOP_REQUESTED = False
_CONTINUOUS_BACKUP_PASSWORD = None
_CONTINUOUS_BACKUP_INTERVAL_SECONDS = 0
_CONTINUOUS_BACKUP_NEXT_RUN = 0.0
_CONTINUOUS_BACKUP_STOP_REQUESTED = False

_COOLDOWN_STATUS_FIELDS = (
    "cooldown_seconds", "last_success_at", "next_allowed_epoch",
    "next_allowed_at",
)

_COLLECTION_CYCLE_RECORD_NAME = re.compile(
    r"^(?P<sequence>[0-9]{20})\.(?P<kind>start|launch|completion)\.json$"
)


class CollectionCycleHoldError(RuntimeError):
    """Persistent cycle evidence cannot safely admit another allocation."""


def _canonical_json_line(payload: object) -> bytes:
    return (
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def durable_publish_collection_cycle_json(path: Path, payload: object) -> None:
    """Durably publish one immutable private JSON record without clobbering."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(target.parent, 0o700)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", dir=target.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(_canonical_json_line(payload))
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, target)
        os.chmod(target, 0o600)
        _fsync_directory(target.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def _read_private_json(path: Path) -> object:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > 16 * 1024 * 1024
        ):
            raise ValueError("persistent cycle record is not a bounded regular file")
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            descriptor = -1
            return json.load(stream)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _mint_cycle_run_token() -> str:
    """Mint the sole production cycle token authority."""
    return uuid.uuid4().hex


def redacted_collection_cycle_invocation_digest(
    argv: object,
    context: object,
    *,
    credential_argv_positions: object,
    credential_context_names: object,
) -> str:
    """Hash invocation metadata after caller-declared credential redaction.

    The caller is authoritative for which fields are credentials.  This
    function mechanically validates only the declaration's shape and applies
    it before hashing; the two-credential invariance test is the guarantee
    that the declared invocation does not create a durable credential oracle.
    """
    if not isinstance(argv, (list, tuple)) or not all(
        isinstance(value, str) for value in argv
    ):
        raise ValueError("collection cycle argv must be text values")
    if not isinstance(context, dict) or not all(
        isinstance(name, str) for name in context
    ):
        raise ValueError("collection cycle context must be a string-keyed mapping")
    if not isinstance(credential_argv_positions, (list, tuple)) or not isinstance(
        credential_context_names, (list, tuple)
    ):
        raise ValueError("credential redaction metadata must be sequences")
    positions = tuple(credential_argv_positions)
    names = tuple(credential_context_names)
    if bool(positions) != bool(names):
        raise ValueError("credential positions and names must be declared together")
    if len(set(positions)) != len(positions) or len(set(names)) != len(names):
        raise ValueError("credential redaction metadata contains duplicates")
    if any(
        isinstance(position, bool)
        or not isinstance(position, int)
        or position < 0
        or position >= len(argv)
        for position in positions
    ):
        raise ValueError("credential argv position is invalid")
    if any(not isinstance(name, str) or name not in context for name in names):
        raise ValueError("credential context name is invalid")
    redacted_argv = list(argv)
    redacted_context = dict(context)
    for position in positions:
        redacted_argv[position] = "<redacted>"
    for name in names:
        redacted_context[name] = "<redacted>"
    payload = {"argv": redacted_argv, "context": redacted_context}
    return hashlib.sha256(canonical_collection_cycle_json(payload)).hexdigest()


def _current_boot_identity() -> str:
    linux_boot = Path("/proc/sys/kernel/random/boot_id")
    if linux_boot.is_file():
        return linux_boot.read_text(encoding="ascii").strip()
    result = subprocess.run(
        ["/usr/sbin/sysctl", "-n", "kern.boottime"],
        text=True,
        capture_output=True,
        timeout=2,
        check=False,
    )
    if not result.returncode and result.stdout.strip():
        return hashlib.sha256(result.stdout.strip().encode("utf-8")).hexdigest()
    # Sandboxed macOS can deny both sysctl and foreign-process inspection.
    # The wall-clock/monotonic delta is the boot epoch; minute quantisation
    # removes call jitter while remaining a reboot discriminator.
    boot_minute = int((time.time() - time.monotonic()) // 60)
    return hashlib.sha256(f"boot-minute:{boot_minute}".encode("ascii")).hexdigest()


def _process_start_identity(pid: int) -> str:
    linux_stat = Path(f"/proc/{pid}/stat")
    if linux_stat.is_file():
        fields = linux_stat.read_text(encoding="ascii").rsplit(")", 1)[1].split()
        if len(fields) < 20:
            raise ProcessLookupError(pid)
        return f"linux:{fields[19]}"
    if sys.platform == "darwin":
        # PROC_PIDTBSDINFO returns a 136-byte proc_bsdinfo whose final two
        # uint64 values are process start seconds and microseconds.
        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        buffer = ctypes.create_string_buffer(136)
        size = library.proc_pidinfo(pid, 3, 0, buffer, len(buffer))
        if size != len(buffer):
            error = ctypes.get_errno()
            if error == 3:
                raise ProcessLookupError(pid)
            raise OSError(error, "proc_pidinfo failed")
        seconds, microseconds = struct.unpack_from("=QQ", buffer.raw, 120)
        return f"darwin:{seconds}.{microseconds:06d}"
    result = subprocess.run(
        ["/bin/ps", "-o", "lstart=", "-p", str(pid)],
        text=True,
        capture_output=True,
        timeout=2,
        check=False,
    )
    if result.returncode or not result.stdout.strip():
        raise ProcessLookupError(pid)
    return result.stdout.strip()


def inspect_collection_cycle_process(binding: object) -> str:
    """Return live/dead/unavailable for an exact coordinator binding."""
    try:
        if not isinstance(binding, dict):
            return "unavailable"
        pid = binding.get("pid")
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            return "unavailable"
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return "dead"
        except (PermissionError, OSError):
            return "unavailable"
        if _current_boot_identity() != binding.get("boot_id"):
            return "dead"
        if _process_start_identity(pid) != binding.get("process_start_time"):
            return "dead"
        return "live"
    except ProcessLookupError:
        return "dead"
    except Exception:
        return "unavailable"


def _validate_collection_cycle_run_result(
    value: object, identity: dict,
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {
        "identity", "outcomes", "summary"
    }:
        raise ValueError("collection cycle run result has invalid keys")
    validated_identity = validate_collection_cycle_identity(value["identity"])
    if validated_identity != identity:
        raise ValueError("collection cycle run result identity mismatch")
    slots = collection_cycle_source_slots(identity["scope"])
    raw_outcomes = value["outcomes"]
    if not isinstance(raw_outcomes, list) or len(raw_outcomes) != len(slots):
        raise ValueError("collection cycle outcome set does not match scope")
    outcomes = [
        validate_collection_slot_outcome(
            raw,
            expected_slot=slot,
            expected_context=identity,
        )
        for slot, raw in zip(slots, raw_outcomes)
    ]
    summary = value["summary"]
    can_summarize = all(item["outcome"] == "accepted" for item in outcomes) and all(
        item["child_result"]["schema_version"] == 2 for item in outcomes
    )
    if not can_summarize:
        if summary is not None:
            raise ValueError("nonaccepted collection cycle cannot carry a summary")
    else:
        if not isinstance(summary, dict):
            raise ValueError("accepted collection cycle requires a summary")
        expected = summarize_collection_cycle_results(
            identity,
            [item["child_result"] for item in outcomes],
            html_annotation=summary.get("html_annotation"),
        )
        if summary != expected:
            raise ValueError("collection cycle summary is not worker-derived")
        summary = expected
    return {
        "identity": validated_identity,
        "outcomes": outcomes,
        "summary": summary,
    }


class CollectionCycleStore:
    """Private immutable collection-cycle ledger bound to one held gate."""

    def __init__(self, *, gate: CollectionGate, source: str = "switch_collection"):
        self.gate = gate
        if source != "switch_collection":
            raise ValueError("collection cycle source is fixed")
        self.source = source
        self._require_gate()
        self.scope = gate.scope
        self.project_identity = gate.project
        self.project_key = collection_cycle_project_key(gate.project)
        self.root_status_dir = Path(gate.status_dir)
        self.status_dir = (
            self.root_status_dir / "collection-cycles" / self.project_key
            / self.scope / self.source
        )
        self.records_dir = self.status_dir / "records"
        self.witness_path = self.status_dir / "high-water.json"

    def _require_gate(self) -> None:
        if (
            not isinstance(self.gate, CollectionGate)
            or self.gate.lane != COLLECTION_LANE
            or self.gate._lock_fd < 0
            or not self.gate.decision.allowed
        ):
            raise CollectionCycleHoldError(
                "collection cycle store requires an active allowed collection gate"
            )

    @staticmethod
    def _sequence_name(sequence: int, kind: str) -> str:
        validate_collection_cycle_sequence(sequence)
        if kind not in {"start", "launch", "completion"}:
            raise ValueError("invalid collection cycle record kind")
        return f"{sequence:020d}.{kind}.json"

    def start_path(self, sequence: int) -> Path:
        return self.records_dir / self._sequence_name(sequence, "start")

    def launch_path(self, sequence: int) -> Path:
        return self.records_dir / self._sequence_name(sequence, "launch")

    def completion_path(self, sequence: int) -> Path:
        return self.records_dir / self._sequence_name(sequence, "completion")

    def _read_witness(self) -> int | None:
        try:
            payload = _read_private_json(self.witness_path)
        except FileNotFoundError:
            return None
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise CollectionCycleHoldError("witness corrupt") from exc
        if (
            not isinstance(payload, dict)
            or set(payload) != {"high_water"}
        ):
            raise CollectionCycleHoldError("witness corrupt")
        value = payload["high_water"]
        try:
            return validate_collection_cycle_sequence(value)
        except ValueError as exc:
            raise CollectionCycleHoldError("witness corrupt") from exc

    def _write_witness(self, sequence: int) -> None:
        self._require_gate()
        sequence = validate_collection_cycle_sequence(sequence)
        current = self._read_witness()
        if current is not None and sequence <= current:
            raise ValueError("collection cycle witness must strictly increase")
        self.status_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.status_dir, 0o700)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".high-water.", dir=self.status_dir
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = -1
                stream.write(_canonical_json_line({"high_water": sequence}))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.witness_path)
            os.chmod(self.witness_path, 0o600)
            _fsync_directory(self.status_dir)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            temporary.unlink(missing_ok=True)

    def _publish_start(self, identity: dict) -> dict:
        self._require_gate()
        validated = validate_collection_cycle_identity(identity)
        durable_publish_collection_cycle_json(
            self.start_path(validated["sequence"]),
            {"schema_version": 1, "kind": "start", "identity": validated},
        )
        return validated

    def _validate_identity_for_store(self, identity: object) -> dict:
        validated = validate_collection_cycle_identity(identity)
        if (
            validated["project_key"] != self.project_key
            or validated["scope"] != self.scope
            or validated["source"] != self.source
        ):
            raise ValueError("collection cycle identity does not belong to store")
        return validated

    def _validate_start_record(self, payload: object, sequence: int) -> dict:
        if not isinstance(payload, dict) or set(payload) != {
            "schema_version", "kind", "identity"
        } or payload.get("schema_version") != 1 or payload.get("kind") != "start":
            raise CollectionCycleHoldError("invalid start record")
        try:
            identity = self._validate_identity_for_store(payload["identity"])
        except ValueError as exc:
            raise CollectionCycleHoldError("invalid start record") from exc
        if identity["sequence"] != sequence:
            raise CollectionCycleHoldError("start identity association mismatch")
        return identity

    def _validate_launch_record(
        self, payload: object, identity: dict,
    ) -> dict[str, object]:
        if not isinstance(payload, dict) or set(payload) != {
            "schema_version", "kind", "identity", "pid", "boot_id",
            "process_start_time", "invocation_digest",
        } or payload.get("schema_version") != 1 or payload.get("kind") != "launch":
            raise CollectionCycleHoldError("invalid launch record")
        try:
            launch_identity = self._validate_identity_for_store(payload["identity"])
        except ValueError as exc:
            raise CollectionCycleHoldError("invalid launch record") from exc
        if launch_identity != identity:
            raise CollectionCycleHoldError("launch identity association mismatch")
        if (
            isinstance(payload["pid"], bool)
            or not isinstance(payload["pid"], int)
            or payload["pid"] <= 0
            or not isinstance(payload["boot_id"], str)
            or not payload["boot_id"]
            or not isinstance(payload["process_start_time"], str)
            or not payload["process_start_time"]
            or not isinstance(payload["invocation_digest"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", payload["invocation_digest"])
        ):
            raise CollectionCycleHoldError("invalid launch record")
        return dict(payload)

    def _validate_completion_record(
        self, payload: object, identity: dict,
    ) -> dict[str, object]:
        if not isinstance(payload, dict) or set(payload) != {
            "schema_version", "kind", "identity", "outcome", "run_result"
        } or payload.get("schema_version") != 1 or payload.get("kind") != "completion":
            raise CollectionCycleHoldError("invalid completion record")
        try:
            completion_identity = self._validate_identity_for_store(
                payload["identity"]
            )
        except ValueError as exc:
            raise CollectionCycleHoldError("invalid completion record") from exc
        if completion_identity != identity:
            raise CollectionCycleHoldError("completion identity association mismatch")
        outcome = payload["outcome"]
        if outcome not in COLLECTION_CYCLE_COMPLETION_OUTCOMES:
            raise CollectionCycleHoldError("invalid completion record")
        if outcome == "cycle_crashed":
            if payload["run_result"] is not None:
                raise CollectionCycleHoldError("invalid crashed completion")
            return dict(payload)
        try:
            run_result = _validate_collection_cycle_run_result(
                payload["run_result"], identity
            )
        except ValueError as exc:
            raise CollectionCycleHoldError("invalid completed result") from exc
        return {**payload, "run_result": run_result}

    def _record_groups(self) -> dict[int, dict[str, Path]]:
        if not self.records_dir.exists():
            return {}
        if not self.records_dir.is_dir():
            raise CollectionCycleHoldError("cycle record path is not a directory")
        groups: dict[int, dict[str, Path]] = {}
        for path in self.records_dir.iterdir():
            match = _COLLECTION_CYCLE_RECORD_NAME.fullmatch(path.name)
            if match is None or not path.is_file():
                raise CollectionCycleHoldError("unexpected cycle record filename")
            sequence = int(match.group("sequence"))
            try:
                validate_collection_cycle_sequence(sequence)
            except ValueError as exc:
                raise CollectionCycleHoldError("invalid cycle record sequence") from exc
            kind = match.group("kind")
            if kind in groups.setdefault(sequence, {}):
                raise CollectionCycleHoldError("duplicate cycle record kind")
            groups[sequence][kind] = path
        return groups

    def _scan_and_reconcile(self, process_inspector) -> tuple[int, frozenset[str]]:
        groups = self._record_groups()
        witness = self._read_witness()
        if not groups:
            if witness is None:
                return 0, frozenset()
            raise CollectionCycleHoldError("witness has no matching start")
        if witness is None:
            raise CollectionCycleHoldError("witness absent with records")
        maximum = max(groups)
        if witness < maximum:
            raise CollectionCycleHoldError("witness below record maximum")
        if witness > maximum:
            raise CollectionCycleHoldError("record maximum below witness")
        expected = list(range(1, maximum + 1))
        if sorted(groups) != expected:
            raise CollectionCycleHoldError("record gap")
        seen_tokens: set[str] = set()
        unfinished: tuple[dict, dict] | None = None
        for sequence in expected:
            records = groups[sequence]
            if "start" not in records:
                raise CollectionCycleHoldError("orphan cycle record")
            try:
                start_payload = _read_private_json(records["start"])
            except Exception as exc:
                raise CollectionCycleHoldError("invalid start record") from exc
            identity = self._validate_start_record(start_payload, sequence)
            if identity["run_token"] in seen_tokens:
                raise CollectionCycleHoldError("duplicate cycle run token")
            seen_tokens.add(identity["run_token"])
            launch = None
            if "launch" in records:
                try:
                    launch = self._validate_launch_record(
                        _read_private_json(records["launch"]), identity
                    )
                except CollectionCycleHoldError:
                    raise
                except Exception as exc:
                    raise CollectionCycleHoldError("invalid launch record") from exc
            completion = None
            if "completion" in records:
                if launch is None:
                    raise CollectionCycleHoldError("orphan completion record")
                try:
                    completion = self._validate_completion_record(
                        _read_private_json(records["completion"]), identity
                    )
                except CollectionCycleHoldError:
                    raise
                except Exception as exc:
                    raise CollectionCycleHoldError("invalid completion record") from exc
            if completion is None:
                if sequence != maximum:
                    raise CollectionCycleHoldError("record gap")
                if launch is None:
                    raise CollectionCycleHoldError("launch record missing")
                unfinished = (identity, launch)
        if unfinished is not None:
            identity, launch = unfinished
            binding = {
                **identity,
                **{
                    name: launch[name]
                    for name in (
                        "pid", "boot_id", "process_start_time",
                        "invocation_digest",
                    )
                },
            }
            try:
                state = process_inspector(binding)
            except Exception as exc:
                raise CollectionCycleHoldError(
                    "process inspection unavailable"
                ) from exc
            if state == "live":
                raise CollectionCycleHoldError("exact-token child live")
            if state != "dead":
                raise CollectionCycleHoldError("process inspection unavailable")
            self._publish_crashed_completion(identity)
        return witness, frozenset(seen_tokens)

    def allocate_start(
        self, *, process_inspector=inspect_collection_cycle_process,
    ) -> dict:
        self._require_gate()
        old_high_water, seen_tokens = self._scan_and_reconcile(process_inspector)
        sequence = validate_collection_cycle_sequence(old_high_water + 1)
        run_token = _mint_cycle_run_token()
        # A local-chain check is sufficient: project_key and scope are both
        # inside the cycle identity, so the same token under another key root
        # cannot collide the derived cycle_id.  Cross-root scanning would add
        # coupling without strengthening identity uniqueness.
        if run_token in seen_tokens:
            raise CollectionCycleHoldError("run_token_collision")
        self._write_witness(sequence)
        identity = build_collection_cycle_identity(
            self.project_identity,
            self.scope,
            sequence,
            run_token,
        )
        return self._publish_start(identity)

    def publish_launch(
        self,
        start: object,
        *,
        pid: object,
        boot_id: object,
        process_start_time: object,
        argv: object,
        context: object,
        credential_argv_positions: object,
        credential_context_names: object,
    ) -> dict[str, object]:
        self._require_gate()
        identity = self._validate_identity_for_store(start)
        if (
            isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0
            or not isinstance(boot_id, str) or not boot_id
            or not isinstance(process_start_time, str) or not process_start_time
        ):
            raise ValueError("collection cycle process binding is invalid")
        record = {
            "schema_version": 1,
            "kind": "launch",
            "identity": identity,
            "pid": pid,
            "boot_id": boot_id,
            "process_start_time": process_start_time,
            "invocation_digest": redacted_collection_cycle_invocation_digest(
                argv,
                context,
                credential_argv_positions=credential_argv_positions,
                credential_context_names=credential_context_names,
            ),
        }
        durable_publish_collection_cycle_json(
            self.launch_path(identity["sequence"]), record
        )
        return record

    def publish_completion(
        self, start: object, run_result: object,
    ) -> dict[str, object]:
        self._require_gate()
        identity = self._validate_identity_for_store(start)
        validated_result = _validate_collection_cycle_run_result(
            run_result, identity
        )
        record = {
            "schema_version": 1,
            "kind": "completion",
            "identity": identity,
            "outcome": "cycle_completed",
            "run_result": validated_result,
        }
        durable_publish_collection_cycle_json(
            self.completion_path(identity["sequence"]), record
        )
        return record

    def _publish_crashed_completion(self, start: object) -> dict[str, object]:
        self._require_gate()
        identity = self._validate_identity_for_store(start)
        record = {
            "schema_version": 1,
            "kind": "completion",
            "identity": identity,
            "outcome": "cycle_crashed",
            "run_result": None,
        }
        durable_publish_collection_cycle_json(
            self.completion_path(identity["sequence"]), record
        )
        return record

    def qualifying_completions(self) -> list[dict]:
        groups = self._record_groups()
        summaries = []
        for sequence in sorted(groups):
            records = groups[sequence]
            if "start" not in records or "completion" not in records:
                continue
            identity = self._validate_start_record(
                _read_private_json(records["start"]), sequence
            )
            completion = self._validate_completion_record(
                _read_private_json(records["completion"]), identity
            )
            run_result = completion["run_result"]
            if (
                completion["outcome"] == "cycle_completed"
                and run_result is not None
                and run_result["summary"] is not None
                and run_result["summary"]["qualifying"]
            ):
                summaries.append(run_result["summary"])
        return summaries


def timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _write_status_file(path: Path, prefix: str, state: str, **extra) -> None:
    STATUS_DIR.mkdir(parents=True, exist_ok=True)
    payload = {"state": state, "updated_at": timestamp(), **extra}
    descriptor, temporary = tempfile.mkstemp(prefix=prefix, dir=STATUS_DIR)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _active_cooldown_fields(path: Path) -> dict:
    """Preserve an unexpired cooldown while a status moves through other states."""
    descriptor = -1
    try:
        flags = (
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > 64 * 1024
        ):
            return {}
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            descriptor = -1
            payload = json.load(stream)
        if not isinstance(payload, dict):
            return {}
        next_epoch = payload.get("next_allowed_epoch")
        if (
            isinstance(next_epoch, bool)
            or not isinstance(next_epoch, (int, float))
            or not math.isfinite(float(next_epoch))
            or float(next_epoch) <= time.time()
        ):
            return {}
        return {
            name: payload[name]
            for name in _COOLDOWN_STATUS_FIELDS if name in payload
        }
    except (OSError, OverflowError, TypeError, ValueError, json.JSONDecodeError):
        return {}
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def write_status(state: str, **extra) -> None:
    retained = _active_cooldown_fields(STATUS_FILE)
    retained.update(extra)
    _write_status_file(STATUS_FILE, ".switch-collection.", state, **retained)


def write_yaml_backup_status(state: str, **extra) -> None:
    retained = _active_cooldown_fields(YAML_BACKUP_STATUS_FILE)
    retained.update(extra)
    _write_status_file(YAML_BACKUP_STATUS_FILE, ".yaml-backup.", state, **retained)


def write_continuous_status(state: str, **extra) -> None:
    _write_status_file(
        CONTINUOUS_STATUS_FILE, ".continuous-collection.", state, **extra,
    )


def write_continuous_backup_status(state: str, **extra) -> None:
    _write_status_file(
        CONTINUOUS_BACKUP_STATUS_FILE, ".continuous-backup.", state, **extra,
    )


def _publish_stage_l_status_after_completion(store) -> None:
    """Report independent REQ7 admission without changing cycle completion."""
    from monitor.issue_tracker_publish_runtime import StageLHold, inspect_stage_l

    project = Path(store.project_identity)
    try:
        status = inspect_stage_l(
            store, http_root=HTTP_ROOT, project=project,
            publication=project / "99-output-monitor",
            template_path=HTTP_ROOT / "monitor/Issue_Tracker_Template_v1.xlsx",
        )
    except StageLHold:
        status = {
            "schema_version": 1, "state": "hold",
            "reason": "stage_l_authority_unavailable",
            "panels": {
                name: {"state": "hold", "reason": "stage_l_authority_unavailable"}
                for name in ("Switch Status", "Eth Link Validation", "IB Link Validation")
            },
            "online": "disabled_no_send_authority",
        }
    _write_status_file(
        ISSUE_TRACKER_STAGE_L_STATUS_FILE, ".issue-tracker-stage-l.",
        status.pop("state"), **status,
    )


def _publish_stage_l_local_after_completion(store):
    """Admit at most one automatic local C6 after a protected prod cycle.

    A collector completion is already durable. This independent lane cannot
    turn a local result into Google authority or relabel collection success.
    """
    if store.scope != "prod":
        return None
    from monitor.issue_tracker_local_workbook_commit import (
        CommittedProdWorkbook, ProdWorkbookNoop,
    )
    from monitor.issue_tracker_publish_runtime import (
        AutoLocalCollectorAnomaly, AutoLocalNotDue, StageLHold,
        TerminalC6AdmissionHold,
        commit_qualified_prod_local, inspect_stage_l, local_publish_interval,
    )

    project = Path(store.project_identity)
    template = HTTP_ROOT / "monitor/Issue_Tracker_Template_v1.xlsx"
    publication = project / "99-output-monitor"
    try:
        interval, policy_sha = local_publish_interval(project)
        source = inspect_stage_l(
            store, http_root=HTTP_ROOT, project=project,
            publication=publication, template_path=template,
        )
        if source["state"] != "qualified":
            return None
        # A first admission is due after N unique completions, not only when
        # the lifetime total happens to be divisible by N. The held C6 writer
        # performs the protected admission/cycle recheck before any write.
        if source["completed_cycles"] < interval:
            source.update({
                "reason": "awaiting_publish_interval",
                "local": "not_due", "publish_every_cycles": interval,
                "policy_sha256": policy_sha,
            })
            _write_status_file(
                ISSUE_TRACKER_STAGE_L_STATUS_FILE, ".issue-tracker-stage-l.",
                source.pop("state"), **source,
            )
            return None
        if local_publish_interval(project) != (interval, policy_sha):
            raise StageLHold("automatic local policy changed before C6")
        result = commit_qualified_prod_local(
            store, http_root=HTTP_ROOT, project=project,
            publication=publication, template_path=template,
            refuse_prior_without_admission=True,
            auto_admission=(policy_sha, interval, _current_boot_identity(),
                            time.monotonic_ns()),
        )
        source["publish_every_cycles"] = interval
        source["policy_sha256"] = policy_sha
        if isinstance(result, AutoLocalNotDue):
            source["reason"] = result.reason
            source["local"] = "not_due"
            _write_status_file(
                ISSUE_TRACKER_STAGE_L_STATUS_FILE, ".issue-tracker-stage-l.",
                source.pop("state"), **source,
            )
            return None
        if isinstance(result, CommittedProdWorkbook):
            state = "local_applied"
            source["local"] = "receipt"
            source["local_receipt_sha256"] = result.receipt.published_sha256
        elif isinstance(result, ProdWorkbookNoop):
            if result.status == "no_candidates" and result.existing_published_sha256 is None:
                state = "local_no_candidates"
                source["local"] = "no_candidates"
            elif result.status == "no_change" and result.existing_published_sha256 is not None:
                state = "local_no_change"
                source["local"] = "no_change"
                source["local_receipt_sha256"] = result.existing_published_sha256
            else:
                raise StageLHold("unexpected local C6 no-op result")
        else:
            raise StageLHold("unexpected local C6 result")
        source["reason"] = ("qualified_empty_set_no_local_write"
                            if state == "local_no_candidates"
                            else "local_receipt_not_online_eligibility")
        _write_status_file(
            ISSUE_TRACKER_STAGE_L_STATUS_FILE, ".issue-tracker-stage-l.",
            state, **{key: value for key, value in source.items() if key != "state"},
        )
        return result
    except TerminalC6AdmissionHold as exc:
        _write_status_file(
            ISSUE_TRACKER_STAGE_L_STATUS_FILE, ".issue-tracker-stage-l.",
            "hold", schema_version=1, reason="local_c6_terminal_admission_state",
            terminal_detail=str(exc),
            online="disabled_no_send_authority",
        )
        return None
    except AutoLocalCollectorAnomaly:
        _write_status_file(
            ISSUE_TRACKER_STAGE_L_STATUS_FILE, ".issue-tracker-stage-l.",
            "hold", schema_version=1, reason="collector_interval_below_minimum",
            online="disabled_no_send_authority",
        )
        return None
    except StageLHold:
        _write_status_file(
            ISSUE_TRACKER_STAGE_L_STATUS_FILE, ".issue-tracker-stage-l.",
            "hold", schema_version=1, reason="local_c6_admission_refused",
            online="disabled_no_send_authority",
        )
        return None


def _validated_password(value) -> str:
    if not isinstance(value, str):
        raise ValueError("password must be text")
    payload = value.encode("utf-8")
    if len(payload) > MAX_PASSWORD_BYTES:
        raise ValueError("password exceeds 1024 bytes")
    if any(marker in value for marker in ("\x00", "\r", "\n")):
        raise ValueError("password contains a forbidden control character")
    return value


def decode_yaml_backup_request(payload: bytes) -> dict:
    """Decode one strict in-memory CGI request without logging its secret."""
    if not isinstance(payload, bytes) or len(payload) > MAX_MEMORY_REQUEST_BYTES:
        raise ValueError("invalid YAML backup request size")
    try:
        message = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid YAML backup request JSON") from exc
    if not isinstance(message, dict) or not isinstance(message.get("action"), str):
        raise ValueError("invalid YAML backup request schema")
    action = message["action"]
    if action == "yaml_backup":
        if set(message) != {"action", "password"}:
            raise ValueError("invalid YAML backup request schema")
        return {"action": action, "password": _validated_password(message["password"])}
    if action == "continuous_collection_start":
        if set(message) != {"action", "interval_minutes"}:
            raise ValueError("invalid continuous collection request schema")
        interval = _validated_interval(message, action)
        return {
            "action": action,
            "interval_minutes": interval,
        }
    if action == "continuous_backup_start":
        if set(message) != {"action", "password", "interval_minutes"}:
            raise ValueError("invalid continuous backup request schema")
        interval = _validated_interval(message, action)
        return {
            "action": action,
            "password": _validated_password(message["password"]),
            "interval_minutes": interval,
        }
    if action in {
        "continuous_collection_stop", "continuous_backup_stop",
    } and set(message) == {"action"}:
        return {"action": action}
    raise ValueError("unsupported YAML backup request action")


def open_memory_socket(path: Path = YAML_BACKUP_SOCKET):
    """Bind the root worker's private datagram endpoint for the CGI."""
    if sys.platform == "darwin" and os.geteuid() != 0:
        # macOS is configuration-generation/test mode only; its sandbox can
        # reject filesystem AF_UNIX binds.  Keep the worker lifecycle testable
        # without publishing a control endpoint that cannot be served there.
        class DisabledMemorySocket:
            def recv(self, _size):
                raise BlockingIOError()

            def close(self):
                return None

        return DisabledMemorySocket(), None
    path = Path(path)
    if os.path.lexists(path):
        metadata = os.lstat(path)
        if (
            not stat.S_ISSOCK(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
        ):
            raise OSError(f"unsafe existing YAML backup socket: {path}")
        path.unlink()
    endpoint = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        endpoint.bind(str(path))
        os.chmod(path, 0o660)
        if os.geteuid() == 0:
            os.chown(path, 0, grp.getgrnam("www-data").gr_gid)
        elif sys.platform != "darwin":
            raise PermissionError("YAML backup socket worker must run as root")
        metadata = os.lstat(path)
        if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_nlink != 1:
            raise OSError(f"invalid YAML backup socket: {path}")
        endpoint.setblocking(False)
        return endpoint, (metadata.st_dev, metadata.st_ino)
    except Exception:
        endpoint.close()
        try:
            path.unlink()
        except OSError:
            pass
        raise


def close_memory_socket(endpoint, identity, path: Path = YAML_BACKUP_SOCKET) -> None:
    endpoint.close()
    if identity is None:
        return
    try:
        metadata = os.lstat(path)
        if (
            stat.S_ISSOCK(metadata.st_mode)
            and (metadata.st_dev, metadata.st_ino) == identity
        ):
            Path(path).unlink()
    except OSError:
        pass


def receive_memory_requests(endpoint) -> list[dict]:
    requests = []
    while True:
        try:
            payload = endpoint.recv(MAX_MEMORY_REQUEST_BYTES + 1)
        except BlockingIOError:
            return requests
        requests.append(decode_yaml_backup_request(payload))


def read_request() -> str:
    """Compatibility read helper using the same safe file contract as claim."""
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(REQUEST_FILE, flags)
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_SH)
            metadata = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_size > 64
            ):
                return ""
            value = stream.read(64).strip()
            return value if value == "collect" else ""
    except OSError:
        return ""


def claim_request(expected: str = "") -> str:
    """Atomically consume one exact request without erasing a newer action."""
    if expected and expected != "collect":
        return ""
    try:
        flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(REQUEST_FILE, flags)
        with os.fdopen(descriptor, "r+", encoding="utf-8") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            metadata = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_size > 64
            ):
                return ""
            current = stream.read().strip()
            if current != "collect" or (expected and current != expected):
                return ""
            stream.seek(0)
            stream.write("idle\n")
            stream.truncate()
            stream.flush()
            os.fsync(stream.fileno())
            return current
    except OSError as exc:
        print(f"[{timestamp()}] [WARN] cannot claim request: {exc}", flush=True)
        return ""


def commands_for_scope(scope: str, lock_wait: int = 600) -> list[list[str]]:
    commands = []
    wait_args = ["--wait-lock", str(max(lock_wait, 0))]
    if scope in {"air", "all"}:
        commands.append(["bash", str(SCRIPTS["ethernet"]), *wait_args, "--air"])
    if scope in {"prod", "all"}:
        commands.extend([
            ["bash", str(SCRIPTS["ethernet"]), *wait_args, "--prod"],
            ["bash", str(SCRIPTS["infiniband"]), *wait_args],
            ["bash", str(SCRIPTS["nvlink"]), *wait_args],
        ])
    return commands


def collection_process_ids(proc_root: Path = Path("/proc")) -> set[int]:
    """Find only processes whose argv contains one of our exact cron.sh paths."""
    if not proc_root.is_dir():
        return set()
    # argv preserves the path used to invoke a script.  IB and NVLink cron.sh
    # are deployment aliases of the Ethernet implementation, so resolving the
    # three paths would collapse them to one canonical filename and make stop
    # miss processes started through either alias.
    scripts = {str(path) for path in SCRIPTS.values()}
    scripts.update(str(path.resolve()) for path in SCRIPTS.values())
    parents: dict[int, int] = {}
    targets: set[int] = set()
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            argv = [item.decode("utf-8", errors="replace") for item in
                    (entry / "cmdline").read_bytes().split(b"\0") if item]
            stat_fields = (entry / "stat").read_text(encoding="utf-8").split(") ", 1)[1].split()
            parents[pid] = int(stat_fields[1])
        except (OSError, ValueError, IndexError):
            continue
        if any(argument in scripts for argument in argv):
            targets.add(pid)
    # Include SSH/SCP/sleep descendants belonging to those exact collectors.
    changed = True
    while changed:
        changed = False
        for pid, parent in parents.items():
            if parent in targets and pid not in targets:
                targets.add(pid)
                changed = True
    targets.discard(os.getpid())
    return targets


def _process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # Treat a group we cannot inspect as live so the shutdown contract
        # fails closed and still attempts the configured escalation.
        return True


def _signal_collector_group(process: subprocess.Popen, sig: int) -> bool:
    """Signal the private session created for one collector invocation."""
    try:
        os.killpg(process.pid, sig)
        return True
    except ProcessLookupError:
        return False
    except PermissionError as exc:
        print(
            f"[{timestamp()}] [WARN] cannot signal collector process group "
            f"{process.pid}: {exc}",
            file=sys.stderr, flush=True,
        )
        return False


def _wait_for_collector_group_exit(
    process: subprocess.Popen, timeout: float,
) -> bool:
    deadline = time.monotonic() + max(float(timeout), 0.0)
    while True:
        # poll() reaps the direct child while killpg(..., 0) also accounts for
        # descendants that remain after their group leader has exited.
        process.poll()
        if not _process_group_exists(process.pid):
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(COLLECTOR_EXIT_POLL_SECONDS, remaining))


def terminate_collector_process(
    process: subprocess.Popen,
    *,
    term_grace_seconds: float = COLLECTOR_TERM_GRACE_SECONDS,
    kill_grace_seconds: float = COLLECTOR_KILL_GRACE_SECONDS,
) -> bool:
    """Stop one collector session, escalating from TERM to KILL if needed."""
    if _process_group_exists(process.pid):
        _signal_collector_group(process, signal.SIGTERM)
    stopped = _wait_for_collector_group_exit(process, term_grace_seconds)
    if not stopped:
        _signal_collector_group(process, signal.SIGKILL)
        stopped = _wait_for_collector_group_exit(process, kill_grace_seconds)
    process.poll()
    return stopped


def _validate_lane(lane: str) -> str:
    if lane not in VALID_LANES:
        raise ValueError(f"invalid collection lane: {lane}")
    return lane


def _set_active_collector(
    process: subprocess.Popen, lane: str = COLLECTION_LANE,
) -> None:
    lane = _validate_lane(lane)
    with _ACTIVE_COLLECTOR_LOCK:
        if _ACTIVE_COLLECTORS[lane] is not None:
            raise RuntimeError(f"another {lane} process is already active")
        _ACTIVE_COLLECTORS[lane] = process


def _clear_active_collector(
    process: subprocess.Popen, lane: str = COLLECTION_LANE,
) -> None:
    lane = _validate_lane(lane)
    with _ACTIVE_COLLECTOR_LOCK:
        if _ACTIVE_COLLECTORS[lane] is process:
            _ACTIVE_COLLECTORS[lane] = None


def lane_cancelled(lane: str) -> bool:
    return _LANE_CANCEL[_validate_lane(lane)].is_set()


def lane_busy(lane: str, *, origin: str | None = None) -> bool:
    lane = _validate_lane(lane)
    with _LANE_TASK_LOCK:
        task = _LANE_TASKS[lane]
        return (
            task is not None and task.is_alive()
            and (origin is None or _LANE_TASK_ORIGINS[lane] == origin)
        )


def start_lane_task(lane: str, origin: str, target, *args) -> bool:
    """Start one lane task without serializing the other operation type."""
    lane = _validate_lane(lane)
    if origin not in {"manual", "continuous"} or not callable(target):
        raise ValueError("invalid lane task")

    def run() -> None:
        try:
            target(*args)
        except Exception as exc:  # defensive boundary for a persistent worker
            print(
                f"[{timestamp()}] [ERROR] unexpected {lane} task failure: "
                f"{type(exc).__name__}: {exc}", file=sys.stderr, flush=True,
            )
            traceback.print_exc()
        finally:
            if origin == "continuous":
                _finalize_continuous_stop_if_requested(lane)
            current = threading.current_thread()
            with _LANE_TASK_LOCK:
                if _LANE_TASKS[lane] is current:
                    _LANE_TASKS[lane] = None
                    _LANE_TASK_ORIGINS[lane] = None
                    _LANE_CANCEL[lane].clear()

    with _LANE_TASK_LOCK:
        current = _LANE_TASKS[lane]
        if current is not None and current.is_alive():
            return False
        _LANE_CANCEL[lane].clear()
        task = threading.Thread(
            target=run, name=f"switch-worker-{lane}-{origin}", daemon=False,
        )
        _LANE_TASKS[lane] = task
        _LANE_TASK_ORIGINS[lane] = origin
        task.start()
    return True


def request_lane_stop(lane: str, *, origin: str | None = None) -> bool:
    """Cancel only a matching active lane task; never cross operation types."""
    lane = _validate_lane(lane)
    with _LANE_TASK_LOCK:
        task = _LANE_TASKS[lane]
        if task is None or not task.is_alive():
            return False
        if origin is not None and _LANE_TASK_ORIGINS[lane] != origin:
            return False
        _LANE_CANCEL[lane].set()
    with _ACTIVE_COLLECTOR_LOCK:
        process = _ACTIVE_COLLECTORS[lane]
    if process is not None:
        _signal_collector_group(process, signal.SIGTERM)
    return True


def join_lane_tasks(timeout: float | None = None) -> None:
    deadline = None if timeout is None else time.monotonic() + max(timeout, 0.0)
    for lane in (COLLECTION_LANE, BACKUP_LANE):
        with _LANE_TASK_LOCK:
            task = _LANE_TASKS[lane]
        if task is None or task is threading.current_thread():
            continue
        remaining = None if deadline is None else max(0.0, deadline - time.monotonic())
        task.join(remaining)


def _request_shutdown(signum: int, _frame) -> None:
    """Record service shutdown and promptly TERM both detached child sessions."""
    global _SHUTDOWN_SIGNAL
    if _SHUTDOWN_SIGNAL is None:
        _SHUTDOWN_SIGNAL = int(signum)
    for lane in VALID_LANES:
        _LANE_CANCEL[lane].set()
        process = _ACTIVE_COLLECTORS[lane]
        if process is not None:
            _signal_collector_group(process, signal.SIGTERM)


def _shutdown_requested() -> bool:
    return _SHUTDOWN_SIGNAL is not None


def stop_all_collectors() -> list[int]:
    targets = collection_process_ids()
    for lane in VALID_LANES:
        _LANE_CANCEL[lane].set()
        process = _ACTIVE_COLLECTORS[lane]
        if process is not None:
            targets.add(process.pid)
            terminate_collector_process(process)
    targets.update(collection_process_ids())
    for sig in (signal.SIGTERM, signal.SIGKILL):
        for pid in sorted(targets, reverse=True):
            try:
                os.kill(pid, sig)
            except (OSError, ProcessLookupError):
                pass
        if sig == signal.SIGTERM and targets:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if not any((Path("/proc") / str(pid)).exists() for pid in targets):
                    return sorted(targets)
                time.sleep(0.2)
    return sorted(targets)


def run_interruptible(
    command: list[str], cwd: Path, timeout: int, *, pass_fds: tuple[int, ...] = (),
    lane: str = COLLECTION_LANE,
) -> tuple[dict, bool]:
    """Run one child while servicing only its lane's stop request."""
    lane = _validate_lane(lane)
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stdout_file, \
            tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stderr_file:
        if _shutdown_requested():
            return {
                "returncode": 128 + int(_SHUTDOWN_SIGNAL),
                "stdout": "", "stderr": "worker shutdown requested",
            }, True
        process = subprocess.Popen(
            command, cwd=cwd, text=True, stdout=stdout_file, stderr=stderr_file,
            stdin=subprocess.DEVNULL, start_new_session=True, pass_fds=pass_fds,
        )
        try:
            _set_active_collector(process, lane)
        except Exception:
            terminate_collector_process(process)
            raise
        deadline = time.monotonic() + timeout
        cancelled = False
        cleanup_succeeded = True
        try:
            while process.poll() is None:
                if _shutdown_requested() or lane_cancelled(lane):
                    cancelled = True
                    terminate_collector_process(process)
                    break
                if time.monotonic() >= deadline:
                    terminate_collector_process(process)
                    return {
                        "returncode": 124, "stdout": "",
                        "stderr": f"timeout after {timeout}s",
                    }, False
                time.sleep(0.2)
        finally:
            # This also handles exceptions in request processing and prevents
            # a detached session from surviving an unexpected worker failure.
            try:
                if _process_group_exists(process.pid):
                    cleanup_succeeded = terminate_collector_process(process)
            finally:
                _clear_active_collector(process, lane)
        if not cleanup_succeeded:
            raise RuntimeError(
                f"collector process group {process.pid} did not stop after escalation"
            )
        process.wait()
        stdout_file.seek(0)
        stderr_file.seek(0)
        return {"returncode": process.returncode,
                "stdout": stdout_file.read(), "stderr": stderr_file.read()}, cancelled


def _yaml_backup_scope(scope: str) -> str:
    return scope if scope in {"air", "prod"} else "auto"


_FAILED_DEVICE_OPERATION_RE = re.compile(r"^[a-z][a-z0-9_]*$")


def _validated_operation_authority(permitted_operations: object) -> tuple[str, ...]:
    if (
        not isinstance(permitted_operations, tuple)
        or not permitted_operations
        or len(permitted_operations) != len(set(permitted_operations))
        or tuple(sorted(permitted_operations)) != permitted_operations
        or any(
            not isinstance(operation, str)
            or not _FAILED_DEVICE_OPERATION_RE.fullmatch(operation)
            for operation in permitted_operations
        )
    ):
        raise ValueError("permitted_operations must be a non-empty canonical tuple")
    return permitted_operations


def parse_task_result(
    output: str,
    expected_task: str,
    *,
    permitted_operations: tuple[str, ...],
) -> dict:
    """Validate one collector-owned machine result without trusting log text."""
    permitted_operations = _validated_operation_authority(permitted_operations)
    if expected_task not in {"switch_collection", "yaml_backup"}:
        raise ValueError("unsupported task result type")
    if not isinstance(output, str):
        raise ValueError("task output must be text")
    markers = [
        line[len(TASK_RESULT_PREFIX):]
        for line in output.splitlines()
        if line.startswith(TASK_RESULT_PREFIX)
    ]
    if len(markers) != 1:
        raise ValueError("task output must contain exactly one result marker")
    try:
        payload = json.loads(markers[0])
    except json.JSONDecodeError as exc:
        raise ValueError("task result is not valid JSON") from exc
    required = {
        "schema_version", "task", "state", "planned", "succeeded",
        "failed_count", "failed_devices",
    }
    if not isinstance(payload, dict) or set(payload) != required:
        raise ValueError("invalid task result schema")
    if payload["schema_version"] != 1 or payload["task"] != expected_task:
        raise ValueError("task result identity mismatch")
    if payload["state"] not in {"success", "partial", "failed"}:
        raise ValueError("invalid task result state")
    for name in ("planned", "succeeded", "failed_count"):
        value = payload[name]
        if (
            isinstance(value, bool) or not isinstance(value, int)
            or value < 0 or value > MAX_TASK_RESULT_DEVICES
        ):
            raise ValueError(f"invalid {name}")
    failures = payload["failed_devices"]
    if not isinstance(failures, list) or len(failures) > MAX_TASK_RESULT_DEVICES:
        raise ValueError("invalid failed_devices")
    seen = set()
    for item in failures:
        if not isinstance(item, dict) or set(item) != {
            "hostname", "operation", "reason",
        }:
            raise ValueError("invalid failed_devices entry")
        for name in ("hostname", "operation", "reason"):
            value = item[name]
            if (
                not isinstance(value, str) or not value.strip()
                or len(value.encode("utf-8")) > MAX_TASK_RESULT_TEXT_BYTES
                or any(marker in value for marker in ("\x00", "\r", "\n"))
            ):
                raise ValueError(f"invalid failed_devices {name}")
        operations = item["operation"].split(",")
        if (
            any(not operation for operation in operations)
            or len(operations) != len(set(operations))
            or tuple(sorted(operations)) != tuple(operations)
            or any(operation not in permitted_operations for operation in operations)
            or ",".join(operations) != item["operation"]
        ):
            raise ValueError("invalid failed_devices operation")
        folded = item["hostname"].casefold()
        if folded in seen:
            raise ValueError("duplicate failed device")
        seen.add(folded)
    if payload["failed_count"] != len(failures):
        raise ValueError("failed_count does not match failed_devices")
    if payload["succeeded"] + payload["failed_count"] != payload["planned"]:
        raise ValueError("task result counts do not match planned")
    if expected_task == "yaml_backup" and payload["planned"] == 0:
        raise ValueError("yaml backup task reported zero planned devices")
    state = payload["state"]
    if state == "success" and payload["failed_count"] != 0:
        raise ValueError("success task result contains failures")
    if state == "partial" and not (
        payload["succeeded"] > 0 and payload["failed_count"] > 0
    ):
        raise ValueError("partial task result requires success and failure")
    if state == "failed" and payload["succeeded"] != 0:
        raise ValueError("failed task result contains successes")
    return payload


class CollectionSlotParseError(ValueError):
    """One fail-closed worker outcome produced while parsing a child marker."""

    def __init__(self, outcome: str, detail: str):
        if outcome not in COLLECTION_SLOT_TERMINAL_OUTCOMES or outcome == "accepted":
            raise ValueError("invalid collection slot parse outcome")
        super().__init__(detail)
        self.outcome = outcome


def _collection_slot_marker_payload(output: object) -> object:
    if not isinstance(output, str):
        raise CollectionSlotParseError(
            "malformed_marker", "collection slot output must be text"
        )
    markers = [
        line[len(TASK_RESULT_PREFIX):]
        for line in output.splitlines()
        if line.startswith(TASK_RESULT_PREFIX)
    ]
    if not markers:
        raise CollectionSlotParseError(
            "missing_marker", "collection slot output has no result marker"
        )
    if len(markers) == 2:
        raise CollectionSlotParseError(
            "duplicate_marker", "collection slot output has a duplicate marker"
        )
    if len(markers) > 2:
        raise CollectionSlotParseError(
            "extra_marker", "collection slot output has extra markers"
        )
    try:
        return json.loads(markers[0])
    except json.JSONDecodeError as exc:
        raise CollectionSlotParseError(
            "malformed_marker", "collection slot marker is not valid JSON"
        ) from exc


def parse_collection_slot_result(
    output: object,
    *,
    expected_context: object,
    expected_slot: object,
) -> dict:
    """Return one validated v2 child or bounded evidence-only v1 child.

    Legacy markers remain schema v1.  In particular, this boundary never
    manufactures the identity, slot, artifact, or inventory assertions that
    only a future v2 producer is allowed to make.
    """
    identity = validate_collection_cycle_identity(expected_context)
    if expected_slot not in collection_cycle_source_slots(identity["scope"]):
        raise CollectionSlotParseError(
            "identity_mismatch", "collection slot is outside the expected scope"
        )
    payload = _collection_slot_marker_payload(output)
    if not isinstance(payload, dict):
        raise CollectionSlotParseError(
            "malformed_marker", "collection slot marker must contain an object"
        )
    version = payload.get("schema_version")
    try:
        if type(version) is int and version == 1:
            return _validate_collection_cycle_legacy_result(payload)
        if type(version) is not int or version != 2:
            raise ValueError("unsupported collection slot schema")

        # Classify a structurally present but forged context separately from a
        # malformed child record.  The full validator still rechecks every
        # field and exact key set below.
        for key, expected in identity.items():
            if key in payload and (
                type(payload[key]) is not type(expected)
                or payload[key] != expected
            ):
                raise CollectionSlotParseError(
                    "identity_mismatch",
                    f"collection slot identity mismatch: {key}",
                )
        if "source_slot" in payload and payload["source_slot"] != expected_slot:
            raise CollectionSlotParseError(
                "identity_mismatch", "collection slot source mismatch"
            )
        return validate_collection_cycle_result(
            payload,
            expected_identity=identity,
            expected_slot=expected_slot,
        )
    except CollectionSlotParseError:
        raise
    except ValueError as exc:
        raise CollectionSlotParseError(
            "malformed_marker", f"invalid collection slot marker: {exc}"
        ) from exc


def _collection_slot_stream_evidence(value: str) -> dict[str, object]:
    encoded = value.encode("utf-8")
    return {
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "size_bytes": len(encoded),
    }


def _collection_slot_process_evidence(result: object) -> dict[str, object]:
    if not isinstance(result, dict) or set(result) != {
        "returncode", "stdout", "stderr"
    }:
        raise ValueError("collection slot process result has invalid keys")
    returncode = result["returncode"]
    if isinstance(returncode, bool) or not isinstance(returncode, int):
        raise ValueError("collection slot returncode must be an integer")
    stdout = result["stdout"]
    stderr = result["stderr"]
    if not isinstance(stdout, str) or not isinstance(stderr, str):
        raise ValueError("collection slot streams must be text")
    # Stream digests are permitted only while the real collector's
    # password-invariance proof remains true.  If that proof regresses, these
    # digests must be treated as credential oracles and reconsidered.
    return {
        "stdout": _collection_slot_stream_evidence(stdout),
        "stderr": _collection_slot_stream_evidence(stderr),
        "returncode": returncode,
    }


def _validate_collection_slot_stream_evidence(
    value: object, field: str,
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {"sha256", "size_bytes"}:
        raise ValueError(f"collection slot {field} evidence has invalid keys")
    digest = value["sha256"]
    size = value["size_bytes"]
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
        or isinstance(size, bool)
        or not isinstance(size, int)
        or size < 0
    ):
        raise ValueError(f"collection slot {field} evidence is invalid")
    if size == 0 and digest != hashlib.sha256(b"").hexdigest():
        raise ValueError(f"collection slot {field} zero-byte digest is invalid")
    return {"sha256": digest, "size_bytes": size}


def validate_collection_slot_outcome(
    value: object,
    *,
    expected_slot: object,
    expected_context: object,
) -> dict[str, object]:
    """Validate one exact worker-owned terminal lifecycle wrapper."""
    identity = validate_collection_cycle_identity(expected_context)
    if expected_slot not in collection_cycle_source_slots(identity["scope"]):
        raise ValueError("collection slot outcome is outside the expected scope")
    if not isinstance(value, dict) or set(value) != {
        "source_slot", "outcome", "child_result", "evidence"
    }:
        raise ValueError("collection slot outcome has invalid keys")
    if value["source_slot"] != expected_slot:
        raise ValueError("collection slot outcome source mismatch")
    outcome = value["outcome"]
    if outcome not in COLLECTION_SLOT_TERMINAL_OUTCOMES:
        raise ValueError("collection slot outcome is not in the closed vocabulary")
    child = value["child_result"]
    if outcome == "accepted":
        if not isinstance(child, dict):
            raise ValueError("accepted collection slot outcome requires a child")
        if type(child.get("schema_version")) is int and child["schema_version"] == 1:
            normalized_child = _validate_collection_cycle_legacy_result(child)
        else:
            normalized_child = validate_collection_cycle_result(
                child,
                expected_identity=identity,
                expected_slot=expected_slot,
            )
    else:
        if child is not None:
            raise ValueError("non-success collection slot outcome cannot carry a child")
        normalized_child = None
    evidence = value["evidence"]
    if not isinstance(evidence, dict) or set(evidence) != {
        "stdout", "stderr", "returncode"
    }:
        raise ValueError("collection slot outcome evidence has invalid keys")
    returncode = evidence["returncode"]
    if isinstance(returncode, bool) or not isinstance(returncode, int):
        raise ValueError("collection slot outcome returncode must be an integer")
    return {
        "source_slot": expected_slot,
        "outcome": outcome,
        "child_result": normalized_child,
        "evidence": {
            "stdout": _validate_collection_slot_stream_evidence(
                evidence["stdout"], "stdout"
            ),
            "stderr": _validate_collection_slot_stream_evidence(
                evidence["stderr"], "stderr"
            ),
            "returncode": returncode,
        },
    }


def _collection_slot_file_evidence(path: object) -> dict[str, object]:
    candidate = Path(path)
    content = candidate.read_bytes()
    return {
        "sha256": hashlib.sha256(content).hexdigest(),
        "size_bytes": len(content),
    }


_COLLECTION_ARTIFACT_ROLES = ("info_archive", "link_archive", "link_csv")


def _collection_private_json(path: Path) -> dict:
    content = path.read_bytes()
    if len(content) > 1024 * 1024:
        raise ValueError("collection sidecar is oversized")
    value = json.loads(content.decode("utf-8"))
    if not isinstance(value, dict) or _canonical_json_line(value) != content:
        raise ValueError("collection sidecar is not canonical JSON")
    return value


def _collection_artifact_path(root: Path, relative: object) -> Path:
    if (not isinstance(relative, str) or not relative
            or any(character in relative for character in ("\x00", "\r", "\n"))
            or "\\" in relative):
        raise ValueError("collection artifact path is invalid")
    pure = PurePosixPath(relative)
    if (pure.is_absolute() or str(pure) != relative
            or any(part in {"", ".", ".."} for part in relative.split("/"))):
        raise ValueError("collection artifact path is not canonical relative")
    candidate = root
    for part in pure.parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise ValueError("collection artifact path traverses a symlink")
    if not candidate.is_file():
        raise ValueError("collection artifact is missing")
    return candidate


def _collection_inventory_count(content: bytes, slot: str) -> tuple[int, bool]:
    text = content.decode("utf-8")
    rows = list(csv.DictReader(io.StringIO(text)))
    expected_type = {"ethernet": {"eth", "eth_spx", "spx"},
                     "infiniband": {"ib"}, "nvlink": {"nvl"}}[slot.split("/")[0]]
    selected = [row for row in rows if row.get("type", "").lower() in expected_type]
    return len(selected), any(row.get("type", "").lower() in {"eth_spx", "spx"}
                              for row in selected)


def _collection_target_plan_matches_sources(
    context: dict, inventory: bytes, slot: str,
) -> bool:
    """Independently reject planner rows without frozen input provenance."""
    try:
        area, scope = slot.split("/", 1)
        plan = context["target_plan"]
        rows = list(csv.DictReader(io.StringIO(inventory.decode("utf-8"))))
        types = {"ethernet": {"air"} if scope == "air" else
                 {"eth", "eth_spx", "spx"},
                 "infiniband": {"ib"}, "nvlink": {"nvl"}}[area]
        static = [row for row in rows if row.get("type", "").strip().lower() in types]
        key = {"ethernet": "eth", "infiniband": "ib", "nvlink": "nv"}[area]
        entries = plan[key]
        if not isinstance(entries, list) or not entries:
            return False
        parsed = []
        for item in entries:
            pieces = item.split("|")
            if len(pieces) not in (2, 3):
                return False
            ipaddress.IPv4Address(pieces[1])
            parsed.append((pieces[0], pieces[1]))
        if ([item[0] for item in parsed[:len(static)]] !=
                [row["hostname"].strip() for row in static]):
            return False
        for row, (name, actual_ip) in zip(static, parsed):
            source_ip = row["eth0_ip"].strip()
            if actual_ip == source_ip:
                continue
            if scope != "air" or not any(
                (parts := raw.split("|"))[0] == name
                and len(parts) == 6 and parts[1] == actual_ip
                and parts[4] == "dhcp-lease-transition"
                for raw in context["air_dynamic_rows"]
            ):
                return False
        if len({name.casefold() for name, _ip in parsed}) != len(parsed):
            return False
        if area == "ethernet":
            expected_links = [row["hostname"].strip() for row in static
                              if row.get("type", "").strip().lower() in
                              {"eth_spx", "spx"}]
            if [item.split("|", 1)[0] for item in plan["spx"]] != expected_links:
                return False
        elif plan["spx"] or plan["dynamic_identities"]:
            return False
        if any(plan[name] for name in {"eth", "ib", "nv"} - {key}):
            return False
        expected_extra = []
        expected_identities = []
        static_names = {row["hostname"].strip().casefold() for row in static}
        if area == "ethernet" and scope == "air":
            for raw in context["air_dynamic_rows"]:
                pieces = raw.split("|")
                if len(pieces) != 6:
                    return False
                name, ip, mac, _template, source, _issue = pieces
                if not ip:
                    continue
                ipaddress.IPv4Address(ip)
                if name.casefold() in static_names:
                    if source == "dhcp-lease-transition":
                        expected_identities.append(f"{name}|{mac}|{source}")
                    continue
                if name.casefold() in {n.casefold() for n, _ in expected_extra}:
                    continue
                expected_extra.append((name, ip))
                expected_identities.append(f"{name}|{mac}|{source or 'dhcp-lease'}")
        elif area == "ethernet":
            used_ips = {ip for _name, ip in parsed[:len(static)]}
            for raw in context["prod_runtime_rows"]:
                pieces = raw.split("|")
                if len(pieces) != 4:
                    return False
                mac, ip, platform, lease_state = pieces
                if platform != "cumulus" or lease_state not in {"active", "observed"}:
                    continue
                normalized = re.sub(r"[^0-9a-f]", "", mac.casefold())
                if len(normalized) != 12 or any(c not in "0123456789abcdef" for c in normalized):
                    continue
                if not ip:
                    continue
                ipaddress.IPv4Address(ip)
                name = "DISCOVERED-CUMULUS-" + normalized.upper()
                if (ip in used_ips or name.casefold() in static_names
                        or name.casefold() in {n.casefold() for n, _ in expected_extra}):
                    continue
                expected_extra.append((name, ip))
                expected_identities.append(f"{name}|{mac}|dhcp-unbound-cumulus")
                used_ips.add(ip)
        return (parsed[len(static):] == expected_extra
                and plan["dynamic_identities"] == expected_identities)
    except (ValueError, KeyError, TypeError, UnicodeError, AttributeError):
        return False


def _collection_runtime_snapshots_match(context: dict, inventory_path: Path) -> bool:
    try:
        hashes = context["runtime_input_hashes"]
        allowed = {"leases": ".leases", "air_json": ".air.json",
                   "dhcp_log": ".dhcp.log"}
        if (not isinstance(hashes, dict) or
                not set(hashes).issubset(set(allowed) | {"journal_derived_rows"})):
            return False
        for key, suffix in allowed.items():
            if key not in hashes:
                continue
            path = inventory_path.with_suffix(suffix)
            if path.is_symlink() or not path.is_file():
                return False
            if hashlib.sha256(path.read_bytes()).hexdigest() != hashes[key]:
                return False
        if "journal_derived_rows" in hashes and hashlib.sha256(
            _canonical_json_line(context["prod_runtime_rows"])
        ).hexdigest() != hashes["journal_derived_rows"]:
            return False
        return True
    except (OSError, TypeError, ValueError, KeyError):
        return False


def _collection_freeze_plan_sources(
    slot: str, bindings: dict, context: dict, plan_raw: bytes,
) -> dict[str, str]:
    """Persist the exact planner output and derived rows within this cycle.

    The anonymous planning FD is deliberately not a later source authority:
    a read-only consumer must be able to recheck these fixed, private bytes
    against the child envelope rather than accepting a caller-supplied plan.
    """
    if not getattr(os, "O_NOFOLLOW", 0):
        raise ValueError("cycle-owned input freeze requires no-follow support")
    directory = Path(bindings["input_inventory"]).parent
    stem = slot.replace("/", "-")
    payloads = {"target_plan": (directory / f"{stem}.target-plan.json", plan_raw)}
    if slot == "ethernet/prod":
        payloads["runtime_derived_rows"] = (
            directory / f"{stem}.runtime-derived-rows.json",
            _canonical_json_line(context["prod_runtime_rows"]),
        )
    frozen = {}
    for role, (path, payload) in payloads.items():
        descriptor = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0), 0o600,
        )
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(descriptor)
        finally:
            os.close(descriptor)
        frozen[role] = str(path)
    _fsync_directory(directory)
    return frozen


def _collection_frozen_plan_sources_match(
    slot: str, bindings: dict, context: dict, plan_raw: bytes,
) -> bool:
    try:
        directory = Path(bindings["input_inventory"]).parent
        stem = slot.replace("/", "-")
        expected = {directory / f"{stem}.target-plan.json": plan_raw}
        if slot == "ethernet/prod":
            expected[directory / f"{stem}.runtime-derived-rows.json"] = (
                _canonical_json_line(context["prod_runtime_rows"])
            )
        for path, payload in expected.items():
            if path.is_symlink() or not path.is_file() or path.read_bytes() != payload:
                return False
        return True
    except (OSError, TypeError, ValueError, KeyError):
        return False


def _collection_validate_artifact_roles(
    evidence: dict, *, root: Path, child: dict, inventory: bytes,
    context: dict | None = None,
) -> bool:
    if set(evidence) != {"roles"} or not isinstance(evidence["roles"], list):
        return False
    roles = evidence["roles"]
    activity = context is not None and "activity" in context
    ib_analysis = context is not None and "ib_analysis" in context
    if activity and ib_analysis:
        return False
    expected_roles = [*_COLLECTION_ARTIFACT_ROLES]
    if activity:
        expected_roles.append("activity_observation")
    if ib_analysis:
        from monitor.collection_ib_producer import IB_ROLE_NAMES
        expected_roles.extend(IB_ROLE_NAMES)
    if len(roles) != len(expected_roles) or [
        item.get("role") if isinstance(item, dict) else None for item in roles
    ] != expected_roles:
        return False
    slot = child["source_slot"]
    area, _scope = slot.split("/", 1)
    prefix = {"ethernet": ("eth-info", "spx-link", "spx-link"),
              "infiniband": ("ib-info", "ib-link", "ib-link"),
              "nvlink": ("nvsw-info", "nvsw-link", "nvsw-link")}[area]
    count, link_selected = _collection_inventory_count(inventory, slot)
    if context is not None:
        plan = context["target_plan"]
        key = {"ethernet": "eth", "infiniband": "ib", "nvlink": "nv"}[area]
        entries = plan[key]
        if not isinstance(entries, list) or not entries:
            return False
        names = [entry.split("|", 1)[0] for entry in entries]
        if len({name.casefold() for name in names}) != len(names):
            return False
        count = len(names)
        link_selected = area != "ethernet" or bool(plan["spx"])
    if count != child["planned"] or count == 0:
        return False
    for index, role in enumerate(roles[:3]):
        if not isinstance(role, dict) or set(role) != {
            "role", "state", "relative_path", "sha256", "size_bytes"
        }:
            return False
        applicable = index == 0 or area != "ethernet" or link_selected
        if not applicable:
            if any(role[key] is not None for key in
                   ("relative_path", "sha256", "size_bytes")) or role["state"] != "not_applicable":
                return False
            continue
        if role["state"] != "present":
            return False
        relative = role["relative_path"]
        expected_prefix = f"{area}/monitor/{prefix[index]}/"
        if not isinstance(relative, str) or not relative.startswith(expected_prefix):
            return False
        path = _collection_artifact_path(root, relative)
        suffix = ".csv" if index == 2 else ".tar.gz"
        if not re.fullmatch(r"[0-9]{8}-[0-9]{4}(?:-(?:air|prod))?" + re.escape(suffix), path.name):
            return False
        if _collection_slot_file_evidence(path) != {
            "sha256": role["sha256"], "size_bytes": role["size_bytes"]
        }:
            return False
    if roles[1]["state"] == "present" and roles[2]["state"] == "present":
        link_name = Path(roles[1]["relative_path"]).name.removesuffix(".tar.gz")
        csv_name = Path(roles[2]["relative_path"]).name.removesuffix(".csv")
        if link_name != csv_name:
            return False
    if activity:
        from monitor.issue_tracker_activity_source import (
            load_eth_activity_evidence, validate_worker_eth_activity_context,
        )
        binding = validate_worker_eth_activity_context(context)
        fourth = roles[3]
        if area != "ethernet" or not isinstance(fourth, dict) or set(fourth) != {
            "role", "state", "relative_path", "sha256", "size_bytes"
        } or fourth["state"] != "present":
            return False
        slot_dir = Path(context["artifacts"]["evidence"]).parent
        expected_path = slot_dir / "activity-observation.json"
        if fourth["relative_path"] != expected_path.relative_to(root).as_posix():
            return False
        published = _collection_artifact_path(root, fourth["relative_path"])
        if _collection_slot_file_evidence(published) != {
            "sha256": fourth["sha256"], "size_bytes": fourth["size_bytes"]
        }:
            return False
        original = Path(context["activity"]["sidecar_path"])
        if original.is_symlink() or _collection_slot_file_evidence(original) != {
            "sha256": fourth["sha256"], "size_bytes": fourth["size_bytes"]
        }:
            return False
        payload = json.loads(published.read_bytes())
        archive = roles[0]
        expected_archive = root / archive["relative_path"]
        if payload["sources"]["archive"] != {
            "path": str(expected_archive), "sha256": archive["sha256"]
        } or _collection_slot_file_evidence(expected_archive) != {
            "sha256": archive["sha256"], "size_bytes": archive["size_bytes"]
        }:
            return False
        source_paths = {
            role: Path(context["activity"]["sources"][role]["path"])
            for role in ("dot", "inventory", "device_aliases")
        }
        source_paths["archive"] = expected_archive
        report = Path(payload["report"]["path"])
        expected_report = (
            root / "tools/lldp-analyze-tool/99-output-p2p"
            / (expected_archive.name.removesuffix(".tar.gz")
               + "-ethernet-topology-validation.xlsx")
        ).resolve()
        if report != expected_report:
            return False
        load_eth_activity_evidence(
            published, sources=source_paths, report_path=report,
            expected_evidence_sha256=fourth["sha256"],
            expected_cycle_binding=binding,
        )
    if ib_analysis:
        from monitor.collection_ib_producer import (
            IbProducerHold, validate_ib_completion_attestation,
        )
        if slot != "infiniband/prod" or area != "infiniband":
            return False
        try:
            verified_ib_roles = validate_ib_completion_attestation(
                context["identity"], context["ib_analysis"], http_root=root,
            )
        except IbProducerHold:
            return False
        if verified_ib_roles != roles[3:]:
            return False
    return True


def _collection_slot_artifacts_match(
    child: dict[str, object], bindings: object, context: dict | None = None,
) -> bool:
    if not isinstance(bindings, dict) or set(bindings) != {
        "evidence", "envelope", "input_inventory"
    }:
        return False
    if not _collection_private_binding_paths(child, bindings):
        return False
    try:
        evidence_path = Path(bindings["evidence"])
        envelope_path = Path(bindings["envelope"])
        inventory_path = Path(bindings["input_inventory"])
        evidence = _collection_slot_file_evidence(evidence_path)
        envelope = _collection_slot_file_evidence(envelope_path)
        inventory_content = inventory_path.read_bytes()
        inventory_sha256 = hashlib.sha256(inventory_content).hexdigest()
        manifest = _collection_private_json(evidence_path)
        identity_envelope = _collection_private_json(envelope_path)
        expected_envelope_keys = {
            "identity", "source_slot", "state", "planned", "succeeded",
            "failed_count", "input_inventory_sha256", "evidence"
        }
        if context is not None:
            plan = context["target_plan"]
            plan_raw = _canonical_json_line(plan)
            if (not isinstance(plan, dict) or set(plan) != {
                "eth", "spx", "ib", "nv", "dynamic_identities"
            } or hashlib.sha256(plan_raw).hexdigest()
                    != context["target_plan_sha256"]):
                return False
            expected_envelope_keys.add("target_plan_sha256")
            expected_envelope_keys.add("runtime_input_hashes")
            if "activity" in context:
                expected_envelope_keys.add("activity_context_sha256")
            if "ib_analysis" in context:
                expected_envelope_keys.add("ib_analysis_context_sha256")
                expected_envelope_keys.add("ib_analysis_binding")
            if not _collection_target_plan_matches_sources(
                context, inventory_content, child["source_slot"]
            ) or not _collection_runtime_snapshots_match(context, inventory_path):
                return False
        if set(identity_envelope) != expected_envelope_keys:
            return False
        expected_envelope = {
            "identity": {key: child[key] for key in (
                "project_key", "run_token", "scope", "sequence", "source", "cycle_id"
            )},
            "source_slot": child["source_slot"], "state": child["state"],
            "planned": child["planned"], "succeeded": child["succeeded"],
            "failed_count": child["failed_count"],
            "input_inventory_sha256": inventory_sha256,
            "evidence": evidence,
        }
        if context is not None:
            expected_envelope["target_plan_sha256"] = context["target_plan_sha256"]
            expected_envelope["runtime_input_hashes"] = context["runtime_input_hashes"]
            if "activity" in context:
                expected_envelope["activity_context_sha256"] = hashlib.sha256(
                    _canonical_json_line(context)
                ).hexdigest()
            if "ib_analysis" in context:
                expected_envelope["ib_analysis_context_sha256"] = hashlib.sha256(
                    _canonical_json_line(context)
                ).hexdigest()
                expected_envelope["ib_analysis_binding"] = {
                    key: context["ib_analysis"][key] for key in (
                        "run_id", "node", "authority_sha256",
                        "expected_topology_sha256", "attestation_sha256",
                    )
                }
        if identity_envelope != expected_envelope:
            return False
        if not _collection_validate_artifact_roles(
            manifest, root=HTTP_ROOT, child=child, inventory=inventory_content,
            context=context,
        ):
            return False
    except (OSError, TypeError, ValueError, KeyError, UnicodeError, json.JSONDecodeError):
        return False
    return (
        child["evidence"] == evidence
        and child["envelope"] == envelope
        and child["input_inventory_sha256"] == inventory_sha256
    )


def _collection_slot_wrapper(
    slot: str,
    outcome: str,
    child: dict | None,
    process_result: dict,
    identity: dict,
) -> dict[str, object]:
    return validate_collection_slot_outcome(
        {
            "source_slot": slot,
            "outcome": outcome,
            "child_result": child,
            "evidence": _collection_slot_process_evidence(process_result),
        },
        expected_slot=slot,
        expected_context=identity,
    )


def _collection_managed_bindings(identity: dict, slot: str) -> dict[str, str]:
    area = slot.split("/", 1)[0]
    scope = identity["scope"]
    directory = (
        HTTP_ROOT / "monitor/status/collection-cycles" / identity["project_key"] / scope
        / "switch_collection" / "artifacts" / f"{identity['sequence']:020d}"
        / slot.replace("/", "-")
    )
    return {
        "evidence": str(directory / "evidence-manifest.json"),
        "envelope": str(directory / "identity-envelope.json"),
        "input_inventory": str(directory.parent / "inputs" /
                               f"{slot.replace('/', '-')}.csv"),
    }


def _collection_private_binding_paths(child: dict, bindings: dict) -> bool:
    identity = {key: child[key] for key in (
        "project_key", "run_token", "scope", "sequence", "source", "cycle_id"
    )}
    if bindings != _collection_managed_bindings(identity, child["source_slot"]):
        return False
    for raw in bindings.values():
        path = Path(raw)
        try:
            parts = path.relative_to(HTTP_ROOT).parts
        except ValueError:
            return False
        current = HTTP_ROOT
        for part in parts:
            current = current / part
            if current.is_symlink():
                return False
    return True


def _collection_snapshot_inventory(slot: str, bindings: dict) -> bytes:
    area = slot.split("/", 1)[0]
    source_name = {"ethernet": "eth.csv", "infiniband": "ib.csv",
                   "nvlink": "nvsw.csv"}[area]
    source = SCRIPTS[area].parent / source_name
    content = source.read_bytes()
    destination = Path(bindings["input_inventory"])
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="wb", dir=destination.parent,
                                     prefix=".frozen-inventory-", delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
    return content


def _collection_freeze_activity_member(source: Path, destination: Path,
                                       *, maximum: int) -> str:
    """Freeze one selected topology authority without following a moving name."""
    named = source.lstat()
    if not stat.S_ISREG(named.st_mode) or named.st_nlink != 1:
        raise ValueError("activity source is not one regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(source, flags)
    temporary = None
    try:
        before = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino) \
                or before.st_size < 0 or before.st_size > maximum:
            raise ValueError("activity source identity or size is invalid")
        digest = hashlib.sha256()
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=destination.parent,
                                         prefix=".activity-freeze-", delete=False) as out:
            temporary = Path(out.name)
            os.fchmod(out.fileno(), 0o600)
            copied = 0
            while True:
                part = os.read(descriptor, 1024 * 1024)
                if not part:
                    break
                copied += len(part)
                if copied > maximum:
                    raise ValueError("activity source exceeds snapshot bound")
                out.write(part)
                digest.update(part)
            out.flush()
            os.fsync(out.fileno())
        after = os.fstat(descriptor)
        named_after = source.lstat()
        identity = lambda value: (
            value.st_dev, value.st_ino, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns,
        )
        if copied != before.st_size or identity(before) != identity(after) \
                or identity(after) != identity(named_after):
            raise ValueError("activity source changed during snapshot")
        os.link(temporary, destination)
        temporary.unlink()
        temporary = None
        _fsync_directory(destination.parent)
        return digest.hexdigest()
    finally:
        os.close(descriptor)
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _collection_activity_file_identity(metadata: os.stat_result) -> tuple:
    return (
        metadata.st_dev, metadata.st_ino, metadata.st_mode,
        metadata.st_nlink, metadata.st_size, metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _collection_activity_link_identity(path: Path) -> tuple:
    """Bind one setup-managed link's inode and exact text, not its resolved name."""
    try:
        before = path.lstat()
        if not stat.S_ISLNK(before.st_mode) or before.st_nlink != 1:
            raise ValueError("activity P2P selection is not one symlink")
        text = os.readlink(path)
        after = path.lstat()
    except OSError as exc:
        raise ValueError("activity P2P selection link is unavailable") from exc
    if _collection_activity_file_identity(before) != _collection_activity_file_identity(after):
        raise ValueError("activity P2P selection changed while read")
    return _collection_activity_file_identity(after), text


def _collection_activity_selected_workbook(fixed: Path) -> tuple[Path, str, tuple]:
    """Resolve the exact two links installed by setup, inside one project."""
    outer = _collection_activity_link_identity(fixed)
    if not outer[1] or os.path.isabs(outer[1]):
        raise ValueError("activity P2P selection must be relative")
    # Resolve the containing directory first: macOS exposes /var through
    # /private/var, so lexical /var and canonical /private/var must not diverge.
    canonical = Path(os.path.abspath(os.path.join(
        fixed.parent.resolve(strict=True), outer[1],
    )))
    project_root = HTTP_ROOT.resolve(strict=True) / "DAY0-Prepare"
    try:
        relative = canonical.relative_to(project_root)
    except ValueError as exc:
        raise ValueError("activity P2P selection escapes project root") from exc
    if len(relative.parts) != 2 or relative.parts[1] != "p2p.xlsx":
        raise ValueError("activity P2P selection is not project/p2p.xlsx")
    for directory in (project_root, canonical.parent):
        metadata = directory.lstat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("activity P2P project directory is not real")
    inner = _collection_activity_link_identity(canonical)
    target_name = inner[1]
    if not target_name or target_name in {".", "..", "p2p.xlsx"} \
            or os.path.isabs(target_name) or os.path.basename(target_name) != target_name \
            or not target_name.lower().endswith(".xlsx"):
        raise ValueError("activity P2P selected workbook name is invalid")
    selected = canonical.parent / target_name
    metadata = selected.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError("activity P2P selected workbook is not one regular file")
    return selected, selected.stem, (fixed, outer, canonical, inner,
                                     _collection_activity_file_identity(metadata))


def _collection_activity_verify_selection(selection: tuple, digest: str) -> None:
    fixed, outer, canonical, inner, initial_target = selection
    if (_collection_activity_link_identity(fixed) != outer
            or _collection_activity_link_identity(canonical) != inner):
        raise ValueError("activity P2P selection changed during snapshot")
    target = canonical.parent / inner[1]
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(target, flags)
    try:
        before = os.fstat(descriptor)
        if _collection_activity_file_identity(before) != initial_target:
            raise ValueError("activity P2P selected workbook identity changed")
        hasher = hashlib.sha256()
        copied = 0
        while True:
            part = os.read(descriptor, 1024 * 1024)
            if not part:
                break
            copied += len(part)
            if copied > 64 * 1024 * 1024:
                raise ValueError("activity P2P selected workbook exceeded snapshot bound")
            hasher.update(part)
        after = os.fstat(descriptor)
        named_after = target.lstat()
        if (_collection_activity_file_identity(after) != initial_target
                or _collection_activity_file_identity(named_after) != initial_target
                or hasher.hexdigest() != digest):
            raise ValueError("activity P2P selected workbook changed during snapshot")
    finally:
        os.close(descriptor)
    if (_collection_activity_link_identity(fixed) != outer
            or _collection_activity_link_identity(canonical) != inner):
        raise ValueError("activity P2P selection changed during snapshot")


def _collection_snapshot_activity_sources(slot: str, bindings: dict) -> dict | None:
    """Freeze ETH topology inputs for this worker slot before collection.

    Absent source files keep the existing operational three-role collector;
    they can never silently become activity evidence.  Present but unsafe
    sources are an explicit worker error, not a substituted latest report.
    """
    if slot not in {"ethernet/air", "ethernet/prod"}:
        return None
    p2p = HTTP_ROOT / "ztp/config/cumulus/template/P2P"
    workbook = p2p / "p2p.xlsx"
    if not workbook.exists() and not workbook.is_symlink():
        return None
    selection = None
    selected = workbook
    selected_stem = workbook.stem
    if workbook.is_symlink():
        selected, selected_stem, selection = _collection_activity_selected_workbook(workbook)
    suffix = "-air.dot" if slot.endswith("/air") else "-lldpq.dot"
    dot = p2p / "output-p2p" / f"{selected_stem}{suffix}"
    inputs = {
        "topology": (selected, "p2p.xlsx", 64 * 1024 * 1024),
        "dot": (dot, "dot", 16 * 1024 * 1024),
        "inventory": (p2p / "01-inventory.log", "lldp-inventory.log", 4 * 1024 * 1024),
        "device_aliases": (
            HTTP_ROOT / "tools/lldp-analyze-tool/04-lldp-device-aliases.json",
            "aliases.json", 4 * 1024 * 1024,
        ),
    }
    if any(not source.exists() and not source.is_symlink()
           for source, _suffix, _maximum in inputs.values()):
        raise ValueError("activity P2P selected source or matching DOT is missing")
    derivation_inputs = {}
    if slot == "ethernet/prod":
        port_mapping = p2p / "02-port-mapping.log"
        splitter_profiles = p2p / "output-p2p" / f"{selected_stem}-splitter-profiles.json"
        if any(path.is_symlink() or (path.exists() and not path.is_file())
               for path in (port_mapping, splitter_profiles)):
            raise ValueError("activity P2P derivation source is not a regular file")
        found = tuple(path.exists() or path.is_symlink()
                      for path in (port_mapping, splitter_profiles))
        # A partially generated old project may still collect LLDP links; it
        # must not gain a P2P->DOT derivation witness until both roles exist.
        if all(found):
            derivation_inputs = {
                "port_mapping": (port_mapping, "port-mapping.log", 4 * 1024 * 1024),
                "splitter_profiles": (
                    splitter_profiles, "splitter-profiles.json", 4 * 1024 * 1024,
                ),
            }
    private = Path(bindings["input_inventory"]).parent
    stem = slot.replace("/", "-")
    frozen = {}
    for role, (source, suffix_name, maximum) in {**inputs, **derivation_inputs}.items():
        destination = private / f"{stem}.{suffix_name}"
        frozen[role] = {
            "path": str(destination),
            "sha256": _collection_freeze_activity_member(
                source, destination, maximum=maximum,
            ),
        }
    if selection is not None:
        _collection_activity_verify_selection(selection, frozen["topology"]["sha256"])
    activity = {
        "schema_version": 1,
        "source_slot": slot,
        "topology": frozen["topology"],
        "sources": {role: frozen[role] for role in (
            "dot", "inventory", "device_aliases"
        )},
        "sidecar_path": str(private / f"{stem}.activity.json"),
    }
    if derivation_inputs:
        activity["derivation_sources"] = {
            role: frozen[role] for role in ("port_mapping", "splitter_profiles")
        }
        activity["selected_workbook_name"] = selected.name
    return activity


def _collection_snapshot_runtime(slot: str, bindings: dict) -> dict:
    """Freeze dynamic resolver inputs and derived rows before cron planning."""
    source_inventory = Path(bindings["input_inventory"])
    directory = source_inventory.parent
    if not slot.startswith("ethernet/"):
        return {"air_dynamic_rows": [], "prod_runtime_rows": [],
                "runtime_input_hashes": {}}

    def unavailable() -> dict:
        # The collection may still run under its preheld lock, but this slot
        # must emit only legacy v1. Absence is never proof of zero dynamic rows.
        return {"air_dynamic_rows": [], "prod_runtime_rows": [],
                "runtime_input_hashes": {},
                "v2_unavailable": "resolver_unavailable"}

    def freeze(source: Path, suffix: str) -> Path:
        if source.is_symlink():
            raise ValueError("runtime input symlink is not trusted")
        data = source.read_bytes() if source.is_file() else b""
        if len(data) > 32 * 1024 * 1024:
            raise ValueError("runtime input exceeds snapshot bound")
        target = directory / (source_inventory.stem + suffix)
        with tempfile.NamedTemporaryFile(mode="wb", dir=directory,
                                         prefix=".runtime-freeze-", delete=False) as stream:
            temporary = Path(stream.name)
            try:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
                os.replace(temporary, target)
            finally:
                temporary.unlink(missing_ok=True)
        return target

    lease_source = Path(os.environ.get("DHCP_LEASES_FILE", "/var/lib/dhcp/dhcpd.leases"))
    if lease_source.is_symlink():
        raise ValueError("runtime resolver lease input is unsafe")
    if not lease_source.is_file():
        return unavailable()
    frozen_lease = freeze(lease_source, ".leases")
    hashes = {"leases": hashlib.sha256(frozen_lease.read_bytes()).hexdigest()}
    if slot == "ethernet/air":
        air_source = HTTP_ROOT / "ztp/config/isc-dhcp-server/p2p-air.json"
        helper = HTTP_ROOT / "ztp/dynamic_air_inventory.py"
        if air_source.is_symlink() or helper.is_symlink():
            raise ValueError("AIR resolver input or helper is unsafe")
        if not air_source.is_file() or not helper.is_file():
            return unavailable()
        frozen_air = freeze(air_source, ".air.json")
        hashes["air_json"] = hashlib.sha256(frozen_air.read_bytes()).hexdigest()
        result = subprocess.run(
            [sys.executable, str(helper), "--inventory", str(source_inventory),
             "--air-json", str(frozen_air), "--leases", str(frozen_lease),
             "--include-static-transitions", "--format", "pipe"],
            cwd=HTTP_ROOT, capture_output=True, text=True, timeout=20,
            check=False,
        )
        if result.returncode or len(result.stdout) > 1024 * 1024:
            return unavailable()
        rows = result.stdout.splitlines()
        return {"air_dynamic_rows": rows, "prod_runtime_rows": [],
                "runtime_input_hashes": hashes}

    log_source = os.environ.get("DHCP_RUNTIME_LOG_FILE", "")
    helper = HTTP_ROOT / "ztp/dhcp_runtime_inventory.py"
    if helper.is_symlink():
        raise ValueError("Production runtime resolver helper is unsafe")
    if not helper.is_file():
        return unavailable()
    if log_source:
        source = Path(log_source)
        if source.is_symlink():
            raise ValueError("Production runtime resolver log is unsafe")
        if not source.is_file():
            return unavailable()
        frozen_log = freeze(source, ".dhcp.log")
    else:
        journal = subprocess.run(
            ["journalctl", "--no-pager", "-o", "short-iso-precise", "-u",
             "isc-dhcp-server", "--since", "-7 days"],
            capture_output=True, timeout=20, check=False,
        )
        if journal.returncode or len(journal.stdout) > 32 * 1024 * 1024:
            return unavailable()
        with tempfile.NamedTemporaryFile(mode="wb", dir=directory,
                                         prefix=".runtime-journal-", delete=False) as stream:
            temporary = Path(stream.name)
            try:
                stream.write(journal.stdout)
                stream.flush()
                os.fsync(stream.fileno())
                frozen_log = directory / (source_inventory.stem + ".dhcp.log")
                os.replace(temporary, frozen_log)
            finally:
                temporary.unlink(missing_ok=True)
    hashes["dhcp_log"] = hashlib.sha256(frozen_log.read_bytes()).hexdigest()
    command = [sys.executable, str(helper), "--stdout", "--inventory",
               str(source_inventory), "--leases", str(frozen_lease),
               "--dhcp-log", str(frozen_log)]
    result = subprocess.run(command, cwd=HTTP_ROOT, capture_output=True,
                            text=True, timeout=20, check=False)
    if result.returncode or len(result.stdout) > 1024 * 1024:
        return unavailable()
    payload = json.loads(result.stdout)
    if not isinstance(payload, dict) or not isinstance(payload.get("devices"), list):
        return unavailable()
    rows = ["|".join("" if item.get(key) is None else str(item[key])
                     for key in ("mac", "ip", "platform", "lease_state"))
            for item in payload["devices"]]
    hashes["journal_derived_rows"] = hashlib.sha256(
        _canonical_json_line(rows)).hexdigest()
    return {"air_dynamic_rows": [], "prod_runtime_rows": rows,
            "runtime_input_hashes": hashes}


def _collection_ib_authority_installed(identity: dict[str, object]) -> bool:
    """Only a root-installed record opts an ordinary IB collection into analysis."""
    authority_path = (
        Path("/var/lib/http-ztp-container/ib-producer-authority")
        / f"{identity['project_key']}.json"
    )
    try:
        authority_path.lstat()
    except OSError:
        return False
    return True


def _collection_prepare_ib_analysis(
    identity: dict[str, object], slot: str,
) -> tuple[dict[str, object] | None, object | None]:
    """Mint extra IB evidence from protected worker inputs, never child data."""
    if slot != "infiniband/prod":
        return None, None
    try:
        project_root = Path(active_project_identity(HTTP_ROOT))
    except CollectionGateError:
        return None, None
    # An ordinary three-role collection must not import optional analyzer or
    # transport dependencies. A present, even unsafe, record is checked below.
    if not _collection_ib_authority_installed(identity):
        return None, None
    from monitor.collection_ib_producer import (
        IbProducerHold, load_ib_producer_authority,
        produce_worker_ib_analysis, recheck_ib_producer_authority,
    )
    try:
        snapshot = load_ib_producer_authority(
            project_key=identity["project_key"], project_root=project_root,
        )
        binding = produce_worker_ib_analysis(
            identity, project_root=project_root, http_root=HTTP_ROOT,
        )
        if binding["authority_sha256"] != snapshot.sha256:
            raise IbProducerHold("IB producer used another protected authority")
        recheck_ib_producer_authority(snapshot)
        return binding, snapshot
    except (IbProducerHold, CollectionGateError):
        # Base switch collection can still run, while Stage L remains HOLD.
        return None, None


def run_collection_slots(
    identity: object,
    *,
    artifact_bindings: object,
    timeout: int,
    lock_wait: int,
) -> dict[str, object]:
    """Run each declared slot once and return total terminal coverage.

    ``timeout`` and ``lock_wait`` are required so this API does not create a
    second default authority. Real collectors can emit v2 only with frozen
    inputs, a matching target plan, and independently checked private
    artifacts. Missing resolver authority or a legacy collector remains
    operational as v1 and cannot qualify a production cycle. The pure
    summarizer independently returns ``qualifying=False`` with the closed
    ``legacy`` reason for such results.
    """
    validated_identity = validate_collection_cycle_identity(identity)
    slots = collection_cycle_source_slots(validated_identity["scope"])
    if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0:
        raise ValueError("collection slot timeout must be a positive integer")
    if isinstance(lock_wait, bool) or not isinstance(lock_wait, int) or lock_wait < 0:
        raise ValueError("collection slot lock wait must be a nonnegative integer")
    if not isinstance(artifact_bindings, dict):
        raise ValueError("collection slot artifact bindings must be a mapping")

    commands = commands_for_scope(validated_identity["scope"], lock_wait)
    if len(commands) != len(slots):
        raise RuntimeError("collection command count does not match declared slots")

    outcomes: list[dict[str, object]] = []
    for slot, command in zip(slots, commands):
        empty_result = {"returncode": 1, "stdout": "", "stderr": ""}
        evidence_result = empty_result
        context = None
        ib_authority_snapshot = None
        cron_lock_fd = None
        try:
            script = next(
                (Path(argument) for argument in command
                 if isinstance(argument, str) and argument.endswith("/cron.sh")),
                HTTP_ROOT,
            )
            cwd = script.parent if script != HTTP_ROOT else HTTP_ROOT
            bindings = artifact_bindings.get(slot)
            area = slot.split("/", 1)[0]
            source_name = {"ethernet": "eth.csv", "infiniband": "ib.csv",
                           "nvlink": "nvsw.csv"}[area]
            inventory_available = (
                SCRIPTS[area].parent / source_name
            ).is_file()
            if script != HTTP_ROOT and script.is_file() and inventory_available:
                cron_lock_fd = os.open(
                    cwd / "cron.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600
                )
                lock_deadline = time.monotonic() + lock_wait
                while True:
                    try:
                        fcntl.flock(cron_lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if time.monotonic() >= lock_deadline or lane_cancelled(COLLECTION_LANE):
                            raise ValueError("collection cron lock is unavailable")
                        time.sleep(0.05)
                if bindings is None:
                    bindings = _collection_managed_bindings(validated_identity, slot)
                if not isinstance(bindings, dict) or set(bindings) != {
                    "evidence", "envelope", "input_inventory"
                }:
                    raise ValueError("collection slot bindings are invalid")
                frozen = _collection_snapshot_inventory(slot, bindings)
                context = {
                    "identity": validated_identity,
                    "source_slot": slot,
                    "artifacts": bindings,
                    "input_inventory_sha256": hashlib.sha256(frozen).hexdigest(),
                    **_collection_snapshot_runtime(slot, bindings),
                }
                with tempfile.TemporaryFile(mode="w+b") as plan_context, \
                        tempfile.TemporaryFile(mode="w+b") as plan_file:
                    plan_context.write(_canonical_json_line(context))
                    plan_context.flush()
                    plan_context.seek(0)
                    planner_command = [
                        *command, "--worker-context-fd", str(plan_context.fileno()),
                        "--emit-target-plan-fd", str(plan_file.fileno()),
                        "--preheld-lock-fd", str(cron_lock_fd),
                    ]
                    plan_result, plan_cancelled = run_interruptible(
                        planner_command, cwd, timeout,
                        pass_fds=(plan_context.fileno(), plan_file.fileno(), cron_lock_fd),
                        lane=COLLECTION_LANE,
                    )
                    if plan_cancelled or plan_result["returncode"] != 0:
                        evidence_result = plan_result
                        raise ValueError("collector target planning failed")
                    plan_size = os.fstat(plan_file.fileno()).st_size
                    if plan_size <= 0 or plan_size > 1024 * 1024:
                        raise ValueError("collector target plan size is invalid")
                    plan_raw = os.pread(plan_file.fileno(), plan_size, 0)
                    plan = json.loads(plan_raw)
                    if _canonical_json_line(plan) != plan_raw:
                        raise ValueError("collector target plan is noncanonical")
                    if not isinstance(plan, dict) or set(plan) != {
                        "eth", "spx", "ib", "nv", "dynamic_identities"
                    }:
                        raise ValueError("collector target plan shape is invalid")
                    context["target_plan"] = plan
                    context["target_plan_sha256"] = hashlib.sha256(plan_raw).hexdigest()
                    _collection_freeze_plan_sources(slot, bindings, context, plan_raw)
                activity = _collection_snapshot_activity_sources(slot, bindings)
                if activity is not None:
                    context["activity"] = activity
                ib_analysis, ib_authority_snapshot = _collection_prepare_ib_analysis(
                    validated_identity, slot,
                )
                if ib_analysis is not None:
                    context["ib_analysis"] = ib_analysis
                with tempfile.TemporaryFile(mode="w+b") as context_file:
                    context_file.write(_canonical_json_line(context))
                    context_file.flush()
                    context_file.seek(0)
                    managed_command = [
                        *command, "--worker-context-fd", str(context_file.fileno()),
                        "--preheld-lock-fd", str(cron_lock_fd),
                    ]
                    process_result, cancelled = run_interruptible(
                        managed_command, cwd, timeout,
                        pass_fds=(context_file.fileno(), cron_lock_fd), lane=COLLECTION_LANE,
                    )
            else:
                # No input inventory means this cannot be an A4 evidence run.
                # Preserve the existing operational/legacy collector path so
                # process supervision remains testable, never v2 qualifying.
                process_result, cancelled = run_interruptible(
                    command, cwd, timeout, lane=COLLECTION_LANE
                )
            evidence_result = process_result
            if cancelled:
                outcomes.append(_collection_slot_wrapper(
                    slot, "cancelled", None, process_result, validated_identity
                ))
                continue
            if process_result["returncode"] < 0:
                outcomes.append(_collection_slot_wrapper(
                    slot, "crashed", None, process_result, validated_identity
                ))
                continue
            try:
                child = parse_collection_slot_result(
                    process_result["stdout"],
                    expected_context=validated_identity,
                    expected_slot=slot,
                )
            except CollectionSlotParseError as exc:
                outcomes.append(_collection_slot_wrapper(
                    slot, exc.outcome, None, process_result, validated_identity
                ))
                continue
            returncode = process_result["returncode"]
            if (
                (returncode != 0 and child["state"] != "failed")
                or (returncode == 0 and child["state"] == "failed")
            ):
                outcomes.append(_collection_slot_wrapper(
                    slot, "returncode_conflict", None, process_result,
                    validated_identity,
                ))
                continue
            if child["schema_version"] == 2 and not _collection_slot_artifacts_match(
                child, bindings, context
            ):
                outcomes.append(_collection_slot_wrapper(
                    slot, "artifact_mismatch", None, process_result,
                    validated_identity,
                ))
                continue
            if ib_authority_snapshot is not None:
                from monitor.collection_ib_producer import (
                    IbProducerHold, recheck_ib_producer_authority,
                )
                try:
                    recheck_ib_producer_authority(ib_authority_snapshot)
                except IbProducerHold:
                    outcomes.append(_collection_slot_wrapper(
                        slot, "artifact_mismatch", None, process_result,
                        validated_identity,
                    ))
                    continue
            outcomes.append(_collection_slot_wrapper(
                slot, "accepted", child, process_result, validated_identity
            ))
        except Exception:
            # Exactly one terminal wrapper is still emitted for this declared
            # slot.  A later slot may proceed, but this wrapper is never
            # replaced or upgraded to accepted.
            process_result = evidence_result
            outcomes.append(_collection_slot_wrapper(
                slot, "worker_error", None, process_result, validated_identity
            ))
        finally:
            if cron_lock_fd is not None:
                fcntl.flock(cron_lock_fd, fcntl.LOCK_UN)
                os.close(cron_lock_fd)

    summary = None
    if all(item["outcome"] == "accepted" for item in outcomes) and all(
        item["child_result"]["schema_version"] == 2 for item in outcomes
    ):
        html_result = subprocess.run(
            [sys.executable, str(HTML_SCRIPT)],
            cwd=HTTP_ROOT,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        html_error = html_result.stderr or html_result.stdout
        html_annotation = {
            "attempted": True,
            "state": "success" if html_result.returncode == 0 else "failed",
            "error_sha256": (
                None if html_result.returncode == 0
                else hashlib.sha256(html_error.encode("utf-8")).hexdigest()
            ),
        }
        summary = summarize_collection_cycle_results(
            validated_identity,
            [item["child_result"] for item in outcomes],
            html_annotation=html_annotation,
        )
    return {
        "identity": validated_identity,
        "outcomes": outcomes,
        "summary": summary,
    }


def _read_collection_cycle_fd_json(descriptor: int) -> object:
    if isinstance(descriptor, bool) or not isinstance(descriptor, int) or descriptor < 3:
        raise ValueError("collection cycle descriptor is invalid")
    chunks = []
    size = 0
    while True:
        chunk = os.read(descriptor, 65536)
        if not chunk:
            break
        size += len(chunk)
        if size > 16 * 1024 * 1024:
            raise ValueError("collection cycle descriptor payload is too large")
        chunks.append(chunk)
    return json.loads(b"".join(chunks).decode("utf-8"))


def _write_collection_cycle_fd_json(descriptor: int, payload: object) -> None:
    if isinstance(descriptor, bool) or not isinstance(descriptor, int) or descriptor < 3:
        raise ValueError("collection cycle descriptor is invalid")
    content = _canonical_json_line(payload)
    position = 0
    while position < len(content):
        position += os.write(descriptor, content[position:])


def _wait_for_collection_cycle_go(descriptor: int, timeout: float = 5.0) -> None:
    offset = os.lseek(descriptor, 0, os.SEEK_CUR)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.fstat(descriptor).st_size > offset:
            command = os.pread(descriptor, 3, offset)
            if command != b"go\n":
                raise ValueError("internal collection cycle go signal is invalid")
            return
        time.sleep(0.01)
    raise TimeoutError("internal collection cycle go signal timed out")


def _run_internal_collection_cycle(context_fd: int, result_fd: int) -> int:
    context = _read_collection_cycle_fd_json(context_fd)
    if not isinstance(context, dict) or set(context) != {
        "identity", "artifact_bindings", "timeout", "lock_wait"
    }:
        raise ValueError("internal collection cycle context has invalid keys")
    _write_collection_cycle_fd_json(
        result_fd,
        {
            "kind": "ready",
            "pid": os.getpid(),
            "boot_id": _current_boot_identity(),
            "process_start_time": _process_start_identity(os.getpid()),
        },
    )
    _wait_for_collection_cycle_go(context_fd)
    result = run_collection_slots(
        context["identity"],
        artifact_bindings=context["artifact_bindings"],
        timeout=context["timeout"],
        lock_wait=context["lock_wait"],
    )
    _write_collection_cycle_fd_json(result_fd, result)
    return 0


def _wait_for_collection_cycle_ready(
    process: subprocess.Popen, descriptor: int, timeout: float = 5.0,
) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        size = os.fstat(descriptor).st_size
        if size:
            content = os.pread(descriptor, size, 0)
            if b"\n" in content:
                try:
                    ready = json.loads(content.split(b"\n", 1)[0].decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise CollectionCycleHoldError(
                        "collection cycle coordinator readiness is invalid"
                    ) from exc
                if (
                    not isinstance(ready, dict)
                    or set(ready) != {
                        "kind", "pid", "boot_id", "process_start_time"
                    }
                    or ready["kind"] != "ready"
                    or ready["pid"] != process.pid
                    or not isinstance(ready["boot_id"], str)
                    or not ready["boot_id"]
                    or not isinstance(ready["process_start_time"], str)
                    or not ready["process_start_time"]
                ):
                    raise CollectionCycleHoldError(
                        "collection cycle coordinator readiness is invalid"
                    )
                return ready
        if process.poll() is not None:
            raise CollectionCycleHoldError(
                "collection cycle coordinator exited before readiness"
            )
        time.sleep(0.01)
    raise CollectionCycleHoldError("collection cycle coordinator readiness timeout")


def run_collection_cycle_coordinator(
    gate: CollectionGate,
    *,
    artifact_bindings: object,
    timeout: int,
    lock_wait: int,
) -> dict[str, object]:
    """Run one gate-bound cycle in a dedicated subprocess and persist it."""
    store = CollectionCycleStore(gate=gate, source="switch_collection")
    start = store.allocate_start()
    context = {
        "identity": start,
        "artifact_bindings": artifact_bindings,
        "timeout": timeout,
        "lock_wait": lock_wait,
    }
    with tempfile.TemporaryFile(mode="w+b") as context_file, \
            tempfile.TemporaryFile(mode="w+b") as result_file:
        context_file.write(_canonical_json_line(context))
        context_file.flush()
        context_size = context_file.tell()
        context_file.seek(0)
        argv = [
            sys.executable,
            str(Path(__file__).resolve()),
            "--internal-cycle",
            "--internal-cycle-context-fd", str(context_file.fileno()),
            "--internal-cycle-result-fd", str(result_file.fileno()),
        ]
        process = subprocess.Popen(
            argv,
            cwd=HTTP_ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            pass_fds=(context_file.fileno(), result_file.fileno()),
        )
        _set_active_collector(process, COLLECTION_LANE)
        try:
            ready = _wait_for_collection_cycle_ready(
                process, result_file.fileno()
            )
            store.publish_launch(
                start,
                pid=process.pid,
                boot_id=ready["boot_id"],
                process_start_time=ready["process_start_time"],
                argv=argv,
                context=context,
                credential_argv_positions=(),
                credential_context_names=(),
            )
            os.pwrite(context_file.fileno(), b"go\n", context_size)
            coordinator_timeout = max(
                60,
                timeout * (len(collection_cycle_source_slots(start["scope"])) + 1),
            )
            try:
                _stdout, stderr = process.communicate(timeout=coordinator_timeout)
            except subprocess.TimeoutExpired as exc:
                process.terminate()
                try:
                    process.wait(timeout=COLLECTOR_TERM_GRACE_SECONDS)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=COLLECTOR_KILL_GRACE_SECONDS)
                raise CollectionCycleHoldError(
                    "collection cycle coordinator timeout"
                ) from exc
            if process.returncode != 0:
                detail = (stderr or "internal coordinator failed")[-2000:]
                raise CollectionCycleHoldError(
                    f"collection cycle coordinator failed: {detail}"
                )
            try:
                content = os.pread(
                    result_file.fileno(), os.fstat(result_file.fileno()).st_size, 0
                )
                lines = content.splitlines()
                if len(lines) != 2:
                    raise json.JSONDecodeError("expected two records", "", 0)
                run_result = json.loads(lines[1].decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise CollectionCycleHoldError(
                    "collection cycle coordinator result is invalid"
                ) from exc
            completion = store.publish_completion(start, run_result)
            try:
                _publish_stage_l_status_after_completion(store)
                _publish_stage_l_local_after_completion(store)
            except OSError:
                # Status is non-authoritative. Its failure cannot relabel the
                # already durable collection-cycle completion.
                print("Issue Tracker Stage L status unavailable", file=sys.stderr)
            return completion["run_result"]
        finally:
            _clear_active_collector(process, COLLECTION_LANE)


def _task_result_status_fields(result: dict) -> dict:
    if result["state"] == "failed":
        summary = f"all {result['failed_count']} selected device(s) failed"
    else:
        summary = (
            f"completed with warnings: {result['failed_count']} device(s) failed"
        )
    return {
        "planned": result["planned"],
        "succeeded": result["succeeded"],
        "failed_count": result["failed_count"],
        "failed_devices": result["failed_devices"],
        "summary": summary,
    }


def run_yaml_backup(password: str, scope: str, timeout: int, lock_wait: int) -> bool:
    """Run the existing YAML collector with a shared password on an anonymous FD."""
    started_at = timestamp()
    write_yaml_backup_status("collecting", scope=scope, started_at=started_at)
    try:
        project = active_project_identity(HTTP_ROOT)
        targets = project_inventory_targets(project, scope)
        if targets == ():
            write_yaml_backup_status(
                "success", scope=scope, started_at=started_at,
                finished_at=timestamp(), planned=0, succeeded=0,
                failed_count=0, failed_devices=[],
                summary="no monitorable devices selected",
            )
            return True
        with CollectionGate(
            project, scope, collection_keys=("yaml-backup",),
            status_dir=STATUS_DIR,
            cooldown_seconds=YAML_BACKUP_COOLDOWN_SECONDS,
            lock_wait_seconds=lock_wait,
            cancel_check=lambda: lane_cancelled(BACKUP_LANE),
            lane=BACKUP_LANE,
        ) as gate:
            if not gate.decision.allowed:
                finished_at = timestamp()
                if gate.decision.reason == "cooldown":
                    write_yaml_backup_status(
                        "success", scope=scope, started_at=started_at,
                        finished_at=finished_at, cooldown_skipped=True,
                        cooldown_seconds=gate.cooldown_seconds,
                        last_success_at=gate.decision.last_success_at,
                        next_allowed_at=gate.decision.next_allowed_at,
                        remaining_seconds=gate.decision.remaining_seconds,
                    )
                    return True
                write_yaml_backup_status(
                    "failed", scope=scope, started_at=started_at,
                    finished_at=finished_at,
                    reason="another managed collection is already running",
                )
                return False
            if not YAML_BACKUP_SCRIPT.is_file():
                write_yaml_backup_status(
                    "failed", scope=scope, started_at=started_at,
                    finished_at=timestamp(), reason="yaml-collect.py is missing",
                )
                return False
            password = _validated_password(password)
            read_fd, write_fd = os.pipe()
            try:
                try:
                    encoded = password.encode("utf-8")
                    view = memoryview(encoded)
                    while view:
                        written = os.write(write_fd, view)
                        view = view[written:]
                finally:
                    os.close(write_fd)
                command = [
                    sys.executable, str(YAML_BACKUP_SCRIPT), "-y", "--type",
                    _yaml_backup_scope(scope), "--password-fd", str(read_fd),
                ]
                result, cancelled = run_interruptible(
                    command, YAML_BACKUP_SCRIPT.parent, timeout,
                    pass_fds=(read_fd,),
                    lane=BACKUP_LANE,
                )
            finally:
                os.close(read_fd)
            if cancelled:
                write_yaml_backup_status(
                    "idle", scope=scope, stopped_at=timestamp(),
                )
                return False
            if result["stdout"]:
                print(
                    result["stdout"],
                    end="" if result["stdout"].endswith("\n") else "\n",
                    flush=True,
                )
            if result["stderr"]:
                print(
                    result["stderr"],
                    end="" if result["stderr"].endswith("\n") else "\n",
                    file=sys.stderr, flush=True,
                )
            task_result = parse_task_result(
                result["stdout"], "yaml_backup",
                permitted_operations=YAML_BACKUP_FAILED_DEVICE_OPERATIONS,
            )
            if task_result["state"] == "failed":
                write_yaml_backup_status(
                    "failed", scope=scope, started_at=started_at,
                    finished_at=timestamp(),
                    reason="all selected devices failed",
                    **_task_result_status_fields(task_result),
                )
                return False
            if result["returncode"]:
                write_yaml_backup_status(
                    "failed", scope=scope, started_at=started_at,
                    finished_at=timestamp(),
                    reason=f"yaml-collect.py exit={result['returncode']}",
                )
                return False
            successful_at = gate.mark_success()
            next_epoch = time.time() + gate.cooldown_seconds
            write_yaml_backup_status(
                task_result["state"], scope=scope, started_at=started_at,
                finished_at=timestamp(), cooldown_seconds=gate.cooldown_seconds,
                last_success_at=successful_at, next_allowed_epoch=next_epoch,
                next_allowed_at=(
                    datetime.fromtimestamp(next_epoch).astimezone()
                    .isoformat(timespec="seconds")
                ),
                **(
                    _task_result_status_fields(task_result)
                    if task_result["state"] == "partial" else {}
                ),
            )
            return True
    except CollectionGateCancelled:
        write_yaml_backup_status("idle", scope=scope, stopped_at=timestamp())
        return False
    except (CollectionGateError, OSError, ValueError) as exc:
        write_yaml_backup_status(
            "failed", scope=scope, started_at=started_at,
            finished_at=timestamp(), reason=f"YAML backup failed: {type(exc).__name__}",
        )
        return False


def run_yaml_backup_safely(
    password: str, scope: str, timeout: int, lock_wait: int,
) -> bool:
    """Keep the persistent scheduler alive after an unexpected backup failure."""
    try:
        return run_yaml_backup(password, scope, timeout, lock_wait)
    except Exception as exc:  # defensive boundary for the long-running worker
        finished_at = timestamp()
        detail = f"{type(exc).__name__}: {exc}"
        write_yaml_backup_status(
            "failed", scope=scope, finished_at=finished_at,
            reason=f"unexpected YAML backup failure: {type(exc).__name__}",
        )
        print(
            f"[{finished_at}] [ERROR] unexpected YAML backup failure: {detail}",
            file=sys.stderr, flush=True,
        )
        traceback.print_exc()
        return False


def _validated_interval(message: dict, action: str) -> int:
    if message.get("action") != action:
        raise ValueError(f"{action} request required")
    interval = message.get("interval_minutes")
    if action == "continuous_collection_start":
        minimum = MIN_CONTINUOUS_INTERVAL_MINUTES
        maximum = MAX_CONTINUOUS_INTERVAL_MINUTES
    elif action == "continuous_backup_start":
        minimum = MIN_CONTINUOUS_BACKUP_INTERVAL_MINUTES
        maximum = MAX_CONTINUOUS_BACKUP_INTERVAL_MINUTES
    else:
        raise ValueError("unsupported continuous interval action")
    if (
        isinstance(interval, bool) or not isinstance(interval, int)
        or not minimum <= interval <= maximum
    ):
        raise ValueError("invalid continuous interval")
    return interval


def continuous_collection_enabled() -> bool:
    with _CONTINUOUS_STATE_LOCK:
        return (
            _CONTINUOUS_COLLECTION_INTERVAL_SECONDS > 0
            or _CONTINUOUS_COLLECTION_STOP_REQUESTED
        )


def continuous_backup_enabled() -> bool:
    with _CONTINUOUS_STATE_LOCK:
        return (
            _CONTINUOUS_BACKUP_PASSWORD is not None
            or _CONTINUOUS_BACKUP_STOP_REQUESTED
        )


def continuous_collection_scheduled() -> bool:
    with _CONTINUOUS_STATE_LOCK:
        return (
            _CONTINUOUS_COLLECTION_INTERVAL_SECONDS > 0
            and not _CONTINUOUS_COLLECTION_STOP_REQUESTED
        )


def continuous_backup_scheduled() -> bool:
    with _CONTINUOUS_STATE_LOCK:
        return (
            _CONTINUOUS_BACKUP_PASSWORD is not None
            and not _CONTINUOUS_BACKUP_STOP_REQUESTED
        )


def configure_continuous_collection(message: dict) -> None:
    global _CONTINUOUS_COLLECTION_INTERVAL_SECONDS
    global _CONTINUOUS_COLLECTION_NEXT_RUN
    global _CONTINUOUS_COLLECTION_STOP_REQUESTED
    interval = _validated_interval(message, "continuous_collection_start")
    next_run = time.monotonic()
    with _CONTINUOUS_STATE_LOCK:
        write_continuous_status(
            "scheduled", enabled=True, interval_minutes=interval,
            message="continuous collection uses the collection cooldown only",
        )
        _CONTINUOUS_COLLECTION_INTERVAL_SECONDS = interval * 60
        _CONTINUOUS_COLLECTION_NEXT_RUN = next_run
        _CONTINUOUS_COLLECTION_STOP_REQUESTED = False


def configure_continuous_backup(message: dict) -> None:
    global _CONTINUOUS_BACKUP_PASSWORD, _CONTINUOUS_BACKUP_INTERVAL_SECONDS
    global _CONTINUOUS_BACKUP_NEXT_RUN
    global _CONTINUOUS_BACKUP_STOP_REQUESTED
    interval = _validated_interval(message, "continuous_backup_start")
    password = _validated_password(message.get("password"))
    next_run = time.monotonic()
    with _CONTINUOUS_STATE_LOCK:
        write_continuous_backup_status(
            "scheduled", enabled=True, interval_minutes=interval,
            message="password is held only in worker memory",
        )
        _CONTINUOUS_BACKUP_PASSWORD = password
        _CONTINUOUS_BACKUP_INTERVAL_SECONDS = interval * 60
        _CONTINUOUS_BACKUP_NEXT_RUN = next_run
        _CONTINUOUS_BACKUP_STOP_REQUESTED = False


def stop_continuous_collection_mode(reason: str) -> None:
    global _CONTINUOUS_COLLECTION_INTERVAL_SECONDS
    global _CONTINUOUS_COLLECTION_NEXT_RUN
    global _CONTINUOUS_COLLECTION_STOP_REQUESTED
    with _CONTINUOUS_STATE_LOCK:
        was_enabled = (
            _CONTINUOUS_COLLECTION_INTERVAL_SECONDS > 0
            or _CONTINUOUS_COLLECTION_STOP_REQUESTED
        )
        _CONTINUOUS_COLLECTION_INTERVAL_SECONDS = 0
        _CONTINUOUS_COLLECTION_NEXT_RUN = 0.0
        if was_enabled and lane_busy(COLLECTION_LANE, origin="continuous"):
            _CONTINUOUS_COLLECTION_STOP_REQUESTED = True
            write_continuous_status(
                "stopping", enabled=True, reason=reason,
                message="waiting for the current collection task to finish",
            )
        else:
            _CONTINUOUS_COLLECTION_STOP_REQUESTED = False
            write_continuous_status("stopped", enabled=False, reason=reason)


def stop_continuous_backup_mode(reason: str) -> None:
    global _CONTINUOUS_BACKUP_PASSWORD, _CONTINUOUS_BACKUP_INTERVAL_SECONDS
    global _CONTINUOUS_BACKUP_NEXT_RUN
    global _CONTINUOUS_BACKUP_STOP_REQUESTED
    with _CONTINUOUS_STATE_LOCK:
        was_enabled = (
            _CONTINUOUS_BACKUP_PASSWORD is not None
            or _CONTINUOUS_BACKUP_STOP_REQUESTED
        )
        _CONTINUOUS_BACKUP_PASSWORD = None
        _CONTINUOUS_BACKUP_INTERVAL_SECONDS = 0
        _CONTINUOUS_BACKUP_NEXT_RUN = 0.0
        if was_enabled and lane_busy(BACKUP_LANE, origin="continuous"):
            _CONTINUOUS_BACKUP_STOP_REQUESTED = True
            write_continuous_backup_status(
                "stopping", enabled=True, reason=reason,
                message="waiting for the current backup task to finish",
            )
        else:
            _CONTINUOUS_BACKUP_STOP_REQUESTED = False
            write_continuous_backup_status("stopped", enabled=False, reason=reason)


def _finalize_continuous_stop_if_requested(lane: str) -> bool:
    """Publish stopped only after the selected continuous task has drained."""
    global _CONTINUOUS_COLLECTION_STOP_REQUESTED
    global _CONTINUOUS_BACKUP_STOP_REQUESTED
    lane = _validate_lane(lane)
    with _CONTINUOUS_STATE_LOCK:
        if lane == COLLECTION_LANE and _CONTINUOUS_COLLECTION_STOP_REQUESTED:
            _CONTINUOUS_COLLECTION_STOP_REQUESTED = False
            write_continuous_status(
                "stopped", enabled=False, reason="current collection task finished",
            )
            return True
        if lane == BACKUP_LANE and _CONTINUOUS_BACKUP_STOP_REQUESTED:
            _CONTINUOUS_BACKUP_STOP_REQUESTED = False
            write_continuous_backup_status(
                "stopped", enabled=False, reason="current backup task finished",
            )
            return True
    return False


def continuous_cooldown_wait(scope: str, lane: str) -> dict:
    """Read only the selected lane's manual/continuous shared cooldown."""
    lane = _validate_lane(lane)
    project = active_project_identity(HTTP_ROOT)
    keys = (
        collection_keys_for_scope(scope)
        if lane == COLLECTION_LANE else ("yaml-backup",)
    )
    with CollectionGate(
        project, scope, collection_keys=keys, status_dir=STATUS_DIR,
        cooldown_seconds=YAML_BACKUP_COOLDOWN_SECONDS,
        lock_wait_seconds=0, clock=time.time, lane=lane,
    ) as gate:
        decision = gate.decision
    if decision.allowed:
        return {}
    if decision.reason == "busy":
        return {
            "remaining_seconds": 1,
            "wait_reason": f"active {lane} task",
            "next_allowed_at": "",
        }
    if decision.reason == "cooldown":
        return {
            "remaining_seconds": decision.remaining_seconds,
            "wait_reason": f"{lane} cooldown",
            "next_allowed_at": decision.next_allowed_at or "",
        }
    raise CollectionGateError(
        f"unexpected continuous {lane} cooldown decision: {decision.reason}"
    )


def _schedule_after_wait(write_status_fn, interval_minutes: int, wait: dict) -> int:
    remaining = max(1, int(wait["remaining_seconds"]))
    next_epoch = time.time() + remaining
    write_status_fn(
        "waiting", enabled=True, interval_minutes=interval_minutes,
        remaining_seconds=remaining, wait_reason=wait["wait_reason"],
        next_run_at=(
            wait.get("next_allowed_at")
            or datetime.fromtimestamp(next_epoch).astimezone()
            .isoformat(timespec="seconds")
        ),
    )
    return remaining


def run_continuous_collection_cycle(
    scope: str, timeout: int, lock_wait: int,
) -> bool:
    global _CONTINUOUS_COLLECTION_NEXT_RUN
    with _CONTINUOUS_STATE_LOCK:
        if _CONTINUOUS_COLLECTION_INTERVAL_SECONDS <= 0:
            return False
        interval_seconds = _CONTINUOUS_COLLECTION_INTERVAL_SECONDS
        interval_minutes = interval_seconds // 60
    try:
        wait = continuous_cooldown_wait(scope, COLLECTION_LANE)
    except CollectionGateError as exc:
        stop_continuous_collection_mode("cooldown gate failed")
        write_continuous_status(
            "failed", enabled=False, interval_minutes=interval_minutes,
            reason=f"continuous collection cooldown gate: {type(exc).__name__}",
        )
        return False
    if wait:
        with _CONTINUOUS_STATE_LOCK:
            if _CONTINUOUS_COLLECTION_STOP_REQUESTED:
                _finalize_continuous_stop_if_requested(COLLECTION_LANE)
                return False
            if _CONTINUOUS_COLLECTION_INTERVAL_SECONDS <= 0:
                return False
            _CONTINUOUS_COLLECTION_NEXT_RUN = (
                time.monotonic()
                + _schedule_after_wait(
                    write_continuous_status, interval_minutes, wait,
                )
            )
        return True
    with _CONTINUOUS_STATE_LOCK:
        if _CONTINUOUS_COLLECTION_STOP_REQUESTED:
            _finalize_continuous_stop_if_requested(COLLECTION_LANE)
            return False
        if _CONTINUOUS_COLLECTION_INTERVAL_SECONDS <= 0:
            return False
        write_continuous_status(
            "running", enabled=True, interval_minutes=interval_minutes,
            started_at=timestamp(),
        )
    result = collect_safely(scope, timeout, lock_wait)
    with _CONTINUOUS_STATE_LOCK:
        if _CONTINUOUS_COLLECTION_STOP_REQUESTED:
            _finalize_continuous_stop_if_requested(COLLECTION_LANE)
            return result
        if _CONTINUOUS_COLLECTION_INTERVAL_SECONDS <= 0:
            return False
        _CONTINUOUS_COLLECTION_NEXT_RUN = time.monotonic() + interval_seconds
        next_epoch = time.time() + interval_seconds
        write_continuous_status(
            "scheduled", enabled=True, interval_minutes=interval_minutes,
            finished_at=timestamp(), collection_ok=result,
            next_run_at=datetime.fromtimestamp(next_epoch).astimezone().isoformat(
                timespec="seconds"
            ),
        )
    return result


def run_continuous_backup_cycle(
    scope: str, timeout: int, lock_wait: int,
) -> bool:
    global _CONTINUOUS_BACKUP_NEXT_RUN
    with _CONTINUOUS_STATE_LOCK:
        password = _CONTINUOUS_BACKUP_PASSWORD
        if password is None:
            return False
        interval_seconds = _CONTINUOUS_BACKUP_INTERVAL_SECONDS
        interval_minutes = interval_seconds // 60
    try:
        wait = continuous_cooldown_wait(scope, BACKUP_LANE)
    except CollectionGateError as exc:
        stop_continuous_backup_mode("cooldown gate failed")
        write_continuous_backup_status(
            "failed", enabled=False, interval_minutes=interval_minutes,
            reason=f"continuous backup cooldown gate: {type(exc).__name__}",
        )
        return False
    if wait:
        with _CONTINUOUS_STATE_LOCK:
            if _CONTINUOUS_BACKUP_STOP_REQUESTED:
                _finalize_continuous_stop_if_requested(BACKUP_LANE)
                return False
            if _CONTINUOUS_BACKUP_PASSWORD is None:
                return False
            _CONTINUOUS_BACKUP_NEXT_RUN = (
                time.monotonic()
                + _schedule_after_wait(
                    write_continuous_backup_status, interval_minutes, wait,
                )
            )
        return True
    with _CONTINUOUS_STATE_LOCK:
        if _CONTINUOUS_BACKUP_STOP_REQUESTED:
            _finalize_continuous_stop_if_requested(BACKUP_LANE)
            return False
        if _CONTINUOUS_BACKUP_PASSWORD is None:
            return False
        write_continuous_backup_status(
            "running", enabled=True, interval_minutes=interval_minutes,
            started_at=timestamp(),
        )
    result = run_yaml_backup_safely(password, scope, timeout, lock_wait)
    with _CONTINUOUS_STATE_LOCK:
        if _CONTINUOUS_BACKUP_STOP_REQUESTED:
            _finalize_continuous_stop_if_requested(BACKUP_LANE)
            return result
        if _CONTINUOUS_BACKUP_PASSWORD is None:
            return False
        _CONTINUOUS_BACKUP_NEXT_RUN = time.monotonic() + interval_seconds
        next_epoch = time.time() + interval_seconds
        write_continuous_backup_status(
            "scheduled", enabled=True, interval_minutes=interval_minutes,
            finished_at=timestamp(), backup_ok=result,
            next_run_at=datetime.fromtimestamp(next_epoch).astimezone().isoformat(
                timespec="seconds"
            ),
        )
    return result


def collect(scope: str, timeout: int, lock_wait: int) -> bool:
    started_at = timestamp()
    write_status("collecting", scope=scope, started_at=started_at)
    try:
        project = active_project_identity(HTTP_ROOT)
        with CollectionGate(
            project, scope, collection_keys=collection_keys_for_scope(scope),
            status_dir=STATUS_DIR, lock_wait_seconds=lock_wait,
            cancel_check=lambda: lane_cancelled(COLLECTION_LANE),
            lane=COLLECTION_LANE,
        ) as gate:
            decision = gate.decision
            if not decision.allowed:
                finished_at = timestamp()
                if decision.reason == "cooldown":
                    print(
                        f"[{finished_at}] [COOLDOWN] skipped; "
                        f"next collection allowed at {decision.next_allowed_at}",
                        flush=True,
                    )
                    write_status(
                        "success", scope=scope, started_at=started_at,
                        finished_at=finished_at, cooldown_skipped=True,
                        last_success_at=decision.last_success_at,
                        next_allowed_at=decision.next_allowed_at,
                        remaining_seconds=decision.remaining_seconds,
                    )
                    return True
                write_status(
                    "failed", scope=scope, started_at=started_at,
                    finished_at=finished_at,
                    reason="another managed Switch collection is already running",
                )
                return False

            if lane_cancelled(COLLECTION_LANE):
                write_status(
                    "idle", scope=scope, stopped_at=timestamp(), stopped_pids=[]
                )
                return False
            run_result = run_collection_cycle_coordinator(
                gate,
                artifact_bindings={},
                timeout=timeout,
                lock_wait=lock_wait,
            )
            errors = []
            task_results = []
            for outcome in run_result["outcomes"]:
                if outcome["outcome"] == "accepted":
                    task_results.append(outcome["child_result"])
                else:
                    errors.append(
                        f"{outcome['source_slot']}: {outcome['outcome']}"
                    )

            failed_devices = []
            seen_failures = set()
            for task_result in task_results:
                for failure in task_result["failed_devices"]:
                    key = failure["hostname"].casefold()
                    if key not in seen_failures:
                        seen_failures.add(key)
                        failed_devices.append(failure)
            failed_devices.sort(key=lambda item: item["hostname"].casefold())
            planned = sum(task_result["planned"] for task_result in task_results)
            succeeded = sum(task_result["succeeded"] for task_result in task_results)
            failed_count = len(failed_devices)
            finished_at = timestamp()
            if not errors and planned == 0:
                write_status(
                    "failed", scope=scope, started_at=started_at,
                    finished_at=finished_at, reason="no devices selected",
                    planned=0, succeeded=0, failed_count=0,
                    failed_devices=[], summary="no devices selected",
                )
                return False
            if not errors and planned > 0 and succeeded == 0:
                write_status(
                    "failed", scope=scope, started_at=started_at,
                    finished_at=finished_at,
                    reason="all selected devices failed",
                    planned=planned, succeeded=0, failed_count=failed_count,
                    failed_devices=failed_devices,
                    summary=f"all {failed_count} selected device(s) failed",
                )
                return False

            # Schema-v2 runs already bind HTML generation into their summary.
            # Legacy operational runs remain nonqualifying but preserve the
            # existing HTML refresh before cooldown success is recorded.
            if not errors and run_result["summary"] is None:
                html_command = [sys.executable, str(HTML_SCRIPT)]
                if scope in {"air", "prod"}:
                    html_command += ["--type", scope]
                result = subprocess.run(
                    html_command, cwd=HTTP_ROOT, text=True,
                    capture_output=True, timeout=180, check=False,
                )
                if result.returncode:
                    errors.append(
                        (result.stderr.strip() or result.stdout.strip()
                         or "monitor.html generation failed")[-2000:]
                    )
            finished_at = timestamp()
            if errors:
                write_status(
                    "failed", scope=scope, started_at=started_at,
                    finished_at=finished_at, reason=" | ".join(errors),
                )
                return False
            successful_at = gate.mark_success()
            next_epoch = time.time() + gate.cooldown_seconds
            final_state = "partial" if failed_devices else "success"
            write_status(
                final_state, scope=scope, started_at=started_at,
                finished_at=finished_at, cooldown_seconds=gate.cooldown_seconds,
                last_success_at=successful_at,
                next_allowed_epoch=next_epoch,
                next_allowed_at=(
                    datetime.fromtimestamp(next_epoch).astimezone()
                    .isoformat(timespec="seconds")
                ),
                **(
                    {
                        "planned": planned,
                        "succeeded": succeeded,
                        "failed_count": failed_count,
                        "failed_devices": failed_devices,
                        "summary": (
                            f"completed with warnings: {failed_count} device(s) failed"
                        ),
                    }
                    if final_state == "partial" else {}
                ),
            )
            return True
    except CollectionGateCancelled:
        write_status(
            "idle", scope=scope, stopped_at=timestamp(), stopped_pids=[],
        )
        return False
    except (CollectionGateError, CollectionCycleHoldError) as exc:
        finished_at = timestamp()
        write_status(
            "failed", scope=scope, started_at=started_at,
            finished_at=finished_at, reason=f"collection cooldown gate: {exc}",
        )
        return False


def collect_safely(scope: str, timeout: int, lock_wait: int) -> bool:
    """Keep the persistent worker alive if one collection has an internal error."""
    try:
        return collect(scope, timeout, lock_wait)
    except Exception as exc:  # defensive boundary for the long-running worker
        finished_at = timestamp()
        detail = f"{type(exc).__name__}: {exc}"
        write_status("failed", scope=scope, finished_at=finished_at, reason=detail)
        print(f"[{finished_at}] [ERROR] unexpected collection failure: {detail}",
              file=sys.stderr, flush=True)
        traceback.print_exc()
        return False


def handle_memory_request(message: dict, scope: str, timeout: int, lock_wait: int) -> None:
    action = message["action"]
    if action == "yaml_backup":
        if continuous_backup_enabled():
            raise ValueError("manual YAML backup is disabled during continuous backup")
        write_yaml_backup_status("queued", scope=scope, queued_at=timestamp())
        if not start_lane_task(
            BACKUP_LANE, "manual", run_yaml_backup_safely,
            message["password"], scope, timeout, lock_wait,
        ):
            raise ValueError("another backup task is already running")
    elif action == "continuous_collection_start":
        if continuous_collection_enabled():
            raise ValueError("continuous collection is already enabled")
        if lane_busy(COLLECTION_LANE):
            raise ValueError("another collection task is already running")
        configure_continuous_collection(message)
    elif action == "continuous_backup_start":
        if continuous_backup_enabled():
            raise ValueError("continuous backup is already enabled")
        if lane_busy(BACKUP_LANE):
            raise ValueError("another backup task is already running")
        configure_continuous_backup(message)
    elif action == "continuous_collection_stop":
        stop_continuous_collection_mode("operator")
    elif action == "continuous_backup_stop":
        stop_continuous_backup_mode("operator")
    else:
        raise ValueError("unsupported memory request")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Switch Status independent collection worker")
    result.add_argument("--scope", choices=("air", "prod", "all"))
    result.add_argument(
        "--internal-cycle", action="store_true", help=argparse.SUPPRESS,
    )
    result.add_argument(
        "--internal-cycle-context-fd", type=int, help=argparse.SUPPRESS,
    )
    result.add_argument(
        "--internal-cycle-result-fd", type=int, help=argparse.SUPPRESS,
    )
    result.add_argument("--poll", type=int, default=2)
    result.add_argument("--timeout", type=int, default=3600)
    result.add_argument("--lock-wait", type=int, default=600)
    return result


def main() -> int:
    global _SHUTDOWN_SIGNAL
    _SHUTDOWN_SIGNAL = None
    signal.signal(signal.SIGTERM, _request_shutdown)
    signal.signal(signal.SIGINT, _request_shutdown)
    argument_parser = parser()
    args = argument_parser.parse_args()
    if args.internal_cycle:
        if (
            args.internal_cycle_context_fd is None
            or args.internal_cycle_result_fd is None
        ):
            print("internal_cycle_gate_required", file=sys.stderr)
            return 64
        try:
            return _run_internal_collection_cycle(
                args.internal_cycle_context_fd,
                args.internal_cycle_result_fd,
            )
        except Exception as exc:
            print(
                f"internal_cycle_failed:{type(exc).__name__}",
                file=sys.stderr,
            )
            return 65
    if args.scope is None:
        argument_parser.error("--scope is required outside internal cycle mode")
    STATUS_DIR.mkdir(parents=True, exist_ok=True)
    write_status("idle", scope=args.scope)
    write_yaml_backup_status("idle", scope=args.scope)
    stop_continuous_collection_mode("worker started")
    stop_continuous_backup_mode("worker started")
    memory_socket, socket_identity = open_memory_socket()
    try:
        while not _shutdown_requested():
            try:
                messages = receive_memory_requests(memory_socket)
            except ValueError as exc:
                write_yaml_backup_status(
                    "failed", scope=args.scope, finished_at=timestamp(),
                    reason=f"invalid in-memory request: {type(exc).__name__}",
                )
                messages = []
            for message in messages:
                try:
                    handle_memory_request(
                        message, args.scope, max(args.timeout, 60),
                        max(args.lock_wait, 0),
                    )
                except Exception as exc:
                    write_yaml_backup_status(
                        "failed", scope=args.scope, finished_at=timestamp(),
                        reason=f"memory request failed: {type(exc).__name__}",
                    )
                finally:
                    if "password" in message:
                        message["password"] = ""
            action = claim_request()
            if action == "collect":
                if continuous_collection_enabled():
                    write_status(
                        "failed", scope=args.scope, finished_at=timestamp(),
                        reason="manual collection is disabled during continuous collection",
                    )
                else:
                    write_status("queued", scope=args.scope, queued_at=timestamp())
                    if not start_lane_task(
                        COLLECTION_LANE, "manual", collect_safely,
                        args.scope, max(args.timeout, 60), max(args.lock_wait, 0),
                    ):
                        write_status(
                            "failed", scope=args.scope, finished_at=timestamp(),
                            reason="another collection task is already running",
                        )
            if (
                continuous_collection_scheduled()
                and time.monotonic() >= _CONTINUOUS_COLLECTION_NEXT_RUN
                and not lane_busy(COLLECTION_LANE)
                and not _shutdown_requested()
            ):
                start_lane_task(
                    COLLECTION_LANE, "continuous", run_continuous_collection_cycle,
                    args.scope, max(args.timeout, 60), max(args.lock_wait, 0),
                )
            if (
                continuous_backup_scheduled()
                and time.monotonic() >= _CONTINUOUS_BACKUP_NEXT_RUN
                and not lane_busy(BACKUP_LANE)
                and not _shutdown_requested()
            ):
                start_lane_task(
                    BACKUP_LANE, "continuous", run_continuous_backup_cycle,
                    args.scope, max(args.timeout, 60), max(args.lock_wait, 0),
                )
            time.sleep(max(args.poll, 1))
    finally:
        stop_continuous_collection_mode("worker stopped")
        stop_continuous_backup_mode("worker stopped")
        stop_all_collectors()
        join_lane_tasks(timeout=COLLECTOR_TERM_GRACE_SECONDS + COLLECTOR_KILL_GRACE_SECONDS)
        close_memory_socket(memory_socket, socket_identity)
        try:
            if int(PID_FILE.read_text().strip()) == os.getpid():
                PID_FILE.unlink(missing_ok=True)
        except (OSError, ValueError):
            pass
    if _SHUTDOWN_SIGNAL is not None:
        return 128 + int(_SHUTDOWN_SIGNAL)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
