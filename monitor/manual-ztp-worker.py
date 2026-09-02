#!/usr/bin/env python3
"""Root worker executing independent per-device manual ZTP GUI requests."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import fcntl
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import threading
import time


HTTP_ROOT = Path(__file__).resolve().parent.parent
STATUS_DIR = HTTP_ROOT / "monitor/status"
REQUEST_FILE = STATUS_DIR / "manual-ztp.request.json"
STATUS_FILE = STATUS_DIR / "manual-ztp.status.json"
PID_FILE = STATUS_DIR / "manual-ztp.pid"
MANUAL_SCRIPT = HTTP_ROOT / "ztp/manual-ztp.py"
RESET_SCRIPT = HTTP_ROOT / "ztp/manual-reset.py"
ZTP_STATUS_DIR = HTTP_ROOT / "ztp/status"
DEVICES_CSV = HTTP_ROOT / "monitor/02-devices_config.csv"
SAFE_HOSTNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
BUSY_STATES = {"queued", "running", "ztp_running"}
PREVIEW_STATES = {
    "preview_queued", "previewing", "preview_ready", "confirm_queued",
    "cancel_queued",
}
TIME_SYNC_STATES = {"time_sync_queued", "time_sync_running"}
ACTIVE_REQUEST_STATES = (
    BUSY_STATES | (PREVIEW_STATES - {"preview_ready"}) | TIME_SYNC_STATES
)
STATUS_LOCK = threading.Lock()
QUEUE_MAX_BYTES = 1024 * 1024
QUEUE_MAX_REQUESTS = 256


def timestamp():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def atomic_json(path, payload, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        existing = path.stat()
    except OSError:
        existing = None
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        if existing is not None:
            os.chown(temporary, existing.st_uid, existing.st_gid)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _read_json(path):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def normalize_status(value, scope=""):
    """Read the current per-device schema and migrate the old single state."""
    if not isinstance(value, dict):
        value = {}
    devices = value.get("devices")
    if isinstance(devices, dict):
        clean = {
            str(hostname): state for hostname, state in devices.items()
            if SAFE_HOSTNAME.fullmatch(str(hostname)) and isinstance(state, dict)
        }
        return {
            "scope": str(value.get("scope") or scope),
            "updated_at": str(value.get("updated_at") or ""),
            "devices": clean,
        }
    hostname = str(value.get("hostname") or "")
    legacy = {}
    if SAFE_HOSTNAME.fullmatch(hostname) and value.get("state"):
        legacy[hostname] = dict(value)
    return {
        "scope": str(value.get("scope") or scope),
        "updated_at": str(value.get("updated_at") or ""),
        "devices": legacy,
    }


def read_status(scope=""):
    return normalize_status(_read_json(STATUS_FILE), scope)


def initialize_status(scope):
    with STATUS_LOCK:
        status = read_status(scope)
        if status.get("scope") not in {"", scope}:
            status = {"scope": scope, "devices": {}}
        status["scope"] = scope
        status["updated_at"] = timestamp()
        atomic_json(STATUS_FILE, status)
        return status


def write_device_status(hostname, state, **extra):
    with STATUS_LOCK:
        status = read_status(str(extra.get("scope") or ""))
        devices = status.setdefault("devices", {})
        devices[hostname] = {
            "state": state, "hostname": hostname,
            "updated_at": timestamp(), **extra,
        }
        status["updated_at"] = timestamp()
        if extra.get("scope"):
            status["scope"] = extra["scope"]
        atomic_json(STATUS_FILE, status)


def cancel_preview(
    hostname, scope, current, operation_id, trigger_id, requested_operation,
):
    """Cancel only the exact pending preview; never touch an executing action."""
    if not (
        isinstance(current, dict)
        and current.get("state") == "preview_ready"
        and str(current.get("operation_id") or "") == operation_id
        and str(current.get("trigger_id") or "") == trigger_id
        and str(current.get("requested_operation") or "") == requested_operation
    ):
        return False
    cancelled_at = timestamp()
    effective_operation = str(
        current.get("effective_operation") or current.get("operation") or "ztp"
    )
    write_device_status(
        hostname, "cancelled", scope=scope,
        requested_at=str(current.get("requested_at") or ""),
        cancelled_at=cancelled_at,
        operation_id=operation_id, trigger_id=trigger_id,
        trigger_source=str(current.get("trigger_source") or "manual_web"),
        operation=effective_operation,
        effective_operation=effective_operation,
        requested_operation=requested_operation, phase="cancel",
        message="用户取消配置差异预检；未执行任何设备变更",
    )
    return True


def _decode_queue(raw):
    try:
        value = json.loads(raw.decode("utf-8") or "{}")
    except (UnicodeError, json.JSONDecodeError):
        return []
    if not isinstance(value, dict):
        return []
    requests = value.get("requests")
    if isinstance(requests, list):
        return [
            item for item in requests
            if isinstance(item, dict)
            and item.get("action") in {"trigger", "reset", "renew", "time-sync"}
            and SAFE_HOSTNAME.fullmatch(str(item.get("hostname") or ""))
        ]
    if (
        value.get("action") in {"trigger", "reset", "renew", "time-sync"}
        and SAFE_HOSTNAME.fullmatch(str(value.get("hostname") or ""))
    ):
        return [value]
    return []


def pop_requests(blocked_hostnames=()):
    """Atomically take runnable requests and retain active-device requests.

    A preview future can publish ``preview_ready`` immediately before the
    future itself becomes ``done``.  The browser may enqueue the exact confirm
    during that short window.  Keeping requests for active hostnames in the
    locked queue prevents that confirm from being consumed and silently lost;
    requests for other devices remain runnable in the same poll.
    """
    blocked = {str(hostname).casefold() for hostname in blocked_hostnames}
    try:
        flags = (
            os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(REQUEST_FILE, flags)
    except OSError:
        return []
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        file_status = os.fstat(descriptor)
        if not stat.S_ISREG(file_status.st_mode) or file_status.st_nlink != 1:
            return []
        if file_status.st_size > QUEUE_MAX_BYTES:
            print(
                f"[{timestamp()}] [ERROR] manual ZTP request queue exceeds "
                f"{QUEUE_MAX_BYTES} bytes; refusing to truncate it",
                file=sys.stderr, flush=True,
            )
            return []
        os.lseek(descriptor, 0, os.SEEK_SET)
        requests = _decode_queue(os.read(descriptor, QUEUE_MAX_BYTES + 1))
        if len(requests) > QUEUE_MAX_REQUESTS:
            print(
                f"[{timestamp()}] [ERROR] manual ZTP request queue exceeds "
                f"{QUEUE_MAX_REQUESTS} entries; refusing to truncate it",
                file=sys.stderr, flush=True,
            )
            return []
        runnable = []
        retained = []
        claimed = set(blocked)
        for item in requests:
            key = str(item["hostname"]).casefold()
            # At most one request per device may leave the durable queue in a
            # poll.  This also protects the state machine if a legacy writer or
            # hand-edited queue contains duplicates despite the CGI guard.
            target = retained if key in claimed else runnable
            target.append(item)
            claimed.add(key)
        # Do not rewrite an entirely blocked queue on every poll.  Besides
        # avoiding needless fsync churn, this keeps a long-running operation
        # from turning a deferred request into a busy-spin disk workload.
        if runnable:
            payload = (
                json.dumps({"requests": retained}, ensure_ascii=False) + "\n"
            ).encode("utf-8")
            if len(payload) > QUEUE_MAX_BYTES:
                print(
                    f"[{timestamp()}] [ERROR] retained manual ZTP queue exceeds "
                    f"{QUEUE_MAX_BYTES} bytes; refusing to truncate it",
                    file=sys.stderr, flush=True,
                )
                return []
            os.lseek(descriptor, 0, os.SEEK_SET)
            os.ftruncate(descriptor, 0)
            os.write(descriptor, payload)
            os.fsync(descriptor)
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)
    return runnable


def command_for(
    hostname, scope, operation="ztp", operation_id="", trigger_id="",
    preflight_only=False, preview_fingerprint=None,
):
    command = [
        sys.executable, str(RESET_SCRIPT if operation == "reset" else MANUAL_SCRIPT), hostname,
        "--type", scope, "--yes", "--non-interactive", "--origin", "web",
    ]
    if operation in {"renew", "time-sync"}:
        command += ["--operation", operation]
    if operation_id:
        command += ["--operation-id", operation_id]
    if trigger_id:
        command += ["--trigger-id", trigger_id]
    if preflight_only:
        command += ["--preflight-only"]
    fingerprint = preview_fingerprint if isinstance(preview_fingerprint, dict) else {}
    if fingerprint:
        command += [
            "--confirmed-current-sha256", str(fingerprint.get("current_sha256") or ""),
            "--confirmed-expected-sha256", str(fingerprint.get("expected_sha256") or ""),
            "--confirmed-release-dir", str(fingerprint.get("published_release_dir") or ""),
            "--confirmed-effective-operation", str(fingerprint.get("effective_operation") or ""),
            "--confirmed-transport-ip", str(fingerprint.get("transport_ip") or ""),
            "--confirmed-interface", str(fingerprint.get("interface") or ""),
            "--confirmed-bootstrap-url", str(fingerprint.get("bootstrap_url") or ""),
            "--confirmed-bootstrap-source-ip", str(fingerprint.get("bootstrap_source_ip") or ""),
            "--confirmed-bootstrap-source-network", str(fingerprint.get("bootstrap_source_network") or ""),
        ]
    return command


def needs_helper_hint(detail):
    """Return true only when the restricted helper/sudo is the actual failure."""
    lowered = str(detail or "").casefold()
    return (
        "sudo: a password is required" in lowered
        or "sudo: no tty present" in lowered
        or (
            ("http-manual-ztp" in lowered or "http-manual-reset" in lowered)
            and any(token in lowered for token in (
                "no such file", "not found", "command not found",
            ))
        )
    )


def _report_time(report, path):
    try:
        return datetime.fromisoformat(
            str(report.get("generated_at") or "").replace("Z", "+00:00")
        ).timestamp()
    except (TypeError, ValueError):
        try:
            return path.stat().st_mtime
        except OSError:
            return 0.0


def _iso_time(value):
    try:
        return datetime.fromisoformat(str(value or "").replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return 0.0


def latest_device_state(hostname):
    candidates = []
    seen = set()
    for report_path in ZTP_STATUS_DIR.glob("*/report.json"):
        try:
            resolved = report_path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for device in report.get("devices", []):
            if not isinstance(device, dict):
                continue
            if str(device.get("hostname") or "").casefold() != hostname.casefold():
                continue
            try:
                ztp_round = max(1, int(device.get("ztp_round", 1)))
            except (TypeError, ValueError):
                ztp_round = 1
            progress = device.get("progress", {})
            try:
                percent = int(progress.get("percent", 0)) if isinstance(progress, dict) else 0
            except (TypeError, ValueError):
                percent = 0
            stages = device.get("stages", {})
            complete = stages.get("complete", {}) if isinstance(stages, dict) else {}
            try:
                complete_success_index = max(
                    0, int(complete.get("success_index") or 0)
                ) if isinstance(complete, dict) else 0
            except (TypeError, ValueError):
                complete_success_index = 0
            issues = device.get("issues", [])
            failure_reason = "; ".join(
                str(item.get("detail") or item.get("message") or item.get("code") or "")
                for item in issues if isinstance(item, dict)
                and str(item.get("severity") or "").casefold() in {"error", "failed"}
            )
            candidates.append((_report_time(report, report_path), {
                "hostname": str(device.get("hostname") or hostname),
                "ztp_round": ztp_round,
                "progress": percent,
                "overall": str(device.get("overall") or "unknown"),
                "complete_status": str(
                    complete.get("status") or "unknown"
                ) if isinstance(complete, dict) else "unknown",
                "complete_success_index": complete_success_index,
                "report_generated_at": str(report.get("generated_at") or ""),
                "manual_cycle_marker": str(device.get("manual_cycle_marker") or ""),
                "trigger_source": str(device.get("trigger_source") or ""),
                "trigger_id": str(device.get("trigger_id") or ""),
                "failure_reason": failure_reason,
            }))
    return max(candidates, key=lambda item: item[0])[1] if candidates else None


def latest_cli_operations():
    """Return the newest explicit CLI operation for each active-project host."""
    try:
        project = DEVICES_CSV.resolve(strict=True).parent
    except OSError:
        return {}
    operations = {}
    paths = [
        (path, source, operation)
        for directory, source, operation in (
            ("manual-trigger", "manual_cli", "ztp"),
            ("manual-reset", "manual_reset_cli", "reset"),
        )
        for path in (project / "99-output-ztp" / directory).glob("*/summary.json")
    ]
    for path, expected_source, operation_name in paths:
        try:
            summary = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(summary, dict) or summary.get("trigger_source") != expected_source:
            continue
        requested_at = str(summary.get("requested_at") or summary.get("generated_at") or "")
        results = {
            str(item.get("hostname") or "").casefold(): item
            for item in summary.get("results", []) if isinstance(item, dict)
        }
        for target in summary.get("targets", []):
            if not isinstance(target, dict):
                continue
            hostname = str(target.get("hostname") or "")
            if not SAFE_HOSTNAME.fullmatch(hostname):
                continue
            result = results.get(hostname.casefold(), {})
            summary_state = str(summary.get("state") or "running")
            state = str(result.get("state") or (
                "failed" if summary_state in {"failed", "cancelled"}
                else "running"
            ))
            operation = {
                "hostname": hostname, "state": state,
                "type": str(target.get("type") or ""),
                "operation_id": str(
                    result.get("operation_id") or summary.get("operation_id")
                    or result.get("trigger_id")
                    or f"cli:{path.parent.name}"
                ),
                "trigger_id": str(
                    result.get("trigger_id") or target.get("trigger_id")
                    or f"cli:{path.parent.name}:{hostname}"
                ),
                "trigger_source": expected_source,
                "operation": str(
                    result.get("effective_operation")
                    or summary.get("effective_operation")
                    or summary.get("operation") or operation_name
                ),
                "requested_operation": str(
                    summary.get("requested_operation") or operation_name
                ),
                "started_at": str(result.get("started_at") or requested_at),
                "updated_at": str(result.get("finished_at") or summary.get("generated_at") or requested_at),
                "reason": str(
                    result.get("reason") or summary.get("reason")
                    or ("用户取消" if summary_state == "cancelled" else "")
                ),
            }
            previous = operations.get(hostname.casefold())
            if previous is None or _iso_time(operation["started_at"]) >= _iso_time(previous["started_at"]):
                operations[hostname.casefold()] = operation
    return operations


def accepted_result(trigger_id):
    """Find the exact web/CLI result produced for this request."""
    if not trigger_id:
        return {}
    try:
        project = DEVICES_CSV.resolve(strict=True).parent
    except OSError:
        return {}
    for directory in ("manual-trigger", "manual-reset"):
        for path in (project / "99-output-ztp" / directory).glob("*/*/result.json"):
            result = _read_json(path)
            if str(result.get("trigger_id") or "") == trigger_id:
                return result
    return {}


def preview_result(operation_id, trigger_id, hostname):
    """Return exact preflight evidence for one completed preview request."""
    if not operation_id or not trigger_id:
        return {}
    try:
        project = DEVICES_CSV.resolve(strict=True).parent
    except OSError:
        return {}
    candidates = []
    for directory in ("manual-trigger", "manual-reset"):
        for path in (project / "99-output-ztp" / directory).glob("*/summary.json"):
            summary = _read_json(path)
            if (
                summary.get("state") != "preview_ready"
                or str(summary.get("operation_id") or "") != operation_id
            ):
                continue
            target = next((
                item for item in summary.get("targets", [])
                if isinstance(item, dict)
                and str(item.get("hostname") or "").casefold() == hostname.casefold()
                and str(item.get("trigger_id") or "") == trigger_id
            ), None)
            evidence = next((
                item for item in summary.get("preflight", [])
                if isinstance(item, dict)
                and str(item.get("hostname") or "").casefold() == hostname.casefold()
                and str(item.get("trigger_id") or "") == trigger_id
                and str(item.get("operation_id") or "") == operation_id
            ), None)
            if target is None or evidence is None:
                continue
            candidates.append((_iso_time(summary.get("generated_at")), {
                "operation_id": operation_id,
                "trigger_id": trigger_id,
                "hostname": hostname,
                "effective_operation": str(
                    target.get("effective_operation")
                    or summary.get("effective_operation")
                    or summary.get("operation") or "ztp"
                ),
                "trigger_source": str(summary.get("trigger_source") or "manual_web"),
                "generated_at": str(summary.get("generated_at") or ""),
                "transport_ip": str(evidence.get("transport_ip") or ""),
                "interface": str(evidence.get("interface") or ""),
                "expected_yaml": str(evidence.get("expected_yaml") or ""),
                "configuration_matches": bool(evidence.get("configuration_matches")),
                "payload_matches_latest": (
                    evidence.get("payload_matches_latest")
                    if isinstance(evidence.get("payload_matches_latest"), bool)
                    else None
                ),
                "fallback_semantic_matches": (
                    evidence.get("fallback_semantic_matches")
                    if isinstance(evidence.get("fallback_semantic_matches"), bool)
                    else None
                ),
                "runtime_matches_latest": (
                    evidence.get("runtime_matches_latest")
                    if isinstance(evidence.get("runtime_matches_latest"), bool)
                    else None
                ),
                "comparison_source": str(
                    evidence.get("comparison_source") or ""
                ),
                "comparison_reason": str(
                    evidence.get("comparison_reason") or ""
                ),
                "preview_fingerprint": {
                    "current_sha256": str(evidence.get("current_sha256") or ""),
                    "expected_sha256": str(evidence.get("expected_sha256") or ""),
                    "published_release_dir": str(
                        evidence.get("published_release_dir") or ""
                    ),
                    "effective_operation": str(
                        target.get("effective_operation")
                        or summary.get("effective_operation") or ""
                    ),
                    "transport_ip": str(evidence.get("transport_ip") or ""),
                    "interface": str(evidence.get("interface") or ""),
                    "bootstrap_url": str(evidence.get("bootstrap_url") or ""),
                    "bootstrap_source_ip": str(
                        evidence.get("bootstrap_source_ip") or ""
                    ),
                    "bootstrap_source_network": str(
                        evidence.get("bootstrap_source_network") or ""
                    ),
                },
                "diff_summary": (
                    evidence.get("diff_summary")
                    if isinstance(evidence.get("diff_summary"), dict) else {}
                ),
                "evidence_dir": str(path.parent / hostname),
            }))
    return max(candidates, key=lambda item: item[0])[1] if candidates else {}


def new_round_complete(
    state, baseline_round, not_before="", operation_id="", trigger_source="",
    trigger_id="",
):
    if not isinstance(state, dict):
        return False
    report_time = _iso_time(state.get("report_generated_at"))
    boundary = _iso_time(not_before)
    expected_trigger = str(trigger_id or operation_id or "")
    if expected_trigger and str(state.get("trigger_id") or "") != expected_trigger:
        return False
    if trigger_source and str(state.get("trigger_source") or "") != trigger_source:
        return False
    try:
        current_round = int(state.get("ztp_round") or 0)
        progress = int(state.get("progress") or 0)
        complete_success_index = int(state.get("complete_success_index") or 0)
    except (TypeError, ValueError):
        return False
    complete_status = str(state.get("complete_status") or "").casefold()
    overall = str(state.get("overall") or "").casefold()
    failure_reason = str(state.get("failure_reason") or "").strip()
    # AIR-only devices legitimately finish with a default-derived hostname
    # baseline.  The monitor marks both config_apply and complete as warning,
    # while still proving all stages for the exact current round.  Treat that
    # as a successful operation with warnings only when the current-round
    # completion index is exact and no error evidence exists.  This prevents a
    # stale warning, failed fallback, or partial round from clearing the GUI
    # operation intent.
    terminal_complete = complete_status == "success" or (
        complete_status == "warning"
        and complete_success_index == current_round
        and overall in {"success", "warning"}
        and not failure_reason
    )
    return (
        current_round > int(baseline_round or 0)
        and progress == 100
        and terminal_complete
        and (not boundary or report_time >= boundary - 5)
    )


def operation_marker_matches(state, operation):
    """Return whether a report represents the accepted CLI operation."""
    state = state if isinstance(state, dict) else {}
    operation = operation if isinstance(operation, dict) else {}
    trigger_id = str(operation.get("trigger_id") or operation.get("operation_id") or "")
    if trigger_id:
        return str(state.get("trigger_id") or "") == trigger_id
    marker = str(state.get("manual_cycle_marker") or "")
    candidates = {
        str(operation.get("updated_at") or ""),
        str(operation.get("started_at") or ""),
    }
    candidates.discard("")
    return bool(marker and marker in candidates)


def matching_terminal_failure(
    state, not_before="", trigger_id="", trigger_source="",
):
    """Return an exact-operation terminal failure, never a stale report."""
    if not isinstance(state, dict) or not trigger_id:
        return ""
    if str(state.get("trigger_id") or "") != trigger_id:
        return ""
    if trigger_source and str(state.get("trigger_source") or "") != trigger_source:
        return ""
    if _iso_time(state.get("report_generated_at")) < _iso_time(not_before) - 5:
        return ""
    overall = str(state.get("overall") or "").casefold()
    complete = str(state.get("complete_status") or "").casefold()
    try:
        current_round = max(0, int(state.get("ztp_round") or 0))
        complete_success_index = max(
            0, int(state.get("complete_success_index") or 0)
        )
    except (TypeError, ValueError):
        current_round = complete_success_index = 0
    # A reset temporarily removes SSH keys/host identity while the switch is
    # rebooting and before bootstrap reinstalls access.  The monitor can
    # legitimately report overall=failed during that window even though the
    # exact operation later completes successfully.  Treat it as terminal only
    # after the same round has reached a terminal bootstrap completion state;
    # otherwise keep polling.  A future explicit complete=failed remains an
    # immediate terminal result.
    if complete != "failed" and not (
        overall == "failed"
        and complete in {"success", "warning"}
        and current_round > 0
        and complete_success_index == current_round
    ):
        return ""
    return str(state.get("failure_reason") or "ZTP 监控报告已标记本次操作失败")


def reconcile_failed_operations(scope, active_hostnames=()):
    """Correct a stale worker failure only from its exact completed report.

    A reset can transiently lose SSH while rebooting.  Older workers persisted
    that observation as a terminal failure and no longer polled it.  Recovery
    is deliberately fail-closed: the hostname, trigger ID/source, report time,
    and completed round must all match the failed operation, and an active task
    always owns its own status.
    """
    active = {str(hostname).casefold() for hostname in active_hostnames}
    corrected = 0
    devices = read_status(scope).get("devices", {})
    for status_hostname, operation_state in devices.items():
        if not isinstance(operation_state, dict):
            continue
        hostname = str(operation_state.get("hostname") or status_hostname)
        hostname_key = hostname.casefold()
        if (
            operation_state.get("state") != "failed"
            or hostname_key in active
            or not SAFE_HOSTNAME.fullmatch(hostname)
            or hostname_key != str(status_hostname).casefold()
        ):
            continue
        trigger_id = str(operation_state.get("trigger_id") or "")
        trigger_source = str(operation_state.get("trigger_source") or "")
        started = str(operation_state.get("started_at") or "")
        operation_id = str(operation_state.get("operation_id") or "")
        if not trigger_id or not trigger_source or _iso_time(started) <= 0:
            continue
        try:
            baseline_round = max(0, int(operation_state.get("baseline_round") or 0))
            expected_round = max(
                baseline_round + 1,
                int(operation_state.get("expected_round") or baseline_round + 1),
            )
        except (TypeError, ValueError):
            continue
        latest = latest_device_state(hostname)
        if (
            not isinstance(latest, dict)
            or str(latest.get("hostname") or "").casefold() != hostname_key
            or not new_round_complete(
                latest, baseline_round, started, operation_id,
                trigger_source, trigger_id,
            )
        ):
            continue
        finished = timestamp()
        operation = str(operation_state.get("operation") or "ztp")
        write_device_status(
            hostname, "success", scope=scope, started_at=started,
            command_finished_at=str(
                operation_state.get("command_finished_at") or ""
            ),
            finished_at=finished, baseline_round=baseline_round,
            expected_round=expected_round,
            completed_round=latest["ztp_round"],
            current_round=latest["ztp_round"], progress=latest["progress"],
            overall=latest["overall"],
            report_generated_at=latest["report_generated_at"],
            operation_id=operation_id, trigger_id=trigger_id,
            trigger_source=trigger_source, operation=operation,
            effective_operation=str(
                operation_state.get("effective_operation") or operation
            ),
            requested_operation=str(
                operation_state.get("requested_operation") or operation
            ),
            message=(
                f"ZTP round {latest['ztp_round']} completed; "
                "corrected an earlier transient monitor failure"
            ),
        )
        corrected += 1
        print(
            f"[{finished}] [RECOVERED] {hostname} ZTP round "
            f"{latest['ztp_round']} completed after transient failure",
            flush=True,
        )
    return corrected


def wait_for_completion(
    hostname, scope, baseline_round, started, command_finished,
    completion_timeout, report_poll, operation_id="", trigger_source="manual_web",
    operation="ztp", trigger_id="", requested_operation="",
):
    trigger_id = str(trigger_id or operation_id or "")
    expected_round = baseline_round + 1
    deadline = time.monotonic() + completion_timeout
    last_state = None
    while time.monotonic() < deadline:
        last_state = latest_device_state(hostname)
        if new_round_complete(
            last_state, baseline_round, started, operation_id, trigger_source,
            trigger_id,
        ):
            finished = timestamp()
            write_device_status(
                hostname, "success", scope=scope, started_at=started,
                command_finished_at=command_finished, finished_at=finished,
                baseline_round=baseline_round, expected_round=expected_round,
                completed_round=last_state["ztp_round"],
                current_round=last_state["ztp_round"],
                progress=last_state["progress"], overall=last_state["overall"],
                report_generated_at=last_state["report_generated_at"],
                operation_id=operation_id, trigger_id=trigger_id,
                trigger_source=trigger_source,
                operation=operation, effective_operation=operation,
                requested_operation=requested_operation or operation,
                message=f"ZTP round {last_state['ztp_round']} completed",
            )
            print(f"[{finished}] [OK] {hostname} ZTP round {last_state['ztp_round']} completed", flush=True)
            return True
        terminal = matching_terminal_failure(
            last_state, started, trigger_id, trigger_source,
        )
        if terminal:
            finished = timestamp()
            write_device_status(
                hostname, "failed", scope=scope, started_at=started,
                command_finished_at=command_finished, finished_at=finished,
                baseline_round=baseline_round, expected_round=expected_round,
                current_round=(last_state or {}).get("ztp_round", baseline_round),
                progress=(last_state or {}).get("progress", 0),
                report_generated_at=(last_state or {}).get("report_generated_at", ""),
                operation_id=operation_id, trigger_id=trigger_id,
                trigger_source=trigger_source, operation=operation,
                effective_operation=operation,
                requested_operation=requested_operation or operation,
                reason=terminal,
            )
            print(f"[{finished}] [FAIL] {hostname}: {terminal}", file=sys.stderr, flush=True)
            return False
        write_device_status(
            hostname, "ztp_running", scope=scope, started_at=started,
            command_finished_at=command_finished,
            baseline_round=baseline_round, expected_round=expected_round,
            current_round=(last_state or {}).get("ztp_round", baseline_round),
            progress=(last_state or {}).get("progress", 0),
            overall=(last_state or {}).get("overall", "waiting"),
            report_generated_at=(last_state or {}).get("report_generated_at", ""),
            operation_id=operation_id, trigger_id=trigger_id,
            trigger_source=trigger_source,
            operation=operation, effective_operation=operation,
            requested_operation=requested_operation or operation,
            message=f"等待 ZTP 第 {expected_round} 轮完成",
        )
        time.sleep(max(report_poll, 1))
    detail = (
        f"等待 ZTP 第 {expected_round} 轮完成超时（{completion_timeout}s）；"
        f"最新轮次={(last_state or {}).get('ztp_round', '无')}，"
        f"进度={(last_state or {}).get('progress', 0)}%，"
        f"状态={(last_state or {}).get('overall', '无报告')}"
    )
    write_device_status(
        hostname, "failed", scope=scope, started_at=started,
        command_finished_at=command_finished, finished_at=timestamp(),
        baseline_round=baseline_round, expected_round=expected_round,
        operation_id=operation_id, trigger_id=trigger_id,
        trigger_source=trigger_source,
        operation=operation, effective_operation=operation,
        requested_operation=requested_operation or operation,
        reason=detail,
    )
    print(f"[{timestamp()}] [FAIL] {hostname}: {detail}", file=sys.stderr, flush=True)
    return False


def execute_preview(
    hostname, scope, trigger_timeout, requested_operation,
    operation_id, trigger_id,
):
    """Run the read-only SSH/release/diff preflight for a GUI request."""
    started = timestamp()
    script_operation = (
        "reset" if requested_operation == "reset"
        else "renew" if requested_operation == "renew" else "ztp"
    )
    write_device_status(
        hostname, "previewing", scope=scope, started_at=started,
        operation_id=operation_id, trigger_id=trigger_id,
        requested_operation=requested_operation, operation=script_operation,
        phase="preview", message="正在采集当前配置并生成差异预览",
    )
    command = command_for(
        hostname, scope, script_operation, operation_id, trigger_id,
        preflight_only=True,
    )
    print(f"[{timestamp()}] [PREVIEW] {' '.join(command)}", flush=True)
    try:
        result = subprocess.run(
            command, cwd=HTTP_ROOT, text=True, capture_output=True,
            stdin=subprocess.DEVNULL, timeout=trigger_timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        write_device_status(
            hostname, "failed", scope=scope, started_at=started,
            finished_at=timestamp(), operation_id=operation_id,
            trigger_id=trigger_id, requested_operation=requested_operation,
            operation=script_operation, phase="preview",
            reason=f"预检超时（{trigger_timeout}s）",
        )
        return
    if result.stdout:
        print(result.stdout, end="" if result.stdout.endswith("\n") else "\n", flush=True)
    if result.stderr:
        print(
            result.stderr, end="" if result.stderr.endswith("\n") else "\n",
            file=sys.stderr, flush=True,
        )
    detail = (result.stderr.strip() or result.stdout.strip() or "no detail")[-4000:]
    if result.returncode:
        write_device_status(
            hostname, "failed", scope=scope, started_at=started,
            finished_at=timestamp(), operation_id=operation_id,
            trigger_id=trigger_id, requested_operation=requested_operation,
            operation=script_operation, phase="preview", reason=detail,
        )
        return
    preview = preview_result(operation_id, trigger_id, hostname)
    if not preview:
        write_device_status(
            hostname, "failed", scope=scope, started_at=started,
            finished_at=timestamp(), operation_id=operation_id,
            trigger_id=trigger_id, requested_operation=requested_operation,
            operation=script_operation, phase="preview",
            reason="预检命令成功，但未找到与本次 ID 完全匹配的 preview_ready 证据",
        )
        return
    ready_at = timestamp()
    write_device_status(
        hostname, "preview_ready", scope=scope, started_at=started,
        preview_ready_at=ready_at, operation_id=operation_id,
        trigger_id=trigger_id, requested_operation=requested_operation,
        operation=preview["effective_operation"],
        effective_operation=preview["effective_operation"],
        trigger_source=preview["trigger_source"], phase="preview",
        transport_ip=preview["transport_ip"], interface=preview["interface"],
        expected_yaml=preview["expected_yaml"],
        configuration_matches=preview["configuration_matches"],
        payload_matches_latest=preview["payload_matches_latest"],
        fallback_semantic_matches=preview["fallback_semantic_matches"],
        runtime_matches_latest=preview["runtime_matches_latest"],
        comparison_source=preview["comparison_source"],
        comparison_reason=preview["comparison_reason"],
        preview_fingerprint=preview["preview_fingerprint"],
        diff_summary=preview["diff_summary"],
        evidence_dir=preview["evidence_dir"],
        message="预检完成，等待用户确认",
    )
    print(
        f"[{ready_at}] [PREVIEW_READY] {hostname} "
        f"operation_id={operation_id} trigger_id={trigger_id}",
        flush=True,
    )


def execute(
    hostname, scope, trigger_timeout, completion_timeout, report_poll,
    operation="ztp", operation_id="", trigger_id="", requested_operation="",
    preview_fingerprint=None,
):
    requested_operation = requested_operation or operation
    started = timestamp()
    baseline_state = latest_device_state(hostname)
    baseline_round = 0 if operation == "reset" else int((baseline_state or {}).get("ztp_round") or 0)
    trigger_source = "manual_reset_web" if operation == "reset" else "manual_web"
    expected_round = 1 if operation == "reset" else baseline_round + 1
    write_device_status(
        hostname, "running", scope=scope, started_at=started,
        baseline_round=baseline_round, expected_round=expected_round,
        current_round=baseline_round, progress=0,
        operation_id=operation_id, trigger_id=trigger_id,
        trigger_source=trigger_source, operation=operation,
        requested_operation=requested_operation,
        message="正在向设备提交手工重置" if operation == "reset" else "正在向设备提交手工 ZTP",
    )
    command = command_for(
        hostname, scope, operation, operation_id, trigger_id,
        preview_fingerprint=preview_fingerprint,
    )
    print(f"[{timestamp()}] [RUN] {' '.join(command)}", flush=True)
    try:
        result = subprocess.run(
            command, cwd=HTTP_ROOT, text=True, capture_output=True,
            stdin=subprocess.DEVNULL, timeout=trigger_timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        write_device_status(
            hostname, "failed", scope=scope, started_at=started,
            finished_at=timestamp(), baseline_round=baseline_round,
            expected_round=expected_round,
            operation_id=operation_id, trigger_id=trigger_id,
            trigger_source=trigger_source, operation=operation,
            requested_operation=requested_operation,
            reason=f"提交{'重置' if operation == 'reset' else ' ZTP'}命令超时（{trigger_timeout}s）",
        )
        return
    if result.stdout:
        print(result.stdout, end="" if result.stdout.endswith("\n") else "\n", flush=True)
    if result.stderr:
        print(result.stderr, end="" if result.stderr.endswith("\n") else "\n", file=sys.stderr, flush=True)
    detail = (result.stderr.strip() or result.stdout.strip() or "no detail")[-2000:]
    if result.returncode:
        if needs_helper_hint(detail):
            detail += (" | Cumulus 尚未安装角色专属受限 helper；请先在 CLI 交互完成一次触发")
        write_device_status(
            hostname, "failed", scope=scope, started_at=started,
            finished_at=timestamp(), baseline_round=baseline_round,
            expected_round=expected_round,
            operation_id=operation_id, trigger_id=trigger_id,
            trigger_source=trigger_source, operation=operation,
            requested_operation=requested_operation, reason=detail,
        )
        return
    accepted = accepted_result(trigger_id)
    if not accepted or accepted.get("state") != "triggered":
        detail = (
            f"远程命令返回成功，但未找到本次 trigger_id={trigger_id} "
            "的持久化接受报告"
        )
        write_device_status(
            hostname, "failed", scope=scope, started_at=started,
            finished_at=timestamp(), baseline_round=baseline_round,
            expected_round=expected_round, operation_id=operation_id,
            trigger_id=trigger_id, trigger_source=trigger_source,
            operation=operation, requested_operation=requested_operation, reason=detail,
        )
        return
    effective = str(
        accepted.get("effective_operation") or accepted.get("operation") or operation
    )
    effective_source = str(accepted.get("trigger_source") or trigger_source)
    effective_baseline = 0 if effective == "reset" else int(
        (baseline_state or {}).get("ztp_round") or 0
    )
    wait_for_completion(
        hostname, scope, effective_baseline, started, timestamp(),
        completion_timeout, report_poll, operation_id, effective_source,
        effective, trigger_id, requested_operation,
    )


def execute_time_sync(hostname, scope, timeout, operation_id, trigger_id):
    """Run one fixed-helper clock sync and persist its independent recheck."""
    started = timestamp()
    write_device_status(
        hostname, "time_sync_running", scope=scope, started_at=started,
        operation_id=operation_id, trigger_id=trigger_id,
        operation="time-sync", requested_operation="time-sync",
        phase="time_sync", message="正在同步并重新测量交换机时间",
    )
    command = command_for(
        hostname, scope, "time-sync", operation_id, trigger_id,
    )
    print(f"[{timestamp()}] [TIME_SYNC] {' '.join(command)}", flush=True)
    try:
        completed = subprocess.run(
            command, cwd=HTTP_ROOT, text=True, capture_output=True,
            stdin=subprocess.DEVNULL, timeout=max(timeout, 30), check=False,
        )
    except subprocess.TimeoutExpired:
        write_device_status(
            hostname, "failed", scope=scope, started_at=started,
            finished_at=timestamp(), operation_id=operation_id,
            trigger_id=trigger_id, operation="time-sync",
            requested_operation="time-sync", phase="time_sync",
            reason=f"时间同步超时（{max(timeout, 30)}s）",
        )
        return
    marker_text = "[TIME_SYNC_RESULT] "
    result_payload = {}
    for line in completed.stdout.splitlines():
        if not line.startswith(marker_text):
            continue
        try:
            candidate = json.loads(line[len(marker_text):])
        except json.JSONDecodeError:
            candidate = {}
        if isinstance(candidate, dict):
            result_payload = candidate
    offset_value = result_payload.get("offset_seconds")
    uncertainty_value = result_payload.get("uncertainty_seconds")
    numeric_measurement = (
        isinstance(offset_value, (int, float))
        and not isinstance(offset_value, bool)
        and isinstance(uncertainty_value, (int, float))
        and not isinstance(uncertainty_value, bool)
    )
    measurement_proves_threshold = bool(
        numeric_measurement
        and math.isfinite(float(offset_value))
        and math.isfinite(float(uncertainty_value))
        and float(uncertainty_value) >= 0.0
        and abs(float(offset_value)) + float(uncertainty_value) <= 5.0
    )
    if (
        completed.returncode
        or result_payload.get("state") != "success"
        or not measurement_proves_threshold
    ):
        detail = (
            completed.stderr.strip() or completed.stdout.strip()
            or "时间同步命令未返回有效结果"
        )[-4000:]
        if (
            not completed.returncode
            and result_payload.get("state") == "success"
            and not measurement_proves_threshold
        ):
            detail = "时间同步结果无法证明最坏偏移不超过 5 秒"
        write_device_status(
            hostname, "failed", scope=scope, started_at=started,
            finished_at=timestamp(), operation_id=operation_id,
            trigger_id=trigger_id, operation="time-sync",
            requested_operation="time-sync", phase="time_sync", reason=detail,
        )
        return
    write_device_status(
        hostname, "time_sync_success", scope=scope, started_at=started,
        finished_at=timestamp(), operation_id=operation_id,
        trigger_id=trigger_id, operation="time-sync",
        requested_operation="time-sync", phase="time_sync",
        offset_seconds=offset_value,
        uncertainty_seconds=uncertainty_value,
        transport_ip=str(result_payload.get("transport_ip") or ""),
        interface=str(result_payload.get("interface") or ""),
        message="时间同步 helper 已执行，且独立 SSH 复测通过",
    )


def parser():
    result = argparse.ArgumentParser(description="Concurrent per-device manual ZTP GUI worker")
    result.add_argument("--scope", choices=("air", "prod"), required=True)
    result.add_argument("--poll", type=int, default=2)
    result.add_argument("--timeout", type=int, default=1200, help="提交远端 ZTP 命令的超时秒数")
    result.add_argument("--completion-timeout", type=int, default=3600, help="等待下一轮 ZTP 完成的超时秒数")
    result.add_argument("--report-poll", type=int, default=5)
    result.add_argument("--max-workers", type=int, default=8, help="并行手工 ZTP 设备上限")
    return result


def main():
    args = parser().parse_args()
    STATUS_DIR.mkdir(parents=True, exist_ok=True)
    status = initialize_status(args.scope)
    active = {}
    executor = ThreadPoolExecutor(max_workers=max(1, args.max_workers))
    try:
        for hostname, device_status in status.get("devices", {}).items():
            if device_status.get("state") in {
                "preview_queued", "previewing", "confirm_queued",
                "time_sync_queued", "time_sync_running",
            }:
                write_device_status(
                    hostname, "failed", scope=args.scope,
                    started_at=str(device_status.get("started_at") or ""),
                    finished_at=timestamp(),
                    operation_id=str(device_status.get("operation_id") or ""),
                    trigger_id=str(device_status.get("trigger_id") or ""),
                    requested_operation=str(
                        device_status.get("requested_operation") or ""
                    ),
                    phase=str(device_status.get("phase") or "preview"),
                    reason="worker 重启中断了未完成的预检/确认请求；请重新预检",
                )
                continue
            if device_status.get("state") not in {"running", "ztp_running"}:
                continue
            if not device_status.get("operation_id") or not device_status.get("trigger_id"):
                write_device_status(
                    hostname, "failed", scope=args.scope,
                    started_at=str(device_status.get("started_at") or ""),
                    finished_at=timestamp(),
                    reason="worker 重启时缺少 operation_id/trigger_id，拒绝用旧报告恢复",
                )
                continue
            baseline_round = int(device_status.get("baseline_round") or 0)
            started = str(device_status.get("started_at") or timestamp())
            print(f"[{timestamp()}] [RECOVER] {hostname} after round {baseline_round}", flush=True)
            active[hostname.casefold()] = executor.submit(
                wait_for_completion, hostname, args.scope, baseline_round, started,
                str(device_status.get("command_finished_at") or timestamp()),
                max(args.completion_timeout, 60), max(args.report_poll, 1),
                str(device_status.get("operation_id") or ""),
                str(device_status.get("trigger_source") or "manual_web"),
                str(device_status.get("operation") or "ztp"),
                str(device_status.get("trigger_id") or ""),
                str(device_status.get("requested_operation") or ""),
            )
        while True:
            active = {key: future for key, future in active.items() if not future.done()}
            reconcile_failed_operations(args.scope, active)
            for key, operation in latest_cli_operations().items():
                if (args.scope == "air") != (operation.get("type") == "air"):
                    continue
                if key in active:
                    continue
                hostname = operation["hostname"]
                statuses = read_status(args.scope).get("devices", {})
                current = next((
                    value for name, value in statuses.items()
                    if name.casefold() == key
                ), {})
                current_started = str(
                    current.get("started_at") or current.get("requested_at") or ""
                )
                if current_started and _iso_time(current_started) > _iso_time(operation["started_at"]):
                    continue
                operation_id = operation["operation_id"]
                trigger_id = operation["trigger_id"]
                same_operation = current.get("operation_id") == operation_id
                if operation["state"] == "running":
                    if not same_operation or current.get("state") != "running":
                        baseline_state = latest_device_state(hostname)
                        is_reset = operation.get("operation") == "reset"
                        baseline_round = 0 if is_reset else int((baseline_state or {}).get("ztp_round") or 0)
                        write_device_status(
                            hostname, "running", scope=args.scope,
                            started_at=operation["started_at"],
                            baseline_round=baseline_round,
                            expected_round=1 if is_reset else baseline_round + 1,
                            current_round=baseline_round, progress=0,
                            operation_id=operation_id, trigger_id=trigger_id,
                            trigger_source=operation["trigger_source"],
                            operation=operation["operation"],
                            effective_operation=operation["operation"],
                            requested_operation=operation.get("requested_operation") or operation["operation"],
                            message="命令行正在提交手工重置" if is_reset else "命令行正在提交手工 ZTP",
                        )
                    continue
                if operation["state"] == "failed":
                    if not same_operation or current.get("state") != "failed":
                        baseline_state = latest_device_state(hostname)
                        is_reset = operation.get("operation") == "reset"
                        baseline_round = 0 if is_reset else int((baseline_state or {}).get("ztp_round") or 0)
                        write_device_status(
                            hostname, "failed", scope=args.scope,
                            started_at=operation["started_at"],
                            finished_at=operation["updated_at"],
                            baseline_round=baseline_round,
                            expected_round=1 if is_reset else baseline_round + 1,
                            operation_id=operation_id, trigger_id=trigger_id,
                            trigger_source=operation["trigger_source"],
                            operation=operation["operation"],
                            effective_operation=operation["operation"],
                            requested_operation=operation.get("requested_operation") or operation["operation"],
                            reason=operation["reason"] or ("命令行手工重置失败" if is_reset else "命令行手工 ZTP 触发失败"),
                        )
                    continue
                if operation["state"] != "triggered":
                    continue
                if same_operation and current.get("state") in {"success", "failed", "ztp_running"}:
                    continue
                latest = latest_device_state(hostname)
                current_round = int((latest or {}).get("ztp_round") or 0)
                # A manual cycle is accepted at successful remote-command
                # return (updated_at/finished_at), not process start. Match
                # the durable trigger id first so a mid-command monitor
                # snapshot cannot make this worker wait for round N+2.
                marker_matches = operation_marker_matches(latest, operation)
                is_reset = operation.get("operation") == "reset"
                baseline_round = 0 if is_reset else (
                    max(0, current_round - 1) if marker_matches else current_round
                )
                active[key] = executor.submit(
                    wait_for_completion, hostname, args.scope, baseline_round,
                    operation["started_at"], operation["updated_at"],
                    max(args.completion_timeout, 60), max(args.report_poll, 1),
                    operation_id, operation["trigger_source"], operation["operation"],
                    trigger_id, operation.get("requested_operation") or operation["operation"],
                )
            # Leave same-device requests in the durable queue until its future
            # is actually done.  In particular, never discard a confirm that
            # races with the final instructions of execute_preview().
            for request in pop_requests(active):
                hostname = str(request["hostname"])
                action = str(request.get("action") or "trigger")
                phase = str(request.get("phase") or "preview")
                operation = (
                    "reset" if action == "reset"
                    else "renew" if action == "renew"
                    else "time-sync" if action == "time-sync"
                    else "ztp"
                )
                trigger_source = "manual_reset_web" if operation == "reset" else "manual_web"
                requested_at = str(request.get("requested_at") or timestamp())
                legacy_time = re.sub(r"[^A-Za-z0-9:._-]", "_", requested_at)
                operation_id = str(
                    request.get("operation_id")
                    or f"legacy-web:{legacy_time}:{hostname}"
                )
                trigger_id = str(
                    request.get("trigger_id") or f"{operation_id}:{hostname}"
                )
                key = hostname.casefold()
                statuses = read_status(args.scope).get("devices", {})
                current = next((
                    value for name, value in statuses.items()
                    if name.casefold() == key
                ), {})
                requested_operation = (
                    "reset" if operation == "reset"
                    else "renew" if operation == "renew"
                    else "time-sync" if operation == "time-sync" else "trigger"
                )
                if phase == "time_sync":
                    if current.get("state") in ACTIVE_REQUEST_STATES:
                        continue
                    write_device_status(
                        hostname, "time_sync_queued", scope=args.scope,
                        requested_at=requested_at, operation_id=operation_id,
                        trigger_id=trigger_id, operation="time-sync",
                        requested_operation="time-sync", phase="time_sync",
                        message="时间同步已排队",
                    )
                    active[key] = executor.submit(
                        execute_time_sync, hostname, args.scope,
                        min(max(args.timeout, 30), 300), operation_id, trigger_id,
                    )
                    continue
                if phase == "cancel":
                    if not cancel_preview(
                        hostname, args.scope, current, operation_id, trigger_id,
                        requested_operation,
                    ):
                        print(
                            f"[{timestamp()}] [WARN] ignored stale preview cancel: "
                            f"{hostname} operation_id={operation_id}",
                            file=sys.stderr, flush=True,
                        )
                    continue
                if phase == "preview":
                    if current.get("state") in ACTIVE_REQUEST_STATES:
                        continue
                    write_device_status(
                        hostname, "preview_queued", scope=args.scope,
                        requested_at=requested_at,
                        operation_id=operation_id, trigger_id=trigger_id,
                        trigger_source=trigger_source, operation=operation,
                        requested_operation=requested_operation, phase="preview",
                        message="预检已排队",
                    )
                    active[key] = executor.submit(
                        execute_preview, hostname, args.scope,
                        max(args.timeout, 60), requested_operation,
                        operation_id, trigger_id,
                    )
                    continue
                if phase != "confirm":
                    write_device_status(
                        hostname, "failed", scope=args.scope,
                        operation_id=operation_id, trigger_id=trigger_id,
                        requested_operation=requested_operation, phase=phase,
                        reason=f"不支持的请求阶段: {phase}",
                    )
                    continue
                preview_matches = (
                    current.get("state") == "preview_ready"
                    and str(current.get("operation_id") or "") == operation_id
                    and str(current.get("trigger_id") or "") == trigger_id
                    and str(current.get("requested_operation") or "")
                    == requested_operation
                )
                if not preview_matches:
                    write_device_status(
                        hostname, "failed", scope=args.scope,
                        requested_at=requested_at,
                        operation_id=operation_id, trigger_id=trigger_id,
                        requested_operation=requested_operation, phase="confirm",
                        reason="confirm 与当前 preview_ready 状态或精确 ID 不匹配，拒绝执行",
                    )
                    continue
                preview_fingerprint = (
                    current.get("preview_fingerprint")
                    if isinstance(current.get("preview_fingerprint"), dict) else {}
                )
                fingerprint_keys = (
                    "current_sha256", "expected_sha256", "published_release_dir",
                    "effective_operation", "transport_ip", "interface",
                )
                if not all(
                    str(preview_fingerprint.get(field) or "")
                    for field in fingerprint_keys
                ):
                    write_device_status(
                        hostname, "failed", scope=args.scope,
                        requested_at=requested_at,
                        operation_id=operation_id, trigger_id=trigger_id,
                        requested_operation=requested_operation, phase="confirm",
                        reason=(
                            "preview_ready 缺少完整配置/发布指纹，"
                            "拒绝执行；请重新预检"
                        ),
                    )
                    continue
                effective_operation = str(
                    current.get("effective_operation")
                    or current.get("operation") or operation
                )
                if effective_operation not in {"ztp", "reset"}:
                    write_device_status(
                        hostname, "failed", scope=args.scope,
                        operation_id=operation_id, trigger_id=trigger_id,
                        requested_operation=requested_operation, phase="confirm",
                        reason="preview_ready 缺少有效的实际操作类型",
                    )
                    continue
                write_device_status(
                    hostname, "confirm_queued", scope=args.scope,
                    requested_at=requested_at,
                    preview_ready_at=str(current.get("preview_ready_at") or ""),
                    operation_id=operation_id, trigger_id=trigger_id,
                    trigger_source=(
                        "manual_reset_web"
                        if effective_operation == "reset" else "manual_web"
                    ),
                    operation=effective_operation,
                    effective_operation=effective_operation,
                    requested_operation=requested_operation, phase="confirm",
                    diff_summary=(
                        current.get("diff_summary")
                        if isinstance(current.get("diff_summary"), dict) else {}
                    ),
                    preview_fingerprint=preview_fingerprint,
                    message="确认已验证，实际操作已排队",
                )
                active[key] = executor.submit(
                    execute, hostname, args.scope, max(args.timeout, 60),
                    max(args.completion_timeout, 60), max(args.report_poll, 1),
                    effective_operation, operation_id, trigger_id,
                    requested_operation,
                    preview_fingerprint,
                )
            time.sleep(max(args.poll, 1))
    except KeyboardInterrupt:
        return 130
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
        try:
            if int(PID_FILE.read_text().strip()) == os.getpid():
                PID_FILE.unlink(missing_ok=True)
        except (OSError, ValueError):
            pass


if __name__ == "__main__":
    raise SystemExit(main())
