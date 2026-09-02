#!/usr/bin/env python3
"""Restricted CGI endpoint for independent exact-hostname ZTP requests."""

from datetime import datetime
import errno
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid
from urllib.parse import parse_qs, urlsplit


STATUS_DIR = Path("/var/www/html/monitor/status")
REQUEST_FILE = STATUS_DIR / "manual-ztp.request.json"
STATUS_FILE = STATUS_DIR / "manual-ztp.status.json"
PID_FILE = STATUS_DIR / "manual-ztp.pid"
SAFE_HOSTNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
SAFE_OPERATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._-]{0,511}$")
BUSY_STATES = {
    "queued", "running", "ztp_running", "time_sync_queued", "time_sync_running",
}
PREVIEW_BUSY_STATES = {
    "preview_queued", "previewing", "confirm_queued", "cancel_queued",
}
ACTIVE_STATES = BUSY_STATES | PREVIEW_BUSY_STATES


def timestamp():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def post_control_guard():
    """Enforce browser same-origin and optional upstream authentication."""
    host = os.environ.get("HTTP_HOST", "").strip().casefold()
    origin = os.environ.get("HTTP_ORIGIN", "").strip()
    fetch_site = os.environ.get("HTTP_SEC_FETCH_SITE", "").strip().casefold()
    require_auth = os.environ.get("CONTROL_REQUIRE_AUTH", "").strip().casefold() \
        in {"1", "true", "yes", "on"}
    try:
        parsed = urlsplit(origin)
    except ValueError:
        return False, "invalid Origin header"
    if (
        not host or not origin or parsed.scheme not in {"http", "https"}
        or parsed.netloc.casefold() != host
    ):
        return False, "same-origin POST is required"
    if fetch_site and fetch_site != "same-origin":
        return False, "cross-site control request rejected"
    if require_auth and not os.environ.get("REMOTE_USER", "").strip():
        return False, "authenticated control user is required"
    return True, ""


def process_state():
    try:
        pid = int(PID_FILE.read_text(encoding="utf-8").strip())
        os.kill(pid, 0)
        return True, pid
    except PermissionError:
        return True, locals().get("pid")
    except (OSError, ValueError):
        return False, None


def read_json(path, default):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else default
    except (OSError, json.JSONDecodeError):
        return default


def normalize_status(value):
    if isinstance(value.get("devices"), dict):
        return value
    hostname = str(value.get("hostname") or "")
    devices = {}
    if SAFE_HOSTNAME.fullmatch(hostname) and value.get("state"):
        devices[hostname] = dict(value)
    return {
        "scope": str(value.get("scope") or ""),
        "updated_at": str(value.get("updated_at") or ""),
        "devices": devices,
    }


def _decode_queue(raw):
    try:
        value = json.loads(raw.decode("utf-8") or "{}")
    except (UnicodeError, json.JSONDecodeError):
        return []
    if not isinstance(value, dict):
        return []
    requests = value.get("requests")
    if isinstance(requests, list):
        return [item for item in requests if isinstance(item, dict)]
    if value.get("action") in {"trigger", "reset", "renew", "time-sync"} and value.get("hostname"):
        return [value]
    return []


def read_queue():
    try:
        flags = (
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(REQUEST_FILE, flags)
    except OSError:
        return []
    try:
        fcntl.flock(descriptor, fcntl.LOCK_SH)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > 1024 * 1024
        ):
            return []
        return _decode_queue(os.read(descriptor, 1024 * 1024))
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def enqueue_request(
    hostname, action="trigger", operation_id="", trigger_id="", phase="preview",
):
    flags = (
        os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(REQUEST_FILE, flags)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise OSError(errno.EINVAL, "request target is not a regular file")
        if metadata.st_size > 1024 * 1024:
            raise OSError(errno.EFBIG, "manual ZTP request queue is too large")
        os.lseek(descriptor, 0, os.SEEK_SET)
        requests = _decode_queue(os.read(descriptor, 1024 * 1024))
        if any(
            str(item.get("hostname") or "").casefold() == hostname.casefold()
            for item in requests
        ):
            return False
        if len(requests) >= 256:
            raise OSError(errno.ENOSPC, "manual ZTP request queue is full")
        operation_id = operation_id or f"web:{uuid.uuid4().hex}"
        trigger_id = trigger_id or f"{operation_id}:{hostname}"
        requests.append({
            "action": action, "hostname": hostname,
            "phase": phase,
            "requested_at": timestamp(),
            "operation_id": operation_id, "trigger_id": trigger_id,
        })
        payload = json.dumps({"requests": requests}, ensure_ascii=False) + "\n"
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.ftruncate(descriptor, 0)
        os.write(descriptor, payload.encode("utf-8"))
        os.fsync(descriptor)
        return True
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def status_with_queue():
    status = normalize_status(read_json(STATUS_FILE, {}))
    devices = dict(status.get("devices") or {})
    for request in read_queue():
        hostname = str(request.get("hostname") or "")
        if not SAFE_HOSTNAME.fullmatch(hostname):
            continue
        previous = devices.get(hostname, {})
        if previous.get("state") not in ACTIVE_STATES:
            phase = str(request.get("phase") or "preview")
            queued_state = {
                "confirm": "confirm_queued", "cancel": "cancel_queued",
                "time_sync": "time_sync_queued",
            }.get(phase, "preview_queued")
            devices[hostname] = {
                **(previous if phase in {"confirm", "cancel"} else {}),
                "state": queued_state,
                "phase": phase, "hostname": hostname,
                "requested_at": str(request.get("requested_at") or ""),
                "requested_operation": str(request.get("action") or "trigger"),
                "operation": (
                    "reset" if request.get("action") == "reset"
                    else "time-sync" if request.get("action") == "time-sync"
                    else "ztp"
                ),
                "operation_id": str(request.get("operation_id") or ""),
                "trigger_id": str(request.get("trigger_id") or ""),
            }
    status["devices"] = devices
    return status


def respond(payload, status="200 OK"):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    print(f"Status: {status}\r")
    print("Content-Type: application/json; charset=utf-8\r")
    print("Cache-Control: no-store\r")
    print(f"Content-Length: {len(body)}\r")
    print("\r")
    sys.stdout.flush()
    sys.stdout.buffer.write(body)


def exact_preview_matches(device_status, operation_id, trigger_id):
    return bool(
        isinstance(device_status, dict)
        and device_status.get("state") == "preview_ready"
        and str(device_status.get("operation_id") or "") == operation_id
        and str(device_status.get("trigger_id") or "") == trigger_id
    )


def main():
    method = os.environ.get("REQUEST_METHOD", "GET").upper()
    alive, pid = process_state()
    current = status_with_queue()
    if method == "GET":
        respond({**current, "process_alive": alive})
        return
    if method != "POST":
        respond({"error": "method not allowed"}, "405 Method Not Allowed")
        return
    if os.environ.get("HTTP_X_REQUESTED_WITH") != "ManualZTPControl":
        respond({"error": "missing control request header"}, "403 Forbidden")
        return
    allowed, reason = post_control_guard()
    if not allowed:
        respond({"error": reason}, "403 Forbidden")
        return
    try:
        length = max(0, min(int(os.environ.get("CONTENT_LENGTH", "0")), 1024))
    except ValueError:
        length = 0
    form = parse_qs(sys.stdin.read(length))
    action = form.get("action", [""])[0].strip().casefold()
    hostname = form.get("hostname", [""])[0].strip()
    if not SAFE_HOSTNAME.fullmatch(hostname):
        respond({"error": "hostname must be valid"}, "400 Bad Request")
        return
    if not alive:
        respond({"error": "manual ZTP worker is not running", "state": "stopped"}, "409 Conflict")
        return
    device_status = next((
        value for name, value in current.get("devices", {}).items()
        if str(name).casefold() == hostname.casefold() and isinstance(value, dict)
    ), {})
    if action in {"confirm", "cancel"}:
        operation_id = form.get("operation_id", [""])[0].strip()
        trigger_id = form.get("trigger_id", [""])[0].strip()
        if not (
            SAFE_OPERATION_ID.fullmatch(operation_id)
            and SAFE_OPERATION_ID.fullmatch(trigger_id)
        ):
            respond({
                "error": f"{action} requires valid operation_id and trigger_id"
            }, "400 Bad Request")
            return
        if not exact_preview_matches(device_status, operation_id, trigger_id):
            respond({
                **current, "process_alive": True,
                "error": "preview-ready state or operation identifiers do not match",
            }, "409 Conflict")
            return
        operation = str(device_status.get("requested_operation") or "")
        if operation not in {"trigger", "reset", "renew"}:
            respond({"error": "preview state has invalid operation"}, "409 Conflict")
            return
        if action == "cancel":
            phase = "cancel"
        else:
            phase = "confirm"
    if action == "confirm":
        preview_fingerprint = (
            device_status.get("preview_fingerprint")
            if isinstance(device_status.get("preview_fingerprint"), dict) else {}
        )
        if not all(
            str(preview_fingerprint.get(field) or "")
            for field in (
                "current_sha256", "expected_sha256", "published_release_dir",
                "effective_operation", "transport_ip", "interface",
            )
        ):
            respond({
                **current, "process_alive": True,
                "error": "preview-ready state has no complete server-side fingerprint",
            }, "409 Conflict")
            return
    elif action == "cancel":
        # Exact preview identity was validated above.  The worker performs the
        # state transition so CGI and worker never race while writing status.
        pass
    elif action == "preview":
        operation = form.get("operation", [""])[0].strip().casefold()
        if operation not in {"trigger", "reset", "renew"}:
            respond({"error": "preview requires operation=trigger/reset/renew"}, "400 Bad Request")
            return
        operation_id = f"web:{uuid.uuid4().hex}"
        trigger_id = f"{operation_id}:{hostname}"
        phase = "preview"
    elif action == "time-sync":
        operation = "time-sync"
        operation_id = f"web:{uuid.uuid4().hex}"
        trigger_id = f"{operation_id}:{hostname}"
        phase = "time_sync"
    elif action in {"trigger", "reset", "renew"}:
        # Compatibility-safe behavior for an older page: the first click now
        # performs preview only and can never mutate a switch.
        operation = action
        operation_id = f"web:{uuid.uuid4().hex}"
        trigger_id = f"{operation_id}:{hostname}"
        phase = "preview"
    else:
        respond({"error": "action must be preview/confirm/cancel/time-sync"}, "400 Bad Request")
        return
    if device_status.get("state") in ACTIVE_STATES:
        respond({
            **current, "process_alive": True,
            "error": f"manual ZTP preview/operation is already active for {hostname}",
        }, "409 Conflict")
        return
    try:
        queued = enqueue_request(
            hostname, operation, operation_id, trigger_id, phase,
        )
    except OSError as exc:
        respond({"error": str(exc)}, "500 Internal Server Error")
        return
    if not queued:
        respond({
            **status_with_queue(), "process_alive": True,
            "error": f"manual ZTP is already queued for {hostname}",
        }, "409 Conflict")
        return
    updated = status_with_queue()
    respond({
        **updated, "process_alive": True,
        "request": {
            "phase": phase, "hostname": hostname,
            "requested_operation": operation,
            "operation_id": operation_id, "trigger_id": trigger_id,
        },
    })


if __name__ == "__main__":
    main()
