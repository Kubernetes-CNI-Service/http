#!/usr/bin/env python3
"""Restricted CGI endpoint for pausing/resuming the persistent ZTP monitor."""

import errno
import fcntl
import json
import os
from pathlib import Path
import stat
import sys
from urllib.parse import parse_qs, urlsplit


STATUS_DIR = Path("/var/www/html/ztp/status")
CONTROL_FILE = STATUS_DIR / "ztp-monitor.control"
PID_FILE = STATUS_DIR / "ztp-monitor.pid"


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


def control_state():
    try:
        value = CONTROL_FILE.read_text(encoding="utf-8").strip()
        if value == "paused":
            return "paused"
        return "running"
    except OSError:
        return "running"


def write_control(value):
    flags = (
        os.O_WRONLY | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(CONTROL_FILE, flags)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise OSError(errno.EINVAL, "control target is not a regular file")
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.ftruncate(descriptor, 0)
        os.write(descriptor, (value + "\n").encode("ascii"))
        os.fsync(descriptor)
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def respond(payload, status="200 OK"):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    print(f"Status: {status}\r")
    print("Content-Type: application/json; charset=utf-8\r")
    print("Cache-Control: no-store\r")
    print(f"Content-Length: {len(body)}\r")
    print("\r")
    sys.stdout.flush()
    sys.stdout.buffer.write(body)


def main():
    method = os.environ.get("REQUEST_METHOD", "GET").upper()
    alive, pid = process_state()
    if method == "GET":
        respond({"state": control_state(), "process_alive": alive})
        return
    if method != "POST":
        respond({"error": "method not allowed"}, "405 Method Not Allowed")
        return
    if os.environ.get("HTTP_X_REQUESTED_WITH") != "ZTPMonitorControl":
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
    action = parse_qs(sys.stdin.read(length)).get("action", [""])[0]
    if action not in {"start", "stop"}:
        respond({"error": "action must be start or stop"}, "400 Bad Request")
        return
    if action == "start" and not alive:
        respond({
            "error": "monitor process is not running; start it with 11-load.py",
            "state": "stopped", "process_alive": False,
        }, "409 Conflict")
        return
    try:
        value = {"start": "running", "stop": "paused"}[action]
        write_control(value)
    except OSError as exc:
        respond({"error": str(exc)}, "500 Internal Server Error")
        return
    respond({
        "state": control_state(), "process_alive": alive,
        "message": {
            "start": "ZTP monitoring resumed",
            "stop": "ZTP monitoring paused",
        }[action],
    })


if __name__ == "__main__":
    main()
