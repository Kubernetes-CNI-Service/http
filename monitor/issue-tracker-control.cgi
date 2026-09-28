#!/usr/bin/env python3
"""REQ7 local-only manual CGI; no credential, row or workbook authority.

Deployment does not expose this route until the protected root worker and
Apache/native/Docker lifecycle have an independent real-environment proof.
"""

import json
import os
import socket
import stat
import sys
from pathlib import Path

# Native and Docker Apache run the CGI from /usr/lib/cgi-bin, not from the
# application root. This path is fixed deployment configuration, never a CGI
# or browser-supplied module path. The route itself is not yet installed.
sys.path.insert(0, "/var/www/html")

from monitor.issue_tracker_manual_channel import (
    ManualChannelHold, validate_ingress,
)


SOCKET_PATH = Path("/run/http-ztp/issue-tracker-manual.sock")


def send_to_worker(request):
    """Use one root-owned socket path; absence never creates a fallback write."""
    parent = SOCKET_PATH.parent
    parent_meta = os.lstat(parent)
    endpoint_meta = os.lstat(SOCKET_PATH)
    if (not stat.S_ISDIR(parent_meta.st_mode) or parent_meta.st_uid != 0
            or stat.S_IMODE(parent_meta.st_mode) != 0o750
            or not stat.S_ISSOCK(endpoint_meta.st_mode)
            or endpoint_meta.st_uid != 0 or endpoint_meta.st_nlink != 1
            or stat.S_IMODE(endpoint_meta.st_mode) != 0o660):
        raise ManualChannelHold("manual root worker endpoint is unsafe")
    payload = json.dumps(request, sort_keys=True,
                         separators=(",", ":")).encode("utf-8") + b"\n"
    if len(payload) > 512:
        raise ManualChannelHold("manual request is oversized")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(2)
        client.connect(str(SOCKET_PATH))
        client.sendall(payload)
        data = client.recv(8193)
    if not data or len(data) > 8192:
        raise ManualChannelHold("manual root worker response is invalid")
    result = json.loads(data.decode("utf-8"))
    if type(result) is not dict:
        raise ManualChannelHold("manual root worker response is invalid")
    return result


def handle(environ, body, *, submit=send_to_worker):
    try:
        request = validate_ingress(environ, body)
    except ManualChannelHold:
        return "403 Forbidden", {"error": "manual_request_forbidden"}
    try:
        result = submit(request)
    except (OSError, TimeoutError, ValueError, UnicodeError, json.JSONDecodeError):
        return "503 Service Unavailable", {"error": "manual_worker_unavailable"}
    if type(result) is not dict:
        return "503 Service Unavailable", {"error": "manual_worker_unavailable"}
    if result.get("error") == "manual_hold":
        return "409 Conflict", {"error": "manual_hold"}
    if "error" in result:
        return "503 Service Unavailable", {"error": "manual_worker_unavailable"}
    return "200 OK", result


def main():
    try:
        length = int(os.environ.get("CONTENT_LENGTH", ""))
    except ValueError:
        length = 0
    body = sys.stdin.buffer.read(min(max(length, 0), 513))
    status, payload = handle(dict(os.environ), body)
    content = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    print(f"Status: {status}\r")
    print("Content-Type: application/json; charset=utf-8\r")
    print("Cache-Control: no-store\r")
    print(f"Content-Length: {len(content)}\r")
    print("\r")
    sys.stdout.flush()
    sys.stdout.buffer.write(content)


if __name__ == "__main__":
    main()
