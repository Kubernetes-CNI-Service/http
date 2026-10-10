#!/usr/bin/env python3
"""Restricted CGI endpoint for the independent Switch Status collector."""

import errno
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import math
import re
import socket
import stat
import sys
import time
from datetime import datetime
from urllib.parse import parse_qs


# This CGI is installed as one byte-identical standalone file under
# /usr/lib/cgi-bin.  These four deployment-contract limits therefore remain
# explicit local literals; tests bind them to the shared worker/UI contract.
MIN_CONTINUOUS_INTERVAL_MINUTES = 10
MAX_CONTINUOUS_INTERVAL_MINUTES = 240
MIN_CONTINUOUS_BACKUP_INTERVAL_MINUTES = 60
MAX_CONTINUOUS_BACKUP_INTERVAL_MINUTES = 1440

STATUS_DIR = Path("/var/www/html/monitor/status")
REQUEST_FILE = STATUS_DIR / "switch-collection.request"
STATUS_FILE = STATUS_DIR / "switch-collection.status.json"
PID_FILE = STATUS_DIR / "switch-collection.pid"
YAML_BACKUP_STATUS_FILE = STATUS_DIR / "yaml-backup.status.json"
CONTINUOUS_STATUS_FILE = STATUS_DIR / "continuous-collection.status.json"
CONTINUOUS_BACKUP_STATUS_FILE = STATUS_DIR / "continuous-backup.status.json"
YAML_BACKUP_SOCKET = STATUS_DIR / ".yaml-backup.sock"
MAX_PASSWORD_BYTES = 1024
CONTROL_USERS = frozenset(("nvis", "cumulus"))
CONTROL_SCRIPT_NAMES = frozenset((
    "/monitor/control/switch-collection",
    "/cgi-bin/switch-collection-control",
))


def control_request_guard():
    """Require exact upstream authentication and routing for every request."""
    if os.environ.get("CONTROL_REQUIRE_AUTH") != "1":
        return False, "control authentication is not enforced"
    if os.environ.get("AUTH_TYPE") != "Basic":
        return False, "invalid authentication type"
    if os.environ.get("REMOTE_USER") not in CONTROL_USERS:
        return False, "invalid control user"
    if os.environ.get("PATH_INFO", "") != "":
        return False, "path info is not allowed"
    if os.environ.get("SCRIPT_NAME") not in CONTROL_SCRIPT_NAMES:
        return False, "invalid control route"
    return True, ""


def post_control_guard():
    """Bind POST to the exact Apache HTTP service-IPv4 authority."""
    server_addr = os.environ.get("SERVER_ADDR", "")
    try:
        address = ipaddress.IPv4Address(server_addr)
    except ipaddress.AddressValueError:
        return False, "invalid service address"
    canonical = str(address)
    if (
        server_addr != canonical
        or address.is_unspecified
        or address.is_multicast
        or int(address) == 0xFFFFFFFF
    ):
        return False, "invalid service address"
    expected_port = os.environ.get("CONTROL_SERVICE_PORT", "80")
    if (
        re.fullmatch(r"[1-9][0-9]{0,4}", expected_port) is None
        or int(expected_port) > 65535
        or os.environ.get("SERVER_PORT") != expected_port
    ):
        return False, "invalid service port"
    if os.environ.get("REQUEST_SCHEME") != "http":
        return False, "invalid request scheme"
    https_marker = os.environ.get("HTTPS")
    if https_marker not in {None, "off"}:
        condition = (
            "TLS is enabled" if https_marker.casefold() == "on"
            else "HTTPS indicator is invalid"
        )
        return False, f"{condition}; control POST requires plain HTTP on port {expected_port}"
    host = os.environ.get("HTTP_HOST", "")
    allowed_hosts = (
        {canonical, f"{canonical}:80"}
        if expected_port == "80" else {f"{canonical}:{expected_port}"}
    )
    if host not in allowed_hosts:
        return False, "invalid Host header"
    origin = os.environ.get("HTTP_ORIGIN", "")
    fetch_site = os.environ.get("HTTP_SEC_FETCH_SITE", "").strip().casefold()
    allowed_origins = (
        {f"http://{canonical}", f"http://{canonical}:80"}
        if expected_port == "80"
        else {f"http://{canonical}:{expected_port}"}
    )
    if origin not in allowed_origins:
        return False, "same-origin POST is required"
    if fetch_site and fetch_site != "same-origin":
        return False, "cross-site control request rejected"
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


def collection_status():
    try:
        value = json.loads(STATUS_FILE.read_text(encoding="utf-8"))
        return status_with_remaining(value) if isinstance(value, dict) else {"state": "idle"}
    except (OSError, json.JSONDecodeError):
        return {"state": "idle"}


def issue_tracker_online_status():
    """Fixed bounded last-observation cache; no admission or journal reader."""
    unproved = {'schema_version': 1, 'state': 'unproved', 'updated_at': None,
        'read_only': True, 'mutation_disabled': True}
    parent = descriptor = None
    owned = {}
    named_before_open = {}
    name = 'issue-tracker-online.status.json'
    keys = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
            'st_size', 'st_mtime_ns', 'st_ctime_ns')
    identity = lambda value: tuple(getattr(value, key) for key in keys)
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value: raise ValueError('duplicate diagnostic field')
            value[key] = item
        return value
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        named_parent = STATUS_DIR.lstat()
        parent = os.open(STATUS_DIR, flags | os.O_DIRECTORY)
        named_before_open[parent] = (named_parent.st_dev, named_parent.st_ino)
        directory = os.fstat(parent); owned[parent] = (directory.st_dev, directory.st_ino)
        named_parent = STATUS_DIR.lstat()
        if (not stat.S_ISDIR(named_parent.st_mode)
                or (named_parent.st_dev, named_parent.st_ino) != owned[parent]
                or directory.st_mode & 0o022 or directory.st_uid not in (0, os.geteuid())):
            raise ValueError('untrusted diagnostic directory')
        named_image = os.stat(name, dir_fd=parent, follow_symlinks=False)
        descriptor = os.open(name, flags, dir_fd=parent)
        named_before_open[descriptor] = (named_image.st_dev, named_image.st_ino)
        before = os.fstat(descriptor); owned[descriptor] = (before.st_dev, before.st_ino)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_mode & 0o022 or before.st_uid != directory.st_uid
                or not 1 <= before.st_size <= 4096
                or identity(before) != identity(os.stat(name, dir_fd=parent, follow_symlinks=False))):
            raise ValueError('untrusted diagnostic image')
        raw = os.pread(descriptor, 4097, 0)
        if (len(raw) != before.st_size or identity(os.fstat(descriptor)) != identity(before)
                or identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != identity(before)
                or (STATUS_DIR.lstat().st_dev, STATUS_DIR.lstat().st_ino) != owned[parent]):
            raise ValueError('diagnostic image changed')
        value = json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=pairs)
        if (type(value) is not dict or set(value) != set(unproved)
                or type(value['schema_version']) is not int or value['schema_version'] != 1
                or value['read_only'] is not True or value['mutation_disabled'] is not True
                or type(value['state']) is not str or value['state'] not in (
                    'stalled', 'retry_exhausted', 'conflict', 'historical_applied', 'no_counted_units')
                or type(value['updated_at']) is not str
                or re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}', value['updated_at']) is None):
            raise ValueError('invalid diagnostic shape')
        observed = datetime.fromisoformat(value['updated_at'])
        if observed.tzinfo is None or observed.timestamp() > time.time():
            raise ValueError('invalid observation time')
        return value
    except (OSError, ValueError, UnicodeError, OverflowError):
        return unproved
    finally:
        for fd in (descriptor, parent):
            if fd is not None:
                try:
                    current = os.fstat(fd)
                    # A first fstat fault must not leak the unchanged named object.
                    # A rebound numeric FD is not evidence of ownership: keep it
                    # open unless the independently captured identity still matches.
                    expected = owned.get(fd, named_before_open.get(fd))
                    if expected == (current.st_dev, current.st_ino): os.close(fd)
                except OSError:
                    pass


def yaml_backup_status():
    try:
        value = json.loads(YAML_BACKUP_STATUS_FILE.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            return {"state": "idle"}
    except (OSError, json.JSONDecodeError):
        return {"state": "idle"}
    return status_with_remaining(value)


def status_with_remaining(value):
    """Derive a bounded live countdown from one worker-owned status payload."""
    value = dict(value)
    next_epoch = value.get("next_allowed_epoch")
    if isinstance(next_epoch, (int, float)) and not isinstance(next_epoch, bool):
        try:
            finite_epoch = float(next_epoch)
        except (OverflowError, TypeError, ValueError):
            finite_epoch = float("nan")
        if math.isfinite(finite_epoch):
            value["remaining_seconds"] = max(
                0, int(math.ceil(finite_epoch - time.time()))
            )
    return value


def _continuous_status(path):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {
            "state": "stopped", "enabled": False,
        }
    except (OSError, json.JSONDecodeError):
        return {"state": "stopped", "enabled": False}


def continuous_collection_status():
    return _continuous_status(CONTINUOUS_STATUS_FILE)


def continuous_backup_status():
    return _continuous_status(CONTINUOUS_BACKUP_STATUS_FILE)


def continuous_status():
    """Compatibility alias for cached pages that still request `view=continuous`."""
    return continuous_collection_status()


def validate_yaml_backup_password(value):
    if not isinstance(value, str):
        raise ValueError("password must be text")
    encoded = value.encode("utf-8")
    if len(encoded) > MAX_PASSWORD_BYTES:
        raise ValueError("password exceeds 1024 bytes")
    if any(marker in value for marker in ("\x00", "\r", "\n")):
        raise ValueError("password contains a forbidden control character")
    return value


def validate_continuous_interval(value, action):
    if not isinstance(value, str) or not value.isascii() or not value.isdigit():
        raise ValueError("interval_minutes must be a decimal integer")
    interval = int(value)
    if action == "continuous_collection_start":
        minimum = MIN_CONTINUOUS_INTERVAL_MINUTES
        maximum = MAX_CONTINUOUS_INTERVAL_MINUTES
    elif action == "continuous_backup_start":
        minimum = MIN_CONTINUOUS_BACKUP_INTERVAL_MINUTES
        maximum = MAX_CONTINUOUS_BACKUP_INTERVAL_MINUTES
    else:
        raise ValueError("unsupported continuous interval action")
    if not minimum <= interval <= maximum:
        raise ValueError(
            "interval_minutes must be between "
            f"{minimum} and {maximum}"
        )
    return interval


def is_cooling_down(value):
    """Accept only a finite positive numeric countdown from worker status."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(float(value)) and float(value) > 0
    except (OverflowError, TypeError, ValueError):
        return False


def send_memory_request(message):
    payload = json.dumps(
        message, ensure_ascii=False, separators=(",", ":"),
    ).encode("utf-8")
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as endpoint:
        sent = endpoint.sendto(payload, str(YAML_BACKUP_SOCKET))
    if sent != len(payload):
        raise OSError(errno.EIO, "incomplete YAML backup request")


def send_yaml_backup_request(password):
    send_memory_request({
        "action": "yaml_backup",
        "password": validate_yaml_backup_password(password),
    })


def request_action():
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


def write_request(action):
    if action != "collect":
        raise ValueError("only a non-interrupting collection request is supported")
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
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.ftruncate(descriptor, 0)
        os.write(descriptor, (action + "\n").encode("ascii"))
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
    allowed, _reason = control_request_guard()
    if not allowed:
        respond({"error": "forbidden"}, "403 Forbidden")
        return
    method = os.environ.get("REQUEST_METHOD", "GET").upper()
    if method == "POST":
        if os.environ.get("HTTP_X_REQUESTED_WITH") != "SwitchCollectionControl":
            respond({"error": "missing control request header"}, "403 Forbidden")
            return
        allowed, reason = post_control_guard()
        if not allowed:
            respond({"error": reason}, "403 Forbidden")
            return
    elif method != "GET":
        respond({"error": "method not allowed"}, "405 Method Not Allowed")
        return
    alive, pid = process_state()
    status = collection_status()
    backup_status = yaml_backup_status()
    recurring_collection_status = continuous_collection_status()
    recurring_backup_status = continuous_backup_status()
    pending = request_action()
    if alive and pending == "collect" and status.get("state") != "collecting":
        status = {**status, "state": "queued"}
    if method == "GET":
        query = parse_qs(os.environ.get("QUERY_STRING", ""), keep_blank_values=True)
        view_values = query.get("view", [""])
        if len(view_values) != 1 or view_values[0] not in {
            "", "switch", "yaml_backup", "continuous",
            "continuous_collection", "continuous_backup",
            "issue_tracker_online",
        }:
            respond({"error": "invalid status view"}, "400 Bad Request")
            return
        if view_values[0] == 'issue_tracker_online':
            respond({**issue_tracker_online_status(), 'process_alive': alive})
            return
        selected = {
            "yaml_backup": backup_status,
            "continuous": recurring_collection_status,
            "continuous_collection": recurring_collection_status,
            "continuous_backup": recurring_backup_status,
        }.get(view_values[0], status)
        respond({**selected, "process_alive": alive})
        return
    try:
        length = int(os.environ.get("CONTENT_LENGTH", "0"))
    except ValueError:
        length = -1
    if length < 0 or length > 4096:
        respond({"error": "invalid request length"}, "400 Bad Request")
        return
    fields = parse_qs(sys.stdin.read(length), keep_blank_values=True)
    actions = fields.get("action", [])
    if len(actions) != 1 or actions[0] not in {
        "collect", "yaml_backup",
        "continuous_collection_start", "continuous_collection_stop",
        "continuous_backup_start", "continuous_backup_stop",
    }:
        respond(
            {"error": "unsupported collection action"},
            "400 Bad Request",
        )
        return
    action = actions[0]
    if not alive:
        respond({"error": "switch collection worker is not running",
                 "state": "stopped", "process_alive": False}, "409 Conflict")
        return
    switch_busy = status.get("state") in {"queued", "collecting", "stopping"}
    backup_busy = backup_status.get("state") in {"queued", "collecting"}
    switch_cooling = is_cooling_down(status.get("remaining_seconds"))
    backup_cooling = is_cooling_down(backup_status.get("remaining_seconds"))
    continuous_collection_enabled = (
        recurring_collection_status.get("enabled") is True
    )
    continuous_backup_enabled = recurring_backup_status.get("enabled") is True
    if action == "continuous_collection_start":
        intervals = fields.get("interval_minutes", [])
        if len(intervals) != 1 or set(fields) != {"action", "interval_minutes"}:
            respond({"error": "exactly one interval_minutes field is required"},
                    "400 Bad Request")
            return
        if continuous_collection_enabled:
            respond({"error": "continuous collection is already enabled"},
                    "409 Conflict")
            return
        if switch_busy:
            respond({"error": "manual collection is already running"},
                    "409 Conflict")
            return
        try:
            message = {
                "action": "continuous_collection_start",
                "interval_minutes": validate_continuous_interval(
                    intervals[0], action,
                ),
            }
            send_memory_request(message)
        except ValueError as exc:
            respond({"error": str(exc)}, "400 Bad Request")
            return
        except OSError as exc:
            respond({"error": f"continuous collection request failed: {exc}"},
                    "503 Service Unavailable")
            return
        respond({"state": "scheduled", "enabled": True,
                 "interval_minutes": message["interval_minutes"],
                 "message": "accepted; worker will wait for collection work and cooldown",
                 "process_alive": True})
        return
    if action == "continuous_backup_start":
        passwords = fields.get("password", [])
        intervals = fields.get("interval_minutes", [])
        if (
            len(passwords) != 1 or len(intervals) != 1
            or set(fields) != {"action", "password", "interval_minutes"}
        ):
            respond({"error": "password and interval_minutes are required"},
                    "400 Bad Request")
            return
        if continuous_backup_enabled:
            respond({"error": "continuous backup is already enabled"},
                    "409 Conflict")
            return
        if backup_busy:
            respond({"error": "manual backup is already running"},
                    "409 Conflict")
            return
        try:
            message = {
                "action": "continuous_backup_start",
                "password": validate_yaml_backup_password(passwords[0]),
                "interval_minutes": validate_continuous_interval(
                    intervals[0], action,
                ),
            }
            send_memory_request(message)
        except ValueError as exc:
            respond({"error": str(exc)}, "400 Bad Request")
            return
        except OSError as exc:
            respond({"error": f"continuous backup request failed: {exc}"},
                    "503 Service Unavailable")
            return
        respond({"state": "scheduled", "enabled": True,
                 "interval_minutes": message["interval_minutes"],
                 "message": "accepted; worker will wait for backup work and cooldown",
                 "process_alive": True})
        return
    if action in {"continuous_collection_stop", "continuous_backup_stop"}:
        try:
            send_memory_request({"action": action})
        except OSError as exc:
            respond({"error": f"continuous mode stop request failed: {exc}"},
                    "503 Service Unavailable")
            return
        respond({"state": "stopping", "enabled": True,
                 "process_alive": True})
        return
    if action == "collect" and continuous_collection_enabled:
        respond({"error": "manual collection is disabled during continuous collection",
                 "process_alive": True}, "409 Conflict")
        return
    if action == "yaml_backup":
        passwords = fields.get("password", [])
        if len(passwords) != 1:
            respond({"error": "exactly one password field is required"}, "400 Bad Request")
            return
        if continuous_backup_enabled:
            respond({"error": "manual backup is disabled during continuous backup",
                     "process_alive": True}, "409 Conflict")
            return
        if backup_busy:
            respond({"error": "another managed backup is already running"}, "409 Conflict")
            return
        if backup_cooling:
            respond({**backup_status, "error": "YAML backup is cooling down",
                     "process_alive": True}, "409 Conflict")
            return
        try:
            send_yaml_backup_request(passwords[0])
        except ValueError as exc:
            respond({"error": str(exc)}, "400 Bad Request")
            return
        except OSError as exc:
            respond({"error": f"YAML backup request failed: {exc}"},
                    "503 Service Unavailable")
            return
        respond({"state": "queued", "process_alive": True,
                 "message": "YAML backup requested"})
        return
    if action == "collect" and switch_busy:
        respond({**status, "error": "switch collection is already running",
                 "process_alive": True}, "409 Conflict")
        return
    if action == "collect" and switch_cooling:
        respond({**status, "error": "switch collection is cooling down",
                 "process_alive": True}, "409 Conflict")
        return
    try:
        write_request(action)
    except OSError as exc:
        respond({"error": str(exc)}, "500 Internal Server Error")
        return
    respond({"state": "queued", "process_alive": True,
             "message": "switch collection requested"})


if __name__ == "__main__":
    main()
