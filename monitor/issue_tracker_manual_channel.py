"""Bounded REQ7 manual ingress and root-private request journal.

This is a local-only, currently uninstalled seam. A browser never supplies
rows, source digests, project paths, credentials or C6 admission witnesses.
The worker owns the preview broker and commits only through its callbacks.
"""

from __future__ import annotations

from contextlib import contextmanager
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
from urllib.parse import parse_qsl

from monitor.issue_tracker_manual_preview import ManualPreviewHold


class ManualChannelHold(ValueError):
    """No CGI or queued request authority may be inferred."""


_USERS = frozenset(("nvis", "cumulus"))
_PANELS = frozenset(("Switch Status", "Eth Link Validation", "IB Link Validation"))
_ROUTES = frozenset(("/monitor/control/issue-tracker",
                     "/cgi-bin/issue-tracker-control"))
_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_JOB = re.compile(r"[0-9a-f]{32}\Z")
_MAX_REQUEST = 512
_MAX_RESULT = 8192


def _canonical(value):
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n")
    except (TypeError, ValueError) as exc:
        raise ManualChannelHold("manual request is not canonical JSON") from exc


def _request(value):
    if type(value) is not dict or value.get("principal") not in _USERS:
        raise ManualChannelHold("manual principal is invalid")
    if type(value.get("panel")) is not str or value["panel"] not in _PANELS:
        raise ManualChannelHold("manual panel is invalid")
    if value.get("action") == "preview" and set(value) == {
            "action", "panel", "principal"}:
        return value
    if value.get("action") == "confirm" and set(value) == {
            "action", "panel", "principal", "token", "confirmation"}:
        if (type(value["token"]) is str and _TOKEN.fullmatch(value["token"])
                and value["confirmation"] == "publish_local"):
            return value
    raise ManualChannelHold("manual action is not one exact panel request")


def validate_ingress(environ, body):
    """Require server-authenticated principal and exact same-origin POST."""
    if (type(environ) is not dict or type(body) is not bytes
            or not body or len(body) > _MAX_REQUEST
            or environ.get("CONTROL_REQUIRE_AUTH") != "1"
            or environ.get("AUTH_TYPE") != "Basic"
            or environ.get("REMOTE_USER") not in _USERS
            or environ.get("SCRIPT_NAME") not in _ROUTES
            or environ.get("PATH_INFO", "") != ""
            or environ.get("REQUEST_METHOD") != "POST"
            or environ.get("REQUEST_SCHEME") != "http"
            or environ.get("HTTPS") not in (None, "off")
            or environ.get("HTTP_X_REQUESTED_WITH") != "IssueTrackerManualControl"
            or environ.get("CONTENT_TYPE") != "application/x-www-form-urlencoded"
            or environ.get("HTTP_SEC_FETCH_SITE", "").strip().casefold()
            not in ("", "same-origin")):
        raise ManualChannelHold("manual CGI authority is incomplete")
    try:
        length = int(environ.get("CONTENT_LENGTH", ""))
        address = ipaddress.IPv4Address(environ.get("SERVER_ADDR", ""))
        port = int(environ.get("CONTROL_SERVICE_PORT", "80"))
    except (TypeError, ValueError, ipaddress.AddressValueError) as exc:
        raise ManualChannelHold("manual service authority is invalid") from exc
    if (length != len(body) or length < 1 or not (1 <= port <= 65535)
            or str(address) != environ.get("SERVER_ADDR")
            or address.is_unspecified or address.is_multicast
            or int(address) == 0xFFFFFFFF
            or environ.get("SERVER_PORT") != str(port)):
        raise ManualChannelHold("manual service authority is invalid")
    canonical = str(address)
    hosts = ({canonical, f"{canonical}:80"} if port == 80
             else {f"{canonical}:{port}"})
    origins = ({f"http://{canonical}", f"http://{canonical}:80"}
               if port == 80 else {f"http://{canonical}:{port}"})
    if (environ.get("HTTP_HOST") not in hosts
            or environ.get("HTTP_ORIGIN") not in origins):
        raise ManualChannelHold("manual POST must be same-origin")
    try:
        text = body.decode("ascii", "strict")
        pairs = parse_qsl(text, keep_blank_values=True, strict_parsing=True,
                          max_num_fields=4, encoding="utf-8", errors="strict")
    except (UnicodeError, ValueError) as exc:
        raise ManualChannelHold("manual form is invalid") from exc
    values = {}
    for key, value in pairs:
        if key in values:
            raise ManualChannelHold("manual form contains duplicate fields")
        values[key] = value
    return _request({**values, "principal": environ["REMOTE_USER"]})


class DurableManualQueue:
    """Root-private, fsynced one-way queue; claimed work is never replayed.

    An interrupted claim is UNKNOWN, not permission to retry a C6 write.
    The production caller must place this root under a trusted root-owned
    ancestor outside the web tree; the directory is never CGI-writable.
    """

    def __init__(self, root, *, boot_id):
        self.root = Path(root)
        self.boot_id = boot_id
        if (not self.root.is_absolute() or type(boot_id) is not str
                or not boot_id or len(boot_id) > 128
                or any(char.isspace() for char in boot_id)):
            raise ManualChannelHold("manual queue identity is invalid")
        try:
            meta = os.lstat(self.root)
            if (not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.geteuid()
                    or stat.S_IMODE(meta.st_mode) != 0o700):
                raise ManualChannelHold("manual queue root is not private")
        except OSError as exc:
            raise ManualChannelHold("manual queue root is absent") from exc

    def _open(self):
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        if not hasattr(os, "O_NOFOLLOW"):
            raise ManualChannelHold("manual queue requires O_NOFOLLOW")
        fd = os.open(self.root, flags | os.O_NOFOLLOW)
        meta = os.fstat(fd)
        if (not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.geteuid()
                or stat.S_IMODE(meta.st_mode) != 0o700):
            os.close(fd)
            raise ManualChannelHold("manual queue root changed")
        return fd

    @contextmanager
    def _directory(self):
        fd = self._open()
        try:
            yield fd
        finally:
            os.close(fd)

    @staticmethod
    def _write_new(fd, name, value):
        body = _canonical(value)
        if len(body) > _MAX_RESULT:
            raise ManualChannelHold("manual queue record is oversized")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        staging = f"staging-{secrets.token_hex(16)}.tmp"
        target = os.open(staging, flags, 0o600, dir_fd=fd)
        try:
            os.fchmod(target, 0o600)
            view = memoryview(body)
            while view:
                written = os.write(target, view)
                if written <= 0:
                    raise ManualChannelHold("manual queue write made no progress")
                view = view[written:]
            os.fsync(target)
        finally:
            os.close(target)
        # Linking the fsynced temporary record creates the final name only
        # when absent. A crash before this point leaves no dispatchable job.
        os.link(staging, name, src_dir_fd=fd, dst_dir_fd=fd,
                follow_symlinks=False)
        os.fsync(fd)
        os.unlink(staging, dir_fd=fd)
        os.fsync(fd)

    @staticmethod
    def _read(fd, name):
        try:
            target = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise ManualChannelHold("manual queue record cannot be opened safely") from exc
        try:
            meta = os.fstat(target)
            if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.geteuid()
                    or meta.st_nlink != 1 or stat.S_IMODE(meta.st_mode) != 0o600
                    or meta.st_size < 1 or meta.st_size > _MAX_RESULT):
                raise ManualChannelHold("manual queue record metadata is unsafe")
            raw = os.read(target, _MAX_RESULT + 1)
        finally:
            os.close(target)
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeError, ValueError) as exc:
            raise ManualChannelHold("manual queue record is corrupt") from exc
        if raw != _canonical(value):
            raise ManualChannelHold("manual queue record is noncanonical")
        return value

    def pending_ids(self):
        with self._directory() as fd:
            with os.scandir(fd) as entries:
                return sorted(name[8:-5] for entry in entries
                              if (name := entry.name).startswith("pending-")
                              and name.endswith(".json"))

    def enqueue(self, request):
        _request(request)
        job = secrets.token_hex(16)
        record = {"boot_id": self.boot_id, "request": request}
        with self._directory() as fd:
            self._write_new(fd, f"pending-{job}.json", record)
        return job

    def claim(self):
        with self._directory() as fd:
            for job in self.pending_ids():
                if not _JOB.fullmatch(job):
                    raise ManualChannelHold("manual queue filename is invalid")
                source = f"pending-{job}.json"
                record = self._read(fd, source)
                if (type(record) is not dict or set(record) != {"boot_id", "request"}
                        or type(record["boot_id"]) is not str):
                    raise ManualChannelHold("manual queue record shape is invalid")
                request = _request(record["request"])
                os.rename(source, f"claimed-{job}.json",
                          src_dir_fd=fd, dst_dir_fd=fd)
                os.fsync(fd)
                if record["boot_id"] != self.boot_id:
                    continue  # stale worker lifetime is permanently UNKNOWN
                return job, request
        return None

    def complete(self, job, result):
        if type(job) is not str or not _JOB.fullmatch(job):
            raise ManualChannelHold("manual job identity is invalid")
        with self._directory() as fd:
            claim = self._read(fd, f"claimed-{job}.json")
            if (type(claim) is not dict or set(claim) != {"boot_id", "request"}
                    or claim["boot_id"] != self.boot_id):
                raise ManualChannelHold("manual job belongs to another worker boot")
            _request(claim["request"])
            self._write_new(fd, f"done-{job}.json", {"state": "done", "result": result})

    def status(self, job):
        if type(job) is not str or not _JOB.fullmatch(job):
            raise ManualChannelHold("manual job identity is invalid")
        with self._directory() as fd:
            try:
                return self._read(fd, f"done-{job}.json")
            except FileNotFoundError:
                pass
            try:
                self._read(fd, f"claimed-{job}.json")
            except FileNotFoundError:
                try:
                    self._read(fd, f"pending-{job}.json")
                except FileNotFoundError:
                    return {"state": "unknown_job"}
                return {"state": "queued"}
            return {"state": "unknown_after_claim"}


class ManualQueueWorker:
    """Single-owner root handoff to the existing one-use Stage L broker."""

    def __init__(self, queue, broker):
        if type(queue) is not DurableManualQueue:
            raise ManualChannelHold("manual worker queue is invalid")
        self.queue = queue
        self.broker = broker

    def process_next(self):
        claim = self.queue.claim()
        if claim is None:
            return None
        job, request = claim
        try:
            if request["action"] == "preview":
                result = self.broker.preview(request["principal"], request["panel"])
            else:
                result = self.broker.confirm(
                    request["principal"], request["panel"], request["token"],
                    confirmation=request["confirmation"],
                )
        except ManualPreviewHold:
            result = {"error": "manual_hold"}
        # Unexpected C6 errors deliberately leave a claimed UNKNOWN and are
        # never retried automatically. The receipt/journal is then authoritative.
        self.queue.complete(job, result)
        return job, result
