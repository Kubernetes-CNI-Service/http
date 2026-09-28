"""Inactive Linux-only REQ7 Unix listener for the private manual queue.

No service entrypoint or Apache route installs this listener. A future trusted
root launcher must supply the dedicated CGI UID/GID and own its lifecycle.
SO_PEERCRED authenticates that Unix process, *not* the HTTP REMOTE_USER: the
Apache Basic-auth CGI remains the principal and same-origin trust boundary.
Other processes with the CGI UID could impersonate a principal, so deployment
must give the route an exclusive, non-login CGI identity before activation.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import stat
import struct
import sys

from monitor.issue_tracker_manual_channel import (
    DurableManualQueue, ManualChannelHold, ManualQueueWorker,
    _canonical, _request,
)


class ManualListenerHold(ValueError):
    """No kernel peer or wire request authority may be inferred."""


SOCKET_PATH = Path("/run/http-ztp/issue-tracker-manual.sock")
_UCRED = struct.Struct("=iII")  # Linux struct ucred: pid_t, uid_t, gid_t
_MAX_WIRE = 512
_UNAVAILABLE = {"error": "manual_worker_unavailable"}


class ManualSocketListener:
    """One-connection-at-a-time relay; it never processes another job's ID."""

    def __init__(self, queue, broker, *, allowed_peer_uid, allowed_peer_gid,
                 socket_path=SOCKET_PATH):
        if (type(queue) is not DurableManualQueue
                or type(allowed_peer_uid) is not int or allowed_peer_uid <= 0
                or type(allowed_peer_gid) is not int or allowed_peer_gid <= 0
                or not isinstance(socket_path, Path) or not socket_path.is_absolute()):
            raise ManualListenerHold("manual listener identity is incomplete")
        self.queue = queue
        self.worker = ManualQueueWorker(queue, broker)
        self.allowed_peer_uid = allowed_peer_uid
        self.allowed_peer_gid = allowed_peer_gid
        self.socket_path = socket_path

    @staticmethod
    def _require_linux_peer(conn):
        if sys.platform != "linux" or not hasattr(socket, "SO_PEERCRED"):
            raise ManualListenerHold("Linux SO_PEERCRED is required")
        raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _UCRED.size)
        if type(raw) is not bytes or len(raw) != _UCRED.size:
            raise ManualListenerHold("Unix peer credentials are incomplete")
        pid, uid, gid = _UCRED.unpack(raw)
        if pid <= 0:
            raise ManualListenerHold("Unix peer PID is invalid")
        return uid, gid

    @staticmethod
    def _read_request(conn):
        conn.settimeout(2)
        raw = bytearray()
        while len(raw) <= _MAX_WIRE:
            chunk = conn.recv(_MAX_WIRE + 1 - len(raw))
            if not chunk:
                raise ManualListenerHold("manual wire request is incomplete")
            raw.extend(chunk)
            if b"\n" in chunk:
                break
        if len(raw) > _MAX_WIRE or raw.count(b"\n") != 1 or raw[-1:] != b"\n":
            raise ManualListenerHold("manual wire framing is invalid")
        try:
            request = json.loads(raw.decode("utf-8"))
            _request(request)
            if bytes(raw) != _canonical(request):
                raise ManualListenerHold("manual wire request is not canonical")
        except (UnicodeError, ValueError, TypeError) as exc:
            raise ManualListenerHold("manual wire request is invalid") from exc
        return request

    def handle_connection(self, conn):
        """Return one bounded reply; an exception after claim never retries C6."""
        try:
            uid, gid = self._require_linux_peer(conn)
            if (uid != self.allowed_peer_uid or gid != self.allowed_peer_gid):
                raise ManualListenerHold("Unix peer is not the dedicated CGI")
            request = self._read_request(conn)
            job = self.queue.enqueue(request)
            finished = self.worker.process_job(job)
            if finished is None or finished[0] != job:
                raise ManualListenerHold("manual response is not this job")
            result = finished[1]
            if type(result) is not dict:
                raise ManualListenerHold("manual result is not a public object")
            reply = _canonical(result)
            if len(reply) > 8192:
                raise ManualListenerHold("manual result is oversized")
        except Exception:
            # A C6 callback can have succeeded before this exception. The
            # claim stays UNKNOWN, never auto-replayed or inferred successful.
            reply = _canonical(_UNAVAILABLE)
        try:
            conn.sendall(reply)
        except OSError:
            pass  # close; never retry an unknown local transaction

    def bind_listener(self):
        """Bind only from root to a pre-existing protected /run directory.

        No stale socket is removed automatically. A launcher must retain the
        returned socket and call serve_one, then explicitly manage shutdown.
        """
        if os.geteuid() != 0 or sys.platform != "linux" or not hasattr(
                socket, "SO_PEERCRED"):
            raise ManualListenerHold("manual listener requires Linux root")
        parent = self.socket_path.parent
        for path in (parent, *parent.parents, self.queue.root.parent,
                     *self.queue.root.parent.parents):
            try:
                meta = os.lstat(path)
            except OSError as exc:
                raise ManualListenerHold("manual socket/queue ancestor is absent") from exc
            if (not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0
                    or stat.S_IMODE(meta.st_mode) & 0o022):
                raise ManualListenerHold("manual socket/queue ancestor is unsafe")
            if path == parent and (stat.S_IMODE(meta.st_mode) != 0o750
                                   or meta.st_gid != self.allowed_peer_gid):
                raise ManualListenerHold("manual socket parent is not CGI-bound")
        try:
            with self.queue._directory():
                pass
        except (OSError, ManualChannelHold) as exc:
            raise ManualListenerHold("manual queue is not root-private") from exc
        if os.path.lexists(self.socket_path):
            raise ManualListenerHold("manual socket already exists; no unlink")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            old_umask = os.umask(0o117)
            try:
                listener.bind(str(self.socket_path))
            finally:
                os.umask(old_umask)
            os.chown(self.socket_path, 0, self.allowed_peer_gid)
            os.chmod(self.socket_path, 0o660)
            meta = os.lstat(self.socket_path)
            if (not stat.S_ISSOCK(meta.st_mode) or meta.st_uid != 0
                    or meta.st_gid != self.allowed_peer_gid
                    or meta.st_nlink != 1 or stat.S_IMODE(meta.st_mode) != 0o660):
                raise ManualListenerHold("manual socket identity changed")
            listener.listen(4)
            return listener
        except Exception:
            listener.close()
            # The bound path, if any, stays for explicit operator inspection.
            raise

    def serve_one(self, listener):
        if os.geteuid() != 0:
            raise ManualListenerHold("manual worker lost root identity")
        conn, _ = listener.accept()
        with conn:
            self.handle_connection(conn)
