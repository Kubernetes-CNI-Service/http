"""Direct REQ7 root-only Unix listener and peer-bound journal contracts."""

import json
import os
from pathlib import Path
import struct
import tempfile
import types
import unittest
from unittest import mock

from monitor.issue_tracker_manual_channel import DurableManualQueue
from monitor.issue_tracker_manual_listener import (
    ManualSocketListener, ManualListenerHold,
)


class FakeConnection:
    def __init__(self, payload, *, uid=1201, gid=1202, pid=422):
        self.chunks = [payload]
        self.cred = struct.pack("=iII", pid, uid, gid)
        self.sent = []
        self.timeout = None

    def settimeout(self, value):
        self.timeout = value

    def getsockopt(self, level, option, length):
        self.asked = (level, option, length)
        return self.cred

    def recv(self, length):
        return self.chunks.pop(0) if self.chunks else b""

    def sendall(self, payload):
        self.sent.append(payload)


class ManualListenerDirectTests(unittest.TestCase):
    def _listener(self, directory, broker):
        root = Path(directory) / "manual"
        root.mkdir(mode=0o700)
        queue = DurableManualQueue(root, boot_id="boot-a")
        return ManualSocketListener(queue, broker, allowed_peer_uid=1201,
                                    allowed_peer_gid=1202), queue

    def test_missing_or_wrong_kernel_credential_rejects_before_queue(self):
        class Broker:
            def preview(self, principal, panel):
                raise AssertionError("unauthorized peer reached broker")

        wire = b'{"action":"preview","panel":"Switch Status","principal":"nvis"}\n'
        with tempfile.TemporaryDirectory() as directory:
            listener, queue = self._listener(directory, Broker())
            for uid, gid, pid in ((1203, 1202, 422), (1201, 1203, 422),
                                  (1201, 1202, 0)):
                with self.subTest(uid=uid, gid=gid, pid=pid), mock.patch(
                        "monitor.issue_tracker_manual_listener.sys.platform", "linux"), \
                        mock.patch("monitor.issue_tracker_manual_listener.socket.SO_PEERCRED",
                                   17, create=True):
                    conn = FakeConnection(wire, uid=uid, gid=gid, pid=pid)
                    listener.handle_connection(conn)
                    self.assertEqual("manual_worker_unavailable",
                                     json.loads(conn.sent[0])["error"])
                    self.assertEqual([], queue.pending_ids())
            with mock.patch("monitor.issue_tracker_manual_listener.sys.platform",
                            "darwin"):
                conn = FakeConnection(wire)
                listener.handle_connection(conn)
                self.assertEqual("manual_worker_unavailable",
                                 json.loads(conn.sent[0])["error"])
                self.assertEqual([], queue.pending_ids())
            with mock.patch("monitor.issue_tracker_manual_listener.sys.platform",
                            "linux"), mock.patch(
                    "monitor.issue_tracker_manual_listener.socket.SO_PEERCRED", 17,
                    create=True):
                conn = FakeConnection(wire)
                conn.cred = conn.cred[:-1]
                listener.handle_connection(conn)
                self.assertEqual("manual_worker_unavailable",
                                 json.loads(conn.sent[0])["error"])
                self.assertEqual([], queue.pending_ids())

    def test_exact_frame_and_job_prevent_cross_principal_result_swap(self):
        class Broker:
            def preview(self, principal, panel):
                return {"principal": principal, "panel": panel}

        with tempfile.TemporaryDirectory() as directory:
            listener, queue = self._listener(directory, Broker())
            previous = queue.enqueue({"action": "preview", "panel": "IB Link Validation",
                                      "principal": "cumulus"})
            good = FakeConnection(
                b'{"action":"preview","panel":"Switch Status","principal":"nvis"}\n')
            with mock.patch("monitor.issue_tracker_manual_listener.sys.platform",
                            "linux"), mock.patch(
                    "monitor.issue_tracker_manual_listener.socket.SO_PEERCRED", 17,
                    create=True):
                listener.handle_connection(good)
                self.assertEqual({"panel": "Switch Status", "principal": "nvis"},
                                 json.loads(good.sent[0]))
                self.assertEqual("queued", queue.status(previous)["state"])
                for bad in (
                    b'{"action":"preview","panel":"Switch Status","principal":"nvis"}',
                    b'{"action":"preview","panel":"Switch Status","principal":"nvis"}\n{}',
                    b'{"principal":"nvis","panel":"Switch Status","action":"preview"}\n',
                    b'{"action":"preview","action":"preview","panel":"Switch Status","principal":"nvis"}\n',
                ):
                    conn = FakeConnection(bad)
                    listener.handle_connection(conn)
                    self.assertEqual("manual_worker_unavailable",
                                     json.loads(conn.sent[0])["error"])
                self.assertEqual([previous], queue.pending_ids())

    def test_post_claim_exception_is_unknown_and_not_replayed(self):
        class Broker:
            calls = 0

            def preview(self, principal, panel):
                self.calls += 1
                raise RuntimeError("simulated crash after claim")

        with tempfile.TemporaryDirectory() as directory:
            broker = Broker()
            listener, queue = self._listener(directory, broker)
            conn = FakeConnection(
                b'{"action":"preview","panel":"Switch Status","principal":"nvis"}\n')
            with mock.patch("monitor.issue_tracker_manual_listener.sys.platform",
                            "linux"), mock.patch(
                    "monitor.issue_tracker_manual_listener.socket.SO_PEERCRED", 17,
                    create=True):
                listener.handle_connection(conn)
            self.assertEqual(1, broker.calls)
            self.assertEqual("manual_worker_unavailable",
                             json.loads(conn.sent[0])["error"])
            self.assertEqual([], queue.pending_ids())
            claimed = list((Path(directory) / "manual").glob("claimed-*.json"))
            self.assertEqual(1, len(claimed))
            self.assertEqual("unknown_after_claim",
                             queue.status(claimed[0].stem[8:])["state"])

    def test_binding_requires_real_root_and_root_owned_private_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            listener, _ = self._listener(directory, object())
            with mock.patch("monitor.issue_tracker_manual_listener.os.geteuid",
                            return_value=501), self.assertRaises(ManualListenerHold):
                listener.bind_listener()

            valid_meta = types.SimpleNamespace(st_mode=0o040750, st_uid=0,
                                               st_gid=1202)
            with mock.patch("monitor.issue_tracker_manual_listener.os.geteuid",
                            return_value=0), mock.patch(
                    "monitor.issue_tracker_manual_listener.sys.platform", "linux"), \
                    mock.patch("monitor.issue_tracker_manual_listener.socket.SO_PEERCRED",
                               17, create=True), mock.patch(
                    "monitor.issue_tracker_manual_listener.os.lstat",
                    return_value=valid_meta), mock.patch(
                    "monitor.issue_tracker_manual_listener.os.path.lexists",
                    return_value=False), mock.patch.object(
                    listener.queue, "_directory",
                    side_effect=ManualListenerHold("queue not root-private")), \
                    self.assertRaises(ManualListenerHold):
                listener.bind_listener()

            wrong_group = types.SimpleNamespace(st_mode=0o040750, st_uid=0,
                                                st_gid=7777)
            with mock.patch("monitor.issue_tracker_manual_listener.os.geteuid",
                            return_value=0), mock.patch(
                    "monitor.issue_tracker_manual_listener.sys.platform", "linux"), \
                    mock.patch("monitor.issue_tracker_manual_listener.socket.SO_PEERCRED",
                               17, create=True), mock.patch(
                    "monitor.issue_tracker_manual_listener.os.lstat",
                    return_value=wrong_group), self.assertRaises(ManualListenerHold):
                listener.bind_listener()


if __name__ == "__main__":
    unittest.main()
