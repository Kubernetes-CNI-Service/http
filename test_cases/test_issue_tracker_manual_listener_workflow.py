"""Real REQ7 CGI -> Unix-listener -> durable queue -> broker workflow.

The Unix kernel/Apache installation is deliberately replaced by a transport
fixture on macOS; Linux SO_PEERCRED and actual route stay REAL_ENV BLOCKED.
"""

import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from monitor.issue_tracker_manual_channel import DurableManualQueue
from monitor.issue_tracker_manual_listener import ManualSocketListener
from monitor.issue_tracker_manual_preview import ManualPreviewBroker
from test_cases.test_issue_tracker_manual_channel import valid_env
from test_cases.test_issue_tracker_manual_listener import FakeConnection
from test_cases.test_issue_tracker_manual_preview import qualified_status

LOCAL_RECEIPT = {
    "local": "committed", "local_applied": True,
    "generation_id": "gen-" + "0" * 19 + "1-" + "a" * 32,
    "manifest_id": "b" * 64, "published_sha256": "c" * 64,
    "online": "disabled_no_send_authority",
}


CGI_PATH = Path(__file__).resolve().parents[1] / "monitor/issue-tracker-control.cgi"
loader = importlib.machinery.SourceFileLoader("issue_tracker_listener_flow", str(CGI_PATH))
spec = importlib.util.spec_from_loader(loader.name, loader)
cgi = importlib.util.module_from_spec(spec)
loader.exec_module(cgi)


class ManualListenerWorkflowTests(unittest.TestCase):
    def test_cgi_peer_bound_listener_preserves_real_k_event_and_exact_replay(self):
        from monitor.issue_tracker_state_owner import (
            current_k, initialize_tracker_state, set_k, tracker_writer,
        )

        with tempfile.TemporaryDirectory(prefix="req7-listener-k-chain-") as directory:
            project = Path(os.path.realpath(directory)) / "project"
            project.mkdir()
            publication = project / "99-output-monitor"
            publication.mkdir()
            initialize_tracker_state(project, publication,
                initialized_at="2026-09-25T00:00:00Z", acquisition_id="listener-k-init")
            queue_root = project / ".tracker/manual-queue"
            queue_root.mkdir(mode=0o700)
            queue = DurableManualQueue(queue_root, boot_id="listener-k-fixture")

            def query():
                with tracker_writer(project, publication) as token:
                    state = current_k(token)
                    return {"settings": "current", "k": state.k,
                            "revision": state.revision, "event_sha256": state.event_sha256,
                            "online": "disabled_no_send_authority"}

            def change(principal, k, revision, request_id):
                with tracker_writer(project, publication) as token:
                    receipt = set_k(token, new_k=k, expected_revision=revision,
                        actor="operator:" + principal, request_id=request_id,
                        recorded_at="2026-09-25T00:01:00Z")
                    return {"settings": "committed", "k": receipt.k,
                            "revision": receipt.revision, "event_sha256": receipt.event_sha256,
                            "replay": receipt.replay, "online": "disabled_no_send_authority"}

            qualify = mock.Mock()
            publish = mock.Mock()
            broker = ManualPreviewBroker(qualify, publish,
                read_settings=query, change_settings=change)
            listener = ManualSocketListener(queue, broker,
                allowed_peer_uid=1201, allowed_peer_gid=1202)

            def relay(request, *, uid=1201, gid=1202):
                wire = json.dumps(request, sort_keys=True,
                    separators=(",", ":")).encode() + b"\n"
                connection = FakeConnection(wire, uid=uid, gid=gid)
                listener.handle_connection(connection)
                self.assertEqual(1, len(connection.sent))
                return json.loads(connection.sent[0])

            def request(body, submit=relay):
                environment = {**valid_env(body),
                    "HTTP_ACCEPT": "application/vnd.http.issue-tracker.settings+json"}
                return cgi.handle(environment, body, submit=submit)

            def originals(root):
                return {str(path.relative_to(root)): (path.stat().st_ino, path.read_bytes())
                        for path in root.rglob("*") if path.is_file()}

            # Only the kernel credential/transport is a macOS fixture. CGI,
            # listener, queue, broker and LK-P settings/event/outbox are actual.
            with mock.patch("monitor.issue_tracker_manual_listener.sys.platform", "linux"), \
                    mock.patch("monitor.issue_tracker_manual_listener.socket.SO_PEERCRED",
                               17, create=True):
                read = b"action=settings&panel=IB+Link+Validation"
                status, initial = request(read)
                self.assertEqual("200 OK", status)
                self.assertEqual(("3", "0"), (initial["k"], initial["revision"]))
                write = (b"action=set_k&panel=IB+Link+Validation&new_k=7"
                         b"&expected_revision=0&request_id=" + b"d" * 32)
                status, receipt = request(write)
                self.assertEqual("200 OK", status)
                self.assertEqual(("7", "1", False),
                    (receipt["k"], receipt["revision"], receipt["replay"]))
                events = project / ".tracker/settings/events"
                self.assertEqual(["0.json", "1.json"], sorted(path.name for path in events.iterdir()))
                event = json.loads((events / "1.json").read_bytes())
                self.assertEqual(("set_k", 3, 7, 1, "operator:nvis", "d" * 32),
                    (event["type"], event["old_k"], event["new_k"], event["revision"],
                     event["actor"], event["request_id"]))
                settings_before = originals(project / ".tracker/settings")
                status, replay = request(write)
                self.assertEqual("200 OK", status)
                self.assertEqual({**receipt, "replay": True}, replay)
                self.assertEqual(settings_before, originals(project / ".tracker/settings"))
                status, current = request(read)
                self.assertEqual("200 OK", status)
                self.assertEqual(("7", "1", receipt["event_sha256"]),
                    (current["k"], current["revision"], current["event_sha256"]))
                # A sanitized unavailable reply alone is not a rejection oracle:
                # require zero enqueue and unchanged real queue/settings originals.
                for uid, gid in ((1203, 1202), (1201, 1203)):
                    with self.subTest(uid=uid, gid=gid):
                        queue_before = originals(queue_root)
                        with mock.patch.object(queue, "enqueue", wraps=queue.enqueue) as enqueue:
                            status, denied = request(write,
                                submit=lambda intent: relay(intent, uid=uid, gid=gid))
                        self.assertEqual("503 Service Unavailable", status)
                        self.assertEqual({"error": "manual_worker_unavailable"}, denied)
                        enqueue.assert_not_called()
                        self.assertEqual(queue_before, originals(queue_root))
                        self.assertEqual(settings_before, originals(project / ".tracker/settings"))
            qualify.assert_not_called()
            publish.assert_not_called()
            self.assertEqual((), tuple(publication.iterdir()))
            self.assertFalse(any((project / ".tracker/generations").glob("*/RECEIPT")))
            self.assertFalse(list(project.rglob("ATTEMPT-*")))
            self.assertFalse(list(project.rglob("CLAIM-*")))
            self.assertEqual("disabled_no_send_authority", receipt["online"])

    def test_authenticated_cgi_relay_preserves_principal_source_and_one_use(self):
        source = qualified_status()
        commits = []
        broker = ManualPreviewBroker(
            lambda: source,
            lambda panel, fingerprint: commits.append((panel, fingerprint)) or
            LOCAL_RECEIPT, clock=lambda: 1000.0,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "manual"
            root.mkdir(mode=0o700)
            queue = DurableManualQueue(root, boot_id="boot-a")
            listener = ManualSocketListener(queue, broker, allowed_peer_uid=1201,
                                            allowed_peer_gid=1202)

            def relay(request):
                wire = json.dumps(request, sort_keys=True,
                                  separators=(",", ":")).encode() + b"\n"
                conn = FakeConnection(wire)
                listener.handle_connection(conn)
                return json.loads(conn.sent[0])

            with mock.patch("monitor.issue_tracker_manual_listener.sys.platform",
                            "linux"), mock.patch(
                    "monitor.issue_tracker_manual_listener.socket.SO_PEERCRED", 17,
                    create=True):
                body = b"action=preview&panel=Switch+Status"
                status, preview = cgi.handle(valid_env(body), body, submit=relay)
                self.assertEqual("200 OK", status)
                self.assertEqual("e" * 64, preview["selected_decision_sha256"])
                self.assertEqual([], commits)
                confirm = (b"action=confirm&panel=Switch+Status&token=" +
                           preview["token"].encode() + b"&confirmation=publish_local")
                spoofed = {**valid_env(confirm), "REMOTE_USER": "cumulus"}
                status, _ = cgi.handle(spoofed, confirm, submit=relay)
                self.assertEqual("409 Conflict", status)
                self.assertEqual([], commits)
                status, result = cgi.handle(valid_env(confirm), confirm,
                                            submit=relay)
                self.assertEqual("200 OK", status)
                self.assertEqual(LOCAL_RECEIPT, result)
                self.assertEqual(1, len(commits))
                status, _ = cgi.handle(valid_env(confirm), confirm, submit=relay)
                self.assertEqual("409 Conflict", status)
                self.assertEqual(1, len(commits))


if __name__ == "__main__":
    unittest.main()
