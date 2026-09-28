"""Real REQ7 CGI -> Unix-listener -> durable queue -> broker workflow.

The Unix kernel/Apache installation is deliberately replaced by a transport
fixture on macOS; Linux SO_PEERCRED and actual route stay REAL_ENV BLOCKED.
"""

import importlib.machinery
import importlib.util
import json
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


CGI_PATH = Path(__file__).resolve().parents[1] / "monitor/issue-tracker-control.cgi"
loader = importlib.machinery.SourceFileLoader("issue_tracker_listener_flow", str(CGI_PATH))
spec = importlib.util.spec_from_loader(loader.name, loader)
cgi = importlib.util.module_from_spec(spec)
loader.exec_module(cgi)


class ManualListenerWorkflowTests(unittest.TestCase):
    def test_authenticated_cgi_relay_preserves_principal_source_and_one_use(self):
        source = qualified_status()
        commits = []
        broker = ManualPreviewBroker(
            lambda: source,
            lambda panel, fingerprint: commits.append((panel, fingerprint)) or
            {"local": "receipt"}, clock=lambda: 1000.0,
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
                self.assertEqual({"local": "receipt"}, result)
                self.assertEqual(1, len(commits))
                status, _ = cgi.handle(valid_env(confirm), confirm, submit=relay)
                self.assertEqual("409 Conflict", status)
                self.assertEqual(1, len(commits))


if __name__ == "__main__":
    unittest.main()
