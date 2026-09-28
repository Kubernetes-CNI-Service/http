"""Real CGI -> durable root request -> preview broker local-only workflow."""

import importlib.machinery
import importlib.util
from pathlib import Path
import tempfile
import unittest

from monitor.issue_tracker_manual_channel import DurableManualQueue, ManualQueueWorker
from monitor.issue_tracker_manual_preview import ManualPreviewBroker
from test_cases.test_issue_tracker_manual_channel import valid_env
from test_cases.test_issue_tracker_manual_preview import qualified_status


CGI_PATH = Path(__file__).resolve().parents[1] / "monitor/issue-tracker-control.cgi"
loader = importlib.machinery.SourceFileLoader("issue_tracker_control_workflow", str(CGI_PATH))
spec = importlib.util.spec_from_loader(loader.name, loader)
cgi = importlib.util.module_from_spec(spec)
loader.exec_module(cgi)

LOCAL_RECEIPT = {
    "local": "committed", "local_applied": True,
    "generation_id": "gen-" + "0" * 19 + "1-" + "a" * 32,
    "manifest_id": "b" * 64, "published_sha256": "c" * 64,
    "online": "disabled_no_send_authority",
}


class ManualChannelWorkflowTests(unittest.TestCase):
    def test_incomplete_post_c6_reply_is_unknown_not_browser_success_or_replay(self):
        commits = []
        broker = ManualPreviewBroker(
            qualified_status,
            lambda panel, fingerprint: commits.append(panel) or
            {"local_applied": True},
            clock=lambda: 1000.0,
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "manual"
            root.mkdir(mode=0o700)
            queue = DurableManualQueue(root, boot_id="boot-a")
            worker = ManualQueueWorker(queue, broker)
            jobs = []

            def submit(request):
                job = queue.enqueue(request)
                jobs.append(job)
                self.assertEqual(job, worker.process_job(job)[0])
                return queue.status(job)["result"]

            preview_body = b"action=preview&panel=Switch+Status"
            status, preview = cgi.handle(valid_env(preview_body), preview_body,
                                         submit=submit)
            self.assertEqual("200 OK", status)
            confirm_body = (b"action=confirm&panel=Switch+Status&token="
                            + preview["token"].encode()
                            + b"&confirmation=publish_local")
            status, reply = cgi.handle(valid_env(confirm_body), confirm_body,
                                       submit=submit)
            self.assertEqual("503 Service Unavailable", status)
            self.assertEqual({"error": "manual_worker_unavailable"}, reply)
            self.assertEqual("unknown_after_claim", queue.status(jobs[-1])["state"])
            self.assertEqual(["Switch Status"], commits)
            status, reply = cgi.handle(valid_env(confirm_body), confirm_body,
                                       submit=submit)
            self.assertEqual("409 Conflict", status)
            self.assertEqual({"error": "manual_hold"}, reply)
            self.assertEqual(["Switch Status"], commits)

    def test_real_cgi_queue_worker_broker_is_one_use_and_source_bound(self):
        status = qualified_status()
        commits = []
        now = [1000.0]
        broker = ManualPreviewBroker(
            lambda: status,
            lambda panel, fingerprint: commits.append((panel, fingerprint)) or
            LOCAL_RECEIPT,
            clock=lambda: now[0],
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "manual"
            root.mkdir(mode=0o700)
            queue = DurableManualQueue(root, boot_id="boot-a")
            worker = ManualQueueWorker(queue, broker)

            def submit(request):
                job = queue.enqueue(request)
                claimed, result = worker.process_next()
                self.assertEqual(job, claimed)
                self.assertEqual("done", queue.status(job)["state"])
                return result

            body = b"action=preview&panel=Switch+Status"
            http_status, preview = cgi.handle(valid_env(body), body, submit=submit)
            self.assertEqual("200 OK", http_status)
            self.assertEqual("e" * 64, preview["selected_decision_sha256"])
            self.assertEqual([], commits)

            wrong_user = (b"action=confirm&panel=Switch+Status&token=" +
                          preview["token"].encode() + b"&confirmation=publish_local")
            other = {**valid_env(wrong_user), "REMOTE_USER": "cumulus"}
            http_status, result = cgi.handle(other, wrong_user, submit=submit)
            self.assertEqual("409 Conflict", http_status)
            self.assertEqual("manual_hold", result["error"])
            self.assertEqual([], commits)

            status["selected_decision_sha256"]["Switch Status"] = "2" * 64
            http_status, result = cgi.handle(valid_env(wrong_user), wrong_user,
                                             submit=submit)
            self.assertEqual("409 Conflict", http_status)
            self.assertEqual("manual_hold", result["error"])
            self.assertEqual([], commits)

            status["selected_decision_sha256"]["Switch Status"] = "e" * 64
            http_status, preview = cgi.handle(valid_env(body), body, submit=submit)
            self.assertEqual("200 OK", http_status)
            confirm = (b"action=confirm&panel=Switch+Status&token=" +
                       preview["token"].encode() + b"&confirmation=publish_local")
            http_status, result = cgi.handle(valid_env(confirm), confirm,
                                             submit=submit)
            self.assertEqual("200 OK", http_status)
            self.assertEqual(LOCAL_RECEIPT, result)
            self.assertEqual(1, len(commits))
            self.assertEqual("Switch Status", commits[0][0])
            http_status, _ = cgi.handle(valid_env(confirm), confirm, submit=submit)
            self.assertEqual("409 Conflict", http_status)
            self.assertEqual(1, len(commits))


if __name__ == "__main__":
    unittest.main()
