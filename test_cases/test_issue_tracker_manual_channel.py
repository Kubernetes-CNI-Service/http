"""Direct REQ7 CGI and root-owned manual request journal contracts."""

import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from monitor.issue_tracker_manual_channel import (
    DurableManualQueue, ManualChannelHold, ManualQueueWorker, validate_ingress,
)


CGI_PATH = Path(__file__).resolve().parents[1] / "monitor/issue-tracker-control.cgi"
loader = importlib.machinery.SourceFileLoader("issue_tracker_control_cgi", str(CGI_PATH))
spec = importlib.util.spec_from_loader(loader.name, loader)
cgi = importlib.util.module_from_spec(spec)
loader.exec_module(cgi)


def valid_env(body):
    return {
        "CONTROL_REQUIRE_AUTH": "1", "AUTH_TYPE": "Basic", "REMOTE_USER": "nvis",
        "SCRIPT_NAME": "/monitor/control/issue-tracker", "PATH_INFO": "",
        "REQUEST_METHOD": "POST", "SERVER_ADDR": "192.0.2.10",
        "SERVER_PORT": "80", "CONTROL_SERVICE_PORT": "80",
        "HTTP_HOST": "192.0.2.10", "REQUEST_SCHEME": "http",
        "HTTPS": "off", "HTTP_ORIGIN": "http://192.0.2.10",
        "HTTP_SEC_FETCH_SITE": "same-origin",
        "HTTP_X_REQUESTED_WITH": "IssueTrackerManualControl",
        "CONTENT_TYPE": "application/x-www-form-urlencoded",
        "CONTENT_LENGTH": str(len(body)),
    }


class ManualChannelDirectTests(unittest.TestCase):
    def test_cgi_accepts_only_server_principal_and_one_panel_intent(self):
        body = b"action=preview&panel=Switch+Status"
        request = validate_ingress(valid_env(body), body)
        self.assertEqual({"action": "preview", "panel": "Switch Status",
                          "principal": "nvis"}, request)
        self.assertNotIn("rows", request)
        for changed in (
            {"REMOTE_USER": "anonymous"}, {"CONTROL_REQUIRE_AUTH": "0"},
            {"HTTP_ORIGIN": "http://evil.invalid"},
            {"HTTP_HOST": "evil.invalid"}, {"PATH_INFO": "/suffix"},
            {"SCRIPT_NAME": "/cgi-bin/other"},
            {"HTTP_X_REQUESTED_WITH": ""}, {"SERVER_PORT": "8080"},
        ):
            with self.subTest(changed=changed), self.assertRaises(ManualChannelHold):
                validate_ingress({**valid_env(body), **changed}, body)
        for invalid in (
            b"action=preview&panel=Switch+Status&rows=forged",
            b"action=preview&panel=Switch+Status&panel=IB+Link+Validation",
            b"action=preview&panel=all",
            b"action=confirm&panel=Switch+Status&token=fake",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ManualChannelHold):
                validate_ingress(valid_env(invalid), invalid)

    def test_cgi_worker_absence_fails_before_any_accepted_job(self):
        body = b"action=preview&panel=Switch+Status"
        submit = mock.Mock(side_effect=FileNotFoundError("worker absent"))
        status, payload = cgi.handle(valid_env(body), body, submit=submit)
        self.assertEqual("503 Service Unavailable", status)
        self.assertEqual("manual_worker_unavailable", payload["error"])
        submit.assert_called_once_with({"action": "preview", "panel": "Switch Status",
                                        "principal": "nvis"})

    def test_queue_is_private_atomic_and_crash_never_replays_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "manual"
            root.mkdir(mode=0o700)
            queue = DurableManualQueue(root, boot_id="boot-a")
            request = {"action": "preview", "panel": "Switch Status",
                       "principal": "nvis"}
            job = queue.enqueue(request)
            self.assertEqual([job], queue.pending_ids())
            self.assertEqual(0o700, root.stat().st_mode & 0o777)
            claim = queue.claim()
            self.assertEqual((job, request), claim)
            self.assertEqual([], queue.pending_ids())
            self.assertIsNone(DurableManualQueue(root, boot_id="boot-b").claim())
            self.assertEqual("unknown_after_claim", queue.status(job)["state"])
            self.assertEqual([], queue.pending_ids())
            with self.assertRaises(ManualChannelHold):
                DurableManualQueue(root, boot_id="boot-b").complete(
                    job, {"error": "manual_hold"})

    def test_queue_rejects_symlink_or_corrupt_payload_without_dispatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "manual"
            root.mkdir(mode=0o700)
            queue = DurableManualQueue(root, boot_id="boot-a")
            target = root / ("pending-" + "0" * 32 + ".json")
            target.symlink_to(root / "outside")
            with self.assertRaises(ManualChannelHold):
                queue.claim()
            target.unlink()
            target.write_text('{"action":"preview"}', encoding="utf-8")
            os.chmod(target, 0o600)
            with self.assertRaises(ManualChannelHold):
                queue.claim()

    def test_queue_short_writes_are_fully_durable_and_unknown_ids_are_not_queued(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "manual"
            root.mkdir(mode=0o700)
            queue = DurableManualQueue(root, boot_id="boot-a")
            actual_write = os.write

            def partial_write(fd, body):
                return actual_write(fd, body[:max(1, len(body) // 3)])

            with mock.patch("monitor.issue_tracker_manual_channel.os.write",
                            side_effect=partial_write):
                job = queue.enqueue({"action": "preview", "panel": "Switch Status",
                                     "principal": "nvis"})
            self.assertEqual(job, queue.claim()[0])
            self.assertEqual("unknown_after_claim", queue.status(job)["state"])
            self.assertEqual("unknown_job", queue.status("f" * 32)["state"])

    def test_cgi_rejects_broken_or_non_object_worker_result(self):
        body = b"action=preview&panel=Switch+Status"
        for result in ([], "ok", None, {"error": "unexpected"}):
            with self.subTest(result=result):
                status, payload = cgi.handle(valid_env(body), body,
                                             submit=lambda request: result)
                self.assertEqual("503 Service Unavailable", status)
                self.assertEqual("manual_worker_unavailable", payload["error"])


if __name__ == "__main__":
    unittest.main()
