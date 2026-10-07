"""REQ7 generated browser form and exact CGI ingress remain fail-closed."""

from pathlib import Path
import importlib.util
from importlib.machinery import SourceFileLoader
import os
import tempfile
import unittest

from test_cases.test_issue_tracker_manual_ui import browser_settings_script, page


ROOT = Path(__file__).resolve().parents[1]
CGI_PATH = ROOT / "monitor/issue-tracker-control.cgi"
SPEC = importlib.util.spec_from_loader(
    "req7_manual_ui_cgi", SourceFileLoader("req7_manual_ui_cgi", str(CGI_PATH))
)
CGI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CGI)


def environ(body):
    return {
        "CONTROL_REQUIRE_AUTH": "1", "AUTH_TYPE": "Basic",
        "REMOTE_USER": "nvis", "SCRIPT_NAME": "/monitor/control/issue-tracker",
        "PATH_INFO": "", "REQUEST_METHOD": "POST", "REQUEST_SCHEME": "http",
        "HTTPS": "off", "HTTP_X_REQUESTED_WITH": "IssueTrackerManualControl",
        "CONTENT_TYPE": "application/x-www-form-urlencoded",
        "CONTENT_LENGTH": str(len(body)), "SERVER_ADDR": "127.0.0.1",
        "CONTROL_SERVICE_PORT": "80", "SERVER_PORT": "80",
        "HTTP_HOST": "127.0.0.1", "HTTP_ORIGIN": "http://127.0.0.1",
        "HTTP_SEC_FETCH_SITE": "same-origin",
    }


class ManualUiIngressWorkflowTests(unittest.TestCase):
    def test_generated_k_intent_crosses_cgi_queue_and_real_durable_settings_chain(self):
        from monitor.issue_tracker_manual_channel import DurableManualQueue, ManualQueueWorker
        from monitor.issue_tracker_manual_preview import ManualPreviewBroker
        from monitor.issue_tracker_state_owner import (
            current_k, initialize_tracker_state, set_k, tracker_writer,
        )

        browser = browser_settings_script(r'''
replies.push(settings('3','0'));
await issueTrackerSettingsRead('IB Link Validation');
elements['issue-tracker-itop-k'].value='7';
replies.push(settings('7','1','committed'));
await issueTrackerSettingsSave('IB Link Validation');
console.log(JSON.stringify({calls}));
''')
        with tempfile.TemporaryDirectory(prefix="req7-browser-k-workflow-") as directory:
            project = Path(os.path.realpath(directory)) / "project"
            project.mkdir()
            publication = project / "99-output-monitor"
            publication.mkdir()
            initialize_tracker_state(project, publication,
                initialized_at="2026-09-25T00:00:00Z", acquisition_id="browser-k-first-use")
            queue_root = project / ".tracker/browser-queue"
            queue_root.mkdir(mode=0o700)
            queue = DurableManualQueue(queue_root, boot_id="browser-fixture")

            def query():
                with tracker_writer(project, publication) as token:
                    state = current_k(token)
                    return {"settings": "current", "k": state.k, "revision": state.revision,
                            "event_sha256": state.event_sha256,
                            "online": "disabled_no_send_authority"}

            def change(principal, k, revision, request_id):
                with tracker_writer(project, publication) as token:
                    receipt = set_k(token, new_k=k, expected_revision=revision,
                        actor="operator:" + principal, request_id=request_id,
                        recorded_at="2026-09-25T00:01:00Z")
                    return {"settings": "committed", "k": receipt.k,
                            "revision": receipt.revision, "event_sha256": receipt.event_sha256,
                            "replay": receipt.replay, "online": "disabled_no_send_authority"}

            broker = ManualPreviewBroker(lambda: self.fail("K query must not qualify rows"),
                lambda *_: self.fail("K save must not publish workbook"),
                read_settings=query, change_settings=change)
            worker = ManualQueueWorker(queue, broker)

            def submit(request):
                job = queue.enqueue(request)
                completed, result = worker.process_job(job)
                self.assertEqual(job, completed)
                self.assertEqual("done", queue.status(job)["state"])
                return result

            results = []
            for call in browser["calls"]:
                body = call["body"].encode("ascii")
                environment = {**environ(body), "HTTP_ACCEPT": call["headers"]["Accept"]}
                status, result = CGI.handle(environment, body, submit=submit)
                self.assertEqual("200 OK", status)
                results.append(result)
            self.assertEqual(("3", "0"), (results[0]["k"], results[0]["revision"]))
            self.assertEqual(("7", "1", False),
                             (results[1]["k"], results[1]["revision"], results[1]["replay"]))
            self.assertEqual(2, len(tuple((project / ".tracker/settings/events").glob("*.json"))))
            self.assertEqual((), tuple(publication.iterdir()))
            self.assertFalse(any((project / ".tracker/generations").glob("*/RECEIPT")))

    def test_opt_in_page_uses_exact_cgi_request_without_client_rows_or_secrets(self):
        rendered = page(local_ui=True)
        self.assertIn("const ISSUE_TRACKER_MANUAL_URL = '/monitor/control/issue-tracker'", rendered)
        self.assertIn("'X-Requested-With': 'IssueTrackerManualControl'", rendered)
        self.assertIn("credentials: 'same-origin'", rendered)
        self.assertIn('new URLSearchParams({action: "preview", panel})', rendered)
        self.assertIn('new URLSearchParams({', rendered)
        for panel in ("Switch Status", "Eth Link Validation", "IB Link Validation"):
            body = ("action=preview&panel=" + panel.replace(" ", "+")).encode()
            captured = []
            status, _ = CGI.handle(environ(body), body,
                                   submit=lambda request: captured.append(request) or
                                   {"error": "manual_hold"})
            self.assertEqual("409 Conflict", status)
            self.assertEqual([{"action": "preview", "panel": panel,
                               "principal": "nvis"}], captured)

    def test_extra_browser_row_or_credential_is_not_an_authorized_request(self):
        for extra in (b"&row=1", b"&credential=secret", b"&project_path=x"):
            body = b"action=preview&panel=Switch+Status" + extra
            submitted = []
            status, _ = CGI.handle(environ(body), body,
                                   submit=lambda request: submitted.append(request))
            self.assertEqual("403 Forbidden", status)
            self.assertEqual([], submitted)
        self.assertNotIn('/monitor/control/issue-tracker', page())


if __name__ == "__main__":
    unittest.main()
