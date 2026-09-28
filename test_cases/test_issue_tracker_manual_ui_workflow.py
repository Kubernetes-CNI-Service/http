"""REQ7 generated browser form and exact CGI ingress remain fail-closed."""

from pathlib import Path
import importlib.util
from importlib.machinery import SourceFileLoader
import unittest

from test_cases.test_issue_tracker_manual_ui import page


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
