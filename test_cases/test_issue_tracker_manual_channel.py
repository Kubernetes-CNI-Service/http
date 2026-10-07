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
    def test_decimal_settings_projection_preserves_large_integer_after_exact_worker_receipt(self):
        body = b"action=settings&panel=Switch+Status"
        environment = {**valid_env(body),
                       "HTTP_ACCEPT": "application/vnd.http.issue-tracker.settings+json"}
        native = {"settings": "current", "k": 9007199254740993,
                  "revision": 9007199254740995, "event_sha256": "d" * 64,
                  "online": "disabled_no_send_authority"}
        expected = {"settings": "current", "k": "9007199254740993",
                    "revision": "9007199254740995", "event_sha256": "d" * 64,
                    "online": "disabled_no_send_authority"}
        self.assertEqual(("200 OK", expected), cgi.handle(
            environment, body, submit=lambda _: native))
        # Negotiation changes representation, never the worker's typed
        # contract: strings/flags/partial replies still cannot be receipts.
        for invalid in (expected, {**native, "k": True}, {"success": True}):
            with self.subTest(invalid=invalid):
                self.assertEqual("503 Service Unavailable", cgi.handle(
                    environment, body, submit=lambda _: invalid)[0])

    def test_authenticated_settings_forms_are_exact_typed_intents(self):
        read = b"action=settings&panel=Switch+Status"
        self.assertEqual({"action": "settings", "panel": "Switch Status",
                          "principal": "nvis"}, validate_ingress(valid_env(read), read))
        body = (b"action=set_k&panel=IB+Link+Validation&new_k=5000"
                b"&expected_revision=12&request_id=" + b"a" * 32)
        self.assertEqual({"action": "set_k", "panel": "IB Link Validation",
                          "principal": "nvis", "new_k": 5000,
                          "expected_revision": 12, "request_id": "a" * 32},
                         validate_ingress(valid_env(body), body))

    def test_settings_form_rejects_noncanonical_values_and_browser_authority(self):
        base = (b"action=set_k&panel=Switch+Status&new_k=5"
                b"&expected_revision=0&request_id=" + b"b" * 32)
        for body in (
            *(base.replace(b"new_k=5", b"new_k=" + value)
              for value in (b"0", b"-1", b"true", b"5.0", b"05", b"%2B5", b"")),
            base.replace(b"expected_revision=0", b"expected_revision=01"),
            base.replace(b"request_id=" + b"b" * 32, b"request_id=bad/path"),
            base + b"&actor=operator:root", base + b"&principal=cumulus",
            base + b"&recorded_at=2026-01-01T00:00:00Z", base + b"&project=/tmp/x",
            base + b"&new_k=6",
        ):
            with self.subTest(body=body), self.assertRaises(ManualChannelHold):
                validate_ingress(valid_env(body), body)

    def test_settings_socket_request_rejects_bool_and_untrusted_extra_fields(self):
        from monitor.issue_tracker_manual_channel import _request
        request = {"action": "set_k", "panel": "Switch Status", "principal": "nvis",
                   "new_k": 5, "expected_revision": 0, "request_id": "c" * 32}
        self.assertEqual(request, _request(request))
        for altered in ({**request, "new_k": True},
                        {**request, "expected_revision": False},
                        {**request, "actor": "operator:root"},
                        {**request, "request_id": "../outside"}):
            with self.subTest(altered=altered), self.assertRaises(ManualChannelHold):
                _request(altered)

    def test_cgi_requires_exact_settings_receipt_not_success_flag(self):
        body = b"action=settings&panel=Switch+Status"
        valid = {"settings": "current", "k": 3, "revision": 0,
                 "event_sha256": "d" * 64, "online": "disabled_no_send_authority"}
        for result in ({"success": True}, {**valid, "k": True},
                       {**valid, "credential": "secret"}, {**valid, "revision": -1},
                       {**valid, "online": "sent"}, {**valid, "settings": "committed"}):
            with self.subTest(result=result):
                status, response = cgi.handle(valid_env(body), body, submit=lambda _: result)
                self.assertEqual("503 Service Unavailable", status)
                self.assertEqual({"error": "manual_worker_unavailable"}, response)
        self.assertEqual(("200 OK", valid), cgi.handle(
            valid_env(body), body, submit=lambda _: valid))

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

    def test_cgi_unsafe_socket_metadata_returns_stable_unavailable(self):
        body = b"action=preview&panel=Switch+Status"
        with tempfile.TemporaryDirectory() as tmp:
            unsafe_endpoint = Path(tmp) / "not-a-socket"
            unsafe_endpoint.write_text("unsafe", encoding="utf-8")
            with mock.patch.object(cgi, "SOCKET_PATH", unsafe_endpoint):
                status, payload = cgi.handle(valid_env(body), body)
        self.assertEqual("503 Service Unavailable", status)
        self.assertEqual({"error": "manual_worker_unavailable"}, payload)

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

    def test_worker_exact_job_cannot_return_another_principals_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "manual"
            root.mkdir(mode=0o700)
            queue = DurableManualQueue(root, boot_id="boot-a")
            first = queue.enqueue({"action": "preview", "panel": "Switch Status",
                                   "principal": "nvis"})
            second = queue.enqueue({"action": "preview", "panel": "IB Link Validation",
                                    "principal": "cumulus"})

            class EchoBroker:
                def preview(self, principal, panel):
                    return {"principal": principal, "panel": panel}

            result = ManualQueueWorker(queue, EchoBroker()).process_job(second)
            self.assertEqual((second, {"principal": "cumulus",
                                       "panel": "IB Link Validation"}), result)
            self.assertEqual("queued", queue.status(first)["state"])
            self.assertEqual("done", queue.status(second)["state"])

    def test_worker_does_not_complete_a_claim_without_local_receipt_identity(self):
        class BrokenBroker:
            def confirm(self, principal, panel, token, *, confirmation):
                return {"local_applied": True}

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "manual"
            root.mkdir(mode=0o700)
            queue = DurableManualQueue(root, boot_id="boot-a")
            job = queue.enqueue({
                "action": "confirm", "panel": "Switch Status",
                "principal": "nvis", "token": "a" * 43,
                "confirmation": "publish_local",
            })
            with self.assertRaises(ManualChannelHold):
                ManualQueueWorker(queue, BrokenBroker()).process_job(job)
            self.assertEqual("unknown_after_claim", queue.status(job)["state"])
            self.assertEqual([], queue.pending_ids())

    def test_claim_never_overwrites_an_existing_unknown_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "manual"
            root.mkdir(mode=0o700)
            queue = DurableManualQueue(root, boot_id="boot-a")
            job = queue.enqueue({"action": "preview", "panel": "Switch Status",
                                 "principal": "nvis"})
            prior = root / f"claimed-{job}.json"
            prior.write_bytes(b"previous unknown claim\n")
            os.chmod(prior, 0o600)
            with self.assertRaises(ManualChannelHold):
                queue.claim(job)
            self.assertEqual(b"previous unknown claim\n", prior.read_bytes())
            self.assertEqual([job], queue.pending_ids())

    def test_cgi_rejects_broken_or_non_object_worker_result(self):
        body = b"action=preview&panel=Switch+Status"
        for result in ([], "ok", None, {"error": "unexpected"}):
            with self.subTest(result=result):
                status, payload = cgi.handle(valid_env(body), body,
                                             submit=lambda request: result)
                self.assertEqual("503 Service Unavailable", status)
                self.assertEqual("manual_worker_unavailable", payload["error"])

    def test_confirm_requires_a_complete_local_receipt_not_a_success_flag(self):
        body = (b"action=confirm&panel=Switch+Status&token=" + b"a" * 43
                + b"&confirmation=publish_local")
        committed = {
            "local": "committed", "local_applied": True,
            "generation_id": "gen-" + "0" * 19 + "1-" + "a" * 32,
            "manifest_id": "b" * 64,
            "published_sha256": "c" * 64,
            "online": "disabled_no_send_authority",
        }
        for false_receipt in (
            {"local_applied": True},
            {**committed, "manifest_id": "bad"},
            {**committed, "published_sha256": "bad"},
            {**committed, "online": "enabled"},
            {**committed, "credentials": "must-not-echo"},
            {**committed, "local_applied": 1},
        ):
            with self.subTest(false_receipt=false_receipt):
                status, payload = cgi.handle(valid_env(body), body,
                                             submit=lambda request: false_receipt)
                self.assertEqual("503 Service Unavailable", status)
                self.assertEqual({"error": "manual_worker_unavailable"}, payload)
        status, payload = cgi.handle(valid_env(body), body,
                                     submit=lambda request: committed)
        self.assertEqual("200 OK", status)
        self.assertEqual(committed, payload)
        noop = {
            "local": "no_change", "local_applied": False,
            "manifest_id": "d" * 64,
            "online": "disabled_no_send_authority",
        }
        status, payload = cgi.handle(valid_env(body), body,
                                     submit=lambda request: noop)
        self.assertEqual("200 OK", status)
        self.assertEqual(noop, payload)


if __name__ == "__main__":
    unittest.main()
