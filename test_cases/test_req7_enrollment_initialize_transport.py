"""Independent child/wire and launcher contract; SOURCE, not native TLS proof.

The child tests use real private four-file images and replace ONLY external TLS,
stdin/stdout and root-UID observation. Launcher direct tests explicitly double
admission and supervision; they do not prove authentication or process cleanup.
"""
import hashlib
import importlib
import inspect
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock
import test_cases

ROOT = Path(test_cases.__file__).resolve().parents[1]
SOURCE = ROOT / "monitor/issue_tracker_enrollment_initialize.py"
TARGET = "synthetic_spreadsheet_id_0001"
TITLES = ("GPU Server", "ETH&IB Switch", "ETH Cabling", "IB Cabling", "Dashboard", "Update_History",
          "Inventory", "ServerProfile", "PortProfile", "CVT_SUM", "CVT_Import", "Agent_status", "Whitelist", "BasicData")
ROWS = (("ETH&IB Switch", 101, "a" * 64), ("ETH Cabling", 102, "b" * 64),
        ("IB Cabling", 103, "c" * 64), ("Update_History", 105, "d" * 64))
NONCE = "f" * 64


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode()


def literal_body():
    return canonical({"requests": [{"createDeveloperMetadata": {"developerMetadata": {
        "metadataKey": "http-ztp-enrollment-v1", "metadataValue": nonce, "visibility": "DOCUMENT",
        "location": {"sheetId": sid}}}} for title, sid, nonce in ROWS], "includeSpreadsheetInResponse": False})


def literal_frame(data=b'{"replies":[]}'):
    return canonical({"schema_version": 1, "nonce": NONCE, "wire_sha256": hashlib.sha256(literal_body()).hexdigest(),
                      "status": 200, "size": len(data), "response_sha256": hashlib.sha256(data).hexdigest()}) + data


class Req7EnrollmentInitializeTransportTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SOURCE.is_file(), "REQ7 fixed enrollment child/launcher capability missing")
        self.module = importlib.import_module("monitor.issue_tracker_enrollment_initialize")
        for name in ("_initialize_child", "_send_initialize_once", "_decode_initialize_completion"):
            self.assertTrue(callable(getattr(self.module, name, None)), "REQ7 initialize transport API missing: " + name)
        from monitor.issue_tracker_online_target import OnlineTargetBinding
        from monitor.issue_tracker_sdk_authentication import AuthenticatedToken
        from monitor.issue_tracker_sheets_read_decode import ObservedTemplateIdentity
        from monitor.issue_tracker_enrollment_journal import JournaledEnrollments
        self.binding = OnlineTargetBinding(TARGET, "1" * 64, "2" * 64)
        self.token = AuthenticatedToken("SYNTHETIC_TOKEN", time.time() + 3600)
        self.identity = ObservedTemplateIdentity(TARGET, tuple((title, 100 + index) for index, title in enumerate(TITLES)), "3" * 64)
        self.journal = JournaledEnrollments(ROWS, "4" * 64)

    def prepared(self):
        from monitor.issue_tracker_enrollment_protocol import prepare_enrollment_mutation
        return prepare_enrollment_mutation(self.binding, self.token, self.identity, self.journal)

    def private(self, **extra):
        return canonical({"schema_version": 1, "nonce": NONCE, "spreadsheet_id": TARGET,
                          "allowlist_sha256": "1" * 64, "policy_sha256": "2" * 64,
                          "token": self.token.value, "expires_at": self.token.expires_at, **extra})

    def files(self, root, *, wrong_marker=False, wrong_wire=False):
        nonces = canonical([list(row) for row in ROWS])
        header = canonical({"schema_version": 1, "spreadsheet_id": TARGET,
                            "sheet_ids": [[title, 100 + index] for index, title in enumerate(TITLES)],
                            "nonces_sha256": hashlib.sha256(nonces).hexdigest()})
        marker = canonical({"schema_version": 1, "state": "INITIALIZED",
                            "header_sha256": "0" * 64 if wrong_marker else hashlib.sha256(header).hexdigest()})
        fds = []
        for name, data in zip(("HEADER", "NONCES", "INITIALIZED", "WIRE"),
                              (header, nonces, marker, b"{}\n" if wrong_wire else literal_body())):
            path = root / name
            with path.open("xb") as stream: stream.write(data)
            path.chmod(0o600); fds.append(os.open(path, os.O_RDONLY | os.O_NOFOLLOW))
        return fds

    def invoke_child(self, fds, native, private=None):
        from monitor import issue_tracker_tls_inputs as tls
        output = bytearray()
        def write(fd, data):
            self.assertEqual(fd, 1); output.extend(data); return len(data)
        with mock.patch.object(self.module.os, "geteuid", return_value=0), \
             mock.patch.object(self.module.os, "read", side_effect=[self.private() if private is None else private, b""]), \
             mock.patch.object(self.module.os, "write", side_effect=write), \
             mock.patch.object(tls, "_native_complete_read", side_effect=native) as transport:
            code = self.module._initialize_child(NONCE, *fds)
        return code, bytes(output), transport

    def test_real_four_images_bind_fixed_wire_and_return_complete_nonce_correlated_frame(self):
        def native(prepared):
            self.assertEqual((prepared.host, prepared.path, prepared.method, prepared.budget_seconds),
                             ("sheets.googleapis.com", "/v4/spreadsheets/" + TARGET + ":batchUpdate", "POST", 60.0))
            self.assertEqual(prepared.body, literal_body())
            return SimpleNamespace(status=200, complete=True, data=b'{"replies":[]}')
        with tempfile.TemporaryDirectory(prefix="req7-init-child-") as raw:
            fds = self.files(Path(raw))
            try:
                code, output, transport = self.invoke_child(fds, native)
                self.assertEqual(code, 0); self.assertEqual(output, literal_frame()); self.assertEqual(transport.call_count, 1)
                for fd in fds: self.assertGreater(os.fstat(fd).st_size, 0)  # Borrowed files remain open.
            finally:
                for fd in fds: os.close(fd)

    def test_wrong_marker_or_wire_cannot_reach_native_or_emit_a_frame(self):
        for mode in ("marker", "wire"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix="req7-init-refuse-") as raw:
                fds = self.files(Path(raw), wrong_marker=mode == "marker", wrong_wire=mode == "wire")
                try:
                    code, output, transport = self.invoke_child(fds, AssertionError("No send from changed original"))
                    self.assertEqual(code, 1); self.assertEqual(output, b""); transport.assert_not_called()
                finally:
                    for fd in fds: os.close(fd)

    def test_private_url_budget_body_override_and_incomplete_native_response_are_denied(self):
        with tempfile.TemporaryDirectory(prefix="req7-init-private-") as raw:
            fds = self.files(Path(raw))
            try:
                for extra in ({"url": "https://example.invalid"}, {"budget": 999}, {"body": "foreign"}):
                    code, output, transport = self.invoke_child(fds, AssertionError("No override"), self.private(**extra))
                    self.assertEqual((code, output), (1, b"")); transport.assert_not_called()
                code, output, transport = self.invoke_child(fds, lambda prepared: SimpleNamespace(status=200, complete=False, data=b"{}"))
                self.assertEqual((code, output), (1, b"")); self.assertEqual(transport.call_count, 1)
            finally:
                for fd in fds: os.close(fd)

    def test_raw_frame_requires_exact_nonce_wire_length_hash_and_no_trailing_body(self):
        prepared = self.prepared()
        observed = self.module._decode_initialize_completion(literal_frame(), NONCE, prepared)
        self.assertEqual(observed.response.data, b'{"replies":[]}')
        self.assertTrue(observed.termination_confirmed)
        for raw in (literal_frame() + b"x", literal_frame().replace(NONCE.encode(), b"e" * 64, 1),
                    literal_frame().replace(hashlib.sha256(literal_body()).hexdigest().encode(), b"0" * 64, 1),
                    literal_frame().replace(b'"size":14', b'"size":13', 1)):
            with self.subTest(raw=raw[:32]), self.assertRaises(self.module.InitializeTransportHold):
                self.module._decode_initialize_completion(raw, NONCE, prepared)

    def test_launcher_fixed_argv_six_inherited_fds_and_post_pipe_final_checks(self):
        from monitor import issue_tracker_history_read_launcher as reads
        parameter = inspect.signature(self.module._send_initialize_once).parameters.get("_template_reads")
        self.assertIsNotNone(parameter, "REQ7 original template cohort must reach the final launch boundary")
        self.assertIs(parameter.kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertIs(parameter.default, inspect.Parameter.empty)
        cohort = (object(), object(), object(), object())  # Direct-only issued-read seam, NOT authority.
        prepared = self.prepared(); events = []
        class Stream:
            def close(self): events.append("pipe-close")
        process = SimpleNamespace(stdin=Stream(), stdout=Stream(), stderr=Stream())
        project = SimpleNamespace(lock_fd=31)
        original = (project, 32, ("original-images",), prepared)
        def originals(*args): events.append("original-check"); return original
        def group(*args):
            self.assertEqual(args[-1], (("template_identity", None, None, cohort[0]),
                ("template_headers", None, None, cohort[1]), ("whitelist", None, None, cohort[2]),
                ("metadata", None, None, cohort[3])))
            events.append("template-final-check")
        def supervised(child, **kwargs):
            self.assertIs(child, process); self.assertEqual(kwargs["kind"], "mutation")
            private = json.loads(kwargs["request_bytes"])
            self.assertEqual(set(private), {"schema_version", "nonce", "spreadsheet_id", "allowlist_sha256", "policy_sha256", "token", "expires_at"})
            self.assertEqual(private["nonce"], NONCE); events.append("supervise")
            return SimpleNamespace(termination_confirmed=True, data=literal_frame())
        with mock.patch.object(self.module, "_parent_originals", side_effect=originals), \
             mock.patch.object(reads, "_require_current_owned_project_read_group", side_effect=group), \
             mock.patch.object(self.module.secrets, "token_hex", return_value=NONCE), \
             mock.patch.object(self.module.subprocess, "Popen", return_value=process) as popen, \
             mock.patch.object(self.module, "supervise_owned_attempt", side_effect=supervised):
            result = self.module._send_initialize_once(object(), object(), self.binding,
                SimpleNamespace(token=self.token), self.identity, self.journal, 41, 42, 43, 44,
                _template_reads=cohort)
        self.assertEqual(events, ["original-check", "template-final-check", "supervise", "pipe-close", "pipe-close", "pipe-close", "original-check"])
        args, kwargs = popen.call_args
        self.assertEqual(args[0], [str(Path(sys.executable).resolve(strict=True)), "-I", "-B", "-c",
            self.module._INITIALIZE_CHILD_PROGRAM, str(self.module._SOURCE_ROOT), NONCE, "41", "42", "43", "44"])
        self.assertEqual(kwargs["pass_fds"], (31, 32, 41, 42, 43, 44))
        self.assertEqual(kwargs["env"], {"LC_ALL": "C"}); self.assertTrue(kwargs["close_fds"])
        self.assertTrue(kwargs["start_new_session"])
        self.assertEqual(result.response.data, b'{"replies":[]}')

    def test_unconfirmed_supervision_or_pending_interrupt_cannot_return_completion(self):
        from monitor.issue_tracker_attempt_supervision import AttemptHold
        from monitor import issue_tracker_history_read_launcher as reads
        parameter = inspect.signature(self.module._send_initialize_once).parameters.get("_template_reads")
        self.assertIsNotNone(parameter, "REQ7 original template cohort must reach the final launch boundary")
        self.assertIs(parameter.kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertIs(parameter.default, inspect.Parameter.empty)
        cohort = (object(), object(), object(), object())
        prepared = self.prepared(); project = SimpleNamespace(lock_fd=31)
        interrupt = KeyboardInterrupt("synthetic-stop")
        class Stream:
            def close(self): raise OSError("synthetic-close-failure")
        process = SimpleNamespace(stdin=Stream(), stdout=Stream(), stderr=Stream())
        for primary in (AttemptHold(False), interrupt):
            with self.subTest(kind=type(primary).__name__), \
                 mock.patch.object(self.module, "_parent_originals", return_value=(project, 32, (), prepared)), \
                 mock.patch.object(reads, "_require_current_owned_project_read_group"), \
                 mock.patch.object(self.module.secrets, "token_hex", return_value=NONCE), \
                 mock.patch.object(self.module.subprocess, "Popen", return_value=process), \
                 mock.patch.object(self.module, "supervise_owned_attempt", side_effect=primary):
                try:
                    self.module._send_initialize_once(object(), object(), self.binding, SimpleNamespace(token=self.token),
                        self.identity, self.journal, 41, 42, 43, 44, _template_reads=cohort)
                except BaseException as error:
                    if primary is interrupt: self.assertIs(error, interrupt)
                    else: self.assertIs(type(error), self.module.InitializeTransportHold); self.assertFalse(error.termination_confirmed)
                else: self.fail("Unknown/interrupt must not emit a completion")

    def test_template_cohort_expiring_during_original_checks_refuses_before_any_child(self):
        from monitor import issue_tracker_history_read_launcher as reads
        parameter = inspect.signature(self.module._send_initialize_once).parameters.get("_template_reads")
        self.assertIsNotNone(parameter, "REQ7 original template cohort must reach the final launch boundary")
        self.assertIs(parameter.kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertIs(parameter.default, inspect.Parameter.empty)
        cohort = (object(), object(), object(), object())
        prepared = self.prepared(); events = []
        writer, owner, authentication = object(), object(), SimpleNamespace(token=self.token)
        def originals(*args):
            events.append("original-check-finished")
            return SimpleNamespace(lock_fd=31), 32, (), prepared
        def expired(actual_writer, actual_owner, actual_binding, actual_authentication, group):
            self.assertEqual(events, ["original-check-finished"])
            self.assertIs(actual_writer, writer); self.assertIs(actual_owner, owner)
            self.assertIs(actual_binding, self.binding); self.assertIs(actual_authentication, authentication)
            self.assertEqual(group, (("template_identity", None, None, cohort[0]),
                ("template_headers", None, None, cohort[1]), ("whitelist", None, None, cohort[2]),
                ("metadata", None, None, cohort[3])))
            events.append("original-cohort-expired")
            raise reads.HistoryReadLauncherHold()
        with mock.patch.object(self.module, "_parent_originals", side_effect=originals), \
             mock.patch.object(reads, "_require_current_owned_project_read_group", side_effect=expired), \
             mock.patch.object(self.module.subprocess, "Popen", side_effect=AssertionError("Expired original cohort cannot spawn")) as child, \
             mock.patch.object(self.module, "supervise_owned_attempt", side_effect=AssertionError("No child to supervise")) as supervision:
            with self.assertRaises(self.module.InitializeTransportHold) as denied:
                self.module._send_initialize_once(writer, owner, self.binding, authentication,
                    self.identity, self.journal, 41, 42, 43, 44, _template_reads=cohort)
        self.assertFalse(denied.exception.termination_confirmed)
        self.assertEqual(events, ["original-check-finished", "original-cohort-expired"])
        child.assert_not_called(); supervision.assert_not_called()
