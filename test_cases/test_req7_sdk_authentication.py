"""Independent fake-wire SDK proofs; no real credential, socket or SDK patch.

This isolated candidate is not landed or approved. The main source/test tree
remains frozen for its ongoing full run. Keys are generated only in memory.
"""

import ast
import base64
import importlib.util
import json
from pathlib import Path
import sys
import threading
from types import SimpleNamespace
import unittest
from unittest import mock
from urllib.parse import parse_qs
import test_cases

ROOT = Path(test_cases.__file__).resolve().parents[1]
CANDIDATE = Path(__file__).resolve().parents[1]
MODULE = CANDIDATE / "monitor/issue_tracker_sdk_authentication.py"
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "tools"))
TOKEN_URL = "https://oauth2.googleapis.com/token"
SCOPE = "https://www.googleapis.com/auth/spreadsheets"


def load():
    if not MODULE.is_file(): raise AssertionError("REQ7 public SDK authentication bridge missing")
    spec = importlib.util.spec_from_file_location("monitor.issue_tracker_sdk_authentication", MODULE)
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def fresh_info():
    from req7_dependency_contract import load_dependency_contract, installed_dependency_identity
    installed_dependency_identity(load_dependency_contract(ROOT))
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return {"type": "service_account", "client_email": "synthetic-account@example.invalid",
            "token_uri": TOKEN_URL, "universe_domain": "googleapis.com",
            "private_key": key.private_bytes(serialization.Encoding.PEM,
                                               serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()).decode()}


def parsed_info(mapping):
    from monitor.issue_tracker_credential_shape import parse_service_account_info
    return parse_service_account_info(json.dumps(mapping).encode())


class FakeTokenUnit:
    """Injection is at the whole wire-unit boundary, never inside the SDK."""
    def __init__(self, *, status=200, data=None, failure=None):
        self.status = status; self.failure = failure; self.calls = []
        self.data = (b'{"access_token":"sentinel","expires_in":3600,"token_type":"Bearer"}'
                     if data is None else data)

    def send_once(self, request):
        self.calls.append(request)
        if self.failure is not None: raise self.failure
        return SimpleNamespace(status=self.status, headers=(("content-type", "application/json"),),
                               data=self.data, complete=True)


class Req7SdkAuthenticationDirectTests(unittest.TestCase):
    def setUp(self): self.module = load()

    def test_g1_cloud_project_requires_fixed_source_and_native_auth_without_caller_unit(self):
        self.assertTrue(hasattr(self.module, '_fixed_cloud_project_inputs'),
                        'G1 cannot infer authentication project from visible metadata')
        self.assertTrue(hasattr(self.module, '_refresh_fixed_cloud_project'),
                        'G1 project-scoped auth needs the actual fixed native OAuth path')
        from monitor import issue_tracker_credential_shape as private
        with mock.patch.object(self.module.os, 'geteuid', return_value=501), \
                mock.patch.object(private, '_read_private_file') as reader:
            with self.assertRaises(self.module.AuthenticationHold): self.module._fixed_cloud_project_inputs()
            reader.assert_not_called()
        mapping=fresh_info()
        for project in (None, True, 7, '', 'foreign project', '../synthetic-cloud', 'synthetic-cloud\n'):
            altered=dict(mapping)
            if project is not None: altered['project_id']=project
            with self.subTest(project_type=type(project).__name__), \
                    mock.patch.object(self.module.os, 'geteuid', return_value=0), \
                    mock.patch.object(private, '_read_private_file', return_value=json.dumps(altered).encode()) as reader, \
                    mock.patch.object(self.module, '_sdk') as sdk:
                with self.assertRaises(self.module.AuthenticationHold) as caught: self.module._fixed_cloud_project_inputs()
                self.assertIsNone(caught.exception.__context__)
                self.assertEqual([mock.call('cre.json')],reader.call_args_list); sdk.assert_not_called()
        with self.assertRaises(TypeError): self.module._refresh_fixed_cloud_project(FakeTokenUnit())

    def test_native_source_root_is_not_rebound_by_the_test_loader(self):
        self.assertEqual(MODULE.resolve().parents[1], self.module.SOURCE_ROOT)

    def test_exact_one_shot_complete_200_is_immutable_and_has_no_network_of_its_own(self):
        unit = FakeTokenUnit(); request = self.module.OneShotTokenRequest(unit)
        with mock.patch("socket.socket", side_effect=AssertionError("real network forbidden")):
            response = request(TOKEN_URL, method="POST", body=b"grant_type=synthetic", headers={
                "Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(200, response.status)
        self.assertEqual(unit.data, response.data)
        self.assertEqual(1, len(unit.calls))
        self.assertEqual(TOKEN_URL, unit.calls[0].url)
        self.assertEqual("POST", unit.calls[0].method)
        self.assertEqual(b"grant_type=synthetic", unit.calls[0].body)
        self.assertNotIn("sentinel", repr(response))
        self.assertNotIn("grant_type=synthetic", repr(unit.calls[0]))
        with self.assertRaises(AttributeError): response.status = 429

    def test_every_non_200_is_sanitized_transport_error_not_sdk_retry_input(self):
        from req7_dependency_contract import load_dependency_contract, installed_dependency_identity
        installed_dependency_identity(load_dependency_contract(ROOT))
        from google.auth.exceptions import TransportError
        for status in (100, 201, 204, 301, 302, 307, 308, 400, 401, 403, 429, 500, 502, 503):
            unit = FakeTokenUnit(status=status, data=b"sentinel")
            request = self.module.OneShotTokenRequest(unit)
            with self.subTest(status=status), self.assertRaises(TransportError) as caught:
                request(TOKEN_URL, method="POST", body=b"x", headers={
                    "Content-Type": "application/x-www-form-urlencoded"})
            self.assertEqual("req7_token_transport_denied", str(caught.exception))
            self.assertIsNone(caught.exception.__cause__)
            self.assertIsNone(caught.exception.__context__)
            self.assertEqual(1, len(unit.calls))

    def test_second_callback_refuses_before_unit_regardless_of_first_outcome(self):
        for status in (200, 429, 503):
            unit = FakeTokenUnit(status=status); request = self.module.OneShotTokenRequest(unit)
            arguments = dict(method="POST", body=b"x", headers={"Content-Type": "application/x-www-form-urlencoded"})
            if status == 200: request(TOKEN_URL, **arguments)
            else:
                with self.assertRaises(Exception): request(TOKEN_URL, **arguments)
            with self.subTest(status=status), self.assertRaises(Exception): request(TOKEN_URL, **arguments)
            self.assertEqual(1, len(unit.calls))

    def test_url_method_headers_and_body_bounds_refuse_before_wire_send(self):
        variants = [{"url": x} for x in (
            "http://oauth2.googleapis.com/token", TOKEN_URL + "/", TOKEN_URL + "?",
            "https://oauth2.googleapis.com:443/token", "https://user@oauth2.googleapis.com/token",
            "https://sheets.googleapis.com/token", "https://OAUTH2.googleapis.com/token")]
        variants += [{"method": "GET"}, {"method": "post"}, {"body": b""}, {"body": b"x" * 65537},
                     {"body": "x"}, {"headers": {"Authorization": "sentinel"}},
                     {"headers": {"Content-Type": "application/json"}}, {"timeout": 31},
                     {"timeout": True}, {"unknown": True}]
        for variant in variants:
            unit = FakeTokenUnit(); request = self.module.OneShotTokenRequest(unit)
            args = dict(url=TOKEN_URL, method="POST", body=b"x", headers={
                "Content-Type": "application/x-www-form-urlencoded"}); args.update(variant)
            with self.subTest(variant=variant), self.assertRaises(Exception): request(**args)
            self.assertEqual([], unit.calls)

    def test_oversized_mutable_or_incomplete_response_is_never_returned_to_sdk(self):
        for data in (b"x" * (2 * 1024 * 1024 + 1), bytearray(b"{}"), "{}", b""):
            unit = FakeTokenUnit(data=data); request = self.module.OneShotTokenRequest(unit)
            with self.subTest(type=type(data).__name__), self.assertRaises(Exception):
                request(TOKEN_URL, method="POST", body=b"x", headers={
                    "Content-Type": "application/x-www-form-urlencoded"})
            self.assertEqual(1, len(unit.calls))
        unit = FakeTokenUnit()
        unit.send_once = lambda request: SimpleNamespace(status=200, data=b"{}", headers=(), complete=False)
        with self.assertRaises(Exception):
            self.module.OneShotTokenRequest(unit)(TOKEN_URL, method="POST", body=b"x", headers={
                "Content-Type": "application/x-www-form-urlencoded"})

    def test_response_header_and_status_contract_is_native_bounded_and_duplicate_free(self):
        variants = [("status", True), ("complete", 1), ("headers", []),
                    ("headers", (("content-type", "application/json"), ("Content-Type", "application/json"))),
                    ("headers", (("not a token", "value"),)), ("headers", (("x", "secret\r\nleak"),)),
                    ("headers", (("x", "x" * 8193),)),
                    ("headers", tuple(("x" + str(i), "x" * 8192) for i in range(9))),
                    ("headers", tuple(("x" + str(i), "") for i in range(101)))]
        for field, value in variants:
            unit = FakeTokenUnit(); send = unit.send_once
            def malformed(wire, field=field, value=value):
                response = send(wire); setattr(response, field, value); return response
            unit.send_once = malformed
            with self.subTest(field=field), self.assertRaises(Exception) as caught:
                self.module.OneShotTokenRequest(unit)(TOKEN_URL, method="POST", body=b"x", headers={
                    "Content-Type": "application/x-www-form-urlencoded"})
            self.assertEqual("req7_token_transport_denied", str(caught.exception))
            self.assertIsNone(caught.exception.__context__); self.assertEqual(1, len(unit.calls))

    def test_transport_exception_is_sanitized_without_hidden_secret_context(self):
        unit = FakeTokenUnit(failure=ValueError("sentinel")); request = self.module.OneShotTokenRequest(unit)
        with self.assertRaises(Exception) as caught:
            request(TOKEN_URL, method="POST", body=b"x", headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual("req7_token_transport_denied", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertEqual(1, len(unit.calls))

    def test_real_public_sdk_refresh_uses_one_fixed_scope_oauth_assertion_not_access_jwt(self):
        info = fresh_info(); unit = FakeTokenUnit()
        with mock.patch("socket.socket", side_effect=AssertionError("real network forbidden")):
            credential = self.module.credentials_from_validated_info(parsed_info(info))
            credential.refresh(self.module.OneShotTokenRequest(unit))
        self.assertEqual((SCOPE,), tuple(credential.scopes))
        self.assertEqual("googleapis.com", credential.universe_domain)
        self.assertEqual("sentinel", credential.token)
        self.assertEqual(1, len(unit.calls))
        form = parse_qs(unit.calls[0].body.decode(), strict_parsing=True)
        self.assertEqual({"grant_type", "assertion"}, set(form))
        self.assertEqual(["urn:ietf:params:oauth:grant-type:jwt-bearer"], form["grant_type"])
        encoded = form["assertion"][0].split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        self.assertEqual(SCOPE, claims["scope"])
        self.assertEqual("https://oauth2.googleapis.com/token", claims["aud"])
        self.assertEqual("synthetic-account@example.invalid", claims["iss"])
        self.assertNotIn("sub", claims)

    def test_real_sdk_default_backoff_never_multiplies_non_200_wire_count(self):
        info = fresh_info()
        for status in (429, 500, 503):
            unit = FakeTokenUnit(status=status, data=b'{"error":"temporarily_unavailable"}')
            with self.subTest(status=status), mock.patch("socket.socket", side_effect=AssertionError("network")), mock.patch(
                "time.sleep", side_effect=AssertionError("SDK retry/backoff is forbidden"),
            ), self.assertRaises(Exception):
                self.module.credentials_from_validated_info(parsed_info(info)).refresh(self.module.OneShotTokenRequest(unit))
            self.assertEqual(1, len(unit.calls))

    def test_forbidden_claims_universe_delegation_and_adc_shapes_never_reach_sdk(self):
        from test_cases.test_issue_tracker_credential_shape import info
        from monitor.issue_tracker_credential_shape import ParsedServiceAccountInfo
        from types import MappingProxyType
        for key, value in (("subject", "synthetic@example.invalid"), ("additional_claims", {}),
                           ("always_use_jwt_access", True), ("universe_domain", "example.invalid"),
                           ("quota_project_id", "synthetic"), ("type", "authorized_user")):
            mapping = info(); mapping[key] = value
            with self.subTest(key=key), self.assertRaises(self.module.AuthenticationHold) as caught:
                self.module.credentials_from_validated_info(ParsedServiceAccountInfo(MappingProxyType(mapping)))
            self.assertEqual("req7_authentication_denied", str(caught.exception))
            self.assertIsNone(caught.exception.__context__)

    def test_unparsed_or_forged_scope_mapping_cannot_enter_public_sdk(self):
        from test_cases.test_issue_tracker_credential_shape import info
        from monitor.issue_tracker_credential_shape import ParsedServiceAccountInfo
        from types import MappingProxyType
        for value in (info(), None, ParsedServiceAccountInfo(MappingProxyType(info()), scope="unapproved"),
                      ParsedServiceAccountInfo(info())):
            with self.subTest(kind=type(value).__name__), self.assertRaises(self.module.AuthenticationHold):
                self.module.credentials_from_validated_info(value)

    def test_dependency_drift_refuses_before_any_sdk_import_or_constructor(self):
        import builtins
        from test_cases.test_issue_tracker_credential_shape import info
        actual_import = builtins.__import__
        imports = []
        def guarded(name, *args, **kwargs):
            if name == "google" or name.startswith("google."):
                imports.append(name)
                raise AssertionError("SDK import before dependency gate")
            return actual_import(name, *args, **kwargs)
        with mock.patch("req7_dependency_contract.installed_dependency_identity", side_effect=ValueError("sentinel")), mock.patch(
            "builtins.__import__", side_effect=guarded,
        ), self.assertRaises(self.module.AuthenticationHold) as caught:
            self.module.credentials_from_validated_info(parsed_info(info()))
        self.assertEqual([], imports)
        self.assertEqual("req7_authentication_denied", str(caught.exception))
        self.assertIsNone(caught.exception.__context__)

    def test_response_fields_are_observed_once_before_the_immutable_sdk_result(self):
        observations = []
        class Response:
            def __getattribute__(self, name):
                observations.append(name)
                values = {"status": 200, "complete": True, "data": b"{}", "headers": ()}
                if observations.count(name) != 1: raise ValueError("sentinel repeated response observation")
                return values[name]
        unit = FakeTokenUnit(); unit.send_once = lambda request: Response()
        result = self.module.OneShotTokenRequest(unit)(TOKEN_URL, method="POST", body=b"x", headers={
            "Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(b"{}", result.data)
        self.assertEqual(["status", "complete", "data", "headers"], observations)

    def test_unit_method_binding_is_captured_once_and_constructor_faults_are_sanitized(self):
        unit = FakeTokenUnit(); request = self.module.OneShotTokenRequest(unit)
        forbidden_calls = []
        unit.send_once = lambda wire: forbidden_calls.append(wire)
        result = request(TOKEN_URL, method="POST", body=b"x", headers={
            "Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(200, result.status)
        self.assertEqual(1, len(unit.calls)); self.assertEqual([], forbidden_calls)
        class BrokenUnit:
            @property
            def send_once(self): raise ValueError("sentinel secret unit attribute")
        with self.assertRaises(self.module.AuthenticationHold) as caught:
            self.module.OneShotTokenRequest(BrokenUnit())
        self.assertEqual("req7_authentication_denied", str(caught.exception))
        self.assertIsNone(caught.exception.__context__)

    def test_invalid_first_callback_consumes_the_request_before_any_wire(self):
        unit = FakeTokenUnit(); request = self.module.OneShotTokenRequest(unit)
        arguments = dict(method="POST", body=b"x", headers={"Content-Type": "application/x-www-form-urlencoded"})
        with self.assertRaises(Exception): request(TOKEN_URL + "?", **arguments)
        with self.assertRaises(Exception): request(TOKEN_URL, **arguments)
        self.assertEqual([], unit.calls)

    def test_concurrent_callback_cannot_get_a_second_wire_capability(self):
        entered = threading.Event(); release = threading.Event(); results = []; failures = []
        unit = FakeTokenUnit(); original_send = unit.send_once
        def send(wire):
            entered.set()
            if not release.wait(3): raise AssertionError("bounded test rendezvous failed")
            return original_send(wire)
        unit.send_once = send
        request = self.module.OneShotTokenRequest(unit)
        def first():
            try: results.append(request(TOKEN_URL, method="POST", body=b"x", headers={
                "Content-Type": "application/x-www-form-urlencoded"}))
            except Exception as exception: failures.append(exception)
        worker = threading.Thread(target=first, daemon=True)
        try:
            worker.start(); self.assertTrue(entered.wait(3))
            with self.assertRaises(Exception):
                request(TOKEN_URL, method="POST", body=b"y", headers={
                    "Content-Type": "application/x-www-form-urlencoded"})
        finally:
            release.set(); worker.join(3)
        self.assertFalse(worker.is_alive()); self.assertEqual([], failures)
        self.assertEqual(1, len(results)); self.assertEqual(1, len(unit.calls))

    def test_public_refresh_returns_a_private_immutable_token_not_sdk_send_authority(self):
        info = parsed_info(fresh_info()); unit = FakeTokenUnit()
        import time
        with mock.patch("socket.socket", side_effect=AssertionError("real network forbidden")):
            token = self.module.refresh_validated_service_account(info, unit)
        self.assertEqual("sentinel", token.value)
        self.assertGreater(token.expires_at, time.time())
        self.assertNotIn("sentinel", repr(token))
        self.assertFalse(hasattr(token, "refresh")); self.assertFalse(hasattr(token, "before_request"))
        with self.assertRaises(AttributeError): token.value = "foreign"
        self.assertEqual(1, len(unit.calls))

    def test_malformed_200_and_unsafe_tokens_never_leak_sdk_refresh_error_context(self):
        info = parsed_info(fresh_info())
        bodies = [b"sentinel not JSON", b'{"error":"sentinel"}', b'[]', b'null']
        for value in (None, True, 42, [], "", "sentinel\r\nAuthorization: leak", "sentinel with space", "x" * 8193):
            bodies.append(json.dumps({"access_token": value, "expires_in": 3600}).encode())
        for expiry in (None, 0, -1, "sentinel"):
            bodies.append(json.dumps({"access_token": "sentinel", "expires_in": expiry}).encode())
        for body in bodies:
            unit = FakeTokenUnit(data=body)
            with self.subTest(body_kind=type(body).__name__), mock.patch("socket.socket", side_effect=AssertionError("network")), self.assertRaises(
                self.module.AuthenticationHold,
            ) as caught:
                self.module.refresh_validated_service_account(info, unit)
            self.assertEqual("req7_authentication_denied", str(caught.exception))
            self.assertIsNone(caught.exception.__cause__); self.assertIsNone(caught.exception.__context__)
            self.assertEqual(1, len(unit.calls))

    def test_refresh_wrapper_keeps_non200_to_one_unit_and_no_secret_context(self):
        info = parsed_info(fresh_info())
        for status in (301, 401, 429, 503):
            unit = FakeTokenUnit(status=status, data=b'{"error":"sentinel"}')
            with self.subTest(status=status), mock.patch("time.sleep", side_effect=AssertionError("retry")), self.assertRaises(
                self.module.AuthenticationHold,
            ) as caught:
                self.module.refresh_validated_service_account(info, unit)
            self.assertEqual(1, len(unit.calls))
            self.assertEqual("req7_authentication_denied", str(caught.exception))
            self.assertIsNone(caught.exception.__context__)


class Req7SdkFixedFdWorkflowTests(unittest.TestCase):
    def setUp(self): self.module = load()

    def test_actual_fixed_fd_mapping_consumes_public_sdk_without_path_reopen(self):
        from test_cases.test_issue_tracker_credential_fd import CredentialFdDirectTests
        # Warm the SDK through the same governed public API before installing
        # the synthetic root metadata fixture; no SDK object/method is patched.
        mapping = fresh_info(); self.module.credentials_from_validated_info(parsed_info(mapping))
        fixture = CredentialFdDirectTests("test_fixed_path_opens_relative_components_and_reads_single_held_fd_once")
        fixture.setUp(); self.addCleanup(fixture.doCleanups)
        fixture.path.write_bytes(json.dumps(mapping).encode()); fixture.path.chmod(0o600)
        credential_inode = fixture.path.stat().st_ino
        private_reads = []
        with fixture.fixture() as (opened, reads):
            original_read = self.module.os.read
            def private_read(descriptor, count):
                if self.module.os.fstat(descriptor).st_ino == credential_inode:
                    private_reads.append((descriptor, count))
                return original_read(descriptor, count)
            with mock.patch("os.read", side_effect=private_read):
                credential = self.module.credentials_from_fixed_file()
        self.assertEqual(["/", "var", "lib", "http-ztp-container", "service-account", "cre.json"],
                         [name for name in opened if name in ("/", "var", "lib", "http-ztp-container", "service-account", "cre.json")])
        self.assertEqual(1, len(private_reads))
        self.assertEqual(65537, private_reads[0][1])
        fixture.path.unlink()  # Owned fake credential only; SDK must not reopen.
        unit = FakeTokenUnit()
        with mock.patch("socket.socket", side_effect=AssertionError("real network forbidden")):
            credential.refresh(self.module.OneShotTokenRequest(unit))
        self.assertEqual("sentinel", credential.token)
        self.assertEqual(1, len(unit.calls))

    def test_nonroot_or_fixed_file_fault_refuses_before_sdk_or_token_unit(self):
        with mock.patch("os.geteuid", return_value=501), mock.patch("os.open") as opening:
            with self.assertRaises(self.module.AuthenticationHold) as caught:
                self.module.credentials_from_fixed_file()
        opening.assert_not_called()
        self.assertEqual("req7_authentication_denied", str(caught.exception))
        self.assertIsNone(caught.exception.__context__)

    def test_fixed_refresh_crosses_actual_fd_parser_dependency_gate_sdk_and_one_unit(self):
        from test_cases.test_issue_tracker_credential_fd import CredentialFdDirectTests
        mapping = fresh_info(); self.module.credentials_from_validated_info(parsed_info(mapping))
        fixture = CredentialFdDirectTests("test_fixed_path_opens_relative_components_and_reads_single_held_fd_once")
        fixture.setUp(); self.addCleanup(fixture.doCleanups)
        fixture.path.write_bytes(json.dumps(mapping).encode()); fixture.path.chmod(0o600)
        inode = fixture.path.stat().st_ino; private_reads = []
        original_read = self.module.os.read
        def read(descriptor, count):
            if self.module.os.fstat(descriptor).st_ino == inode: private_reads.append(count)
            return original_read(descriptor, count)
        unit = FakeTokenUnit(); actual_send = unit.send_once
        def send(wire):
            fixture.path.unlink()  # Only the owned fake file; no SDK reopen permitted.
            return actual_send(wire)
        unit.send_once = send
        with fixture.fixture(), mock.patch("os.read", side_effect=read), mock.patch(
            "socket.socket", side_effect=AssertionError("real network forbidden"),
        ):
            token = self.module.refresh_fixed_service_account(unit)
        self.assertEqual("sentinel", token.value); self.assertEqual([65537], private_reads)
        self.assertFalse(fixture.path.exists()); self.assertEqual(1, len(unit.calls))
        with mock.patch("os.geteuid", return_value=501), mock.patch("os.open") as opening:
            denied_unit = FakeTokenUnit()
            with self.assertRaises(self.module.AuthenticationHold):
                self.module.refresh_fixed_service_account(denied_unit)
        opening.assert_not_called(); self.assertEqual([], denied_unit.calls)

    def test_real_fixed_reader_drift_and_invalid_key_do_not_leak_or_refresh(self):
        from test_cases.test_issue_tracker_credential_fd import CredentialFdDirectTests
        fixture = CredentialFdDirectTests("test_fixed_path_opens_relative_components_and_reads_single_held_fd_once")
        fixture.setUp(); self.addCleanup(fixture.doCleanups)
        for fault in ("file_uid", "short_read", None):
            with self.subTest(fault=fault), fixture.fixture(fault=fault), self.assertRaises(
                self.module.AuthenticationHold,
            ) as caught:
                self.module.credentials_from_fixed_file()
            self.assertEqual("req7_authentication_denied", str(caught.exception))
            self.assertIsNone(caught.exception.__cause__)
            self.assertIsNone(caught.exception.__context__)

    def test_production_source_uses_no_adc_private_grant_or_sdk_patch(self):
        source = MODULE.read_text(); ast.parse(source)
        for forbidden in ("jwt_grant", "before_request", "from_service_account_file", "AuthorizedSession",
                          "google.auth.default", "requests", "httplib2", "mock.patch", "setattr("):
            self.assertNotIn(forbidden, source)
        self.assertIn("Credentials.from_service_account_info", source)
        self.assertIn("installed_dependency_identity", source)


if __name__ == "__main__": unittest.main()
