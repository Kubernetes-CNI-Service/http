"""Real owned CA-file/SSL contexts, synthetic ownership; no network or real CA changes."""
from contextlib import ExitStack, contextmanager
from datetime import datetime, timedelta
import hashlib
import importlib.util
import os
from pathlib import Path
import ssl
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import test_cases

ROOT = Path(test_cases.__file__).resolve().parents[1]
CANDIDATE = Path(__file__).resolve().parents[1]
MODULE = CANDIDATE / "monitor/issue_tracker_tls_inputs.py"
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(Path(__file__).resolve().parent))


def load():
    if not MODULE.is_file(): raise AssertionError("REQ7 controlled TLS-input helper missing")
    spec = importlib.util.spec_from_file_location("req7_tls_inputs_candidate", MODULE)
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module
    spec.loader.exec_module(module); return module


def public_ca():
    from req7_dependency_contract import load_dependency_contract, installed_dependency_identity
    installed_dependency_identity(load_dependency_contract(ROOT))
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Owned REQ7 synthetic test CA")])
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                   .serial_number(1).not_valid_before(datetime.utcnow() - timedelta(days=1))
                   .not_valid_after(datetime.utcnow() + timedelta(days=1))
                   .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                   .sign(key, hashes.SHA256()))
    return certificate.public_bytes(serialization.Encoding.PEM)


class Req7TlsInputsDirectTests(unittest.TestCase):
    def test_synthetic_root_metadata_preserves_native_timestamp_fields_for_dependency_queries(self):
        expected = os.stat(self.root)
        fields = ("st_atime", "st_mtime", "st_ctime",
                  "st_atime_ns", "st_mtime_ns", "st_ctime_ns")
        with self.fixture():
            actual = os.stat(self.root)
            uid = actual.st_uid
            observed = {field: getattr(actual, field, None) for field in fields}
        self.assertEqual(0, uid)
        for field in fields:
            with self.subTest(field=field):
                self.assertEqual(getattr(expected, field), observed[field])

    def test_original_mutation_fd_shape_is_readonly_bounded_and_consumed_on_metadata_failure(self):
        self.assertTrue(hasattr(self.module,'NativeOriginalSheetsMutationUnit'),'held original image native boundary missing')
        from test_cases.test_req7_send_unit import load as load_unit, inputs, TARGET
        from monitor.issue_tracker_online_target import OnlineTargetBinding
        from monitor.issue_tracker_sdk_authentication import AuthenticatedToken
        import time
        unit = load_unit().freeze_send_unit(**inputs())
        target = OnlineTargetBinding(TARGET,'a'*64,'b'*64)
        credential = AuthenticatedToken('sentinel.private-token',time.time()+3600)
        action = self.root/'ACTION'; wire = self.root/'WIRE'
        action.write_bytes(unit.action_preimage); wire.write_bytes(unit.wire_bytes)
        action.chmod(0o600); wire.chmod(0o600)
        a = os.open(action,os.O_RDONLY); w = os.open(wire,os.O_RDONLY); writable = os.open(wire,os.O_RDWR)
        for fd in (a,w,writable): self.addCleanup(os.close,fd)
        with self.fixture(), mock.patch.object(self.module,'controlled_tls_context') as ca, mock.patch('http.client.HTTPSConnection') as connecting:
            for fds in ((a,a),(a,writable),(True,w),(0,w)):
                with self.assertRaises(self.module.TlsInputHold): self.module.NativeOriginalSheetsMutationUnit(target,credential,*fds)
            native = self.module.NativeOriginalSheetsMutationUnit(target,credential,a,w)
            wire.chmod(0o400)
            with self.assertRaises(self.module.TlsInputHold) as caught: native.send_once()
            self.assertIsNone(caught.exception.__context__)
            wire.chmod(0o600)
            with self.assertRaises(self.module.TlsInputHold): native.send_once()
            ca.assert_not_called(); connecting.assert_not_called()

    def test_native_mutation_revalidates_fixed_shape_before_ca_or_connection(self):
        self.assertTrue(hasattr(self.module,'NativeSheetsMutationUnit'),'fixed one-shot native mutation unit missing')
        from dataclasses import replace
        from test_cases.test_req7_send_unit import load as load_unit, inputs, TARGET
        from monitor.issue_tracker_online_target import OnlineTargetBinding
        from monitor.issue_tracker_sdk_authentication import AuthenticatedToken
        import time
        composer = load_unit(); unit = composer.freeze_send_unit(**inputs())
        binding = OnlineTargetBinding(TARGET,'a'*64,'b'*64)
        token = AuthenticatedToken('sentinel.private-token',time.time()+3600)
        original = composer.prepare_mutation_request(binding,token,unit)
        for changes in ({'host':'foreign.invalid'}, {'path':'/foreign'}, {'method':'GET'},
                        {'body':b'{}'}, {'headers':()}, {'budget_seconds':True}, {'budget_seconds':61},
                        {'wire_sha256':'f'*64}):
            native = self.module.NativeSheetsMutationUnit(binding,token,unit)
            native._prepared = replace(original,**changes)
            with self.subTest(fields=tuple(changes)), mock.patch.object(self.module,'controlled_tls_context') as ca:
                with mock.patch('http.client.HTTPSConnection') as connect:
                    with self.assertRaises(self.module.TlsInputHold) as caught: native.send_once()
                    self.assertIsNone(caught.exception.__context__)
                    with self.assertRaises(self.module.TlsInputHold): native.send_once()
                    ca.assert_not_called(); connect.assert_not_called()

    def test_low_level_mutation_type_cannot_fall_through_to_read_or_oauth_branch(self):
        from dataclasses import replace
        from test_cases.test_req7_send_unit import load as load_unit, inputs, TARGET
        from monitor.issue_tracker_online_target import OnlineTargetBinding
        from monitor.issue_tracker_sdk_authentication import AuthenticatedToken
        import time
        composer = load_unit()
        plan = composer.prepare_mutation_request(OnlineTargetBinding(TARGET,'a'*64,'b'*64),
            AuthenticatedToken('sentinel.private-token',time.time()+3600),composer.freeze_send_unit(**inputs()))
        for changes in ({'method':'GET'}, {'host':'oauth2.googleapis.com','path':'/token'}):
            with self.subTest(fields=tuple(changes)), mock.patch.object(self.module,'controlled_tls_context') as ca:
                with mock.patch('http.client.HTTPSConnection') as connect:
                    with self.assertRaises(self.module.TlsInputHold): self.module._native_complete_read(replace(plan,**changes))
                    ca.assert_not_called(); connect.assert_not_called()

    def setUp(self):
        self.module = load(); self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.path = self.root / "etc/ssl/certs/ca-certificates.crt"
        self.path.parent.mkdir(parents=True); self.path.write_bytes(public_ca()); self.path.chmod(0o644)

    @contextmanager
    def fixture(self, fault=None):
        real_open, real_stat, real_fstat, real_read = os.open, os.stat, os.fstat, os.read
        inode = self.path.stat().st_ino; reads = []; opened = []
        def metadata(value):
            fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                      "st_size", "st_atime", "st_mtime", "st_ctime",
                      "st_atime_ns", "st_mtime_ns", "st_ctime_ns")
            result = SimpleNamespace(**{name: getattr(value, name) for name in fields}); result.st_uid = 0
            if fault == "uid" and result.st_ino == inode: result.st_uid = 501
            if fault == "writable_ancestor" and stat.S_ISDIR(result.st_mode): result.st_mode |= 0o002
            return result
        def opening(name, flags, *args, **kwargs):
            opened.append(name)
            return real_open(self.root if name == "/" else name, flags, *args, **kwargs)
        def reading(fd, count):
            reads.append(count); data = real_read(fd, count)
            if fault == "short": return data[:-1]
            if fault == "rebind":
                self.path.rename(self.path.with_name("retained-original.pem"))
                self.path.write_bytes(data); self.path.chmod(0o644)
            return data
        with ExitStack() as stack:
            for target, value in (("os.geteuid", lambda: 0), ("os.open", opening),
                                  ("os.fstat", lambda fd: metadata(real_fstat(fd))),
                                  ("os.stat", lambda *a, **k: metadata(real_stat(*a, **k))), ("os.read", reading)):
                stack.enter_context(mock.patch(target, side_effect=value))
            yield opened, reads

    def test_fixed_held_ca_bytes_create_real_verified_ssl_context_without_environment_trust(self):
        original = self.path.read_bytes()
        with mock.patch.dict(os.environ, {name: "/unapproved/sentinel.pem" for name in (
            "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "HTTPS_PROXY", "ALL_PROXY")}), self.fixture() as (opened, reads):
            context, identity = self.module.controlled_tls_context()
        self.assertIs(type(context), ssl.SSLContext); self.assertIs(context.check_hostname, True)
        self.assertEqual(ssl.CERT_REQUIRED, context.verify_mode)
        self.assertEqual(ssl.TLSVersion.TLSv1_2, context.minimum_version)
        self.assertEqual(1, context.cert_store_stats()["x509_ca"])
        self.assertEqual(["/", "etc", "ssl", "certs", "ca-certificates.crt"], opened)
        self.assertEqual([2 * 1024 * 1024 + 1], reads)
        self.assertEqual(hashlib.sha256(original).hexdigest(), identity.sha256)
        self.assertEqual("/etc/ssl/certs/ca-certificates.crt", identity.path)
        self.assertEqual(original, self.path.read_bytes())

    def _literal_native_cleanup_fixture(self, *, body_error=None, response_error=None, connection_error=None):
        """Only the resource interface is fake; expected cleanup stays literal."""
        events=[]
        def headers():
            if body_error is not None:raise body_error
            return ()
        def response_close():
            events.append('response.close')
            if response_error is not None:raise response_error
        def connection_close():
            events.append('connection.close')
            if connection_error is not None:raise connection_error
        response=SimpleNamespace(status=401,getheaders=headers,close=response_close)
        connection=SimpleNamespace(set_debuglevel=lambda value:None,request=lambda *a,**k:None,
            getresponse=lambda:response,close=connection_close)
        prepared=SimpleNamespace(host='oauth2.googleapis.com',method='POST',path='/token',
            body=b'literal-owned-request',headers=(),budget_seconds=0.5)
        return prepared,connection,events

    def test_denied_native_response_is_closed_before_connection_and_sanitized_hold(self):
        prepared,connection,events=self._literal_native_cleanup_fixture()
        with mock.patch.object(self.module,'controlled_tls_context',return_value=(object(),object())), \
                mock.patch('http.client.HTTPSConnection',return_value=connection):
            with self.assertRaises(self.module.TlsInputHold) as caught:
                self.module._native_complete_read(prepared)
        self.assertEqual(['response.close','connection.close'],events)
        self.assertIsNone(caught.exception.__context__)

    def test_native_response_close_interruption_keeps_identity_and_still_closes_connection(self):
        interrupted=KeyboardInterrupt('literal response close interruption')
        original_cause=ValueError('literal original cause');interrupted.__cause__=original_cause
        prepared,connection,events=self._literal_native_cleanup_fixture(response_error=interrupted)
        with mock.patch.object(self.module,'controlled_tls_context',return_value=(object(),object())), \
                mock.patch('http.client.HTTPSConnection',return_value=connection):
            with self.assertRaises(BaseException) as caught:self.module._native_complete_read(prepared)
        self.assertIs(caught.exception,interrupted)
        self.assertIs(caught.exception.__cause__,original_cause)
        self.assertEqual(['response.close','connection.close'],events)

    def test_native_original_interruption_wins_over_two_independent_cleanup_interruptions(self):
        interrupted=KeyboardInterrupt('literal original response interruption')
        original_cause=ValueError('literal body cause');interrupted.__cause__=original_cause
        prepared,connection,events=self._literal_native_cleanup_fixture(body_error=interrupted,
            response_error=SystemExit('literal response cleanup'),connection_error=SystemExit('literal connection cleanup'))
        with mock.patch.object(self.module,'controlled_tls_context',return_value=(object(),object())), \
                mock.patch('http.client.HTTPSConnection',return_value=connection):
            with self.assertRaises(BaseException) as caught:self.module._native_complete_read(prepared)
        self.assertIs(caught.exception,interrupted)
        self.assertIs(caught.exception.__cause__,original_cause)
        self.assertEqual(['response.close','connection.close'],events)

    def test_ca_authority_drift_and_short_read_are_sanitized_without_repair_or_fallback(self):
        for fault in ("uid", "writable_ancestor", "short", "rebind"):
            with self.subTest(fault=fault), self.fixture(fault), self.assertRaises(self.module.TlsInputHold) as caught:
                self.module.controlled_tls_context()
            self.assertEqual("req7_tls_input_denied", str(caught.exception))
            self.assertIsNone(caught.exception.__context__)
            if fault == "rebind":
                self.path.unlink(); self.path.with_name("retained-original.pem").rename(self.path)

    def test_nonroot_missing_kernel_flag_or_unsafe_ca_file_never_becomes_trust(self):
        with mock.patch("os.geteuid", return_value=501), mock.patch("os.open") as opening:
            with self.assertRaises(self.module.TlsInputHold): self.module.controlled_tls_context()
        opening.assert_not_called()
        # Construct only the invalid sentinel used by this negative test;
        # no actual key material or public-audit exemption is introduced.
        invalid_key = b"-----BEGIN " + b"PRIVATE KEY-----\nsentinel\n-----END " + b"PRIVATE KEY-----\n"
        for source in (b"", b"x" * (2 * 1024 * 1024 + 1), b"sentinel not PEM", invalid_key):
            self.path.write_bytes(source)
            with self.subTest(size=len(source)), self.fixture(), self.assertRaises(self.module.TlsInputHold) as caught:
                self.module.controlled_tls_context()
            self.assertIsNone(caught.exception.__context__)
        self.path.write_bytes(public_ca()); self.path.chmod(0o666)
        with self.fixture(), self.assertRaises(self.module.TlsInputHold): self.module.controlled_tls_context()
        self.assertEqual(0o666, stat.S_IMODE(self.path.stat().st_mode))

    def test_symlink_and_hardlink_ca_are_denied_and_both_owned_originals_preserved(self):
        original = self.path.read_bytes(); saved = self.path.with_name("original.pem")
        self.path.rename(saved); self.path.symlink_to(saved.name)
        with self.fixture(), self.assertRaises(self.module.TlsInputHold): self.module.controlled_tls_context()
        self.assertEqual(original, saved.read_bytes()); self.assertTrue(self.path.is_symlink())
        self.path.unlink(); os.link(saved, self.path)
        with self.fixture(), self.assertRaises(self.module.TlsInputHold): self.module.controlled_tls_context()
        self.assertEqual(original, saved.read_bytes()); self.assertEqual(original, self.path.read_bytes())

    def test_header_parser_identity_is_pinned_not_globally_rewritten(self):
        import http.client
        self.assertEqual((65536, 100), self.module.stdlib_header_bounds())
        for field, value in (("_MAXLINE", 65537), ("_MAXHEADERS", 101)):
            with self.subTest(field=field), mock.patch.object(http.client, field, value), self.assertRaises(self.module.TlsInputHold):
                self.module.stdlib_header_bounds()
            self.assertEqual((65536, 100), self.module.stdlib_header_bounds())

    def test_missing_kernel_flags_refuse_before_open_and_close_fault_closes_all_owned_fds(self):
        with mock.patch("os.geteuid", return_value=0), mock.patch("os.open") as opening:
            with mock.patch.object(os, "O_NOFOLLOW", create=True):
                saved = os.O_NOFOLLOW; del os.O_NOFOLLOW
                try:
                    with self.assertRaises(self.module.TlsInputHold): self.module.controlled_tls_context()
                finally: os.O_NOFOLLOW = saved
        opening.assert_not_called()
        actual_close = os.close; closed = []
        def close(descriptor):
            closed.append(descriptor); actual_close(descriptor)
            if len(closed) == 1: raise OSError("sentinel close fault")
        with self.fixture(), mock.patch("os.close", side_effect=close), self.assertRaises(self.module.TlsInputHold) as caught:
            self.module.controlled_tls_context()
        self.assertEqual(5, len(closed)); self.assertEqual(5, len(set(closed)))
        self.assertIsNone(caught.exception.__context__)
        for descriptor in closed:
            with self.assertRaises(OSError): os.fstat(descriptor)


class Req7TlsSdkWorkflowTests(unittest.TestCase):
    # Share only owned-fixture machinery; all six direct tests stay in their
    # original class and execute once, with every assertion unchanged.
    setUp = Req7TlsInputsDirectTests.setUp
    fixture = Req7TlsInputsDirectTests.fixture

    def test_actual_public_sdk_callback_prepares_exact_token_shape_at_the_fake_unit_boundary(self):
        from test_req7_sdk_authentication import load as load_auth, fresh_info, parsed_info, FakeTokenUnit
        auth = load_auth(); info = parsed_info(fresh_info()); fake = FakeTokenUnit(); contexts = []
        auth.credentials_from_validated_info(info)  # Real governed constructor before synthetic os.stat.
        tls = self.module
        class Unit:
            def send_once(self, wire):
                prepared = tls.prepare_token_request(wire)
                context, identity = tls.controlled_tls_context()
                contexts.append((context, identity, prepared))
                return fake.send_once(wire)
        with self.fixture(), mock.patch("socket.socket", side_effect=AssertionError("real network forbidden")):
            token = auth.refresh_validated_service_account(info, Unit())
        self.assertEqual("sentinel", token.value); self.assertEqual(1, len(fake.calls))
        self.assertEqual(1, len(contexts)); context, identity, prepared = contexts[0]
        self.assertEqual("oauth2.googleapis.com", prepared.host); self.assertEqual("/token", prepared.path)
        self.assertEqual("POST", prepared.method); self.assertEqual(30.0, prepared.budget_seconds)
        self.assertEqual(fake.calls[0].body, prepared.body); self.assertNotIn("assertion", repr(prepared))
        self.assertTrue(context.check_hostname); self.assertEqual(ssl.CERT_REQUIRED, context.verify_mode)

    def test_wire_shape_cannot_supply_foreign_url_headers_or_deadline_before_ca_or_network(self):
        from test_req7_sdk_authentication import load as load_auth
        auth = load_auth()
        variants = [{"url": x} for x in ("https://sheets.googleapis.com/token", "http://oauth2.googleapis.com/token",
                     "https://oauth2.googleapis.com:443/token", "https://oauth2.googleapis.com/token?",
                     "https://user@oauth2.googleapis.com/token", "https://oauth2.googleapis.com/token#")]
        variants += [{"method": "GET"}, {"body": b""}, {"body": b"x" * 65537}, {"body": bytearray(b"x")},
                     {"headers": (("Authorization", "sentinel"),)}, {"headers": []},
                     {"headers": (("Content-Type", "application/x-www-form-urlencoded"), ("content-type", "foreign"))},
                     {"budget_seconds": True}, {"budget_seconds": 31}, {"budget_seconds": 0},
                     {"budget_seconds": float("nan")}, {"budget_seconds": float("inf")}]
        variants += [{"budget_seconds": 10 ** 1000}]
        for variant in variants:
            arguments = dict(url="https://oauth2.googleapis.com/token", method="POST", body=b"x",
                             headers=(("Content-Type", "application/x-www-form-urlencoded"),), budget_seconds=30.0)
            arguments.update(variant)
            with self.subTest(fields=tuple(variant)), mock.patch("http.client.HTTPSConnection") as connecting, self.assertRaises(
                self.module.TlsInputHold,
            ):
                self.module.prepare_token_request(auth.TokenWireRequest(**arguments))
            connecting.assert_not_called()

    def test_native_unit_consumes_once_and_sanitizes_ca_failure_without_network(self):
        from test_req7_sdk_authentication import load as load_auth
        auth = load_auth(); wire = auth.TokenWireRequest("https://oauth2.googleapis.com/token", "POST", b"x",
                                                        (("Content-Type", "application/x-www-form-urlencoded"),))
        unit = self.module.NativeTokenHttpsUnit()
        with mock.patch("os.geteuid", return_value=501), mock.patch("http.client.HTTPSConnection") as connecting:
            with self.assertRaises(self.module.TlsInputHold) as caught: unit.send_once(wire)
        self.assertEqual("req7_tls_input_denied", str(caught.exception)); self.assertIsNone(caught.exception.__context__)
        connecting.assert_not_called()
        with mock.patch.object(self.module, "controlled_tls_context") as context, mock.patch("http.client.HTTPSConnection") as connecting:
            with self.assertRaises(self.module.TlsInputHold): unit.send_once(wire)
        context.assert_not_called(); connecting.assert_not_called()


if __name__ == "__main__": unittest.main()
