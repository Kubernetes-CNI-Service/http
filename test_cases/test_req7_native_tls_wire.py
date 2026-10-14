"""Actual stdlib TLS/HTTP to an owned loopback fake server, never online OAuth.

Only DNS and root CA-file metadata are synthetic boundaries. HTTPSConnection,
SSLContext, hostname verification, request generation and response parsing are
not mocked. No real credential or installed CA is read or modified.
"""
from contextlib import contextmanager
from datetime import datetime, timedelta
import base64
import json
import os
from pathlib import Path
import selectors
import socket
import ssl
import sys
import threading
import unittest
from unittest import mock
from urllib.parse import parse_qs

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_req7_tls_inputs as tls_fixtures


class Req7NativeTlsWireTests(unittest.TestCase):
    setUp = tls_fixtures.Req7TlsInputsDirectTests.setUp
    fixture = tls_fixtures.Req7TlsInputsDirectTests.fixture

    def mutation(self):
        self.assertTrue(hasattr(self.module,'NativeSheetsMutationUnit'),'fixed native mutation unit missing')
        from test_cases.test_req7_send_unit import load as load_unit, inputs, TARGET
        from monitor.issue_tracker_online_target import OnlineTargetBinding
        from monitor.issue_tracker_sdk_authentication import AuthenticatedToken
        import time
        unit = load_unit().freeze_send_unit(**inputs())
        return self.module.NativeSheetsMutationUnit(OnlineTargetBinding(TARGET,'a'*64,'b'*64),
            AuthenticatedToken('sentinel.private-token',time.time()+3600),unit),unit

    def test_actual_fixed_batch_post_keeps_original_wire_and_only_correlated_rejection_observation(self):
        import hashlib
        for status,name,expected in ((200,None,'UNKNOWN'),(400,'INVALID_ARGUMENT','DEFINITE_REJECTION'),
                                     (403,'PERMISSION_DENIED','DEFINITE_REJECTION'),(404,'NOT_FOUND','DEFINITE_REJECTION'),
                                     (403,'NOT_FOUND','UNKNOWN')):
            native,unit = self.mutation()
            body = b'{}' if name is None else json.dumps({'error':{'code':status,'status':name}}).encode()
            response = ('HTTP/1.1 %d Synthetic\r\nContent-Length: %d\r\nConnection: close\r\n\r\n' % (status,len(body))).encode()+body
            with self.subTest(status=status,name=name), self.server(response,hostname='sheets.googleapis.com',destination='sheets.googleapis.com') as (records,errors):
                with self.fixture(), mock.patch.dict(os.environ,{'HTTPS_PROXY':'http://foreign.invalid:9'}):
                    result = native.send_once()
                    with self.assertRaises(self.module.TlsInputHold): native.send_once()
            self.assertEqual([],errors); self.assertEqual(1,len(records))
            self.assertEqual(b'POST /v4/spreadsheets/synthetic_spreadsheet_id_0001:batchUpdate HTTP/1.1\r\n',records[0][0])
            self.assertEqual(unit.wire_bytes,records[0][2])
            self.assertEqual((status,unit.wire_sha256,hashlib.sha256(body).hexdigest(),expected),
                (result.status,result.wire_sha256,result.response_sha256,result.outcome))
            self.assertFalse(hasattr(result,'permit')); self.assertFalse(hasattr(result,'applied'))
            self.assertNotIn('sentinel.private-token',repr(result))

    def test_native_mutation_redirect_auth_quota_and_server_errors_never_refresh_follow_or_resend(self):
        for status in (302,401,429,503):
            native,_unit = self.mutation()
            response = ('HTTP/1.1 %d Denied\r\nContent-Length: 2\r\nLocation: https://foreign.invalid/\r\nConnection: close\r\n\r\n{}' % status).encode()
            with self.subTest(status=status), self.server(response,hostname='sheets.googleapis.com',destination='sheets.googleapis.com') as (records,errors):
                with self.fixture():
                    result = native.send_once()
                    with self.assertRaises(self.module.TlsInputHold): native.send_once()
            self.assertEqual((status,'UNKNOWN'),(result.status,result.outcome))
            self.assertEqual(1,len(records)); self.assertEqual([],errors)

    def test_native_mutation_incomplete_or_conflicting_framing_never_becomes_rejection(self):
        body = b'{"error":{"code":403,"status":"PERMISSION_DENIED"}}'
        replies = (b'HTTP/1.1 403 Denied\r\nConnection: close\r\n\r\n'+body,
                   b'HTTP/1.1 403 Denied\r\nContent-Length: 999\r\nConnection: close\r\n\r\n'+body,
                   b'HTTP/1.1 403 Denied\r\nContent-Length: 2\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}',
                   b'HTTP/1.1 403 Denied\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\n{}\r\n')
        for response in replies:
            native,_unit = self.mutation()
            with self.subTest(bytes=len(response)), self.server(response,hostname='sheets.googleapis.com',destination='sheets.googleapis.com') as (records,errors):
                with self.fixture(), self.assertRaises(self.module.TlsInputHold) as caught: native.send_once()
                self.assertIsNone(caught.exception.__context__)
                with self.assertRaises(self.module.TlsInputHold): native.send_once()
            self.assertEqual(1,len(records)); self.assertEqual([],errors)

    def test_native_whole_batch_larger_than_private_stdin_limit_is_not_split_or_truncated(self):
        from test_cases.test_req7_send_unit import load as load_unit, inputs, TARGET
        from monitor.issue_tracker_online_target import OnlineTargetBinding
        from monitor.issue_tracker_sdk_authentication import AuthenticatedToken
        import time
        arguments = inputs(20)
        arguments['business'] = tuple({**item,'values':{'L':'x'*4096}} for item in arguments['business'])
        unit = load_unit().freeze_send_unit(**arguments)
        self.assertGreater(len(unit.wire_bytes),65536); self.assertLessEqual(len(unit.wire_bytes),1024*1024)
        native = self.module.NativeSheetsMutationUnit(OnlineTargetBinding(TARGET,'a'*64,'b'*64),
            AuthenticatedToken('sentinel.private-token',time.time()+3600),unit)
        with self.server(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}',
                         hostname='sheets.googleapis.com',destination='sheets.googleapis.com',request_limit=1024*1024) as (records,errors):
            with self.fixture(): result = native.send_once()
        self.assertEqual([],errors); self.assertEqual(1,len(records)); self.assertEqual(unit.wire_bytes,records[0][2])
        self.assertEqual(22,len(json.loads(records[0][2])['requests']))
        self.assertEqual('UNKNOWN',result.outcome)

    def certificates(self, hostname="oauth2.googleapis.com"):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Owned local REQ7 wire-test CA")])
        ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
              .serial_number(2).not_valid_before(datetime.utcnow() - timedelta(days=1))
              .not_valid_after(datetime.utcnow() + timedelta(days=1))
              .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
              .sign(ca_key, hashes.SHA256()))
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
                .issuer_name(ca_name).public_key(leaf_key.public_key()).serial_number(3)
                .not_valid_before(datetime.utcnow() - timedelta(days=1)).not_valid_after(datetime.utcnow() + timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .sign(ca_key, hashes.SHA256()))
        self.path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        certificate = self.root / "owned-server.pem"; key = self.root / "owned-server-key.pem"
        certificate.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        key.write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption())); key.chmod(0o600)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        return context

    @contextmanager
    def prepared_server_certificate(self, hostname):
        # Preparation belongs to the synthetic remote server, before client
        # observations start. This scope does not renew any client evidence.
        context = self.certificates(hostname)
        prior = getattr(self, '_prepared_server_material', None)
        material = (hostname, context, self._server_material_originals())
        self._prepared_server_material = material
        try:
            yield context
        finally:
            self._prepared_server_material = prior

    def _server_material_originals(self):
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid',
                  'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        originals = []
        for path in (self.path, self.root/'owned-server.pem', self.root/'owned-server-key.pem'):
            before = path.stat()
            raw = path.read_bytes()
            after = path.stat()
            stamp = lambda value: tuple(getattr(value, field) for field in fields)
            self.assertEqual(stamp(before), stamp(after), 'owned server material changed while read')
            originals.append((str(path), stamp(after), raw))
        return tuple(originals)

    @contextmanager
    def server(self, response, hostname="oauth2.googleapis.com", destination="oauth2.googleapis.com", *, request_limit=65536):
        replies=response if type(response) is tuple else (response,)
        self.assertIn(len(replies),(1,4),'owned fixture supports one reply or the fixed four-read cohort')
        prepared = getattr(self, '_prepared_server_material', None)
        if prepared is None:
            context = self.certificates(hostname)
        else:
            self.assertEqual(hostname, prepared[0], 'prepared server hostname cannot change')
            self.assertEqual(prepared[2], self._server_material_originals(),
                             'prepared server originals cannot change')
            context = prepared[1]
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0)); listener.listen(1); listener.settimeout(3)
        address = listener.getsockname(); observations = []; errors = []
        stop_read, stop_write = socket.socketpair()
        # Non-authoritative diagnostic snapshot of this fixture's actual
        # original readiness descriptors, before any close/reuse.
        self._last_owned_tls_ready_fds=(listener.fileno(),stop_read.fileno())
        def serve():
            try:
                # Client startup/local validation belongs to the caller's
                # unchanged TOTAL budget, not a fake-server accept deadline.
                # Wait for an actual pending connection or explicit scope
                # cancellation. Accept/handshake/body retain their 3s bounds.
                # Original catalog/source graphs may hold high descriptors.
                # DefaultSelector uses the native scalable readiness backend;
                # retain the same two original sockets and cancellation path.
                for reply in replies:
                    with selectors.DefaultSelector() as readiness:
                        readiness.register(listener,selectors.EVENT_READ)
                        readiness.register(stop_read,selectors.EVENT_READ)
                        ready={key.fileobj for key,_event in readiness.select()}
                    if stop_read in ready: return
                    connection, _peer = listener.accept(); connection.settimeout(3)
                    with connection:
                        with context.wrap_socket(connection, server_side=True) as transport:
                            with transport.makefile("rb") as incoming:
                                request_line = incoming.readline(8193); headers = []
                                for _ in range(100):
                                    line = incoming.readline(8193)
                                    if line == b"\r\n": break
                                    if not line or len(line) > 8192: raise AssertionError("invalid owned-fixture request")
                                    headers.append(line)
                                else: raise AssertionError("owned fixture header overflow")
                                lengths = [int(line.split(b":", 1)[1]) for line in headers if line.lower().startswith(b"content-length:")]
                                if request_line.startswith(b"GET "):
                                    if lengths not in ([], [0]): raise AssertionError("GET fixture received a body")
                                    body = b""
                                else:
                                    if len(lengths) != 1 or not 0 <= lengths[0] <= request_limit: raise AssertionError("invalid owned fixture length")
                                    body = incoming.read(lengths[0])
                                observations.append((request_line, tuple(headers), body))
                            if callable(reply): reply(transport)
                            else: transport.sendall(reply)
            except Exception as error: errors.append(error)
        thread = threading.Thread(target=serve, daemon=True); thread.start()
        def resolve(host, port, *args, **kwargs):
            if host != destination or port != 443:
                raise AssertionError("foreign/online DNS forbidden")
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", address)]
        try:
            with mock.patch("socket.getaddrinfo", side_effect=resolve): yield observations, errors
        finally:
            try:
                stop_write.sendall(b"x"); thread.join(4)
                self.assertFalse(thread.is_alive(), "owned TLS fixture must terminate")
            finally:
                listener.close(); stop_read.close(); stop_write.close()

    def test_fixed_four_reply_fixture_really_accepts_four_original_connections(self):
        # The fixed cohort needs four actual native HTTP requests, not one
        # fabricated composite reply. This only checks the local TLS fixture.
        bodies=(b'{"literal":1}',b'{"literal":2}',b'{"literal":3}',b'{"literal":4}')
        replies=tuple(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+
                      b'\r\nConnection: close\r\n\r\n'+body for body in bodies)
        observed=[]
        with self.server(replies) as (records,errors),self.fixture():
            for _body in bodies:
                response=self.module.NativeTokenHttpsUnit().send_once(self.wire())
                observed.append((response.status,response.data,response.complete))
        self.assertEqual(tuple((200,body,True) for body in bodies),tuple(observed))
        self.assertEqual((4,[]),(len(records),errors))
        self.assertTrue(all(row[0].startswith(b'POST /token ') for row in records))

    def wire(self):
        from test_req7_sdk_authentication import load as load_auth
        auth = load_auth()
        return auth.TokenWireRequest("https://oauth2.googleapis.com/token", "POST", b"synthetic-body",
                                     (("Content-Type", "application/x-www-form-urlencoded"),), 0.5)

    def test_prepared_remote_certificate_is_not_regenerated_between_real_client_observations(self):
        # Literal fixture expectation: one remote certificate preparation,
        # two distinct original TLS connections and two complete HTTP replies.
        original = self.certificates
        with mock.patch.object(self, 'certificates', wraps=original) as preparing:
            with self.prepared_server_certificate('oauth2.googleapis.com'):
                ca_bytes = self.path.read_bytes()
                for _ in range(2):
                    with self.server(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}') as (records, errors):
                        with self.fixture():
                            result = self.module.NativeTokenHttpsUnit().send_once(self.wire())
                    self.assertEqual([], errors); self.assertEqual(1, len(records))
                    self.assertEqual((200, b'{}', True), (result.status, result.data, result.complete))
                    self.assertEqual(ca_bytes, self.path.read_bytes())
                self.assertEqual(1, preparing.call_count)
            # A later independent fixture must generate its own certificate.
            with self.server(b'') as (records, errors):
                self.assertEqual([], records); self.assertEqual([], errors)
            self.assertEqual(2, preparing.call_count)

    def test_prepared_remote_certificate_keeps_actual_hostname_rejection(self):
        with self.prepared_server_certificate('foreign.invalid'):
            with self.server(b'', hostname='foreign.invalid') as (records, errors):
                with self.fixture(), self.assertRaises(self.module.TlsInputHold):
                    self.module.NativeTokenHttpsUnit().send_once(self.wire())
            self.assertEqual([], records); self.assertEqual(1, len(errors))
            self.assertIsInstance(errors[0], ssl.SSLError)

    def test_prepared_remote_certificate_refuses_original_drift_and_restores_on_interrupt(self):
        original = self.certificates
        incoming = KeyboardInterrupt('owned fixture interrupt')
        with mock.patch.object(self, 'certificates', wraps=original) as preparing:
            for path in (self.path, self.root/'owned-server.pem', self.root/'owned-server-key.pem'):
                with self.prepared_server_certificate('sheets.googleapis.com'):
                    prior = path.read_bytes()
                    moved = path.with_name(path.name+'.prior')
                    path.rename(moved); path.write_bytes(prior)
                    with self.assertRaises(AssertionError):
                        with self.server(b'', hostname='sheets.googleapis.com', destination='sheets.googleapis.com'):
                            self.fail('changed original must refuse before opening listener')
                    path.unlink(); moved.rename(path)
            with self.assertRaises(KeyboardInterrupt) as caught:
                with self.prepared_server_certificate('sheets.googleapis.com'):
                    with self.assertRaises(AssertionError):
                        with self.server(b'', hostname='oauth2.googleapis.com'):
                            self.fail('foreign host cannot borrow prepared Sheets material')
                    raise incoming
            self.assertIs(incoming, caught.exception)
            self.assertEqual(4, preparing.call_count)
            with self.server(b'') as (records, errors):
                self.assertEqual([], records); self.assertEqual([], errors)
            self.assertEqual(5, preparing.call_count)

    def test_owned_server_does_not_spend_transport_timeout_before_client_start(self):
        # Independent fixture contract: no connection has started while the
        # owned launcher performs imports/local checks. A transport deadline
        # must not run during this phase. Production/client budgets are intact.
        with self.server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}") as (records, errors):
            threading.Event().wait(3.25)
            self.assertEqual([], records)
            self.assertEqual([], errors, "idle startup is not a transport timeout")
            with self.fixture():
                result = self.module.NativeTokenHttpsUnit().send_once(self.wire())
        self.assertEqual([], errors); self.assertEqual(1, len(records))
        self.assertEqual((200, b"{}", True), (result.status, result.data, result.complete))

    def test_owned_tls_server_readiness_accepts_high_original_descriptors(self):
        # Genuine catalog/source holders can keep more than select's fd-set
        # limit live. Readiness must still observe the original sockets, not
        # treat this as a server/transport timeout or extend the client budget.
        leaf=self.root/'owned-high-descriptor-file';leaf.write_bytes(b'owned fixture only\n')
        held=[]
        try:
            for _ in range(1200):
                fd=os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW);held.append(fd)
                if fd>=1100:break
            self.assertGreaterEqual(held[-1],1100,'local fixture needs its own high-fd precondition')
            with self.server(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}') as (records,errors):
                with self.fixture():
                    try:result=self.module.NativeTokenHttpsUnit().send_once(self.wire())
                    except Exception:
                        self.assertEqual([],errors,'original server readiness must survive its high owned fd')
                        raise
            self.assertEqual([],errors,'owned high descriptors cannot break server readiness')
            self.assertEqual(1,len(records))
            self.assertEqual((200,b'{}',True),(result.status,result.data,result.complete))
        finally:
            for fd in reversed(held):os.close(fd)

    def test_owned_idle_server_cleanup_does_not_require_a_client_or_timeout(self):
        # Observe the actual owned server thread; never enumerate/kill others.
        native_start = threading.Thread.start
        threads = []
        def started(thread):
            threads.append(thread)
            return native_start(thread)
        with mock.patch.object(threading.Thread, 'start', started):
            with self.server(b"") as (records, errors):
                self.assertEqual(1, len(threads)); self.assertTrue(threads[0].is_alive())
        self.assertFalse(threads[0].is_alive())
        self.assertEqual([], records); self.assertEqual([], errors)

    def test_owned_connected_client_without_tls_still_hits_original_transport_bound(self):
        with self.server(b"") as (records, errors):
            address=socket.getaddrinfo('oauth2.googleapis.com',443)[0][4]
            client=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            try:
                client.connect(address)
                # A real connection without a TLS handshake must still fail;
                # readiness synchronization cannot erase the original 3s cap.
                threading.Event().wait(3.25)
                self.assertEqual([],records); self.assertEqual(1,len(errors))
                self.assertIsInstance(errors[0],socket.timeout)
            finally: client.close()

    def test_actual_verified_tls_post_has_fixed_host_path_no_proxy_and_complete_bounded_response(self):
        wire = self.wire()
        with self.server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}") as (records, errors):
            with self.fixture(), mock.patch.dict(os.environ, {"HTTPS_PROXY": "http://foreign.invalid:9",
                                                             "SSL_CERT_FILE": "/foreign/sentinel.pem"}):
                result = self.module.NativeTokenHttpsUnit().send_once(wire)
        self.assertEqual([], errors); self.assertEqual(1, len(records))
        self.assertEqual(b"POST /token HTTP/1.1\r\n", records[0][0])
        self.assertIn(b"Host: oauth2.googleapis.com\r\n", records[0][1])
        self.assertEqual(b"synthetic-body", records[0][2])
        self.assertEqual(200, result.status); self.assertEqual(b"{}", result.data)
        self.assertIs(True, result.complete); self.assertNotIn("{}", repr(result))

    def test_redirect_and_non200_are_rejected_at_native_boundary_without_second_connection(self):
        wire = self.wire()
        for status in (302, 429, 503):
            reply = ("HTTP/1.1 %d Denied\r\nContent-Length: 2\r\nLocation: https://foreign.invalid/\r\n"
                     "Connection: close\r\n\r\n{}" % status).encode()
            with self.subTest(status=status):
                with self.server(reply) as (records, errors):
                    with self.fixture(), self.assertRaises(self.module.TlsInputHold) as caught:
                        self.module.NativeTokenHttpsUnit().send_once(wire)
                self.assertEqual("req7_tls_input_denied", str(caught.exception))
                self.assertIsNone(caught.exception.__context__)
                self.assertEqual(1, len(records)); self.assertEqual([], errors)

    def test_wrong_hostname_refuses_before_any_http_request(self):
        wire = self.wire()
        with self.server(b"", hostname="foreign.invalid") as (records, errors):
            with self.fixture(), self.assertRaises(self.module.TlsInputHold) as caught:
                self.module.NativeTokenHttpsUnit().send_once(wire)
        self.assertEqual([], records); self.assertEqual(1, len(errors))
        self.assertIsInstance(errors[0], ssl.SSLError)
        self.assertIsNone(caught.exception.__context__)

    def test_duplicate_framing_short_body_and_incomplete_chunks_never_become_complete(self):
        wire = self.wire()
        responses = (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
                     b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\n{}",
                     b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\n{}\r\n",
                     b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n0\r\n\r\n")
        for response in responses:
            with self.subTest(response_bytes=len(response)), self.server(response) as (records, errors):
                with self.fixture(), self.assertRaises(self.module.TlsInputHold) as caught:
                    self.module.NativeTokenHttpsUnit().send_once(wire)
            self.assertEqual(1, len(records)); self.assertEqual([], errors)
            self.assertIsNone(caught.exception.__context__)

    def test_close_only_response_cannot_prove_the_intended_body_length(self):
        # A syntactically complete JSON prefix is not complete HTTP framing.
        # Refuse an unframed EOF even if its bytes happen to be valid JSON.
        with self.server(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{}") as (records, errors):
            with self.fixture(), self.assertRaises(self.module.TlsInputHold) as caught:
                self.module.NativeTokenHttpsUnit().send_once(self.wire())
        self.assertEqual(1, len(records)); self.assertEqual([], errors)
        self.assertIsNone(caught.exception.__context__)

    def test_public_sdk_does_not_accept_or_retry_an_unframed_native_token_response(self):
        from test_req7_sdk_authentication import load as load_auth, fresh_info, parsed_info
        auth = load_auth()
        credential = auth.credentials_from_validated_info(parsed_info(fresh_info()))
        adapter = auth.OneShotTokenRequest(self.module.NativeTokenHttpsUnit())
        payload = b'{"access_token":"sentinel","expires_in":3600}'
        with self.server(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" + payload) as (records, errors):
            with self.fixture():
                from google.auth.exceptions import TransportError
                with self.assertRaises(TransportError) as caught: credential.refresh(adapter)
        self.assertEqual(1, len(records)); self.assertEqual([], errors)
        self.assertIsNone(caught.exception.__context__); self.assertIsNone(credential.token)

    def test_public_sdk_refresh_crosses_actual_native_tls_unit_and_never_follows_or_retries(self):
        from test_req7_sdk_authentication import load as load_auth, fresh_info, parsed_info
        auth = load_auth(); parsed = parsed_info(fresh_info())
        for status in (200, 302, 503):
            # The public constructor and dependency gate run before synthetic
            # CA root remapping. No SDK function or HTTPS internals are patched.
            credential = auth.credentials_from_validated_info(parsed)
            adapter = auth.OneShotTokenRequest(self.module.NativeTokenHttpsUnit())
            payload = b'{"access_token":"sentinel","expires_in":3600}'
            response = ("HTTP/1.1 %d Synthetic\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % (
                status, len(payload))).encode() + payload
            with self.subTest(status=status):
                with self.server(response) as (records, errors):
                    with self.fixture():
                        if status == 200: credential.refresh(adapter)
                        else:
                            from google.auth.exceptions import TransportError
                            with self.assertRaises(TransportError) as caught: credential.refresh(adapter)
                            self.assertIsNone(caught.exception.__context__)
                self.assertEqual([], errors); self.assertEqual(1, len(records))
                self.assertEqual(b"POST /token HTTP/1.1\r\n", records[0][0])
                form = parse_qs(records[0][2].decode(), strict_parsing=True)
                self.assertEqual({"grant_type", "assertion"}, set(form))
                encoded = form["assertion"][0].split(".")[1]
                claims = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
                self.assertEqual("https://oauth2.googleapis.com/token", claims["aud"])
                self.assertEqual("https://www.googleapis.com/auth/spreadsheets", claims["scope"])
                self.assertNotIn("sub", claims)
                if status == 200: self.assertEqual("sentinel", credential.token)


if __name__ == "__main__": unittest.main()
