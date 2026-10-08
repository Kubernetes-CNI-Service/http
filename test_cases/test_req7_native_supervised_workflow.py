"""Native HTTPS in a test-owned child, with a real inherited temporary lock.

The child entry and fake DNS/CA arguments exist only in this test module. No
production launcher, CA override, online credential or send permission ships.
The test uses the actual 30-second total budget, not an increased socket timeout
or a mocked monotonic clock. Full deployment/native DNS identity remains NOT RUN.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock

CANDIDATE = Path(__file__).resolve().parents[1]
# Explicit test-only bootstrap for Python -I. The partial candidate deliberately
# does not copy the governed main package; the parent supplies its owning test
# package root. No production launcher accepts this argument or a source root.
if len(sys.argv) > 1 and sys.argv[1] in ("--owned-fixture-child", "--owned-fixture-input-child", "--owned-fixture-dns-child", "--owned-fixture-mutation-child", "--owned-fixture-import-check"):
    package_root = sys.argv[2] if sys.argv[1] == "--owned-fixture-import-check" else sys.argv[4]
    sys.path.insert(0, package_root)
    sys.path.insert(0, str(Path(package_root) / "tools"))
sys.path.insert(0, str(CANDIDATE / "test_cases"))
import test_req7_native_tls_wire as wire_fixtures
import test_req7_tls_inputs as tls_fixtures
import test_req7_attempt_supervision as supervision_fixtures


def cleanup_owned_fixture_child(child):
    # This fixture creates no descendants. Reap an early import failure without
    # signalling its now-stale group number. A live child must retain its own
    # session identity; failure to confirm cleanup remains a test error.
    try:
        if child.poll() is None:
            if os.getpgid(child.pid) != child.pid or os.getsid(child.pid) != child.pid:
                raise AssertionError("owned fixture lost its session identity")
            try: os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError: pass
        child.wait(timeout=3)
    finally:
        for stream in (child.stdin, child.stdout, child.stderr):
            if stream is not None: stream.close()


def owned_fixture_child():
    from test_req7_sdk_authentication import load as load_auth
    tls, auth = tls_fixtures.load(), load_auth()
    # Test-owned CA bytes; the production helper still uses its fixed path.
    fixture = object.__new__(tls_fixtures.Req7TlsInputsDirectTests)
    fixture.root = Path(sys.argv[2]); fixture.path = fixture.root / "etc/ssl/certs/ca-certificates.crt"
    port = int(sys.argv[3])
    def resolve(host, endpoint, *args, **kwargs):
        if (host, endpoint) != ("oauth2.googleapis.com", 443):
            raise AssertionError("online/foreign DNS forbidden in owned test child")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
    body = b"synthetic-body"
    if sys.argv[1] == "--owned-fixture-input-child":
        body = sys.stdin.buffer.read(32769)
        if body != b"owned-private-request" * 900:
            raise AssertionError("owned private request differs or lacks bounded EOF")
    wire = auth.TokenWireRequest("https://oauth2.googleapis.com/token", "POST", body,
                                (("Content-Type", "application/x-www-form-urlencoded"),), 30.0)
    with fixture.fixture(), mock.patch("socket.getaddrinfo", side_effect=resolve):
        result = tls.NativeTokenHttpsUnit().send_once(wire)
    os.write(1, result.data)


def owned_blocked_dns_fixture_child():
    from test_req7_sdk_authentication import load as load_auth
    tls, auth = tls_fixtures.load(), load_auth()
    fixture = object.__new__(tls_fixtures.Req7TlsInputsDirectTests)
    fixture.root = Path(sys.argv[2]); fixture.path = fixture.root / "etc/ssl/certs/ca-certificates.crt"

    def blocked_resolve(host, endpoint, *args, **kwargs):
        if (host, endpoint) != ("oauth2.googleapis.com", 443):
            raise AssertionError("foreign destination in owned DNS fixture")
        (fixture.root / "dns-entered").write_text("oauth2.googleapis.com:443\n")
        time.sleep(90)
        raise AssertionError("fixed total budget must stop the owned blocked resolver")

    wire = auth.TokenWireRequest("https://oauth2.googleapis.com/token", "POST", b"synthetic-body",
                                (("Content-Type", "application/x-www-form-urlencoded"),), 30.0)
    with fixture.fixture(), mock.patch("socket.getaddrinfo", side_effect=blocked_resolve):
        result = tls.NativeTokenHttpsUnit().send_once(wire)
    os.write(1, result.data)


def owned_original_mutation_fixture_child():
    # Test-owned isolated program only. Production TLS/FD/coherence and parent
    # supervision are real; only local DNS and root/CA metadata are synthetic.
    from monitor import issue_tracker_tls_inputs as tls
    from monitor.issue_tracker_online_target import OnlineTargetBinding
    from monitor.issue_tracker_sdk_authentication import AuthenticatedToken
    raw = sys.stdin.buffer.read(32769)
    if len(raw) > 32768: raise AssertionError('private input limit unchanged')
    value = json.loads(raw)
    if set(value) != {'binding','token','expires_at'}: raise AssertionError('no body/program/URL override')
    target = OnlineTargetBinding(**value['binding'])
    token = AuthenticatedToken(value['token'],value['expires_at'])
    fixture = object.__new__(tls_fixtures.Req7TlsInputsDirectTests)
    fixture.root = Path(sys.argv[2]); fixture.path = fixture.root/'etc/ssl/certs/ca-certificates.crt'
    port = int(sys.argv[3]); action_fd,wire_fd = int(sys.argv[5]),int(sys.argv[6])
    def resolve(host,endpoint,*args,**kwargs):
        if (host,endpoint) != ('sheets.googleapis.com',443): raise AssertionError('foreign destination')
        return [(socket.AF_INET,socket.SOCK_STREAM,6,'',('127.0.0.1',port))]
    with fixture.fixture(), mock.patch('socket.getaddrinfo',side_effect=resolve):
        native = tls.NativeOriginalSheetsMutationUnit(target,token,action_fd,wire_fd)
        observed = native.send_once()
        try: native.send_once()
        except tls.TlsInputHold: pass
        else: raise AssertionError('one object resent original')
    if 'yaml' in sys.modules or 'openpyxl' in sys.modules: raise AssertionError('parent-only dependencies in child')
    os.write(1,json.dumps(vars(observed),sort_keys=True,separators=(',',':')).encode()+b'\n')


class Req7NativeSupervisedWorkflowTests(unittest.TestCase):
    setUp = tls_fixtures.Req7TlsInputsDirectTests.setUp
    certificates = wire_fixtures.Req7NativeTlsWireTests.certificates
    fixture = tls_fixtures.Req7TlsInputsDirectTests.fixture
    server = wire_fixtures.Req7NativeTlsWireTests.server

    def original_mutation(self,stack,*,large=False):
        from test_cases.test_req7_history_read_launcher import Req7HistoryReadLauncherWorkflowTests as owners
        from test_cases.test_req7_global_attempt_journal import load as load_global
        from test_cases.test_req7_send_unit import load as load_unit, inputs, TARGET
        local,ownership,writer,owner,target,token,_config = owners.owners(self,stack,target_id=TARGET)
        arguments = inputs(20 if large else 2)
        if large: arguments['business'] = tuple({**item,'values':{'L':'x'*4096}} for item in arguments['business'])
        value = load_unit().freeze_send_unit(**arguments); journal = load_global()
        journal.prepare_global_unit(owner,target,value); journal.record_global_attempt_intent(owner,target,value)
        image = stack.enter_context(journal._hold_counted_original_wire(writer,owner,target,value))
        raw = json.dumps({'binding':vars(target),'token':token.value,'expires_at':token.expires_at},sort_keys=True,separators=(',',':')).encode()
        self.assertLessEqual(len(raw),32768); self.assertNotIn(value.wire_bytes,raw)
        locks = (local._owner(writer).lock_fd,ownership.owner_lock_fd(owner,target))
        contenders = tuple(os.open(self.root/'project/.tracker/LOCK' if index==0 else
            self.root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(TARGET.encode()).hexdigest()+'.lock'),os.O_RDWR)
            for index in range(2))
        for fd in contenders: stack.callback(os.close,fd)
        return journal,owner,target,value,image,raw,locks,contenders

    def launch_original_fixture(self,port,image,locks):
        started = time.monotonic()
        child = subprocess.Popen([sys.executable,'-I','-B',str(Path(__file__).resolve()),
            '--owned-fixture-mutation-child',str(self.root),str(port),str(tls_fixtures.ROOT),str(image.action_fd),str(image.fd)],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True,
            start_new_session=True,pass_fds=locks+(image.action_fd,image.fd),env={'LC_ALL':'C'})
        self.addCleanup(cleanup_owned_fixture_child,child)
        return child,started

    def test_real_isolated_large_original_mutation_consumes_claim_once_with_dual_locks_and_no_resend(self):
        from contextlib import ExitStack
        supervision = supervision_fixtures.load()
        reply = b'HTTP/1.1 401 Denied\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}'
        with self.server(reply,hostname='sheets.googleapis.com',destination='sheets.googleapis.com',request_limit=1024*1024) as (records,errors), ExitStack() as stack:
            port = socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
            journal,owner,target,value,image,raw,locks,contenders = self.original_mutation(stack,large=True)
            self.assertGreater(len(value.wire_bytes),65536)
            child,started = self.launch_original_fixture(port,image,locks)
            completion = supervision.supervise_owned_attempt(child,started_monotonic=started,kind='mutation',request_bytes=raw)
            self.assertTrue(completion.termination_confirmed); self.assertEqual(0,child.returncode)
            result = json.loads(completion.data)
            self.assertEqual({'status':401,'wire_sha256':value.wire_sha256,'response_sha256':hashlib.sha256(b'{}').hexdigest(),'outcome':'UNKNOWN'},result)
            for fd in contenders:
                with self.assertRaises(BlockingIOError): fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.assertEqual(1,journal.inspect_global_unit(owner,target,value).attempt_count)
            self.assertFalse((self.root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(target.spreadsheet_id.encode()).hexdigest()+'.journal')/'ATTEMPT-2').exists())
        self.assertEqual([],errors); self.assertEqual(1,len(records))
        self.assertEqual(b'POST /v4/spreadsheets/synthetic_spreadsheet_id_0001:batchUpdate HTTP/1.1\r\n',records[0][0])
        self.assertEqual(value.wire_bytes,records[0][2]); self.assertEqual(22,len(json.loads(records[0][2])['requests']))

    def test_real_original_mutation_slow_body_is_killed_at_total_60_seconds_and_keeps_unknown(self):
        from contextlib import ExitStack
        supervision = supervision_fixtures.load(); stop = threading.Event(); reached = threading.Event()
        def slow(transport):
            transport.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{')
            reached.set(); stop.wait(75)
        try:
            with self.server(slow,hostname='sheets.googleapis.com',destination='sheets.googleapis.com') as (records,errors), ExitStack() as stack:
                port = socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
                journal,owner,target,value,image,raw,locks,contenders = self.original_mutation(stack)
                child,started = self.launch_original_fixture(port,image,locks)
                try:
                    with self.assertRaises(supervision.AttemptHold) as caught:
                        supervision.supervise_owned_attempt(child,started_monotonic=started,kind='mutation',request_bytes=raw)
                finally: stop.set()
                self.assertTrue(reached.is_set(),'actual original batch did not reach slow native TLS response')
                self.assertTrue(caught.exception.termination_confirmed); self.assertIsNotNone(child.poll())
                elapsed = time.monotonic()-started
                self.assertGreaterEqual(elapsed,59.5); self.assertLess(elapsed,63.0)
                for fd in contenders:
                    with self.assertRaises(BlockingIOError): fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                self.assertEqual((1,'UNKNOWN'),(journal.inspect_global_unit(owner,target,value).attempt_count,journal.inspect_global_unit(owner,target,value).outcome))
            self.assertEqual([],errors); self.assertEqual(1,len(records)); self.assertEqual(value.wire_bytes,records[0][2])
        finally: stop.set()

    def test_private_input_eof_precedes_one_native_tls_request_and_completion_retains_parent_lock(self):
        supervision = supervision_fixtures.load(); context = self.certificates()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0)); listener.listen(1); listener.settimeout(5)
        self.addCleanup(listener.close)
        path = self.root / 'owned-private-input.lock'
        held = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        self.addCleanup(os.close, held); fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        contender = os.open(path, os.O_RDWR); self.addCleanup(os.close, contender)
        request = b'owned-private-request' * 900; seen = []; failures = []
        def serve():
            try:
                connection, _peer = listener.accept(); connection.settimeout(5)
                with context.wrap_socket(connection, server_side=True) as transport:
                    with transport.makefile('rb') as incoming:
                        self.assertEqual(b'POST /token HTTP/1.1\r\n', incoming.readline(8193))
                        headers = []
                        for _ in range(100):
                            line = incoming.readline(8193)
                            if line == b'\r\n': break
                            self.assertTrue(line); headers.append(line)
                        else: self.fail('owned headers exceed independent bound')
                        self.assertIn(b'Host: oauth2.googleapis.com\r\n', headers)
                        sizes = [int(line.split(b':', 1)[1]) for line in headers if line.lower().startswith(b'content-length:')]
                        self.assertEqual([len(request)], sizes)
                        seen.append(incoming.read(len(request))); self.assertEqual(request, seen[0])
                    with self.assertRaises(BlockingIOError): fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    transport.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 18\r\nConnection: close\r\n\r\nowned-tls-response')
            except BaseException as exc: failures.append(exc)
        thread = threading.Thread(target=serve, daemon=True); thread.start()
        started = time.monotonic()
        child = subprocess.Popen([sys.executable, '-I', '-B', str(Path(__file__).resolve()),
                                  '--owned-fixture-input-child', str(self.root), str(listener.getsockname()[1]),
                                  str(tls_fixtures.ROOT)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, close_fds=True, start_new_session=True, pass_fds=(held,))
        self.addCleanup(cleanup_owned_fixture_child, child)
        try:
            result = supervision.supervise_owned_attempt(child, started_monotonic=started, kind='read', request_bytes=request)
        finally: thread.join(6)
        self.assertFalse(thread.is_alive()); self.assertEqual([], failures)
        self.assertEqual([request], seen); self.assertEqual(b'owned-tls-response', result.data)
        self.assertTrue(result.termination_confirmed); self.assertTrue(child.stdin.closed); self.assertEqual(0, child.returncode)
        self.assertNotIn('owned-private-request', repr(result))
        with self.assertRaises(BlockingIOError): fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_isolated_fixture_bootstrap_imports_the_owning_package_without_ambient_sys_path(self):
        result = subprocess.run([sys.executable, "-I", "-B", str(Path(__file__).resolve()),
                                 "--owned-fixture-import-check", str(tls_fixtures.ROOT)],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, timeout=5)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("owned-fixture-import-ok\n", result.stdout)

    def test_already_exited_fixture_cleanup_reaps_without_signalling_a_stale_group_id(self):
        child = subprocess.Popen([sys.executable, "-I", "-B", "-c", "pass"], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        child.wait(timeout=3)
        try:
            with mock.patch("os.killpg", side_effect=AssertionError("exited fixture must not be signalled")):
                cleanup_owned_fixture_child(child)
        finally:
            for stream in (child.stdout, child.stderr): stream.close()
        self.assertIsNotNone(child.returncode)
        self.assertTrue(child.stdout.closed); self.assertTrue(child.stderr.closed)

    def test_real_slow_tls_body_cannot_restart_total_budget_and_inherited_lock_survives_parent_close(self):
        supervision = supervision_fixtures.load()
        context = self.certificates()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0)); listener.listen(1); listener.settimeout(5)
        self.addCleanup(listener.close)
        path = self.root / "owned-sheet.lock"
        held = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        started = time.monotonic()
        try:
            child = subprocess.Popen(
                [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--owned-fixture-child",
                 str(self.root), str(listener.getsockname()[1]), str(tls_fixtures.ROOT)], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
                start_new_session=True, pass_fds=(held,),
            )
        finally: os.close(held)
        self.addCleanup(cleanup_owned_fixture_child, child)
        contender = os.open(path, os.O_RDWR); self.addCleanup(os.close, contender)
        connection, _peer = listener.accept(); connection.settimeout(5)
        transport = context.wrap_socket(connection, server_side=True)
        self.addCleanup(transport.close)
        with transport.makefile("rb") as incoming:
            self.assertEqual(b"POST /token HTTP/1.1\r\n", incoming.readline(8193))
            headers = []
            for _ in range(100):
                line = incoming.readline(8193)
                if line == b"\r\n": break
                self.assertTrue(line); headers.append(line)
            else: self.fail("owned request headers exceed independent bound")
            self.assertIn(b"Host: oauth2.googleapis.com\r\n", headers)
            length = [int(line.split(b":", 1)[1]) for line in headers if line.lower().startswith(b"content-length:")]
            self.assertEqual([14], length); self.assertEqual(b"synthetic-body", incoming.read(14))
        with self.assertRaises(BlockingIOError): fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        transport.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 128\r\nConnection: close\r\n\r\n")
        import threading
        stopped = threading.Event(); sent = []
        def drip():
            try:
                for _ in range(128):
                    if stopped.wait(0.5): break
                    transport.sendall(b"x"); sent.append(1)
            except OSError: pass  # Killing this test-owned client may reset TLS.
        thread = threading.Thread(target=drip, daemon=True); thread.start()
        try:
            with self.assertRaises(supervision.AttemptHold) as caught:
                supervision.supervise_owned_attempt(child, started_monotonic=started, kind="token")
        finally:
            stopped.set(); thread.join(3)
        self.assertFalse(thread.is_alive()); self.assertGreater(len(sent), 1)
        self.assertLess(len(sent), 128)
        self.assertEqual("req7_attempt_denied", str(caught.exception))
        self.assertIsNone(caught.exception.__context__)
        self.assertIs(True, caught.exception.termination_confirmed)
        elapsed = time.monotonic() - started
        self.assertGreaterEqual(elapsed, 29.5)
        self.assertLess(elapsed, 33.0)
        self.assertIsNotNone(child.poll())
        fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.assertTrue(path.is_file())

    def test_native_https_blocked_dns_is_included_in_total_budget_with_inherited_lock(self):
        supervision = supervision_fixtures.load()
        self.certificates()
        marker = self.root / "dns-entered"
        path = self.root / "owned-dns-sheet.lock"
        held = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        started = time.monotonic()
        try:
            child = subprocess.Popen(
                [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--owned-fixture-dns-child",
                 str(self.root), "unused-owned-port", str(tls_fixtures.ROOT)],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                close_fds=True, start_new_session=True, pass_fds=(held,),
            )
        finally:
            os.close(held)
        self.addCleanup(cleanup_owned_fixture_child, child)
        contender = os.open(path, os.O_RDWR); self.addCleanup(os.close, contender)
        ready_deadline = time.monotonic() + 5
        while not marker.exists() and child.poll() is None and time.monotonic() < ready_deadline:
            time.sleep(0.01)
        self.assertTrue(marker.exists(), "actual HTTPS did not reach the owned blocked DNS fixture")
        self.assertEqual("oauth2.googleapis.com:443\n", marker.read_text())
        self.assertIsNone(child.poll())
        with self.assertRaises(BlockingIOError):
            fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with self.assertRaises(supervision.AttemptHold) as caught:
            supervision.supervise_owned_attempt(child, started_monotonic=started, kind="token")
        self.assertEqual("req7_attempt_denied", str(caught.exception))
        self.assertIsNone(caught.exception.__context__)
        self.assertIs(True, caught.exception.termination_confirmed)
        self.assertGreaterEqual(time.monotonic() - started, 29.5)
        self.assertLess(time.monotonic() - started, 33.0)
        self.assertIsNotNone(child.poll())
        fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.assertTrue(path.is_file())


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("--owned-fixture-child", "--owned-fixture-input-child"): owned_fixture_child()
    elif len(sys.argv) > 1 and sys.argv[1] == "--owned-fixture-dns-child": owned_blocked_dns_fixture_child()
    elif len(sys.argv) > 1 and sys.argv[1] == "--owned-fixture-mutation-child": owned_original_mutation_fixture_child()
    elif len(sys.argv) > 1 and sys.argv[1] == "--owned-fixture-import-check": print("owned-fixture-import-ok")
    else: unittest.main()
