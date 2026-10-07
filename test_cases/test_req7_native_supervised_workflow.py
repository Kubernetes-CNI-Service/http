"""Native HTTPS in a test-owned child, with a real inherited temporary lock.

The child entry and fake DNS/CA arguments exist only in this test module. No
production launcher, CA override, online credential or send permission ships.
The test uses the actual 30-second total budget, not an increased socket timeout
or a mocked monotonic clock. Full deployment/native DNS identity remains NOT RUN.
"""
import fcntl
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
import unittest
from unittest import mock

CANDIDATE = Path(__file__).resolve().parents[1]
# Explicit test-only bootstrap for Python -I. The partial candidate deliberately
# does not copy the governed main package; the parent supplies its owning test
# package root. No production launcher accepts this argument or a source root.
if len(sys.argv) > 1 and sys.argv[1] in ("--owned-fixture-child", "--owned-fixture-dns-child", "--owned-fixture-import-check"):
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
        for stream in (child.stdout, child.stderr): stream.close()


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
    wire = auth.TokenWireRequest("https://oauth2.googleapis.com/token", "POST", b"synthetic-body",
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


class Req7NativeSupervisedWorkflowTests(unittest.TestCase):
    setUp = tls_fixtures.Req7TlsInputsDirectTests.setUp
    certificates = wire_fixtures.Req7NativeTlsWireTests.certificates
    fixture = tls_fixtures.Req7TlsInputsDirectTests.fixture

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
    if len(sys.argv) > 1 and sys.argv[1] == "--owned-fixture-child": owned_fixture_child()
    elif len(sys.argv) > 1 and sys.argv[1] == "--owned-fixture-dns-child": owned_blocked_dns_fixture_child()
    elif len(sys.argv) > 1 and sys.argv[1] == "--owned-fixture-import-check": print("owned-fixture-import-ok")
    else: unittest.main()
