"""Owned real child processes; no sockets, real locks, credentials or online activation."""
import fcntl
import importlib.util
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

MODULE = Path(__file__).resolve().parents[1] / "monitor/issue_tracker_attempt_supervision.py"
sys.path.insert(0, str(Path(__file__).resolve().parent))


def load():
    if not MODULE.is_file(): raise AssertionError("REQ7 owned attempt supervision missing")
    spec = importlib.util.spec_from_file_location("req7_attempt_supervision_candidate", MODULE)
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module
    spec.loader.exec_module(module); return module


class Req7AttemptSupervisionDirectTests(unittest.TestCase):
    def setUp(self): self.module = load(); self.children = []; self.addCleanup(self.cleanup)

    def cleanup(self):
        for child in self.children:
            try:
                # No PID/group-number signal after reaping a terminal fixture.
                # The supervisor-death case releases and observes its own
                # descendant's lock before leaving the test body.
                if child.poll() is None:
                    if os.getpgid(child.pid) != child.pid or os.getsid(child.pid) != child.pid:
                        raise AssertionError("owned fixture lost its private session")
                    try: os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                child.wait(timeout=3)
            finally:
                for stream in (child.stdin, child.stdout, child.stderr):
                    if stream is not None: stream.close()

    def child(self, program, pass_fds=()):
        process = subprocess.Popen([sys.executable, "-I", "-B", "-c", program],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True,
                                   close_fds=True, pass_fds=pass_fds)
        self.children.append(process); return process

    def test_terminal_fixture_cleanup_reaps_without_signalling_a_stale_group_number(self):
        process = self.child('pass')
        process.wait(timeout=3)
        with mock.patch("os.killpg", side_effect=AssertionError("terminal fixture group must not be signalled")):
            self.cleanup()
        self.assertEqual(0, process.returncode)
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)

    def test_terminal_leader_with_a_live_group_cannot_establish_signal_ownership(self):
        process = self.child('pass')
        process.wait(timeout=3)
        # After the native leader is reaped, matching PID/PGID/SID numbers may
        # refer to a reused identity. Neither a live numeric group nor cached
        # Popen identity is authority to signal it or release a sheet lock.
        with mock.patch.object(self.module, "_group_alive", return_value=True), \
                mock.patch.object(self.module.os, "getpgid", return_value=process.pid), \
                mock.patch.object(self.module.os, "getsid", return_value=process.pid), \
                mock.patch.object(self.module.os, "killpg") as kill, \
                self.assertRaises(self.module.AttemptHold) as caught:
            self.module.supervise_owned_attempt(process, started_monotonic=time.monotonic(), kind="mutation")
        kill.assert_not_called()
        self.assertIs(False, caught.exception.termination_confirmed)
        self.assertIsNone(caught.exception.__context__)

    def test_complete_exit_and_bounded_bytes_are_private_and_immutable(self):
        started = time.monotonic()
        process = self.child('import os; os.write(1,b"synthetic-complete-response")')
        result = self.module.supervise_owned_attempt(process, started_monotonic=started, kind="token")
        self.assertEqual(b"synthetic-complete-response", result.data)
        self.assertIs(True, result.termination_confirmed); self.assertEqual(0, process.returncode)
        self.assertNotIn("synthetic-complete-response", repr(result))
        with self.assertRaises(AttributeError): result.data = b"foreign"

    def test_leader_reaped_after_admission_cannot_authorize_cleanup_signals(self):
        process = self.child('import time; time.sleep(100)')
        self.assertIsNone(process.poll())
        def fail_after_reaping():
            # Only this fixture's still-owned leader is terminated here.
            process.terminate()
            process.wait(timeout=3)
            raise OSError("synthetic selector fault after identity was lost")
        with mock.patch.object(self.module.selectors, "DefaultSelector", side_effect=fail_after_reaping), \
                mock.patch.object(self.module, "_group_alive", return_value=True), \
                mock.patch.object(self.module.os, "killpg") as kill, \
                self.assertRaises(self.module.AttemptHold) as caught:
            self.module.supervise_owned_attempt(process, started_monotonic=time.monotonic(), kind="mutation")
        kill.assert_not_called()
        self.assertIs(False, caught.exception.termination_confirmed)
        self.assertIsNone(caught.exception.__context__)

    def test_slow_resolver_or_reader_uses_remaining_total_budget_not_a_fresh_timeout(self):
        for phase in ("synthetic DNS block", "synthetic slow-read block"):
            process = self.child('import time; time.sleep(100)')
            before = time.monotonic()
            with self.subTest(phase=phase), self.assertRaises(self.module.AttemptHold) as caught:
                self.module.supervise_owned_attempt(process, started_monotonic=before - 29.8, kind="token")
            self.assertLess(time.monotonic() - before, 3)
            self.assertEqual("req7_attempt_denied", str(caught.exception))
            self.assertIsNone(caught.exception.__context__)
            self.assertIs(True, caught.exception.termination_confirmed)
            self.assertIsNotNone(process.returncode)

    def test_stderr_nonzero_empty_or_oversized_output_never_returns_a_complete_response(self):
        programs = ('import os; os.write(2,b"sentinel secret error")',
                    'import os; os.write(1,b"sentinel secret"); raise SystemExit(7)',
                    'pass',
                    'import os; remaining=2*1024*1024+1\nwhile remaining:\n n=os.write(1,b"x"*min(65536,remaining)); remaining-=n')
        for program in programs:
            before = time.monotonic(); process = self.child(program)
            with self.subTest(case=program.split(";")[0]), self.assertRaises(self.module.AttemptHold) as caught:
                self.module.supervise_owned_attempt(process, started_monotonic=before, kind="read")
            self.assertEqual("req7_attempt_denied", str(caught.exception))
            self.assertIsNone(caught.exception.__context__)
            self.assertIs(True, caught.exception.termination_confirmed)

    def test_closed_response_pipe_does_not_prove_that_the_child_cannot_still_send(self):
        process = self.child('import os,time; os.close(1); os.close(2); time.sleep(100)')
        with self.assertRaises(self.module.AttemptHold) as caught:
            self.module.supervise_owned_attempt(process, started_monotonic=time.monotonic() - 29.8, kind="read")
        self.assertIs(True, caught.exception.termination_confirmed)
        self.assertIsNotNone(process.returncode)

    def test_unconfirmed_group_termination_is_explicit_hold_not_success_or_unlock(self):
        process = self.child('import time; time.sleep(100)')
        actual_kill = os.killpg
        def deny_signal(group, operation):
            if operation == 0: return actual_kill(group, operation)
            raise PermissionError("sentinel cannot terminate owned group")
        with mock.patch("os.killpg", side_effect=deny_signal), self.assertRaises(self.module.AttemptHold) as caught:
            self.module.supervise_owned_attempt(process, started_monotonic=time.monotonic() - 30, kind="token")
        self.assertIs(False, caught.exception.termination_confirmed)
        self.assertIsNone(caught.exception.__context__)
        self.assertIsNone(process.poll())

    def test_selector_setup_failure_still_stops_the_owned_child_and_sanitizes_context(self):
        process = self.child('import time; time.sleep(100)')
        with mock.patch.object(self.module.selectors, "DefaultSelector", side_effect=OSError("sentinel selector fault")), self.assertRaises(
            self.module.AttemptHold,
        ) as caught:
            self.module.supervise_owned_attempt(process, started_monotonic=time.monotonic(), kind="token")
        self.assertEqual("req7_attempt_denied", str(caught.exception))
        self.assertIsNone(caught.exception.__context__)
        self.assertIs(True, caught.exception.termination_confirmed)
        self.assertIsNotNone(process.poll())

    def test_cleanup_fault_is_sanitized_unconfirmed_hold_and_keeps_the_child_live(self):
        process = self.child('import time; time.sleep(100)')
        with mock.patch.object(self.module.selectors, "DefaultSelector", side_effect=OSError("sentinel selector fault")), \
                mock.patch.object(self.module, "_stop_owned_group", side_effect=OSError("sentinel secret cleanup error")), \
                self.assertRaises(self.module.AttemptHold) as caught:
            self.module.supervise_owned_attempt(process, started_monotonic=time.monotonic(), kind="token")
        self.assertEqual("req7_attempt_denied", str(caught.exception))
        self.assertIsNone(caught.exception.__context__)
        self.assertIsNone(caught.exception.__cause__)
        self.assertIs(False, caught.exception.termination_confirmed)
        self.assertIsNone(process.poll())

    def test_invalid_budget_identity_refuses_without_signalling_the_owned_child(self):
        process = self.child('import time; time.sleep(100)')
        for kind, started in (("other", time.monotonic()), ("token", True), ("token", float("nan")),
                              ("token", float("inf")), ("token", 10 ** 1000),
                              ("token", time.monotonic() + 100)):
            with self.subTest(kind=kind, started_type=type(started).__name__), mock.patch("os.killpg") as kill, self.assertRaises(
                self.module.AttemptHold,
            ):
                self.module.supervise_owned_attempt(process, started_monotonic=started, kind=kind)
            kill.assert_not_called(); self.assertIsNone(process.poll())


class Req7AttemptLockWorkflowTests(unittest.TestCase):
    # Direct tests execute only in the original class; share fixture machinery.
    setUp = Req7AttemptSupervisionDirectTests.setUp
    child = Req7AttemptSupervisionDirectTests.child
    cleanup = Req7AttemptSupervisionDirectTests.cleanup

    def test_failed_termination_keeps_inherited_sheet_lock_until_owned_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "owned-unconfirmed-spreadsheet.lock"
            descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                process = self.child('import os,time; os.write(1,b"ready"); time.sleep(100)', (descriptor,))
                self.assertEqual([process.stdout], select.select([process.stdout], [], [], 3)[0])
                self.assertEqual(b"ready", process.stdout.read(5))
            finally:
                os.close(descriptor)
            contender = os.open(path, os.O_RDWR)
            actual_kill = os.killpg
            def deny_signal(group, operation):
                if operation == 0: return actual_kill(group, operation)
                raise PermissionError("owned fixture termination denied")
            try:
                with mock.patch("os.killpg", side_effect=deny_signal), self.assertRaises(self.module.AttemptHold) as caught:
                    self.module.supervise_owned_attempt(process, started_monotonic=time.monotonic()-60, kind="mutation")
                self.assertIs(False, caught.exception.termination_confirmed)
                self.assertIsNone(caught.exception.__context__)
                self.assertIsNone(process.poll())
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.assertEqual(process.pid, os.getpgid(process.pid))
                self.assertEqual(process.pid, os.getsid(process.pid))
                actual_kill(process.pid, signal.SIGKILL)
                process.wait(timeout=3)
                fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.assertTrue(path.is_file())
            finally:
                os.close(contender)

    def test_child_inherited_lock_survives_parent_descriptor_close_until_confirmed_termination(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "owned-spreadsheet.lock"
            descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                process = self.child('import os,time; os.write(1,b"ready"); time.sleep(100)', (descriptor,))
                self.assertEqual([process.stdout], select.select([process.stdout], [], [], 3)[0])
                self.assertEqual(b"ready", process.stdout.read(5))
            finally: os.close(descriptor)
            contender = os.open(path, os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError): fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaises(self.module.AttemptHold) as caught:
                    self.module.supervise_owned_attempt(process, started_monotonic=time.monotonic() - 60, kind="mutation")
                self.assertIs(True, caught.exception.termination_confirmed)
                fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.assertTrue(path.is_file())
            finally: os.close(contender)

    def test_real_supervisor_death_does_not_release_an_inherited_child_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "owned-orphan-spreadsheet.lock"
            descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            release_read, release_write = os.pipe()
            child_program = 'import os; os.write(1,b"ready"); os.read(%d,1)' % release_read
            parent_program = ('import subprocess,sys,time; subprocess.Popen([sys.executable,"-I","-B","-c",%r],'
                              'close_fds=True,pass_fds=(%d,%d)); time.sleep(100)') % (
                                  child_program, descriptor, release_read)
            try:
                supervisor = self.child(parent_program, (descriptor, release_read))
                self.assertEqual([supervisor.stdout], select.select([supervisor.stdout], [], [], 3)[0])
                self.assertEqual(b"ready", supervisor.stdout.read(5))
            finally:
                os.close(descriptor); os.close(release_read)
            contender = os.open(path, os.O_RDWR)
            try:
                supervisor.kill(); supervisor.wait(timeout=3)  # Only this test-owned fake supervisor.
                with self.assertRaises(BlockingIOError): fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                os.write(release_write, b"x")
                deadline = time.monotonic() + 3
                acquired = False
                while time.monotonic() < deadline:
                    try:
                        fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB); acquired = True; break
                    except BlockingIOError: time.sleep(0.01)
                self.assertTrue(acquired)
                self.assertTrue(path.is_file())
            finally:
                os.close(contender); os.close(release_write)

    def test_public_sdk_and_tls_shape_cross_a_supervised_fake_unit_without_hidden_retry(self):
        from test_req7_sdk_authentication import load as load_auth, parsed_info, fresh_info
        from test_req7_tls_inputs import load as load_tls
        auth, tls = load_auth(), load_tls()
        parsed = parsed_info(fresh_info())
        for status in (200, 503):
            observations = []; outer = self
            class FakeSupervisedUnit:
                def send_once(self, wire):
                    observations.append(tls.prepare_token_request(wire))
                    started = time.monotonic()
                    process = outer.child('import os; os.write(1,b\'{"access_token":"sentinel","expires_in":3600}\')')
                    completion = outer.module.supervise_owned_attempt(process, started_monotonic=started, kind="token")
                    return SimpleNamespace(status=status, complete=completion.termination_confirmed,
                                           data=completion.data, headers=(("content-type", "application/json"),))
            with self.subTest(status=status), mock.patch("socket.socket", side_effect=AssertionError("network forbidden")):
                if status == 200:
                    result = auth.refresh_validated_service_account(parsed, FakeSupervisedUnit())
                    self.assertEqual("sentinel", result.value)
                else:
                    with self.assertRaises(auth.AuthenticationHold) as caught:
                        auth.refresh_validated_service_account(parsed, FakeSupervisedUnit())
                    self.assertIsNone(caught.exception.__context__)
            self.assertEqual(1, len(observations))
            self.assertEqual("oauth2.googleapis.com", observations[0].host)
            self.assertEqual(30.0, observations[0].budget_seconds)


if __name__ == "__main__": unittest.main()
