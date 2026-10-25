"""O-only tests-first TEXT; not executed by its author.

Intended ordinary path: test_cases/test_initial_setup_pty_cleanup.py.
Only three owned PUBLIC child processes, one per method, on future Root issue.
No SSH, keys, packages, credentials, network or device operations are involved.
The current and prospective source remain immutable; this is not proof of a
new regression. The fixture's independent cleanup is never counted as SUT reap.
"""
from pathlib import Path
import errno
import os
import signal
import sys
import unittest
from unittest import mock

from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
INITIAL = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
READY = "PUBLIC-ready\n"


class InitialPTYClosePrimaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.name != "posix" or not INITIAL.is_file():
            raise RuntimeError("FIXTURE_HOLD: canonical POSIX source prerequisite")
        cls.app = load_script("initial_pty_cleanup_public_subject", INITIAL)

    def _observe(self, *, fail_in_responder):
        app = self.app
        # Capture all real functions before installing any transparent bridge.
        real_fork = app.pty.fork
        real_close, real_fstat = os.close, os.fstat
        real_waitpid, real_kill = os.waitpid, os.kill
        original = RuntimeError("PUBLIC original responder error")
        close_error = OSError(errno.EIO, "PUBLIC master close diagnostic")
        facts = {
            "pid": None, "master": None, "forks": 0,
            "ready": False, "close_calls": 0, "real_close_returned": False,
            "closed_ebadf": False, "sut_reaped": False, "sut_status": None,
            "sut_waits": [], "fixture_waits": [], "fixture_kill": False,
            "fixture_reaped": False, "fixture_close": False,
            "adapter_errors": [], "fixture_errors": [],
        }

        def fork_bridge():
            pid, master = real_fork()
            if pid > 0:
                facts["forks"] += 1
                facts["pid"], facts["master"] = pid, master
            return pid, master

        def close_bridge(fd):
            if fd != facts["master"] or facts["master"] is None:
                return real_close(fd)
            facts["close_calls"] += 1
            if facts["close_calls"] != 1:
                # Never actually retry a possibly closed/reused descriptor.
                facts["adapter_errors"].append("RETRIED_TARGET_MASTER_CLOSE")
                raise close_error
            try:
                real_close(fd)
            except OSError:
                facts["adapter_errors"].append("REAL_MASTER_CLOSE_DID_NOT_RETURN")
                raise
            facts["real_close_returned"] = True
            try:
                real_fstat(fd)
            except OSError as error:
                facts["closed_ebadf"] = error.errno == errno.EBADF
            else:
                facts["adapter_errors"].append("MASTER_NOT_CLOSED")
            raise close_error

        def wait_bridge(pid, options):
            result = real_waitpid(pid, options)
            if pid == facts["pid"]:
                facts["sut_waits"].append((options, result))
                if result[0] == pid:
                    facts["sut_reaped"] = True
                    facts["sut_status"] = result[1]
            return result

        def responder(output):
            if READY.strip() in output:
                facts["ready"] = True
                if fail_in_responder:
                    raise original
            return None

        # The child has no descendants or filesystem/network actions. Its only
        # output is a fixed PUBLIC readiness prefix. Normal case really exits7;
        # responder-error case has a finite8-second sleep as a fail-safe.
        child = (
            "import os,time; os.write(1,b'PUBLIC-ready\\n'); "
            + ("time.sleep(8); os._exit(0)" if fail_in_responder
               else "time.sleep(0.05); os._exit(7)")
        )
        caught, returned = None, None
        try:
            with mock.patch.object(app.pty, "fork", side_effect=fork_bridge), \
                    mock.patch.object(app.os, "close", side_effect=close_bridge), \
                    mock.patch.object(app.os, "waitpid", side_effect=wait_bridge):
                try:
                    returned = app.interactive_run(
                        [sys.executable, "-I", "-S", "-B", "-c", child],
                        responder, 3,
                    )
                except BaseException as error:
                    caught = error
        finally:
            # This is a fail-safe fixture, outside all patches. It may reap only
            # the actual pid returned by this method's one real pty.fork. A
            # successful SUT wait token means no further fixture wait/signal.
            pid = facts["pid"]
            if type(pid) is int and pid > 0 and not facts["sut_reaped"]:
                try:
                    result = real_waitpid(pid, os.WNOHANG)
                    facts["fixture_waits"].append((os.WNOHANG, result))
                    if result[0] == pid:
                        facts["fixture_reaped"] = True
                    elif result[0] == 0:
                        real_kill(pid, signal.SIGKILL)
                        facts["fixture_kill"] = True
                        result = real_waitpid(pid, 0)
                        facts["fixture_waits"].append((0, result))
                        facts["fixture_reaped"] = result[0] == pid
                except OSError as error:
                    facts["fixture_errors"].append(("OWN_CHILD_CLEANUP", error.errno))
            # If the target never attempted closing its owned master, the
            # fixture may close that still-owned fd once. Never retry a close
            # that the target already attempted, regardless of its errno.
            master = facts["master"]
            if type(master) is int and master >= 0 and facts["close_calls"] == 0:
                try:
                    real_close(master)
                    facts["fixture_close"] = True
                except OSError as error:
                    facts["fixture_errors"].append(("UNATTEMPTED_MASTER_CLOSE", error.errno))

        if (facts["forks"] != 1 or not facts["ready"]
                or facts["close_calls"] == 0 or not facts["real_close_returned"]
                or not facts["closed_ebadf"] or facts["adapter_errors"]
                or facts["fixture_errors"]):
            raise RuntimeError("FIXTURE_HOLD: required real PTY/close witness incomplete")
        return facts, caught, returned, original, close_error

    def test_responder_primary_survives_close_error_and_owned_child_is_reaped(self):
        facts, caught, returned, original, _close_error = self._observe(
            fail_in_responder=True)
        self.assertIs(original, caught)
        self.assertIsNone(returned)
        self.assertEqual(1, facts["close_calls"])
        self.assertTrue(facts["real_close_returned"])
        self.assertTrue(facts["closed_ebadf"])
        self.assertTrue(facts["sut_reaped"], "fixture reap is not target cleanup proof")
        self.assertFalse(facts["fixture_reaped"])
        self.assertFalse(facts["fixture_kill"])
        self.assertEqual([], facts["fixture_waits"])

    def test_normal_child_close_error_is_not_success_or_retried(self):
        facts, caught, returned, _original, close_error = self._observe(
            fail_in_responder=False)
        self.assertIs(close_error, caught)
        self.assertIsNone(returned)
        self.assertEqual(1, facts["close_calls"])
        self.assertTrue(facts["real_close_returned"])
        self.assertTrue(facts["closed_ebadf"])
        self.assertTrue(facts["sut_reaped"])
        self.assertEqual(7, os.waitstatus_to_exitcode(facts["sut_status"]))
        self.assertFalse(facts["fixture_reaped"])
        self.assertFalse(facts["fixture_kill"])
        self.assertEqual([], facts["fixture_waits"])


    def test_double_signal_denial_preserves_primary_and_reports_actual_unreaped_uncertainty(self):
        app = self.app
        real_fork = app.pty.fork
        real_close, real_fstat = os.close, os.fstat
        real_waitpid, real_kill = os.waitpid, os.kill
        original = RuntimeError("PUBLIC original signal-denial primary")
        state = {
            "pid": None, "master": None, "forks": 0, "ready": False,
            "close_calls": 0, "closed": False, "signals": [],
            "sut_waits": [], "sut_reaped": False, "blocking_attempt": False,
            "fixture_waits": [], "fixture_killed": False,
            "fixture_reaped": False, "fixture_closed": False,
            "adapter_errors": [], "fixture_errors": [],
        }

        def fork_bridge():
            pid, master = real_fork()
            if pid > 0:
                state["forks"] += 1
                state["pid"], state["master"] = pid, master
            return pid, master

        def close_bridge(fd):
            if fd != state["master"] or state["master"] is None:
                return real_close(fd)
            state["close_calls"] += 1
            if state["close_calls"] != 1:
                state["adapter_errors"].append("RETRIED_TARGET_CLOSE")
                raise OSError(errno.EIO, "PUBLIC prevented ambiguous close retry")
            real_close(fd)
            try:
                real_fstat(fd)
            except OSError as error:
                state["closed"] = error.errno == errno.EBADF

        def deny_group(pid, sig):
            state["signals"].append(("killpg", pid, sig))
            if pid != state["pid"]:
                state["adapter_errors"].append("FOREIGN_GROUP_SIGNAL_ATTEMPT")
            raise PermissionError(errno.EPERM, "PUBLIC modeled group denial")

        def deny_pid(pid, sig):
            state["signals"].append(("kill", pid, sig))
            if pid != state["pid"]:
                state["adapter_errors"].append("FOREIGN_PID_SIGNAL_ATTEMPT")
            raise PermissionError(errno.EPERM, "PUBLIC modeled pid denial")

        def wait_bridge(pid, options):
            if pid != state["pid"]:
                state["adapter_errors"].append("FOREIGN_WAIT_ATTEMPT")
                raise RuntimeError("PUBLIC forbidden foreign wait")
            if options != os.WNOHANG:
                # Unsafe blocking attempts are a behavior failure observed
                # outside the subject, not a fabricated waitpid result.
                state["blocking_attempt"] = True
                raise RuntimeError("PUBLIC unexpected blocking wait")
            result = real_waitpid(pid, options)
            state["sut_waits"].append((options, result))
            if result[0] == pid:
                state["sut_reaped"] = True
            return result

        def responder(output):
            if READY.strip() in output:
                state["ready"] = True
                raise original
            return None

        # The first PUBLIC write follows real HUP-ignore registration, so real
        # master close cannot manufacture an already-reaped child. No target
        # signal call is actually sent in this explicit permission-error MODEL.
        child = (
            "import os,signal,time; signal.signal(signal.SIGHUP,signal.SIG_IGN); "
            "os.write(1,b'PUBLIC-ready\\n'); time.sleep(8); os._exit(0)"
        )
        caught, returned = None, None
        try:
            with mock.patch.object(app.pty, "fork", side_effect=fork_bridge), \
                    mock.patch.object(app.os, "close", side_effect=close_bridge), \
                    mock.patch.object(app.os, "killpg", side_effect=deny_group), \
                    mock.patch.object(app.os, "kill", side_effect=deny_pid), \
                    mock.patch.object(app.os, "waitpid", side_effect=wait_bridge):
                try:
                    returned = app.interactive_run(
                        [sys.executable, "-I", "-S", "-B", "-c", child],
                        responder, 3,
                    )
                except BaseException as error:
                    caught = error
        finally:
            # Real functions and only this method's actual owned PID, after
            # every product patch exits. This cleanup is not SUT success.
            pid = state["pid"]
            if type(pid) is int and pid > 0 and not state["sut_reaped"]:
                try:
                    result = real_waitpid(pid, os.WNOHANG)
                    state["fixture_waits"].append((os.WNOHANG, result))
                    if result[0] == pid:
                        state["fixture_reaped"] = True
                    elif result[0] == 0:
                        real_kill(pid, signal.SIGKILL)
                        state["fixture_killed"] = True
                        result = real_waitpid(pid, 0)
                        state["fixture_waits"].append((0, result))
                        state["fixture_reaped"] = result[0] == pid
                except OSError as error:
                    state["fixture_errors"].append(("OWN_CHILD_DRAIN", error.errno))
            master = state["master"]
            if type(master) is int and master >= 0 and state["close_calls"] == 0:
                try:
                    real_close(master)
                    state["fixture_closed"] = True
                except OSError as error:
                    state["fixture_errors"].append(("OWN_MASTER_DRAIN", error.errno))

        if (state["forks"] != 1 or not state["ready"] or not state["closed"]
                or state["adapter_errors"] or state["fixture_errors"]):
            raise RuntimeError("FIXTURE_HOLD: real signal-denial fixture incomplete")
        self.assertIs(original, caught)
        self.assertIsNone(returned)
        self.assertEqual(("PUBLIC original signal-denial primary",), original.args)
        self.assertEqual("PUBLIC original signal-denial primary", str(original))
        self.assertIsNone(original.__cause__)
        self.assertIs(True, getattr(original, "cleanup_uncertain", None))
        self.assertEqual(1, state["close_calls"])
        self.assertEqual(
            [("killpg", state["pid"], signal.SIGKILL),
             ("kill", state["pid"], signal.SIGKILL)],
            state["signals"],
        )
        self.assertFalse(state["blocking_attempt"])
        self.assertEqual([(os.WNOHANG, (0, 0))], state["sut_waits"])
        self.assertFalse(state["sut_reaped"])
        self.assertTrue(state["fixture_killed"])
        self.assertTrue(state["fixture_reaped"])
        self.assertEqual(
            [os.WNOHANG, 0], [options for options, _result in state["fixture_waits"]])


if __name__ == "__main__":
    unittest.main()
