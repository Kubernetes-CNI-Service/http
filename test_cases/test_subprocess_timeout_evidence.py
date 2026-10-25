"""Observe a private child before run() kills it, without changing its failure."""

import os
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases import subprocess_timeout_evidence as EVIDENCE


class SubprocessTimeoutEvidenceTests(unittest.TestCase):
    def test_real_timeout_observer_runs_before_original_child_is_killed(self):
        native = subprocess.Popen
        observed = []

        def collect(child, original_popen):
            self.assertIs(native, original_popen)
            observed.append((child.pid, child.poll()))
            return {"capture_phase": "before_cleanup", "pid": child.pid,
                    "returncode": child.poll(), "stage": "unknown"}

        argv = [sys.executable, "-B", "-c", "import time; time.sleep(30)"]
        with EVIDENCE.capture_timeout_before_cleanup(collector=collect):
            with self.assertRaises(subprocess.TimeoutExpired) as caught:
                subprocess.run(argv, capture_output=True, timeout=0.1, check=True)
        self.assertEqual(1, len(observed), "the original live timeout site was never observed")
        pid, state = observed[0]
        self.assertIsNone(state, "run() killed/reaped the child before observation")
        error = caught.exception
        self.assertEqual(argv, error.cmd)
        self.assertEqual(0.1, error.timeout)
        self.assertEqual({"capture_phase": "before_cleanup", "pid": pid,
                          "returncode": None, "stage": "unknown"}, error.prekill_process_evidence)
        self.assertIs(native, subprocess.Popen, "diagnostic context leaked global Popen mutation")

    def test_diagnostic_error_does_not_replace_original_timeout_or_disable_cleanup(self):
        seen = []

        def fail(child, native):
            seen.append(child)
            raise OSError("independent private observer failure")

        argv = [sys.executable, "-B", "-c", "import time; time.sleep(30)"]
        with EVIDENCE.capture_timeout_before_cleanup(collector=fail):
            with self.assertRaises(subprocess.TimeoutExpired) as caught:
                subprocess.run(argv, capture_output=True, timeout=0.1)
        self.assertEqual(1, len(seen))
        self.assertIsNotNone(seen[0].poll(), "standard run() child cleanup did not finish")
        self.assertEqual(0.1, caught.exception.timeout)
        self.assertEqual(argv, caught.exception.cmd)
        self.assertEqual("unknown", caught.exception.prekill_process_evidence["stage"])
        self.assertIn("observer failure", caught.exception.prekill_process_evidence["error"])

    def test_success_does_not_collect_or_change_subprocess_contract(self):
        collect = mock.Mock(side_effect=AssertionError("success must not trigger diagnostics"))
        native = subprocess.Popen
        with EVIDENCE.capture_timeout_before_cleanup(collector=collect):
            result = subprocess.run([sys.executable, "-B", "-c", "print('private-success')"],
                                    capture_output=True, text=True, check=True, timeout=10)
        self.assertEqual("private-success\n", result.stdout)
        self.assertEqual("", result.stderr)
        self.assertEqual(0, result.returncode)
        collect.assert_not_called()
        self.assertIs(native, subprocess.Popen)

    def test_real_default_observer_retains_root_state_but_does_not_infer_stage(self):
        with EVIDENCE.capture_timeout_before_cleanup():
            with self.assertRaises(subprocess.TimeoutExpired) as caught:
                subprocess.run([sys.executable, "-B", "-c", "import time; time.sleep(30)"],
                               capture_output=True, timeout=0.1)
        evidence = getattr(caught.exception, "prekill_process_evidence", None)
        self.assertIsInstance(evidence, dict)
        self.assertEqual("before_cleanup", evidence["capture_phase"])
        self.assertEqual("unknown", evidence["stage"])
        self.assertIsNone(evidence["returncode"])
        self.assertGreater(evidence["pid"], 0)
        self.assertTrue(evidence["root"]["state"])
        self.assertEqual(os.getpid(), evidence["root"]["ppid"])
        self.assertNotIn("argv", evidence["root"], "diagnostics must not capture command secrets")

    def test_exited_root_does_not_query_recycled_pid_or_claim_pipe_owner(self):
        native = mock.Mock(side_effect=AssertionError("an exited PID is not an authority"))
        child = SimpleNamespace(pid=7301, poll=lambda: 0)
        evidence = EVIDENCE.collect_process_state(child, native)
        self.assertEqual(0, evidence["returncode"])
        self.assertIsNone(evidence["root"])
        self.assertEqual([], evidence["descendants"])
        self.assertEqual("unknown", evidence["descendant_state"])
        native.assert_not_called()

    def test_exited_private_child_with_descendant_pipe_is_not_reported_as_running_root(self):
        read_fd, write_fd = os.pipe()
        source = ("import subprocess,sys; "
                  f"subprocess.Popen([sys.executable,'-B','-c','import os; os.read({read_fd},1)'],"
                  f"pass_fds=({read_fd},))")
        try:
            with EVIDENCE.capture_timeout_before_cleanup():
                with subprocess.Popen([sys.executable, "-B", "-c", source],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      pass_fds=(read_fd,)) as child:
                    try:
                        self.assertEqual(0, child.wait(timeout=5))
                        with self.assertRaises(subprocess.TimeoutExpired) as caught:
                            child.communicate(timeout=0.01)
                        evidence = caught.exception.prekill_process_evidence
                        self.assertEqual(0, evidence["returncode"])
                        self.assertIsNone(evidence["root"])
                        self.assertEqual("unknown", evidence["descendant_state"])
                        self.assertEqual("unknown", evidence["stage"])
                    finally:
                        os.write(write_fd, b"x")  # A handshake, not a sleep-dependent descendant lifetime.
                        child.communicate(timeout=5)  # Private descendant exits itself; no signal or leak.
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_scoped_observer_does_not_capture_unrelated_child(self):
        collect = mock.Mock(side_effect=AssertionError("unrelated child must not be observed"))
        with EVIDENCE.capture_timeout_before_cleanup(expected_command=["bash", "private-fixture"],
                                                     collector=collect):
            with self.assertRaises(subprocess.TimeoutExpired) as caught:
                subprocess.run([sys.executable, "-B", "-c", "import time; time.sleep(30)"],
                               capture_output=True, timeout=0.1)
        self.assertFalse(hasattr(caught.exception, "prekill_process_evidence"))
        collect.assert_not_called()

    def test_descendant_enumeration_is_bounded_and_only_records_matching_ancestry(self):
        commands = []

        def native(argv, **kwargs):
            commands.append(argv)
            pid = int(argv[2])
            if argv[0] == "/bin/ps":
                parent = os.getpid() if pid == 7301 else 7301
                payload = f"{pid} {parent} S private-process\n".encode()
            else:
                self.assertEqual(["/usr/bin/pgrep", "-P", "7301"], argv)
                payload = b"".join(f"{number}\n".encode() for number in range(7302, 7322))
            return SimpleNamespace(returncode=0, communicate=lambda timeout: (payload, b""))

        evidence = EVIDENCE.collect_process_state(SimpleNamespace(pid=7301, poll=lambda: None), native)
        self.assertEqual(15, len(evidence["descendants"]))
        self.assertEqual(list(range(7302, 7317)), [node["pid"] for node in evidence["descendants"]])
        self.assertEqual("partial", evidence["descendant_state"])
        self.assertIn("private descendant count bound reached", evidence["errors"])
        self.assertTrue(all(node["ppid"] == 7301 for node in evidence["descendants"]))
        self.assertEqual(17, len(commands))

    def test_observation_budget_exhaustion_stays_unknown_without_probing(self):
        native = mock.Mock(side_effect=AssertionError("budget exhausted"))
        with mock.patch.object(EVIDENCE.time, "monotonic", side_effect=[0, 1]):
            evidence = EVIDENCE.collect_process_state(SimpleNamespace(pid=7301, poll=lambda: None), native)
        self.assertIsNone(evidence["root"])
        self.assertEqual("unknown", evidence["descendant_state"])
        self.assertTrue(any("budget exhausted" in error for error in evidence["errors"]))
        native.assert_not_called()
