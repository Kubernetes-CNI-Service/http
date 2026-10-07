"""Two-real-module C-25 local workflow; no relay or online publication."""

from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from monitor.issue_tracker_cycle_source import CycleEvidence
from monitor.issue_tracker_k_chain import assess_k_window
from monitor.issue_tracker_k_store import (
    apply_local_k_change, initialize_local_k_store, read_local_k_store,
)
from test_cases.subprocess_timeout_evidence import collect_process_state


def _collect_private_k_race(child, root, directory):
    """Keep original 5s/10s bounds; observe before reaping only owned children."""
    processes, drained = [], set()
    native_popen = subprocess.Popen
    failed = False
    def observe(process):
        try:
            return collect_process_state(process, native_popen)
        except Exception as error:
            # Diagnostics cannot replace the original readiness/10s failure.
            return {"capture_phase": "before_cleanup", "stage": "unknown",
                    "pid": process.pid, "error": str(error)[:256]}
    try:
        for index in range(2):
            token = Path(directory) / f"request-{index}"
            ready = Path(directory) / f"ready-{index}"
            processes.append(subprocess.Popen(
                [sys.executable, "-B", "-c", child, str(root), str(ready),
                 str(Path(directory) / "launch"), str(token)],
                cwd=str(Path(__file__).parents[1]), stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            ))
        deadline = time.monotonic() + 5
        while not all((Path(directory) / f"ready-{i}").exists() for i in range(2)):
            if time.monotonic() > deadline:
                evidence = []
                for index, process in enumerate(processes):
                    evidence.append({
                        "ready": (Path(directory) / f"ready-{index}").exists(),
                        "process": observe(process),
                    })
                raise AssertionError("independent process barrier did not become ready; "
                                     "precleanup evidence=" + json.dumps(evidence, sort_keys=True))
            time.sleep(.005)
        (Path(directory) / "launch").write_text("go")
        results = []
        for process in processes:
            try:
                _, stderr = process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                print("K_RACE_PRE_CLEANUP " + json.dumps(
                    observe(process), sort_keys=True), file=sys.stderr)
                raise
            drained.add(id(process))
            results.append((process.returncode, stderr))
        return results
    except BaseException:
        failed = True
        raise
    finally:
        cleanup_errors = []
        for process in processes:
            if id(process) in drained:
                continue
            try:
                if process.poll() is None:
                    process.kill()  # Exactly our Popen child, never another process/group.
                stdout, stderr = process.communicate(timeout=10)
                if failed:
                    # Reaped streams diagnose import/exit failures; they are
                    # never represented as a live pre-cleanup observation.
                    print("K_RACE_POST_CLEANUP " + json.dumps({
                        "capture_phase": "after_cleanup", "pid": process.pid,
                        "returncode": process.returncode,
                        "stdout": stdout[:4096].decode("utf-8", errors="replace"),
                        "stderr": stderr[:4096].decode("utf-8", errors="replace"),
                        "stdout_truncated": len(stdout) > 4096,
                        "stderr_truncated": len(stderr) > 4096,
                    }, sort_keys=True), file=sys.stderr)
            except (OSError, subprocess.SubprocessError) as error:
                cleanup_errors.append(type(error).__name__ + ": " + str(error))
        if cleanup_errors:
            if failed:
                print("K_RACE_CLEANUP_ERRORS " + json.dumps(cleanup_errors), file=sys.stderr)
            else:
                raise AssertionError("private K race cleanup failed: " + repr(cleanup_errors))


class IssueTrackerKStoreWorkflowTests(unittest.TestCase):
    def test_committed_k_changes_history_sufficiency_without_manufacturing_cycles(self):
        with tempfile.TemporaryDirectory(prefix="tracker-k-workflow-") as directory:
            root = Path(os.path.realpath(directory)) / ".tracker"
            initialize_local_k_store(root, initialized_at="2026-09-25T00:00:00Z",
                                     acquisition_id="acquisition-0")
            first = CycleEvidence(cycle_id="cycle-1", sequence=1,
                                  project_key="project-A", scope="prod",
                                  source_slots=("source-A",), qualifying=True,
                                  summary_sha256="1" * 64, completion_sha256="2" * 64)
            cycles = tuple(replace(first, cycle_id=f"cycle-{i}", sequence=i)
                           for i in range(1, 4))
            self.assertEqual("history_sufficient",
                             assess_k_window(cycles, read_local_k_store(root)).status)
            apply_local_k_change(root, new_k=4, actor="operator:fixture",
                                 recorded_at="2026-09-25T00:01:00Z",
                                 request_id="request-1", expected_revision=0)
            window = assess_k_window(cycles, read_local_k_store(root))
            self.assertEqual(("pending", "cold_start", 3, 4),
                             (window.status, window.reason, window.observed, window.required))

    def test_two_independent_processes_cannot_both_commit_expected_revision_zero(self):
        with tempfile.TemporaryDirectory(prefix="tracker-k-race-") as directory:
            root = Path(os.path.realpath(directory)) / ".tracker"
            initialize_local_k_store(root, initialized_at="2026-09-25T00:00:00Z",
                                     acquisition_id="acquisition-0")
            child = """
import pathlib, sys, time
from monitor.issue_tracker_k_chain import KChainHoldError
from monitor.issue_tracker_k_store import apply_local_k_change
root, ready, launch, token = map(pathlib.Path, sys.argv[1:5])
ready.write_text('ready')
deadline = time.monotonic() + 5
while not launch.exists():
    if time.monotonic() > deadline:
        sys.exit(12)
    time.sleep(.005)
try:
    apply_local_k_change(root, new_k=4, actor='operator:fixture',
                         recorded_at='2026-09-25T00:01:00Z', request_id=token.name,
                         expected_revision=0)
except KChainHoldError:
    sys.exit(7)
sys.exit(0)
"""
            results = _collect_private_k_race(child, root, directory)
            self.assertEqual([0, 7], sorted(code for code, _ in results), results)
            self.assertEqual(1, read_local_k_store(root).revision)
            self.assertEqual(["0.json", "1.json"], sorted(
                path.name for path in (root / "settings" / "events").iterdir()))

    def test_unready_race_keeps_original_failure_and_reaps_only_owned_children(self):
        from types import SimpleNamespace
        events = []
        children = []
        def owned(index):
            process = SimpleNamespace(pid=7301 + index, returncode=None)
            process.poll = lambda: process.returncode
            def kill():
                events.append(("kill", index))
                process.returncode = -9
            def communicate(*, timeout):
                self.assertEqual(10, timeout)
                events.append(("reap", index))
                return b"", b"independent child stderr"
            process.kill, process.communicate = kill, communicate
            children.append(process)
            return process
        def observe(process, native):
            self.assertIsNone(process.poll())
            events.append(("observe", process.pid - 7301))
            return {"capture_phase": "before_cleanup", "pid": process.pid,
                    "stage": "unknown", "returncode": None}
        with tempfile.TemporaryDirectory(prefix="tracker-k-unready-") as directory:
            root = Path(directory) / ".tracker"
            with mock.patch.object(subprocess, "Popen", side_effect=[owned(0), owned(1)]) as popen, \
                    mock.patch.object(time, "monotonic", side_effect=[0, 6]), \
                    mock.patch(__name__ + ".collect_process_state", side_effect=observe):
                with self.assertRaisesRegex(AssertionError,
                        "independent process barrier did not become ready; precleanup evidence=") as caught:
                    _collect_private_k_race("independent child", root, directory)
            self.assertEqual(2, popen.call_count)
            self.assertEqual([("observe", 0), ("observe", 1), ("kill", 0), ("reap", 0),
                              ("kill", 1), ("reap", 1)], events)
            self.assertIn('"stage": "unknown"', str(caught.exception))
            self.assertFalse((Path(directory) / "launch").exists())
            self.assertEqual([-9, -9], [child.returncode for child in children])

    def test_race_communicate_timeout_keeps_exception_when_observer_fails(self):
        from types import SimpleNamespace
        events = []
        timeout_error = subprocess.TimeoutExpired("private-k-child", 10)
        children = []
        def owned(index):
            process = SimpleNamespace(pid=7401 + index, returncode=None)
            process.poll = lambda: process.returncode
            def kill():
                events.append(("kill", index))
                process.returncode = -9
            def communicate(*, timeout):
                self.assertEqual(10, timeout)
                if process.returncode is None:
                    events.append(("timeout", index))
                    raise timeout_error
                events.append(("reap", index))
                return b"", b"private stderr"
            process.kill, process.communicate = kill, communicate
            children.append(process)
            return process
        def unavailable(process, native):
            self.assertIsNone(process.poll())
            events.append(("observe", process.pid - 7401))
            raise OSError("private diagnostic unavailable")
        with tempfile.TemporaryDirectory(prefix="tracker-k-communicate-") as directory:
            for index in range(2):
                (Path(directory) / f"ready-{index}").write_text("ready")
            with (mock.patch.object(subprocess, "Popen", side_effect=[owned(0), owned(1)]),
                  mock.patch(__name__ + ".collect_process_state", side_effect=unavailable),
                  mock.patch.object(sys, "stderr") as diagnostic):
                with self.assertRaises(subprocess.TimeoutExpired) as caught:
                    _collect_private_k_race("private child", Path(directory) / ".tracker", directory)
            self.assertIs(timeout_error, caught.exception)
            self.assertEqual([("timeout", 0), ("observe", 0), ("kill", 0), ("reap", 0),
                              ("kill", 1), ("reap", 1)], events)
            self.assertEqual([-9, -9], [process.returncode for process in children])
            self.assertIn("K_RACE_PRE_CLEANUP", "".join(
                call.args[0] for call in diagnostic.write.call_args_list))

    def test_unready_exited_child_keeps_bounded_post_cleanup_import_stderr(self):
        from types import SimpleNamespace
        exited = SimpleNamespace(pid=7501, returncode=13)
        exited.poll = lambda: 13
        exited.kill = mock.Mock(side_effect=AssertionError("already exited child"))
        exited.communicate = mock.Mock(return_value=(b"private stdout", b"import failed: " + b"X" * 5000))
        other = SimpleNamespace(pid=7502, returncode=12)
        other.poll = lambda: 12
        other.kill = mock.Mock(side_effect=AssertionError("already exited child"))
        other.communicate = mock.Mock(return_value=(b"", b"barrier not launched"))
        with tempfile.TemporaryDirectory(prefix="tracker-k-exited-") as directory:
            with (mock.patch.object(subprocess, "Popen", side_effect=[exited, other]),
                  mock.patch.object(time, "monotonic", side_effect=[0, 6]),
                  mock.patch(__name__ + ".collect_process_state", return_value={
                      "capture_phase": "before_cleanup", "stage": "unknown"}),
                  mock.patch.object(sys, "stderr") as diagnostic):
                with self.assertRaisesRegex(AssertionError,
                        "independent process barrier did not become ready; precleanup evidence="):
                    _collect_private_k_race("private child", Path(directory) / ".tracker", directory)
            output = "".join(call.args[0] for call in diagnostic.write.call_args_list)
            records = [json.loads(line.partition(" ")[2]) for line in output.splitlines()
                       if line.startswith("K_RACE_POST_CLEANUP ")]
            self.assertEqual(2, len(records))
            self.assertEqual([7501, 7502], [row["pid"] for row in records])
            self.assertEqual([13, 12], [row["returncode"] for row in records])
            self.assertTrue(all(row["capture_phase"] == "after_cleanup" for row in records))
            self.assertEqual("private stdout", records[0]["stdout"])
            self.assertEqual("import failed: " + "X" * (4096 - len("import failed: ")),
                             records[0]["stderr"])
            self.assertTrue(records[0]["stderr_truncated"])
            self.assertFalse(records[1]["stderr_truncated"])
            for process in (exited, other):
                process.communicate.assert_called_once_with(timeout=10)
                process.kill.assert_not_called()

if __name__ == "__main__":
    unittest.main()
