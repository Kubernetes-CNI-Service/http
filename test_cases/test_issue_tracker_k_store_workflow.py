"""Two-real-module C-25 local workflow; no relay or online publication."""

from dataclasses import replace
from contextlib import contextmanager
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


@contextmanager
def _owned_fixture_children():
    processes = []
    failed = True
    try:
        yield processes
        failed = False
    finally:
        # Stop only handles created by this fixture, before removing its paths.
        for process in processes:
            if process.poll() is None:
                process.kill()
        for process in processes:
            _, stderr = process.communicate(timeout=5)
            if failed:
                print("owned K fixture child exit=" + str(process.returncode)
                      + " stderr=" + stderr.decode("utf-8", "replace"),
                      file=sys.stderr, flush=True)


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
            launch = Path(directory) / "launch"
            child = """
import sys, time
print('phase=python-start', file=sys.stderr, flush=True)
import pathlib
from monitor.issue_tracker_k_chain import KChainHoldError
from monitor.issue_tracker_k_store import apply_local_k_change
print('phase=k-imported', file=sys.stderr, flush=True)
root, ready, launch, token = map(pathlib.Path, sys.argv[1:5])
ready.write_text('ready')
print('phase=k-ready', file=sys.stderr, flush=True)
while not launch.exists():
    time.sleep(.005)
try:
    apply_local_k_change(root, new_k=4, actor='operator:fixture',
                         recorded_at='2026-09-25T00:01:00Z', request_id=token.name,
                         expected_revision=0)
except KChainHoldError:
    sys.exit(7)
sys.exit(0)
"""
            with _owned_fixture_children() as processes:
                for index in range(2):
                    token = Path(directory) / f"request-{index}"
                    ready = Path(directory) / f"ready-{index}"
                    processes.append(subprocess.Popen(
                        [sys.executable, "-B", "-c", child, str(root), str(ready),
                         str(launch), str(token)],
                        cwd=str(Path(__file__).parents[1]), stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                    ))
                deadline = time.monotonic() + 5
                while not all((Path(directory) / f"ready-{i}").exists() for i in range(2)):
                    if time.monotonic() > deadline:
                        self.fail("independent process barrier did not become ready")
                    time.sleep(.005)
                launch.write_text("go")
                results = []
                for process in processes:
                    _, stderr = process.communicate(timeout=10)
                    results.append((process.returncode, stderr))
                self.assertEqual([0, 7], sorted(code for code, _ in results), results)
                self.assertEqual(1, read_local_k_store(root).revision)
                self.assertEqual(["0.json", "1.json"], sorted(
                    path.name for path in (root / "settings" / "events").iterdir()))


class KStoreFixtureLifecycleTests(unittest.TestCase):
    """Independent fault oracles for the real two-process workflow fixture."""

    def _exercise(self, fault):
        real_popen = subprocess.Popen
        owned = []

        def spawn(argv, **kwargs):
            command = list(argv)
            if owned and fault in ("second_spawn", "delayed_spawn"):
                ready = Path(owned[0].args[5])
                deadline = time.monotonic() + 5
                while not ready.exists():
                    self.assertIsNone(owned[0].poll())
                    if time.monotonic() > deadline:
                        self.fail("controlled fault did not reach first ready phase")
                    time.sleep(.005)
                if fault == "second_spawn":
                    raise OSError("controlled second spawn fault")
                # Ready does not authorize self-release before the parent.
                time.sleep(6)
            if fault == "ready_timeout":
                command[3] = "import threading\nthreading.Event().wait()\n"
            process = real_popen(command, **kwargs)
            owned.append(process)
            return process

        try:
            with mock.patch("subprocess.Popen", side_effect=spawn):
                case = IssueTrackerKStoreWorkflowTests().test_two_independent_processes_cannot_both_commit_expected_revision_zero
                if fault == "second_spawn":
                    with self.assertRaisesRegex(OSError, "controlled second spawn fault"):
                        case()
                elif fault == "ready_timeout":
                    with self.assertRaisesRegex(AssertionError, "independent process barrier did not become ready"):
                        case()
                else:
                    case()
            self.assertTrue(owned)
            self.assertTrue(all(process.poll() is not None for process in owned),
                            "workflow left its own fixture children running")
        finally:
            # RED tests must not themselves leak the old fixture's children.
            for process in owned:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)

    def test_second_spawn_failure_reaps_first_child(self):
        self._exercise("second_spawn")

    def test_readiness_timeout_reaps_children(self):
        self._exercise("ready_timeout")

    def test_parent_release_survives_delayed_sibling_spawn(self):
        self._exercise("delayed_spawn")


if __name__ == "__main__":
    unittest.main()
