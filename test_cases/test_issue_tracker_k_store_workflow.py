"""Two-real-module C-25 local workflow; no relay or online publication."""

from dataclasses import replace
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from monitor.issue_tracker_cycle_source import CycleEvidence
from monitor.issue_tracker_k_chain import assess_k_window
from monitor.issue_tracker_k_store import (
    apply_local_k_change, initialize_local_k_store, read_local_k_store,
)


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
            processes = []
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


if __name__ == "__main__":
    unittest.main()
