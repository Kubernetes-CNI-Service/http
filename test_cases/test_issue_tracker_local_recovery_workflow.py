"""Real state-owner/C-6 child-crash to new-process recovery workflow."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from monitor.issue_tracker_state_owner import initialize_tracker_state
from monitor.issue_tracker_local_recovery import inspect_recovered_generations
from test_cases.test_issue_tracker_local_recovery import cold_inspect, disk_snapshot


class LocalRecoveryWorkflowTests(unittest.TestCase):
    def test_killed_writer_leaves_only_unresolved_intent_for_new_process(self):
        with tempfile.TemporaryDirectory(prefix="tracker-recovery-workflow-") as tmp:
            project = Path(tmp).resolve(strict=True) / "project"
            project.mkdir(mode=0o755)
            publication = project / "99-output-monitor"
            publication.mkdir(mode=0o755)
            initialize_tracker_state(
                project, publication,
                initialized_at="2026-09-25T00:00:00Z",
                acquisition_id="recovery-workflow-first-use",
            )
            script = """
import os
import sys
from monitor.issue_tracker_local_commit import begin_generation, record_intent
from monitor.issue_tracker_state_owner import tracker_writer
with tracker_writer(sys.argv[1], sys.argv[2]) as token:
    generation = begin_generation(token, b'{"schema_version":1}\\n')
    record_intent(token, generation, b'cold child prepared bytes\\n')
    os._exit(23)
"""
            killed = subprocess.run(
                [sys.executable, "-B", "-c", script, str(project), str(publication)],
                cwd=Path(__file__).resolve().parents[1],
                text=True, capture_output=True, timeout=15,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            )
            self.assertEqual(23, killed.returncode, killed.stderr)
            self.assertEqual("", killed.stdout)
            generation_dirs = list((project / ".tracker" / "generations").iterdir())
            self.assertEqual(1, len(generation_dirs))
            self.assertTrue((generation_dirs[0] / "INTENT").is_file())
            self.assertFalse((generation_dirs[0] / "RECEIPT").exists())
            before = disk_snapshot(project)
            recovered = cold_inspect(project, publication)
            self.assertEqual(0, recovered.returncode, recovered.stderr)
            self.assertEqual([{
                "generation_id": generation_dirs[0].name,
                "sequence": 1,
                "manifest_id": hashlib.sha256(b'{"schema_version":1}\n').hexdigest(),
                "status": "UNRESOLVED",
                "prepared_observation": "PREPARED-PRESENT",
            }], json.loads(recovered.stdout))
            self.assertEqual(before, disk_snapshot(project))
            self.assertFalse((generation_dirs[0] / "RECEIPT").exists())


if __name__ == "__main__":
    unittest.main()
