"""C-5 real manifest freezer to C-6 local INTENT/RECEIPT, never online."""

from pathlib import Path
import os
import subprocess
import sys
import tempfile
import time
import unittest

from monitor.issue_tracker_manifest import freeze_qualified_manifest
from monitor.issue_tracker_local_commit import (
    begin_generation, commit, create_local_commit_store, inspect_local_generation,
    record_intent, writer_owner,
)
from test_cases.test_issue_tracker_manifest import METADATA, QUALIFIED


class LocalCommitWorkflowTests(unittest.TestCase):
    def test_frozen_qualified_manifest_survives_local_commit_but_is_not_remote_proof(self):
        body, identity = freeze_qualified_manifest(
            QUALIFIED, metadata=METADATA, expected_template_sha256="b" * 64)
        with tempfile.TemporaryDirectory(prefix="tracker-local-workflow-") as directory:
            project = Path(directory).resolve(strict=True)
            publish = project / "publication"
            publish.mkdir(mode=0o700)
            create_local_commit_store(project, publish)
            with writer_owner(project, publish) as token:
                generation = begin_generation(token, body)
                record_intent(token, generation, b"workbook-projection-fixture\n")
                receipt = commit(token, generation)
            self.assertEqual(identity, receipt.manifest_id)
            self.assertEqual("RECEIPT-PRESENT-NOT-ELIGIBILITY",
                             inspect_local_generation(project, publish, generation).status)

    def test_two_processes_serialize_on_one_local_writer_lock(self):
        with tempfile.TemporaryDirectory(prefix="tracker-local-race-") as directory:
            project = Path(directory).resolve(strict=True)
            publish = project / "publication"
            publish.mkdir(mode=0o700)
            create_local_commit_store(project, publish)
            hold = project / "hold"
            ready = project / "ready"
            acquired = project / "acquired"
            first_code = """
from pathlib import Path
import sys, time
from monitor.issue_tracker_local_commit import writer_owner
project, publication, ready, hold = map(Path, sys.argv[1:5])
with writer_owner(project, publication):
    ready.write_text('held')
    limit = time.monotonic() + 5
    while not hold.exists():
        if time.monotonic() > limit:
            sys.exit(12)
        time.sleep(.01)
"""
            second_code = """
from pathlib import Path
import sys
from monitor.issue_tracker_local_commit import writer_owner
project, publication, acquired = map(Path, sys.argv[1:4])
with writer_owner(project, publication):
    acquired.write_text('held')
"""
            env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
            repo = str(Path(__file__).parents[1])
            first = subprocess.Popen(
                [sys.executable, "-B", "-c", first_code, str(project), str(publish),
                 str(ready), str(hold)], cwd=repo, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            deadline = time.monotonic() + 5
            while not ready.exists():
                if time.monotonic() > deadline:
                    self.fail("first process did not acquire local writer lock")
                time.sleep(.01)
            second = subprocess.Popen(
                [sys.executable, "-B", "-c", second_code, str(project), str(publish),
                 str(acquired)], cwd=repo, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(.15)
            self.assertFalse(acquired.exists(), "second process entered while first owns lock")
            hold.write_text("release")
            _, first_error = first.communicate(timeout=8)
            _, second_error = second.communicate(timeout=8)
            self.assertEqual((0, 0), (first.returncode, second.returncode),
                             (first_error, second_error))
            self.assertTrue(acquired.exists())


if __name__ == "__main__":
    unittest.main()
