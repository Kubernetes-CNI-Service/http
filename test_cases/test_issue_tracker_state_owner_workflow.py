"""Two-real-module S0 workflow and cross-process LK-P exclusion."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from monitor.issue_tracker_state_owner import (
    current_k, initialize_tracker_state, set_k, tracker_writer,
)
from monitor.issue_tracker_k_store import read_local_k_store
from monitor.issue_tracker_local_commit import begin_generation, record_intent


class TrackerStateOwnerWorkflowTests(unittest.TestCase):
    def test_one_lock_serializes_k_change_and_generation_in_other_process(self):
        with tempfile.TemporaryDirectory(prefix="tracker-shared-race-") as directory:
            project = Path(os.path.realpath(directory)) / "project"
            project.mkdir(mode=0o755)
            project.chmod(0o755)
            publication = project / "99-output-monitor"
            publication.mkdir(mode=0o755)
            publication.chmod(0o755)
            root = project / ".tracker"
            initialize_tracker_state(
                project, publication, initialized_at="2026-09-25T00:00:00Z",
                acquisition_id="acquisition-0",
            )
            ready = project / "ready"
            release = project / "release"
            child = """
from pathlib import Path
import sys, time
from monitor.issue_tracker_state_owner import current_k, set_k, tracker_writer
from monitor.issue_tracker_local_commit import begin_generation, record_intent
project, publication, ready, release = map(Path, sys.argv[1:5])
with tracker_writer(project, publication) as token:
    assert (current_k(token).revision, current_k(token).k) == (0, 3)
    generation = begin_generation(token, b'{"operations":[],"schema_version":1}\\n')
    record_intent(token, generation, b'child-prepared\\n')
    ready.write_text('held')
    until = time.monotonic() + 5
    while not release.exists():
        if time.monotonic() > until:
            sys.exit(12)
        time.sleep(.01)
    set_k(token, new_k=4, actor='operator:fixture',
          recorded_at='2026-09-25T00:01:00Z', request_id='request-1',
          expected_revision=0)
"""
            process = subprocess.Popen(
                [sys.executable, "-B", "-c", child, str(project), str(publication),
                 str(ready), str(release)], cwd=str(Path(__file__).parents[1]),
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            observer = None
            try:
                deadline = time.monotonic() + 5
                while not ready.exists():
                    if process.poll() is not None or time.monotonic() > deadline:
                        self.fail("child could not acquire shared owner")
                    time.sleep(.01)
                # No second K-store lock owner or C6 lock owner may slip in.
                observer = subprocess.Popen(
                    [sys.executable, "-B", "-c",
                     "import sys; from monitor.issue_tracker_k_store import read_local_k_store; "
                     "read_local_k_store(sys.argv[1])", str(root)],
                    cwd=str(Path(__file__).parents[1]),
                    env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                time.sleep(.15)
                self.assertIsNone(observer.poll(), "K reader escaped the shared owner lock")
                release.write_text("release")
                _, first_err = process.communicate(timeout=8)
                _, second_err = observer.communicate(timeout=8)
                self.assertEqual((0, 0), (process.returncode, observer.returncode),
                                 (first_err, second_err))
                self.assertEqual((1, 4), (read_local_k_store(root).revision,
                                          read_local_k_store(root).k))
                self.assertEqual(1, len(list((root / "generations").iterdir())))
            finally:
                if observer is not None and observer.poll() is None:
                    observer.kill()
                    observer.communicate(timeout=5)
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
