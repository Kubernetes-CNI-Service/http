"""C-5 real manifest freezer to C-6 local INTENT/RECEIPT, never online."""

from pathlib import Path
from contextlib import contextmanager
import os
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from monitor.issue_tracker_manifest import freeze_qualified_manifest
from monitor.issue_tracker_local_commit import (
    begin_generation, commit, create_local_commit_store, inspect_local_generation,
    record_intent, writer_owner,
)
from test_cases.test_issue_tracker_manifest import METADATA, QUALIFIED


@contextmanager
def _owned_fixture_children():
    processes = []
    failed = True
    try:
        yield processes
        failed = False
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
        for process in processes:
            _, stderr = process.communicate(timeout=5)
            if failed:
                print("owned local fixture child exit=" + str(process.returncode)
                      + " stderr=" + stderr.decode("utf-8", "replace"),
                      file=sys.stderr, flush=True)


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
            attempted = project / "attempted"
            first_code = """
import sys, time
print('phase=python-start', file=sys.stderr, flush=True)
from pathlib import Path
from monitor.issue_tracker_local_commit import writer_owner
print('phase=local-imported', file=sys.stderr, flush=True)
project, publication, ready, hold = map(Path, sys.argv[1:5])
with writer_owner(project, publication):
    ready.write_text('held')
    print('phase=local-owner-held', file=sys.stderr, flush=True)
    while not hold.exists():
        time.sleep(.01)
"""
            second_code = """
from pathlib import Path
import sys
from monitor.issue_tracker_local_commit import writer_owner
project, publication, acquired, attempted = map(Path, sys.argv[1:5])
attempted.write_text('attempting')
with writer_owner(project, publication):
    acquired.write_text('held')
"""
            env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
            repo = str(Path(__file__).parents[1])
            with _owned_fixture_children() as processes:
                first = subprocess.Popen(
                    [sys.executable, "-B", "-c", first_code, str(project), str(publish),
                     str(ready), str(hold)], cwd=repo, env=env,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                processes.append(first)
                deadline = time.monotonic() + 5
                while not ready.exists():
                    if time.monotonic() > deadline:
                        self.fail("first process did not acquire local writer lock")
                    time.sleep(.01)
                second = subprocess.Popen(
                    [sys.executable, "-B", "-c", second_code, str(project), str(publish),
                     str(acquired), str(attempted)], cwd=repo, env=env,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                processes.append(second)
                second_deadline = time.monotonic() + 5
                while not attempted.exists():
                    if time.monotonic() > second_deadline:
                        self.fail("second process did not attempt local writer lock")
                    time.sleep(.01)
                time.sleep(.15)
                self.assertFalse(acquired.exists(), "second process entered while first owns lock")
                hold.write_text("release")
                _, first_error = first.communicate(timeout=8)
                _, second_error = second.communicate(timeout=8)
                self.assertEqual((0, 0), (first.returncode, second.returncode),
                                 (first_error, second_error))
                self.assertTrue(acquired.exists())


class LocalCommitFixtureLifecycleTests(unittest.TestCase):
    """Fault oracles preserve the original lock and exclusion assertions."""

    def _exercise(self, fault):
        real_popen = subprocess.Popen
        owned = []

        def spawn(argv, **kwargs):
            command = list(argv)
            if owned and fault in ("second_spawn", "delayed_spawn"):
                ready = Path(owned[0].args[6])
                deadline = time.monotonic() + 5
                while not ready.exists():
                    self.assertIsNone(owned[0].poll())
                    if time.monotonic() > deadline:
                        self.fail("controlled fault did not reach first ready phase")
                    time.sleep(.005)
                if fault == "second_spawn":
                    raise OSError("controlled second spawn fault")
                time.sleep(6)
            if fault == "ready_timeout":
                command[3] = "import threading\nthreading.Event().wait()\n"
            process = real_popen(command, **kwargs)
            owned.append(process)
            return process

        try:
            with mock.patch("subprocess.Popen", side_effect=spawn):
                case = LocalCommitWorkflowTests().test_two_processes_serialize_on_one_local_writer_lock
                if fault == "second_spawn":
                    with self.assertRaisesRegex(OSError, "controlled second spawn fault"):
                        case()
                elif fault == "ready_timeout":
                    with self.assertRaisesRegex(AssertionError, "first process did not acquire local writer lock"):
                        case()
                else:
                    case()
            self.assertTrue(owned)
            self.assertTrue(all(process.poll() is not None for process in owned),
                            "workflow left its own fixture children running")
        finally:
            for process in owned:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)

    def test_second_spawn_failure_reaps_first_child(self):
        self._exercise("second_spawn")

    def test_readiness_timeout_reaps_child(self):
        self._exercise("ready_timeout")

    def test_parent_release_survives_delayed_sibling_spawn(self):
        self._exercise("delayed_spawn")

    def test_exclusion_is_checked_after_second_child_attempts_lock(self):
        real_popen = subprocess.Popen
        real_write = Path.write_text
        owned = []

        def spawn(argv, **kwargs):
            command = list(argv)
            if owned:
                command[3] = "import time; time.sleep(.25)\n" + command[3]
            process = real_popen(command, **kwargs)
            owned.append(process)
            return process

        def write(path, data, *args, **kwargs):
            if path.name == "hold" and data == "release":
                self.assertTrue((path.parent / "attempted").is_file(),
                                "parent released before sibling attempted the lock")
            return real_write(path, data, *args, **kwargs)

        try:
            with mock.patch("subprocess.Popen", side_effect=spawn), \
                 mock.patch.object(Path, "write_text", write):
                LocalCommitWorkflowTests().test_two_processes_serialize_on_one_local_writer_lock()
            self.assertTrue(all(process.poll() is not None for process in owned))
        finally:
            for process in owned:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
