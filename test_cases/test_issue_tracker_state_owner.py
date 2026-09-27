"""REQ7 S0: one local writer authority for settings and generations.

Only private scratch projects are used. These tests do not grant online
eligibility or send to any Issue Tracker service.
"""

import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from monitor.issue_tracker_state_owner import (
    TrackerStateHold, current_k, initialize_tracker_state, set_k, tracker_writer,
)
from monitor.issue_tracker_local_commit import (
    LocalCommitHold, begin_generation, commit, record_intent,
)


T0 = "2026-09-25T00:00:00Z"
T1 = "2026-09-25T00:01:00Z"
MANIFEST = b'{"operations":[],"schema_version":1}\n'
PREPARED = b"scratch-workbook-projection\n"


class TrackerStateOwnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tracker-shared-owner-")
        self.addCleanup(self.temp.cleanup)
        base = Path(os.path.realpath(self.temp.name))
        self.project = base / "project"
        self.project.mkdir(mode=0o755)
        self.project.chmod(0o755)
        self.publication = self.project / "99-output-monitor"
        self.publication.mkdir(mode=0o755)
        self.publication.chmod(0o755)
        self.root = self.project / ".tracker"

    def initialize(self):
        return initialize_tracker_state(
            self.project, self.publication, initialized_at=T0,
            acquisition_id="acquisition-0",
        )

    def test_actual_style_paths_share_one_private_root_lock_and_k_zero(self):
        state = self.initialize()
        self.assertEqual((0, 3), (state.revision, state.k))
        self.assertEqual(0, self.root.stat().st_mode & 0o077)
        self.assertEqual(0, (self.root / "LOCK").stat().st_mode & 0o077)
        self.assertEqual({"LOCK", "INITIALIZED", "settings", "generations", "quarantine"},
                         {child.name for child in self.root.iterdir()})
        self.assertEqual(["LOCK"], [child.name for child in self.root.iterdir()
                                    if child.name == "LOCK"])
        with tracker_writer(self.project, self.publication) as token:
            self.assertEqual((0, 3), (current_k(token).revision, current_k(token).k))
            generation = begin_generation(token, MANIFEST)
            record_intent(token, generation, PREPARED)
            receipt = commit(token, generation)
            self.assertEqual(generation.generation_id, receipt.generation_id)
            changed = set_k(token, new_k=5, actor="operator:fixture",
                            recorded_at=T1, request_id="request-1",
                            expected_revision=0)
            self.assertEqual((1, 5), (changed.revision, changed.k))
            self.assertEqual((1, 5), (current_k(token).revision, current_k(token).k))
        with self.assertRaises(TrackerStateHold):
            current_k(token)

    def test_require_current_k_reuses_exact_active_writer_and_rejects_drift(self):
        from monitor.issue_tracker_state_owner import require_current_k

        self.initialize()
        with tracker_writer(self.project, self.publication) as token:
            original = current_k(token)
            require_current_k(token, self.project, self.publication, original)
            with self.assertRaises(TrackerStateHold):
                require_current_k(object(), self.project, self.publication, original)
            with self.assertRaises(TrackerStateHold):
                require_current_k(token, self.project.parent, self.publication, original)
            changed = set_k(token, new_k=5, actor="operator:fixture",
                            recorded_at=T1, request_id="current-k-drift",
                            expected_revision=0)
            self.assertNotEqual(original, changed)
            with self.assertRaises(TrackerStateHold):
                require_current_k(token, self.project, self.publication, original)
            require_current_k(token, self.project, self.publication, current_k(token))

    def test_interrupted_bootstrap_is_not_reinterpreted_as_first_use(self):
        with mock.patch("monitor.issue_tracker_state_owner.initialize_local_k_store",
                        side_effect=OSError("injected crash after root creation")):
            with self.assertRaises(TrackerStateHold):
                self.initialize()
        self.assertTrue(self.root.is_dir())
        self.assertFalse((self.root / "INITIALIZED").exists())
        with self.assertRaises(TrackerStateHold):
            self.initialize()
        with self.assertRaises(TrackerStateHold):
            with tracker_writer(self.project, self.publication):
                self.fail("unfinished tracker state was admitted")
        self.assertFalse((self.root / "settings").exists())

    def test_ancestor_alias_and_rebound_lock_never_authorize_settings_or_commit(self):
        self.initialize()
        alias = self.project.parent / "alias"
        alias.symlink_to(self.project, target_is_directory=True)
        with self.assertRaises(TrackerStateHold):
            with tracker_writer(alias, alias / "99-output-monitor"):
                self.fail("symlink alias acquired state authority")
        with tracker_writer(self.project, self.publication) as token:
            (self.root / "LOCK").unlink()
            (self.root / "LOCK").write_bytes(b"")
            with self.assertRaises(TrackerStateHold):
                current_k(token)
            with self.assertRaises(LocalCommitHold):
                begin_generation(token, MANIFEST)

    def test_rebound_root_or_publication_path_cannot_use_pinned_old_descriptors(self):
        self.initialize()
        with tracker_writer(self.project, self.publication) as token:
            self.root.rename(self.project / ".tracker-detached")
            self.root.mkdir(mode=0o700)
            with self.assertRaises(TrackerStateHold):
                current_k(token)
            with self.assertRaises(LocalCommitHold):
                begin_generation(token, MANIFEST)
        # A second fresh fixture isolates the publication rebind case.
        with tempfile.TemporaryDirectory(prefix="tracker-output-rebind-") as directory:
            project = Path(os.path.realpath(directory)) / "project"
            project.mkdir(mode=0o755)
            project.chmod(0o755)
            publication = project / "99-output-monitor"
            publication.mkdir(mode=0o755)
            publication.chmod(0o755)
            initialize_tracker_state(project, publication, initialized_at=T0,
                                     acquisition_id="acquisition-0")
            with tracker_writer(project, publication) as token:
                publication.rename(project / "output-detached")
                publication.mkdir(mode=0o755)
                publication.chmod(0o755)
                with self.assertRaises(LocalCommitHold):
                    begin_generation(token, MANIFEST)

    def test_caller_body_exception_propagates_without_reclassification(self):
        self.initialize()
        sentinel = ValueError("caller-owned sentinel")
        token = None
        try:
            with tracker_writer(self.project, self.publication) as token:
                raise sentinel
        except ValueError as caught:
            self.assertIs(sentinel, caught)
        else:
            self.fail("caller exception was swallowed")
        with self.assertRaises(TrackerStateHold):
            current_k(token)


if __name__ == "__main__":
    unittest.main()
