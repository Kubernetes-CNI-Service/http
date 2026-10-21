"""Independent owner cleanup contract SOURCE, NOT RUN; no online authority."""
import errno
import unittest

from test_cases import owner_ni_cleanup_fixture as f


class OwnerNICleanupTests(unittest.TestCase):
    def test_actual_sheet_owner_preserves_body_ni_and_closes_all_originals_once(self):
        f.run_owned(self, '_exercise_actual_sheet_owner_body_ni_close_eio')

    def test_tracker_writer_real_local_owner_preserves_ni_and_finishes_known_cleanup(self):
        f.run_owned(self, '_exercise_tracker_writer_local_owner_body_ni_close_eio')

    def _assert_settled(self, outcome, count):
        self.assertTrue(outcome['ready'], 'REAL_OWNER_BODY_NOT_REACHED')
        self.assertTrue(outcome['token_revoked'])
        self.assertIsInstance(outcome['revoked_error'], outcome['hold'])
        self.assertEqual(count, outcome['snapshot']['slots'])
        self.assertEqual(count, outcome['snapshot']['calls'])
        self.assertEqual([True] * count, outcome['snapshot']['revoked'])
        self.assertEqual([errno.EBADF] * count, outcome['snapshot']['closed_errno'])
        self.assertEqual([], outcome['snapshot']['remaining'])

    def _exercise_actual_sheet_owner_body_ni_close_eio(self):
        root = f.new_root()
        healthy = f.sheet_case(root / 'healthy')
        f.diagnostic('sheet-health', healthy)
        self.assertIsNone(healthy['error'])
        self._assert_settled(healthy, 6)
        self.assertEqual(0, healthy['snapshot']['faults'])
        outcome = f.sheet_case(root / 'fault', fault=True)
        f.diagnostic('sheet-body-ni-close-eio', outcome)
        # All assertions occur after genuine owner + IO façade + finalizers.
        self.assertIs(outcome['ni'], outcome['error'], 'BODY_NI_WAS_REPLACED')
        self.assertIs(outcome['cause'], outcome['error'].__cause__)
        self._assert_settled(outcome, 6)
        self.assertEqual(1, outcome['snapshot']['faults'])

    def _exercise_tracker_writer_local_owner_body_ni_close_eio(self):
        from monitor import issue_tracker_state_owner as state
        root = f.new_root()
        project = root / 'project'
        project.mkdir(mode=0o755)
        project.chmod(0o755)
        publication = project / '99-output-monitor'
        publication.mkdir(mode=0o755)
        publication.chmod(0o755)
        state.initialize_tracker_state(project, publication,
            initialized_at='2026-09-25T00:00:00Z', acquisition_id='acquisition-0')
        healthy = f.tracker_case(project, publication)
        f.diagnostic('tracker-health', healthy)
        self.assertIsNone(healthy['error'])
        self.assertEqual((0, 3), healthy['observed_k'])
        self.assertTrue(healthy['context_revoked'])
        self._assert_settled(healthy, 4)
        self.assertEqual(0, healthy['snapshot']['faults'])
        lock = project / '.tracker/LOCK'
        original = lock.stat()
        outcome = f.tracker_case(project, publication, fault=True)
        f.diagnostic('tracker-body-ni-close-eio', outcome)
        after = lock.stat()
        self.assertIs(outcome['ni'], outcome['error'], 'TRACKER_BODY_NI_WAS_REPLACED')
        self.assertIs(outcome['cause'], outcome['error'].__cause__)
        self.assertEqual((0, 3), outcome['observed_k'])
        self.assertTrue(outcome['context_revoked'])
        self._assert_settled(outcome, 4)
        self.assertEqual(1, outcome['snapshot']['faults'])
        self.assertEqual((original.st_dev, original.st_ino), (after.st_dev, after.st_ino))
        self.assertEqual(0o600, after.st_mode & 0o777)
