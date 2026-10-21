"""Independent fixture-only SOURCE; no C6/qualification or SDK authority.

NOT RUN. Root first mechanically exposes the old finally/doCleanups behavior
under the explicit finalizer seam, then runs these unchanged assertions.
"""
from contextlib import redirect_stderr
import errno
from io import StringIO
import os
from pathlib import Path
import tempfile
import unittest

from test_cases import issue_tracker_cable_post_c6_fixture as SUBJECT


class PostC6FixtureCleanupTests(unittest.TestCase):
    def finalizer(self):
        function = getattr(SUBJECT, '_run_fixture_action_with_cleanup', None)
        error = getattr(SUBJECT, 'FixtureCleanupError', None)
        self.assertTrue(callable(function), 'MISSING_TEST_ONLY_CLEANUP_SEAM')
        self.assertTrue(isinstance(error, type) and issubclass(error, Exception),
                        'MISSING_TEST_ONLY_CLEANUP_ERROR')
        return function, error

    def owned_descriptor(self):
        root = Path(tempfile.mkdtemp(prefix='req7-post-c6-cleanup-direct-', dir='/private/tmp'))
        print('POST_C6_CLEANUP_DIRECT_OWNED_ROOT=' + str(root), flush=True)
        path = root / 'literal-owned-input'
        path.write_bytes(b'independent fixture-only original\n')
        return os.open(path, os.O_RDONLY | os.O_NOFOLLOW)

    def assert_closed(self, descriptor):
        caught = None
        try:
            os.fstat(descriptor)
        except OSError as error:
            caught = error
        self.assertIsNotNone(caught, 'test-owned native descriptor must close')
        self.assertEqual(errno.EBADF, caught.errno)

    def test_real_cleanup_failure_and_skip_cannot_be_reported_as_outer_success(self):
        run, cleanup_error = self.finalizer()
        healthy = unittest.TestCase('runTest')
        healthy_fd = self.owned_descriptor()
        healthy.addCleanup(os.close, healthy_fd)
        actions = []
        self.assertIsNone(run(healthy, lambda: actions.append('healthy-body')))
        self.assertEqual(['healthy-body'], actions)
        self.assert_closed(healthy_fd)
        self.assertEqual([], healthy._cleanups)
        for fault_type in (RuntimeError, AssertionError, unittest.SkipTest):
            with self.subTest(fault_type=fault_type.__name__):
                case = unittest.TestCase('runTest')
                descriptor = self.owned_descriptor()
                case.addCleanup(os.close, descriptor)
                events = []
                fault = fault_type('literal owned fixture cleanup failure')
                def broken_cleanup():
                    events.append('cleanup-fault')
                    raise fault
                case.addCleanup(broken_cleanup)
                caught = None
                try:
                    run(case, lambda: events.append('body-returned'))
                except BaseException as error:
                    caught = error
                self.assertEqual(['body-returned', 'cleanup-fault'], events)
                self.assert_closed(descriptor)
                self.assertEqual([], case._cleanups)
                self.assertIsInstance(caught, cleanup_error,
                    'inner doCleanups False/Skip must not become outer success')

    def test_original_body_interrupt_and_cause_survive_ordinary_cleanup_failure(self):
        run, _cleanup_error = self.finalizer()
        for interrupt_type in (KeyboardInterrupt, SystemExit):
            with self.subTest(interrupt_type=interrupt_type.__name__):
                case = unittest.TestCase('runTest')
                descriptor = self.owned_descriptor()
                events = []
                case.addCleanup(os.close, descriptor)
                def broken_cleanup():
                    events.append('ordinary-cleanup-fault')
                    raise OSError(errno.EIO, 'literal after-body fixture failure')
                case.addCleanup(broken_cleanup)
                cause = ValueError('independent original body cause')
                interrupt = interrupt_type('independent original body interrupt')
                interrupt.__cause__ = cause
                def body():
                    events.append('body-interrupt')
                    raise interrupt
                caught = None
                diagnostic = StringIO()
                with redirect_stderr(diagnostic):
                    try:
                        run(case, body)
                    except BaseException as error:
                        caught = error
                self.assertEqual('POST_C6_FIXTURE_CLEANUP_FAILED_BODY_EXCEPTION_PRESERVED\n',
                                 diagnostic.getvalue())
                self.assertIs(interrupt, caught)
                self.assertIs(cause, caught.__cause__)
                self.assertEqual(['body-interrupt', 'ordinary-cleanup-fault'], events)
                self.assert_closed(descriptor)
                self.assertEqual([], case._cleanups)


if __name__ == '__main__':
    unittest.main()

