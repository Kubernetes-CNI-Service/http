"""SOURCE-only UNIT negatives: normal producer return is not completion.

Only initialize_current_project is replaced, explicitly as a producer UNIT seam.
No owner, target, completion reader/verifier, token or record is substituted.
The CLI receives a truly absent project leaf beneath this test's own empty TD;
its original owner/reader path must refuse, not accept a DTO/string as authority.
No legitimate completed-project positive, TLS, NEW/COUNT/send or cold durability
proof is claimed. A missing project can refuse before the completion reader.
"""
from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from monitor import issue_tracker_enrollment_journal as SUBJECT
from monitor import issue_tracker_enrollment_initialize as initialize


REFUSED = 'enrollment initialization refused; evidence retained\n'
SUCCESS = 'enrollment initialized; automatic sending remains disabled\n'


class InitializationReturnValueUnitTests(unittest.TestCase):
    def test_non_none_objects_dto_pass_and_done_cannot_report_missing_project_complete(self):
        # This is a real original-reader refusal control, not an owner fixture:
        # None supplies no original writer/owner/binding and must never yield.
        # Keep assertions outside its normalizing contextmanager scope.
        reader_error = None
        reader_yielded = False
        try:
            with initialize._hold_initialization_completion(None, None, None):
                reader_yielded = True
        except initialize.EnrollmentInitializeHold as error:
            reader_error = error
        self.assertIs(type(reader_error), initialize.EnrollmentInitializeHold)
        self.assertFalse(reader_yielded)

        # Independent literals, not producer output copied into the oracle.
        # In particular the completion-shaped DTO is merely Python DATA; it
        # cannot stand in for a final record tied to thirteen held originals.
        returns = (
            ('opaque-object', object()),
            ('completion-shaped-dto', SimpleNamespace(schema_version=1,
                outcome='INITIALIZATION_COMPLETED', automatic_sending_enabled=False)),
            ('pass-dto', SimpleNamespace(status='PASS', complete=True)),
            ('pass-string', 'PASS'),
            ('done-string', 'DONE'),
            ('true-scalar', True),
            ('done-mapping', {'state': 'DONE', 'success': True}),
        )
        for label, returned in returns:
            with self.subTest(producer_return=label), \
                 tempfile.TemporaryDirectory(prefix='req7-report-return-unit-') as raw:
                root = Path(raw).resolve()
                project = root / 'absent-project'
                self.assertFalse(project.exists())
                self.assertEqual([], list(root.iterdir()))
                output, errors = io.StringIO(), io.StringIO()
                with mock.patch.object(initialize, 'initialize_current_project',
                        return_value=returned) as producer, \
                     mock.patch.object(sys, 'argv', ['issue_tracker_enrollment_journal.py',
                         '--initialize-project', str(project)]), \
                     mock.patch('socket.socket', side_effect=AssertionError('UNIT forbids network')) as network, \
                     mock.patch('subprocess.Popen', side_effect=AssertionError('UNIT forbids child')) as child, \
                     mock.patch('threading.Thread.start', side_effect=AssertionError('UNIT forbids thread')) as thread, \
                     redirect_stdout(output), redirect_stderr(errors):
                    status = SUBJECT._manual_main()
                producer.assert_called_once_with(project)
                network.assert_not_called()
                child.assert_not_called()
                thread.assert_not_called()
                # No actual project/evidence was created or repaired. The
                # real missing-original/owner gate remains in place throughout.
                self.assertFalse(project.exists())
                self.assertEqual([], list(root.iterdir()))
                self.assertEqual((3, '', REFUSED),
                    (status, output.getvalue(), errors.getvalue()),
                    'NORMAL_RETURN_DATA_IS_NOT_INITIALIZATION_COMPLETION')
                self.assertNotIn(SUCCESS, output.getvalue())


if __name__ == '__main__':
    unittest.main()
