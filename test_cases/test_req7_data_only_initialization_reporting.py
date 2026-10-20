"""Independent SOURCE-only reporting negatives; no completion issuer/permit.

The direct case has an explicit UNIT seam for a DATA-only None return. The
workflow uses the real canonical manual producer, owners, private TLS child
protocols, evidence files and next worker. Nothing creates STAGING/COMPLETED,
substitutes a completion verifier, or grants sending authority.

The old fixture's refusal branch is selected by a new expected-outcome tag.
This tag matches NONE of its four fault-injection names, so the manual path is
healthy through real readback/owner cleanup, not a manufactured remote error.
The original helper and every existing test/assertion remain unchanged.
"""
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

from test_cases import test_req7_explicit_enrollment_initialize_workflow as canonical


REFUSED = 'enrollment initialization refused; evidence retained\n'
SUCCESS = 'enrollment initialized; automatic sending remains disabled\n'
ATTEMPT_LEAVES = frozenset((
    'INTENT', 'PREFLIGHT-template_identity', 'PREFLIGHT-template_headers',
    'PREFLIGHT-whitelist', 'PREFLIGHT-metadata', 'WIRE', 'RESPONSE',
    'RESPONSE-STATUS', 'READBACK', 'OBSERVED-DATA',
))
JOURNAL_LEAVES = frozenset(('HEADER', 'NONCES', 'INITIALIZED'))
REFUSAL_EXPECTATION_ONLY = 'data-only-without-final-completion'


class DataOnlyInitializationReportDirectTests(unittest.TestCase):
    def test_none_data_return_cannot_be_reported_as_completed_initialization(self):
        from monitor import issue_tracker_enrollment_journal as journal
        from monitor import issue_tracker_enrollment_initialize as initialize

        # UNIT seam only. None is the current real DATA-only producer return,
        # not a completion record, fake grant or healthy-publisher substitute.
        project = Path('/not-opened/req7-report-unit-project')
        output, errors = io.StringIO(), io.StringIO()
        with mock.patch.object(initialize, 'initialize_current_project',
                return_value=None) as producer, \
             mock.patch.object(sys, 'argv', [str(canonical.CLI),
                 '--initialize-project', str(project)]), \
             mock.patch('socket.socket', side_effect=AssertionError('UNIT has no network')) as network, \
             mock.patch('subprocess.Popen', side_effect=AssertionError('UNIT has no child')) as child, \
             redirect_stdout(output), redirect_stderr(errors):
            status = journal._manual_main()
        producer.assert_called_once_with(project)
        network.assert_not_called()
        child.assert_not_called()
        self.assertEqual((3, '', REFUSED), (status, output.getvalue(), errors.getvalue()),
                         'DATA_ONLY_NONE_RETURN_IS_NOT_INITIALIZATION_COMPLETION')
        self.assertNotIn(SUCCESS, output.getvalue())


class DataOnlyInitializationReportTlsWorkflowTests(unittest.TestCase):
    def test_actual_tls_observed_data_refuses_success_and_next_worker_new(self):
        fixture = canonical.ExplicitEnrollmentInitializeWorkflowTests(methodName='runTest')

        def cleanup_original_fixture():
            self.assertTrue(fixture.doCleanups(), 'ORIGINAL_TLS_FIXTURE_CLEANUP_INCOMPLETE')

        self.addCleanup(cleanup_original_fixture)
        fixture.setUp()
        observations = []

        def after_initialize(project, state, bound, *original_owners):
            # Called by the original helper after its real manual owners have
            # returned, all original requests were checked and children reaped.
            # All assertions below stay OUTSIDE original owner contexts.
            stem = hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()
            attempt = state / ('enrollment-init-' + stem)
            journal = state / (stem + '.enrollment')
            self.assertEqual(ATTEMPT_LEAVES, frozenset(p.name for p in attempt.iterdir()))
            self.assertEqual(JOURNAL_LEAVES, frozenset(p.name for p in journal.iterdir()))
            observed = json.loads((attempt / 'OBSERVED-DATA').read_bytes())
            self.assertEqual(1, observed['schema_version'])
            self.assertEqual('ENROLLMENT_READBACK_DATA', observed['outcome'])
            self.assertIs(False, observed['automatic_sending_enabled'])
            self.assertFalse((attempt / '.COMPLETED-STAGED').exists())
            self.assertFalse((attempt / 'COMPLETED').exists())
            retained = canonical.tree_images(state)

            # The real normal worker is called. Its original completion gate
            # must stop before NEW preparation, OAuth, COUNT, send, any extra
            # child/network operation or automatic manual initialization.
            fixture._assert_initialized_worker_gate(project, state, bound,
                *original_owners, expected_new_entries=0)
            self.assertEqual(retained, canonical.tree_images(state))
            observations.append((len(ATTEMPT_LEAVES), len(JOURNAL_LEAVES)))

        # This is NOT any recognized fault injection: remote-existing,
        # write-UNKNOWN, readback-mismatch or owner-cleanup. The unchanged
        # original helper's else branch independently requires exit3, empty
        # stdout, fixed refusal stderr, and zero success emissions. All four
        # real TLS stages plus original cleanup/secret/COUNT checks still run.
        fixture._exercise_actual_initialize(REFUSAL_EXPECTATION_ONLY,
                                           after_initialize=after_initialize)
        self.assertEqual([(10, 3)], observations)


if __name__ == '__main__':
    unittest.main()
