"""Two independent owned-child cleanup wholes, SOURCE ONLY / NOT RUN."""
import errno
import unittest
from test_cases import private_input_ni_fixture as f


class PrivateInputNICleanupTests(unittest.TestCase):
    def test_credential_original_body_ni_survives_distinct_actual_close_ni(self):
        f.run_owned(self,'_exercise_credential_body_ni_then_close_ni')

    def test_target_original_body_ni_survives_distinct_actual_close_ni(self):
        f.run_owned(self,'_exercise_target_body_ni_then_close_ni')

    def _assert_closed(self,snapshot,count,*,faults,revocation=False):
        self.assertEqual(count,snapshot['slots'])
        self.assertEqual(count,snapshot['calls'])
        self.assertEqual([errno.EBADF]*count,snapshot['ebadf'])
        self.assertEqual(faults,snapshot['faults'])
        self.assertTrue(snapshot['each_known_slot_once'])
        self.assertEqual([],snapshot['remaining'])
        if revocation:self.assertEqual([True]*count,snapshot['revoked'])

    def _exercise_credential_body_ni_then_close_ni(self):
        healthy=f.credential_case(fault=False);f.diagnostic('credential-health',healthy)
        self.assertTrue(healthy['ready'],'HEALTH_NOT_REACHED_FAULT_NOT_EXECUTED')
        self.assertIsNone(healthy['error'])
        self.assertEqual(f.CRE,healthy['observed'][0])
        self.assertEqual('https://oauth2.googleapis.com/token',healthy['observed'][1]['token_uri'])
        self.assertTrue(healthy['shared_os_unchanged'])
        self._assert_closed(healthy['private'],6,faults=0)
        fault=f.credential_case(fault=True);f.diagnostic('credential-bodyNI-closeNI',fault)
        self.assertTrue(fault['ready'])
        self.assertIs(fault['body'],fault['error'])
        self.assertIs(fault['cause'],fault['error'].__cause__)
        self.assertIsNot(fault['body'],fault['close'])
        self.assertIs(fault['close_cause'],fault['close'].__cause__)
        self.assertTrue(fault['shared_os_unchanged'])
        self._assert_closed(fault['private'],6,faults=1)

    def _exercise_target_body_ni_then_close_ni(self):
        healthy=f.target_case(fault=False);f.diagnostic('target-health',healthy)
        self.assertTrue(healthy['ready'],'HEALTH_NOT_REACHED_FAULT_NOT_EXECUTED')
        self.assertIsNone(healthy['error'])
        self.assertEqual((0,3),healthy['observed_k'])
        self.assertEqual(f.TARGET,healthy['binding'].spreadsheet_id)
        self.assertEqual((1,[]),(healthy['profile_seen'],healthy['profile_errors']))
        self.assertTrue(healthy['target_revoked']);self.assertTrue(healthy['local_revoked'])
        self.assertIsInstance(healthy['revoked_error'],healthy['hold'])
        self.assertTrue(healthy['config_unchanged']);self.assertTrue(healthy['shared_os_unchanged'])
        self._assert_closed(healthy['private'],6,faults=0,revocation=True)
        self._assert_closed(healthy['target'],healthy['target_expected_slots'],faults=0,revocation=True)
        self._assert_closed(healthy['local'],4,faults=0,revocation=True)
        fault=f.target_case(fault=True);f.diagnostic('target-bodyNI-closeNI',fault)
        self.assertTrue(fault['ready'])
        self.assertIs(fault['body'],fault['error'])
        self.assertIs(fault['cause'],fault['error'].__cause__)
        self.assertIsNot(fault['body'],fault['close'])
        self.assertIs(fault['close_cause'],fault['close'].__cause__)
        self.assertEqual((1,[]),(fault['profile_seen'],fault['profile_errors']))
        self.assertTrue(fault['target_revoked']);self.assertTrue(fault['local_revoked'])
        self.assertIsInstance(fault['revoked_error'],fault['hold'])
        self.assertTrue(fault['config_unchanged']);self.assertTrue(fault['shared_os_unchanged'])
        self._assert_closed(fault['private'],6,faults=0,revocation=True)
        self._assert_closed(fault['target'],fault['target_expected_slots'],faults=1,revocation=True)
        self._assert_closed(fault['local'],4,faults=0,revocation=True)
