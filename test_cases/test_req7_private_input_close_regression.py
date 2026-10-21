"""One independent whole, four isolated close-only regression subcases; NOT RUN."""
import errno
import unittest
from test_cases import private_input_close_regression_fixture as f


class PrivateInputCloseRegressionTests(unittest.TestCase):
    def test_close_only_ni_and_ordinary_eio_preserve_original_cleanup_contracts(self):
        for holder,kind in (('credential','ni'),('credential','eio'),('target','ni'),('target','eio')):
            with self.subTest(holder=holder,kind=kind):f.run_owned(self,holder,kind)

    def _closed(self,snapshot,count,*,faults,revocation=False):
        self.assertEqual(count,snapshot['slots'])
        self.assertEqual(count,snapshot['calls'])
        self.assertEqual([errno.EBADF]*count,snapshot['ebadf'])
        self.assertEqual(faults,snapshot['faults'])
        self.assertTrue(snapshot['each_known_slot_once'])
        self.assertEqual([],snapshot['remaining'])
        if revocation:self.assertEqual([True]*count,snapshot['revoked'])

    def _exercise(self,holder,kind):
        # Each scenario gets a fresh cold child and a complete healthy control
        # BEFORE constructing its no-body-error fault case.
        healthy=(f.original.credential_case(fault=False) if holder=='credential'
                 else f.original.target_case(fault=False))
        f.original.diagnostic(holder+'-close-only-health',healthy)
        self.assertTrue(healthy['ready'],'HEALTH_NOT_REACHED_FAULT_NOT_EXECUTED')
        self.assertIsNone(healthy['error'])
        self.assertTrue(healthy['shared_os_unchanged'])
        self._closed(healthy['private'],6,faults=0,revocation=holder=='target')
        if holder=='credential':self.assertEqual(f.original.CRE,healthy['observed'][0])
        else:
            self.assertEqual((0,3),healthy['observed_k'])
            self.assertEqual(f.original.TARGET,healthy['binding'].spreadsheet_id)
            self.assertEqual((1,[]),(healthy['profile_seen'],healthy['profile_errors']))
            self.assertTrue(healthy['target_revoked']);self.assertTrue(healthy['local_revoked'])
            self.assertIsInstance(healthy['revoked_error'],healthy['hold'])
            self.assertTrue(healthy['config_unchanged'])
            self.assertEqual(6,healthy['target_expected_slots'])
            self._closed(healthy['target'],6,faults=0,revocation=True)
            self._closed(healthy['local'],4,faults=0,revocation=True)
        outcome=f.credential_case(kind) if holder=='credential' else f.target_case(kind)
        f.diagnostic(holder,kind,outcome)
        self.assertTrue(outcome['body_completed'])
        self.assertTrue(outcome['shared_os_unchanged'])
        if kind=='ni':
            self.assertIs(outcome['close_error'],outcome['error'])
            self.assertIs(outcome['close_cause'],outcome['error'].__cause__)
        else:
            self.assertIs(type(outcome['error']),outcome['hold'])
            self.assertEqual('credential_file_authority_invalid' if holder=='credential'
                             else 'current_target_binding_unproved',str(outcome['error']))
            self.assertIsNone(outcome['error'].__cause__)
            self.assertNotIn(f.SECRET,str(outcome['error']))
            self.assertNotIn(f.SECRET,repr(outcome['error']))
        self._closed(outcome['private'],6,faults=1 if holder=='credential' else 0,revocation=holder=='target')
        if holder=='credential':self.assertEqual(f.original.CRE,outcome['observed'][0])
        else:
            self.assertEqual((0,3),outcome['observed_k'])
            self.assertEqual(f.original.TARGET,outcome['binding'].spreadsheet_id)
            self.assertEqual((1,[]),(outcome['profile_seen'],outcome['profile_errors']))
            self.assertTrue(outcome['target_revoked']);self.assertTrue(outcome['local_revoked'])
            self.assertIsInstance(outcome['revoked_error'],outcome['hold'])
            self.assertTrue(outcome['config_unchanged'])
            self.assertEqual(6,outcome['target_expected_slots'])
            self._closed(outcome['target'],6,faults=1,revocation=True)
            self._closed(outcome['local'],4,faults=0,revocation=True)
