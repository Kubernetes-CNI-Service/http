"""Actual SDK healthy control then two literal allocation-slot mutations."""
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from test_cases import issue_tracker_cable_post_c6_fixture as old
from test_cases import test_req7_cable_read_owner_core as core_test

from test_cases import test_req7_cable_credential_construction as direct


class RsaAllocationOriginWorkflowTests(unittest.TestCase):
    healthy_source = core_test.CableReadOwnerCoreTests.healthy_source
    observed_owners = core_test.CableReadOwnerCoreTests.observed_owners

    def test_healthy_then_two_changed_RSA_allocation_slots_refuse_before_entry(self):
        direct.entry(self)
        def body(runtime, _core, reader, sheet, case, inputs):
            function = runtime._hold_current_cable_sdk_credential_prerequisite
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            from google.auth.crypt import rsa as auth_rsa, _cryptography_rsa
            from google.oauth2 import service_account
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pem = key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            inputs['cre'].write_bytes(json.dumps({'type': 'service_account',
                'client_email': 'fixture@example.invalid',
                'project_id': 'owned-fixture-project', 'private_key': pem.decode('ascii'),
                'token_uri': 'https://oauth2.googleapis.com/token'}).encode())
            inputs['cre'].chmod(0o600)
            with direct.observe_providers() as healthy:
                with function(reader, http_root=case.root) as proof:
                    proof.verify()
                    outcome = proof.outcome
                self.assertEqual('NO_SEND', outcome)
                self.assertEqual(1, healthy['from_info'])
                self.assertEqual(1, len(healthy['credentials']))
                self.assertIs(type(healthy['credentials'][0]), service_account.Credentials)
            self.assertEqual({}, sheet._ACTIVE)
            with self.assertRaises(runtime.CableSourceHold):
                proof.verify()
            self.assertEqual((0, 0), (inputs['network'].call_count, inputs['children'].call_count))
            print('ACTUAL_RSA_ALLOCATION_HEALTHY_CONTROL=' + json.dumps(
                dict(from_info=1, actual_sa=1, revoked=True, no_network=True)), flush=True)

            for label, provider in (('RSA_WRAPPER_NEW', auth_rsa.RSASigner),
                                    ('RSA_IMPLEMENTATION_NEW', _cryptography_rsa.RSASigner)):
                with self.subTest(provider=label):
                    inherited = '__new__' not in vars(provider)
                    descriptor = vars(provider).get('__new__')
                    original = provider.__new__
                    attempts = []
                    def changed(cls, *args, **kwargs):
                        attempts.append(label)
                        return original(cls)
                    self.assertIsNot(changed, original)
                    start = len(inputs['opened'])
                    yielded = False
                    refusal = None
                    provider.__new__ = staticmethod(changed)
                    try:
                        try:
                            with function(reader, http_root=case.root) as candidate:
                                yielded = True
                                candidate.verify()
                        except runtime.CableSourceHold as error:
                            refusal = type(error).__name__
                        closed = old.fds_closed(inputs['opened'][start:])
                        active = len(sheet._ACTIVE)
                    finally:
                        if inherited:
                            del provider.__new__
                        else:
                            provider.__new__ = descriptor
                    observed = dict(provider=label, modified_entries=len(attempts),
                        handle_yielded=yielded, refused=refusal is not None,
                        known_fds_closed=all(v for _n, v in closed), sheet_active=active,
                        network_calls=inputs['network'].call_count,
                        child_calls=inputs['children'].call_count)
                    print('MODIFIED_RSA_ALLOCATION_OBSERVATION=' + json.dumps(observed), flush=True)
                    self.assertIs(provider.__new__, original, 'EXACT_ALLOCATION_SLOT_NOT_RESTORED')
                    self.assertEqual([], attempts, 'MODIFIED_RSA_SLOT_MUST_BE_REFUSED_BEFORE_ENTRY')
                    self.assertFalse(yielded, 'MODIFIED_RSA_SLOT_YIELDED_PREREQUISITE')
                    self.assertIsNotNone(refusal, 'MODIFIED_RSA_SLOT_NOT_REFUSED')
                    self.assertTrue(all(v for _n, v in closed))
                    self.assertEqual(0, active)
                    self.assertEqual((0, 0), (inputs['network'].call_count, inputs['children'].call_count))
        core_test.CableReadOwnerCoreTests.exercise(self, body)


if __name__ == '__main__':
    unittest.main(verbosity=2)
