"""Real protected C6/current originals/dual owners -> actual SDK, NO_SEND."""
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from test_cases import completed_collection_source_read_fixture as completed
from test_cases import issue_tracker_cable_post_c6_fixture as old
from test_cases import test_req7_cable_read_owner_core as core_test

# Import the independent canonical helper module, not its TestCase.
from test_cases import test_req7_cable_credential_construction as direct


class CredentialConstructionWorkflowTests(unittest.TestCase):
    healthy_source = core_test.CableReadOwnerCoreTests.healthy_source
    observed_owners = core_test.CableReadOwnerCoreTests.observed_owners

    def test_real_current_source_constructs_once_then_invalid_original_refuses_without_io(self):
        # Initial missing API stops here; protected C6/construction NOT_REACHED.
        _runtime, _function = direct.entry(self)
        def body(runtime, _core, reader, sheet, case, inputs):
            function = getattr(runtime, '_hold_current_cable_sdk_credential_prerequisite')
            # Fixture-only local key generation BEFORE current source/code scope.
            # No actual service account or external key/file is read.
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            from google.oauth2 import service_account
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pem = private_key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            mapping = {'type': 'service_account',
                'client_email': 'fixture@example.invalid',
                'project_id': 'owned-fixture-project',
                'private_key': pem.decode('ascii'),
                'token_uri': 'https://oauth2.googleapis.com/token'}
            inputs['cre'].write_bytes(json.dumps(mapping).encode('utf-8'))
            inputs['cre'].chmod(0o600)

            # Real constructor-free prior prerequisite must itself be healthy.
            with direct.observe_providers() as old_events:
                with runtime._hold_current_cable_sdk_code_prerequisite(reader, http_root=case.root) as old_proof:
                    old_proof.verify()
                    self.assertEqual('NO_SEND', old_proof.outcome)
                self.assertEqual([], old_events['constructors'])
                self.assertEqual(0, old_events['from_info'])

            start = len(inputs['opened'])
            sheet_fds = ()
            with direct.observe_providers() as events:
                with self.observed_owners(sheet) as (_tokens, order, errors):
                    with function(reader, http_root=case.root) as proof:
                        self.assertEqual('NO_SEND', proof.outcome)
                        proof.verify()
                        proof.verify()
                        self.assertEqual([True], order)
                        self.assertEqual([], errors)
                        self.assertEqual(1, len(sheet._ACTIVE))
                        token, owner = next(iter(sheet._ACTIVE.items()))
                        self.assertEqual(old.TARGET, owner.binding.spreadsheet_id)
                        self.assertIs(owner, sheet._validated_owner(token, owner.binding))
                        sheet_fds = owner.descriptors
                        self.assertTrue(all(not completed.fd_closed(fd) for fd in sheet_fds))
                        self.assertEqual(1, events['from_info'], 'SDK_FROM_INFO_NOT_ONCE')
                        self.assertEqual(1, len(events['credentials']), 'SA_CONSTRUCTION_NOT_ONCE')
                        credential = events['credentials'][0]
                        self.assertIs(type(credential), service_account.Credentials)
                        self.assertEqual(('https://www.googleapis.com/auth/spreadsheets',), tuple(credential.scopes))
                        self.assertEqual('googleapis.com', credential.universe_domain)
                        self.assertIs(False, credential._always_use_jwt_access)
                        self.assertEqual('fixture@example.invalid', credential.service_account_email)
                        self.assertEqual('owned-fixture-project', credential.project_id)
                        self.assertIsNone(credential.token)
                        self.assertIsNone(credential.expiry)
                        opened = inputs['opened'][start:]
                        self.assertEqual(['issue-tracker-spreadsheet-whitelist.json', 'cre.json'],
                                         [name for name, _fd, _key in opened])
                        for name in ('credential', 'credential_raw', 'signer', 'token',
                                     'writer_token', 'sheet_token', 'fd', 'sdk',
                                     'transport', 'service'):
                            self.assertFalse(hasattr(proof, name), 'NO_SEND_EXPORTS_' + name)
                        shown = repr((proof, {'proof': proof}))
                        self.assertNotIn('BEGIN PRIVATE KEY', shown)
                        self.assertNotIn('fixture@example.invalid', shown)
                    self.assertEqual({}, sheet._ACTIVE)
                    self.assertTrue(all(completed.fd_closed(fd) for fd in sheet_fds))
                    self.assertTrue(all(closed for _name, closed in old.fds_closed(opened)))
                    with self.assertRaises(runtime.CableSourceHold):
                        proof.verify()
                self.assertEqual(1, events['from_info'])
                self.assertEqual(1, len(events['credentials']))

            # Fresh scope, strict shape but non-signable actual original bytes.
            # The successful old scope is never resurrected or retried.
            inputs['cre'].write_bytes(old.SYNTHETIC_CREDENTIAL)
            inputs['cre'].chmod(0o600)
            start = len(inputs['opened'])
            with direct.observe_providers() as bad_events:
                entered = False
                refusal = None
                try:
                    with function(reader, http_root=case.root):
                        entered = True
                except runtime.CableSourceHold as error:
                    refusal = error
                # Every refusal assertion is outside the product context.
                self.assertFalse(entered, 'NON_SIGNABLE_ORIGINAL_ADMITTED')
                self.assertIsNotNone(refusal, 'NON_SIGNABLE_ORIGINAL_NOT_REFUSED')
                self.assertEqual(1, bad_events['from_info'])
                self.assertEqual([], bad_events['credentials'])
                self.assertNotIn('SYNTHETIC-NOT-A-KEY', str(refusal))
                self.assertIsNone(refusal.__context__)
                self.assertIsNone(refusal.__cause__)
            self.assertEqual({}, sheet._ACTIVE)
            self.assertTrue(all(closed for _name, closed in old.fds_closed(inputs['opened'][start:])))
            self.assertEqual((0, 0), (inputs['network'].call_count, inputs['children'].call_count))
        core_test.CableReadOwnerCoreTests.exercise(self, body)


if __name__ == '__main__':
    unittest.main(verbosity=2)

