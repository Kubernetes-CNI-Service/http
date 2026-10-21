"""Real protected C6 + current-source + dual-owner + public-code NO_SEND.

Uses actual existing parent completion/source/local/sheet scripts, not a caller
DTO or native-success verifier. Does not construct SDK credentials or send.
"""
import unittest
from test_cases import completed_collection_source_read_fixture as completed
from test_cases import issue_tracker_cable_post_c6_fixture as old
from test_cases import test_req7_cable_read_owner_core as core_test
from test_cases import test_req7_cable_public_sdk_code as code_test


class CableSdkCodeOwnerWorkflowTests(unittest.TestCase):
    # Reuse the actual protected fixture and existing healthy-A control without
    # inheriting/duplicating either old whole test method.
    healthy_source = core_test.CableReadOwnerCoreTests.healthy_source
    observed_owners = core_test.CableReadOwnerCoreTests.observed_owners

    def test_real_post_c6_source_and_both_original_owners_remain_no_send_with_code_prerequisite(self):
        def body(runtime, _old_core, reader, sheet, case, inputs):
            entry = getattr(runtime, '_hold_current_cable_sdk_code_prerequisite', None)
            self.assertTrue(callable(entry), 'MISSING_SAME_SOURCE_OWNER_CODE_PREREQUISITE')
            start = len(inputs['opened'])
            sheet_fds = ()
            with code_test.CablePublicSdkCodeTests.observed_no_constructors(self) as constructors:
                with self.observed_owners(sheet) as (_tokens, order, errors):
                    with entry(reader, http_root=case.root) as proof:
                        self.assertEqual('NO_SEND', proof.outcome)
                        proof.verify()
                        proof.verify()
                        self.assertEqual([True], order, 'SHEET_WITHOUT_ACTUAL_LOCAL_OWNER')
                        self.assertEqual([], errors)
                        self.assertEqual(1, len(sheet._ACTIVE))
                        token, owner = next(iter(sheet._ACTIVE.items()))
                        self.assertEqual(old.TARGET, owner.binding.spreadsheet_id)
                        self.assertIs(owner, sheet._validated_owner(token, owner.binding))
                        sheet_fds = owner.descriptors
                        self.assertTrue(all(not completed.fd_closed(fd) for fd in sheet_fds))
                        opened = inputs['opened'][start:]
                        self.assertEqual(['issue-tracker-spreadsheet-whitelist.json', 'cre.json'],
                                         [name for name, _fd, _key in opened])
                        for name in ('credential', 'credential_raw', 'token', 'writer_token',
                                     'sheet_token', 'fd', 'sdk', 'transport', 'service'):
                            self.assertFalse(hasattr(proof, name), 'NO_SEND_EXPORTS_' + name)
                    # First-result observations before new use or fixture cleanup.
                    self.assertEqual({}, sheet._ACTIVE)
                    self.assertTrue(all(completed.fd_closed(fd) for fd in sheet_fds))
                    self.assertTrue(all(closed for _name, closed in old.fds_closed(opened)))
                    with self.assertRaises(runtime.CableSourceHold):
                        proof.verify()
                self.assertEqual([], constructors, 'CODE_OWNER_PREREQUISITE_CONSTRUCTED_CREDENTIAL_OR_SIGNER')
        core_test.CableReadOwnerCoreTests.exercise(self, body)
