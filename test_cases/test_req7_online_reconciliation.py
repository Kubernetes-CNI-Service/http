"""Fixed project-authenticated reads reconcile originals, never retry or NEW."""
from contextlib import ExitStack, contextmanager
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import socket
import unittest
from unittest import mock

from test_cases import test_req7_remote_history_match as native
from test_cases import test_req7_history_read_launcher as read_fixture
from test_cases.test_req7_global_attempt_journal import original_read_files


class OnlineReconciliationDirectTests(unittest.TestCase):
    def test_manifest_registers_one_primary_suite_and_actual_reconciliation_members(self):
        registry = json.loads((Path(__file__).resolve().parent/'script_test_manifest.json').read_text())
        test = 'test_cases.test_req7_online_reconciliation'
        self.assertEqual(['issue-tracker-local'],
            [suite['id'] for suite in registry['test_suites'] if test in suite['tests']])
        self.assertTrue(any('monitor/issue_tracker_remote_history_match.py' in rule['paths']
            and test in rule['tests'] for rule in registry['test_rules']))
        required = {'monitor/issue_tracker_remote_history_match.py',
            'monitor/issue_tracker_history_read_launcher.py', 'monitor/issue_tracker_token_launcher.py',
            'monitor/issue_tracker_sdk_authentication.py', 'monitor/issue_tracker_online_target.py',
            'monitor/issue_tracker_local_commit.py', 'monitor/issue_tracker_spreadsheet_owner.py',
            'monitor/issue_tracker_global_attempt_journal.py', 'monitor/issue_tracker_enrollment_journal.py'}
        self.assertTrue(any(required <= set(item['members']) and test in item['tests']
            for item in registry['workflows']))

    def test_unheld_owners_refuse_before_auth_or_any_read(self):
        from monitor import issue_tracker_history_read_launcher as reads
        from monitor import issue_tracker_token_launcher as tokens
        module = native.load()
        api = getattr(module, 'reconcile_owned_project_unit', None)
        self.assertTrue(callable(api), 'default reconciliation needs a fixed original-only read driver')
        with mock.patch.object(tokens, 'require_current_owned_project_token') as auth, \
                mock.patch.object(reads, 'OwnedProjectSheetsReadUnit') as read:
            with self.assertRaises(module.RemoteHistoryHold) as caught:
                api(object(), object(), object(), object(), object(), generation=object())
        self.assertIsNone(caught.exception.__context__)
        auth.assert_not_called(); read.assert_not_called()


class OnlineReconciliationWorkflowTests(unittest.TestCase):
    _Fixture = native.Req7OwnedHistoryMatchWorkflowTests._Fixture
    setUp = native.Req7OwnedHistoryMatchWorkflowTests.setUp
    server = native.Req7OwnedHistoryMatchWorkflowTests.server
    owners = native.Req7OwnedHistoryMatchWorkflowTests.owners
    intercept = native.Req7OwnedHistoryMatchWorkflowTests.intercept
    child_fixture = native.Req7OwnedHistoryMatchWorkflowTests.child_fixture
    read_owned = native.Req7OwnedHistoryMatchWorkflowTests.read_owned
    prepare_owned = native.Req7OwnedHistoryMatchWorkflowTests.prepare_owned
    project_auth = read_fixture.Req7HistoryReadLauncherWorkflowTests.project_auth

    def certificates(self, hostname='oauth2.googleapis.com'):
        # One owned server certificate per contiguous destination phase. The
        # original fixture otherwise rewrites its CA/key on EVERY server;
        # those are test setup, not business-journal mutation by the driver.
        if getattr(self, '_certificate_destination', None) != hostname:
            self._certificates = native.Req7OwnedHistoryMatchWorkflowTests.certificates(self, hostname)
            self._certificate_destination = hostname
        return self._certificates

    def api(self):
        module = native.load()
        api = getattr(module, 'reconcile_owned_project_unit', None)
        self.assertTrue(callable(api), 'actual owned OAuth and four fixed reads must drive original settlement')
        return module, api

    def exercise(self, fault=None):
        module, api = self.api()
        from monitor import issue_tracker_history_read_launcher as reads
        from monitor import issue_tracker_spreadsheet_owner as ownership
        from monitor import issue_tracker_global_attempt_journal as globals_
        from monitor import issue_tracker_token_launcher as tokens
        with ExitStack() as stack:
            writer, owner, bound, _token, config, unit, docs = self.prepare_owned(stack, native_generation=True)
            auth, _credential, _raw = self.project_auth(stack, ownership, owner, bound)
            self.certificates('sheets.googleapis.com')
            before = original_read_files(self.root); kinds = []; children_seen = []; read_facts = []
            replaced = []
            if fault == 'complete-handoff-rebind':
                actual_holder = module._hold_completion_originals
                proof_entries = []
                @contextmanager
                def replace_before_second_capture(*args):
                    proof_entries.append(True)
                    if len(proof_entries) == 2:
                        state = self.root/'var/lib/http-ztp-container/issue-tracker'
                        prefix = hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()
                        marker = state/(prefix+'.completion')/'COMPLETE'
                        raw = marker.read_bytes(); old_inode = marker.stat().st_ino
                        marker.rename(self.root/'preserved-handoff-complete')
                        marker.write_bytes(raw); marker.chmod(0o600)
                        replaced.append((old_inode, marker.stat().st_ino))
                    with actual_holder(*args) as verify:
                        yield verify
                stack.enter_context(mock.patch.object(module, '_hold_completion_originals',
                    side_effect=replace_before_second_capture))
            if fault == 'key-rebind-after-auth':
                key = self.root/'project/.tracker'/('REMOTE-KEY-HIGH-WATER-'+unit.unit_id)
                actual_auth = tokens.require_current_owned_project_token
                def auth_then_rebind(*args):
                    value = actual_auth(*args)
                    if key.exists() and not replaced:
                        raw = key.read_bytes(); old_inode = key.stat().st_ino
                        key.rename(self.root/'preserved-final-key')
                        key.write_bytes(raw); key.chmod(0o600)
                        replaced.append((old_inode, key.stat().st_ino))
                    return value
                stack.enter_context(mock.patch.object(tokens, 'require_current_owned_project_token', side_effect=auth_then_rebind))
            documents = {kind: deepcopy(document) for kind, document in docs.values()}
            if fault == 'missing-fence':
                documents['metadata']['matchedDeveloperMetadata'].pop()
            if fault == 'missing-audit':
                documents['history_tail']['sheets'][0]['data'][0]['rowData'].pop()
            original_read = reads.OwnedProjectSheetsReadUnit.read_once
            def read_actual(reader):
                kinds.append(reader._kind)
                body = json.dumps(documents[reader._kind], separators=(',', ':')).encode()
                reply = b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\nConnection: close\r\n\r\n' + body
                with self.server(reply, hostname='sheets.googleapis.com', destination='sheets.googleapis.com') as (records, errors), ExitStack() as launched:
                    port = socket.getaddrinfo('sheets.googleapis.com', 443)[0][4][1]
                    calls, children = self.intercept(launched, self.child_fixture(port), writer, owner, bound)
                    result = original_read(reader)
                    children_seen.extend(children)
                # Retain request/cleanup observations for assertions AFTER the
                # driver's normalization scope, especially negative cases.
                read_facts.append((reader._kind, len(records), len(calls),
                    tuple(type(error).__name__ for error in errors), children[0].returncode))
                if fault == 'revoke-after-last-read' and reader._kind == 'history_tail':
                    config.write_bytes(b'{"schema_version":2}')
                return result
            candidate = replace(auth) if fault == 'copied-auth' else auth
            with mock.patch.object(reads.OwnedProjectSheetsReadUnit, 'read_once', autospec=True, side_effect=read_actual):
                if fault in ('copied-auth', 'revoke-after-last-read', 'key-rebind-after-auth', 'complete-handoff-rebind'):
                    with self.assertRaises(module.RemoteHistoryHold) as caught:
                        api(writer, owner, bound, unit, candidate, generation=self.native_generation)
                    self.assertIsNone(caught.exception.__context__)
                else:
                    result = api(writer, owner, bound, unit, candidate, generation=self.native_generation)
            # Real counter and actual fixture requests, not returned labels.
            self.assertEqual((1, 'UNKNOWN'), (globals_.inspect_global_unit(owner, bound, unit).attempt_count,
                globals_.inspect_global_unit(owner, bound, unit).outcome))
            self.assertEqual([] if fault == 'copied-auth' else
                ['template_identity', 'template_headers', 'metadata', 'history_tail'], kinds)
            self.assertEqual([(kind, 1, 1, (), 0) for kind in kinds], read_facts)
            self.assertTrue(all(child.returncode == 0 for child in children_seen))
            state = self.root/'var/lib/http-ztp-container/issue-tracker'
            prefix = hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()
            if fault is None:
                self.assertEqual(('APPLIED', unit.unit_id, ('switch:0001',)),
                    (result.state, result.unit_id, result.applied_operation_ids))
                self.assertEqual(result, module.inspect_owned_applied_evidence(writer, owner, bound, unit, generation=self.native_generation))
                self.assertTrue(module.inspect_owned_applied_key_watermarks(writer, owner, bound, unit, generation=self.native_generation))
                self.assertTrue((state/(prefix+'.completion')/'COMPLETE').is_file())
                self.assertTrue(before.items() <= original_read_files(self.root).items())
                with mock.patch.object(reads, 'OwnedProjectSheetsReadUnit') as no_new_read:
                    self.assertEqual(result, api(writer, owner, bound, unit, auth, generation=self.native_generation))
                no_new_read.assert_not_called()
                self.assertEqual(4, len(kinds))
            elif fault == 'key-rebind-after-auth':
                self.assertEqual(1, len(replaced)); self.assertNotEqual(*replaced[0])
                self.assertEqual(key.read_bytes(), (self.root/'preserved-final-key').read_bytes())
                self.assertTrue(before.items() <= original_read_files(self.root).items())
            elif fault == 'complete-handoff-rebind':
                self.assertEqual(1, len(replaced)); self.assertNotEqual(*replaced[0])
                marker = state/(prefix+'.completion')/'COMPLETE'
                self.assertEqual(marker.read_bytes(), (self.root/'preserved-handoff-complete').read_bytes())
                self.assertFalse((self.root/'project/.tracker'/('REMOTE-APPLIED-'+unit.unit_id)).exists())
                self.assertFalse((self.root/'project/.tracker'/('REMOTE-KEY-HIGH-WATER-'+unit.unit_id)).exists())
                self.assertTrue(before.items() <= original_read_files(self.root).items())
            else:
                self.assertFalse((state/(prefix+'.completion')).exists())
                self.assertFalse((self.root/'project/.tracker'/('REMOTE-APPLIED-'+unit.unit_id)).exists())
                if fault in ('missing-fence', 'missing-audit'):
                    self.assertEqual('UNKNOWN' if fault == 'missing-fence' else 'CONFLICT', result.state)
                    self.assertEqual(before, original_read_files(self.root))
            if fault not in ('copied-auth', 'revoke-after-last-read', 'key-rebind-after-auth', 'complete-handoff-rebind'):
                self.assertFalse(any(hasattr(result, name) for name in ('permit', 'retry', 'send_once')))

    def test_actual_project_auth_four_reads_complete_applied_keys_without_another_wire_attempt(self):
        self.exercise()

    def test_missing_fence_preserves_unknown_and_every_original(self):
        self.exercise('missing-fence')

    def test_missing_audit_is_conflict_not_completion_or_retry(self):
        self.exercise('missing-audit')

    def test_equal_auth_copy_cannot_start_any_read(self):
        self.exercise('copied-auth')

    def test_policy_revoked_after_last_read_never_installs_completion(self):
        self.exercise('revoke-after-last-read')

    def test_final_auth_recheck_cannot_adopt_a_same_byte_key_watermark_replacement(self):
        self.exercise('key-rebind-after-auth')

    def test_created_complete_cannot_be_rebound_before_the_applied_handoff(self):
        self.exercise('complete-handoff-rebind')
