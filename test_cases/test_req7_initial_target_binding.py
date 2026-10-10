"""Independent initial-binding cases under actual owner and fixed root reads."""
import hashlib
import importlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_cases.test_issue_tracker_online_target import TARGET, OTHER, document


class InitialTargetBindingDirectTests(unittest.TestCase):
    def test_manifest_registers_initial_binding_direct_and_actual_fixed_read_workflow(self):
        registry = json.loads((Path(__file__).resolve().parent/'script_test_manifest.json').read_text())
        test = 'test_cases.test_req7_initial_target_binding'
        self.assertEqual(['issue-tracker-local'],
            [suite['id'] for suite in registry['test_suites'] if test in suite['tests']])
        self.assertTrue(any('monitor/issue_tracker_online_target.py' in rule['paths']
            and test in rule['tests'] for rule in registry['test_rules']))
        required = {'monitor/issue_tracker_online_target.py', 'monitor/issue_tracker_local_commit.py',
            'monitor/issue_tracker_credential_shape.py', 'tools/project_contract.py'}
        self.assertTrue(any(required <= set(item['members']) and test in item['tests']
            for item in registry['workflows']))

    def api(self):
        module = importlib.import_module('monitor.issue_tracker_online_target')
        api = getattr(module, 'bind_current_project_online_target', None)
        self.assertTrue(callable(api), 'initial target must come from actual held config and fixed root enumeration')
        return module, api

    def test_initial_binding_rejects_nonroot_or_unheld_owner_before_any_input(self):
        module, api = self.api()
        from monitor import issue_tracker_credential_shape as private
        for euid in (0, 501):
            with self.subTest(euid=euid), mock.patch.object(module.os, 'geteuid', return_value=euid), \
                    mock.patch.object(module.os, 'open') as opening, \
                    mock.patch.object(private, 'read_target_allowlist') as listing:
                with self.assertRaises(module.OnlineTargetHold) as caught:
                    api(object())
                opening.assert_not_called(); listing.assert_not_called()
                self.assertIsNone(caught.exception.__context__)


class InitialTargetBindingWorkflowTests(unittest.TestCase):
    api = InitialTargetBindingDirectTests.api
    # The workflow's own cases exercise real owner/native flock/config/fixed
    # no-follow enumeration; no caller document or URL enters the new API.
    def exercise(self, fault=None):
        module, api = self.api()
        from monitor import issue_tracker_credential_shape as private
        from monitor.issue_tracker_local_commit import create_local_commit_store, writer_owner
        from test_cases.test_req7_spreadsheet_owner import scoped_fixture
        with tempfile.TemporaryDirectory(prefix='req7-initial-target-') as directory:
            project = Path(directory).resolve(); publication = project/'publication'
            publication.mkdir(mode=0o700); create_local_commit_store(project, publication)
            authority = project/'owned-root'
            private_dir = authority/'var/lib/http-ztp-container/service-account'
            private_dir.mkdir(parents=True, mode=0o700)
            listing = private_dir/'issue-tracker-spreadsheet-whitelist.json'
            raw = json.dumps([TARGET, OTHER]).encode(); listing.write_bytes(raw); listing.chmod(0o600)
            config = project/'01-global.yaml'
            config_raw = json.dumps(document(cycles=3)).encode()
            config.write_bytes(config_raw); config.chmod(0o644)
            with scoped_fixture(authority, private), scoped_fixture(authority, module), \
                    writer_owner(project, publication) as token:
                real_listing = private.read_target_allowlist
                seen = []
                def observe_listing():
                    value = real_listing(); seen.append(True)
                    if fault == 'config-rebind':
                        config.rename(project/'preserved-global.yaml')
                        config.write_bytes(config_raw); config.chmod(0o644)
                    return value
                if fault == 'disabled':
                    config.write_bytes(json.dumps(document(status='disabled')).encode())
                if fault == 'empty-list': listing.write_bytes(b'[]')
                with mock.patch.object(private, 'read_target_allowlist', side_effect=observe_listing):
                    if fault:
                        with self.assertRaises(module.OnlineTargetHold) as caught:
                            api(token)
                        self.assertIsNone(caught.exception.__context__)
                    else:
                        result = api(token)
                self.assertEqual(1, len(seen))
                if not fault:
                    policy = {'presence': 'explicit', 'status': 'enabled',
                              'publish_every_cycles': 3, 'spreadsheet_id': TARGET}
                    # Independent policy contract (confirmed by schema tests),
                    # never a digest copied from the binding implementation.
                    digest = hashlib.sha256((json.dumps(policy, sort_keys=True,
                        separators=(',', ':'), ensure_ascii=False)+'\n').encode()).hexdigest()
                    self.assertEqual((TARGET, hashlib.sha256(raw).hexdigest(), digest),
                        (result.spreadsheet_id, result.allowlist_sha256, result.policy_sha256))
                    for name in ('permit', 'send_once', 'complete'):
                        self.assertFalse(hasattr(result, name))
                    self.assertEqual(result, module.inspect_project_online_target(token, result))
                self.assertEqual([], list((project/'.tracker/generations').iterdir()))
            self.assertEqual(raw if fault != 'empty-list' else b'[]', listing.read_bytes())

    def test_actual_held_initial_policy_and_fixed_enumeration_create_only_binding(self):
        self.exercise()

    def test_disabled_current_policy_cannot_initialize_target(self):
        self.exercise('disabled')

    def test_empty_fixed_enumeration_cannot_initialize_target(self):
        self.exercise('empty-list')

    def test_initial_binding_rejects_same_byte_config_replacement_during_fixed_root_read(self):
        self.exercise('config-rebind')
