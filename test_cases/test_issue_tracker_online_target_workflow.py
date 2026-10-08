"""Actual project policy -> exact C-2 target binding; fake-only, no send."""

import copy
import importlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools.project_contract import normalize_issue_tracker_policy
from test_cases.test_issue_tracker_online_target import TARGET, OTHER, document


class OnlineTargetPolicyWorkflowTests(unittest.TestCase):
    def setUp(self):
        name = "monitor.issue_tracker_online_target"
        self.assertIsNotNone(importlib.util.find_spec(name), "C-2 target loader is missing")
        self.module = importlib.import_module(name)

    def test_actual_locked_project_and_fixed_fd_allowlist_reject_revocation_and_changed_cadence(self):
        self.assertTrue(hasattr(self.module, 'inspect_project_online_target'),
            'locked real config and fixed held-FD target enumeration are missing')
        from monitor import issue_tracker_credential_shape as private
        from monitor.issue_tracker_local_commit import create_local_commit_store, writer_owner
        with tempfile.TemporaryDirectory(prefix='req7-current-target-') as directory:
            project = Path(directory).resolve(); publication = project/'publication'
            publication.mkdir(mode=0o700); create_local_commit_store(project, publication)
            authority = project/'owned-root'; private_dir = authority/'var/lib/http-ztp-container/service-account'
            private_dir.mkdir(parents=True, mode=0o700)
            listing = private_dir/'issue-tracker-spreadsheet-whitelist.json'
            listing.write_bytes(json.dumps([TARGET, OTHER]).encode()); listing.chmod(0o600)
            config = project/'01-global.yaml'; config.write_bytes(json.dumps(document(cycles=3)).encode())
            config.chmod(0o644)
            expected = self.module.bind_online_target(document(cycles=3),
                self.module.freeze_target_allowlist(listing.read_bytes()))
            from test_cases.test_req7_spreadsheet_owner import scoped_fixture
            # Only private-input and new config reader OS boundaries synthesize
            # root identity. Original project owner/native flock stay real.
            with scoped_fixture(authority, private), scoped_fixture(authority, self.module), writer_owner(project, publication) as token:
                self.assertEqual(expected, self.module.inspect_project_online_target(token, expected))
                saved_config, saved_listing = config.read_bytes(), listing.read_bytes()
                for changed in (document(OTHER, cycles=3), document(cycles=4), document(status='disabled'),
                                {'schema_version': 2}, document(cycles=True)):
                    config.write_bytes(json.dumps(changed).encode())
                    with self.assertRaises(self.module.OnlineTargetHold):
                        self.module.inspect_project_online_target(token, expected)
                    self.assertEqual(saved_listing, listing.read_bytes())
                config.write_bytes(saved_config)
                for changed in (b'[]', json.dumps([OTHER]).encode(), saved_listing+b' '):
                    listing.write_bytes(changed)
                    with self.assertRaises(self.module.OnlineTargetHold):
                        self.module.inspect_project_online_target(token, expected)
                    self.assertEqual(saved_config, config.read_bytes())
                listing.write_bytes(saved_listing)
                self.assertEqual(expected, self.module.inspect_project_online_target(token, expected))
                actual_read = self.module.os.read
                for fault in ('mutate', 'same_bytes_new_inode', 'short_read'):
                    config_reads = []
                    def drift_config(fd, limit):
                        config_reads.append(fd); data = actual_read(fd, limit)
                        if fault == 'mutate': config.write_bytes(saved_config+b'\n')
                        if fault == 'same_bytes_new_inode':
                            config.rename(project/'preserved-global.yaml')
                            config.write_bytes(saved_config); config.chmod(0o644)
                        return data[:-1] if fault == 'short_read' else data
                    with self.subTest(fault=fault), mock.patch.object(self.module.os, 'read', side_effect=drift_config):
                        with self.assertRaises(self.module.OnlineTargetHold) as caught:
                            self.module.inspect_project_online_target(token, expected)
                    self.assertEqual(1, len(config_reads)); self.assertIsNone(caught.exception.__context__)
                    with self.assertRaises(OSError): os.fstat(config_reads[0])
                    if fault == 'same_bytes_new_inode':
                        self.assertEqual(saved_config, config.read_bytes())
                        config.unlink(); (project/'preserved-global.yaml').rename(config)
                    if fault == 'mutate':
                        self.assertEqual(saved_config+b'\n', config.read_bytes())
                        config.write_bytes(saved_config)  # undo this owned injection only
                for fault in ('symlink', 'hardlink', 'writable', 'fifo', 'oversize', 'missing'):
                    if fault == 'symlink':
                        config.rename(project/'preserved-global.yaml'); config.symlink_to(project/'preserved-global.yaml')
                    elif fault == 'hardlink': os.link(config, project/'preserved-global.yaml')
                    elif fault == 'writable': config.chmod(0o666)
                    else:
                        config.rename(project/'preserved-global.yaml')
                        if fault == 'fifo': os.mkfifo(config, 0o600)
                        if fault == 'oversize': config.write_bytes(b' '*(1024*1024+1))
                    try:
                        with self.subTest(fault=fault), mock.patch.object(self.module.os, 'read') as reading:
                            with self.assertRaises(self.module.OnlineTargetHold):
                                self.module.inspect_project_online_target(token, expected)
                            reading.assert_not_called()
                    finally:
                        if fault == 'hardlink': (project/'preserved-global.yaml').unlink()
                        elif fault == 'writable': config.chmod(0o644)
                        else:
                            if fault != 'missing': config.unlink()
                            (project/'preserved-global.yaml').rename(config)
                    self.assertEqual(saved_config, config.read_bytes()); self.assertEqual(saved_listing, listing.read_bytes())
                private_read = private.read_target_allowlist
                def drift_during_fixed_allowlist():
                    result = private_read(); config.write_bytes(saved_config+b'\n'); return result
                with mock.patch.object(private, 'read_target_allowlist', side_effect=drift_during_fixed_allowlist):
                    with self.assertRaises(self.module.OnlineTargetHold):
                        self.module.inspect_project_online_target(token, expected)
                self.assertEqual(saved_config+b'\n', config.read_bytes()); config.write_bytes(saved_config)
                for name in ('permit', 'send_once', 'complete'): self.assertFalse(hasattr(expected, name))
            with scoped_fixture(authority, private), scoped_fixture(authority, self.module):
                with self.assertRaises(self.module.OnlineTargetHold):
                    self.module.inspect_project_online_target(token, expected)
            self.assertEqual([], list((project/'.tracker/generations').iterdir()))

    def test_manifest_maps_live_locked_config_fixed_fd_and_real_count_workflow(self):
        root = Path(__file__).resolve().parents[1]
        manifest = json.loads((root/'test_cases/script_test_manifest.json').read_text())
        required = {'monitor/issue_tracker_online_target.py', 'monitor/issue_tracker_credential_shape.py',
            'monitor/issue_tracker_local_commit.py', 'tools/project_contract.py'}
        self.assertTrue(any(required <= set(item['members']) and
            'test_cases.test_issue_tracker_online_target_workflow' in item['tests'] for item in manifest['workflows']))
        self.assertTrue(any(item['id'] == 'req7_protected_original_receipt_business_count' and
            required | {'monitor/issue_tracker_global_attempt_journal.py'} <= set(item['members'])
            for item in manifest['workflows']))

    def test_real_policy_validator_is_consumed_on_every_target_revalidation(self):
        config = document(cycles=3)
        before = copy.deepcopy(config)
        listing = self.module.freeze_target_allowlist(json.dumps([TARGET, OTHER]).encode())
        with mock.patch("tools.project_contract.normalize_issue_tracker_policy",
                        wraps=normalize_issue_tracker_policy) as validator:
            bound = self.module.bind_online_target(config, listing)
            self.assertEqual(TARGET, bound.spreadsheet_id)
            self.assertEqual(bound, self.module.bind_online_target(config, listing, expected=bound))
            config["common"]["mgmt"]["issue-tracker"]["spreadsheet_id"] = OTHER
            with self.assertRaises(self.module.OnlineTargetHold) as caught:
                self.module.bind_online_target(config, listing, expected=bound)
        self.assertEqual("stale_target_binding", caught.exception.reason)
        self.assertEqual(3, validator.call_count)
        config["common"]["mgmt"]["issue-tracker"]["spreadsheet_id"] = TARGET
        self.assertEqual(before, config)

    def test_enabled_schema_cannot_create_a_target_enumeration(self):
        config = document()
        self.assertEqual(TARGET, normalize_issue_tracker_policy(config)["spreadsheet_id"])
        for raw in (b"[]", json.dumps([OTHER]).encode()):
            listing = self.module.freeze_target_allowlist(raw)
            with self.assertRaises(self.module.OnlineTargetHold):
                self.module.bind_online_target(config, listing)
        config["schema_version"] = 1
        listing = self.module.freeze_target_allowlist(json.dumps([TARGET]).encode())
        with self.assertRaises(self.module.OnlineTargetHold) as caught:
            self.module.bind_online_target(config, listing)
        self.assertEqual("invalid_online_policy", caught.exception.reason)


if __name__ == "__main__":
    unittest.main()
