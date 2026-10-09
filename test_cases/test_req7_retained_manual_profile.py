"""Independent manual boundaries for retained and pending originals."""
import importlib.util
from pathlib import Path
import unittest
import test_cases

ROOT = Path(test_cases.__file__).resolve().parents[1]
CANDIDATE = Path(__file__).resolve().parents[1]


class RetainedManualProfileTests(unittest.TestCase):
    def load(self):
        private = CANDIDATE / 'tools/update-user-manual.py'
        source = private if private.is_file() else ROOT / 'tools/update-user-manual.py'
        spec = importlib.util.spec_from_file_location('owned_req7_manual_profile', source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_both_original_libraries_are_not_installed_or_operator_clis(self):
        updater = self.load()
        for name in ('retained_inventory', 'unit_catalog'):
            relative = 'monitor/issue_tracker_' + name + '.py'
            with self.subTest(path=relative):
                profile = updater.script_profile(ROOT, relative)
                self.assertTrue(profile['direct'].startswith('否'))
                for word in ('未安装', '未启用'):
                    self.assertIn(word, profile['environment'])
                self.assertIn('无独立 CLI', profile['parameters'])
                self.assertIn('不授予', profile['success'])
                self.assertNotIn('python3 -B ' + relative, profile['syntax'])
                self.assertNotIn('python3 -B ' + relative, profile['example'])

    def test_legacy_observation_does_not_claim_multiple_units_or_new_authority(self):
        profile = self.load().script_profile(ROOT, 'monitor/issue_tracker_retained_inventory.py')
        self.assertIn('单个', profile['scenario'])
        for word in ('原件', 'APPLIED', 'UNKNOWN', 'NEW'):
            self.assertIn(word, ' '.join(profile.values()))
        self.assertIn('不证明', profile['outputs'])

    def test_pending_storage_is_not_a_send_attempt_or_c6_settlement_proof(self):
        profile = self.load().script_profile(ROOT, 'monitor/issue_tracker_unit_catalog.py')
        for word in ('原件', '不计数', 'C6', 'APPLIED', 'NEW'):
            self.assertIn(word, ' '.join(profile.values()))
        for word in ('部分', 'HOLD', '不修复'):
            self.assertIn(word, profile['recovery'])

    def test_catalog_diagnostic_original_keys_do_not_claim_global_release_or_replace_legacy_contract(self):
        profile = self.load().script_profile(ROOT, 'monitor/issue_tracker_retained_inventory.py')
        self.assertIn('单个 legacy', profile['scenario'])
        self.assertIn('catalog', profile['scenario'])
        self.assertIn('所有 unit', profile['scenario'])
        self.assertIn('未尝试', profile['outputs'])
        for word in ('COMPLETE', 'APPLIED', '原件', '部分前缀'):
            self.assertIn(word, ' '.join(profile.values()))
        for word in ('global maximum', 'FIFO', 'G1', 'NEW'):
            self.assertIn(word, profile['outputs'])

    def test_project_key_fold_is_not_cross_project_sequence_or_new_authority(self):
        profile = self.load().script_profile(ROOT, 'monitor/issue_tracker_retained_inventory.py')
        self.assertIn('单项目逐 key 最大值', profile['outputs'])
        self.assertIn('不跨项目比较', profile['outputs'])
        for word in ('UNKNOWN', 'FIFO', 'G1', 'NEW'):
            self.assertIn(word, ' '.join(profile.values()))
