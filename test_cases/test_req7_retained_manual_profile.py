"""Independent manual boundaries for retained and pending originals."""
import importlib.util
from pathlib import Path
import unittest
import test_cases

ROOT = Path(test_cases.__file__).resolve().parents[1]
CANDIDATE = Path(__file__).resolve().parents[1]


class RetainedManualProfileTests(unittest.TestCase):
    def test_explicit_enrollment_manual_entry_is_fresh_only_and_not_a_worker_action(self):
        updater = self.load()
        profile = updater.script_profile(ROOT, 'monitor/issue_tracker_enrollment_journal.py')
        self.assertTrue(profile['direct'].startswith('仅显式人工'))
        self.assertIn('--initialize-project', profile['parameters'])
        self.assertIn('python3 -B -m monitor.issue_tracker_enrollment_journal', profile['syntax'])
        for word in ('普通 worker 永不自动初始化', '全新', '无冲突'):
            self.assertIn(word, profile['scenario'])
        for word in ('部分', '丢失', '冲突', 'UNKNOWN', '不修复', '不接管'):
            self.assertIn(word, profile['recovery'])
        self.assertIn('不启用自动发送', profile['success'])
        rendered = updater.render_script_reference(ROOT, ('monitor/issue_tracker_enrollment_journal.py',))
        self.assertIn('--initialize-project', rendered)

    def test_shared_fifo_catalog_order_and_project_scoped_sequences_are_not_new_authority(self):
        profile = self.load().script_profile(ROOT, 'monitor/issue_tracker_retained_inventory.py')
        for word in ('跨项目 per-key FIFO', 'catalog 顺序', '序号只按原项目', '不释放 FIFO'):
            self.assertIn(word, profile['outputs'])
        for word in ('原件', 'UNKNOWN', '不修复', 'HOLD'):
            self.assertIn(word, profile['recovery'])
        self.assertTrue(profile['direct'].startswith('否'))

    def test_original_cold_identity_is_checked_before_locking_any_replacement(self):
        profile = self.load().script_profile(ROOT, 'monitor/issue_tracker_unit_catalog.py')
        for word in ('flock 前', '原始身份', '不锁住替换件'):
            self.assertIn(word, profile['outputs'])

    def test_all_project_original_applied_join_stays_readonly_and_never_compares_local_sequences(self):
        profile = self.load().script_profile(ROOT, 'monitor/issue_tracker_retained_inventory.py')
        for word in ('跨项目原始 C6', '已计数', 'APPLIED', '不跨项目比较', '不释放 FIFO'):
            self.assertIn(word, profile['outputs'])
        for word in ('原始项目来源', '调用方路径'):
            self.assertIn(word, profile['inputs'])
        self.assertTrue(profile['direct'].startswith('否'))

    def test_origin_locator_is_not_foreign_c6_permission_and_cold_owner_is_nonblocking(self):
        profile = self.load().script_profile(ROOT, 'monitor/issue_tracker_unit_catalog.py')
        self.assertIn('原始项目来源', profile['inputs'])
        for word in ('历史 C6', '非阻塞', '不授予 NEW'):
            self.assertIn(word, profile['outputs'])
        for word in ('原件', '不修复', 'HOLD'):
            self.assertIn(word, profile['recovery'])

    def test_counted_wire_origin_originals_are_held_through_claim_not_a_send_permission(self):
        profile = self.load().script_profile(ROOT, 'monitor/issue_tracker_global_attempt_journal.py')
        self.assertIn('ORIGIN／WITNESS', profile['outputs'])
        self.assertIn('CLAIM', profile['outputs'])
        self.assertIn('没有', profile['outputs'])
        self.assertTrue(profile['direct'].startswith('否'))

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

    def test_unsent_disposition_requires_later_applied_and_preserves_safe_boundary(self):
        profile = self.load().script_profile(ROOT, 'monitor/issue_tracker_retained_inventory.py')
        for word in ('未尝试且更晚 APPLIED', '不释放 FIFO'):
            self.assertIn(word, profile['outputs'])
        for word in ('写前见证', '整对丢失', '不修复', 'UNKNOWN'):
            self.assertIn(word, profile['recovery'])
        self.assertTrue(profile['direct'].startswith('否'))
