#!/usr/bin/env python3
"""Contracts for the canonical, extensible test-case repository."""

from __future__ import annotations

import ast
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tools.project_contract import path_disposition


ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "test_cases"
LEGACY = ROOT / "tests"


class TestCaseRepositoryTests(unittest.TestCase):
    def test_canonical_directory_is_unique(self):
        self.assertTrue(CASES.is_dir())
        self.assertFalse(os.path.lexists(LEGACY))

    def test_all_repository_regressions_live_in_canonical_directory(self):
        discovered = []
        for current, directories, files in os.walk(ROOT, followlinks=False):
            current_path = Path(current)
            directories[:] = [
                name for name in directories
                if name not in {".git", "__pycache__", "99-output-eth",
                                "99-output-ib_nvl", "99-output-p2p",
                                "99-output-ztp"}
            ]
            for name in files:
                if name.startswith("test_") and name.endswith(".py"):
                    discovered.append(current_path / name)
        outside = [
            path.relative_to(ROOT).as_posix()
            for path in discovered
            if CASES not in path.parents
        ]
        reference_root = ROOT / "monitor/cabletracker-main"
        reference_tests = sorted((
            "monitor/cabletracker-main/tests/test_cvt_sum.py",
            "monitor/cabletracker-main/tests/test_offline_workflow.py",
        ))
        expected_outside = reference_tests if reference_root.is_dir() else []
        self.assertEqual(expected_outside, sorted(outside))
        for relative in outside:
            self.assertEqual("reference-only", path_disposition(relative))
        self.assertGreaterEqual(len(discovered), 20)

    def test_no_alias_or_persistent_symlink_can_duplicate_discovery(self):
        for alias in ("test", "tests", "test-case", "test-cases"):
            self.assertFalse(os.path.lexists(ROOT / alias), alias)
        links = [
            path.relative_to(ROOT).as_posix()
            for path in CASES.rglob("*") if path.is_symlink()
        ]
        self.assertEqual([], links)

    def test_every_test_module_is_reached_by_canonical_discovery(self):
        suite = unittest.defaultTestLoader.discover(
            str(CASES), pattern="test_*.py", top_level_dir=str(ROOT),
        )

        def case_ids(node):
            for child in node:
                if isinstance(child, unittest.TestSuite):
                    yield from case_ids(child)
                else:
                    yield child.id()

        loaded_modules = {
            case_id.rsplit(".", 2)[0] for case_id in case_ids(suite)
        }
        expected_modules = {
            f"test_cases.{path.stem}" for path in CASES.glob("test_*.py")
        }
        self.assertEqual(expected_modules, loaded_modules)

    def test_every_executable_case_has_a_module_purpose(self):
        missing = []
        for path in sorted(CASES.glob("test_*.py")):
            module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            if not ast.get_docstring(module):
                missing.append(path.name)
        self.assertEqual([], missing)

    def test_extension_contract_is_present(self):
        readme = (CASES / "README.md").read_text(encoding="utf-8")
        self.assertIn("CASE_TEMPLATE.md", readme)
        self.assertIn("REAL_ENVIRONMENT.md", readme)
        self.assertIn("CHANGE_AWARE_TESTING.md", readme)
        self.assertIn("run_related_tests.py --check", readme)
        self.assertIn("run_related_tests.py --all", readme)
        self.assertIn("run_related_tests.py --list-suites", readme)
        self.assertIn("run_related_tests.py --suite deployment-runtime", readme)
        self.assertIn("分类运行不会更新批准哈希", readme)
        self.assertIn("discover -s test_cases", readme)
        self.assertTrue((CASES / "CASE_TEMPLATE.md").is_file())
        self.assertTrue((CASES / "REAL_ENVIRONMENT.md").is_file())
        self.assertTrue((CASES / "CHANGE_AWARE_TESTING.md").is_file())
        self.assertTrue((CASES / "run_related_tests.py").is_file())
        self.assertTrue((CASES / "script_test_manifest.json").is_file())

        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        self.assertIn("script_test_manifest.json", agents)
        self.assertIn("direct", agents)
        self.assertIn("workflow", agents)
        self.assertIn("REAL_ENVIRONMENT.md", agents)
        self.assertIn("run_related_tests.py --all", agents)
        self.assertIn("run_related_tests.py --check", agents)

    def test_req16_real_environment_card_records_owner_key_dispositions(self):
        real_environment = (CASES / "REAL_ENVIRONMENT.md").read_text(
            encoding="utf-8"
        )
        marker = "## TC-REAL-REQ16-GENERATION-REPORT-001"
        self.assertEqual(1, real_environment.count(marker))
        card = real_environment.split(marker, 1)[1].split("\n## ", 1)[0]
        self.assertIn("既有有效公钥与 HOME 不一致时拒绝", card)
        self.assertIn("原有公钥逐字节不动", card)
        self.assertIn("RSA-only 管理服务器 HOME 在 PRE 范围内 fail closed", card)
        self.assertIn("不读取 RSA 私钥", card)
        self.assertNotIn("A/B owner 事实选择", card)
        self.assertNotIn("RSA-only 私钥读取例外", card)

    def test_case_repository_is_never_deployed(self):
        contract_path = ROOT / "tools/project_contract.py"
        spec = importlib.util.spec_from_file_location(
            "test_case_project_contract", contract_path,
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        contract = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = contract
        try:
            spec.loader.exec_module(contract)
        finally:
            sys.modules.pop(spec.name, None)
        self.assertIsNotNone(
            contract.transfer_exclude_reason("test_cases/test_example.py")
        )
        self.assertIn("test_cases/", contract.rsync_excludes())


class HistoricalSFixtureLifecycleContracts(unittest.TestCase):
    def history_modules(self):
        from test_cases import test_public_s_phase_contract, test_public_s_phase_workflow
        return (test_public_s_phase_contract, test_public_s_phase_workflow)

    def test_direct_history_module_cleanup_removes_only_owned_root_and_resets_cache(self):
        for history in self.history_modules():
            with self.subTest(module=history.__name__):
                self.assert_owned_cleanup(history)

    def assert_owned_cleanup(self, history):
        with tempfile.TemporaryDirectory(prefix="history-owner-contract-") as directory:
            parent = Path(directory)
            sentinel = parent / "unrelated-sentinel"
            sentinel.write_bytes(b"independent unrelated bytes\n")
            owner = tempfile.TemporaryDirectory(prefix="owned-history-", dir=parent)
            checkout = Path(owner.name) / "checkout"
            checkout.mkdir()
            (checkout / "owned-sentinel").write_bytes(b"owned fixture\n")
            try:
                with mock.patch.object(history, "_S_HISTORY_TEMP", owner), \
                        mock.patch.object(history, "_S_HISTORY_CHECKOUT", checkout):
                    cleanup = getattr(history, "tearDownModule", None)
                    self.assertTrue(callable(cleanup), "history module must release its owned fixture at module end")
                    cleanup()
                    self.assertFalse(os.path.lexists(owner.name))
                    self.assertIsNone(history._S_HISTORY_TEMP)
                    self.assertIsNone(history._S_HISTORY_CHECKOUT)
                    cleanup()
                    self.assertEqual(b"independent unrelated bytes\n", sentinel.read_bytes())
            finally:
                owner.cleanup()

    def test_direct_history_module_cleanup_failure_remains_visible_with_owner_retained(self):
        for history in self.history_modules():
            with self.subTest(module=history.__name__):
                self.assert_cleanup_failure(history)

    def assert_cleanup_failure(self, history):
        owner = mock.Mock()
        owner.cleanup.side_effect = OSError("independent fixture cleanup refusal")
        checkout = Path("independent-owned-checkout")
        with mock.patch.object(history, "_S_HISTORY_TEMP", owner), \
                mock.patch.object(history, "_S_HISTORY_CHECKOUT", checkout):
            cleanup = getattr(history, "tearDownModule", None)
            self.assertTrue(callable(cleanup), "history cleanup failure must fail the module")
            with self.assertRaisesRegex(OSError, "independent fixture cleanup refusal"):
                cleanup()
            self.assertIs(owner, history._S_HISTORY_TEMP)
            self.assertEqual(checkout, history._S_HISTORY_CHECKOUT)

    def test_real_history_replays_then_canonical_scan_in_one_process_with_tree_local_tmpdir(self):
        ledger = ROOT / "test_cases/script_test_approved_hashes.json"
        before = ledger.read_bytes()
        child = '''
import unittest
from test_cases import test_public_s_phase_contract as history
from test_cases import test_public_s_phase_workflow as workflow
ids = [
    "test_cases.test_public_s_phase_contract.PublicSPhaseDirectTests.test_literal_inventory_and_current_reviewed_bytes_are_frozen",
    "test_cases.test_public_s_phase_contract.PublicSPhaseDirectTests.test_s_manifest_has_exact_forward_and_reverse_closure",
    "test_cases.test_public_s_phase_workflow.PublicSPhaseWorkflowTests.test_s_stage_delta_is_exact_and_excludes_deferred_families",
    "test_cases.test_test_case_repository.TestCaseRepositoryTests.test_all_repository_regressions_live_in_canonical_directory",
]
suite = unittest.defaultTestLoader.loadTestsFromNames(ids)
result = unittest.TextTestRunner(verbosity=2).run(suite)
cleared = all(module._S_HISTORY_TEMP is None and module._S_HISTORY_CHECKOUT is None
              for module in (history, workflow))
print("MODULE_HISTORY_CACHE_CLEARED=" + str(cleared))
raise SystemExit(0 if result.wasSuccessful() and cleared else 1)
'''
        area = ROOT / "outputs/test-diagnostics"
        area.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="history-canonical-workflow-", dir=area) as directory:
            env = dict(os.environ, TMPDIR=directory, PYTHONPYCACHEPREFIX=str(Path(directory) / "pyc"))
            result = subprocess.run([sys.executable, "-B", "-c", child], cwd=ROOT,
                                    env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, check=False, timeout=300)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertIn("MODULE_HISTORY_CACHE_CLEARED=True", result.stdout)
            self.assertIn("Ran 4 tests in", result.stderr)
            self.assertTrue(result.stderr.rstrip().endswith("OK"), result.stderr)
            self.assertEqual([], list(Path(directory).glob("http-s-direct-history-*")))
            self.assertEqual([], list(Path(directory).glob("http-s-workflow-history-*")))
        self.assertEqual(before, ledger.read_bytes())


if __name__ == "__main__":
    unittest.main()
