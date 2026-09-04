#!/usr/bin/env python3
"""Contracts for the canonical, extensible test-case repository."""

from __future__ import annotations

import ast
import importlib.util
import os
from pathlib import Path
import sys
import unittest


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
        self.assertEqual([], outside)
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


if __name__ == "__main__":
    unittest.main()
