"""Independent source-only tools fixture boundaries, bytes and permissions."""
from __future__ import annotations

import ast
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SUPPORT = ROOT / "test_cases/source_tools_fixture.py"
EXPECTED_RUNTIME_PATHS = frozenset({
    "lldp-analyze-tool/99-output-p2p",
    "lldp-analyze-tool/99-output-monitor",
    "ibdiagnet-analyze-tool/99-output-p2p",
})


class SourceToolsFixtureContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="source-tools-contract-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        (self.source / "tools/sub").mkdir(parents=True)
        (self.source / "tools/a.py").write_bytes(b"literal source\n")
        (self.source / "tools/sub/b.txt").write_bytes(b"literal nested source\n")
        (self.source / "tools/a.py").chmod(0o751)
        (self.source / "tools/sub/b.txt").chmod(0o640)

    def helper(self):
        self.assertTrue(SUPPORT.is_file(), "source-only fixture helper must exist")
        spec = importlib.util.spec_from_file_location("independent_source_tools_fixture", SUPPORT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_literal_runtime_paths_also_match_declared_production_outputs(self):
        helper = self.helper()
        self.assertEqual(EXPECTED_RUNTIME_PATHS, helper.OPERATOR_RUNTIME_LINKS)
        tree = ast.parse((ROOT / "tools/project_contract.py").read_bytes())
        assignment = next(n for n in tree.body if isinstance(n, ast.Assign)
                          and any(isinstance(t, ast.Name) and t.id == "ANALYZER_OUTPUT_SPECS"
                                  for t in n.targets))
        declared = frozenset(path[len("tools/"):] for path, _ in ast.literal_eval(assignment.value)
                             if path.startswith("tools/"))
        self.assertEqual(EXPECTED_RUNTIME_PATHS, declared)

    def test_regular_tree_keeps_original_copytree_bytes_modes_and_mtimes(self):
        helper = self.helper()
        baseline = self.root / "baseline"
        destination = self.root / "candidate"
        shutil.copytree(self.source / "tools", baseline)
        result = helper.copy_source_tools(destination, source_root=self.source)
        self.assertEqual(destination, Path(result))
        self.assertEqual({"a.py", "sub", "sub/b.txt"},
                         {p.relative_to(destination).as_posix() for p in destination.rglob("*")})
        for relative, data, mode in (("a.py", b"literal source\n", 0o751),
                                     ("sub/b.txt", b"literal nested source\n", 0o640)):
            with self.subTest(path=relative):
                copied = destination / relative
                self.assertEqual(data, copied.read_bytes())
                self.assertEqual(mode, stat.S_IMODE(copied.stat().st_mode))
                self.assertEqual((baseline / relative).stat().st_mtime_ns, copied.stat().st_mtime_ns)

    def test_three_runtime_links_are_excluded_without_following_their_targets(self):
        helper = self.helper()
        outside = self.root / "synthetic-runtime"
        outside.mkdir()
        (outside / "not-source.txt").write_bytes(b"synthetic runtime must not be copied")
        for number, relative in enumerate(sorted(EXPECTED_RUNTIME_PATHS)):
            path = self.source / "tools" / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.symlink_to(outside if number == 0 else (self.root / "missing" if number == 1 else path))
        destination = self.root / "copied"
        helper.copy_source_tools(destination, source_root=self.source)
        self.assertEqual({"a.py", "sub/b.txt"},
                         {p.relative_to(destination).as_posix() for p in destination.rglob("*") if p.is_file()})
        for relative in EXPECTED_RUNTIME_PATHS:
            with self.subTest(path=relative):
                self.assertFalse(os.path.lexists(destination / relative))

    def test_reserved_runtime_paths_are_excluded_for_real_files_and_directories_too(self):
        helper = self.helper()
        for number, relative in enumerate(sorted(EXPECTED_RUNTIME_PATHS)):
            path = self.source / "tools" / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if number == 0:
                path.write_bytes(b"runtime marker")
            else:
                path.mkdir()
                (path / "runtime.txt").write_bytes(b"runtime output")
        destination = self.root / "copied"
        helper.copy_source_tools(destination, source_root=self.source)
        for relative in EXPECTED_RUNTIME_PATHS:
            with self.subTest(path=relative):
                self.assertFalse(os.path.lexists(destination / relative))

    def test_unexpected_resolving_and_dangling_links_fail_closed(self):
        helper = self.helper()
        for kind in ("file", "directory", "dangling"):
            with self.subTest(kind=kind):
                link = self.source / "tools/sub/unexpected"
                target = {"file": self.source / "tools/a.py", "directory": self.source / "tools/sub",
                          "dangling": self.root / "missing"}[kind]
                link.symlink_to(target)
                try:
                    with self.assertRaisesRegex(AssertionError, "sub/unexpected"):
                        helper.copy_source_tools(self.root / ("copy-" + kind), source_root=self.source)
                finally:
                    link.unlink()

    def test_symlinked_tools_root_is_not_followed(self):
        helper = self.helper()
        alias = self.root / "alias"
        alias.mkdir()
        (alias / "tools").symlink_to(self.source / "tools")
        destination = self.root / "copy"
        with self.assertRaisesRegex(AssertionError, "source tools root"):
            helper.copy_source_tools(destination, source_root=alias)
        self.assertFalse(destination.exists())

    def test_existing_destination_retains_original_failure_and_is_not_overwritten(self):
        helper = self.helper()
        destination = self.root / "copy"
        destination.mkdir()
        marker = destination / "keep.txt"
        marker.write_bytes(b"independent existing destination")
        with self.assertRaises(FileExistsError):
            helper.copy_source_tools(destination, source_root=self.source)
        self.assertEqual(b"independent existing destination", marker.read_bytes())

    def test_exact_two_source_copy_sites_use_the_shared_helper(self):
        # DEV v3.1.0 (owner 2026-11-06 set the DEV count, then 12: gib 10, tlrt 2): AP-b removed the
        # setup-switch WAL tests holding 10 of them (owner 11-03 Q6), leaving one each; DEV never
        # had test_setup_switch_plan_contract (the WAL is not merged).
        expected = {"test_generation_input_binding_workflow.py": 1,
                    "test_load_release_transaction.py": 1}
        for filename, count in expected.items():
            with self.subTest(module=filename):
                tree = ast.parse((ROOT / "test_cases" / filename).read_bytes())
                calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                         and isinstance(n.func, ast.Name) and n.func.id == "copy_source_tools"]
                self.assertEqual(count, len(calls))
                self.assertTrue(all(len(n.args) == 1 and not n.keywords for n in calls))
                self.assertFalse(any(isinstance(n, ast.Call) and ast.unparse(n.func) == "shutil.copytree"
                                     and n.args and ast.unparse(n.args[0]) == "ROOT / 'tools'"
                                     for n in ast.walk(tree)))

    def test_manifest_tracks_support_and_all_three_existing_workflows(self):
        manifest = json.loads((ROOT / "test_cases/script_test_manifest.json").read_bytes())
        self.assertIn("test_cases/source_tools_fixture.py", manifest["tracked_support"])
        rules = [r for r in manifest["path_rules"] if "test_cases/source_tools_fixture.py" in r["paths"]]
        self.assertEqual(1, len(rules))
        # DEV: no test_setup_switch_plan_contract (no setup-switch WAL), and gib never re-exported
        # a test_v2_generation_flow class in DEV's history, so DEV's FORMER_REEXPORT_EDGES (G1)
        # has no gib edge and the rule needs no test_v2_generation_flow.
        self.assertEqual({"test_cases.test_source_tools_fixture_contract",
                          "test_cases.test_generation_input_binding_workflow",
                          "test_cases.test_load_release_transaction"}, set(rules[0]["tests"]))
        self.assertEqual(["repository-governance"], [s["id"] for s in manifest["test_suites"]
                         if "test_cases.test_source_tools_fixture_contract" in s["tests"]])


if __name__ == "__main__":
    unittest.main()
