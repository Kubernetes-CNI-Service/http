#!/usr/bin/env python3
"""Contracts for the canonical, extensible test-case repository."""

from __future__ import annotations

import ast
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest

from tools.project_contract import path_disposition


ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "test_cases"
LEGACY = ROOT / "tests"


def repository_test_paths(root: Path) -> list[Path]:
    """Find tests in this checkout, never in an embedded Git checkout."""
    discovered = []
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        directories[:] = [
            name for name in directories
            if name not in {".git", "__pycache__", "99-output-eth",
                            "99-output-ib_nvl", "99-output-p2p",
                            "99-output-ztp"}
            and not os.path.lexists(current_path / name / ".git")
        ]
        for name in files:
            if name.startswith("test_") and name.endswith(".py"):
                discovered.append(current_path / name)
    return discovered


class TestCaseRepositoryTests(unittest.TestCase):
    # Independent literal fixture roles, not copied from generated/source AST.
    _FIRST_STAGE_PATCH_ROLES = (
        ('state_owner', 'current_k', 'diagnosed_k', False),
        ('remote', '_hold_current_project_online_inputs', 'diagnosed_first_inputs', False),
        ('remote', '_hold_current_project_online_original_inputs', 'diagnosed_worker_inputs', False),
        ('global_api', '_receipted_original_facts', 'diagnosed_receipted_facts', False),
        ('global_api', 'record_global_attempt_intent', 'diagnosed_count', False),
        ('global_api', '_hold_count_claim_project_c6', 'observe_c6_borrow', False),
        ('allocation', '_sync_completed_source_leaf_originals', 'observe_c19_sync', False),
        ('remote', 'inspect_completion_evidence', 'reject_recursive_source_c19', False),
        ('catalog', 'hold_pending_project_c6_units', 'reject_duplicate_source_c6', False),
        ('catalog', '_hold_project_c6_from_origins', 'reject_duplicate_source_leaf_c6', False),
        ('global_api', '_hold_continuous_owned_attempt_wire', 'diagnosed_count_wire', False),
        ('launcher', 'require_current_owned_project_read', 'diagnosed_read_guard', False),
        ('launcher.OwnedProjectSheetsReadUnit', 'read_once', 'read_first_with_prefetch', True),
        ('launcher.OwnedProjectTemplateReadCohort', 'read_once', 'read_first_cohort_with_prefetch', True),
        ('mutation', '_send_counted_original_once', 'send', False),
    )

    def _stage_l_first_patch_scope(self):
        source = CASES / 'test_issue_tracker_stage_l_consumer_workflow.py'
        tree = ast.parse(source.read_text(encoding='utf-8'), filename=str(source))
        classes = [node for node in tree.body if isinstance(node, ast.ClassDef)
            and node.name == 'ProdStageLConsumerWorkflowTests']
        self.assertEqual(1, len(classes))
        functions = [node for node in classes[0].body if isinstance(node, ast.FunctionDef)
            and node.name == '_compile_current_issued_switch_after_actual_archive']
        self.assertEqual(1, len(functions))
        candidates = []
        for node in ast.walk(functions[0]):
            if not isinstance(node, ast.With):
                continue
            calls = [item.context_expr for item in node.items
                if isinstance(item.context_expr, ast.Call)
                and ast.unparse(item.context_expr.func) == 'mock.patch.object']
            calls += [statement.value.args[0] for statement in node.body
                if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call)
                and ast.unparse(statement.value.func) == 'first_patches.enter_context'
                and len(statement.value.args) == 1]
            if len(calls) == 15 and isinstance(calls[0], ast.Call) and len(calls[0].args) == 2:
                if (ast.unparse(calls[0].args[0]), ast.literal_eval(calls[0].args[1])) == ('state_owner', 'current_k'):
                    candidates.append((node, calls))
        self.assertEqual(1, len(candidates), 'one fixed FIRST patch scope')
        return candidates[0]

    def test_stage_l_workflow_module_compiles_without_static_patch_block_overflow(self):
        source = CASES / 'test_issue_tracker_stage_l_consumer_workflow.py'
        failure = None
        try:
            compile(source.read_bytes(), str(source), 'exec')
        except SyntaxError as error:
            failure = error.msg
        self.assertIsNone(failure, 'compile the whole current module without importing its workflows')

    def test_stage_l_first_fixture_has_fifteen_literal_patches_in_one_lexical_stack(self):
        node, calls = self._stage_l_first_patch_scope()
        actual = []
        for call in calls:
            self.assertEqual('mock.patch.object', ast.unparse(call.func))
            self.assertEqual(2, len(call.args))
            keywords = tuple((keyword.arg, ast.unparse(keyword.value)) for keyword in call.keywords)
            actual.append((ast.unparse(call.args[0]), ast.literal_eval(call.args[1]), keywords))
        expected = [(owner, name, ((('autospec', 'True'),) if autospec else ()) + (('side_effect', callback),))
            for owner, name, callback, autospec in self._FIRST_STAGE_PATCH_ROLES]
        self.assertEqual(expected, actual)
        self.assertEqual(1, len(node.items))
        self.assertEqual('ExitStack()', ast.unparse(node.items[0].context_expr))
        self.assertEqual('first_patches', ast.unparse(node.items[0].optional_vars))
        self.assertEqual(15, len(calls))
        self.assertIsInstance(node.body[15], ast.Try, 'original dispatch/exception body follows all entries')

    def test_stage_l_first_fixture_patch_headers_preserve_reverse_exit_and_partial_rollback(self):
        # Execute only actual patch headers over local literal objects. No
        # Stage-L module import, real owner, Count, SDK, TLS or workflow call.
        import copy
        from contextlib import ExitStack
        from types import SimpleNamespace
        from unittest import mock
        node, _calls = self._stage_l_first_patch_scope()
        def exercise(failed_entry=None, interrupt=False):
            events = []; originals = []; labels = {}
            namespace = {'ExitStack': ExitStack}
            for owner, name, callback, _autospec in self._FIRST_STAGE_PATCH_ROLES:
                parts = owner.split('.')
                target = namespace.setdefault(parts[0], SimpleNamespace())
                for part in parts[1:]:
                    if not hasattr(target, part):
                        setattr(target, part, SimpleNamespace())
                    target = getattr(target, part)
                def original(*args, **kwargs):
                    return None
                setattr(target, name, original)
                originals.append((target, name, original)); labels[id(target)] = owner
                namespace[callback] = lambda *args, **kwargs: None
            primary = KeyboardInterrupt('literal body')
            partial = ValueError('literal entry')
            class Patch:
                def __init__(self, actual, ordinal):
                    self.actual = actual; self.ordinal = ordinal
                def __enter__(self):
                    events.append(('enter', self.ordinal))
                    if self.ordinal == failed_entry:
                        raise partial
                    return self.actual.__enter__()
                def __exit__(self, *info):
                    events.append(('exit', self.ordinal))
                    return self.actual.__exit__(*info)
            ordinal = [0]
            def object_patch(target, name, **kwargs):
                ordinal[0] += 1
                expected_owner, expected_name, _callback, _autospec = self._FIRST_STAGE_PATCH_ROLES[ordinal[0] - 1]
                self.assertEqual((expected_owner, expected_name), (labels[id(target)], name))
                return Patch(mock.patch.object(target, name, **kwargs), ordinal[0])
            namespace['mock'] = SimpleNamespace(patch=SimpleNamespace(object=object_patch))
            def literal_body():
                events.append(('body', 0))
                for target, name, original in originals:
                    self.assertIsNot(getattr(target, name), original)
                if interrupt:
                    raise primary
            namespace['literal_body'] = literal_body
            header = copy.deepcopy(node)
            header.body = [statement for statement in header.body
                if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call)
                and ast.unparse(statement.value.func) == 'first_patches.enter_context'] if len(header.items) == 1 else []
            header.body.append(ast.Expr(value=ast.Call(func=ast.Name(id='literal_body', ctx=ast.Load()), args=[], keywords=[])))
            caught = None
            try:
                exec(compile(ast.fix_missing_locations(ast.Module(body=[header], type_ignores=[])),
                    '<literal-first-patch-headers>', 'exec'), namespace)
            except BaseException as error:
                caught = error
            # This is after the lexical header scope, matching the actual
            # fixture's subsequent assertions rather than its outer stack.
            for target, name, original in originals:
                self.assertIs(getattr(target, name), original)
            return events, caught, primary, partial
        events, caught, _, _ = exercise()
        self.assertIsNone(caught)
        self.assertEqual([('enter', i) for i in range(1, 16)] + [('body', 0)]
            + [('exit', i) for i in range(15, 0, -1)], events)
        events, caught, primary, _ = exercise(interrupt=True)
        self.assertIs(caught, primary)
        self.assertEqual([('exit', i) for i in range(15, 0, -1)], events[-15:])
        events, caught, _, partial = exercise(failed_entry=8)
        self.assertIs(caught, partial)
        self.assertEqual([('enter', i) for i in range(1, 9)] + [('exit', i) for i in range(7, 0, -1)], events)

    def test_canonical_directory_is_unique(self):
        self.assertTrue(CASES.is_dir())
        self.assertFalse(os.path.lexists(LEGACY))

    def test_all_repository_regressions_live_in_canonical_directory(self):
        discovered = repository_test_paths(ROOT)
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

    def test_embedded_checkout_is_excluded_but_main_tree_rogue_test_is_found(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            embedded = root / "vendor/other-checkout"
            embedded.mkdir(parents=True)
            (embedded / ".git").write_text("gitdir: elsewhere\n", encoding="ascii")
            (embedded / "test_foreign.py").write_text("", encoding="ascii")
            rogue = root / "vendor/test_rogue.py"
            rogue.write_text("", encoding="ascii")
            self.assertEqual([rogue], repository_test_paths(root))

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


if __name__ == "__main__":
    unittest.main()
