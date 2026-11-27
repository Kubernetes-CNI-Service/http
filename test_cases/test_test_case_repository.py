#!/usr/bin/env python3
"""Contracts for the canonical, extensible test-case repository."""

from __future__ import annotations

import ast
import collections
import importlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
import uuid
from unittest import mock

from tools.project_contract import path_disposition


ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "test_cases"
LEGACY = ROOT / "tests"

BORROW_FIX_HINT = (
    "canonical discovery must collect every TestCase class exactly once, from its "
    "defining test module: do not bind another test module's TestCase class at module "
    "level (import, rename, star import or assignment) and do not subclass a collected "
    "TestCase that has test methods; bind the module instead "
    "(`from test_cases import test_x as X`, then `X.SomeTests`), import inside a "
    "function, or move shared helpers into a mixin without test methods. Every TestCase "
    "class defined at the top level of a discovered module must stay bound there."
)


class _OriginTaggingLoader(unittest.TestLoader):
    """Remember which module namespace produced each module-level suite."""

    def loadTestsFromModule(self, module, *args, pattern=None, **kws):
        suite = super().loadTestsFromModule(module, *args, pattern=pattern, **kws)
        suite._collected_by = module.__name__
        return suite


def discovery_occurrences(start_dir, top_level_dir, pattern="test_*.py"):
    """Repeat the canonical discover call with a private loader (never the shared one).

    Returns (loader errors, rows); one row per collected case instance:
    (collecting module, case class, class in the MRO that defines the method, case id).
    Only the top-level sys.path entry inserted here is removed again, by object identity;
    paths declared by imported test modules stay, as after any canonical discovery.
    """
    loader = _OriginTaggingLoader()
    top = os.path.abspath(str(top_level_dir))
    own_entry = None
    if top not in sys.path:
        # discover() then sees an equal entry and inserts nothing itself; only this exact
        # object is removed afterwards, never an equal path that a test module declared.
        own_entry = top
        sys.path.insert(0, own_entry)
    try:
        suite = loader.discover(str(start_dir), pattern=pattern, top_level_dir=top)
    finally:
        if own_entry is not None:
            for index, entry in enumerate(sys.path):
                if entry is own_entry:
                    del sys.path[index]
                    break
    rows = []

    def walk(node, collected_by):
        collected_by = getattr(node, "_collected_by", collected_by)
        for child in node:
            if isinstance(child, unittest.TestSuite):
                walk(child, collected_by)
            else:
                case_class = type(child)
                method = getattr(child, "_testMethodName", "")
                owner = next(
                    (klass for klass in case_class.__mro__ if method in vars(klass)),
                    case_class,
                )
                rows.append((collected_by, case_class, owner, child.id()))

    walk(suite, None)
    return list(loader.errors), rows


_FAILED_IMPORT_PREFIX = "unittest.loader._FailedTest."


def split_import_failures(rows):
    """Split discovery rows into module-collected cases, modules whose import failed and
    any other case that no module collected.

    A failed import is a unittest `_FailedTest` placeholder that the same discovery
    already reports as its own ERROR case (for example a module that needs the private
    fixture input); such a module cannot be checked for repeats here.
    """
    checked, failed, unattributed = [], [], []
    for row in rows:
        collected_by, case_class, _owner, case_id = row
        if collected_by is not None:
            checked.append(row)
        elif case_class.__name__ == "_FailedTest" and case_id.startswith(_FAILED_IMPORT_PREFIX):
            failed.append(case_id[len(_FAILED_IMPORT_PREFIX):])
        else:
            unattributed.append(case_id)
    return checked, sorted(failed), sorted(unattributed)


def _qualified(klass):
    return f"{klass.__module__}.{klass.__qualname__}"


def borrowed_collections(rows):
    """(collecting module, defining class) -> occurrences collected outside the definer."""
    return dict(collections.Counter(
        (collected_by, _qualified(case_class))
        for collected_by, case_class, _owner, _case_id in rows
        if collected_by != case_class.__module__
    ))


def repeated_case_classes(rows):
    """class path -> extra occurrences of an already collected case id."""
    occurrences = collections.Counter(case_id for *_prefix, case_id in rows)
    return dict(collections.Counter(
        case_id.rsplit(".", 1)[0]
        for case_id, count in occurrences.items() for _extra in range(count - 1)
    ))


def inherited_collected_methods(rows):
    """(subclass, owner) -> test methods a subclass re-runs from another collected class."""
    collected = {case_class for _by, case_class, _owner, _case_id in rows}
    return dict(collections.Counter(
        (_qualified(case_class), _qualified(owner))
        for _by, case_class, owner, _case_id in rows
        if owner is not case_class and owner in collected
    ))


def uncollected_definitions(rows, module_files, package):
    """Top-level class definitions of discovered modules that discovery never runs there.

    Reads each module's source independently of the loader (AST) and reports
    `module.Class` for (a) a TestCase class with test methods that its own module does
    not collect, and (b) a class statement with its own test methods whose module-level
    name no longer refers to that class (rebound or deleted after definition).
    """
    collected = {(collected_by, case_class) for collected_by, case_class, *_rest in rows}
    names_loader = unittest.TestLoader()
    missing = []
    for path in module_files:
        module_name = f"{package}.{Path(path).stem}"
        module = sys.modules.get(module_name)
        tree = ast.parse(Path(path).read_bytes(), filename=str(path))
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            own_tests = any(
                isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                and item.name.startswith(names_loader.testMethodPrefix)
                for item in node.body
            )
            bound = vars(module).get(node.name) if module is not None else None
            if not (
                isinstance(bound, type)
                and bound.__module__ == module_name
                and bound.__qualname__ == node.name
            ):
                if own_tests:
                    missing.append(f"{module_name}.{node.name}")
                continue
            if (
                issubclass(bound, unittest.TestCase)
                and names_loader.getTestCaseNames(bound)
                and (module_name, bound) not in collected
            ):
                missing.append(f"{module_name}.{node.name}")
    return sorted(missing)


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
        # The owner's CableTracker reference project (tools/cabletracker, owner 2026-10-23) is refreshed by
        # the owner, so only its disposition is pinned, never its file list (as in
        # test_reference_only_path_disposition): its test files may be present, each reference-only below.
        lldpq_reference = [path for path in outside if path.startswith("tools/cabletracker/")]
        self.assertEqual(expected_outside, sorted(path for path in outside if path not in lldpq_reference))
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
        with mock.patch.object(sys, "path", [str(ROOT / "tools"), *sys.path]), \
                mock.patch.dict(sys.modules, clear=False):
            sys.modules.pop("project_pointer", None)
            sys.modules[spec.name] = contract
            try:
                try:
                    spec.loader.exec_module(contract)
                except ModuleNotFoundError as error:
                    if error.name != "project_pointer":
                        raise
                    self.fail("the actual deployment contract must load its declared same-source pointer dependency")
            finally:
                sys.modules.pop(spec.name, None)
            self.assertEqual(
                (ROOT / "tools/project_pointer.py").resolve(),
                Path(contract._project_pointer.__file__).resolve(),
            )
        self.assertIsNotNone(
            contract.transfer_exclude_reason("test_cases/test_example.py")
        )
        self.assertIn("test_cases/", contract.rsync_excludes())

    def test_canonical_discovery_collects_each_case_once_in_its_defining_module(self):
        errors, rows = discovery_occurrences(CASES, ROOT)
        checked, unimportable, unattributed = split_import_failures(rows)
        # Every loader error must be one of the import failures, which this same discovery
        # already turns into ERROR cases; any other error stays visible here.
        self.assertEqual(len(unimportable), len(errors), errors)
        self.assertGreater(len(checked), 0)
        importable = [
            path for path in sorted(CASES.glob("test_*.py"))
            if f"test_cases.{path.stem}" not in unimportable
        ]
        self.assertEqual(
            {"borrowed": {}, "repeated": {}, "inherited": {}, "uncollected": [],
             "unattributed": []},
            {
                "borrowed": borrowed_collections(checked),
                "repeated": repeated_case_classes(checked),
                "inherited": inherited_collected_methods(checked),
                "uncollected": uncollected_definitions(checked, importable, "test_cases"),
                "unattributed": unattributed,
            },
            f"{BORROW_FIX_HINT} [not importable here, reported as their own ERROR cases "
            f"and not checked: {unimportable}]",
        )

    def test_discovery_origin_detector_flags_rebinding_repeat_subclass_and_lost_forms(self):
        # Synthetic files use case_*.py, never test_*.py: an interrupted run with an in-tree
        # TMPDIR must not leave files that the canonical-directory scan would report.
        package = "discovery_origin_" + uuid.uuid4().hex
        declared = f"/nonexistent/{package}/module-declared-path"
        files = {
            "__init__.py": "",
            "case_origin.py": (
                "import sys\n"
                "import unittest\n"
                f"sys.path.append({declared!r})\n"
                "class OriginTests(unittest.TestCase):\n"
                "    def test_one(self): pass\n"
                "    def test_two(self): pass\n"
                "class FixtureBase(unittest.TestCase):\n"
                "    def helper(self): return 1\n"
                "class SharedChecks:\n"
                "    def test_shared(self): pass\n"
            ),
            "case_reexport.py": f"from {package}.case_origin import OriginTests\n",
            "case_renamed.py": f"from {package}.case_origin import OriginTests as Borrowed\n",
            "case_star.py": f"from {package}.case_origin import *\n",
            "case_assigned.py": (
                f"from {package} import case_origin as ORIGIN\nCOPY = ORIGIN.OriginTests\n"
            ),
            "case_self_alias.py": (
                "import unittest\n"
                "class LocalTests(unittest.TestCase):\n"
                "    def test_local(self): pass\n"
                "AGAIN = LocalTests\n"
            ),
            "case_subclassed.py": (
                f"from {package} import case_origin as ORIGIN\n"
                "class Again(ORIGIN.OriginTests):\n"
                "    pass\n"
            ),
            "case_module_alias.py": (
                "import unittest\n"
                f"from {package} import case_origin as ORIGIN\n"
                "class UsesFixture(unittest.TestCase):\n"
                "    def test_uses(self): ORIGIN.OriginTests('test_one')\n"
            ),
            "case_function_local.py": (
                "import unittest\n"
                "class UsesLocal(unittest.TestCase):\n"
                "    def test_local_import(self):\n"
                f"        from {package}.case_origin import OriginTests\n"
                "        OriginTests('test_one')\n"
            ),
            "case_fixture_base.py": f"from {package}.case_origin import FixtureBase\n",
            "case_mixin.py": (
                "import unittest\n"
                f"from {package} import case_origin as ORIGIN\n"
                "class MixedTests(ORIGIN.SharedChecks, unittest.TestCase):\n"
                "    pass\n"
                "class ExtendsBase(ORIGIN.FixtureBase):\n"
                "    def test_extends(self): pass\n"
            ),
            "case_rebound.py": (
                "import unittest\n"
                "class Hidden(unittest.TestCase):\n"
                "    def test_hidden(self): pass\n"
                "Hidden = None\n"
                "class Removed(unittest.TestCase):\n"
                "    def test_removed(self): pass\n"
                "del Removed\n"
                "class Kept(unittest.TestCase):\n"
                "    def test_kept(self): pass\n"
            ),
            "case_broken.py": "raise ImportError('synthetic module that cannot be imported')\n",
        }
        self.addCleanup(self._forget_package, package)
        self.addCleanup(self._forget_path, declared)
        with tempfile.TemporaryDirectory(prefix="discovery-origin-") as directory:
            top = Path(directory).resolve()
            root = top / package
            root.mkdir()
            for name, text in files.items():
                (root / name).write_text(text, encoding="utf-8")
            errors, rows = discovery_occurrences(root, top, pattern="case_*.py")
            self.assertNotIn(str(top), sys.path)
            checked, unimportable, unattributed = split_import_failures(rows)
            uncollected = uncollected_definitions(
                checked, sorted(root.glob("case_*.py")), package,
            )
        self.assertIn(declared, sys.path)
        origin = f"{package}.case_origin.OriginTests"
        self.assertEqual(1, len(errors))
        self.assertIn(f"{package}.case_broken", errors[0])
        self.assertEqual([f"{package}.case_broken"], unimportable)
        self.assertEqual([], unattributed)
        self.assertEqual(len(rows) - 1, len(checked))
        rows = checked
        self.assertEqual({
            (f"{package}.case_reexport", origin): 2,
            (f"{package}.case_renamed", origin): 2,
            (f"{package}.case_star", origin): 2,
            (f"{package}.case_assigned", origin): 2,
        }, borrowed_collections(rows))
        self.assertEqual({
            origin: 8,
            f"{package}.case_self_alias.LocalTests": 1,
        }, repeated_case_classes(rows))
        self.assertEqual({
            (f"{package}.case_subclassed.Again", origin): 2,
        }, inherited_collected_methods(rows))
        self.assertEqual([
            f"{package}.case_rebound.Hidden",
            f"{package}.case_rebound.Removed",
        ], uncollected)
        self.assertIn(
            f"{package}.case_rebound.Kept.test_kept", {row[3] for row in rows},
        )

    @staticmethod
    def _forget_package(package):
        for name in [n for n in sys.modules if n == package or n.startswith(package + ".")]:
            sys.modules.pop(name, None)
        importlib.invalidate_caches()

    @staticmethod
    def _forget_path(declared):
        sys.path[:] = [entry for entry in sys.path if entry != declared]


class Version314RegistrationTests(unittest.TestCase):
    """r521 §5.1/5.2/9.5 and the accepted package specs: mapping, not product revalidation."""

    # Formal public ancestor; its manifest is byte-identical to the private synthesis base.
    BASE = "50ad1700c5e5675a06c413aa699c7c0e72803289"
    INITIAL = "infiniband/bringup/xdr-initial-setup/initial-setup.py"
    DIRECT = {
        "initial_setup_jump_sessions_direct": ([INITIAL], ["test_initial_setup_jump_sessions"]),
        "initial_setup_jump_gate_direct": ([INITIAL], ["test_initial_setup_jump_gate"]),
        "initial_setup_ipv4_readiness_direct": ([INITIAL, "tools/login_path.py"], ["test_initial_setup_ipv4_readiness"]),
        "login_path_direct": (["tools/login_path.py"], ["test_login_path"]),
        "initial_setup_host_key_refresh_direct": ([INITIAL], ["test_initial_setup_host_key_refresh"]),
        "helper_scripts_direct": (["*/helper-*"], ["test_all_script_entrypoints"]),
    }
    APPEND_DIRECT = {
        "ibsw225_entry_render_component_direct": ["test_ibsw_upgrade_layout_independence"],
        "ibsw_v2_entry_direct": ["test_ibsw_upgrade_entry_runtime"],
        "fleet_engine_direct": ["test_ibsw_upgrade_entry_runtime", "test_fleet_canary_routes"],
        "ibsw_v2_device_direct": ["test_ibsw_upgrade_entry_runtime", "test_ibsw_upgrade_connection_drops",
                                  "test_fleet_canary_routes", "test_troot_checkscript_env_control"],
        "fleet_ssh_direct": ["test_ibsw_upgrade_connection_drops"],
    }
    WORKFLOWS = {
        "initial_setup_jump_sessions_handoff": (["DAY0-Prepare/01-a-setup.py", INITIAL],
                                                ["test_initial_setup_jump_sessions"]),
        "initial_setup_jump_multiplex_and_unreachable": (
            [INITIAL, "ztp/config/cumulus/template/90-c2-generate_configs.py"],
            ["test_initial_setup_jump_unreachable_workflow"]),
        "initial_setup_host_key_refresh": (
            ["ztp/config_sync_authority.py", INITIAL, "tools/login_path.py",
             "tools/hostname_ranges.py", "tools/device_identity.py"],
            ["test_initial_setup_host_key_refresh_workflow"]),
        "helper_scripts_with_initial_setup": (["*/helper-*", INITIAL], ["test_all_script_entrypoints"]),
        "ibsw_upgrade_project_inventory": (
            ["infiniband/bringup/xdr-upgrade/upgrade2.py", "tools/inventory_subset.py",
             "tools/device_identity.py", "tools/project_contract.py"],
            ["test_ibsw_upgrade_project_inventory_workflow"]),
        "operator_identity_sealed_environment_transport": (
            ["tools/operator_identity.py", "tools/credentials_fd.py"], ["test_operator_identity"]),
    }
    APPEND_WORKFLOWS = {
        "ibsw_v2_upgrade_flow": ["test_ibsw_upgrade_layout_independence_workflow",
                                "test_ibsw_upgrade_connection_drops_workflow",
                                "test_ibsw_upgrade_canary_routes_workflow",
                                "test_ibsw_upgrade_runtime_lock_workflow",
                                "test_troot_checkscript_env_control"],
        "ibsw_v2_same_kernel_guard": ["test_ibsw_upgrade_runtime_lock_workflow"],
    }
    DEPLOYMENT = ["test_initial_setup_jump_sessions", "test_initial_setup_jump_gate",
                  "test_initial_setup_jump_unreachable_workflow", "test_initial_setup_ipv4_readiness",
                  "test_login_path", "test_initial_setup_host_key_refresh",
                  "test_initial_setup_host_key_refresh_workflow"]
    FLEET = ["test_ibsw_upgrade_layout_independence", "test_ibsw_upgrade_layout_independence_workflow",
             "test_ibsw_upgrade_entry_runtime", "test_ibsw_upgrade_project_inventory_workflow",
             "test_ibsw_upgrade_runtime_lock_workflow", "test_ibsw_upgrade_connection_drops",
             "test_ibsw_upgrade_connection_drops_workflow", "test_fleet_canary_routes",
             "test_ibsw_upgrade_canary_routes_workflow", "test_troot_checkscript_env_control"]
    LANES = {
        # A6 independently reviewed canonical rows + v3.1.3 timing weights;
        # retain all five keys so the original alphabetical-order checks stay active.
        "w0": [],
        "w1": [name for name in FLEET if name != "test_troot_checkscript_env_control"],
        "w2": [],
        "w3": [name for name in DEPLOYMENT if name != "test_initial_setup_jump_sessions"]
              + ["test_project_pointer_contract", "test_project_pointer_entry_workflow"],
        "w4": ["test_troot_checkscript_env_control"],
        # v3.1.5 R611 moves this one timing-sensitive module; exact uniqueness stays.
        "wq": ["test_initial_setup_jump_sessions"],
    }

    def setUp(self):
        self.manifest = json.loads((CASES / "script_test_manifest.json").read_text(encoding="utf-8"))
        self.plan = json.loads((CASES / "full_shard_plan.json").read_text(encoding="utf-8"))

    def table(self, name):
        rows = self.manifest[name]
        self.assertEqual(len(rows), len({row["id"] for row in rows}), "registration IDs must be unique")
        return {row["id"]: row for row in rows}

    @staticmethod
    def names(short_names):
        return ["test_cases." + name for name in short_names]

    def test_new_production_canonical_paths_and_helper_exception_are_registered(self):
        # Approved r521 :1252; AGENTS helper exception; filesystem is an independent canonical oracle.
        for path in ("tools/login_path.py", "infiniband/bringup/xdr-initial-setup/helper-prepare-eth-jump.sh"):
            with self.subTest(path=path):
                self.assertEqual(path, self.manifest["scripts"].get(path))
                self.assertTrue((ROOT / path).is_file())
                self.assertEqual(path, (ROOT / path).resolve(strict=True).relative_to(ROOT.resolve()).as_posix())
        index = subprocess.check_output(["git", "-C", str(ROOT), "ls-files", "-s"], text=True)
        for line in index.splitlines():
            metadata, path = line.split("\t", 1)
            if metadata.split()[0] != "120000" or Path(path).suffix not in {".py", ".sh"}:
                continue
            if path_disposition(path) != "production":
                continue
            with self.subTest(release_alias=path):
                canonical = (ROOT / path).resolve(strict=True).relative_to(ROOT.resolve()).as_posix()
                self.assertEqual(canonical, self.manifest["scripts"].get(path))

    def test_required_direct_rules_cover_actual_paths(self):
        # r521 :1253/:1256, plus accepted RV92 test-carrier-only additive mapping.
        rows = self.table("test_rules")
        for identity, (paths, tests) in self.DIRECT.items():
            with self.subTest(rule=identity):
                entry = rows.get(identity, {})
                self.assertTrue(set(paths) <= set(entry.get("paths", [])), "required direct paths missing")
                self.assertTrue(set(self.names(tests)) <= set(entry.get("tests", [])), "required direct tests missing")
        for identity, tests in self.APPEND_DIRECT.items():
            with self.subTest(existing_rule=identity):
                self.assertTrue(set(self.names(tests)) <= set(rows.get(identity, {}).get("tests", [])))

    def test_workflow_members_retain_full_real_producer_consumer_union(self):
        # r521 :1254/:1257/:1258 and original WP3 authority path, never replaced by narrower WP5 list.
        rows = self.table("workflows")
        for identity, (members, tests) in self.WORKFLOWS.items():
            with self.subTest(workflow=identity):
                entry = rows.get(identity, {})
                self.assertTrue(set(members) <= set(entry.get("members", [])), "real producer/consumer member missing")
                self.assertTrue(set(self.names(tests)) <= set(entry.get("tests", [])), "real workflow module missing")
        for identity, tests in self.APPEND_WORKFLOWS.items():
            with self.subTest(existing_workflow=identity):
                self.assertTrue(set(self.names(tests)) <= set(rows.get(identity, {}).get("tests", [])))
        self.assertIn("tools/credentials_fd.py", rows["initial_setup_operator_reexec"]["members"])
        dependency_members = rows["deps_table_to_cron_image_and_code_copies"]["members"]
        self.assertTrue({"infiniband/bringup/xdr-upgrade/upgrade2.py", "tools/fleet_ssh.py"} <= set(dependency_members))

    def test_original_entries_are_retained_without_canonical_or_support_changes(self):
        # r521 :1259 and each accepted package spec explicitly retain original entries, including v1 driver.
        raw = subprocess.check_output(["git", "-C", str(ROOT), "show", self.BASE + ":test_cases/script_test_manifest.json"])
        original = json.loads(raw)
        for path, canonical in original["scripts"].items():
            with self.subTest(original_script=path):
                self.assertEqual(canonical, self.manifest["scripts"].get(path))
        # v3.1.5 P050 (r757 §5.1, WP9-SUPPORT-01): keep the original ordered
        # lists exactly, with only this approved helper and its literal rule,
        # then (v3.1.6 A.5) only the three NS source layers listed below.
        # The fourteen original consumers plus the approved WP6/WP8 workflows
        # are independent of the manifest being checked.
        support = "test_cases/initial_setup_jump_fixture.py"
        p050_consumers = [
            "test_cases.test_ibsw225_managed_outer_guard_workflow",
            "test_cases.test_initial_setup_bringup_results_workflow",
            "test_cases.test_initial_setup_credentials_fd_workflow",
            "test_cases.test_initial_setup_host_key_refresh_workflow",
            "test_cases.test_initial_setup_jump_sessions",
            "test_cases.test_initial_setup_offline_main",
            "test_cases.test_initial_setup_oob_spine_main",
            "test_cases.test_initial_setup_operator_reexec",
            "test_cases.test_initial_setup_operator_reexec_workflow",
            "test_cases.test_initial_setup_project_names_workflow",
            "test_cases.test_initial_setup_replace_workflow",
            "test_cases.test_initial_setup_strict_stage_skeleton",
            "test_cases.test_initial_setup_summary_output",
            "test_cases.test_initial_setup_target_credentials_workflow",
            "test_cases.test_initial_setup_worker_queue",
            "test_cases.test_req10b_services_keys_workflow",
        ]
        # v3.1.6 A.5: the NS1/NS2/NS3 exact DATA inverse layers (http dev accepted, NS1 pending 2 /
        # NS3 pending 1 after NS2 pending 3; agentNS1/2/3-manifest-spec.json) each add one tracked
        # support path and its literal rule, appended after P050 in spec file-name order.
        v316_ns_support = [
            "test_cases/ns1_monitor_stop_source_layer.py",
            "test_cases/ns2_load_report_source_layer.py",
            "test_cases/ns3_load_report_source_layer.py",
        ]
        v316_ns_rules = [
            {
                "paths": ["test_cases/ns1_monitor_stop_source_layer.py"],
                "tests": [
                    "test_cases.test_monitor_writer_quiesce_workflow",
                    "test_cases.test_h_graph_local_scope_memo",
                ],
            },
            {
                "paths": ["test_cases/ns2_load_report_source_layer.py"],
                "tests": [
                    "test_cases.test_monitor_writer_quiesce_workflow",
                    "test_cases.test_h_graph_local_scope_memo",
                ],
            },
            {
                "paths": ["test_cases/ns3_load_report_source_layer.py"],
                "tests": [
                    "test_cases.test_monitor_writer_quiesce_workflow",
                    "test_cases.test_h_graph_local_scope_memo",
                ],
            },
        ]
        self.assertEqual(original["tracked_support"] + [support] + v316_ns_support, self.manifest["tracked_support"])
        self.assertEqual(
            original["path_rules"] + [{"paths": [support], "tests": p050_consumers}] + v316_ns_rules,
            self.manifest["path_rules"],
        )
        for name in ("test_rules", "workflows", "test_suites"):
            current = self.table(name)
            for before in original[name]:
                with self.subTest(table=name, entry=before["id"]):
                    self.assertIn(before["id"], current)
                    after = current[before["id"]]
                    for field, value in before.items():
                        if field in {"tests", "members"}:
                            self.assertEqual(value, after[field][:len(value)], "old ordered entries must remain")
                        else:
                            self.assertEqual(value, after[field])

    def test_all_version_modules_belong_their_approved_suites(self):
        # r521 :1260 supplies the independent literal 16; RV92 adds only its accepted test-control module.
        rows = self.table("test_suites")
        for identity, tests in (("deployment-runtime", self.DEPLOYMENT), ("fleet-upgrade-v2", self.FLEET)):
            self.assertTrue(set(self.names(tests)) <= set(rows[identity]["tests"]))
            for name in tests:
                with self.subTest(module=name):
                    self.assertTrue((CASES / (name + ".py")).is_file())

    def test_new_modules_have_exactly_one_supported_lane(self):
        # r521 :1272–1275; RV92 follows its original device_scripts consumer's w1, not quiet phase.
        assignments = collections.defaultdict(list)
        for lane in [*self.plan["phase_a"], self.plan["phase_b"]]:
            for unit in lane["units"]:
                if isinstance(unit, str):
                    assignments[unit].append(lane["lane"])
        for lane, tests in self.LANES.items():
            for name in self.names(tests):
                with self.subTest(module=name):
                    self.assertEqual([lane], assignments[name])
        # Existing COMMON A.6 :1717 says to insert while retaining lane-internal alphabetical order.
        for lane in self.plan["phase_a"]:
            if lane["lane"] in self.LANES:
                self.assertEqual(sorted(lane["units"]), lane["units"], "free lane units must remain sorted")


if __name__ == "__main__":
    unittest.main()
