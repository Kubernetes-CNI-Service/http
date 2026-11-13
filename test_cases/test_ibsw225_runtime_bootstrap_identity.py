"""Canonical test bootstrap identity: independent cached-fake refusal and real control.
SOURCE only; no device/transport/guard/worker/CLI invocation.
"""
import ast
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest import mock

from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
MODULES = (
    ("project_contract", "project_contract.py"),
    ("_package_common", "_package_common.py"),
    ("ssh_key_preparation", "ssh_key_preparation.py"),
    ("ibsw_upgrade_contract", "ibsw_upgrade_contract.py"),
    ("ibsw_upgrade_inputs", "ibsw_upgrade_inputs.py"),
    ("ibsw_upgrade_driver", "ibsw_upgrade_driver.py"),
    ("ibsw_upgrade_schedule", "ibsw_upgrade_schedule.py"),
    ("ibsw_upgrade_component", "ibsw_upgrade_component.py"),
    ("ibsw_upgrade_observer", "ibsw_upgrade_observer.py"),
    ("ibsw_upgrade_executor", "ibsw_upgrade_executor.py"),
    ("ibsw_upgrade_access", "ibsw_upgrade_access.py"),
    ("ibsw_upgrade_pipeline", "ibsw_upgrade_pipeline.py"),
)
ENTRY_NAME = "_ibsw225_canonical_cli_source"
ENTRY = ROOT / "infiniband/bringup/xdr-upgrade/upgrade.py"
SUPPORT = ROOT / "test_cases/ibsw225_fixture_support/runtime_source_support.py"


def source_helper(name):
    return load_script(name, SUPPORT)


class CurrentNonnativeCopySourceTests(unittest.TestCase):
    def test_current_copied_runner_scripts_register_pointer_without_removing_core(self):
        sites = (
            ("test_runner_preflight.py", "PreflightFixture", "setUp"),
            ("test_full_shard_workflow.py", "ShardFixture", "build"),
        )
        core = {"tools/project_contract.py", "tools/sync-code.py",
                "infra/docker/activate.py", "tools/_package_common.py"}
        for filename, class_name, method_name in sites:
            with self.subTest(file=filename, scope=class_name + "." + method_name):
                tree = ast.parse((ROOT / "test_cases" / filename).read_text(encoding="utf-8"))
                classes = [node for node in tree.body if isinstance(node, ast.ClassDef)
                           and node.name == class_name]
                self.assertEqual(len(classes), 1)
                methods = [node for node in classes[0].body if isinstance(node, ast.FunctionDef)
                           and node.name == method_name]
                self.assertEqual(len(methods), 1)
                assignments = [node for node in methods[0].body if isinstance(node, ast.Assign)
                               and any(isinstance(target, ast.Name) and target.id == "scripts"
                                       for target in node.targets)]
                self.assertEqual(len(assignments), 1)
                self.assertIsInstance(assignments[0].value, ast.DictComp)
                declared = {node.value for node in ast.walk(assignments[0].value)
                            if isinstance(node, ast.Constant) and isinstance(node.value, str)}
                self.assertTrue(core.issubset(declared), "all original four source mappings remain")
                self.assertEqual(declared, core | {"tools/project_pointer.py"},
                                 "copied current source requires its ordinary manifest mapping")

    def test_current_copy_sites_explicitly_declare_the_pointer_source(self):
        # Independent current dependency declaration only. This does not import
        # the large fixture modules or claim their real workflows have run.
        sites = (
            ("test_initial_setup_operator_reexec_workflow.py", "TOOLS", "project_pointer"),
            ("test_load_collection_worker_workflow.py", "WORKER_FILES", "tools/project_pointer.py"),
            ("test_continuous_interval_handoff_workflow.py", "ContinuousIntervalHandoffWorkflowTests.make_layout", "tools/project_pointer.py"),
            ("test_collection_cycle_handoff_workflow.py", "CollectionCycleHandoffWorkflowTests.make_layout", "tools/project_pointer.py"),
            ("test_cron_operator_identity.py", "stage_tree", "project_pointer.py"),
            ("test_collection_lock_owner.py", "CollectionLockOwnerTests.test_operator_cron_sh_takes_lock_after_worker_released_it", "project_pointer.py"),
            ("test_monitor_stack_review.py", "SwitchWorkerProcessLifecycleTests.test_supervisor_sigterm_workflow_stops_detached_collector_tree", "tools/project_pointer.py"),
            ("test_vm_validation_runner.py", "actual_deployment_contract_fixture", "project_pointer.py"),
            ("test_load_release_transaction.py", "ReleaseTransactionTests._prepare_h04_schema_v1_collision_generator", "tools/project_pointer.py"),
            ("test_mlag_evpn_generation.py", "prepare_schema_v1_collision_generator", "tools/project_pointer.py"),
            ("test_docker_management_ssh_key.py", "DockerManagementSshKeyWorkflowTests.test_real_deploy_entrypoint_drives_locked_helper_then_11_load", "tools/project_pointer.py"),
            ("test_req19_infra_log_contract.py", "RV3DeployInfraWithoutActiveProjectTests.setUp", "tools/project_pointer.py"),
            ("test_req19_infra_log_contract.py", "RV5CheckInfraWithoutActiveProjectTests.setUp", "tools/project_pointer.py"),
            ("test_documentation_catalog.py", "ManualPF2CurrentCliWorkflowTests.INVENTORY", "tools/project_pointer.py"),
            ("test_runner_preflight.py", "PreflightFixture.setUp", "tools/project_pointer.py"),
            ("test_full_shard_workflow.py", "ShardFixture.build", "tools/project_pointer.py"),
            ("test_switch_status.py", "IsolationTest.test_the_project_is_found_through_the_activate_project_pointer", "tools/project_pointer.py"),
        )
        self.assertEqual(len({name for name, _scope, _literal in sites}), 16)
        self.assertEqual(len(sites), 17)
        for filename, scope, literal in sites:
            with self.subTest(file=filename, scope=scope):
                node = ast.parse((ROOT / "test_cases" / filename).read_text(encoding="utf-8"))
                for part in scope.split("."):
                    matches = [child for child in node.body
                               if (isinstance(child, (ast.ClassDef, ast.FunctionDef)) and child.name == part)
                               or (isinstance(child, ast.Assign) and any(
                                   isinstance(target, ast.Name) and target.id == part for target in child.targets))]
                    self.assertEqual(len(matches), 1, "the declared actual copy scope must remain unambiguous")
                    node = matches[0]
                declared = {item.value for item in ast.walk(node)
                            if isinstance(item, ast.Constant) and isinstance(item.value, str)}
                self.assertIn(literal, declared, "current copy source dependency must be explicit in its actual scope")


class CanonicalBootstrapIdentityTests(unittest.TestCase):
    def test_current_registry_adds_one_pointer_without_changing_core_rows(self):
        helper = source_helper("ibsw_bootstrap_current_registry_source")
        pointer = ("project_pointer", "project_pointer.py")
        self.assertEqual(tuple(row for row in helper.REGISTRY if row != pointer), MODULES)
        self.assertEqual(helper.REGISTRY.count(pointer), 1,
                         "the current runtime must declare its one same-source pointer dependency")
        self.assertEqual(len(helper.REGISTRY), 13)

    def test_current_pointer_none_and_namespace_cache_are_refused_before_any_import(self):
        helper = source_helper("ibsw_bootstrap_pointer_negative_source")
        path = ROOT / "tools/project_pointer.py"
        for shape, fake in (("none", None), ("namespace", SimpleNamespace(__file__=str(path)))):
            with self.subTest(shape=shape):
                attempts = []
                def no_import_before_refusal(import_name, *args, **kwargs):
                    attempts.append(import_name)
                    raise RuntimeError("independent pointer preflight must precede imports")
                caught = None
                with mock.patch.dict(sys.modules), mock.patch.object(sys, "path", list(sys.path)):
                    for name, _leaf in MODULES:
                        sys.modules.pop(name, None)
                    sys.modules.pop(ENTRY_NAME, None)
                    sys.modules["project_pointer"] = fake
                    with mock.patch.object(helper.importlib, "import_module", side_effect=no_import_before_refusal):
                        try:
                            helper.support(self)
                        except BaseException as error:
                            caught = error
                    self.assertIn("project_pointer", sys.modules)
                    self.assertIs(sys.modules["project_pointer"], fake)
                self.assertIs(type(caught), AssertionError,
                              "foreign pointer cache must fail in strict preflight")
                self.assertEqual(attempts, [], "even the first runtime import must not be attempted")

    def test_foreign_same_path_cached_objects_are_rejected_before_any_runtime_import(self):
        helper = source_helper("ibsw_bootstrap_negative_source")
        locations = [(name, ROOT / "tools" / leaf) for name, leaf in MODULES]
        locations.append((ENTRY_NAME, ENTRY))
        for name, path in locations:
            for shape in ("namespace", "module"):
                with self.subTest(name=name, shape=shape):
                    fake = (SimpleNamespace(__file__=str(path)) if shape == "namespace"
                            else ModuleType(name))
                    if shape == "module":
                        fake.__file__ = str(path)
                    attempts = []
                    def no_import_before_refusal(import_name, *args, **kwargs):
                        attempts.append(import_name)
                        raise RuntimeError("independent unexpected runtime import before cached-fake refusal")
                    caught = None
                    with mock.patch.dict(sys.modules, {name: fake}), mock.patch.object(
                            helper.importlib, "import_module", side_effect=no_import_before_refusal):
                        try:
                            helper.support(self)
                        except BaseException as error:
                            caught = error
                        self.assertIs(sys.modules.get(name), fake, "cannot overwrite the supplied foreign object")
                    self.assertIs(type(caught), AssertionError,
                                  "same-path fake must be rejected by bootstrap preflight, not delegated")
                    self.assertEqual(attempts, [], "refusal must precede every genuine module import")

    def test_genuine_fixed_modules_and_entry_remain_reusable_without_business_execution(self):
        helper = source_helper("ibsw_bootstrap_genuine_source")
        first = helper.support(self)
        actual = {name: sys.modules[name] for name, _leaf in MODULES}
        for name, leaf in MODULES:
            module = actual[name]
            self.assertIs(type(module), ModuleType)
            self.assertEqual(Path(module.__file__).resolve(), ROOT / "tools" / leaf)
            self.assertIsNotNone(module.__spec__)
            self.assertEqual(Path(module.__spec__.origin).resolve(), ROOT / "tools" / leaf)
        self.assertIs(type(first.app), ModuleType)
        self.assertIs(first.app, sys.modules[ENTRY_NAME])
        self.assertEqual(Path(first.app.__file__).resolve(), ENTRY)
        self.assertIs(first.app._fixed_driver.__globals__, vars(first.app))
        self.assertEqual(Path(first.app._fixed_driver.__code__.co_filename), ENTRY)
        again = helper.support(self)
        self.assertIs(again.app, first.app)
        self.assertIs(again.driver, actual["ibsw_upgrade_driver"])
        self.assertIs(again.observer, actual["ibsw_upgrade_observer"])
        self.assertIs(again.contract, actual["ibsw_upgrade_contract"])
        self.assertTrue(all(sys.modules[name] is module for name, module in actual.items()))
