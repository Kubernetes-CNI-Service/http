"""Canonical test bootstrap identity: independent cached-fake refusal and real control.
SOURCE only; no device/transport/guard/worker/CLI invocation.
"""
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


class CanonicalBootstrapIdentityTests(unittest.TestCase):
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
