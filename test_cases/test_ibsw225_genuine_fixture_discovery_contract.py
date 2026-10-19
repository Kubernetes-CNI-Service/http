"""Independent fixed genuine fixture bootstrap and normal-module discovery only.

Loading/discovery does not execute any original device or workflow test method.
"""
import importlib
from importlib.machinery import SourceFileLoader
from pathlib import Path
import sys
from types import ModuleType
import unittest

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / "test_cases/ibsw225_fixture_support"
FIXTURES = (
    ("test_upgrade_cli", "_fixture_test_upgrade_cli", "WorkflowTests"),
    ("test_known_hosts", "_fixture_test_known_hosts", "HostPinTests"),
    ("test_manual_execution", "_fixture_test_manual_execution", "MemorySFTP"),
    ("test_nvos_observations", "_fixture_test_nvos_observations", "ObservationParserTests"),
    ("test_three_component_workflow", "_fixture_test_three_component_workflow", "ThreeComponentWorkflowTests"),
    ("test_access_recovery", "_fixture_test_access_recovery", "AccessWorkflowTests"),
    ("test_grouped_summary", "_fixture_test_grouped_summary", "GroupedSummaryTests"),
    ("test_runtime_budgets", "_fixture_test_runtime_budgets", "ReaderDirectTests"),
    ("test_os_alternatives", "_fixture_test_os_alternatives", "AlternativeStageDirectTests"),
    ("test_input_isolation", "_fixture_test_input_isolation", "InventoryIsolationTests"),
    ("test_health_upgrade_gate", "_fixture_test_health_upgrade_gate", "HealthGateDirectTests"),
    ("test_compact_summary", "_fixture_test_compact_summary", "CompactSummaryDirectTests"),
    ("test_os_download_telemetry", "_fixture_test_os_download_telemetry", "DownloadDirectTests"),
    ("test_standalone_links", "_fixture_test_standalone_links", "StandaloneLinkTests"),
)
NORMAL_COUNTS = (
    ("test_cases.test_ibsw225_device_globs", 15),
    ("test_cases.test_ibsw225_input_isolation", 19),
    ("test_cases.test_ibsw225_os_alternatives", 28),
    ("test_cases.test_ibsw225_three_component_workflow", 18),
    ("test_cases.test_ibsw225_known_hosts", 17),
    ("test_cases.test_ibsw225_access_recovery", 43),
    ("test_cases.test_ibsw225_os_canary_coverage", 26),
    ("test_cases.test_ibsw225_cooperative_pipeline", 14),
)


def test_ids(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from test_ids(item)
        else:
            yield item.id()


class GenuineFixtureDiscoveryContractTests(unittest.TestCase):
    def genuine_module(self, name, path):
        module = sys.modules[name]
        self.assertIs(type(module), ModuleType)
        self.assertEqual(Path(module.__file__).resolve(), path)
        self.assertEqual(module.__spec__.name, name)
        self.assertEqual(Path(module.__spec__.origin).resolve(), path)
        self.assertIs(type(module.__spec__.loader), SourceFileLoader)
        self.assertIs(module.__loader__, module.__spec__.loader)
        self.assertEqual(module.__loader__.path, str(path))
        return module

    def test_literal_fixed_fixture_registry_contains_fourteen_real_source_paths(self):
        registry = importlib.import_module("test_cases.ibsw225_fixture_support.fixed_fixture_registry")
        self.genuine_module(registry.__name__, HERE / "fixed_fixture_registry.py")
        self.assertEqual(registry.REGISTRY, tuple((legacy, leaf) for legacy, leaf, _api in FIXTURES))
        for _legacy, leaf, _api in FIXTURES:
            path = HERE / (leaf + ".py")
            with self.subTest(source=leaf):
                self.assertTrue(path.is_file())
                self.assertFalse(path.is_symlink())
                self.assertTrue(path.read_bytes(), "fixed real fixture cannot be an empty stub")

    def test_real_fixed_fixture_bootstrap_reuse_and_normal_eight_module_discovery(self):
        support = importlib.import_module("test_cases.ibsw225_fixture_support.runtime_source_support")
        runtime = support.support(self)
        registry = importlib.import_module("test_cases.ibsw225_fixture_support.fixed_fixture_registry")
        loaded = registry.install_fixed_fixtures()
        self.assertEqual(list(loaded), [legacy for legacy, _leaf, _api in FIXTURES])
        for legacy, leaf, api in FIXTURES:
            canonical = "test_cases.ibsw225_fixture_support." + leaf
            module = self.genuine_module(canonical, HERE / (leaf + ".py"))
            self.assertIs(loaded[legacy], module)
            self.assertIs(sys.modules[legacy], module)
            self.assertIs(registry.OWNED[canonical], module)
            self.assertEqual(getattr(module, api).__module__, canonical)
        again = registry.install_fixed_fixtures()
        self.assertTrue(all(again[name] is module for name, module in loaded.items()))
        all_ids = []
        for name, count in NORMAL_COUNTS:
            suite = unittest.defaultTestLoader.loadTestsFromName(name)
            ids = list(test_ids(suite))
            self.assertEqual(suite.countTestCases(), count)
            self.assertEqual(len(ids), len(set(ids)))
            self.assertTrue(all(value.startswith(name + ".") for value in ids))
            module = self.genuine_module(name, ROOT / (name.replace(".", "/") + ".py"))
            self.assertIs(module._ibsw225_runtime.app, runtime.app)
            all_ids.extend(ids)
        self.assertEqual(len(all_ids), 180)
        self.assertEqual(len(set(all_ids)), 180)
        self.assertFalse(any("._fixture_" in name for name in all_ids))
        self.assertTrue(all(sys.modules[name] is module for name, module in loaded.items()))
