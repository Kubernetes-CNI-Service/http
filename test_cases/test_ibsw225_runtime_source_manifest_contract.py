"""Independent canonical IB runtime and manifest source contracts; SOURCE only.

Read/render is not upgrade execution. The snapshot micro-fixture calls the real
runner as a hash consumer, not the full test runner and never a ledger writer.
"""
import fnmatch
import hashlib
import importlib
import json
from pathlib import Path
import tempfile
import unittest

from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
ENTRY = "infiniband/bringup/xdr-upgrade/upgrade.py"
SHELLS = (
    "infiniband/bringup/xdr-upgrade/upgrade.sh",
    "infiniband/bringup/xdr-upgrade/upgrade-component.sh",
    "infiniband/bringup/xdr-upgrade/upgrade-owned-runner.sh",
)
PYTHON_RUNTIME = (ENTRY,) + tuple("tools/" + name for name in (
    "ibsw_upgrade_contract.py", "ibsw_upgrade_inputs.py", "ibsw_upgrade_schedule.py",
    "ibsw_upgrade_component.py", "ibsw_upgrade_driver.py", "ibsw_upgrade_executor.py",
    "ibsw_upgrade_observer.py", "ibsw_upgrade_access.py", "ibsw_upgrade_pipeline.py",
    "project_contract.py", "_package_common.py", "ssh_key_preparation.py",
))
GUARD = "tools/ib_bringup_runtime_guard.py"
REQUIREMENTS = "infiniband/bringup/xdr-upgrade/requirements.txt"
NORMAL_MODULES = (
    "test_cases.test_ibsw225_runtime_source_manifest_contract",
    "test_cases.test_ibsw225_ib_alias_derivation_workflow",
)
# Frozen approved 2.25 original bytes, not values copied from the tested tree.
# Composed entry/project/package/guard are intentionally NOT given flat hashes.
FROZEN_SHA256 = {
    "tools/ibsw_upgrade_contract.py": "eab213b06e6885eb7861cfb010e4863ae5008b6bf061afc508197a95d4d83088",
    "tools/ibsw_upgrade_inputs.py": "75c700e576b9fb6bd8ce5a117aa2f0c0f6e7ea96f9a1a12bc973ef814a13cbae",
    "tools/ibsw_upgrade_schedule.py": "547f957b99e7df2c8d1dfe682e501a37c31cf03e601f86564135d9bc3a287fb2",
    "tools/ibsw_upgrade_component.py": "106ddd7095e28503a355e9637dfb4fbd7fa151a2d4198e951590233da02ec45a",
    "tools/ibsw_upgrade_driver.py": "3c76f3bf02f2a41e2338bf78b38681dc5defb63a957d31155709de85f0eaffe2",
    "tools/ibsw_upgrade_executor.py": "d2b81d44d2a3a5b4682be705d3a43ed2a18e94097e8ccab6d7dd842306d373c9",
    "tools/ibsw_upgrade_observer.py": "46614501ad84e3d0d6b98fa83c9671df55431ee64e3e31901159152e5e67ece9",
    "tools/ibsw_upgrade_access.py": "aa05f8394ac390a0d0dd5313938cca6137b1c1e37dc1d5d8a83fec266de7d89f",
    "tools/ibsw_upgrade_pipeline.py": "559afde86615eb8a0d8ab518e05ffaae5da242ba0805bd5e64b9a2342ddd30ac",
    "tools/ssh_key_preparation.py": "16a383dfff78cfb9410db50d63ae4b25ad885021445ce8567c9a6d95f2a36352",
    SHELLS[0]: "0ddbbf01f920bb3f4d6dcd9406083c8ca407d8edba94aad49669b8bb36899e65",
    SHELLS[1]: "ad082ec6bbeafff9ab4921815b00a45769b65e14f1a211a1b34614df0fe3a635",
    SHELLS[2]: "cb9cc7d68fda9e24972e6335e58e5c6fa196e8d685532d949b78e290e654e1e2",
}
GLOBAL = """schema_version: 2
common:
  mgmt:
    http:
      status: enabled
      address: 192.0.2.254
      port: 8088
      http_root: /var/www/html
switches:
- ib:
    version: '25.03.1010'
    upgrade:
      packages:
        os:
          files:
          - file: nvos-amd64-25.02.8008.bin
          - file: nvos-amd64-25.03.1010.bin
"""


class CanonicalRuntimeManifestContractTests(unittest.TestCase):
    def test_literal_runtime_inventory_sources_have_direct_and_real_workflow_mapping(self):
        self.assertTrue(all((ROOT / name).is_file() and not (ROOT / name).is_symlink()
                            for name in PYTHON_RUNTIME + SHELLS + (GUARD,)),
                        "complete literal canonical runtime capability missing")
        manifest = json.loads((ROOT / "test_cases/script_test_manifest.json").read_text())
        self.assertEqual(len(PYTHON_RUNTIME), 13)
        self.assertEqual(len(SHELLS), 3)
        for relative in PYTHON_RUNTIME + SHELLS + (GUARD,):
            with self.subTest(relative=relative):
                path = ROOT / relative
                self.assertTrue(path.is_file() and not path.is_symlink(), "missing canonical runtime capability")
                self.assertEqual(manifest["scripts"].get(relative), relative)
                self.assertTrue(any(any(fnmatch.fnmatchcase(relative, p) for p in r["paths"])
                                    for r in manifest["test_rules"]), "direct mapping absent")
                flows = [r for r in manifest["workflows"]
                         if any(fnmatch.fnmatchcase(relative, p) for p in r["members"])]
                self.assertTrue(flows, "workflow mapping absent")
                for flow in flows:
                    targets = {target for name, target in manifest["scripts"].items()
                               if any(fnmatch.fnmatchcase(name, p) for p in flow["members"])}
                    self.assertGreaterEqual(len(targets), 2)
        for relative, expected in FROZEN_SHA256.items():
            with self.subTest(original=relative):
                self.assertEqual(hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(), expected)
        self.assertIn(REQUIREMENTS, manifest["tracked_support"])

    def test_normal_modules_and_complete_real_helper_files_are_explicitly_hash_bound(self):
        manifest = json.loads((ROOT / "test_cases/script_test_manifest.json").read_text())
        for name in NORMAL_MODULES:
            path = ROOT / (name.replace(".", "/") + ".py")
            self.assertTrue(path.is_file() and not path.is_symlink(), "normal top-level contract missing")
        helper_root = ROOT / "test_cases/ibsw225_fixture_support"
        self.assertTrue(helper_root.is_dir() and not helper_root.is_symlink(), "fixed helper capability missing")
        self.assertTrue((helper_root / "runtime_source_support.py").is_file())
        self.assertTrue((helper_root / "_fixture_test_upgrade_cli.py").is_file())
        entries = [p for p in helper_root.rglob("*") if "__pycache__" not in p.parts]
        for path in entries:
            self.assertFalse(path.is_symlink(), "helper closure cannot hide a foreign directory/file")
            self.assertTrue(path.is_dir() or path.is_file(), "nonregular helper entry")
        helper_files = [p for p in entries if p.is_file()]
        self.assertTrue(helper_files, "empty helper glob is not complete binding")
        self.assertTrue(any(r.get("complete_tracked_support") is True
                            and "test_cases/ibsw225_fixture_support/*.py" in r["paths"]
                            for r in manifest["path_rules"]), "unlisted helper additions must invalidate proof")
        for path in helper_files + [ROOT / REQUIREMENTS]:
            relative = str(path.relative_to(ROOT))
            self.assertFalse(path.is_symlink())
            self.assertIn(relative, manifest["tracked_support"])
            rules = [r for r in manifest["path_rules"]
                     if any(fnmatch.fnmatchcase(relative, p) for p in r["paths"])]
            self.assertTrue(rules, "tracked helper lacks impact rule")
            self.assertTrue(any(r.get("tests") or r.get("full_suite") is True for r in rules))
        suite_tests = [name for suite in manifest["test_suites"] for name in suite["tests"]]
        for name in NORMAL_MODULES:
            self.assertEqual(suite_tests.count(name), 1)

    def test_real_canonical_entry_driver_renderer_and_owned_template_keep_local_sources(self):
        self.assertTrue(all((ROOT / name).is_file() and not (ROOT / name).is_symlink()
                            for name in PYTHON_RUNTIME + SHELLS + (GUARD,)),
                        "complete literal canonical renderer bundle capability missing")
        app = load_script("ibsw_new_contract_actual_entry", ROOT / ENTRY)
        driver = app._fixed_driver()
        self.assertEqual(Path(driver.__file__).resolve(), ROOT / "tools/ibsw_upgrade_driver.py")
        contract = importlib.import_module("ibsw_upgrade_contract")
        component = importlib.import_module("ibsw_upgrade_component")
        executor = importlib.import_module("ibsw_upgrade_executor")
        for module in (contract, component, executor):
            self.assertEqual(Path(module.__file__).resolve().parent, ROOT / "tools")
        self.assertEqual(component._TEMPLATE, ROOT / SHELLS[1])
        policy = contract.normalize_upgrade(contract.load_global_text(GLOBAL), selected=("os",), method="http")
        node = contract.InventoryDevice("ib-contract", "192.0.2.21", "02:00:00:00:00:21")
        step = component.render_declared_step(policy, node, component="os", package_index=1,
            run_id="contract", method="http", switch_dir="/home/admin")
        self.assertIn("nvos-amd64-25.03.1010.bin", step.script)
        self.assertIn("nv action install system image", step.script)
        binding = dict(run_id="contract", node=dict(hostname="ib-contract"), stage="os-0001",
                       component="os", script_sha256="a" * 64)
        remote = "/home/admin/.ibsw-contract-ib-contract-os-0001-" + "b" * 32 + "/step.sh"
        payload = executor._owned_runner_bytes(binding, remote)
        self.assertTrue(payload.endswith((ROOT / SHELLS[2]).read_bytes()))
        self.assertIn(b"IBSW_OWNED_EXIT_V1", payload)

    def test_real_runner_snapshots_handwritten_helper_bytes_and_rejects_private_test_ids(self):
        runner = load_script("ibsw_new_contract_actual_runner", ROOT / "test_cases/run_related_tests.py")
        self.assertEqual(Path(runner.path_disposition.__globals__["__file__"]).resolve(),
                         ROOT / "tools/project_contract.py")
        first = b"VALUE = 'source-before'\n"
        second = b"VALUE = 'source-after'\n"
        with tempfile.TemporaryDirectory(prefix="ibsw-manifest-hash-") as folder:
            root = Path(folder)
            cases = root / "test_cases"
            helpers = cases / "ibsw225_fixture_support"
            helpers.mkdir(parents=True)
            (cases / "test_contract.py").write_text(
                "import unittest\nclass LiteralCase(unittest.TestCase):\n"
                "    def test_literal_contract(self):\n        self.assertEqual('source', 'source')\n",
                encoding="ascii")
            helper = helpers / "literal_helper.py"
            helper.write_bytes(first)
            support = "test_cases/ibsw225_fixture_support/literal_helper.py"
            manifest_path = root / "manifest.json"
            manifest = dict(tracked_support=[support], path_rules=[dict(
                paths=["test_cases/ibsw225_fixture_support/*.py"],
                tests=["test_cases.test_contract"], complete_tracked_support=True)])
            manifest_path.write_text(json.dumps(manifest), encoding="ascii")
            self.assertEqual(set(runner.discover_tests(root)), {"test_cases.test_contract"})
            runner._validate_test_ids(root, ["test_cases.test_contract"], "literal normal module")
            with self.assertRaises(runner.ImpactError):
                runner._validate_test_ids(root,
                    ["test_cases.ibsw225_fixture_support.literal_helper"], "private helper is not a test")
            with self.assertRaises(runner.ImpactError):
                runner._validate_test_ids(root,
                    ["test_cases.test_contract.Case.test_one"], "method is not a manifest module")
            before = runner.make_snapshot(root, manifest_path, manifest)
            self.assertEqual(before.support[support], hashlib.sha256(first).hexdigest())
            helper.write_bytes(second)
            after = runner.make_snapshot(root, manifest_path, manifest)
            self.assertEqual(after.support[support], hashlib.sha256(second).hexdigest())
            self.assertNotEqual(before.support[support], after.support[support])
            (helpers / "unrecorded_helper.py").write_bytes(b"VALUE = 'not-approved'\n")
            with self.assertRaises(runner.ImpactError):
                runner.make_snapshot(root, manifest_path, manifest)
