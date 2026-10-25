"""Contracts for a child-only fixture without pruning production imports.

The original parent helpers remain canonical.  These checks forbid silent
drift of their child copies and keep all six child programs otherwise intact.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
CHILD = ROOT / "test_cases/release_child_fixture.py"
PARENT = ROOT / "test_cases/test_load_release_transaction.py"
HELPERS = (
    "sha256",
    "assert_private_dhcp_transaction_retention",
    "assert_private_dhcp_preimage_disk_inspection",
    "assert_private_dhcp_inspection_parent_rebind_hold",
    "assert_private_dhcp_cold_pending_hold",
    "private_publication_candidates",
    "private_a_health_ports",
)
REAL_IMPORTS = (
    ("day0_load", "DAY0-Prepare/11-load.py"),
    ("manual_ztp_release_contract", "ztp/manual-ztp.py"),
    ("dhcp_release_contract", "ztp/config/isc-dhcp-server/c1-generate_dhcp.py"),
    ("air_topology_release_contract", "ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py"),
    ("cumulus_scope_generation_contract", "ztp/config/cumulus/template/90-c2-generate_configs.py"),
    ("cumulus_scope_publication_contract", "ztp/config/cumulus/d-hostname2mac.py"),
    ("day0_setup_release_contract", "DAY0-Prepare/01-a-setup.py"),
    ("day0_unsetup_release_contract", "DAY0-Prepare/02-unsetup.py"),
)


class ReleaseChildFixtureContractTests(unittest.TestCase):
    def child_tree(self):
        self.assertTrue(CHILD.is_file(), "the child fixture must exist")
        return ast.parse(CHILD.read_bytes())

    def test_all_seven_helper_bodies_defaults_and_decorators_match_parent(self):
        parent = {n.name: n for n in ast.parse(PARENT.read_bytes()).body
                  if isinstance(n, ast.FunctionDef)}
        body = self.child_tree().body
        first = next(i for i, n in enumerate(body)
                     if isinstance(n, ast.FunctionDef) and n.name == "sha256")
        child = {n.name: n for n in body[first:] if isinstance(n, ast.FunctionDef)}
        self.assertEqual(set(HELPERS), set(child))
        for name in HELPERS:
            with self.subTest(helper=name):
                self.assertEqual(ast.dump(parent[name]), ast.dump(child[name]))

    def test_entire_real_import_prefix_is_preserved_not_literal_preloading(self):
        original = ast.parse(PARENT.read_bytes()).body
        first = next(i for i, n in enumerate(original)
                     if isinstance(n, ast.FunctionDef) and n.name == "sha256")
        child = self.child_tree().body
        self.assertEqual([ast.dump(n) for n in original[:first]],
                         [ast.dump(n) for n in child[:first]])
        self.assertTrue(all(isinstance(n, ast.FunctionDef) for n in child[first:]))

    def test_child_has_no_test_classes_or_discovery_occurrences(self):
        tree = self.child_tree()
        self.assertFalse(any(isinstance(n, ast.ClassDef) for n in tree.body))
        self.assertFalse(any(isinstance(n, ast.FunctionDef) and n.name.startswith("test_")
                             for n in tree.body))

    def test_exact_six_embedded_child_import_sites_keep_original_names(self):
        expected = {
            "test_generation_input_binding_workflow.py": [
                ("private_publication_candidates", "assert_private_dhcp_transaction_retention", "private_a_health_ports"),
                ("private_a_health_ports",),
                ("private_publication_candidates",),
                ("assert_private_dhcp_transaction_retention",),
                ("assert_private_dhcp_cold_pending_hold",),
            ],
            "test_load_release_transaction.py": [("assert_private_dhcp_transaction_retention",)],
        }
        for filename, names in expected.items():
            with self.subTest(module=filename):
                tree = ast.parse((ROOT / "test_cases" / filename).read_bytes())
                imports = []
                # Compare source order, not ast.walk's breadth-first nesting order.
                for literal in sorted(ast.walk(tree), key=lambda n: getattr(n, "lineno", 0)):
                    if not isinstance(literal, ast.Constant) or not isinstance(literal.value, str):
                        continue
                    if "from test_cases.release_child_fixture import " not in literal.value:
                        continue
                    program = ast.parse(literal.value)
                    imports.extend(tuple(a.name for a in node.names) for node in ast.walk(program)
                                   if isinstance(node, ast.ImportFrom)
                                   and node.module == "test_cases.release_child_fixture")
                self.assertEqual(names, imports)

    def test_parent_helpers_are_not_reexported_or_rebound(self):
        tree = ast.parse(PARENT.read_bytes())
        for name in HELPERS:
            with self.subTest(helper=name):
                definitions = [n for n in tree.body if isinstance(n, ast.FunctionDef)
                               and n.name == name]
                self.assertEqual(1, len(definitions))
                self.assertFalse(any(isinstance(n, ast.ImportFrom)
                                     and any(a.asname == name or a.name == name for a in n.names)
                                     for n in tree.body))

    def test_manifest_tracks_support_and_selects_direct_and_both_real_workflows(self):
        manifest = json.loads((ROOT / "test_cases/script_test_manifest.json").read_bytes())
        self.assertIn("test_cases/release_child_fixture.py", manifest["tracked_support"])
        rules = [r for r in manifest["path_rules"]
                 if "test_cases/release_child_fixture.py" in r["paths"]]
        self.assertEqual(1, len(rules))
        # test_v2_generation_flow: the workflow module once re-exported its
        # V2MlagSetupPreflightTests; the borrower->definer closure keeps that class selected.
        self.assertEqual({"test_cases.test_release_child_fixture",
                          "test_cases.test_generation_input_binding_workflow",
                          "test_cases.test_load_release_transaction",
                          "test_cases.test_v2_generation_flow"}, set(rules[0]["tests"]))
        owners = [suite["id"] for suite in manifest["test_suites"]
                  if "test_cases.test_release_child_fixture" in suite["tests"]]
        self.assertEqual(["repository-governance"], owners)

    def test_fresh_child_executes_all_eight_real_bodies_and_csv_effect_twice(self):
        import yaml
        self.assertTrue(CHILD.is_file(), "the child fixture must exist")
        program = r'''
import csv, importlib.machinery, importlib.util, json, sys, tempfile
from pathlib import Path
from unittest import mock
root = Path(sys.argv[1]); sys.path.insert(0, str(root))
# -I hides the user site-packages, where the formal CLT interpreter keeps PyYAML
# (imported by release_child_fixture.py): append only that declared directory.
sys.path.append(sys.argv[3])
expected = json.loads(sys.argv[2])
paths = {str(root / relative): name for name, relative in expected}
executed = []
original = importlib.machinery.SourceFileLoader.exec_module
def witness(loader, module):
    path = str(Path(loader.path).resolve())
    if path in paths:
        executed.append((module.__name__, str(Path(path).relative_to(root))))
    return original(loader, module)
def fresh():
    csv.field_size_limit(7)
    spec = importlib.util.spec_from_file_location('independent_release_child', root / 'test_cases/release_child_fixture.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    assert csv.field_size_limit() == min(sys.maxsize, 2**31 - 1)
    assert module.sha256.__globals__ is vars(module)
    return module
with mock.patch.object(importlib.machinery.SourceFileLoader, 'exec_module', witness):
    first = fresh()
    first.LOAD._child_only_independent_marker = object()
    second = fresh()
assert first is not second and first.LOAD is not second.LOAD
assert not hasattr(second.LOAD, '_child_only_independent_marker')
assert executed == [tuple(item) for item in expected] * 2, executed
with tempfile.TemporaryDirectory(prefix='release-child-sha-') as directory:
    source = Path(directory) / 'abc'; source.write_bytes(b'abc')
    assert second.sha256(source) == 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
print('FRESH_REAL_IMPORTS_AND_LITERAL_SHA_OK')
'''
        child = subprocess.run([sys.executable, "-I", "-B", "-c", program,
                                str(ROOT), json.dumps(REAL_IMPORTS),
                                str(Path(yaml.__file__).resolve().parents[1])],
                               capture_output=True, text=True, timeout=60)
        self.assertEqual(0, child.returncode, child.stdout + child.stderr)
        self.assertEqual("FRESH_REAL_IMPORTS_AND_LITERAL_SHA_OK\n", child.stdout)


if __name__ == "__main__":
    unittest.main()
