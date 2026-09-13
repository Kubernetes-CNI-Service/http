#!/usr/bin/env python3
"""Direct contracts for the sanitized project fixture used by public tests."""

import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest
import zipfile

from test_cases.public_project_fixture import (
    PRIVATE_SITE_PROJECT,
    PUBLIC_INPUTS,
    materialized_public_project,
)


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PUBLIC_INPUTS = {
    "01-global.yaml.example": "01-global.yaml",
    "02-devices_config.csv.example": "02-devices_config.csv",
    "02-dhcp-subnet_config.csv.example": "02-dhcp-subnet_config.csv",
}
EXPECTED_PRIVATE_SITE_PROJECT = "2026-12-vb-gb300"
RUN_VM = ROOT / "test_cases/run_vm_validation.py"
PACKAGING_METHODS = {
    "test_cases/test_deployment_writer_lock.py": {
        "test_sync_payload_covers_every_local_source_manifest_member",
        "test_project_rsync_excludes_global_for_dedicated_merge",
    },
    "test_cases/test_deploy_upload_archive.py": {
        "test_real_packager_relay_copy_installer_and_embedded_guard_workflow",
    },
    "test_cases/test_upload_package_contract.py": {
        "test_real_upload_archive_exactly_satisfies_packaged_source_manifest",
        "test_relay_release_externalizes_project_switch_images",
    },
}
GOVERNED_PUBLIC_FIXTURE_SUPPORT = {
    "test_cases/public_project_fixture.py",
    *(
        "examples/public-project/" + source
        for source in PUBLIC_INPUTS
    ),
}


def _load_run_vm():
    spec = importlib.util.spec_from_file_location("public_run_vm_contract", RUN_VM)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PublicProjectFixtureDirectTests(unittest.TestCase):
    def test_materializer_copies_exact_public_bytes_and_creates_valid_xlsx(self):
        source_root = ROOT / "examples/public-project"
        self.assertEqual(EXPECTED_PUBLIC_INPUTS, PUBLIC_INPUTS)
        self.assertEqual(EXPECTED_PRIVATE_SITE_PROJECT, PRIVATE_SITE_PROJECT)
        with materialized_public_project(ROOT) as project:
            self.assertNotIn(EXPECTED_PRIVATE_SITE_PROJECT, project.as_posix())
            for source_name, destination_name in EXPECTED_PUBLIC_INPUTS.items():
                with self.subTest(source=source_name):
                    source = source_root / source_name
                    destination = project / destination_name
                    self.assertEqual(source.read_bytes(), destination.read_bytes())
                    self.assertEqual(
                        hashlib.sha256(source.read_bytes()).hexdigest(),
                        hashlib.sha256(destination.read_bytes()).hexdigest(),
                    )
                    self.assertNotIn(
                        EXPECTED_PRIVATE_SITE_PROJECT,
                        destination.read_text(encoding="utf-8"),
                    )
            workbook = project / "public-p2p.xlsx"
            self.assertTrue(zipfile.is_zipfile(workbook))
            with zipfile.ZipFile(workbook) as archive:
                self.assertIsNone(archive.testzip())
                self.assertIn("xl/workbook.xml", archive.namelist())

    def test_vm_validation_requires_an_explicit_project(self):
        run_vm = _load_run_vm()
        self.assertEqual(EXPECTED_PRIVATE_SITE_PROJECT, PRIVATE_SITE_PROJECT)
        with self.assertRaises(SystemExit):
            run_vm.parse_args([])
        parsed = run_vm.parse_args(["public-project"])
        self.assertEqual("public-project", parsed.project)
        self.assertNotIn(
            EXPECTED_PRIVATE_SITE_PROJECT, RUN_VM.read_text(encoding="utf-8"),
        )

    def test_exact_five_packaging_tests_use_the_shared_public_materializer(self):
        seen = set()
        for relative, expected_methods in PACKAGING_METHODS.items():
            tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
            functions = {
                node.name: node for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            for method in expected_methods:
                with self.subTest(path=relative, method=method):
                    self.assertIn(method, functions)
                    body = ast.get_source_segment(
                        (ROOT / relative).read_text(encoding="utf-8"),
                        functions[method],
                    ) or ""
                    self.assertIn("materialized_public_project", body)
                    self.assertNotIn(EXPECTED_PRIVATE_SITE_PROJECT, body)
                    seen.add((relative, method))
        self.assertEqual(5, len(seen))

    def test_public_fixture_inputs_and_helper_are_governed_tracked_support(self):
        manifest = json.loads(
            (ROOT / "test_cases/script_test_manifest.json").read_text(encoding="utf-8")
        )
        support = set(manifest["tracked_support"])
        self.assertEqual(EXPECTED_PUBLIC_INPUTS, PUBLIC_INPUTS)
        expected_support = {
            "test_cases/public_project_fixture.py",
            *("examples/public-project/" + name for name in EXPECTED_PUBLIC_INPUTS),
        }
        self.assertEqual(expected_support, GOVERNED_PUBLIC_FIXTURE_SUPPORT)
        self.assertEqual(set(), expected_support - support)


if __name__ == "__main__":
    unittest.main()
