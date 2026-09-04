#!/usr/bin/env python3
"""Contracts for complete script impact mapping and change-aware test runs."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = ROOT / "test_cases/run_related_tests.py"
MANIFEST_PATH = ROOT / "test_cases/script_test_manifest.json"


def load_runner():
    spec = importlib.util.spec_from_file_location("change_aware_runner", RUNNER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {RUNNER_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


RUNNER = load_runner()


class ImpactManifestTests(unittest.TestCase):
    def test_rendered_runtime_bootstraps_are_not_source_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = (
                "ztp/templates/ztp-bootstrap.sh",
                "ztp/ztp-bootstrap_oob.sh",
                "ztp/ztp-bootstrap_oobofoob.sh",
            )
            for relative in paths:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("#!/bin/sh\n", encoding="utf-8")
            scratch = root / ".codex_tmp_review/audit.py"
            scratch.parent.mkdir(parents=True)
            scratch.write_text("print('scratch')\n", encoding="utf-8")
            ignored_production = root / ".private/production.py"
            ignored_production.parent.mkdir(parents=True)
            ignored_production.write_text("print('production')\n", encoding="utf-8")
            (root / ".gitignore").write_text(
                ".private/production.py\n", encoding="utf-8"
            )

            discovered = RUNNER.discover_source_scripts(root)

        self.assertIn("ztp/templates/ztp-bootstrap.sh", discovered)
        self.assertNotIn("ztp/ztp-bootstrap_oob.sh", discovered)
        self.assertNotIn("ztp/ztp-bootstrap_oobofoob.sh", discovered)
        self.assertNotIn(".codex_tmp_review/audit.py", discovered)
        self.assertIn(
            ".private/production.py", discovered,
            "an arbitrary hidden/ignored script must still fail closed into inventory",
        )

    def test_every_source_and_symlink_alias_has_direct_and_workflow_mapping(self):
        manifest = RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)
        actual = RUNNER.discover_source_scripts(ROOT)
        self.assertEqual(actual, manifest["scripts"])
        self.assertGreaterEqual(len(actual), 100)
        self.assertNotIn("test_cases/run_related_tests.py", actual)
        self.assertEqual(
            [
                ".gitattributes",
                ".github/workflows/tests.yml",
                ".gitignore",
                "requirements-dev.txt",
                "test_cases/audit_public_tree.py",
                "test_cases/run_related_tests.py",
                "DAY0-Prepare/template/01-global.yaml",
                "DAY0-Prepare/template/02-devices_config.csv",
                "ztp/config/cumulus/template/03-templates-j2/_direct_vlan_ports.yaml.j2",
                "ztp/config/cumulus/template/03-templates-j2/_l2_svis.yaml.j2",
                "ztp/config/cumulus/template/03-templates-j2/border.yaml.j2",
                "ztp/config/cumulus/template/03-templates-j2/oob-core.yaml.j2",
                "ztp/config/cumulus/template/03-templates-j2/oob-leaf.yaml.j2",
                "ztp/config/cumulus/template/03-templates-j2/oob-rack-tor.yaml.j2",
                "ztp/config/cumulus/template/03-templates-j2/oob-su-leaf.yaml.j2",
                "ztp/config/cumulus/template/03-templates-j2/oob-su-spine.yaml.j2",
                "ztp/config/cumulus/template/03-templates-j2/oobofoob-leaf.yaml.j2",
                "ztp/config/cumulus/template/03-templates-j2/oobofoob-spine.yaml.j2",
                "ztp/config/cumulus/template/03-templates-j2/tan-cp-1gleaf.yaml.j2",
                "ztp/config/cumulus/template/03-templates-j2/tan-cp-leaf.yaml.j2",
                "ztp/config/cumulus/template/03-templates-j2/tan-hps-leaf.yaml.j2",
                "ztp/config/cumulus/template/03-templates-j2/tan-leaf.yaml.j2",
                "ztp/config/cumulus/template/03-templates-j2/tan-spine.yaml.j2",
                "ztp/config/cumulus/template/03-templates-j2/tan-su-leaf.yaml.j2",
                "ztp/templates/ztp.json",
            ],
            manifest["tracked_support"],
        )
        self.assertNotEqual(
            actual["infiniband/monitor/cron.sh"],
            "infiniband/monitor/cron.sh",
        )

    def test_new_unmapped_script_fails_closed(self):
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        removed = next(iter(manifest["scripts"]))
        del manifest["scripts"][removed]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(RUNNER.ImpactError, "source inventory differs"):
                RUNNER.load_and_validate_manifest(ROOT, path)

    def test_script_selects_direct_contract_and_multi_script_workflow(self):
        manifest = RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)
        snapshot = RUNNER.make_snapshot(ROOT, MANIFEST_PATH, manifest)
        approvals = RUNNER.snapshot_as_json(snapshot)
        pending = RUNNER.detect_pending(snapshot, approvals)
        selection = RUNNER.select_tests(
            ROOT, manifest, ["ztp/config/isc-dhcp-server/c1-generate_dhcp.py"], pending,
        )
        self.assertFalse(selection.full_suite)
        self.assertIn("test_cases.test_load_release_transaction", selection.tests)
        self.assertIn("test_cases.test_full_flow_integration", selection.tests)
        self.assertTrue(any("workflow" in reason for reason in selection.reasons))

    def test_nvos_ztp_template_selects_its_render_contract(self):
        manifest = RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)
        snapshot = RUNNER.make_snapshot(ROOT, MANIFEST_PATH, manifest)
        selection = RUNNER.select_tests(
            ROOT, manifest, ["ztp/templates/ztp.json"],
            RUNNER.detect_pending(snapshot, RUNNER.snapshot_as_json(snapshot)),
        )
        self.assertFalse(selection.full_suite)
        self.assertIn("test_cases.test_project_contracts", selection.tests)
        self.assertIn("test_cases.test_ztp_release_core_review", selection.tests)

    def test_canonical_script_change_expands_all_shared_symlink_paths(self):
        manifest = RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)
        snapshot = RUNNER.make_snapshot(ROOT, MANIFEST_PATH, manifest)
        selection = RUNNER.select_tests(
            ROOT,
            manifest,
            ["ethernet/monitor/cron.sh"],
            RUNNER.detect_pending(snapshot, RUNNER.snapshot_as_json(snapshot)),
        )
        self.assertTrue(
            {
                "ethernet/monitor/cron.sh",
                "infiniband/monitor/cron.sh",
                "nvlink/monitor/cron.sh",
            }.issubset(selection.changed_paths)
        )
        self.assertIn("test_cases.test_monitor_stack_review", selection.tests)

    def test_unknown_changed_path_falls_back_to_full_suite(self):
        manifest = RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)
        snapshot = RUNNER.make_snapshot(ROOT, MANIFEST_PATH, manifest)
        selection = RUNNER.select_tests(
            ROOT, manifest, ["new-domain/behavior.conf"],
            RUNNER.detect_pending(snapshot, RUNNER.snapshot_as_json(snapshot)),
        )
        self.assertTrue(selection.full_suite)


class ApprovalLedgerTests(unittest.TestCase):
    def test_hash_change_is_pending_and_approval_snapshot_is_exact(self):
        snapshot = RUNNER.Snapshot(
            manifest_sha256="a" * 64,
            scripts={"x.py": {"canonical": "x.py", "sha256": "b" * 64}},
            tests={"test_cases.test_x": "c" * 64},
        )
        approved = RUNNER.snapshot_as_json(snapshot)
        self.assertFalse(RUNNER.detect_pending(snapshot, approved).any())
        changed = RUNNER.Snapshot(
            manifest_sha256=snapshot.manifest_sha256,
            scripts={"x.py": {"canonical": "x.py", "sha256": "d" * 64}},
            tests=snapshot.tests,
        )
        self.assertEqual({"x.py"}, RUNNER.detect_pending(changed, approved).scripts)

    def test_test_harness_change_is_hash_tracked_without_becoming_runtime_source(self):
        baseline = RUNNER.Snapshot(
            manifest_sha256="a" * 64,
            scripts={}, tests={},
            support={"test_cases/run_related_tests.py": "b" * 64},
        )
        approved = RUNNER.snapshot_as_json(baseline)
        changed = RUNNER.Snapshot(
            manifest_sha256=baseline.manifest_sha256,
            scripts={}, tests={},
            support={"test_cases/run_related_tests.py": "c" * 64},
        )
        self.assertEqual(
            {"test_cases/run_related_tests.py"},
            RUNNER.detect_pending(changed, approved).support,
        )

    def test_failed_related_tests_do_not_update_approval_ledger(self):
        manifest = RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)
        snapshot = RUNNER.make_snapshot(ROOT, MANIFEST_PATH, manifest)
        with tempfile.TemporaryDirectory() as directory:
            approvals = Path(directory) / "approved.json"
            RUNNER.atomic_write_approvals(approvals, snapshot)
            before = approvals.read_bytes()
            args = RUNNER.parser().parse_args([
                "--approvals", str(approvals),
                "--changed", "DAY0-Prepare/11-load.py",
            ])
            with mock.patch.object(RUNNER, "run_selection", return_value=1):
                code, _state = RUNNER._one_cycle(args)
            self.assertEqual(1, code)
            self.assertEqual(before, approvals.read_bytes())

    def test_list_mode_never_rewrites_tests_or_approvals(self):
        manifest = RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)
        snapshot = RUNNER.make_snapshot(ROOT, MANIFEST_PATH, manifest)
        test_hashes = dict(snapshot.tests)
        with tempfile.TemporaryDirectory() as directory:
            approvals = Path(directory) / "approved.json"
            RUNNER.atomic_write_approvals(approvals, snapshot)
            before = approvals.read_bytes()
            result = subprocess.run(
                [
                    sys.executable, "-B", str(RUNNER_PATH),
                    "--approvals", str(approvals),
                    "--changed", "ztp/manual-ztp.py", "--list",
                ],
                cwd=ROOT, text=True, capture_output=True, timeout=30,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("test_cases.test_manual_applied_config", result.stdout)
            self.assertEqual(before, approvals.read_bytes())
            current = RUNNER.make_snapshot(ROOT, MANIFEST_PATH, manifest)
            self.assertEqual(test_hashes, current.tests)


if __name__ == "__main__":
    unittest.main()
