#!/usr/bin/env python3
"""REQ-15 flow from setup's selection record to load and upload transport."""

from __future__ import annotations

import argparse
import contextlib
import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

from test_cases.test_upload_package_contract import REQUIRED_UPLOAD_SOURCES
from test_cases.test_load_release_transaction import ReleaseTransactionTests, LOAD, MANUAL


ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
    return module


def workbook(path: Path, payload: str) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("xl/workbook.xml", f"<workbook>{payload}</workbook>")
    return path


class P2PSelectionWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.setup = load_script("req15_workflow_setup", ROOT / "DAY0-Prepare/01-a-setup.py")
        cls.load = load_script("req15_workflow_load", ROOT / "DAY0-Prepare/11-load.py")
        tools = str(ROOT / "tools")
        if tools not in sys.path:
            sys.path.insert(0, tools)
        cls.package = load_script("req15_workflow_package", ROOT / "tools/_package_common.py")

    def select_and_link(self, project: Path, explicit: str | None = None) -> tuple[Path | None, str]:
        old_file, old_dry = self.setup._P2P_FILE, self.setup._DRY_RUN
        output = io.StringIO()
        try:
            self.setup._P2P_FILE = explicit
            self.setup._DRY_RUN = False
            with contextlib.redirect_stdout(output):
                source = self.setup._select_p2p_source(str(project))
                if source is None:
                    return None, output.getvalue()
                linked = self.setup._ensure_project_p2p_link(str(project), source)
        finally:
            self.setup._P2P_FILE, self.setup._DRY_RUN = old_file, old_dry
        return Path(linked) if linked else None, output.getvalue()

    def test_setup_repoints_stale_link_and_load_reads_latest_root_workbook(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            older = workbook(project / "Fabric P2P_v1.0.xlsx", "old")
            newer = workbook(project / "Fabric P2P_v2.0.xlsx", "new")
            os.utime(older, (1_900_000_000, 1_900_000_000))
            os.utime(newer, (1_600_000_000, 1_600_000_000))
            (project / "p2p.xlsx").symlink_to(older.name)

            linked, output = self.select_and_link(project)

            self.assertEqual(project / "p2p.xlsx", linked)
            self.assertEqual(newer, linked.resolve())
            self.assertIn(f"p2p.xlsx: {older.name} -> {newer.name}", output)
            self.assertEqual(newer, self.load.select_p2p(project))

    def test_deliberate_older_pin_controls_load_and_upload_after_mtime_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            older = workbook(project / "Fabric P2P_v1.0.xlsx", "pinned")
            newer = workbook(project / "Fabric P2P_v2.0.xlsx", "latest")

            linked, output = self.select_and_link(project, older.name)

            self.assertEqual(project / "p2p.xlsx", linked)
            self.assertEqual(older, linked.resolve())
            self.assertIn(newer.name, output)
            self.assertRegex(output, "(?i)(rename|重命名|改名)")
            os.utime(older, (1_600_000_000, 1_600_000_000))
            os.utime(newer, (1_900_000_000, 1_900_000_000))
            self.assertEqual(older, self.load.select_p2p(project, older.name))
            self.assertEqual(older, self.package.select_upload_p2p(project))

    def test_zero_byte_placeholder_becomes_relative_link(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            expected = workbook(project / "Fabric P2P_v1.0.xlsx", "sole")
            (project / "p2p.xlsx").touch()

            linked, _ = self.select_and_link(project)

            self.assertEqual(project / "p2p.xlsx", linked)
            self.assertTrue(linked.is_symlink())
            self.assertEqual(expected.name, os.readlink(linked))
            self.assertEqual(expected, self.load.select_p2p(project))
            self.assertEqual(expected, self.package.select_upload_p2p(project))

    def test_nonempty_canonical_is_rescued_without_losing_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            canonical = workbook(project / "p2p.xlsx", "owner-data")
            original_digest = hashlib.sha256(canonical.read_bytes()).hexdigest()

            linked, _ = self.select_and_link(project)

            rescued = list(project.glob("p2p-original-*.xlsx"))
            self.assertEqual(1, len(rescued))
            self.assertRegex(rescued[0].name, r"^p2p-original-\d{8}-\d{6}(?:-\d+)?\.xlsx$")
            self.assertEqual(original_digest, hashlib.sha256(rescued[0].read_bytes()).hexdigest())
            self.assertEqual(project / "p2p.xlsx", linked)
            self.assertTrue(linked.is_symlink())
            self.assertEqual(rescued[0], linked.resolve())
            self.assertEqual(rescued[0], self.package.select_upload_p2p(project))

    def test_rescue_name_collision_preserves_existing_file_and_uses_next_name(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            canonical = workbook(project / "p2p.xlsx", "owner-data")
            original_bytes = canonical.read_bytes()
            atomic_rename = self.setup._atomic_rename_noreplace
            occupied = []

            def race_for_first_name(source, destination):
                if not occupied:
                    workbook(destination, "other-owner")
                    occupied.append((destination, destination.read_bytes()))
                return atomic_rename(source, destination)

            with mock.patch.object(
                self.setup, "_atomic_rename_noreplace",
                side_effect=race_for_first_name,
            ):
                rescued = self.setup._rescue_canonical_p2p(canonical)

            self.assertEqual(1, len(occupied))
            first_name, first_bytes = occupied[0]
            self.assertEqual(first_bytes, first_name.read_bytes())
            self.assertEqual(
                first_name.with_name(f"{first_name.stem}-1.xlsx"), rescued,
            )
            self.assertEqual(original_bytes, rescued.read_bytes())
            self.assertFalse(canonical.exists())

    def test_nonempty_canonical_with_other_candidate_fails_after_rescue(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            original = workbook(project / "p2p.xlsx", "owner-data")
            original_digest = hashlib.sha256(original.read_bytes()).hexdigest()
            workbook(project / "Fabric P2P_v2.0.xlsx", "other")

            linked, output = self.select_and_link(project)

            self.assertIsNone(linked)
            rescued = list(project.glob("p2p-original-*.xlsx"))
            self.assertEqual(1, len(rescued))
            self.assertEqual(original_digest, hashlib.sha256(rescued[0].read_bytes()).hexdigest())
            self.assertRegex(output, "(?i)(version|版本)")

    def test_rescue_fails_before_moving_when_atomic_noreplace_is_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            canonical = workbook(project / "p2p.xlsx", "owner-data")
            before = canonical.read_bytes()
            with mock.patch.object(
                self.setup, "_atomic_rename_noreplace",
                side_effect=OSError(errno.ENOTSUP, "atomic no-replace unavailable"),
            ):
                linked, output = self.select_and_link(project)
            self.assertIsNone(linked)
            self.assertIn("atomic no-replace unavailable", output)
            self.assertEqual(before, canonical.read_bytes())
            self.assertEqual([], list(project.glob("p2p-original-*.xlsx")))

    def test_day0_all_archive_carries_only_the_last_selected_workbook(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            workspace = base / "http"
            day0 = workspace / "DAY0-Prepare"
            project = day0 / "customer"
            project.mkdir(parents=True)
            (workspace / "ztp").mkdir()
            (workspace / "tools").mkdir()
            (project / "01-global.yaml").write_text("schema_version: 2\ncommon: {}\n", encoding="utf-8")
            (project / "02-devices_config.csv").write_text("hostname,type\nleaf01,eth\n", encoding="utf-8")
            (project / "02-dhcp-subnet_config.csv").write_text("shared_network,subnet\nmgmt,192.0.2.0\n", encoding="utf-8")
            for relative in REQUIRED_UPLOAD_SOURCES:
                path = workspace / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                if not path.exists():
                    path.write_text(f"fixture for {relative}\n", encoding="utf-8")
            selected = workbook(project / "Fabric P2P_v1.0.xlsx", "selected")
            other = workbook(project / "Fabric P2P_v2.0.xlsx", "not-selected")
            assignment = workbook(project / "ip assignment_v9.0.xlsx", "not-p2p")
            (project / "p2p.xlsx").symlink_to(selected.name)
            second_project = day0 / "second-customer"
            second_project.mkdir()
            (second_project / "01-global.yaml").write_text("schema_version: 2\ncommon: {}\n", encoding="utf-8")
            (second_project / "02-devices_config.csv").write_text("hostname,type\nleaf02,eth\n", encoding="utf-8")
            second_selected = workbook(second_project / "Site P2P_v4.0.xlsx", "second-selected")
            second_other = workbook(second_project / "Site P2P_v5.0.xlsx", "second-not-selected")
            (second_project / "p2p.xlsx").symlink_to(second_selected.name)
            output = base / "whole-day0.tar.gz"
            args = argparse.Namespace(
                project=str(project), output=output, force=False,
                max_file_size_mib=50, include_images=False, include_apps=False,
                apps_platform=None, apps_platforms=set(), include_firmware=False,
                exclude_project_images=False,
            )

            def source_manifest(destination: Path) -> Path:
                destination.write_bytes(b'{"schema_version":1,"sources":{"runtime.py":"fixed"}}\n')
                return destination

            with mock.patch.multiple(
                self.package,
                ROOT=workspace,
                DAY0=day0,
                MANIFEST=workspace / "ztp/.setup_manifest",
                TOOLS_DIR=workspace / "tools",
                write_deployment_source_manifest=source_manifest,
            ), contextlib.redirect_stdout(io.StringIO()):
                self.package.create_package(args, day0_all=True, artifact_kind="upload")
            with tarfile.open(output, "r:gz") as archive:
                names = {member.name.removeprefix("./") for member in archive.getmembers()}
            workbook_members = names & {
                f"DAY0-Prepare/customer/{selected.name}",
                f"DAY0-Prepare/customer/{other.name}",
                f"DAY0-Prepare/customer/{assignment.name}",
                "DAY0-Prepare/customer/p2p.xlsx",
                f"DAY0-Prepare/second-customer/{second_selected.name}",
                f"DAY0-Prepare/second-customer/{second_other.name}",
                "DAY0-Prepare/second-customer/p2p.xlsx",
            }
            self.assertEqual({
                f"DAY0-Prepare/customer/{selected.name}",
                f"DAY0-Prepare/second-customer/{second_selected.name}",
            }, workbook_members)

    def test_day0_all_rejects_a_project_without_safe_canonical_pointer(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            workspace = base / "http"
            project = workspace / "DAY0-Prepare/customer"
            project.mkdir(parents=True)
            (workspace / "ztp").mkdir()
            (workspace / "tools").mkdir()
            (project / "01-global.yaml").write_text("schema_version: 2\ncommon: {}\n", encoding="utf-8")
            (project / "02-devices_config.csv").write_text("hostname,type\nleaf01,eth\n", encoding="utf-8")
            workbook(project / "Fabric P2P_v1.0.xlsx", "unselected")
            args = argparse.Namespace(
                project=str(project), output=base / "unsafe.tar.gz", force=False,
                max_file_size_mib=50, include_images=False, include_apps=False,
                apps_platform=None, apps_platforms=set(), include_firmware=False,
                exclude_project_images=False,
            )
            with mock.patch.multiple(
                self.package,
                ROOT=workspace,
                DAY0=workspace / "DAY0-Prepare",
                MANIFEST=workspace / "ztp/.setup_manifest",
                TOOLS_DIR=workspace / "tools",
            ), self.assertRaisesRegex(ValueError, "p2p.xlsx"):
                self.package.create_package(args, day0_all=True, artifact_kind="upload")
            self.assertFalse(args.output.exists())

    def test_download_backup_preserves_unselected_workbook_without_runtime_pointer(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            workspace = base / "http"
            project = workspace / "DAY0-Prepare/customer"
            project.mkdir(parents=True)
            (workspace / "ztp").mkdir()
            (workspace / "tools").mkdir()
            (project / "01-global.yaml").write_text("schema_version: 2\ncommon: {}\n", encoding="utf-8")
            (project / "02-devices_config.csv").write_text("hostname,type\nleaf01,eth\n", encoding="utf-8")
            (project / "02-dhcp-subnet_config.csv").write_text(
                "shared_network,subnet\nmgmt,192.0.2.0\n", encoding="utf-8",
            )
            for relative in REQUIRED_UPLOAD_SOURCES:
                path = workspace / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                if not path.exists():
                    path.write_text(f"fixture for {relative}\n", encoding="utf-8")
            source = workbook(project / "historical P2P_v1.0.xlsx", "backup-only")
            args = argparse.Namespace(
                project=str(project), output=base / "backup.tar.gz", force=False,
                max_file_size_mib=50, include_images=False, include_apps=False,
                apps_platform=None, apps_platforms=set(), include_firmware=False,
                exclude_project_images=False,
            )
            with mock.patch.multiple(
                self.package,
                ROOT=workspace,
                DAY0=workspace / "DAY0-Prepare",
                MANIFEST=workspace / "ztp/.setup_manifest",
                TOOLS_DIR=workspace / "tools",
            ), contextlib.redirect_stdout(io.StringIO()):
                self.package.create_package(args, day0_all=True, artifact_kind="download")
            with tarfile.open(args.output, "r:gz") as archive:
                member = archive.extractfile(f"./DAY0-Prepare/customer/{source.name}")
                self.assertIsNotNone(member)
                self.assertEqual(source.read_bytes(), member.read())

    def test_parent_release_and_manual_gate_bind_selected_real_path_and_digest(self):
        fixture = ReleaseTransactionTests(
            "test_manual_preflight_binds_parent_to_the_exact_current_child",
        )
        fixture.setUp()
        try:
            fixture.p2p_file.unlink()
            selected = workbook(fixture.project / "Fabric P2P_v1.0.xlsx", "pinned")
            other = fixture.project / "Fabric P2P_v2.0.xlsx"
            other.write_bytes(selected.read_bytes())
            fixture.p2p_file.symlink_to(selected.name)
            inputs = LOAD.replace(fixture.inputs, p2p_file=selected)
            expected = {
                "path": selected.name,
                "sha256": hashlib.sha256(selected.read_bytes()).hexdigest(),
            }

            parent = LOAD.validate_and_publish_release(fixture.project, inputs)
            self.assertEqual(expected, parent["input_sources"]["p2p"])
            self.assertEqual(expected["sha256"], parent["inputs"]["p2p"])
            device = {
                "hostname": "leaf01", "type": "eth",
                "mac_plain": "020000000001",
                "identity_macs": {"eth0": "020000000001"},
            }
            with mock.patch.object(
                MANUAL, "DHCP_RELEASE_MANIFEST",
                fixture.ztp / "config/isc-dhcp-server/dhcp-release-manifest.json",
            ):
                MANUAL.validate_parent_release_binding(fixture.project, device)
                fixture.p2p_file.unlink()
                fixture.p2p_file.symlink_to(other.name)
                self.assertEqual(
                    hashlib.sha256(selected.read_bytes()).hexdigest(),
                    hashlib.sha256(other.read_bytes()).hexdigest(),
                )
                with self.assertRaises(MANUAL.ManualZtpError):
                    MANUAL.validate_parent_release_binding(fixture.project, device)
        finally:
            fixture.tearDown()

    def test_legacy_v1_parent_without_real_source_binding_requires_fresh_load(self):
        fixture = ReleaseTransactionTests(
            "test_manual_preflight_binds_parent_to_the_exact_current_child",
        )
        fixture.setUp()
        try:
            parent = LOAD.validate_and_publish_release(fixture.project, fixture.inputs)
            legacy = dict(parent)
            # The current load publishes schema v2. Build an actual v1
            # fixture before removing the real-source binding under test.
            legacy["schema_version"] = 1
            legacy.pop("dhcp_status")
            legacy.pop("input_sources")
            legacy_basis = {
                key: legacy[key] for key in (
                    "project", "deployment_scope", "switch_scope", "inputs",
                    "components", "inventory",
                )
            }
            legacy["release_id"] = hashlib.sha256(
                json.dumps(
                    legacy_basis, ensure_ascii=False, sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()[:20]
            self.assertEqual(1, legacy["schema_version"])
            (fixture.project / "99-output-ztp/current-release.json").write_text(
                json.dumps(legacy), encoding="utf-8",
            )
            device = {
                "hostname": "leaf01", "type": "eth",
                "mac_plain": "020000000001",
                "identity_macs": {"eth0": "020000000001"},
            }
            with mock.patch.object(
                MANUAL, "DHCP_RELEASE_MANIFEST",
                fixture.ztp / "config/isc-dhcp-server/dhcp-release-manifest.json",
            ), self.assertRaises(MANUAL.ManualZtpError):
                MANUAL.validate_parent_release_binding(fixture.project, device)
        finally:
            fixture.tearDown()


if __name__ == "__main__":
    unittest.main()
