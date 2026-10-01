#!/usr/bin/env python3
"""CLI and final-mode contracts for the management-server download archive."""

from __future__ import annotations

import importlib.util
import io
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/tar-for-download.py"
SPEC = importlib.util.spec_from_file_location("download_cli_contract", SCRIPT)
assert SPEC and SPEC.loader
DOWNLOAD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DOWNLOAD)


class DownloadCliContractTests(unittest.TestCase):
    def test_selected_historical_project_without_devices_is_archival_only(self):
        """Default single-project download retains raw history without device CSV."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "DAY0-Prepare/old-project"
            project.mkdir(parents=True)
            (project / "01-global.yaml").write_bytes(b"legacy: true\n")
            (project / "field-note.txt").write_bytes(b"customer note\n")
            output = root / "single-history.tar.gz"
            args = DOWNLOAD.parse_args([str(project), "-o", str(output)])
            notice = io.StringIO()
            with mock.patch.object(
                DOWNLOAD.package_core, "resolve_project", return_value=project,
            ), mock.patch.object(
                DOWNLOAD.package_core, "managed_pubkey_paths", return_value=[],
            ), redirect_stdout(notice):
                DOWNLOAD.create_day0_archive(args)
            with tarfile.open(output, "r:gz") as archive:
                note = archive.extractfile(
                    "DAY0-Prepare/old-project/field-note.txt"
                )
                self.assertIsNotNone(note)
                self.assertEqual(b"customer note\n", note.read())
            self.assertIn("[NON-DEPLOYABLE] old-project", notice.getvalue())
            self.assertIn("02-devices_config.csv", notice.getvalue())
            self.assertIn("02-dhcp-subnet_config.csv", notice.getvalue())

    def test_incomplete_historical_day0_download_keeps_raw_files_and_lists_missing_core(self):
        """A historical project is archived, never silently omitted as deployable."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            day0 = root / "DAY0-Prepare"
            missing_global = day0 / "missing-global"
            missing_devices = day0 / "missing-devices"
            missing_subnet = day0 / "missing-subnet"
            for project in (missing_global, missing_devices, missing_subnet):
                project.mkdir(parents=True)
                (project / "field-note.txt").write_bytes(project.name.encode())
            (missing_global / "02-devices_config.csv").write_bytes(b"hostname\nleaf\n")
            (missing_global / "02-dhcp-subnet_config.csv").write_bytes(b"legacy\n")
            (missing_devices / "01-global.yaml").write_bytes(b"legacy: true\n")
            (missing_devices / "02-dhcp-subnet_config.csv").write_bytes(b"legacy\n")
            (missing_subnet / "01-global.yaml").write_bytes(b"legacy: true\n")
            (missing_subnet / "02-devices_config.csv").write_bytes(b"hostname\nleaf\n")
            output = root / "all-history.tar.gz"
            args = DOWNLOAD.parse_args(["--all-day0", "-o", str(output)])
            notice = io.StringIO()
            with mock.patch.multiple(
                DOWNLOAD.package_core, ROOT=root, DAY0=day0,
                MANIFEST=root / "ztp/.setup_manifest",
            ), mock.patch.object(
                DOWNLOAD.package_core, "managed_pubkey_paths", return_value=[],
            ), redirect_stdout(notice):
                DOWNLOAD.create_day0_archive(args)
            with tarfile.open(output, "r:gz") as archive:
                names = set(archive.getnames())
                for project in (missing_global, missing_devices, missing_subnet):
                    member = archive.extractfile(
                        f"DAY0-Prepare/{project.name}/field-note.txt"
                    )
                    self.assertIsNotNone(member)
                    self.assertEqual(project.name.encode(), member.read())
                self.assertNotIn("tools/deploy-upload-archive.py", names)
            for project, absent in (
                (missing_global, "01-global.yaml"),
                (missing_devices, "02-devices_config.csv"),
                (missing_subnet, "02-dhcp-subnet_config.csv"),
            ):
                self.assertIn(f"[NON-DEPLOYABLE] {project.name}", notice.getvalue())
                self.assertIn(absent, notice.getvalue())

    def test_project_folder_is_the_default_positional_argument(self):
        expected = "DAY0-Prepare/2099-example-site/"
        self.assertEqual(expected, DOWNLOAD.parse_args([expected]).project)
        self.assertEqual(
            "2099-example-site",
            DOWNLOAD.parse_args(["-p", "2099-example-site"]).project,
        )

    def test_positional_and_project_option_are_mutually_exclusive(self):
        with (
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit),
        ):
            DOWNLOAD.parse_args(["customer", "-p", "other"])

    def test_all_day0_rejects_a_positional_project(self):
        args = DOWNLOAD.parse_args(["customer", "--all-day0"])
        with self.assertRaisesRegex(ValueError, "--all-day0"):
            DOWNLOAD.validate_scope_options(args)

    def test_validated_final_archive_is_world_readable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "DAY0-Prepare/customer"
            project.mkdir(parents=True)
            (project / "02-devices_config.csv").write_text(
                "hostname,type\n", encoding="utf-8",
            )
            output = root / "customer-download.tar.gz"
            args = DOWNLOAD.parse_args(["customer", "-o", str(output)])
            with (
                mock.patch.object(
                    DOWNLOAD.package_core, "resolve_project", return_value=project,
                ),
                mock.patch.object(
                    DOWNLOAD.package_core, "managed_pubkey_paths", return_value=[],
                ),
                redirect_stdout(io.StringIO()),
            ):
                DOWNLOAD.create_day0_archive(args)
            self.assertEqual(0o644, stat.S_IMODE(output.stat().st_mode))

    def test_project_archive_rebound_output_parent_cannot_publish_foreign_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "DAY0-Prepare/customer"
            project.mkdir(parents=True)
            (project / "02-devices_config.csv").write_text(
                "hostname,type\n", encoding="utf-8",
            )
            safe = root / "safe"
            moved = root / "safe-moved"
            foreign = root / "foreign"
            safe.mkdir()
            foreign.mkdir()
            output = safe / "customer-download.tar.gz"
            args = DOWNLOAD.parse_args(["customer", "-o", str(output)])
            original_open = DOWNLOAD.tarfile.open
            archive_opens = 0

            @contextmanager
            def rebind_after_validation(*open_args, **open_kwargs):
                nonlocal archive_opens
                with original_open(*open_args, **open_kwargs) as archive:
                    yield archive
                archive_opens += 1
                if archive_opens == 2:
                    safe.rename(moved)
                    safe.symlink_to(foreign, target_is_directory=True)
                    stages = list(moved.glob(".*.tar.gz"))
                    self.assertEqual(1, len(stages))
                    (foreign / stages[0].name).write_bytes(b"attacker stage")
                    (foreign / output.name).write_bytes(b"foreign original")

            with (
                mock.patch.object(
                    DOWNLOAD.package_core, "resolve_project", return_value=project,
                ),
                mock.patch.object(
                    DOWNLOAD.package_core, "managed_pubkey_paths", return_value=[],
                ),
                mock.patch.object(DOWNLOAD.tarfile, "open", side_effect=rebind_after_validation),
                redirect_stdout(io.StringIO()),
            ):
                with self.assertRaisesRegex(
                    ValueError, "输出目录在归档校验后发生变化",
                ):
                    DOWNLOAD.create_day0_archive(args)
            self.assertEqual(2, archive_opens)
            self.assertEqual(b"foreign original", (foreign / output.name).read_bytes())

    def test_project_archive_does_not_replace_output_created_during_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "DAY0-Prepare/customer"
            project.mkdir(parents=True)
            (project / "02-devices_config.csv").write_text(
                "hostname,type\n", encoding="utf-8",
            )
            output = root / "customer-download.tar.gz"
            args = DOWNLOAD.parse_args(["customer", "-o", str(output)])
            original_open = DOWNLOAD.tarfile.open
            archive_opens = 0

            @contextmanager
            def create_output_after_validation(*open_args, **open_kwargs):
                nonlocal archive_opens
                with original_open(*open_args, **open_kwargs) as archive:
                    yield archive
                archive_opens += 1
                if archive_opens == 2:
                    output.write_bytes(b"concurrent original")

            with (
                mock.patch.object(
                    DOWNLOAD.package_core, "resolve_project", return_value=project,
                ),
                mock.patch.object(
                    DOWNLOAD.package_core, "managed_pubkey_paths", return_value=[],
                ),
                mock.patch.object(
                    DOWNLOAD.tarfile, "open", side_effect=create_output_after_validation,
                ),
                redirect_stdout(io.StringIO()),
            ):
                with self.assertRaises(FileExistsError):
                    DOWNLOAD.create_day0_archive(args)
            self.assertEqual(2, archive_opens)
            self.assertEqual(b"concurrent original", output.read_bytes())

    def test_project_archive_replaced_stage_cannot_be_published(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "DAY0-Prepare/customer"
            project.mkdir(parents=True)
            (project / "02-devices_config.csv").write_text(
                "hostname,type\n", encoding="utf-8",
            )
            output = root / "customer-download.tar.gz"
            args = DOWNLOAD.parse_args(["customer", "-o", str(output)])
            original_open = DOWNLOAD.tarfile.open
            archive_opens = 0

            @contextmanager
            def replace_stage_after_validation(*open_args, **open_kwargs):
                nonlocal archive_opens
                with original_open(*open_args, **open_kwargs) as archive:
                    yield archive
                archive_opens += 1
                if archive_opens == 2:
                    stages = list(root.glob(".customer-*.tar.gz"))
                    self.assertEqual(1, len(stages))
                    stages[0].unlink()
                    stages[0].write_bytes(b"attacker stage")

            with (
                mock.patch.object(
                    DOWNLOAD.package_core, "resolve_project", return_value=project,
                ),
                mock.patch.object(
                    DOWNLOAD.package_core, "managed_pubkey_paths", return_value=[],
                ),
                mock.patch.object(DOWNLOAD.tarfile, "open", side_effect=replace_stage_after_validation),
                redirect_stdout(io.StringIO()),
            ):
                with self.assertRaisesRegex(ValueError, "临时归档身份已变化"):
                    DOWNLOAD.create_day0_archive(args)
            self.assertEqual(2, archive_opens)
            self.assertFalse(output.exists())

    def test_full_workspace_uses_download_artifact_without_deployment_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "full-workspace.tar.gz"
            args = DOWNLOAD.parse_args([
                "--full-workspace", "-o", str(output),
            ])
            events = []

            def create_download(
                actual_args, *, day0_all, artifact_kind,
            ):
                self.assertIs(args, actual_args)
                self.assertTrue(day0_all)
                self.assertEqual("download", artifact_kind)
                events.append("package:download")
                return output

            with mock.patch.object(
                DOWNLOAD, "parse_args", return_value=args,
            ), mock.patch.object(
                DOWNLOAD.package_core, "create_package",
                side_effect=create_download,
            ), mock.patch.object(
                DOWNLOAD, "run_predeploy_test_gate", create=True,
                side_effect=AssertionError(
                    "download recovery artifacts must not require deployment gate",
                ),
            ) as deployment_gate, redirect_stdout(io.StringIO()), \
                    redirect_stderr(io.StringIO()):
                self.assertEqual(0, DOWNLOAD.main([]))

            self.assertEqual(["package:download"], events)
            deployment_gate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
