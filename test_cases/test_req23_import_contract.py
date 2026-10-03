"""REQ23: an external configuration set is selected, never guessed by mtime."""

from __future__ import annotations

import os
from pathlib import Path
from contextlib import redirect_stderr, redirect_stdout
import io
import tempfile
import unittest
from unittest import mock

from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
LOAD = load_script("req23_import_contract_load", ROOT / "DAY0-Prepare/11-load.py")
SETUP = load_script("req23_import_contract_setup", ROOT / "DAY0-Prepare/01-a-setup.py")
CSV_HEADER = (
    "hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac,"
    "eth1_ip,netmask,eth1_gw,eth1_mac\n"
)
HOST_ROW = "leaf01,eth,NA,192.0.2.10,24,NA,02:00:00:00:00:10,NA,NA,NA,NA\n"
HOST_YAML = (
    b"- set:\n    interface:\n      eth0:\n        ipv4:\n"
    b"          address:\n            192.0.2.10/24: {}\n"
)


class ImportSelectorTests(unittest.TestCase):
    def _source(self, project: Path) -> Path:
        source = project / "import-configs" / "20261003_101112"
        source.mkdir(parents=True)
        (project / "02-devices_config.csv").write_text(
            CSV_HEADER + HOST_ROW, encoding="utf-8",
        )
        (source / "leaf01.yaml").write_bytes(HOST_YAML)
        return source

    def test_cli_accepts_auto_and_explicit_single_timestamp(self):
        auto = LOAD.parse_args(["sample", "--import-configs"])
        explicit = LOAD.parse_args([
            "sample", "--import-configs=20261003_101112",
        ])
        ordinary = LOAD.parse_args(["sample"])
        self.assertEqual(auto.import_configs, "")
        self.assertEqual(explicit.import_configs, "20261003_101112")
        self.assertIsNone(ordinary.import_configs)

    def test_auto_selects_latest_name_not_latest_mtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            root = project / "import-configs"
            older = root / "20261002_235959"
            newer = root / "20261003_000001"
            older.mkdir(parents=True)
            newer.mkdir()
            os.utime(older, (9999999999, 9999999999))
            os.utime(newer, (1, 1))
            with LOAD.select_import_config_set(project, "") as selected:
                self.assertEqual(selected.name, newer.name)
                self.assertEqual(os.fstat(selected.directory_fd).st_ino, newer.stat().st_ino)

    def test_explicit_selector_can_choose_older_set(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            root = project / "import-configs"
            older = root / "20261002_235959"
            older.mkdir(parents=True)
            (root / "20261003_000001").mkdir()
            with LOAD.select_import_config_set(project, older.name) as selected:
                self.assertEqual(selected.name, older.name)

    def test_explicit_selector_rejects_traversal_and_newline(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            for value in (
                "20261003_040000/../../../etc",
                "20261003_040000\n",
                "../20261003_040000",
                "/20261003_040000",
            ):
                with self.subTest(value=value), self.assertRaises(LOAD.LoadError):
                    LOAD.select_import_config_set(project, value)

    def test_auto_never_falls_back_when_latest_is_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            root = project / "import-configs"
            (root / "20261002_235959").mkdir(parents=True)
            (root / "20261003_000001").symlink_to(root / "20261002_235959")
            with self.assertRaises(LOAD.LoadError):
                LOAD.select_import_config_set(project, "")

    def test_preflight_binds_actual_bytes_and_complete_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            self._source(project)
            with LOAD.select_import_config_set(project, "") as selected:
                snapshot = LOAD.preflight_import_configs(
                    selected, project / "02-devices_config.csv",
                )
                self.assertEqual(snapshot.files, (("leaf01.yaml", HOST_YAML),))
                self.assertEqual(snapshot.source_name, "20261003_101112")
                self.assertRegex(snapshot.digest, r"\A[0-9a-f]{64}\Z")

    def test_preflight_rejects_default_unknown_and_symlink_without_copying(self):
        for bad_name, payload, symlink in (
            ("default.yaml", HOST_YAML, False),
            ("unknown.yaml", HOST_YAML, False),
            ("other.yaml", HOST_YAML, True),
        ):
            with self.subTest(bad_name=bad_name), tempfile.TemporaryDirectory() as temporary:
                project = Path(temporary)
                source = self._source(project)
                bad = source / bad_name
                if symlink:
                    bad.symlink_to(source / "leaf01.yaml")
                else:
                    bad.write_bytes(payload)
                with LOAD.select_import_config_set(project, "") as selected:
                    with self.assertRaises(LOAD.LoadError):
                        LOAD.preflight_import_configs(
                            selected, project / "02-devices_config.csv",
                        )
                self.assertEqual(sorted(item.name for item in source.iterdir()),
                                 sorted(("leaf01.yaml", bad_name)))

    def test_preflight_rejects_null_and_missing_expected_device(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            source = self._source(project)
            (source / "leaf01.yaml").write_bytes(HOST_YAML + b"  bad: null\n")
            with LOAD.select_import_config_set(project, "") as selected:
                with self.assertRaises(LOAD.LoadError):
                    LOAD.preflight_import_configs(
                        selected, project / "02-devices_config.csv",
                    )
            (source / "leaf01.yaml").unlink()
            with LOAD.select_import_config_set(project, "") as selected:
                with self.assertRaises(LOAD.LoadError):
                    LOAD.preflight_import_configs(
                        selected, project / "02-devices_config.csv",
                    )

    def test_preflight_rejects_noncanonical_hostname_case(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            source = self._source(project)
            (source / "leaf01.yaml").rename(source / "Leaf01.yaml")
            with LOAD.select_import_config_set(project, "") as selected:
                with self.assertRaisesRegex(LOAD.LoadError, "canonical|hostname"):
                    LOAD.preflight_import_configs(
                        selected, project / "02-devices_config.csv",
                    )

    def test_preflight_rejects_hardlinked_member(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            source = self._source(project)
            os.link(source / "leaf01.yaml", project / "linked.yaml")
            with LOAD.select_import_config_set(project, "") as selected:
                with self.assertRaises(LOAD.LoadError):
                    LOAD.preflight_import_configs(
                        selected, project / "02-devices_config.csv",
                    )

    def test_setup_never_enters_operator_owned_import_alias(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            template = base / "template"
            (template / "import-configs").mkdir(parents=True)
            (template / "import-configs" / "retired.txt").write_text("old")
            external = base / "external"
            external.mkdir()
            project = base / "project"
            project.mkdir()
            (project / "import-configs").symlink_to(external, target_is_directory=True)
            with mock.patch.object(SETUP, "TEMPLATE_DIR", str(template)), \
                    mock.patch.object(SETUP, "_DRY_RUN", False), \
                    mock.patch.object(SETUP, "_LINK_ERRORS", 0):
                SETUP._initialize_project_from_template(str(project))
            self.assertTrue((project / "import-configs").is_symlink())
            self.assertEqual(list(external.iterdir()), [])

    def test_source_change_after_preflight_cannot_be_published(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            source = self._source(project)
            with LOAD.select_import_config_set(project, "") as selected:
                snapshot = LOAD.preflight_import_configs(
                    selected, project / "02-devices_config.csv",
                )
                (source / "leaf01.yaml").write_bytes(HOST_YAML + b"# changed\n")
                with self.assertRaises(LOAD.LoadError):
                    LOAD.assert_import_source_unchanged(
                        selected, snapshot, project / "02-devices_config.csv",
                    )

    def test_auto_selection_rejects_newer_set_added_during_load(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            self._source(project)
            with LOAD.select_import_config_set(project, "") as selected:
                snapshot = LOAD.preflight_import_configs(
                    selected, project / "02-devices_config.csv",
                )
                (project / "import-configs" / "20261004_000000").mkdir()
                with self.assertRaises(LOAD.LoadError):
                    LOAD.assert_import_source_unchanged(
                        selected, snapshot, project / "02-devices_config.csv",
                    )

    def test_output_is_new_load_timestamp_directory_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            self._source(project)
            output_root = project / "99-output"
            output_root.mkdir()
            with LOAD.select_import_config_set(project, "") as selected:
                snapshot = LOAD.preflight_import_configs(
                    selected, project / "02-devices_config.csv",
                )
            output = LOAD.publish_imported_output(
                snapshot, output_root, "20261003_111213",
            )
            self.assertEqual(output.name, "20261003_111213")
            self.assertEqual((output / "leaf01.yaml").read_bytes(), HOST_YAML)
            self.assertFalse((output / "default.yaml").exists())
            with self.assertRaises(LOAD.LoadError):
                LOAD.publish_imported_output(
                    snapshot, output_root, "20261003_111213",
                )
            self.assertEqual((output / "leaf01.yaml").read_bytes(), HOST_YAML)

    def test_output_accepts_managed_logical_99_output_alias(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            self._source(project)
            physical_root = project / "99-output-eth"
            physical_root.mkdir()
            logical_root = project / "template" / "99-output"
            logical_root.parent.mkdir()
            logical_root.symlink_to(physical_root, target_is_directory=True)
            with LOAD.select_import_config_set(project, "") as selected:
                snapshot = LOAD.preflight_import_configs(
                    selected, project / "02-devices_config.csv",
                )
            output = LOAD.publish_imported_output(
                snapshot, logical_root, "20261003_111213",
            )
            self.assertEqual(output, logical_root / "20261003_111213")
            self.assertEqual((physical_root / output.name / "leaf01.yaml").read_bytes(),
                             HOST_YAML)

    def test_invalid_import_fails_real_load_entry_before_setup_or_shared_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            source = self._source(project)
            (source / "default.yaml").write_bytes(HOST_YAML)
            old_marker = project / "old-release-marker"
            old_marker.write_bytes(b"OLD RELEASE\n")
            argv = [
                "project", "--host-role=workstation", "--prod", "--switch=eth",
                "--no-upgrade", "--import-configs",
            ]
            with mock.patch.object(LOAD, "runtime_os", return_value="Linux"), \
                    mock.patch.object(LOAD, "resolve_project", return_value=project), \
                    mock.patch.object(LOAD, "sync_marker_present", return_value=False), \
                    mock.patch.object(LOAD, "acquire_deployment_lock", return_value=91), \
                    mock.patch.object(LOAD, "release_deployment_lock") as release_lock, \
                    mock.patch.object(LOAD, "activate_project") as activate, \
                    redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                result = LOAD.main(argv)
            self.assertEqual(result, 1)
            activate.assert_not_called()
            release_lock.assert_called_once_with(91)
            self.assertEqual(old_marker.read_bytes(), b"OLD RELEASE\n")


if __name__ == "__main__":
    unittest.main()
