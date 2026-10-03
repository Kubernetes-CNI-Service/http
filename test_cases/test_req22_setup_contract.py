"""Independent REQ22 setup input expectations."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
SETUP = load_script("req22_setup_contract", ROOT / "DAY0-Prepare/01-a-setup.py")
HEADER = (
    "shared_network,subnet,netmask,range_start,range_end,routers,"
    "ztp_service_ip,cumulus_profile,nvos_ztp\n"
)


class Req22SetupInputTests(unittest.TestCase):
    @staticmethod
    def _project(root: Path, *, dhcp: str, ztp: str, subnet: str) -> Path:
        project = root / "DAY0-Prepare" / "fixture"
        project.mkdir(parents=True)
        (project / "01-global.yaml").write_text(
            "schema_version: 2\ncommon:\n  mgmt:\n"
            f"    dhcp-server:\n      status: {dhcp}\n"
            f"    ztp:\n      status: {ztp}\n",
            encoding="utf-8",
        )
        (project / "02-dhcp-subnet_config.csv").write_text(
            subnet, encoding="utf-8",
        )
        return project

    def test_disabled_mode_accepts_canonical_header_only_csv(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "02-dhcp-subnet_config.csv"
            source.write_text(HEADER + "\n", encoding="utf-8")
            errors, _ = SETUP._validate_subnet_csv(
                str(source), dhcp_enabled=False, ztp_enabled=False,
            )
            self.assertEqual([], errors)

    def test_enabled_mode_rejects_canonical_header_only_csv(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "02-dhcp-subnet_config.csv"
            source.write_text(HEADER, encoding="utf-8")
            errors, _ = SETUP._validate_subnet_csv(
                str(source), dhcp_enabled=True, ztp_enabled=False,
            )
            self.assertTrue(any("没有 subnet 记录" in item for item in errors), errors)

    def test_disabled_mode_rejects_physically_blank_csv(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "02-dhcp-subnet_config.csv"
            source.write_text(" \n\t\n", encoding="utf-8")
            errors, _ = SETUP._validate_subnet_csv(
                str(source), dhcp_enabled=False, ztp_enabled=False,
            )
            self.assertTrue(errors)

    def test_setup_rejects_disabled_dhcp_enabled_ztp_before_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            project = self._project(
                Path(directory), dhcp="disabled", ztp="enabled", subnet=HEADER,
            )
            with mock.patch.object(SETUP, "require_project_eligible"), \
                    mock.patch.object(
                        SETUP, "infra_log_root_lock",
                        side_effect=AssertionError("write-capable setup lock reached"),
                    ):
                with self.assertRaisesRegex(ValueError, "DHCP disabled.*ZTP enabled"):
                    SETUP.setup(str(project))

    def test_setup_rejects_missing_subnet_before_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            project = self._project(
                Path(directory), dhcp="disabled", ztp="disabled", subnet=HEADER,
            )
            (project / "02-dhcp-subnet_config.csv").unlink()
            with mock.patch.object(SETUP, "require_project_eligible"), \
                    mock.patch.object(
                        SETUP, "infra_log_root_lock",
                        side_effect=AssertionError("write-capable setup lock reached"),
                    ):
                with self.assertRaisesRegex(ValueError, "subnet"):
                    SETUP.setup(str(project))

    def test_cli_rejects_invalid_modes_before_monitor_stop(self):
        with tempfile.TemporaryDirectory() as directory:
            project = self._project(
                Path(directory), dhcp="disabled", ztp="enabled", subnet=HEADER,
            )
            args = SimpleNamespace(
                project=str(project), csv_dir=None, p2p_file=None,
                create=False, host_role="management-server", _server_delegated=False,
            )
            with mock.patch.object(SETUP, "require_project_eligible"), \
                    mock.patch.object(
                        SETUP, "stop_native_ztp_monitors",
                        side_effect=AssertionError("monitor touched before R22 gate"),
                    ), mock.patch.object(
                        SETUP, "setup",
                        side_effect=AssertionError("setup entered before R22 gate"),
                    ):
                with self.assertRaisesRegex(ValueError, "DHCP disabled.*ZTP enabled"):
                    SETUP._main_locked(args)

    def test_internal_setup_rejects_invalid_csv_before_template_write(self):
        with tempfile.TemporaryDirectory() as directory:
            project = self._project(
                Path(directory), dhcp="enabled", ztp="disabled", subnet=HEADER,
            )
            with mock.patch.object(
                SETUP, "_initialize_project_from_template",
                side_effect=AssertionError("template write reached before CSV gate"),
            ) as initialize:
                with self.assertRaisesRegex(ValueError, "没有 subnet 记录"):
                    SETUP._setup_impl(str(project))
            initialize.assert_not_called()


if __name__ == "__main__":
    unittest.main()
