"""Independent REQ22 DHCP runtime input and mode expectations."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = load_script("req22_runtime_contract", ROOT / "tools/ztp_service_runtime.py")
ACTIVATE = load_script("req22_activate_contract", ROOT / "infra/docker/activate.py")
HEADER = (
    "shared_network,subnet,netmask,range_start,range_end,routers,"
    "ztp_service_ip,cumulus_profile,nvos_ztp\n"
)


class Req22RuntimeInputTests(unittest.TestCase):
    @staticmethod
    def _project(root: Path, *, dhcp: str, ztp: str) -> Path:
        project = root / "DAY0-Prepare" / "fixture"
        project.mkdir(parents=True)
        (project / "01-global.yaml").write_text(
            "common:\n  mgmt:\n"
            f"    dhcp-server:\n      status: {dhcp}\n"
            f"    ztp:\n      status: {ztp}\n",
            encoding="utf-8",
        )
        (project / "02-dhcp-subnet_config.csv").write_text(
            HEADER, encoding="utf-8",
        )
        return project

    def test_disabled_header_only_csv_produces_no_local_listeners(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "02-dhcp-subnet_config.csv"
            source.write_text(HEADER, encoding="utf-8")
            plan = RUNTIME.plan_dhcp_runtime(
                source, link_snapshot=[], address_snapshot=[],
                dhcp_enabled=False, ztp_enabled=False,
            )
            self.assertEqual((), plan.listener_names)
            self.assertEqual((), plan.endpoint_ips)

    def test_enabled_header_only_csv_is_not_a_runnable_dhcp_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "02-dhcp-subnet_config.csv"
            source.write_text(HEADER, encoding="utf-8")
            with self.assertRaisesRegex(RUNTIME.RuntimeContractError, "subnet row"):
                RUNTIME.plan_dhcp_runtime(
                    source, link_snapshot=[], address_snapshot=[],
                    dhcp_enabled=True, ztp_enabled=False,
                )

    def test_delimiter_only_record_is_not_a_blank_physical_line(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "02-dhcp-subnet_config.csv"
            source.write_text(HEADER + ",,,,,,,,\n", encoding="utf-8")
            with self.assertRaisesRegex(RUNTIME.RuntimeContractError, "empty delimiter"):
                RUNTIME._read_dhcp_networks(source)

    def test_symlink_csv_cannot_supply_runtime_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.csv"
            target.write_text(HEADER, encoding="utf-8")
            source = Path(directory) / "02-dhcp-subnet_config.csv"
            source.symlink_to(target.name)
            with self.assertRaisesRegex(RUNTIME.RuntimeContractError, "non-symlink"):
                RUNTIME._read_dhcp_networks(source)

    def test_docker_reads_explicit_modes_from_current_global(self):
        with tempfile.TemporaryDirectory() as directory:
            project = self._project(
                Path(directory), dhcp="disabled", ztp="disabled",
            )
            settings = SimpleNamespace(project_dir=project)
            self.assertEqual(
                (False, False), ACTIVATE.current_project_dhcp_ztp_modes(settings),
            )
            global_file = project / "01-global.yaml"
            global_file.write_text(
                global_file.read_text(encoding="utf-8").replace(
                    "ztp:\n      status: disabled", "ztp:\n      status: enabled",
                ), encoding="utf-8",
            )
            with self.assertRaisesRegex(ACTIVATE.ActivationError, "DHCP disabled.*ZTP enabled"):
                ACTIVATE.current_project_dhcp_ztp_modes(settings)

    def test_docker_and_runtime_share_disabled_header_only_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            project = self._project(
                Path(directory), dhcp="disabled", ztp="disabled",
            )
            settings = SimpleNamespace(
                project_dir=project,
                subnet_csv=project / "02-dhcp-subnet_config.csv",
                http_root=ROOT, allowlist=(), relay_ingress=(),
            )
            with mock.patch.object(ACTIVATE, "validate_project_mount"), \
                    mock.patch.object(
                        ACTIVATE, "capture_stable_network_snapshot",
                        return_value=([], []),
                    ), mock.patch.object(
                        ACTIVATE, "_load_runtime_module", return_value=RUNTIME,
                    ), mock.patch.object(
                        RUNTIME, "plan_dhcp_runtime",
                        wraps=RUNTIME.plan_dhcp_runtime,
                    ) as planner:
                selected, _links, _addresses, runtime = ACTIVATE.build_runtime_plan(settings)
            self.assertIs(RUNTIME, runtime)
            self.assertEqual((), selected.listener_names)
            self.assertEqual((), selected.endpoint_ips)
            self.assertIs(False, planner.call_args.kwargs["dhcp_enabled"])
            self.assertIs(False, planner.call_args.kwargs["ztp_enabled"])


if __name__ == "__main__":
    unittest.main()
