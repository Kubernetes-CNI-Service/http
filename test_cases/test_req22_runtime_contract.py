"""Independent REQ22 DHCP runtime input and mode expectations."""

from __future__ import annotations

import ast
import hashlib
import inspect
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

    def test_dhcp_exec_revalidation_carries_current_explicit_modes(self):
        tree = ast.parse(inspect.getsource(ACTIVATE.exec_managed_service))
        calls = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "revalidate_dhcp_runtime_plan"
        ]
        self.assertEqual(1, len(calls))
        keywords = {item.arg for item in calls[0].keywords}
        self.assertIn("dhcp_enabled", keywords)
        self.assertIn("ztp_enabled", keywords)

    def test_docker_observation_rejects_same_size_csv_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = self._project(root, dhcp="disabled", ztp="disabled")
            source = project / "02-dhcp-subnet_config.csv"
            replacement = project / "replacement.csv"
            source.write_text(HEADER + " \n", encoding="utf-8")
            replacement.write_text(HEADER + "\t\n", encoding="utf-8")
            self.assertEqual(source.stat().st_size, replacement.stat().st_size)
            settings = ACTIVATE.Settings(
                project_name="fixture", scope="prod", http_root=root,
                state_root=root / "state", log_root=root / "log",
                apache_listeners=root / "apache.conf",
            )

            def replace_after_parse(*_args):
                source.rename(project / "old-subnet.csv")
                replacement.rename(source)
                selected = SimpleNamespace(endpoint_ips=())
                return selected, [], [], SimpleNamespace()

            with mock.patch.object(
                ACTIVATE, "build_runtime_plan", side_effect=replace_after_parse,
            ), mock.patch.object(
                ACTIVATE, "runtime_plan_payload", return_value={},
            ), mock.patch.object(ACTIVATE, "_atomic_write") as write:
                with self.assertRaisesRegex(ACTIVATE.ActivationError, "subnet.*changed"):
                    ACTIVATE.observe_runtime(settings)
            write.assert_not_called()
            self.assertFalse(settings.state_root.exists())

    def test_parent_hash_accepts_only_receipt_proven_empty_host_file(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "dhcpd_ib.hosts"
            output.write_bytes(b"")
            with self.assertRaises(ACTIVATE.ActivationError):
                ACTIVATE.sha256_path(output)
            self.assertEqual(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                ACTIVATE.sha256_path(
                    output, allow_empty=True, expected_host_count=0,
                ),
            )
            output.write_text("host sw1 {\n}\n", encoding="utf-8")
            with self.assertRaises(ACTIVATE.ActivationError):
                ACTIVATE.sha256_path(
                    output, allow_empty=True, expected_host_count=0,
                )
            self.assertEqual(
                hashlib.sha256(b"host sw1 {\n}\n").hexdigest(),
                ACTIVATE.sha256_path(output, expected_host_count=1),
            )

    def test_docker_prepare_rejects_invalid_subnet_before_runtime_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = self._project(root, dhcp="disabled", ztp="disabled")
            (project / "02-dhcp-subnet_config.csv").write_bytes(b"")
            settings = ACTIVATE.Settings(
                project_name="fixture", scope="prod", http_root=root,
                state_root=root / "state", log_root=root / "log",
                apache_listeners=root / "apache.conf",
            )
            with mock.patch.object(
                ACTIVATE, "ensure_runtime_directories",
            ) as mkdir, mock.patch.object(
                ACTIVATE, "_atomic_write",
            ) as write, mock.patch.object(
                ACTIVATE, "build_runtime_plan",
            ) as planner:
                with self.assertRaises(ACTIVATE.ActivationError):
                    ACTIVATE.prepare_runtime(settings)
            mkdir.assert_not_called()
            write.assert_not_called()
            planner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
