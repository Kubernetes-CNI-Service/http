#!/usr/bin/env python3
"""Cross-script Phase-C proof that ``eth_jump`` produces zero configuration."""

from __future__ import annotations

import contextlib
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from test_cases.module_loader import load_script
from test_cases.test_eth_jump_zero_config_contract import (
    BACKUP,
    DIAGNOSTICS,
    GATE,
    GENERATOR,
    HTML,
    MONITOR,
    SETUP,
    jump_row,
    write_devices,
)
from test_cases.test_mlag_evpn_generation import (
    prepare_schema_v1_collision_generator,
)


ROOT = Path(__file__).resolve().parents[1]
LOAD = load_script("eth_jump_zero_workflow_load", ROOT / "DAY0-Prepare/11-load.py")


class EthJumpZeroConfigWorkflowTests(unittest.TestCase):
    def test_generator_native_handoff_is_accepted_by_real_linux_load_parser(self):
        guidance = "\n".join(GENERATOR._production_handoff_rows(lambda text="": text))
        command = next(
            line.strip() for line in guidance.splitlines()
            if line.strip().startswith("sudo python3 DAY0-Prepare/11-load.py")
        )
        words = shlex.split(command)
        self.assertEqual(
            ["sudo", "python3", "DAY0-Prepare/11-load.py"], words[:3],
        )
        parsed = LOAD.parse_args(words[3:])
        self.assertEqual("DAY0-Prepare/<project>", str(parsed.project))
        self.assertEqual(
            "management-server", LOAD.resolve_host_role(parsed.host_role, "linux"),
        )
        missing_role = [
            word for word in words[3:]
            if word != "--host-role=management-server"
        ]
        with self.assertRaisesRegex(LOAD.LoadError, "Linux requires explicit --host-role"):
            LOAD.resolve_host_role(LOAD.parse_args(missing_role).host_role, "linux")

    def test_schema_admission_is_bound_to_complete_monitor_exclusion(self):
        with tempfile.TemporaryDirectory() as name:
            project = Path(name)
            inventory = project / "02-devices_config.csv"
            leases = project / "dhcpd.leases"
            leases.write_text("", encoding="utf-8")
            write_devices(inventory, [jump_row()])

            self.assertEqual(frozenset({"eth_jump"}), LOAD.load_device_types(inventory))
            errors, warnings = SETUP._validate_eth_csv(str(inventory))
            self.assertEqual(([], []), (errors, warnings))
            self.assertEqual([], MONITOR.read_devices(inventory, dhcp_leases=leases))
            self.assertEqual([], BACKUP.load_devices_csv(str(inventory)))
            self.assertEqual((), GATE.project_inventory_targets(str(project), "all"))
            for types in ({"eth", "eth_spx", "spx"}, {"ib"}, {"nvl"}):
                self.assertEqual([], HTML.read_host_csv(inventory, types))
            with self.assertRaises(DIAGNOSTICS.DiagnosticError):
                DIAGNOSTICS.select_devices({"devices": [{
                    "hostname": "EXAMPLE-JUMP01", "type": "eth_jump",
                    "environment": "production",
                }]}, ["EXAMPLE-JUMP01"], "all")

    def test_html_omits_jump_from_every_runtime_placeholder_family(self):
        runtime_cases = (
            ("cumulus", True),
            ("nvos", False),
            ("unknown", False),
        )
        for platform, managed in runtime_cases:
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                inventory = root / "02-devices_config.csv"
                write_devices(inventory, [jump_row()])
                output = root / "monitor.html"
                runtime_device = {
                    "hostname": "EXAMPLE-JUMP01",
                    "type": "eth_jump",
                    "environment": "production",
                    "unbound_identity": True,
                    "managed_ztp": managed,
                    "platform_family": platform,
                    "ip": "192.0.2.10",
                    "mac": "02:00:00:00:00:10",
                }
                missing = root / "missing"
                patches = {
                    "DEVICES_CSV": inventory,
                    "ETH_LOG": inventory,
                    "IB_LOG": inventory,
                    "NV_LOG": inventory,
                    "OUTPUT": output,
                    "LOG_FILE": root / "generate.log",
                    "GENERATION_LOCK": root / ".lock",
                    "ETH_INFO_DIR": missing / "eth-info",
                    "SPX_LINK_DIR": missing / "spx-link",
                    "IB_INFO_DIR": missing / "ib-info",
                    "IBL_LINK_DIR": missing / "ib-link",
                    "NV_INFO_DIR": missing / "nvsw-info",
                    "NVL_LINK_DIR": missing / "nvsw-link",
                    "P2P_OUTPUT_DIR": missing / "p2p",
                    "ZTP_STATUS_DIR": missing / "ztp-status",
                }
                with contextlib.ExitStack() as stack:
                    for key, value in patches.items():
                        stack.enter_context(mock.patch.object(HTML, key, value))
                    stack.enter_context(mock.patch.object(
                        HTML, "load_dynamic_air_inventory", return_value=[],
                    ))
                    stack.enter_context(mock.patch.object(
                        HTML, "load_ztp_status", return_value={
                            "available": True, "source": "fixture",
                            "devices": [runtime_device],
                        },
                    ))
                    HTML._generate_monitor_html("prod")
                rendered = output.read_text(encoding="utf-8")
                self.assertFalse(
                    "EXAMPLE-JUMP01" in rendered,
                    f"eth_jump hostname leaked into {platform} HTML placeholder path",
                )

    def test_three_real_collectors_never_deploy_sw_info_to_jump(self):
        cases = (
            ("ethernet/monitor", "eth.csv", "eth"),
            ("infiniband/monitor", "ib.csv", "ib"),
            ("nvlink/monitor", "nvsw.csv", "nvl"),
        )
        for family, csv_name, type_filter in cases:
            with self.subTest(family=family), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                monitor = root / family
                monitor.mkdir(parents=True)
                shutil.copy2(ROOT / "ethernet/monitor/cron.sh", monitor / "cron.sh")
                write_devices(monitor / csv_name, [jump_row()])
                completed = subprocess.run(
                    ["bash", "-x", str(monitor / "cron.sh"), "--type", type_filter],
                    cwd=monitor, text=True, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, timeout=15, check=False,
                    errors="replace",
                )
                self.assertEqual(1, completed.returncode, completed.stdout)
                trace_lines = [
                    line for line in completed.stdout.splitlines()
                    if line.startswith("+")
                ]
                self.assertFalse(
                    any("scp " in line and "sw-info.sh" in line for line in trace_lines),
                    completed.stdout,
                )

    def test_html_omits_jump_from_cross_environment_archive_placeholder(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            inventory = root / "02-devices_config.csv"
            write_devices(inventory, [jump_row()])
            output = root / "monitor.html"
            missing = root / "missing"
            runtime_device = {
                "hostname": "EXAMPLE-JUMP01", "type": "eth_jump",
                "environment": "production", "unbound_identity": True,
                "managed_ztp": True, "platform_family": "cumulus",
                "ip": "192.0.2.10", "mac": "02:00:00:00:00:10",
            }
            patches = {
                "DEVICES_CSV": inventory, "ETH_LOG": inventory,
                "IB_LOG": inventory, "NV_LOG": inventory, "OUTPUT": output,
                "LOG_FILE": root / "generate.log", "GENERATION_LOCK": root / ".lock",
                "ETH_INFO_DIR": root / "eth-info", "SPX_LINK_DIR": missing / "spx-link",
                "IB_INFO_DIR": missing / "ib-info", "IBL_LINK_DIR": missing / "ib-link",
                "NV_INFO_DIR": missing / "nvsw-info", "NVL_LINK_DIR": missing / "nvsw-link",
                "P2P_OUTPUT_DIR": missing / "p2p", "ZTP_STATUS_DIR": missing / "ztp-status",
            }
            patches["ETH_INFO_DIR"].mkdir()
            with contextlib.ExitStack() as stack:
                for key, value in patches.items():
                    stack.enter_context(mock.patch.object(HTML, key, value))
                stack.enter_context(mock.patch.object(
                    HTML, "load_dynamic_air_inventory", return_value=[],
                ))
                stack.enter_context(mock.patch.object(
                    HTML, "load_ztp_status", return_value={
                        "available": True, "source": "fixture", "devices": [runtime_device],
                    },
                ))
                stack.enter_context(mock.patch.object(
                    HTML, "find_latest_eth_tars",
                    return_value={"air": root / "air-fixture.tar.gz"},
                ))
                stack.enter_context(mock.patch.object(
                    HTML, "extract_info_files", return_value={},
                ))
                HTML._generate_monitor_html("all")
            self.assertNotIn("EXAMPLE-JUMP01", output.read_text(encoding="utf-8"))

    def test_both_generator_passes_count_but_never_render_jump_host(self):
        for branch in ("eth", "ib"):
            with self.subTest(branch=branch), tempfile.TemporaryDirectory() as name:
                script, _devices, template_dir = prepare_schema_v1_collision_generator(
                    Path(name)
                )
                shutil.copy2(
                    ROOT / "ztp/dynamic_air_inventory.py",
                    Path(name) / "ztp/dynamic_air_inventory.py",
                )
                write_devices(template_dir / "02-devices_config.csv", [jump_row()])

                completed = subprocess.run(
                    [sys.executable, "-B", str(script), "--branch", branch, "-y"],
                    cwd=template_dir,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    timeout=30,
                    check=False,
                )
                self.assertEqual(0, completed.returncode, completed.stdout)
                self.assertIn("type=eth_jump: 1", completed.stdout)
                outputs = [
                    path for path in template_dir.rglob("*")
                    if path.is_file()
                    and ("99-output" in path.parts or path.name == "91-devices.yaml")
                ]
                self.assertFalse(
                    any("EXAMPLE-JUMP01" in path.read_text(encoding="utf-8") for path in outputs),
                    outputs,
                )
                self.assertFalse(
                    any(path.name == "EXAMPLE-JUMP01.yaml" for path in outputs),
                    outputs,
                )

    def test_load_does_not_dispatch_a_generator_for_jump_only_inventory(self):
        commands: list[list[str]] = []

        def record(command, **_kwargs):
            commands.append([str(item) for item in command])

        with mock.patch.object(LOAD, "run", side_effect=record), mock.patch.object(
            LOAD, "_device_types_after_dhcp", return_value=frozenset({"eth_jump"}),
        ):
            LOAD.generate_configs(
                frozenset({"eth_jump"}),
                install_dhcp=False,
                dry_run=False,
            )

        basenames = [Path(command[1]).name for command in commands if len(command) > 1]
        self.assertIn("c1-generate_dhcp.py", basenames)
        self.assertNotIn("90-c2-generate_configs.py", basenames)
        self.assertNotIn("d-hostname2mac.py", basenames)

    def test_nvos_entry_is_a_byte_identical_canonical_alias(self):
        canonical = ROOT / "ztp/config/cumulus/template/90-c2-generate_configs.py"
        nvos = ROOT / "ztp/config/nvos/template/90-c2-generate_configs.py"
        self.assertTrue(nvos.is_symlink())
        self.assertEqual(canonical.resolve(), nvos.resolve())
        self.assertEqual(canonical.read_bytes(), nvos.read_bytes())

    def test_monitor_and_backup_share_the_jump_zero_row_boundary(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            csv_path = root / "02-devices_config.csv"
            leases = root / "dhcpd.leases"
            leases.write_text("", encoding="utf-8")
            write_devices(csv_path, [jump_row()])

            self.assertEqual([], MONITOR.read_devices(csv_path, dhcp_leases=leases))
            self.assertEqual([], BACKUP.load_devices_csv(str(csv_path)))


if __name__ == "__main__":
    unittest.main()
