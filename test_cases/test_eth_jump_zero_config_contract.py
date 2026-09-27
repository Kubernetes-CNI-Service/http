#!/usr/bin/env python3
"""Direct Phase-C contracts for configuration-inert ``eth_jump`` rows."""

from __future__ import annotations

import contextlib
import csv
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
LOAD = load_script("eth_jump_zero_load", ROOT / "DAY0-Prepare/11-load.py")
SETUP = load_script("eth_jump_zero_setup", ROOT / "DAY0-Prepare/01-a-setup.py")
GENERATOR = load_script(
    "eth_jump_zero_generator",
    ROOT / "ztp/config/cumulus/template/90-c2-generate_configs.py",
)
DHCP = load_script(
    "eth_jump_zero_dhcp",
    ROOT / "ztp/config/isc-dhcp-server/c1-generate_dhcp.py",
)
PUBLISHER = load_script(
    "eth_jump_zero_publisher",
    ROOT / "ztp/config/cumulus/d-hostname2mac.py",
)
MANUAL = load_script("eth_jump_zero_manual", ROOT / "ztp/manual-ztp.py")
MONITOR = load_script(
    "eth_jump_zero_monitor", ROOT / "DAY0-Prepare/12-ztp-monitor.py",
)
BACKUP = load_script(
    "eth_jump_zero_backup", ROOT / "ztp/backup/yaml-collect.py",
)
HTML = load_script(
    "eth_jump_zero_html", ROOT / "monitor/generate-monitor-html.py",
)
GATE = load_script(
    "switch_collection_gate", ROOT / "monitor/switch_collection_gate.py",
)
WORKER = load_script(
    "eth_jump_zero_worker", ROOT / "monitor/switch-collection-worker.py",
)
DIAGNOSTICS = load_script(
    "eth_jump_zero_diagnostics", ROOT / "tools/collect-ztp-diagnostics.py",
)


DEVICE_HEADER = (
    "hostname", "type", "template", "eth0_ip", "netmask", "eth0_gw",
    "eth0_mac", "eth1_ip", "netmask", "eth1_gw", "eth1_mac", "lo_ip",
    "vrf_default", "vlan_id", "svi_ip", "netmask", "vrr_ip", "vrr_mac",
    "vlan_ports", "bgp_asn", "bgp_ports", "bond_ports", "bond_type",
    "bond_mac", "peerlink_ports", "vrl", "evpn_vrf", "evpn_l3vni",
    "evpn_l3vlan", "dhcp_relay", "evpn_l2vni", "evpn_l2vlan", "svi_ip",
    "netmask", "vrr_ip", "vrr_mac", "vlan_ports",
)
CONFIG_ONLY_FIELDS = (
    "lo_ip", "vrf_default", "vlan_id", "svi_ip", "vrr_ip", "vrr_mac",
    "vlan_ports", "bgp_asn", "bgp_ports", "bond_ports", "bond_type",
    "bond_mac", "peerlink_ports", "vrl", "evpn_vrf", "evpn_l3vni",
    "evpn_l3vlan", "dhcp_relay", "evpn_l2vni", "evpn_l2vlan",
)


def jump_row(*, template: str = "NA", field: str | None = None) -> list[str]:
    row = ["NA"] * len(DEVICE_HEADER)
    row[0:7] = [
        "EXAMPLE-JUMP01", "eth_jump", template, "192.0.2.10", "24",
        "192.0.2.1", "02:00:00:00:00:10",
    ]
    if field is not None:
        row[DEVICE_HEADER.index(field)] = "1"
    return row


def write_devices(path: Path, rows: list[list[str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as stream:
        csv.writer(stream).writerows((DEVICE_HEADER, *rows))


class EthJumpZeroConfigContractTests(unittest.TestCase):
    def test_generator_native_handoff_requires_explicit_server_role(self):
        guidance = "\n".join(GENERATOR._production_handoff_rows(lambda text="": text))
        native = next(
            line.strip() for line in guidance.splitlines()
            if line.strip().startswith("sudo python3 DAY0-Prepare/11-load.py")
        )
        self.assertEqual(
            "sudo python3 DAY0-Prepare/11-load.py DAY0-Prepare/<project> "
            "--host-role=management-server", native,
        )
        for command in (
            "sudo ./infra/docker/deploy.sh deploy",
            "sudo ./infra/docker/deploy.sh deploy-preloaded <IMAGE_ID>",
            "sudo ./infra/docker/deploy.sh load",
        ):
            self.assertIn(command, guidance)

    def test_collector_parser_leaves_all_four_lanes_empty_for_jump(self):
        source = (ROOT / "ethernet/monitor/cron.sh").read_text(encoding="utf-8")
        start = source.index("parse_csv_hosts() {")
        end = source.index("\n# ── Phase 1", start)
        parser = source[start:end]
        cases = {
            "eth.csv": ("", "ethernet", "eth", "eth_spx", "spx", "air"),
            "ib.csv": ("", "ib"),
            "nvsw.csv": ("", "nvl"),
        }
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            for csv_name, filters in cases.items():
                for type_filter in filters:
                    with self.subTest(csv=csv_name, type_filter=type_filter):
                        for old in ("eth.csv", "ib.csv", "nvsw.csv"):
                            (root / old).unlink(missing_ok=True)
                        write_devices(root / csv_name, [jump_row()])
                        outputs = [root / item for item in ("ETH", "SPX", "IB", "NV")]
                        for output in outputs:
                            output.write_text("", encoding="utf-8")
                        harness = "\n".join((
                            "set -u",
                            f"BASE={str(root)!r}",
                            f"TYPE_FILTER={type_filter!r}",
                            "COLLECTION_ENV=prod",
                            "DYNAMIC_AIR_DISCOVERED=0",
                            *(f"{key}={str(path)!r}" for key, path in zip(
                                ("ETH", "SPX", "IB", "NV"), outputs
                            )),
                            "log() { :; }",
                            "append_dynamic_air_hosts() { :; }",
                            "append_unbound_prod_cumulus_hosts() { :; }",
                            parser,
                            "parse_csv_hosts",
                        ))
                        completed = subprocess.run(
                            ["bash", "-c", harness], text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            check=False,
                        )
                        self.assertEqual(1, completed.returncode, completed.stderr)
                        self.assertTrue(all(path.read_bytes() == b"" for path in outputs))

    def test_collector_parser_rejects_jump_as_a_type_filter(self):
        source = (ROOT / "ethernet/monitor/cron.sh").read_text(encoding="utf-8")
        start = source.index("parse_csv_hosts() {")
        end = source.index("\n# ── Phase 1", start)
        parser = source[start:end]
        for csv_name in ("eth.csv", "ib.csv", "nvsw.csv"):
            with self.subTest(csv=csv_name), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                write_devices(root / csv_name, [jump_row()])
                outputs = [root / item for item in ("ETH", "SPX", "IB", "NV")]
                for output in outputs:
                    output.write_text("", encoding="utf-8")
                harness = "\n".join((
                    f"BASE={str(root)!r}",
                    "TYPE_FILTER=eth_jump",
                    "COLLECTION_ENV=prod",
                    "DYNAMIC_AIR_DISCOVERED=0",
                    *(f"{key}={str(path)!r}" for key, path in zip(
                        ("ETH", "SPX", "IB", "NV"), outputs
                    )),
                    "log() { printf '%s\\n' \"$*\" >&2; }",
                    "append_dynamic_air_hosts() { :; }",
                    "append_unbound_prod_cumulus_hosts() { :; }",
                    parser,
                    "parse_csv_hosts",
                ))
                completed = subprocess.run(
                    ["bash", "-c", harness], text=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertEqual(1, completed.returncode)
                self.assertIn("incompatible", completed.stderr)
                self.assertTrue(all(path.read_bytes() == b"" for path in outputs))

    def test_safe_row_is_admitted_by_both_phase_c_schema_gates(self):
        with tempfile.TemporaryDirectory() as name:
            csv_path = Path(name) / "02-devices_config.csv"
            write_devices(csv_path, [jump_row()])

            self.assertEqual(
                frozenset({"eth_jump"}),
                LOAD.load_device_types(csv_path),
            )
            errors, warnings = SETUP._validate_eth_csv(str(csv_path))
            self.assertEqual([], errors)
            self.assertEqual([], warnings)

    def test_configuration_intent_is_rejected_by_both_schema_gates(self):
        cases = (("template", "border"),) + tuple(
            (field, None) for field in CONFIG_ONLY_FIELDS
        )
        for field, template in cases:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as name:
                csv_path = Path(name) / "02-devices_config.csv"
                row = jump_row(
                    template=template or "NA",
                    field=None if field == "template" else field,
                )
                write_devices(csv_path, [row])

                with self.assertRaisesRegex(
                    LOAD.LoadError, rf"eth_jump.*{field}.*配置意图冲突"
                ):
                    LOAD.load_device_types(csv_path)
                errors, _warnings = SETUP._validate_eth_csv(str(csv_path))
                self.assertTrue(
                    any(
                        "eth_jump" in error
                        and field in error
                        and "配置意图冲突" in error
                        for error in errors
                    ),
                    errors,
                )

    def test_generator_exclusion_is_explicit_future_proofing(self):
        self.assertTrue(GENERATOR._exclude_config_type("air"))
        self.assertTrue(GENERATOR._exclude_config_type("eth_jump"))
        self.assertFalse(GENERATOR._exclude_config_type("eth"))

    def test_ib_pass_counts_and_names_each_actual_excluded_type(self):
        with tempfile.TemporaryDirectory() as name:
            csv_path = Path(name) / "02-devices_config.csv"
            air = jump_row()
            air[0], air[1] = "AIR-EXAMPLE01", "air"
            write_devices(csv_path, [air, jump_row()])
            output = io.StringIO()
            with mock.patch.object(
                GENERATOR, "_CSV_FILE", str(csv_path),
            ), mock.patch.object(
                GENERATOR, "_load_global_document", return_value=({}, 1),
            ), contextlib.redirect_stdout(output):
                devices, errors = GENERATOR._load_csv_ib()

            self.assertEqual([], devices)
            self.assertEqual([], errors)
            report = output.getvalue()
            self.assertIn("type=air: 1", report)
            self.assertIn("type=eth_jump: 1", report)

    def test_dhcp_ztp_and_reset_consumers_emit_no_jump_row(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            csv_path = root / "02-devices_config.csv"
            leases = root / "dhcpd.leases"
            leases.write_text("", encoding="utf-8")
            write_devices(csv_path, [jump_row()])

            self.assertEqual([], DHCP.load_csv(str(csv_path)))
            self.assertEqual({}, PUBLISHER.load_csv(str(csv_path)))
            self.assertEqual(
                [], MANUAL.read_devices(csv_path, dhcp_leases=leases),
                "manual ZTP/reset inventory must contain no eth_jump row",
            )

    def test_monitor_inventory_emits_no_jump_row(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            csv_path = root / "02-devices_config.csv"
            leases = root / "dhcpd.leases"
            leases.write_text("", encoding="utf-8")
            write_devices(csv_path, [jump_row()])

            self.assertEqual(
                [],
                MONITOR.read_devices(csv_path, dhcp_leases=leases),
                "monitor inventory must contain no eth_jump row",
            )

    def test_backup_inventory_emits_no_jump_row(self):
        with tempfile.TemporaryDirectory() as name:
            csv_path = Path(name) / "02-devices_config.csv"
            write_devices(csv_path, [jump_row()])

            self.assertEqual(
                [],
                BACKUP.load_devices_csv(str(csv_path)),
                "backup inventory must contain no eth_jump row",
            )

    def test_html_inventory_filters_jump_from_all_three_missing_lanes(self):
        with tempfile.TemporaryDirectory() as name:
            csv_path = Path(name) / "02-devices_config.csv"
            write_devices(csv_path, [jump_row()])
            for types in ({"eth", "eth_spx", "spx"}, {"ib"}, {"nvl"}):
                with self.subTest(types=types):
                    self.assertEqual([], HTML.read_host_csv(csv_path, types))

    def test_jump_only_project_never_dispatches_yaml_backup(self):
        class AllowedGate:
            def __init__(self, *_args, **_kwargs):
                self.decision = type("Decision", (), {"allowed": True})()
                self.cooldown_seconds = 600

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def mark_success(self):
                return "fixture-success"

        success = {
            "schema_version": 1, "task": "yaml_backup", "state": "success",
            "planned": 1, "succeeded": 1, "failed_count": 0,
            "failed_devices": [],
        }
        with tempfile.TemporaryDirectory() as name:
            project = Path(name)
            write_devices(project / "02-devices_config.csv", [jump_row()])
            for scope in ("prod", "air", "all"):
                with self.subTest(scope=scope):
                    self.assertEqual(
                        (), GATE.project_inventory_targets(str(project), scope),
                        "the collection gate must expose no governed jump target",
                    )
                    runner = mock.Mock(return_value=({
                        "returncode": 0,
                        "stdout": WORKER.TASK_RESULT_PREFIX + json.dumps(success) + "\n",
                        "stderr": "",
                    }, False))
                    with mock.patch.object(
                        WORKER, "active_project_identity", return_value=str(project),
                    ), mock.patch.object(
                        WORKER, "CollectionGate", AllowedGate,
                    ), mock.patch.object(
                        WORKER, "YAML_BACKUP_SCRIPT", ROOT / "ztp/backup/yaml-collect.py",
                    ), mock.patch.object(
                        WORKER, "run_interruptible", runner,
                    ), mock.patch.object(WORKER, "write_yaml_backup_status"):
                        self.assertTrue(WORKER.run_yaml_backup("secret", scope, 30, 0))
                    runner.assert_not_called()

    def test_diagnostics_rejects_explicit_jump_target(self):
        report = {
            "devices": [{
                "hostname": "EXAMPLE-JUMP01", "type": "eth_jump",
                "environment": "production",
            }],
        }
        with self.assertRaisesRegex(
            DIAGNOSTICS.DiagnosticError, "not unique in current prod report",
        ):
            DIAGNOSTICS.select_devices(report, ["EXAMPLE-JUMP01"], "prod")


if __name__ == "__main__":
    unittest.main()
