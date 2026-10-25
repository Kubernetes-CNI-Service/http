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


INITIAL = load_script(
    "i19_inventory_initial",
    ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py",
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


def public_ib_row():
    row = [""] * len(DEVICE_HEADER)
    row[:7] = [
        "EXAMPLE-IB01", "ib", "NA", "198.51.100.2", "24",
        "198.51.100.1", "02:00:00:00:00:02",
    ]
    return row


def public_jump_row(*, populated=False):
    row = [""] * len(DEVICE_HEADER)
    row[:3] = ["EXAMPLE-JUMP01", "eth_jump", ""]
    if populated:
        # Not a real template. Admission/rendering must not try to read it.
        row[:7] = [
            "EXAMPLE-JUMP01", "eth_jump", "INVENTORY-ONLY-NOT-A-TEMPLATE",
            "192.0.2.10", "24", "192.0.2.1", "02:00:00:00:00:10",
        ]
        values = {
            "eth1_ip": "192.0.2.20", "eth1_gw": "192.0.2.1",
            "eth1_mac": "02:00:00:00:00:20", "lo_ip": "203.0.113.10/32",
            "vrf_default": "inventory-vrf", "vlan_id": "100/200",
            "svi_ip": "203.0.113.1", "vrr_ip": "203.0.113.254",
            "vrr_mac": "02:00:00:00:01:fe", "vlan_ports": "swp1-2",
            "bgp_asn": "65010", "bgp_ports": "swp3", "bond_ports": "bond4-5",
            "bond_type": "localbond", "bond_mac": "02:00:00:00:02:10",
            "peerlink_ports": "swp49-50", "vrl": "false",
            "evpn_vrf": "inventory-evpn", "evpn_l3vni": "10010",
            "evpn_l3vlan": "1010", "dhcp_relay": "false",
            "evpn_l2vni": "10200", "evpn_l2vlan": "200",
        }
        for index, field in enumerate(DEVICE_HEADER):
            if field in values:
                row[index] = values[field]
            elif field == "netmask":
                row[index] = "24"
    return row


def write_inventory(path, jump):
    write_devices(path, [public_ib_row(), jump])



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

    def test_inventory_metadata_is_not_configuration_intent(self):
        populated = public_jump_row(populated=True)
        for field in ("template", *CONFIG_ONLY_FIELDS):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as name:
                csv_path = Path(name) / "02-devices_config.csv"
                row = jump_row()
                row[DEVICE_HEADER.index(field)] = populated[DEVICE_HEADER.index(field)]
                write_devices(csv_path, [row])
                self.assertEqual(frozenset({"eth_jump"}), LOAD.load_device_types(csv_path))
                self.assertEqual(([], []), SETUP._validate_eth_csv(str(csv_path)))

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


    def test_blank_inventory_is_admitted_by_three_real_inputs(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "02-devices_config.csv"
            write_inventory(path, public_jump_row())
            self.assertEqual(frozenset({"ib", "eth_jump"}), LOAD.load_device_types(path))
            self.assertEqual(([], []), SETUP._validate_eth_csv(str(path)))
            ib, transit = INITIAL.load_devices(path)
            self.assertEqual({"example-ib01"}, set(ib))
            self.assertEqual({"example-jump01"}, set(transit))
            self.assertEqual("eth_jump", transit["example-jump01"].dev_type)
            self.assertEqual("", transit["example-jump01"].login_ip)
            self.assertEqual("", transit["example-jump01"].eth0_mac)


    def test_populated_metadata_is_not_a_template_or_config_request(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "02-devices_config.csv"
            write_inventory(path, public_jump_row(populated=True))
            self.assertEqual(frozenset({"ib", "eth_jump"}), LOAD.load_device_types(path))
            self.assertEqual(([], []), SETUP._validate_eth_csv(str(path)))
            _ib, transit = INITIAL.load_devices(path)
            self.assertEqual("192.0.2.10", transit["example-jump01"].login_ip)
            self.assertFalse((Path(name) / "INVENTORY-ONLY-NOT-A-TEMPLATE").exists())


    def test_filled_invalid_typed_values_are_rejected_not_ignored(self):
        # Independent (physical 0-based column, field occurrence, invalid literal).
        cases = (
            (3, "eth0_ip", "not-an-ip"),
            (4, "netmask[1]", "255.0.255.0"),
            (5, "eth0_gw", "300.0.0.1"),
            (6, "eth0_mac", "not-a-mac"),
            (7, "eth1_ip", "300.0.0.1"),
            (10, "eth1_mac", "not-a-mac"),
            (11, "lo_ip", "300.1.1.1/32"),
            (13, "vlan_id", "4095"),
            (14, "svi_ip[1]", "300.1.1.1"),
            (16, "vrr_ip[1]", "300.1.1.1"),
            (17, "vrr_mac[1]", "bad-mac"),
            (23, "bond_mac", "bad-mac"),
            (32, "svi_ip[2]", "300.1.1.1"),
            (35, "vrr_mac[2]", "bad-mac"),
        )
        for index, label, value in cases:
            with self.subTest(index=index, field=label), tempfile.TemporaryDirectory() as name:
                path = Path(name) / "02-devices_config.csv"
                row = public_jump_row(populated=True)
                row[index] = value
                write_inventory(path, row)
                with self.assertRaises(LOAD.LoadError) as caught:
                    LOAD.load_device_types(path)
                load_error = str(caught.exception)
                self.assertIn(label, load_error)
                self.assertIn(value, load_error)
                self.assertNotIn("配置意图", load_error)
                errors, _warnings = SETUP._validate_eth_csv(str(path))
                self.assertTrue(any(label in item and value in item for item in errors), errors)
                self.assertFalse(any("配置意图" in item for item in errors), errors)
                with self.assertRaises(INITIAL.SetupError) as caught:
                    INITIAL.load_devices(path)
                self.assertIn(label, str(caught.exception))
                self.assertIn(value, str(caught.exception))


    def test_unknown_jump_spellings_do_not_extend_any_role_registry(self):
        for kind in ("ib_jump", "nvl_jump", "unknown_jump", "jump"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as name:
                path = Path(name) / "02-devices_config.csv"
                # Independent valid identity, distinct from every known row.
                unknown = [""] * len(DEVICE_HEADER)
                unknown[:7] = [
                    "EXAMPLE-UNKNOWN01", kind, "", "192.0.2.40", "24",
                    "192.0.2.1", "02:00:00:00:00:40",
                ]
                write_devices(path, [public_ib_row(), public_jump_row(populated=True), unknown])
                with self.assertRaisesRegex(LOAD.LoadError, rf"type=.*{kind}.*无效"):
                    LOAD.load_device_types(path)
                errors, _warnings = SETUP._validate_eth_csv(str(path))
                self.assertTrue(
                    any("type 无效" in error and kind in error for error in errors),
                    errors,
                )
                _ib, transit = INITIAL.load_devices(path)
                self.assertEqual({"example-jump01"}, set(transit))


    def test_normal_transit_types_do_not_gain_optional_login_address(self):
        for kind in ("eth", "eth_spx", "spx", "ethernet"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as name:
                path = Path(name) / "02-devices_config.csv"
                ordinary = public_jump_row()
                ordinary[1] = kind
                write_inventory(path, ordinary)
                with self.assertRaisesRegex(INITIAL.SetupError, "login address is required"):
                    INITIAL.load_devices(path)


    def test_inventory_without_endpoint_refuses_remote_transport_before_io(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "02-devices_config.csv"
            write_inventory(path, public_jump_row())
            _ib, transit = INITIAL.load_devices(path)
            device = transit["example-jump01"]
            with self.assertRaisesRegex(INITIAL.SetupError, "login address"):
                INITIAL.outer_ssh_command(device, "cumulus", ["hostname"], 3)
            # Existing explicit local mode does not require a remote endpoint.
            self.assertEqual(
                ["hostname"],
                INITIAL.outer_ssh_command(device, "cumulus", ["hostname"], 3, local=True),
            )


    def test_empty_endpoint_guard_is_independent_of_inventory_admission(self):
        jump = INITIAL.Device("EXAMPLE-JUMP01", "eth_jump", "", "", "", "", "", "")
        ib = INITIAL.Device(
            "EXAMPLE-IB01", "ib", "198.51.100.2", "198.51.100.2/24",
            "198.51.100.1", "02:00:00:00:00:02", "", "",
        )
        target = INITIAL.Target(ib, jump, "swp7", "eth0")
        neighbor = INITIAL.Neighbor("fe80::1", "swp7", "02:11:22:33:44:55")
        calls = (
            ("outer", lambda: INITIAL.outer_ssh_command(jump, "cumulus", ["hostname"], 3)),
            ("ethernet", lambda: INITIAL.run_on_ethernet(jump, "cumulus", "PUBLIC", ["hostname"], 3)),
            ("nested", lambda: INITIAL.run_on_ib(
                target, neighbor, "cumulus", "PUBLIC", "admin", "PUBLIC", 3,
                ["nv", "config", "show"],
            )),
            ("ipv4", lambda: INITIAL.verify_ipv4_login(
                target, "default", "cumulus", "PUBLIC", "admin", 3,
            )),
        )
        for label, invoke in calls:
            with self.subTest(caller=label), mock.patch.object(
                INITIAL, "interactive_run", return_value=INITIAL.SessionResult("", 0),
            ) as interactive, mock.patch.object(
                INITIAL, "ethernet_responder", wraps=INITIAL.ethernet_responder,
            ) as responder, mock.patch.object(
                INITIAL, "NestedResponder", wraps=INITIAL.NestedResponder,
            ) as nested:
                with self.assertRaisesRegex(INITIAL.SetupError, "login address"):
                    invoke()
                interactive.assert_not_called()
                responder.assert_not_called()
                nested.assert_not_called()
        self.assertEqual(
            ["hostname"],
            INITIAL.outer_ssh_command(jump, "cumulus", ["hostname"], 3, local=True),
        )


    def test_schema_v2_optional_inventory_and_repeated_fields(self):
        # Independently frozen public schema-2 header: two VLAN groups, one EVPN group.
        header = (
            "hostname", "type", "template", "eth0_ip", "netmask", "eth0_gw",
            "eth0_mac", "eth1_ip", "netmask", "eth1_gw", "eth1_mac", "lo_ip",
            "vlan_id", "svi_ip", "netmask", "vlan_ports",
            "vlan_id", "svi_ip", "netmask", "vlan_ports",
            "bgp_asn", "bgp_ports", "bond_ports", "bond_type", "bond_mac",
            "peerlink_ports", "vrl",
            "evpn_vrf", "evpn_l3vni", "evpn_l3vlan", "dhcp_relay",
            "evpn_l2vni", "evpn_l2vlan", "svi_ip", "netmask", "vlan_ports",
        )
        for populated in (False, True):
            with self.subTest(populated=populated), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                path = root / "02-devices_config.csv"
                (root / "01-global.yaml").write_text("schema_version: 2\n", encoding="utf-8")
                ib = [""] * len(header)
                ib[:7] = ["EXAMPLE-IB01", "ib", "NA", "198.51.100.2", "24",
                          "198.51.100.1", "02:00:00:00:00:02"]
                jump = [""] * len(header)
                jump[:3] = ["EXAMPLE-JUMP01", "eth_jump", ""]
                if populated:
                    jump[2] = "INVENTORY-ONLY-NOT-A-TEMPLATE"
                    jump[12:20] = [
                        "100", "203.0.113.1", "24", "swp1",
                        "200", "203.0.113.2", "24", "swp2",
                    ]
                with path.open("w", newline="", encoding="utf-8") as stream:
                    csv.writer(stream).writerows((header, ib, jump))
                self.assertEqual(
                    frozenset({"ib", "eth_jump"}),
                    LOAD.load_device_types(path, schema_version=2),
                )
                self.assertEqual(([], []), SETUP._validate_eth_csv(str(path)))
                _ib, transit = INITIAL.load_devices(path)
                self.assertEqual({"example-jump01"}, set(transit))
                self.assertEqual("", transit["example-jump01"].login_ip)
                if populated:
                    for index, label, value in (
                        (17, "svi_ip[2]", "300.1.1.1"),
                        (18, "netmask[4]", "255.0.255.0"),
                    ):
                        with self.subTest(index=index):
                            bad = list(jump)
                            bad[index] = value
                            with path.open("w", newline="", encoding="utf-8") as stream:
                                csv.writer(stream).writerows((header, ib, bad))
                            with self.assertRaises(LOAD.LoadError) as caught:
                                LOAD.load_device_types(path, schema_version=2)
                            self.assertIn(label, str(caught.exception))
                            self.assertIn(value, str(caught.exception))
                            self.assertNotIn("配置意图", str(caught.exception))
                            errors, _warnings = SETUP._validate_eth_csv(str(path))
                            self.assertTrue(any(label in e and value in e for e in errors), errors)
                            self.assertFalse(any("配置意图" in e for e in errors), errors)
                            with self.assertRaises(INITIAL.SetupError) as caught:
                                INITIAL.load_devices(path)
                            self.assertIn(label, str(caught.exception))
                            self.assertIn(value, str(caught.exception))


    def test_inventory_bond_mac_groups_validate_each_token_without_companions(self):
        good = "02:00:00:00:04:01|02:00:00:00:04:02"
        bad = "02:00:00:00:04:01|bad-mac"
        self.assertEqual("bond_mac", DEVICE_HEADER[23])
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "02-devices_config.csv"
            row = jump_row()
            row[23] = good
            # No bond_ports/type: inventory syntax does not imply configuration completeness.
            self.assertEqual("NA", row[21])
            self.assertEqual("NA", row[22])
            write_inventory(path, row)
            with self.subTest(stage="good", reader="LOAD"):
                self.assertEqual(frozenset({"ib", "eth_jump"}), LOAD.load_device_types(path))
            with self.subTest(stage="good", reader="SETUP"):
                self.assertEqual(([], []), SETUP._validate_eth_csv(str(path)))
            with self.subTest(stage="good", reader="INITIAL"):
                _ib, transit = INITIAL.load_devices(path)
                self.assertEqual({"example-jump01"}, set(transit))
            placeholder = "NA|02:00:00:00:04:02"
            row[23] = placeholder
            write_inventory(path, row)
            with self.subTest(stage="placeholder", reader="LOAD"):
                self.assertEqual(frozenset({"ib", "eth_jump"}), LOAD.load_device_types(path))
            with self.subTest(stage="placeholder", reader="SETUP"):
                self.assertEqual(([], []), SETUP._validate_eth_csv(str(path)))
            with self.subTest(stage="placeholder", reader="INITIAL"):
                _ib, transit = INITIAL.load_devices(path)
                self.assertEqual({"example-jump01"}, set(transit))
            row[23] = bad
            write_inventory(path, row)
            with self.subTest(stage="bad", reader="LOAD"):
                with self.assertRaises(LOAD.LoadError) as caught:
                    LOAD.load_device_types(path)
                self.assertIn("bond_mac", str(caught.exception))
                self.assertIn(bad, str(caught.exception))
                self.assertNotIn("配置意图", str(caught.exception))
            with self.subTest(stage="bad", reader="SETUP"):
                errors, _warnings = SETUP._validate_eth_csv(str(path))
                self.assertTrue(any("bond_mac" in e and bad in e for e in errors), errors)
                self.assertFalse(any("配置意图" in e for e in errors), errors)
            with self.subTest(stage="bad", reader="INITIAL"):
                with self.assertRaises(INITIAL.SetupError) as caught:
                    INITIAL.load_devices(path)
                self.assertIn("bond_mac", str(caught.exception))
                self.assertIn(bad, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
