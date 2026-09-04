#!/usr/bin/env python3
"""Direct contracts for project schema v2, VRR, native VLANs, and bonds."""

from __future__ import annotations

import copy
from contextlib import redirect_stdout
import csv
import importlib.util
from importlib.machinery import SourceFileLoader
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import project_contract as CONTRACT


VRR_VLAN_100_MAC = ":".join(("02", "00", "5e", "01", "01", "00"))
VRR_VLAN_110_MAC = ":".join(("00", "00", "5e", "00", "00", "6e"))
VRR_VLAN_111_MAC = ":".join(("00", "00", "5e", "00", "00", "6f"))
MLAG_MAC_A = "02:00:00:ff:00:12"
MLAG_MAC_B = "02:00:00:ff:00:34"
EVPN_MAC = "02:00:00:ff:00:56"


def load_script(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(path)))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


GENERATOR = load_script(
    "v2_generator_under_test",
    ROOT / "ztp/config/cumulus/template/90-c2-generate_configs.py",
)
SETUP = load_script(
    "v2_setup_under_test",
    ROOT / "DAY0-Prepare/01-a-setup.py",
)
P2P = load_script(
    "v2_p2p_under_test",
    ROOT / "ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py",
)
FEEDBACK = load_script(
    "v2_feedback_under_test",
    ROOT / "ztp/optimize/feedback.py",
)


class GeneratedYamlMacScalarTests(unittest.TestCase):
    """MAC-shaped YAML scalars must survive render/load/dump as strings."""

    def test_digit_only_mac_stays_string_without_changing_numbers(self):
        mac = "46:38:39:01:01:01"
        rendered = GENERATOR.build_env().from_string(
            "mac-address: {{ mac }}\nautonomous-system: {{ asn }}\n"
            "elapsed: 12:34:56\n"
        ).render(mac=mac, asn=65001)

        self.assertIn(f'mac-address: "{mac}"', rendered)
        document = GENERATOR._load_generated_yaml(rendered)
        self.assertEqual(mac, document["mac-address"])
        self.assertIsInstance(document["mac-address"], str)
        self.assertEqual(65001, document["autonomous-system"])
        self.assertIsInstance(document["autonomous-system"], int)
        self.assertEqual(45296, document["elapsed"])
        self.assertIsInstance(document["elapsed"], int)

        reparsed = yaml.safe_load(GENERATOR._dump_generated_yaml(document))
        self.assertEqual(mac, reparsed["mac-address"])
        self.assertIsInstance(reparsed["mac-address"], str)
        self.assertEqual(65001, reparsed["autonomous-system"])
        self.assertIsInstance(reparsed["autonomous-system"], int)


def v2_header(*, vlan_groups: int = 1, evpn_groups: int = 1) -> list[str]:
    return (
        list(CONTRACT.DEVICE_BASE_COLUMNS)
        + list(CONTRACT.DEVICE_V2_VLAN_COLUMNS) * vlan_groups
        + list(CONTRACT.DEVICE_FIXED_COLUMNS)
        + list(CONTRACT.DEVICE_V2_EVPN_COLUMNS) * evpn_groups
    )


def l2_device(hostname: str, svi: str, vlan: int = 100) -> dict:
    return {
        "hostname": hostname,
        "lo_ip": "198.51.100.1/32",
        "vrfs": [{
            "evpn_vrf": "BLUE",
            "evpn_l3vni": 4001,
            "evpn_l3vlan": 4001,
            "l2vlans": [{
                "vlan_id": vlan,
                "vlan_ids": [vlan],
                "vlan_spec": str(vlan),
                "svi_ip": svi,
                "vrr_ip": "",
                "vrr_mac": "",
                "vlan_ports": [],
            }],
        }],
    }


def v2_mlag_global(shared_addresses=None, *, legacy_pairs=None) -> dict:
    """Return a complete v2 global fixture without deriving expectations."""
    mlag = {"init-delay": 20, "priority": [100, 200]}
    if shared_addresses is not None:
        mlag["shared-addresses"] = copy.deepcopy(shared_addresses)
    if legacy_pairs is not None:
        mlag["pairs"] = copy.deepcopy(legacy_pairs)
    return {
        "schema_version": 2,
        "common": {"mgmt": {"ztp": {"ztp_url_prefix": "/ztp"}}},
        "switches": [{"eth": {
            "version": "5.16.4",
            "bridge": {"domain": {"br_default": {
                "stp": {"priority": 4096},
            }}},
            "vrr": {
                "base_mac": "02:00:5e:01:00:00",
                "gateway_ip": "subnet_maximum",
            },
            "mlag": mlag,
            "system": {
                "aaa": {"user": {"cumulus": {
                    "full-name": "cumulus,,,,",
                    "hashed-password": "'*'",
                }}},
                "date-time": {"timezone": "Etc/UTC"},
                "dns": {"server": ["192.0.2.53"], "vrf": "mgmt"},
                "ntp": {"server": ["192.0.2.123"], "vrf": "mgmt"},
            },
            "vrf": {"default": {"router": {"bfd": {"profile": {
                "bgp-underlay-bfd": {
                    "detect-multiplier": 3,
                    "min-rx-interval": 300,
                    "min-tx-interval": 300,
                },
            }}}}},
        }}],
    }


def v2_redundant_row(
        hostname: str, host_id: int, loopback: str, bond_type: str,
        bond_mac: str, *, vxlan: bool = True, svi_ip: str = "",
        vrf: str = "BLUE", l3_vni: bool | None = None,
        l2_vni: bool | None = None) -> list[str]:
    """Build one fixed-width v2 row with an explicitly referenced bond."""
    has_l3_vni = vxlan if l3_vni is None else l3_vni
    has_l2_vni = vxlan if l2_vni is None else l2_vni
    return [
        hostname, "eth", "border" if bond_type == "mlag" else "tan-leaf",
        f"192.0.2.{host_id}", "24", "192.0.2.1",
        f"02:00:00:00:01:{host_id:02x}", "NA", "NA", "NA", "NA",
        loopback,
        "65001", "swp53", "bond1", bond_type, bond_mac,
        "swp49-50" if bond_type == "mlag" else "NA", "false",
        vrf, "4001" if has_l3_vni else "NA",
        "4001" if has_l3_vni else "NA",
        "NA", "10100" if has_l2_vni else "NA", "100",
        svi_ip or "NA", "24" if svi_ip else "NA", "bond1",
    ]


def generate_v2_redundancy_project(
        rows: list[list[str]], global_document: dict) -> tuple[dict, str]:
    """Run the real generator and require failure to leave no partial model."""
    header = v2_header(vlan_groups=0, evpn_groups=1)
    if any(len(row) != len(header) for row in rows):
        raise AssertionError("fixture row width does not match v2 header")
    output = io.StringIO()
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        global_file = root / "01-global.yaml"
        devices_file = root / "02-devices_config.csv"
        intermediate = root / "91-devices.yaml"
        global_file.write_text(
            yaml.safe_dump(global_document, sort_keys=False), encoding="utf-8",
        )
        with devices_file.open("w", newline="", encoding="utf-8") as stream:
            csv.writer(stream).writerows([header, *rows])
        try:
            with mock.patch.multiple(
                GENERATOR,
                _CSV_FILE=str(devices_file),
                _GLOBAL_FILE=str(global_file),
                DEVICES_FILE=str(intermediate),
            ), mock.patch.object(
                GENERATOR, "_refresh_cumulus_defaults_from_global",
            ), redirect_stdout(output):
                GENERATOR._generate_devices_yaml()
        except BaseException:
            if intermediate.exists():
                raise AssertionError(
                    "failed v2 generation retained a partial 91-devices.yaml"
                )
            raise
        return yaml.safe_load(intermediate.read_text(encoding="utf-8")), output.getvalue()


class SchemaSelectionTests(unittest.TestCase):
    def test_canonical_project_template_starts_new_projects_as_v2(self):
        template = ROOT / "DAY0-Prepare/template"
        document = yaml.safe_load(
            (template / "01-global.yaml").read_text(encoding="utf-8")
        )
        self.assertEqual(2, document["schema_version"])
        eth = next(item["eth"] for item in document["switches"] if "eth" in item)
        self.assertEqual(
            {"base_mac": "02:00:5e:01:00:00", "gateway_ip": "subnet_maximum"},
            eth["vrr"],
        )
        self.assertNotIn("pairs", eth["mlag"])
        self.assertEqual(
            [
                {
                    "bond-mac": "02:00:00:ff:01:ff",
                    "anycast-ip": "192.0.2.201",
                },
                {
                    "bond-mac": "02:00:00:ff:02:ff",
                    "anycast-ip": "192.0.2.202",
                },
            ],
            eth["mlag"]["shared-addresses"],
        )
        with (template / "02-devices_config.csv").open(
            newline="", encoding="utf-8-sig",
        ) as stream:
            header = next(csv.reader(stream))
        layout = CONTRACT.parse_device_csv_layout(header, 2)
        self.assertEqual(2, len(layout.vlan_group_starts))
        self.assertEqual(4, len(layout.evpn_group_starts))
        self.assertEqual(
            {"terminal_l2_ports": layout.fixed_start + 7},
            layout.policy_indices,
        )
        self.assertNotIn("vrf_default", header)
        self.assertNotIn("vrr_ip", header)
        self.assertNotIn("vrr_mac", header)

    def test_missing_schema_is_v1_but_explicit_values_are_strict(self):
        self.assertEqual(1, CONTRACT.detect_global_schema_version({"common": {}}))
        self.assertEqual(1, CONTRACT.detect_global_schema_version({"schema_version": 1}))
        self.assertEqual(2, CONTRACT.detect_global_schema_version({"schema_version": 2}))
        for value in (None, True, "2", 0, 3):
            with self.subTest(value=value), self.assertRaises(ValueError):
                CONTRACT.detect_global_schema_version({"schema_version": value})

    def test_v2_vrr_policy_rejects_invalid_inputs(self):
        for config in (
            {},
            {"vrr": {"base_mac": ":".join(("00",) * 6)}},
            {"vrr": {
                "base_mac": ":".join(("01", "00", "00", "00", "00", "00")),
            }},
            {"vrr": {
                "base_mac": ":".join(("00", "00", "5e", "01", "00", "00")),
            }},
            {"vrr": {"base_mac": "02:00:5e:01:00:01"}},
            {"vrr": {"base_mac": "02:00:5e:01:00:00", "gateway_ip": "none"}},
            {"vrr": {"base_mac": "not-a-mac"}},
        ):
            with self.subTest(config=config), self.assertRaises(ValueError):
                CONTRACT.normalize_v2_vrr_policy(config)

    def test_v2_layout_supports_zero_or_many_vlan_and_evpn_groups(self):
        empty = CONTRACT.parse_device_csv_layout(
            v2_header(vlan_groups=0, evpn_groups=0), 2,
        )
        self.assertEqual((), empty.vlan_group_starts)
        self.assertEqual((), empty.evpn_group_starts)
        self.assertEqual(12, empty.fixed_start)

        repeated = CONTRACT.parse_device_csv_layout(
            v2_header(vlan_groups=2, evpn_groups=3), 2,
        )
        self.assertEqual((12, 16), repeated.vlan_group_starts)
        self.assertEqual((27, 36, 45), repeated.evpn_group_starts)
        self.assertEqual(20, repeated.fixed_start)

    def test_v2_rejects_v1_only_columns_and_partial_groups(self):
        v1_header = (
            list(CONTRACT.DEVICE_BASE_COLUMNS)
            + list(CONTRACT.DEVICE_V1_VLAN_COLUMNS)
            + list(CONTRACT.DEVICE_FIXED_COLUMNS)
            + list(CONTRACT.DEVICE_V1_EVPN_COLUMNS)
        )
        with self.assertRaises(ValueError):
            CONTRACT.parse_device_csv_layout(v1_header, 2)

        broken = v2_header(vlan_groups=1, evpn_groups=1)
        broken.pop(14)
        with self.assertRaises(ValueError):
            CONTRACT.parse_device_csv_layout(broken, 2)

    def test_v2_rows_must_match_the_repeated_header_width_exactly(self):
        header = v2_header(vlan_groups=1, evpn_groups=0)
        row = [""] * len(header)
        CONTRACT.require_device_csv_row_width(row, len(header), 2, lineno=2)
        # V1 retains its historical tolerance for omitted trailing empty cells.
        CONTRACT.require_device_csv_row_width(row[:-1], len(header), 1, lineno=2)
        for malformed in (row[:-1], row + ["unexpected"]):
            with self.subTest(width=len(malformed)), self.assertRaisesRegex(
                ValueError, "表头完全一致",
            ):
                CONTRACT.require_device_csv_row_width(
                    malformed, len(header), 2, lineno=2,
                )

    def test_v1_layout_keeps_optional_vrl_backward_compatibility(self):
        legacy_fixed = list(CONTRACT.DEVICE_FIXED_COLUMNS[:-1])
        without_vrl = (
            list(CONTRACT.DEVICE_BASE_COLUMNS)
            + list(CONTRACT.DEVICE_V1_VLAN_COLUMNS)
            + legacy_fixed
            + list(CONTRACT.DEVICE_V1_EVPN_COLUMNS)
        )
        layout = CONTRACT.parse_device_csv_layout(without_vrl, 1)
        self.assertNotIn("vrl", layout.fixed_indices)
        self.assertEqual((25,), layout.evpn_group_starts)

    def test_setup_accepts_schema_v2_and_rejects_unknown_schema(self):
        base = """common:
  mgmt:
    ztp:
      ztp_url_prefix: /ztp
switches:
  - eth:
      version: 5.16.4
      bridge: {}
      system: {}
      vrr:
        base_mac: 02:00:5e:01:00:00
"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "01-global.yaml"
            path.write_text("schema_version: 2\n" + base, encoding="utf-8")
            errors, _warnings = SETUP._validate_global_yaml(str(path), "eth")
            self.assertEqual([], errors)

            path.write_text("schema_version: 3\n" + base, encoding="utf-8")
            errors, _warnings = SETUP._validate_global_yaml(str(path), "eth")
            self.assertTrue(any("schema_version=3" in error for error in errors))

    def test_setup_rejects_legacy_or_malformed_v2_mlag_address_schema(self):
        valid = v2_mlag_global([{
            "bond-mac": MLAG_MAC_A,
            "anycast-ip": "198.51.100.201",
        }])
        invalid_documents = {
            "legacy pairs": v2_mlag_global(legacy_pairs=[{
                "shared-addresses": ["198.51.100.201"],
                "system-mac": [MLAG_MAC_A, MLAG_MAC_B],
                "mac-address": [MLAG_MAC_A],
            }]),
            "mapping instead of list": v2_mlag_global({
                "bond-mac": MLAG_MAC_A,
                "anycast-ip": "198.51.100.201",
            }),
            "missing bond-mac": v2_mlag_global([{
                "anycast-ip": "198.51.100.201",
            }]),
            "missing anycast-ip": v2_mlag_global([{
                "bond-mac": MLAG_MAC_A,
            }]),
            "unknown field": v2_mlag_global([{
                "bond-mac": MLAG_MAC_A,
                "anycast-ip": "198.51.100.201",
                "system-mac": MLAG_MAC_B,
            }]),
            "duplicate bond-mac": v2_mlag_global([
                {"bond-mac": MLAG_MAC_A, "anycast-ip": "198.51.100.201"},
                {"bond-mac": MLAG_MAC_A, "anycast-ip": "198.51.100.202"},
            ]),
            "duplicate anycast-ip": v2_mlag_global([
                {"bond-mac": MLAG_MAC_A, "anycast-ip": "198.51.100.201"},
                {"bond-mac": MLAG_MAC_B, "anycast-ip": "198.51.100.201"},
            ]),
            "invalid bond-mac": v2_mlag_global([{
                "bond-mac": "not-a-mac",
                "anycast-ip": "198.51.100.201",
            }]),
            "invalid anycast-ip": v2_mlag_global([{
                "bond-mac": MLAG_MAC_A,
                "anycast-ip": "not-an-ip",
            }]),
            "CIDR is not a bare IPv4 address": v2_mlag_global([{
                "bond-mac": MLAG_MAC_A,
                "anycast-ip": "198.51.100.201/32",
            }]),
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "01-global.yaml"
            path.write_text(yaml.safe_dump(valid), encoding="utf-8")
            errors, _warnings = SETUP._validate_global_yaml(str(path), "eth")
            self.assertEqual([], errors)
            for label, document in invalid_documents.items():
                with self.subTest(label=label):
                    path.write_text(
                        yaml.safe_dump(document, sort_keys=False), encoding="utf-8",
                    )
                    errors, _warnings = SETUP._validate_global_yaml(
                        str(path), "eth",
                    )
                    self.assertTrue(errors, f"{label} must fail closed")

    def test_setup_validates_v2_offsets_native_vlan_and_bond_aliases(self):
        header = v2_header(vlan_groups=1, evpn_groups=0)
        row = [
            "leaf01", "eth", "tan-leaf", "192.0.2.10", "24",
            "192.0.2.1", "02:00:00:00:00:10", "NA", "NA", "NA",
            "NA", "198.51.100.10", "100/native", "203.0.113.2", "24",
            "swp1", "65001", "swp49", "bond49b51", "local", "NA",
            "NA", "false",
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "01-global.yaml").write_text(
                "schema_version: 2\n", encoding="utf-8",
            )
            csv_path = root / "02-devices_config.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as stream:
                csv.writer(stream).writerows([header, row])
            errors, _warnings = SETUP._validate_eth_csv(str(csv_path))
        self.assertEqual([], errors)

    def test_setup_rejects_undeclared_v2_bond_references(self):
        header = v2_header(vlan_groups=1, evpn_groups=0)
        row = [
            "leaf01", "eth", "tan-leaf", "192.0.2.10", "24",
            "192.0.2.1", "02:00:00:00:00:10", "NA", "NA", "NA",
            "NA", "198.51.100.10", "100", "NA", "NA", "bond7",
            "65001", "swp49", "NA", "NA", "NA", "NA", "false",
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "01-global.yaml").write_text(
                "schema_version: 2\n", encoding="utf-8",
            )
            csv_path = root / "02-devices_config.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as stream:
                csv.writer(stream).writerows([header, row])
            errors, _warnings = SETUP._validate_eth_csv(str(csv_path))
        self.assertTrue(
            any("bond7" in error and "未在 bond_ports 定义" in error
                for error in errors),
            errors,
        )

    def test_setup_warns_when_v2_bond_is_declared_but_unused(self):
        header = v2_header(vlan_groups=1, evpn_groups=0)
        row = [
            "leaf01", "eth", "tan-leaf", "192.0.2.10", "24",
            "192.0.2.1", "02:00:00:00:00:10", "NA", "NA", "NA",
            "NA", "198.51.100.10", "100", "NA", "NA", "swp1",
            "65001", "swp49", "bond49b51", "local", "NA", "NA",
            "false",
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "01-global.yaml").write_text(
                "schema_version: 2\n", encoding="utf-8",
            )
            csv_path = root / "02-devices_config.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as stream:
                csv.writer(stream).writerows([header, row])
            errors, warnings = SETUP._validate_eth_csv(str(csv_path))
        self.assertEqual([], errors)
        self.assertTrue(
            any("bond49b51" in warning and "未在任何 vlan_ports 使用" in warning
                for warning in warnings),
            warnings,
        )

    def test_setup_rejects_v2_bond_alignment_and_mac_semantics(self):
        header = v2_header(vlan_groups=0, evpn_groups=0)
        variants = (
            (
                "bond49b51|bond1-2", "local|evpn|mlag", "NA",
                "bond_type 有 3 个分组",
            ),
            (
                "bond49b51", "local", "02:00:00:00:00:20",
                "没有 MLAG 或 EVPN multihoming bond",
            ),
            (
                "bond1-2", "evpn", "NA",
                "EVPN multihoming bond 必须配置非零 unicast bond_mac",
            ),
            (
                "bond1", "mlag", "00:00:00:00:00:00",
                "MLAG bond 必须配置非零 unicast bond_mac",
            ),
            (
                "bond1", "evpn", "01:00:00:00:00:01",
                "EVPN multihoming bond 必须配置非零 unicast bond_mac",
            ),
            (
                "bond49bond51", "evpn", "02:00:00:00:00:20",
                "多成员 bond bond49bond51 只允许 bond_type=local",
            ),
        )
        for bond_ports, bond_type, bond_mac, expected in variants:
            with self.subTest(bond_ports=bond_ports, bond_type=bond_type):
                row = [
                    "leaf01", "eth", "tan-leaf", "192.0.2.10", "24",
                    "192.0.2.1", "02:00:00:00:00:10", "NA", "NA", "NA",
                    "NA", "198.51.100.10", "65001", "swp49",
                    bond_ports, bond_type, bond_mac, "NA", "false",
                ]
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / "01-global.yaml").write_text(
                        "schema_version: 2\n", encoding="utf-8",
                    )
                    csv_path = root / "02-devices_config.csv"
                    with csv_path.open(
                        "w", newline="", encoding="utf-8",
                    ) as stream:
                        csv.writer(stream).writerows([header, row])
                    errors, _warnings = SETUP._validate_eth_csv(str(csv_path))
                self.assertTrue(
                    any(expected in error for error in errors), errors,
                )

        shared_mac_row = [
            "leaf01", "eth", "tan-leaf", "192.0.2.10", "24",
            "192.0.2.1", "02:00:00:00:00:10", "NA", "NA", "NA",
            "NA", "198.51.100.10", "65001", "swp49",
            "bond1|bond2", "evpn|evpn", "02:00:00:00:00:20", "NA",
            "false",
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "01-global.yaml").write_text(
                "schema_version: 2\n", encoding="utf-8",
            )
            csv_path = root / "02-devices_config.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as stream:
                csv.writer(stream).writerows([header, shared_mac_row])
            errors, _warnings = SETUP._validate_eth_csv(str(csv_path))
        self.assertEqual([], errors)

    def test_setup_enforces_the_29_half_only_for_border(self):
        header = v2_header(vlan_groups=0, evpn_groups=1)

        def row(template, svi, netmask="29"):
            return [
                "Border01", "eth", template, "192.0.2.10", "24",
                "192.0.2.1", "02:00:00:00:00:10", "NA", "NA", "NA",
                "NA", "198.51.100.10",
                "65001", "swp49", "NA", "NA", "NA", "NA", "false",
                "BLUE", "4001", "4001", "NA", "NA", "100", svi,
                netmask, "swp1",
            ]

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "01-global.yaml").write_text(
                """schema_version: 2
switches:
  - eth:
      vrr: {base_mac: '02:00:5e:01:00:00', gateway_ip: subnet_maximum}
""",
                encoding="utf-8",
            )
            csv_path = root / "02-devices_config.csv"

            with csv_path.open("w", newline="", encoding="utf-8") as stream:
                csv.writer(stream).writerows([header, row("border", "192.0.2.137")])
            errors, _warnings = SETUP._validate_eth_csv(str(csv_path))
            self.assertTrue(any("subnet_maximum" in error for error in errors), errors)

            with csv_path.open("w", newline="", encoding="utf-8") as stream:
                csv.writer(stream).writerows([header, row("border", "192.0.2.140")])
            errors, _warnings = SETUP._validate_eth_csv(str(csv_path))
            self.assertEqual([], errors)

            with csv_path.open("w", newline="", encoding="utf-8") as stream:
                csv.writer(stream).writerows([
                    header, row("border", "192.0.2.2", "24"),
                ])
            errors, _warnings = SETUP._validate_eth_csv(str(csv_path))
            self.assertEqual([], errors)

            with csv_path.open("w", newline="", encoding="utf-8") as stream:
                csv.writer(stream).writerows([header, row("tan-leaf", "192.0.2.137")])
            errors, _warnings = SETUP._validate_eth_csv(str(csv_path))
            self.assertEqual([], errors)


class V2VrrTests(unittest.TestCase):
    def test_29_triplet_plan_uses_the_nearest_peer_address(self):
        maximum = CONTRACT.v2_vrr_ipv4_plan(
            "192.0.2.136/29", "subnet_maximum",
        )
        self.assertEqual("192.0.2.142", maximum["gateway_ip"])
        self.assertEqual(
            ("192.0.2.140", "192.0.2.141"), maximum["device_ips"],
        )
        self.assertEqual("192.0.2.139", maximum["peer_gateway_ip"])

        minimum = CONTRACT.v2_vrr_ipv4_plan(
            "192.0.2.136/29", "subnet_minimum",
        )
        self.assertEqual("192.0.2.137", minimum["gateway_ip"])
        self.assertEqual(
            ("192.0.2.138", "192.0.2.139"), minimum["device_ips"],
        )
        self.assertEqual("192.0.2.140", minimum["peer_gateway_ip"])

        with self.assertRaisesRegex(ValueError, "只适用于 /29"):
            CONTRACT.v2_vrr_ipv4_plan(
                "192.0.2.0/24", "subnet_maximum",
            )

    def test_vrr_mac_encodes_four_decimal_vlan_digits_and_defaults_gateway(self):
        policy = GENERATOR._normalize_v2_vrr_policy({
            "vrr": {"base_mac": "02:00:5e:01:00:00", "gateway_ip": None},
        })
        self.assertEqual("subnet_maximum", policy["gateway_ip"])
        self.assertEqual("02:00:5e:01:01:10", GENERATOR._v2_vrr_mac(policy, 110))
        self.assertEqual("02:00:5e:01:40:94", GENERATOR._v2_vrr_mac(policy, 4094))

        fabric_two = GENERATOR._normalize_v2_vrr_policy({
            "vrr": {"base_mac": "02:00:5e:02:00:00", "gateway_ip": None},
        })
        self.assertEqual(
            "02:00:5e:02:01:10", GENERATOR._v2_vrr_mac(fabric_two, 110),
        )
        self.assertEqual(
            "02:00:5e:02:40:94", GENERATOR._v2_vrr_mac(fabric_two, 4094),
        )

    def test_every_local_schema_v2_global_uses_the_canonical_vrr_base(self):
        checked = []
        for path in sorted((ROOT / "DAY0-Prepare").glob("*/01-global.yaml")):
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
            if document.get("schema_version") != 2:
                continue
            eth = next(
                item["eth"] for item in document["switches"] if "eth" in item
            )
            self.assertEqual(
                "02:00:5e:01:00:00", eth["vrr"]["base_mac"], str(path),
            )
            checked.append(path)
        self.assertTrue(checked)

    def test_unique_svis_create_vrr_ip_and_giaddress_relay_mode(self):
        devices = {
            "leaf01": l2_device("leaf01", "192.0.2.2/24"),
            "leaf02": l2_device("leaf02", "192.0.2.3/24"),
        }
        policy = GENERATOR._normalize_v2_vrr_policy({
            "vrr": {"base_mac": "02:00:5e:01:00:00"},
        })
        GENERATOR._apply_v2_vrr_policy(devices, policy)
        for device in devices.values():
            l2 = device["vrfs"][0]["l2vlans"][0]
            self.assertEqual("192.0.2.254/24", l2["vrr_ip"])
            self.assertEqual("02:00:5e:01:01:00", l2["vrr_mac"])
        catalog = {"BLUE": {"servers": {
            "servers": ["203.0.113.10"], "upstream_interface": "vlan4001_l3",
        }}}
        devices["leaf01"]["vrfs"][0]["l2vlans"][0].update({
            "dhcp_relay": True, "dhcp_server": "servers",
        })
        relay = GENERATOR._resolve_device_dhcp_relays(devices["leaf01"], catalog)
        self.assertEqual("giaddress", relay[0]["mode"])

    def test_shared_gateway_svi_uses_snippet_and_gateway_relay_mode(self):
        devices = {
            "leaf01": l2_device("leaf01", "192.0.2.254/24"),
            "leaf02": l2_device("leaf02", "192.0.2.254/24"),
        }
        policy = GENERATOR._normalize_v2_vrr_policy({
            "vrr": {"base_mac": "02:00:5e:01:00:00"},
        })
        GENERATOR._apply_v2_vrr_policy(devices, policy)
        l2 = devices["leaf01"]["vrfs"][0]["l2vlans"][0]
        self.assertEqual("", l2["vrr_ip"])
        self.assertEqual("02:00:5e:01:01:00", l2["vrr_mac"])
        l2.update({"dhcp_relay": True, "dhcp_server": "servers"})
        catalog = {"BLUE": {"servers": {
            "servers": ["203.0.113.10"], "upstream_interface": "vlan4001_l3",
        }}}
        relay = GENERATOR._resolve_device_dhcp_relays(devices["leaf01"], catalog)
        self.assertEqual("gateway", relay[0]["mode"])
        self.assertEqual("198.51.100.1", relay[0]["gateway_address"])
        self.assertEqual(
            "hwaddress 02:00:5e:01:01:00\n",
            relay[0]["ifupdown_snippets"]["vlan100"],
        )
        self.assertEqual({}, relay[0]["svi_link_macs"])

    def test_shared_gateway_svi_uses_native_link_mac_for_cumulus_518(self):
        devices = {
            "leaf01": l2_device("leaf01", "192.0.2.254/24"),
            "leaf02": l2_device("leaf02", "192.0.2.254/24"),
        }
        policy = GENERATOR._normalize_v2_vrr_policy({
            "vrr": {"base_mac": "02:00:5e:01:00:00"},
        })
        GENERATOR._apply_v2_vrr_policy(devices, policy)
        l2 = devices["leaf01"]["vrfs"][0]["l2vlans"][0]
        l2.update({"dhcp_relay": True, "dhcp_server": "servers"})
        catalog = {"BLUE": {"servers": {
            "servers": ["203.0.113.10"], "upstream_interface": "vlan4001_l3",
        }}}
        relay = GENERATOR._resolve_device_dhcp_relays(
            devices["leaf01"], catalog, native_svi_link_mac=True,
        )
        self.assertEqual("gateway", relay[0]["mode"])
        self.assertEqual({}, relay[0]["ifupdown_snippets"])
        self.assertEqual(
            {"vlan100": "02:00:5e:01:01:00"},
            relay[0]["svi_link_macs"],
        )

    def test_single_non_gateway_svi_remains_standalone(self):
        devices = {
            "leaf01": l2_device("leaf01", "192.0.2.2/24"),
        }
        policy = GENERATOR._normalize_v2_vrr_policy({
            "vrr": {"base_mac": "02:00:5e:01:00:00"},
        })
        GENERATOR._apply_v2_vrr_policy(devices, policy)
        l2 = devices["leaf01"]["vrfs"][0]["l2vlans"][0]
        self.assertEqual("standalone", l2["vrr_mode"])
        self.assertEqual("", l2["vrr_ip"])
        self.assertEqual("", l2["vrr_mac"])
        self.assertEqual("", l2["vrr_gateway_ip"])

    def test_same_vlan_id_in_different_vrfs_is_inferred_independently(self):
        standalone = l2_device("leaf01", "192.0.2.2/24")
        standalone["vrfs"][0]["evpn_vrf"] = "inband"
        shared_gateway = l2_device("border01", "198.51.100.254/24")
        shared_gateway["vrfs"][0]["evpn_vrf"] = "Vrf_3"
        devices = {
            "leaf01": standalone,
            "border01": shared_gateway,
        }
        policy = GENERATOR._normalize_v2_vrr_policy({
            "vrr": {"base_mac": "02:00:5e:01:00:00"},
        })
        GENERATOR._apply_v2_vrr_policy(devices, policy)

        leaf_l2 = standalone["vrfs"][0]["l2vlans"][0]
        border_l2 = shared_gateway["vrfs"][0]["l2vlans"][0]
        self.assertEqual("standalone", leaf_l2["vrr_mode"])
        self.assertEqual("snippet", border_l2["vrr_mode"])
        self.assertEqual("", leaf_l2["vrr_mac"])
        self.assertEqual("02:00:5e:01:01:00", border_l2["vrr_mac"])
        self.assertEqual(
            [], GENERATOR._validate_project_svi_vrr(devices),
        )

    def test_minimum_gateway_and_ambiguous_svi_claims(self):
        minimum = GENERATOR._normalize_v2_vrr_policy({
            "vrr": {
                "base_mac": "02:00:5e:01:00:00",
                "gateway_ip": "subnet_minimum",
            },
        })
        devices = {
            "leaf01": l2_device("leaf01", "192.0.2.2/24"),
            "leaf02": l2_device("leaf02", "192.0.2.3/24"),
        }
        GENERATOR._apply_v2_vrr_policy(devices, minimum)
        self.assertEqual(
            "192.0.2.1/24",
            devices["leaf01"]["vrfs"][0]["l2vlans"][0]["vrr_ip"],
        )

        ambiguous = {
            "leaf01": l2_device("leaf01", "192.0.2.2/24"),
            "leaf02": l2_device("leaf02", "192.0.2.2/24"),
            "leaf03": l2_device("leaf03", "192.0.2.3/24"),
        }
        with self.assertRaisesRegex(ValueError, "既非全部唯一.*也非全部相同"):
            GENERATOR._apply_v2_vrr_policy(ambiguous, minimum)

    def test_29_svis_must_use_the_selected_local_triplet(self):
        maximum = GENERATOR._normalize_v2_vrr_policy({
            "vrr": {"base_mac": "02:00:5e:01:00:00"},
        })
        valid_maximum = {
            "leaf01": l2_device("leaf01", "192.0.2.140/29"),
            "leaf02": l2_device("leaf02", "192.0.2.141/29"),
        }
        for device in valid_maximum.values():
            device["template"] = "border"
        GENERATOR._apply_v2_vrr_policy(valid_maximum, maximum)
        GENERATOR._assign_v2_border_default_routes(valid_maximum)
        max_l2 = valid_maximum["leaf01"]["vrfs"][0]["l2vlans"][0]
        self.assertEqual("192.0.2.142/29", max_l2["vrr_ip"])
        self.assertEqual("192.0.2.139", max_l2["peer_gateway_ip"])

        invalid_maximum = {
            "leaf01": l2_device("leaf01", "192.0.2.137/29"),
            "leaf02": l2_device("leaf02", "192.0.2.138/29"),
        }
        for device in invalid_maximum.values():
            device["template"] = "border"
        GENERATOR._apply_v2_vrr_policy(invalid_maximum, maximum)
        with self.assertRaisesRegex(ValueError, r"subnet_maximum.*\.140.*\.141"):
            GENERATOR._assign_v2_border_default_routes(invalid_maximum)

        minimum = GENERATOR._normalize_v2_vrr_policy({
            "vrr": {
                "base_mac": "02:00:5e:01:00:00",
                "gateway_ip": "subnet_minimum",
            },
        })
        valid_minimum = {
            "leaf01": l2_device("leaf01", "192.0.2.138/29"),
            "leaf02": l2_device("leaf02", "192.0.2.139/29"),
        }
        for device in valid_minimum.values():
            device["template"] = "border"
        GENERATOR._apply_v2_vrr_policy(valid_minimum, minimum)
        GENERATOR._assign_v2_border_default_routes(valid_minimum)
        min_l2 = valid_minimum["leaf01"]["vrfs"][0]["l2vlans"][0]
        self.assertEqual("192.0.2.137/29", min_l2["vrr_ip"])
        self.assertEqual("192.0.2.140", min_l2["peer_gateway_ip"])

    def test_border_v2_default_route_uses_only_one_29_transit_vlan(self):
        device = l2_device("Border01", "192.0.2.140/29")
        peer = l2_device("Border02", "192.0.2.141/29")
        devices = {"Border01": device, "Border02": peer}
        for border in devices.values():
            border.update({"template": "border", "_project_schema_version": 2})
        policy = GENERATOR._normalize_v2_vrr_policy({
            "vrr": {"base_mac": "02:00:5e:01:00:00"},
        })
        GENERATOR._apply_v2_vrr_policy(devices, policy)
        GENERATOR._assign_v2_border_default_routes(devices)
        self.assertEqual(
            "192.0.2.139",
            device["vrfs"][0]["default_route_next_hop"],
        )

        ordinary_svi = copy.deepcopy(device["vrfs"][0]["l2vlans"][0])
        ordinary_svi.update({
            "vlan_id": 101,
            "vlan_ids": [101],
            "svi_ip": "198.51.100.2/24",
            "vrr_ip": "198.51.100.254/24",
            "vrr_gateway_ip": "198.51.100.254/24",
        })
        device["vrfs"][0]["l2vlans"].append(ordinary_svi)
        GENERATOR._assign_v2_border_default_routes(devices)
        self.assertEqual(
            "192.0.2.139",
            device["vrfs"][0]["default_route_next_hop"],
        )

        second_29 = copy.deepcopy(device["vrfs"][0]["l2vlans"][0])
        second_29.update({"vlan_id": 102, "vlan_ids": [102]})
        device["vrfs"][0]["l2vlans"].append(second_29)
        with self.assertRaisesRegex(ValueError, "多个 /29.*默认路由"):
            GENERATOR._assign_v2_border_default_routes(devices)

    def test_vrf_default_route_must_use_a_distinct_connected_host(self):
        document = [{"set": {
            "interface": {"vlan112": {
                "ipv4": {
                    "address": {"192.0.2.137/29": {}},
                    "vrr": {
                        "address": {"192.0.2.142/29": {}},
                        "mac-address": "02:00:5e:01:01:12",
                    },
                },
                "vrf": "inband",
            }},
            "vrf": {"inband": {"router": {"static": {"default": {
                "via": {"192.0.2.145": {"type": "ipv4-address"}},
            }}}}},
        }}]
        self.assertRegex(
            "\n".join(GENERATOR._vrf_default_route_errors(document)),
            r"192\.0\.2\.145.*不在.*192\.0\.2\.136/29",
        )

        document[0]["set"]["vrf"]["inband"]["router"]["static"][
            "default"
        ]["via"] = {"192.0.2.141": {"type": "ipv4-address"}}
        self.assertEqual([], GENERATOR._vrf_default_route_errors(document))

        document[0]["set"]["vrf"]["inband"]["router"]["static"][
            "default"
        ]["via"] = {"192.0.2.142": {"type": "ipv4-address"}}
        self.assertRegex(
            "\n".join(GENERATOR._vrf_default_route_errors(document)),
            r"192\.0\.2\.142.*本机 SVI/VRR 地址冲突",
        )


class NativeVlanAndBondTests(unittest.TestCase):
    def test_v2_mlag_bond_mac_is_the_pair_identity(self):
        groups = GENERATOR._csv_parse_bond_groups(
            "bond1|bond2", "mlag|mlag", MLAG_MAC_A, schema_version=2,
        )
        self.assertEqual(["mlag", "mlag"], [group["type"] for group in groups])
        self.assertEqual(
            [MLAG_MAC_A, MLAG_MAC_A],
            [group["mac-address"] for group in groups],
        )
        with self.assertRaisesRegex(ValueError, "MLAG.*bond_mac|bond_mac.*MLAG"):
            GENERATOR._csv_parse_bond_groups(
                "bond1|bond2", "mlag|mlag", f"{MLAG_MAC_A}|{MLAG_MAC_B}",
                schema_version=2,
            )

    def test_v2_mlag_pairing_override_and_automatic_address_are_mac_driven(self):
        rows = [
            v2_redundant_row(
                "A1", 10, "198.51.100.10", "mlag", MLAG_MAC_A,
                vrf="L2ONLY", l3_vni=False,
            ),
            v2_redundant_row(
                "B1", 20, "198.51.100.20", "mlag", MLAG_MAC_B,
                vrf="L3ONLY", l2_vni=False,
            ),
            v2_redundant_row(
                "A2", 11, "198.51.100.11", "mlag", MLAG_MAC_A,
                vrf="L2ONLY", l3_vni=False,
            ),
            v2_redundant_row(
                "B2", 21, "198.51.100.25", "mlag", MLAG_MAC_B,
                vrf="L3ONLY", l2_vni=False,
            ),
            v2_redundant_row("EVPN1", 40, "198.51.100.40", "evpn", EVPN_MAC),
        ]
        document, _output = generate_v2_redundancy_project(
            rows,
            v2_mlag_global([{
                "bond-mac": MLAG_MAC_A,
                "anycast-ip": "198.51.100.201",
            }]),
        )
        devices = document["devices"]
        expected = {
            "A1": ("192.0.2.11", MLAG_MAC_A, "198.51.100.201"),
            "A2": ("192.0.2.10", MLAG_MAC_A, "198.51.100.201"),
            "B1": ("192.0.2.21", MLAG_MAC_B, "198.51.100.26"),
            "B2": ("192.0.2.20", MLAG_MAC_B, "198.51.100.26"),
        }
        for hostname, (backup, pair_mac, shared) in expected.items():
            with self.subTest(hostname=hostname):
                device = devices[hostname]
                self.assertEqual(backup, device["mlag_backup"])
                self.assertEqual(pair_mac, device["mlag_mac_address"])
                self.assertEqual(shared, device["mlag_shared_address"])
                self.assertNotIn("system_mac", device)
        self.assertNotIn("mlag_mac_address", devices["EVPN1"])
        self.assertNotIn("mlag_shared_address", devices["EVPN1"])

    def test_v2_missing_shared_addresses_key_uses_only_active_mlag_derivation(self):
        rows = [
            v2_redundant_row(
                "A1", 10, "198.51.100.10", "mlag", MLAG_MAC_A,
            ),
            v2_redundant_row(
                "A2", 11, "198.51.100.11", "mlag", MLAG_MAC_A,
            ),
            v2_redundant_row(
                "P1", 20, "198.51.100.20", "mlag", MLAG_MAC_B,
                vxlan=False, vrf="PLAIN",
            ),
            v2_redundant_row(
                "P2", 21, "198.51.100.21", "mlag", MLAG_MAC_B,
                vxlan=False, vrf="PLAIN",
            ),
            v2_redundant_row(
                "EVPN1", 40, "198.51.100.40", "evpn", EVPN_MAC,
            ),
        ]
        global_document = v2_mlag_global()
        eth = global_document["switches"][0]["eth"]
        self.assertIn("mlag", eth)
        self.assertNotIn("shared-addresses", eth["mlag"])

        document, _output = generate_v2_redundancy_project(
            rows, global_document,
        )
        devices = document["devices"]
        for hostname, backup in (("A1", "192.0.2.11"),
                                 ("A2", "192.0.2.10")):
            with self.subTest(hostname=hostname):
                self.assertEqual(backup, devices[hostname]["mlag_backup"])
                self.assertEqual(
                    MLAG_MAC_A, devices[hostname]["mlag_mac_address"],
                )
                self.assertEqual(
                    "198.51.100.12",
                    devices[hostname]["mlag_shared_address"],
                )
        for hostname in ("P1", "P2"):
            with self.subTest(hostname=hostname):
                self.assertEqual(
                    MLAG_MAC_B, devices[hostname]["mlag_mac_address"],
                )
                self.assertNotIn("mlag_shared_address", devices[hostname])
        self.assertNotIn("mlag_mac_address", devices["EVPN1"])
        self.assertNotIn("mlag_shared_address", devices["EVPN1"])

    def test_v2_mlag_rejects_templates_without_complete_peer_support(self):
        rows = [
            v2_redundant_row("A1", 10, "198.51.100.10", "mlag", MLAG_MAC_A),
            v2_redundant_row("A2", 11, "198.51.100.11", "mlag", MLAG_MAC_A),
        ]
        for row in rows:
            row[2] = "tan-leaf"
        with self.assertRaises(SystemExit):
            generate_v2_redundancy_project(rows, v2_mlag_global([]))

        for row in rows:
            row[2] = "oobofoob-spine"
        with self.assertRaises(SystemExit):
            generate_v2_redundancy_project(rows, v2_mlag_global([]))

    def test_v2_mlag_pair_requires_matching_vxlan_inventory(self):
        for label, column, value in (
                ("L2 VNI", 23, "10200"),
                ("L3 VNI", 20, "4002")):
            rows = [
                v2_redundant_row(
                    "A1", 10, "198.51.100.10", "mlag", MLAG_MAC_A,
                ),
                v2_redundant_row(
                    "A2", 11, "198.51.100.11", "mlag", MLAG_MAC_A,
                ),
            ]
            rows[1][column] = value
            with self.subTest(label=label), self.assertRaises(SystemExit):
                generate_v2_redundancy_project(rows, v2_mlag_global([]))

    def test_v2_redundancy_mac_must_be_nonzero_unicast(self):
        for value in ("00:00:00:00:00:00", "01:00:00:00:00:01"):
            with self.subTest(value=value), self.assertRaisesRegex(
                    ValueError, "nonzero unicast|non-zero unicast|unicast"):
                GENERATOR._csv_parse_bond_groups(
                    "bond1", "mlag", value,
                    context="leaf01", schema_version=2,
                )

    def test_v2_shared_address_override_requires_one_active_mlag_pair(self):
        active_pair = [
            v2_redundant_row("A1", 10, "198.51.100.10", "mlag", MLAG_MAC_A),
            v2_redundant_row("A2", 11, "198.51.100.11", "mlag", MLAG_MAC_A),
        ]
        cases = {
            "orphan bond MAC": (
                active_pair,
                [{"bond-mac": MLAG_MAC_B, "anycast-ip": "198.51.100.201"}],
            ),
            "EVPN multihoming is not MLAG": (
                [v2_redundant_row(
                    "EVPN1", 40, "198.51.100.40", "evpn", EVPN_MAC,
                )],
                [{"bond-mac": EVPN_MAC, "anycast-ip": "198.51.100.201"}],
            ),
            "MLAG without a VNI is not VXLAN active-active": (
                [
                    v2_redundant_row(
                        "P1", 30, "198.51.100.30", "mlag", MLAG_MAC_A,
                        vxlan=False,
                    ),
                    v2_redundant_row(
                        "P2", 31, "198.51.100.31", "mlag", MLAG_MAC_A,
                        vxlan=False,
                    ),
                ],
                [{"bond-mac": MLAG_MAC_A, "anycast-ip": "198.51.100.201"}],
            ),
            "one MAC cannot identify more than two peers": (
                [
                    v2_redundant_row(
                        f"P{index}", 50 + index, f"198.51.100.{index * 10}",
                        "mlag", MLAG_MAC_A,
                    )
                    for index in range(1, 5)
                ],
                [],
            ),
        }
        for label, (rows, overrides) in cases.items():
            with self.subTest(label=label), self.assertRaises(SystemExit):
                generate_v2_redundancy_project(
                    rows, v2_mlag_global(overrides),
                )

    def test_v2_anycast_address_cannot_collide_with_project_addresses(self):
        base_rows = [
            v2_redundant_row("A1", 10, "198.51.100.10", "mlag", MLAG_MAC_A),
            v2_redundant_row("A2", 11, "198.51.100.11", "mlag", MLAG_MAC_A),
        ]
        svi_rows = [
            v2_redundant_row(
                "A1", 10, "198.51.100.10", "mlag", MLAG_MAC_A,
                svi_ip="203.0.113.2",
            ),
            v2_redundant_row(
                "A2", 11, "198.51.100.11", "mlag", MLAG_MAC_A,
                svi_ip="203.0.113.3",
            ),
        ]
        explicit_cases = {
            "loopback": (base_rows, "198.51.100.10"),
            "management": (base_rows, "192.0.2.10"),
            "SVI": (svi_rows, "203.0.113.2"),
            "derived VRR": (svi_rows, "203.0.113.254"),
        }
        for label, (rows, address) in explicit_cases.items():
            with self.subTest(label=label), self.assertRaises(SystemExit):
                generate_v2_redundancy_project(
                    rows,
                    v2_mlag_global([{
                        "bond-mac": MLAG_MAC_A,
                        "anycast-ip": address,
                    }]),
                )

        automatic_collision = base_rows + [
            v2_redundant_row(
                "EVPN1", 40, "198.51.100.12", "evpn", EVPN_MAC,
            ),
        ]
        with self.assertRaises(SystemExit):
            generate_v2_redundancy_project(
                automatic_collision, v2_mlag_global([]),
            )

    def test_v2_vlan_without_svi_is_bridge_only(self):
        group = GENERATOR._csv_parse_v2_vlan_group(
            ["19/native", "NA", "NA", "swp1-2"],
        )
        self.assertTrue(group["bridge_only"])
        vrfs = GENERATOR._csv_build_vrfs([group], schema_version=2)
        self.assertFalse(vrfs[0]["l2vlans"][0]["emit_svi"])

    def test_native_suffix_is_single_vlan_only(self):
        self.assertEqual(
            (100, "100", [100], True),
            GENERATOR._csv_parse_vlan_selector_with_native("100/native", "vlan_id"),
        )
        for value in ("100-101/native", "100/native,101", "native", "100/NATIVE/x"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                GENERATOR._csv_parse_vlan_selector_with_native(value, "vlan_id")

    def test_native_vlan_remains_in_trunk_membership_even_when_it_is_alone(self):
        device = l2_device("leaf01", "")
        first = device["vrfs"][0]["l2vlans"][0]
        first.update({"native": True, "vlan_ports": ["swp1"]})
        processed = GENERATOR.preprocess_device(device)
        port = processed["computed_vlan_ports"][0]
        self.assertEqual("trunk", port["vlan_mode"])
        self.assertEqual(100, port["vlan_native"])
        self.assertEqual("100", port["vlan_trunk_range"])

        second = copy.deepcopy(first)
        second.update({
            "vlan_id": None, "vlan_ids": list(range(101, 201)),
            "vlan_spec": "101-200", "native": False,
        })
        device["vrfs"][0]["l2vlans"].append(second)
        processed = GENERATOR.preprocess_device(device)
        port = processed["computed_vlan_ports"][0]
        self.assertEqual(100, port["vlan_native"])
        self.assertEqual("100-200", port["vlan_trunk_range"])

    def test_one_interface_cannot_inherit_two_native_vlans(self):
        device = l2_device("leaf01", "")
        first = device["vrfs"][0]["l2vlans"][0]
        first.update({"native": True, "vlan_ports": ["swp1"]})
        second = copy.deepcopy(first)
        second.update({"vlan_id": 101, "vlan_ids": [101], "vlan_spec": "101"})
        device["vrfs"][0]["l2vlans"].append(second)
        with self.assertRaisesRegex(ValueError, "多个 native VLAN"):
            GENERATOR.preprocess_device(device)

    def test_repeated_v2_groups_cannot_overlap_the_same_vlan(self):
        first = GENERATOR._csv_parse_v2_vlan_group(
            ["100-102", "", "", "swp1"],
        )
        second = GENERATOR._csv_parse_v2_vlan_group(
            ["102-104", "", "", "swp2"],
        )
        with self.assertRaisesRegex(ValueError, "重复定义 VLAN.*102"):
            GENERATOR._csv_build_vrfs(
                [first, second], schema_version=2,
            )

    def test_v2_bond_aliases_compact_local_members_and_single_evpn_mac(self):
        groups = GENERATOR._csv_parse_bond_groups(
            "bond49b51b53|bond1-48", "local|evpn",
            "02:00:00:00:01:9a", schema_version=2,
        )
        self.assertEqual("localbond", groups[0]["type"])
        self.assertNotIn("mac-address", groups[0])
        self.assertEqual("evpn_multihoming", groups[1]["type"])
        self.assertEqual("02:00:00:00:01:9a", groups[1]["mac-address"])
        self.assertEqual(
            [f"bond{index}" for index in range(1, 49)],
            groups[1]["bond_list"],
        )

        device = l2_device("leaf01", "")
        device["bond_groups"] = groups
        device["vrfs"][0]["l2vlans"][0]["vlan_ports"] = [
            {"bonds": copy.deepcopy(groups[0])},
            {"bonds": copy.deepcopy(groups[1])},
        ]
        processed = GENERATOR.preprocess_device(device)
        bonds = {item["name"]: item for item in processed["computed_bonds"]}
        self.assertEqual(["swp49", "swp51", "swp53"], bonds["bond49b51b53"]["members"])
        self.assertEqual("02:00:00:00:01:9a", bonds["bond1"]["mac_address"])

        for compact_name in ("bond49b51", "bond49bond51"):
            with self.subTest(compact_name=compact_name), self.assertRaisesRegex(
                ValueError, "多成员 bond.*只允许 bond_type=local",
            ):
                GENERATOR._csv_parse_bond_groups(
                    compact_name, "evpn", "02:00:00:00:01:9a",
                    schema_version=2,
                )

    def test_v2_bond_pipe_groups_must_align(self):
        with self.assertRaisesRegex(ValueError, "bond_type 有 3 个分组"):
            GENERATOR._csv_parse_bond_groups(
                "bond49b51b53|bond1-48", "local|mlag|evpn", "NA",
                schema_version=2,
            )
        with self.assertRaisesRegex(ValueError, "bond_mac 有 3 个分组"):
            GENERATOR._csv_parse_bond_groups(
                "bond49b51b53|bond1-48", "local|evpn",
                "NA|02:00:00:00:01:9a|NA", schema_version=2,
            )
        shared = GENERATOR._csv_parse_bond_groups(
            "bond1|bond2", "evpn|evpn", "02:00:00:00:01:9a",
            schema_version=2,
        )
        self.assertEqual(
            ["02:00:00:00:01:9a", "02:00:00:00:01:9a"],
            [group["mac-address"] for group in shared],
        )
        with self.assertRaisesRegex(ValueError, "同一设备所有.*bond_mac"):
            GENERATOR._csv_parse_bond_groups(
                "bond1|bond2", "evpn|evpn",
                "02:00:00:00:01:9a|02:00:00:00:01:9b",
                schema_version=2,
            )

    def test_p2p_air_inventory_expands_v2_compact_local_bond_members(self):
        header = v2_header(vlan_groups=0, evpn_groups=0)
        row = [
            "leaf01", "eth", "tan-leaf", "192.0.2.10", "24",
            "192.0.2.1", "02:00:00:00:00:10", "NA", "NA", "NA",
            "NA", "198.51.100.10", "65001", "swp53",
            "bond49b51b53|bond1-48", "local|evpn",
            "02:00:00:00:01:00", "NA", "false",
        ]
        self.assertEqual(len(header), len(row))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "02-devices_config.csv"
            with path.open("w", newline="", encoding="utf-8") as stream:
                csv.writer(stream).writerows([header, row])
            ports = P2P._configured_bond_member_inventory(str(path))["leaf01"]
        self.assertIn("swp49", ports)
        self.assertIn("swp51", ports)
        self.assertIn("swp53", ports)
        self.assertIn("swp1", ports)
        self.assertIn("swp48", ports)

    def test_bond_mac_is_empty_without_redundancy_and_bond_references_are_declared(self):
        with self.assertRaisesRegex(ValueError, "没有 MLAG 或 EVPN"):
            GENERATOR._csv_parse_bond_groups(
                "bond49b51", "local", "02:00:00:00:00:01", schema_version=2,
            )
        groups = GENERATOR._csv_parse_bond_groups(
            "bond49b51", "local", "NA", schema_version=2,
        )
        with self.assertRaisesRegex(ValueError, "未在 bond_ports"):
            GENERATOR._csv_build_vrfs([{
                "vrf": "BLUE", "l3vni": 4001, "l3vlan": 4001,
                "l2vni": 10100, "l2vni_ids": [10100],
                "l2vlan": 100, "l2vlan_ids": [100], "l2vlan_spec": "100",
                "svi_ip": "", "vrr_ip": "", "vrr_mac": "",
                "vlan_ports": "bond1", "dhcp_server": "",
            }], groups, schema_version=2)

    def test_v2_blank_vlan_ports_never_implicitly_consumes_a_bond_group(self):
        groups = GENERATOR._csv_parse_bond_groups(
            "bond49b51", "local", "NA", schema_version=2,
        )
        vlan = {
            "vrf": "default", "l3vni": None, "l3vlan": None,
            "l2vni": None, "l2vni_ids": [], "l2vlan": 100,
            "l2vlan_ids": [100], "l2vlan_spec": "100", "svi_ip": "",
            "vrr_ip": "", "vrr_mac": "", "native": False,
            "vlan_ports": "", "dhcp_server": "", "bridge_only": True,
        }
        vrfs = GENERATOR._csv_build_vrfs(
            [vlan], groups, schema_version=2,
        )
        self.assertEqual([], vrfs[0]["l2vlans"][0]["vlan_ports"])
        device = {
            "_project_schema_version": 2,
            "bond_groups": groups,
            "vrfs": vrfs,
        }
        self.assertEqual([], GENERATOR.preprocess_device(device)["computed_bonds"])

        marker = copy.deepcopy(vlan)
        marker["vlan_ports"] = "bond"
        with self.assertRaisesRegex(ValueError, "显式 bond interface"):
            GENERATOR._csv_build_vrfs(
                [marker], groups, schema_version=2,
            )


class V2FeedbackTests(unittest.TestCase):
    def test_feedback_runtime_loader_keeps_digit_only_bond_mac_canonical(self):
        mac = ":".join(("46", "38", "39", "01", "01", "01"))
        runtime = (
            "- set:\n"
            "    mlag:\n"
            f"      mac-address: {mac}\n"
            "    interface:\n"
            "      bond1:\n"
            "        type: bond\n"
            "        bond:\n"
            "          member:\n"
            "            swp1: {}\n"
            "          mlag:\n"
            "            id: 1\n"
            "            state: enabled\n"
            "    vrf:\n"
            "      default:\n"
            "        router:\n"
            "          bgp:\n"
            "            autonomous-system: 65001\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "leaf01.yaml"
            source.write_text(runtime, encoding="utf-8")
            cfg = FEEDBACK.load_yaml(source)

        self.assertEqual(mac, cfg["mlag"]["mac-address"])
        self.assertIsInstance(cfg["mlag"]["mac-address"], str)
        self.assertEqual(
            65001,
            cfg["vrf"]["default"]["router"]["bgp"]["autonomous-system"],
        )
        _base, _ordinary, fixed, _evpn = FEEDBACK.parse_device_v2(
            cfg,
            "leaf01",
            "eth",
            {
                "template": "border", "eth0_ip": "NA", "netmask": "NA",
                "eth0_gw": "NA", "eth0_mac": "NA", "eth1_ip": "NA",
                "eth1_nm": "NA", "eth1_gw": "NA", "eth1_mac": "NA",
            },
        )
        self.assertEqual(mac, fixed[4])

    def test_feedback_v2_recovers_mlag_bond_mac_from_runtime(self):
        cfg = {
            "mlag": {"mac-address": MLAG_MAC_A},
            "interface": {
                "bond1": {
                    "type": "bond",
                    "bond": {
                        "member": {"swp1": {}},
                        "mlag": {"id": 1, "state": "enabled"},
                    },
                },
                "bond2": {
                    "type": "bond",
                    "bond": {
                        "member": {"swp2": {}},
                        "mlag": {"id": 2, "state": "enabled"},
                    },
                },
            },
        }
        info = {
            "template": "border", "eth0_ip": "NA", "netmask": "NA",
            "eth0_gw": "NA", "eth0_mac": "NA", "eth1_ip": "NA",
            "eth1_nm": "NA", "eth1_gw": "NA", "eth1_mac": "NA",
        }

        _base, _ordinary, fixed, _evpn = FEEDBACK.parse_device_v2(
            cfg, "border01", "eth", info,
        )

        self.assertEqual("bond1-2", fixed[2])
        self.assertEqual("mlag", fixed[3])
        self.assertEqual(MLAG_MAC_A, fixed[4])

    def test_feedback_v2_global_uses_mac_keyed_shared_address(self):
        configs = [
            {
                "mlag": {
                    "init-delay": 20,
                    "priority": priority,
                    "mac-address": MLAG_MAC_A.upper(),
                },
                "nve": {"vxlan": {"mlag": {
                    "shared-address": "198.51.100.201",
                }}},
                # Runtime system MAC is device-local state and must not be
                # projected into the schema-v2 MLAG global contract.
                "system": {"global": {
                    "system-mac": f"02:00:00:00:00:{index:02x}",
                }},
            }
            for index, priority in ((1, 100), (2, 200))
        ]

        document = FEEDBACK.build_global_document(
            configs, v2_mlag_global([]),
        )
        eth = next(item["eth"] for item in document["switches"] if "eth" in item)

        self.assertEqual(
            [{"bond-mac": MLAG_MAC_A, "anycast-ip": "198.51.100.201"}],
            eth["mlag"]["shared-addresses"],
        )
        self.assertNotIn("pairs", eth["mlag"])
        self.assertNotIn("system-mac", eth["mlag"])

    def test_feedback_v2_global_rejects_ambiguous_shared_address_identity(self):
        def runtime(mac, address):
            return {
                "mlag": {"mac-address": mac},
                "nve": {"vxlan": {"mlag": {"shared-address": address}}},
            }

        conflicts = {
            "one MAC with two IPs": [
                runtime(MLAG_MAC_A, "198.51.100.201"),
                runtime(MLAG_MAC_A, "198.51.100.202"),
            ],
            "one IP with two MACs": [
                runtime(MLAG_MAC_A, "198.51.100.201"),
                runtime(MLAG_MAC_B, "198.51.100.201"),
            ],
        }
        for label, configs in conflicts.items():
            with self.subTest(label=label), self.assertRaisesRegex(
                ValueError, "bond-mac|anycast-ip|MAC|IP",
            ):
                FEEDBACK.build_global_document(configs, v2_mlag_global([]))

        with self.assertRaisesRegex(ValueError, "已删除.*mlag.pairs"):
            FEEDBACK.build_global_document(
                [],
                v2_mlag_global(legacy_pairs=[{
                    "shared-addresses": ["198.51.100.201"],
                    "system-mac": [MLAG_MAC_A, MLAG_MAC_B],
                    "mac-address": [MLAG_MAC_A],
                }]),
            )

    def test_feedback_v1_keeps_legacy_mlag_pair_shape(self):
        configs = [{
            "mlag": {
                "init-delay": 20,
                "priority": 100,
                "mac-address": MLAG_MAC_A,
            },
            "nve": {"vxlan": {"mlag": {
                "shared-address": "198.51.100.201",
            }}},
            "system": {"global": {"system-mac": MLAG_MAC_B}},
        }]
        baseline = {
            "schema_version": 1,
            "switches": [{"eth": {"mlag": {}}}],
        }

        document = FEEDBACK.build_global_document(configs, baseline)
        eth = document["switches"][0]["eth"]

        self.assertEqual(
            [{
                "shared-addresses": ["198.51.100.201"],
                "system-mac": [MLAG_MAC_B],
                "mac-address": [MLAG_MAC_A],
            }],
            eth["mlag"]["pairs"],
        )

    def test_feedback_projects_runtime_state_into_v2_groups(self):
        cfg = {
            "system": {"hostname": "leaf01"},
            "bridge": {"domain": {"br_default": {"vlan": {
                "100": {}, "101": {},
                "110": {"vni": {"10110": {}}},
            }}}},
            "interface": {
                "eth0": {"ipv4": {"address": {"192.0.2.10/24": {}},
                                     "gateway": {"192.0.2.1": {}}}},
                "lo": {"ipv4": {"address": {"198.51.100.10/32": {}}}},
                "bond49b51": {
                    "type": "bond",
                    "bond": {"member": {"swp49": {}, "swp51": {}}},
                    "bridge": {"domain": {"br_default": {
                        "untagged": 100, "vlan": {"100": {}, "101": {}},
                    }}},
                },
                "bond1": {
                    "type": "bond",
                    "bond": {"member": {"swp1": {}}},
                    "evpn": {"multihoming": {"segment": {
                        "mac-address": "02:00:00:00:10:01",
                    }}},
                    "bridge": {"domain": {"br_default": {
                        "untagged": 110, "vlan": {"110": {}},
                    }}},
                },
                "vlan110": {
                    "type": "svi", "vlan": 110, "vrf": "BLUE",
                    "ipv4": {
                        "address": {"203.0.113.2/24": {}},
                        "vrr": {
                            "address": {"203.0.113.254/24": {}},
                            "mac-address": "02:00:5e:01:01:10",
                        },
                    },
                },
            },
            "vrf": {"default": {"router": {"bgp": {
                "autonomous-system": 65001,
            }}}, "BLUE": {"evpn": {"vlan": 4001, "vni": {"4001": {}}}}},
            "service": {"dhcp-relay": {"BLUE": {
                "downstream-interface": {"vlan110": {
                    "server-group-name": "servers",
                }},
            }}},
        }
        info = {
            "template": "tan-leaf", "eth0_ip": "192.0.2.10",
            "netmask": "24", "eth0_gw": "192.0.2.1",
            "eth0_mac": "02:00:00:00:00:10", "eth1_ip": "NA",
            "eth1_nm": "NA", "eth1_gw": "NA", "eth1_mac": "NA",
        }

        base, ordinary, fixed, evpn = FEEDBACK.parse_device_v2(
            cfg, "leaf01", "eth", info,
        )

        self.assertEqual(12, len(base))
        self.assertEqual(
            [
                ["100/native", "NA", "NA", "bond49b51"],
                ["101", "NA", "NA", "bond49b51"],
            ],
            ordinary,
        )
        self.assertEqual("bond49b51|bond1", fixed[2])
        self.assertEqual("local|evpn", fixed[3])
        self.assertEqual("NA|02:00:00:00:10:01", fixed[4])
        self.assertEqual(
            [[
                "BLUE", "4001", "4001", "servers", "10110",
                "110/native", "203.0.113.2", "24", "bond1",
            ]],
            evpn,
        )
        self.assertNotIn("203.0.113.254", "|".join(evpn[0]))
        self.assertNotIn(VRR_VLAN_110_MAC, "|".join(evpn[0]))

    def test_feedback_rejects_runtime_native_vlan_that_v2_cannot_express(self):
        cfg = {
            "bridge": {"domain": {"br_default": {"vlan": {"100": {}}}}},
            "interface": {
                "swp1": {"bridge": {"domain": {"br_default": {
                    "untagged": 100, "vlan": {"100": {}},
                }}}},
                "swp2": {"bridge": {"domain": {"br_default": {
                    "vlan": {"100": {}},
                }}}},
            },
        }
        info = {
            "template": "tan-leaf", "eth0_ip": "NA", "netmask": "NA",
            "eth0_gw": "NA", "eth0_mac": "NA", "eth1_ip": "NA",
            "eth1_nm": "NA", "eth1_gw": "NA", "eth1_mac": "NA",
        }
        with self.assertRaisesRegex(ValueError, "native.*有的端口.*有的端口"):
            FEEDBACK.parse_device_v2(cfg, "leaf01", "eth", info)

    def test_feedback_semantic_headers_distinguish_v2_repeated_groups(self):
        header = v2_header(vlan_groups=2, evpn_groups=2)
        semantic = FEEDBACK._semantic_headers(header)
        self.assertEqual("vlan[1].vlan_id", semantic[12])
        self.assertEqual("vlan[2].vlan_id", semantic[16])
        self.assertEqual("bgp_asn", semantic[20])
        self.assertEqual("evpn[1].evpn_vrf", semantic[27])
        self.assertEqual("evpn[2].evpn_vrf", semantic[36])

    def test_feedback_comparison_keeps_derived_runtime_vrr_evidence(self):
        config = {
            "interface": {"vlan100": {
                "type": "svi", "vlan": 100,
                "ipv4": {
                    "address": {"192.0.2.2/24": {}},
                    "vrr": {
                        "address": {"192.0.2.254/24": {}},
                        "mac-address": "02:00:5e:01:01:00",
                    },
                },
            }},
        }
        signature = FEEDBACK._vrr_runtime_signature(config)
        self.assertIn("vlan100", signature)
        self.assertIn("192.0.2.254/24", signature)
        self.assertIn(VRR_VLAN_100_MAC, signature)

        drift = copy.deepcopy(config)
        drift["interface"]["vlan100"]["ipv4"]["vrr"][
            "mac-address"
        ] = VRR_VLAN_100_MAC[:-2] + "65"
        self.assertNotEqual(signature, FEEDBACK._vrr_runtime_signature(drift))


if __name__ == "__main__":
    unittest.main()
