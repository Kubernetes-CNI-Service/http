#!/usr/bin/env python3
"""Schema-v2 workflow across setup, load, DHCP, generators, and Jinja output."""

from __future__ import annotations

import copy
from contextlib import redirect_stdout
import csv
import hashlib
import importlib.util
import io
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
TEMPLATES = ROOT / "ztp/config/cumulus/template/03-templates-j2"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    sys.path[:0] = [str(path.parent), str(TOOLS), str(ROOT)]
    try:
        spec.loader.exec_module(module)
    finally:
        del sys.path[:3]
    return module


SETUP = load_module("v2_flow_setup", ROOT / "DAY0-Prepare/01-a-setup.py")
LOAD = load_module("v2_flow_load", ROOT / "DAY0-Prepare/11-load.py")
DHCP = load_module(
    "v2_flow_dhcp", ROOT / "ztp/config/isc-dhcp-server/c1-generate_dhcp.py",
)
GENERATOR = load_module(
    "v2_flow_generator",
    ROOT / "ztp/config/cumulus/template/90-c2-generate_configs.py",
)
PUBLISHER = load_module(
    "v2_flow_publisher", ROOT / "ztp/config/cumulus/d-hostname2mac.py",
)
FEEDBACK = load_module(
    "v2_flow_feedback", ROOT / "ztp/optimize/feedback.py",
)


BASE_HEADER = [
    "hostname", "type", "template", "eth0_ip", "netmask", "eth0_gw",
    "eth0_mac", "eth1_ip", "netmask", "eth1_gw", "eth1_mac", "lo_ip",
]
VLAN_HEADER = ["vlan_id", "svi_ip", "netmask", "vlan_ports"]
FIXED_HEADER = [
    "bgp_asn", "bgp_ports", "bond_ports", "bond_type", "bond_mac",
    "peerlink_ports", "vrl",
]
EVPN_HEADER = [
    "evpn_vrf", "evpn_l3vni", "evpn_l3vlan", "dhcp_relay",
    "evpn_l2vni", "evpn_l2vlan", "svi_ip", "netmask", "vlan_ports",
]


def set_block(document):
    blocks = [
        item["set"] for item in document
        if isinstance(item, dict) and isinstance(item.get("set"), dict)
    ]
    if len(blocks) != 1:
        raise AssertionError(f"expected one set block, got {len(blocks)}")
    return blocks[0]


def v2_mlag_preflight_global(shared_addresses=None):
    """Build an independent setup-preflight fixture for the v2 MLAG contract."""
    mlag = {}
    if shared_addresses is not None:
        mlag["shared-addresses"] = copy.deepcopy(shared_addresses)
    return {
        "schema_version": 2,
        "common": {"mgmt": {"ztp": {"ztp_url_prefix": "/ztp"}}},
        "switches": [{"eth": {
            "bridge": {},
            "vrr": {
                "base_mac": "02:00:5e:01:00:00",
                "gateway_ip": "subnet_maximum",
            },
            "mlag": mlag,
            "system": {},
        }}],
    }


def v2_mlag_preflight_row(
        hostname, host_id, loopback, *, template="border",
        bond_mac="02:00:00:ff:00:12", bond_ports="bond1",
        bond_type="mlag", peerlink="swp49-50", vrf="BLUE",
        l3vni="4001", l3vlan="4001", l2vni="10100", l2vlan="100",
        svi_ip="NA", netmask="NA"):
    """Return one fixed-width row without deriving any expected result."""
    return [
        hostname, "eth", template, f"192.0.2.{host_id}", "24",
        "192.0.2.1", f"02:00:00:00:03:{host_id:02x}",
        "NA", "NA", "NA", "NA", loopback,
        "65001", "swp53", bond_ports, bond_type, bond_mac, peerlink,
        "false", vrf, l3vni, l3vlan, "NA", l2vni, l2vlan,
        svi_ip, netmask, bond_ports,
    ]


def run_v2_mlag_setup_preflight(rows, shared_addresses=None):
    """Write a complete project input pair and call setup's direct validator."""
    header = BASE_HEADER + FIXED_HEADER + EVPN_HEADER
    if {len(row) for row in rows} != {len(header)}:
        raise AssertionError("fixture row width does not match v2 header")
    temporary = tempfile.TemporaryDirectory()
    root = Path(temporary.name)
    global_file = root / "01-global.yaml"
    devices_file = root / "02-devices_config.csv"
    global_file.write_text(
        yaml.safe_dump(
            v2_mlag_preflight_global(shared_addresses), sort_keys=False,
        ),
        encoding="utf-8",
    )
    with devices_file.open("w", newline="", encoding="utf-8") as stream:
        csv.writer(stream).writerows([header, *rows])
    errors, warnings = SETUP._validate_v2_mlag_project(
        str(global_file), str(devices_file),
    )
    return temporary, root, errors, warnings


class V2MlagSetupPreflightTests(unittest.TestCase):
    """Direct and workflow tests for setup's cross-file fail-closed gate."""

    MAC_A = "02:00:00:ff:00:12"
    MAC_B = "02:00:00:ff:00:34"

    def pair(self, **overrides):
        first = v2_mlag_preflight_row(
            "Border01", 10, "198.51.100.10", **overrides,
        )
        second_options = dict(overrides)
        second_options.pop("hostname", None)
        second_options.pop("host_id", None)
        second_options.pop("loopback", None)
        second = v2_mlag_preflight_row(
            "Border02", 11, "198.51.100.11", **second_options,
        )
        return [first, second]

    def assert_preflight_fails(self, rows, expected, shared_addresses=None):
        temporary, _root, errors, _warnings = run_v2_mlag_setup_preflight(
            rows, shared_addresses,
        )
        try:
            self.assertTrue(
                any(expected in message for message in errors), errors,
            )
        finally:
            temporary.cleanup()

    def test_direct_preflight_accepts_complete_active_plain_and_evpn_groups(self):
        active = self.pair()
        plain = [
            v2_mlag_preflight_row(
                "OOB01", 20, "198.51.100.20", template="oobofoob-spine",
                bond_mac=self.MAC_B, vrf="PLAIN", l3vni="NA", l3vlan="NA",
                l2vni="NA", l2vlan="200",
            ),
            v2_mlag_preflight_row(
                "OOB02", 21, "198.51.100.21", template="oobofoob-spine",
                bond_mac=self.MAC_B, vrf="PLAIN", l3vni="NA", l3vlan="NA",
                l2vni="NA", l2vlan="200",
            ),
        ]
        evpn = v2_mlag_preflight_row(
            "Leaf01", 30, "198.51.100.30", template="tan-leaf",
            bond_mac="02:00:00:ff:00:56", bond_type="evpn",
            peerlink="NA", vrf="RED", l3vni="5001", l3vlan="5001",
            l2vni="10200", l2vlan="200",
        )
        temporary, _root, errors, warnings = run_v2_mlag_setup_preflight(
            [*active, *plain, evpn], [{
                "bond-mac": self.MAC_A,
                "anycast-ip": "198.51.100.201",
            }],
        )
        try:
            self.assertEqual([], errors)
            self.assertEqual([], warnings)
        finally:
            temporary.cleanup()

    def test_direct_preflight_rejects_invalid_pair_and_override_contracts(self):
        one_member = self.pair()[:1]
        self.assert_preflight_fails(one_member, "必须恰好对应 2 台设备")

        missing_peerlink = self.pair()
        missing_peerlink[1][17] = "NA"
        self.assert_preflight_fails(missing_peerlink, "必须配置 peerlink_ports")

        mismatched_bonds = self.pair()
        mismatched_bonds[1][14] = "bond2"
        mismatched_bonds[1][27] = "bond2"
        self.assert_preflight_fails(mismatched_bonds, "bond 集合不一致")

        mismatched_vni = self.pair()
        mismatched_vni[1][23] = "10101"
        self.assert_preflight_fails(mismatched_vni, "VLAN/VNI inventory 不一致")

        unsupported = self.pair(template="tan-leaf", l3vni="NA",
                                l3vlan="NA", l2vni="NA")
        self.assert_preflight_fails(unsupported, "只支持 border 或 oobofoob-spine")

        unsupported_active = self.pair(template="oobofoob-spine")
        self.assert_preflight_fails(
            unsupported_active, "启用 VNI 时只支持 border 模板",
        )

        nonactive = self.pair(l3vni="NA", l3vlan="NA", l2vni="NA")
        self.assert_preflight_fails(
            nonactive,
            "未对应 VXLAN active-active MLAG pair",
            [{"bond-mac": self.MAC_A, "anycast-ip": "198.51.100.201"}],
        )
        self.assert_preflight_fails(
            self.pair(),
            "未对应 VXLAN active-active MLAG pair",
            [{"bond-mac": self.MAC_B, "anycast-ip": "198.51.100.201"}],
        )

    def test_direct_preflight_rejects_override_and_derived_ip_collisions(self):
        collision_variants = (
            ("192.0.2.10", "eth0"),
            ("198.51.100.10", "lo"),
            ("203.0.113.2", "svi"),
            ("203.0.113.254", "vrr"),
        )
        for address, label in collision_variants:
            with self.subTest(label=label):
                rows = self.pair(
                    svi_ip="203.0.113.2", netmask="24",
                )
                rows[1][25] = "203.0.113.3"
                self.assert_preflight_fails(
                    rows, "与现有地址冲突", [{
                        "bond-mac": self.MAC_A,
                        "anycast-ip": address,
                    }],
                )

        rows = self.pair()
        rows.append(v2_mlag_preflight_row(
            "Standalone", 12, "198.51.100.12", template="tan-spine",
            bond_ports="NA", bond_type="NA", bond_mac="NA",
            peerlink="NA", vrf="NA", l3vni="NA", l3vlan="NA",
            l2vni="NA", l2vlan="NA",
        ))
        self.assert_preflight_fails(rows, "与现有地址冲突")

    def test_direct_preflight_rejects_v2_source_yaml_audit_rows(self):
        header = (
            BASE_HEADER + FIXED_HEADER + EVPN_HEADER
            + [
                "source_yaml_b64", "source_yaml_sha256",
                "source_fields_sha256",
            ]
        )
        row = self.pair()[0] + ["gzip+base64:fixture", "a" * 64, "b" * 64]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            global_file = root / "01-global.yaml"
            devices_file = root / "02-devices_config.csv"
            global_file.write_text(
                yaml.safe_dump(v2_mlag_preflight_global(), sort_keys=False),
                encoding="utf-8",
            )
            with devices_file.open("w", newline="", encoding="utf-8") as stream:
                csv.writer(stream).writerows([header, row])
            errors, _warnings = SETUP._validate_v2_mlag_project(
                str(global_file), str(devices_file),
            )
        self.assertTrue(
            any("source_yaml" in message and "删除" in message
                for message in errors),
            errors,
        )

    def test_workflow_stops_before_link_transaction_on_cross_file_error(self):
        temporary, root, _errors, _warnings = run_v2_mlag_setup_preflight(
            self.pair()[:1],
        )
        p2p = root / "p2p.xlsx"
        p2p.write_bytes(b"fixture")
        old_state = (
            SETUP._P2P_SOURCE, SETUP._LINK_TRANSACTION, SETUP._STRICT,
            SETUP._DRY_RUN, SETUP._AUTO_YES, SETUP._FORCE,
        )
        try:
            SETUP._P2P_SOURCE = None
            SETUP._LINK_TRANSACTION = None
            SETUP._STRICT = False
            SETUP._DRY_RUN = True
            SETUP._AUTO_YES = True
            SETUP._FORCE = False
            with mock.patch.object(
                SETUP, "_initialize_project_from_template",
            ), mock.patch.object(
                SETUP, "_select_p2p_source", return_value=str(p2p),
            ), mock.patch.object(
                SETUP, "_validate_global_yaml", return_value=([], []),
            ), mock.patch.object(
                SETUP, "_validate_eth_csv", return_value=([], []),
            ), mock.patch.object(
                SETUP, "_validate_xlsx", return_value=([], []),
            ), mock.patch.object(
                SETUP, "_SetupLinkTransaction",
            ) as transaction:
                with self.assertRaises(SystemExit):
                    SETUP._setup_impl(str(root))
            transaction.assert_not_called()
        finally:
            (
                SETUP._P2P_SOURCE, SETUP._LINK_TRANSACTION, SETUP._STRICT,
                SETUP._DRY_RUN, SETUP._AUTO_YES, SETUP._FORCE,
            ) = old_state
            temporary.cleanup()


class V2GenerationWorkflowTests(unittest.TestCase):
    """Run the new declarative schema through all local production consumers."""

    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        try:
            cls._build(Path(cls.temporary.name))
        except BaseException:
            cls.temporary.cleanup()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    @classmethod
    def _build(cls, root: Path):
        cls.root = root
        cls.global_file = root / "01-global.yaml"
        cls.devices_file = root / "02-devices_config.csv"
        cls.subnet_file = root / "02-dhcp-subnet_config.csv"
        cls.intermediate = root / "91-devices.yaml"
        cls.output = root / "generated"
        cls.dhcp_dir = root / "dhcp"
        cls.dhcp_dir.mkdir()

        cls.global_file.write_text(
            """schema_version: 2
common:
  mgmt:
    dhcp-server: {status: enabled, package: isc-dhcp-server}
    http: {status: enabled, package: apache2, http_root: /var/www/html}
    ztp: {status: enabled, ztp_url_prefix: /ztp}
  switch:
    system:
      config: {auto-save: {state: enabled}}
      date-time: {timezone: Etc/UTC}
      dns: {server: [192.0.2.53]}
      ntp: {server: [192.0.2.123]}
switches:
  - eth:
      version: 5.16.4
      bridge: {domain: {br_default: {stp: {priority: 4096}}}}
      vrr: {base_mac: '02:00:5e:01:00:00', gateway_ip: subnet_maximum}
      mlag:
        init-delay: 20
        priority: [100, 200]
        shared-addresses: []
      services:
        dhcp_relay:
          BLUE:
            server_group:
              - group: servers
                servers: [203.0.113.10]
          RED:
            server_group:
              - group: servers
                servers: [198.51.100.10]
      system:
        aaa:
          user:
            cumulus: {full-name: 'cumulus,,,', hashed-password: "'*'"}
        dns: {server: [192.0.2.53], vrf: mgmt}
        ntp: {server: [192.0.2.123], vrf: mgmt}
      vrf:
        default:
          router:
            bfd:
              profile:
                bgp-underlay-bfd:
                  detect-multiplier: 3
                  min-rx-interval: 300
                  min-tx-interval: 300
  - ib:
      version: 25.02
      system: {aaa: {user: {admin: {password: '*'}}}}
""",
            encoding="utf-8",
        )

        header = BASE_HEADER + VLAN_HEADER * 2 + FIXED_HEADER + EVPN_HEADER * 2

        def base(host, kind, template, ip, mac, lo, *, eth1=None):
            second = eth1 or ("NA", "NA", "NA", "NA")
            return [
                host, kind, template, ip, "24", "192.0.2.1", mac,
                *second, lo,
            ]

        def leaf(host, ip, mac, lo, unique_svi, evpn_mac):
            return (
                base(host, "eth", "tan-leaf", ip, mac, lo)
                + ["100/native", "", "", "bond49b51"]
                + ["101-102", "", "", "bond49b51"]
                + [
                    "65001", "swp53s0", "bond49b51|bond1", "local|evpn",
                    evpn_mac, "NA", "false",
                ]
                + [
                    "BLUE", "4001", "4001", "servers", "10110",
                    "110/native", unique_svi, "24", "bond1",
                ]
                + [
                    "RED", "4002", "4002", "servers", "10111", "111",
                    "198.51.100.254", "24", "bond1",
                ]
            )

        def spine(host, ip, mac, lo):
            return (
                base(host, "eth", "oobofoob-spine", ip, mac, lo)
                + ["200/native", "", "", "bond49"]
                + ["201-202", "", "", "bond49"]
                + [
                    "NA", "NA", "bond49", "mlag",
                    "02:00:00:ff:00:45", "swp50-51",
                    "false",
                ]
                + [""] * (len(EVPN_HEADER) * 2)
            )

        ib = (
            base(
                "EXAMPLE-IB01", "ib", "leaf", "192.0.2.20",
                "02:00:00:00:00:20", "NA",
                eth1=("192.0.3.20", "24", "192.0.3.1", "02:00:00:00:00:21"),
            )
            + [""] * (len(header) - len(BASE_HEADER))
        )
        rows = [
            leaf(
                "EXAMPLE-Leaf01", "192.0.2.10", "02:00:00:00:00:10",
                "192.0.2.210", "203.0.113.2", "02:00:00:00:10:01",
            ),
            leaf(
                "EXAMPLE-Leaf02", "192.0.2.11", "02:00:00:00:00:11",
                "192.0.2.211", "203.0.113.3", "02:00:00:00:10:02",
            ),
            spine(
                "EXAMPLE-OOB-Spine01", "192.0.2.30", "02:00:00:00:00:30",
                "192.0.2.230",
            ),
            spine(
                "EXAMPLE-OOB-Spine02", "192.0.2.31", "02:00:00:00:00:31",
                "192.0.2.231",
            ),
            base(
                "EXAMPLE-TAN-Spine01", "eth", "tan-spine", "192.0.2.32",
                "02:00:00:00:00:32", "192.0.2.232",
            ) + [
                "300/native", "", "", "swp10",
                "301-302", "", "", "swp10",
                "65010", "swp41", "NA", "NA", "NA", "NA", "false",
            ] + [""] * (len(EVPN_HEADER) * 2),
            base(
                "EXAMPLE-OOB-SUSpine01", "eth", "oob-su-spine", "192.0.2.33",
                "02:00:00:00:00:33", "192.0.2.233",
            ) + [
                "310/native", "", "", "swp10",
                "311-312", "", "", "swp10",
                "65011", "swp1", "NA", "NA", "NA", "NA", "false",
            ] + [""] * (len(EVPN_HEADER) * 2),
            base(
                "EXAMPLE-NoVlan", "eth", "tan-leaf", "192.0.2.40",
                "02:00:00:00:00:40", "192.0.2.240",
            ) + [""] * (len(VLAN_HEADER) * 2) + [
                "65003", "swp53", "NA", "NA", "NA", "NA", "false",
            ] + [""] * (len(EVPN_HEADER) * 2),
            ib,
        ]
        if any(len(row) != len(header) for row in rows):
            raise AssertionError("fixture row width does not match v2 header")
        with cls.devices_file.open("w", newline="", encoding="utf-8") as stream:
            csv.writer(stream).writerows([header, *rows])

        cls.subnet_file.write_text(
            "shared_network,subnet,netmask,range_start,range_end,routers,"
            "ztp_service_ip,cumulus_profile,nvos_ztp\n"
            "mgmt,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.199,"
            "192.0.2.1,192.0.2.2,oob,yes\n"
            "ib-secondary,192.0.3.0,255.255.255.0,192.0.3.100,192.0.3.199,"
            "192.0.3.1,,none,no\n",
            encoding="utf-8",
        )

        cls.setup_errors, cls.setup_warnings = SETUP._validate_eth_csv(
            str(cls.devices_file)
        )
        cls.settings = LOAD.load_global(cls.global_file)
        cls.device_types = LOAD.load_device_types(
            cls.devices_file, cls.settings.schema_version,
        )

        bindings = {
            "SCRIPT_DIR": str(cls.dhcp_dir),
            "OUTPUT_ETH": str(cls.dhcp_dir / "dhcpd_eth.hosts"),
            "OUTPUT_IB": str(cls.dhcp_dir / "dhcpd_ib.hosts"),
            "OUTPUT_NVL": str(cls.dhcp_dir / "dhcpd_nvl.hosts"),
            "OUTPUT_CONF": str(cls.dhcp_dir / "dhcpd.conf"),
            "OUTPUT_MANIFEST": str(cls.dhcp_dir / "dhcp-release-manifest.json"),
            "SUBNET_CSV": str(cls.subnet_file),
            "GLOBAL_YAML": str(cls.global_file),
            "P2P_AIR_JSON": str(root / "absent-air.json"),
            "DEVICES_CSV": str(cls.devices_file),
            "_AUTO_YES": False,
        }
        with mock.patch.multiple(DHCP, **bindings), mock.patch.object(
            sys, "argv", ["c1-generate_dhcp.py", "-y"],
        ):
            DHCP.main()

        subnets = DHCP.load_subnet_csv(cls.subnet_file, "/ztp")
        DHCP.append_air_records_to_csv(
            cls.devices_file,
            [{
                "hostname": "AIR-EXAMPLE-Leaf01", "iface": "eth0",
                "mac": "02:00:00:00:00:aa",
            }],
            subnets,
        )
        cls.device_types = LOAD.load_device_types(
            cls.devices_file, cls.settings.schema_version,
        )

        with mock.patch.multiple(
            GENERATOR,
            _CSV_FILE=str(cls.devices_file),
            _GLOBAL_FILE=str(cls.global_file),
            DEVICES_FILE=str(cls.intermediate),
            TEMPLATES_DIR=str(TEMPLATES),
        ), mock.patch.object(GENERATOR, "_refresh_cumulus_defaults_from_global"):
            GENERATOR._generate_devices_yaml()
            with mock.patch.object(GENERATOR, "OUTPUT_DIR", str(cls.output)):
                GENERATOR.generate_all()

        cls.intermediate_document = yaml.safe_load(
            cls.intermediate.read_text(encoding="utf-8")
        )
        cls.generated_devices = cls.intermediate_document["devices"]
        cls.outputs = {
            path.stem: yaml.safe_load(PUBLISHER._canonical_yaml(str(path)))
            for path in cls.output.glob("*.yaml")
        }

        with mock.patch.multiple(
            GENERATOR,
            _CSV_FILE=str(cls.devices_file),
            _GLOBAL_FILE=str(cls.global_file),
        ):
            cls.nvos_devices, cls.nvos_errors = GENERATOR._load_csv_ib()

    def test_setup_load_dhcp_and_nvos_share_the_same_v2_layout(self):
        self.assertEqual([], self.setup_errors)
        self.assertEqual([], self.setup_warnings)
        self.assertEqual(2, self.settings.schema_version)
        self.assertEqual({"air", "eth", "ib"}, set(self.device_types))
        self.assertEqual([], self.nvos_errors)
        self.assertEqual(["EXAMPLE-IB01"], [item["hostname"] for item in self.nvos_devices])
        self.assertIn("host EXAMPLE-Leaf01", (self.dhcp_dir / "dhcpd_eth.hosts").read_text())
        self.assertIn("host EXAMPLE-IB01", (self.dhcp_dir / "dhcpd_ib.hosts").read_text())

    def test_mlag_shared_addresses_follow_bond_mac_through_the_real_flow(self):
        """Setup/load/generation/rendering must share the MAC-keyed contract."""
        pair_a_mac = "02:00:00:ff:00:12"
        pair_b_mac = "02:00:00:ff:00:34"
        pair_c_mac = "02:00:00:ff:00:45"
        evpn_mac = "02:00:00:ff:00:56"
        header = BASE_HEADER + FIXED_HEADER + EVPN_HEADER

        def row(
                hostname, host_id, loopback, bond_type, bond_mac, *,
                vxlan=True, vrf="BLUE", vlan=100,
                l3_vni=None, l2_vni=None, svi_ip="NA"):
            has_l3_vni = vxlan if l3_vni is None else l3_vni
            has_l2_vni = vxlan if l2_vni is None else l2_vni
            return [
                hostname, "eth",
                "border" if bond_type == "mlag" else "tan-leaf",
                f"192.0.2.{host_id}", "24", "192.0.2.1",
                f"02:00:00:00:02:{host_id:02x}",
                "NA", "NA", "NA", "NA", loopback,
                "65001", "swp53s0", "bond1", bond_type, bond_mac,
                "swp49-50" if bond_type == "mlag" else "NA", "false",
                vrf, "4001" if has_l3_vni else "NA",
                "4001" if has_l3_vni else "NA", "NA",
                "10100" if has_l2_vni else "NA", str(vlan),
                svi_ip, "24" if svi_ip != "NA" else "NA", "bond1",
            ]

        # Deliberately interleave the members: row order must not define pairs.
        rows = [
            row(
                "A1", 10, "198.51.100.10", "mlag", pair_a_mac,
                vrf="L2ONLY", l3_vni=False,
                svi_ip="203.0.113.254",
            ),
            row(
                "B1", 20, "198.51.100.20", "mlag", pair_b_mac,
                vrf="L3ONLY", l2_vni=False,
            ),
            row(
                "C1", 30, "198.51.100.30", "mlag", pair_c_mac,
                vxlan=False, vrf="PLAIN", vlan=200,
            ),
            row(
                "A2", 11, "198.51.100.11", "mlag", pair_a_mac,
                vrf="L2ONLY", l3_vni=False,
                svi_ip="203.0.113.254",
            ),
            row(
                "B2", 21, "198.51.100.25", "mlag", pair_b_mac,
                vrf="L3ONLY", l2_vni=False,
            ),
            row(
                "C2", 31, "198.51.100.31", "mlag", pair_c_mac,
                vxlan=False, vrf="PLAIN", vlan=200,
            ),
            row(
                "EVPN1", 40, "198.51.100.40", "evpn", evpn_mac,
                vrf="RED", vlan=300,
            ),
        ]
        self.assertEqual({len(header)}, {len(item) for item in rows})

        global_document = yaml.safe_load(
            self.global_file.read_text(encoding="utf-8")
        )
        eth = next(
            item["eth"] for item in global_document["switches"] if "eth" in item
        )
        eth["mlag"] = {
            "init-delay": 20,
            "priority": [100, 200],
            "shared-addresses": [{
                "bond-mac": pair_a_mac,
                "anycast-ip": "198.51.100.201",
            }],
        }

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            global_file = root / "01-global.yaml"
            devices_file = root / "02-devices_config.csv"
            intermediate = root / "91-devices.yaml"
            output = root / "generated"
            global_file.write_text(
                yaml.safe_dump(global_document, sort_keys=False), encoding="utf-8",
            )
            with devices_file.open("w", newline="", encoding="utf-8") as stream:
                csv.writer(stream).writerows([header, *rows])

            global_errors, _warnings = SETUP._validate_global_yaml(
                str(global_file), "eth",
            )
            csv_errors, _warnings = SETUP._validate_eth_csv(str(devices_file))
            self.assertEqual([], global_errors)
            self.assertEqual([], csv_errors)
            settings = LOAD.load_global(global_file)
            self.assertEqual(2, settings.schema_version)
            self.assertEqual(
                {"eth"}, set(LOAD.load_device_types(
                    devices_file, settings.schema_version,
                )),
            )

            with mock.patch.multiple(
                GENERATOR,
                _CSV_FILE=str(devices_file),
                _GLOBAL_FILE=str(global_file),
                DEVICES_FILE=str(intermediate),
                TEMPLATES_DIR=str(TEMPLATES),
            ), mock.patch.object(
                GENERATOR, "_refresh_cumulus_defaults_from_global",
            ):
                GENERATOR._generate_devices_yaml()
                with mock.patch.object(GENERATOR, "OUTPUT_DIR", str(output)):
                    GENERATOR.generate_all()

            model = yaml.safe_load(intermediate.read_text(encoding="utf-8"))
            devices = model["devices"]
            expected = {
                "A1": ("192.0.2.11", pair_a_mac, "198.51.100.201", True),
                "A2": ("192.0.2.10", pair_a_mac, "198.51.100.201", True),
                "B1": ("192.0.2.21", pair_b_mac, "198.51.100.26", True),
                "B2": ("192.0.2.20", pair_b_mac, "198.51.100.26", True),
                "C1": ("192.0.2.31", pair_c_mac, None, False),
                "C2": ("192.0.2.30", pair_c_mac, None, False),
            }
            documents = {
                path.stem: yaml.safe_load(PUBLISHER._canonical_yaml(str(path)))
                for path in output.glob("*.yaml")
            }
            for hostname, (backup, pair_mac, shared, active) in expected.items():
                with self.subTest(hostname=hostname):
                    device = devices[hostname]
                    self.assertEqual(backup, device["mlag_backup"])
                    self.assertEqual(pair_mac, device["mlag_mac_address"])
                    self.assertNotIn("system_mac", device)
                    if active:
                        self.assertEqual(shared, device["mlag_shared_address"])
                    else:
                        self.assertNotIn("mlag_shared_address", device)

                    block = set_block(documents[hostname])
                    self.assertEqual(pair_mac, block["mlag"]["mac-address"])
                    system_global = block.get("system", {}).get("global", {})
                    self.assertNotIn("system-mac", system_global)
                    if active:
                        self.assertEqual(
                            shared,
                            block["nve"]["vxlan"]["mlag"]["shared-address"],
                        )
                        self.assertEqual(
                            pair_mac, system_global["anycast-mac"],
                        )
                    else:
                        self.assertNotIn("mlag", block["nve"]["vxlan"])
                        self.assertNotIn("anycast-mac", system_global)

                    if hostname in {"A1", "A2"}:
                        vlan = device["vrfs"][0]["l2vlans"][0]
                        self.assertEqual("203.0.113.254/24", vlan["svi_ip"])
                        self.assertEqual("snippet", vlan["vrr_mode"])
                        self.assertEqual("", vlan["vrr_ip"])
                        self.assertEqual("02:00:5e:01:01:00", vlan["vrr_mac"])
                        vlan_ipv4 = block["interface"]["vlan100"]["ipv4"]
                        self.assertEqual(
                            {"203.0.113.254/24": {}}, vlan_ipv4["address"],
                        )
                        self.assertNotIn("vrr", vlan_ipv4)
                        self.assertEqual(
                            "hwaddress 02:00:5e:01:01:00\n",
                            block["system"]["config"]["snippet"]
                            ["ifupdown2_eni"]["vlan100"],
                        )

            evpn_device = devices["EVPN1"]
            self.assertNotIn("mlag_mac_address", evpn_device)
            self.assertNotIn("mlag_shared_address", evpn_device)
            evpn_block = set_block(documents["EVPN1"])
            self.assertEqual(
                evpn_mac,
                evpn_block["interface"]["bond1"]["evpn"]["multihoming"][
                    "segment"
                ]["mac-address"],
            )
            self.assertNotIn(
                "anycast-mac", evpn_block.get("system", {}).get("global", {}),
            )

    def test_missing_shared_addresses_key_defaults_through_real_consumers(self):
        """A present MLAG mapping needs no override list for auto derivation."""
        pair_mac = "02:00:00:ff:00:12"
        plain_mac = "02:00:00:ff:00:34"
        evpn_mac = "02:00:00:ff:00:56"
        rows = [
            v2_mlag_preflight_row(
                "A1", 10, "198.51.100.10", bond_mac=pair_mac,
            ),
            v2_mlag_preflight_row(
                "A2", 11, "198.51.100.11", bond_mac=pair_mac,
            ),
            v2_mlag_preflight_row(
                "P1", 20, "198.51.100.20", template="oobofoob-spine",
                bond_mac=plain_mac, vrf="NA", l3vni="NA", l3vlan="NA",
                l2vni="NA", l2vlan="NA",
            ),
            v2_mlag_preflight_row(
                "P2", 21, "198.51.100.21", template="oobofoob-spine",
                bond_mac=plain_mac, vrf="NA", l3vni="NA", l3vlan="NA",
                l2vni="NA", l2vlan="NA",
            ),
            v2_mlag_preflight_row(
                "EVPN1", 40, "198.51.100.40", template="tan-leaf",
                bond_mac=evpn_mac, bond_type="evpn", peerlink="NA",
                vrf="RED", l3vni="5001", l3vlan="3001",
                l2vni="10200", l2vlan="200",
            ),
        ]
        rows[-1][13] = "swp53s0"
        global_document = yaml.safe_load(
            self.global_file.read_text(encoding="utf-8")
        )
        eth = next(
            item["eth"] for item in global_document["switches"] if "eth" in item
        )
        eth["mlag"] = {"init-delay": 20, "priority": [100, 200]}
        self.assertNotIn("shared-addresses", eth["mlag"])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            global_file = root / "01-global.yaml"
            devices_file = root / "02-devices_config.csv"
            intermediate = root / "91-devices.yaml"
            output = root / "generated"
            global_file.write_text(
                yaml.safe_dump(global_document, sort_keys=False), encoding="utf-8",
            )
            with devices_file.open("w", newline="", encoding="utf-8") as stream:
                csv.writer(stream).writerows([
                    BASE_HEADER + FIXED_HEADER + EVPN_HEADER, *rows,
                ])

            global_errors, _warnings = SETUP._validate_global_yaml(
                str(global_file), "eth",
            )
            csv_errors, _warnings = SETUP._validate_eth_csv(str(devices_file))
            project_errors, _warnings = SETUP._validate_v2_mlag_project(
                str(global_file), str(devices_file),
            )
            self.assertEqual([], global_errors)
            self.assertEqual([], csv_errors)
            self.assertEqual([], project_errors)
            self.assertEqual(2, LOAD.load_global(global_file).schema_version)

            with mock.patch.multiple(
                GENERATOR,
                _CSV_FILE=str(devices_file),
                _GLOBAL_FILE=str(global_file),
                DEVICES_FILE=str(intermediate),
                TEMPLATES_DIR=str(TEMPLATES),
            ), mock.patch.object(
                GENERATOR, "_refresh_cumulus_defaults_from_global",
            ):
                GENERATOR._generate_devices_yaml()
                with mock.patch.object(GENERATOR, "OUTPUT_DIR", str(output)):
                    GENERATOR.generate_all()

            devices = yaml.safe_load(
                intermediate.read_text(encoding="utf-8")
            )["devices"]
            documents = {
                path.stem: yaml.safe_load(PUBLISHER._canonical_yaml(str(path)))
                for path in output.glob("*.yaml")
            }
            for hostname in ("A1", "A2"):
                with self.subTest(hostname=hostname):
                    self.assertEqual(
                        "198.51.100.12",
                        devices[hostname]["mlag_shared_address"],
                    )
                    block = set_block(documents[hostname])
                    self.assertEqual(
                        "198.51.100.12",
                        block["nve"]["vxlan"]["mlag"]["shared-address"],
                    )
                    self.assertEqual(
                        pair_mac, block["system"]["global"]["anycast-mac"],
                    )
            for hostname in ("P1", "P2"):
                with self.subTest(hostname=hostname):
                    self.assertNotIn("mlag_shared_address", devices[hostname])
                    block = set_block(documents[hostname])
                    self.assertNotIn(
                        "anycast-mac", block.get("system", {}).get("global", {}),
                    )
                    self.assertNotIn(
                        "mlag", block.get("nve", {}).get("vxlan", {}),
                    )
            self.assertNotIn("mlag_shared_address", devices["EVPN1"])
            evpn_block = set_block(documents["EVPN1"])
            self.assertEqual(
                evpn_mac,
                evpn_block["interface"]["bond1"]["evpn"]["multihoming"]
                ["segment"]["mac-address"],
            )
            self.assertNotIn(
                "anycast-mac", evpn_block.get("system", {}).get("global", {}),
            )

    def test_same_vlan_number_in_distinct_vrfs_survives_the_real_flow(self):
        """Setup/load/generator must scope VRR inference by VRF plus VLAN."""
        with self.devices_file.open(newline="", encoding="utf-8") as stream:
            rows = list(csv.reader(stream))
        header = rows[0]
        selected = [copy.deepcopy(rows[1]), copy.deepcopy(rows[2])]
        first_evpn = (
            len(BASE_HEADER) + len(VLAN_HEADER) * 2 + len(FIXED_HEADER)
        )
        selected[0][first_evpn + 3] = "NA"
        selected[1][first_evpn:first_evpn + 8] = [
            "GREEN", "4003", "4003", "NA", "10112", "110",
            "198.51.100.254", "24",
        ]

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            global_file = root / "01-global.yaml"
            devices_file = root / "02-devices_config.csv"
            intermediate = root / "91-devices.yaml"
            global_file.write_bytes(self.global_file.read_bytes())
            with devices_file.open("w", newline="", encoding="utf-8") as stream:
                csv.writer(stream).writerows([header, *selected])

            setup_errors, _warnings = SETUP._validate_eth_csv(
                str(devices_file)
            )
            self.assertEqual([], setup_errors)
            settings = LOAD.load_global(global_file)
            self.assertEqual(2, settings.schema_version)
            self.assertEqual(
                {"eth"}, set(LOAD.load_device_types(
                    devices_file, settings.schema_version,
                )),
            )

            with mock.patch.multiple(
                GENERATOR,
                _CSV_FILE=str(devices_file),
                _GLOBAL_FILE=str(global_file),
                DEVICES_FILE=str(intermediate),
                TEMPLATES_DIR=str(TEMPLATES),
            ), mock.patch.object(
                GENERATOR, "_refresh_cumulus_defaults_from_global",
            ):
                GENERATOR._generate_devices_yaml()

            devices = yaml.safe_load(
                intermediate.read_text(encoding="utf-8")
            )["devices"]
            def vlan110(hostname):
                return next(
                    l2
                    for vrf in devices[hostname]["vrfs"]
                    for l2 in vrf["l2vlans"]
                    if l2.get("vlan_id") == 110
                )

            leaf1 = vlan110("EXAMPLE-Leaf01")
            leaf2 = vlan110("EXAMPLE-Leaf02")
            self.assertEqual("standalone", leaf1["vrr_mode"])
            self.assertEqual("", leaf1["vrr_mac"])
            self.assertEqual("snippet", leaf2["vrr_mode"])
            self.assertEqual("02:00:5e:01:01:10", leaf2["vrr_mac"])

        with self.devices_file.open(newline="", encoding="utf-8") as stream:
            rows = list(csv.reader(stream))
        self.assertEqual({len(rows[0])}, {len(row) for row in rows})
        air = next(row for row in rows[1:] if row[0] == "AIR-EXAMPLE-Leaf01")
        self.assertEqual("air", air[1])
        self.assertEqual("192.0.2.10", air[3])
        self.assertTrue(all(not value for value in air[12:]))

    def test_vrr_modes_native_vlan_and_bond_groups_survive_rendering(self):
        leaf = set_block(self.outputs["EXAMPLE-Leaf01"])
        interfaces = leaf["interface"]
        self.assertEqual(
            {"mode": "lossless", "state": "enabled"},
            leaf["qos"]["roce"],
        )
        self.assertEqual(
            {"state": "enable"},
            interfaces["swp53s0"]["qos"]["pfc-watchdog"],
        )
        self.assertEqual(
            "enabled",
            interfaces["swp53s0"]["evpn"]["multihoming"]["uplink"],
        )
        local_bond = interfaces["bond49b51"]
        self.assertEqual(
            {"swp49": {}, "swp51": {}}, local_bond["bond"]["member"],
        )
        self.assertEqual(100, local_bond["bridge"]["domain"]["br_default"]["untagged"])
        self.assertEqual(
            {"100-102": {}},
            local_bond["bridge"]["domain"]["br_default"]["vlan"],
        )
        evpn_bond = interfaces["bond1"]
        self.assertEqual(110, evpn_bond["bridge"]["domain"]["br_default"]["untagged"])
        self.assertEqual(
            {"110-111": {}},
            evpn_bond["bridge"]["domain"]["br_default"]["vlan"],
        )
        for vlan in (100, 101, 102):
            self.assertNotIn(f"vlan{vlan}", interfaces)

        vlan110 = interfaces["vlan110"]
        self.assertEqual("br_default", vlan110["base-interface"])
        self.assertEqual(
            {"203.0.113.254/24": {}}, vlan110["ipv4"]["vrr"]["address"],
        )
        self.assertEqual(
            "02:00:5e:01:01:10", vlan110["ipv4"]["vrr"]["mac-address"],
        )
        vlan111 = interfaces["vlan111"]
        self.assertEqual({"198.51.100.254/24": {}}, vlan111["ipv4"]["address"])
        self.assertNotIn("vrr", vlan111["ipv4"])
        self.assertEqual(
            "hwaddress 02:00:5e:01:01:11\n",
            leaf["system"]["config"]["snippet"]["ifupdown2_eni"]["vlan111"],
        )

        relays = leaf["service"]["dhcp-relay"]
        self.assertEqual("giaddress", relays["BLUE"]["source-ip"])
        self.assertEqual(
            {"lo": {"address": "192.0.2.210"}},
            relays["RED"]["gateway-interface"],
        )
        self.assertNotIn("source-ip", relays["RED"])

    def test_oobofoob_spine_consumes_every_normalized_vlan_block(self):
        spine = set_block(self.outputs["EXAMPLE-OOB-Spine01"])
        bridge_vlans = spine["bridge"]["domain"]["br_default"]["vlan"]
        self.assertEqual({"200": {}, "201-202": {}}, bridge_vlans)
        bond = spine["interface"]["bond49"]
        self.assertEqual(200, bond["bridge"]["domain"]["br_default"]["untagged"])
        self.assertEqual(
            {"200-202": {}}, bond["bridge"]["domain"]["br_default"]["vlan"],
        )
        self.assertNotIn("bridge", spine["interface"]["peerlink"])
        for vlan in (200, 201, 202):
            self.assertNotIn(f"vlan{vlan}", spine["interface"])

    def test_every_spine_template_consumes_repeated_normalized_vlans(self):
        for hostname, native, selector in (
            ("EXAMPLE-TAN-Spine01", 300, "300-302"),
            ("EXAMPLE-OOB-SUSpine01", 310, "310-312"),
        ):
            with self.subTest(hostname=hostname):
                rendered = set_block(self.outputs[hostname])
                self.assertEqual(
                    {str(native): {}, f"{native + 1}-{native + 2}": {}},
                    rendered["bridge"]["domain"]["br_default"]["vlan"],
                )
                port = rendered["interface"]["swp10"]
                self.assertEqual(
                    native,
                    port["bridge"]["domain"]["br_default"]["untagged"],
                )
                self.assertEqual(
                    {selector: {}},
                    port["bridge"]["domain"]["br_default"]["vlan"],
                )

    def test_every_concrete_cumulus_template_renders_direct_native_vlan(self):
        """A normalized L2 attachment must never be silently lost by a template."""
        template_names = sorted(
            path.name.removesuffix(".yaml.j2")
            for path in TEMPLATES.glob("*.yaml.j2")
            if not path.name.startswith("_")
        )
        environment = GENERATOR.build_env()
        for template_name in template_names:
            with self.subTest(template=template_name):
                device = copy.deepcopy(self.generated_devices["EXAMPLE-NoVlan"])
                device.update({
                    "hostname": f"EXAMPLE-{template_name}",
                    "template": template_name,
                    # oobofoob-spine historically owns an unconditional MLAG
                    # section.  These values satisfy its unrelated template
                    # inputs while this case exercises only normalized L2.
                    "mlag_backup": "192.0.2.99",
                    "mlag_shared_address": "198.51.100.253",
                    "mlag_mac_address": "02:00:00:00:20:ff",
                    "mlag_priority": 100,
                    "system_mac": "02:00:00:00:20:01",
                    "vrfs": [{
                        "evpn_vrf": "default",
                        "evpn_l3vni": None,
                        "evpn_l3vlan": None,
                        "l2vlans": [{
                            "vlan_id": 350,
                            "vlan_spec": "350",
                            "vlan_ids": [350],
                            "vni": None,
                            "emit_svi": False,
                            "svi_ip": "",
                            "vrr_ip": "",
                            "vrr_mac": "",
                            "native": True,
                            "dhcp_relay": False,
                            "dhcp_server": "",
                            "vlan_ports": ["swp54"],
                        }],
                    }],
                })
                rendered = GENERATOR.render(
                    environment,
                    self.intermediate_document["global"],
                    device["hostname"],
                    device,
                )
                document = GENERATOR._load_generated_yaml(rendered)
                config = set_block(document)
                port = config["interface"]["swp54"]
                bridge = port["bridge"]["domain"]["br_default"]
                self.assertEqual(350, bridge["untagged"])
                self.assertEqual({"350": {}}, bridge["vlan"])
                self.assertIn(
                    "350", config["bridge"]["domain"]["br_default"]["vlan"],
                )

    def test_intermediate_model_has_no_v1_first_vlan_copy(self):
        leaf = self.generated_devices["EXAMPLE-Leaf01"]
        self.assertEqual(2, leaf["_project_schema_version"])
        self.assertNotIn("vlan_id", leaf)
        self.assertNotIn("svi_ip", leaf)
        self.assertNotIn("vrr_ip", leaf)
        self.assertEqual(
            ["default", "BLUE", "RED"],
            [vrf["evpn_vrf"] for vrf in leaf["vrfs"]],
        )

    def test_device_can_render_without_any_vlan_group(self):
        device = self.generated_devices["EXAMPLE-NoVlan"]
        self.assertEqual([], device["vrfs"])
        rendered = set_block(self.outputs["EXAMPLE-NoVlan"])
        self.assertFalse(any(
            str(name).startswith("vlan")
            for name in rendered["interface"]
        ))

    def test_v1_svi_render_keeps_its_legacy_shape(self):
        """Schema v2 fields must not create unrelated v1 configuration drift."""
        device = copy.deepcopy(self.generated_devices["EXAMPLE-Leaf01"])
        device["_project_schema_version"] = 1
        rendered = GENERATOR.render(
            GENERATOR.build_env(),
            self.intermediate_document["global"],
            device["hostname"],
            device,
        )
        config = set_block(GENERATOR._load_generated_yaml(rendered))
        self.assertNotIn("base-interface", config["interface"]["vlan110"])

    def test_border_v2_ignores_non_29_for_automatic_default_route(self):
        """Only a /29 Border SVI participates in the opposite-triplet plan."""
        device = copy.deepcopy(self.generated_devices["EXAMPLE-Leaf01"])
        device["template"] = "border"
        device["vrfs"] = [device["vrfs"][1]]
        device["vrfs"][0]["l2vlans"][0].update({
            "svi_ip": "203.0.113.2/24",
            "vrr_ip": "203.0.113.254/24",
            "vrr_gateway_ip": "203.0.113.254/24",
            "vrr_gateway_mode": "subnet_maximum",
            "vrr_mac": "02:00:5e:01:01:10",
        })
        GENERATOR._assign_v2_border_default_routes({"Border01": device})
        self.assertNotIn("default_route_next_hop", device["vrfs"][0])
        self.assertNotIn("peer_gateway_ip", device["vrfs"][0]["l2vlans"][0])

    def test_border_v2_renders_the_exact_opposite_triplet_next_hop(self):
        cases = (
            (
                "subnet_maximum", "203.0.113.140/29",
                "203.0.113.142/29", "203.0.113.139",
            ),
            (
                "subnet_minimum", "203.0.113.138/29",
                "203.0.113.137/29", "203.0.113.140",
            ),
        )
        for mode, svi, gateway, expected_peer in cases:
            with self.subTest(mode=mode):
                device = copy.deepcopy(self.generated_devices["EXAMPLE-Leaf01"])
                device.update({"hostname": "Border01", "template": "border"})
                device["vrfs"] = [device["vrfs"][1]]
                l2 = device["vrfs"][0]["l2vlans"][0]
                l2.update({
                    "svi_ip": svi,
                    "vrr_ip": gateway,
                    "vrr_gateway_ip": gateway,
                    "vrr_gateway_mode": mode,
                    "peer_gateway_ip": expected_peer,
                })
                GENERATOR._assign_v2_border_default_routes({"Border01": device})

                rendered = GENERATOR._load_generated_yaml(GENERATOR.render(
                    GENERATOR.build_env(), self.intermediate_document["global"],
                    "Border01", device,
                ))
                via = set_block(rendered)["vrf"]["BLUE"]["router"]["static"][
                    "default"
                ]["via"]
                self.assertEqual(
                    {expected_peer: {"type": "ipv4-address"}}, via,
                )

    def test_generation_aborts_before_publish_on_invalid_border_default_route(self):
        """The final rendered-route gate must reject a corrupted v2 next-hop."""
        device = copy.deepcopy(self.generated_devices["EXAMPLE-Leaf01"])
        device["template"] = "border"
        device["vrfs"] = [device["vrfs"][1]]
        device["vrfs"][0]["l2vlans"][0].update({
            "svi_ip": "203.0.113.140/29",
            "vrr_ip": "203.0.113.142/29",
            "vrr_mac": "02:00:5e:01:01:10",
        })
        device["vrfs"][0]["default_route_next_hop"] = "203.0.113.145"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "generated"
            with mock.patch.object(
                GENERATOR, "load_devices",
                return_value=(self.intermediate_document["global"], {"Border01": device}),
            ), mock.patch.object(GENERATOR, "OUTPUT_DIR", str(output)):
                with self.assertRaises(SystemExit) as raised:
                    GENERATOR.generate_all()
            self.assertEqual(1, raised.exception.code)
            self.assertFalse(output.exists())

    def test_generated_yaml_feedback_preserves_v2_csv_shape_and_native_markers(self):
        """Generator output must round-trip through the real Feedback consumer as v2."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "runtime"
            source.mkdir()
            shutil.copy2(
                self.output / "EXAMPLE-Leaf01.yaml",
                source / "EXAMPLE-Leaf01.yaml",
            )

            with self.devices_file.open(newline="", encoding="utf-8") as stream:
                rows = list(csv.reader(stream))
            inventory = root / "02-devices_config.csv"
            with inventory.open("w", newline="", encoding="utf-8") as stream:
                csv.writer(stream).writerows([
                    rows[0], next(row for row in rows[1:] if row[0] == "EXAMPLE-Leaf01"),
                ])
            global_file = root / "01-global.yaml"
            shutil.copy2(self.global_file, global_file)
            output = root / "feedback.csv"

            FEEDBACK.convert_one(
                source, output,
                devices_config_path=inventory,
                global_config_path=global_file,
                environment_scope="prod",
            )

            with output.open(newline="", encoding="utf-8") as stream:
                feedback_rows = list(csv.reader(stream))
            header, row = feedback_rows
            layout = __import__("project_contract").parse_device_csv_layout(header, 2)
            self.assertNotIn("vrr_ip", header)
            self.assertNotIn("vrr_mac", header)
            self.assertEqual(len(header), len(row))
            self.assertEqual(
                ["100/native", "101-102"],
                [row[start] for start in layout.vlan_group_starts],
            )
            self.assertEqual(
                ["110/native", "111"],
                [row[start + 5] for start in layout.evpn_group_starts],
            )
            self.assertEqual("local|evpn", row[layout.fixed_indices["bond_type"]])
            self.assertTrue(row[layout.metadata_start].startswith("gzip+base64:"))

    def test_feedback_mlag_source_receipts_are_audit_only_for_v2_generation(self):
        """Feedback preserves source evidence, but v2 generation rejects it."""
        pair_mac = "02:00:00:ff:00:12"
        shared_address = "198.51.100.201"
        hosts = (
            ("SOURCE-MLAG01", 10, 11, 100),
            ("SOURCE-MLAG02", 11, 10, 200),
        )

        def runtime_yaml(hostname, host_id, peer_id, priority):
            block = {
                "bridge": {"domain": {"br_default": {"vlan": {
                    "100": {"vni": {"10100": {}}},
                }}}},
                "evpn": {"state": "enabled"},
                "interface": {
                    "eth0": {
                        "ipv4": {
                            "address": {f"192.0.2.{host_id}/24": {}},
                            "gateway": {"192.0.2.1": {}},
                        },
                        "type": "eth",
                    },
                    "lo": {
                        "ipv4": {"address": {
                            f"198.51.100.{host_id}/32": {},
                        }},
                        "type": "loopback",
                    },
                    "bond1": {
                        "bond": {
                            "lacp-bypass": "on",
                            "member": {"swp1": {}},
                            "mlag": {"id": 1, "state": "enabled"},
                            "mode": "lacp",
                        },
                        "bridge": {"domain": {"br_default": {
                            "stp": {
                                "admin-edge": "on",
                                "bpdu-guard": "on",
                            },
                            "vlan": {"100": {}},
                        }}},
                        "type": "bond",
                    },
                    "peerlink": {
                        "bond": {
                            "member": {"swp49": {}, "swp50": {}},
                            "mode": "lacp",
                        },
                        "type": "peerlink",
                    },
                    "peerlink.4094": {
                        "base-interface": "peerlink",
                        "type": "sub",
                        "vlan": 4094,
                    },
                    "swp1": {"type": "swp"},
                    "swp49": {"type": "swp"},
                    "swp50": {"type": "swp"},
                    "vlan100": {
                        "base-interface": "br_default",
                        "ipv4": {"address": {
                            f"203.0.113.{host_id}/24": {},
                        }},
                        "type": "svi",
                        "vlan": 100,
                        "vrf": "BLUE",
                    },
                },
                "mlag": {
                    "backup": {f"192.0.2.{peer_id}": {}},
                    "init-delay": 20,
                    "mac-address": pair_mac,
                    "peer-ip": "linklocal",
                    "priority": priority,
                    "state": "enabled",
                },
                "nve": {"vxlan": {
                    "mlag": {"shared-address": shared_address},
                    "source": {"address": f"198.51.100.{host_id}"},
                    "state": "enabled",
                }},
                "system": {
                    "global": {"anycast-mac": pair_mac},
                    "hostname": hostname,
                },
                "vrf": {"BLUE": {"evpn": {
                    "vlan": 4001,
                    "vni": {"4001": {}},
                }}},
            }
            return yaml.safe_dump([{"set": block}], sort_keys=False)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "runtime"
            runtime.mkdir()
            source_bytes = {}
            for hostname, host_id, peer_id, priority in hosts:
                content = runtime_yaml(hostname, host_id, peer_id, priority).encode()
                source_bytes[hostname] = content
                (runtime / f"{hostname}.yaml").write_bytes(content)

            inventory = root / "02-devices_config.csv"
            header = BASE_HEADER + FIXED_HEADER + EVPN_HEADER
            rows = []
            for hostname, host_id, _peer_id, _priority in hosts:
                base = [
                    hostname, "eth", "oobofoob-spine",
                    f"192.0.2.{host_id}", "24", "192.0.2.1",
                    f"02:00:00:00:03:{host_id:02x}",
                    "NA", "NA", "NA", "NA", f"198.51.100.{host_id}",
                ]
                rows.append(base + [""] * (len(header) - len(base)))
            with inventory.open("w", newline="", encoding="utf-8") as stream:
                csv.writer(stream).writerows([header, *rows])

            baseline = yaml.safe_load(self.global_file.read_text(encoding="utf-8"))
            eth = next(
                item["eth"] for item in baseline["switches"] if "eth" in item
            )
            eth["mlag"] = {
                "init-delay": 20,
                "priority": [100, 200],
                "shared-addresses": [],
            }
            global_file = root / "01-global.yaml"
            global_file.write_text(
                yaml.safe_dump(baseline, sort_keys=False), encoding="utf-8",
            )

            feedback_csv = root / "feedback.csv"
            FEEDBACK.convert_one(
                runtime, feedback_csv,
                devices_config_path=inventory,
                global_config_path=global_file,
                environment_scope="prod",
            )
            feedback_global = root / "feedback-global.yaml"
            inferred = yaml.safe_load(feedback_global.read_text(encoding="utf-8"))
            inferred_eth = next(
                item["eth"] for item in inferred["switches"] if "eth" in item
            )
            self.assertEqual(
                [{"bond-mac": pair_mac, "anycast-ip": shared_address}],
                inferred_eth["mlag"]["shared-addresses"],
            )

            with feedback_csv.open(newline="", encoding="utf-8") as stream:
                feedback_rows = list(csv.reader(stream))
            feedback_header = feedback_rows[0]
            metadata = {
                name: feedback_header.index(name) for name in (
                    "source_yaml_b64", "source_yaml_sha256",
                    "source_fields_sha256",
                )
            }
            self.assertEqual(2, len(feedback_rows[1:]))
            for row in feedback_rows[1:]:
                hostname = row[0]
                with self.subTest(hostname=hostname):
                    self.assertTrue(
                        row[metadata["source_yaml_b64"]].startswith("gzip+base64:"),
                    )
                    self.assertEqual(
                        hashlib.sha256(source_bytes[hostname]).hexdigest(),
                        row[metadata["source_yaml_sha256"]],
                    )
                    self.assertRegex(
                        row[metadata["source_fields_sha256"]], r"^[0-9a-f]{64}$",
                    )

            intermediate = root / "91-devices.yaml"
            captured = io.StringIO()
            with mock.patch.multiple(
                GENERATOR,
                _CSV_FILE=str(feedback_csv),
                _GLOBAL_FILE=str(feedback_global),
                DEVICES_FILE=str(intermediate),
                TEMPLATES_DIR=str(TEMPLATES),
            ), mock.patch.object(
                GENERATOR, "_refresh_cumulus_defaults_from_global",
            ), redirect_stdout(captured), self.assertRaises(SystemExit) as raised:
                GENERATOR._generate_devices_yaml()
            self.assertEqual(1, raised.exception.code)
            self.assertFalse(intermediate.exists())
            self.assertRegex(
                captured.getvalue(),
                r"(?s)source_yaml_?.*删除.*source_yaml_.*元数据",
            )

    def test_v1_and_v2_inventory_produce_identical_dhcp_runtime_files(self):
        """Schema migration must not alter DHCP addressing or platform routing."""
        with self.devices_file.open(newline="", encoding="utf-8") as stream:
            v2_rows = list(csv.reader(stream))

        v1_header = (
            BASE_HEADER
            + ["vrf_default", "vlan_id", "svi_ip", "netmask", "vrr_ip", "vrr_mac", "vlan_ports"]
            + FIXED_HEADER
            + [
                "evpn_vrf", "evpn_l3vni", "evpn_l3vlan", "dhcp_relay",
                "evpn_l2vni", "evpn_l2vlan", "svi_ip", "netmask",
                "vrr_ip", "vrr_mac", "vlan_ports",
            ]
        )
        v1_rows = [v1_header]
        for row in v2_rows[1:]:
            v1_rows.append(row[:len(BASE_HEADER)] + [""] * (len(v1_header) - len(BASE_HEADER)))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            v1_csv = root / "devices-v1.csv"
            with v1_csv.open("w", newline="", encoding="utf-8") as stream:
                csv.writer(stream).writerows(v1_rows)
            v1_global = root / "global-v1.yaml"
            v1_global.write_text(
                self.global_file.read_text(encoding="utf-8").replace(
                    "schema_version: 2", "schema_version: 1", 1,
                ),
                encoding="utf-8",
            )

            def generate_dhcp(label, global_file, devices_file):
                target = root / label
                target.mkdir()
                bindings = {
                    "SCRIPT_DIR": str(target),
                    "OUTPUT_ETH": str(target / "dhcpd_eth.hosts"),
                    "OUTPUT_IB": str(target / "dhcpd_ib.hosts"),
                    "OUTPUT_NVL": str(target / "dhcpd_nvl.hosts"),
                    "OUTPUT_CONF": str(target / "dhcpd.conf"),
                    "OUTPUT_MANIFEST": str(target / "dhcp-release-manifest.json"),
                    "SUBNET_CSV": str(self.subnet_file),
                    "GLOBAL_YAML": str(global_file),
                    "P2P_AIR_JSON": str(root / "absent-air.json"),
                    "DEVICES_CSV": str(devices_file),
                    "_AUTO_YES": False,
                }
                with mock.patch.multiple(DHCP, **bindings), mock.patch.object(
                    sys, "argv", ["c1-generate_dhcp.py", "-y"],
                ):
                    DHCP.main()
                return target

            old = generate_dhcp("v1", v1_global, v1_csv)
            new = generate_dhcp("v2", self.global_file, self.devices_file)
            for filename in (
                "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts",
                "dhcpd_nvl.hosts",
            ):
                with self.subTest(filename=filename):
                    def without_generation_time(path):
                        return "\n".join(
                            line for line in path.read_text(encoding="utf-8").splitlines()
                            if "Generated at " not in line
                        )
                    self.assertEqual(
                        without_generation_time(old / filename),
                        without_generation_time(new / filename),
                    )


if __name__ == "__main__":
    unittest.main()
