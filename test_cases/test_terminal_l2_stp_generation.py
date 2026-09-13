#!/usr/bin/env python3
"""Terminal-facing layer-2 STP generation and workflow contracts."""

from __future__ import annotations

import base64
import copy
import csv
import hashlib
import importlib.util
from importlib.machinery import SourceFileLoader
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
    "terminal_l2_stp_generator_under_test",
    ROOT / "ztp/config/cumulus/template/90-c2-generate_configs.py",
)
PUBLISHER = load_script(
    "terminal_l2_stp_publisher_under_test",
    ROOT / "ztp/config/cumulus/d-hostname2mac.py",
)
MANUAL = load_script(
    "terminal_l2_stp_manual_compare_under_test",
    ROOT / "ztp/manual-ztp.py",
)
SETUP = load_script(
    "terminal_l2_stp_setup_under_test",
    ROOT / "DAY0-Prepare/01-a-setup.py",
)
FEEDBACK = load_script(
    "terminal_l2_stp_feedback_under_test",
    ROOT / "ztp/optimize/feedback.py",
)


CURRENT_CUMULUS_VERSION = "5.18.1"
EDGE_STP = {"admin-edge": "enabled", "bpdu-guard": "enabled"}
LEGACY_EDGE_STP = {"admin-edge": "on", "bpdu-guard": "on"}


def inject_terminal_l2_stp(document, **kwargs):
    kwargs.setdefault("cumulus_version", CURRENT_CUMULUS_VERSION)
    return GENERATOR._inject_terminal_l2_stp(document, **kwargs)


def terminal_l2_stp_errors(document, **kwargs):
    kwargs.setdefault("cumulus_version", CURRENT_CUMULUS_VERSION)
    return GENERATOR._terminal_l2_stp_errors(document, **kwargs)


def set_block(document):
    blocks = [
        item["set"] for item in document
        if isinstance(item, dict) and isinstance(item.get("set"), dict)
    ]
    if len(blocks) != 1:
        raise AssertionError(f"expected one set block, got {len(blocks)}")
    return blocks[0]


def direct_document():
    return [{"set": {"interface": {
        "swp1": {
            "bridge": {"domain": {"br_default": {"access": 10}}},
            "type": "swp",
        },
        "bond1": {
            "bond": {"member": {"swp2,3": {}}, "mode": "lacp"},
            "bridge": {"domain": {"br_default": {"vlan": {"10-20": {}}}}},
            "type": "bond",
        },
        "bond8": {
            "bond": {"member": {"swp8": {}, "swp9": {}}, "mode": "lacp"},
            "bridge": {"domain": {"br_default": {"vlan": {"10-20": {}}}}},
            "type": "bond",
        },
        "swp2": {
            "bridge": {"domain": {"br_default": {"access": 10}}},
            "type": "swp",
        },
        "swp3": {
            "bridge": {"domain": {"br_default": {"access": 10}}},
            "type": "swp",
        },
        "swp4": {"ipv4": {"address": {"192.0.2.4/31": {}}}, "type": "swp"},
        "swp8": {"type": "swp"},
        "swp9": {"type": "swp"},
        "peerlink": {
            "bond": {"member": {"swp49": {}, "swp50": {}}},
            "type": "peerlink",
        },
    }}}]


def border_globals():
    return {
        "bridge": {"domain": {"br_default": {"stp": {"priority": 4096}}}},
        "mlag": {"init-delay": 180},
        "version": CURRENT_CUMULUS_VERSION,
        "vrf": {"default": {"router": {"bfd": {"profile": {
            "bgp-underlay-bfd": {
                "detect-multiplier": 3,
                "min-rx-interval": 300,
                "min-tx-interval": 300,
            },
        }}}}},
        "system": {
            "aaa": {"user": {"cumulus": {
                "full-name": "cumulus,,,",
                "hashed-password": "'*'",
            }}},
            "date-time": {"timezone": "UTC"},
            "dns": {"server": ["192.0.2.53"], "vrf": "mgmt"},
            "ntp": {"server": ["192.0.2.123"], "vrf": "mgmt"},
        },
    }


def border_device():
    mlag_bond = {
        "type": "mlag",
        "bond_list": ["bond1"],
        "lacp-bypass": "enabled",
        "mac-address": "",
    }
    return {
        "_project_schema_version": 2,
        "template": "border",
        "hostname": "EXAMPLE-BORDER01",
        "eth0_ip": "192.0.2.10/24",
        "eth0_gw": "192.0.2.1",
        "has_eth1": False,
        "lo_ip": "198.51.100.10/32",
        "bgp_asn": 65101,
        "bgp_neighbors": ["swp9"],
        "peerlink_ports": "swp49-50",
        "vlan_id": 10,
        "vlan_ports": [],
        "bond_groups": [copy.deepcopy(mlag_bond)],
        "vrfs": [{
            "evpn_vrf": "BLUE",
            "evpn_l3vlan": None,
            "evpn_l3vni": None,
            "l2vlans": [{
                "vlan_id": 10,
                "vlan_spec": "10",
                "vlan_ids": [10],
                "vni": 1010,
                "emit_svi": False,
                "svi_ip": "",
                "vrr_ip": "",
                "vrr_mac": "",
                "vlan_ports": ["swp5", {"bonds": copy.deepcopy(mlag_bond)}],
            }],
        }],
        "mlag_backup": "192.0.2.11",
        "mlag_priority": 1000,
        "mlag_mac_address": "02:00:00:00:10:01",
        "mlag_shared_address": "198.51.100.1",
    }


def v2_header():
    return (
        list(CONTRACT.DEVICE_BASE_COLUMNS)
        + list(CONTRACT.DEVICE_V2_VLAN_COLUMNS)
        + list(CONTRACT.DEVICE_FIXED_COLUMNS)
    )


def v2_row():
    return [
        "leaf01", "eth", "tan-leaf", "192.0.2.10", "24",
        "192.0.2.1", "02:00:00:00:00:10", "NA", "NA", "NA",
        "NA", "198.51.100.10", "100", "NA", "NA", "swp5/bond1",
        "65001", "swp49", "bond1", "local", "NA", "NA", "false",
    ]


class TerminalL2StpDirectTests(unittest.TestCase):
    def test_all_standalone_l2_swp_and_bonds_are_automatic_edge_targets(self):
        document = direct_document()

        self.assertTrue(inject_terminal_l2_stp(document))
        interfaces = set_block(document)["interface"]
        for name in ("swp1", "bond1", "bond8"):
            self.assertEqual(
                EDGE_STP,
                interfaces[name]["bridge"]["domain"]["br_default"]["stp"],
            )
        for name in ("swp2", "swp3"):
            self.assertNotIn(
                "stp", interfaces[name]["bridge"]["domain"]["br_default"],
            )
        self.assertNotIn("bridge", interfaces["swp4"])
        self.assertNotIn("bridge", interfaces["peerlink"])
        self.assertEqual([], terminal_l2_stp_errors(document))

    def test_current_nvue_edge_values_are_strings_at_the_exact_interface_path(self):
        document = direct_document()

        inject_terminal_l2_stp(document)

        stp = (
            set_block(document)["interface"]["swp1"]
            ["bridge"]["domain"]["br_default"]["stp"]
        )
        self.assertEqual(
            {"admin-edge": "enabled", "bpdu-guard": "enabled"}, stp,
        )
        self.assertTrue(all(isinstance(value, str) for value in stp.values()))
        round_trip = yaml.safe_load(yaml.safe_dump(stp, sort_keys=True))
        self.assertEqual(stp, round_trip)
        self.assertTrue(all(isinstance(value, str) for value in round_trip.values()))

    def test_terminal_stp_enum_changes_at_cumulus_5_15_boundary(self):
        cases = (
            ("5.14.99", LEGACY_EDGE_STP),
            ("5.15", EDGE_STP),
            ("5.16.4", EDGE_STP),
            ("5.18.1", EDGE_STP),
            ("6.0", EDGE_STP),
        )
        for version, expected in cases:
            with self.subTest(version=version):
                self.assertEqual(
                    expected,
                    GENERATOR._terminal_l2_stp_policy(version),
                )

        for invalid in (None, "", "latest", "5", "v5.18.1", 5.18, True):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(ValueError, "Cumulus.*version"):
                    GENERATOR._terminal_l2_stp_policy(invalid)

    def test_legacy_nvue_uses_on_and_rejects_current_enum(self):
        document = direct_document()

        self.assertTrue(GENERATOR._inject_terminal_l2_stp(
            document, cumulus_version="5.14.99",
        ))
        self.assertEqual(
            LEGACY_EDGE_STP,
            set_block(document)["interface"]["swp1"]
            ["bridge"]["domain"]["br_default"]["stp"],
        )
        self.assertEqual([], GENERATOR._terminal_l2_stp_errors(
            document, cumulus_version="5.14.99",
        ))

        conflict = direct_document()
        conflict[0]["set"]["interface"]["swp1"]["bridge"]["domain"] \
            ["br_default"]["stp"] = {"admin-edge": "enabled"}
        with self.assertRaisesRegex(ValueError, "swp1.*admin-edge"):
            GENERATOR._inject_terminal_l2_stp(
                conflict, cumulus_version="5.14.99",
            )

    def test_every_stp_fragment_must_be_a_mapping_before_any_injection(self):
        for invalid in ("enabled", 1, [], True, None):
            document = [
                {"set": {"interface": {"swp1": {
                    "bridge": {"domain": {"br_default": {"access": 10}}},
                    "type": "swp",
                }}}},
                {"set": {"interface": {"swp1": {
                    "bridge": {"domain": {"br_default": {"stp": invalid}}},
                }}}},
            ]
            before = copy.deepcopy(document)
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(ValueError, "swp1.*stp.*mapping"):
                    inject_terminal_l2_stp(document)
                self.assertEqual(before, document)
                errors = terminal_l2_stp_errors(document)
                self.assertTrue(
                    any("swp1" in error and "stp" in error
                        and "mapping" in error for error in errors),
                    errors,
                )

    def test_schema_v1_does_not_enable_automatic_edge_policy(self):
        document = direct_document()

        self.assertFalse(inject_terminal_l2_stp(
            document, schema_version=1,
        ))
        self.assertEqual([], terminal_l2_stp_errors(
            document, schema_version=1,
        ))
        interfaces = set_block(document)["interface"]
        for name in ("swp1", "bond1", "bond8", "swp2", "swp3"):
            self.assertNotIn(
                "stp", interfaces[name]["bridge"]["domain"]["br_default"],
            )

    def test_bgp_interface_with_bridge_fragment_is_rejected_as_role_conflict(self):
        document = direct_document()

        with self.assertRaisesRegex(ValueError, "swp1.*BGP.*bridge"):
            inject_terminal_l2_stp(
                document, template="tan-cp-leaf", bgp_neighbors=["swp1"],
            )
        errors = terminal_l2_stp_errors(
            document, template="tan-cp-leaf", bgp_neighbors=["swp1"],
        )
        self.assertTrue(any("swp1" in error and "BGP" in error for error in errors))

    def test_gate_requires_edge_policy_on_every_automatic_target(self):
        document = direct_document()

        errors = terminal_l2_stp_errors(document)

        for name in ("swp1", "bond1", "bond8"):
            self.assertTrue(
                any(name in error and "admin-edge" in error for error in errors),
                errors,
            )

    def test_v2_layout_has_no_terminal_l2_policy_column(self):
        layout = CONTRACT.parse_device_csv_layout(v2_header(), 2)
        self.assertEqual(len(v2_header()), layout.metadata_start)

        for index in (12, len(v2_header())):
            with self.subTest(index=index):
                forbidden = v2_header()
                forbidden.insert(index, "terminal_l2_ports")
                with self.assertRaisesRegex(ValueError, "terminal_l2_ports"):
                    CONTRACT.parse_device_csv_layout(forbidden, 2)

    def test_setup_accepts_column_free_schema_and_rejects_terminal_policy_column(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "01-global.yaml").write_text(
                "schema_version: 2\n", encoding="utf-8",
            )
            devices = root / "02-devices_config.csv"
            with devices.open("w", newline="", encoding="utf-8") as stream:
                csv.writer(stream).writerows([v2_header(), v2_row()])
            errors, warnings = SETUP._validate_eth_csv(str(devices))
            self.assertEqual([], errors)
            self.assertFalse(
                any("terminal_l2_ports" in warning for warning in warnings),
                warnings,
            )

            forbidden_header = v2_header() + ["terminal_l2_ports"]
            invalid = v2_row() + ["swp5"]
            with devices.open("w", newline="", encoding="utf-8") as stream:
                csv.writer(stream).writerows([forbidden_header, invalid])
            errors, _warnings = SETUP._validate_eth_csv(str(devices))
            self.assertTrue(
                any("terminal_l2_ports" in error for error in errors),
                errors,
            )

    def test_bond_members_are_excluded_even_when_definitions_span_set_operations(self):
        document = [
            {"set": {"interface": {"bond7": {
                "bond": {"member": {"swp7": {}}},
                "type": "bond",
            }}}},
            {"set": {"interface": {
                "bond7": {"bridge": {"domain": {"br_default": {"access": 7}}}},
                "swp7": {
                    "bridge": {"domain": {"br_default": {"access": 7}}},
                    "type": "swp",
                },
            }}},
        ]

        self.assertTrue(inject_terminal_l2_stp(document))
        self.assertEqual(
            EDGE_STP,
            document[1]["set"]["interface"]["bond7"]
            ["bridge"]["domain"]["br_default"]["stp"],
        )
        self.assertNotIn(
            "stp",
            document[1]["set"]["interface"]["swp7"]
            ["bridge"]["domain"]["br_default"],
        )
        self.assertEqual(
            [], terminal_l2_stp_errors(document),
        )

    def test_existing_conflicting_terminal_stp_is_rejected_not_overwritten(self):
        for invalid in ("on", "disabled", True):
            document = direct_document()
            domain = (
                document[0]["set"]["interface"]["swp1"]
                ["bridge"]["domain"]["br_default"]
            )
            domain["stp"] = {"admin-edge": invalid}

            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(ValueError, "swp1.*admin-edge"):
                    inject_terminal_l2_stp(document)

        document = direct_document()
        self.assertTrue(inject_terminal_l2_stp(document))
        after_first_injection = copy.deepcopy(document)
        self.assertFalse(inject_terminal_l2_stp(document))
        self.assertEqual(after_first_injection, document)

    def test_compact_bridge_selector_mixing_terminal_and_bond_members_is_rejected(self):
        document = [{"set": {"interface": {
            "bond1": {
                "bond": {"member": {"swp2": {}}},
                "bridge": {"domain": {"br_default": {"access": 10}}},
                "type": "bond",
            },
            "swp1-3": {
                "bridge": {"domain": {"br_default": {"access": 10}}},
                "type": "swp",
            },
        }}}]

        with self.assertRaisesRegex(ValueError, "swp1-3.*bond member.*swp2"):
            inject_terminal_l2_stp(document)
        errors = terminal_l2_stp_errors(document)
        self.assertTrue(any("swp1-3" in error and "swp2" in error for error in errors))

    def test_gate_rejects_missing_edge_setting_and_member_level_setting(self):
        missing = direct_document()
        errors = terminal_l2_stp_errors(missing)
        self.assertTrue(any("swp1" in error and "admin-edge" in error for error in errors))
        self.assertTrue(any("bond1" in error and "bpdu-guard" in error for error in errors))

        invalid_member = direct_document()
        member_domain = {"access": 10, "stp": copy.deepcopy(EDGE_STP)}
        invalid_member[0]["set"]["interface"]["swp2"]["bridge"] = {
            "domain": {"br_default": member_domain},
        }
        inject_terminal_l2_stp(invalid_member)
        errors = terminal_l2_stp_errors(invalid_member)
        self.assertTrue(any("swp2" in error and "bond member" in error for error in errors))

    def test_oobofoob_leaf_keeps_spine_bond_in_normal_stp_mode(self):
        document = [{"set": {"interface": {
            "bond49b51": {
                "bond": {"member": {"swp49": {}, "swp51": {}}},
                "bridge": {"domain": {"br_default": {"vlan": {"10": {}}}}},
                "type": "bond",
            },
            "bond2": {
                "bond": {"member": {"swp2": {}}},
                "bridge": {"domain": {"br_default": {"access": 10}}},
                "type": "bond",
            },
            "swp3": {
                "bridge": {"domain": {"br_default": {"access": 10}}},
                "type": "swp",
            },
            "swp2": {"type": "swp"},
            "swp49": {"type": "swp"},
            "swp51": {"type": "swp"},
        }}}]

        self.assertTrue(inject_terminal_l2_stp(
            document, template="oobofoob-leaf",
        ))
        interfaces = set_block(document)["interface"]
        self.assertNotIn(
            "stp",
            interfaces["bond49b51"]["bridge"]["domain"]["br_default"],
        )
        for name in ("bond2", "swp3"):
            self.assertEqual(
                EDGE_STP,
                interfaces[name]["bridge"]["domain"]["br_default"]["stp"],
            )
        self.assertEqual([], terminal_l2_stp_errors(
            document, template="oobofoob-leaf",
        ))

    def test_oobofoob_spine_excludes_only_leaf_facing_bonds_1_through_11(self):
        interfaces = {}
        for bond_id in range(1, 13):
            member = f"swp{bond_id}"
            interfaces[f"bond{bond_id}"] = {
                "bond": {"member": {member: {}}},
                "bridge": {"domain": {"br_default": {"vlan": {"10": {}}}}},
                "type": "bond",
            }
            interfaces[member] = {"type": "swp"}
        document = [{"set": {"interface": interfaces}}]

        self.assertTrue(inject_terminal_l2_stp(
            document, template="oobofoob-spine",
        ))
        for bond_id in range(1, 12):
            self.assertNotIn(
                "stp",
                interfaces[f"bond{bond_id}"]["bridge"]["domain"]["br_default"],
            )
        self.assertEqual(
            EDGE_STP,
            interfaces["bond12"]["bridge"]["domain"]["br_default"]["stp"],
        )
        self.assertEqual([], terminal_l2_stp_errors(
            document, template="oobofoob-spine",
        ))

    def test_gate_rejects_edge_settings_on_oobofoob_stp_transit_bond(self):
        document = [{"set": {"interface": {
            "bond49b51": {
                "bond": {"member": {"swp49": {}, "swp51": {}}},
                "bridge": {"domain": {"br_default": {
                    "stp": copy.deepcopy(EDGE_STP),
                    "vlan": {"10": {}},
                }}},
                "type": "bond",
            },
            "swp49": {"type": "swp"},
            "swp51": {"type": "swp"},
        }}}]

        errors = terminal_l2_stp_errors(
            document, template="oobofoob-leaf",
        )
        self.assertTrue(
            any("bond49b51" in error and "不得配置" in error for error in errors),
            errors,
        )

    def test_gate_rejects_edge_settings_on_peerlink(self):
        document = [{"set": {"interface": {
            "peerlink": {
                "bond": {"member": {"swp49": {}, "swp51": {}}},
                "bridge": {"domain": {"br_default": {
                    "stp": copy.deepcopy(EDGE_STP),
                    "vlan": {"10": {}},
                }}},
                "type": "peerlink",
            },
            "peerlink.4094": {
                "base-interface": "peerlink",
                "bridge": {"domain": {"br_default": {
                    "stp": copy.deepcopy(EDGE_STP),
                }}},
                "type": "sub",
                "vlan": 4094,
            },
            "swp49": {"type": "swp"},
            "swp51": {"type": "swp"},
        }}}]

        errors = terminal_l2_stp_errors(document)
        for name in ("peerlink", "peerlink.4094"):
            self.assertTrue(
                any(name in error and "不得配置" in error for error in errors),
                errors,
            )


class TerminalL2StpWorkflowTests(unittest.TestCase):
    def test_column_free_v2_csv_automatically_protects_standalone_l2_ports(self):
        global_document = {
            "schema_version": 2,
            "common": {
                "mgmt": {"ztp": {"ztp_url_prefix": "/ztp"}},
                "switch": {"system": {
                    "config": {"auto-save": {"state": "enabled"}},
                    "date-time": {"timezone": "Etc/UTC"},
                    "dns": {"server": ["192.0.2.53"]},
                    "ntp": {"server": ["192.0.2.123"]},
                }},
            },
            "switches": [{"eth": {
                "version": "5.18.0",
                "bridge": {"domain": {"br_default": {
                    "stp": {"priority": 4096},
                }}},
                "vrr": {
                    "base_mac": "02:00:5e:01:00:00",
                    "gateway_ip": "subnet_maximum",
                },
                "mlag": {
                    "init-delay": 20,
                    "priority": [100, 200],
                    "shared-addresses": [],
                },
                "services": {"dhcp_relay": {}},
                "system": {
                    "aaa": {"user": {"cumulus": {
                        "full-name": "cumulus,,,", "hashed-password": "'*'",
                    }}},
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
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            global_file = root / "01-global.yaml"
            devices_file = root / "02-devices_config.csv"
            intermediate = root / "91-devices.yaml"
            output = root / "generated"
            global_file.write_text(
                yaml.safe_dump(global_document, sort_keys=False),
                encoding="utf-8",
            )
            with devices_file.open("w", newline="", encoding="utf-8") as stream:
                csv.writer(stream).writerows([
                    v2_header(), v2_row(),
                ])

            with mock.patch.multiple(
                GENERATOR,
                _CSV_FILE=str(devices_file),
                _GLOBAL_FILE=str(global_file),
                DEVICES_FILE=str(intermediate),
            ), mock.patch.object(
                GENERATOR, "_refresh_cumulus_defaults_from_global",
            ):
                GENERATOR._generate_devices_yaml()
                intermediate_document = yaml.safe_load(
                    intermediate.read_text(encoding="utf-8"),
                )
                self.assertNotIn(
                    "terminal_l2_ports",
                    intermediate_document["devices"]["leaf01"],
                )
                with mock.patch.object(GENERATOR, "OUTPUT_DIR", str(output)):
                    GENERATOR.generate_all()

            document = yaml.safe_load(
                (output / "leaf01.yaml").read_text(encoding="utf-8"),
            )
            interfaces = set_block(document)["interface"]
            self.assertEqual(
                EDGE_STP,
                interfaces["swp5"]["bridge"]["domain"]["br_default"]["stp"],
            )
            self.assertEqual(
                EDGE_STP,
                interfaces["bond1"]["bridge"]["domain"]["br_default"]["stp"],
            )

    def test_column_free_v2_oobofoob_workflow_preserves_stp_transit_bonds(self):
        eth_global = border_globals()
        eth_global.update({
            "version": "5.18.0",
            "vrr": {
                "base_mac": "02:00:5e:01:00:00",
                "gateway_ip": "subnet_maximum",
            },
            "mlag": {
                "init-delay": 20,
                "priority": [100, 200],
                "shared-addresses": [],
            },
            "services": {"dhcp_relay": {}},
        })
        global_document = {
            "schema_version": 2,
            "common": {"mgmt": {"ztp": {"ztp_url_prefix": "/ztp"}}},
            "switches": [{"eth": eth_global}],
        }

        def row(hostname, host_id, template, vlan_ports, bond_ports,
                bond_type, bond_mac="NA", peerlink="NA"):
            return [
                hostname, "eth", template, f"192.0.2.{host_id}", "24",
                "192.0.2.1", f"02:00:00:00:00:{host_id:02x}",
                "NA", "NA", "NA", "NA", f"198.51.100.{host_id}",
                "10", "NA", "NA", vlan_ports,
                "NA", "NA", bond_ports, bond_type, bond_mac,
                peerlink, "false",
            ]

        rows = [
            row(
                "oobofoob-pod1-leaf01", 10, "oobofoob-leaf",
                "bond49b51/bond2", "bond49b51|bond2", "local|local",
            ),
            row(
                "oobofoob-spine01", 20, "oobofoob-spine",
                "bond1-12", "bond1-12", "mlag",
                "02:00:00:ff:00:12", "swp49-50",
            ),
            row(
                "oobofoob-spine02", 21, "oobofoob-spine",
                "bond1-12", "bond1-12", "mlag",
                "02:00:00:ff:00:12", "swp49-50",
            ),
        ]

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            global_file = root / "01-global.yaml"
            devices_file = root / "02-devices_config.csv"
            intermediate = root / "91-devices.yaml"
            output = root / "generated"
            global_file.write_text(
                yaml.safe_dump(global_document, sort_keys=False),
                encoding="utf-8",
            )
            with devices_file.open("w", newline="", encoding="utf-8") as stream:
                csv.writer(stream).writerows([v2_header(), *rows])

            with mock.patch.multiple(
                GENERATOR,
                _CSV_FILE=str(devices_file),
                _GLOBAL_FILE=str(global_file),
                DEVICES_FILE=str(intermediate),
            ), mock.patch.object(
                GENERATOR, "_refresh_cumulus_defaults_from_global",
            ):
                GENERATOR._generate_devices_yaml()
                with mock.patch.object(GENERATOR, "OUTPUT_DIR", str(output)):
                    GENERATOR.generate_all()

            leaf = set_block(yaml.safe_load(
                (output / "oobofoob-pod1-leaf01.yaml").read_text(
                    encoding="utf-8",
                )
            ))["interface"]
            self.assertNotIn(
                "stp", leaf["bond49b51"]["bridge"]["domain"]["br_default"],
            )
            self.assertEqual(
                EDGE_STP,
                leaf["bond2"]["bridge"]["domain"]["br_default"]["stp"],
            )

            spine = set_block(yaml.safe_load(
                (output / "oobofoob-spine01.yaml").read_text(encoding="utf-8")
            ))["interface"]
            for bond_id in range(1, 12):
                self.assertNotIn(
                    "stp",
                    spine[f"bond{bond_id}"]["bridge"]["domain"]["br_default"],
                )
            self.assertEqual(
                EDGE_STP,
                spine["bond12"]["bridge"]["domain"]["br_default"]["stp"],
            )

    def test_generate_publish_and_runtime_compare_preserve_automatic_stp_policy(self):
        device = border_device()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "generated"
            with mock.patch.object(
                GENERATOR,
                "load_devices",
                return_value=(border_globals(), {device["hostname"]: device}),
            ), mock.patch.object(GENERATOR, "OUTPUT_DIR", str(output)):
                GENERATOR.generate_all()
            source = output / f"{device['hostname']}.yaml"
            published = PUBLISHER._canonical_yaml(str(source))

        published_document = yaml.safe_load(published)
        interfaces = set_block(published_document)["interface"]
        self.assertEqual(
            EDGE_STP,
            interfaces["swp5"]["bridge"]["domain"]["br_default"]["stp"],
        )
        self.assertEqual(
            EDGE_STP,
            interfaces["bond1"]["bridge"]["domain"]["br_default"]["stp"],
        )
        for member in ("swp1", "swp49", "swp50"):
            self.assertNotIn("bridge", interfaces[member])

        current = yaml.safe_dump([
            {"header": {"model": "vx", "nvue-api-version": "nvue_v1"}},
            published_document[0],
        ], sort_keys=False)
        self.assertEqual(
            MANUAL.runtime_comparable_nvue_config(published, label="latest"),
            MANUAL.runtime_comparable_nvue_config(current, label="nv config show"),
        )

    def test_pre_5_15_generate_publish_and_compare_preserve_legacy_stp_enum(self):
        device = border_device()
        global_vars = border_globals()
        global_vars["version"] = "5.14.99"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "generated"
            with mock.patch.object(
                GENERATOR,
                "load_devices",
                return_value=(global_vars, {device["hostname"]: device}),
            ), mock.patch.object(GENERATOR, "OUTPUT_DIR", str(output)):
                GENERATOR.generate_all()
            source = output / f"{device['hostname']}.yaml"
            published = PUBLISHER._canonical_yaml(str(source))

        published_document = yaml.safe_load(published)
        stp = (
            set_block(published_document)["interface"]["swp5"]
            ["bridge"]["domain"]["br_default"]["stp"]
        )
        self.assertEqual(LEGACY_EDGE_STP, stp)
        current = yaml.safe_dump([
            {"header": {"model": "vx", "nvue-api-version": "nvue_v1"}},
            published_document[0],
        ], sort_keys=False)
        self.assertEqual(
            MANUAL.runtime_comparable_nvue_config(published, label="latest"),
            MANUAL.runtime_comparable_nvue_config(current, label="nv config show"),
        )

    def test_schema_v1_generate_all_keeps_existing_l2_stp_output_unchanged(self):
        device = border_device()
        device["_project_schema_version"] = 1
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "generated"
            with mock.patch.object(
                GENERATOR,
                "load_devices",
                return_value=(border_globals(), {device["hostname"]: device}),
            ), mock.patch.object(GENERATOR, "OUTPUT_DIR", str(output)):
                GENERATOR.generate_all()

            document = yaml.safe_load(
                (output / f"{device['hostname']}.yaml").read_text(
                    encoding="utf-8",
                )
            )
        interfaces = set_block(document)["interface"]
        for name in ("swp5", "bond1"):
            self.assertNotIn(
                "stp", interfaces[name]["bridge"]["domain"]["br_default"],
            )

    def test_source_yaml_receipt_is_not_rewritten_by_automatic_policy(self):
        source = yaml.safe_dump(direct_document(), sort_keys=False)
        source_bytes = source.encode("utf-8")
        device = {
            "_project_schema_version": 2,
            "template": "source-receipt",
            "hostname": "EXAMPLE-SOURCE01",
            "source_yaml_b64": base64.b64encode(source_bytes).decode("ascii"),
            "source_yaml_sha256": hashlib.sha256(source_bytes).hexdigest(),
        }

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "generated"
            with mock.patch.object(
                GENERATOR,
                "load_devices",
                return_value=({}, {device["hostname"]: device}),
            ), mock.patch.object(
                GENERATOR, "OUTPUT_DIR", str(output),
            ), mock.patch.object(
                GENERATOR,
                "_inject_terminal_l2_stp",
                wraps=GENERATOR._inject_terminal_l2_stp,
            ) as inject:
                GENERATOR.generate_all()
            inject.assert_not_called()
            self.assertTrue(output.exists())
            self.assertEqual(
                yaml.safe_load(source),
                yaml.safe_load(
                    (output / "EXAMPLE-SOURCE01.yaml").read_text(
                        encoding="utf-8",
                    )
                ),
            )

    def test_feedback_keeps_v2_csv_free_of_terminal_policy_column(self):
        runtime = {
            "bridge": {"domain": {"br_default": {"vlan": {"100": {}}}}},
            "interface": {
                "eth0": {
                    "ipv4": {
                        "address": {"192.0.2.10/24": {}},
                        "gateway": {"192.0.2.1": {}},
                    },
                    "type": "eth",
                    "vrf": "mgmt",
                },
                "lo": {
                    "ipv4": {"address": {"198.51.100.10/32": {}}},
                    "type": "loopback",
                },
                "swp5": {
                    "bridge": {"domain": {"br_default": {
                        "access": 100,
                        "stp": copy.deepcopy(EDGE_STP),
                    }}},
                    "type": "swp",
                },
            },
            "system": {"hostname": "leaf01"},
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "runtime"
            source.mkdir()
            (source / "leaf01.yaml").write_text(
                yaml.safe_dump(runtime, sort_keys=False), encoding="utf-8",
            )
            inventory = root / "02-devices_config.csv"
            with inventory.open("w", newline="", encoding="utf-8") as stream:
                csv.writer(stream).writerows([v2_header(), v2_row()])
            global_file = root / "01-global.yaml"
            global_file.write_text(
                "schema_version: 2\nswitches:\n  - eth: {}\n",
                encoding="utf-8",
            )
            output = root / "feedback.csv"

            FEEDBACK.convert_one(
                source, output,
                devices_config_path=inventory,
                global_config_path=global_file,
                environment_scope="prod",
            )

            with output.open(newline="", encoding="utf-8") as stream:
                rows = list(csv.reader(stream))
            CONTRACT.parse_device_csv_layout(rows[0], 2)
            self.assertNotIn("terminal_l2_ports", rows[0])


if __name__ == "__main__":
    unittest.main()
