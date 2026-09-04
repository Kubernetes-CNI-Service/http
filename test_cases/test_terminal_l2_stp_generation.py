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


EDGE_STP = {"admin-edge": "on", "bpdu-guard": "on"}


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


def v2_header(*, terminal_policy=True):
    header = (
        list(CONTRACT.DEVICE_BASE_COLUMNS)
        + list(CONTRACT.DEVICE_V2_VLAN_COLUMNS)
        + list(CONTRACT.DEVICE_FIXED_COLUMNS)
    )
    if terminal_policy:
        header.append("terminal_l2_ports")
    return header


def v2_row(*, terminal_ports="swp5/bond1"):
    return [
        "leaf01", "eth", "tan-leaf", "192.0.2.10", "24",
        "192.0.2.1", "02:00:00:00:00:10", "NA", "NA", "NA",
        "NA", "198.51.100.10", "100", "NA", "NA", "swp5/bond1",
        "65001", "swp49", "bond1", "local", "NA", "NA", "false",
    ] + ([terminal_ports] if terminal_ports is not None else [])


class TerminalL2StpDirectTests(unittest.TestCase):
    def test_missing_policy_does_not_automatically_mark_l2_interfaces_terminal(self):
        document = direct_document()

        self.assertFalse(GENERATOR._inject_terminal_l2_stp(document))
        interfaces = set_block(document)["interface"]
        for name in ("swp1", "bond1", "bond8", "swp2", "swp3"):
            self.assertNotIn(
                "stp", interfaces[name]["bridge"]["domain"]["br_default"],
            )
        for name in ("swp4", "peerlink"):
            self.assertNotIn("bridge", interfaces[name])
        self.assertEqual([], GENERATOR._terminal_l2_stp_errors(document))

    def test_explicit_policy_only_injects_listed_terminal_interfaces(self):
        document = direct_document()

        self.assertTrue(
            GENERATOR._inject_terminal_l2_stp(document, ["swp1", "bond1"]),
        )
        interfaces = set_block(document)["interface"]
        for name in ("swp1", "bond1"):
            self.assertEqual(
                EDGE_STP,
                interfaces[name]["bridge"]["domain"]["br_default"]["stp"],
            )
        self.assertNotIn(
            "stp", interfaces["bond8"]["bridge"]["domain"]["br_default"],
        )
        self.assertEqual(
            [],
            GENERATOR._terminal_l2_stp_errors(
                document, ["swp1", "bond1"],
            ),
        )

    def test_explicit_empty_policy_leaves_all_l2_interfaces_unmodified(self):
        document = direct_document()

        self.assertFalse(GENERATOR._inject_terminal_l2_stp(document, []))
        self.assertEqual([], GENERATOR._terminal_l2_stp_errors(document, []))
        interfaces = set_block(document)["interface"]
        for name in ("swp1", "bond1", "bond8"):
            self.assertNotIn(
                "stp", interfaces[name]["bridge"]["domain"]["br_default"],
            )

    def test_explicit_policy_rejects_missing_nonbridge_member_and_peerlink(self):
        variants = {
            "missing": ("bond999", "不存在"),
            "routed": ("swp4", "二层 bridge"),
            "bond member": ("swp2", "bond member"),
            "peerlink": ("peerlink", "peerlink"),
        }
        for label, (target, expected) in variants.items():
            with self.subTest(label=label), self.assertRaisesRegex(
                ValueError, expected,
            ):
                GENERATOR._inject_terminal_l2_stp(
                    direct_document(), [target],
                )

    def test_explicit_gate_rejects_terminal_stp_on_unlisted_l2_interface(self):
        document = direct_document()
        domain = (
            document[0]["set"]["interface"]["bond8"]
            ["bridge"]["domain"]["br_default"]
        )
        domain["stp"] = copy.deepcopy(EDGE_STP)

        errors = GENERATOR._terminal_l2_stp_errors(
            document, ["swp1", "bond1"],
        )

        self.assertTrue(
            any("bond8" in error and "未在 terminal_l2_ports" in error
                for error in errors),
            errors,
        )

    def test_shared_v2_layout_and_terminal_selector_contract(self):
        explicit = CONTRACT.parse_device_csv_layout(v2_header(), 2)
        self.assertEqual(
            {"terminal_l2_ports": 23}, explicit.policy_indices,
        )
        legacy = CONTRACT.parse_device_csv_layout(
            v2_header(terminal_policy=False), 2,
        )
        self.assertEqual({}, legacy.policy_indices)
        self.assertEqual(
            ("swp1", "swp2", "swp3s0", "swp3s1", "bond49b51"),
            CONTRACT.parse_terminal_l2_ports(
                "swp1-2/swp3s0-1/bond49b51",
            ),
        )
        for value in (
            "peerlink", "peerlink.4094", "swp2-1", "swp1//bond1",
            "swp1/swp1", "eth1", "bond1|bond2",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                CONTRACT.parse_terminal_l2_ports(value)

        misplaced = v2_header(terminal_policy=False)
        misplaced.insert(12, "terminal_l2_ports")
        with self.assertRaisesRegex(ValueError, "terminal_l2_ports"):
            CONTRACT.parse_device_csv_layout(misplaced, 2)

    def test_setup_validates_explicit_column_and_warns_when_column_missing(self):
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

            invalid = v2_row(terminal_ports="peerlink")
            with devices.open("w", newline="", encoding="utf-8") as stream:
                csv.writer(stream).writerows([v2_header(), invalid])
            errors, _warnings = SETUP._validate_eth_csv(str(devices))
            self.assertTrue(
                any("terminal_l2_ports" in error and "peerlink" in error
                    for error in errors),
                errors,
            )

            with devices.open("w", newline="", encoding="utf-8") as stream:
                csv.writer(stream).writerows([
                    v2_header(terminal_policy=False),
                    v2_row(terminal_ports=None),
                ])
            errors, warnings = SETUP._validate_eth_csv(str(devices))
            self.assertEqual([], errors)
            self.assertTrue(
                any("terminal_l2_ports" in warning and "不会自动" in warning
                    for warning in warnings),
                warnings,
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

        self.assertTrue(GENERATOR._inject_terminal_l2_stp(document, ["bond7"]))
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
            [], GENERATOR._terminal_l2_stp_errors(document, ["bond7"]),
        )

    def test_existing_conflicting_terminal_stp_is_rejected_not_overwritten(self):
        document = direct_document()
        domain = document[0]["set"]["interface"]["swp1"]["bridge"]["domain"]["br_default"]
        domain["stp"] = {"admin-edge": "off"}

        with self.assertRaisesRegex(ValueError, "swp1.*admin-edge"):
            GENERATOR._inject_terminal_l2_stp(document, ["swp1"])

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
            GENERATOR._inject_terminal_l2_stp(
                document, ["swp1", "swp2", "swp3"],
            )
        errors = GENERATOR._terminal_l2_stp_errors(
            document, ["swp1", "swp2", "swp3"],
        )
        self.assertTrue(any("swp1-3" in error and "swp2" in error for error in errors))

    def test_gate_rejects_missing_edge_setting_and_member_level_setting(self):
        missing = direct_document()
        errors = GENERATOR._terminal_l2_stp_errors(
            missing, ["swp1", "bond1", "bond8"],
        )
        self.assertTrue(any("swp1" in error and "admin-edge" in error for error in errors))
        self.assertTrue(any("bond1" in error and "bpdu-guard" in error for error in errors))

        invalid_member = direct_document()
        member_domain = {"access": 10, "stp": copy.deepcopy(EDGE_STP)}
        invalid_member[0]["set"]["interface"]["swp2"]["bridge"] = {
            "domain": {"br_default": member_domain},
        }
        GENERATOR._inject_terminal_l2_stp(
            invalid_member, ["swp1", "bond1", "bond8"],
        )
        errors = GENERATOR._terminal_l2_stp_errors(
            invalid_member, ["swp1", "bond1", "bond8"],
        )
        self.assertTrue(any("swp2" in error and "bond member" in error for error in errors))


class TerminalL2StpWorkflowTests(unittest.TestCase):
    def test_v2_csv_policy_flows_through_intermediate_yaml_and_renderer(self):
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
                    v2_header(), v2_row(terminal_ports="swp5"),
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
                self.assertEqual(
                    ["swp5"],
                    intermediate_document["devices"]["leaf01"]
                    ["terminal_l2_ports"],
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
            self.assertNotIn(
                "stp", interfaces["bond1"]["bridge"]["domain"]["br_default"],
            )

    def test_generate_publish_and_runtime_compare_preserve_terminal_stp_policy(self):
        device = border_device()
        device["terminal_l2_ports"] = ["swp5"]
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
        self.assertNotIn(
            "stp", interfaces["bond1"]["bridge"]["domain"]["br_default"],
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

    def test_source_yaml_is_not_rewritten_when_missing_policy_means_no_targets(self):
        source = yaml.safe_dump(direct_document(), sort_keys=False)
        source_bytes = source.encode("utf-8")
        device = {
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

    def test_feedback_preserves_explicit_terminal_policy_without_inference(self):
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
            layout = CONTRACT.parse_device_csv_layout(rows[0], 2)
            self.assertEqual(
                "swp5/bond1",
                rows[1][layout.policy_indices["terminal_l2_ports"]],
            )


if __name__ == "__main__":
    unittest.main()
