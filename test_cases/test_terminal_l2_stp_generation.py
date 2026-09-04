#!/usr/bin/env python3
"""Terminal-facing layer-2 STP generation and workflow contracts."""

from __future__ import annotations

import base64
import copy
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
        "swp2": {
            "bridge": {"domain": {"br_default": {"access": 10}}},
            "type": "swp",
        },
        "swp3": {
            "bridge": {"domain": {"br_default": {"access": 10}}},
            "type": "swp",
        },
        "swp4": {"ipv4": {"address": {"192.0.2.4/31": {}}}, "type": "swp"},
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


class TerminalL2StpDirectTests(unittest.TestCase):
    def test_injects_edge_and_bpdu_guard_only_on_standalone_l2_swp_and_bond(self):
        document = direct_document()

        self.assertTrue(GENERATOR._inject_terminal_l2_stp(document))
        interfaces = set_block(document)["interface"]
        self.assertEqual(
            EDGE_STP,
            interfaces["swp1"]["bridge"]["domain"]["br_default"]["stp"],
        )
        self.assertEqual(
            EDGE_STP,
            interfaces["bond1"]["bridge"]["domain"]["br_default"]["stp"],
        )
        for name in ("swp2", "swp3"):
            self.assertNotIn(
                "stp", interfaces[name]["bridge"]["domain"]["br_default"],
            )
        for name in ("swp4", "peerlink"):
            self.assertNotIn("bridge", interfaces[name])
        self.assertEqual([], GENERATOR._terminal_l2_stp_errors(document))

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

        self.assertTrue(GENERATOR._inject_terminal_l2_stp(document))
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
        self.assertEqual([], GENERATOR._terminal_l2_stp_errors(document))

    def test_existing_conflicting_terminal_stp_is_rejected_not_overwritten(self):
        document = direct_document()
        domain = document[0]["set"]["interface"]["swp1"]["bridge"]["domain"]["br_default"]
        domain["stp"] = {"admin-edge": "off"}

        with self.assertRaisesRegex(ValueError, "swp1.*admin-edge"):
            GENERATOR._inject_terminal_l2_stp(document)

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
            GENERATOR._inject_terminal_l2_stp(document)
        errors = GENERATOR._terminal_l2_stp_errors(document)
        self.assertTrue(any("swp1-3" in error and "swp2" in error for error in errors))

    def test_gate_rejects_missing_edge_setting_and_member_level_setting(self):
        missing = direct_document()
        errors = GENERATOR._terminal_l2_stp_errors(missing)
        self.assertTrue(any("swp1" in error and "admin-edge" in error for error in errors))
        self.assertTrue(any("bond1" in error and "bpdu-guard" in error for error in errors))

        invalid_member = direct_document()
        member_domain = {"access": 10, "stp": copy.deepcopy(EDGE_STP)}
        invalid_member[0]["set"]["interface"]["swp2"]["bridge"] = {
            "domain": {"br_default": member_domain},
        }
        GENERATOR._inject_terminal_l2_stp(invalid_member)
        errors = GENERATOR._terminal_l2_stp_errors(invalid_member)
        self.assertTrue(any("swp2" in error and "bond member" in error for error in errors))


class TerminalL2StpWorkflowTests(unittest.TestCase):
    def test_generate_publish_and_runtime_compare_preserve_terminal_stp_policy(self):
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
        for name in ("swp5", "bond1"):
            self.assertEqual(
                EDGE_STP,
                interfaces[name]["bridge"]["domain"]["br_default"]["stp"],
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

    def test_source_yaml_is_not_rewritten_and_missing_policy_fails_closed(self):
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
                with self.assertRaises(SystemExit):
                    GENERATOR.generate_all()
            inject.assert_not_called()
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
