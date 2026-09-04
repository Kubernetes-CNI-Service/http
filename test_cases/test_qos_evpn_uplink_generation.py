#!/usr/bin/env python3
"""QoS and EVPN-MH BGP-uplink generation/workflow contracts."""

from __future__ import annotations

import copy
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
    "qos_evpn_generator_under_test",
    ROOT / "ztp/config/cumulus/template/90-c2-generate_configs.py",
)
PUBLISHER = load_script(
    "qos_evpn_publisher_under_test",
    ROOT / "ztp/config/cumulus/d-hostname2mac.py",
)
MANUAL = load_script(
    "qos_evpn_manual_under_test", ROOT / "ztp/manual-ztp.py",
)


def config(document):
    blocks = GENERATOR._nvue_set_operations(document)
    if len(blocks) != 1:
        raise AssertionError(f"expected one set operation, got {len(blocks)}")
    return blocks[0]


def base_document(*, multihoming=True):
    evpn = {"state": "enabled"}
    if multihoming:
        evpn["multihoming"] = {"state": "enabled"}
    return [{"set": {
        "evpn": evpn,
        "interface": {
            "swp1": {"link": {"mtu": 9216}, "type": "swp"},
            "swp2": {"link": {"mtu": 9216}, "type": "swp"},
            "swp3": {
                "link": {"breakout": {"4x": {"lanes-per-port": "2"}}},
                "type": "swp",
            },
            "swp3s0": {"type": "swp"},
            "swp3s1-3": {"type": "swp"},
            "bond7": {
                "bond": {"member": {"swp1": {}}},
                "bridge": {"domain": {"br_default": {"access": 10}}},
                "type": "bond",
            },
            "peerlink.4094": {"type": "sub", "vlan": 4094},
        },
        "vrf": {"default": {"router": {"bgp": {"neighbor": {
            "swp2": {"type": "unnumbered"},
            "swp3s0": {"type": "unnumbered"},
            "peerlink.4094": {"type": "unnumbered"},
            "192.0.2.1": {"remote-as": "external"},
        }}}}},
    }}]


def oob_core_evpn_device():
    """Return an OOB core sharing one breakout parent across BGP and bonds."""
    evpn_bond = {
        "type": "evpn_multihoming",
        "bond_list": ["bond15s4", "bond15s5"],
        "lacp-bypass": "enabled",
        "mac-address": "02:00:00:00:40:01",
    }
    return {
        "_project_schema_version": 2,
        "template": "oob-core",
        "hostname": "EXAMPLE-OOB-CORE01",
        "eth0_ip": "192.0.2.10/24",
        "eth0_gw": "192.0.2.1",
        "has_eth1": False,
        "lo_ip": "198.51.100.10/32",
        "bgp_asn": 65101,
        # One physical parent legitimately mixes routed lanes s0-s3 and
        # server-facing EVPN-MH lanes s4-s5.  The parent must be rendered once
        # in 8x mode; empty lanes s6-s7 stay plain interfaces.
        "bgp_neighbors": [
            "swp15s0", "swp15s1", "swp15s2", "swp15s3",
            "peerlink.4094",
        ],
        "peerlink_ports": "",
        "vlan_ports": [],
        "bond_groups": [copy.deepcopy(evpn_bond)],
        "vrfs": [{
            "evpn_vrf": "OOB",
            "evpn_l3vlan": 4001,
            "evpn_l3vni": 4001,
            "l2vlans": [{
                "vlan_id": 10,
                "vlan_spec": "10",
                "vlan_ids": [10],
                "vni": 400010,
                "emit_svi": False,
                "svi_ip": "",
                "vrr_ip": "",
                "vrr_mac": "",
                "vlan_ports": [{"bonds": copy.deepcopy(evpn_bond)}],
            }],
        }],
    }


def evpn_uplink_interfaces(block):
    """Return expanded interface names carrying the MH uplink leaf."""
    result = set()
    for selector, interface in block.get("interface", {}).items():
        uplink = (
            interface.get("evpn", {})
            .get("multihoming", {})
            .get("uplink")
        )
        if uplink == "enabled":
            result.update(GENERATOR.expand_nvue_selector(selector))
    return result


class QosDirectTests(unittest.TestCase):
    def test_border_qos_targets_parent_physical_ports_only(self):
        document = base_document()
        self.assertTrue(GENERATOR._inject_qos_policy(document, "border"))
        block = config(document)
        self.assertEqual(
            {"mode": "lossless", "state": "enabled"},
            block["qos"]["roce"],
        )
        self.assertEqual(
            {"state": "enable"},
            block["interface"]["swp1"]["qos"]["pfc-watchdog"],
        )
        for name in ("swp3", "swp3s0", "swp3s1-3", "bond7", "peerlink.4094"):
            self.assertNotIn("qos", block["interface"][name])
        self.assertEqual([], GENERATOR._qos_policy_errors(document, "border"))

    def test_tan_qos_targets_breakout_children_and_excludes_1g_leaf(self):
        document = base_document()
        self.assertTrue(GENERATOR._inject_qos_policy(document, "tan-hps-leaf"))
        block = config(document)
        self.assertEqual(
            {"state": "enable"},
            block["interface"]["swp3s0"]["qos"]["pfc-watchdog"],
        )
        for name in ("swp1", "swp2", "swp3", "bond7"):
            self.assertNotIn("qos", block["interface"][name])

        excluded = base_document()
        self.assertFalse(GENERATOR._inject_qos_policy(excluded, "tan-cp-1gleaf"))
        self.assertNotIn("qos", config(excluded))
        self.assertEqual([], GENERATOR._qos_policy_errors(excluded, "tan-cp-1gleaf"))

    def test_qos_conflicts_and_wrong_placement_fail_closed(self):
        conflict = base_document()
        config(conflict)["qos"] = {"roce": {"mode": "lossy"}}
        with self.assertRaisesRegex(ValueError, "qos.*roce.*mode"):
            GENERATOR._inject_qos_policy(conflict, "border")

        wrong = base_document()
        config(wrong)["interface"]["bond7"]["qos"] = {
            "pfc-watchdog": {"state": "enable"},
        }
        errors = GENERATOR._qos_policy_errors(wrong, "border")
        self.assertTrue(any("bond7" in error and "不得" in error for error in errors))


class EvpnMhUplinkDirectTests(unittest.TestCase):
    def test_mh_marks_every_interface_bgp_neighbor_except_peerlink(self):
        document = base_document(multihoming=True)
        self.assertTrue(GENERATOR._inject_evpn_mh_uplinks(
            document, ["swp2", "swp3s0", "peerlink.4094"], True,
        ))
        interfaces = config(document)["interface"]
        for name in ("swp2", "swp3s0"):
            self.assertEqual(
                "enabled",
                interfaces[name]["evpn"]["multihoming"]["uplink"],
            )
        self.assertNotIn("evpn", interfaces["peerlink.4094"])
        self.assertEqual([], GENERATOR._evpn_mh_uplink_errors(
            document, ["swp2", "swp3s0", "peerlink.4094"], True,
        ))

    def test_non_mh_never_accepts_stale_uplink(self):
        document = base_document(multihoming=False)
        config(document)["interface"]["swp2"]["evpn"] = {
            "multihoming": {"uplink": "enabled"},
        }
        errors = GENERATOR._evpn_mh_uplink_errors(
            document, ["swp2"], False,
        )
        self.assertTrue(any("swp2" in error and "非 EVPN-MH" in error for error in errors))

    def test_mixed_compact_selector_is_rejected(self):
        document = base_document(multihoming=True)
        interfaces = config(document)["interface"]
        interfaces.pop("swp1")
        interfaces.pop("swp2")
        interfaces["swp1-2"] = {"type": "swp"}
        with self.assertRaisesRegex(ValueError, "selector.*swp1-2"):
            GENERATOR._inject_evpn_mh_uplinks(document, ["swp2"], True)

    def test_oob_core_v2_marks_only_breakout_bgp_interfaces(self):
        from test_cases.test_mlag_evpn_generation import border_globals

        device = oob_core_evpn_device()
        prepared = GENERATOR.preprocess_device(device)
        rendered = GENERATOR.render(
            GENERATOR.build_env(), border_globals(), device["hostname"], prepared,
        )
        document = GENERATOR._load_generated_yaml(rendered)
        self.assertTrue(GENERATOR._inject_evpn_mh_uplinks(
            document, device["bgp_neighbors"], True,
        ))
        block = config(document)

        self.assertEqual(
            {"swp15s0", "swp15s1", "swp15s2", "swp15s3"},
            evpn_uplink_interfaces(block),
        )
        self.assertEqual(
            {"8x": {"lanes-per-port": "1"}},
            block["interface"]["swp15"]["link"]["breakout"],
        )
        for bond in ("bond15s4", "bond15s5"):
            bond_mh = block["interface"][bond]["evpn"]["multihoming"]
            self.assertIn("segment", bond_mh)
            self.assertNotIn("uplink", bond_mh)
        for name in ("swp15", "swp15s4", "swp15s5", "swp15s6", "swp15s7"):
            self.assertNotIn("evpn", block["interface"][name])
        self.assertNotIn("peerlink.4094", block["interface"])
        self.assertEqual([], GENERATOR._evpn_mh_uplink_errors(
            document, device["bgp_neighbors"], True,
        ))


class QosEvpnWorkflowTests(unittest.TestCase):
    def test_real_border_generate_publish_compare_combines_all_policies(self):
        from test_cases.test_mlag_evpn_generation import (
            border_globals, border_mlag_device,
        )

        device = border_mlag_device()
        device["bond_groups"][0].update({
            "type": "evpn_multihoming",
            "mac-address": "02:00:00:00:30:01",
        })
        device["vrfs"][0]["l2vlans"][0]["vlan_ports"][0]["bonds"].update({
            "type": "evpn_multihoming",
            "mac-address": "02:00:00:00:30:01",
        })
        for key in (
            "mlag_backup", "mlag_priority", "mlag_mac_address",
            "mlag_shared_address", "system_mac",
        ):
            device.pop(key, None)
        device["peerlink_ports"] = ""
        device["bgp_neighbors"] = ["swp49"]

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "generated"
            with mock.patch.object(
                GENERATOR, "load_devices",
                return_value=(border_globals(), {device["hostname"]: device}),
            ), mock.patch.object(GENERATOR, "OUTPUT_DIR", str(output)):
                GENERATOR.generate_all()
            published = PUBLISHER._canonical_yaml(
                str(output / f"{device['hostname']}.yaml")
            )

        block = config(yaml.safe_load(published))
        self.assertEqual(
            {"mode": "lossless", "state": "enabled"},
            block["qos"]["roce"],
        )
        self.assertEqual(
            "enabled",
            block["interface"]["swp49"]["evpn"]["multihoming"]["uplink"],
        )
        self.assertNotIn("qos", block["interface"]["bond1"])
        current = yaml.safe_dump(
            [{"header": {"model": "vx"}}, *yaml.safe_load(published)],
            sort_keys=False,
        )
        self.assertEqual(
            MANUAL.runtime_comparable_nvue_config(published, label="latest"),
            MANUAL.runtime_comparable_nvue_config(current, label="runtime"),
        )

    def test_oob_core_v2_generate_publish_marks_only_bgp_breakout_interfaces(self):
        from test_cases.test_mlag_evpn_generation import border_globals

        device = oob_core_evpn_device()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "generated"
            with mock.patch.object(
                GENERATOR, "load_devices",
                return_value=(border_globals(), {device["hostname"]: device}),
            ), mock.patch.object(GENERATOR, "OUTPUT_DIR", str(output)):
                GENERATOR.generate_all()
            published = PUBLISHER._canonical_yaml(
                str(output / f"{device['hostname']}.yaml")
            )

        block = config(yaml.safe_load(published))
        self.assertEqual(
            {"swp15s0", "swp15s1", "swp15s2", "swp15s3"},
            evpn_uplink_interfaces(block),
        )
        self.assertEqual(
            {"8x": {"lanes-per-port": "1"}},
            block["interface"]["swp15"]["link"]["breakout"],
        )
        for bond in ("bond15s4", "bond15s5"):
            bond_mh = block["interface"][bond]["evpn"]["multihoming"]
            self.assertIn("segment", bond_mh)
            self.assertNotIn("uplink", bond_mh)
        for name in ("swp15", "swp15s4", "swp15s5", "swp15s6", "swp15s7"):
            self.assertNotIn("evpn", block["interface"][name])
        self.assertNotIn("peerlink.4094", block["interface"])
        self.assertEqual([], GENERATOR._evpn_mh_uplink_errors(
            yaml.safe_load(published), device["bgp_neighbors"], True,
        ))


if __name__ == "__main__":
    unittest.main()
