#!/usr/bin/env python3
"""REQ-14 direct contracts: splitter intent, not connected-lane count, owns mode.

The internal ``splitter_profiles`` device field carries already inferred
profiles. Transport from the P2P producer has separate workflow coverage; these tests
deliberately isolate consumption of that authority from its file representation.
"""

from __future__ import annotations

import copy
import unittest

from test_cases.test_qos_evpn_uplink_generation import (
    GENERATOR, oob_core_evpn_device,
)


def device_for_ports(hostname, ports, profile, *, role="bgp"):
    """Minimal independent device input using an existing public template fixture."""
    device = oob_core_evpn_device()
    device["hostname"] = hostname
    device["bgp_neighbors"] = []
    device["bond_groups"] = []
    device["splitter_profiles"] = dict(profile)
    vlan = device["vrfs"][0]["l2vlans"][0]
    vlan["vlan_ports"] = []
    if role == "bgp":
        device["bgp_neighbors"] = list(ports)
    elif role == "direct":
        vlan["vlan_ports"] = list(ports)
    elif role == "bond":
        bond = {
            "type": "evpn_multihoming",
            "bond_list": [port.replace("swp", "bond", 1) for port in ports],
            "lacp-bypass": "enabled",
            "mac-address": "02:00:00:00:40:01",
        }
        device["bond_groups"] = [copy.deepcopy(bond)]
        vlan["vlan_ports"] = [{"bonds": bond}]
    else:
        raise AssertionError(role)
    return device


class SplitterProfileDirectTests(unittest.TestCase):
    def assert_parent(self, device, name, count, lanes):
        before = copy.deepcopy(device)
        prepared = GENERATOR.preprocess_device(device)
        parents = {**prepared["parent_swps"], **prepared["bgp_uplink_parents"]}
        self.assertEqual(count, parents[name]["breakout"])
        self.assertEqual(lanes, parents[name]["lanes"])
        self.assertEqual(list(range(count)), parents[name]["subs"])
        self.assertEqual(before, device, "preprocessing must not mutate input authority")
        return prepared

    def test_profile_mapping_does_not_depend_on_highest_connected_lane(self):
        for profile, count, lanes in (("1to2", 2, 4), ("1to4", 4, 2), ("1to8", 8, 1)):
            for role in ("bgp", "direct", "bond"):
                with self.subTest(profile=profile, role=role):
                    self.assert_parent(device_for_ports(
                        "EXAMPLE-OOB-CORE01", ["swp9s0"], {"swp9": profile},
                        role=role,
                    ), "swp9", count, lanes)

    def test_real_oob_partial_bgp_lanes_do_not_shrink_eight_way_profile(self):
        self.assert_parent(device_for_ports(
            "EXAMPLE-OOB-CORE01",
            ["swp9s0", "swp9s1", "swp9s2", "swp9s3"],
            {"swp9": "1to8"},
        ), "swp9", 8, 1)

    def test_real_storage_single_bond_lane_does_not_shrink_eight_way_profile(self):
        self.assert_parent(device_for_ports(
            "EXAMPLE-TAN-OBJ-LEAF01", ["swp19s0"],
            {"swp19": "1to8"}, role="bond",
        ), "swp19", 8, 1)

    def test_mixed_role_merge_preserves_profile_and_exact_bgp_neighbors(self):
        device = device_for_ports(
            "EXAMPLE-OOB-CORE01", ["swp9s0"], {"swp9": "1to8"}, role="bond",
        )
        device["bgp_neighbors"] = ["swp9s1"]
        prepared = self.assert_parent(device, "swp9", 8, 1)
        self.assertEqual({}, prepared["bgp_uplink_parents"])
        self.assertEqual(["swp9s1"], prepared["bgp_neighbors"])

    def test_missing_invalid_or_narrower_authority_fails_closed(self):
        for profiles, ports in (
            ({}, ["swp9s0"]),
            ({"swp9": "1to16"}, ["swp9s0"]),
            ({"swp9": "1to2"}, ["swp9s2"]),
            ({"swp9": "1to8"}, ["swp9s8"]),
        ):
            for role in ("direct", "bond", "bgp"):
                with self.subTest(profiles=profiles, ports=ports, role=role):
                    with self.assertRaisesRegex(ValueError, "splitter|profile|拆分"):
                        GENERATOR.preprocess_device(device_for_ports(
                            "EXAMPLE-OOB-CORE01", ports, profiles, role=role,
                        ))

    def test_unused_profile_does_not_materialize_a_parent(self):
        prepared = GENERATOR.preprocess_device(device_for_ports(
            "EXAMPLE-OOB-CORE01", ["swp9s0"],
            {"swp9": "1to8", "swp10": "1to8"},
        ))
        self.assertEqual({"swp9"}, set(prepared["bgp_uplink_parents"]))
        self.assertEqual({}, prepared["parent_swps"])

    def test_unused_profile_does_not_materialize_on_bond_path(self):
        device = device_for_ports(
            "EXAMPLE-TAN-OBJ-LEAF01", ["swp19s0"],
            {"swp19": "1to8", "swp20": "1to8"}, role="bond",
        )
        prepared = self.assert_parent(device, "swp19", 8, 1)
        self.assertEqual({"swp19"}, set(prepared["parent_swps"]))
        self.assertEqual({}, prepared["bgp_uplink_parents"])
        self.assertEqual(["bond19s0"], [bond["name"] for bond in prepared["computed_bonds"]])

    def test_conflicting_parent_metadata_is_rejected_by_merge_helper(self):
        # Defensive helper contract; current normal preprocessing uses one
        # authority and cannot naturally construct these disagreeing maps.
        for key, conflicting in (("breakout", 4), ("lanes", 2), ("subs", [0, 1])):
            with self.subTest(key=key):
                parent = {"breakout": 8, "lanes": 1, "subs": list(range(8))}
                bgp = dict(parent, **{key: conflicting})
                with self.assertRaisesRegex(ValueError, "conflicting splitter profile metadata for swp9"):
                    GENERATOR._merge_overlapping_breakout_parents({"swp9": parent}, {"swp9": bgp})


if __name__ == "__main__":
    unittest.main()
