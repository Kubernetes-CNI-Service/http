#!/usr/bin/env python3
"""MLAG versus EVPN multihoming generation and publication contracts."""

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
TEMPLATES = ROOT / "ztp/config/cumulus/template/03-templates-j2"
GLOBAL_EVPN_TEMPLATE = "_global_evpn.yaml.j2"
MLAG_PEERLINK_TEMPLATE = "_mlag_peerlink.yaml.j2"
GLOBAL_EVPN_PARENTS = {
    "border.yaml.j2",
    "oob-core.yaml.j2",
    "oob-leaf.yaml.j2",
    "oob-su-leaf.yaml.j2",
    "tan-cp-1gleaf.yaml.j2",
    "tan-cp-leaf.yaml.j2",
    "tan-hps-leaf.yaml.j2",
    "tan-leaf.yaml.j2",
    "tan-spine.yaml.j2",
    "tan-su-leaf.yaml.j2",
}


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
    "mlag_evpn_generator_under_test",
    ROOT / "ztp/config/cumulus/template/90-c2-generate_configs.py",
)
PUBLISHER = load_script(
    "mlag_evpn_publisher_under_test",
    ROOT / "ztp/config/cumulus/d-hostname2mac.py",
)
MANUAL = load_script(
    "mlag_evpn_manual_compare_under_test",
    ROOT / "ztp/manual-ztp.py",
)


def bond_device(*bond_types: str) -> dict:
    groups = []
    names = []
    for index, bond_type in enumerate(bond_types, start=1):
        name = f"bond{index}"
        names.append(name)
        groups.append({
            "type": bond_type,
            "bond_list": [name],
            "lacp-bypass": "enabled",
            "mac-address": (
                f"02:00:00:00:00:{index:02x}"
                if bond_type == "evpn_multihoming" else ""
            ),
        })
    return {
        "vlan_id": 13,
        "vlan_ports": names,
        "bond_groups": groups,
        "vrfs": [],
    }


def global_evpn_document(is_mlag: bool) -> tuple[str, list[dict]]:
    fragment = GENERATOR.build_env().get_template(
        GLOBAL_EVPN_TEMPLATE,
    ).render(d={"is_mlag": is_mlag})
    text = "- set:\n" + fragment
    return text, yaml.safe_load(text)


def border_globals() -> dict:
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


def border_mlag_device() -> dict:
    device = bond_device("mlag")
    mlag_bond = copy.deepcopy(device["bond_groups"][0])
    device.update({
        "template": "border",
        "hostname": "EXAMPLE-MLAG01",
        "eth0_ip": "192.0.2.10/24",
        "eth0_gw": "192.0.2.1",
        "has_eth1": False,
        "lo_ip": "198.51.100.10/32",
        "bgp_asn": 65101,
        "bgp_neighbors": ["swp49"],
        "peerlink_ports": "swp50-51",
        "vlan_ports": [],
        "vrfs": [
            {
                "evpn_vrf": "BLUE",
                "evpn_l3vlan": None,
                "evpn_l3vni": None,
                "l2vlans": [{
                    "vlan_id": None,
                    "vlan_spec": "10-12,20",
                    "vlan_ids": [10, 11, 12, 20],
                    "vni": None,
                    "emit_svi": False,
                    "svi_ip": "",
                    "vrr_ip": "",
                    "vrr_mac": "",
                    "vlan_ports": [{"bonds": mlag_bond}],
                }],
            },
            {
                "evpn_vrf": "RED",
                "evpn_l3vlan": None,
                "evpn_l3vni": None,
                "l2vlans": [{
                    "vlan_id": 30,
                    "vlan_spec": "30",
                    "vlan_ids": [30],
                    "vni": 1030,
                    "emit_svi": False,
                    "svi_ip": "",
                    "vrr_ip": "",
                    "vrr_mac": "",
                    "vlan_ports": [],
                }],
            },
        ],
        "mlag_backup": "192.0.2.11",
        "mlag_priority": 1000,
        "mlag_mac_address": "02:00:00:00:10:01",
        "system_mac": "02:00:00:00:20:01",
        "mlag_shared_address": "198.51.100.1",
    })
    return device


def set_block(document: list[dict]) -> dict:
    blocks = [item["set"] for item in document if isinstance(item, dict) and "set" in item]
    if len(blocks) != 1:
        raise AssertionError(f"expected one set block, found {len(blocks)}")
    return blocks[0]


class MlagEvpnDirectTests(unittest.TestCase):
    def test_preprocess_builds_one_consolidated_peerlink_vlan_selector(self):
        processed = GENERATOR.preprocess_device(border_mlag_device())
        self.assertEqual(
            ["10-12,20,30"],
            processed["bridge_vlan_selectors"],
        )

    def test_preprocess_marks_mlag_and_rejects_same_device_mlag_evpn_mh_mix(self):
        mlag = GENERATOR.preprocess_device(bond_device("mlag"))
        self.assertIs(mlag["is_mlag"], True)

        evpn_mh = GENERATOR.preprocess_device(bond_device("evpn_multihoming"))
        self.assertIs(evpn_mh["is_mlag"], False)

        with self.assertRaisesRegex(ValueError, "MLAG.*EVPN multihoming"):
            GENERATOR.preprocess_device(
                bond_device("mlag", "evpn_multihoming"),
            )

    def test_local_bonds_can_coexist_with_either_redundancy_mode(self):
        local_mlag = GENERATOR.preprocess_device(
            bond_device("localbond", "mlag"),
        )
        self.assertIs(local_mlag["is_mlag"], True)
        local_evpn_mh = GENERATOR.preprocess_device(
            bond_device("localbond", "evpn_multihoming"),
        )
        self.assertIs(local_evpn_mh["is_mlag"], False)

    def test_csv_rejects_same_device_mlag_evpn_mh_profiles(self):
        with self.assertRaisesRegex(ValueError, "MLAG.*EVPN multihoming"):
            GENERATOR._csv_parse_bond_groups(
                "bond1|bond2",
                "mlagbond|evpn_multihoming",
                "NA|02:00:00:00:00:02",
                context="EXAMPLE-Leaf01",
            )

    def test_nested_and_cross_source_bond_profiles_reject_mlag_evpn_mh_mix(self):
        device = bond_device("mlag")
        device["vrfs"] = [{
            "l2vlans": [{
                "vlan_id": 13,
                "vlan_ports": [{"bonds": {
                    "type": "evpn_multihoming",
                    "bond_list": ["bond2"],
                    "mac-address": "02:00:00:00:00:02",
                }}],
            }],
        }]
        with self.assertRaisesRegex(ValueError, "MLAG.*EVPN multihoming"):
            GENERATOR.preprocess_device(device)

    def test_mlag_keeps_evpn_control_plane_without_global_multihoming(self):
        _text, document = global_evpn_document(is_mlag=True)
        self.assertEqual(
            {"state": "enabled"}, document[0]["set"]["evpn"],
        )

    def test_non_mlag_keeps_global_evpn_multihoming(self):
        _text, document = global_evpn_document(is_mlag=False)
        self.assertEqual(
            {
                "multihoming": {"state": "enabled"},
                "state": "enabled",
            },
            document[0]["set"]["evpn"],
        )

    def test_final_document_gate_rejects_mlag_with_global_evpn_mh(self):
        invalid = [{"set": {
            "evpn": {
                "multihoming": {"state": "enabled"},
                "state": "enabled",
            },
            "interface": {
                "bond1": {
                    "bond": {"mlag": {"id": 1, "state": "enabled"}},
                    "type": "bond",
                },
            },
            "mlag": {"state": "enabled"},
        }}]
        self.assertRegex(
            GENERATOR._redundancy_mode_errors(invalid)[0],
            "MLAG.*EVPN multihoming",
        )
        self.assertEqual(
            [],
            GENERATOR._redundancy_mode_errors([{"set": {
                "evpn": {"state": "enabled"},
                "mlag": {"state": "enabled"},
            }}]),
        )

    def test_final_document_gate_aggregates_sets_and_requires_mlag_output(self):
        split_conflict = [
            {"set": {"mlag": {"state": "enabled"}}},
            {"set": {"evpn": {"multihoming": {"state": "enabled"}}}},
        ]
        self.assertRegex(
            GENERATOR._redundancy_mode_errors(split_conflict)[0],
            "MLAG.*EVPN multihoming",
        )
        disabled_is_still_forbidden = [{"set": {
            "mlag": {"state": "enabled"},
            "evpn": {"multihoming": {"state": "disabled"}},
        }}]
        self.assertRegex(
            GENERATOR._redundancy_mode_errors(disabled_is_still_forbidden)[0],
            "MLAG.*EVPN multihoming",
        )
        peerlink_conflict = [{"set": {
            "interface": {"peerlink": {"type": "peerlink"}},
            "evpn": {"multihoming": {"state": "enabled"}},
        }}]
        self.assertRegex(
            GENERATOR._redundancy_mode_errors(peerlink_conflict)[0],
            "MLAG.*EVPN multihoming",
        )
        self.assertRegex(
            GENERATOR._redundancy_mode_errors(
                [{"set": {"evpn": {"state": "enabled"}}}],
                expected_bond_types={"mlag"},
            )[0],
            "声明 MLAG.*没有生成 MLAG",
        )

    def test_peerlink_vlan_gate_rejects_missing_extra_vni_and_vlan_4094(self):
        base = [{"set": {
            "bridge": {"domain": {"br_default": {"vlan": {
                "10-12,20": {}, "30": {"vni": {"1030": {}}},
            }}}},
            "interface": {"peerlink": {
                "bond": {"member": {"swp50": {}, "swp51": {}}},
                "bridge": {"domain": {"br_default": {"vlan": {
                    "10-12,20,30": {},
                }}}},
                "type": "peerlink",
            }},
            "mlag": {"state": "enabled"},
        }}]
        self.assertEqual(
            [],
            GENERATOR._peerlink_vlan_errors(
                base, expected_bond_types={"mlag"},
            ),
        )
        for label, mutate in {
            "missing": lambda vlan: (
                vlan.clear(), vlan.__setitem__("10-12,20", {})
            ),
            "extra": lambda vlan: (
                vlan.clear(), vlan.__setitem__("10-12,20,30,40", {})
            ),
            "vni": lambda vlan: vlan["10-12,20,30"].update(
                {"vni": {"1030": {}}}
            ),
            "4094": lambda vlan: (
                vlan.clear(), vlan.__setitem__("10-12,20,30,4094", {})
            ),
        }.items():
            with self.subTest(label=label):
                invalid = copy.deepcopy(base)
                peer_vlan = set_block(invalid)["interface"]["peerlink"]["bridge"]["domain"]["br_default"]["vlan"]
                mutate(peer_vlan)
                self.assertTrue(
                    GENERATOR._peerlink_vlan_errors(
                        invalid, expected_bond_types={"mlag"},
                    )
                )

    def test_peerlink_vlan_gate_allows_no_business_vlan_without_empty_node(self):
        no_vlans = [{"set": {
            "bridge": {"domain": {"br_default": {}}},
            "interface": {"peerlink": {
                "bond": {"member": {"swp50": {}, "swp51": {}}},
                "type": "peerlink",
            }},
            "mlag": {"state": "enabled"},
        }}]
        self.assertEqual(
            [],
            GENERATOR._peerlink_vlan_errors(
                no_vlans, expected_bond_types={"mlag"},
            ),
        )

    def test_source_yaml_mlag_cannot_bypass_peerlink_vlan_or_4094_gate(self):
        missing_peer_vlan = [{"set": {
            "bridge": {"domain": {"br_default": {"vlan": {"10": {}}}}},
            "interface": {"peerlink": {
                "bond": {"member": {"swp50": {}, "swp51": {}}},
                "type": "peerlink",
            }},
            "mlag": {"state": "enabled"},
        }}]
        self.assertTrue(
            GENERATOR._peerlink_vlan_errors(missing_peer_vlan),
            "MLAG evidence in source YAML must activate the final VLAN gate",
        )

        forbidden_4094 = copy.deepcopy(missing_peer_vlan)
        block = set_block(forbidden_4094)
        block["bridge"]["domain"]["br_default"]["vlan"] = {"4094": {}}
        block["interface"]["peerlink"]["bridge"] = {
            "domain": {"br_default": {"vlan": {"4094": {}}}},
        }
        self.assertTrue(any(
            "4094" in error
            for error in GENERATOR._peerlink_vlan_errors(forbidden_4094)
        ))

    def test_peerlink_vlan_gate_merges_same_interface_across_set_operations(self):
        split_source = [
            {"set": {
                "bridge": {"domain": {"br_default": {"vlan": {"10": {}}}}},
                "interface": {"peerlink": {
                    "bond": {"member": {"swp50": {}, "swp51": {}}},
                    "type": "peerlink",
                }},
                "mlag": {"state": "enabled"},
            }},
            {"set": {
                "bridge": {"domain": {"br_default": {"vlan": {"20": {}}}}},
                "interface": {"peerlink": {
                    "bridge": {"domain": {"br_default": {
                        "vlan": {"10,20": {}},
                    }}},
                }},
            }},
        ]
        self.assertEqual(
            [],
            GENERATOR._peerlink_vlan_errors(
                split_source, expected_bond_types={"mlag"},
            ),
        )

        fragmented = copy.deepcopy(split_source)
        fragmented[1]["set"]["interface"]["peerlink"]["bridge"]["domain"][
            "br_default"
        ]["vlan"] = {"10": {}}
        fragmented.append({"set": {"interface": {"peerlink": {
            "bridge": {"domain": {"br_default": {"vlan": {"20": {}}}}},
        }}}})
        self.assertTrue(
            GENERATOR._peerlink_vlan_errors(
                fragmented, expected_bond_types={"mlag"},
            )
        )

    def test_peerlink_vlan_gate_requires_exact_normalized_single_selector(self):
        base = [{"set": {
            "bridge": {"domain": {"br_default": {"vlan": {
                "10-12,20": {}, "30": {"vni": {"1030": {}}},
            }}}},
            "interface": {"peerlink": {
                "bridge": {"domain": {"br_default": {"vlan": {}}}},
                "type": "peerlink",
            }},
            "mlag": {"state": "enabled"},
        }}]
        invalid_selectors = [
            {"10-12,20": {}, "30": {}},
            {"30,20,10-12": {}},
            {"10-11,12,20,30": {}},
            {"10-12/20/30": {}},
            {"010-012,020,030": {}},
        ]
        for mapping in invalid_selectors:
            with self.subTest(mapping=mapping):
                invalid = copy.deepcopy(base)
                set_block(invalid)["interface"]["peerlink"]["bridge"][
                    "domain"
                ]["br_default"]["vlan"] = mapping
                self.assertTrue(
                    GENERATOR._peerlink_vlan_errors(
                        invalid, expected_bond_types={"mlag"},
                    )
                )

    def test_all_parent_templates_use_the_single_conditional_global_evpn_fragment(self):
        old_unconditional = (
            "    evpn:\n"
            "      multihoming:\n"
            "        state: enabled\n"
            "      state: enabled\n"
        )
        for template_name in sorted(GLOBAL_EVPN_PARENTS):
            with self.subTest(template=template_name):
                source = (TEMPLATES / template_name).read_text(encoding="utf-8")
                self.assertEqual(
                    1,
                    source.count(f"{{% include '{GLOBAL_EVPN_TEMPLATE}' %}}"),
                )
                self.assertNotIn(old_unconditional, source)
        for template_path in sorted(TEMPLATES.glob("*.yaml.j2")):
            if template_path.name.startswith("_"):
                continue
            with self.subTest(no_future_unconditional=template_path.name):
                self.assertNotIn(
                    old_unconditional,
                    template_path.read_text(encoding="utf-8"),
                )

    def test_all_mlag_peerlink_parents_use_one_shared_fragment(self):
        actual = {
            path.name
            for path in TEMPLATES.glob("*.yaml.j2")
            if not path.name.startswith("_")
            and (
                "type: peerlink" in path.read_text(encoding="utf-8")
                or f"{{% include '{MLAG_PEERLINK_TEMPLATE}' %}}"
                in path.read_text(encoding="utf-8")
            )
        }
        self.assertEqual({"border.yaml.j2", "oobofoob-spine.yaml.j2"}, actual)
        for template_name in sorted(actual):
            source = (TEMPLATES / template_name).read_text(encoding="utf-8")
            with self.subTest(template=template_name):
                self.assertEqual(
                    1,
                    source.count(f"{{% include '{MLAG_PEERLINK_TEMPLATE}' %}}"),
                )
                self.assertNotIn("      peerlink:\n", source)

    def test_legacy_oobofoob_mlag_peerlink_copies_its_single_bridge_vlan(self):
        device = border_mlag_device()
        device.update({
            "template": "oobofoob-spine",
            "vrfs": [{
                "evpn_vrf": "EXAMPLE-IGNORED",
                "l2vlans": [{
                    "vlan_id": 30,
                    "vlan_spec": "30",
                    "vlan_ids": [30],
                    "vni": 1030,
                    "vlan_ports": [],
                }],
            }],
            "vlan_id": 13,
            "svi_ip": "198.51.100.13/24",
            "vrr_ip": "",
            "vrr_mac": "",
        })
        rendered = GENERATOR.render(
            GENERATOR.build_env(), border_globals(),
            "EXAMPLE-OOB-SPINE01", device,
        )
        block = set_block(yaml.safe_load(rendered))
        self.assertEqual(
            {"13"},
            set(block["bridge"]["domain"]["br_default"]["vlan"]),
        )
        self.assertEqual(
            {"13": {}},
            block["interface"]["peerlink"]["bridge"]["domain"]["br_default"]["vlan"],
        )


class MlagEvpnGeneratePublishCompareWorkflowTests(unittest.TestCase):
    def test_generate_all_rejects_mlag_input_on_template_without_mlag_output(self):
        device = border_mlag_device()
        device["template"] = "tan-spine"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "generated"
            with mock.patch.object(
                GENERATOR,
                "load_devices",
                return_value=(
                    border_globals(),
                    {"EXAMPLE-MLAG01": device},
                ),
            ), mock.patch.object(GENERATOR, "OUTPUT_DIR", str(output)):
                with self.assertRaises(SystemExit):
                    GENERATOR.generate_all()
            self.assertFalse(output.exists())

    def test_generated_mlag_state_survives_publisher_and_runtime_comparison(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "generated"
            with mock.patch.object(
                GENERATOR,
                "load_devices",
                return_value=(
                    border_globals(),
                    {"EXAMPLE-MLAG01": border_mlag_device()},
                ),
            ), mock.patch.object(GENERATOR, "OUTPUT_DIR", str(output)):
                GENERATOR.generate_all()
            source = output / "EXAMPLE-MLAG01.yaml"
            published = PUBLISHER._canonical_yaml(str(source))

        published_document = yaml.safe_load(published)
        block = set_block(published_document)
        self.assertEqual(
            {"state": "enabled"},
            block["evpn"],
        )
        global_vlans = block["bridge"]["domain"]["br_default"]["vlan"]
        peerlink_vlans = block["interface"]["peerlink"]["bridge"]["domain"]["br_default"]["vlan"]
        self.assertEqual({"10-12,20", "30"}, set(global_vlans))
        self.assertEqual({"10-12,20,30": {}}, peerlink_vlans)
        self.assertEqual({}, global_vlans["10-12,20"])
        self.assertEqual({"vni": {"1030": {}}}, global_vlans["30"])
        self.assertNotIn("4094", peerlink_vlans)
        current = yaml.safe_dump(
            [
                {"header": {"model": "vx", "nvue-api-version": "nvue_v1"}},
                published_document[0],
            ],
            sort_keys=False,
        )
        self.assertEqual(
            MANUAL.runtime_comparable_nvue_config(
                published, label="published MLAG latest",
            ),
            MANUAL.runtime_comparable_nvue_config(
                current, label="MLAG nv config show",
            ),
        )
        drifted_document = copy.deepcopy(published_document)
        drifted_peerlink_vlans = (
            set_block(drifted_document)["interface"]["peerlink"]
            ["bridge"]["domain"]["br_default"]["vlan"]
        )
        drifted_peerlink_vlans.clear()
        drifted_peerlink_vlans["10-12,20"] = {}
        drifted = yaml.safe_dump(
            [
                {"header": {"model": "vx", "nvue-api-version": "nvue_v1"}},
                {"set": set_block(drifted_document)},
            ],
            sort_keys=False,
        )
        drifted_comparable, _drifted_rendered, _drifted_digest = (
            MANUAL.runtime_comparable_nvue_config(
                drifted, label="drifted MLAG nv config show",
            )
        )
        published_comparable, _published_rendered, _published_digest = (
            MANUAL.runtime_comparable_nvue_config(
                published, label="published MLAG latest",
            )
        )
        changed_paths = MANUAL._changed_config_paths(
            drifted_comparable,
            published_comparable,
        )
        self.assertTrue(any(
            path.startswith("interface.peerlink.bridge.domain.br_default.vlan")
            for path in changed_paths
        ), changed_paths)


if __name__ == "__main__":
    unittest.main()
