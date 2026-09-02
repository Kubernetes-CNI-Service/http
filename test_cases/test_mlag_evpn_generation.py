#!/usr/bin/env python3
"""MLAG versus EVPN multihoming generation and publication contracts."""

from __future__ import annotations

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
            "dns": {"server": ["192.0.2.53"]},
            "ntp": {"server": ["192.0.2.123"]},
        },
    }


def border_mlag_device() -> dict:
    device = bond_device("mlag")
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
        "vrfs": [],
        "mlag_backup": "192.0.2.11",
        "mlag_priority": 1000,
        "mlag_mac_address": "02:00:00:00:10:01",
        "system_mac": "02:00:00:00:20:01",
        "mlag_shared_address": "198.51.100.1",
    })
    return device


class MlagEvpnDirectTests(unittest.TestCase):
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
        self.assertEqual(
            {"state": "enabled"},
            published_document[0]["set"]["evpn"],
        )
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


if __name__ == "__main__":
    unittest.main()
