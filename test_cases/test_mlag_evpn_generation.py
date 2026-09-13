#!/usr/bin/env python3
"""MLAG versus EVPN multihoming generation and publication contracts."""

from __future__ import annotations

import base64
import copy
import csv
import ast
import hashlib
import io
import importlib.util
import json
from importlib.machinery import SourceFileLoader
import os
from pathlib import Path
import shutil
import stat
import subprocess
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

ALL_BOND_MODES = frozenset({"localbond", "mlag", "evpn_multihoming"})
ALL_BOND_MODE_COMBINATIONS = tuple(
    frozenset(
        mode for index, mode in enumerate(sorted(ALL_BOND_MODES))
        if mask & (1 << index)
    )
    for mask in range(1 << len(ALL_BOND_MODES))
)
EXPECTED_TEMPLATE_BOND_MODE_COMBINATIONS = {
    "border": frozenset({
        frozenset(),
        frozenset({"localbond"}),
        frozenset({"evpn_multihoming"}),
        frozenset({"localbond", "evpn_multihoming"}),
        frozenset({"mlag"}),
        frozenset({"localbond", "mlag"}),
    }),
    "oob-core": frozenset({
        frozenset(), frozenset({"localbond"}),
        frozenset({"evpn_multihoming"}),
        frozenset({"localbond", "evpn_multihoming"}),
    }),
    "oob-leaf": frozenset({
        frozenset(), frozenset({"localbond"}),
        frozenset({"evpn_multihoming"}),
        frozenset({"localbond", "evpn_multihoming"}),
    }),
    "tan-cp-leaf": frozenset({
        frozenset(), frozenset({"localbond"}),
        frozenset({"evpn_multihoming"}),
        frozenset({"localbond", "evpn_multihoming"}),
    }),
    "tan-hps-leaf": frozenset({
        frozenset(), frozenset({"localbond"}),
        frozenset({"evpn_multihoming"}),
        frozenset({"localbond", "evpn_multihoming"}),
    }),
    "tan-leaf": frozenset({
        frozenset(), frozenset({"localbond"}),
        frozenset({"evpn_multihoming"}),
        frozenset({"localbond", "evpn_multihoming"}),
    }),
    "tan-su-leaf": frozenset({
        frozenset(), frozenset({"localbond"}),
        frozenset({"evpn_multihoming"}),
        frozenset({"localbond", "evpn_multihoming"}),
    }),
    "oob-su-leaf": frozenset({
        frozenset(), frozenset({"localbond"}),
    }),
    "oob-rack-tor": frozenset({
        frozenset(), frozenset({"localbond"}),
    }),
    "oobofoob-leaf": frozenset({
        frozenset(), frozenset({"localbond"}),
    }),
    "tan-cp-1gleaf": frozenset({
        frozenset(), frozenset({"localbond"}),
    }),
    "tan-spine": frozenset({frozenset()}),
    "oob-su-spine": frozenset({frozenset()}),
    "oobofoob-spine": frozenset({
        frozenset({"mlag"}),
        frozenset({"localbond", "mlag"}),
    }),
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


SCHEMA_V1_COLLISION_HEADER = (
    "hostname", "type", "template", "eth0_ip", "netmask", "eth0_gw",
    "eth0_mac", "eth1_ip", "netmask", "eth1_gw", "eth1_mac", "lo_ip",
    "vrf_default", "vlan_id", "svi_ip", "netmask", "vrr_ip", "vrr_mac",
    "vlan_ports", "bgp_asn", "bgp_ports", "bond_ports", "bond_type",
    "bond_mac", "peerlink_ports", "vrl", "evpn_vrf", "evpn_l3vni",
    "evpn_l3vlan", "dhcp_relay", "evpn_l2vni", "evpn_l2vlan", "svi_ip",
    "netmask", "vrr_ip", "vrr_mac", "vlan_ports",
)
SCHEMA_V1_COLLISION_HOSTNAME = "COLLIDE-LEAF01"
SCHEMA_V1_COLLISION_VRR_MAC = "00:00:5e:00:01:c8"


def schema_v1_collision_row() -> tuple[str, ...]:
    row = ["NA"] * len(SCHEMA_V1_COLLISION_HEADER)
    replacements = {
        0: SCHEMA_V1_COLLISION_HOSTNAME,
        1: "eth",
        2: "tan-leaf",
        3: "192.0.2.10",
        4: "24",
        5: "192.0.2.1",
        6: "02:00:00:00:00:10",
        11: "198.51.100.10",
        12: "default",
        19: "65101",
        20: "swp49",
        21: "bond1s0|bond10",
        22: "evpn_multihoming",
        23: "02:00:00:00:10:10",
        26: "BLUE",
        27: "4000",
        28: "4000",
        29: "false",
        30: "100200",
        31: "200",
        32: "192.0.2.2",
        33: "24",
        34: "192.0.2.1",
        35: SCHEMA_V1_COLLISION_VRR_MAC,
        36: "bond1s0/bond10",
    }
    for index, value in replacements.items():
        row[index] = value
    return tuple(row)


def prepare_schema_v1_collision_generator(root: Path) -> tuple[Path, Path, Path]:
    """Materialize the real canonical generator and only its runtime inputs."""
    template_dir = root / "ztp/config/cumulus/template"
    service_dir = template_dir.parent
    template_dir.mkdir(parents=True)
    tools_dir = root / "tools"
    tools_dir.mkdir()
    (root / "ztp").mkdir(exist_ok=True)
    shutil.copy2(
        ROOT / "ztp/config/cumulus/template/90-c2-generate_configs.py",
        template_dir / "90-c2-generate_configs.py",
    )
    shutil.copy2(ROOT / "tools/project_contract.py", tools_dir)
    shutil.copy2(ROOT / "ztp/nvue_normalizer.py", root / "ztp")
    shutil.copy2(
        ROOT / "ztp/config/cumulus/d-hostname2mac.py",
        service_dir / "d-hostname2mac.py",
    )
    shutil.copy2(ROOT / "ztp/config/cumulus/default.yaml", service_dir)
    shutil.copytree(
        ROOT / "ztp/config/cumulus/template/03-templates-j2",
        template_dir / "03-templates-j2",
    )
    (template_dir / "01-global.yaml").write_text(
        yaml.safe_dump(dict(border_globals(), schema_version=1), sort_keys=False),
        encoding="utf-8",
    )
    with (template_dir / "02-devices_config.csv").open(
        "w", newline="", encoding="utf-8",
    ) as stream:
        csv.writer(stream).writerows((
            SCHEMA_V1_COLLISION_HEADER,
            schema_v1_collision_row(),
        ))
    devices = template_dir / "91-devices.yaml"
    devices.write_bytes(b"sentinel-91-before-collision\n")
    devices.chmod(0o640)
    os.utime(devices, ns=(1_650_000_000_000_000_000,) * 2)
    return template_dir / "90-c2-generate_configs.py", devices, template_dir


def run_traced_generator_main(
    script: Path, template_dir: Path,
) -> tuple[subprocess.CompletedProcess[str], list[list[str]]]:
    events = template_dir / "main-events.json"
    tracer = r'''import json, os, runpy, sys
script, event_path, *arguments = sys.argv[1:]
recorded = []
real_makedirs = os.makedirs
def traced_makedirs(path, *args, **kwargs):
    recorded.append(["makedirs", os.fspath(path)])
    return real_makedirs(path, *args, **kwargs)
def trace(frame, event, _arg):
    if event == "call" and frame.f_code.co_name == "render":
        recorded.append(["render", frame.f_code.co_filename])
    return trace
os.makedirs = traced_makedirs
sys.setprofile(trace)
sys.argv = [script, *arguments]
try:
    runpy.run_path(script, run_name="__main__")
finally:
    sys.setprofile(None)
    with open(event_path, "w", encoding="utf-8") as stream:
        json.dump(recorded, stream)
'''
    completed = subprocess.run(
        [
            sys.executable, "-B", "-c", tracer, str(script), str(events),
            "--branch", "eth", "-y", "--skip-descriptions",
        ],
        cwd=template_dir,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
        check=False,
    )
    return completed, json.loads(events.read_text(encoding="utf-8"))


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
        "version": "5.18.1",
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


def direct_evpn_gate_fixture() -> tuple[tuple[dict, ...], list[dict]]:
    """Return an independently authored valid schema-v2 EVPN-MH proof."""
    expected = ({
        "name": "bond3",
        "type": "evpn_multihoming",
        "member": "swp3",
        "id": 3,
        "mac_address": "02:00:00:00:00:03",
        "vlan_mode": "access",
        "vlan_access": 203,
        "vlan_native": None,
        "vlan_trunk_range": None,
        "template": "tan-leaf",
        "peerlink_members": (),
    },)
    document = [{"set": {
        "evpn": {
            "multihoming": {"state": "enabled"},
            "state": "enabled",
        },
        "interface": {"bond3": {
            "type": "bond",
            "bond": {"member": {"swp3": {}}, "mode": "lacp"},
            "bridge": {"domain": {"br_default": {"access": 203}}},
            "evpn": {"multihoming": {"segment": {
                "local-id": 3,
                "mac-address": "02:00:00:00:00:03",
                "state": "enabled",
            }}},
        }},
    }}]
    return expected, document


def direct_mlag_gate_fixture() -> tuple[tuple[dict, ...], list[dict]]:
    """Return an independently authored valid schema-v2 MLAG proof."""
    expected = ({
        "name": "bond7",
        "type": "mlag",
        "member": "swp7",
        "id": 7,
        "mac_address": "02:00:00:00:00:07",
        "vlan_mode": "access",
        "vlan_access": 207,
        "vlan_native": None,
        "vlan_trunk_range": None,
        "template": "border",
        "peerlink_members": ("swp49", "swp50"),
    },)
    document = [{"set": {
        "evpn": {"state": "enabled"},
        "interface": {
            "bond7": {
                "type": "bond",
                "bond": {
                    "member": {"swp7": {}},
                    "mlag": {"id": 7, "state": "enabled"},
                    "mode": "lacp",
                },
                "bridge": {"domain": {"br_default": {"access": 207}}},
            },
            "peerlink": {
                "type": "peerlink",
                "bond": {"member": {"swp49": {}, "swp50": {}}},
            },
            "peerlink.4094": {
                "base-interface": "peerlink", "type": "sub", "vlan": 4094,
            },
        },
        "mlag": {"backup": {"192.0.2.11": {}}, "state": "enabled"},
    }}]
    return expected, document


class MlagEvpnDirectTests(unittest.TestCase):
    @staticmethod
    def _derived_id_device(*bond_names: str) -> dict:
        group = {
            "type": "evpn_multihoming",
            "bond_list": list(bond_names),
            "lacp-bypass": "enabled",
            "mac-address": "02:00:00:00:00:10",
        }
        return {
            "_project_schema_version": 2,
            "template": "tan-leaf",
            "vlan_ports": [],
            "bond_groups": [copy.deepcopy(group)],
            "vrfs": [{
                "l2vlans": [{
                    "vlan_id": 200,
                    "vlan_ids": [200],
                    "vlan_ports": [{"bonds": copy.deepcopy(group)}],
                }],
            }],
        }

    def test_same_device_derived_bond_id_collision_names_both_bonds(self):
        device = self._derived_id_device("bond1s0", "bond10")

        with self.assertRaises(ValueError) as raised:
            GENERATOR.preprocess_device(device)

        diagnostic = str(raised.exception)
        self.assertIn("bond1s0", diagnostic)
        self.assertIn("bond10", diagnostic)
        self.assertIn("10", diagnostic)

    def test_bond_id_collision_diagnostic_has_canonical_total_order(self):
        diagnostics = []
        for names in (("bond1", "bond01"), ("bond01", "bond1")):
            with self.subTest(names=names), self.assertRaises(ValueError) as raised:
                GENERATOR.preprocess_device(self._derived_id_device(*names))
            diagnostics.append(str(raised.exception))

        self.assertEqual(diagnostics[0], diagnostics[1])
        self.assertRegex(
            diagnostics[0], r"bond01(?:\s+与|,\s*)bond1(?:\D|$)",
        )

    def test_all_derived_bond_id_collisions_are_reported_together(self):
        device = self._derived_id_device(
            "bond10", "bond2", "bond1s0", "bond02",
        )

        with self.assertRaises(ValueError) as raised:
            GENERATOR.preprocess_device(device)

        diagnostic = str(raised.exception)
        for name in ("bond02", "bond1s0", "bond10", "bond2"):
            self.assertIn(name, diagnostic)
        self.assertLess(diagnostic.index("ID 2"), diagnostic.index("ID 10"))

    def test_localbond_names_do_not_participate_in_derived_id_collisions(self):
        device = self._derived_id_device("bond1")
        local_group = {
            "type": "localbond",
            "bond_list": ["bond01"],
            "lacp-bypass": "enabled",
            "mac-address": "",
        }
        device["bond_groups"].append(copy.deepcopy(local_group))
        device["vrfs"][0]["l2vlans"][0]["vlan_ports"].append(
            {"bonds": copy.deepcopy(local_group)},
        )

        prepared = GENERATOR.preprocess_device(device)

        self.assertEqual(
            {"bond01": None, "bond1": 1},
            {
                bond["name"]: bond.get("id")
                for bond in prepared["computed_bonds"]
            },
        )

    def test_distinct_derived_bond_ids_remain_valid(self):
        prepared = GENERATOR.preprocess_device(
            self._derived_id_device("bond1s0", "bond11"),
        )

        self.assertEqual(
            [("bond1s0", 10), ("bond11", 11)],
            [(bond["name"], bond["id"])
             for bond in prepared["computed_bonds"]],
        )

    def test_different_devices_may_reuse_the_same_derived_bond_id(self):
        first = GENERATOR.preprocess_device(
            self._derived_id_device("bond1s0"),
        )
        second = GENERATOR.preprocess_device(
            self._derived_id_device("bond10"),
        )

        self.assertEqual(10, first["computed_bonds"][0]["id"])
        self.assertEqual(10, second["computed_bonds"][0]["id"])

    def test_schema_v1_main_collision_preserves_published_devices_authority(self):
        """The real canonical entrypoint must preflight before replacing 91."""
        with tempfile.TemporaryDirectory() as directory:
            script, devices, template_dir = prepare_schema_v1_collision_generator(
                Path(directory) / "http",
            )
            before_bytes = devices.read_bytes()
            before = devices.stat()
            completed, events = run_traced_generator_main(script, template_dir)
            after = devices.stat()

            self.assertEqual(1, completed.returncode, completed.stdout)
            self.assertIn(SCHEMA_V1_COLLISION_HOSTNAME, completed.stdout)
            self.assertIn("bond1s0", completed.stdout)
            self.assertIn("bond10", completed.stdout)
            self.assertEqual([], events, "collision preflight must precede mkdir/render")
            self.assertEqual(before_bytes, devices.read_bytes())
            self.assertEqual(before.st_dev, after.st_dev)
            self.assertEqual(before.st_ino, after.st_ino)
            self.assertEqual(stat.S_IMODE(before.st_mode), stat.S_IMODE(after.st_mode))
            self.assertEqual(before.st_mtime_ns, after.st_mtime_ns)
            self.assertEqual([], list(template_dir.glob("91-devices.yaml.tmp.*")))
            self.assertFalse((template_dir / "99-output").exists())

    def test_schema_v2_gate_requires_one_mapping_set_before_evidence_scan(self):
        evpn_expected, evpn_valid = direct_evpn_gate_fixture()
        mlag_expected, mlag_valid = direct_mlag_gate_fixture()
        variants = {
            "non-mapping-first": (
                [{"set": None}, *copy.deepcopy(evpn_valid)],
                evpn_expected,
                r"\$\[0\]\.set.*mapping",
            ),
            "disabled-evpn-first": (
                [{"set": {"evpn": {
                    "state": "disabled",
                    "multihoming": {"state": "disabled"},
                }}}, *copy.deepcopy(evpn_valid)],
                evpn_expected,
                r"恰好.*1.*mapping.*set.*实际=2",
            ),
            "disabled-mlag-first": (
                [{"set": {"mlag": {
                    "state": "disabled", "backup": {},
                }}}, *copy.deepcopy(mlag_valid)],
                mlag_expected,
                r"恰好.*1.*mapping.*set.*实际=2",
            ),
            "empty-second": (
                [*copy.deepcopy(evpn_valid), {"set": {}}],
                evpn_expected,
                r"恰好.*1.*mapping.*set.*实际=2",
            ),
        }
        for label, (document, expected, diagnostic) in variants.items():
            with self.subTest(label=label):
                errors = GENERATOR._redundancy_mode_errors(
                    document, expected_bonds=expected,
                )
                self.assertEqual(1, len(errors), errors)
                self.assertRegex(errors[0], diagnostic)

    def test_legacy_gate_preserves_non_mapping_and_multi_set_aggregation(self):
        evpn_expected, evpn_valid = direct_evpn_gate_fixture()
        del evpn_expected
        legacy_documents = (
            [{"set": None}, *copy.deepcopy(evpn_valid)],
            [{"set": {}}, {"set": {}}],
            [
                {"header": {"model": "vx"}},
                {"set": {"evpn": {"state": "enabled"}}},
                {"set": {"interface": {"swp1": {"type": "swp"}}}},
            ],
        )
        for document in legacy_documents:
            with self.subTest(document=document):
                self.assertEqual(
                    [],
                    GENERATOR._redundancy_mode_errors(
                        document, expected_bonds=None,
                    ),
                )

        split_conflict = [
            {"set": {"mlag": {"state": "enabled"}}},
            {"set": {"evpn": {"multihoming": {"state": "enabled"}}}},
        ]
        self.assertRegex(
            GENERATOR._redundancy_mode_errors(
                split_conflict, expected_bonds=None,
            )[0],
            "MLAG.*EVPN multihoming",
        )

    def test_template_bond_mode_set_policy_is_explicit_complete_and_exhaustive(self):
        expected = EXPECTED_TEMPLATE_BOND_MODE_COMBINATIONS
        concrete_templates = {
            path.name.removesuffix(".yaml.j2")
            for path in TEMPLATES.glob("*.yaml.j2")
            if not path.name.startswith("_")
        }

        self.assertEqual(concrete_templates, set(expected))
        self.assertEqual(
            expected,
            GENERATOR._V2_TEMPLATE_BOND_MODE_COMBINATIONS,
        )

        for template, allowed_combinations in expected.items():
            for modes in ALL_BOND_MODE_COMBINATIONS:
                with self.subTest(template=template, modes=sorted(modes)):
                    if modes in allowed_combinations:
                        GENERATOR._validate_template_bond_modes(
                            template,
                            modes,
                            hostname="EXAMPLE-Bond01",
                            source_line=17,
                        )
                        continue
                    with self.assertRaises(ValueError) as raised:
                        GENERATOR._validate_template_bond_modes(
                            template,
                            modes,
                            hostname="EXAMPLE-Bond01",
                            source_line=17,
                        )
                    diagnostic = str(raised.exception)
                    self.assertIn("行17", diagnostic)
                    self.assertIn("EXAMPLE-Bond01", diagnostic)
                    self.assertIn(f"template={template}", diagnostic)
                    self.assertIn("mode组合=", diagnostic)
                    self.assertIn("允许组合=", diagnostic)

    def test_mlag_capable_templates_have_the_mode_set_policy_as_single_authority(self):
        expected = frozenset({"border", "oobofoob-spine"})
        independently_selected = frozenset(
            template
            for template, combinations in EXPECTED_TEMPLATE_BOND_MODE_COMBINATIONS.items()
            if any("mlag" in combination for combination in combinations)
        )
        self.assertEqual(expected, independently_selected)
        self.assertEqual(expected, GENERATOR._V2_MLAG_CAPABLE_TEMPLATES)

    def test_csv_rejects_every_non_na_empty_pipe_group(self):
        for ports in ("|", "bond1|", "|bond1", "bond1||bond2", " | "):
            with self.subTest(ports=ports), self.assertRaisesRegex(
                ValueError, r"bond_ports.*\|.*不能为空"
            ):
                GENERATOR._csv_parse_bond_groups(
                    ports, "local", "NA", schema_version=2,
                )

    def test_active_schema_v2_bond_must_have_a_renderable_vlan_attachment(self):
        device = bond_device("localbond")
        device.update({
            "template": "tan-leaf",
            "hostname": "EXAMPLE-Unattached01",
            "_project_schema_version": 2,
            "vrfs": [],
            "vlan_ports": [],
        })
        with self.assertRaisesRegex(
            ValueError, "active bond.*未关联.*VLAN|未生成 render descriptor"
        ):
            GENERATOR._expected_active_bond_descriptors(device)

    def test_post_render_gate_proves_each_active_bond_semantics(self):
        expected = (
            {
                "name": "bond1b2",
                "type": "localbond",
                "members": ("swp1", "swp2"),
                "vlan_mode": "access",
                "vlan_access": 200,
                "vlan_native": None,
                "vlan_trunk_range": None,
                "template": "tan-leaf",
                "peerlink_members": (),
            },
            {
                "name": "bond3",
                "type": "evpn_multihoming",
                "member": "swp3",
                "id": 3,
                "mac_address": "02:00:00:00:00:03",
                "vlan_mode": "trunk",
                "vlan_access": None,
                "vlan_native": 201,
                "vlan_trunk_range": "201-202",
                "template": "tan-leaf",
                "peerlink_members": (),
            },
        )
        valid = [{"set": {
            "evpn": {
                "multihoming": {"state": "enabled"},
                "state": "enabled",
            },
            "interface": {
                "bond1b2": {
                    "type": "bond",
                    "bond": {
                        "member": {"swp1": {}, "swp2": {}},
                        "mode": "lacp",
                    },
                    "bridge": {"domain": {"br_default": {"access": 200}}},
                },
                "bond3": {
                    "type": "bond",
                    "bond": {"member": {"swp3": {}}, "mode": "lacp"},
                    "bridge": {"domain": {"br_default": {
                        "untagged": 201,
                        "vlan": {"201-202": {}},
                    }}},
                    "evpn": {"multihoming": {"segment": {
                        "local-id": 3,
                        "mac-address": "02:00:00:00:00:03",
                        "state": "enabled",
                    }}},
                },
            },
        }}]
        self.assertEqual(
            [], GENERATOR._redundancy_mode_errors(
                valid, expected_bonds=expected,
            ),
        )

        corruptions = {
            "local-members": ("interface", "bond1b2", "bond", "member", {"swp1": {}}),
            "local-bridge": ("interface", "bond1b2", "bridge", "domain", "br_default", {"access": 201}),
            "evpn-member": ("interface", "bond3", "bond", "member", {"swp4": {}}),
            "evpn-id": ("interface", "bond3", "evpn", "multihoming", "segment", "local-id", 4),
            "evpn-mac": ("interface", "bond3", "evpn", "multihoming", "segment", "mac-address", "02:00:00:00:00:04"),
            "evpn-state": ("interface", "bond3", "evpn", "multihoming", "segment", "state", "disabled"),
            "global-evpn-state": ("evpn", "multihoming", "state", "disabled"),
        }
        for label, (*path, replacement) in corruptions.items():
            with self.subTest(label=label):
                invalid = copy.deepcopy(valid)
                node = invalid[0]["set"]
                for key in path[:-1]:
                    node = node[key]
                node[path[-1]] = replacement
                self.assertTrue(
                    GENERATOR._redundancy_mode_errors(
                        invalid, expected_bonds=expected,
                    ),
                    label,
                )

        misplaced = copy.deepcopy(valid)
        misplaced[0]["set"]["interface"]["bond4"] = misplaced[0]["set"][
            "interface"
        ]["bond3"].pop("evpn")
        self.assertTrue(GENERATOR._redundancy_mode_errors(
            misplaced, expected_bonds=expected,
        ))

    def test_post_render_gate_requires_per_bond_mlag_and_role_evidence(self):
        expected = ({
            "name": "bond7",
            "type": "mlag",
            "member": "swp7",
            "id": 7,
            "mac_address": "02:00:00:00:00:07",
            "vlan_mode": "access",
            "vlan_access": 207,
            "vlan_native": None,
            "vlan_trunk_range": None,
            "template": "border",
            "peerlink_members": ("swp49", "swp50"),
        },)
        valid = [{"set": {
            "evpn": {"state": "enabled"},
            "interface": {
                "bond7": {
                    "type": "bond",
                    "bond": {
                        "member": {"swp7": {}},
                        "mlag": {"id": 7, "state": "enabled"},
                        "mode": "lacp",
                    },
                    "bridge": {"domain": {"br_default": {"access": 207}}},
                },
                "peerlink": {
                    "type": "peerlink",
                    "bond": {"member": {"swp49": {}, "swp50": {}}},
                },
                "peerlink.4094": {
                    "base-interface": "peerlink", "type": "sub", "vlan": 4094,
                },
            },
            "mlag": {"backup": {"192.0.2.11": {}}, "state": "enabled"},
        }}]
        self.assertEqual([], GENERATOR._redundancy_mode_errors(
            valid, expected_bonds=expected,
        ))
        for missing in ("bond-mlag", "peerlink", "top-level"):
            with self.subTest(missing=missing):
                invalid = copy.deepcopy(valid)
                if missing == "bond-mlag":
                    del invalid[0]["set"]["interface"]["bond7"]["bond"]["mlag"]
                elif missing == "peerlink":
                    del invalid[0]["set"]["interface"]["peerlink"]
                else:
                    del invalid[0]["set"]["mlag"]
                self.assertTrue(GENERATOR._redundancy_mode_errors(
                    invalid, expected_bonds=expected,
                ))

    def test_empty_active_bond_set_rejects_orphan_redundancy_topology(self):
        orphan_documents = {
            "peerlink": [{"set": {"interface": {
                "peerlink": {
                    "type": "peerlink",
                    "bond": {"member": {"swp49": {}, "swp50": {}}},
                },
            }}}],
            "evpn-uplink": [{"set": {"interface": {
                "swp53": {"type": "swp", "evpn": {
                    "multihoming": {"uplink": "enabled"},
                }},
            }}}],
        }
        for label, document in orphan_documents.items():
            with self.subTest(label=label):
                self.assertTrue(
                    GENERATOR._redundancy_mode_errors(
                        document, expected_bonds=(),
                    )
                )

    def test_mlag_global_system_mac_is_optional_but_honored_when_present(self):
        environment = GENERATOR.build_env()
        configured = border_mlag_device()
        configured_block = set_block(yaml.safe_load(GENERATOR.render(
            environment, border_globals(), configured["hostname"], configured,
        )))
        self.assertEqual(
            configured["system_mac"],
            configured_block["system"]["global"]["system-mac"],
        )

        automatic = copy.deepcopy(configured)
        automatic.pop("system_mac")
        automatic_block = set_block(yaml.safe_load(GENERATOR.render(
            environment, border_globals(), automatic["hostname"], automatic,
        )))
        self.assertEqual(
            automatic["mlag_mac_address"],
            automatic_block["system"]["global"]["anycast-mac"],
        )
        self.assertNotIn("system-mac", automatic_block["system"]["global"])

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

    def test_mlag_peerlink_relies_on_bridge_vlan_inheritance(self):
        border = border_mlag_device()
        legacy = copy.deepcopy(border)
        legacy.update({
            "template": "oobofoob-spine",
            "vlan_id": 13,
            "svi_ip": "198.51.100.13/24",
            "vrr_ip": "",
            "vrr_mac": "",
        })
        for label, device in (("border", border), ("legacy", legacy)):
            with self.subTest(template=label):
                rendered = GENERATOR.render(
                    GENERATOR.build_env(), border_globals(),
                    device["hostname"], device,
                )
                block = set_block(yaml.safe_load(rendered))
                peerlink = block["interface"]["peerlink"]
                self.assertEqual("peerlink", peerlink["type"])
                self.assertEqual(
                    {"swp50": {}, "swp51": {}},
                    peerlink["bond"]["member"],
                )
                self.assertNotIn(
                    "bridge", peerlink,
                    "peerlink inherits every br_default VLAN by default",
                )
                self.assertEqual(
                    {
                        "base-interface": "peerlink",
                        "type": "sub",
                        "vlan": 4094,
                    },
                    block["interface"]["peerlink.4094"],
                )


class MlagEvpnGeneratePublishCompareWorkflowTests(unittest.TestCase):
    @staticmethod
    def _replace_bonds(device: dict, *names: str) -> dict:
        replaced = copy.deepcopy(device)
        group = copy.deepcopy(replaced["bond_groups"][0])
        group["bond_list"] = list(names)
        replaced["bond_groups"] = [copy.deepcopy(group)]
        replaced["vrfs"][0]["l2vlans"][0]["vlan_ports"] = [
            {"bonds": copy.deepcopy(group)},
        ]
        return replaced

    def test_schema_v1_collision_preflight_has_zero_mkdir_render_or_write(self):
        good = border_mlag_device()
        good["hostname"] = "GOOD-MLAG01"
        bad = self._replace_bonds(
            border_mlag_device(), "bond1s0", "bond10",
        )
        bad["hostname"] = "BAD-MLAG01"

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "generated"
            captured = io.StringIO()
            write_paths = []
            real_open = open

            def track_writes(path, mode="r", *args, **kwargs):
                if any(flag in mode for flag in "wax+"):
                    write_paths.append(str(path))
                return real_open(path, mode, *args, **kwargs)

            with mock.patch.object(
                GENERATOR,
                "load_devices",
                return_value=(
                    border_globals(),
                    {"GOOD-MLAG01": good, "BAD-MLAG01": bad},
                ),
            ), mock.patch.object(
                GENERATOR, "OUTPUT_DIR", str(output),
            ), mock.patch.object(
                GENERATOR.os, "makedirs", wraps=GENERATOR.os.makedirs,
            ) as mkdir_spy, mock.patch.object(
                GENERATOR, "render", wraps=GENERATOR.render,
            ) as render_spy, mock.patch(
                "builtins.open", side_effect=track_writes,
            ), mock.patch("sys.stdout", captured):
                with self.assertRaises(SystemExit) as raised:
                    GENERATOR.generate_all()

            self.assertEqual(1, raised.exception.code)
            self.assertIn("BAD-MLAG01", captured.getvalue())
            self.assertEqual([], write_paths)
            mkdir_spy.assert_not_called()
            render_spy.assert_not_called()
            self.assertFalse(output.exists())
            self.assertFalse(Path(str(output) + ".tmp").exists())

    def test_bond_id_collision_stops_before_render_or_output_publish(self):
        device = border_mlag_device()
        device["_project_schema_version"] = 2
        device = self._replace_bonds(device, "bond1s0", "bond10")

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "generated"
            captured = io.StringIO()
            with mock.patch.object(
                GENERATOR,
                "load_devices",
                return_value=(
                    border_globals(),
                    {"EXAMPLE-MLAG01": device},
                ),
            ), mock.patch.object(
                GENERATOR, "OUTPUT_DIR", str(output),
            ), mock.patch.object(
                GENERATOR.os, "makedirs", wraps=GENERATOR.os.makedirs,
            ) as mkdir_spy, mock.patch.object(
                GENERATOR, "render", wraps=GENERATOR.render,
            ) as render_spy, mock.patch("sys.stdout", captured):
                with self.assertRaises(SystemExit) as raised:
                    GENERATOR.generate_all()

            self.assertEqual(1, raised.exception.code)
            diagnostic = captured.getvalue()
            self.assertIn("EXAMPLE-MLAG01", diagnostic)
            self.assertIn("bond1s0", diagnostic)
            self.assertIn("bond10", diagnostic)
            mkdir_spy.assert_not_called()
            render_spy.assert_not_called()
            self.assertFalse(output.exists())
            self.assertFalse(Path(str(output) + ".tmp").exists())

    def test_schema_v2_multi_set_template_stops_without_publishing_output(self):
        device = border_mlag_device()
        device["_project_schema_version"] = 2
        additions = {
            "empty-second-set": "\n- set: {}\n",
            "conflicting-second-set": (
                "\n- set:\n"
                "    mlag:\n"
                "      backup: {}\n"
                "      state: disabled\n"
            ),
        }
        for label, addition in additions.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                templates = root / "templates"
                shutil.copytree(TEMPLATES, templates)
                template = templates / "border.yaml.j2"
                template.write_text(
                    template.read_text(encoding="utf-8") + addition,
                    encoding="utf-8",
                )
                output = root / "generated"
                with mock.patch.object(
                    GENERATOR,
                    "load_devices",
                    return_value=(border_globals(), {"EXAMPLE-MLAG01": device}),
                ), mock.patch.multiple(
                    GENERATOR,
                    OUTPUT_DIR=str(output),
                    TEMPLATES_DIR=str(templates),
                ):
                    with self.assertRaises(SystemExit) as raised:
                        GENERATOR.generate_all()
                self.assertEqual(1, raised.exception.code)
                self.assertFalse(output.exists())
                self.assertFalse(Path(str(output) + ".tmp").exists())

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
        device = border_mlag_device()
        device.pop("system_mac")
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
                GENERATOR.generate_all()
            source = output / "EXAMPLE-MLAG01.yaml"
            published = PUBLISHER._canonical_yaml(str(source))

        published_document = yaml.safe_load(published)
        block = set_block(published_document)
        self.assertEqual(
            {"state": "enabled"},
            block["evpn"],
        )
        self.assertEqual(
            device["mlag_mac_address"],
            block["system"]["global"]["anycast-mac"],
        )
        self.assertNotIn("system-mac", block["system"]["global"])
        global_vlans = block["bridge"]["domain"]["br_default"]["vlan"]
        self.assertEqual({"10-12,20", "30"}, set(global_vlans))
        self.assertEqual({}, global_vlans["10-12,20"])
        self.assertEqual({"vni": {"1030": {}}}, global_vlans["30"])
        self.assertNotIn("bridge", block["interface"]["peerlink"])
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

    def test_generate_all_parses_each_rendered_yaml_only_once(self):
        """The publication gate reuses the already validated document."""
        device = border_mlag_device()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "generated"
            with mock.patch.object(
                GENERATOR,
                "load_devices",
                return_value=(
                    border_globals(),
                    {"EXAMPLE-MLAG01": device},
                ),
            ), mock.patch.object(
                GENERATOR, "OUTPUT_DIR", str(output),
            ), mock.patch.object(
                GENERATOR,
                "_load_generated_yaml",
                wraps=GENERATOR._load_generated_yaml,
            ) as parse_spy:
                GENERATOR.generate_all()

        self.assertEqual(1, parse_spy.call_count)


class YamlAccelerationContractTests(unittest.TestCase):
    """Keep the generator's YAML hot path on libyaml without semantic drift."""

    @staticmethod
    def _pure_python_generator():
        generator_path = (
            ROOT / "ztp/config/cumulus/template/90-c2-generate_configs.py"
        )
        with mock.patch.object(yaml, "__with_libyaml__", False):
            return load_script(
                "yaml_deep_nesting_fallback_generator", generator_path,
            )

    @staticmethod
    def _deep_flow_sequence() -> str:
        # This fixed, roughly 1 KiB document is intentionally far below every
        # input-size limit while exceeding SafeLoader's recursive call depth.
        return "[" * 500 + "0" + "]" * 500

    def test_cached_staging_gate_binds_exact_member_set_and_rendered_text(self):
        """Cached semantic validation remains bound to the published bytes."""
        with tempfile.TemporaryDirectory() as directory:
            staging = Path(directory)
            leaf = staging / "leaf01.yaml"
            rendered = "set:\n  system:\n    hostname: leaf01\n"
            leaf.write_text(rendered, encoding="utf-8")
            cached = {"leaf01.yaml": (rendered, {"set": {"system": {}}})}

            self.assertEqual(
                [], GENERATOR._validate_cached_yaml_directory(directory, cached),
            )

            leaf.unlink()
            missing = GENERATOR._validate_cached_yaml_directory(directory, cached)
            self.assertEqual(1, len(missing))
            self.assertIn("missing=['leaf01.yaml']", missing[0])

            leaf.write_text(rendered, encoding="utf-8")
            extra = staging / "unexpected.yaml"
            extra.write_text("set: {}\n", encoding="utf-8")
            unexpected = GENERATOR._validate_cached_yaml_directory(
                directory, cached,
            )
            self.assertEqual(1, len(unexpected))
            self.assertIn("unexpected=['unexpected.yaml']", unexpected[0])

            extra.unlink()
            leaf.write_text(
                "set:\n  system:\n    hostname: substituted\n", encoding="utf-8",
            )
            drift = GENERATOR._validate_cached_yaml_directory(directory, cached)
            self.assertEqual(1, len(drift))
            self.assertIn("写入字节与已验证渲染结果不一致", drift[0])

    def test_custom_safe_loader_and_dumper_select_libyaml_when_available(self):
        if getattr(yaml, "__with_libyaml__", False):
            self.assertIs(GENERATOR._MacStringSafeLoader.__bases__[0], yaml.CSafeLoader)
            self.assertIs(GENERATOR._GeneratedYamlDumper.__bases__[0], yaml.CSafeDumper)
        else:
            self.assertIs(GENERATOR._MacStringSafeLoader.__bases__[0], yaml.SafeLoader)
            self.assertIs(GENERATOR._GeneratedYamlDumper.__bases__[0], yaml.SafeDumper)

    def test_custom_yaml_classes_fall_back_when_libyaml_is_unavailable(self):
        generator_path = (
            ROOT / "ztp/config/cumulus/template/90-c2-generate_configs.py"
        )
        with mock.patch.object(yaml, "__with_libyaml__", False):
            fallback = load_script("yaml_fallback_generator", generator_path)
        self.assertIs(fallback._MacStringSafeLoader.__bases__[0], yaml.SafeLoader)
        self.assertIs(fallback._GeneratedYamlDumper.__bases__[0], yaml.SafeDumper)

    def test_pure_python_fallback_rejects_deep_global_with_controlled_exit(self):
        fallback = self._pure_python_generator()
        source = (
            "schema_version: 2\ncommon:\n  nested: "
            + self._deep_flow_sequence()
            + "\nswitches: []\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            authority = Path(directory) / "01-global.yaml"
            authority.write_text(source, encoding="utf-8")
            captured = io.StringIO()
            with mock.patch.object(fallback, "_GLOBAL_FILE", str(authority)), \
                    mock.patch("sys.stdout", captured), \
                    self.assertRaises(SystemExit) as stopped:
                fallback._load_global_document()
        self.assertEqual(1, stopped.exception.code)
        self.assertIn("YAML 嵌套层级超过支持上限", captured.getvalue())

    def test_pure_python_fallback_rejects_deep_source_receipt_as_value_error(self):
        fallback = self._pure_python_generator()
        source = (
            "- set:\n    interface:\n      deep: "
            + self._deep_flow_sequence()
            + "\n"
        ).encode("utf-8")
        with self.assertRaisesRegex(ValueError, "YAML 嵌套层级超过支持上限"):
            fallback._decode_source_yaml(
                base64.b64encode(source).decode("ascii"),
                hashlib.sha256(source).hexdigest(),
            )

    def test_pure_python_fallback_rejects_deep_rendered_yaml_as_yaml_error(self):
        fallback = self._pure_python_generator()
        rendered = (
            "- set:\n    interface:\n      deep: "
            + self._deep_flow_sequence()
            + "\n"
        )
        with self.assertRaisesRegex(
            yaml.YAMLError, "YAML 嵌套层级超过支持上限",
        ):
            fallback._load_generated_yaml(rendered)

    def test_generator_has_no_implicit_pure_python_yaml_hot_path(self):
        source = (
            ROOT / "ztp/config/cumulus/template/90-c2-generate_configs.py"
        ).read_text(encoding="utf-8")
        tree = ast.parse(source)
        violations = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if not isinstance(node.func.value, ast.Name) or node.func.value.id != "yaml":
                continue
            name = node.func.attr
            keywords = {item.arg for item in node.keywords}
            if name in {"safe_load", "safe_dump"}:
                violations.append((node.lineno, name, "implicit SafeLoader/SafeDumper"))
            elif name == "load" and "Loader" not in keywords:
                violations.append((node.lineno, name, "missing Loader"))
            elif name == "dump" and "Dumper" not in keywords:
                violations.append((node.lineno, name, "missing Dumper"))
        self.assertEqual([], violations)

    def test_accelerated_loader_preserves_mac_and_duplicate_key_contracts(self):
        document = GENERATOR._load_generated_yaml(
            "mac: 02:38:39:00:00:01\nname: leaf01\n"
        )
        self.assertEqual("02:38:39:00:00:01", document["mac"])
        with self.assertRaisesRegex(yaml.constructor.ConstructorError, "duplicate key 'a'"):
            GENERATOR._load_generated_yaml("a: 1\na: 2\n")

    def test_global_authority_rejects_duplicate_keys(self):
        source = (
            "schema_version: 1\n"
            "schema_version: 2\n"
            "common: {}\n"
            "switches: []\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            authority = Path(directory) / "01-global.yaml"
            authority.write_text(source, encoding="utf-8")
            with mock.patch.object(GENERATOR, "_GLOBAL_FILE", str(authority)), \
                    self.assertRaises(SystemExit) as stopped:
                GENERATOR._load_global_document()
        self.assertEqual(1, stopped.exception.code)

    def test_source_yaml_receipt_rejects_duplicate_keys(self):
        source = (
            "- set:\n"
            "    interface:\n"
            "      swp1: first\n"
            "    interface:\n"
            "      swp2: second\n"
        ).encode("utf-8")
        encoded = base64.b64encode(source).decode("ascii")
        with self.assertRaisesRegex(ValueError, "duplicate key 'interface'"):
            GENERATOR._decode_source_yaml(
                encoded, hashlib.sha256(source).hexdigest(),
            )

    def test_rendered_device_authority_rejects_duplicate_keys(self):
        source = (
            "global: {}\n"
            "devices:\n"
            "  leaf01: {}\n"
            "devices:\n"
            "  leaf02: {}\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            authority = Path(directory) / "91-devices.yaml"
            authority.write_text(source, encoding="utf-8")
            with mock.patch.object(GENERATOR, "DEVICES_FILE", str(authority)), \
                    self.assertRaisesRegex(
                        yaml.constructor.ConstructorError, "duplicate key 'devices'",
                    ):
                GENERATOR.load_devices()

    def test_accelerated_dumper_preserves_literal_snippet_round_trip(self):
        document = [{
            "set": {
                "system": {
                    "config": {
                        "snippet": {
                            "ifupdown2_eni": {
                                "swp1": "auto swp1\niface swp1\n",
                            },
                        },
                    },
                },
            },
        }]
        rendered = GENERATOR._dump_generated_yaml(document)
        self.assertIn("swp1: |", rendered)
        self.assertEqual(document, GENERATOR._load_generated_yaml(rendered))


if __name__ == "__main__":
    unittest.main()
