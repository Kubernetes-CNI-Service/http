#!/usr/bin/env python3
"""REQ-8 H-05/H-06: shared role fragment and generator phase boundaries."""

from __future__ import annotations

import copy
from contextlib import redirect_stdout
import ast
import base64
import csv
import hashlib
import inspect
import io
import json
from pathlib import Path
import tempfile
import textwrap
import unittest
from unittest import mock

import yaml

from test_cases import test_v2_generation_flow as fixture


GENERATOR = fixture.GENERATOR
TEMPLATES = fixture.TEMPLATES


ROLE_NAMES = tuple(sorted(
    path.name.removesuffix(".yaml.j2")
    for path in TEMPLATES.glob("*.yaml.j2")
    if not path.name.startswith("_")
))
DHCP_CLIENT_ROLES = frozenset({"oobofoob-leaf", "oobofoob-spine"})

# Pre-refactor render digest, captured before changing any role or generator
# byte.  Each member is framed with its role, eth1 state and exact byte length;
# no expected output is regenerated from the post-change implementation.
PRE_REFACTOR_ROLE_RENDER_SHA256 = (
    "eee15c2377d1a26a3edd826f44448320cf8e9fea1305d9f817e913769ba73406"
)
PRE_PHASE_EXTRACTION_DEVICES_YAML_SHA256 = (
    "8cf33e6a978f37089f9022772fc0c6d7a856a08f19a443ab2a8e1feea336be6a"
)


class H05H06DirectTests(unittest.TestCase):
    def test_explicit_template_resolver_only_checks_the_selected_hint(self):
        """The resolver may score a hostname, but must discard non-exact matches."""
        resolver = ast.parse(textwrap.dedent(
            inspect.getsource(GENERATOR._resolve_device_csv_template)
        ))
        calls = [
            node for node in ast.walk(resolver)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_best_template"
        ]
        self.assertEqual(1, len(calls))
        self.assertIsInstance(calls[0].args[0], ast.Name)
        self.assertEqual("template", calls[0].args[0].id)

    def test_standalone_yaml_render_rejects_missing_or_nonexact_template(self):
        """A directly loaded 91-devices.yaml has not passed the CSV resolver."""
        for hint in (None, "not-an-exact-role"):
            with self.subTest(hint=hint), tempfile.TemporaryDirectory() as directory:
                devices_file = Path(directory) / "91-devices.yaml"
                device = {"hostname": "Leaf01", "vrfs": []}
                if hint is not None:
                    device["template"] = hint
                devices_file.write_text(yaml.safe_dump({
                    "global": {}, "devices": {"Leaf01": device},
                }), encoding="utf-8")
                with mock.patch.object(GENERATOR, "DEVICES_FILE", str(devices_file)):
                    global_vars, devices = GENERATOR.load_devices()
                env = mock.Mock()
                with mock.patch.object(
                    GENERATOR, "_best_template",
                    return_value=("near.yaml.j2", False),
                ) as best, self.assertRaisesRegex(
                    ValueError, "template|模板",
                ):
                    GENERATOR.render(env, global_vars, "Leaf01", devices["Leaf01"])
                env.get_template.assert_not_called()
                if hint is None:
                    best.assert_not_called()
                else:
                    best.assert_called_once_with(hint, "Leaf01")

    def test_csv_publication_boundary_cleans_provenance_and_never_replaces_on_dump_failure(self):
        devices = {"Leaf01": {"vrfs": [{"l2vlans": [{
            "vlan_id": 100, "_csv_source": {"line": 7},
        }]}]}}
        seen = []
        output = io.StringIO()
        with mock.patch.object(GENERATOR, "DEVICES_FILE", "/tmp/91-devices.yaml"), \
                mock.patch.object(
                    GENERATOR, "_publish_devices_yaml",
                    side_effect=lambda global_data, device_data: seen.append(
                        copy.deepcopy(device_data)
                    ),
                ), redirect_stdout(output):
            GENERATOR._finalize_device_csv_publication({"version": 1}, devices)
        self.assertEqual(
            {"Leaf01": {"vrfs": [{"l2vlans": [{"vlan_id": 100}]}]}},
            seen[0],
        )
        self.assertEqual(
            "Generated /tmp/91-devices.yaml: 1 global keys, 1 devices\n",
            output.getvalue(),
        )
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "91-devices.yaml"
            target.write_bytes(b"previous complete publication\n")
            failed_devices = {"Leaf02": {"vrfs": [{"l2vlans": [{
                "_csv_source": {"line": 8},
            }]}]}}
            output = io.StringIO()

            def fail_after_partial_dump(_data, stream, **_kwargs):
                stream.write("partial temporary content")
                raise OSError("injected dump failure")

            with mock.patch.object(GENERATOR, "DEVICES_FILE", str(target)), \
                    mock.patch.object(GENERATOR.yaml, "dump", side_effect=fail_after_partial_dump), \
                    redirect_stdout(output), self.assertRaisesRegex(
                        OSError, "injected dump failure",
                    ):
                GENERATOR._finalize_device_csv_publication(
                    {"version": 1}, failed_devices,
                )
            self.assertEqual(b"previous complete publication\n", target.read_bytes())
            self.assertNotIn("Generated", output.getvalue())

    def test_duplicate_profile_gate_stops_in_order_before_staging(self):
        devices, macs, prior = {"Leaf01": {"hostname": "Leaf01"}}, {}, [" earlier"]
        output = io.StringIO()
        with mock.patch.object(
            GENERATOR, "_collect_duplicate_value_errors", return_value=[" duplicate"],
        ) as duplicates, mock.patch.object(
            GENERATOR, "_attach_splitter_profiles",
        ) as profiles, redirect_stdout(output), self.assertRaises(SystemExit) as stopped:
            GENERATOR._validate_project_duplicates_and_profiles(devices, macs, prior)
        self.assertEqual(1, stopped.exception.code)
        duplicates.assert_called_once_with(devices, macs, prior)
        profiles.assert_not_called()
        self.assertEqual(
            "[ERROR] 02-devices_config.csv 中存在重复值，请修正后重新运行：\n"
            " duplicate\n", output.getvalue(),
        )
        output = io.StringIO()
        with mock.patch.object(
            GENERATOR, "_collect_duplicate_value_errors", return_value=[],
        ), mock.patch.object(
            GENERATOR, "_attach_splitter_profiles", side_effect=ValueError("bad profile"),
        ) as profiles, redirect_stdout(output), self.assertRaises(SystemExit) as stopped:
            GENERATOR._validate_project_duplicates_and_profiles(devices, macs, prior)
        self.assertEqual(1, stopped.exception.code)
        profiles.assert_called_once_with(devices)
        self.assertEqual("[ERROR] bad profile\n", output.getvalue())
        order = []
        with mock.patch.object(
            GENERATOR, "_collect_duplicate_value_errors",
            side_effect=lambda *args: order.append("duplicates") or [],
        ), mock.patch.object(
            GENERATOR, "_attach_splitter_profiles",
            side_effect=lambda *args: order.append("profiles"),
        ):
            GENERATOR._validate_project_duplicates_and_profiles(devices, macs, prior)
        self.assertEqual(["duplicates", "profiles"], order)
        self.assertEqual([" earlier"], prior)

    def test_project_runtime_stage_skips_prior_errors_receipts_and_bad_vrl(self):
        devices = {
            "Receipt": {"source_yaml_b64": "YQ==", "vrl": True},
            "Leaf01": {"vrl": True, "vrfs": []},
        }
        prior = [" prior"]
        with mock.patch.object(GENERATOR, "_resolve_device_svi_vrr_support") as svi, \
                mock.patch.object(GENERATOR, "_resolve_device_dhcp_relays") as relay:
            GENERATOR._apply_project_device_runtime_fields(
                devices, {"vrl_render": {"imports": [], "vrfs": ["BLUE"]}},
                False, [], prior,
            )
        self.assertEqual([" prior"], prior)
        svi.assert_not_called()
        relay.assert_not_called()
        errors = []
        with mock.patch.object(GENERATOR, "_resolve_device_svi_vrr_support") as svi:
            GENERATOR._apply_project_device_runtime_fields(
                devices, {"vrl_render": {"imports": [], "vrfs": ["BLUE"]}},
                False, [], errors,
            )
        self.assertEqual(
            ["  Leaf01: vrl=true，但 01-global.yaml 未配置 vrl"], errors,
        )
        self.assertNotIn("svi_vrr_support", devices["Receipt"])
        svi.assert_not_called()
        errors = []
        GENERATOR._apply_project_device_runtime_fields(
            {"Leaf02": {"vrl": True, "vrfs": []}},
            {"vrl_render": {"imports": ["imp"], "vrfs": ["BLUE"]}},
            False, [], errors,
        )
        self.assertEqual(
            ["  Leaf02: vrl=true，但设备缺少参与 leaking 的 VRF：BLUE"], errors,
        )

    def test_project_runtime_stage_orders_svi_before_relay_and_preserves_error(self):
        device = {"vrl": False, "vrfs": []}
        errors = []
        with mock.patch.object(
            GENERATOR, "_resolve_device_svi_vrr_support", return_value={"mode": "native"},
        ) as svi, mock.patch.object(
            GENERATOR, "_resolve_device_dhcp_relays", return_value=[{"upstream": "BLUE"}],
        ) as relay:
            GENERATOR._apply_project_device_runtime_fields(
                {"Leaf01": device}, {}, True, ["server"], errors,
            )
        self.assertEqual({"mode": "native"}, device["svi_vrr_support"])
        self.assertEqual([{"upstream": "BLUE"}], device["dhcp_relays"])
        svi.assert_called_once_with(device, native_svi_link_mac=True)
        relay.assert_called_once_with(
            device, ["server"], native_svi_link_mac=True,
        )
        self.assertEqual([], errors)
        failed = {"vrl": False, "vrfs": []}
        with mock.patch.object(
            GENERATOR, "_resolve_device_svi_vrr_support", side_effect=ValueError("bad SVI"),
        ), mock.patch.object(GENERATOR, "_resolve_device_dhcp_relays") as relay:
            GENERATOR._apply_project_device_runtime_fields(
                {"Leaf02": failed}, {}, False, [], errors,
            )
        relay.assert_not_called()
        self.assertEqual(
            ["  Leaf02: SVI/VRR/DHCP relay 配置: bad SVI"], errors,
        )

    def test_csv_template_stage_keeps_precedence_and_fail_closed_errors(self):
        errors = []
        output = io.StringIO()
        with mock.patch.object(
            GENERATOR, "_best_template", return_value=("oobofoob-leaf.yaml.j2", True),
        ) as best, redirect_stdout(output):
            template = GENERATOR._resolve_device_csv_template(
                "Leaf01", "leaf", "oobofoob-leaf", "oobofoob-spine", errors,
            )
        self.assertEqual("oobofoob-leaf", template)
        self.assertEqual([], errors)
        best.assert_called_once_with("oobofoob-leaf", "Leaf01")
        self.assertIn("覆盖 devices_template 默认值", output.getvalue())
        missing = []
        with mock.patch.object(GENERATOR, "_best_template") as best:
            self.assertIsNone(GENERATOR._resolve_device_csv_template(
                "Leaf02", "leaf", "", None, missing,
            ))
        best.assert_not_called()
        self.assertEqual([
            "  Leaf02: type=leaf 必须在 devices_config.csv "
            "或 devices_template 中显式指定模板，已禁止按 hostname 自动猜测",
        ], missing)
        absent = []
        with mock.patch.object(
            GENERATOR, "_best_template", return_value=("near.yaml.j2", False),
        ):
            self.assertIsNone(GENERATOR._resolve_device_csv_template(
                "Leaf03", "leaf", "missing", None, absent,
            ))
        self.assertEqual(
            ["  Leaf03: 指定模板 'missing.yaml.j2' 不存在（最接近: near）"], absent,
        )

    def test_csv_initial_record_keeps_source_line_before_vrl_error(self):
        errors, lines = [], {}
        device = GENERATOR._new_device_csv_record(
            ["true"], "Leaf01", "oobofoob-leaf", 7, 2, 0, errors, lines,
        )
        self.assertEqual({
            "template": "oobofoob-leaf", "hostname": "Leaf01", "vrfs": [],
            "_project_schema_version": 2, "vrl": True,
        }, device)
        self.assertEqual({"Leaf01": 7}, lines)
        self.assertEqual([], errors)
        with mock.patch.object(
            GENERATOR, "_csv_vrl_enabled", side_effect=ValueError("bad vrl"),
        ):
            self.assertIsNone(GENERATOR._new_device_csv_record(
                ["invalid"], "Leaf02", "oobofoob-leaf", 8, 2, 0,
                errors, lines,
            ))
        self.assertEqual({"Leaf01": 7, "Leaf02": 8}, lines)
        self.assertEqual(["  Leaf02: bad vrl"], errors)

    def test_csv_bgp_stage_keeps_numeric_and_port_expansion(self):
        device, port_errors = {}, []
        with mock.patch.object(
            GENERATOR, "_csv_expand_ports", return_value=["swp1", "swp2"],
        ) as expand:
            GENERATOR._apply_device_csv_bgp_fields(
                ["65000", "swp1-2"], {"bgp_asn": 0, "bgp_ports": 1},
                "Leaf01", device, port_errors,
            )
        self.assertEqual({"bgp_asn": 65000, "bgp_neighbors": ["swp1", "swp2"]}, device)
        expand.assert_called_once_with("swp1-2", "Leaf01.bgp_ports", port_errors)
        empty = {}
        with mock.patch.object(GENERATOR, "_csv_expand_ports") as expand:
            GENERATOR._apply_device_csv_bgp_fields(
                ["NA", "NA"], {"bgp_asn": 0, "bgp_ports": 1},
                "Leaf02", empty, port_errors,
            )
        self.assertEqual({"bgp_asn": None}, empty)
        expand.assert_not_called()

    def test_project_device_error_stage_preserves_order_and_v1_odd_mlag(self):
        devices = {"Leaf01": {"hostname": "Leaf01"}}
        lines = {"Leaf01": 7}
        duplicates = [" duplicate"]
        ports = [" port"]
        with mock.patch.object(
            GENERATOR, "_collect_device_field_errors", return_value=[" field"],
        ) as fields:
            errors = GENERATOR._collect_project_device_errors(
                devices, 1, lines, ["Leaf01"], duplicates, ports,
            )
        fields.assert_called_once_with(devices, 1, lines)
        self.assertEqual(
            [" field", "  MLAG 设备数量为奇数 (1)，无法配对: ['Leaf01']",
             " duplicate", " port"], errors,
        )
        self.assertEqual([" duplicate"], duplicates)
        self.assertEqual([" port"], ports)
        with mock.patch.object(
            GENERATOR, "_collect_device_field_errors", return_value=[],
        ):
            self.assertEqual(
                [" duplicate", " port"],
                GENERATOR._collect_project_device_errors(
                    devices, 2, lines, ["Leaf01"], duplicates, ports,
                ),
            )

    def test_project_mlag_stage_preserves_v1_pair_fields_and_v2_errors(self):
        devices = {
            "Leaf01": {"bond_groups": [{"type": "mlagbond"}], "eth0_ip": "192.0.2.1/24"},
            "Leaf02": {"bond_groups": [{"type": "mlagbond"}], "eth0_ip": "192.0.2.2/24"},
            "Receipt": {"bond_groups": [{"type": "mlagbond"}],
                        "eth0_ip": "192.0.2.3/24", "source_yaml_b64": "YQ=="},
        }
        global_mlag = {"pairs": [{
            "system-mac": ["aa:00:00:00:00:01", "aa:00:00:00:00:02"],
            "shared-addresses": ["192.0.2.99"], "mac-address": ["aa:00:00:00:00:ff"],
        }], "priority": [100, 90]}
        self.assertEqual(
            ["Leaf01", "Leaf02"],
            GENERATOR._apply_project_mlag_attributes(devices, global_mlag, {}, 1, []),
        )
        self.assertEqual("192.0.2.2", devices["Leaf01"]["mlag_backup"])
        self.assertEqual("192.0.2.1", devices["Leaf02"]["mlag_backup"])
        self.assertEqual([100, 90], [devices[name]["mlag_priority"] for name in ("Leaf01", "Leaf02")])
        self.assertEqual("aa:00:00:00:00:02", devices["Leaf02"]["system_mac"])
        self.assertEqual("192.0.2.99", devices["Leaf01"]["mlag_shared_address"])
        self.assertEqual("aa:00:00:00:00:ff", devices["Leaf01"]["mlag_mac_address"])
        self.assertNotIn("mlag_backup", devices["Receipt"])
        errors = []
        with mock.patch.object(
            GENERATOR, "_apply_v2_mlag_attributes", side_effect=ValueError("bad MLAG"),
        ) as apply:
            hosts = GENERATOR._apply_project_mlag_attributes(
                devices, global_mlag, {"policy": "fixed"}, 2, errors,
            )
        self.assertEqual(["Leaf01", "Leaf02"], hosts)
        apply.assert_called_once_with(devices, global_mlag, {"policy": "fixed"})
        self.assertEqual(["  bad MLAG"], errors)

    def test_project_vrr_route_stage_is_fail_closed_and_ordered(self):
        devices, policy = {"Leaf01": {"vrfs": []}}, {"mode": "literal"}
        prior_errors = ["earlier parse failure"]
        with mock.patch.object(GENERATOR, "_apply_v2_vrr_policy") as vrr, \
                mock.patch.object(GENERATOR, "_assign_v2_border_default_routes") as route:
            GENERATOR._apply_project_v2_vrr_routes(devices, policy, prior_errors)
        vrr.assert_not_called()
        route.assert_not_called()
        with mock.patch.object(GENERATOR, "_apply_v2_vrr_policy") as vrr, \
                mock.patch.object(GENERATOR, "_assign_v2_border_default_routes") as route:
            GENERATOR._apply_project_v2_vrr_routes(devices, policy, [])
        vrr.assert_called_once_with(devices, policy)
        route.assert_called_once_with(devices)
        output = io.StringIO()
        with mock.patch.object(
            GENERATOR, "_apply_v2_vrr_policy", side_effect=ValueError("bad\nsecond"),
        ), mock.patch.object(
            GENERATOR, "_assign_v2_border_default_routes",
        ) as route, redirect_stdout(output), self.assertRaises(SystemExit) as stopped:
            GENERATOR._apply_project_v2_vrr_routes(devices, policy, [])
        self.assertEqual(1, stopped.exception.code)
        self.assertEqual(
            "[ERROR] 02-devices_config.csv 的 SVI/VRR 地址策略冲突：\n"
            "  bad\n  second\n", output.getvalue(),
        )
        route.assert_not_called()
        errors = []
        with mock.patch.object(GENERATOR, "_apply_v2_vrr_policy"), \
                mock.patch.object(
                    GENERATOR, "_assign_v2_border_default_routes",
                    side_effect=ValueError("route conflict"),
                ):
            GENERATOR._apply_project_v2_vrr_routes(devices, policy, errors)
        self.assertEqual(["  Border 默认路由推导失败：route conflict"], errors)

    def test_evpn_vrf_stage_preserves_order_failure_and_v1_backfill(self):
        ordinary = [{"tag": "ordinary"}]
        evpn = [{"tag": "evpn"}]
        built = [{"evpn_vrf": "BLUE", "l2vlans": []}]
        device, errors = {"vrfs": []}, []
        with mock.patch.object(
            GENERATOR, "_csv_collect_evpn_groups", return_value=evpn,
        ) as collect, mock.patch.object(
            GENERATOR, "_csv_build_vrfs_checked", return_value=built,
        ) as build:
            self.assertTrue(GENERATOR._apply_device_csv_vrfs(
                ["row"], 2, "tan-leaf", "Leaf01", 7, 2, 12, 9,
                ordinary, [{"type": "localbond"}], device, errors,
            ))
        collect.assert_called_once_with(
            ["row"], 2, "Leaf01", errors, base=12, width=9,
            schema_version=2, source_line=7,
        )
        self.assertEqual([*ordinary, *evpn], build.call_args.args[0])
        self.assertEqual(built, device["vrfs"])
        with mock.patch.object(
            GENERATOR, "_csv_collect_evpn_groups", return_value=None,
        ), mock.patch.object(GENERATOR, "_csv_build_vrfs_checked") as build:
            self.assertFalse(GENERATOR._apply_device_csv_vrfs(
                [], 2, "tan-leaf", "Leaf02", 8, 1, 0, 9,
                ordinary, [], {"vrfs": []}, [],
            ))
        build.assert_not_called()
        v1_vrfs = [{"l2vlans": [{
            "vlan_id": 100, "vlan_spec": "100", "svi_ip": "192.0.2.10/24",
        }]}]
        v1_device = {"vrfs": [], "svi_ip": ""}
        with mock.patch.object(
            GENERATOR, "_csv_collect_evpn_groups", return_value=[{"tag": "v1"}],
        ), mock.patch.object(
            GENERATOR, "_csv_build_vrfs_checked", return_value=v1_vrfs,
        ):
            self.assertTrue(GENERATOR._apply_device_csv_vrfs(
                [], 1, "oobofoob-leaf", "Leaf03", 9, 1, 0, 11,
                [], [], v1_device, [],
            ))
        self.assertEqual((100, "100", "192.0.2.10/24"), (
            v1_device["vlan_id"], v1_device["vlan_spec"],
            v1_device["svi_ip"],
        ))
        v1_existing = {"vrfs": [], "vlan_id": 200, "vlan_spec": "200",
                       "svi_ip": "203.0.113.1/24"}
        with mock.patch.object(
            GENERATOR, "_csv_collect_evpn_groups", return_value=[{"tag": "v1"}],
        ), mock.patch.object(
            GENERATOR, "_csv_build_vrfs_checked", return_value=v1_vrfs,
        ):
            self.assertTrue(GENERATOR._apply_device_csv_vrfs(
                [], 1, "oobofoob-leaf", "Leaf04", 10, 1, 0, 11,
                [], [], v1_existing, [],
            ))
        self.assertEqual((200, "200", "203.0.113.1/24"), (
            v1_existing["vlan_id"], v1_existing["vlan_spec"],
            v1_existing["svi_ip"],
        ))

    def test_bond_csv_stage_distinguishes_valid_stale_and_missing_pair(self):
        header = (
            fixture.BASE_HEADER + fixture.VLAN_HEADER * 2
            + fixture.FIXED_HEADER + fixture.EVPN_HEADER * 2
        )
        fixed = GENERATOR._device_csv_header_context(header, 2)["fixed"]
        row = [""] * len(header)
        row[fixed["bond_ports"]] = "bond1"
        row[fixed["bond_type"]] = "local"
        row[fixed["bond_mac"]] = "NA"
        row[fixed["peerlink_ports"]] = "swp49-50"
        device, errors, port_errors = {}, [], []
        groups = GENERATOR._parse_device_csv_bond_groups(
            row, fixed, 2, "tan-leaf", "Leaf01", 7,
            device, errors, port_errors,
        )
        self.assertEqual([], errors)
        self.assertEqual([], port_errors)
        self.assertEqual(1, len(groups))
        self.assertEqual("localbond", groups[0]["type"])
        self.assertEqual(groups, device["bond_groups"])
        self.assertEqual("swp49-50", device["peerlink_ports"])
        stale = row[:]
        stale[fixed["bond_ports"]] = "NA"
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual([], GENERATOR._parse_device_csv_bond_groups(
                stale, fixed, 2, "tan-leaf", "Leaf02", 8, {}, [], [],
            ))
        self.assertIn("bond_type 已填写", output.getvalue())
        missing = row[:]
        missing[fixed["bond_type"]] = "NA"
        failures = []
        self.assertIsNone(GENERATOR._parse_device_csv_bond_groups(
            missing, fixed, 2, "tan-leaf", "Leaf03", 9,
            {}, failures, [],
        ))
        self.assertIn("bond_ports 与 bond_type 必须同时填写", failures[-1])

    def test_v1_simple_vlan_stage_enforces_selector_and_vrr_pairing(self):
        row = [""] * 19
        row[13:19] = [
            "100", "192.0.2.10", "24", "192.0.2.11",
            "02:00:5e:00:01:64", "swp1-2",
        ]
        device, errors, port_errors = {}, [], []
        self.assertTrue(GENERATOR._apply_v1_simple_vlan_fields(
            row, "Leaf01", device, errors, port_errors,
        ))
        self.assertEqual([], errors)
        self.assertEqual([], port_errors)
        self.assertEqual((100, "100", [100]), (
            device["vlan_id"], device["vlan_spec"], device["vlan_ids"],
        ))
        self.assertEqual("192.0.2.10/24", device["svi_ip"])
        self.assertEqual("192.0.2.11/24", device["vrr_ip"])
        self.assertEqual("02:00:5e:00:01:64", device["vrr_mac"])
        self.assertEqual(["swp1", "swp2"], device["vlan_ports"])
        for replacements, fragment in (
            ({13: "100-101"}, "VLAN 范围"),
            ({17: ""}, "必须同时指定 vrr_mac"),
            ({14: "192.0.2.11"}, "svi_ip 与 vrr_ip 不能相同"),
        ):
            with self.subTest(replacements=replacements):
                bad = row[:]
                for index, value in replacements.items():
                    bad[index] = value
                messages = []
                self.assertFalse(GENERATOR._apply_v1_simple_vlan_fields(
                    bad, "Leaf01", {}, messages, [],
                ))
                self.assertIn(fragment, messages[-1])

    def test_v2_ordinary_vlan_stage_keeps_two_groups_and_rejects_partial_group(self):
        header = (
            fixture.BASE_HEADER + fixture.VLAN_HEADER * 2
            + fixture.FIXED_HEADER + fixture.EVPN_HEADER * 2
        )
        layout = GENERATOR._device_csv_header_context(header, 2)["layout"]
        row = [""] * len(header)
        first, second = layout.vlan_group_starts
        row[first:first + 4] = ["100/native", "192.0.2.10", "24", "swp1"]
        row[second:second + 4] = ["101-102", "", "", "swp2"]
        errors = []
        groups = GENERATOR._parse_v2_ordinary_vlan_groups(
            row, layout, "Leaf01", 7, errors,
        )
        self.assertEqual([], errors)
        self.assertEqual(2, len(groups))
        self.assertEqual((100, "192.0.2.10/24", True), (
            groups[0]["l2vlan"], groups[0]["svi_ip"], groups[0]["native"],
        ))
        self.assertEqual([101, 102], groups[1]["l2vlan_ids"])
        self.assertTrue(groups[1]["bridge_only"])
        self.assertEqual(
            [{"line": 7, "group": "普通 VLAN 组 1"},
             {"line": 7, "group": "普通 VLAN 组 2"}],
            [group["_csv_source"] for group in groups],
        )
        row[second:second + 4] = ["", "192.0.2.11", "24", "swp2"]
        self.assertIsNone(GENERATOR._parse_v2_ordinary_vlan_groups(
            row, layout, "Leaf01", 8, errors,
        ))
        self.assertIn("Leaf01: 普通 VLAN 组 2:", errors[-1])
        self.assertEqual([], GENERATOR._parse_v2_ordinary_vlan_groups(
            [""] * len(header), layout, "Leaf02", 9, [],
        ))

    def test_source_yaml_metadata_stage_accepts_literal_receipt_and_rejects_tampering(self):
        source = b"- set:\n    system:\n      hostname: Leaf01\n"
        encoded = base64.b64encode(source).decode("ascii")
        fields_hash = hashlib.sha256(
            b'["Leaf01","eth","tan-leaf"]'
        ).hexdigest()
        source_hash = hashlib.sha256(source).hexdigest()
        row = ["Leaf01", "eth", "tan-leaf", encoded,
               source_hash.upper(), fields_hash.upper()]
        context = {
            "source_yaml_col": 3,
            "source_sha256_col": 4,
            "source_fields_sha256_col": 5,
            "evpn_end": 3,
        }
        device, errors = {"hostname": "Leaf01"}, []
        self.assertIs(True, GENERATOR._apply_source_yaml_metadata(
            row, "Leaf01", device, context, errors,
        ))
        self.assertEqual([], errors)
        self.assertEqual({
            "hostname": "Leaf01",
            "source_yaml_b64": encoded,
            "source_yaml_sha256": source_hash,
            "source_fields_sha256": fields_hash,
        }, device)
        for changed, expected in (
            (row[:3] + ["NA", row[4], row[5]], None),
            (["Leaf01", "eth", "other-template", *row[3:]], False),
            (row[:4] + ["0" * 64, row[5]], False),
        ):
            with self.subTest(changed=changed[2:]):
                copy_device, copy_errors = {"hostname": "Leaf01"}, []
                self.assertIs(expected, GENERATOR._apply_source_yaml_metadata(
                    changed, "Leaf01", copy_device, context, copy_errors,
                ))
                self.assertEqual({"hostname": "Leaf01"}, copy_device)
                self.assertEqual(bool(expected is False), bool(copy_errors))

    def test_base_interface_csv_stage_preserves_addresses_and_mac_owners(self):
        row = [
            "Leaf01", "eth", "tan-leaf", "192.0.2.10", "24", "192.0.2.1",
            "AA:BB:CC:DD:EE:FF", "192.0.3.10", "25", "192.0.3.1",
            "AA:BB:CC:DD:EE:01", "198.51.100.10",
        ]
        device, mac_owners = {}, {}
        GENERATOR._populate_device_csv_interfaces(
            row, "Leaf01", device, mac_owners,
        )
        self.assertEqual({
            "eth0_ip": "192.0.2.10/24",
            "eth0_gw": "192.0.2.1",
            "has_eth1": True,
            "eth1_ip": "192.0.3.10/25",
            "eth1_gw": "192.0.3.1",
            "lo_ip": "198.51.100.10/32",
        }, device)
        self.assertEqual({
            "aa:bb:cc:dd:ee:ff": ["Leaf01"],
            "aa:bb:cc:dd:ee:01": ["Leaf01"],
        }, mac_owners)
        row[7], row[11] = "NA", "NA"
        no_eth1, no_eth1_mac_owners = {}, {}
        GENERATOR._populate_device_csv_interfaces(
            row, "Leaf02", no_eth1, no_eth1_mac_owners,
        )
        self.assertFalse(no_eth1["has_eth1"])
        self.assertNotIn("eth1_ip", no_eth1)
        self.assertNotIn("eth1_gw", no_eth1)
        self.assertEqual("NA", no_eth1["lo_ip"])
        self.assertEqual(["Leaf02"], no_eth1_mac_owners["aa:bb:cc:dd:ee:01"])

    def test_csv_header_context_and_row_triage_preserve_v2_contract(self):
        header = (
            fixture.BASE_HEADER + fixture.VLAN_HEADER * 2
            + fixture.FIXED_HEADER + fixture.EVPN_HEADER * 2
        )
        context = GENERATOR._device_csv_header_context(header, 2)
        self.assertEqual(2, len(context["layout"].vlan_group_starts))
        self.assertEqual(2, len(context["layout"].evpn_group_starts))
        self.assertEqual(1, context["type_col"])
        self.assertEqual(len(header), context["evpn_end"])
        self.assertEqual(None, context["source_yaml_col"])
        errors, skipped, owners = [], {}, {}
        row = ["  Leaf01  ", " ETH ", " tan-leaf "] + [""] * (len(header) - 3)
        parsed = GENERATOR._triage_device_csv_row(
            row, 2, len(header), 2, context["type_col"],
            errors, skipped, owners,
        )
        self.assertEqual(("eth", "Leaf01", "tan-leaf"), parsed[1:])
        self.assertEqual("Leaf01", parsed[0][0])
        self.assertEqual(len(header) + 47, len(parsed[0]))
        self.assertEqual({"leaf01": "Leaf01"}, owners)
        self.assertIsNone(GENERATOR._triage_device_csv_row(
            ["leaf01", "eth", "tan-leaf"] + [""] * (len(header) - 3),
            3, len(header), 2, context["type_col"], errors, skipped, owners,
        ))
        self.assertEqual("  重复 hostname: 'leaf01'", errors[-1])
        self.assertIsNone(GENERATOR._triage_device_csv_row(
            ["EXAMPLE-IB01", "ib"] + [""] * (len(header) - 2),
            4, len(header), 2, context["type_col"], errors, skipped, owners,
        ))
        self.assertEqual({}, skipped)  # IB is skipped, but not an excluded type.
        self.assertIsNone(GENERATOR._triage_device_csv_row(
            ["AIR-EXAMPLE-Leaf01", "air"] + [""] * (len(header) - 2),
            5, len(header), 2, context["type_col"], errors, skipped, owners,
        ))
        self.assertEqual({"air": 1}, skipped)
        self.assertIsNone(GENERATOR._triage_device_csv_row(
            ["TooShort", "eth"], 6, len(header), 2,
            context["type_col"], errors, skipped, owners,
        ))
        self.assertIn("第 6 行列数必须与 schema 2 表头完全一致", errors[-1])

    def test_csv_row_stage_keeps_explicit_source_receipt_before_interface_parse(self):
        header = (
            fixture.BASE_HEADER + fixture.VLAN_HEADER * 2
            + fixture.FIXED_HEADER + fixture.EVPN_HEADER * 2
        )
        context = GENERATOR._device_csv_header_context(header, 2)
        row = ["Leaf01", "eth", "tan-leaf"] + [""] * (len(header) - 3)
        devices, errors, ports, macs, lines, excluded, owners = (
            {}, [], [], {}, {}, {}, {},
        )
        receipt = {"hostname": "Leaf01", "template": "tan-leaf"}
        with mock.patch.object(
            GENERATOR, "_best_template", return_value=("tan-leaf.yaml.j2", True),
        ), mock.patch.object(
            GENERATOR, "_new_device_csv_record", return_value=receipt,
        ), mock.patch.object(
            GENERATOR, "_apply_source_yaml_metadata", return_value=True,
        ) as source, mock.patch.object(
            GENERATOR, "_populate_device_csv_interfaces",
        ) as interfaces:
            GENERATOR._ingest_device_csv_row(
                row, 2, len(header), 2, context, {}, devices,
                errors, ports, macs, lines, excluded, owners,
            )
        self.assertEqual({"Leaf01": receipt}, devices)
        self.assertEqual({"leaf01": "Leaf01"}, owners)
        self.assertEqual(([], [], {}, {}), (errors, ports, macs, excluded))
        source.assert_called_once()
        interfaces.assert_not_called()

    def test_all_fourteen_roles_share_management_interface_fragments(self):
        self.assertEqual(14, len(ROLE_NAMES))
        self.assertTrue(DHCP_CLIENT_ROLES.issubset(ROLE_NAMES))
        for fragment_name, token in (
            ("_management_eth0_static.yaml.j2", "      eth0:\n"),
            ("_management_eth0_dhcp.yaml.j2", "dhcp-client:"),
            ("_management_eth1.yaml.j2", "{% if d.has_eth1 %}"),
        ):
            fragment = TEMPLATES / fragment_name
            self.assertTrue(fragment.is_file(), fragment_name)
            self.assertIn(token, fragment.read_text(encoding="utf-8"))
        manifest = json.loads(
            (fixture.ROOT / "test_cases/script_test_manifest.json").read_text(
                encoding="utf-8"
            )
        )
        for fragment_name in (
            "_management_eth0_static.yaml.j2",
            "_management_eth0_dhcp.yaml.j2",
            "_management_eth1.yaml.j2",
        ):
            self.assertIn(
                "ztp/config/cumulus/template/03-templates-j2/" + fragment_name,
                manifest["tracked_support"],
            )
        for name in ROLE_NAMES:
            with self.subTest(role=name):
                source = (TEMPLATES / f"{name}.yaml.j2").read_text(
                    encoding="utf-8"
                )
                eth0_fragment = (
                    "_management_eth0_dhcp.yaml.j2"
                    if name in DHCP_CLIENT_ROLES
                    else "_management_eth0_static.yaml.j2"
                )
                self.assertEqual(
                    1, source.count(
                        "{% include '" + eth0_fragment + "' %}"
                    ),
                )
                self.assertEqual(
                    1, source.count(
                        "{% include '_management_eth1.yaml.j2' %}"
                    ),
                )
                self.assertNotIn("      eth0:\n", source)
                self.assertNotIn("      eth1:\n", source)

    def test_duplicate_phase_reports_cross_device_ip_without_publishing(self):
        devices = {
            "Alpha": {"eth0_ip": "192.0.2.5/24", "vrfs": []},
            "Beta": {"eth0_ip": "192.0.2.5/24", "vrfs": []},
        }
        errors = GENERATOR._collect_duplicate_value_errors(
            devices, {}, ["earlier parse failure"]
        )
        self.assertEqual(
            ["  重复 eth0_ip='192.0.2.5/24'：Alpha, Beta"], errors
        )

    def test_global_preparation_phase_preserves_v1_contract(self):
        global_data = {"_project_schema_version": 1, "version": "5.16.4"}
        with mock.patch.object(
            GENERATOR, "_load_devices_template", return_value={"leaf": "spine"},
        ), mock.patch.object(
            GENERATOR, "load_global", return_value=global_data,
        ), mock.patch.object(
            GENERATOR, "_cumulus_uses_native_svi_link_mac", return_value=True,
        ), mock.patch.object(
            GENERATOR, "_refresh_cumulus_defaults_from_global",
        ) as refresh, mock.patch.object(
            GENERATOR, "_normalize_dhcp_server_groups", return_value={"group": ["192.0.2.1"]},
        ), mock.patch.object(
            GENERATOR, "_normalize_vrl_config", return_value={"imports": []},
        ):
            result = GENERATOR._prepare_devices_generation_globals()
        self.assertEqual(
            ({"leaf": "spine"}, global_data, 1, True, None, None,
             {"group": ["192.0.2.1"]}), result,
        )
        self.assertEqual({"imports": []}, global_data["vrl_render"])
        refresh.assert_called_once_with()

    def test_global_preparation_phase_preserves_v2_policy_error(self):
        output = io.StringIO()
        with mock.patch.object(
            GENERATOR, "_load_devices_template", return_value={},
        ), mock.patch.object(
            GENERATOR, "load_global", return_value={"_project_schema_version": 2},
        ), mock.patch.object(
            GENERATOR, "_cumulus_uses_native_svi_link_mac", return_value=False,
        ), mock.patch.object(
            GENERATOR, "_normalize_v2_vrr_policy", side_effect=ValueError("bad VRR"),
        ), redirect_stdout(output):
            with self.assertRaises(SystemExit) as raised:
                GENERATOR._prepare_devices_generation_globals()
        self.assertEqual(1, raised.exception.code)
        self.assertEqual(
            "[ERROR] 01-global.yaml schema v2 配置无效：bad VRR\n",
            output.getvalue(),
        )

    def test_publication_phase_keeps_project_symlink_and_exact_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            actual = root / "project" / "91-devices.yaml"
            actual.parent.mkdir()
            actual.write_text("old document\n", encoding="utf-8")
            entry = root / "setup" / "91-devices.yaml"
            entry.parent.mkdir()
            entry.symlink_to(actual)
            with mock.patch.object(GENERATOR, "DEVICES_FILE", str(entry)):
                GENERATOR._publish_devices_yaml(
                    {"site": "example"}, {"leaf": {"hostname": "leaf"}},
                )
            self.assertTrue(entry.is_symlink())
            self.assertEqual(actual.resolve(), entry.resolve())
            self.assertEqual(
                b"global:\n  site: example\ndevices:\n  leaf:\n    hostname: leaf\n",
                actual.read_bytes(),
            )
            self.assertEqual([], list(actual.parent.glob("*.tmp.*")))


class H05H06RealWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with redirect_stdout(io.StringIO()):
            fixture.V2GenerationWorkflowTests.setUpClass()

    @classmethod
    def tearDownClass(cls):
        fixture.V2GenerationWorkflowTests.tearDownClass()

    def test_all_role_outputs_keep_exact_pre_refactor_bytes_with_and_without_eth1(self):
        self.assertEqual(14, len(ROLE_NAMES))
        environment = GENERATOR.build_env()
        digest = hashlib.sha256()
        for name in ROLE_NAMES:
            for eth1 in (False, True):
                with self.subTest(role=name, eth1=eth1):
                    device = copy.deepcopy(
                        fixture.V2GenerationWorkflowTests.generated_devices[
                            "EXAMPLE-NoVlan"
                        ]
                    )
                    device.update({
                        "hostname": "EXAMPLE-" + name,
                        "template": name,
                        "mlag_backup": "192.0.2.99",
                        "mlag_shared_address": "198.51.100.253",
                        "mlag_mac_address": "02:00:00:00:20:ff",
                        "mlag_priority": 100,
                        "system_mac": "02:00:00:00:20:01",
                        "has_eth1": eth1,
                        "eth1_ip": "192.0.2.2/24",
                        "eth1_gw": "192.0.2.1",
                    })
                    rendered = GENERATOR.render(
                        environment,
                        fixture.V2GenerationWorkflowTests.intermediate_document["global"],
                        device["hostname"],
                        device,
                    ).encode("utf-8")
                    label = f"{name}:{int(eth1)}".encode("utf-8")
                    digest.update(len(label).to_bytes(4, "big"))
                    digest.update(label)
                    digest.update(len(rendered).to_bytes(8, "big"))
                    digest.update(rendered)
        self.assertEqual(PRE_REFACTOR_ROLE_RENDER_SHA256, digest.hexdigest())

    def test_real_csv_to_intermediate_yaml_bytes_survive_phase_extraction(self):
        intermediate = fixture.V2GenerationWorkflowTests.intermediate
        self.assertEqual(14275, len(intermediate.read_bytes()))
        self.assertEqual(
            PRE_PHASE_EXTRACTION_DEVICES_YAML_SHA256,
            hashlib.sha256(intermediate.read_bytes()).hexdigest(),
        )

    def test_real_setup_load_dhcp_csv_triage_matches_published_eth_devices(self):
        source = fixture.V2GenerationWorkflowTests.devices_file
        with source.open(newline="", encoding="utf-8") as stream:
            reader = csv.reader(stream)
            header = next(reader)
            context = GENERATOR._device_csv_header_context(header, 2)
            errors, skipped, owners = [], {}, {}
            selected = []
            for lineno, raw in enumerate(reader, start=2):
                parsed = GENERATOR._triage_device_csv_row(
                    raw, lineno, len(header), 2, context["type_col"],
                    errors, skipped, owners,
                )
                if parsed is not None:
                    selected.append(parsed[2])
        self.assertEqual([], errors)
        self.assertNotIn("ib", skipped)
        self.assertEqual(1, skipped.get("air"))
        self.assertIn("EXAMPLE-Leaf01", selected)
        self.assertNotIn("EXAMPLE-IB01", selected)
        self.assertEqual(
            sorted(selected),
            sorted(fixture.V2GenerationWorkflowTests.generated_devices),
        )

    def test_real_csv_interface_stage_matches_published_leaf_fields(self):
        source = fixture.V2GenerationWorkflowTests.devices_file
        with source.open(newline="", encoding="utf-8") as stream:
            rows = list(csv.reader(stream))
        raw = next(row for row in rows[1:] if row[0] == "EXAMPLE-Leaf01")
        device, mac_owners = {}, {}
        GENERATOR._populate_device_csv_interfaces(
            raw, "EXAMPLE-Leaf01", device, mac_owners,
        )
        self.assertEqual("192.0.2.10/24", device["eth0_ip"])
        self.assertEqual("192.0.2.1", device["eth0_gw"])
        self.assertFalse(device["has_eth1"])
        self.assertEqual("192.0.2.210/32", device["lo_ip"])
        self.assertEqual(
            device,
            {key: fixture.V2GenerationWorkflowTests.generated_devices[
                "EXAMPLE-Leaf01"
            ][key] for key in device},
        )
        self.assertEqual(
            {"02:00:00:00:00:10": ["EXAMPLE-Leaf01"]}, mac_owners,
        )

    def test_real_v1_source_receipt_tamper_stops_before_yaml_publication(self):
        header = (
            fixture.BASE_HEADER
            + ["vrf_default", "vlan_id", "svi_ip", "netmask",
               "vrr_ip", "vrr_mac", "vlan_ports"]
            + fixture.FIXED_HEADER
            + ["evpn_vrf", "evpn_l3vni", "evpn_l3vlan", "dhcp_relay",
               "evpn_l2vni", "evpn_l2vlan", "svi_ip", "netmask",
               "vrr_ip", "vrr_mac", "vlan_ports"]
            + ["source_yaml_b64", "source_yaml_sha256", "source_fields_sha256"]
        )
        row = [
            "DeepLeaf01", "eth", "border", "192.0.2.70", "24",
            "192.0.2.1", "02:00:00:00:00:70", "NA", "NA", "NA",
            "NA", "198.51.100.70",
        ]
        row += [""] * (len(header) - 3 - len(row))
        source = b"- set:\n    system:\n      hostname: DeepLeaf01\n"
        row += [
            base64.b64encode(source).decode("ascii"),
            hashlib.sha256(source).hexdigest(),
            "0" * 64,  # Deliberately not the editable-field digest.
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            global_file = root / "01-global.yaml"
            csv_file = root / "02-devices_config.csv"
            output = root / "91-devices.yaml"
            global_file.write_text(yaml.safe_dump({
                **fixture.v2_mlag_preflight_global(), "schema_version": 1,
            }, sort_keys=False), encoding="utf-8")
            with csv_file.open("w", newline="", encoding="utf-8") as stream:
                csv.writer(stream).writerows([header, row])
            fixture.SETUP._validate_eth_csv(str(csv_file))
            console = io.StringIO()
            with mock.patch.multiple(
                GENERATOR,
                _CSV_FILE=str(csv_file), _GLOBAL_FILE=str(global_file),
                DEVICES_FILE=str(output), TEMPLATES_DIR=str(TEMPLATES),
            ), mock.patch.object(
                GENERATOR, "_refresh_cumulus_defaults_from_global",
            ), mock.patch.object(
                GENERATOR, "_apply_source_yaml_metadata",
                wraps=GENERATOR._apply_source_yaml_metadata,
            ) as stage, redirect_stdout(console), self.assertRaises(SystemExit):
                GENERATOR._generate_devices_yaml()
            self.assertEqual(1, stage.call_count)
            self.assertIn("CSV 可编辑字段已变化", console.getvalue())
            self.assertFalse(output.exists())

    def test_real_setup_load_dhcp_csv_vlan_groups_retain_literal_provenance(self):
        source = fixture.V2GenerationWorkflowTests.devices_file
        with source.open(newline="", encoding="utf-8") as stream:
            reader = csv.reader(stream)
            header = next(reader)
            selected = next(
                (lineno, row) for lineno, row in enumerate(reader, start=2)
                if row[0] == "EXAMPLE-Leaf01"
            )
        layout = GENERATOR._device_csv_header_context(header, 2)["layout"]
        errors = []
        groups = GENERATOR._parse_v2_ordinary_vlan_groups(
            selected[1], layout, "EXAMPLE-Leaf01", selected[0], errors,
        )
        self.assertEqual([], errors)
        self.assertEqual(2, len(groups))
        self.assertEqual((100, [100], True), (
            groups[0]["l2vlan"], groups[0]["l2vlan_ids"],
            groups[0]["native"],
        ))
        self.assertEqual([101, 102], groups[1]["l2vlan_ids"])
        self.assertEqual(
            ["普通 VLAN 组 1", "普通 VLAN 组 2"],
            [group["_csv_source"]["group"] for group in groups],
        )
        self.assertEqual(14275, len(
            fixture.V2GenerationWorkflowTests.intermediate.read_bytes()
        ))

    def test_real_v1_setup_load_generator_keeps_simple_vlan_fields(self):
        header = (
            fixture.BASE_HEADER
            + ["vrf_default", "vlan_id", "svi_ip", "netmask",
               "vrr_ip", "vrr_mac", "vlan_ports"]
            + fixture.FIXED_HEADER
            + ["evpn_vrf", "evpn_l3vni", "evpn_l3vlan", "dhcp_relay",
               "evpn_l2vni", "evpn_l2vlan", "svi_ip", "netmask",
               "vrr_ip", "vrr_mac", "vlan_ports"]
        )
        row = [
            "Leaf01", "eth", "oobofoob-leaf", "192.0.2.10", "24",
            "192.0.2.1", "02:00:00:00:00:10", "NA", "NA", "NA",
            "NA", "198.51.100.10", "", "100", "192.0.2.20", "24",
            "192.0.2.21", "02:00:5e:00:01:64", "swp1",
        ]
        row.extend(["NA"] * len(fixture.FIXED_HEADER))
        row.extend([""] * 11)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            global_file = root / "01-global.yaml"
            csv_file = root / "02-devices_config.csv"
            output = root / "91-devices.yaml"
            global_file.write_text(yaml.safe_dump({
                **fixture.v2_mlag_preflight_global(), "schema_version": 1,
            }, sort_keys=False), encoding="utf-8")
            with csv_file.open("w", newline="", encoding="utf-8") as stream:
                csv.writer(stream).writerows([header, row])
            fixture.SETUP._validate_eth_csv(str(csv_file))
            self.assertEqual(
                frozenset({"eth"}), fixture.LOAD.load_device_types(csv_file, 1),
            )
            with mock.patch.multiple(
                GENERATOR,
                _CSV_FILE=str(csv_file), _GLOBAL_FILE=str(global_file),
                DEVICES_FILE=str(output), TEMPLATES_DIR=str(TEMPLATES),
            ), mock.patch.object(
                GENERATOR, "_refresh_cumulus_defaults_from_global",
            ), mock.patch.object(
                GENERATOR, "_apply_v1_simple_vlan_fields",
                wraps=GENERATOR._apply_v1_simple_vlan_fields,
            ) as stage, redirect_stdout(io.StringIO()):
                GENERATOR._generate_devices_yaml()
            self.assertEqual(1, stage.call_count)
            parsed = yaml.safe_load(output.read_text(encoding="utf-8"))
            leaf = parsed["devices"]["Leaf01"]
            self.assertEqual(100, leaf["vlan_id"])
            self.assertEqual("192.0.2.20/24", leaf["svi_ip"])
            self.assertEqual("192.0.2.21/24", leaf["vrr_ip"])

    def test_real_setup_load_dhcp_csv_bond_stage_keeps_pair_modes(self):
        source = fixture.V2GenerationWorkflowTests.devices_file
        with source.open(newline="", encoding="utf-8") as stream:
            reader = csv.reader(stream)
            header = next(reader)
            leaf = next(row for row in reader if row[0] == "EXAMPLE-Leaf01")
        fixed = GENERATOR._device_csv_header_context(header, 2)["fixed"]
        device, errors, port_errors = {}, [], []
        groups = GENERATOR._parse_device_csv_bond_groups(
            leaf, fixed, 2, "tan-leaf", "EXAMPLE-Leaf01", 2,
            device, errors, port_errors,
        )
        self.assertEqual([], errors)
        self.assertEqual([], port_errors)
        self.assertEqual(2, len(groups))
        self.assertEqual(
            {"localbond", "evpn_multihoming"},
            {group["type"] for group in groups},
        )
        self.assertEqual(
            groups,
            fixture.V2GenerationWorkflowTests.generated_devices[
                "EXAMPLE-Leaf01"
            ]["bond_groups"],
        )
        self.assertEqual(
            PRE_PHASE_EXTRACTION_DEVICES_YAML_SHA256,
            hashlib.sha256(
                fixture.V2GenerationWorkflowTests.intermediate.read_bytes()
            ).hexdigest(),
        )

    def test_real_setup_load_dhcp_generator_calls_evpn_stage_without_byte_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "91-devices.yaml"
            with mock.patch.multiple(
                GENERATOR,
                _CSV_FILE=str(fixture.V2GenerationWorkflowTests.devices_file),
                _GLOBAL_FILE=str(fixture.V2GenerationWorkflowTests.global_file),
                DEVICES_FILE=str(output), TEMPLATES_DIR=str(TEMPLATES),
            ), mock.patch.object(
                GENERATOR, "_refresh_cumulus_defaults_from_global",
            ), mock.patch.object(
                GENERATOR, "_apply_device_csv_vrfs",
                wraps=GENERATOR._apply_device_csv_vrfs,
            ) as stage, redirect_stdout(io.StringIO()):
                GENERATOR._generate_devices_yaml()
            self.assertEqual(
                len(fixture.V2GenerationWorkflowTests.generated_devices),
                stage.call_count,
            )
            self.assertEqual(14275, len(output.read_bytes()))
            self.assertEqual(
                PRE_PHASE_EXTRACTION_DEVICES_YAML_SHA256,
                hashlib.sha256(output.read_bytes()).hexdigest(),
            )

    def test_real_setup_load_dhcp_generator_calls_vrr_route_phase_without_byte_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "91-devices.yaml"
            with mock.patch.multiple(
                GENERATOR,
                _CSV_FILE=str(fixture.V2GenerationWorkflowTests.devices_file),
                _GLOBAL_FILE=str(fixture.V2GenerationWorkflowTests.global_file),
                DEVICES_FILE=str(output), TEMPLATES_DIR=str(TEMPLATES),
            ), mock.patch.object(
                GENERATOR, "_refresh_cumulus_defaults_from_global",
            ), mock.patch.object(
                GENERATOR, "_apply_project_v2_vrr_routes",
                wraps=GENERATOR._apply_project_v2_vrr_routes,
            ) as stage, redirect_stdout(io.StringIO()):
                GENERATOR._generate_devices_yaml()
            self.assertEqual(1, stage.call_count)
            self.assertEqual(14275, len(output.read_bytes()))
            self.assertEqual(
                PRE_PHASE_EXTRACTION_DEVICES_YAML_SHA256,
                hashlib.sha256(output.read_bytes()).hexdigest(),
            )

    def test_real_setup_load_dhcp_generator_calls_mlag_phase_without_byte_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "91-devices.yaml"
            with mock.patch.multiple(
                GENERATOR,
                _CSV_FILE=str(fixture.V2GenerationWorkflowTests.devices_file),
                _GLOBAL_FILE=str(fixture.V2GenerationWorkflowTests.global_file),
                DEVICES_FILE=str(output), TEMPLATES_DIR=str(TEMPLATES),
            ), mock.patch.object(
                GENERATOR, "_refresh_cumulus_defaults_from_global",
            ), mock.patch.object(
                GENERATOR, "_apply_project_mlag_attributes",
                wraps=GENERATOR._apply_project_mlag_attributes,
            ) as stage, redirect_stdout(io.StringIO()):
                GENERATOR._generate_devices_yaml()
            self.assertEqual(1, stage.call_count)
            self.assertEqual(14275, len(output.read_bytes()))
            self.assertEqual(
                PRE_PHASE_EXTRACTION_DEVICES_YAML_SHA256,
                hashlib.sha256(output.read_bytes()).hexdigest(),
            )

    def test_real_setup_load_dhcp_generator_calls_final_validation_phase_without_byte_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "91-devices.yaml"
            with mock.patch.multiple(
                GENERATOR,
                _CSV_FILE=str(fixture.V2GenerationWorkflowTests.devices_file),
                _GLOBAL_FILE=str(fixture.V2GenerationWorkflowTests.global_file),
                DEVICES_FILE=str(output), TEMPLATES_DIR=str(TEMPLATES),
            ), mock.patch.object(
                GENERATOR, "_refresh_cumulus_defaults_from_global",
            ), mock.patch.object(
                GENERATOR, "_collect_project_device_errors",
                wraps=GENERATOR._collect_project_device_errors,
            ) as stage, redirect_stdout(io.StringIO()):
                GENERATOR._generate_devices_yaml()
            self.assertEqual(1, stage.call_count)
            self.assertEqual(14275, len(output.read_bytes()))
            self.assertEqual(
                PRE_PHASE_EXTRACTION_DEVICES_YAML_SHA256,
                hashlib.sha256(output.read_bytes()).hexdigest(),
            )

    def test_real_setup_load_dhcp_generator_calls_csv_identity_bgp_phases_without_byte_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "91-devices.yaml"
            with mock.patch.multiple(
                GENERATOR,
                _CSV_FILE=str(fixture.V2GenerationWorkflowTests.devices_file),
                _GLOBAL_FILE=str(fixture.V2GenerationWorkflowTests.global_file),
                DEVICES_FILE=str(output), TEMPLATES_DIR=str(TEMPLATES),
            ), mock.patch.object(
                GENERATOR, "_refresh_cumulus_defaults_from_global",
            ), mock.patch.object(
                GENERATOR, "_resolve_device_csv_template",
                wraps=GENERATOR._resolve_device_csv_template,
            ) as select, mock.patch.object(
                GENERATOR, "_new_device_csv_record",
                wraps=GENERATOR._new_device_csv_record,
            ) as initial, mock.patch.object(
                GENERATOR, "_apply_device_csv_bgp_fields",
                wraps=GENERATOR._apply_device_csv_bgp_fields,
            ) as bgp, redirect_stdout(io.StringIO()):
                GENERATOR._generate_devices_yaml()
            self.assertGreater(select.call_count, 0)
            self.assertGreater(initial.call_count, 0)
            self.assertGreater(bgp.call_count, 0)
            self.assertEqual(14275, len(output.read_bytes()))
            self.assertEqual(
                PRE_PHASE_EXTRACTION_DEVICES_YAML_SHA256,
                hashlib.sha256(output.read_bytes()).hexdigest(),
            )

    def test_real_setup_load_dhcp_generator_calls_project_runtime_phase_without_byte_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "91-devices.yaml"
            with mock.patch.multiple(
                GENERATOR,
                _CSV_FILE=str(fixture.V2GenerationWorkflowTests.devices_file),
                _GLOBAL_FILE=str(fixture.V2GenerationWorkflowTests.global_file),
                DEVICES_FILE=str(output), TEMPLATES_DIR=str(TEMPLATES),
            ), mock.patch.object(
                GENERATOR, "_refresh_cumulus_defaults_from_global",
            ), mock.patch.object(
                GENERATOR, "_apply_project_device_runtime_fields",
                wraps=GENERATOR._apply_project_device_runtime_fields,
            ) as stage, redirect_stdout(io.StringIO()):
                GENERATOR._generate_devices_yaml()
            self.assertEqual(1, stage.call_count)
            self.assertEqual(14275, len(output.read_bytes()))
            self.assertEqual(
                PRE_PHASE_EXTRACTION_DEVICES_YAML_SHA256,
                hashlib.sha256(output.read_bytes()).hexdigest(),
            )

    def test_real_setup_load_dhcp_generator_calls_duplicate_profile_gate_without_byte_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "91-devices.yaml"
            with mock.patch.multiple(
                GENERATOR,
                _CSV_FILE=str(fixture.V2GenerationWorkflowTests.devices_file),
                _GLOBAL_FILE=str(fixture.V2GenerationWorkflowTests.global_file),
                DEVICES_FILE=str(output), TEMPLATES_DIR=str(TEMPLATES),
            ), mock.patch.object(
                GENERATOR, "_refresh_cumulus_defaults_from_global",
            ), mock.patch.object(
                GENERATOR, "_validate_project_duplicates_and_profiles",
                wraps=GENERATOR._validate_project_duplicates_and_profiles,
            ) as stage, redirect_stdout(io.StringIO()):
                GENERATOR._generate_devices_yaml()
            self.assertEqual(1, stage.call_count)
            self.assertEqual(14275, len(output.read_bytes()))
            self.assertEqual(
                PRE_PHASE_EXTRACTION_DEVICES_YAML_SHA256,
                hashlib.sha256(output.read_bytes()).hexdigest(),
            )

    def test_real_setup_load_dhcp_generator_calls_csv_publication_boundary_without_byte_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "91-devices.yaml"
            with mock.patch.multiple(
                GENERATOR,
                _CSV_FILE=str(fixture.V2GenerationWorkflowTests.devices_file),
                _GLOBAL_FILE=str(fixture.V2GenerationWorkflowTests.global_file),
                DEVICES_FILE=str(output), TEMPLATES_DIR=str(TEMPLATES),
            ), mock.patch.object(
                GENERATOR, "_refresh_cumulus_defaults_from_global",
            ), mock.patch.object(
                GENERATOR, "_finalize_device_csv_publication",
                wraps=GENERATOR._finalize_device_csv_publication,
            ) as stage, redirect_stdout(io.StringIO()):
                GENERATOR._generate_devices_yaml()
            self.assertEqual(1, stage.call_count)
            self.assertEqual(14275, len(output.read_bytes()))
            self.assertEqual(
                PRE_PHASE_EXTRACTION_DEVICES_YAML_SHA256,
                hashlib.sha256(output.read_bytes()).hexdigest(),
            )

    def test_field_validation_phase_rejects_invalid_address_independently(self):
        device = copy.deepcopy(
            fixture.V2GenerationWorkflowTests.generated_devices["EXAMPLE-NoVlan"]
        )
        device["eth0_ip"] = "not-an-address"
        errors = GENERATOR._collect_device_field_errors(
            {"EXAMPLE-NoVlan": device}, 2, {"EXAMPLE-NoVlan": 7}
        )
        self.assertIn(
            "  EXAMPLE-NoVlan: eth0_ip='not-an-address'", errors
        )


if __name__ == "__main__":
    unittest.main()
