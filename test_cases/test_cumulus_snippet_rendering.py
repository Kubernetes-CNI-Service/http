#!/usr/bin/env python3
"""Cumulus ifupdown2 snippet rendering and runtime-compare contracts."""

from __future__ import annotations

import copy
import importlib.util
from importlib.machinery import SourceFileLoader
from pathlib import Path
import re
import sys
import unittest

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
    "cumulus_snippet_generator_under_test",
    ROOT / "ztp/config/cumulus/template/90-c2-generate_configs.py",
)
MANUAL = load_script(
    "cumulus_snippet_manual_compare_under_test",
    ROOT / "ztp/manual-ztp.py",
)
FEEDBACK = load_script(
    "cumulus_svi_mac_feedback_under_test",
    ROOT / "ztp/optimize/feedback.py",
)

MAC = "02:00:00:00:00:13"
SNIPPET = f"hwaddress {MAC}\n"


def scenario_device() -> dict:
    return {
        "lo_ip": "203.0.113.13/32",
        "vrfs": [{
            "evpn_vrf": "Vrf_13",
            "evpn_l3vni": 13,
            "l2vlans": [{
                "vlan_id": 13,
                "svi_ip": "198.51.100.13/24",
                "vrr_ip": "",
                "vrr_mac": MAC,
                "dhcp_relay": False,
            }],
        }],
    }


def base_document() -> list[dict]:
    return [{"set": {"system": {"hostname": "EXAMPLE-Leaf13"}}}]


def inject_scenario(snippet: str = SNIPPET) -> list[dict]:
    document = base_document()
    support = GENERATOR._resolve_device_svi_vrr_support(scenario_device())
    support[0]["ifupdown_snippets"]["vlan13"] = snippet
    changed = GENERATOR._inject_dhcp_relay_support(
        document, {"svi_vrr_support": support},
    )
    if not changed:
        raise AssertionError("scenario-3 support was not injected")
    return document


class CumulusSnippetDirectTests(unittest.TestCase):
    def test_native_svi_link_mac_version_boundary(self):
        for version in ("5.18", "5.18.0", "5.19.1", "6.0"):
            with self.subTest(version=version):
                self.assertTrue(
                    GENERATOR._cumulus_uses_native_svi_link_mac(version),
                )
        for version in ("5.17.99", "5.16.4", "", None, "latest"):
            with self.subTest(version=version):
                self.assertFalse(
                    GENERATOR._cumulus_uses_native_svi_link_mac(version),
                )

    def test_scenario_three_resolves_exact_ifupdown2_hwaddress_text(self):
        support = GENERATOR._resolve_device_svi_vrr_support(scenario_device())
        self.assertEqual(1, len(support))
        self.assertEqual(
            {"vlan13": SNIPPET}, support[0]["ifupdown_snippets"],
        )
        self.assertEqual({}, support[0]["svi_link_macs"])

    def test_cumulus_518_renders_mac_under_svi_link(self):
        support = GENERATOR._resolve_device_svi_vrr_support(
            scenario_device(), native_svi_link_mac=True,
        )
        self.assertEqual({}, support[0]["ifupdown_snippets"])
        self.assertEqual(
            {"vlan13": MAC}, support[0]["svi_link_macs"],
        )
        document = [{"set": {
            "system": {"hostname": "EXAMPLE-Leaf13"},
            "interface": {"vlan13": {
                "type": "svi",
                "ipv4": {"address": {"198.51.100.13/24": {}}},
            }},
        }}]
        self.assertTrue(GENERATOR._inject_dhcp_relay_support(
            document, {"svi_vrr_support": support},
        ))
        block = document[0]["set"]
        self.assertEqual("svi", block["interface"]["vlan13"]["type"])
        self.assertEqual(
            MAC,
            block["interface"]["vlan13"]["link"]["mac-address"],
        )
        self.assertNotIn("config", block["system"])

    def test_feedback_reads_cumulus_518_svi_link_mac(self):
        svi = {
            "ipv4": {"address": {"198.51.100.13/24": {}}},
            "link": {"mac-address": MAC},
        }
        self.assertEqual(
            ("198.51.100.13", "24", FEEDBACK.NA, MAC),
            FEEDBACK.svi_vrr_info(svi, {"interface": {"vlan13": svi}}, 13),
        )

    def test_generated_yaml_uses_literal_block_and_round_trips_exactly(self):
        rendered = GENERATOR._dump_generated_yaml(inject_scenario())

        self.assertRegex(
            rendered,
            rf"(?m)^\s+vlan13: \|\n\s+hwaddress {re.escape(MAC)}$",
        )
        self.assertNotRegex(rendered, r"(?m)^\s+vlan13: '")
        parsed = yaml.safe_load(rendered)
        self.assertEqual(
            SNIPPET,
            parsed[0]["set"]["system"]["config"]["snippet"]
            ["ifupdown2_eni"]["vlan13"],
        )

    def test_multiline_snippet_preserves_line_order_and_trailing_newline(self):
        snippet = f"hwaddress {MAC}\nmtu 9216\n"
        rendered = GENERATOR._dump_generated_yaml(inject_scenario(snippet))

        self.assertRegex(
            rendered,
            rf"(?m)^\s+vlan13: \|\n"
            rf"\s+hwaddress {re.escape(MAC)}\n\s+mtu 9216$",
        )
        parsed = yaml.safe_load(rendered)
        self.assertEqual(
            snippet,
            parsed[0]["set"]["system"]["config"]["snippet"]
            ["ifupdown2_eni"]["vlan13"],
        )


class CumulusSnippetGenerateCompareWorkflowTests(unittest.TestCase):
    def test_literal_latest_matches_nv_show_quoted_multiline_scalar(self):
        generated_document = inject_scenario()
        latest_yaml = GENERATOR._dump_generated_yaml(generated_document)

        # ``nv config show`` can serialize the same scalar using PyYAML's
        # single-quoted multiline presentation.  YAML style is not state.
        current_document = [
            {"header": {"model": "vx", "nvue-api-version": "nvue_v1"}},
            copy.deepcopy(generated_document[0]),
        ]
        current_yaml = yaml.safe_dump(
            current_document, allow_unicode=True, sort_keys=False, width=120,
        )
        self.assertRegex(current_yaml, r"(?m)^\s+vlan13: '")

        latest = MANUAL.runtime_comparable_nvue_config(
            latest_yaml, label="latest literal snippet",
        )
        current = MANUAL.runtime_comparable_nvue_config(
            current_yaml, label="nv config show quoted snippet",
        )
        self.assertEqual(latest, current)

    def test_changed_hwaddress_remains_observable_runtime_drift(self):
        latest_yaml = GENERATOR._dump_generated_yaml(inject_scenario())
        current_document = inject_scenario(
            "hwaddress 02:00:00:00:00:14\n",
        )
        current_yaml = yaml.safe_dump(
            [{"header": {"model": "vx"}}, current_document[0]],
            allow_unicode=True,
            sort_keys=False,
            width=120,
        )

        latest_value = MANUAL.runtime_comparable_nvue_config(
            latest_yaml, label="latest snippet",
        )[0]
        current_value = MANUAL.runtime_comparable_nvue_config(
            current_yaml, label="changed nv config show snippet",
        )[0]
        self.assertEqual(
            ["system.config.snippet.ifupdown2_eni.vlan13"],
            MANUAL._changed_config_paths(current_value, latest_value),
        )


if __name__ == "__main__":
    unittest.main()
