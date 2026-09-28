#!/usr/bin/env python3
"""ISSUE-0007: role templates must not impose a link FEC or MTU."""

from pathlib import Path
import unittest

from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "ztp/config/cumulus/template/03-templates-j2"
GENERATOR = load_script(
    "issue0007_generator_direct",
    ROOT / "ztp/config/cumulus/template/90-c2-generate_configs.py",
)

# Independent owner-approved scope, not discovered from the templates under test.
TARGET_ROLES = (
    "border", "oob-core", "oob-leaf", "oob-su-leaf",
    "tan-cp-1gleaf", "tan-cp-leaf", "tan-hps-leaf", "tan-su-leaf",
)
BREAKOUT_ROLES = {
    "oob-core": 2, "tan-cp-leaf": 2, "tan-hps-leaf": 2,
    "tan-su-leaf": 2, "tan-leaf": 2, "oob-su-spine": 1,
    "tan-spine": 1,
}


class Issue0007RoleLinkDirectTests(unittest.TestCase):
    def test_eight_role_templates_remove_literal_fec_mtu_and_empty_links(self):
        for role in TARGET_ROLES:
            with self.subTest(role=role):
                source = (TEMPLATES / f"{role}.yaml.j2").read_text(
                    encoding="utf-8",
                )
                self.assertNotIn("fec: auto", source)
                self.assertNotIn("mtu: 9216", source)
                lines = source.splitlines()
                for index, line in enumerate(lines):
                    if line.strip() == "link:":
                        self.assertTrue(
                            index + 1 < len(lines)
                            and lines[index + 1].strip() == "breakout:",
                            f"{role}:{index + 1} has a link without breakout",
                        )
                GENERATOR.build_env().get_template(f"{role}.yaml.j2")

    def test_all_twelve_breakout_links_remain_explicit(self):
        for role, expected_count in BREAKOUT_ROLES.items():
            with self.subTest(role=role):
                source = (TEMPLATES / f"{role}.yaml.j2").read_text(
                    encoding="utf-8",
                )
                self.assertEqual(expected_count, source.count("        link:\n          breakout:"))
                self.assertEqual(expected_count, source.count("lanes-per-port:"))

    def test_real_generator_keeps_type_and_breakout_without_link_defaults(self):
        from test_cases.test_mlag_evpn_generation import border_globals
        from test_cases.test_qos_evpn_uplink_generation import oob_core_evpn_device

        device = oob_core_evpn_device()
        prepared = GENERATOR.preprocess_device(device)
        document = GENERATOR._load_generated_yaml(GENERATOR.render(
            GENERATOR.build_env(), border_globals(), device["hostname"],
            prepared,
        ))
        interfaces = GENERATOR._nvue_set_operations(document)[0]["interface"]
        self.assertEqual("bond", interfaces["bond15s4"]["type"])
        self.assertNotIn("link", interfaces["bond15s4"])
        self.assertEqual("swp", interfaces["swp15s4"]["type"])
        self.assertNotIn("link", interfaces["swp15s4"])
        self.assertEqual("swp", interfaces["swp15s0"]["type"])
        self.assertNotIn("link", interfaces["swp15s0"])
        self.assertEqual(
            {"8x": {"lanes-per-port": "1"}},
            interfaces["swp15"]["link"]["breakout"],
        )


if __name__ == "__main__":
    unittest.main()
