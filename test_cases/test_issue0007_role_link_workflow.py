#!/usr/bin/env python3
"""ISSUE-0007 generation through the real Cumulus YAML publisher."""

from pathlib import Path
import tempfile
import unittest

from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
GENERATOR = load_script(
    "issue0007_generator_workflow",
    ROOT / "ztp/config/cumulus/template/90-c2-generate_configs.py",
)
PUBLISHER = load_script(
    "issue0007_publisher_workflow",
    ROOT / "ztp/config/cumulus/d-hostname2mac.py",
)


class Issue0007RoleLinkWorkflowTests(unittest.TestCase):
    def test_generated_role_yaml_publishes_without_forced_link_defaults(self):
        from test_cases.test_mlag_evpn_generation import border_globals
        from test_cases.test_qos_evpn_uplink_generation import oob_core_evpn_device

        device = oob_core_evpn_device()
        prepared = GENERATOR.preprocess_device(device)
        global_vars = border_globals()
        global_vars["bridge"]["domain"]["br_default"]["stp"]["state"] = "enabled"
        rendered = GENERATOR.render(
            GENERATOR.build_env(), global_vars, device["hostname"],
            prepared,
        )
        identity = {
            "hostname": device["hostname"], "dev_type": "eth",
            "eth0_mac": "02:00:00:00:00:70", "eth1_mac": "",
            "eth0_ip_cidr": device["eth0_ip"],
            "eth0_gw": device["eth0_gw"],
        }
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / f"{device['hostname']}.yaml").write_text(
                rendered, encoding="utf-8",
            )
            ok, counters, hosts = PUBLISHER._process_yaml_files(
                directory, {device["hostname"].lower(): identity}, {"eth"},
            )
            self.assertTrue(ok, counters)
            self.assertEqual({device["hostname"].lower()}, hosts)
            published = output / f"{identity['eth0_mac'].replace(':', '')}.yaml"
            self.assertTrue(published.is_file())
            valid, document, diagnostic = PUBLISHER.validate_yaml(published)
            self.assertTrue(valid, diagnostic)
            interfaces = GENERATOR._nvue_set_operations(document)[0]["interface"]
            for name in ("bond15s4", "swp15s4", "swp15s0"):
                with self.subTest(name=name):
                    self.assertNotIn("link", interfaces[name])
            self.assertEqual(
                {"8x": {"lanes-per-port": "1"}},
                interfaces["swp15"]["link"]["breakout"],
            )


if __name__ == "__main__":
    unittest.main()
