"""AIR's producer sentinels remain valid through real Cumulus YAML generation.

Literal oracle inputs are independent of the shared protocol constants. Invalid
link shapes and endpoints must fail before staging any output directory.
"""
from contextlib import redirect_stdout
import ast
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

import yaml

from test_cases.test_flow_release_platform_matrix import CUMULUS_GENERATOR as GENERATOR
from test_cases.test_splitter_profile_breakout_workflow import P2P
from test_cases.test_mlag_evpn_generation import border_globals
from tools import project_contract


class AirLinkEndpointDirectTests(unittest.TestCase):
    def test_script_loaders_restore_complete_import_path_after_nested_import(self):
        from test_cases.test_qos_evpn_uplink_generation import load_script as qos_load
        from test_cases.test_mlag_evpn_generation import load_script as mlag_load
        for loader in (qos_load, mlag_load):
            with self.subTest(loader=loader.__module__), tempfile.TemporaryDirectory() as directory:
                script = Path(directory) / "nested_import.py"
                script.write_text('import sys\nsys.path.insert(0, "nested-module-path")\n')
                before = sys.path[:]
                try:
                    loader("req14_import_isolation", script)
                    self.assertEqual(before, sys.path)
                finally:
                    sys.path[:] = before

    def test_both_scripts_import_one_shared_definition_for_each_literal(self):
        shared = ast.parse(Path(project_contract.__file__).read_text())
        for name, literal in (("AIR_UNCONNECTED_ENDPOINT", "unconnected"),
                              ("AIR_OUTBOUND_ENDPOINT", "outbound")):
            with self.subTest(name=name):
                definitions = [node for node in ast.walk(shared)
                               if isinstance(node, ast.Assign)
                               and any(isinstance(target, ast.Name) and target.id == name
                                       for target in node.targets)]
                self.assertEqual(1, len(definitions))
                self.assertEqual(literal, ast.literal_eval(definitions[0].value))
                self.assertEqual(1, sum(isinstance(node, ast.Constant) and node.value == literal
                                        for node in ast.walk(shared)))
                self.assertEqual(literal, getattr(project_contract, name))
                for module in (P2P, GENERATOR):
                    source = Path(module.__file__).read_text()
                    for quote in ('"', "'"):
                        self.assertNotIn(quote + literal + quote, source)
                    imports = [node for node in ast.walk(ast.parse(source))
                               if isinstance(node, ast.ImportFrom)
                               and node.module == "project_contract"
                               and any(alias.name == name and alias.asname in (None, name)
                                       for alias in node.names)]
                    self.assertEqual(1, len(imports))
                    self.assertEqual(literal, getattr(module, name))

    def test_exact_protocol_shapes_preserve_only_real_endpoints(self):
        endpoint = {"node": "AIR-fw-01", "interface": "swp7"}
        peer = {"node": "AIR-leaf-01", "interface": "swp48"}
        cases = [([endpoint, peer], [endpoint, peer])]
        for literal in ("unconnected", "outbound"):
            cases.extend((([endpoint, literal], [endpoint]),
                          ([literal, endpoint], [endpoint])))
        for link, expected in cases:
            with self.subTest(link=link):
                before = copy.deepcopy(link)
                self.assertEqual(expected, GENERATOR._air_link_real_endpoints(link, 0))
                self.assertEqual(before, link)

    def test_unknown_strings_types_and_incomplete_real_endpoints_are_rejected(self):
        endpoint = {"node": "AIR-fw-01", "interface": "swp7"}
        invalid = [[], [endpoint], [endpoint, endpoint, endpoint], {},
                   ["unconnected", "unconnected"], ["outbound", "outbound"],
                   ["unconnected", "outbound"], [endpoint, "UNCONNECTED"],
                   [endpoint, "unconnected "], [endpoint, "external"],
                   [endpoint, None], [endpoint, 0], [endpoint, True],
                   [endpoint, []], [{}, "unconnected"],
                   [{"node": "AIR-fw-01"}, "unconnected"],
                   [{"node": [], "interface": "swp7"}, "unconnected"],
                   [{"node": "AIR-fw-01", "interface": ""}, "unconnected"]]
        for key in ("node", "interface"):
            for value in ("", " ", "\t\n"):
                invalid.append([dict(endpoint, **{key: value}), "unconnected"])
        for link in invalid:
            with self.subTest(link=link), self.assertRaisesRegex(ValueError, "AIR JSON link"):
                GENERATOR._air_link_real_endpoints(link, 7)


class AirLinkEndpointWorkflowTests(unittest.TestCase):
    def fixture(self, root):
        service = root / "cumulus"
        template = service / "template"
        p2p = template / "P2P"
        p2p.mkdir(parents=True)
        global_file = template / "01-global.yaml"
        global_file.write_text(yaml.safe_dump(border_globals()))
        (service / "default.yaml").write_text(
            "- set:\n    system:\n      date-time:\n        timezone: Etc/UTC\n")
        (p2p / "p2p.xlsx").write_bytes(b"stem authority only; no workbook parsing here")
        output = p2p / "output-p2p"
        output.mkdir()
        air_dot = root / "fixture-air.dot"
        air_dot.write_text(
            'graph "fixture" {\n'
            '"AIR-fw-01" [os="cumulus-vx-5.18.1" template_node="fw"]\n'
            '"AIR-leaf-01" [os="cumulus-vx-5.18.1" template_node="leaf"]\n'
            '"ztp-server" [os="oob-mgmt-server" template_node="ztp-server"]\n'
            '"AIR-fw-01":"swp7" -- "AIR-leaf-01":"swp48"\n'
            '"AIR-leaf-01":"swp49" -- "ztp-server":"eth1"\n}\n')
        air_template = root / "template.json"
        air_template.write_text(json.dumps({"content": {
            "nodes": {
                "fw": {"os": "cumulus-vx-5.18.1", "labels": {"model": "FWTEST"}},
                "leaf": {"os": "cumulus-vx-5.18.1", "labels": {"model": "LEAFTEST"}},
                "ztp-server": {"os": "oob-mgmt-server", "labels": {"model": "SERVERTEST"}},
            },
            "model_port_profiles": {"FWTEST": ["swp7", "swp8"],
                                    "LEAFTEST": ["swp48", "swp49"],
                                    "SERVERTEST": ["eth0", "eth1"]},
            "links": [[{"node": "ztp-server", "interface": "eth0",
                        "mac": "02:00:00:00:00:11"}, "outbound"]],
            "oob": {},
        }}))
        air_json = output / "p2p-air.json"
        with redirect_stdout(io.StringIO()):
            P2P.generate_air_json(str(air_dot), str(air_json), str(air_template))
        sources = root / "production"
        sources.mkdir()
        bindings = dict(SCRIPT_DIR=str(template), _GLOBAL_FILE=str(global_file),
                        P2P_INPUT_DIR=str(p2p), P2P_OUTPUT_DIR=str(output))
        return air_json, sources, bindings

    def test_real_producer_unconnected_and_outbound_reach_baseline_interface_up(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            air_json, sources, bindings = self.fixture(root)
            links = json.loads(air_json.read_text())["content"]["links"]
            self.assertEqual(1, sum("unconnected" in link for link in links))
            self.assertEqual(1, sum("outbound" in link for link in links))
            output = root / "air"
            with mock.patch.multiple(GENERATOR, **bindings), redirect_stdout(io.StringIO()):
                GENERATOR.generate_air_hostname_configs(str(sources), str(output))
            document = yaml.safe_load((output / "AIR-fw-01.yaml").read_text())
            interfaces = {name: value for item in document
                          for name, value in item.get("set", {}).get("interface", {}).items()}
            self.assertEqual({"swp7", "swp8"}, set(interfaces))
            for config in interfaces.values():
                self.assertEqual({"link": {"state": {"up": {}}}, "type": "swp"}, config)
            self.assertFalse((output / "ztp-server.yaml").exists())

    def test_invalid_real_endpoint_rejected_before_output_staging(self):
        for interface in (None, "", "swp7-8"):
            with self.subTest(interface=interface), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                air_json, sources, bindings = self.fixture(root)
                document = json.loads(air_json.read_text())
                document["content"]["links"] = [[
                    {"node": "AIR-fw-01", "interface": interface}, "unconnected",
                ]]
                air_json.write_text(json.dumps(document))
                with mock.patch.multiple(GENERATOR, **bindings), self.assertRaises(ValueError), \
                        mock.patch.object(GENERATOR.os, "makedirs") as mkdir:
                    GENERATOR.generate_air_hostname_configs(str(sources), str(root / "air"))
                mkdir.assert_not_called()
                self.assertFalse((root / "air").exists())


if __name__ == "__main__":
    unittest.main()
