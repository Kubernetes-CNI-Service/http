#!/usr/bin/env python3
"""Cross-consumer inventory and LLDP identity contracts."""

from __future__ import annotations

import importlib.util
import ast
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "ztp/config/cumulus/template/P2P/01-inventory.log"
TOPOLOGY_RULES = ROOT / "ztp/config/topology_rules.py"
ALIASES = ROOT / "tools/lldp-analyze-tool/04-lldp-device-aliases.json"


def load_module(name: str, relative: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


CUMULUS = load_module(
    "topology_contract_cumulus",
    "ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py",
)
NVOS = load_module(
    "topology_contract_nvos",
    "ztp/config/nvos/template/P2P/p2p-to-validation.py",
)
LLDP = load_module(
    "topology_contract_lldp",
    "tools/lldp-analyze-tool/analyze_lldp.py",
)


class InventoryResolutionDirectTests(unittest.TestCase):
    LITERAL_EXPECTATIONS = {
        "PDU-01": "PDU",
        "gpusrv-GPU-01": "SMC-B300",
        "GPU-01": "GB300-GPU",
    }

    def test_shared_stdlib_resolver_exists(self):
        self.assertTrue(TOPOLOGY_RULES.is_file())
        source = TOPOLOGY_RULES.read_text(encoding="utf-8")
        imported_roots = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".", 1)[0])
        self.assertLessEqual(
            imported_roots,
            {"__future__", "dataclasses", "fnmatch", "pathlib", "typing"},
        )

    def test_shipped_inventory_preserves_pdu_and_places_specific_gpu_section_first(self):
        text = INVENTORY.read_text(encoding="utf-8")
        self.assertLess(text.index("[PDU]"), text.index("[Eth-SW]"))
        self.assertLess(text.index("[SMC-B300]"), text.index("[GB300-GPU]"))

    def test_cumulus_direct_literal_device_types(self):
        patterns, order = CUMULUS.load_inventory(INVENTORY)
        actual = {
            name: CUMULUS.get_device_type(name, patterns, order)
            for name in self.LITERAL_EXPECTATIONS
        }
        self.assertEqual(self.LITERAL_EXPECTATIONS, actual)

    def test_nvos_direct_literal_device_types(self):
        with tempfile.TemporaryDirectory() as directory:
            empty = Path(directory) / "empty.csv"
            empty.write_text("", encoding="utf-8")
            rules = NVOS.RuleSet(INVENTORY, empty, empty)
            actual = {
                name: rules.device_type(name)
                for name in self.LITERAL_EXPECTATIONS
            }
        self.assertEqual(self.LITERAL_EXPECTATIONS, actual)

    def test_lldp_direct_literal_device_types(self):
        patterns, order = LLDP.load_inventory(INVENTORY)
        actual = {
            name: LLDP.device_type(name, patterns, order)
            for name in self.LITERAL_EXPECTATIONS
        }
        self.assertEqual(self.LITERAL_EXPECTATIONS, actual)

    def test_section_first_not_longest_pattern_wins_in_every_consumer(self):
        inventory_text = "[broad]\n*GPU*\n\n[precise]\n*gpusrv*\n"
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            inventory = base / "inventory.log"
            empty = base / "empty.csv"
            inventory.write_text(inventory_text, encoding="utf-8")
            empty.write_text("", encoding="utf-8")

            c_patterns, c_order = CUMULUS.load_inventory(inventory)
            n_rules = NVOS.RuleSet(inventory, empty, empty)
            l_patterns, l_order = LLDP.load_inventory(inventory)
            results = {
                "cumulus": CUMULUS.get_device_type(
                    "gpusrv-GPU-01", c_patterns, c_order,
                ),
                "nvos": n_rules.device_type("gpusrv-GPU-01"),
                "lldp": LLDP.device_type(
                    "gpusrv-GPU-01", l_patterns, l_order,
                ),
            }
        self.assertEqual(
            {"cumulus": "broad", "nvos": "broad", "lldp": "broad"},
            results,
        )

    def test_shared_parser_accepts_bom_and_preserves_metadata_sections(self):
        topology = load_module("topology_contract_shared_bom", "ztp/config/topology_rules.py")
        with tempfile.TemporaryDirectory() as directory:
            inventory = Path(directory) / "inventory.log"
            inventory.write_text(
                "\ufeff[PDU]\n*PDU*\n\n[[ARM-CPU]]\n[ignored-meta]\n\n"
                "[SMC-B300]\n*gpusrv*\n",
                encoding="utf-8",
            )
            sections = topology.load_inventory_sections(inventory)
        self.assertEqual(["PDU", "SMC-B300"], [item.name for item in sections])
        self.assertEqual(
            "SMC-B300",
            topology.resolve_inventory_device_type("gpusrv-01", sections),
        )

    def test_shared_parser_rejects_ambiguous_or_malformed_inventory(self):
        topology = load_module("topology_contract_shared_invalid", "ztp/config/topology_rules.py")
        invalid_texts = (
            "*orphan*\n",
            "[broken\n*GPU*\n",
            "[GPU]\n*GPU*\n\n[gPu]\n*other*\n",
        )
        with tempfile.TemporaryDirectory() as directory:
            inventory = Path(directory) / "inventory.log"
            for text in invalid_texts:
                with self.subTest(text=text):
                    inventory.write_text(text, encoding="utf-8")
                    with self.assertRaises(ValueError):
                        topology.load_inventory_sections(inventory)

    def test_each_consumer_delegates_classification_to_shared_resolver(self):
        sentinel = "shared-result"
        with mock.patch.object(
            CUMULUS, "resolve_inventory_device_type", return_value=sentinel,
        ) as resolver:
            self.assertEqual(sentinel, CUMULUS.get_device_type("GPU-01", {}, []))
            resolver.assert_called_once()
        with tempfile.TemporaryDirectory() as directory:
            empty = Path(directory) / "empty.csv"
            empty.write_text("", encoding="utf-8")
            rules = NVOS.RuleSet(INVENTORY, empty, empty)
        with mock.patch.object(
            NVOS, "resolve_inventory_device_type", return_value=sentinel,
        ) as resolver:
            self.assertEqual(sentinel, rules.device_type("GPU-01"))
            resolver.assert_called_once()
        with mock.patch.object(
            LLDP, "resolve_inventory_device_type", return_value=sentinel,
        ) as resolver:
            self.assertEqual(sentinel, LLDP.device_type("GPU-01", {}, []))
            resolver.assert_called_once()

    def test_nvos_shipped_inventory_alias_resolves_to_cumulus_authority(self):
        nvos_inventory = ROOT / "ztp/config/nvos/template/P2P/01-inventory.log"
        self.assertTrue(nvos_inventory.is_symlink())
        self.assertEqual(
            INVENTORY.resolve(strict=True), nvos_inventory.resolve(strict=True),
        )
        manifest = json.loads(
            (ROOT / "test_cases/script_test_manifest.json").read_text(encoding="utf-8")
        )
        self.assertIn(nvos_inventory.relative_to(ROOT).as_posix(), manifest["tracked_support"])


class LldpIdentityDirectTests(unittest.TestCase):
    def test_exact_normalized_names_match(self):
        self.assertTrue(LLDP.device_names_match(" LEAF1. ", "leaf1"))
        self.assertTrue(LLDP.device_names_match("Leaf1.dc.example.", "leaf1.dc.example"))

    def test_actual_fqdn_may_match_expected_exact_short_name(self):
        self.assertTrue(LLDP.device_names_match("Leaf1.dc.example", "leaf1"))

    def test_substrings_and_different_fqdns_do_not_match(self):
        self.assertFalse(LLDP.device_names_match("Leaf11", "Leaf1"))
        self.assertFalse(LLDP.device_names_match("Leaf1", "Leaf11"))
        self.assertFalse(
            LLDP.device_names_match("leaf1.actual.example", "leaf1.expected.example")
        )
        self.assertFalse(LLDP.device_names_match("leaf1", "leaf1.expected.example"))

    def test_shipped_alias_authority_is_schema_one_empty_map(self):
        self.assertEqual(
            {"schema_version": 1, "canonical_to_aliases": {}},
            json.loads(ALIASES.read_text(encoding="utf-8")),
        )
        self.assertEqual({}, LLDP.load_device_aliases(ALIASES))

    def test_explicit_alias_allows_nonstandard_name(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "aliases.json"
            path.write_text(json.dumps({
                "schema_version": 1,
                "canonical_to_aliases": {"leaf1": ["rack-a-switch"]},
            }), encoding="utf-8")
            aliases = LLDP.load_device_aliases(path)
        self.assertTrue(
            LLDP.device_names_match("rack-a-switch", "leaf1", aliases)
        )
        self.assertFalse(
            LLDP.device_names_match("rack-a-switch-extra", "leaf1", aliases)
        )

    def test_alias_may_explicitly_authorize_short_actual_for_expected_fqdn(self):
        aliases = {
            "leaf1.expected.example": frozenset({"leaf1"}),
        }
        self.assertFalse(
            LLDP.device_names_match("leaf1", "leaf1.expected.example", {})
        )
        self.assertTrue(
            LLDP.device_names_match(
                "leaf1", "leaf1.expected.example", aliases,
            )
        )

    def test_alias_schema_fails_closed(self):
        invalid_payloads = (
            [],
            {"schema_version": True, "canonical_to_aliases": {}},
            {"schema_version": 2, "canonical_to_aliases": {}},
            {"schema_version": 1},
            {"schema_version": 1, "canonical_to_aliases": []},
            {"schema_version": 1, "canonical_to_aliases": {"": ["leaf-a"]}},
            {"schema_version": 1, "canonical_to_aliases": {"leaf1": "leaf-a"}},
            {"schema_version": 1, "canonical_to_aliases": {"leaf1": [1]}},
            {"schema_version": 1, "canonical_to_aliases": {"leaf1": [""]}},
            {"schema_version": 1, "canonical_to_aliases": {"...": ["leaf-a"]}},
            {"schema_version": 1, "canonical_to_aliases": {"leaf1": ["..."]}},
            {"schema_version": 1, "canonical_to_aliases": {"leaf1": ["LEAF1."]}},
            {"schema_version": 1, "canonical_to_aliases": {"leaf1": ["alias", "ALIAS."]}},
            {"schema_version": 1, "canonical_to_aliases": {}, "extra": True},
            {
                "schema_version": 1,
                "canonical_to_aliases": {
                    "leaf1": ["shared-name"],
                    "leaf2": ["SHARED-NAME."],
                },
            },
            {
                "schema_version": 1,
                "canonical_to_aliases": {
                    "leaf1": ["leaf2"],
                    "leaf2": ["rack-b-switch"],
                },
            },
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "aliases.json"
            for index, payload in enumerate(invalid_payloads):
                with self.subTest(index=index, payload=payload):
                    path.write_text(json.dumps(payload), encoding="utf-8")
                    with self.assertRaises(ValueError):
                        LLDP.load_device_aliases(path)
            path.write_text("{not-json", encoding="utf-8")
            with self.assertRaises(ValueError):
                LLDP.load_device_aliases(path)

    def test_alias_authority_must_be_one_regular_file_without_symlink_following(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            valid = base / "valid.json"
            valid.write_text(
                '{"schema_version":1,"canonical_to_aliases":{}}',
                encoding="utf-8",
            )
            symlink = base / "alias-link.json"
            symlink.symlink_to(valid.name)
            fifo = base / "alias.fifo"
            os.mkfifo(fifo)
            for path in (symlink, base, fifo):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    LLDP.load_device_aliases(path)

    def test_expected_peer_uses_alias_authority(self):
        state = LLDP.InterfaceState(
            name="swp1", admin="up", oper="up", speed="100G", kind="eth",
            remote_host="rack-a-switch", remote_port="swp2",
        )
        peer = LLDP.Endpoint("leaf1", "swp2")
        aliases = {"leaf1": frozenset({"rack-a-switch"})}
        self.assertTrue(LLDP.expected_peer_matches(state, peer, aliases))
        self.assertFalse(LLDP.expected_peer_matches(state, peer, {}))

    def test_analyze_link_threads_loaded_aliases_into_real_peer_decision(self):
        link = LLDP.ExpectedLink(
            LLDP.Endpoint("leaf1", "swp1"),
            LLDP.Endpoint("leaf2", "swp2"),
            7,
        )
        snapshots = {
            "leaf1": {
                "swp1": LLDP.InterfaceState(
                    "swp1", "up", "up", "100G", "eth",
                    "rack-b-switch", "swp2",
                ),
            },
            "leaf2": {
                "swp2": LLDP.InterfaceState(
                    "swp2", "up", "up", "100G", "eth",
                    "leaf1", "swp1",
                ),
            },
        }
        without_alias = LLDP.analyze_link(link, snapshots, {"leaf1", "leaf2"}, {})
        with_alias = LLDP.analyze_link(
            link,
            snapshots,
            {"leaf1", "leaf2"},
            {"leaf2": frozenset({"rack-b-switch"})},
        )
        self.assertEqual("WRONG_PEER", without_alias.status)
        self.assertEqual("CONFIRMED_BOTH_SIDE", with_alias.status)

    def test_local_snapshot_identity_keeps_fqdns_distinct_and_directional(self):
        self.assertNotEqual(
            LLDP.normalize_device("leaf1.actual.example"),
            LLDP.normalize_device("leaf1.expected.example"),
        )
        link = LLDP.ExpectedLink(
            LLDP.Endpoint("leaf1.expected.example", "swp1"),
            LLDP.Endpoint("server1", "eth0"),
            9,
        )
        state = LLDP.InterfaceState(
            "swp1", "up", "up", "100G", "eth", "server1", "eth0",
        )
        without_alias = LLDP.analyze_link(
            link,
            {"leaf1": {"swp1": state}},
            {"leaf1.expected.example"},
            {},
        )
        with_alias = LLDP.analyze_link(
            link,
            {"leaf1": {"swp1": state}},
            {"leaf1.expected.example"},
            {"leaf1.expected.example": frozenset({"leaf1"})},
        )
        actual_fqdn = LLDP.analyze_link(
            LLDP.ExpectedLink(
                LLDP.Endpoint("leaf1", "swp1"),
                LLDP.Endpoint("server1", "eth0"),
                10,
            ),
            {"leaf1.actual.example": {"swp1": state}},
            {"leaf1"},
            {},
        )
        self.assertEqual("MISSING_DEVICE", without_alias.status)
        self.assertEqual("CONFIRMED_SW_SIDE", with_alias.status)
        self.assertEqual("CONFIRMED_SW_SIDE", actual_fqdn.status)
        planned = {LLDP.canonical_link(link.left, link.right)}
        self.assertEqual(
            [],
            LLDP.unexpected_lldp(
                {"leaf1": {"swp1": state}},
                planned,
                aliases={"leaf1.expected.example": frozenset({"leaf1"})},
            ),
            "one confirmed alias-backed local port cannot also be unexpected",
        )

    def test_collected_fqdn_is_authoritative_switch_evidence_for_expected_short(self):
        link = LLDP.ExpectedLink(
            LLDP.Endpoint("custom1", "swp1"),
            LLDP.Endpoint("server1", "eth0"),
            11,
        )
        state = LLDP.InterfaceState(
            "swp1", "up", "up", "100G", "eth", "server1", "eth0",
        )
        result = LLDP.analyze_link(
            link,
            {"custom1.dc.example": {"swp1": state}},
            {"custom1.dc.example"},
            {},
        )
        self.assertIsNotNone(result)
        self.assertEqual("CONFIRMED_SW_SIDE", result.status)


class TopologyWorkflowTests(unittest.TestCase):
    def test_manifest_binds_shared_resolver_alias_and_four_script_workflow(self):
        manifest = json.loads(
            (ROOT / "test_cases/script_test_manifest.json").read_text(encoding="utf-8")
        )
        shared = "ztp/config/topology_rules.py"
        consumers = {
            "ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py",
            "ztp/config/nvos/template/P2P/p2p-to-validation.py",
            "tools/lldp-analyze-tool/analyze_lldp.py",
        }
        test_name = "test_cases.test_topology_consistency"
        self.assertEqual(shared, manifest["scripts"].get(shared))
        self.assertIn(
            "tools/lldp-analyze-tool/04-lldp-device-aliases.json",
            manifest["tracked_support"],
        )
        direct = [
            rule for rule in manifest["test_rules"]
            if shared in rule.get("paths", ())
        ]
        self.assertTrue(direct)
        self.assertTrue(any(test_name in rule.get("tests", ()) for rule in direct))
        for consumer in consumers:
            with self.subTest(direct_consumer=consumer):
                self.assertTrue(any(
                    consumer in rule.get("paths", ())
                    and test_name in rule.get("tests", ())
                    for rule in manifest["test_rules"]
                ))
        alias = "tools/lldp-analyze-tool/04-lldp-device-aliases.json"
        self.assertTrue(any(
            alias in rule.get("paths", ())
            and test_name in rule.get("tests", ())
            for rule in manifest["path_rules"]
        ))
        workflows = [
            workflow for workflow in manifest["workflows"]
            if {shared, *consumers}.issubset(set(workflow.get("members", ())))
        ]
        self.assertTrue(workflows)
        self.assertTrue(any(test_name in item.get("tests", ()) for item in workflows))
    def test_each_real_entrypoint_imports_shared_rules_outside_repo_cwd(self):
        scripts = (
            ROOT / "ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py",
            ROOT / "ztp/config/nvos/template/P2P/p2p-to-validation.py",
            ROOT / "tools/lldp-analyze-tool/analyze_lldp.py",
        )
        with tempfile.TemporaryDirectory() as directory:
            for script in scripts:
                with self.subTest(script=script):
                    completed = subprocess.run(
                        [sys.executable, "-B", os.fspath(script), "--help"],
                        cwd=directory,
                        text=True,
                        capture_output=True,
                        check=False,
                        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                    )
                    self.assertEqual(
                        0, completed.returncode,
                        completed.stderr or completed.stdout,
                    )

    def test_air_generation_excludes_literal_pdu_node(self):
        patterns, order = CUMULUS.load_inventory(INVENTORY)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "expected-lldpq.dot"
            output = base / "air.dot"
            source.write_text(
                '"OOB-Core-PDU-01":"eth0" -- "OOB-Leaf01":"swp1"\n',
                encoding="utf-8",
            )
            CUMULUS.generate_air_dot(
                source,
                output,
                patterns,
                order,
                template_file=CUMULUS.AIR_JSON_TEMPLATE,
            )
            rendered = output.read_text(encoding="utf-8")
        self.assertNotIn("AIR-OOB-Core-PDU-01", rendered)
        self.assertIn("AIR-OOB-Leaf01", rendered)
        self.assertIn("swp1", rendered)

    def test_analyzer_cli_defaults_alias_authority_and_rejects_invalid_before_archive(self):
        parsed = LLDP.parse_args([])
        self.assertEqual(ALIASES, parsed.device_aliases)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for name in ("expected.dot", "capture.tar.gz", "inventory.log"):
                (base / name).write_text("placeholder\n", encoding="utf-8")
            invalid = base / "aliases.json"
            invalid.write_text("[]", encoding="utf-8")
            completed = subprocess.run(
                [
                    sys.executable, "-B",
                    os.fspath(ROOT / "tools/lldp-analyze-tool/analyze_lldp.py"),
                    "--dot", os.fspath(base / "expected.dot"),
                    "--archive", os.fspath(base / "capture.tar.gz"),
                    "--inventory", os.fspath(base / "inventory.log"),
                    "--device-aliases", os.fspath(invalid),
                ],
                cwd=directory, text=True, capture_output=True, check=False,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            )
        self.assertEqual(2, completed.returncode)
        self.assertIn("alias", completed.stderr.casefold())
        self.assertNotIn("tar", completed.stderr.casefold())

    def test_one_inventory_authority_drives_all_three_real_consumers(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            inventory = base / "01-inventory.log"
            empty = base / "empty.csv"
            inventory.write_text(
                "[PDU]\n*PDU*\n\n"
                "[SMC-B300]\n*gpusrv*\n\n"
                "[GB300-GPU]\n*GPU*\n",
                encoding="utf-8",
            )
            empty.write_text("", encoding="utf-8")
            c_patterns, c_order = CUMULUS.load_inventory(inventory)
            n_rules = NVOS.RuleSet(inventory, empty, empty)
            l_patterns, l_order = LLDP.load_inventory(inventory)
            for hostname, expected in InventoryResolutionDirectTests.LITERAL_EXPECTATIONS.items():
                with self.subTest(hostname=hostname):
                    self.assertEqual(
                        [expected, expected, expected],
                        [
                            CUMULUS.get_device_type(hostname, c_patterns, c_order),
                            n_rules.device_type(hostname),
                            LLDP.device_type(hostname, l_patterns, l_order),
                        ],
                    )


if __name__ == "__main__":
    unittest.main()
