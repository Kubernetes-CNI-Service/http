#!/usr/bin/env python3
"""Independent D-75 UFM family schema tests; no real UFM operations."""

from __future__ import annotations

import copy
import csv
import datetime as dt
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_cases.module_loader import load_script
import yaml


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = load_script("ufm_input_contract_direct", ROOT / "tools/ufm_input_contract.py")
RUNTIME = load_script("ufm_dhcp_runtime_direct", ROOT / "ztp/dhcp_runtime_inventory.py")


def lease_block(address: str, mac: str, *, state: str = "active",
                end: str = "2030/01/01 00:00:00") -> str:
    return (
        f"lease {address} {{\n"
        "  starts 3 2026/09/23 00:00:00;\n"
        f"  ends 3 {end};\n"
        f"  binding state {state};\n"
        f"  hardware ethernet {mac};\n"
        "}\n"
    )


def valid_document() -> dict:
    return {
        "servers": [{"ufm": {
            "version": "2.5.1-8",
            "interfaces": {"alias": {"eth0": "eno8303", "eth1": "eno8403"}},
        }}],
        "switches": [{"eth": {"services": {"dhcp_relay": {
            "inband": {"server_group": {"servers": ["192.0.2.53"]}},
            "oob": {"server_group": {"servers": ["192.0.2.54"]}},
        }}}}],
    }


class UfmInputContractTests(unittest.TestCase):
    def test_immutable_csv_snapshot_parser_matches_path_parser_without_reread(self):
        document = valid_document()
        rows = (
            "hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac\n"
            "EXAMPLE-UFM01,ufm,NA,192.0.2.21,24,192.0.2.1,02:00:00:00:00:21\n"
            "EXAMPLE-UFM02,ufm,NA,192.0.2.22,24,192.0.2.1,02:00:00:00:00:22\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "02-devices_config.csv"
            path.write_text(rows, encoding="utf-8")
            self.assertEqual(CONTRACT.bind_ufm_inventory(document, path),
                             CONTRACT.bind_ufm_inventory_text(document, rows))
            path.write_text("modified on disk", encoding="utf-8")
            self.assertEqual(2, len(CONTRACT.bind_ufm_inventory_text(document, rows)))

    def test_single_ufm_has_no_ha_or_vip_default_and_can_discover_one_lease(self):
        document = valid_document()
        policy = document["servers"][0]["ufm"]
        policy.pop("version")  # Upgrade is a separate value-presence gate.
        policy["interfaces"]["alias"].pop("eth1")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "02-devices_config.csv"
            with path.open("w", newline="", encoding="utf-8") as stream:
                csv.writer(stream).writerows([
                    ("hostname", "type", "template", "eth0_ip", "netmask", "eth0_gw", "eth0_mac"),
                    ("EXAMPLE-UFM01", "ufm", "NA", "192.0.2.21", "24", "192.0.2.1", "02:00:00:00:00:21"),
                ])
            nodes = CONTRACT.bind_ufm_inventory(document, path)
            self.assertEqual(("EXAMPLE-UFM01",), tuple(node.hostname for node in nodes))
            observed = RUNTIME.bind_ufm_current_leases(
                nodes, lease_block("192.0.2.21", "02:00:00:00:00:21"),
                now=dt.datetime(2026, 9, 26, tzinfo=dt.timezone.utc),
            )
            self.assertEqual(("EXAMPLE-UFM01",), tuple(node.hostname for node in observed))
            policy["vip"] = "192.0.2.99"
            with self.assertRaises(CONTRACT.UfmInputError):
                CONTRACT.bind_ufm_inventory(document, path)

    def test_discovery_cli_emits_only_read_only_observation_or_no_product(self):
        script = ROOT / "tools/ufm-discover.py"
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            document = valid_document()
            document["servers"][0]["ufm"]["vip"] = "192.0.2.99"
            (project / "01-global.yaml").write_text(
                yaml.safe_dump(document), encoding="utf-8"
            )
            csv_path = project / "02-devices_config.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as stream:
                csv.writer(stream).writerows([
                    ("hostname", "type", "template", "eth0_ip", "netmask", "eth0_gw", "eth0_mac"),
                    ("EXAMPLE-UFM01", "ufm", "NA", "192.0.2.21", "24", "192.0.2.1", "02:00:00:00:00:21"),
                    ("EXAMPLE-UFM02", "ufm", "NA", "192.0.2.22", "24", "192.0.2.1", "02:00:00:00:00:22"),
                ])
            leases = project / "synthetic.leases"
            leases.write_text(
                lease_block("192.0.2.21", "02:00:00:00:00:21")
                + lease_block("192.0.2.22", "02:00:00:00:00:22"),
                encoding="utf-8",
            )
            command = [sys.executable, "-B", str(script), "--project", str(project),
                       "--leases", str(leases)]
            result = subprocess.run(command, text=True, capture_output=True, check=False)
            self.assertEqual(0, result.returncode, result.stderr)
            product = json.loads(result.stdout)
            self.assertEqual("discovery_only", product["phase"])
            self.assertEqual(True, product["ha_requested"])
            self.assertEqual(["EXAMPLE-UFM01", "EXAMPLE-UFM02"], [
                item["hostname"] for item in product["nodes"]
            ])
            self.assertFalse(product["ssh_identity_verified"])
            self.assertFalse(product["license_mac_verified"])
            self.assertFalse(product["vip_configured"])
            self.assertFalse(product["vip_live_verified"])
            self.assertFalse(product["vip_operator_approved"])
            self.assertFalse((project / "99-output-ufm").exists())
            leases.write_text(
                lease_block("192.0.2.21", "02:00:00:00:00:99")
                + lease_block("192.0.2.22", "02:00:00:00:00:22"),
                encoding="utf-8",
            )
            failed = subprocess.run(command, text=True, capture_output=True, check=False)
            self.assertNotEqual(0, failed.returncode)
            self.assertEqual("", failed.stdout, "failed discovery must publish no JSON")
            self.assertFalse((project / "99-output-ufm").exists())
            private = project / "SYNTHETIC-PRIVATE-PATH-TOKEN" / "missing.leases"
            redaction = subprocess.run(
                [*command[:-1], str(private)], text=True, capture_output=True,
                check=False,
            )
            self.assertNotEqual(0, redaction.returncode)
            self.assertEqual("", redaction.stdout)
            self.assertNotIn("SYNTHETIC-PRIVATE-PATH-TOKEN", redaction.stderr)

    def test_current_lease_authority_rejects_stale_reassigned_or_ambiguous_node(self):
        now = dt.datetime(2026, 9, 26, tzinfo=dt.timezone.utc)
        nodes = (
            CONTRACT.UfmNode("EXAMPLE-UFM01", "192.0.2.21", "02:00:00:00:00:21", "192.0.2.0/24"),
            CONTRACT.UfmNode("EXAMPLE-UFM02", "192.0.2.22", "02:00:00:00:00:22", "192.0.2.0/24"),
        )
        good = lease_block("192.0.2.21", nodes[0].management_mac) + lease_block(
            "192.0.2.22", nodes[1].management_mac
        )
        bound = RUNTIME.bind_ufm_current_leases(nodes, good, now=now)
        self.assertEqual(("EXAMPLE-UFM01", "EXAMPLE-UFM02"), tuple(
            item.hostname for item in bound
        ))
        self.assertEqual(("192.0.2.21", "192.0.2.22"), tuple(
            item.address for item in bound
        ))
        bad_sources = (
            lease_block("192.0.2.21", nodes[0].management_mac),
            lease_block("192.0.2.21", nodes[0].management_mac, end="2026/09/25 00:00:00")
            + lease_block("192.0.2.22", nodes[1].management_mac),
            good + lease_block("192.0.2.21", nodes[0].management_mac, state="free"),
            lease_block("192.0.2.21", nodes[1].management_mac)
            + lease_block("192.0.2.22", nodes[0].management_mac),
            good + lease_block("192.0.2.23", nodes[0].management_mac),
            good + "lease 192.0.2.21 {\n  binding state free;\n",
        )
        for lease_text in bad_sources:
            with self.subTest(lease_text=lease_text):
                with self.assertRaises(ValueError):
                    RUNTIME.bind_ufm_current_leases(nodes, lease_text, now=now)

    def test_two_node_vip_binding_uses_management_csv_subnets(self):
        document = valid_document()
        document["servers"][0]["ufm"]["vip"] = "192.0.2.99"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "02-devices_config.csv"
            with path.open("w", newline="", encoding="utf-8") as stream:
                csv.writer(stream).writerows([
                    ("hostname", "type", "template", "eth0_ip", "netmask", "eth0_gw", "eth0_mac"),
                    ("EXAMPLE-UFM02", "ufm", "NA", "192.0.2.22", "24", "192.0.2.1", "02:00:00:00:00:22"),
                    ("EXAMPLE-UFM01", "ufm", "NA", "192.0.2.21", "24", "192.0.2.1", "02:00:00:00:00:21"),
                ])
            nodes = CONTRACT.bind_ufm_inventory(document, path)
            self.assertEqual(("EXAMPLE-UFM01", "EXAMPLE-UFM02"), tuple(
                node.hostname for node in nodes
            ))
            self.assertEqual(("192.0.2.21", "192.0.2.22"), tuple(
                node.address for node in nodes
            ))
            document["servers"][0]["ufm"].pop("version")
            self.assertEqual(2, len(CONTRACT.bind_ufm_inventory(document, path)),
                             "absent version skips upgrade, not HA planning")
            for bad_vip in ("198.51.100.99", "192.0.2.21"):
                with self.subTest(vip=bad_vip):
                    document["servers"][0]["ufm"]["vip"] = bad_vip
                    with self.assertRaises(CONTRACT.UfmInputError):
                        CONTRACT.bind_ufm_inventory(document, path)

    def test_two_node_vip_default_is_only_an_unconfigured_candidate(self):
        document = valid_document()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "02-devices_config.csv"
            with path.open("w", newline="", encoding="utf-8") as stream:
                csv.writer(stream).writerows([
                    ("hostname", "type", "template", "eth0_ip", "netmask", "eth0_gw", "eth0_mac"),
                    ("EXAMPLE-UFM01", "ufm", "NA", "192.0.2.21", "24", "192.0.2.1", "02:00:00:00:00:21"),
                    ("EXAMPLE-UFM02", "ufm", "NA", "192.0.2.22", "24", "192.0.2.1", "02:00:00:00:00:22"),
                ])
            nodes = CONTRACT.bind_ufm_inventory(document, path)
            plan = CONTRACT.plan_ufm_vip(document, nodes)
            self.assertEqual("192.0.2.23", plan.candidate)
            self.assertEqual("derived", plan.source)
            self.assertFalse(plan.configured)
            document["servers"][0]["ufm"]["vip"] = "192.0.2.99"
            plan = CONTRACT.plan_ufm_vip(document, CONTRACT.bind_ufm_inventory(document, path))
            self.assertEqual("192.0.2.99", plan.candidate)
            self.assertEqual("declared", plan.source)
            self.assertFalse(plan.configured, "CSV intent cannot prove a live VIP")

    def test_two_node_vip_gateway_broadcast_and_subnet_conflicts_fail_closed(self):
        cases = (
            (("192.0.2.252", "192.0.2.253"), "192.0.2.1", None),
            (("192.0.2.253", "192.0.2.254"), "192.0.2.1", None),
            (("192.0.2.21", "192.0.2.22"), "192.0.2.23", None),
            (("192.0.2.21", "192.0.2.22"), "192.0.2.1", "192.0.2.1"),
            (("192.0.2.21", "192.0.2.22"), "192.0.2.1", "192.0.2.254"),
            (("192.0.2.21", "192.0.2.22"), "192.0.2.1", "192.0.2.255"),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "02-devices_config.csv"
            for addresses, gateway, vip in cases:
                with self.subTest(addresses=addresses, gateway=gateway, vip=vip):
                    document = valid_document()
                    if vip is not None:
                        document["servers"][0]["ufm"]["vip"] = vip
                    with path.open("w", newline="", encoding="utf-8") as stream:
                        csv.writer(stream).writerows([
                            ("hostname", "type", "template", "eth0_ip", "netmask", "eth0_gw", "eth0_mac"),
                            ("EXAMPLE-UFM01", "ufm", "NA", addresses[0], "24", gateway, "02:00:00:00:00:21"),
                            ("EXAMPLE-UFM02", "ufm", "NA", addresses[1], "24", gateway, "02:00:00:00:00:22"),
                        ])
                    with self.assertRaisesRegex(CONTRACT.UfmInputError, "vip"):
                        CONTRACT.bind_ufm_inventory(document, path)

    def test_two_node_vip_requires_same_management_subnet(self):
        document = valid_document()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "02-devices_config.csv"
            with path.open("w", newline="", encoding="utf-8") as stream:
                csv.writer(stream).writerows([
                    ("hostname", "type", "template", "eth0_ip", "netmask", "eth0_gw", "eth0_mac"),
                    ("EXAMPLE-UFM01", "ufm", "NA", "192.0.2.21", "24", "192.0.2.1", "02:00:00:00:00:21"),
                    ("EXAMPLE-UFM02", "ufm", "NA", "192.0.2.22", "25", "192.0.2.1", "02:00:00:00:00:22"),
                ])
            with self.assertRaisesRegex(CONTRACT.UfmInputError, "vip"):
                CONTRACT.bind_ufm_inventory(document, path)

    def test_missing_family_or_second_node_cannot_form_ha_plan(self):
        document = valid_document()
        document["servers"][0]["ufm"]["vip"] = "192.0.2.99"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "02-devices_config.csv"
            with path.open("w", newline="", encoding="utf-8") as stream:
                csv.writer(stream).writerows([
                    ("hostname", "type", "template", "eth0_ip", "netmask", "eth0_gw", "eth0_mac"),
                    ("EXAMPLE-UFM01", "ufm", "NA", "192.0.2.21", "24", "192.0.2.1", "02:00:00:00:00:21"),
                ])
            with self.assertRaises(CONTRACT.UfmInputError):
                CONTRACT.bind_ufm_inventory(document, path)
            without_family = copy.deepcopy(document)
            without_family.pop("servers")
            with self.assertRaises(CONTRACT.UfmInputError):
                CONTRACT.bind_ufm_inventory(without_family, path)

    def test_list_of_single_key_families_preserves_nested_server_groups(self):
        document = valid_document()
        before = copy.deepcopy(document)
        families = CONTRACT.parse_ufm_servers(document)
        self.assertEqual(["ufm"], list(families))
        self.assertEqual("2.5.1-8", families["ufm"]["version"])
        self.assertEqual(
            {"eth0": "eno8303", "eth1": "eno8403"},
            families["ufm"]["interfaces"]["alias"],
        )
        self.assertEqual(before, document, "schema parser must not rewrite intent")
        self.assertEqual(
            ["192.0.2.53"],
            document["switches"][0]["eth"]["services"]["dhcp_relay"]
            ["inband"]["server_group"]["servers"],
        )
        self.assertEqual(
            ["192.0.2.54"],
            document["switches"][0]["eth"]["services"]["dhcp_relay"]
            ["oob"]["server_group"]["servers"],
        )

    def test_mapping_shape_duplicate_family_and_numeric_version_fail_closed(self):
        invalids = []
        mapping = valid_document()
        mapping["servers"] = {"ufm": mapping["servers"][0]["ufm"]}
        invalids.append(mapping)
        duplicate = valid_document()
        duplicate["servers"].append(copy.deepcopy(duplicate["servers"][0]))
        invalids.append(duplicate)
        extra_family_key = valid_document()
        extra_family_key["servers"][0]["ordinary"] = {}
        invalids.append(extra_family_key)
        for version in (2, 2.5, True, [], {}):
            item = valid_document()
            item["servers"][0]["ufm"]["version"] = version
            invalids.append(item)
        for document in invalids:
            with self.subTest(servers=document["servers"]):
                with self.assertRaises(CONTRACT.UfmInputError):
                    CONTRACT.parse_ufm_servers(document)

    def test_alias_direction_conflicts_and_unbounded_service_paths_reject(self):
        invalid_alias = valid_document()
        invalid_alias["servers"][0]["ufm"]["interfaces"]["alias"] = {
            "eno8303": "eth0"
        }
        duplicate_target = valid_document()
        duplicate_target["servers"][0]["ufm"]["interfaces"]["alias"] = {
            "eth0": "eno8303", "eth1": "eno8303"
        }
        freeform_service = valid_document()
        freeform_service["servers"][0]["ufm"]["services"] = {
            "dns": "/tmp/arbitrary-target"
        }
        non_mapping_service = valid_document()
        non_mapping_service["servers"][0]["ufm"]["services"] = []
        for document in (
            invalid_alias, duplicate_target, freeform_service,
            non_mapping_service,
        ):
            with self.subTest(document=document):
                with self.assertRaises(CONTRACT.UfmInputError):
                    CONTRACT.parse_ufm_servers(document)

    def test_yaml_duplicate_key_is_rejected_before_family_interpretation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "01-global.yaml"
            path.write_text(
                "servers:\n"
                "  - ufm:\n"
                "      version: '2.5.1-8'\n"
                "      version: '2.5.1-9'\n"
                "      interfaces:\n"
                "        alias: {eth0: eno8303}\n",
                encoding="utf-8",
            )
            with self.assertRaises(CONTRACT.UfmInputError):
                CONTRACT.load_ufm_servers(path)


if __name__ == "__main__":
    unittest.main()
