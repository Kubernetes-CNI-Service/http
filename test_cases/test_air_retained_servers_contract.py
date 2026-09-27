"""AIR retained-server contract from ISSUE-0013 and CODEX-0455 section 3.

The literal topology and expected endpoints are independent of the producer.
Both AIR writers run against real temporary DOT and JSON files.
"""

from contextlib import redirect_stdout
import io
import json
import linecache
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_cases.test_splitter_profile_breakout_workflow import P2P


ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "ztp/config/cumulus/template/P2P/01-inventory.log"
ZTP = "ztp-server"
BCM = "AIR-Rack-BCM-A"
UFM = "AIR-site-UfM-01"
LEAVES = {"AIR-OOB-Leaf01", "AIR-OOB-Leaf02", "AIR-OOB-Leaf03"}
FIXED_ZTP_MAC = "02:00:00:00:00:11"
SOURCE_EDGES = (
    ("OOB-Leaf01", "swp7", "demo-ztp-server", "BF-P1"),
    ("OOB-Leaf02", "swp8", "Rack-BCM-A", "eth1"),
    ("OOB-Leaf02", "swp10", "Rack-BCM-A", "mgmt0"),
    ("OOB-Leaf03", "swp9", "site-UfM-01", "enp9s0"),
    ("OOB-Core99", "swp1", "OOB-Leaf01", "swp2"),
)
EXPECTED_SERVER_LINKS = {
    frozenset((("AIR-OOB-Leaf01", "swp7"), (ZTP, "eth1"))),
    frozenset((("AIR-OOB-Leaf02", "swp8"), (BCM, "eth1"))),
    frozenset((("AIR-OOB-Leaf02", "swp10"), (BCM, "mgmt0"))),
    frozenset((("AIR-OOB-Leaf03", "swp9"), (UFM, "enp9s0"))),
}
EXPECTED_RETAINED_SOURCE_ENDPOINTS = {
    (BCM, "eth1"),
    (BCM, "mgmt0"),
    (UFM, "enp9s0"),
}


def _template():
    def prototype(os_name, model, *, mac=None):
        value = {"os": os_name, "labels": {"model": model},
                 "cpu": 2, "memory": 4096, "storage": 20}
        if mac is not None:
            value["management_interfaces"] = {
                "eth0": {"ip": "192.0.2.1", "mac_address": mac},
            }
        return value

    return {"content": {
        "nodes": {
            "OOB-Leaf": prototype("cumulus-vx-5.18.1", "SN2201"),
            "OOB-Core": prototype("cumulus-vx-5.18.1", "SN5610"),
            "ztp-server": prototype("generic/ubuntu2204", "SERVERTEST",
                                    mac=FIXED_ZTP_MAC),
            "bcm": prototype("generic/ubuntu2204", "SERVERTEST",
                             mac=FIXED_ZTP_MAC),
            "ufm": prototype("generic/ubuntu2204", "SERVERTEST",
                             mac=FIXED_ZTP_MAC),
        },
        "oob": {},
    }}


def _mini_policy():
    return {
        "node_allowlist": {}, "link_rewrites": [],
        "mini_sampling": {
            "location_prefix_regex": r"^(?P<logical>.+)$",
            "unknown_role_action": "exclude",
            "roles": [{
                "name": "oob-leaf",
                "hostname_regex": r"^OOB-Leaf(?P<index>\d+)$",
                "selection": {"mode": "indices", "capture_group": "index",
                              "indices": [1]},
            }],
        },
    }


class AirRetainedServersContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "lldpq.dot"
        self.air = self.root / "air.dot"
        self.air_json = self.root / "air.json"
        self.template = self.root / "air-template.json"
        self.source.write_text("\n".join(
            f'"{left}":"{left_port}" -- "{right}":"{right_port}"'
            for left, left_port, right, right_port in SOURCE_EDGES
        ) + "\n", encoding="utf-8")
        self.template.write_text(json.dumps(_template()), encoding="utf-8")
        self.patterns, self.order = P2P.load_inventory(INVENTORY)

    def produce(self, *, mini=False):
        policy = None
        if mini:
            policy_file = self.root / "03-air-topology-policy.json"
            policy_file.write_text(json.dumps(_mini_policy()), encoding="utf-8")
            policy = P2P.load_air_topology_policy(
                policy_file, project_root=self.root,
            )
        with redirect_stdout(io.StringIO()):
            P2P.generate_air_dot(
                self.source, self.air, self.patterns, self.order,
                template_file=self.template, air_topology_policy=policy,
                mini=mini,
                mini_devices_file=self.root / "customer-mini.txt" if mini else None,
            )
        return policy

    def json_document(self, policy=None):
        with redirect_stdout(io.StringIO()):
            P2P.generate_air_json(
                self.air, self.air_json, self.template,
                lldpq_file=self.source, air_topology_policy=policy,
            )
        return json.loads(self.air_json.read_text(encoding="utf-8"))

    @staticmethod
    def endpoint_links(document):
        return {
            frozenset((endpoint["node"], endpoint["interface"])
                      for endpoint in link)
            for link in document["content"]["links"]
            if all(isinstance(endpoint, dict) for endpoint in link)
        }

    def assert_servers_and_ports(self, document):
        nodes = document["content"]["nodes"]
        self.assertTrue({ZTP, BCM, UFM} <= set(nodes))
        self.assertEqual(3, len({ZTP.casefold(), BCM.casefold(), UFM.casefold()}))
        self.assertTrue(EXPECTED_SERVER_LINKS <= self.endpoint_links(document))
        self.assertEqual("generic/ubuntu2204", nodes[BCM]["os"])
        self.assertEqual("generic/ubuntu2204", nodes[UFM]["os"])
        ips = [nodes[name]["management_interfaces"]["eth0"]["ip"]
               for name in (ZTP, BCM, UFM)]
        macs = [nodes[name]["management_interfaces"]["eth0"]["mac_address"]
                for name in (ZTP, BCM, UFM)]
        self.assertTrue(all(ips))
        self.assertEqual(3, len(set(ips)))
        self.assertEqual(3, len(set(macs)))
        self.assertEqual(FIXED_ZTP_MAC, macs[0])
        self.assertNotIn(FIXED_ZTP_MAC, macs[1:])

    def assert_retained_original_endpoint_provenance(self, document):
        _nodes, dot_links = P2P._parse_air_dot(self.air)
        dot_connections = {
            frozenset(((left, left_port), (right, right_port)))
            for left, left_port, right, right_port in dot_links
        }
        dot_endpoints = {
            (name, interface)
            for left, left_port, right, right_port in dot_links
            for name, interface in ((left, left_port), (right, right_port))
        }
        json_endpoints = {
            (endpoint["node"], endpoint["interface"])
            for link in document["content"]["links"]
            for endpoint in link if isinstance(endpoint, dict)
        }
        self.assertTrue(EXPECTED_SERVER_LINKS <= dot_connections)
        self.assertTrue(EXPECTED_SERVER_LINKS <= self.endpoint_links(document))
        self.assertTrue(EXPECTED_RETAINED_SOURCE_ENDPOINTS <= dot_endpoints)
        self.assertTrue(EXPECTED_RETAINED_SOURCE_ENDPOINTS <= json_endpoints)
        self.assertNotIn((BCM, "BMC"), dot_endpoints)
        self.assertNotIn((BCM, "BMC"), json_endpoints)

    def test_retained_original_labels_match_dot_and_json(self):
        with self.source.open("a", encoding="utf-8") as stream:
            stream.write('"OOB-Leaf02":"swp11" -- "Rack-BCM-A":"BMC"\n')
        self.produce()
        self.assert_retained_original_endpoint_provenance(self.json_document())

    def test_full_air_dot_and_json_keep_distinct_server_endpoint_owners(self):
        self.produce()
        dot_nodes, dot_links = P2P._parse_air_dot(self.air)
        self.assertTrue({ZTP, BCM, UFM} <= {name for name, _ in dot_nodes})
        self.assertTrue(EXPECTED_SERVER_LINKS <= {
            frozenset(((left, left_port), (right, right_port)))
            for left, left_port, right, right_port in dot_links
        })
        self.assert_servers_and_ports(self.json_document())

    def test_retained_non_ztp_servers_inherit_owner_ztp_vm_tier(self):
        self.produce()
        nodes = self.json_document()["content"]["nodes"]
        for name in (BCM, UFM):
            with self.subTest(name=name):
                self.assertEqual(
                    {"cpu": 8, "memory": 8192, "storage": 80},
                    {field: nodes[name].get(field)
                     for field in ("cpu", "memory", "storage")},
                )

    def test_retained_bmc_dropped_from_dot_stays_out_of_json(self):
        with self.source.open("a", encoding="utf-8") as stream:
            stream.write('"OOB-Leaf02":"swp11" -- "Rack-BCM-A":"BMC"\n')
        self.produce()
        _nodes, dot_links = P2P._parse_air_dot(self.air)
        self.assertFalse(any(
            (left == BCM and left_port == "BMC")
            or (right == BCM and right_port == "BMC")
            for left, left_port, right, right_port in dot_links
        ))
        links = self.json_document()["content"]["links"]
        self.assertFalse(any(
            isinstance(endpoint, dict)
            and endpoint.get("node") == BCM
            and endpoint.get("interface") == "BMC"
            for link in links for endpoint in link
        ))
        self.assertTrue(any(
            {"node": "AIR-OOB-Leaf02", "interface": "swp11"}.items()
            <= endpoint.items()
            and "unconnected" in link
            for link in links for endpoint in link
            if isinstance(endpoint, dict)
        ))

    def test_mini_retains_servers_and_promotes_their_adjacent_switches(self):
        policy = self.produce(mini=True)
        report = json.loads((self.root / "air-mini-selection.json").read_text())
        minimum = set(report["minimum_required"])
        selected = set(report["selected"])
        missing = set(report["customer_missing_minimum"])
        self.assertEqual([], report["customer_provided"])
        self.assertTrue({ZTP, "Rack-BCM-A", "site-UfM-01"} <= minimum)
        self.assertTrue({"OOB-Leaf01", "OOB-Leaf02", "OOB-Leaf03"} <= minimum)
        self.assertEqual(minimum, selected)
        self.assertEqual(minimum, missing)
        self.assertNotIn("OOB-Core99", selected)
        by_hostname = {item["hostname"]: item for item in report["selection_reasons"]}
        for leaf in ("OOB-Leaf02", "OOB-Leaf03"):
            self.assertEqual("minimum retained-server adjacency",
                             by_hostname[leaf]["reason"])
        dot_nodes, _ = P2P._parse_air_dot(self.air)
        emitted = {name for name, _ in dot_nodes}
        self.assertTrue({ZTP, BCM, UFM} | LEAVES <= emitted)
        self.assertNotIn("AIR-OOB-Core99", emitted)
        self.assert_servers_and_ports(self.json_document(policy))

    def test_customer_ztp_entry_resolves_without_retained_alias_ambiguity(self):
        (self.root / "customer-mini.txt").write_text(
            "ztp-server\n", encoding="utf-8",
        )
        policy = self.produce(mini=True)
        report = json.loads((self.root / "air-mini-selection.json").read_text())
        self.assertEqual(["ztp-server"], report["customer_provided"])
        self.assertIn("ztp-server", report["selected"])
        self.assertTrue({"Rack-BCM-A", "site-UfM-01"}
                        <= set(report["minimum_required"]))
        self.assert_servers_and_ports(self.json_document(policy))

    def test_management_mac_collision_reaches_the_management_guard(self):
        self.produce()
        original = P2P._stable_air_mac

        def collide(namespace, node, interface):
            if (namespace == "management" and interface == "eth0"
                    and "bcm" in str(node).casefold()):
                return FIXED_ZTP_MAC
            return original(namespace, node, interface)

        with mock.patch.object(P2P, "_stable_air_mac", side_effect=collide):
            try:
                self.json_document()
            except ValueError as error:
                self.assertRegex(str(error), "duplicate generated AIR MAC")
                deepest = error.__traceback__
                while deepest.tb_next is not None:
                    deepest = deepest.tb_next
                self.assertEqual("generate_air_json", deepest.tb_frame.f_code.co_name)
                self.assertEqual(
                    'raise ValueError(f"duplicate generated AIR MAC: {management_mac}")',
                    linecache.getline(deepest.tb_frame.f_code.co_filename,
                                      deepest.tb_lineno).strip(),
                )
            else:
                self.fail("management MAC collision did not reach its guard")


if __name__ == "__main__":
    unittest.main()
