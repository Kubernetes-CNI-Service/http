"""Direct tests: v15 OOB Spine candidate selection, kept on the merged initial-setup.

What: the read-only building blocks v15 added in front of the unchanged IB pipeline -- the Spine
inventory role hint, LLDP candidates from the real `nv show interface` columns, the target VLAN's
real SVI, the SVI address gates, the strict `ip -j address show` parser and allowlist, and the
Spine-side ND/EUI-64 neighbour choice.  No transport, no device, no worker.

Expectation sources (not derived from the implementation):
- v15 design `参考/initial-setup-v15/V15-OOB-SPINE.md` (cited per test: :25-27 Spine role hint and
  --oob-spines, :64-67 LLDP columns / short names / dedupe / CSV-only Spines, :69-72 real SVI, own
  IPv4, usable link-local, UP, VRR macvlan never substitutes, :99 the one new read-only remote
  command) and `参考/initial-setup-v15/CURRENT-CONTRACT.md` :30-38 (Jump selection rules 1-5);
  guide WP-7 table 7-1 (v3.1.3 guide :829) and the module table (:851).
- The v15 delivered test `initial-setup-v15-test-cases/test_v15_oob_spine.py::CandidateDirectTests`
  (:80-188), whose bytes are bound by `HANDOFF-SHA256SUMS:62`.  Its
  `test_existing_ib_command_and_authentication_functions_are_unchanged` (:88-98, the v14/v15 AST
  identity check) is not moved: after the merge it must fail and later releases change those
  functions (guide :834).

Fixture rewrites: none of the v15 literals needed a change for the public audit (its addresses are
documentation ranges and its MACs are 02:00:00:...); the module loads the merged
`infiniband/bringup/xdr-initial-setup/initial-setup.py` instead of the v15 delivery file.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
INITIAL = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
app = load_script("initial_setup_v15_oob_spine", INITIAL)

MAC1 = "02:00:00:00:00:10"
MAC2 = "02:00:00:00:00:12"


def device(host, ip="198.51.100.10", kind="eth_jump"):
    return app.Device(host, kind, ip, "", "", "", "", "")


def target(number=1, leaf=None):
    mac = MAC1 if number == 1 else MAC2
    ib = app.Device("ib%02d.example.test" % number, "ib", "192.0.2.%d" % (number + 10),
                    "192.0.2.%d/24" % (number + 10), "192.0.2.1", mac, "", "")
    return app.Target(ib, leaf or device("oob-leaf01"), "swp%d" % number, "eth0")


def interface_table(peers=(), ports=(1, 2)):
    header = ["Interface", "Admin Status", "Oper Status", "Speed", "MTU", "Type",
              "Remote Host", "Remote Port", "Summary"]
    widths = [16, 15, 15, 8, 8, 12, 38, 18, 12]

    def row(values):
        return "".join(str(value).ljust(width) for value, width in zip(values, widths)).rstrip()
    rows = [row(header), row(["-" * (n - 2) for n in widths])]
    rows += [row(["swp%d" % p, "up", "up", "1G", "9216", "swp", "nvos", "eth0", ""]) for p in ports]
    for p, peer, oper in peers:
        rows.append(row([p, "up", oper, "100G", "9216", "swp", peer, "swp1", ""]))
    return "\n".join(rows) + "\n"


def links(with_svi=True, vlan=1000, bridge="br_default"):
    value = ("1: br_default: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9216 state UP\n"
             "    bridge forward_delay 1500\n"
             "2: swp1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9216 master br_default state UP\n"
             "3: swp2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9216 master br_default state UP\n")
    if with_svi:
        value += ("4: vlan%d@%s: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9216 master oob state UP\n"
                  "    vlan protocol 802.1Q id %d <REORDER_HDR>\n") % (vlan, bridge, vlan)
    return value


def addresses(ipv4=True, ipv6=True, interface="vlan1000", state="UP"):
    items = []
    if ipv4:
        items.append({"family": "inet", "local": "192.0.2.1", "prefixlen": 24, "scope": "global"})
    if ipv6:
        items.append({"family": "inet6", "local": "fe80::1", "prefixlen": 64, "scope": "link"})
    return [{"ifname": interface, "flags": ["BROADCAST", "MULTICAST", "UP"],
             "operstate": state, "addr_info": items}]


class OobSpineCandidateTests(unittest.TestCase):
    # v15 CandidateDirectTests.test_default_role_hint_and_explicit_nonstandard_names_still_need_lldp
    # (test_v15_oob_spine.py:81).  V15-OOB-SPINE.md:25-27, CURRENT-CONTRACT.md:30-31.
    def test_default_role_hint_and_explicit_nonstandard_names_still_need_lldp(self):
        one, two = device("oob-spine01"), device("aggregation01")
        self.assertEqual(app.select_spine_inventory([one, two]), [one])
        self.assertEqual(app.select_spine_inventory([one, two], "aggregation01"), [two])
        for value in ("unknown", "oob-spine01,oob-spine01"):
            with self.assertRaises(app.SetupError):
                app.select_spine_inventory([one, two], value)

    # v15 CandidateDirectTests.test_lldp_only_actual_remote_host_column_not_summary
    # (test_v15_oob_spine.py:101).  V15-OOB-SPINE.md:64-66, CURRENT-CONTRACT.md:32-33.
    def test_lldp_only_actual_remote_host_column_not_summary(self):
        spine = device("oob-spine01.example.test")
        table = interface_table([("swp49", "OOB-SPINE01", "up")])
        table += " " * 125 + "Description: TO oob-spine02\n"
        self.assertEqual(app.lldp_spine_candidates(table, [spine]), [spine])

    # v15 CandidateDirectTests.test_csv_only_down_unknown_or_non_eth_jump_never_candidates
    # (test_v15_oob_spine.py:107).  V15-OOB-SPINE.md:64, :67; CURRENT-CONTRACT.md:30, :32.
    def test_csv_only_down_unknown_or_non_eth_jump_never_candidates(self):
        one = device("oob-spine01")
        two = device("oob-spine02")
        three = device("oob-spine03", kind="eth")
        table = interface_table([("swp49", "oob-spine01", "down"),
                                 ("swp50", "oob-spine03", "up"),
                                 ("swp51", "oob-spine99", "up")])
        self.assertEqual(app.lldp_spine_candidates(table, [one, two, three]), [])

    # v15 CandidateDirectTests.test_duplicate_uplinks_deduplicate_one_spine
    # (test_v15_oob_spine.py:116).  V15-OOB-SPINE.md:67.
    def test_duplicate_uplinks_deduplicate_one_spine(self):
        one = device("oob-spine01")
        self.assertEqual(app.lldp_spine_candidates(interface_table([
            ("swp49", one.hostname, "up"), ("swp50", one.hostname, "up")]), [one]), [one])

    # v15 CandidateDirectTests.test_short_name_is_not_arbitrary_prefix_match
    # (test_v15_oob_spine.py:121).  V15-OOB-SPINE.md:65; CURRENT-CONTRACT.md:33.
    def test_short_name_is_not_arbitrary_prefix_match(self):
        one = device("oob-spine01")
        self.assertEqual(app.lldp_spine_candidates(
            interface_table([("swp49", "oob-spine010", "up")]), [one]), [])

    # v15 CandidateDirectTests.test_ambiguous_csv_short_names_fail_closed
    # (test_v15_oob_spine.py:126).  V15-OOB-SPINE.md:66; CURRENT-CONTRACT.md:33.
    def test_ambiguous_csv_short_names_fail_closed(self):
        with self.assertRaisesRegex(app.SetupError, "ambiguous"):
            app.lldp_spine_candidates(interface_table([("swp49", "oob-spine01", "up")]),
                                      [device("oob-spine01.a.test"), device("oob-spine01.b.test")])

    # v15 CandidateDirectTests.test_missing_lldp_headers_is_not_a_description_scan
    # (test_v15_oob_spine.py:131).  V15-OOB-SPINE.md:64-65.
    def test_missing_lldp_headers_is_not_a_description_scan(self):
        self.assertEqual(app.lldp_spine_candidates("swp49 up up oob-spine01\n",
                                                   [device("oob-spine01")]), [])

    # v15 CandidateDirectTests.test_svi_is_real_vlan_not_virtual_vrr_interface
    # (test_v15_oob_spine.py:135).  V15-OOB-SPINE.md:70-71; CURRENT-CONTRACT.md:34-35.
    def test_svi_is_real_vlan_not_virtual_vrr_interface(self):
        value = links() + ("5: vlan1000-v0@vlan1000: <BROADCAST,UP> state UP\n"
                           "    macvlan mode private\n")
        self.assertEqual(app.vlan_svi_interfaces(value, 1000, "br_default"), ["vlan1000"])

    # v15 CandidateDirectTests.test_wrong_vlan_and_multiple_svis_do_not_guess
    # (test_v15_oob_spine.py:140).  V15-OOB-SPINE.md:70-71 ("不猜接口名"); CURRENT-CONTRACT.md:34.
    def test_wrong_vlan_and_multiple_svis_do_not_guess(self):
        self.assertEqual(app.vlan_svi_interfaces(links(), 2000), [])
        duplicate = links() + "5: blue1000@br_blue: <UP> state UP\n    vlan protocol 802.1Q id 1000\n"
        self.assertEqual(app.vlan_svi_interfaces(duplicate, 1000), ["vlan1000", "blue1000"])

    # v15 CandidateDirectTests.test_spine_needs_independent_ipv4_and_usable_link_local
    # (test_v15_oob_spine.py:145).  V15-OOB-SPINE.md:69-70; CURRENT-CONTRACT.md:34-35.
    def test_spine_needs_independent_ipv4_and_usable_link_local(self):
        for rows in (addresses(False), addresses(ipv6=False), addresses(state="DOWN")):
            with self.subTest(rows=rows):
                self.assertFalse(app.svi_address_ready(rows, "vlan1000", require_ipv6=True))
        self.assertTrue(app.svi_address_ready(addresses(), "vlan1000", require_ipv6=True))

    # v15 CandidateDirectTests.test_virtual_gateway_address_cannot_substitute_for_svi_ipv4
    # (test_v15_oob_spine.py:151).  V15-OOB-SPINE.md:71; CURRENT-CONTRACT.md:35.
    def test_virtual_gateway_address_cannot_substitute_for_svi_ipv4(self):
        rows = addresses(False) + addresses(interface="vlan1000-v0")
        self.assertFalse(app.svi_address_ready(rows, "vlan1000", require_ipv6=True))

    # v15 CandidateDirectTests.test_tentative_duplicate_or_unspecified_address_is_not_ready
    # (test_v15_oob_spine.py:155).  V15-OOB-SPINE.md:69-70 (own IPv4, usable link-local).
    def test_tentative_duplicate_or_unspecified_address_is_not_ready(self):
        for family, local, flags in (("inet6", "fe80::1", ["tentative"]),
                                     ("inet6", "fe80::1", ["dadfailed"]),
                                     ("inet", "0.0.0.0", [])):
            rows = addresses()
            for value in rows[0]["addr_info"]:
                if value["family"] == family:
                    value.update(local=local, flags=flags)
            self.assertFalse(app.svi_address_ready(rows, "vlan1000", require_ipv6=True))

    # v15 CandidateDirectTests.test_address_json_failure_is_not_an_absent_svi
    # (test_v15_oob_spine.py:165).  V15-OOB-SPINE.md:57; CURRENT-CONTRACT.md:28.
    def test_address_json_failure_is_not_an_absent_svi(self):
        for text in ("", "{}", "not-json", '[{"ifname":"vlan1000"}]'):
            with self.subTest(text=text), self.assertRaises(app.SetupError):
                app.parse_oob_addresses(text)

    # v15 CandidateDirectTests.test_new_address_query_is_readonly_allowlisted
    # (test_v15_oob_spine.py:170).  V15-OOB-SPINE.md:99.
    def test_new_address_query_is_readonly_allowlisted(self):
        self.assertEqual(app.ethernet_command_argv(["ip", "-j", "address", "show"]),
                         ["ip", "-j", "address", "show"])
        for command in (["ip", "address", "add", "192.0.2.1/24", "dev", "vlan1000"],
                        ["ip", "-j", "address", "show", ";reboot"]):
            with self.assertRaises(app.SetupError):
                app.ethernet_command_argv(command)

    # v15 CandidateDirectTests.test_spine_nd_must_match_mac_and_selected_interface
    # (test_v15_oob_spine.py:177).  V15-OOB-SPINE.md:72; CURRENT-CONTRACT.md:37.
    def test_spine_nd_must_match_mac_and_selected_interface(self):
        t = target()
        other = "fe80::999 dev vlan2000 lladdr %s REACHABLE\n" % MAC1
        result = app._spine_neighbor(t, ("", "", other), "vlan1000", "oob", MAC1)
        self.assertEqual(result.ipv6, "fe80::ff:fe00:10")
        self.assertEqual(result.address_source, "FDB_EUI64_CANDIDATE")
        valid = "fe80::1234 dev vlan1000 lladdr %s REACHABLE\n" % MAC1
        self.assertEqual(app._spine_neighbor(t, ("", "", valid), "vlan1000", "oob", MAC1).ipv6,
                         "fe80::1234")
        conflict = "fe80::ff:fe00:10 dev vlan1000 lladdr 02:00:00:00:ff:ff REACHABLE\n"
        with self.assertRaisesRegex(app.SetupError, "conflicting"):
            app._spine_neighbor(t, ("", "", conflict), "vlan1000", "oob", MAC1)


if __name__ == "__main__":
    unittest.main()
