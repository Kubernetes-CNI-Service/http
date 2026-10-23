"""Direct and simulated-login tests for infiniband/bringup/ufm-setup-upgrade."""

import json
import os
import pty
import re
import select
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from pathlib import Path
from unittest import mock
from xml.sax.saxutils import escape

from test_cases.module_loader import load_script
from test_cases.test_ubuntu24_host import MANUAL_NETPLAN

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "infiniband/bringup/ufm-setup-upgrade/ufm-setup-upgrade.py"
ufm = load_script("ufm_setup_upgrade_under_test", SCRIPT)

HEADER = ("hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw,eth1_mac,"
          "lo_ip,vlan_id,svi_ip,netmask,vlan_ports,vlan_id,svi_ip,netmask,vlan_ports,bgp_asn,bgp_ports,"
          "bond_ports,bond_type,bond_mac,peerlink_ports,vrl,evpn_vrf,evpn_l3vni,evpn_l3vlan,dhcp_relay,"
          "evpn_l2vni,evpn_l2vlan,svi_ip,netmask,vlan_ports")
UFM01 = "ufm01.site01.example.test,server_ufm,NA,198.51.101.130,23,198.51.101.254,02:00:00:00:01:01"
UFM02 = "ufm02.site01.example.test,server_ufm,NA,198.51.101.132,23,198.51.101.254,02:00:00:00:02:01"
OTHER_ROWS = [
    "ew-spine001.site01.example.test,ib,NA,198.51.100.1,/23,198.51.101.254,,198.51.100.2,/23,198.51.101.254,,,,,,,,,,,,,,,,,,,,,,,,,,",
    "oob-leaf115,eth_jump,NA,203.0.112.117,23,203.0.113.254,02:00:00:00:A1:15,,,,02:00:00:00:A1:16,,,,,,,,,,,,,,,,,,,,,,,,,",
    "oob-leaf117,eth_jump,NA,203.0.112.119,23,203.0.113.254,02:00:00:00:A1:17,,,,02:00:00:00:A1:18,,,,,,,,,,,,,,,,,,,,,,,,,",
]
GLOBAL = """\
schema_version: 2
common:
  switch:
    system:
      dns:
        server:
        - 160.250.70.5
        - 160.250.71.202
      ntp:
        server:
        - 160.250.71.253
        - ntp.ubuntu.com
      date-time:
        timezone: Etc/UTC
  mgmt:
    http:
      status: enabled
      port: 8088
      address: 198.51.103.200
switches:
  - eth:
      system: {}
servers:
  - ufm:
      version: "2.6.1-8"
      vip: "198.51.101.133"
      interfaces:
        alias:
          eth0: eno8303   # 逻辑管理接口 → 实际接口
        primary:
          ipmi:
            address: "198.51.101.129/23"
          eno8403: "192.0.2.1/30"
          ib0: "100.126.255.1/16"
          ib1: "100.126.255.2/16"
        secondary:
          ipmi:
            address: "198.51.101.131/23"
          eno8403: "192.0.2.2/30"
          ib0: "100.126.255.3/16"
          ib1: "100.126.255.4/16"
"""
IPMI_PRIMARY = '          ipmi:\n            address: "198.51.101.129/23"\n'
IPMI_SECONDARY = '          ipmi:\n            address: "198.51.101.131/23"\n'
P2P_ROWS = [
    ["Name", "Port", "Name", "Port"],
    ["ufm-01", "8303", "oob-leaf117", "17"],
    ["ufm-02", "8303", "oob-leaf117", "18"],
    ["ufm-01", "8403", "ufm-02", "8403"],
    ["ufm-01", "BMC", "oob-leaf115", "17"],
    ["ufm-02", "BMC", "oob-leaf115", "18"],
    ["UFM-01", "IB0", "IBSW-SU1-Leaf01", "FNM"],
]
UFM01_LL = "fe80::ff:fe00:101"   # RFC 4291 EUI-64 of 02:00:00:00:01:01
UFM02_LL = "fe80::ff:fe00:201"   # EUI-64 of 02:00:00:00:02:01, here learnt from the ND table

LEAF_LINKS = """\
17: swp17: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9216 qdisc pfifo_fast master br_default state UP mode DEFAULT group default qlen 1000
    link/ether 02:00:00:00:a1:17 brd ff:ff:ff:ff:ff:ff promiscuity 1
    bridge_slave state forwarding priority 8 cost 2 hairpin off learning on flood on
18: swp18: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9216 qdisc pfifo_fast master br_default state UP mode DEFAULT group default qlen 1000
    link/ether 02:00:00:00:a1:17 brd ff:ff:ff:ff:ff:ff promiscuity 1
    bridge_slave state forwarding priority 8 cost 2 hairpin off learning on flood on
40: br_default: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9216 qdisc noqueue state UP mode DEFAULT group default qlen 1000
    link/ether 02:00:00:00:a1:17 brd ff:ff:ff:ff:ff:ff promiscuity 0
    bridge forward_delay 1500 hello_time 200 max_age 2000 vlan_filtering 1
41: vlan1000@br_default: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9216 qdisc noqueue master oob state UP mode DEFAULT group default qlen 1000
    link/ether 02:00:00:00:a1:17 brd ff:ff:ff:ff:ff:ff promiscuity 0
    vlan protocol 802.1Q id 1000 <REORDER_HDR>
    vrf_slave table 1001
"""
LEAF_FDB = """\
02:00:00:00:01:01 dev swp17 vlan 1000 master br_default
02:00:00:00:02:01 dev swp18 vlan 1000 master br_default
02:00:00:00:a1:17 dev swp17 vlan 1000 master br_default permanent
"""
LEAF_NEIGH = f"""\
{UFM02_LL} dev vlan1000 lladdr 02:00:00:00:02:01 STALE
203.0.112.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
"""


def nv_interface_table(rows):
    """Cumulus 'nv show interface' layout as used by the ib-initial-setup v15 tests."""
    header = ["Interface", "Admin Status", "Oper Status", "Speed", "MTU", "Type",
              "Remote Host", "Remote Port", "Summary"]
    widths = [16, 15, 15, 8, 8, 12, 38, 18, 12]

    def line(values):
        return "".join(str(v).ljust(w) for v, w in zip(values, widths)).rstrip()
    lines = [line(header), line(["-" * (w - 2) for w in widths])]
    lines += [line([name, "up", oper, "1G", "9216", "swp", host, port, ""]) for name, oper, host, port in rows]
    return "\n".join(lines) + "\n"


def address_rows(*items):
    rows = []
    for name, ipv4, ipv6, state in items:
        info = []
        if ipv4:
            address, prefix = ipv4.split("/")
            info.append({"family": "inet", "local": address, "prefixlen": int(prefix), "scope": "global"})
        if ipv6:
            info.append({"family": "inet6", "local": ipv6, "prefixlen": 64, "scope": "link"})
        rows.append({"ifname": name, "flags": ["BROADCAST", "MULTICAST", "UP"] if state == "UP" else ["BROADCAST"],
                     "operstate": state, "addr_info": info})
    return rows


def switch_state(hostname, interfaces, links, fdb, neigh, addresses, *, reach, vrf="oob", iface="vlan1000"):
    return {"hostname": hostname, "interfaces": interfaces, "links": links, "fdb": fdb, "neigh": neigh,
            "addresses": addresses, "reach": reach, "vrf": vrf, "iface": iface,
            "ifquery": {iface: f"auto {iface}\niface {iface}\n    vlan-id 1000\n    vrf {vrf}"}}


def csv_row(hostname, kind, *, eth0_ip="", netmask="", vlan_id="", svi_ip="", svi_mask=""):
    values = [""] * len(HEADER.split(","))
    values[0], values[1], values[2], values[3], values[4] = hostname, kind, "NA", eth0_ip, netmask
    values[12], values[13], values[14] = vlan_id, svi_ip, svi_mask
    return ",".join(values)


LEAF_INTERFACES = nv_interface_table([
    ("swp17", "up", "", ""), ("swp18", "up", "", ""),
    ("swp49", "up", "oob-spine01", "swp1"), ("swp50", "up", "oob-spine02.site01.example.test", "swp1")])
LEAF_LL = "fe80::2eb1:b7ff:fee4:9348"
LEAF_ADDRESSES_V4 = address_rows(("eth0", "203.0.112.119/23", None, "UP"),
                                 ("vlan1000", "198.19.0.117/24", LEAF_LL, "UP"))
LEAF_ADDRESSES_NO_V4 = address_rows(("eth0", "203.0.112.119/23", None, "UP"),
                                    ("vlan1000", None, LEAF_LL, "UP"))
SPINE_ROWS = [
    csv_row("oob-spine01", "eth_jump", vlan_id="4000", svi_ip="203.0.113.201", svi_mask="23"),
    csv_row("oob-spine02.site01.example.test", "eth_jump", eth0_ip="203.0.113.202", netmask="23"),
]
SPINE_LINKS = """\
1: br_default: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9216 qdisc noqueue state UP mode DEFAULT
    bridge forward_delay 1500 vlan_filtering 1
2: swp1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9216 master br_default state UP mode DEFAULT
    bridge_slave state forwarding
3: vlan1000@br_default: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9216 master oob state UP mode DEFAULT
    vlan protocol 802.1Q id 1000 <REORDER_HDR>
4: vlan1000-v0@vlan1000: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9216 master oob state UP mode DEFAULT
    macvlan mode private
"""
SPINE_INTERFACES = nv_interface_table([("swp1", "up", "oob-leaf117", "swp49")])


def write_xlsx(path, rows):
    main = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    body = "".join(
        f'<row r="{r}">' + "".join(
            f'<c r="{chr(65 + c)}{r}" t="inlineStr"><is><t>{escape(v)}</t></is></c>'
            for c, v in enumerate(row)) + "</row>"
        for r, row in enumerate(rows, 1))
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("xl/workbook.xml", (
            f'<workbook xmlns="{main}" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            '<sheets><sheet name="P2P" sheetId="1" r:id="rId1"/></sheets></workbook>'))
        archive.writestr("xl/_rels/workbook.xml.rels", (
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="worksheet" Target="worksheets/sheet1.xml"/></Relationships>'))
        archive.writestr("xl/worksheets/sheet1.xml", f'<worksheet xmlns="{main}"><sheetData>{body}</sheetData></worksheet>')


def make_inputs(directory, *, csv_rows=None, global_text=GLOBAL, p2p_rows=P2P_ROWS):
    directory = Path(directory)
    rows = csv_rows if csv_rows is not None else OTHER_ROWS + [UFM01, UFM02]
    (directory / "ib.csv").write_text(HEADER + "\n" + "\n".join(rows) + "\n", encoding="utf-8")
    (directory / "01-global.yaml").write_text(global_text, encoding="utf-8")
    if p2p_rows is not None:
        write_xlsx(directory / "p2p.xlsx", p2p_rows)
    (directory / "publickey").mkdir(exist_ok=True)
    (directory / "publickey" / "mgmt-server.pub").write_text(f"ssh-ed25519 {TEST_KEY_BLOB} mgmt-server\n",
                                                             encoding="utf-8")
    return directory


class InputContractTest(unittest.TestCase):
    def plan(self, **kwargs):
        with tempfile.TemporaryDirectory() as tmp:
            return ufm.build_plan(make_inputs(tmp, **kwargs))

    def assert_rejected(self, plan, *needles):
        self.assertTrue(plan.errors, "expected an input error")
        text = "\n".join(plan.errors)
        for needle in needles:
            self.assertIn(needle, text)

    def test_owner_format_is_accepted_with_roles_addresses_and_oob(self):
        plan = self.plan()
        self.assertEqual(plan.errors, [])
        self.assertEqual(plan.version, "2.6.1-8")
        self.assertEqual(plan.vip, "198.51.101.133")
        self.assertEqual(plan.mgmt_device, "eno8303")
        self.assertEqual(plan.roles, {"primary": "ufm01.site01.example.test",
                                      "secondary": "ufm02.site01.example.test"})
        self.assertEqual(plan.addresses["secondary"],
                         {"ipmi": "198.51.101.131/23", "eno8403": "192.0.2.2/30",
                          "ib0": "100.126.255.3/16", "ib1": "100.126.255.4/16"})
        node = {item.hostname: item for item in plan.nodes}["ufm02.site01.example.test"]
        self.assertEqual((node.address, node.interface, node.gateway, node.mac),
                         ("198.51.101.132", "198.51.101.132/23", "198.51.101.254", "02:00:00:00:02:01"))
        attachments = {host: (a.leaf.hostname, a.leaf.login_ip, a.port) for host, a in plan.attachments.items()}
        self.assertEqual(attachments, {
            "ufm01.site01.example.test": ("oob-leaf117", "203.0.112.119", "swp17"),
            "ufm02.site01.example.test": ("oob-leaf117", "203.0.112.119", "swp18"),
        })
        self.assertEqual(plan.public_keys, ["mgmt-server.pub"])

    def test_csv_row_order_does_not_decide_primary(self):
        plan = self.plan(csv_rows=OTHER_ROWS + [UFM02, UFM01])
        self.assertEqual(plan.errors, [])
        self.assertEqual(plan.roles["primary"], "ufm01.site01.example.test")

    def test_slash_prefix_netmask_is_equivalent(self):
        plan = self.plan(csv_rows=OTHER_ROWS + [UFM01.replace(",23,", ",/23,"), UFM02])
        self.assertEqual(plan.errors, [])

    def test_old_type_ufm_is_rejected(self):
        self.assert_rejected(self.plan(csv_rows=OTHER_ROWS + [UFM01.replace("server_ufm", "ufm"), UFM02]),
                             "server_ufm")

    def test_values_after_seventh_column_are_rejected(self):
        stale = UFM01 + ",192.0.2.1,/30"
        self.assert_rejected(self.plan(csv_rows=OTHER_ROWS + [stale, UFM02]), "eth1_ip", "01-global.yaml")

    def test_duplicate_mac_is_rejected(self):
        twin = UFM02.replace("02:00:00:00:02:01", "02:00:00:00:01:01")
        self.assert_rejected(self.plan(csv_rows=OTHER_ROWS + [UFM01, twin]), "eth0_mac")

    def test_missing_gateway_and_gateway_outside_subnet_are_rejected(self):
        self.assert_rejected(self.plan(csv_rows=OTHER_ROWS + [UFM01.replace("198.51.101.254", ""), UFM02]),
                             "eth0_gw")
        self.assert_rejected(self.plan(csv_rows=OTHER_ROWS + [UFM01.replace("198.51.101.254", "198.51.102.1"), UFM02]),
                             "eth0_gw")

    def test_primary_must_be_uniquely_identifiable(self):
        renamed = UFM01.replace("ufm01.site01", "ufm03.site01")
        self.assert_rejected(self.plan(csv_rows=OTHER_ROWS + [renamed, UFM02]), "ufm01")

    def test_unknown_interface_section_is_rejected(self):
        self.assert_rejected(self.plan(global_text=GLOBAL.replace("        primary:\n", "        ipoib:\n          primary: \"198.51.100.1/24\"\n        primary:\n", 1)),
                             "ipoib")

    def test_unquoted_version_is_rejected(self):
        self.assert_rejected(self.plan(global_text=GLOBAL.replace('version: "2.6.1-8"', "version: 2.6")),
                             "version")

    def test_addresses_and_macs_owned_by_other_csv_rows_are_rejected(self):
        # Owner 2026-10-20: check validates the inputs; no UFM address may clash with another device.
        clash = "oob-leaf119,eth_jump,NA,198.51.101.130,23,203.0.113.254,02:00:00:00:a1:19,,,,,,,,,,,,,,,,,,,,,,,,,,,,,"
        self.assert_rejected(self.plan(csv_rows=OTHER_ROWS + [clash, UFM01, UFM02]),
                             "198.51.101.130", "已在 ib.csv 中分配给 oob-leaf119 eth0_ip")
        same_mac = "oob-leaf119,eth_jump,NA,203.0.112.121,23,203.0.113.254,02:00:00:00:02:01,,,,,,,,,,,,,,,,,,,,,,,,,,,,,"
        self.assert_rejected(self.plan(csv_rows=OTHER_ROWS + [same_mac, UFM01, UFM02]),
                             "02:00:00:00:02:01", "oob-leaf119 eth0_mac")
        vip_on_switch = "oob-leaf119,eth_jump,NA,198.51.101.133,23,203.0.113.254,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,"
        self.assert_rejected(self.plan(csv_rows=OTHER_ROWS + [vip_on_switch, UFM01, UFM02]), "198.51.101.133（vip）")

    def test_vip_collision_with_ipmi_is_rejected(self):
        self.assert_rejected(self.plan(global_text=GLOBAL.replace('vip: "198.51.101.133"', 'vip: "198.51.101.131"')),
                             "198.51.101.131")

    def test_two_nodes_require_vip(self):
        self.assert_rejected(self.plan(global_text=GLOBAL.replace('      vip: "198.51.101.133"\n', "")), "vip")

    def test_role_blocks_must_have_same_interfaces(self):
        text = GLOBAL.replace('          ib1: "100.126.255.4/16"\n', "")
        self.assert_rejected(self.plan(global_text=text), "secondary")

    def test_paired_interface_must_share_subnet(self):
        text = GLOBAL.replace('eno8403: "192.0.2.2/30"', 'eno8403: "192.0.2.6/30"')
        self.assert_rejected(self.plan(global_text=text), "eno8403")

    def test_management_interface_cannot_be_redefined_in_role_block(self):
        text = GLOBAL.replace('          eno8403: "192.0.2.1/30"\n',
                              '          eno8403: "192.0.2.1/30"\n          eno8303: "198.51.101.140/23"\n')
        self.assert_rejected(self.plan(global_text=text), "eno8303")

    def test_host_interface_overlapping_management_subnet_is_rejected(self):
        text = GLOBAL.replace('eno8403: "192.0.2.1/30"', 'eno8403: "198.51.101.200/23"').replace(
            'eno8403: "192.0.2.2/30"', 'eno8403: "198.51.101.201/23"')
        self.assert_rejected(self.plan(global_text=text), "eno8403")

    def test_duplicate_yaml_key_is_rejected(self):
        text = GLOBAL.replace('      vip: "198.51.101.133"\n', '      vip: "198.51.101.133"\n      vip: "198.51.101.134"\n')
        self.assert_rejected(self.plan(global_text=text), "vip")

    def test_missing_p2p_is_only_a_warning(self):
        plan = self.plan(p2p_rows=None)
        self.assertEqual(plan.errors, [])
        self.assertEqual(plan.attachments, {})
        self.assertTrue(any("p2p.xlsx" in warning for warning in plan.warnings))

    def test_ambiguous_management_link_is_rejected(self):
        rows = P2P_ROWS + [["ufm-01", "eno8303", "oob-leaf115", "40"]]
        self.assert_rejected(self.plan(p2p_rows=rows), "ufm01")

    def test_p2p_peer_missing_from_csv_is_rejected(self):
        rows = [row if row[0] != "ufm-02" or row[1] != "8303" else ["ufm-02", "8303", "oob-leaf999", "18"]
                for row in P2P_ROWS]
        self.assert_rejected(self.plan(p2p_rows=rows), "oob-leaf999")


class P2PPortNamingTest(unittest.TestCase):
    U1, U2 = "ufm01.site01.example.test", "ufm02.site01.example.test"

    def plan(self, rows, global_text=GLOBAL):
        with tempfile.TemporaryDirectory() as tmp:
            return ufm.build_plan(make_inputs(tmp, p2p_rows=[["Name", "Port", "Name", "Port"]] + rows,
                                              global_text=global_text))

    def test_management_port_spellings_all_mean_eno8303(self):
        for spelling in ("8303", "eno8303", "eth0", "ENO8303", "Eth0"):
            with self.subTest(spelling=spelling):
                plan = self.plan([["ufm-01", spelling, "oob-leaf117", "17"],
                                  ["ufm-02", spelling, "oob-leaf117", "18"]])
                self.assertEqual(plan.errors, [])
                self.assertEqual({host: a.port for host, a in plan.attachments.items()},
                                 {self.U1: "swp17", self.U2: "swp18"})

    def test_ha_port_spellings_all_mean_eno8403(self):
        for left, right in (("8403", "8403"), ("eno8403", "eth1"), ("eth1", "ENO8403"), ("Eth1", "eth1")):
            with self.subTest(left=left, right=right):
                plan = self.plan([["ufm-01", "8303", "oob-leaf117", "17"],
                                  ["ufm-02", "8303", "oob-leaf117", "18"],
                                  ["ufm-01", left, "ufm-02", right]])
                self.assertEqual(plan.errors, [])
                self.assertEqual(plan.ha_links[self.U1][:3], (self.U2, "eno8403", "eno8403"))
                self.assertEqual(plan.ha_links[self.U2][:3], (self.U1, "eno8403", "eno8403"))
                self.assertFalse([w for w in plan.warnings if "eno8403" in w], plan.warnings)

    def test_eth1_is_inferred_as_the_ha_interface_when_alias_omits_it(self):
        plan = self.plan([["ufm-01", "8303", "oob-leaf117", "17"]])
        self.assertEqual(plan.logical, {"eth0": "eno8303", "eth1": "eno8403"})

    def test_explicit_eth1_alias_is_honoured(self):
        text = GLOBAL.replace("          eth0: eno8303   # 逻辑管理接口 → 实际接口\n",
                              "          eth0: eno8303\n          eth1: eno8403\n")
        plan = self.plan([["ufm-01", "eth1", "ufm-02", "eth1"]], global_text=text)
        self.assertEqual(plan.errors, [])
        self.assertEqual(plan.logical["eth1"], "eno8403")
        self.assertEqual(plan.ha_links[self.U1][:3], (self.U2, "eno8403", "eno8403"))

    def test_ambiguous_eth1_is_not_guessed(self):
        text = (GLOBAL.replace('          eno8403: "192.0.2.1/30"\n',
                               '          eno8403: "192.0.2.1/30"\n          eno12399: "192.0.2.65/30"\n')
                .replace('          eno8403: "192.0.2.2/30"\n',
                         '          eno8403: "192.0.2.2/30"\n          eno12399: "192.0.2.66/30"\n'))
        plan = self.plan([["ufm-01", "eth1", "ufm-02", "eth1"]], global_text=text)
        self.assertEqual(plan.errors, [])
        self.assertNotIn("eth1", plan.logical)
        self.assertEqual(plan.ha_links, {})
        self.assertTrue([w for w in plan.warnings if "eth1" in w], plan.warnings)

    def test_numeric_port_never_matches_ib_interfaces(self):
        plan = self.plan([["ufm-01", "1", "oob-leaf117", "17"], ["ufm-02", "0", "oob-leaf117", "18"]])
        self.assertEqual(plan.attachments, {})

    def test_ha_port_cabled_to_a_switch_is_reported(self):
        plan = self.plan([["ufm-01", "8303", "oob-leaf117", "17"],
                          ["ufm-01", "8403", "oob-leaf117", "30"]])
        self.assertEqual(plan.errors, [])
        self.assertNotIn(self.U1, plan.ha_links)
        self.assertTrue([w for w in plan.warnings if "eno8403" in w and "oob-leaf117" in w], plan.warnings)

    def test_missing_ha_link_is_a_warning(self):
        plan = self.plan([["ufm-01", "8303", "oob-leaf117", "17"], ["ufm-02", "8303", "oob-leaf117", "18"]])
        self.assertEqual(plan.errors, [])
        self.assertEqual(plan.ha_links, {})
        self.assertTrue([w for w in plan.warnings if "eno8403" in w], plan.warnings)


def standalone_tool(root):
    """Only the entry script, the shared host module and the inputs; no git, setup, load or lock files."""
    tool = Path(root) / "infiniband/bringup/ufm-setup-upgrade"
    tool.mkdir(parents=True)
    shutil.copy2(SCRIPT, tool / SCRIPT.name)
    (Path(root) / "infra").mkdir()
    shutil.copy2(ROOT / "infra/ubuntu24_host.py", Path(root) / "infra/ubuntu24_host.py")
    return tool


class StandaloneRunTest(unittest.TestCase):
    def run_check(self, tool, cwd):
        env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
        return subprocess.run([sys.executable, "-B", str(tool / SCRIPT.name), "check", "--inputs-only"],
                              cwd=cwd, env=env, capture_output=True, text=True, timeout=60)

    def test_check_runs_with_only_the_script_shared_module_and_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            tool = standalone_tool(tmp)
            make_inputs(tool)
            result = self.run_check(tool, tmp)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("oob-leaf117 (203.0.112.119) swp18", result.stdout)
        # Owner 2026-10-20 layout: per node, its interfaces, then where each one is cabled.
        self.assertIn("[primary] ufm01.site01.example.test\n"
                      "    Interfaces:\n"
                      "      eno8303: 198.51.101.130/23\n"
                      "      eno8403: 192.0.2.1/30\n"
                      "      ib0: 100.126.255.1/16\n"
                      "      ib1: 100.126.255.2/16\n"
                      "      ipmi: 198.51.101.129/23\n"
                      "    Connections:\n"
                      "      eno8303: oob-leaf117 (203.0.112.119) swp17  [P2P ufm-01:8303]\n"
                      "      eno8403: ufm02.site01.example.test eno8403  [P2P ufm-01:8403 - ufm-02:8403]\n"
                      "      ipmi: oob-leaf115 (203.0.112.117) swp17  [P2P ufm-01:BMC]\n", result.stdout)

    def test_check_exits_nonzero_on_input_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            tool = standalone_tool(tmp)
            make_inputs(tool, csv_rows=OTHER_ROWS + [UFM01])
            result = self.run_check(tool, "/")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("vip", result.stdout)


class LeafDiscoveryTest(unittest.TestCase):
    def setUp(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.plan = ufm.build_plan(make_inputs(tmp))
        self.nodes = {node.hostname.split(".")[0]: node for node in self.plan.nodes}

    def attachment(self, short):
        return self.plan.attachments[self.nodes[short].hostname]

    def test_neighbor_table_entry_is_used_when_present(self):
        node = self.nodes["ufm02"]
        self.assertEqual(ufm.select_neighbor(node, self.attachment("ufm02"), LEAF_LINKS, LEAF_FDB, LEAF_NEIGH),
                         (UFM02_LL, "vlan1000", "ND"))

    def test_eui64_candidate_uses_fdb_vlan_svi_when_neighbor_missing(self):
        node = self.nodes["ufm01"]
        self.assertEqual(ufm.select_neighbor(node, self.attachment("ufm01"), LEAF_LINKS, LEAF_FDB, LEAF_NEIGH),
                         (UFM01_LL, "vlan1000", "FDB_EUI64"))

    def test_other_mac_on_port_stops(self):
        node = self.nodes["ufm01"]
        fdb = LEAF_FDB.replace("02:00:00:00:01:01 dev swp17", "02:11:22:33:44:55 dev swp17")
        with self.assertRaises(ufm.UfmError) as caught:
            ufm.select_neighbor(node, self.attachment("ufm01"), LEAF_LINKS, fdb, LEAF_NEIGH)
        self.assertIn("02:11:22:33:44:55", str(caught.exception))

    def test_no_learned_mac_stops(self):
        node = self.nodes["ufm01"]
        fdb = "\n".join(line for line in LEAF_FDB.splitlines() if "swp17" not in line or "permanent" in line)
        with self.assertRaises(ufm.UfmError):
            ufm.select_neighbor(node, self.attachment("ufm01"), LEAF_LINKS, fdb, LEAF_NEIGH)

    def test_nested_command_matches_manual_hop(self):
        argv = ufm.nested_ufm_argv(self.attachment("ufm02").leaf, "cumulus",
                                   ufm.Neighbor(UFM02_LL, "vlan1000", "oob", "ND"), "root",
                                   ["true"], "abc123", 5, batch=False)
        self.assertEqual(argv[0], "ssh")
        self.assertIn("cumulus@203.0.112.119", argv)
        self.assertNotIn("StrictHostKeyChecking=no", " ".join(argv))
        remote = argv[-1]
        for fragment in ("ip vrf exec oob ssh -6 -tt", "-B vlan1000", f"root@{UFM02_LL}",
                         "PubkeyAuthentication=no", "StrictHostKeyChecking=accept-new"):
            self.assertIn(fragment, remote)


class ResponderTest(unittest.TestCase):
    DEST = f"root@{UFM02_LL}"
    MANUAL = [
        f"{DEST}'s password: ",
        "You are required to change your password immediately (administrator enforced).\n"
        "Welcome to Ubuntu 24.04.3 LTS\nChanging password for root.\nCurrent password: ",
        "New password: ",
        "Retype new password: ",
    ]

    def feed(self, responder, chunks):
        text, answers = "", []
        for chunk in chunks:
            text += chunk
            answers.append(responder(text))
        return answers

    def test_manual_forced_change_sequence(self):
        responder = ufm.Responder(ufm_destination=self.DEST, login_password="factory",
                                  new_password="NewPw", allow_change=True, outer_password="leaf")
        answers = self.feed(responder, ["cumulus@203.0.112.119's password: "] + self.MANUAL)
        self.assertEqual(answers, ["leaf", "factory", "factory", "NewPw", "NewPw"])
        self.assertTrue(responder.change_attempted)

    def test_forced_change_without_permission_aborts(self):
        responder = ufm.Responder(ufm_destination=self.DEST, login_password="factory",
                                  new_password="NewPw", allow_change=False)
        answers = self.feed(responder, self.MANUAL[:2])
        self.assertEqual(answers[0], "factory")
        self.assertIs(answers[1], ufm.ABORT)
        self.assertTrue(responder.change_blocked)

    def test_policy_rejection_of_new_password_aborts(self):
        responder = ufm.Responder(ufm_destination=self.DEST, login_password="factory",
                                  new_password="short", allow_change=True)
        answers = self.feed(responder, self.MANUAL + ["BAD PASSWORD: The password is shorter than 8 characters\nNew password: "])
        self.assertIs(answers[-1], ufm.ABORT)
        self.assertIn("BAD PASSWORD", responder.bad_password)

    def test_keyboard_interactive_prompt_format(self):
        responder = ufm.Responder(ufm_destination="root@198.51.101.130", login_password="pw",
                                  new_password="new", allow_change=False)
        self.assertEqual(responder("(root@198.51.101.130) Password: "), "pw")


class ClassifyTest(unittest.TestCase):
    def outcome(self, output, code=255, destination="root@198.51.101.130"):
        responder = ufm.Responder(ufm_destination=destination, login_password="x",
                                  new_password="y", allow_change=False)
        return ufm.classify(ufm.SessionResult(output, code), responder, "m")

    def test_categories(self):
        self.assertEqual(self.outcome("ssh: connect to host 198.51.101.130 port 22: Connection timed out"), "UNREACHABLE")
        self.assertEqual(self.outcome("ssh: connect to host 198.51.101.130 port 22: No route to host"), "UNREACHABLE")
        self.assertEqual(self.outcome("ssh: connect to host 198.51.101.130 port 22: Connection refused"), "REFUSED")
        self.assertEqual(self.outcome("root@198.51.101.130: Permission denied (publickey,password)."), "AUTH_REJECTED")
        self.assertEqual(self.outcome("cumulus@203.0.112.119: Permission denied (publickey,password).",
                                      destination=f"root@{UFM02_LL}"), "LEAF_AUTH_REJECTED")
        self.assertEqual(self.outcome("@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@"), "HOSTKEY_CONFLICT")
        self.assertEqual(self.outcome("something odd"), "UNKNOWN")
        self.assertEqual(self.outcome("ok but no frame", code=0), "UNKNOWN")
        self.assertEqual(self.outcome("\n__UFM_BEGIN_m__\nmac=x\n__UFM_END_m__=0\n", code=0), "OK")


FAKE_SSH = r'''#!{python}
import getpass, json, os, re, shlex, subprocess, sys
STATE = os.environ["FAKE_UFM_STATE"]
state = json.load(open(STATE))
args = sys.argv[1:]
target = next(a for a in args if "@" in a and not a.startswith("-"))
remote = args[-1]
with open(STATE + ".calls", "a") as log:
    log.write(json.dumps({"target": target, "remote": remote,
                          "strict": "StrictHostKeyChecking=yes" in args}) + "\n")
user, host = target.split("@", 1)

def say(text):
    print(text, flush=True)

def ufm_session(name, dest, command):
    item = state["ufms"][name]
    if item.get("down_sessions", 0) > 0:
        item["down_sessions"] -= 1
        json.dump(state, open(STATE, "w"))
        say(f"ssh: connect to host {dest} port 22: Connection timed out")
        sys.exit(255)
    sys.path.insert(0, os.environ["FAKE_UFM_BIN"])
    import _ufm_tool
    if "BatchMode=yes" in args and "PreferredAuthentications=publickey" in args:
        base = _ufm_tool.prepare(name)
        keys = os.path.join(base, "root/.ssh/authorized_keys")
        if not (os.path.exists(keys) and os.environ["FAKE_LOCAL_KEY_BLOB"] in open(keys).read()):
            say(f"root@{dest}: Permission denied (publickey).")
            sys.exit(255)
        env = dict(os.environ, FAKE_UFM_NAME=name,
                   PATH=os.environ["FAKE_UFM_BIN"] + os.pathsep + os.environ["PATH"])
        sys.exit(subprocess.call(["/bin/sh", "-c", _ufm_tool.rewrite(command, base)], env=env))
    password = getpass.getpass(f"root@{dest}'s password: ")
    if password != item["password"] and item.get("kbd_interactive"):
        # sshd with KbdInteractiveAuthentication retries through keyboard-interactive
        password = getpass.getpass(f"(root@{dest}) Password: ")
    if password != item["password"]:
        say(f"root@{dest}: Permission denied (publickey,password,keyboard-interactive).")
        sys.exit(255)
    if item["expired"]:
        # As ufm-manual.log: sshd + PAM change the password, then the session simply continues.
        say("You are required to change your password immediately (administrator enforced).")
        say("Changing password for root.")
        current = getpass.getpass("Current password: ")
        if current != item["password"]:
            say("fatal: PAM: pam_chauthtok(): Authentication token manipulation error")
            sys.exit(1)
        for _ in range(3):
            new = getpass.getpass("New password: ")
            if len(new) < item.get("min_length", 0):
                say("You must choose a longer password.")
                continue
            if getpass.getpass("Retype new password: ") != new:
                say("Sorry, passwords do not match.")
                continue
            break
        else:
            say("fatal: PAM: pam_chauthtok(): Authentication token manipulation error")
            sys.exit(1)
        item["password"], item["expired"] = new, False
        json.dump(state, open(STATE, "w"))
    base = _ufm_tool.prepare(name)
    env = dict(os.environ, FAKE_UFM_NAME=name,
               PATH=os.environ["FAKE_UFM_BIN"] + os.pathsep + os.environ["PATH"])
    sys.exit(subprocess.call(["/bin/sh", "-c", _ufm_tool.rewrite(command, base)], env=env))

if user == "cumulus":
    sw = state["switches"].get(host)
    if sw is None:
        say(f"ssh: connect to host {host} port 22: Connection timed out")
        sys.exit(255)
    if "BatchMode=yes" in args and state.get("leaf_keys") is False:
        say(f"{target}: Permission denied (publickey,password).")
        sys.exit(255)
    answer = "" if "BatchMode=yes" in args else getpass.getpass(f"{target}'s password: ")
    if "BatchMode=yes" not in args and answer != state["leaf_password"]:
        say(f"{target}: Permission denied (publickey,password).")
        sys.exit(255)
    probe = re.search(r": addr-probe ([0-9.]+) (\S+)", remote)
    if probe:   # the OOB address-occupancy probe: sw["arp"] maps an address to the MAC that answers
        sw.setdefault("probes", []).append(probe.group(1))
        json.dump(state, open(STATE, "w"))
        mac = sw.get("arp", {}).get(probe.group(1))
        evpn = sw.get("evpn", {}).get(probe.group(1))   # learned from another VTEP: no ping reply comes back
        say("ping=yes" if mac else "ping=no")
        say(f"neigh={probe.group(1)} lladdr {mac} REACHABLE" if mac else
            f"neigh={probe.group(1)} lladdr {evpn} extern_learn NOARP proto zebra" if evpn else "neigh=")
        sys.exit(0)
    if "ip vrf exec" in remote:
        dest = re.search(r"root@(fe80::[0-9a-f:]+)", remote).group(1)
        if f"ip vrf exec {sw['vrf']} ssh -6" not in remote or f"-B {sw['iface']}" not in remote:
            say("wrong vrf/interface")
            sys.exit(97)
        name = next((n for n, u in state["ufms"].items() if u["lladdr"] == dest and dest in sw["reach"]), None)
        if name is None:
            say(f"ssh: connect to host {dest} port 22: No route to host")
            sys.exit(255)
        ufm_session(name, dest, shlex.split(shlex.split(remote)[2])[-1])
    query = re.search(r"exec ifquery ([A-Za-z0-9_.:-]+)", remote)
    if query:
        text = sw["ifquery"].get(query.group(1))
        if text is None:
            sys.exit(1)
        say(text)
        sys.exit(0)
    for needle, key in (("nv show interface", "interfaces"), ("ip -j address show", "addresses"),
                        ("bridge fdb show", "fdb"), ("ip neighbor", "neigh"), ("ip -d link show", "links"),
                        ("exec hostname", "hostname")):
        if needle in remote:
            value = sw[key]
            say(value if isinstance(value, str) else json.dumps(value))
            sys.exit(0)
    say("unexpected switch command")
    sys.exit(98)

ha = state.get("ha", {})
if host == ha.get("vip") and ha.get("started"):
    # owner 2026-10-22: after a failover the VIP answers with the other UFM's host key
    name = ha["master"]
    key = state.get("vip_key_override") or state["ufms"][name].get(
        "host_key", f"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHOSTKEY{name.upper()}")
    known = next((a.split("=", 1)[1] for a in args if a.startswith("UserKnownHostsFile=")), "")
    if "StrictHostKeyChecking=yes" not in args or not known or f"{host} {key}" not in open(known).read():
        say(f"@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\nHost key for {host} has changed and "
            "you have requested strict checking.\nHost key verification failed.")
        sys.exit(255)
    ufm_session(name, host, remote)
name = next((n for n, u in state["ufms"].items() if u["answers_on"] and u["answers_on"] == host), None)
if name is None or host in state.get("no_direct", []):
    say(f"ssh: connect to host {host} port 22: Connection timed out")
    sys.exit(255)
ufm_session(name, host, remote)
'''

# A stateful stand-in for the UFM host tools seen in ufm-manual.log; one file, dispatched by argv[0].
FAKE_TOOL = r'''#!{python}
import getpass, glob, hashlib, json, os, sys, tempfile, time
STATE = os.environ["FAKE_UFM_STATE"]
MGMT = "eno8303"


def load():
    with open(STATE) as handle:
        return json.load(handle)


def save(state):
    temporary = f"{STATE}.tmp{os.getpid()}"
    with open(temporary, "w") as handle:
        json.dump(state, handle)
    os.replace(temporary, STATE)


def base_dir(name):
    return os.path.join(os.environ["FAKE_UFM_SANDBOX"], name)


def shared_dir():
    """/opt/ufm/files sits on the DRBD volume: the master of the moment sees the same files."""
    return os.path.join(os.environ["FAKE_UFM_SANDBOX"], "drbd")


def rewrite(text, base):
    # /tmp/ first: on Linux the sandbox itself may live under /tmp
    for old in ("/tmp/", "/etc/netplan", "/etc/os-release", "/etc/systemd", "/etc/hosts", "/usr/share/zoneinfo",
                "/sys/class/net", "/root/", "/etc/ufm-release", "/var/log/", "/etc/ssh/"):
        text = text.replace(old, base + old)
    return text.replace("/opt/ufm/", shared_dir() + "/opt/ufm/")


def prepare(name):
    state = load()
    item = state["ufms"][name]
    base = base_dir(name)
    for sub in ("etc/netplan", "root", "var/log", "tmp"):
        os.makedirs(os.path.join(base, sub), exist_ok=True)
    with open(os.path.join(base, "etc/os-release"), "w") as handle:
        handle.write('PRETTY_NAME="Ubuntu 24.04.3 LTS"\n')
    os.makedirs(os.path.join(base, "etc/ssh"), exist_ok=True)
    with open(os.path.join(base, "etc/ssh/ssh_host_ed25519_key.pub"), "w") as handle:
        handle.write(item.get("host_key", f"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHOSTKEY{name.upper()}")
                     + f" root@{name}\n")
    devices = {MGMT: {"mac": item["reported_mac"], "oper": "up"}}
    devices.update(item.get("ifaces", {}))
    for device, info in devices.items():
        directory = os.path.join(base, "sys/class/net", device)
        os.makedirs(directory, exist_ok=True)
        with open(os.path.join(directory, "address"), "w") as handle:
            handle.write(info.get("mac", "00:00:00:00:00:00") + "\n")
        with open(os.path.join(directory, "operstate"), "w") as handle:
            handle.write(info.get("oper", "down") + "\n")
    if not item.get("seeded"):
        for relative, text in item.get("files", {}).items():
            path = os.path.join(base, relative)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as handle:
                handle.write(text)
        item["seeded"] = True
        save(state)
    return base


def systemctl(state, item, args):
    unit = args[-1] if args else ""
    if args[:3] == ["show", "--property=LoadState", "--value"]:
        print("not-found" if unit in item.get("missing_units", []) else "loaded")
        return 0
    if args[:1] == ["is-enabled"]:
        print(item.get("unit_state", {}).get(unit, "enabled"))
        return 0
    if args[:1] == ["is-active"]:
        active = item.get("services", {}).get(unit, "active")
        print(active)
        return 0 if active == "active" else 3
    if args[:1] == ["stop"]:
        item.setdefault("systemctl", []).append(" ".join(args))
        if unit not in item.get("stop_fails", []):
            item.setdefault("services", {})[unit] = "inactive"
        save(state)
        return 0 if unit not in item.get("stop_fails", []) else 1
    if args[:1] in (["restart"], ["unmask"]) or args[:2] == ["enable", "--now"]:
        item.setdefault("systemctl", []).append(" ".join(args))
        if args[0] == "unmask":
            item.setdefault("unit_state", {})[unit] = "disabled"
        save(state)
        return 0
    return 1


def netplan(state, item, base, args):
    import yaml
    merged = {}
    for path in sorted(glob.glob(os.path.join(base, "etc/netplan/*.yaml"))):
        try:
            document = yaml.safe_load(open(path).read()) or {}
        except Exception as exc:
            print(f"Error in network definition {path}: {exc}", file=sys.stderr)
            return 1
        for device, config in ((document.get("network") or {}).get("ethernets") or {}).items():
            merged.setdefault(device, {}).update(config or {})
    if args[:1] == ["generate"]:
        if item.get("generate_fails"):
            print("netplan generate: invalid configuration (fake)", file=sys.stderr)
            return 1
        return 0
    if args[:1] == ["apply"]:
        config = merged.get(MGMT, {})
        addresses = [str(value) for value in config.get("addresses") or []]
        item["ipv4"] = " ".join(addresses)
        item["answers_on"] = addresses[0].split("/")[0] if addresses else ""
        gateway = config.get("gateway4")
        for route in config.get("routes") or []:
            if str(route.get("to")) in ("default", "0.0.0.0/0"):
                gateway = route.get("via")
        item["default"] = f"default via {gateway} dev {MGMT} proto static" if gateway else ""
        for device, info in item.get("ifaces", {}).items():
            info["addrs"] = [str(value) for value in merged.get(device, {}).get("addresses") or []]
        item["applied"] = item.get("applied", 0) + 1
        save(state)
        return 0
    return 1


def ipmitool(state, item, args):
    ipmi = item["ipmi"]
    lan, users = ipmi["lan"], ipmi["users"]
    if args[:2] == ["-I", "lanplus"]:   # over the network to the BMC: address, LAN access, user and password
        if "-a" not in args or "-P" in args or "-E" in args:
            print("fake ipmitool wants the password prompted (-a)", file=sys.stderr)
            return 9
        target, name = args[args.index("-H") + 1], args[args.index("-U") + 1]
        typed = getpass.getpass("Password: ")
        uid = next((key for key, user in users.items() if user.get("name") == name), None)
        user = users.get(uid, {})
        if (lan["ip"] != target or ipmi.get("access", "always available") != "always available"
                or ipmi.get("lan_sessions_fail") or not user.get("enabled") or not user.get("ipmi")
                or ipmi["passwords"].get(uid) != typed):
            print("Error: Unable to establish IPMI v2 / RMCP+ session", file=sys.stderr)
            return 1
        if args[args.index("-a") + 1:] == ["chassis", "power", "status"]:
            print("Chassis Power is on")
            return 0
        return 1
    if ipmi.get("unavailable"):
        print("Could not open device at /dev/ipmi0 or /dev/ipmi/0 or /dev/ipmidev/0: No such file or directory",
              file=sys.stderr)
        return 1
    # ufm01 on 2026-10-20: the iDRAC refused every in-band write (completion code 0xd4).
    if ipmi.get("refuse_writes") and args[:2] in (["lan", "set"], ["user", "set"], ["channel", "setaccess"],
                                                   ["user", "enable"]):
        return 1
    if args[:2] == ["channel", "info"]:
        mode = ipmi.get("access", "always available")
        print(f"Channel 0x{args[2]} info:\n  Channel Medium Type   : 802.3 LAN\n  Volatile(active) Settings\n"
              f"    Access Mode         : {mode}\n  Non-Volatile Settings\n    Access Mode         : {mode}")
        return 0
    if args[:2] == ["lan", "print"]:
        for key, value in (("Set in Progress", "Set Complete"), ("IP Address Source", lan["source"]),
                           ("IP Address", lan["ip"]), ("Subnet Mask", lan["mask"]),
                           ("MAC Address", "02:00:00:00:b0:01"), ("Default Gateway IP", lan["gw"]),
                           ("Default Gateway MAC", "00:00:00:00:00:00")):
            print(f"{key:<24}: {value}")
        return 0
    if args[:2] == ["lan", "set"]:
        rest = args[3:]
        if rest == ["access", "on"]:
            ipmi["access"] = "always available"
            print(f"Set Channel Access for channel {args[2]} was successful.")
        elif rest == ["ipsrc", "static"]:
            lan["source"] = "Static Address"
        elif rest[:1] == ["ipaddr"] and len(rest) == 2:
            lan["ip"] = rest[1]
            print(f"Setting LAN IP Address to {rest[1]}")
        elif rest[:1] == ["netmask"] and len(rest) == 2:
            lan["mask"] = rest[1]
            print(f"Setting LAN Subnet Mask to {rest[1]}")
        elif rest[:2] == ["defgw", "ipaddr"] and len(rest) == 3:
            lan["gw"] = rest[2]
            print(f"Setting LAN Default Gateway IP to {rest[2]}")
        else:
            return 1
        save(state)
        return 0
    if args[:2] == ["user", "list"]:
        print("ID  Name             Callin  Link Auth  IPMI Msg   Channel Priv Limit")
        for number in range(1, 17):
            user = users.get(str(number), {})
            print(f"{number:<4}{user.get('name', ''):<17}{'true':<8}{str(user.get('link', False)).lower():<11}"
                  f"{str(user.get('ipmi', False)).lower():<11}{user.get('priv', 'NO ACCESS')}")
        return 0
    if args[:3] == ["user", "set", "name"] and len(args) == 5:
        users[args[3]] = {"name": args[4], "link": False, "ipmi": False, "priv": "NO ACCESS", "enabled": False}
        if ipmi.get("lose_password_after_create"):   # ufm01 2026-10-21: the first password did not take
            ipmi.setdefault("lose_next", []).append(args[3])
        save(state)
        return 0
    if args[:2] == ["user", "test"] and len(args) == 4:
        typed = getpass.getpass(f"Password for user {args[2]}: ")
        if ipmi["passwords"].get(args[2]) == typed:
            print("Success")
            return 0
        print("Failure: password incorrect")
        return 1
    if args[:3] == ["user", "set", "password"]:
        if len(args) != 4:
            print("fake ipmitool refuses passwords in argv", file=sys.stderr)
            return 9
        first = getpass.getpass(f"Password for user {args[3]}: ")
        second = getpass.getpass(f"Password for user {args[3]}: ")
        if first != second:
            print("Passwords do not match.")
            return 1
        if args[3] in ipmi.get("lose_next", []) or ipmi.get("ignore_passwords"):
            if args[3] in ipmi.get("lose_next", []):
                ipmi["lose_next"].remove(args[3])
        else:
            ipmi["passwords"][args[3]] = first
        save(state)
        print(f"Set User Password command successful (user {args[3]})")
        return 0
    if args[:2] == ["channel", "setaccess"]:
        user = users[args[3]]
        options = dict(value.split("=", 1) for value in args[4:])
        user["link"], user["ipmi"] = options.get("link") == "on", options.get("ipmi") == "on"
        if options.get("privilege") == "4":
            user["priv"] = "ADMINISTRATOR"
        save(state)
        print(f"Set User Access (channel {args[2]} id {args[3]}) successful.")
        return 0
    if args[:2] == ["user", "enable"]:
        users[args[2]]["enabled"] = True
        save(state)
        return 0
    if args[:2] == ["channel", "getaccess"]:
        user = users.get(args[3], {})
        print("Maximum User IDs     : 16")
        print(f"Enabled User IDs     : {sum(1 for value in users.values() if value.get('enabled'))}")
        print()
        for key, value in (("User ID", args[3]), ("User Name", user.get("name", "")), ("Fixed Name", "No"),
                           ("Access Available", "call-in / callback"),
                           ("Link Authentication", "enabled" if user.get("link") else "disabled"),
                           ("IPMI Messaging", "enabled" if user.get("ipmi") else "disabled"),
                           ("Privilege Level", user.get("priv", "NO ACCESS")),
                           ("Enable Status", "enabled" if user.get("enabled") else "disabled")):
            print(f"{key:<21}: {value}")
        return 0
    return 1


FAKE_UPGRADE_SH = "#!/bin/bash\nexec ufm-fake-os-upgrade {version} \"$@\"\n"
FAKE_IMAGE = "fake appliance image\n"
STATUS_LOG = "var/log/ufm_os_upgrade_26.07.24-9_status.log"


def stamp():
    return time.strftime("%Y%m%d-%H_%M_%S")


def ufm_os_upgrade(state, item, base, args):
    """Mimics ufm-os-upgrade.sh from ufm-manual.log, including the reboot and first boot."""
    version, options = args[0], args[1:]
    if options != ["--appliance-sw-upgrade", "-r", "-y"]:
        return 9
    log = os.path.join(base, STATUS_LOG)

    def line(step, outcome):
        with open(log, "a") as handle:
            handle.write(f"{stamp()}: {step:<36}[{outcome:<10}]\n")

    item["os_upgrade_runs"] = item.get("os_upgrade_runs", 0) + 1
    item["upgrade_saw_ufm_enterprise"] = item.get("services", {}).get("ufm-enterprise", "active")
    item["upgrade_tty"] = os.isatty(0)
    save(state)
    line("UFM_OS_UPGRADE", "STARTED")
    if item.get("upgrade_hangs"):
        return 0
    if item.get("upgrade_fails"):
        line("APPLIANCE-UPGRADE", "FAILED")
        return 1
    line("APPLIANCE-UPGRADE", "PASSED")
    line("UFM-OS-UPGRADE", "PASSED")
    state = load()
    state["ufms"][os.environ["FAKE_UFM_NAME"]]["down_sessions"] = 2   # the reboot: next two logins time out
    save(state)
    release = os.path.join(base, "etc/ufm-release")
    text = open(release).read() if os.path.exists(release) else ""
    kept = [entry for entry in text.splitlines() if not entry.startswith("UFM_APPLIANCE=")]
    with open(release, "w") as handle:
        handle.write("\n".join(kept + [f"UFM_APPLIANCE={version}"]) + "\n")
    for relative, text in item.get("upgrade_resets", {}).items():
        with open(os.path.join(base, relative), "w") as handle:
            handle.write(text)
    line("UFM-OS-FIRSTBOOT", "PASSED")
    return 0


def systemd_run(args):
    index, delay = 0, 0
    while index < len(args) and args[index].startswith("--"):
        if args[index] == "--unit":
            index += 1
        elif args[index].startswith("--on-active="):
            delay = int(args[index].split("=", 1)[1])
        index += 1
    command = args[index:]
    if os.fork() == 0:
        os.setsid()
        null = os.open(os.devnull, os.O_RDWR)
        for descriptor in (0, 1, 2):
            os.dup2(null, descriptor)
        time.sleep(delay)
        os.execvp(command[0], command)
    return 0


def ping_ok(state, item, args):
    target, device = args[-1], args[args.index("-I") + 1] if "-I" in args else None
    if device == MGMT:
        local = {"oper": "up", "addrs": item.get("ipv4", "").split()}
    else:
        local = item.get("ifaces", {}).get(device, {}) if device else {"oper": "up", "addrs": ["any"]}
    if local.get("oper") != "up" or not local.get("addrs"):
        return False
    for other in state["ufms"].values():
        if other is item:
            continue
        if device in (None, MGMT) and target in [value.split("/")[0] for value in other.get("ipv4", "").split()]:
            return True
        # back-to-back links: only the same-named interface on the peer answers
        for peer_device, info in other.get("ifaces", {}).items():
            if (device in (None, peer_device) and info.get("oper") == "up"
                    and target in [value.split("/")[0] for value in info.get("addrs", [])]):
                return True
    host = state.get("lan_hosts", {}).get(target)
    return bool(host and host.get("icmp", True) and device in (None, MGMT))


def short(item):
    return item.get("hostname", "").split(".")[0]


def first_address(text):
    return text.split()[0].split("/")[0] if text.split() else ""


def ha_status_text(state, ha):
    """`ufm_ha_cluster status` in the Pacemaker 2 layout ufm01 printed on 2026-10-22. Before
    `ufm_ha_cluster start` the layout is inferred: the resources are Stopped (disabled)."""
    master, standby = state["ufms"][ha["master"]], state["ufms"][ha["standby"]]
    m, s = ha.get("names", [short(master), short(standby)])
    synced = ha.get("sync_left", 0) <= 0
    if ha.get("started"):
        clone = f"    * Promoted: [ {m} ]\n    * Unpromoted: [ {s} ]"
        running = f"Started {m}"
        enterprise = "Stopped" if master.get("ha_enterprise_fails") else running
    else:
        clone = f"    * Stopped (disabled): [ {m} {s} ]"
        running = enterprise = "Stopped (disabled)"
    return f"""Reading configuration from /var/lib/ufm_ha/ha_state
Loading enabled add-ons from registry
Cluster name: ufmcluster
Cluster Summary:
  * Stack: corosync (Pacemaker is running)
  * Current DC: {m} (version 2.1.6-6fdc9deea29) - partition with quorum
  * 2 nodes configured
  * 7 resource instances configured

Node List:
  * Online: [ {m} {s} ]

Full List of Resources:
  * Clone Set: ha_data_drbd-clone [ha_data_drbd] (promotable):
{clone}
  * Resource Group: ufmcluster-grp:
    * ha_data_file_system       (ocf:heartbeat:Filesystem):      {running}
    * cluster_virtual_ip_0      (ocf:heartbeat:IPaddr2):         {running}
    * ufm-ha-watcher    (systemd:ufm-ha-watcher):        {running}
    * ufm-enterprise    (systemd:ufm-enterprise):        {enterprise}
  * ha-monitor  (systemd:ha-monitor):    {running}

Daemon Status:
  corosync: active/enabled
  pacemaker: active/enabled
  pcsd: active/enabled

DRBD Status:
  DRBD_RESOURCE:              [ha_data]
  DRBD_CONNECTIVITY:          [{'Connected' if synced else 'SyncSource'}]
  DISK_STATE:                 [UpToDate]
  DRBD_ROLE:                  [Primary]
  PEER_DISK_STATE:            [{'UpToDate' if synced else 'Inconsistent'}]
  PEER_DRBD_ROLE:             [Secondary]
VIRTUAL_IP:                   [{ha['vip']}]"""


def ufm_ha_cluster(state, item, name, args):
    """`ufm_ha_cluster config/start/status` as the owner ran them on 2026-10-22."""
    ha = state.get("ha", {})
    if args[:1] == ["config"]:
        options = dict(zip(args[1::2], args[2::2]))
        role = options.get("-r")
        item.setdefault("ha_config_calls", []).append(args[1:])
        item["ha_config_stdout_tty"] = os.isatty(1)
        item["ha_saw_ufm_enterprise"] = item.get("services", {}).get("ufm-enterprise", "active")
        state.setdefault("ha_order", []).append(f"{name}:{role}")
        save(state)
        print(f"Assigning CLI IPs to nodes (role: {role})")
        print("Setting Cluster Password")
        # passwd fed by the tool itself; a session that saw this line would take it for a password change
        print(": ".join(["New password", "Retype new password", "passwd", "password updated successfully"]))
        if item.get("ha_config_fails"):
            print("Error: DRBD preflight validation failed (fake)")
            return 1
        peer_name = next(key for key in state["ufms"] if key != name)
        peer = state["ufms"][peer_name]
        expected = {"--local-primary-ip": first_address(" ".join(item["ifaces"]["eno8403"]["addrs"])),
                    "--peer-primary-ip": first_address(" ".join(peer["ifaces"]["eno8403"]["addrs"])),
                    "--local-secondary-ip": first_address(item["ipv4"]),
                    "--peer-secondary-ip": first_address(peer["ipv4"])}
        wrong = {key: options.get(key) for key, value in expected.items() if options.get(key) != value}
        if wrong or role not in ("standby", "master") or ("--virtual-ip" in options) != (role == "master"):
            print(f"Error: unexpected arguments (fake): {wrong}")
            return 2
        if role == "standby":
            state["ha"] = {"standby": name}
        else:
            if ha.get("standby") != peer_name:
                print("Error: the peer is not configured as standby (fake)")
                return 1
            state["ha"] = dict(ha, master=name, vip=options["--virtual-ip"], started=False,
                               sync_left=state.get("ha_sync_polls", 2))
        save(state)
        print("[*] Configuring HA cluster done.")
        if role == "master":
            print("Once DRBD sync is completed, you can start HA cluster using: ufm_ha_cluster start")
        return 0
    if args == ["failover"]:
        if ha.get("master") != name or not ha.get("started"):
            print("Error: this node is not the HA master (fake)")
            return 1
        old, new = state["ufms"][name], state["ufms"][ha["standby"]]
        old["ipv4"] = " ".join(value for value in old["ipv4"].split() if not value.startswith(ha["vip"] + "/"))
        new["ipv4"] = f"{new['ipv4']} {ha['vip']}/23"
        ha["master"], ha["standby"] = ha["standby"], name
        ha["failovers"] = ha.get("failovers", 0) + 1
        load_shared_configuration(state, ha)
        save(state)
        print("Cleaned up all resources on all nodes")
        print("Migration will take effect until: 2026-10-22 06:35:59Z")
        return 0
    if args == ["start"]:
        if ha.get("master") != name:
            print("Error: HA cluster is not configured on this node (fake)")
            return 1
        ha["started"] = True
        load_shared_configuration(state, ha)
        if not item.get("ha_enterprise_fails"):
            item.setdefault("services", {})["ufm-enterprise"] = "active"
        item["ipv4"] = f"{item['ipv4']} {ha['vip']}/23"   # IPaddr2 adds the VIP on the management port
        save(state)
        return 0
    if args == ["status"]:
        if not ha.get("master") or name not in (ha["master"], ha["standby"]):
            # inferred: on a node without a cluster pcs cannot read the cluster information base
            print("Error: error running crm_mon, is pacemaker running?")
            return 1
        print(ha_status_text(state, ha))
        return 0
    return 2


def load_shared_configuration(state, ha):
    """ufm-enterprise starting on the master reads gv.cfg and the licenses from /opt/ufm/files; with
    multi_port_sm = ha_enabled and ib1 added, opensm runs on both smi ports (ufm-manual.log 2085-2087)."""
    files = os.path.join(shared_dir(), "opt/ufm/files")
    gv = open(os.path.join(files, "conf/gv.cfg")).read() if os.path.exists(os.path.join(files, "conf/gv.cfg")) else ""
    master = state["ufms"][ha["master"]]
    lines = [f'{master.get("hca_guid", "0x0200000000000a01")}, VALID    , MAIN     ,    0, "smi0:1"']
    if "multi_port_sm = ha_enabled" in gv and "additional_fabric_interfaces = ib1" in gv:
        lines.append(f'{master.get("hca_guid2", "0x0200000000000a02")}, VALID    , AUXILIARY,    0, "smi1:1"')
    os.makedirs(os.path.join(files, "log"), exist_ok=True)
    with open(os.path.join(files, "log/opensm-smdb.dump"), "w") as handle:
        handle.write("\n".join(lines) + "\n")
    licenses = os.path.join(files, "licenses")
    ha["loaded_licenses"] = sorted(os.listdir(licenses)) if os.path.isdir(licenses) else []


def docker(state, name, args):
    """`docker exec ufm ...` on the HA master: ibswitches and ufmlicense."""
    ha = state.get("ha", {})
    if args[:2] != ["exec", "ufm"] or ha.get("master") != name or not ha.get("started"):
        print("Error response from daemon: container ufm is not running", file=sys.stderr)
        return 1
    # the fake bash moved /opt/ufm/ into the sandbox, so match on the end of the path
    if len(args) == 3 and args[2].endswith("/opt/ufm/opensm/sbin/ibswitches"):
        print("src/query_smp.c:199; umad (DR path slid 0; dlid 0; 0,1,75) bad status 110; Connection timed out",
              file=sys.stderr)
        for guid, description in state.get("fabric", []):
            print(f'Switch  : {guid} ports 149 "{description}" enhanced port 0 lid 11 lmc 0')
        return 0
    if args[2:] == ["ufmlicense"]:
        rule = "|" + "-" * 120 + "|"
        print(rule)
        print("|   Customer ID   |     SN     |        swName      |        Type         |   MAC Address   "
              "|   Exp. Date   |Limit| Functionality | Status |")
        print(rule)
        print("|986799359        |1234567899  |UFM Enterprise      |Evaluation           |NA               "
              "|2026-11-21     |1024 |Advanced       |Valid   |")
        for _license in ha.get("loaded_licenses", []):
            for node in sorted(state["ufms"]):
                status = "Valid" if node == ha["master"] else "Invalid"
                print(f"|986799359        |7777777777  |UFM Enterprise      |Subscription         "
                      f"|{state['ufms'][node]['reported_mac']}|2027-10-21     |1024 |Advanced       |{status}   |")
        print(rule)
        return 0
    print(f"fake docker: unsupported {args}", file=sys.stderr)
    return 2


def drbdadm(state, name):
    ha = state.get("ha", {})
    if ha.get("master") != name:
        print("ha_data: No such resource")
        return 10
    left = ha.get("sync_left", 0)
    if left > 0:
        ha["sync_left"] = left - 1
        save(state)
        print(f"ha_data role:Primary\n  disk:UpToDate\n  peer role:Secondary\n"
              f"    replication:SyncSource peer-disk:Inconsistent done:{100 - 10 * min(left, 9):.2f}")
    else:
        print("ha_data role:Primary\n  disk:UpToDate\n  peer role:Secondary\n"
              "    replication:Established peer-disk:UpToDate")
    return 0


def main():
    tool, args = os.path.basename(sys.argv[0]), sys.argv[1:]
    if tool == "nohup":
        import signal
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
        os.execvp(args[0], args)
    if tool == "timeout":
        index = 0
        while args[index].startswith("-"):
            index += 2 if args[index] in ("-k", "-s") else 1
        os.execvp(args[index + 1], args[index + 1:])
    name = os.environ["FAKE_UFM_NAME"]
    state = load()
    item, base = state["ufms"][name], base_dir(name)
    if tool == "ufm_ha_cluster":
        return ufm_ha_cluster(state, item, name, args)
    if tool == "drbdadm" and args == ["status"]:
        return drbdadm(state, name)
    if tool == "docker":
        return docker(state, name, args)
    if tool == "ufm_enterprise_sanity.sh":
        print("Checking Service...")
        if state.get("sanity_fails") or not state.get("ha", {}).get("started"):
            print("Failed")
            return 1
        print("Done\nChecking Images...\nDone\nChecking Containers...\nDone\nChecking ufm REST server...\nDone")
        print("Sanity tests completed successfully!")
        return 0
    if tool == "wget" and "--spider" in args:
        if args[-1] != state.get("image_url"):
            return 8
        if "-S" in args:
            print(f"  HTTP/1.1 200 OK\n  Content-Length: {len(FAKE_IMAGE)}", file=sys.stderr)
        return 0
    if tool == "wget":
        output, url = args[args.index("-O") + 1], args[-1]
        item.setdefault("wget", []).append(url)
        save(state)
        if url in state.get("served", {}):
            with open(output, "w") as handle:
                handle.write(state["served"][url])
            return 0
        if url != state.get("image_url"):
            print(f"{url}: 404 Not Found", file=sys.stderr)
            return 8
        with open(output, "w") as handle:
            handle.write(FAKE_IMAGE)
        return 0
    if tool == "tar" and args[:1] == ["-C"] and args[2:3] == ["-xf"]:
        image = os.path.basename(args[3])
        folder = os.path.join(args[1], image[:-len(".tar")])
        version = image[len("ufm-appliance-"):-len("-omu.x86_64.tar")]
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, "ufm-os-upgrade.sh"), "w") as handle:
            handle.write(FAKE_UPGRADE_SH.format(version=version))
        item["extracted"] = item.get("extracted", 0) + 1
        save(state)
        return 0
    if tool == "ufm-fake-os-upgrade":
        return ufm_os_upgrade(state, item, base, args)
    if tool == "systemd-run":
        return systemd_run(args)
    if tool == "arping" and "-D" in args:
        return 1 if args[-1] in state.get("lan_hosts", {}) else 0   # DAD: 0 means nobody answered
    if tool == "ibstat":
        for number, physical in enumerate(item.get("ib_ports", []), 1):
            print(f"CA 'mlx5_{number - 1}'\n\tPort 1:\n\t\tState: Initializing\n\t\tPhysical state: {physical}")
        return 0
    if tool == "hostname":
        print(item.get("hostname", "localhost"))
        return 0
    if tool == "hostnamectl" and args[:1] == ["set-hostname"] and len(args) == 2:
        item["hostname"] = args[1]
        save(state)
        return 0
    if tool == "ip":
        if args[:4] == ["-4", "-o", "addr", "show"] and args[4:5] == ["dev"]:
            device = args[5]
            if device == MGMT:
                addresses = item.get("ipv4", "").split()
            else:
                info = item.get("ifaces", {}).get(device, {})
                addresses = info.get("addrs", []) if info.get("oper") == "up" else []
            for value in addresses:
                print(f"2: {device}    inet {value} scope global {device}")
            return 0
        if args == ["-4", "-o", "addr", "show"]:
            for device, values in [(MGMT, item.get("ipv4", "").split())] + [
                    (device, info.get("addrs", [])) for device, info in item.get("ifaces", {}).items()]:
                for value in values:
                    print(f"2: {device}    inet {value} scope global {device}")
            return 0
        if args[:3] == ["route", "show", "default"]:
            if item.get("default"):
                print(item["default"])
            return 0
        if args[:3] == ["neigh", "flush", "to"] and args[4:5] == ["dev"]:
            item.get("stale_neigh", {}).pop(args[3], None)
            save(state)
            return 0
        if args[:2] == ["neigh", "show"] and args[3:4] == ["dev"]:
            host = state.get("lan_hosts", {}).get(args[2])
            stale = item.get("stale_neigh", {}).get(args[2])   # cache left by a VIP that was just removed
            if host and args[4] == MGMT:
                print(f"{args[2]} dev {MGMT} lladdr {host['mac']} REACHABLE")
            elif stale and args[4] == MGMT:
                print(f"{args[2]} dev {MGMT} lladdr {stale} REACHABLE")
            elif args[2] in item.get("probed", []):
                print(f"{args[2]} dev {args[4]} FAILED")
            return 0
        return 1
    if tool == "netplan":
        return netplan(state, item, base, args)
    if tool == "ipmitool":
        return ipmitool(state, item, args)
    if tool == "systemctl":
        return systemctl(state, item, args)
    if tool == "timedatectl":
        if args == ["show", "-p", "Timezone", "--value"]:
            print(item.get("timezone", "Etc/UTC"))
            return 0
        if args == ["show", "-p", "NTPSynchronized", "--value"]:
            print(item.get("ntp_synced", "no"))
            return 0
        if args[:1] == ["set-timezone"] and len(args) == 2:
            item["timezone"] = args[1]
            save(state)
            return 0
        return 1
    if tool == "ssh-keygen" and args[:2] == ["-q", "-t"] and "-f" in args:
        path = args[args.index("-f") + 1]
        with open(path, "w") as handle:
            handle.write("PRIVATE KEY\n")
        with open(path + ".pub", "w") as handle:
            handle.write(f"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI{name.upper()}KEY root@{item.get('hostname')}\n")
        return 0
    if tool == "ssh":
        target = next(value for value in args if "@" in value)
        peer_ip = target.split("@", 1)[1]
        peer = next((key for key, value in state["ufms"].items() if value.get("answers_on") == peer_ip), None)
        if peer is None:
            print(f"ssh: connect to host {peer_ip} port 22: Connection timed out", file=sys.stderr)
            return 255
        own = os.path.join(base, "root/.ssh/id_ed25519.pub")
        blob = open(own).read().split()[1] if os.path.exists(own) else None
        peer_keys = os.path.join(base_dir(peer), "root/.ssh/authorized_keys")
        known = os.path.join(base, "root/.ssh/known_hosts")
        recorded = os.path.exists(known) and f"{peer_ip} " in open(known).read()
        if not recorded and "StrictHostKeyChecking=accept-new" not in args:
            # real ssh prints this regardless of LogLevel=ERROR
            print(f"No ED25519 host key is known for {peer_ip}.\nHost key verification failed.", file=sys.stderr)
            return 255
        if not blob or not os.path.exists(peer_keys) or blob not in open(peer_keys).read():
            print(f"{target}: Permission denied (publickey).", file=sys.stderr)
            return 255
        if not recorded:
            with open(known, "a") as handle:
                handle.write(f"{peer_ip} ssh-ed25519 HOSTKEY{peer}\n")
            if "LogLevel=ERROR" not in args:
                print(f"Warning: Permanently added '{peer_ip}' (ED25519) to the list of known hosts.",
                      file=sys.stderr)
        remote = args[args.index(target) + 1:]
        if remote != ["ip", "-o", "addr", "show"]:
            print(f"fake peer ssh: unsupported remote command {remote}", file=sys.stderr)
            return 127
        other = state["ufms"][peer]
        rows = [(MGMT, value) for value in other.get("ipv4", "").split()] + [
            (device, value) for device, info in other.get("ifaces", {}).items() for value in info.get("addrs", [])]
        for index, (device, value) in enumerate(rows, 2):
            print(f"{index}: {device}    inet {value} scope global {device}\\       valid_lft forever")
        return 0
    if tool == "ping":
        item.setdefault("probed", []).append(args[-1])
        save(state)
        return 0 if ping_ok(state, item, args) else 1
    if tool == "getent" and args[:1] == ["hosts"] and len(args) == 2:
        if args[1] == item.get("hostname"):
            print(f"198.19.0.1  {args[1]}")   # systemd-resolved synthesises the local host name
            return 0
        for line in open(os.path.join(base, "etc/hosts")).read().splitlines():
            if args[1] in line.split()[1:]:
                print(line)
                return 0
        return 2
    if tool == "sha256sum" and not args:
        print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest() + "  -")
        return 0
    if tool == "sha256sum" and args == ["-c", "--status"]:
        valid = True
        for line in sys.stdin.read().splitlines():
            digest, path = line.split(None, 1)
            valid &= hashlib.sha256(open(path.strip(), "rb").read()).hexdigest() == digest
        return 0 if valid else 1
    if tool == "setsid":
        os.setsid()
        os.execvp(args[0], args)
    if tool == "bash" and args and os.path.isfile(args[0]):
        descriptor, temporary = tempfile.mkstemp(suffix=".sh")
        os.write(descriptor, rewrite(open(args[0]).read(), base).encode())
        os.close(descriptor)
        os.execv("/bin/bash", ["/bin/bash", temporary] + args[1:])
    print(f"fake tool: unsupported {tool} {args}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
'''
FAKE_TOOL_NAMES = ("hostname", "hostnamectl", "ip", "netplan", "ipmitool", "sha256sum", "setsid", "bash",
                   "systemctl", "timedatectl", "getent", "ssh-keygen", "ssh", "ping", "wget", "tar",
                   "systemd-run", "ufm-fake-os-upgrade", "ibstat", "arping",
                   "ufm_ha_cluster", "drbdadm", "ufm_enterprise_sanity.sh", "nohup", "timeout", "docker")
TEST_KEY_BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAITESTKEYmgmtserver"
UBUNTU_RESOLVED = "[Resolve]\n#DNS=\n#FallbackDNS=\n#Domains=\n#DNSSEC=no\n"
UBUNTU_TIMESYNCD = "[Time]\n#NTP=\n#FallbackNTP=ntp.ubuntu.com\n#RootDistanceMaxSec=5\n"
UFM_RELEASE_SHIPPED = "UFM_OS=25.10.24-9\nUFM_APPLIANCE=2.3.1-8\nUFM_ENTERPRISE=6.23.1-6\nUFM_HA=6.1.1-2\n"
IMAGE_URL = "http://198.51.103.200:8088/image/ufm-appliance-2.6.1-8-omu.x86_64.tar"
# /opt/ufm/files/conf/gv.cfg as shipped, abridged (ufm-manual.log 1180-1187 shows the [Server] keys)
GV_CFG_SHIPPED = """[Server]
fabric_interface = ib0
# disabled (default) | enabled (configure opensm with multiple GUIDs) | ha_enabled (configure multiport SM with high availability).
multi_port_sm = disabled
# When enabling multi_port_sm, specify here the additional fabric interfaces for OpenSM conf.
additional_fabric_interfaces =
ws_port = 8000

[Logging]
level = INFO
"""
OPENSM_CONF = ("root_guid_file /opt/ufm/files/conf/opensm/root_guid.conf\n"
               "# 0x2 - The root_guid_file is complete for all ranks.\n")
LICENSE_TEXT = "fixture license, not a real one\n"
LICENSE_URL = "http://198.51.103.200:8088/image/site.lic"
SPINE = "ew-spine001.site01.example.test"   # the ib row in OTHER_ROWS
# ibswitches as on ufm01: one Q3400 has four ASICs (U1-U4); listed out of order on purpose
FABRIC = [["0x02000000000001a1", f"MF0;{SPINE}:Q3400_RA/U2"], ["0x02000000000001a0", f"MF0;{SPINE}:Q3400_RA/U1"],
          ["0x02000000000002b0", "MF0;ew-leaf001.site01.example.test:Q3400_RA/U1"]]


def ufm_state(lladdr, password, expired, mac):
    """A freshly racked UFM: no IPv4, DHCP IPMI with only root, links as in ufm-manual.log."""
    return {"lladdr": lladdr, "password": password, "expired": expired, "reported_mac": mac,
            "ipv4": "", "answers_on": "", "hostname": "localhost", "default": "",
            "ifaces": {"eno8403": {"mac": "02:00:00:00:02:02", "oper": "up", "addrs": []},
                       "ib0": {"mac": "02:00:00:00:1b:00", "oper": "down", "addrs": []},
                       "ib1": {"mac": "02:00:00:00:1b:01", "oper": "down", "addrs": []}},
            "ipmi": {"lan": {"source": "DHCP Address", "ip": "0.0.0.0", "mask": "0.0.0.0", "gw": "0.0.0.0"},
                     "users": {"2": {"name": "root", "link": True, "ipmi": True, "priv": "ADMINISTRATOR",
                                     "enabled": True}},
                     "passwords": {}},
            "services": {"ufm-enterprise": "active"}, "ib_ports": [],
            "files": {"etc/systemd/resolved.conf": UBUNTU_RESOLVED,
                      "etc/systemd/timesyncd.conf": UBUNTU_TIMESYNCD,
                      "etc/hosts": "127.0.0.1\tlocalhost\n",
                      "etc/ufm-release": UFM_RELEASE_SHIPPED,
                      "usr/share/zoneinfo/Etc/UTC": "TZif2\n"}}


class FakeSshCase(unittest.TestCase):
    NEW, FACTORY, LEAF, OTHER = "New-Pw-2026!", "Factory-Pw-1", "Leaf-Pw-9", "Someone-Else-Pw"
    CSV_ROWS = None

    def switches(self):
        return {"203.0.112.119": switch_state("oob-leaf117", LEAF_INTERFACES, LEAF_LINKS, LEAF_FDB, LEAF_NEIGH,
                                               LEAF_ADDRESSES_V4, reach=[UFM01_LL, UFM02_LL])}

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        (base / "inputs").mkdir()
        self.inputs = make_inputs(base / "inputs", csv_rows=self.CSV_ROWS)
        self.bin = base / "bin"
        self.bin.mkdir()
        fake = self.bin / "ssh"
        fake.write_text(FAKE_SSH.replace("{python}", sys.executable), encoding="utf-8")
        fake.chmod(0o755)
        self.devbin = base / "devbin"
        self.devbin.mkdir()
        tool = self.devbin / "_ufm_tool.py"
        tool.write_text(FAKE_TOOL.replace("{python}", sys.executable), encoding="utf-8")
        tool.chmod(0o755)
        for name in FAKE_TOOL_NAMES:
            (self.devbin / name).symlink_to("_ufm_tool.py")
        self.sandbox = base / "sandbox"
        self.state_path = base / "state.json"
        self.state = {
            "leaf_password": self.LEAF,
            "switches": self.switches(),
            "ufms": {
                "ufm01": ufm_state(UFM01_LL, self.NEW, False, "02:00:00:00:01:01"),
                "ufm02": ufm_state(UFM02_LL, self.FACTORY, True, "02:00:00:00:02:01"),
            },
        }
        self.old_env = {key: os.environ.get(key) for key in (
            "PATH", "FAKE_UFM_STATE", "FAKE_UFM_BIN", "FAKE_UFM_SANDBOX", "FAKE_LOCAL_KEY_BLOB")}
        os.environ["FAKE_LOCAL_KEY_BLOB"] = TEST_KEY_BLOB
        os.environ["PATH"] = f"{self.bin}{os.pathsep}{os.environ.get('PATH', '')}"
        os.environ["FAKE_UFM_STATE"] = str(self.state_path)
        os.environ["FAKE_UFM_BIN"] = str(self.devbin)
        os.environ["FAKE_UFM_SANDBOX"] = str(self.sandbox)

    def tearDown(self):
        for key, value in self.old_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.tmp.cleanup()

    def run_login(self, allow_change=True, choose=None, action="login", ipmi_password="", upgrade_wait=(1, 1, 30),
                  apply=True, confirm=None, factory=None, ask_continue=None, confirm_new_password=None,
                  eth_password=None, ask_eth=None, ha_wait=(0, 60, 0, 60)):
        if not self.state_path.exists():
            self.state.setdefault("image_url", IMAGE_URL)
            self.state_path.write_text(json.dumps(self.state), encoding="utf-8")
        plan = ufm.build_plan(self.inputs)
        self.assertEqual(plan.errors, [])
        self.run_dir = run_dir = Path(self.tmp.name) / f"run-{len(os.listdir(self.tmp.name))}"
        run_dir.mkdir()
        lines = []
        creds = ufm.Credentials("root", self.NEW, self.FACTORY if factory is None else factory, "cumulus",
                                ipmi_password=ipmi_password, eth_password=eth_password)
        session = ufm.Session(plan, creds, 5, run_dir, lines.append, ask_eth or (lambda: self.LEAF),
                              choose=choose or (lambda items: items[0]), apply_wait=(4, 1, 8),
                              ask_ufm_password=lambda: self.NEW, upgrade_wait=upgrade_wait,
                              apply=apply, confirm=confirm, ask_continue=ask_continue,
                              confirm_new_password=confirm_new_password, ha_wait=ha_wait)
        self.session = session
        if action in ("trust", "ha_setup", "check", "config_upgrade_all", "ha_post_config_command"):
            results = {item.hostname.split(".")[0]: item for item in getattr(session, action)(plan.nodes)}
        else:
            results = {node.hostname.split(".")[0]: getattr(session, action)(node, allow_change)
                       for node in plan.nodes}
        calls_path = Path(str(self.state_path) + ".calls")
        calls = [json.loads(line) for line in calls_path.read_text().splitlines()] if calls_path.exists() else []
        logs = "".join(path.read_text(encoding="utf-8") for path in run_dir.iterdir())
        return results, json.loads(self.state_path.read_text()), calls, logs + "\n".join(lines)


class SimulatedLoginTest(FakeSshCase):
    def test_leaf_with_ipv4_svi_is_the_jump(self):
        results, _state, calls, _logs = self.run_login()
        self.assertEqual({short: (item.status, item.route["jump"], item.route["reason"], item.route["port"])
                          for short, item in results.items()},
                         {"ufm01": ("VERIFIED", "oob-leaf117", "LEAF", "swp17"),
                          "ufm02": ("VERIFIED", "oob-leaf117", "LEAF", "swp18")})

    def test_access_port_down_stops_before_any_ufm_login(self):
        self.state["switches"]["203.0.112.119"]["interfaces"] = nv_interface_table([
            ("swp17", "down", "", ""), ("swp18", "up", "", "")])
        results, _state, calls, _logs = self.run_login()
        self.assertEqual(results["ufm01"].status, "OOB_DISCOVERY_FAILED")
        self.assertIn("swp17", results["ufm01"].detail)
        self.assertFalse([c for c in calls if UFM01_LL in c["remote"]])
        self.assertEqual(results["ufm02"].status, "VERIFIED")

    def test_unreachable_ipv4_falls_back_to_oob_and_completes_forced_change(self):
        results, state, calls, logs = self.run_login()
        one, two = results["ufm01"], results["ufm02"]
        self.assertEqual((one.status, one.path, one.password), ("VERIFIED", "OOB-IPv6", "new"))
        self.assertEqual(one.neighbor, {"ipv6": UFM01_LL, "interface": "vlan1000", "vrf": "oob", "source": "FDB_EUI64"})
        self.assertEqual((two.status, two.path, two.password), ("VERIFIED", "OOB-IPv6", "changed"))
        self.assertEqual(two.neighbor["source"], "ND")
        # The forced change is detected first without answering it, confirmed (--apply), then performed.
        self.assertEqual([(a["path"], a["password"], a["outcome"]) for a in two.attempts], [
            ("IPv4", "new", "UNREACHABLE"),
            ("OOB-IPv6", "new", "AUTH_REJECTED"),
            ("OOB-IPv6", "factory", "PASSWORD_CHANGE_REQUIRED"),
            ("OOB-IPv6", "factory", "PASSWORD_CHANGED"),
            ("OOB-IPv6", "new", "OK"),
        ])
        self.assertEqual((state["ufms"]["ufm02"]["password"], state["ufms"]["ufm02"]["expired"]), (self.NEW, False))
        snapshots = [c for c in calls if c["target"].startswith("cumulus@") and "ip -j address show" in c["remote"]]
        self.assertEqual(len(snapshots), 1, "leaf tables must be collected once per leaf")
        for secret in (self.NEW, self.FACTORY, self.LEAF):
            self.assertNotIn(secret, logs)

    def test_forced_change_is_not_performed_without_permission(self):
        results, state, _calls, _logs = self.run_login(allow_change=False)
        self.assertEqual(results["ufm02"].status, "PASSWORD_CHANGE_REQUIRED")
        self.assertEqual((state["ufms"]["ufm02"]["password"], state["ufms"]["ufm02"]["expired"]),
                         (self.FACTORY, True))
        self.assertEqual(results["ufm01"].status, "VERIFIED")

    def test_keyboard_interactive_retry_counts_as_a_rejected_password(self):
        # Docker finding S1: sshd re-asks "(root@host) Password:" after a wrong password.
        self.state["ufms"]["ufm02"]["kbd_interactive"] = True
        results, state, _calls, _logs = self.run_login()
        two = results["ufm02"]
        self.assertEqual(two.status, "VERIFIED", two.detail)
        self.assertEqual([(a["password"], a["outcome"]) for a in two.attempts if a["path"] == "OOB-IPv6"], [
            ("new", "AUTH_REJECTED"), ("factory", "PASSWORD_CHANGE_REQUIRED"), ("factory", "PASSWORD_CHANGED"),
            ("new", "OK")])
        self.assertEqual(state["ufms"]["ufm02"]["password"], self.NEW)

    def test_pam_unix_rejection_of_a_short_new_password_stops_at_once(self):
        # Docker finding S4: Ubuntu's pam_unix says "You must choose a longer password."
        self.state["ufms"]["ufm02"]["min_length"] = 20
        results, state, _calls, _logs = self.run_login()
        two = results["ufm02"]
        self.assertEqual(two.status, "NEW_PASSWORD_REJECTED")
        self.assertIn("You must choose a longer password", two.detail)
        self.assertEqual((state["ufms"]["ufm02"]["password"], state["ufms"]["ufm02"]["expired"]),
                         (self.FACTORY, True))

    def test_management_mac_mismatch_stops(self):
        self.state["ufms"]["ufm01"]["reported_mac"] = "02:00:00:00:01:02"
        results, _state, _calls, _logs = self.run_login()
        self.assertEqual(results["ufm01"].status, "IDENTITY_MISMATCH")

    def test_reachable_ipv4_never_touches_the_leaf(self):
        for item, address in (("ufm01", "198.51.101.130/23"), ("ufm02", "198.51.101.132/23")):
            self.state["ufms"][item].update(answers_on=address.split("/")[0], ipv4=address,
                                            expired=False, password=self.NEW)
        results, _state, calls, _logs = self.run_login()
        self.assertEqual({r.status for r in results.values()}, {"VERIFIED"})
        self.assertEqual({r.path for r in results.values()}, {"IPv4"})
        self.assertFalse([c for c in calls if c["target"].startswith("cumulus@")])

    def test_ipv4_authentication_rejection_does_not_switch_path(self):
        self.state["ufms"]["ufm01"].update(answers_on="198.51.101.130", ipv4="198.51.101.130/23")
        self.state["ufms"]["ufm01"]["password"] = self.OTHER
        results, _state, calls, _logs = self.run_login()
        self.assertEqual(results["ufm01"].status, "AUTH_REJECTED")
        self.assertEqual([(a["path"], a["password"]) for a in results["ufm01"].attempts],
                         [("IPv4", "new"), ("IPv4", "factory")])
        self.assertFalse([c for c in calls if c["target"].startswith("cumulus@")
                          and UFM01_LL in c["remote"]])

    def test_ipv4_address_not_on_management_interface_stops(self):
        self.state["ufms"]["ufm01"].update(answers_on="198.51.101.130", ipv4="198.18.0.5/24")
        results, _state, _calls, _logs = self.run_login()
        self.assertEqual(results["ufm01"].status, "IDENTITY_MISMATCH")
        self.assertEqual([a["path"] for a in results["ufm01"].attempts], ["IPv4"])


class SpineDirectTest(unittest.TestCase):
    def plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            return ufm.build_plan(make_inputs(tmp, csv_rows=OTHER_ROWS + SPINE_ROWS + [UFM01, UFM02]))

    def test_spine_rows_log_in_through_eth0_or_their_single_vlan_svi(self):
        plan = self.plan()
        self.assertEqual(plan.errors, [])
        self.assertEqual(plan.transits["oob-spine01"][0].login_ip, "203.0.113.201")
        self.assertEqual(plan.transits["oob-spine02"][0].login_ip, "203.0.113.202")

    def test_default_spine_inventory_and_explicit_names(self):
        plan = self.plan()
        self.assertEqual([t.hostname for t in ufm.select_spine_inventory(plan)],
                         ["oob-spine01", "oob-spine02.site01.example.test"])
        self.assertEqual([t.hostname for t in ufm.select_spine_inventory(plan, "oob-leaf115")], ["oob-leaf115"])
        for value in ("unknown", "oob-spine01,oob-spine01"):
            with self.subTest(value=value), self.assertRaises(ufm.UfmError):
                ufm.select_spine_inventory(plan, value)

    def test_lldp_candidates_need_up_remote_host_with_exact_identity(self):
        inventory = ufm.select_spine_inventory(self.plan())
        table = nv_interface_table([("swp49", "down", "oob-spine01", "swp1"),
                                    ("swp50", "up", "oob-spine010", "swp1"),
                                    ("swp51", "up", "OOB-SPINE02", "swp1"),
                                    ("swp52", "up", "oob-spine02.site01.example.test", "swp2")])
        table += " " * 125 + "Description: TO oob-spine01\n"
        self.assertEqual([t.hostname for t in ufm.lldp_spine_candidates(table, inventory)],
                         ["oob-spine02.site01.example.test"])
        self.assertEqual(ufm.lldp_spine_candidates("swp49 up up oob-spine01\n", inventory), [])

    def test_lldp_ambiguous_short_name_fails_closed(self):
        inventory = [ufm.Transit("oob-spine01.a.test", "eth_jump", "192.0.2.1"),
                     ufm.Transit("oob-spine01.b.test", "eth_jump", "192.0.2.2")]
        with self.assertRaises(ufm.UfmError):
            ufm.lldp_spine_candidates(nv_interface_table([("swp49", "up", "oob-spine01", "swp1")]), inventory)

    def test_vrr_macvlan_is_not_an_svi(self):
        self.assertEqual(ufm.vlan_svi_interfaces(SPINE_LINKS, "1000"), ["vlan1000"])
        self.assertEqual(ufm.vlan_svi_interfaces(SPINE_LINKS, "1000", "br_other"), [])
        self.assertEqual(ufm.vlan_svi_interfaces(SPINE_LINKS, "2000"), [])

    def test_svi_readiness_rules(self):
        self.assertTrue(ufm.svi_address_ready(address_rows(("vlan1000", "198.18.0.1/24", "fe80::1", "UP")),
                                              "vlan1000", require_ipv6=True))
        self.assertTrue(ufm.svi_address_ready(address_rows(("vlan1000", "198.18.0.1/24", None, "UP")), "vlan1000"))
        for rows in (address_rows(("vlan1000", None, "fe80::1", "UP")),
                     address_rows(("vlan1000", "198.18.0.1/24", None, "UP")),
                     address_rows(("vlan1000", "198.18.0.1/24", "fe80::1", "DOWN")),
                     address_rows(("vlan1000", None, "fe80::1", "UP"), ("vlan1000-v0", "198.18.0.1/24", None, "UP"))):
            with self.subTest(rows=rows):
                self.assertFalse(ufm.svi_address_ready(rows, "vlan1000", require_ipv6=True))
        tentative = address_rows(("vlan1000", "198.18.0.1/24", "fe80::1", "UP"))
        tentative[0]["addr_info"][1]["flags"] = ["tentative"]
        self.assertFalse(ufm.svi_address_ready(tentative, "vlan1000", require_ipv6=True))

    def test_address_snapshot_must_be_valid(self):
        for text in ("", "{}", "not-json", '[{"ifname":"vlan1000"}]'):
            with self.subTest(text=text), self.assertRaises(ufm.UfmError):
                ufm.parse_oob_addresses(text)

    def test_spine_neighbor_prefers_nd_then_eui64_and_rejects_conflicts(self):
        mac = "02:00:00:00:02:01"
        self.assertEqual(ufm.spine_neighbor(mac, f"{UFM02_LL} dev vlan1000 lladdr {mac} REACHABLE\n", "vlan1000", "oob"),
                         ufm.Neighbor(UFM02_LL, "vlan1000", "oob", "ND"))
        self.assertEqual(ufm.spine_neighbor(mac, "", "vlan1000", "oob"),
                         ufm.Neighbor(UFM02_LL, "vlan1000", "oob", "FDB_EUI64"))
        self.assertEqual(ufm.spine_neighbor(mac, f"{UFM02_LL} dev vlan2000 lladdr {mac} REACHABLE\n",
                                            "vlan1000", "oob").source, "FDB_EUI64")
        with self.assertRaises(ufm.UfmError):
            ufm.spine_neighbor(mac, f"{UFM02_LL} dev vlan1000 lladdr 02:11:22:33:44:55 STALE\n", "vlan1000", "oob")


class SpineJumpLoginTest(FakeSshCase):
    CSV_ROWS = OTHER_ROWS + SPINE_ROWS + [UFM01, UFM02]
    SPINE2 = "oob-spine02.site01.example.test"

    def switches(self):
        spine1 = switch_state("oob-spine01", SPINE_INTERFACES, SPINE_LINKS, "", "",
                              address_rows(("eth0", "203.0.113.201/23", None, "UP"),
                                           ("vlan1000", "198.19.0.201/24", None, "UP"),
                                           ("vlan1000-v0", "198.19.0.1/24", None, "UP")),
                              reach=[UFM01_LL, UFM02_LL])
        spine2 = switch_state("oob-spine02", SPINE_INTERFACES, SPINE_LINKS, "",
                              f"{UFM02_LL} dev vlan1000 lladdr 02:00:00:00:02:01 REACHABLE\n",
                              address_rows(("eth0", "203.0.113.202/23", None, "UP"),
                                           ("vlan1000", "198.19.0.202/24", "fe80::202", "UP")),
                              reach=[UFM01_LL, UFM02_LL])
        leaf = switch_state("oob-leaf117", LEAF_INTERFACES, LEAF_LINKS, LEAF_FDB, LEAF_NEIGH,
                            LEAF_ADDRESSES_NO_V4, reach=[])
        return {"203.0.112.119": leaf, "203.0.113.201": spine1, "203.0.113.202": spine2}

    @staticmethod
    def nested_targets(calls):
        return sorted({c["target"] for c in calls if "ip vrf exec" in c["remote"]})

    def test_leaf_svi_without_ipv4_uses_the_only_qualified_spine_for_both_nodes(self):
        results, _state, calls, _logs = self.run_login()
        for short in ("ufm01", "ufm02"):
            route = results[short].route
            self.assertEqual(results[short].status, "VERIFIED", results[short].detail)
            self.assertEqual((route["leaf"], route["jump"], route["reason"], route["vlan"]),
                             ("oob-leaf117", self.SPINE2, "LEAF_SVI_HAS_NO_IPV4", "1000"))
            self.assertIn("oob-spine01", route["rejected"])
        self.assertEqual(results["ufm02"].neighbor["source"], "ND")
        self.assertEqual(results["ufm01"].neighbor,
                         {"ipv6": UFM01_LL, "interface": "vlan1000", "vrf": "oob", "source": "FDB_EUI64"})
        self.assertEqual(self.nested_targets(calls), ["cumulus@203.0.113.202"])
        for ip in ("203.0.112.119", "203.0.113.201", "203.0.113.202"):
            snapshots = [c for c in calls if c["target"] == f"cumulus@{ip}" and "ip -j address show" in c["remote"]]
            self.assertEqual(len(snapshots), 1, ip)
            self.assertFalse([c for c in calls if c["target"] == f"cumulus@{ip}" and "exec hostname" in c["remote"]],
                             "switch identity is checked by address, never by host name")

    def test_one_random_choice_per_leaf_is_reused_for_the_second_node(self):
        self.state["switches"]["203.0.113.201"]["addresses"] = address_rows(
            ("eth0", "203.0.113.201/23", None, "UP"), ("vlan1000", "198.19.0.201/24", "fe80::201", "UP"))
        picks = []

        def choose(items):
            picks.append([spine.hostname for spine, _neighbor in items])
            return items[-1]
        results, _state, calls, _logs = self.run_login(choose=choose)
        self.assertEqual(picks, [["oob-spine01", self.SPINE2]])
        self.assertEqual({item.route["jump"] for item in results.values()}, {self.SPINE2})
        self.assertEqual(self.nested_targets(calls), ["cumulus@203.0.113.202"])

    def test_missing_leaf_svi_is_reported_as_the_reason(self):
        leaf = self.state["switches"]["203.0.112.119"]
        leaf["links"] = "\n".join(LEAF_LINKS.splitlines()[:9]) + "\n"
        leaf["addresses"] = address_rows(("eth0", "203.0.112.119/23", None, "UP"))
        results, _state, _calls, _logs = self.run_login()
        self.assertEqual({(item.status, item.route["reason"]) for item in results.values()},
                         {("VERIFIED", "LEAF_SVI_MISSING")})

    def test_no_lldp_spine_stops_without_ufm_login(self):
        self.state["switches"]["203.0.112.119"]["interfaces"] = nv_interface_table([
            ("swp17", "up", "", ""), ("swp18", "up", "", "")])
        results, _state, calls, _logs = self.run_login()
        for item in results.values():
            self.assertEqual(item.status, "OOB_DISCOVERY_FAILED")
            self.assertIn("LLDP", item.detail)
        self.assertEqual(self.nested_targets(calls), [])

    def test_a_spine_that_does_not_own_its_login_address_is_rejected(self):
        # Owner 2026-10-19: identity by IP/IPv6 address, never by host name.
        self.state["switches"]["203.0.113.202"]["addresses"] = address_rows(
            ("eth0", "203.0.113.99/23", None, "UP"), ("vlan1000", "198.19.0.202/24", "fe80::202", "UP"))
        results, _state, calls, _logs = self.run_login()
        for item in results.values():
            self.assertEqual(item.status, "OOB_DISCOVERY_FAILED")
            self.assertIn("交换机身份不符", item.route["rejected"][self.SPINE2])
        self.assertEqual(self.nested_targets(calls), [])

    def test_no_qualified_spine_stops_with_each_rejection_reason(self):
        self.state["switches"]["203.0.113.202"]["addresses"] = address_rows(
            ("eth0", "203.0.113.202/23", None, "UP"), ("vlan1000", None, "fe80::202", "UP"))
        results, _state, calls, _logs = self.run_login()
        for item in results.values():
            self.assertEqual(item.status, "OOB_DISCOVERY_FAILED")
            self.assertIn("oob-spine01", item.detail)
            self.assertIn("oob-spine02", item.detail)
        self.assertEqual(self.nested_targets(calls), [])


def desired_netplan(address, ha, ib0, ib1):
    return {"network": {"version": 2, "ethernets": {
        "eno8303": {"dhcp4": False, "addresses": [address], "routes": [{"to": "default", "via": "198.51.101.254"}]},
        "eno8403": {"dhcp4": False, "addresses": [ha]},
        "ib0": {"dhcp4": False, "addresses": [ib0]},
        "ib1": {"dhcp4": False, "addresses": [ib1]}}}}


UFM02_NETPLAN = desired_netplan("198.51.101.132/23", "192.0.2.2/30", "100.126.255.3/16", "100.126.255.4/16")
UFM01_NETPLAN = desired_netplan("198.51.101.130/23", "192.0.2.1/30", "100.126.255.1/16", "100.126.255.2/16")


class InitPureTest(unittest.TestCase):
    def setUp(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.plan = ufm.build_plan(make_inputs(tmp))
        self.nodes = {node.hostname.split(".")[0]: node for node in self.plan.nodes}

    def test_node_netplan_follows_csv_and_role_block(self):
        self.assertEqual(ufm.node_netplan(self.plan, self.nodes["ufm02"]), UFM02_NETPLAN)
        self.assertEqual(ufm.node_netplan(self.plan, self.nodes["ufm01"]), UFM01_NETPLAN)

    def test_infra_settings_come_from_common_switch_system(self):
        self.assertEqual((self.plan.dns, self.plan.ntp, self.plan.timezone),
                         (["160.250.70.5", "160.250.71.202"], ["160.250.71.253", "ntp.ubuntu.com"], "Etc/UTC"))
        with tempfile.TemporaryDirectory() as tmp:
            bad = ufm.build_plan(make_inputs(tmp, global_text=GLOBAL.replace("- 160.250.70.5", "- not-an-ip")))
        self.assertTrue([error for error in bad.errors if "dns" in error], bad.errors)

    def test_only_plain_public_keys_are_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = make_inputs(tmp)
            (directory / "publickey" / "forced.pub").write_text(
                f'command="reboot" ssh-ed25519 {TEST_KEY_BLOB} x\n', encoding="utf-8")
            plan = ufm.build_plan(directory)
        self.assertTrue([error for error in plan.errors if "forced.pub" in error], plan.errors)

    def test_ipmitool_password_prompts_are_answered_from_the_pty_only(self):
        responder = ufm.Responder(ufm_destination="root@198.51.101.132", login_password="pw", new_password="n",
                                  allow_change=False,
                                  extra=(("ipmi", ufm.host.IPMI_PASSWORD_PROMPT, "IpmiPw"),))
        self.assertEqual(responder("Password for user 3: "), "IpmiPw")
        self.assertEqual(responder("Password for user 3: \nPassword for user 3: "), "IpmiPw")

    def test_ipmi_outside_the_eth0_subnet_without_gateway_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = ufm.build_plan(make_inputs(tmp, global_text=GLOBAL.replace(
                'address: "198.51.101.129/23"', 'address: "198.51.101.129/29"')))
        self.assertTrue([error for error in plan.errors if "ipmi" in error and "没有提供 gateway" in error],
                        plan.errors)

    def plan_with_ipmi(self, primary, secondary):
        text = GLOBAL.replace(IPMI_PRIMARY, primary).replace(IPMI_SECONDARY, secondary)
        with tempfile.TemporaryDirectory() as tmp:
            return ufm.build_plan(make_inputs(tmp, global_text=text))

    def test_ipmi_in_its_own_subnet_takes_its_own_gateway(self):
        # Owner 2026-10-21: the BMC may sit in another subnet than eno8303, with its own gateway.
        plan = self.plan_with_ipmi(
            '          ipmi:\n            address: "198.18.252.209/24"\n            gateway: "198.18.252.254"\n',
            '          ipmi:\n            address: "198.18.252.210/24"\n            gateway: "198.18.252.254"\n')
        self.assertEqual(plan.errors, [])
        self.assertEqual(plan.addresses["primary"]["ipmi"], "198.18.252.209/24")
        self.assertEqual(plan.ipmi_gateways, {"primary": "198.18.252.254", "secondary": "198.18.252.254"})
        printed = []
        ufm.print_plan(plan, printed.append)
        self.assertIn("      ipmi: 198.18.252.209/24  gw 198.18.252.254", printed)

    def test_without_gateway_the_eth0_subnet_uses_the_csv_gateway(self):
        # Owner 2026-10-21: gateway is optional; in the eno8303 subnet the IPMI uses the CSV eth0_gw.
        plan = self.plan_with_ipmi(IPMI_PRIMARY, IPMI_SECONDARY)
        self.assertEqual((plan.errors, plan.ipmi_gateways), ([], {}))
        printed = []
        ufm.print_plan(plan, printed.append)
        self.assertIn("      ipmi: 198.51.101.129/23", printed)

    def test_the_old_string_form_is_rejected_with_the_new_layout(self):
        plan = self.plan_with_ipmi(IPMI_PRIMARY, '          ipmi: "198.51.101.131/23"\n')
        errors = [error for error in plan.errors if "secondary.ipmi" in error]
        self.assertTrue(errors, plan.errors)
        self.assertIn('address: "198.51.101.131/23"', errors[0], "the message shows how to write it")

    def test_invalid_ipmi_mappings_are_rejected(self):
        cases = {
            "another subnet without gateway": ('          ipmi:\n            address: "198.18.252.209/24"\n',
                                               "没有提供 gateway"),
            "gateway outside the subnet": ('          ipmi:\n            address: "198.18.252.209/24"\n'
                                           '            gateway: "198.18.253.254"\n', "198.18.253.254"),
            "gateway is the address": ('          ipmi:\n            address: "198.18.252.209/24"\n'
                                       '            gateway: "198.18.252.209"\n', "198.18.252.209"),
            "unknown key": ('          ipmi:\n            address: "198.18.252.209/24"\n'
                            '            gw: "198.18.252.254"\n', "gw"),
            "no address": ('          ipmi:\n            gateway: "198.18.252.254"\n', "address"),
        }
        for label, (primary, needle) in cases.items():
            secondary = ('          ipmi:\n            address: "198.18.252.210/24"\n'
                         '            gateway: "198.18.252.254"\n')
            plan = self.plan_with_ipmi(primary, secondary)
            self.assertTrue([error for error in plan.errors if "ipmi" in error and needle in error],
                            (label, plan.errors))


MANUAL_RESOLVED = UBUNTU_RESOLVED.replace("#DNS=\n", "DNS=160.250.70.5 160.250.71.202 8.8.8.8\n")
MANUAL_TIMESYNCD = UBUNTU_TIMESYNCD.replace("#NTP=\n", "NTP=160.250.71.253 ntp.ubuntu.com\n")


class PhasesCase(FakeSshCase):
    """ufm01 freshly racked (factory password, DHCP), ufm02 configured by hand as in ufm-manual.log."""
    IPMI = "Ipmi-Pw-77"
    U1, U2 = "ufm01.site01.example.test", "ufm02.site01.example.test"

    def setUp(self):
        super().setUp()
        fresh = self.state["ufms"]["ufm01"]
        fresh["password"] = self.FACTORY
        fresh.update(expired=True, unit_state={"systemd-timesyncd.service": "masked"})
        fresh["files"]["etc/netplan/50-cloud-init.yaml"] = (
            "network:\n  version: 2\n  ethernets:\n    eno8303:\n      dhcp4: true\n")
        done = self.state["ufms"]["ufm02"]
        done["password"] = self.NEW
        done.update(expired=False, hostname=self.U2, ipv4="198.51.101.132/23",
                    answers_on="198.51.101.132", default="default via 198.51.101.254 dev eno8303 proto static")
        done["files"].update({
            "etc/netplan/01-netcfg.yaml": MANUAL_NETPLAN,
            "etc/systemd/resolved.conf": MANUAL_RESOLVED,
            "etc/systemd/timesyncd.conf": MANUAL_TIMESYNCD,
            # as ufm-manual.log leaves ufm02: both UFMs by their HA link address (owner 2026-10-22)
            "etc/hosts": (f"127.0.0.1\tlocalhost\n127.0.1.1\t{self.U2} ufm02\n\n"
                          f"192.0.2.1    {self.U1}  ufm01\n192.0.2.2    {self.U2}  ufm02\n"),
            "root/.ssh/authorized_keys": f"ssh-ed25519 {TEST_KEY_BLOB} operator@mgmt.example.test\n",
            "root/.ssh/id_ed25519": "PRIVATE KEY\n",
            "root/.ssh/id_ed25519.pub": f"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIUFM02KEY root@{self.U2}\n"})
        done["ifaces"]["eno8403"]["addrs"] = ["192.0.2.2/30"]
        done["ipmi"]["lan"] = {"source": "Static Address", "ip": "198.51.101.131", "mask": "255.255.254.0",
                               "gw": "198.51.101.254"}
        done["ipmi"]["users"]["3"] = {"name": "admin", "link": True, "ipmi": True, "priv": "ADMINISTRATOR",
                                      "enabled": True}

    def read(self, name, relative):
        return (self.sandbox / name / relative).read_text()

    @staticmethod
    def outcomes(result):
        return [(step["step"], step["outcome"]) for step in result.steps]


# After the upgrade and reboot every configuration step is checked again (owner 2026-10-20).
POST_UPGRADE_QUIET = [("post_upgrade_netplan", "UNCHANGED"), ("post_upgrade_authorized_keys", "UNCHANGED"),
                      ("post_upgrade_key_login", "OK"), ("post_upgrade_hostname", "UNCHANGED"),
                      ("post_upgrade_ipmi_lan", "UNCHANGED"), ("post_upgrade_ipmi_user", "UNCHANGED"),
                      ("post_upgrade_ipmi_power", "OK"),
                      ("post_upgrade_dns", "UNCHANGED"), ("post_upgrade_dns_domains", "UNCHANGED"),
                      ("post_upgrade_ntp", "UNCHANGED"), ("post_upgrade_timezone", "UNCHANGED"),
                      ("post_upgrade_hosts", "UNCHANGED")]


class SimulatedPhasesTest(PhasesCase):
    def test_config_upgrade_converges_fresh_and_manually_configured_nodes_in_one_pass(self):
        # Owner 2026-10-20: access + base config, then (UFM) the upgrade, in one command: config-upgrade.
        base, state, base_calls, base_logs = self.run_login(action="config_upgrade_all", ipmi_password=self.IPMI)
        one, two = base["ufm01"], base["ufm02"]
        self.assertEqual(one.status, "UPGRADED", one.detail)
        self.assertEqual(self.outcomes(one), [
            ("netplan", "CHANGED"), ("authorized_keys", "ADDED_1"), ("key_login", "OK"), ("hostname", "CHANGED"),
            ("ipmi_lan", "CHANGED"), ("ipmi_user", "CREATED"), ("ipmi_power", "OK"), ("dns", "CHANGED"),
            ("dns_domains", "CHANGED"),
            ("ntp", "CHANGED"), ("timezone", "UNCHANGED"), ("hosts", "CHANGED"),
            ("upgrade", "UPGRADED")] + POST_UPGRADE_QUIET)
        self.assertEqual([(a["path"], a["password"], a["outcome"]) for a in one.attempts if a["path"] == "OOB-IPv6"], [
            ("OOB-IPv6", "new", "AUTH_REJECTED"), ("OOB-IPv6", "factory", "PASSWORD_CHANGE_REQUIRED"),
            ("OOB-IPv6", "factory", "PASSWORD_CHANGED"), ("OOB-IPv6", "new", "OK")])
        self.assertEqual(one.path, "IPv4-KEY", "after the key probe the remaining steps use the key")
        self.assertEqual(two.status, "UPGRADED", two.detail)
        self.assertEqual(self.outcomes(two), [
            ("netplan", "CHANGED"), ("authorized_keys", "UNCHANGED"), ("key_login", "OK"), ("hostname", "UNCHANGED"),
            ("ipmi_lan", "UNCHANGED"), ("ipmi_user", "UPDATED"), ("ipmi_power", "OK"), ("dns", "CHANGED"),
            ("dns_domains", "CHANGED"),
            ("ntp", "UNCHANGED"), ("timezone", "UNCHANGED"), ("hosts", "UNCHANGED"),
            ("upgrade", "UPGRADED")] + POST_UPGRADE_QUIET)
        self.assertEqual(two.password, "key", "a node that already has the deployment key is not logged in by password")

        fresh, done = state["ufms"]["ufm01"], state["ufms"]["ufm02"]
        self.assertEqual(fresh["hostname"], self.U1)
        hosts = self.read("ufm01", "etc/hosts")
        self.assertIn(f"127.0.1.1\t{self.U1} ufm01\n", hosts, "the hostname step is unchanged")
        self.assertTrue(hosts.endswith(f"192.0.2.1    {self.U1}  ufm01\n192.0.2.2    {self.U2}  ufm02\n"),
                        "owner 2026-10-22: both UFMs by their HA link address, only appended")
        self.assertEqual(fresh["ipmi"]["lan"], {"source": "Static Address", "ip": "198.51.101.129",
                                                "mask": "255.255.254.0", "gw": "198.51.101.254"})
        self.assertEqual(fresh["ipmi"]["users"]["3"], {"name": "admin", "link": True, "ipmi": True,
                                                       "priv": "ADMINISTRATOR", "enabled": True})
        self.assertEqual((fresh["ipmi"]["passwords"], done["ipmi"]["passwords"]), ({"3": self.IPMI}, {"3": self.IPMI}))
        self.assertEqual((fresh["applied"], done["applied"]), (1, 1))
        import yaml
        self.assertEqual(sorted(os.listdir(self.sandbox / "ufm01/etc/netplan")), ["01-netcfg.yaml"])
        self.assertEqual(yaml.safe_load(self.read("ufm01", "etc/netplan/01-netcfg.yaml")), UFM01_NETPLAN)
        self.assertEqual(yaml.safe_load(self.read("ufm02", "etc/netplan/01-netcfg.yaml")), UFM02_NETPLAN)
        for name in ("ufm01", "ufm02"):
            resolved = self.read(name, "etc/systemd/resolved.conf").splitlines()
            self.assertEqual([line for line in resolved if "DNS=" in line and not line.startswith("#Fallback")],
                             ["DNS=160.250.70.5 160.250.71.202"], name)
            self.assertIn("Domains=site01.example.test", resolved, name)
            self.assertIn("NTP=160.250.71.253 ntp.ubuntu.com", self.read(name, "etc/systemd/timesyncd.conf"))
        self.assertIn("DNS=160.250.70.5 160.250.71.202 8.8.8.8", self.read(
            "ufm02", f"root/ufm-setup-upgrade-backup/{self.run_dir.name}/resolved.conf"))
        self.assertIn("unmask systemd-timesyncd.service", fresh["systemctl"])
        self.assertIn("enable --now systemd-timesyncd.service", fresh["systemctl"])
        self.assertEqual(self.read("ufm01", "root/.ssh/authorized_keys").count(TEST_KEY_BLOB), 1)
        self.assertEqual(sorted(item.split()[0] for item in one.facts["network_pending"]), ["ib0", "ib1"])
        for secret in (self.NEW, self.FACTORY, self.LEAF, self.IPMI):
            self.assertNotIn(secret, base_logs)
            self.assertNotIn(secret, json.dumps(base_calls))

        keys = self.sandbox / "ufm02/root/.ssh/authorized_keys"
        keys.write_text("".join(line + "\n" for line in keys.read_text().splitlines() if TEST_KEY_BLOB not in line))
        trust, _state, _calls, _logs = self.run_login(action="trust")
        self.assertEqual({item.status for item in trust.values()}, {"TRUSTED"}, [t.detail for t in trust.values()])
        self.assertEqual((trust["ufm01"].path, trust["ufm02"].path), ("IPv4-KEY", "IPv4"),
                         "mutual trust must not depend on deployment-key login")
        self.assertEqual(self.outcomes(trust["ufm01"]),
                         [("root_keypair", "CREATED"), ("peer_key", "ADDED"), ("peer_login", "OK")])
        self.assertEqual(self.outcomes(trust["ufm02"]),
                         [("root_keypair", "UNCHANGED"), ("peer_key", "ADDED"), ("peer_login", "OK")])
        self.assertIn("AAAAC3NzaC1lZDI1NTE5AAAAIUFM02KEY", self.read("ufm01", "root/.ssh/authorized_keys"))
        self.assertIn("AAAAC3NzaC1lZDI1NTE5AAAAIUFM01KEY", self.read("ufm02", "root/.ssh/authorized_keys"))
        self.assertIn("198.51.101.132 ", self.read("ufm01", "root/.ssh/known_hosts"))
        again, _state, _calls, _logs = self.run_login(action="trust")
        self.assertEqual([self.outcomes(again[name]) for name in ("ufm01", "ufm02")],
                         [[("root_keypair", "UNCHANGED"), ("peer_key", "UNCHANGED"), ("peer_login", "OK")]] * 2)

    def test_trust_requires_the_ha_link_to_reach_the_peer(self):
        self.run_login(action="config_upgrade_all", ipmi_password=self.IPMI)
        state = json.loads(self.state_path.read_text())
        state["ufms"]["ufm02"]["ifaces"]["eno8403"]["oper"] = "down"
        self.state_path.write_text(json.dumps(state))
        results, _state, _calls, _logs = self.run_login(action="trust")
        self.assertEqual({item.status for item in results.values()}, {"NOT_READY"},
                         [item.detail for item in results.values()])
        self.assertIn("192.0.2.2", results["ufm01"].detail)
        self.assertIn("192.0.2.1", results["ufm02"].detail)
        self.assertFalse([step for item in results.values() for step in item.steps if step["step"] == "peer_key"])

    def test_trust_changes_nothing_until_both_nodes_are_configured(self):
        before = self.state["ufms"]["ufm02"]["files"]["root/.ssh/authorized_keys"]
        results, _state, _calls, _logs = self.run_login(action="trust")
        self.assertEqual((results["ufm01"].status, results["ufm02"].status), ("NOT_READY", "NOT_READY"))
        self.assertIn("198.51.101.130", results["ufm01"].detail)
        self.assertIn("192.0.2.1", results["ufm02"].detail, "ufm02 cannot reach the unconfigured peer's HA link")
        self.assertEqual(self.read("ufm02", "root/.ssh/authorized_keys"), before)
        self.assertEqual(results["ufm02"].steps, [])

    def test_config_upgrade_without_the_deployment_key_logs_in_by_password_and_installs_it(self):
        self.state["ufms"]["ufm02"]["files"].pop("root/.ssh/authorized_keys")
        results, _state, _calls, _logs = self.run_login(action="config_upgrade_all", ipmi_password=self.IPMI)
        two = results["ufm02"]
        self.assertEqual(two.status, "UPGRADED", two.detail)
        self.assertIn(("IPv4", "new", "OK"), [(a["path"], a["password"], a["outcome"]) for a in two.attempts])
        self.assertEqual(dict(self.outcomes(two))["authorized_keys"], "ADDED_1")
        self.assertEqual(self.read("ufm02", "root/.ssh/authorized_keys").count(TEST_KEY_BLOB), 1)

    def test_later_commands_report_only_the_password_they_tried(self):
        # Docker finding R3: ha-setup never uses the factory password.
        results, _state, _calls, _logs = self.run_login(action="ha_setup", factory="")
        detail = results["ufm01"].detail
        self.assertEqual(results["ufm01"].status, "HA_NOT_READY")
        self.assertEqual(detail.count("root 新密码被拒绝（该命令不使用出厂密码）"), 1, detail)
        self.assertNotIn("出厂密码都被拒绝", detail)

    def test_no_direct_route_from_the_deployment_server(self):
        self.state["no_direct"] = ["198.51.101.130", "198.51.101.132"]
        base, state, _calls, _logs = self.run_login(action="config_upgrade_all", ipmi_password=self.IPMI)
        for name in ("ufm01", "ufm02"):
            self.assertEqual((base[name].status, base[name].path), ("UPGRADED", "OOB-IPv6"), base[name].detail)
            outcomes = dict(self.outcomes(base[name]))
            self.assertEqual((outcomes["netplan"], outcomes["key_login"]), ("CHANGED", "WARN_NO_DIRECT_KEY_LOGIN"))
            self.assertIs(base[name].facts["ipv4_verified_from_server"], False)
        self.assertEqual(state["ufms"]["ufm01"]["hostname"], self.U1)
        trust, _state, _calls, _logs = self.run_login(action="trust")
        self.assertEqual({item.status for item in trust.values()}, {"TRUSTED"}, [t.detail for t in trust.values()])

    def test_netplan_generate_failure_in_phase_one_restores_original_files(self):
        self.state["ufms"]["ufm01"]["generate_fails"] = True
        results, state, _calls, _logs = self.run_login(action="config_upgrade_all")
        self.assertEqual(results["ufm01"].status, "STEP_FAILED_NETPLAN")
        self.assertEqual(sorted(os.listdir(self.sandbox / "ufm01/etc/netplan")), ["50-cloud-init.yaml"])
        self.assertIsNone(state["ufms"]["ufm01"].get("applied"))
        self.assertNotIn("root/.ssh/authorized_keys", os.listdir(self.sandbox / "ufm01"))

    def test_ipmi_in_its_own_subnet_is_set_with_its_own_gateway(self):
        # Owner 2026-10-21: `ipmi: {address, gateway}` in global; the BMC gets that gateway, not eth0_gw.
        text = GLOBAL.replace(IPMI_PRIMARY, '          ipmi:\n            address: "198.18.252.209/24"\n'
                                            '            gateway: "198.18.252.254"\n').replace(
            IPMI_SECONDARY,
            '          ipmi:\n            address: "198.18.252.210/24"\n            gateway: "198.18.252.254"\n')
        make_inputs(self.inputs, global_text=text)
        results, state, _calls, logs = self.run_login(action="config_upgrade_all", ipmi_password=self.IPMI)
        for name, address in (("ufm01", "198.18.252.209"), ("ufm02", "198.18.252.210")):
            self.assertEqual(dict(self.outcomes(results[name]))["ipmi_lan"], "CHANGED", results[name].detail)
            self.assertEqual(state["ufms"][name]["ipmi"]["lan"], {"source": "Static Address", "ip": address,
                                                                  "mask": "255.255.255.0", "gw": "198.18.252.254"})
        self.assertIn("网关 198.18.252.254", logs)

    def test_a_password_that_did_not_take_is_set_again_and_verified(self):
        # ufm01 2026-10-21: after creating admin the run said CREATED, yet the next run's `ipmitool user
        # test` showed the password was not the root new password. The password is now verified after it is set.
        self.state["ufms"]["ufm01"]["ipmi"]["lose_password_after_create"] = True
        results, state, _calls, logs = self.run_login(action="config_upgrade_all", ipmi_password=self.IPMI)
        self.assertEqual(dict(self.outcomes(results["ufm01"]))["ipmi_user"], "CREATED", results["ufm01"].detail)
        self.assertEqual(state["ufms"]["ufm01"]["ipmi"]["passwords"], {"3": self.IPMI})
        self.assertIn("密码设置后校验未通过，已重设一次并校验通过", logs)
        again, _state, _calls, _logs = self.run_login(action="check", apply=False, ipmi_password=self.IPMI)
        self.assertEqual(dict(self.outcomes(again["ufm01"]))["ipmi_user"], "UNCHANGED")

    def test_a_password_that_never_takes_fails_the_ipmi_user_step(self):
        self.state["ufms"]["ufm01"]["ipmi"]["ignore_passwords"] = True
        results, _state, _calls, _logs = self.run_login(action="config_upgrade_all", ipmi_password=self.IPMI)
        first = results["ufm01"]
        self.assertEqual(dict(self.outcomes(first))["ipmi_user"], "FAILED")
        self.assertEqual(first.status, "STEP_FAILED_IPMI_USER", first.detail)
        self.assertIn("user test", first.facts["deferred_failures"][0]["detail"])
        self.assertEqual(dict(self.outcomes(first))["timezone"], "UNCHANGED", "the rest still ran")

    def test_ipmi_over_lan_is_switched_on_when_the_channel_access_is_disabled(self):
        # ufm01 2026-10-21: the LAN channel Access Mode was disabled, so the admin user could not manage
        # power over the network; the owner ran `ipmitool lan set 1 access on`.
        self.state["ufms"]["ufm02"]["ipmi"]["access"] = "disabled"
        checked, _state, _calls, logs = self.run_login(action="check", apply=False, ipmi_password=self.IPMI)
        self.assertEqual(dict(self.outcomes(checked["ufm02"]))["ipmi_lan"], "WOULD_CHANGE")
        self.assertIn("开启 IPMI over LAN（通道 1 Access Mode disabled → always available）", logs)
        lan_before = dict(self.state["ufms"]["ufm02"]["ipmi"]["lan"])
        results, state, _calls, _logs = self.run_login(action="config_upgrade_all", ipmi_password=self.IPMI)
        self.assertEqual(dict(self.outcomes(results["ufm02"]))["ipmi_lan"], "CHANGED", results["ufm02"].detail)
        self.assertEqual(state["ufms"]["ufm02"]["ipmi"]["access"], "always available")
        self.assertEqual(state["ufms"]["ufm02"]["ipmi"]["lan"], lan_before, "the LAN address was already right")
        again, _state, _calls, _logs = self.run_login(action="check", apply=False, ipmi_password=self.IPMI)
        self.assertEqual(dict(self.outcomes(again["ufm02"]))["ipmi_lan"], "UNCHANGED")

    def test_admin_reads_the_power_state_over_the_network_from_the_ufm(self):
        # Owner 2026-10-21: the admin user is for viewing/managing power; test it on the UFM itself.
        results, _state, calls, _logs = self.run_login(action="config_upgrade_all", ipmi_password=self.IPMI)
        for name, host_name, bmc in (("ufm01", self.U1, "198.51.101.129"), ("ufm02", self.U2, "198.51.101.131")):
            self.assertEqual(dict(self.outcomes(results[name]))["ipmi_power"], "OK", results[name].detail)
            self.assertEqual(results[name].facts["ipmi_power"], "on")
            scripts = sorted(self.run_dir.glob(f"{host_name}-[0-9]*-ipmi-power-status.sh"))
            self.assertTrue(scripts)
            self.assertIn(f"ipmitool -I lanplus -H {bmc} -U admin -a chassis power status", scripts[0].read_text())
        self.assertNotIn(self.IPMI, json.dumps(calls))
        for path in self.run_dir.iterdir():
            self.assertNotIn(self.IPMI, path.read_text(errors="replace"), path.name)

    def test_a_power_check_that_cannot_log_in_fails_the_node_without_blocking(self):
        self.state["ufms"]["ufm01"]["ipmi"]["lan_sessions_fail"] = True
        results, _state, _calls, _logs = self.run_login(action="config_upgrade_all", ipmi_password=self.IPMI)
        first = results["ufm01"]
        self.assertEqual(dict(self.outcomes(first))["ipmi_power"], "FAILED")
        self.assertEqual(first.status, "STEP_FAILED_IPMI_POWER", first.detail)
        self.assertIn("Unable to establish IPMI v2", first.facts["deferred_failures"][0]["detail"])
        self.assertEqual(dict(self.outcomes(first))["upgrade"], "UPGRADED", "the rest still ran")

    def test_ipmi_user_is_skipped_without_a_password(self):
        results, state, _calls, _logs = self.run_login(action="config_upgrade_all")
        self.assertEqual(dict(self.outcomes(results["ufm01"]))["ipmi_user"], "SKIPPED")
        self.assertNotIn("3", state["ufms"]["ufm01"]["ipmi"]["users"])


class InspectModeTest(PhasesCase):
    """Without --apply (as initial-setup): no password change, no configuration; the only thing left on the
    UFM is the copy of each script that ran, under /root/.setup/<run>/ (owner 2026-10-20)."""

    def assert_untouched(self, name):
        """Every seeded file is byte-identical; besides the kept scripts nothing else was written
        (prepare() only adds fixtures)."""
        seeded = self.state["ufms"][name]["files"]
        root = self.sandbox / name
        if not root.exists():
            return   # never logged in
        written = {str(path.relative_to(root)) for path in root.rglob("*") if path.is_file()}
        fixtures = {item for item in written
                    if item in ("etc/os-release", "etc/ssh/ssh_host_ed25519_key.pub") or item.startswith("sys/class/net/")}
        kept = {item for item in written if item.startswith(f"root/.setup/{self.run_dir.name}/")}
        for item in kept:
            self.assertRegex(item.rsplit("/", 1)[1], r"^\d{3}-[a-z0-9-]+\.sh$")
        self.assertEqual(written - fixtures - kept, set(seeded), name)
        for relative, text in seeded.items():
            self.assertEqual((root / relative).read_text(), text, (name, relative))

    def test_check_stops_at_a_new_device_and_reports_a_configured_one(self):
        base, state, calls, logs = self.run_login(action="check", apply=False)
        self.assertEqual(base["ufm01"].status, "NEW_DEVICE", "a forced password change means a new device: stop")
        self.assertEqual(base["ufm01"].steps, [], "nothing after the password prompt is checked")
        self.assertEqual((state["ufms"]["ufm01"]["password"], state["ufms"]["ufm01"]["expired"]), (self.FACTORY, True))
        two = base["ufm02"]
        self.assertEqual(two.status, "NEEDS_CONFIGURATION", two.detail)
        self.assertEqual(self.outcomes(two), [
            ("netplan", "WOULD_CHANGE"), ("authorized_keys", "UNCHANGED"), ("key_login", "OK"),
            ("hostname", "UNCHANGED"), ("ipmi_lan", "UNCHANGED"), ("ipmi_user", "WOULD_CHANGE"),
            ("ipmi_power", "NOT_TESTED"),
            ("dns", "WOULD_CHANGE"), ("dns_domains", "WOULD_CHANGE"), ("ntp", "UNCHANGED"), ("timezone", "UNCHANGED"),
            ("hosts", "UNCHANGED"), ("upgrade", "WOULD_CHANGE")])
        self.assertIn("[dns] WOULD_CHANGE：/etc/systemd/resolved.conf 中 DNS=", logs, "one line per step")
        self.assertIn("DNS=160.250.70.5 160.250.71.202", logs)
        done = state["ufms"]["ufm02"]
        self.assertNotIn("applied", done)
        self.assertNotIn("systemctl", done)
        self.assertEqual(done["ipmi"]["passwords"], {})
        for name in ("ufm01", "ufm02"):
            self.assert_untouched(name)
        self.assertFalse([call for call in calls if "/root/ufm-setup-upgrade/" in call["remote"]])
        self.assertTrue(list((self.sandbox / "ufm02/root/.setup" / self.run_dir.name).glob("001-*.sh")),
                        "check keeps its scripts too")

    def test_a_mistyped_confirmation_changes_no_password(self):
        # Owner 2026-10-21: one password per run; a second entry only right before a device's forced change.
        asked = []
        results, state, _calls, _logs = self.run_login(
            action="config_upgrade_all", ipmi_password=self.IPMI,
            confirm_new_password=lambda: asked.append(1) or "Mistyped-Pw")
        self.assertEqual(results["ufm01"].status, "NOT_AUTHORIZED", results["ufm01"].detail)
        self.assertIn("不一致", results["ufm01"].detail)
        self.assertEqual((state["ufms"]["ufm01"]["password"], state["ufms"]["ufm01"]["expired"]), (self.FACTORY, True))
        self.assertEqual(len(asked), 1)

    def test_a_matching_confirmation_lets_the_new_device_change_its_password(self):
        asked = []
        results, state, _calls, _logs = self.run_login(
            action="config_upgrade_all", ipmi_password=self.IPMI,
            confirm_new_password=lambda: asked.append(1) or self.NEW)
        self.assertNotEqual(results["ufm01"].status, "NOT_AUTHORIZED", results["ufm01"].detail)
        self.assertEqual(state["ufms"]["ufm01"]["password"], self.NEW)
        self.assertEqual(len(asked), 1, "asked once, only for the device that had to change")

    def test_declined_confirmation_writes_nothing(self):
        asked = []
        results, state, _calls, _logs = self.run_login(
            action="config_upgrade_all", ipmi_password=self.IPMI,
            confirm=lambda host, action: asked.append((host, action)) or False)
        self.assertEqual([results[name].status for name in ("ufm01", "ufm02")], ["NOT_AUTHORIZED"] * 2)
        self.assertEqual(len(asked), 1, "one question for the run; a refusal stops it")
        self.assertEqual(asked[0][0], self.U1)
        self.assertIn("出厂密码改为新密码", asked[0][1], "the confirmation shows the whole checked plan")
        self.assertIn(f"{self.U2}: 需要改动 netplan", asked[0][1])
        self.assertEqual((state["ufms"]["ufm01"]["password"], state["ufms"]["ufm01"]["expired"]), (self.FACTORY, True))
        self.assertNotIn("applied", state["ufms"]["ufm02"])
        for name in ("ufm01", "ufm02"):
            self.assert_untouched(name)


COMPLIANT_RESOLVED = UBUNTU_RESOLVED.replace("#DNS=\n", "DNS=160.250.70.5 160.250.71.202\n").replace(
    "#Domains=\n", "Domains=site01.example.test\n")


class ConfiguredPairCase(PhasesCase):
    """Two nodes whose base configuration already matches CSV/global, so the config part of
    config-upgrade is all UNCHANGED and a test isolates the upgrade, HA or address checks."""

    def setUp(self):
        super().setUp()
        import yaml
        one, two = self.state["ufms"]["ufm01"], self.state["ufms"]["ufm02"]
        one["password"] = self.NEW
        one.update(expired=False, hostname=self.U1, ipv4="198.51.101.130/23", unit_state={},
                   answers_on="198.51.101.130", default=two["default"])
        one["files"]["root/.ssh/authorized_keys"] = two["files"]["root/.ssh/authorized_keys"]
        one["files"].pop("etc/netplan/50-cloud-init.yaml")
        one["files"]["etc/hosts"] = (f"127.0.0.1\tlocalhost\n127.0.1.1\t{self.U1} ufm01\n\n"
                                     f"192.0.2.1    {self.U1}  ufm01\n192.0.2.2    {self.U2}  ufm02\n")
        one["ifaces"]["eno8403"]["addrs"] = ["192.0.2.1/30"]
        one["ipmi"]["lan"] = {"source": "Static Address", "ip": "198.51.101.129", "mask": "255.255.254.0",
                              "gw": "198.51.101.254"}
        for item, netplan in ((one, UFM01_NETPLAN), (two, UFM02_NETPLAN)):
            item["files"]["etc/netplan/01-netcfg.yaml"] = yaml.safe_dump(netplan)
            item["files"]["etc/systemd/resolved.conf"] = COMPLIANT_RESOLVED
            item["files"]["etc/systemd/timesyncd.conf"] = MANUAL_TIMESYNCD
        # after HA (owner 2026-10-22): /opt/ufm/files on DRBD, the image directory, the fabric
        self.files = self.sandbox / "drbd/opt/ufm/files"
        for sub in ("conf/opensm", "licenses", "log"):
            (self.files / sub).mkdir(parents=True, exist_ok=True)
        (self.files / "conf/gv.cfg").write_text(GV_CFG_SHIPPED)
        (self.files / "conf/opensm/opensm.conf").write_text(OPENSM_CONF)
        (self.inputs / "image").mkdir()
        (self.inputs / "image/site.lic").write_text(LICENSE_TEXT)
        self.state["served"] = {LICENSE_URL: LICENSE_TEXT}
        self.state["fabric"] = FABRIC

    CONFIG_STEPS = (("netplan", "UNCHANGED"), ("authorized_keys", "UNCHANGED"), ("key_login", "OK"),
                    ("hostname", "UNCHANGED"), ("ipmi_lan", "UNCHANGED"), ("ipmi_user", "SKIPPED"),
                    ("ipmi_power", "SKIPPED"),
                    ("dns", "UNCHANGED"), ("dns_domains", "UNCHANGED"), ("ntp", "UNCHANGED"),
                    ("timezone", "UNCHANGED"), ("hosts", "UNCHANGED"))



class SimulatedUpgradeAndHaTest(ConfiguredPairCase):
    def status_log(self, name):
        return self.sandbox / name / "var/log/ufm_os_upgrade_26.07.24-9_status.log"

    def test_upgrade_follows_the_manual_and_waits_through_the_reboot_then_is_idempotent(self):
        stale = ("20250101-00_00_00: UFM_OS_UPGRADE                      [STARTED   ]\n"
                 "20250101-00_01_00: APPLIANCE-UPGRADE                   [FAILED    ]\n")
        self.state["ufms"]["ufm01"]["files"]["var/log/ufm_os_upgrade_26.07.24-9_status.log"] = stale
        results, state, calls, logs = self.run_login(action="config_upgrade_all")
        for name in ("ufm01", "ufm02"):
            item = state["ufms"][name]
            self.assertEqual(results[name].status, "UPGRADED", results[name].detail)
            self.assertEqual(self.outcomes(results[name]),
                             list(self.CONFIG_STEPS) + [("upgrade", "UPGRADED")] +
                             [(f"post_upgrade_{step}", outcome) for step, outcome in self.CONFIG_STEPS],
                             "the upgrade runs after the base configuration, then everything is checked again")
            self.assertEqual(results[name].facts["post_upgrade_reconfigured"], [])
            self.assertEqual(item["wget"], [IMAGE_URL])
            self.assertIn("stop ufm-enterprise", item["systemctl"])
            self.assertEqual(item["upgrade_saw_ufm_enterprise"], "inactive",
                             "ufm-os-upgrade.sh must only run once ufm-enterprise is stopped")
            self.assertIs(item["upgrade_tty"], False, "the upgrade must not depend on the SSH session")
            self.assertEqual(item["os_upgrade_runs"], 1)
            self.assertIn("UFM_APPLIANCE=2.6.1-8", self.read(name, "etc/ufm-release").splitlines())
            self.assertEqual(results[name].facts["upgrade_before"], "2.3.1-8")
        self.assertIn("暂不可达", logs, "probes during the reboot are transient, not failures")
        self.assertTrue(self.status_log("ufm01").read_text().startswith(stale))
        for secret in (self.NEW, self.FACTORY, self.LEAF):
            self.assertNotIn(secret, logs)
            self.assertNotIn(secret, json.dumps(calls))

        again, state, _calls, _logs = self.run_login(action="config_upgrade_all")
        for name in ("ufm01", "ufm02"):
            self.assertEqual(again[name].status, "UP_TO_DATE", again[name].detail)
            self.assertEqual(self.outcomes(again[name])[-1], ("upgrade", "UNCHANGED"))
            self.assertEqual((state["ufms"][name]["os_upgrade_runs"], len(state["ufms"][name]["wget"])), (1, 1))

    def test_check_reports_config_version_trust_and_ha_without_changes(self):
        # Owner 2026-10-20: a node that accepts the new password gets every read-only check.
        results, state, _calls, logs = self.run_login(action="check", apply=False)
        for name in ("ufm01", "ufm02"):
            outcomes = self.outcomes(results[name])
            self.assertEqual(results[name].status, "NEEDS_CONFIGURATION", results[name].detail)
            self.assertEqual([step for step, _outcome in outcomes][:len(self.CONFIG_STEPS) + 1],
                             [step for step, _outcome in self.CONFIG_STEPS] + ["upgrade"])
            self.assertEqual(dict(outcomes)["upgrade"], "WOULD_CHANGE")
            self.assertEqual(dict(outcomes)["peer_login"], "NOT_TESTED")
            # Owner 2026-10-22: `ufm_ha_cluster status` decides; no cluster yet, so ha-setup would configure it.
            self.assertEqual(dict(outcomes)["ha_config"], "WOULD_CHANGE")
            self.assertEqual(dict(outcomes)["ha_preconditions"], "NOT_MET")
            self.assertIn("ufm-enterprise 正在运行", results[name].facts["ha_problems"][0])
            self.assertNotIn("wget", state["ufms"][name])
            self.assertNotIn("systemctl", state["ufms"][name])
            self.assertEqual(state["ufms"][name]["services"]["ufm-enterprise"], "active")
            self.assertIn("UFM_APPLIANCE=2.3.1-8", self.read(name, "etc/ufm-release"))
        self.assertEqual(dict(self.outcomes(results["ufm01"]))["root_keypair"], "WOULD_CHANGE")
        self.assertEqual(dict(self.outcomes(results["ufm02"]))["root_keypair"], "UNCHANGED")
        self.assertIn("2.3.1-8 → 2.6.1-8", logs)
        self.assertFalse((self.sandbox / "ufm01/root/.ssh/id_ed25519").exists())
        for name in ("ufm01", "ufm02"):
            self.assertFalse((self.sandbox / name / "root/.ssh/known_hosts").exists())
            self.assertFalse((self.sandbox / name / "root/ufm-setup-upgrade").exists())
            self.assertEqual(os.listdir(self.sandbox / name / "tmp"), [], "nothing is left in /tmp")
            kept = sorted(os.listdir(self.sandbox / name / "root/.setup" / self.run_dir.name))
            self.assertEqual([int(item[:3]) for item in kept], list(range(1, len(kept) + 1)), kept)

    def test_first_change_is_confirmed_once_and_a_refusal_stops_everything(self):
        asked = []
        refused, state, _calls, _logs = self.run_login(
            action="config_upgrade_all", confirm=lambda host, action: asked.append(host) or False)
        self.assertEqual([refused[name].status for name in ("ufm01", "ufm02")], ["NOT_AUTHORIZED"] * 2)
        self.assertEqual(asked, [self.U1])
        for name in ("ufm01", "ufm02"):
            self.assertNotIn("wget", state["ufms"][name])
            self.assertNotIn("os_upgrade_runs", state["ufms"][name])
        asked.clear()
        granted, state, _calls, _logs = self.run_login(
            action="config_upgrade_all", confirm=lambda host, action: asked.append(host) or True)
        self.assertEqual([granted[name].status for name in ("ufm01", "ufm02")], ["UPGRADED"] * 2)
        self.assertEqual(asked, [self.U1], "one authorization covers the rest of the run")

    def test_a_left_over_image_is_reused_only_when_its_size_matches_the_server(self):
        # Docker finding S9: an older or interrupted download must not be upgraded from.
        image = "root/ufm-appliance-2.6.1-8-omu.x86_64.tar"
        self.state["ufms"]["ufm01"]["files"][image] = "partial\n"
        self.state["ufms"]["ufm02"]["files"][image] = "fake appliance image\n"   # same size as the server copy
        results, state, _calls, _logs = self.run_login(action="config_upgrade_all")
        self.assertEqual({item.status for item in results.values()}, {"UPGRADED"})
        self.assertEqual(state["ufms"]["ufm01"]["wget"], [IMAGE_URL])
        self.assertNotIn("wget", state["ufms"]["ufm02"])
        self.assertEqual(self.read("ufm01", image), "fake appliance image\n")

    def test_the_confirmed_upgrade_action_names_reuse_or_download_as_it_will_happen(self):
        # Docker finding R2: the probe applies the same size rule as the start script.
        image = "root/ufm-appliance-2.6.1-8-omu.x86_64.tar"
        self.state["ufms"]["ufm01"]["files"][image] = "partial\n"
        self.state["ufms"]["ufm02"]["files"][image] = "fake appliance image\n"   # server size
        results, _state, _calls, _logs = self.run_login(action="check", apply=False)
        self.assertIn(f"下载 {IMAGE_URL}", results["ufm01"].facts["upgrade_action"])
        self.assertNotIn("复用", results["ufm01"].facts["upgrade_action"])
        self.assertIn(f"复用设备上已下载的 /{image}", results["ufm02"].facts["upgrade_action"])
        upgraded, state, _calls, _logs = self.run_login(action="config_upgrade_all")
        self.assertEqual({item.status for item in upgraded.values()}, {"UPGRADED"})
        self.assertEqual((state["ufms"]["ufm01"]["wget"], state["ufms"]["ufm02"].get("wget")), ([IMAGE_URL], None),
                         "what was confirmed is what ran")

    def test_no_ipmi_address_skips_the_ipmi_steps_in_both_modes(self):
        # Docker finding S6: inspect and --apply must agree.
        global_text = GLOBAL.replace(IPMI_PRIMARY, "").replace(IPMI_SECONDARY, "")
        make_inputs(self.inputs, global_text=global_text)
        for action, apply in (("check", False), ("config_upgrade_all", True)):
            results, _state, _calls, _logs = self.run_login(action=action, apply=apply)
            for name in ("ufm01", "ufm02"):
                outcomes = dict(self.outcomes(results[name]))
                self.assertEqual((outcomes["ipmi_lan"], outcomes["ipmi_user"]), ("SKIPPED", "SKIPPED"), (apply, name))

    def test_configuration_the_upgrade_overwrote_is_listed_and_configured_again(self):
        # Owner 2026-10-20: after the reboot confirm the version, check again, redo what changed.
        self.state["ufms"]["ufm01"]["upgrade_resets"] = {"etc/systemd/resolved.conf": UBUNTU_RESOLVED}
        results, state, _calls, logs = self.run_login(action="config_upgrade_all")
        one = results["ufm01"]
        self.assertEqual(one.status, "UPGRADED", one.detail)
        self.assertEqual(one.facts["post_upgrade_reconfigured"], ["dns", "dns_domains"])
        self.assertEqual(dict(self.outcomes(one))["post_upgrade_dns"], "CHANGED")
        self.assertIn("DNS=160.250.70.5 160.250.71.202", self.read("ufm01", "etc/systemd/resolved.conf"))
        self.assertIn("升级改动了以下配置，已重新配置: dns, dns_domains", logs)
        self.assertEqual(results["ufm02"].facts["post_upgrade_reconfigured"], [])

    def test_ipmi_failures_do_not_stop_the_rest_but_still_fail_the_node(self):
        # Owner 2026-10-20 (ufm01's iDRAC refused the writes): record the IPMI failures, carry on with
        # DNS, NTP, time zone and the upgrade, then still mark the node failed and list the IPMI errors.
        one = self.state["ufms"]["ufm01"]
        one["ipmi"]["lan"] = {"source": "DHCP Address", "ip": "0.0.0.0", "mask": "0.0.0.0", "gw": "0.0.0.0"}
        one["ipmi"]["refuse_writes"] = True
        results, state, _calls, logs = self.run_login(action="config_upgrade_all", ipmi_password=self.IPMI)
        first = results["ufm01"]
        config = [(step, "FAILED" if step in ("ipmi_lan", "ipmi_user") else
                   "NOT_TESTED" if step == "ipmi_power" else outcome) for step, outcome in self.CONFIG_STEPS]
        self.assertEqual(self.outcomes(first), config + [("upgrade", "UPGRADED")] +
                         [(f"post_upgrade_{step}", outcome) for step, outcome in config])
        self.assertEqual(first.status, "STEP_FAILED_IPMI_LAN", first.detail)
        self.assertEqual([item["step"] for item in first.facts["deferred_failures"]], ["ipmi_lan", "ipmi_user"])
        lan_error = first.facts["deferred_failures"][0]["detail"]
        self.assertIn("BMC 拒绝了全部写入", lan_error)
        self.assertIn("1 1 ipsrc static", lan_error)
        self.assertIn("不影响后续步骤", logs)
        self.assertEqual(state["ufms"]["ufm01"]["os_upgrade_runs"], 1)
        self.assertIn("UFM_APPLIANCE=2.6.1-8", self.read("ufm01", "etc/ufm-release").splitlines())
        self.assertEqual(state["ufms"]["ufm01"]["ipmi"]["lan"]["source"], "DHCP Address")
        self.assertEqual(results["ufm02"].status, "UPGRADED", results["ufm02"].detail)

        printed = []
        args = ufm.parse_args(["config-upgrade", "--apply"])
        with tempfile.TemporaryDirectory() as tmp:
            code = ufm.summarize(args, list(results.values()), Path(tmp), printed.append)
        self.assertEqual(code, 1)
        summary = "\n".join(printed)
        self.assertIn("ipmi_lan: IPMI LAN 设置后读回不符", summary)
        self.assertIn("ipmi_user: ", summary)

    def test_every_script_run_on_the_ufm_is_kept_under_root_setup_in_execution_order(self):
        # Owner 2026-10-20: the scripts that really ran on the UFM are kept under /root/.setup/ for manual
        # use, named with the execution order. The read-only pass, the change and the post-upgrade re-check
        # run the same steps; none overwrites another, on the UFM or in the local run directory.
        self.run_login(action="config_upgrade_all")
        kept = self.sandbox / "ufm01/root/.setup" / self.run_dir.name
        names = sorted(path.name for path in kept.iterdir())
        self.assertEqual([int(name[:3]) for name in names], list(range(1, len(names) + 1)),
                         "contiguous on the UFM: only scripts that ran there take a number")
        self.assertEqual(len([name for name in names if name.endswith("-ipmi-lan-read.sh")]), 3,
                         "check pass, change pass and post-upgrade re-check")
        for name in names:
            self.assertRegex(name, r"^\d{3}-[a-z0-9-]+\.sh$")
            local = self.run_dir / f"{self.U1}-{name}"
            self.assertEqual((kept / name).read_text(), local.read_text(), "the UFM keeps the script that ran")
            self.assertTrue(local.with_name(local.name[:-3] + ".out.txt").exists(), name)
        local_scripts = sorted(path.name[len(self.U1) + 1:] for path in self.run_dir.glob(f"{self.U1}-[0-9]*.sh"))
        self.assertEqual(local_scripts, names, "locally the same numbers as on the UFM")
        # The status probes during the reboot never reached the UFM: kept locally only, with the reason.
        not_run = sorted(self.run_dir.glob(f"*-{self.U1}-upgrade-status-*-not-run.out.txt"))
        self.assertTrue(not_run)
        for path in not_run:
            self.assertIn("Connection timed out", path.read_text())
        self.assertFalse([name for name in names if "not-run" in name])
        self.assertFalse((self.sandbox / "ufm01/root/ufm-setup-upgrade").exists())
        logs = sorted(path.name for path in self.run_dir.iterdir())
        keys = [name for name in logs if name.endswith(f"-{self.U1}-key-login.txt")]
        self.assertGreaterEqual(len(keys), 3, "one deployment-key login per pass, the reboot included")

    def test_check_reports_an_ipmi_failure_after_every_other_check(self):
        self.state["ufms"]["ufm01"]["ipmi"]["unavailable"] = True
        results, _state, _calls, _logs = self.run_login(action="check", apply=False)
        first = results["ufm01"]
        outcomes = dict(self.outcomes(first))
        self.assertEqual((outcomes["ipmi_lan"], outcomes["ipmi_user"]), ("FAILED", "FAILED"))
        self.assertEqual((outcomes["timezone"], outcomes["upgrade"]), ("UNCHANGED", "WOULD_CHANGE"))
        self.assertEqual(outcomes["ha_config"], "WOULD_CHANGE", "the HA checks still run")
        self.assertEqual(first.status, "STEP_FAILED_IPMI_LAN", first.detail)
        self.assertIn("Could not open device", first.facts["deferred_failures"][0]["detail"])
        self.assertEqual(results["ufm02"].status, "NEEDS_CONFIGURATION", results["ufm02"].detail)

    def test_an_address_conflict_is_not_hidden_by_an_ipmi_failure(self):
        results = {"ufm01": ufm.NodeResult("ufm01", "primary", status="ADDRESS_CONFLICT", detail="eth0 taken",
                                           facts={"deferred_failures": [{"step": "ipmi_lan", "detail": "boom"}]})}
        session = ufm.Session.__new__(ufm.Session)
        session.say = lambda _text: None
        self.assertEqual(session.settle_deferred(results["ufm01"]).status, "ADDRESS_CONFLICT")

    def test_the_long_wait_reports_progress_with_timestamps(self):
        # Owner 2026-10-20: the first 600 s printed nothing and looked stuck; a timestamped line every
        # 100 s (here 1 s), and timestamps on the start, probe and completion lines.
        with mock.patch.object(ufm.Session, "PROGRESS_EVERY", 1):
            results, _state, _calls, logs = self.run_login(action="config_upgrade_all", upgrade_wait=(3, 1, 30))
        self.assertEqual({item.status for item in results.values()}, {"UPGRADED"})
        stamp = r"\[\d{2}:\d{2}:\d{2}\] "
        self.assertEqual(len(re.findall(stamp + "升级已在设备上启动", logs)), 2)
        self.assertGreaterEqual(len(re.findall(stamp + r"等待升级：已等待 \d+s / 3s", logs)), 4, "two per node")
        self.assertEqual(len(re.findall(stamp + "升级完成", logs)), 2)
        for line in logs.splitlines():
            if "探测 [" in line:
                self.assertRegex(line, stamp + r"探测 \[")

    def test_upgrade_does_not_start_while_ufm_enterprise_keeps_running(self):
        self.state["ufms"]["ufm01"]["stop_fails"] = ["ufm-enterprise"]
        results, state, _calls, _logs = self.run_login(action="config_upgrade_all")
        self.assertEqual(results["ufm01"].status, "STEP_FAILED_UPGRADE")
        self.assertIn("result=ufm_enterprise_running", results["ufm01"].detail)
        self.assertNotIn("os_upgrade_runs", state["ufms"]["ufm01"])
        self.assertEqual(results["ufm02"].status, "UPGRADED", results["ufm02"].detail)

    def test_failed_status_line_stops_without_restarting_the_upgrade(self):
        self.state["ufms"]["ufm02"]["upgrade_fails"] = True
        results, state, _calls, _logs = self.run_login(action="config_upgrade_all")
        self.assertEqual(results["ufm02"].status, "STEP_FAILED_UPGRADE")
        self.assertIn("APPLIANCE-UPGRADE", results["ufm02"].detail)
        self.assertIn("[FAILED", results["ufm02"].detail)
        self.assertEqual(state["ufms"]["ufm02"]["os_upgrade_runs"], 1)

    def test_wait_limit_stops_and_reports_the_last_state(self):
        for name in ("ufm01", "ufm02"):
            self.state["ufms"][name]["upgrade_hangs"] = True
        results, state, _calls, _logs = self.run_login(action="config_upgrade_all", upgrade_wait=(0, 1, 2))
        for name in ("ufm01", "ufm02"):
            self.assertEqual(results[name].status, "STEP_FAILED_UPGRADE")
            self.assertIn("等待 2s 仍未完成", results[name].detail)
            self.assertIn("UFM_APPLIANCE=2.3.1-8", results[name].detail)
            self.assertEqual(state["ufms"][name]["os_upgrade_runs"], 1)

    def test_missing_image_stops_before_ufm_enterprise_is_touched(self):
        self.state["image_url"] = "http://198.51.103.200:8088/image/other.tar"
        results, state, _calls, _logs = self.run_login(action="config_upgrade_all")
        for name in ("ufm01", "ufm02"):
            self.assertEqual(results[name].status, "STEP_FAILED_UPGRADE")
            self.assertIn("IMAGE_UNAVAILABLE", results[name].detail)
            self.assertIn(IMAGE_URL, results[name].detail)
            self.assertNotIn("wget", state["ufms"][name])
            self.assertNotIn("systemctl", state["ufms"][name])
            self.assertFalse((self.sandbox / name / "root/ufm-appliance-2.6.1-8-omu.x86_64.tar").exists())

    def test_upgrade_is_skipped_without_a_version_and_needs_the_image_server(self):
        plan = ufm.build_plan(self.inputs)
        lines = []
        session = ufm.Session(plan, ufm.Credentials("root", "", "", "cumulus"), 5, Path(self.tmp.name),
                              lines.append, lambda: self.LEAF, apply=True)
        result = ufm.NodeResult(plan.nodes[0].hostname, "primary")
        plan.version = ""
        self.assertEqual(session.step_upgrade(plan.nodes[0], result), "SKIPPED")
        plan.version, plan.image_server = "2.6.1-8", ""
        with self.assertRaisesRegex(ufm.UfmError, "common.mgmt.http"):
            session.step_upgrade(plan.nodes[0], result)
        self.assertFalse(Path(str(self.state_path) + ".calls").exists(), "neither case may log in")

    def make_ha_ready(self):
        state = (json.loads(self.state_path.read_text()) if self.state_path.exists()
                 else dict(self.state, image_url=IMAGE_URL))
        for name in ("ufm01", "ufm02"):
            state["ufms"][name]["services"]["ufm-enterprise"] = "inactive"
            state["ufms"][name]["ib_ports"] = ["Polling", "LinkUp"]
        self.state_path.write_text(json.dumps(state))

    def make_only_the_service_block(self):
        self.make_ha_ready()
        state = json.loads(self.state_path.read_text())
        for name in ("ufm01", "ufm02"):
            state["ufms"][name]["services"]["ufm-enterprise"] = "active"
        self.state_path.write_text(json.dumps(state))

    def test_ha_setup_stops_at_a_real_blocker_and_changes_nothing(self):
        results, state, _calls, _logs = self.run_login(action="ha_setup")
        for name in ("ufm01", "ufm02"):
            self.assertEqual(results[name].status, "HA_NOT_READY")
            self.assertIn("LinkUp", results[name].detail)
            self.assertNotIn("不通", results[name].detail, "eth0 and eth1 both reach the peer")
            self.assertNotIn("VIP", results[name].detail)
            self.assertEqual(state["ufms"][name]["services"]["ufm-enterprise"], "active")
            self.assertNotIn("systemctl", state["ufms"][name])
            self.assertEqual(results[name].steps, [])
        self.assertFalse((self.sandbox / "ufm01/root/.ssh/id_ed25519").exists(), "no trust before HA is possible")

    def test_only_a_running_ufm_enterprise_is_offered_for_stop_then_ha_is_configured_and_started(self):
        # Owner 2026-10-20: ha-check comes first; ask before stopping ufm-enterprise; trust before HA.
        # Owner 2026-10-22 (ufm-manual.log): standby config, master config with the VIP, wait for the DRBD
        # sync, `ufm_ha_cluster start`; `ufm_ha_cluster status` alone decides, a failed sanity is a note.
        self.make_only_the_service_block()
        inspect, state, _calls, logs = self.run_login(action="check", apply=False)
        for name in ("ufm01", "ufm02"):
            self.assertEqual(inspect[name].facts["ha_problems"], ["ufm-enterprise 正在运行（active）"],
                             "check shows the running service as the only HA blocker")
            self.assertEqual(dict(self.outcomes(inspect[name]))["ha_config"], "WOULD_CHANGE")
            self.assertEqual(state["ufms"][name]["services"]["ufm-enterprise"], "active")
        self.assertIn(("root_keypair", "WOULD_CHANGE"), self.outcomes(inspect["ufm01"]))
        self.assertFalse((self.sandbox / "ufm01/root/.ssh/id_ed25519").exists())

        asked = []
        applied, state, _calls, logs = self.run_login(
            action="ha_setup", confirm=lambda host, action: asked.append(action) or True)
        self.assertEqual(len(asked), 1, "one confirmation covers the whole HA plan")
        for needle in ("停止", self.U1, self.U2, "/opt/ha_data", "ufm_ha_cluster start", "ha-post-config",
                       "ufm_ha_cluster config -r standby --local-primary-ip 192.0.2.2 --peer-primary-ip 192.0.2.1",
                       "--virtual-ip 198.51.101.133"):
            self.assertIn(needle, asked[0])
        self.assertEqual(state["ha_order"], ["ufm02:standby", "ufm01:master"], "the standby is configured first")
        self.assertEqual(state["ufms"]["ufm02"]["ha_config_calls"], [[
            "-r", "standby", "--local-primary-ip", "192.0.2.2", "--peer-primary-ip", "192.0.2.1",
            "--local-secondary-ip", "198.51.101.132", "--peer-secondary-ip", "198.51.101.130"]])
        self.assertEqual(state["ufms"]["ufm01"]["ha_config_calls"], [[
            "-r", "master", "--local-primary-ip", "192.0.2.1", "--peer-primary-ip", "192.0.2.2",
            "--local-secondary-ip", "198.51.101.130", "--peer-secondary-ip", "198.51.101.132",
            "--virtual-ip", "198.51.101.133"]])
        for name, role in (("ufm01", "master"), ("ufm02", "standby")):
            item = state["ufms"][name]
            self.assertEqual(applied[name].status, "HA_CONFIGURED", applied[name].detail)
            self.assertEqual(item["ha_saw_ufm_enterprise"], "inactive")
            self.assertIs(item["ha_config_stdout_tty"], False, "the configuration output goes to a log on the UFM")
            log = (self.sandbox / name / "root/.setup" / self.run_dir.name / f"ha-config-{role}.log").read_text()
            self.assertIn("[*] Configuring HA cluster done.", log)
            self.assertIn("New password", log)
            outcomes = self.outcomes(applied[name])
            self.assertEqual(outcomes[0], ("stop_ufm_enterprise", "STOPPED"), "the service is stopped before trust")
            self.assertLess(outcomes.index(("peer_login", "OK")), outcomes.index(("ha_config", "CONFIGURED")))
            self.assertIn(("ha_status", "OK"), outcomes)
        self.assertNotIn("New password", logs, "ufm_ha_cluster's own passwd prompts never reach the session")
        master = self.outcomes(applied["ufm01"])
        # Owner 2026-10-22: once HA is really set up, ha-setup goes on with ha-post-config.
        self.assertEqual(master[master.index(("ha_config", "CONFIGURED")):],
                         [("ha_config", "CONFIGURED"), ("drbd_sync", "SYNCED"), ("ha_start", "STARTED"),
                          ("ha_status", "OK"), ("post_ha_license", "INSTALLED"), ("post_ha_gv_cfg", "CHANGED"),
                          ("post_ha_root_guid", "CHANGED"), ("post_ha_failover", "DONE")])
        self.assertEqual(self.outcomes(applied["ufm02"])[-1], ("post_ha_verify", "OK"))
        self.assertEqual((state["ha"]["master"], state["ha"]["failovers"]), ("ufm02", 1), "no failback")
        self.assertEqual(state["ha"]["sync_left"], 0)
        self.assertIn("等待 DRBD 同步 [2]", logs, "a timestamped line per probe while the sync runs")
        self.assertIn("done:", logs)
        self.assertIn("DRBD 同步完成", logs)
        self.assertEqual(applied["ufm02"].facts["ha_sanity"], "passed", "on the master after the failover")
        self.assertEqual([note for item in applied.values() for note in item.facts.get("notes", [])], [])

        # Owner 2026-10-22: with an HA configuration present, ha-setup sets nothing up and ends with a hint.
        again, state, _calls, _logs = self.run_login(action="ha_setup",
                                                     confirm=lambda host, action: self.fail(action))
        for name in ("ufm01", "ufm02"):
            self.assertEqual(again[name].status, "HA_EXISTS", again[name].detail)
            self.assertEqual(again[name].steps, [])
            self.assertEqual(len(state["ufms"][name]["ha_config_calls"]), 1)
        self.assertEqual(len(again["ufm01"].facts["notes"]), 1)
        for needle in ("已有 HA 配置", "status 正常", "VIRTUAL_IP 198.51.101.133", "请先清除"):
            self.assertIn(needle, again["ufm01"].facts["notes"][0])

        checked, _state, _calls, _logs = self.run_login(action="check", apply=False)
        for name in ("ufm01", "ufm02"):
            outcomes = dict(self.outcomes(checked[name]))
            self.assertEqual((outcomes["ha_preconditions"], outcomes["ha_config"], outcomes["root_keypair"],
                              outcomes["peer_key"], outcomes["peer_login"]),
                             ("SKIPPED", "OK", "UNCHANGED", "UNCHANGED", "OK"), name)

    def test_a_failed_standby_configuration_leaves_the_master_untouched(self):
        self.make_ha_ready()
        state = json.loads(self.state_path.read_text())
        state["ufms"]["ufm02"]["ha_config_fails"] = True
        self.state_path.write_text(json.dumps(state))
        results, state, _calls, _logs = self.run_login(action="ha_setup")
        self.assertEqual(results["ufm02"].status, "HA_CONFIG_FAILED")
        self.assertIn("DRBD preflight validation failed", results["ufm02"].detail)
        self.assertIn("ha-config-standby.log", results["ufm02"].detail)
        self.assertNotIn("password", results["ufm02"].detail.casefold())
        self.assertEqual(results["ufm01"].status, "INCOMPLETE")
        self.assertNotIn("ha_config_calls", state["ufms"]["ufm01"])

    def test_a_sync_that_outlasts_the_wait_stops_before_start_and_the_next_run_changes_nothing(self):
        self.make_ha_ready()
        state = json.loads(self.state_path.read_text())
        state["ha_sync_polls"] = 1000
        self.state_path.write_text(json.dumps(state))
        results, state, _calls, _logs = self.run_login(action="ha_setup", ha_wait=(0, 1, 0, 60))
        for name in ("ufm01", "ufm02"):
            self.assertEqual(results[name].status, "HA_SYNC_TIMEOUT", results[name].detail)
            self.assertIn(f"同步完成后在 {self.U1} 上执行 ufm_ha_cluster start", results[name].detail)
            self.assertIn("已有 HA 配置", results[name].detail)
        self.assertFalse(state["ha"]["started"])
        state["ha"]["sync_left"] = 0
        self.state_path.write_text(json.dumps(state))
        again, state, _calls, _logs = self.run_login(action="ha_setup",
                                                     confirm=lambda host, action: self.fail(action))
        for name in ("ufm01", "ufm02"):
            self.assertEqual(again[name].status, "HA_EXISTS", again[name].detail)
            self.assertEqual(len(state["ufms"][name]["ha_config_calls"]), 1)
        self.assertFalse(state["ha"]["started"], "a configured cluster is never started by a later run")
        self.assertIn("Stopped (disabled)", again["ufm01"].facts["notes"][0])

    def test_a_cluster_with_another_vip_is_an_existing_configuration_and_left_alone(self):
        self.make_ha_ready()
        state = json.loads(self.state_path.read_text())
        state["ha"] = {"master": "ufm01", "standby": "ufm02", "vip": "198.51.101.140", "started": True,
                       "sync_left": 0}
        self.state_path.write_text(json.dumps(state))
        results, state, _calls, _logs = self.run_login(action="ha_setup",
                                                       confirm=lambda host, action: self.fail(action))
        for name in ("ufm01", "ufm02"):
            self.assertEqual(results[name].status, "HA_EXISTS")
            self.assertEqual(results[name].steps, [])
            self.assertNotIn("ha_config_calls", state["ufms"][name])
        note = results["ufm01"].facts["notes"][0]
        self.assertIn("集群的 VIRTUAL_IP 为 198.51.101.140，global 为 198.51.101.133", note)
        self.assertIn(f"{self.U1}, {self.U2} 上读到", note)
        self.assertFalse((self.sandbox / "ufm01/root/.ssh/id_ed25519").exists(), "no trust either")

    def test_the_status_after_start_decides_and_an_unhealthy_cluster_is_not_touched_again(self):
        self.make_ha_ready()
        state = json.loads(self.state_path.read_text())
        state["ufms"]["ufm01"]["ha_enterprise_fails"] = True
        self.state_path.write_text(json.dumps(state))
        results, state, _calls, _logs = self.run_login(action="ha_setup", ha_wait=(0, 60, 0, 1))
        for name in ("ufm01", "ufm02"):
            self.assertEqual(results[name].status, "HA_UNHEALTHY", results[name].detail)
            self.assertIn("ufm-enterprise Stopped", results[name].detail)
        self.assertIn(("ha_start", "STARTED"), self.outcomes(results["ufm01"]))
        again, state, _calls, _logs = self.run_login(action="ha_setup",
                                                     confirm=lambda host, action: self.fail(action))
        for name in ("ufm01", "ufm02"):
            self.assertEqual(again[name].status, "HA_EXISTS")
            self.assertEqual(len(state["ufms"][name]["ha_config_calls"]), 1)
        self.assertIn("ufm-enterprise Stopped", again["ufm01"].facts["notes"][0])

    def test_a_failed_sanity_check_is_only_a_note_at_the_end(self):
        self.make_ha_ready()
        state = json.loads(self.state_path.read_text())
        state["sanity_fails"] = True
        self.state_path.write_text(json.dumps(state))
        results, _state, _calls, _logs = self.run_login(action="ha_setup")
        self.assertEqual({item.status for item in results.values()}, {"HA_CONFIGURED"})
        self.assertEqual(results["ufm02"].facts["ha_sanity"], "failed")
        self.assertIn("ufm_enterprise_sanity.sh 未通过（不影响 HA 判定）: Checking Service... Failed",
                      results["ufm02"].facts["notes"][0])

    def test_declining_the_stop_changes_nothing(self):
        self.make_only_the_service_block()
        results, state, _calls, _logs = self.run_login(action="ha_setup", confirm=lambda host, action: False)
        self.assertEqual({item.status for item in results.values()}, {"NOT_AUTHORIZED"})
        for name in ("ufm01", "ufm02"):
            self.assertEqual(state["ufms"][name]["services"]["ufm-enterprise"], "active")
        self.assertFalse((self.sandbox / "ufm01/root/.ssh/id_ed25519").exists())

    def test_ha_setup_detects_a_vip_holder_that_ignores_ping_and_a_down_ha_link(self):
        self.make_ha_ready()
        state = json.loads(self.state_path.read_text())
        state["lan_hosts"] = {"198.51.101.133": {"mac": "aa:bb:cc:00:11:22", "icmp": False}}
        state["ufms"]["ufm02"]["ifaces"]["eno8403"]["oper"] = "down"
        self.state_path.write_text(json.dumps(state))
        results, _state, _calls, _logs = self.run_login(action="ha_setup")
        for name in ("ufm01", "ufm02"):
            self.assertEqual(results[name].status, "HA_NOT_READY")
            self.assertIn("VIP 198.51.101.133 已被网络中的设备使用（ARP 重复地址检测有应答）", results[name].detail)
            self.assertIn("HA 直连 eth1", results[name].detail)
            self.assertNotIn("管理口 eth0", results[name].detail)
        # Without arping the neighbour table is the fallback evidence.
        (self.devbin / "arping").unlink()
        if shutil.which("arping"):
            self.skipTest("a real arping on PATH would answer for the fake network")
        results, _state, _calls, _logs = self.run_login(action="ha_setup")
        self.assertIn("VIP 198.51.101.133 已被网络中的设备使用（lladdr aa:bb:cc:00:11:22）", results["ufm01"].detail)

    def test_a_stale_neighbour_entry_of_a_removed_vip_is_not_evidence(self):
        # Docker finding R1: right after the VIP moves away a REACHABLE cache entry remains.
        self.make_ha_ready()
        self.run_login(action="trust")
        for with_arping in (True, False):
            state = json.loads(self.state_path.read_text())
            for name in ("ufm01", "ufm02"):
                state["ufms"][name]["stale_neigh"] = {"198.51.101.133": "aa:bb:cc:00:11:22"}
            self.state_path.write_text(json.dumps(state))
            if not with_arping:
                (self.devbin / "arping").unlink()
                if shutil.which("arping"):
                    self.skipTest("a real arping on PATH would answer for the fake network")
            results, state, _calls, _logs = self.run_login(action="check", apply=False)
            self.assertEqual({dict(self.outcomes(item))["ha_preconditions"] for item in results.values()}, {"OK"},
                             (with_arping, [item.facts.get("ha_problems") for item in results.values()]))
            self.assertEqual(state["ufms"]["ufm01"]["stale_neigh"], {}, "the cached entry is flushed first")


class HaPostConfigTest(ConfiguredPairCase):
    """Owner 2026-10-22 (ufm-manual.log 1143-2088): ha-post-config through the VIP on a running HA."""
    VIP = "198.51.101.133"

    def make_ha_running(self, **ha):
        state = dict(self.state, image_url=IMAGE_URL)
        state["ha"] = dict({"master": "ufm01", "standby": "ufm02", "vip": self.VIP, "started": True,
                            "sync_left": 0, "loaded_licenses": []}, **ha)
        master = state["ufms"][state["ha"]["master"]]
        master["ipv4"] = f"{master['ipv4']} {self.VIP}/23"
        master["services"]["ufm-enterprise"] = "active"
        (self.files / "log/opensm-smdb.dump").write_text('0x0200000000000a01, VALID    , MAIN     ,    0, "smi0:1"\n')
        self.state_path.write_text(json.dumps(state))

    def add_ib_rows(self, *names):
        with (self.inputs / "ib.csv").open("a", encoding="utf-8") as handle:
            for index, name in enumerate(names):
                handle.write(f"{name},ib,NA,198.51.100.{20 + 2 * index},/23,198.51.101.254,,"
                             f"198.51.100.{21 + 2 * index},/23,198.51.101.254" + "," * 26 + "\n")

    def test_changes_fail_over_once_and_are_checked_on_the_new_master(self):
        self.make_ha_running()
        asked = []
        results, state, calls, logs = self.run_login(
            action="ha_post_config_command", confirm=lambda host, action: asked.append(action) or True)
        for name in ("ufm01", "ufm02"):
            self.assertEqual(results[name].status, "HA_POST_CONFIGURED", results[name].detail)
        self.assertEqual(len(asked), 1)
        self.assertIn("ha-post-config", asked[0])
        # license: downloaded by the master from the image server, into /opt/ufm/files/licenses
        self.assertEqual((self.files / "licenses/site.lic").read_text(), LICENSE_TEXT)
        self.assertEqual(state["ufms"]["ufm01"]["wget"], [LICENSE_URL])
        # gv.cfg: the three [Server] keys, every other byte as it was, the original backed up
        expected = (GV_CFG_SHIPPED.replace("multi_port_sm = disabled", "multi_port_sm = ha_enabled")
                    .replace("additional_fabric_interfaces =\n", "additional_fabric_interfaces = ib1\n"))
        self.assertEqual((self.files / "conf/gv.cfg").read_text(), expected)
        backup = self.sandbox / "ufm01/root/ufm-setup-upgrade-backup" / self.run_dir.name / "post-ha"
        self.assertEqual((backup / "gv.cfg").read_text(), GV_CFG_SHIPPED)
        # root_guid.conf: every ASIC of the spine in ib.csv, in the owner's order; the leaf is not a root
        self.assertEqual((self.files / "conf/opensm/root_guid.conf").read_text(),
                         "0x02000000000001a0\n0x02000000000001a1\n")
        # one failover; the new master shows two smi lines and a Valid license for its own MAC
        self.assertEqual((state["ha"]["master"], state["ha"]["failovers"]), ("ufm02", 1))
        self.assertEqual(state["ha"]["loaded_licenses"], ["site.lic"])
        self.assertEqual(self.outcomes(results["ufm01"]),
                         [("post_ha_license", "INSTALLED"), ("post_ha_gv_cfg", "CHANGED"),
                          ("post_ha_root_guid", "CHANGED"), ("post_ha_failover", "DONE")])
        self.assertEqual(self.outcomes(results["ufm02"]), [("post_ha_verify", "OK")])
        self.assertEqual([note for item in results.values() for note in item.facts.get("notes", [])], [])
        # every VIP login checked the host key against the two UFMs' own keys only
        vip_calls = [call for call in calls if call["target"].endswith("@" + self.VIP)]
        self.assertTrue(vip_calls)
        self.assertTrue(all(call["strict"] for call in vip_calls))
        known = (self.run_dir / "vip-known-hosts").read_text()
        self.assertIn(f"{self.VIP} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHOSTKEYUFM01", known)
        self.assertIn(f"{self.VIP} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHOSTKEYUFM02", known)

        # run again: everything is as wanted, nothing changes, no failover, nothing to confirm
        again, state, _calls, _logs = self.run_login(action="ha_post_config_command",
                                                     confirm=lambda host, action: self.fail(action))
        for name in ("ufm01", "ufm02"):
            self.assertEqual(again[name].status, "HA_POST_UP_TO_DATE", again[name].detail)
        self.assertEqual(self.outcomes(again["ufm02"]),
                         [("post_ha_license", "UNCHANGED"), ("post_ha_gv_cfg", "UNCHANGED"),
                          ("post_ha_root_guid", "UNCHANGED"), ("post_ha_failover", "NOT_NEEDED")])
        self.assertEqual(state["ha"]["failovers"], 1)

    def test_check_of_an_existing_ha_built_without_our_trust_counts_no_trust_change(self):
        # Owner 2026-10-23 (lab check of an HA set up by hand): ha-setup never touches an existing HA, so it
        # never builds trust for it, and config-upgrade does not either. A missing root key pair or peer key
        # is shown but never counted as a change to make, or check could never reach COMPLIANT.
        self.make_ha_running()
        self.assertFalse((self.sandbox / "ufm01/root/.ssh/id_ed25519").exists(), "the HA has no trust of ours")
        checked, _state, _calls, logs = self.run_login(action="check", apply=False)
        # As in the lab: ufm01 has no root key pair, ufm02 has one but not ufm01's key.
        self.assertEqual(dict(self.outcomes(checked["ufm01"]))["root_keypair"], "NOT_NEEDED")
        self.assertEqual(dict(self.outcomes(checked["ufm02"]))["peer_key"], "NOT_NEEDED")
        for name in ("ufm01", "ufm02"):
            outcomes = dict(self.outcomes(checked[name]))
            self.assertEqual(outcomes["ha_config"], "OK", name)
            for step in ("root_keypair", "peer_key", "peer_login"):
                self.assertIn(outcomes[step], {"UNCHANGED", "NOT_NEEDED", "NOT_TESTED", "OK"}, (name, step))
                self.assertNotIn(step, checked[name].detail or "", name)
        self.assertIn("已有 HA 配置：互信只作提示", logs)
        self.assertFalse((self.sandbox / "ufm01/root/.ssh/id_ed25519").exists(), "check never creates a key")

    def test_without_a_license_and_with_a_spine_missing_from_the_fabric_only_notes_are_left(self):
        (self.inputs / "image/site.lic").unlink()
        self.add_ib_rows("ew-spine002.site01.example.test")
        self.make_ha_running()
        results, state, _calls, _logs = self.run_login(action="ha_post_config_command")
        self.assertEqual({item.status for item in results.values()}, {"HA_POST_CONFIGURED"})
        notes = results["ufm01"].facts["notes"]
        self.assertIn("image 目录里没有 .lic 文件：未安装 license，跳过这一步；当前评估 license 到期日 2026-11-21", notes)
        self.assertTrue(any("ew-spine002.site01.example.test" in note and "补齐后重跑 ha-post-config" in note
                            for note in notes), notes)
        self.assertEqual((self.files / "conf/opensm/root_guid.conf").read_text(),
                         "0x02000000000001a0\n0x02000000000001a1\n", "what was found is still written")
        self.assertFalse(list((self.files / "licenses").iterdir()))
        self.assertNotIn("wget", state["ufms"]["ufm01"])

    def test_core_switches_are_the_only_roots_when_the_fabric_has_them(self):
        # Owner 2026-10-22: a large fabric has core switches (named "core"); then only they are roots.
        self.add_ib_rows("ew-core001.site01.example.test")
        self.state["fabric"] = FABRIC + [["0x02000000000003c0", "MF0;ew-core001.site01.example.test:Q3400_RA/U1"]]
        self.make_ha_running()
        results, _state, _calls, _logs = self.run_login(action="ha_post_config_command")
        self.assertEqual({item.status for item in results.values()}, {"HA_POST_CONFIGURED"})
        self.assertEqual((self.files / "conf/opensm/root_guid.conf").read_text(), "0x02000000000003c0\n")

    def test_a_stranger_answering_the_vip_is_refused_before_any_change(self):
        self.make_ha_running()
        state = json.loads(self.state_path.read_text())
        state["vip_key_override"] = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISTRANGER"
        self.state_path.write_text(json.dumps(state))
        results, state, _calls, _logs = self.run_login(action="ha_post_config_command")
        for name in ("ufm01", "ufm02"):
            self.assertEqual(results[name].status, "HA_POST_CONFIG_FAILED")
            self.assertIn("Host key verification failed", results[name].detail)
        self.assertEqual((self.files / "conf/gv.cfg").read_text(), GV_CFG_SHIPPED)
        self.assertNotIn("failovers", state["ha"])

    def test_no_running_ha_means_no_post_config(self):
        results, _state, _calls, _logs = self.run_login(action="ha_post_config_command")
        for name in ("ufm01", "ufm02"):
            self.assertEqual(results[name].status, "HA_NOT_READY")
            self.assertIn("没有 HA 集群", results[name].detail)
        self.assertEqual((self.files / "conf/gv.cfg").read_text(), GV_CFG_SHIPPED)


class HaPostConfigPureTest(unittest.TestCase):
    def test_only_the_three_server_keys_change(self):
        new, changes = ufm.gv_server_update(GV_CFG_SHIPPED)
        self.assertEqual(changes, ["multi_port_sm: disabled → ha_enabled", "additional_fabric_interfaces: 空 → ib1"])
        self.assertEqual(new.replace("multi_port_sm = ha_enabled", "multi_port_sm = disabled")
                         .replace("additional_fabric_interfaces = ib1", "additional_fabric_interfaces ="), GV_CFG_SHIPPED)
        self.assertEqual(ufm.gv_server_update(new), (new, []))
        added, changes = ufm.gv_server_update("[Server]\nws_port = 8000\n\n[Logging]\nlevel = INFO\n")
        self.assertEqual(added, "[Server]\nws_port = 8000\nfabric_interface = ib0\nmulti_port_sm = ha_enabled\n"
                                "additional_fabric_interfaces = ib1\n\n[Logging]\nlevel = INFO\n")
        self.assertEqual(len(changes), 3)
        with self.assertRaises(ufm.UfmError):
            ufm.gv_server_update("[Logging]\nlevel = INFO\n")

    def test_ibswitches_lines_and_roots(self):
        text = ('src/query_smp.c:199; umad (DR path slid 0; dlid 0; 0,1,75) bad status 110; Connection timed out\n'
                'Switch  : 0x02000000000001a1 ports 149 "MF0;ew-spine010.example.test:Q3400_RA/U2" enhanced port 0 lid 1 lmc 0\n'
                'Switch  : 0x02000000000001a0 ports 149 "MF0;ew-spine010.example.test:Q3400_RA/U1" enhanced port 0 lid 2 lmc 0\n'
                'Switch  : 0x02000000000001b0 ports 149 "MF0;ew-spine002.example.test:Q3400_RA/U1" enhanced port 0 lid 3 lmc 0\n')
        switches = ufm.parse_ibswitches(text)
        self.assertEqual(len(switches), 3)
        guids, missing = ufm.root_guid_plan(switches, ["ew-spine002", "ew-spine010.example.test", "ew-spine003"])
        self.assertEqual(guids, ["0x02000000000001b0", "0x02000000000001a0", "0x02000000000001a1"],
                         "natural order: spine002 before spine010, U1 before U2")
        self.assertEqual(missing, ["ew-spine003"])

    def test_the_license_row_of_the_master_must_be_valid(self):
        table = ("|----|\n|   Customer ID   |   Type   |   MAC Address   |   Exp. Date   | Status |\n|----|\n"
                 "|1 |Evaluation |NA |2026-11-21 |Valid |\n"
                 "|1 |Subscription |02:00:00:00:01:01 |2027-10-21 |Valid |\n"
                 "|1 |Subscription |02-00-00-00-02-01 |2027-10-21 |Invalid |\n")
        rows = ufm.license_rows(table)
        self.assertTrue(ufm.license_valid_for(rows, "02:00:00:00:01:01"))
        self.assertFalse(ufm.license_valid_for(rows, "02:00:00:00:02:01"))
        self.assertEqual(ufm.evaluation_expiry(rows), "2026-11-21")


class AddressOccupancyTest(ConfiguredPairCase):
    """Owner 2026-10-20: input addresses must not be in use by other devices; probed from the OOB
    Leaf/Spine that owns the subnet (here oob-leaf117 vlan1000), BMC ownership from oob-leaf115's FDB."""
    BMC = {"ufm01": "02:00:00:00:b0:01", "ufm02": "02:00:00:00:b0:02"}

    def switches(self):
        leaf117 = switch_state("oob-leaf117", LEAF_INTERFACES, LEAF_LINKS, LEAF_FDB, LEAF_NEIGH,
                               address_rows(("eth0", "203.0.112.119/23", None, "UP"),
                                            ("vlan1000", "198.51.101.250/23", LEAF_LL, "UP")),
                               reach=[UFM01_LL, UFM02_LL])
        bmc_fdb = (f"{self.BMC['ufm01']} dev swp17 vlan 1000 master br_default\n"
                   f"{self.BMC['ufm02']} dev swp18 vlan 1000 master br_default\n")
        leaf115 = switch_state("oob-leaf115", LEAF_INTERFACES, LEAF_LINKS, bmc_fdb, "",
                               address_rows(("eth0", "203.0.112.117/23", None, "UP")), reach=[])
        return {"203.0.112.119": leaf117, "203.0.112.117": leaf115}

    def answering(self, mapping):
        self.state["switches"]["203.0.112.119"]["arp"] = mapping

    def verdicts(self, result):
        return {item["kind"]: item["outcome"] for item in result.facts["address_check"]}

    def test_own_devices_answering_are_not_conflicts(self):
        self.answering({"198.51.101.130": "02:00:00:00:01:01", "198.51.101.132": "02:00:00:00:02:01",
                        "198.51.101.129": self.BMC["ufm01"], "198.51.101.131": self.BMC["ufm02"]})
        results, state, _calls, _logs = self.run_login(action="check", apply=False)
        self.assertEqual(self.verdicts(results["ufm01"]), {"eth0": "SELF", "ipmi": "SELF", "vip": "FREE"})
        self.assertEqual(self.verdicts(results["ufm02"]), {"eth0": "SELF", "ipmi": "SELF"})
        self.assertNotEqual(results["ufm01"].status, "ADDRESS_CONFLICT")
        self.assertEqual(sorted(state["switches"]["203.0.112.119"]["probes"]),
                         sorted(["198.51.101.130", "198.51.101.129", "198.51.101.132", "198.51.101.131",
                                 "198.51.101.133"]), "every input address is probed once, from the Leaf")

    def test_switches_use_the_deployment_key_and_never_ask_when_it_works(self):
        # Owner 2026-10-21: OOB Leaf/Spine by the deployment server's key first; a password only if it fails.
        asked = []
        results, state, _calls, logs = self.run_login(action="check", apply=False, eth_password="",
                                                      ask_eth=lambda: asked.append(1) or self.LEAF)
        self.assertEqual(asked, [])
        self.assertIn("198.51.101.130", state["switches"]["203.0.112.119"]["probes"])
        self.assertEqual(self.verdicts(results["ufm01"])["eth0"], "FREE")

    def test_a_rejected_key_asks_for_the_switch_password_once(self):
        self.state["leaf_keys"] = False
        asked = []
        results, state, _calls, logs = self.run_login(action="check", apply=False, eth_password="",
                                                      ask_eth=lambda: asked.append(1) or self.LEAF)
        self.assertEqual(len(asked), 1, "asked once for the whole run")
        self.assertIn("公钥登录被拒，改用密码", logs)
        self.assertEqual(sorted(state["switches"]["203.0.112.119"]["probes"]),
                         sorted(["198.51.101.130", "198.51.101.129", "198.51.101.132", "198.51.101.131",
                                 "198.51.101.133"]))
        self.assertEqual(results["ufm01"].facts["cabling"]["outcome"], "MATCH")

    def test_no_switch_password_leaves_the_switch_checks_unchecked(self):
        self.state["leaf_keys"] = False
        asked = []
        results, _state, _calls, _logs = self.run_login(action="check", apply=False, eth_password="",
                                                        ask_eth=lambda: asked.append(1) or "")
        self.assertEqual(len(asked), 1, "an empty answer is not asked again")
        self.assertEqual(set(self.verdicts(results["ufm01"]).values()), {"UNCHECKED"})
        self.assertEqual(results["ufm01"].facts["cabling"]["outcome"], "UNCHECKED")

    def test_neighbour_states_are_read_wherever_they_appear(self):
        # oob-leaf117 on 2026-10-21: the BMC's entry was "lladdr ... extern_learn NOARP proto zebra" (EVPN);
        # taking the word right after the MAC as the state turned it into FREE.
        mac, owner = "02:00:00:00:b0:01", ufm.address_owner
        self.assertEqual(owner({"ping": "no", "neigh": f"198.51.101.129 lladdr {mac} extern_learn NOARP proto zebra"}),
                         mac)
        self.assertEqual(owner({"ping": "no", "neigh": f"198.51.101.129 lladdr {mac} REACHABLE"}), mac)
        self.assertEqual(owner({"ping": "no", "neigh": f"198.51.101.129 lladdr {mac} STALE"}), "")
        self.assertEqual(owner({"ping": "yes", "neigh": f"198.51.101.129 lladdr {mac} STALE"}), mac)
        self.assertEqual(owner({"ping": "no", "neigh": "198.51.101.129 FAILED"}), "")

    def test_a_bmc_known_only_through_evpn_is_its_own(self):
        self.state["switches"]["203.0.112.119"]["evpn"] = {"198.51.101.129": self.BMC["ufm01"],
                                                          "198.51.101.131": self.BMC["ufm02"]}
        results, _state, _calls, _logs = self.run_login(action="check", apply=False)
        self.assertEqual(self.verdicts(results["ufm01"])["ipmi"], "SELF")
        self.assertEqual(self.verdicts(results["ufm02"])["ipmi"], "SELF")

    def test_the_ipmi_address_is_probed_from_the_bmc_leaf_first(self):
        # With an EVPN anycast gateway a reply goes to the host's own Leaf, so ping from where the BMC is cabled.
        leaf115 = self.state["switches"]["203.0.112.117"]
        leaf115["addresses"] = address_rows(("eth0", "203.0.112.117/23", None, "UP"),
                                            ("vlan1000", "198.51.101.250/23", LEAF_LL, "UP"))
        leaf115["arp"] = {"198.51.101.129": self.BMC["ufm01"], "198.51.101.131": self.BMC["ufm02"]}
        results, state, _calls, _logs = self.run_login(action="check", apply=False)
        self.assertEqual(sorted(state["switches"]["203.0.112.117"]["probes"]), ["198.51.101.129", "198.51.101.131"])
        self.assertNotIn("198.51.101.129", state["switches"]["203.0.112.119"]["probes"])
        self.assertIn("198.51.101.130", state["switches"]["203.0.112.119"]["probes"], "eth0 from its own Leaf")
        self.assertEqual(self.verdicts(results["ufm01"])["ipmi"], "SELF")

    def test_the_probe_reads_the_neighbour_again_when_evpn_has_not_caught_up(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "ip"
            fake.write_text('#!/bin/sh\n'
                            'case "$*" in *"vrf exec"*) exit 1;; esac\n'
                            f'if [ -e {tmp}/seen ]; then echo "198.51.101.129 lladdr 02:00:00:00:b0:01 extern_learn '
                            'NOARP proto zebra"; else touch ' + tmp + '/seen; fi\n')
            fake.chmod(0o755)
            script = ufm.address_probe_command("oob", "vlan1000", "198.51.101.129")[2]
            out = subprocess.run(["sh", "-c", script], env=dict(os.environ, PATH=f"{tmp}{os.pathsep}{os.environ['PATH']}"),
                                 capture_output=True, text=True, timeout=30).stdout
        facts = dict(line.split("=", 1) for line in out.splitlines())
        self.assertEqual(facts["ping"], "no")
        self.assertEqual(ufm.address_owner(facts), "02:00:00:00:b0:01")

    def test_an_address_taken_by_another_device_stops_check_and_config_upgrade(self):
        self.answering({"198.51.101.133": "02:aa:bb:cc:dd:ee", "198.51.101.131": "02:aa:bb:cc:dd:ef"})
        results, _state, _calls, _logs = self.run_login(action="check", apply=False)
        self.assertEqual((results["ufm01"].status, results["ufm02"].status), ("ADDRESS_CONFLICT", "ADDRESS_CONFLICT"))
        self.assertIn("vip 198.51.101.133: CONFLICT 已被其他设备 02:aa:bb:cc:dd:ee 占用", results["ufm01"].detail)
        self.assertIn("ipmi 198.51.101.131: CONFLICT", results["ufm02"].detail, "a MAC not on the BMC port")
        applied, state, _calls, _logs = self.run_login(action="config_upgrade_all")
        self.assertEqual({item.status for item in applied.values()}, {"ADDRESS_CONFLICT"})
        for name in ("ufm01", "ufm02"):
            self.assertNotIn("os_upgrade_runs", state["ufms"][name])
            self.assertNotIn("applied", state["ufms"][name])

    def test_a_conflict_on_one_node_leaves_the_other_untouched(self):
        self.answering({"198.51.101.132": "02:aa:bb:cc:dd:ee"})
        applied, state, _calls, _logs = self.run_login(action="config_upgrade_all")
        self.assertEqual((applied["ufm01"].status, applied["ufm02"].status), ("NOT_ATTEMPTED", "ADDRESS_CONFLICT"))
        self.assertNotIn("os_upgrade_runs", state["ufms"]["ufm01"])

    def test_without_an_svi_on_the_subnet_the_address_is_reported_unchecked(self):
        self.state["switches"]["203.0.112.119"]["addresses"] = LEAF_ADDRESSES_V4
        results, _state, _calls, _logs = self.run_login(action="check", apply=False)
        self.assertEqual(self.verdicts(results["ufm01"]), {"eth0": "UNCHECKED", "ipmi": "UNCHECKED", "vip": "UNCHECKED"})
        self.assertNotEqual(results["ufm01"].status, "ADDRESS_CONFLICT")


class CablingCheckTest(AddressOccupancyTest):
    """ib-initial-setup v15 rule: the MAC learned on the P2P OOB Leaf port of eth0 must be the CSV eth0_mac.
    Owner 2026-10-20: otherwise show the details and ask whether to continue (default no, 15 s)."""
    SWAPPED = ("02:00:00:00:02:01 dev swp17 vlan 1000 master br_default\n"
               "02:00:00:00:01:01 dev swp18 vlan 1000 master br_default\n")

    def leaf(self):
        return self.state["switches"]["203.0.112.119"]

    def logged_in(self, calls, name):
        address = {"ufm01": "198.51.101.130", "ufm02": "198.51.101.132"}[name]
        return [call for call in calls if address in str(call.get("target", ""))]

    def test_learned_macs_matching_the_csv_need_no_question(self):
        asked = []
        results, _state, _calls, logs = self.run_login(action="check", apply=False,
                                                       ask_continue=lambda text: asked.append(text) or False)
        self.assertEqual(asked, [])
        for name, mac, port in (("ufm01", "02:00:00:00:01:01", "swp17"), ("ufm02", "02:00:00:00:02:01", "swp18")):
            self.assertEqual(results[name].facts["cabling"]["outcome"], "MATCH")
            self.assertIn(f"eth0 MATCH: oob-leaf117 {port} 学到 {mac}", logs)
            self.assertEqual(results[name].status, "NEEDS_CONFIGURATION", results[name].detail)

    def test_swapped_cabling_is_explained_and_by_default_nothing_is_done(self):
        self.leaf()["fdb"] = self.SWAPPED
        asked = []
        results, state, calls, logs = self.run_login(action="config_upgrade_all",
                                                     ask_continue=lambda text: asked.append(text) or False)
        self.assertEqual([results[name].status for name in ("ufm01", "ufm02")], ["MAC_MISMATCH"] * 2)
        self.assertEqual(len(asked), 2, "one question per UFM")
        self.assertIn(self.U1, asked[0])
        for text in ("P2P 连线: ufm-01:8303 -> oob-leaf117 swp17", "CSV eth0_mac: 02:00:00:00:01:01",
                     "oob-leaf117 swp17 学到的 MAC: 02:00:00:00:02:01", "CSV 的 eth0_mac 写错"):
            self.assertIn(text, logs)
        self.assertIn("不继续", logs)
        for name in ("ufm01", "ufm02"):
            self.assertEqual(self.logged_in(calls, name), [], "no login to a UFM whose cabling does not match")
            self.assertNotIn("os_upgrade_runs", state["ufms"][name])
            self.assertEqual(results[name].facts["cabling"]["observed"],
                             ["02:00:00:00:02:01"] if name == "ufm01" else ["02:00:00:00:01:01"])

    def test_continuing_after_the_details_checks_the_node(self):
        self.leaf()["fdb"] = self.SWAPPED
        results, _state, calls, logs = self.run_login(action="check", apply=False, ask_continue=lambda text: True)
        for name in ("ufm01", "ufm02"):
            self.assertEqual(results[name].status, "NEEDS_CONFIGURATION", results[name].detail)
            self.assertTrue(results[name].facts["cabling"]["continued"])
            self.assertTrue(self.logged_in(calls, name))
        self.assertIn("用户选择继续", logs)
        printed = []
        with tempfile.TemporaryDirectory() as tmp:
            ufm.summarize(ufm.parse_args(["check"]), list(results.values()), Path(tmp), printed.append)
        self.assertIn("P2P 连线核对 MAC_MISMATCH，用户选择继续", "\n".join(printed))

    def test_a_port_that_is_down_or_learned_nothing_is_asked_about_too(self):
        self.leaf()["interfaces"] = nv_interface_table([("swp17", "down", "", ""), ("swp18", "up", "", "")])
        self.leaf()["fdb"] = "02:00:00:00:a1:17 dev swp18 vlan 1000 master br_default permanent\n"
        asked = []
        results, _state, calls, logs = self.run_login(action="check", apply=False,
                                                      ask_continue=lambda text: asked.append(text) or False)
        self.assertEqual((results["ufm01"].status, results["ufm02"].status), ("LINK_DOWN", "MAC_NOT_LEARNED"))
        self.assertEqual(len(asked), 2)
        self.assertIn("oob-leaf117 swp17 Oper Status=down", logs)
        self.assertIn("oob-leaf117 swp18 没有学到动态 MAC", logs)
        # Owner 2026-10-20 (as initial-setup v15): a link-local is derived only from a MAC the FDB learned
        # (when ND has no IPv6 for it), never from the CSV MAC of a port that learned nothing.
        self.assertFalse([call for call in calls if "ssh -6" in call["remote"]], "no link-local login attempt")

    def test_the_csv_mac_learned_on_another_port_of_that_leaf_is_named(self):
        self.leaf()["fdb"] = ("02:00:00:00:02:01 dev swp18 vlan 1000 master br_default\n"
                              "02:00:00:00:01:01 dev swp20 vlan 1000 master br_default\n")
        asked = []
        results, _state, _calls, logs = self.run_login(action="check", apply=False,
                                                       ask_continue=lambda text: asked.append(text) or False)
        self.assertEqual(results["ufm01"].status, "MAC_MISMATCH")
        self.assertIn("CSV MAC 02:00:00:00:01:01 出现在 oob-leaf117 swp20", results["ufm01"].facts["cabling"]["detail"])
        self.assertEqual(len(asked), 1)


class HaProblemsTest(unittest.TestCase):
    READY = {"ufm_enterprise": "inactive", "mgmt_peer": "yes", "ha_peer": "yes", "vip_local": "",
             "vip_ping": "no", "vip_neigh": "", "ib_linkup": "2"}

    def problems(self, **changes):
        return ufm.ha_problems(dict(self.READY, **changes), "ufm02", "198.51.101.133")

    def test_each_owner_condition_is_checked(self):
        self.assertEqual(self.problems(), [])
        for changes, needle in ((dict(ufm_enterprise="active"), "ufm-enterprise"),
                                (dict(ufm_enterprise="activating"), "ufm-enterprise"),
                                (dict(mgmt_peer="no"), "管理口 eth0"),
                                (dict(ha_peer="no"), "HA 直连 eth1"),
                                (dict(vip_ping="yes"), "ping 有应答"),
                                (dict(vip_neigh="lladdr aa:bb:cc:dd:ee:ff"), "lladdr aa:bb:cc:dd:ee:ff"),
                                (dict(vip_arp="used"), "ARP 重复地址检测"),
                                (dict(vip_arp="free", vip_ping="yes"), "ping 有应答"),
                                (dict(vip_local="eno8303"), "已配置在本机 eno8303"),
                                (dict(ib_linkup="0"), "LinkUp"),
                                (dict(ib_linkup="missing"), "没有 ibstat"),
                                (dict(ib_linkup=""), "LinkUp")):
            found = self.problems(**changes)
            self.assertEqual(len(found), 1, (changes, found))
            self.assertIn(needle, found[0], changes)
        self.assertEqual(self.problems(ufm_enterprise="failed"), [], "only a running service blocks HA")
        self.assertEqual(self.problems(vip_arp="free", vip_neigh="lladdr aa:bb:cc:dd:ee:ff"), [],
                         "with arping, a cached neighbour entry is not evidence")

    def test_script_runs_read_only_commands_on_the_named_interfaces(self):
        script = ufm.ha_check_script("eno8303", "198.51.101.132", "eno8403", "192.0.2.2", "198.51.101.133")
        self.assertIn("ping -c 3 -W 2 -I eno8303 198.51.101.132", script)
        self.assertIn("ping -c 3 -W 2 -I eno8403 192.0.2.2", script)
        self.assertIn("ip neigh show 198.51.101.133 dev eno8303", script)
        self.assertIn("Physical state: LinkUp", script)
        for verb in ("systemctl stop", "systemctl start", "systemctl restart", "ip addr add", "> /etc"):
            self.assertNotIn(verb, script)
        self.assertEqual(subprocess.run(["bash", "-n"], input=script, text=True).returncode, 0)
        with self.assertRaises(ufm.UfmError):
            ufm.ha_check_script("eno8303;reboot", "198.51.101.132", "eno8403", "192.0.2.2", "198.51.101.133")
        with self.assertRaises(ValueError):
            ufm.ha_check_script("eno8303", "198.51.101.132", "eno8403", "192.0.2.2", "1.2.3.4; reboot")


# `ufm_ha_cluster status` as ufm-manual.log records it (owner 2026-10-22), documentation VIP.
HA_STATUS_STARTED = """Reading configuration from /var/lib/ufm_ha/ha_state
Loading enabled add-ons from registry
Cluster name: ufmcluster
Cluster Summary:
  * Stack: corosync (Pacemaker is running)
  * Current DC: ufm01 (version 2.1.6-6fdc9deea29) - partition with quorum
  * Last updated: Thu Oct 22 05:34:09 2026 on ufm01
  * Last change:  Thu Oct 22 05:30:59 2026 by root via cibadmin on ufm01
  * 2 nodes configured
  * 7 resource instances configured

Node List:
  * Online: [ ufm01 ufm02 ]

Full List of Resources:
  * Clone Set: ha_data_drbd-clone [ha_data_drbd] (promotable):
    * Promoted: [ ufm01 ]
    * Unpromoted: [ ufm02 ]
  * Resource Group: ufmcluster-grp:
    * ha_data_file_system       (ocf:heartbeat:Filesystem):      Started ufm01
    * cluster_virtual_ip_0      (ocf:heartbeat:IPaddr2):         Started ufm01
    * ufm-ha-watcher    (systemd:ufm-ha-watcher):        Started ufm01
    * ufm-enterprise    (systemd:ufm-enterprise):        Started ufm01
  * ha-monitor  (systemd:ha-monitor):    Started ufm01

Daemon Status:
  corosync: active/enabled
  pacemaker: active/enabled
  pcsd: active/enabled

DRBD Status:
  DRBD_RESOURCE:              [ha_data]
  DRBD_CONNECTIVITY:          [Connected]
  DISK_STATE:                 [UpToDate]
  DRBD_ROLE:                  [Primary]
  PEER_DISK_STATE:            [UpToDate]
  PEER_DRBD_ROLE:             [Secondary]
VIRTUAL_IP:                   [198.51.101.133]"""
# After `ufm_ha_cluster failover` (ufm-manual.log): ufm02 promoted, plus a WARNINGS block about the move.
HA_STATUS_AFTER_FAILOVER = (HA_STATUS_STARTED
                            .replace("Cluster name: ufmcluster\n", "Cluster name: ufmcluster\n\nWARNINGS:\n"
                                     "Following resources have been moved and their move constraints are still in "
                                     "place: 'ufmcluster-grp'\nRun 'pcs constraint location' or 'pcs resource clear "
                                     "<resource id>' to view or remove the constraints, respectively\n\n")
                            .replace("Promoted: [ ufm01 ]", "Promoted: [ ufm02 ]")
                            .replace("Unpromoted: [ ufm02 ]", "Unpromoted: [ ufm01 ]")
                            .replace("Started ufm01", "Started ufm02"))
# Inferred, not observed: configured by `ufm_ha_cluster config` but not started yet.
HA_STATUS_NOT_STARTED = (HA_STATUS_STARTED
                         .replace("    * Promoted: [ ufm01 ]\n    * Unpromoted: [ ufm02 ]",
                                  "    * Stopped (disabled): [ ufm01 ufm02 ]")
                         .replace("Started ufm01", "Stopped (disabled)"))
# Inferred, not observed: a node without a cluster.
HA_STATUS_NONE = "Error: error running crm_mon, is pacemaker running?"
# The older layout from the owner's 2026-10-21 example (Pacemaker 1).
HA_STATUS_PACEMAKER_1 = """Cluster name: ufmcluster
Stack: corosync
Current DC: ufm02 (version 1.1.18-2b07d5c5a9) - partition with quorum

2 nodes configured
6 resources configured

Online: [ ufm01 ufm02 ]

Full list of resources:

 Master/Slave Set: ha_data_drbd_master [ha_data_drbd]
     Masters: [ ufm01 ]
     Slaves: [ ufm02 ]
 Resource Group: ufmcluster-grp
     ha_data_file_system        (ocf::heartbeat:Filesystem):    Started ufm01
     cluster_virtual_ip (ocf::heartbeat:IPaddr2):       Started ufm01
     ufm-ha-watcher     (systemd:ufm-ha-watcher):       Started ufm01
     ufm-enterprise     (systemd:ufm-enterprise):       Started ufm01

Daemon Status:
  corosync: active/enabled
  pacemaker: active/enabled
  pcsd: active/enabled
DRBD_RESOURCE:     ha_data
DRBD_CONNECTIVITY: Connected
DISK_STATE:        UpToDate
DRBD_ROLE:         Primary
PEER_DISK_STATE:   UpToDate
PEER_DRBD_ROLE:    Secondary
VIRTUAL_IP:        198.51.101.133"""
# `drbdadm status` on the master: synced as the owner saw it; while syncing (DRBD 9 layout, inferred);
# right after `ufm_ha_cluster config` (verbose layout from the config output).
DRBD_SYNCED = ("ha_data role:Primary\n  disk:UpToDate\n  peer role:Secondary\n"
               "    replication:Established peer-disk:UpToDate\n")
DRBD_SYNCING = ("ha_data role:Primary\n  disk:UpToDate\n  peer role:Secondary\n"
                "    replication:SyncSource peer-disk:Inconsistent done:42.17\n")
DRBD_CONNECTING = ("ha_data role:Primary suspended:no\n    write-ordering:drain\n  volume:0 minor:0 disk:UpToDate\n"
                   "      size:157147424 read:2112 written:0 al-writes:8 bm-writes:0 upper-pending:0\n"
                   "  peer connection:Connecting role:Unknown congested:no\n"
                   "    volume:0 replication:Off peer-disk:DUnknown resync-suspended:no\n")


class HaStatusTest(unittest.TestCase):
    """Owner 2026-10-22: `ufm_ha_cluster status` is the only basis for judging HA."""
    U1, U2 = PhasesCase.U1, PhasesCase.U2
    VIP = "198.51.101.133"

    def setUp(self):
        self.master = ufm.UfmNode(self.U1, 1, "198.51.101.130", "198.51.101.130/23", "198.51.101.254",
                                  "02:00:00:00:01:01")
        self.standby = ufm.UfmNode(self.U2, 2, "198.51.101.132", "198.51.101.132/23", "198.51.101.254",
                                   "02:00:00:00:02:01")
        self.nodes = [self.master, self.standby]

    def judge(self, text, master=None):
        return ufm.ha_status_problems(ufm.parse_ha_status(text), self.nodes, self.VIP, master)

    def test_the_status_after_start_from_ufm01_is_read_in_full_and_healthy(self):
        status = ufm.parse_ha_status(HA_STATUS_STARTED)
        self.assertEqual((status["online"], status["masters"], status["slaves"], status["nodes"], status["quorum"]),
                         (["ufm01", "ufm02"], ["ufm01"], ["ufm02"], 2, True))
        self.assertEqual(status["drbd"]["VIRTUAL_IP"], self.VIP)
        self.assertEqual(len(status["resources"]), 5)
        self.assertEqual(ufm.ha_cluster_kind(status, self.nodes, self.VIP), ("ours", ""))
        self.assertEqual(self.judge(HA_STATUS_STARTED, self.master), [], "pacemaker names the FQDN hosts by label")
        self.assertEqual(self.judge(HA_STATUS_PACEMAKER_1, self.master), [])

    def test_after_a_failover_either_node_may_be_promoted_unless_the_master_is_required(self):
        self.assertEqual(self.judge(HA_STATUS_AFTER_FAILOVER), [], "the WARNINGS block is not a resource")
        self.assertEqual(self.judge(HA_STATUS_AFTER_FAILOVER, self.master),
                         [f"Promoted 为 {self.U2}，应为 {self.U1}"])
        half = HA_STATUS_AFTER_FAILOVER.replace("ufm-enterprise    (systemd:ufm-enterprise):        Started ufm02",
                                                "ufm-enterprise    (systemd:ufm-enterprise):        Started ufm01")
        self.assertEqual(self.judge(half), [f"ufm-enterprise 运行在 ufm01，不在 {self.U2}"])

    def test_a_field_that_cannot_be_read_is_a_problem_not_a_default(self):
        bare = HA_STATUS_STARTED.split("Daemon Status:")[0]
        problems = self.judge(bare, self.master)
        for needle in ("corosync 未读到", "pcsd 未读到", "DRBD_CONNECTIVITY 未读到", "PEER_DISK_STATE 未读到",
                       "VIRTUAL_IP 未读到"):
            self.assertTrue(any(needle in item for item in problems), (needle, problems))
        broken = HA_STATUS_STARTED.replace("[Connected]", "[StandAlone]").replace(
            "PEER_DISK_STATE:            [UpToDate]", "PEER_DISK_STATE:            [Outdated]")
        self.assertEqual(self.judge(broken, self.master),
                         ["DRBD_CONNECTIVITY StandAlone（应为 Connected）", "PEER_DISK_STATE Outdated（应为 UpToDate）"])
        offline = HA_STATUS_STARTED.replace("Online: [ ufm01 ufm02 ]", "Online: [ ufm01 ]\n  * OFFLINE: [ ufm02 ]")
        self.assertIn(f"不在线: {self.U2}", self.judge(offline, self.master))

    def test_absent_ours_and_foreign_clusters(self):
        def kind(text):
            return ufm.ha_cluster_kind(ufm.parse_ha_status(text), self.nodes, self.VIP)
        self.assertEqual(kind(HA_STATUS_NONE), ("absent", ""))
        self.assertEqual(kind(""), ("absent", ""))
        self.assertEqual(kind(HA_STATUS_NOT_STARTED)[0], "ours")
        other_vip = kind(HA_STATUS_STARTED.replace(self.VIP, "198.51.101.140"))
        self.assertEqual(other_vip[0], "foreign")
        self.assertIn("198.51.101.140", other_vip[1])
        stranger = kind(HA_STATUS_STARTED.replace("Online: [ ufm01 ufm02 ]", "Online: [ ufm01 ufm09 ]"))
        self.assertEqual(stranger[0], "foreign")
        self.assertIn("ufm09", stranger[1])
        self.assertIn(self.U2, stranger[1])

    def test_a_configured_but_not_started_cluster_is_an_existing_configuration(self):
        # Owner 2026-10-22: any HA configuration counts, whatever its state.
        status = ufm.parse_ha_status(HA_STATUS_NOT_STARTED)
        self.assertEqual(ufm.ha_cluster_kind(status, self.nodes, self.VIP), ("ours", ""))
        summary = ufm.ha_summary(status, self.nodes, self.VIP)
        self.assertTrue(summary.startswith("节点 ufm01 ufm02，VIRTUAL_IP 198.51.101.133，status 不正常: "), summary)
        self.assertIn("ha_data_file_system Stopped (disabled)", summary)
        self.assertTrue(summary.endswith("…"), "at most four problems, the rest elided")
        self.assertEqual(ufm.ha_summary(ufm.parse_ha_status(HA_STATUS_STARTED), self.nodes, self.VIP),
                         "节点 ufm01 ufm02，VIRTUAL_IP 198.51.101.133，status 正常")

    def test_drbd_sync_is_done_only_when_both_disks_are_up_to_date_and_replicating(self):
        self.assertTrue(ufm.drbd_sync_state(DRBD_SYNCED)["synced"])
        syncing = ufm.drbd_sync_state(DRBD_SYNCING)
        self.assertEqual((syncing["synced"], syncing["replication"], syncing["peer_disk"], syncing["done"]),
                         (False, "SyncSource", "Inconsistent", "42.17"))
        connecting = ufm.drbd_sync_state(DRBD_CONNECTING)
        self.assertEqual((connecting["synced"], connecting["disk"], connecting["connection"], connecting["peer_disk"]),
                         (False, "UpToDate", "Connecting", "DUnknown"))
        self.assertFalse(ufm.drbd_sync_state(DRBD_SYNCED.replace("  disk:UpToDate", "  disk:Inconsistent"))["synced"],
                         "the local disk is read separately from peer-disk")
        self.assertFalse(ufm.drbd_sync_state("")["synced"])

    def test_the_scripts_are_read_only_or_log_everything_on_the_ufm(self):
        for script in (ufm.ha_status_script(), ufm.DRBD_STATUS_SCRIPT, ufm.HA_SANITY_SCRIPT):
            self.assertEqual(subprocess.run(["bash", "-n"], input=script, text=True).returncode, 0)
            for verb in ("config", "start", "failover", "systemctl"):
                self.assertNotIn(f"ufm_ha_cluster {verb}", script)
        argv = ufm.ha_config_argv("master", "192.0.2.1", "192.0.2.2", "198.51.101.130", "198.51.101.132", self.VIP)
        script = ufm.ha_logged_script(argv, "/root/.setup/run-1/ha-config-master.log", "config",
                                      ufm.HA_CONFIG_DONE)
        self.assertEqual(subprocess.run(["bash", "-n"], input=script, text=True).returncode, 0)
        self.assertIn('nohup ufm_ha_cluster config -r master --local-primary-ip 192.0.2.1 --peer-primary-ip 192.0.2.2 '
                      '--local-secondary-ip 198.51.101.130 --peer-secondary-ip 198.51.101.132 '
                      '--virtual-ip 198.51.101.133 </dev/null >"$log" 2>&1', script)
        self.assertIn("grep -viF password", script, "the tail never carries the hacluster password prompts")
        with self.assertRaises(ufm.UfmError):
            ufm.ha_config_argv("standby", "192.0.2.2", "192.0.2.1", "198.51.101.132", "198.51.101.130", self.VIP)
        with self.assertRaises(ufm.UfmError):
            ufm.ha_config_argv("master", "192.0.2.1", "192.0.2.2", "198.51.101.130", "198.51.101.132")
        with self.assertRaises(ValueError):
            ufm.ha_config_argv("standby", "192.0.2.2; reboot", "192.0.2.1", "198.51.101.132", "198.51.101.130")
        with self.assertRaises(ufm.UfmError):
            ufm.ha_logged_script(argv, "/tmp/x.log", "config")


class CommandLineTest(unittest.TestCase):
    def parse_fails(self, argv):
        with self.assertRaises(SystemExit, msg=argv) as caught, open(os.devnull, "w") as null:
            stderr, sys.stderr = sys.stderr, null
            try:
                ufm.parse_args(argv)
            finally:
                sys.stderr = stderr
        self.assertEqual(caught.exception.code, 2, argv)

    def test_three_commands_and_defaults(self):
        # Owner 2026-10-20: check (default, includes login) / config-upgrade / ha-setup.
        for argv in ([], ["--input-dir", str(ufm.TOOL_DIR)]):
            args = ufm.parse_args(argv)
            self.assertEqual((args.command, args.node, args.apply, args.inputs_only), ("check", None, False, False))
            self.assertEqual(args.input_dir, ufm.TOOL_DIR)
        # Owner 2026-10-22: HA is split into ha-setup and ha-post-config.
        self.assertEqual(set(ufm.DONE_STATUSES), {"check", "config-upgrade", "ha-setup", "ha-post-config"})
        self.assertEqual(ufm.FIRST_LOGIN_COMMANDS, {"check", "config-upgrade"})
        self.assertEqual(ufm.PAIR_COMMANDS, {"ha-setup", "ha-post-config"})
        self.assertEqual(ufm.DONE_STATUSES["ha-post-config"], {"HA_POST_CONFIGURED", "HA_POST_UP_TO_DATE"})
        args = ufm.parse_args(["config-upgrade", "--apply", "--node", "ufm01"])
        self.assertEqual((args.node, args.wait_initial, args.wait_interval, args.wait_max), ("ufm01", 600, 30, 2400))
        self.assertEqual(ufm.DONE_STATUSES["config-upgrade"], {"UPGRADED", "UP_TO_DATE", "CONFIGURED"})
        # Owner 2026-10-22: ha-setup configures and starts HA; an existing configuration (HA_EXISTS) and
        # HA_READY (preconditions only) are not done.
        self.assertEqual(ufm.DONE_STATUSES["ha-setup"], {"HA_CONFIGURED"})
        self.assertIsNone(ufm.parse_args(["ha-setup", "--apply"]).node)
        for removed in ("login", "access", "base", "base-config", "trust", "upgrade", "ha-check"):
            self.parse_fails([removed])
        for bad in (["config-upgrade"], ["ha-setup"], ["ha-post-config"], ["config-upgrade", "--yes"],
                    ["config-upgrade", "--apply", "--wait-initial", "3000"],
                    ["config-upgrade", "--apply", "--wait-interval", "0"],
                    ["config-upgrade", "--apply", "--wait-max", "10"], ["check", "--apply"],
                    ["check", "--yes"], ["ha-setup", "--apply", "--inputs-only"]):
            self.parse_fails(bad)

    def test_check_inputs_only_never_prompts(self):
        with tempfile.TemporaryDirectory() as tmp:
            inputs = make_inputs(Path(tmp))
            with mock.patch.object(ufm, "read_secret", side_effect=AssertionError("prompted")), \
                    mock.patch("builtins.print"):
                self.assertEqual(ufm.main(["--input-dir", str(inputs), "check", "--inputs-only"]), 0)

    def run_main(self, argv, typed="New-Pw-2026!"):
        """cmd_nodes up to the Session: which prompts appear, in which order, and what the Session receives."""
        prompts, captured = [], {}

        class FakeSession:
            def __init__(self, plan, creds, *args, **kwargs):
                captured.update(creds=creds, apply=kwargs["apply"], confirm=kwargs["confirm"], ask_eth=args[3],
                                ask_continue=kwargs["ask_continue"],
                                confirm_new_password=kwargs["confirm_new_password"])
                self.stopped = ""

            def stop(self, result, status, detail):
                result.status, result.detail = status, detail
                return result

            def config_upgrade(self, node, _allow=False):
                captured.setdefault("visited", []).append(node.hostname)
                return ufm.NodeResult(node.hostname, "primary", status="UPGRADED")

            def check(self, nodes):
                captured["visited"] = [node.hostname for node in nodes]
                return [ufm.NodeResult(node.hostname, "primary", status="COMPLIANT") for node in nodes]

            def ha_setup(self, nodes):
                return [ufm.NodeResult(node.hostname, "primary", status="HA_CONFIGURED") for node in nodes]

            def ha_post_config_command(self, nodes):
                captured["visited"] = [node.hostname for node in nodes]
                return [ufm.NodeResult(node.hostname, "primary", status="HA_POST_UP_TO_DATE") for node in nodes]

            def config_upgrade_all(self, nodes):
                return [self.config_upgrade(node) for node in nodes]

        class Terminal:
            @staticmethod
            def isatty():
                return True
        with tempfile.TemporaryDirectory() as tmp:
            inputs = make_inputs(Path(tmp))
            with mock.patch.object(ufm, "read_secret", side_effect=lambda text: prompts.append(text) or typed), \
                    mock.patch.object(ufm, "Session", FakeSession), mock.patch.object(sys, "stdin", Terminal()), \
                    mock.patch("builtins.print"):
                code = ufm.main(["--input-dir", str(inputs)] + argv)
        return code, prompts, captured

    def test_new_password_is_asked_first_and_reused_for_the_ipmi_user(self):
        # Owner 2026-10-21: the operator types one password per run.
        code, prompts, captured = self.run_main(["config-upgrade", "--apply", "--yes"])
        self.assertEqual((code, len(prompts)), (0, 1), prompts)
        self.assertEqual(captured["creds"].eth_password, "", "OOB Leaf/Spine: deployment keys, no prompt")
        creds = captured["creds"]
        self.assertEqual((creds.new_password, creds.ipmi_password, creds.factory_password),
                         ("New-Pw-2026!", "New-Pw-2026!", ufm.DEFAULT_FACTORY_PASSWORD))
        self.assertIs(captured["confirm"], None)
        self.assertEqual(ufm.DEFAULT_FACTORY_PASSWORD, "UFMappliance")
        code, prompts, captured = self.run_main([])
        self.assertEqual((code, len(prompts), captured["apply"]), (0, 1, False), "bare invocation runs check")
        self.assertEqual(captured["creds"].factory_password, ufm.DEFAULT_FACTORY_PASSWORD)
        self.assertEqual(len(captured["visited"]), 2, "every server_ufm by default")
        code, prompts, captured = self.run_main(["ha-setup", "--apply"])
        self.assertEqual((code, len(prompts), captured["creds"].factory_password), (0, 1, ""),
                         "only the first login uses the factory default")
        code, prompts, _captured = self.run_main(["config-upgrade", "--apply", "--ask-factory-password"],
                                                 typed="Other-Pw-1")
        self.assertEqual(len(prompts), 2)
        code, prompts, captured = self.run_main(["config-upgrade", "--apply", "--yes"], typed="A-Very-Long-Pw-17")
        self.assertEqual((code, captured), (1, {}), "a password ipmitool cannot take stops before any login")
        code, _prompts, captured = self.run_main(["check", "--node", "ufm01"])
        self.assertEqual((code, captured["visited"]), (0, ["ufm01.site01.example.test"]))
        code, _prompts, captured = self.run_main(["ha-setup", "--apply", "--node", "ufm01"])
        self.assertEqual((code, captured), (1, {}), "ha-setup always works on both nodes")
        code, _prompts, captured = self.run_main(["ha-post-config", "--apply"])
        self.assertEqual((code, len(captured["visited"])), (0, 2), "ha-post-config works on both nodes too")
        code, _prompts, captured = self.run_main(["ha-post-config", "--apply", "--node", "ufm02"])
        self.assertEqual((code, captured), (1, {}))

    def test_a_cabling_question_waits_15_seconds_and_defaults_to_no(self):
        code, _prompts, captured = self.run_main(["check"])
        self.assertEqual(code, 0)
        with mock.patch.object(ufm, "ask_yes_no_timed", return_value=False) as timed:
            self.assertIs(captured["ask_continue"]("继续？"), False)
        prompt, timeout = timed.call_args[0]
        self.assertEqual(timeout, 15)
        self.assertIn("15 秒", prompt)
        self.assertIn("[y/N]", prompt)

    def test_the_switch_password_is_asked_only_when_the_key_is_rejected(self):
        code, prompts, captured = self.run_main(["check"])
        self.assertEqual((code, len(prompts), captured["creds"].eth_password), (0, 1, ""))
        with mock.patch.object(ufm, "read_secret", return_value="Leaf-Pw-9") as typed:
            self.assertEqual(captured["ask_eth"](), "Leaf-Pw-9")
        self.assertIn("OOB Leaf/Spine", typed.call_args[0][0])
        with self.assertRaises(SystemExit):
            ufm.parse_args(["check", "--ask-eth-password"])

    def test_a_forced_password_change_is_confirmed_by_typing_it_again(self):
        _code, _prompts, captured = self.run_main(["config-upgrade", "--apply", "--yes"])
        with mock.patch.object(ufm, "read_secret", return_value="New-Pw-2026!") as typed:
            self.assertEqual(captured["confirm_new_password"](), "New-Pw-2026!")
        self.assertIn("再次输入", typed.call_args[0][0])

    def test_mode_lines(self):
        self.assertIn("只读", ufm.mode_line(ufm.parse_args([])))
        self.assertIn("/root/.setup", ufm.mode_line(ufm.parse_args([])), "check keeps the scripts it ran")
        self.assertNotIn("不留文件", ufm.mode_line(ufm.parse_args([])))
        for command in ("config-upgrade", "ha-setup", "ha-post-config"):
            self.assertIn("APPLY", ufm.mode_line(ufm.parse_args([command, "--apply"])))
            self.assertIn("--yes", ufm.mode_line(ufm.parse_args([command, "--apply", "--yes"])))

    def test_exit_code_separates_pending_changes_from_failures(self):
        def code(command, statuses):
            args = ufm.parse_args([command] + (["--apply"] if command != "check" else []))
            results = [ufm.NodeResult(f"ufm0{index}", "primary", status=status)
                       for index, status in enumerate(statuses, 1)]
            with tempfile.TemporaryDirectory() as tmp:
                return ufm.summarize(args, results, Path(tmp), lambda _text: None)
        self.assertEqual(ufm.EXIT_PENDING, 3, "2 is argparse's usage error (owner 2026-10-20)")
        self.assertEqual(code("check", ["COMPLIANT", "COMPLIANT"]), 0)
        self.assertEqual(code("check", ["COMPLIANT", "NEEDS_CONFIGURATION"]), 3)
        self.assertEqual(code("check", ["NEW_DEVICE", "COMPLIANT"]), 3)
        self.assertEqual(code("check", ["NEW_DEVICE", "AUTH_REJECTED"]), 1)
        self.assertEqual(code("config-upgrade", ["UPGRADED", "UP_TO_DATE"]), 0)
        self.assertEqual(code("config-upgrade", ["NOT_AUTHORIZED", "NOT_ATTEMPTED"]), 1)
        self.assertEqual(code("config-upgrade", ["NEEDS_CONFIGURATION"]), 1, "--apply never leaves work pending")
        self.assertEqual(code("ha-setup", ["HA_CONFIGURED", "HA_NOT_READY"]), 1)
        self.assertEqual(code("ha-setup", ["HA_CONFIGURED", "HA_CONFIGURED"]), 0)
        self.assertEqual(code("ha-setup", ["HA_EXISTS", "HA_EXISTS"]), 1, "an existing HA must be cleared first")
        self.assertEqual(code("ha-post-config", ["HA_POST_UP_TO_DATE", "HA_POST_CONFIGURED"]), 0)
        self.assertEqual(code("ha-post-config", ["HA_POST_CONFIG_FAILED", "HA_POST_CONFIG_FAILED"]), 1)
        self.assertEqual(code("ha-setup", ["HA_READY", "HA_READY"]), 1, "preconditions alone are not HA")

    def test_notes_come_last_and_change_no_exit_code(self):
        # Owner 2026-10-22: a failed ufm_enterprise_sanity.sh is only pointed out at the end.
        args = ufm.parse_args(["ha-setup", "--apply"])
        results = [ufm.NodeResult("ufm01", "primary", status="HA_CONFIGURED",
                                  facts={"notes": ["ufm_enterprise_sanity.sh 未通过（不影响 HA 判定）: Failed"]}),
                   ufm.NodeResult("ufm02", "secondary", status="HA_CONFIGURED")]
        lines = []
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(ufm.summarize(args, results, Path(tmp), lines.append), 0)
        self.assertTrue(lines[-2].startswith("结果: 2/2"), lines)
        self.assertEqual(lines[-1], "提示: ufm01: ufm_enterprise_sanity.sh 未通过（不影响 HA 判定）: Failed")


class TimedSecretTest(unittest.TestCase):
    """The timed terminal reader behind the 15 s P2P cabling question (owner 2026-10-20)."""

    def ask(self, keys, timeout=0.6):
        master, slave = pty.openpty()
        box = {}

        def worker():
            try:
                box["value"] = ufm.read_timed("pw: ", timeout, echo=False, timeout_note="按回车处理",
                                              tty_path=os.ttyname(slave))
            except ufm.UfmError as exc:
                box["error"] = str(exc)
        shown = bytearray()

        def terminal():   # a terminal keeps reading what the prompt writes
            while thread.is_alive() or select.select([master], [], [], 0.2)[0]:
                if select.select([master], [], [], 0.1)[0]:
                    try:
                        shown.extend(os.read(master, 4096))
                    except OSError:
                        return
        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        reader = threading.Thread(target=terminal, daemon=True)
        reader.start()
        for delay, data in keys:
            time.sleep(delay)
            os.write(master, data)
        thread.join(10)
        reader.join(10)
        alive = thread.is_alive()
        os.close(master)
        os.close(slave)
        self.assertFalse(alive, "the prompt must return")
        return box, bytes(shown).decode("utf-8", "replace")

    def test_no_key_within_the_deadline_counts_as_enter(self):
        started = time.monotonic()
        box, shown = self.ask([])
        self.assertEqual(box, {"value": ""})
        self.assertLess(time.monotonic() - started, 5)
        self.assertIn("pw: ", shown)
        self.assertIn("按回车处理", shown)

    def test_typed_password_is_read_without_echo(self):
        box, shown = self.ask([(0.2, b"Leaf-Pw-9\r")])
        self.assertEqual(box, {"value": "Leaf-Pw-9"})
        self.assertNotIn("Leaf-Pw-9", shown)
        self.assertNotIn("按回车处理", shown)

    def test_the_first_key_cancels_the_deadline(self):
        box, _shown = self.ask([(0.2, b"Le"), (1.0, b"af\r")], timeout=0.5)
        self.assertEqual(box, {"value": "Leaf"})

    def test_backspace_and_line_kill_edit_the_input(self):
        box, _shown = self.ask([(0.2, b"xx\x15abx\x7fc\r")])
        self.assertEqual(box, {"value": "abc"})

    def test_ctrl_c_cancels(self):
        box, _shown = self.ask([(0.2, b"ab\x03")])
        self.assertEqual(box, {"error": "已取消输入"})

    def answer(self, keys, timeout=0.6):
        master, slave = pty.openpty()
        box, shown = {}, bytearray()

        def worker():
            box["value"] = ufm.ask_yes_no_timed("go? ", timeout, tty_path=os.ttyname(slave))

        def terminal():
            while thread.is_alive() or select.select([master], [], [], 0.2)[0]:
                if select.select([master], [], [], 0.1)[0]:
                    try:
                        shown.extend(os.read(master, 4096))
                    except OSError:
                        return
        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        reader = threading.Thread(target=terminal, daemon=True)
        reader.start()
        for delay, data in keys:
            time.sleep(delay)
            os.write(master, data)
        thread.join(10)
        reader.join(10)
        os.close(master)
        os.close(slave)
        return box.get("value"), bytes(shown).decode("utf-8", "replace")

    def test_yes_no_question_defaults_to_no_after_the_deadline(self):
        value, shown = self.answer([])
        self.assertIs(value, False)
        self.assertIn("按 N 处理", shown)

    def test_yes_no_question_echoes_and_accepts_y(self):
        value, shown = self.answer([(0.2, b"y\r")])
        self.assertIs(value, True)
        self.assertIn("go? y", shown)
        self.assertIs(self.answer([(0.2, b"n\r")])[0], False)
        self.assertIs(self.answer([(0.2, b"\r")])[0], False, "Enter keeps the default N")

    def test_yes_no_question_without_a_terminal_is_no(self):
        self.assertIs(ufm.ask_yes_no_timed("go? ", 15, tty_path="/nonexistent/tty"), False)

    def test_without_a_terminal_there_is_no_answer(self):
        self.assertIsNone(ufm.read_timed("pw: ", 10, echo=False, timeout_note="", tty_path="/nonexistent/tty"))


class ScriptLoaderTest(unittest.TestCase):
    """Owner 2026-10-20: only scripts that really ran stay on the UFM, under /root/.setup/<run>/, numbered by
    the UFM in execution order. The loader itself, run by a POSIX sh (Ubuntu's is dash)."""

    def loaders(self, run_name, steps):
        captured = []

        class Sent(Exception):
            pass

        def send(argv, *_args, **_kwargs):
            captured.append(argv[-1])
            raise Sent()

        session = ufm.Session.__new__(ufm.Session)
        session.access = {"h": {"path": "IPv4"}}
        session.run_dir = Path("/unused") / run_name
        session.creds = ufm.Credentials("root", "n", "f", "cumulus")
        session.timeout, session.sequence = 5, iter(range(1, 99))
        session.save, session.secrets = (lambda *_args: None), (lambda: [])
        session.ufm_destination = lambda *_args: "root@h"
        session.ufm_argv = lambda _node, _access, remote, _marker: remote
        node = mock.Mock(hostname="h", address="198.51.100.1")
        with mock.patch.object(ufm, "interactive_run", send):
            for step, body in steps:
                with self.assertRaises(Sent):
                    session.run_script(node, ufm.NodeResult("h", "primary"), step, body)
        return captured

    def test_a_script_that_bash_cannot_parse_is_never_sent(self):
        # Owner 2026-10-22 (10-12 merged requirement, item 3): `bash -n` locally before anything is sent.
        sent, saved = [], {}
        session = ufm.Session.__new__(ufm.Session)
        session.access = {"h": {"path": "IPv4"}}
        session.run_dir = Path("/unused/20261022-170000-check")
        session.creds = ufm.Credentials("root", "n", "f", "cumulus")
        session.timeout, session.sequence = 5, iter(range(1, 99))
        session.save, session.secrets = (lambda name, text: saved.__setitem__(name, text)), (lambda: [])
        session.ufm_destination = lambda *_args: "root@h"
        session.ufm_argv = lambda _node, _access, remote, _marker: remote
        node = mock.Mock(hostname="h", address="198.51.100.1")
        with mock.patch.object(ufm, "interactive_run", lambda *args, **_kwargs: sent.append(args)):
            with self.assertRaises(ufm.UfmError) as caught:
                session.run_script(node, ufm.NodeResult("h", "primary"), "broken", "if true; then\necho x\n")
        self.assertEqual(sent, [], "nothing reaches the UFM")
        self.assertIn("bash -n", str(caught.exception))
        [(name, text)] = [(name, text) for name, text in saved.items() if name.endswith(".out.txt")]
        self.assertRegex(name, r"^\d+-h-broken-not-run\.out\.txt$")
        self.assertIn("bash -n", text)

    def test_scripts_are_numbered_on_landing_and_a_failed_transfer_leaves_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            first, second, corrupt, again = self.loaders("20261020-170000-check", (
                ("first", "echo one"), ("second", "echo two"), ("bad", "echo three"), ("first", "echo one")))
            corrupt = re.sub(r"\b[0-9a-f]{64}\b", "0" * 64, corrupt, count=1)
            shim = Path(tmp) / "bin"
            shim.mkdir()
            gnu = shutil.which("sha256sum") and "GNU" in subprocess.run(
                ["sha256sum", "--version"], capture_output=True, text=True).stdout
            if not gnu:   # macOS ships a BSD sha256sum that cannot read the check list from stdin
                (shim / "sha256sum").write_text('#!/bin/sh\nexec shasum -a 256 "$@"\n')
                (shim / "sha256sum").chmod(0o755)
            env = dict(os.environ, PATH=f"{shim}{os.pathsep}{os.environ['PATH']}")
            folder = Path(tmp) / "root/.setup/20261020-170000-check"

            def run(loader):
                return subprocess.run(["sh", "-c", loader.replace("/root/.setup", f"{tmp}/root/.setup")],
                                      env=env, capture_output=True, text=True, timeout=30)
            outputs = [run(loader) for loader in (first, second)]
            self.assertEqual([item.stdout for item in outputs],
                             [f"{ufm.SCRIPT_TAG}001-first.sh\none\n", f"{ufm.SCRIPT_TAG}002-second.sh\ntwo\n"])
            failed = run(corrupt)
            self.assertEqual((failed.returncode, failed.stdout), (1, ""), "a script that fails sha256 never runs")
            self.assertEqual(sorted(os.listdir(folder)), ["001-first.sh", "002-second.sh"], "and leaves no file")
            (folder / "001-first.sh").unlink()   # someone tidied up by hand: numbers still only go up
            self.assertEqual(run(again).stdout, f"{ufm.SCRIPT_TAG}003-first.sh\none\n")
            self.assertEqual(oct(folder.stat().st_mode & 0o777), "0o700")


class UpgradeScriptTest(unittest.TestCase):
    def test_status_lines_before_this_run_are_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "status.log"
            log.write_text("20250101-00_00_00: APPLIANCE-UPGRADE   [FAILED    ]\n"
                           "20261019-13_06_46: UFM-OS-UPGRADE      [PASSED    ]\n"
                           "20261019-13_18_58: UFM-OS-FIRSTBOOT    [PASSED    ]\n")
            script = ufm.upgrade_status_script("20261019-12_55_39").replace(
                "/var/log/ufm_os_upgrade_*_status.log", str(log)).replace("/etc/ufm-release", str(log))
            out = subprocess.run(["bash", "-c", script], text=True, capture_output=True).stdout
        facts = dict(line.split("=", 1) for line in out.splitlines())
        self.assertEqual((facts["firstboot"], facts["failed"]), ("PASSED", ""))
        with self.assertRaises(ufm.UfmError):
            ufm.upgrade_status_script("2026-10-19; reboot")

    def test_start_script_matches_the_manual_and_refuses_bad_input(self):
        script = ufm.upgrade_start_script("2.6.1-5", "http://198.51.103.200:8088/image/"
                                          "ufm-appliance-2.6.1-5-omu.x86_64.tar")
        order = ["wget", "tar -C /root/ -xf", "systemctl stop ufm-enterprise", "systemctl is-active ufm-enterprise",
                 "systemd-run", "ufm-os-upgrade.sh --appliance-sw-upgrade -r -y"]
        positions = [script.index(item) for item in order]
        self.assertEqual(positions, sorted(positions))
        self.assertNotIn("sha256", script.lower(), "owner: no image checksum")
        self.assertEqual(subprocess.run(["bash", "-n"], input=script, text=True).returncode, 0)
        with self.assertRaises(ufm.UfmError):
            ufm.upgrade_start_script("2.6.1-5", "http://evil/$(reboot)")
        with self.assertRaises(ufm.UfmError):
            ufm.image_name("2.6.1-5; reboot")


if __name__ == "__main__":
    unittest.main()
