"""Direct contract of tools/inventory_subset.py: <network>.csv against 02-devices_config.csv (v3.1.1 M4).

Expectations are written from the owner's rule, not from the module (需求文档 R-016, owner 2026-11-05,
Codex RV31-16): the header is the same; every row of the network CSV has a row with the same host name
in the master CSV and every column is equal; the only allowed difference is type eth_jump in the subset
where the master has an Ethernet type (O1 point 10: eth, eth_spx, spx; not air); cells are compared after
trimming surrounding blanks; MACs are compared after M4's normalisation; extra master rows are fine; a
subset that is a link to the master passes.  Record fields and kinds follow the v3.1.1 guide 14.3
(columns by position, a repeated header name carries its occurrence such as netmask#2; utf-8-sig;
whole-blank rows skipped; host lookup strip + casefold, then the host-name column compared as written).
"""
from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import inventory_subset as INV  # noqa: E402

HEADER = "hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw,eth1_mac,lo_ip"
OOB = "oob-leaf01.site.example.test,eth,oob-leaf,192.0.2.11,24,192.0.2.1,02:00:00:00:01:01,NA,NA,NA,NA,NA"
IB1 = ("ib-leaf001.site.example.test,ib,NA,192.0.2.21,24,192.0.2.1,02:00:00:00:02:01,"
       "198.51.100.21,24,198.51.100.1,02:00:00:00:02:02,NA")
IB2 = ("ib-leaf002.site.example.test,ib,NA,192.0.2.22,24,192.0.2.1,02:00:00:00:02:03,"
       "198.51.100.22,24,198.51.100.1,02:00:00:00:02:04,NA")
UFM = "ufm01.site.example.test,server_ufm,NA,203.0.113.11,24,203.0.113.1,02:00:00:00:03:01,,,,,"
EW = "ew-leaf001.site.example.test,eth,leaf,192.0.2.31,24,192.0.2.1,02:00:00:00:04:01,NA,NA,NA,NA,NA"
MASTER = [HEADER, OOB, IB1, IB2, UFM, EW]

# The full header of DAY0-Prepare/template/02-devices_config.csv (63 columns, many repeated names).
TEMPLATE_HEADER = (
    "hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw,eth1_mac,lo_ip,"
    "vlan_id,svi_ip,netmask,vlan_ports,vlan_id,svi_ip,netmask,vlan_ports,bgp_asn,bgp_ports,bond_ports,"
    "bond_type,bond_mac,peerlink_ports,vrl,evpn_vrf,evpn_l3vni,evpn_l3vlan,dhcp_relay,evpn_l2vni,evpn_l2vlan,"
    "svi_ip,netmask,vlan_ports,evpn_vrf,evpn_l3vni,evpn_l3vlan,dhcp_relay,evpn_l2vni,evpn_l2vlan,svi_ip,"
    "netmask,vlan_ports,evpn_vrf,evpn_l3vni,evpn_l3vlan,dhcp_relay,evpn_l2vni,evpn_l2vlan,svi_ip,netmask,"
    "vlan_ports,evpn_vrf,evpn_l3vni,evpn_l3vlan,dhcp_relay,evpn_l2vni,evpn_l2vlan,svi_ip,netmask,vlan_ports"
)


def replace(line, index, value):
    cells = line.split(",")
    cells[index] = value
    return ",".join(cells)


class InventorySubsetTests(unittest.TestCase):
    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self.root = Path(self._directory.name)

    def compare(self, subset_lines, master_lines=MASTER, *, subset_text=None, encoding="utf-8"):
        master = self.root / "02-devices_config.csv"
        master.write_text("\n".join(master_lines) + "\n", encoding="utf-8")
        subset = self.root / "ib.csv"
        text = subset_text if subset_text is not None else "\n".join(subset_lines) + "\n"
        subset.write_text(text, encoding=encoding)
        return INV.compare(subset, master)

    def assertOne(self, records, **fields):
        self.assertEqual(1, len(records), records)
        for name, value in fields.items():
            self.assertEqual(value, getattr(records[0], name), (name, records[0]))

    # --- consistent: 0 records -------------------------------------------------------------------------

    def test_same_file_content(self):
        self.assertEqual([], self.compare(MASTER))

    def test_subset_of_the_rows(self):
        self.assertEqual([], self.compare([HEADER, IB2, UFM]))

    def test_ethernet_type_becomes_eth_jump(self):
        self.assertEqual([], self.compare([HEADER, replace(OOB, 1, "eth_jump"), IB1, UFM]))
        for master_type in ("eth", "eth_spx", "spx"):
            with self.subTest(master_type=master_type):
                master = [HEADER, replace(OOB, 1, master_type), IB1]
                self.assertEqual([], self.compare([HEADER, replace(OOB, 1, "eth_jump"), IB1], master))

    def test_mac_spellings_compare_after_normalisation(self):
        subset = [HEADER, replace(replace(IB1, 6, "02-00-00-00-02-01"), 10, "0200.0000.0202"),
                  replace(UFM, 6, "020000000301"), replace(IB2, 6, "02:00:00:00:02:03".upper())]
        self.assertEqual([], self.compare(subset))
        self.assertEqual([], self.compare([HEADER, replace(OOB, 10, "n/a")]))   # NA words are the same "missing"

    def test_surrounding_blanks_are_ignored(self):
        subset = [" hostname ,type,template,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw,eth1_mac,lo_ip",
                  ",".join(f" {cell} " for cell in IB1.split(","))]
        self.assertEqual([], self.compare(subset))

    def test_bom_and_blank_rows(self):
        text = "\n".join([HEADER, "", IB1, ",,,,,,,,,,,", "   ", UFM, ""]) + "\n"
        self.assertEqual([], self.compare([], subset_text=text, encoding="utf-8-sig"))

    def test_subset_linked_to_the_master_passes(self):
        # R-016 11-05: a project that does not split links the network CSV to the master itself.
        master = self.root / "02-devices_config.csv"
        master.write_text("\n".join(MASTER) + "\n", encoding="utf-8")
        link = self.root / "ib.csv"
        os.symlink(master.name, link)
        self.assertEqual([], INV.compare(link, master))

    # --- inconsistent: one record each ---------------------------------------------------------------

    def test_extra_row(self):
        extra = replace(IB2, 0, "ib-leaf003.site.example.test")
        records = self.compare([HEADER, IB1, extra])
        self.assertOne(records, line=3, hostname="ib-leaf003.site.example.test", kind=INV.NOT_IN_MASTER)

    def test_one_changed_column(self):
        records = self.compare([HEADER, IB2, replace(IB1, 3, "192.0.2.99")])
        self.assertOne(records, line=3, hostname="ib-leaf001.site.example.test", column="eth0_ip",
                       subset_value="192.0.2.99", master_value="192.0.2.21", kind=INV.VALUE)

    def test_repeated_header_name_carries_its_occurrence(self):
        records = self.compare([HEADER, replace(IB1, 8, "25")])
        self.assertOne(records, column="netmask#2", subset_value="25", master_value="24", kind=INV.VALUE)
        records = self.compare([HEADER, replace(IB1, 4, "25")])
        self.assertOne(records, column="netmask", kind=INV.VALUE)

    def test_full_template_header_positions(self):
        width = len(TEMPLATE_HEADER.split(","))
        self.assertEqual(63, width)
        row = ",".join(IB1.split(",") + [""] * (width - 12))
        master = [TEMPLATE_HEADER, row]
        self.assertEqual([], self.compare(master, master))
        records = self.compare([TEMPLATE_HEADER, replace(row, 16, "200")], master)   # the second vlan_id
        self.assertOne(records, column="vlan_id#2", subset_value="200", master_value="", kind=INV.VALUE)
        records = self.compare([TEMPLATE_HEADER, replace(row, 43, "24")], master)    # the sixth netmask
        self.assertOne(records, column="netmask#6", kind=INV.VALUE)

    def test_header_missing_a_column(self):
        header = HEADER.rsplit(",", 1)[0]
        records = self.compare([header, IB1.rsplit(",", 1)[0]])
        self.assertOne(records, kind=INV.HEADER)

    def test_header_with_two_columns_swapped(self):
        cells = HEADER.split(",")
        cells[3], cells[4] = cells[4], cells[3]
        records = self.compare([",".join(cells), IB1, IB2])
        self.assertOne(records, kind=INV.HEADER)

    def test_eth_jump_over_a_non_ethernet_type(self):
        for master_type in ("ib", "air"):
            with self.subTest(master_type=master_type):
                master = [HEADER, replace(OOB, 1, master_type), IB1]
                records = self.compare([HEADER, replace(OOB, 1, "eth_jump"), IB1], master)
                self.assertOne(records, hostname="oob-leaf01.site.example.test", column="type",
                               subset_value="eth_jump", master_value=master_type, kind=INV.TYPE_NOT_ALLOWED)

    def test_other_type_change_is_a_value_difference(self):
        records = self.compare([HEADER, replace(OOB, 1, "ib")])
        self.assertOne(records, column="type", subset_value="ib", master_value="eth", kind=INV.VALUE)

    def test_duplicate_subset_row(self):
        records = self.compare([HEADER, IB1, IB2, IB1])
        self.assertOne(records, line=4, hostname="ib-leaf001.site.example.test", kind=INV.DUPLICATE)

    def test_host_name_case_is_found_but_reported(self):
        records = self.compare([HEADER, replace(IB1, 0, "IB-Leaf001.site.example.test")])
        self.assertOne(records, hostname="IB-Leaf001.site.example.test", column="hostname",
                       subset_value="IB-Leaf001.site.example.test", master_value="ib-leaf001.site.example.test",
                       kind=INV.VALUE)

    def test_different_or_unrecognised_mac(self):
        records = self.compare([HEADER, replace(IB1, 6, "02:00:00:00:02:09")])
        self.assertOne(records, column="eth0_mac", subset_value="02:00:00:00:02:09", kind=INV.VALUE)
        records = self.compare([HEADER, replace(IB1, 10, "02 00 00 00 02 02")])
        self.assertOne(records, column="eth1_mac", subset_value="02 00 00 00 02 02", kind=INV.VALUE)

    def test_other_mac_columns_compare_as_text(self):
        header = HEADER + ",bond_mac"
        master = [header, IB1 + ",02:00:00:00:05:01"]
        self.assertEqual([], self.compare(master, master))
        records = self.compare([header, IB1 + ",02-00-00-00-05-01"], master)
        self.assertOne(records, column="bond_mac", kind=INV.VALUE)

    def test_every_difference_is_listed_in_subset_order(self):
        subset = [HEADER, replace(replace(IB1, 3, "192.0.2.98"), 5, "192.0.2.254"),
                  replace(IB2, 0, "ib-leaf009.site.example.test"), IB2, IB2]
        records = self.compare(subset)
        self.assertEqual(
            [(2, "eth0_ip", INV.VALUE), (2, "eth0_gw", INV.VALUE), (3, "hostname", INV.NOT_IN_MASTER),
             (5, "hostname", INV.DUPLICATE)],
            [(record.line, record.column, record.kind) for record in records],
        )


if __name__ == "__main__":
    unittest.main()
