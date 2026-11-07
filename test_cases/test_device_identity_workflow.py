"""Workflows across the M4 modules (v3.1.1): the real modules call each other, nothing is mocked.

device_selector_roundtrip (tools/hostname_ranges.py + tools/device_identity.py): the lines of `compress`
joined by commas and handed to `select` choose exactly the original devices (R-002 acceptance :98, the
round trip; R-003 Q6 A: the merged output is a valid --devices value).  The CSV is written with full
names, short names and a mix; items without "." are compared with device_identity's display short name
(O1 point 1), so its case matters for letter ranges.  Compressing a part of the inventory and selecting
from the whole inventory chooses exactly that part.

inventory_subset_mac_rule (tools/inventory_subset.py + tools/device_identity.py): a network CSV that
writes MACs with dashes, upper case, dots or no separator matches a master written with colons; a MAC
that cannot be recognised, or a different MAC, is a difference (R-016 11-05: "MAC 按 M4 规整后比"; I-018).
Every row of the shared fixture test_cases/fixtures/mac_spellings.tsv goes through the comparison too.
"""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import hostname_ranges as HR  # noqa: E402
from tools import inventory_subset as INV  # noqa: E402

SHORT = (
    [f"ew-leaf{n:03d}" for n in range(1, 113) if n != 34]
    + [f"ew-spine{n:03d}" for n in range(1, 73) if n not in (13, 32, 69)]
    + [f"ib-pod{pod}-leaf{n:02d}" for pod in "abcd" for n in range(1, 13)]
    + [f"IB-Pod{pod}-Spine{n}" for pod in "ABC" for n in range(1, 3)]
    + [f"ib-leaf{n}" for n in range(1, 13)]
    + ["ew-leaf9", "ew-leaf0010", "ufm01", "ufm02", "oob-leaf01"]
)


def full(name):
    return f"{name}.site.example.test"


INVENTORIES = {
    "full": [full(name) for name in SHORT],
    "short": list(SHORT),
    "mixed": [full(name) if index % 3 else name for index, name in enumerate(SHORT)],
}


class DeviceSelectorRoundtripWorkflowTests(unittest.TestCase):
    def roundtrip(self, part, inventory):
        lines = HR.compress(part)
        self.assertTrue(all(not line.startswith("- ") for line in lines))
        chosen = HR.select(HR.parse_selector(",".join(lines)), inventory)
        self.assertEqual(len(chosen), len(set(chosen)))
        return lines, set(chosen)

    def test_whole_inventory_round_trip(self):
        for label, inventory in INVENTORIES.items():
            with self.subTest(csv=label):
                lines, chosen = self.roundtrip(inventory, inventory)
                self.assertEqual(set(inventory), chosen)
                # The list really was merged (the round trip alone would pass with no merging at all).
                self.assertLess(len(lines), len(inventory) // (1 if label == "mixed" else 4))

    def test_part_of_the_inventory_selects_exactly_that_part(self):
        for label, inventory in INVENTORIES.items():
            part = [name for index, name in enumerate(inventory) if index % 7 not in (2, 5)]
            with self.subTest(csv=label):
                _, chosen = self.roundtrip(part, inventory)
                self.assertEqual(set(part), chosen)

    def test_upper_case_letter_ranges_keep_their_case_through_the_short_name(self):
        part = [full("IB-PodA-Spine1"), full("IB-PodB-Spine1")]
        lines, chosen = self.roundtrip(part, INVENTORIES["full"])
        self.assertEqual(["IB-Pod[A-B]-Spine1.site.example.test"], lines)
        self.assertEqual(set(part), chosen)
        short_part = ["IB-PodA-Spine1", "IB-PodB-Spine1"]
        lines, chosen = self.roundtrip(short_part, INVENTORIES["full"])
        self.assertEqual(["IB-Pod[A-B]-Spine1"], lines)
        self.assertEqual({full(name) for name in short_part}, chosen)


HEADER = "hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw,eth1_mac,lo_ip"
MASTER = [
    HEADER,
    "oob-leaf01.site.example.test,eth,oob-leaf,192.0.2.11,24,192.0.2.1,02:00:00:00:01:01,NA,NA,NA,NA,NA",
    "ib-leaf001.site.example.test,ib,NA,192.0.2.21,24,192.0.2.1,02:00:00:00:02:01,"
    "198.51.100.21,24,198.51.100.1,02:00:00:00:02:02,NA",
    "ib-leaf002.site.example.test,ib,NA,192.0.2.22,24,192.0.2.1,02:ab:cd:ef:02:03,"
    "198.51.100.22,24,198.51.100.1,02:ab:cd:ef:02:04,NA",
    "ufm01.site.example.test,server_ufm,NA,203.0.113.11,24,203.0.113.1,02:00:00:00:03:01,,,,,",
]


class InventorySubsetMacRuleWorkflowTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.master = self.root / "02-devices_config.csv"
        self.master.write_text("\n".join(MASTER) + "\n", encoding="utf-8")

    def compare(self, macs):
        """Subset = the four master rows with type eth_jump on the OOB leaf and the given MAC cells."""
        rows = [HEADER]
        for line, (eth0, eth1) in zip(MASTER[1:], macs):
            cells = line.split(",")
            cells[6], cells[10] = eth0, eth1
            if cells[1] == "eth":
                cells[1] = "eth_jump"
            rows.append(",".join(cells))
        subset = self.root / "ib.csv"
        subset.write_text("\n".join(rows) + "\n", encoding="utf-8")
        return INV.compare(subset, self.master)

    def test_other_spellings_are_the_same_mac(self):
        self.assertEqual([], self.compare([
            ("02-00-00-00-01-01", "na"),
            ("0200.0000.0201", "020000000202"),
            ("02-AB-CD-EF-02-03", "02ABCDEF0204"),
            ("02:00-00.0003:01", ""),
        ]))

    def test_unrecognised_or_different_mac_is_a_difference(self):
        records = self.compare([
            ("02-00-00-00-01-01", "NA"),
            ("02:00:00:00:02:1", "02:00:00:00:02:02"),        # 11 hex digits: not a MAC
            ("02:ab:cd:ef:02:03", "02-ab-cd-ef-02-05"),       # a different MAC in another spelling
            ("2:0:0:0:3:1", ""),                              # one digit per group (O1 point 7)
        ])
        self.assertEqual(
            [("ib-leaf001.site.example.test", "eth0_mac", INV.VALUE),
             ("ib-leaf002.site.example.test", "eth1_mac", INV.VALUE),
             ("ufm01.site.example.test", "eth0_mac", INV.VALUE)],
            [(record.hostname, record.column, record.kind) for record in records],
        )

    def test_every_spelling_of_the_shared_fixture(self):
        # P3b: one fixture for every reader of the MAC rule.  A subset cell written in any accepted
        # spelling matches the master's colon form, a missing one matches NA, an invalid one differs.
        lines = FIXTURE.read_text(encoding="utf-8").splitlines()
        self.assertEqual("input\texpected", lines[0])
        for value, expected in (line.split("\t") for line in lines[1:]):
            with self.subTest(value=value):
                master_mac = {"MISSING": "NA", "INVALID": "02:00:00:00:00:05"}.get(expected, expected)
                self.master.write_text("\n".join([HEADER, replace_mac(MASTER[3], master_mac)]) + "\n",
                                       encoding="utf-8")
                subset = self.root / "ib.csv"
                subset.write_text("\n".join([HEADER, replace_mac(MASTER[3], value)]) + "\n", encoding="utf-8")
                records = INV.compare(subset, self.master)
                if expected == "INVALID":
                    self.assertEqual([("eth0_mac", value.strip(), INV.VALUE)],
                                     [(record.column, record.subset_value, record.kind) for record in records])
                else:
                    self.assertEqual([], records)


FIXTURE = ROOT / "test_cases/fixtures/mac_spellings.tsv"


def replace_mac(line, value):
    cells = line.split(",")
    cells[6] = value
    return ",".join(cells)


if __name__ == "__main__":
    unittest.main()
