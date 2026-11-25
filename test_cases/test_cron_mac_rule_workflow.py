"""Workflow: cron.sh's awk MAC rule agrees with tools/device_identity.py normalize_mac (I-018, v3.1.6 C1).

Every row of the shared fixture test_cases/fixtures/mac_spellings.tsv gets the same answer from both
(C1-O1 (a), C1-O9 (a)).

Two real scripts: load_inventory_macs is cut out of ethernet/monitor/cron.sh and run by bash; normalize_mac is
imported from tools/device_identity.py. Neither result is the expectation of the other: a valid spelling must
give the same lowercase colon MAC, an empty/NA cell must give no row on the cron side and "" on the Python side,
and a ValueError must be an "invalid" row (P3b §2.1, 设计/P3b设备身份规则.md :46-65)."""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CRON = ROOT / "ethernet/monitor/cron.sh"
MAC_SPELLINGS = ROOT / "test_cases/fixtures/mac_spellings.tsv"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.device_identity import normalize_mac  # noqa: E402


class CronMacRuleWorkflowTests(unittest.TestCase):
    def test_load_inventory_macs_agrees_with_device_identity(self):
        source = CRON.read_text(encoding="utf-8")
        match = re.search(r"^load_inventory_macs\(\) \{\n.*?^\}\n", source, re.S | re.M)
        self.assertIsNotNone(match)
        rows = MAC_SPELLINGS.read_text(encoding="utf-8").splitlines()
        self.assertEqual(rows[0], "input\texpected")
        inputs = [row.split("\t", 1)[0] for row in rows[1:]]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            csv = root / "inventory.csv"
            csv.write_text("hostname,type,eth0_ip,eth0_mac\n" + "".join(
                f"dev{index:02d},ib,192.0.2.{index},{text}\n" for index, text in enumerate(inputs, 1)),
                encoding="utf-8")
            output = root / "inventory-macs"
            harness = root / "harness.sh"
            harness.write_text("#!/bin/bash\n" + match.group(0) + 'load_inventory_macs "$1"\n', encoding="utf-8")
            result = subprocess.run(["bash", str(harness), str(csv)], env=dict(os.environ, INVENTORY_MACS=str(output)),
                                    stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60, check=False)
            self.assertEqual(result.returncode, 0, result)
            cron_side = dict(line.split("|", 1) for line in output.read_text(encoding="utf-8").splitlines())
        for index, text in enumerate(inputs, 1):
            name = f"dev{index:02d}"
            with self.subTest(spelling=text):
                try:
                    python_side = normalize_mac(text)
                except ValueError:
                    self.assertEqual(cron_side.get(name), "invalid")
                    continue
                if python_side:
                    self.assertEqual(cron_side.get(name), python_side)
                else:
                    self.assertNotIn(name, cron_side, "a missing MAC is no row on the cron side")
        self.assertLessEqual(set(cron_side), {f"dev{index:02d}" for index in range(1, len(inputs) + 1)})


if __name__ == "__main__":
    unittest.main()
