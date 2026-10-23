"""Direct test: ufm-setup-upgrade (ha-setup/check) and the monitor page read `ufm_ha_cluster status` the same way.

Owner 2026-10-22: the status is the only basis for judging HA, in the tool and on the page alike. Each script
keeps its own parser (both run on their own, the monitor without the tool's shared module), so this test
holds the two readings equal on every recorded layout.
"""

import unittest

from test_cases.module_loader import load_script
from test_cases.test_ufm_setup_upgrade import (HA_STATUS_AFTER_FAILOVER, HA_STATUS_NONE, HA_STATUS_NOT_STARTED,
                                               HA_STATUS_PACEMAKER_1, HA_STATUS_STARTED, ROOT, ufm)

FIELDS = ("online", "offline", "masters", "slaves", "nodes", "dc", "quorum", "resources", "daemons", "drbd")


def monitor_snapshot(status_text):
    """The `<host>.ha` file ufm-info.sh --ha writes, as the monitor reads it."""
    line, sep = "=" * 52, "#" * 52
    return (f"{line}\nDevice:       ufm01.example.test\nServer Type:  UFM-HA\nCollect Time: 2026-10-22 05:34:00\n"
            f"{line}\n{sep}\n# Execute Command: ufm_ha_cluster status\n{sep}\n{status_text}\n"
            f"\n{line}\n# Collect complete\n{line}\n")


class UfmHaStatusParityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.monitor = load_script("monitor_ha_status_parity", ROOT / "monitor/generate-monitor-html.py")

    def test_both_scripts_read_every_recorded_layout_alike(self):
        for label, text in (("started", HA_STATUS_STARTED), ("failover", HA_STATUS_AFTER_FAILOVER),
                            ("not-started", HA_STATUS_NOT_STARTED), ("none", HA_STATUS_NONE),
                            ("pacemaker-1", HA_STATUS_PACEMAKER_1)):
            with self.subTest(label):
                tool = ufm.parse_ha_status(text)
                page = self.monitor.parse_ufm_ha_status(monitor_snapshot(text))
                self.assertEqual({key: tool[key] for key in FIELDS}, {key: page[key] for key in FIELDS})

    def test_the_comparison_is_not_vacuous(self):
        tool = ufm.parse_ha_status(HA_STATUS_STARTED)
        self.assertEqual((tool["masters"], len(tool["resources"]), tool["drbd"]["DRBD_CONNECTIVITY"]),
                         (["ufm01"], 5, "Connected"))
        page = self.monitor.parse_ufm_ha_status(monitor_snapshot(HA_STATUS_STARTED))
        self.assertEqual(page["drbd"]["VIRTUAL_IP"], "198.51.101.133")


if __name__ == "__main__":
    unittest.main()
