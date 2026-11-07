"""Scenario contract across all three published collector entrypoints.

Owner 2026-11-04 (R-016 详细设计 v1.1 §5.2): every entrypoint reads its own <type>/publickey/mgmt-server.pub
through DAY0-Prepare/activate-project; switching the pointer (R-016 §1: the one link that changes with the
project) switches the key all three entrypoints read, and no environment value overrides it.
"""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from test_cases.test_collector_inventory_pubkey import (
    INVENTORIES,
    OTHER_PROJECT,
    PROJECT,
    ROOT,
    key_fields,
    preflight_values,
    run_preflight,
    stage_collector_tree,
)


class CollectorInventoryPubkeyWorkflowTests(unittest.TestCase):
    def test_real_shared_entrypoints_resolve_the_published_project_key(self):
        self.assertEqual(
            "../../ethernet/monitor/cron.sh",
            os.readlink(ROOT / "infiniband/monitor/cron.sh"),
        )
        self.assertEqual(
            "../../ethernet/monitor/cron.sh",
            os.readlink(ROOT / "nvlink/monitor/cron.sh"),
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            projects = stage_collector_tree(root)
            self.assertNotEqual(key_fields(projects[PROJECT]), key_fields(projects[OTHER_PROJECT]),
                                "fixture keys must be distinct")
            for active, foreign in ((PROJECT, OTHER_PROJECT), (OTHER_PROJECT, PROJECT)):
                pointer = root / "DAY0-Prepare/activate-project"
                pointer.unlink()
                pointer.symlink_to(active)
                results = {
                    area: run_preflight(
                        root, area,
                        environment={"MGMT_PUBKEY_FILE": str(projects[foreign] / "mgmt-server.pub")},
                    )
                    for area in INVENTORIES
                }
                self.assertEqual(
                    {area: 0 for area in INVENTORIES},
                    {area: result.returncode for area, result in results.items()},
                    {area: result.stderr for area, result in results.items()},
                )
                for area, csv_name in INVENTORIES.items():
                    with self.subTest(active=active, area=area):
                        values = preflight_values(results[area])
                        self.assertEqual(str(root / area / "publickey/mgmt-server.pub"),
                                         values["MGMT_PUBKEY_FILE"])
                        self.assertEqual(key_fields(projects[active]), values["SSH_KEY"])
                        self.assertTrue((root / area / "monitor" / csv_name).is_symlink())


if __name__ == "__main__":
    unittest.main()
