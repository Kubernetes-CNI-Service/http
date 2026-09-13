"""Scenario contract across all three published collector entrypoints."""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from test_cases.test_collector_inventory_pubkey import (
    INVENTORIES,
    ROOT,
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
            staged = stage_collector_tree(root)
            results = {}
            for area in INVENTORIES:
                foreign_area = "ethernet" if area != "ethernet" else "nvlink"
                foreign_project, _foreign_inventory = staged[foreign_area]
                results[area] = run_preflight(
                    root,
                    area,
                    environment={
                        "MGMT_PUBKEY_FILE": str(
                            foreign_project / "mgmt-server.pub"
                        )
                    },
                )

            self.assertEqual(
                {area: 0 for area in INVENTORIES},
                {area: result.returncode for area, result in results.items()},
                {area: result.stderr for area, result in results.items()},
            )
            expected_keys = {
                " ".join(
                    (project / "mgmt-server.pub").read_text(
                        encoding="utf-8"
                    ).split()[:2]
                )
                for project, _inventory in staged.values()
            }
            self.assertEqual(3, len(expected_keys), "fixture keys must be distinct")
            for area, csv_name in INVENTORIES.items():
                project, inventory = staged[area]
                self.assertNotIn(
                    "active project mgmt-server.pub is missing",
                    results[area].stderr,
                )
                self.assertIn(f"ACTIVE_INVENTORY={inventory}\n", results[area].stdout)
                self.assertIn(
                    f"MGMT_PUBKEY_FILE={project / 'mgmt-server.pub'}\n",
                    results[area].stdout,
                )
                expected_key = " ".join(
                    (project / "mgmt-server.pub").read_text(
                        encoding="utf-8"
                    ).split()[:2]
                )
                self.assertIn(f"SSH_KEY={expected_key}\n", results[area].stdout)
                self.assertTrue((root / area / "monitor" / csv_name).is_symlink())


if __name__ == "__main__":
    unittest.main()
