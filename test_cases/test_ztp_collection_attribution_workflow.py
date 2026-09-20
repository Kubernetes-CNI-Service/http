#!/usr/bin/env python3
"""Workflow contracts joining attribution cache, admission and report selection."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from test_cases.test_ztp_collection_attribution import device, load_monitor, record


class CollectionAttributionWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.monitor = load_monitor()

    def test_verified_cache_admits_only_bound_row_after_unrelated_input_edit(self):
        address = "192.0.2.60"
        prod = device("prod-leaf-06", "020000000051", address)
        air = device("air-leaf-06", "020000000052", address)
        stale_other = device("removed-leaf", "020000000053", "192.0.2.61")
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "collection-attribution.json"
            self.monitor.persist_collection_attribution(
                state, {"inventory.csv": "a" * 64},
                [record(self.monitor, air), record(self.monitor, stale_other)],
            )
            reconciled = self.monitor.load_collection_attribution(
                state, [prod, air], {"inventory.csv": "b" * 64},
            )
            selected = self.monitor.devices_for_switch_collection(
                [prod, air], {}, attribution_records=reconciled,
            )
        self.assertEqual([air], selected)
        self.assertFalse(prod["collection_admission"]["eligible"])
        self.assertTrue(air["collection_admission"]["eligible"])
        path = air["collection_admission"]["addresses"][0]["paths"]["posthoc_identity"]
        self.assertEqual("matched", path["status"])
        self.assertEqual("device_reported", path["source_kind"])
        self.assertEqual("ssh-posthoc", path["source"])

    def test_failed_probe_is_visible_but_cannot_cross_write_another_row(self):
        address = "192.0.2.70"
        rows = [
            device("prod-leaf-07", "020000000061", address),
            device("air-leaf-07", "020000000062", address),
        ]
        selected = self.monitor.devices_for_switch_collection(rows, {})
        calls = 0

        def failed_probe(candidate_address, candidates):
            nonlocal calls
            calls += 1
            return {
                "status": "probe_failed",
                "source": "ssh-posthoc",
                "source_kind": "device_reported",
                "address": candidate_address,
                "observation_time": "2026-09-20T08:02:00+00:00",
                "observed_identity": None,
            }

        selected, records, attempts = self.monitor.resolve_shared_address_attributions(
            rows, selected, failed_probe,
        )
        self.assertEqual(1, calls)
        self.assertEqual([], selected)
        self.assertEqual([], records)
        self.assertEqual("probe_failed", attempts[address]["status"])
        for row in rows:
            verdict = row["collection_admission"]["addresses"][0]
            self.assertFalse(verdict["eligible"])
            self.assertEqual("probe_failed", verdict["paths"]["posthoc_identity"]["status"])


if __name__ == "__main__":
    unittest.main()
