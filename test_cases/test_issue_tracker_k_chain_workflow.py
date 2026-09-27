"""Real worker cycle-source evidence plus separately validated C25 K snapshot."""

import tempfile
import unittest
from pathlib import Path

from monitor.issue_tracker_cycle_source import read_completed_cycle_evidence
from monitor.issue_tracker_k_chain import assess_k_window, validate_k_chain_snapshot
from test_cases.test_collection_cycle_persistence import WORKER, PROJECT_IDENTITY, TOKEN_1, TOKEN_2
from test_cases.test_issue_tracker_cycle_source import completed
from test_cases.test_issue_tracker_k_chain import fixtures


class IssueTrackerKChainWorkflowTests(unittest.TestCase):
    def test_k_greater_than_retained_real_cycles_is_pending_not_reduced(self):
        events, current, initialized = fixtures(new_k=5)
        settings = validate_k_chain_snapshot(events, current, initialized)
        with tempfile.TemporaryDirectory() as directory:
            with WORKER.CollectionGate(
                PROJECT_IDENTITY, "prod", status_dir=Path(directory),
                enforce_cooldown=False, lane="collection",
            ) as gate:
                self.assertTrue(gate.decision.allowed)
                store = WORKER.CollectionCycleStore(gate=gate)
                first = completed(store, TOKEN_1)
                second = completed(store, TOKEN_2)
                cycles = read_completed_cycle_evidence(store)
                self.assertEqual((first["cycle_id"], second["cycle_id"]),
                                 tuple(cycle.cycle_id for cycle in cycles))
                decision = assess_k_window(cycles, settings)
                self.assertEqual("pending", decision.status)
                self.assertEqual("cold_start", decision.reason)
                self.assertEqual(2, decision.observed)
                self.assertEqual(5, decision.required)
                self.assertFalse(hasattr(decision, "operations_json"))


if __name__ == "__main__":
    unittest.main()
