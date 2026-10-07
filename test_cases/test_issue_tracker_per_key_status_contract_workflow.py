"""Real worker-cycle -> cycle-source -> per-key projection workflow.

Active-key sets remain explicit fixtures: this proves cycle identity binding,
not production source provenance or publication authority.
"""

import tempfile
import unittest
from pathlib import Path

from monitor import issue_tracker_k_chain
from monitor.issue_tracker_cycle_source import read_completed_cycle_evidence
from monitor.issue_tracker_k_chain import validate_k_chain_snapshot
from test_cases.test_collection_cycle_persistence import (
    PROJECT_IDENTITY, TOKEN_1, TOKEN_2, WORKER,
)
from test_cases.test_issue_tracker_cycle_source import completed
from test_cases.test_issue_tracker_k_chain import fixtures
from test_cases.test_issue_tracker_per_key_status_contract import KEY_A, KEY_B


class PerKeyStatusContractWorkflowTests(unittest.TestCase):
    def test_real_worker_cycles_do_not_collapse_distinct_key_progress(self):
        assess = getattr(issue_tracker_k_chain, "assess_per_key_window", None)
        events, current, initialized = fixtures(new_k=3)
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
                observed = {first["cycle_id"]: frozenset((KEY_A,)),
                            second["cycle_id"]: frozenset((KEY_A, KEY_B))}
                self.assertIsNotNone(assess, "C-25 per-key projection is not implemented")
                a = assess(cycles, observed, settings, KEY_A)
                b = assess(cycles, observed, settings, KEY_B)
                self.assertEqual(("pending", 2, 3),
                                 (a.status, a.observed, a.required))
                self.assertEqual(("pending", 1, 3),
                                 (b.status, b.observed, b.required))


if __name__ == "__main__":
    unittest.main()
