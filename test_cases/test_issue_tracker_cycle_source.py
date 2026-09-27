"""REQ7 C23→C25 read-only handoff: real worker evidence, no operations."""

import copy
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from monitor.issue_tracker_cycle_source import CycleSourceHoldError, read_completed_cycle_evidence
from test_cases.test_collection_cycle_persistence import (
    WORKER, PROJECT_IDENTITY, TOKEN_1, TOKEN_2, successful_cycle_result,
)


def completed(store, token):
    with mock.patch.object(WORKER, "_mint_cycle_run_token", return_value=token):
        start = store.allocate_start(process_inspector=lambda _binding: "dead")
    store.publish_launch(
        start, pid=4321, boot_id="fixture-boot", process_start_time="9000",
        argv=["collector"], context={"scope": "prod"},
        credential_argv_positions=(), credential_context_names=(),
    )
    store.publish_completion(start, successful_cycle_result(start))
    return start


class IssueTrackerCycleSourceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        gate = WORKER.CollectionGate(
            PROJECT_IDENTITY, "prod", status_dir=Path(self.directory.name),
            enforce_cooldown=False, lane="collection",
        )
        self.gate = gate.__enter__()
        self.addCleanup(lambda: gate.__exit__(None, None, None))
        self.assertTrue(self.gate.decision.allowed)
        self.store = WORKER.CollectionCycleStore(gate=self.gate)

    def test_completed_worker_chain_yields_identity_and_digest_without_operations(self):
        start = completed(self.store, TOKEN_1)
        evidence = read_completed_cycle_evidence(self.store)
        self.assertEqual(1, len(evidence))
        self.assertEqual(start["cycle_id"], evidence[0].cycle_id)
        self.assertEqual(1, evidence[0].sequence)
        self.assertEqual("prod", evidence[0].scope)
        self.assertTrue(evidence[0].qualifying)
        self.assertRegex(evidence[0].summary_sha256, r"^[0-9a-f]{64}$")
        self.assertFalse(hasattr(evidence[0], "operations_json"))

    def test_partial_chain_and_witness_gap_fail_closed_without_repair_write(self):
        with mock.patch.object(WORKER, "_mint_cycle_run_token", return_value=TOKEN_1):
            start = self.store.allocate_start(process_inspector=lambda _binding: "dead")
        self.store.publish_launch(
            start, pid=4321, boot_id="fixture-boot", process_start_time="9000",
            argv=["collector"], context={"scope": "prod"},
            credential_argv_positions=(), credential_context_names=(),
        )
        before = tuple(sorted((path.name, path.read_bytes()) for path in self.store.records_dir.iterdir()))
        with self.assertRaises(CycleSourceHoldError):
            read_completed_cycle_evidence(self.store)
        self.assertEqual(before, tuple(sorted((path.name, path.read_bytes()) for path in self.store.records_dir.iterdir())))
        self.store.publish_completion(start, successful_cycle_result(start))
        self.store._write_witness(2)
        with self.assertRaises(CycleSourceHoldError):
            read_completed_cycle_evidence(self.store)

    def test_duplicate_run_token_rejected_even_with_different_cycle_id(self):
        completed(self.store, TOKEN_1)
        # A forged second start with an otherwise valid identity must not count.
        self.store._write_witness(2)
        second = WORKER.build_collection_cycle_identity(PROJECT_IDENTITY, "prod", 2, TOKEN_1)
        self.store._publish_start(second)
        self.store.publish_launch(
            second, pid=4322, boot_id="fixture-boot", process_start_time="9001",
            argv=["collector"], context={"scope": "prod"},
            credential_argv_positions=(), credential_context_names=(),
        )
        self.store.publish_completion(second, successful_cycle_result(second))
        with self.assertRaises(CycleSourceHoldError):
            read_completed_cycle_evidence(self.store)

    def test_changed_completion_bytes_refuse_evidence(self):
        completed(self.store, TOKEN_2)
        path = self.store.completion_path(1)
        altered = path.read_bytes().replace(b'"cycle_completed"', b'"cycle_crashed"')
        self.assertNotEqual(path.read_bytes(), altered)
        path.write_bytes(altered)
        with self.assertRaises(CycleSourceHoldError):
            read_completed_cycle_evidence(self.store)

    def test_nonqualifying_completed_cycle_remains_visible_as_k_gap(self):
        with mock.patch.object(WORKER, "_mint_cycle_run_token", return_value=TOKEN_1):
            start = self.store.allocate_start(process_inspector=lambda _binding: "dead")
        self.store.publish_launch(
            start, pid=4321, boot_id="fixture-boot", process_start_time="9000",
            argv=["collector"], context={"scope": "prod"},
            credential_argv_positions=(), credential_context_names=(),
        )
        result = copy.deepcopy(successful_cycle_result(start))
        legacy = {
            "schema_version": 1, "task": "switch_collection", "state": "success",
            "planned": 0, "succeeded": 0, "failed_count": 0, "failed_devices": [],
        }
        for outcome in result["outcomes"]:
            outcome["child_result"] = dict(legacy)
        result["summary"] = None
        self.store.publish_completion(start, result)
        self.assertEqual([], self.store.qualifying_completions())
        evidence = read_completed_cycle_evidence(self.store)
        self.assertEqual(1, len(evidence))
        self.assertFalse(evidence[0].qualifying)
        self.assertIsNone(evidence[0].summary_sha256)


if __name__ == "__main__":
    unittest.main()
