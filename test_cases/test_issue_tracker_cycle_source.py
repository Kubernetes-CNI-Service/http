"""REQ7 C23→C25 read-only handoff: real worker evidence, no operations."""

import copy
import os
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
    def test_scoped_cycle_verifier_checks_originals_without_replaying_semantics(self):
        from monitor import issue_tracker_cycle_source as source
        completed(self.store, TOKEN_1)
        path = self.store.completion_path(1)
        real = self.store._validate_completion_record
        rejected = []
        with mock.patch.object(self.store, '_validate_completion_record', wraps=real) as replay:
            with self.assertRaises(CycleSourceHoldError):
                with source._hold_completed_cycle_replay(self.store) as verify:
                    self.assertTrue(callable(verify), 'held boundary must expose its actual original verifier')
                    verify()
                    self.assertEqual(1, replay.call_count)
                    raw = path.read_bytes()
                    path.rename(Path(self.directory.name) / 'owned-verifier-original')
                    path.write_bytes(raw)
                    with self.assertRaises(CycleSourceHoldError):
                        verify()
                    self.assertEqual(1, replay.call_count)
                    rejected.append(True)
        self.assertEqual([True], rejected, 'the actual verifier must be reached before rejection')

    def test_scoped_cycle_replay_rejects_store_binding_changes(self):
        from monitor import issue_tracker_cycle_source as source
        completed(self.store, TOKEN_1)
        rejected = []
        with self.assertRaises(CycleSourceHoldError):
            with source._hold_completed_cycle_replay(self.store):
                self.store.project_key = 'foreign-project'
                with self.assertRaises(CycleSourceHoldError):
                    source.read_completed_cycle_evidence(self.store)
                rejected.append(True)
        self.assertEqual([True], rejected)

    def test_scoped_cycle_replay_missing_original_is_a_typed_hold_without_repair(self):
        from monitor import issue_tracker_cycle_source as source
        completed(self.store,TOKEN_1); path=self.store.completion_path(1); rejected=[]
        with self.assertRaises(CycleSourceHoldError):
            with source._hold_completed_cycle_replay(self.store):
                path.unlink()
                with self.assertRaises(CycleSourceHoldError): source.read_completed_cycle_evidence(self.store)
                rejected.append(True)
        self.assertEqual([True],rejected)
        self.assertFalse(path.exists(),'missing originals must never be reconstructed')

    def test_scoped_cycle_replay_reuses_only_the_validated_held_original_chain(self):
        from monitor import issue_tracker_cycle_source as source
        self.assertTrue(hasattr(source, '_hold_completed_cycle_replay'))
        start = completed(self.store, TOKEN_1)
        real = self.store._validate_completion_record
        with mock.patch.object(self.store, '_validate_completion_record', wraps=real) as replay:
            with source._hold_completed_cycle_replay(self.store):
                for _ in range(3):
                    evidence = source.read_completed_cycle_evidence(self.store)
                    self.assertEqual((start['cycle_id'], 1, 'prod'),
                                     (evidence[0].cycle_id,evidence[0].sequence,evidence[0].scope))
                self.assertEqual(1,replay.call_count,
                                 'unchanged held originals need one semantic replay, not recursive reparsing')
            self.assertEqual(start['cycle_id'],source.read_completed_cycle_evidence(self.store)[0].cycle_id)
            self.assertEqual(2,replay.call_count,'scope exit must revoke all reuse')

    def test_scoped_cycle_replay_refuses_same_byte_completion_rebinding(self):
        from monitor import issue_tracker_cycle_source as source
        self.assertTrue(hasattr(source, '_hold_completed_cycle_replay'))
        completed(self.store,TOKEN_1); path=self.store.completion_path(1)
        original=path.read_bytes(); inode=path.stat().st_ino; rejected=[]
        with self.assertRaises(CycleSourceHoldError):
            with source._hold_completed_cycle_replay(self.store):
                path.rename(Path(self.directory.name)/'owned-original-completion')
                path.write_bytes(original)
                self.assertNotEqual(inode,path.stat().st_ino)
                with self.assertRaises(CycleSourceHoldError): source.read_completed_cycle_evidence(self.store)
                rejected.append(True)
        self.assertEqual([True],rejected); self.assertEqual(original,path.read_bytes())

    def test_scoped_cycle_replay_refuses_record_namespace_aba(self):
        from monitor import issue_tracker_cycle_source as source
        self.assertTrue(hasattr(source, '_hold_completed_cycle_replay'))
        completed(self.store,TOKEN_1); path=self.store.completion_path(1)
        original=path.read_bytes(); inode=path.stat().st_ino; rejected=[]
        with self.assertRaises(CycleSourceHoldError):
            with source._hold_completed_cycle_replay(self.store):
                away=Path(self.directory.name)/'owned-record-aba'
                path.rename(away); away.rename(path)
                self.assertEqual(inode,path.stat().st_ino)
                with self.assertRaises(CycleSourceHoldError): source.read_completed_cycle_evidence(self.store)
                rejected.append(True)
        self.assertEqual([True],rejected); self.assertEqual(original,path.read_bytes())

    def test_scoped_cycle_replay_refuses_same_inode_witness_rewrite_with_restored_mtime(self):
        from monitor import issue_tracker_cycle_source as source
        self.assertTrue(hasattr(source, '_hold_completed_cycle_replay'))
        completed(self.store,TOKEN_1); path=self.store.witness_path
        original=path.read_bytes(); info=path.stat(); rejected=[]
        with self.assertRaises(CycleSourceHoldError):
            with source._hold_completed_cycle_replay(self.store):
                path.write_bytes(b'x'*len(original)); path.write_bytes(original)
                os.utime(path,ns=(info.st_atime_ns,info.st_mtime_ns))
                self.assertEqual(info.st_ino,path.stat().st_ino)
                self.assertEqual(info.st_mtime_ns,path.stat().st_mtime_ns)
                with self.assertRaises(CycleSourceHoldError): source.read_completed_cycle_evidence(self.store)
                rejected.append(True)
        self.assertEqual([True],rejected); self.assertEqual(original,path.read_bytes())

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        gate = WORKER.CollectionGate(
            PROJECT_IDENTITY, "prod", status_dir=Path(self.directory.name).resolve(),
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
