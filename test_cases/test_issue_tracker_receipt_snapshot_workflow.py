"""Real worker/emitter -> protected Stage L -> C6 local receipt snapshot."""

import unittest
import importlib.util
import hashlib
import os
import shutil
from unittest import mock

from monitor.issue_tracker_state_owner import current_k, tracker_writer
from monitor.issue_tracker_whitelist_workbook import read_whitelist_workbook
from test_cases.test_collection_cycle_persistence import WORKER
from test_cases.test_issue_tracker_stage_l_consumer import ProdStageLFixture
import test_cases.test_issue_tracker_stage_l_consumer_workflow as source_workflow


class CurrentCycleReceiptSnapshotWorkflowTests(ProdStageLFixture):
    def setUp(self):
        self.assertIsNotNone(
            importlib.util.find_spec("monitor.issue_tracker_receipt_snapshot"),
            "cycle-bound local receipt snapshot is not implemented")
        super().setUp()

    _exercise_real_protected_three_panel_fixture = (
        source_workflow.ProdStageLConsumerWorkflowTests
        ._exercise_real_protected_three_panel_fixture
    )

    def test_real_worker_emitter_c6_receipt_is_current_cycle_only(self):
        from monitor.issue_tracker_local_workbook_commit import CommittedProdWorkbook
        from monitor.issue_tracker_receipt_snapshot import read_current_cycle_local_receipts
        from monitor.issue_tracker_stage_l_consumer import qualify_prod_stage_l

        real_publish = WORKER._publish_stage_l_local_after_completion
        observed = []

        def after_publish(store):
            result = real_publish(store)
            if isinstance(result, CommittedProdWorkbook):
                template = self.root / "monitor/Issue_Tracker_Template_v1.xlsx"
                whitelist = read_whitelist_workbook(template)
                with tracker_writer(self.project, self.publication) as token:
                    settings = current_k(token)
                    qualified = qualify_prod_stage_l(
                        store, http_root=self.root, settings=settings,
                        whitelist_snapshot=whitelist, whitelist_path=template,
                        writer_token=token,
                    )
                    snap = read_current_cycle_local_receipts(
                        token, store,
                        expected_template_sha256=whitelist.workbook_sha256,
                        settings=settings,
                        whitelist_sha256=whitelist.whitelist.sha256,
                        qualified_source=qualified,
                    )
                    from monitor.issue_tracker_receipt_snapshot import (
                        LocalReceiptSnapshotHold, read_local_receipt_history,
                    )
                    history = read_local_receipt_history(
                        token, store, expected_template_sha256=whitelist.workbook_sha256,
                        settings=settings, whitelist_sha256=whitelist.whitelist.sha256,
                        qualified_source=qualified)
                    self.assertEqual(1, len(history.receipts))
                    self.assertEqual(result.receipt.generation_id, history.receipts[0].generation_id)
                    self.assertEqual(snap.cycle_id, history.receipts[0].cycle_id)
                    with self.assertRaises(LocalReceiptSnapshotHold):
                        read_local_receipt_history(
                            token, store, expected_template_sha256=whitelist.workbook_sha256,
                            settings=settings, whitelist_sha256=whitelist.whitelist.sha256)
                observed.append((snap.published, snap.generation_ids))
            return result

        with mock.patch.object(WORKER, "_publish_stage_l_local_after_completion",
                               side_effect=after_publish):
            self._exercise_real_protected_three_panel_fixture(
                skip_history=False, automatic_first=True,
            )
        self.assertEqual(1, len(observed))
        self.assertEqual(1, observed[0][0])
        self.assertEqual(1, len(observed[0][1]))

    def test_prior_cycle_receipt_is_not_current_cycle_publication(self):
        from monitor.issue_tracker_receipt_snapshot import read_current_cycle_local_receipts

        real_cycle = self._cycle
        after_second_cycle = []

        def observed_cycle(*args, **kwargs):
            result = real_cycle(*args, **kwargs)
            if (self.project / ".tracker/admissions").exists():
                with tracker_writer(self.project, self.publication) as token:
                    snap = read_current_cycle_local_receipts(
                        token, self.store,
                        expected_template_sha256=self.snapshot.workbook_sha256,
                        settings=current_k(token),
                        whitelist_sha256=self.snapshot.whitelist.sha256,
                    )
                after_second_cycle.append((result[0]["cycle_id"], snap))
            return result

        self._cycle = observed_cycle
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, automatic_first=True,
            manual_second_probe=True,
        )
        self.assertEqual(1, len(after_second_cycle))
        cycle_id, snapshot = after_second_cycle[0]
        self.assertEqual(cycle_id, snapshot.cycle_id)
        self.assertEqual(0, snapshot.published)
        self.assertEqual((), snapshot.generation_ids)

    def _old_receipt_fixture(self, probe):
        """Actual first C6, then actual second protected completion without C6."""
        from monitor.issue_tracker_local_workbook_commit import CommittedProdWorkbook
        real_publish = WORKER._publish_stage_l_local_after_completion
        real_cycle = self._cycle
        first = []

        def capture_publish(store):
            result = real_publish(store)
            if isinstance(result, CommittedProdWorkbook):
                first.append(result)
            return result

        def after_cycle(*args, **kwargs):
            result = real_cycle(*args, **kwargs)
            if first:
                probe(first[0])
            return result

        self._cycle = after_cycle
        with mock.patch.object(WORKER, "_publish_stage_l_local_after_completion",
                               side_effect=capture_publish):
            self._exercise_real_protected_three_panel_fixture(
                skip_history=False, automatic_first=True, manual_second_probe=True)
        self.assertEqual(1, len(first))

    def _history(self, token):
        from monitor import issue_tracker_receipt_snapshot as receipts
        return receipts.read_local_receipt_history(
            token, self.store, expected_template_sha256=self.snapshot.workbook_sha256,
            settings=current_k(token), whitelist_sha256=self.snapshot.whitelist.sha256)

    def test_old_original_receipt_remains_observable_but_not_current_publication(self):
        from monitor import issue_tracker_receipt_snapshot as receipts
        self.assertTrue(callable(getattr(receipts, "read_local_receipt_history", None)),
                        "historical original receipt reader is absent")

        def probe(original):
            before = {path.relative_to(self.project).as_posix():
                      (path.stat().st_ino, hashlib.sha256(path.read_bytes()).hexdigest())
                      for path in (self.project / ".tracker").rglob("*") if path.is_file()}
            with tracker_writer(self.project, self.publication) as token:
                result = self._history(token)
                latest = receipts.read_current_cycle_local_receipts(
                    token, self.store, expected_template_sha256=self.snapshot.workbook_sha256,
                    settings=current_k(token), whitelist_sha256=self.snapshot.whitelist.sha256)
            self.assertEqual("RECEIPT-HISTORY-PRESENT-NOT-ELIGIBILITY", result.state)
            self.assertEqual(1, len(result.receipts))
            old = result.receipts[0]
            self.assertEqual(original.receipt.generation_id, old.generation_id)
            self.assertEqual(original.receipt.published_sha256, old.published_sha256)
            self.assertNotEqual(latest.cycle_id, old.cycle_id)
            self.assertEqual((0, ()), (latest.published, latest.generation_ids))
            self.assertFalse(hasattr(old, "permit"))
            after = {path.relative_to(self.project).as_posix():
                     (path.stat().st_ino, hashlib.sha256(path.read_bytes()).hexdigest())
                     for path in (self.project / ".tracker").rglob("*") if path.is_file()}
            self.assertEqual(before, after, "history observation must not mutate original state")
        self._old_receipt_fixture(probe)

    def test_history_rejects_same_byte_original_replacement_during_actual_read(self):
        from monitor import issue_tracker_receipt_snapshot as receipts
        self.assertTrue(callable(getattr(receipts, "read_local_receipt_history", None)),
                        "historical original receipt reader is absent")

        def probe(original):
            target = self.project / ".tracker/generations" / original.receipt.generation_id / "RECEIPT"
            saved = target.read_bytes()
            real_read = receipts.read_current_cycle_local_receipts

            def substituted(*args, **kwargs):
                result = real_read(*args, **kwargs)
                replacement = target.with_name("test-owned-replacement")
                replacement.write_bytes(saved)
                replacement.chmod(0o600)
                os.replace(replacement, target)
                return result

            with tracker_writer(self.project, self.publication) as token:
                with mock.patch.object(receipts, "read_current_cycle_local_receipts",
                                       side_effect=substituted):
                    with self.assertRaises(receipts.LocalReceiptSnapshotHold):
                        self._history(token)
            self.assertEqual(saved, target.read_bytes())
        self._old_receipt_fixture(probe)

    def test_history_pins_every_original_namespace_through_native_recovery(self):
        from monitor import issue_tracker_receipt_snapshot as receipts
        from monitor.issue_tracker_local_commit import _published_name

        def probe(original):
            tracker = self.project / ".tracker"
            generation = tracker / "generations" / original.receipt.generation_id
            targets = [generation / name for name in ("STATE", "MANIFEST", "INTENT", "RECEIPT")]
            targets += [tracker / "admissions/admission-00000000000000000001.json",
                        tracker / "settings/current", tracker / "settings/events/1.json",
                        tracker / "settings/outbox/1.json",
                        self.publication / _published_name(original.receipt.generation_id, "xlsx"),
                        tracker / "admissions", tracker / "generations", tracker / "settings"]
            temporary = self.root / "test-owned-history-substitution"
            temporary.mkdir(mode=0o700)
            real_read = receipts.read_current_cycle_local_receipts
            for number, target in enumerate(targets):
                with self.subTest(target=target.relative_to(self.project).as_posix()):
                    backup = temporary / f"original-{number}"
                    replacement = temporary / f"replacement-{number}"
                    abandoned = temporary / f"abandoned-{number}"
                    before = target.stat().st_ino
                    changed = []

                    def substitute(*args, **kwargs):
                        result = real_read(*args, **kwargs)
                        if not changed:
                            if target.is_dir():
                                shutil.copytree(target, replacement)
                            else:
                                shutil.copy2(target, replacement)
                            os.rename(target, backup)
                            os.rename(replacement, target)
                            changed.append(True)
                        return result

                    try:
                        with tracker_writer(self.project, self.publication) as token:
                            with mock.patch.object(receipts, "read_current_cycle_local_receipts",
                                                   side_effect=substitute):
                                with self.assertRaises(receipts.LocalReceiptSnapshotHold):
                                    self._history(token)
                        self.assertEqual([True], changed, "fault must follow the real chain read")
                    finally:
                        if changed:
                            os.rename(target, abandoned)
                            os.rename(backup, target)
                    self.assertEqual(before, target.stat().st_ino)
        self._old_receipt_fixture(probe)


if __name__ == "__main__":
    unittest.main()
