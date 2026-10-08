"""Real worker/emitter -> protected Stage L -> C6 local receipt snapshot."""

import unittest
import importlib.util
import hashlib
import json
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


    def _original_replay_args(self, token, original):
        return dict(http_root=self.root, settings=current_k(token),
                    whitelist_snapshot=self.snapshot, whitelist_path=self.template,
                    expected_template_sha256=self.snapshot.workbook_sha256,
                    local_generation_id=original.receipt.generation_id,
                    writer_token=token)

    def _old_two_cycle_receipt_fixture(self, probe):
        """Native K=2 C5/C6 over cycles 1+2, then protected cycle 3 without C6.

        Keep the existing K=1 fixture and all its assertions untouched. The
        independent replay contract requires an actual two-cycle original,
        not changing its expected K to match the one-cycle fixture.
        """
        import datetime as dt
        from monitor import issue_tracker_local_workbook_commit as workbooks
        from monitor.collection_ib_producer import produce_worker_ib_analysis
        from test_cases import test_issue_tracker_switch_runtime_workflow as switch_fixture
        from tools.project_contract import build_collection_cycle_identity
        verifier = source_workflow.ProdStageLConsumerWorkflowTests._verify_two_cycle_latest_local_commit
        commit = workbooks.commit_prod_stage_l_workbook
        originals = []

        def capture_commit(*args, **kwargs):
            result = commit(*args, **kwargs)
            originals.append(result)
            return result

        def finish_original_and_advance(project, arguments, cycle_ids):
            with mock.patch.object(workbooks, 'commit_prod_stage_l_workbook', side_effect=capture_commit):
                verifier(self, project, arguments, cycle_ids)
            self.assertEqual(1, len(originals))
            identity = build_collection_cycle_identity(
                str(project), 'prod', 3, '33333333333343338333333333333333')
            binding = produce_worker_ib_analysis(
                identity, project_root=project, http_root=self.root,
                clock=lambda: dt.datetime(2026, 9, 26, 4, 42, tzinfo=dt.timezone.utc),
                runner=lambda _argv: self.fail('transport is supplied by owned fixture'))
            # Existing two-cycle source fixture deliberately has only TOKEN_1
            # and TOKEN_2. Supply a distinct, literal third worker-mint input;
            # do not weaken the native duplicate-token rejection.
            with mock.patch.object(switch_fixture, 'TOKEN_2', identity['run_token']):
                cycle, _ = self._cycle(
                    activity=True, derivation=True, observed_peer='later-peer', ib_analysis=binding,
                    fabric_templates={'ethernet/prod': 'tan-leaf', 'nvlink/prod': 'border-leaf'})
            self.assertEqual(identity['cycle_id'], cycle['cycle_id'])
            probe(originals[0])

        with mock.patch.object(self, '_verify_two_cycle_latest_local_commit',
                               side_effect=finish_original_and_advance, create=True):
            self._exercise_real_protected_three_panel_fixture(
                skip_history=False, two_cycle_changed_latest=True)

    def _tracker_images(self):
        return {p.relative_to(self.project).as_posix():
                (p.stat().st_ino, hashlib.sha256(p.read_bytes()).hexdigest())
                for p in (self.project / '.tracker').rglob('*') if p.is_file()}

    def test_actual_old_c6_replays_its_original_protected_window_without_new_receipt_or_send(self):
        from monitor import issue_tracker_stage_l_consumer as consumer
        from monitor.issue_tracker_cycle_source import read_completed_cycle_evidence
        from monitor.issue_tracker_receipt_snapshot import read_current_cycle_local_receipts

        def probe(original):
            generation = self.project / '.tracker/generations' / original.receipt.generation_id
            raw = (generation / 'MANIFEST').read_bytes()
            source = json.loads(raw)['qualified_source']
            with tracker_writer(self.project, self.publication) as token:
                before_cycles = read_completed_cycle_evidence(self.store)
                self.assertNotEqual(source['cycle_ids'][-1], before_cycles[-1].cycle_id)
                self.assertEqual(2, source['k'])
                self.assertEqual(2, len(source['cycle_ids']))
                images = self._tracker_images()
                result = consumer.replay_original_receipted_prod_source(
                    self.store, **self._original_replay_args(token, original))
                self.assertIs(type(result), consumer.ProdStageLQualifiedSet)
                self.assertEqual(tuple(source['cycle_ids']), result.cycle_ids)
                self.assertEqual(tuple(source['completion_sha256']), result.completion_sha256)
                self.assertEqual(source['source_authority_sha256'], result.source_authority_sha256)
                self.assertEqual(source['observations_sha256'], result.observations_sha256)
                self.assertEqual(source['k_event_sha256'], result.k_event_sha256)
                self.assertEqual('prod-runtime-protected-v1', result.mode)
                self.assertEqual('prod', result.scope)
                self.assertFalse(hasattr(result, 'permit'))
                self.assertFalse(hasattr(result, 'send_authority'))
                self.assertEqual(before_cycles, read_completed_cycle_evidence(self.store),
                                 'historical projection must not escape replay scope')
                current = read_current_cycle_local_receipts(token, self.store,
                    expected_template_sha256=self.snapshot.workbook_sha256,
                    settings=current_k(token), whitelist_sha256=self.snapshot.whitelist.sha256)
                self.assertEqual((0, ()), (current.published, current.generation_ids))
            self.assertEqual(images, self._tracker_images())
            self.assertEqual(raw, (generation / 'MANIFEST').read_bytes())
        self._old_two_cycle_receipt_fixture(probe)

    def test_old_replay_refuses_unproved_generation_config_and_owner_before_native_qualification(self):
        from dataclasses import replace
        from monitor import issue_tracker_stage_l_consumer as consumer

        def probe(original):
            before = self._tracker_images()
            with tracker_writer(self.project, self.publication) as token:
                args = self._original_replay_args(token, original)
                variants = (
                    {'local_generation_id': 'gen-00000000000000000099-' + 'f' * 32},
                    {'expected_template_sha256': '0' * 64},
                    {'settings': replace(args['settings'], k=3)},
                    {'writer_token': object()},
                )
                with mock.patch.object(consumer, 'qualify_prod_stage_l') as native:
                    for variant in variants:
                        with self.subTest(invalid=tuple(variant)), self.assertRaises(consumer.StageLConsumerHold):
                            consumer.replay_original_receipted_prod_source(self.store, **{**args, **variant})
                native.assert_not_called()
            self.assertEqual(before, self._tracker_images())
        self._old_two_cycle_receipt_fixture(probe)

    def test_old_replay_scoped_cycle_view_is_revoked_on_return(self):
        from monitor import issue_tracker_stage_l_consumer as consumer
        from monitor.issue_tracker_cycle_source import read_completed_cycle_evidence

        def probe(original):
            native = consumer.qualify_prod_stage_l
            views = []
            def capture_view(store, **kwargs):
                self.assertIsNot(store, self.store)
                views.append(store)
                return native(store, **kwargs)
            with tracker_writer(self.project, self.publication) as token:
                before = read_completed_cycle_evidence(self.store)
                with mock.patch.object(consumer, 'qualify_prod_stage_l', side_effect=capture_view):
                    consumer.replay_original_receipted_prod_source(
                        self.store, **self._original_replay_args(token, original))
                self.assertEqual(1, len(views))
                with self.assertRaises(ValueError):
                    read_completed_cycle_evidence(views[0])
                self.assertEqual(before, read_completed_cycle_evidence(self.store))
        self._old_two_cycle_receipt_fixture(probe)

    def test_old_replay_detects_same_byte_policy_swap_and_restore_during_native_window_walk(self):
        from monitor import issue_tracker_stage_l_consumer as consumer

        def probe(original):
            policy = self.project / '01-global.yaml'
            raw = policy.read_bytes()
            backup = self.project / 'owned-replay-original-policy'
            replacement = self.project / 'owned-replay-policy-copy'
            native = consumer.qualify_prod_stage_l
            reached = []
            def swap_and_restore(view, **kwargs):
                read = view._read_witness
                def mutate():
                    if not reached:
                        replacement.write_bytes(raw); replacement.chmod(policy.stat().st_mode & 0o777)
                        policy.rename(backup); replacement.rename(policy)
                        policy.rename(replacement); backup.rename(policy)
                        reached.append(True)
                    return read()
                with mock.patch.object(view, '_read_witness', side_effect=mutate):
                    return native(view, **kwargs)
            with tracker_writer(self.project, self.publication) as token:
                with mock.patch.object(consumer, 'qualify_prod_stage_l', side_effect=swap_and_restore):
                    with self.assertRaises(consumer.StageLConsumerHold):
                        consumer.replay_original_receipted_prod_source(
                            self.store, **self._original_replay_args(token, original))
                self.assertEqual([True], reached, 'fault must enter the real native window walk')
            self.assertEqual(raw, policy.read_bytes()); self.assertEqual(raw, replacement.read_bytes())
        self._old_two_cycle_receipt_fixture(probe)

    def test_old_replay_detects_original_record_directory_swap_and_restore_during_native_window_walk(self):
        from monitor import issue_tracker_stage_l_consumer as consumer

        def probe(original):
            records = self.store.records_dir
            inode = records.stat().st_ino
            images = {p.name:(p.stat().st_ino,p.read_bytes()) for p in records.iterdir()}
            backup = self.project/'owned-native-replay-original-records'
            clone = self.project/'owned-native-replay-clone-records'
            shutil.copytree(records, clone)
            native = consumer.qualify_prod_stage_l
            reached = []
            def swap_and_restore(view, **kwargs):
                read = view._read_witness
                def mutate():
                    if not reached:
                        records.rename(backup); clone.rename(records)
                        records.rename(clone); backup.rename(records)
                        reached.append(True)
                    return read()
                with mock.patch.object(view, '_read_witness', side_effect=mutate):
                    return native(view, **kwargs)
            with tracker_writer(self.project,self.publication) as token:
                with mock.patch.object(consumer,'qualify_prod_stage_l',side_effect=swap_and_restore):
                    with self.assertRaises(consumer.StageLConsumerHold):
                        consumer.replay_original_receipted_prod_source(
                            self.store, **self._original_replay_args(token,original))
                self.assertEqual([True],reached,'fault must enter the actual native window walk')
            self.assertEqual(inode, records.stat().st_ino)
            self.assertEqual(images,{p.name:(p.stat().st_ino,p.read_bytes()) for p in records.iterdir()})
            self.assertEqual({name:raw for name,(_ino,raw) in images.items()},
                             {p.name:p.read_bytes() for p in clone.iterdir()})
        self._old_two_cycle_receipt_fixture(probe)

    def test_old_replay_pins_current_high_water_even_when_original_window_is_unchanged(self):
        from monitor import issue_tracker_stage_l_consumer as consumer

        def probe(original):
            witness = self.store.witness_path
            raw = witness.read_bytes()
            native = consumer.qualify_prod_stage_l
            reached = []
            def replace_current_witness(*args, **kwargs):
                result = native(*args, **kwargs)
                replacement = witness.with_name('owned-replay-new-witness')
                replacement.write_bytes(raw)
                replacement.chmod(witness.stat().st_mode & 0o777)
                witness.rename(self.project / 'owned-original-current-witness')
                replacement.rename(witness)
                reached.append(True)
                return result
            with tracker_writer(self.project, self.publication) as token:
                with mock.patch.object(consumer, 'qualify_prod_stage_l', side_effect=replace_current_witness):
                    with self.assertRaises(consumer.StageLConsumerHold):
                        consumer.replay_original_receipted_prod_source(
                            self.store, **self._original_replay_args(token, original))
                self.assertEqual([True], reached)
            self.assertEqual(raw, witness.read_bytes())
            self.assertEqual(raw, (self.project / 'owned-original-current-witness').read_bytes())
        self._old_two_cycle_receipt_fixture(probe)

    def test_old_replay_does_not_adopt_same_byte_manifest_replacement_after_native_qualification(self):
        from monitor import issue_tracker_stage_l_consumer as consumer
        from monitor.issue_tracker_cycle_source import read_completed_cycle_evidence

        def probe(original):
            manifest = self.project / '.tracker/generations' / original.receipt.generation_id / 'MANIFEST'
            raw = manifest.read_bytes()
            native = consumer.qualify_prod_stage_l
            reached = []
            def replace_after_native(*args, **kwargs):
                result = native(*args, **kwargs)
                replacement = manifest.with_name('owned-replay-replacement')
                replacement.write_bytes(raw)
                replacement.chmod(0o600)
                preserved = self.project / 'owned-old-replay-original-manifest'
                manifest.rename(preserved)
                replacement.rename(manifest)
                reached.append(True)
                return result
            with tracker_writer(self.project, self.publication) as token:
                before_cycles = read_completed_cycle_evidence(self.store)
                with mock.patch.object(consumer, 'qualify_prod_stage_l', side_effect=replace_after_native):
                    with self.assertRaises(consumer.StageLConsumerHold):
                        consumer.replay_original_receipted_prod_source(
                            self.store, **self._original_replay_args(token, original))
                self.assertEqual([True], reached, 'fault must reach actual protected native replay')
                self.assertEqual(before_cycles, read_completed_cycle_evidence(self.store))
            self.assertEqual(raw, manifest.read_bytes())
            self.assertEqual(raw, (self.project / 'owned-old-replay-original-manifest').read_bytes())
        self._old_two_cycle_receipt_fixture(probe)



if __name__ == "__main__":
    unittest.main()
