"""REQ7 prod Stage L source binding must remain HOLD without all three panels."""

from __future__ import annotations

import hashlib
import os
import unittest
from unittest import mock

from monitor.issue_tracker_cycle_source import read_completed_cycle_evidence
from monitor.issue_tracker_ib_runtime import IbBoundCycleReport, IbReportLink
from monitor.issue_tracker_state_owner import (
    current_k, initialize_tracker_state, set_k, tracker_writer,
)
from monitor.issue_tracker_whitelist_workbook import read_whitelist_workbook
from test_cases.test_issue_tracker_whitelist_workbook import literal_xlsx


class ProdStageLFixture(unittest.TestCase):
    def _archive(self, *args, **kwargs):
        from test_cases.test_issue_tracker_switch_runtime_workflow import (
            ProdSwitchSourceWorkflowTests,
        )
        return ProdSwitchSourceWorkflowTests._archive(self, *args, **kwargs)

    def _cycle(self, *args, **kwargs):
        from test_cases.test_issue_tracker_switch_runtime_workflow import (
            ProdSwitchSourceWorkflowTests,
        )
        return ProdSwitchSourceWorkflowTests._cycle(self, *args, **kwargs)

    def setUp(self):
        from test_cases.test_issue_tracker_switch_runtime_workflow import (
            ProdSwitchSourceWorkflowTests,
        )
        ProdSwitchSourceWorkflowTests.setUp(self)
        self.publication = self.project / "99-output-monitor"
        self.publication.mkdir()
        initialize_tracker_state(
            self.project, self.publication,
            initialized_at="2026-09-25T00:00:00Z",
            acquisition_id="prod-three-panel-source-gate",
        )
        with tracker_writer(self.project, self.publication) as token:
            set_k(token, new_k=2, actor="operator:fixture",
                  recorded_at="2026-09-25T00:01:00Z", request_id="prod-k-two",
                  expected_revision=0)
            self.settings = current_k(token)
        self.template = self.project / "local-template.xlsx"
        self.template.write_bytes(literal_xlsx())
        self.snapshot = read_whitelist_workbook(self.template)

    def two_cycles(self, *, activity=False, derivation=False, **kwargs):
        first, _ = self._cycle(activity=activity, derivation=derivation,
                               **kwargs)
        second, artifacts = self._cycle(activity=activity,
                                        derivation=derivation, **kwargs)
        return first, second, artifacts


class ProdStageLConsumerDirectTests(ProdStageLFixture):
    def test_original_replay_rejects_record_directory_swap_back_even_with_all_original_files_restored(self):
        import shutil
        from monitor import issue_tracker_stage_l_consumer as consumer
        self.two_cycles(activity=True, derivation=True)
        (self.project/'01-global.yaml').write_bytes(b'schema_version: 2\ncommon: {}\n')
        records = self.store.records_dir
        inode = records.stat().st_ino
        images = {p.name:(p.stat().st_ino,p.read_bytes()) for p in records.iterdir()}
        original = self.project/'owned-swapped-back-original-records'
        clone = self.project/'owned-swapped-back-clone-records'
        shutil.copytree(records, clone)
        with self.assertRaises(consumer.StageLConsumerHold):
            with consumer._hold_original_replay_inputs(self.store,self.project,self.template) as verify:
                records.rename(original)
                clone.rename(records)
                records.rename(clone)
                original.rename(records)
                self.assertEqual(inode, records.stat().st_ino)
                self.assertEqual(images,{p.name:(p.stat().st_ino,p.read_bytes()) for p in records.iterdir()})
                verify()
        self.assertEqual(inode, records.stat().st_ino)
        self.assertEqual(images,{p.name:(p.stat().st_ino,p.read_bytes()) for p in records.iterdir()})

    def test_original_replay_pins_record_directory_before_first_namespace_read(self):
        from pathlib import Path
        from monitor import issue_tracker_stage_l_consumer as consumer
        self.two_cycles(activity=True, derivation=True)
        (self.project / '01-global.yaml').write_bytes(b'schema_version: 2\ncommon: {}\n')
        records = self.store.records_dir
        original = records.stat()
        image = {p.name: (p.read_bytes(), p.stat().st_mode & 0o777)
                 for p in records.iterdir()}
        backup = self.project / 'owned-original-record-directory'
        abandoned = self.project / 'owned-replacement-record-directory'
        native_listdir = os.listdir
        reached = []

        def replace_after_first_namespace_read(path):
            names = native_listdir(path)
            if isinstance(path, int):
                info = os.fstat(path)
                selected = (info.st_dev, info.st_ino) == (original.st_dev, original.st_ino)
            else:
                selected = Path(path) == records
            if selected and not reached:
                records.rename(backup)
                records.mkdir(mode=original.st_mode & 0o777)
                for name, (raw, mode) in image.items():
                    member = records / name
                    member.write_bytes(raw)
                    member.chmod(mode)
                reached.append(True)
            return names

        try:
            with mock.patch.object(consumer.os, 'listdir', side_effect=replace_after_first_namespace_read):
                with self.assertRaises(consumer.StageLConsumerHold):
                    with consumer._hold_original_replay_inputs(self.store, self.project, self.template) as verify:
                        verify()
            self.assertEqual([True], reached, 'fault must follow the real first namespace read')
            self.assertNotEqual(original.st_ino, records.stat().st_ino)
            for name, (raw, _mode) in image.items():
                self.assertEqual(raw, (backup / name).read_bytes())
                self.assertEqual(raw, (records / name).read_bytes())
        finally:
            if backup.exists():
                records.rename(abandoned)
                backup.rename(records)
        self.assertEqual(original.st_ino, records.stat().st_ino)

    def test_original_replay_input_scope_holds_named_policy_whitelist_and_full_current_chain(self):
        from monitor import issue_tracker_stage_l_consumer as consumer
        self.two_cycles(activity=True, derivation=True)
        policy = self.project / '01-global.yaml'
        policy.write_bytes(b'schema_version: 2\ncommon: {}\n')
        paths = (policy, self.template, self.store.witness_path,
                 self.store.completion_path(2))
        for number, path in enumerate(paths):
            with self.subTest(original=path.name):
                raw = path.read_bytes()
                inode = path.stat().st_ino
                backup = self.project / ('owned-pin-original-' + str(number))
                replacement = self.project / ('owned-pin-replacement-' + str(number))
                replacement.write_bytes(raw)
                replacement.chmod(path.stat().st_mode & 0o777)
                try:
                    with self.assertRaises(consumer.StageLConsumerHold):
                        with consumer._hold_original_replay_inputs(self.store, self.project, self.template) as verify:
                            path.rename(backup)
                            replacement.rename(path)
                            self.assertNotEqual(inode, path.stat().st_ino)
                            verify()
                    self.assertEqual(raw, path.read_bytes())
                    self.assertEqual(raw, backup.read_bytes())
                finally:
                    if backup.exists():
                        path.rename(replacement)
                        backup.rename(path)
                self.assertEqual(inode, path.stat().st_ino)

    def test_original_source_replay_refuses_unreceipted_generation_without_creating_evidence(self):
        from monitor import issue_tracker_stage_l_consumer as consumer
        before = {p.relative_to(self.project).as_posix(): p.read_bytes()
                  for p in (self.project / '.tracker').rglob('*') if p.is_file()}
        with tracker_writer(self.project, self.publication) as token:
            with mock.patch.object(consumer, 'qualify_prod_stage_l') as native:
                with self.assertRaises(consumer.StageLConsumerHold):
                    consumer.replay_original_receipted_prod_source(
                        self.store, http_root=self.root, settings=current_k(token),
                        whitelist_snapshot=self.snapshot, whitelist_path=self.template,
                        expected_template_sha256=self.snapshot.workbook_sha256,
                        local_generation_id='gen-00000000000000000001-' + 'a' * 32,
                        writer_token=token)
                native.assert_not_called()
        self.assertEqual(before, {p.relative_to(self.project).as_posix(): p.read_bytes()
            for p in (self.project / '.tracker').rglob('*') if p.is_file()})

    def test_original_source_replay_refuses_released_owner_before_native_reads(self):
        from monitor import issue_tracker_stage_l_consumer as consumer
        with tracker_writer(self.project, self.publication) as token:
            settings = current_k(token)
        with mock.patch.object(consumer, 'qualify_prod_stage_l') as native:
            with self.assertRaises(consumer.StageLConsumerHold):
                consumer.replay_original_receipted_prod_source(
                    self.store, http_root=self.root, settings=settings,
                    whitelist_snapshot=self.snapshot, whitelist_path=self.template,
                    expected_template_sha256=self.snapshot.workbook_sha256,
                    local_generation_id='gen-00000000000000000001-' + 'a' * 32,
                    writer_token=token)
            native.assert_not_called()

    def test_source_file_identity_requires_regular_named_bytes_and_records_mtime(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, _bound_source_file,
        )

        source = self.root / "monitor/status/synthetic-panel-source.bin"
        source.write_bytes(b"independent fixture source\n")
        digest = hashlib.sha256(b"independent fixture source\n").hexdigest()
        relative = source.relative_to(self.root).as_posix()
        first = _bound_source_file(self.root, relative, digest)
        self.assertEqual(relative, first.path)
        self.assertEqual(digest, first.sha256)
        self.assertEqual(source.stat().st_mtime_ns, first.mtime_ns)
        self.assertTrue(first.recorded_at_utc.endswith("Z"))
        with self.assertRaises(StageLConsumerHold):
            _bound_source_file(self.root, relative, "0" * 64)
        old = source.stat().st_mtime_ns
        os.utime(source, ns=(old + 2_000_000_000, old + 2_000_000_000))
        second = _bound_source_file(self.root, relative, digest)
        self.assertNotEqual(first, second)  # same bytes but stale timestamp
        alias = source.with_name("synthetic-panel-alias.bin")
        alias.symlink_to(source.name)
        with self.assertRaises(StageLConsumerHold):
            _bound_source_file(self.root, alias.relative_to(self.root).as_posix(),
                               digest)

    def test_source_validation_rejects_same_bytes_same_mtime_inode_replacement(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, _bound_source_file,
            validate_prod_stage_l_panel_source_files,
        )

        content = b"independent fixture source\n"
        digest = hashlib.sha256(content).hexdigest()
        source = self.root / "monitor/status/synthetic-panel-source.bin"
        source.write_bytes(content)
        relative = source.relative_to(self.root).as_posix()
        original = _bound_source_file(self.root, relative, digest)

        replacement = source.with_name("synthetic-panel-replacement.bin")
        replacement.write_bytes(content)
        os.utime(replacement, ns=(original.mtime_ns, original.mtime_ns))
        os.replace(replacement, source)
        current = _bound_source_file(self.root, relative, digest)
        self.assertEqual(original.sha256, current.sha256)
        self.assertEqual(original.size_bytes, current.size_bytes)
        self.assertEqual(original.mtime_ns, current.mtime_ns)
        self.assertNotEqual(original.inode, current.inode)

        with mock.patch(
            "monitor.issue_tracker_stage_l_consumer.read_prod_stage_l_panel_source_files",
            return_value=(current,),
        ) as reread:
            with self.assertRaisesRegex(StageLConsumerHold, "changed; preview again"):
                validate_prod_stage_l_panel_source_files(
                    (original,), object(), object(), panel="Switch Status",
                    http_root=self.root, settings=self.settings,
                    whitelist_snapshot=self.snapshot,
                    whitelist_path=self.template,
                )
        reread.assert_called_once()

    def test_panel_source_identity_rejects_unbound_caller_rows(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, read_prod_stage_l_panel_source_files,
        )

        with self.assertRaises(StageLConsumerHold):
            read_prod_stage_l_panel_source_files(
                {"project_key": self.store.project_key}, self.store,
                panel="Switch Status", http_root=self.root,
                settings=self.settings, whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            )

    def test_dynamic_switch_host_without_frozen_fabric_identity_holds(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, inspect_prod_stage_l_sources,
        )

        self._cycle(dynamic_eth=True)
        self._cycle(dynamic_eth=True)
        with self.assertRaisesRegex(StageLConsumerHold, "Fabric"):
            inspect_prod_stage_l_sources(
                self.store, http_root=self.root, settings=self.settings,
                whitelist_snapshot=self.snapshot, whitelist_path=self.template,
            )

    def test_fabric_classifier_refuses_unresolved_identity_instead_of_guessing(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, classify_stage_l_fabric,
        )

        self.assertEqual(("Compute", "type"), classify_stage_l_fabric(
            "eth_spx", "tan-leaf", "oob-leaf",
        ))
        self.assertEqual(("OOB", "template"), classify_stage_l_fabric(
            "eth", "oob-leaf", "tan-leaf",
        ))
        self.assertEqual(("Inband", "hostname-fallback"),
                         classify_stage_l_fabric("eth", "", "tan-leaf"))
        with self.assertRaises(StageLConsumerHold):
            classify_stage_l_fabric("eth", "", "leaf-a")

    def test_source_projection_rejects_caller_dict_not_a_bound_witness(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, project_prod_stage_l_source_candidates,
        )

        with self.assertRaises(StageLConsumerHold):
            project_prod_stage_l_source_candidates(
                {"qualified": True}, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            )

    def test_qualification_holds_without_protected_ib_and_fabric(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, qualify_prod_stage_l,
        )

        self.two_cycles(activity=True, derivation=True)
        with self.assertRaises(StageLConsumerHold):
            qualify_prod_stage_l(
                self.store, http_root=self.root, settings=self.settings,
                whitelist_snapshot=self.snapshot, whitelist_path=self.template,
            )

    def test_composed_source_never_infers_missing_ib_from_real_eth_activity(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, inspect_prod_stage_l_composed_sources,
            validate_prod_stage_l_composed_sources,
        )

        self.two_cycles(activity=True, derivation=True)
        with self.assertRaises(StageLConsumerHold):
            inspect_prod_stage_l_composed_sources(
                self.store, http_root=self.root, settings=self.settings,
                whitelist_snapshot=self.snapshot, whitelist_path=self.template,
            )
        with self.assertRaises(StageLConsumerHold):
            validate_prod_stage_l_composed_sources(
                {"cycle_ids": ("0" * 64,)}, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            )
        self.assertEqual((), tuple(self.publication.iterdir()))

    def test_switch_and_ib_source_requires_real_ib_completed_role(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, inspect_prod_stage_l_bound_sources,
        )

        self.two_cycles()
        with self.assertRaises(StageLConsumerHold):
            inspect_prod_stage_l_bound_sources(
                self.store, http_root=self.root, settings=self.settings,
                whitelist_snapshot=self.snapshot, whitelist_path=self.template,
            )
        self.assertEqual((), tuple(self.publication.iterdir()))

    def test_switch_and_ib_source_rejects_foreign_ib_cycle_or_topology(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, inspect_prod_stage_l_bound_sources,
        )

        self.two_cycles()
        cycles = read_completed_cycle_evidence(self.store)
        row = IbReportLink(
            "Mis-wiring", ("leaf-ib", "1/1", "server01", "mlx5_0"),
            ("server02", "mlx5_1"), "Miswired_Links", 2,
        )
        reports = {
            cycle.sequence: IbBoundCycleReport(
                cycle.cycle_id, cycle.sequence, cycle.completion_sha256,
                f"{cycle.sequence}" * 64, "a" * 64, (row,),
            ) for cycle in cycles
        }
        reports[cycles[-1].sequence] = IbBoundCycleReport(
            "foreign-cycle", cycles[-1].sequence,
            cycles[-1].completion_sha256, "2" * 64, "a" * 64, (row,),
        )
        with mock.patch(
            "monitor.issue_tracker_ib_runtime.read_completed_ib_cycle_report",
            side_effect=lambda _store, *, http_root, sequence: reports[sequence],
        ):
            with self.assertRaises(StageLConsumerHold):
                inspect_prod_stage_l_bound_sources(
                    self.store, http_root=self.root, settings=self.settings,
                    whitelist_snapshot=self.snapshot, whitelist_path=self.template,
                )
        reports[cycles[-1].sequence] = IbBoundCycleReport(
            cycles[-1].cycle_id, cycles[-1].sequence,
            cycles[-1].completion_sha256, "2" * 64, "b" * 64, (row,),
        )
        with mock.patch(
            "monitor.issue_tracker_ib_runtime.read_completed_ib_cycle_report",
            side_effect=lambda _store, *, http_root, sequence: reports[sequence],
        ):
            with self.assertRaises(StageLConsumerHold):
                inspect_prod_stage_l_bound_sources(
                    self.store, http_root=self.root, settings=self.settings,
                    whitelist_snapshot=self.snapshot, whitelist_path=self.template,
                )

    def test_latest_rows_follow_cycle_sequence_not_k_window_length(self):
        from monitor.issue_tracker_stage_l_consumer import inspect_prod_stage_l_sources
        from test_cases import test_issue_tracker_switch_runtime_workflow as workflow

        self.two_cycles()
        with mock.patch.object(workflow, "TOKEN_2", "abcdef01234546778899aabbccddeeff"):
            third, _ = self._cycle()
        source = inspect_prod_stage_l_sources(
            self.store, http_root=self.root, settings=self.settings,
            whitelist_snapshot=self.snapshot, whitelist_path=self.template,
        )
        self.assertEqual(third["cycle_id"], source.cycle_ids[-1])
        self.assertEqual(2, len(source.cycle_ids))

    def test_real_prod_switch_values_are_bound_but_ib_absence_prevents_qualification(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, inspect_prod_stage_l_sources,
            require_complete_stage_l_sources,
        )

        first, second, _ = self.two_cycles()
        source = inspect_prod_stage_l_sources(
            self.store, http_root=self.root, settings=self.settings,
            whitelist_snapshot=self.snapshot, whitelist_path=self.template,
        )
        self.assertEqual((first["cycle_id"], second["cycle_id"]), source.cycle_ids)
        self.assertEqual("hold", source.state)
        self.assertFalse(source.qualified)
        self.assertEqual("ib_report_not_bound_to_completed_cycle", source.reason)
        self.assertEqual(("leaf-a", "fan", "PSU1/FAN1"),
                         (source.switch_rows[0].hostname,
                          source.switch_rows[0].category,
                          source.switch_rows[0].component_or_sensor))
        self.assertIn("state=fail", source.switch_rows[0].value.evidence_description)
        self.assertTrue(any(row.source_slot == "nvlink/prod"
                            for row in source.switch_rows))
        with self.assertRaisesRegex(StageLConsumerHold,
                                    "IB report.*completed cycle"):
            require_complete_stage_l_sources(
                source, self.store, http_root=self.root,
                settings=self.settings,
                whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            )
        self.assertEqual((), tuple(self.publication.iterdir()))

    def test_k_whitelist_or_last_cycle_drift_never_becomes_source_authority(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, inspect_prod_stage_l_sources,
            validate_prod_stage_l_sources,
        )

        _, _, artifacts = self.two_cycles()
        source = inspect_prod_stage_l_sources(
            self.store, http_root=self.root, settings=self.settings,
            whitelist_snapshot=self.snapshot, whitelist_path=self.template,
        )
        self.assertEqual(source, validate_prod_stage_l_sources(
            source, self.store, http_root=self.root,
            settings=self.settings, whitelist_snapshot=self.snapshot,
            whitelist_path=self.template,
        ))
        self.template.write_bytes(literal_xlsx(rules=("nvsw01",)))
        with self.assertRaises(StageLConsumerHold):
            validate_prod_stage_l_sources(
                source, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            )
        self.template.write_bytes(literal_xlsx())
        latest_info = artifacts["ethernet/prod"]["info"]
        latest_info.write_bytes(latest_info.read_bytes() + b"late drift")
        with self.assertRaises(StageLConsumerHold):
            validate_prod_stage_l_sources(
                source, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            )


if __name__ == "__main__":
    unittest.main()
