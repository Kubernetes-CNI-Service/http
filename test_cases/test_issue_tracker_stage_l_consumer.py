"""REQ7 prod Stage L source binding must remain HOLD without all three panels."""

from __future__ import annotations

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
