"""REQ7 manual C5/C6 selects one sheet after full protected-source replay."""

from dataclasses import replace
from io import BytesIO
import json
from types import SimpleNamespace
import unittest
from unittest import mock
import zipfile

from monitor.issue_tracker_manifest import freeze_prod_stage_l_manifest
from monitor.issue_tracker_stage_l_consumer import (
    ProdStageLQualifiedSet, StageLQualifiedSkip, StageLSourceCandidate,
)
from tools.project_contract import collection_cycle_project_key
from test_cases.test_issue_tracker_local_workbook import fake_workbook


PANELS = ("Switch Status", "Eth Link Validation", "IB Link Validation")
SHEETS = ("ETH&IB Switch", "ETH Cabling", "IB Cabling")


def full_qualified():
    candidates = (
        StageLSourceCandidate(
            "a-switch", ("switch", "leaf01", "fan", "fan1"),
            "Switch Status", "ETH&IB Switch", "fan", "fail", "fan alarm",
            fabric="Compute", fabric_source="type",
            recorded_at_utc="2026-09-28T00:00:00Z", qualified=True,
        ),
        StageLSourceCandidate(
            "b-eth", ("eth_cabling", "leaf01", "swp1", "Link Down"),
            "Eth Link Validation", "ETH Cabling", "Link Down", "Link Down",
            "eth alarm", expected_endpoints=("leaf01", "swp1", "leaf02", "swp2"),
            recorded_at_utc="2026-09-28T00:00:00Z", qualified=True,
        ),
        StageLSourceCandidate(
            "c-ib", ("ib_cabling", "leaf03", "swp3", "Link Down"),
            "IB Link Validation", "IB Cabling", "Link Down", "Link Down",
            "ib alarm", expected_endpoints=("leaf03", "swp3", "leaf04", "swp4"),
            recorded_at_utc="2026-09-28T00:00:00Z", qualified=True,
        ),
    )
    operations = [{"action": "upsert", "activity_key": list(item.activity_key),
                   "operation_id": item.operation_id} for item in candidates]
    return ProdStageLQualifiedSet(
        operations_json=json.dumps(operations, sort_keys=True,
                                   separators=(",", ":")).encode(),
        candidates=candidates,
        whitelist_skips=(
            StageLQualifiedSkip("switch", "rule-switch", record_id="switch:leaf01"),
            StageLQualifiedSkip("eth_cabling", "rule-eth",
                                endpoints=("leaf11", "swp11", "leaf12", "swp12")),
            StageLQualifiedSkip("ib_cabling", "rule-ib", activity_key=(
                "ib_cabling", "leaf13", "leaf14", "Link Down")),
        ),
        cycle_ids=("cycle-a",), completion_sha256=("1" * 64,),
        source_authority_sha256="2" * 64, observations_sha256="3" * 64,
        k_event_sha256="4" * 64, whitelist_sha256="5" * 64,
        template_sha256="6" * 64,
        project_key=collection_cycle_project_key("site-a"), scope="prod", k=1,
        recorded_at_utc="2026-09-28T00:00:00Z",
    )


class ManualPanelWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.qualified = full_qualified()
        self.metadata = {
            "project_id": "site-a", "schema_version": 1,
            "producer_version": "stage-l-runtime-v1",
            "template_contract_version": "local-xlsx-v1",
            "template_sha256": self.qualified.template_sha256,
        }
        self.snapshot = SimpleNamespace(workbook_sha256=self.qualified.template_sha256)

    def _freeze(self, panel):
        with mock.patch("monitor.issue_tracker_stage_l_consumer.qualify_prod_stage_l",
                        return_value=self.qualified) as replay:
            body, identity = freeze_prod_stage_l_manifest(
                self.qualified, object(), http_root=object(), settings=object(),
                whitelist_snapshot=self.snapshot, whitelist_path=object(),
                metadata=self.metadata,
                expected_template_sha256=self.qualified.template_sha256,
                selected_panel=panel,
            )
        self.assertGreaterEqual(replay.call_count, 2)
        return json.loads(body), identity

    def test_each_panel_manifest_has_only_its_operations_and_skip_provenance(self):
        expected_source = ("switch", "eth_cabling", "ib_cabling")
        for panel, source in zip(PANELS, expected_source):
            with self.subTest(panel=panel):
                body, _ = self._freeze(panel)
                self.assertEqual(panel, body["qualified_source"]["selected_panel"])
                self.assertEqual([next(item.operation_id for item in
                                       self.qualified.candidates if item.panel == panel)],
                                 [item["operation_id"] for item in body["operations"]])
                self.assertEqual([source], [item["source"] for item in
                                            body["qualified_source"]["whitelist_skips"]])
                self.assertEqual(self.qualified.source_authority_sha256,
                                 body["qualified_source"]["source_authority_sha256"])
                self.assertEqual(self.qualified.observations_sha256,
                                 body["qualified_source"]["observations_sha256"])
                states = body["qualified_source"]["panel_evaluation"]
                self.assertEqual(set(PANELS), set(states))
                self.assertEqual({"state": "evaluated", "whitelist_skips": "skips-present"},
                                 states[panel])
                for other in set(PANELS) - {panel}:
                    self.assertEqual({"state": "not-evaluated-in-this-manifest"},
                                     states[other])

    def test_selected_panel_no_skips_is_not_confused_with_unevaluated_panel(self):
        self.qualified = replace(self.qualified, whitelist_skips=())
        body, _ = self._freeze("Switch Status")
        self.assertEqual([], body["qualified_source"]["whitelist_skips"])
        self.assertEqual({"state": "evaluated", "whitelist_skips": "no-skips"},
                         body["qualified_source"]["panel_evaluation"]["Switch Status"])
        self.assertEqual({"state": "not-evaluated-in-this-manifest"},
                         body["qualified_source"]["panel_evaluation"]["IB Link Validation"])

    def test_existing_full_manifest_remains_three_panel_and_has_no_manual_marker(self):
        with mock.patch("monitor.issue_tracker_stage_l_consumer.qualify_prod_stage_l",
                        return_value=self.qualified):
            body, _ = freeze_prod_stage_l_manifest(
                self.qualified, object(), http_root=object(), settings=object(),
                whitelist_snapshot=self.snapshot, whitelist_path=object(),
                metadata=self.metadata,
                expected_template_sha256=self.qualified.template_sha256,
            )
        full = json.loads(body)
        self.assertEqual(3, len(full["operations"]))
        self.assertEqual(3, len(full["qualified_source"]["whitelist_skips"]))
        self.assertNotIn("selected_panel", full["qualified_source"])
        self.assertNotIn("panel_evaluation", full["qualified_source"])

    def test_invalid_panel_holds_before_manifest_or_any_write(self):
        for panel in ("all", "switch status", 1):
            with self.subTest(panel=panel), self.assertRaises(ValueError):
                self._freeze(panel)

    def test_single_panel_projection_changes_only_target_and_history_members(self):
        from monitor.issue_tracker_local_workbook_commit import project_manual_panel_image
        from monitor.issue_tracker_local_workbook import _sheet_paths

        source = fake_workbook(reserved_switch_rows=2, existing_switch_id="NV10001")
        for panel, target in zip(PANELS, SHEETS):
            with self.subTest(panel=panel):
                _, identity = self._freeze(panel)
                image = project_manual_panel_image(
                    source, self.qualified, panel, identity)
                with zipfile.ZipFile(BytesIO(source)) as before, \
                     zipfile.ZipFile(BytesIO(image)) as after:
                    paths = _sheet_paths(before, set(before.namelist()))
                    self.assertNotEqual(before.read(paths[target]), after.read(paths[target]))
                    self.assertNotEqual(before.read(paths["Update_History"]),
                                        after.read(paths["Update_History"]))
                    history = after.read(paths["Update_History"])
                    selected_rule = {"Switch Status": b"rule-switch",
                                     "Eth Link Validation": b"rule-eth",
                                     "IB Link Validation": b"rule-ib"}[panel]
                    self.assertIn(selected_rule, history)
                    for other_rule in {b"rule-switch", b"rule-eth", b"rule-ib"} - {selected_rule}:
                        self.assertNotIn(other_rule, history)
                    for other in set(SHEETS) - {target}:
                        self.assertEqual(before.read(paths[other]), after.read(paths[other]),
                                         other)
                self.assertEqual(source, fake_workbook(
                    reserved_switch_rows=2, existing_switch_id="NV10001"))


if __name__ == "__main__":
    unittest.main()
