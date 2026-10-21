"""Independent contracts for the REQ7 source/data boundary; no send authority."""

from dataclasses import FrozenInstanceError, replace
import importlib
import importlib.util
import unittest

from monitor.issue_tracker_stage_l_consumer import StageLSourceCandidate
from monitor.issue_tracker_local_commit import LocalCommitHold


def candidates():
    return (
        StageLSourceCandidate(
            operation_id="eth-op", activity_key=("eth_cabling", "leaf01", "swp1", "Link Down"),
            panel="Eth Link Validation", source_sheet="ETH Link", issue_type="Link Down",
            source_status="Link Down", evidence_description="peer down",
            expected_endpoints=("leaf01", "swp1", "spine01", "swp9"),
            actual_endpoints=("spine01", "swp9", "leaf01", "swp1"),
            recorded_at_utc="2026-10-21T03:00:00Z"),
        StageLSourceCandidate(
            operation_id="ib-op", activity_key=("ib_cabling", "ib-leaf01", "1/1", "Link Down"),
            panel="IB Link Validation", source_sheet="IB Link", issue_type="Link Down",
            source_status="Link Down", evidence_description="IB peer down",
            expected_endpoints=("ib-leaf01", "1/1", "ib-spine01", "2/1"),
            actual_endpoints=("ib-spine01", "2/1", "ib-leaf01", "1/1"),
            recorded_at_utc="2026-10-21T03:00:00Z"),
        StageLSourceCandidate(
            operation_id="switch-op", activity_key=("switch", "leaf02", "fan", "PSU1/FAN"),
            panel="Switch Status", source_sheet="Switch Status", issue_type="PSU1/FAN",
            source_status="Fail", evidence_description="fan unhealthy",
            fabric="Inband", fabric_source="template",
            recorded_at_utc="2026-10-21T03:00:00Z"),
    )


class SourceAdapterTests(unittest.TestCase):
    def modules(self):
        for name in ("monitor.issue_tracker_source_model", "monitor.issue_tracker_collected_source"):
            self.assertIsNotNone(importlib.util.find_spec(name),
                                 "source model/adapter must be independent of workbook commit")
        return (importlib.import_module("monitor.issue_tracker_source_model"),
                importlib.import_module("monitor.issue_tracker_collected_source"))

    def test_public_row_types_are_reexported_without_split_type_identity(self):
        model, _ = self.modules()
        from monitor import issue_tracker_local_workbook as workbook
        for name in ("CablingSourceRow", "SwitchSourceWorkbookRow"):
            self.assertIs(getattr(model, name), getattr(workbook, name))
            self.assertEqual(getattr(model, name).__module__, "monitor.issue_tracker_source_model")

    def test_collected_values_and_ib_link_down_empty_actual_are_literal(self):
        model, adapter = self.modules()
        changes = adapter.collected_changes(candidates())
        self.assertIs(type(changes), model.TrackerChanges)
        self.assertEqual(tuple(row.sheet for row in changes.cabling), ("ETH Cabling", "IB Cabling"))
        self.assertEqual(changes.cabling[0].expected_endpoints, ("leaf01", "swp1", "spine01", "swp9"))
        self.assertEqual(changes.cabling[0].actual_endpoints, ("spine01", "swp9", "leaf01", "swp1"))
        self.assertEqual(changes.cabling[1].actual_endpoints, ())
        self.assertEqual((changes.switch[0].priority, changes.switch[0].fabric,
                          changes.switch[0].fabric_source), ("P2", "Inband", "template"))
        self.assertEqual(changes.switch[0].evidence_description, "fan unhealthy")
        self.assertFalse(hasattr(changes, "qualified"))
        self.assertFalse(hasattr(changes, "permit"))
        with self.assertRaises(FrozenInstanceError):
            changes.switch = ()

    def test_panel_mismatch_is_not_hidden_by_selection(self):
        _, adapter = self.modules()
        bad = replace(candidates()[0], panel="IB Link Validation")
        with self.assertRaises(LocalCommitHold):
            adapter.collected_changes((bad,), selected_panel="Switch Status")

    def test_only_selection_does_not_rewrite_or_include_other_panels(self):
        _, adapter = self.modules()
        values = candidates()
        changes = adapter.collected_changes(values, selected_panel="Switch Status")
        self.assertEqual(changes.cabling, ())
        self.assertEqual(len(changes.switch), 1)
        self.assertEqual(values, candidates())
        with self.assertRaises(LocalCommitHold):
            adapter.collected_changes(values, selected_panel="CVT")

    def test_model_contains_no_cvt_fetcher_and_adapter_rejects_unknown_source(self):
        model, adapter = self.modules()
        self.assertFalse(hasattr(model, "fetch_cvt"))
        unknown = replace(candidates()[0], activity_key=("cvt", "leaf01", "swp1", "Link Down"))
        with self.assertRaises(LocalCommitHold):
            adapter.collected_changes((unknown,))


if __name__ == "__main__":
    unittest.main()
