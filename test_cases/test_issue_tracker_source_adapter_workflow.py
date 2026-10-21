"""Real collected adapter → shared model → actual XLSX projector workflow."""

from types import SimpleNamespace
import unittest

from test_cases import test_issue_tracker_source_adapter as source_cases
from test_cases.test_issue_tracker_local_workbook import fake_workbook
from test_cases.test_issue_tracker_cabling_projection import _sheet, _value


class SourceAdapterWorkflowTests(unittest.TestCase):
    def test_real_commit_bridge_and_both_projectors_use_same_typed_changes(self):
        _, adapter = source_cases.SourceAdapterTests().modules()
        from monitor.issue_tracker_local_workbook import (
            project_cabling_workbook_image, project_switch_workbook_image,
        )
        from monitor.issue_tracker_local_workbook_commit import _source_rows
        values = source_cases.candidates()
        changes = adapter.collected_changes(values)
        self.assertEqual(_source_rows(SimpleNamespace(candidates=values)),
                         (changes.cabling, changes.switch))
        base = fake_workbook(reserved_switch_rows=2, existing_switch_id="NV10001")
        image = project_switch_workbook_image(
            project_cabling_workbook_image(base, changes.cabling), changes.switch)
        eth, ib, switch = (_sheet(image, number) for number in (3, 4, 2))
        self.assertEqual((_value(eth, "A3"), _value(ib, "A3")), ("NV30001", "NV30002"))
        self.assertEqual((_value(eth, "K3"), _value(ib, "K3")), ("leaf01", "ib-leaf01"))
        self.assertEqual(_value(switch, "F4"), "leaf02")
        self.assertEqual(_value(switch, "K4"), "P2")
        self.assertIn("fan unhealthy", _value(switch, "L4"))
        # A future source adapter can produce this SAME model; it must not
        # require a second workbook implementation or import the collector.
        model, _ = source_cases.SourceAdapterTests().modules()
        neutral = model.TrackerChanges(changes.cabling, changes.switch)
        replay = project_switch_workbook_image(
            project_cabling_workbook_image(image, neutral.cabling), neutral.switch)
        self.assertEqual(replay, image)


if __name__ == "__main__":
    unittest.main()
