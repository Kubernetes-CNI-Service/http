"""REQ7 manual preview is an opaque, one-use, principal-bound local admission."""

import unittest
from unittest import mock

from monitor.issue_tracker_manual_preview import ManualPreviewHold, ManualPreviewBroker


def qualified_status():
    return {
        "state": "qualified", "online": "disabled_no_send_authority",
        "project_key": "project-a", "scope": "prod", "k": 3,
        "k_revision": 2, "latest_cycle_id": "cycle-3",
        "window_cycle_ids": ["cycle-1", "cycle-2", "cycle-3"],
        "whitelist_sha256": "a" * 64, "template_sha256": "b" * 64,
        "source_authority_sha256": "c" * 64,
        "observations_sha256": "d" * 64,
        "qualified_operation_count": 2, "whitelist_skip_count": 1,
        "selected_decision_sha256": {
            "Switch Status": "e" * 64,
            "Eth Link Validation": "f" * 64,
            "IB Link Validation": "1" * 64,
        },
        "panels": {name: {"state": "qualified"} for name in (
            "Switch Status", "Eth Link Validation", "IB Link Validation")},
    }


class ManualPreviewDirectTests(unittest.TestCase):
    def setUp(self):
        self.status = qualified_status()
        self.reader = mock.Mock(return_value=self.status)
        self.commit = mock.Mock(return_value={"local": "receipt"})
        self.now = 1000.0
        self.broker = ManualPreviewBroker(self.reader, self.commit,
                                          clock=lambda: self.now)

    def test_preview_token_is_opaque_and_second_confirmation_is_one_use(self):
        preview = self.broker.preview("nvis", "Switch Status")
        self.assertEqual("ETH&IB Switch", preview["target_sheet"])
        self.assertEqual(2, preview["qualified_operation_count"])
        self.assertNotIn("rows", preview)
        self.assertNotIn("credentials", preview)
        self.assertRegex(preview["token"], r"^[A-Za-z0-9_-]{43}$")
        result = self.broker.confirm("nvis", "Switch Status", preview["token"],
                                     confirmation="publish_local")
        self.assertEqual({"local": "receipt"}, result)
        self.commit.assert_called_once()
        self.assertEqual("Switch Status", self.commit.call_args.args[0])
        self.assertEqual("c" * 64,
                         self.commit.call_args.args[1]["source_authority_sha256"])
        self.assertEqual("e" * 64,
                         self.commit.call_args.args[1]["selected_decision_sha256"])
        with self.assertRaises(ManualPreviewHold):
            self.broker.confirm("nvis", "Switch Status", preview["token"],
                                confirmation="publish_local")
        self.commit.assert_called_once()

    def test_hold_never_mints_token(self):
        self.status["state"] = "hold"
        with self.assertRaises(ManualPreviewHold):
            self.broker.preview("nvis", "Switch Status")
        self.assertFalse(self.broker.pending_count)
        self.commit.assert_not_called()

    def test_principal_panel_expiry_and_drift_reject_without_commit(self):
        preview = self.broker.preview("nvis", "Switch Status")
        for user, panel in (("cumulus", "Switch Status"),
                            ("nvis", "IB Link Validation")):
            with self.assertRaises(ManualPreviewHold):
                self.broker.confirm(user, panel, preview["token"],
                                    confirmation="publish_local")
        self.status["source_authority_sha256"] = "e" * 64
        with self.assertRaises(ManualPreviewHold):
            self.broker.confirm("nvis", "Switch Status", preview["token"],
                                confirmation="publish_local")
        self.commit.assert_not_called()
        preview = self.broker.preview("nvis", "Switch Status")
        self.now += 121
        with self.assertRaises(ManualPreviewHold):
            self.broker.confirm("nvis", "Switch Status", preview["token"],
                                confirmation="publish_local")
        self.commit.assert_not_called()

    def test_client_never_supplies_rows_or_publish_authority(self):
        preview = self.broker.preview("nvis", "Eth Link Validation")
        with self.assertRaises(ManualPreviewHold):
            self.broker.confirm("nvis", "Eth Link Validation", preview["token"],
                                confirmation="yes")
        self.commit.assert_not_called()
        with self.assertRaises(ManualPreviewHold):
            self.broker.preview("anonymous", "Switch Status")
        with self.assertRaises(ManualPreviewHold):
            self.broker.preview(["nvis"], "Switch Status")

    def test_selected_decision_missing_or_changed_holds_without_commit(self):
        selected = self.status.pop("selected_decision_sha256")
        with self.assertRaises(ManualPreviewHold):
            self.broker.preview("nvis", "Switch Status")
        self.status["selected_decision_sha256"] = selected
        preview = self.broker.preview("nvis", "Switch Status")
        self.assertEqual("e" * 64, preview["selected_decision_sha256"])
        selected["Switch Status"] = "2" * 64
        with self.assertRaises(ManualPreviewHold):
            self.broker.confirm("nvis", "Switch Status", preview["token"],
                                confirmation="publish_local")
        self.commit.assert_not_called()


if __name__ == "__main__":
    unittest.main()
