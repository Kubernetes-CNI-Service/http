"""REQ7 manual preview is an opaque, one-use, principal-bound local admission."""

import unittest
from types import SimpleNamespace
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
    def test_settings_without_trusted_worker_callbacks_fail_closed(self):
        for method in ("settings", "set_k"):
            self.assertTrue(callable(getattr(self.broker, method, None)),
                            "trusted worker settings relay is missing")
        with self.assertRaises(ManualPreviewHold):
            self.broker.settings("nvis", "Switch Status")
        with self.assertRaises(ManualPreviewHold):
            self.broker.set_k("nvis", "Switch Status", new_k=5,
                              expected_revision=2, request_id="a" * 32)
        self.reader.assert_not_called()
        self.commit.assert_not_called()

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

    def test_protected_stage_l_adapter_binds_worker_clock_policy_and_public_receipt(self):
        from monitor.issue_tracker_manual_preview import make_protected_stage_l_broker
        from monitor.issue_tracker_local_workbook_commit import (
            CommittedProdWorkbook, ProdWorkbookNoop,
        )

        receipt = CommittedProdWorkbook(
            SimpleNamespace(generation_id="gen-" + "0" * 19 + "1-" + "a" * 32),
            SimpleNamespace(manifest_id="f" * 64, published_sha256="a" * 64),
            SimpleNamespace(),
        )
        with (mock.patch("monitor.issue_tracker_publish_runtime.inspect_stage_l",
                         return_value=qualified_status()) as inspect,
              mock.patch("monitor.issue_tracker_publish_runtime.local_publish_interval",
                         return_value=(2, "b" * 64)) as policy,
              mock.patch("monitor.issue_tracker_publish_runtime.commit_qualified_prod_local",
                         return_value=receipt) as commit):
            broker = make_protected_stage_l_broker(
                object(), http_root="/synthetic/http", project="/synthetic/project",
                publication="/synthetic/project/99-output-monitor",
                template_path="/synthetic/http/monitor/Issue_Tracker_Template_v1.xlsx",
                boot_id="synthetic-boot", monotonic_ns=lambda: 1234,
                clock=lambda: 1000.0,
            )
            token = broker.preview("nvis", "Switch Status")["token"]
            result = broker.confirm("nvis", "Switch Status", token,
                                    confirmation="publish_local")
        self.assertEqual({
            "local": "committed",
            "generation_id": "gen-" + "0" * 19 + "1-" + "a" * 32,
            "manifest_id": "f" * 64, "published_sha256": "a" * 64,
            "local_applied": True,
            "online": "disabled_no_send_authority",
        }, result)
        self.assertEqual(2, inspect.call_count)
        policy.assert_called_once_with("/synthetic/project")
        self.assertEqual("Switch Status", commit.call_args.kwargs["selected_panel"])
        self.assertEqual(("b" * 64, 2, "synthetic-boot", 1234),
                         commit.call_args.kwargs["manual_admission"])
        self.assertEqual("e" * 64,
                         commit.call_args.kwargs["expected_manual_preview"]
                         ["selected_decision_sha256"])
        with self.assertRaises(ManualPreviewHold):
            broker.confirm("nvis", "Switch Status", token,
                           confirmation="publish_local")

        with (mock.patch("monitor.issue_tracker_publish_runtime.inspect_stage_l",
                         return_value=qualified_status()),
              mock.patch("monitor.issue_tracker_publish_runtime.local_publish_interval",
                         return_value=(2, "b" * 64)),
              mock.patch("monitor.issue_tracker_publish_runtime.commit_qualified_prod_local",
                         return_value=ProdWorkbookNoop("no_candidates", None,
                                                       "c" * 64))):
            broker = make_protected_stage_l_broker(
                object(), http_root="/synthetic/http", project="/synthetic/project",
                publication="/synthetic/project/99-output-monitor",
                template_path="/synthetic/http/monitor/Issue_Tracker_Template_v1.xlsx",
                boot_id="synthetic-boot", monotonic_ns=lambda: 1234,
                clock=lambda: 1000.0,
            )
            token = broker.preview("nvis", "Switch Status")["token"]
            self.assertEqual({
                "local": "no_candidates", "manifest_id": "c" * 64,
                "local_applied": False,
                "online": "disabled_no_send_authority",
            }, broker.confirm("nvis", "Switch Status", token,
                              confirmation="publish_local"))

        malformed = CommittedProdWorkbook(
            SimpleNamespace(generation_id="gen-fixture"),
            SimpleNamespace(manifest_id="f" * 64, published_sha256="bad"),
            SimpleNamespace(),
        )
        with (mock.patch("monitor.issue_tracker_publish_runtime.inspect_stage_l",
                         return_value=qualified_status()),
              mock.patch("monitor.issue_tracker_publish_runtime.local_publish_interval",
                         return_value=(2, "b" * 64)),
              mock.patch("monitor.issue_tracker_publish_runtime.commit_qualified_prod_local",
                         return_value=malformed)):
            broker = make_protected_stage_l_broker(
                object(), http_root="/synthetic/http", project="/synthetic/project",
                publication="/synthetic/project/99-output-monitor",
                template_path="/synthetic/http/monitor/Issue_Tracker_Template_v1.xlsx",
                boot_id="synthetic-boot", monotonic_ns=lambda: 1234,
                clock=lambda: 1000.0,
            )
            token = broker.preview("nvis", "Switch Status")["token"]
            with self.assertRaises(RuntimeError):
                broker.confirm("nvis", "Switch Status", token,
                               confirmation="publish_local")
            with self.assertRaises(ManualPreviewHold):
                broker.confirm("nvis", "Switch Status", token,
                               confirmation="publish_local")

        with self.assertRaises(ManualPreviewHold):
            make_protected_stage_l_broker(
                object(), http_root="/synthetic/http", project="/synthetic/project",
                publication="/synthetic/project/99-output-monitor",
                template_path="/synthetic/http/monitor/Issue_Tracker_Template_v1.xlsx",
                boot_id="", monotonic_ns=lambda: 1234,
            )

    def test_protected_broker_rejects_non_c6_generation_identity(self):
        from monitor.issue_tracker_manual_preview import make_protected_stage_l_broker
        from monitor.issue_tracker_local_workbook_commit import CommittedProdWorkbook

        malformed = CommittedProdWorkbook(
            SimpleNamespace(generation_id="gen-fixture"),
            SimpleNamespace(manifest_id="f" * 64, published_sha256="a" * 64),
            SimpleNamespace(),
        )
        with (mock.patch("monitor.issue_tracker_publish_runtime.inspect_stage_l",
                         return_value=qualified_status()),
              mock.patch("monitor.issue_tracker_publish_runtime.local_publish_interval",
                         return_value=(2, "b" * 64)),
              mock.patch("monitor.issue_tracker_publish_runtime.commit_qualified_prod_local",
                         return_value=malformed)):
            broker = make_protected_stage_l_broker(
                object(), http_root="/synthetic/http", project="/synthetic/project",
                publication="/synthetic/project/99-output-monitor",
                template_path="/synthetic/http/monitor/Issue_Tracker_Template_v1.xlsx",
                boot_id="synthetic-boot", monotonic_ns=lambda: 1234,
                clock=lambda: 1000.0,
            )
            token = broker.preview("nvis", "Switch Status")["token"]
            with self.assertRaises(RuntimeError):
                broker.confirm("nvis", "Switch Status", token,
                               confirmation="publish_local")
            with self.assertRaises(ManualPreviewHold):
                broker.confirm("nvis", "Switch Status", token,
                               confirmation="publish_local")


if __name__ == "__main__":
    unittest.main()
