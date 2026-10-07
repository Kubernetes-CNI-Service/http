"""Actual project policy -> exact C-2 target binding; fake-only, no send."""

import copy
import importlib
import importlib.util
import json
import unittest
from unittest import mock

from tools.project_contract import normalize_issue_tracker_policy
from test_cases.test_issue_tracker_online_target import TARGET, OTHER, document


class OnlineTargetPolicyWorkflowTests(unittest.TestCase):
    def setUp(self):
        name = "monitor.issue_tracker_online_target"
        self.assertIsNotNone(importlib.util.find_spec(name), "C-2 target loader is missing")
        self.module = importlib.import_module(name)

    def test_real_policy_validator_is_consumed_on_every_target_revalidation(self):
        config = document(cycles=3)
        before = copy.deepcopy(config)
        listing = self.module.freeze_target_allowlist(json.dumps([TARGET, OTHER]).encode())
        with mock.patch("tools.project_contract.normalize_issue_tracker_policy",
                        wraps=normalize_issue_tracker_policy) as validator:
            bound = self.module.bind_online_target(config, listing)
            self.assertEqual(TARGET, bound.spreadsheet_id)
            self.assertEqual(bound, self.module.bind_online_target(config, listing, expected=bound))
            config["common"]["mgmt"]["issue-tracker"]["spreadsheet_id"] = OTHER
            with self.assertRaises(self.module.OnlineTargetHold) as caught:
                self.module.bind_online_target(config, listing, expected=bound)
        self.assertEqual("stale_target_binding", caught.exception.reason)
        self.assertEqual(3, validator.call_count)
        config["common"]["mgmt"]["issue-tracker"]["spreadsheet_id"] = TARGET
        self.assertEqual(before, config)

    def test_enabled_schema_cannot_create_a_target_enumeration(self):
        config = document()
        self.assertEqual(TARGET, normalize_issue_tracker_policy(config)["spreadsheet_id"])
        for raw in (b"[]", json.dumps([OTHER]).encode()):
            listing = self.module.freeze_target_allowlist(raw)
            with self.assertRaises(self.module.OnlineTargetHold):
                self.module.bind_online_target(config, listing)
        config["schema_version"] = 1
        listing = self.module.freeze_target_allowlist(json.dumps([TARGET]).encode())
        with self.assertRaises(self.module.OnlineTargetHold) as caught:
            self.module.bind_online_target(config, listing)
        self.assertEqual("invalid_online_policy", caught.exception.reason)


if __name__ == "__main__":
    unittest.main()
