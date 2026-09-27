"""Two real production modules: qualification to canonical C-5 body, local only."""

import hashlib
import json
import unittest

from monitor.issue_tracker_qualification import qualify_stage_l
from monitor.issue_tracker_manifest import freeze_qualified_manifest
from test_cases.test_issue_tracker_qualification import (
    CABLING, SWITCH, EMPTY_WHITELIST_SHA, TOKEN_1, TOKEN_2, cycle,
)


class IssueTrackerManifestWorkflowTests(unittest.TestCase):
    def test_qualified_two_operation_intent_survives_one_item_local_projection(self):
        first = cycle(7, TOKEN_1, [SWITCH, CABLING])
        second = cycle(8, TOKEN_2, [CABLING, SWITCH])
        local_diff_projection = [CABLING]
        qualified = qualify_stage_l(
            [first, second], k=2, whitelist_rules=[],
            whitelist_sha256=EMPTY_WHITELIST_SHA,
            template_sha256="b" * 64,
        )
        body, manifest_id = freeze_qualified_manifest(
            qualified,
            metadata={
                "project_id": "site-a", "schema_version": 1,
                "producer_version": "1", "template_contract_version": "1",
                "template_sha256": "b" * 64,
            },
            expected_template_sha256="b" * 64,
        )
        parsed = json.loads(body)
        self.assertEqual([CABLING, SWITCH], parsed["operations"])
        self.assertEqual(1, len(local_diff_projection))
        self.assertEqual(2, len(parsed["operations"]))
        self.assertEqual(hashlib.sha256(body).hexdigest(), manifest_id)
        self.assertEqual(first["identity"]["cycle_id"], parsed["qualified_source"]["cycle_ids"][0])
        self.assertEqual(second["identity"]["cycle_id"], parsed["qualified_source"]["cycle_ids"][1])

    def test_unverified_runtime_source_cannot_reach_manifest(self):
        with self.assertRaises(ValueError):
            qualify_stage_l(
                [cycle(7, TOKEN_1, [CABLING], source_mode="runtime"), cycle(8, TOKEN_2, [CABLING])],
                k=2, whitelist_rules=[], whitelist_sha256=EMPTY_WHITELIST_SHA,
                template_sha256="b" * 64,
            )


if __name__ == "__main__":
    unittest.main()
