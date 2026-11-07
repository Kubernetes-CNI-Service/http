"""ZTP monitor binds a load parent's imported_configs declaration into its release identity.

DEV-side direct test for TEST 3e7f8c9's 12-ztp-monitor hunk.  In TEST that hunk is only
exercised by test_req23_import_workflow, which belongs to the later REQ23 merge wave; this
module states the same contract on load's real schema-2 parent without the import machinery.
The expected release ID is computed here from the parent's documented basis keys, not taken
from the monitor.
"""

import copy
import hashlib
import json
import unittest

from test_cases import test_load_release_transaction as release_fixture
from test_cases.module_loader import load_script


MONITOR = load_script(
    "monitor_imported_configs_parent_under_test",
    release_fixture.ROOT / "DAY0-Prepare/12-ztp-monitor.py",
)
LOAD = release_fixture.LOAD
SCHEMA2_BASIS = (
    "project", "deployment_scope", "switch_scope", "inputs",
    "input_sources", "dhcp_status", "components", "inventory",
)
DECLARATION = {"source_name": "20260101_000000", "sha256": "0" * 64}


def bound_release_id(parent: dict, keys: tuple[str, ...]) -> str:
    return hashlib.sha256(json.dumps(
        {key: parent[key] for key in keys}, ensure_ascii=False,
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()[:20]


class MonitorImportedConfigsParentDirectTests(unittest.TestCase):
    def setUp(self):
        self.release = release_fixture.ReleaseTransactionTests(
            "test_writes_parent_release_after_all_components_match"
        )
        self.release.setUp()
        self.project = self.release.project
        self.parent_path = self.project / "99-output-ztp/current-release.json"
        self.published = LOAD.validate_and_publish_release(
            self.project, self.release.inputs, publish=True,
        )

    def tearDown(self):
        self.release.tearDown()

    def write_parent(self, parent: dict) -> None:
        self.parent_path.write_text(
            json.dumps(parent, sort_keys=True) + "\n", encoding="utf-8",
        )

    def test_declaration_inside_release_id_is_accepted(self):
        parent = copy.deepcopy(self.published)
        self.assertNotIn("imported_configs", parent)
        parent["imported_configs"] = dict(DECLARATION)
        parent["release_id"] = bound_release_id(parent, SCHEMA2_BASIS + ("imported_configs",))
        self.write_parent(parent)
        identity = MONITOR.load_release_identity(self.project)
        self.assertEqual(parent["release_id"], identity["release_id"])

    def test_declaration_outside_release_id_is_rejected(self):
        parent = copy.deepcopy(self.published)
        parent["imported_configs"] = dict(DECLARATION)
        self.assertEqual(parent["release_id"], bound_release_id(parent, SCHEMA2_BASIS))
        self.write_parent(parent)
        with self.assertRaisesRegex(ValueError, "release_id 无效"):
            MONITOR.load_release_identity(self.project)

    def test_legacy_v1_parent_cannot_claim_imported_configs(self):
        parent = copy.deepcopy(self.published)
        parent["schema_version"] = 1
        parent.pop("dhcp_status")
        parent["imported_configs"] = dict(DECLARATION)
        parent["release_id"] = bound_release_id(
            parent, tuple(key for key in SCHEMA2_BASIS if key != "dhcp_status"),
        )
        self.write_parent(parent)
        with self.assertRaisesRegex(ValueError, "legacy v1 不允许 imported_configs"):
            MONITOR.load_release_identity(self.project)


if __name__ == "__main__":
    unittest.main()
