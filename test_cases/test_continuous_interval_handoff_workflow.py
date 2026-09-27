#!/usr/bin/env python3
"""Real-subprocess handoff for the canonical continuous interval floor."""

from __future__ import annotations

import json
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ContinuousIntervalHandoffWorkflowTests(unittest.TestCase):
    SCRIPT = r'''import json, runpy, sys
from pathlib import Path
root = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(root / "monitor"))
worker = runpy.run_path(str(root / "monitor/switch-collection-worker.py"))
import project_contract
test_value = "-".join(("fixed", "secret"))
collection_min = project_contract.MIN_CONTINUOUS_INTERVAL_MINUTES
collection_max = project_contract.MAX_CONTINUOUS_INTERVAL_MINUTES
backup_min = project_contract.MIN_CONTINUOUS_BACKUP_INTERVAL_MINUTES
backup_max = project_contract.MAX_CONTINUOUS_BACKUP_INTERVAL_MINUTES
checks = {}
for action in ("continuous_collection_start", "continuous_backup_start"):
    action_checks = {}
    for value in (
        collection_min - 1, collection_min,
        collection_max, collection_max + 1,
        backup_min - 1, backup_min, backup_max, backup_max + 1,
        True, float(collection_min), str(collection_min),
    ):
        message = {"action": action, "interval_minutes": value}
        if action == "continuous_backup_start":
            message["password"] = test_value
        try:
            decoded = worker["decode_yaml_backup_request"](
                json.dumps(message).encode("utf-8")
            )
            direct = worker["_validated_interval"](message, action)
            observed = [decoded["interval_minutes"], direct]
        except ValueError:
            observed = "rejected"
        action_checks[repr(value)] = observed
    checks[action] = action_checks
worker["configure_continuous_collection"]({
    "action": "continuous_collection_start", "interval_minutes": collection_min,
})
worker["configure_continuous_backup"]({
    "action": "continuous_backup_start", "password": test_value,
    "interval_minutes": backup_max,
})
state = worker["configure_continuous_collection"].__globals__
print(json.dumps({
    "authorities": {
        "collection_min": worker["MIN_CONTINUOUS_INTERVAL_MINUTES"],
        "collection_max": worker["MAX_CONTINUOUS_INTERVAL_MINUTES"],
        "backup_min": worker["MIN_CONTINUOUS_BACKUP_INTERVAL_MINUTES"],
        "backup_max": worker["MAX_CONTINUOUS_BACKUP_INTERVAL_MINUTES"],
    },
    "authority_file": str(Path(project_contract.__file__).resolve()),
    "checks": checks,
    "collection_seconds": state["_CONTINUOUS_COLLECTION_INTERVAL_SECONDS"],
    "backup_seconds": state["_CONTINUOUS_BACKUP_INTERVAL_SECONDS"],
}, sort_keys=True))
'''

    def make_layout(self, directory: str) -> Path:
        root = Path(directory)
        (root / "tools").mkdir()
        (root / "monitor").mkdir()
        shutil.copy2(
            ROOT / "tools/project_contract.py", root / "tools/project_contract.py",
        )
        for name in ("switch-collection-worker.py", "switch_collection_gate.py"):
            shutil.copy2(ROOT / "monitor" / name, root / "monitor" / name)
        return root

    def run_layout(self, root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-B", "-c", self.SCRIPT, str(root)],
            text=True, capture_output=True, timeout=30, check=False,
            env={"PYTHONDONTWRITEBYTECODE": "1"},
        )

    def test_real_worker_imports_exact_temp_authority_and_enforces_edges(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_layout(directory)
            result = self.run_layout(root)
            self.assertEqual(0, result.returncode, result.stderr)
            payload = json.loads(result.stdout)

        self.assertEqual({
            "collection_min": 10,
            "collection_max": 240,
            "backup_min": 60,
            "backup_max": 1440,
        }, payload["authorities"])
        self.assertEqual(
            str((root / "tools/project_contract.py").resolve()),
            payload["authority_file"],
        )
        collection = payload["checks"]["continuous_collection_start"]
        self.assertEqual("rejected", collection["9"])
        self.assertEqual([10, 10], collection["10"])
        self.assertEqual([240, 240], collection["240"])
        self.assertEqual("rejected", collection["241"])
        self.assertEqual("rejected", collection["1440"])
        backup = payload["checks"]["continuous_backup_start"]
        self.assertEqual("rejected", backup["59"])
        self.assertEqual([60, 60], backup["60"])
        self.assertEqual([1440, 1440], backup["1440"])
        self.assertEqual("rejected", backup["1441"])
        for action in ("continuous_collection_start", "continuous_backup_start"):
            checks = payload["checks"][action]
            self.assertEqual("rejected", checks["True"])
            self.assertEqual("rejected", checks["10.0"])
            self.assertEqual("rejected", checks["'10'"])
        self.assertEqual(10 * 60, payload["collection_seconds"])
        self.assertEqual(1440 * 60, payload["backup_seconds"])

    def test_temp_authority_change_to_fifteen_is_consumed_by_real_worker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_layout(directory)
            authority = root / "tools/project_contract.py"
            source = authority.read_text(encoding="utf-8")
            self.assertEqual(
                1, source.count("MIN_CONTINUOUS_INTERVAL_MINUTES = 10"),
            )
            authority.write_text(
                source.replace(
                    "MIN_CONTINUOUS_INTERVAL_MINUTES = 10",
                    "MIN_CONTINUOUS_INTERVAL_MINUTES = 15",
                    1,
                ),
                encoding="utf-8",
            )
            result = self.run_layout(root)
            self.assertEqual(0, result.returncode, result.stderr)
            payload = json.loads(result.stdout)

        self.assertEqual({
            "collection_min": 15,
            "collection_max": 240,
            "backup_min": 90,
            "backup_max": 1440,
        }, payload["authorities"])
        self.assertEqual("rejected", payload["checks"][
            "continuous_collection_start"
        ]["14"])
        self.assertEqual([15, 15], payload["checks"][
            "continuous_collection_start"
        ]["15"])
        self.assertEqual("rejected", payload["checks"][
            "continuous_backup_start"
        ]["89"])
        self.assertEqual([90, 90], payload["checks"][
            "continuous_backup_start"
        ]["90"])
        self.assertEqual(15 * 60, payload["collection_seconds"])

    def test_missing_or_incomplete_authority_fails_worker_import_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_layout(directory)
            (root / "tools/project_contract.py").unlink()
            missing = self.run_layout(root)
            self.assertNotEqual(0, missing.returncode)
            self.assertIn("project_contract", missing.stderr)

        with tempfile.TemporaryDirectory() as directory:
            root = self.make_layout(directory)
            (root / "tools/project_contract.py").write_text(
                "UNRELATED = 10\n", encoding="utf-8",
            )
            incomplete = self.run_layout(root)
            self.assertNotEqual(0, incomplete.returncode)
            self.assertRegex(
                incomplete.stderr,
                "(?:MIN_CONTINUOUS_INTERVAL_MINUTES|MAX_CONTINUOUS_INTERVAL_MINUTES)",
            )

    def test_real_environment_case_names_provenance_and_exact_edges(self):
        document = (ROOT / "test_cases/REAL_ENVIRONMENT.md").read_text(
            encoding="utf-8",
        )
        section = document.split(
            "## TC-REAL-SWITCH-CONTINUOUS-BACKUP-001", 1,
        )[1].split("\n## ", 1)[0]
        for expected in (
            "tools/project_contract.py",
            "MIN_CONTINUOUS_INTERVAL_MINUTES",
            "收集 9、10、240、241",
            "备份 59、60、1440、1441",
            "Native",
            "container",
        ):
            self.assertIn(expected, section)

    def test_cgi_and_rendered_controls_share_action_specific_authority(self):
        cgi = runpy.run_path(str(ROOT / "monitor/switch-collection-control.cgi"))
        validate = cgi["validate_continuous_interval"]
        for action, accepted, rejected in (
            ("continuous_collection_start", ("10", "240"), ("9", "241", "1440")),
            ("continuous_backup_start", ("60", "1440"), ("10", "59", "1441")),
        ):
            for value in accepted:
                with self.subTest(action=action, value=value):
                    self.assertEqual(int(value), validate(value, action))
            for value in rejected:
                with self.subTest(action=action, value=value), self.assertRaises(ValueError):
                    validate(value, action)

        generator = (ROOT / "monitor/generate-monitor-html.py").read_text(
            encoding="utf-8"
        )
        for name in (
            "MIN_CONTINUOUS_INTERVAL_MINUTES",
            "MAX_CONTINUOUS_INTERVAL_MINUTES",
            "MIN_CONTINUOUS_BACKUP_INTERVAL_MINUTES",
            "MAX_CONTINUOUS_BACKUP_INTERVAL_MINUTES",
        ):
            self.assertIn(name, generator)
        self.assertIn("intervalNode?.min", generator)
        self.assertIn("intervalNode?.max", generator)
        self.assertNotIn("interval < 10 || interval > 1440", generator)


if __name__ == "__main__":
    unittest.main()
