#!/usr/bin/env python3
"""Real-subprocess handoff for the canonical continuous interval floor."""

from __future__ import annotations

import json
from pathlib import Path
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
authority = project_contract.MIN_CONTINUOUS_INTERVAL_MINUTES
checks = {}
for action in ("continuous_collection_start", "continuous_backup_start"):
    action_checks = {}
    for value in (
        9, 10, authority - 1, authority, 1440, 1441,
        True, float(authority), str(authority),
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
    "action": "continuous_collection_start", "interval_minutes": authority,
})
worker["configure_continuous_backup"]({
    "action": "continuous_backup_start", "password": test_value,
    "interval_minutes": 1440,
})
state = worker["configure_continuous_collection"].__globals__
print(json.dumps({
    "authority": worker["MIN_CONTINUOUS_INTERVAL_MINUTES"],
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

        self.assertEqual(10, payload["authority"])
        self.assertEqual(
            str((root / "tools/project_contract.py").resolve()),
            payload["authority_file"],
        )
        for action in (
            "continuous_collection_start", "continuous_backup_start",
        ):
            checks = payload["checks"][action]
            self.assertEqual("rejected", checks["9"])
            self.assertEqual([10, 10], checks["10"])
            self.assertEqual([1440, 1440], checks["1440"])
            self.assertEqual("rejected", checks["1441"])
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

        self.assertEqual(15, payload["authority"])
        self.assertEqual("rejected", payload["checks"][
            "continuous_collection_start"
        ]["10"])
        self.assertEqual("rejected", payload["checks"][
            "continuous_collection_start"
        ]["14"])
        self.assertEqual([15, 15], payload["checks"][
            "continuous_collection_start"
        ]["15"])
        self.assertEqual("rejected", payload["checks"][
            "continuous_backup_start"
        ]["10"])
        self.assertEqual("rejected", payload["checks"][
            "continuous_backup_start"
        ]["14"])
        self.assertEqual([15, 15], payload["checks"][
            "continuous_backup_start"
        ]["15"])
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
            self.assertIn("MIN_CONTINUOUS_INTERVAL_MINUTES", incomplete.stderr)

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
            "9、10、1440、1441",
            "Native",
            "container",
        ):
            self.assertIn(expected, section)


if __name__ == "__main__":
    unittest.main()
