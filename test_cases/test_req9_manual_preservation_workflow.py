"""REQ9: real manual updater must preserve historical hand-maintained chapters.

The body expectations below were fixed from the first checked-in HTML manual at
991a644. They are not calculated from the current manual or updater output.
"""

from __future__ import annotations

from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MANUAL = ROOT / "user-manual.html"
UPDATER = ROOT / "tools/update-user-manual.py"
LOAD = ROOT / "DAY0-Prepare/11-load.py"

# Stable chapter IDs plus substantive operating/risk/recovery text from 991a644.
HISTORICAL_BODY = {
    "v1-workflow": "每个箭头都是失败边界：前一步没有明确成功就不得执行下一步。",
    "v1-scenario-update": "备份未通过时不 unload；保留现场等待重试。",
    "v2-overview": "Docker 尚无成功的端到端部署证据，不能作为已支持生产流程",
    "v3-dev-import": "同一 record ID 的不同内容必须拒绝；相同 bundle 重导入只能幂等确认",
}


def assert_historical_body(test: unittest.TestCase, manual: str) -> None:
    for chapter, body in HISTORICAL_BODY.items():
        match = re.search(
            rf'<section id="{re.escape(chapter)}" data-chapter>(.*?)</section>',
            manual,
            flags=re.DOTALL,
        )
        test.assertIsNotNone(match, chapter)
        test.assertIn(body, match.group(1), chapter)


class Req9ManualPreservationWorkflowTests(unittest.TestCase):
    def fixture(self, directory: str) -> Path:
        root = Path(directory) / "repository"
        for source, relative in (
            (MANUAL, "user-manual.html"),
            (UPDATER, "tools/update-user-manual.py"),
            (LOAD, "DAY0-Prepare/11-load.py"),
        ):
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run(
            ["git", "add", "user-manual.html", "tools/update-user-manual.py",
             "DAY0-Prepare/11-load.py"],
            cwd=root, check=True, capture_output=True,
        )
        return root

    def run_updater(self, root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-B", str(root / "tools/update-user-manual.py"), *arguments],
            cwd=root, text=True, capture_output=True, timeout=30,
        )

    def test_real_updater_preserves_v1_v2_v3_body_while_refreshing_real_load_entry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            manual = root / "user-manual.html"
            before = manual.read_text(encoding="utf-8")
            assert_historical_body(self, before)

            first = self.run_updater(root)
            self.assertEqual(0, first.returncode, first.stderr)
            after = manual.read_text(encoding="utf-8")
            assert_historical_body(self, after)
            self.assertIn('data-script-reference="DAY0-Prepare/11-load.py"', after)
            self.assertIn("--host-role=workstation", after)
            self.assertNotEqual(before, after, "the real catalog must have refreshed")

            check = self.run_updater(root, "--check")
            self.assertEqual(0, check.returncode, check.stdout + check.stderr)
            self.assertEqual(after, manual.read_text(encoding="utf-8"))

    def test_oracle_rejects_a_removed_old_recovery_paragraph_after_real_update(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            manual = root / "user-manual.html"
            before = manual.read_text(encoding="utf-8")
            old = HISTORICAL_BODY["v1-scenario-update"]
            self.assertEqual(1, before.count(old))
            manual.write_text(before.replace(old, ""), encoding="utf-8")

            result = self.run_updater(root)
            self.assertEqual(0, result.returncode, result.stderr)
            with self.assertRaises(AssertionError):
                assert_historical_body(self, manual.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
