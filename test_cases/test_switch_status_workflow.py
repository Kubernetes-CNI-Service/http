"""Workflow: cron.sh -> ufm-info.sh archive -> monitor/issue-tracker/switch-status.py (owner 2026-10-23).

The real cron.sh collects the UFMs through the staged harness of test_ufm_monitor_cron_workflow (fake SSH,
fake UFM commands). It must call switch-status.py after the page refresh and before the REQ7 sync, once per
device type, with this run's exact archive (or --no-archive) and the devices it planned. The archive and the
planned list it passed then go through the real switch-status.py and the real page parser.
"""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

from test_cases.test_ufm_monitor_cron_workflow import UFMS, UfmCronCase

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "monitor/issue-tracker/switch-status.py"


class SwitchStatusCronWorkflowTest(UfmCronCase):
    def setUp(self):
        super().setUp()
        # a stand-in at the published path: records each call and keeps a copy of the planned list,
        # which cron.sh deletes when it exits
        self.calls_log = self.root / "switch-status.jsonl"
        self.write_exec(self.mkdir("monitor/issue-tracker") / "switch-status.py",
                        "import json, shutil, sys\n"
                        "args = sys.argv[1:]\n"
                        "planned = args[args.index('--planned') + 1]\n"
                        f"copy = {str(self.root)!r} + '/planned-' + args[args.index('--type') + 1]\n"
                        "shutil.copy(planned, copy)\n"
                        f"open({str(self.calls_log)!r}, 'a').write(json.dumps(args) + '\\n')\n"
                        f"open({str(self.order)!r}, 'a').write('switch-status\\n')\n"
                        "print('[SWITCH-STATUS] stand-in called')\n")

    def status_calls(self):
        return [json.loads(line) for line in self.calls_log.read_text().splitlines()]

    def real(self, *args):
        result = subprocess.run([sys.executable, "-B", str(SCRIPT), "--project-dir", str(self.project), *args],
                                capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        path = self.project / "99-output-monitor/infiniband/issue-tracker/ufm-switch-status.json"
        return json.loads(path.read_text(encoding="utf-8"))

    def test_cron_hands_this_runs_ufm_archive_and_candidates_to_the_switch_status(self):
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = {call[call.index("--type") + 1]: call for call in self.status_calls()}
        self.assertEqual(sorted(calls), ["eth", "ib", "nvl", "ufm"])
        archive = self.archives()[0]
        self.assertEqual(Path(calls["ufm"][calls["ufm"].index("--archive") + 1]).resolve(), archive.resolve(),
                         "this run's exact ufm-info archive (through setup's data link), never a discovered latest")
        for kind in ("eth", "ib", "nvl"):
            self.assertIn("--no-archive", calls[kind], "nothing of that type was collected in this run")
        self.assertEqual(sorted(line.split("|", 1)[0] for line in
                                (self.root / "planned-ufm").read_text().splitlines()), sorted(UFMS))
        order = self.order.read_text().splitlines()
        self.assertLess(order.index("generate"), order.index("switch-status"), "after the page refresh")
        self.assertIn("[SWITCH-STATUS] stand-in called", result.stdout, "its lines reach the cron log")

        document = self.real("--type", "ufm", "--archive", str(archive),
                             "--planned", str(self.root / "planned-ufm"))
        self.assertEqual((document["expected"], document["collected"]), (2, 2))
        self.assertEqual(document["source"]["archive"], archive.name)
        for row in document["rows"]:
            self.assertIn(row["Host Name"], UFMS)
            self.assertEqual((row["Submitor"], row["Status"], row["Fabric"]), ("CVT", "New", "Compute"))
            self.assertNotIn("Not collected", row["Issue Description"])

    def test_a_ufm_that_returned_nothing_is_reported_not_collected(self):
        self.state["down"] = [UFMS["ufm02.example.test"][0]]
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        call = [call for call in self.status_calls() if call[call.index("--type") + 1] == "ufm"][0]
        archive = call[call.index("--archive") + 1]
        document = self.real("--type", "ufm", "--archive", archive, "--planned", str(self.root / "planned-ufm"))
        self.assertEqual((document["expected"], document["collected"]), (2, 1))
        rows = {row["Host Name"]: row for row in document["rows"]}
        self.assertIn("Not collected", rows["ufm02.example.test"]["Issue Description"])
        self.assertEqual(rows["ufm02.example.test"]["Priority"], "High")
        self.assertEqual(rows["ufm02.example.test"]["OOB IP"], UFMS["ufm02.example.test"][0])

    def test_a_missing_switch_status_script_is_only_a_warning(self):
        (self.root / "monitor/issue-tracker/switch-status.py").unlink()
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("[SWITCH-STATUS] WARNING: missing", result.stdout)


if __name__ == "__main__":
    unittest.main()
