"""Workflow: cron.sh -> ufm-info.sh archive -> monitor/issue-tracker/switch-status.py (owner 2026-10-23).

The real cron.sh collects the UFMs through the staged harness of test_ufm_monitor_cron_workflow (fake SSH,
fake UFM commands). It must call switch-status.py after the page refresh and before the REQ7 sync, once per
device type, with this run's exact archive (or --no-archive) and the devices it planned. The archive and the
planned list it passed then go through the real switch-status.py and the real page parser.
"""
from __future__ import annotations

import json
import re
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
        # the fake UFM's systemctl never answers "active" and there is no HA state yet (VIP unanswered)
        self.assertEqual({row["Host Name"]: (row["Priority"], row["Issue Description"]) for row in document["rows"]},
                         {name: ("Medium", "UFM service ufm-enterprise: not active") for name in UFMS})
        for row in document["rows"]:
            self.assertEqual((row["Submitor"], row["Status"], row["Fabric"]), ("CVT", "New", "Compute"))
            self.assertEqual(row["OOB IP"], UFMS[row["Host Name"]][0])

    def test_when_every_ufm_is_unreachable_both_are_reported_not_collected(self):
        self.state["down"] = [ip for ip, _mac in UFMS.values()]
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.archives(), [], "nothing was collected")
        call = [call for call in self.status_calls() if call[call.index("--type") + 1] == "ufm"][0]
        self.assertIn("--no-archive", call)
        document = self.real("--type", "ufm", "--no-archive", "--planned", str(self.root / "planned-ufm"))
        self.assertEqual((document["expected"], document["collected"]), (2, 0))
        self.assertEqual({row["Host Name"] for row in document["rows"]}, set(UFMS))
        self.assertTrue(all(row["Issue Description"].startswith("Not collected") for row in document["rows"]))

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


class CronWiringTest(unittest.TestCase):
    """The switch-status call in cron.sh: production only, after the page, before the REQ7 sync, and each type
    reads the archive its own collector published in this run."""

    def setUp(self):
        self.source = (ROOT / "ethernet/monitor/cron.sh").read_text(encoding="utf-8")

    def function(self, name):
        match = re.search(rf"^{name}\(\) \{{\n(.*?)^\}}", self.source, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(match, name)
        return match.group(1)

    def test_each_collector_publishes_the_archive_its_type_is_given(self):
        calls = dict(re.findall(r'^\s*(?:\[\[[^\]]*\]\] && )?switch_status (\w+) "\$(\w+)"', self.source, re.MULTILINE))
        self.assertEqual(calls, {"eth": "ETH_ARCHIVE", "ib": "IB_INFO_ARCHIVE", "nvl": "NV_INFO_ARCHIVE",
                                 "ufm": "UFM_INFO_ARCHIVE"})
        for collector, variable in (("collect_eth_info", "ETH_ARCHIVE"), ("collect_ib_info", "IB_INFO_ARCHIVE"),
                                    ("collect_nv_info", "NV_INFO_ARCHIVE"), ("ufm_info_fetch", "UFM_INFO_ARCHIVE")):
            with self.subTest(collector=collector):
                body = self.function(collector)
                published = body.index('archive_collection_dir')
                assigned = re.search(rf"^\s*{variable}=", body, re.MULTILINE)
                self.assertIsNotNone(assigned, f"{collector} never sets {variable}")
                self.assertGreater(assigned.start(), published, "set only once the archive is published")
                self.assertEqual(len(re.findall(rf"^\s*{variable}=", self.source, re.MULTILINE)), 2,
                                 f"{variable}: declared empty once, set by {collector} only")

    def test_production_only_after_the_page_and_before_the_sync(self):
        block = re.search(r'^if \[\[ "\$\{COLLECTION_ENV:-prod\}" == prod \]\]; then\n((?:    .*\n)+?)fi\n',
                          self.source[self.source.index("switch_status() {"):], re.MULTILINE)
        self.assertIsNotNone(block)
        self.assertEqual(block.group(1).count("switch_status "), 4)
        start = self.source.index("switch_status() {")
        self.assertLess(self.source.index('python3 "$HTML_GENERATOR"'), start)
        self.assertLess(start, self.source.index("ISSUE_TRACKER_SYNC="))
        self.assertIn('[[ -s "$UFM_CANDIDATES" ]] && switch_status ufm', block.group(1),
                      "every planned UFM, also when key preparation failed on all of them")


if __name__ == "__main__":
    unittest.main()
