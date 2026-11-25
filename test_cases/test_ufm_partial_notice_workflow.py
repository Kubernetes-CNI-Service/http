"""Workflow (I-065): a usable ibdiagnet run that timed out stays ok and its notice reaches every consumer.

The real cron.sh runs the real ufm-ibdiagnet.sh on the VIP holder through the staged harness of
test_ufm_monitor_cron_workflow (fake SSH/SCP; a fake docker stands in for the vendor tool); the real
infiniband/monitor/post-collect.py writes the receipt and cron.sh the run record. The real page reader
(monitor/generate-monitor-html.py) and the real local sync (monitor/issue-tracker/issue-tracker-sync.py,
--convert-only, never online) then read this run's exact files. Narrow stand-ins only for the vendor tool,
SSH, the offline analyzer (a fixed workbook with real provenance) and the offline CVT converter.
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import re
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import xlsxwriter

from test_cases.test_ufm_monitor_cron_workflow import UFMS, VIP, UfmCronCase

ROOT = Path(__file__).resolve().parents[1]
# I-065 fixed expectations (Q-056, http dev material section 6 C1 :296-297)
PARTIAL_NOTICE = "ibdiagnet timed out after 900s; partial output"
PAGE_SUFFIX = "（超时，部分结果）"
HOLDER = UFMS["ufm02.example.test"][0]   # ufm02 holds the VIP

# The offline analyzer: a fixed workbook as the report, with the provenance the real one writes.
ANALYZER = r"""import hashlib, json, os, shutil, sys
args = sys.argv[1:]
def identity(path):
    real = os.path.realpath(path)
    return {"path": os.path.abspath(path), "resolved_path": real, "kind": "file",
            "sha256": hashlib.sha256(open(real, "rb").read()).hexdigest()}
output = args[args.index("--output") + 1]
shutil.copyfile(WORKBOOK, output)
json.dump({"schema": "ib-report-provenance-v1", "report": identity(output),
           "cvt": identity(args[args.index("--p2p") + 1]), "actual": identity(args[1])},
          open(output + ".provenance.json", "w"))
"""

# The offline CVT converter of the sync: an empty circuit list in the engine's source format.
CONVERTER = r"""import json, sys
argv = sys.argv
open(argv[argv.index("--output") + 1], "w").write(json.dumps({"row_count": 0, "rows": []}))
open(argv[argv.index("--summary-output") + 1], "w").write(json.dumps({"records": 0}))
"""


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module   # dataclasses resolve string annotations through sys.modules
    sys.path.insert(0, str(path.parent))   # the page imports its sibling dot_to_html, as when it runs
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


class UfmPartialNoticeWorkflowTest(UfmCronCase):
    def setUp(self):
        super().setUp()
        workbook = self.root / "fixture-report.xlsx"
        book = xlsxwriter.Workbook(str(workbook))
        book.add_worksheet("Summary").write(0, 0, "Item")
        book.close()
        (self.root / "tools/ibdiagnet-analyze-tool/analyze.py").write_text(
            f"WORKBOOK = {str(workbook)!r}\n" + ANALYZER, encoding="utf-8")
        self.state["vip"] = {VIP: HOLDER}
        self.page = load("ufm_partial_notice_page", ROOT / "monitor/generate-monitor-html.py")
        self.sync = load("ufm_partial_notice_sync", ROOT / "monitor/issue-tracker/issue-tracker-sync.py")
        converter = self.root / "fake_generate_report.py"
        converter.write_text(CONVERTER, encoding="utf-8")
        patcher = mock.patch.object(self.sync, "GENERATE_REPORT", converter)
        patcher.start()
        self.addCleanup(patcher.stop)

    def collect(self, rc, **env):
        result = self.run_cron(FAKE_IBDIAGNET_RC=rc, **env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def latest_record(self):
        paths = sorted(self.ibdiag_output.glob("*.ufm-run.json"), key=lambda path: path.stat().st_mtime_ns)
        return json.loads(paths[-1].read_text(encoding="utf-8"))

    def failures(self):
        text = (self.ibdiag_output / ".ibdiagnet-state").read_text(encoding="utf-8")
        return int(re.search(r"^failures=(\d+)$", text, re.M).group(1))

    def page_view(self):
        tab = self.page.load_topology_validation(self.p2p_output, "infiniband", "prod")
        return tab.get("collection", ""), self.page.render_topology_panel(tab, "itop", "InfiniBand")

    def local_sync(self):
        stream = io.StringIO()
        with redirect_stdout(stream):
            code = self.sync.main(["--project-dir", str(self.project), "--convert-only"])
        self.assertEqual(0, code, stream.getvalue())
        return stream.getvalue()

    def sync_log(self):
        return (self.project / "99-output-monitor/issue-tracker-sync.log").read_text(encoding="utf-8")

    def assert_chain(self, rc, notice):
        result = self.collect(rc)
        record = self.latest_record()
        run_id = record["run_id"]
        # done -> run record: ok, the vendor rc, the exact reason, no failure counted, no UFM warning
        self.assertEqual((record["outcome"], record["reason"], record["analysis"]), ("ok", notice, "ok"))
        self.assertEqual((record["ibdiagnet_failures_in_a_row"], self.failures()), (0, 0))
        done_path = self.ibdiag_output / record["done"]["name"]
        done = dict(line.split("=", 1) for line in done_path.read_text(encoding="utf-8").splitlines() if "=" in line)
        self.assertEqual((done["result"], done["rc"], done["reason"], done["run_id"]), ("ok", rc, notice, run_id))
        self.assertNotIn("UFM warnings", result.stdout)
        self.assertIn("cron finish ==========", result.stdout)
        # done -> receipt: the collector metadata of this exact .done
        receipt = json.loads((self.p2p_output / record["receipt"]["name"]).read_text(encoding="utf-8"))
        self.assertEqual((receipt["run_id"], receipt["collector"]["rc"], receipt["collector"]["reason"]),
                         (run_id, rc, notice))
        self.assertEqual(receipt["done"]["sha256"], hashlib.sha256(done_path.read_bytes()).hexdigest())
        self.assertEqual(receipt["done"]["sha256"], record["done"]["sha256"])
        # receipt -> IB Link Validation page
        collection, html = self.page_view()
        original = f"UFM ufm02 · ibdiagnet · run-id {run_id}"
        line = f"[IB] {PARTIAL_NOTICE} (run-id {run_id})"
        text = self.local_sync()
        if notice:
            self.assertEqual(original + PAGE_SUFFIX, collection)
            self.assertIn(f'<span class="i-warn">{PAGE_SUFFIX}</span>', html)
            # done -> local sync log, bound to the selected input of this run
            self.assertIn(line, text)
            self.assertIn(line, self.sync_log())
        else:
            self.assertEqual(original, collection)
            self.assertNotIn(PAGE_SUFFIX, html)
            self.assertNotIn("partial output", text)
        self.assertIn("IB: wrote ib-cvt.json (no sync: --convert-only)", text)

    def test_rc124_with_usable_output_carries_the_notice_to_every_consumer(self):
        self.assert_chain("124", PARTIAL_NOTICE)

    def test_rc137_with_usable_output_carries_the_notice_to_every_consumer(self):
        self.assert_chain("137", PARTIAL_NOTICE)

    def test_rc1_with_usable_output_stays_the_original_plain_success(self):
        self.assert_chain("1", "")

    def test_rc0_is_a_normal_success_without_a_notice(self):
        self.assert_chain("0", "")

    def test_no_new_dump_and_a_failed_archive_still_fail_without_a_notice(self):
        # I-065 8.2 item 2: no output of this run, or an archive that could not be made, stays a failure.
        result = self.run_cron(FAKE_IBDIAGNET_RC="124", FAKE_IBDIAGNET_NO_NET_DUMP="1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = self.latest_record()
        self.assertEqual((record["outcome"], record["input"], record["receipt"]), ("failed", None, None))
        self.assertNotIn("partial output", record["reason"])
        self.assertEqual(self.failures(), 1)
        self.assertIn("cron finish with UFM warnings", result.stdout)
        shared = self.mkdir(f"hosts/{HOLDER}/container/opt/ufm/files")
        shared.chmod(0o500)   # packing inside the container cannot write its archive
        try:
            result = self.run_cron(FAKE_IBDIAGNET_RC="124")
        finally:
            shared.chmod(0o700)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = self.latest_record()
        self.assertEqual((record["outcome"], record["input"], record["receipt"]), ("failed", None, None))
        self.assertNotIn("partial output", record["reason"])
        self.assertEqual(self.failures(), 2)
        self.assertEqual(self.ibdiag_archives(), [])
        collection, html = self.page_view()
        self.assertEqual("", collection)
        text = self.local_sync()
        self.assertIn("IB: no prod ibdiagnet2.tgz", text)
        self.assertNotIn("partial output", text)

    def test_a_later_run_never_borrows_an_earlier_runs_notice(self):
        # I-065 8.2 item 5: the notice belongs to the selected input only, never to the round before it.
        self.collect("124")
        first = self.latest_record()["run_id"]
        self.collect("0")
        record = self.latest_record()
        self.assertNotEqual(first, record["run_id"])
        self.assertEqual((record["outcome"], record["reason"]), ("ok", ""))
        collection, html = self.page_view()
        self.assertEqual(f"UFM ufm02 · ibdiagnet · run-id {record['run_id']}", collection)
        self.assertNotIn(PAGE_SUFFIX, html)
        text = self.local_sync()
        self.assertNotIn("partial output", text)
        self.assertIn(f"IB: converting {record['run_id']}_ufm02_ibdiagnet2.tgz", text)


if __name__ == "__main__":
    unittest.main()
