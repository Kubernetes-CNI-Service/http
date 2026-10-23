"""IB closed loop, modelled on Ethernet's post-collect.py (owner 2026-10-21: "参考 eth 来做 ib").

The exact ibdiagnet archive that cron.sh fetched from the UFM in this run is analysed against the
project's CVT and published to 99-output-p2p, where the IB Link Validation tab reads it
(infiniband/monitor/UFM-MONITOR.md section 13)."""

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import xlsxwriter

from test_cases.test_ib_analysis_domain import write_ibdiagnet_fixture
from test_cases.test_project_contracts import load_module

ROOT = Path(__file__).resolve().parents[1]
POST_COLLECT = ROOT / "infiniband/monitor/post-collect.py"
RUN_ID = "20261021-0300-prod-0123456789abcdef"

# Records its argv and writes the --output workbook with the provenance beside it, like the real
# analyzer on success (ztp/config/ib_topology_provenance.py::write_report_provenance).
FAKE_ANALYZER = r"""import hashlib, json, os, sys
args = sys.argv[1:]
def identity(path):
    real = os.path.realpath(path)
    return {"path": os.path.abspath(path), "resolved_path": real, "kind": "file",
            "sha256": hashlib.sha256(open(real, "rb").read()).hexdigest()}
option = "--iblinkinfo" if "--iblinkinfo" in args else "--ibdiagnet"
actual = args[args.index(option) + 1]
with open(os.environ["FAKE_ANALYZER_LOG"], "a") as log:
    text = open(actual).read() if option == "--iblinkinfo" else ""
    log.write(json.dumps({"argv": args, "iblinkinfo_text": text}) + "\n")
if os.environ.get("FAKE_ANALYZER_RC"):
    sys.exit("ERROR: fixture analyzer failure")
if not os.environ.get("FAKE_ANALYZER_NO_REPORT"):
    output = args[args.index("--output") + 1]
    open(output, "wb").write(b"PK fixture workbook")
    if not os.environ.get("FAKE_ANALYZER_NO_PROVENANCE"):
        record = {"schema": "ib-report-provenance-v1", "report": identity(output),
                  "cvt": identity(args[args.index("--p2p") + 1]), "actual": identity(actual)}
        if os.environ.get("FAKE_ANALYZER_OTHER_INPUT"):   # a report written for another run's input
            record["actual"]["sha256"] = "0" * 64
        open(output + ".provenance.json", "w").write(json.dumps(record))
"""


def load_post_collect():
    spec = importlib.util.spec_from_file_location("ib_post_collect_under_test", POST_COLLECT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ibdiagnet_archive(directory: Path, name: str) -> Path:
    """The UFM's archive as ufm-ibdiagnet.sh builds it: members under ibdiagnet2/."""
    snapshot = directory / "snapshot" / "ibdiagnet2"
    snapshot.mkdir(parents=True)
    write_ibdiagnet_fixture(snapshot)
    archive = directory / name
    with tarfile.open(archive, "w:gz") as bundle:
        bundle.add(snapshot, arcname="ibdiagnet2")
    return archive


class IbPostCollectDirectTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.module = load_post_collect()
        self.project = self.root / "project"
        self.output = self.project / "99-output-p2p"
        self.output.mkdir(parents=True)
        (self.project / "fabric-blue.xlsx").write_bytes(b"p2p")
        (self.project / "p2p.xlsx").symlink_to("fabric-blue.xlsx")
        self.cvt = self.output / "fabric-blue-cvt.xlsx"
        self.cvt.write_bytes(b"cvt")
        self.data = self.root / "ufm-ibdiagnet"
        self.data.mkdir()
        analyzer = self.root / "analyze.py"
        analyzer.write_text(FAKE_ANALYZER, encoding="utf-8")
        self.calls = self.root / "analyzer.jsonl"
        for name, value in (("ANALYZER", analyzer), ("OUTPUT_DIR", self.root / "tool-link"),
                            ("ARCHIVE_DIR", self.data)):
            patcher = mock.patch.object(self.module, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        (self.root / "tool-link").symlink_to(self.output)   # the setup-managed 99-output-p2p link
        self.env = mock.patch.dict(os.environ, {"FAKE_ANALYZER_LOG": str(self.calls)})
        self.env.start()
        self.addCleanup(self.env.stop)

    def tearDown(self):
        self.tmp.cleanup()

    def archive(self, name=f"{RUN_ID}_ufm01_ibdiagnet2.tgz", done="rc=0\nreason=\nhostname=ufm01.example.test\n"):
        """What cron.sh keeps: the fetched file and the UFM's .done record beside it."""
        path = self.data / name
        if name.endswith(".log"):
            path.write_text("Switch: 0x0200000000000001 MF0;leaf01:Q3400/U1:\n", encoding="utf-8")
        else:
            path.write_bytes(b"\x1f\x8b fixture ibdiagnet archive")
        if done is not None and "_" in name:
            path.with_name(name.rsplit(".", 1)[0] + ".done").write_text(done, encoding="utf-8")
        return path

    def call(self):
        return [json.loads(line) for line in self.calls.read_text().splitlines()][-1]

    def receipt(self, stem, kind):
        return json.loads((self.output / f"{stem}-{kind}-topology-validation.receipt.json").read_text())

    def test_the_exact_ibdiagnet_archive_is_analysed_against_the_project_cvt(self):
        archive = self.archive()
        self.assertEqual(0, self.module.main(["--archive", str(archive)]))
        argv = self.call()["argv"]
        report = self.output / f"{RUN_ID}_ufm01-ibdiagnet-topology-validation.xlsx"
        self.assertEqual(["--ibdiagnet", str(archive), "--p2p", str(self.cvt.resolve()),
                          "--output", str(report.resolve())], argv)
        self.assertTrue(report.is_file())
        # Owner 2026-10-22: a receipt says which run, which UFM, and whether iblinkinfo stood in.
        receipt = self.receipt(f"{RUN_ID}_ufm01", "ibdiagnet")
        self.assertEqual((receipt["schema"], receipt["run_id"], receipt["node"], receipt["kind"], receipt["degraded"]),
                         ("ufm-ib-report-receipt-v1", RUN_ID, "ufm01", "ibdiagnet", False))
        self.assertEqual(receipt["collector"], {"rc": "0", "reason": "", "hostname": "ufm01.example.test"})
        for key, path in (("input", archive), ("cvt", self.cvt), ("report", report),
                          ("provenance", report.with_name(report.name + ".provenance.json"))):
            self.assertEqual(receipt[key], {"name": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()},
                             key)

    def test_an_iblinkinfo_log_is_analysed_as_it_is_and_marked_degraded(self):
        log = self.archive(f"{RUN_ID}_ufm02_iblinkinfo.log")
        self.assertEqual(0, self.module.main(["--archive", str(log)]))
        call = self.call()
        self.assertEqual(["--iblinkinfo", str(log)], call["argv"][:2], "stdout-only log, no unpacking")
        self.assertIn("leaf01", call["iblinkinfo_text"])
        self.assertTrue((self.output / f"{RUN_ID}_ufm02-iblinkinfo-topology-validation.xlsx").is_file())
        receipt = self.receipt(f"{RUN_ID}_ufm02", "iblinkinfo")
        self.assertEqual((receipt["kind"], receipt["node"], receipt["degraded"]), ("iblinkinfo", "ufm02", True))

    def test_the_cvt_of_the_current_p2p_wins_and_ambiguity_fails_closed(self):
        (self.output / "other-cvt.xlsx").write_bytes(b"cvt")
        self.assertEqual(0, self.module.main(["--archive", str(self.archive())]))
        self.assertEqual(str(self.cvt.resolve()), self.call()["argv"][3])
        (self.project / "p2p.xlsx").unlink()
        self.assertEqual(2, self.module.main(["--archive", str(self.archive())]), "two CVTs, no P2P to choose")
        for path in self.output.glob("*-cvt.xlsx"):
            path.unlink()
        self.assertEqual(2, self.module.main(["--archive", str(self.archive())]), "no CVT at all")

    def test_a_report_is_accepted_only_with_provenance_for_this_input(self):
        # Owner 2026-10-22: provenance (input and CVT sha256), not the modification time, ties the
        # report to this run.
        archive = self.archive()
        report = self.output / f"{RUN_ID}_ufm01-ibdiagnet-topology-validation.xlsx"
        receipt = self.output / f"{RUN_ID}_ufm01-ibdiagnet-topology-validation.receipt.json"
        for env in ({"FAKE_ANALYZER_RC": "1"}, {"FAKE_ANALYZER_NO_REPORT": "1"},
                    {"FAKE_ANALYZER_NO_PROVENANCE": "1"}, {"FAKE_ANALYZER_OTHER_INPUT": "1"}):
            with self.subTest(env=sorted(env)), mock.patch.dict(os.environ, env):
                for path in self.output.glob(f"{RUN_ID}_*"):
                    path.unlink()
                self.assertEqual(2, self.module.main(["--archive", str(archive)]))
                self.assertFalse(receipt.exists())
        # a report left by an earlier analysis of the same name is not taken for this run's
        report.write_bytes(b"old")
        with mock.patch.dict(os.environ, {"FAKE_ANALYZER_NO_REPORT": "1"}):
            self.assertEqual(2, self.module.main(["--archive", str(archive)]), "an old report without provenance")

    def test_only_a_ufm_snapshot_of_this_naming_is_accepted(self):
        for name in ("latest.tgz", f"{RUN_ID}_ufm01.tar.gz", f"{RUN_ID}_ufm01_ibdiagnet2.tar.gz",
                     f"{RUN_ID}_ufm_01_ibdiagnet2.tgz", f"x{RUN_ID}_ufm01_ibdiagnet2.tgz",
                     f"{RUN_ID}_ufm01_iblinkinfo.txt"):
            with self.subTest(name=name):
                path = self.data / name
                path.write_bytes(b"x")
                self.assertEqual(2, self.module.main(["--archive", str(path)]))
        self.assertFalse(self.calls.exists(), "nothing was analysed")

    def test_run_on_its_own_it_takes_the_newest_input_beside_it(self):
        # Owner 2026-10-21: every script is self-contained; its inputs sit in its own directory.
        older = self.archive("20261021-0200-prod-0000000000000001_ufm01_ibdiagnet2.tgz")
        newer = self.archive("20261021-0300-prod-0000000000000002_ufm02_iblinkinfo.log")
        os.utime(newer, (1, 1))   # the run-id time decides, not the file time
        (self.data / "20261022-daily.tar.gz").write_bytes(b"x")   # retention bundles are not runs
        self.assertEqual(0, self.module.main([]))
        self.assertEqual(str(newer.resolve()), self.call()["argv"][1])
        self.assertNotEqual(str(older.resolve()), self.call()["argv"][1])

    def test_run_on_its_own_without_any_archive_fails_cleanly(self):
        self.assertEqual(2, self.module.main([]))
        self.assertFalse(self.calls.exists())

    def test_without_the_setup_output_link_nothing_runs(self):
        (self.root / "tool-link").unlink()
        self.assertEqual(2, self.module.main(["--archive", str(self.archive())]))


class IbPostCollectRealAnalyzerWorkflowTest(unittest.TestCase):
    """Real P2P→CVT converter, real UFM-layout ibdiagnet archive, real analyzer, real page reader."""

    def test_a_ufm_ibdiagnet_archive_reaches_the_ib_link_validation_tab(self):
        with tempfile.TemporaryDirectory(prefix="ib-post-collect-") as directory:
            root = Path(directory).resolve()
            # the published layout: this post-collect with its own-directory links (setup), and the
            # shared analyzer code
            monitor = root / "infiniband/monitor"
            monitor.mkdir(parents=True)
            shutil.copy2(POST_COLLECT, monitor / "post-collect.py")
            tool = root / "tools/ibdiagnet-analyze-tool"
            tool.mkdir(parents=True)
            (tool / "analyze.py").symlink_to(ROOT / "tools/ibdiagnet-analyze-tool/analyze.py")
            project = root / "DAY0-Prepare/fabric-a"
            output = project / "99-output-p2p"
            output.mkdir(parents=True)
            (monitor / "99-output-p2p").symlink_to(output)
            # P2P: leaf01 sw1p1 <-> server01 mlx5_0, converted by the real p2p-to-validation.py
            p2p = project / "fabric-blue.xlsx"
            book = xlsxwriter.Workbook(str(p2p))
            sheet = book.add_worksheet("CL links")
            for column, value in enumerate(("Name", "Port", "Name", "Port")):
                sheet.write(0, column, value)
            for column, value in enumerate(("leaf01", "sw1p1", "server01", "mlx5_0")):
                sheet.write(1, column, value)
            book.close()
            (project / "p2p.xlsx").symlink_to(p2p.name)
            setup = root / "converter"
            setup.mkdir()
            # [IB-SW] as in the real template inventory: a section name with "-sw" makes a switch
            for name, text in (("01-inventory.log", "[IB-SW]\n*leaf*\n\n[server]\n*server*\n"),
                               ("02-port-mapping.log", ""), ("03-splitter.log", "")):
                (setup / name).write_text(text, encoding="utf-8")
            (setup / "p2p.xlsx").symlink_to(project / "p2p.xlsx")
            converted = subprocess.run(
                [sys.executable, "-B", str(ROOT / "ztp/config/nvos/template/P2P/p2p-to-validation.py"),
                 "--output", str(output / "fabric-blue-cvt.xlsx"),
                 "--inventory", str(setup / "01-inventory.log"),
                 "--port-map", str(setup / "02-port-mapping.log"),
                 "--splitter", str(setup / "03-splitter.log")],
                cwd=setup, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "XLSX_TO_CSV_BASE_DIR": str(setup)},
                capture_output=True, text=True, timeout=120, check=False)
            self.assertEqual(0, converted.returncode, converted.stdout + converted.stderr)
            data = root / "infiniband/monitor/ufm-ibdiagnet"
            data.mkdir()
            archive = ibdiagnet_archive(data, f"{RUN_ID}_ufm01_ibdiagnet2.tgz")

            # run on its own, as an operator would: no arguments, inputs from its own directory
            completed = subprocess.run(
                [sys.executable, "-B", str(monitor / "post-collect.py")],
                capture_output=True, text=True, timeout=300, check=False, cwd=root,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
            self.assertIn(str(archive), completed.stdout)
            self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
            report_name = f"{RUN_ID}_ufm01-ibdiagnet-topology-validation.xlsx"
            self.assertTrue((output / report_name).is_file(), completed.stdout)
            # the real analyzer's provenance names this archive and CVT, so the report is accepted
            receipt = json.loads((output / report_name.replace(".xlsx", ".receipt.json")).read_text())
            self.assertEqual((receipt["run_id"], receipt["node"], receipt["kind"]), (RUN_ID, "ufm01", "ibdiagnet"))
            self.assertEqual(receipt["input"]["sha256"], hashlib.sha256(archive.read_bytes()).hexdigest())

            page = load_module("ib_post_collect_page", ROOT / "monitor/generate-monitor-html.py")
            tab = page.load_topology_validation(output, "infiniband", "prod")
            self.assertEqual(f"Production: {report_name}", tab["source"])
            self.assertEqual(1, tab["counts"]["Matching"], tab["counts"])
            self.assertEqual(0, tab["counts"]["Missing"] + tab["counts"]["Miswired"] + tab["counts"]["Undefined"])
            self.assertEqual("PASS", tab["result"])
            # Owner 2026-10-22: the IB Link Validation page names the run, the UFM and whether it degraded.
            self.assertEqual(f"UFM ufm01 · ibdiagnet · run-id {RUN_ID}", tab["collection"])
            self.assertIn(f"采集：<strong>UFM ufm01 · ibdiagnet · run-id {RUN_ID}</strong>",
                          page.render_topology_panel(tab, "itop", "InfiniBand"))
            receipt_path = output / report_name.replace(".xlsx", ".receipt.json")
            receipt = json.loads(receipt_path.read_text())
            receipt["report"]["sha256"] = "0" * 64   # a receipt for other report bytes is not shown
            receipt_path.write_text(json.dumps(receipt))
            self.assertEqual("", page.load_topology_validation(output, "infiniband", "prod")["collection"])


if __name__ == "__main__":
    unittest.main()
