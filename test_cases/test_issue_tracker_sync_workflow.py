"""REQ7 Issue Tracker sync workflow: collected data -> real converters -> the real engine's source adapters.

ETH: an eth-info archive and the planned *-lldpq.dot go through tools/lldp-analyze-tool/analyze_lldp.py
(--payload-json) and the wrapper's LLDPQ projection; IB: a UFM ibdiagnet2.tgz and the project *-cvt.xlsx
go through the vendored cabletracker/ibdiagnet/generate_report.py. Each result is then read by the
vendored cabletracker_runner.py's own adapter in a child interpreter, so the files the wrapper hands to
the engine are proved acceptable to it without contacting Google. The engine's AI client modules are
only stood in for when they are not installed; the wrapper never enables AI features.
"""

from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from contextlib import redirect_stdout


ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "monitor/issue-tracker/issue-tracker-sync.py"
RUNNER = ROOT / "monitor/issue-tracker/cabletracker/cabletracker_runner.py"
ANALYZER = ROOT / "tools/lldp-analyze-tool/analyze_lldp.py"
SPREADSHEET = "1" + "B" * 43

ENGINE_READ = r'''
import importlib.util, json, sys, types
for name in ("openai", "httpx"):
    try:
        __import__(name)
    except ImportError:
        stub = types.ModuleType(name)
        stub.OpenAI = stub.Client = object
        sys.modules[name] = stub
spec = importlib.util.spec_from_file_location("cabletracker_runner", sys.argv[1])
runner = importlib.util.module_from_spec(spec)
sys.modules["cabletracker_runner"] = runner
spec.loader.exec_module(runner)
links = runner.SOURCE_ADAPTERS[sys.argv[3]]().normalize(json.load(open(sys.argv[2])), True)
print(json.dumps([{
    "status": link.status, "protocol": link.protocol,
    "a": [link.a.node, link.a.port], "z": [link.z.node, link.z.port],
    "z_actual": [link.z.actual_node, link.z.actual_port],
    "issue": runner.issue_type(link.a.report, link.z.report) if link.status == "Fail" else "",
} for link in links]))
'''


def load_wrapper():
    spec = importlib.util.spec_from_file_location("issue_tracker_sync_workflow_subject", WRAPPER)
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolve string annotations through sys.modules[cls.__module__]
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def info_text(rows) -> bytes:
    widths = (16, 16, 16, 12, 12, 12, 22, 16, 12)
    headers = ("Interface", "Admin Status", "Oper Status", "Speed", "MTU",
               "Type", "Remote Host", "Remote Port", "Other")
    line = lambda items: "".join(str(item).ljust(width) for item, width in zip(items, widths))
    text = ["# Execute Command: nv show interface", line(headers), line("-" * (w - 1) for w in widths)]
    for port, oper, host, remote in rows:
        text.append(line((port, "up", oper, "100G", "9216", "swp", host or "-", remote or "-", "-")))
    return ("\n".join(text) + "\n").encode()


def write_tar(path: Path, members: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w:gz") as bundle:
        for name, body in members.items():
            member = tarfile.TarInfo(name)
            member.size = len(body)
            bundle.addfile(member, io.BytesIO(body))


def engine_read(source: Path, kind: str) -> list:
    completed = subprocess.run([sys.executable, "-B", "-c", ENGINE_READ, str(RUNNER), str(source), kind],
                               capture_output=True, text=True, timeout=300, check=False)
    if completed.returncode != 0:
        raise AssertionError(completed.stderr[-3000:])
    return json.loads(completed.stdout.strip().splitlines()[-1])


class IssueTrackerSyncWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.project = Path(self.directory.name) / "project"
        (self.project / "99-output-p2p").mkdir(parents=True)
        # conversion needs a set-up project; the online sync itself stays disabled here
        (self.project / "01-global.yaml").write_text("schema_version: 2\n", encoding="utf-8")

    def convert(self, only: str) -> str:
        stream = io.StringIO()
        with redirect_stdout(stream):
            code = load_wrapper().main(["--project-dir", str(self.project), "--only", only,
                                        "--convert-only"])
        self.assertEqual(0, code, stream.getvalue())
        return stream.getvalue()

    def test_eth_archive_reaches_the_engine_as_lldpq_rows(self):
        (self.project / "99-output-p2p/plan-lldpq.dot").write_bytes(
            b'"leaf-a":"swp1" -- "leaf-z":"swp2"\n"leaf-b":"swp3" -- "leaf-z":"swp4"\n')
        write_tar(self.project / "99-output-monitor/ethernet/eth-info/20261023-0900-prod.tar.gz", {
            "leaf-a.info": info_text([("swp1", "up", "leaf-z", "swp2")]),
            "leaf-b.info": info_text([("swp3", "down", "", "")]),
            "leaf-z.info": info_text([("swp2", "up", "leaf-a", "swp1"), ("swp4", "down", "", "")]),
        })
        text = self.convert("eth")
        self.assertIn("ETH: 2 rows (FAILED 1, SUCCESS 1)", text)
        links = engine_read(self.project / "99-output-monitor/ethernet/issue-tracker/eth-lldpq.json", "lldpq")
        by_a = {tuple(link["a"]): link for link in links}
        self.assertEqual({("leaf-a", "swp1"), ("leaf-b", "swp3")}, set(by_a))
        self.assertEqual(("Pass", "ethernet", ["leaf-z", "swp2"], ["leaf-z", "swp2"], ""),
                         tuple(by_a[("leaf-a", "swp1")][key]
                               for key in ("status", "protocol", "z", "z_actual", "issue")))
        self.assertEqual(("Fail", "ethernet", ["leaf-z", "swp4"], "Link Down"),
                         tuple(by_a[("leaf-b", "swp3")][key] for key in ("status", "protocol", "z", "issue")))

    def test_analyzer_keeps_the_payload_its_report_was_built_from(self):
        base = Path(self.directory.name)
        dot = base / "plan-lldpq.dot"
        dot.write_bytes(b'"leaf-a":"swp1" -- "leaf-z":"swp2"\n')
        archive = base / "20261023-0900-prod.tar.gz"
        write_tar(archive, {"leaf-a.info": info_text([("swp1", "up", "leaf-z", "swp2")]),
                            "leaf-z.info": info_text([("swp2", "up", "leaf-a", "swp1")])})
        payload = base / "kept/payload.json"
        completed = subprocess.run(
            [sys.executable, "-B", str(ANALYZER), "--dot", str(dot), "--archive", str(archive),
             "--output-dir", str(base / "reports"), "--payload-json", str(payload)],
            capture_output=True, text=True, check=False, timeout=120)
        self.assertEqual(0, completed.returncode, completed.stderr or completed.stdout)
        self.assertTrue((base / "reports/20261023-0900-prod-ethernet-topology-validation.xlsx").is_file())
        document = json.loads(payload.read_text(encoding="utf-8"))
        self.assertEqual(["CONFIRMED_BOTH_SIDE"], [item["status"] for item in document["matching_links"]])
        self.assertEqual(([], []), (document["miswired_links"], document["missing_links"]))
        self.assertEqual(str(archive.resolve()), document["metadata"]["collection_archive"])
        self.assertEqual("leaf-z", document["matching_links"][0]["observation_a"]["remote_host"])

    def test_ufm_snapshot_and_cvt_reach_the_engine_as_cvt_circuits(self):
        from openpyxl import Workbook

        workbook = Workbook()
        sheets = {
            "Nodes": [("FabricId", "Rack", "Unit", "NodeName", "NodeType", "NodeModel", "Managed"),
                      ("fabric-1", "R01", 40, "spine-1", "Switch", "Q3400", "yes"),
                      ("fabric-1", "R02", 40, "leaf-1", "Switch", "Q3400", "yes")],
            "DC Floor Layout": [("DataHall", "ScalableUnit", "Rack"), ("DH1", "SU1", "R01"), ("DH1", "SU1", "R02")],
            "Links": [("Protocol", "A-Node", "A-Port", "Z-Node", "Z-Port"), ("ib", "spine-1", "1", "leaf-1", "1")],
            "Server Profile": [("ServerProfile", "PhysicalPort", "RDMAName", "CustomNICName", "NICOSName",
                                "PCIAddress"), ("none", "p0", "mlx5_0", "nic0", "ibp0", "0000:01:00.0")],
        }
        workbook.remove(workbook.active)
        for name, rows in sheets.items():
            sheet = workbook.create_sheet(name)
            for row in rows:
                sheet.append(row)
        workbook.save(self.project / "99-output-p2p/plan-cvt.xlsx")
        iblinkinfo = (
            "Switch: 0x0000000000000001 MF0;spine-1:Q3400/U1:\n"
            '   1    1[  ] ==( 4X 212.5 Gbps Active/  LinkUp)==>       2    1[  ] "MF0;leaf-1:Q3400/U1" ( )\n'
            "Switch: 0x0000000000000002 MF0;leaf-1:Q3400/U1:\n"
            '   2    1[  ] ==( 4X 212.5 Gbps Active/  LinkUp)==>       1    1[  ] "MF0;spine-1:Q3400/U1" ( )\n'
        ).encode()
        run = "20261023-0900-prod-" + "f" * 16 + "_ufm01"
        write_tar(self.project / f"99-output-monitor/infiniband/ufm-ibdiagnet/{run}_ibdiagnet2.tgz", {
            "ibdiagnet2/ibdiagnet2.iblinkinfo": iblinkinfo,
            "ibdiagnet2/ibdiagnet2.net_dump_ext": b"# synthetic: no port runtime rows\n",
            "ibdiagnet2/ibdiagnet2.net_dump": b"# synthetic\n",
        })
        text = self.convert("ib")
        self.assertIn("IB: 1 records", text)
        circuits = json.loads((self.project / "99-output-monitor/infiniband/issue-tracker/ib-cvt.json").read_text())
        self.assertEqual(1, len(circuits))
        self.assertEqual("ib", circuits[0]["protocol"])
        links = engine_read(self.project / "99-output-monitor/infiniband/issue-tracker/ib-cvt.json", "cvt")
        self.assertEqual(1, len(links))
        self.assertEqual(("ib", ["spine-1", "1"], ["leaf-1", "1"]),
                         (links[0]["protocol"], links[0]["a"], links[0]["z"]))
        self.assertIn(links[0]["status"], ("Pass", "Fail", None))


if __name__ == "__main__":
    unittest.main()
