"""Real CVT producer must carry byte-bound IB topology provenance."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import xlsxwriter

from ztp.config.ib_topology_provenance import (
    ProvenanceError, read_cvt_provenance, read_report_provenance,
)


ROOT = Path(__file__).resolve().parents[1]
CONVERTER = ROOT / "ztp/config/nvos/template/P2P/p2p-to-validation.py"
VALIDATOR = ROOT / "tools/ibdiagnet-analyze-tool/scripts/validate_ib_topology.py"
ANALYZER = ROOT / "tools/ibdiagnet-analyze-tool/analyze.py"


class IbCvtProvenanceWorkflowTests(unittest.TestCase):
    def test_real_cvt_cli_rejects_day0_project_path_even_when_child_links_out(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "ztp/config"
            fake_converter = config / "nvos/template/P2P/p2p-to-validation.py"
            fake_converter.parent.mkdir(parents=True)
            shutil.copy2(CONVERTER, fake_converter)
            for name in ("topology_rules.py", "ib_topology_provenance.py"):
                shutil.copy2(ROOT / "ztp/config" / name, config / name)
            stage = root / "private-stage"
            stage.mkdir()
            workbook = xlsxwriter.Workbook(str(stage / "p2p.xlsx"))
            sheet = workbook.add_worksheet("CL links")
            for column, value in enumerate(("Name", "Port", "Name", "Port")):
                sheet.write(0, column, value)
            for column, value in enumerate(("leaf01", "sw1p1", "server01", "mlx5_0")):
                sheet.write(1, column, value)
            workbook.close()
            inventory = stage / "01-inventory.log"
            inventory.write_text("[ib]\n*leaf*\n\n[server]\n*server*\n", encoding="utf-8")
            port_map = stage / "02-port-mapping.log"
            port_map.write_text("", encoding="utf-8")
            splitter = stage / "03-splitter.log"
            splitter.write_text("", encoding="utf-8")
            project = root / "DAY0-Prepare/demo"
            project.mkdir(parents=True)
            (project / "99-output-ztp").symlink_to(stage, target_is_directory=True)
            output = project / "99-output-ztp/report.xlsx"
            completed = subprocess.run(
                [sys.executable, "-B", str(fake_converter), "--output", str(output),
                 "--inventory", str(inventory), "--port-map", str(port_map),
                 "--splitter", str(splitter)],
                cwd=stage, text=True, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, timeout=60, check=False,
                env={**os.environ, "XLSX_TO_CSV_BASE_DIR": str(stage),
                     "PYTHONDONTWRITEBYTECODE": "1"},
            )
            self.assertNotEqual(0, completed.returncode, completed.stdout)
            self.assertFalse((stage / "report.xlsx").exists())
            self.assertFalse((stage / "report.xlsx.provenance.json").exists())

    def test_real_converter_and_validator_bind_same_expected_topology(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            p2p = root / "p2p.xlsx"
            workbook = xlsxwriter.Workbook(str(p2p))
            sheet = workbook.add_worksheet("CL links")
            for column, value in enumerate(("Name", "Port", "Name", "Port")):
                sheet.write(0, column, value)
            for column, value in enumerate(("leaf01", "sw1p1", "server01", "mlx5_0")):
                sheet.write(1, column, value)
            workbook.close()
            inventory = root / "01-inventory.log"
            inventory.write_text("[ib]\n*leaf*\n\n[server]\n*server*\n", encoding="utf-8")
            port_map = root / "02-port-mapping.log"
            port_map.write_text("", encoding="utf-8")
            splitter = root / "03-splitter.log"
            splitter.write_text("", encoding="utf-8")
            cvt = root / "expected-cvt.xlsx"
            env = {**os.environ, "XLSX_TO_CSV_BASE_DIR": str(root),
                   "PYTHONDONTWRITEBYTECODE": "1"}
            conversion = subprocess.run(
                [sys.executable, "-B", str(CONVERTER), "--output", str(cvt),
                 "--inventory", str(inventory), "--port-map", str(port_map),
                 "--splitter", str(splitter)],
                cwd=root, text=True, capture_output=True, timeout=60,
                check=False, env=env,
            )
            self.assertEqual(0, conversion.returncode, conversion.stderr)
            actual = root / "iblinkinfo.log"
            actual.write_text(
                "Switch: 0x1 MF0;leaf01:MQM9700/U1:\n"
                ' 10 1[  ] ==( 4X 200 Gbps Active / LinkUp )==> '
                '20 1[  ] "server01 mlx5_0"\n',
                encoding="utf-8",
            )
            report = root / "iblinkinfo-topology-validation.xlsx"
            validation = subprocess.run(
                [sys.executable, "-B", str(VALIDATOR), "--iblinkinfo", str(actual),
                 "--p2p", str(cvt), "--output", str(report)],
                cwd=root, text=True, capture_output=True, timeout=60,
                check=False, env=env,
            )
            self.assertEqual(0, validation.returncode, validation.stderr)
            record = read_report_provenance(report)
            self.assertEqual(
                hashlib.sha256(cvt.read_bytes()).hexdigest(),
                record["expected_topology_sha256"],
            )
            old_time = cvt.stat().st_mtime_ns
            cvt.write_bytes(cvt.read_bytes() + b"changed")
            os.utime(cvt, ns=(old_time, old_time))
            with self.assertRaises(ProvenanceError):
                read_report_provenance(report)
            batch = subprocess.run(
                [sys.executable, "-B", str(ANALYZER), str(root)],
                cwd=root, text=True, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, timeout=60, check=False, env=env,
            )
            self.assertNotEqual(0, batch.returncode, batch.stdout)
            self.assertNotIn("[SKIPPED]", batch.stdout)

    def test_real_converter_carries_expected_topology_bytes_and_rejects_changed_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            p2p = root / "p2p.xlsx"
            workbook = xlsxwriter.Workbook(str(p2p))
            sheet = workbook.add_worksheet("CL links")
            for column, value in enumerate(("Name", "Port", "Name", "Port")):
                sheet.write(0, column, value)
            for column, value in enumerate(("leaf01", "sw1p1", "server01", "mlx5_0")):
                sheet.write(1, column, value)
            workbook.close()

            inventory = root / "01-inventory.log"
            inventory.write_text("[ib]\n*leaf*\n\n[server]\n*server*\n", encoding="utf-8")
            port_map = root / "02-port-mapping.log"
            port_map.write_text("", encoding="utf-8")
            splitter = root / "03-splitter.log"
            splitter.write_text("", encoding="utf-8")
            cvt = root / "expected-cvt.xlsx"
            completed = subprocess.run(
                [sys.executable, "-B", str(CONVERTER), "--output", str(cvt),
                 "--inventory", str(inventory), "--port-map", str(port_map),
                 "--splitter", str(splitter)],
                cwd=root, text=True, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, timeout=60, check=False,
                env={**os.environ, "XLSX_TO_CSV_BASE_DIR": str(root),
                     "PYTHONDONTWRITEBYTECODE": "1"},
            )
            self.assertEqual(0, completed.returncode, completed.stdout)
            self.assertTrue(cvt.is_file())
            record = read_cvt_provenance(cvt)
            self.assertEqual(
                hashlib.sha256(cvt.read_bytes()).hexdigest(),
                record["cvt_sha256"],
            )
            self.assertEqual(
                hashlib.sha256(p2p.read_bytes()).hexdigest(),
                record["sources"]["p2p"]["sha256"],
            )
            original_time = p2p.stat().st_mtime_ns
            p2p.write_bytes(p2p.read_bytes() + b"changed")
            os.utime(p2p, ns=(original_time, original_time))
            with self.assertRaises(ProvenanceError):
                read_cvt_provenance(cvt)


if __name__ == "__main__":
    unittest.main()
