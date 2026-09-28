"""Synthetic UFM archive -> real ibdiagnet analyzer -> bound local panel receipt."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from test_cases.test_ib_analysis_domain import write_ibdiagnet_fixture
from test_cases.test_ufm_collection_pipeline_workflow import _write_cvt
from test_cases.module_loader import load_script
from tools.ufm_collection_contract import collection_plan, publish_local_archive
from tools.ufm_collection_pipeline import PipelineError, run_local_ibdiagnet, validated_receipts


RUN_ID = "20260926-0315-air-0123456789abcdef"
HTML = load_script("ufm_ibdiagnet_pipeline_html", Path(__file__).resolve().parents[1]
                   / "monitor/generate-monitor-html.py")


class UfmIbdiagnetPipelineWorkflowTests(unittest.TestCase):
    def test_pre_receipt_gate_failure_never_claims_completed_ibdiagnet(self):
        plan = collection_plan("ibdiagnet", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            snapshot = root / "snapshot"
            snapshot.mkdir()
            write_ibdiagnet_fixture(snapshot)
            private = root / "private"
            private.mkdir()
            archive = publish_local_archive(plan, snapshot, private)
            cvt = root / "cvt.xlsx"
            _write_cvt(cvt)
            project = root / "project"
            project.mkdir()
            with self.assertRaises(PipelineError):
                run_local_ibdiagnet(plan, "EXAMPLE-UFM01", archive, cvt, project,
                                    before_receipt=lambda: (_ for _ in ()).throw(
                                        ValueError("independent stop")))
            target = project / "99-output-ufm" / "runs" / RUN_ID / "EXAMPLE-UFM01"
            self.assertFalse((target / "receipt.json").exists())
            self.assertEqual([], validated_receipts(project, "air"))
            self.assertIn("未知", HTML.render_ufm_evidence_panel(project, "air"))

    def test_real_archive_analyzer_receipt_and_panel(self):
        plan = collection_plan("ibdiagnet", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            snapshot = root / "snapshot"
            snapshot.mkdir()
            write_ibdiagnet_fixture(snapshot)
            private = root / "private"
            private.mkdir()
            archive = publish_local_archive(plan, snapshot, private)
            cvt = root / "cvt.xlsx"
            _write_cvt(cvt)
            project = root / "project"
            project.mkdir()
            self.assertEqual([], validated_receipts(project, "air"))
            result = run_local_ibdiagnet(plan, "EXAMPLE-UFM01", archive, cvt, project)
            expected = f"ibdiagnet2_{RUN_ID}-topology-validation.xlsx"
            self.assertTrue((result / expected).is_file())
            receipts = validated_receipts(project, "air")
            self.assertEqual(1, len(receipts))
            self.assertEqual("ibdiagnet", receipts[0]["kind"])
            panel = HTML.render_ufm_evidence_panel(project, "air")
            self.assertIn("EXAMPLE-UFM01", panel)
            self.assertIn("ibdiagnet", panel)


if __name__ == "__main__":
    unittest.main()
