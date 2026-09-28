"""Synthetic UFM archive -> real ibdiagnet analyzer -> bound local panel receipt."""

from __future__ import annotations

from pathlib import Path
import hashlib
import tempfile
import unittest
from unittest import mock

from test_cases.test_ib_analysis_domain import write_ibdiagnet_fixture
from test_cases.test_ufm_collection_pipeline_workflow import _write_cvt
from test_cases.module_loader import load_script
from tools.ufm_collection_contract import collection_plan, publish_local_archive
from tools.ufm_collection_pipeline import PipelineError, run_local_ibdiagnet, validated_receipts
from tools import ufm_collection_pipeline as PIPELINE


RUN_ID = "20260926-0315-air-0123456789abcdef"
HTML = load_script("ufm_ibdiagnet_pipeline_html", Path(__file__).resolve().parents[1]
                   / "monitor/generate-monitor-html.py")


class UfmIbdiagnetPipelineWorkflowTests(unittest.TestCase):
    def test_staged_archive_replacement_after_first_digest_cannot_publish_receipt(self):
        plan = collection_plan("ibdiagnet", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            snapshot = root / "snapshot"
            snapshot.mkdir()
            write_ibdiagnet_fixture(snapshot)
            private = root / "private"
            private.mkdir()
            archive = publish_local_archive(plan, snapshot, private)
            original_bytes = archive.read_bytes()
            alternate_snapshot = root / "alternate-snapshot"
            alternate_snapshot.mkdir()
            write_ibdiagnet_fixture(alternate_snapshot)
            dump = alternate_snapshot / "ibdiagnet2.net_dump"
            dump.write_text(dump.read_text(encoding="utf-8").replace("200 : RS", "100 : RS"),
                            encoding="utf-8")
            alternate_private = root / "alternate-private"
            alternate_private.mkdir()
            alternate = publish_local_archive(plan, alternate_snapshot, alternate_private)
            alternate_bytes = alternate.read_bytes()
            self.assertNotEqual(original_bytes, alternate_bytes)
            cvt = root / "cvt.xlsx"
            _write_cvt(cvt)
            project = root / "project"
            project.mkdir()
            original_sha256 = PIPELINE._sha256
            swapped = []

            def swap_after_first_stage_hash(path):
                digest = original_sha256(path)
                if (path.name == plan.archive_name
                        and path.parent.name.startswith(".ufm-handoff-")
                        and not swapped):
                    replacement = path.parent / "replacement-archive"
                    replacement.write_bytes(alternate_bytes)
                    replacement.replace(path)
                    swapped.append(True)
                return digest

            with mock.patch.object(PIPELINE, "_sha256", side_effect=swap_after_first_stage_hash):
                with self.assertRaises(PipelineError):
                    run_local_ibdiagnet(plan, "EXAMPLE-UFM01", archive, cvt, project)
            self.assertEqual([True], swapped)
            self.assertEqual(original_bytes, archive.read_bytes())
            target = project / "99-output-ufm" / "runs" / RUN_ID / "EXAMPLE-UFM01"
            self.assertFalse((target / "receipt.json").exists())
            self.assertEqual([], validated_receipts(project, "air"))

    def test_retrieved_source_drift_before_receipt_never_claims_success(self):
        plan = collection_plan("ibdiagnet", RUN_ID)
        for mutation in ("bytes", "same_bytes_new_inode"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
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

                def change_retrieved_source():
                    if mutation == "bytes":
                        archive.write_bytes(archive.read_bytes() + b"changed")
                    else:
                        replacement = root / "same-content-replacement"
                        replacement.write_bytes(archive.read_bytes())
                        replacement.replace(archive)

                with self.assertRaises(PipelineError):
                    run_local_ibdiagnet(
                        plan, "EXAMPLE-UFM01", archive, cvt, project,
                        before_receipt=change_retrieved_source,
                    )
                target = project / "99-output-ufm" / "runs" / RUN_ID / "EXAMPLE-UFM01"
                self.assertFalse((target / "receipt.json").exists())
                self.assertEqual([], validated_receipts(project, "air"))
                self.assertIn("未知", HTML.render_ufm_evidence_panel(project, "air"))

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
            self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(),
                             receipts[0]["archive_sha256"])
            panel = HTML.render_ufm_evidence_panel(project, "air")
            self.assertIn("EXAMPLE-UFM01", panel)
            self.assertIn("ibdiagnet", panel)


if __name__ == "__main__":
    unittest.main()
