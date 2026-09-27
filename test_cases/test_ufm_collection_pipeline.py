#!/usr/bin/env python3
"""Local-only UFM archive handoff: fail closed before a public receipt."""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
PIPELINE = load_script("ufm_collection_pipeline_direct", ROOT / "tools/ufm_collection_pipeline.py")
HTML = load_script("ufm_candidate_panel_direct", ROOT / "monitor/generate-monitor-html.py")

RUN_ID = "20260926-0315-air-0123456789abcdef"


class UfmCollectionPipelineTests(unittest.TestCase):
    def test_candidate_panel_refuses_unbound_preview_without_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            baseline = HTML.render_ufm_evidence_panel(project, "air")
            candidate = {
                "schema": "ufm-collection-v1", "status": "success",
                "kind": "iblinkinfo", "run_id": RUN_ID, "node": "EXAMPLE-UFM01",
                "archive": f"iblinkinfo_{RUN_ID}.tar.gz",
                "archive_sha256": "0" * 64,
                "report": f"iblinkinfo_{RUN_ID}-topology-validation.xlsx",
                "report_sha256": "1" * 64,
                "report_provenance_sha256": "2" * 64,
            }
            for changed in (
                {**candidate, "archive": "iblinkinfo_other.tar.gz"},
                {**candidate, "report_sha256": "not-a-digest"},
                {**candidate, "status": "unverified"},
            ):
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    HTML.render_ufm_candidate_panel(project, "air", changed)
            self.assertEqual(baseline, HTML.render_ufm_evidence_panel(project, "air"))
            self.assertFalse((project / "99-output-ufm").exists())

    def test_missing_stage_attestation_refuses_before_a_result_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            report, log, cvt = (root / "report.xlsx", root / "actual.log",
                                root / "cvt.xlsx")
            for path in (report, log, cvt):
                path.write_bytes(b"synthetic")
            with self.assertRaises(PIPELINE.PipelineError):
                PIPELINE._staged_analysis_attestation(report, log, cvt)

    def test_held_result_chain_rejects_replaced_node_and_missing_nofollow(self):
        plan = PIPELINE.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve() / "project"
            node = project / "99-output-ufm" / "runs" / RUN_ID / "EXAMPLE-UFM01"
            node.mkdir(parents=True)
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            root_fd = os.open(project, flags)
            run_fd = os.open(node.parent, flags)
            node_fd = os.open(node, flags)
            try:
                self.assertTrue(PIPELINE._result_chain_still_bound(
                    root_fd, plan, node.name, run_fd, node_fd))
                with mock.patch.object(PIPELINE.os, "O_NOFOLLOW", 0):
                    self.assertFalse(PIPELINE._result_chain_still_bound(
                        root_fd, plan, node.name, run_fd, node_fd))
                node.rename(project / "retained-original-node")
                node.mkdir()
                self.assertFalse(PIPELINE._result_chain_still_bound(
                    root_fd, plan, node.name, run_fd, node_fd))
            finally:
                os.close(node_fd)
                os.close(run_fd)
                os.close(root_fd)

    def test_report_sidecar_publication_never_overwrites_an_incumbent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            name = "report.xlsx.provenance.json"
            incumbent = root / name
            incumbent.write_bytes(b"operator-owned-sidecar")
            directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                with self.assertRaises(PIPELINE.PipelineError):
                    PIPELINE._publish_result_sidecar_at(
                        directory_fd, name, {"schema": "synthetic-only"},
                    )
            finally:
                os.close(directory_fd)
            self.assertEqual(b"operator-owned-sidecar", incumbent.read_bytes())
            self.assertEqual([incumbent], list(root.iterdir()))

    def test_intermediate_output_symlink_cannot_import_external_receipt(self):
        plan = PIPELINE.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            project = root / "project"
            project.mkdir()
            external = root / "external"
            node = external / "runs" / RUN_ID / "EXAMPLE-UFM01"
            node.mkdir(parents=True)
            archive = node / plan.archive_name
            report = node / f"iblinkinfo_{RUN_ID}-topology-validation.xlsx"
            archive.write_bytes(b"external-archive")
            report.write_bytes(b"external-report")
            (node / "receipt.json").write_text(json.dumps({
                "schema": "ufm-collection-v1", "status": "success", "kind": "iblinkinfo",
                "run_id": RUN_ID, "node": "EXAMPLE-UFM01",
                "archive": archive.name,
                "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                "report": report.name,
                "report_sha256": hashlib.sha256(report.read_bytes()).hexdigest(),
            }), encoding="utf-8")
            (project / "99-output-ufm").symlink_to(external, target_is_directory=True)
            self.assertEqual([], PIPELINE.validated_receipts(project, "air"))

    def test_archive_member_must_be_the_single_nonempty_regular_artifact(self):
        plan = PIPELINE.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            cvt = root / "cvt.xlsx"
            cvt.write_bytes(b"synthetic-cvt-marker")
            output = root / "project"
            output.mkdir()
            for body in (b"", b"not a gzip archive"):
                archive = root / plan.archive_name
                archive.write_bytes(body)
                with self.subTest(body=body), self.assertRaises(PIPELINE.PipelineError):
                    PIPELINE.run_local_iblinkinfo(plan, "EXAMPLE-UFM01", archive, cvt, output)
                self.assertFalse((output / "99-output-ufm").exists())

    def test_wrong_run_name_or_existing_result_never_overwrites(self):
        plan = PIPELINE.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            archive = root / "iblinkinfo_other.tar.gz"
            archive.write_bytes(b"synthetic")
            cvt = root / "cvt.xlsx"
            cvt.write_bytes(b"synthetic-cvt-marker")
            output = root / "project"
            output.mkdir()
            with self.assertRaises(PIPELINE.PipelineError):
                PIPELINE.run_local_iblinkinfo(plan, "EXAMPLE-UFM01", archive, cvt, output)
            self.assertFalse((output / "99-output-ufm").exists())

    def test_receipt_schema_cannot_claim_success_without_bound_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            run = root / "99-output-ufm" / "runs" / RUN_ID / "EXAMPLE-UFM01"
            run.mkdir(parents=True)
            (run / "receipt.json").write_text(json.dumps({
                "schema": "ufm-collection-v1", "status": "success",
                "kind": "iblinkinfo", "run_id": RUN_ID, "node": "EXAMPLE-UFM01",
                "report": f"iblinkinfo_{RUN_ID}-topology-validation.xlsx",
                "report_sha256": "0" * 64,
            }), encoding="utf-8")
            self.assertEqual([], PIPELINE.validated_receipts(root, "air"))



if __name__ == "__main__":
    unittest.main()
