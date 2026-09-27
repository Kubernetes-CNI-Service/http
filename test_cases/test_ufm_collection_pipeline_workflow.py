#!/usr/bin/env python3
"""Real D70 product -> real analyzer -> UFM-only dashboard evidence."""

from __future__ import annotations

from pathlib import Path
from datetime import datetime, timezone
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import xlsxwriter

from test_cases.module_loader import load_script
from tools import ufm_collection_contract as COLLECTION


ROOT = Path(__file__).resolve().parents[1]
PIPELINE = load_script("ufm_collection_pipeline_workflow", ROOT / "tools/ufm_collection_pipeline.py")
HTML = load_script("ufm_collection_pipeline_workflow_html", ROOT / "monitor/generate-monitor-html.py")
SETUP = load_script("ufm_collection_pipeline_workflow_setup", ROOT / "DAY0-Prepare/01-a-setup.py")
PROVENANCE = load_script(
    "ufm_collection_pipeline_workflow_provenance",
    ROOT / "ztp/config/ib_topology_provenance.py",
)
RUN_ID = "20260926-0315-air-0123456789abcdef"


def _write_cvt(path: Path) -> None:
    """Use the real P2P converter so the CVT has byte-bound source provenance."""
    base = path.parent
    workbook = xlsxwriter.Workbook(str(base / "p2p.xlsx"))
    links = workbook.add_worksheet("CL links")
    for column, value in enumerate(("Name", "Port", "Name", "Port")):
        links.write(0, column, value)
    for column, value in enumerate(("leaf01", "sw1p1", "server01", "mlx5_0")):
        links.write(1, column, value)
    workbook.close()
    (base / "01-inventory.log").write_text(
        "[ib]\n*leaf*\n\n[server]\n*server*\n", encoding="utf-8",
    )
    (base / "02-port-mapping.log").write_text("", encoding="utf-8")
    (base / "03-splitter.log").write_text("", encoding="utf-8")
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
           "XLSX_TO_CSV_BASE_DIR": str(base)}
    result = subprocess.run(
        [sys.executable, "-B", str(ROOT / "ztp/config/nvos/template/P2P/p2p-to-validation.py"),
         "--output", str(path), "--inventory", str(base / "01-inventory.log"),
         "--port-map", str(base / "02-port-mapping.log"),
         "--splitter", str(base / "03-splitter.log")],
        cwd=base, env=env, capture_output=True, text=True, timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(f"real P2P conversion failed: {result.stdout} {result.stderr}")
    PROVENANCE.read_cvt_provenance(path)


class UfmCollectionPipelineWorkflowTests(unittest.TestCase):
    def test_failed_pre_receipt_gate_keeps_real_analyzer_result_unpublished(self):
        plan = COLLECTION.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            vendor_output = root / "iblinkinfo.txt"
            vendor_output.write_text(
                "Switch: 0x1 MF0;leaf01:MQM9700/U1:\n"
                ' 10 1[  ] ==( 4X 200 Gbps Active / LinkUp )==> '
                '20 1[  ] "server01 mlx5_0"\n', encoding="utf-8",
            )
            ufm_dir = root / "ufm-private"
            ufm_dir.mkdir()
            archive = COLLECTION.publish_local_archive(plan, vendor_output, ufm_dir)
            cvt = root / "cvt.xlsx"
            _write_cvt(cvt)
            project = root / "project"
            project.mkdir()
            visited = []
            def reject_before_receipt():
                visited.append(True)
                raise ValueError("synthetic mandatory log retrieval failure")
            with self.assertRaises(PIPELINE.PipelineError):
                PIPELINE.run_local_iblinkinfo(
                    plan, "EXAMPLE-UFM01", archive, cvt, project,
                    before_receipt=reject_before_receipt,
                )
            self.assertEqual([True], visited)
            target = project / "99-output-ufm" / "runs" / RUN_ID / "EXAMPLE-UFM01"
            self.assertFalse((target / "receipt.json").exists())
            self.assertEqual([], PIPELINE.validated_receipts(project, "air"))
            self.assertIn("未知", HTML.render_ufm_evidence_panel(project, "air"))

    def test_source_change_during_pre_receipt_gate_cannot_publish_receipt(self):
        plan = COLLECTION.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            vendor_output = root / "iblinkinfo.txt"
            vendor_output.write_text(
                "Switch: 0x1 MF0;leaf01:MQM9700/U1:\n"
                ' 10 1[  ] ==( 4X 200 Gbps Active / LinkUp )==> '
                '20 1[  ] "server01 mlx5_0"\n', encoding="utf-8",
            )
            ufm_dir = root / "ufm-private"
            ufm_dir.mkdir()
            archive = COLLECTION.publish_local_archive(plan, vendor_output, ufm_dir)
            cvt = root / "cvt.xlsx"
            _write_cvt(cvt)
            project = root / "project"
            project.mkdir()
            def mutate_authority_during_log_retrieval():
                (root / "p2p.xlsx").write_bytes(b"changed during log retrieval")
            with self.assertRaises(PIPELINE.PipelineError):
                PIPELINE.run_local_iblinkinfo(
                    plan, "EXAMPLE-UFM01", archive, cvt, project,
                    before_receipt=mutate_authority_during_log_retrieval,
                )
            target = project / "99-output-ufm" / "runs" / RUN_ID / "EXAMPLE-UFM01"
            self.assertFalse((target / "receipt.json").exists())
            self.assertEqual([], PIPELINE.validated_receipts(project, "air"))

    @staticmethod
    def _html_with_ufm(panel: str) -> str:
        stats = {"changed": 0, "new": 0, "removed": 0, "same": 0}
        return HTML.build_html(
            {}, "", 0, "", "", 0, {}, "",
            "", "", stats, None, 0,
            "", "", stats, None, 0,
            "", "", 0, "",
            "", "", stats, None, 0,
            {}, {}, {}, {}, {}, ufm_panel=panel,
        )

    def test_ufm_panel_does_not_rewrite_existing_network_tabs(self):
        panel = '<div id="panel-ufm" class="panel">Synthetic UFM receipt</div>'
        with mock.patch.object(HTML, "datetime") as clock:
            clock.now.return_value = datetime(2026, 9, 26, tzinfo=timezone.utc)
            before = self._html_with_ufm("")
            after = self._html_with_ufm(panel)
        self.assertEqual(before, after.replace(panel, ""))
        for existing in ("Switch Status", "Eth Link Validation", "IB Link Monitor", "NVLink Monitor"):
            self.assertIn(existing, before)

    def test_cli_entrypoint_is_importable_outside_repository_cwd(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, str(ROOT / "tools/ufm_collection_pipeline.py"), "--help"],
                cwd=directory, capture_output=True, text=True, check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("--archive", result.stdout)

    def test_setup_maps_project_ufm_receipts_to_monitor_reader(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            project = root / "project"
            project.mkdir()
            self.assertIn("99-output-ufm", SETUP.OUTPUT_DIRS)
            (project / "99-output-ufm").mkdir()
            http = root / "http"
            (http / "monitor").mkdir(parents=True)
            with mock.patch.object(SETUP, "HTTP_BASE", str(http)):
                pairs = SETUP._monitor_link_paths(str(project))
                self.assertIn((str(http / "monitor" / "99-output-ufm"),
                               str(project / "99-output-ufm")), pairs)
                self.assertIn(str(http / "monitor" / "99-output-ufm"),
                              SETUP._collect_expected_links(str(project)))
                (http / "monitor" / "99-output-ufm").symlink_to(
                    project / "99-output-ufm", target_is_directory=True
                )
            self.assertIn("未知", HTML.render_ufm_evidence_panel(http / "monitor", "air"))

    def test_setup_existing_regular_monitor_path_is_never_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            project = root / "legacy-project"
            project.mkdir()
            http = root / "http"
            monitor = http / "monitor"
            monitor.mkdir(parents=True)
            occupied = monitor / "99-output-ufm"
            occupied.write_text("operator-owned marker", encoding="utf-8")
            with mock.patch.object(SETUP, "HTTP_BASE", str(http)), mock.patch.object(
                SETUP, "_DRY_RUN", False
            ):
                link, target = next(
                    pair for pair in SETUP._monitor_link_paths(str(project))
                    if pair[0] == str(occupied)
                )
                self.assertEqual(str(occupied), link)
                self.assertEqual(str(project / "99-output-ufm"), target)
                self.assertEqual("error", SETUP._make_link(link, target))
            self.assertEqual("operator-owned marker", occupied.read_text(encoding="utf-8"))
            self.assertFalse((project / "99-output-ufm").exists())

    def test_local_collect_process_display_sync_without_plain_lane_drift(self):
        plan = COLLECTION.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            vendor_output = root / "iblinkinfo.txt"
            vendor_output.write_text(
                "Switch: 0x1 MF0;leaf01:MQM9700/U1:\n"
                ' 10 1[  ] ==( 4X 200 Gbps Active / LinkUp )==> '
                '20 1[  ] "server01 mlx5_0"\n',
                encoding="utf-8",
            )
            ufm_dir = root / "ufm-private"
            ufm_dir.mkdir()
            archive = COLLECTION.publish_local_archive(plan, vendor_output, ufm_dir)
            cvt = root / "cvt.xlsx"
            _write_cvt(cvt)
            project = root / "project"
            project.mkdir()
            before = HTML.render_ufm_evidence_panel(project, "air")
            final = PIPELINE.run_local_iblinkinfo(plan, "EXAMPLE-UFM01", archive, cvt, project)
            self.assertTrue((final / "receipt.json").is_file())
            report = final / f"iblinkinfo_{RUN_ID}-topology-validation.xlsx"
            self.assertTrue(report.is_file())
            source = PROVENANCE.read_report_provenance(report)
            self.assertEqual(PROVENANCE.read_cvt_provenance(cvt)["cvt_sha256"],
                             source["expected_topology_sha256"])
            after = HTML.render_ufm_evidence_panel(project, "air")
            self.assertNotEqual(before, after)
            self.assertIn("EXAMPLE-UFM01", after)
            self.assertIn(RUN_ID, after)
            self.assertIn('id="ufm-collection-panel"', after)
            self.assertNotIn("synthetic-cvt-marker", after)
            self.assertEqual([], PIPELINE.validated_receipts(project, "prod"))
            with self.assertRaises(PIPELINE.PipelineError):
                PIPELINE.run_local_iblinkinfo(plan, "EXAMPLE-UFM01", archive, cvt, project)
            self.assertEqual(after, HTML.render_ufm_evidence_panel(project, "air"))
            (cvt.parent / "p2p.xlsx").write_bytes(b"changed source after publication")
            self.assertEqual([], PIPELINE.validated_receipts(project, "air"))
            self.assertIn("未知", HTML.render_ufm_evidence_panel(project, "air"))

    def test_candidate_panel_is_private_until_final_receipt_and_matches_public_panel(self):
        plan = COLLECTION.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            vendor_output = root / "iblinkinfo.txt"
            vendor_output.write_text(
                "Switch: 0x1 MF0;leaf01:MQM9700/U1:\n"
                ' 10 1[  ] ==( 4X 200 Gbps Active / LinkUp )==> '
                '20 1[  ] "server01 mlx5_0"\n', encoding="utf-8",
            )
            ufm_dir = root / "ufm-private"
            ufm_dir.mkdir()
            archive = COLLECTION.publish_local_archive(plan, vendor_output, ufm_dir)
            cvt = root / "cvt.xlsx"
            _write_cvt(cvt)
            project = root / "project"
            project.mkdir()
            preview = []

            def prepare(candidate):
                self.assertEqual([], PIPELINE.validated_receipts(project, "air"))
                self.assertNotIn(RUN_ID, HTML.render_ufm_evidence_panel(project, "air"))
                panel = HTML.render_ufm_candidate_panel(project, "air", candidate)
                self.assertIn(RUN_ID, panel)
                preview.append(panel)

            PIPELINE.run_local_iblinkinfo(
                plan, "EXAMPLE-UFM01", archive, cvt, project,
                prepare_panel=prepare,
            )
            self.assertEqual([HTML.render_ufm_evidence_panel(project, "air")], preview)
            self.assertEqual(1, len(PIPELINE.validated_receipts(project, "air")))

    def test_candidate_panel_failure_cannot_publish_a_success_receipt(self):
        plan = COLLECTION.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            vendor_output = root / "iblinkinfo.txt"
            vendor_output.write_text(
                "Switch: 0x1 MF0;leaf01:MQM9700/U1:\n"
                ' 10 1[  ] ==( 4X 200 Gbps Active / LinkUp )==> '
                '20 1[  ] "server01 mlx5_0"\n', encoding="utf-8",
            )
            ufm_dir = root / "ufm-private"
            ufm_dir.mkdir()
            archive = COLLECTION.publish_local_archive(plan, vendor_output, ufm_dir)
            cvt = root / "cvt.xlsx"
            _write_cvt(cvt)
            project = root / "project"
            project.mkdir()

            def reject(_candidate):
                raise OSError("synthetic panel unavailable")

            with self.assertRaises(PIPELINE.PipelineError):
                PIPELINE.run_local_iblinkinfo(
                    plan, "EXAMPLE-UFM01", archive, cvt, project,
                    prepare_panel=reject,
                )
            target = project / "99-output-ufm" / "runs" / RUN_ID / "EXAMPLE-UFM01"
            self.assertTrue((target / ".receipt.prepared").is_file())
            self.assertFalse((target / "receipt.json").exists())
            self.assertEqual([], PIPELINE.validated_receipts(project, "air"))
            self.assertNotIn(RUN_ID, HTML.render_ufm_evidence_panel(project, "air"))

    def test_missing_real_analyzer_attestation_never_publishes_a_receipt(self):
        plan = COLLECTION.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            vendor_output = root / "iblinkinfo.txt"
            vendor_output.write_text(
                "Switch: 0x1 MF0;leaf01:MQM9700/U1:\n"
                ' 10 1[  ] ==( 4X 200 Gbps Active / LinkUp )==> '
                '20 1[  ] "server01 mlx5_0"\n', encoding="utf-8",
            )
            ufm_dir = root / "ufm-private"
            ufm_dir.mkdir()
            archive = COLLECTION.publish_local_archive(plan, vendor_output, ufm_dir)
            cvt = root / "cvt.xlsx"
            _write_cvt(cvt)
            project = root / "project"
            project.mkdir()
            real_run = subprocess.run
            analyzed = []

            def remove_attestation_after_real_analyzer(*args, **kwargs):
                result = real_run(*args, **kwargs)
                if args[0][1] == str(ROOT / "tools/ibdiagnet-analyze-tool/analyze.py"):
                    self.assertEqual(0, result.returncode, result.stderr)
                    PROVENANCE.sidecar_path(Path(args[0][-1])).unlink()
                    analyzed.append(True)
                return result

            with mock.patch.object(PIPELINE.subprocess, "run",
                                   side_effect=remove_attestation_after_real_analyzer):
                with self.assertRaises(PIPELINE.PipelineError):
                    PIPELINE.run_local_iblinkinfo(plan, "EXAMPLE-UFM01",
                                                  archive, cvt, project)
            self.assertEqual([True], analyzed)
            self.assertEqual([], PIPELINE.validated_receipts(project, "air"))
            self.assertIn("未知", HTML.render_ufm_evidence_panel(project, "air"))

    def test_node_directory_replacement_cannot_write_foreign_attestation(self):
        plan = COLLECTION.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            vendor_output = root / "iblinkinfo.txt"
            vendor_output.write_text(
                "Switch: 0x1 MF0;leaf01:MQM9700/U1:\n"
                ' 10 1[  ] ==( 4X 200 Gbps Active / LinkUp )==> '
                '20 1[  ] "server01 mlx5_0"\n', encoding="utf-8",
            )
            ufm_dir = root / "ufm-private"
            ufm_dir.mkdir()
            archive = COLLECTION.publish_local_archive(plan, vendor_output, ufm_dir)
            cvt = root / "cvt.xlsx"
            _write_cvt(cvt)
            project = root / "project"
            project.mkdir()
            outside = root / "outside"
            outside.mkdir()
            sentinel = outside / "sentinel"
            sentinel.write_bytes(b"external-original")
            target = project / "99-output-ufm" / "runs" / RUN_ID / "EXAMPLE-UFM01"
            retained = project / "retained-original-node"
            report_name = f"iblinkinfo_{RUN_ID}-topology-validation.xlsx"
            log_name = f"iblinkinfo_{RUN_ID}.log"
            real_copy = PIPELINE._copy_regular_to_at
            injected = []

            def rebind_node_after_copy(source, target_fd, name):
                real_copy(source, target_fd, name)
                if name == report_name and not injected:
                    (outside / report_name).write_bytes((target / report_name).read_bytes())
                    (outside / log_name).write_bytes((target / log_name).read_bytes())
                    target.rename(retained)
                    outside.rename(target)
                    injected.append(True)

            with mock.patch.object(PIPELINE, "_copy_regular_to_at",
                                   side_effect=rebind_node_after_copy):
                with self.assertRaises(PIPELINE.PipelineError):
                    PIPELINE.run_local_iblinkinfo(
                        plan, "EXAMPLE-UFM01", archive, cvt, project,
                    )
            self.assertEqual([True], injected)
            self.assertFalse(PROVENANCE.sidecar_path(target / report_name).exists())
            self.assertEqual(b"external-original", (target / "sentinel").read_bytes())
            self.assertEqual([], PIPELINE.validated_receipts(project, "air"))

    def test_concurrent_empty_target_cannot_be_replaced_by_publish(self):
        plan = COLLECTION.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            vendor_output = root / "iblinkinfo.txt"
            vendor_output.write_text(
                "Switch: 0x1 MF0;leaf01:MQM9700/U1:\n"
                ' 10 1[  ] ==( 4X 200 Gbps Active / LinkUp )==> '
                '20 1[  ] "server01 mlx5_0"\n',
                encoding="utf-8",
            )
            ufm_dir = root / "ufm-private"
            ufm_dir.mkdir()
            archive = COLLECTION.publish_local_archive(plan, vendor_output, ufm_dir)
            cvt = root / "cvt.xlsx"
            _write_cvt(cvt)
            project = root / "project"
            project.mkdir()
            target = project / "99-output-ufm" / "runs" / RUN_ID / "EXAMPLE-UFM01"
            real_mkdir = os.mkdir
            incumbent_inode = []

            def inject_target(path, mode=0o777, *, dir_fd=None):
                if Path(path).name == target.name and not incumbent_inode:
                    if dir_fd is None:
                        real_mkdir(path, mode)
                    else:
                        real_mkdir(path, mode, dir_fd=dir_fd)
                    incumbent_inode.append(target.stat().st_ino)
                if dir_fd is None:
                    return real_mkdir(path, mode)
                return real_mkdir(path, mode, dir_fd=dir_fd)

            with mock.patch.object(PIPELINE.os, "mkdir", side_effect=inject_target):
                with self.assertRaises(PIPELINE.PipelineError):
                    PIPELINE.run_local_iblinkinfo(
                        plan, "EXAMPLE-UFM01", archive, cvt, project
                    )
            self.assertEqual(incumbent_inode, [target.stat().st_ino])
            self.assertEqual([], list(target.iterdir()))
            self.assertEqual([], PIPELINE.validated_receipts(project, "air"))

    def test_existing_output_symlink_must_not_redirect_publish(self):
        plan = COLLECTION.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            vendor_output = root / "iblinkinfo.txt"
            vendor_output.write_text(
                "Switch: 0x1 MF0;leaf01:MQM9700/U1:\n"
                ' 10 1[  ] ==( 4X 200 Gbps Active / LinkUp )==> '
                '20 1[  ] "server01 mlx5_0"\n',
                encoding="utf-8",
            )
            ufm_dir = root / "ufm-private"
            ufm_dir.mkdir()
            archive = COLLECTION.publish_local_archive(plan, vendor_output, ufm_dir)
            cvt = root / "cvt.xlsx"
            _write_cvt(cvt)
            project = root / "project"
            project.mkdir()
            outside = root / "outside"
            outside.mkdir()
            (project / "99-output-ufm").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(PIPELINE.PipelineError):
                PIPELINE.run_local_iblinkinfo(plan, "EXAMPLE-UFM01", archive, cvt, project)
            self.assertEqual([], list(outside.iterdir()))

    def test_parent_rebind_during_handoff_cannot_write_outside_project(self):
        plan = COLLECTION.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            vendor_output = root / "iblinkinfo.txt"
            vendor_output.write_text(
                "Switch: 0x1 MF0;leaf01:MQM9700/U1:\n"
                ' 10 1[  ] ==( 4X 200 Gbps Active / LinkUp )==> '
                '20 1[  ] "server01 mlx5_0"\n', encoding="utf-8",
            )
            ufm_dir = root / "ufm-private"
            ufm_dir.mkdir()
            archive = COLLECTION.publish_local_archive(plan, vendor_output, ufm_dir)
            cvt = root / "cvt.xlsx"
            _write_cvt(cvt)
            project = root / "project"
            project.mkdir()
            outside = root / "outside"
            outside.mkdir()
            sentinel = outside / "sentinel"
            sentinel.write_bytes(b"external-original")
            real_mkdir = os.mkdir
            injected = []

            def swap_parent_after_create(path, mode=0o777, *, dir_fd=None):
                if dir_fd is None:
                    real_mkdir(path, mode)
                else:
                    real_mkdir(path, mode, dir_fd=dir_fd)
                if Path(path).name == "99-output-ufm" and not injected:
                    child = project / "99-output-ufm"
                    child.rename(project / "retained-original-output")
                    child.symlink_to(outside, target_is_directory=True)
                    injected.append(True)

            with mock.patch.object(PIPELINE.os, "mkdir", side_effect=swap_parent_after_create):
                with self.assertRaises(PIPELINE.PipelineError):
                    PIPELINE.run_local_iblinkinfo(plan, "EXAMPLE-UFM01", archive, cvt, project)
            self.assertEqual([True], injected)
            self.assertEqual(b"external-original", sentinel.read_bytes())
            self.assertEqual([sentinel], list(outside.iterdir()))
            self.assertEqual([], PIPELINE.validated_receipts(project, "air"))
            self.assertIn("未知", HTML.render_ufm_evidence_panel(project, "air"))

    def test_project_root_rebind_during_handoff_cannot_publish_outside(self):
        plan = COLLECTION.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            vendor_output = root / "iblinkinfo.txt"
            vendor_output.write_text(
                "Switch: 0x1 MF0;leaf01:MQM9700/U1:\n"
                ' 10 1[  ] ==( 4X 200 Gbps Active / LinkUp )==> '
                '20 1[  ] "server01 mlx5_0"\n', encoding="utf-8",
            )
            ufm_dir = root / "ufm-private"
            ufm_dir.mkdir()
            archive = COLLECTION.publish_local_archive(plan, vendor_output, ufm_dir)
            cvt = root / "cvt.xlsx"
            _write_cvt(cvt)
            project = root / "project"
            project.mkdir()
            outside = root / "retained-original-project"
            real_prepare = PIPELINE._prepare_output_parents
            injected = []

            def swap_root_before_publish(*args, **kwargs):
                if not injected:
                    project.rename(outside)
                    project.mkdir()
                    injected.append(True)
                return real_prepare(*args, **kwargs)

            with mock.patch.object(PIPELINE, "_prepare_output_parents",
                                   side_effect=swap_root_before_publish):
                with self.assertRaises(PIPELINE.PipelineError):
                    PIPELINE.run_local_iblinkinfo(plan, "EXAMPLE-UFM01", archive, cvt, project)
            self.assertEqual([True], injected)
            self.assertEqual([], list(project.iterdir()), "replacement project must stay untouched")

    def test_private_stage_cleanup_failure_cannot_publish_success_receipt(self):
        plan = COLLECTION.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            vendor_output = root / "iblinkinfo.txt"
            vendor_output.write_text(
                "Switch: 0x1 MF0;leaf01:MQM9700/U1:\n"
                ' 10 1[  ] ==( 4X 200 Gbps Active / LinkUp )==> '
                '20 1[  ] "server01 mlx5_0"\n',
                encoding="utf-8",
            )
            ufm_dir = root / "ufm-private"
            ufm_dir.mkdir()
            archive = COLLECTION.publish_local_archive(plan, vendor_output, ufm_dir)
            cvt = root / "cvt.xlsx"
            _write_cvt(cvt)
            project = root / "project"
            project.mkdir()
            with mock.patch.object(PIPELINE.shutil, "rmtree", side_effect=OSError("injected cleanup")):
                with self.assertRaises((OSError, PIPELINE.PipelineError)):
                    PIPELINE.run_local_iblinkinfo(
                        plan, "EXAMPLE-UFM01", archive, cvt, project
                    )
            self.assertEqual([], PIPELINE.validated_receipts(project, "air"))


if __name__ == "__main__":
    unittest.main()
