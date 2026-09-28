"""D-70 ibdiagnet handoff must reject unsafe or unbound local inputs."""

from __future__ import annotations

from pathlib import Path
import hashlib
import tarfile
import tempfile
import unittest

from tools import ufm_collection_pipeline as pipeline
from tools.ufm_collection_contract import collection_plan


RUN_ID = "20260926-0315-air-0123456789abcdef"


class UfmIbdiagnetPipelineDirectTests(unittest.TestCase):
    def test_cli_kind_selector_rejects_untrusted_archive_without_receipt(self):
        plan = collection_plan("ibdiagnet", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            archive = root / plan.archive_name
            archive.write_bytes(b"untrusted")
            cvt = root / "cvt.xlsx"
            cvt.write_bytes(b"independent-input")
            project = root / "project"
            project.mkdir()
            self.assertEqual(1, pipeline.main([
                "--kind", "ibdiagnet", "--run-id", RUN_ID,
                "--node", "EXAMPLE-UFM01", "--archive", str(archive),
                "--cvt", str(cvt), "--project", str(project),
            ]))
            self.assertFalse((project / "99-output-ufm").exists())

    def test_private_panel_candidate_uses_exact_ibdiagnet_names(self):
        from test_cases.module_loader import load_script
        html = load_script("ufm_ibdiagnet_candidate_direct", Path(__file__).resolve().parents[1]
                           / "monitor/generate-monitor-html.py")
        candidate = {
            "schema": "ufm-collection-v1", "status": "success", "kind": "ibdiagnet",
            "run_id": RUN_ID, "node": "EXAMPLE-UFM01",
            "archive": f"ibdiagnet2_{RUN_ID}.tar.gz",
            "archive_sha256": hashlib.sha256(b"archive").hexdigest(),
            "report": f"ibdiagnet2_{RUN_ID}-topology-validation.xlsx",
            "report_sha256": hashlib.sha256(b"report").hexdigest(),
            "report_provenance_sha256": hashlib.sha256(b"sidecar").hexdigest(),
        }
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            preview = html.render_ufm_candidate_panel(project, "air", candidate)
            self.assertIn("ibdiagnet", preview)
            self.assertFalse((project / "99-output-ufm").exists())
            with self.assertRaises(ValueError):
                html.render_ufm_candidate_panel(project, "air", {
                    **candidate, "archive": f"iblinkinfo_{RUN_ID}.tar.gz",
                })

    def test_wrong_kind_or_name_is_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            project = root / "project"
            project.mkdir()
            cvt = root / "cvt.xlsx"
            cvt.write_bytes(b"independent-input")
            archive = root / "wrong.tar.gz"
            archive.write_bytes(b"not-a-valid-archive")
            for plan in (collection_plan("iblinkinfo", RUN_ID),
                         collection_plan("ibdiagnet", RUN_ID)):
                with self.subTest(plan=plan.kind), self.assertRaises(pipeline.PipelineError):
                    pipeline.run_local_ibdiagnet(plan, "EXAMPLE-UFM01", archive, cvt, project)
            self.assertFalse((project / "99-output-ufm").exists())

    def test_archive_requires_one_real_snapshot_not_symlinks_or_traversal(self):
        plan = collection_plan("ibdiagnet", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            project = root / "project"
            project.mkdir()
            cvt = root / "cvt.xlsx"
            cvt.write_bytes(b"independent-input")
            archive = root / plan.archive_name
            for name, kind in (("../escape", "file"),
                               ("artifact/ibdiagnet2.net_dump", "symlink"),
                               ("artifact/unrelated", "file")):
                with self.subTest(name=name, kind=kind):
                    with tarfile.open(archive, "w:gz") as bundle:
                        info = tarfile.TarInfo(name)
                        if kind == "symlink":
                            info.type = tarfile.SYMTYPE
                            info.linkname = "/etc/passwd"
                            bundle.addfile(info)
                        else:
                            import io
                            data = b"synthetic-input"
                            info.size = len(data)
                            bundle.addfile(info, io.BytesIO(data))
                    with self.assertRaises(pipeline.PipelineError):
                        pipeline.run_local_ibdiagnet(
                            plan, "EXAMPLE-UFM01", archive, cvt, project)
                    self.assertFalse((project / "99-output-ufm").exists())


if __name__ == "__main__":
    unittest.main()
