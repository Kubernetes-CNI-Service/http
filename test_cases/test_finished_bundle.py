#!/usr/bin/env python3
"""Direct contracts for producing and verifying finished-project bundles."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

from tools import finished_bundle


ROOT = Path(__file__).resolve().parents[1]
IMPORTER_PATH = ROOT / "tools/import-from-download.py"


def load_importer():
    spec = importlib.util.spec_from_file_location(
        "finished_bundle_importer", IMPORTER_PATH,
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FinishedBundleTests(unittest.TestCase):
    def test_final_delta_records_create_replace_delete_and_mode_change(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            before = root / "before"
            after = root / "after"
            output = root / "delta"
            before.mkdir()
            after.mkdir()
            (before / "keep.txt").write_text("keep\n", encoding="utf-8")
            (before / "delete.txt").write_text("old\n", encoding="utf-8")
            (before / "replace.txt").write_text("before\n", encoding="utf-8")
            (before / "mode.txt").write_text("mode\n", encoding="utf-8")
            (after / "keep.txt").write_text("keep\n", encoding="utf-8")
            (after / "replace.txt").write_text("after\n", encoding="utf-8")
            (after / "mode.txt").write_text("mode\n", encoding="utf-8")
            (after / "mode.txt").chmod(0o755)
            (after / "create.txt").write_text("new\n", encoding="utf-8")

            manifest_path, archive_path = finished_bundle.build_final_delta(
                before, after, output,
            )

            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            actions = {
                row["path"]: row["action"] for row in manifest["changes"]
            }
            self.assertEqual({
                "create.txt": "create",
                "delete.txt": "delete",
                "mode.txt": "replace",
                "replace.txt": "replace",
            }, actions)
            with tarfile.open(archive_path, "r:gz") as archive:
                self.assertEqual(
                    {"delta", "delta/create.txt", "delta/mode.txt", "delta/replace.txt"},
                    set(archive.getnames()),
                )

    def test_bundle_generated_from_pre_and_post_views_is_importer_compatible(self):
        importer = load_importer()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            project = root / "project"
            post = root / "post"
            source = root / "source"
            project.mkdir()
            post.mkdir()
            source.mkdir()
            (project / "02-devices_config.csv").write_text(
                "hostname,type\nleaf01,cumulus\n", encoding="utf-8",
            )
            (project / "99-output-ztp").mkdir()
            (project / "99-output-ztp/status.json").write_text(
                '{"phase":"running"}\n', encoding="utf-8",
            )
            (post / "02-devices_config.csv").write_bytes(
                (project / "02-devices_config.csv").read_bytes()
            )
            (post / "99-output-ztp").mkdir()
            (post / "99-output-ztp/status.json").write_text(
                '{"phase":"stopped"}\n', encoding="utf-8",
            )
            (source / "tool.py").write_text("print('frozen')\n", encoding="utf-8")
            destination = root / "finished.tar.gz"

            result = finished_bundle.create_finished_bundle(
                project="customer",
                transaction_id="finish-20260916T081150Z-001",
                runtime="native",
                created_at="2026-09-16T08:11:50Z",
                pre_stop_project=project,
                post_stop_project=post,
                deployment_source=source,
                host_state={"runtime": "native", "stopped": True},
                deployment_footprint={"schema_version": 1, "paths": []},
                deletion_plan={"schema_version": 1, "items": []},
                output=destination,
            )
            self.assertEqual(destination, result.path)
            self.assertTrue(result.record_id.startswith("20260916T081150Z-"))

            review = root / "review"
            finished = root / "records"
            output = io.StringIO()
            with mock.patch.object(importer, "ROOT", root), \
                    mock.patch.object(importer, "DAY0", root / "DAY0-Prepare"), \
                    mock.patch.object(importer, "FINISHED_ROOT", finished), \
                    redirect_stdout(output), redirect_stderr(output):
                (root / "DAY0-Prepare").mkdir()
                code = importer.main([
                    str(destination), "--review-root", str(review), "--review-only",
                ])
            self.assertEqual(0, code, output.getvalue())
            reconstructed = next(review.iterdir()) / "reconstructed-final"
            self.assertEqual(
                b'{"phase":"stopped"}\n',
                (reconstructed / "99-output-ztp/status.json").read_bytes(),
            )

    def test_archive_rejects_hardlinks_and_escaping_symlinks(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            project = root / "project"
            project.mkdir()
            primary = project / "input.txt"
            primary.write_text("input\n", encoding="utf-8")
            os.link(primary, project / "hardlink.txt")
            with self.assertRaisesRegex(finished_bundle.BundleError, "hard link"):
                finished_bundle.inventory_tree(project)
            (project / "hardlink.txt").unlink()
            (project / "escape").symlink_to(root / "outside")
            with self.assertRaisesRegex(finished_bundle.BundleError, "symlink"):
                finished_bundle.inventory_tree(project)

    def test_published_bundle_can_be_reverified_without_trusting_receipt(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            before = root / "before"
            after = root / "after"
            source = root / "source"
            before.mkdir()
            after.mkdir()
            source.mkdir()
            (before / "input.txt").write_text("before\n", encoding="utf-8")
            (after / "input.txt").write_text("after\n", encoding="utf-8")
            (source / "tool.py").write_text("pass\n", encoding="utf-8")
            output = root / "finished.tar.gz"
            created = finished_bundle.create_finished_bundle(
                project="customer",
                transaction_id="finish-20260916T082220Z-verify0000000001",
                runtime="native",
                created_at="2026-09-16T08:22:20Z",
                pre_stop_project=before,
                post_stop_project=after,
                deployment_source=source,
                host_state={"runtime_stopped": True},
                deployment_footprint={"schema_version": 1, "paths": []},
                deletion_plan={"schema_version": 1, "automatic_deletion": False},
                output=output,
            )

            verified = finished_bundle.verify_finished_bundle(
                output,
                expected_project="customer",
                expected_transaction_id="finish-20260916T082220Z-verify0000000001",
                expected_runtime="native",
                expected_created_at="2026-09-16T08:22:20Z",
            )
            self.assertEqual(created, verified)
            output.write_bytes(output.read_bytes() + b"tampered")
            with self.assertRaises(finished_bundle.BundleError):
                finished_bundle.verify_finished_bundle(
                    output,
                    expected_project="customer",
                    expected_transaction_id="finish-20260916T082220Z-verify0000000001",
                    expected_runtime="native",
                    expected_created_at="2026-09-16T08:22:20Z",
                )


if __name__ == "__main__":
    unittest.main()
