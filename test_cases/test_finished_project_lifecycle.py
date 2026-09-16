#!/usr/bin/env python3
"""Workflow contracts for finished-record import and deployment isolation."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
from pathlib import Path, PurePosixPath
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

from test_cases.test_finished_project_import import build_finished_bundle


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


IMPORTER = load_module("finished_lifecycle_importer", ROOT / "tools/import-from-download.py")
PACKAGE = load_module("finished_lifecycle_package", ROOT / "tools/_package_common.py")
CONTRACT = load_module("finished_lifecycle_contract", ROOT / "tools/project_contract.py")


class FinishedProjectLifecycleWorkflowTests(unittest.TestCase):
    def test_finished_record_is_excluded_after_real_import_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "http"
            day0 = workspace / "DAY0-Prepare"
            project = day0 / "customer"
            review_root = workspace / "package-imports"
            finished_root = workspace / "Finished-projects"
            project.mkdir(parents=True)
            (project / "02-devices_config.csv").write_text("hostname,type\n", encoding="utf-8")
            archive = workspace / "incoming-finished.tar.gz"
            record_id, _manifest = build_finished_bundle(archive)
            output = io.StringIO()
            with (
                mock.patch.object(IMPORTER, "ROOT", workspace),
                mock.patch.object(IMPORTER, "DAY0", day0),
                mock.patch.object(IMPORTER, "FINISHED_ROOT", finished_root, create=True),
                redirect_stdout(output),
                redirect_stderr(output),
            ):
                result = IMPORTER.main([
                    str(archive), "--review-root", str(review_root), "--finish",
                ])
            self.assertEqual(0, result, output.getvalue())
            record = finished_root / "customer" / record_id
            self.assertTrue(record.is_dir())
            history = project / "finished-history" / record_id
            self.assertTrue(history.is_symlink())
            self.assertEqual(record.resolve(), history.resolve())

            relative = PurePosixPath(
                f"Finished-projects/customer/{record_id}/bundle-manifest.json"
            )
            self.assertEqual("finished project archive", CONTRACT.transfer_exclude_reason(relative))
            self.assertIn("Finished-projects/", CONTRACT.rsync_excludes())
            self.assertIn("finished-history/", CONTRACT.rsync_excludes())
            self.assertEqual(
                "finished project history link",
                PACKAGE.classify_project_entry(PurePosixPath(f"finished-history/{record_id}")),
            )

            output_archive = workspace / "workspace-upload.tar.gz"
            with mock.patch.multiple(
                PACKAGE,
                ROOT=workspace,
                DAY0=day0,
                MANIFEST=workspace / "ztp/.setup_manifest",
            ):
                package_filter = PACKAGE.PackageFilter(
                    project,
                    output_archive,
                    include_images=False,
                    include_apps=False,
                    include_firmware=False,
                    max_file_size=1024 * 1024,
                    day0_all=True,
                )
                with tarfile.open(output_archive, "w:gz") as outgoing:
                    for source in sorted(workspace.iterdir()):
                        outgoing.add(
                            source,
                            arcname=f"./{source.name}",
                            recursive=True,
                            filter=package_filter,
                        )
            with tarfile.open(output_archive, "r:gz") as outgoing:
                names = set(outgoing.getnames())
            self.assertFalse(
                any(name.removeprefix("./").startswith("Finished-projects") for name in names)
            )
            self.assertFalse(any("finished-history" in name for name in names))

    def test_finished_root_is_not_a_deployment_project_or_docker_context(self):
        load = load_module("finished_lifecycle_load", ROOT / "DAY0-Prepare/11-load.py")
        with self.assertRaises(load.LoadError):
            load.resolve_project(str(ROOT / "Finished-projects/customer/record"))
        dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")
        self.assertIn("Finished-projects/**", dockerignore)
        self.assertNotIn("!Finished-projects", dockerignore)


if __name__ == "__main__":
    unittest.main()
