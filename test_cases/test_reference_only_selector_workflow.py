#!/usr/bin/env python3
"""Workflow contracts binding every deployment selector to one disposition."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
DOCKER = ROOT / "infra/docker"
for directory in (TOOLS, DOCKER):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

import project_contract as CONTRACT  # noqa: E402


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


SYNC = load_module("reference_only_sync", ROOT / "tools/sync-code.py")
ARCHIVE = load_module("reference_only_archive", ROOT / "tools/_package_common.py")
ACTIVATE = load_module("reference_only_activate", ROOT / "infra/docker/activate.py")
RUNNER = load_module("reference_only_runner", ROOT / "test_cases/run_related_tests.py")


CABLETRACKER_REFERENCE_PATHS = (
    "monitor/cabletracker-main/.env.example",
    "monitor/cabletracker-main/.gitignore",
    "monitor/cabletracker-main/.gitlab-ci.yml",
    "monitor/cabletracker-main/Dockerfile",
    "monitor/cabletracker-main/README.md",
    "monitor/cabletracker-main/cabletracker_runner.py",
    "monitor/cabletracker-main/docker-compose.yaml",
    "monitor/cabletracker-main/mapping_v4.json",
    "monitor/cabletracker-main/refresh_cvt_sum.py",
    "monitor/cabletracker-main/requirements.txt",
    "monitor/cabletracker-main/tests/fixtures/cvt_offline_sample.json",
    "monitor/cabletracker-main/tests/test_cvt_sum.py",
    "monitor/cabletracker-main/tests/test_offline_workflow.py",
    "monitor/cabletracker-main/tmp.json",
)


def package_filter(root: Path, project: Path, output: Path):
    with mock.patch.multiple(
        ARCHIVE,
        ROOT=root,
        DAY0=root / "DAY0-Prepare",
        MANIFEST=root / "ztp/.setup_manifest",
    ):
        return ARCHIVE.PackageFilter(
            project,
            output,
            include_images=False,
            include_apps=False,
            include_firmware=False,
            max_file_size=1024 * 1024,
            day0_all=False,
            artifact_kind="upload",
        )


def selected_by_package_filter(filter_, relative: str) -> bool:
    info = tarfile.TarInfo(relative)
    info.type = tarfile.REGTYPE
    info.mode = 0o644
    info.size = 1
    return filter_(info) is not None


def directory_selected_by_package_filter(filter_, relative: str) -> bool:
    info = tarfile.TarInfo(relative)
    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    info.size = 0
    return filter_(info) is not None


class ReferenceOnlySelectorWorkflowTests(unittest.TestCase):
    def test_real_transfer_image_archive_and_runner_exclude_exact_reference_tree(self):
        expected = set(CABLETRACKER_REFERENCE_PATHS)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "upload.tar.gz"
            archive_filter = package_filter(
                ROOT, ROOT / "DAY0-Prepare/template", output,
            )
            archive_selected = {
                relative for relative in expected
                if selected_by_package_filter(archive_filter, relative)
            }

        cable_root = ROOT / "monitor/cabletracker-main"
        transfer_selected = {
            path.relative_to(ROOT).as_posix()
            for path in SYNC.matching_files(cable_root, ("**/*", ".*"))
        }
        image_selected = set(ACTIVATE.image_source_paths(ROOT)) & expected
        runner_selected = set(RUNNER.discover_source_scripts(ROOT)) & expected
        self.assertEqual(
            {
                "archive": set(),
                "transfer": set(),
                "image": set(),
                "runner": set(),
            },
            {
                "archive": archive_selected,
                "transfer": transfer_selected,
                "image": image_selected,
                "runner": runner_selected,
            },
        )

        production = "monitor/generate-monitor-html.py"
        self.assertIn(production, ACTIVATE.image_source_paths(ROOT))
        self.assertIn(production, RUNNER.discover_source_scripts(ROOT))
        self.assertIn(
            ROOT / production,
            SYNC.matching_files(ROOT / "monitor", ("*.py",)),
        )
        with tempfile.TemporaryDirectory() as directory:
            archive_filter = package_filter(
                ROOT, ROOT / "DAY0-Prepare/template",
                Path(directory) / "upload.tar.gz",
            )
            self.assertTrue(selected_by_package_filter(archive_filter, production))

    def test_patched_central_reference_subtree_updates_all_real_consumers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "DAY0-Prepare/project"
            project.mkdir(parents=True)
            monitor = root / "monitor"
            reference = monitor / "vendor-reference"
            reference.mkdir(parents=True)
            nondeployment = monitor / "qa-fixtures"
            nondeployment.mkdir(parents=True)
            sibling = monitor / "qa-fixtures-sibling"
            sibling.mkdir(parents=True)
            runtime = monitor / "runtime.py"
            opaque = reference / "opaque.runtime.py"
            fixture = nondeployment / "opaque.runtime.py"
            sibling_runtime = sibling / "runtime.py"
            runtime.write_text("RUNTIME = True\n", encoding="utf-8")
            opaque.write_text("REFERENCE = True\n", encoding="utf-8")
            fixture.write_text("FIXTURE = True\n", encoding="utf-8")
            sibling_runtime.write_text("SIBLING = True\n", encoding="utf-8")

            reference_subtrees = getattr(
                CONTRACT, "REFERENCE_ONLY_SUBTREES", frozenset(),
            ) | {"monitor/vendor-reference"}
            with mock.patch.object(
                CONTRACT, "REFERENCE_ONLY_SUBTREES", reference_subtrees,
                create=True,
            ), mock.patch.object(
                CONTRACT,
                "NON_DEPLOYMENT_DIR_NAMES",
                getattr(CONTRACT, "NON_DEPLOYMENT_DIR_NAMES", frozenset())
                | {"qa-fixtures"},
                create=True,
            ), mock.patch.object(SYNC, "ROOT", root), mock.patch.multiple(
                ACTIVATE,
                IMAGE_SOURCE_SCAN_ROOTS=("monitor",),
                IMAGE_SOURCE_EXCLUDED_PREFIXES=(),
                IMAGE_SOURCE_EXCLUDED_PATHS=frozenset(),
            ):
                archive_filter = package_filter(
                    root, project, root / "upload.tar.gz",
                )
                selected = {
                    "archive": selected_by_package_filter(
                        archive_filter, "monitor/vendor-reference/opaque.runtime.py",
                    ),
                    "transfer": opaque in SYNC.matching_files(
                        monitor, ("**/*.py",),
                    ),
                    "image": "monitor/vendor-reference/opaque.runtime.py"
                    in ACTIVATE.image_source_paths(root),
                    "runner": "monitor/vendor-reference/opaque.runtime.py"
                    in RUNNER.discover_source_scripts(root),
                }
                nondeployment_selected = {
                    "archive": selected_by_package_filter(
                        archive_filter, "monitor/qa-fixtures/opaque.runtime.py",
                    ),
                    "transfer": fixture in SYNC.matching_files(
                        monitor, ("**/*.py",),
                    ),
                    "image": "monitor/qa-fixtures/opaque.runtime.py"
                    in ACTIVATE.image_source_paths(root),
                    "runner": "monitor/qa-fixtures/opaque.runtime.py"
                    in RUNNER.discover_source_scripts(root),
                }
                retained = {
                    "archive": selected_by_package_filter(
                        archive_filter, "monitor/runtime.py",
                    ),
                    "transfer": runtime in SYNC.matching_files(
                        monitor, ("**/*.py",),
                    ),
                    "image": "monitor/runtime.py" in ACTIVATE.image_source_paths(root),
                    "runner": "monitor/runtime.py"
                    in RUNNER.discover_source_scripts(root),
                }
                sibling_retained = {
                    "archive": selected_by_package_filter(
                        archive_filter, "monitor/qa-fixtures-sibling/runtime.py",
                    ),
                    "transfer": sibling_runtime in SYNC.matching_files(
                        monitor, ("**/*.py",),
                    ),
                    "image": "monitor/qa-fixtures-sibling/runtime.py"
                    in ACTIVATE.image_source_paths(root),
                    "runner": "monitor/qa-fixtures-sibling/runtime.py"
                    in RUNNER.discover_source_scripts(root),
                }
                directory_headers = {
                    "reference": directory_selected_by_package_filter(
                        archive_filter, "monitor/vendor-reference",
                    ),
                    "nondeployment": directory_selected_by_package_filter(
                        archive_filter, "monitor/qa-fixtures",
                    ),
                }

            self.assertEqual(
                {"archive": False, "transfer": False, "image": False, "runner": False},
                selected,
            )
            self.assertEqual(
                {"archive": False, "transfer": False, "image": False, "runner": False},
                nondeployment_selected,
            )
            self.assertEqual(
                {"archive": True, "transfer": True, "image": True, "runner": True},
                retained,
            )
            self.assertEqual(
                {"archive": True, "transfer": True, "image": True, "runner": True},
                sibling_retained,
            )
            self.assertEqual(
                {"reference": False, "nondeployment": False},
                directory_headers,
            )

    def test_manifest_audit_uses_central_reference_disposition(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in (
                "monitor/runtime.py",
                "tools/runtime.py",
                "monitor/vendor-reference/opaque.runtime.py",
                "test_cases/test_dummy.py",
                "README.support",
            ):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("VALUE = True\n", encoding="utf-8")
            test_id = "test_cases.test_dummy"
            scripts = {
                "monitor/runtime.py": "monitor/runtime.py",
                "tools/runtime.py": "tools/runtime.py",
            }
            manifest = {
                "schema_version": 1,
                "baseline_tests": [test_id],
                "tracked_support": ["README.support"],
                "scripts": scripts,
                "test_rules": [{
                    "id": "runtime-direct",
                    "paths": ["monitor/*.py", "tools/*.py"],
                    "tests": [test_id],
                }],
                "workflows": [{
                    "id": "runtime-workflow",
                    "members": ["monitor/*.py", "tools/*.py"],
                    "tests": [test_id],
                }],
                "path_rules": [{
                    "paths": ["README.support"],
                    "tests": [test_id],
                }],
                "test_suites": [{
                    "id": "runtime",
                    "description": "isolated reference disposition fixture",
                    "tests": [test_id],
                }],
            }
            manifest_path = root / "test_cases/script_test_manifest.json"
            manifest_path.write_text(
                json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8",
            )
            reference_subtrees = getattr(
                CONTRACT, "REFERENCE_ONLY_SUBTREES", frozenset(),
            ) | {"monitor/vendor-reference"}
            with mock.patch.object(
                CONTRACT, "REFERENCE_ONLY_SUBTREES", reference_subtrees,
                create=True,
            ), mock.patch.object(
                RUNNER, "deployment_authority_paths", return_value=set(scripts),
            ):
                try:
                    validated = RUNNER.load_and_validate_manifest(root, manifest_path)
                except RUNNER.ImpactError as exc:
                    self.fail(f"manifest audit did not use central disposition: {exc}")
            self.assertEqual(scripts, validated["scripts"])

    def test_consumers_do_not_own_reference_prefix_tables(self):
        for relative in (
            "tools/sync-code.py",
            "tools/_package_common.py",
            "infra/docker/activate.py",
            "test_cases/run_related_tests.py",
        ):
            with self.subTest(relative=relative):
                source = (ROOT / relative).read_text(encoding="utf-8")
                self.assertNotIn("cabletracker-main", source.casefold())


if __name__ == "__main__":
    unittest.main()
