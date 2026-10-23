#!/usr/bin/env python3
"""Direct contracts for the central repository path-disposition authority."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import project_contract as CONTRACT  # noqa: E402


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
# The owner's CableTracker reference project (2026-10-23).  Its contents are
# refreshed by the owner (a downloaded online tracker, instance files), so
# only its disposition is pinned here, never its file list.
CABLETRACKER_LLDPQ_ROOT = "tools/cabletracker"
CABLETRACKER_LLDPQ_SAMPLE_PATHS = (
    "tools/cabletracker/cabletracker_runner.py",
    "tools/cabletracker/ibdiagnet/generate_report.py",
    "tools/cabletracker/online_Issue_Tracker.xlsx",
    "tools/cabletracker/tests/test_lldpq_source.py",
)


def disposition(value: str) -> str:
    classifier = getattr(CONTRACT, "path_disposition", None)
    if classifier is None:
        return "MISSING-CENTRAL-PATH-DISPOSITION"
    return classifier(value)


class ReferenceOnlyPathDispositionTests(unittest.TestCase):
    def test_exact_cabletracker_inventory_is_reference_only(self):
        root = ROOT / "monitor/cabletracker-main"
        actual = tuple(sorted(
            path.relative_to(ROOT).as_posix()
            for path in root.rglob("*")
            if path.is_file() or path.is_symlink()
        ))
        # The owner may retain this precise reference-only tree in the live
        # checkout; it is intentionally absent from the published candidate.
        if root.exists():
            self.assertTrue(root.is_dir())
            self.assertFalse(root.is_symlink())
            self.assertEqual(tuple(sorted(CABLETRACKER_REFERENCE_PATHS)), actual)
        else:
            self.assertEqual((), actual)
        self.assertEqual(
            frozenset({"monitor/cabletracker-main", CABLETRACKER_LLDPQ_ROOT}),
            getattr(CONTRACT, "REFERENCE_ONLY_SUBTREES", frozenset()),
        )
        self.assertEqual("reference-only", disposition("monitor/cabletracker-main"))
        for relative in CABLETRACKER_REFERENCE_PATHS:
            with self.subTest(relative=relative):
                self.assertEqual("reference-only", disposition(relative))
                self.assertEqual(
                    "reference-only input",
                    CONTRACT.transfer_exclude_reason(relative),
                )

    def test_cabletracker_lldpq_reference_project_never_ships(self):
        root = ROOT / CABLETRACKER_LLDPQ_ROOT
        if root.exists():
            self.assertTrue(root.is_dir())
            self.assertFalse(root.is_symlink())
        present = tuple(sorted(
            path.relative_to(ROOT).as_posix()
            for path in root.rglob("*")
            if path.is_file() or path.is_symlink()
        ))
        self.assertEqual("reference-only", disposition(CABLETRACKER_LLDPQ_ROOT))
        # Code, the downloaded workbook and the project's own tests alike:
        # reference-only wins over the nondeployment test-directory rule.
        for relative in CABLETRACKER_LLDPQ_SAMPLE_PATHS + present:
            with self.subTest(relative=relative):
                self.assertEqual("reference-only", disposition(relative))
                self.assertEqual(
                    "reference-only input",
                    CONTRACT.transfer_exclude_reason(relative),
                )

    def test_test_directories_and_production_paths_share_one_disposition(self):
        expected = {
            "test_cases/test_reference_only_path_disposition.py": "nondeployment",
            "monitor/runtime/tests/test_component.py": "nondeployment",
            "monitor/runtime/test/fixture.json": "nondeployment",
            "monitor/generate-monitor-html.py": "production",
            "monitor/cabletracker-mainline/runtime.py": "production",
            "monitor/cabletracker-main-sibling/runtime.py": "production",
            "tools/cabletracker-lldpq-sync/runtime.py": "production",
            "tools/cabletracker/runtime.py": "production",
        }
        self.assertEqual(
            expected,
            {relative: disposition(relative) for relative in expected},
        )

    def test_nonrelative_or_ambiguous_paths_fail_closed(self):
        classifier = getattr(CONTRACT, "path_disposition", lambda _value: None)
        for hostile in (
            "/monitor/generate-monitor-html.py",
            "../monitor/generate-monitor-html.py",
            "monitor/../tools/runtime.py",
            "monitor/runtime.py\0reference",
        ):
            with self.subTest(hostile=hostile):
                with self.assertRaises((TypeError, ValueError)):
                    classifier(hostile)


if __name__ == "__main__":
    unittest.main()
