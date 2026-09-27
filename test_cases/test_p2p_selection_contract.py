#!/usr/bin/env python3
"""REQ-15 direct contracts for selecting one project-root P2P workbook."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]


def load_day0():
    spec = importlib.util.spec_from_file_location(
        "req15_direct_day0", ROOT / "DAY0-Prepare/11-load.py",
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(spec.name)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        if previous is None:
            sys.modules.pop(spec.name, None)
        else:
            sys.modules[spec.name] = previous
    return module


def workbook(path: Path, *, mtime_ns: int = 1_700_000_000_000_000_000) -> Path:
    """Create a small valid XLSX independently of the selector under test."""
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("xl/workbook.xml", "<workbook/>")
    os.utime(path, ns=(mtime_ns, mtime_ns))
    return path


class P2PSelectionContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.load = load_day0()

    def test_project_root_only_excludes_old_subdirectory_and_ip_assignment(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            expected = workbook(project / "Fabric P2P_v2.1.xlsx")
            workbook(project / "ip assignment_v99.9.xlsx")
            nested = project / "p2p"
            nested.mkdir()
            workbook(nested / "Fabric P2P_v999.9.xlsx")
            self.assertEqual(expected, self.load.select_p2p(project))

    def test_root_candidate_filter_ignores_temporary_empty_and_canonical(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            expected = workbook(project / "rack P2P_v2.1.xlsx")
            workbook(project / "~$rack P2P_v99.9.xlsx")
            workbook(project / "._rack P2P_v98.9.xlsx")
            (project / "rack P2P_v97.9.xlsx").touch()
            workbook(project / "p2p.xlsx")
            self.assertEqual(expected, self.load.select_p2p(project))

    def test_single_unversioned_candidate_needs_no_comparison(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            expected = workbook(project / "renamed P2P workbook.xlsx")
            self.assertEqual(expected, self.load.select_p2p(project))

    def test_symlinked_root_candidate_does_not_count_as_regular(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            expected = workbook(project / "Fabric P2P_v1.0.xlsx")
            (project / "Fabric P2P_v99.0.xlsx").symlink_to(expected.name)
            self.assertEqual(expected, self.load.select_p2p(project))

    def test_numeric_version_beats_mtime_and_lexical_order(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            workbook(project / "Fabric P2P_v2.9.xlsx", mtime_ns=1_900_000_000_000_000_000)
            expected = workbook(project / "Fabric P2P_v2.10.xlsx", mtime_ns=1_600_000_000_000_000_000)
            self.assertEqual(expected, self.load.select_p2p(project))

    def test_newer_valid_date_precedes_mtime_when_versions_equal(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            workbook(project / "Fabric P2P_v2.1_2026-09-06.xlsx", mtime_ns=1_900_000_000_000_000_000)
            expected = workbook(project / "Fabric P2P_v2.1_2026-0915.xlsx", mtime_ns=1_600_000_000_000_000_000)
            self.assertEqual(expected, self.load.select_p2p(project))

    def test_dated_candidate_beats_undated_at_same_version(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            workbook(project / "Fabric P2P_v2.1.xlsx", mtime_ns=1_900_000_000_000_000_000)
            expected = workbook(project / "Fabric P2P_v2.1_2026-0915.xlsx", mtime_ns=1_600_000_000_000_000_000)
            self.assertEqual(expected, self.load.select_p2p(project))

    def test_mtime_breaks_equal_version_and_date(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            workbook(project / "Fabric P2P_v2.1_2026-0915-A.xlsx", mtime_ns=1_600_000_000_000_000_000)
            expected = workbook(project / "Fabric P2P_v2.1_2026-0915-B.xlsx", mtime_ns=1_700_000_000_000_000_000)
            self.assertEqual(expected, self.load.select_p2p(project))

    def test_equal_version_date_and_mtime_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            workbook(project / "Fabric P2P_v2.1_2026-0915-A.xlsx")
            workbook(project / "Fabric P2P_v2.1_2026-0915-B.xlsx")
            with self.assertRaises(self.load.LoadError):
                self.load.select_p2p(project)

    def test_invalid_calendar_date_fails_instead_of_becoming_undated(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            workbook(project / "Fabric P2P_v2.1_2026-0230.xlsx")
            workbook(project / "Fabric P2P_v1.9_2026-0215.xlsx")
            with self.assertRaises(self.load.LoadError):
                self.load.select_p2p(project)

    def test_compared_candidate_with_two_version_tokens_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            workbook(project / "Fabric P2P_v2.1-v3.0.xlsx")
            workbook(project / "Fabric P2P_v1.9.xlsx")
            with self.assertRaises(self.load.LoadError):
                self.load.select_p2p(project)

    def test_override_selects_older_regular_root_workbook(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            expected = workbook(project / "Fabric P2P_v1.0.xlsx")
            workbook(project / "Fabric P2P_v2.0.xlsx")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(expected, self.load.select_p2p(project, expected.name))

    def test_explicit_root_workbook_need_not_have_p2p_in_its_name(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            expected = workbook(project / "Customer topology.xlsx")
            workbook(project / "Fabric P2P_v9.0.xlsx")
            self.assertEqual(expected, self.load.select_p2p(project, expected.name))

    def test_p2p_guides_and_load_help_distinguish_auto_from_explicit(self):
        template = (ROOT / "DAY0-Prepare/template/README.txt").read_text(
            encoding="utf-8",
        )
        guide = (ROOT / "DAY0-Prepare/template/p2p/README.txt").read_text(
            encoding="utf-8",
        )
        help_text = self.load._build_parser().format_help()

        for source, text in (("template", template), ("p2p", guide)):
            with self.subTest(source=source):
                self.assertIn("自动选择候选", text)
                self.assertIn("显式 --p2p-file", text)
                self.assertIn("无需包含 p2p", text)
        self.assertIn("唯一候选", guide)
        self.assertIn("多候选", guide)
        self.assertIn("[-N]", guide)
        self.assertIn("无原子无覆盖移动能力时停止", guide)
        self.assertIn("项目根目录", help_text)
        self.assertNotIn("项目根目录或 p2p/ 下", help_text)

    def test_override_rejects_old_subdirectory_and_outside_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            project = root / "project"
            project.mkdir()
            nested = project / "p2p"
            nested.mkdir()
            workbook(nested / "Fabric P2P_v1.0.xlsx")
            outside = workbook(root / "outside P2P_v1.0.xlsx")
            (project / "outside P2P_v1.0.xlsx").symlink_to(outside)
            for name in ("p2p/Fabric P2P_v1.0.xlsx", "outside P2P_v1.0.xlsx"):
                with self.subTest(name=name), self.assertRaises(self.load.LoadError):
                    self.load.select_p2p(project, name)

    def test_release_source_binding_names_selected_real_workbook_and_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            older = workbook(project / "Fabric P2P_v1.0.xlsx")
            workbook(project / "Fabric P2P_v2.0.xlsx")
            (project / "p2p.xlsx").symlink_to(older.name)

            expected = {
                "path": older.name,
                "sha256": hashlib.sha256(older.read_bytes()).hexdigest(),
            }
            self.assertEqual(
                expected, self.load.p2p_release_source_binding(project, older),
            )
            self.assertNotEqual("p2p.xlsx", expected["path"])


if __name__ == "__main__":
    unittest.main()
