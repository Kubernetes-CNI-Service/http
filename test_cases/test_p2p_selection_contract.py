#!/usr/bin/env python3
"""Direct contracts for selecting one project-root or linked-directory P2P workbook."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
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

    def test_root_and_p2p_directory_share_one_versioned_candidate_pool(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            expected = workbook(project / "Fabric P2P_v2.1.xlsx")
            workbook(project / "ip assignment_v99.9.xlsx")
            nested = project / "p2p"
            nested.mkdir()
            workbook(nested / "Fabric P2P_v999.9.xlsx")
            self.assertEqual(nested / "Fabric P2P_v999.9.xlsx", self.load.select_p2p(project))

    def test_linked_external_p2p_directory_uses_same_version_date_mtime_order(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            project = root / "project"
            external = root / "external"
            project.mkdir()
            external.mkdir()
            root_candidate = workbook(
                project / "Fabric P2P_v2.10_2026-0915-root.xlsx",
                mtime_ns=1_600_000_000_000_000_000,
            )
            external_candidate = workbook(
                external / "Fabric P2P_v2.10_2026-0915-external.xlsx",
                mtime_ns=1_700_000_000_000_000_000,
            )
            (project / "p2p").symlink_to(external, target_is_directory=True)
            self.assertEqual(project / "p2p" / external_candidate.name,
                             self.load.select_p2p(project))
            os.utime(root_candidate, ns=(1_800_000_000_000_000_000,) * 2)
            self.assertEqual(root_candidate, self.load.select_p2p(project))

    def test_cross_directory_equal_rank_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            project = root / "project"
            external = root / "external"
            project.mkdir()
            external.mkdir()
            tie_mtime_ns = 1_700_000_000_000_000_000
            workbook(project / "A P2P_v2.10_2026-0915.xlsx", mtime_ns=tie_mtime_ns)
            workbook(external / "B P2P_v2.10_2026-0915.xlsx", mtime_ns=tie_mtime_ns)
            (project / "p2p").symlink_to(external, target_is_directory=True)
            with self.assertRaisesRegex(self.load.LoadError, "无法裁决"):
                self.load.select_p2p(project)

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

    def test_p2p_guide_lives_in_root_template_without_copying_p2p_directory(self):
        template = (ROOT / "DAY0-Prepare/template/README.txt").read_text(
            encoding="utf-8",
        )
        help_text = self.load._build_parser().format_help()

        self.assertFalse((ROOT / "DAY0-Prepare/template/p2p").exists())
        for expected in ("自动选择候选", "显式 --p2p-file", "无需包含 p2p",
                         "唯一候选", "多候选", "[-N]", "无原子无覆盖移动能力时停止"):
            self.assertIn(expected, template)
        self.assertIn("项目根目录或 p2p/ 下", help_text)

    def test_transfer_help_explains_selected_workbook_receipt_and_conflicts(self):
        sync_help = (ROOT / "tools/sync-code.py").read_text(encoding="utf-8")
        upload_help = (ROOT / "tools/tar-for-upload.py").read_text(encoding="utf-8")
        for text in (sync_help, upload_help):
            self.assertIn("03-selected-p2p.json", text)
            self.assertIn("同名不同摘要", text)
            self.assertIn("p2p/", text)

    def test_explicit_pin_distinguishes_same_basename_and_rejects_unsafe_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            project = root / "project"
            project.mkdir()
            nested = project / "p2p"
            nested.mkdir()
            nested_source = workbook(nested / "Fabric P2P_v1.0.xlsx")
            root_source = workbook(project / nested_source.name)
            outside = workbook(root / "outside P2P_v1.0.xlsx")
            (project / "outside P2P_v1.0.xlsx").symlink_to(outside)
            self.assertEqual(root_source, self.load.select_p2p(project, root_source.name))
            self.assertEqual(nested_source, self.load.select_p2p(
                project, f"p2p/{nested_source.name}"))
            for name in ("outside P2P_v1.0.xlsx", "../outside P2P_v1.0.xlsx",
                         str(outside), "p2p/../Fabric P2P_v1.0.xlsx",
                         "p2p/deeper/Fabric P2P_v1.0.xlsx"):
                with self.subTest(name=name), self.assertRaises(self.load.LoadError):
                    self.load.select_p2p(project, name)

    def test_dangling_p2p_directory_does_not_silently_select_stale_root(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            workbook(project / "Fabric P2P_v1.0.xlsx")
            (project / "p2p").symlink_to(project / "gone", target_is_directory=True)
            with self.assertRaises(self.load.LoadError):
                self.load.select_p2p(project)

    def test_management_server_receipt_pins_older_materialized_workbook(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            chosen = workbook(project / "Fabric P2P_v1.0.xlsx")
            workbook(project / "Fabric P2P_v9.0.xlsx")
            digest = hashlib.sha256(chosen.read_bytes()).hexdigest()
            (project / "03-selected-p2p.json").write_text(json.dumps({
                "schema_version": 1, "basename": chosen.name, "sha256": digest,
            }) + "\n", encoding="ascii")
            self.assertEqual(chosen, self.load.select_p2p(
                project, management_server=True))
            with self.assertRaisesRegex(self.load.LoadError, "收据"):
                self.load.select_p2p(
                    project, "Fabric P2P_v9.0.xlsx", management_server=True)
            chosen.write_bytes(b"modified-after-transfer")
            with self.assertRaisesRegex(self.load.LoadError, "收据"):
                self.load.select_p2p(project, management_server=True)

    def test_management_server_multiple_candidates_without_receipt_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            workbook(project / "Fabric P2P_v1.0.xlsx")
            workbook(project / "Fabric P2P_v2.0.xlsx")
            with self.assertRaisesRegex(self.load.LoadError, "缺少本次传输收据"):
                self.load.select_p2p(project, management_server=True)

    def test_external_directory_swap_between_selection_and_zip_read_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            project = base / "project"
            first = base / "source-one"
            second = base / "source-two"
            project.mkdir()
            first.mkdir()
            second.mkdir()
            name = "Fabric P2P_v2.0.xlsx"
            workbook(first / name)
            workbook(second / name)
            alias = project / "p2p"
            alias.symlink_to(first, target_is_directory=True)
            original = zipfile.ZipFile

            def swap_before_read(*args, **kwargs):
                alias.unlink()
                alias.symlink_to(second, target_is_directory=True)
                return original(*args, **kwargs)

            with mock.patch.object(self.load.zipfile, "ZipFile", side_effect=swap_before_read):
                with self.assertRaisesRegex(self.load.LoadError, "变化"):
                    self.load.select_p2p(project)

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
