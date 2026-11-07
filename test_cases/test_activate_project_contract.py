"""R-016 AP-a (v3.1.1 WP-3): the activate-project pointer and the reader that resolves it.

Every expected value is written from the design, never read back from the implementation:
- R-016 详细设计 v1.1 §2: DAY0-Prepare/activate-project is valid only when it is a link whose text is one
  plain name -- not template, activate-project, nor a name starting with "." -- and DAY0-Prepare/<name> is a
  real directory judged by lstat (never a link).  §4.2 细节 (R16-19): the same check also excludes tests,
  test_cases, dumps and runs require_project_eligible.
- R-016 §5.1: project_contract.active_project_dir(http_root) -> Path | None returns the real project directory
  when valid, None without a pointer, raises an error naming the reason when the pointer is invalid; read-only,
  no lock.  详细工作指导 WP-3 「先写的测试」: seven cases -- no pointer, valid, template, a link, a multi-level
  name, a missing directory, a leading ".".
- http dev 2026-11-07: the error type is frozen for WP-4/6/9 -- ActiveProjectPointerError, a ValueError (the
  type require_project_eligible already raises).
"""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = load_script("activate_project_contract_project_contract", ROOT / "tools/project_contract.py")

PROJECT = "site-p"


def active_project_dir():
    if not hasattr(CONTRACT, "active_project_dir"):
        raise AssertionError("R-016 §5.1: project_contract.active_project_dir(http_root) resolves the pointer")
    return CONTRACT.active_project_dir


def pointer_error():
    if not hasattr(CONTRACT, "ActiveProjectPointerError"):
        raise AssertionError("http dev 2026-11-07: an invalid pointer raises ActiveProjectPointerError")
    return CONTRACT.ActiveProjectPointerError


def tree_state(root: Path) -> dict[str, tuple[int, int, str | None]]:
    """Every entry under root with its mode, mtime and link text: the read-only witness."""
    state = {}
    for current, directories, files in os.walk(root):
        for name in (*directories, *files):
            path = Path(current) / name
            info = path.lstat()
            state[str(path.relative_to(root))] = (
                info.st_mode, info.st_mtime_ns, os.readlink(path) if path.is_symlink() else None,
            )
    return state


class ActiveProjectDirTests(unittest.TestCase):
    """R-016 §2, §5.1: the seven cases of 详细工作指导 WP-3, and the exclusions §4.2 adds."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "http"
        self.day0 = self.root / "DAY0-Prepare"
        for name in (PROJECT, "site-q", "template"):
            (self.day0 / name).mkdir(parents=True)
            (self.day0 / name / "01-global.yaml").write_text("common: {}\n", encoding="utf-8")

    def point(self, text: str) -> None:
        os.symlink(text, self.day0 / "activate-project")

    def assert_invalid(self, *reason_words: str) -> None:
        error = pointer_error()
        self.assertTrue(issubclass(error, ValueError))
        with self.assertRaises(error) as raised:
            active_project_dir()(self.root)
        for word in reason_words:
            self.assertIn(word, str(raised.exception))

    def test_no_pointer_is_none(self):
        self.assertIsNone(active_project_dir()(self.root))

    def test_no_pointer_even_without_day0_is_none(self):
        empty = self.root.parent / "empty-http"
        empty.mkdir()
        self.assertIsNone(active_project_dir()(empty))

    def test_valid_pointer_returns_the_real_project_directory(self):
        self.point(PROJECT)
        found = active_project_dir()(self.root)
        self.assertIsInstance(found, Path)
        self.assertEqual(found, Path(os.path.realpath(self.day0 / PROJECT)))
        # §5.1 「返回真实项目目录」: even when the caller names the tree through an alias.
        alias = self.root.parent / "http-alias"
        os.symlink(self.root, alias)
        self.assertEqual(active_project_dir()(str(alias)), Path(os.path.realpath(self.day0 / PROJECT)))

    def test_reading_the_pointer_changes_nothing(self):
        self.point(PROJECT)
        before = tree_state(self.root.parent)
        active_project_dir()(self.root)
        self.assertEqual(tree_state(self.root.parent), before)

    def test_pointer_to_template_is_invalid(self):
        self.point("template")
        self.assert_invalid("template")

    def test_pointer_to_a_link_is_invalid(self):
        os.symlink(PROJECT, self.day0 / "linked-project")
        self.point("linked-project")
        self.assert_invalid("linked-project")

    def test_multi_level_names_are_invalid(self):
        (self.day0 / PROJECT / "nested").mkdir()
        for text in (PROJECT + "/nested", "../DAY0-Prepare/" + PROJECT, str(self.day0 / PROJECT)):
            with self.subTest(text=text):
                self.point(text)
                self.assert_invalid(text)
                (self.day0 / "activate-project").unlink()

    def test_pointer_to_a_missing_directory_is_invalid(self):
        self.point("site-gone")
        self.assert_invalid("site-gone")

    def test_pointer_to_a_dot_name_is_invalid(self):
        for text in (".hidden", "..", "."):
            with self.subTest(text=text):
                if text == ".hidden":
                    (self.day0 / text).mkdir()
                self.point(text)
                self.assert_invalid()
                (self.day0 / "activate-project").unlink()

    def test_excluded_names_are_invalid(self):
        for text in ("activate-project", "tests", "test_cases", "dumps"):
            with self.subTest(text=text):
                if text != "activate-project":
                    (self.day0 / text).mkdir()
                self.point(text)
                self.assert_invalid(text)
                (self.day0 / "activate-project").unlink()

    def test_pointer_to_a_regular_file_is_invalid(self):
        (self.day0 / "notes.txt").write_text("x\n", encoding="utf-8")
        self.point("notes.txt")
        self.assert_invalid("notes.txt")

    def test_pointer_that_is_not_a_link_is_invalid(self):
        (self.day0 / "activate-project").mkdir()
        self.assert_invalid("activate-project")

    def test_project_that_require_project_eligible_rejects_is_invalid(self):
        # A restore receipt without its commit marker: require_project_eligible refuses the project.
        (self.day0 / PROJECT / CONTRACT.REHYDRATE_RECEIPT_NAME).write_text("{}", encoding="ascii")
        self.point(PROJECT)
        self.assert_invalid(PROJECT)

    def test_incomplete_sync_makes_the_pointer_invalid(self):
        (self.root / ".sync-code-in-progress").write_text("", encoding="ascii")
        self.point(PROJECT)
        self.assert_invalid()


if __name__ == "__main__":
    unittest.main()
