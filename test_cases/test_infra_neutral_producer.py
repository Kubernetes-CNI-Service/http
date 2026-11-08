#!/usr/bin/env python3
"""v3.1.2 WP-1 (D-3): setup writes the default managed initial-setup tool root's infra-neutral.conf.

Every expected value is written from the sources below, never read back from the implementation:
- 问题文档 D-3: the production project's tool directory has no producer of infra-neutral.conf; the managed
  initial-setup fails closed with "unavailable" on a real project.  Owner 2026-11-07 (「同意你的建议。」, http dev
  转述): D-3 no longer blocks a release; 详细工作指导 已定 1: M2 still adds the producer.
- 参考/合并/EXECUTION-CHECKLIST.md【发布阻断项的验收要求（http merge 15:39）】, direct: once the tool root is built
  the file exists and qualifies -- regular, not a symlink, nlink 1, owned by the current UID, not group- or
  other-writable.  The tool root itself must be owned by the current UID and not group- or world-writable
  (test_cases/README.md, managed tool inputs), else the consumer refuses its namespace.
- 详细工作指导 WP-1 and §3.2 O1 ① (owner 2026-11-07「同意你在v3.1.2里的默认建议」, http dev 转述): in setup's step 2
  (prepare) write infra/infra-neutral.conf as <project>/infiniband/bringup/xdr-initial-setup/infra-neutral.conf;
  equal bytes are left alone, different bytes are replaced atomically (temporary file in the same directory, then
  os.replace); a regular 0644 file; --dry-run only prints; the source is checked once.
- R-016 v1.1 / v3.1.1 指导 O6: every step is safe to repeat -- a second run changes nothing.
- 需求文档 R-014 第 2 条, owner 2026-11-02 「不向指向外部目录的链接里写东西」; v3.1.1 setup (_safe_target_path):
  a project path that leaves the project through a link is skipped with a notice, not an error (R-014 第 3 条
  allows such user links).  The guide wrote 「报错」 before v3.1.1 landed; the code's rule is kept (原则 8).
- v3.1.1 setup rules (R-016 §4.2 第 2 步, setup's docstring): a real directory where setup writes is an error,
  counted and kept, never deleted; an error in step 2 exits 1 before the switch.
The fixture is test_activate_project_contract.Sandbox: a temporary tree holding the repository's template and two
synthetic projects, setup's globals rebased onto it.
"""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from test_cases import test_activate_project_contract as ACTIVATE
from test_cases import test_activate_project_workflow as ACTIVATE_WORKFLOW


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "infra/infra-neutral.conf"
TOOL_ROOT = Path("infiniband/bringup/xdr-initial-setup")
CONF = TOOL_ROOT / "infra-neutral.conf"
SETUP = ACTIVATE.SETUP


class InfraNeutralProducerTests(unittest.TestCase):
    def sandbox(self):
        temporary = tempfile.TemporaryDirectory(prefix="infra-neutral-producer-")
        self.addCleanup(temporary.cleanup)
        return ACTIVATE.Sandbox(Path(temporary.name).resolve())

    def activate(self, box, name: str = ACTIVATE.PROJECT, *, umask: int | None = None, **overrides):
        """setup() for DAY0-Prepare/<name>: (exit code, printed output)."""
        output = io.StringIO()
        code = 0
        previous = os.umask(umask) if umask is not None else None
        try:
            with box.patches(**overrides), redirect_stdout(output), redirect_stderr(output):
                try:
                    SETUP.setup(str(box.day0 / name))
                except SystemExit as stop:
                    code = ACTIVATE.exit_code(stop)
        finally:
            if previous is not None:
                os.umask(previous)
        return code, output.getvalue()

    def test_setup_writes_regular_owned_conf_equal_to_infra_source(self):
        box = self.sandbox()
        project = box.day0 / ACTIVATE.PROJECT
        # umask 002 is common for a Linux operator (user private groups); the consumer refuses group-writable.
        code, output = self.activate(box, umask=0o002)
        self.assertEqual(0, code, output)
        conf = project / CONF
        self.assertTrue(os.path.lexists(conf), f"D-3: setup produces {CONF}\n{output}")
        info = os.lstat(conf)
        self.assertTrue(stat.S_ISREG(info.st_mode), "regular, not a symlink")
        self.assertEqual(1, info.st_nlink)
        self.assertEqual(os.geteuid(), info.st_uid)
        self.assertEqual(0, info.st_mode & 0o022, oct(info.st_mode))
        self.assertEqual(SOURCE.read_bytes(), conf.read_bytes())
        root = os.lstat(project / TOOL_ROOT)
        self.assertTrue(stat.S_ISDIR(root.st_mode))
        self.assertEqual(os.geteuid(), root.st_uid)
        self.assertEqual(0, root.st_mode & 0o022, oct(root.st_mode))
        self.assertEqual(ACTIVATE.PROJECT, box.pointer())

    def test_rerun_does_not_rewrite_equal_content(self):
        box = self.sandbox()
        code, output = self.activate(box)
        self.assertEqual(0, code, output)
        conf = box.day0 / ACTIVATE.PROJECT / CONF
        self.assertTrue(os.path.lexists(conf), f"D-3: setup produces {CONF}\n{output}")
        before = os.lstat(conf)
        code, output = self.activate(box)
        self.assertEqual(0, code, output)
        after = os.lstat(conf)
        self.assertEqual((before.st_ino, before.st_mtime_ns), (after.st_ino, after.st_mtime_ns))

    def test_dry_run_writes_nothing(self):
        box = self.sandbox()
        project = box.day0 / ACTIVATE.PROJECT
        output = io.StringIO()
        with box.patches(), redirect_stdout(output), redirect_stderr(io.StringIO()):
            try:
                code = SETUP.main(["--dry-run", "--host-role=workstation", "--no-upgrade", ACTIVATE.PROJECT])
            except SystemExit as stop:
                code = ACTIVATE.exit_code(stop)
        self.assertEqual(0, code, output.getvalue())
        self.assertFalse(os.path.lexists(project / "infiniband"), "--dry-run makes no directory")
        # R-016 §4.1: a dry run prints what it would do.
        self.assertIn(CONF.as_posix(), output.getvalue())

    def test_differing_project_copy_is_atomically_replaced(self):
        box = self.sandbox()
        project = box.day0 / ACTIVATE.PROJECT
        conf = project / CONF
        conf.parent.mkdir(parents=True)
        old = b"DNS=192.0.2.53\nNTP=ntp.example.test\nTIMEZONE=Etc/UTC\n"
        conf.write_bytes(old)
        old_inode = os.lstat(conf).st_ino
        wanted = SOURCE.read_bytes()
        self.assertNotEqual(old, wanted, "fixture: the project copy differs from infra/")
        seen = []
        real_replace = os.replace

        def witness(source, destination, *args, **kwargs):
            if os.fspath(destination) == os.fspath(conf):
                # The swap itself: until it, readers see the whole old file; what moves in is already complete.
                seen.append((Path(destination).read_bytes(), Path(source).read_bytes(),
                             os.path.dirname(os.fspath(source))))
            return real_replace(source, destination, *args, **kwargs)

        with mock.patch.object(SETUP.os, "replace", side_effect=witness):
            code, output = self.activate(box)
        self.assertEqual(0, code, output)
        self.assertEqual([(old, wanted, os.fspath(conf.parent))], seen, "O1 ①: temporary file, then os.replace")
        self.assertEqual(wanted, conf.read_bytes())
        info = os.lstat(conf)
        self.assertNotEqual(old_inode, info.st_ino, "replaced, not rewritten in place")
        self.assertEqual(0o644, stat.S_IMODE(info.st_mode))
        self.assertEqual(["infra-neutral.conf"], sorted(os.listdir(conf.parent)), "no temporary file left")

    def test_outside_link_on_tool_root_path_is_refused_without_write(self):
        box = self.sandbox()
        project = box.day0 / ACTIVATE.PROJECT
        outside = box.root.parent / "outside"
        outside.mkdir()
        (project / "infiniband").symlink_to(outside)
        code, output = self.activate(box)
        # v3.1.1 setup: a user link out of the project is skipped with a notice, not counted as an error.
        self.assertEqual(0, code, output)
        self.assertEqual([], sorted(p.relative_to(outside).as_posix() for p in outside.rglob("*")),
                         "R-014 第 2 条: nothing is written through a link that leaves the project")
        self.assertEqual(os.fspath(outside), os.readlink(project / "infiniband"), "the user's link is kept")
        self.assertIn("[SKIP]", output)
        self.assertIn(os.fspath(project / CONF), output)

    def test_directory_at_the_conf_path_is_an_error_and_kept(self):
        box = self.sandbox()
        project = box.day0 / ACTIVATE.PROJECT
        (project / CONF).mkdir(parents=True)
        (project / CONF / "operator-note").write_text("kept\n", encoding="utf-8")
        code, output = self.activate(box)
        self.assertEqual(1, code, output)
        self.assertIsNone(box.pointer(), "an error in step 2 exits before the switch")
        self.assertEqual("kept\n", (project / CONF / "operator-note").read_text(encoding="utf-8"))
        self.assertIn("[ERROR]", output)
        self.assertIn(CONF.as_posix(), output)

    def test_source_that_is_not_a_regular_file_is_a_preparation_error(self):
        # The real script in a copied tree whose infra/infra-neutral.conf is gone: checked once, at the entry.
        temporary = tempfile.TemporaryDirectory(prefix="infra-neutral-producer-source-")
        self.addCleanup(temporary.cleanup)
        space = ACTIVATE_WORKFLOW.Workspace(Path(temporary.name).resolve())
        source = space.http / "infra/infra-neutral.conf"
        source.unlink()
        source.symlink_to("../DAY0-Prepare/template")  # not a regular file
        result = space.setup(ACTIVATE_WORKFLOW.FIRST, "-y")
        self.assertEqual(1, result.returncode, result.stdout)
        self.assertIsNone(space.pointer(), "an error in step 2 exits before the switch")
        self.assertFalse(os.path.lexists(space.project(ACTIVATE_WORKFLOW.FIRST) / CONF))
        self.assertIn("[ERROR]", result.stdout)
        self.assertIn("infra/infra-neutral.conf", result.stdout)


if __name__ == "__main__":
    unittest.main()
