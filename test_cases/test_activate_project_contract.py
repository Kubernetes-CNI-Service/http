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



# ── v3.1.1 WP-6: unsetup through the pointer (R-016 §4.4, Q7, O14) ───────────────────────────────────────
# Imports and helpers stay with this section: parallel work packages append their own classes to this file.
from contextlib import redirect_stdout  # noqa: E402
import io  # noqa: E402
from types import SimpleNamespace  # noqa: E402
from unittest import mock  # noqa: E402

WP6_UNSETUP = load_script("activate_project_contract_unsetup", ROOT / "DAY0-Prepare/02-unsetup.py")
# O14 (owner 2026-11-07 「同意你的建议。」 via http dev): the four names older setups left behind; the fifth is
# monitor/99-output-ufm, which R-013 took out of the table (WP-8 待决 1, settled by http dev 2026-11-08: a legacy
# name handled like the four).
WP6_RETIRED_MONITOR_LINK = "monitor/99-output-ufm"
WP6_LEGACY_LINKS = (
    "ztp/config/nvos/template/99-output-ib",
    "ztp/config/nvos/template/99-output-nvl",
    "ztp/config/nvos/template/99-output-published",
    "ztp/config/cumulus/template/AIR/output-p2p",
    WP6_RETIRED_MONITOR_LINK,
)
# R-016 §3.2 (owner 2026-11-04): one link per project key in each of the four real key directories.
WP6_KEY_NAMES = ("laptop.pub", "mgmt-server.pub")
WP6_SHARED_IMAGE = "ztp/image/cumulus/cumulus-linux-fixture-amd64.bin"
WP6_SHARED_DIRECTORY = "infiniband/bringup/ufm-setup-upgrade/image"


def wp6_link_state(root: Path) -> dict[str, str]:
    """Every symlink under root with its text: what unsetup may change."""
    state = {}
    for current, directories, files in os.walk(root):
        for name in (*directories, *files):
            path = Path(current) / name
            if path.is_symlink():
                state[str(path.relative_to(root))] = os.readlink(path)
    return state


class WP6UnsetupTests(unittest.TestCase):
    """R-016 §4.4 unsetup with the pointer layout (v3.1.1 WP-6).

    Expected values come from the design and the owner's rulings, never from 02-unsetup.py:
    - R-016 详细设计 v1.1 §4.4 (Q1-Q7 「好的」, owner 2026-11-03): read the project with active_project_dir()
      first, then unlink DAY0-Prepare/activate-project; withdraw the configuration authorities of that project,
      not of projects inferred from link realpaths (R16-20); ``02-unsetup.py <project>`` runs only when that
      project is the active one; crontab cleanup as before; .setup_manifest deleted.
    - Q7: the table's fixed links stay; dangling, they mean "no project is active".
    - O14 (owner 2026-11-07 「同意你的建议。」 via http dev): besides the pointer and .setup_manifest, unsetup removes
      only the per-key links of the four key directories, the ztp/optimize/*-sample/* links and the four legacy
      names; the fixed links, the shared-image section included, stay.
    - 详细工作指导 WP-6: a project argument naming another project does nothing.  The exit codes follow the
      existing unsetup contract: a refusal is 1 and touches nothing (as the log-receipt and infra/logs gates);
      nothing to do is 0 (as "未找到任何由 setup 管理的软链接，无需操作").
    - infra/logs: its canonical pointer-form text is accepted only once WP-9b adapts
      project_contract.managed_infra_log_project (WP-6 dispatch); the fixture leaves it out except in the test
      that names this dependency.
    """

    PROJECT = "site-p"
    OTHER = "site-q"

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve() / "http"
        self.day0 = self.root / "DAY0-Prepare"
        self.project = self.day0 / self.PROJECT
        self.other = self.day0 / self.OTHER

    # ── fixture: the tree as setup leaves it with site-p active ──
    def build(self, *, infra_logs: bool = False) -> None:
        for project in (self.project, self.other):
            project.mkdir(parents=True)
            (project / "01-global.yaml").write_text("common: {}\n", encoding="utf-8")
            for name in WP6_KEY_NAMES:
                (project / name).write_text("ssh-ed25519 AAAA fixture\n", encoding="ascii")
        (self.root / "infra").mkdir()
        (self.root / "image").mkdir()
        (self.root / "image/cumulus-linux-fixture-amd64.bin").write_bytes(b"shared image\n")
        rows = [row for row in CONTRACT.SETUP_LINK_SPECS if row.base == "project"]
        for row in rows:
            if row.kind == "dir":
                (self.project / row.target).mkdir(parents=True, exist_ok=True)
        for row in rows:
            if row.kind == "file":
                (self.project / row.target).parent.mkdir(parents=True, exist_ok=True)
                (self.project / row.target).write_bytes(b"project file\n")
        # The publisher rows reach <99-output-*>/latest through their release directory rows.
        for name in ("99-output-eth/latest", "99-output-ib_nvl/latest"):
            (self.project / name).mkdir(parents=True, exist_ok=True)
        os.symlink(self.PROJECT, self.day0 / "activate-project")
        for path, text in CONTRACT.pointer_link_specs():
            if path == "infra/logs" and not infra_logs:
                continue
            self.symlink(path, text)
        for directory in CONTRACT.PUBLICKEY_DIRECTORIES:
            for name in WP6_KEY_NAMES:
                self.symlink(directory + "/" + name, CONTRACT.pointer_link_target(directory + "/" + name, name))
        (self.root / "ethernet/publickey/operator.pub").write_text("operator-owned key\n", encoding="ascii")
        sample = "ztp/optimize/" + self.PROJECT + "-sample"
        for name, target in (("01-global.yaml", "01-global.yaml"), ("comparison", "99-output-ztp")):
            self.symlink(sample + "/" + name, os.path.relpath(self.project / target, self.root / sample))
        (self.root / sample / "operator-notes.txt").write_text("operator-owned\n", encoding="utf-8")
        for path in WP6_LEGACY_LINKS:
            self.symlink(path, os.path.relpath(self.project / "99-output-ib_nvl", (self.root / path).parent))
        self.symlink(WP6_SHARED_IMAGE, os.path.relpath(self.root / "image/cumulus-linux-fixture-amd64.bin",
                                                       (self.root / WP6_SHARED_IMAGE).parent))
        self.symlink(WP6_SHARED_DIRECTORY, os.path.relpath(self.root / "image",
                                                           (self.root / WP6_SHARED_DIRECTORY).parent))
        manifest = self.root / "ztp/.setup_manifest"
        # R16-14 / Q5: the manifest body is a derived record, never a list of what to delete.
        manifest.write_text(f"# setup manifest — proj: {self.project}\n{self.root / 'monitor/01-global.yaml'}\n",
                            encoding="utf-8")

    def symlink(self, relative: str, text: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(text, path)

    def fixed_paths(self, *, infra_logs: bool = False) -> list[str]:
        return [path for path, _text in CONTRACT.pointer_link_specs() if infra_logs or path != "infra/logs"]

    def unsetup(self, project: str | None = None) -> tuple[int | None, str]:
        output = io.StringIO()
        with mock.patch.multiple(
            WP6_UNSETUP, HTTP_BASE=str(self.root), HERE=str(self.day0), ZTP=str(self.root / "ztp"),
            MANIFEST_FILE=str(self.root / "ztp/.setup_manifest"), _AUTO_YES=True, _DRY_RUN=False,
        ), redirect_stdout(output):
            # The real filesystem stage: main() would also stop host services outside this fixture.
            result = WP6_UNSETUP._main_locked(SimpleNamespace(project=project))
        return result, output.getvalue()

    # ── R-016 §4.4, Q7, O14 ──
    def assert_unsetup_result(self, before: dict[str, str], *, infra_logs: bool = False) -> None:
        self.assertFalse(os.path.lexists(self.day0 / "activate-project"), "R-016 §4.4: the pointer is unlinked")
        self.assertIsNone(CONTRACT.active_project_dir(self.root), "R-016 §5.1: no project is active")
        self.assertFalse(os.path.lexists(self.root / "ztp/.setup_manifest"), "R-016 §4.4: the manifest goes")
        for path in self.fixed_paths(infra_logs=infra_logs):
            link = self.root / path
            with self.subTest(fixed=path):
                self.assertTrue(link.is_symlink(), "Q7: the fixed link stays")
                self.assertEqual(before[path], os.readlink(link), "Q7: the fixed link stays as it was")
                self.assertFalse(link.exists(), "Q7: dangling means no project is active")
        for directory in CONTRACT.PUBLICKEY_DIRECTORIES:
            for name in WP6_KEY_NAMES:
                with self.subTest(key=directory + "/" + name):
                    self.assertFalse(os.path.lexists(self.root / directory / name), "O14: per-key links go")
        self.assertEqual(b"operator-owned key\n", (self.root / "ethernet/publickey/operator.pub").read_bytes())
        sample = self.root / "ztp/optimize" / (self.PROJECT + "-sample")
        self.assertEqual(["operator-notes.txt"], sorted(item.name for item in sample.iterdir()),
                         "O14: only the sample links go")
        for path in WP6_LEGACY_LINKS:
            with self.subTest(legacy=path):
                self.assertFalse(os.path.lexists(self.root / path), "O14: the legacy names go")
        for path in (WP6_SHARED_IMAGE, WP6_SHARED_DIRECTORY):
            with self.subTest(shared=path):
                self.assertEqual(before[path], os.readlink(self.root / path), "O14: the shared section stays")
                self.assertTrue((self.root / path).exists())
        self.assertEqual(b"project file\n", (self.project / "02-devices_config.csv").read_bytes(), "data stays")

    def test_unsetup_unlinks_the_pointer_and_keeps_every_fixed_link_dangling(self):
        self.build()
        before = wp6_link_state(self.root)
        for path in self.fixed_paths():
            with self.subTest(fixture=path):
                self.assertTrue((self.root / path).exists(), "fixture: every fixed link resolves while active")
        result, output = self.unsetup()
        self.assertEqual(0, result, output)
        self.assert_unsetup_result(before)

    def test_unsetup_naming_the_active_project_runs(self):
        self.build()
        before = wp6_link_state(self.root)
        result, output = self.unsetup(str(self.project))
        self.assertEqual(0, result, output)
        self.assert_unsetup_result(before)

    def test_unsetup_naming_another_project_changes_nothing_and_exits_1(self):
        self.build()
        before = wp6_link_state(self.root)
        manifest = (self.root / "ztp/.setup_manifest").read_bytes()
        result, output = self.unsetup(str(self.other))
        self.assertEqual(1, result, output)
        self.assertIn(self.PROJECT, output, "the message names the active project")
        self.assertIn(self.OTHER, output, "the message names the project asked for")
        self.assertIn("未做任何改动", output)
        self.assertEqual(before, wp6_link_state(self.root))
        self.assertEqual(manifest, (self.root / "ztp/.setup_manifest").read_bytes())

    def test_unsetup_withdraws_the_authorities_of_the_pointer_project_only(self):
        # R16-20: the project comes from the pointer, never from link realpaths.  A legacy link into site-q
        # used to add site-q to the withdrawal set.
        from test_cases import test_config_sync_authority as AUTHORITY_TESTS

        authority = WP6_UNSETUP.config_sync_authority
        self.build()
        os.unlink(self.root / WP6_LEGACY_LINKS[0])
        self.symlink(WP6_LEGACY_LINKS[0], os.path.relpath(self.other, (self.root / WP6_LEGACY_LINKS[0]).parent))
        roots = {}
        for project in (self.project, self.other):
            root = project / "99-output-ztp/configuration-methods"
            ticket = authority.begin_method(root, "leaf1", "cycle-1", "leaf1-cycle-1", "ztp_monitor_cycle")
            authority.finish_method(root, ticket, AUTHORITY_TESTS.ConfigSyncAuthorityTests.method_receipt_v2(ticket))
            roots[project.name] = root
        result, output = self.unsetup()
        self.assertEqual(0, result, output)
        self.assertEqual("failed", authority.read_method_current(roots[self.PROJECT], "leaf1")["state"])
        self.assertEqual("success", authority.read_method_current(roots[self.OTHER], "leaf1")["state"])

    def test_without_a_pointer_unsetup_removes_only_leftovers_and_a_project_argument_does_nothing(self):
        # The state a finished unsetup leaves (Q7): fixed links dangle; the infiniband xdr-initial-setup log
        # link is one of them, and REQ10C cleanup must read that as "nothing to clean", not fail.
        self.build()
        result, output = self.unsetup()
        self.assertEqual(0, result, output)
        state = wp6_link_state(self.root)
        result, output = self.unsetup(str(self.project))
        self.assertEqual(0, result, output)
        self.assertIn("没有激活的项目", output)
        self.assertEqual(state, wp6_link_state(self.root))
        # Leftovers an interrupted run or an older setup can leave: removed; the fixed links stay.
        self.symlink(WP6_LEGACY_LINKS[1], "../../../../DAY0-Prepare/site-p/99-output-nvl")
        self.symlink("nvlink/publickey/laptop.pub", "../../DAY0-Prepare/activate-project/laptop.pub")
        result, output = self.unsetup()
        self.assertEqual(0, result, output)
        self.assertEqual(state, wp6_link_state(self.root))
        # Q5: the manifest is the derived record of the active project and goes with the pointer; without a
        # pointer it is no project's record, and unsetup leaves it for setup to rewrite (existing contract:
        # no project named, no manifest removed).
        manifest = self.root / "ztp/.setup_manifest"
        manifest.write_text(f"# setup manifest — proj: {self.project}\n", encoding="utf-8")
        result, output = self.unsetup()
        self.assertEqual(0, result, output)
        self.assertEqual(state, wp6_link_state(self.root))
        self.assertTrue(manifest.is_file())

    def test_invalid_pointer_changes_nothing_and_exits_1(self):
        self.build()
        os.unlink(self.day0 / "activate-project")
        os.symlink("template", self.day0 / "activate-project")
        before = wp6_link_state(self.root)
        result, output = self.unsetup()
        self.assertEqual(1, result, output)
        self.assertIn("activate-project", output)
        self.assertEqual(before, wp6_link_state(self.root))
        self.assertTrue((self.root / "ztp/.setup_manifest").is_file())

    def test_retired_monitor_link_in_a_real_directory_is_reported_and_kept(self):
        # Owner rule 2026-11-03 (需求文档 R-016 设计输入, :920-925): a same-named real file is reported, not
        # replaced or deleted, and the run does not stop.  WP-8 待决 1 (http dev 2026-11-08) applies it here.
        self.build()
        retired = self.root / WP6_RETIRED_MONITOR_LINK
        os.unlink(retired)
        retired.mkdir()
        (retired / "operator.txt").write_text("operator-owned\n", encoding="utf-8")
        before = wp6_link_state(self.root)
        result, output = self.unsetup()
        self.assertEqual(1, result, output)
        self.assertIn("[ERROR]", output)
        self.assertIn(WP6_RETIRED_MONITOR_LINK, output)
        self.assertEqual("operator-owned\n", (retired / "operator.txt").read_text(encoding="utf-8"))
        # Not interrupted: the rest of unsetup still ran.
        self.assertFalse(os.path.lexists(self.day0 / "activate-project"))
        for path in WP6_LEGACY_LINKS[:-1]:
            with self.subTest(legacy=path):
                self.assertFalse(os.path.lexists(self.root / path))
        for path in self.fixed_paths():
            with self.subTest(fixed=path):
                self.assertEqual(before[path], os.readlink(self.root / path))

    def test_pointer_form_infra_logs_is_kept_and_a_second_unsetup_succeeds(self):
        # Depends on WP-9b: managed_infra_log_project must accept the canonical pointer-form text, and keep
        # accepting it when the pointer is gone and the link dangles (Q7).  RED until WP-9b lands.
        self.build(infra_logs=True)
        before = wp6_link_state(self.root)
        result, output = self.unsetup()
        self.assertEqual(0, result, output)
        self.assert_unsetup_result(before, infra_logs=True)
        state = wp6_link_state(self.root)
        result, output = self.unsetup()
        self.assertEqual(0, result, output)
        self.assertEqual(state, wp6_link_state(self.root))


WP6_PACKAGE = load_script("activate_project_contract_package_common", ROOT / "tools/_package_common.py")


class WP6RetiredLinkPackagingTests(unittest.TestCase):
    """WP-8 待决 1 (http dev 2026-11-08): tar and sync leave the retired monitor/99-output-ufm link behind.

    WP-8 measured that neither packaging path excluded the dangling link any more once R-013 removed it from the
    table.  Tar filters every member through project_contract.transfer_exclude_reason and setup_managed_links;
    sync's monitor/ rsync job takes its link excludes from setup_managed_links only.
    """

    def test_transfer_exclude_reason_names_the_retired_link(self):
        self.assertIsNotNone(CONTRACT.transfer_exclude_reason(WP6_RETIRED_MONITOR_LINK))
        self.assertIsNone(CONTRACT.transfer_exclude_reason("monitor/generate-monitor-html.py"), "control")

    def test_setup_managed_links_name_a_retired_link_that_is_present(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "DAY0-Prepare").mkdir()
            manifest = root / "ztp/.setup_manifest"
            with mock.patch.multiple(WP6_PACKAGE, ROOT=root, DAY0=root / "DAY0-Prepare", MANIFEST=manifest):
                absent = WP6_PACKAGE.setup_managed_links()
                (root / "monitor").mkdir()
                os.symlink("../DAY0-Prepare/site-p/99-output-ufm", root / WP6_RETIRED_MONITOR_LINK)
                present = WP6_PACKAGE.setup_managed_links()
        self.assertNotIn(WP6_RETIRED_MONITOR_LINK, absent)
        self.assertEqual({WP6_RETIRED_MONITOR_LINK}, present - absent)


if __name__ == "__main__":
    unittest.main()
