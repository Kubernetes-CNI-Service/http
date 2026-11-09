"""Direct contract of tools/operator_identity.py: the operator rule, the root re-run and its marker (v3.1.2 WP-4, M6).

Expectations come from the requirement texts, never from the module:
- design `设计/I-006与R-005实现计划.md` §4.2: the operator is the owner of the project directory; the five-row
  table (U / U+sudo / root login / V / V+sudo against a U-owned or root-owned project); the home directory comes
  from passwd, never from HOME; one identity line such as
  「操作员：U（项目目录属主）；当前：root 经 sudo（发起人 U）→ 项目侧以 U 执行」; mixing the two ways of running
  never flips the operator;
- 问题文档 I-006, the scheme owner 2026-10-27 agreed (item 1, :291): under sudo the real user comes from
  SUDO_USER/SUDO_UID, must exist in passwd with the same uid and must not be root; :351 (owner 2026-10-27): a
  refusal names who owns the project and who is running;
- v3.1.2 guide 3.2 (owner 2026-11-07 「同意你在v3.1.2里的默认建议」, http dev 转述): O7 ② (V with sudo on U's
  project is refused, the hint names switching to U or a direct root login), O7 ④ (the SUDO_USER/SUDO_UID check is
  done), O9 (the group is passwd's pw_gid), O11 ④ (a project the run creates belongs to the sudo invoker);
- v3.1.2 guide WP-4 :513 (OP pending point 3, http dev default; review b-6): a project owner missing from passwd
  is refused, a direct root login included, with the hint `sudo chown <操作员>:<操作员主组> <项目>`;
- v3.1.2 guide WP-4 (re-run mechanism): trigger = euid 0, operator not root, no marker; argv
  `runuser -u <op> -- env -i <whitelist> <python> <absolute script> <args>`; whitelist PATH, LANG, LC_ALL, TERM plus
  HOME/USER/LOGNAME of the operator plus names the caller adds; exec keeps the caller's fds inheritable, the wait
  form passes them in pass_fds, sets the marker in the child, forwards SIGINT/SIGTERM and exits with the child's
  code (128+n when a signal killed it; 开发计划 :404); 已定 2: the marker means only "started by a root parent";
  no project (no pointer) means no identity check; an invalid pointer is raised to the caller, never treated as
  None; -h/--help/--version skip the identity step (test_all_script_entrypoints runs --help in a clean clone);
- http dev 2026-11-08: the module's top level imports only the standard library; the project_contract import is
  deferred into the function, and a failed import reaches the caller as ImportError;
- appendix A.7 / v3.1.2 brief: a library module has a docstring and no argparse or __main__.

No real uid switch happens here (v3.1.2 guide 2.2 item 6): passwd, euid, environ and stat are function inputs;
os.execvp and subprocess.Popen are replaced by recorders.  The workflow class at the end runs the real
tools/project_contract.py pointer reader together with this module.
"""
from __future__ import annotations

import ast
import os
from pathlib import Path
import pwd
import signal
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import operator_identity as OI  # noqa: E402

ROOT_ENTRY = pwd.struct_passwd(("root", "x", 0, 0, "root", "/root", "/bin/bash"))
# The operator's primary group differs from its uid so a uid-for-gid slip is visible (O9).
U_ENTRY = pwd.struct_passwd(("opuser", "x", 1001, 2001, "operator", "/home/opuser", "/bin/bash"))
V_ENTRY = pwd.struct_passwd(("otheruser", "x", 1002, 2002, "other", "/home/otheruser", "/bin/bash"))
ACCOUNTS = (ROOT_ENTRY, U_ENTRY, V_ENTRY)
U_PROJECT = "/srv/fixture/DAY0-Prepare/u-project"
ROOT_PROJECT = "/srv/fixture/DAY0-Prepare/root-project"
NEW_PROJECT = "/srv/fixture/DAY0-Prepare/new-project"
OWNERS = {U_PROJECT: 1001, ROOT_PROJECT: 0}
SUDO_U = {"SUDO_USER": "opuser", "SUDO_UID": "1001", "SUDO_GID": "2001"}
SUDO_V = {"SUDO_USER": "otheruser", "SUDO_UID": "1002", "SUDO_GID": "2002"}
U_OPERATOR = ("opuser", 1001, 2001, "/home/opuser")


def getpwuid(uid):
    for entry in ACCOUNTS:
        if entry.pw_uid == uid:
            return entry
    raise KeyError(f"getpwuid(): uid not found: {uid}")


def getpwnam(name):
    for entry in ACCOUNTS:
        if entry.pw_name == name:
            return entry
    raise KeyError(f"getpwnam(): name not found: {name!r}")


def fake_stat(path):
    try:
        uid = OWNERS[str(path)]
    except KeyError:
        raise FileNotFoundError(2, "No such file or directory", str(path)) from None
    return os.stat_result((0o40755, 1, 1, 3, uid, 0, 4096, 0, 0, 0))


def resolve(project, euid, environ=None):
    return OI.resolve_operator(project, euid=euid, environ=dict(environ or {}), getpwuid=getpwuid,
                               getpwnam=getpwnam, stat=fake_stat)


class OperatorTableTests(unittest.TestCase):
    """Design §4.2 table, one test per cell; refusals name owner, current user and a way out."""

    def assert_runs(self, result, action, operator):
        self.assertIsNone(result.refusal, result)
        self.assertEqual(action, result.action, result)
        self.assertEqual(operator, tuple(result.operator), result)

    def assert_refused(self, result, *needles):
        self.assertEqual("refuse", result.action, result)
        self.assertIsInstance(result.refusal, str, result)
        for needle in needles:
            self.assertIn(needle, result.refusal)

    def test_u_direct_on_u_project_runs_as_u(self):
        self.assert_runs(resolve(U_PROJECT, 1001), "self", U_OPERATOR)

    def test_u_direct_on_root_project_refused_with_owner_current_and_fix(self):
        # Design §4.2: 「拒绝：项目属于 root，请用 sudo 或 root 运行」.
        result = resolve(ROOT_PROJECT, 1001)
        self.assert_refused(result, ROOT_PROJECT, "root", "opuser", "sudo")

    def test_u_sudo_on_u_project_operator_is_u(self):
        # Design §4.2: system side as root, operator side is U -> root represents U.
        self.assert_runs(resolve(U_PROJECT, 0, SUDO_U), "represent", U_OPERATOR)

    def test_u_sudo_on_root_project_runs_as_root(self):
        self.assert_runs(resolve(ROOT_PROJECT, 0, SUDO_U), "self", ("root", 0, 0, "/root"))

    def test_root_login_on_u_project_represents_u(self):
        self.assert_runs(resolve(U_PROJECT, 0), "represent", U_OPERATOR)

    def test_root_login_on_root_project_runs_as_root(self):
        self.assert_runs(resolve(ROOT_PROJECT, 0), "self", ("root", 0, 0, "/root"))

    def test_v_direct_on_u_project_refused(self):
        # 问题文档 :351: say who owns the project and who is running; the way out is U or root.
        self.assert_refused(resolve(U_PROJECT, 1002), U_PROJECT, "opuser", "otheruser", "root")

    def test_v_direct_on_root_project_refused(self):
        self.assert_refused(resolve(ROOT_PROJECT, 1002), ROOT_PROJECT, "root", "otheruser", "sudo")

    def test_v_sudo_on_u_project_refused(self):
        # O7 ②: refuse; the hint is "switch to U" or "a direct root login".
        result = resolve(U_PROJECT, 0, SUDO_V)
        self.assert_refused(result, U_PROJECT, "opuser", "otheruser", "root 直接登录")

    def test_v_sudo_on_root_project_runs_as_root(self):
        self.assert_runs(resolve(ROOT_PROJECT, 0, SUDO_V), "self", ("root", 0, 0, "/root"))

    def test_home_and_gid_come_from_passwd_not_env(self):
        misleading = {"HOME": "/root", "USER": "root", "LOGNAME": "root"}
        for environ in (misleading, {**misleading, **SUDO_U}):
            with self.subTest(environ=sorted(environ)):
                result = resolve(U_PROJECT, 0, environ)
                self.assertIsNotNone(result.operator, result)
                self.assertEqual("/home/opuser", result.operator.home)
                self.assertEqual(2001, result.operator.gid)   # pw_gid (O9), not the uid 1001
                self.assertEqual("opuser", result.operator.name)

    def test_sudo_user_unknown_root_or_uid_mismatch_is_refused(self):
        # 问题文档 :291 (owner 10-27 item 1) and O7 ④: exists in passwd, same uid, not root; else fail closed.
        cases = {
            "unknown": {"SUDO_USER": "ghost", "SUDO_UID": "1003"},
            "root": {"SUDO_USER": "root", "SUDO_UID": "0"},
            "uid mismatch": {"SUDO_USER": "opuser", "SUDO_UID": "1002"},
            "uid missing": {"SUDO_USER": "opuser"},
        }
        for label, environ in cases.items():
            for project in (U_PROJECT, ROOT_PROJECT, NEW_PROJECT):
                with self.subTest(case=label, project=project):
                    result = resolve(project, 0, environ)
                    self.assert_refused(result, "SUDO_USER")
                    self.assertFalse(OI.needs_reexec(result, environ))

    def test_project_owner_missing_from_passwd_is_refused_with_chown_hint(self):
        # v3.1.2 guide WP-4 :513 (start check OP pending point 3, http dev default; review b-6, direct case added with
        # G4 (b)): an owner uid missing from passwd is refused for U directly, for root via sudo by a valid invoker and
        # for a direct root login alike; the reason is that the project owner has no account and the hint is
        # `sudo chown <操作员>:<操作员主组> <项目>`.  问题文档 :351: the refusal names who owns the project.
        orphan, owner = "/srv/fixture/DAY0-Prepare/orphan-project", 1009

        def orphan_stat(path):
            if str(path) != orphan:
                raise FileNotFoundError(2, "No such file or directory", str(path))
            return os.stat_result((0o40755, 1, 1, 3, owner, 0, 4096, 0, 0, 0))

        for label, euid, environ in (("U directly", 1001, {}), ("root via sudo by U", 0, SUDO_U),
                                     ("direct root login", 0, {})):
            with self.subTest(label):
                result = OI.resolve_operator(orphan, euid=euid, environ=dict(environ), getpwuid=getpwuid,
                                             getpwnam=getpwnam, stat=orphan_stat)
                self.assert_refused(result, "项目属主没有账户", str(owner),
                                    f"sudo chown <操作员>:<操作员主组> {orphan}")
                self.assertFalse(OI.needs_reexec(result, environ))

    def test_project_none_skips_identity(self):
        # No pointer -> no project -> nothing to decide; even a broken sudo environment does not refuse.
        for euid, environ in ((1001, {}), (1002, {}), (0, {}), (0, SUDO_U), (0, SUDO_V),
                              (0, {"SUDO_USER": "ghost"})):
            with self.subTest(euid=euid, environ=sorted(environ)):
                result = resolve(None, euid, environ)
                self.assertEqual("plain", result.action)
                self.assertIsNone(result.operator)
                self.assertIsNone(result.refusal)
                self.assertFalse(OI.needs_reexec(result, environ))

    def test_help_and_version_skip_identity(self):
        for argv in (["--help"], ["-h"], ["--version"], ["--project", U_PROJECT, "--help"]):
            with self.subTest(argv=argv):
                self.assertTrue(OI.skips_identity(argv))
        for argv in ([], ["--inspect-only"], ["--helpful"], ["--project", U_PROJECT]):
            with self.subTest(argv=argv):
                self.assertFalse(OI.skips_identity(argv))

    def test_new_project_operator_from_sudo_user_else_root(self):
        # O11 ④: a sudo load creating the project hands it to SUDO_USER; a direct root run keeps root.
        self.assert_runs(resolve(NEW_PROJECT, 0, SUDO_U), "represent", U_OPERATOR)
        self.assert_runs(resolve(NEW_PROJECT, 0), "self", ("root", 0, 0, "/root"))

    def test_banner_names_operator_and_current(self):
        # Design §4.2 example line, names substituted.
        self.assertEqual(
            "操作员：opuser（项目目录属主）；当前：root 经 sudo（发起人 opuser）→ 项目侧以 opuser 执行",
            resolve(U_PROJECT, 0, SUDO_U).banner,
        )
        for project, euid, environ, needles in (
            (U_PROJECT, 1001, {}, ("操作员：opuser", "当前：opuser")),
            (U_PROJECT, 0, {}, ("操作员：opuser", "当前：root")),
            (ROOT_PROJECT, 0, {}, ("操作员：root", "当前：root")),
            (U_PROJECT, 1002, {}, ("操作员：opuser", "当前：otheruser")),
        ):
            with self.subTest(project=project, euid=euid):
                banner = resolve(project, euid, environ).banner
                self.assertNotIn("\n", banner)
                for needle in needles:
                    self.assertIn(needle, banner)

    def test_mixed_modes_keep_the_same_operator(self):
        # Design §4.2: sudo one day, root login the next, U the day after -- the operator stays U.
        operators = [resolve(U_PROJECT, euid, environ).operator
                     for euid, environ in ((1001, {}), (0, SUDO_U), (0, {}))]
        self.assertEqual([U_OPERATOR] * 3, [None if item is None else tuple(item) for item in operators])


class _RecordedExec(Exception):
    pass


class ReexecTests(unittest.TestCase):
    """Guide WP-4 re-run mechanism; os.execvp and subprocess.Popen are recorders."""

    OPERATOR = OI.Operator(*U_OPERATOR)
    ENVIRON = {
        "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TERM": "xterm",
        "HOME": "/root", "USER": "root", "LOGNAME": "root", "SSH_AUTH_SOCK": "/tmp/agent.sock",
        "SUDO_USER": "opuser", "SUDO_UID": "1001", "PYTHONPATH": "/srv/elsewhere",
        "IB_INITIAL_PASSWORD": "fixture-value",
    }

    def exec_argv(self, **kwargs):
        calls = []

        def execvp(file, argv):
            calls.append((file, list(argv)))
            raise _RecordedExec()

        with mock.patch.object(OI.os, "execvp", execvp):
            with self.assertRaises(_RecordedExec):
                OI.exec_as_operator(self.OPERATOR, "/srv/fixture/tool.py", ["--inspect-only", "x y"],
                                    environ=self.ENVIRON, **kwargs)
        self.assertEqual(1, len(calls))
        return calls[0]

    @staticmethod
    def split_env(argv):
        head, rest = argv[:6], argv[6:]
        assignments = []
        while rest and "=" in rest[0] and not rest[0].startswith("/"):
            assignments.append(rest.pop(0))
        return head, dict(item.split("=", 1) for item in assignments), rest

    def test_exec_argv_starts_with_runuser_and_env_is_whitelist_only(self):
        file, argv = self.exec_argv()
        self.assertEqual("runuser", file)
        head, assignments, command = self.split_env(argv)
        self.assertEqual(["runuser", "-u", "opuser", "--", "env", "-i"], head)
        self.assertEqual({
            "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TERM": "xterm",
            "HOME": "/home/opuser", "USER": "opuser", "LOGNAME": "opuser",
        }, assignments)
        self.assertEqual([sys.executable, "/srv/fixture/tool.py", "--inspect-only", "x y"], command)
        # Exec replaces this process: no root parent stays behind, so no marker (已定 2 semantics).
        self.assertNotIn(OI.ROOT_PARENT_MARKER, assignments)

    def test_caller_named_variables_join_the_whitelist(self):
        # Guide WP-4: the caller may add names (D1: the --ib-initial-password-env variable).
        _file, argv = self.exec_argv(keep=("IB_INITIAL_PASSWORD", "NOT_SET_ANYWHERE"))
        _head, assignments, _command = self.split_env(argv)
        self.assertEqual("fixture-value", assignments["IB_INITIAL_PASSWORD"])
        self.assertNotIn("NOT_SET_ANYWHERE", assignments)
        self.assertEqual("/home/opuser", assignments["HOME"])
        with self.assertRaises(ValueError):
            OI.reexec_command(self.OPERATOR, "/srv/fixture/tool.py", [], environ=self.ENVIRON,
                              keep=(OI.ROOT_PARENT_MARKER,))

    def test_relative_script_becomes_absolute(self):
        argv = OI.reexec_command(self.OPERATOR, "tool.py", [], environ=self.ENVIRON)
        self.assertEqual([os.path.abspath("tool.py")], argv[-1:])

    def test_non_root_or_operator_root_never_reexecs(self):
        for project, euid, environ in ((U_PROJECT, 1001, {}), (ROOT_PROJECT, 0, {}), (ROOT_PROJECT, 0, SUDO_U),
                                       (U_PROJECT, 1002, {}), (U_PROJECT, 0, SUDO_V)):
            with self.subTest(project=project, euid=euid, environ=sorted(environ)):
                self.assertFalse(OI.needs_reexec(resolve(project, euid, environ), environ))
        for environ in ({}, SUDO_U):
            with self.subTest(represent=sorted(environ)):
                self.assertTrue(OI.needs_reexec(resolve(U_PROJECT, 0, environ), environ))

    def test_root_parent_marker_prevents_reexec(self):
        for environ in ({OI.ROOT_PARENT_MARKER: "1"}, {**SUDO_U, OI.ROOT_PARENT_MARKER: "1"}):
            with self.subTest(environ=sorted(environ)):
                result = resolve(U_PROJECT, 0, environ)
                self.assertEqual("represent", result.action)
                self.assertFalse(OI.needs_reexec(result, environ))

    def test_inherited_fds_survive_exec_and_wait(self):
        read_fd, write_fd = os.pipe()
        self.addCleanup(os.close, read_fd)
        self.addCleanup(os.close, write_fd)
        self.assertFalse(os.get_inheritable(read_fd))
        self.exec_argv(inherit_fds=(read_fd,))
        self.assertTrue(os.get_inheritable(read_fd))
        popen = self.fake_popen(0)
        with mock.patch.object(OI.subprocess, "Popen", popen):
            OI.run_as_operator(self.OPERATOR, "/srv/fixture/tool.py", [], environ=self.ENVIRON,
                               pass_fds=(read_fd, write_fd))
        self.assertEqual(1, len(popen.calls))
        self.assertEqual((read_fd, write_fd), tuple(popen.calls[0][1].get("pass_fds", ())))

    @staticmethod
    def fake_popen(returncode, during_wait=None):
        calls, signals = [], []

        class Child:
            def __init__(self, argv, **kwargs):
                calls.append((list(argv), kwargs))
                self.returncode = None

            def send_signal(self, number):
                signals.append(number)

            def wait(self):
                if during_wait is not None:
                    during_wait()
                self.returncode = returncode
                return returncode

        Child.calls, Child.signals = calls, signals
        return Child

    def test_wait_mode_sets_marker_and_returns_child_code(self):
        self.assertEqual("HTTP_ZTP_ROOT_PARENT", OI.ROOT_PARENT_MARKER)
        for returncode, expected in ((0, 0), (3, 3), (-signal.SIGTERM, 128 + signal.SIGTERM),
                                     (-signal.SIGKILL, 128 + signal.SIGKILL)):
            with self.subTest(returncode=returncode):
                popen = self.fake_popen(returncode)
                with mock.patch.object(OI.subprocess, "Popen", popen):
                    code = OI.run_as_operator(self.OPERATOR, "/srv/fixture/tool.py", ["--a"],
                                              environ=self.ENVIRON)
                self.assertEqual(expected, code)
                self.assertEqual(1, len(popen.calls))
                head, assignments, command = self.split_env(popen.calls[0][0])
                self.assertEqual(["runuser", "-u", "opuser", "--", "env", "-i"], head)
                self.assertEqual("1", assignments.get(OI.ROOT_PARENT_MARKER))
                self.assertEqual("/home/opuser", assignments["HOME"])
                self.assertEqual([sys.executable, "/srv/fixture/tool.py", "--a"], command)

    def test_wait_mode_forwards_sigint_and_sigterm_then_restores_handlers(self):
        # A guard catches any signal the module fails to take over, so a regression fails this test instead
        # of killing the test process.
        unexpected = []

        def guard(number, _frame):
            unexpected.append(number)

        for number in (signal.SIGINT, signal.SIGTERM):
            self.addCleanup(signal.signal, number, signal.signal(number, guard))
        before = (signal.getsignal(signal.SIGINT), signal.getsignal(signal.SIGTERM))

        def deliver():
            os.kill(os.getpid(), signal.SIGINT)
            os.kill(os.getpid(), signal.SIGTERM)

        popen = self.fake_popen(-signal.SIGTERM, during_wait=deliver)
        with mock.patch.object(OI.subprocess, "Popen", popen):
            code = OI.run_as_operator(self.OPERATOR, "/srv/fixture/tool.py", [], environ=self.ENVIRON)
        self.assertEqual([], unexpected)
        self.assertEqual([signal.SIGINT, signal.SIGTERM], popen.signals)
        self.assertEqual(128 + signal.SIGTERM, code)
        self.assertEqual(before, (signal.getsignal(signal.SIGINT), signal.getsignal(signal.SIGTERM)))


class ModuleContractTests(unittest.TestCase):
    """Library-module rules (appendix A.7, v3.1.2 brief) and the deferred import (http dev 2026-11-08)."""

    SOURCE = (TOOLS / "operator_identity.py").read_text(encoding="utf-8")

    def test_library_module_has_docstring_and_no_command_line(self):
        tree = ast.parse(self.SOURCE)
        self.assertTrue(ast.get_docstring(tree))
        self.assertNotIn("argparse", self.SOURCE)
        self.assertNotIn("__main__", self.SOURCE)
        self.assertIn("from __future__ import annotations", self.SOURCE)

    def test_top_level_imports_only_the_standard_library(self):
        tree = ast.parse(self.SOURCE)
        names = set()
        for node in tree.body:
            if isinstance(node, ast.Import):
                names.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                names.add(node.module.split(".")[0])
        self.assertLessEqual(names, {"__future__", "os", "pwd", "signal", "subprocess", "sys", "typing"})


class ActiveProjectPointerWorkflowTests(unittest.TestCase):
    """tools/project_contract.py's pointer reader feeding the operator rule (both real modules)."""

    def tree(self):
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        root = Path(holder.name).resolve()   # macOS /var -> /private/var
        (root / "DAY0-Prepare").mkdir()
        return root

    def test_pointer_project_owner_is_the_operator(self):
        root = self.tree()
        (root / "DAY0-Prepare/site-a").mkdir()
        os.symlink("site-a", root / "DAY0-Prepare/activate-project")
        project = OI.active_project(root)
        self.assertEqual(root / "DAY0-Prepare/site-a", project)
        result = OI.resolve_operator(project, euid=os.geteuid(), environ={})
        self.assertEqual("self", result.action)
        self.assertEqual(os.geteuid(), result.operator.uid)
        self.assertEqual(pwd.getpwuid(os.geteuid()).pw_gid, result.operator.gid)
        self.assertFalse(OI.needs_reexec(result, {}))

    def test_no_pointer_returns_none_and_skips_identity(self):
        project = OI.active_project(self.tree())
        self.assertIsNone(project)
        self.assertEqual("plain", OI.resolve_operator(project, euid=0, environ={}).action)

    def test_invalid_pointer_is_raised_not_treated_as_none(self):
        import project_contract

        root = self.tree()
        (root / "DAY0-Prepare/activate-project").write_text("site-a\n", encoding="utf-8")
        with self.assertRaises(project_contract.ActiveProjectPointerError):
            OI.active_project(root)
        (root / "DAY0-Prepare/activate-project").unlink()
        os.symlink("missing-site", root / "DAY0-Prepare/activate-project")
        with self.assertRaises(ValueError):
            OI.active_project(root)

    def test_unimportable_project_contract_raises_import_error(self):
        root = self.tree()
        os.symlink("site-a", root / "DAY0-Prepare/activate-project")
        with mock.patch.dict(sys.modules, {"project_contract": None}):
            with self.assertRaises(ImportError):
                OI.active_project(root)


if __name__ == "__main__":
    unittest.main()
