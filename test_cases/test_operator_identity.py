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
import hashlib
import json
import os
from pathlib import Path
import pwd
import signal
import subprocess
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
        # Q-060: keep still reaches the real child (workflow below), but never argv.
        self.assertNotIn("IB_INITIAL_PASSWORD", assignments)
        self.assertFalse(any("fixture-value" in item for item in argv))
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

    def test_transport_bootstrap_alone_disables_bytecode_and_keeps_the_target_interpreter(self):
        argv = OI.reexec_command(OI.Operator(*U_OPERATOR), "/fixture/entry.py", ["literal argument"],
                                 environ={"PUBLIC_M6B": "public-input"}, keep=("PUBLIC_M6B",),
                                 interpreter=("python3", "-B"), env_fds=(123,))
        index = argv.index(sys.executable)
        self.assertEqual([sys.executable, "-I", "-S", "-B", "-c"], argv[index:index + 5])
        self.assertEqual(["python3", "-B", "/fixture/entry.py", "literal argument"], argv[-4:])

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
        self.assertLessEqual(names, {"__future__", "json", "os", "pwd", "signal", "subprocess", "sys", "typing"})


class OperatorEnvironmentPipeWorkflowTests(unittest.TestCase):
    """Q-060 / r515 §9: real exec/wait, original reader, independent public input."""

    def setUp(self):
        parent = Path(os.environ["HTTP_TEST_OWNED_ROOT"])
        self.assertEqual(parent, parent.resolve())
        self.assertEqual(0o700, parent.stat().st_mode & 0o777)
        self.holder = tempfile.TemporaryDirectory(prefix="m6b-real-", dir=parent)
        self.addCleanup(self.holder.cleanup)
        self.base = Path(self.holder.name)
        self.home = self.base / "home"
        self.home.mkdir()
        self.bin = self.base / "bin"
        self.bin.mkdir()

    def run_transport(self, mode, *, short=False, path_keep=False):
        # Public synthetic values only; failure diagnostics never print values.
        values = {
            "PUBLIC_M6B_VALUE": "-".join(("PUBLIC", "M6B", "literal")),
            "PUBLIC_M6B_EMPTY": "", "PUBLIC_M6B_SPACE": "a b c",
            "PUBLIC_M6B_NEWLINE": "first\nsecond", "PUBLIC_M6B_UNICODE": "值-é",
            "PUBLIC_M6B_SURROGATE": "raw-" + chr(0xDCE9),
            "LANG": "C.UTF-8", "HOME": "not-the-passwd-home",
        }
        if path_keep:
            values["PATH"] = str(self.bin) + ":/usr/bin:/bin"
        expected = dict(values, HOME=str(self.home), USER="fixture-op", LOGNAME="fixture-op")
        if mode == "wait":
            expected[OI.ROOT_PARENT_MARKER] = "1"
        payload = {"nvos_initial_password": "-".join(("PUBLIC", "M6B", "business"))}
        report = self.base / "result.json"
        record = self.base / "runuser.json"
        target = self.base / "target.py"
        target.write_text(
            "import hashlib,json,os,pathlib,sys\n"
            + "sys.path.insert(0," + repr(str(TOOLS)) + ")\n"
            + "import credentials_fd\n"
            + "data=credentials_fd.read_credentials(int(sys.argv[2]),required=(),optional=('nvos_initial_password',))\n"
            + "names=" + repr(tuple(expected)) + "\n"
            + "answer={'env':{name:os.environ.get(name) for name in names},"
              "'business':hashlib.sha256(json.dumps(data,sort_keys=True).encode()).hexdigest(),"
              "'args':sys.argv[3:],'unrelated':'PUBLIC_M6B_UNRELATED' in os.environ,"
              "'missing':'PUBLIC_M6B_MISSING' in os.environ,"
              "'marker':os.environ.get('HTTP_ZTP_ROOT_PARENT'),"
              "'pid':os.getpid()}\n"
            + "pathlib.Path(sys.argv[1]).write_text(json.dumps(answer,ensure_ascii=True))\n"
            + "raise SystemExit(23)\n", encoding="utf-8")
        stub = self.bin / "runuser"
        stub.write_text(
            "#!" + sys.executable + "\nimport json,os,pathlib,sys\n"
            + "pathlib.Path(" + repr(str(record)) + ").write_text(json.dumps(sys.argv[1:]))\n"
            + "assert sys.argv[1:4]==['-u','fixture-op','--']\n"
            + "os.execv('/usr/bin/env',sys.argv[4:])\n", encoding="utf-8")
        stub.chmod(0o700)
        launcher = self.base / "launcher.py"
        launcher.write_text(
            "import os,pathlib,sys\n"
            + "sys.path.insert(0," + repr(str(TOOLS)) + ")\nimport operator_identity as oi\n"
            + "values=" + repr(values) + "\n"
            + "environment={'PATH':" + repr(str(self.bin) + ":/usr/bin:/bin")
            + ",'PUBLIC_M6B_UNRELATED':'excluded',**values}\n"
            + "operator=oi.Operator('fixture-op',os.getuid(),os.getgid()," + repr(str(self.home)) + ")\n"
            + "pathlib.Path(" + repr(str(self.base / "driver.pid")) + ").write_text(str(os.getpid()))\n"
            + ("real_write=os.write\ndef limited(fd,data):\n return real_write(fd,data[:7])\noi.os.write=limited\n" if short else "")
            + "args=[" + repr(str(report)) + ",sys.argv[1],'literal argument with spaces']\n"
            + "options=dict(environ=environment,keep=" + repr(tuple(values) + ("PUBLIC_M6B_MISSING",))
            + (",interpreter=('python3','-B'))\n" if path_keep else ",interpreter=(sys.executable,'-B'))\n")
            + ("oi.exec_as_operator(operator," + repr(str(target)) + ",args,inherit_fds=(int(sys.argv[1]),),**options)\n"
               if mode == "exec" else
               "raise SystemExit(oi.run_as_operator(operator," + repr(str(target))
               + ",args,pass_fds=(int(sys.argv[1]),),**options))\n"), encoding="utf-8")
        reader, writer = os.pipe()
        try:
            os.write(writer, json.dumps(payload).encode())
        finally:
            os.close(writer)
        try:
            environment = dict(os.environ, HOME=str(self.home), PATH=str(self.bin) + ":/usr/bin:/bin")
            done = subprocess.run([sys.executable, "-B", str(launcher), str(reader)],
                                  env=environment, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  pass_fds=(reader,), timeout=30)
        finally:
            os.close(reader)
        self.assertEqual(23, done.returncode, "real operator chain must keep target exit")
        self.assertEqual(b"", done.stdout, "no transport value on stdout")
        self.assertEqual(b"", done.stderr, "no transport value or traceback on stderr")
        answer = json.loads(report.read_text())
        self.assertTrue(answer["env"] == expected, "final environment differs from independent input")
        self.assertFalse(answer["unrelated"], "unrequested environment crossed identity boundary")
        self.assertFalse(answer["missing"], "absent keep name became an environment entry")
        self.assertEqual("1" if mode == "wait" else None, answer["marker"])
        self.assertEqual(["literal argument with spaces"], answer["args"])
        driver_pid = int((self.base / "driver.pid").read_text())
        if mode == "exec":
            self.assertEqual(driver_pid, answer["pid"], "exec must replace the driver without a waiting parent")
        else:
            self.assertNotEqual(driver_pid, answer["pid"], "wait keeps its original parent")
        self.assertEqual(hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest(),
                         answer["business"], "real original business reader changed input")
        argv = json.loads(record.read_text())
        for name, value in values.items():
            if name == "HOME":
                continue  # Passwd overrides this input; it must not become a payload value.
            with self.subTest(name=name, mode=mode, short=short):
                self.assertFalse(any(item.startswith(name + "=") for item in argv),
                                 "caller keep assignment leaked into runuser argv")
                if value:
                    self.assertFalse(any(value in item for item in argv),
                                     "caller keep value leaked into runuser argv")
                    encoded = json.dumps(value, ensure_ascii=True)[1:-1]
                    self.assertFalse(any(encoded in item for item in argv),
                                     "encoded caller value leaked into runuser argv")

    def test_real_exec_keeps_original_environment_and_business_fd_without_argv_values(self):
        self.run_transport("exec")

    def test_real_wait_keeps_original_environment_and_business_fd_without_argv_values(self):
        self.run_transport("wait")

    def test_real_exec_positive_short_writes_keep_the_complete_ordered_payload(self):
        self.run_transport("exec", short=True)

    def test_real_wait_positive_short_writes_keep_the_complete_ordered_payload(self):
        self.run_transport("wait", short=True)

    def test_relative_interpreter_and_overlapping_path_keep_preserve_clean_search_semantics(self):
        for mode in ("exec", "wait"):
            with self.subTest(mode=mode):
                self.run_transport(mode, path_keep=True)

    def test_pure_command_without_payload_context_refuses_instead_of_using_argv(self):
        with self.assertRaises(ValueError):
            OI.reexec_command(OI.Operator(*U_OPERATOR), "/fixture/entry.py", [],
                              environ={"PUBLIC_M6B_VALUE": "-".join(("PUBLIC", "M6B", "one"))},
                              keep=("PUBLIC_M6B_VALUE",))

    def test_actual_bootstrap_ordinary_errors_are_fixed_and_never_start_business(self):
        cases = {
            "json": b"public-malformed-input", "decode": b"\xff",
            "shape": b"[]", "framework": b'{"HOME":"public-not-authorized"}',
            "restore": b'{"PUBLIC_M6B_ENV":"public\\u0000invalid"}',
            "read": b'{"PUBLIC_M6B_ENV":"public-valid"}',
            "exec": b'{"PUBLIC_M6B_ENV":"public-valid"}',
        }
        for case, raw in cases.items():
            with self.subTest(case=case):
                reader, writer = os.pipe()
                os.write(writer, raw)
                os.close(writer)
                marker = self.base / (case + ".business")
                target = self.base / (case + ".py")
                target.write_text("from pathlib import Path\nPath(" + repr(str(marker)) + ").write_text('bad')\n")
                interpreter = "m6b-public-absent-executable" if case == "exec" else sys.executable
                command = [sys.executable, "-I", "-S", "-B", "-c", OI._ENVIRONMENT_BOOTSTRAP,
                           json.dumps([reader]), json.dumps(["PUBLIC_M6B_ENV"]), interpreter, str(target)]
                try:
                    result = subprocess.run(command, env=dict(os.environ, HOME=str(self.home)),
                                            pass_fds=() if case == "read" else (reader,),
                                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE, timeout=20)
                finally:
                    os.close(reader)
                self.assertEqual(2, result.returncode, "ordinary bootstrap failure code changed")
                self.assertEqual(b"", result.stdout)
                self.assertEqual(b"operator environment transport failed\n", result.stderr,
                                 "bootstrap must not expose the exception or input")
                self.assertFalse(marker.exists(), "business entry ran after transport failure")

    def test_actual_bootstrap_keyboardinterrupt_is_not_converted_and_closes_its_reader(self):
        reader, writer = os.pipe()
        os.close(writer)
        report = self.base / "interrupted.json"
        program = (
            "import json,os,pathlib,sys\n"
            + "sys.path.insert(0," + repr(str(TOOLS)) + ")\nimport operator_identity as oi\n"
            + "descriptor=int(sys.argv[1])\n"
            + "def interrupt(fd,size):\n raise KeyboardInterrupt\nos.read=interrupt\n"
            + "sys.argv=['bootstrap',json.dumps([descriptor]),json.dumps(['PUBLIC_M6B_ENV']),'not-started']\n"
            + "try:\n exec(oi._ENVIRONMENT_BOOTSTRAP)\nexcept KeyboardInterrupt:\n"
            + " try:\n  os.fstat(descriptor)\n  closed=False\n except OSError:\n  closed=True\n"
            + " pathlib.Path(" + repr(str(report)) + ").write_text(json.dumps({'closed':closed}))\n"
            + " raise SystemExit(130)\n")
        try:
            result = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", program, str(reader)],
                                    env=dict(os.environ, HOME=str(self.home)), pass_fds=(reader,),
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=20)
        finally:
            os.close(reader)
        self.assertEqual(130, result.returncode, "KeyboardInterrupt must escape the bootstrap")
        self.assertTrue(json.loads(report.read_text())["closed"], "interrupted reader stayed open")

    def test_actual_blocked_bootstrap_keeps_sigint_and_sigterm_semantics(self):
        import time
        for number in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(number=number):
                reader, writer = os.pipe()
                ready = self.base / ("reading-" + str(number))
                program = (
                    "import json,os,pathlib,sys\n"
                    + "sys.path.insert(0," + repr(str(TOOLS)) + ")\nimport operator_identity as oi\n"
                    + "descriptor=int(sys.argv[1])\nreal_read=os.read\n"
                    + "def read(fd,size):\n pathlib.Path(" + repr(str(ready))
                    + ").write_text('ready')\n return real_read(fd,size)\nos.read=read\n"
                    + "sys.argv=['bootstrap',json.dumps([descriptor]),json.dumps(['PUBLIC_M6B_ENV']),'not-started']\n"
                    + "exec(oi._ENVIRONMENT_BOOTSTRAP)\n")
                child = None
                try:
                    child = subprocess.Popen([sys.executable, "-I", "-S", "-B", "-c", program, str(reader)],
                                             env=dict(os.environ, HOME=str(self.home)), pass_fds=(reader,),
                                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    until = time.monotonic() + 10
                    while not ready.exists() and child.poll() is None and time.monotonic() < until:
                        time.sleep(0.01)
                    self.assertTrue(ready.exists(), "bootstrap did not reach real pipe read")
                    child.send_signal(number)
                    out, err = child.communicate(timeout=10)
                    self.assertEqual(-number, child.returncode, "signal was changed into ordinary error rc2")
                    self.assertEqual(b"", out)
                    self.assertNotIn(b"operator environment transport failed", err)
                finally:
                    os.close(reader)
                    os.close(writer)
                    if child is not None and child.poll() is None:
                        child.kill()
                        child.communicate(timeout=10)

    def test_actual_wait_parent_returns_130_and_143_for_bootstrap_signal_termination(self):
        import time
        for number in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signal=number):
                ready = self.base / ("wait-ready-" + str(number))
                target = self.base / ("unreached-" + str(number) + ".py")
                marker = self.base / ("business-started-" + str(number))
                target.write_text("from pathlib import Path\nPath(" + repr(str(marker)) + ").touch()\n")
                stub = self.bin / "runuser"
                stub.write_text("#!" + sys.executable + "\nimport os,sys\nos.execv('/usr/bin/env',sys.argv[4:])\n")
                stub.chmod(0o700)
                setup = ("import os,pathlib,signal\n_real_read=os.read\n"
                         "def observed_read(fd,size):\n"
                         " pathlib.Path(" + repr(str(ready)) + ").touch()\n"
                         " signal.pause()\n return _real_read(fd,size)\n"
                         "os.read=observed_read\n")
                driver = ("import sys\nsys.path.insert(0," + repr(str(TOOLS)) + ")\n"
                          "import operator_identity as oi\n"
                          "oi._ENVIRONMENT_BOOTSTRAP=" + repr(setup + OI._ENVIRONMENT_BOOTSTRAP) + "\n"
                          "raise SystemExit(oi.run_as_operator(oi.Operator('fixture-op',501,20,"
                          + repr(str(self.home)) + ")," + repr(str(target)) + ",[],environ="
                          + repr({"PATH": str(self.bin) + ":/usr/bin:/bin", "PUBLIC_M6B": "public-value"})
                          + ",keep=('PUBLIC_M6B',)))\n")
                child = subprocess.Popen([sys.executable, "-I", "-B", "-c", driver],
                                         env=dict(os.environ, HOME=str(self.home),
                                                  PATH=str(self.bin) + ":/usr/bin:/bin"),
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    deadline = time.monotonic() + 15
                    while not ready.exists() and child.poll() is None and time.monotonic() < deadline:
                        time.sleep(0.01)
                    if not ready.exists() and child.poll() is not None:
                        _out, fixture_error = child.communicate(timeout=15)
                        (Path(os.environ["HTTP_TEST_OWNED_ROOT"]) / ("wait-fixture-" + str(number) + ".stderr")).write_bytes(fixture_error)
                    self.assertTrue(ready.exists(), "real wait child did not enter bootstrap")
                    child.send_signal(number)
                    out, err = child.communicate(timeout=15)
                    self.assertEqual(128 + number, child.returncode)
                    self.assertEqual(b"", out)
                    self.assertNotIn(b"operator environment transport failed", err)
                    self.assertFalse(marker.exists(), "business started after bootstrap interruption")
                finally:
                    if child.poll() is None:
                        child.kill()
                        child.communicate(timeout=15)


class EnvironmentPipeOwnershipTests(unittest.TestCase):
    """r515 §9.3: only newly created descriptors belong to the carrier."""

    def test_positive_short_write_uses_one_write_per_pipe_and_seals_each_chunk(self):
        payload = {"PUBLIC_M6B": "independent-" * 8, "PUBLIC_EMPTY": ""}
        real_pipe, real_write = os.pipe, os.write
        pairs, writes, readers = [], [], ()

        def pipe():
            pair = real_pipe()
            pairs.append(pair)
            return pair

        def write(descriptor, data):
            writes.append((len(pairs), descriptor, os.get_blocking(descriptor)))
            return real_write(descriptor, data[:7])

        try:
            with mock.patch.object(OI.os, "pipe", side_effect=pipe), \
                    mock.patch.object(OI.os, "write", side_effect=write):
                readers = OI._seal_environment(payload)
            self.assertGreater(len(pairs), 1)
            self.assertEqual(tuple(pair[0] for pair in pairs), readers)
            self.assertEqual(list(range(1, len(pairs) + 1)), [number for number, _fd, _blocking in writes])
            self.assertTrue(all(not blocking for _number, _fd, blocking in writes))
            chunks = []
            for reader in readers:
                chunks.append(os.read(reader, 65536))
                self.assertEqual(b"", os.read(reader, 1), "writer was not sealed before the consumer")
            self.assertEqual(payload, json.loads(b"".join(chunks).decode("ascii")))
        finally:
            for reader in readers:
                os.close(reader)

    def test_every_producer_failure_closes_only_its_pipes_and_never_consumes_business_fd(self):
        real_pipe, real_write = os.pipe, os.write
        operator = OI.Operator(*U_OPERATOR)
        for failure in ("second-pipe", "blocking", "again", "zero", "command", "inherit", "exec", "popen"):
            with self.subTest(failure=failure):
                reader, writer = real_pipe()
                original = b"independent-public-business-input"
                real_write(writer, original)
                os.close(writer)
                made, writes = [], []

                def pipe():
                    if failure == "second-pipe" and made:
                        raise OSError("controlled second pipe failure")
                    pair = real_pipe()
                    made.extend(pair)
                    return pair

                def write(fd, data):
                    writes.append(len(made) // 2)
                    if failure == "again":
                        raise BlockingIOError("controlled no progress")
                    if failure == "zero":
                        return 0
                    return real_write(fd, data[:7])

                options = dict(environ={"PUBLIC_M6B": "public-long-input-" * 3}, keep=("PUBLIC_M6B",))
                try:
                    with mock.patch.object(OI.os, "pipe", side_effect=pipe), \
                            mock.patch.object(OI.os, "write", side_effect=write), \
                            mock.patch.object(OI.os, "execvp", side_effect=OSError("controlled exec failure")), \
                            mock.patch.object(OI.subprocess, "Popen", side_effect=OSError("controlled spawn failure")):
                        from contextlib import ExitStack
                        with ExitStack() as stack:
                            if failure == "blocking":
                                stack.enter_context(mock.patch.object(OI.os, "set_blocking", side_effect=OSError("controlled blocking failure")))
                            if failure == "command":
                                stack.enter_context(mock.patch.object(OI, "reexec_command", side_effect=ValueError("controlled command failure")))
                            if failure == "inherit":
                                stack.enter_context(mock.patch.object(OI.os, "set_inheritable", side_effect=OSError("controlled inherit failure")))
                            with self.assertRaises((OSError, ValueError)):
                                if failure == "popen":
                                    OI.run_as_operator(operator, "/fixture/entry.py", [], pass_fds=(reader,), **options)
                                else:
                                    OI.exec_as_operator(operator, "/fixture/entry.py", [], inherit_fds=(reader,), **options)
                    self.assertTrue(made, "carrier never created an owned pipe")
                    for fd in made:
                        with self.assertRaises(OSError):
                            os.fstat(fd)
                    self.assertEqual(len(writes), len(set(writes)), "one write per new empty pipe")
                    self.assertTrue(os.read(reader, 4096) == original, "caller input was consumed or changed")
                finally:
                    os.close(reader)
                    for fd in made:
                        try:
                            os.close(fd)
                        except OSError:
                            pass

    def test_absent_or_framework_only_keep_creates_no_carrier(self):
        for keep, environment in (((), {}), (("PUBLIC_MISSING",), {}),
                                  (("HOME", "USER", "LOGNAME"), {"HOME": "ignored", "USER": "ignored"})):
            with self.subTest(keep=keep), mock.patch.object(OI.os, "pipe", side_effect=AssertionError("unneeded pipe")), \
                    mock.patch.object(OI.os, "execvp", side_effect=_RecordedExec):
                with self.assertRaises(_RecordedExec):
                    OI.exec_as_operator(OI.Operator(*U_OPERATOR), "/fixture/entry.py", [],
                                        keep=keep, environ=environment)


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
