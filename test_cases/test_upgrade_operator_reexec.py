"""Direct contract: upgrade.py and upgrade2.py re-run as the operator when root runs them (v3.1.2 WP-10, I-006).

Expectations come from the requirement texts, never from the entries under test:
- design `设计/I-006与R-005实现计划.md` §4.3 (:97): root running upgrade/upgrade2 for another account's project re-runs
  as the operator before doing anything or asking any password; another ordinary user is refused;
- 问题文档 I-006 :351 (owner 2026-10-27): running as a different identity is refused, saying who owns the project and
  who is running;
- v3.1.2 guide WP-10 steps 1-5: -h/--help/--version skip the step; the project is --project, else the one
  DAY0-Prepare/activate-project selects; no project (flat bundle, clean clone, no pointer) runs unchanged; an
  invalid pointer stops before anything runs; root re-runs once in exec form
  `runuser -u <op> -- env -i <PATH LANG LC_ALL TERM> HOME/USER/LOGNAME of the operator <python> <entry> <args>`;
  the venv switch comes after the identity switch; upgrade2 switches before the shared runtime guard
  (test_ibsw_v2_entry.py :98-117); the identity line is printed;
- guide WP-4 / 已定 2: HTTP_ZTP_ROOT_PARENT (started by a root parent) never re-runs;
- guide 3.2 O15 (a): upgrade.py does not import tools/operator_identity.py (the flat bundle lacks it); it keeps an
  inline copy of the rule, and this module keeps the two equal: same decision, same runuser argv and environment
  for the same inputs.

No real uid switch happens here (guide 2.2 item 6).  euid, environ, passwd and stat are the identity rule's inputs:
the tests wrap the entries' rule functions with injected inputs instead of mocking os.geteuid globally.  os.execvp,
os.execve, password prompts and the runtime guard are recorders that stop the run.
"""
from __future__ import annotations

import ast
import contextlib
import functools
import importlib.util
import io
import os
from pathlib import Path
import pwd
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_cases.ibsw225_fixture_support.runtime_source_support import support as _support
from test_cases.test_ibsw225_flat_tools_layout import MEMBERS as FLAT_MEMBERS

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
ENTRY = ROOT / "infiniband/bringup/xdr-upgrade/upgrade.py"
ENTRY2 = ROOT / "infiniband/bringup/xdr-upgrade/upgrade2.py"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import ib_bringup_runtime_guard as GUARD2  # noqa: E402  upgrade2 imports the guard by this bare name
import operator_identity as OI  # noqa: E402

app = _support(unittest.TestCase()).app


def _load_upgrade2():
    spec = importlib.util.spec_from_file_location("ibsw_upgrade2_operator_reexec_under_test", ENTRY2)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


app2 = _load_upgrade2()

ROOT_ENTRY = pwd.struct_passwd(("root", "x", 0, 0, "root", "/root", "/bin/bash"))
# The operator's primary group differs from its uid so a uid-for-gid slip is visible (O9).
U_ENTRY = pwd.struct_passwd(("opuser", "x", 1001, 2001, "operator", "/home/opuser", "/bin/bash"))
V_ENTRY = pwd.struct_passwd(("otheruser", "x", 1002, 2002, "other", "/home/otheruser", "/bin/bash"))
ACCOUNTS = (ROOT_ENTRY, U_ENTRY, V_ENTRY)
U_PROJECT = "/srv/fixture/DAY0-Prepare/u-project"
ROOT_PROJECT = "/srv/fixture/DAY0-Prepare/root-project"
NEW_PROJECT = "/srv/fixture/DAY0-Prepare/new-project"
GHOST_PROJECT = "/srv/fixture/DAY0-Prepare/ghost-project"
OWNERS = {U_PROJECT: 1001, ROOT_PROJECT: 0, GHOST_PROJECT: 3003}
SUDO_U = {"SUDO_USER": "opuser", "SUDO_UID": "1001", "SUDO_GID": "2001"}
SUDO_V = {"SUDO_USER": "otheruser", "SUDO_UID": "1002", "SUDO_GID": "2002"}
MARKER = "HTTP_ZTP_ROOT_PARENT"
VENV_MARKER = "IBSW_UPGRADE_VENV_REEXEC"
SHELL_ENV = {"PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8", "TERM": "xterm"}
RUNUSER_HEAD = ["runuser", "-u", "opuser", "--", "env", "-i"]
REAL_INLINE_RULE = app._resolve_operator
REAL_SHARED_RULE = OI.resolve_operator
# requirements.txt of the entry directory: eight exact pins plus PyYAML (test_ibsw_upgrade_usability PINS).
VENV_VERSIONS = (("paramiko", "5.0.0"), ("bcrypt", "5.0.0"), ("cryptography", "50.0.1"), ("invoke", "2.2.1"),
                 ("PyNaCl", "1.6.2"), ("cffi", "2.0.0"), ("pycparser", "2.23"), ("typing-extensions", "4.16.0"),
                 ("PyYAML", "6.0.2"))


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


def injected(rule, euid, environ):
    """The entry's own rule with the identity inputs fixed: what the process would see as euid, env and passwd."""
    return functools.partial(rule, euid=euid, environ=dict(environ), getpwuid=getpwuid, getpwnam=getpwnam,
                             stat=fake_stat)


def missing_runtime(name):
    raise app.metadata.PackageNotFoundError(name)


def split_runuser(argv):
    """(head, NAME=VALUE assignments after env -i, command) of a runuser argv."""
    head, rest = list(argv[:6]), list(argv[6:])
    assignments = {}
    while rest and "=" in rest[0] and not rest[0].startswith("/"):
        name, _, value = rest.pop(0).partition("=")
        assignments[name] = value
    return head, assignments, rest


def make_venv(home):
    """A fixed-candidate venv (~/.venvs/http/ibsw-upgrade) whose metadata satisfies requirements.txt."""
    venv = home / ".venvs" / "http" / "ibsw-upgrade"
    site = venv / "lib" / "python3.9" / "site-packages"
    (venv / "bin").mkdir(parents=True)
    site.mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\n")
    python = venv / "bin" / "python3"
    python.write_text("#!/bin/sh\nexit 97\n")
    python.chmod(0o755)
    for name, version in VENV_VERSIONS:
        info = site / (name.replace("-", "_") + "-" + version + ".dist-info")
        info.mkdir()
        (info / "METADATA").write_text("Metadata-Version: 2.1\nName: %s\nVersion: %s\n" % (name, version))
    for directory in (home, home / ".venvs", home / ".venvs" / "http", venv, venv / "bin", venv / "lib",
                      site.parent, site):
        directory.chmod(0o755)
    return venv


def _main_block_code():
    blocks = [node for node in ast.parse(ENTRY.read_text(encoding="utf-8")).body
              if isinstance(node, ast.If) and ast.unparse(node.test) == "__name__ == '__main__'"]
    assert len(blocks) == 1, "upgrade.py has exactly one script-entry block"
    return compile(ast.Module(body=blocks[0].body, type_ignores=[]), str(ENTRY), "exec")


class _Stop(BaseException):
    """Ends a run at an exec, a prompt or the guard; BaseException so the entry cannot swallow it."""


class _Recorder:
    def __init__(self):
        self.events = []

    def execvp(self, file, argv):
        self.events.append(("execvp", file, list(argv)))
        raise _Stop()

    def execve(self, path, argv, env):
        self.events.append(("execve", path, list(argv), dict(env)))
        raise _Stop()

    def prompt(self, *_args, **_kwargs):
        self.events.append(("prompt",))
        raise _Stop()

    def guard(self):
        recorder = self

        class Guard:
            def __enter__(self):
                recorder.events.append(("guard",))
                raise _Stop()

            def __exit__(self, *_exc):
                return False
        return Guard

    def kinds(self):
        return [event[0] for event in self.events]


class _EntryHarness(unittest.TestCase):
    def setUp(self):
        holder = tempfile.TemporaryDirectory(prefix="w10-upgrade-reexec-")
        self.addCleanup(holder.cleanup)
        self.root = Path(holder.name).resolve()   # macOS /var -> /private/var
        self.home = self.root / "invoking-home"
        make_venv(self.home)

    def run_upgrade(self, args, *, euid, environ=(), runtime_present=False, extra=()):
        """Run the real `if __name__ == "__main__":` body of upgrade.py in its module namespace.

        The venv switch is live: when it runs before the identity step it execs the fixed venv (an execve event).
        """
        environ = dict(environ)
        recorder = _Recorder()
        stderr = io.StringIO()
        version = (lambda name: dict(VENV_VERSIONS)[name]) if runtime_present else missing_runtime
        rule = injected(REAL_INLINE_RULE, euid, environ)
        with contextlib.ExitStack() as stack:
            for patcher in (
                patch.object(app, "_resolve_operator", rule),
                patch.dict(os.environ, {**SHELL_ENV, "HOME": str(self.home), **environ}, clear=True),
                patch.object(os, "execvp", recorder.execvp),
                patch.object(os, "execve", recorder.execve),
                patch.object(app, "_read_password", recorder.prompt),
                patch.object(app.getpass, "getpass", recorder.prompt),
                patch.object(app.metadata, "version", side_effect=version),
                patch.object(app, "_runtime_instance_guard", recorder.guard()),
                patch.object(sys, "argv", ["upgrade.py", *args]),
                contextlib.redirect_stderr(stderr),
                *extra,
            ):
                stack.enter_context(patcher)
            try:
                exec(_main_block_code(), app.__dict__)
            except _Stop:
                pass
            except SystemExit as exit:
                recorder.events.append(("exit", exit.code))
        return recorder, stderr.getvalue()

    def run_upgrade2(self, args, *, euid, environ=(), extra=()):
        environ = dict(environ)
        recorder = _Recorder()
        stderr = io.StringIO()
        with contextlib.ExitStack() as stack:
            for patcher in (
                patch.object(OI, "resolve_operator", injected(REAL_SHARED_RULE, euid, environ)),
                patch.dict(os.environ, {**SHELL_ENV, "HOME": str(self.home), **environ}, clear=True),
                patch.object(os, "execvp", recorder.execvp),
                patch.object(GUARD2, "_runtime_instance_guard", recorder.guard()),
                patch.object(app2, "run", side_effect=AssertionError("run() before the identity step")),
                patch.object(sys, "argv", ["upgrade2.py", *args]),
                contextlib.redirect_stderr(stderr),
                *extra,
            ):
                stack.enter_context(patcher)
            try:
                code = app2.main()
            except _Stop:
                pass
            else:
                recorder.events.append(("exit", code))
        return recorder, stderr.getvalue()

    def assert_runuser(self, event, entry, args, *, environ=()):
        self.assertEqual("execvp", event[0], event)
        self.assertEqual("runuser", event[1])
        head, assignments, command = split_runuser(event[2])
        self.assertEqual(RUNUSER_HEAD, head)
        expected = {name: value for name, value in {**SHELL_ENV, **dict(environ)}.items()
                    if name in ("PATH", "LANG", "LC_ALL", "TERM")}
        expected.update(HOME="/home/opuser", USER="opuser", LOGNAME="opuser")
        self.assertEqual(expected, assignments)
        self.assertEqual([sys.executable, str(entry), *args], command)

    def pointer_tree(self):
        """A tree whose DAY0-Prepare/activate-project selects site-a; returns (tree, project path)."""
        tree = self.root / "tree"
        (tree / "DAY0-Prepare/site-a").mkdir(parents=True)
        os.symlink("site-a", tree / "DAY0-Prepare/activate-project")
        return tree, str(tree / "DAY0-Prepare/site-a")

    def broken_pointer_tree(self):
        """A regular file is not a pointer: project_contract raises ActiveProjectPointerError."""
        tree = self.root / "broken"
        (tree / "DAY0-Prepare").mkdir(parents=True)
        (tree / "DAY0-Prepare/activate-project").write_text("site-a\n", encoding="utf-8")
        return tree


class UpgradeReexecEntryTests(_EntryHarness):
    """Guide WP-10 direct table, plus the pointer, marker and help rows of steps 1-4."""

    def test_upgrade_root_on_user_project_execs_runuser_before_venv_switch(self):
        # Design §4.3 :97: before doing anything.  The venv switch is live and would exec first if it ran first.
        args = ("--inspect-only", "--project", U_PROJECT)
        for label, environ in (("root login", {}), ("sudo by the owner", SUDO_U)):
            with self.subTest(label):
                recorder, _err = self.run_upgrade(args, euid=0, environ=environ)
                self.assertEqual(["execvp"], recorder.kinds(), recorder.events)
                self.assert_runuser(recorder.events[0], ENTRY, args, environ=environ)

    def test_upgrade_no_password_prompt_before_reexec(self):
        # Design §4.3 :97: no password is asked before the switch, even for a real upgrade.
        args = ("--upgrade", "--yes", "--password", "--project", U_PROJECT)
        recorder, _err = self.run_upgrade(args, euid=0, runtime_present=True)
        self.assertEqual(["execvp"], recorder.kinds(), recorder.events)
        self.assertNotIn(("prompt",), recorder.events)

    def test_upgrade_env_is_whitelist_with_operator_home(self):
        # Guide WP-4/WP-10: env -i keeps PATH LANG LC_ALL TERM; HOME/USER/LOGNAME are the operator's (passwd).
        environ = {"SSH_AUTH_SOCK": "/tmp/agent.sock", "PYTHONPATH": "/srv/elsewhere", "USER": "root",
                   "LOGNAME": "root", VENV_MARKER: "1", "IBSW_TEST_CANARY": "root-only", **SUDO_U}
        args = ("--inspect-only", "--project", U_PROJECT)
        recorder, _err = self.run_upgrade(args, euid=0, environ=environ)
        self.assertEqual(["execvp"], recorder.kinds(), recorder.events)
        self.assert_runuser(recorder.events[0], ENTRY, args, environ=environ)

    def test_upgrade_foreign_user_refused_with_owner_and_current(self):
        # 问题文档 :351: refused, naming the project owner and the current user; nothing else runs.
        for label, euid, environ in (("V directly", 1002, {}), ("V with sudo (O7 ②)", 0, SUDO_V)):
            with self.subTest(label):
                recorder, err = self.run_upgrade(("--inspect-only", "--project", U_PROJECT), euid=euid,
                                                 environ=environ)
                self.assertEqual([("exit", 2)], recorder.events)
                for needle in (U_PROJECT, "opuser", "otheruser"):
                    self.assertIn(needle, err)

    def test_upgrade_flat_bundle_without_project_runs_unchanged(self):
        # O15 (a): a flat bundle has no project; root or not, the identity step decides nothing.
        empty = self.root / "flat-bundle"
        empty.mkdir()
        calls = []

        def rule(*args, **kwargs):
            calls.append(args)
            return REAL_INLINE_RULE(*args, **kwargs)
        recorder, err = self.run_upgrade(("--inspect-only",), euid=0, extra=(
            patch.object(app, "_REPOSITORY_ROOT", empty), patch.object(app, "_resolve_operator", rule)))
        self.assertEqual([], calls)
        self.assertEqual(["execve"], recorder.kinds(), recorder.events)   # the unchanged flow: venv switch
        self.assertNotIn("操作员", err)

    def test_upgrade_flat_bundle_copy_without_pyyaml_runs_unchanged(self):
        # The real flat bundle (test_ibsw225_flat_tools_layout MEMBERS) under an interpreter without site-packages
        # (no PyYAML before the venv switch), no project: no runuser, no identity line, the run reaches the guard.
        bundle = self.root / "bundle"
        bundle.mkdir()
        for relative in FLAT_MEMBERS:
            (bundle / Path(relative).name).write_bytes((ROOT / relative).read_bytes())
        record = self.root / "flat-record"
        record.mkdir()
        launcher = (
            "import importlib, os, pathlib, runpy, sys\n"
            "bundle, record = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])\n"
            "def note(event):\n"
            "    with open(record / 'events', 'a') as handle:\n"
            "        handle.write(event + '\\n')\n"
            "def execvp(file, argv):\n"
            "    note('execvp ' + file)\n"
            "    os._exit(91)\n"
            "os.execvp = execvp\n"
            "os.geteuid = lambda: 0   # root makes no difference without a project\n"
            "sys.path.insert(0, str(bundle))\n"
            "guard = importlib.import_module('ib_bringup_runtime_guard')\n"
            "class Busy:\n"
            "    def __enter__(self):\n"
            "        note('guard')\n"
            "        raise guard._InstanceGuardError('ALREADY_RUNNING', 'test stop')\n"
            "    def __exit__(self, *exc):\n"
            "        return False\n"
            "guard._runtime_instance_guard = Busy\n"
            "sys.argv = [str(bundle / 'upgrade.py'), *sys.argv[3:]]\n"
            "runpy.run_path(str(bundle / 'upgrade.py'), run_name='__main__')\n"
        )
        environment = {"PATH": "/usr/bin:/bin", "HOME": str(self.root / "empty-home"), "LANG": "en_US.UTF-8",
                       "LC_ALL": "en_US.UTF-8"}
        result = subprocess.run([sys.executable, "-B", "-S", "-c", launcher, str(bundle), str(record),
                                 "--inspect-only"], cwd=self.root, env=environment, stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, encoding="utf-8", timeout=60)
        self.assertEqual(75, result.returncode, result.stderr)
        self.assertEqual(["guard"], (record / "events").read_text().splitlines())
        self.assertNotIn("Traceback", result.stderr)
        self.assertNotIn("操作员", result.stderr)

    def test_upgrade_non_root_operator_runs_unchanged(self):
        # Regression guard: the operator's own run keeps the original flow and prints its identity line.
        args = ("--inspect-only", "--project", U_PROJECT)
        recorder, _err = self.run_upgrade(args, euid=1001)
        self.assertEqual(["execve"], recorder.kinds(), recorder.events)   # straight on to the venv switch
        recorder, err = self.run_upgrade(args, euid=1001, runtime_present=True)
        self.assertEqual(["guard"], recorder.kinds(), recorder.events)
        lines = [line for line in err.splitlines() if line.startswith("操作员：")]
        self.assertEqual(1, len(lines), err)
        for needle in ("操作员：opuser", "当前：opuser"):
            self.assertIn(needle, lines[0])

    def test_upgrade_root_parent_marker_never_reexecs(self):
        # 已定 2: a process started by a root parent (HTTP_ZTP_ROOT_PARENT) never re-runs.
        recorder, _err = self.run_upgrade(("--inspect-only", "--project", U_PROJECT), euid=0,
                                          environ={MARKER: "1"})
        self.assertEqual(["execve"], recorder.kinds(), recorder.events)

    def test_upgrade_pointer_project_is_the_default_and_an_invalid_pointer_stops(self):
        # Guide WP-10 step 2: no --project -> the pointer's project; an invalid pointer exits non-zero, runs nothing.
        tree, project = self.pointer_tree()
        with patch.dict(OWNERS, {project: 1001}):
            recorder, _err = self.run_upgrade(("--inspect-only",), euid=0,
                                              extra=(patch.object(app, "_REPOSITORY_ROOT", tree),))
        self.assertEqual(["execvp"], recorder.kinds(), recorder.events)
        self.assert_runuser(recorder.events[0], ENTRY, ("--inspect-only",))
        recorder, err = self.run_upgrade(("--inspect-only",), euid=0,
                                         extra=(patch.object(app, "_REPOSITORY_ROOT", self.broken_pointer_tree()),))
        self.assertEqual([("exit", 2)], recorder.events)
        self.assertIn("activate-project", err)

    def test_upgrade2_root_on_user_project_execs_before_guard(self):
        # Design §4.3 :97; the shared guard (test_ibsw_v2_entry :98-117) is taken only after the switch.
        args = ["--project", U_PROJECT, "--plan"]
        for label, environ in (("root login", {}), ("sudo by the owner", SUDO_U)):
            with self.subTest(label):
                recorder, _err = self.run_upgrade2(args, euid=0, environ=environ)
                self.assertEqual(["execvp"], recorder.kinds(), recorder.events)
                self.assert_runuser(recorder.events[0], ENTRY2, args, environ=environ)

    def test_upgrade2_foreign_user_refused(self):
        # 问题文档 :351.
        for label, euid, environ in (("V directly", 1002, {}), ("V with sudo (O7 ②)", 0, SUDO_V)):
            with self.subTest(label):
                recorder, err = self.run_upgrade2(["--project", U_PROJECT], euid=euid, environ=environ)
                self.assertEqual([("exit", 2)], recorder.events)
                for needle in (U_PROJECT, "opuser", "otheruser"):
                    self.assertIn(needle, err)

    def test_upgrade2_operator_marker_and_pointer_rows(self):
        # The operator itself and a root-parent child go straight to the guard; the pointer is the default project;
        # an invalid pointer stops with 2 before the guard.
        for label, euid, environ in (("operator", 1001, {}), ("root parent marker", 0, {MARKER: "1"})):
            with self.subTest(label):
                recorder, err = self.run_upgrade2(["--project", U_PROJECT], euid=euid, environ=environ)
                self.assertEqual(["guard"], recorder.kinds(), recorder.events)
                self.assertEqual(1, sum(line.startswith("操作员：") for line in err.splitlines()), err)
        tree, project = self.pointer_tree()
        with patch.dict(OWNERS, {project: 1001}):
            recorder, _err = self.run_upgrade2(["--plan"], euid=0, extra=(patch.object(app2, "REPOSITORY", tree),))
        self.assertEqual(["execvp"], recorder.kinds(), recorder.events)
        self.assert_runuser(recorder.events[0], ENTRY2, ["--plan"])
        recorder, err = self.run_upgrade2(["--plan"], euid=0,
                                          extra=(patch.object(app2, "REPOSITORY", self.broken_pointer_tree()),))
        self.assertEqual([("exit", 2)], recorder.events)
        self.assertIn("activate-project", err)


class InlineReexecParityTests(_EntryHarness):
    """O15 (a): upgrade.py's inline rule and tools/operator_identity.py agree for the same inputs."""

    EUIDS = (1001, 1002, 0, 4242)
    PROJECTS = (U_PROJECT, ROOT_PROJECT, NEW_PROJECT, GHOST_PROJECT, None)
    ENVIRONS = ({}, SUDO_U, SUDO_V, {"SUDO_USER": "ghost", "SUDO_UID": "1003"}, {"SUDO_USER": "root", "SUDO_UID": "0"},
                {"SUDO_USER": "opuser", "SUDO_UID": "1002"}, {"SUDO_USER": "opuser"}, {MARKER: "1"},
                {**SUDO_U, MARKER: "1"})

    def test_upgrade_inline_rule_matches_operator_identity(self):
        self.assertEqual(OI.ROOT_PARENT_MARKER, app._ROOT_PARENT_MARKER)
        self.assertEqual(OI.REEXEC_ENV_WHITELIST, app._REEXEC_ENV_WHITELIST)
        for euid in self.EUIDS:
            for project in self.PROJECTS:
                for environ in self.ENVIRONS:
                    with self.subTest(euid=euid, project=project, environ=sorted(environ)):
                        self.assert_same(euid, project, environ)

    def assert_same(self, euid, project, environ):
        expected = OI.resolve_operator(project, euid=euid, environ=dict(environ), getpwuid=getpwuid,
                                       getpwnam=getpwnam, stat=fake_stat)
        inline = REAL_INLINE_RULE(project, euid=euid, environ=dict(environ), getpwuid=getpwuid, getpwnam=getpwnam,
                                  stat=fake_stat)
        self.assertEqual(tuple(expected), inline)
        if project is None:
            return
        args = ("--inspect-only", "--project", project)
        live = {**SHELL_ENV, "HOME": "/root", "SSH_AUTH_SOCK": "/tmp/agent.sock", **environ}
        recorder = _Recorder()
        stderr = io.StringIO()
        returned = None
        with patch.object(app, "_resolve_operator", injected(REAL_INLINE_RULE, euid, environ)), \
                patch.dict(os.environ, live, clear=True), patch.object(os, "execvp", recorder.execvp), \
                contextlib.redirect_stderr(stderr):
            try:
                returned = app._reexec_as_operator(args)
            except _Stop:
                pass
            except SystemExit as exit:
                recorder.events.append(("exit", exit.code))
        if expected.refusal is not None:
            self.assertEqual([("exit", 2)], recorder.events)
            self.assertIn(expected.refusal, stderr.getvalue())
        elif OI.needs_reexec(expected, live):
            self.assertEqual(["execvp"], recorder.kinds())
            self.assertEqual(OI.reexec_command(expected.operator, app.__file__, list(args), environ=live),
                             recorder.events[0][2])
        else:
            self.assertEqual([], recorder.events)
            self.assertEqual(expected.banner, returned)

    def test_help_and_version_skip_in_both(self):
        calls = []
        for argv in (("--help",), ("-h",), ("--version",), ("--project", U_PROJECT, "--help")):
            with self.subTest(argv=argv):
                self.assertTrue(OI.skips_identity(argv))
                with patch.object(app, "_resolve_operator", side_effect=lambda *a, **k: calls.append(a)):
                    self.assertIsNone(app._reexec_as_operator(argv))
        self.assertEqual([], calls)


if __name__ == "__main__":
    unittest.main()
