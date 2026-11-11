"""Direct: initial-setup run by root re-runs as the project's operator and waits (I-006, v3.1.3 guide WP-9).

What: before the runtime guard, _guarded_main hands the run to one switch step.  Help, version and the
password-hash worker never compute an identity; the project is --project-dir as given, else the one
DAY0-Prepare/activate-project selects in the repository layout (an invalid pointer exits 2, never "no
project"); a Leaf directory or a desktop copy runs unchanged.  Root acting for another operator starts
the run again as that operator with operator_identity's wait form (env whitelist with the initial-password
variable, --credentials-fd in pass_fds), never takes the guard itself and exits with the child's code;
a refused identity exits 2 before the guard.  LeafLayoutImportTests pins O5's two layouts at run time.

Expectation sources (not derived from the implementation):
- v3.1.3 guide WP-9 :981-990 (switch point, steps 1-5, entry structure, import timing), its test tables
  :994-1015 and table 6-1 row 11 (exit codes by the moment of Ctrl-C); O5 (:258, WP-5 :656-674);
- v3.1.2 guide :1423, :1427 (wait form, whitelist, pass_fds, the parent never takes the guard), WP-4
  :487 ff. (help/version skip identity; the rule table; no project means unchanged; an invalid pointer is
  never treated as no project, :515-516), :528 (exit with the child's code, 128 + n on a signal);
- v3.1.2 已定 2 (落地记录.md:1614): a process that sees the root-parent marker never re-runs;
- 问题文档 I-006 (owner 2026-10-27, :351 「身份一致」).

Root is never real here.  Tests play root by replacing operator_identity.resolve_operator with the real
rule on injected inputs (euid, SUDO_*, passwd, project owner), never by mocking os.geteuid as a whole
(guide 2.2 #5); the wait form's process start is a recorder.  Real uid switching is
TC-REAL-I006-OPERATOR-REEXEC-001 (NOT RUN).
"""

from __future__ import annotations

import builtins
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
import csv
import getpass
import importlib.abc
import io
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
INITIAL = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
APP = load_script("initial_setup_operator_reexec_direct", INITIAL)
# The package modules _import_tools hands to initial-setup in this repository (O5): the same objects.
IDENTITY = APP._import_tools("tools.operator_identity")
CONTRACT = APP._import_tools("tools.project_contract")
RESOLVE = IDENTITY.resolve_operator
ACTIVE = CONTRACT.active_project_dir
MARKER = IDENTITY.ROOT_PARENT_MARKER
FACTORY_ENV = "NVOS_FACTORY_DEFAULT_ADMIN_PASSWORD"

ME = pwd.getpwuid(os.getuid())


def passwd_entry(name: str, uid: int, home: str) -> pwd.struct_passwd:
    return pwd.struct_passwd((name, "x", uid, ME.pw_gid, "fixture", home, "/bin/sh"))


U = passwd_entry("opuser", ME.pw_uid + 1, "/nonexistent/fixture-home/opuser")
V = passwd_entry("vuser", ME.pw_uid + 2, "/nonexistent/fixture-home/vuser")


def secret(label: str) -> str:
    # Assembled at run time so no credential literal appears in the source (public audit).
    return "-".join(("PUBLIC", "wp9", label, str(os.getpid()), "Zq7"))


def play(*, euid: int, owner: pwd.struct_passwd, sudo: pwd.struct_passwd | None = None):
    """operator_identity.resolve_operator on injected inputs: how these tests play root (guide 2.2 #5)."""
    entries = {entry.pw_uid: entry for entry in (U, V)}
    names = {entry.pw_name: entry for entry in (U, V)}
    projects = []

    def getpwuid(uid):
        if uid not in entries:
            raise KeyError(uid)
        return entries[uid]

    def getpwnam(name):
        if name not in names:
            raise KeyError(name)
        return names[name]

    environ = {} if sudo is None else {"SUDO_USER": sudo.pw_name, "SUDO_UID": str(sudo.pw_uid)}

    def resolve(project_dir):
        projects.append(project_dir)
        return RESOLVE(project_dir, euid=euid, environ=environ, getpwuid=getpwuid, getpwnam=getpwnam,
                       stat=lambda _path: SimpleNamespace(st_uid=owner.pw_uid))

    return mock.patch.object(IDENTITY, "resolve_operator", resolve), projects


class _Child:
    """The wait form's process start (operator_identity.run_as_operator's subprocess.Popen)."""

    def __init__(self, code: int) -> None:
        self.code = code
        self.started = []

    def popen(self, command, pass_fds=()):
        self.started.append({"command": list(command), "pass_fds": tuple(pass_fds)})
        return SimpleNamespace(wait=lambda: self.code, send_signal=lambda _number: None)


class InitialSetupOperatorReexecTests(unittest.TestCase):
    def run_entry(self, argv, *, child_code=0, guard=None, environ=None, play_as=None):
        """_guarded_main in this process; the guard and the guarded body are recorders."""
        events = []
        child = _Child(child_code)

        @contextmanager
        def recording_guard():
            events.append("guard")
            yield 99

        def body():
            events.append("main")
            return 0

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(sys, "argv", [str(INITIAL), *argv]))
            stack.enter_context(mock.patch.object(APP, "_runtime_instance_guard", guard or recording_guard))
            stack.enter_context(mock.patch.object(APP, "_standalone_main_with_report_cleanup", body))
            stack.enter_context(mock.patch.object(IDENTITY, "subprocess", SimpleNamespace(Popen=child.popen)))
            stack.enter_context(mock.patch.object(
                IDENTITY, "exec_as_operator", side_effect=AssertionError("only the wait form (guide :985)")))
            stack.enter_context(mock.patch.dict(os.environ))
            os.environ.pop(MARKER, None)
            os.environ.update(environ or {})
            if play_as is not None:
                stack.enter_context(play_as)
            out = stack.enter_context(redirect_stdout(io.StringIO()))
            err = stack.enter_context(redirect_stderr(io.StringIO()))
            try:
                code = APP._guarded_main()
            except SystemExit as exc:
                code = exc.code
        return SimpleNamespace(code=code, events=events, started=child.started,
                               out=out.getvalue(), err=err.getvalue())

    def test_root_on_user_project_uses_wait_mode_with_whitelist_and_fd(self):
        # Guide :985 (wait form; whitelist: the --ib-initial-password-env variable and, with
        # --factory-default-admin, NVOS_FACTORY_DEFAULT_ADMIN_PASSWORD; the --credentials-fd fd in
        # pass_fds); v3.1.2 guide :1423, :1427; v15 resolve_initial_ib_password :731-746.
        with tempfile.TemporaryDirectory(prefix="wp9-represent-") as folder:
            project = Path(folder).resolve()
            reader, writer = os.pipe()
            self.addCleanup(os.close, reader)
            os.write(writer, b'{"nvos_initial_password": "' + secret("fd").encode() + b'"}')
            os.close(writer)
            for extra, name in ((("--ib-initial-password-env", "PUBLIC_WP9_INITIAL"), "PUBLIC_WP9_INITIAL"),
                                (("--factory-default-admin",), FACTORY_ENV)):
                with self.subTest(source=name):
                    patch, projects = play(euid=0, owner=U, sudo=U)
                    argv = ["--project-dir", str(project), *extra, "--credentials-fd", str(reader)]
                    run = self.run_entry(argv, child_code=0, play_as=patch,
                                         environ={name: secret("environment")})
                    self.assertEqual(0, run.code, run.err)
                    self.assertEqual([], run.events, "the root parent takes no guard and runs no main")
                    self.assertEqual(1, len(run.started))
                    command, fds = run.started[0]["command"], run.started[0]["pass_fds"]
                    self.assertEqual(["runuser", "-u", U.pw_name, "--", "env", "-i"], command[:6])
                    self.assertIn(f"{name}={secret('environment')}", command)
                    self.assertIn(f"HOME={U.pw_dir}", command)
                    self.assertIn(f"{MARKER}=1", command)
                    self.assertEqual(str(INITIAL), command[-len(argv) - 1])
                    self.assertEqual(argv, command[-len(argv):])
                    self.assertIn(reader, fds)
                    self.assertEqual(1, len(projects))
            # The parent never reads the fd: the child's main does (guide :987).
            self.assertIn(secret("fd").encode(), os.read(reader, 4096))

    def test_help_version_and_verify_worker_skip_identity(self):
        # Guide :982 step 1 and v3.1.2 guide WP-4 (:487 ff.): help and version never compute an
        # identity; O5 / guide :988: tools modules are not imported for them, nor by the -I -S worker.
        trace = []

        def no_tools(name):
            trace.append(name)
            raise AssertionError("tools import for help/version: " + name)

        with mock.patch.object(APP, "_import_tools", no_tools):
            for argv in (["-h"], ["--help"], ["--version"], ["-h", "--apply"], ["--he", "--apply"]):
                with self.subTest(argv=argv):
                    run = self.run_entry(argv, play_as=mock.patch.object(IDENTITY, "resolve_operator",
                                                                         side_effect=AssertionError("identity"))
                                         )
                    self.assertEqual([], run.started)
                    self.assertNotIn("Traceback", run.err)
                    if "--apply" in argv:
                        # Mixed help skips the pre-lock parse and goes straight into the guard (:982).
                        self.assertEqual(["guard", "main"], run.events)
        self.assertEqual([], trace)
        # Separate processes, recorded by the interpreter's own import trace (-X importtime).
        with tempfile.TemporaryDirectory(prefix="wp9-skip-") as folder:
            environment = {"PATH": os.defpath, "LC_ALL": "C", "LANG": "C"}
            for options, stdin in ((["-I", "-S"], ["--_verify-password"]), ([], ["--help"]),
                                   ([], ["-h"]), ([], ["--version"])):
                with self.subTest(argv=stdin):
                    done = subprocess.run([sys.executable, *options, "-B", "-X", "importtime", str(INITIAL),
                                           *stdin], input=b"", capture_output=True, cwd=folder,
                                          env=environment, timeout=120, check=False)
                    imported = [line.rsplit("|", 1)[-1].strip() for line in
                                done.stderr.decode("utf-8", "replace").splitlines() if "|" in line]
                    self.assertTrue(imported, "the import trace was recorded")
                    self.assertFalse([name for name in imported if name.split(".")[0] in ("tools", "yaml")
                                      or name in ("operator_identity", "project_contract")])
                    self.assertEqual(2 if stdin == ["--_verify-password"] else 0, done.returncode)
            self.assertEqual([], list(Path(folder).iterdir()))

    def test_no_project_runs_unchanged(self):
        # Guide :983 step 2; v3.1.2 guide :515 (project None: no check, unchanged); v3.1.1 guide :700-707.
        calls = []
        patch, projects = play(euid=0, owner=U, sudo=U)
        with mock.patch.object(CONTRACT, "active_project_dir",
                               lambda root: calls.append(Path(root).resolve()) or None):
            run = self.run_entry(["--plan"], play_as=patch)
        self.assertEqual(0, run.code, run.err)
        self.assertEqual([ROOT], calls, "the repository root's pointer is read once")
        self.assertEqual([], projects, "no project: no identity")
        self.assertEqual([], run.started)
        self.assertEqual(["guard", "main"], run.events)
        # A Leaf directory or a desktop copy is not the repository layout: no pointer, no identity.
        for layout in ("leaf", "desktop"):
            with self.subTest(layout=layout), tempfile.TemporaryDirectory(prefix="wp9-" + layout + "-") as folder:
                copy = Path(folder).resolve() / "initial-setup.py"
                copy.write_bytes(INITIAL.read_bytes())
                if layout == "leaf":
                    (copy.parent / "tools").mkdir()
                app = load_script(f"initial_setup_operator_reexec_{layout}_{os.getpid()}", copy)
                trace = []
                events = []

                @contextmanager
                def guard():
                    events.append("guard")
                    yield 99

                with mock.patch.object(sys, "argv", [str(copy), "--plan"]), \
                     mock.patch.object(app, "_import_tools", lambda name: trace.append(name)), \
                     mock.patch.object(app, "_runtime_instance_guard", guard), \
                     mock.patch.object(app, "_standalone_main_with_report_cleanup",
                                       lambda: events.append("main") or 0), \
                     redirect_stderr(io.StringIO()):
                    self.assertEqual(0, app._guarded_main())
                self.assertEqual([], trace)
                self.assertEqual(["guard", "main"], events)

    def invalid_pointers(self, day0: Path):
        """The three ways a pointer exists but selects no project (v3.1.2 guide :516)."""
        pointer = day0 / "activate-project"
        yield "not a link", lambda: pointer.write_text("site-a\n")
        yield "not a plain name", lambda: os.symlink("template", pointer)
        yield "no such directory", lambda: os.symlink("site-missing", pointer)

    def test_invalid_pointer_exits_2_without_fallback(self):
        # Guide :983 step 2 and :987 (wrapped as SetupError with the original text, exit 2 before the
        # guard); v3.1.2 guide :516 (http dev: an invalid pointer is never let through as None);
        # tools/project_contract.py::active_project_dir :1556-1591@v3.1.1 docstring.
        with tempfile.TemporaryDirectory(prefix="wp9-pointer-") as folder:
            tree = Path(folder).resolve()
            day0 = tree / "DAY0-Prepare"
            day0.mkdir()
            for reason, make in self.invalid_pointers(day0):
                with self.subTest(reason=reason):
                    pointer = day0 / "activate-project"
                    if os.path.lexists(pointer):
                        pointer.unlink()
                    make()
                    with self.assertRaises(CONTRACT.ActiveProjectPointerError) as expected:
                        ACTIVE(tree)
                    calls = []
                    patch, projects = play(euid=0, owner=U, sudo=U)
                    with mock.patch.object(CONTRACT, "active_project_dir",
                                           lambda root: calls.append(Path(root).resolve()) or ACTIVE(tree)):
                        run = self.run_entry(["--plan"], play_as=patch)
                    self.assertEqual(2, run.code)
                    self.assertIn(str(expected.exception), run.err)
                    self.assertEqual([ROOT], calls)
                    self.assertEqual([], run.events, "no guard, no main: not run as 'no project'")
                    self.assertEqual([], run.started)
                    self.assertEqual([], projects)

    def test_explicit_project_dir_never_reads_pointer(self):
        # v3.1.2 guide :516 「显式传项目的调用方不经指针」; guide :983 step 2.
        with tempfile.TemporaryDirectory(prefix="wp9-explicit-") as folder:
            project = Path(folder).resolve()
            patch, projects = play(euid=U.pw_uid, owner=U)
            with mock.patch.object(CONTRACT, "active_project_dir",
                                   side_effect=AssertionError("pointer read although --project-dir was given")):
                run = self.run_entry(["--project-dir", str(project), "--plan"], play_as=patch)
            self.assertEqual(0, run.code, run.err)
            self.assertEqual([project], [Path(item).resolve() for item in projects])
            self.assertEqual(["guard", "main"], run.events, "U on U's project runs here")
            self.assertEqual([], run.started)

    def test_root_parent_marker_never_reexecs(self):
        # v3.1.2 已定 2 (落地记录.md:1614; v3.1.2 guide :529-530): a process that sees the marker never re-runs.
        with tempfile.TemporaryDirectory(prefix="wp9-marker-") as folder:
            project = Path(folder).resolve()
            patch, projects = play(euid=0, owner=U)
            run = self.run_entry(["--project-dir", str(project), "--plan"], play_as=patch,
                                 environ={MARKER: "1"})
        self.assertEqual(0, run.code, run.err)
        self.assertEqual(1, len(projects), "the identity is still computed")
        self.assertIn("操作员：" + U.pw_name, run.err, "the identity line (guide :1049)")
        self.assertEqual([], run.started)
        self.assertEqual(["guard", "main"], run.events)

    def test_parent_never_takes_runtime_guard(self):
        # v3.1.2 guide :1427 (the parent does not take the runtime guard); guide :987.
        with tempfile.TemporaryDirectory(prefix="wp9-guard-") as folder:
            project = Path(folder).resolve()
            for sudo in (U, None):
                with self.subTest(sudo=bool(sudo)):
                    patch, _projects = play(euid=0, owner=U, sudo=sudo)
                    run = self.run_entry(["--project-dir", str(project), "--plan"], play_as=patch,
                                         guard=mock.Mock(side_effect=AssertionError("parent took the guard")))
                    self.assertEqual(0, run.code, run.err)
                    self.assertEqual(1, len(run.started))
                    self.assertEqual([], run.events)

    def test_refusal_names_owner_current_and_fix_and_exits_2(self):
        # 问题文档 :351 (owner 10-27 「身份一致」); v3.1.2 guide :510-511 (V directly, V + sudo: refuse);
        # guide :984 (the message names the owner, the current user and the ways out), :987 (exit 2
        # before the runtime guard; the __main__ block is unchanged).
        with tempfile.TemporaryDirectory(prefix="wp9-refuse-") as folder:
            project = Path(folder).resolve()
            for euid, sudo in ((V.pw_uid, None), (0, V)):
                with self.subTest(sudo=bool(sudo)):
                    patch, _projects = play(euid=euid, owner=U, sudo=sudo)
                    run = self.run_entry(["--project-dir", str(project), "--plan"], play_as=patch)
                    self.assertEqual(2, run.code)
                    self.assertIn(U.pw_name, run.err)
                    self.assertIn(V.pw_name, run.err)
                    self.assertIn(f"请以 {U.pw_name} 运行" if sudo is None else f"请切换到 {U.pw_name} 运行", run.err)
                    self.assertEqual([], run.events)
                    self.assertEqual([], run.started)

    def test_keyboard_interrupt_at_password_prompt_exits_2(self):
        # Table 6-1 row 11 (O4 adopts v15's mapping: Ctrl-C at a password prompt becomes a SetupError
        # "...cancelled", v15 :389-390, and the run ends 2).  Both hidden prompts of the IB target.
        with tempfile.TemporaryDirectory(prefix="wp9-prompt-") as folder:
            root = Path(folder).resolve()
            (root / "01-global.yaml").write_text(_global_text(), encoding="utf-8")
            for interrupted in (1, 2):
                with self.subTest(prompt=interrupted):
                    answers = iter([secret("target")] * (interrupted - 1))

                    def prompt(_text=""):
                        try:
                            return next(answers)
                        except StopIteration:
                            raise KeyboardInterrupt from None

                    cancelled = None
                    with mock.patch.object(getpass, "getpass", side_effect=prompt), \
                         redirect_stdout(io.StringIO()):
                        policy = APP.ProjectPasswordPolicy(root / "01-global.yaml", "admin")
                        try:
                            policy.password()
                        except APP.SetupError as error:
                            cancelled = error
                        except KeyboardInterrupt:
                            self.fail("Ctrl-C at the prompt escaped as KeyboardInterrupt")
                    self.assertIsNotNone(cancelled)
                    self.assertRegex(str(cancelled), r"cancelled$")
            # The same prompt inside a real --apply run: the device asks for the target after an
            # expired initial password; Ctrl-C there writes nothing and the run ends 2.
            world = _MainWorld(self, root, expired=True)
            prompts = []

            def interrupted_prompt(text=""):
                prompts.append(text)
                raise KeyboardInterrupt

            code = world.run_guarded(["--apply", "--yes"], getpass_side_effect=interrupted_prompt)
            self.assertEqual(2, code, world.err)
            self.assertEqual(1, len(prompts), "the target prompt was reached and interrupted once")
            self.assertEqual([], world.writes)
            self.assertEqual(["guard"], world.guard_events)

    def test_parent_exit_code_follows_child(self):
        # Development plan §3 H4; v3.1.2 guide :528 (M6: the child's exit code, 128 + n on signal n);
        # v15 main :5875 (0 SUCCESS, 1 FAILED, 2 INCOMPLETE or entry error); 75 the guard is busy.
        with tempfile.TemporaryDirectory(prefix="wp9-codes-") as folder:
            project = Path(folder).resolve()
            for child_code, expected in ((0, 0), (1, 1), (2, 2), (75, 75), (-15, 143)):
                with self.subTest(child=child_code):
                    patch, _projects = play(euid=0, owner=U, sudo=U)
                    run = self.run_entry(["--project-dir", str(project), "--plan"], play_as=patch,
                                         child_code=child_code)
                    self.assertEqual(expected, run.code)
                    self.assertEqual(1, len(run.started))
                    self.assertEqual([], run.events)


def _global_text() -> str:
    target_hash = "$" + "6$PUBLICsalt$" + "A" * 86
    return ("schema_version: 2\ncommon:\n  switch:\n    system:\n"
            "      config:\n        auto-save:\n          state: enabled\n"
            "switches:\n- ib:\n    system:\n      aaa:\n        user:\n"
            "          admin:\n            password: {}\n").format(json.dumps(target_hash))


JUMP = "example-oob-leaf01"
IB = "example-ib001"
FACTORY = secret("factory")
AUTH_RE = re.compile(r"__HTTP_IB_AUTH_([0-9a-f]{32})_(auth-probe-readonly|password-change|post-change-read)__=BEGIN")
FRAME_RE = re.compile(r"__HTTP_IB_BEGIN_([0-9a-f]{32})__")
EXPIRY = "\nYou are required to change your password immediately.\n"
CONFIGURED = ("nv set system config auto-save state enabled\nnv set system ztp config-save enabled\n"
              "nv set interface eth0 ipv4 address 192.0.2.10/24\nnv set interface eth0-1 ipv4 gateway 192.0.2.1\n"
              "nv set interface eth0-1 link state up\nnv set interface eth0-1 type eth\n"
              f"nv set system hostname {IB}\nnv set system dns server 192.0.2.53\n"
              "nv set system ntp server 192.0.2.123 state enabled\nnv set system date-time timezone Etc/UTC\n")


class _MainWorld:
    """One IB behind one OOB Leaf for a real main(); only SSH, the clock and the prompts are replaced.

    Modelled on test_initial_setup_offline_main.py (not imported): the fake Leaf answers the v15
    snapshot reads; the fake IB answers the strict authentication read as a DEV phase session
    through the real responder, or a v15 password-only framed read.  Any other device command is a
    write and is recorded.
    """

    def __init__(self, test, root: Path, *, app=APP, script=INITIAL, expired=False) -> None:
        self.test, self.root, self.app, self.script, self.expired = test, root, app, script, expired
        self.writes, self.guard_events, self.reads = [], [], []
        self.err = ""
        # WP-8 table 8-1 (guide :923): --project-dir reads the project's own neutral defaults here.
        neutral = root / "infiniband/bringup/xdr-initial-setup/infra-neutral.conf"
        neutral.parent.mkdir(parents=True, exist_ok=True)
        neutral.write_text("DNS=192.0.2.53\nNTP=192.0.2.123\nTIMEZONE=Etc/UTC\n")
        with (root / "ib.csv").open("w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["hostname", "type", "eth0_ip", "netmask", "eth0_gw", "eth0_mac"])
            writer.writerow([IB, "ib", "192.0.2.10", "24", "192.0.2.1", "02:00:00:00:00:0a"])
            writer.writerow([JUMP, "eth_jump", "198.51.100.10", "", "", ""])
        (root / "p2p.dot").write_text(f'"{IB}":"eth0" -- "{JUMP}":"swp1"\n')

    def argv(self, *extra):
        root = self.root
        mode = [] if "--execution-mode" in extra else ["--execution-mode", "management"]
        return [str(self.script), "--project-dir", str(root), "--ib-csv", str(root / "ib.csv"),
                "--p2p", str(root / "p2p.dot"), "--target-cache", str(root / "tasks.json"),
                "--report", str(root / "report.log"), "--snapshot-dir", str(root / "snapshots"),
                *mode, *extra]

    @staticmethod
    def ethernet(_device, _user, _password, command, _timeout, **_kwargs):
        command = tuple(command)
        answers = {
            ("hostname",): JUMP + "\n",
            ("nv", "show", "interface"): "swp1 up up\n",
            ("ip", "-d", "link", "show"): (
                "1: swp1: <UP> mtu 1500 master br_default\n40: br_default: <UP> mtu 1500\n"
                "    bridge forward_delay 1500 vlan_filtering 1\n"
                "41: ib-mgmt1000@br_default: <UP> mtu 1500 master oob\n"
                "    vlan protocol 802.1Q id 1000 <REORDER_HDR>\n"),
            ("bridge", "fdb", "show"): "02:00:00:00:00:0a dev swp1 vlan 1000 master br_default\n",
            ("ip", "neighbor"): "fe80::a dev ib-mgmt1000 lladdr 02:00:00:00:00:0a REACHABLE\n",
            ("ip", "-j", "address", "show"): json.dumps([{
                "ifname": "ib-mgmt1000", "flags": ["BROADCAST", "MULTICAST", "UP"], "operstate": "UP",
                "addr_info": [{"family": "inet", "local": "192.0.2.1", "prefixlen": 24, "scope": "global"},
                              {"family": "inet6", "local": "fe80::1", "prefixlen": 64, "scope": "link"}]}]),
            ("ifquery", "ib-mgmt1000"): "iface ib-mgmt1000\n    vrf oob\n",
        }
        if command not in answers:
            raise AssertionError("Unexpected OOB command: " + repr(command))
        return answers[command]

    def session(self, responder):
        app = self.app
        phase = getattr(responder, "_phase", None)
        reader, writer = os.pipe()
        state = {"output": ""}

        def feed(text):
            state["output"] += text
            if phase is not None:
                phase.observe(state["output"])
            reply = responder(app.strip_ansi(state["output"]))
            if getattr(responder, "password_change_blocked", False):
                if phase is not None:
                    phase.cancel_requested = True
                return "\x03"
            if reply is not None and phase is not None:
                phase.write_reply(writer, reply, responder, time.monotonic() + 60)
                os.read(reader, 65536)
            return reply

        def result(code):
            os.close(reader)
            os.close(writer)
            return app.SessionResult(app.strip_ansi(state["output"]), code, password_change_required=bool(
                getattr(responder, "password_change_blocked", False)))

        return feed, result

    def transport(self, argv, responder, _timeout, **_kwargs):
        text = " ".join(argv)
        auth, frame = AUTH_RE.search(text), FRAME_RE.search(text)
        peer = re.search(r"admin@\[?(fe80::[0-9a-f:]+)", text)
        if peer is None:
            self.writes.append(text)
            raise AssertionError("Unexpected SSH destination: " + text)
        feed, result = self.session(responder)
        if auth is not None:
            nonce, operation = auth.groups()
            end = f"__HTTP_IB_AUTH_{nonce}_{operation}__=EXIT:"
            if operation != "auth-probe-readonly":
                result(255)
                self.writes.append(operation)
                raise AssertionError("Unexpected IB phase: " + operation)
            self.reads.append(operation)
            feed(f"\n__HTTP_IB_AUTH_{nonce}_{operation}__=BEGIN\n")
            if feed(f"admin@{peer.group(1)}'s password: ") != FACTORY:
                feed(f"\nadmin@{peer.group(1)}: Permission denied (password).\n{end}255\n")
                return result(255)
            if self.expired:
                feed(EXPIRY)
                feed("(current) UNIX password: ")
                return result(1)
            feed(f"\n__HTTP_IB_BEGIN_{nonce}__\n{CONFIGURED}__HTTP_IB_END_{nonce}__=0\n{end}0\n")
            return result(0)
        if frame is None or not ("nv show system ztp" in text or "nv config show -o commands" in text):
            result(255)
            self.writes.append(text)
            raise AssertionError("Unexpected IB command: " + text)
        self.reads.append(text)
        if responder(f"admin@{peer.group(1)}'s password: ") != FACTORY:
            raise AssertionError("the IB read must answer with the selected IB credential")
        payload = ("service disabled\nstatus aborted\nconfig-save enabled enabled\n"
                   if "nv show system ztp" in text else CONFIGURED)
        nonce = frame.group(1)
        result(0)
        return self.app.SessionResult(f"__HTTP_IB_BEGIN_{nonce}__\n{payload}__HTTP_IB_END_{nonce}__=0\n", 0)

    def run_guarded(self, extra, *, getpass_side_effect=None, more=()):
        """The real _guarded_main and main(); the runtime guard is a private recorder."""
        app = self.app
        home = self.root / "home"
        home.mkdir(exist_ok=True)

        @contextmanager
        def guard():
            self.guard_events.append("guard")
            yield 99

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(sys, "argv", self.argv(*extra)))
            stack.enter_context(mock.patch.object(app, "REPORT_HANDLE", None))
            stack.enter_context(mock.patch.object(app, "_runtime_instance_guard", guard))
            stack.enter_context(mock.patch.dict(os.environ, {"HOME": str(home)}))
            os.environ.pop(MARKER, None)
            stack.enter_context(mock.patch.object(Path, "home", return_value=home))
            stack.enter_context(mock.patch.object(app, "probe_ethernet_key", return_value="key"))
            stack.enter_context(mock.patch.object(app, "run_on_ethernet", side_effect=self.ethernet))
            stack.enter_context(mock.patch.object(app, "interactive_run", side_effect=self.transport))
            stack.enter_context(mock.patch.object(app.subprocess, "run",
                                                  side_effect=AssertionError("External commands forbidden")))
            stack.enter_context(mock.patch.object(app.time, "sleep", return_value=None))   # guide :173
            stack.enter_context(mock.patch.object(app, "resolve_initial_ib_password", return_value=FACTORY))
            stack.enter_context(mock.patch.object(
                getpass, "getpass",
                side_effect=getpass_side_effect or AssertionError("No password prompt expected")))
            stack.enter_context(mock.patch.object(builtins, "input",
                                                  side_effect=AssertionError("No authorization prompt expected")))
            for patch in more:
                stack.enter_context(patch)
            out = stack.enter_context(redirect_stdout(io.StringIO()))
            err = stack.enter_context(redirect_stderr(io.StringIO()))
            try:
                code = app._guarded_main()
            except SystemExit as exc:
                code = exc.code
            except KeyboardInterrupt:
                code = "KeyboardInterrupt escaped the entry"
            finally:
                if app.REPORT_HANDLE is not None:
                    app.REPORT_HANDLE.close()
            self.err = err.getvalue() + out.getvalue()
        return code


class _ImportRecorder(importlib.abc.MetaPathFinder):
    """Fails and records any import of the names a Leaf directory must never need (O5, DEV README :275)."""

    FORBIDDEN = ("yaml", "tools.project_contract", "tools.operator_identity")

    def __init__(self) -> None:
        self.hits = []

    def find_spec(self, fullname, path=None, target=None):
        if fullname in self.FORBIDDEN or fullname.startswith("yaml."):
            self.hits.append(fullname)
            raise ImportError("forbidden on a Leaf directory: " + fullname)
        return None


class LeafLayoutImportTests(unittest.TestCase):
    """O5's two fixed layouts at run time (guide :258, WP-5 :656-674)."""

    @contextmanager
    def fresh_tools(self):
        """Forget every loaded tools/yaml module for one block, so each import really happens."""
        with mock.patch.dict(sys.modules):
            for name in [name for name in sys.modules
                         if name == "tools" or name.startswith(("tools.", "yaml"))
                         or name in ("operator_identity", "project_contract")]:
                del sys.modules[name]
            yield

    def leaf(self, folder: Path, *, modules=("device_identity", "credentials_fd")):
        script = folder / "initial-setup.py"
        script.write_bytes(INITIAL.read_bytes())
        (folder / "tools").mkdir()
        for name in modules:
            (folder / "tools" / (name + ".py")).write_bytes((ROOT / "tools" / (name + ".py")).read_bytes())
        return script

    def test_leaf_layout_never_imports_project_contract_or_yaml(self):
        # DEV README :275 (an OOB Leaf's P2 needs no local YAML or PyYAML); O5 (operator_identity and
        # project_contract only from the repository; a direct run already has the script directory as
        # sys.path[0], so nothing is added).
        with tempfile.TemporaryDirectory(prefix="wp9-leaf-") as raw:
            folder = Path(raw).resolve()
            script = self.leaf(folder)
            app = load_script(f"initial_setup_operator_reexec_leaf_import_{os.getpid()}", script)
            world = _MainWorld(self, folder, app=app, script=script)
            leaf_mode = ("--execution-mode", "ethernet", "--local-ethernet-hostname", JUMP)
            host = (mock.patch.object(app.socket, "gethostname", return_value=JUMP),
                    mock.patch.object(app.socket, "getfqdn", return_value=JUMP))
            reader, writer = os.pipe()
            os.write(writer, json.dumps({"jump_passwords": {JUMP: secret("leaf")},
                                         "nvos_initial_password": FACTORY}).encode())
            os.close(writer)
            # The Leaf reads the target cache the management server generated (v15 contract).
            self.assertEqual(0, world.run_guarded(("--generate-json",)), world.err)
            runs = (("help", ("--help",)), ("check-only", leaf_mode),
                    ("credentials-fd", (*leaf_mode, "--credentials-fd", str(reader))))
            for label, extra in runs:
                with self.subTest(run=label), self.fresh_tools():
                    recorder = _ImportRecorder()
                    before = list(sys.path)
                    with mock.patch.object(sys, "path", [str(folder), *before]), \
                         mock.patch.object(sys, "meta_path", [recorder, *sys.meta_path]), \
                         mock.patch.object(app, "_TOOLS_ROOT", None):
                        code = world.run_guarded(extra, more=host)
                        path_after = list(sys.path)
                        identity_file = getattr(sys.modules.get("tools.device_identity"), "__file__", None)
                    self.assertEqual([], recorder.hits)
                    self.assertEqual([str(folder), *before], path_after, "sys.path gained nothing")
                    if label == "help":
                        self.assertEqual(0, code)
                    else:
                        self.assertIn(code, (0, 2), world.err)
                        self.assertTrue(world.reads, "the read-only check reached the IB read\n" + world.err)
                        self.assertEqual([], world.writes)
                    if label == "credentials-fd":
                        self.assertIsNotNone(identity_file)
                        self.assertEqual(folder / "tools", Path(identity_file).resolve().parent)

    def test_repository_layout_inserts_root_once_and_uses_package_names(self):
        # O5 steps 1-5: the repository root goes on sys.path once (not when already there); package
        # names only; one module object per process; only the white list; reserved names import.
        app = load_script(f"initial_setup_operator_reexec_repository_{os.getpid()}", INITIAL)
        for present in (True, False):
            with self.subTest(root_already_on_path=present), self.fresh_tools():
                stripped = [entry for entry in sys.path if Path(entry or ".").resolve() != ROOT]
                start = [str(ROOT), *stripped] if present else stripped
                with mock.patch.object(sys, "path", list(start)), \
                     mock.patch.object(app, "_TOOLS_ROOT", None):
                    preloaded = __import__("tools.device_identity", fromlist=["short_key"]) if present else None
                    first = app._import_tools("tools.device_identity")
                    second = app._import_tools("tools.device_identity")
                    reserved = [app._import_tools(name) for name in ("tools.inventory_subset",
                                                                      "tools.hostname_ranges")]
                    roots = [entry for entry in sys.path if Path(entry or ".").resolve() == ROOT]
                    with self.assertRaises(app.SetupError):
                        app._import_tools("tools.sync-code")
                self.assertEqual(1, len(roots))
                self.assertIs(first, second)
                if preloaded is not None:
                    self.assertIs(preloaded, first)
                self.assertEqual("tools.device_identity", first.__name__)
                self.assertEqual(ROOT / "tools", Path(first.__file__).resolve().parent)
                self.assertEqual(["tools.inventory_subset", "tools.hostname_ranges"],
                                 [module.__name__ for module in reserved])

    def test_ambiguous_or_foreign_layout_refused_only_when_needed(self):
        # O5 step 1 (exactly one layout, never guessed) and step 3 (__file__ must be under the chosen
        # root); a run that needs no tools module is unaffected.
        with tempfile.TemporaryDirectory(prefix="wp9-ambiguous-") as raw:
            base = Path(raw).resolve()
            both = base / "both" / "infiniband" / "bringup" / "xdr-initial-setup"
            both.mkdir(parents=True)
            (base / "both" / "tools").mkdir()
            (base / "both" / "tools" / "device_identity.py").write_bytes(
                (ROOT / "tools" / "device_identity.py").read_bytes())
            neither = base / "neither"
            neither.mkdir()
            for label, folder in (("both", both), ("neither", neither)):
                with self.subTest(layout=label):
                    script = folder / "initial-setup.py"
                    script.write_bytes(INITIAL.read_bytes())
                    if label == "both":
                        self.leaf(folder, modules=("device_identity",))
                        script.write_bytes(INITIAL.read_bytes())
                    app = load_script(f"initial_setup_operator_reexec_{label}_{os.getpid()}", script)
                    with self.fresh_tools(), mock.patch.object(app, "_TOOLS_ROOT", None):
                        with self.assertRaises(app.SetupError):
                            app._import_tools("tools.device_identity")
                    with mock.patch.object(sys, "argv", [str(script), "--help"]), \
                         redirect_stdout(io.StringIO()) as out, \
                         mock.patch.object(app, "_runtime_instance_guard",
                                           side_effect=AssertionError("help takes no guard")):
                        with self.assertRaises(SystemExit) as stopped:
                            app._guarded_main()
                    self.assertEqual(0, stopped.exception.code)
                    self.assertIn("usage:", out.getvalue())
            # A plain package "tools" earlier on sys.path shadows the namespace package: refused.
            leaf_folder = base / "leaf"
            leaf_folder.mkdir()
            script = self.leaf(leaf_folder, modules=("device_identity",))
            app = load_script(f"initial_setup_operator_reexec_foreign_{os.getpid()}", script)
            foreign = base / "foreign"
            (foreign / "tools").mkdir(parents=True)
            (foreign / "tools" / "__init__.py").write_text("")
            (foreign / "tools" / "device_identity.py").write_text("FOREIGN = True\n")
            with self.fresh_tools(), mock.patch.object(sys, "path", [str(foreign), *sys.path]), \
                 mock.patch.object(app, "_TOOLS_ROOT", None):
                with self.assertRaises(app.SetupError):
                    app._import_tools("tools.device_identity")


if __name__ == "__main__":
    unittest.main()
