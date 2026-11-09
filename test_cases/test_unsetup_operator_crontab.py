"""02-unsetup cleans the operator's REQ10C watch with crontab -u; 13-unload names the operator (v3.1.2 WP-8, M6).

Expected values come from the requirement texts, never from the scripts:
- design `设计/I-006与R-005实现计划.md` §4.3 (:96): under root, 02-unsetup uses `crontab -u <operator>` and the
  owner check of the auto state directory becomes "equals the operator"; §4.2: the operator is the owner of the
  project directory, every script prints one identity line such as
  「操作员：U（项目目录属主）；当前：root 经 sudo（发起人 U）→ 项目侧以 U 执行」, V with sudo on U's project is
  refused (O7 ②), root on a root-owned project runs as root;
- 问题文档 I-006 初步分析第 5 条 (:268-270): a sudo unload must clean the crontab of the user who installed the
  watch, not root's, and must not reject that user's state directory; :351 (owner 2026-10-27): a refusal names who
  owns the project and who is running; scheme item 4 (:294, owner 2026-10-27) and O11 ②: a file root creates in
  the project belongs to the operator at once;
- v3.1.2 guide WP-8: only when euid is 0 and the operator is not root does the crontab argv change, every other run
  keeps ['-l'] / ['-'] exactly (the AGENTS.md REQ10C exception tests depend on it); group/other-write rules stay;
  the new parameters have defaults, so no-argument calls keep working; the operator is computed once at the entry
  from the project the pointer selected;
- start check report §5 item 5 (adopted by http dev, BRIEF-v312-wave2): the pointer is read once (02-unsetup's
  entry reads it and hands the project on);
- the existing lock contract (an owned 0600 single-link file, `_req10c_crontab_lock`) is not weakened by the
  hand-over: a lock with a second link is neither handed over nor used;
- owner 2026-11-09 「Q-006 选 (b)」 (http dev 转述, 04 Q-006), which replaces review ruling D3; v3.1.2 guide 8.1
  「随 BF 一起做：G4 (b)」, O7 ② (:223), the decision table (:511): on the native backend (HTTP_ZTP_RUNTIME_BACKEND
  unset or systemd) root running 13-unload or 02-unsetup is refused at the entry when the operator rule refuses
  (V via sudo, an invalid sudo invoker, via sudo a project owner missing from passwd): the identity line and an
  [ERROR] with the refusal, exit 1, nothing stopped or changed; 02-unsetup refuses after the deployment lock and
  before the monitor stop, 13-unload before its confirmation; --dry-run alike (http dev 2026-11-09).  A direct root
  login on a project whose owner is missing from passwd goes on as v3.1.1 did, with one [WARN] that names the uid
  and the hint `sudo chown <操作员>:<操作员主组> <项目>` (http dev 2026-11-09, default 2: that login is the way out
  O7 ② gives).  The supervisor (Docker) backend works out no identity and prints no identity line: v3.1.1 exactly
  (开发计划 :112, Docker frozen; review d-3).  A non-root run prints the identity line and is v3.1.1 otherwise
  (guide WP-8 :868; review d-2; http dev 2026-11-09).

No real uid switch happens (guide 2.2 item 6).  The test process plays root: `operator_identity.resolve_operator`
receives euid 0, environ and passwd as inputs (the real rule runs on them), and `OwnerView` is 02-unsetup's view of
`os` (guide 2.2 item 6, exception ①): it reports euid 0, the files the operator made report the operator's uid,
what this process made reports uid 0, and `fchown` is recorded instead of performed.  02-unsetup's main runs as
13-unload runs it, the deployment lock held already, with `stop_native_ztp_monitors` a recorder (the way
test_load_operator_workflow's unload() replaces them).  The crontab is a fake executable on PATH that records its
argv; nothing touches a real crontab.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import pwd
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import operator_identity as OI  # noqa: E402
from test_cases.module_loader import load_script  # noqa: E402

UNSETUP = ROOT / "DAY0-Prepare/02-unsetup.py"
UNLOAD = ROOT / "DAY0-Prepare/13-unload.py"
TOOL = "infiniband/bringup/xdr-initial-setup"
# project_contract.BRINGUP_OUTPUT_SPECS: the tool's log directory lives in the project.
STATE = "99-output-ib_nvl/bringup/xdr-initial-setup-logs"
PROJECT = "w8-site"
FOREIGN = "1 * * * * /usr/bin/true # not ours\n"

RUNNER = os.geteuid()  # the test process; it plays root
OP_UID, OP_GID = RUNNER + 1, os.getegid() + 1  # opuser owns the project: the operator
V_UID, V_GID = RUNNER + 2, os.getegid() + 2  # vuser: somebody else
UNKNOWN_UID = RUNNER + 3  # owns a project but has no passwd entry (e.g. a host uid inside a container)
ACCOUNTS = (
    pwd.struct_passwd(("root", "x", 0, 0, "root", "/root", "/bin/bash")),
    pwd.struct_passwd(("opuser", "x", OP_UID, OP_GID, "operator", "/home/opuser", "/bin/bash")),
    pwd.struct_passwd(("vuser", "x", V_UID, V_GID, "other", "/home/vuser", "/bin/bash")),
)
SUDO_OP = {"SUDO_USER": "opuser", "SUDO_UID": str(OP_UID)}
SUDO_V = {"SUDO_USER": "vuser", "SUDO_UID": str(V_UID)}
OPERATOR = OI.Operator("opuser", OP_UID, OP_GID, "/home/opuser")
# design §4.2 example line with U = opuser.
BANNER_SUDO = "操作员：opuser（项目目录属主）；当前：root 经 sudo（发起人 opuser）→ 项目侧以 opuser 执行"
LEGACY = [["-l"], ["-l"], ["-"]]
DASH_U = [["-u", "opuser", "-l"], ["-u", "opuser", "-l"], ["-u", "opuser", "-"]]
WATCH = ("auto.env", "auto-watch.state", "auto-terminal.json")
BACKEND = "HTTP_ZTP_RUNTIME_BACKEND"  # tools/ztp_service_runtime.py RUNTIME_BACKEND_ENV
# design §4.2 identity line, V running with sudo on opuser's project (the decision part is the rule's).
BANNER_SUDO_V = "操作员：opuser（项目目录属主）；当前：root 经 sudo（发起人 vuser）"
# guide WP-4 :513 and 8.1 G4 (b): the way out named when the project owner has no passwd entry.
CHOWN_HINT = "sudo chown <操作员>:<操作员主组> "

FAKE_CRONTAB = """#!{python}
import json, os, pathlib, sys
argv = sys.argv[1:]
with open(os.environ["W8_CRON_EVENTS"], "a", encoding="utf-8") as out:
    out.write(json.dumps(argv) + "\\n")
if argv[:1] == ["-u"]:
    argv = argv[2:]
db = pathlib.Path(os.environ["W8_CRON_DB"])
if argv == ["-l"]:
    sys.stdout.write(db.read_text(encoding="utf-8"))
elif argv == ["-"]:
    db.write_text(sys.stdin.read(), encoding="utf-8")
else:
    sys.exit(2)
"""


def account(uid):
    for entry in ACCOUNTS:
        if entry.pw_uid == uid:
            return entry
    raise KeyError(uid)


def account_named(name):
    for entry in ACCOUNTS:
        if entry.pw_name == name:
            return entry
    raise KeyError(name)


class Seen:
    """A stat result whose owner is reported as `st_uid`; every other field is the real one."""

    def __init__(self, info, uid):
        self._info, self.st_uid = info, uid

    def __getattr__(self, name):
        return getattr(self._info, name)


class OwnerView:
    """02-unsetup's `os` while the test process plays root acting for another user.

    Everything is the real os module, except: stat/lstat/fstat report `owners[(st_dev, st_ino)]` as the owner of the
    inodes listed there (files the operator made), and fchown records (inode, uid, gid) and moves that inode to the
    new owner instead of calling the kernel.  With euid 0 (guide 2.2 item 6, exception ①: 02-unsetup's entry reads
    its own euid; precedent test_collection_lock_owner._WorkerOs(euid=0)) geteuid reports 0 and every other inode
    this process owns reports uid 0: what the process playing root made is root's, as the lock hand-over
    (`info.st_uid == os.geteuid()`) expects.  euid None: the real process.
    """

    def __init__(self, owners=None, euid=None):
        self.owners, self.fchowns, self.euid = dict(owners or {}), [], euid

    def __getattr__(self, name):
        return getattr(os, name)

    def geteuid(self):
        return os.geteuid() if self.euid is None else self.euid

    def _seen(self, info):
        uid = self.owners.get((info.st_dev, info.st_ino))
        if uid is None and self.euid == 0 and info.st_uid == os.geteuid():
            uid = 0
        return info if uid is None else Seen(info, uid)

    def stat(self, *args, **kwargs):
        return self._seen(os.stat(*args, **kwargs))

    def lstat(self, *args, **kwargs):
        return self._seen(os.lstat(*args, **kwargs))

    def fstat(self, descriptor):
        return self._seen(os.fstat(descriptor))

    def fchown(self, descriptor, uid, gid):
        info = os.fstat(descriptor)
        self.fchowns.append((info.st_ino, uid, gid))
        self.owners[(info.st_dev, info.st_ino)] = uid


def inode(path):
    info = os.lstat(path)
    return info.st_dev, info.st_ino


class Fixture(unittest.TestCase):
    """A temporary code tree with one active project whose REQ10C watch is installed, and a fake crontab."""

    @classmethod
    def setUpClass(cls):
        cls.unsetup = load_script("unsetup_operator_crontab_unsetup", UNSETUP)
        holder = tempfile.TemporaryDirectory(prefix="w8-crontab-bin-")
        cls.addClassCleanup(holder.cleanup)
        cls.bin = Path(holder.name).resolve()
        fake = cls.bin / "crontab"
        fake.write_text(FAKE_CRONTAB.format(python=sys.executable), encoding="utf-8")
        fake.chmod(0o700)

    def tree(self, *, lock=None, state_kind="watch"):
        """state_kind: "watch" (auto.env, marker, terminal), "idle" (the log directory only) or None (no directory)."""
        holder = tempfile.TemporaryDirectory(prefix="w8-unsetup-")
        self.addCleanup(holder.cleanup)
        base = Path(holder.name).resolve()
        day0 = base / "DAY0-Prepare"
        state = day0 / PROJECT / STATE
        (day0 / PROJECT).mkdir(parents=True)
        if state_kind is not None:
            state.mkdir(parents=True)
            state.chmod(0o700)
        (day0 / "activate-project").symlink_to(PROJECT)
        tool = base / TOOL
        tool.mkdir(parents=True)
        # setup's fixed link goes through the pointer (R-016 §4.2).
        (tool / "xdr-initial-setup-logs").symlink_to(os.path.relpath(day0 / "activate-project" / STATE, tool))
        # Things unsetup removes besides the pointer (O14, Q5): a per-key link and the setup manifest.
        key_link = base / "ztp/config/publickey/laptop.pub"
        key_link.parent.mkdir(parents=True)
        key_link.symlink_to("../../../DAY0-Prepare/activate-project/publickey/laptop.pub")
        manifest = base / "ztp/.setup_manifest"
        manifest.write_text("{}\n", encoding="ascii")
        leaves = {}
        for name, text in ((("auto.env", "NVOS_INITIAL_PASSWORD=fixture\n"), ("auto-watch.state", "watch\n"),
                            ("auto-terminal.json", "{}\n")) if state_kind == "watch" else ()):
            leaves[name] = state / name
            leaves[name].write_text(text, encoding="ascii")
            leaves[name].chmod(0o600)
        if lock is not None:
            leaves["auto-crontab.lock"] = state / "auto-crontab.lock"
            leaves["auto-crontab.lock"].write_bytes(b"")
            leaves["auto-crontab.lock"].chmod(lock)
        own = (f"*/10 * * * * cd {tool} && python3 {tool / 'initial-setup.py'} --auto --apply --yes "
               f"--credentials-file {tool / 'xdr-initial-setup-logs/auto.env'} # http-v3-req10c-auto\n")
        db = base / "cron.db"
        db.write_text(FOREIGN + own, encoding="utf-8")
        events = base / "cron-events"
        env = {"PATH": f"{self.bin}{os.pathsep}{os.environ.get('PATH', '')}",
               "W8_CRON_DB": str(db), "W8_CRON_EVENTS": str(events)}
        return SimpleNamespace(base=base, day0=day0, project=day0 / PROJECT, state=state, leaves=leaves,
                               lock=state / "auto-crontab.lock", db=db, events=events, env=env, own=own,
                               key_link=key_link, manifest=manifest)

    @staticmethod
    def calls(tree):
        if not tree.events.exists():
            return []
        return [json.loads(line) for line in tree.events.read_text(encoding="utf-8").splitlines()]

    @staticmethod
    def operator_made(tree, *names, project=True, uid=OP_UID):
        """The view in which uid (the operator) made the project, its state directory and the named leaves."""
        paths = ([tree.project] if project else []) + [tree.state] + [tree.state / name for name in names]
        return OwnerView({inode(path): uid for path in paths if os.path.lexists(path)})

    @contextmanager
    def globals_of(self, tree, view, *, dry_run=False):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.dict(os.environ, tree.env))
            self.assertEqual(str(self.bin / "crontab"), shutil.which("crontab"), "fixture: the fake crontab is used")
            for name, value in (("HTTP_BASE", str(tree.base)), ("HERE", str(tree.day0)),
                                ("ZTP", str(tree.base / "ztp")),
                                ("MANIFEST_FILE", str(tree.base / "ztp/.setup_manifest")),
                                ("_AUTO_YES", True), ("_DRY_RUN", dry_run), ("os", view)):
                stack.enter_context(mock.patch.object(self.unsetup, name, value))
            yield

    def run_unsetup(self, tree, view, environ=None, *, euid=0, dry_run=False, backend=None):
        """Run 02-unsetup's main with -y (and --dry-run) as 13-unload runs it: the deployment lock is held already and
        stop_native_ztp_monitors is a recorder.  Returns (code, output); tree.stops gets the output printed before each
        monitor stop, tree.rule the resolve_operator calls.

        environ None: the process's own identity.  Else the process plays `euid` with these sudo variables, which
        resolve_operator receives as inputs (the real rule runs on them) and 02-unsetup's os.environ carries; euid 0
        makes `view` play root too.  backend: HTTP_ZTP_RUNTIME_BACKEND, unset when None.
        """
        real = OI.resolve_operator
        output = io.StringIO()
        tree.stops = []
        (tree.base / "infra").mkdir(exist_ok=True)  # a code tree has it; _main_locked's infra_log_root_lock needs it

        @contextmanager
        def held(_root, *, dry_run=False):
            yield 9

        def stop(_root):
            tree.stops.append(output.getvalue())
            return ()

        process = {name: value for name, value in os.environ.items() if not name.startswith("SUDO_") and name != BACKEND}
        process.update(environ or {})
        if backend is not None:
            process[BACKEND] = backend
        if environ is not None and euid == 0:
            view.euid = 0
        resolve = real if environ is None else (lambda project: real(
            project, euid=euid, environ=environ, getpwuid=account, getpwnam=account_named, stat=view.stat))
        with ExitStack() as stack:
            stack.enter_context(mock.patch.dict(os.environ, process, clear=True))
            stack.enter_context(self.globals_of(tree, view, dry_run=dry_run))
            stack.enter_context(mock.patch.object(self.unsetup, "deployment_lock", held))
            stack.enter_context(mock.patch.object(self.unsetup, "stop_native_ztp_monitors", side_effect=stop))
            tree.rule = stack.enter_context(mock.patch.object(OI, "resolve_operator", side_effect=resolve))
            stack.enter_context(redirect_stdout(output))
            code = self.unsetup.main(["-y", "--dry-run"] if dry_run else ["-y"])
        return code, output.getvalue()

    @staticmethod
    def snapshot(tree):
        """Every entry of the code tree: its kind and its link target or bytes (infra/ made as run_unsetup makes it)."""
        (tree.base / "infra").mkdir(exist_ok=True)
        entries = {}
        for directory, names, files in os.walk(tree.base):
            for name in names + files:
                path = Path(directory) / name
                entries[str(path)] = (("link", os.readlink(path)) if path.is_symlink() else ("dir", None)
                                      if path.is_dir() else ("file", path.read_bytes()))
        return entries

    @staticmethod
    def identity_lines(output):
        return [line for line in output.splitlines() if line.startswith("操作员：")]

    def assert_cleaned(self, tree):
        self.assertEqual(FOREIGN, tree.db.read_text(encoding="utf-8"), "only the project's own watch line goes")
        for name in ("auto.env", "auto-watch.state", "auto-terminal.json"):
            self.assertFalse(os.path.lexists(tree.leaves[name]), name)


class UnsetupOperatorCrontabTests(Fixture):
    def test_root_with_user_operator_uses_crontab_dash_u(self):
        # design §4.3 (:96); 问题文档 :269: root cleans the operator's crontab, not its own.
        for label, environ in (("sudo by the owner", SUDO_OP), ("direct root login", {})):
            with self.subTest(label):
                tree = self.tree()
                view = self.operator_made(tree, "auto.env", "auto-watch.state", "auto-terminal.json")
                code, output = self.run_unsetup(tree, view, environ)
                self.assertEqual(DASH_U, self.calls(tree), output)
                self.assertEqual(0, code, output)
                self.assert_cleaned(tree)
                self.assertFalse(os.path.lexists(tree.day0 / "activate-project"), "unsetup still unlinks the pointer")
                lines = output.splitlines()
                if environ:
                    self.assertIn(BANNER_SUDO, lines, "design §4.2 identity line")
                self.assertTrue(any(line.startswith("操作员：opuser（项目目录属主）") for line in lines), output)

    def test_non_root_keeps_exact_legacy_argv(self):
        # guide WP-8: no -u unless euid 0 and the operator is not root (AGENTS.md REQ10C exception tests).
        with self.subTest("non-root owner of the project, real process identity"):
            tree = self.tree()
            view = OwnerView()
            code, output = self.run_unsetup(tree, view)
            self.assertEqual(LEGACY, self.calls(tree), output)
            self.assertEqual(0, code, output)
            self.assert_cleaned(tree)
            self.assertEqual([], view.fchowns)
        with self.subTest("root on a root-owned project (design §4.2: runs as root)"):
            tree = self.tree()
            # The running process plays root and made everything, so only the project's owner is reported as 0.
            view = OwnerView({inode(tree.project): 0})
            code, output = self.run_unsetup(tree, view, {})
            self.assertEqual(LEGACY, self.calls(tree), output)
            self.assertEqual(0, code, output)
            self.assert_cleaned(tree)
            self.assertEqual([], view.fchowns)

    def test_operator_owned_state_dir_and_files_accepted_under_root(self):
        # design §4.3 (:96): the owner checks compare with the operator, not with the running root.
        tree = self.tree(lock=0o600)
        view = self.operator_made(tree, "auto.env", "auto-watch.state", "auto-terminal.json", "auto-crontab.lock",
                                  project=False)
        with self.globals_of(tree, view):
            self.unsetup._cleanup_req10c_auto_watch(None, OPERATOR)
        self.assertEqual(DASH_U, self.calls(tree))
        self.assert_cleaned(tree)
        self.assertTrue(tree.lock.exists(), "the lock inode is retained")
        self.assertEqual([], view.fchowns, "an operator-owned lock is used as it is")

    def test_foreign_owned_state_dir_still_refused(self):
        # design §4.2 (a third party's files are never taken over); guide WP-8 test table: refused, files kept.
        everything = ("auto.env", "auto-watch.state", "auto-terminal.json", "auto-crontab.lock")
        cases = (
            ("state directory owned by another user", None, V_UID),
            ("state directory owned by the running root", None, RUNNER),
            ("auto-crontab.lock owned by another user", "auto-crontab.lock", V_UID),
            ("auto.env owned by another user", "auto.env", V_UID),
            ("auto-watch.state owned by another user", "auto-watch.state", V_UID),
            ("auto-terminal.json owned by another user", "auto-terminal.json", V_UID),
        )
        for label, foreign, owner in cases:
            with self.subTest(label):
                tree = self.tree(lock=0o600)
                view = self.operator_made(tree, *everything, project=False)
                target = tree.state if foreign is None else tree.leaves[foreign]
                view.owners[inode(target)] = owner
                with self.globals_of(tree, view), self.assertRaises(OSError):
                    self.unsetup._cleanup_req10c_auto_watch(None, OPERATOR)
                self.assertTrue(os.path.lexists(target), f"{label}: the foreign object is preserved")
                if foreign in (None, "auto-crontab.lock"):
                    self.assertEqual([], self.calls(tree), "refused before the crontab is read")
                    self.assertEqual(FOREIGN + tree.own, tree.db.read_text(encoding="utf-8"))
                    for name in everything:
                        self.assertTrue(os.path.lexists(tree.leaves[name]), name)
                self.assertEqual([], view.fchowns)

    def test_root_created_crontab_lock_is_handed_to_operator(self):
        # 问题文档 :294 (scheme item 4); O11 ②: the lock root creates in the operator's directory is the operator's.
        tree = self.tree()
        view = self.operator_made(tree, "auto.env", "auto-watch.state", "auto-terminal.json", project=False)
        with self.globals_of(tree, view):
            self.unsetup._cleanup_req10c_auto_watch(None, OPERATOR)
        self.assertEqual([(os.lstat(tree.lock).st_ino, OP_UID, OP_GID)], view.fchowns)
        self.assertEqual(DASH_U, self.calls(tree))
        self.assert_cleaned(tree)

        with self.subTest("not acting for an operator: nothing is handed over"):
            tree = self.tree()
            view = OwnerView()
            with self.globals_of(tree, view):
                self.unsetup._cleanup_req10c_auto_watch()
            self.assertTrue(tree.lock.exists())
            self.assertEqual([], view.fchowns)
            self.assertEqual(LEGACY, self.calls(tree))

        with self.subTest("a root-owned lock with a second link is neither handed over nor used"):
            tree = self.tree(lock=0o600)
            os.link(tree.lock, tree.base / "second-link")
            view = self.operator_made(tree, "auto.env", "auto-watch.state", "auto-terminal.json", project=False)
            with self.globals_of(tree, view), self.assertRaises(OSError):
                self.unsetup._cleanup_req10c_auto_watch(None, OPERATOR)
            self.assertEqual([], view.fchowns)
            self.assertEqual([], self.calls(tree))

    def test_no_argument_calls_still_work(self):
        # guide WP-8: the parameters have defaults; other modules call these without arguments.
        tree = self.tree()
        view = OwnerView()
        with self.globals_of(tree, view):
            self.assertEqual(FOREIGN + tree.own, self.unsetup._read_req10c_crontab())
            self.assertEqual(FOREIGN + tree.own, self.unsetup._read_stable_req10c_crontab())
            self.unsetup._cleanup_req10c_auto_watch()
        self.assertEqual([["-l"], ["-l"], ["-l"]] + LEGACY, self.calls(tree))
        self.assert_cleaned(tree)

        tree = self.tree()
        tool = str(tree.base / TOOL)
        state = os.path.join(tool, "xdr-initial-setup-logs")
        with self.globals_of(tree, view), self.unsetup._req10c_crontab_lock(state):
            self.unsetup._cleanup_req10c_auto_watch_locked(
                tool, os.path.join(state, "auto.env"), os.path.join(state, "auto-watch.state"),
                os.path.join(state, "auto-terminal.json"))
        self.assertEqual(LEGACY, self.calls(tree))
        self.assert_cleaned(tree)

    def test_refused_identity_changes_nothing(self):
        # design §4.2 and O7 ②: V with sudo on U's project is refused; 问题文档 :351: the refusal names the owner
        # and the current user.  A refused real run stops before the crontab, the state and the pointer; owner
        # 2026-11-09 「Q-006 选 (b)」 (04 Q-006): at the entry, before the monitor stop.
        tree = self.tree()
        view = self.operator_made(tree, *WATCH)
        code, output = self.run_unsetup(tree, view, SUDO_V)
        self.assertEqual([], self.calls(tree), output)
        refusal = [line for line in output.splitlines() if "opuser" in line and "vuser" in line and "[ERROR]" in line]
        self.assertTrue(refusal, output)
        self.assertEqual(1, code, output)
        self.assertTrue(os.path.islink(tree.day0 / "activate-project"))
        self.assertFalse(tree.lock.exists(), "no lock is made in a directory nobody acts for")
        self.assertEqual(FOREIGN + tree.own, tree.db.read_text(encoding="utf-8"))
        for leaf in tree.leaves.values():
            self.assertTrue(leaf.exists(), leaf.name)
        self.assertEqual([], tree.stops, "refused before the monitor stop")

        # A dry run is refused the same way (http dev 2026-11-09: as load does, guide 8.1 G4 (b)).
        tree = self.tree()
        view = self.operator_made(tree, *WATCH)
        code, output = self.run_unsetup(tree, view, SUDO_V, dry_run=True)
        self.assertEqual(1, code, output)
        self.assertTrue([line for line in output.splitlines() if "opuser" in line and "vuser" in line
                         and "[ERROR]" in line], output)
        self.assertEqual([], self.calls(tree))
        self.assertTrue(os.path.islink(tree.day0 / "activate-project"))

    def test_sudo_v_is_refused_at_entry_before_the_monitor_stop(self):
        # O7 ② (:223), decision table :511, owner 2026-11-09 「Q-006 选 (b)」 (04 Q-006; guide 8.1 G4 (b) #1): on the
        # native backend root running 02-unsetup for V via sudo on U's project is refused after the deployment lock and
        # before the monitor stop -- whatever REQ10C state there is, and with --dry-run too (http dev 2026-11-09).  The
        # identity line is printed, the [ERROR] names U and V (问题文档 :351), the exit code is 1, no monitor is stopped,
        # no crontab runs, and the pointer, links, manifest and REQ10C state are as before, no lock made.  The same
        # rule refuses an invalid sudo invoker (O7 ④) and, via sudo, a project owner missing from passwd (:513).
        invalid = {"SUDO_USER": "vuser", "SUDO_UID": str(OP_UID)}
        cases = (
            ("V via sudo, REQ10C watch", "watch", OP_UID, SUDO_V, False, ("opuser", "vuser")),
            ("V via sudo, empty state directory", "idle", OP_UID, SUDO_V, False, ("opuser", "vuser")),
            ("V via sudo, no state directory", None, OP_UID, SUDO_V, False, ("opuser", "vuser")),
            ("V via sudo, --dry-run", "watch", OP_UID, SUDO_V, True, ("opuser", "vuser")),
            ("invalid sudo invoker", "watch", OP_UID, invalid, False, ("opuser", "vuser", "SUDO_UID")),
            ("via sudo, owner missing from passwd, REQ10C watch", "watch", UNKNOWN_UID, SUDO_V, False,
             (str(UNKNOWN_UID), "vuser", CHOWN_HINT)),
            ("via sudo, owner missing from passwd, empty state directory", "idle", UNKNOWN_UID, SUDO_V, False,
             (str(UNKNOWN_UID), "vuser", CHOWN_HINT)),
            ("via sudo, owner missing from passwd, no state directory", None, UNKNOWN_UID, SUDO_V, False,
             (str(UNKNOWN_UID), "vuser", CHOWN_HINT)),
        )
        for label, kind, owner, environ, dry_run, needles in cases:
            with self.subTest(label):
                tree = self.tree(state_kind=kind)
                view = self.operator_made(tree, *(WATCH if kind == "watch" else ()), uid=owner)
                before = self.snapshot(tree)
                code, output = self.run_unsetup(tree, view, environ, dry_run=dry_run)
                self.assertEqual(1, code, output)
                identity = self.identity_lines(output)
                self.assertEqual(1, len(identity), output)
                self.assertIn("；当前：root 经 sudo（发起人 vuser）", identity[0])
                if owner == OP_UID:
                    self.assertTrue(identity[0].startswith(BANNER_SUDO_V), identity[0])
                self.assertTrue([line for line in output.splitlines()
                                 if "[ERROR]" in line and all(needle in line for needle in needles)], output)
                self.assertEqual([], tree.stops, "refused before stop_native_ztp_monitors")
                self.assertEqual([], self.calls(tree), output)
                self.assertEqual(before, self.snapshot(tree), "pointer, links, manifest, state: nothing changes")
                self.assertEqual([], view.fchowns)

    def assert_unset(self, tree, code, output):
        self.assertEqual(0, code, output)
        self.assertFalse(os.path.lexists(tree.day0 / "activate-project"), "R-016 §4.4: the pointer goes")
        self.assertFalse(os.path.lexists(tree.key_link), "O14: the per-key link goes")
        self.assertFalse(os.path.lexists(tree.manifest), "Q5: the setup manifest goes")

    def assert_kept(self, tree):
        self.assertTrue(os.path.islink(tree.day0 / "activate-project"))
        self.assertTrue(os.path.islink(tree.key_link))
        self.assertTrue(tree.manifest.exists())
        self.assertEqual(FOREIGN + tree.own, tree.db.read_text(encoding="utf-8"))
        for leaf in tree.leaves.values():
            self.assertTrue(leaf.exists(), leaf.name)

    def test_unknown_owner_without_req10c_state_still_unsets(self):
        # D3 regression guard (green on v3.1.1 too): root in a container, project owner missing from passwd, no
        # REQ10C state at all: unsetup removes the pointer, the links and the manifest and returns 0.  A container runs
        # the supervisor backend (owner 2026-11-09 「Q-006 选 (b)」, 04 Q-006; 开发计划 :112: Docker is frozen).
        tree = self.tree(state_kind=None)
        view = OwnerView({inode(tree.project): UNKNOWN_UID})
        code, output = self.run_unsetup(tree, view, {}, backend="supervisor")
        self.assert_unset(tree, code, output)
        self.assertEqual([], self.calls(tree), output)

    def test_unknown_owner_without_req10c_watch_is_refused_at_entry(self):
        # A project owner missing from passwd, no auto state to clean (no log directory, or one without
        # auto.env/marker/terminal).  Owner 2026-11-09 「Q-006 选 (b)」 (04 Q-006; guide 8.1 G4 (b)) replaces D3's WARN:
        # via sudo the entry refuses (exit 1, nothing stopped or changed); a direct root login goes on as v3.1.1 did
        # with one [WARN] naming the uid and the `sudo chown` hint (http dev 2026-11-09, default 2) -- v3.1.1 unsets
        # without a log directory and stops with 1 at the directory owner check (_req10c_crontab_lock) with one; the
        # supervisor backend is v3.1.1 with no identity line (开发计划 :112).
        for kind in (None, "idle"):
            with self.subTest("via sudo", state_kind=kind):
                tree = self.tree(state_kind=kind)
                view = self.operator_made(tree, uid=UNKNOWN_UID)
                before = self.snapshot(tree)
                code, output = self.run_unsetup(tree, view, SUDO_OP)
                self.assertEqual(1, code, output)
                self.assertTrue([line for line in output.splitlines()
                                 if "[ERROR]" in line and str(UNKNOWN_UID) in line and CHOWN_HINT in line], output)
                self.assertEqual([], tree.stops)
                self.assertEqual(before, self.snapshot(tree))
            for label, environ, backend in (("direct root login", {}, None), ("supervisor backend", {}, "supervisor")):
                with self.subTest(label, state_kind=kind):
                    tree = self.tree(state_kind=kind)
                    view = self.operator_made(tree, uid=UNKNOWN_UID)
                    code, output = self.run_unsetup(tree, view, environ, backend=backend)
                    warns = [line for line in output.splitlines() if "[WARN]" in line]
                    if backend is None:
                        self.assertEqual(1, len(warns), output)
                        self.assertIn(str(UNKNOWN_UID), warns[0])
                        self.assertIn(CHOWN_HINT + str(tree.project), warns[0])
                    else:
                        self.assertEqual([], warns, output)
                        self.assertEqual([], self.identity_lines(output), output)
                    self.assertEqual(1, len(tree.stops), "the run goes on: the monitors are stopped as in v3.1.1")
                    self.assertEqual([], self.calls(tree), output)
                    self.assertFalse(tree.lock.exists(), "no lock is made in a directory owned by somebody else")
                    self.assertEqual([], view.fchowns)
                    if kind is None:
                        self.assert_unset(tree, code, output)
                    else:
                        self.assertEqual(1, code, output)
                        self.assert_kept(tree)

    def test_unknown_owner_with_req10c_watch_stops_before_the_crontab(self):
        # The same owner with a watch to clean exits 1; no crontab is read or written, the state, pointer and links
        # stay; the run names the project and its owner's uid (问题文档 :302, :351).  Owner 2026-11-09 「Q-006 选 (b)」:
        # via sudo the entry refuses with the [ERROR] before the monitor stop; a direct root login goes on as v3.1.1
        # (the monitors are stopped) up to the state directory's owner check (_req10c_crontab_lock), which stops it
        # with 1 and an [ERROR]; there the entry's [WARN] is the line that names the project and the uid.
        for label, environ in (("via sudo", SUDO_OP), ("direct root login", {})):
            with self.subTest(label):
                tree = self.tree()
                view = self.operator_made(tree, *WATCH, uid=UNKNOWN_UID)
                code, output = self.run_unsetup(tree, view, environ)
                lines = output.splitlines()
                self.assertEqual([], self.calls(tree), output)
                self.assertEqual(1, code, output)
                self.assertTrue([line for line in lines if "[ERROR]" in line], output)
                naming = "[ERROR]" if environ else "[WARN]"
                self.assertTrue([line for line in lines if naming in line and str(UNKNOWN_UID) in line
                                 and str(tree.project) in line], output)
                self.assert_kept(tree)
                self.assertFalse(tree.lock.exists(), "no lock is made in a directory nobody acts for")
                self.assertEqual(0 if environ else 1, len(tree.stops), output)

    def test_supervisor_backend_keeps_v311_unsetup(self):
        # 开发计划 :112 (Docker is frozen), 04 Q-006 result column (owner 2026-11-09 「Q-006 选 (b)」), review d-3; guide
        # 8.1 G4 (b) #3: with HTTP_ZTP_RUNTIME_BACKEND=supervisor 02-unsetup works out no identity (resolve_operator is
        # not called) and prints no identity line and no WARN.  Root in a container whose project owner is missing from
        # passwd. Without REQ10C state the pointer, links and manifest go (exit 0); with a state directory owned by that
        # uid, v3.1.1 stops with 1 at the directory owner check (_req10c_crontab_lock), removing nothing.  13-unload on
        # this backend: UnloadOperatorIdentityTests.test_supervisor_backend_keeps_v311_unload.
        for kind in (None, "idle", "watch"):
            with self.subTest(state_kind=kind):
                tree = self.tree(state_kind=kind)
                view = self.operator_made(tree, *(WATCH if kind == "watch" else ()), uid=UNKNOWN_UID)
                code, output = self.run_unsetup(tree, view, {}, backend="supervisor")
                tree.rule.assert_not_called()
                self.assertEqual([], self.identity_lines(output), output)
                self.assertFalse([line for line in output.splitlines() if "[WARN]" in line], output)
                self.assertEqual([], self.calls(tree), output)
                self.assertEqual(1, len(tree.stops), "v3.1.1 stops the native monitors on every backend")
                if kind is None:
                    self.assert_unset(tree, code, output)
                else:
                    self.assertEqual(1, code, output)
                    self.assertTrue([line for line in output.splitlines() if "[ERROR]" in line], output)
                    self.assert_kept(tree)
                    self.assertFalse(tree.lock.exists())

    def test_non_root_refused_identity_keeps_v311_path(self):
        # Guide WP-8 :868 (the non-root path is not changed), review d-2; http dev 2026-11-09: a non-root run only
        # prints the identity line; guide 8.1 G4 (b) #4.  V runs 02-unsetup directly on U's project: with U's state
        # directory but no auto files v3.1.1 stops with 1 at the directory owner check (_req10c_crontab_lock), the
        # pointer and links stay; without a state directory it unsets as v3.1.1 (pointer and links go, exit 0).
        for kind in ("idle", None):
            with self.subTest(state_kind=kind):
                tree = self.tree(state_kind=kind)
                view = self.operator_made(tree)
                code, output = self.run_unsetup(tree, view, {}, euid=V_UID)
                identity = self.identity_lines(output)
                self.assertEqual(1, len(identity), output)
                self.assertTrue(identity[0].startswith("操作员：opuser（项目目录属主）；当前：vuser"), identity[0])
                self.assertFalse([line for line in output.splitlines() if "[WARN]" in line], output)
                self.assertEqual([], self.calls(tree), output)
                self.assertEqual(1, len(tree.stops), "v3.1.1: the monitors are stopped first")
                if kind is None:
                    self.assert_unset(tree, code, output)
                else:
                    self.assertEqual(1, code, output)
                    self.assert_kept(tree)
                    self.assertFalse(tree.lock.exists())

    def test_root_login_unknown_owner_still_unsets_with_warn(self):
        # http dev 2026-11-09 (land2 check, default 2): a direct root login is the way out O7 ② (:223) names, so a
        # project owner missing from passwd does not stop it; v3.1.1 unset such a project and so does this run, with one
        # [WARN] from the entry (before the monitor stop, guide 8.1 G4 (b) step 3) that names the owner's uid as missing
        # from passwd and gives `sudo chown <操作员>:<操作员主组> <项目>` (:513).  Native backend, no REQ10C state; guide
        # 8.1 G4 (b) #6.  13-unload: UnloadOperatorIdentityTests.test_unload_root_login_unknown_owner_goes_on_with_warn.
        tree = self.tree(state_kind=None)
        view = OwnerView({inode(tree.project): UNKNOWN_UID})
        code, output = self.run_unsetup(tree, view, {})
        self.assert_unset(tree, code, output)
        self.assertEqual([], self.calls(tree), output)
        self.assertEqual(1, len(tree.stops), output)
        warns = [line for line in tree.stops[0].splitlines() if "[WARN]" in line]
        self.assertEqual(1, len(warns), output)
        for needle in (str(UNKNOWN_UID), "passwd", CHOWN_HINT + str(tree.project)):
            self.assertIn(needle, warns[0])
        self.assertEqual(1, len([line for line in output.splitlines() if "[WARN]" in line]), output)
        self.assertFalse([line for line in output.splitlines() if "[ERROR]" in line], output)


class UnloadOperatorIdentityTests(unittest.TestCase):
    STEPS = ["stop_monitor", "stop_monitor_workers", "stop_services", "remove_ztp_prefix_publication",
             "remove_dhcp_runtime_files", "remove_project_links"]

    @classmethod
    def setUpClass(cls):
        cls.unload = load_script("unsetup_operator_crontab_unload", UNLOAD)

    def run_unload(self, environ, *, argv=("-y",), backend="systemd", owner=OP_UID, euid=0):
        """13-unload's main as `euid` (0: root); environ: the sudo variables, which resolve_operator receives as inputs
        and os.environ carries; backend: the name service_runtime_backend returns; owner: the project directory's owner.
        The confirmation and the six teardown steps record into events; self.locks records the deployment lock taken,
        self.resolved the projects resolve_operator was asked about.  stdout and stderr both go into the output."""
        holder = tempfile.TemporaryDirectory(prefix="w8-unload-")
        self.addCleanup(holder.cleanup)
        project = Path(holder.name).resolve() / "DAY0-Prepare" / PROJECT
        project.mkdir(parents=True)
        real = OI.resolve_operator
        events = []
        self.locks, self.resolved = [], []
        output = io.StringIO()

        def owner_of(path):
            info = os.stat(path)
            return Seen(info, owner) if Path(path) == project else info

        def resolve(path):
            self.resolved.append(path)
            return real(path, euid=euid, environ=environ, getpwuid=account, getpwnam=account_named, stat=owner_of)

        @contextmanager
        def held(_root, *, dry_run=False, finish_transaction_id=None):
            self.locks.append(dry_run)
            yield 9

        def step(name, result=None):
            return lambda *_args, **_kwargs: events.append(name) or result

        process = {name: value for name, value in os.environ.items() if not name.startswith("SUDO_") and name != BACKEND}
        process.update(environ)
        with ExitStack() as stack:
            def patch(name, **kwargs):
                stack.enter_context(mock.patch.object(self.unload, name, **kwargs))

            stack.enter_context(mock.patch.dict(os.environ, process, clear=True))
            patch("resolve_project", return_value=project)
            # 13-unload's own root check (:565-566), patched as test_finish_native_workflow does.
            stack.enter_context(mock.patch.object(self.unload.os, "geteuid", return_value=euid))
            patch("confirm", side_effect=lambda *_args: events.append(("confirm", output.getvalue())) or True)
            patch("service_runtime_backend", return_value=SimpleNamespace(name=backend))
            patch("deployment_lock", new=held)
            patch("unmanaged_dhcp_runtime_files", return_value=[])
            for name in self.STEPS:
                patch(name, side_effect=step(name, [] if name == "remove_dhcp_runtime_files" else None))
            stack.enter_context(mock.patch.object(OI, "resolve_operator", side_effect=resolve))
            stack.enter_context(redirect_stdout(output))
            stack.enter_context(redirect_stderr(output))
            code = self.unload.main(list(argv))
        return code, events, output.getvalue()

    def test_unload_prints_identity_line_before_confirming_and_keeps_its_flow(self):
        # design §4.2: one identity line at the start; guide WP-8: 13-unload adds only that, the flow is unchanged.
        code, events, output = self.run_unload(SUDO_OP)
        self.assertEqual(0, code, output)
        self.assertEqual("confirm", events[0][0])
        self.assertIn(BANNER_SUDO, events[0][1].splitlines(), "the identity line comes before the confirmation")
        self.assertEqual(self.STEPS, events[1:])

    def test_unload_refuses_sudo_v_before_confirming(self):
        # O7 ② (:223), decision table :511, owner 2026-11-09 「Q-006 选 (b)」 (04 Q-006; guide 8.1 G4 (b) #2): on the
        # native backend root running 13-unload for V via sudo on U's project is refused at the entry: the identity
        # line, an [ERROR] naming U and V (问题文档 :351), exit 1; neither the confirmation nor the deployment lock nor
        # any of the six teardown steps runs.  --dry-run alike (http dev 2026-11-09).
        for argv in (("-y",), ("--dry-run",)):
            with self.subTest(argv=argv):
                code, events, output = self.run_unload(SUDO_V, argv=argv)
                self.assertEqual(1, code, output)
                self.assertEqual([], events, output)
                self.assertEqual([], self.locks, "refused before the deployment lock")
                lines = output.splitlines()
                self.assertTrue([line for line in lines if line.startswith(BANNER_SUDO_V)], output)
                self.assertTrue([line for line in lines if "[ERROR]" in line and "opuser" in line and "vuser" in line],
                                output)

    def test_supervisor_backend_keeps_v311_unload(self):
        # Guide 8.1 G4 (b) #3, 13-unload half: on the supervisor backend (开发计划 :112; 04 Q-006; review d-3) 13-unload
        # works out no identity and prints no identity line, even for a project owner missing from passwd; the flow is
        # v3.1.1's (confirmation, then the six steps), exit 0.
        code, events, output = self.run_unload({}, backend="supervisor", owner=UNKNOWN_UID)
        self.assertEqual(0, code, output)
        self.assertEqual([], self.resolved)
        self.assertFalse([line for line in output.splitlines() if line.startswith("操作员：") or "[WARN]" in line],
                         output)
        self.assertEqual("confirm", events[0][0])
        self.assertEqual(self.STEPS, events[1:])

    def test_unload_root_login_unknown_owner_goes_on_with_warn(self):
        # Guide 8.1 G4 (b) #6, 13-unload half (http dev 2026-11-09, default 2): a direct root login on a project whose
        # owner is missing from passwd tears down as v3.1.1 did, with one [WARN] before the confirmation that names the
        # owner's uid as missing from passwd and gives `sudo chown <操作员>:<操作员主组> <项目>` (:513).
        code, events, output = self.run_unload({}, owner=UNKNOWN_UID)
        self.assertEqual(0, code, output)
        self.assertEqual("confirm", events[0][0])
        self.assertEqual(self.STEPS, events[1:])
        warns = [line for line in events[0][1].splitlines() if "[WARN]" in line]
        self.assertEqual(1, len(warns), output)
        for needle in (str(UNKNOWN_UID), "passwd", CHOWN_HINT):
            self.assertIn(needle, warns[0])
        self.assertFalse([line for line in output.splitlines() if "[ERROR]" in line], output)

    def test_non_root_dry_run_only_prints_the_identity_line(self):
        # Guide 8.1 G4 (b) (http dev 2026-11-09): a non-root run -- for 13-unload only --dry-run can be one -- prints
        # the identity line and is refused nowhere; the rest is v3.1.1 (the dry-run lock, the confirmation, the six
        # steps listing only).  V on U's project.
        code, events, output = self.run_unload({}, argv=("--dry-run",), euid=V_UID)
        self.assertEqual(0, code, output)
        self.assertTrue([line for line in output.splitlines()
                         if line.startswith("操作员：opuser（项目目录属主）；当前：vuser")], output)
        self.assertFalse([line for line in output.splitlines() if "[ERROR]" in line or "[WARN]" in line], output)
        self.assertEqual([True], self.locks)
        self.assertEqual("confirm", events[0][0])
        self.assertEqual(self.STEPS, events[1:])


if __name__ == "__main__":
    unittest.main()
