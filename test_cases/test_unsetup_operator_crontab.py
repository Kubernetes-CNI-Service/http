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
  from the project the pointer selected; 13-unload only adds the identity line and its flow is unchanged;
- start check report §5 item 5 (adopted by http dev, BRIEF-v312-wave2): reuse the pointer `_main_locked_impl` read;
- the existing lock contract (an owned 0600 single-link file, `_req10c_crontab_lock`) is not weakened by the
  hand-over: a lock with a second link is neither handed over nor used;
- http dev review of agentW8.patch, ruling D3 (Docker is frozen, owner 11-02: its behaviour must not regress): a
  refused identity stops only the step that would touch a crontab.  With REQ10C auto state to clean (the files
  that make the cleanup touch the crontab) the run exits 1 and no crontab is touched; without it a WARN says the
  identity was not verified and the pointer and links go as before, exit code unchanged.  A project owner
  missing from passwd (a container's case) with no REQ10C state must unset exactly as v3.1.1 did.

No real uid switch happens (guide 2.2 item 6).  The test process plays root: `operator_identity.resolve_operator`
receives euid 0, environ and passwd as inputs (the real rule runs on them), and `OwnerView` is 02-unsetup's view of
`os` in which the files the operator made report the operator's uid and `fchown` is recorded instead of performed.
The crontab is a fake executable on PATH that records its argv; nothing touches a real crontab.
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
    new owner instead of calling the kernel.
    """

    def __init__(self, owners=None):
        self.owners, self.fchowns = dict(owners or {}), []

    def __getattr__(self, name):
        return getattr(os, name)

    def _seen(self, info):
        uid = self.owners.get((info.st_dev, info.st_ino))
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

    def run_unsetup(self, tree, view, environ=None, *, dry_run=False):
        """Run 02-unsetup's locked body with -y.  environ None: the process's own identity; else it plays root."""
        real = OI.resolve_operator
        output = io.StringIO()
        with ExitStack() as stack:
            stack.enter_context(self.globals_of(tree, view, dry_run=dry_run))
            if environ is not None:
                stack.enter_context(mock.patch.object(OI, "resolve_operator", side_effect=lambda project: real(
                    project, euid=0, environ=environ, getpwuid=account, getpwnam=account_named, stat=view.stat)))
            stack.enter_context(redirect_stdout(output))
            code = self.unsetup._main_locked_impl(self.unsetup._parse_args(["-y"]))
        return code, output.getvalue()

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
        # and the current user.  A refused real run stops before the crontab, the state and the pointer.
        tree = self.tree()
        view = self.operator_made(tree, "auto.env", "auto-watch.state", "auto-terminal.json")
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

        # A dry run changes nothing anyway: it reports the refusal and lists as before (pending point, default).
        tree = self.tree()
        view = self.operator_made(tree, "auto.env", "auto-watch.state", "auto-terminal.json")
        code, output = self.run_unsetup(tree, view, SUDO_V, dry_run=True)
        self.assertEqual(0, code, output)
        self.assertTrue([line for line in output.splitlines() if "opuser" in line and "vuser" in line
                         and "[WARN]" in line], output)
        self.assertEqual([], self.calls(tree))
        self.assertTrue(os.path.islink(tree.day0 / "activate-project"))

    def assert_unset(self, tree, code, output):
        self.assertEqual(0, code, output)
        self.assertFalse(os.path.lexists(tree.day0 / "activate-project"), "R-016 §4.4: the pointer goes")
        self.assertFalse(os.path.lexists(tree.key_link), "O14: the per-key link goes")
        self.assertFalse(os.path.lexists(tree.manifest), "Q5: the setup manifest goes")

    def test_unknown_owner_without_req10c_state_still_unsets(self):
        # D3 regression guard (green on v3.1.1 too): root in a container, project owner missing from passwd, no
        # REQ10C state at all: unsetup removes the pointer, the links and the manifest and returns 0.
        tree = self.tree(state_kind=None)
        view = OwnerView({inode(tree.project): UNKNOWN_UID})
        code, output = self.run_unsetup(tree, view, {})
        self.assert_unset(tree, code, output)
        self.assertEqual([], self.calls(tree), output)

    def test_unknown_owner_without_req10c_watch_warns_and_goes_on(self):
        # D3: no auto state to clean (no log directory, or one without auto.env/marker/terminal): a WARN names the
        # unverified identity (问题文档 :351, :302: whose project, the owner's uid), nothing in the directory is touched.
        for kind in (None, "idle"):
            with self.subTest(state_kind=kind):
                tree = self.tree(state_kind=kind)
                view = self.operator_made(tree, uid=UNKNOWN_UID)
                code, output = self.run_unsetup(tree, view, {})
                self.assert_unset(tree, code, output)
                self.assertTrue([line for line in output.splitlines()
                                 if "[WARN]" in line and str(UNKNOWN_UID) in line], output)
                self.assertEqual([], self.calls(tree), output)
                self.assertFalse(tree.lock.exists(), "no lock is made in a directory nobody acts for")
                self.assertEqual([], view.fchowns)

    def test_unknown_owner_with_req10c_watch_stops_before_the_crontab(self):
        # D3: the same identity with a watch to clean exits 1; no crontab is read or written, the state, pointer and
        # links stay; the error names the project and its owner's uid (问题文档 :302, :351).
        tree = self.tree()
        view = self.operator_made(tree, "auto.env", "auto-watch.state", "auto-terminal.json", uid=UNKNOWN_UID)
        code, output = self.run_unsetup(tree, view, {})
        self.assertEqual([], self.calls(tree), output)
        self.assertEqual(1, code, output)
        self.assertTrue([line for line in output.splitlines() if "[ERROR]" in line and str(UNKNOWN_UID) in line
                         and str(tree.project) in line], output)
        self.assertEqual(FOREIGN + tree.own, tree.db.read_text(encoding="utf-8"))
        for leaf in tree.leaves.values():
            self.assertTrue(leaf.exists(), leaf.name)
        self.assertFalse(tree.lock.exists(), "no lock is made in a directory nobody acts for")
        self.assertTrue(os.path.islink(tree.day0 / "activate-project"))
        self.assertTrue(os.path.islink(tree.key_link))
        self.assertTrue(tree.manifest.exists())


class UnloadOperatorIdentityTests(unittest.TestCase):
    STEPS = ["stop_monitor", "stop_monitor_workers", "stop_services", "remove_ztp_prefix_publication",
             "remove_dhcp_runtime_files", "remove_project_links"]

    @classmethod
    def setUpClass(cls):
        cls.unload = load_script("unsetup_operator_crontab_unload", UNLOAD)

    def run_unload(self, environ):
        holder = tempfile.TemporaryDirectory(prefix="w8-unload-")
        self.addCleanup(holder.cleanup)
        project = Path(holder.name).resolve() / "DAY0-Prepare" / PROJECT
        project.mkdir(parents=True)
        real = OI.resolve_operator
        events = []
        output = io.StringIO()

        def owner_of(path):
            info = os.stat(path)
            return Seen(info, OP_UID) if Path(path) == project else info

        @contextmanager
        def held(_root, *, dry_run=False, finish_transaction_id=None):
            yield 9

        def step(name, result=None):
            return lambda *_args, **_kwargs: events.append(name) or result

        with ExitStack() as stack:
            def patch(name, **kwargs):
                stack.enter_context(mock.patch.object(self.unload, name, **kwargs))

            patch("resolve_project", return_value=project)
            # 13-unload's own root check (:565-566), patched as test_finish_native_workflow does.
            stack.enter_context(mock.patch.object(self.unload.os, "geteuid", return_value=0))
            patch("confirm", side_effect=lambda *_args: events.append(("confirm", output.getvalue())) or True)
            patch("service_runtime_backend", return_value=SimpleNamespace(name="systemd"))
            patch("deployment_lock", new=held)
            patch("unmanaged_dhcp_runtime_files", return_value=[])
            for name in self.STEPS:
                patch(name, side_effect=step(name, [] if name == "remove_dhcp_runtime_files" else None))
            stack.enter_context(mock.patch.object(OI, "resolve_operator", side_effect=lambda path: real(
                path, euid=0, environ=environ, getpwuid=account, getpwnam=account_named, stat=owner_of)))
            stack.enter_context(redirect_stdout(output))
            stack.enter_context(redirect_stderr(io.StringIO()))
            code = self.unload.main(["-y"])
        return code, events, output.getvalue()

    def test_unload_prints_identity_line_before_confirming_and_keeps_its_flow(self):
        # design §4.2: one identity line at the start; guide WP-8: 13-unload adds only that, the flow is unchanged.
        code, events, output = self.run_unload(SUDO_OP)
        self.assertEqual(0, code, output)
        self.assertEqual("confirm", events[0][0])
        self.assertIn(BANNER_SUDO, events[0][1].splitlines(), "the identity line comes before the confirmation")
        self.assertEqual(self.STEPS, events[1:])

    def test_unload_names_a_refused_identity_and_keeps_its_flow(self):
        # 问题文档 :351: the identity line names who owns the project and who runs; guide WP-8: 13-unload adds only
        # that line and its flow is unchanged (the refusal happens in 02-unsetup, test_refused_identity_changes_nothing).
        code, events, output = self.run_unload(SUDO_V)
        self.assertEqual(0, code, output)
        self.assertTrue([line for line in events[0][1].splitlines() if "opuser" in line and "vuser" in line], output)
        self.assertEqual(self.STEPS, events[1:])


if __name__ == "__main__":
    unittest.main()
