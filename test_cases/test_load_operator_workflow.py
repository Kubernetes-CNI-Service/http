"""Workflow (v3.1.2 WP-13, M6, I-006): way A, way B, mixing them, and the cross-script owners around load.

Expected values come from the requirement texts, never from the scripts under test:
- design `设计/I-006与R-005实现计划.md` §1 (owner 2026-10-27: way A is an ordinary user plus sudo -- load and
  unload with sudo, upgrade without it; way B is root logging in and running everything; users may mix the two
  and that must work), §4.2 (the operator is the owner of the project directory; root logging in acts for U; the
  passwd home, never HOME; one identity line per script, e.g.
  「操作员：U（项目目录属主）；当前：root 经 sudo（发起人 U）→ 项目侧以 U 执行」; when A and B are mixed the operator
  stays the project owner and never flips), §4.3 (load reads the management key from the operator's ~/.ssh and
  hands what it writes into the project to the operator; 02-unsetup under root uses `crontab -u <operator>`;
  upgrade run by root re-runs itself with `runuser -u <operator> --` before anything else; 12-ztp-monitor stays a
  root process that reads the operator's key) and §4.6 (workflow: way A sudo load -> upgrade by U -> sudo unload;
  way B root throughout; mixed sudo load -> root -> U -> root unload; all along the project files belong to the
  operator, the operator's key is used and the crontab is the operator's).  The initial-setup step of §4.6 moves
  to D1 (v3.1.3); v3.1.2 guide 1.3 replaces it with upgrade.
- 问题文档 I-006, the scheme the owner approved on 2026-10-27 (:290-306): item 1 (the sudo invoker's passwd home),
  item 4 (what root writes into the project belongs to the real user); :351 (another identity is refused, the
  monitor likewise); :352 (mixing the two ways is supported).
- v3.1.2 guide WP-13 (the test table), with the decisions of guide section 3 (owner 2026-11-07 「同意你在v3.1.2里的默认
  建议」, http dev 转述): O9 (the group handed over is the operator's passwd primary group), O11 ② and ⑤ (root's
  new project files are fchown'd to the operator; infra-setup hands its log to the owner of the directory it sits
  in), O12 ① (root logs in with -i <operator home>/.ssh/id_ed25519), O14 (load pre-creates the three cron.lock
  for the operator); agentOP report 4.4 (root-private project state, never handed over).
- Load's permission repair (owner 2026-10-27: load checks and repairs the project's permissions at its start,
  问题文档 I-006 :331, :407; design §4.4; guide WP-6 with O8, O9, O10 ①): what root left in U's project and U's
  too-open ~/.ssh end up U's, one `[PERM] <路径> <原属主:组 原模式> -> <新属主:组 新模式>` line each, and a second
  repair changes nothing (design §4.6); config_sync_authority's two namespaces are system side (design §4.1) and
  stay root's, so a sudo unload after the repair still withdraws them (guide WP-13 table; design §4.6: way A
  ends with a sudo unload that must go through).

No real uid switch happens (guide 2.2 item 6) and os.geteuid is never mocked.  The operator U is a passwd entry
whose uid is the test user's + 1, whose primary group is a second group of the test user and whose home is a
temporary directory, so a hand-over to the running user or to its egid cannot pass for a hand-over to U.  Root is
played the way agentL57 does it: the identity rules (tools/operator_identity.py, and upgrade.py's inline copy) get
euid 0, sudo's environment, that passwd and the project owner as inputs.  Where load's permission repair runs
for real, the owners root would meet are modelled the way agentW6 does it (its OwnerModel: 11-load's own ``os``
view, uid 0 being what root made), and 13-unload's run sees the owners load left, uid 0 standing for the test
user, who plays root for root's own state (config_sync_authority compares its namespaces with the real euid).
The two scripts whose own code asks
whether it runs as root get a root view instead: 13-unload and deploy_infra a module-local view of ``os`` whose
geteuid is 0 (agentW9's precedent), infra-setup its ``is_root``.  load runs through agentM3's systemd main
fixture; upgrade.py's real ``__main__`` block through agentW10's in-process launcher; 13-unload and 02-unsetup
through agentW8's tree, fake crontab and owner view, 13-unload's command for 02-unsetup being run in this process;
12-ztp-monitor, deploy_infra and infra-setup through agentW12's module copies.  fchown and runuser are recorded,
never performed.  The real uid switch belongs to TC-REAL-I006-OPERATOR-LOAD-001 (NOT RUN).

SyncThenLoadOperatorWorkflowTests (v3.1.3 I-058, owner 2026-11-10 04 Q-021 (b)) puts tools/sync-code.py's real
project jobs in front of load; its expectations and its receiver model are in its own docstring.
"""

from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
import functools
import io
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases import test_collection_lock_owner as W9
from test_cases import test_load_collection_worker_contract as M3
from test_cases import test_load_operator_contract as L57
from test_cases import test_load_permission_repair_contract as W6
from test_cases import test_operator_peripheral_contract as W12
from test_cases import test_unsetup_operator_crontab as W8
from test_cases import test_upgrade_operator_reexec as W10
from test_cases.module_loader import load_script
from test_cases.public_project_fixture import materialized_public_project

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))
import operator_identity as OI  # noqa: E402  (after the tools path, as the scripts import it)

LOAD = W6.LOAD                # the 11-load copy agentW6's OwnerModel views; M3's fixture runs the one it is given
INITIALIZE = LOAD.initialize_from_template
START_MONITOR = LOAD.start_ztp_monitor
REPAIR = LOAD.repair_project_permissions
UNLOAD = load_script("load_operator_workflow_unload", ROOT / "DAY0-Prepare/13-unload.py")
UNSETUP = load_script("load_operator_workflow_unsetup", ROOT / "DAY0-Prepare/02-unsetup.py")
SYNC = load_script("load_operator_workflow_sync", ROOT / "tools/sync-code.py")
SYNC_REMOTE_ROOT = "/var/www/html"
# rsync(1) --itemize-changes: the update type, the file type, the attribute columns, a space, the name.
ITEMIZED = re.compile(r"^[<>ch.*][fdLDS]\S* (.+)$")
AREAS = ("ethernet", "infiniband", "nvlink")
SUDO_NAMES = ("SUDO_USER", "SUDO_UID", "SUDO_GID", OI.ROOT_PARENT_MARKER, "HTTP_ZTP_RUNTIME_BACKEND")
WATCH = ("auto.env", "auto-watch.state", "auto-terminal.json")
# agentOP report 4.4 #5 (http dev adopted it as the root-private list): the template's only root-private entry.
ROOT_PRIVATE_TEMPLATE_ENTRY = "99-output-backup"


def banner_sudo(name: str) -> str:
    """Design §4.2's identity line for 「U + sudo」 on U's project, with U named."""
    return f"操作员：{name}（项目目录属主）；当前：root 经 sudo（发起人 {name}）→ 项目侧以 {name} 执行"


def identity_lines(text: str) -> list[str]:
    return [line[line.index("操作员："):] for line in text.splitlines() if "操作员：" in line]


def operator_named(line: str) -> str:
    """The operator an identity line names (design §4.2: 「操作员：U（项目目录属主）……」)."""
    return line[len("操作员："):line.index("（")]


class _OperatorFlow(M3.SystemdLoadMainFixture):
    """One code tree, one project, and the scripts of a way A / way B run on it (no test methods)."""

    load_module = LOAD

    def flow(self) -> SimpleNamespace:
        """agentW8's tree (pointer, REQ10C watch of the project, fake crontab) plus what a code tree has."""
        group = next((gid for gid in os.getgroups() if gid != os.getegid()), None)
        self.assertIsNotNone(group, "the fixture needs a second group of the test user to stand for U's group")
        holder = tempfile.TemporaryDirectory(prefix="wp13-bin-")
        self.addCleanup(holder.cleanup)
        self.bin = Path(holder.name).resolve()
        crontab = self.bin / "crontab"
        crontab.write_text(W8.FAKE_CRONTAB.format(python=sys.executable), encoding="utf-8")
        crontab.chmod(0o700)
        self.unsetup = UNSETUP                  # agentW8's globals_of patches this module
        tree = W8.Fixture.tree(self)
        base = tree.base
        operator = L57.passwd_entry("opuser", L57.ME.pw_uid + 1, group, base / "home-opuser")
        root = L57.passwd_entry("root", 0, 0, base / "root-home")
        (tree.project / "01-global.yaml").write_text("# placeholder\n", encoding="utf-8")
        for area in AREAS:
            (base / area / "monitor").mkdir(parents=True, exist_ok=True)
        # setup's managed infra log link (R-016 §2), as agentW12's infra_tree has it.
        (base / "infra").mkdir()
        (base / "infra/logs").symlink_to("../DAY0-Prepare/activate-project/99-output-infra")
        return SimpleNamespace(tree=tree, root=base, project=tree.project, u=operator, root_entry=root,
                               entries=(operator, root))

    @staticmethod
    def passwd(flow):
        by_uid = {entry.pw_uid: entry for entry in flow.entries}
        by_name = {entry.pw_name: entry for entry in flow.entries}

        def getpwuid(uid):
            if uid not in by_uid:
                raise KeyError(uid)
            return by_uid[uid]

        def getpwnam(name):
            if name not in by_name:
                raise KeyError(name)
            return by_name[name]

        return getpwuid, getpwnam

    @contextmanager
    def process_as(self, flow, *, euid: int, sudo=None, owner_uid: int | None = None):
        """What tools/operator_identity.py sees in every script of this step: euid, sudo, passwd, project owner.

        agentL57's resolution() on injected inputs; os.environ carries the same sudo variables, and HOME is root's
        under root (sudo resets it), so a script that read HOME instead of passwd would show.
        """
        owner = flow.u.pw_uid if owner_uid is None else owner_uid
        environment = {name: value for name, value in os.environ.items() if name not in SUDO_NAMES}
        environment["HOME"] = str(flow.root_entry.pw_dir if euid == 0 else flow.u.pw_dir)
        if sudo is not None:
            environment.update(SUDO_USER=sudo.pw_name, SUDO_UID=str(sudo.pw_uid), SUDO_GID=str(sudo.pw_gid))

        def resolve(project_dir, **_live_defaults):
            return L57.resolution(project_dir, euid=euid, sudo=sudo, entries=flow.entries, owner_uid=owner)

        with mock.patch.dict(os.environ, environment, clear=True), \
                mock.patch.object(OI, "resolve_operator", side_effect=resolve) as rule:
            yield rule

    # ---------------------------------------------------------------- load
    def load(self, flow, *, inputs=None, http=False, dhcp=False, patches=None, model=None, **overrides):
        """The real 11-load main (agentM3's systemd fixture) on the flow's project, the real template fill
        included; returns the fixture result plus the recorded fchown calls (inode, uid, gid) and the names that
        existed before.  With ``model`` (agentW6's OwnerModel) the real permission repair runs as well, under
        root's umask 022 (agentW6 W6-7), and load sees the modelled owners."""
        values = {"HTTP_ROOT": flow.root, "resolve_project": mock.Mock(return_value=flow.project),
                  "initialize_from_template": INITIALIZE}
        if model is not None:
            values["repair_project_permissions"] = REPAIR       # M3's fixture records it by default
        values.update(patches or {})
        before = set(L57.entries_by_inode(flow.project).values())
        arguments = dict(project=flow.project.name, ssh_dir=None, deployment_scope="prod")
        arguments.update(overrides)
        with ExitStack() as stack:
            calls = stack.enter_context(L57.recorded_fchown())
            if model is not None:
                stack.enter_context(model.active(forbid_path_calls=False))
                stack.callback(os.umask, os.umask(0o022))
            result = self.run_load_main(self.main_args(**arguments),
                                        inputs or self.main_inputs(http=http, dhcp=dhcp), patches=values)
        if model is not None:
            calls = [(entry[1], uid, gid) for entry, uid, gid in model.chowns]
        return SimpleNamespace(result=result, chowns=calls, before=before)

    def migrating_project(self, flow):
        """Way A's first sudo load on a project root has been writing into (design §4.5), modelled.

        U's own: the project directory (made private: the card's step 2), its REQ10C watch, and a too-open
        ~/.ssh key pair.  Root's: 01-global.yaml (group-writable) and the bringup parents.  Returns the model, the
        [PERM] lines O9 asks for (owner U and U's passwd group; the project 0755, ~/.ssh 0700, the private key
        0600, everything else only tightened) and the names whose owner the repair changes.
        """
        operator = (flow.u.pw_uid, flow.u.pw_gid)
        model = W6.OwnerModel()
        project = flow.project
        project.chmod(0o700)
        for path in (project, flow.tree.state, *flow.tree.leaves.values()):
            model.own(path, *operator)
        settings = project / "01-global.yaml"
        settings.chmod(0o664)
        model.own(settings, 0, 0)
        for name in ("99-output-ib_nvl", "99-output-ib_nvl/bringup"):
            (project / name).chmod(0o755)
            model.own(project / name, 0, 0)
        ssh = Path(flow.u.pw_dir) / ".ssh"
        ssh.mkdir(parents=True)
        ssh.chmod(0o755)
        model.own(ssh, *operator)
        for name in ("id_ed25519", "id_ed25519.pub"):
            (ssh / name).write_bytes(b"fixture\n")
            (ssh / name).chmod(0o644)
            model.own(ssh / name, *operator)
        lines = {
            W6.perm_line(project, (*operator, 0o700), (*operator, 0o755)),
            W6.perm_line(settings, (0, 0, 0o664), (*operator, 0o644)),
            W6.perm_line(project / "99-output-ib_nvl", (0, 0, 0o755), (*operator, 0o755)),
            W6.perm_line(project / "99-output-ib_nvl/bringup", (0, 0, 0o755), (*operator, 0o755)),
            W6.perm_line(ssh, (*operator, 0o755), (*operator, 0o700)),
            W6.perm_line(ssh / "id_ed25519", (*operator, 0o644), (*operator, 0o600)),
        }
        return model, lines, {"01-global.yaml", "99-output-ib_nvl", "99-output-ib_nvl/bringup"}

    @staticmethod
    def owners_after(model):
        """The owners load left, as 13-unload's run sees them: uid 0 is the test user, who plays root."""
        return {entry: (L57.ME.pw_uid if uid == 0 else uid) for entry, (uid, _gid) in model.owners.items()}

    def assert_sudo_load_acts_for_operator(self, flow, load, *, repaired=frozenset()) -> None:
        """U's sudo load: who runs it (root, no runuser) and who owns what it made, repaired and read (U)."""
        result = load.result
        self.assertEqual(0, result.rc, result.stderr)
        # 以谁执行: load itself stays root (a system tool, design §4.2 「系统侧工作以 root 做」) and says so once.
        self.assertEqual([banner_sudo(flow.u.pw_name)], identity_lines(result.stdout), result.stdout)
        launched = list(result.popen)
        self.assertTrue(launched)
        for argv in [*launched, *map(list, result.runs)]:
            self.assertNotIn("runuser", argv, argv)
        self.assertEqual({sys.executable}, {argv[0] for argv in launched})
        # 文件属于谁 (key): the operator's ~/.ssh from passwd, not root's HOME (scheme item 1; design §4.3).
        key_dir = Path(flow.u.pw_dir) / ".ssh"
        validated = result.mocks["validate_inputs"].call_args.args[1].ssh_dir
        self.assertEqual(key_dir, validated)
        self.assertNotEqual(Path(flow.root_entry.pw_dir) / ".ssh", validated, "HOME was root's during the step")
        # 文件属于谁 (files): every entry load made, and each entry root had left that the repair corrected
        # (``repaired``), goes to U and U's passwd group (O11 ②, O9; 问题文档 :331); nothing else that existed
        # before, no link and no root-private state is touched (agentOP 4.4).
        names = L57.entries_by_inode(flow.project)
        for area in AREAS:   # O14: load pre-creates the three collection locks for the operator
            self.assertTrue(os.path.lexists(flow.root / area / "monitor/cron.lock"), area)
        locks = {(flow.root / area / "monitor/cron.lock").lstat().st_ino: area for area in AREAS}
        operator = (flow.u.pw_uid, flow.u.pw_gid)
        self.assertEqual({operator}, {(uid, gid) for _ino, uid, gid in load.chowns})
        handed = [names[ino] for ino, _uid, _gid in load.chowns if ino in names]
        self.assertEqual(sorted(AREAS), sorted(locks[ino] for ino, _uid, _gid in load.chowns if ino in locks))
        self.assertEqual(len(load.chowns), len(handed) + len(AREAS), "nothing outside the project and locks")
        self.assertEqual(len(handed), len(set(handed)), "each entry once")
        new = set(names.values()) - load.before
        expected = {name for name in new if not (flow.project / name).is_symlink()
                    and name != ROOT_PRIVATE_TEMPLATE_ENTRY
                    and not name.startswith(ROOT_PRIVATE_TEMPLATE_ENTRY + "/")}
        self.assertLessEqual(set(repaired), load.before)
        for name in ("laptop.pub", "mgmt-server.pub", "02-devices_config.csv", "99-output-infra", "99-output-ztp"):
            self.assertIn(name, expected | set(repaired))     # made by this load, or root's and repaired by it
        self.assertEqual(expected | set(repaired), set(handed))

    # ---------------------------------------------------------------- upgrade
    def upgrade(self, flow, *, euid: int, sudo=None, owner_uid: int | None = None):
        """upgrade.py's real __main__ block through agentW10's in-process launcher; its inline rule gets the
        same inputs (euid, passwd, project owner; the environment is the process's)."""
        owner = flow.u.pw_uid if owner_uid is None else owner_uid
        getpwuid, getpwnam = self.passwd(flow)

        def project_owner(path):
            os.stat(path)          # as agentL57's resolution(): a missing project stays a new one (O11 ④)
            return SimpleNamespace(st_uid=owner)

        rule = functools.partial(W10.REAL_INLINE_RULE, euid=euid, getpwuid=getpwuid, getpwnam=getpwnam,
                                 stat=project_owner)
        environ = {} if sudo is None else {"SUDO_USER": sudo.pw_name, "SUDO_UID": str(sudo.pw_uid),
                                           "SUDO_GID": str(sudo.pw_gid)}
        self.home = getpwuid(euid).pw_dir          # the launcher's HOME: the account that runs it
        args = ("--inspect-only", "--project", str(flow.project))
        before = sorted(L57.entries_by_inode(flow.project).values())
        with L57.recorded_fchown() as calls:
            recorder, stderr = W10._EntryHarness.run_upgrade(
                self, args, euid=euid, environ=environ, runtime_present=True,
                extra=(mock.patch.object(W10.app, "_resolve_operator", rule),))
        return SimpleNamespace(recorder=recorder, stderr=stderr, args=args, chowns=calls,
                               project_unchanged=before == sorted(L57.entries_by_inode(flow.project).values()))

    def assert_upgrade_switches_to(self, flow, run) -> None:
        """Root on U's project: the only thing the entry does is exec runuser -u U (design §4.3 :97)."""
        self.assertEqual(["execvp"], run.recorder.kinds(), run.recorder.events)
        head, assignments, command = W10.split_runuser(run.recorder.events[0][2])
        # 以谁执行: the work runs as U.
        self.assertEqual(["runuser", "-u", flow.u.pw_name, "--", "env", "-i"], head)
        self.assertEqual([sys.executable, str(W10.ENTRY), *run.args], command)
        self.assertEqual((flow.u.pw_name, flow.u.pw_name), (assignments["USER"], assignments["LOGNAME"]))
        # 文件属于谁: the key, known_hosts and venv the U layer uses are under U's passwd home; root wrote and
        # handed over nothing in U's project before switching.
        self.assertEqual(flow.u.pw_dir, assignments["HOME"])
        self.assertEqual([], run.chowns)
        self.assertTrue(run.project_unchanged)

    def assert_upgrade_runs_as_itself(self, run, name: str) -> None:
        """No switch: the run reaches the runtime guard in this process, which says it runs as itself."""
        self.assertEqual(["guard"], run.recorder.kinds(), run.recorder.events)
        lines = identity_lines(run.stderr)
        self.assertEqual(1, len(lines), run.stderr)
        self.assertTrue(lines[0].startswith(f"操作员：{name}（项目目录属主）；当前：{name}"), lines[0])
        self.assertTrue(lines[0].endswith(f"以 {name} 执行"), lines[0])
        self.assertNotIn("项目侧", lines[0])
        self.assertNotIn("root", lines[0])
        self.assertEqual([], run.chowns)
        self.assertTrue(run.project_unchanged)

    # ---------------------------------------------------------------- unload
    def unload(self, flow, view, authority_view=None):
        """The real 13-unload main as root; its command for 02-unsetup runs the real 02-unsetup main in this
        process (agentW8's globals: the tree, the fake crontab on PATH, ``view`` as 02-unsetup's os;
        ``authority_view`` as config_sync_authority's)."""
        commands = []

        @contextmanager
        def held(*_args, **_kwargs):
            yield 9

        def run_unsetup(command, *, dry_run=False, inherited_lock_descriptor=None):
            commands.append(list(command))
            with ExitStack() as stack:
                stack.enter_context(W8.Fixture.globals_of(self, flow.tree, view))
                stack.enter_context(mock.patch.object(UNSETUP, "deployment_lock", held))   # 13-unload holds it
                stack.enter_context(mock.patch.object(UNSETUP, "stop_native_ztp_monitors", return_value=()))
                if authority_view is not None:
                    stack.enter_context(mock.patch.object(UNSETUP.config_sync_authority, "os", authority_view))
                code = UNSETUP.main(list(command[2:]))
            if code:
                raise subprocess.CalledProcessError(code, command)

        output = io.StringIO()
        with ExitStack() as stack:
            for name, value in (
                ("HERE", flow.root / "DAY0-Prepare"), ("HTTP_ROOT", flow.root),
                # 13-unload's own root check reads os.geteuid(): a root view of os for this module only.
                ("os", W9._WorkerOs(euid=0, chowns=[])),
                ("service_runtime_backend", mock.Mock(return_value=SimpleNamespace(name="systemd"))),
                ("deployment_lock", held), ("unmanaged_dhcp_runtime_files", mock.Mock(return_value=[])),
                ("stop_monitor", mock.Mock()), ("stop_monitor_workers", mock.Mock()), ("stop_services", mock.Mock()),
                ("remove_ztp_prefix_publication", mock.Mock()),
                ("remove_dhcp_runtime_files", mock.Mock(return_value=[])), ("run", run_unsetup),
            ):
                stack.enter_context(mock.patch.object(UNLOAD, name, value))
            stack.enter_context(redirect_stdout(output))
            stack.enter_context(redirect_stderr(output))
            code = UNLOAD.main(["-y", str(flow.project)])
        return SimpleNamespace(code=code, output=output.getvalue(), commands=commands,
                               crontab=W8.Fixture.calls(flow.tree), chowns=view.fchowns)

    def assert_unload(self, flow, run, *, crontab_user: str | None) -> None:
        self.assertEqual(0, run.code, run.output)
        # 以谁执行: 13-unload runs 02-unsetup itself (no runuser), so the crontab is driven by root.
        self.assertEqual([[sys.executable, str(UNLOAD.UNSETUP_SCRIPT), "-y", str(flow.project)]], run.commands)
        self.assertFalse(os.path.lexists(flow.root / "DAY0-Prepare/activate-project"), "unsetup ran to the end")
        # 文件属于谁: whose crontab root edits, and that only the project's watch line went from it.
        self.assertTrue(run.crontab)
        self.assertEqual({"-l", "-"}, {argv[-1] for argv in run.crontab})
        prefix = [] if crontab_user is None else ["-u", crontab_user]
        for argv in run.crontab:
            self.assertEqual(prefix, argv[:-1], run.crontab)
        W8.Fixture.assert_cleaned(self, flow.tree)


class OperatorModesWorkflowTests(_OperatorFlow, unittest.TestCase):
    """Design §4.6 workflow rows; guide WP-13 table (the initial-setup step is D1's)."""

    def test_mode_a_sudo_load_operator_upgrade_sudo_unload(self) -> None:
        # Design §1/§4.6 way A: sudo load -> upgrade by U -> sudo unload; §4.5: the first sudo load meets a project
        # root has been writing into.
        flow = self.flow()
        name = flow.u.pw_name
        operator = (flow.u.pw_uid, flow.u.pw_gid)
        model, lines, repaired = self.migrating_project(flow)
        with self.process_as(flow, euid=0, sudo=flow.u):
            load = self.load(flow, model=model)
        self.assert_sudo_load_acts_for_operator(flow, load, repaired=repaired)
        # load's repair points at U (问题文档 :331; O9): one [PERM] line per corrected entry, each naming U and U's
        # passwd group, and none from the later repairs (design §4.6: a second run changes nothing).
        printed = W6.perm_lines(load.result.stdout)
        self.assertEqual(len(printed), len(set(printed)), load.result.stdout)
        self.assertEqual(lines, set(printed))
        for line in printed:
            self.assertIn(f" -> {flow.u.pw_uid}:{flow.u.pw_gid} ", line)
        ssh = Path(flow.u.pw_dir) / ".ssh"
        named = {W6.key(path): path for path in (flow.project, flow.project / "01-global.yaml", ssh,
                                                 ssh / "id_ed25519")}
        self.assertEqual({flow.project: 0o755, flow.project / "01-global.yaml": 0o644, ssh: 0o700,
                          ssh / "id_ed25519": 0o600},
                         {named.get(entry, entry): value for entry, value in model.chmods})
        # After load the project, root's leftovers included, and the key pair are U's (design §4.6).
        for path in (flow.project, *(flow.project / entry for entry in repaired), flow.tree.state,
                     *flow.tree.leaves.values(), ssh, ssh / "id_ed25519", ssh / "id_ed25519.pub"):
            self.assertEqual(operator, model.owner(path), path)

        with self.process_as(flow, euid=flow.u.pw_uid):
            upgrade = self.upgrade(flow, euid=flow.u.pw_uid)
        self.assert_upgrade_runs_as_itself(upgrade, name)   # design §4.2: 「U 直接运行……以 U 执行」

        view = W8.OwnerView(self.owners_after(model))         # the owners load left
        with self.process_as(flow, euid=0, sudo=flow.u):
            unload = self.unload(flow, view)
        self.assert_unload(flow, unload, crontab_user=name)   # design §4.3 :96
        self.assertEqual([banner_sudo(name)] * 2, identity_lines(unload.output), "13-unload and 02-unsetup")
        # O11 ②: the crontab lock root made in U's directory is U's at once.
        self.assertEqual([(flow.tree.lock.lstat().st_ino, flow.u.pw_uid, flow.u.pw_gid)], unload.chowns)

    def test_mode_b_root_throughout_never_runuser(self) -> None:
        # Design §1/§4.6 way B: root logs in and runs everything on a root-owned project; §4.2 「以 root 执行」.
        flow = self.flow()
        root_home = Path(flow.root_entry.pw_dir)
        with self.process_as(flow, euid=0, owner_uid=0):
            load = self.load(flow)
            upgrade = self.upgrade(flow, euid=0, owner_uid=0)
            unload = self.unload(flow, W8.OwnerView({W8.inode(flow.project): 0}))
        result = load.result
        self.assertEqual(0, result.rc, result.stderr)
        self.assertEqual(["guard"], upgrade.recorder.kinds(), upgrade.recorder.events)   # no runuser exec
        for text in (result.stdout, upgrade.stderr, unload.output):
            for line in identity_lines(text):
                # 以谁执行: root, as itself, never on someone's behalf.
                self.assertTrue(line.startswith("操作员：root（项目目录属主）；当前：root"), line)
                self.assertTrue(line.endswith("以 root 执行"), line)
                self.assertNotIn("sudo", line)
                self.assertNotIn("项目侧", line)
        self.assertEqual([1, 1, 2], [len(identity_lines(text)) for text in (result.stdout, upgrade.stderr,
                                                                             unload.output)])
        for argv in [*result.popen, *map(list, result.runs)]:
            self.assertNotIn("runuser", argv, argv)
        # 文件属于谁: the key is root's (/root/.ssh stands for the passwd home of root here) ...
        self.assertEqual(root_home / ".ssh", result.mocks["validate_inputs"].call_args.args[1].ssh_dir)
        # ... what root made stays root's: nothing is handed over and no lock is pre-created for anyone ...
        self.assertEqual([], load.chowns)
        self.assertEqual([], [area for area in AREAS if os.path.lexists(flow.root / area / "monitor/cron.lock")])
        self.assertEqual([], upgrade.chowns)
        self.assertEqual([], unload.chowns)
        # ... and the crontab is root's own: no -u.
        self.assert_unload(flow, unload, crontab_user=None)

    def test_mixed_sudo_load_root_upgrade_operator_upgrade_root_unload_operator_never_flips(self) -> None:
        # Design §4.6 mixed (initial-setup replaced by upgrade, guide 1.3); 问题文档 :352; §4.2 「不会来回变」.
        flow = self.flow()
        name = flow.u.pw_name
        with self.process_as(flow, euid=0, sudo=flow.u):
            load = self.load(flow)
        self.assert_sudo_load_acts_for_operator(flow, load)
        operators = [operator_named(identity_lines(load.result.stdout)[0])]

        with self.process_as(flow, euid=0):                  # root logs in
            by_root = self.upgrade(flow, euid=0)
        self.assert_upgrade_switches_to(flow, by_root)
        operators.append(W10.split_runuser(by_root.recorder.events[0][2])[0][2])   # runuser -u <who>

        with self.process_as(flow, euid=flow.u.pw_uid):     # U itself
            by_u = self.upgrade(flow, euid=flow.u.pw_uid)
        self.assert_upgrade_runs_as_itself(by_u, name)
        operators.append(operator_named(identity_lines(by_u.stderr)[0]))

        view = W8.Fixture.operator_made(flow.tree, *WATCH, uid=flow.u.pw_uid)
        with self.process_as(flow, euid=0):                  # root logs in
            unload = self.unload(flow, view)
        self.assert_unload(flow, unload, crontab_user=name)
        lines = identity_lines(unload.output)
        self.assertEqual(2, len(lines), unload.output)
        for line in lines:
            # Root logged in, no sudo: acting for U (design §4.2 「root 直接登录……代表 U」).
            self.assertTrue(line.startswith(f"操作员：{name}（项目目录属主）；当前：root"), line)
            self.assertNotIn("sudo", line)
            self.assertTrue(line.endswith(f"项目侧以 {name} 执行"), line)
        operators.extend(operator_named(line) for line in lines)
        operators.append(unload.crontab[-1][1])                     # crontab -u <whose>
        self.assertEqual([(flow.tree.lock.lstat().st_ino, flow.u.pw_uid, flow.u.pw_gid)], unload.chowns)
        # Four steps, one operator: the project owner U, whoever runs (design §4.2 「不会来回变」).
        self.assertEqual([name] * 6, operators)


class LoadCrossScriptOwnershipWorkflowTests(_OperatorFlow, unittest.TestCase):
    """Guide WP-13: owners that cross from load into the scripts it starts."""

    def test_load_started_monitor_uses_operator_identity(self) -> None:
        # Design §4.3 :98 (the monitor stays root and reads the operator's key); scheme item 1 (:291); O12 ①.
        flow = self.flow()
        started = []

        def popen(command, **kwargs):
            started.append((list(command), dict(kwargs)))
            return M3._FakeProcess()

        with self.process_as(flow, euid=0, sudo=flow.u):
            load = self.load(flow, http=True, dhcp=True, start_ztp_monitor=True, patches={
                "start_ztp_monitor": START_MONITOR, "ZTP_DIR": flow.root / "ztp", "_popen_subprocess": popen})
            self.assertEqual(0, load.result.rc, load.result.stderr)
            monitors = [(argv, kwargs) for argv, kwargs in started if Path(argv[2]).name == "12-ztp-monitor.py"]
            self.assertEqual(1, len(monitors), started)
            argv, kwargs = monitors[0]
            # 以谁执行: load (root) starts the monitor itself, which inherits load's process and environment.
            self.assertEqual([sys.executable, "-u"], argv[:2])
            self.assertNotIn("runuser", argv)
            self.assertNotIn("--identity", argv)                 # load passes no key (guide WP-12)
            self.assertNotIn("env", kwargs)
            seen, rc, output = self.run_monitor(flow, argv[3:])
        self.assertEqual(130, rc, output)                        # the test's own stop after the first cycle
        self.assertIn(banner_sudo(flow.u.pw_name), identity_lines(output))
        # 文件属于谁: the key the monitor logs in with is U's, from U's passwd home (O12 ①: id_ed25519).
        key = Path(flow.u.pw_dir) / ".ssh/id_ed25519"
        operator = OI.Operator(flow.u.pw_name, flow.u.pw_uid, flow.u.pw_gid, flow.u.pw_dir)
        self.assertEqual([{"identity": key, "operator": operator}], seen)   # while HOME was root's (process_as)

    def run_monitor(self, flow, argv):
        """The real 12-ztp-monitor main on load's argv, stopped by the test after one recorded cycle."""
        monitor = W12.MONITOR
        seen = []

        def cycle(args, _project):
            seen.append({"identity": args.identity, "operator": getattr(args, "_project_operator", None)})
            raise KeyboardInterrupt

        output = io.StringIO()
        with ExitStack() as stack:
            for name, value in (
                ("require_active_project", mock.Mock(return_value=flow.project)),
                ("active_project_dir", mock.Mock(side_effect=AssertionError("second pointer read"))),
                ("monitor_once", mock.Mock(side_effect=cycle)),
                ("read_report", mock.Mock(return_value={"devices": []})),
                ("print_environment_summary", mock.Mock()),
                ("monitor_control_state", mock.Mock(return_value="running")),
                ("_governed_watch_identity", mock.Mock(return_value=("bound",))),
                ("active_project_moved", mock.Mock(return_value=None)),
            ):
                stack.enter_context(mock.patch.object(monitor, name, value))
            stack.enter_context(mock.patch.object(OI, "active_project",
                                                  side_effect=AssertionError("second pointer read")))
            stack.enter_context(mock.patch.object(monitor.signal, "signal"))
            stack.enter_context(redirect_stdout(output))
            stack.enter_context(redirect_stderr(output))
            rc = monitor.main(list(argv))
        return seen, rc, output.getvalue()

    def test_sudo_load_infra_logs_end_up_operator_owned(self) -> None:
        # Scheme item 4 (:294); O11 ② (deploy_infra hands its project log to the operator), O11 ⑤ (infra-setup to
        # the owner of the directory, which after load is U); O9 (U's passwd group).
        flow = self.flow()
        inputs = self.main_inputs(http=True, dhcp=False)
        inputs.settings.http_address = "192.0.2.10"
        inputs.global_file = flow.project / "01-global.yaml"
        inputs.devices_file = flow.project / "02-devices_config.csv"
        operator = (flow.u.pw_uid, flow.u.pw_gid)
        output = flow.project / "99-output-infra"
        with self.process_as(flow, euid=0, sudo=flow.u):
            load = self.load(flow, inputs=inputs, skip_infra=False, skip_doca=True)
            self.assertEqual(0, load.result.rc, load.result.stderr)
            # load handed its new 99-output-infra to U; on disk the group change is real (the test user is in that
            # group), the owner is what 02-unsetup-style owner views report.
            self.assertIn((output.lstat().st_ino, *operator), load.chowns)
            os.chown(output, -1, flow.u.pw_gid)
            deploy = [list(command) for command in load.result.runs
                      if len(command) > 1 and Path(command[1]).name == "deploy_infra.py"]
            setup = [list(command) for command in load.result.runs
                     if len(command) > 2 and Path(command[2]).name == "infra-setup.py"]
            self.assertEqual(1, len(deploy), load.result.runs)
            self.assertEqual(1, len(setup), load.result.runs)
            # 以谁执行: load runs both itself, as root (no runuser, no sudo -u).
            for command in (deploy[0], setup[0]):
                self.assertEqual(sys.executable, command[0])
                self.assertNotIn("runuser", command)
                self.assertNotIn("-u", command)
            self.assertIn("--prepare-only", deploy[0])

            # deploy_infra --prepare-only: its script entry wraps main in run_with_log (the real one here).
            deployed, parsed = [], []
            with mock.patch.object(W12.DEPLOY, "SCRIPT_DIR", flow.root / "infra"), \
                    mock.patch.object(W12.DEPLOY, "os", W9._WorkerOs(euid=0, chowns=deployed)), \
                    mock.patch.object(sys, "argv", deploy[0][1:]), redirect_stdout(io.StringIO()):
                self.assertEqual(0, W12.DEPLOY.run_with_log(
                    "deploy_infra", lambda: parsed.append(W12.DEPLOY.parse_args()) or 0))
            self.assertTrue(parsed[0].prepare_only)

            options = W12.INFRA_SETUP.parse_arguments(setup[0][3:])
            with mock.patch.object(W12.INFRA_SETUP, "SCRIPT_PATH", str(flow.root / "infra/infra-setup.py")):
                infra = W12.INFRA_SETUP.InfraSetup(options)
            view = W8.OwnerView({W8.inode(output): flow.u.pw_uid})
            with mock.patch.object(W12.INFRA_SETUP, "is_root", return_value=True), \
                    mock.patch.object(W12.INFRA_SETUP, "os", view), \
                    redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                infra.open_log()
            os.close(infra.log_fd)
        # 文件属于谁: each log root wrote into the project went to U and U's passwd group.
        deploy_logs = list(output.glob("deploy_infra-*.log"))
        setup_logs = list(output.glob("infra-setup-*.log"))
        self.assertEqual(1, len(deploy_logs))
        self.assertEqual(1, len(setup_logs))
        self.assertEqual([(W12.identity_of(deploy_logs[0]), *operator)], deployed)
        self.assertEqual([(setup_logs[0].lstat().st_ino, *operator)], view.fchowns)

    def test_sudo_unload_after_repair_still_withdraws_config_authorities(self) -> None:
        # Guide WP-13 table; design §4.1 (config_sync_authority's namespaces are system side: root makes and checks
        # them against its own euid) and §4.6 (way A ends with a sudo unload, which must go through); agentOP 4.4.
        flow = self.flow()
        operator = (flow.u.pw_uid, flow.u.pw_gid)
        model, _lines, repaired = self.migrating_project(flow)    # way A's first sudo load, as in the test above
        authority = UNSETUP.config_sync_authority
        output = flow.project / "99-output-ztp"
        output.mkdir()
        output_mode = W6.mode(output)
        manual, methods = output / "manual-config-sync", output / "configuration-methods"
        # Eras an earlier root monitor and manual-ztp opened (test_config_sync_authority's calls).
        authority.begin(manual, "leaf1", "teardown", "teardown-leaf1", "manual_config_sync_cli")
        authority.begin_method(methods, "leaf1", "first", "first-leaf1", "ztp_monitor_cycle")
        for read, root in ((authority.read_current, manual), (authority.read_method_current, methods)):
            self.assertEqual("pending", read(root, "leaf1")["state"])   # open eras before load
        model.own_tree(output, 0, 0)                          # root made all of 99-output-ztp
        private = {W6.key(path) for root in (manual, methods) for path in (root, *root.rglob("*"))}
        self.assertTrue(any(path.name == ".authority" for path in manual.iterdir()))

        with self.process_as(flow, euid=0, sudo=flow.u):
            load = self.load(flow, model=model)
        # 文件属于谁 (load): root's repair never touched what is under the two namespaces (no fchown, no fchmod,
        # still root's), whatever else load went on to do.
        self.assertEqual(set(), private & model.changed())
        for root in (manual, methods):
            for path in (root, *root.rglob("*")):
                self.assertEqual((0, 0), model.owner(path), path)
        # 以谁执行 (load) and the rest of 文件属于谁: the same sudo load as way A's (one identity line, no runuser,
        # U's key directory, new and repaired entries U's), 99-output-ztp itself among the repaired ones.
        self.assert_sudo_load_acts_for_operator(flow, load, repaired=repaired | {"99-output-ztp"})
        self.assertIn(W6.perm_line(output, (0, 0, output_mode), (*operator, output_mode & ~0o022)),
                      W6.perm_lines(load.result.stdout))
        self.assertEqual(operator, model.owner(output))

        # 以谁执行: the sudo unload's 02-unsetup is root and withdraws root's own eras; 文件属于谁: it sees the owners
        # load left (agentW8's OwnerView for 02-unsetup and for config_sync_authority).
        owners = self.owners_after(model)
        with self.process_as(flow, euid=0, sudo=flow.u):
            unload = self.unload(flow, W8.OwnerView(owners), W8.OwnerView(dict(owners)))
        self.assert_unload(flow, unload, crontab_user=flow.u.pw_name)
        self.assertEqual([(flow.tree.lock.lstat().st_ino, *operator)], unload.chowns)
        self.assertEqual(("failed", True), tuple(authority.read_current(manual, "leaf1")[name]
                                                 for name in ("state", "veto")))
        self.assertEqual(("failed", True), tuple(authority.read_method_current(methods, "leaf1")[name]
                                                 for name in ("state", "veto")))


class _RootLoadOwnerModel(W6.OwnerModel):
    """agentW6's OwnerModel for way B: what the test user made and the model names no owner for is root's.

    The test user plays root's load here (as owners_after has it for 13-unload), so what the real load creates
    while it runs (template backfill, outputs) is root's, as on the server; modelled owners still win.
    """

    def _view(self, metadata):
        if (metadata.st_dev, metadata.st_ino) in self.owners or metadata.st_uid != L57.ME.pw_uid:
            return super()._view(metadata)
        fields = {name: getattr(metadata, name) for name in dir(metadata) if name.startswith("st_")}
        fields["st_uid"], fields["st_gid"] = 0, 0
        return SimpleNamespace(**fields)

    def owner(self, path: Path) -> tuple[int, int]:
        metadata = os.lstat(path)
        played = (0, 0) if metadata.st_uid == L57.ME.pw_uid else (metadata.st_uid, metadata.st_gid)
        return self.owners.get((metadata.st_dev, metadata.st_ino), played)


class SyncThenLoadOperatorWorkflowTests(_OperatorFlow, unittest.TestCase):
    """I-058 (v3.1.3 guide 9.5 #3): sync-code's project jobs, then load on what they left, in way A and way B.

    Expected values: 问题文档 I-006 (the operator is the owner of the project directory), the v3.1.2 release notes
    3.3 table (way A: U's project; way B: root's), 04 Q-017 (an owner that is neither root nor the operator is
    listed and load stops) and 04 Q-021 / 问题文档 I-058 (owner 2026-11-10 (b): a native sync does not carry the
    workstation's owner into the server's project; guide 9.2: an existing project directory keeps its owner, what
    the sync writes belongs to the receiver, root, until load's repair hands it to the operator).

    The real SYNC.build_jobs and rsync_command build the project jobs, replayed between local directories as
    test_project_link_inputs_workflow's sync_project does (sudo=False; the flag string depends on the runtime
    only, and the sudo=True string is compared directly).  The receiver would be root on the server and cannot be
    here, so what it owns afterwards is modelled from rsync(1) in agentW6's OwnerModel: a flag string that keeps
    the owner (a or o) gives the project directory and every itemized entry the workstation's account -- either a
    uid the server's passwd lacks, or a same-named server account that is not the operator; one that does not
    keeps what existed and gives every new entry 0:0.  Then the real 11-load main runs as the model's project
    owner says.  The real mapping is TC-REAL-I006-OPERATOR-LOAD-001's step 0 (guide 9.8).
    """

    WORKSTATION_ACCOUNTS = ("uid missing from the server's passwd", "same-named server account")

    def sync_then_load(self, way: str, workstation: str) -> SimpleNamespace:
        flow = self.flow()
        owner = (0, 0) if way == "B" else (flow.u.pw_uid, flow.u.pw_gid)
        model = _RootLoadOwnerModel() if way == "B" else W6.OwnerModel()
        model.own_tree(flow.project, *owner)       # the project as the server has it before the sync
        if workstation == self.WORKSTATION_ACCOUNTS[0]:
            account = (L57.ME.pw_uid, L57.ME.pw_gid)  # the test user plays the workstation account
            self.assertNotIn(L57.ME.pw_uid, {entry.pw_uid for entry in flow.entries})
        else:
            namesake = L57.passwd_entry(L57.ME.pw_name, L57.ME.pw_uid + 3, L57.ME.pw_gid + 3,
                                        flow.root / "home-namesake")
            flow.entries = (*flow.entries, namesake)
            account = (namesake.pw_uid, namesake.pw_gid)
        args = argparse.Namespace(runtime="native", dry_run=False, sudo=False, host="sync-target", port=22,
                                  identity=None)
        root_receiver = argparse.Namespace(**{**vars(args), "sudo": True})
        flags, itemized = set(), []
        with materialized_public_project(ROOT) as source:
            with redirect_stdout(io.StringIO()):
                jobs = SYNC.build_jobs(source, SYNC_REMOTE_ROOT)
            jobs = [job for job in jobs if job.remote_dir == f"{SYNC_REMOTE_ROOT}/DAY0-Prepare/{source.name}"]
            self.assertTrue(jobs)
            for job in jobs:
                command = SYNC.rsync_command(job, args)
                self.assertEqual(SYNC.rsync_command(job, root_receiver)[1], command[1])
                flags.add(command[1])
                transport = command.index("-e")
                del command[transport:transport + 2]
                self.assertEqual(f"{args.host}:{job.remote_dir}/", command[-1])
                command[-1] = os.fspath(flow.project) + "/"
                done = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      text=True)
                for line in done.stdout.splitlines():
                    match = ITEMIZED.match(line)
                    if match:
                        itemized.append(match.group(1).split(" -> ", 1)[0].rstrip("/"))
        self.assertTrue(itemized)
        written = []
        if any(letter in flag[1:] for flag in flags for letter in "ao"):
            for path in (flow.project, *(flow.project / name for name in itemized)):
                model.own(path, *account)
        else:
            written = [name for name in itemized if W6.key(flow.project / name) not in model.owners]
            for name in written:
                model.own(flow.project / name, 0, 0)
        modes = {name: W6.mode(flow.project / name) for name in written}
        with self.process_as(flow, euid=0, sudo=flow.u if way == "A" else None,
                             owner_uid=model.owner(flow.project)[0]):
            load = self.load(flow, model=model)
        return SimpleNamespace(flow=flow, model=model, written=written, modes=modes, load=load)

    def test_way_b_root_project_keeps_root_as_operator_after_a_sync(self) -> None:
        # Guide 9.5 #3 way B; v3.1.2 release notes 3.3 (way B: root's project); 04 Q-017; 04 Q-021, 问题文档 I-058.
        for workstation in self.WORKSTATION_ACCOUNTS:
            with self.subTest(workstation=workstation):
                run = self.sync_then_load("B", workstation)
                result = run.load.result
                # 以谁执行: design §4.2's line for root on its own project (guide 9.5 #3 quotes it).
                self.assertEqual(["操作员：root（项目目录属主）；当前：root 直接运行 → 以 root 执行"],
                                 identity_lines(result.stdout), result.stdout + result.stderr)
                self.assertEqual(0, result.rc, result.stderr)
                # 文件属于谁: the gate-side repair met no third-party owner (04 Q-017); the project directory is
                # still root's and what the sync wrote is the receiver's, root's (guide 9.2).
                self.assertNotIn("项目权限检查停止", result.stdout + result.stderr)
                self.assertEqual((0, 0), run.model.owner(run.flow.project))
                self.assertTrue(run.written)
                for name in run.written:
                    self.assertEqual((0, 0), run.model.owner(run.flow.project / name), name)

    def test_way_a_operator_keeps_the_project_and_takes_what_the_sync_wrote(self) -> None:
        # Guide 9.5 #3 way A; 问题文档 I-006 (operator = project owner; what root writes goes to the real user);
        # v3.1.2 release notes 3.3 (way A: U's project); 04 Q-021, 问题文档 I-058 and guide 9.2 (load's repair
        # before the HTTP gate hands the sync's root:root entries to the operator).
        for workstation in self.WORKSTATION_ACCOUNTS:
            with self.subTest(workstation=workstation):
                run = self.sync_then_load("A", workstation)
                flow, result = run.flow, run.load.result
                self.assertEqual([banner_sudo(flow.u.pw_name)], identity_lines(result.stdout),
                                 result.stdout + result.stderr)
                self.assertEqual(0, result.rc, result.stderr)
                operator = (flow.u.pw_uid, flow.u.pw_gid)
                self.assertEqual(operator, run.model.owner(flow.project))
                self.assertTrue(run.written)
                printed = W6.perm_lines(result.stdout)
                for name in run.written:
                    path = flow.project / name
                    before = run.modes[name]
                    self.assertIn(W6.perm_line(path, (0, 0, before), (*operator, before & ~0o022)), printed)
                    self.assertEqual(operator, run.model.owner(path), name)


if __name__ == "__main__":
    unittest.main()
