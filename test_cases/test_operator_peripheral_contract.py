"""Operator identity at the edges of load (v3.1.2 WP-12, M6): 12-ztp-monitor, deploy_infra, infra-setup,
collect-ztp-diagnostics and the deps.py hint.

Expectations come from the requirement texts, never from the scripts:
- 问题文档 I-006, the scheme owner 2026-10-27 agreed (:290-306): item 1 -- under sudo the real user comes from
  SUDO_USER/SUDO_UID and its ~/.ssh (home from passwd) is read; item 2 -- project-side owner checks compare the
  operator; item 3 -- a missing key is never generated for root on the operator's behalf, the user is told to run
  without sudo; item 4 -- files root writes into the project belong to the operator.  :351 (owner 2026-10-27):
  running with another identity is refused, the monitor likewise.  :254-258: way A (load under sudo, cron.sh
  without it) and way B (root login).
- design `设计/I-006与R-005实现计划.md` §4.1 (root-private state stays root's: config_sync_authority's namespaces,
  the monitor lock files), §4.2 (operator = owner of the project directory), §4.3 :98 (12-ztp-monitor: read the
  operator's key, project writes belong to the operator).
- v3.1.2 guide 3.2 (owner 2026-11-07 「同意你在v3.1.2里的默认建议」, http dev 转述): O11 ② (root's new project
  files are fchown'd to the operator on the descriptor, the monitor too), O11 ⑤ (infra-setup imports no
  project-tree module; its log goes to the owner of the directory it sits in), O12 ① (root uses
  -i <operator home>/.ssh/id_ed25519, no IdentitiesOnly).
- v3.1.2 guide WP-12 and the brief addendum (http dev 2026-11-08): the monitor takes the operator from the project
  require_active_project bound for the run, never a second pointer read (v3.1.1 review 3 A2), and hands over
  files under that bound live root; the diagnostics collector computes its defaults through
  operator_identity.active_project() and resolve_operator(), and falls back to its v3.1.1 defaults with one hint
  line when project_contract/PyYAML cannot be imported (it must still start in a broken environment);
  `_method_release_text` compares the operator.
- `test_infra_setup_py.py::…test_overlapping_duties_have_no_second_implementation` and `test_deps_table.py`
  (existing contracts kept: infra-setup is self-contained; the deps hint keeps the word HOME).
- Docker does not regress (owner 2026-11-02: Docker behaviour and tests stay; Docker work waits for stage 6;
  http dev 2026-11-09 addendum for every M6 package): in the container -- the supervisor backend
  `infra/docker/deploy.sh` sets with HTTP_ZTP_RUNTIME_BACKEND=supervisor for a root container whose passwd often
  lacks the project owner -- the monitor and the diagnostics collector neither refuse nor chown and keep their
  v3.1.1 defaults.

No real uid switch happens (v3.1.2 guide 2.2 item 6): the operator rule gets euid, environ, passwd and the project
owner as inputs through a wrapper around operator_identity.resolve_operator; os.fchown is a recorder.  The only
direct euid patches are narrow calls whose own code reads os.geteuid() (deploy_infra's key generation and its log
hand-over, deps.py's root hint), as test_deps_table already does.
"""
from __future__ import annotations

from contextlib import ExitStack, redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import pwd
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import operator_identity as OI  # noqa: E402

MONITOR = load_script("operator_peripheral_monitor", ROOT / "DAY0-Prepare/12-ztp-monitor.py")
DEPLOY = load_script("operator_peripheral_deploy", ROOT / "infra/deploy_infra.py")
INFRA_SETUP = load_script("operator_peripheral_infra_setup", ROOT / "infra/infra-setup.py")
COLLECTOR = load_script("operator_peripheral_collector", ROOT / "tools/collect-ztp-diagnostics.py")
DEPS = load_script("operator_peripheral_deps", ROOT / "infra/deps.py")

ROOT_ENTRY = pwd.struct_passwd(("root", "x", 0, 0, "root", "/root", "/bin/bash"))
# The operator's primary group differs from its uid so a uid-for-gid slip is visible (O9).
U_ENTRY = pwd.struct_passwd(("opuser", "x", 1001, 2001, "operator", "/home/opuser", "/bin/bash"))
V_ENTRY = pwd.struct_passwd(("otheruser", "x", 1002, 2002, "other", "/home/otheruser", "/bin/bash"))
ACCOUNTS = (ROOT_ENTRY, U_ENTRY, V_ENTRY)
U_OPERATOR = OI.Operator("opuser", 1001, 2001, "/home/opuser")
SUDO_U = {"SUDO_USER": "opuser", "SUDO_UID": "1001", "SUDO_GID": "2001"}
SUDO_V = {"SUDO_USER": "otheruser", "SUDO_UID": "1002", "SUDO_GID": "2002"}
REAL_RESOLVE = OI.resolve_operator


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


def acting_as(euid, environ, owners):
    """Run the real operator rule with this euid/environ and these project owners ({path: uid}).

    The scripts call operator_identity.resolve_operator(project) with the live defaults; the wrapper supplies the
    inputs instead (guide 2.2 item 6: patch the identity function's inputs, never the global euid).  The patch
    object records which project each call named.
    """
    known = {os.path.realpath(str(path)): uid for path, uid in owners.items()}

    def stat(path):
        try:
            return SimpleNamespace(st_uid=known[os.path.realpath(str(path))])
        except KeyError:
            raise FileNotFoundError(path) from None

    def resolve(project_dir, **_live_defaults):
        return REAL_RESOLVE(project_dir, euid=euid, environ=environ, getpwuid=getpwuid,
                            getpwnam=getpwnam, stat=stat)

    return mock.patch.object(OI, "resolve_operator", side_effect=resolve)


def fchown_recorder(records):
    """os.fchown stand-in: remember which object (by device and inode) was handed to whom."""
    def record(descriptor, uid, gid):
        info = os.fstat(descriptor)
        records.append(((info.st_dev, info.st_ino), uid, gid))
    return mock.patch.object(os, "fchown", side_effect=record)


def identity_of(path):
    info = os.lstat(path)
    return info.st_dev, info.st_ino


class ZtpMonitorOperatorTests(unittest.TestCase):
    def _projects(self):
        directory = tempfile.TemporaryDirectory(prefix="wp12-monitor-")
        self.addCleanup(directory.cleanup)
        day0 = Path(directory.name).resolve() / "http/DAY0-Prepare"
        # The CLI names one directory; require_active_project binds another (a test device: the operator must come
        # from the bound project, so only that one has an owner in the fake passwd view).
        named, bound = day0 / "u-project", day0 / "u-bound"
        for project in (named, bound):
            (project / "99-output-ztp").mkdir(parents=True)
            (project / "02-devices_config.csv").write_text("hostname,type\n", encoding="utf-8")
        return named, bound

    def _run_main(self, argv_tail, *, euid, environ, owner_uid, extra=(), process_environment=None):
        """MONITOR.main on the live path with the cycle replaced by a recorder; returns (rc, seen, resolve, out, err).

        process_environment: variables the monitor process itself sees (the container's backend selection).
        """
        named, bound = self._projects()
        seen = []

        def cycle(args, project):
            seen.append({"identity": args.identity, "operator": getattr(args, "_project_operator", None)})
            return bound / "99-output-ztp/run"

        stdout, stderr = io.StringIO(), io.StringIO()
        with ExitStack() as stack:
            resolve = stack.enter_context(acting_as(euid, environ, {bound: owner_uid}))
            stack.enter_context(mock.patch.object(MONITOR, "require_active_project", return_value=bound))
            # v3.1.1 review 3 A2: the run binds its project once; any further pointer read is a defect here.
            stack.enter_context(mock.patch.object(
                MONITOR, "active_project_dir", side_effect=AssertionError("second pointer read")))
            stack.enter_context(mock.patch.object(
                OI, "active_project", side_effect=AssertionError("second pointer read")))
            stack.enter_context(mock.patch.object(MONITOR, "monitor_once", side_effect=cycle))
            stack.enter_context(mock.patch.object(MONITOR, "read_report", return_value={"devices": []}))
            stack.enter_context(mock.patch.object(MONITOR, "print_environment_summary"))
            stack.enter_context(mock.patch.object(MONITOR, "monitor_control_state", return_value="running"))
            stack.enter_context(mock.patch.object(MONITOR.signal, "signal"))
            base = {name: value for name, value in os.environ.items() if name != "HTTP_ZTP_RUNTIME_BACKEND"}
            stack.enter_context(mock.patch.dict(os.environ, {**base, **(process_environment or {})}, clear=True))
            for target, value in extra:
                stack.enter_context(mock.patch.object(MONITOR, target, value))
            stack.enter_context(redirect_stdout(stdout))
            stack.enter_context(redirect_stderr(stderr))
            rc = MONITOR.main([str(named), *argv_tail])
        return rc, seen, resolve, stdout.getvalue(), stderr.getvalue(), bound

    def test_root_monitor_defaults_identity_to_operator_key(self):
        """Design §4.3 :98 (read the operator's key) and O12 ①: root acting for operator U, no --identity -> U's key."""
        key = Path("/home/opuser/.ssh/id_ed25519")
        for label, environ in (("root login", {}), ("sudo by U", SUDO_U)):
            with self.subTest(label):
                rc, seen, resolve, out, err, bound = self._run_main([], euid=0, environ=environ, owner_uid=1001)
                self.assertEqual(0, rc, err)
                self.assertEqual([{"identity": key, "operator": U_OPERATOR}], seen)
                self.assertEqual([mock.call(bound)], resolve.call_args_list, "operator from the bound project")
                self.assertIn("操作员：opuser（项目目录属主）", out, "one identity line (design §4.2)")
        with self.subTest("an explicit --identity wins"):
            rc, seen, *_ = self._run_main(["--identity", "/srv/keys/given"], euid=0, environ={}, owner_uid=1001)
            self.assertEqual(0, rc)
            self.assertEqual(Path("/srv/keys/given"), seen[0]["identity"])
        for label, euid, owner in (("root on root's project", 0, 0), ("the operator itself", 1001, 1001)):
            with self.subTest(label):
                rc, seen, *_ = self._run_main([], euid=euid, environ={}, owner_uid=owner)
                self.assertEqual(0, rc)
                self.assertEqual([{"identity": None, "operator": None}], seen, "nothing to act for")

    def test_other_user_refused(self):
        """问题文档 :351 (owner 2026-10-27, the monitor likewise) and O7 ②: another user, plain or via sudo, is refused."""
        for label, euid, environ in (("V directly", 1002, {}), ("V via sudo", 0, SUDO_V)):
            with self.subTest(label):
                rc, seen, _resolve, _out, err, _bound = self._run_main([], euid=euid, environ=environ, owner_uid=1001)
                self.assertEqual(2, rc)
                self.assertEqual([], seen, "refused before any cycle")
                self.assertIn("属于 opuser", err, "names the project owner")
                self.assertIn("otheruser", err, "names who is running")

    def _monitor_cycle(self, operator):
        """One real monitor_once over a published release, as a root run acting for `operator` (or not).

        The fixture is test_config_sync_authority_workflow's F02 method cycle (one ztp leaf, isolated device I/O).
        main binds the live root through require_active_project and sets the operator; here both are set the
        way main sets them.  Returns (project, run dir, device, fchown records, _method_release_text calls).
        """
        from test_cases import test_load_release_transaction as release_fixture
        from test_cases import test_manual_applied_config as applied
        fixture = release_fixture.ReleaseTransactionTests("test_writes_parent_release_after_all_components_match")
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        project = fixture.project.resolve()
        expected = applied.MonitorMethodConfigurationTests.EXPECTED.replace("leaf1", "leaf01")
        config = project / "99-output-eth/20260830_120000_combine/leaf01.yaml"
        config.write_text(expected)
        manifest_path = config.parent / "release-manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["devices"][0]["config_sha256"] = hashlib.sha256(expected.encode()).hexdigest()
        manifest_path.write_text(json.dumps(manifest))
        release_fixture.LOAD.validate_and_publish_release(project, fixture.inputs, publish=True)
        apache, dhcp, air = project / "apache.log", project / "dhcp.log", project / "air-link.json"
        apache.write_text("")
        dhcp.write_text("")
        (project / "99-output-p2p").mkdir(exist_ok=True)
        (project / "99-output-p2p/p2p-air.json").write_text('{"nodes": {}}')
        air.symlink_to("99-output-p2p/p2p-air.json")
        args = MONITOR.parser().parse_args([str(project), "--apache-log", str(apache), "--dhcp-log", str(dhcp)])
        args._live_output_root = project / "99-output-ztp"
        if operator is not None:
            args._project_operator = operator
        raw = ("__HOSTNAME_BEGIN__\nleaf01\n__HOSTNAME_END__\n"
               "__ETH0_MAC_BEGIN__\n02:00:00:00:00:01\n__ETH0_MAC_END__\n"
               "__ETH1_MAC_BEGIN__\n\n__ETH1_MAC_END__\n"
               "__HTTP_MONITOR_LIVE_V1_BEGIN__\n" + expected + "\n__HTTP_MONITOR_LIVE_V1_END__=0\n"
               "__HTTP_MONITOR_APPLIED_V1_BEGIN__\n" + applied.protocol(expected)
               + "\n__HTTP_MONITOR_APPLIED_V1_END__=0\n")
        records, reads = [], []
        real_read = MONITOR._method_release_text

        def read(project_dir, relative, *rest):
            try:
                text = real_read(project_dir, relative, *rest)
            except ValueError as exc:
                reads.append((str(relative), rest, str(exc)))
                raise
            reads.append((str(relative), rest, "ok"))
            return text

        with mock.patch.object(MONITOR, "service_runtime_backend", return_value=SimpleNamespace(name="systemd")), \
                mock.patch.object(MONITOR, "service_state",
                                  return_value={"active": "fixture", "enabled": "fixture", "error": ""}), \
                mock.patch.object(MONITOR, "ACTIVE_AIR_JSON", air), \
                mock.patch.object(MONITOR, "run_command",
                                  return_value={"returncode": 0, "stdout": raw, "stderr": ""}), \
                mock.patch.object(MONITOR, "_method_release_text", side_effect=read), \
                fchown_recorder(records), redirect_stdout(io.StringIO()):
            run = MONITOR.monitor_once(args, project)
        device = json.loads((run / "report.json").read_text())["devices"][0]
        return project, run, device, records, reads

    def test_method_release_owner_check_compares_operator(self):
        """问题文档 :292 (scheme item 2) and design §4.2: release members owned by the operator pass; another owner fails.

        The fixture files belong to the user running the test.  As the operator they pass; for an operator with
        another uid the same files are a third party's and the observation is refused -- although the running
        user still owns them, so the comparison is the operator's, not the running user's.
        """
        owner = os.getuid()
        with self.subTest("members owned by the operator"):
            _project, _run, device, _records, reads = self._monitor_cycle(
                OI.Operator("fixture-owner", owner, os.getgid(), "/home/fixture-owner"))
            self.assertTrue(reads)
            self.assertEqual({((owner,), "ok")}, {(rest, outcome) for _name, rest, outcome in reads})
            self.assertEqual("success", device["configuration_method_authority"]["state"])
        with self.subTest("members of a third party"):
            _project, _run, device, _records, reads = self._monitor_cycle(U_OPERATOR._replace(uid=owner + 1))
            self.assertEqual(("99-output-ztp/current-release.json", (owner + 1,),
                              "method project root is not privately owned"), reads[0])
            self.assertNotEqual("success", device["configuration_method_authority"]["state"])

    def test_status_files_created_in_project_are_handed_to_operator(self):
        """问题文档 :294 (scheme item 4), O11 ②: every new snapshot entry and state file goes to the operator on its
        descriptor; config_sync_authority's namespaces and the monitor locks stay root's (design §4.1)."""
        project, run, _device, records, _reads = self._monitor_cycle(U_OPERATOR)
        self.assertTrue(records)
        self.assertEqual({(1001, 2001)}, {(uid, gid) for _identity, uid, gid in records}, "only to the operator")
        handed = {identity for identity, _uid, _gid in records}
        snapshot = [run, *run.rglob("*")]
        self.assertIn(run / "report.json", snapshot)
        self.assertIn(run / "raw/switches/leaf01/ztp_log.log", snapshot)
        for path in snapshot:
            self.assertIn(identity_of(path), handed, f"not handed over: {path.relative_to(project)}")
        output = project / "99-output-ztp"
        self.assertIn(identity_of(output / ".collection-attribution.json"), handed)
        kept = [path for name in ("configuration-methods", "manual-config-sync") if (output / name).exists()
                for path in (output / name).rglob("*")]
        self.assertTrue(kept, "the cycle wrote its configuration-methods boundary")
        kept += [output / "..collection-attribution.json.lock", output / "current-release.json"]
        for path in kept:
            self.assertNotIn(identity_of(path), handed, f"root-private or load-owned: {path.relative_to(project)}")
        self.assertFalse(os.path.islink(run))

    def _watch_with_handoff(self, process_environment=None):
        """MONITOR.main in watch mode for one cycle with one ready completion handoff; returns (rc, records, out)."""
        records = []
        report = {"devices": [{"hostname": "leaf01", "type": "eth"}]}
        extra = (
            ("_governed_watch_identity", mock.Mock(return_value=("bound",))),
            ("active_project_moved", mock.Mock(return_value=None)),
            ("ready_completion_handoff_reports", mock.Mock(return_value={"prod-ethernet": report})),
            ("completion_signature", mock.Mock(return_value=(("leaf01", "eth", "done"),))),
            ("run_completion_handoff_with_gate", mock.Mock(return_value=True)),
            ("controlled_sleep", mock.Mock(side_effect=KeyboardInterrupt)),
        )
        with fchown_recorder(records):
            rc, seen, _resolve, _out, err, bound = self._run_main(
                ["--watch", "5", "--collect-on-complete"], euid=0, environ=SUDO_U, owner_uid=1001, extra=extra,
                process_environment=process_environment)
        self.assertEqual(130, rc, err)
        self.assertEqual(1, len(seen))
        output = bound / "99-output-ztp"
        for name in (".ztp-monitor-watch-state.json", ".ztp-completion-handoff.json"):
            self.assertTrue((output / name).is_file(), name)
        return output, records

    def test_watch_and_handoff_state_written_by_main_go_to_operator(self):
        """O11 ②: main's own state files under the bound live root (watch sidecar, completion handoff record)."""
        output, records = self._watch_with_handoff()
        handed = {identity: (uid, gid) for identity, uid, gid in records}
        for name in (".ztp-monitor-watch-state.json", ".ztp-completion-handoff.json"):
            self.assertEqual((1001, 2001), handed.get(identity_of(output / name)), name)

    def test_docker_supervisor_monitor_keeps_v311_behaviour(self):
        """Owner 2026-11-02 (Docker must not regress) and the http dev 2026-11-09 addendum: in the container the
        monitor neither refuses nor chowns and keeps the v3.1.1 --identity default (none)."""
        container = {"HTTP_ZTP_RUNTIME_BACKEND": "supervisor"}
        unknown = 4242   # a host uid the container's passwd does not know
        with self.subTest("native contrast: the same owner is refused on the host"):
            rc, seen, *_ = self._run_main([], euid=0, environ={}, owner_uid=unknown)
            self.assertEqual((2, []), (rc, seen))
        for label, euid, owner in (("root, owner unknown in passwd", 0, unknown), ("root for U", 0, 1001),
                                   ("another user", 1002, 1001)):
            with self.subTest(label):
                rc, seen, resolve, out, err, _bound = self._run_main(
                    [], euid=euid, environ={}, owner_uid=owner, process_environment=container)
                self.assertEqual(0, rc, err)
                self.assertEqual([{"identity": None, "operator": None}], seen)
                self.assertEqual([], resolve.call_args_list, "no identity step in the container")
                self.assertNotIn("操作员：", out)
        with self.subTest("no hand-over of state files"):
            _output, records = self._watch_with_handoff(container)
            self.assertEqual([], records)


def infra_tree(base):
    """A tree whose infra/logs is setup's managed link through DAY0-Prepare/activate-project (R-016 §2)."""
    root = Path(base).resolve() / "http"
    infra = root / "infra"
    infra.mkdir(parents=True)
    project = root / "DAY0-Prepare/u-project"
    (project / "99-output-infra").mkdir(parents=True)
    pointer = root / "DAY0-Prepare/activate-project"
    pointer.symlink_to(project.name)
    (infra / "logs").symlink_to(os.path.relpath(pointer / "99-output-infra", infra))
    return infra, project


class InfraLogOwnerTests(unittest.TestCase):
    def test_deploy_infra_project_log_handed_to_operator_under_root(self):
        """问题文档 :294 (scheme item 4), O11 ②: root's deploy_infra log in the project belongs to the operator."""
        for label, acting, expected in (("root via sudo by U", True, [(1001, 2001)]),
                                        ("the operator itself", False, [])):
            with self.subTest(label), tempfile.TemporaryDirectory(prefix="wp12-deploy-") as directory:
                infra, project = infra_tree(directory)
                records = []
                with ExitStack() as stack:
                    resolve = None
                    if acting:
                        resolve = stack.enter_context(acting_as(0, SUDO_U, {project: 1001}))
                        # run_with_log itself asks whether it runs as root; nothing else on its path reads euid.
                        stack.enter_context(mock.patch.object(DEPLOY.os, "geteuid", return_value=0))
                    stack.enter_context(mock.patch.object(DEPLOY, "SCRIPT_DIR", infra))
                    stack.enter_context(fchown_recorder(records))
                    stack.enter_context(redirect_stdout(io.StringIO()))
                    self.assertEqual(0, DEPLOY.run_with_log("deploy_infra", lambda: 0))
                logs = list((project / "99-output-infra").glob("deploy_infra-*.log"))
                self.assertEqual(1, len(logs))
                self.assertEqual([(identity_of(logs[0]), *owner) for owner in expected], records)
                if resolve is not None:
                    self.assertEqual([mock.call(project)], resolve.call_args_list, "the project the log link bound")

    def test_infra_setup_project_log_handed_to_dir_owner_under_root(self):
        """O11 ⑤: infra-setup hands its new log to the owner of the directory it sits in (the project's output)."""
        group = next((gid for gid in os.getgroups() if gid != os.getegid()), None)
        self.assertIsNotNone(group, "the fixture needs a second group to tell the directory's group from egid")
        for label, root in (("as root", True), ("not root", False)):
            with self.subTest(label), tempfile.TemporaryDirectory(prefix="wp12-setup-") as directory:
                infra, project = infra_tree(directory)
                output = project / "99-output-infra"
                os.chown(output, -1, group)
                options = INFRA_SETUP.parse_arguments(["--client", "--non-interactive"])
                with mock.patch.object(INFRA_SETUP, "SCRIPT_PATH", str(infra / "infra-setup.py")):
                    setup = INFRA_SETUP.InfraSetup(options)
                records = []
                with mock.patch.object(INFRA_SETUP, "is_root", return_value=root), fchown_recorder(records), \
                        redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    setup.open_log()
                os.close(setup.log_fd)
                logs = list(output.glob("infra-setup-*.log"))
                self.assertEqual(1, len(logs))
                owner = os.stat(output)
                expected = [(identity_of(logs[0]), owner.st_uid, group)] if root else []
                self.assertEqual(expected, records)

    def test_infra_setup_still_imports_no_project_tree_module(self):
        """test_infra_setup_py.py :614-631 (regression): infra-setup stays self-contained (O11 ⑤)."""
        source = (ROOT / "infra/infra-setup.py").read_text(encoding="utf-8")
        for name in ("project_contract", "operator_identity"):
            self.assertNotIn(name, source)


class DeployInfraKeyTests(unittest.TestCase):
    def test_sudo_without_key_refuses_to_generate_root_key(self):
        """问题文档 :293 (scheme item 3): under sudo with no key, never ssh-keygen for root; tell the user to drop sudo."""
        class Terminal:
            @staticmethod
            def isatty():
                return True

        for label, environ, generates in (("sudo by U", SUDO_U, False), ("root login", {}, True)):
            with self.subTest(label), tempfile.TemporaryDirectory(prefix="wp12-key-") as directory:
                home = Path(directory) / "root-home"
                home.mkdir()
                base = {name: value for name, value in os.environ.items() if not name.startswith("SUDO_")}
                with mock.patch.dict(os.environ, {**base, "HOME": str(home), **environ}, clear=True), \
                        mock.patch.object(DEPLOY.os, "geteuid", return_value=0), \
                        mock.patch.object(DEPLOY.sys, "stdin", Terminal()), \
                        mock.patch("builtins.input", return_value="y") as asked, \
                        mock.patch.object(DEPLOY.subprocess, "run") as run:
                    if generates:
                        DEPLOY.ensure_public_key(None)
                    else:
                        with self.assertRaises(DEPLOY.DeployError) as raised:
                            DEPLOY.ensure_public_key(None)
                if generates:
                    self.assertEqual("ssh-keygen", run.call_args.args[0][0], "root's own login keeps today's offer")
                else:
                    run.assert_not_called()
                    asked.assert_not_called()
                    self.assertIn("不加 sudo", str(raised.exception))
                    self.assertFalse((home / ".ssh").exists())


class DiagnosticsDefaultsTests(unittest.TestCase):
    def _tree(self):
        directory = tempfile.TemporaryDirectory(prefix="wp12-diagnostics-")
        self.addCleanup(directory.cleanup)
        root = Path(directory.name).resolve()
        project = root / "DAY0-Prepare/u-project"
        project.mkdir(parents=True)
        (root / "DAY0-Prepare/activate-project").symlink_to(project.name)
        return root, project

    def test_known_hosts_and_identity_default_to_operator_home(self):
        """问题文档 :291 (scheme item 1): read the operator's ~/.ssh; with root as the operator (way B) as before."""
        root, project = self._tree()
        cases = (
            ("sudo by U", 0, SUDO_U, 1001, [], ("/home/opuser/.ssh/known_hosts", "/home/opuser/.ssh/id_ed25519")),
            ("root login for U", 0, {}, 1001, [], ("/home/opuser/.ssh/known_hosts", "/home/opuser/.ssh/id_ed25519")),
            ("explicit values win", 0, SUDO_U, 1001, ["--known-hosts", "/srv/kh", "--identity", "/srv/id"],
             ("/srv/kh", "/srv/id")),
            ("root's project (way B)", 0, {}, 0, [], ("/root/.ssh/known_hosts", None)),
        )
        for label, euid, environ, owner, extra, expected in cases:
            with self.subTest(label):
                stdout = io.StringIO()
                with acting_as(euid, environ, {project: owner}) as resolve, \
                        mock.patch.object(COLLECTOR, "ROOT", root), redirect_stdout(stdout), \
                        redirect_stderr(io.StringIO()):
                    args = COLLECTOR.parse_args(["-p", project.name, *extra])
                self.assertEqual(expected, (args.known_hosts, args.identity))
                self.assertEqual([mock.call(project)], resolve.call_args_list, "the operator owns the active project")
                self.assertIn("操作员：", stdout.getvalue(), "one identity line")

    def test_docker_supervisor_collector_keeps_v311_defaults(self):
        """Owner 2026-11-02 (Docker must not regress) and the http dev 2026-11-09 addendum: inside the container the
        defaults stay /root/.ssh/known_hosts and no identity, with no identity step and no extra line."""
        root, project = self._tree()
        stdout, stderr = io.StringIO(), io.StringIO()
        base = {name: value for name, value in os.environ.items() if name != "HTTP_ZTP_RUNTIME_BACKEND"}
        with acting_as(0, {}, {project: 4242}) as resolve, \
                mock.patch.dict(os.environ, {**base, "HTTP_ZTP_RUNTIME_BACKEND": "supervisor"}, clear=True), \
                mock.patch.object(COLLECTOR, "ROOT", root), redirect_stdout(stdout), redirect_stderr(stderr):
            args = COLLECTOR.parse_args(["-p", project.name])
        self.assertEqual(("/root/.ssh/known_hosts", None), (args.known_hosts, args.identity))
        self.assertEqual([], resolve.call_args_list)
        self.assertEqual(("", ""), (stdout.getvalue(), stderr.getvalue()))

    def test_without_pyyaml_the_collector_starts_with_its_old_defaults(self):
        """Brief addendum (precheck P8-2, http dev 2026-11-08): no PyYAML -> it still starts, the v3.1.1 defaults
        stay, and one line says why."""
        root, project = self._tree()
        stderr = io.StringIO()
        with mock.patch.dict(sys.modules, {"yaml": None}):
            sys.modules.pop("project_contract", None)
            collector = load_script("operator_peripheral_collector_without_yaml", ROOT / "tools/collect-ztp-diagnostics.py")
            with mock.patch.object(collector, "ROOT", root), redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                args = collector.parse_args(["-p", project.name])
        self.assertEqual(("/root/.ssh/known_hosts", None), (args.known_hosts, args.identity))
        hint = [line for line in stderr.getvalue().splitlines() if "yaml" in line]
        self.assertEqual(1, len(hint), stderr.getvalue())
        self.assertIn("--known-hosts", hint[0])


class DepsHintTests(unittest.TestCase):
    def test_root_home_hint_names_operator_and_keeps_home_word(self):
        """问题文档 :254-258 (way A: load under sudo, cron.sh without): the hint names the worker's root venv and the
        operator's own venv, no longer "the user who runs 11-load.py"; it keeps HOME (test_deps_table)."""
        with mock.patch.dict(os.environ, {"HOME": "/home/opuser"}), \
                mock.patch.object(DEPS.os, "geteuid", return_value=0), \
                mock.patch.object(DEPS.pwd, "getpwuid", return_value=ROOT_ENTRY):
            message = DEPS.root_home_problem()
        self.assertIn("HOME", message)
        self.assertNotIn("the user who runs 11-load.py", message)
        self.assertIn("operator", message)
        self.assertIn("worker", message)


if __name__ == "__main__":
    unittest.main()
