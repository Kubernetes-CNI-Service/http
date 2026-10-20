"""Manual shell-to-Python contract: no deployment, history or file-lock gates.

Expected results are explicit. Only SSH/device IO is simulated; the real CLI,
input binding, prepare, component executor, observer and status writer run.
"""
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import socket
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_upgrade_cli as fixtures
import ibsw_upgrade_inputs as inputs
import ibsw_upgrade_executor as executor
import ibsw_upgrade_schedule as schedule
from ibsw_upgrade_contract import ComponentDispatchResult, SharedUpgradeHold

app, driver, observer = fixtures.app, fixtures.driver, fixtures.observer
HEALTH = (Path(__file__).resolve().parents[1] / "fixtures/nvos-system-health.txt").read_bytes()
BACKUP = b"nv set system hostname ew-spine01.example\n"
HOST = "ew-spine01.example"


class MemorySFTP:
    """Only remote file IO is fake; native upload/runner/dispatch are real."""
    def __init__(self):
        self.files = {}
        self.modes = {"/home": stat.S_IFDIR|0o755, "/home/admin": stat.S_IFDIR|0o700}

    def lstat(self, path):
        if path not in self.modes:
            raise FileNotFoundError(path)
        return SimpleNamespace(st_mode=self.modes[path], st_uid=1000, st_gid=1000,
                               st_size=len(self.files.get(path,b"")), st_mtime=1)

    def mkdir(self, path, mode):
        if path in self.modes:
            raise FileExistsError(path)
        self.modes[path] = stat.S_IFDIR|mode

    def chmod(self, path, mode):
        self.modes[path] = stat.S_IFMT(self.modes[path])|mode

    def open(self, path, mode):
        owner = self
        if "x" in mode:
            if path in self.modes:
                raise FileExistsError(path)
            self.modes[path], self.files[path] = stat.S_IFREG|0o600, b""
        if path not in self.files:
            raise FileNotFoundError(path)
        class Handle(io.BytesIO):
            def __init__(self):
                super().__init__(owner.files[path])
            def stat(self):
                self.flush()
                return owner.lstat(path)
            def flush(self):
                owner.files[path]=self.getvalue()
            def close(self):
                if not self.closed:
                    self.flush()
                super().close()
        return Handle()

    def get_channel(self):
        return SimpleNamespace(settimeout=lambda value: None)

    def close(self):
        pass

    def rename(self,old,new):
        if new in self.modes:
            raise FileExistsError(new)
        self.posix_rename(old,new)

    def posix_rename(self,old,new):
        self.files[new]=self.files.pop(old)
        self.modes[new]=self.modes.pop(old)


class ManualTests(unittest.TestCase):
    def fixture(self, root, *, debris=False):
        project, home, known = fixtures.WorkflowTests().fixture(root)
        logs = project / "99-output-ib_nvl/bringup/xdr-upgrade-logs"
        logs.mkdir(parents=True)
        if debris:
            (logs / ".gitkeep").write_text("repository placeholder\n")
            (logs / ".request-inventory.lock").write_bytes(b"obsolete-lock-not-a-gate\n")
            (logs / ".git").mkdir()
            (logs / "operator-notes.txt").write_text("keep my notes\n")
            old = logs / ("run-" + "1" * 32)
            old.mkdir(mode=0o700)
            (old / "os-status.json").write_text('{"state":"UNKNOWN","manual_required":true}\n')
            # No earlier run needs to be valid or parseable for a NEW manual run.
            (old / "plan.json").write_text("old-format-not-json\n")
        return project, home, known, logs

    @contextlib.contextmanager
    def no_deployment_or_filesystem_locks(self):
        with patch.object(driver, "_RequestNamespaceLease", side_effect=AssertionError("No file lock")), \
             patch.object(driver.fcntl, "flock", side_effect=AssertionError("No flock")), \
             patch.object(driver._PreparedRunScope, "_inventory_requests_locked", side_effect=AssertionError("No old-run scan")), \
             patch.object(inputs, "require_project_eligible", side_effect=AssertionError("No load/restore/sync gate")), \
             patch.object(driver, "open_managed_inputs", side_effect=AssertionError("No setup manifest")), \
             patch.object(socket, "socket", side_effect=AssertionError("No real network in tests")):
            yield

    def arguments(self, project):
        return ("--project", str(project), "--standalone-inputs", "--os-only", "--method", "local", "--yes")

    def test_cli_explicit_project_also_selects_standalone_inputs(self):
        parsed = app._parse_cli(("--project", "/inputs/project", "--os-only"))
        self.assertIn("--standalone-inputs", app._local_input_arguments(parsed, "/work"))

    def test_new_manual_prepare_never_creates_or_checks_a_lock(self):
        with tempfile.TemporaryDirectory() as folder:
            project, home, known, logs = self.fixture(Path(folder).resolve())
            with self.no_deployment_or_filesystem_locks():
                prepared = driver.prepare_manual_run(app.__file__, str(project), self.arguments(project))
                with driver.open_manual_run(app.__file__, str(project), self.arguments(project), prepared["run_directory"]) as scope:
                    self.assertTrue(scope.manual_execution)
                    scope.verify()
            self.assertFalse((logs / ".request-inventory.lock").exists())
            self.assertEqual(set(Path(prepared["run_directory"]).iterdir()), {
                Path(prepared["run_directory"]) / name for name in
                ("plan.json", "evidence.json", "input-inventory.csv", "input-global.yaml")})

    def test_gitkeep_invalid_old_lock_and_unknown_history_do_not_block_or_change(self):
        with tempfile.TemporaryDirectory() as folder:
            project, home, known, logs = self.fixture(Path(folder).resolve(), debris=True)
            originals = {p: p.read_bytes() for p in logs.rglob("*") if p.is_file()}
            with self.no_deployment_or_filesystem_locks():
                prepared = driver.prepare_manual_run(app.__file__, str(project), self.arguments(project))
                with driver.open_manual_run(app.__file__, str(project), self.arguments(project), prepared["run_directory"]) as scope:
                    scope.enable_cooperative_status_snapshots()
                    scope.initialize_native_component_status_data()
                    path = scope.prepare_requested_step(HOST, "os", 1)
                    scope.request_prepared_step(HOST, "os", 1)
                    self.assertTrue((Path(path) / "request.json").is_file())
            self.assertEqual({p: p.read_bytes() for p in originals}, originals)

    def test_current_run_request_is_not_automatically_dispatched_twice(self):
        with tempfile.TemporaryDirectory() as folder:
            project, home, known, logs = self.fixture(Path(folder).resolve())
            with self.no_deployment_or_filesystem_locks():
                prepared = driver.prepare_manual_run(app.__file__, str(project), self.arguments(project))
                with driver.open_manual_run(app.__file__, str(project), self.arguments(project), prepared["run_directory"]) as scope:
                    scope.prepare_requested_step(HOST, "os", 1)
                    scope.request_prepared_step(HOST, "os", 1)
                    with self.assertRaisesRegex(driver.PreparationHold, "automatic resend forbidden"):
                        scope.request_prepared_step(HOST, "os", 1)

    def test_manual_bound_input_change_still_stops_before_any_device_write(self):
        with tempfile.TemporaryDirectory() as folder:
            project, home, known, logs = self.fixture(Path(folder).resolve())
            with self.no_deployment_or_filesystem_locks():
                prepared = driver.prepare_manual_run(app.__file__, str(project), self.arguments(project))
                with self.assertRaises(ValueError):
                    with driver.open_manual_run(app.__file__, str(project), self.arguments(project), prepared["run_directory"]) as scope:
                        with (project / "01-global.yaml").open("a") as handle:
                            handle.write("\n# changed during operation\n")
                        scope.verify()

    def test_manual_scopes_serialize_only_in_process_status_updates(self):
        from concurrent.futures import ThreadPoolExecutor
        with tempfile.TemporaryDirectory() as folder:
            project, home, known, logs = self.fixture(Path(folder).resolve())
            with self.no_deployment_or_filesystem_locks(), contextlib.ExitStack() as stack:
                args = self.arguments(project)
                prepared = driver.prepare_manual_run(app.__file__, str(project), args)
                scopes = [stack.enter_context(driver.open_manual_run(app.__file__, str(project), args, prepared["run_directory"])) for _ in range(3)]
                for scope in scopes:
                    scope.enable_cooperative_status_snapshots()
                scopes[0].initialize_native_component_status_data()
                def update(scope, host):
                    scope._record_native_component_failure("os", host, "UNKNOWN", "SIMULATED_IN_FLIGHT_FAILURE")
                with ThreadPoolExecutor(max_workers=2) as pool:
                    jobs = [pool.submit(update, scopes[i+1], host) for i, host in enumerate((HOST,"ew-spine02.example"))]
                    for job in jobs:
                        job.result(timeout=5)
                doc = scopes[0].read_component_status_data("os")
                self.assertEqual([r["state"] for r in doc["targets"]], ["UNKNOWN", "UNKNOWN"])
                self.assertEqual(doc["revision"], 2)

    def test_manual_cli_no_change_needs_no_load_git_lock_or_redundant_executor(self):
        queries = []
        @contextlib.contextmanager
        def session(leaf, **kwargs):
            identity = (leaf.node.hostname + "\n" + leaf.node.mac + "\n").encode()
            yield object(), 99999999999, (identity,b"",0,True), "password", "synthetic-pin"
        def query(leaf, transport, command, deadline):
            queries.append(command)
            answers = {"nv show system version": fixtures.OS_TABLE,
                       'id -u; getent passwd "$(id -u)"':b'1000\nadmin:x:1000:1000:Admin:/home/admin:/bin/bash\n',
                       "nv show platform firmware": b"not selected in OS-only inspection",
                       "hostname; cat /sys/class/net/eth0/address": (leaf.node.hostname+"\n"+leaf.node.mac+"\n").encode(),
                       "nv config show -o commands": BACKUP,
                       "nv config diff -o commands": b"",
                       "nv show system health": HEALTH}
            self.assertIn(command, answers, "A no-upgrade-needed device must not receive a write command")
            return answers[command], b"", 0, True
        with tempfile.TemporaryDirectory() as folder:
            project, home, known, logs = self.fixture(Path(folder).resolve(), debris=True)
            from test_access_recovery import access_fixture
            _remote,sdk=access_fixture(home)
            with self.no_deployment_or_filesystem_locks(), \
                 patch.object(observer,'_fixed_sdk',return_value=sdk) as sdk_io, \
                 patch.object(executor,'_fixed_sdk',sdk_io), \
                 patch.object(observer, "_signed_session", side_effect=session) as session_io, \
                 patch.object(executor, "_signed_session", session_io), \
                 patch.object(observer, "_read_channel", side_effect=query) as read_io, \
                 patch.object(executor, "_read_channel", read_io):
                self.assertIs(observer._fixed_sdk, executor._fixed_sdk)
                self.assertIs(observer._signed_session, executor._signed_session)
                self.assertIs(observer._read_channel, executor._read_channel)
                code, out, err, prompts = fixtures.WorkflowTests().invoke(project, home,
                    "--devices", HOST, "--method", "http", "--upgrade", "--yes")
            self.assertEqual(code, 0, err + out)
            report = json.loads(out)
            self.assertEqual(report["state"], "UPGRADE_NO_CHANGE")
            self.assertEqual(report["components"][0]["targets"],[])
            self.assertEqual(report["components"][0]["no_change"][0]["action"],"AT_TARGET_PREFLIGHT")
            self.assertEqual(report["targets"], [{"hostname": HOST, "state": "NO_CHANGE"}])
            current = Path(report["run_directory"])
            self.assertFalse((current / HOST / "os-0001/component-completion.json").exists())
            self.assertFalse((current / HOST / "os-0001/request.json").exists())
            self.assertNotIn("nv config show -o commands", queries)
            self.assertEqual(queries.count("nv show system health"),1)
            self.assertEqual(report['health_summary']['counts']['PASS'],1)
            self.assertNotIn("PreparationHold", err)

    def test_pre_dispatch_failure_is_reported_without_false_inflight_unknown(self):
        @contextlib.contextmanager
        def session(leaf, **kwargs):
            identity = (leaf.node.hostname+"\n"+leaf.node.mac+"\n").encode()
            yield object(), 99999999999, (identity,b"",0,True), "password", "synthetic-pin"
        with tempfile.TemporaryDirectory() as folder:
            project, home, known, logs = self.fixture(Path(folder).resolve())
            from test_access_recovery import access_fixture
            _remote,sdk=access_fixture(home)
            def query(leaf, transport, command, deadline):
                if command=='id -u; getent passwd "$(id -u)"':
                    return b'1000\nadmin:x:1000:1000:Admin:/home/admin:/bin/bash\n',b'',0,True
                if command=='nv show system health': return HEALTH,b'',0,True
                # This scenario exercises a real upgrade candidate, not the
                # 2.13 no-change queue exclusion. The failure assertions stay.
                return fixtures.OS_TABLE.replace(b'25.03.1010',b'25.02.8008'),b'',0,True
            dispatch_failure = observer._NativeObservationHold(reason_code="SSH_CONNECT_FAILED")
            with self.no_deployment_or_filesystem_locks(), \
                 patch.object(observer,'_fixed_sdk',return_value=sdk) as sdk_io, \
                 patch.object(executor,'_fixed_sdk',sdk_io), \
                 patch.object(observer,"_signed_session",session), \
                 patch.object(observer,"_read_channel",side_effect=query) as read_io, \
                 patch.object(executor,"_read_channel",read_io), \
                 patch.object(executor,"_signed_session",side_effect=dispatch_failure):
                self.assertIs(observer._fixed_sdk, executor._fixed_sdk)
                self.assertIs(observer._read_channel, executor._read_channel)
                self.assertIs(observer._signed_session, session)
                self.assertIsNot(observer._signed_session, executor._signed_session)
                self.assertIs(executor._signed_session.side_effect, dispatch_failure)
                code, out, err, prompts = fixtures.WorkflowTests().invoke(project, home,
                    "--devices", HOST, "--method", "http", "--upgrade", "--yes")
            self.assertEqual(code, 3, err + out)
            report=json.loads(out)
            self.assertEqual(report["execution_state"], "NOT_EXECUTED")
            self.assertEqual(report["targets"][0]["state"], "NOT_EXECUTED")
            status=json.loads((Path(report["run_directory"])/"os-status.json").read_text())
            self.assertFalse(status["targets"][0]["manual_required"])
            self.assertIn("SSH_CONNECT_FAILED",status["targets"][0]["reason"])
            self.assertIn("SSH_CONNECT_FAILED",err)

    def test_needed_http_upgrade_reaches_real_native_upload_and_single_dispatch(self):
        channels, remote = [], MemorySFTP()
        @contextlib.contextmanager
        def session(leaf, **kwargs):
            identity=(leaf.node.hostname+"\n"+leaf.node.mac+"\n").encode()
            yield SimpleNamespace(close=lambda: None),99999999999,(identity,b"",0,True),"password","synthetic-pin"
        def query(leaf, transport, command, deadline):
            channels.append(command)
            if command.startswith("/usr/bin/nohup "):
                self.assertTrue((leaf.scope.run_directory/HOST/"os-0001/request.json").is_file())
                return b"IBSW_LAUNCH_REQUESTED\n",b"",0,True
            answers={"nv show system version": fixtures.OS_TABLE.replace(b"25.03.1010",b"25.02.8008"),
                     "hostname; cat /sys/class/net/eth0/address": (leaf.node.hostname+"\n"+leaf.node.mac+"\n").encode(),
                     "nv config show -o commands": BACKUP,
                     "nv config diff -o commands": b"", "nv show system health": HEALTH,
                     "id -u": b"1000\n", executor._CAPABILITY_COMMAND: b""}
            self.assertIn(command,answers)
            return answers[command],b"",0,True
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve()
            project,home,known,logs=self.fixture(root,debris=True)
            package_root=root/"packages"
            (package_root/"image").mkdir(parents=True)
            (package_root/"image/nvos-amd64-25.03.1010.bin").write_bytes(b"SYNTHETIC-IMAGE-NOT-FIRMWARE")
            global_path=project/"01-global.yaml"
            text=fixtures.GLOBAL.replace("        os:\n", "        os:\n          sub_dir: image\n")
            text=text.replace('http_root: /var/www/html','http_root: '+str(package_root))
            global_path.write_text(text)
            args=("--project",str(project),"--os-only","--method","http","--package-dir",str(package_root),"--yes")
            with self.no_deployment_or_filesystem_locks(), \
                 patch.object(executor,"_signed_session",session), \
                 patch.object(observer,"_read_channel",side_effect=query), \
                 patch.object(executor,"_read_channel",side_effect=query), \
                 patch.object(executor,"_fixed_sdk",return_value=SimpleNamespace(SFTPClient=SimpleNamespace(from_transport=lambda t:remote))):
                prepared=driver.prepare_manual_run(app.__file__,str(project),args)
                with driver.open_manual_run(app.__file__,str(project),args,prepared["run_directory"]) as scope:
                    with scope.open_readonly_query_inputs(HOST,known_hosts_path=str(known),identity_path=None,management_public_path=None,user="admin") as leaf:
                        dispatch=leaf.execute_component_once("os",password="SYNTHETIC-PASSWORD")
                        self.assertEqual(dispatch.state,"DISPATCHED_UNKNOWN")
                        self.assertEqual(dispatch.target_version,"25.03.1010")
                        self.assertTrue(scope.component_attempt_may_have_started(HOST,"os"))
                        with self.assertRaisesRegex(ValueError,"never retry"):
                            leaf.execute_component_once("os",password="SYNTHETIC-PASSWORD")
            stage=Path(prepared["run_directory"])/HOST/"os-0001"
            self.assertEqual((stage/"before.commands").read_bytes(),BACKUP)
            self.assertTrue((stage/"component-dispatch.json").is_file())
            self.assertEqual(len([c for c in channels if c.startswith("/usr/bin/nohup ")]),1)
            script=next(value for name,value in remote.files.items() if name.endswith("/step.sh"))
            self.assertIn(b"http://192.0.2.254:8088/image/nvos-amd64-25.03.1010.bin",script)
            self.assertIn(b"nv action fetch system image",script)
            self.assertIn(b"nv action install system image",script)
            self.assertNotIn(b"SYNTHETIC-PASSWORD",script)

    def test_safe_failure_reason_does_not_echo_exception_payload(self):
        reason=schedule._native_failure_reason(ValueError("PASSWORD-AND-PRIVATE-CONFIG"))
        self.assertEqual(reason,"ValueError")

    def test_existing_current_run_request_keeps_failure_unknown_and_never_resends(self):
        with tempfile.TemporaryDirectory() as folder:
            project,home,known,logs=self.fixture(Path(folder).resolve())
            args=self.arguments(project)
            with self.no_deployment_or_filesystem_locks():
                prepared=driver.prepare_manual_run(app.__file__,str(project),args)
                with driver.open_manual_run(app.__file__,str(project),args,prepared["run_directory"]) as scope:
                    scope.enable_cooperative_status_snapshots()
                    scope.initialize_native_component_status_data()
                    scope._native_schedule_started=True
                    scope.prepare_requested_step(HOST,"os",1)
                    scope.request_prepared_step(HOST,"os",1)
                    with patch.object(executor,"_execute_component_once",side_effect=ValueError("PRIVATE-ERROR")) as dispatch:
                        report=schedule.run_upgrade_component(scope,HOST,"os",known_hosts_path=str(known),
                            identity_path=None,management_public_path=None,user="admin",password="PRIVATE")
                    self.assertEqual(dispatch.call_count,1)
                    self.assertEqual(report["state"],"UNKNOWN")
                    self.assertNotIn("PRIVATE",report["reason"])
                    row=scope.read_component_status_data("os")["targets"][0]
                    self.assertEqual(row["state"],"UNKNOWN")
                    self.assertTrue(row["manual_required"])

    def test_no_argument_cwd_project_links_ignore_deployment_controls_and_old_lock(self):
        @contextlib.contextmanager
        def session(leaf,**kwargs):
            identity=(leaf.node.hostname+"\n"+leaf.node.mac+"\n").encode()
            yield object(),99999999999,(identity,b"",0,True),"password","synthetic-pin"
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve()
            (root/"DAY0-Prepare").mkdir()
            project,home,known,logs=self.fixture(root/"DAY0-Prepare",debris=True)
            known.write_text(known.read_text()+known.read_text().replace("192.0.2.1 ","192.0.2.2 "))
            (root/".sync-code-in-progress").write_text("not a prerequisite for manual upgrade\n")
            entry=root/"infiniband/bringup/xdr-upgrade"
            entry.mkdir(parents=True)
            (entry/"ib.csv").symlink_to(project/"02-devices_config.csv")
            (entry/"01-global.yaml").symlink_to(project/"01-global.yaml")
            (entry/"xdr-upgrade-logs").symlink_to(logs,target_is_directory=True)
            out,err=io.StringIO(),io.StringIO()
            with self.no_deployment_or_filesystem_locks(), \
                 patch.object(app,"__file__",str(entry/"upgrade.py")), \
                 patch.object(app,"_fixed_driver",return_value=driver), \
                 patch.object(app.os,"getcwd",return_value=str(entry)), \
                 patch.object(Path,"home",return_value=home), \
                 patch.object(app,"_check_runtime"),patch.object(app,"_read_password",return_value="PRIVATE"), \
                 patch.object(observer,"_signed_session",session), \
                 patch.object(observer,"_read_channel",return_value=(fixtures.OS_TABLE,b"",0,True)), \
                 contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
                code=app.main(["--os-only"])
            self.assertEqual(code,0,err.getvalue()+out.getvalue())
            self.assertEqual(json.loads(out.getvalue())["ready_ib_count"],2)
            self.assertEqual((logs/".request-inventory.lock").read_bytes(),b"obsolete-lock-not-a-gate\n")


if __name__ == "__main__":
    unittest.main()
