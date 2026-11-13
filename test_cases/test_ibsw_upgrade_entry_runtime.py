"""WP-A2 entry/runtime contract: independent literal expectations from r511 a–m.

No switch transport, runtime guard file, real operator exec or private input is used.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "infiniband/bringup/xdr-upgrade/upgrade2.py"
sys.path.insert(0, str(ROOT / "tools"))


def load_entry():
    spec = importlib.util.spec_from_file_location("a2_entry_contract", ENTRY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class EntryRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.entry = load_entry()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.project = Path(self.tmp.name) / "project"
        self.project.mkdir()

    def invoke(self, argv):
        out = io.StringIO()
        with mock.patch.object(self.entry, "_ask", side_effect=AssertionError("unexpected password")), \
                mock.patch("subprocess.run", side_effect=AssertionError("unexpected subprocess")):
            try:
                code = self.entry.run(argv, out=out)
            except Exception as error:
                self.fail("input rejection must return 2, not " + type(error).__name__)
        return code, out.getvalue()

    def without_yaml_child(self, mode, argv):
        # This is a real interpreter with site disabled, not a fake entry/parser.
        # The import hook makes absent PyYAML deterministic on any developer host.
        launcher = '''import importlib.util,runpy,sys
class NoYaml:
    def find_spec(self,fullname,path=None,target=None):
        if fullname.split('.')[0]=='yaml':
            raise ModuleNotFoundError('PyYAML intentionally unavailable',name=fullname)
sys.meta_path.insert(0,NoYaml())
def deny_external_effect(event,args):
    if event in ('subprocess.Popen','socket.connect','os.exec','os.system'):
        raise AssertionError('unexpected child external effect: '+event)
sys.addaudithook(deny_external_effect)
entry,mode,*arguments=sys.argv[1:]
sys.argv=[entry,*arguments]
if mode=='main':
    runpy.run_path(entry,run_name='__main__')
else:
    spec=importlib.util.spec_from_file_location('owned_no_yaml_entry',entry)
    app=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app)
    raise SystemExit(app.run(arguments))
'''
        work = self.project / ('child-' + mode + '-' + str(len(list(self.project.iterdir()))))
        work.mkdir()
        home = work / 'home'
        home.mkdir()
        environment = {name: os.environ[name] for name in ('TMPDIR', 'HTTP_TEST_OWNED_ROOT')}
        environment.update(HOME=str(home), PATH='/usr/bin:/bin:/usr/sbin:/sbin', LANG='en_US.UTF-8')
        return subprocess.run([sys.executable, '-S', '-B', '-c', launcher, str(ENTRY), mode, *argv],
                              cwd=work, env=environment, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=15)

    def test_help_and_short_help_need_no_yaml_before_argparse(self):
        for mode in ('main', 'run'):
            for option in ('--help', '-h'):
                with self.subTest(mode=mode, option=option):
                    done = self.without_yaml_child(mode, [option])
                    self.assertEqual(done.returncode, 0, done.stderr)
                    for literal in ('usage: upgrade2.py', '--project', '--plan', '--upgrade'):
                        self.assertTrue(literal in done.stdout, 'missing literal help field: ' + literal)
                    self.assertNotIn('Traceback', done.stderr)

    def test_version_needs_no_yaml_before_argparse(self):
        for mode in ('main', 'run'):
            with self.subTest(mode=mode):
                done = self.without_yaml_child(mode, ['--version'])
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertEqual(done.stdout, 'ibsw-upgrade-v2 2026-10-23\n')
                self.assertEqual(done.stderr, '')

    def test_direct_argument_validation_needs_no_yaml_or_project(self):
        # main's old default-pointer bootstrap is RV99-B, not changed here.
        done = self.without_yaml_child('run', ['--upgrade'])
        self.assertEqual(done.returncode, 2, done.stderr)
        self.assertIn('ERROR: --upgrade needs --yes', done.stderr)
        self.assertNotIn('Traceback', done.stderr)

    def test_real_invalid_pointer_stays_a_friendly_input_error(self):
        repository = self.project / 'repository'
        day0 = repository / 'DAY0-Prepare'
        day0.mkdir(parents=True)
        (day0 / 'activate-project').write_text('not a symlink\n')
        with mock.patch.object(self.entry, 'REPOSITORY', repository):
            code, text = self.invoke([])
        self.assertEqual(code, 2)
        self.assertIn('ERROR: DAY0-Prepare/activate-project is not a link:', text)
        self.assertNotIn('Traceback', text)
        self.assertEqual(sorted(path.name for path in day0.iterdir()), ['activate-project'])

    def test_no_active_project_fails_before_inputs(self):
        # O-A2-2/e: direct run(), not only main(), resolves the active pointer.
        import project_contract
        with mock.patch.object(project_contract, "active_project_dir", return_value=None) as active:
            code, text = self.invoke([])
        self.assertEqual(code, 2)
        self.assertIn("no active project", text.lower())
        active.assert_called_once_with(self.entry.REPOSITORY)
        self.assertEqual(list(self.project.iterdir()), [])

    def test_bad_pointer_is_a_friendly_input_error(self):
        import project_contract
        with mock.patch.object(project_contract, "active_project_dir",
                               side_effect=project_contract.ActiveProjectPointerError("pointer is invalid")):
            code, text = self.invoke([])
        self.assertEqual(code, 2)
        self.assertIn("ERROR:", text)
        self.assertIn("pointer is invalid", text)
        self.assertNotIn("Traceback", text)

    def test_missing_project_inputs_are_friendly_before_password(self):
        code, text = self.invoke(["--project", str(self.project), "--upgrade", "-y"])
        self.assertEqual(code, 2)
        self.assertIn("ERROR:", text)
        self.assertIn(str(self.project), text)
        self.assertNotIn("Traceback", text)
        self.assertFalse((self.project / "99-output-ib_nvl").exists())

    def test_argument_validation_precedes_project_lookup(self):
        import project_contract
        with mock.patch.object(project_contract, "active_project_dir",
                               side_effect=AssertionError("validation order")):
            code, text = self.invoke(["--upgrade"])
        self.assertEqual(code, 2)
        self.assertIn("--upgrade needs --yes", text)

    def test_guard_failure_is_not_busy(self):
        # O-A2-8(a)/l: preserve original text and distinguish the two codes.
        import operator_identity
        import ib_bringup_runtime_guard as guard
        for reason, expected in (("INSTANCE_GUARD_UNAVAILABLE", 2), ("ALREADY_RUNNING", 75)):
            @contextlib.contextmanager
            def refused():
                raise guard._InstanceGuardError(reason, "synthetic guard refusal")
                yield
            with self.subTest(reason=reason), \
                    mock.patch.object(operator_identity, "skips_identity", return_value=True), \
                    mock.patch.object(guard, "_runtime_instance_guard", refused), \
                    mock.patch.object(sys, "argv", [str(ENTRY), "--project", str(self.project)]), \
                    mock.patch.dict(self.entry.__dict__, {"_reexec_in_runtime_venv": lambda *a, **k: None}), \
                    contextlib.redirect_stderr(io.StringIO()) as out:
                self.assertEqual(self.entry.main(), expected)
                self.assertIn("ERROR [" + reason + "] synthetic guard refusal", out.getvalue())

    def test_inventory_mismatch_precedes_input_parsing_and_contact(self):
        # R-016/g: real comparator, independently specified line format.
        (self.project / "02-devices_config.csv").write_text("hostname,type\nexample-ib01,ib\n")
        (self.project / "ib.csv").write_text("hostname,type\nexample-ib01,eth_jump\n")
        code, text = self.invoke(["--project", str(self.project)])
        self.assertEqual(code, 2)
        self.assertIn("INVENTORY MISMATCH: example-ib01; type; ib.csv=eth_jump; 02=ib; type-not-allowed", text)
        self.assertNotIn("global", text.lower())
        self.assertNotIn("--inventory-checked", self.entry.parser().format_help())

    def test_pointer_project_rejects_foreign_explicit_inputs(self):
        import project_contract
        foreign = self.project.parent / "foreign.csv"
        foreign.write_text("hostname,type\nexample-ib01,ib\n")
        for option in ("--ib-csv", "--global"):
            with self.subTest(option=option), mock.patch.object(project_contract, "active_project_dir",
                                                               return_value=self.project):
                code, text = self.invoke([option, str(foreign)])
                self.assertEqual(code, 2)
                self.assertIn("explicit project input cannot silently use foreign source", text)

    def test_runtime_switch_preserves_argv_and_inheritable_fd(self):
        switch = getattr(self.entry, "_reexec_in_runtime_venv", None)
        self.assertTrue(callable(switch), "WP-A2 a requires its own audited runtime switch")
        import fleet_ssh
        from importlib import metadata
        argv = ["--project", str(self.project), "--devices", "example-ib*"]
        class Switched(BaseException):
            pass
        reader, writer = os.pipe()
        self.addCleanup(os.close, reader)
        self.addCleanup(os.close, writer)
        os.set_inheritable(reader, True)
        captured = []
        def execve(path, command, environment):
            captured.append((path, command, environment, os.get_inheritable(reader)))
            raise Switched()
        def version(name):
            return "wrong" if name == "paramiko" else dict(fleet_ssh.SSH_RUNTIME_PINS).get(name, "6.0")
        with mock.patch.object(metadata, "version", side_effect=version), \
                mock.patch.object(self.entry, "_runtime_venv_candidates", return_value=(self.project / "venv",)), \
                mock.patch.object(self.entry, "_audited_runtime_venv", return_value=("/synthetic/bin/python3", "usable")), \
                mock.patch.object(os, "execve", side_effect=execve), \
                mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(sys, "argv", [str(ENTRY)]):
            with self.assertRaises(Switched):
                switch(argv)
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0][0], "/synthetic/bin/python3")
        self.assertEqual(captured[0][1][-len(argv):], argv)
        self.assertTrue(captured[0][3])
        self.assertEqual(captured[0][2]["IBSW_UPGRADE_VENV_REEXEC"], "1")

    def test_runtime_help_current_and_missing_candidate(self):
        switch = getattr(self.entry, "_reexec_in_runtime_venv", None)
        self.assertTrue(callable(switch), "WP-A2 a requires a v2 runtime switch")
        import fleet_ssh
        from importlib import metadata
        pins = dict(fleet_ssh.SSH_RUNTIME_PINS)
        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch.object(metadata, "version", side_effect=lambda name: pins.get(name, "6.0")), \
                mock.patch.object(os, "execve", side_effect=AssertionError("must stay in process")):
            self.assertEqual(switch([]), "NOT_NEEDED")
            self.assertEqual(switch(["--help"]), "NOT_NEEDED")
        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch.object(metadata, "version", side_effect=metadata.PackageNotFoundError), \
                mock.patch.object(self.entry, "_runtime_venv_candidates", return_value=(self.project / "venv",)), \
                mock.patch.object(self.entry, "_audited_runtime_venv", return_value=(None, "missing")), \
                contextlib.redirect_stderr(io.StringIO()) as out:
            self.assertEqual(switch([]), "NO_CANDIDATE")
        self.assertIn("fixed venv", out.getvalue())
        self.assertNotIn("requirements.txt", out.getvalue())

    def test_runtime_record_selection_is_shared_and_metadata_only(self):
        helper = getattr(self.entry, "_runtime_locked_files", None)
        self.assertTrue(callable(helper), "WP-A2 k selects the same runtime distributions as a")
        from importlib import metadata
        import fleet_engine as engine
        normal, missing = self.project / "runtime.py", self.project / "absent.py"
        normal.write_bytes(b"runtime fixture")
        asked = []
        expected_names = ["paramiko", "bcrypt", "cryptography", "invoke", "PyNaCl", "cffi",
                          "pycparser", "typing-extensions", "PyYAML"]
        def distribution(name):
            asked.append(name)
            if name == "PyYAML":
                return SimpleNamespace(files=None)
            return SimpleNamespace(files=[Path("runtime.py"), Path("__pycache__/runtime.pyc"), Path("absent.py")],
                                   locate_file=lambda item: self.project / item)
        out = io.StringIO()
        with mock.patch.object(metadata, "distribution", side_effect=distribution):
            locked = helper(engine.LockedFile, out)
        self.assertEqual(asked, expected_names)
        self.assertEqual({item.path for item in locked}, {str(normal)})
        self.assertEqual(len(locked), 8)
        self.assertEqual(out.getvalue(), "[LOCK] WARN PyYAML: no RECORD; its files are not locked\n")

    def test_runtime_identity_precedes_venv_and_guard(self):
        import operator_identity
        import ib_bringup_runtime_guard as guard
        calls = []
        identity = SimpleNamespace(refusal=None, banner="synthetic operator", operator=object())
        @contextlib.contextmanager
        def runtime_guard():
            calls.append("guard")
            yield
        def runtime(_argv):
            calls.append("venv")
            return "NOT_NEEDED"
        with mock.patch.object(operator_identity, "skips_identity", return_value=False), \
                mock.patch.object(operator_identity, "resolve_operator", side_effect=lambda p: (calls.append("identity") or identity)), \
                mock.patch.object(operator_identity, "needs_reexec", return_value=False), \
                mock.patch.object(guard, "_runtime_instance_guard", runtime_guard), \
                mock.patch.dict(self.entry.__dict__, {"_reexec_in_runtime_venv": runtime}), \
                mock.patch.object(self.entry, "run", return_value=0), \
                mock.patch.object(sys, "argv", [str(ENTRY), "--project", str(self.project)]), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(self.entry.main(), 0)
        self.assertEqual(calls, ["identity", "venv", "guard"])

    def test_fixed_venv_audit_uses_own_pins_and_rejects_unsafe_layout(self):
        # O-A2-5/a: real metadata audit, not the v1 sibling requirements file.
        home = self.project / "operator-home"
        venv = home / ".venvs/http/ibsw-upgrade"
        site = venv / "lib/python3.9/site-packages"
        site.mkdir(parents=True)
        (venv / "bin").mkdir()
        (venv / "pyvenv.cfg").write_text("home = /usr/bin\n")
        python = venv / "bin/python3"
        python.write_text("#!/bin/sh\nexit 0\n")
        python.chmod(0o755)
        versions = (("paramiko", "5.0.0"), ("bcrypt", "5.0.0"), ("cryptography", "50.0.1"),
                    ("invoke", "2.2.1"), ("PyNaCl", "1.6.2"), ("cffi", "2.0.0"),
                    ("pycparser", "2.23"), ("typing-extensions", "4.16.0"), ("PyYAML", "6.0.2"))
        for name, version in versions:
            info = site / (name.replace("-", "_") + "-" + version + ".dist-info")
            info.mkdir()
            (info / "METADATA").write_text("Metadata-Version: 2.1\nName: " + name + "\nVersion: " + version + "\n")
        with mock.patch.dict(os.environ, {"HOME": str(home)}):
            self.assertEqual(self.entry._audited_runtime_venv(venv), (str(python), "usable"))
            site.chmod(0o777)
            self.assertIsNone(self.entry._audited_runtime_venv(venv)[0])
            site.chmod(0o755)
            config = venv / "pyvenv.cfg"
            config.unlink()
            config.symlink_to(home / "missing-config")
            self.assertIsNone(self.entry._audited_runtime_venv(venv)[0])
            config.unlink()
            config.write_text("home = /usr/bin\n")
            metadata_file = site / "paramiko-5.0.0.dist-info/METADATA"
            metadata_file.write_text("Metadata-Version: 2.1\nName: paramiko\nVersion: 4.0.0\n")
            self.assertIsNone(self.entry._audited_runtime_venv(venv)[0])

    def test_missing_runtime_stops_main_before_guard(self):
        import operator_identity
        import ib_bringup_runtime_guard as guard
        with mock.patch.object(operator_identity, "skips_identity", return_value=True), \
                mock.patch.object(self.entry, "_reexec_in_runtime_venv", return_value="NO_CANDIDATE"), \
                mock.patch.object(guard, "_runtime_instance_guard", side_effect=AssertionError("guard before runtime")), \
                mock.patch.object(self.entry, "run", side_effect=AssertionError("business before runtime")), \
                mock.patch.object(sys, "argv", [str(ENTRY), "--project", str(self.project)]):
            self.assertEqual(self.entry.main(), 2)

    def test_runtime_record_unstatable_entry_is_skipped_not_batch_error(self):
        from importlib import metadata
        import fleet_engine as engine
        good, unreadable = self.project / "runtime.py", self.project / "forbidden.py"
        good.write_bytes(b"owned runtime")
        unreadable.write_bytes(b"owned runtime metadata-only")
        real_stat = os.stat
        def stat(path, *args, **kwargs):
            if Path(path) == unreadable:
                raise PermissionError(13, "Permission denied", str(unreadable))
            return real_stat(path, *args, **kwargs)
        def distribution(name):
            return SimpleNamespace(files=[Path("runtime.py"), Path("forbidden.py")] if name == "paramiko" else [],
                                   locate_file=lambda item: self.project / item)
        with mock.patch.object(metadata, "distribution", side_effect=distribution), mock.patch.object(os, "stat", stat):
            try:
                locked = self.entry._runtime_locked_files(engine.LockedFile, io.StringIO())
            except OSError:
                self.fail("unstatable runtime RECORD entry is omitted by the approved k contract")
        self.assertEqual([item.path for item in locked], [str(good)])


class EngineRuntimeTests(unittest.TestCase):
    def world(self, **kwargs):
        from test_cases import test_fleet_engine as fixture
        return fixture.World(self, ["canary", "other"], selected=("os",),
                             needs={host: {"os": [["os-2.bin"]]} for host in ("canary", "other")}, **kwargs)

    def test_optional_package_failure_is_not_whole_batch_hold(self):
        import fleet_engine as engine
        world = self.world()
        missing = world.family.by_name["os-3.bin"].path
        Path(missing).unlink()
        world.family.optional_package_paths = lambda selected: frozenset([missing])
        try:
            world.engine._load_packages()
        except engine.Hold:
            self.fail("an unreadable optional OS alternative must not hold the whole batch")
        self.assertNotIn(missing, world.engine.packages)
        self.assertIn(world.family.by_name["os-2.bin"].path, world.engine.packages)

    def test_initial_mandatory_package_hold_is_reported(self):
        import fleet_engine as engine
        world = self.world()
        Path(world.family.by_name["fw.bin"].path).unlink()
        try:
            report = world.engine.run()
        except engine.Hold:
            self.fail("initial package Hold must become a durable report and exit 2")
        self.assertIn("package unreadable:", report["hold"])
        self.assertEqual(engine.exit_code(report), 2)
        self.assertTrue((world.engine.evidence.root / "run-report.json").is_file())

    def test_canary_already_at_target_does_not_pass(self):
        world = self.world()
        original = world.ops.dispatch
        def dispatch(device, step, **kwargs):
            if device.hostname == "canary":
                return {"state": "AT_TARGET"}
            return original(device, step, **kwargs)
        world.ops.dispatch = dispatch
        results = world.run()
        self.assertEqual(results["other"][0], "BLOCKED")
        self.assertEqual(results["other"][1], "CANARY_FAILED")
        self.assertFalse(world.events("dispatch"))
        self.assertIn("CANARY_NOT_PERFORMED_AND_VERIFIED", world.out.getvalue())

    def test_locked_file_identity_change_holds_without_content(self):
        import fleet_engine as engine
        locked_type = getattr(engine, "LockedFile", None)
        self.assertTrue(callable(locked_type), "WP-A2 k requires a generic metadata-only LockedFile")
        for operation in ("replace", "touch", "chmod"):
            with self.subTest(operation=operation):
                world = self.world()
                path = world.engine.evidence.root.parent / "management.pub"
                path.write_bytes(b"synthetic-public-value-never-printed")
                world.engine.locked_inputs = (locked_type.read("management public key", path),)
                original = world.ops.dispatch
                def dispatch(device, step, **kwargs):
                    result = original(device, step, **kwargs)
                    if device.hostname == "canary":
                        if operation == "replace":
                            replacement = path.with_suffix(".new")
                            replacement.write_bytes(path.read_bytes())
                            os.replace(replacement, path)
                        elif operation == "touch":
                            info = path.stat()
                            os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns + 1000000))
                        else:
                            path.chmod(0o600)
                    return result
                world.ops.dispatch = dispatch
                results = world.run()
                self.assertEqual(results["canary"][0], "UPGRADED")
                self.assertEqual(results["other"][0], "NOT_EXECUTED")
                self.assertTrue(results["other"][1].startswith("INPUT_CHANGED: " + str(path)))
                self.assertEqual(engine.exit_code(world.report), 2)
                self.assertNotIn("synthetic-public-value", world.out.getvalue())
                self.assertNotIn("synthetic-public-value", (world.engine.evidence.root / "run-report.json").read_text())

    def test_known_hosts_watch_is_one_line_even_with_hold(self):
        import fleet_engine as engine
        locked_type = getattr(engine, "LockedFile", None)
        self.assertTrue(callable(locked_type), "WP-A2 m reuses LockedFile identity, never reads host-key bytes")
        world = self.world()
        watched = world.engine.evidence.root.parent / "known_hosts"
        watched.write_bytes(b"synthetic-public-host-key")
        world.engine.watched_inputs = (locked_type.read("known hosts", watched),)
        original = world.ops.dispatch
        def dispatch(device, step, **kwargs):
            result = original(device, step, **kwargs)
            watched.write_bytes(watched.read_bytes() + b"\n")
            return result
        world.ops.dispatch = dispatch
        results = world.run()
        self.assertEqual({value[0] for value in results.values()}, {"UPGRADED"})
        self.assertIsNone(world.report["hold"])
        expected = "[KNOWN_HOSTS] " + str(watched) + ": modified during the run; this run keeps the snapshot taken at start"
        self.assertEqual(world.out.getvalue().splitlines().count(expected), 1)
        self.assertEqual(engine.exit_code(world.report), 0)

    def test_watch_still_warns_when_locked_input_also_changes(self):
        import fleet_engine as engine
        world = self.world()
        paths = [world.engine.evidence.root.parent / name for name in ("runtime.py", "known_hosts")]
        for path in paths:
            path.write_bytes(b"synthetic")
        world.engine.locked_inputs = (engine.LockedFile.read("runtime", paths[0]),)
        world.engine.watched_inputs = (engine.LockedFile.read("known hosts", paths[1]),)
        original = world.ops.dispatch
        def dispatch(device, step, **kwargs):
            result = original(device, step, **kwargs)
            for path in paths:
                path.write_bytes(b"changed synthetic")
            return result
        world.ops.dispatch = dispatch
        world.run()
        self.assertEqual(world.report["hold"], "INPUT_CHANGED: " + str(paths[0]))
        self.assertEqual(world.out.getvalue().count("[KNOWN_HOSTS] " + str(paths[1])), 1)

    def test_multihop_canary_requires_every_hop_real_verification(self):
        from test_cases import test_fleet_engine as fixture
        for at_target in ("os-0", "os-1"):
            with self.subTest(at_target=at_target):
                world = fixture.World(self, ["canary", "other"], selected=("os",),
                                      needs={host: {"os": [["os-2.bin"], ["os-3.bin"]]}
                                             for host in ("canary", "other")})
                original = world.ops.dispatch
                def dispatch(device, step, **kwargs):
                    if device.hostname == "canary" and step.stage == at_target:
                        return {"state": "AT_TARGET"}
                    return original(device, step, **kwargs)
                world.ops.dispatch = dispatch
                results = world.run()
                self.assertEqual(results["other"][0], "BLOCKED")
                self.assertFalse(any(host == "other" for _t, host, _step in world.events("dispatch")))

    def test_previous_component_proof_does_not_release_next_component(self):
        from test_cases import test_fleet_engine as fixture
        world = fixture.World(self, ["canary", "other"])
        original = world.ops.dispatch
        def dispatch(device, step, **kwargs):
            if device.hostname == "canary" and step.component == "fw":
                return {"state": "AT_TARGET"}
            return original(device, step, **kwargs)
        world.ops.dispatch = dispatch
        results = world.run()
        self.assertEqual(results["other"][0], "BLOCKED")
        self.assertTrue(any(host == "canary" and step == "os-0" for _t, host, step in world.events("verify")))
        self.assertFalse(any(host == "other" and step == "fw-0" for _t, host, step in world.events("dispatch")))

    def test_os_available_routes_distinguish_missing_stage_and_unapproved_current(self):
        import ibsw_v2_device as ib
        from ibsw_upgrade_contract import Package, UpgradePolicy
        packages = tuple(Package(name, version, "/synthetic/" + name) for name, version in
                         (("old.bin", "25.02.6077"), ("first.bin", "25.02.7002"),
                          ("alternative.bin", "25.02.7003"), ("final.bin", "25.02.8008")))
        policy = UpgradePolicy("/synthetic", "25.02.8008", packages, os_stages=((0,), (1, 2), (3,)))
        available = frozenset(["/synthetic/alternative.bin", "/synthetic/final.bin"])
        plan = ib.plan_device(policy, ("os",), SimpleNamespace(os_version="25.02.6077", firmware_record=None),
                              available=available)
        self.assertEqual([item.file for item in plan.os_path], ["alternative.bin", "final.bin"])
        self.assertEqual(plan.issues, ())
        for version, expected in (("25.02.6077", "OS_PACKAGE_ROUTE_UNAVAILABLE"),
                                  ("25.02.9999", "OS_UPGRADE_PATH_REJECTED")):
            plan = ib.plan_device(policy, ("os",), SimpleNamespace(os_version=version, firmware_record=None),
                                  available=frozenset(["/synthetic/final.bin"]))
            self.assertEqual(plan.issues, (("os", expected),))
        plan = ib.plan_device(policy, ("os",), SimpleNamespace(os_version="25.02.8008", firmware_record=None),
                              available=frozenset())
        self.assertEqual((plan.issues, plan.os_path), ((), ()))

    def test_liveops_precheck_and_dispatch_share_actual_available_set(self):
        import ibsw_v2_device as ib
        from ibsw_upgrade_contract import Package, UpgradePolicy
        packages = tuple(Package(name, version, "/synthetic/" + name) for name, version in
                         (("old.bin", "25.02.6077"), ("first.bin", "25.02.8007"), ("alternative.bin", "25.02.8008")))
        policy = UpgradePolicy("/synthetic", "25.02.8008", packages, os_stages=((0,), (1, 2)))
        ops = ib.LiveOps(pins=object(), credentials=SimpleNamespace(password=None), policy=policy,
                         selected=("os",), run_id="owned-test")
        available = frozenset(["/synthetic/alternative.bin"])
        ops.bind_available_packages(available)
        facts = SimpleNamespace(os_version="25.02.6077", firmware_record=None,
                                guard=lambda: (None, None), health_record=None, health_complete=True,
                                before_commands=None)
        device = SimpleNamespace(hostname="example-ib01")
        with mock.patch.object(ops, "_connect", side_effect=lambda *a, **k: (contextlib.nullcontext(object()), False)), \
                mock.patch.object(ib, "run_check", return_value={}), \
                mock.patch.object(ib, "facts_from", return_value=facts), \
                mock.patch.object(ib, "health_state", return_value=("PASS", None, True)), \
                mock.patch.object(ib, "plan_device", wraps=ib.plan_device) as plan:
            result = ops.precheck(device, upgrade=False, journal=lambda *a: None)
            self.assertEqual([p.file for p in result["plan"].os_path], ["alternative.bin"])
            result = ops.dispatch(device, SimpleNamespace(component="os", target_version="25.02.8008"),
                                  backup=None, staged={}, journal=lambda *a: None)
            self.assertEqual(result, {"state": "FAILED", "reason": "CONFIG_BACKUP_QUERY_FAILED"})
        self.assertEqual(plan.call_count, 2)
        self.assertTrue(all(call.kwargs["available"] is available for call in plan.call_args_list))

    def test_ib_optional_classification_keeps_selected_firmware_mandatory(self):
        from dataclasses import replace
        import fleet_engine as engine
        import ibsw_v2_device as ib
        from ibsw_upgrade_contract import Package, UpgradePolicy
        world = self.world()
        base = world.engine.evidence.root.parent
        os_package = Package("os.bin", "25.02.8008", str(base / "os.bin"))
        Path(os_package.path).write_bytes(b"owned package")
        bios = Package("bios.bin", "7", str(base / "missing-bios.bin"))
        burn = Package("burn.bin", None, str(base / "missing-burn.bin"))
        refresh = Package("refresh.bin", None, str(base / "missing-refresh.bin"))
        world.engine.family = ib.IbFamily(UpgradePolicy(str(base), "25.02.8008", (os_package,), bios, burn, refresh))
        world.engine._load_packages()
        self.assertEqual(set(world.engine.packages), {str(base / "os.bin")})
        for component in ("bios", "cpld"):
            world.engine.options = replace(world.engine.options, selected=(component,))
            with self.subTest(component=component), self.assertRaises(engine.Hold):
                world.engine._load_packages()

    def test_runtime_lock_single_pass_stat_cost_is_recorded(self):
        import fleet_engine as engine
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            files = []
            for index in range(370):
                path = base / ("runtime-" + str(index) + ".py")
                path.write_bytes(b"owned runtime fixture")
                files.append(engine.LockedFile.read("runtime", path))
            started = time.perf_counter()
            unchanged = [item.unchanged() for item in files]
            elapsed = time.perf_counter() - started
            print("WP-A2 LOCK-BENCH files=370 elapsed_ms=%.6f threshold_ms=5" % (elapsed * 1000))
            self.assertEqual(unchanged, [True] * 370)

    def test_lock_snapshot_never_reads_file_contents(self):
        import fleet_engine as engine
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic-key"
            path.write_bytes(b"synthetic-value-not-for-lock-reader")
            info = path.stat()
            with mock.patch.object(Path, "open", side_effect=AssertionError("metadata lock read contents")):
                locked = engine.LockedFile.read("synthetic key", path)
                self.assertTrue(locked.unchanged())
            self.assertEqual(locked.identity, (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns))

    def test_hold_follows_two_inflight_devices_and_stops_unstarted_devices(self):
        from dataclasses import replace
        from test_cases import test_fleet_engine as fixture
        import fleet_engine as engine
        hosts = ["example-ib01", "example-ib02", "example-ib03", "example-ib04"]
        world = fixture.World(self, hosts, selected=("os",), in_flight=2,
                              needs={host: {"os": [["os-2.bin"]]} for host in hosts})
        world.engine.options = replace(world.engine.options, skip_canary=True)
        path = world.engine.evidence.root.parent / "management.pub"
        path.write_bytes(b"synthetic-original")
        world.engine.locked_inputs = (engine.LockedFile.read("management public key", path),)
        barrier = threading.Barrier(2, action=lambda: path.write_bytes(b"synthetic-replaced"))
        original = world.ops.dispatch
        def dispatch(device, step, **kwargs):
            result = original(device, step, **kwargs)
            barrier.wait(timeout=3)
            return result
        world.ops.dispatch = dispatch
        outcomes = world.run()
        started = [host for _t, host, _stage in world.events("dispatch")]
        self.assertEqual(len(started), 2)
        self.assertEqual([outcomes[host][0] for host in started], ["UPGRADED", "UPGRADED"])
        self.assertEqual([outcomes[host][0] for host in hosts if host not in started], ["NOT_EXECUTED", "NOT_EXECUTED"])
        self.assertEqual(world.report["hold"], "INPUT_CHANGED: " + str(path))
        self.assertEqual(engine.exit_code(world.report), 2)

    def test_skip_canary_keeps_ordinary_at_target_behavior(self):
        from dataclasses import replace
        world = self.world()
        world.engine.options = replace(world.engine.options, skip_canary=True)
        world.ops.dispatch = lambda *args, **kwargs: {"state": "AT_TARGET"}
        results = world.run()
        self.assertEqual({value[0] for value in results.values()}, {"AT_TARGET"})
        self.assertFalse(world.engine.phase_blocked)

    def test_existing_package_change_still_uses_original_hold_contract(self):
        import fleet_engine as engine
        world = self.world()
        package = Path(world.family.by_name["os-2.bin"].path)
        original = world.ops.dispatch
        def dispatch(device, step, **kwargs):
            result = original(device, step, **kwargs)
            package.write_bytes(b"changed owned package")
            return result
        world.ops.dispatch = dispatch
        outcomes = world.run()
        self.assertEqual(world.report["hold"], "PACKAGE_CHANGED: " + str(package))
        self.assertEqual(outcomes["canary"][0], "UPGRADED")
        self.assertEqual(outcomes["other"][0], "NOT_EXECUTED")
        self.assertTrue(outcomes["other"][1].startswith("PACKAGE_CHANGED: " + str(package)))
        self.assertEqual(engine.exit_code(world.report), 2)
