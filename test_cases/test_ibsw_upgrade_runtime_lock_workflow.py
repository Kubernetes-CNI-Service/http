"""I-014: real entry -> IB family -> fleet engine while owned inputs change.

Fake I/O is in-process only; no SimFleet shell/system temporary files or SSH runs.
"""
from __future__ import annotations

import os
import contextlib
import fcntl
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from test_cases.ibsw_upgrade_runtime_fixture import OwnedWorkflow

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "infiniband/bringup/xdr-upgrade/upgrade2.py"

GUARD_LAUNCHER = '''import importlib.util, pathlib, sys
entry, guard_path, project = sys.argv[1:]
spec = importlib.util.spec_from_file_location("a2_guard_entry", entry)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module._runtime_problems = lambda version: []
import ib_bringup_runtime_guard as guard
guard._RUNTIME_GUARD_PATH = pathlib.Path(guard_path)
sys.argv = [entry, "--project", project, "--plan"]
raise SystemExit(module.main())
'''

RUNTIME_LAUNCHER = '''import importlib.util, json, os, pathlib, sys
entry, record, descriptor, *args = sys.argv[1:]
spec = importlib.util.spec_from_file_location("a2_exec_entry", entry)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
switched = "IBSW_UPGRADE_VENV_REEXEC" in os.environ
module._runtime_problems = lambda version: [] if switched else ["paramiko"]
module._runtime_venv_candidates = lambda: (pathlib.Path(record).parent / "venv",)
module._audited_runtime_venv = lambda candidate: (sys.executable, "usable")
with open(record, "a") as handle:
    handle.write(json.dumps({"switched": switched, "args": args}) + "\\n")
result = module._reexec_in_runtime_venv(sys.argv[1:])
if result != "NOT_NEEDED" or not switched:
    raise SystemExit(91)
if os.read(int(descriptor), 32) != b"owned-fd-control":
    raise SystemExit(92)
'''


def child_environment():
    # Every spawned interpreter inherits the runner's explicit owned test root.
    owned = os.environ["HTTP_TEST_OWNED_ROOT"]
    return {"HOME": os.environ["HOME"], "USER": os.environ.get("USER", ""),
            "LOGNAME": os.environ.get("LOGNAME", ""), "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "LANG": "en_US.UTF-8", "TMPDIR": owned, "HTTP_TEST_OWNED_ROOT": owned,
            "PYTHONPYCACHEPREFIX": str(Path(owned) / "pyc")}


class UpgradeRuntimeLockWorkflowTests(unittest.TestCase):
    def test_runtime_guard_exit_codes_through_the_real_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            launcher, project, guard = base / "guard-launcher.py", base / "project", base / "guard.lock"
            launcher.write_text(GUARD_LAUNCHER)
            project.mkdir()
            guard.write_bytes(b"")
            guard.chmod(0o600)
            with guard.open("rb") as handle:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                busy = subprocess.run([sys.executable, "-B", str(launcher), str(ENTRY), str(guard), str(project)],
                                      capture_output=True, text=True, timeout=30, env=child_environment())
            self.assertEqual(busy.returncode, 75, busy.stderr)
            self.assertIn("ALREADY_RUNNING", busy.stderr)
            guard.chmod(0o666)
            unsafe = subprocess.run([sys.executable, "-B", str(launcher), str(ENTRY), str(guard), str(project)],
                                    capture_output=True, text=True, timeout=30, env=child_environment())
            self.assertEqual(unsafe.returncode, 2, unsafe.stderr)
            self.assertIn("INSTANCE_GUARD_UNAVAILABLE", unsafe.stderr)
            self.assertEqual(list(project.iterdir()), [])

    def test_runtime_real_exec_preserves_arguments_and_inheritable_fd(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            launcher, record = base / "runtime-launcher.py", base / "events.jsonl"
            launcher.write_text(RUNTIME_LAUNCHER)
            reader, writer = os.pipe()
            try:
                os.write(writer, b"owned-fd-control")
                os.close(writer)
                writer = None
                args = [str(ENTRY), str(record), str(reader), "--devices", "example-ib*", "--plan"]
                child = subprocess.run([sys.executable, "-B", str(launcher), *args], pass_fds=(reader,),
                                       capture_output=True, text=True, timeout=30, env=child_environment())
            finally:
                os.close(reader)
                if writer is not None:
                    os.close(writer)
            self.assertEqual(child.returncode, 0, child.stderr)
            rows = [json.loads(line) for line in record.read_text().splitlines()]
            self.assertEqual(rows, [{"switched": False, "args": ["--devices", "example-ib*", "--plan"]},
                                    {"switched": True, "args": ["--devices", "example-ib*", "--plan"]}])

    def test_replaced_management_key_mid_upgrade_holds_and_names_it(self):
        fixture = OwnedWorkflow(self)
        changed = []
        def replace(device, _step):
            if not changed:
                changed.append(device.hostname)
                new = fixture.public.with_suffix(".new")
                new.write_bytes(fixture.public.read_bytes())
                os.replace(new, fixture.public)
        fixture.change = replace
        self.assertEqual(fixture.run(["--upgrade", "-y"]), 2)
        [report] = fixture.reports()
        self.assertEqual(report["hold"], "INPUT_CHANGED: " + str(fixture.public))
        outcomes = {row["hostname"]: row for row in report["devices"]}
        self.assertEqual(outcomes["example-ib01"]["category"], "UPGRADED")
        self.assertEqual(outcomes["example-ib02"]["category"], "NOT_EXECUTED")
        self.assertTrue(outcomes["example-ib02"]["reason"].startswith("INPUT_CHANGED: " + str(fixture.public)))
        self.assertIn("HOLD: INPUT_CHANGED: " + str(fixture.public), fixture.out.getvalue())
        self.assertEqual(len([item for item in fixture.ops.log if item[1] == "dispatch"]), 1)
        self.assertNotIn("synthetic-private-never-parsed", fixture.out.getvalue())
        self.assertNotIn("synthetic-public-never-sent", str(report))

    def test_touched_known_hosts_mid_upgrade_does_not_hold(self):
        import fleet_ssh
        for kind in ("append", "replace"):
            with self.subTest(kind=kind):
                fixture = OwnedWorkflow(self)
                def change(_device, _step):
                    if kind == "replace":
                        new = fixture.hosts.with_suffix(".new")
                        new.write_bytes(fixture.hosts.read_bytes() + b"# changed\n")
                        os.replace(new, fixture.hosts)
                    else:
                        fixture.hosts.write_bytes(fixture.hosts.read_bytes() + b"# changed\n")
                fixture.change = change
                with mock.patch.object(fleet_ssh.HostPins, "load", wraps=fleet_ssh.HostPins.load) as load:
                    self.assertEqual(fixture.run(["--upgrade", "-y"]), 0)
                self.assertEqual(load.call_count, 1)
                self.assertEqual(str(load.call_args.args[0]), str(fixture.hosts))
                [report] = fixture.reports()
                self.assertIsNone(report["hold"])
                self.assertEqual({row["category"] for row in report["devices"]}, {"UPGRADED"})
                expected = "[KNOWN_HOSTS] " + str(fixture.hosts) + ": modified during the run; this run keeps the snapshot taken at start"
                self.assertEqual(fixture.out.getvalue().splitlines().count(expected), 1)
