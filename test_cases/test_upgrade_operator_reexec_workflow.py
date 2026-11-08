"""Workflow: root starts upgrade.py / upgrade2.py on an operator's project; the entry re-runs once as the operator.

v3.1.2 guide WP-10 (workflow): a launcher makes the identity rule see euid 0 by patching the rule's inputs in that
process only (os.geteuid, and passwd whose operator is this test user with a temporary home); a `runuser` stand-in on
PATH records its argv and environment, then runs the command it was given as this user and reports its exit code.
Expected (design `设计/I-006与R-005实现计划.md` §4.3 :97; guide WP-10 steps 4-5 and 「venv 切换在身份切换之后」;
test_ibsw_v2_entry.py :98-117 shared guard): the switch happens exactly once, because the second layer sees it is not
root; it precedes the venv switch (upgrade.py) and the runtime guard; the operator run's exit code is the code the
caller sees; one identity line is printed by the process that does the work.

Every layer runs from a temporary copy (the flat bundle of test_ibsw225_flat_tools_layout for upgrade.py; upgrade2.py
with the two tools modules its entry imports) so a layer started with `env -i` writes no bytecode into this tree,
and every layer's runtime guard is a recorder, never the host guard.  Real uid switching is
TC-REAL-I006-OPERATOR-REEXEC-001 (NOT RUN).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import tempfile
import unittest

from test_cases.test_ibsw225_flat_tools_layout import MEMBERS as FLAT_MEMBERS

ROOT = Path(__file__).resolve().parents[1]
VENV_MARKER = "IBSW_UPGRADE_VENV_REEXEC"
GUARD_STOP = 75   # ALREADY_RUNNING from the recorder guard: the operator run's own exit code
VENV_VERSIONS = (("paramiko", "5.0.0"), ("bcrypt", "5.0.0"), ("cryptography", "50.0.1"), ("invoke", "2.2.1"),
                 ("PyNaCl", "1.6.2"), ("cffi", "2.0.0"), ("pycparser", "2.23"), ("typing-extensions", "4.16.0"),
                 ("PyYAML", "6.0.2"))

# The "root" layer: only the identity rule's inputs differ (euid 0; passwd gives this user a temporary home).
ROOT_LAUNCHER = '''import importlib, os, pathlib, pwd, runpy, sys
record, guard_dir, home, entry = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
me = pwd.getpwuid(os.getuid())
operator = pwd.struct_passwd((me.pw_name, "x", me.pw_uid, me.pw_gid, me.pw_gecos, home, me.pw_shell))
real_getpwuid, real_getpwnam = pwd.getpwuid, pwd.getpwnam
pwd.getpwuid = lambda uid: operator if uid == me.pw_uid else real_getpwuid(uid)
pwd.getpwnam = lambda name: operator if name == me.pw_name else real_getpwnam(name)
os.geteuid = lambda: 0
def note(event):
    with open(record / "events", "a") as handle:
        handle.write(event + "\\n")
sys.path.insert(0, guard_dir)
guard = importlib.import_module("ib_bringup_runtime_guard")
class Busy:
    def __enter__(self):
        note("guard as root")
        raise guard._InstanceGuardError("ALREADY_RUNNING", "workflow stop")
    def __exit__(self, *exc):
        return False
guard._runtime_instance_guard = Busy
note("root")
sys.argv = [entry, *sys.argv[5:]]
runpy.run_path(entry, run_name="__main__")
'''

# Every layer after the switch: the real process identity; the guard is a recorder; this interpreter lacks the
# SSH runtime, so upgrade.py's venv switch is deterministic.
CHILD_LAUNCHER = '''import importlib, importlib.metadata as metadata, os, pathlib, runpy, sys
record, guard_dir, args = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3:]
if args[:1] == ["-B"]:
    args = args[1:]
def note(event):
    with open(record / "events", "a") as handle:
        handle.write(event + "\\n")
note("child uid=%d venv=%s" % (os.geteuid(), os.environ.get("IBSW_UPGRADE_VENV_REEXEC", "-")))
sys.path.insert(0, guard_dir)
guard = importlib.import_module("ib_bringup_runtime_guard")
class Busy:
    def __enter__(self):
        note("guard uid=%d" % os.geteuid())
        raise guard._InstanceGuardError("ALREADY_RUNNING", "workflow stop")
    def __exit__(self, *exc):
        return False
guard._runtime_instance_guard = Busy
def missing(name):
    raise metadata.PackageNotFoundError(name)
metadata.version = missing
sys.argv = list(args)
runpy.run_path(args[0], run_name="__main__")
'''

RUNUSER = '''#!{python}
import json, os, subprocess, sys
record, launcher, guard_dir = {record!r}, {launcher!r}, {guard_dir!r}
with open(record + "/events", "a") as handle:
    handle.write("runuser\\n")
argv = sys.argv[1:]
with open(record + "/runuser.json", "w") as handle:
    json.dump({{"argv": argv, "env": dict(os.environ)}}, handle)
if argv[:1] != ["-u"] or argv[2:3] != ["--"] or argv[3:5] != ["env", "-i"]:
    sys.exit(90)
command = argv[3:]
index = 2
while "=" in command[index]:
    index += 1
command[index + 1:index + 1] = [launcher, record, guard_dir]   # after the interpreter, before the entry
code = subprocess.call(command)
with open(record + "/runuser.exit", "w") as handle:
    handle.write(str(code))
sys.exit(code)
'''

VENV_PYTHON = '''#!{python}
import json, os, sys
record, launcher, guard_dir, python = {record!r}, {launcher!r}, {guard_dir!r}, {python!r}
with open(record + "/events", "a") as handle:
    handle.write("venv\\n")
with open(record + "/venv.json", "w") as handle:
    json.dump({{"argv": sys.argv[1:], "env": dict(os.environ)}}, handle)
os.execv(python, [python, launcher, record, guard_dir, *sys.argv[1:]])
'''


class UpgradeReexecWorkflowTests(unittest.TestCase):
    def setUp(self):
        holder = tempfile.TemporaryDirectory(prefix="w10-reexec-workflow-")
        self.addCleanup(holder.cleanup)
        self.root = Path(holder.name).resolve()   # macOS /var -> /private/var
        self.me = pwd.getpwuid(os.getuid())
        self.home = self.root / "operator-home"
        self.home.mkdir()
        self.home.chmod(0o755)
        self.project = self.root / "DAY0-Prepare" / "site-a"
        self.project.mkdir(parents=True)

    def write_executable(self, path, text):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        path.chmod(0o755)
        return path

    def stage(self, name, guard_dir):
        record = self.root / ("record-" + name)
        record.mkdir()
        launcher = self.write_executable(self.root / "child-launcher.py", CHILD_LAUNCHER)
        bin_dir = self.root / ("bin-" + name)
        self.write_executable(bin_dir / "runuser", RUNUSER.format(
            python=sys.executable, record=str(record), launcher=str(launcher), guard_dir=str(guard_dir)))
        return record, launcher, bin_dir

    def launch(self, record, guard_dir, bin_dir, entry, args, sudo):
        environment = {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(self.root / "root-home"),
                       "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8", "TERM": "dumb", "USER": "root",
                       "LOGNAME": "root", "SSH_AUTH_SOCK": str(self.root / "agent.sock"),
                       "IBSW_TEST_CANARY": "root-only"}
        if sudo:
            environment.update(SUDO_USER=self.me.pw_name, SUDO_UID=str(self.me.pw_uid),
                               SUDO_GID=str(self.me.pw_gid))
        result = subprocess.run([sys.executable, "-B", "-c", ROOT_LAUNCHER, str(record), str(guard_dir),
                                 str(self.home), str(entry), *args], cwd=self.root, env=environment,
                                stdin=subprocess.DEVNULL, capture_output=True, text=True, encoding="utf-8",
                                timeout=120)
        return result

    def assert_switched_once(self, record, result, entry, args):
        runuser = json.loads((record / "runuser.json").read_text())
        argv = runuser["argv"]
        self.assertEqual(["-u", self.me.pw_name, "--", "env", "-i"], argv[:5])
        command = argv[5:]
        assignments = {}
        while "=" in command[0]:
            name, _, value = command.pop(0).partition("=")
            assignments[name] = value
        self.assertEqual({"PATH": runuser["env"]["PATH"], "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8",
                          "TERM": "dumb", "HOME": str(self.home), "USER": self.me.pw_name,
                          "LOGNAME": self.me.pw_name}, assignments)
        self.assertEqual([sys.executable, str(entry), *args], command)
        # The caller sees the operator run's exit code (exec form: the root layer leaves no parent behind).
        self.assertEqual(GUARD_STOP, result.returncode, result.stderr)
        self.assertEqual(str(GUARD_STOP), (record / "runuser.exit").read_text())
        identity = [line for line in result.stderr.splitlines() if line.startswith("操作员：")]
        self.assertEqual(1, len(identity), result.stderr)
        self.assertIn("操作员：" + self.me.pw_name, identity[0])
        self.assertIn("当前：" + self.me.pw_name, identity[0])
        self.assertIn("ALREADY_RUNNING", result.stderr)

    def test_upgrade_py_root_launch_switches_once_then_venv_then_guard(self):
        bundle = self.root / "bundle"
        bundle.mkdir()
        for relative in FLAT_MEMBERS:
            (bundle / Path(relative).name).write_bytes((ROOT / relative).read_bytes())
        entry = bundle / "upgrade.py"
        args = ["--inspect-only", "--project", str(self.project)]
        for label, sudo in (("root login", False), ("sudo by the owner", True)):
            with self.subTest(label):
                record, launcher, bin_dir = self.stage("v1-" + str(int(sudo)), bundle)
                venv = self.home / ".venvs" / "http" / "ibsw-upgrade"
                if not venv.exists():
                    self.make_venv(venv)
                self.write_executable(venv / "bin" / "python3", VENV_PYTHON.format(
                    python=sys.executable, record=str(record), launcher=str(launcher), guard_dir=str(bundle)))
                result = self.launch(record, bundle, bin_dir, entry, args, sudo)
                uid = self.me.pw_uid
                self.assertEqual(["root", "runuser", f"child uid={uid} venv=-", "venv", f"child uid={uid} venv=1",
                                  f"guard uid={uid}"], (record / "events").read_text().splitlines(), result.stderr)
                self.assert_switched_once(record, result, entry, args)
                # The venv switch ran in the operator layer: the operator's home, nothing of root's environment.
                venv_run = json.loads((record / "venv.json").read_text())
                self.assertEqual([str(entry), *args], venv_run["argv"])
                self.assertEqual("1", venv_run["env"].get(VENV_MARKER))
                self.assertEqual(str(self.home), venv_run["env"]["HOME"])
                self.assertEqual(self.me.pw_name, venv_run["env"]["USER"])
                for name in ("IBSW_TEST_CANARY", "SSH_AUTH_SOCK", "SUDO_USER", "SUDO_UID", "HTTP_ZTP_ROOT_PARENT"):
                    self.assertNotIn(name, venv_run["env"])

    def test_upgrade2_root_launch_switches_once_then_guard(self):
        tree = self.root / "tree"
        entry = tree / "infiniband/bringup/xdr-upgrade/upgrade2.py"
        entry.parent.mkdir(parents=True)
        entry.write_bytes((ROOT / "infiniband/bringup/xdr-upgrade/upgrade2.py").read_bytes())
        (tree / "tools").mkdir()
        for name in ("operator_identity.py", "ib_bringup_runtime_guard.py"):
            (tree / "tools" / name).write_bytes((ROOT / "tools" / name).read_bytes())
        args = ["--project", str(self.project), "--plan"]
        for label, sudo in (("root login", False), ("sudo by the owner", True)):
            with self.subTest(label):
                record, _launcher, bin_dir = self.stage("v2-" + str(int(sudo)), tree / "tools")
                result = self.launch(record, tree / "tools", bin_dir, entry, args, sudo)
                uid = self.me.pw_uid
                self.assertEqual(["root", "runuser", f"child uid={uid} venv=-", f"guard uid={uid}"],
                                 (record / "events").read_text().splitlines(), result.stderr)
                self.assert_switched_once(record, result, entry, args)

    @staticmethod
    def make_venv(venv):
        site = venv / "lib" / "python3.9" / "site-packages"
        (venv / "bin").mkdir(parents=True)
        site.mkdir(parents=True)
        (venv / "pyvenv.cfg").write_text("home = /usr/bin\n")
        for name, version in VENV_VERSIONS:
            info = site / (name.replace("-", "_") + "-" + version + ".dist-info")
            info.mkdir()
            (info / "METADATA").write_text("Metadata-Version: 2.1\nName: %s\nVersion: %s\n" % (name, version))
        home = venv.parents[2]
        for directory in (home / ".venvs", home / ".venvs" / "http", venv, venv / "bin", venv / "lib",
                          site.parent, site):
            directory.chmod(0o755)


if __name__ == "__main__":
    unittest.main()
