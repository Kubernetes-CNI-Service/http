"""Workflow: root runs the standalone 01-a-setup.py on an operator's project; U's child prepares the key, U gets the entries.

v3.1.3 guide 8.5 (workflow table :1941-1946): a temporary tree holds the real 01-a-setup.py, 11-load.py,
tools/ and template (test_activate_project_workflow.Workspace, the existing setup workflow fixture).  A root
launcher replaces only 01-a-setup's entry step with itself on injected inputs (euid 0, SUDO_USER, a passwd
whose "opuser" has uid = this uid + 1 and a temporary home holding one key, the project owned by opuser;
guide 8.4 #1, 2.2 #5) and records os.fchown instead of changing owners; the parent's HOME holds a different
key.  A `runuser` stand-in on PATH records its argv and environment and runs the command after `--` as this
user (macOS has no runuser, guide 2.2 #6) through a child launcher that only adds the declared PyYAML
location (env -i drops the user site).

Expected (not derived from the implementation): 问题文档 I-006 方案 :291 (the operator's passwd home, never
root's), :294-295 (what root creates in the project belongs to the user; 01-a-setup the same), :347 (write
on the operator side as the operator); v3.1.2 guide :528 (wait form), :624-626 (only this run's new
entries, the passwd primary group, root-private state stays root's: 11-load ROOT_PRIVATE_PROJECT_STATE);
O7 ② (v3.1.2 guide :223, :511) and :2215 (V via sudo is refused before any write).  Real uid switching is
TC-REAL-I006-OPERATOR-LOAD-001 step 10 (NOT RUN).
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
from pathlib import Path
import pwd
import site
import subprocess
import sys
import tempfile
import unittest

from test_cases import test_activate_project_workflow as WORKFLOW
from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
LOAD = load_script("setup_operator_identity_workflow_load", ROOT / "DAY0-Prepare/11-load.py")

ROOT_LAUNCHER = '''import functools, json, os, pathlib, pwd, sys, types
record, setup_path, operator_home, sudo_user = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
me = pwd.getpwuid(os.getuid())
entries = {
    "opuser": pwd.struct_passwd(("opuser", "x", me.pw_uid + 1, me.pw_gid, "fixture", operator_home, "/bin/sh")),
    "vuser": pwd.struct_passwd(("vuser", "x", me.pw_uid + 2, me.pw_gid, "fixture", "/nonexistent/vuser", "/bin/sh")),
}
by_uid = {entry.pw_uid: entry for entry in entries.values()}
def getpwuid(uid):
    return by_uid[uid]
def getpwnam(name):
    return entries[name]
def owner(path):
    os.stat(path)
    return types.SimpleNamespace(st_uid=me.pw_uid + 1)
handed = []
real_fchown = os.fchown
def fchown(descriptor, uid, gid):
    held = os.fstat(descriptor)
    handed.append([held.st_dev, held.st_ino, uid, gid])
os.fchown = fchown
import importlib.util
spec = importlib.util.spec_from_file_location("setup_root_parent", setup_path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
real = getattr(module, "_setup_operator", None)
if real is not None:
    environ = {"SUDO_USER": sudo_user, "SUDO_UID": str(entries[sudo_user].pw_uid)}
    module._setup_operator = functools.partial(real, euid=0, environ=environ, getpwuid=getpwuid,
                                               getpwnam=getpwnam, stat=owner)
sys.argv = [setup_path, *sys.argv[5:]]
try:
    code = module.main()
finally:
    (record / "fchown.json").write_text(json.dumps(handed))
raise SystemExit(code)
'''

CHILD_LAUNCHER = '''import json, os, pathlib, runpy, sys
record, yaml_site, script = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
sys.path.append(yaml_site)
(record / "child.json").write_text(json.dumps({"env": dict(os.environ), "args": sys.argv[4:]}))
sys.argv = [script, *sys.argv[4:]]
runpy.run_path(script, run_name="__main__")
'''

RUNUSER = '''#!{python}
import json, os, subprocess, sys
record, launcher, yaml_site = {record!r}, {launcher!r}, {yaml_site!r}
argv = sys.argv[1:]
with open(record + "/runuser.json", "w") as handle:
    json.dump({{"argv": argv, "env": dict(os.environ)}}, handle)
if argv[:1] != ["-u"] or argv[2:3] != ["--"] or argv[3:5] != ["env", "-i"]:
    sys.exit(90)
command = argv[3:]
index = 2
while "=" in command[index]:
    index += 1
command[index + 1:index + 1] = [launcher, record, yaml_site]   # after the interpreter
code = subprocess.call(command)
sys.exit(128 - code if code < 0 else code)
'''


def tree_witness(root: Path) -> dict:
    """Path, type, content sha256, mode and link target of every entry: the unchanged-tree witness."""
    state = {}
    for current, directories, files in os.walk(root):
        for name in (*directories, *files):
            path = Path(current) / name
            info = path.lstat()
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                state[relative] = ("link", os.readlink(path), info.st_mode)
            elif path.is_dir():
                state[relative] = ("dir", info.st_mode)
            else:
                state[relative] = ("file", hashlib.sha256(path.read_bytes()).hexdigest(), info.st_mode)
    return state


def root_private(name: str) -> bool:
    """11-load's ROOT_PRIVATE_PROJECT_STATE (agentOP report 4.4, the list http dev adopted): never handed over."""
    parts = name.split("/")
    return any(fnmatch.fnmatchcase("/".join(parts[:count]), pattern)
               for count in range(1, len(parts) + 1) for pattern in LOAD.ROOT_PRIVATE_PROJECT_STATE)


class SetupOperatorIdentityWorkflowTests(unittest.TestCase):
    def setUp(self):
        holder = tempfile.TemporaryDirectory(prefix="setup-operator-workflow-")
        self.addCleanup(holder.cleanup)
        self.base = Path(holder.name).resolve()
        self.space = WORKFLOW.Workspace(self.base)            # its HOME holds the parent's (root's) key
        self.project = self.space.project(WORKFLOW.FIRST)
        (self.space.http / ".deployment.lock").touch(mode=0o644)   # the lock inode exists before any run
        self.me = pwd.getpwuid(os.getuid())
        self.operator_home = self.base / "opuser-home"
        (self.operator_home / ".ssh").mkdir(parents=True, mode=0o700)
        self.operator_key = WORKFLOW.public_key(77, "opuser@laptop")
        (self.operator_home / ".ssh/id_ed25519.pub").write_text(self.operator_key, encoding="ascii")
        self.record = self.base / "record"
        self.record.mkdir()
        launchers = self.base / "launchers"
        launchers.mkdir()
        (launchers / "root_launcher.py").write_text(ROOT_LAUNCHER, encoding="utf-8")
        (launchers / "child_launcher.py").write_text(CHILD_LAUNCHER, encoding="utf-8")
        self.root_launcher = launchers / "root_launcher.py"
        stub = self.base / "bin"
        stub.mkdir()
        runuser = stub / "runuser"
        runuser.write_text(RUNUSER.format(python=sys.executable, record=str(self.record),
                                          launcher=str(launchers / "child_launcher.py"),
                                          yaml_site=site.getusersitepackages()), encoding="utf-8")
        runuser.chmod(0o755)
        self.stub = stub

    def run_setup(self, sudo_user: str) -> subprocess.CompletedProcess:
        environment = {"PATH": f"{self.stub}:/usr/bin:/bin", "LANG": "C", "HOME": str(self.space.home),
                       "PYTHONUSERBASE": site.getuserbase(), "PYTHONDONTWRITEBYTECODE": "1"}
        return subprocess.run(
            [sys.executable, "-B", str(self.root_launcher), str(self.record),
             str(self.space.http / "DAY0-Prepare/01-a-setup.py"), str(self.operator_home), sudo_user,
             "--host-role=workstation", "--no-upgrade", "-y", WORKFLOW.FIRST],
            cwd=self.space.http, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, timeout=600, check=False)

    def test_sudo_u_prepares_key_as_u_and_hands_this_runs_entries_to_u(self):
        before = {name for name in tree_witness(self.project)}
        done = self.run_setup("opuser")
        self.assertEqual(0, done.returncode, done.stdout)
        laptop = (self.project / "laptop.pub").read_text(encoding="ascii")
        self.assertEqual(self.operator_key.strip(), laptop.strip(), "opuser's key, not the parent HOME's")
        runuser = json.loads((self.record / "runuser.json").read_text())
        self.assertEqual(["-u", "opuser", "--", "env", "-i"], runuser["argv"][:5])
        self.assertIn(f"HOME={self.operator_home}", runuser["argv"])
        self.assertIn("HTTP_ZTP_ROOT_PARENT=1", runuser["argv"])
        after = tree_witness(self.project)
        created = {name for name in after if name not in before}
        expected = {name for name in created if after[name][0] != "link" and not root_private(name)}
        inodes = {}
        for current, directories, files in os.walk(self.project):
            for name in (*directories, *files):
                info = (Path(current) / name).lstat()
                inodes[(info.st_dev, info.st_ino)] = (Path(current) / name).relative_to(self.project).as_posix()
        handed = json.loads((self.record / "fchown.json").read_text())
        names = {inodes.get((device, inode), "<outside the project>") for device, inode, _uid, _gid in handed}
        self.assertTrue(expected, "fixture check: this run created project entries")
        self.assertEqual(expected, names)
        self.assertEqual({(self.me.pw_uid + 1, self.me.pw_gid)}, {(uid, gid) for _d, _i, uid, gid in handed})
        self.assertFalse(names & before, "entries that existed before stay as they were")
        self.assertIn("[OWNER]", done.stdout)

    def test_sudo_v_refused_and_tree_unchanged(self):
        before = tree_witness(self.space.http)
        done = self.run_setup("vuser")
        self.assertEqual(1, done.returncode, done.stdout)
        error = next((line for line in done.stdout.splitlines() if "[ERROR]" in line), "")
        self.assertIn("opuser", error)
        self.assertIn("vuser", error)
        self.assertEqual(before, tree_witness(self.space.http))
        self.assertFalse((self.record / "runuser.json").exists(), "runuser was not called")


if __name__ == "__main__":
    unittest.main()
