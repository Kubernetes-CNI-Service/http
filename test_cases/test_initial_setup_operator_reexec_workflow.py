"""Workflow: root runs initial-setup on an operator's project; the run goes once through runuser as the operator.

v3.1.3 guide WP-9 (workflow table :1017-1023): a temporary tree holds the merged initial-setup.py at its
repository place, the real tools/operator_identity.py and tools/project_contract.py, a project and the
DAY0-Prepare/activate-project pointer to it.  A root launcher makes the identity rule see euid 0 by
replacing operator_identity.resolve_operator in that process only with the real rule on injected inputs
(guide 2.2 #5; passwd gives this user a temporary home), then runs the real _guarded_main.  A `runuser`
stand-in on PATH records its argv and environment and runs the command after `--` as this user (macOS
has no runuser, guide 2.2 #6), forwarding SIGINT and SIGTERM as the real one is expected to; it inserts a
child launcher after the interpreter that records the child's environment and signals, gives it the
declared PyYAML location (env -i drops the user site) and a private runtime guard, and, for the Ctrl-C
case, replaces only the SSH transport with a fake device whose first IB command writes a marker and
blocks.

Expected (not derived from the implementation): v3.1.2 guide :1423, :1427 and 设计/I-006与R-005实现计划.md
§4.3 (the wait form: the child's environment is only the whitelist, HOME from passwd; the parent waits
and exits with the child's code; the --credentials-fd fd reaches the child, development plan :314 and §3
H4); table 6-1 row 11 (Ctrl-C in the execution phase: v15 single slot :4475-4476 makes the batch fatal,
FAILED, main :5875 returns 1) and v3.1.2 guide :528 (M6: the parent exits with the child's code; 128 + n
only when the child is killed by a signal).  Real uid switching is TC-REAL-I006-OPERATOR-REEXEC-001.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
from pathlib import Path
import pwd
import signal
import site
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
INITIAL = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
TOOLS = ("device_identity", "operator_identity", "project_contract", "credentials_fd")
WHITELIST = {"PATH", "LANG", "LC_ALL", "TERM", "HOME", "USER", "LOGNAME", "HTTP_ZTP_ROOT_PARENT"}
JUMP = "example-oob-leaf01"
IB = "example-ib001"


def secret(label: str) -> str:
    # Assembled at run time so no credential literal appears in the source (public audit).
    return "-".join(("PUBLIC", "wp9w", label, str(os.getpid()), "Zq7"))


# The "root" layer: only the identity rule's inputs differ (euid 0, root logged in directly; passwd gives
# this user a temporary home).  The parent must never take the runtime guard or run main itself.
ROOT_LAUNCHER = '''import contextlib, json, os, pathlib, pwd, sys
record, tree, home, script = (pathlib.Path(item) for item in sys.argv[1:5])
sys.path.insert(0, str(tree))
import tools.operator_identity as identity
me = pwd.getpwuid(os.getuid())
operator = pwd.struct_passwd((me.pw_name, "x", me.pw_uid, me.pw_gid, me.pw_gecos, str(home), me.pw_shell))
def note(event):
    with open(record / "events", "a") as handle:
        handle.write(event + "\\n")
def getpwuid(uid):
    if uid != me.pw_uid:
        raise KeyError(uid)
    return operator
def getpwnam(name):
    if name != me.pw_name:
        raise KeyError(name)
    return operator
real = identity.resolve_operator
def resolve(project_dir):
    note("resolve " + str(project_dir))
    return real(project_dir, euid=0, environ={}, getpwuid=getpwuid, getpwnam=getpwnam)
identity.resolve_operator = resolve
import importlib.util
spec = importlib.util.spec_from_file_location("initial_setup_root_parent", script)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module   # dataclasses look it up
spec.loader.exec_module(module)
@contextlib.contextmanager
def guard():
    note("guard as root")
    raise AssertionError("the root parent took the runtime guard")
    yield
module._runtime_instance_guard = guard
module._standalone_main_with_report_cleanup = lambda: note("main as root") or 99
sys.argv = [str(script), *sys.argv[5:]]
raise SystemExit(module._guarded_main())
'''

# Every layer after the switch: the real process identity, the declared PyYAML path, a private guard.
CHILD_LAUNCHER = '''import hashlib, importlib.util, json, os, pathlib, signal, sys, time
record, yaml_site, scenario, script = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
sys.path.append(yaml_site)
def note(event):
    with open(record / "events", "a") as handle:
        handle.write(event + "\\n")
with open(record / "child.json", "w") as handle:
    json.dump({"env": dict(os.environ), "uid": os.getuid(), "args": sys.argv[5:]}, handle)
def interrupted(number, frame):
    note("child SIGINT")
    raise KeyboardInterrupt
signal.signal(signal.SIGINT, interrupted)
tree = pathlib.Path(script).resolve().parents[3]
sys.path.insert(0, str(tree))
spec = importlib.util.spec_from_file_location("initial_setup_operator_child", script)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module   # dataclasses look it up
spec.loader.exec_module(module)
module._RUNTIME_GUARD_PATH = record / "private-runtime.lock"   # never the host-wide guard inode
if scenario == "fd":
    import tools.credentials_fd as credentials
    read = credentials.read_credentials
    def recording(*args, **kwargs):
        value = read(*args, **kwargs)
        note("fd " + hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest())
        return value
    credentials.read_credentials = recording
if scenario == "sigint":
    fixture = json.loads((record / "sigint.json").read_text())
    JUMP, SECRET = fixture["jump"], fixture["initial"]
    answers = {
        ("hostname",): JUMP + "\\n",
        ("nv", "show", "interface"): "swp1 up up\\n",
        ("ip", "-d", "link", "show"): ("1: swp1: <UP> mtu 1500 master br_default\\n40: br_default: <UP> mtu 1500\\n"
            "    bridge forward_delay 1500 vlan_filtering 1\\n41: ib-mgmt1000@br_default: <UP> mtu 1500 master oob\\n"
            "    vlan protocol 802.1Q id 1000 <REORDER_HDR>\\n"),
        ("bridge", "fdb", "show"): "02:00:00:00:00:0a dev swp1 vlan 1000 master br_default\\n",
        ("ip", "neighbor"): "fe80::a dev ib-mgmt1000 lladdr 02:00:00:00:00:0a REACHABLE\\n",
        ("ip", "-j", "address", "show"): json.dumps([{"ifname": "ib-mgmt1000", "flags": ["UP"], "operstate": "UP",
            "addr_info": [{"family": "inet", "local": "192.0.2.1", "prefixlen": 24, "scope": "global"},
                          {"family": "inet6", "local": "fe80::1", "prefixlen": 64, "scope": "link"}]}]),
        ("ifquery", "ib-mgmt1000"): "iface ib-mgmt1000\\n    vrf oob\\n",
    }
    def ethernet(device, user, password, command, timeout, **kwargs):
        return answers[tuple(command)]
    calls = []
    def transport(command, responder, timeout, **kwargs):
        calls.append(command)
        if len(calls) > 1:
            note("device command after the cancel")
            raise AssertionError("no device command after the first one")
        (record / "first-device-command").write_text("blocked\\n")
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            time.sleep(0.05)
        raise AssertionError("no SIGINT arrived")
    module.probe_ethernet_key = lambda *args, **kwargs: "key"
    module.run_on_ethernet = ethernet
    module.interactive_run = transport
    module.resolve_initial_ib_password = lambda *args, **kwargs: SECRET
sys.argv = [script, *sys.argv[5:]]
code = module._guarded_main()
note("child exit %d" % code)
raise SystemExit(code)
'''

RUNUSER = '''#!{python}
import json, os, signal, subprocess, sys
record, launcher, yaml_site, scenario = {record!r}, {launcher!r}, {yaml_site!r}, {scenario!r}
argv = sys.argv[1:]
with open(record + "/events", "a") as handle:
    handle.write("runuser\\n")
with open(record + "/runuser.json", "w") as handle:
    json.dump({{"argv": argv, "env": dict(os.environ)}}, handle)
if argv[:1] != ["-u"] or argv[2:3] != ["--"] or argv[3:5] != ["env", "-i"]:
    sys.exit(90)
command = argv[3:]
index = 2
while "=" in command[index]:
    index += 1
command[index + 1:index + 1] = [launcher, record, yaml_site, scenario]   # after the interpreter
child = None
def forward(number, frame):
    with open(record + "/events", "a") as handle:
        handle.write("runuser forwards %d\\n" % number)
    if child is not None:
        child.send_signal(number)
signal.signal(signal.SIGINT, forward)
signal.signal(signal.SIGTERM, forward)
child = subprocess.Popen(command, close_fds=False)
code = child.wait()
with open(record + "/runuser.exit", "w") as handle:
    handle.write(str(code))
sys.exit(128 - code if code < 0 else code)
'''


class InitialSetupOperatorReexecWorkflowTests(unittest.TestCase):
    def setUp(self):
        holder = tempfile.TemporaryDirectory(prefix="wp9-reexec-workflow-")
        self.addCleanup(holder.cleanup)
        self.base = Path(holder.name).resolve()   # macOS /var -> /private/var
        self.me = pwd.getpwuid(os.getuid())
        self.tree = self.base / "tree"
        script_dir = self.tree / "infiniband/bringup/xdr-initial-setup"
        script_dir.mkdir(parents=True)
        self.script = script_dir / "initial-setup.py"
        self.script.write_bytes(INITIAL.read_bytes())
        (script_dir / "infra-neutral.conf").write_text("DNS=192.0.2.53\nNTP=192.0.2.123\nTIMEZONE=Etc/UTC\n")
        (self.tree / "tools").mkdir()
        for name in TOOLS:
            (self.tree / "tools" / (name + ".py")).write_bytes((ROOT / "tools" / (name + ".py")).read_bytes())
        self.project = self.tree / "DAY0-Prepare" / "site-a"
        self.project.mkdir(parents=True)
        os.symlink("site-a", self.tree / "DAY0-Prepare" / "activate-project")
        self.home = self.base / "operator-home"
        self.home.mkdir()
        self.work = self.base / "work"
        self.work.mkdir()
        self.launchers = self.base / "launchers"
        self.launchers.mkdir()
        (self.launchers / "root_launcher.py").write_text(ROOT_LAUNCHER, encoding="utf-8")
        (self.launchers / "child_launcher.py").write_text(CHILD_LAUNCHER, encoding="utf-8")
        self.record = self.base / "record"
        self.record.mkdir()

    def stage_runuser(self, scenario: str) -> Path:
        stub = self.base / "bin"
        stub.mkdir(exist_ok=True)
        path = stub / "runuser"
        path.write_text(RUNUSER.format(python=sys.executable, record=str(self.record),
                                       launcher=str(self.launchers / "child_launcher.py"),
                                       yaml_site=site.getusersitepackages(), scenario=scenario),
                        encoding="utf-8")
        path.chmod(0o755)
        return stub

    def start(self, scenario: str, args: list, *, pass_fds=()):
        stub = self.stage_runuser(scenario)
        environment = {"PATH": f"{stub}:/usr/bin:/bin", "LANG": "C", "HOME": str(self.base / "root-home"),
                       "PYTHONUSERBASE": site.getuserbase(), "PYTHONDONTWRITEBYTECODE": "1",
                       "PUBLIC_WP9_INITIAL": secret("environment"), "PUBLIC_WP9_UNRELATED": "1"}
        return subprocess.Popen(
            [sys.executable, "-B", str(self.launchers / "root_launcher.py"), str(self.record), str(self.tree),
             str(self.home), str(self.script), *args],
            cwd=self.work, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, pass_fds=pass_fds, start_new_session=True)

    def events(self) -> list:
        path = self.record / "events"
        return path.read_text().splitlines() if path.is_file() else []

    def absent_inputs(self) -> list:
        # An entry error before any device (exit 2): the IB CSV does not exist.
        return ["--ib-initial-password-env", "PUBLIC_WP9_INITIAL", "--execution-mode", "management",
                "--ib-csv", str(self.work / "absent.csv"), "--p2p", str(self.work / "absent.dot")]

    def test_real_switch_runs_child_through_runuser_stub_and_returns_its_code(self):
        parent = self.start("plain", self.absent_inputs())
        out, err = parent.communicate(timeout=180)
        events = self.events()
        self.assertEqual(2, parent.returncode, err)
        self.assertEqual("2", (self.record / "runuser.exit").read_text(), "the child's own exit code")
        self.assertEqual(1, events.count("runuser"), events)
        self.assertNotIn("guard as root", events)
        self.assertNotIn("main as root", events)
        self.assertIn("resolve " + str(self.project), events, "the project came from the pointer")
        runuser = json.loads((self.record / "runuser.json").read_text())
        self.assertEqual(["-u", self.me.pw_name, "--", "env", "-i"], runuser["argv"][:5])
        child = json.loads((self.record / "child.json").read_text())
        self.assertEqual(str(self.home), child["env"]["HOME"])
        self.assertEqual(secret("environment"), child["env"]["PUBLIC_WP9_INITIAL"])
        self.assertEqual("1", child["env"]["HTTP_ZTP_ROOT_PARENT"])
        # What env -i was given is the whole environment; the interpreter itself may add locale
        # names (PEP 538 LC_CTYPE, macOS __CF_USER_TEXT_ENCODING), so the given set is compared.
        command = runuser["argv"][5:]
        given = {item.split("=", 1)[0] for item in command[:next(
            index for index, item in enumerate(command) if "=" not in item)]}
        self.assertEqual(set(), given - WHITELIST - {"PUBLIC_WP9_INITIAL"},
                         "the child's environment is only the whitelist")
        for name in ("PUBLIC_WP9_UNRELATED", "PYTHONUSERBASE", "PYTHONDONTWRITEBYTECODE"):
            self.assertNotIn(name, child["env"])
        self.assertEqual(self.absent_inputs(), child["args"])
        self.assertIn("absent.csv", err)

    def test_credentials_fd_survives_reexec(self):
        payload = {"nvos_initial_password": secret("fd")}
        reader, writer = os.pipe()
        os.write(writer, json.dumps(payload).encode())
        os.close(writer)
        try:
            parent = self.start("fd", [*self.absent_inputs(), "--credentials-fd", str(reader)],
                                pass_fds=(reader,))
        finally:
            os.close(reader)
        out, err = parent.communicate(timeout=180)
        self.assertEqual(2, parent.returncode, err)
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        self.assertIn("fd " + digest, self.events(), "the child read the same JSON object")
        self.assertNotIn(secret("fd"), out + err)

    def test_sigint_reaches_child_once(self):
        for name, text in (("ib.csv", None), ("p2p.dot", f'"{IB}":"eth0" -- "{JUMP}":"swp1"\n')):
            if text is None:
                with (self.work / name).open("w", newline="") as handle:
                    writer = csv.writer(handle)
                    writer.writerow(["hostname", "type", "eth0_ip", "netmask", "eth0_gw", "eth0_mac"])
                    writer.writerow([IB, "ib", "192.0.2.10", "24", "192.0.2.1", "02:00:00:00:00:0a"])
                    writer.writerow([JUMP, "eth_jump", "198.51.100.10", "", "", ""])
            else:
                (self.work / name).write_text(text)
        (self.record / "sigint.json").write_text(json.dumps({"jump": JUMP, "initial": secret("initial")}))
        args = ["--execution-mode", "management", "--ib-csv", str(self.work / "ib.csv"),
                "--p2p", str(self.work / "p2p.dot"), "--target-cache", str(self.work / "tasks.json"),
                "--report", str(self.work / "report.log"), "--snapshot-dir", str(self.work / "snapshots")]
        parent = self.start("sigint", args)
        marker = self.record / "first-device-command"
        deadline = time.monotonic() + 120
        while not marker.exists() and parent.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertTrue(marker.exists(), "the child reached its first device command")
        os.kill(parent.pid, signal.SIGINT)
        out, err = parent.communicate(timeout=180)
        events = self.events()
        self.assertEqual(1, events.count("child SIGINT"), events)
        self.assertNotIn("device command after the cancel", events)
        self.assertEqual("1", (self.record / "runuser.exit").read_text(), "a normal exit, not a signal")
        self.assertEqual(1, parent.returncode, err)
        self.assertIn("user cancelled the batch", out + err)


if __name__ == "__main__":
    unittest.main()
