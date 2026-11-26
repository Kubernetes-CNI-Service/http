"""Direct contract of ethernet/monitor/cron.sh's operator identity step before K4 (v3.1.2 WP-11, M6, I-006).

Expectations come from the requirement texts, never from cron.sh:
- v3.1.2 guide 3.1 已定 2 (owner 2026-11-07「同意你的建议。」, http dev 转述, 落地记录.md:1612): before K4 cron.sh
  re-runs as the operator only when root runs it directly; started by a root parent (the switch-collection worker,
  12-ztp-monitor) it keeps running as root, told by the 「由 root 父进程启动」 marker that WP-4 defines once;
- guide 3.2 (owner 2026-11-07「同意你在v3.1.2里的默认建议」, http dev 转述): O13 - sudo is handled like the
  interactive root (re-run), a root crontab (no SUDO_USER, stdin not a terminal) is not re-run; O12 ① - a root run
  that is not re-run logs in with -i <operator home>/.ssh/id_ed25519 and no IdentitiesOnly; O14 - a non-root run only
  collects (no monitor.html refresh, neither cron.sh's own nor the one inside post-collect; R-038 之后：有 sudo 时经
  sudo 刷新) and a code-tree log the runner cannot write is skipped while the terminal still gets every line;
- R-038 (需求文档 R-038, 05 P-056; owner「我觉得这种情况下应该自动用 sudo 命令来跑，需要密码的话就提示用户输入」,
  http dev 记录第 29 节 :1944; v3.1.6 guide 8.24 :2690-2714): only an operator run that collects only (the operator
  directly, or root / sudo re-run as the operator) hands the two root-side steps to sudo - the Ethernet lane's
  post-collect (it refreshes the page itself) and the page generator - as `sudo -n -- python3 -B <program> <fixed
  arguments>`; only sudo's own "password required" failure leads to `sudo -v` on a terminal, without a terminal
  nothing waits and the complete command is printed; a refused password keeps the collection and its result; a
  failing step is reported as on the root path and never run twice; root parents, root crontab, no pointer and the
  container never call sudo; a program outside the code tree or inside the project directory is never run;
- design `设计/I-006与R-005实现计划.md` §4.3 (:97): root re-runs itself with `runuser -u <operator> --` before doing
  anything, with a whitelisted environment and HOME = the operator's home taken from passwd (§4.2); another ordinary
  user is refused; §4.6: a refusal names who owns the project and who is running;
- §4.2 and guide WP-11 step 1: without a DAY0-Prepare/activate-project pointer there is no operator, cron.sh runs
  unchanged and starts no identity check;
- guide WP-9 现状 / WP-11 step 5 (plan v3.1.2, M6 cron.sh row): a collection lock that cannot be opened is reported
  with its cause, never as "the previous round is still running";
- owner 2026-10-27 scheme item 6 (问题文档 :296-298), the owner 2026-11-06 Docker freeze (开发计划 :112) and http
  dev 2026-11-09 (all M6 packages: Docker must not regress; the project owner's uid is often missing from the
  container's passwd): in the container (cron.sh's own container signals HTTP_ZTP_RUNTIME_BACKEND=supervisor and
  HTTP_ZTP_ASKPASS_TMPDIR) cron.sh behaves as in v3.1.1 and is never stopped for an unknown operator;
- agentOP WP-4 report §2.3 (the module interface): an invalid pointer is an error, never "no project";
- http dev 2026-11-08 (WP-11 dispatch, pending item W11-1 default): when the operator module cannot be imported (for
  example PyYAML is broken) collection is not stopped and one explicit WARN line is printed.

No uid switch happens here (guide 2.2 item 6).  A staged copy of the real cron.sh puts recorders in front of its
pinned PATH (the test_ufm_monitor_cron_workflow precedent): `id -u` answers the euid a case plays while the process
stays the test user; `runuser` records its argv and what already exists when it is reached; ssh/scp record their
options and hand back fixture files; the page generator and the Ethernet post-collect record that they ran; `sudo`
records its argv and plays the sudoers answer named by FAKE_SUDO (the default asks for a password), running the
command as the test user when it lets it through.
"""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import pty
import pwd
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from operator_identity import ROOT_PARENT_MARKER, ROOT_PARENT_MARKER_VALUE  # noqa: E402

COLLECTOR = ROOT / "ethernet/monitor/cron.sh"
PINNED_PATH = "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
PROJECT = "site"
INVENTORY = (
    "hostname,type,eth0_ip\n"
    "EXAMPLE-IB01,ib,192.0.2.11\n"
    "AIR-EXAMPLE-Leaf01,air,192.0.2.10\n"
)
ME = pwd.getpwuid(os.getuid())
OPERATOR_KEY = os.path.join(ME.pw_dir, ".ssh", "id_ed25519")
CLEARED = ("SUDO_USER", "SUDO_UID", "SUDO_GID", "SUDO_COMMAND", ROOT_PARENT_MARKER, "HTTP_ZTP_RUNTIME_BACKEND",
           "HTTP_ZTP_ASKPASS_TMPDIR", "FAKE_EUID", "PYTHONPATH", "FAKE_SUDO", "FAKE_STEP_RC")

ID_STUB = f'''#!/bin/sh
if [ "$1" = "-u" ] && [ -n "${{FAKE_EUID:-}}" ]; then
    printf '%s\\t%s\\n' "${{{ROOT_PARENT_MARKER}:-}}" "${{SUDO_USER:-}}" >> "$FAKE_LOG_DIR/id.log"
    echo "$FAKE_EUID"
    exit 0
fi
exec /usr/bin/id "$@"
'''
# runuser: what the re-run would execute, and whether cron.sh had already made a temporary file or the lock.
RUNUSER_STUB = '''#!{python}
import json, os, sys
record = {{"argv": sys.argv[1:], "tmpdir": sorted(os.listdir(os.environ["TMPDIR"])),
          "lock": os.path.lexists(os.environ["FAKE_LOCK"])}}
with open(os.path.join(os.environ["FAKE_LOG_DIR"], "runuser.jsonl"), "a", encoding="utf-8") as stream:
    stream.write(json.dumps(record) + "\\n")
'''
# ssh/scp: record the options; a remote *.info/*.link fetch gets a complete fixture file.
REMOTE_STUB = '''#!{python}
import json, os, sys
tool = os.path.basename(sys.argv[0])
with open(os.path.join(os.environ["FAKE_LOG_DIR"], "remote.jsonl"), "a", encoding="utf-8") as stream:
    stream.write(json.dumps({{"tool": tool, "argv": sys.argv[1:]}}) + "\\n")
destination = sys.argv[-1]
if tool == "scp" and ":" not in destination and destination.endswith((".info", ".link")):
    with open(destination, "w", encoding="utf-8") as stream:
        stream.write("fixture-info\\n# Collect complete\\n" if destination.endswith(".info") else "port,peer\\n1,fixture\\n")
'''
RECORDER = '''import json, os, sys
with open(os.path.join(os.environ["FAKE_LOG_DIR"], {name!r}), "a", encoding="utf-8") as stream:
    stream.write(json.dumps(sys.argv[1:]) + "\\n")
raise SystemExit(int(os.environ.get("FAKE_STEP_RC", "0")))
'''
# sudo (R-038 guide 8.24: a recorder first on PATH, so the developer machine's real sudo is never reached): record
# the argv; FAKE_SUDO plays the sudoers answer - "nopasswd" lets `-n --` through, "password" (the default) wants a
# password first, which `sudo -v` (a terminal prompt) gives, "refuse" rejects that password.  A command let through
# runs as the test user (no uid switch here, guide 2.2 item 6).
SUDO_STUB = '''#!{python}
import json, os, sys
logs = os.environ["FAKE_LOG_DIR"]
arguments = sys.argv[1:]
with open(os.path.join(logs, "sudo.jsonl"), "a", encoding="utf-8") as stream:
    stream.write(json.dumps(arguments) + "\\n")
mode = os.environ.get("FAKE_SUDO", "password")
validated = os.path.join(logs, "sudo.validated")
if arguments == ["-v"]:
    if mode == "refuse":
        print("sudo: 1 incorrect password attempt", file=sys.stderr)
        sys.exit(1)
    open(validated, "w").close()
    sys.exit(0)
if arguments[:2] != ["-n", "--"] or len(arguments) < 3:
    print("sudo: fixture: unexpected arguments", file=sys.stderr)
    sys.exit(2)
if mode != "nopasswd" and not os.path.exists(validated):
    print("sudo: a password is required", file=sys.stderr)
    sys.exit(1)
os.execvp(arguments[2], arguments[2:])
'''
# flock(1) on the inherited descriptor, as util-linux reports a descriptor that is not open.
FLOCK_STUB = '''#!/bin/sh
for last in "$@"; do :; done
[ -e "/dev/fd/$last" ] || { echo "flock: $last: Bad file descriptor" >&2; exit 1; }
exit 0
'''


def write_exec(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


def stage_tree(root: Path, *, pointer: bool) -> None:
    """The published layout around a copy of the real cron.sh: one project, setup's links, recorders on PATH."""
    source = COLLECTOR.read_text(encoding="utf-8")
    if source.count(PINNED_PATH) != 1:
        raise AssertionError("cron.sh must pin PATH exactly once")
    bin_dir = root / "bin"
    write_exec(root / "ethernet/monitor/cron.sh",
               source.replace(PINNED_PATH, PINNED_PATH.replace("PATH=", f"PATH={bin_dir}:")))
    for name in ("sw-info.sh", "sw-link.sh"):
        shutil.copy2(ROOT / "ethernet/monitor" / name, root / "ethernet/monitor" / name)
    monitor = root / "infiniband/monitor"
    monitor.mkdir(parents=True)
    for name in ("cron.sh", "sw-info.sh", "sw-link.sh"):
        (monitor / name).symlink_to(f"../../ethernet/monitor/{name}")
    # cron.sh's data retention and log rotation, and the operator rule with the pointer reader it imports
    for name in ("collection_archive.py", "log_rotation.py", "operator_identity.py", "project_contract.py", "project_pointer.py"):
        (root / "tools").mkdir(exist_ok=True)
        shutil.copy2(TOOLS / name, root / "tools" / name)
    project = root / "DAY0-Prepare" / PROJECT
    project.mkdir(parents=True)
    (project / "02-devices_config.csv").write_text(INVENTORY, encoding="utf-8")
    key = root / "fixture-management-key"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "fixture", "-f", str(key)],
                   check=True, capture_output=True)
    shutil.copy2(key.with_suffix(".pub"), project / "mgmt-server.pub")
    for area, csv_name in (("ethernet", "eth.csv"), ("infiniband", "ib.csv")):
        (root / area / "monitor" / csv_name).symlink_to(project / "02-devices_config.csv")
        (root / area / "publickey").mkdir()
        (root / area / "publickey/mgmt-server.pub").symlink_to(project / "mgmt-server.pub")
    if pointer:
        (root / "DAY0-Prepare/activate-project").symlink_to(PROJECT)
    write_exec(bin_dir / "python3", f"#!/bin/sh\nexec {shlex.quote(sys.executable)} \"$@\"\n")
    write_exec(bin_dir / "id", ID_STUB)
    write_exec(bin_dir / "runuser", RUNUSER_STUB.format(python=sys.executable))
    for tool in ("ssh", "scp"):
        write_exec(bin_dir / tool, REMOTE_STUB.format(python=sys.executable))
    write_exec(bin_dir / "flock", FLOCK_STUB)
    write_exec(bin_dir / "sudo", SUDO_STUB.format(python=sys.executable))
    write_exec(bin_dir / "sleep", "#!/bin/sh\nexit 0\n")
    write_exec(root / "monitor/generate-monitor-html.py", RECORDER.format(name="generator.jsonl"))
    write_exec(root / "ethernet/monitor/post-collect.py", RECORDER.format(name="post-collect.jsonl"))
    (root / "logs").mkdir()
    (root / "tmp").mkdir()
    (root / "dhcpd.leases").write_text("", encoding="utf-8")
    (root / "dhcp-runtime.log").write_text("", encoding="utf-8")


def fixture_environment(root: Path, area: str = "infiniband", **extra: str) -> dict:
    environment = {name: value for name, value in os.environ.items() if name not in CLEARED}
    environment.update(
        TMPDIR=str(root / "tmp"), FAKE_LOG_DIR=str(root / "logs"),
        FAKE_LOCK=str(root / area / "monitor/cron.lock"), COPYFILE_DISABLE="1",
        DHCP_LEASES_FILE=str(root / "dhcpd.leases"), DHCP_RUNTIME_LOG_FILE=str(root / "dhcp-runtime.log"),
    )
    environment.update(extra)
    return environment


# The project owner's uid missing from passwd, as in a container: every python3 that cron.sh starts sees
# pwd.getpwuid fail for that uid (the staged project belongs to the test user; uids cannot be changed here).
UNKNOWN_OWNER = """import os, pwd
_unknown = int(os.environ["FAKE_UNKNOWN_UID"])
_lookup = pwd.getpwuid


def _getpwuid(uid):
    if uid == _unknown:
        raise KeyError(f"getpwuid(): uid not found: {uid}")
    return _lookup(uid)


pwd.getpwuid = _getpwuid
"""


def unknown_owner(root: Path) -> dict:
    site = root / "unknown-owner-site"
    site.mkdir(exist_ok=True)
    (site / "sitecustomize.py").write_text(UNKNOWN_OWNER, encoding="utf-8")
    return {"PYTHONPATH": str(site), "FAKE_UNKNOWN_UID": str(ME.pw_uid)}


def records(root: Path, name: str) -> list:
    path = root / "logs" / name
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def identity_options(root: Path) -> list:
    """The -i values of every recorded ssh/scp call (None for a call without -i)."""
    found = []
    for call in records(root, "remote.jsonl"):
        argv = call["argv"]
        found.append(argv[argv.index("-i") + 1] if "-i" in argv else None)
    return found


class CronIdentityCase(unittest.TestCase):
    """Fixture only: one staged tree per test."""

    def stage(self, *, pointer: bool = True) -> Path:
        directory = tempfile.TemporaryDirectory(prefix="cron-identity-")
        self.addCleanup(directory.cleanup)
        root = Path(directory.name).resolve()   # macOS /var alias: the path cron.sh sees is the resolved one
        stage_tree(root, pointer=pointer)
        return root

    def run_cron(self, root: Path, *args: str, area: str = "infiniband", tty: bool = False,
                 **extra: str) -> subprocess.CompletedProcess:
        command = ["bash", str(root / area / "monitor/cron.sh"), *args]
        environment = fixture_environment(root, area, **extra)
        if not tty:
            return subprocess.run(command, cwd=root, env=environment, stdin=subprocess.DEVNULL,
                                  capture_output=True, text=True, timeout=120, check=False)
        controller, terminal = pty.openpty()
        try:
            return subprocess.run(command, cwd=root, env=environment, stdin=terminal,
                                  capture_output=True, text=True, timeout=120, check=False)
        finally:
            os.close(terminal)
            os.close(controller)

    def assert_reexec(self, root: Path, completed: subprocess.CompletedProcess, *args: str) -> None:
        calls = records(root, "runuser.jsonl")
        self.assertEqual(1, len(calls), completed.stdout + completed.stderr)
        argv = calls[0]["argv"]
        # design §4.3 (:97): runuser -u <operator> --, a whitelisted environment, HOME from passwd (§4.2)
        self.assertEqual(["-u", ME.pw_name, "--", "env", "-i"], argv[:5])
        bash = argv.index("bash")
        assignments = dict(item.split("=", 1) for item in argv[5:bash])
        self.assertEqual(ME.pw_dir, assignments["HOME"])
        self.assertEqual(ME.pw_name, assignments["USER"])
        self.assertEqual(ME.pw_name, assignments["LOGNAME"])
        self.assertLessEqual(set(assignments), {"PATH", "LANG", "LC_ALL", "TERM", "HOME", "USER", "LOGNAME"})
        self.assertEqual([str(root / "infiniband/monitor/cron.sh"), *args], argv[bash + 1:])
        # before any temporary file or the collection lock (guide WP-11 first test)
        self.assertEqual([], calls[0]["tmpdir"])
        self.assertFalse(calls[0]["lock"])
        self.assertEqual([], records(root, "remote.jsonl"))


class CronOperatorIdentityTests(CronIdentityCase):
    def test_interactive_root_without_marker_reexecs_via_runuser_before_mktemp_and_lock(self):
        root = self.stage()
        completed = self.run_cron(root, "--wait-lock", "0", tty=True, FAKE_EUID="0")
        self.assert_reexec(root, completed, "--wait-lock", "0")

    def test_sudo_without_marker_reexecs(self):
        root = self.stage()
        completed = self.run_cron(root, "--type", "ib", FAKE_EUID="0",
                                  SUDO_USER=ME.pw_name, SUDO_UID=str(ME.pw_uid))
        self.assert_reexec(root, completed, "--type", "ib")

    def test_root_with_marker_does_not_reexec(self):
        root = self.stage()
        completed = self.run_cron(root, tty=True, FAKE_EUID="0", SUDO_USER=ME.pw_name, SUDO_UID=str(ME.pw_uid),
                                  **{ROOT_PARENT_MARKER: ROOT_PARENT_MARKER_VALUE})
        self.assertEqual([], records(root, "runuser.jsonl"), completed.stderr)
        # 已定 2: it keeps running as root for the operator, so it logs in with the operator's key (O12 ①)
        self.assertTrue(identity_options(root), completed.stdout + completed.stderr)
        self.assertEqual({OPERATOR_KEY}, set(identity_options(root)))

    def test_root_crontab_without_tty_does_not_reexec(self):
        root = self.stage()
        completed = self.run_cron(root, FAKE_EUID="0")
        self.assertEqual([], records(root, "runuser.jsonl"), completed.stderr)
        self.assertTrue(identity_options(root), completed.stdout + completed.stderr)
        self.assertEqual({OPERATOR_KEY}, set(identity_options(root)))

    def test_root_run_uses_operator_identity_file(self):
        root = self.stage()
        completed = self.run_cron(root, FAKE_EUID="0", **{ROOT_PARENT_MARKER: ROOT_PARENT_MARKER_VALUE})
        calls = records(root, "remote.jsonl")
        self.assertTrue(calls, completed.stdout + completed.stderr)
        self.assertEqual({"ssh", "scp"}, {call["tool"] for call in calls})
        # O12 ①: every key login (ssh and scp) offers the operator's key first; no IdentitiesOnly, so root's own
        # keys stay the fallback while the switches still trust them
        self.assertEqual([OPERATOR_KEY] * len(calls), identity_options(root))
        self.assertFalse(any("IdentitiesOnly" in item for call in calls for item in call["argv"]))
        # a root run refreshes the page as before (O14 concerns only non-root runs)
        self.assertEqual([["--type", "prod"]], records(root, "generator.jsonl"))

    def test_other_user_refused(self):
        root = self.stage()
        other = next(entry for entry in sorted(pwd.getpwall(), key=lambda item: item.pw_uid)
                     if entry.pw_uid not in (0, ME.pw_uid) and entry.pw_uid > 0)
        completed = self.run_cron(root, FAKE_EUID=str(other.pw_uid))
        self.assertNotEqual(0, completed.returncode)
        # design §4.6: the refusal names who owns the project and who is running
        self.assertIn(ME.pw_name, completed.stderr)
        self.assertIn(other.pw_name, completed.stderr)
        self.assertEqual([], records(root, "runuser.jsonl"))
        self.assertEqual([], records(root, "remote.jsonl"))
        self.assertEqual([], sorted(os.listdir(root / "tmp")))
        self.assertFalse((root / "infiniband/monitor/cron.lock").exists())

    def test_no_pointer_runs_unchanged(self):
        root = self.stage(pointer=False)
        with self.subTest(run="root from a terminal"):
            completed = self.run_cron(root, tty=True, FAKE_EUID="0")
            self.assertEqual([], records(root, "runuser.jsonl"))
            self.assertNotIn("[IDENTITY]", completed.stderr)
            self.assertTrue(identity_options(root), completed.stdout + completed.stderr)
            self.assertEqual({None}, set(identity_options(root)))
        root = self.stage(pointer=False)
        with self.subTest(run="ordinary user"):
            completed = self.run_cron(root, FAKE_EUID=str(ME.pw_uid))
            self.assertNotIn("[IDENTITY]", completed.stderr)
            # nothing decides "collect only" without an operator: the page is refreshed as before
            self.assertEqual([["--type", "prod"]], records(root, "generator.jsonl"),
                             completed.stdout + completed.stderr)

    def test_non_root_run_skips_page_refresh(self):
        # R-038 (guide 8.24「要改的现有断言」, 8.21.M3): O14 now holds for the branch without a terminal where sudo
        # wants a password (the fixture sudo's default); the zero-run assertions stay, and the log carries the
        # complete command to run
        root = self.stage()
        completed = self.run_cron(root, FAKE_EUID=str(ME.pw_uid))
        self.assertTrue(list((root / "infiniband/monitor/ib-info").glob("*.tar.gz")),
                        completed.stdout + completed.stderr)   # it still collects
        self.assertEqual([], records(root, "generator.jsonl"))
        self.assertIn(f"sudo python3 -B {root / 'monitor/generate-monitor-html.py'} --type prod",
                      completed.stdout + completed.stderr)
        root = self.stage()
        completed = self.run_cron(root, "--air", area="ethernet", FAKE_EUID=str(ME.pw_uid))
        archives = list((root / "ethernet/monitor/eth-info").glob("*.tar.gz"))
        self.assertTrue(archives, completed.stdout + completed.stderr)
        # the Ethernet page refresh runs inside post-collect, so post-collect is not started either
        self.assertEqual([], records(root, "post-collect.jsonl"))
        self.assertEqual([], records(root, "generator.jsonl"))
        self.assertIn(f"sudo python3 -B {root / 'ethernet/monitor/post-collect.py'} --archive {archives[0]} "
                      "--environment air", completed.stdout + completed.stderr)

    def test_lock_open_failure_reports_cause_not_previous_round(self):
        root = self.stage(pointer=False)
        lock = root / "infiniband/monitor/cron.lock"
        lock.write_text("", encoding="utf-8")
        lock.chmod(0o000)
        self.addCleanup(lock.chmod, 0o600)
        completed = self.run_cron(root)
        self.assertEqual(1, completed.returncode)
        self.assertIn("无法打开采集锁", completed.stderr)
        self.assertIn(str(lock), completed.stderr)
        self.assertIn("Permission denied", completed.stderr)
        self.assertNotIn("上一轮", completed.stderr)
        self.assertEqual([], records(root, "remote.jsonl"))

    def test_unwritable_tree_log_goes_to_terminal_only(self):
        root = self.stage(pointer=False)
        monitor = root / "infiniband/monitor"
        (monitor / "ib.csv").unlink()   # stop right after the first log lines
        (monitor / "cron.lock").write_text("", encoding="utf-8")
        monitor.chmod(0o555)
        self.addCleanup(monitor.chmod, 0o755)
        controller, terminal = pty.openpty()
        chunks = []

        def drain():
            while True:
                try:
                    data = os.read(controller, 4096)
                except OSError:
                    return
                if not data:
                    return
                chunks.append(data)

        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        try:
            completed = subprocess.run(["bash", str(monitor / "cron.sh")], cwd=root,
                                       env=fixture_environment(root), stdin=subprocess.DEVNULL,
                                       stdout=terminal, stderr=subprocess.PIPE, text=True, timeout=60,
                                       check=False)
        finally:
            os.close(terminal)
            reader.join(timeout=10)
            os.close(controller)
        shown = b"".join(chunks).decode("utf-8", errors="replace")
        self.assertIn("cron start", shown)
        self.assertNotIn("Permission denied", completed.stderr)
        self.assertEqual([], [path.name for path in monitor.glob("cron.sh-*.log")])

    def test_container_runtime_keeps_root_unchanged(self):
        # http dev 2026-11-09 (all M6 packages): Docker must not regress.  The container runs as root and the
        # project owner's uid is often missing from the container's passwd; started by the worker or
        # 12-ztp-monitor there, cron.sh behaves as in v3.1.1 (as without any operator: no re-run, no operator
        # key, collection and page refresh as before) and is never stopped for an unknown operator.
        container = {"supervisor backend": {"HTTP_ZTP_RUNTIME_BACKEND": "supervisor"},
                     "askpass directory": {"HTTP_ZTP_ASKPASS_TMPDIR": "/run/http-ztp/askpass"}}
        for label, signal in container.items():
            for parent, extra in (("root parent", {ROOT_PARENT_MARKER: ROOT_PARENT_MARKER_VALUE}),
                                  ("terminal", {})):
                with self.subTest(container=label, run=parent):
                    root = self.stage()
                    completed = self.run_cron(root, tty=not extra, FAKE_EUID="0",
                                              **unknown_owner(root), **signal, **extra)
                    self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
                    self.assertNotIn("[IDENTITY]", completed.stderr)
                    self.assertEqual([], records(root, "runuser.jsonl"))
                    self.assertTrue(identity_options(root), completed.stdout + completed.stderr)
                    self.assertEqual({None}, set(identity_options(root)))
                    self.assertEqual([["--type", "prod"]], records(root, "generator.jsonl"))
        # control: the same unknown owner on the native backend is what the container must not run into
        root = self.stage()
        completed = self.run_cron(root, FAKE_EUID="0", **unknown_owner(root),
                                  **{ROOT_PARENT_MARKER: ROOT_PARENT_MARKER_VALUE})
        self.assertNotEqual(0, completed.returncode)
        self.assertIn("passwd", completed.stderr)
        self.assertEqual([], records(root, "remote.jsonl"))

    def test_invalid_pointer_is_refused(self):
        root = self.stage()
        pointer = root / "DAY0-Prepare/activate-project"
        pointer.unlink()
        pointer.symlink_to("no-such-project")
        completed = self.run_cron(root, FAKE_EUID="0")
        self.assertNotEqual(0, completed.returncode)
        self.assertIn("activate-project", completed.stderr)
        self.assertEqual([], records(root, "runuser.jsonl"))
        self.assertEqual([], records(root, "remote.jsonl"))
        self.assertEqual([], sorted(os.listdir(root / "tmp")))

    def test_unimportable_operator_module_warns_and_collects_as_before(self):
        root = self.stage()
        # PyYAML broken: project_contract's `import yaml` finds this module first (tools/ leads sys.path)
        (root / "tools/yaml.py").write_text("raise ImportError('fixture: PyYAML is broken')\n", encoding="utf-8")
        with self.subTest(run="root from a terminal"):
            completed = self.run_cron(root, tty=True, FAKE_EUID="0")
            self.assertEqual(1, completed.stderr.count("[IDENTITY] WARN"), completed.stderr)
            self.assertIn("PyYAML is broken", completed.stderr)
            self.assertEqual([], records(root, "runuser.jsonl"))
            self.assertTrue(identity_options(root), completed.stdout + completed.stderr)
            self.assertEqual({None}, set(identity_options(root)))
            self.assertEqual([["--type", "prod"]], records(root, "generator.jsonl"))
        root = self.stage()
        (root / "tools/yaml.py").write_text("raise ImportError('fixture: PyYAML is broken')\n", encoding="utf-8")
        with self.subTest(run="ordinary user"):
            completed = self.run_cron(root, FAKE_EUID=str(ME.pw_uid))
            self.assertEqual(1, completed.stderr.count("[IDENTITY] WARN"), completed.stderr)
            # no operator was determined, so nothing switches this run to "collect only"
            self.assertEqual([["--type", "prod"]], records(root, "generator.jsonl"),
                             completed.stdout + completed.stderr)

    def test_marker_literal_matches_operator_identity_constant(self):
        # 已定 2: the marker is defined once (WP-4); cron.sh leaves the decision to operator_identity.needs_reexec
        cron = COLLECTOR.read_text(encoding="utf-8")
        self.assertEqual(set(), set(re.findall(r"HTTP_ZTP_[A-Z_]*PARENT[A-Z_]*", cron)) - {ROOT_PARENT_MARKER})
        self.assertIn("operator_identity.needs_reexec(", cron)
        # guide WP-11 step 3: the two root parents import the constant and never spell it
        for relative in ("monitor/switch-collection-worker.py", "DAY0-Prepare/12-ztp-monitor.py"):
            with self.subTest(parent=relative):
                tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
                modules = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
                           for alias in node.names}
                modules |= {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
                self.assertIn("operator_identity", modules)
                names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
                names |= {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
                self.assertLessEqual({"ROOT_PARENT_MARKER", "ROOT_PARENT_MARKER_VALUE"}, names)
                literals = {node.value for node in ast.walk(tree)
                            if isinstance(node, ast.Constant) and isinstance(node.value, str)}
                self.assertNotIn(ROOT_PARENT_MARKER, literals)


LANES = ("ethernet", "infiniband")


class CronOperatorSudoRefreshTests(CronIdentityCase):
    """R-038: an operator run that only collects hands the root-side step to sudo (guide 8.24 先写的测试)."""

    def operator_run(self, area: str, *, tty: bool = False, **extra: str):
        root = self.stage()
        arguments = ("--air",) if area == "ethernet" else ()
        completed = self.run_cron(root, *arguments, area=area, tty=tty, FAKE_EUID=str(ME.pw_uid), **extra)
        return root, completed, completed.stdout + completed.stderr

    def root_step(self, root: Path, area: str) -> tuple:
        """This lane's root-side program with its fixed arguments, and the recorder that notes it ran (8.24 第 2 条:
        the Ethernet lane's post-collect with this run's archive and environment; the page generator)."""
        if area == "ethernet":
            archives = sorted((root / "ethernet/monitor/eth-info").glob("*.tar.gz"))
            self.assertEqual(1, len(archives), archives)
            return ([str(root / "ethernet/monitor/post-collect.py"), "--archive", str(archives[0]),
                     "--environment", "air"], "post-collect.jsonl")
        self.assertTrue(list((root / "infiniband/monitor/ib-info").glob("*.tar.gz")))   # it collected
        return [str(root / "monitor/generate-monitor-html.py"), "--type", "prod"], "generator.jsonl"

    def assert_ran(self, root: Path, step: list, record: str, times: int) -> None:
        expected = {"post-collect.jsonl": [], "generator.jsonl": []}
        expected[record] = [step[1:]] * times
        for name, value in expected.items():
            self.assertEqual(value, records(root, name), name)

    def test_operator_run_refreshes_through_passwordless_sudo(self):
        # owner :1944「我觉得这种情况下应该自动用 sudo 命令来跑」; R-038; guide 8.24 第 2 条 (sudo -n --, python3 -B,
        # no -E); the Ethernet page is refreshed inside post-collect, so nothing refreshes it a second time
        for area in LANES:
            with self.subTest(area=area):
                root, completed, output = self.operator_run(area, FAKE_SUDO="nopasswd")
                step, record = self.root_step(root, area)
                self.assertEqual([["-n", "--", "python3", "-B", *step]], records(root, "sudo.jsonl"), output)
                self.assert_ran(root, step, record, 1)
                self.assertEqual(0, completed.returncode, output)

    def test_operator_run_asks_for_the_password_on_a_terminal(self):
        # owner :1944「需要密码的话就提示用户输入」; guide 8.24 第 2 条: only sudo's own password failure leads to
        # `sudo -v` on a terminal, then one more `sudo -n --`
        for area in LANES:
            with self.subTest(area=area):
                root, completed, output = self.operator_run(area, tty=True, FAKE_SUDO="password")
                step, record = self.root_step(root, area)
                command = ["-n", "--", "python3", "-B", *step]
                self.assertEqual([command, ["-v"], command], records(root, "sudo.jsonl"), output)
                self.assert_ran(root, step, record, 1)
                self.assertEqual(0, completed.returncode, output)

    def test_without_a_terminal_it_does_not_wait_and_prints_the_command(self):
        # R-038「无TTY不挂起」; guide 8.24 第 2 条「没有终端 → 不等待，打 … 请执行：sudo python3 -B <程序> <参数>」,
        # collection products and the exit code as before (an operator run that only collects exits 0)
        for area in LANES:
            with self.subTest(area=area):
                root, completed, output = self.operator_run(area, FAKE_SUDO="password")
                step, record = self.root_step(root, area)
                self.assertEqual([["-n", "--", "python3", "-B", *step]], records(root, "sudo.jsonl"), output)
                self.assert_ran(root, step, record, 0)
                self.assertIn("[ROOT-STEP]", output)
                self.assertIn("没有终端", output)
                self.assertIn("monitor.html 未刷新", output)
                self.assertIn(f"sudo python3 -B {' '.join(step)}", output)
                self.assertEqual(0, completed.returncode, output)

    def test_a_refused_or_cancelled_password_keeps_the_collection(self):
        # R-038「拒绝取消保采集」; guide 8.24 第 2 条「密码被拒或取消 → 打「未刷新（sudo 未通过）」… 不置
        # collection_failed」, 第 3 条「没有权限时按「未通过」处理并打出命令」
        for area in LANES:
            with self.subTest(area=area):
                root, completed, output = self.operator_run(area, tty=True, FAKE_SUDO="refuse")
                step, record = self.root_step(root, area)
                self.assertEqual([["-n", "--", "python3", "-B", *step], ["-v"]], records(root, "sudo.jsonl"), output)
                self.assert_ran(root, step, record, 0)
                self.assertIn("未刷新（sudo 未通过）", output)
                self.assertIn(f"sudo python3 -B {' '.join(step)}", output)
                self.assertNotIn("refresh failed", output)
                self.assertEqual(0, completed.returncode, output)

    def test_a_failing_refresh_is_not_retried(self):
        # R-038「认证失败与child失败分开且不二跑」; guide 8.24 第 2 条「执行失败 → 与 root 路径同语义 … 不重试」
        # (the root path's lines: ETH :2809-2812 and IB/NV :2841-2842 at 26ae34b)
        for mode, tty in (("nopasswd", False), ("password", True)):
            for area in LANES:
                with self.subTest(sudo=mode, area=area):
                    root, completed, output = self.operator_run(area, tty=tty, FAKE_SUDO=mode, FAKE_STEP_RC="1")
                    step, record = self.root_step(root, area)
                    self.assert_ran(root, step, record, 1)
                    self.assertIn("refresh failed", output)
                    self.assertNotIn("sudo 未通过", output)
                    self.assertNotEqual(0, completed.returncode, output)

    def test_root_parent_and_root_crontab_never_call_sudo(self):
        # R-038「root/无人worker不变」; guide 8.24 第 1 条: root, the root-parent marker, root crontab, no pointer and
        # the container stay as before and never call sudo (the fixture sudo would let everything through)
        cases = {
            "root parent marker": ({"FAKE_EUID": "0", ROOT_PARENT_MARKER: ROOT_PARENT_MARKER_VALUE}, True),
            "root crontab": ({"FAKE_EUID": "0"}, True),
            "no pointer, ordinary user": ({"FAKE_EUID": str(ME.pw_uid)}, False),
            "container": ({"FAKE_EUID": "0", "HTTP_ZTP_RUNTIME_BACKEND": "supervisor"}, True),
        }
        for label, (extra, pointer) in cases.items():
            for area in LANES:
                with self.subTest(run=label, area=area):
                    root = self.stage(pointer=pointer)
                    arguments = ("--air",) if area == "ethernet" else ()
                    completed = self.run_cron(root, *arguments, area=area, FAKE_SUDO="nopasswd", **extra)
                    output = completed.stdout + completed.stderr
                    self.assertEqual([], records(root, "sudo.jsonl"), output)
                    step, record = self.root_step(root, area)
                    self.assert_ran(root, step, record, 1)   # the root side runs the step itself, as before
                    self.assertNotIn("[ROOT-STEP]", output)

    def test_the_root_step_only_runs_the_two_code_tree_programs(self):
        # R-038「项目可写内容不得控制root执行」; guide 8.24 第 2 条: the program's realpath stays under the code tree
        # and outside the project directory DAY0-Prepare/activate-project selects
        outside = tempfile.TemporaryDirectory(prefix="cron-root-step-outside-")
        self.addCleanup(outside.cleanup)
        for label, area, relative in (("post-collect in the project", "ethernet", "ethernet/monitor/post-collect.py"),
                                      ("generator in the project", "infiniband", "monitor/generate-monitor-html.py"),
                                      ("post-collect outside the tree", "ethernet", "ethernet/monitor/post-collect.py")):
            with self.subTest(case=label):
                root = self.stage()
                record = "post-collect.jsonl" if "post-collect" in relative else "generator.jsonl"
                place = (Path(outside.name).resolve() / f"{area}-{Path(relative).name}" if "outside" in label
                         else root / "DAY0-Prepare" / PROJECT / Path(relative).name)
                write_exec(place, RECORDER.format(name=record))
                (root / relative).unlink()
                (root / relative).symlink_to(place)
                arguments = ("--air",) if area == "ethernet" else ()
                completed = self.run_cron(root, *arguments, area=area, FAKE_EUID=str(ME.pw_uid),
                                          FAKE_SUDO="nopasswd")
                output = completed.stdout + completed.stderr
                self.assertEqual([], records(root, "sudo.jsonl"), output)
                self.assertEqual([], records(root, record))
                refusal = [line for line in output.splitlines() if "[ROOT-STEP]" in line]
                self.assertTrue(refusal, output)
                self.assertIn(str(place), "\n".join(refusal))


if __name__ == "__main__":
    unittest.main()
