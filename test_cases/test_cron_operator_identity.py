"""Direct contract of ethernet/monitor/cron.sh's operator identity step before K4 (v3.1.2 WP-11, M6, I-006).

Expectations come from the requirement texts, never from cron.sh:
- v3.1.2 guide 3.1 已定 2 (owner 2026-11-07「同意你的建议。」, http dev 转述, 落地记录.md:1612): before K4 cron.sh
  re-runs as the operator only when root runs it directly; started by a root parent (the switch-collection worker,
  12-ztp-monitor) it keeps running as root, told by the 「由 root 父进程启动」 marker that WP-4 defines once;
- guide 3.2 (owner 2026-11-07「同意你在v3.1.2里的默认建议」, http dev 转述): O13 - sudo is handled like the
  interactive root (re-run), a root crontab (no SUDO_USER, stdin not a terminal) is not re-run; O12 ① - a root run
  that is not re-run logs in with -i <operator home>/.ssh/id_ed25519 and no IdentitiesOnly; O14 - a non-root run only
  collects (no monitor.html refresh, neither cron.sh's own nor the one inside post-collect) and a code-tree log the
  runner cannot write is skipped while the terminal still gets every line;
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
options and hand back fixture files; the page generator and the Ethernet post-collect record that they ran.
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
           "HTTP_ZTP_ASKPASS_TMPDIR", "FAKE_EUID", "PYTHONPATH")

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
    for name in ("collection_archive.py", "log_rotation.py", "operator_identity.py", "project_contract.py"):
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
        root = self.stage()
        completed = self.run_cron(root, FAKE_EUID=str(ME.pw_uid))
        self.assertTrue(list((root / "infiniband/monitor/ib-info").glob("*.tar.gz")),
                        completed.stdout + completed.stderr)   # it still collects
        self.assertEqual([], records(root, "generator.jsonl"))
        root = self.stage()
        completed = self.run_cron(root, "--air", area="ethernet", FAKE_EUID=str(ME.pw_uid))
        self.assertTrue(list((root / "ethernet/monitor/eth-info").glob("*.tar.gz")),
                        completed.stdout + completed.stderr)
        # the Ethernet page refresh runs inside post-collect, so post-collect is not started either
        self.assertEqual([], records(root, "post-collect.jsonl"))
        self.assertEqual([], records(root, "generator.jsonl"))

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


if __name__ == "__main__":
    unittest.main()
