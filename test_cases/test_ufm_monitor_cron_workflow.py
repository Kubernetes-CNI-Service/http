"""Workflow: the real cron.sh runs the real ufm-info.sh on each server_ufm and archives the snapshots
(infiniband/monitor/UFM-MONITOR.md). SSH/SCP reach per-IP sandboxes; the UFM commands are fakes."""

from array import array
import json
import os
import re
import select
import shlex
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from pathlib import Path

from test_cases.test_ufm_monitor_scripts import FAKE_DOCKER, FAKES

ROOT = Path(__file__).resolve().parents[1]
UFMS = {
    "ufm01.example.test": ("198.51.101.130", "02:00:00:00:01:01"),
    "ufm02.example.test": ("198.51.101.132", "02:00:00:00:02:01"),
}
MGMT = ("mgmt01.example.test", "198.51.101.140", "02:00:00:00:03:01")
VIP = "198.51.101.133"
PINNED_PATH = "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
# The owner timing (wait a minute, then every 5 s), shortened in the staged copy only.
TIMING = {"RETRIEVE_FIRST_WAIT=60": "RETRIEVE_FIRST_WAIT=1", "RETRIEVE_POLL=5 ": "RETRIEVE_POLL=1 ",
          # owner 2026-10-22: 5 minutes / 30 s / 17 minutes for ibdiagnet and iblinkinfo
          "UFM_IBDIAG_FIRST_WAIT=300": "UFM_IBDIAG_FIRST_WAIT=1", "UFM_IBDIAG_POLL=30": "UFM_IBDIAG_POLL=1",
          "UFM_IBDIAG_WAIT=1020": "UFM_IBDIAG_WAIT=60"}

_CUSTODY_FD = "FAKE_UFM_CUSTODY_FD"
_REMOTE_CLEANUP_SECONDS = 10
_CRON_SECONDS = 240
_FD_SIZE = array("i").itemsize


def _send_fds(channel, tag, fds):
    if channel.sendmsg([tag], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array("i", fds))]) != 1:
        raise RuntimeError("incomplete fixture descriptor transfer")


def _receive_fds(channel):
    """Receive a single local admission with an exact, tag-specific rights count."""
    # Leave headroom to enumerate and release invalid excess rights too.
    # On Darwin a narrowly tailored buffer truncated the synthetic
    # seven-right negative control before all of its pipe ends were observable.
    # The larger bounded receive space does not change which packets are valid.
    tag, ancillary, flags, _ = channel.recvmsg(1, socket.CMSG_SPACE(64 * 1024))
    expected = {b"R": 5, b"X": 1}.get(tag)
    received = []
    malformed = False
    try:
        for level, kind, data in ancillary:
            if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                malformed = True
                continue
            remainder = len(data) % _FD_SIZE
            malformed |= bool(remainder)
            values = array("i")
            # Even a rejected message may contain a prefix of complete
            # rights that the kernel installed in this process.
            values.frombytes(data[:len(data) - remainder])
            received.extend(values)
        if malformed or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(received) != expected:
            raise RuntimeError("truncated or incomplete fixture descriptor transfer")
        for fd in received:
            os.set_inheritable(fd, False)
        return tag, received
    except BaseException:
        for fd in received:
            os.close(fd)
        raise


def _receive_exact(channel, size):
    data = bytearray()
    while len(data) < size:
        chunk = channel.recv(size - len(data))
        if not chunk:
            raise EOFError("fixture custody channel closed")
        data.extend(chunk)
    return bytes(data)


_REMOTE_SESSION_ANCHOR = r"""
import os, signal, socket, struct, subprocess, sys
status_fd, release_fd, writer_fd, stdin_fd, stdout_fd, stderr_fd = map(int, sys.argv[1:7])
# Install a caught handler, not SIG_IGN: exec resets this handler in the real Bash.
signal.signal(signal.SIGTERM, lambda signum, frame: None)
with socket.socket(fileno=status_fd) as reply:
    try:
        env = dict(os.environ, FAKE_UFM_WRITER_FD=str(writer_fd))
        remote = subprocess.Popen(["bash", "-c", sys.argv[7]], env=env,
                                  stdin=stdin_fd, stdout=stdout_fd, stderr=stderr_fd,
                                  pass_fds=(writer_fd,))
    finally:
        for fd in (stdin_fd, stdout_fd, stderr_fd, writer_fd):
            os.close(fd)
    try:
        reply.sendall(struct.pack("!i", remote.wait()))
    except (BrokenPipeError, ConnectionResetError):
        pass
try:
    # The original Popen remains the private group leader after Bash has
    # returned. Only the test parent can release it, after writer EOF.
    if os.read(release_fd, 1):
        raise RuntimeError("unexpected UFM custody release byte")
finally:
    os.close(release_fd)
"""


def _signal_retained_group(process, signum):
    """PID is meaningful only in the custody of this unreaped Popen."""
    if process.returncode is not None:
        raise ProcessLookupError("the original fixture session has already been reaped")
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        raise RuntimeError("the fixture requires original child reaping")
    os.killpg(process.pid, signum)


class _OwnedRemoteSession:
    def __init__(self, process, writer_reader, release_writer):
        self.process = process
        self.writer_reader = writer_reader
        self.release_writer = release_writer

    def writer_stopped(self):
        if not select.select([self.writer_reader], [], [], 0)[0]:
            return False
        if os.read(self.writer_reader, 1):
            raise RuntimeError("the synthetic UFM writer guard is not a data channel")
        return True

    def reap(self, deadline):
        if self.release_writer is not None:
            os.close(self.release_writer)
            self.release_writer = None
        self.process.wait(timeout=max(0, deadline - time.monotonic()))
        os.close(self.writer_reader)


class _RemoteSessionCustodian:
    """Private FD-only launch channel for the already-local fake SSH.

    Each invocation hands back the original status and standard streams. Only
    this test process launches and owns the actual session leaders. It never
    resolves process IDs by path or a filesystem record.
    """

    def __init__(self, root, owned):
        self.root, self.owned = root, owned
        self.server, self.client = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.deadline = time.monotonic() + _CRON_SECONDS
        self.cleanup_deadline = None
        self.closing = threading.Event()
        self.error = None
        self.thread = threading.Thread(target=self._serve, name="ufm-fixture-custody", daemon=True)

    def _serve(self):
        try:
            while True:
                tag, fds = _receive_fds(self.server)
                try:
                    if tag == b"X":
                        return
                    request = socket.socket(fileno=fds[0])
                    # Only the request socket now owns the reply endpoint.
                    fds = fds[1:]
                    with request:
                        if (request.family != socket.AF_UNIX
                                or request.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM):
                            raise RuntimeError("invalid synthetic UFM reply stream")
                        if self.closing.is_set():
                            continue
                        remaining = self.deadline - time.monotonic()
                        if remaining <= 0:
                            raise TimeoutError("UFM custody request exceeded the original cron deadline")
                        request.settimeout(remaining)
                        # Do not read the frame until the sender knows the broker
                        # owns the originally transferred reply endpoint. The ACK
                        # uses its own pipe: rejection must still be visible as EOF
                        # while the sender holds both sides of the reply socket.
                        ack = fds[-1]
                        if not stat.S_ISFIFO(os.fstat(ack).st_mode):
                            raise RuntimeError("invalid UFM fixture confirmation pipe")
                        os.set_blocking(ack, False)
                        if os.write(ack, b"A") != 1:
                            raise RuntimeError("incomplete UFM fixture admission confirmation")
                        fds = fds[:-1]
                        os.close(ack)
                        self._launch(request, fds)
                finally:
                    for fd in fds:
                        os.close(fd)
        except BaseException as exc:
            self.error = exc
        finally:
            # Closing the receiving endpoint also releases any undelivered
            # SCM_RIGHTS in the queue. Their private reply streams can then
            # observe EOF instead of waiting for the whole cron deadline.
            self.server.close()

    def _launch(self, request, stream_fds):
        release_reader = release_writer = writer_reader = writer = None
        try:
            size, = struct.unpack("!I", _receive_exact(request, 4))
            if not 0 < size <= os.sysconf("SC_ARG_MAX"):
                raise RuntimeError("invalid synthetic UFM request size")
            payload = json.loads(_receive_exact(request, size))
            command, cwd, env = payload["command"], Path(payload["cwd"]), payload["env"]
            if (cwd.resolve() != cwd or cwd.parent.parent != self.root / "hosts" or cwd.name != "root"
                    or env.get("HOME") != str(cwd) or env.get("TMPDIR") != str(cwd.parent / "tmp")):
                raise RuntimeError("fake SSH attempted to leave its private UFM home")
            env.pop(_CUSTODY_FD, None)
            if self.closing.is_set():
                raise RuntimeError("UFM fixture admissions already closed")
            release_reader, release_writer = os.pipe()
            writer_reader, writer = os.pipe()
            control = (request.fileno(), release_reader, writer, *stream_fds)
            process = subprocess.Popen(
                [sys.executable, "-I", "-S", "-B", "-c", _REMOTE_SESSION_ANCHOR,
                 *(str(fd) for fd in control), command],
                cwd=cwd, env=env, start_new_session=True, pass_fds=control,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            self.owned.append(_OwnedRemoteSession(process, writer_reader, release_writer))
            writer_reader = release_writer = None
            # Diagnostic only: no shutdown or probe reads this file.
            with (self.root / "remote-sessions").open("a", encoding="ascii") as record:
                record.write(f"{process.pid}\n")
        finally:
            for fd in (release_reader, release_writer, writer_reader, writer):
                if fd is not None:
                    os.close(fd)

    def __enter__(self):
        try:
            if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
                raise RuntimeError("the test harness must keep its original owned children")
            self.thread.start()
        except BaseException:
            self.server.close()
            self.client.close()
            raise
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.closing.set()
        try:
            # The cron has already returned; only the actual parent sends the
            # sentinel on its private endpoint. Ancillary remains exactly one fd.
            transport_error = None
            if self.thread.is_alive():
                try:
                    _send_fds(self.client, b"X", [self.client.fileno()])
                except OSError as rejected:
                    # The broker may have just failed and closed its endpoint.
                    # Join before deciding which error is the first cause.
                    transport_error = rejected
            self.thread.join(timeout=max(0, self.deadline - time.monotonic()))
            if self.thread.is_alive():
                # An expired cron leaves no read deadline. Share this wait with
                # the original 10-second TERM phase, never add a third phase.
                self.cleanup_deadline = time.monotonic() + _REMOTE_CLEANUP_SECONDS
                self.thread.join(timeout=max(0, self.cleanup_deadline - time.monotonic()))
            if self.thread.is_alive() and exc is None:
                raise RuntimeError("UFM custody admissions have not closed")
            if self.error is not None and (exc is None or isinstance(exc, subprocess.TimeoutExpired)):
                raise self.error from exc
            if transport_error is not None and exc is None:
                raise transport_error
        finally:
            self.server.close()
            self.client.close()

# ssh/scp stand-ins: user@IP is the sandbox <root>/hosts/<IP>; "/root/" maps into it.
FAKE_REMOTE = r'''#!{python}
from array import array
import glob, json, os, shutil, socket, struct, subprocess, sys
REQUIRE_CUSTODY = False
state = json.load(open(os.environ["FAKE_UFM_STATE"]))
tool = os.path.basename(sys.argv[0])
args, words = sys.argv[1:], []
i = 0
while i < len(args):
    if args[i] == "-o":
        i += 2
        continue
    if args[i].startswith("-") and len(words) == 0 and args[i] != "--":
        i += 1
        continue
    words.append(args[i])
    i += 1
log = open(os.environ["FAKE_UFM_CALLS"], "a")
def home(ip):
    return os.path.join(os.environ["FAKE_UFM_HOSTS"], ip)
def local(ip, path):
    # /home/admin: an IB switch's monitor directory (cron.sh IB_REMOTE_DIR), also kept in the sandbox
    for top in ("/root", "/home/admin"):
        if path.startswith(top):
            return path.replace(top, home(ip) + top, 1)
    return path
def down(ip):
    if ip in state.get("down", []) or ip not in state["ufms"]:
        print(f"ssh: connect to host {ip} port 22: Connection timed out", file=sys.stderr)
        sys.exit(255)
FAILOVER = os.path.join(os.environ["FAKE_UFM_HOSTS"], "failover-done")
def holder(ip):
    # owner 2026-10-22: `ufm_ha_cluster failover` moves the VIP to the other UFM at any moment
    if os.path.exists(FAILOVER) and ip in state.get("failover", {}).get("vip", {}):
        return state["failover"]["vip"][ip]
    return state.get("vip", {}).get(ip, ip)
def refuse_key(ip):
    if ip in state.get("no_key", []) and "BatchMode=yes" in sys.argv:
        print(f"root@{ip}: Permission denied (publickey,password).", file=sys.stderr)
        sys.exit(255)
if tool == "ssh":
    target, command = words[0], " ".join(words[1:])
    user, ip = target.split("@", 1)
    log.write(json.dumps({"tool": "ssh", "user": user, "ip": ip, "command": command,
                          "alive": "ServerAliveInterval=10" in sys.argv}) + "\n")
    vip_address = ip
    ip = holder(ip)
    down(ip)
    refuse_key(ip)
    ufm = state["ufms"][ip]
    for device, mac in (("lo", "00:00:00:00:00:00"), ("eno8303", ufm["mac"])):
        os.makedirs(f"{home(ip)}/sys/class/net/{device}", exist_ok=True)
        with open(f"{home(ip)}/sys/class/net/{device}/address", "w") as handle:
            handle.write(mac + "\n")
    os.makedirs(home(ip) + "/root", exist_ok=True)
    os.makedirs(home(ip) + "/tmp", exist_ok=True)
    # HOME is the sandbox: key preparation writes ~/.ssh/authorized_keys there, never on this machine.
    env = dict(os.environ, HOME=home(ip) + "/root", PATH=os.environ["FAKE_UFM_BIN"] + os.pathsep + os.environ["PATH"],
               FAKE_HOSTNAME=ufm["hostname"], FAKE_MAC=ufm["mac"], TMPDIR=home(ip) + "/tmp",
               UFM_INFO_IB_SYSFS=os.environ["FAKE_UFM_SYSFS"], FAKE_CONTAINER=home(ip) + "/container",
               UFM_HOST_FILES=home(ip) + "/container/opt/ufm/files",   # the master's bind mount
               FAKE_DOCKER_LOG=home(ip) + "/docker.log", COPYFILE_DISABLE="1")
    for sub in ("/container/opt/ufm/files", "/container/var/tmp"):
        os.makedirs(home(ip) + sub, exist_ok=True)
    after = state.get("failover", {}).get("after")
    trigger = after and after in command and vip_address in state.get("failover", {}).get("vip", {})
    command = command.replace("/home/admin", home(ip) + "/home/admin")
    command = command.replace("/root", home(ip) + "/root").replace("/sys/class/net", home(ip) + "/sys/class/net")
    custody = os.environ.get("FAKE_UFM_CUSTODY_FD")
    if custody is not None:
        # The fixture's parent owns the session even after this stub returns.
        # The preopened channel is a capability; no filesystem ID grants it.
        recv, reply = socket.socketpair()
        with recv, socket.socket(fileno=os.dup(int(custody))) as intake:
            with reply:
                ack_reader, ack_writer = os.pipe()
                try:
                    try:
                        # Keep the original reply endpoint until the broker
                        # explicitly accepts custody. Only it owns the equivalent
                        # ACK write end after this send and local close.
                        rights = array("i", [reply.fileno(), 0, 1, 2, ack_writer])
                        if intake.sendmsg([b"R"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)]) != 1:
                            raise RuntimeError("incomplete UFM custody request")
                    finally:
                        os.close(ack_writer)
                    if os.read(ack_reader, 1) != b"A":
                        raise RuntimeError("UFM custody admission was not confirmed")
                finally:
                    os.close(ack_reader)
            payload = json.dumps({"command": command, "cwd": home(ip) + "/root", "env": env}).encode("utf-8")
            recv.sendall(struct.pack("!I", len(payload)) + payload)
            status = bytearray()
            while len(status) < 4:
                part = recv.recv(4 - len(status))
                if not part:
                    raise RuntimeError("UFM custody reply missing")
                status.extend(part)
            rc, = struct.unpack("!i", status)
    else:
        if REQUIRE_CUSTODY:
            raise RuntimeError("the staged SSH fixture requires its original custody channel")
        rc = subprocess.call(["bash", "-c", command], env=env, cwd=home(ip) + "/root")
    if trigger:
        open(FAILOVER, "w").close()
    sys.exit(rc)
src, dst = words[-2], words[-1]
remote = src if "@" in src else dst
ip = remote.split("@", 1)[1].split(":", 1)[0]
log.write(json.dumps({"tool": "scp", "ip": ip, "src": src, "dst": dst,
                      "alive": "ServerAliveInterval=10" in sys.argv}) + "\n")
ip = holder(ip)
down(ip)
refuse_key(ip)
if "@" in src:
    matches = sorted(glob.glob(local(ip, src.split(":", 1)[1])))
    if not matches:
        print("scp: No such file or directory", file=sys.stderr)
        sys.exit(1)
    shutil.copy(matches[0], dst)
else:
    # like scp on a terminal: a progress line on stdout, an error on stderr (I-018 output problem 3)
    if ip in state.get("scp_fail", []):
        print(f"{os.path.basename(src)}                 0%    0     0.0KB/s   --:-- ETA")
        print(f"scp: {dst.split(':', 1)[1]}: Permission denied", file=sys.stderr)
        sys.exit(1)
    path = local(ip, dst.split(":", 1)[1])
    shutil.copy(src, os.path.join(path, os.path.basename(src)) if path.endswith("/") else path)
    print(f"{os.path.basename(src)}               100%   64    64.0KB/s   00:00")
'''


class UfmCronCase(unittest.TestCase):
    def setUp(self):
        # Keep the sandbox if unprovable writers survive; no automatic
        # TemporaryDirectory finalizer may delete it after a teardown refusal.
        self.root = Path(tempfile.mkdtemp(prefix="ufm-cron-fixture-")).resolve()
        root_info = self.root.lstat()
        self._root_identity = root_info.st_dev, root_info.st_ino, root_info.st_uid
        self._owned_remote_sessions = []
        self._unsettled_admissions = False
        self._admissions_cleanup_deadline = None
        # the published tree: the shared collector and its infiniband entry point. cron.sh pins PATH, so
        # the staged copy puts the fake ssh/scp/flock in front of it; the pinned line must exist exactly once.
        self.bin = self.mkdir("bin")
        source = (ROOT / "ethernet/monitor/cron.sh").read_text(encoding="utf-8")
        self.assertEqual(source.count(PINNED_PATH), 1)
        staged = self.mkdir("ethernet/monitor") / "cron.sh"
        source = source.replace(PINNED_PATH, PINNED_PATH.replace("PATH=", f"PATH={self.bin}:"))
        for line, short in TIMING.items():
            self.assertEqual(source.count(line), 1, line)
            source = source.replace(line, short)
        staged.write_text(source, encoding="utf-8")
        monitor = self.mkdir("infiniband/monitor")
        (monitor / "cron.sh").symlink_to("../../ethernet/monitor/cron.sh")
        # the page generator cron.sh calls at the end: records how it was called
        self.generated = self.root / "generated.jsonl"
        self.order = self.root / "order.log"
        self.write_exec(self.mkdir("monitor") / "generate-monitor-html.py",
                        "import json, sys\n"
                        f"open({str(self.generated)!r}, 'a').write(json.dumps(sys.argv[1:]) + '\\n')\n"
                        f"open({str(self.order)!r}, 'a').write('generate\\n')\n")
        shutil.copy(ROOT / "infiniband/monitor/ufm-info.sh", monitor / "ufm-info.sh")
        shutil.copy(ROOT / "infiniband/monitor/ufm-ibdiagnet.sh", monitor / "ufm-ibdiagnet.sh")
        # the IB closed loop: the real post-collect, a stand-in analyzer, the setup output link and a CVT
        shutil.copy(ROOT / "infiniband/monitor/post-collect.py", monitor / "post-collect.py")
        for module in ("log_rotation.py", "collection_archive.py"):   # cronjob.log and the data retention
            shutil.copy(ROOT / "tools" / module, self.mkdir("tools") / module)
        self.analyzed = self.root / "analyzed.jsonl"
        tool = self.mkdir("tools/ibdiagnet-analyze-tool")
        # like the real analyzer: the report, and its provenance naming the input and the CVT
        (tool / "analyze.py").write_text(
            "import hashlib, json, os, sys\n"
            "args = sys.argv[1:]\n"
            f"open({str(self.analyzed)!r}, 'a').write(json.dumps(args) + '\\n')\n"
            f"open({str(self.order)!r}, 'a').write('analyze\\n')\n"
            f"if os.path.exists({str(self.root / 'analyzer-fails')!r}): sys.exit('ERROR: fixture')\n"
            "def identity(path):\n"
            "    real = os.path.realpath(path)\n"
            "    return {'path': os.path.abspath(path), 'resolved_path': real, 'kind': 'file',\n"
            "            'sha256': hashlib.sha256(open(real, 'rb').read()).hexdigest()}\n"
            "output = args[args.index('--output') + 1]\n"
            # records whether the shared report lock is held while the report is written
            "probe = os.environ.get('FAKE_REPORT_LOCK_PROBE')\n"
            "if probe:\n"
            "    import fcntl\n"
            "    with open(os.path.join(os.path.dirname(os.path.realpath(output)), '.report-writer.lock'), 'a') as lock:\n"
            "        try:\n"
            "            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
            "            state = 'free'\n"
            "        except BlockingIOError:\n"
            "            state = 'held'\n"
            "    open(probe, 'w').write(state)\n"
            "open(output, 'wb').write(b'PK report')\n"
            "json.dump({'schema': 'ib-report-provenance-v1', 'report': identity(output),\n"
            "           'cvt': identity(args[args.index('--p2p') + 1]), 'actual': identity(args[1])},\n"
            "          open(output + '.provenance.json', 'w'))\n", encoding="utf-8")
        self.p2p_output = self.mkdir("DAY0-Prepare/site/99-output-p2p")
        (self.p2p_output / "site-cvt.xlsx").write_bytes(b"cvt")
        (monitor / "99-output-p2p").symlink_to(self.p2p_output)   # post-collect's own-directory link
        # the project and the links setup creates (ib.csv, the ufm-info data directory)
        self.project = self.mkdir("DAY0-Prepare/site")
        rows = ["hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac"]
        rows += [f"{name},server_ufm,NA,{ip},23,198.51.101.254,{mac}" for name, (ip, mac) in UFMS.items()]
        rows.append(f"{MGMT[0]},server_mgmt,NA,{MGMT[1]},23,198.51.101.254,{MGMT[2]}")
        (self.project / "02-devices_config.csv").write_text("\n".join(rows) + "\n", encoding="utf-8")
        key = self.root / "fixture-key"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
        shutil.copy(key.with_suffix(".pub"), self.project / "mgmt-server.pub")
        # owner 2026-11-04 (R-016 §5.2): cron.sh reads <type>/publickey/mgmt-server.pub, setup's key link
        (self.mkdir("infiniband/publickey") / "mgmt-server.pub").symlink_to(self.project / "mgmt-server.pub")
        (monitor / "ib.csv").symlink_to(self.project / "02-devices_config.csv")
        self.output = self.mkdir("DAY0-Prepare/site/99-output-monitor/infiniband/ufm-info")
        (monitor / "ufm-info").symlink_to(self.output)
        self.ibdiag_output = self.mkdir("DAY0-Prepare/site/99-output-monitor/infiniband/ufm-ibdiagnet")
        (monitor / "ufm-ibdiagnet").symlink_to(self.ibdiag_output)
        (self.project / "01-global.yaml").write_text(f'servers:\n  - ufm:\n      vip: "{VIP}"\n', encoding="utf-8")
        (monitor / "01-global.yaml").symlink_to(self.project / "01-global.yaml")
        # fakes: ssh/scp, flock (absent on macOS), and the UFM's own commands
        self.ufm_bin = self.mkdir("ufm-bin")
        self.assertEqual(1, FAKE_REMOTE.count("REQUIRE_CUSTODY = False"))
        staged_remote = FAKE_REMOTE.replace("REQUIRE_CUSTODY = False", "REQUIRE_CUSTODY = True")
        for tool in ("ssh", "scp"):
            self.write_exec(self.bin / tool, staged_remote.replace("{python}", sys.executable))
        self.write_exec(self.bin / "flock", "#!/bin/sh\nexit 0\n")
        fakes = dict(FAKES, hostname='echo "$FAKE_HOSTNAME"',
                     ip='echo "eno8303          UP             $FAKE_MAC <BROADCAST,MULTICAST,UP>"')
        for name, body in fakes.items():
            self.write_exec(self.ufm_bin / name, f"#!/bin/sh\n{body}\n")
        native_docker = FAKE_DOCKER.replace("{python}", sys.executable)
        old = 'sys.exit(subprocess.call(["sh", "-c", script]))'
        self.assertEqual(1, native_docker.count(old))
        native_docker = native_docker.replace(old, 'fd = os.environ.get("FAKE_UFM_WRITER_FD")\n'
            '    sys.exit(subprocess.call(["sh", "-c", script], pass_fds=(() if fd is None else (int(fd),))))')
        self.write_exec(self.ufm_bin / "docker", native_docker)
        self.sysfs = self.mkdir("sys-infiniband")
        (self.sysfs / "mlx5_0").mkdir()
        self.state = {"ufms": {ip: {"hostname": name, "mac": mac} for name, (ip, mac) in UFMS.items()},
                      "down": []}

    def tearDown(self):
        self.stop_remote_sessions()
        info = self.root.lstat()
        self.assertEqual(self._root_identity, (info.st_dev, info.st_ino, info.st_uid))
        self.assertEqual(self.root, self.root.resolve())
        shutil.rmtree(self.root)

    @staticmethod
    def _darwin_group_has_only_owned_zombies(group):
        """Accept only exact current-UID all-Z metadata after a Darwin signal refusal."""
        if sys.platform != "darwin":
            return False
        try:
            result = subprocess.run(
                ["/bin/ps", "-x", "-g", str(group), "-o", "pgid=,uid=,stat="],
                stdin=subprocess.DEVNULL, capture_output=True, text=True, check=False,
            )
        except (OSError, UnicodeError, subprocess.SubprocessError):
            return False
        if (result.returncode != 0 or type(result.stdout) is not str
                or type(result.stderr) is not str or result.stderr or not result.stdout):
            return False
        owner = os.geteuid()
        for line in result.stdout.splitlines():
            fields = line.split()
            if (len(fields) != 3 or not fields[0].isdecimal() or not fields[1].isdecimal()
                    or int(fields[0]) != group or int(fields[1]) != owner
                    or not fields[2].startswith("Z")):
                return False
        return True

    def stop_remote_sessions(self):
        """cron.sh starts the collectors on a UFM with nohup and need not wait for them: on a VIP holder that is
        then rejected, ufm-ibdiagnet.sh and `ufm-info.sh --ha` are never fetched and may still run when cron.sh
        returns; ufm-ibdiagnet.sh was seen writing into the sandbox while it was being removed ("Directory not
        empty"). Stop the sessions held by this test (SIGTERM, then SIGKILL after
        10 s) before removing its sandbox; assertions run before this cleanup."""
        owned = getattr(self, "_owned_remote_sessions", [])
        sessions = owned[:]
        for signum in (signal.SIGTERM, signal.SIGKILL):
            for session in sessions:
                try:
                    _signal_retained_group(session.process, signum)
                except ProcessLookupError:
                    pass  # Still require the original writer pipe and Popen below.
                except PermissionError:
                    if not session.writer_stopped():
                        raise
            deadline = time.monotonic() + _REMOTE_CLEANUP_SECONDS
            if signum == signal.SIGTERM and getattr(self, "_admissions_cleanup_deadline", None) is not None:
                deadline = min(deadline, self._admissions_cleanup_deadline)
            while sessions:
                for session in sessions[:]:
                    if session.writer_stopped():
                        try:
                            session.reap(deadline)
                        except subprocess.TimeoutExpired:
                            # Keep the original handle and reader; the old
                            # second phase still owns the unreaped group.
                            continue
                        sessions.remove(session)
                        owned.remove(session)
                remaining = deadline - time.monotonic()
                if not sessions or remaining <= 0:
                    break
                time.sleep(min(0.05, remaining))
            if not sessions:
                if getattr(self, "_unsettled_admissions", False):
                    self.fail("UFM custody admissions still open; preserving fixture sandbox")
                return
        self.fail("original remote sessions still have a writer after SIGKILL")

    def _stop_modelled_owned_groups(self, owned):
        """Original permission/refusal matrix with pre-registered model handles.

        The native fixture uses the original writer FD instead of reconstructing
        identity with ps. The legacy compatibility model still requires a
        custodian and tests the original exact evidence and refusal assertions.
        """
        groups = set(owned)
        for signum in (signal.SIGTERM, signal.SIGKILL):
            for group in sorted(groups):
                try:
                    _signal_retained_group(owned[group], signum)
                except ProcessLookupError:
                    groups.discard(group)
                except PermissionError:
                    if not self._darwin_group_has_only_owned_zombies(group):
                        raise
                    groups.discard(group)
            deadline = time.monotonic() + _REMOTE_CLEANUP_SECONDS
            while groups and time.monotonic() < deadline:
                for group in sorted(groups):
                    try:
                        _signal_retained_group(owned[group], 0)
                    except ProcessLookupError:
                        groups.discard(group)
                    except PermissionError:
                        if not self._darwin_group_has_only_owned_zombies(group):
                            raise
                        groups.discard(group)
                if groups:
                    time.sleep(0.05)
            if not groups:
                return
        self.fail(f"remote sessions still running after SIGKILL: {sorted(groups)}")

    def mkdir(self, relative):
        path = self.root / relative
        path.mkdir(parents=True, exist_ok=True)
        return path

    @staticmethod
    def write_exec(path, text):
        path.write_text(text, encoding="utf-8")
        path.chmod(0o755)

    def _fixture_environment(self, **extra_env):
        state_path = self.root / "state.json"
        state_path.write_text(json.dumps(self.state), encoding="utf-8")
        self.calls = self.root / "calls.jsonl"
        # COPYFILE_DISABLE: macOS tar would otherwise add "._" metadata members (GNU tar never does).
        return dict(os.environ, PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}", LC_ALL="C", COPYFILE_DISABLE="1",
                   FAKE_UFM_STATE=str(state_path), FAKE_UFM_CALLS=str(self.calls),
                   FAKE_UFM_HOSTS=str(self.mkdir("hosts")), FAKE_UFM_BIN=str(self.ufm_bin),
                   FAKE_UFM_SYSFS=str(self.sysfs),
                   **extra_env)

    def _run_with_custody(self, command, *, pass_fds=(), input_text=None, **extra_env):
        if self._unsettled_admissions:
            raise RuntimeError("refusing new UFM requests while earlier custody is unsettled")
        env = self._fixture_environment(**extra_env)
        custodian = _RemoteSessionCustodian(self.root, self._owned_remote_sessions)
        try:
            with custodian:
                descriptor = custodian.client.fileno()
                env[_CUSTODY_FD] = str(descriptor)
                return subprocess.run(command, cwd=self.root, env=env, input=input_text,
                                      capture_output=True, text=True, timeout=_CRON_SECONDS,
                                      pass_fds=(*pass_fds, descriptor))
        finally:
            self._unsettled_admissions |= custodian.thread.is_alive()
            if custodian.cleanup_deadline is not None:
                self._admissions_cleanup_deadline = custodian.cleanup_deadline

    def run_cron(self, *args, pass_fds=(), **extra_env):
        return self._run_with_custody(["bash", str(self.root / "infiniband/monitor/cron.sh"), *args],
                                     pass_fds=pass_fds, **extra_env)

    def archives(self):
        return sorted(self.output.glob("*.tar.gz"))

    def members(self, archive):
        with tarfile.open(archive) as bundle:
            return {Path(member.name).name: bundle.extractfile(member).read().decode()
                    for member in bundle.getmembers() if member.isfile()}

    def contacted(self):
        if not self.calls.exists():
            return set()
        return {json.loads(line)["ip"] for line in self.calls.read_text().splitlines()}

    def ibdiag_archives(self):
        return sorted(path.name for path in self.ibdiag_output.iterdir()
                      if path.name.endswith(("_ibdiagnet2.tgz", "_iblinkinfo.log")))


class UfmCronWorkflowTest(UfmCronCase):
    def test_cron_runs_ufm_info_on_every_ufm_and_archives_the_snapshots(self):
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        archives = self.archives()
        self.assertEqual(len(archives), 1, result.stdout)
        members = self.members(archives[0])
        self.assertEqual(sorted(members), sorted(f"{name}.info" for name in UFMS))
        for name, text in members.items():
            self.assertIn(f"Device:       {name[:-5]}\n", text)
            self.assertIn("Server Type:  UFM", text)
            self.assertIn("# Collect complete", text)
        self.assertNotIn(MGMT[1], self.contacted(), "server_mgmt is not collected in this phase")
        self.assertIn("HA 未就绪", result.stdout, "no device answers the VIP yet: ibdiagnet is skipped")
        self.assertEqual([path.name for path in self.ibdiag_output.iterdir() if not path.name.endswith(".ufm-run.json")],
                         [], "only the run record says the run was skipped")
        self.assertEqual({json.loads(line)["user"] for line in self.calls.read_text().splitlines()
                          if json.loads(line)["tool"] == "ssh"}, {"root"})
        self.assertIn('"planned":0', result.stdout, "UFMs never join the switch result")
        self.assertIn("cron finish ==========", result.stdout)
        self.assertEqual(self.generated.read_text().splitlines(), ['["--type", "prod"]'],
                         "owner 2026-10-21: any data collected in this run is published")
        key = (self.project / "mgmt-server.pub").read_text().split()[:2]
        for ip, _mac in UFMS.values():
            keys = (self.root / "hosts" / ip / "root/.ssh/authorized_keys").read_text()
            self.assertIn(" ".join(key), keys, "the deployment key is installed at key preparation")
        self.assertRegex(result.stdout, r"ufm-info ──\n.*\[CLN\] found +1 file\(s\) to bundle", "counted through the link")

    def test_an_unreachable_ufm_is_reported_without_failing_the_switch_result(self):
        self.state["down"] = ["198.51.101.132"]
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(sorted(self.members(self.archives()[0])), ["ufm01.example.test.info"])
        # 问题文档 I-018 期望 4（每台的具体原因，v3.1.6 C1-O5 (a)）：连不上就写连不上
        self.assertIn("UFM ufm02.example.test: SSH transport or remote preparation failed", result.stdout)
        self.assertIn('"state":"success"', result.stdout)
        self.assertIn("cron finish with UFM warnings", result.stdout)

    def test_a_machine_with_another_management_mac_is_rejected_at_key_preparation(self):
        self.state["ufms"]["198.51.101.132"]["mac"] = "02:00:00:00:09:09"
        result = self.run_cron()
        self.assertEqual(sorted(self.members(self.archives()[0])), ["ufm01.example.test.info"])
        self.assertIn("management MAC identity mismatch", result.stdout + result.stderr)
        self.assertIn("ufm02.example.test", result.stdout)
        self.assertIn("cron finish with UFM warnings", result.stdout)
        self.assertFalse((self.root / "hosts/198.51.101.132/root/.ssh/authorized_keys").exists(),
                         "nothing is installed on the wrong machine")

    def test_a_refused_key_without_a_terminal_leaves_only_a_ufm_warning(self):
        self.state["no_key"] = ["198.51.101.132"]
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(sorted(self.members(self.archives()[0])), ["ufm01.example.test.info"])
        # 问题文档 I-018 期望 4（每台的具体原因，v3.1.6 C1-O5 (a)）：公钥被拒就写认证被拒
        self.assertIn("UFM ufm02.example.test: authentication rejected", result.stdout)
        self.assertIn('"state":"success"', result.stdout, "the switch result is untouched")
        self.assertIn("cron finish with UFM warnings", result.stdout)

    def test_without_the_setup_data_links_no_ufm_is_touched(self):
        (self.root / "infiniband/monitor/ufm-info").unlink()
        (self.root / "infiniband/monitor/ufm-ibdiagnet").unlink()
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("setup", result.stdout)
        self.assertEqual(self.archives(), [])
        self.assertFalse(self.generated.exists(), "nothing collected, nothing to publish")
        self.assertFalse((self.root / "infiniband/monitor/ufm-info").exists())
        self.assertEqual(self.contacted(), set(), "no UFM is touched without a place to store the result")
        self.assertFalse((self.root / "infiniband/monitor/ufm-ibdiagnet").exists())

    def test_a_missing_info_link_stops_only_the_info_phase(self):
        (self.root / "infiniband/monitor/ufm-info").unlink()
        self.state["vip"] = {VIP: "198.51.101.130"}
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ufm-info 不存在", result.stdout)
        self.assertFalse((self.root / "infiniband/monitor/ufm-info").exists())
        self.assertEqual(len(self.ibdiag_archives()), 1, "ibdiagnet still runs")

    def test_ibdiagnet_runs_on_the_vip_holder_and_lands_under_the_real_node(self):
        self.state["vip"] = {VIP: "198.51.101.132"}   # ufm02 holds the VIP
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        names = self.ibdiag_archives()
        self.assertEqual(len(names), 1, result.stdout)
        # owner 2026-10-22: run-id (minute timestamp) first for the daily bundling, then the real node
        self.assertRegex(names[0], r"^\d{8}-\d{4}-prod-[0-9a-f]{16}_ufm02_ibdiagnet2\.tgz$")
        done = (self.ibdiag_output / names[0].replace(".tgz", ".done")).read_text()
        self.assertIn("result=ok", done, "the UFM's completion record is kept beside it")
        with tarfile.open(self.ibdiag_output / names[0]) as bundle:
            self.assertIn("ibdiagnet2/ibdiagnet2.log", bundle.getnames(), "the ibdiagnet archive as is")
        self.assertIn("cron finish ==========", result.stdout)

    def test_the_fetched_ibdiagnet_archive_becomes_the_ib_link_validation_report_before_the_page(self):
        # Owner 2026-10-21: IB modelled on Ethernet's closed loop, on this run's exact archive.
        self.state["vip"] = {VIP: "198.51.101.132"}
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        [archive] = self.ibdiag_archives()
        [argv] = [json.loads(line) for line in self.analyzed.read_text().splitlines()]
        self.assertEqual(["--ibdiagnet", str((self.ibdiag_output / archive).resolve()),
                          "--p2p", str((self.p2p_output / "site-cvt.xlsx").resolve())], argv[:4])
        report = archive.replace("_ibdiagnet2.tgz", "-ibdiagnet-topology-validation.xlsx")
        self.assertTrue((self.p2p_output / report).is_file())
        self.assertTrue((self.p2p_output / report.replace(".xlsx", ".receipt.json")).is_file())
        self.assertEqual(["analyze", "generate"], self.order.read_text().split())
        self.assertIn("cron finish ==========", result.stdout)

    def test_a_failed_ib_analysis_is_a_ufm_warning_and_the_page_is_still_refreshed(self):
        self.state["vip"] = {VIP: "198.51.101.132"}
        (self.root / "analyzer-fails").write_text("1")
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(["analyze", "generate"], self.order.read_text().split())
        self.assertIn("[IB-CLOSED-LOOP] ERROR", result.stdout)
        self.assertIn("cron finish with UFM warnings", result.stdout)
        self.assertIn('"state":"success"', result.stdout, "the switch result is untouched")

    def test_without_an_ibdiagnet_archive_no_analysis_runs(self):
        result = self.run_cron()   # no device holds the VIP: ibdiagnet is skipped
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.analyzed.exists())
        self.assertEqual(["generate"], self.order.read_text().split())

    def test_a_vip_held_by_another_machine_is_not_collected(self):
        self.state["ufms"]["198.51.101.150"] = {"hostname": "intruder.example.test", "mac": "02:00:00:00:09:09"}
        self.state["vip"] = {VIP: "198.51.101.150"}
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.ibdiag_archives(), [])
        self.assertEqual(sorted(self.members(self.archives()[0])), sorted(f"{name}.info" for name in UFMS),
                         "nor is its HA state")
        self.assertIn("不是 ib.csv 中的 UFM", result.stdout)
        self.assertIn("cron finish with UFM warnings", result.stdout)

    def test_the_ha_state_is_read_on_the_vip_holder_and_kept_under_that_node(self):
        # Owner 2026-10-21: the HA state comes only from the primary, through the VIP.
        self.state["vip"] = {VIP: "198.51.101.132"}   # ufm02 is the primary
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        members = self.members(self.archives()[0])
        self.assertEqual(sorted(members), sorted([f"{name}.info" for name in UFMS] + ["ufm02.example.test.ha"]))
        ha = members["ufm02.example.test.ha"]
        self.assertIn("Server Type:  UFM-HA", ha)
        self.assertIn("Sanity tests completed successfully!", ha)
        for name in UFMS:
            self.assertNotIn("ufm_ha_cluster", members[f"{name}.info"], "no HA command runs per node")
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertTrue(any(call["tool"] == "scp" and call["ip"] == VIP and call["dst"].endswith("/root/monitor/ha/")
                            for call in calls),
                        "the VIP copy never overwrites the node script that may still be running there")
        self.assertIn("cron finish ==========", result.stdout)

    def failover_after(self, launched):
        """ufm02 holds the VIP when the collector starts; right after `launched` the VIP moves to ufm01,
        which still keeps the HA state it wrote when it was the primary."""
        self.state["vip"] = {VIP: "198.51.101.132"}
        self.state["failover"] = {"after": launched, "vip": {VIP: "198.51.101.130"}}
        stale = self.mkdir("hosts/198.51.101.130/root/monitor")
        (stale / "ufm01.example.test.ha").write_text(
            "Device:       ufm01.example.test\nServer Type:  UFM-HA\nSTALE 02:00:00:00:01:01\n"
            "# Collect complete\n", encoding="utf-8")

    def test_a_failover_after_the_ha_start_still_fetches_this_runs_state_from_that_node(self):
        # Owner 2026-10-22: the code must cope with a UFM failover; the VIP may move mid-collection.
        self.failover_after("ufm-info.sh --ha")
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        members = self.members(self.archives()[0])
        self.assertIn("ufm02.example.test.ha", members)
        self.assertNotIn("ufm01.example.test.ha", members, "the old primary's leftover state is never taken")
        self.assertNotIn("STALE", "".join(members.values()))
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        fetched = [call for call in calls if call["tool"] == "scp" and call["src"].endswith("/*.ha")]
        self.assertEqual([call["ip"] for call in fetched], ["198.51.101.132"],
                         "fetched from the node that ran it, by its own address")

    def test_a_failover_during_ibdiagnet_fetches_from_the_node_that_ran_it(self):
        self.failover_after("ufm-ibdiagnet.sh")
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        names = self.ibdiag_archives()
        self.assertEqual(len(names), 1, result.stdout)
        self.assertRegex(names[0], r"_ufm02_ibdiagnet2\.tgz$")
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        done_reads = [call["ip"] for call in calls if call["tool"] == "ssh" and ".done" in call["command"]]
        self.assertTrue(done_reads)
        self.assertEqual(set(done_reads), {"198.51.101.132"})

    def test_every_ufm_session_detects_a_dead_peer(self):
        # A VIP that nobody holds for a while would otherwise leave scp waiting on TCP retransmits.
        self.state["vip"] = {VIP: "198.51.101.132"}
        self.run_cron()
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertTrue(calls)
        self.assertEqual([call for call in calls if not call["alive"]], [])

    def test_an_unanswered_vip_skips_only_the_ha_state(self):
        result = self.run_cron()   # no device holds the VIP yet
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertRegex(result.stdout, r"\[UFM\] SKIPPED: .*HA 未就绪")
        self.assertEqual(sorted(self.members(self.archives()[0])), sorted(f"{name}.info" for name in UFMS))
        self.assertNotIn("UFM warnings", result.stdout, "HA that is not set up yet is not a failure")


SWITCHES = {
    "ibsw01.example.test": ("198.51.100.21", "02:00:00:00:0a:01"),
    "ibsw02.example.test": ("198.51.100.22", "02:00:00:00:0a:02"),
}
# Stand-ins for sw-info.sh and sw-link.sh on an IB switch: a complete file at once.
SW_INFO = r'''#!/bin/bash
cd "$(dirname "$0")" || exit 1
printf 'Device: %s\n# Collect complete\n' "$(hostname)" > "$(hostname).info"
'''
SW_LINK = r'''#!/bin/bash
cd "$(dirname "$0")" || exit 1
printf 'Hostname,Port\n%s,1\n' "$(hostname)" > "$(hostname).link"
'''


class UfmCronIdentityAndEndingTest(UfmCronCase):
    """I-018 (v3.1.6 C1, 问题文档 I-018): every MAC spelling is read, a rejected UFM keeps its own reason and a
    run record, the final line names both kinds of warning, and the scp that deploys the switch scripts
    shows its errors but no progress bar."""

    def add_ib_switches(self):
        """Two IB switches beside the UFMs, without eth0_mac (they pass the hostname check)."""
        csv = self.project / "02-devices_config.csv"
        csv.write_text(csv.read_text(encoding="utf-8") + "".join(
            f"{name},ib,NA,{ip},24,198.51.100.254,\n" for name, (ip, _mac) in SWITCHES.items()), encoding="utf-8")
        monitor = self.root / "infiniband/monitor"
        self.write_exec(monitor / "sw-info.sh", SW_INFO)
        self.write_exec(monitor / "sw-link.sh", SW_LINK)
        for name, (ip, mac) in SWITCHES.items():
            self.state["ufms"][ip] = {"hostname": name, "mac": mac}

    def final_line(self, result):
        return result.stdout.rstrip("\n").splitlines()[-1]

    def test_a_dash_upper_case_mac_and_full_name_pass_by_mac(self):
        # 问题文档 I-018 验收 :1127: UFM 行用短横线大写 MAC、主机名写全名，通过 MAC 核对，进入 ufm-info 和 ufm-ibdiagnet
        csv = self.project / "02-devices_config.csv"
        text = csv.read_text(encoding="utf-8")
        for name, (ip, mac) in UFMS.items():
            self.assertEqual(text.count(f",{mac}\n"), 1)
            text = text.replace(f",{mac}\n", f",{mac.upper().replace(':', '-')}\n")
            self.state["ufms"][ip]["hostname"] = name.split(".", 1)[0]   # `hostname -s` answers the short name
        csv.write_text(text, encoding="utf-8")
        self.state["vip"] = {VIP: "198.51.101.132"}
        result = self.run_cron()
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, output)
        for name, (ip, _mac) in UFMS.items():
            self.assertIn(f"[KEY][OK]   {name} ({ip})", result.stdout)
        self.assertNotIn("HOSTNAME-MISMATCH", output)
        # the first part of the full name is the short name: cron.sh warns only when they differ
        self.assertNotIn("MAC-VERIFIED-HOSTNAME-TRANSITION", output)
        members = self.members(self.archives()[0])
        for name in UFMS:
            self.assertIn(f"{name}.info", members)
        names = self.ibdiag_archives()
        self.assertEqual(len(names), 1, result.stdout)
        self.assertRegex(names[0], r"_ufm02_ibdiagnet2\.tgz$", "ibdiagnet ran on the VIP holder")
        self.assertIn("cron finish ==========", result.stdout)

    def test_all_ufms_rejected_still_leave_a_run_record(self):
        # 需求文档 :374（从 ufm-run.json 读出 UFM 被拒的原因）；问题文档 I-018 期望 4 :1117；v3.1.6 C1-O8 (a)
        for index, ip in enumerate(sorted(ip for ip, _mac in UFMS.values()), 1):
            self.state["ufms"][ip]["mac"] = f"02:00:00:00:09:0{index}"
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        records = sorted(self.ibdiag_output.glob("*.ufm-run.json"))
        self.assertEqual(len(records), 1, result.stdout)
        record = json.loads(records[0].read_text(encoding="utf-8"))
        self.assertEqual((record["outcome"], record["run_id"], record["done"], record["report"]),
                         ("skipped", None, None, None))
        self.assertIn("management MAC identity mismatch", record["reason"])
        for name in UFMS:
            self.assertIn(name, record["reason"])
        self.assertEqual(self.archives(), [], "no UFM was collected")
        self.assertIn("cron finish with UFM warnings", result.stdout)

    def test_finish_names_device_and_ufm_warnings(self):
        # 问题文档 I-018 输出问题 2 :1103、期望 4 :1118、验收 :1126；退出码不变
        self.add_ib_switches()
        self.state["scp_fail"] = ["198.51.100.21"]   # a device warning
        self.state["down"] = ["198.51.101.132"]      # a UFM warning
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('"state":"partial"', result.stdout)
        self.assertTrue(self.final_line(result).endswith(
            "] ========== cron finish with device warnings and UFM warnings =========="), result.stdout)

    def test_finish_with_one_kind_of_warning_keeps_its_text(self):
        # 问题文档 I-018 期望 4 :1118; v3.1.6 guide WP-8 第 5 条 (:1419)「只有一种时保持原文」
        self.add_ib_switches()
        self.state["scp_fail"] = ["198.51.100.21"]   # only a device warning
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.final_line(result).endswith("] ========== cron finish with device warnings =========="),
                        result.stdout)

    def test_deploy_scp_shows_errors_without_progress(self):
        # 问题文档 I-018 输出问题 3 :1104、期望 4 :1119（不刷进度条，失败时仍打印错误信息；C1-O6 (b)）
        self.add_ib_switches()
        self.state["scp_fail"] = ["198.51.100.21"]
        result = self.run_cron()
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, output)
        self.assertNotRegex(output, r"sw-(info|link)\.sh +\d+%", "no scp progress line")
        self.assertIn("scp: /home/admin/monitor/: Permission denied", output)
        self.assertIn("[PARALLEL][FAIL] ibsw01.example.test (198.51.100.21, exit=1)", output)
        [archive] = sorted((self.root / "infiniband/monitor/ib-info").glob("*.tar.gz"))
        self.assertIn("ibsw02.example.test.info", self.members(archive), "the other switch is still collected")


class UfmCronFabricModeAndRetentionTest(UfmCronCase):
    """Owner 2026-10-22: ibdiagnet by default, iblinkinfo after three failures in a row, ibdiagnet again
    every sixth run; 3-day retention for everything collected; cronjob.log rotation; skipped overlap."""

    def state_file(self):
        return self.ibdiag_output / ".ibdiagnet-state"

    def counts(self):
        text = self.state_file().read_text()
        return tuple(int(re.search(rf"^{key}=(\d+)$", text, re.M).group(1)) for key in ("failures", "since_probe"))

    def kinds_run(self):
        log = self.root / "hosts/198.51.101.132/docker.log"
        calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
        return [call[-1].rsplit("/", 1)[-1] if call[-1].endswith("iblinkinfo") else "ibdiagnet"
                for call in calls if call[-1].endswith("/iblinkinfo") or "--rail_validation" in call]

    def test_three_ibdiagnet_failures_switch_to_iblinkinfo_and_every_sixth_run_tries_ibdiagnet(self):
        self.state["vip"] = {VIP: "198.51.101.132"}
        for attempt in (1, 2, 3):
            result = self.run_cron(FAKE_IBDIAGNET_NO_NET_DUMP="1")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(self.counts(), (attempt, 0))
            self.assertIn("cron finish with UFM warnings", result.stdout)
        self.assertIn("已连续失败 3 次：之后改采 iblinkinfo", result.stdout)
        self.assertEqual(self.kinds_run(), ["ibdiagnet"] * 3)
        result = self.run_cron(FAKE_IBDIAGNET_NO_NET_DUMP="1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.kinds_run()[-1], "iblinkinfo", "the fourth run collects iblinkinfo")
        [log] = [name for name in self.ibdiag_archives() if name.endswith("_iblinkinfo.log")]
        self.assertRegex(log, r"^\d{8}-\d{4}-prod-[0-9a-f]{16}_ufm02_iblinkinfo\.log$")
        self.assertTrue((self.p2p_output / log.replace("_iblinkinfo.log", "-iblinkinfo-topology-validation.xlsx")).is_file())
        self.assertEqual(self.counts(), (3, 1), "an iblinkinfo run only advances the countdown")
        # the sixth run in that state tries ibdiagnet again; a success clears the count
        self.state_file().write_text("failures=3\nsince_probe=5\n")
        result = self.run_cron()
        self.assertEqual(self.kinds_run()[-1], "ibdiagnet")
        self.assertIn("本轮再试一次 ibdiagnet", result.stdout)
        self.assertIn("ibdiagnet 恢复成功", result.stdout)
        self.assertEqual(self.counts(), (0, 0))

    def run_record(self):
        [path] = list(self.ibdiag_output.glob("*.ufm-run.json"))
        self.assertRegex(path.name, r"^\d{8}-\d{4}-prod-[0-9a-f]{16}\.ufm-run\.json$")
        return json.loads(path.read_text())

    def test_every_run_leaves_a_record_naming_only_its_own_files(self):
        # Codex review 2026-10-22: what each run did is persisted; a failed or skipped run names no
        # report, so an older report can never be counted for it.
        import hashlib
        self.state["vip"] = {VIP: "198.51.101.132"}
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = self.run_record()
        [archive] = self.ibdiag_archives()
        run_id = archive.split("_", 1)[0]
        stem = f"{run_id}_ufm02-ibdiagnet-topology-validation"
        self.assertEqual((record["schema"], record["outcome"], record["run_id"], record["node"], record["kind"],
                          record["analysis"], record["cycle"]),
                         ("ufm-ib-run-record-v1", "ok", run_id, "ufm02", "ibdiagnet", "ok", None))
        for key, path in (("input", self.ibdiag_output / archive),
                          ("done", self.ibdiag_output / archive.replace(".tgz", ".done")),
                          ("report", self.p2p_output / f"{stem}.xlsx"),
                          ("receipt", self.p2p_output / f"{stem}.receipt.json")):
            content = path.read_bytes()
            self.assertEqual(record[key], {"name": path.name, "sha256": hashlib.sha256(content).hexdigest(),
                                           "size": len(content)}, key)
        receipt = json.loads((self.p2p_output / f"{stem}.receipt.json").read_text())
        self.assertEqual(receipt["done"]["sha256"], record["done"]["sha256"], "the receipt names this .done")

    def test_a_worker_run_record_carries_the_worker_cycle_identity(self):
        # Codex review 2026-10-22: REQ7 maps a worker cycle to this run through the record, not by time.
        import hashlib
        import tempfile
        identity = {"cycle_id": "c" * 64, "project_key": "site", "run_token": "t" * 32,
                    "scope": "infiniband/prod", "sequence": 7, "source": "page"}
        plan = {"eth": [], "spx": [], "ib": [], "nv": [], "dynamic_identities": [],
                "ufm": [f"{name}|{ip}" for name, (ip, _mac) in UFMS.items()]}
        plan_line = (json.dumps(plan, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
        inventory = self.project / "02-devices_config.csv"
        context = {"identity": identity, "target_plan": plan,
                   "target_plan_sha256": hashlib.sha256(plan_line).hexdigest(),
                   "artifacts": {"input_inventory": str(inventory)},
                   "input_inventory_sha256": hashlib.sha256(inventory.read_bytes()).hexdigest()}
        self.state["vip"] = {VIP: "198.51.101.132"}
        with tempfile.TemporaryFile() as handle:
            handle.write(json.dumps(context).encode())
            handle.flush()
            handle.seek(0)
            result = self.run_cron("--worker-context-fd", str(handle.fileno()), pass_fds=(handle.fileno(),))
        self.assertIn("loaded frozen target plan", result.stdout, result.stdout + result.stderr)
        record = self.run_record()
        self.assertEqual((record["cycle"], record["outcome"]), (identity, "ok"), result.stdout + result.stderr)

    def test_a_failed_run_is_recorded_with_its_own_done_and_no_report(self):
        self.state["vip"] = {VIP: "198.51.101.132"}
        result = self.run_cron(FAKE_IBDIAGNET_NO_NET_DUMP="1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = self.run_record()
        self.assertEqual((record["outcome"], record["input"], record["report"], record["receipt"],
                          record["analysis"], record["ibdiagnet_failures_in_a_row"]),
                         ("failed", None, None, None, "not_run", 1))
        self.assertIn("net_dump", record["reason"])
        done = self.ibdiag_output / record["done"]["name"]
        self.assertIn("result=failed", done.read_text(), "the UFM's failed .done is kept as evidence")
        self.assertEqual(self.ibdiag_archives(), [])

    def test_a_skipped_run_is_recorded_as_skipped(self):
        result = self.run_cron()   # no device holds the VIP
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = self.run_record()
        self.assertEqual((record["outcome"], record["run_id"], record["done"], record["report"]),
                         ("skipped", None, None, None))
        self.assertIn("HA 未就绪", record["reason"])

    def test_a_second_run_in_the_same_minute_never_replaces_an_archive(self):
        # Codex review 2026-10-22: minute names; a rerun within the minute fails instead of overwriting.
        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc)
        kept = {}
        for moment in (now, now + timedelta(minutes=1)):
            path = self.output / (moment.strftime("%Y%m%d-%H%M") + ".tar.gz")
            path.write_bytes(b"first run")
            kept[path] = b"first run"
        result = self.run_cron()
        self.assertIn("already exists (not replaced)", result.stdout)
        for path, content in kept.items():
            self.assertEqual(path.read_bytes(), content)
        self.assertIn("cron finish with UFM warnings", result.stdout)

    def test_a_skipped_run_does_not_touch_the_failure_count(self):
        self.ibdiag_output.mkdir(exist_ok=True)
        self.state_file().write_text("failures=2\nsince_probe=0\n")
        result = self.run_cron()   # no device holds the VIP: HA not ready
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.state_file().read_text(), "failures=2\nsince_probe=0\n")

    def test_everything_collected_is_kept_three_days_and_the_two_days_before_today_are_bundled(self):
        from datetime import datetime, timedelta, timezone
        today = datetime.now(timezone.utc)
        yesterday, old = ((today - timedelta(days=days)).strftime("%Y%m%d") for days in (1, 4))
        for day in (yesterday, old):
            for suffix in ("_ufm01_ibdiagnet2.tgz", "_ufm01_ibdiagnet2.done", "_ufm02_iblinkinfo.log"):
                (self.ibdiag_output / f"{day}-0100-prod-0000000000000001{suffix}").write_text("x")
        # owner 2026-10-23: the newest file of each kind always stays loose; here today's are the newest
        for suffix in ("_ufm01_ibdiagnet2.tgz", "_ufm01_ibdiagnet2.done", "_ufm02_iblinkinfo.log"):
            (self.ibdiag_output / f"{today.strftime('%Y%m%d')}-0000-prod-0000000000000002{suffix}").write_text("x")
        link = self.mkdir("infiniband/monitor/ib-link")
        for day in (yesterday, old):
            (link / f"{day}-0100.csv").write_text("csv")
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        today_name = today.strftime("%Y%m%d")
        names = sorted(path.name for path in self.ibdiag_output.iterdir() if not path.name.startswith(today_name))
        self.assertEqual(names, [f"{yesterday}-daily.tar.gz"], "yesterday bundled, four days ago deleted")
        members = [f"{yesterday}-0100-prod-0000000000000001{suffix}"
                   for suffix in ("_ufm01_ibdiagnet2.tgz", "_ufm01_ibdiagnet2.done", "_ufm02_iblinkinfo.log")]
        with tarfile.open(self.ibdiag_output / names[0]) as bundle:
            self.assertEqual(sorted(bundle.getnames()), sorted(members + [f"{yesterday}-daily.index"]))
            index = bundle.extractfile(f"{yesterday}-daily.index").read().decode()
        # codex review 2026-10-22: every member by sha256, size and its original name
        import hashlib
        self.assertEqual(sorted(index.splitlines()), sorted(
            f"{hashlib.sha256(b'x').hexdigest()}  1  {name}" for name in members))
        self.assertFalse(list(self.ibdiag_output.glob("*.part")))
        self.assertEqual(sorted(path.name for path in link.iterdir()), [f"{yesterday}-0100.csv"],
                         "CSVs stay unbundled for the page, and go after three days")

    def test_cronjob_log_is_compressed_at_10_mb_keeping_seven_copies(self):
        import gzip
        real = self.mkdir("DAY0-Prepare/site/99-output-monitor/infiniband") / "cronjob.log"
        real.write_bytes(b"first line\n" + b"x" * (10 * 1024 * 1024))
        (self.root / "infiniband/monitor/cronjob.log").symlink_to(real)
        for number in range(1, 8):
            with gzip.open(real.with_name(f"cronjob.log.{number}.gz"), "wb") as handle:
                handle.write(f"copy {number}\n".encode())
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(real.stat().st_size, 0, "emptied in place: the crontab redirection keeps writing to it")
        self.assertTrue((self.root / "infiniband/monitor/cronjob.log").is_symlink())
        with gzip.open(real.with_name("cronjob.log.1.gz")) as handle:
            self.assertTrue(handle.read().startswith(b"first line\n"))
        for number in range(2, 8):
            with gzip.open(real.with_name(f"cronjob.log.{number}.gz")) as handle:
                self.assertEqual(handle.read(), f"copy {number - 1}\n".encode())
        self.assertFalse(real.with_name("cronjob.log.8.gz").exists(), "at most seven copies")
        self.assertIn("cronjob.log 达到", result.stdout)

    def test_dated_reports_in_99_output_p2p_follow_the_same_rule_and_the_cvt_stays(self):
        # Owner 2026-10-22: every file with a date in its name follows the cron.sh rule, reports too.
        from datetime import datetime, timedelta, timezone
        today = datetime.now(timezone.utc)
        yesterday, old = ((today - timedelta(days=days)).strftime("%Y%m%d") for days in (1, 4))
        (self.root / "monitor/99-output-p2p").symlink_to(self.p2p_output)   # the page's setup link
        names = ("-0100-prod-0000000000000001_ufm01-ibdiagnet-topology-validation.xlsx",
                 "-0100-prod-0000000000000001_ufm01-ibdiagnet-topology-validation.xlsx.provenance.json",
                 "-0100-prod-0000000000000001_ufm01-ibdiagnet-topology-validation.receipt.json",
                 "-0100-prod-ethernet-topology-validation.xlsx")
        for day in (yesterday, old):
            for name in names:
                (self.p2p_output / f"{day}{name}").write_text("x")
        # owner 2026-10-23: the newest file of each kind always stays loose; here today's are the newest
        today_name = today.strftime("%Y%m%d")
        for name in names:
            (self.p2p_output / f"{today_name}{name.replace('-0100-', '-0000-').replace('0001_', '0002_')}").write_text("x")
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        # the hidden report lock lives in the directory (codex review 2026-10-22) and is not data
        self.assertTrue((self.p2p_output / ".report-writer.lock").is_file())
        self.assertEqual(sorted(path.name for path in self.p2p_output.iterdir()
                                if not path.name.startswith((".", today_name))),
                         sorted(["site-cvt.xlsx", f"{yesterday}-daily.tar.gz"]))
        with tarfile.open(self.p2p_output / f"{yesterday}-daily.tar.gz") as bundle:
            self.assertEqual(sorted(bundle.getnames()),
                             sorted([f"{yesterday}{name}" for name in names] + [f"{yesterday}-daily.index"]))

    def test_cron_leaves_the_logs_other_scripts_write_to_them(self):
        # Owner 2026-10-22: whoever writes a log rotates it; cron.sh rotates only its cronjob.log
        # (test_log_rotation covers the generator and the worker rotating their own).
        logs = [self.root / "monitor/generate-monitor.log", self.mkdir("monitor/status") / "switch-collection.log"]
        for log in logs:
            log.write_bytes(b"x" * (10 * 1024 * 1024))
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for log in logs:
            self.assertEqual(log.stat().st_size, 10 * 1024 * 1024, log.name)
            self.assertFalse(log.with_name(log.name + ".1.gz").exists(), log.name)

    def test_a_small_cronjob_log_is_left_alone(self):
        real = self.mkdir("DAY0-Prepare/site/99-output-monitor/infiniband") / "cronjob.log"
        real.write_text("short\n")
        (self.root / "infiniband/monitor/cronjob.log").symlink_to(real)
        self.run_cron()
        self.assertEqual(real.read_text(), "short\n")
        self.assertFalse(real.with_name("cronjob.log.1.gz").exists())

    def test_a_run_that_finds_the_previous_one_still_running_says_so_and_skips(self):
        self.write_exec(self.bin / "flock", "#!/bin/sh\nexit 1\n")   # the lock is held
        result = self.run_cron()
        self.assertEqual(result.returncode, 1)
        self.assertIn("上一轮采集仍在运行", result.stderr)
        self.assertIn("本轮跳过", result.stderr)
        self.assertFalse(self.calls.exists(), "nothing is contacted")


REAL_FLOCK = r'''#!{python}
"""flock(1) for the tests: locks the inherited descriptor, as util-linux does (-n, -s, -w seconds)."""
import fcntl, sys, time
mode, blocking, wait, fd, args = fcntl.LOCK_EX, True, None, None, sys.argv[1:]
while args:
    arg = args.pop(0)
    if arg == "-n":
        blocking = False
    elif arg == "-s":
        mode = fcntl.LOCK_SH
    elif arg == "-w":
        wait = float(args.pop(0))
    else:
        fd = int(arg)
deadline = None if wait is None else time.monotonic() + wait
while True:
    try:
        fcntl.flock(fd, mode | fcntl.LOCK_NB)
        sys.exit(0)
    except BlockingIOError:
        if not blocking or (deadline is not None and time.monotonic() >= deadline):
            sys.exit(1)
        time.sleep(0.05)
'''


class UfmSharedReportCleanupTest(UfmCronCase):
    """Codex review 2026-10-22: the shared 99-output-p2p is written by the post-collect of every lane and
    cleaned by whichever lane finishes; a report still being written is never bundled or deleted, a file
    that arrives after its day was bundled stays beside the bundle, and an old day leaves in full."""

    def setUp(self):
        super().setUp()
        self.write_exec(self.bin / "flock", REAL_FLOCK.replace("{python}", sys.executable))
        (self.root / "monitor/99-output-p2p").symlink_to(self.p2p_output)   # the page's setup link

    @staticmethod
    def days(*ago):
        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc)
        return [(now - timedelta(days=days)).strftime("%Y%m%d") for days in ago]

    def test_the_cleanup_leaves_reports_alone_while_a_report_is_being_written(self):
        import fcntl
        [yesterday, today] = self.days(1, 0)
        report = self.p2p_output / f"{yesterday}-2358-prod-0000000000000009_ufm01-ibdiagnet-topology-validation.xlsx"
        report.write_text("half written")
        # owner 2026-10-23: the newest file of each kind always stays loose; today's is the newest here
        (self.p2p_output / f"{today}-0000-prod-000000000000000a_ufm01-ibdiagnet-topology-validation.xlsx").write_text("x")
        with open(self.p2p_output / ".report-writer.lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_SH)   # another lane's post-collect is writing
            result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(report.read_text(), "half written")
        self.assertFalse((self.p2p_output / f"{yesterday}-daily.tar.gz").exists())
        self.assertIn("正在写报告", result.stdout)
        result = self.run_cron()   # the writer is gone: the day is bundled as usual
        self.assertFalse(report.exists())
        self.assertTrue((self.p2p_output / f"{yesterday}-daily.tar.gz").is_file())

    def test_the_ib_report_is_written_under_the_shared_report_lock(self):
        self.state["vip"] = {VIP: "198.51.101.132"}
        probe = self.root / "lock-probe"
        result = self.run_cron(FAKE_REPORT_LOCK_PROBE=str(probe))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(probe.read_text(), "held", "the cleanup of another lane cannot take the directory")

    def test_a_late_file_stays_beside_the_bundle_of_its_day(self):
        [yesterday] = self.days(1)
        (self.p2p_output / f"{yesterday}-0100-prod-ethernet-topology-validation.xlsx").write_text("x")
        self.run_cron()
        bundle = self.p2p_output / f"{yesterday}-daily.tar.gz"
        before = bundle.read_bytes()
        # a run that started before midnight published its report after the day was bundled
        late = self.p2p_output / f"{yesterday}-2358-prod-0000000000000009_ufm01-ibdiagnet-topology-validation.xlsx"
        late.write_text("late")
        result = self.run_cron()
        self.assertEqual((late.read_text(), bundle.read_bytes()), ("late", before), "neither is rewritten")
        self.assertIn("1 个迟到文件", result.stdout)

    def test_an_old_day_kept_only_as_a_bundle_is_deleted_with_its_late_files(self):
        [old] = self.days(4)
        for directory in (self.p2p_output, self.ibdiag_output):
            (directory / f"{old}-daily.tar.gz").write_bytes(b"bundle")
        late = self.p2p_output / f"{old}-2358-prod-0000000000000009_ufm01-ibdiagnet-topology-validation.xlsx"
        late.write_text("late")
        # owner 2026-10-23: the newest file of each kind always stays loose; today's is the newest here
        [today] = self.days(0)
        (self.p2p_output / f"{today}-0000-prod-000000000000000a_ufm01-ibdiagnet-topology-validation.xlsx").write_text("x")
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for directory in (self.p2p_output, self.ibdiag_output):
            self.assertEqual([path.name for path in directory.iterdir() if path.name.startswith(old)], [], directory)
        self.assertTrue((self.p2p_output / "site-cvt.xlsx").is_file(), "the CVT has no date and stays")

    def test_the_newest_switch_archive_stays_loose_for_the_page_after_a_ufm_only_run(self):
        # Owner 2026-10-23 (lab): a cron.sh run that collected only the UFMs bundled the IB switch archive of
        # the day before, the only one there, and the page lost every IB switch. 所有采集信息一定要留一份最新
        # 的散放；可以打包，但是不要删除掉最新的一份.
        yesterday, old = self.days(1, 4)
        info = self.mkdir("infiniband/monitor/ib-info")
        newest = info / f"{yesterday}-0659.tar.gz"
        for path in (info / f"{old}-0100.tar.gz", info / f"{yesterday}-0100.tar.gz", newest):
            path.write_text(path.name)
        result = self.run_cron()   # the fixture project has UFMs and no switch: a UFM-only run
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(sorted(path.name for path in info.iterdir()),
                         sorted([newest.name, f"{yesterday}-daily.tar.gz"]))
        self.assertEqual(newest.read_text(), newest.name)
        with tarfile.open(info / f"{yesterday}-daily.tar.gz") as bundle:
            self.assertEqual(bundle.getnames()[1:], [f"{yesterday}-0100.tar.gz", newest.name])
        self.assertIn(f"newest of its kind kept loose: {newest.name}", result.stdout)


class UfmCronCleanupCustodyContractTests(unittest.TestCase):
    def _confirmation(self, stack):
        reader, writer = os.pipe()
        return (stack.enter_context(os.fdopen(reader, "rb", buffering=0)),
                stack.enter_context(os.fdopen(writer, "wb", buffering=0)))

    def _send_confirmed_admission(self, custody, reply, stdio, confirmation_writer):
        _send_fds(custody.client, b"R", [reply.fileno(), *stdio, confirmation_writer.fileno()])
        confirmation_writer.close()

    def _expect_confirmation(self, confirmation_reader, expected=b"A"):
        self.assertTrue(select.select([confirmation_reader], [], [], 2)[0],
                        "fixture confirmation channel still open")
        self.assertEqual(expected, confirmation_reader.read(1))

    def test_fake_sender_waits_for_independent_admission_ack_or_fails_on_its_eof(self):
        from contextlib import ExitStack

        fixture = UfmCronCase()
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        host = UFMS["ufm01.example.test"][0]
        for accepted in (True, False):
            with self.subTest(accepted=accepted), ExitStack() as stack:
                broker, intake = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
                stack.enter_context(broker)
                stack.enter_context(intake)
                sender = stack.enter_context(subprocess.Popen(
                    [str(fixture.bin / "ssh"), f"root@{host}", "exit 37"],
                    cwd=fixture.root, env=fixture._fixture_environment(**{_CUSTODY_FD: str(intake.fileno())}),
                    pass_fds=(intake.fileno(),), stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                ))
                # On timeout or failed adoption, close the receiving end (and
                # queued ACK writers) before Popen.__exit__ waits for our sender.
                stack.callback(broker.close)
                broker.settimeout(2)
                tag, messages, flags, _ = broker.recvmsg(1, socket.CMSG_SPACE(64 * 1024))
                rights = array("i")
                for level, kind, payload in messages:
                    if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                        rights.frombytes(payload)
                # Adopt every test-owned right before asserting the wire contract.
                descriptors = [stack.enter_context(os.fdopen(fd, "wb", buffering=0)) for fd in rights]
                self.assertEqual(b"R", tag)
                self.assertFalse(flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC))
                self.assertEqual(5, len(descriptors), "admission needs a separate one-way confirmation pipe")
                request = stack.enter_context(socket.socket(fileno=os.dup(descriptors[0].fileno())))
                request.settimeout(2)
                confirmation = descriptors[-1]
                self.assertFalse(select.select([request], [], [], 0.1)[0],
                                 "the fake sender must not write any frame before confirmation")
                if accepted:
                    self.assertEqual(1, confirmation.write(b"A"))
                    confirmation.close()
                    size, = struct.unpack("!I", _receive_exact(request, 4))
                    self.assertEqual("exit 37", json.loads(_receive_exact(request, size))["command"])
                    request.sendall(struct.pack("!i", 37))
                    # Duplicate stdout/stderr pipe writers belong to this receiver.
                    for fd in descriptors:
                        fd.close()
                    stdout, stderr = sender.communicate(timeout=2)
                    self.assertEqual((37, b"", b""), (sender.returncode, stdout, stderr))
                else:
                    confirmation.close()
                    # ACK EOF must end the sender even while the test broker still holds the reply stream.
                    self.assertEqual(b"", request.recv(1), "a declined admission sent request bytes")
                    for fd in descriptors:
                        fd.close()
                    stdout, stderr = sender.communicate(timeout=2)
                    self.assertNotEqual(0, sender.returncode)
                    self.assertEqual(b"", stdout)
                    self.assertIn(b"UFM custody admission was not confirmed", stderr)

    def test_unconfirmed_admission_releases_ack_and_three_stdio_without_launching(self):
        from contextlib import ExitStack
        from unittest import mock

        custody = _RemoteSessionCustodian(Path("."), [])
        custody.closing.set()
        recv, original_reply = socket.socketpair()
        with ExitStack() as stack:
            stack.enter_context(recv)
            stack.enter_context(original_reply)
            readers, writers = [], []
            for _ in range(4):  # three stdio writes, then the independent ACK write
                reader, writer = os.pipe()
                stack.callback(os.close, reader)
                readers.append(reader)
                writers.append(stack.enter_context(os.fdopen(writer, "wb", buffering=0)))
            launch = stack.enter_context(mock.patch.object(custody, "_launch"))
            with custody:
                _send_fds(custody.client, b"R", [original_reply.fileno(), *(p.fileno() for p in writers)])
                for writer in writers:
                    writer.close()
                for reader in readers:
                    self.assertTrue(select.select([reader], [], [], 2)[0],
                                    "refusal must release every writer while sender retains its original reply")
                    self.assertEqual(b"", os.read(reader, 1), "unconfirmed request saw an acknowledgement")
                self.assertGreaterEqual(original_reply.fileno(), 0)
                self.assertIsNone(custody.error)
                launch.assert_not_called()

    def test_atomic_remote_admission_owns_reply_and_three_streams_before_reading_payload(self):
        from contextlib import ExitStack
        from unittest import mock

        custody = _RemoteSessionCustodian(Path("."), [])
        values = (b"synthetic stdin", b"synthetic stdout", b"synthetic stderr")
        payload = b"local protocol control"
        seen = []

        def observe(request, standard_streams):
            seen.append(tuple(os.read(fd, 64) for fd in standard_streams))
            size, = struct.unpack("!I", _receive_exact(request, 4))
            seen.append(_receive_exact(request, size))
            request.sendall(b"OK")

        recv, reply = socket.socketpair()
        with ExitStack() as stack:
            stack.enter_context(recv)
            stack.enter_context(reply)
            stdio = []
            for value in values:
                reader, writer = os.pipe()
                stack.callback(os.close, reader)
                try:
                    self.assertEqual(len(value), os.write(writer, value))
                finally:
                    os.close(writer)
                stdio.append(reader)
            stack.enter_context(mock.patch.object(custody, "_launch", side_effect=observe))
            stack.enter_context(custody)
            ack_reader, ack_writer = self._confirmation(stack)
            self._send_confirmed_admission(custody, reply, stdio, ack_writer)
            self._expect_confirmation(ack_reader)
            reply.close()
            # The request stream carries only the existing length/payload/status framing.
            recv.settimeout(2)
            try:
                recv.sendall(struct.pack("!I", len(payload)) + payload)
            except (BrokenPipeError, ConnectionResetError):
                pass
            self.assertEqual(b"OK", _receive_exact(recv, 2))
        self.assertEqual([values, payload], seen)

    def test_closing_admission_releases_all_transferred_streams_without_launching(self):
        from contextlib import ExitStack
        from unittest import mock

        custody = _RemoteSessionCustodian(Path("."), [])
        custody.closing.set()
        recv, reply = socket.socketpair()
        with ExitStack() as stack:
            stack.enter_context(recv)
            stack.enter_context(reply)
            held, readers, writers = [], [], []
            for _ in range(3):
                reader, writer = os.pipe()
                stack.callback(os.close, reader)
                writers.append(stack.enter_context(os.fdopen(writer, "wb", buffering=0)))
                readers.append(reader)
                held.append(writer)
            mocked = stack.enter_context(mock.patch.object(custody, "_launch"))
            stack.enter_context(custody)
            ack_reader, ack_writer = self._confirmation(stack)
            self._send_confirmed_admission(custody, reply, held, ack_writer)
            self._expect_confirmation(ack_reader, b"")
            reply.close()
            for writer in writers:
                writer.close()
            recv.settimeout(2)
            self.assertEqual(b"", recv.recv(1))
            for reader in readers:
                self.assertTrue(select.select([reader], [], [], 2)[0], "rejected stdio retained by broker")
                self.assertEqual(b"", os.read(reader, 1))
            self.assertIsNone(custody.error)
            mocked.assert_not_called()

    def test_admission_rejects_wrong_tag_or_count_and_releases_received_rights(self):
        from contextlib import ExitStack
        from unittest import mock

        for tag, count in ((b"R", 1), (b"R", 4), (b"R", 7), (b"X", 4), (b"?", 4)):
            with self.subTest(tag=tag, count=count), ExitStack() as stack:
                custody = _RemoteSessionCustodian(Path("."), [])
                recv, reply = socket.socketpair()
                stack.enter_context(recv)
                stack.enter_context(reply)
                reads, writes = [], []
                for _ in range(count - 1):
                    reader, writer = os.pipe()
                    stack.callback(os.close, reader)
                    reads.append(reader)
                    writes.append(stack.enter_context(os.fdopen(writer, "wb", buffering=0)))
                launch = stack.enter_context(mock.patch.object(custody, "_launch"))
                with self.assertRaises(RuntimeError) as raised:
                    with custody:
                        _send_fds(custody.client, tag, [reply.fileno(), *(p.fileno() for p in writes)])
                        reply.close()
                        for writer in writes:
                            writer.close()
                        recv.settimeout(2)
                        self.assertEqual(b"", recv.recv(1), "rejected reply must close")
                        for reader in reads:
                            self.assertTrue(select.select([reader], [], [], 2)[0], "malformed bundle retained stdio")
                            self.assertEqual(b"", os.read(reader, 1))
                        custody.thread.join(timeout=2)
                        launch.assert_not_called()
                        self.assertIsInstance(custody.error, RuntimeError)
                self.assertIs(custody.error, raised.exception)

    def test_invalid_reply_or_incomplete_length_cannot_launch_or_keep_owned_stdio(self):
        from contextlib import ExitStack
        from unittest import mock

        for socket_type, error_type in ((socket.SOCK_DGRAM, RuntimeError),
                                        (socket.SOCK_STREAM, EOFError)):
            with self.subTest(socket_type=socket_type), ExitStack() as stack:
                custody = _RemoteSessionCustodian(Path("."), [])
                recv, reply = socket.socketpair(socket.AF_UNIX, socket_type)
                stack.enter_context(recv)
                stack.enter_context(reply)
                readers, writers = [], []
                for _ in range(3):
                    reader, writer = os.pipe()
                    stack.callback(os.close, reader)
                    readers.append(reader)
                    writers.append(stack.enter_context(os.fdopen(writer, "wb", buffering=0)))
                launch = stack.enter_context(mock.patch.object(subprocess, "Popen"))
                ack_reader, ack_writer = self._confirmation(stack)
                with self.assertRaises(error_type) as caught:
                    with custody:
                        self._send_confirmed_admission(
                            custody, reply, [p.fileno() for p in writers], ack_writer,
                        )
                        self._expect_confirmation(ack_reader, b"A" if socket_type == socket.SOCK_STREAM else b"")
                        reply.close()
                        for writer in writers:
                            writer.close()
                        if socket_type == socket.SOCK_STREAM:
                            recv.sendall(b"\x00\x00")
                            recv.shutdown(socket.SHUT_WR)
                        for reader in readers:
                            self.assertTrue(select.select([reader], [], [], 2)[0], "refusal retained stdio")
                            self.assertEqual(b"", os.read(reader, 1))
                        custody.thread.join(timeout=2)
                        self.assertFalse(custody.thread.is_alive())
                        launch.assert_not_called()
                self.assertIs(custody.error, caught.exception)
                self.assertEqual([], custody.owned)

    def test_broker_launch_failure_closes_both_active_and_queued_request_streams(self):
        from contextlib import ExitStack
        from unittest import mock

        active = threading.Event()
        release = threading.Event()
        first_cause = RuntimeError("synthetic UFM fixture launch failure")
        custody = _RemoteSessionCustodian(Path("."), [])

        def fail_launch(request, standard_streams):
            active.set()
            if not release.wait(2):
                raise AssertionError("control did not queue the second request")
            raise first_cause

        first_reader, first_reply = socket.socketpair()
        queued_reader, queued_reply = socket.socketpair()
        with first_reader, first_reply, queued_reader, queued_reply, open(os.devnull, "rb") as inert, \
                mock.patch.object(custody, "_launch", side_effect=fail_launch), ExitStack() as stack:
            first_ack, first_ack_writer = self._confirmation(stack)
            queued_ack, queued_ack_writer = self._confirmation(stack)
            with self.assertRaisesRegex(RuntimeError, str(first_cause)) as stopped:
                with custody:
                    try:
                        self._send_confirmed_admission(custody, first_reply, [inert.fileno()] * 3, first_ack_writer)
                        self._expect_confirmation(first_ack)
                        first_reply.close()
                        self.assertTrue(active.wait(2), "the first request must reach the injected failure")
                        self._send_confirmed_admission(custody, queued_reply, [inert.fileno()] * 3, queued_ack_writer)
                    finally:
                        release.set()
                    custody.thread.join(timeout=2)
                    self.assertFalse(custody.thread.is_alive())
                    self.assertIs(first_cause, custody.error)
                    self._expect_confirmation(queued_ack, b"")
                    queued_reply.close()
                    for label, reader in (("active", first_reader), ("queued", queued_reader)):
                        self.assertTrue(select.select([reader], [], [], 2)[0],
                                        f"{label} request still waits after the first broker failure")
                        self.assertEqual(b"", reader.recv(1), f"{label} request cannot receive a success reply")
            self.assertIs(first_cause, stopped.exception)

    def test_cron_wait_timeout_keeps_the_prior_fixture_broker_failure_as_cause(self):
        from contextlib import ExitStack
        from unittest import mock

        custody = _RemoteSessionCustodian(Path("."), [])
        first_cause = RuntimeError("synthetic UFM broker failure before cron wait expires")
        expired = subprocess.TimeoutExpired(["synthetic-ufm-control"], _CRON_SECONDS)
        returned, transferred = socket.socketpair()
        reported = None
        with returned, transferred, open(os.devnull, "rb") as inert, \
                mock.patch.object(custody, "_launch", side_effect=first_cause), ExitStack() as stack:
            ack_reader, ack_writer = self._confirmation(stack)
            try:
                with custody:
                    self._send_confirmed_admission(custody, transferred, [inert.fileno()] * 3, ack_writer)
                    self._expect_confirmation(ack_reader)
                    transferred.close()
                    custody.thread.join(timeout=2)
                    self.assertFalse(custody.thread.is_alive())
                    self.assertIs(first_cause, custody.error)
                    raise expired
            except (RuntimeError, subprocess.TimeoutExpired) as exc:
                reported = exc
        self.assertIs(first_cause, reported)
        self.assertIs(expired, reported.__cause__)

    def test_unsettled_admissions_do_not_skip_cleanup_of_already_held_children(self):
        from unittest import mock

        subject = UfmCronCase()
        subject._unsettled_admissions = True
        subject._admissions_cleanup_deadline = time.monotonic()
        owned = mock.Mock()
        owned.process = mock.Mock(spec=subprocess.Popen, pid=424242, returncode=None)
        owned.writer_stopped.return_value = True
        subject._owned_remote_sessions = [owned]
        with mock.patch.object(os, "killpg") as signal_group:
            with self.assertRaisesRegex(AssertionError, "preserving fixture sandbox"):
                subject.stop_remote_sessions()
        signal_group.assert_called_once_with(owned.process.pid, signal.SIGTERM)
        owned.reap.assert_called_once()
        self.assertEqual([], subject._owned_remote_sessions)

    def test_audit_group_number_without_a_custodian_is_never_signalled_or_probed(self):
        from unittest import mock

        with tempfile.TemporaryDirectory(prefix="ufm-unowned-cleanup-") as folder:
            subject = UfmCronCase()
            subject.root = Path(folder)
            record = subject.root / "remote-sessions"
            audit_only = "424242\n"
            record.write_text(audit_only, encoding="ascii")
            with mock.patch.object(os, "killpg", side_effect=ProcessLookupError) as group, \
                    mock.patch.object(subprocess, "run") as lookup:
                subject.stop_remote_sessions()
            group.assert_not_called()
            lookup.assert_not_called()
            self.assertEqual(audit_only, record.read_text(encoding="ascii"))


class UfmCronNativeSessionCustodyTests(UfmCronCase):
    def test_fake_ssh_keeps_exact_streams_status_and_owned_detached_writer(self):
        from unittest import mock

        command = (
            'IFS= read -r line || exit 98; printf "stdout:%s\\n" "$line"; '
            'printf "fixture stderr\\n" >&2; '
        )
        writer = (
            'test -n "${FAKE_UFM_WRITER_FD:-}" || exit 98; '
            'printf "owned writer ready\\n" > custody-ready.part && mv custody-ready.part custody-ready || exit 98; '
            'while :; do sleep 0.05; done'
        )
        inside = f"nohup /bin/sh -c {shlex.quote(writer)} </dev/null >/dev/null 2>&1 &"
        command += f"docker exec ufm sh -c {shlex.quote(inside)} || exit 98; exit 37"
        addr = UFMS["ufm01.example.test"][0]
        result = self._run_with_custody([str(self.bin / "ssh"), f"root@{addr}", command],
                                        input_text="original stdin\n")
        self.assertEqual(37, result.returncode, (result.stdout, result.stderr))
        self.assertEqual("stdout:original stdin\n", result.stdout)
        self.assertEqual("fixture stderr\n", result.stderr)
        self.assertEqual(1, len(self._owned_remote_sessions))
        observed = self._owned_remote_sessions[0]
        ready = self.root / "hosts" / addr / "root" / "custody-ready"
        deadline = time.monotonic() + _REMOTE_CLEANUP_SECONDS
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual("owned writer ready\n", ready.read_text(encoding="ascii"))
        self.assertFalse(observed.writer_stopped(), "detached writer must still own the guard after fake SSH returns")

        record = self.root / "remote-sessions"
        audit_only = record.read_text(encoding="ascii") + "424242\n"
        record.write_text(audit_only, encoding="ascii")
        native_signal = os.killpg
        actual = []

        def original_signal(group, signum):
            self.assertEqual(observed.process.pid, group)
            self.assertIsNone(observed.process.returncode)
            actual.append(signum)
            return native_signal(group, signum)

        with mock.patch.object(os, "killpg", side_effect=original_signal):
            self.stop_remote_sessions()
        self.assertEqual([signal.SIGTERM], actual)
        self.assertIsNotNone(observed.process.returncode)
        self.assertEqual([], self._owned_remote_sessions)
        self.assertEqual(audit_only, record.read_text(encoding="ascii"))
        self.assertTrue(self.root.is_dir(), "group cleanup must precede removing the sandbox")


class UfmCronZombieCleanupControllerTests(unittest.TestCase):
    """Model only cleanup signals and exact-group metadata; never launch a UFM fixture."""

    GROUP = 424242

    def _observe_cleanup(self, stage, *, platform_name="darwin", stdout="",
                         stderr="", returncode=0, query_error=None, missing=False):
        from unittest import mock

        primary = (ProcessLookupError(3, "synthetic missing owned group") if missing
                   else PermissionError(1, "synthetic owned-group signal refusal"))
        signals, queries = [], []

        def signal_group(group, signum):
            self.assertEqual(self.GROUP, group, "never signal an unrecorded group")
            signals.append((group, signum))
            if stage == "poll" and len(signals) == 1:
                self.assertEqual(signal.SIGTERM, signum)
                return None
            self.assertEqual(signal.SIGTERM if stage == "signal" else 0, signum)
            raise primary

        def query_group(argv, **kwargs):
            expected = ["/bin/ps", "-x", "-g", str(self.GROUP), "-o", "pgid=,uid=,stat="]
            self.assertEqual(expected, argv, "only the recorded group metadata may be requested")
            queries.append(list(argv))
            if query_error is not None:
                raise query_error
            return subprocess.CompletedProcess(argv, returncode, stdout, stderr)

        with tempfile.TemporaryDirectory(prefix="ufm-cleanup-controller-") as folder:
            subject = UfmCronCase()
            subject.root = Path(folder)
            record = subject.root / "remote-sessions"
            original_record = f"{self.GROUP}\n"
            record.write_text(original_record, encoding="ascii")
            observed = None
            with mock.patch.object(os, "killpg", side_effect=signal_group), \
                    mock.patch.object(subprocess, "run", side_effect=query_group), \
                    mock.patch.object(sys, "platform", platform_name):
                try:
                    owner = mock.Mock(spec=subprocess.Popen, pid=self.GROUP, returncode=None)
                    subject._stop_modelled_owned_groups({self.GROUP: owner})
                except PermissionError as error:
                    observed = error
            self.assertEqual(original_record, record.read_text(encoding="ascii"))
        expected_signals = [(self.GROUP, signal.SIGTERM)]
        if stage == "poll":
            expected_signals.append((self.GROUP, 0))
        self.assertEqual(expected_signals, signals, "no additional signal after the refusal")
        return primary, observed, queries

    def test_darwin_eperm_accepts_only_current_uid_all_zombie_rows(self):
        uid = os.geteuid()
        outputs = (
            ("single-zombie", f"{self.GROUP} {uid} Z\n"),
            ("zombie-status-flags", f"{self.GROUP} {uid} Z+\n{self.GROUP} {uid} Zs\n"),
        )
        for stage in ("signal", "poll"):
            for name, stdout in outputs:
                with self.subTest(stage=stage, rows=name):
                    primary, observed, queries = self._observe_cleanup(stage, stdout=stdout)
                    if observed is not None:
                        self.assertIs(primary, observed)
                        self.fail("an exact current-UID all-Z group has no runnable remote writer")
                    self.assertEqual(1, len(queries), "the permission refusal needs exact group evidence")

    def test_darwin_eperm_keeps_unknown_live_or_foreign_groups_fatal(self):
        uid = os.geteuid()
        valid = f"{self.GROUP} {uid} Z\n"
        rejected = (
            ("empty", "", "", 0),
            ("whitespace-only", " \n", "", 0),
            ("live", f"{self.GROUP} {uid} S+\n", "", 0),
            ("mixed", valid + f"{self.GROUP} {uid} R\n", "", 0),
            ("foreign-uid", f"{self.GROUP} {uid + 1} Z\n", "", 0),
            ("wrong-group", f"{self.GROUP + 1} {uid} Z\n", "", 0),
            ("partial-row", f"{self.GROUP} {uid}\n", "", 0),
            ("extra-field", f"{self.GROUP} {uid} Z unexpected\n", "", 0),
            ("invalid-group", f"not-a-group {uid} Z\n", "", 0),
            ("invalid-uid", f"{self.GROUP} not-a-uid Z\n", "", 0),
            ("query-failed", valid, "", 1),
            ("query-stderr", valid, "synthetic metadata warning\n", 0),
        )
        for stage in ("signal", "poll"):
            for name, stdout, stderr, returncode in rejected:
                with self.subTest(stage=stage, refusal=name):
                    primary, observed, queries = self._observe_cleanup(
                        stage, stdout=stdout, stderr=stderr, returncode=returncode,
                    )
                    self.assertIs(primary, observed, "unknown group state must preserve the original refusal")
                    self.assertEqual(1, len(queries))
            with self.subTest(stage=stage, refusal="metadata-unavailable"):
                primary, observed, queries = self._observe_cleanup(
                    stage, stdout=valid, query_error=OSError("synthetic metadata unavailable"),
                )
                self.assertIs(primary, observed, "a metadata error is not evidence of group exit")
                self.assertEqual(1, len(queries))
            with self.subTest(stage=stage, refusal="not-darwin"):
                primary, observed, queries = self._observe_cleanup(
                    stage, platform_name="linux", stdout=valid,
                )
                self.assertIs(primary, observed, "the compatibility exception is Darwin-only")
                self.assertEqual([], queries)

    def test_missing_process_group_finishes_without_metadata_query(self):
        for stage in ("signal", "poll"):
            with self.subTest(stage=stage):
                _primary, observed, queries = self._observe_cleanup(stage, missing=True)
                self.assertIsNone(observed)
                self.assertEqual([], queries, "the existing missing-group path needs no ps command")


if __name__ == "__main__":
    unittest.main()
