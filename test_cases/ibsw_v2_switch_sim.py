"""Local simulated NVOS IB switches for the v2 upgrade tests (test support, not a test module).

Each switch has its own home directory, /proc and /sys under a private root, a state
directory and stub programs (`nv`, `curl`, `scp`, `getent`, ...). Commands that
tools/ibsw_v2_device.py sends run for real with bash on this machine: the check script,
the fetch helper, the v1 component step and the v1 owned runner. `nv action install`
records the request; the next probe sees the switch go down, come back with a new boot
id and the new version, then nvued becomes ready. The key login is accepted only when the
management key is in the switch's authorized_keys file, like a real sshd. `fail_command`
makes the n-th matching command raise an SshError (a timed-out query) instead of running.
`connector_for(credentials)` also checks the typed password like the switch's sshd and
refuses a wrong one with PASSWORD_REJECTED (what tools/fleet_ssh.py raises); every
password login is recorded in `password_logins`.
"""
import json
import os
import subprocess
import sys
import textwrap
import threading
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import fleet_ssh as ssh  # noqa: E402

HEALTH_OK = ("            operational  applied\n----------  -----------  -------\nstatus      OK\n"
             "status-led  green\n\nHealth issues\n=============\nNo Data\n")
PROGRAMS = ("/bin/bash", "/usr/bin/nohup", "/usr/bin/setsid", "/usr/bin/python3", "/usr/bin/scp", "/usr/bin/ssh",
            "/usr/bin/curl", "/usr/bin/sha256sum", "/usr/bin/timeout")


def _stub(directory, name, body):
    path = directory / name
    path.write_text("#!" + sys.executable + "\n" + textwrap.dedent(body), encoding="utf-8")
    path.chmod(0o755)


NV = '''
    import os, re, sys
    state = os.environ["FAKE_STATE"]
    def read(name):
        try:
            return open(os.path.join(state, name)).read()
        except FileNotFoundError:
            return ""
    def write(name, text):
        open(os.path.join(state, name), "w").write(text)
    args = sys.argv[1:]
    if args == ["show", "system", "version"]:
        print("                operational\\n--------------  -----------\\nkernel          5.10.0-nvos\\n"
              "build-date      2026-01-01\\nimage           nvos-%s\\nonie            2023.05" % read("version").strip())
    elif args == ["show", "platform", "firmware"]:
        print("Name   Actual FW        Part Number  FW Source\\n-----  ---------------  -----------  ---------\\n"
              "BIOS   0ACQF_06.01.003  N/A          default")
    elif args == ["show", "system", "health"]:
        sys.stdout.write(open(os.path.join(state, "health")).read())
    elif args[:2] == ["config", "show"]:
        sys.stdout.write(read("config"))
    elif args[:2] == ["config", "diff"]:
        sys.stdout.write(read("pending"))
    elif args[:2] == ["config", "patch"]:
        write("pending", open(args[2]).read())
    elif args[:2] == ["config", "apply"]:
        write("config", read("config") + read("pending")); write("pending", "")
    elif args[:2] == ["config", "save"]:
        pass
    elif args[:4] == ["action", "fetch", "system", "image"]:
        path = args[4][len("file://"):]
        if not os.path.isfile(path):
            print("Error: file not found"); sys.exit(1)
        write("fetched", read("fetched") + os.path.basename(path) + "\\n")
        print("Action succeeded")
    elif args[:4] == ["action", "install", "system", "image"]:
        version = re.fullmatch(r"nvos-amd64-([0-9.]+)\\.bin", args[5])[1]
        write("install_target", version)
        print("Action succeeded")
    else:
        sys.exit(2)
'''


class LocalSwitch:
    def __init__(self, base, hostname, address, mac, version, *, password, down=0.3, nvue=0.2,
                 drop_keys_on_reboot=False, lose_config_line=None):
        self.hostname, self.address, self.mac = hostname, address, mac
        self.login_password = password
        self.down, self.nvue = down, nvue
        self.drop_keys_on_reboot, self.lose_config_line = drop_keys_on_reboot, lose_config_line
        root = Path(os.path.realpath(base)) / hostname
        self.home = root / "home" / "admin"
        self.sysroot, self.state, self.bin = root / "sysroot", root / "state", root / "bin"
        for path in (self.home, self.sysroot / "proc/sys/kernel/random", self.sysroot / "sys/class/net/eth0",
                     self.sysroot / "usr/bin", self.sysroot / "bin", self.state, self.bin, self.home / ".ssh"):
            path.mkdir(parents=True, exist_ok=True)
        for path in (root, root / "home", self.home):
            path.chmod(0o755)
        (self.home / ".ssh").chmod(0o700)
        keys = self.home / ".ssh" / "authorized_keys"
        operator = ssh._sdk().ECDSAKey.generate()               # generated per run: no key material in the file
        keys.write_text(f"{operator.get_name()} {operator.get_base64()} operator\n")
        keys.chmod(0o600)
        for program in PROGRAMS:
            fake = self.sysroot / program.lstrip("/")
            fake.write_text("#\n")
            fake.chmod(0o755)
        (self.sysroot / "proc/uptime").write_text("100.00 50.00\n")
        (self.sysroot / "sys/class/net/eth0/address").write_text(mac + "\n")
        self._boot(str(uuid.uuid4()))
        (self.state / "version").write_text(version)
        (self.state / "health").write_text(HEALTH_OK)
        (self.state / "config").write_text(f"nv set system hostname {hostname}\nnv set system ntp server 192.0.2.123\n")
        (self.state / "pending").write_text("")
        _stub(self.bin, "nv", NV)
        _stub(self.bin, "hostname", f"print({hostname!r})\n")
        _stub(self.bin, "timeout", "import os, sys\nos.execvp(sys.argv[2], sys.argv[2:])\n")
        _stub(self.bin, "stat", """
            import os, sys
            item = os.stat(sys.argv[-1])
            print(item.st_size if sys.argv[2] == "%s" else int(item.st_mtime))
        """)
        _stub(self.bin, "sha256sum", """
            import hashlib, sys
            print(hashlib.sha256(open(sys.argv[-1], "rb").read()).hexdigest() + "  " + sys.argv[-1])
        """)
        _stub(self.bin, "getent", f"import os\nprint('admin:x:%d:%d::{self.home}:/bin/bash' % (os.getuid(), os.getgid()))\n")
        _stub(self.bin, "id", """
            import os, sys
            print(os.getuid())
        """)
        _stub(self.bin, "systemctl", """
            import os
            state = open(os.path.join(os.environ["FAKE_STATE"], "nvued")).read().strip()
            print("ActiveState=active\\nSubState=running" if state == "running" else "ActiveState=activating\\nSubState=start")
        """)
        _stub(self.bin, "pgrep", "import sys\nsys.exit(1)\n")
        _stub(self.bin, "curl", """
            import os, sys, shutil
            argv = sys.argv[1:]
            out, url = argv[argv.index("-o") + 1], argv[-1]
            source = os.path.join(os.environ["FAKE_HTTP_ROOT"], url.split("/", 3)[3])
            if not os.path.isfile(source):
                sys.stdout.write("404|0|0.1|0"); sys.exit(22)
            shutil.copyfile(source, out)
            sys.stdout.write("200|%d|0.1|1000" % os.path.getsize(out))
        """)
        _stub(self.bin, "scp", """
            import os, shlex, shutil, sys
            argv = sys.argv[1:]
            sys.stdout.write("admin@peer's password: "); sys.stdout.flush()
            if sys.stdin.readline().rstrip("\\n") != os.environ["FAKE_SWITCH_PASSWORD"]:
                sys.stdout.write("Permission denied (password).\\n"); sys.exit(1)
            remote = shlex.split(argv[-2].split(":", 1)[1])[0]
            shutil.copyfile(remote, argv[-1])
            with open(os.path.join(os.environ["FAKE_STATE"], "scp-log"), "a") as log:
                log.write(argv[-2].split(":", 1)[0] + " " + remote + "\\n")
        """)
        (self.state / "nvued").write_text("running")
        self.lock = threading.Lock()
        self.rebooting_until, self.nvue_at, self.pending_version = None, None, None
        self.faults = []                                        # [marker, SshError code, occurrences left]

    def fail_command(self, marker, code, *, occurrence=1):
        """The occurrence-th command whose text contains marker raises SshError(code) instead of running."""
        with self.lock:
            self.faults.append([marker, code, occurrence])

    def take_fault(self, command):
        with self.lock:
            for fault in self.faults:
                if fault[0] in command:
                    fault[2] -= 1
                    if fault[2] == 0:
                        self.faults.remove(fault)
                        return fault[1]
                    return None
        return None

    def _boot(self, value):
        (self.sysroot / "proc/sys/kernel/random/boot_id").write_text(value + "\n")
        self.boot_id = value

    def tick(self):
        """Advance the simulated reboot: install request -> down -> new boot -> nvued ready."""
        with self.lock:
            now = time.monotonic()
            target = self.state / "install_target"
            if self.rebooting_until is None and target.exists():
                self.pending_version = target.read_text().strip()
                target.unlink()
                self.rebooting_until = now + self.down
            if self.rebooting_until is not None and now >= self.rebooting_until:
                self.rebooting_until = None
                self._boot(str(uuid.uuid4()))
                (self.state / "version").write_text(self.pending_version)
                (self.state / "nvued").write_text("starting")
                self.nvue_at = now + self.nvue
                if self.drop_keys_on_reboot:
                    keys = self.home / ".ssh" / "authorized_keys"
                    keys.write_text("".join(line for line in keys.read_text().splitlines(True)
                                            if "operator" in line))
                if self.lose_config_line:
                    config = self.state / "config"
                    config.write_text(config.read_text().replace(self.lose_config_line, ""))
            if self.nvue_at is not None and now >= self.nvue_at:
                (self.state / "nvued").write_text("running")
                self.nvue_at = None
            return self.rebooting_until is not None

    def key_allowed(self, key_base64):
        return key_base64 in (self.home / ".ssh" / "authorized_keys").read_text()


class Result(ssh.Result):
    pass


class LocalFile:
    def __init__(self, handle):
        self.handle = handle

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()

    def write(self, data):
        self.handle.write(data)

    def read(self, size=-1):
        return self.handle.read(size)

    def flush(self):
        self.handle.flush()

    def seek(self, offset):
        self.handle.seek(offset)

    def stat(self):
        return os.fstat(self.handle.fileno())

    def close(self):
        self.handle.close()


class LocalSftp:
    MODES = {"r": "rb", "rb": "rb", "wx": "xb", "w+x": "x+b", "w": "wb"}

    def lstat(self, path):
        return os.lstat(path)

    def open(self, path, mode="r"):
        return LocalFile(open(path, self.MODES[mode]))

    def mkdir(self, path, mode=0o777):
        os.mkdir(path, mode)

    def chmod(self, path, mode):
        os.chmod(path, mode)

    def rename(self, old, new):
        if os.path.exists(new):
            raise OSError("exists")
        os.rename(old, new)

    def posix_rename(self, old, new):
        os.replace(old, new)

    def remove(self, path):
        os.unlink(path)

    def close(self):
        pass


class LocalSession:
    def __init__(self, switch, fleet, method):
        self.switch, self.fleet, self.authentication = switch, fleet, method
        self._sftp = LocalSftp()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()

    def close(self):
        pass

    def sftp(self):
        return self._sftp

    def run(self, command, *, timeout=25.0, stdin=None, limit=None):
        switch = self.switch
        if switch.tick():
            raise ssh.SshError("COMMAND_INCOMPLETE")
        fault = switch.take_fault(command)
        if fault is not None:
            raise ssh.SshError(fault)
        command = (command.replace("/proc/sys/kernel/random/boot_id", str(switch.sysroot / "proc/sys/kernel/random/boot_id"))
                   .replace("/sys/class/net/eth0/address", str(switch.sysroot / "sys/class/net/eth0/address"))
                   .replace("/usr/bin/python3", sys.executable))
        if stdin is not None and command.startswith(sys.executable + " -c"):
            context = json.loads(stdin.decode())
            context.update(curl=str(switch.bin / "curl"), scp=str(switch.bin / "scp"), retry_sleep=0)
            stdin = (json.dumps(context) + "\n").encode()
            self.fleet.contexts.append(context)
        env = {"PATH": f"{switch.bin}:/usr/bin:/bin", "IBSW_SYSROOT": str(switch.sysroot), "LC_ALL": "C",
               "FAKE_STATE": str(switch.state), "FAKE_HTTP_ROOT": str(self.fleet.http_root),
               "FAKE_SWITCH_PASSWORD": switch.login_password, "HOME": str(switch.home)}
        started = time.monotonic()
        try:
            done = subprocess.run(["/bin/bash", "-c", command], input=stdin or b"", capture_output=True, env=env,
                                  cwd=switch.home, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise ssh.SshError("COMMAND_TIMEOUT") from None
        self.fleet.commands.append((switch.hostname, self.authentication, command[:120]))
        return ssh.Result(done.returncode, done.stdout, done.stderr, True, time.monotonic() - started)


class SimFleet:
    """connector / ping / tcp / dir_for hooks for ibsw_v2_device.LiveOps over local switches."""

    def __init__(self, switches, http_root, key_base64):
        self.switches = {switch.hostname: switch for switch in switches}
        self.by_address = {switch.address: switch for switch in switches}
        self.http_root, self.key_base64 = http_root, key_base64
        self.commands, self.contexts = [], []
        self.password_logins = []                               # (hostname, accepted) per checked password login

    def connector(self, device, method, *, password=None):
        """password=None: the password is not checked (older tests); otherwise a wrong one is refused."""
        switch = self.switches[device.hostname]
        if switch.tick():
            raise ssh.SshError("CONNECT_FAILED")
        if method == "key" and not switch.key_allowed(self.key_base64):
            raise ssh.SshError("AUTH_REJECTED")
        if method == "password" and password is not None:
            accepted = password == switch.login_password
            self.password_logins.append((switch.hostname, accepted))
            if not accepted:
                raise ssh.SshError("PASSWORD_REJECTED")
        return LocalSession(switch, self, method)

    def connector_for(self, credentials):
        """A connector(device, method) for LiveOps that checks the credentials' password."""
        return lambda device, method: self.connector(device, method, password=credentials.password)

    def ping_run(self, argv, **_kwargs):
        switch = self.by_address[argv[-1]]
        return subprocess.CompletedProcess(argv, 1 if switch.tick() else 0)

    def tcp(self, address):
        return not self.by_address[address].tick()

    def dir_for(self, device):
        return str(self.switches[device.hostname].home)
