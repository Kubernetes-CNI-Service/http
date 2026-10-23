#!/usr/bin/env python3
"""Direct contracts for infra/infra-setup.py (the management/client host setup entry).

infra-setup.py is the active entry; infra-setup.sh is kept (保留) but no caller runs it.  The shell
script's observable contract is recorded here as literals (usage text, the CLI error table, package
arrays, the lldpd and ports.conf contents) and re-checked against the kept script; the Apache
boundary is bound to DAY0 load's pinned hash and the control-auth pin to tools/control-auth.py
itself.  None is copied from the Python implementation.
Every run happens in a temporary sandbox: host paths are redirected through the script's HOST_ROOT
seam, mutating commands (systemctl, timedatectl, apt-get, dpkg, a2enmod, ...) are fakes placed
first on PATH, the fake `bash` rewrites canonical host paths inside ubuntu24_host scripts into the
sandbox, and the fake `python3` intercepts the installed control-auth helper so the real helper
never runs.
"""

from __future__ import annotations

import hashlib
import importlib.util
import gzip
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
PY_SETUP = ROOT / "infra/infra-setup.py"
HOST_MODULE = ROOT / "infra/ubuntu24_host.py"
NEUTRAL = ROOT / "infra/infra-neutral.conf"
CONTROL_AUTH = ROOT / "tools/control-auth.py"

GLOBAL = """\
common:
  switch:
    system:
      dns:
        server:
          - 160.250.70.5
          - 8.8.8.8
      ntp:
        server:
          - 160.250.71.253
          - ntp.ubuntu.com
      date-time:
        timezone: Asia/Taipei
"""
UBUNTU_RESOLVED = "[Resolve]\n#DNS=\n#FallbackDNS=\n#Domains=\n#DNSSEC=no\n"
UBUNTU_TIMESYNCD = "[Time]\n#NTP=\n#FallbackNTP=ntp.ubuntu.com\n#RootDistanceMaxSec=5\n"
ORIGINAL_HOSTS = "127.0.0.1\tlocalhost\n"
DOCA_VERSION = "3.3.0-088000-26.01-ubuntu2404"
DOCA_DEB = "doca-host_3.3.0-088000-26.01-ubuntu2404_amd64.deb"
# The files infra-teardown.sh accepts from managed-files (its restore_managed_files case list).
TEARDOWN_MANAGED_PATHS = {
    "/etc/hosts", "/etc/systemd/resolved.conf", "/etc/systemd/timesyncd.conf", "/etc/lldpd.d/lldpcli.conf",
    "/etc/apache2/conf-available/servername.conf", "/etc/apache2/ports.conf",
    "/etc/apache2/conf-enabled/http-ztp-listeners.conf",
    "/etc/apache2/conf-enabled/http-ztp-public-boundary.conf", "/etc/apache2/sites-enabled/000-default.conf",
}

# Recorded from infra-setup.sh (its usage heredoc, renamed to the Python entry).
SH_USAGE = """Usage: infra-setup.py [options]
  --client                Use client policy (default): no Apache/DHCP, BF NIC yes, power cycle no
  --interactive           Prompt for optional software and BlueField actions
  --non-interactive       Never prompt; apply the selected policy and explicit action flags
  --all                   Confirm all optional software and BlueField actions
  --install-apache        Install/configure Apache without prompting
  --install-dhcp          Install ISC DHCP server without prompting
  --download-doca         Download/cache DOCA without installing doca-ofed when no NIC is detected
  --skip-doca             Skip all DOCA download, cache and installation actions
  --enable-bluefield-nic  Change detected BlueField DPU mode to NIC mode
  --power-cycle           Allow required BlueField power cycle after mode change
  --mgmt                  Cache downloaded DEBs in ../apps and publish a local APT repository
                          Without a Mellanox NIC, DOCA defaults to cache after 10s, without install
  --offline               With --mgmt, require a matching ../apps repository; never use Internet
  --defer-services        Install/configure Apache and DHCP but never start/restart them
                          Intended for transactional load; activation happens only after commit
  --recover-monitor-authority
                          Stop Apache and explicitly repair invalid Monitor cache content
  -h, --help              Show this help
"""
# (argv, exit code, stdout, stderr) observed from `bash infra/infra-setup.sh ARGV` (name normalised).
EXCLUSIVE = "ERROR: --client, --interactive and --all are mutually exclusive.\n"
SH_CLI_TABLE = (
    (["--bogus"], 2, "", "ERROR: Unknown option: --bogus\n" + SH_USAGE),
    (["--client", "--all"], 2, "", EXCLUSIVE),
    (["--interactive", "--client"], 2, "", EXCLUSIVE),
    (["--all", "--all", "--client"], 2, "", EXCLUSIVE),
    (["--recover-monitor-authority", "--client"], 2, "",
     "ERROR: --recover-monitor-authority must be the only option.\n"),
    (["--client", "--recover-monitor-authority"], 2, "",
     "ERROR: --recover-monitor-authority must be the only option.\n"),
    (["--download-doca", "--skip-doca"], 2, "", "ERROR: --download-doca and --skip-doca are mutually exclusive.\n"),
    (["--offline"], 2, "", "ERROR: --offline is only valid together with --mgmt.\n"),
    (["--mgmt", "--offline", "--download-doca"], 2, "", "ERROR: --offline cannot be combined with --download-doca.\n"),
    (["--help"], 0, SH_USAGE, ""),
    (["-h", "--bogus"], 0, SH_USAGE, ""),
    (["--client", "--all", "--help"], 2, "", EXCLUSIVE),
    (["--help", "--client", "--all"], 0, SH_USAGE, ""),
)
SH_LLDP = ("configure system hostname .\n"
           "configure lldp portidsubtype ifname\n"
           "configure system interface pattern eth*,eno*,enp*,ens*,enP*\n")
# ports.conf keeps the shell script's two lines; only the managed-by marker names the new entry.
EXPECTED_PORTS = ("# Managed by http/infra/infra-setup.py.\n"
                  "# DAY0-Prepare/11-load.py owns every exact service-IPv4 Listen directive.\n")
SH_BASE = ["wget", "lldpd", "tzdata"]
SH_COMMON = ["ipmitool", "sshpass", "docker.io", "unzip", "nfs-common", "arping", "jq"]
SH_ZTP = ["python3", "python3-yaml", "python3-jinja2", "python3-openpyxl", "python3-pandas",
          "python3-xlsxwriter", "openssh-client", "curl"]
SH_OPTIONAL = ["apache2", "apache2-utils", "ssl-cert", "isc-dhcp-server"]
SH_MODULES = ["auth_basic", "authn_file", "authn_core", "authz_user", "authz_core", "env", "alias", "cgid",
              "headers"]
SH_CONTROL_AUTH_SHA = hashlib.sha256(CONTROL_AUTH.read_bytes()).hexdigest()
LOAD_BOUNDARY_SHA = re.search(
    r'APACHE_PUBLIC_BOUNDARY_SHA256 = \(\s*"([0-9a-f]{64})"',
    (ROOT / "DAY0-Prepare/11-load.py").read_text(encoding="utf-8")).group(1)
DOCKER_BOUNDARY = (ROOT / "infra/docker/apache-ztp.conf").read_text(encoding="utf-8")


FAKE_TOOL = r'''#!{python}
import json, os, re, subprocess, sys, time

STATE = os.environ["FAKE_INFRA_STATE"]
ROOT = os.environ["FAKE_INFRA_ROOT"]
REWRITE = re.compile(r"(?<![\w/.-])(/etc/|/usr/share/zoneinfo|/run/|/var/lib/http-infra)")


def load():
    with open(STATE) as handle:
        return json.load(handle)


def save(state):
    temporary = f"{STATE}.tmp{os.getpid()}"
    with open(temporary, "w") as handle:
        json.dump(state, handle)
    os.replace(temporary, STATE)


def host(path):
    return os.path.join(ROOT, path.lstrip("/"))


def record(entry):
    with open(STATE + ".calls", "a") as handle:
        handle.write(json.dumps(entry) + "\n")


def write_deb(path, package, version, arch="amd64"):
    with open(path, "w") as handle:
        json.dump({"Package": package, "Version": version, "Architecture": arch}, handle)


def systemctl(state, args):
    units, active = state.setdefault("unit_state", {}), state.setdefault("active", {})
    if args[:3] == ["show", "--property=LoadState", "--value"]:
        unit = args[3]
        print("not-found" if unit in state.get("missing_units", []) else
              "masked" if units.get(unit) == "masked" else "loaded")
        return 0
    if args[:3] == ["show", "--property=ActiveState", "--value"]:
        print(active.get(args[3], "inactive"))
        return 0
    if args[:1] == ["is-enabled"]:
        value = units.get(args[1], "enabled")
        print(value)
        return 0 if value == "enabled" else 1
    if args[:1] == ["is-active"]:
        return 0 if active.get(args[-1]) == "active" else 3
    unit = args[-1]
    if args[0] in ("restart", "start") and units.get(unit) == "masked":
        print(f"Failed to {args[0]} {unit}: Unit {unit} is masked.", file=sys.stderr)
        return 1
    if args[0] == "unmask":
        units[unit] = "disabled"
    elif args[:2] == ["enable", "--now"]:
        units[unit], active[unit] = "enabled", "active"
    elif args[0] in ("restart", "start"):
        active[unit] = "active"
    elif args[0] == "stop":
        active[unit] = "inactive"
    elif args[0] == "disable":
        units[unit] = "disabled"
    else:
        return 97
    save(state)
    return 0


def apt_get(state, args):
    options, rest, index = {}, [], 0
    while index < len(args):
        if args[index] == "-o":
            key, _, value = args[index + 1].partition("=")
            options[key] = value
            index += 2
        else:
            rest.append(args[index])
            index += 1
    if rest == ["update"]:
        return 0
    download = "--download-only" in rest
    rest = [item for item in rest if item not in ("--download-only", "-y")]
    if rest[:1] != ["install"]:
        return 97
    packages = rest[1:]
    if download:
        for package in packages:
            write_deb(os.path.join(options["Dir::Cache::archives"], f"{package}_1.0_amd64.deb"), package, "1.0")
        print("Download complete and in download only mode")
        return 0
    for package in packages:
        if package in state.get("apt_unavailable", []):
            print(f"E: Unable to locate package {package}")
            return 100
    for package in packages:
        if package.endswith(".deb"):
            with open(package) as handle:
                meta = json.load(handle)
            state["installed"][meta["Package"]] = meta["Version"]
        else:
            state["installed"][package] = f"{package}-test-1"
            if package == "tzdata":
                for zone in state.get("tzdata_zones", []):
                    path = host(f"/usr/share/zoneinfo/{zone}")
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, "w") as handle:
                        handle.write("TZif2\n")
    save(state)
    print("Fetched 1 kB in 0s (1 kB/s)")
    return 0


def python3(state, args):
    if len(args) < 2 or not args[0].endswith("control-auth.py"):
        print(f"fake python3 refuses to run {args!r}", file=sys.stderr)
        return 99
    command = args[1]
    spec = state.get("monitor", {}).get(command)
    if spec is None:
        spec = ({"stdout": "attest-valid"} if command.endswith("-decision") else
                {"stdout": '{"valid": true}\n'} if command == "status" else {})
    if spec.get("spawn"):
        subprocess.Popen(["sleep", "30"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
    if spec.get("sleep"):
        time.sleep(spec["sleep"])
    sys.stdout.write(spec.get("stdout", ""))
    sys.stderr.write(spec.get("stderr", ""))
    return spec.get("rc", 0)


def main():
    tool, args = os.path.basename(sys.argv[0]), sys.argv[1:]
    state = load()
    entry = {"tool": tool, "args": args if tool != "bash" else args[:1] + [args[-1][:120]]}
    if tool == "apt-get":
        policy = host("/usr/sbin/policy-rc.d")
        entry["policy"] = open(policy).read() if os.path.isfile(policy) else None
        for option in args:
            if option.startswith("Dir::Etc::sourcelist="):
                entry["sources"] = open(option.split("=", 1)[1]).read()
    record(entry)
    key = " ".join([tool] + args)
    if key in state.get("fail", {}):
        print(f"fake failure: {key}", file=sys.stderr)
        return state["fail"][key]
    if tool == "hostname":
        if args == []:
            print(state["hostname"])
            return 0
        if args == ["-f"]:
            print(state.get("fqdn", state["hostname"]))
            return 0
        return 97
    if tool == "getent" and args[:1] == ["hosts"] and len(args) == 2:
        for line in open(host("/etc/hosts")).read().splitlines():
            if args[1] in line.split()[1:]:
                print(line)
                return 0
        return 2
    if tool == "systemctl":
        return systemctl(state, args)
    if tool == "timedatectl":
        if args == ["show", "-p", "Timezone", "--value"]:
            print(state["timezone"])
            return 0
        if args == ["show", "-p", "NTPSynchronized", "--value"]:
            print("yes")
            return 0
        if args[:1] == ["set-timezone"] and len(args) == 2:
            state["timezone"] = args[1]
            save(state)
            return 0
        if args == ["status"]:
            print(f"                Time zone: {state['timezone']}")
            return 0
        return 97
    if tool == "dpkg" and args[:1] == ["-s"]:
        return 0 if args[1] in state["installed"] else 1
    if tool == "dpkg-query" and args[:1] == ["-W"]:
        if args[2] not in state["installed"]:
            return 1
        sys.stdout.write(state["installed"][args[2]] if args[1] == "-f=${Version}" else "installed")
        return 0
    if tool == "dpkg-deb" and args[:1] == ["-f"]:
        try:
            with open(args[1]) as handle:
                meta = json.load(handle)
        except (OSError, ValueError):
            return 2
        if len(args) == 3:
            print(meta.get(args[2], ""))
        else:
            print("".join(f"{key}: {value}\n" for key, value in meta.items()), end="")
        return 0
    if tool == "apt-get":
        return apt_get(state, args)
    if tool == "lspci":
        print(state.get("lspci", ""), end="")
        return 0
    if tool == "uname" and args == ["-m"]:
        print("x86_64")
        return 0
    if tool == "wget":
        if args[:2] == ["-q", "--spider"]:
            return 0 if args[2] in state.get("reachable", []) else 8
        if args[:1] == ["-q"] and args[2:3] == ["-O"]:
            meta = state["download"]
            write_deb(args[3], meta["Package"], meta["Version"], meta["Architecture"])
            print("downloaded")
            return 0
        return 97
    if tool == "curl":
        return 7
    if tool in ("a2enconf", "a2enmod"):
        kind, suffix = ("conf", ".conf") if tool == "a2enconf" else ("mods", ".load")
        enabled = host(f"/etc/apache2/{kind}-enabled/{args[0]}{suffix}")
        os.makedirs(os.path.dirname(enabled), exist_ok=True)
        if not os.path.lexists(enabled):
            os.symlink(f"../{kind}-available/{args[0]}{suffix}", enabled)
        return 0
    if tool in ("ipmitool", "mst"):
        if tool == "mst" and args == ["status"]:
            print(state.get("mst_status", ""))
        return 0
    if tool == "a2dissite":
        path = host(f"/etc/apache2/sites-enabled/{args[0]}.conf")
        if os.path.lexists(path):
            os.unlink(path)
        return 0
    if tool == "apache2ctl" and args == ["configtest"]:
        print("Syntax OK")
        return state.get("configtest_rc", 0)
    if tool == "mlxconfig":
        if args[2:] == ["q"]:
            print(state.get("mlxconfig_q", ""))
        return 0
    if tool == "python3":
        return python3(state, args)
    if tool == "bash" and len(args) == 2 and args[0] == "-c":
        os.execv("/bin/bash", ["/bin/bash", "-c", REWRITE.sub(lambda m: ROOT + m.group(1), args[1])])
    print(f"fake tool: unsupported {tool} {args}", file=sys.stderr)
    return 97


if __name__ == "__main__":
    sys.exit(main())
'''
FAKE_TOOL_NAMES = ("hostname", "hostnamectl", "getent", "systemctl", "timedatectl", "dpkg", "dpkg-query",
                   "dpkg-deb", "apt-get", "lspci", "uname", "wget", "curl", "a2enconf", "a2enmod", "a2dissite",
                   "apache2ctl", "mst", "mlxconfig", "ipmitool", "python3", "bash")

LAUNCHER = r'''
import importlib.util, json, os, sys
from pathlib import Path

config = json.loads(os.environ["FAKE_INFRA_LAUNCH"])
script = config["script"]
sys.path.insert(0, os.path.dirname(script))
import ubuntu24_host

def wrap(name):
    original = getattr(ubuntu24_host, name)
    def spied(*args, **kwargs):
        with open(config["spy"], "a") as handle:
            handle.write(json.dumps({"name": name, "args": [repr(item) for item in args]}) + "\n")
        return original(*args, **kwargs)
    setattr(ubuntu24_host, name, spied)

for name in ("infra_settings", "hostname_script", "timezone_script", "config_line_script", "config_line_value",
             "parse_kv"):
    wrap(name)
spec = importlib.util.spec_from_file_location("infra_setup_under_test", script)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.HOST_ROOT = Path(config["root"])
module.is_root = lambda: config["root_user"]

def chown(path, user, group):
    with open(config["chown_log"], "a") as handle:
        handle.write(json.dumps([module.canonical(path), user, group]) + "\n")

module.chown = chown
module.user_exists = lambda name: name in config["users"]
module.MONITOR_DECISION_TIMEOUT = float(config["decision_timeout"])
if config["tty"]:
    module.stdin_is_tty = lambda: True
sys.exit(module.main(sys.argv[1:]))
'''


def default_state() -> dict:
    return {"hostname": "mgmt01.lab.example", "fqdn": "mgmt01.lab.example", "timezone": "Etc/UTC",
            "installed": {"wget": "1.21.4", "tzdata": "2024a"}, "missing_units": [], "unit_state": {},
            "active": {}, "fail": {}, "lspci": "00:1f.6 Ethernet controller: Intel Corporation I219-LM\n",
            "reachable": [], "monitor": {}, "tzdata_zones": [],
            "download": {"Package": "doca-host", "Version": DOCA_VERSION, "Architecture": "amd64"}}


class Sandbox:
    def __init__(self, base: Path, *, global_text: str | None = GLOBAL, apache: bool = False,
                 systemd: bool = True):
        self.base = base
        self.http, self.root, self.bin = base / "http", base / "root", base / "bin"
        self.infra = self.http / "infra"
        self.infra.mkdir(parents=True)
        for source in (PY_SETUP, HOST_MODULE, NEUTRAL):
            shutil.copy2(source, self.infra / source.name)
        tools = self.http / "tools"
        tools.mkdir()
        shutil.copy2(CONTROL_AUTH, tools / "control-auth.py")
        (self.http / "apps").mkdir()
        if global_text is not None:
            (self.infra / "01-global.yaml").write_text(global_text, encoding="utf-8")
        self.files = {"etc/os-release": 'ID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu 24.04.3 LTS"\n',
                      "etc/hosts": ORIGINAL_HOSTS, "etc/systemd/resolved.conf": UBUNTU_RESOLVED,
                      "etc/systemd/timesyncd.conf": UBUNTU_TIMESYNCD, "usr/share/zoneinfo/Etc/UTC": "TZif2\n",
                      "usr/share/zoneinfo/Asia/Taipei": "TZif2\n"}
        for relative, text in self.files.items():
            self.write(relative, text)
        for directory in ("run/lock", "tmp", "usr/sbin", "var/lib", "usr/local/lib"):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        if systemd:
            (self.root / "run/systemd/system").mkdir(parents=True)
        if apache:
            for directory in ("conf-available", "conf-enabled", "sites-available", "sites-enabled"):
                (self.root / "etc/apache2" / directory).mkdir(parents=True)
            self.write("etc/apache2/ports.conf", "Listen 80\n")
            self.write("etc/apache2/sites-available/000-default.conf", "<VirtualHost *:80>\n</VirtualHost>\n")
            (self.root / "etc/apache2/sites-enabled/000-default.conf").symlink_to("../sites-available/000-default.conf")
        self.bin.mkdir()
        tool = self.bin / "_infra_tool.py"
        tool.write_text(FAKE_TOOL.replace("{python}", sys.executable), encoding="utf-8")
        tool.chmod(0o755)
        for name in FAKE_TOOL_NAMES:
            (self.bin / name).symlink_to("_infra_tool.py")
        self.launcher = base / "launcher.py"
        self.launcher.write_text(LAUNCHER, encoding="utf-8")
        self.state_path = base / "state.json"
        self.state = default_state()
        self.runs = 0

    def write(self, relative: str, text: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def read(self, relative: str) -> str:
        return (self.root / relative).read_text(encoding="utf-8")

    def exists(self, relative: str) -> bool:
        return os.path.lexists(self.root / relative)

    def run(self, *args: str, root_user: bool = True, users: tuple = (), decision_timeout: float = 11.0,
            tty: bool = False, answer: str | None = None):
        if self.runs == 0 or not self.state_path.exists():
            self.state_path.write_text(json.dumps(self.state), encoding="utf-8")
        self.runs += 1
        calls_path = Path(f"{self.state_path}.calls")
        spy_path, chown_path = self.base / "spy.jsonl", self.base / "chown.jsonl"
        for path in (calls_path, spy_path, chown_path):
            if path.exists():
                path.unlink()
        env = {"PATH": f"{self.bin}{os.pathsep}/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C",
               "HOME": os.environ.get("HOME", str(self.base)), "FAKE_INFRA_STATE": str(self.state_path),
               "FAKE_INFRA_ROOT": str(self.root), "PYTHONPYCACHEPREFIX": "/tmp/http-test-pyc",
               "PYTHONDONTWRITEBYTECODE": "1",
               "FAKE_INFRA_LAUNCH": json.dumps({
                   "script": str(self.infra / "infra-setup.py"), "root": str(self.root),
                   "root_user": root_user, "users": list(users), "spy": str(spy_path),
                   "chown_log": str(chown_path), "decision_timeout": decision_timeout, "tty": tty})}
        result = subprocess.run([sys.executable, "-B", str(self.launcher), *args], cwd=self.http, env=env,
                                input=answer, stdin=None if answer is not None else subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=300)
        self.state = json.loads(self.state_path.read_text(encoding="utf-8"))

        def lines(path):
            return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
        return result, lines(calls_path), lines(spy_path), lines(chown_path)

    def apply(self, *args: str, **kwargs):
        """An authorized unattended run (--apply --yes): the behaviour the scenarios describe."""
        return self.run(*args, "--apply", "--yes", **kwargs)

    def snapshot(self) -> dict:
        """Every path under the host root and the HTTP tree, except the run log and the two locks."""
        result = {}
        skip = {self.http / "infra/logs", self.http / "infra/.logs.lock", self.root / "run/lock/http-infra.lock"}
        for top in (self.root, self.http):
            for directory, names, files in os.walk(top):
                directory = Path(directory)
                names[:] = [name for name in names if directory / name not in skip]
                for name in names + files:
                    path = directory / name
                    if path in skip:
                        continue
                    info = path.lstat()
                    if path.is_symlink():
                        value = ("link", os.readlink(path))
                    elif path.is_dir():
                        value = ("dir", oct(info.st_mode & 0o7777))
                    else:
                        value = ("file", oct(info.st_mode & 0o7777), path.read_bytes())
                    result[str(path.relative_to(self.base))] = value
        return result

    def managed_files(self) -> list:
        path = self.root / "var/lib/http-infra/managed-files"
        return path.read_text(encoding="utf-8").splitlines() if path.exists() else []

    def packages(self) -> dict:
        path = self.root / "var/lib/http-infra/installed-packages"
        if not path.exists():
            return {}
        return {line.split("\t")[0]: line.split("\t") for line in path.read_text().splitlines() if line}

    def key_values(self, path: Path) -> dict:
        return dict(line.split("=", 1) for line in path.read_text(encoding="utf-8").splitlines() if "=" in line)

    def backups(self, relative: str) -> list:
        return sorted((self.root / relative).parent.glob(Path(relative).name + ".http-infra.bak.*"))


def commands(calls: list, tool: str) -> list:
    return [" ".join(call["args"]) for call in calls if call["tool"] == tool]


READ_ONLY_SYSTEMCTL = ("show ", "is-enabled ", "is-active ")
READ_ONLY_HELPER = ("monitor-authority-attest-decision", "status", "validate")


def mutating_calls(calls: list) -> list:
    """Fake-tool calls that change the host; a check-only run must make none."""
    changed = []
    for call in calls:
        tool, args = call["tool"], call["args"]
        line = " ".join(args)
        if tool in ("apt-get", "hostnamectl", "a2enconf", "a2enmod", "a2dissite", "ipmitool", "apache2ctl"):
            changed.append(f"{tool} {line}")
        elif tool == "systemctl" and not line.startswith(READ_ONLY_SYSTEMCTL):
            changed.append(f"{tool} {line}")
        elif tool == "timedatectl" and args[:1] not in (["show"], ["status"]):
            changed.append(f"{tool} {line}")
        elif tool == "mst" and args != ["status"]:
            changed.append(f"{tool} {line}")
        elif tool == "mlxconfig" and "set" in args:
            changed.append(f"{tool} {line}")
        elif tool == "wget" and "--spider" not in args:
            changed.append(f"{tool} {line}")
        elif tool == "python3" and args[1:2] and args[1] not in READ_ONLY_HELPER:
            changed.append(f"{tool} {line}")
    return changed


class InfraSetupPySourceContracts(unittest.TestCase):
    """Bytes and tables recorded from the removed shell script, DAY0 load and control-auth."""

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("infra_setup_contract", PY_SETUP)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_apache_boundary_is_the_load_pinned_policy(self):
        boundary = self.module.APACHE_PUBLIC_BOUNDARY
        self.assertEqual(LOAD_BOUNDARY_SHA, hashlib.sha256(boundary.encode("utf-8")).hexdigest())
        self.assertEqual(DOCKER_BOUNDARY, boundary)

    def test_pins_and_package_tables_match_the_shell_script(self):
        self.assertEqual(SH_CONTROL_AUTH_SHA, self.module.CONTROL_AUTH_SOURCE_SHA256)
        self.assertEqual(hashlib.sha256(CONTROL_AUTH.read_bytes()).hexdigest(), self.module.CONTROL_AUTH_SOURCE_SHA256)
        self.assertEqual(SH_BASE, list(self.module.BASE_PACKAGES))
        self.assertEqual(SH_COMMON, list(self.module.COMMON_PACKAGES))
        self.assertEqual(SH_ZTP, list(self.module.ZTP_DEPENDENCY_PACKAGES))
        self.assertEqual(SH_OPTIONAL, list(self.module.OPTIONAL_SERVICE_PACKAGES))
        self.assertEqual(SH_MODULES, list(self.module.APACHE_AUTH_MODULES))
        self.assertEqual(EXPECTED_PORTS, self.module.APACHE_PORTS_CONTENT)
        self.assertEqual(SH_LLDP, self.module.LLDPCLI_CONTENT)
        self.assertEqual("3.3.0-088000-26.01", self.module.DOCA_RELEASE)
        self.assertEqual("infra-setup.py", PY_SETUP.name)
        self.assertTrue(os.access(PY_SETUP, os.X_OK))
        self.assertTrue(PY_SETUP.read_text(encoding="utf-8").startswith("#!/usr/bin/env python3\n"))
        self.assertTrue(os.access(ROOT / "infra/infra-setup.sh", os.X_OK), "infra-setup.sh is kept (保留)")

    def test_overlapping_duties_have_no_second_implementation(self):
        source = PY_SETUP.read_text(encoding="utf-8")
        self.assertIn("import ubuntu24_host as host", source)
        for name in ("host.hostname_script(", "host.config_line_script(", "host.timezone_script(",
                     "host.infra_settings(", "host.parse_kv(", "host.config_line_value("):
            self.assertIn(name, source)
        # The module's own backup copies are not used: infra's rollback is managed-files.
        self.assertRegex(source, r"host\.hostname_script\(name, None\)")
        self.assertEqual(2, len(re.findall(r'host\.config_line_script\([^)]*, None\)', source)))
        self.assertIn("sys.dont_write_bytecode = True", source.split("import ubuntu24_host", 1)[0])
        for duplicate in ("set-timezone", "hostnamectl", "127.0.1.1", "sed -i", '"unmask"', "'unmask'"):
            self.assertNotIn(duplicate, source)
        # Self-contained: no git, no load-generated lock/guard/manifest, no project-tree imports.
        self.assertNotRegex(source, r"[\"'\[]git[\"' ]")
        for dependency in ("deployment.lock", "prewrite", "deployment-source-manifest", "project_contract",
                           "DEPLOYMENT_WRITER", "import yaml"):
            self.assertNotIn(dependency, source.replace(DOCKER_BOUNDARY, ""))


class RecordedShellContractMatchesKeptScript(unittest.TestCase):
    """The literals above are the kept infra-setup.sh's contract; prove they still are."""

    SHELL = ROOT / "infra/infra-setup.sh"

    def heredoc(self, opening: str, terminator: str) -> str:
        source = self.SHELL.read_text(encoding="utf-8")
        start = source.index(opening) + len(opening) + 1
        return source[start:source.index(f"\n{terminator}\n", start) + 1]

    def array(self, name: str) -> list:
        source = self.SHELL.read_text(encoding="utf-8")
        match = re.search(rf"^{re.escape(name)}=\((.*?)\)", source, re.S | re.M)
        return [item for item in match.group(1).split() if not item.startswith('"')]

    def test_recorded_tables_and_bytes_match_the_kept_shell_script(self):
        rename = lambda text: text.replace("infra-setup.sh", "infra-setup.py")  # noqa: E731
        self.assertEqual(SH_USAGE, rename(self.heredoc("usage() {\n  cat <<'EOF'", "EOF")))
        self.assertEqual(SH_LLDP, self.heredoc("cat > \"$lldpcli_conf\" << 'EOF'", "EOF"))
        self.assertEqual(EXPECTED_PORTS, rename(self.heredoc("cat > \"$ports_candidate\" <<'EOF'", "EOF")))
        self.assertEqual(DOCKER_BOUNDARY, self.heredoc("cat <<'APACHE_PUBLIC_BOUNDARY_EOF'", "APACHE_PUBLIC_BOUNDARY_EOF"))
        for name, expected in (("base_packages", SH_BASE), ("common_packages", SH_COMMON),
                               ("ztp_dependency_packages", SH_ZTP), ("optional_service_packages", SH_OPTIONAL),
                               ("apache_auth_modules", SH_MODULES)):
            self.assertEqual(expected, self.array(name), name)
        self.assertIn(f'control_auth_source_sha256="{SH_CONTROL_AUTH_SHA}"', self.SHELL.read_text(encoding="utf-8"))

    def test_recorded_cli_table_matches_the_kept_shell_script(self):
        # Every case ends while parsing arguments, so nothing on this machine is touched.
        for argv, returncode, stdout, stderr in SH_CLI_TABLE:
            with self.subTest(argv=argv):
                shell = subprocess.run(["/bin/bash", str(self.SHELL), *argv], capture_output=True, text=True,
                                       stdin=subprocess.DEVNULL, timeout=30)
                rename = lambda text: text.replace("infra-setup.sh", "infra-setup.py")  # noqa: E731
                self.assertEqual((returncode, stdout, stderr),
                                 (shell.returncode, rename(shell.stdout), rename(shell.stderr)))


PY_USAGE = SH_USAGE.replace(
    "  -h, --help              Show this help\n",
    "                          (combines only with --apply and --yes)\n"
    "  --apply                 Make the changes; without it only check and print WOULD APPLY\n"
    "                          (exit 0: nothing to change, 3: changes pending, 1: failure;\n"
    "                          usage errors exit 2)\n"
    "  --yes                   With --apply: do not ask before the first change\n"
    "  -h, --help              Show this help\n")
PY_CLI_TABLE = tuple((argv, code, stdout.replace(SH_USAGE, PY_USAGE), stderr.replace(SH_USAGE, PY_USAGE))
                     for argv, code, stdout, stderr in SH_CLI_TABLE) + (
    (["--client", "--yes"], 2, "", "ERROR: --yes is only valid together with --apply.\n"),
    (["--recover-monitor-authority", "--apply", "--yes", "--client"], 2, "",
     "ERROR: --recover-monitor-authority must be the only option.\n"),
)


class InfraSetupPyCommandLine(unittest.TestCase):
    def test_cli_matches_the_recorded_shell_contract(self):
        with tempfile.TemporaryDirectory(prefix="infra-setup-py-cli-") as directory:
            sandbox = Sandbox(Path(directory))
            for argv, returncode, stdout, stderr in PY_CLI_TABLE:
                with self.subTest(argv=argv):
                    python, calls, _spy, _chown = sandbox.run(*argv, root_user=False)
                    self.assertEqual((returncode, stdout, stderr), (python.returncode, python.stdout, python.stderr))
                    self.assertEqual([], calls)
            self.assertFalse(sandbox.exists("var/lib/http-infra"))

    def test_explicit_cli_contract(self):
        with tempfile.TemporaryDirectory(prefix="infra-setup-py-cli2-") as directory:
            sandbox = Sandbox(Path(directory))
            result, _c, _s, _o = sandbox.run("--help", root_user=False)
            self.assertEqual(0, result.returncode)
            self.assertEqual(PY_USAGE, result.stdout)
            result, _c, _s, _o = sandbox.run("--offline", "--mgmt", "--download-doca", root_user=False)
            self.assertEqual(2, result.returncode)
            self.assertEqual("ERROR: --offline cannot be combined with --download-doca.\n", result.stderr)
            result, calls, _s, _o = sandbox.run("--client", "--non-interactive", root_user=False)
            self.assertEqual(1, result.returncode)
            self.assertEqual("ERROR: infra-setup.py must be run as root.\n", result.stderr)
            self.assertEqual([], calls)
            self.assertFalse(sandbox.exists("var/lib/http-infra"))
            self.assertFalse((sandbox.infra / "logs").exists())


class InfraSetupPyClientRun(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="infra-setup-py-")
        self.sandbox = Sandbox(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_fresh_client_run_then_idempotent_rerun(self):
        box = self.sandbox
        result, calls, spy, _chown = box.apply("--client", "--non-interactive")
        self.assertEqual(0, result.returncode, result.stderr + result.stdout)
        # DNS/NTP/timezone from 01-global.yaml common.switch.system, through the shared module.
        self.assertEqual(UBUNTU_RESOLVED.replace("#DNS=\n", "DNS=160.250.70.5 8.8.8.8\n"),
                         box.read("etc/systemd/resolved.conf"))
        self.assertEqual(UBUNTU_TIMESYNCD.replace("#NTP=\n", "NTP=160.250.71.253 ntp.ubuntu.com\n"),
                         box.read("etc/systemd/timesyncd.conf"))
        self.assertEqual("Asia/Taipei", box.state["timezone"])
        self.assertEqual("Etc/UTC\n", box.read("var/lib/http-infra/original-timezone"))
        # sudo needs the kernel hostname to resolve: 127.0.1.1 <fqdn> <short>, as the shell script.
        self.assertEqual(ORIGINAL_HOSTS + "127.0.1.1\tmgmt01.lab.example mgmt01\n", box.read("etc/hosts"))
        names = [entry["name"] for entry in spy]
        for name in ("infra_settings", "hostname_script", "config_line_script", "config_line_value",
                     "timezone_script"):
            self.assertIn(name, names)
        self.assertIn(["'mgmt01.lab.example'", "None"],
                      [entry["args"] for entry in spy if entry["name"] == "hostname_script"])
        config_calls = [entry["args"] for entry in spy if entry["name"] == "config_line_script"]
        # Each file is checked (check_only=True) and then written with the same arguments.
        self.assertEqual(2, config_calls.count(["'/etc/systemd/resolved.conf'", "'DNS'", "'160.250.70.5 8.8.8.8'",
                                                "'systemd-resolved'", "None"]))
        self.assertEqual(2, config_calls.count(["'/etc/systemd/timesyncd.conf'", "'NTP'",
                                                "'160.250.71.253 ntp.ubuntu.com'", "'systemd-timesyncd'", "None"]))
        self.assertIn(["'Asia/Taipei'"], [entry["args"] for entry in spy if entry["name"] == "timezone_script"])
        # Teardown bookkeeping: managed-files with original backups, recorded packages.
        self.assertEqual(["/etc/hosts\trestore", "/etc/systemd/resolved.conf\trestore",
                          "/etc/systemd/timesyncd.conf\trestore", "/etc/lldpd.d/lldpcli.conf\tdelete"],
                         box.managed_files())
        for relative, original in (("etc/hosts", ORIGINAL_HOSTS), ("etc/systemd/resolved.conf", UBUNTU_RESOLVED),
                                   ("etc/systemd/timesyncd.conf", UBUNTU_TIMESYNCD)):
            backups = box.backups(relative)
            self.assertEqual(1, len(backups), relative)
            self.assertEqual(original, backups[0].read_text(encoding="utf-8"))
        self.assertEqual(SH_LLDP, box.read("etc/lldpd.d/lldpcli.conf"))
        packages = box.packages()
        self.assertEqual(["lldpd"] + SH_COMMON, list(packages))
        for name, fields in packages.items():
            self.assertRegex(name, r"^[a-z0-9][a-z0-9+.-]*(:[a-z0-9]+)?$")
            self.assertEqual(3, len(fields))
            self.assertEqual(f"{name}-test-1", fields[1])
        systemctl = commands(calls, "systemctl")
        for expected in ("restart systemd-resolved.service", "restart systemd-timesyncd.service", "restart lldpd"):
            self.assertIn(expected, systemctl)
        self.assertNotIn("hostnamectl", [call["tool"] for call in calls])
        self.assertEqual([], [call for call in calls if call["tool"] in ("a2enmod", "apache2ctl", "python3")])
        self.assertFalse(box.exists("usr/sbin/policy-rc.d"))
        # Status files read by check_infra.py / infra-teardown.sh.
        run_info = box.key_values(box.root / "var/lib/http-infra/run-info")
        self.assertEqual("2", run_info["schema_version"])
        self.assertEqual("completed", run_info["status"])
        self.assertEqual("160.250.70.5 8.8.8.8", run_info["expected_dns"])
        self.assertEqual("160.250.71.253 ntp.ubuntu.com", run_info["expected_ntp"])
        self.assertEqual("Asia/Taipei", run_info["expected_timezone"])
        self.assertEqual("false", run_info["mgmt_mode"])
        self.assertEqual("false", run_info["local_http_enabled"])
        self.assertEqual("http://127.0.0.1/apps/ubuntu-24.04/amd64", run_info["http_server"])
        self.assertEqual(hashlib.sha256((box.infra / "infra-setup.py").read_bytes()).hexdigest(),
                         run_info["script_sha256"])
        status = box.key_values(box.infra / "infra-status")
        self.assertEqual(("setup", "completed", "0", str(len(packages))),
                         (status["last_action"], status["status"], status["exit_code"], status["recorded_packages"]))
        logs = list((box.infra / "logs").glob("infra-setup-*.log"))
        self.assertEqual(1, len(logs))
        log_text = logs[0].read_text(encoding="utf-8")
        self.assertIn("infra-setup.py started", log_text)
        self.assertIn("infra-setup.py finished", log_text)
        self.assertEqual(status["log_file"], str(logs[0]))
        self.assertEqual([], list((box.root / "run").glob("http-infra-host-backup.*")))

        managed_before = box.managed_files()
        result, calls, _spy, _chown = box.apply("--client", "--non-interactive")
        self.assertEqual(0, result.returncode, result.stderr + result.stdout)
        self.assertIn("DNS already matches desired configuration.", result.stdout)
        self.assertIn("NTP already matches desired configuration.", result.stdout)
        self.assertIn("Timezone already matches desired configuration.", result.stdout)
        self.assertIn("Local hostname resolves correctly: mgmt01.lab.example", result.stdout)
        systemctl = commands(calls, "systemctl")
        self.assertNotIn("restart systemd-resolved.service", systemctl)
        # Contract: an authorized run with nothing to change changes nothing (no unconditional
        # timesyncd restart as the shell script did).
        self.assertNotIn("restart systemd-timesyncd.service", systemctl)
        self.assertEqual([], mutating_calls(calls))
        self.assertIn("already in the desired state, nothing changed", result.stdout)
        self.assertEqual([], [command for command in commands(calls, "apt-get") if " install " in f" {command} "])
        self.assertEqual(managed_before, box.managed_files())
        self.assertEqual(1, len(box.backups("etc/systemd/resolved.conf")))
        self.assertEqual("Etc/UTC\n", box.read("var/lib/http-infra/original-timezone"))
        self.assertEqual(ORIGINAL_HOSTS + "127.0.1.1\tmgmt01.lab.example mgmt01\n", box.read("etc/hosts"))
        self.assertEqual(2, len(list((box.infra / "logs").glob("infra-setup-*.log"))))

    def test_short_hostname_still_resolves(self):
        self.sandbox.state.update(hostname="mgmt02", fqdn="mgmt02")
        result, _calls, _spy, _chown = self.sandbox.apply("--client", "--non-interactive")
        self.assertEqual(0, result.returncode, result.stderr)
        # Exactly the line the shell script wrote for a single-label name: no repeated alias.
        self.assertEqual(ORIGINAL_HOSTS + "127.0.1.1\tmgmt02\n", self.sandbox.read("etc/hosts"))
        self.assertEqual(["/etc/hosts\trestore"], self.sandbox.managed_files()[:1])

    def test_masked_timesyncd_is_recorded_unmasked_and_enabled(self):
        self.sandbox.state["unit_state"]["systemd-timesyncd.service"] = "masked"
        result, calls, _spy, _chown = self.sandbox.apply("--client", "--non-interactive")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("masked\n", self.sandbox.read("var/lib/http-infra/original-timesyncd-unit-state"))
        systemctl = commands(calls, "systemctl")
        self.assertIn("unmask systemd-timesyncd.service", systemctl)
        self.assertIn("enable --now systemd-timesyncd.service", systemctl)
        self.assertNotIn("restart systemd-timesyncd.service", systemctl)
        self.assertIn("systemd-timesyncd.service is masked; temporarily unmasking it for managed NTP.", result.stdout)
        self.assertEqual(UBUNTU_TIMESYNCD.replace("#NTP=\n", "NTP=160.250.71.253 ntp.ubuntu.com\n"),
                         self.sandbox.read("etc/systemd/timesyncd.conf"))

    def test_masked_resolved_fails_without_rewriting_dns(self):
        self.sandbox.state["unit_state"]["systemd-resolved.service"] = "masked"
        result, _calls, _spy, _chown = self.sandbox.apply("--client", "--non-interactive")
        self.assertEqual(1, result.returncode)
        self.assertIn("Unable to restart systemd-resolved.service.", result.stderr)
        self.assertEqual(UBUNTU_RESOLVED, self.sandbox.read("etc/systemd/resolved.conf"))
        self.assertEqual("failed", self.sandbox.key_values(self.sandbox.infra / "infra-status")["status"])

    def test_missing_units_skip_dns_and_ntp(self):
        self.sandbox.state["missing_units"] = ["systemd-resolved.service", "systemd-timesyncd.service"]
        result, calls, _spy, _chown = self.sandbox.apply("--client", "--non-interactive")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("systemd-resolved.service is not installed; skipping managed DNS configuration.", result.stdout)
        self.assertIn("systemd-timesyncd.service is not installed; skipping managed NTP configuration.", result.stdout)
        self.assertEqual(UBUNTU_RESOLVED, self.sandbox.read("etc/systemd/resolved.conf"))
        self.assertEqual(UBUNTU_TIMESYNCD, self.sandbox.read("etc/systemd/timesyncd.conf"))
        self.assertNotIn("restart systemd-timesyncd.service", commands(calls, "systemctl"))

    def test_without_systemd_timezone_uses_localtime_and_timezone_files(self):
        box = Sandbox(Path(self.tmp.name) / "nosystemd", systemd=False)
        box.write("etc/timezone", "Etc/UTC\n")
        result, calls, _spy, _chown = box.apply("--client", "--non-interactive")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("Asia/Taipei\n", box.read("etc/timezone"))
        self.assertEqual(str(box.root / "usr/share/zoneinfo/Asia/Taipei"), os.readlink(box.root / "etc/localtime"))
        self.assertEqual("Etc/UTC\n", box.read("var/lib/http-infra/original-timezone"))
        self.assertEqual(UBUNTU_RESOLVED, box.read("etc/systemd/resolved.conf"))
        self.assertIn("systemd is not running; configuration for lldpd was written but service restart was skipped.",
                      result.stdout)
        self.assertEqual([], [call for call in calls if call["tool"] in ("systemctl", "timedatectl")
                              and call["args"][:1] not in (["show"], ["is-enabled"])])

    def test_missing_zone_installs_and_records_tzdata(self):
        box = self.sandbox
        (box.root / "usr/share/zoneinfo/Asia/Taipei").unlink()
        del box.state["installed"]["tzdata"]
        box.state["tzdata_zones"] = ["Asia/Taipei"]
        result, _calls, _spy, _chown = box.apply("--client", "--non-interactive")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("tzdata", box.packages())
        self.assertEqual("Asia/Taipei", box.state["timezone"])

    def test_missing_zone_with_tzdata_installed_fails(self):
        (self.sandbox.root / "usr/share/zoneinfo/Asia/Taipei").unlink()
        result, _calls, _spy, _chown = self.sandbox.apply("--client", "--non-interactive")
        self.assertEqual(1, result.returncode)
        self.assertIn("tzdata is installed but timezone data is missing: Asia/Taipei", result.stderr)
        self.assertEqual("failed", self.sandbox.key_values(self.sandbox.infra / "infra-status")["status"])

    def test_apt_failure_leaves_a_pending_record(self):
        self.sandbox.state["apt_unavailable"] = ["lldpd"]
        result, _calls, _spy, _chown = self.sandbox.apply("--client", "--non-interactive")
        self.assertEqual(1, result.returncode)
        self.assertIn("[ERROR] APT failed after", result.stderr)
        self.assertIn("(exit=100)", result.stderr)
        self.assertIn("E: Unable to locate package lldpd", result.stderr)
        self.assertIn("[ERROR] Full APT output is available in:", result.stderr)
        self.assertEqual("pending", self.sandbox.packages()["lldpd"][1])
        status = self.sandbox.key_values(self.sandbox.infra / "infra-status")
        self.assertEqual(("failed", "1", "1"), (status["status"], status["exit_code"], status["recorded_packages"]))

    def test_failed_restart_marks_the_run_failed(self):
        self.sandbox.state["fail"]["systemctl restart lldpd"] = 5
        result, _calls, _spy, _chown = self.sandbox.apply("--client", "--non-interactive")
        self.assertEqual(1, result.returncode)  # contract: every failure is exit 1
        status = self.sandbox.key_values(self.sandbox.infra / "infra-status")
        self.assertEqual(("failed", "1"), (status["status"], status["exit_code"]))
        self.assertEqual("started", self.sandbox.key_values(self.sandbox.root / "var/lib/http-infra/run-info")["status"])


MGMT_PACKAGES = SH_BASE + SH_COMMON + SH_ZTP + SH_OPTIONAL


class InfraSetupPyApplyContract(unittest.TestCase):
    """Default CHECK_ONLY, --apply asks once before the first change, --yes is unattended; 0/3/1 (usage 2)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="infra-setup-py-contract-")
        self.base = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def assert_untouched(self, box, before, calls):
        self.assertEqual(before, box.snapshot())
        self.assertEqual([], mutating_calls(calls))

    def test_exit_codes_separate_pending_from_usage_errors(self):
        # Owner ruling 2026-10-20: 0 desired state, 3 check found changes, 1 failure or not authorized;
        # argument/usage errors keep 2, so a caller can never read a usage error as "changes pending".
        box = Sandbox(self.base / "codes")
        usage, calls, _spy, _chown = box.run("--client", "--yes")
        self.assertEqual((2, "ERROR: --yes is only valid together with --apply.\n"), (usage.returncode, usage.stderr))
        self.assertEqual([], calls)
        unknown, _calls, _spy, _chown = box.run("--no-such-option")
        self.assertEqual(2, unknown.returncode)
        pending, _calls, _spy, _chown = box.run("--client", "--non-interactive")
        self.assertEqual(3, pending.returncode, pending.stderr + pending.stdout)
        refused, _calls, _spy, _chown = box.run("--client", "--apply", tty=True, answer="n\n")
        self.assertEqual(1, refused.returncode, refused.stderr + refused.stdout)
        applied, _calls, _spy, _chown = box.apply("--client", "--non-interactive")
        self.assertEqual(0, applied.returncode, applied.stderr + applied.stdout)
        settled, _calls, _spy, _chown = box.run("--client", "--non-interactive")
        self.assertEqual(0, settled.returncode, settled.stderr + settled.stdout)
        self.assertFalse([line for line in settled.stdout.splitlines() if line.startswith("WOULD APPLY")])

    def test_check_only_is_the_default_and_writes_nothing(self):
        box = Sandbox(self.base / "client")
        before = box.snapshot()
        result, calls, spy, _chown = box.run("--client", "--non-interactive")
        self.assertEqual(3, result.returncode, result.stderr + result.stdout)
        self.assert_untouched(box, before, calls)
        self.assertFalse(box.exists("var/lib/http-infra"))
        self.assertFalse((box.infra / "infra-status").exists())
        self.assertIn("模式: CHECK_ONLY", result.stdout)
        would = [line for line in result.stdout.splitlines() if line.startswith("WOULD APPLY: ")]
        for expected in ("add the local hostname mapping for mgmt01.lab.example to /etc/hosts",
                         "set DNS=160.250.70.5 8.8.8.8 in /etc/systemd/resolved.conf",
                         "set NTP=160.250.71.253 ntp.ubuntu.com in /etc/systemd/timesyncd.conf",
                         "set timezone Asia/Taipei (now Etc/UTC)", "install lldpd, write /etc/lldpd.d/lldpcli.conf",
                         "install " + " ".join(SH_COMMON), "record the run state"):
            self.assertTrue(any(expected in line for line in would), (expected, would))
        self.assertIn(f"结果: 需要 {len(would)} 项改动", result.stdout)
        # Check and apply decisions come from the same module scripts, run in check mode here.
        self.assertIn(["'mgmt01.lab.example'", "None"],
                      [entry["args"] for entry in spy if entry["name"] == "hostname_script"])
        config = [entry for entry in spy if entry["name"] == "config_line_script"]
        self.assertEqual(2, len(config))
        self.assertIn(["'Asia/Taipei'"], [entry["args"] for entry in spy if entry["name"] == "timezone_script"])

    def test_apply_then_check_reports_the_desired_state(self):
        box = Sandbox(self.base / "client")
        result, _calls, _spy, _chown = box.apply("--client", "--non-interactive")
        self.assertEqual(0, result.returncode, result.stderr + result.stdout)
        self.assertIn("模式: APPLY --yes", result.stdout)
        self.assertNotIn("授权本次及后续改动", result.stdout)
        before = box.snapshot()
        result, calls, _spy, _chown = box.run("--client", "--non-interactive")
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertEqual([], [line for line in result.stdout.splitlines() if line.startswith("WOULD APPLY")])
        self.assertIn("检查完成：主机已处于期望状态", result.stdout)
        self.assert_untouched(box, before, calls)

    def test_apply_asks_once_before_the_first_change(self):
        box = Sandbox(self.base / "refuse")
        before = box.snapshot()
        result, calls, _spy, _chown = box.run("--client", "--apply", tty=True, answer="n\n")
        self.assertEqual(1, result.returncode)
        self.assertEqual(1, result.stdout.count("授权本次及后续改动？[y/N]"))
        self.assertIn("首次改动: add the local hostname mapping for mgmt01.lab.example to /etc/hosts", result.stdout)
        self.assertIn("操作员未授权改动，本次运行停止，未做任何改动", result.stderr)
        self.assert_untouched(box, before, calls)
        self.assertFalse((box.infra / "infra-status").exists())

        box = Sandbox(self.base / "grant")
        result, _calls, _spy, _chown = box.run("--client", "--apply", tty=True, answer="y\n")
        self.assertEqual(0, result.returncode, result.stderr + result.stdout)
        self.assertEqual(1, result.stdout.count("授权本次及后续改动？[y/N]"))
        self.assertIn("127.0.1.1\tmgmt01.lab.example mgmt01\n", box.read("etc/hosts"))
        self.assertEqual("completed", box.key_values(box.infra / "infra-status")["status"])

    def test_apply_without_yes_needs_an_interactive_terminal(self):
        box = Sandbox(self.base / "notty")
        before = box.snapshot()
        for argv, tty in ((("--client", "--apply"), False), (("--client", "--non-interactive", "--apply"), True)):
            with self.subTest(argv=argv, tty=tty):
                result, calls, _spy, _chown = box.run(*argv, tty=tty)
                self.assertEqual(1, result.returncode)
                self.assertIn("--apply 需要在交互终端确认第一次改动；非交互运行请同时加 --yes", result.stderr)
                self.assertEqual([], calls)
                self.assertEqual(before, box.snapshot())
                self.assertFalse((box.infra / "logs").exists())

    def test_mgmt_check_only_installs_and_configures_nothing(self):
        box = Sandbox(self.base / "mgmt", apache=True)
        before = box.snapshot()
        result, calls, _spy, chowns = box.run("--mgmt", "--defer-services", "--install-apache", "--install-dhcp",
                                              "--skip-doca", users=("_apt",))
        self.assertEqual(3, result.returncode, result.stderr + result.stdout)
        self.assert_untouched(box, before, calls)
        self.assertEqual([], chowns)
        self.assertFalse(box.exists("usr/sbin/policy-rc.d"))
        self.assertFalse(box.exists("usr/local/lib/http-ztp"))
        self.assertFalse((box.http / "apps/ubuntu-24.04").exists())
        would = "\n".join(line for line in result.stdout.splitlines() if line.startswith("WOULD APPLY: "))
        for expected in ("refresh APT indexes and cache the offline package closure",
                         "install " + " ".join(SH_ZTP), "configure apache2: install apache2 apache2-utils ssl-cert",
                         "install the authenticated publication boundary", "install isc-dhcp-server, then stop and disable it"):
            self.assertIn(expected, would)
        apps = os.path.realpath(box.http / "apps/ubuntu-24.04/amd64")
        self.assertIn(f"WOULD APPLY: refresh APT indexes and cache the offline package closure "
                      f"({len(MGMT_PACKAGES)} packages) into {apps} (offline repository missing: {apps}/Packages.gz)",
                      result.stdout.splitlines())
        self.assertEqual([], commands(calls, "apt-get"))

    # Owner ruling B (2026-10-20): on --mgmt without --offline the check reads <apps>/Packages.gz in memory;
    # the refresh is pending only when that repository is missing/unreadable or a required top-level
    # package (every name the management cache holds) is absent.  --apply still refreshes every time.
    MGMT_ARGS = ("--mgmt", "--defer-services", "--install-apache", "--install-dhcp", "--skip-doca")

    def applied_mgmt_box(self, name: str):
        box = Sandbox(self.base / name, apache=True)
        result, _calls, _spy, _chown = box.apply(*self.MGMT_ARGS)
        self.assertEqual(0, result.returncode, result.stderr + result.stdout)
        return box, Path(os.path.realpath(box.http / "apps/ubuntu-24.04/amd64"))

    @staticmethod
    def would_lines(result) -> list:
        return [line for line in result.stdout.splitlines() if line.startswith("WOULD APPLY: ")]

    def test_authorized_mgmt_run_then_check_only_is_settled(self):
        box, apps = self.applied_mgmt_box("mgmt")
        names = {line.split(": ", 1)[1] for line in gzip.decompress((apps / "Packages.gz").read_bytes())
                 .decode("utf-8").splitlines() if line.startswith("Package: ")}
        self.assertLessEqual(set(MGMT_PACKAGES), names)
        before = box.snapshot()
        result, calls, _spy, _chown = box.run(*self.MGMT_ARGS)
        self.assertEqual(0, result.returncode, result.stderr + result.stdout)
        self.assert_untouched(box, before, calls)
        self.assertEqual([], self.would_lines(result))
        self.assertIn("离线缓存完整", result.stdout)
        self.assertIn("--apply 时会检查上游更新并刷新", result.stdout)
        self.assertEqual([], commands(calls, "apt-get"))  # no apt update in check mode
        helper_calls = [call["args"][1] for call in calls if call["tool"] == "python3"]
        self.assertEqual(["monitor-authority-attest-decision", "status"], helper_calls)

    def test_mgmt_check_only_reports_each_cache_gap_read_only(self):
        box, apps = self.applied_mgmt_box("gaps")
        original = (apps / "Packages.gz").read_bytes()
        stanzas = gzip.decompress(original).decode("utf-8").split("\n\n")
        without_lldpd = "\n\n".join(item for item in stanzas if "Package: lldpd\n" not in item + "\n")
        deb = apps / "lldpd_1.0_amd64.deb"
        deb_bytes = deb.read_bytes()
        prefix = (f"WOULD APPLY: refresh APT indexes and cache the offline package closure "
                  f"({len(MGMT_PACKAGES)} packages) into {apps} ")
        cases = (
            ("stanza", lambda: (apps / "Packages.gz").write_bytes(gzip.compress(without_lldpd.encode("utf-8"))),
             prefix + "(missing from the offline repository: lldpd)"),
            ("deb", lambda: deb.unlink(), prefix + "(missing from the offline repository: lldpd)"),
            ("corrupt", lambda: (apps / "Packages.gz").write_bytes(b"not a gzip stream"),
             prefix + f"(offline repository unreadable: {apps}/Packages.gz)"),
            ("missing", lambda: (apps / "Packages.gz").unlink(),
             prefix + f"(offline repository missing: {apps}/Packages.gz)"),
        )
        for name, damage, expected in cases:
            with self.subTest(case=name):
                damage()
                before = box.snapshot()
                result, calls, _spy, _chown = box.run(*self.MGMT_ARGS)
                self.assertEqual(3, result.returncode, result.stderr + result.stdout)
                self.assert_untouched(box, before, calls)
                self.assertEqual([expected], self.would_lines(result))
                self.assertNotIn("离线缓存完整", result.stdout)
                self.assertEqual([], commands(calls, "apt-get"))
                (apps / "Packages.gz").write_bytes(original)
                deb.write_bytes(deb_bytes)

    def test_mgmt_apply_still_refreshes_a_complete_cache(self):
        box, apps = self.applied_mgmt_box("refresh")
        checked, _calls, _spy, _chown = box.run(*self.MGMT_ARGS)
        self.assertEqual(0, checked.returncode, checked.stderr + checked.stdout)
        result, calls, _spy, _chown = box.apply(*self.MGMT_ARGS)
        self.assertEqual(0, result.returncode, result.stderr + result.stdout)
        apt_calls = commands(calls, "apt-get")
        self.assertTrue(any(call.endswith(" update") or call == "update" for call in apt_calls), apt_calls)
        downloads = [call["args"] for call in calls if call["tool"] == "apt-get" and "--download-only" in call["args"]]
        self.assertTrue(downloads)
        self.assertLessEqual(set(MGMT_PACKAGES), set(downloads[0]))
        self.assertIn(f"Local APT repository refreshed: {apps}/Packages.gz", result.stdout)


class InfraSetupPyInputs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="infra-setup-py-inputs-")
        self.base = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def run_box(self, name: str, global_text: str | None, runtime: str | None = None):
        box = Sandbox(self.base / name, global_text=global_text)
        if runtime is not None:
            (box.infra / "infra-runtime.conf").write_text(runtime, encoding="utf-8")
        result, calls, spy, _chown = box.apply("--client", "--non-interactive")
        return box, result

    def deploy_module(self):
        spec = importlib.util.spec_from_file_location("infra_setup_py_deploy", ROOT / "infra/deploy_infra.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module

    def test_runtime_conf_from_deploy_infra_is_used_without_a_global(self):
        block = self.deploy_module().render_managed_block(
            "192.0.2.10", ["192.0.2.53"], ["ntp.site.example"], "Asia/Taipei", local_http_enabled=False)
        box, result = self.run_box("runtime", None, block + "\n")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("DNS=192.0.2.53\n", box.read("etc/systemd/resolved.conf"))
        self.assertIn("NTP=ntp.site.example\n", box.read("etc/systemd/timesyncd.conf"))
        run_info = box.key_values(box.root / "var/lib/http-infra/run-info")
        self.assertEqual("http://192.0.2.10/apps/ubuntu-24.04/amd64", run_info["http_server"])
        self.assertEqual("Asia/Taipei", run_info["expected_timezone"])

    def test_client_uses_a_reachable_local_repository(self):
        block = self.deploy_module().render_managed_block(
            "192.0.2.10", ["192.0.2.53"], ["ntp.site.example"], "Etc/UTC", local_http_enabled=True)
        box = Sandbox(self.base / "localrepo", global_text=None)
        (box.infra / "infra-runtime.conf").write_text(block + "\n", encoding="utf-8")
        box.state["reachable"] = ["http://192.0.2.10/apps/ubuntu-24.04/amd64/Packages.gz"]
        result, calls, _spy, _chown = box.apply("--client", "--non-interactive")
        self.assertEqual(0, result.returncode, result.stderr)
        installs = [call for call in calls if call["tool"] == "apt-get" and "install" in call["args"]]
        self.assertTrue(installs)
        for call in installs:
            self.assertEqual("deb [trusted=yes] http://192.0.2.10/apps/ubuntu-24.04/amd64/ ./\n", call["sources"])
            self.assertIn("Dir::Etc::sourceparts=-", call["args"])
        self.assertEqual([], list((box.root / "tmp").glob("http-infra-apt-source.*")))
        self.assertEqual("true", box.key_values(box.root / "var/lib/http-infra/run-info")["local_http_enabled"])

    def test_repository_probe_targets_only_ip_literals(self):
        # Owner ruling 2026-10-19: connectivity tests use IP/IPv6 literals, never host names.
        for name, server, code in (("v4", "http://192.0.2.10/apps", 0), ("v6", "http://[2001:db8::10]:8080/apps", 0),
                                   ("name", "http://mgmt01.lab.example/apps", 1)):
            with self.subTest(server=server):
                box, result = self.run_box(name, None, f"http_server={server}\nlocal_http_enabled=true\n")
                self.assertEqual(code, result.returncode, result.stderr)
                if code:
                    self.assertIn("http_server must use an IP address literal", result.stderr)
                    self.assertFalse(box.exists("var/lib/http-infra"))
                else:
                    self.assertTrue(box.exists("var/lib/http-infra/run-info"))

    def test_neutral_defaults_without_global_or_runtime(self):
        box, result = self.run_box("neutral", None)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("DNS=8.8.8.8\n", box.read("etc/systemd/resolved.conf"))
        self.assertIn("NTP=ntp.ubuntu.com\n", box.read("etc/systemd/timesyncd.conf"))
        self.assertFalse(box.exists("var/lib/http-infra/original-timezone"))
        self.assertEqual("Etc/UTC", box.key_values(box.root / "var/lib/http-infra/run-info")["expected_timezone"])

    def test_absent_global_keys_use_neutral_values(self):
        text = "common:\n  switch:\n    system:\n      dns:\n        server: [192.0.2.53]\n"
        box, result = self.run_box("partial", text)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("DNS=192.0.2.53\n", box.read("etc/systemd/resolved.conf"))
        self.assertIn("NTP=ntp.ubuntu.com\n", box.read("etc/systemd/timesyncd.conf"))
        self.assertEqual("Etc/UTC", box.state["timezone"])

    def test_global_wins_over_a_stale_runtime_conf(self):
        block = self.deploy_module().render_managed_block(
            "192.0.2.10", ["192.0.2.99"], ["ntp.old.example"], "Etc/UTC", local_http_enabled=False)
        box, result = self.run_box("stale", GLOBAL, block + "\n")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("DNS=160.250.70.5 8.8.8.8\n", box.read("etc/systemd/resolved.conf"))
        self.assertIn("infra-runtime.conf DNS differs from 01-global.yaml; using 01-global.yaml.", result.stdout)
        self.assertEqual("http://192.0.2.10/apps/ubuntu-24.04/amd64",
                         box.key_values(box.root / "var/lib/http-infra/run-info")["http_server"])

    def test_global_link_into_a_project_is_followed(self):
        box = Sandbox(self.base / "linked", global_text=None)
        project = box.http / "DAY0-Prepare/proj"
        project.mkdir(parents=True)
        (project / "01-global.yaml").write_text(GLOBAL, encoding="utf-8")
        (box.infra / "01-global.yaml").symlink_to("../DAY0-Prepare/proj/01-global.yaml")
        result, _calls, _spy, _chown = box.apply("--client", "--non-interactive")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("DNS=160.250.70.5 8.8.8.8\n", box.read("etc/systemd/resolved.conf"))
        (project / "01-global.yaml").unlink()
        result, _calls, _spy, _chown = box.apply("--client", "--non-interactive")
        self.assertEqual(1, result.returncode)
        self.assertIn("dangling link", result.stderr)

    def test_present_invalid_global_keys_fail_before_any_change(self):
        cases = ({"dns": {}}, {"dns": {"server": []}}, {"dns": {"server": ["not-an-ip"]}}, {"ntp": {}},
                 {"ntp": {"server": []}}, {"date-time": {}}, {"date-time": {"timezone": ""}},
                 {"date-time": {"timezone": "../etc"}}, {"date-time": {"timezone": 8}},
                 {"ntp": {"server": [1234]}}, {"dns": {"server": [None]}})
        for index, system in enumerate(cases):
            with self.subTest(system=system):
                text = yaml.safe_dump({"common": {"switch": {"system": system}}}, sort_keys=False)
                box, result = self.run_box(f"invalid{index}", text)
                self.assertEqual(1, result.returncode, result.stdout)
                self.assertIn("01-global.yaml", result.stderr)
                self.assertEqual(UBUNTU_RESOLVED, box.read("etc/systemd/resolved.conf"))
                self.assertFalse(box.exists("var/lib/http-infra/run-info"))
        box, result = self.run_box("nosystem", "common: {}\n")
        self.assertEqual(1, result.returncode)

    def test_runtime_conf_is_parsed_never_executed(self):
        marker = self.base / "executed"
        box, result = self.run_box("hostile", None, f"dns_servers=(192.0.2.53)\ntouch {marker}\n")
        self.assertEqual(1, result.returncode)
        self.assertIn("is not a deploy_infra.py managed assignment", result.stderr)
        self.assertFalse(marker.exists())
        self.assertEqual(UBUNTU_RESOLVED, box.read("etc/systemd/resolved.conf"))

    def test_invalid_neutral_defaults_fail(self):
        box = Sandbox(self.base / "badneutral")
        (box.infra / "infra-neutral.conf").write_text("DNS=8.8.8.8\nNTP=ntp.ubuntu.com\nTIMEZONE=Etc/UTC", "utf-8")
        result, _calls, _spy, _chown = box.apply("--client", "--non-interactive")
        self.assertEqual(1, result.returncode)
        self.assertIn("ERROR: neutral defaults are incomplete or invalid", result.stderr)


class InfraSetupPyLogBinding(unittest.TestCase):
    def test_log_root_rules(self):
        with tempfile.TemporaryDirectory(prefix="infra-setup-py-logs-") as directory:
            box = Sandbox(Path(directory))
            foreign = Path(directory) / "foreign"
            foreign.mkdir()
            logs = box.infra / "logs"
            logs.symlink_to(os.path.relpath(foreign, box.infra))
            result, calls, _spy, _chown = box.apply("--client", "--non-interactive")
            self.assertEqual(1, result.returncode)
            self.assertIn("ERROR: infra/logs is not a managed project link", result.stderr)
            self.assertEqual([], list(foreign.iterdir()))
            self.assertFalse(box.exists("var/lib/http-infra"))
            logs.unlink()
            output = box.http / "DAY0-Prepare/proj/99-output-infra"
            output.mkdir(parents=True)
            logs.symlink_to("../DAY0-Prepare/proj/99-output-infra")
            (box.infra / ".logs-migration.json").write_text("{}", encoding="utf-8")
            result, _calls, _spy, _chown = box.apply("--client", "--non-interactive")
            self.assertEqual(1, result.returncode)
            self.assertIn("ERROR: infra log migration state is pending", result.stderr)
            (box.infra / ".logs-migration.json").unlink()
            result, _calls, _spy, _chown = box.apply("--client", "--non-interactive")
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(1, len(list(output.glob("infra-setup-*.log"))))


class InfraSetupPyManagement(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="infra-setup-py-mgmt-")
        self.box = Sandbox(Path(self.tmp.name), apache=True)

    def tearDown(self):
        self.tmp.cleanup()

    def test_mgmt_apache_dhcp_transactional_load(self):
        box = self.box
        box.write("usr/sbin/policy-rc.d", "#!/bin/sh\nexit 0\n")
        (box.root / "usr/sbin/policy-rc.d").chmod(0o755)
        result, calls, _spy, chowns = box.apply("--mgmt", "--defer-services", "--install-apache", "--install-dhcp",
                                              "--skip-doca", users=("_apt",))
        self.assertEqual(0, result.returncode, result.stderr + result.stdout)
        self.assertIn("Transactional load mode: Apache/DHCP package auto-start is blocked until load commits.",
                      result.stdout)
        # policy-rc.d blocked apache2/isc-dhcp-server during every package install, then came back.
        installs = [call for call in calls if call["tool"] == "apt-get" and "install" in call["args"]
                    and "--download-only" not in call["args"]]
        self.assertTrue(installs)
        for call in installs:
            self.assertIn("apache2|*/apache2|isc-dhcp-server|*/isc-dhcp-server) exit 101 ;;", call["policy"])
        self.assertEqual("#!/bin/sh\nexit 0\n", box.read("usr/sbin/policy-rc.d"))
        self.assertEqual([], list((box.root / "usr/sbin").glob("policy-rc.d.http-infra.*")))
        # Apache boundary, listeners and default site exactly as the shell script leaves them.
        boundary = (box.root / "etc/apache2/conf-enabled/http-ztp-public-boundary.conf").read_bytes()
        self.assertEqual(LOAD_BOUNDARY_SHA, hashlib.sha256(boundary).hexdigest())
        self.assertEqual(EXPECTED_PORTS, box.read("etc/apache2/ports.conf"))
        self.assertEqual("ServerName mgmt01.lab.example\n", box.read("etc/apache2/conf-available/servername.conf"))
        self.assertEqual("enabled\n", box.read("var/lib/http-infra/apache-default-site-enabled"))
        self.assertFalse(box.exists("etc/apache2/sites-enabled/000-default.conf"))
        self.assertEqual(["servername"], commands(calls, "a2enconf"))
        self.assertEqual(SH_MODULES, commands(calls, "a2enmod"))
        self.assertEqual(["000-default"], commands(calls, "a2dissite"))
        helper = box.root / "usr/local/lib/http-ztp/control-auth.py"
        self.assertEqual(SH_CONTROL_AUTH_SHA, hashlib.sha256(helper.read_bytes()).hexdigest())
        helper_calls = [call["args"][1] for call in calls if call["tool"] == "python3"]
        self.assertEqual(["monitor-authority-provision-decision", "monitor-authority-attest-decision", "ensure",
                          "validate", "status"], helper_calls)
        self.assertIn(["/usr/local/lib/http-ztp", "root", "root"], chowns)
        for prefix in ("/etc/apache2/conf-enabled/http-ztp-public-boundary.conf.tmp.", "/etc/apache2/ports.conf.tmp.",
                       "/usr/local/lib/http-ztp/control-auth.py.tmp."):
            self.assertTrue(any(path.startswith(prefix) and owner == ["root", "root"]
                                for path, *owner in chowns), prefix)
        self.assertIn([os.path.realpath(box.http / "apps/ubuntu-24.04/amd64/partial"), "_apt", "root"], chowns)
        for entry in box.managed_files():
            path, action = entry.split("\t")
            self.assertIn(path, TEARDOWN_MANAGED_PATHS)
            self.assertIn(action, ("restore", "delete"))
        self.assertIn("/etc/apache2/ports.conf\trestore", box.managed_files())
        self.assertIn("/etc/apache2/conf-enabled/http-ztp-public-boundary.conf\tdelete", box.managed_files())
        # DHCP installed, then stopped and disabled; services never started.
        systemctl = commands(calls, "systemctl")
        self.assertIn("stop isc-dhcp-server", systemctl)
        self.assertIn("disable isc-dhcp-server", systemctl)
        self.assertFalse([command for command in systemctl if command.startswith(("start ", "restart apache2"))])
        packages = box.packages()
        for package in SH_ZTP + ["apache2", "apache2-utils", "ssl-cert", "isc-dhcp-server"]:
            self.assertIn(package, packages)
        # Management repository built from the cached closure.
        downloads = [call["args"] for call in calls if call["tool"] == "apt-get" and "--download-only" in call["args"]]
        self.assertEqual(1, len(downloads))
        self.assertEqual(SH_BASE + SH_COMMON + SH_ZTP + SH_OPTIONAL, downloads[0][downloads[0].index("-y") + 1:])
        apps = box.http / "apps/ubuntu-24.04/amd64"
        meta = box.key_values(apps / "repository.meta")
        self.assertEqual(("ubuntu", "24.04", "amd64"), (meta["os_id"], meta["os_version"], meta["architecture"]))
        self.assertIn("Filename: ./lldpd_1.0_amd64.deb", (apps / "Packages").read_text(encoding="utf-8"))
        run_info = box.key_values(box.root / "var/lib/http-infra/run-info")
        self.assertEqual(("true", "completed", "false"),
                         (run_info["mgmt_mode"], run_info["status"], run_info["local_http_enabled"]))

    def test_monitor_decision_must_be_exact(self):
        cases = ({"stdout": "recovery-in-progress"}, {"stdout": "attest-valid\n"},
                 {"stdout": "attest-valid", "stderr": "noise"}, {"stdout": "attest-valid", "rc": 3},
                 {"stdout": "attest-valid", "spawn": True})
        for index, spec in enumerate(cases):
            with self.subTest(spec=spec):
                box = Sandbox(Path(self.tmp.name) / f"decision{index}", apache=True)
                box.state["monitor"] = {"monitor-authority-provision-decision": spec}
                result, calls, _spy, _chown = box.apply("--mgmt", "--defer-services", "--install-apache",
                                                      "--skip-doca")
                self.assertEqual(1, result.returncode, result.stdout)
                if spec["stdout"] == "recovery-in-progress" and len(spec) == 1:
                    self.assertIn("classification=recovery-in-progress", result.stderr)
                    self.assertIn("--recover-monitor-authority", result.stderr)
                else:
                    self.assertIn("routine Monitor cache authority validation failed", result.stderr)
                self.assertFalse(box.exists("etc/apache2/conf-enabled/http-ztp-public-boundary.conf"))
                self.assertFalse(box.exists("usr/sbin/policy-rc.d"))
                self.assertEqual([], list((box.root / "run").glob("http-ztp-monitor-decision.*")))

    def test_monitor_decision_deadline(self):
        box = self.box
        box.state["monitor"] = {"monitor-authority-provision-decision": {"stdout": "attest-valid", "sleep": 5}}
        result, _calls, _spy, _chown = box.apply("--mgmt", "--defer-services", "--install-apache", "--skip-doca",
                                               decision_timeout=1.0)
        self.assertEqual(1, result.returncode)
        self.assertIn("routine Monitor cache authority validation failed", result.stderr)

    def test_failed_configtest_restores_and_stops_apache(self):
        box = self.box
        box.state["configtest_rc"] = 1
        result, calls, _spy, _chown = box.apply("--mgmt", "--defer-services", "--install-apache", "--skip-doca")
        self.assertEqual(1, result.returncode)
        self.assertIn("Apache publication boundary failed configtest", result.stderr)
        self.assertFalse(box.exists("etc/apache2/conf-enabled/http-ztp-public-boundary.conf"))
        self.assertIn("stop apache2", commands(calls, "systemctl"))

    def test_mgmt_requires_the_pinned_control_auth_source(self):
        box = self.box
        source = box.http / "tools/control-auth.py"
        source.write_bytes(source.read_bytes() + b"\n")
        result, calls, _spy, _chown = box.apply("--mgmt", "--skip-doca")
        self.assertEqual(1, result.returncode)
        self.assertIn("Control auth helper source hash mismatch", result.stderr)
        self.assertEqual([], calls)

    def test_offline_requires_matching_repository(self):
        box = self.box
        result, _calls, _spy, _chown = box.apply("--mgmt", "--offline", "--skip-doca")
        self.assertEqual(1, result.returncode)
        self.assertIn("Packaged offline APT repository is missing", result.stderr)
        apps = box.http / "apps/ubuntu-24.04/amd64"
        (apps / "Packages.gz").write_bytes(b"\x1f\x8b packaged")
        (apps / "repository.meta").write_text("schema_version=1\nos_id=ubuntu\nos_version=22.04\n"
                                              "architecture=amd64\n", encoding="utf-8")
        result, calls, _spy, _chown = box.apply("--mgmt", "--offline", "--skip-doca")
        self.assertEqual(1, result.returncode)
        self.assertIn("Offline repository metadata is missing or mismatched", result.stderr)
        self.assertEqual([], commands(calls, "apt-get"))

    def test_offline_mgmt_uses_only_the_packaged_repository(self):
        box = self.box
        apps = box.http / "apps/ubuntu-24.04/amd64"
        apps.mkdir(parents=True)
        (apps / "Packages.gz").write_bytes(b"\x1f\x8b packaged")
        (apps / "repository.meta").write_text("schema_version=1\nos_id=ubuntu\nos_version=24.04\n"
                                              "architecture=amd64\n", encoding="utf-8")
        (apps / "lldpd_1.0_amd64.deb").write_text(json.dumps(
            {"Package": "lldpd", "Version": "1.0", "Architecture": "amd64"}), encoding="utf-8")
        result, calls, _spy, _chown = box.apply("--mgmt", "--offline", "--skip-doca")
        self.assertEqual(0, result.returncode, result.stderr + result.stdout)
        apt = [call for call in calls if call["tool"] == "apt-get"]
        self.assertTrue(apt)
        for call in apt:
            self.assertNotIn("--download-only", call["args"])
            self.assertEqual(f"deb [trusted=yes] file:{os.path.realpath(apps)} ./\n", call["sources"])
            self.assertIn(f"Dir::Cache::archives={os.path.realpath(apps)}/", call["args"])
        self.assertEqual([], [command for command in commands(calls, "wget") if "-O" in command])
        self.assertIn("Filename: ./lldpd_1.0_amd64.deb", (apps / "Packages").read_text(encoding="utf-8"))
        self.assertEqual([], list((box.root / "tmp").glob("http-infra-apt-source.*")))

    def test_apache_without_mgmt_is_refused(self):
        result, _calls, _spy, _chown = self.box.apply("--client", "--install-apache", "--non-interactive")
        self.assertEqual(1, result.returncode)
        self.assertIn("Authenticated Monitor Apache configuration requires --mgmt", result.stderr)
        self.assertFalse(self.box.exists("usr/sbin/policy-rc.d"))


class InfraSetupPyRecovery(unittest.TestCase):
    def prepare(self, base: Path, recover: str, attest: str = "attest-valid") -> Sandbox:
        box = Sandbox(base, apache=True)
        helper = box.root / "usr/local/lib/http-ztp/control-auth.py"
        helper.parent.mkdir(parents=True)
        shutil.copy2(CONTROL_AUTH, helper)
        box.state["active"]["apache2"] = "active"
        box.state["monitor"] = {"monitor-authority-recover-decision": {"stdout": recover},
                                "monitor-authority-attest-decision": {"stdout": attest}}
        return box

    def test_recovery_restarts_apache_only_when_allowed(self):
        with tempfile.TemporaryDirectory(prefix="infra-setup-py-recover-") as directory:
            box = self.prepare(Path(directory) / "check", "restart-allowed:complete;reset-invalid-cache=true")
            result, calls, _spy, _chown = box.run("--recover-monitor-authority")
            self.assertEqual(3, result.returncode, result.stderr)
            self.assertIn("WOULD APPLY: stop apache2 (ActiveState=active)", result.stdout)
            self.assertEqual(["show --property=ActiveState --value apache2"], commands(calls, "systemctl"))
            self.assertEqual([], mutating_calls(calls))

            box = self.prepare(Path(directory) / "ok", "restart-allowed:complete;reset-invalid-cache=true")
            result, calls, _spy, _chown = box.apply("--recover-monitor-authority")
            self.assertEqual("", result.stdout)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(["show --property=ActiveState --value apache2", "stop apache2",
                              "show --property=ActiveState --value apache2", "start apache2",
                              "show --property=ActiveState --value apache2"],
                             [command for command in commands(calls, "systemctl")])
            self.assertIn("WARNING: explicit Monitor authority recovery reset invalid cache state", result.stderr)
            self.assertIn("[OK] explicit Monitor cache authority recovery completed.", result.stderr)
            self.assertFalse(box.exists("var/lib/http-infra"))

            box = self.prepare(Path(directory) / "blocked", "restart-blocked:marker-retained;reset-invalid-cache=false")
            result, calls, _spy, _chown = box.apply("--recover-monitor-authority")
            self.assertEqual(1, result.returncode)
            self.assertIn("marker cleanup remains; Apache remains stopped", result.stderr)
            self.assertNotIn("start apache2", commands(calls, "systemctl"))

            box = self.prepare(Path(directory) / "bad", "restart-allowed:complete")
            result, _calls, _spy, _chown = box.apply("--recover-monitor-authority")
            self.assertEqual(1, result.returncode)
            self.assertIn("invalid structured result", result.stderr)


class InfraSetupPyDoca(unittest.TestCase):
    def test_client_with_bluefield_in_dpu_mode(self):
        with tempfile.TemporaryDirectory(prefix="infra-setup-py-doca-") as directory:
            box = Sandbox(Path(directory))
            box.state.update(
                lspci=("03:00.0 Ethernet controller: Mellanox Technologies MT43244 BlueField-3 integrated "
                       "ConnectX-7 network controller (rev 01)\n"),
                mst_status="MST devices:\n------------\n/dev/mst/mt41692_pciconf0         - PCI configuration "
                           "cycles access.\n                                   domain:bus:dev.fn=0000:03:00.0\n",
                mlxconfig_q="         INTERNAL_CPU_OFFLOAD_ENGINE                 ENABLED(0)\n")
            box.state["installed"]["mst"] = "1"
            (box.bin / "mst").exists()
            result, calls, _spy, _chown = box.apply("--client", "--non-interactive", "--enable-bluefield-nic")
            self.assertEqual(0, result.returncode, result.stderr + result.stdout)
            self.assertIn(f"-q https://www.mellanox.com/downloads/DOCA/DOCA_v3.3.0/host/{DOCA_DEB} -O "
                          f"{box.root}/tmp/{DOCA_DEB}.part.", " ".join(commands(calls, "wget")))
            self.assertEqual(DOCA_VERSION, box.state["installed"]["doca-host"])
            self.assertIn("doca-ofed", box.state["installed"])
            self.assertIn("doca-host", box.packages())
            self.assertIn("doca-ofed", box.packages())
            self.assertFalse((box.root / "tmp" / DOCA_DEB).exists())
            self.assertIn("-d /dev/mst/mt41692_pciconf0 -y set INTERNAL_CPU_OFFLOAD_ENGINE=1",
                          commands(calls, "mlxconfig"))
            self.assertIn("  ipmitool chassis power cycle", result.stdout)
            self.assertEqual([], commands(calls, "ipmitool"))


if __name__ == "__main__":
    unittest.main()
