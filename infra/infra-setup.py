#!/usr/bin/env python3
"""Prepare an Ubuntu 22.04/24.04 infra host: management server (--mgmt) or deployed client.

The active entry; infra-setup.sh is kept (保留) but no caller runs it.  The command line keeps the
shell script's options and adds the check/apply contract shared with ufm-setup-upgrade and
initial-setup: without --apply every stage only reads, decides and prints `WOULD APPLY: <action>`;
--apply asks once before the first change (--yes: never).  Exit 0: already in the desired state
(or the changes were applied); 3 (EXIT_PENDING): check mode found changes; 1: failure or not
authorized; usage errors exit 2.  DNS, NTP, timezone and local hostname resolution go through the shared host
module ``ubuntu24_host`` (check and apply decisions come from the same scripts);
infra-teardown.sh consumes the state it records.

Inputs default to this script's own directory, never to a loaded project or git state:
  infra-neutral.conf  required neutral DNS/NTP/TIMEZONE defaults (strict line format)
  01-global.yaml      common.switch.system dns/ntp/date-time; authoritative when present
                      (normally the setup-created link to the project file)
  infra-runtime.conf  optional deploy_infra.py managed block: http_server/local_http_enabled,
                      plus DNS/NTP/timezone when no 01-global.yaml is present (remote clients)

Host paths are written once as their canonical absolute path.  Python-side file access goes
through host_path() and shell scripts from ubuntu24_host receive the canonical path; both are the
same file on a real host.
"""

from __future__ import annotations

from datetime import datetime, timezone
import fcntl
import fnmatch
import glob
import grp
import gzip
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import select
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.parse
import zlib

# Runs as root from the published tree: never leave root-owned bytecode beside the sources.
sys.dont_write_bytecode = True
SCRIPT_PATH = os.path.abspath(__file__)
SCRIPT_DIR = Path(SCRIPT_PATH).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
import ubuntu24_host as host  # noqa: E402


ENTRY = "infra-setup.py"
RECOVERY_COMMAND = "sudo ./infra/infra-setup.py --recover-monitor-authority --apply"
HOST_ROOT = Path("/")

USAGE = f"""Usage: {ENTRY} [options]
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
                          (combines only with --apply and --yes)
  --apply                 Make the changes; without it only check and print WOULD APPLY
                          (exit 0: nothing to change, 3: changes pending, 1: failure;
                          usage errors exit 2)
  --yes                   With --apply: do not ask before the first change
  -h, --help              Show this help
"""

POLICIES = {
    "client": {"apache": "no", "dhcp": "no", "doca": "ask", "bluefield": "yes", "power_cycle": "no"},
    "interactive": {"apache": "ask", "dhcp": "ask", "doca": "ask", "bluefield": "ask", "power_cycle": "ask"},
    "all": {"apache": "yes", "dhcp": "yes", "doca": "yes", "bluefield": "yes", "power_cycle": "yes"},
}
FLAG_NAMES = {
    "--non-interactive": "non_interactive", "--install-apache": "force_apache",
    "--install-dhcp": "force_dhcp", "--download-doca": "force_doca", "--skip-doca": "skip_doca",
    "--enable-bluefield-nic": "force_bluefield", "--power-cycle": "force_power_cycle",
    "--mgmt": "mgmt", "--offline": "offline", "--defer-services": "defer_services",
    "--recover-monitor-authority": "recover", "--apply": "apply", "--yes": "yes",
}

CONTROL_AUTH_SOURCE_SHA256 = "f5cea5266ab808250b718250a8a73d7d6f6452a199b97fa500643d7ed9e988db"
CONTROL_AUTH_HELPER = "/usr/local/lib/http-ztp/control-auth.py"
MONITOR_AUTHORITY_RECOVERY_WARNING = "WARNING: explicit Monitor authority recovery reset invalid cache state; review the accepted www-data denial residual."  # noqa: E501
MONITOR_DECISION_TOKENS = (
    "attest-valid",
    "recovery-in-progress",
    "recovery-committed-cleanup-pending",
    "restart-allowed:complete;reset-invalid-cache=false",
    "restart-allowed:complete;reset-invalid-cache=true",
    "restart-allowed:marker-removal-durability-unknown;reset-invalid-cache=false",
    "restart-allowed:marker-removal-durability-unknown;reset-invalid-cache=true",
    "restart-blocked:marker-retained;reset-invalid-cache=false",
    "restart-blocked:marker-retained;reset-invalid-cache=true",
    "restart-blocked:marker-authority-uncertain;reset-invalid-cache=false",
    "restart-blocked:marker-authority-uncertain;reset-invalid-cache=true",
)
MONITOR_DECISION_TIMEOUT = 11.0
MONITOR_DECISION_LIMIT = 4097

LOCK_FILE = "/run/lock/http-infra.lock"
STATE_DIR = "/var/lib/http-infra"
STATE_FILE = f"{STATE_DIR}/installed-packages"
MANAGED_FILES_FILE = f"{STATE_DIR}/managed-files"
TIMEZONE_STATE_FILE = f"{STATE_DIR}/original-timezone"
TIMESYNCD_UNIT_STATE_FILE = f"{STATE_DIR}/original-timesyncd-unit-state"
RUN_INFO_FILE = f"{STATE_DIR}/run-info"
APACHE_PUBLIC_BOUNDARY_CONF = "/etc/apache2/conf-enabled/http-ztp-public-boundary.conf"
APACHE_LISTENER_CONF = "/etc/apache2/conf-enabled/http-ztp-listeners.conf"
APACHE_PORTS_CONF = "/etc/apache2/ports.conf"
APACHE_SERVERNAME_CONF = "/etc/apache2/conf-available/servername.conf"
APACHE_DEFAULT_SITE = "/etc/apache2/sites-enabled/000-default.conf"
APACHE_DEFAULT_SITE_STATE = f"{STATE_DIR}/apache-default-site-enabled"
DEFERRED_POLICY_PATH = "/usr/sbin/policy-rc.d"
RESOLVED_CONF = "/etc/systemd/resolved.conf"
TIMESYNCD_CONF = "/etc/systemd/timesyncd.conf"
LLDPCLI_CONF = "/etc/lldpd.d/lldpcli.conf"
ZONEINFO = "/usr/share/zoneinfo"
DOCA_SOURCE_LIST = "/etc/apt/sources.list.d/doca.list"
APT_HELPER = "/usr/lib/apt/apt-helper"
APT_LOCK_TIMEOUT = 600
PROMPT_TIMEOUT = 15
DOCA_PROMPT_TIMEOUT = 10

DOCA_RELEASE = "3.3.0-088000-26.01"
BASE_PACKAGES = ("wget", "lldpd", "tzdata")
COMMON_PACKAGES = ("ipmitool", "sshpass", "docker.io", "unzip", "nfs-common", "arping", "jq")
ZTP_DEPENDENCY_PACKAGES = ("python3", "python3-yaml", "python3-jinja2", "python3-openpyxl",
                           "python3-pandas", "python3-xlsxwriter", "openssh-client", "curl")
OPTIONAL_SERVICE_PACKAGES = ("apache2", "apache2-utils", "ssl-cert", "isc-dhcp-server")
APACHE_PACKAGES = ("apache2", "apache2-utils", "ssl-cert")
APACHE_AUTH_MODULES = ("auth_basic", "authn_file", "authn_core", "authz_user", "authz_core", "env",
                       "alias", "cgid", "headers")
MGMT_CACHE_PACKAGES = BASE_PACKAGES + COMMON_PACKAGES + ZTP_DEPENDENCY_PACKAGES + OPTIONAL_SERVICE_PACKAGES
EXIT_PENDING = 3  # check mode found changes; 2 stays the usage error (same name as ufm-setup-upgrade)
SUMMARY_FILES = (RESOLVED_CONF, TIMESYNCD_CONF, LLDPCLI_CONF, APACHE_SERVERNAME_CONF, APACHE_PORTS_CONF,
                 APACHE_LISTENER_CONF, APACHE_PUBLIC_BOUNDARY_CONF, APACHE_DEFAULT_SITE)

LLDPCLI_CONTENT = ("configure system hostname .\n"
                   "configure lldp portidsubtype ifname\n"
                   "configure system interface pattern eth*,eno*,enp*,ens*,enP*\n")
APACHE_PORTS_CONTENT = ("# Managed by http/infra/infra-setup.py.\n"
                        "# DAY0-Prepare/11-load.py owns every exact service-IPv4 Listen directive.\n")
APT_SUMMARY_RE = re.compile(
    r"^(Need to get|After this operation|Fetched |Download complete|[0-9]+ upgraded,"
    r"|[0-9]+ packages? can be upgraded)")
RUNTIME_SCALARS = ("http_server", "local_http_enabled", "time_zone")
RUNTIME_ARRAYS = ("dns_servers", "ntp_servers")

# DAY0 load pins the SHA-256 of these exact bytes before Apache may start; keep them identical
# to infra/docker/apache-ztp.conf (the historical "infra-setup.sh" marker is part of the bytes).
APACHE_PUBLIC_BOUNDARY = r'''# Managed by http/infra/infra-setup.sh.  Keep the marker and bytes stable:
# DAY0 load verifies this exact policy before Apache can be started.
# HTTP-ZTP-PUBLIC-BOUNDARY-V2

# Direct URLs remain usable, but Apache must not enumerate DocumentRoot.
<Directory "/var/www/html">
    Options -Indexes

    <FilesMatch "(?i)\.(?:py|pyc|pyo|cgi|log)$">
        Require all denied
    </FilesMatch>

    <FilesMatch "(?i)(?:manifest|current-release\.json|\.setup_manifest|\.ztp-prefix-publication\.json|\.deployment\.lock)">
        Require all denied
    </FilesMatch>

    <FilesMatch "(?i)(?:01-global\.yaml|02-devices_config\.csv|02-dhcp-subnet_config\.csv|dhcpd(?:_[^/]*)?\.(?:conf|hosts)|p2p-air\.json)">
        Require all denied
    </FilesMatch>
</Directory>

# The Monitor landing page is the browser authentication entry point.  The
# browser reuses this Basic-auth protection space for subsequent control calls,
# while Apache still authenticates every request server-side.
<Directory "/var/www/html/monitor">
    <Files "monitor.html">
        AuthType Basic
        AuthName "HTTP ZTP Monitor Control"
        AuthBasicProvider file
        AuthUserFile /etc/http-ztp/control-users.htpasswd
        Require user nvis cumulus
        Header always set Cache-Control "no-store"
    </Files>
</Directory>

# Bind both canonical and compatibility URLs to the same three exact CGI
# filesystem targets.  Anchors plus AcceptPathInfo Off reject suffix paths.
ScriptAliasMatch "^/monitor/control/ztp-monitor$" "/usr/lib/cgi-bin/ztp-monitor-control"
ScriptAliasMatch "^/monitor/control/switch-collection$" "/usr/lib/cgi-bin/switch-collection-control"
ScriptAliasMatch "^/monitor/control/manual-ztp$" "/usr/lib/cgi-bin/manual-ztp-control"

<Directory "/usr/lib/cgi-bin">
    <FilesMatch "^(?:ztp-monitor-control|switch-collection-control|manual-ztp-control)$">
        AuthType Basic
        AuthName "HTTP ZTP Monitor Control"
        AuthBasicProvider file
        AuthUserFile /etc/http-ztp/control-users.htpasswd
        Require user nvis cumulus
        SetEnv CONTROL_REQUIRE_AUTH 1
        AcceptPathInfo Off
    </FilesMatch>
</Directory>

# Authenticate the canonical and legacy URL spaces as well as their rejected
# PATH_INFO variants, so an invalid suffix can never bypass the challenge.
<LocationMatch "^/(?:monitor/control/(?:ztp-monitor|switch-collection|manual-ztp)|cgi-bin/(?:ztp-monitor-control|switch-collection-control|manual-ztp-control))(?:/.*)?$">
    AuthType Basic
    AuthName "HTTP ZTP Monitor Control"
    AuthBasicProvider file
    AuthUserFile /etc/http-ztp/control-users.htpasswd
    Require user nvis cumulus
    SetEnv CONTROL_REQUIRE_AUTH 1
    AcceptPathInfo Off
</LocationMatch>

# Protect the real filesystem targets even when another URL maps to them.
<DirectoryMatch "^/var/www/html/(?:DAY0-Prepare|monitor/status|ztp/(?:status|backup|optimize)|ztp/config/(?:isc-dhcp-server|cumulus/template|nvos/template))(?:/|$)">
    Require all denied
</DirectoryMatch>

# URL-space rules cover setup aliases and arbitrary ztp_url_prefix links.  A
# segment match is deliberate: infra does not know the selected prefix.
<LocationMatch "(?i)(?:^|/)(?:DAY0-Prepare|status|backup|optimize|monitor/ztp-status|config/(?:isc-dhcp-server|cumulus/template|nvos/template))(?:/|$)">
    Require all denied
</LocationMatch>

# Deny executable source and logs even if a future symlink publishes one
# outside the protected directory prefixes.
<LocationMatch "(?i)(?:^|/)[^/]*\.(?:py|pyc|pyo|cgi|log)(?:/|$)">
    Require all denied
</LocationMatch>

# Release manifests and host-local deployment state are never public assets.
<LocationMatch "(?i)(?:^|/)(?:[^/]*manifest[^/]*|current-release\.json|\.setup_manifest|\.ztp-prefix-publication\.json|\.deployment\.lock)(?:/|$)">
    Require all denied
</LocationMatch>

# Protect declarative inputs and DHCP runtime files wherever they are linked.
<LocationMatch "(?i)(?:^|/)(?:01-global\.yaml|02-devices_config\.csv|02-dhcp-subnet_config\.csv|dhcpd(?:_[^/]*)?\.(?:conf|hosts)|p2p-air\.json)(?:/|$)">
    Require all denied
</LocationMatch>
'''


class SetupExit(Exception):
    def __init__(self, code: int):
        super().__init__(code)
        self.code = int(code)


# ------------------------------------------------------------------ host seams

def host_path(path: str) -> Path:
    """The file a canonical absolute host path names (HOST_ROOT is "/" on a real host)."""
    return HOST_ROOT / path.lstrip("/")


def canonical(path: object) -> str:
    """Inverse of host_path() for messages and for paths handed to host shell scripts."""
    text = os.path.abspath(str(path))
    root = os.path.abspath(str(HOST_ROOT))
    if root == "/":
        return text
    relative = os.path.relpath(text, root)
    return text if relative.startswith("..") else "/" + ("" if relative == "." else relative)


def is_root() -> bool:
    return os.geteuid() == 0


def chown(path: object, user: str, group: str) -> None:
    os.chown(path, pwd.getpwnam(user).pw_uid, grp.getgrnam(group).gr_gid)


def user_exists(name: str) -> bool:
    try:
        pwd.getpwnam(name)
    except KeyError:
        return False
    return True


def sha256_file(path: object) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical_single_link_executable(path: Path) -> bool:
    """[[ -f && ! -L && -x ]] and a link count of exactly one."""
    try:
        info = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and os.access(path, os.X_OK) and info.st_nlink == 1


def write_atomic(path: Path, text: str, mode: int, prefix: str | None = None) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=prefix or f"{path.name}.tmp.", dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except BaseException:
        if os.path.lexists(temporary):
            os.unlink(temporary)
        raise


def current_config_value(path: Path, key: str) -> str:
    """The value ubuntu24_host.config_line_script compares, read before any change is made."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return host.config_line_value(text, key)


# ------------------------------------------------------------- argument parsing

def parse_arguments(argv: list) -> dict:
    options = {name: False for name in FLAG_NAMES.values()}
    explicit_policy = ""
    policy = "client"
    for argument in argv:
        if argument in ("--client", "--interactive", "--all"):
            requested = argument[2:]
            if explicit_policy and explicit_policy != requested:
                print("ERROR: --client, --interactive and --all are mutually exclusive.", file=sys.stderr)
                raise SetupExit(2)
            explicit_policy = policy = requested
        elif argument in FLAG_NAMES:
            options[FLAG_NAMES[argument]] = True
        elif argument in ("-h", "--help"):
            sys.stdout.write(USAGE)
            raise SetupExit(0)
        else:
            print(f"ERROR: Unknown option: {argument}", file=sys.stderr)
            sys.stderr.write(USAGE)
            raise SetupExit(2)
    if options["recover"] and any(item not in ("--recover-monitor-authority", "--apply", "--yes")
                                  for item in argv):
        print("ERROR: --recover-monitor-authority must be the only option.", file=sys.stderr)
        raise SetupExit(2)
    if options["force_doca"] and options["skip_doca"]:
        print("ERROR: --download-doca and --skip-doca are mutually exclusive.", file=sys.stderr)
        raise SetupExit(2)
    if options["offline"] and not options["mgmt"]:
        print("ERROR: --offline is only valid together with --mgmt.", file=sys.stderr)
        raise SetupExit(2)
    if options["offline"] and options["force_doca"]:
        print("ERROR: --offline cannot be combined with --download-doca.", file=sys.stderr)
        raise SetupExit(2)
    if options["yes"] and not options["apply"]:
        print("ERROR: --yes is only valid together with --apply.", file=sys.stderr)
        raise SetupExit(2)
    modes = dict(POLICIES[policy])
    for flag, mode in (("force_apache", "apache"), ("force_dhcp", "dhcp"), ("force_doca", "doca"),
                       ("force_bluefield", "bluefield"), ("force_power_cycle", "power_cycle")):
        if options[flag]:
            modes[mode] = "yes"
    if options["skip_doca"]:
        modes["doca"] = "no"
    options["policy"], options["modes"] = policy, modes
    return options


# ------------------------------------------------------------------- the setup

class InfraSetup:
    def __init__(self, options: dict):
        self.opt = options
        self.modes = options["modes"]
        self.mgmt = options["mgmt"]
        self.offline = options["offline"]
        self.non_interactive = options["non_interactive"]
        self.log_fd: int | None = None
        self.log_file = ""
        self.lock_fds: list = []
        self.setup_status = "started"
        self.trap_installed = False
        self.apt_updated = False
        self.local_apt_repo = False
        self.apt_source_file = ""
        self.local_http_enabled = False
        self.http_server = "http://127.0.0.1/apps"
        self.dns_servers: list = []
        self.ntp_servers: list = []
        self.time_zone = ""
        self.policy_guard_installed = False
        self.policy_backup = ""
        self.policy_delegate = ""
        self.policy_temporary = ""
        self.bluefield_mode_changed = False
        self.changed_mst_devices: list = []
        self.monitor_authority_decision = ""
        # Check/apply contract: nothing is written unless apply; apply asks once unless --yes.
        self.apply = options["apply"]
        self.authorized = options["apply"] and options["yes"]
        self.began = False
        self.pending: list = []
        self.applied: list = []
        self.apt_source_line = ""
        source_dir = os.path.dirname(SCRIPT_PATH)
        self.source_dir = Path(source_dir)
        if os.path.basename(source_dir) == "current":
            self.runtime_dir = Path(os.path.abspath(os.path.join(source_dir, "..")))
        else:
            self.runtime_dir = Path(os.path.abspath(source_dir))
        self.mgmt_http_root = Path(os.path.realpath(os.path.join(source_dir, "..")))
        self.control_auth_source = self.mgmt_http_root / "tools/control-auth.py"
        self.apps_root = self.mgmt_http_root / "apps"
        self.apps_dir: Path | None = None
        self.public_status_file = self.runtime_dir / "infra-status"

    # ------------------------------------------------------------- output
    def to_log(self, text: str) -> None:
        if self.log_fd is not None:
            os.write(self.log_fd, (text + "\n").encode("utf-8", "replace"))

    def logecho(self, text: str = "") -> None:
        print(text, flush=True)
        self.to_log(text)

    def info(self, text: str) -> None:
        self.logecho(f"[INFO]  {text}")

    def warn(self, text: str) -> None:
        self.logecho(f"[WARN]  {text}")

    def success(self, text: str) -> None:
        self.logecho(f"[OK]    {text}")

    def error(self, text: str) -> None:
        print(f"[ERROR] {text}", file=sys.stderr, flush=True)
        self.to_log(f"[ERROR] {text}")

    def fail(self, text: str, code: int = 1) -> None:
        self.error(text)
        raise SetupExit(code)

    def stderr_and_log(self, text: str) -> None:
        print(text, file=sys.stderr, flush=True)
        self.to_log(text)

    def print_section(self, title: str) -> None:
        self.logecho("")
        self.logecho("╔══════════════════════════════════════════════════════╗")
        self.logecho(f"║  {title:<50}║")
        self.logecho("╚══════════════════════════════════════════════════════╝")

    # ----------------------------------------------------------- commands
    def run(self, command: list, *, check: bool = True, to_log: bool = False, capture: bool = False,
            quiet: bool = False) -> subprocess.CompletedProcess:
        """Run a command; check=True mirrors `set -e` by exiting with the command's status."""
        kwargs: dict = {"stdin": subprocess.DEVNULL}
        if capture:
            kwargs.update(stdout=subprocess.PIPE, stderr=subprocess.DEVNULL if quiet else subprocess.PIPE)
        elif to_log and self.log_fd is not None:
            kwargs.update(stdout=self.log_fd, stderr=self.log_fd)
        elif quiet:
            kwargs.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            result = subprocess.run([str(item) for item in command], **kwargs)
        except FileNotFoundError:
            if check:
                self.stderr_and_log(f"{command[0]}: command not found")
                raise SetupExit(127)
            result = subprocess.CompletedProcess(command, 127, b"", b"")
        if capture:
            result.stdout = (result.stdout or b"").decode("utf-8", "replace")
            if isinstance(result.stderr, bytes):
                result.stderr = result.stderr.decode("utf-8", "replace")
        if check and result.returncode != 0:
            if capture and result.stderr:
                self.stderr_and_log(result.stderr.rstrip("\n"))
            raise SetupExit(result.returncode)
        return result

    def output_of(self, command: list) -> str:
        """$(command 2>/dev/null || true): stdout even when the command fails, trailing newlines stripped."""
        return self.run(command, check=False, capture=True, quiet=True).stdout.rstrip("\n")

    def succeeds(self, command: list) -> bool:
        return self.run(command, check=False, quiet=True).returncode == 0

    def run_host_script(self, script: str, label: str) -> tuple:
        """Run one ubuntu24_host script locally as root; (rc, parsed facts, stderr)."""
        result = subprocess.run(["bash", "-c", script], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        self.to_log(f"[HOST]  {label}: exit={result.returncode}")
        for stream in (result.stdout, result.stderr):
            if stream:
                self.to_log(stream.rstrip("\n"))
        return result.returncode, host.parse_kv(result.stdout), result.stderr.strip()

    @staticmethod
    def has(command: str) -> bool:
        return shutil.which(command) is not None

    def systemd_is_operational(self) -> bool:
        return self.has("systemctl") and host_path("/run/systemd/system").is_dir()

    def systemd_unit_load_state(self, unit: str) -> str:
        if not self.systemd_is_operational():
            return "not-found"
        return self.output_of(["systemctl", "show", "--property=LoadState", "--value", unit])

    def systemd_unit_is_missing(self, unit: str) -> bool:
        return self.systemd_unit_load_state(unit) in ("", "not-found")

    def restart_systemd_service(self, unit: str) -> None:
        if not self.systemd_is_operational():
            self.warn(f"systemd is not running; configuration for {unit} was written but service "
                      "restart was skipped.")
            return
        self.run(["systemctl", "restart", unit])

    def dpkg_installed(self, package: str) -> bool:
        return self.succeeds(["dpkg", "-s", package])

    def hostname_fqdn(self) -> str:
        """$(hostname -f 2>/dev/null || hostname)."""
        result = self.run(["hostname", "-f"], check=False, capture=True, quiet=True)
        if result.returncode == 0:
            return result.stdout.rstrip("\n")
        return self.run(["hostname"], check=False, capture=True).stdout.rstrip("\n")

    # ------------------------------------------------------- prompts
    def confirm_action(self, mode: str, prompt: str, timeout: int, default_answer: str = "no") -> bool:
        if mode == "yes":
            return True
        if mode == "no":
            return False
        if not self.apply:
            self.logecho(f"WOULD ASK: {prompt}（检查模式按默认{'执行' if default_answer == 'yes' else '跳过'}评估）")
            return default_answer == "yes"
        if self.non_interactive or not stdin_is_tty():
            self.warn(f"{prompt} — skipped (non-interactive mode)")
            return False
        if default_answer == "yes":
            sys.stderr.write(f"{prompt} [Y/n] (default: perform, auto-perform in {timeout}s) ")
        else:
            sys.stderr.write(f"{prompt} [y/N] (default: skip, auto-skip in {timeout}s) ")
        sys.stderr.flush()
        answer = ""
        try:
            ready, _, _ = select.select([sys.stdin], [], [], timeout)
            if ready:
                answer = sys.stdin.readline().strip()
        except (OSError, ValueError):
            answer = ""
        self.logecho("")
        if answer.lower() in ("yes", "y"):
            return True
        if answer.lower() in ("no", "n"):
            return False
        return default_answer == "yes"

    # ------------------------------------------------------- locks and log
    def acquire_host_lock(self) -> None:
        lock = host_path(LOCK_FILE)
        os.makedirs(lock.parent, exist_ok=True)
        descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o666)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        self.lock_fds.append(descriptor)

    def open_log(self) -> None:
        runtime = self.runtime_dir
        log_dir = runtime / "logs"
        log_root_lock = runtime / ".logs.lock"
        if log_root_lock.is_symlink() or (os.path.lexists(log_root_lock) and not log_root_lock.is_file()):
            print("ERROR: invalid infra log-root lock", file=sys.stderr)
            raise SetupExit(1)
        old_umask = os.umask(0o077)
        try:
            lock_fd = os.open(log_root_lock, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o666)
        finally:
            os.umask(old_umask)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            if log_root_lock.is_symlink() or not log_root_lock.is_file():
                print("ERROR: infra log-root lock changed", file=sys.stderr)
                raise SetupExit(1)
            for pending in sorted(glob.glob(str(runtime / ".logs-migration.*"))):
                if os.path.lexists(pending):
                    print("ERROR: infra log migration state is pending", file=sys.stderr)
                    raise SetupExit(1)
            if log_dir.is_symlink():
                target = os.readlink(log_dir)
                if not (target.startswith("../DAY0-Prepare/") and target.endswith("/99-output-infra")
                        and len(target) > len("../DAY0-Prepare/") + len("/99-output-infra") - 1):
                    print("ERROR: infra/logs is not a managed project link", file=sys.stderr)
                    raise SetupExit(1)
                project = target[len("../DAY0-Prepare/"):-len("/99-output-infra")]
                if project in ("", ".", "..") or "/" in project:
                    print("ERROR: invalid infra log project", file=sys.stderr)
                    raise SetupExit(1)
                projects_root = runtime / "../DAY0-Prepare"
                physical = projects_root / project / "99-output-infra"
                if (projects_root.is_symlink() or (projects_root / project).is_symlink()
                        or physical.is_symlink() or not physical.is_dir()):
                    print("ERROR: infra log owner is not a real project output", file=sys.stderr)
                    raise SetupExit(1)
                if not log_dir.is_dir() or os.path.realpath(log_dir) != os.path.realpath(physical):
                    print("ERROR: infra log owner changed during binding", file=sys.stderr)
                    raise SetupExit(1)
            elif os.path.lexists(log_dir):
                if not log_dir.is_dir():
                    print("ERROR: infra/logs is not a real directory", file=sys.stderr)
                    raise SetupExit(1)
                physical = log_dir
            else:
                os.mkdir(log_dir, 0o700)
                physical = log_dir
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.log_file = str(physical / f"infra-setup-{stamp}-{os.getpid()}.log")
            self.log_fd = os.open(self.log_file, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o666)
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
        self.to_log(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {ENTRY} started")

    # ---------------------------------------------- Monitor authority decisions
    def capture_monitor_authority_decision(self, helper: Path, operation: str) -> bool:
        self.monitor_authority_decision = capture_decision(helper, operation, host_path("/run"))
        return bool(self.monitor_authority_decision)

    def run_native_monitor_authority_routine(self, operation: str) -> bool:
        if operation not in ("monitor-authority-provision", "monitor-authority-attest"):
            self.stderr_line("ERROR: invalid routine Monitor authority operation; service must remain stopped.")
            return False
        helper = host_path(CONTROL_AUTH_HELPER)
        if not self.capture_monitor_authority_decision(helper, f"{operation}-decision"):
            self.stderr_line("ERROR: routine Monitor cache authority validation failed; Apache must remain stopped.")
            return False
        decision = self.monitor_authority_decision
        if decision == "attest-valid":
            return True
        if decision in ("recovery-in-progress", "recovery-committed-cleanup-pending"):
            self.explain_recovery_state(decision)
            return False
        self.stderr_line("ERROR: routine Monitor cache authority validation failed; Apache must remain stopped.")
        return False

    def explain_recovery_state(self, decision: str) -> None:
        if decision == "recovery-in-progress":
            self.stderr_line("ERROR: classification=recovery-in-progress; Monitor authority recovery has not "
                             "been committed; Apache must remain stopped. Run exactly: " + RECOVERY_COMMAND)
        elif decision == "recovery-committed-cleanup-pending":
            self.stderr_line("ERROR: classification=recovery-committed-cleanup-pending; previous Monitor "
                             "authority recovery COMPLETED and the repaired authority itself is not in "
                             "question; Apache must remain stopped. Re-run exactly to reattest and finish "
                             "marker cleanup: " + RECOVERY_COMMAND)

    def stderr_line(self, text: str) -> None:
        """`echo ... >&2` in the shell version: terminal only, not the log."""
        print(text, file=sys.stderr, flush=True)

    def both_streams(self, text: str) -> None:
        """`echo >&2; echo >&3`."""
        print(text, file=sys.stderr, flush=True)
        self.to_log(text)

    def apache_active_state(self) -> str | None:
        result = self.run(["systemctl", "show", "--property=ActiveState", "--value", "apache2"],
                          check=False, capture=True)
        if result.returncode != 0:
            return None
        return result.stdout.rstrip("\n")

    def recover_monitor_authority(self) -> int:
        """0: recovered; EXIT_PENDING: check mode (prerequisites verified read-only); 1: refused or failed."""
        if not self.systemd_is_operational():
            self.stderr_line("ERROR: systemd state is unavailable; Monitor authority was not repaired.")
            return 1
        initial = self.apache_active_state()
        if initial not in ("active", "inactive", "failed"):
            self.stderr_line("ERROR: Apache state cannot be proven; Monitor authority was not repaired.")
            return 1
        action = (f"stop apache2 (ActiveState={initial}) and explicitly recover the Monitor cache authority"
                  + ("; start apache2 again once the recovered authority attests" if initial == "active" else ""))
        if not self.apply:
            # The apply run checks these only after Apache is stopped; here they are read-only.
            helper = host_path(CONTROL_AUTH_HELPER)
            problem = ""
            if (not canonical_single_link_executable(self.control_auth_source)
                    or sha256_file(self.control_auth_source) != CONTROL_AUTH_SOURCE_SHA256):
                problem = "recovery requires the pinned canonical sibling tools/control-auth.py"
            elif not canonical_single_link_executable(helper) or sha256_file(helper) != CONTROL_AUTH_SOURCE_SHA256:
                problem = "the installed recovery helper is missing, unsafe or not the pinned version"
            elif not self.succeeds_visible([helper, "validate"]):
                problem = "Monitor credentials are invalid"
            if problem:
                self.stderr_line(f"ERROR: {problem}; Monitor authority would not be repaired (check mode, nothing changed).")
                return 1
            self.logecho(f"WOULD APPLY: {action}")
            self.logecho(self.mode_line())
            self.logecho("结果: 需要显式恢复（检查模式未改动；核对上面的 WOULD APPLY 后加 --apply 重跑）")
            return EXIT_PENDING
        self.change(action, announce=False)
        if not self.succeeds_visible(["systemctl", "stop", "apache2"]):
            self.stderr_line("ERROR: Apache could not be stopped; Monitor authority was not repaired.")
            return 1
        stopped = self.apache_active_state()
        if stopped not in ("inactive", "failed"):
            self.stderr_line("ERROR: Apache is not provably stopped; Monitor authority was not repaired.")
            return 1
        self.both_streams("[WARN] Apache stopped for explicit Monitor cache authority recovery.")
        if not canonical_single_link_executable(self.control_auth_source):
            self.stderr_line("ERROR: recovery requires canonical sibling tools/control-auth.py; "
                             "Apache remains stopped.")
            return 1
        if sha256_file(self.control_auth_source) != CONTROL_AUTH_SOURCE_SHA256:
            self.stderr_line("ERROR: recovery helper source hash mismatch; Apache remains stopped.")
            return 1
        helper = host_path(CONTROL_AUTH_HELPER)
        if not canonical_single_link_executable(helper):
            self.stderr_line("ERROR: installed recovery helper is missing or unsafe; Apache remains stopped.")
            return 1
        if sha256_file(helper) != CONTROL_AUTH_SOURCE_SHA256:
            self.stderr_line("ERROR: installed recovery helper hash mismatch; Apache remains stopped.")
            return 1
        if not self.succeeds_visible([helper, "validate"]):
            self.stderr_line("ERROR: Monitor credentials are invalid; Apache remains stopped.")
            return 1
        if not self.capture_monitor_authority_decision(helper, "monitor-authority-recover-decision"):
            self.stderr_line("ERROR: explicit Monitor authority recovery returned an invalid structured "
                             "result; Apache remains stopped.")
            return 1
        decision = self.monitor_authority_decision
        if decision.endswith(";reset-invalid-cache=true"):
            self.both_streams(MONITOR_AUTHORITY_RECOVERY_WARNING)
        elif not decision.endswith(";reset-invalid-cache=false"):
            self.stderr_line("ERROR: explicit Monitor authority recovery returned an invalid warning "
                             "decision; Apache remains stopped.")
            return 1
        state = decision.rsplit(";", 1)[0]
        if state == "restart-allowed:complete":
            pass
        elif state == "restart-allowed:marker-removal-durability-unknown":
            self.stderr_line("WARNING: previous Monitor authority recovery COMPLETED, but marker removal "
                             "durability is unknown; a stale completed marker may reappear after crash.")
        elif state == "restart-blocked:marker-retained":
            self.stderr_line("ERROR: previous Monitor authority recovery COMPLETED and the repaired "
                             "authority itself is not in question, but marker cleanup remains; Apache "
                             "remains stopped. Re-run exactly: " + RECOVERY_COMMAND)
            return 1
        elif state == "restart-blocked:marker-authority-uncertain":
            self.stderr_line("ERROR: Monitor recovery marker authority is uncertain after semantic commit; "
                             "Apache remains stopped. Re-run exactly: " + RECOVERY_COMMAND)
            return 1
        else:
            self.stderr_line("ERROR: explicit Monitor authority recovery returned an invalid structured "
                             "result; Apache remains stopped.")
            return 1
        if not self.run_native_monitor_authority_routine("monitor-authority-attest"):
            self.stderr_line("ERROR: recovered Monitor authority did not attest; Apache remains stopped.")
            return 1
        if initial == "active":
            if not self.succeeds_visible(["systemctl", "start", "apache2"]):
                self.stderr_line("ERROR: Apache could not be restored after recovery; it remains stopped.")
                return 1
            if self.apache_active_state() != "active":
                self.succeeds_visible(["systemctl", "stop", "apache2"])
                self.stderr_line("ERROR: Apache restart could not be attested; it remains stopped.")
                return 1
        self.both_streams("[OK] explicit Monitor cache authority recovery completed.")
        return 0

    def succeeds_visible(self, command: list) -> bool:
        """A conditional command whose own output stays on the terminal."""
        return self.run(command, check=False).returncode == 0

    # ---------------------------------------------------------- inputs
    def load_neutral_defaults(self) -> None:
        neutral = self.source_dir / "infra-neutral.conf"
        if not os.access(neutral, os.R_OK):
            print(f"ERROR: governed neutral defaults are missing: {neutral}", file=sys.stderr)
            raise SetupExit(1)
        text = neutral.read_text(encoding="utf-8", errors="replace")
        # `while read` drops a final line without a newline; keep that behaviour.
        lines = text.split("\n")[:-1]
        values = {}
        for number, line in enumerate(lines, 1):
            key, _, value = line.partition("=")
            if (key not in ("DNS", "NTP", "TIMEZONE")
                    or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/+-]*", value)):
                print(f"ERROR: invalid neutral defaults line {number}", file=sys.stderr)
                raise SetupExit(1)
            if (key, number) not in (("DNS", 1), ("NTP", 2), ("TIMEZONE", 3)):
                print("ERROR: neutral defaults must be ordered DNS/NTP/TIMEZONE", file=sys.stderr)
                raise SetupExit(1)
            values[key] = value
        dns = values.get("DNS", "")
        dns_valid = bool(re.fullmatch(r"([0-9]{1,3}\.){3}[0-9]{1,3}", dns)) and all(
            not (octet != "0" and octet.startswith("0")) and int(octet) <= 255 for octet in dns.split("."))
        if (len(lines) != 3 or not dns_valid
                or not re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?", values.get("NTP", ""))
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_+.-]*(/[A-Za-z0-9][A-Za-z0-9_+.-]*)*",
                                    values.get("TIMEZONE", ""))):
            print("ERROR: neutral defaults are incomplete or invalid", file=sys.stderr)
            raise SetupExit(1)
        self.neutral = ([dns], [values["NTP"]], values["TIMEZONE"])
        self.dns_servers, self.ntp_servers, self.time_zone = [dns], [values["NTP"]], values["TIMEZONE"]

    def load_runtime_config(self) -> dict:
        """Parse deploy_infra.py's managed block without executing it."""
        runtime = self.source_dir / "infra-runtime.conf"
        try:
            if not runtime.is_file() or runtime.stat().st_size == 0:
                return {}
            lines = runtime.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as exc:
            print(f"ERROR: cannot read {runtime}: {exc}", file=sys.stderr)
            raise SetupExit(1) from exc
        values: dict = {}
        for number, raw in enumerate(lines, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            key, _, rest = line.partition("=")
            try:
                if key in RUNTIME_ARRAYS and rest.startswith("(") and rest.endswith(")"):
                    items = shlex.split(rest[1:-1])
                    if not items:
                        raise ValueError("empty array")
                    values[key] = items
                    continue
                if key in RUNTIME_SCALARS:
                    items = shlex.split(rest)
                    if len(items) > 1:
                        raise ValueError("more than one word")
                    values[key] = items[0] if items else ""
                    continue
            except ValueError:
                pass
            print(f"ERROR: {runtime} line {number} is not a deploy_infra.py managed assignment", file=sys.stderr)
            raise SetupExit(1)
        return values

    def load_global(self) -> dict | None:
        """common.switch.system from 01-global.yaml in this script's directory (None when absent)."""
        global_file = self.source_dir / "01-global.yaml"
        if not os.path.lexists(global_file):
            return None
        if not global_file.is_file():
            print(f"ERROR: global input is not a readable file (dangling link?): {global_file}", file=sys.stderr)
            raise SetupExit(1)
        try:
            document = host.yaml_module().safe_load(global_file.read_text(encoding="utf-8"))
        except host.HostConfigError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            raise SetupExit(1) from exc
        except Exception as exc:  # yaml.YAMLError, OSError, UnicodeError
            print(f"ERROR: invalid global YAML {global_file}: {exc}", file=sys.stderr)
            raise SetupExit(1) from exc
        # deploy_infra.load_common requires the mapping itself; infra_settings treats it as empty.
        common = document.get("common") if isinstance(document, dict) else None
        switch = common.get("switch") if isinstance(common, dict) else None
        if not isinstance(switch, dict) or not isinstance(switch.get("system"), dict):
            print(f"ERROR: {global_file} lacks the common.switch.system mapping", file=sys.stderr)
            raise SetupExit(1)
        # infra_settings: an absent key is skipped (empty result, warning), a present but empty or
        # invalid key is an error, never a silent neutral fallback.
        dns, ntp, zone, errors, _warnings = host.infra_settings(document)
        if errors:
            for item in errors:
                print(f"ERROR: {global_file}: {item}", file=sys.stderr)
            raise SetupExit(1)
        return {"dns": dns or None, "ntp": ntp or None, "timezone": zone or None, "path": str(global_file)}

    def resolve_inputs(self) -> None:
        self.load_neutral_defaults()
        runtime = self.load_runtime_config()
        settings = self.load_global()
        if "http_server" in runtime:
            self.http_server = runtime["http_server"]
        if "local_http_enabled" in runtime:
            self.local_http_enabled = runtime["local_http_enabled"] == "true"
        neutral_dns, neutral_ntp, neutral_zone = self.neutral
        if settings is None:
            self.dns_servers = runtime.get("dns_servers", neutral_dns)
            self.ntp_servers = runtime.get("ntp_servers", neutral_ntp)
            self.time_zone = runtime.get("time_zone", neutral_zone)
            self.input_note = ("infra-runtime.conf" if runtime else "infra-neutral.conf") + " (no 01-global.yaml)"
        else:
            self.dns_servers = settings["dns"] if settings["dns"] is not None else neutral_dns
            self.ntp_servers = settings["ntp"] if settings["ntp"] is not None else neutral_ntp
            self.time_zone = settings["timezone"] if settings["timezone"] is not None else neutral_zone
            self.input_note = settings["path"]
            stale = [label for label, key, mine in (("DNS", "dns_servers", self.dns_servers),
                                                    ("NTP", "ntp_servers", self.ntp_servers),
                                                    ("timezone", "time_zone", self.time_zone))
                     if key in runtime and runtime[key] != mine]
            self.runtime_mismatch = stale
        base = self.http_server[:-1] if self.http_server.endswith("/") else self.http_server
        # Connectivity checks use IP/IPv6 literals only, never host names (owner ruling 2026-10-19).
        try:
            ipaddress.ip_address(urllib.parse.urlsplit(base).hostname or "")
        except ValueError:
            print(f"ERROR: http_server must use an IP address literal, not a host name: {base}", file=sys.stderr)
            raise SetupExit(1)
        self.http_server = f"{base}/{self.repo_relative_path}"

    # ---------------------------------------------------------- state files
    def record_package_state(self, package: str, state: str) -> None:
        if state == "installed":
            result = self.run(["dpkg-query", "-W", "-f=${Version}", package], check=False, capture=True,
                              quiet=True)
            if result.returncode != 0:
                self.fail(f"Package installation could not be verified: {package}")
            version = result.stdout
        else:
            version = state
        state_file = host_path(STATE_FILE)
        kept = [line for line in state_file.read_text(encoding="utf-8").splitlines()
                if line.split("\t", 1)[0] != package]
        kept.append(f"{package}\t{version}\t{utc_now()}")
        write_atomic(state_file, "".join(line + "\n" for line in kept), 0o600, f"{state_file.name}.tmp.")

    def begin_package_install(self, package: str) -> None:
        self.record_package_state(package, "pending")

    def commit_package_install(self, package: str) -> None:
        self.record_package_state(package, "installed")

    def backup_file(self, file: str) -> None:
        path = host_path(file)
        if not path.is_file():
            return
        for existing in sorted(glob.glob(f"{glob.escape(str(path))}.http-infra.bak.*")):
            if os.path.isfile(existing):
                self.info(f"Original backup already exists: {canonical(existing)}")
                return
        backup = f"{file}.http-infra.bak.{datetime.now():%Y%m%d_%H%M%S}"
        copy_preserving(path, host_path(backup))
        self.info(f"Backed up: {file} → {backup}")

    def track_managed_file(self, file: str) -> None:
        managed = host_path(MANAGED_FILES_FILE)
        content = managed.read_text(encoding="utf-8")
        if any(line.split("\t", 1)[0] == file for line in content.splitlines()):
            return
        if host_path(file).is_file():
            self.backup_file(file)
            action = "restore"
        else:
            action = "delete"
        write_atomic(managed, content + f"{file}\t{action}\n", 0o600, f"{managed.name}.tmp.")

    def write_run_info(self) -> None:
        lines = ["schema_version=2", f"last_setup_started={utc_now()}", "status=started",
                 f"script_sha256={sha256_file(SCRIPT_PATH)}", f"http_server={self.http_server}",
                 f"local_http_enabled={str(self.local_http_enabled).lower()}",
                 f"mgmt_mode={str(self.mgmt).lower()}", f"expected_dns={' '.join(self.dns_servers)}",
                 f"expected_ntp={' '.join(self.ntp_servers)}", f"expected_timezone={self.time_zone}"]
        run_info = host_path(RUN_INFO_FILE)
        write_atomic(run_info, "".join(line + "\n" for line in lines), 0o600, f"{run_info.name}.tmp.")

    def mark_run_complete(self) -> None:
        run_info = host_path(RUN_INFO_FILE)
        kept = [line for line in run_info.read_text(encoding="utf-8").splitlines()
                if line.split("=", 1)[0] not in ("status", "last_setup_completed", "local_http_enabled")]
        kept += [f"local_http_enabled={str(self.local_http_enabled).lower()}", "status=completed",
                 f"last_setup_completed={utc_now()}"]
        write_atomic(run_info, "".join(line + "\n" for line in kept), 0o600, f"{run_info.name}.tmp.")

    def write_public_status(self, exit_code: int) -> None:
        try:
            recorded = sum(1 for line in host_path(STATE_FILE).read_text(encoding="utf-8").splitlines()
                           if line.split())
        except OSError:
            recorded = 0
        lines = ["schema_version=1", f"hostname={self.hostname_fqdn()}", "last_action=setup",
                 f"status={self.setup_status}", f"exit_code={exit_code}", f"updated_at={utc_now()}",
                 f"http_server={self.http_server}", f"local_http_enabled={str(self.local_http_enabled).lower()}",
                 f"mgmt_mode={str(self.mgmt).lower()}", f"log_file={self.log_file}",
                 f"recorded_packages={recorded}"]
        write_atomic(self.public_status_file, "".join(line + "\n" for line in lines), 0o644, ".infra-status.")

    # ------------------------------------------------- deferred service policy
    def install_deferred_service_policy(self) -> None:
        if not self.opt["defer_services"] and self.modes["apache"] == "no" and self.modes["dhcp"] == "no":
            return
        policy = host_path(DEFERRED_POLICY_PATH)
        os.makedirs(policy.parent, exist_ok=True)
        if os.path.lexists(policy):
            descriptor, backup = tempfile.mkstemp(prefix=f"{policy.name}.http-infra.backup.", dir=str(policy.parent))
            os.close(descriptor)
            os.unlink(backup)
            if policy.is_symlink():
                self.policy_delegate = os.path.realpath(policy)
            os.rename(policy, backup)
            self.policy_backup = backup
            if not self.policy_delegate:
                self.policy_delegate = backup
        # Ownership is marked before the replacement exists so cleanup restores an old policy.
        self.policy_guard_installed = True
        descriptor, temporary = tempfile.mkstemp(prefix=f"{policy.name}.http-infra.guard.", dir=str(policy.parent))
        self.policy_temporary = temporary
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write("#!/bin/sh\n"
                         'case "${1:-}" in\n'
                         "  apache2|*/apache2|isc-dhcp-server|*/isc-dhcp-server) exit 101 ;;\n"
                         "esac\n"
                         f'if [ -n "{self.policy_delegate}" ] && [ -x "{self.policy_delegate}" ]; then\n'
                         f'  exec "{self.policy_delegate}" "$@"\n'
                         "fi\n"
                         "exit 0\n")
        os.chmod(temporary, 0o755)
        os.replace(temporary, policy)
        self.policy_temporary = ""
        if self.opt["defer_services"]:
            self.logecho("[INFO]  Transactional load mode: Apache/DHCP package auto-start is blocked until "
                         "load commits.")
        else:
            self.logecho("[INFO]  Apache/DHCP package auto-start is blocked until configuration validation "
                         "succeeds.")

    def restore_deferred_service_policy(self) -> None:
        if not self.policy_guard_installed:
            return
        if self.policy_temporary and os.path.lexists(self.policy_temporary):
            os.unlink(self.policy_temporary)
        policy = host_path(DEFERRED_POLICY_PATH)
        if os.path.lexists(policy):
            os.unlink(policy)
        if self.policy_backup and os.path.lexists(self.policy_backup):
            os.rename(self.policy_backup, policy)
        self.policy_guard_installed = False

    def on_setup_exit(self, exit_code: int) -> int:
        try:
            self.restore_deferred_service_policy()
        except OSError:
            self.both_streams(f"ERROR: Failed to restore {DEFERRED_POLICY_PATH}")
            exit_code = 1
        if self.apt_source_file:
            try:
                os.unlink(self.apt_source_file)
            except OSError:
                pass
        if exit_code != 0:
            self.setup_status = "failed"
        try:
            self.write_public_status(exit_code)
        except Exception:
            pass
        return exit_code

    # ------------------------------------------------------------ APT
    def apt_log(self, command: list) -> int:
        started = time.monotonic()
        command = [str(item) for item in command]
        prefix = ["stdbuf", "-oL", "-eL"] if self.has("stdbuf") else []
        joined = " ".join(command)
        if os.path.basename(command[0]) == "apt-get" or (
                os.path.basename(command[0]) == "env" and fnmatch.fnmatchcase(f" {joined} ", "* apt-get *")):
            # The shell `case` patterns, evaluated with the same glob semantics.
            padded = f" {joined} "
            for pattern, action in (("* --download-only * install *", "downloading packages into the offline cache"),
                                    ("* install *", "installing packages"),
                                    ("* update *", "refreshing package indexes"),
                                    ("* remove *", "removing packages"), ("* purge *", "removing packages"),
                                    ("*", "processing packages")):
                if fnmatch.fnmatchcase(padded, pattern):
                    break
            self.info(f"APT: {action} (quiet mode; dpkg lock timeout {APT_LOCK_TIMEOUT}s).")
            self.to_log(f"[INFO]  Full APT command: {joined}")
            with tempfile.TemporaryFile() as output:
                try:
                    process = subprocess.Popen(prefix + command, stdin=subprocess.DEVNULL, stdout=output,
                                               stderr=subprocess.STDOUT)
                except FileNotFoundError:
                    self.error(f"APT failed after 0s (exit=127). Last output:")
                    return 127
                reported = 0
                while True:
                    try:
                        status = process.wait(timeout=1)
                        break
                    except subprocess.TimeoutExpired:
                        elapsed = int(time.monotonic() - started)
                        if elapsed > 0 and elapsed % 15 == 0 and elapsed != reported:
                            reported = elapsed
                            self.info(f"APT still {action}; elapsed {elapsed}s...")
                output.seek(0)
                text = output.read().decode("utf-8", "replace")
            if self.log_fd is not None and text:
                os.write(self.log_fd, text.encode("utf-8", "replace"))
            for line in [line for line in text.splitlines() if APT_SUMMARY_RE.match(line)][-6:]:
                self.info(f"APT: {line}")
            elapsed = int(time.monotonic() - started)
            if status != 0:
                self.error(f"APT failed after {elapsed}s (exit={status}). Last output:")
                tail = text.splitlines()[-30:]
                if tail:
                    print("\n".join(tail), file=sys.stderr, flush=True)
                self.error(f"Full APT output is available in: {self.log_file}")
                return status
            self.success(f"APT completed in {elapsed}s: {action}.")
            return 0
        self.info(f"Running: {joined}")
        self.info("Live command output follows.")
        try:
            process = subprocess.Popen(prefix + command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT)
        except FileNotFoundError:
            self.error(f"Command failed after 0s (exit=127): {joined}")
            return 127
        for chunk in iter(lambda: process.stdout.readline(), b""):
            sys.stdout.write(chunk.decode("utf-8", "replace"))
            sys.stdout.flush()
            if self.log_fd is not None:
                os.write(self.log_fd, chunk)
        process.stdout.close()
        status = process.wait()
        elapsed = int(time.monotonic() - started)
        if status != 0:
            self.error(f"Command failed after {elapsed}s (exit={status}): {joined}")
            return status
        self.success(f"Command completed in {elapsed}s.")
        return 0

    def apt_get(self, *arguments: str) -> int:
        self.ensure_apt_source_file()
        base = ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "-o", f"DPkg::Lock::Timeout={APT_LOCK_TIMEOUT}"]
        if self.mgmt and self.offline:
            options = ["-o", f"Dir::Etc::sourcelist={self.apt_source_file}", "-o", "Dir::Etc::sourceparts=-",
                       "-o", "APT::Get::List-Cleanup=0", "-o", f"Dir::Cache::archives={self.apps_dir}/"]
        elif self.mgmt:
            options = ["-o", f"Dir::Cache::archives={self.apps_dir}/", "-o", "APT::Keep-Downloaded-Packages=true",
                       "-o", "Binary::apt-get::APT::Keep-Downloaded-Packages=true"]
        elif self.local_apt_repo:
            options = ["-o", f"Dir::Etc::sourcelist={self.apt_source_file}", "-o", "Dir::Etc::sourceparts=-",
                       "-o", "APT::Get::List-Cleanup=0"]
        else:
            options = []
        return self.apt_log(base + options + list(arguments))

    def require(self, status: int) -> None:
        if status != 0:
            raise SetupExit(status)

    def apt_update_once(self) -> None:
        if not self.apt_updated:
            self.info("Refreshing APT package indexes from the configured repositories...")
            self.require(self.apt_get("update"))
            self.apt_updated = True

    def apt_install(self, *packages: str) -> None:
        self.require(self.apt_get("install", "-y", *packages))
        self.refresh_mgmt_repository()

    def install_recorded(self, packages: list) -> None:
        for package in packages:
            self.begin_package_install(package)
        self.apt_update_once()
        self.apt_install(*packages)
        for package in packages:
            self.commit_package_install(package)

    def http_file_exists(self, url: str) -> bool:
        if self.has("wget"):
            return self.succeeds(["wget", "-q", "--spider", url])
        if self.has("curl"):
            return self.succeeds(["curl", "-fsSIL", "--max-time", "5", url])
        helper = host_path(APT_HELPER)
        if os.access(helper, os.X_OK):
            descriptor, probe = tempfile.mkstemp(prefix="http-infra-http-probe.", dir=str(host_path("/tmp")))
            os.close(descriptor)
            try:
                return self.succeeds([helper, "download-file", url, probe])
            finally:
                os.unlink(probe)
        return False

    def new_apt_source_file(self, line: str) -> None:
        """Remember the private APT source; the temporary file is written only when APT runs."""
        self.apt_source_line = line

    def ensure_apt_source_file(self) -> None:
        if self.apt_source_line and not self.apt_source_file:
            descriptor, path = tempfile.mkstemp(prefix="http-infra-apt-source.", dir=str(host_path("/tmp")))
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(self.apt_source_line + "\n")
            self.apt_source_file = path

    def configure_local_apt_repo(self) -> None:
        if self.mgmt and self.offline:
            packages = self.apps_dir / "Packages.gz"
            if not (packages.is_file() and packages.stat().st_size > 0):
                self.fail(f"Offline management repository is missing: {self.apps_dir}/Packages.gz")
            meta = self.apps_dir / "repository.meta"
            lines = meta.read_text(encoding="utf-8").splitlines() if meta.is_file() and meta.stat().st_size else []
            if not lines or any(item not in lines for item in (
                    "os_id=ubuntu", f"os_version={self.version_id}", f"architecture={self.arch}")):
                self.fail(f"Offline repository metadata is missing or mismatched: {meta}")
            self.new_apt_source_file(f"deb [trusted=yes] file:{self.apps_dir} ./")
            self.local_apt_repo = True
            self.success(f"Offline management APT repository selected: {self.apps_dir}/Packages.gz")
            return
        if self.mgmt or not self.local_http_enabled or not self.http_server:
            return
        if self.http_file_exists(f"{self.http_server}/Packages.gz"):
            self.new_apt_source_file(f"deb [trusted=yes] {self.http_server}/ ./")
            self.local_apt_repo = True
            self.success(f"Local APT repository detected: {self.http_server}/Packages.gz")
        else:
            self.info("No local APT repository index found; package installation will use configured "
                      "Internet repositories.")

    def enable_embedded_doca_repo(self) -> None:
        if not self.local_apt_repo:
            return
        self.ensure_apt_source_file()
        source = host_path(DOCA_SOURCE_LIST)
        if not os.access(source, os.R_OK):
            self.fail(f"doca-host did not create the expected APT source: {DOCA_SOURCE_LIST}")
        with open(self.apt_source_file, encoding="utf-8") as handle:
            existing = handle.read().splitlines()
        for line in source.read_text(encoding="utf-8").splitlines():
            if not re.match(r"^deb .*file:", line):
                continue
            if line not in existing:
                with open(self.apt_source_file, "a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
                existing.append(line)
        if not any(re.match(r"^deb .*file:", line) for line in existing):
            self.fail(f"No binary DOCA file repository was found in {DOCA_SOURCE_LIST}")
        self.apt_updated = False
        self.success("Embedded DOCA repository enabled for this offline run.")

    def refresh_mgmt_repository(self) -> None:
        if not self.mgmt:
            return
        apps = self.apps_dir
        records = []
        for deb in sorted(apps.glob("*.deb")):
            if not deb.is_file():
                continue
            control = self.run(["dpkg-deb", "-f", deb], capture=True).stdout
            data = deb.read_bytes()
            records.append(control + f"Filename: ./{deb.name}\nSize: {len(data)}\n"
                           f"MD5sum: {hashlib.md5(data).hexdigest()}\n"
                           f"SHA256: {hashlib.sha256(data).hexdigest()}\n\n")
        packages = "".join(records).encode("utf-8")
        write_atomic_bytes(apps / "Packages", packages, 0o644, ".Packages.")
        write_atomic_bytes(apps / "Packages.gz", gzip.compress(packages, compresslevel=9, mtime=0), 0o644,
                           ".Packages.")
        meta = (f"schema_version=1\nos_id=ubuntu\nos_version={self.version_id}\narchitecture={self.arch}\n"
                f"generated_at={utc_now()}\n")
        write_atomic_bytes(apps / "repository.meta", meta.encode("utf-8"), 0o644, ".repository.meta.")
        for path in list(apps.glob("*.deb")) + [apps / "Packages", apps / "Packages.gz", apps / "repository.meta"]:
            try:
                os.chmod(path, 0o644)
            except OSError:
                pass
        try:
            os.unlink(apps / "lock")
        except FileNotFoundError:
            pass
        self.success(f"Local APT repository refreshed: {apps}/Packages.gz")

    def cache_mgmt_package_closure(self, *packages: str) -> None:
        if not self.mgmt:
            return
        descriptor, status_file = tempfile.mkstemp(prefix="http-infra-empty-status.", dir=str(host_path("/tmp")))
        os.close(descriptor)
        self.info(f"Caching complete package closure for offline clients: {' '.join(packages)}")
        try:
            status = self.apt_log(["apt-get", "-o", f"DPkg::Lock::Timeout={APT_LOCK_TIMEOUT}",
                                   "-o", f"Dir::State::status={status_file}",
                                   "-o", f"Dir::Cache::archives={self.apps_dir}/",
                                   "-o", "APT::Keep-Downloaded-Packages=true",
                                   "-o", "Binary::apt-get::APT::Keep-Downloaded-Packages=true",
                                   "--download-only", "install", "-y", *packages])
        finally:
            os.unlink(status_file)
        if status != 0:
            raise SetupExit(1)
        self.refresh_mgmt_repository()

    def deb_field(self, path: object, field: str) -> str:
        return self.output_of(["dpkg-deb", "-f", path, field])

    def doca_metadata_matches(self, path: object) -> bool:
        return (self.deb_field(path, "Package") == "doca-host"
                and self.deb_field(path, "Version") == self.doca_package_version
                and self.deb_field(path, "Architecture") == self.arch)

    def ensure_doca_host_package(self, destination: Path) -> None:
        if destination.is_file():
            if self.doca_metadata_matches(destination):
                self.success(f"Reusing verified DOCA host package: {canonical(destination)}")
                return
            self.warn(f"Existing DOCA host package is invalid or mismatched; replacing: {canonical(destination)}")
        if self.offline:
            self.fail(f"Offline mode requires a verified packaged DOCA host file: {canonical(destination)}")
        if (self.local_http_enabled and self.http_server
                and self.http_file_exists(f"{self.http_server}/{self.doca_package}")):
            source_url = f"{self.http_server}/{self.doca_package}"
        else:
            source_url = self.doca_path
        descriptor, part = tempfile.mkstemp(prefix=f"{destination.name}.part.", dir=str(destination.parent))
        os.close(descriptor)
        self.info(f"Downloading {self.doca_package} from: {source_url}")
        if self.apt_log(["wget", "-q", source_url, "-O", part]) != 0:
            os.unlink(part)
            self.fail(f"Failed to download DOCA host package: {source_url}")
        if not self.doca_metadata_matches(part):
            os.unlink(part)
            self.fail("Downloaded DOCA host package failed metadata validation")
        os.chmod(part, 0o644)
        os.replace(part, destination)
        self.success(f"DOCA host package downloaded and verified: {canonical(destination)}")

    # ------------------------------------------------------------- run
    # ------------------------------------------------------- check / apply
    def mode_line(self) -> str:
        if not self.apply:
            return ("模式: CHECK_ONLY（未加 --apply：只检查并列出 WOULD APPLY，不安装软件、不写配置或状态、"
                    "不启停服务）")
        return ("模式: APPLY --yes（不再确认，直接改动）" if self.opt["yes"]
                else "模式: APPLY（第一次改动前确认一次，授权对本次运行的后续改动同样有效）")

    def confirm_change(self, action: str) -> bool:
        print(f"\n首次改动: {action}", flush=True)
        try:
            answer = input("授权本次及后续改动？[y/N]: ").strip().casefold()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        granted = answer in {"y", "yes"}
        self.logecho(f"  操作员{'已授权' if granted else '未授权'}")
        return granted

    def change(self, action: str, *, announce: bool = True) -> bool:
        """Gate in front of every write.

        Check mode records `WOULD APPLY: <action>` and returns False, so the caller skips the
        write.  Apply mode asks once, before the first change of the run (--yes: never), starts
        the run bookkeeping and returns True.  A refusal stops the run before anything is written.
        """
        if not self.apply:
            self.pending.append(action)
            self.logecho(f"WOULD APPLY: {action}")
            return False
        if not self.authorized:
            self.to_log(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] authorization requested: {action}")
            if not self.confirm_change(action):
                self.error("操作员未授权改动，本次运行停止，未做任何改动。")
                raise SetupExit(1)
            self.authorized = True
        self.applied.append(action)
        self.begin_apply()
        if announce:
            self.info(f"APPLY: {action}")
        else:
            self.to_log(f"[INFO]  APPLY: {action}")
        return True

    def begin_apply(self) -> None:
        """Run bookkeeping started by the first authorized change; check mode never reaches it."""
        if self.began or self.opt["recover"]:
            return
        self.began = True
        os.makedirs(host_path(STATE_DIR), exist_ok=True)
        for path in (STATE_FILE, MANAGED_FILES_FILE):
            host_path(path).touch()
            os.chmod(host_path(path), 0o600)
        self.write_run_info()
        self.write_public_status(0)
        self.trap_installed = True
        self.install_deferred_service_policy()
        if self.mgmt:
            self.prepare_apps_dir()

    def prepare_apps_dir(self) -> None:
        partial = self.apps_dir / "partial"
        os.makedirs(partial, exist_ok=True)
        os.chmod(self.apps_dir, 0o755)
        if user_exists("_apt"):
            chown(partial, "_apt", "root")
            os.chmod(partial, 0o700)
        else:
            os.chmod(partial, 0o755)

    # ------------------------------------------------------------- run
    def run_setup(self) -> int:
        """0: already in the wanted state (or changes applied); EXIT_PENDING: check mode found changes."""
        opt = self.opt
        if (self.mgmt or opt["recover"]) and not os.path.isfile(SCRIPT_PATH):
            print(f"ERROR: this operation requires executing {ENTRY} from its governed file.", file=sys.stderr)
            raise SetupExit(1)
        if self.mgmt:
            if not canonical_single_link_executable(self.control_auth_source):
                print(f"ERROR: --mgmt requires canonical sibling tools/control-auth.py: {self.control_auth_source}",
                      file=sys.stderr)
                raise SetupExit(1)
            if sha256_file(self.control_auth_source) != CONTROL_AUTH_SOURCE_SHA256:
                print(f"ERROR: Control auth helper source hash mismatch: {self.control_auth_source}", file=sys.stderr)
                raise SetupExit(1)
        if not is_root():
            print(f"ERROR: {ENTRY} must be run as root.", file=sys.stderr)
            raise SetupExit(1)
        self.acquire_host_lock()
        self.open_log()
        if opt["recover"]:
            self.to_log(self.mode_line())
            return self.recover_monitor_authority()

        self.logecho(self.mode_line())
        self.detect_platform()
        self.resolve_inputs()
        self.doca_package = f"doca-host_{DOCA_RELEASE}-ubuntu{self.ubuntu_tag}_{self.arch}.deb"
        self.doca_package_version = f"{DOCA_RELEASE}-ubuntu{self.ubuntu_tag}"
        self.doca_path = f"https://www.mellanox.com/downloads/DOCA/DOCA_v3.3.0/host/{self.doca_package}"

        self.preflight()
        self.step_dns()
        self.step_ntp()
        self.step_timezone()
        self.step_lldpd()
        self.step_doca()
        self.step_common_tools()
        self.step_ztp_and_services()
        if self.mgmt:
            if self.http_server and self.http_file_exists(f"{self.http_server}/Packages.gz"):
                self.local_http_enabled = True
                self.success(f"Published APT repository verified: {self.http_server}/Packages.gz")
            else:
                self.local_http_enabled = False
                self.warn(f"APT files are expected in {self.apps_dir}, but "
                          f"{self.http_server or '<unset>'}/Packages.gz is not reachable.")
        self.step_record()
        self.summary()
        self.power_cycle_reminder()
        if self.began:
            self.mark_run_complete()
            self.setup_status = "completed"
        self.to_log(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {ENTRY} finished")
        return self.finish()

    def finish(self) -> int:
        self.logecho("")
        self.logecho(self.mode_line())
        if not self.apply:
            if self.pending:
                self.logecho(f"结果: 需要 {len(self.pending)} 项改动（检查模式未改动；核对上面的 WOULD APPLY 后"
                             "加 --apply 重跑）；日志 " + self.log_file)
                return EXIT_PENDING
            self.success(f"检查完成：主机已处于期望状态，无需改动；日志 {self.log_file}")
            return 0
        if self.applied:
            self.success(f"{ENTRY} completed successfully: {len(self.applied)} change(s) applied; "
                         f"log {self.log_file}")
        else:
            self.success(f"{ENTRY} completed successfully: already in the desired state, nothing changed; "
                         f"log {self.log_file}")
        return 0

    def detect_platform(self) -> None:
        os_release = host_path("/etc/os-release")
        if not os_release.is_file():
            print("ERROR: Cannot determine OS. Aborting.", file=sys.stderr)
            self.to_log("ERROR: Cannot determine OS. Aborting.")
            raise SetupExit(1)
        fields = parse_os_release(os_release.read_text(encoding="utf-8", errors="replace"))
        self.version_id = fields.get("VERSION_ID", "")
        self.pretty_name = fields.get("PRETTY_NAME", "")
        if fields.get("ID") != "ubuntu" or self.version_id not in ("22.04", "24.04"):
            print(f"ERROR: This script requires Ubuntu 22.04 or 24.04. Detected: {self.pretty_name or 'unknown'}",
                  file=sys.stderr)
            self.to_log(f"ERROR: Unsupported OS: {self.pretty_name or 'unknown'}")
            raise SetupExit(1)
        machine = self.output_of(["uname", "-m"])
        self.arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(machine, "")
        if not self.arch:
            print(f"ERROR: Unsupported architecture: {machine}", file=sys.stderr)
            raise SetupExit(1)
        self.ubuntu_tag = self.version_id.replace(".", "")
        self.repo_relative_path = f"ubuntu-{self.version_id}/{self.arch}"
        if self.mgmt:
            self.apps_dir = self.apps_root / self.repo_relative_path

    def preflight(self) -> None:
        self.print_section("Preflight Checks")
        self.success(f"OS check passed: {self.pretty_name} ({self.arch})")
        self.info(f"APT repository scope: {self.repo_relative_path}")
        self.info(f"DNS/NTP/timezone input: {self.input_note}")
        for label in getattr(self, "runtime_mismatch", []):
            self.warn(f"infra-runtime.conf {label} differs from 01-global.yaml; using 01-global.yaml.")
        self.ensure_local_hostname_resolution()
        if self.mgmt:
            try:
                mode = format(stat.S_IMODE(os.stat(self.mgmt_http_root).st_mode), "o")
            except OSError:
                mode = ""
            if mode != "755":
                self.warn(f"HTTP document root {self.mgmt_http_root} has mode {mode or 'unknown'}; Apache needs 0755.")
                if self.change(f"chmod 0755 {self.mgmt_http_root} (HTTP document root traversal)"):
                    os.chmod(self.mgmt_http_root, 0o755)
                    self.success("HTTP document root permissions set to 0755.")
            else:
                self.success("HTTP document root permissions already allow Apache traversal.")
            if self.offline:
                packages = self.apps_dir / "Packages.gz"
                if packages.is_file() and packages.stat().st_size > 0:
                    self.success(f"Packaged offline APT repository found: {packages}")
                else:
                    self.fail(f"Packaged offline APT repository is missing: {packages}")
            elif self.http_server and self.http_file_exists(f"{self.http_server}/Packages.gz"):
                self.success(f"Existing local APT repository is reachable: {self.http_server}/Packages.gz")
            else:
                self.info("Local APT repository is not published yet; management mode will build it from "
                          "configured APT sources.")
        elif self.local_http_enabled:
            if self.http_file_exists(f"{self.http_server}/Packages.gz"):
                self.success(f"Local APT repository is reachable: {self.http_server}/Packages.gz")
            else:
                self.warn("Local APT repository became unavailable; this run will use Internet downloads directly.")
                self.local_http_enabled = False
        else:
            self.info("Local HTTP download is disabled; Internet sources will be used directly.")
        self.configure_local_apt_repo()
        if self.mgmt:
            self.info(f"Management cache mode enabled; package repository directory: {self.apps_dir}")
            if self.offline:
                self.success("Offline mode: reusing the packaged repository without Internet downloads.")
                return
            action = (f"refresh APT indexes and cache the offline package closure "
                      f"({len(MGMT_CACHE_PACKAGES)} packages) into {self.apps_dir}")
            gap = "" if self.apply else self.offline_cache_gap()
            if not self.apply and not gap:
                # Complete is not pending; --apply still checks upstream and refreshes on every run.
                self.info(f"离线缓存完整：{len(dict.fromkeys(MGMT_CACHE_PACKAGES))} 个必需顶层包都在 "
                          f"{self.apps_dir}/Packages.gz（未核对依赖闭包）；--apply 时会检查上游更新并刷新。")
            elif self.change(action + (f" ({gap})" if gap else "")):
                self.apt_update_once()
                self.cache_mgmt_package_closure(*MGMT_CACHE_PACKAGES)

    def offline_cache_gap(self) -> str:
        """Read-only gap of the management offline cache; '' when every required package is present.

        Reads <apps>/Packages.gz, gunzips it in memory and parses its stanzas.  A required package (every
        MGMT_CACHE_PACKAGES name) is present only when a stanza names it and its Filename is a regular
        file inside the repository.  Only the top-level names are checked: proving the dependency closure
        from the cached metadata needs version relations, alternatives and Provides, i.e. a resolver, so
        that is left to --apply, which re-downloads the whole closure on every run.
        """
        index_path = self.apps_dir / "Packages.gz"
        if not os.path.lexists(index_path):
            return f"offline repository missing: {index_path}"
        try:
            if not index_path.is_file():
                raise OSError("not a regular file")
            index = gzip.decompress(index_path.read_bytes()).decode("utf-8")
        except (OSError, EOFError, zlib.error, UnicodeDecodeError) as exc:
            self.warn(f"Offline repository index cannot be read: {index_path}: {exc}")
            return f"offline repository unreadable: {index_path}"
        present = set()
        for stanza in re.split(r"\n[ \t]*\n", index):
            fields = {}
            for line in stanza.splitlines():
                key, separator, value = line.partition(":")
                if separator and line[:1] not in (" ", "\t"):
                    fields[key.strip()] = value.strip()
            name, filename = fields.get("Package", ""), fields.get("Filename", "")
            relative = Path(filename)
            if (name and filename and not relative.is_absolute() and ".." not in relative.parts
                    and (self.apps_dir / relative).is_file()):
                present.add(name)
        missing = [name for name in dict.fromkeys(MGMT_CACHE_PACKAGES) if name not in present]
        return "missing from the offline repository: " + " ".join(missing) if missing else ""

    # ------------------------------------ shared-module duties (ubuntu24_host)
    def ensure_local_hostname_resolution(self) -> None:
        """sudo resolves the kernel hostname; add the module's reversible loopback mapping when it does not."""
        name = self.output_of(["hostname"])
        if not name:
            self.warn("Kernel hostname is empty; skipping local hostname resolution check.")
            return
        try:
            check = host.hostname_script(name, None, check_only=True)
            script = host.hostname_script(name, None)  # rollback: managed-files
        except host.HostConfigError as exc:
            self.fail(f"Local hostname cannot be mapped through the shared host module: {exc}")
        status, facts, detail = self.run_host_script(check, "hostname resolution check")
        if status != 0:
            if detail:
                self.error(detail)
            self.fail(f"Local hostname resolution could not be checked: {name}")
        if facts.get("would_hosts") != "yes":
            self.success(f"Local hostname resolves correctly: {name}")
            return
        if not self.change(f"add the local hostname mapping for {name} to /etc/hosts (sudo resolves the kernel hostname)"):
            return
        self.track_managed_file("/etc/hosts")
        status, facts, detail = self.run_host_script(script, "hostname resolution")
        if status == 0 and facts.get("resolves") == "yes" and facts.get("after") == name:
            self.success(f"Added local hostname mapping to /etc/hosts: {name}")
            return
        if detail:
            self.error(detail)
        self.fail(f"Local hostname still cannot be resolved after updating /etc/hosts: {name}")

    def config_line_facts(self, path: str, key: str, value: str, service: str, label: str) -> dict:
        status, facts, detail = self.run_host_script(
            host.config_line_script(path, key, value, service, None, check_only=True), f"{label} check")
        if status != 0:
            if detail:
                self.error(detail)
            self.fail(f"{path} {key}= could not be checked.")
        return facts

    def step_dns(self) -> None:
        self.print_section("Step 1: DNS Configuration")
        unit = "systemd-resolved.service"
        if self.systemd_unit_is_missing(unit):
            self.warn(f"{unit} is not installed; skipping managed DNS configuration.")
            return
        desired = " ".join(self.dns_servers)
        facts = self.config_line_facts(RESOLVED_CONF, "DNS", desired, "systemd-resolved", "resolved.conf DNS")
        if facts.get("result") == "service_missing":
            self.warn(f"{unit} is not installed; skipping managed DNS configuration.")
            return
        if facts.get("would_write") != "yes":
            self.success("DNS already matches desired configuration.")
            return
        if facts.get("would_unmask") == "yes":
            # A masked resolver cannot be restarted; refuse before anything is written.
            self.fail(f"Unable to restart {unit}.")
        if not self.change(f"set DNS={desired} in {RESOLVED_CONF} and restart systemd-resolved "
                           f"(now {facts.get('before') or 'unset'})"):
            return
        self.track_managed_file(RESOLVED_CONF)
        script = host.config_line_script(RESOLVED_CONF, "DNS", desired, "systemd-resolved", None)
        status, facts, detail = self.run_host_script(script, "resolved.conf DNS")
        if status != 0:
            if detail:
                self.error(detail)
            self.fail(f"Unable to restart {unit}.")
        if facts.get("after") != desired:
            self.fail(f"DNS verification failed: {RESOLVED_CONF} has {facts.get('after')!r}, expected {desired!r}.")
        self.success("DNS configured and systemd-resolved restarted.")

    def step_ntp(self) -> None:
        self.print_section("Step 2: NTP Configuration")
        unit = "systemd-timesyncd.service"
        if self.systemd_unit_is_missing(unit):
            self.warn(f"{unit} is not installed; skipping managed NTP configuration.")
            return
        desired = " ".join(self.ntp_servers)
        facts = self.config_line_facts(TIMESYNCD_CONF, "NTP", desired, "systemd-timesyncd", "timesyncd.conf NTP")
        if facts.get("result") == "service_missing":
            self.warn(f"{unit} is not installed; skipping managed NTP configuration.")
            return
        write, unmask = facts.get("would_write") == "yes", facts.get("would_unmask") == "yes"
        if not write and not unmask:
            self.success("NTP already matches desired configuration.")
            return
        if unmask:
            self.warn(f"{unit} is masked; temporarily unmasking it for managed NTP.")
        actions = [f"set NTP={desired} in {TIMESYNCD_CONF} (now {facts.get('before') or 'unset'})"] if write else []
        actions.append("unmask, enable and start systemd-timesyncd" if unmask else "restart systemd-timesyncd")
        if not self.change("; ".join(actions)):
            return
        if unmask:
            state_file = host_path(TIMESYNCD_UNIT_STATE_FILE)
            if not state_file.is_file():
                state_file.write_text("masked\n", encoding="utf-8")
                os.chmod(state_file, 0o600)
        if write:
            self.track_managed_file(TIMESYNCD_CONF)
        script = host.config_line_script(TIMESYNCD_CONF, "NTP", desired, "systemd-timesyncd", None)
        status, facts, detail = self.run_host_script(script, "timesyncd.conf NTP")
        if status != 0:
            if detail:
                self.error(detail)
            if unmask:
                self.fail(f"Unable to enable {unit} after unmasking; check for another conflicting NTP daemon.")
            self.fail(f"Unable to restart {unit}.")
        if facts.get("after") != desired:
            self.fail(f"NTP verification failed: {TIMESYNCD_CONF} has {facts.get('after')!r}, expected {desired!r}.")
        if write:
            self.success("NTP configuration updated.")
        self.success("systemd-timesyncd unmasked, enabled and started." if unmask else "systemd-timesyncd restarted.")

    def timedatectl_usable(self) -> bool:
        return self.has("timedatectl") and self.systemd_is_operational()

    def current_timezone_name(self) -> str:
        value = ""
        if self.timedatectl_usable():
            status, facts, _detail = self.run_host_script(host.timezone_script("", check_only=True), "timezone probe")
            if status == 0:
                value = facts.get("before", "")
        zone_file = host_path("/etc/timezone")
        if not value and zone_file.is_file() and zone_file.stat().st_size > 0:
            lines = zone_file.read_text(encoding="utf-8", errors="replace").splitlines()
            value = " ".join(lines[0].split()) if lines else ""
        localtime = host_path("/etc/localtime")
        if not value and localtime.is_symlink():
            resolved = os.path.realpath(localtime)
            prefix = str(host_path(ZONEINFO)) + "/"
            value = resolved[len(prefix):] if resolved.startswith(prefix) else resolved
        return value

    def timezone_differs(self, zone: str) -> tuple:
        """(needs a change, current zone); timedatectl hosts decide through the module's check script."""
        if self.timedatectl_usable() and host_path(f"{ZONEINFO}/{zone}").is_file():
            try:
                check = host.timezone_script(zone, check_only=True)
            except host.HostConfigError as exc:
                self.fail(str(exc))
            status, facts, detail = self.run_host_script(check, "timezone check")
            if status != 0:
                if detail:
                    self.error(detail)
                self.fail(f"Timezone {zone} could not be checked.")
            return facts.get("would_timezone") == "yes", facts.get("before", "")
        current = self.current_timezone_name()
        return current != zone, current

    def apply_timezone(self, zone: str) -> None:
        if not host_path(f"{ZONEINFO}/{zone}").is_file():
            self.fail(f"Unknown timezone: {zone}")
        if self.timedatectl_usable():
            try:
                script = host.timezone_script(zone)
            except host.HostConfigError as exc:
                self.fail(str(exc))
            status, facts, detail = self.run_host_script(script, "timezone")
            if status != 0:
                if detail:
                    self.error(detail)
                self.fail(f"Unable to set timezone {zone}.")
            if facts.get("after") != zone:
                self.fail(f"Timezone verification failed: {facts.get('after')!r} != {zone!r}.")
            return
        localtime = host_path("/etc/localtime")
        if os.path.lexists(localtime) and not localtime.is_dir():
            os.unlink(localtime)
        os.symlink(str(host_path(f"{ZONEINFO}/{zone}")), localtime)
        host_path("/etc/timezone").write_text(zone + "\n", encoding="utf-8")
        self.warn("systemd/timedatectl is unavailable; timezone was applied through /etc/localtime and /etc/timezone.")

    def step_timezone(self) -> None:
        self.print_section("Step 3: Timezone & Clock Sync")
        zone = self.time_zone
        zone_data = host_path(f"{ZONEINFO}/{zone}").is_file()
        if not zone_data:
            if self.dpkg_installed("tzdata"):
                self.fail(f"tzdata is installed but timezone data is missing: {zone}")
            self.info("Timezone database is not installed.")
            if self.change(f"install tzdata (timezone data for {zone})"):
                self.install_recorded(["tzdata"])
                zone_data = True
        if zone_data:
            differs, current = self.timezone_differs(zone)
        else:
            current = self.current_timezone_name()
            differs = current != zone
        if not differs:
            self.success("Timezone already matches desired configuration.")
        elif self.change(f"set timezone {zone} (now {current or 'unknown'})"):
            state_file = host_path(TIMEZONE_STATE_FILE)
            if not state_file.is_file():
                state_file.write_text(current + "\n", encoding="utf-8")
            self.apply_timezone(zone)
            self.success("Timezone set.")
        if self.timedatectl_usable():
            self.info("Current timedatectl status:")
            for line in self.run(["timedatectl", "status"], check=False, capture=True, quiet=True).stdout.splitlines():
                self.logecho(line)
        else:
            self.info(f"Current timezone: {self.current_timezone_name()} (systemd unavailable)")

    # --------------------------------------------------- ported duties
    def write_lldpcli_conf(self) -> None:
        os.makedirs(host_path("/etc/lldpd.d"), exist_ok=True)
        self.track_managed_file(LLDPCLI_CONF)
        host_path(LLDPCLI_CONF).write_text(LLDPCLI_CONTENT, encoding="utf-8")
        self.success(f"lldpd configuration written: {LLDPCLI_CONF}")

    def step_lldpd(self) -> None:
        self.print_section("Step 4: lldpd")
        conf = host_path(LLDPCLI_CONF)
        installed = self.dpkg_installed("lldpd")
        current = conf.read_text(encoding="utf-8", errors="replace").rstrip("\n") if conf.is_file() else None
        conf_ok = current == LLDPCLI_CONTENT.rstrip("\n")
        if installed:
            self.success("lldpd is already installed.")
            if conf_ok:
                self.success(f"{LLDPCLI_CONF} already matches desired configuration.")
                return
            self.info(f"{LLDPCLI_CONF} differs from desired configuration.")
            action = f"write {LLDPCLI_CONF} and restart lldpd"
        else:
            self.info("lldpd not found.")
            action = f"install lldpd, write {LLDPCLI_CONF} and restart lldpd"
        if not self.change(action):
            return
        if not installed:
            self.install_recorded(["lldpd"])
        self.write_lldpcli_conf()
        self.restart_systemd_service("lldpd")
        self.success("lldpd installed and configuration applied." if not installed else "lldpd configuration applied.")

    def step_doca(self) -> None:
        self.print_section("Step 5: Mellanox NIC & DOCA-OFED")
        lspci = self.output_of(["lspci"])
        has_mellanox = "mellanox" in lspci.casefold()
        process_doca = has_mellanox
        if self.opt["skip_doca"]:
            process_doca = False
            self.warn("DOCA handling explicitly skipped by --skip-doca.")
        elif not has_mellanox:
            if self.mgmt:
                if self.offline:
                    self.warn("No Mellanox NIC detected; offline mode will not attempt a DOCA download/cache.")
                    process_doca = False
                else:
                    mode = self.modes["doca"]
                    if mode == "ask" and (self.non_interactive or not stdin_is_tty()):
                        mode = "yes"
                        self.info("No interactive terminal; applying the default DOCA cache action.")
                    if self.confirm_action(mode, "No Mellanox NIC detected. Download and cache DOCA packages for "
                                           "offline clients?", DOCA_PROMPT_TIMEOUT, "yes"):
                        process_doca = True
                        self.info("DOCA download/cache enabled without a local Mellanox NIC.")
                    else:
                        self.warn("No Mellanox NIC detected; skipping DOCA download and cache.")
            else:
                self.warn("No Mellanox NIC detected, skipping DOCA-OFED installation.")
        self.bluefield_mode_changed = False
        self.changed_mst_devices = []
        if not process_doca:
            return
        if not self.has("wget"):
            self.info("DOCA cache/install requires wget.")
            if self.change("install wget (DOCA download tool)"):
                self.install_recorded(["wget"])
                self.success("wget installed.")
        preexisting = self.doca_host_installed()
        doca_tmp = (self.apps_dir if self.mgmt else host_path("/tmp")) / self.doca_package
        package_ok = doca_tmp.is_file() and self.doca_metadata_matches(doca_tmp)
        if package_ok:
            self.success(f"Verified DOCA host package present: {canonical(doca_tmp)}")
        elif self.offline:
            self.fail(f"Offline mode requires a verified packaged DOCA host file: {canonical(doca_tmp)}")
        if preexisting and package_ok:
            self.success("doca-host is already installed.")
        else:
            actions = [] if package_ok else [f"download {self.doca_package}"]
            actions += [] if preexisting else ["install doca-host"]
            if self.change(" and ".join(actions or ["install doca-host"])):
                self.ensure_doca_host_package(doca_tmp)
                if not preexisting:
                    self.begin_package_install("doca-host")
                if self.apt_get("install", "-y", str(doca_tmp)) == 0:
                    self.refresh_mgmt_repository()
                else:
                    self.warn("doca-host installation command failed; checking package state before aborting")
                if not self.doca_host_installed():
                    self.fail("doca-host installation could not be verified.")
                if not preexisting:
                    self.commit_package_install("doca-host")
        if self.mgmt:
            if self.offline:
                self.success("Offline mode: using the packaged DOCA closure without new downloads.")
            elif self.change("refresh APT indexes with the embedded DOCA repository and cache the doca-ofed "
                             f"closure into {self.apps_dir}"):
                self.enable_embedded_doca_repo()
                self.apt_updated = False
                self.apt_update_once()
                self.cache_mgmt_package_closure("doca-ofed")
        if not has_mellanox:
            self.success("No local Mellanox NIC: the DOCA-OFED closure is cached for Mellanox-equipped offline "
                         "clients and doca-ofed is not installed on this management host.")
        elif self.dpkg_installed("doca-ofed"):
            self.success("doca-ofed is already installed.")
        else:
            self.info("Mellanox NIC detected; DOCA-OFED is not installed.")
            if self.change("install doca-ofed"):
                self.enable_embedded_doca_repo()
                self.install_recorded(["doca-ofed"])
                self.success("doca-ofed installed.")
        if not self.mgmt and self.began and os.path.lexists(doca_tmp):
            os.unlink(doca_tmp)
        self.bluefield_mode_check()

    def doca_host_installed(self) -> bool:
        return self.output_of(["dpkg-query", "-W", "-f=${db:Status-Status}", "doca-host"]) == "installed"

    def bluefield_mode_check(self) -> None:
        devices = [line.split()[0] for line in self.output_of(["lspci"]).splitlines()
                   if re.search("MT43244 BlueField", line, re.IGNORECASE)
                   and re.search(r"[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.0", line) and line.split()]
        if not devices:
            self.info("No BlueField-3 device detected, skipping mode check.")
            return
        if not self.has("mst"):
            self.warn("mst tool not found, skipping Bluefield mode check.")
            return
        self.info(f"Found {len(devices)} BlueField-3 device(s): {' '.join(devices)}")
        if self.apply:
            self.run(["mst", "start"], check=False, quiet=True)
        else:
            self.info("Check mode does not run `mst start`; devices without an mst node are queried by PCI address.")
        status_lines = self.output_of(["mst", "status"]).splitlines()
        for pci in devices:
            self.info(f"── Processing BF3 at PCI {pci} ──")
            context = []
            for index, line in enumerate(status_lines):
                if grep_matches(pci, line):
                    context.extend(range(max(0, index - 1), min(len(status_lines), index + 2)))
            device = ""
            for index in sorted(set(context)):
                match = re.search(r"/dev/mst/mt[0-9a-zA-Z_]+", status_lines[index])
                if match:
                    device = match.group(0)
                    break
            target = device or ("" if self.apply else pci)
            if not target:
                self.warn(f"No mst device found for PCI {pci}, skipping.")
                continue
            self.info(f"Using mst device: {target}")
            query = self.output_of(["mlxconfig", "-d", target, "q"])
            offload = "\n".join(line.split()[-1] for line in query.splitlines()
                                if "internal_cpu_offload_engine" in line.casefold() and line.split())
            self.info(f"INTERNAL_CPU_OFFLOAD_ENGINE = {offload or 'unknown'}")
            if offload.upper() == "ENABLED(0)":
                self.warn(f"BF3 [{pci}] is in DPU mode (INTERNAL_CPU_OFFLOAD_ENGINE=ENABLED(0)).")
                if not self.confirm_action(self.modes["bluefield"], f"Change BF3 [{pci}] from DPU to NIC mode?",
                                           PROMPT_TIMEOUT, "yes"):
                    self.info(f"Skipping BF3 [{pci}] mode change.")
                elif self.change(f"set BF3 [{pci}] to NIC mode (mlxconfig -d {target} set "
                                 "INTERNAL_CPU_OFFLOAD_ENGINE=1; takes effect after a power cycle)"):
                    self.run(["mlxconfig", "-d", target, "-y", "set", "INTERNAL_CPU_OFFLOAD_ENGINE=1"], to_log=True)
                    self.success(f"BF3 [{pci}] mode set to NIC (INTERNAL_CPU_OFFLOAD_ENGINE=DISABLED(1)).")
                    self.success("Power cycle required to take effect.")
                    self.bluefield_mode_changed = True
                    self.changed_mst_devices.append(target)
            elif offload.upper() == "DISABLED(1)":
                self.success(f"BF3 [{pci}] is already in NIC mode (INTERNAL_CPU_OFFLOAD_ENGINE=DISABLED(1)), "
                             "no change needed.")
            else:
                self.warn(f"BF3 [{pci}] mode undetermined (value: {offload or 'unknown'}), skipping.")

    def install_missing(self, packages: tuple, label: str, done_label: str) -> bool:
        """Install and record the packages dpkg does not know; True when none were missing."""
        missing = []
        for package in packages:
            if self.dpkg_installed(package):
                self.success(f"{package} is already installed.")
            else:
                missing.append(package)
        if missing:
            self.info(f"{label}: {' '.join(missing)}")
            if self.change(f"install {' '.join(missing)}"):
                self.install_recorded(missing)
                self.success(f"{done_label}: {' '.join(missing)}")
        return not missing

    def step_common_tools(self) -> None:
        self.print_section("Step 6: Common Tools")
        self.install_missing(COMMON_PACKAGES, "Missing", "Packages installed")

    def step_ztp_and_services(self) -> None:
        self.print_section("Step 7: ZTP Dependencies & Optional Services")
        if self.mgmt:
            if self.install_missing(ZTP_DEPENDENCY_PACKAGES, "Missing ZTP dependencies",
                                    "ZTP dependencies installed"):
                self.success("All ZTP dependencies are already installed.")
        else:
            self.info("Client mode: ZTP generation and analysis dependencies are not required; skipping.")
        if self.dpkg_installed("apache2"):
            self.success("apache2 is already installed.")
            configure = self.confirm_action(self.modes["apache"], "Configure existing apache2?", PROMPT_TIMEOUT)
            if not configure:
                self.info("Skipping apache2 configuration.")
        else:
            configure = self.confirm_action(self.modes["apache"], "Install and configure apache2?", PROMPT_TIMEOUT)
            if not configure:
                self.info("Skipping apache2 installation.")
        if configure:
            self.configure_apache()
        self.configure_dhcp()

    def monitor_authority_attests(self, helper: Path) -> bool:
        """Read-only attestation of an installed, pinned helper; recovery states stop the run."""
        decision = capture_decision(helper, "monitor-authority-attest-decision", host_path("/run"))
        if decision in ("recovery-in-progress", "recovery-committed-cleanup-pending"):
            self.monitor_authority_decision = decision
            self.explain_recovery_state(decision)
            raise SetupExit(1)
        return decision == "attest-valid"

    def apache_pending(self) -> list:
        """Read-only list of what the authenticated Monitor Apache configuration still needs."""
        pending = []
        missing = [package for package in APACHE_PACKAGES if not self.dpkg_installed(package)]
        if missing:
            pending.append(f"install {' '.join(missing)}")
        helper = host_path(CONTROL_AUTH_HELPER)
        if (helper.parent.is_symlink() or not canonical_single_link_executable(helper)
                or sha256_file(helper) != CONTROL_AUTH_SOURCE_SHA256):
            pending.append(f"install {CONTROL_AUTH_HELPER} and provision the Monitor cache authority and credentials")
        else:
            if not self.monitor_authority_attests(helper):
                pending.append("provision the Monitor cache authority")
            status = self.run([helper, "status"], check=False, capture=True, quiet=True)
            try:
                valid = json.loads(status.stdout or "{}").get("valid") is True
            except ValueError:
                valid = False
            if not valid:
                pending.append("initialize the Monitor control credentials (control-auth ensure)")
        servername = host_path(APACHE_SERVERNAME_CONF)
        wanted = f"ServerName {self.hostname_fqdn()}\n"
        current = servername.read_text(encoding="utf-8", errors="replace") if servername.is_file() else None
        if current != wanted:
            pending.append(f"write {APACHE_SERVERNAME_CONF}")
        if not os.path.lexists(host_path("/etc/apache2/conf-enabled/servername.conf")):
            pending.append("a2enconf servername")
        modules = [module for module in APACHE_AUTH_MODULES
                   if not os.path.lexists(host_path(f"/etc/apache2/mods-enabled/{module}.load"))]
        if modules:
            pending.append(f"a2enmod {' '.join(modules)}")
        ports = host_path(APACHE_PORTS_CONF)
        if not ports.is_file() or ports.read_text(encoding="utf-8", errors="replace") != APACHE_PORTS_CONTENT:
            pending.append(f"replace {APACHE_PORTS_CONF} (no wildcard Listen; load publishes exact listeners)")
        default_site = host_path(APACHE_DEFAULT_SITE)
        if default_site.is_symlink():
            pending.append("disable the 000-default site")
        elif os.path.lexists(default_site):
            self.fail("Unsafe non-symlink Apache default-site authority.")
        listener = host_path(APACHE_LISTENER_CONF)
        if listener.is_symlink() or (os.path.lexists(listener) and not listener.is_file()):
            self.fail(f"Unsafe Apache exact-listener authority: {APACHE_LISTENER_CONF}")
        if os.path.lexists(listener):
            pending.append(f"remove {APACHE_LISTENER_CONF}")
        boundary = host_path(APACHE_PUBLIC_BOUNDARY_CONF)
        if (not boundary.is_file()
                or boundary.read_text(encoding="utf-8", errors="replace") != APACHE_PUBLIC_BOUNDARY):
            pending.append(f"install the authenticated publication boundary {APACHE_PUBLIC_BOUNDARY_CONF}")
        return pending

    def configure_apache(self) -> None:
        if not self.mgmt:
            self.fail("Authenticated Monitor Apache configuration requires --mgmt and its canonical "
                      "control-auth helper.")
        pending = self.apache_pending()
        if not pending:
            self.success("apache2 already carries the authenticated Monitor boundary and exact-listener layout.")
            return
        if not self.change("configure apache2: " + "; ".join(pending)):
            return
        missing = [package for package in APACHE_PACKAGES if not self.dpkg_installed(package)]
        if missing:
            self.install_recorded(missing)
        for package in APACHE_PACKAGES:
            if not self.dpkg_installed(package):
                self.fail(f"Required Apache package is unavailable after installation: {package}")
        self.info("Configuring apache2...")
        if self.systemd_is_operational() and self.succeeds(["systemctl", "is-active", "--quiet", "apache2"]):
            self.run(["systemctl", "stop", "apache2"])
            self.warn("Stopped Apache before replacing its authenticated Monitor boundary.")
        self.install_control_auth_helper()
        self.track_managed_file(APACHE_SERVERNAME_CONF)
        servername = host_path(APACHE_SERVERNAME_CONF)
        os.makedirs(servername.parent, exist_ok=True)
        servername.write_text(f"ServerName {self.hostname_fqdn()}\n", encoding="utf-8")
        self.run(["a2enconf", "servername"], to_log=True)
        for module in APACHE_AUTH_MODULES:
            self.run(["a2enmod", module], to_log=True)
        # Native Apache has no authority until load publishes exact service-IPv4 listeners.
        self.track_managed_file(APACHE_PORTS_CONF)
        ports = host_path(APACHE_PORTS_CONF)
        descriptor, candidate = tempfile.mkstemp(prefix=f"{ports.name}.tmp.", dir=str(ports.parent))
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(APACHE_PORTS_CONTENT)
        os.chmod(candidate, 0o644)
        chown(candidate, "root", "root")
        os.replace(candidate, ports)
        default_site = host_path(APACHE_DEFAULT_SITE)
        site_state = host_path(APACHE_DEFAULT_SITE_STATE)
        if default_site.is_symlink():
            site_state.write_text("enabled\n", encoding="utf-8")
        elif not default_site.exists():
            site_state.write_text("disabled\n", encoding="utf-8")
        else:
            self.fail("Unsafe non-symlink Apache default-site authority.")
        os.chmod(site_state, 0o600)
        self.run(["a2dissite", "000-default"], check=False, to_log=True)
        listener = host_path(APACHE_LISTENER_CONF)
        if listener.is_symlink() or (os.path.lexists(listener) and not listener.is_file()):
            self.fail(f"Unsafe Apache exact-listener authority: {APACHE_LISTENER_CONF}")
        self.track_managed_file(APACHE_LISTENER_CONF)
        if os.path.lexists(listener):
            os.unlink(listener)
        self.install_apache_publication_boundary()
        self.run(["apache2ctl", "configtest"], to_log=True)
        self.success("apache2 wildcard listeners disabled; service activation deferred until load publishes "
                     "exact listeners.")

    def install_control_auth_helper(self) -> None:
        helper = host_path(CONTROL_AUTH_HELPER)
        helper_dir = helper.parent
        if helper_dir.is_symlink() or (os.path.lexists(helper_dir) and not helper_dir.is_dir()):
            self.fail(f"Unsafe control auth helper directory: {canonical(helper_dir)}")
        os.makedirs(helper_dir, exist_ok=True)
        os.chmod(helper_dir, 0o755)
        chown(helper_dir, "root", "root")
        if helper_dir.is_symlink():
            self.fail(f"Control auth helper directory became a symbolic link: {canonical(helper_dir)}")
        descriptor, candidate = tempfile.mkstemp(prefix=f"{helper.name}.tmp.", dir=str(helper_dir))
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(self.control_auth_source.read_bytes())
        os.chmod(candidate, 0o755)
        chown(candidate, "root", "root")
        if sha256_file(candidate) != CONTROL_AUTH_SOURCE_SHA256:
            os.unlink(candidate)
            self.fail("Installed control auth helper candidate hash mismatch.")
        os.replace(candidate, helper)
        if sha256_file(helper) != CONTROL_AUTH_SOURCE_SHA256:
            self.fail("Installed control auth helper hash mismatch.")
        # Create only a missing factory file, then validate the complete persistent state before
        # publishing any Apache policy which references it.
        for operation in ("monitor-authority-provision", "monitor-authority-attest"):
            if not self.run_native_monitor_authority_routine(operation):
                raise SetupExit(1)
        self.run([helper, "ensure"])
        self.run([helper, "validate"])
        status_json = self.run([helper, "status"], capture=True).stdout.rstrip("\n")
        self.info(f"Monitor control auth status: {status_json}")
        self.success("Monitor control auth helper and credential state validated.")

    def install_apache_publication_boundary(self) -> None:
        destination = host_path(APACHE_PUBLIC_BOUNDARY_CONF)
        self.track_managed_file(APACHE_PUBLIC_BOUNDARY_CONF)
        descriptor, candidate = tempfile.mkstemp(prefix=f"{destination.name}.tmp.", dir=str(destination.parent))
        os.close(descriptor)
        descriptor, rollback = tempfile.mkstemp(prefix=f"{destination.name}.rollback.", dir=str(destination.parent))
        os.close(descriptor)
        existed = destination.is_file()
        if existed:
            copy_preserving(destination, Path(rollback))
        with open(candidate, "w", encoding="utf-8") as handle:
            handle.write(APACHE_PUBLIC_BOUNDARY)
        os.chmod(candidate, 0o644)
        chown(candidate, "root", "root")
        os.replace(candidate, destination)
        if self.run(["apache2ctl", "configtest"], check=False, to_log=True).returncode != 0:
            if existed:
                copy_preserving(Path(rollback), destination)
            elif os.path.lexists(destination):
                os.unlink(destination)
            os.unlink(rollback)
            if self.systemd_is_operational():
                self.run(["systemctl", "stop", "apache2"], check=False)
            self.fail("Apache publication boundary failed configtest; previous configuration restored and "
                      "Apache remains stopped.")
        os.unlink(rollback)
        self.success("Apache static publication boundary installed and configtest passed.")

    def stop_disable_dhcp(self) -> None:
        self.info("Stopping isc-dhcp-server (disabled by default)...")
        if self.systemd_is_operational():
            self.run(["systemctl", "stop", "isc-dhcp-server"], check=False)
            self.run(["systemctl", "disable", "isc-dhcp-server"], check=False)
        else:
            self.warn("systemd is not running; isc-dhcp-server stop/disable was skipped.")
        self.success("isc-dhcp-server stopped and disabled.")

    def configure_dhcp(self) -> None:
        if self.dpkg_installed("isc-dhcp-server"):
            self.success("isc-dhcp-server is already installed.")
            if not self.confirm_action(self.modes["dhcp"],
                                       "Configure existing isc-dhcp-server (stop and disable service)?",
                                       PROMPT_TIMEOUT):
                self.info("Skipping isc-dhcp-server configuration.")
                return
            if not self.systemd_is_operational():
                self.warn("systemd is not running; isc-dhcp-server stop/disable was skipped.")
                return
            active = self.succeeds(["systemctl", "is-active", "--quiet", "isc-dhcp-server"])
            enabled = self.output_of(["systemctl", "is-enabled", "isc-dhcp-server"]) == "enabled"
            if not active and not enabled:
                self.success("isc-dhcp-server is already stopped and disabled.")
            elif self.change("stop and disable isc-dhcp-server (load starts it only after commit)"):
                self.stop_disable_dhcp()
            return
        if self.confirm_action(self.modes["dhcp"], "Install isc-dhcp-server?", PROMPT_TIMEOUT):
            if self.change("install isc-dhcp-server, then stop and disable it"):
                self.info("Installing isc-dhcp-server...")
                self.install_recorded(["isc-dhcp-server"])
                self.stop_disable_dhcp()
        else:
            self.info("Skipping isc-dhcp-server installation.")

    def step_record(self) -> None:
        """The run state check_infra.py reads (run-info, infra-status) is part of the desired state."""
        if self.began:
            return
        wanted = {"status": "completed", "http_server": self.http_server,
                  "local_http_enabled": str(self.local_http_enabled).lower(), "mgmt_mode": str(self.mgmt).lower(),
                  "expected_dns": " ".join(self.dns_servers), "expected_ntp": " ".join(self.ntp_servers),
                  "expected_timezone": self.time_zone}
        stale = []
        for path, label, expected in ((host_path(RUN_INFO_FILE), RUN_INFO_FILE, wanted),
                                      (self.public_status_file, canonical(self.public_status_file),
                                       {"status": "completed", "last_action": "setup"})):
            try:
                current = dict(line.split("=", 1) for line in path.read_text(encoding="utf-8").splitlines()
                               if "=" in line)
            except OSError:
                current = {}
            fields = [key for key, value in expected.items() if current.get(key) != value]
            if fields:
                stale.append(f"{label} ({', '.join(fields)})")
        if not stale:
            self.success("Run state already records the desired configuration.")
            return
        self.change("record the run state: " + "; ".join(stale))

    def summary(self) -> None:
        self.print_section("SUMMARY")
        self.logecho("")
        self.logecho("── Installed packages ──────────────────────────────────")
        for package in MGMT_CACHE_PACKAGES + ("doca-host", "doca-ofed"):
            if self.dpkg_installed(package):
                self.logecho(f"  [+] {package}")
        self.logecho("")
        self.logecho("── Modified / created files ────────────────────────────")
        for file in SUMMARY_FILES:
            if host_path(file).is_file():
                self.logecho(f"  [*] {file}")
                for backup in sorted(glob.glob(f"{glob.escape(str(host_path(file)))}.http-infra.bak.*")):
                    if os.path.isfile(backup):
                        self.logecho(f"       backup: {canonical(backup)}")
        self.logecho("")
        self.logecho("── System settings ─────────────────────────────────────")
        self.logecho(f"  Timezone : {self.current_timezone_name()}")
        self.logecho(f"  DNS      : {current_config_value(host_path(RESOLVED_CONF), 'DNS') or 'not set'}")
        self.logecho(f"  NTP      : {current_config_value(host_path(TIMESYNCD_CONF), 'NTP') or 'not set'}")
        self.logecho(f"  Local APT: {str(self.local_http_enabled).lower()} ({self.http_server or 'not configured'})")
        self.logecho(f"  Log file : {self.log_file}")
        self.logecho("")
        title, items = (("── Changes applied ─────────────────────────────────────", self.applied) if self.apply
                        else ("── WOULD APPLY (check mode; nothing was changed) ───────", self.pending))
        self.logecho(title)
        for item in items:
            self.logecho(f"  - {item}")
        if not items:
            self.logecho("  (none)")
        self.logecho("")

    def power_cycle_reminder(self) -> None:
        if not self.bluefield_mode_changed:
            return
        self.logecho("")
        self.logecho("╔══════════════════════════════════════════════════════╗")
        self.logecho("║           ⚠  POWER CYCLE REQUIRED  ⚠               ║")
        self.logecho("╚══════════════════════════════════════════════════════╝")
        self.warn("Bluefield mode was changed to NIC. The change takes effect only after")
        self.warn("a full server power cycle (not just reboot).")
        self.logecho("")

        def verify_hint() -> None:
            self.info("To verify Bluefield mode after next boot:")
            self.logecho("  mst start && mst status")
            for device in self.changed_mst_devices:
                self.logecho(f"  mlxconfig -d {device} q | grep INTERNAL_CPU_OFFLOAD_ENGINE")
            self.logecho("  ENABLED(0) = DPU mode, DISABLED(1) = NIC mode")
            self.logecho("")

        if (self.confirm_action(self.modes["power_cycle"], "Perform power cycle now?", PROMPT_TIMEOUT, "yes")
                and self.change("power cycle this server (ipmitool chassis power cycle)")):
            self.success("Power cycle command will be executed.")
            verify_hint()
            self.run(["ipmitool", "chassis", "power", "cycle"])
        else:
            self.warn("Power cycle skipped. Run the following command manually when ready:")
            self.logecho("")
            self.logecho("  ipmitool chassis power cycle")
            self.logecho("")
            verify_hint()


# ------------------------------------------------------------------ helpers

def stdin_is_tty() -> bool:
    try:
        return sys.stdin is not None and sys.stdin.isatty()
    except (AttributeError, ValueError):
        return False


def grep_matches(pattern: str, line: str) -> bool:
    """`grep PATTERN` (basic regex) for the PCI addresses lspci prints."""
    try:
        return re.search(pattern, line) is not None
    except re.error:
        return pattern in line


def parse_os_release(text: str) -> dict:
    fields = {}
    for line in text.splitlines():
        match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line.strip())
        if not match:
            continue
        try:
            fields[match.group(1)] = "".join(shlex.split(match.group(2)))
        except ValueError:
            fields[match.group(1)] = match.group(2)
    return fields


def copy_preserving(source: Path, destination: Path) -> None:
    """cp -p: content, mode, timestamps and (when permitted) ownership."""
    shutil.copy2(source, destination)
    info = os.stat(source)
    try:
        os.chown(destination, info.st_uid, info.st_gid)
    except PermissionError:
        pass


def write_atomic_bytes(path: Path, data: bytes, mode: int, prefix: str) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=prefix, dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except BaseException:
        if os.path.lexists(temporary):
            os.unlink(temporary)
        raise


class BoundedReader:
    """Read two pipes concurrently, keeping at most `limit` bytes of each (later bytes are dropped)."""

    def __init__(self, streams: tuple, limit: int):
        self.order = [stream.fileno() for stream in streams]
        self.buffers = {descriptor: bytearray() for descriptor in self.order}
        self.open = set(self.order)
        self.limit = limit

    def pump(self, timeout: float) -> None:
        ready, _, _ = select.select(sorted(self.open), [], [], max(0.0, timeout))
        for descriptor in ready:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                self.open.discard(descriptor)
                continue
            buffer = self.buffers[descriptor]
            buffer.extend(chunk[: max(0, self.limit - len(buffer))])

    def drain(self, deadline: float) -> None:
        while self.open and time.monotonic() < deadline:
            self.pump(deadline - time.monotonic())

    @property
    def complete(self) -> bool:
        return not self.open

    def data(self) -> tuple:
        return tuple(bytes(self.buffers[descriptor]) for descriptor in self.order)


def kill_process_group(pgid: int) -> bool:
    """SIGKILL a process group; True when it still had a member."""
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def terminate_descriptor_holders(holder_path: str, identities: set) -> bool:
    """Kill every other process holding the holder file or a decision pipe; False when one existed.

    Linux identifies holders through /proc; without /proc nothing can be identified here and only
    the read deadline bounds an escaped holder.
    """
    if not os.path.isdir("/proc/self/fd"):
        return True
    clean = True
    for _attempt in range(8):
        found = False
        for descriptor in glob.glob("/proc/[0-9]*/fd/[0-9]*"):
            pid = int(descriptor.split("/")[2])
            if pid == os.getpid():
                continue
            try:
                info = os.stat(descriptor)
            except OSError:
                continue
            if (info.st_dev, info.st_ino) in identities:
                found, clean = True, False
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
        if not found:
            break
    return clean


def capture_decision(helper: object, operation: str, result_parent: Path) -> str:
    """Run `helper operation`; return its exact structured token, or "" when anything is off.

    The helper runs in its own process group with a private holder file inherited by every
    descendant.  Within MONITOR_DECISION_TIMEOUT it must exit 0 with an exact token on stdout and
    nothing on stderr (each stream read to at most MONITOR_DECISION_LIMIT bytes).  Afterwards no
    member of its group and no escaped descendant may still hold the holder file or either pipe:
    such holders are killed and the decision is rejected, and the deadline bounds the reads even
    when a holder cannot be killed.
    """
    deadline = time.monotonic() + MONITOR_DECISION_TIMEOUT
    try:
        result_dir = tempfile.mkdtemp(prefix="http-ztp-monitor-decision.", dir=str(result_parent))
    except OSError:
        return ""
    holder_path = os.path.join(result_dir, "holder")
    process = reader = None
    healthy, returncode = True, None
    try:
        with open(holder_path, "w"):
            pass
        holder_fd = os.open(holder_path, os.O_RDONLY)
        try:
            process = subprocess.Popen([str(helper), operation], stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       pass_fds=(holder_fd,), start_new_session=True)
        except OSError:
            return ""
        finally:
            os.close(holder_fd)
        identities = {(info.st_dev, info.st_ino) for info in (
            os.fstat(process.stdout.fileno()), os.fstat(process.stderr.fileno()), os.stat(holder_path))}
        reader = BoundedReader((process.stdout, process.stderr), MONITOR_DECISION_LIMIT)
        while process.poll() is None and time.monotonic() < deadline:
            step = min(0.05, max(0.0, deadline - time.monotonic()))
            if reader.open:
                reader.pump(step)
            else:
                try:
                    process.wait(timeout=step)
                except subprocess.TimeoutExpired:
                    pass
        if process.poll() is None:
            healthy = False
            kill_process_group(process.pid)
        returncode = process.wait()
        if kill_process_group(process.pid):
            healthy = False  # a member was left in the command's own process group
        if not terminate_descriptor_holders(holder_path, identities):
            healthy = False  # an escaped descendant still held the holder file or a pipe
        reader.drain(deadline)
        if not reader.complete:
            healthy = False
            terminate_descriptor_holders(holder_path, identities)
    finally:
        if process is not None:
            for stream in (process.stdout, process.stderr):
                stream.close()
        try:
            for name in os.listdir(result_dir):
                os.unlink(os.path.join(result_dir, name))
            os.rmdir(result_dir)
        except OSError:
            healthy = False
    stdout, stderr = reader.data() if reader is not None else (b"", b"")
    if healthy and returncode == 0 and not stderr:
        for token in MONITOR_DECISION_TOKENS:
            if stdout == token.encode("ascii"):
                return token
    return ""


def main(argv: list | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        options = parse_arguments(argv)
    except SetupExit as exc:
        return exc.code
    if options["apply"] and not options["yes"] and (options["non_interactive"] or not stdin_is_tty()):
        print("ERROR: --apply 需要在交互终端确认第一次改动；非交互运行请同时加 --yes", file=sys.stderr)
        return 1
    setup = InfraSetup(options)

    def terminate(signum, _frame):
        raise SetupExit(128 + signum)

    for signum in (signal.SIGTERM, signal.SIGHUP):
        try:
            signal.signal(signum, terminate)
        except (OSError, ValueError):
            pass
    code = 0
    try:
        code = setup.run_setup()
    except SetupExit as exc:
        code = 1 if exc.code else 0  # every failure is exit 1; usage errors exit 2 from parse_arguments
    except KeyboardInterrupt:
        code = 1
    except host.HostConfigError as exc:
        setup.error(str(exc))
        code = 1
    except Exception:  # an unexpected defect must still leave failed status behind
        setup.error("unexpected failure:\n" + traceback.format_exc().rstrip())
        code = 1
    if setup.trap_installed:
        code = setup.on_setup_exit(code)
    return code


if __name__ == "__main__":
    sys.exit(main())
