#!/usr/bin/env python3
"""Manual IB switch inspection and explicitly confirmed component upgrades.

Read local CSV/global inputs without load, Git or historical lock prerequisites.
Operational CLI runs hold one host-local initialization/upgrade runtime guard.
Device queries, component canaries and post-upgrade verification remain required.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import errno
import fcntl
import getpass
import hashlib
import importlib
from importlib import metadata
import json
import os
import queue
from pathlib import Path
import re
import socket
import stat
import sys
import threading
import time
import warnings
from contextlib import contextmanager

_DESKTOP_REVISION = "desktop-20261018-upgrade2.25"

# Fixed host-local identity, independent of user HOME/TMPDIR, cwd, project,
# selected devices and renamed/copied entries. Initial setup uses the same path.
_ENTRY_DIRECTORY = Path(__file__).resolve().parent
# The same two fixed layouts as _fixed_driver: complete flat siblings, or
# the canonical repository entry with its repository/tools dependencies.
if (_ENTRY_DIRECTORY / "ibsw_upgrade_driver.py").is_file():
    _REPOSITORY_ROOT = _TOOLS_ROOT = _ENTRY_DIRECTORY
    _RUNTIME_GUARD_MODULE = "ib_bringup_runtime_guard"
else:
    _REPOSITORY_ROOT = _ENTRY_DIRECTORY.parents[2]
    _TOOLS_ROOT = _REPOSITORY_ROOT / "tools"
    _RUNTIME_GUARD_MODULE = "tools.ib_bringup_runtime_guard"
_RUNTIME_GUARD_SOURCE = _TOOLS_ROOT / "ib_bringup_runtime_guard.py"
# A missing dependency in the selected layout is not another layout to try.
if not _RUNTIME_GUARD_SOURCE.is_file():
    raise ModuleNotFoundError("Missing fixed runtime guard: " + str(_RUNTIME_GUARD_SOURCE),
                              name=_RUNTIME_GUARD_MODULE, path=str(_RUNTIME_GUARD_SOURCE))
for _source_root in (_REPOSITORY_ROOT, _TOOLS_ROOT):
    if str(_source_root) not in sys.path:
        sys.path.insert(0, str(_source_root))
_runtime_guard_owner = importlib.import_module(_RUNTIME_GUARD_MODULE)
if Path(_runtime_guard_owner.__file__).resolve() != _RUNTIME_GUARD_SOURCE:
    raise ImportError("Mixed runtime guard sources refused",
                      name=_RUNTIME_GUARD_MODULE, path=str(_RUNTIME_GUARD_SOURCE))
_InstanceGuardError = _runtime_guard_owner._InstanceGuardError
_runtime_instance_guard = _runtime_guard_owner._runtime_instance_guard


def _guarded_main():
    # Only unambiguous, local help/version queries bypass the operational guard.
    if tuple(sys.argv[1:]) in (('--version',), ('--help',), ('-h',)):
        return main()
    try:
        with _runtime_instance_guard():
            return main()
    except _InstanceGuardError as error:
        sys.stderr.write('ERROR [' + error.code + ']: ' + str(error) + '\n')
        return 75 if error.code == 'ALREADY_RUNNING' else 2
_PROGRESS_HEARTBEAT_SECONDS = 30.0
_PROGRESS_POLL_SECONDS = 0.25
_TCP_DIAGNOSTIC_SECONDS = 5.0

_TCP_DIAGNOSTICS = {
    'TCP_CONNECT_TIMEOUT': ('TIMEOUT', 'TCP/22 connection timed out within the 5-second probe; reachability is not established.'),
    'TCP_CONNECTION_REFUSED': ('REFUSED', 'TCP/22 connection was refused; a reachable TCP endpoint rejected the connection, not a password.'),
    'TCP_NO_ROUTE': ('NO_ROUTE', 'The local network stack reported no route to the target; inspect routing and the management network.'),
    'TCP_CONNECT_BLOCKED_LOCALLY': ('LOCAL_BLOCKED', 'The local system denied the TCP/22 connection; inspect local firewall or socket permissions before blaming the switch.'),
    'TCP_CONNECT_FAILED': ('CONNECT_FAILED', 'TCP/22 connection could not be established; the cause is not an SSH credential rejection.'),
}


class _InspectionHold(ValueError):
    """Trusted fixed CLI diagnostic; backend exception text is never echoed."""


class _InvalidParallelLimit(_InspectionHold):
    """Fixed old numeric-argument category; never includes the supplied value."""


class _PasswordReentry(Exception):
    def __init__(self,directory): self.directory=str(directory)


def _password_retry_allowed(skipped,*,access_prepared,attempt):
    """Only explicit credential rejection before any authorization/upgrade write."""
    return (not access_prepared and type(attempt) is int and 1<=attempt<3
            and any('PASSWORD_PREFLIGHT_REJECTED' in row.get('reasons',()) for row in skipped))


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's normal diagnostic can reflect an untrusted argument value.
        raise _InspectionHold("invalid arguments")


class _Once(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        seen = getattr(namespace, "_seen_values", None)
        if seen is None:
            seen = set()
            namespace._seen_values = seen
        if self.dest in seen:
            raise _InspectionHold("repeated value option")
        seen.add(self.dest)
        setattr(namespace, self.dest, values)


_PREPARE_VALUES = (
    "--project", "--ib-csv", "--global", "--method", "--package-dir", "--devices",
    "--scp-root", "--source-root", "--local-dir", "--http-scheme",
)
_PREPARE_FLAGS = (
    "--os", "--bios", "--cpld", "--os-only", "--bios-only", "--cpld-only",
    "--all", "-A", "--os-first", "--skip-canary", "--yes", "-y",
    "--exclusive-config-window", "--force",
)
_AUTH_VALUES = ("--known-hosts", "--user", "--identity", "--management-public-key")
_RUNTIME_VALUES = ('--parallel-limit','--os-download-jitter')
# These old options retain their meanings: they are NOT aliases for new auth.
_UNMIGRATED_VALUES = (
    "--ib-log", "--public-key", "--mgmt-server", "--mgmt-user",
    "--http-server", "--phase-wait",
)


def _parse_cli(argv):
    parser = _Parser(
        description="IB read-only inspection or confirmed component upgrades with original SSH authorization preservation.",
        epilog=("Default: read-only inspection as admin, using the current user's ~/.ssh/known_hosts. "
                "Default inputs are ib.csv and 01-global.yaml beside this entry script, independent of CWD. "
                "Same-source input symlinks are supported; load/setup is not required. HTTP only. "
                "Manual runs do not inspect Git, deployment receipts or old runs. "
                "A host-local runtime guard prevents concurrent initialization/upgrade entries. "
                "Do not use another server or configuration writer against these switches at the same time. "
                "Alternatively use --project /var/www/html/DAY0-Prepare/PROJECT. "
                "Upgrade workers U=min(32,ceil(ready_devices/2)); verification workers V=min(8,ceil(U/4)). "
                "Startup preflight is also parallel: min(32,ceil(candidate_devices/2)), limited by half-soft FD headroom. "
                "Each component's upgrade canary must pass; after reboot require nvued running AND a usable version query, at most 5 rounds 60 seconds apart. "
                "--devices is a case-insensitive full-hostname glob selector, not a regex. "
                "Quote patterns such as 'ew-spine00[1-9]*' or 'ib-pod[a-d]-leaf*'. "
                "Real upgrades still require --upgrade --yes; inspection never upgrades devices."),
        allow_abbrev=False,
    )
    parser.add_argument("--inspect-only", action="store_true",
                        help="collect selected fixed read-only queries; never changes device authorization")
    parser.add_argument("--diagnose-inputs", action="store_true",
                        help="report input paths/link chains and validation only; no SSH, password prompt or run artifacts")
    parser.add_argument("--version", action="version", version=_DESKTOP_REVISION)
    parser.add_argument("--json", dest="output_json", action="store_true",
                        help="also emit machine-readable JSON on interactive stdout; redirected stdout keeps JSON by default")
    parser.add_argument("--upgrade", action="store_true",
                        help="run selected OS/BIOS/CPLD through the fixed verified workflow; requires --yes")
    parser.add_argument("--password", action="store_true",
                        help="hidden existing password prompt; actual upgrades always verify BOTH key and password login")
    for option in _AUTH_VALUES + _PREPARE_VALUES + _UNMIGRATED_VALUES + _RUNTIME_VALUES:
        parser.add_argument(option, action=_Once,
                            help=("lower startup/upgrade worker capacity (1..32); never raises the default formula"
                                  if option=='--parallel-limit' else
                                  "OS dispatch stagger window in seconds (0..3600); default 60*ceil(capacity/8); 0 disables"
                                  if option=='--os-download-jitter' else
                                  "case-insensitive full-hostname glob: *, ?, [0-9], [a-d], [abc], [!0-9]; "
                                  "each bracket class matches one character. Quote the pattern in your shell"
                                  if option == "--devices" else "explicit absolute normalized path" if option in
                                  ("--known-hosts", "--identity", "--management-public-key") else None))
    for option in _PREPARE_FLAGS:
        parser.add_argument(option, action="store_true", help=(
            "explicit HEALTH-ONLY override; records every exception; never bypasses trust, identity, backup, pending edits or canary"
            if option=='--force' else "compatibility maintenance-window note; optional for manual runs, not a file lock"
            if option == "--exclusive-config-window" else None))
    parser.add_argument("--scripts-only", action="store_true",
                        help="declare HTTP component scripts only; never authenticate or execute")
    parser.add_argument("--dry-run", action="store_true",
                        help="alias for read-only inspection; never upgrades devices")
    parser.add_argument("--verify-only", action="store_true",
                        help="strictly read-only selected target-version check; unmet targets return nonzero; does not recover earlier UNKNOWN runs")
    args = tuple(argv)
    if not all(isinstance(arg, str) for arg in args):
        raise _InspectionHold("string arguments required")
    parsed = parser.parse_args(args)
    if parsed.diagnose_inputs and (parsed.upgrade or parsed.scripts_only):
        raise _InspectionHold("--diagnose-inputs cannot be combined with --upgrade or --scripts-only")
    if any(getattr(parsed, option[2:].replace("-", "_")) is not None
           for option in _UNMIGRATED_VALUES if option != "--parallel-limit"):
        raise _InspectionHold("legacy option not migrated")
    if parsed.verify_only:
        if parsed.upgrade or parsed.scripts_only:
            raise _InspectionHold('--verify-only is strictly read-only and cannot upgrade or declare scripts')
        parsed.inspect_only=True
    if parsed.dry_run and (parsed.upgrade or parsed.scripts_only):
        raise _InspectionHold("--dry-run cannot be combined with --upgrade or --scripts-only")
    if parsed.dry_run or not any((parsed.inspect_only, parsed.scripts_only, parsed.upgrade)):
        parsed.inspect_only = True
    if sum((parsed.inspect_only, parsed.scripts_only, parsed.upgrade)) != 1:
        raise _InspectionHold("choose only one of --inspect-only, --scripts-only or --upgrade")
    if parsed.upgrade and not (parsed.yes or parsed.y):
        raise _InspectionHold("explicit upgrade confirmation required")
    if parsed.force and not parsed.upgrade:
        raise _InspectionHold('--force is an explicit health-only exception for --upgrade; inspection and declarations never need it')
    if parsed.exclusive_config_window and not parsed.upgrade:
        raise _InspectionHold("maintenance-window declaration belongs to upgrade only")
    if parsed.scripts_only:
        if parsed.password or any(getattr(parsed, option[2:].replace("-", "_")) is not None
                                  for option in _AUTH_VALUES):
            raise _InspectionHold("script declarations do not accept authentication")
        parsed.parallel_limit = parsed.parallel_limit if parsed.parallel_limit is not None else "8"
        if re.fullmatch(r"[0-9]+", parsed.parallel_limit) is None:
            raise _InvalidParallelLimit("non-negative integer required")
    else:
        if parsed.parallel_limit is not None:
            if re.fullmatch(r'[0-9]+',parsed.parallel_limit) is None or not 1<=int(parsed.parallel_limit)<=32:
                raise _InvalidParallelLimit('positive cap between 1 and 32 required')
            parsed.parallel_limit=int(parsed.parallel_limit)
        parsed.user = "admin" if parsed.user is None else parsed.user
        parsed.known_hosts = str(Path.home() / ".ssh/known_hosts") if parsed.known_hosts is None else parsed.known_hosts
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9._-]{0,63}", parsed.user):
            raise _InspectionHold("invalid explicit account")
        if (parsed.identity is None) != (parsed.management_public_key is None):
            raise _InspectionHold("both explicit key roles required")
        for value in (parsed.known_hosts, parsed.identity, parsed.management_public_key):
            if value is not None and (not value or "\x00" in value
                                      or not os.path.isabs(value)
                                      or os.path.normpath(value) != value):
                raise _InspectionHold("invalid explicit source path")
    if parsed.os_download_jitter is not None:
        if re.fullmatch(r'[0-9]+',parsed.os_download_jitter) is None or not 0<=int(parsed.os_download_jitter)<=3600:
            raise _InspectionHold('OS jitter must be between 0 and 3600 seconds')
        parsed.os_download_jitter=int(parsed.os_download_jitter)
    method = parsed.method
    if method is not None:
        method = {"1": "scp", "2": "http", "3": "local"}.get(method, method)
        if method != "http":
            raise _InspectionHold("HTTP-only upgrade entry; HTTPS, SCP and local transports are refused without fallback")
    if parsed.http_scheme is not None:
        if parsed.http_scheme != "http" or method not in (None, "http"):
            raise _InspectionHold("HTTPS or conflicting HTTP selector refused")
    # Keep input/phase argument order, but NEVER pass authentication material to
    # prepare: its declared plan deliberately persists the supplied argv.
    prepare_args = []
    index = 0
    while index < len(args):
        token = args[index]
        option, equal, inline = token.partition("=")
        if option in _PREPARE_VALUES:
            if equal:
                value = inline
            else:
                index += 1
                value = args[index]
            if option == "--method":
                value = method
            prepare_args.extend((option, value))
        elif token in _PREPARE_FLAGS or token == "--scripts-only":
            prepare_args.append(token)
        elif option in _AUTH_VALUES + _RUNTIME_VALUES and not equal:
            index += 1
        index += 1
    parsed.prepare_args = tuple(prepare_args)
    if hasattr(parsed, "_seen_values"):
        del parsed._seen_values
    return parsed


def _read_password():
    if not sys.stdin.isatty():
        raise _InspectionHold("hidden interactive TTY required")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            password = getpass.getpass(prompt="Switch password: ")
    except (EOFError, getpass.GetPassWarning):
        raise _InspectionHold("hidden password unavailable") from None
    if not isinstance(password, str) or not password or "\x00" in password:
        raise _InspectionHold("invalid password")
    return password


def _local_input_arguments(parsed, cwd):
    """Entry-directory defaults; explicit relative overrides retain caller CWD."""
    args = list(parsed.prepare_args)
    args.append("--standalone-inputs")
    if parsed.method is None and parsed.http_scheme is None:
        args.extend(("--method", "http"))
    if parsed.project is not None:
        return tuple(args)
    root = Path(__file__).absolute().parent
    if parsed.ib_csv is None:
        args.extend(("--ib-csv", str(root / "ib.csv")))
    if parsed.__dict__["global"] is None:
        args.extend(("--global", str(root / "01-global.yaml")))
    return tuple(args)


def _fixed_driver():
    # Admit one complete fixed layout, never mix a flat bundle with older tools.
    directory = Path(__file__).resolve().parent
    tools = directory if (directory / "ibsw_upgrade_driver.py").is_file() else directory.parents[2] / "tools"
    required = ("ibsw_upgrade_driver", "ibsw_upgrade_contract", "ibsw_upgrade_inputs",
                "ibsw_upgrade_component", "ibsw_upgrade_schedule", "ibsw_upgrade_observer",
                "ibsw_upgrade_executor", "ibsw_upgrade_access", "ibsw_upgrade_pipeline", "_package_common", "project_contract", "ssh_key_preparation")
    missing = [name + ".py" for name in required if not (tools / (name + ".py")).is_file()]
    if missing:
        raise _InspectionHold("incomplete upgrade bundle; missing: " + ", ".join(missing)
                              + ". Copy the complete bundle beside upgrade.py or deploy the matching repository tools directory")
    tools = str(tools)
    if tools not in sys.path:
        sys.path.insert(0, tools)
    import ibsw_upgrade_driver
    for name in required:
        module = importlib.import_module(name)
        if Path(module.__file__).resolve().parent != Path(tools):
            raise _InspectionHold("mixed module sources refused; use one complete matching upgrade bundle")
    return ibsw_upgrade_driver


def _check_runtime():
    from ibsw_upgrade_observer import SSH_RUNTIME_PINS
    problems = []
    for name, expected in SSH_RUNTIME_PINS:
        try:
            installed = metadata.version(name)
        except metadata.PackageNotFoundError:
            installed = "missing"
        if installed != expected:
            visible = installed if re.fullmatch(r"[A-Za-z0-9.+_-]{1,80}", installed) else "unsupported"
            problems.append(f"{name} expected={expected} installed={visible}")
    if problems:
        raise _InspectionHold("SSH runtime mismatch: " + "; ".join(problems)
                              + ". Use the matching virtual environment or install requirements.txt there; nothing was installed automatically")


def _resolve_auth(parsed):
    """Choose existing sources only; the driver still binds/rechecks originals."""
    known = Path(parsed.known_hosts)
    if not known.is_file() or known.is_symlink() or known.stat().st_size == 0:
        raise _InspectionHold("KNOWN_HOSTS: trusted host file is missing, empty or not a regular file. "
                              "Use --known-hosts /absolute/path/to/known_hosts with independently verified IB IP host keys (literal or OpenSSH hashed records); no automatic enrollment")
    if parsed.identity is None and (parsed.upgrade or not parsed.password):
        for name in ("id_ed25519", "id_rsa"):
            key = Path.home() / ".ssh" / name
            public = key.with_name(key.name + ".pub")
            if key.is_file() and public.is_file() and not key.is_symlink() and not public.is_symlink():
                parsed.identity, parsed.management_public_key = str(key), str(public)
                break
        else:
            parsed.password = True
    if parsed.upgrade:
        if parsed.identity is None:
            raise _InspectionHold('Actual upgrades require an existing management private/public key pair AND a verified password; no key is generated or installed during preflight')
        parsed.password = True


_SAFE_BACKEND_HINTS = {
    'HEALTH_PREFLIGHT_EVIDENCE_SAVE_FAILED': ('HEALTH_PREFLIGHT_EVIDENCE_SAVE_FAILED',
        'Could not reliably save startup health observations. No component installer was dispatched; inspect the private run directory.'),
    'SSD_PREFLIGHT_EVIDENCE_SAVE_FAILED; no component dispatch': ('SSD_PREFLIGHT_EVIDENCE_SAVE_FAILED',
        'The local SSD preflight record could not be saved reliably. Preserve this run and check '
        'its output permissions, storage and original evidence; no component installer was dispatched'),
    'TCP probe cleanup failed; no SSH session started': ('TCP_PROBE_CLEANUP_FAILED',
        'The diagnostic TCP socket could not be closed reliably. No SSH session was started; preserve this run and inspect local socket resources before retrying'),
    'startup original evidence/source transfer failed; no component dispatch': ('STARTUP_EVIDENCE_FAILED',
        'Startup worker original evidence or shared package source could not be retained safely. '
        'Preserve this run and inspect its local input, route and access evidence; no component installer was dispatched'),
    'startup cleanup incomplete; original evidence retained': ('STARTUP_CLEANUP_FAILED',
        'Startup worker cleanup was incomplete. No component installer was dispatched; preserve the run for review'),
    "--devices matched no IB devices": ("DEVICE_SELECTION", "--devices matched no IB hostname. It is an exact hostname/glob, not a substring; try a full CSV hostname or a quoted pattern such as 'ew-spine01*'"),
    "selected global is missing; no active-project fallback": ("INPUT_PREFLIGHT", "The selected global.yaml (or compatibility 01-global.yaml) is missing or dangling. Provide inputs in the current directory or use --project /var/www/html/DAY0-Prepare/PROJECT"),
    "managed global is not the exact direct project link": ("INPUT_BINDING", "The global link is not an admitted same-project link. Check its chain or use --project with the actual project directory; do not remove the input-identity checks"),
    "managed CSV must be same-project canonical input or known direct IB alias": ("INPUT_BINDING", "The CSV alias is not an admitted same-project source. Use --project with the actual project directory"),
    "no exact pre-provisioned literal endpoint pin; never TOFU": ("KNOWN_HOSTS", "No trusted entry matched the exact IB IP in known_hosts. Literal and OpenSSH hashed IP records are supported; hostname-only/wildcard records are not IP pins. Provide an independently verified target record; no automatic enrollment"),
    "invalid hashed known_hosts endpoint": ("KNOWN_HOSTS_FORMAT", "known_hosts contains a malformed hashed endpoint; verify the trust file format without disabling host-key checks"),
    "unsupported known_hosts hash format": ("KNOWN_HOSTS_FORMAT", "known_hosts contains an unsupported hash format; only OpenSSH |1| hashed endpoints are supported"),
    "marked host trust entry needs actual native policy": ("KNOWN_HOSTS_POLICY", "A matching known_hosts entry uses a trust marker such as @revoked or @cert-authority; it cannot authorize this connection. Review its trust policy; do not delete it just to proceed"),
    "explicit IB upgrade policy required; no legacy constants": ("UPGRADE_POLICY", "global requires switches.ib.upgrade.packages; old fixed versions are not used as fallback"),
    "selected component requires explicit policy": ("UPGRADE_POLICY", "A selected component has no policy in global. Select only configured components, for example --os-only, or complete the intended policy"),
    "project HTTP is not enabled": ("HTTP_POLICY", "HTTP is disabled in global; use an enabled approved method or correct global before selecting --method http"),
    "artifact parent must be an owned, non-group/other-writable real directory": ("OUTPUT_PERMISSIONS", "The output parent must belong to the current user and not be group/other writable. Check only the intended project output path; do not recursively change the shared HTTP tree"),
}

_SAFE_INPUT_RULES = {
    "setup manifest lacks selected aliases or core identity anchors": ("INPUT_MANIFEST_INCOMPLETE", "setup manifest lacks selected aliases or core identity anchors. Verify this project's registered links; do not edit the manifest merely to bypass checks. An explicit --project can select canonical project inputs"),
    "setup manifest and original selected alias disagree on project": ("INPUT_PROJECT_MISMATCH", "setup manifest and input aliases identify different projects. Reconcile the intended project before running"),
    "managed input alias text does not match selected project": ("INPUT_PROJECT_MISMATCH", "An input alias does not point to the expected same-project source. Check the reported link chain"),
    "explicit project conflicts with original managed input owner": ("INPUT_PROJECT_MISMATCH", "The explicit project conflicts with the managed input owner"),
    "explicit known managed global alias required; no active fallback": ("INPUT_ALIAS_UNSUPPORTED", "The global symlink is not an admitted managed entry. Use an ordinary local global.yaml or the explicit canonical --project; do not strip identity checks"),
    "managed input alias must use exact relative canonical text": ("INPUT_ALIAS_INVALID", "The input alias must use the expected relative canonical target"),
    "managed input alias must be a single-link symlink": ("INPUT_ALIAS_INVALID", "The managed alias is not a single-link symlink"),
    "managed canonical input must be a single-link regular file": ("INPUT_FILE_INVALID", "A canonical project input must be a single-link regular file"),
    "inputs must be UTF-8": ("INPUT_ENCODING_INVALID", "CSV/global inputs must be UTF-8"),
    "duplicate IB target identity/address": ("CSV_DUPLICATE_IDENTITY", "CSV contains a duplicate IB hostname, eth0 address or MAC. Reconcile the duplicate; no row is silently discarded"),
    "no IB targets": ("CSV_NO_IB_DEVICES", "The CSV has no type=ib devices"),
    "CSV header required": ("CSV_LAYOUT_INVALID", "The CSV header is missing"),
    "invalid CSV format; no legacy fallback": ("CSV_FORMAT_INVALID", "CSV syntax is invalid; there is no fallback to a legacy device list"),
    "bounded regular input required": ("INPUT_FILE_INVALID", "An input must be a nonempty bounded regular file"),
    "input scope changed or became ineligible": ("INPUT_CHANGED", "The input scope changed or became ineligible; inspect the original project/link identity"),
    "original managed input alias identity/text changed": ("INPUT_CHANGED", "A managed input alias changed during validation"),
}
_SAFE_POLICY_RULES = frozenset({
    "OS alternative stage requires 2 to 64 ordered candidates",
    "OS path must be known and strictly increasing between stages",
    "duplicate OS filename or version across stages/candidates",
    "OS files must be nonempty ordered list", "filename/explicit OS target conflict",
    "OS path must be known and strictly increasing", "OS last path node must equal ib.version",
    "BIOS requires 0ACQF.cab and explicit target version",
    "CPLD BURN/REFRESH FUI and target sets must match",
})
_DIAGNOSTIC_MODULES = frozenset({"upgrade.py", "project_contract.py", "_package_common.py",
    "ibsw_upgrade_driver.py", "ibsw_upgrade_inputs.py", "ibsw_upgrade_contract.py",
    "ibsw_upgrade_component.py", "ibsw_upgrade_schedule.py", "ibsw_upgrade_observer.py", "ibsw_upgrade_executor.py",
    "ibsw_upgrade_pipeline.py", "ibsw_upgrade_access.py"})


def _error_chain(error):
    seen = set()
    for _ in range(8):
        if error is None or id(error) in seen:
            break
        seen.add(id(error))
        yield error
        error = error.__cause__ or error.__context__


def _error_source(error):
    source = {}
    for current in _error_chain(error):
        trace = current.__traceback__
        while trace is not None:
            frame = trace.tb_frame
            module = Path(frame.f_code.co_filename).name
            if module in _DIAGNOSTIC_MODULES:
                source = {"module": module, "function": frame.f_code.co_name, "line": trace.tb_lineno}
                row = frame.f_locals.get("lineno")
                if type(row) is int and 1 <= row <= 10000000:
                    source["csv_row"] = row
            trace = trace.tb_next
    return source


def _error_functions(error):
    functions = set()
    for current in _error_chain(error):
        trace = current.__traceback__
        while trace is not None:
            if Path(trace.tb_frame.f_code.co_filename).name in _DIAGNOSTIC_MODULES:
                functions.add(trace.tb_frame.f_code.co_name)
            trace = trace.tb_next
    return functions


def _input_path_diagnostics(path):
    """Metadata only, bounded link walk; never reads CSV/YAML/key contents."""
    current, seen, rows = os.path.normpath(str(path)), set(), []
    for _ in range(16):
        if current in seen:
            rows.append({"path": current, "kind": "loop"})
            return rows
        seen.add(current)
        try:
            info = os.lstat(current)
            if stat.S_ISLNK(info.st_mode):
                target = os.readlink(current)
                rows.append({"path": current, "kind": "symlink", "target": target})
                current = os.path.normpath(os.path.join(os.path.dirname(current), target))
                continue
            kind = "file" if stat.S_ISREG(info.st_mode) else "directory" if stat.S_ISDIR(info.st_mode) else "other"
            rows.append({"path": current, "kind": kind, "size": info.st_size})
        except OSError as error:
            rows.append({"path": current, "kind": "missing" if error.errno == errno.ENOENT else "inaccessible", "errno": error.errno})
        return rows
    rows.append({"path": current, "kind": "link_depth_limit"})
    return rows


def _selection_summary(selected, blocked):
    """Summaries are DATA only; original live inputs control all device IO."""
    return {"result": "INCOMPLETE" if blocked else "SUCCESS",
            "selected_ib_count": len(selected) + len(blocked),
            "eligible_ib_count": len(selected), "skipped_ib_count": len(blocked),
            "skipped_devices": [{"hostname": item.hostname, "csv_row": item.csv_row,
                                 "state": "SKIPPED_INPUT_INVALID", "reasons": list(item.reasons)}
                                for item in blocked]}


def _upgrade_worker_count(ready_count,cap=None):
    workers=min(32,(ready_count+1)//2)
    return min(workers,cap) if cap is not None else workers


def _print_ready_device(index, total, hostname, rows):
    """One device block after all readiness checks; display never grants IO."""
    sys.stderr.write(f'[READY {index}/{total}] {hostname}\n')
    for component in ('os','bios','cpld'):
        for row in rows:
            if row['component']!=component:
                continue
            sys.stderr.write(f"  {component.upper()} current={row['current']} "
                             f"target={row['target']} action={row['action']}\n")
            if row.get('path'):
                sys.stderr.write('    OS path: '+' -> '.join(row['path'])+'\n')


def _print_component_plans(version_plan, selected):
    """List registry-ordered actions, at most four device names per line."""
    from ibsw_upgrade_schedule import component_order
    for component in component_order(selected):
        sys.stderr.write(f'[{component.upper()} PLAN]\n')
        rows=[row for row in version_plan if row['component']==component]
        for action in ('UPGRADE_REQUIRED','AT_TARGET_NO_FLASH','REVIEW_REQUIRED'):
            names=[row['hostname'] for row in rows if row['action']==action]
            if not names and action!='UPGRADE_REQUIRED':
                continue
            sys.stderr.write(f'  {action} ({len(names)}):'+('' if names else ' none')+'\n')
            for start in range(0,len(names),4):
                sys.stderr.write('    - '+', '.join(names[start:start+4])+'\n')


def _safe_query_diagnostic(error):
    """Allowlisted operational facts only; no native exceptions or query text."""
    from ibsw_upgrade_observer import READONLY_FAILURE_HINTS, UPGRADE_FAILURE_HINTS
    captured=getattr(error,'capture_raw',None)
    data=captured.get('safe_diagnostic',{}) if type(captured) is dict else {}
    if type(data) is not dict: return {}
    safe={}
    commands={'nv show system version','nv show platform firmware','nv show system health',
        'hostname; cat /sys/class/net/eth0/address','nv config show -o commands','nv config diff -o commands'}
    if data.get('command') in commands: safe['command']=data['command']
    for name in ('budget_seconds','elapsed_seconds','precheck_seconds','postcheck_seconds'):
        value=data.get(name)
        if type(value) in (int,float) and 0<=value<=1000000: safe[name]=round(value,3)
    for name in ('stdout_bytes','stderr_bytes','returncode'):
        value=data.get(name)
        if type(value) is int and 0<=value<=2**31: safe[name]=value
        elif name=='returncode' and name in data and value is None: safe[name]=None
    if type(data.get('stream_complete')) is bool: safe['stream_complete']=data['stream_complete']
    if data.get('native_errno') in set(errno.errorcode.values()): safe['native_errno']=data['native_errno']
    if data.get('reason_code') in set(READONLY_FAILURE_HINTS)|set(UPGRADE_FAILURE_HINTS)|{'QUERY_COMPLETE'}:
        safe['reason_code']=data['reason_code']
    return safe


def _readiness_skip(error, node):
    """Only known device-local failures are skips; raw exceptions stay private."""
    from ibsw_upgrade_observer import _NativeObservationHold, READONLY_FAILURE_HINTS, UPGRADE_FAILURE_HINTS
    known = {"SSH_CONNECT_FAILED": "SKIPPED_UNREACHABLE", "SSH_HANDSHAKE_FAILED": "SKIPPED_SSH_HANDSHAKE",
             "SSH_AUTHENTICATION_FAILED": "SKIPPED_AUTHENTICATION", "SSH_HOST_KEY_MISMATCH": "SKIPPED_HOST_KEY",
             "DEVICE_IDENTITY_MISMATCH": "SKIPPED_IDENTITY_MISMATCH", "DEVICE_IDENTITY_QUERY_FAILED": "SKIPPED_IDENTITY_QUERY",
             "READONLY_QUERY_FAILED": "SKIPPED_READONLY_INSPECTION",
             "READONLY_DEADLINE_EXCEEDED": "SKIPPED_READONLY_INSPECTION"}
    known.update({code: "SKIPPED_READONLY_INSPECTION" for code in READONLY_FAILURE_HINTS})
    known.update({code:'SKIPPED_HEALTH_CHECK_FAILED' for code in
        ('HEALTH_PRECHECK_NOT_OK','HEALTH_STATUS_UNAVAILABLE','HEALTH_PARSE_FAILED','HEALTH_QUERY_FAILED')})
    known.update({code:'SKIPPED_READONLY_INSPECTION' for code in
        ('READONLY_QUERY_TIMEOUT','READONLY_QUERY_INCOMPLETE','SSH_CONNECT_TIMEOUT','SSH_HANDSHAKE_TIMEOUT')})
    known['NVOS_CLI_INITIALIZING']='SKIPPED_NVUE_NOT_READY'
    from ibsw_upgrade_access import prepare_upgrade_access, AccessHold, access_failure_detail
    for code in ('SSH_AUTHENTICATION_REJECTED','SSH_AUTH_TRANSPORT_LOST','SSH_AUTH_PROTOCOL_FAILED',
                 'SSH_AUTH_TIMEOUT','SSH_PASSWORD_AUTH_RESULT_UNKNOWN','SSH_AUTH_RESULT_UNKNOWN',
                 'KEY_PREFLIGHT_REJECTED','KEY_PREFLIGHT_RECHECK_FAILED','PASSWORD_PREFLIGHT_REJECTED','UPGRADE_DUAL_AUTH_REQUIRED',
                 'AUTHORIZED_KEYS_UNSAFE','AUTHORIZED_KEYS_MANAGEMENT_KEY_MISSING','AUTHORIZED_KEYS_READ_FAILED',
                 'AUTHORIZED_KEYS_CHANGED_DURING_RECOVERY','AUTHORIZED_KEYS_ACCOUNT_CHANGED','MANAGEMENT_KEY_IMPORT_FAILED'):
        known[code] = ('SKIPPED_AUTHENTICATION' if code.startswith('SSH_AUTH') or code in
            ('KEY_PREFLIGHT_REJECTED','KEY_PREFLIGHT_RECHECK_FAILED','PASSWORD_PREFLIGHT_REJECTED','UPGRADE_DUAL_AUTH_REQUIRED') else 'SKIPPED_ACCESS_BACKUP')
    code = getattr(error, 'reason_code', '')
    if isinstance(error, (_NativeObservationHold, AccessHold)) and code in known:
        state = known[code]
    elif str(error) == 'no exact pre-provisioned literal endpoint pin; never TOFU':
        code, state = 'KNOWN_HOSTS', 'SKIPPED_HOST_KEY'
    else:
        return None
    row = dict(hostname=node.hostname, ip=node.address, state=state, reasons=[code])
    if code in READONLY_FAILURE_HINTS: row['detail'] = READONLY_FAILURE_HINTS[code]
    elif code in UPGRADE_FAILURE_HINTS: row['detail'] = UPGRADE_FAILURE_HINTS[code]
    elif code == 'SSH_CONNECT_FAILED':
        row['detail'] = 'TCP/22 connection could not be established. SSH authentication and device identity were not verified; check routing, TCP/22 and the management IP.'
    elif code == 'SSH_HANDSHAKE_FAILED':
        row['detail'] = 'TCP connected but the SSH handshake did not complete. Credentials were not verified; inspect SSH availability and network filtering.'
    if isinstance(error,AccessHold) and (state=='SKIPPED_ACCESS_BACKUP' or
            error.diagnostic['check_code']!='ACCESS_CHECK_UNCLASSIFIED'):
        row['access_diagnostic']=error.diagnostic
        row['detail']=access_failure_detail(error)
    diagnostic=_safe_query_diagnostic(error)
    if diagnostic:
        row['query_diagnostic']=diagnostic
        facts=[]
        for name,label in (('command','command'),('budget_seconds','budget'),('elapsed_seconds','elapsed'),
                ('precheck_seconds','local-precheck'),('postcheck_seconds','local-postcheck'),
                ('returncode','exit'),('stdout_bytes','stdout-bytes'),('stderr_bytes','stderr-bytes'),('native_errno','errno')):
            if name in diagnostic: facts.append(label+'='+str(diagnostic[name]))
        if 'stream_complete' in diagnostic: facts.append('stream-complete='+('yes' if diagnostic['stream_complete'] else 'no'))
        row['detail']=(row.get('detail','')+' '+', '.join(facts)).strip()
    if code == 'KNOWN_HOSTS':
        row['detail'] = ('No trusted host-key entry for this IP in the selected known_hosts file. '
            'No SSH handshake or authentication was attempted; target identity is unverified. '
            'Verify the fingerprint independently and register the exact IP (literal or OpenSSH hashed).')
    if getattr(error,'package_issues',None): row['package_issues'] = error.package_issues
    return row


def _probe_missing_host_pin(scope, node, stop):
    """One bounded TCP connect only; never SSH, TOFU, auth or positive admission.

    Run only after the original trust binding reports a missing endpoint pin.
    A successful connection does not lift that blocker. Local resource or
    cleanup failures remain batch failures, not fictitious network failures.
    """
    from ibsw_upgrade_contract import SharedUpgradeHold
    scope.verify()
    if stop.is_set(): raise SharedUpgradeHold('shared startup stop before reachability probe')
    started=time.monotonic()
    connection, original, code, native_errno = None, None, None, None
    try:
        connection=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        connection.settimeout(_TCP_DIAGNOSTIC_SECONDS)
        connection.connect((node.address,22))
    except OSError as error:
        native_errno=errno.errorcode.get(error.errno,'UNKNOWN')
        if error.errno in (errno.EMFILE,errno.ENFILE,errno.ENOMEM,errno.ENOBUFS):
            original=error
        elif isinstance(error,TimeoutError) or error.errno==errno.ETIMEDOUT:
            code='TCP_CONNECT_TIMEOUT'
        elif error.errno==errno.ECONNREFUSED:
            code='TCP_CONNECTION_REFUSED'
        elif error.errno in (errno.EHOSTUNREACH,errno.ENETUNREACH):
            code='TCP_NO_ROUTE'
        elif error.errno in (errno.EACCES,errno.EPERM):
            code='TCP_CONNECT_BLOCKED_LOCALLY'
        else: code='TCP_CONNECT_FAILED'
    except BaseException as error:
        original=error
    finally:
        if connection is not None:
            try: connection.close()
            except BaseException as cleanup:
                if original is None:
                    original=SharedUpgradeHold('TCP probe cleanup failed; no SSH session started') if isinstance(cleanup,Exception) else cleanup
                elif isinstance(original,Exception) and not isinstance(cleanup,Exception): original=cleanup
        try: scope.verify()
        except BaseException as cleanup:
            if original is None or (isinstance(original,Exception) and not isinstance(cleanup,Exception)):
                original=cleanup
    if original is not None: raise original
    if stop.is_set(): raise SharedUpgradeHold('shared startup stop after reachability probe')
    return dict(address=node.address,port=22,timeout_seconds=_TCP_DIAGNOSTIC_SECONDS,
        elapsed_seconds=round(time.monotonic()-started,3),
        status=_TCP_DIAGNOSTICS[code][0] if code else 'CONNECTED',reason_code=code,
        native_errno=native_errno,ssh_handshake_attempted=False,credentials_sent=False,identity_verified=False)


def _add_missing_pin_diagnostic(scope, node, row, stop):
    probe=_probe_missing_host_pin(scope,node,stop)
    row.update(tcp_probe=probe,trust_status='MISSING',stage='TCP_CONNECT_DIAGNOSTIC')
    code=probe['reason_code']
    if code:
        row.update(state='SKIPPED_CONNECTIVITY_DIAGNOSTIC' if code=='TCP_CONNECT_BLOCKED_LOCALLY' else 'SKIPPED_UNREACHABLE',
            reasons=[code,'KNOWN_HOSTS'],detail=_TCP_DIAGNOSTICS[code][1]+' '+row['detail'])
    else:
        row['detail']='TCP/22 accepted a connection, but this does not verify SSH availability or device identity. '+row['detail']
    return row


def _check_readiness_one(scope, node, parsed, password, stop):
    from ibsw_upgrade_contract import SharedUpgradeHold
    from ibsw_upgrade_observer import _NativeObservationHold
    from ibsw_upgrade_access import prepare_upgrade_access, AccessHold
    def check_stop():
        if stop.is_set(): raise SharedUpgradeHold('shared startup stop; no new device action')
    check_stop(); scope.verify()
    with scope.open_readonly_query_inputs(node.hostname, known_hosts_path=parsed.known_hosts,
            identity_path=parsed.identity, management_public_path=parsed.management_public_key, user=parsed.user) as leaf:
        try:
            result = leaf.observe_initial_plan_once(password=password)
        except _NativeObservationHold as error:
            if scope._access_required and error.reason_code == 'SSH_AUTHENTICATION_REJECTED':
                raise AccessHold('KEY_PREFLIGHT_REJECTED') from None
            raise
        rows = result['initial_plan'].get('version_rows', [])
        if (result.get('state') != 'READONLY_NATIVE_DATA'
                or result.get('initial_plan',{}).get('state') != 'INITIAL_NATIVE_DATA_PLAN'):
            raise _NativeObservationHold(reason_code=result.get('initial_plan',{}).get('reason_code','READONLY_QUERY_FAILED'))
        check_stop()
        if 'os' in scope.parsed.selected and scope.policy.os_stages:
            from ibsw_upgrade_executor import _freeze_os_route
            current, route = _freeze_os_route(leaf)
            for row in rows:
                if row['component'] == 'os':
                    row.update(path=[current]+[p.version for p in route], files=[p.file for p in route],
                        package_paths=[p.path for p in route], route_evidence=node.hostname+'/os-route-plan.json')
            result['initial_plan']['os_path'] = tuple(p.file for p in route)
        check_stop()
        if scope._access_required and any(row['action'] == 'UPGRADE_REQUIRED' for row in rows):
            prepare_upgrade_access(leaf, password)
    scope.verify(); check_stop()
    return result


class _ReadinessWork:
    def __init__(self, index, node):
        self.index, self.node, self.scope = index, node, None
        self.result, self.skip, self.error = None, None, None
        self.ssd_check = None


def _collect_readiness(scope, nodes, parsed, password):
    """Independent startup scopes; only parent adopts originals and prints.

    No component installer/canary starts until every startup future is settled.
    Device-local failure does not stop peers. A shared input/source/evidence
    failure sets stop immediately, cancels unstarted work and joins live tasks.
    """
    from ibsw_upgrade_contract import SharedUpgradeHold
    from ibsw_upgrade_pipeline import (available_preflight_slots, _soft_descriptor_limit,
                                      _open_descriptor_count)
    nodes = tuple(nodes)
    scope._component_readiness_issues = []
    scope._version_plan = []
    scope._startup_ssd_checks = []
    scope._health_checks = []
    scope._access_required = bool(getattr(parsed, 'upgrade', False))
    bus, stop = _ProgressBus(), threading.Event()
    first_failure, failure_lock = [], threading.Lock()
    completed, pending = {}, {}
    cursor = publish = 0
    nominal = _upgrade_worker_count(len(nodes),getattr(parsed,'parallel_limit',None))
    scope._readiness_scheduler = dict(workers=nominal, max_pending=0, completed=0,
        descriptor_budget=_soft_descriptor_limit()//2, per_pending_reserved=64)
    if not nodes: return (), []
    sys.stderr.write(f'[PREFLIGHT] candidates={len(nodes)} workers={nominal} '
                     f'fd-budget={scope._readiness_scheduler["descriptor_budget"]} rule=min(32,ceil(N/2))\n')
    def work(index, node, baselines):
        outcome = _ReadinessWork(index, node)
        try:
            if stop.is_set(): raise SharedUpgradeHold('shared startup stop before device binding')
            child = scope.fork_readiness_scope(node.hostname, baselines)
            outcome.scope = child
            child._access_required = scope._access_required
            def progress(hostname, component, stage):
                if stop.is_set(): raise SharedUpgradeHold('shared startup stop before device action')
                bus.emit(hostname, component, stage)  # Only queue; parent alone drains.
            child._progress_callback = progress if child._access_required else None
            outcome.result = _check_readiness_one(child, node, parsed, password, stop)
        except BaseException as error:
            try:
                if outcome.scope is not None: outcome.scope.verify()
                outcome.skip = _readiness_skip(error, node) if isinstance(error,Exception) else None
                if outcome.skip is not None and outcome.skip['reasons']==['KNOWN_HOSTS']:
                    outcome.skip=_add_missing_pin_diagnostic(outcome.scope,node,outcome.skip,stop)
                if outcome.skip is not None and outcome.scope is not None and hasattr(outcome.scope,'_record_startup_diagnostic'):
                    evidence=outcome.scope._record_startup_diagnostic(node.hostname,error)
                    if evidence: outcome.skip['log_directory']=evidence
                if outcome.skip is None: outcome.error = error
            except BaseException as shared:
                outcome.error = error if not isinstance(error,Exception) else shared
            if outcome.error is not None:
                with failure_lock:
                    if not first_failure: first_failure.append(outcome.error)
                    stop.set()
        finally:
            if outcome.scope is not None: outcome.scope._progress_callback = None
        return outcome
    def publish_result(outcome):
        node, index = outcome.node, outcome.index+1
        if outcome.skip is None:
            _print_ready_device(index,len(nodes),node.hostname,outcome.result['initial_plan'].get('version_rows',[]))
            for health in (r for r in getattr(scope,'_health_overrides',[]) if r['hostname']==node.hostname):
                sys.stderr.write(f'  HEALTH FORCED: {health["reason_code"]}; status={health["status"]}; issues={health["issue_count"]}\n')
        else:
            row = outcome.skip
            sys.stderr.write(f'[SKIP {index}/{len(nodes)}] {node.hostname}: {row["state"]} ({row["reasons"][0]})\n')
            if row.get('tcp_probe'):
                probe=row['tcp_probe']
                sys.stderr.write(f'  TCP/22: {probe["status"]} (timeout={probe["timeout_seconds"]:g}s); trust=MISSING\n')
            if row.get('detail'): sys.stderr.write(f'  IP: {node.address}\n  Detail: {row["detail"]}\n')
            for issue in row.get('package_issues',[]): sys.stderr.write(f'  {issue["reason"]}: {issue["path"]}\n')
    last_progress = time.monotonic()
    with ThreadPoolExecutor(max_workers=nominal,thread_name_prefix='ib-preflight') as workers:
        try:
            while cursor < len(nodes) or pending:
                scope.verify()
                if stop.is_set() and not pending: raise SharedUpgradeHold('shared startup failure; no component dispatch')
                slots = available_preflight_slots(len(pending),nominal) if not stop.is_set() else 0
                if cursor < len(nodes) and not pending and slots == 0:
                    raise SharedUpgradeHold('FD_BUDGET_INSUFFICIENT: no startup scope fits within half the soft limit; '
                        'select a smaller --devices batch or explicitly increase the shell soft limit; no installer dispatched by this coordinator')
                for _ in range(min(slots,len(nodes)-cursor)):
                    if stop.is_set(): break
                    baselines = tuple(getattr(scope,'_os_source_baselines',{}).items())
                    future = workers.submit(work,cursor,nodes[cursor],baselines)
                    pending[future] = cursor
                    cursor += 1
                scope._readiness_scheduler['max_pending'] = max(scope._readiness_scheduler['max_pending'],len(pending))
                done, _ = wait(tuple(pending),timeout=_PROGRESS_POLL_SECONDS,return_when=FIRST_COMPLETED)
                bus.drain(set(),quiet=True)
                for future in sorted(done,key=lambda item:pending[item]):
                    outcome = future.result()
                    if outcome.error is not None: raise first_failure[0] if first_failure else outcome.error
                    scope.verify()
                    try:
                        scope.adopt_readiness_scope(outcome.scope,outcome.node.hostname)
                        outcome.ssd_check = getattr(outcome.scope,'_startup_ssd_check',None)
                    finally:
                        outcome.scope.close()
                    outcome.scope = None  # Do not retain closed per-device input/policy payloads.
                    completed[outcome.index] = outcome
                    del pending[future]
                    scope._readiness_scheduler['completed'] += 1
                while publish in completed:
                    publish_result(completed[publish]); publish += 1
                if time.monotonic()-last_progress >= _PROGRESS_HEARTBEAT_SECONDS:
                    sys.stderr.write(f'[PREFLIGHT PROGRESS] running={len(pending)} queued={len(nodes)-cursor} '
                                     f'completed={len(completed)}/{len(nodes)}\n')
                    last_progress = time.monotonic()
        except BaseException as original:
            stop.set()
            for future in pending: future.cancel()
            cleanup = []
            for future in pending:
                if future.cancelled(): continue
                try:
                    outcome = future.result()
                    if outcome.scope is not None: outcome.scope.close()
                except BaseException as error: cleanup.append(error)
            if isinstance(original,Exception):
                for error in cleanup:
                    if not isinstance(error,Exception): raise error
                if cleanup:
                    raise SharedUpgradeHold('startup cleanup incomplete; original evidence retained') from original
            raise
        finally:
            bus.drain(set(),quiet=True)
    ready, skipped = [], []
    for index in range(len(nodes)):
        outcome = completed[index]
        if outcome.ssd_check is not None:
            scope._startup_ssd_checks.append(dict(hostname=outcome.node.hostname,**outcome.ssd_check))
        if outcome.skip is not None: skipped.append(outcome.skip); continue
        ready.append(outcome.node)
        scope._version_plan.extend(dict(hostname=outcome.node.hostname,**row)
            for row in outcome.result['initial_plan'].get('version_rows',[]))
        scope._component_readiness_issues.extend(dict(hostname=outcome.node.hostname,**issue)
            for issue in outcome.result['initial_plan'].get('component_issues',()))
    scope._record_health_preflight()
    scope._progress_events = bus.events
    return tuple(ready), skipped


class _ProgressBus:
    """Workers enqueue fixed codes; only the coordinator writes user output."""
    STAGES = frozenset(('ACCESS_PREFLIGHT','ACCESS_BACKUP_SAVED','KEY_REJECTED_PASSWORD_FALLBACK',
        'INITIAL_KEY_PASSWORD_FALLBACK','MANAGEMENT_KEY_IMPORTING','MANAGEMENT_KEY_IMPORTED','WAIT_OS_DOWNLOAD_STAGGER',
        'AUTHORIZED_KEYS_RESTORING','AUTHORIZED_KEYS_RESTORED','KEY_LOGIN_RECHECK','KEY_LOGIN_VERIFIED',
        'CHECK_CURRENT_VERSION','VERIFY_RECOVERY_PASSWORD','BACKUP_CONFIGURATION','ALREADY_AT_TARGET','UPLOAD_UPGRADE_SCRIPT','INSTALL_REQUEST_DISPATCH',
        'WAIT_INSTALLER','WAIT_REBOOT','WAIT_NEW_BOOT','POST_REBOOT_VERIFICATION','CHECK_NVUED','WAIT_NVUED','NVUED_RUNNING',
        'CHECK_NVUE_CLI','WAIT_NVUE_CLI','NVUE_READY','PACKAGE_DOWNLOAD','WAIT_DOWNLOAD_RECORD','PACKAGE_READY','IMAGE_FETCH','INSTALL_REQUESTED',
        'BIOS_FETCH','CPLD_BURN','CPLD_REFRESH','POSTCHECK_CONFIGURATION','POSTCHECK_HEALTH','HEALTH_OVERRIDE_USED',
        'POSTCHECK_SSD','FINAL_KEY_ACCESS_CHECK','POSTCHECK_VERIFIED','COMMITTING_EVIDENCE'))
    def __init__(self):
        self.queue = queue.SimpleQueue()
        self.latest, self.started, self.last_print, self.stage_started = {}, {}, {}, {}
        self.events = []
        self.download_queue=queue.SimpleQueue()

    def emit_download(self,record):
        self.download_queue.put(record)

    def emit(self, hostname, component, stage):
        if stage not in self.STAGES or component not in ('os','bios','cpld','ACCESS'):
            raise ValueError('unknown internal progress stage')
        self.queue.put((hostname, component, stage, time.monotonic()))

    def start_phase(self):
        self.latest.clear()
        self.started.clear()
        self.last_print.clear()
        self.stage_started.clear()

    def drain(self, active, *, quiet=False):
        while True:
            try: record=self.download_queue.get_nowait()
            except queue.Empty: break
            row=record['measurement']
            if not quiet:
                sys.stderr.write(f"[OS DOWNLOAD] {record['hostname']} {record['stage']} attempt={row['attempt']} "
                    f"bytes={row['bytes_downloaded']} elapsed={row['elapsed_seconds']:.3f}s "
                    f"avg={row['average_bytes_per_second']/1000000:.2f}MB/s "
                    f"http={row['http_status']} curl-exit={row['curl_exit']}\n")
        while True:
            try:
                hostname, component, stage, stamp = self.queue.get_nowait()
            except queue.Empty:
                break
            key=(hostname, component)
            self.started.setdefault(key, stamp)
            if self.latest.get(key) == stage:
                continue
            previous=self.latest.get(key)
            duration=max(0,stamp-self.stage_started[key]) if previous is not None else None
            self.stage_started[key]=stamp
            self.latest[key], self.last_print[key] = stage, time.monotonic()
            elapsed=int(max(0, stamp-self.started[key]))
            self.events.append(dict(hostname=hostname, component=component, stage=stage, elapsed_seconds=elapsed,
                previous_stage=previous,previous_stage_duration_seconds=duration,
                emitted_monotonic_seconds=stamp))
            if not quiet:
                sys.stderr.write(f'[{component.upper()}][{hostname}] {stage} elapsed={elapsed}s\n')
        if quiet:
            return
        now=time.monotonic()
        for key, stage in tuple(self.latest.items()):
            if key[0] in active and now-self.last_print[key] >= _PROGRESS_HEARTBEAT_SECONDS:
                self.last_print[key]=now
                status='COMMITTING_EVIDENCE: finalizing local records' if stage=='POSTCHECK_VERIFIED' else stage+': still waiting'
                sys.stderr.write(f'[{key[1].upper()}][{key[0]}] {status}; elapsed={int(now-self.started[key])}s\n')


def _run_component_queue(names, components, execute, *, verify_shared, skip_canary, record_blocked=None, progress=None):
    """Fixed parent orchestration. execute is an internal/test seam, not authority."""
    from ibsw_upgrade_contract import SharedUpgradeHold
    from ibsw_upgrade_schedule import component_order
    names = tuple(names)
    try:
        if tuple(components) != component_order(components):
            raise ValueError("illegal component order")
    except (ValueError, TypeError) as error:
        raise SharedUpgradeHold("selected components must follow the fixed registry order") from error
    if len(set(name.casefold() for name in names)) != len(names):
        raise SharedUpgradeHold("duplicate ready target")
    workers, stop = _upgrade_worker_count(len(names)), threading.Event()
    quarantined, phases = set(), []
    matrix = {name: {} for name in names}
    sys.stderr.write(f"Scheduler: ready-ib={len(names)} workers={workers} rule=min(32,ceil(N/2))\n")
    for component in components:
        if stop.is_set():
            break
        if progress is not None:
            progress.start_phase()
        candidates = [name for name in names if name not in quarantined]
        canary = None if skip_canary or not candidates else candidates[0]
        phase = {"component": component, "canary": canary, "targets": [], "blocked_by_canary": []}
        phases.append(phase)
        def block(name, state, reason):
            row = {"hostname": name, "component": component, "state": state, "reason": reason}
            phase["targets"].append(row)
            matrix[name][component] = state
            if record_blocked is not None:
                verify_shared()
                record_blocked(name, component, reason)
                verify_shared()
        for name in names:
            if name in quarantined:
                block(name, "BLOCKED_PREVIOUS_FAILURE", "Earlier device failure requires manual review; no later writes")
        def accept(name, report):
            if (type(report) is not dict or report.get("hostname") != name
                    or report.get("component") != component
                    or report.get("state") not in {"COMPLETE", "FAILED", "FAIL", "UNKNOWN", "NOT_EXECUTED"}):
                raise SharedUpgradeHold("foreign or malformed component worker result")
            phase["targets"].append(report)
            matrix[name][component] = report["state"]
            if report["state"] != "COMPLETE":
                quarantined.add(name)
            sys.stderr.write(f"[DONE {component.upper()}] {name}: {report['state']}\n")
            if report.get("reason"):
                sys.stderr.write(f"  Reason: {report['reason']}\n")
        if canary is not None:
            verify_shared()
            sys.stderr.write(f"[CANARY {component.upper()}] {canary}\n")
            with ThreadPoolExecutor(max_workers=1, thread_name_prefix='ib-canary') as canary_pool:
                future=canary_pool.submit(execute,canary,component,True,stop)
                while not future.done():
                    wait((future,),timeout=_PROGRESS_POLL_SECONDS)
                    if progress is not None:
                        progress.drain({canary})
                report=future.result()
                if progress is not None:
                    progress.drain(set())
            verify_shared()
            accept(canary, report)
            if report["state"] != "COMPLETE":
                phase["blocked_by_canary"] = candidates[1:]
                for name in candidates[1:]:
                    block(name, "BLOCKED_CANARY", "This component's canary failed or is unknown; this component was not attempted")
                # No rotation for THIS component. Peers may proceed to another
                # component, whose executor must freshly verify their own OS.
                continue
            candidates = candidates[1:]
        pending, iterator, last_progress = {}, iter(candidates), time.monotonic()
        with ThreadPoolExecutor(max_workers=max(1, workers), thread_name_prefix="ib-upgrade") as pool:
            def fill():
                while len(pending) < workers and not stop.is_set():
                    name = next(iterator, None)
                    if name is None:
                        break
                    verify_shared()
                    pending[pool.submit(execute, name, component, False, stop)] = name
            try:
                fill()
                while pending:
                    completed, _ = wait(pending, timeout=_PROGRESS_POLL_SECONDS, return_when=FIRST_COMPLETED)
                    if progress is not None:
                        progress.drain(set(pending.values()))
                    if not completed and time.monotonic() - last_progress >= _PROGRESS_HEARTBEAT_SECONDS:
                        sys.stderr.write(f"[PROGRESS {component.upper()}] running={len(pending)} completed={len(phase['targets'])}/{len(names)}\n")
                        last_progress = time.monotonic()
                    for future in completed:
                        name = pending.pop(future)
                        report = future.result()
                        verify_shared()
                        accept(name, report)
                    fill()
            except BaseException:
                stop.set()
                for future in pending:
                    future.cancel()
                raise  # running installs still get their original readback; never replay.
    def outcome(name):
        states = matrix[name].values()
        for state in ("UNKNOWN", "FAILED", "FAIL", "NOT_EXECUTED", "BLOCKED_CANARY", "BLOCKED_PREVIOUS_FAILURE"):
            if state in states:
                return state
        return "COMPLETE" if len(matrix[name]) == len(components) else "NOT_EXECUTED"
    complete = bool(names) and all(outcome(name) == "COMPLETE" for name in names)
    return {"state": "COMPLETE" if complete else "INCOMPLETE", "workers": workers,
            "components": phases, "targets": [{"hostname": name, "state": outcome(name)} for name in names]}


def _parallel_component_upgrade(scope, ready, parsed, password, driver, entry, cwd, run_directory):
    from ibsw_upgrade_schedule import component_order
    from ibsw_upgrade_pipeline import NativeAdapter,run_pipeline
    from ibsw_upgrade_contract import SharedUpgradeHold
    if not scope.manual_execution and not scope.parsed.exclusive_config_window:
        raise SharedUpgradeHold("explicit exclusive configuration maintenance window required")
    scope.enable_cooperative_status_snapshots()
    scope.initialize_native_component_status_data()
    scope._native_schedule_started = True
    bus = _ProgressBus()
    scope._access_required = True
    adapter=NativeAdapter(scope,parsed,password,driver,entry,cwd,run_directory,bus)
    result=run_pipeline([node.hostname for node in ready],component_order(scope.parsed.selected),adapter,
                       skip_canary=scope.parsed.canary_mode=="skip",progress=bus,
                       probe_factory=__import__("ibsw_upgrade_pipeline").ParentTCPProbes)
    scope._progress_callback = None
    scope._progress_events = getattr(scope, '_progress_events', []) + bus.events
    return result


def _report_input_skips(blocked):
    for item in blocked:
        sys.stderr.write(f"[SKIP] {item.hostname}: SKIPPED_INPUT_INVALID "
                         f"(CSV row {item.csv_row}; {', '.join(item.reasons)})\n")


def _component_result_rows(summary):
    versions={(r['hostname'],r['component']):r for r in summary.get('version_plan',[])}
    recovered={(r['hostname'],r['component']) for r in summary.get('progress_events',[])
               if r['stage']=='KEY_LOGIN_VERIFIED'}
    results=[]
    for phase in summary.get('components',[]):
        for row in phase['targets']+phase.get('no_change',[]):
            key=(row['hostname'],phase['component'])
            version=versions.get(key,{})
            results.append(dict(hostname=key[0],component=key[1],state=row['state'],
                action=row.get('action','NOT_VERIFIED'),
                preflight_version=version.get('current','UNVERIFIED'),
                target_version=version.get('target','UNVERIFIED'),
                ssh_key_restored_verified=key in recovered,
                reason=row.get('reason'),log_directory=row.get('log_directory')))
            if row.get('verification_basis') is not None:
                results[-1].update(verification_basis=row['verification_basis'],
                                   installer_exit_code=row.get('installer_exit_code'))
            if row.get('ssd_check') is not None:
                results[-1]['ssd_check']=row['ssd_check']
            for field in ('installation_started','failure_phase'):
                if field in row: results[-1][field]=row[field]
            if row.get('health_overrides'):
                results[-1].update(health_overrides=row['health_overrides'],health_verified=False)
    return results


def _ssd_check_rows(summary,expected_version):
    """Account for the whole selected OS scope, without additional device IO."""
    if expected_version is None or summary.get('mode')=='SCRIPTS_ONLY':
        return []
    outcomes={row['hostname']:row for row in summary.get('component_results',[]) if row['component']=='os'}
    preflight={row['hostname']:row for row in summary.get('ssd_preflight_checks',[])}
    os_rows={row['hostname']:row for row in summary.get('version_plan',[]) if row['component']=='os'}
    skipped={row['hostname'] for row in summary.get('skipped_devices',[])}
    names={row['hostname'] for row in summary.get('targets',[])}|set(outcomes)|skipped
    rows=[]
    for name in sorted(names,key=lambda n:(n.casefold(),n)):
        outcome=outcomes.get(name,{})
        if outcome.get('ssd_check') is not None:
            check=dict(outcome['ssd_check'])
        elif name in preflight and (not outcome or outcome.get('state')=='PREFLIGHT_NO_CHANGE'):
            check={key:value for key,value in preflight[name].items() if key!='hostname'}
        else:
            at_target=(outcome.get('state')=='PREFLIGHT_NO_CHANGE' or
                (not outcome and os_rows.get(name,{}).get('current')==os_rows.get(name,{}).get('target')
                 and bool(os_rows.get(name,{}))))
            if name not in skipped and at_target:
                check=dict(state='WARNING',status='UNAVAILABLE',expected_version=expected_version,observed_version=None,
                    reason_code='SSD_PREFLIGHT_RESULT_MISSING',verification_basis='PREFLIGHT_OS_AT_TARGET',informational_only=True)
            else:
                status='PREFLIGHT_SKIPPED' if name in skipped else 'NOT_REACHED' if outcome else 'OS_NOT_AT_TARGET'
                check=dict(state='NOT_CHECKED',status=status,expected_version=expected_version,observed_version=None,
                    reason_code={'PREFLIGHT_SKIPPED':'DEVICE_PREFLIGHT_SKIPPED','NOT_REACHED':'OS_POSTCHECK_NOT_REACHED',
                                 'OS_NOT_AT_TARGET':'OS_FINAL_NOT_REACHED'}[status],informational_only=True)
        rows.append(dict(hostname=name,**check))
    return rows


_SUMMARY_CATEGORIES = (
    ('UPGRADED', 'Upgraded and verified'),
    ('AT_TARGET', 'Already at target / not flashed'),
    ('AT_TARGET_OBSERVED', 'No change / preflight observation only (not flashed)'),
    ('AT_TARGET_PRECHECK', 'No change / at target in preflight; final verification incomplete'),
    ('UPGRADE_REQUIRED', 'Upgrade required (not executed)'),
    ('FAILED', 'Failed'),
    ('UNKNOWN', 'Unknown / manual verification required'),
    ('REVIEW_REQUIRED', 'Observation requires review'),
    ('BLOCKED', 'Blocked by component canary / prior device failure'),
    ('NOT_EXECUTED', 'Not executed / not fully verified'),
    ('HEALTH_BLOCKED', 'Pre-upgrade health check blocked (installer was not dispatched)'),
    ('SKIPPED', 'Preflight skipped'),
    ('DECLARED_ONLY', 'Scripts declared only'),
)


def _summary_mode(summary):
    if summary.get('mode'):
        return summary['mode']
    return ('INSPECT_ONLY' if summary['state']=='READONLY_INSPECTION_DATA' else
            'SCRIPTS_ONLY' if summary['state']=='DECLARED_CANDIDATES_NOT_EXECUTED' else 'UPGRADE')


def _summary_groups(summary):
    """Presentation DATA only. Never changes native results or grants device IO."""
    mode=_summary_mode(summary)
    labels=dict(_SUMMARY_CATEGORIES)
    order={name:index for index,(name,_label) in enumerate(_SUMMARY_CATEGORIES)}
    selected=summary.get('selected_components')
    if selected is None:
        observed={r['component'] for r in summary.get('version_plan',[])}
        observed.update(p['component'] for p in summary.get('components',[]))
        selected=[c for c in ('os','bios','cpld') if c in observed]
    selected=[c for c in ('os','bios','cpld') if c in selected]
    names=sorted({r['hostname'] for r in summary.get('targets',[])},key=lambda n:(n.casefold(),n))
    skipped={r['hostname']:r for r in summary.get('skipped_devices',[])}
    versions={(r['hostname'],r['component']):r for r in summary.get('version_plan',[])}
    outcomes={(r['hostname'],r['component']):r for r in summary.get('component_results',[])}
    issues={(r['hostname'],r.get('component')):r for r in summary.get('component_precheck_issues',[])}
    per_node={n:[] for n in names if n not in skipped}
    component_groups=[]
    attention={}

    def issue(component,category,reason,name,log=None):
        key=(component,category,reason)
        bucket=attention.setdefault(key,dict(component=component,category=category,reason=reason,devices=[],logs=[]))
        if name not in bucket['devices']: bucket['devices'].append(name)
        if log: bucket['logs'].append(dict(hostname=name,path=log))

    for component in selected:
        buckets={}
        for name in per_node:
            version=versions.get((name,component),{})
            outcome=outcomes.get((name,component),{})
            observation=issues.get((name,component),{})
            reason=outcome.get('reason') or observation.get('reason_code') or ''
            if mode=='SCRIPTS_ONLY':
                category='DECLARED_ONLY'
            elif mode in ('INSPECT_ONLY','VERIFY_ONLY'):
                category={'AT_TARGET_NO_FLASH':'AT_TARGET','UPGRADE_REQUIRED':'UPGRADE_REQUIRED'}.get(
                    version.get('action'),'REVIEW_REQUIRED')
                if category=='REVIEW_REQUIRED' and not reason: reason='Component observation incomplete or requires review'
            else:
                state=outcome.get('state','NOT_EXECUTED')
                if state=='COMPLETE':
                    category={'UPGRADE_PERFORMED_AND_VERIFIED':'UPGRADED','ALREADY_AT_TARGET_VERIFIED':'AT_TARGET'}.get(
                        outcome.get('action'),'REVIEW_REQUIRED')
                elif state=='PREFLIGHT_NO_CHANGE': category='AT_TARGET_OBSERVED'
                elif state in ('FAIL','FAILED'): category='FAILED'
                elif state=='UNKNOWN': category='UNKNOWN'
                elif state in ('BLOCKED_CANARY','BLOCKED_PREVIOUS_FAILURE'): category='BLOCKED'
                elif state=='NOT_EXECUTED' and any(code in reason for code in
                        ('HEALTH_PRECHECK_NOT_OK','HEALTH_STATUS_UNAVAILABLE','HEALTH_QUERY_FAILED','HEALTH_PARSE_FAILED')):
                    category='HEALTH_BLOCKED'
                else: category='NOT_EXECUTED'
            execution_category=category
            # A no-flash plan and an unfinished postcheck are different facts.
            # Keep native outcomes/device completion unchanged; never turn a
            # live failure, missing outcome or unobserved version into success.
            if (mode=='UPGRADE' and version.get('action')=='AT_TARGET_NO_FLASH'
                    and outcome.get('state') in ('BLOCKED_CANARY','BLOCKED_PREVIOUS_FAILURE','NOT_EXECUTED')
                    and outcome.get('action')=='NOT_VERIFIED' and not observation):
                category='AT_TARGET_PRECHECK'
            current=outcome.get('preflight_version',version.get('current','UNVERIFIED'))
            target=outcome.get('target_version',version.get('target','UNVERIFIED'))
            key=(category,current,target,reason)
            bucket=buckets.setdefault(key,dict(category=category,label=labels[category],current=current,
                target=target,reason=reason,devices=[]))
            bucket['devices'].append(name)
            per_node[name].append(execution_category)
            if category in ('AT_TARGET_PRECHECK','UPGRADE_REQUIRED','FAILED','UNKNOWN','REVIEW_REQUIRED','BLOCKED','NOT_EXECUTED','HEALTH_BLOCKED'):
                issue(component,category,reason or labels[category],name,outcome.get('log_directory'))
        groups=sorted(buckets.values(),key=lambda g:(order[g['category']],g['current'],g['target'],g['reason']))
        for group in groups: group['count']=len(group['devices'])
        phase=next((p for p in summary.get('components',[]) if p['component']==component),{})
        canary=phase.get('canary')
        canary_row=next((r for r in phase.get('targets',[]) if r['hostname']==canary),{})
        canary_details=[]
        for name in phase.get('canaries', [canary] if canary else []):
            outcome=next((r for r in phase.get('targets',[]) if r['hostname']==name),{})
            route=next((r for r in phase.get('canary_routes',[]) if r['hostname']==name),{})
            canary_details.append(dict(hostname=name,state=outcome.get('state','NOT_EXECUTED'),
                path=list(route.get('path',[])),files=list(route.get('files',[])),covers=list(route.get('covers',[]))))
        no_change=sum(g['count'] for g in groups if g['category'] in ('AT_TARGET','AT_TARGET_PRECHECK','AT_TARGET_OBSERVED'))
        verified_no_change=sum(g['count'] for g in groups if g['category']=='AT_TARGET') if mode=='UPGRADE' else 0
        component_groups.append(dict(component=component,canary=canary,
            canaries=canary_details,
            canary_state=canary_row.get('state'),canary_requirement=phase.get('canary_requirement'),groups=groups,
            no_change_counts=dict(total=no_change,final_verified=verified_no_change,
                                  preflight_only=no_change-verified_no_change)))

    node_buckets={}
    for name in sorted(set(names)|set(skipped),key=lambda n:(n.casefold(),n)):
        state,reason='',''
        if name in skipped:
            category='HEALTH_BLOCKED' if skipped[name].get('state')=='SKIPPED_HEALTH_CHECK_FAILED' else 'SKIPPED'
            state=skipped[name].get('state','SKIPPED')
            reason=', '.join(sorted(skipped[name].get('reasons',[]))) or state
            if skipped[name].get('detail'): reason+=': '+skipped[name]['detail']
            issue('preflight',category,reason,name,skipped[name].get('log_directory'))
        elif mode=='SCRIPTS_ONLY': category='DECLARED_ONLY'
        else:
            values=per_node[name]
            category=next((c for c in ('UNKNOWN','FAILED','REVIEW_REQUIRED','HEALTH_BLOCKED','BLOCKED','NOT_EXECUTED') if c in values),None)
            if category is None:
                if not values: category='NOT_EXECUTED' if mode=='UPGRADE' else 'REVIEW_REQUIRED'
                elif mode in ('INSPECT_ONLY','VERIFY_ONLY'): category='UPGRADE_REQUIRED' if 'UPGRADE_REQUIRED' in values else 'AT_TARGET'
                else: category='UPGRADED' if 'UPGRADED' in values else 'AT_TARGET'
        bucket=node_buckets.setdefault((category,state,reason),dict(category=category,label=labels[category],
            state=state,reason=reason,devices=[]))
        bucket['devices'].append(name)
    device_groups=sorted(node_buckets.values(),key=lambda g:(order[g['category']],g['state'],g['reason']))
    for index,group in enumerate(device_groups,1):
        group.update(id='D'+format(index,'02d'),count=len(group['devices']))
    for group in attention.values():
        group['devices'].sort(key=lambda n:(n.casefold(),n))
        group['logs'].sort(key=lambda r:(r['hostname'].casefold(),r['path']))
        group['count']=len(group['devices'])
    ready_unresolved=len({n for g in device_groups if g['category'] in
        ('FAILED','UNKNOWN','REVIEW_REQUIRED','BLOCKED','NOT_EXECUTED','HEALTH_BLOCKED') for n in g['devices'] if n in per_node})
    selection_counts=dict(selected=summary.get('selected_ib_count',len(names)+len(skipped)),ready=len(per_node),
        preflight_skipped=len(skipped),ready_unresolved=ready_unresolved,selected_not_completed=len(skipped)+ready_unresolved)
    return dict(schema_version=2,mode=mode,device_groups=device_groups,component_groups=component_groups,selection_counts=selection_counts,
        upgraded_devices=sum(g['count'] for g in device_groups if g['category']=='UPGRADED'),
        upgraded_components=sum(g['count'] for p in component_groups for g in p['groups'] if g['category']=='UPGRADED'),
        devices_with_component_upgrades=len({n for p in component_groups for g in p['groups']
                                             if g['category']=='UPGRADED' for n in g['devices']}),
        attention=sorted(attention.values(),key=lambda g:(('preflight',*selected).index(g['component']),
                          order[g['category']],g['reason'])))


def _summary_next_action(category,reason):
    if any(code in reason for code in ('DOWNLOAD_FAILED_BEFORE_INSTALL','DOWNLOAD_RECORD_FAILED_BEFORE_INSTALL')):
        return ('This original hop ended before installation; the device is isolated and its active slot was released. '
                'Review its HTTP/download or telemetry-ACK evidence and any earlier completed OS hops. '
                'No automatic retry was performed; resolve the cause before explicitly planning a new run.')
    if category=='HEALTH_BLOCKED' or any(code in reason for code in ('HEALTH_STATUS_UNAVAILABLE','HEALTH_PARSE_FAILED','HEALTH_DEGRADED')):
        return ('Inspect nv show system health and the saved original health records. Repair the device before a new run. '
                '--force is a health-only explicit exception, not proof of health; never resend an uncertain installer.')
    if category=='AT_TARGET_PRECHECK':
        return ('The preflight version was already at target; no component flash was required. '
                'Resolve the OS/earlier-device issue, then repeat live checks; final verification is not complete.')
    if category in ('UNKNOWN','FAILED'):
        return 'Inspect the original management-server request/verification evidence and live device state; do not resend an uncertain installation.'
    if category=='BLOCKED':
        return "Resolve the component canary or this device's earlier failure; do not bypass its verification gate."
    if category=='UPGRADE_REQUIRED':
        return 'Review the declared version path and maintenance window before explicitly requesting --upgrade --yes.'
    if category=='SKIPPED':
        if 'AUTHORIZED_KEYS_READ_FAILED' in reason:
            return ('Check SFTP availability and the named read/close operation, account home and file readability. '
                    'Inspect the private startup diagnostic; do not overwrite authorized_keys or treat this as a bad password.')
        if 'AUTHORIZED_KEYS_' in reason or 'MANAGEMENT_KEY_IMPORT' in reason:
            return ('Inspect the named authorization path and the reported type, owner UID, mode or content-check code. '
                    'Confirm the intended account and preserve existing authorizations; do not blindly chmod, chown, delete or replace the file.')
        if any(code in reason for code in ('OS_VERSION_QUERY_FAILED','FIRMWARE_QUERY_FAILED','READONLY_QUERY_',
                'READONLY_DEADLINE_EXCEEDED')):
            return ('Review the command query budget, elapsed time, stream completeness, exit code and saved raw diagnostic. '
                    'Check management-server load and NVUE readiness; this is not proof of a bad password. '
                    'Repeat a narrow inspection after resolving the cause; do not bypass identity or backups.')
        if 'NVOS_CLI_INITIALIZING' in reason:
            return ('Wait for nv show system version to return a complete parsable table, then inspect this device again. '
                    'A running nvued service alone is not sufficient; no installer was dispatched.')
        if 'TCP_CONNECT_BLOCKED_LOCALLY' in reason:
            return ('Check local firewall/socket permissions, then repeat inspection. '
                    'If reachable, verify the host fingerprint through a trusted channel; do not disable host-key checking.')
        if any(code in reason for code in _TCP_DIAGNOSTICS):
            return ('Check management routing, reachability and TCP/22 first. After restoring connectivity, '
                    'verify the host fingerprint through a trusted channel and register the exact IP; do not disable host-key checking.')
        if 'OS_PACKAGE_ROUTE_UNAVAILABLE' in reason:
            return ('Provide a readable nonempty declared package for every required future OS stage, '
                    'then repeat inspection. Do not delete an approved intermediate stage to bypass a missing package.')
        if any(code in reason for code in ('CONNECT','UNREACHABLE','HANDSHAKE')):
            return 'Check routing, reachability, TCP/22 and the selected management IP; then repeat inspection.'
        if any(code in reason for code in ('KNOWN_HOSTS','HOST_KEY')):
            return 'Verify the host fingerprint through a trusted channel; do not disable host-key checking.'
        if any(code in reason for code in ('MAC','IP','INPUT')):
            return "Correct this device's CSV IP/MAC identity using real inventory; do not insert a dummy MAC."
        return "Check this device's identity and SSH credentials; then repeat inspection without widening the target set."
    if any(code in reason for code in ('READONLY_DEADLINE_EXCEEDED','CONFIG_BACKUP_QUERY_FAILED')):
        return ('Check SSH/query latency and nvued readiness at the named phase. Confirm the backup completed '
                'before a new run; this run did not dispatch this installer. Do not replace the MAC or bypass backup.')
    return "Review this device's saved observations and prechecks; resolve the stated issue before further writes."


def _health_check_summary(summary):
    """Display-only latest facts plus non-erased history of abnormal checks."""
    names={r['hostname'] for r in (*summary.get('targets',[]),*summary.get('skipped_devices',[]),
                                  *summary.get('version_plan',[]),*summary.get('health_checks',[]))}
    latest={}
    abnormal=set()
    forced=set(summary.get('health_forced_devices',[]))
    counts=dict(PASS=0,FAIL=0,UNAVAILABLE=0,NOT_CHECKED=0)
    groups={key:[] for key in counts}
    phase_counts={key:0 for key in ('STARTUP','BEFORE_INSTALL','POST_INSTALL','FINAL_HEALTH')}
    checks=summary.get('health_checks',[])
    for row in checks:
        state=row.get('observed_state')
        if state not in ('PASS','FAIL','UNAVAILABLE'): state='UNAVAILABLE'
        latest[row['hostname']]=state
        if state!='PASS': abnormal.add(row['hostname'])
        if row.get('forced'): forced.add(row['hostname'])
        if row.get('phase') in phase_counts: phase_counts[row['phase']]+=1
    missing_post=set()
    for component in summary.get('components',[]):
        for row in component.get('targets',[]):
            if not row.get('health_postcheck_required'): continue
            name,stage=row['hostname'],row.get('health_postcheck_stage')
            actual=[r for r in row.get('health_checks',[]) if r.get('stage')==stage]
            if any(r['phase']=='FINAL_HEALTH' for r in actual): continue
            missing_post.add(name)
            if latest.get(name) not in ('FAIL','UNAVAILABLE'):
                latest[name]='UNAVAILABLE'
            abnormal.add(name)
    for name in sorted(names,key=lambda n:(n.casefold(),n)):
        groups[latest.get(name,'NOT_CHECKED')].append(name)
    counts={state:len(cohort) for state,cohort in groups.items()}
    all_passed=(False if abnormal else None if not names or counts['NOT_CHECKED'] else True)
    return dict(counts=counts,groups=groups,total=len(names),all_passed=all_passed,
        observation_count=len(checks),phase_counts=phase_counts,
        postcheck_incomplete_devices=sorted(missing_post,key=lambda n:(n.casefold(),n)),
        forced_devices=sorted(forced,key=lambda n:(n.casefold(),n)),
        abnormal_devices=sorted(abnormal,key=lambda n:(n.casefold(),n)))


def _render_summary(summary):
    """Compact grouped English output; identical device lists are referenced once."""
    import copy
    view=copy.deepcopy(summary.get('summary_groups') or _summary_groups(summary))
    health_codes=r'\b(?:HEALTH_PRECHECK_NOT_OK|HEALTH_STATUS_UNAVAILABLE|HEALTH_QUERY_FAILED|HEALTH_PARSE_FAILED|HEALTH_DEGRADED)\b'
    def health(group):
        return group.get('_health_summary') or group.get('category')=='HEALTH_BLOCKED' or bool(re.search(health_codes,group.get('reason','')))
    def coalesce_health(groups):
        output=[]; buckets={}
        for group in groups:
            if not health(group): output.append(group); continue
            key=group['category']
            if key not in buckets:
                merged=dict(group,_health_summary=True,reason='Health check requires manual inspection.',devices=[])
                buckets[key]=merged; output.append(merged)
            merged=buckets[key]
            merged['devices']=sorted(set(merged['devices'])|set(group['devices']),key=lambda n:(n.casefold(),n))
            merged['count']=len(merged['devices'])
        return output
    health_devices=set(summary.get('health_forced_devices',[]))
    health_view=_health_check_summary(summary)
    health_devices.update(health_view['abnormal_devices'])
    for group in view['attention']:
        if health(group): health_devices.update(group['devices'])
    view['device_groups']=coalesce_health(view['device_groups'])
    for phase in view['component_groups']: phase['groups']=coalesce_health(phase['groups'])
    view['attention']=[group for group in view['attention'] if not health(group)]
    lines=['','========== IB Upgrade Summary ==========']
    def add(value=''): lines.append(re.sub(r'[\x00-\x1f\x7f]', '?',str(value)))
    def section(label): add(); add('+-- '+label+' '+('-'*max(1,61-len(label))))
    def detail(label,value):
        add(label+str(value))  # One logical line; terminal soft-wrapping is not a stored newline.
    canaries={p['component']:{r['hostname'] for r in p.get('canaries',[])} or
              ({p['canary']} if p['canary'] else set()) for p in view['component_groups']}
    def device_name(name,component): return name+(' [CANARY]' if name in canaries.get(component,set()) else '')
    def device_lines(items,indent):
        items=tuple(items)
        for start in range(0,len(items),4):
            add(indent+'- '+', '.join(items[start:start+4]))
    def devices(names,indent,component=None):
        device_lines((device_name(name,component) for name in names),indent)
    def ssd_results():
        add('  SSD firmware (informational only):')
        buckets={}
        for check in sorted(summary['ssd_checks'],key=lambda r:r['hostname'].casefold()):
            buckets.setdefault((check['state'],check['status']),[]).append(check)
        for (state,status),checks in sorted(buckets.items(),key=lambda item:(
                {'PASS':0,'WARNING':1,'NOT_CHECKED':2}.get(item[0][0],3),item[0][1])):
            observed=', '.join(sorted({str(c['observed_version'] or 'UNAVAILABLE') for c in checks}))
            expected=', '.join(sorted({c['expected_version'] for c in checks}))
            detail('    '+state+' / '+status+': ',str(len(checks))+' device(s) | observed='+observed+' target='+expected)
            bases={}
            for check in checks: bases.setdefault(check.get('verification_basis','NOT_RECORDED'),[]).append(check)
            for basis,cohort in sorted(bases.items()):
                if basis!='NOT_RECORDED': detail('      Basis: ',basis+' ('+str(len(cohort))+' device(s))')
                devices([c['hostname'] for c in cohort],'      ','os')
            reasons=', '.join(sorted({c['reason_code'] for c in checks if c['reason_code']}))
            if reasons: detail('      Reason: ',reasons)
    section('01 OVERVIEW')
    add('Mode: '+view['mode'])
    add('Result: '+summary.get('result','INCOMPLETE'))
    add('Selected: '+str(summary.get('selected_ib_count',0))+'  Ready: '+str(summary.get('ready_ib_count',0))+
        '  Skipped: '+str(summary.get('skipped_ib_count',0)))
    add('Selected components: '+', '.join(g['component'].upper() for g in view['component_groups']))
    add('Upgraded and verified: '+str(view['upgraded_devices'])+' device(s), required upgrades verified; no-change observations listed separately')
    add('Components upgraded and verified: '+str(view['upgraded_components'])+' on '+
        str(view['devices_with_component_upgrades'])+' device(s)')
    accounting=view.get('selection_counts') or _summary_groups(summary)['selection_counts']
    add('Selected devices not completed: '+str(accounting['selected_not_completed'])+
        ' (preflight-skipped='+str(accounting['preflight_skipped'])+', ready-unresolved='+str(accounting['ready_unresolved'])+')')
    add('Unverified / failed among ready devices: '+str(accounting['ready_unresolved'])+' device(s)')
    if summary.get('ssd_checks'):
        ssd=summary['ssd_checks']
        add('SSD checks: passed='+str(sum(r['state']=='PASS' for r in ssd))+
            ' warnings='+str(sum(r['state']=='WARNING' for r in ssd))+
            ' not-checked='+str(sum(r['state']=='NOT_CHECKED' for r in ssd))+' total='+str(len(ssd)))
        if any(r['state']=='NOT_CHECKED' for r in ssd):
            add('SSD not checked: os-not-at-target='+str(sum(r['status']=='OS_NOT_AT_TARGET' for r in ssd))+
                ' not-reached='+str(sum(r['status']=='NOT_REACHED' for r in ssd))+
                ' preflight-skipped='+str(sum(r['status']=='PREFLIGHT_SKIPPED' for r in ssd)))
        add('SSD warnings: '+str(sum(r['state']=='WARNING' for r in summary['ssd_checks']))+
            ' (informational only; non-blocking)')
    if view['mode'] in ('INSPECT_ONLY','VERIFY_ONLY'):
        add('No upgrade was executed. Results describe current observations, not a completed upgrade or full health validation.')
        if view['mode']=='VERIFY_ONLY': add('VERIFY_ONLY checks selected target versions only; earlier UNKNOWN requests are not reclassified.')
    elif view['mode']=='SCRIPTS_ONLY':
        add('Scripts were declared only; devices were not executed or verified.')
    else: add('Counts below distinguish unique devices from per-component outcomes. Earlier runs are not reclassified.')
    if summary.get('health_override_used'):
        add('WARNING: HEALTH OVERRIDE USED (--force). Completion does NOT certify device health.')
        add('Forced-health devices: '+str(len(summary.get('health_forced_devices',[]))))
    if view['mode']=='UPGRADE' and any(p['no_change_counts']['preflight_only'] for p in view['component_groups']):
        add('No-change includes preflight observation only; these devices/components were excluded from upgrade workers. It does not imply final verification passed.')
    if view['mode']=='UPGRADE' and any(r.get('verification_basis')=='LIVE_POST_REBOOT'
                                     for r in summary.get('component_results',[])):
        add('Success uses live post-reboot checks; remote exit files are not required after reboot.')
    exits=sum(type(r.get('installer_exit_code')) is int and r['installer_exit_code']!=0
              for r in summary.get('component_results',[]))
    if exits: add('Original pre-reboot nonzero exit records: '+str(exits)+' device/component outcome(s).')
    section('02 DEVICE GROUPS')
    if not view['device_groups']: add('No device results.')
    references={tuple(g['devices']):g['id'] for g in view['device_groups']}
    displayed_categories=set()
    for group in view['device_groups']:
        if group['category'] not in displayed_categories:
            displayed_categories.add(group['category'])
            count=sum(g['count'] for g in view['device_groups'] if g['category']==group['category'])
            add('['+group['id']+'] '+group['label']+': '+str(count)+' device(s)')
        if view['mode']!='UPGRADE':
            if group['reason']: detail('  Reason: ',group['reason'])
            devices(group['devices'],'  ')
    if view['mode']=='UPGRADE': add('Device lists are shown below per component; overall device categories are mutually exclusive.')
    section('03 COMPONENT RESULTS')
    for phase in view['component_groups']:
        add(phase['component'].upper()+':')
        if view['mode']=='UPGRADE':
            details=phase.get('canaries',[])
            if len(details)>1:
                add(f'  Canaries ({len(details)}):')
                device_lines((row['hostname']+' ['+row['state']+']' for row in details),'    ')
            elif phase['canary']: add('  Canary: '+phase['canary']+' | '+str(phase['canary_state'] or 'NOT_VERIFIED'))
            else: add('  Canary: '+('not required (no upgrade planned)' if phase['canary_requirement']=='NOT_REQUIRED'
                      else 'explicitly skipped' if phase['canary_requirement']=='EXPLICITLY_SKIPPED' else 'not selected'))
            for row in details:
                if row['path']:
                    detail('    Path ('+row['hostname']+'): ', ' -> '.join(row['path']))
                    add(f"    Covers ({len(row['covers'])}):")
                    devices(row['covers'],'      ')
            counts={category:sum(g['count'] for g in phase['groups'] if g['category']==category)
                    for category,_label in _SUMMARY_CATEGORIES}
            add('  Upgraded='+str(counts['UPGRADED'])+'  No-change='+str(phase['no_change_counts']['total'])+
                '  Failed='+str(counts['FAILED'])+'  Unknown='+str(counts['UNKNOWN']))
            add('  Blocked='+str(counts['BLOCKED'])+'  Not-executed='+str(counts['NOT_EXECUTED'])+
                '  Review-required='+str(counts['REVIEW_REQUIRED'])+'  Health-blocked='+str(counts['HEALTH_BLOCKED']))
            add('  No-change verification: final-verified='+str(phase['no_change_counts']['final_verified'])+
                '  preflight-only='+str(phase['no_change_counts']['preflight_only']))
        if not phase['groups']: add('  No eligible device observations.')
        displayed_categories=set()
        for group in phase['groups']:
            if group['category'] not in displayed_categories:
                displayed_categories.add(group['category'])
                count=sum(g['count'] for g in phase['groups'] if g['category']==group['category'])
                add('  '+group['label']+': '+str(count)+' device(s)')
            current,target=group['current'],group['target']
            if phase['component']=='cpld': current,target=current.replace(';','; '),target.replace('+',', ')
            if not health(group): detail('    Observed before: ',current+'    Target: '+target)
            reference=references.get(tuple(group['devices']))
            if reference and view['mode']!='UPGRADE': add('    Devices: ['+reference+']')
            else:
                devices(group['devices'],'    ',phase['component'])
            if group['reason'] and not health(group): detail('    Reason: ',group['reason'])
        if phase['component']=='os' and summary.get('ssd_checks'):
            ssd_results()
        if phase['component']=='os' and summary.get('os_downloads'):
            measurements=summary['os_downloads']
            add('  OS image download measurements (not installation results):')
            add('    Attempts='+str(len(measurements))+' successful-transfers='+str(sum(
                r['measurement']['curl_exit']==0 and r['measurement']['http_status']==200 for r in measurements)))
            for record in sorted(measurements,key=lambda r:(r['hostname'].casefold(),r['stage'],r['measurement']['attempt'])):
                row=record['measurement']
                detail('    '+device_name(record['hostname'],'os')+' '+record['stage']+': ',
                    f"attempt={row['attempt']} {row['bytes_downloaded']/1000000:.1f}MB "
                    f"{row['elapsed_seconds']:.3f}s avg={row['average_bytes_per_second']/1000000:.2f}MB/s "
                    f"HTTP={row['http_status']} curl-exit={row['curl_exit']}")
    if summary.get('ssd_checks') and not any(p['component']=='os' for p in view['component_groups']):
        ssd_results()
    section('04 HEALTH CHECKS')
    add('Latest observations: '+'  '.join(key+'='+str(value) for key,value in health_view['counts'].items())+
        '  Total='+str(health_view['total']))
    add('Queries: '+'  '.join(phase.lower().replace('_','-')+'='+str(count)
        for phase,count in health_view['phase_counts'].items()))
    add('PASS means the observed health check passed, not that all upgrade postconditions were verified.')
    for state,names in health_view['groups'].items():
        if not names: continue
        add('  '+state+': '+str(len(names))+' device(s)')
        reference=references.get(tuple(names))
        if reference and view['mode']!='UPGRADE':
            add('    Devices: ['+reference+']')
        else:
            devices(names,'    ')
    if health_view['forced_devices']:
        add('  FORCED (--force): '+str(len(health_view['forced_devices']))+
            ' device(s); health gate overridden, not passed.')
        devices(health_view['forced_devices'],'    ')
    if health_view['counts']['NOT_CHECKED']:
        add('NOT_CHECKED is not healthy: prerequisites failed or the health query was not reached.')
    if health_view['abnormal_devices']:
        add('Earlier abnormal observations remain in the report even if a later check passes.')
    if health_view['postcheck_incomplete_devices']:
        add('  Post-upgrade health not fully verified: '+str(len(health_view['postcheck_incomplete_devices']))+' device(s)')
        devices(health_view['postcheck_incomplete_devices'],'    ')
    section('05 ATTENTION & NEXT ACTIONS')
    if health_devices:
        add('HEALTH / CHECK_REQUIRED: '+str(len(health_devices))+' device(s)')
        devices(sorted(health_devices,key=lambda n:(n.casefold(),n)),'  ')
        add('  Next: Manually inspect each device with nv show system health; resolve its health issues.')
        if summary.get('health_override_used'):
            add('  FORCED (--force): '+str(len(summary.get('health_forced_devices',[])))+' device(s); health was overridden, not passed.')
    if not view['attention'] and not health_devices and not summary.get('health_override_used') and not any(r['state']=='WARNING' for r in summary.get('ssd_checks',[])):
        add("None identified within this run's selected checks.")
    attention_buckets={}
    for group in view['attention']:
        attention_buckets.setdefault((group['component'],group['category']),[]).append(group)
    for (component,category),groups in attention_buckets.items():
        count=len({name for g in groups for name in g['devices']})
        add(component.upper()+' / '+category+': '+str(count)+' device(s)')
        for index,group in enumerate(groups):
            if index: add()
            detail('  Reason: ',group['reason'])
            devices(group['devices'],'  ',component)
            detail('  Next: ',_summary_next_action(category,group['reason']))
    ssd_warnings=[r for r in summary.get('ssd_checks',[]) if r['state']=='WARNING']
    if ssd_warnings:
        add('SSD / WARNING (informational only; non-blocking): '+str(len(ssd_warnings))+' device(s)')
        add('  See the grouped SSD firmware results above; per-device evidence is retained in the report.')
        detail('  Next: ','Review the expected SSD version and saved firmware query. '
            'No SSD flash or automatic retry was requested; OS/BIOS/CPLD gates are unchanged.')
    section('06 EVIDENCE')
    if summary.get('run_directory'):
        detail('Logs: ',summary['run_directory'])
        detail('Report: ',str(Path(summary['run_directory'])/'run-report.json'))
        add('Full versions, component actions and device lists are retained in the JSON report.')
    else: add('No run directory was created; stopped before device execution.')
    return '\n'.join(lines)+'\n'


def _emit_report_json(summary,*,force=False):
    # Existing redirected/machine consumers retain their JSON contract. A human
    # terminal gets the final grouped report, not an enormous duplicate JSON line.
    if not force and sys.stdout.isatty(): return False
    sys.stdout.write(json.dumps(summary,sort_keys=True,separators=(',',':'))+'\n')
    sys.stdout.flush()
    return True


def _print_upgrade_summary(summary):
    sys.stderr.write(_render_summary(summary))
    sys.stderr.flush()


def _input_diagnostic_document(parsed, prepare, entry, cwd, stage, error=None, selected=(), blocked=()):
    document = {"revision": _DESKTOP_REVISION, "state": "INPUT_PREFLIGHT_FAILED" if error else "INPUT_PREFLIGHT_PASSED",
        "diagnostic_data_only": True, "execution_state": "NOT_EXECUTED", "ssh_attempted": False,
        "local_artifacts_created": False, "entry": entry, "cwd": cwd, "inputs": {}}
    if entry:
        try:
            with open(entry, "rb") as handle:
                source = handle.read(1024 * 1024 + 1)
            if len(source) <= 1024 * 1024:
                document["entry_sha256"] = hashlib.sha256(source).hexdigest()
        except OSError:
            pass
    document["loaded_modules"] = {}
    for name in ("ibsw_upgrade_driver", "ibsw_upgrade_inputs", "ibsw_upgrade_contract", "project_contract"):
        module = sys.modules.get(name)
        path = getattr(module, "__file__", None)
        if not path or Path(path).name not in _DIAGNOSTIC_MODULES:
            continue
        record = {"path": str(Path(path).resolve())}
        try:
            with open(path, "rb") as handle:
                payload = handle.read(1024 * 1024 + 1)
            if len(payload) <= 1024 * 1024:
                record["sha256"] = hashlib.sha256(payload).hexdigest()
        except OSError:
            pass
        document["loaded_modules"][name] = record
    if prepare is not None:
        document["inputs"] = {"csv": _input_path_diagnostics(prepare.paths.csv_path),
                              "global": _input_path_diagnostics(prepare.paths.global_path)}
        document["selected_components"] = list(prepare.selected)
        document["method"] = prepare.method
    if error is None:
        document.update(_selection_summary(selected, blocked))
        if blocked:
            document["state"] = "INPUT_PREFLIGHT_INCOMPLETE"
    else:
        code, message = _failure_detail(error, stage)
        document["error"] = {"code": code, "message": message, "exception_type": type(error).__name__,
                             "source": _error_source(error)}
        for current in _error_chain(error):
            if type(current).__module__.startswith("yaml."):
                mark = getattr(current, "problem_mark", None)
                if mark is not None and type(mark.line) is int and type(mark.column) is int:
                    document["error"].update(yaml_line=mark.line+1, yaml_column=mark.column+1)
                    break
    return document


def _failure_detail(error, stage):
    if isinstance(error, _InspectionHold):
        return stage, str(error)
    current, visited = error, set()
    for _ in range(8):
        if current is None or id(current) in visited:
            break
        visited.add(id(current))
        if isinstance(current,OSError) and current.errno in {errno.EMFILE,errno.ENFILE}:
            return 'LOCAL_DESCRIPTOR_EXHAUSTED', ('Local file descriptor allocation failed ('+
                errno.errorcode[current.errno]+'); preserve the current run and in-flight device requests. '
                'Check descriptor usage and the soft limit; do not resend an uncertain installer')
        if isinstance(current,Exception) and str(current).startswith(('FD_BUDGET_INSUFFICIENT:',
                'FD_BUDGET_INVALID:', 'FD_BUDGET_UNAVAILABLE:')):
            return str(current).split(':',1)[0], str(current)
        package_hold=getattr(sys.modules.get('ibsw_upgrade_executor'),'_PackageSourceHold',None)
        if package_hold is not None and type(current) is package_hold:
            return current.reason_code, ('Local package source: '+current.package_path+
                '; verify its configured path, read permissions and unchanged file identity. No automatic route switch was attempted')
        if str(current) in _SAFE_BACKEND_HINTS:
            return _SAFE_BACKEND_HINTS[str(current)]
        if str(current) in _SAFE_INPUT_RULES:
            return _SAFE_INPUT_RULES[str(current)]
        if str(current) in _SAFE_POLICY_RULES:
            return "UPGRADE_POLICY", str(current) + "; correct the declared global upgrade policy"
        if type(current).__module__.startswith("yaml."):
            return "GLOBAL_YAML_INVALID", "Global YAML syntax/structure is invalid; use diagnostic line/column, not a printed configuration snippet"
        if isinstance(current, ModuleNotFoundError):
            name = current.name if re.fullmatch(r"[A-Za-z0-9_.]{1,80}", current.name or "") else "dependency"
            return "DEPENDENCIES", "Missing Python module: " + name + "; activate the matching environment and copy the complete bundle"
        current = current.__cause__ or current.__context__
    if stage in {"INPUT_PREFLIGHT", "INPUT_BINDING", "PREPARE"}:
        for current in _error_chain(error):
            if isinstance(current, OSError):
                if current.errno == errno.ENOENT:
                    return "INPUT_FILE_MISSING", "A required input, alias target or setup manifest is missing. Run --diagnose-inputs to see the selected input/link paths"
                if current.errno == errno.EACCES:
                    return "INPUT_ACCESS_DENIED", "Access to an input or parent directory was denied; check the selected path's read/search permissions"
                if current.errno in {errno.ELOOP, errno.ENOTDIR}:
                    return "INPUT_PATH_INVALID", "A symlink traversal/loop or non-directory path component was refused; inspect the selected input chain"
        functions = _error_functions(error)
        if functions.intersection({"parse_device_csv_layout", "require_device_csv_row_width", "_repeated_group_starts"}):
            return "CSV_LAYOUT_INVALID", "CSV header, repeated groups or row width do not match the declared schema_version; inspect the reported validation location/CSV row"
        if "detect_global_schema_version" in functions:
            return "GLOBAL_SCHEMA_INVALID", "Global schema_version must be a supported integer; inspect the local global file"
        if functions.intersection({"_ibsw_validate_upgrade", "_ibsw_ib", "_ibsw_version", "_ibsw_file", "_ibsw_subdir", "normalize_upgrade"}):
            return "UPGRADE_POLICY", "Global IB upgrade policy is invalid; inspect the reported validator location. No configured value is echoed"
    code = getattr(error, "reason_code", "")
    if code == "SSH_AUTHENTICATION_FAILED":
        return code, "IB SSH authentication failed; check the selected key/credentials. Try --password for explicit password-only login; no key installation or password rotation was performed"
    if code in {"SSH_CONNECT_FAILED", "SSH_HANDSHAKE_FAILED", "SSH_HOST_KEY_MISMATCH", "SSH_AUTHENTICATION_FAILED", "DEVICE_IDENTITY_MISMATCH", "DEVICE_IDENTITY_QUERY_FAILED", "READONLY_QUERY_FAILED"}:
        return code, "Read-only observation stopped. Check the indicated SSH/identity/query stage; no upgrade permission was inferred"
    return stage, ("Validation refused (" + type(error).__name__ + "). See Location below or run --diagnose-inputs for source/path diagnostics; raw exception text is withheld to protect credentials")


def main(argv=None,*,_password_attempt=1,_password_history=()):
    is_upgrade = False
    stage = "ARGUMENTS"
    parsed, prepare_arguments, entry, cwd = None, None, None, None
    prepared = None
    try:
        parsed = _parse_cli(tuple(sys.argv[1:] if argv is None else argv))
        is_upgrade = parsed.upgrade
        stage = "DEPENDENCIES"
        driver = _fixed_driver()
        entry, cwd = str(Path(__file__).resolve()), os.getcwd()
        parsed.prepare_args = _local_input_arguments(parsed, cwd)
        # Pure argument validation precedes any prompt or private-output creation.
        stage = "INPUT_PREFLIGHT"
        prepare_arguments = driver.parse_prepare_args(entry, cwd, parsed.prepare_args)
        if parsed.scripts_only and prepare_arguments.method not in ("local", "http"):
            raise _InspectionHold("SCP script declarations are not implemented")
        # Refuse no-match before prompt/output. Prepare independently reopens
        # and verifies the full CSV; this snapshot never becomes permission.
        selection = driver.preflight_inventory_selection(entry, cwd, parsed.prepare_args)
        selected, blocked = selection.devices, selection.blocked_devices
        if parsed.diagnose_inputs:
            document = _input_diagnostic_document(parsed, prepare_arguments, entry, cwd, stage, selected=selected, blocked=blocked)
            sys.stdout.write(json.dumps(document, sort_keys=True, indent=2) + "\n")
            return 3 if blocked else 0
        _report_input_skips(blocked)
        if not selected:
            # All requested nodes are explicitly blocked. No auth, output,
            # runtime check or scheduler invocation for an empty eligible set.
            document = {"state": "NO_ELIGIBLE_IB_DEVICES", "execution_state": "NOT_EXECUTED",
                        "activation_state": "UNKNOWN", "ssh_attempted": False,
                        "local_artifacts_created": False, "targets": [],
                        **_selection_summary(selected, blocked)}
            document.update(mode='UPGRADE' if parsed.upgrade else 'SCRIPTS_ONLY' if parsed.scripts_only else 'INSPECT_ONLY',
                            selected_components=list(prepare_arguments.selected),ready_ib_count=0)
            if parsed.verify_only: document['mode']='VERIFY_ONLY'
            document['health_checks']=[]
            document['health_summary']=_health_check_summary(document)
            document['health_all_passed']=document['health_summary']['all_passed']
            document['summary_groups']=_summary_groups(document)
            _emit_report_json(document,force=parsed.output_json)
            _print_upgrade_summary(document)
            return 3
        if not parsed.scripts_only:
            stage = "AUTH_SOURCES"
            _resolve_auth(parsed)
            stage = "SSH_RUNTIME"
            _check_runtime()
        stage = "PASSWORD"
        if parsed.upgrade:
            if prepare_arguments.force_health:
                sys.stderr.write('[WARNING] --force enables HEALTH OVERRIDE only for installation gates. '
                    'All health queries and actual results are retained; an override is FORCED, never healthy. '
                    'Trust, identity, pending configuration, backups, '
                    'version paths and canary gates remain mandatory.\n')
            sys.stderr.write('[AUTH] Enter the existing IB switch password for preflight and post-reboot recovery. '
                             'For devices requiring installation, key AND password login must both work; no password is changed.\n')
        password = _read_password() if parsed.password else None
        stage = "PREPARE"
        prepared = driver.prepare_manual_run(entry, cwd, parsed.prepare_args)
        targets, upgrade_result, readiness_skips = [], None, []
        stage = "INPUT_BINDING"
        with driver.open_manual_run(entry, cwd, parsed.prepare_args,
                                      prepared["run_directory"]) as scope:
            live_selection = driver.select_inventory_devices(scope.session.inventory(), parsed.devices)
            nodes, blocked = live_selection.devices, live_selection.blocked_devices
            ready = nodes
            if not parsed.scripts_only:
                stage = "TARGET_READINESS"
                ready, readiness_skips = _collect_readiness(scope, nodes, parsed, password)
                _print_component_plans(getattr(scope,'_version_plan',[]),scope.parsed.selected)
                access_prepared=any(key[1] in ('access-bootstrap.json','access-backup.json') for key in scope.files)
                if parsed.upgrade and _password_retry_allowed(readiness_skips,
                        access_prepared=access_prepared,attempt=_password_attempt):
                    # Do not reuse immutable diagnostics or import keys twice.
                    # Preserve this complete failed run, close original handles,
                    # then create a fresh run only for a corrected credential.
                    scope.write_run_report(dict(revision=_DESKTOP_REVISION,mode='UPGRADE',result='INCOMPLETE',
                        state='PASSWORD_PREFLIGHT_REJECTED',execution_state='NOT_EXECUTED',activation_state='UNKNOWN',
                        run_directory=prepared['run_directory'],selected_components=list(scope.parsed.selected),
                        targets=[dict(hostname=n.hostname) for n in ready],skipped_devices=readiness_skips,
                        version_plan=getattr(scope,'_version_plan',[]),password_attempt=_password_attempt,
                        previous_password_attempt_runs=list(_password_history)))
                    raise _PasswordReentry(prepared['run_directory'])
            if parsed.upgrade:
                stage = "UPGRADE"
                sys.stderr.write("[NOTICE] Manual upgrade: no deployment or history gates. The CLI holds a "
                                 "host-local initialization/upgrade runtime guard; ensure no other server or "
                                 "configuration writer is operating on these switches.\n")
                upgrade_result = (_parallel_component_upgrade(scope, ready, parsed, password, driver, entry, cwd,
                                                               prepared["run_directory"]) if ready else
                                  {"state": "INCOMPLETE", "targets": [], "components": [], "workers": 0})
                targets.extend(upgrade_result["targets"])
            elif parsed.scripts_only:
                stage = "SCRIPT_DECLARATION"
                # Entire declared chains only: no current/version observations,
                # no request, dispatch, status initialization or canary permission.
                for component in scope.parsed.selected:
                    indices = range(len(scope.policy.os)) if component == "os" else (0,)
                    for node in nodes:
                        for index in indices:
                            scope.prepare_requested_step(node.hostname, component, index)
                targets.extend({"hostname": node.hostname} for node in nodes)
            else:
                targets.extend({"hostname": node.hostname} for node in ready)
            stage = "FINAL_INPUT_VERIFY"
            scope.verify()
        # Publication is after every leaf and the original scope's final verify
        # and close. No query/status/request/dispatch artifact is written here.
        if parsed.upgrade:
            summary = {"state": "UPGRADE_VERIFIED", "execution_state": "COMPLETE",
                       "activation_state": "VERIFIED", "targets": targets,
                       "components": upgrade_result["components"], "run_directory": prepared["run_directory"]}
        else:
            summary = {"state": ("DECLARED_CANDIDATES_NOT_EXECUTED" if parsed.scripts_only
                             else "READONLY_INSPECTION_DATA"),
                   "execution_state": "NOT_EXECUTED",
                   "activation_state": "UNKNOWN", "targets": targets}
        summary.update(_selection_summary(nodes, blocked))
        summary.update(revision=_DESKTOP_REVISION,mode='UPGRADE' if parsed.upgrade else
                       'SCRIPTS_ONLY' if parsed.scripts_only else 'INSPECT_ONLY',
                       selected_components=list(scope.parsed.selected))
        if parsed.verify_only: summary['mode']='VERIFY_ONLY'
        if parsed.upgrade:
            summary['password_attempt']=_password_attempt
            summary['previous_password_attempt_runs']=list(_password_history)
        summary.update(input_eligible_ib_count=len(nodes), ready_ib_count=len(ready), eligible_ib_count=len(ready))
        summary["run_directory"] = prepared["run_directory"]
        summary['version_plan'] = getattr(scope,'_version_plan',[])
        if getattr(scope,'_startup_ssd_checks',[]):
            summary['ssd_preflight_checks']=list(scope._startup_ssd_checks)
        summary['readiness_scheduler'] = getattr(scope,'_readiness_scheduler',{})
        overrides=list(getattr(scope,'_health_overrides',[]))
        health_checks=list(getattr(scope,'_health_checks',[]))
        for phase in (upgrade_result.get('components',[]) if parsed.upgrade else []):
            for row in phase.get('targets',[]):
                overrides.extend(row.get('health_overrides',[]))
                health_checks.extend(row.get('health_checks',[]))
        # Original per-job facts only; a multi-hop job can return its retained
        # earlier checks again, but duplicates must not inflate query counts.
        seen=set()
        summary['health_checks']=[]
        for row in health_checks:
            identifier=row['observation_id']
            if identifier in seen: continue
            seen.add(identifier)
            summary['health_checks'].append(row)
        summary['health_overrides']=overrides
        summary['health_override_used']=bool(overrides)
        summary['health_forced_devices']=sorted({r['hostname'] for r in overrides})
        summary['health_blocked_ib_count']=sum(r['state']=='SKIPPED_HEALTH_CHECK_FAILED' for r in readiness_skips)
        if parsed.upgrade:
            summary['progress_events'] = getattr(scope,'_progress_events',[])
            summary['os_downloads']=upgrade_result.get('os_downloads',[])
            summary['os_download_policy']=dict(single_attempt_timeout_seconds=600,max_attempts=4,
                retry_delay_seconds=5,jitter_formula='60*ceil(N/8)',
                jitter_override_seconds=parsed.os_download_jitter,parallel_limit=parsed.parallel_limit)
            summary['scheduler'] = dict(upgrade_workers=upgrade_result.get('workers',0),
                verification_workers=upgrade_result.get('verification_workers',0),
                in_flight_limit=upgrade_result.get('in_flight_limit',0))
            summary['resource_budget'] = upgrade_result.get('resource_budget')
            summary['verification_timeline'] = upgrade_result.get('verification_timeline',[])
            summary['unresolved_in_flight'] = upgrade_result.get('unresolved_in_flight',[])
        component_issues = getattr(scope, "_component_readiness_issues", [])
        if component_issues:
            summary["component_precheck_issues"] = component_issues
        summary["skipped_devices"].extend(readiness_skips)
        summary["skipped_ib_count"] += len(readiness_skips)
        summary['health_summary']=_health_check_summary(summary)
        summary['health_all_passed']=summary['health_summary']['all_passed']
        incomplete = bool(blocked or readiness_skips or (component_issues and not parsed.upgrade)
                          or (parsed.upgrade and upgrade_result["state"] != "COMPLETE"))
        if parsed.verify_only:
            unmet=any(row['action']!='AT_TARGET_NO_FLASH' for row in summary['version_plan']
                if row['component'] in summary['selected_components'])
            incomplete=incomplete or unmet
            summary.update(state='READONLY_VERIFICATION_INCOMPLETE' if incomplete else 'READONLY_VERIFICATION_PASSED',
                           result='INCOMPLETE' if incomplete else 'SUCCESS')
        if incomplete:
            summary["result"] = "INCOMPLETE"
        if parsed.upgrade and incomplete:
            observed_execution = any(row.get('state') not in
                {'NOT_EXECUTED','BLOCKED_CANARY','BLOCKED_PREVIOUS_FAILURE'}
                for phase in upgrade_result['components'] for row in phase['targets'])
            summary.update(state="UPGRADE_INCOMPLETE", execution_state="PARTIAL" if observed_execution else "NOT_EXECUTED", activation_state="UNKNOWN")
        if parsed.upgrade:
            summary['component_results'] = _component_result_rows(summary)
            if not incomplete and all(row.get('state')=='NO_CHANGE' for row in targets):
                summary.update(state='UPGRADE_NO_CHANGE',execution_state='NOT_EXECUTED',activation_state='NOT_REQUIRED')
        if parsed.upgrade or summary.get('ssd_preflight_checks'):
            ssd_checks=_ssd_check_rows(summary,scope.policy.ssd_version)
            if ssd_checks: summary['ssd_checks']=ssd_checks
        summary['summary_groups']=_summary_groups(summary)
        summary['health_blocked_ib_count']=sum(g['count'] for g in summary['summary_groups']['device_groups']
                                              if g['category']=='HEALTH_BLOCKED')
        stage = "SAVE_RUN_REPORT"
        with driver.open_manual_run(entry, cwd, parsed.prepare_args, prepared["run_directory"]) as final_scope:
            final_scope.write_run_report(summary)
        _emit_report_json(summary,force=parsed.output_json)
        _print_upgrade_summary(summary)
        return 3 if incomplete else 0
    except _PasswordReentry as retry:
        sys.stderr.write(f'[AUTH] Existing password was explicitly rejected before any key or installer write. '
            f'Attempt {_password_attempt+1}/3; previous evidence retained at {retry.directory}\n')
        return main(argv,_password_attempt=_password_attempt+1,
                    _password_history=(*_password_history,retry.directory))
    except _InvalidParallelLimit:
        sys.stderr.write("HOLD: Invalid --parallel-limit: expected a non-negative integer.\n")
        return 1
    except Exception as error:
        # Fixed CLI/allowlisted diagnostics only: never raw SDK/argv/passwords.
        code, detail = _failure_detail(error, stage)
        if parsed is not None and parsed.diagnose_inputs:
            document = _input_diagnostic_document(parsed, prepare_arguments, entry, cwd, stage, error=error)
            sys.stdout.write(json.dumps(document, sort_keys=True, indent=2) + "\n")
        prefix = "upgrade incomplete" if is_upgrade else "read-only inspection incomplete"
        sys.stderr.write(f"HOLD [{code}]: {prefix}\n{detail}\n")
        source = _error_source(error)
        if source:
            sys.stderr.write(f"Location: {source['module']}:{source['line']} in {source['function']}\n")
        if prepared is not None:
            sys.stderr.write("Run logs: " + prepared["run_directory"] + "\n")
        return 2


if __name__ == "__main__":
    try:
        raise SystemExit(_guarded_main())
    except KeyboardInterrupt:
        sys.stderr.write("HOLD: inspection interrupted\n")
        raise SystemExit(130) from None
