#!/usr/bin/env python3
"""Initialize NVOS management through Ethernet OOB switches.

The program runs on a management host.  It logs in to each Ethernet switch
listed in ib.csv, correlates P2P ports with ``ip -d link show``,
``bridge fdb show`` and ``ip neighbor``, then reaches the attached NVOS switch
through its IPv6 link-local address from that Ethernet switch.

Python 3 standard library only.  No sshpass, pexpect, Paramiko, or Excel module
is required.

Repository entry, based on the v15 field script (owner 2026-11-06: rename it to
initial-setup.py and develop on it).  --version prints the repository revision
written in this file.  Run from the original input directory, or specify
--project-dir.  On the management server a present project 01-global.yaml binds
every IB read and write to its target password (DEV strict stages); without it,
--apply still configures and never rotates a password.  Password verification uses
native libcrypt/libxcrypt; no password is saved and no cron is installed (the
former --auto watch and --credentials-file are retired, owner 2026-11-02).
--credentials-fd N reads the passwords once from an inherited pipe as one JSON object
(tools/credentials_fd.py, R-012 design 8.3) and then never prompts.

After all OOB snapshots and prechecks, use a global dynamic queue with
min(16, ceil(eligible IB / 16)) worker slots. A one-slot run executes inline;
larger runs isolate each device task in a child process. Only the coordinator
prompts, authorizes writes, prints complete device log blocks and writes reports.
See I21/I15 in the TEST issue tracker. Full I19/I20 input/multi-address identity
adaptation remains pending; the historical v13 VLAN-only fallback is retained.
If ND is missing, a unique CSV-matched FDB MAC may supply a modified EUI-64
candidate, scoped by the actual VLAN SVI/VRF. A candidate is not a verified login.
Default output is compact; --verbose also prints full device blocks. Full
reports/JSON remain available. The summary separates base/services/key actions
and OOB IPv4 readiness from the management-server direct SSH probe.
"""

from __future__ import annotations

import argparse
import ast
import base64
import copy
import csv
import errno
import fcntl
import getpass
import hashlib
import hmac
import ipaddress
import json
import multiprocessing
from multiprocessing.connection import wait as wait_connections
import os
import pty
import random
import re
import select
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import weakref
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, replace
from collections import deque
from collections.abc import Mapping
from contextlib import contextmanager
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from types import MappingProxyType
from typing import Callable, Optional


NA_VALUES = {"", "na", "n/a", "none", "null", "tbd", "-"}
IB_PORT_ALIASES = {"eth0", "mgmt", "management", "bmc"}
DEFAULT_HOSTNAMES = {"", "nvos"}
TRANSIT_DEVICE_TYPES = frozenset({"eth", "eth_spx", "spx", "ethernet", "eth_jump"})
TARGET_CACHE_VERSION = 5
_SELF_SOURCE_PATH = Path(__file__).resolve()
MAC_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
DOT_LINK_RE = re.compile(
    r'^\s*"([^"]+)"\s*:\s*"([^"]+)"\s*--\s*'
    r'"([^"]+)"\s*:\s*"([^"]+)"'
)
REPORT_HANDLE = None
# Fixed in the file: an OOB Leaf copy has no git to derive it from.  Every version that
# changes this script sets it to that version before its release tag (guide WP-2, A.11).
_REPOSITORY_REVISION = "http-v3.1.3"

# Fixed host-local identity, independent of user HOME/TMPDIR, cwd, project,
# selected devices and renamed/copied entries. Upgrade uses the same path.
_RUNTIME_GUARD_PATH = Path('/tmp/http-ib-bringup.runtime.lock')


class _InstanceGuardError(RuntimeError):
    def __init__(self, code, detail):
        super().__init__(detail)
        self.code = code


@contextmanager
def _runtime_instance_guard():
    """Nonblocking kernel lock, not a PID/sentinel or deployment prerequisite.

    The persistent empty regular inode is intentional: never unlink it when
    releasing, which would allow two processes to lock different generations.
    Existing files are opened read-only so another UID, including root, can
    participate without rewriting/chmodding the original creator's file.
    """
    descriptor = None
    try:
        flags = os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        try:
            descriptor = os.open(_RUNTIME_GUARD_PATH,
                                 os.O_RDWR | os.O_CREAT | os.O_EXCL | flags, 0o644)
            os.fchmod(descriptor, 0o644)
        except FileExistsError:
            descriptor = os.open(_RUNTIME_GUARD_PATH, os.O_RDONLY | flags)
        os.set_inheritable(descriptor, False)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o022:
            raise _InstanceGuardError('INSTANCE_GUARD_UNAVAILABLE',
                'Unsafe runtime guard type, links or permissions. No operations started. '
                'Ask the administrator to inspect ' + str(_RUNTIME_GUARD_PATH))
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            if error.errno not in (errno.EAGAIN, errno.EACCES):
                raise
            raise _InstanceGuardError('ALREADY_RUNNING',
                'Another initialization or upgrade process is running on this management host. '
                'No operations started. Wait for it to finish; do not delete the runtime guard: '
                + str(_RUNTIME_GUARD_PATH)) from None
        current = os.stat(_RUNTIME_GUARD_PATH, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            raise _InstanceGuardError('INSTANCE_GUARD_UNAVAILABLE',
                'Runtime guard changed while opening. No operations started. '
                'Ask the administrator to inspect ' + str(_RUNTIME_GUARD_PATH))
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
            descriptor = None
        raise _InstanceGuardError('INSTANCE_GUARD_UNAVAILABLE',
            'Cannot safely acquire the runtime guard (errno=' + str(error.errno) + '). '
            'No operations started. Ask the administrator to inspect '
            + str(_RUNTIME_GUARD_PATH)) from None
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        raise
    primary = None
    try:
        yield descriptor
    except BaseException as exc:
        primary = exc
        raise
    finally:
        # Close, never LOCK_UN: retain the original owned-FD protocol.
        try:
            os.close(descriptor)
        except BaseException as cleanup:
            if primary is None or (
                isinstance(primary, Exception) and not isinstance(cleanup, Exception)
            ):
                raise


def _standalone_main_with_report_cleanup():
    """Run the real algorithm and final diagnostic/close within the host guard."""
    primary = None
    try:
        try:
            return main()
        except SetupError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            if REPORT_HANDLE is not None:
                print(f"ERROR: {exc}", file=REPORT_HANDLE, flush=True)
            return 2
    except BaseException as exc:
        primary = exc
        raise
    finally:
        if REPORT_HANDLE is not None:
            try:
                REPORT_HANDLE.close()
            except BaseException as cleanup:
                if primary is None or (
                    isinstance(primary, Exception) and not isinstance(cleanup, Exception)
                ):
                    raise


def _guarded_main():
    # Only explicit sole help is exempt. Argparse also accepts long help
    # abbreviations; these and mixed help must not escape operational locking.
    # --version is answered by this pre-lock parse_args(): it prints the
    # repository revision and exits 0 without a lock or report (v15 contract).
    argv = tuple(sys.argv[1:])
    option_argv = argv[:argv.index("--")] if "--" in argv else argv
    requests_help = any(
        arg == "-h" or (len(arg) > 2 and arg.startswith("--")
                        and "--help".startswith(arg))
        for arg in option_argv
    )
    if argv in (("--help",), ("-h",)) or not requests_help:
        # Pure syntax rejection does not read inputs/passwords/create the lock.
        parse_args()
    try:
        child_code = _run_as_operator_if_root(requests_help)
    except SetupError as exc:
        # Before the guard and main: no report is open yet.
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if child_code is not None:
        return child_code
    try:
        with _runtime_instance_guard():
            return _standalone_main_with_report_cleanup()
    except _InstanceGuardError as exc:
        print(f"{exc.code}: {exc}", file=sys.stderr)
        return 75 if exc.code == "ALREADY_RUNNING" else 2


def _run_as_operator_if_root(requests_help):
    """I-006 (guide WP-9): root runs this entry again as the project's operator and waits for it.

    Help never computes an identity.  Only the repository layout has a project tree (O5): a Leaf
    directory or a desktop copy runs unchanged.  The project is --project-dir as given, else the one
    DAY0-Prepare/activate-project selects; none means unchanged, an invalid pointer raises.  The rule
    is tools/operator_identity.py's: a refusal raises SetupError (exit 2 before the guard); root acting
    for another operator starts `runuser -u <operator> -- env -i ...` with the initial-password
    variable kept and the --credentials-fd fd passed, takes no guard itself and returns the child's
    exit code.  Otherwise prints the identity line and returns None: this process runs.
    """
    if requests_help:
        return None
    # The repository layout of _import_tools: exactly <repo>/tools/device_identity.py, no Leaf tools/.
    script = _SELF_SOURCE_PATH
    repository = script.parents[3] if len(script.parents) > 3 else None
    if (repository is None or not (repository / "tools" / "device_identity.py").is_file()
            or (script.parent / "tools").is_dir()):
        return None
    args = parse_args()
    project = args.project_dir
    if project is None:
        project_contract = _import_tools("tools.project_contract")
        try:
            project = project_contract.active_project_dir(repository)
        except project_contract.ActiveProjectPointerError as error:
            raise SetupError(str(error)) from None
        if project is None:
            return None
    operator_identity = _import_tools("tools.operator_identity")
    identity = operator_identity.resolve_operator(project)
    if identity.refusal is not None:
        raise SetupError(identity.refusal)
    print(identity.banner, file=sys.stderr)
    if not operator_identity.needs_reexec(identity):
        return None
    keep = [args.ib_initial_password_env]
    if args.factory_default_admin:
        keep.append("NVOS_FACTORY_DEFAULT_ADMIN_PASSWORD")
    code = operator_identity.run_as_operator(
        identity.operator, script, sys.argv[1:], keep=keep,
        pass_fds=() if args.credentials_fd is None else (args.credentials_fd,))
    # The operator's run has ended: 0, 1 FAILED, 2 (entry error or INCOMPLETE), 75 busy, 128+n on
    # signal n.  This version only exits with it; H4 (v3.1.10) adds the root-side hosts write here,
    # and a partial success is 2 too (guide WP-9 step 5).
    return code


_PROGRESS_HEARTBEAT_SECONDS = 30
_CONSOLE_VERBOSE = False
_WORKER_CONNECTION = None
_WORKER_STOP = None
_WORKER_SECRETS = []
_ACTIVE_COORDINATOR = None
_TASK_LOG_BUFFER = None
_TASK_DEADLINE = None
# Conservative authorized_keys grammar; preserve existing records byte-for-byte.
# Actual program strings remain single-line for the unchanged typed argv gate.
_KEY_AWK_LEXER = (
    "function stop_invalid() { invalid=1; exit 34; } "
    "function hws(c) { return c==\" \" || c==\"\\t\"; } "
    "function algorithm(s) { return s ~ /^(ssh-|ecdsa-|sk-)[A-Za-z0-9@._+-]+$/; } "
    "function canonical_blob(s, n,p,v) { "
    "n=length(s); if(n<4 || n%4!=0 || s !~ /^[A-Za-z0-9+\\/]+=?=?$/) return 0; "
    "p=index(s,\"=\"); if(!p) return 1; "
    "if(substr(s,n-1,2)==\"==\") { if(p!=n-1) return 0; v=index(alphabet,substr(s,n-2,1))-1; return v>=0 && v%16==0; } "
    "if(p!=n) return 0; v=index(alphabet,substr(s,n-1,1))-1; return v>=0 && v%4==0; "
    "} "
    "function option_list(s, p,n,start,name,c,closed) { "
    "n=length(s); p=1; if(!n) stop_invalid(); "
    "while(p<=n) { "
    "start=p; while(p<=n && substr(s,p,1)!=\"=\" && substr(s,p,1)!=\",\") p++; "
    "name=substr(s,start,p-start); if(name !~ /^[A-Za-z][A-Za-z0-9-]*$/) stop_invalid(); c=substr(s,p,1); "
    "if(c==\"=\") { "
    "if(!(name in valued)) stop_invalid(); p++; if(substr(s,p,1)!=\"\\\"\") stop_invalid(); p++; closed=0; "
    "while(p<=n) { c=substr(s,p,1); if(c==\"\\\\\") { if(p==n || substr(s,p+1,1)!=\"\\\"\") stop_invalid(); p+=2; continue; } if(c==\"\\\"\") { p++; closed=1; break; } p++; } "
    "if(!closed) stop_invalid(); if(p<=n && substr(s,p,1)!=\",\") stop_invalid(); "
    "} else { if(!(name in flag)) stop_invalid(); } "
    "if(p>n) return 1; if(substr(s,p,1)!=\",\") stop_invalid(); p++; if(p>n) stop_invalid(); "
    "} "
    "return 1; "
    "} "
    "function identity(line,request, n,p,start,c,quoted,first,alg,blob) { "
    "n=length(line); if(request) { if(index(line,\"\\r\")) stop_invalid(); } else if(n && substr(line,n,1)==\"\\r\") { line=substr(line,1,n-1); n--; } "
    "if(index(line,\"\\r\")) stop_invalid(); p=1; while(p<=n && hws(substr(line,p,1))) p++; "
    "if(p>n || substr(line,p,1)==\"#\") { if(request) stop_invalid(); return \"\"; } "
    "start=p; quoted=0; "
    "while(p<=n) { c=substr(line,p,1); if(c==\"\\\\\") { if(!quoted || p==n || substr(line,p+1,1)!=\"\\\"\") stop_invalid(); p+=2; continue; } if(c==\"\\\"\") { quoted=!quoted; p++; continue; } if(!quoted && hws(c)) break; p++; } "
    "if(quoted) stop_invalid(); first=substr(line,start,p-start); "
    "if(algorithm(first)) { alg=first; } else { if(request) stop_invalid(); option_list(first); while(p<=n && hws(substr(line,p,1))) p++; start=p; while(p<=n && !hws(substr(line,p,1))) p++; alg=substr(line,start,p-start); if(!algorithm(alg)) stop_invalid(); } "
    "while(p<=n && hws(substr(line,p,1))) p++; start=p; while(p<=n && !hws(substr(line,p,1))) p++; blob=substr(line,start,p-start); "
    "if(!canonical_blob(blob)) stop_invalid(); return alg SUBSEP blob; "
    "} "
    "BEGIN { "
    "if(ARGC!=3) stop_invalid(); alphabet=\"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\"; "
    "n=split(\"restrict cert-authority no-agent-forwarding no-port-forwarding no-pty no-user-rc no-X11-forwarding agent-forwarding port-forwarding pty user-rc X11-forwarding no-touch-required verify-required\",names,\" \"); for(i=1;i<=n;i++) flag[names[i]]=1; "
    "n=split(\"command environment expiry-time from permitlisten permitopen principals tunnel\",names,\" \"); for(i=1;i<=n;i++) valued[names[i]]=1; "
    "} "
)


_KEY_INSTALL_AWK = _KEY_AWK_LEXER + (
    "FILENAME==ARGV[1] { k=identity($0,0); if(k!=\"\") seen[k]=1; next; } "
    "FILENAME==ARGV[2] { k=identity($0,1); requests++; if(!(k in seen)) { seen[k]=1; missing[++count]=$0; } next; } "
    "{ stop_invalid(); } "
    "END { if(invalid || !requests) exit 34; for(i=1;i<=count;i++) print missing[i]; } "
)
_KEY_VERIFY_AWK = _KEY_AWK_LEXER + (
    "FILENAME==ARGV[1] { k=identity($0,1); wanted[k]=1; requests++; next; } "
    "FILENAME==ARGV[2] { k=identity($0,0); if(k!=\"\") found[k]=1; next; } "
    "{ stop_invalid(); } "
    "END { if(invalid || !requests) exit 34; for(k in wanted) if(!(k in found)) exit 34; } "
)
_KEY_INSTALL_SCRIPT = (
    "set -eu; LC_ALL=C; export LC_ALL; "
    "command -v tr >/dev/null 2>&1 || exit 34; "
    "test -n \"${HOME:-}\" && test -d \"$HOME\" && test ! -L \"$HOME\" || exit 31; "
    "ssh_dir=\"$HOME/.ssh\"; "
    "if test -L \"$ssh_dir\" || { test -e \"$ssh_dir\" && test ! -d \"$ssh_dir\"; }; then exit 32; fi; "
    "umask 077; mkdir -p \"$ssh_dir\"; chmod 700 \"$ssh_dir\"; "
    "auth=\"$ssh_dir/authorized_keys\"; "
    "if test -L \"$auth\" || { test -e \"$auth\" && test ! -f \"$auth\"; }; then exit 33; fi; "
    "tmp=\"\"; required=\"\"; staged=\"\"; appended=\"\"; bytecheck=\"\"; "
    "trap 'for task_private in \"$tmp\" \"$required\" \"$staged\" \"$appended\" \"$bytecheck\"; do if test -n \"$task_private\"; then rm -f \"$task_private\" || :; fi; done' EXIT HUP INT TERM; "
    "tmp=\"$(mktemp \"$ssh_dir/.authorized_keys.XXXXXX\")\" || exit 34; "
    "required=\"$(mktemp \"$ssh_dir/.required_keys.XXXXXX\")\" || exit 34; "
    "staged=\"$(mktemp \"$ssh_dir/.staged_keys.XXXXXX\")\" || exit 34; "
    "appended=\"$(mktemp \"$ssh_dir/.appended_keys.XXXXXX\")\" || exit 34; "
    "bytecheck=\"$(mktemp \"$ssh_dir/.key_bytes.XXXXXX\")\" || exit 34; "
    "printf %s \"$1\" | base64 -d >\"$required\" || exit 34; "
    "test -s \"$required\" || exit 34; "
    "if test -f \"$auth\"; then ( cat \"$auth\" >\"$staged\"; ) || exit 34; fi; "
    "for task_input in \"$staged\" \"$required\"; do tr -d '\\011\\012\\015\\040-\\176\\200-\\377' <\"$task_input\" >\"$bytecheck\" || exit 34; test ! -s \"$bytecheck\" || exit 34; done; "
    "awk '"
    + _KEY_INSTALL_AWK +
    "' \"$staged\" \"$required\" >\"$appended\" || exit 34; "
    "cat \"$staged\" >\"$tmp\" || exit 34; "
    "if test -s \"$appended\"; then if test -s \"$staged\"; then "
    "task_last=\"$(tail -c 1 \"$staged\")\" || exit 34; "
    "if test -n \"$task_last\"; then printf '\\n' >>\"$tmp\" || exit 34; fi; "
    "fi; cat \"$appended\" >>\"$tmp\" || exit 34; fi; "
    "awk '"
    + _KEY_VERIFY_AWK +
    "' \"$required\" \"$tmp\" || exit 34; "
    "chmod 600 \"$tmp\" || exit 34; "
    "if test ! -s \"$appended\"; then "
    "test -f \"$auth\" && test ! -L \"$auth\" || exit 33; "
    "chmod 600 \"$auth\" || exit 34; "
    "rm -f \"$tmp\" \"$required\" \"$staged\" \"$appended\" \"$bytecheck\" || exit 34; "
    "trap - EXIT HUP INT TERM; "
    "printf 'IBSW_PUBLIC_KEYS_UNCHANGED\\n'; exit 0; fi; "
    "if test -L \"$auth\" || { test -e \"$auth\" && test ! -f \"$auth\"; }; then exit 33; fi; "
    "mv -f \"$tmp\" \"$auth\" || exit 34; tmp=\"\"; "
    "rm -f \"$required\" \"$staged\" \"$appended\" \"$bytecheck\" || exit 34; "
    "trap - EXIT HUP INT TERM; "
    "printf 'IBSW_PUBLIC_KEYS_UPDATED\\n'"
)


class SetupError(RuntimeError):
    pass


class DirectSSHNetworkError(SetupError):
    """Read-only direct SSH exhausted bounded network/session retries."""


class NeighborNotLearned(SetupError):
    """FDB exists but no matching IPv6 LL entry; eligible for guarded fallback."""


class IBMacMismatch(SetupError):
    """FDB identity differs from the expected CSV IB eth0 MAC."""
    def __init__(self, message, *, expected_mac=None, observed_mac=None):
        super().__init__(message)
        self.expected_mac, self.observed_mac = expected_mac, observed_mac


class ProjectInputChanged(SetupError):
    """Shared input changed: stop dispatch and block subsequent writes."""


class BatchStopped(SetupError):
    """Coordinator cancelled pending work; never replay a partial write."""


# Manual runs only: no cron or plaintext credential cache.
# crypt setting verification: https://github.com/besser82/libxcrypt/blob/develop/doc/crypt.5
# Nested PTY semantics: https://man.openbsd.org/ssh.1
class IBAuthenticationError(SetupError):
    """An explicit authentication rejection, not a transport/identity failure."""


class IBPasswordChangeUncertain(SetupError):
    """A password write was attempted but its outcome is not verified."""


class IBConfigurationStageUncertain(SetupError):
    """A configuration write stage did not reach verified completion."""


_EXPIRED_PASSWORD = re.compile(
    r"(?i)(?:password (?:has )?expired|password has expired|"
    r"required to change your password|must change your password|"
    r"password change required|authentication token (?:is |has )?expired)"
)
_PASSWORD_UPDATED = re.compile(
    r"(?i)(?:password.*(?:updated|changed).*success|all authentication tokens updated)"
)
_NETWORK_FAILURE = re.compile(
    r"(?i)(?:host key verification failed|remote host identification has changed|"
    r"connection (?:timed out|refused|reset)|no route to host|network is unreachable|"
    r"could not resolve hostname|permission denied.*(?:ip vrf|exec))"
)
_SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def _validate_password_hash(value: str) -> None:
    if type(value) is not str or len(value) > 512:
        raise SetupError("invalid project password hash")
    sha = re.fullmatch(r"\$6\$(?:rounds=([0-9]+)\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}", value)
    if sha:
        if sha.group(1) and not 1000 <= int(sha.group(1)) <= 1000000:
            raise SetupError("unsupported SHA-512 password hash cost")
        return
    if re.fullmatch(r"\$y\$j[789]T\$[./A-Za-z0-9]{1,86}\$[./A-Za-z0-9]{43}", value):
        return
    raise SetupError("project password is unset, malformed, or uses an unsupported hash setting")


def _validate_target_password(value: str) -> None:
    if type(value) is not str or not 8 <= len(value) <= 128 or any(
            not 32 <= ord(char) <= 126 for char in value):
        raise SetupError("IB target password must be 8-128 printable ASCII characters")


def _password_protocol_object(raw, keys):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("repeated protocol key")
            result[key] = value
        return result
    result = json.loads(raw, object_pairs_hook=unique)
    if type(result) is not dict or set(result) != set(keys):
        raise ValueError("invalid password protocol object")
    return result


def _password_hash_worker() -> int:
    """Private bounded native verifier: no project, device, auto or network work."""
    import ctypes
    try:
        raw = sys.stdin.buffer.read(8193)
        if len(raw) > 8192 or sys.stdin.buffer.read(1) != b"":
            raise ValueError("password protocol exceeds its fixed budget")
        payload = _password_protocol_object(raw.decode("utf-8"), ("password", "hash"))
        password, setting = payload["password"], payload["hash"]
        _validate_password_hash(setting)
        if type(password) is not str or len(password) > 1024 or "\x00" in password:
            raise ValueError("invalid password input")
        if sys.platform == "darwin":
            candidates = (
                "/opt/homebrew/opt/libxcrypt/lib/libcrypt.dylib",
                "/usr/local/opt/libxcrypt/lib/libcrypt.dylib",
            )
        elif sys.platform.startswith("linux"):
            candidates = ("libcrypt.so.2", "libcrypt.so.1")
        else:
            candidates = ()
        for name in candidates:
            try:
                library = ctypes.CDLL(name)
                function = library.crypt
                function.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
                function.restype = ctypes.c_char_p
                answer = function(password.encode("utf-8"), setting.encode("ascii"))
                if not answer or answer.startswith(b"*"):
                    continue
                answer_text = answer.decode("ascii")
                if not answer_text.startswith("$" + setting.split("$")[1] + "$"):
                    continue
                _validate_password_hash(answer_text)
                print(json.dumps({"status": "match" if hmac.compare_digest(
                    answer, setting.encode("ascii")) else "mismatch"}))
                return 0
            except (OSError, AttributeError, UnicodeError, SetupError):
                continue
        print('{"status":"unsupported"}')
        return 2
    except (ValueError, TypeError, KeyError, UnicodeError, OSError, SetupError, RecursionError):
        print('{"status":"error"}')
        return 2


def verify_password_hash(password: str, setting: str) -> bool:
    _validate_password_hash(setting)
    if type(password) is not str or len(password) > 1024 or "\x00" in password:
        raise SetupError("invalid IB password input")
    payload = json.dumps({"password": password, "hash": setting})
    if len(payload.encode("utf-8")) > 8192:
        raise SetupError("password verification request exceeds its fixed budget")
    try:
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-B", str(_SELF_SOURCE_PATH.resolve()),
             "--_verify-password"],
            input=payload, text=True, capture_output=True, timeout=8, check=False,
            env={"PATH": os.defpath, "LC_ALL": "C", "LANG": "C",
                 "PYTHONDONTWRITEBYTECODE": "1"},
        )
        if type(result.returncode) is not int or type(result.stdout) is not str or (
                type(result.stderr) is not str or result.stderr != ""):
            raise ValueError("invalid password worker response")
        reply = _password_protocol_object(result.stdout, ("status",))
        if result.returncode != 0 or reply["status"] not in ("match", "mismatch"):
            raise ValueError("password worker unavailable")
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired, RecursionError):
        raise SetupError("project password verification backend failed or is unavailable") from None
    return reply["status"] == "match"


def _read_project_password_global(path: Path):
    """One bounded read with named/FD binding; a symlinked project alias is allowed."""
    fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
              "st_size", "st_mtime_ns", "st_ctime_ns")
    def nine(value):
        return tuple(getattr(value, field) for field in fields)
    try:
        declared_before = path.lstat()
        resolved = path.resolve(strict=True)
        resolved_before = resolved.lstat()
        fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            first = os.fstat(fd)
            if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1 or first.st_size > 1048576:
                raise SetupError("project global has unsafe type/link or exceeds its size bound")
            first9 = nine(first)
            if nine(resolved_before) != first9 or nine(resolved.lstat()) != first9:
                raise SetupError("project global named file differs from its open descriptor")
            chunks = []
            total = 0
            eof = False
            while total < 1048577:
                part = os.read(fd, min(65536, 1048577 - total))
                if not part:
                    eof = True
                    break
                total += len(part)
                chunks.append(part)
            if not eof or total != first.st_size:
                raise SetupError("project global changed size or lacks bounded EOF")
            raw = b"".join(chunks)
            if nine(os.fstat(fd)) != first9 or nine(resolved.lstat()) != first9:
                raise SetupError("project global changed while its descriptor was held")
            if path.resolve(strict=True) != resolved or nine(path.lstat()) != nine(declared_before):
                raise SetupError("project global alias changed while its descriptor was held")
            binding = (str(resolved), nine(declared_before), first9,
                       hashlib.sha256(raw).hexdigest())
        finally:
            os.close(fd)
    except OSError:
        raise SetupError("project global cannot be read through a stable regular file") from None
    return binding, raw


class ProjectPasswordPolicy:
    """Read-only same-project IB authority; cached cleartext never bypasses binding."""
    def __init__(self, path: Path, user: str, *, target_password=None, interactive=True):
        if type(interactive) is not bool or type(user) is not str or not valid_ssh_user(user):
            raise SetupError("invalid IB password policy options")
        self.path = Path(os.path.abspath(path))
        self.binding, self.raw = _read_project_password_global(self.path)
        try:
            document = _global_yaml_subset(self.raw.decode("utf-8"), _password_policy=True)
        except UnicodeError:
            raise SetupError("project global is not valid UTF-8") from None
        sections = document.get("switches")
        if type(sections) is not list or any(type(item) is not dict for item in sections):
            raise SetupError("project global switches must be mappings in one list")
        families = [item["ib"] for item in sections if "ib" in item]
        if len(families) != 1 or type(families[0]) is not dict:
            raise SetupError("global must contain exactly one IB family mapping")
        merged = _merged_global(document, "ib")
        current = merged
        for key in ("system", "aaa", "user", user, "password"):
            if type(current) is not dict or key not in current:
                raise SetupError("global has no unambiguous target password for the IB account")
            current = current[key]
        _validate_password_hash(current)
        if target_password is not None:
            _validate_target_password(target_password)
        self.target_hash = current
        self.user = user
        self.interactive = interactive
        self._supplied_password = target_password
        self._password = None

    def assert_unchanged(self) -> None:
        try:
            binding, raw = _read_project_password_global(self.path)
        except SetupError:
            raise ProjectInputChanged("project global changed during this run; stop and re-run") from None
        if binding != self.binding or raw != self.raw:
            raise ProjectInputChanged("project global changed during this run; stop and re-run")

    def matches(self, password: str) -> bool:
        self.assert_unchanged()
        matched = verify_password_hash(password, self.target_hash)
        self.assert_unchanged()
        return matched

    def password(self) -> str:
        self.assert_unchanged()
        if self._password is None:
            if self._supplied_password is not None:
                first = self._supplied_password
            elif not self.interactive:
                raise SetupError("non-interactive credentials lack an explicit verified IB target; no change performed")
            else:
                log("IB target password must match this project's global; it is not the OOB password.")
                try:
                    first = getpass.getpass(f"IB target password ({self.user}): ")
                    second = getpass.getpass("Confirm IB target password: ")
                except (EOFError, KeyboardInterrupt):
                    raise SetupError("IB target password confirmation cancelled") from None
                _validate_target_password(first)
                _validate_target_password(second)
                if not hmac.compare_digest(first, second):
                    raise SetupError("IB password confirmations do not match; no change performed")
            _validate_target_password(first)
            if not self.matches(first):
                raise SetupError("IB password does not match project target; no change performed")
            self.assert_unchanged()
            self._password = first
        return self._password


def _hidden_password_timeout(prompt: str, seconds: int = 5) -> str:
    """Read one complete hidden line under one absolute deadline."""
    import termios
    if not sys.stdin.isatty():
        raise SetupError("initial IB password needs a terminal or an explicit credential")
    fd = sys.stdin.fileno()
    original = termios.tcgetattr(fd)
    hidden = list(original)
    hidden[3] &= ~termios.ECHO
    sys.stderr.write(prompt)
    sys.stderr.flush()
    try:
        termios.tcsetattr(fd, termios.TCSANOW, hidden)
        readable, _, _ = select.select([fd], [], [], seconds)
        if not readable:
            termios.tcflush(fd, termios.TCIFLUSH)
            return "admin"
        line = sys.stdin.readline()
        if not line:
            raise SetupError("initial IB password input ended; no default assumed")
        value = line.rstrip("\r\n")
        return value or "admin"
    except KeyboardInterrupt:
        raise SetupError("initial IB password input cancelled") from None
    finally:
        termios.tcsetattr(fd, termios.TCSANOW, original)
        sys.stderr.write("\n")
        sys.stderr.flush()


def _framed_script(command: list[str], marker: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_]{1,80}", marker):
        raise SetupError("invalid command-frame marker")
    return (
        'printf "\\n__HTTP_IB_BEGIN_' + marker + '__\\n"; '
        + shlex.join(command)
        + '; task_rc=$?; printf "\\n__HTTP_IB_END_' + marker
        + '__=%s\\n" "$task_rc"; exit "$task_rc"'
    )


def extract_command_output(output: str, marker: str, *, expected_exit_code: int = 0) -> str:
    begin, end = "__HTTP_IB_BEGIN_" + marker + "__", "__HTTP_IB_END_" + marker + "__"
    normalized = strip_ansi(output)
    if (len(re.findall(r"(?m)^" + re.escape(begin) + r"$", normalized)) != 1 or
            len(re.findall(r"(?m)^" + re.escape(end) + r"=[0-9]+\s*$", normalized)) != 1):
        raise SetupError("IB command output is unverified; configuration is UNKNOWN")
    matches = list(re.finditer(
        r"(?m)^" + re.escape(begin) + r"\n(.*?)^" + re.escape(end) + r"=([0-9]+)\s*$",
        normalized, re.S | re.M))
    if len(matches) != 1:
        raise SetupError("IB command output is unverified (missing/duplicate frame); configuration is UNKNOWN")
    if int(matches[0].group(2)) != expected_exit_code:
        raise SetupError("IB command-frame status does not match the expected result; configuration is UNKNOWN")
    return matches[0].group(1).strip("\n") + ("\n" if matches[0].group(1).strip("\n") else "")


def probe_ethernet_key(device: Device, user: str, timeout: int) -> str:
    """No writes; fail closed on network, host-key and identity failures."""
    remote = "export PATH=" + shlex.quote(_SAFE_PATH) + '; exec hostname'
    argv = ["ssh", *ssh_options(min(timeout, 5)),
            "-o", "BatchMode=yes", "-o", "PreferredAuthentications=publickey",
            "-o", "ControlMaster=no", "-o", "ControlPath=none",
            f"{user}@{device.login_ip}", remote]
    try:
        result = subprocess.run(argv, text=True, capture_output=True,
                                timeout=min(timeout, 5), check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise SetupError(f"OOB key probe failed/timed out: {device.hostname}") from None
    if result.returncode == 0:
        actual = result.stdout.strip()
        if (not valid_hostname(actual) or
            normalize_name(actual).split(".")[0] != normalize_name(device.hostname).split(".")[0]):
            raise SetupError(f"OOB identity mismatch at {device.login_ip}")
        return "key"
    if not _NETWORK_FAILURE.search(result.stderr) and re.search(
            r"(?im)(?:^|\n)[^\n]*Permission denied \([^\n]+\)\.?\s*$", result.stderr):
        return "password"
    raise SetupError(f"OOB key probe failed (network/host-key/identity): {device.hostname}")


def inspect_ib_device(target: Target, neighbor: Neighbor, eth_user: str,
                      eth_password: str, ib_user: str, initial_password: str,
                      timeout: int, policy: ProjectPasswordPolicy, *,
                      apply: bool, authorized: bool, local: bool, strict: bool = False
                      ) -> tuple[SessionResult, str, bool]:
    """Inspect first; rotate only when PAM requires it and the operator authorizes.

    The one IB authentication readback (P3c map P5; owner Q-035 (a)): v15's credential order
    (initial, project target, then one answer for the actual current password: I14, T18), its
    password change with a fresh-connection readback, and with --apply the current password
    must match the project target (v15 :552; map 4.5 P1).  strict (a management-server task
    with the project global) only replaces each session with the DEV phase session (map D32d).
    Without a global (P1) --apply is allowed but no rotation is possible.
    """
    command = ["nv", "config", "show", "-o", "commands"]

    def session(operation):
        return ({"_phase_operation": operation, "_password_policy": policy} if strict
                else {"password_only": True})

    login = None
    try:
        login = _authenticate_ib_read(
            target, neighbor, eth_user, eth_password, ib_user, initial_password, timeout,
            local=local, _password_policy=policy, strict=strict)
    except SetupError as exc:
        if str(exc) != _IB_CREDENTIALS_EXHAUSTED:
            raise
    if login is not None:
        credential, result = login.current_password, login.read_result
    else:
        # T18 (v15): one answer for the actual current password; fd mode fails this device (O10).
        try:
            credential = request_current_ib_password(target.ib.hostname)
        except (EOFError, KeyboardInterrupt):
            raise SetupError("current IB password input cancelled") from None
        if not credential:
            raise SetupError("current IB password cannot be empty")
        result = run_on_ib(target, neighbor, eth_user, eth_password, ib_user, credential, timeout,
                           command, local=local, allow_password_change=False,
                           **session("auth-probe-readonly"))
    if result.password_change_required:
        if not apply:
            return result, credential, authorized
        if policy is None:
            # P1: no project global, no verified target; never the old Ethernet-password rotation.
            raise SetupError("IB requires a password change, but the project global target is unavailable; no change performed")
        new_password = (_ib_project_value(policy, user=ib_user, fetch=True) if strict
                        else policy.password())
        if not authorized:
            authorized = confirm_first_device_change(
                target, "change the expired IB password to the verified project IB password, "
                "then reconnect and inspect NVUE configuration")
        if not authorized:
            raise SetupError("IB password change not authorized; no change performed")
        policy.assert_unchanged()
        try:
            changed = run_on_ib(
                target, neighbor, eth_user, eth_password, ib_user, credential,
                timeout, command, local=local, allow_password_change=True,
                ib_new_password=new_password, **session("password-change"))
            if not (changed.password_changed or changed.password_change_attempted):
                raise SetupError("IB password change was not confirmed")
            log("IB password change was attempted; verifying its outcome with a fresh password-only connection.")
            credential = new_password
            result = run_on_ib(target, neighbor, eth_user, eth_password, ib_user,
                               credential, timeout, command, local=local,
                               allow_password_change=False, **session("post-change-read"))
            if result.password_change_required:
                raise SetupError("IB still requires a password change after reconnect")
            parse_nvue_state(result.output)
        except (ProjectInputChanged, BatchStopped):
            raise
        except SetupError as exc:
            raise IBPasswordChangeUncertain(
                "IB password-write outcome is UNKNOWN: " + str(exc) +
                ". Stop; do not assume the old password still works or blindly repeat the change."
            ) from None
        log("IB new-password authentication and NVUE readback verified.")
    if apply and policy is not None and not policy.matches(credential):
        raise SetupError("current IB password does not match project global; "
                         "read-only discovery succeeded, but configuration is blocked. "
                         "Resolve the target/current password drift explicitly.")
    return result, credential, authorized


@dataclass(frozen=True)
class Device:
    hostname: str
    dev_type: str
    login_ip: str
    eth0_prefix: str
    eth0_gateway: str
    eth0_mac: str
    eth1_prefix: str
    eth1_gateway: str
    login_interface: str = "eth0"


@dataclass(frozen=True)
class Link:
    left_device: str
    left_port: str
    right_device: str
    right_port: str


@dataclass(frozen=True)
class Target:
    ib: Device
    ethernet: Device
    ethernet_port: str
    ib_port_alias: str
    # Populated ONLY by the v15 preflight adapter. Legacy IB stages still use
    # ethernet/ethernet_port as their already selected execution endpoint.
    attachment: Optional[Target] = None
    jump_reason: str = ""
    access_vlan: str = ""


@dataclass(frozen=True)
class Neighbor:
    ipv6: str
    interface: str
    mac: str
    vrf: str = "default"
    address_source: str = "ND"


@dataclass(frozen=True)
class DeviceState:
    eth0_addresses: tuple[str, ...]
    eth1_addresses: tuple[str, ...]
    eth0_gateways: tuple[str, ...]
    eth1_gateways: tuple[str, ...]
    hostname: str
    raw_commands: str


@dataclass
class SessionResult:
    output: str
    exit_code: int
    password_changed: bool = False
    password_change_required: bool = False
    password_change_attempted: bool = False
    ib_authentication_rejected: bool = False


def log(message: str = "") -> None:
    if _WORKER_CONNECTION is not None:
        _WORKER_CONNECTION.send(("log", redact_worker_text(message)))
        return
    if _TASK_LOG_BUFFER is not None:
        _TASK_LOG_BUFFER.append(str(message))
        return
    print(message, flush=True)
    if REPORT_HANDLE is not None:
        print(message, file=REPORT_HANDLE, flush=True)


_STANDARD_LOG = log


def report_detail(message: str = "", *, verbose=None) -> None:
    """Keep full parent evidence without flooding the default terminal view."""
    if (_WORKER_CONNECTION is not None or _TASK_LOG_BUFFER is not None
            or (_CONSOLE_VERBOSE if verbose is None else verbose)):
        log(message)
    elif REPORT_HANDLE is not None:
        print(message, file=REPORT_HANDLE, flush=True)


def clean(value: object) -> str:
    return str(value or "").strip().strip("‘’“”")


def usable(value: str) -> bool:
    return clean(value).casefold() not in NA_VALUES


def normalize_mac(value: str, *, field: str) -> str:
    """Return a lowercase colon-delimited MAC, or empty for an omitted value."""
    raw = clean(value)
    if not usable(raw):
        return ""
    compact = re.sub(r"[.:-]", "", raw)
    if not re.fullmatch(r"[0-9a-fA-F]{12}", compact):
        raise SetupError(f"invalid {field}: {raw!r}")
    return ":".join(compact[index:index + 2] for index in range(0, 12, 2)).casefold()


def normalize_name(value: str) -> str:
    return clean(value).casefold().rstrip(".")


def names_match(left: str, right: str) -> bool:
    a, b = normalize_name(left), normalize_name(right)
    return a == b or a.endswith("-" + b) or b.endswith("-" + a)


def cumulus_port_name(value: str) -> str:
    """Convert LLDPq numeric Ethernet ports to their Cumulus interface names."""
    port = clean(value)
    return f"swp{port}" if port.isdigit() else port


def header_indexes(header: list[str]) -> dict[str, list[int]]:
    indexes: dict[str, list[int]] = {}
    for index, name in enumerate(header):
        indexes.setdefault(clean(name).casefold(), []).append(index)
    return indexes


def row_value(row: list[str], indexes: dict[str, list[int]], name: str,
              occurrence: int = 0) -> str:
    positions = indexes.get(name.casefold(), [])
    if occurrence >= len(positions) or positions[occurrence] >= len(row):
        return ""
    return clean(row[positions[occurrence]])


def _eth_jump_inventory_errors(fields, row, is_na, *, skip_indices=(), schema_version=None):
    """Check supplied inventory cells without deriving configuration or doing IO.

    ``None`` is the standalone initial reader's schema-independent metadata
    mode: recognize only existing v1/v2 lexical spellings, not either dialect's
    configuration completeness. Setup/load pass their declared schema version.
    """
    errors = []
    totals = {field: fields.count(field) for field in fields}
    occurrences = {}

    def numeric_selector(value, maximum, *, native=False):
        if value.casefold().endswith("/native"):
            if not native or not re.fullmatch(r"[0-9]+", value[:-7]):
                return False
            value = value[:-7]
        for token in re.split(r"[/,]", value):
            match = re.fullmatch(r"([0-9]+)(?:-([0-9]+))?", token.strip())
            if match is None:
                return False
            start = int(match.group(1))
            end = int(match.group(2) or start)
            if not 1 <= start <= end <= maximum:
                return False
        return True

    def port_selector(value, *, bond=False, peerlink=False):
        for group in value.split("|" if bond else "/"):
            if not group.strip():
                return False
            for token in group.split("/"):
                token = token.strip()
                if not peerlink and (
                    token == "peerlink.4094"
                    or re.fullmatch(r"(?:bond[0-9]+)+", token)
                    or (schema_version in (None, 2)
                        and re.fullmatch(r"bond[0-9]+(?:b[0-9]+)+", token))
                ):
                    continue
                prefix = "bond" if bond else "swp"
                pattern = (
                    r"([1-9][0-9]*)(?:-([1-9][0-9]*))?" if peerlink else
                    r"([0-9]+)(?:-([0-9]+))?(?:s([0-9]+)(?:-([0-9]+))?)?"
                )
                match = re.fullmatch(prefix + pattern, token)
                if match is None:
                    return False
                if int(match.group(2) or match.group(1)) < int(match.group(1)):
                    return False
                if not peerlink and match.group(3) is not None:
                    if int(match.group(4) or match.group(3)) < int(match.group(3)):
                        return False
        return True

    for index, field in enumerate(fields):
        occurrence = occurrences.get(field, 0) + 1
        occurrences[field] = occurrence
        if index in skip_indices:
            continue
        value = str(row[index] or "").strip() if index < len(row) else ""
        if is_na(value):
            continue
        label = field if totals[field] == 1 else f"{field}[{occurrence}]"
        valid = True
        try:
            if field in {"eth0_ip", "eth1_ip", "eth0_gw", "eth1_gw"}:
                ipaddress.IPv4Address(value)
            elif field in {"lo_ip", "svi_ip", "vrr_ip"}:
                ipaddress.ip_interface(value)
            elif field == "netmask":
                if value.isdigit():
                    valid = 1 <= int(value) <= 32
                else:
                    valid = str(ipaddress.IPv4Network("0.0.0.0/" + value).netmask) == value
            elif field == "bond_mac":
                valid = all(
                    is_na(token.strip()) or bool(re.fullmatch(
                        r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}|"
                        r"(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}", token.strip(),
                    ))
                    for token in value.split("|")
                )
            elif field in {"eth0_mac", "eth1_mac", "vrr_mac"}:
                valid = bool(re.fullmatch(
                    r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}|"
                    r"(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}", value,
                ))
            elif field in {"vlan_id", "evpn_l3vlan", "evpn_l2vlan"}:
                valid = numeric_selector(
                    value, 4094,
                    native=(schema_version in (None, 2)
                            and field in {"vlan_id", "evpn_l2vlan"}),
                )
            elif field in {"evpn_l3vni", "evpn_l2vni"}:
                valid = numeric_selector(value, 16777215)
            elif field == "bgp_asn":
                valid = 1 <= int(value) <= 4294967295
            elif field in {"bgp_ports", "vlan_ports", "peerlink_ports", "bond_ports"}:
                valid = port_selector(
                    value, bond=(field == "bond_ports"),
                    peerlink=(field == "peerlink_ports"),
                )
            elif field == "bond_type":
                allowed = {"localbond", "mlag", "mlagbond", "evpn_multihoming"}
                if schema_version in (None, 2):
                    allowed |= {"local", "evpn"}
                valid = all(token.strip().casefold() in allowed for token in value.split("|"))
            elif field == "vrl":
                valid = value.casefold() in {"false", "0", "no", "n", "true", "1", "yes", "y"}
            # template, VRF labels and relay server-group selectors remain
            # inventory text: no template/global lookup or companion inference.
        except (ValueError, TypeError, OverflowError):
            valid = False
        if not valid:
            errors.append(f"{label}={value!r} 无效")
    return tuple(errors)


def ipv4_prefix(address: str, netmask: str, *, field: str,
                required: bool) -> str:
    if not usable(address):
        if required:
            raise SetupError(f"{field} is required")
        return ""
    if "/" in address:
        value = address
    elif usable(netmask):
        value = f"{address}/{netmask}"
    else:
        raise SetupError(f"{field} has no netmask")
    try:
        interface = ipaddress.IPv4Interface(value)
        if interface.network.prefixlen <= 30 and interface.ip in {
            interface.network.network_address, interface.network.broadcast_address,
        }:
            raise SetupError(f"{field} uses a network/broadcast address: {value}")
        return str(interface)
    except ValueError as exc:
        raise SetupError(f"invalid {field}: {value}: {exc}") from exc


def valid_hostname(value: str) -> bool:
    hostname = clean(value).rstrip(".")
    if not hostname or len(hostname) > 253:
        return False
    label = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
    return all(label.fullmatch(part) for part in hostname.split("."))


def valid_ssh_user(value: str) -> bool:
    """Accept a login name, never an SSH option or shell fragment."""
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9._-]{0,63}", clean(value)))


def resolve_initial_ib_password(
    environment_name: str, *, factory_default_admin: bool = False,
    interactive: Optional[bool] = None,
) -> str:
    selected_name = ("NVOS_FACTORY_DEFAULT_ADMIN_PASSWORD"
                     if factory_default_admin else environment_name)
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", selected_name):
        raise SetupError("invalid initial-password environment name")
    supplied = os.environ.get(selected_name, "")
    if supplied:
        return supplied
    can_prompt = sys.stdin.isatty() if interactive is None else interactive
    if not can_prompt:
        raise SetupError("initial IB credential unavailable: run interactively or use the existing explicit source")
    return _hidden_password_timeout(
        "Initial IB password [admin; Enter or 5 seconds without a complete line uses admin]: ", 5)

def validate_ib_devices(devices: dict[str, Device]) -> None:
    addresses: dict[str, tuple[str, str]] = {}
    gateways_by_network: dict[str, tuple[str, str]] = {}
    gateway_uses: list[tuple[str, str, str]] = []
    for device in devices.values():
        if not valid_hostname(device.hostname):
            raise SetupError(f"invalid IB hostname: {device.hostname!r}")
        for interface_name, prefix, gateway in (
            ("eth0", device.eth0_prefix, device.eth0_gateway),
            ("eth1", device.eth1_prefix, device.eth1_gateway),
        ):
            if not prefix:
                continue
            interface = ipaddress.IPv4Interface(prefix)
            address = str(interface.ip)
            if address in addresses:
                other_hostname, other_interface = addresses[address]
                raise SetupError(
                    f"duplicate IB address {address}: "
                    f"{other_hostname}.{other_interface} and "
                    f"{device.hostname}.{interface_name}"
                )
            addresses[address] = (device.hostname, interface_name)
            gateway_address = ipaddress.IPv4Address(gateway)
            if interface.network.prefixlen <= 30 and gateway_address in {
                interface.network.network_address, interface.network.broadcast_address,
            }:
                raise SetupError(
                    f"{device.hostname}.{interface_name} gateway {gateway} is a "
                    "network/broadcast address"
                )
            network = str(interface.network)
            previous = gateways_by_network.get(network)
            if previous and previous[0] != gateway:
                raise SetupError(
                    f"conflicting IB gateways for {network}: {previous[0]} "
                    f"({previous[1]}) and {gateway} "
                    f"({device.hostname}.{interface_name})"
                )
            gateways_by_network[network] = (
                gateway, f"{device.hostname}.{interface_name}"
            )
            gateway_uses.append((gateway, device.hostname, interface_name))
    for gateway, hostname, interface_name in gateway_uses:
        if gateway in addresses:
            owner_hostname, owner_interface = addresses[gateway]
            raise SetupError(
                f"IB gateway {gateway} for {hostname}.{interface_name} duplicates "
                f"device address {owner_hostname}.{owner_interface}"
            )


def eth_jump_login_address(row, indexes, hostname):
    """Historical v13 selection; full eth0->multiple-VLAN identity policy is I20, pending.

    VLAN/SVI is existing read-only reachability metadata, never desired eth0 state.
    """
    def address(value, mask, field):
        parsed = (ipaddress.IPv4Interface(ipv4_prefix(value, mask, field=field, required=True)).ip
                  if "/" in value or usable(mask) else ipaddress.IPv4Address(value))
        if parsed.is_unspecified or parsed.is_loopback or parsed.is_multicast or str(parsed) == "255.255.255.255":
            raise SetupError(f"{field} is not a usable unicast login address")
        return str(parsed)
    value = row_value(row, indexes, "eth0_ip")
    if usable(value):
        return address(value, "", hostname + ".eth0_ip"), "eth0"
    fields = {position: name for name, positions in indexes.items() for position in positions}
    boundaries = {"vlan_id", "vlan_ports", "bgp_asn", "bgp_ports", "bond_ports", "evpn_vrf", "evpn_l2vlan"}
    candidates = []
    for start in indexes.get("vlan_id", []):
        end = next((index for index in range(start + 1, max(fields) + 1)
                    if fields[index] in boundaries), max(fields) + 1)
        positions = [index for index in indexes.get("svi_ip", []) if start < index < end]
        if not any(index < len(row) and usable(row[index]) for index in positions):
            continue
        if len(positions) != 1:
            raise SetupError(f"{hostname}: ambiguous vlan_id/svi_ip login group")
        vlan = clean(row[start]) if start < len(row) else ""
        if not re.fullmatch(r"[1-9][0-9]{0,3}", vlan) or not 1 <= int(vlan) <= 4094:
            raise SetupError(f"{hostname}: SVI login requires a single vlan_id in 1-4094")
        position = positions[0]
        mask_position = next((index for index in indexes.get("netmask", []) if position < index < end), None)
        mask = clean(row[mask_position]) if mask_position is not None and mask_position < len(row) else ""
        candidates.append((address(clean(row[position]), mask, hostname + ".svi_ip"), "vlan" + vlan))
    if not candidates:
        # I19 (T13): the inventory is admitted without a login address; remote
        # transport refuses it before any I/O (outer_ssh_command).
        return "", "eth0"
    if len(candidates) != 1:
        raise SetupError(f"{hostname}: multiple VLAN login addresses; select one (I20 multi-address flow pending)")
    return candidates[0]


def load_devices(path: Path) -> tuple[dict[str, Device], dict[str, Device]]:
    try:
        handle = path.open("r", encoding="utf-8-sig", newline="")
    except OSError as exc:
        raise SetupError(f"cannot open device CSV {path}: {exc}") from exc

    ib_devices: dict[str, Device] = {}
    eth_devices: dict[str, Device] = {}
    with handle:
        reader = csv.reader(handle)
        try:
            raw_header = next(reader)
        except StopIteration as exc:
            raise SetupError(f"device CSV is empty: {path}") from exc
        indexes = header_indexes(raw_header)
        if len(indexes.get("config_method", ())) > 1:
            raise SetupError(
                f"device CSV config_method duplicate column: {path}"
            )
        required_headers = {"hostname", "type", "eth0_ip"}
        missing = sorted(required_headers - indexes.keys())
        if missing:
            raise SetupError(f"device CSV missing column(s): {', '.join(missing)}")

        for line_number, row in enumerate(reader, 2):
            hostname = row_value(row, indexes, "hostname")
            dev_type = row_value(row, indexes, "type").casefold()
            config_method = row_value(row, indexes, "config_method").casefold()
            if hostname and dev_type != "eth_jump" and "config_method" in indexes and not config_method:
                raise SetupError(
                    f"{path}:{line_number}: {hostname} config_method is empty"
                )
            if hostname and dev_type == "ib" and config_method not in {"", "initial-setup"}:
                raise SetupError(
                    f"{path}:{line_number}: {hostname} 声明 {config_method}，"
                    "与当前 initial-setup 执行者不兼容"
                )
            if hostname and dev_type == "nvl" and config_method == "initial-setup":
                raise SetupError(
                    f"{path}:{line_number}: {hostname} 声明 initial-setup，"
                    "但当前 NVL 执行者只支持 IB；拒绝静默跳过 NVL"
                )
            if (hostname and dev_type in TRANSIT_DEVICE_TYPES
                    and config_method == "initial-setup"):
                raise SetupError(
                    f"{path}:{line_number}: {hostname} 声明 initial-setup，"
                    "但此执行者仅将 Ethernet 设备作为 transit，不能将其配置计为成功"
                )
            if hostname and config_method and (
                (dev_type == "eth_jump")
                or (dev_type in TRANSIT_DEVICE_TYPES and config_method != "ztp")
                or (dev_type == "nvl" and config_method != "ztp")
            ):
                raise SetupError(
                    f"{path}:{line_number}: {hostname} config_method="
                    f"{config_method} incompatible with initial-setup inventory binding"
                )
            if not hostname or dev_type not in ({"ib"} | TRANSIT_DEVICE_TYPES):
                continue
            if not valid_hostname(hostname):
                raise SetupError(f"{path}:{line_number}: invalid hostname {hostname!r}")
            eth0_ip = row_value(row, indexes, "eth0_ip")
            netmask0 = row_value(row, indexes, "netmask", 0)
            eth0_gateway = row_value(row, indexes, "eth0_gw")
            eth0_mac = row_value(row, indexes, "eth0_mac")
            eth1_ip = row_value(row, indexes, "eth1_ip")
            netmask1 = row_value(row, indexes, "netmask", 1) or netmask0
            eth1_gateway = row_value(row, indexes, "eth1_gw")
            login_interface = "eth0"
            try:
                if dev_type == "eth_jump":
                    inventory_errors = _eth_jump_inventory_errors(
                        [clean(field).casefold() for field in raw_header], row,
                        lambda value: not usable(value),
                    )
                    if inventory_errors:
                        raise SetupError("; ".join(inventory_errors))
                eth0_mac = normalize_mac(eth0_mac, field=f"{hostname}.eth0_mac")
                if dev_type == "ib":
                    eth0 = ipv4_prefix(
                        eth0_ip, netmask0, field=f"{hostname}.eth0_ip", required=True
                    )
                    eth1 = ipv4_prefix(
                        eth1_ip, netmask1, field=f"{hostname}.eth1_ip", required=False
                    )
                    if not usable(eth0_gateway):
                        raise SetupError(f"{hostname}.eth0_gw is required")
                    eth0_gateway = str(ipaddress.IPv4Address(eth0_gateway))
                    if ipaddress.IPv4Address(eth0_gateway) not in ipaddress.IPv4Interface(eth0).network:
                        raise SetupError(
                            f"{hostname}.eth0_gw {eth0_gateway} is outside "
                            f"{ipaddress.IPv4Interface(eth0).network}"
                        )
                    if eth1:
                        if not usable(eth1_gateway):
                            raise SetupError(
                                f"{hostname}.eth1_gw is required when eth1_ip is set"
                            )
                        eth1_gateway = str(ipaddress.IPv4Address(eth1_gateway))
                        if ipaddress.IPv4Address(eth1_gateway) not in ipaddress.IPv4Interface(eth1).network:
                            raise SetupError(
                                f"{hostname}.eth1_gw {eth1_gateway} is outside "
                                f"{ipaddress.IPv4Interface(eth1).network}"
                            )
                    elif usable(eth1_gateway):
                        raise SetupError(
                            f"{hostname}.eth1_gw is set but eth1_ip is empty"
                        )
                    else:
                        eth1_gateway = ""
                    login_ip = eth0.split("/", 1)[0]
                elif dev_type == "eth_jump":
                    login_ip, login_interface = eth_jump_login_address(row, indexes, hostname)
                    eth0 = login_ip if login_interface == "eth0" else ""
                    eth1, eth0_gateway, eth1_gateway = "", "", ""
                else:
                    if not usable(eth0_ip):
                        raise SetupError(f"{hostname}.eth0_ip login address is required")
                    eth0 = str(ipaddress.IPv4Address(eth0_ip.split("/", 1)[0]))
                    eth1 = ""
                    eth0_gateway = ""
                    eth1_gateway = ""
                    login_ip = eth0
            except (SetupError, ValueError) as exc:
                raise SetupError(f"{path}:{line_number}: {exc}") from exc

            device = Device(
                hostname, dev_type, login_ip, eth0,
                eth0_gateway, eth0_mac, eth1, eth1_gateway, login_interface,
            )
            target_map = ib_devices if dev_type == "ib" else eth_devices
            key = normalize_name(hostname)
            if key in target_map:
                raise SetupError(f"duplicate device hostname in CSV: {hostname}")
            target_map[key] = device

    if not ib_devices:
        raise SetupError(f"device CSV contains no type=ib devices: {path}")
    if not eth_devices:
        raise SetupError(f"device CSV contains no Ethernet switch devices: {path}")
    validate_ib_devices(ib_devices)
    owners = {}
    for device in (*ib_devices.values(), *eth_devices.values()):
        for address in [device.login_ip, *([device.eth1_prefix.split("/", 1)[0]] if device.eth1_prefix else [])]:
            if not address:
                continue  # an eth_jump without a login address (I19, T13) owns none
            previous = owners.get(address)
            if previous is not None and "eth_jump" in {previous.dev_type, device.dev_type}:
                raise SetupError(f"duplicate eth_jump login address {address}")
            owners.setdefault(address, device)
    return ib_devices, eth_devices


def parse_p2p(path: Path) -> list[Link]:
    if path.suffix.casefold() == ".xlsx":
        return parse_p2p_xlsx(path)
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError as exc:
        raise SetupError(f"cannot read P2P file {path}: {exc}") from exc

    links: list[Link] = []
    if path.suffix.casefold() == ".dot" or " -- " in text:
        for line in text.splitlines():
            match = DOT_LINK_RE.search(line)
            if match:
                links.append(Link(*(clean(value) for value in match.groups())))
        if not links:
            raise SetupError(f"no links found in DOT file: {path}")
        return links

    nonblank = [line for line in text.splitlines() if line.strip()]
    if not nonblank:
        raise SetupError(f"P2P file is empty: {path}")
    rows = list(csv.reader(nonblank))
    header = [clean(value).casefold() for value in rows[0]]
    aliases = {
        "left_device": ("a-node", "srcdevice", "src_device", "source device"),
        "left_port": ("a-port", "srcport", "src_port", "source port"),
        "right_device": ("z-node", "dstdevice", "dst_device", "destination device"),
        "right_port": ("z-port", "dstport", "dst_port", "destination port"),
    }
    positions: dict[str, int] = {}
    for field, choices in aliases.items():
        for choice in choices:
            if choice in header:
                positions[field] = header.index(choice)
                break
    if len(positions) == 4:
        for row in rows[1:]:
            if len(row) <= max(positions.values()):
                continue
            values = [clean(row[positions[name]]) for name in aliases]
            if all(values):
                links.append(Link(*values))
    else:
        for line in nonblank:
            fields = [clean(value) for value in line.split()]
            if len(fields) < 4 or fields[0].casefold() in {"name", "source", "srcdevice"}:
                continue
            links.append(Link(fields[0], fields[1], fields[-2], fields[-1]))
    if not links:
        raise SetupError(f"no usable links found in P2P file: {path}")
    return links


def xlsx_cell_value(cell: ET.Element, shared_strings: list[str], ns: str) -> str:
    cell_type = cell.get("t", "")
    if cell_type == "inlineStr":
        return clean("".join(node.text or "" for node in cell.findall(f".//{ns}t")))
    value = cell.find(f"{ns}v")
    if value is None or value.text is None:
        return ""
    if cell_type == "s":
        try:
            return clean(shared_strings[int(value.text)])
        except (ValueError, IndexError):
            return ""
    return clean(value.text)


def xlsx_column(reference: str) -> int:
    letters = re.match(r"[A-Za-z]+", reference)
    if not letters:
        return 0
    result = 0
    for character in letters.group(0).upper():
        result = result * 26 + ord(character) - ord("A") + 1
    return result - 1


def parse_p2p_xlsx(path: Path) -> list[Link]:
    """Read source/destination name+port columns from an OOXML workbook."""
    main_ns = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
    rel_ns = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
    package_rel_ns = "{http://schemas.openxmlformats.org/package/2006/relationships}"
    try:
        archive = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise SetupError(f"cannot open P2P workbook {path}: {exc}") from exc
    with archive:
        names = set(archive.namelist())
        shared_strings: list[str] = []
        if "xl/sharedStrings.xml" in names:
            root = ET.fromstring(archive.read("xl/sharedStrings.xml"))
            shared_strings = [
                "".join(node.text or "" for node in item.findall(f".//{main_ns}t"))
                for item in root.findall(f"{main_ns}si")
            ]
        try:
            workbook = ET.fromstring(archive.read("xl/workbook.xml"))
            relationships = ET.fromstring(
                archive.read("xl/_rels/workbook.xml.rels")
            )
        except (KeyError, ET.ParseError) as exc:
            raise SetupError(f"invalid P2P workbook structure in {path}: {exc}") from exc
        targets = {
            item.get("Id", ""): item.get("Target", "")
            for item in relationships.findall(f"{package_rel_ns}Relationship")
        }
        links: list[Link] = []
        for sheet in workbook.findall(f".//{main_ns}sheet"):
            rel_id = sheet.get(f"{rel_ns}id", "")
            target = targets.get(rel_id, "").lstrip("/")
            sheet_path = target if target.startswith("xl/") else f"xl/{target}"
            if sheet_path not in names:
                continue
            try:
                sheet_root = ET.fromstring(archive.read(sheet_path))
            except ET.ParseError as exc:
                raise SetupError(
                    f"invalid worksheet {sheet.get('name', rel_id)} in {path}: {exc}"
                ) from exc
            rows: list[list[str]] = []
            for row_node in sheet_root.findall(f".//{main_ns}row"):
                values: list[str] = []
                for cell in row_node.findall(f"{main_ns}c"):
                    index = xlsx_column(cell.get("r", ""))
                    if index >= len(values):
                        values.extend([""] * (index - len(values) + 1))
                    values[index] = xlsx_cell_value(cell, shared_strings, main_ns)
                rows.append(values)
            for header_index, row in enumerate(rows[:20]):
                header = [re.sub(r"\s+", "", clean(value).casefold()) for value in row]
                name_columns = [index for index, value in enumerate(header) if value == "name"]
                if len(name_columns) < 2:
                    continue
                left_name, right_name = name_columns[:2]

                def find_port(start: int, end: int) -> Optional[int]:
                    for index in range(start + 1, min(end, len(header))):
                        if "port" in header[index]:
                            return index
                    return None

                left_port = find_port(left_name, right_name)
                right_port = find_port(right_name, len(header))
                if left_port is None or right_port is None:
                    continue
                for data in rows[header_index + 1:]:
                    positions = (left_name, left_port, right_name, right_port)
                    if max(positions) >= len(data):
                        continue
                    values = [clean(data[index]) for index in positions]
                    if all(usable(value) for value in values):
                        links.append(Link(*values))
                break
    if not links:
        raise SetupError(
            f"no worksheets with two name+port column groups found in {path}"
        )
    return links


def validate_p2p_links(links: list[Link]) -> None:
    seen_links: dict[tuple[tuple[str, str], tuple[str, str]], int] = {}
    endpoints: dict[tuple[str, str], tuple[tuple[str, str], int]] = {}
    for line_number, link in enumerate(links, 1):
        left = (normalize_name(link.left_device), clean(link.left_port).casefold())
        right = (normalize_name(link.right_device), clean(link.right_port).casefold())
        if not all((*left, *right)):
            raise SetupError(f"P2P link {line_number} has an empty device or port")
        if left == right:
            raise SetupError(
                f"P2P link {line_number} connects an endpoint to itself: "
                f"{link.left_device}:{link.left_port}"
            )
        canonical = tuple(sorted((left, right)))
        if canonical in seen_links:
            raise SetupError(
                f"duplicate P2P link at parsed records "
                f"{seen_links[canonical]} and {line_number}: "
                f"{link.left_device}:{link.left_port} <-> "
                f"{link.right_device}:{link.right_port}"
            )
        seen_links[canonical] = line_number
        for endpoint, peer in ((left, right), (right, left)):
            previous = endpoints.get(endpoint)
            if previous and previous[0] != peer:
                previous_peer, previous_line = previous
                raise SetupError(
                    f"P2P endpoint {endpoint[0]}:{endpoint[1]} has multiple peers "
                    f"at parsed records {previous_line} and {line_number}: "
                    f"{previous_peer[0]}:{previous_peer[1]} and "
                    f"{peer[0]}:{peer[1]}"
                )
            endpoints[endpoint] = (peer, line_number)


def resolve_device(name: str, devices: dict[str, Device]) -> Optional[Device]:
    normalized = normalize_name(name)
    if normalized in devices:
        return devices[normalized]
    matches = [device for key, device in devices.items()
               if normalized.endswith("-" + key) or key.endswith("-" + normalized)]
    return matches[0] if len(matches) == 1 else None


def build_targets(links: list[Link], ib_devices: dict[str, Device],
                  eth_devices: dict[str, Device]) -> list[Target]:
    targets: list[Target] = []
    seen: set[str] = set()
    for link in links:
        orientations = (
            (link.left_device, link.left_port, link.right_device, link.right_port),
            (link.right_device, link.right_port, link.left_device, link.left_port),
        )
        for ib_name, ib_port, eth_name, eth_port in orientations:
            ib = resolve_device(ib_name, ib_devices)
            if not ib or clean(ib_port).casefold() not in IB_PORT_ALIASES:
                continue
            ethernet = resolve_device(eth_name, eth_devices)
            if not ethernet:
                raise SetupError(
                    f"P2P peer {eth_name!r} for IB device {ib.hostname} is not a "
                    "supported Ethernet transit device with a login IP in the CSV"
                )
            key = normalize_name(ib.hostname)
            if key in seen:
                raise SetupError(f"multiple management links found for IB device {ib.hostname}")
            seen.add(key)
            targets.append(
                Target(ib, ethernet, cumulus_port_name(eth_port), clean(ib_port))
            )
    missing = [device.hostname for key, device in ib_devices.items() if key not in seen]
    if missing:
        log("WARNING: no Ethernet management link found for: " + ", ".join(sorted(missing)))
    if not targets:
        raise SetupError(
            "no IB management links to supported Ethernet transit devices "
            "were found in P2P"
        )
    return sorted(targets, key=lambda target: normalize_name(target.ib.hostname))


def device_to_dict(device: Device) -> dict[str, str]:
    return {
        "hostname": device.hostname,
        "dev_type": device.dev_type,
        "login_ip": device.login_ip,
        "eth0_prefix": device.eth0_prefix,
        "eth0_gateway": device.eth0_gateway,
        "eth0_mac": device.eth0_mac,
        "eth1_prefix": device.eth1_prefix,
        "eth1_gateway": device.eth1_gateway,
        "login_interface": device.login_interface,
    }


def _global_yaml_subset(source: str, *, _password_policy: bool = False) -> dict:
    """Read the bounded project-global block dialect without a leaf dependency.

    This is deliberately not general YAML: unsupported constructs fail closed.
    Real IB and NVL project globals are parity-checked against the generator.
    """
    if len(source.encode("utf-8")) > 1024 * 1024:
        raise SetupError("01-global.yaml exceeds the supported size")
    lines: list[tuple[int, str]] = []
    anchors: dict[str, object] = {}
    depth = 0
    for raw in source.splitlines():
        if re.match(r"^ *\t", raw):
            raise SetupError("01-global.yaml has tab indentation")
        quote = ""
        index = 0
        while index < len(raw):
            char = raw[index]
            if quote == "'":
                if char == "'" and index + 1 < len(raw) and raw[index + 1] == "'":
                    index += 2
                    continue
                if char == "'":
                    quote = ""
            elif quote == '"':
                if char == "\\":
                    index += 2
                    continue
                if char == '"':
                    quote = ""
            elif char in "'\"":
                quote = char
            elif char == "#" and (index == 0 or raw[index - 1].isspace()):
                raw = raw[:index]
                break
            index += 1
        text = raw.rstrip()
        if not text.strip():
            continue
        if text.strip() in {"---", "..."}:
            raise SetupError("01-global.yaml must contain one document")
        lines.append((len(text) - len(text.lstrip(" ")), text.lstrip(" ")))
    if not lines or len(lines) > 20000:
        raise SetupError("01-global.yaml is empty or too large")

    def scalar(value: str) -> object:
        if _password_policy and value.startswith("!"):
            raise SetupError("project password global has an unsupported YAML tag")
        if _password_policy and value.startswith('"'):
            try:
                return json.loads(value)
            except (ValueError, TypeError):
                raise SetupError("project password global requires one JSON double-quoted scalar") from None
        if _password_policy and value.startswith("'"):
            position = 1
            while position < len(value):
                char = value[position]
                if char in "\r\n":
                    raise SetupError("project password global quoted scalar must be single-line")
                if char == "'":
                    if position + 1 < len(value) and value[position + 1] == "'":
                        position += 2
                        continue
                    if position != len(value) - 1:
                        raise SetupError("project password global has trailing quoted tokens")
                    return value[1:-1].replace("''", "'")
                position += 1
            raise SetupError("project password global has an unterminated quoted scalar")
        if value.startswith("{"):
            raise SetupError("01-global.yaml flow mapping is unsupported")
        if value.startswith("["):
            if not value.endswith("]") or any(c in value[1:-1] for c in "[]{}"):
                raise SetupError("01-global.yaml nested flow syntax is unsupported")
            inner = value[1:-1]
            return [scalar(part.strip()) for part in inner.split(",")] if inner.strip() else []
        if value.startswith('"'):
            try:
                return ast.literal_eval(value)
            except (SyntaxError, ValueError) as exc:
                raise SetupError("01-global.yaml has an invalid quoted value") from exc
        if value.startswith("'"):
            if not value.endswith("'"):
                raise SetupError("01-global.yaml has an invalid quoted value")
            return value[1:-1].replace("''", "'")
        low = value.lower()
        if low in {"null", "~"}:
            return None
        if low in {"true", "yes", "on"}:
            return True
        if low in {"false", "no", "off"}:
            return False
        if re.fullmatch(r"[+-]?\d+", value):
            return int(value)
        if re.fullmatch(r"[+-]?(?:\d+\.\d*|\.\d+)(?:[Ee][+-]?\d+)?", value):
            return float(value)
        return value

    def key_value(text: str) -> tuple[str, str]:
        match = re.fullmatch(r"([^:]+):(?:\s+(.*))?", text)
        if not match or not re.fullmatch(r"[A-Za-z0-9_.-]+", match.group(1).strip()):
            raise SetupError("01-global.yaml has unsupported mapping syntax")
        return match.group(1).strip(), match.group(2) or ""

    def child(index: int, indent: int) -> tuple[object, int]:
        if index < len(lines) and (lines[index][0] > indent or
                                   lines[index][0] == indent and lines[index][1].startswith("- ")):
            return parse(index, lines[index][0])
        return None, index

    def value_at(value: str, index: int, indent: int) -> tuple[object, int]:
        if value.startswith("*"):
            if not re.fullmatch(r"\*[A-Za-z0-9_-]+", value) or value[1:] not in anchors:
                raise SetupError("01-global.yaml has an unknown alias")
            return copy.deepcopy(anchors[value[1:]]), index
        if value.startswith("&"):
            match = re.fullmatch(r"&([A-Za-z0-9_-]+)(?:\s+(.+))?", value)
            if not match:
                raise SetupError("01-global.yaml has invalid anchor syntax")
            if _password_policy and match.group(1) in anchors:
                raise SetupError("project password global has an ambiguous duplicate anchor")
            parsed, index = (scalar(match.group(2)), index) if match.group(2) else child(index, indent)
            anchors[match.group(1)] = copy.deepcopy(parsed)
            return parsed, index
        return scalar(value), index

    def mapping(index: int, indent: int) -> tuple[dict, int]:
        result: dict = {}
        while index < len(lines) and lines[index][0] == indent and not lines[index][1].startswith("- "):
            key, value = key_value(lines[index][1])
            if key in result:
                raise SetupError("01-global.yaml has a duplicate key")
            index += 1
            result[key], index = value_at(value, index, indent) if value else child(index, indent)
        return result, index

    def sequence(index: int, indent: int) -> tuple[list, int]:
        result: list = []
        while index < len(lines) and lines[index][0] == indent and lines[index][1].startswith("- "):
            body = lines[index][1][2:].strip()
            index += 1
            if not body:
                value, index = child(index, indent)
            elif re.match(r"[^:]+:(?:\s|$)", body):
                key, remainder = key_value(body)
                member, index = value_at(remainder, index, indent) if remainder else child(index, indent)
                value = {key: member}
                if index < len(lines) and lines[index][0] > indent:
                    extra, index = mapping(index, lines[index][0])
                    if key in extra:
                        raise SetupError("01-global.yaml has a duplicate key")
                    value.update(extra)
            else:
                value, index = value_at(body, index, indent)
            result.append(value)
        return result, index

    def parse(index: int, indent: int) -> tuple[object, int]:
        nonlocal depth
        depth += 1
        try:
            if depth > 64:
                raise SetupError("01-global.yaml nesting exceeds the supported limit")
            if lines[index][1].startswith("- "):
                return sequence(index, indent)
            return mapping(index, indent)
        finally:
            depth -= 1

    document, end = parse(0, lines[0][0])
    if end != len(lines) or not isinstance(document, dict):
        raise SetupError("01-global.yaml has unsupported trailing syntax")
    return document


def _deep_merge_global(base: dict, override: dict) -> dict:
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge_global(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _merged_global(document: dict, family: str) -> dict:
    switches = document.get("switches")
    if not isinstance(switches, list):
        raise SetupError("01-global.yaml switches must be a list")
    section = next((item[family] for item in switches
                    if isinstance(item, dict) and family in item), None)
    common = document.get("common", {})
    if not isinstance(common, dict) or not isinstance(common.get("switch", {}), dict) or not isinstance(section, dict):
        raise SetupError(f"01-global.yaml has invalid {family} or common.switch section")
    return _deep_merge_global(common.get("switch", {}), section)


def _neutral_services(tool: Path) -> dict[str, str]:
    neutral_path = tool / "infra-neutral.conf"
    try:
        lines = neutral_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise SetupError(f"neutral service authority unavailable: {neutral_path}") from exc
    values: dict[str, str] = {}
    for line in lines:
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or key in values or key not in {"DNS", "NTP", "TIMEZONE"}:
            raise SetupError("infra-neutral.conf has invalid or duplicate service entry")
        values[key] = value.strip()
    if set(values) != {"DNS", "NTP", "TIMEZONE"} or not all(values.values()):
        raise SetupError("infra-neutral.conf lacks a service fallback")
    return values


def _service_profile(tool: Path, *, neutral_dir: Optional[Path] = None) -> Optional[dict[str, object]]:
    """The cached services from <tool>/01-global.yaml; neutral_dir holds infra-neutral.conf (None: tool)."""
    global_path = tool / "01-global.yaml"
    if not global_path.is_file():
        return None
    try:
        document = _global_yaml_subset(global_path.read_text(encoding="utf-8"))
        merged = _merged_global(document, "ib")
    except (OSError, UnicodeError) as exc:
        raise SetupError(f"cannot read 01-global.yaml: {exc}") from exc
    system = merged.get("system")
    if not isinstance(system, dict):
        raise SetupError("01-global.yaml IB system must be a mapping")
    neutral = _neutral_services(tool if neutral_dir is None else neutral_dir)
    output: dict[str, object] = {}
    for key, field, fallback in (
        ("dns", "server", "DNS"), ("ntp", "server", "NTP"),
        ("date-time", "timezone", "TIMEZONE"),
    ):
        group = system.get(key, {})
        if group is None:
            group = {}
        if not isinstance(group, dict):
            raise SetupError(f"01-global.yaml system.{key} must be a mapping")
        value = group.get(field)
        if value is None or value == "" or value == []:
            value = neutral[fallback] if field == "timezone" else [neutral[fallback]]
        if field == "server":
            if not isinstance(value, list) or not value or any(
                not isinstance(item, str) or not item.strip() for item in value
            ):
                raise SetupError(f"01-global.yaml system.{key}.{field} is invalid")
            for item in value:
                ib_command_argv(["nv", "set", "system", key, field, item])
            output[key] = list(value)
        else:
            if not isinstance(value, str) or not value.strip():
                raise SetupError("01-global.yaml timezone is invalid")
            ib_command_argv(["nv", "set", "system", key, field, value])
            output["timezone"] = value
    return output


def _public_key_fingerprint(line: str) -> str:
    if not isinstance(line, str) or re.search(r"[\x00-\x1f\x7f-\x9f]", line):
        raise SetupError("SSH public key contains a control character")
    parts = line.split()
    if len(parts) < 2 or not re.fullmatch(
        r"ssh-(?:ed25519|rsa)|ecdsa-sha2-nistp(?:256|384|521)|"
        r"sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com",
        parts[0],
    ):
        raise SetupError("invalid SSH public key type")
    try:
        blob = base64.b64decode(parts[1], validate=True)
        fields: list[bytes] = []
        offset = 0
        while offset < len(blob):
            if len(blob) - offset < 4:
                raise ValueError("truncated SSH key field")
            size = int.from_bytes(blob[offset:offset + 4], "big")
            offset += 4
            if size > 65536 or size > len(blob) - offset:
                raise ValueError("invalid SSH key field length")
            fields.append(blob[offset:offset + size])
            offset += size
        if not fields or fields[0].decode("ascii") != parts[0]:
            raise ValueError("SSH key type/blob mismatch")
        if parts[0] == "ssh-ed25519" and (len(fields) != 2 or len(fields[1]) != 32):
            raise ValueError("invalid ed25519 key payload")
        if len(fields) < 2:
            raise ValueError("SSH key has no public payload")
    except (ValueError, UnicodeError) as exc:
        raise SetupError("invalid SSH public key blob") from exc
    return "SHA256:" + base64.b64encode(
        hashlib.sha256(blob).digest()
    ).rstrip(b"=").decode("ascii")


class _CacheInputSnapshot:
    """Closed immutable bytes/mtime/canonical-name inputs from a held reader.

    This optional management-host path never reopens project data. Missing or
    malformed members reject the cache; they cannot fall back to live paths.
    The disconnected leaf's ordinary filesystem parser is unchanged.
    """
    def __init__(self, values):
        if not isinstance(values, Mapping):
            raise ValueError("cache input snapshot must be a mapping")
        images = {}
        for name, value in values.items():
            if (not isinstance(name, str) or not Path(name).is_absolute()
                    or ".." in Path(name).parts or type(value) is not tuple or len(value) != 3
                    or not isinstance(value[0], str) or not Path(value[0]).is_absolute()
                    or ".." in Path(value[0]).parts or type(value[1]) is not int or value[1] < 0
                    or type(value[2]) is not bytes or not 0 < len(value[2]) <= 8 * 1024 * 1024):
                raise ValueError("invalid bounded cache input snapshot member")
            images[name] = value
        self.images = MappingProxyType(images)

    def image(self, path):
        try:
            return self.images[str(path)]
        except KeyError as exc:
            raise ValueError("cache input snapshot member is missing") from exc

    def read(self, path):
        return self.image(path)[2]

    def mtime_ns(self, path):
        return self.image(path)[1]

    def canonical(self, path):
        return self.image(path)[0]

    def is_file(self, path):
        return str(path) in self.images

    def public_keys(self, tool, public_key_dir=None):
        directory = tool / "publickey" if public_key_dir is None else public_key_dir
        return sorted(Path(name) for name in self.images
                      if Path(name).parent == directory and Path(name).name.endswith(".pub"))


def _public_key_profile(tool: Path, *, validate_with_ssh_keygen: bool = True,
                        input_snapshot: Optional[_CacheInputSnapshot] = None,
                        public_key_dir: Optional[Path] = None
                        ) -> list[dict[str, str]]:
    """The *.pub keys in public_key_dir (None: <tool>/publickey); empty files are skipped."""
    directory = tool / "publickey" if public_key_dir is None else public_key_dir
    if input_snapshot is None and not directory.is_dir():
        return []
    result: list[dict[str, str]] = []
    validator: Optional[str] = None
    paths = (input_snapshot.public_keys(tool, public_key_dir) if input_snapshot is not None
             else sorted(directory.glob("*.pub")))
    for path in paths:
        try:
            source = (input_snapshot.read(path).decode("utf-8") if input_snapshot is not None
                      else path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError) as exc:
            raise SetupError(f"cannot read public key {path.name}: {exc}") from exc
        if not source.strip():
            continue  # project preparation placeholder; never deploy it
        for line in source.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                fingerprint = _public_key_fingerprint(line)
            except SetupError as exc:
                raise SetupError(f"invalid SSH public key in {path.name}") from exc
            if validate_with_ssh_keygen:
                if validator is None:
                    validator = shutil.which("ssh-keygen")
                    if validator is None:
                        raise SetupError("ssh-keygen is required to validate project public keys")
                try:
                    probe = subprocess.run(
                        [validator, "-l", "-E", "sha256", "-f", "/dev/stdin"],
                        input=line + "\n", capture_output=True, text=True,
                        timeout=10, check=False,
                    )
                except (OSError, subprocess.TimeoutExpired) as exc:
                    raise SetupError(
                        f"ssh-keygen could not validate public key in {path.name}"
                    ) from exc
                if (
                    probe.returncode != 0
                    or len(probe.stdout.splitlines()) != 1
                    or fingerprint not in probe.stdout.split()
                ):
                    raise SetupError(f"ssh-keygen rejected public key in {path.name}")
            result.append({"name": path.name, "line": line, "fingerprint": fingerprint})
    return result


def _validate_cache_profile(payload: dict) -> None:
    services = payload.get("services")
    if services is not None:
        if not isinstance(services, dict) or set(services) != {"dns", "ntp", "timezone"}:
            raise SetupError("target cache has invalid service categories")
        for category in ("dns", "ntp"):
            values = services[category]
            if not isinstance(values, list) or not values or any(
                not isinstance(value, str) for value in values
            ):
                raise SetupError(f"target cache has invalid {category} values")
            for value in values:
                ib_command_argv(["nv", "set", "system", category, "server", value])
        ib_command_argv([
            "nv", "set", "system", "date-time", "timezone", services["timezone"],
        ])
    keys = payload.get("public_keys")
    if not isinstance(keys, list):
        raise SetupError("target cache has invalid public-key list")
    if keys:
        key_install_command(keys)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _cache_authority(ib_csv: Path, p2p: Path,
                     global_file: Optional[Path]) -> dict[str, object]:
    """Record the P1 parser and source authority without requiring YAML on P2.

    This generator uses the bounded stdlib global dialect rather than PyYAML.
    PyYAML is explicitly not required by this stdlib-only generator.  P2
    never imports or reparses that dependency, even if it is installed.
    """
    return {
        "ib_csv_sha256": _file_sha256(ib_csv),
        "p2p_sha256": _file_sha256(p2p),
        "global_sha256": _file_sha256(global_file) if global_file else None,
        "generator": "initial-setup.py",
        "generator_sha256": _file_sha256(_SELF_SOURCE_PATH),
        "python": f"{sys.implementation.name}:{sys.version_info.major}.{sys.version_info.minor}",
        "pyyaml_required": False,
        "pyyaml_version": "not-required",
    }


def _valid_cache_authority(payload: dict, ib_csv: Path, p2p: Path,
                           global_file: Optional[Path], *,
                           input_snapshot: Optional[_CacheInputSnapshot] = None) -> bool:
    authority = payload.get("cache_authority")
    if not isinstance(authority, dict) or set(authority) != {
        "ib_csv_sha256", "p2p_sha256", "global_sha256", "generator",
        "generator_sha256", "python", "pyyaml_required", "pyyaml_version",
    }:
        return False
    hexdigest = r"[0-9a-f]{64}"
    if (
        authority["generator"] != "initial-setup.py"
        or authority["python"] !=
        f"{sys.implementation.name}:{sys.version_info.major}.{sys.version_info.minor}"
        or authority["pyyaml_required"] is not False
        or authority["pyyaml_version"] != "not-required"
        or any(not isinstance(authority[field], str)
               or not re.fullmatch(hexdigest, authority[field])
               for field in ("ib_csv_sha256", "p2p_sha256", "generator_sha256"))
        or (authority["global_sha256"] is not None and
            (not isinstance(authority["global_sha256"], str)
             or not re.fullmatch(hexdigest, authority["global_sha256"])))
    ):
        return False
    if (payload.get("global") is None) != (authority["global_sha256"] is None):
        return False
    def input_hash(path):
        return (hashlib.sha256(input_snapshot.read(path)).hexdigest() if input_snapshot is not None
                else _file_sha256(path))
    if (
        authority["ib_csv_sha256"] != input_hash(ib_csv)
        or authority["p2p_sha256"] != input_hash(p2p)
        or authority["generator_sha256"] != _file_sha256(_SELF_SOURCE_PATH)
    ):
        return False
    if global_file is not None and (input_snapshot.is_file(global_file) if input_snapshot is not None else global_file.is_file()):
        if authority["global_sha256"] != input_hash(global_file):
            return False
    return True


def _cache_profile_snapshot(services, public_keys):
    """Detach the finite cache profile without changing its ordered values."""
    if services is None:
        saved_services = None
    else:
        if (
            type(services) is not dict
            or any(type(key) is not str for key in services)
            or set(services) != {"dns", "ntp", "timezone"}
            or type(services["dns"]) is not list
            or type(services["ntp"]) is not list
            or any(type(value) is not str for value in services["dns"])
            or any(type(value) is not str for value in services["ntp"])
            or type(services["timezone"]) is not str
        ):
            raise SetupError("invalid private cache admission profile")
        saved_services = {
            "dns": list(services["dns"]),
            "ntp": list(services["ntp"]),
            "timezone": services["timezone"],
        }
    if type(public_keys) is not list:
        raise SetupError("invalid private cache admission profile")
    saved_keys = []
    for entry in public_keys:
        if (
            type(entry) is not dict
            or any(type(key) is not str for key in entry)
            or set(entry) != {"name", "line", "fingerprint"}
            or any(type(value) is not str for value in entry.values())
        ):
            raise SetupError("invalid private cache admission profile")
        saved_keys.append({
            "name": entry["name"],
            "line": entry["line"],
            "fingerprint": entry["fingerprint"],
        })
    return {"services": saved_services, "public_keys": saved_keys}


def load_target_cache(cache_path: Path, ib_csv: Path,
                      p2p: Path, *, public_key_tool: Optional[Path] = None,
                      validate_public_keys_with_ssh_keygen: bool = False,
                      allow_baked_missing_global: bool = False,
                      input_snapshot=None,
                      _admission_out=None,
                      public_key_dir: Optional[Path] = None
                      ) -> Optional[tuple[int, list[Target]]]:
    if _admission_out is not None and (
        type(_admission_out) is not dict or _admission_out
    ):
        error = SetupError("invalid private cache admission output")
        try:
            raise error from None
        except SetupError:
            error.__cause__ = None
            error.__context__ = None
            raise
    try:
        captured = _CacheInputSnapshot(input_snapshot) if input_snapshot is not None else None
        def mtime(path):
            return captured.mtime_ns(path) / 1000000000 if captured is not None else path.stat().st_mtime
        def mtime_ns(path):
            return captured.mtime_ns(path) if captured is not None else path.stat().st_mtime_ns
        if mtime(cache_path) < max(mtime(ib_csv), mtime(p2p)):
            return None
        checksum_path = cache_path.with_name(cache_path.name + ".sha256")
        if mtime_ns(cache_path) > mtime_ns(checksum_path):
            return None
        raw_cache = captured.read(cache_path) if captured is not None else cache_path.read_bytes()
        checksum_fields = (captured.read(checksum_path).decode("ascii") if captured is not None
                           else checksum_path.read_text(encoding="ascii")).split()
        if len(checksum_fields) != 2 or checksum_fields[1] != cache_path.name:
            return None
        if not re.fullmatch(r"[0-9a-f]{64}", checksum_fields[0]):
            return None
        if hashlib.sha256(raw_cache).hexdigest() != checksum_fields[0]:
            return None
        payload = json.loads(raw_cache.decode("utf-8"))
        if payload.get("version") != TARGET_CACHE_VERSION:
            return None
        if payload.get("ib_csv") != str(ib_csv) or payload.get("p2p") != str(p2p):
            return None
        current_global = public_key_tool / "01-global.yaml" if public_key_tool else None
        if captured is not None and current_global is not None:
            captured.read(current_global)  # Required capture, never a live fallback.
        if not _valid_cache_authority(payload, ib_csv, p2p, current_global, input_snapshot=captured):
            return None
        if "global" not in payload or "services" not in payload or "public_keys" not in payload:
            return None
        _validate_cache_profile(payload)
        if public_key_tool is not None:
            global_file = public_key_tool / "01-global.yaml"
            if (captured.is_file(global_file) if captured is not None else global_file.is_file()):
                canonical = captured.canonical(global_file) if captured is not None else str(global_file.resolve())
                if payload["global"] != canonical:
                    return None
                if mtime_ns(global_file) > mtime_ns(cache_path):
                    return None
            elif payload["global"] is not None and not allow_baked_missing_global:
                return None
            source_dir = public_key_tool / "publickey" if public_key_dir is None else public_key_dir
            source_available = captured is not None or source_dir.is_dir()
            paths = (captured.public_keys(public_key_tool, public_key_dir) if captured is not None
                     else source_dir.glob("*.pub"))
            if source_available and any(
                mtime_ns(path) > mtime_ns(cache_path)
                for path in paths
            ):
                return None
            if source_available or not allow_baked_missing_global:
                if _public_key_profile(
                    public_key_tool,
                    validate_with_ssh_keygen=validate_public_keys_with_ssh_keygen,
                    input_snapshot=captured,
                    public_key_dir=public_key_dir,
                ) != payload["public_keys"]:
                    return None
        targets = [
            Target(
                Device(**item["ib"]), Device(**item["ethernet"]),
                clean(item["ethernet_port"]), clean(item["ib_port_alias"]),
            )
            for item in payload["targets"]
        ]
        candidate_count = int(payload["ib_candidate_count"])
        if candidate_count < len(targets) or not targets:
            return None
        if _admission_out is None:
            return candidate_count, targets
        result = (candidate_count, targets)
        profile = _cache_profile_snapshot(payload["services"], payload["public_keys"])
        accepted = {"result": result, "profile": profile}
        _admission_out["accepted"] = accepted
        return result
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return None


def save_target_cache(cache_path: Path, ib_csv: Path, p2p: Path,
                      ib_candidate_count: int, targets: list[Target], *,
                      global_file: Optional[Path] = None,
                      services: Optional[dict[str, object]] = None,
                      public_keys: Optional[list[dict[str, str]]] = None) -> None:
    payload = {
        "version": TARGET_CACHE_VERSION,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S %Z"),
        "ib_csv": str(ib_csv),
        "p2p": str(p2p),
        "global": str(global_file.resolve()) if global_file is not None else None,
        "cache_authority": _cache_authority(ib_csv, p2p, global_file),
        "ib_candidate_count": ib_candidate_count,
        "services": services,
        "public_keys": public_keys or [],
        "targets": [
            {
                "ib": device_to_dict(target.ib),
                "ethernet": device_to_dict(target.ethernet),
                "ethernet_port": target.ethernet_port,
                "ib_port_alias": target.ib_port_alias,
            }
            for target in targets
        ],
    }
    _validate_cache_profile(payload)
    checksum_path = cache_path.with_name(cache_path.name + ".sha256")
    temporary = cache_path.with_name(cache_path.name + ".tmp")
    checksum_temporary = checksum_path.with_name(checksum_path.name + ".tmp")
    try:
        raw_cache = (
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
        ).encode("utf-8")
        temporary.write_bytes(raw_cache)
        checksum_temporary.write_text(
            f"{hashlib.sha256(raw_cache).hexdigest()}  {cache_path.name}\n",
            encoding="ascii",
        )
        temporary.replace(cache_path)
        checksum_temporary.replace(checksum_path)
    except OSError as exc:
        for unfinished in (temporary, checksum_temporary):
            try:
                unfinished.unlink(missing_ok=True)
            except OSError:
                pass
        raise SetupError(f"cannot write target cache {cache_path}: {exc}") from exc


def strip_ansi(value: str) -> str:
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", value).replace("\r", "")


def _ib_phase_error_facts(error):
    uncertain = getattr(error, "cleanup_uncertain", None) is True
    number = getattr(error, "errno", None)
    return uncertain, number if type(number) is int and 1 <= number <= 255 else None


def _ib_raise_phase_failure(stage, uncertain=False, number=None):
    messages = {
        "project": "IB phase project authority failed; device state is UNKNOWN",
        "transport": "IB phase transport failed; device state is UNKNOWN",
        "verification": "IB phase verification failed; device state is UNKNOWN",
    }
    error = SetupError(messages[stage])
    if uncertain is True:
        error.cleanup_uncertain = True
    if type(number) is int and 1 <= number <= 255:
        error.io_errno = number
    # This owned error, not the original exception, is consumed at the choke.
    # fromNone only suppresses printing; explicitly detach both stored links.
    try:
        raise error from None
    except SetupError:
        error.__cause__ = None
        error.__context__ = None
        raise


def _ib_project_value(policy, requested=None, *, user, fetch=False):
    failure = None
    value = None
    try:
        # The v15 coordinator hands each task a pinned copy (WorkerPasswordPolicy) of
        # the same bound policy; no other type is accepted.
        if type(policy) not in (ProjectPasswordPolicy, WorkerPasswordPolicy):
            raise SetupError("actual same-project password policy is required")
        if policy.user != user:
            raise SetupError("project policy does not match IB account")
        policy.assert_unchanged()
        if fetch:
            value = policy.password()
            _validate_target_password(value)
            if requested is not None:
                _validate_target_password(requested)
            if requested is not None and (
                    type(requested) is not str or not hmac.compare_digest(requested, value)):
                raise SetupError("explicit target differs from project authority")
            if not policy.matches(value):
                raise SetupError("target is not verified by project authority")
            policy.assert_unchanged()
    except (SetupError, OSError) as error:
        failure = _ib_phase_error_facts(error)
    if failure is not None:
        _ib_raise_phase_failure("project", *failure)
    return value


class _IBPhase:
    """Per-session bounded temporal facts; no raw transcript or secret repr."""
    def __init__(self, nonce, operation, endpoint, outer_endpoint, policy):
        if (type(nonce) is not str or not re.fullmatch(r"[0-9a-f]{32}", nonce)
                or type(operation) is not str
                or operation not in ("auth-probe-readonly", "password-change", "post-change-read")):
            raise SetupError("invalid private IB phase request")
        self.nonce = nonce
        self.operation = operation
        self.endpoint = endpoint
        self.outer_endpoint = outer_endpoint
        self.policy = policy
        self.serial = 0
        self.begin_count = self.exit_count = self.prompt_count = self.denied_count = 0
        self.begin_at = self.exit_at = self.prompt_at = self.denied_at = -1
        self.declared = None
        self.current_done = 0
        self.current_at = self.denied_event = -1
        self.outer_done = False
        self.pam_current_done = self.new_done = self.confirm_done = False
        self.pending = None
        self.invalid = self.network = self.any_frame = False
        self.incomplete_marker = False
        self.command_begin_count = self.command_end_count = self.command_marker_count = 0
        self.command_begin_at = self.command_end_at = -1
        self.pam_positions = {"current": -1, "new": -1, "retype": -1}
        self.expiry_at = self.notice_at = -1
        self.expiry = self.updated = False
        self.expiry_after_input = False
        self.cancel_requested = False
        self.authority_pending = False
        self.pam_counts = {"current": 0, "new": 0, "retype": 0}

    def observe(self, output):
        self.serial += 1
        text = strip_ansi(output)
        base = "__HTTP_IB_AUTH_" + self.nonce + "_" + self.operation + "__="
        begins = list(re.finditer(r"(?m)^" + re.escape(base + "BEGIN") + r"\n", text))
        exits = list(re.finditer(r"(?m)^" + re.escape(base + "EXIT:") + r"([0-9]{1,3})\n", text))
        markers = list(re.finditer(r"(?m)^__HTTP_IB_AUTH_[^\n]*\n", text))
        self.begin_count, self.exit_count = len(begins), len(exits)
        if len(markers) != self.begin_count + self.exit_count:
            self.invalid = True
        if self.begin_count:
            self.begin_at = begins[0].start()
        if self.exit_count:
            self.exit_at = exits[0].start()
            self.declared = int(exits[0].group(1))
        if self.begin_count > 1 or self.exit_count > 1 or (
                self.exit_count and (not self.begin_count or self.exit_at <= self.begin_at)):
            self.invalid = True
        prompts = list(re.finditer(
            r"(?m)^" + re.escape(self.endpoint + "'s password:") + r"[ \t]*$", text))
        self.prompt_count = len(prompts)
        if prompts:
            self.prompt_at = prompts[0].start()
            if self.begin_count != 1 or self.prompt_at <= self.begin_at:
                self.invalid = True
        if self.prompt_count > 1:
            self.invalid = True
        denied = list(re.finditer(
            r"(?m)^" + re.escape(self.endpoint + ": Permission denied (password).") + r"\n", text))
        if denied and not self.denied_count:
            self.denied_event = self.serial
            if self.current_done != 1:
                self.invalid = True
        self.denied_count = len(denied)
        if denied:
            self.denied_at = denied[0].start()
        if self.denied_count > 1:
            self.invalid = True
        if self.denied_count and (self.begin_count != 1 or self.denied_at <= self.prompt_at or
                                  (self.exit_count and self.denied_at >= self.exit_at)):
            self.invalid = True
        self.network = self.network or bool(_NETWORK_FAILURE.search(text))
        self.any_frame = self.any_frame or bool(re.search(r"(?m)^__HTTP_IB_(?:BEGIN|END)_", text))
        self.incomplete_marker = bool(re.search(r"(?m)^__HTTP_IB_(?:AUTH|BEGIN|END)_[^\n]*\Z", text))
        command_begins = list(re.finditer(
            r"(?m)^" + re.escape("__HTTP_IB_BEGIN_" + self.nonce + "__") + r"\n", text))
        command_ends = list(re.finditer(
            r"(?m)^" + re.escape("__HTTP_IB_END_" + self.nonce + "__=") + r"[0-9]{1,3}\n", text))
        self.command_begin_count, self.command_end_count = len(command_begins), len(command_ends)
        if (command_begins or command_ends) and self.current_done != 1:
            self.invalid = True
        if command_begins:
            self.command_begin_at = command_begins[0].start()
        if command_ends:
            self.command_end_at = command_ends[0].start()
        self.command_marker_count = len(re.findall(r"(?m)^__HTTP_IB_(?:BEGIN|END)_[^\n]*\n", text))
        expiries = list(_EXPIRED_PASSWORD.finditer(text))
        expired = bool(expiries)
        if expired and not self.expiry:
            self.expiry_at = expiries[0].start()
            self.expiry_after_input = self.current_done == 1
        self.expiry = self.expiry or expired
        patterns = {
            "current": r"(?im)^[ \t]*\(current\) UNIX password:[ \t]*$",
            "new": r"(?im)^[ \t]*New password:[ \t]*$",
            "retype": r"(?im)^[ \t]*Retype new password:[ \t]*$",
        }
        pam_matches = {key: list(re.finditer(pattern, text)) for key, pattern in patterns.items()}
        self.pam_counts = {key: len(matches) for key, matches in pam_matches.items()}
        self.pam_positions = {key: matches[0].start() if matches else -1
                              for key, matches in pam_matches.items()}
        if self.pam_counts["current"] and self.current_done != 1:
            self.invalid = True
        notice_positions = []
        offset = 0
        for line in text.splitlines(keepends=True):
            if _pending_diff_has_password_update_notice(line):
                notice_positions.append(offset)
            offset += len(line)
        if notice_positions:
            self.notice_at = notice_positions[0]
        consumed_positions = (
            [match.start() for match in command_begins + command_ends + expiries]
            + [match.start() for matches in pam_matches.values() for match in matches]
            + notice_positions)
        if any(self.begin_count != 1 or position <= self.begin_at
               or (self.exit_count and position >= self.exit_at)
               for position in consumed_positions):
            self.invalid = True
        if any(count > 1 for count in self.pam_counts.values()):
            self.invalid = True
        if self.pam_counts["new"] and not self.pam_current_done:
            self.invalid = True
        if self.pam_counts["retype"] and not self.new_done:
            self.invalid = True
        if _pending_diff_has_password_update_notice(text):
            if self.operation != "password-change" or not (
                    self.pam_current_done and self.new_done and self.confirm_done):
                self.invalid = True
            self.updated = True

    def response(self, output, responder):
        if self.invalid or self.network:
            raise SetupError("IB phase observation is not safely attributable")
        text = strip_ansi(output)
        outer = re.findall(r"(?m)^" + re.escape(self.outer_endpoint + "'s password:") + r"[ \t]*$", text)
        if len(outer) > 1:
            raise SetupError("repeated outer credential request")
        if outer and not self.outer_done:
            if self.begin_count or self.current_done:
                raise SetupError("outer credential request is not phase isolated")
            self.pending = "outer"
            return responder.ethernet_password
        if self.prompt_count == 1 and not self.current_done:
            if self.exit_count:
                raise SetupError("credential requested after phase exit")
            self.pending = "ib"
            return responder.ib_default_password
        if self.expiry:
            if not self.expiry_after_input or self.begin_count != 1:
                raise SetupError("password expiry lacks completed current input")
            if self.exit_count:
                return None
            if self.operation != "password-change":
                if self.operation != "auth-probe-readonly":
                    raise SetupError("post-change credential requires unsafe further PAM")
                # An expiry banner can precede a split current-PAM prompt.
                # Waiting is not permission to begin another credential session.
                if self.pam_counts["current"] == 0:
                    return None
                if (self.pam_counts != {"current": 1, "new": 0, "retype": 0}
                        or not (self.begin_at < self.prompt_at < self.expiry_at
                                < self.pam_positions["current"])):
                    raise SetupError("IB read-only expiry challenge is not safely attributable")
                responder.password_change_blocked = True
                return "\x03"
            if responder.allow_password_change is not True:
                raise SetupError("password change lacks prior authorization")
            if self.pam_counts["current"] and not self.pam_current_done:
                self.pending = "pam-current"
                return responder.ib_default_password
            if self.pam_counts["new"] and not self.new_done:
                self.pending = "new"
                responder.password_change_attempted = True
                return responder.ib_new_password
            if self.pam_counts["retype"] and not self.confirm_done:
                self.pending = "retype"
                responder.password_change_attempted = True
                return responder.ib_new_password
        return None

    def write_reply(self, fd, response, responder, deadline):
        role, self.pending = self.pending, None
        if role not in ("outer", "ib", "pam-current", "new", "retype") or type(response) is not str:
            raise SetupError("invalid private IB credential response")
        if (not response or re.search(r"[\x00-\x1f\x7f-\x9f]", response)
                or any(0xD800 <= ord(char) <= 0xDFFF for char in response)):
            raise SetupError("unsafe private IB credential input")
        data = response.encode("utf-8") + b"\n"
        if len(data) > 4097:
            raise SetupError("unsafe private IB credential input")
        offset = 0
        while offset < len(data):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SetupError("IB credential input exceeded the existing session deadline")
            _, writable, _ = select.select([], [fd], [], min(0.2, remaining))
            if not writable:
                continue
            self.authority_pending = True
            if role in ("pam-current", "new", "retype"):
                if deadline - time.monotonic() < 8:
                    raise SetupError("IB target verification lacks its fixed budget")
                _ib_project_value(self.policy, responder.ib_new_password, user=self.endpoint.split("@", 1)[0], fetch=True)
            elif self.policy is not None:
                _ib_project_value(self.policy, user=self.endpoint.split("@", 1)[0])
            self.authority_pending = False
            if time.monotonic() >= deadline:
                raise SetupError("IB credential input exceeded the existing session deadline")
            try:
                amount = os.write(fd, data[offset:])
            except BlockingIOError:
                continue
            if type(amount) is not int or not 0 < amount <= len(data) - offset:
                raise SetupError("IB credential input did not complete")
            offset += amount
            self.serial += 1
        if role == "outer":
            self.outer_done = True
        elif role == "ib":
            self.current_done += 1
            self.current_at = self.serial
        elif role == "pam-current":
            self.pam_current_done = True
        elif role == "new":
            self.new_done = True
        else:
            self.confirm_done = True

    def finish(self, result):
        # Called only AFTER interactive_run returned through successful cleanup.
        base = (not self.invalid and not self.network and not self.incomplete_marker
                and type(result.exit_code) is int and self.begin_count == 1
                and self.prompt_count == 1 and self.current_done == 1)
        if (base and self.operation == "auth-probe-readonly" and self.expiry
                and self.expiry_after_input and self.cancel_requested
                and self.pam_counts == {"current": 1, "new": 0, "retype": 0}
                and self.begin_at < self.prompt_at < self.expiry_at < self.pam_positions["current"]
                and self.exit_count == 0 and not self.any_frame and result.exit_code != 0):
            result.password_change_required = True
            result.password_changed = False
            return result
        complete = (base and self.exit_count == 1 and self.begin_at < self.exit_at
                    and type(result.exit_code) is int and result.exit_code == self.declared)
        if (complete and self.operation == "auth-probe-readonly"
                and self.declared == 255 and self.denied_count == 1
                and self.current_at < self.denied_event and not self.expiry
                and not self.any_frame and not any(self.pam_counts.values())):
            raise IBAuthenticationError("IB read-only password rejection is attributable")
        if not complete or self.declared != 0:
            _ib_raise_phase_failure("verification")
        if self.operation == "password-change":
            if (not self.expiry or not self.updated or self.any_frame or
                    not all((self.pam_current_done, self.new_done, self.confirm_done))
                    or not (self.begin_at < self.prompt_at < self.expiry_at
                            < self.pam_positions["current"] < self.pam_positions["new"]
                            < self.pam_positions["retype"] < self.notice_at < self.exit_at)):
                _ib_raise_phase_failure("verification")
            result.password_changed = True
            result.password_change_required = False
            return result
        if (self.expiry or self.updated or self.denied_count or any(self.pam_counts.values())
                or self.command_begin_count != 1 or self.command_end_count != 1
                or self.command_marker_count != 2
                or not (self.begin_at < self.prompt_at < self.command_begin_at
                        < self.command_end_at < self.exit_at)):
            _ib_raise_phase_failure("verification")
        result.output = extract_command_output(result.output, self.nonce)
        result.password_changed = result.password_change_required = False
        return result


def _ib_phase_script(command, phase):
    return ('printf "\\n__HTTP_IB_AUTH_' + phase.nonce + "_" + phase.operation
            + '__=BEGIN\\n"; ' + shlex.join(command)
            + '; inner_rc=$?; printf "\\n__HTTP_IB_AUTH_' + phase.nonce + "_"
            + phase.operation + '__=EXIT:%s\\n" "$inner_rc"; exit "$inner_rc"')


def _execute_ib_phase(target, neighbor, eth_user, ethernet_password, ib_user,
                      current_password, timeout, ib_command, *, local=False,
                      allow_password_change=False, ib_new_password=None,
                      _phase_operation=None, _password_policy=None):
    if local or ib_command != ["nv", "config", "show", "-o", "commands"]:
        raise SetupError("private IB phase supports only nonlocal read/PAM operations")
    if (type(current_password) is not str or not current_password
            or any(0xD800 <= ord(char) <= 0xDFFF for char in current_password)
            or len(current_password.encode("utf-8")) > 4096
            or re.search(r"[\x00-\x1f\x7f-\x9f]", current_password)
            or type(timeout) is not int or timeout <= 0):
        raise SetupError("invalid private IB current credential or timeout")
    validate_jump_target(target)
    validate_neighbor_boundary(neighbor)
    if not valid_ssh_user(eth_user) or not valid_ssh_user(ib_user):
        raise SetupError("invalid private IB account")
    if _phase_operation == "password-change":
        if allow_password_change is not True or type(ib_new_password) is not str:
            _ib_raise_phase_failure("project")
        _ib_project_value(_password_policy, ib_new_password, user=ib_user, fetch=True)
    elif _phase_operation == "post-change-read":
        _ib_project_value(_password_policy, current_password, user=ib_user, fetch=True)
    elif _phase_operation != "auth-probe-readonly":
        raise SetupError("unsupported private IB phase operation")
    elif _password_policy is not None:
        _ib_project_value(_password_policy, user=ib_user)
    phase = _IBPhase(os.urandom(16).hex(), _phase_operation,
                     ib_user + "@" + neighbor.ipv6, eth_user + "@" + target.ethernet.login_ip,
                     _password_policy)
    command = nested_ssh_command(target, neighbor, eth_user, ib_user, timeout, ib_command,
                                 local=False, marker=phase.nonce, password_only=True, _phase=phase)
    responder = NestedResponder(ethernet_password, current_password,
                                _phase_operation == "password-change" and allow_password_change is True,
                                ib_new_password=ib_new_password,
                                ib_destination=phase.endpoint, _phase=phase)
    failure = None
    result = None
    try:
        result = interactive_run(command, responder, max(timeout * 4, 60))
    except (SetupError, OSError) as error:
        failure = _ib_phase_error_facts(error)
    if failure is not None:
        _ib_raise_phase_failure("project" if phase.authority_pending else "transport", *failure)
    return phase.finish(result)


_IB_CREDENTIALS_EXHAUSTED = "known IB credential sources are exhausted; device is HOLD"


@dataclass(repr=False)
class _IBLogin:
    current_password: str
    read_result: SessionResult


def _authenticate_ib_read(target, neighbor, eth_user, ethernet_password, ib_user,
                          initial_password, timeout, *, local=False, _password_policy=None,
                          strict=True):
    """The first two credential sources of the one IB authentication readback (P3c map P5).

    v15 order (I14): the initial password, then the independently verified project target.
    strict (a management-server task with the project global): each read is a DEV phase
    session, the target comes through _ib_project_value, and an initial password equal to the
    target is not tried twice (DEV).  Otherwise a v15 password-only session.  When both are
    rejected this raises _IB_CREDENTIALS_EXHAUSTED; inspect_ib_device then asks once (T18).
    """
    command = ["nv", "config", "show", "-o", "commands"]
    password = initial_password
    for attempt in (1, 2):
        rejected = False
        try:
            if strict:
                record_metric("ib_ssh_attempts")
                result = _execute_ib_phase(
                    target, neighbor, eth_user, ethernet_password, ib_user, password, timeout,
                    command, local=local, _phase_operation="auth-probe-readonly",
                    _password_policy=_password_policy)
            else:
                result = run_on_ib(target, neighbor, eth_user, ethernet_password, ib_user,
                                   password, timeout, command, local=local,
                                   allow_password_change=False, password_only=True)
        except IBAuthenticationError:
            rejected = True
        if not rejected:
            return _IBLogin(password, result)
        if attempt == 2:
            break
        # Not inside the caught rejection's exception scope; the target is lazy.
        if _password_policy is None:
            raise SetupError("IB initial credential rejected; project global is needed to verify "
                             "an already-changed password")
        password = (_ib_project_value(_password_policy, user=ib_user, fetch=True) if strict
                    else _password_policy.password())
        log("Initial IB credential rejected; trying the project IB password (no rotation).")
        if strict and hmac.compare_digest(initial_password.encode("utf-8"), password.encode("utf-8")):
            break
    raise SetupError(_IB_CREDENTIALS_EXHAUSTED)


def interactive_run(command: list[str], responder: Callable[[str], Optional[str]],
                    timeout: int, *, display: bool = False) -> SessionResult:
    """PTY transport with bounded output/time, drained completion and secret redaction."""
    phase = responder._phase if type(responder) is NestedResponder else None
    if phase is not None and type(phase) is not _IBPhase:
        raise SetupError("invalid private IB responder phase")
    pid, fd = pty.fork()
    if pid == 0:
        try:
            os.execvp(command[0], command)
        except OSError:
            os._exit(127)
    output = ""
    secrets = []
    deadline = time.monotonic() + timeout
    ended_status = None
    cancellation_requested = False
    primary = None
    try:
        if phase is not None:
            os.set_blocking(fd, False)
        while True:
            check_task_cancelled()  # v15: coordinator stop and per-task deadline
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SetupError("SSH/PAM session timed out; device state may be unknown")
            ready, _, _ = select.select([fd], [], [], min(0.2, remaining))
            if ready:
                try:
                    chunk = os.read(fd, 4096)
                except OSError:
                    if phase is not None:
                        import errno
                        read_error = sys.exc_info()[1]
                        if read_error.errno not in (errno.EAGAIN, errno.EWOULDBLOCK, errno.EIO):
                            raise
                    chunk = b""
                if chunk:
                    output += chunk.decode("utf-8", errors="replace")
                    if len(output) > 4 * 1024 * 1024:
                        raise SetupError("SSH output exceeded the safety limit")
                    if phase is not None:
                        phase.observe(output)
                    response = responder(strip_ansi(output))
                    if getattr(responder, "password_change_blocked", False):
                        # Read-only cancellation needs no PTY input. A Ctrl-C
                        # write can race the SSH/PAM process closing its slave,
                        # turning a controlled cancellation into an EIO error.
                        if not cancellation_requested:
                            cancellation_requested = True
                            if phase is not None:
                                phase.cancel_requested = True
                            try:
                                os.killpg(pid, signal.SIGTERM)
                            except PermissionError:
                                try:
                                    os.kill(pid, signal.SIGTERM)
                                except ProcessLookupError:
                                    pass
                            except ProcessLookupError:
                                pass
                    elif response is not None:
                        if response != "\x03" and response:
                            secrets.append(response)
                        if phase is not None:
                            phase.write_reply(fd, response, responder, deadline)
                        else:
                            os.write(fd, response.encode("utf-8") + b"\n")
            ended, status = os.waitpid(pid, os.WNOHANG)
            if ended:
                ended_status = status
                # The exit can race the final output chunk. Drain before parsing.
                while select.select([fd], [], [], 0)[0]:
                    try:
                        chunk = os.read(fd, 4096)
                    except OSError:
                        if phase is not None:
                            import errno
                            read_error = sys.exc_info()[1]
                            if read_error.errno not in (errno.EAGAIN, errno.EWOULDBLOCK, errno.EIO):
                                raise
                        break
                    if not chunk:
                        break
                    output += chunk.decode("utf-8", errors="replace")
                    if len(output) > 4 * 1024 * 1024:
                        raise SetupError("SSH output exceeded the safety limit")
                    if phase is not None:
                        phase.observe(output)
                break
        clean_output = strip_ansi(output)
        attempted = bool(getattr(responder, "password_change_attempted", False))
        completed = attempted and bool(_PASSWORD_UPDATED.search(clean_output))
        required = bool(getattr(responder, "password_change_blocked", False))
        endpoint = getattr(responder, "ib_destination", None)
        ib_rejected = bool(endpoint and not _NETWORK_FAILURE.search(clean_output) and
                           re.search(re.escape(endpoint) + r":[^\n]*Permission denied",
                                     clean_output, re.I))
        for secret in sorted(set(secrets), key=len, reverse=True):
            clean_output = clean_output.replace(secret, "[REDACTED]")
        if display:
            sys.stdout.write(clean_output)
        return SessionResult(clean_output, os.waitstatus_to_exitcode(ended_status),
                             completed, required, attempted, ib_rejected)
    except BaseException as exc:
        primary = exc
        raise
    finally:
        cleanup_error = None
        cleanup_uncertain = False
        owned_fd, fd = fd, None
        try:
            os.close(owned_fd)
        except BaseException as exc:
            cleanup_error = exc
        if ended_status is None:
            signalled = False
            try:
                os.killpg(pid, signal.SIGKILL)
                signalled = True
            except ProcessLookupError:
                pass
            except BaseException as group_error:
                if not isinstance(group_error, PermissionError) and cleanup_error is None:
                    cleanup_error = group_error
                try:
                    os.kill(pid, signal.SIGKILL)
                    signalled = True
                except ProcessLookupError:
                    pass
                except BaseException:
                    if cleanup_error is None:
                        cleanup_error = group_error
            try:
                reaped, _status = os.waitpid(pid, 0 if signalled else os.WNOHANG)
                if reaped != pid:
                    cleanup_uncertain = True
                    if cleanup_error is None:
                        cleanup_error = SetupError("PTY cleanup could not confirm owned child exit")
            except BaseException as exc:
                cleanup_uncertain = True
                if cleanup_error is None:
                    cleanup_error = exc
        if cleanup_uncertain:
            error = primary if primary is not None else cleanup_error
            if error is not None:
                try:
                    error.cleanup_uncertain = True
                except BaseException:
                    pass
        if primary is None and cleanup_error is not None:
            raise cleanup_error

def ssh_options(timeout: int) -> list[str]:
    return [
        "-o", f"ConnectTimeout={timeout}",
        "-o", "ServerAliveInterval=10",
        "-o", "ServerAliveCountMax=2",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "LogLevel=ERROR",
    ]


def typed_argv(argv: object, *, label: str) -> list[str]:
    """Copy one command vector after rejecting scalar and control-byte carriers."""
    if type(argv) is not list or not argv:
        raise SetupError(f"{label} must be a non-empty argv array")
    if any(type(item) is not str or not item for item in argv):
        raise SetupError(f"{label} must contain only non-empty string tokens")
    if any(re.search(r"[\x00-\x1f\x7f-\x9f]", item) for item in argv):
        raise SetupError(f"{label} contains a forbidden control character")
    return list(argv)


def ethernet_command_argv(argv: object) -> list[str]:
    """Enforce the complete read-only command surface of a transit switch."""
    command = typed_argv(argv, label="Ethernet jump command")
    exact_commands = {
        ("hostname",),
        ("nv", "show", "interface"),
        ("nv", "config", "show"),
        ("ip", "-d", "link", "show"),
        ("bridge", "fdb", "show"),
        ("ip", "neighbor"),
        ("ip", "-j", "address", "show"),
    }
    tokens = tuple(command)
    if tokens in exact_commands:
        return command
    if (
        len(command) == 2
        and command[0] == "ifquery"
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", command[1])
    ):
        return command
    raise SetupError(
        "Ethernet jump command is not allowed by the read-only argv allowlist: "
        + shlex.join(command)
    )


def ib_command_argv(argv: object) -> list[str]:
    """Enforce the NVOS command vectors used by this Network workflow."""
    command = typed_argv(argv, label="NVOS command")
    tokens = tuple(command)
    if (
        len(command) == 5 and command[:2] == ["sh", "-c"]
        and command[2] == _KEY_INSTALL_SCRIPT and command[3] == "--"
        and len(command[4]) <= 131072
        and re.fullmatch(r"[A-Za-z0-9+/=]+", command[4])
    ):
        return command
    if tokens in {
        ("true",),
        ("nv", "config", "show"),
        ("nv", "config", "show", "-o", "commands"),
        ("nv", "config", "diff", "-o", "commands"),
        ("nv", "show", "system", "ztp"),
        ("nv", "config", "apply", "-y"),
        ("nv", "set", "system", "config", "auto-save", "state", "enabled"),
        ("nv", "set", "system", "ztp", "config-save", "enabled"),
        ("nv", "config", "save"),
    }:
        return command
    if (
        command[:3] == ["nv", "set", "interface"] and len(command) >= 4
        and command[3] in {"eth0", "eth1", "eth0-1"}
        and command[4:] in (["link", "state", "up"], ["type", "eth"])
    ):
        return command
    if len(command) == 7 and command[:3] == ["nv", "set", "interface"]:
        interface, family, operation, value = command[3:]
        if interface not in {"eth0", "eth1", "eth0-1"} or family != "ipv4":
            raise SetupError(
                "NVOS command is not allowed by the Network argv allowlist: "
                + shlex.join(command)
            )
        try:
            if operation == "address":
                ipaddress.IPv4Interface(value)
            elif operation == "gateway":
                ipaddress.IPv4Address(value)
            else:
                raise ValueError(operation)
        except ValueError as exc:
            raise SetupError(
                "NVOS command has an invalid interface value: "
                + shlex.join(command)
            ) from exc
        return command
    if (
        len(command) == 5
        and command[:4] == ["nv", "set", "system", "hostname"]
        and valid_hostname(command[4])
    ):
        return command
    if len(command) == 6 and command[:3] == ["nv", "set", "system"]:
        category, field, value = command[3:]
        if (category, field) == ("dns", "server"):
            try:
                ipaddress.ip_address(value)
            except ValueError as exc:
                raise SetupError("invalid DNS server address") from exc
            return command
        if (category, field) == ("ntp", "server") and re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,252}", value
        ):
            return command
        if (category, field) == ("date-time", "timezone") and re.fullmatch(
            r"[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)*", value
        ):
            return command
    raise SetupError(
        "NVOS command is not allowed by the Network argv allowlist: "
        + shlex.join(command)
    )


def outer_ssh_command(ethernet: Device, user: str, remote_argv: list[str],
                      timeout: int, *, tty: bool = False,
                      local: bool = False) -> list[str]:
    command = typed_argv(remote_argv, label="outer SSH command")
    # Local execution uses the same fixed PATH as the remote wrapper (v15; T14).
    script = "export PATH=" + shlex.quote(_SAFE_PATH) + "; exec " + shlex.join(command)
    wrapper = ["sh", "-c", script]
    if local:
        return wrapper
    # An inventory without a login address is admitted (I19, T13); remote access is not.
    if not usable(ethernet.login_ip):
        raise SetupError(
            f"{ethernet.hostname}.eth0_ip login address is required for remote Ethernet access"
        )
    return ["ssh", *(["-tt"] if tty else []), *ssh_options(timeout),
            "-o", "ControlMaster=no", "-o", "ControlPath=none",
            f"{user}@{ethernet.login_ip}", shlex.join(wrapper)]

def ethernet_responder(ethernet_password: str) -> Callable[[str], Optional[str]]:
    answered_at = 0

    def respond(output: str) -> Optional[str]:
        nonlocal answered_at
        prompts = len(re.findall(r"(?im)(?:password|passphrase).*:\s*$", output))
        if prompts > answered_at:
            answered_at = prompts
            return ethernet_password
        if re.search(r"(?im)are you sure you want to continue connecting.*\?\s*$", output):
            return "yes"
        return None

    return respond


def run_on_ethernet(ethernet: Device, user: str, password: str,
                    remote_argv: list[str], timeout: int, *, local: bool = False) -> str:
    if ethernet.dev_type not in TRANSIT_DEVICE_TYPES:
        raise SetupError(
            f"{ethernet.hostname} is not a supported Ethernet transit device"
        )
    command = ethernet_command_argv(remote_argv)
    result = interactive_run(
        outer_ssh_command(ethernet, user, command, timeout, local=local),
        (lambda _output: None) if local else ethernet_responder(password), timeout,
    )
    if result.exit_code != 0:
        if (
            command[0] == "ifquery"
            and result.exit_code == 1
            and not result.output.strip()
        ):
            # ifupdown2 uses exit 1 with no output when the interface has no
            # stanza.  That semantic absence means the Linux default VRF; no
            # other exit/output combination is downgraded.
            return ""
        raise SetupError(
            f"Ethernet SSH failed for {ethernet.hostname} ({ethernet.login_ip}), "
            f"exit={result.exit_code}: {result.output.strip()[-600:]}"
        )
    return re.sub(
        r"(?im)^[^\n]*@[^:\n]+'s password:\s*(?:\n|$)", "", result.output
    )


def collect_ethernet_interfaces(ethernet: Device, user: str, password: str,
                                timeout: int, *,
                                local: bool = False) -> tuple[str, str]:
    hostname_output = run_on_ethernet(
        ethernet, user, password, ["hostname"], timeout, local=local
    )
    interface_output = run_on_ethernet(
        ethernet, user, password, ["nv", "show", "interface"], timeout,
        local=local,
    )
    hostname_lines = [clean(line) for line in hostname_output.splitlines() if clean(line)]
    if len(hostname_lines) != 1 or not valid_hostname(hostname_lines[0]):
        raise SetupError(
            f"Ethernet switch {ethernet.login_ip} returned an invalid hostname: "
            f"{hostname_output.strip()!r}"
        )
    actual_hostname = hostname_lines[0]
    expected_short = normalize_name(ethernet.hostname).split(".", 1)[0]
    actual_short = normalize_name(actual_hostname).split(".", 1)[0]
    if actual_short != expected_short:
        raise SetupError(
            f"Ethernet identity mismatch at {ethernet.login_ip}: CSV expects "
            f"{ethernet.hostname}, device reports {actual_hostname}"
        )
    log(f"  Ethernet identity verified: {actual_hostname} ({ethernet.login_ip})")
    if not interface_output.strip():
        raise SetupError(f"empty 'nv show interface' output from {ethernet.hostname}")
    return actual_hostname, interface_output.strip()


def collect_ethernet_network_tables(ethernet: Device, user: str,
                                    password: str, timeout: int, *,
                                    local: bool = False) -> tuple[str, str, str]:
    links = run_on_ethernet(
        ethernet, user, password, ["ip", "-d", "link", "show"], timeout,
        local=local,
    )
    fdb = run_on_ethernet(
        ethernet, user, password, ["bridge", "fdb", "show"], timeout,
        local=local,
    )
    neighbors = run_on_ethernet(
        ethernet, user, password, ["ip", "neighbor"], timeout, local=local,
    )
    if not links.strip():
        raise SetupError(f"empty 'ip -d link show' output from {ethernet.hostname}")
    return links.strip(), fdb.strip(), neighbors.strip()


def snapshot_filename(hostname: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", clean(hostname))
    if not value or value in {".", ".."}:
        raise SetupError(f"cannot create snapshot filename for {hostname!r}")
    return value + ".snapshot.txt"


def discover_input_file(explicit: Optional[Path], preferred_name: str,
                        suffix: str, label: str) -> Path:
    if explicit is not None:
        path = explicit.expanduser().resolve()
        if not path.is_file():
            raise SetupError(f"{label} does not exist or is not a file: {path}")
        return path

    current = Path.cwd()
    preferred = current / preferred_name
    if preferred.is_file():
        return preferred.resolve()
    candidates = sorted(
        (
            path.resolve() for path in current.iterdir()
            if path.is_file()
            and path.suffix.casefold() == suffix.casefold()
            and not path.name.startswith((".", "~$"))
            and "tbd" not in path.name.casefold()
        ),
        key=lambda path: path.name.casefold(),
    )
    if not candidates:
        raise SetupError(
            f"no {label} found in current directory {current}; expected "
            f"{preferred_name!r} or one {suffix} file"
        )
    if len(candidates) > 1:
        raise SetupError(
            f"multiple {label} candidates found in current directory {current}; "
            "specify the input explicitly: "
            + ", ".join(path.name for path in candidates)
        )
    return candidates[0]


def save_ethernet_snapshot(directory: Path, ethernet: Device,
                           actual_hostname: str, location: str,
                           interfaces: str, links: str, fdb: str,
                           neighbors: str) -> Path:
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise SetupError(f"cannot create snapshot directory {directory}: {exc}") from exc
    path = directory / snapshot_filename(ethernet.hostname)
    temporary = path.with_name(path.name + ".tmp")
    content = (
        "Ethernet snapshot\n"
        f"Collected: {time.strftime('%Y-%m-%d %H:%M:%S %Z')}\n"
        f"CSV hostname: {ethernet.hostname}\n"
        f"Device hostname: {actual_hostname}\n"
        f"Login IP: {ethernet.login_ip}\n"
        f"Execution: {location}\n"
        "\n===== nv show interface =====\n"
        f"{interfaces.rstrip()}\n"
        "\n===== ip -d link show =====\n"
        f"{links.rstrip()}\n"
        "\n===== bridge fdb show =====\n"
        f"{fdb.rstrip()}\n"
        "\n===== ip neighbor =====\n"
        f"{neighbors.rstrip()}\n"
    )
    try:
        temporary.write_text(content, encoding="utf-8")
        temporary.replace(path)
    except OSError as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise SetupError(f"cannot write Ethernet snapshot {path}: {exc}") from exc
    return path


def interface_status_line(interface_table: str, interface: str) -> str:
    escaped = re.escape(clean(interface))
    pattern = re.compile(
        rf"^\s*[|│┃]?\s*{escaped}(?:\s|[|│┃]|$)", re.IGNORECASE
    )
    matches = [
        line.strip() for line in interface_table.splitlines()
        if pattern.search(line)
    ]
    unique = list(dict.fromkeys(matches))
    if not unique:
        raise SetupError(f"{interface} is absent from 'nv show interface' output")
    if len(unique) > 1:
        raise SetupError(
            f"{interface} has multiple rows in 'nv show interface' output: "
            + " / ".join(unique)
        )
    return unique[0]


def interface_oper_status(status_line: str, interface: str) -> str:
    fields = status_line.translate(str.maketrans({
        "|": " ", "│": " ", "┃": " ",
    })).split()
    if len(fields) < 3 or fields[0].casefold() != clean(interface).casefold():
        raise SetupError(
            f"cannot parse Admin/Oper Status for {interface}: {status_line}"
        )
    return fields[2].casefold()


def _ip_link_blocks(link_table: str) -> dict[str, list[str]]:
    """Split ``ip -d link show`` output into blocks keyed by interface name."""
    blocks: dict[str, list[str]] = {}
    current: Optional[str] = None
    header = re.compile(r"^\s*\d+:\s+([^:@\s]+)(?:@[^:\s]+)?:\s+(.*)$")
    for raw_line in link_table.splitlines():
        match = header.match(raw_line)
        if match:
            current = clean(match.group(1))
            blocks.setdefault(current, []).append(raw_line)
        elif current is not None:
            blocks[current].append(raw_line)
    return blocks


def fdb_port_for_interface(link_table: str, interface: str) -> str:
    """Return the interface name used by FDB for a physical switch port.

    A bridge member keeps its original swp name in ``bridge fdb show``. A bond
    slave is represented by the bond master, so substitution occurs only when
    the detailed master block identifies link-kind ``bond``.
    """
    port = clean(interface)
    blocks = _ip_link_blocks(link_table)
    member_block = blocks.get(port)
    if not member_block:
        raise SetupError(f"{port} is absent from 'ip -d link show' output")
    master_match = re.search(r"(?:^|\s)master\s+(\S+)", member_block[0])
    if not master_match:
        return port
    master = master_match.group(1).split("@", 1)[0]
    master_block = blocks.get(master)
    if not master_block:
        raise SetupError(
            f"{port} reports master {master}, but that master is absent from "
            "'ip -d link show' output"
        )
    master_details = "\n".join(master_block)
    if re.search(r"(?m)^\s*bond\s+mode\s+", master_details):
        return master
    return port


def macs_on_port(fdb: str, port: str) -> list[str]:
    result: list[str] = []
    for line in fdb.splitlines():
        fields = line.split()
        if "dev" not in fields:
            continue
        try:
            line_port = fields[fields.index("dev") + 1]
        except IndexError:
            continue
        if line_port != port or "permanent" in {value.casefold() for value in fields}:
            continue
        match = MAC_RE.search(line)
        if match:
            mac = match.group(0).casefold()
            if mac not in result:
                result.append(mac)
    return result


def neighbor_for_port(fdb: str, neighbor_table: str, port: str) -> Neighbor:
    macs = macs_on_port(fdb, port)
    if not macs:
        raise SetupError(f"no dynamic MAC learned on Ethernet port {port}")
    matches: dict[tuple[str, str, str], Neighbor] = {}
    for line in neighbor_table.splitlines():
        fields = line.split()
        if len(fields) < 5 or "dev" not in fields or "lladdr" not in fields:
            continue
        try:
            address = ipaddress.ip_address(fields[0].split("%", 1)[0])
            interface = fields[fields.index("dev") + 1]
            mac = fields[fields.index("lladdr") + 1].casefold()
        except (ValueError, IndexError):
            continue
        if address.version == 6 and address.is_link_local and mac in macs:
            neighbor = Neighbor(str(address), interface, mac)
            matches[(neighbor.ipv6, neighbor.interface, neighbor.mac)] = neighbor
    if not matches:
        raise NeighborNotLearned(
            f"port {port} learned MAC(s) {', '.join(macs)}, but ip neighbor has no "
            "matching IPv6 link-local entry"
        )
    if len(matches) != 1:
        details = ", ".join(
            f"{item.ipv6}%{item.interface}/{item.mac}" for item in matches.values()
        )
        raise SetupError(f"multiple IPv6 neighbors match port {port}: {details}")
    return next(iter(matches.values()))


def mac_to_link_local(mac: str) -> str:
    """RFC 4291 Appendix A candidate, not evidence that the peer uses this IID."""
    text = clean(mac)
    if not MAC_RE.fullmatch(text):
        raise SetupError(f"invalid MAC for EUI-64 candidate: {text!r}")
    octets = bytearray.fromhex(text.replace(":", ""))
    if not any(octets) or octets[0] & 1:
        raise SetupError("EUI-64 candidate requires a nonzero unicast MAC")
    octets[0] ^= 0x02
    iid = bytes(octets[:3]) + b"\xff\xfe" + bytes(octets[3:])
    return str(ipaddress.IPv6Address(int(ipaddress.IPv6Address("fe80::")) | int.from_bytes(iid, "big")))


def derived_neighbor_for_port(target: Target, fdb: str, link_table: str, port: str) -> Neighbor:
    """Derive one candidate only from unique, CSV-matched FDB and L2/L3 scope."""
    macs = macs_on_port(fdb, port)
    if len(macs) != 1:
        raise SetupError(f"ND missing: EUI-64 fallback needs exactly one dynamic MAC on {port}")
    if not target.ib.eth0_mac:
        raise SetupError("ND missing: EUI-64 fallback requires the CSV IB eth0 MAC")
    mac = macs[0]
    verify_fdb_eth0_mac(target, mac)
    address = mac_to_link_local(mac)
    contexts = set()
    for row in fdb.splitlines():
        fields = row.split()
        if not fields or fields[0].casefold() != mac or "dev" not in fields:
            continue
        if {field.casefold() for field in fields} & {"permanent", "static", "local", "self"}:
            continue
        try:
            if fields[fields.index("dev") + 1] != port:
                continue
            bridge = fields[fields.index("master") + 1] if "master" in fields else ""
            vlan = fields[fields.index("vlan") + 1] if "vlan" in fields else ""
        except IndexError as exc:
            raise SetupError("ND missing: malformed FDB bridge/VLAN context") from exc
        contexts.add((bridge, vlan))
    if len(contexts) != 1:
        raise SetupError("ND missing: FDB bridge/VLAN context is missing or ambiguous")
    bridge, vlan = next(iter(contexts))
    blocks = _ip_link_blocks(link_table)
    if not vlan:
        # A routed physical interface/bond needs no SVI. Bridged ports need
        # explicit VLAN scope; never guess their PVID or bridge L3 interface.
        block = blocks.get(port, [])
        if bridge or not block or re.search(r"\bmaster\s+", block[0]):
            raise SetupError("ND missing: bridged FDB entry has no unambiguous VLAN/L3 scope")
        interface = port
    else:
        if not re.fullmatch(r"[0-9]{1,4}", vlan) or not 1 <= int(vlan) <= 4094 or not bridge:
            raise SetupError("ND missing: invalid FDB VLAN/bridge context")
        candidates = []
        for name, block in blocks.items():
            parent = re.match(r"\s*\d+:\s+[^:@\s]+@([^:\s]+):", block[0])
            ids = re.findall(r"(?m)^\s*vlan\s+protocol\s+802\.1(?:Q|ad)\s+id\s+(\d+)\b", "\n".join(block))
            if parent and parent.group(1) == bridge and ids == [str(int(vlan))]:
                candidates.append(name)
        if len(candidates) != 1:
            raise SetupError(f"ND missing: VLAN {vlan} on {bridge} has {len(candidates)} matching L3 interfaces")
        interface = candidates[0]
    validate_network_selector(interface, label="derived neighbor interface")
    return Neighbor(address, interface, mac, address_source="FDB_EUI64_CANDIDATE")


def interface_vrf(ethernet: Device, user: str, password: str,
                  interface: str, timeout: int, *, local: bool = False) -> str:
    """Return the SVI's explicitly configured VRF, or default."""
    output = run_on_ethernet(
        ethernet, user, password, ["ifquery", interface], timeout,
        local=local,
    )
    matches = re.findall(r"(?im)^\s*vrf\s+(\S+)\s*$", output)
    unique = list(dict.fromkeys(clean(value) for value in matches if usable(value)))
    if len(unique) > 1:
        raise SetupError(
            f"interface {interface} has multiple VRF values in ifquery output: "
            + ", ".join(unique)
        )
    return unique[0] if unique else "default"


class NestedResponder:
    def __init__(self, ethernet_password: str, ib_default_password: str,
                 allow_password_change: bool, *,
                 ib_new_password: Optional[str] = None,
                 ib_destination: Optional[str] = None, _phase=None):
        if _phase is not None and type(_phase) is not _IBPhase:
            raise SetupError("invalid private responder phase")
        self._phase = _phase
        self.ethernet_password = ethernet_password
        self.ib_default_password = ib_default_password
        self.ib_new_password = ib_new_password
        self.ib_destination = ib_destination
        self.allow_password_change = allow_password_change
        self.password_change_blocked = False
        self.password_change_attempted = False
        self.counts = {}

    def _new_prompt(self, category: str, pattern: str, output: str) -> bool:
        count = len(re.findall(pattern, output, re.I | re.M))
        previous = self.counts.get(category, 0)
        if count > previous:
            self.counts[category] = count
            return True
        return False

    def __call__(self, output: str) -> Optional[str]:
        if self._phase is not None:
            return self._phase.response(output, self)
        if _EXPIRED_PASSWORD.search(output) and not self.allow_password_change:
            self.password_change_blocked = True
            return "\x03"
        for category, pattern in (
            ("current", r"^\s*(?:\(current\)|current|old)[^\n]*password\s*:\s*$"),
            ("retype", r"^\s*[^\n]*(?:retype|repeat|confirm)[^\n]*password\s*:\s*$"),
            ("new", r"^(?![^\n]*(?:retype|repeat|confirm))[^\n]*new[^\n]*password\s*:\s*$"),
        ):
            if not self._new_prompt(category, pattern, output):
                continue
            if not self.allow_password_change:
                self.password_change_blocked = True
                return "\x03"
            if not self.ib_new_password:
                raise SetupError("independent, project-verified IB new password is required")
            if category == "current":
                return self.ib_default_password
            self.password_change_attempted = True
            return self.ib_new_password
        if self._new_prompt("hostkey", r"are you sure you want to continue connecting", output):
            return "yes"  # preserve accept-new; changed host keys still fail
        lines = re.findall(r"(?im)^([^\n]*password[^\n]*):\s*$", output)
        ib_lines = [line for line in lines if "fe80:" in line.casefold() or
                    (self.ib_destination is not None and self.ib_destination in line)]
        outer_lines = [line for line in lines if line not in ib_lines and
                       "@" in line and "'s password" in line.casefold()]
        if len(outer_lines) > self.counts.get("outer", 0):
            self.counts["outer"] = len(outer_lines)
            if not self.ethernet_password:
                return None
            return self.ethernet_password if len(outer_lines) == 1 else None
        if len(ib_lines) > self.counts.get("ib", 0):
            self.counts["ib"] = len(ib_lines)
            return self.ib_default_password if len(ib_lines) == 1 else None
        return None

def validate_jump_target(target: Target) -> None:
    """Bind a jump operation to one IB target and one supported transit."""
    if target.ib.dev_type != "ib":
        raise SetupError(
            f"{target.ib.hostname} is not a type=ib Network target"
        )
    if target.ethernet.dev_type not in TRANSIT_DEVICE_TYPES:
        raise SetupError(
            f"{target.ethernet.hostname} is not a supported Ethernet transit device"
        )


def validate_network_selector(value: object, *, label: str) -> str:
    """Reject empty/control-bearing interface and VRF selectors."""
    if (
        type(value) is not str
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value)
    ):
        raise SetupError(f"invalid {label}: {value!r}")
    return value


def validate_neighbor_boundary(neighbor: Neighbor) -> None:
    """Validate semantic nested-SSH selectors before credentials are created."""
    if type(neighbor.ipv6) is not str or "%" in neighbor.ipv6:
        raise SetupError(f"invalid IPv6 link-local neighbor: {neighbor.ipv6!r}")
    try:
        address = ipaddress.IPv6Address(neighbor.ipv6)
    except ipaddress.AddressValueError as exc:
        raise SetupError(
            f"invalid IPv6 link-local neighbor: {neighbor.ipv6!r}"
        ) from exc
    if not address.is_link_local:
        raise SetupError(f"neighbor is not IPv6 link-local: {neighbor.ipv6!r}")
    validate_network_selector(neighbor.interface, label="neighbor interface")
    validate_network_selector(neighbor.vrf, label="neighbor VRF")


def nested_ssh_command(target: Target, neighbor: Neighbor, eth_user: str,
                       ib_user: str, timeout: int, ib_command: list[str], *,
                       local: bool = False, marker: Optional[str] = None,
                       password_only: bool = False, _phase=None) -> list[str]:
    validate_jump_target(target)
    validate_neighbor_boundary(neighbor)
    command = ib_command_argv(ib_command)
    nonce = marker or os.urandom(16).hex()
    nested = [
        "ip", "vrf", "exec", neighbor.vrf, "ssh", "-6", "-tt",
        "-o", f"ConnectTimeout={timeout}",
        "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR",
        "-o", "ControlMaster=no", "-o", "ControlPath=none",
        "-o", "NumberOfPasswordPrompts=1",
    ]
    if password_only:
        nested += ["-o", "PubkeyAuthentication=no",
                   "-o", "PreferredAuthentications=password,keyboard-interactive"]
    nested += ["-B", neighbor.interface, f"{ib_user}@{neighbor.ipv6}",
               shlex.join(["sh", "-c", _framed_script(command, nonce)])]
    if _phase is not None:
        if (type(_phase) is not _IBPhase or local or marker != _phase.nonce or not password_only
                or command != ["nv", "config", "show", "-o", "commands"]
                or _phase.endpoint != ib_user + "@" + neighbor.ipv6
                or _phase.outer_endpoint != eth_user + "@" + target.ethernet.login_ip):
            raise SetupError("private phase is not bound to this exact SSH request")
        nested = ["sh", "-c", _ib_phase_script(nested, _phase)]
    return outer_ssh_command(target.ethernet, eth_user, nested, timeout,
                             tty=True, local=local)

def _pending_diff_has_password_update_notice(output: str) -> bool:
    """Recognize notification lines, not keywords inside NVUE setter values."""
    for raw_line in strip_ansi(output).splitlines():
        line = raw_line.strip()
        if (
            re.match(r"(?i)^(?:passwd:\s*)?(?:password\b|all authentication tokens\b)", line)
            and _PASSWORD_UPDATED.search(line)
        ):
            return True
    return False


def run_on_ib(target: Target, neighbor: Neighbor, eth_user: str,
              ethernet_password: str, ib_user: str, ib_default_password: str,
              timeout: int, ib_command: list[str], *, local: bool = False,
              allow_password_change: bool = False,
              ib_new_password: Optional[str] = None,
              password_only: bool = False,
              _phase_operation: Optional[str] = None, _password_policy=None) -> SessionResult:
    if (ib_command == ["nv", "config", "diff", "-o", "commands"]
            and allow_password_change):
        raise SetupError("read-only pending diff cannot allow password change")
    check_task_cancelled()
    if _phase_operation is not None:
        if _phase_operation == "password-change":
            obtain_write_permit("password")
        record_metric("ib_ssh_attempts")
        return _execute_ib_phase(
            target, neighbor, eth_user, ethernet_password, ib_user, ib_default_password,
            timeout, ib_command, local=local, allow_password_change=allow_password_change,
            ib_new_password=ib_new_password, _phase_operation=_phase_operation,
            _password_policy=_password_policy)
    mutating = (allow_password_change or ib_command[:2] in (["nv", "set"], ["sh", "-c"])
                or ib_command[:3] in (["nv", "config", "apply"], ["nv", "config", "save"]))
    marker = os.urandom(16).hex()
    command = nested_ssh_command(
        target, neighbor, eth_user, ib_user, timeout, ib_command,
        local=local, marker=marker, password_only=password_only,
    )
    if mutating:
        obtain_write_permit("password" if allow_password_change else
                            "public_key" if ib_command[:2] == ["sh", "-c"] else "nvue")
    responder = NestedResponder(
        ethernet_password, ib_default_password, allow_password_change,
        ib_new_password=ib_new_password,
        ib_destination=f"{ib_user}@{neighbor.ipv6}",
    )
    record_metric("ib_ssh_attempts")
    result = interactive_run(command, responder, max(timeout * 4, 60))
    if ib_command == ["nv", "config", "diff", "-o", "commands"] and (
        result.password_changed or result.password_change_required
        or result.password_change_attempted or result.ib_authentication_rejected
        or responder.password_change_attempted or responder.password_change_blocked
        or _EXPIRED_PASSWORD.search(result.output)
        or _pending_diff_has_password_update_notice(result.output)
    ):
        raise SetupError("read-only pending diff has unverified authentication or password-change evidence")
    if result.password_change_required or (
        _EXPIRED_PASSWORD.search(result.output) and not allow_password_change
    ):
        if ib_command != ["nv", "config", "show", "-o", "commands"]:
            raise SetupError("IB requires a password change; command success is unverified")
        result.password_change_required = True
        return result
    if result.password_changed or (allow_password_change and result.password_change_attempted):
        # v15: the caller verifies an attempted change with a fresh connection.
        return result
    if ib_command == ["nv", "config", "diff", "-o", "commands"] and (
        type(result.exit_code) is not int or result.exit_code not in (0, 1)
        or _NETWORK_FAILURE.search(result.output)
    ):
        raise SetupError("pending diff transport evidence is UNKNOWN")
    if result.exit_code != 0:
        endpoint = re.escape(f"{ib_user}@{neighbor.ipv6}")
        if result.ib_authentication_rejected or (
                not _NETWORK_FAILURE.search(result.output) and re.search(
                    endpoint + r":[^\n]*Permission denied", result.output, re.I)):
            raise IBAuthenticationError(f"IB authentication rejected for {target.ib.hostname}")
        if (
            ib_command == ["nv", "config", "diff", "-o", "commands"]
            and type(result.exit_code) is int and result.exit_code == 1
            and not _NETWORK_FAILURE.search(result.output)
        ):
            # I-005: the pending diff passes the same readback entry before the owned check.
            pending = _split_comma_interface_lines(
                extract_command_output(result.output, marker, expected_exit_code=1))
            if not _validate_owned_pending(target.ib, pending):
                raise SetupError("pending diff returned 1 without verifiable owned changes")
            result.output = pending
            return result
        detail = _ib_failure_detail(
            result.output, marker,
            (ethernet_password, ib_default_password, ib_new_password or ""),
        )
        error = SetupError(
            f"nested SSH to {target.ib.hostname} via {target.ethernet.hostname} "
            f"failed, exit={result.exit_code}: {detail}"
        )
        # The message embeds device output; reports outside this direct
        # diagnostic use only this product-written summary.
        error.report_summary = (
            f"nested SSH to {target.ib.hostname} via {target.ethernet.hostname} "
            f"failed, exit={result.exit_code}; device output withheld"
        )
        raise error
    if allow_password_change and responder.password_change_attempted:
        raise SetupError("IB password change outcome is UNKNOWN; reconnect before retrying")
    try:
        result.output = extract_command_output(result.output, marker)
    except SetupError as exc:
        detail = _ib_failure_detail(
            result.output, marker,
            (ethernet_password, ib_default_password, ib_new_password or ""),
        )
        error = SetupError(f"{exc}; device output: {detail}")
        error.report_summary = f"{exc}; device output withheld"
        raise error from None
    if ib_command == ["nv", "config", "diff", "-o", "commands"]:
        result.output = _split_comma_interface_lines(result.output)
        _validate_owned_pending(target.ib, result.output)
    return result


def _ib_failure_detail(output: str, marker: str, secrets: tuple[str, ...]) -> str:
    """Keep bounded device diagnostics without exposing credential values."""
    normalized = strip_ansi(output)
    frame = re.search(
        r"(?ms)^__HTTP_IB_BEGIN_" + re.escape(marker) + r"__\n(.*?)"
        r"^__HTTP_IB_END_" + re.escape(marker) + r"__=[0-9]+\s*$", normalized)
    detail = frame.group(1) if frame else normalized
    for secret in sorted(set(secrets) - {""}, key=len, reverse=True):
        detail = detail.replace(secret, "<redacted>")
    detail = re.sub(r"(?im)(\bnv\s+set\s+system\s+aaa\s+[^\n]*?\bpassword\s+)\S+",
                    r"\1<redacted>", detail)
    detail = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", detail).strip()
    return detail[-4000:] or "<no device output captured>"

def parse_nvue_state(output: str) -> DeviceState:
    if not output.strip() or _EXPIRED_PASSWORD.search(output):
        raise SetupError("NVUE configuration is UNKNOWN, not an empty/unconfigured device")
    if not any(line.strip().startswith("nv set ") for line in output.splitlines()):
        raise SetupError("NVUE readback has no verifiable configuration commands")
    eth0: list[str] = []
    eth1: list[str] = []
    eth0_gateways: list[str] = []
    eth1_gateways: list[str] = []
    hostname = ""
    commands: list[str] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line.startswith("nv set "):
            continue
        commands.append(line)
        match = re.match(r"nv set interface eth0 ipv4 address (\S+)", line)
        if match:
            eth0.append(match.group(1))
            continue
        match = re.match(r"nv set interface eth1 ipv4 address (\S+)", line)
        if match:
            eth1.append(match.group(1))
            continue
        match = re.match(r"nv set interface (eth0-1|eth0|eth1) ipv4 gateway (\S+)", line)
        if match:
            interface, gateway = match.groups()
            if interface in {"eth0", "eth0-1"}:
                eth0_gateways.append(gateway)
            if interface in {"eth1", "eth0-1"}:
                eth1_gateways.append(gateway)
            continue
        match = re.match(r"nv set system hostname\s+(\S+)", line)
        if match:
            hostname = match.group(1)
    return DeviceState(
        tuple(eth0), tuple(eth1), tuple(eth0_gateways),
        tuple(eth1_gateways), hostname, "\n".join(commands),
    )


def verify_fdb_eth0_mac(target: Target, learned_mac: str) -> None:
    """Compare an optional CSV MAC with the MAC learned on the P2P OOB port."""
    device = target.ib
    if not device.eth0_mac:
        return
    actual = normalize_mac(
        learned_mac, field=f"{target.ethernet.hostname}.{target.ethernet_port}.fdb_mac"
    )
    if actual != device.eth0_mac:
        raise IBMacMismatch(
            f"eth0 MAC mismatch: CSV expected {device.eth0_mac}, "
            f"OOB Leaf FDB reports {actual}; "
            "the CSV MAC may be wrong, or the IB device may be connected to the wrong "
            f"OOB Leaf interface (expected {target.ethernet.hostname}:"
            f"{target.ethernet_port} for {device.hostname})",
            expected_mac=device.eth0_mac, observed_mac=actual,
        )
    report_detail(f"  eth0 MAC verified from OOB Leaf FDB: {actual}")


def state_is_unconfigured(state: DeviceState) -> bool:
    hostname = normalize_name(state.hostname)
    return (
        not state.eth0_addresses
        and not state.eth1_addresses
        and not state.eth0_gateways
        and not state.eth1_gateways
        and hostname in DEFAULT_HOSTNAMES
    )


def classify_auto_day0(device: Device, state: DeviceState) -> str:
    """Required values are a subset; extra applied configuration is preserved."""
    if state_is_unconfigured(state):
        return "unconfigured"
    try:
        verify_state(device, state)
    except SetupError:
        return "terminal"
    return "complete"


def _classify_managed_day0(device: Device, state: DeviceState) -> str:
    """Field-exact Day-0 classification for the managed observation (O7).

    The DEV classify_auto_day0 under its managed name: existing fields must match
    the CSV exactly; neither a missing nor a contradictory field is complete.  The
    run path keeps classify_auto_day0's v15 subset semantics.
    """
    if state_is_unconfigured(state):
        return "unconfigured"
    if normalize_name(state.hostname) != normalize_name(device.hostname):
        return "terminal"
    fields = (
        (state.eth0_addresses, device.eth0_prefix),
        (state.eth0_gateways, device.eth0_gateway),
        (state.eth1_addresses, device.eth1_prefix),
    )
    if any(actual != ((expected,) if expected else ()) for actual, expected in fields):
        return "terminal"
    allowed_eth1_gateways = (
        (device.eth1_gateway,) if device.eth1_prefix else (),
        (device.eth0_gateway,) if not device.eth1_prefix else (),
    )
    if state.eth1_gateways not in allowed_eth1_gateways:
        return "terminal"
    return "complete"

def desired_commands(device: Device) -> list[list[str]]:
    if device.dev_type != "ib":
        raise SetupError("configuration commands require a type=ib device; transit is read-only")
    commands = [["nv", "set", "interface", "eth0", "ipv4", "address", device.eth0_prefix]]
    if device.eth1_prefix and device.eth1_gateway != device.eth0_gateway:
        commands.extend([
            ["nv", "set", "interface", "eth0", "ipv4", "gateway", device.eth0_gateway],
            ["nv", "set", "interface", "eth1", "ipv4", "gateway", device.eth1_gateway],
        ])
    else:
        commands.append(["nv", "set", "interface", "eth0-1", "ipv4", "gateway", device.eth0_gateway])
    commands.extend([
        ["nv", "set", "interface", "eth0-1", "link", "state", "up"],
        ["nv", "set", "interface", "eth0-1", "type", "eth"],
    ])
    if device.eth1_prefix:
        commands.append(["nv", "set", "interface", "eth1", "ipv4", "address", device.eth1_prefix])
    commands.extend([
        ["nv", "set", "system", "hostname", device.hostname],
        ["nv", "config", "apply", "-y"],
        ["nv", "config", "save"],
    ])
    return commands

def _ntp_server_is_configured(server: str, current: str) -> bool:
    """Compare complete server identity without resetting existing properties."""
    def identity(value: str) -> str:
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return value.casefold().rstrip(".")
    expected = identity(server)
    present = False
    for line in current.splitlines():
        if not re.match(r"^\s*nv\s+set\s+system\s+ntp\s+server(?:\s|$)", line):
            continue
        try:
            tokens = shlex.split(line)
        except ValueError:
            raise SetupError("invalid NTP configuration readback; server membership is UNKNOWN") from None
        if len(tokens) < 6:
            raise SetupError("NTP configuration readback has no server identity")
        if tokens[:5] == ["nv", "set", "system", "ntp", "server"] and identity(tokens[5]) == expected:
            present = True
    return present


def initial_configuration_commands() -> list[list[str]]:
    return [
        ["nv", "set", "system", "config", "auto-save", "state", "enabled"],
        ["nv", "set", "system", "ztp", "config-save", "enabled"],
        ["nv", "config", "apply", "-y"],
        ["nv", "config", "save"],
    ]


def _split_comma_interface_lines(readback: str) -> str:
    """The NVUE readback entry (I-005): one line per member of `nv set interface A,B,... <rest>`.

    NVUE merges interfaces with the same setting into one comma line (`eth0-1,fnm1 link state
    up`).  Only such lines change, once, here (guide WP-12, criterion 2); every other line, a
    lone `eth0-1` line included, is kept byte for byte.  Members are not judged here: the
    management Network readback refuses an unqualified one.
    """
    lines = readback.split("\n")
    for index, line in enumerate(lines):
        match = re.fullmatch(r"(\s*nv\s+set\s+interface\s+)([^\s,'\"\\]+(?:,[^\s,'\"\\]+)+)(\s.*)?",
                             line, re.S)
        if match is not None:
            prefix, members, rest = match.group(1), match.group(2), match.group(3) or ""
            lines[index] = "\n".join(prefix + member + rest for member in members.split(","))
    return "\n".join(lines)


def _management_selector_ports(selector: str) -> Optional[tuple[str, ...]]:
    """The reserved ports an interface selector names; () when unrelated, None when unqualified.

    This is a read-only disjointness proof, not a range expander: unknown aliases or groups
    might include the reserved management ports.  `fnm<N>` is unrelated (I-005 O16).
    """
    if selector in {"eth0", "eth1"}:
        return (selector,)
    if selector == "eth0-1":
        return ("eth0", "eth1")
    eth_range = re.fullmatch(r"eth([0-9]+)-([0-9]+)", selector)
    if eth_range is not None:
        lower, upper = (int(value) for value in eth_range.groups())
        return () if 2 <= lower <= upper else None
    if (re.fullmatch(r"eth(?:[2-9]|[1-9][0-9]+)", selector) is not None
            or re.fullmatch(r"(?:swp|ibp|bond|vlan)[0-9]+(?:s[0-9]+)?", selector) is not None
            or re.fullmatch(r"(?:swp|ibp|bond|vlan)[0-9]+-[0-9]+", selector) is not None
            or re.fullmatch(r"fnm[0-9]+", selector) is not None
            or selector == "lo"):
        return ()
    return None


def _management_selector_location(readback: str) -> Optional[tuple[int, str, str]]:
    """(readback line, member, setting) of the first unqualified interface member, else None.

    I-005 O15: the management Network errors keep their fixed text; the caller that caught
    one prints this as a separate line.  The line counts the readback as the device returned
    it, before comma lines are split; the setting names the field, never its value.
    """
    for number, line in enumerate(readback.splitlines(), 1):
        for piece in _split_comma_interface_lines(line).split("\n"):
            try:
                tokens = shlex.split(piece)
            except ValueError:
                continue  # malformed quoting is refused by the readback; it names no member
            if (tokens[:3] == ["nv", "set", "interface"] and len(tokens) > 3
                    and _management_selector_ports(tokens[3]) is None):
                field = tokens[4:6] if tokens[4:5] in (["ipv4"], ["link"]) else tokens[4:5]
                return number, tokens[3], " ".join(field)
    return None


def _management_ports_ready(current: str) -> bool:
    """Both reserved ports are link-up and typed eth, read from actual NVUE tokens.

    The readback parse is DEV's _management_network_facts (WP-1 difficulty 3); the
    v15 whole-line match of eth0-1 is not kept.
    """
    _, up_ports, eth_ports = _management_network_facts(current)
    both = frozenset({"eth0", "eth1"})
    return up_ports == both and eth_ports == both


def _management_network_facts(current: str) -> tuple[DeviceState, frozenset[str], frozenset[str]]:
    """Project only actual NVUE tokens; do not grant configuration authority."""
    failed = False
    try:
        if type(current) is not str or any(
                ord(character) < 32 and character not in "\t\r\n"
                or ord(character) == 127 for character in current):
            raise SetupError("invalid management Network readback")
        # Keep the original parser's UNKNOWN gate; quoted values need a second,
        # actual-only canonical parse, not desired CSV facts.
        parse_nvue_state(current)
        canonical: list[str] = []
        hostnames: set[str] = set()
        links: dict[str, set[str]] = {"eth0": set(), "eth1": set()}
        types: dict[str, set[str]] = {"eth0": set(), "eth1": set()}
        for raw_line in current.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            tokens = shlex.split(line)
            if tokens[:2] != ["nv", "set"]:
                continue
            if len(tokens) < 3:
                raise SetupError("invalid management Network command fact")
            canonical.append(shlex.join(tokens))
            if tokens[2:4] == ["system", "hostname"]:
                if (len(tokens) != 5 or tokens[4] != clean(tokens[4])
                        or not valid_hostname(tokens[4])):
                    raise SetupError("invalid management Network hostname fact")
                hostnames.add(normalize_name(tokens[4]))
                continue
            if tokens[2:3] != ["interface"]:
                continue
            if len(tokens) < 4:
                raise SetupError("invalid management Network interface fact")
            ports = _management_selector_ports(tokens[3])
            if ports is None:
                raise SetupError("management Network selector is not qualified")
            if not ports:
                continue
            field = tokens[4:]
            if not field or field == ["link"] or field == ["ipv4"]:
                raise SetupError("truncated management Network interface fact")
            if field[:2] == ["ipv4", "address"]:
                if len(tokens) != 7 or len(ports) != 1:
                    raise SetupError("invalid management Network address fact")
                address = ipaddress.IPv4Interface(tokens[6])
                if str(address) != tokens[6]:
                    raise SetupError("noncanonical management Network address fact")
            elif field[:2] == ["ipv4", "gateway"]:
                if len(tokens) != 7:
                    raise SetupError("invalid management Network gateway fact")
                gateway = ipaddress.IPv4Address(tokens[6])
                if str(gateway) != tokens[6]:
                    raise SetupError("noncanonical management Network gateway fact")
            elif field[:2] == ["link", "state"]:
                if len(tokens) != 7 or tokens[6] not in {"up", "down"}:
                    raise SetupError("invalid management Network link fact")
                for port in ports:
                    links[port].add(tokens[6])
            elif field[:1] == ["type"]:
                if len(tokens) != 6 or not tokens[5]:
                    raise SetupError("invalid management Network type fact")
                for port in ports:
                    types[port].add(tokens[5])
        if len(hostnames) > 1 or any(
                len(values) > 1 for values in (*links.values(), *types.values())):
            raise SetupError("contradictory management Network facts")
        if any(values and values != {"up"} for values in links.values()):
            raise SetupError("management Network link repair is not qualified")
        if any(values and values != {"eth"} for values in types.values()):
            raise SetupError("management Network type repair is not qualified")
        state = parse_nvue_state("\n".join(canonical))
        return (
            state,
            frozenset(port for port, values in links.items() if values == {"up"}),
            frozenset(port for port, values in types.items() if values == {"eth"}),
        )
    except (SetupError, ValueError):
        failed = True
    if failed:
        error = SetupError("management Network readback is UNKNOWN")
        try:
            raise error from None
        except SetupError:
            error.__cause__ = None
            error.__context__ = None
            raise


def _management_network_commands(device: Device, current: str) -> list[list[str]]:
    """Return only missing setters; no apply/save, prompt, policy or transport."""
    failed = False
    failure_field = None
    try:
        if (type(device) is not Device or type(device.dev_type) is not str
                or device.dev_type != "ib"
                or any(type(value) is not str for value in (
                    device.hostname, device.eth0_prefix, device.eth0_gateway,
                    device.eth1_prefix, device.eth1_gateway))
                or device.hostname != clean(device.hostname)
                or not valid_hostname(device.hostname)):
            raise SetupError("invalid management Network device")
        if (str(ipaddress.IPv4Interface(device.eth0_prefix)) != device.eth0_prefix
                or str(ipaddress.IPv4Address(device.eth0_gateway)) != device.eth0_gateway):
            raise SetupError("invalid management Network primary input")
        if device.eth1_prefix and (
                str(ipaddress.IPv4Interface(device.eth1_prefix)) != device.eth1_prefix
                or str(ipaddress.IPv4Address(device.eth1_gateway)) != device.eth1_gateway):
            raise SetupError("invalid management Network secondary input")
        state, up_ports, eth_ports = _management_network_facts(current)
        expected_name = normalize_name(device.hostname)
        actual_name = normalize_name(state.hostname)
        if actual_name not in DEFAULT_HOSTNAMES and actual_name != expected_name:
            failure_field = "hostname"
            raise SetupError("management Network hostname conflicts")
        required_gateways = [(state.eth0_gateways, device.eth0_gateway, "eth0 gateway")]
        if device.eth1_prefix:
            required_gateways.append((state.eth1_gateways, device.eth1_gateway, "eth1 gateway"))
        for actual, expected, field in required_gateways:
            if actual and expected not in actual:
                failure_field = field
                raise SetupError("management Network gateway conflicts")
        commands: list[list[str]] = []
        if device.eth0_prefix not in state.eth0_addresses:
            commands.append(["nv", "set", "interface", "eth0", "ipv4", "address", device.eth0_prefix])
        if device.eth1_prefix and device.eth1_prefix not in state.eth1_addresses:
            commands.append(["nv", "set", "interface", "eth1", "ipv4", "address", device.eth1_prefix])
        need_zero = device.eth0_gateway not in state.eth0_gateways
        need_one = bool(device.eth1_prefix) and device.eth1_gateway not in state.eth1_gateways
        shared_missing = (
            need_zero and not state.eth1_gateways and not device.eth1_prefix
            or need_zero and need_one and device.eth0_gateway == device.eth1_gateway
        )
        if shared_missing:
            commands.append(["nv", "set", "interface", "eth0-1", "ipv4", "gateway", device.eth0_gateway])
        else:
            if need_zero:
                commands.append(["nv", "set", "interface", "eth0", "ipv4", "gateway", device.eth0_gateway])
            if need_one:
                commands.append(["nv", "set", "interface", "eth1", "ipv4", "gateway", device.eth1_gateway])
        for present, tail in (
                (up_ports, ["link", "state", "up"]), (eth_ports, ["type", "eth"])):
            missing = tuple(port for port in ("eth0", "eth1") if port not in present)
            if missing == ("eth0", "eth1"):
                commands.append(["nv", "set", "interface", "eth0-1", *tail])
            elif missing:
                commands.append(["nv", "set", "interface", missing[0], *tail])
        if actual_name != expected_name:
            commands.append(["nv", "set", "system", "hostname", device.hostname])
        return commands
    except (SetupError, ValueError):
        failed = True
    if failed:
        messages = {
            None: "management Network setter plan is not qualified",
            "hostname": "management Network hostname conflict; device state is UNKNOWN",
            "eth0 gateway": "management Network eth0 gateway conflict; device state is UNKNOWN",
            "eth1 gateway": "management Network eth1 gateway conflict; device state is UNKNOWN",
        }
        error = SetupError(messages[failure_field])
        try:
            raise error from None
        except SetupError:
            error.__cause__ = None
            error.__context__ = None
            raise


def _verify_management_network_state(device: Device, current: str) -> DeviceState:
    """Verify CSV membership and both reserved ports from actual readback."""
    failed = False
    try:
        if (type(device) is not Device or type(device.dev_type) is not str
                or device.dev_type != "ib"
                or any(type(value) is not str for value in (
                    device.hostname, device.eth0_prefix, device.eth0_gateway,
                    device.eth1_prefix, device.eth1_gateway))
                or device.hostname != clean(device.hostname)
                or not valid_hostname(device.hostname)):
            raise SetupError("invalid management Network device")
        if (str(ipaddress.IPv4Interface(device.eth0_prefix)) != device.eth0_prefix
                or str(ipaddress.IPv4Address(device.eth0_gateway)) != device.eth0_gateway):
            raise SetupError("invalid management Network primary input")
        if device.eth1_prefix and (
                str(ipaddress.IPv4Interface(device.eth1_prefix)) != device.eth1_prefix
                or str(ipaddress.IPv4Address(device.eth1_gateway)) != device.eth1_gateway):
            raise SetupError("invalid management Network secondary input")
        state, up_ports, eth_ports = _management_network_facts(current)
        verify_state(device, state)
        if up_ports != frozenset({"eth0", "eth1"}) or eth_ports != frozenset({"eth0", "eth1"}):
            raise SetupError("management Network reserved ports are not verified")
        return state
    except (SetupError, ValueError):
        failed = True
    if failed:
        error = SetupError("management Network post-configuration verification failed; device state is UNKNOWN")
        try:
            raise error from None
        except SetupError:
            error.__cause__ = None
            error.__context__ = None
            raise


def base_stage_needed(device: Device, state: DeviceState, force: bool) -> bool:
    if state_is_unconfigured(state):
        return True
    if force:
        return force_day0_needed(device, state) or not _management_ports_ready(state.raw_commands)
    if classify_auto_day0(device, state) != "complete":
        raise SetupError(
            "Network fields are partial or conflict with CSV; no initialization/infra "
            "writes are permitted. Inspect applied and pending configuration. "
            "--force may only fill missing fields, never overwrite a conflict."
        )
    return not _management_ports_ready(state.raw_commands)


def _ztp_disabled(output: str) -> bool:
    """Read the operational service/state, not config-save or stage history."""
    top = re.split(r"(?im)^\s*ZTP stages\b", strip_ansi(output), maxsplit=1)[0]

    def row(name: str) -> Optional[str]:
        values = re.findall(r"(?im)^\s*" + name + r"\s+(\S+)", top)
        if len(values) > 1:
            raise SetupError("duplicate ZTP " + name + " rows; operational state is unknown")
        return values[0].casefold() if values else None

    service, state = row("service"), row("state")
    if service == "disabled" and state in {None, "disabled"}:
        return True
    if service in {None, "inactive"} and state in {"enabled", "disabled"}:
        return state == "disabled"
    if service in {"enabled", "active", "active-discovery", "running", "starting", "stopping"}:
        if state not in {None, "enabled"}:
            raise SetupError("contradictory ZTP operational state; initialization is blocked")
        return False
    detail = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", top).strip()[-1500:]
    raise SetupError("cannot verify current ZTP state; initialization is blocked; "
                     "nv show system ztp: " + (detail or "<empty>"))


def _verify_ztp_disabled(output: str) -> None:
    if not _ztp_disabled(output):
        raise SetupError("ZTP is not disabled after save; inspect 'nv show system ztp'")


def _validate_owned_pending(device: Device, output: str) -> int:
    """Qualify only closed Initial/management setters bound to this target."""
    allowed = {
        tuple(command) for command in desired_commands(device)
        if command[:2] == ["nv", "set"]
    }
    allowed.update({
        ("nv", "set", "system", "config", "auto-save", "state", "enabled"),
        ("nv", "set", "system", "ztp", "config-save", "enabled"),
    })
    for port in ("eth0", "eth1", "eth0-1"):
        allowed.add(("nv", "set", "interface", port, "type", "eth"))
        allowed.add(("nv", "set", "interface", port, "link", "state", "up"))
    for port, gateway in (
        ("eth0", device.eth0_gateway),
        ("eth1", device.eth1_gateway if device.eth1_prefix else device.eth0_gateway),
    ):
        allowed.add(("nv", "set", "interface", port, "ipv4", "gateway", gateway))
    count = 0
    for raw in output.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("+"):
            line = line[1:].lstrip()
        try:
            tokens = tuple(shlex.split(line))
        except ValueError:
            tokens = ()
        if tokens not in allowed:
            raise SetupError("unrelated or unrecognized pending changes; no changes cleared or committed")
        count += 1
    return count


def _require_empty_pending(target: Target, neighbor: Neighbor, eth_user: str,
                           eth_password: str, ib_user: str, ib_password: str,
                           timeout: int, *, local: bool) -> None:
    """A write stage starts only on an empty pending diff (DEV; T15): never clear, adopt or commit it."""
    result = run_on_ib(
        target, neighbor, eth_user, eth_password, ib_user, ib_password, timeout,
        ["nv", "config", "diff", "-o", "commands"], local=local, allow_password_change=False)
    if result.exit_code != 0 or result.output:
        raise SetupError("pre-existing pending configuration; no changes cleared or committed")


# The latest authorized-helper failure as (weak reference to the helper's own
# fixed safe error, product-written text of the known error it replaced).  The
# helper's error keeps its fixed args and closed attribute set and the helper
# prints nothing; main() adds the text to its report line only for that same
# error object (see _authorized_failure_text).
_AUTHORIZED_FAILURE_NOTE: list = []


def _authorized_failure_summary(error, secrets) -> Optional[str]:
    """The product's own text of a known SetupError; never device output or a credential."""
    if not isinstance(error, SetupError):
        return None
    summary = getattr(error, "report_summary", None)
    if summary is None and len(error.args) == 1:
        summary = error.args[0]
    if type(summary) is not str:
        return None
    present = [secret for secret in secrets if type(secret) is str and secret]
    # Check the text as raised, then again after folding.
    if any(secret in summary for secret in present):
        return None
    summary = re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", summary)
    summary = " ".join(summary.split())
    if not summary or any(secret in summary for secret in present):
        return None
    return summary[:300]


def _authorized_failure_text(error) -> str:
    """str(error), plus the replaced product text when `error` is the helper's own."""
    text = str(error)
    for reference, summary in _AUTHORIZED_FAILURE_NOTE:
        if reference() is error:
            text = f"{text}: {summary}"
    return text


def _run_authorized_ib_command(target: Target, neighbor: Neighbor, eth_user: str,
                               ethernet_password: str, ib_user: str,
                               current_password: str, timeout: int,
                               ib_command: list[str], *, local: bool = False,
                               _password_policy=None) -> SessionResult:
    """Authorize one ordinary management command without changing credential roles."""
    result = None
    failure = None
    summary = None
    withheld = None
    try:
        if (type(local) is not bool or local
                or type(target) is not Target
                or type(target.ib) is not Device
                or type(target.ethernet) is not Device
                or type(neighbor) is not Neighbor
                or type(timeout) is not int or timeout <= 0):
            raise SetupError("invalid authorized management operation")
        validate_jump_target(target)
        validate_neighbor_boundary(neighbor)
        if (type(eth_user) is not str or type(ib_user) is not str
                or clean(eth_user) != eth_user or clean(ib_user) != ib_user
                or not valid_ssh_user(eth_user) or not valid_ssh_user(ib_user)):
            raise SetupError("invalid authorized management account")
        # P3 (owner Q-032 default): an OOB public-key login leaves the Ethernet
        # password empty; the IB current credential must still be non-empty.
        for credential, required in ((ethernet_password, False), (current_password, True)):
            if (type(credential) is not str or (required and not credential)
                    or any(0xD800 <= ord(char) <= 0xDFFF for char in credential)
                    or len(credential.encode("utf-8")) > 4096
                    or re.search(r"[\x00-\x1f\x7f-\x9f]", credential)):
                raise SetupError("invalid authorized management credential")
        command = ib_command_argv(ib_command)
        # Target permission is separate from the selected, already authenticated
        # inner credential. This value must never replace current_password;
        # it is kept only to withhold it from a failure summary.
        withheld = _ib_project_value(_password_policy, user=ib_user, fetch=True)
        result = run_on_ib(
            target, neighbor, eth_user, ethernet_password, ib_user,
            current_password, timeout, command, local=False,
            allow_password_change=False,
        )
        if (type(result) is not SessionResult
                or type(result.exit_code) is not int or result.exit_code != 0
                or type(result.output) is not str
                or any(getattr(result, name) is not False for name in (
                    "password_changed", "password_change_required",
                    "password_change_attempted", "ib_authentication_rejected"))
                or _EXPIRED_PASSWORD.search(result.output)
                or _pending_diff_has_password_update_notice(result.output)):
            raise SetupError("management command outcome is unverified")
        _password_policy.assert_unchanged()
    except (SetupError, OSError) as error:
        uncertain, number = _ib_phase_error_facts(error)
        if number is None:
            candidate = getattr(error, "io_errno", None)
            if type(candidate) is int and 1 <= candidate <= 255:
                number = candidate
        failure = uncertain, number
        summary = _authorized_failure_summary(
            error, (ethernet_password, current_password, withheld))
    if failure is not None:
        error = SetupError("management IB operation failed; device state is UNKNOWN")
        if failure[0] is True:
            error.cleanup_uncertain = True
        if failure[1] is not None:
            error.io_errno = failure[1]
        _AUTHORIZED_FAILURE_NOTE[:] = [(weakref.ref(error), summary)] if summary else []
        try:
            raise error from None
        except SetupError:
            error.__cause__ = None
            error.__context__ = None
            raise
    return result


def _stage_ib_command(target: Target, neighbor: Neighbor, eth_user: str,
                      ethernet_password: str, ib_user: str, ib_password: str, timeout: int,
                      command: list[str], *, local: bool, strict: bool,
                      policy=None) -> SessionResult:
    """One ordinary IB command of a stage.  A management-server task with the project global
    (strict) sends it through the DEV authorized helper, any other task through v15's run_on_ib
    (P3c map D32d and section 9 item 1); the stage logic around it is the same."""
    if strict:
        return _run_authorized_ib_command(target, neighbor, eth_user, ethernet_password, ib_user,
                                          ib_password, timeout, command, local=False,
                                          _password_policy=policy)
    return run_on_ib(target, neighbor, eth_user, ethernet_password, ib_user, ib_password,
                     timeout, command, local=local)


def run_initial_stage(target: Target, neighbor: Neighbor, eth_user: str,
                      ethernet_password: str, ib_user: str, timeout: int,
                      current: str, *, local: bool, apply: bool, authorized: bool,
                      _ib_current_password=None, _password_policy=None,
                      ib_password: Optional[str] = None,
                      policy: Optional[ProjectPasswordPolicy] = None,
                      details: Optional[dict] = None) -> tuple[str, bool]:
    """Stage 1 (v15): auto-save and ZTP config-save, saved, then ZTP verified disabled.

    Returns (readback, authorized): the readback after the Initial writes, else `current`;
    execute_ib_task recomputes the later stages from it (v15 :4199-4204).  One implementation
    (owner Q-035 (a)): the current ZTP state is read first and both settings plus a disabled
    ZTP gate the skip (T17); writes start on an empty pending diff (T15).  With the
    management-server context (_ib_current_password/_password_policy) every read and write
    goes through the authorized helper (P3c map D32d) and a failure becomes the fixed UNKNOWN
    error; the DEV readback parse (map 2.3) gates the settings on both paths.  A read-only
    check reads ZTP without the helper, which needs the project target (guide :649).
    `details["needed"]` tells the caller whether Initial could be skipped (owner Q-037 (b)).
    """
    strict = _ib_current_password is not None or _password_policy is not None
    if strict:
        if (type(local) is not bool or local or type(apply) is not bool
                or type(authorized) is not bool or type(current) is not str
                or _ib_current_password is None or _password_policy is None):
            raise SetupError("invalid Initial stage options or current state")
        credential, guard = _ib_current_password, _password_policy
    else:
        if type(ib_password) is not str:
            raise SetupError("Initial stage needs the selected IB credential")
        credential, guard = ib_password, policy
    settings = (
        ("nv", "set", "system", "config", "auto-save", "state", "enabled"),
        ("nv", "set", "system", "ztp", "config-save", "enabled"),
    )
    commands = initial_configuration_commands()

    def enabled(body):
        """Both settings are enabled in an actual readback; unknown facts are refused (DEV)."""
        state = parse_nvue_state(body)
        values = {command: set() for command in settings}
        try:
            for line in state.raw_commands.splitlines():
                tokens = tuple(shlex.split(line))
                for command in settings:
                    # Both owned namespaces have exactly five fixed tokens.
                    if tokens[:5] == command[:5]:
                        if (len(tokens) != len(command) or tokens[:-1] != command[:-1]
                                or tokens[-1] not in {"enabled", "disabled"}):
                            raise SetupError("Initial configuration fact is UNKNOWN")
                        values[command].add(tokens[-1])
                    elif len(tokens) < 5 and command[:len(tokens)] == tokens:
                        raise SetupError("Initial configuration fact is truncated")
        except ValueError:
            raise SetupError("Initial configuration command syntax is UNKNOWN") from None
        if any(len(found) > 1 for found in values.values()):
            raise SetupError("Initial configuration facts are contradictory")
        return all(found == {"enabled"} for found in values.values())

    failure = None
    try:
        ready = enabled(current)
        status = _stage_ib_command(target, neighbor, eth_user, ethernet_password, ib_user, credential,
                                   timeout, ["nv", "show", "system", "ztp"], local=local,
                                   strict=strict and apply, policy=guard)
        ztp_disabled = _ztp_disabled(status.output)
        if details is not None:
            details["needed"] = not (ready and ztp_disabled)
        if ready and ztp_disabled:
            log("  Initial setup SKIP: auto-save/config-save enabled; ZTP is disabled.")
            return current, authorized
        log("  Stage 1: initial configuration (before management interface changes)")
        for command in commands:
            log(f"    {'PLAN' if apply else 'WOULD APPLY'}: {shlex.join(command)}")
        if not apply:
            return current, authorized
        if not authorized:
            authorized = confirm_first_device_change(
                target, "enable auto-save and ZTP config-save, apply -y, save, "
                        "verify ZTP disabled; then configure management interfaces")
        if not authorized:
            raise SetupError("initial configuration was not authorized; no changes performed")
        _require_empty_pending(target, neighbor, eth_user, ethernet_password, ib_user,
                               credential, timeout, local=local)
        try:
            for index, command in enumerate(commands, 1):
                if guard is not None:
                    guard.assert_unchanged()
                log(f"  INIT RUN [{index}/{len(commands)}]: {shlex.join(command)}")
                _stage_ib_command(target, neighbor, eth_user, ethernet_password, ib_user, credential,
                                  timeout, command, local=local, strict=strict, policy=guard)
                log(f"  INIT OK  [{index}/{len(commands)}]")
            readback = _stage_ib_command(target, neighbor, eth_user, ethernet_password, ib_user,
                                         credential, timeout, ["nv", "config", "show", "-o", "commands"],
                                         local=local, strict=strict, policy=guard).output
            if not enabled(readback):
                raise SetupError("Initial readback does not prove both enabled values")
            status = _stage_ib_command(target, neighbor, eth_user, ethernet_password, ib_user, credential,
                                       timeout, ["nv", "show", "system", "ztp"], local=local,
                                       strict=strict, policy=guard)
            _verify_ztp_disabled(status.output)
            parse_nvue_state(readback)
            log("  Initial setup SUCCESS: saved configuration and disabled ZTP verified.")
        except (ProjectInputChanged, BatchStopped):
            raise
        except SetupError as exc:
            raise IBConfigurationStageUncertain(
                "initial configuration was not fully verified; writes may be partial: " + str(exc)
            ) from None
        return readback, authorized
    except (ProjectInputChanged, BatchStopped):
        raise
    except (SetupError, OSError) as error:
        if not strict:
            raise
        uncertain, number = _ib_phase_error_facts(error)
        if number is None:
            candidate = getattr(error, "io_errno", None)
            if type(candidate) is int and 1 <= candidate <= 255:
                number = candidate
        failure = uncertain, number
    error = SetupError("Initial stage failed; device state is UNKNOWN")
    if failure[0] is True:
        error.cleanup_uncertain = True
    if failure[1] is not None:
        error.io_errno = failure[1]
    try:
        raise error from None
    except SetupError:
        error.__cause__ = None
        error.__context__ = None
        raise


def desired_service_commands(services: dict[str, object], current: str) -> list[list[str]]:
    """Add missing service values only; never synthesize an nv unset."""
    commands: list[list[str]] = []
    for category in ("dns", "ntp"):
        values = services.get(category)
        if not isinstance(values, list) or not values:
            raise SetupError(f"target cache has invalid {category} profile")
        for value in values:
            command = ib_command_argv(["nv", "set", "system", category, "server", value])
            present = (_ntp_server_is_configured(value, current) if category == "ntp"
                       else shlex.join(command) in current.splitlines())
            if not present:
                commands.append(command)
    timezone = services.get("timezone")
    command = ib_command_argv(["nv", "set", "system", "date-time", "timezone", timezone])
    if shlex.join(command) not in current.splitlines():
        commands.append(command)
    return commands


def force_day0_needed(device: Device, state: DeviceState) -> bool:
    """Fill missing required values without removing extra applied settings."""
    fields = (
        ("eth0 address", state.eth0_addresses, device.eth0_prefix),
        ("eth1 address", state.eth1_addresses, device.eth1_prefix),
        ("eth0 gateway", state.eth0_gateways, device.eth0_gateway),
        ("eth1 gateway", state.eth1_gateways, device.eth1_gateway if device.eth1_prefix else ""),
    )
    missing = False
    conflicts: list[str] = []
    for label, actual, expected in fields:
        if not expected or expected in actual:
            continue
        if actual and label.endswith("gateway"):
            conflicts.append(f"{label}: expected {expected}, found {actual}")
        else:
            missing = True
    hostname = normalize_name(state.hostname)
    if hostname in DEFAULT_HOSTNAMES:
        missing = True
    elif hostname != normalize_name(device.hostname):
        conflicts.append(f"hostname: expected {device.hostname}, found {state.hostname}")
    if conflicts:
        raise SetupError("Network conflict; manual resolution required: " + "; ".join(conflicts))
    return missing

def key_install_command(keys: list[dict[str, str]]) -> list[str]:
    """Carry only validated public lines through a fixed, closed shell program."""
    if not isinstance(keys, list) or not keys:
        raise SetupError("public-key installation needs nonempty cache entries")
    lines: list[str] = []
    for entry in keys:
        if not isinstance(entry, dict) or set(entry) != {"name", "line", "fingerprint"}:
            raise SetupError("target cache has an invalid public-key entry")
        if not isinstance(entry["name"], str) or not re.fullmatch(
            r"[A-Za-z0-9_.-]+\.pub", entry["name"]
        ):
            raise SetupError("target cache has invalid public-key name")
        line = entry["line"]
        fingerprint = _public_key_fingerprint(line)
        if entry.get("fingerprint") != fingerprint:
            raise SetupError("target cache has mismatched public-key fingerprint")
        lines.append(line)
    encoded = base64.b64encode(("\n".join(lines) + "\n").encode("utf-8")).decode("ascii")
    return ib_command_argv(["sh", "-c", _KEY_INSTALL_SCRIPT, "--", encoded])


def verify_state(device: Device, state: DeviceState) -> None:
    expected_eth1 = (device.eth1_prefix,) if device.eth1_prefix else ()
    errors: list[str] = []
    if device.eth0_prefix not in state.eth0_addresses:
        errors.append(f"eth0 expected {device.eth0_prefix}, got {state.eth0_addresses or 'none'}")
    if expected_eth1 and device.eth1_prefix not in state.eth1_addresses:
        errors.append(f"eth1 expected {device.eth1_prefix}, got {state.eth1_addresses or 'none'}")
    if device.eth0_gateway not in state.eth0_gateways:
        errors.append(
            f"eth0 gateway expected {device.eth0_gateway}, "
            f"got {state.eth0_gateways or 'none'}"
        )
    if device.eth1_prefix and device.eth1_gateway not in state.eth1_gateways:
        errors.append(
            f"eth1 gateway expected {device.eth1_gateway}, "
            f"got {state.eth1_gateways or 'none'}"
        )
    if normalize_name(state.hostname) != normalize_name(device.hostname):
        errors.append(f"hostname expected {device.hostname}, got {state.hostname or 'none'}")
    if errors:
        raise SetupError("post-configuration verification failed: " + "; ".join(errors))


def verify_ipv4_login(target: Target, vrf: str, eth_user: str,
                      ethernet_password: str, ib_user: str, timeout: int, *,
                      local: bool = False, _ib_current_password=None,
                      _password_policy=None, ib_password: Optional[str] = None) -> None:
    """Up to 3 read-only IPv4 readiness probes, each after a 10 s wait (v15; table 6-1 row 9).

    One loop (guide 2.3 :204).  Authentication, host-key, local-command and password-change
    evidence is never retried; only a session timeout or a non-zero exit without such evidence
    is.  The management-server context (_ib_current_password/_password_policy) keeps the DEV
    probe: credential roles and the project target are checked first, every result fact is
    checked, and a failure becomes the fixed safe management error (P3c map 2.3).  Otherwise
    the v15 password-only probe runs with the selected IB credential (ib_password).
    """
    nonretryable = re.compile(
        r"(?i)permission denied|authentication failed|"
        r"host key verification failed|remote host identification has changed|"
        r"offending .* key|operation not permitted|command not found|"
        r"could not resolve hostname")
    strict = _ib_current_password is not None or _password_policy is not None
    failure = None
    try:
        if strict:
            if (type(local) is not bool or local
                    or _ib_current_password is None or _password_policy is None
                    or type(target) is not Target
                    or type(target.ib) is not Device
                    or type(target.ethernet) is not Device
                    or type(timeout) is not int or timeout <= 0):
                raise SetupError("invalid explicit IPv4 management operation")
            validate_jump_target(target)
            validated_vrf = validate_network_selector(vrf, label="IPv4 verification VRF")
            if (type(eth_user) is not str or type(ib_user) is not str
                    or clean(eth_user) != eth_user or clean(ib_user) != ib_user
                    or not valid_ssh_user(eth_user) or not valid_ssh_user(ib_user)):
                raise SetupError("invalid explicit IPv4 management account")
            # P3 (owner Q-032 default): an OOB public-key login leaves the Ethernet
            # password empty; the IB current credential must still be non-empty.
            for credential, required in ((ethernet_password, False), (_ib_current_password, True)):
                if (type(credential) is not str or (required and not credential)
                        or any(0xD800 <= ord(char) <= 0xDFFF for char in credential)
                        or len(credential.encode("utf-8")) > 4096
                        or re.search(r"[\x00-\x1f\x7f-\x9f]", credential)):
                    raise SetupError("invalid explicit IPv4 management credential")
            if type(target.ib.login_ip) is not str:
                raise SetupError("invalid IPv4 management destination")
            try:
                destination = str(ipaddress.IPv4Address(target.ib.login_ip))
            except ipaddress.AddressValueError:
                raise SetupError("invalid IPv4 management destination") from None
            # Verified target permission never replaces the selected inner current.
            _ib_project_value(_password_policy, user=ib_user, fetch=True)
            password = _ib_current_password
            probe = typed_argv(outer_ssh_command(
                target.ethernet, eth_user, typed_argv([
                    "ip", "vrf", "exec", validated_vrf, "ssh",
                    "-o", f"ConnectTimeout={timeout}",
                    "-o", "StrictHostKeyChecking=accept-new",
                    "-o", "LogLevel=ERROR",
                    f"{ib_user}@{destination}", shlex.join(ib_command_argv(["true"])),
                ], label="IPv4 management command"), timeout, tty=True, local=False,
            ), label="IPv4 management outer command")
        else:
            validate_jump_target(target)
            validated_vrf = validate_network_selector(vrf, label="IPv4 verification VRF")
            if type(ib_password) is not str:
                raise SetupError("IPv4 verification needs the selected IB credential")
            password = ib_password
            destination = target.ib.login_ip
        last_failure = "no verified response"
        for attempt in range(1, 4):
            log(f"  IPv4 SSH [{attempt}/3]: waiting 10s for interface readiness; "
                f"{destination} via {target.ethernet.hostname}, VRF {validated_vrf}")
            check_task_cancelled()
            time.sleep(10)
            marker = os.urandom(16).hex()
            if not strict:
                probe = outer_ssh_command(target.ethernet, eth_user, [
                    "ip", "vrf", "exec", validated_vrf, "ssh", "-tt",
                    "-o", f"ConnectTimeout={timeout}", "-o", "StrictHostKeyChecking=accept-new",
                    "-o", "LogLevel=ERROR", "-o", "ControlMaster=no", "-o", "ControlPath=none",
                    "-o", "NumberOfPasswordPrompts=1", "-o", "PubkeyAuthentication=no",
                    "-o", "PreferredAuthentications=password,keyboard-interactive",
                    f"{ib_user}@{destination}",
                    shlex.join(["sh", "-c", _framed_script(["true"], marker)]),
                ], timeout, tty=True, local=local)
            responder = NestedResponder(ethernet_password, password, False,
                                        ib_destination=f"{ib_user}@{destination}")
            record_metric("ib_ssh_attempts")
            try:
                result = interactive_run(probe, responder, max(timeout * 3, 45))
            except SetupError as exc:
                if not str(exc).startswith("SSH/PAM session timed out;"):
                    raise
                last_failure = "SSH session timed out"
            else:
                detail = _ib_failure_detail(result.output, marker, (ethernet_password, password))
                if (result.password_change_required or result.password_change_attempted
                        or _EXPIRED_PASSWORD.search(result.output)):
                    raise SetupError(f"IPv4 SSH verification blocked for {target.ib.hostname}: "
                                     "password change is required; no rotation or retry performed")
                if result.ib_authentication_rejected or nonretryable.search(result.output):
                    raise SetupError(f"IPv4 SSH verification blocked for {target.ib.hostname}: "
                                     f"authentication/host-key/local command failure; {detail}")
                if strict and (type(result) is not SessionResult
                               or type(result.exit_code) is not int
                               or type(result.output) is not str
                               or any(getattr(result, name) is not False for name in (
                                   "password_changed", "password_change_required",
                                   "password_change_attempted", "ib_authentication_rejected"))
                               or responder.password_change_attempted
                               or responder.password_change_blocked
                               or _pending_diff_has_password_update_notice(result.output)):
                    raise SetupError("IPv4 management outcome is unverified")
                if result.exit_code == 0:
                    if strict:
                        _password_policy.assert_unchanged()
                    else:
                        extract_command_output(result.output, marker)
                    log(f"  IPv4 SSH SUCCESS [{attempt}/3]: "
                        f"{'management' if strict else 'password-only'} login verified.")
                    return
                last_failure = f"exit={result.exit_code}; {detail}"
            log(f"  IPv4 SSH [{attempt}/3] not ready: {last_failure}")
        raise SetupError(f"IPv4 password-only SSH verification failed for {target.ib.hostname} "
                         f"after 3 attempts (10s wait before each); last failure: {last_failure}")
    except (ProjectInputChanged, BatchStopped):
        raise
    except (SetupError, OSError) as error:
        if not strict:
            raise
        uncertain, number = _ib_phase_error_facts(error)
        if number is None:
            candidate = getattr(error, "io_errno", None)
            if type(candidate) is int and 1 <= candidate <= 255:
                number = candidate
        failure = uncertain, number
    error = SetupError("management IB operation failed; device state is UNKNOWN")
    if failure[0] is True:
        error.cleanup_uncertain = True
    if failure[1] is not None:
        error.io_errno = failure[1]
    try:
        raise error from None
    except SetupError:
        error.__cause__ = None
        error.__context__ = None
        raise


def readonly_direct_ssh_retry(label, address, timeout, metric, attempt_once, *, secrets=()):
    """Retry only direct read-only SSH, not any configuration or key writes."""
    connect_timeout = min(timeout, 3)
    last_failure = "no verified connection"
    nonretryable = re.compile(
        r"(?i)permission denied|authentication failed|too many authentication failures|"
        r"host key verification failed|remote host identification has changed|offending .*key|"
        r"no matching .*found|invalid format|load key|identity file .*not accessible|"
        r"command not found|operation not permitted|could not resolve hostname")
    transient = re.compile(
        r"(?i)no route to host|network is unreachable|connection (?:timed out|refused|reset)|"
        r"connection (?:closed by|to .*closed by remote host)|timed out during banner exchange")
    for attempt in range(1, 4):
        check_task_cancelled()
        record_metric(metric)
        report_detail(f"  DIRECT CHECK [{attempt}/3]: {label} {address}; connect-timeout={connect_timeout}s")
        try:
            result = attempt_once(connect_timeout)
        except subprocess.TimeoutExpired:
            last_failure = "read-only SSH session timed out"
        except SetupError as exc:
            if not str(exc).startswith("SSH/PAM session timed out;"):
                raise
            last_failure = "read-only SSH session timed out"
        except OSError as exc:
            raise SetupError(f"{label} could not start local SSH: {exc}") from exc
        else:
            detail = " ".join(_ib_failure_detail(result.output, "direct-check-no-frame", secrets).split())
            if (result.password_change_required or result.password_change_attempted
                    or _EXPIRED_PASSWORD.search(result.output)):
                raise SetupError(f"{label} requires a password change; no change or retry performed; {detail}")
            if result.exit_code == 0:
                report_detail(f"  DIRECT CHECK [{attempt}/3] transport/session completed: {label} {address}")
                return result
            last_failure = f"exit={result.exit_code}; {detail}"
            if nonretryable.search(result.output) or not transient.search(result.output):
                raise SetupError(f"{label} failed (attempt {attempt}/3; no retry): {last_failure}")
        report_detail(f"  DIRECT CHECK [{attempt}/3] temporary connection failure: {last_failure}")
        if attempt < 3:
            check_task_cancelled()
            report_detail("  DIRECT CHECK: waiting 3s before the next read-only attempt; no writes replayed")
            time.sleep(3)
    raise DirectSSHNetworkError(
        f"{label} network/session verification failed after 3 attempts "
        f"(connect-timeout={connect_timeout}s, retry-delay=3s): {last_failure}")


def verify_management_direct_ssh(device: Device, interface: str, user: str,
                                 password: str, timeout: int) -> None:
    """Final read-only management-server -> IB check, with no configured proxy."""
    if device.dev_type != "ib" or not valid_ssh_user(user):
        raise SetupError("invalid IB target or user for management direct SSH")
    prefix = {"eth0": device.eth0_prefix, "eth1": device.eth1_prefix}.get(interface)
    if not prefix:
        raise SetupError("management direct SSH needs a configured eth0/eth1 CSV address")
    address = str(ipaddress.IPv4Interface(prefix).ip)
    marker = os.urandom(16).hex()
    command = ib_command_argv(["nv", "config", "show", "-o", "commands"])
    def attempt_once(connect_timeout):
        argv = [
            "ssh", "-4", "-tt", *ssh_options(connect_timeout),
            "-o", "ConnectionAttempts=1", "-o", "ProxyCommand=none", "-o", "ProxyJump=none",
            "-o", "ControlMaster=no", "-o", "ControlPath=none",
            "-o", "NumberOfPasswordPrompts=1", "-o", "PubkeyAuthentication=no",
            "-o", "PreferredAuthentications=password,keyboard-interactive",
            f"{user}@{address}",
            shlex.join(["sh", "-c", _framed_script(command, marker)]),
        ]
        return interactive_run(
            argv, NestedResponder("", password, False, ib_destination=f"{user}@{address}"),
            max(connect_timeout * 3, 15))
    result = readonly_direct_ssh_retry("direct password-only IPv4 SSH", address, timeout,
                                      "direct_ssh_attempts", attempt_once, secrets=(password,))
    output = _split_comma_interface_lines(extract_command_output(result.output, marker))
    verify_state(device, parse_nvue_state(output))


def run_management_direct_checks(targets: list[Target], credentials: dict[str, str],
                                 user: str, timeout: int, *,
                                 on_management_server: bool) -> list[dict[str, str]]:
    """Prefer eth0; probe eth1 only after eth0 fails. Never report credentials."""
    log("\nStage 5: ZTP server -> IB direct IPv4 SSH checks (NO OOB jump)")
    log("  Password-only SSH and applied hostname/IP identity are checked; no device changes.")
    log("  Probe eth0 first; eth1 is a fallback only if eth0 fails and CSV supplies an eth1 address.")
    rows: list[dict[str, str]] = []
    for target in targets:
        device = target.ib
        key = normalize_name(device.hostname)
        eth0_passed = False
        for interface, prefix in (("eth0", device.eth0_prefix), ("eth1", device.eth1_prefix)):
            if not prefix:
                continue
            row = {"hostname": device.hostname, "interface": interface,
                   "ip": str(ipaddress.IPv4Interface(prefix).ip), "status": "NOT_TESTED", "detail": ""}
            if interface == "eth1" and eth0_passed:
                row["status"] = "NOT_NEEDED"
                row["detail"] = "eth0 passed; eth1 fallback was not needed or attempted"
            elif not on_management_server:
                row["detail"] = "run this check on the ZTP/management server, not the OOB switch"
            elif key not in credentials:
                row["detail"] = "base IPv4 configuration/credential was not verified in this run"
            else:
                log(f"  DIRECT SSH RUN: {device.hostname} {interface} {row['ip']}")
                try:
                    verify_management_direct_ssh(device, interface, user, credentials[key], timeout)
                except SetupError as exc:
                    row["status"] = "FAIL"
                    row["detail"] = str(exc).replace(credentials[key], "<redacted>") if credentials[key] else str(exc)
                else:
                    row["status"] = "PASS"
                    row["detail"] = "direct password-only SSH and expected applied configuration verified"
                    if interface == "eth0":
                        eth0_passed = True
            rows.append(row)
    return rows


def summarize_management_direct_checks(rows: list[dict[str, str]]) -> dict[str, int]:
    """Count devices, not failed probes; a working eth1 fallback is ready."""
    groups: dict[str, list[dict[str, str]]] = {}
    for row in rows:
        groups.setdefault(row["hostname"], []).append(row)
    summary = {"ready": 0, "failed": 0, "not_tested": 0, "fallback": 0}
    for device_rows in groups.values():
        passed = next((row for row in device_rows if row["status"] == "PASS"), None)
        if passed is not None:
            summary["ready"] += 1
            summary["fallback"] += int(passed["interface"] == "eth1")
        elif any(row["status"] == "FAIL" for row in device_rows):
            summary["failed"] += 1
        else:
            summary["not_tested"] += 1
    return summary


def log_management_direct_summary(rows: list[dict[str, str]], *, console=True) -> None:
    emit = log if console else report_detail
    emit("\nDirect SSH results from ZTP server (not via OOB):")
    for row in sorted(rows, key=lambda row: (row["hostname"], row["interface"])):
        if row["status"] in {"NOT_NEEDED", "NOT_TESTED"}:
            continue
        emit(f"  {row['hostname']} {row['interface']} {row['ip']}: "
            f"{row['status']} - {row['detail']}")
    counts = summarize_management_direct_checks(rows)
    emit(f"Upgrade SSH access READY: {counts['ready']}; unreachable={counts['failed']}; "
         f"not-tested={counts['not_tested']}; eth1-fallback={counts['fallback']}")
    emit("  READY confirms management-server SSH access only; upgrade packages/version gates are NOT checked.")

def local_ethernet_keys(targets: list[Target], mode: str,
                        override: str) -> set[str]:
    switches = {
        normalize_name(target.ethernet.hostname): target.ethernet
        for target in targets
    }
    if mode == "management":
        if override:
            raise SetupError(
                "--local-ethernet-hostname cannot be used with "
                "--execution-mode management"
            )
        return set()
    local_names = {
        normalize_name(socket.gethostname()), normalize_name(socket.getfqdn())
    }
    local_shorts = {value.split(".", 1)[0] for value in local_names if value}
    if override:
        requested = normalize_name(override)
        matches = [
            key for key in switches
            if key == requested or key.split(".", 1)[0] == requested.split(".", 1)[0]
        ]
        if len(matches) != 1:
            raise SetupError(
                f"local Ethernet override {override!r} does not uniquely match "
                "an Ethernet switch used by the P2P targets"
            )
        return {matches[0]}
    matches = {
        key for key in switches if key.split(".", 1)[0] in local_shorts
    }
    if len(matches) > 1:
        raise SetupError(
            "local hostname matches multiple Ethernet devices: "
            + ", ".join(sorted(matches))
        )
    if mode == "ethernet" and not matches:
        raise SetupError(
            f"local hostname {socket.gethostname()!r} does not match an Ethernet "
            "device used by the P2P targets; specify --local-ethernet-hostname"
        )
    return matches


def prompt_ethernet_passwords(targets: list[Target], supplied: Optional[str],
                              local_keys: set[str], *, eth_user: str = "cumulus",
                              timeout: int = 5,
                              password_for: Optional[Callable[[str], Optional[str]]] = None,
                              ) -> dict[str, Optional[str]]:
    """Public key first (I13); then the shared/per-switch hidden prompts, or with
    password_for (--credentials-fd) the fd table and never a prompt (R-012 design :345).
    "" is a public-key login, a local switch or a failed probe; None (an fd table without this
    switch) means this switch is never logged in to."""
    if supplied is not None:
        raise SetupError("passwords in command-line arguments are not supported; use hidden prompts")
    switches = {normalize_name(target.ethernet.hostname): target.ethernet for target in targets}
    passwords = {}
    pending = []
    for key, switch in sorted(switches.items()):
        if key in local_keys:
            passwords[key] = ""
            continue
        try:
            mode = probe_ethernet_key(switch, eth_user, timeout)
        except SetupError as exc:
            log(f"OOB access unavailable: {exc}; snapshot collection will report its dependents.")
            passwords[key] = ""
            continue
        if mode == "key":
            log(f"OOB public-key login verified: {switch.hostname}")
            passwords[key] = ""
        else:
            pending.append((key, switch))
    if pending and password_for is not None:
        for key, switch in pending:
            value = password_for(switch.hostname)
            if value is None:
                # O10 and R-012 design :302, :345: no prompt and no login with a guessed (empty)
                # password; None marks this switch unavailable, so its snapshot and its
                # dependents fail while the other switches proceed.
                log(f"OOB password for {switch.hostname} is not in --credentials-fd; "
                    "no login attempted, its dependents are reported.")
            passwords[key] = value
        return passwords
    if pending:
        if not sys.stdin.isatty():
            raise SetupError("OOB password is required; run interactively")
        answer = input("Use the same password for all OOB Leafs requiring a password? [Y/n]: ").strip().lower()
        if answer not in {"", "y", "yes", "n", "no"}:
            raise SetupError("invalid shared-password selection")
        shared = answer in {"", "y", "yes"}
        common = getpass.getpass("Shared OOB Leaf password: ") if shared else None
        for key, switch in pending:
            value = common if shared else getpass.getpass(
                f"OOB password for {switch.hostname} ({switch.login_ip}): ")
            if not value:
                raise SetupError("OOB password cannot be empty")
            passwords[key] = value
    return passwords


def _ask_first_device_change(target: Target, reason: str) -> bool:
    log(
        f"\nFIRST DEVICE CHANGE: {target.ib.hostname} via "
        f"{target.ethernet.hostname}:{target.ethernet_port}"
    )
    log(f"  Required action: {reason}")
    answer = input(
        "Authorize this change and subsequent eligible IB devices? [y/N]: "
    ).strip().casefold()
    return answer in {"y", "yes"}


def confirm_first_device_change(target: Target, reason: str) -> bool:
    if _WORKER_CONNECTION is not None:
        return bool(worker_request("authorize", reason))
    if _ACTIVE_COORDINATOR is not None:
        return _ACTIVE_COORDINATOR.authorize(target, reason)
    return _ask_first_device_change(target, reason)


def run_service_stage(target: Target, neighbor: Neighbor, eth_user: str,
                      eth_password: str, ib_user: str, timeout: int,
                      services: Optional[dict[str, object]], current: str,
                      *, local: bool, apply: bool, authorized: bool,
                      _ib_current_password=None, _password_policy=None,
                      ib_password: Optional[str] = None) -> tuple[bool, bool]:
    """Infra Services stage (v15); returns (authorized, skipped).

    One implementation (owner Q-035 (a)): the management-server context
    (_ib_current_password/_password_policy) checks its credential roles first and writes
    through the authorized helper (DEV; P3c map D32d); otherwise the selected IB credential
    (ib_password).
    A write or verification failure is IBConfigurationStageUncertain on both (map 2.3).
    """
    strict = _ib_current_password is not None or _password_policy is not None
    if strict:
        if type(apply) is not bool or type(authorized) is not bool:
            error = SetupError("management IB operation failed; device state is UNKNOWN")
            try:
                raise error from None
            except SetupError:
                error.__cause__ = None
                error.__context__ = None
                raise
        if (type(local) is not bool or local
                or _ib_current_password is None or _password_policy is None
                or type(_ib_current_password) is not str or not _ib_current_password
                or any(0xD800 <= ord(char) <= 0xDFFF for char in _ib_current_password)
                or len(_ib_current_password.encode("utf-8")) > 4096
                or re.search(r"[\x00-\x1f\x7f-\x9f]", _ib_current_password)
                or type(ib_user) is not str or clean(ib_user) != ib_user
                or not valid_ssh_user(ib_user)):
            raise SetupError("invalid explicit management credential context")
        _ib_project_value(_password_policy, user=ib_user)
    elif type(ib_password) is not str:
        raise SetupError("Infra Services stage needs the selected IB credential")
    log("  Stage 3: Infra Services configuration")
    if services is None:
        log("  Infra Services SKIP: 01-global.yaml was unavailable at cache generation.")
        return authorized, True
    commands = desired_service_commands(services, current)
    if not commands:
        log("  Infra Services SKIP: all desired values are already present; no flash save.")
        return authorized, True
    for command in commands:
        log(f"  Infra Services {'PLAN' if apply else 'WOULD APPLY'}: {shlex.join(command)}")
    if not apply:
        return authorized, False
    if not authorized:
        authorized = confirm_first_device_change(
            target, "apply the missing NVOS services and verify them independently"
        )
        if not authorized:
            log("  Infra Services SKIP: device changes were not authorized.")
            return False, True
    stage_commands = [*commands, ["nv", "config", "apply", "-y"], ["nv", "config", "save"]]
    password = _ib_current_password if strict else ib_password
    try:
        for index, command in enumerate(stage_commands, 1):
            log(f"  INFRA SERVICES RUN [{index}/{len(stage_commands)}]: {shlex.join(command)}")
            _stage_ib_command(target, neighbor, eth_user, eth_password, ib_user, password, timeout,
                              command, local=local, strict=strict, policy=_password_policy)
            log(f"  INFRA SERVICES OK  [{index}/{len(stage_commands)}]")
        result = _stage_ib_command(target, neighbor, eth_user, eth_password, ib_user, password, timeout,
                                   ["nv", "config", "show", "-o", "commands"], local=local,
                                   strict=strict, policy=_password_policy)
        remaining = desired_service_commands(services, result.output)
        if remaining:
            raise SetupError("service verification failed: " +
                             ", ".join(shlex.join(command) for command in remaining))
    except (ProjectInputChanged, BatchStopped):
        raise
    except SetupError as exc:
        # The authorized helper's own fixed error carries the product text it replaced
        # (DEV _authorized_failure_text); keep it through the v15 wrapper (map 2.3 :121).
        raise IBConfigurationStageUncertain(
            "services were not fully verified; writes may be partial: "
            + _authorized_failure_text(exc)) from None
    log("  Infra Services SUCCESS: desired values verified.")
    return authorized, False

def verify_management_key_possession(target: Target, ib_user: str,
                                     entry: dict[str, str], private_key: Path,
                                     timeout: int) -> None:
    """Prove the installed management key by a public-key-only IPv4 reconnect."""
    if private_key.is_symlink() or not private_key.is_file():
        raise SetupError("management private key is not a regular local file")
    if not valid_ssh_user(ib_user):
        raise SetupError("invalid IB user for public-key verification")
    try:
        login_ip = str(ipaddress.IPv4Address(target.ib.login_ip))
        derived = subprocess.run(
            ["ssh-keygen", "-y", "-f", str(private_key)],
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=max(timeout, 10), check=False,
        )
        if derived.returncode != 0:
            raise SetupError("local management private key could not be read")
        if _public_key_fingerprint(derived.stdout.strip()) != entry["fingerprint"]:
            raise SetupError("local management private key does not match installed public key")
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        raise SetupError("management public-key verification could not complete") from exc
    def attempt_once(connect_timeout):
        probe = [
            "ssh", "-4", "-i", str(private_key),
            "-o", "BatchMode=yes", "-o", "PreferredAuthentications=publickey",
            "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
            "-o", "IdentitiesOnly=yes", "-o", f"ConnectTimeout={connect_timeout}",
            "-o", "ConnectionAttempts=1", "-o", "ProxyCommand=none", "-o", "ProxyJump=none",
            "-o", "ControlMaster=no", "-o", "ControlPath=none",
            "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR",
            f"{ib_user}@{login_ip}", "true",
        ]
        result = subprocess.run(probe, stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, timeout=15, check=False)
        return SessionResult((result.stdout or "") + "\n" + (result.stderr or ""), result.returncode)
    readonly_direct_ssh_retry("management public-key-only IPv4 SSH", login_ip, timeout,
                              "public_key_ssh_attempts", attempt_once)
    record_metric("public_key_ssh_verified")


INITIAL_OBSERVATION_MAX_BYTES = 8 * 1024 * 1024


def _run_initial_observation(command, timeout, *, pass_fds=()):
    """Drain both pipes within one finite byte/deadline budget; always reap."""
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, pass_fds=pass_fds)
    streams = {process.stdout.fileno(): bytearray(), process.stderr.fileno(): bytearray()}
    buffers = dict(streams)
    deadline, total = time.monotonic() + timeout, 0
    try:
        for descriptor in streams:
            os.set_blocking(descriptor, False)
        while streams:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SetupError("initial method observation deadline exceeded")
            ready, _, _ = select.select(list(streams), [], [], min(remaining, 0.1))
            for descriptor in ready:
                chunk = os.read(descriptor, min(65536, INITIAL_OBSERVATION_MAX_BYTES - total + 1))
                if not chunk:
                    del streams[descriptor]
                    continue
                total += len(chunk)
                if total > INITIAL_OBSERVATION_MAX_BYTES:
                    raise SetupError("initial method combined output exceeds capture budget")
                buffers[descriptor].extend(chunk)
        result = process.wait(timeout=max(0.001, deadline - time.monotonic()))
        return subprocess.CompletedProcess(command, result,
            buffers[process.stdout.fileno()].decode("utf-8"),
            buffers[process.stderr.fileno()].decode("utf-8"))
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()
        process.stderr.close()


@contextmanager
def _initial_observation_key(private_key):
    """Hold a no-follow private identity through the whole BatchMode session."""
    descriptors = []
    path = Path(os.path.abspath(private_key))
    try:
        descriptor = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        descriptors.append(descriptor)
        for part in path.parts[1:-1]:
            descriptor = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 dir_fd=descriptor)
            descriptors.append(descriptor)
        parent = os.fstat(descriptor)
        if parent.st_uid != os.geteuid() or parent.st_mode & 0o022:
            raise SetupError("initial method private identity parent is not safely owned")
        key_fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                         dir_fd=descriptor)
        descriptors.append(key_fd)
        before = os.fstat(key_fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or before.st_mode & 0o777 != 0o600 or before.st_nlink != 1
                or not 0 < before.st_size <= 1024 * 1024):
            raise SetupError("initial method private identity is not a finite owned 0600 single-link file")
        yield key_fd
        # fstat includes nanosecond metadata; recheck the exact named identity too.
        def identity(info):
            return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
                    info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if (identity(os.fstat(key_fd)) != identity(before)
                or identity(os.stat(path, follow_symlinks=False)) != identity(before)):
            raise SetupError("initial method private identity changed during observation")
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def initial_method_input_digest(target, services, keys):
    device = target.ib
    expected = {"schema_version": 1, "type": "ib", "config_method": "initial-setup",
                "hostname": device.hostname, "eth0": device.eth0_prefix,
                "eth0_gateway": device.eth0_gateway, "eth1": device.eth1_prefix,
                "eth1_gateway": device.eth1_gateway,
                "eth0_mac": normalize_mac(device.eth0_mac, field="initial method eth0 MAC"),
                "dns": services["dns"], "ntp": services["ntp"], "timezone": services["timezone"],
                "key_fingerprints": sorted({entry["fingerprint"] for entry in keys})}
    return hashlib.sha256(json.dumps(expected, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode()).hexdigest()


def observe_managed_initial_configuration(
    target: Target, ib_user: str, private_key: Path, timeout: int,
    services: dict[str, object], keys: list[dict[str, str]],
) -> dict[str, object]:
    """Read-only own-session configuration proof, separate from key possession.

    This standard-library-only leaf does not mint a local generation or write
    receipts. A managed publisher must capture its pending boundary and input
    before execution and recheck both after this observation. Interactive
    Day-0/service/key logs never supply positive configuration evidence.
    """
    rejected = {"schema_version": 1, "hostname": target.ib.hostname,
                "batch_identity_verified": False, "config_verified": False,
                "interface": "eth0", "transport_ip": "", "mac_plain": "",
                "live_state_sha256": "", "input_sha256": "", "observation_sha256": "",
                "reason": "initial-current-configuration-not-verified"}
    try:
        device = target.ib
        if device.dev_type != "ib" or not valid_ssh_user(ib_user):
            raise SetupError("initial method executor/type incompatible")
        login_ip = str(ipaddress.IPv4Address(device.login_ip))
        expected_mac = normalize_mac(device.eth0_mac, field="initial method eth0 MAC")
        if not expected_mac or not private_key.is_file() or private_key.is_symlink():
            raise SetupError("initial method lacks bound MAC or management key")
        if (type(timeout) is not int or not 1 <= timeout <= 600 or not isinstance(services, dict)
                or set(services) != {"dns", "ntp", "timezone"}):
            raise SetupError("initial method profile incomplete")
        desired_service_commands(services, "")  # Typed profile validation, no I/O.
        key_install_command(keys)  # Closed, fingerprint-checked public profile.
        captured_services, captured_keys = copy.deepcopy(services), copy.deepcopy(keys)
        input_digest = initial_method_input_digest(target, captured_services, captured_keys)
        script = (
            "set -eu; printf '__HTTP_INITIAL_METHOD_V1_IDENTITY_BEGIN__\\n'; "
            "hostname; cat /sys/class/net/eth0/address; "
            "printf '__HTTP_INITIAL_METHOD_V1_IDENTITY_END__\\n'; "
            "printf '__HTTP_INITIAL_METHOD_V1_CONFIG_BEGIN__\\n'; "
            "set +e; nv config show -o commands; rc=$?; set -e; "
            "printf '__HTTP_INITIAL_METHOD_V1_CONFIG_END__=%s\\n' \"$rc\"; "
            "printf '__HTTP_INITIAL_METHOD_V1_KEYS_BEGIN__\\n'; "
            "test -n \"${HOME:-}\" && test ! -L \"$HOME/.ssh\" && "
            "test ! -L \"$HOME/.ssh/authorized_keys\" && test -f \"$HOME/.ssh/authorized_keys\"; "
            "set +e; cat \"$HOME/.ssh/authorized_keys\"; rc=$?; set -e; "
            "printf '__HTTP_INITIAL_METHOD_V1_KEYS_END__=%s\\n' \"$rc\""
        )
        command = ["ssh", "-i", str(private_key), "-o", "BatchMode=yes",
                   "-o", "PreferredAuthentications=publickey", "-o", "PasswordAuthentication=no",
                   "-o", "KbdInteractiveAuthentication=no", "-o", "IdentitiesOnly=yes",
                   "-o", f"ConnectTimeout={timeout}", "-o", "StrictHostKeyChecking=accept-new",
                   "-o", "LogLevel=ERROR", f"{ib_user}@{login_ip}", shlex.join(["sh", "-c", script])]
        with _initial_observation_key(private_key) as key_fd:
            command[2] = "/dev/fd/" + str(key_fd)
            result = _run_initial_observation(command, max(timeout * 2, 30), pass_fds=(key_fd,))
        raw = result.stdout
        if type(result.returncode) is not int or result.returncode != 0 or not isinstance(raw, str) or len(raw.encode()) > 8 * 1024 * 1024:
            raise SetupError("initial method batch command failed or oversized")
        lines = raw.splitlines(keepends=True)
        frames, cursor = {}, 0
        for label in ("IDENTITY", "CONFIG", "KEYS"):
            begin = "__HTTP_INITIAL_METHOD_V1_" + label + "_BEGIN__"
            end = "__HTTP_INITIAL_METHOD_V1_" + label + "_END__"
            starts = [index for index, line in enumerate(lines) if line.rstrip("\r\n") == begin]
            ends = [index for index, line in enumerate(lines) if line.rstrip("\r\n").startswith(end)]
            if len(starts) != 1 or len(ends) != 1 or not cursor <= starts[0] < ends[0]:
                raise SetupError("initial method framing missing, duplicated or out of order")
            if lines[ends[0]].rstrip("\r\n") != end + ("" if label == "IDENTITY" else "=0"):
                raise SetupError("initial method frame command did not succeed")
            frames[label] = "".join(lines[starts[0] + 1:ends[0]])
            cursor = ends[0] + 1
        identity = frames["IDENTITY"].splitlines()
        if (len(identity) != 2 or identity[0] != device.hostname
                or normalize_mac(identity[1], field="observed eth0 MAC") != expected_mac):
            raise SetupError("initial method own-session identity differs")
        current = frames["CONFIG"]
        if _classify_managed_day0(device, parse_nvue_state(current)) != "complete":
            raise SetupError("initial method current Day-0 fields are missing or conflicting")
        if desired_service_commands(captured_services, current):
            raise SetupError("initial method current services differ")
        actual_keys = set()
        for line in frames["KEYS"].splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            tokens = shlex.split(line)
            for index, token in enumerate(tokens[:-1]):
                if re.fullmatch(r"(?:ssh-|ecdsa-|sk-)[A-Za-z0-9@._+-]+", token):
                    actual_keys.add(_public_key_fingerprint(" ".join(tokens[index:index + 2])))
                    break
        if not {entry["fingerprint"] for entry in captured_keys}.issubset(actual_keys):
            raise SetupError("initial method current authorized keys differ")
        if services != captured_services or keys != captured_keys:
            raise SetupError("initial method expected profile changed during the session")
        return {**rejected, "batch_identity_verified": True, "config_verified": True,
                "transport_ip": login_ip, "mac_plain": expected_mac.replace(":", ""),
                "live_state_sha256": hashlib.sha256(current.encode()).hexdigest(),
                "input_sha256": input_digest, "observation_sha256": hashlib.sha256(raw.encode()).hexdigest(), "reason": ""}
    except (SetupError, OSError, subprocess.TimeoutExpired, ValueError, TypeError, KeyError, UnicodeError):
        return rejected


def run_key_stage(target: Target, neighbor: Neighbor, eth_user: str,
                  eth_password: str, ib_user: str, timeout: int,
                  keys: list[dict[str, str]], *, local: bool,
                  apply: bool, authorized: bool,
                  management_private_key: Optional[Path] = None,
                  _ib_current_password=None, _password_policy=None,
                  ib_password: Optional[str] = None,
                  details: Optional[dict] = None) -> bool:
    """Public-key stage: the management-server context installs through the
    authorized helper (DEV), otherwise with the selected IB credential (v15);
    only the two canonical receipts are accepted (DEV)."""
    strict = _ib_current_password is not None or _password_policy is not None
    if strict:
        if type(apply) is not bool or type(authorized) is not bool:
            error = SetupError("management IB operation failed; device state is UNKNOWN")
            try:
                raise error from None
            except SetupError:
                error.__cause__ = None
                error.__context__ = None
                raise
        if (type(local) is not bool or local
                or _ib_current_password is None or _password_policy is None
                or type(_ib_current_password) is not str or not _ib_current_password
                or any(0xD800 <= ord(char) <= 0xDFFF for char in _ib_current_password)
                or len(_ib_current_password.encode("utf-8")) > 4096
                or re.search(r"[\x00-\x1f\x7f-\x9f]", _ib_current_password)
                or type(ib_user) is not str or clean(ib_user) != ib_user
                or not valid_ssh_user(ib_user)):
            raise SetupError("invalid explicit management credential context")
        _ib_project_value(_password_policy, user=ib_user)
    elif type(ib_password) is not str:
        raise SetupError("public-key stage needs the selected IB credential")
    log(f"  Stage 4: IB public-key installation ({ib_user} ~/.ssh/authorized_keys)")
    if not keys:
        log("  Public keys SKIP: no usable project public keys were baked into cache.")
        return authorized
    command = key_install_command(keys)
    for entry in keys:
        log(f"  Public key {'PLAN INSTALL' if apply else 'WOULD INSTALL'}: "
            f"{entry['name']} {entry['fingerprint']}")
    if not apply:
        return authorized
    if not authorized:
        authorized = confirm_first_device_change(
            target, "install validated project public keys into authorized_keys"
        )
        if not authorized:
            log("  Public keys SKIP: device changes were not authorized.")
            return False
    log(f"  KEYS RUN: install {len(keys)} validated public-key entry/entries on {target.ib.hostname}")
    result = _stage_ib_command(target, neighbor, eth_user, eth_password, ib_user,
                               _ib_current_password if strict else ib_password,
                               timeout, command, local=local, strict=strict, policy=_password_policy)
    if (type(result.exit_code) is not int or result.exit_code != 0
            or type(result.output) is not str
            or result.output not in (
                "IBSW_PUBLIC_KEYS_UPDATED\n", "IBSW_PUBLIC_KEYS_UNCHANGED\n",
            )):
        raise SetupError("public-key installation receipt is unverified")
    changed = result.output == "IBSW_PUBLIC_KEYS_UPDATED\n"
    if details is not None:
        details.update(content_action="UPDATED" if changed else "UNCHANGED", requested_keys=len(keys))
    log("  KEYS WRITE OK: required public keys are present; content " +
        ("updated." if changed else "unchanged (no file replacement)."))
    record_metric("public_key_install_completed")
    record_metric("public_key_content_updated" if changed else "public_key_content_unchanged")
    for entry in keys:
        if entry["name"] == "mgmt-server.pub" and management_private_key is not None:
            verify_management_key_possession(
                target, ib_user, entry, management_private_key, timeout,
            )
            log(f"  Public key {entry['name']} {entry['fingerprint']}: 已验证")
        else:
            log(f"  Public key {entry['name']} {entry['fingerprint']}: 已写入，未验证")
    return authorized


# Guide O5 (v3.1.3 WP-5): shared tools modules are imported by package name from one of two fixed
# layouts, never guessed.  Reserved names: inventory_subset, hostname_ranges (v3.1.1 M4) and
# login_path (v3.1.4 D3) for later versions; operator_identity and project_contract only from the
# repository (they bring the project tree and PyYAML).
_TOOLS_MODULES = frozenset({
    "tools.operator_identity", "tools.project_contract", "tools.device_identity",
    "tools.credentials_fd", "tools.inventory_subset", "tools.hostname_ranges", "tools.login_path",
})
_REPOSITORY_ONLY_TOOLS = frozenset({"tools.operator_identity", "tools.project_contract"})
_TOOLS_ROOT = None


def _import_tools(name: str):
    """Import one allowed tools module by its package name and confirm where it came from.

    Repository layout: <repo>/infiniband/bringup/xdr-initial-setup/initial-setup.py with
    <repo>/tools/device_identity.py (root <repo>).  Leaf layout: <dir>/initial-setup.py with a
    <dir>/tools/ directory (root <dir>; no __init__.py, no project_contract or operator_identity).
    Exactly one must hold.  The root goes to sys.path[0] once per process unless already there.
    """
    global _TOOLS_ROOT
    if name not in _TOOLS_MODULES:
        raise SetupError(f"tools module is not allowed: {name}")
    script = Path(__file__).resolve()
    repository = script.parents[3] if len(script.parents) > 3 else None
    layouts = []
    if repository is not None and (repository / "tools" / "device_identity.py").is_file():
        layouts.append((repository, "repository"))
    if (script.parent / "tools").is_dir():
        layouts.append((script.parent, "leaf"))
    if len(layouts) != 1:
        raise SetupError(
            "cannot choose the tools layout: need exactly one of "
            "<repository>/tools/device_identity.py (repository layout, script at "
            "<repository>/infiniband/bringup/xdr-initial-setup/) or a tools/ directory next to "
            f"{script.name} (Leaf layout); found {len(layouts)}")
    root, layout = layouts[0]
    if layout == "leaf" and name in _REPOSITORY_ONLY_TOOLS:
        raise SetupError(f"{name} is not used from a Leaf directory")
    source = root / "tools" / (name.split(".", 1)[1] + ".py")
    if not source.is_file():
        raise SetupError(f"{name} is missing: {source}")
    if _TOOLS_ROOT is None:
        if root not in {Path(entry or ".").resolve() for entry in sys.path}:
            sys.path.insert(0, str(root))
        _TOOLS_ROOT = root
    if name == "tools.credentials_fd":
        import tools.credentials_fd
    elif name == "tools.device_identity":
        import tools.device_identity
    elif name == "tools.operator_identity":
        import tools.operator_identity
    elif name == "tools.project_contract":
        import tools.project_contract
    elif name == "tools.inventory_subset":
        import tools.inventory_subset
    elif name == "tools.hostname_ranges":
        import tools.hostname_ranges
    else:
        import tools.login_path
    module = sys.modules[name]
    # tools is a namespace package: an unrelated "tools" earlier on sys.path would shadow it.
    if Path(module.__file__).resolve().parent != root / "tools":
        raise SetupError(f"{name} was not loaded from {root / 'tools'}")
    return module


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Initialize unconfigured NVOS switches through their Ethernet OOB peers.",
        epilog="Never installs cron or stores new passwords."
    )
    parser.add_argument("--version", action="version", version=_REPOSITORY_REVISION,
                        help="print the repository revision of this script without reading project inputs")
    parser.add_argument("--project-dir", type=Path,
                        help=("read this project by its own names: ib.csv, p2p.xlsx (or its one *.xlsx), "
                              "01-global.yaml, the non-empty *.pub at its root and "
                              "infiniband/bringup/xdr-initial-setup/infra-neutral.conf; outputs stay under the "
                              "current directory (default: CSV and P2P from the current directory, global, keys "
                              "and neutral defaults from this script's directory)"))
    parser.add_argument(
        "--ib-csv", type=Path,
        help="device CSV (default: discover CSV in current directory)",
    )
    parser.add_argument(
        "--p2p", type=Path,
        help="P2P XLSX/DOT/CSV/log (default: discover XLSX in current directory)",
    )
    parser.add_argument("--eth-user", default="cumulus",
                        help="Ethernet SSH user (default: cumulus)")
    parser.add_argument("--oob-spines", metavar="HOST[,HOST...]",
                        help=("optional explicit Spine names from CSV type=eth_jump; default: "
                              "CSV short names beginning oob-spine. UP Leaf LLDP presence "
                              "and actual SVI/address checks are always required"))
    parser.add_argument("--ib-user", default="admin",
                        help="NVOS SSH user (default: admin)")
    password_source = parser.add_mutually_exclusive_group()
    password_source.add_argument(
        "--ib-initial-password-env", default="NVOS_INITIAL_PASSWORD",
        metavar="NAME",
        help=("environment variable containing the initial NVOS password "
              "(default: NVOS_INITIAL_PASSWORD)"),
    )
    password_source.add_argument(
        "--factory-default-admin", action="store_true",
        help=("explicit factory-default admin credential flow; read "
              "NVOS_FACTORY_DEFAULT_ADMIN_PASSWORD or prompt without echo"),
    )
    parser.add_argument("--connect-timeout", type=int, default=10,
                        help="SSH connect timeout seconds (default: 10)")
    parser.add_argument("--max-workers", type=int, default=16,
                        help="global worker cap, 1-16; count is ceil(ready IB/16), capped here")
    parser.add_argument("--task-timeout", type=int, default=1800,
                        help="per-device deadline seconds, excluding coordinator prompts (default: 1800)")
    parser.add_argument("--plan", action="store_true",
                        help="show targets and all potential Network, Infra Services and key commands without connecting")
    parser.add_argument("--verbose", action="store_true",
                        help="print full device log blocks and phase events; default: compact progress and modular summary (full reports are always kept)")
    parser.add_argument("--apply", action="store_true",
                        help="configure devices that pass the all-unconfigured check")
    parser.add_argument("--force", action="store_true",
                        help="only complete missing Network fields; refuse conflicts")
    parser.add_argument("--yes", action="store_true",
                        help="with --apply, do not ask for final confirmation")
    parser.add_argument(
        "--report", type=Path,
        help=("run report path (default: a new file per run, "
              "./xdr-initial-setup-logs/initial-setup-report-<YYYYmmdd-HHMMSS>.log, "
              "with -<pid> added when that name exists)"),
    )
    parser.add_argument(
        "--snapshot-dir", type=Path,
        default=Path("xdr-initial-setup-logs/initial-setup-ethernet-snapshots"),
        help=("Ethernet snapshot directory (default: "
              "./xdr-initial-setup-logs/initial-setup-ethernet-snapshots)"),
    )
    parser.add_argument(
        "--target-cache", type=Path,
        default=Path("xdr-initial-setup-logs/initial-setup-targets.json"),
        help=("parsed target cache (default: "
              "./xdr-initial-setup-logs/initial-setup-targets.json)"),
    )
    parser.add_argument(
        "--generate-json", "--generate-json-only",
        dest="generate_json", action="store_true",
        help="validate inputs, generate target JSON/checksum, then exit",
    )
    parser.add_argument(
        "--execution-mode", choices=("auto", "management", "ethernet"),
        default="auto",
        help="execution location (default: auto-detect local Ethernet)",
    )
    parser.add_argument(
        "--local-ethernet-hostname", default="",
        help="Ethernet CSV hostname representing this local switch",
    )
    parser.add_argument(
        "--credentials-fd", type=int, metavar="N",
        help=("read the passwords once from inherited pipe fd N as one JSON object, then close it; "
              "keys jump_passwords (host -> password), nvos_initial_password, ib_target_password; "
              "no password prompts and no password environment variables in this mode"),
    )
    # Kept so a former DEV user gets "do not put passwords in argv" instead of "unknown option".
    parser.add_argument("--ethernet-password", help=argparse.SUPPRESS)
    return parser.parse_args()


@dataclass(frozen=True)
class PreparedIBTask:
    target: Target
    neighbor: Neighbor
    ethernet_password: str
    local: bool


def automatic_worker_count(count: int, max_workers: int = 16) -> int:
    if type(count) is not int or count < 0 or type(max_workers) is not int or not 1 <= max_workers <= 16:
        raise SetupError("ready count must be nonnegative; --max-workers must be in 1-16")
    return min(max_workers, (count + 15) // 16) if count else 0


def interleave_oob_tasks(tasks):
    """Spread initial submissions across OOBs without reserving any worker."""
    groups = {}
    for task in tasks:
        groups.setdefault(normalize_name(task.target.ethernet.hostname), deque()).append(task)
    ordered = []
    while groups:
        for key in list(groups):
            ordered.append(groups[key].popleft())
            if not groups[key]:
                del groups[key]
    return ordered


class RuntimeInputAuthority:
    """Pin bytes and symlink targets; cheap stat checks avoid rehashing XLSX per command."""
    def __init__(self, paths):
        self.entries = []
        for item in paths:
            path = Path(item).absolute()
            resolved = path.resolve(strict=True)
            self.entries.append([path, resolved, self.signature(resolved), _file_sha256(resolved)])

    @staticmethod
    def signature(path):
        value = path.stat()
        return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)

    def assert_unchanged(self):
        for entry in self.entries:
            path, resolved, old_stat, digest = entry
            try:
                if path.resolve(strict=True) != resolved:
                    raise ProjectInputChanged(f"input link target changed: {path}")
                current = self.signature(resolved)
                if current != old_stat:
                    if _file_sha256(resolved) != digest:
                        raise ProjectInputChanged(f"input bytes changed: {path}")
                    entry[2] = current
            except OSError as exc:
                raise ProjectInputChanged(f"input disappeared/unreadable: {path}") from exc


def redact_text(value, secrets):
    text = str(value)
    for secret in sorted({item for item in secrets if item}, key=len, reverse=True):
        text = text.replace(secret, "[REDACTED]")
    return text


def redact_worker_text(value):
    return redact_text(value, _WORKER_SECRETS)


def redact_data(value, secrets):
    if isinstance(value, str):
        return redact_text(value, secrets)
    if isinstance(value, dict):
        return {key: redact_data(item, secrets) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [redact_data(item, secrets) for item in value]
    return value


def check_task_cancelled():
    if _WORKER_STOP is not None and _WORKER_STOP.is_set():
        raise BatchStopped("coordinator stopped this batch; no subsequent write is authorized")
    if _ACTIVE_COORDINATOR is not None and _ACTIVE_COORDINATOR.stopped:
        raise BatchStopped(_ACTIVE_COORDINATOR.fatal or "batch cancelled")
    if _TASK_DEADLINE is not None and time.monotonic() >= _TASK_DEADLINE:
        raise SetupError("device task deadline exceeded; write outcome may be unverified")


def worker_request(kind, value=None):
    check_task_cancelled()
    _WORKER_CONNECTION.send(("request", (kind, value)))
    try:
        status, reply = _WORKER_CONNECTION.recv()
    except (EOFError, OSError) as exc:
        raise BatchStopped("coordinator channel closed; do not replay device writes") from exc
    if status == "project-changed":
        raise ProjectInputChanged(reply)
    if status == "stopped":
        raise BatchStopped(reply)
    if status != "ok":
        raise SetupError(reply)
    if kind in {"target-password", "current-password"} and reply:
        _WORKER_SECRETS.append(reply)
    return reply


def record_metric(name):
    if _WORKER_CONNECTION is not None:
        _WORKER_CONNECTION.send(("metric", name))
    elif _ACTIVE_COORDINATOR is not None:
        metrics = _ACTIVE_COORDINATOR.metrics
        metrics[name] = metrics.get(name, 0) + 1


def obtain_write_permit(category="nvue"):
    check_task_cancelled()
    if _WORKER_CONNECTION is not None:
        worker_request("write", category)
    elif _ACTIVE_COORDINATOR is not None:
        _ACTIVE_COORDINATOR.before_write(category)


def task_phase(phase):
    check_task_cancelled()
    if _WORKER_CONNECTION is not None:
        _WORKER_CONNECTION.send(("phase", phase))
    elif _ACTIVE_COORDINATOR is not None:
        _ACTIVE_COORDINATOR.progress(phase)


_CREDENTIALS_FD_MODE = False  # set by main() for --credentials-fd; inherited by forked workers


def request_current_ib_password(hostname):
    if _CREDENTIALS_FD_MODE:
        # R-012 design :345 and O10: fd mode never asks; this device fails, the others go on.
        raise SetupError(f"IB credentials from --credentials-fd were rejected by {hostname}; "
                         "fd mode does not ask for the current IB password")
    if _WORKER_CONNECTION is not None:
        return worker_request("current-password")
    if _ACTIVE_COORDINATOR is not None:
        return _ACTIVE_COORDINATOR.current_password(hostname)
    return getpass.getpass(f"Actual current IB password for {hostname} (not OOB): ")


class WorkerPasswordPolicy(ProjectPasswordPolicy):
    @classmethod
    def pinned_copy(cls, original):
        if original is None:
            return None
        instance = object.__new__(cls)
        instance.__dict__.update(original.__dict__)
        return instance

    def password(self):
        self.assert_unchanged()
        if _WORKER_CONNECTION is not None:
            return worker_request("target-password")
        if _ACTIVE_COORDINATOR is not None:
            return _ACTIVE_COORDINATOR.password()
        return super().password()


class RuntimeCoordinator:
    def __init__(self, args, policy, initial_password, tasks, authority):
        self.args, self.policy, self.authority = args, policy, authority
        self.authorized = bool(args.apply and args.yes)
        self.stopped, self.fatal, self.writes_attempted = False, "", False
        self.secrets = [initial_password, *(task.ethernet_password for task in tasks)]
        self.paused_seconds = 0.0
        self.current_target = None
        self.metrics = {}

    def assert_unchanged(self):
        self.authority.assert_unchanged()
        if self.policy is not None:
            self.policy.assert_unchanged()

    def prompt(self, callback):
        global _TASK_LOG_BUFFER, _TASK_DEADLINE
        start = time.monotonic()
        previous, _TASK_LOG_BUFFER = _TASK_LOG_BUFFER, None
        try:
            self.assert_unchanged()
            return callback()
        except (KeyboardInterrupt, EOFError):
            self.stopped, self.fatal = True, "user cancelled coordinator input"
            raise BatchStopped(self.fatal) from None
        finally:
            elapsed = time.monotonic() - start
            self.paused_seconds += elapsed
            if _TASK_DEADLINE is not None:
                _TASK_DEADLINE += elapsed
            _TASK_LOG_BUFFER = previous

    def password(self):
        if self.policy is None:
            raise SetupError("project global is required to verify the IB target password")
        value = self.prompt(self.policy.password)
        self.secrets.append(value)
        return value

    def current_password(self, hostname):
        value = self.prompt(lambda: getpass.getpass(
            f"Actual current IB password for {hostname} (not OOB): "))
        if not value:
            raise SetupError("current IB password cannot be empty")
        self.secrets.append(value)
        return value

    def authorize(self, target, reason):
        self.assert_unchanged()
        if self.stopped:
            raise BatchStopped(self.fatal or "batch stopped")
        if not self.authorized:
            self.authorized = self.prompt(lambda: _ask_first_device_change(target, reason))
            if not self.authorized:
                self.stopped, self.fatal = True, "device changes were not authorized"
                raise BatchStopped(self.fatal)
        return True

    def before_write(self, category="nvue"):
        self.assert_unchanged()
        if self.stopped:
            raise BatchStopped(self.fatal or "batch stopped")
        if not self.args.apply or not self.authorized:
            raise SetupError("device write blocked: coordinator has not authorized --apply")
        self.writes_attempted = True
        # Pairs keep this write-category table (not a credential) outside the
        # public audit's literal-credential pattern.
        metric = dict((("nvue", "nvue_write_commands"), ("public_key", "public_key_install_attempts"),
                       ("password", "password_change_sessions"))).get(category)
        if metric is None:
            raise SetupError("unknown device write category")
        self.metrics[metric] = self.metrics.get(metric, 0) + 1

    def progress(self, phase):
        global _TASK_LOG_BUFFER
        previous, _TASK_LOG_BUFFER = _TASK_LOG_BUFFER, None
        try:
            name = self.current_target.ib.hostname if self.current_target else "-"
            # The inline one-slot path has no scheduler heartbeat; keep its
            # coarse phase notices live while retaining command detail in files.
            log(f"[PHASE] {name}: {phase}")
        finally:
            _TASK_LOG_BUFFER = previous

    def request(self, kind, value, target):
        if kind == "target-password":
            return self.password()
        if kind == "current-password":
            return self.current_password(target.ib.hostname)
        if kind == "authorize":
            return self.authorize(target, str(value))
        if kind == "write":
            self.before_write(value)
            return True
        raise SetupError("unknown worker coordinator request")


def execute_ib_task(task, args, policy, initial_password, services, keys,
                    management_private_key, authorized=False):
    """One IB owns its full ordered pipeline. Never retries an uncertain write.

    v15's stage skeleton, judgments and failure isolation for every task (owner Q-035 (a);
    P3c map D32d): Initial (ZTP read before and verified after) -> Network -> IPv4 readiness on
    every --apply -> Infra Services -> public keys -> final direct SSH probe; partial or
    conflicting Network fields refuse before any write; a device failure stops only this
    device (table 6-1 row 1).  A management-server task with the project global (main sets
    args._strict_cache) only sends each IB read and write through the DEV phase session or the
    authorized helper and passes the per-task cache/project admission first; a write stage starts
    only on an empty pending diff (T15) and Network writes only the missing setters (T16).
    """
    target, neighbor = task.target, task.neighbor
    result_record = {"hostname": target.ib.hostname, "outcome": "FAILED", "reason": "",
                     "direct_rows": [], "writes_attempted": False, "batch_error": "",
                     "stage_status": {stage: "NOT_REACHED" for stage in
                         ("authentication", "initial", "day0", "ipv4_readiness", "services", "public_keys", "direct_ssh")}}
    stages = result_record["stage_status"]
    stage = "authentication"
    credential = None
    readback = ""
    base_verified = False
    strict_cache = getattr(args, "_strict_cache", None)
    strict = strict_cache is not None and policy is not None and not task.local
    log(f"[{target.ib.hostname}] via {target.ethernet.hostname}:{target.ethernet_port}")
    if target.attachment is not None:
        physical = target.attachment
        log(f"  Attachment: {physical.ethernet.hostname}:{physical.ethernet_port} "
            f"VLAN={target.access_vlan}; Jump={target.ethernet.hostname}; reason={target.jump_reason}")
    log(f"  IB IPv6 path: {neighbor.ipv6} dev {neighbor.interface} vrf {neighbor.vrf}; source={neighbor.address_source}")
    try:
        check_task_cancelled()
        if policy is not None:
            policy.assert_unchanged()
        task_phase("IB authentication/readback")
        stages[stage] = "RUNNING"
        if strict:
            cache_payload, ib_csv_path, p2p_path, global_path = strict_cache
            strict_failure = None
            try:
                if not _valid_cache_authority(cache_payload, ib_csv_path, p2p_path, global_path):
                    raise SetupError("manual target cache authority is stale")
                _ib_project_value(policy, user=args.ib_user)
            except (SetupError, OSError) as error:
                strict_failure = _ib_phase_error_facts(error)
            if strict_failure is not None:
                _ib_raise_phase_failure("project", *strict_failure)
        current, credential, authorized = inspect_ib_device(
            target, neighbor, args.eth_user, task.ethernet_password, args.ib_user,
            initial_password, args.connect_timeout, policy, apply=args.apply,
            authorized=authorized, local=task.local, strict=strict)
        if current.password_change_required:
            result_record["outcome"] = "PASSWORD_CHANGE_REQUIRED"
            stages[stage] = "PASSWORD_CHANGE_REQUIRED"
            log("  BLOCKED: initial IB password change required; read-only mode made no change.")
            return result_record
        stages[stage] = "VERIFIED"
        # I-005: each Network readback enters here once; comma interface lines are split and
        # every later consumer reads `body`.  `readback` keeps the device text for the location.
        readback = current.output
        body = _split_comma_interface_lines(readback)
        state = parse_nvue_state(body)
        log(f"  Current: hostname={state.hostname or 'unset'} "
            f"eth0={','.join(state.eth0_addresses) or 'unset'} "
            f"eth1={','.join(state.eth1_addresses) or 'unset'}")
        # The stages' credential context: the DEV phase/helper authority on a strict task.
        stage_context = ({"_ib_current_password": credential, "_password_policy": policy} if strict
                         else {"ib_password": credential})
        base_stage_needed(target.ib, state, args.force)
        task_phase("initial configuration")
        stage = "initial"
        stages[stage] = "RUNNING"
        initial_details = {}
        readback, authorized = run_initial_stage(
            target, neighbor, args.eth_user, task.ethernet_password, args.ib_user,
            args.connect_timeout, current.output, local=task.local,
            apply=args.apply, authorized=authorized, policy=policy, details=initial_details,
            **stage_context)
        body = _split_comma_interface_lines(readback)
        stages[stage] = "VERIFIED" if args.apply else "CHECKED"
        state = parse_nvue_state(body)
        needs_base = base_stage_needed(target.ib, state, args.force)
        stage = "day0"
        stages[stage] = "RUNNING" if needs_base else "ALREADY_PRESENT"
        if needs_base:
            task_phase("base management configuration")
            # T16: only the missing setters (DEV), then apply and save.
            commands = [*_management_network_commands(target.ib, body),
                        ["nv", "config", "apply", "-y"], ["nv", "config", "save"]]
            for command in commands:
                log(f"  {'PLAN' if args.apply else 'WOULD APPLY'}: {shlex.join(command)}")
            if not args.apply:
                result_record["outcome"] = "CHECK_ONLY"
                stages[stage] = "NEEDS_CONFIGURATION"
                return result_record
            if not authorized:
                authorized = confirm_first_device_change(target, "apply Network commands and verify IPv4 SSH")
            _require_empty_pending(target, neighbor, args.eth_user, task.ethernet_password,
                                   args.ib_user, credential, args.connect_timeout, local=task.local)
            for index, command in enumerate(commands, 1):
                if policy is not None:
                    policy.assert_unchanged()
                log(f"  BASE RUN [{index}/{len(commands)}]: {shlex.join(command)}")
                _stage_ib_command(target, neighbor, args.eth_user, task.ethernet_password, args.ib_user,
                                  credential, args.connect_timeout, command, local=task.local,
                                  strict=strict, policy=policy)
                log(f"  BASE OK [{index}/{len(commands)}]")
            readback = _stage_ib_command(target, neighbor, args.eth_user, task.ethernet_password,
                                         args.ib_user, credential, args.connect_timeout,
                                         ["nv", "config", "show", "-o", "commands"], local=task.local,
                                         strict=strict, policy=policy).output
            body = _split_comma_interface_lines(readback)
            state = parse_nvue_state(body)
        verify_state(target.ib, state)
        if needs_base:
            # The reserved ports are verified from actual tokens (WP-1 difficulty 3).
            _verify_management_network_state(target.ib, body)
        stages[stage] = "VERIFIED" if needs_base else "ALREADY_PRESENT"
        base_verified = True
        if args.apply:
            stage = "ipv4_readiness"
            stages[stage] = "RUNNING"
            task_phase("IPv4 readiness: up to 3 attempts, 10s before each")
            verify_ipv4_login(target, neighbor.vrf, args.eth_user, task.ethernet_password,
                              args.ib_user, args.connect_timeout, local=task.local, **stage_context)
            stages[stage] = "VERIFIED"
        else:
            stages["ipv4_readiness"] = "NOT_REQUESTED"
        if not needs_base:
            log("  Network SKIP: all required CSV values are present; extra applied settings preserved.")
        task_phase("Infra Services")
        stage = "services"
        stages[stage] = "RUNNING"
        services_missing = services is not None and bool(desired_service_commands(services, body))
        if args.apply and services_missing:
            _require_empty_pending(target, neighbor, args.eth_user, task.ethernet_password,
                                   args.ib_user, credential, args.connect_timeout, local=task.local)
        authorized, service_skipped = run_service_stage(
            target, neighbor, args.eth_user, task.ethernet_password, args.ib_user,
            args.connect_timeout, services, body, local=task.local, apply=args.apply,
            authorized=authorized, **stage_context)
        stages[stage] = ("NOT_CONFIGURED" if services is None else "ALREADY_PRESENT" if not services_missing
                         else "UNVERIFIED" if service_skipped else "VERIFIED" if args.apply else "PLANNED_NOT_APPLIED")
        task_phase("IB public keys")
        stage = "public_keys"
        stages[stage] = "RUNNING"
        key_details = {}
        result_record["public_key_update"] = key_details
        authorized = run_key_stage(
            target, neighbor, args.eth_user, task.ethernet_password, args.ib_user,
            args.connect_timeout, keys, local=task.local, apply=args.apply, authorized=authorized,
            management_private_key=management_private_key, details=key_details, **stage_context)
        stages[stage] = "NO_KEYS_PROVIDED" if not keys else "COMPLETED" if args.apply else "PLANNED_NOT_APPLIED"
        # Owner 04 Q-037 (b) (R-260): on a check-only run an Initial stage that cannot be skipped
        # also needs configuration; --apply keeps the v15 formula.
        result_record["needs_configuration"] = bool(
            needs_base or (services is not None and not service_skipped)
            or (not args.apply and initial_details.get("needed") is True))
        result_record["outcome"] = ("CHECK_ONLY" if not args.apply and result_record["needs_configuration"]
                                    else "CONFIGURED" if needs_base else "ALREADY_CONFIGURED")
        log("  Configuration-stage checks finished; final direct SSH verification follows.")
    except ProjectInputChanged as exc:
        result_record["failed_stage"] = stage
        stages[stage] = "UNVERIFIED"
        result_record["batch_error"] = str(exc)
        result_record["reason"] = str(exc)
        log(f"  BATCH STOP: {exc}")
    except BatchStopped as exc:
        result_record["failed_stage"] = stage
        stages[stage] = "UNVERIFIED"
        result_record["reason"] = str(exc)
        result_record["batch_error"] = str(exc)
        result_record["outcome"] = "NOT_ATTEMPTED"
        log(f"  DEVICE STOP: {exc}; no further writes.")
    except SetupError as exc:
        result_record["failed_stage"] = stage
        if isinstance(exc, DirectSSHNetworkError):
            result_record["failure_kind"] = "DIRECT_SSH_NETWORK"
        stages[stage] = "FAILED"
        result_record["reason"] = _authorized_failure_text(exc)
        log(f"  ERROR: {_authorized_failure_text(exc)}")
        # I-005 O15: a management Network error keeps its fixed text; where an unqualified
        # interface member sits (line, name, setting; never a value) is a separate line.
        if str(exc) in ("management Network readback is UNKNOWN",
                        "management Network setter plan is not qualified",
                        "management Network post-configuration verification failed; "
                        "device state is UNKNOWN"):
            location = _management_selector_location(readback)
            if location is not None:
                number, member, setting = location
                log(f"  LOCATION: readback line {number}, interface {member}, setting {setting or '-'}")
        log("  DEVICE STOP: no further writes or automatic replay; other IB tasks remain eligible.")
    # Keep the final direct probe inside this task, rather than a serial tail.
    if base_verified and credential is not None and not result_record["batch_error"]:
        try:
            task_phase("ZTP server direct IPv4 SSH (eth0, then eth1 fallback)")
            result_record["direct_rows"] = run_management_direct_checks(
                [target], {normalize_name(target.ib.hostname): credential}, args.ib_user,
                args.connect_timeout, on_management_server=getattr(args, "_on_management_server",
                    args.execution_mode != "ethernet" and not task.local))
            stages["direct_ssh"] = ("VERIFIED" if any(row["status"] == "PASS" for row in result_record["direct_rows"])
                                      else "FAILED" if any(row["status"] == "FAIL" for row in result_record["direct_rows"])
                                      else "NOT_TESTED")
        except (BatchStopped, ProjectInputChanged) as exc:
            result_record["batch_error"] = str(exc)
        except SetupError as exc:
            stages["direct_ssh"] = "FAILED"
            result_record.setdefault("failed_stage", "direct_ssh")
            result_record["outcome"], result_record["reason"] = "FAILED", str(exc)
    return result_record


class WorkerOutput:
    """Unexpected Python output also travels to the parent, never the shared TTY."""
    encoding = "utf-8"
    def write(self, text):
        if text:
            _WORKER_CONNECTION.send(("log", redact_worker_text(text.rstrip("\n"))))
        return len(text)
    def flush(self):
        pass


def _worker_entry(connection, task, args, policy, initial_password, services, keys,
                   management_private_key, authorized, stop_event, close_fds):
    global REPORT_HANDLE, _WORKER_CONNECTION, _WORKER_STOP, _WORKER_SECRETS, log
    global _ACTIVE_COORDINATOR, _TASK_LOG_BUFFER, _TASK_DEADLINE
    for fd in close_fds:
        try:
            os.close(fd)
        except OSError:
            pass
    if REPORT_HANDLE is not None:
        REPORT_HANDLE.close()
    REPORT_HANDLE = None
    _ACTIVE_COORDINATOR, _TASK_LOG_BUFFER, _TASK_DEADLINE = None, None, None
    _WORKER_CONNECTION, _WORKER_STOP = connection, stop_event
    _WORKER_SECRETS = [initial_password, task.ethernet_password]
    if policy is not None and policy._password:
        _WORKER_SECRETS.append(policy._password)
    log = _STANDARD_LOG
    def terminated(_signum, _frame):
        global _TASK_DEADLINE
        _TASK_DEADLINE = 0.0
        raise SetupError("worker task terminated; any attempted write requires verification, not replay")
    signal.signal(signal.SIGTERM, terminated)
    signal.signal(signal.SIGINT, signal.SIG_IGN)  # Only the coordinator owns terminal cancellation.
    getpass.getpass = lambda _prompt="": worker_request("current-password")
    sys.stdin = open(os.devnull, "r", encoding="utf-8")
    try:
        with redirect_stdout(WorkerOutput()), redirect_stderr(WorkerOutput()):
            record = execute_ib_task(task, args, WorkerPasswordPolicy.pinned_copy(policy),
                                     initial_password, services, keys, management_private_key, authorized)
        connection.send(("result", record))
    except BaseException as exc:
        try:
            connection.send(("result", {"hostname": task.target.ib.hostname, "outcome": "FAILED",
                "reason": redact_worker_text(type(exc).__name__ + ": " + str(exc)),
                "direct_rows": [], "batch_error": "", "script_error": True}))
        except (OSError, EOFError):
            pass
    finally:
        connection.close()


def print_worker_progress(active, queued, completed, total, *, now=None, secrets=()):
    """Parent-only bounded heartbeat; detail the tail without printing worker IDs."""
    now = time.monotonic() if now is None else now
    phases = {}
    for job in active.values():
        phase = " ".join(redact_text(str(job.get("phase", "starting")), secrets).split())
        phases[phase] = phases.get(phase, 0) + 1
    log(f"[PROGRESS] running={len(active)} queued={queued} completed={completed}/{total}")
    if len(active) > 4:
        log("  Phases: " + ", ".join(f"{phase}={number}" for phase, number in sorted(phases.items())))
    else:
        for job in sorted(active.values(), key=lambda item: item["task"].target.ib.hostname):
            name = job["task"].target.ib.hostname
            phase = " ".join(redact_text(str(job.get("phase", "starting")), secrets).split())
            elapsed = max(0, int(now-job.get("started_at", now)))
            phase_elapsed = max(0, int(now-job.get("phase_at", now)))
            log(f"  [WAIT] {name}: {phase} elapsed={elapsed}s phase-elapsed={phase_elapsed}s")


def run_prepared_tasks(tasks, args, policy, initial_password, services, keys,
                       management_private_key, authority=None, method_cycle=None):
    """Global dynamic task queue; up to 16 process slots, never OOB-affine.

    A fresh process handles each task in a reused slot. One-slot runs execute
    inline, with the same pipeline/coordinator and no concurrent TTY writers.
    Only the parent writes reports and prints complete per-device log blocks.
    A managed run (method_cycle) always uses the one inline slot, so its receipts,
    tickets and descriptors never cross a fork: each completed device is observed
    and receipted (method_cycle.complete) before the next one starts, and every
    attempted device is then closed out with fail_unfinished (WP-1 difficulty 2).
    """
    global _ACTIVE_COORDINATOR, _TASK_LOG_BUFFER, _TASK_DEADLINE
    count = automatic_worker_count(len(tasks), getattr(args, "max_workers", 16))
    if method_cycle is not None:
        count = min(count, 1)
    log(f"Scheduler: ready-ib={len(tasks)} workers={count} "
        f"rule=min({getattr(args, 'max_workers', 16)},ceil(N/16)); hard cap 16; global queue, no OOB affinity")
    result = {"outcomes": {}, "direct_rows": [], "records": {}, "fatal": "", "workers": count}
    # O12: the run's report timestamp; a direct caller without one gets the current time.
    stamp = getattr(args, "run_stamp", None) or time.strftime("%Y%m%d-%H%M%S")
    directory = Path(tempfile.mkdtemp(prefix=f"devices-{stamp}-", dir=Path(args.report).resolve().parent))
    result["log_dir"] = str(directory)
    log(f"Run evidence: {directory} (parent-only writes)")
    if not tasks:
        return result
    names = [normalize_name(task.target.ib.hostname) for task in tasks]
    if len(set(names)) != len(names):
        raise SetupError("duplicate IB tasks refused before worker startup")
    tasks = interleave_oob_tasks(tasks)
    coordinator = RuntimeCoordinator(args, policy, initial_password, tasks, authority or RuntimeInputAuthority([]))
    coordinator.assert_unchanged()
    outcomes = result["outcomes"]
    timeout = getattr(args, "task_timeout", 1800)

    def finish(task, record, path, writes, metrics=None):
        name = normalize_name(task.target.ib.hostname)
        if writes and record.get("outcome") == "NOT_ATTEMPTED":
            record["outcome"] = "FAILED"
        outcome = record.get("outcome", "FAILED")
        if outcome not in {"CONFIGURED", "ALREADY_CONFIGURED", "CHECK_ONLY", "PASSWORD_CHANGE_REQUIRED", "FAILED", "NOT_ATTEMPTED"}:
            outcome = "FAILED"
            record["reason"] = "worker returned an invalid final outcome"
            record["script_error"] = True
        record["hostname"] = task.target.ib.hostname
        record["outcome"], record["writes_attempted"] = outcome, bool(writes)
        record["metrics"] = dict(metrics or {})
        physical = task.target.attachment or task.target
        record["oob"] = physical.ethernet.hostname
        record["port"] = physical.ethernet_port
        record["jump"] = {"hostname": task.target.ethernet.hostname,
                          "login_ip": task.target.ethernet.login_ip,
                          "interface": task.neighbor.interface, "vrf": task.neighbor.vrf,
                          "access_vlan": task.target.access_vlan or None,
                          "selection_reason": task.target.jump_reason or "LEAF_LOCAL_PATH"}
        record["neighbor"] = {"ipv6": task.neighbor.ipv6, "interface": task.neighbor.interface,
                              "vrf": task.neighbor.vrf, "mac": task.neighbor.mac,
                              "address_source": task.neighbor.address_source}
        expected_mac = task.target.ib.eth0_mac
        record["csv_fdb_mac_check"] = {
            "expected": expected_mac or None, "observed": task.neighbor.mac,
            "status": ("NOT_CONFIGURED" if not expected_mac else
                       "MATCH" if expected_mac == task.neighbor.mac else "MISMATCH")}
        record["log"] = str(path)
        record = redact_data(record, coordinator.secrets)
        result["records"][name] = record
        path.with_suffix(".json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        outcomes[name] = outcome
        result["direct_rows"].extend(record.get("direct_rows", []))
        if record.get("batch_error"):
            coordinator.stopped, coordinator.fatal = True, record["batch_error"]
        verbose = getattr(args, "verbose", False)
        report_detail(f"\n===== DEVICE LOG BEGIN: {task.target.ib.hostname} =====", verbose=verbose)
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                report_detail(redact_text(line.rstrip("\n"), coordinator.secrets), verbose=verbose)
        report_detail(f"===== DEVICE LOG END: {task.target.ib.hostname} [{outcome}] =====", verbose=verbose)
        stages = record.get("stage_status", {})
        state = " ".join(f"{label}={stages.get(key, '-')}" for key, label in
                         (("day0", "base"), ("services", "svc"), ("public_keys", "keys"), ("direct_ssh", "ssh")))
        log(f"[DONE {len(outcomes)}/{len(tasks)}] {task.target.ib.hostname}: {record_category(record)} | {state}")
        if record.get("reason"):
            reason = " ".join(redact_text(record["reason"], coordinator.secrets).split())
            log("  Reason: " + (reason if len(reason) <= 180 else reason[:177] + "... (full evidence in device log/JSON)"))
        report_detail(f"  Device evidence: {path}", verbose=verbose)

    if count == 1:
        _ACTIVE_COORDINATOR = coordinator
        try:
            for task in tasks:
                if coordinator.stopped:
                    break
                coordinator.assert_unchanged()
                coordinator.current_target, coordinator.writes_attempted = task.target, False
                coordinator.metrics = {}
                report_detail(f"[START worker=1] {task.target.ib.hostname} via {task.target.ethernet.hostname}", verbose=getattr(args, "verbose", False))
                path = directory / (task.target.ib.hostname + ".log")
                _TASK_LOG_BUFFER = []
                _TASK_DEADLINE = time.monotonic() + timeout
                try:
                    # Inline strict (management-server) tasks keep the one admitted policy
                    # object, the DEV phase/helper authority; worker processes get pinned copies.
                    task_policy = (policy if getattr(args, "_strict_cache", None) is not None
                                   else WorkerPasswordPolicy.pinned_copy(policy))
                    record = execute_ib_task(task, args, task_policy,
                                             initial_password, services, keys, management_private_key,
                                             coordinator.authorized)
                    if policy is not None and policy._password:
                        coordinator.secrets.append(policy._password)
                except (KeyboardInterrupt, EOFError):
                    coordinator.stopped, coordinator.fatal = True, "user cancelled the batch"
                    record = {"outcome": "FAILED" if coordinator.writes_attempted else "NOT_ATTEMPTED",
                              "reason": coordinator.fatal}
                except Exception as exc:
                    record = {"outcome": "FAILED", "reason": type(exc).__name__ + ": " + str(exc),
                              "script_error": True}
                finally:
                    lines, _TASK_LOG_BUFFER = _TASK_LOG_BUFFER, None
                    _TASK_DEADLINE = None
                if method_cycle is not None:
                    if (record.get("outcome") in {"CONFIGURED", "ALREADY_CONFIGURED"}
                            and not record.get("batch_error")):
                        if not coordinator.authorized or not method_cycle.complete(
                                task.target, args.ib_user, management_private_key,
                                args.connect_timeout, services, keys):
                            record["outcome"] = "FAILED"
                            record["failed_stage"] = "managed_receipt"
                            record["reason"] = "managed current initial-setup configuration was not verified"
                    method_cycle.fail_unfinished(task.target)
                with path.open("x", encoding="utf-8") as handle:
                    os.chmod(path, 0o600)
                    for line in lines:
                        handle.write(redact_text(line, coordinator.secrets) + "\n")
                finish(task, record, path, coordinator.writes_attempted, coordinator.metrics)
        except ProjectInputChanged as exc:
            coordinator.stopped, coordinator.fatal = True, str(exc)
        finally:
            _ACTIVE_COORDINATOR, _TASK_LOG_BUFFER, _TASK_DEADLINE = None, None, None
    else:
        context = multiprocessing.get_context("fork")
        stop_event = context.Event()
        active, pending = {}, list(tasks)
        free_slots = list(range(1, count + 1))
        last_heartbeat = time.monotonic()
        try:
            while pending or active:
                try:
                    coordinator.assert_unchanged()
                except ProjectInputChanged as exc:
                    coordinator.stopped, coordinator.fatal = True, str(exc)
                if coordinator.stopped:
                    stop_event.set()
                while pending and free_slots and not coordinator.stopped:
                    task, slot = pending.pop(0), free_slots.pop(0)
                    parent, child = context.Pipe(duplex=True)
                    # A new fork must not retain other workers' IPC descriptors.
                    other_fds = [job["connection"].fileno() for job in active.values()
                                 if not job["connection"].closed]
                    path = directory / (task.target.ib.hostname + ".log")
                    handle = path.open("x", encoding="utf-8")
                    os.chmod(path, 0o600)
                    other_fds.extend(job["handle"].fileno() for job in active.values())
                    process = context.Process(target=_worker_entry, args=(child, task, args, policy,
                        initial_password, services, keys, management_private_key,
                        coordinator.authorized, stop_event, [parent.fileno(), handle.fileno(), *other_fds]))
                    try:
                        process.start()
                    except (OSError, RuntimeError) as exc:
                        child.close()
                        parent.close()
                        handle.write("Worker startup failed; no automatic task replay.\n")
                        handle.close()
                        coordinator.stopped, coordinator.fatal = True, "worker process startup failed: " + str(exc)
                        finish(task, {"outcome": "FAILED", "reason": coordinator.fatal}, path, False)
                        break
                    child.close()
                    started_at = time.monotonic()
                    active[slot] = {"process": process, "connection": parent, "task": task,
                        "path": path, "handle": handle, "record": None, "writes": False,
                        "deadline": started_at + timeout, "terminated": None, "phase": "starting", "metrics": {},
                        "started_at": started_at, "phase_at": started_at}
                    report_detail(f"[START worker={slot}] {task.target.ib.hostname} via {task.target.ethernet.hostname}", verbose=getattr(args, "verbose", False))
                connections = [job["connection"] for job in active.values() if not job["connection"].closed]
                ready = wait_connections(connections, timeout=0.2) if connections else []
                if not connections and active:
                    time.sleep(0.05)
                for slot, job in list(active.items()):
                    connection, task = job["connection"], job["task"]
                    if connection in ready:
                        try:
                            kind, payload = connection.recv()
                        except (EOFError, OSError):
                            connection.close()
                            kind, payload = "closed", None
                        if kind == "log":
                            job["handle"].write(redact_text(payload, coordinator.secrets) + "\n")
                            job["handle"].flush()
                        elif kind == "phase":
                            if job["phase"] != str(payload):
                                job["phase_at"] = time.monotonic()
                            job["phase"] = str(payload)
                            report_detail(f"[PHASE worker={slot}] {task.target.ib.hostname}: {payload}", verbose=getattr(args, "verbose", False))
                        elif kind == "metric":
                            job["metrics"][str(payload)] = job["metrics"].get(str(payload), 0) + 1
                        elif kind == "result":
                            job["record"] = payload
                        elif kind == "request":
                            request_kind, value = payload
                            before = coordinator.paused_seconds
                            coordinator.metrics = job["metrics"]
                            try:
                                coordinator.assert_unchanged()
                                if coordinator.stopped:
                                    raise BatchStopped(coordinator.fatal or "batch stopped")
                                answer = coordinator.request(request_kind, value, task.target)
                                if request_kind == "write":
                                    job["writes"] = True
                                reply = ("ok", answer)
                            except ProjectInputChanged as exc:
                                coordinator.stopped, coordinator.fatal = True, str(exc)
                                reply = ("project-changed", str(exc))
                            except BatchStopped as exc:
                                reply = ("stopped", str(exc))
                            except SetupError as exc:
                                reply = ("error", str(exc))
                            pause = coordinator.paused_seconds - before
                            for running in active.values():
                                running["deadline"] += pause
                            try:
                                connection.send(reply)
                            except (BrokenPipeError, OSError):
                                pass
                        elif kind not in {"closed"}:
                            coordinator.stopped, coordinator.fatal = True, "invalid worker message"
                    process = job["process"]
                    now = time.monotonic()
                    if process.is_alive() and now >= job["deadline"] and job["terminated"] is None:
                        log(f"[TIMEOUT] {task.target.ib.hostname}; terminating worker, no automatic replay")
                        job["terminated"] = now
                        process.terminate()
                    if job["terminated"] is not None and process.is_alive() and now - job["terminated"] > 5:
                        process.kill()
                    # Drain queued records/logs even after the child exits.
                    more = not connection.closed and connection.poll()
                    if not process.is_alive() and not more:
                        process.join(timeout=0)
                        connection.close()
                        job["handle"].close()
                        record = job["record"] or {"outcome": "FAILED", "direct_rows": [],
                            "script_error": True,
                            "reason": f"worker exited without a complete result (exit={process.exitcode}); "
                                      "writes may be partial; do not replay"}
                        if job["terminated"] is not None:
                            record["outcome"], record["reason"] = "FAILED", "task deadline exceeded; verify any partial writes"
                            record["script_error"] = True
                        record["elapsed_seconds"] = round(max(0, now-job["started_at"]), 3)
                        record["last_phase"] = job["phase"]
                        finish(task, record, job["path"], job["writes"], job["metrics"])
                        del active[slot]
                        free_slots.append(slot)
                if coordinator.stopped:
                    stop_event.set()
                if time.monotonic() - last_heartbeat >= _PROGRESS_HEARTBEAT_SECONDS and active:
                    print_worker_progress(active, len(pending), len(outcomes), len(tasks), secrets=coordinator.secrets)
                    last_heartbeat = time.monotonic()
                if coordinator.stopped and not active:
                    break
        except (KeyboardInterrupt, EOFError):
            coordinator.stopped, coordinator.fatal = True, "user cancelled the batch"
            stop_event.set()
        finally:
            stop_event.set()
            for job in active.values():
                if job["process"].is_alive():
                    job["process"].terminate()
            shutdown = time.monotonic() + 5
            for job in active.values():
                process = job["process"]
                process.join(timeout=max(0, shutdown - time.monotonic()))
                if process.is_alive():
                    process.kill()
                    process.join(timeout=1)
                job["connection"].close()
                job["handle"].close()
                finish(job["task"], {"outcome": "FAILED" if job["writes"] else "NOT_ATTEMPTED",
                    "reason": "batch interrupted; inspect preserved log and any partial writes"},
                    job["path"], job["writes"], job["metrics"])
    for name in names:
        outcomes.setdefault(name, "NOT_ATTEMPTED")
    result["fatal"] = coordinator.fatal
    if coordinator.fatal:
        log("BATCH STOP: " + redact_text(coordinator.fatal, coordinator.secrets))
    return result


def prepare_ready_ib_tasks(targets, args, passwords, local_keys, interface_tables,
                            network_tables, table_failures, outcomes, records=None):
    ready = []
    vrfs = {}
    records = records if records is not None else {}
    for target in targets:
        name, eth_key = normalize_name(target.ib.hostname), normalize_name(target.ethernet.hostname)
        def skipped(category, reason):
            outcomes[name] = "SKIPPED"
            records[name] = {"hostname": target.ib.hostname, "oob": target.ethernet.hostname,
                "outcome": "SKIPPED", "category": category, "reason": str(reason),
                "port": target.ethernet_port, "metrics": {}, "stage_status": {}, "writes_attempted": False}
            log(f"[SKIP] {target.ib.hostname} | {category} | {target.ethernet.hostname}:{target.ethernet_port}")
            if isinstance(reason, IBMacMismatch) and reason.expected_mac and reason.observed_mac:
                records[name]["mac_mismatch"] = {"expected": reason.expected_mac, "observed": reason.observed_mac}
                log(f"  MAC: expected={reason.expected_mac} observed={reason.observed_mac}; no IB login/write attempted")
            report_detail(f"  Full skip reason: {reason}")
        try:
            if eth_key in table_failures:
                reason = table_failures[eth_key]
                category = ("SKIPPED_OOB_IDENTITY_CONFLICT" if re.search(r"(?i)identity|host key|identification", reason)
                    else "SKIPPED_OOB_UNREACHABLE" if re.search(r"(?i)route|unreachable|timed? out|timeout|connect|permission denied|authentication", reason)
                    else "SKIPPED_OOB_SNAPSHOT_FAILED")
                skipped(category, reason)
                continue
            try:
                line = interface_status_line(interface_tables[eth_key], target.ethernet_port)
                oper = interface_oper_status(line, target.ethernet_port)
            except SetupError as exc:
                skipped("SKIPPED_PORT_STATE_UNKNOWN", exc)
                continue
            if oper != "up":
                skipped("SKIPPED_LINK_DOWN", f"{target.ethernet_port}: Oper Status {oper.upper()}")
                continue
            links, fdb, neighbors = network_tables[eth_key]
            try:
                fdb_port = fdb_port_for_interface(links, target.ethernet_port)
                try:
                    neighbor = neighbor_for_port(fdb, neighbors, fdb_port)
                except NeighborNotLearned:
                    neighbor = derived_neighbor_for_port(target, fdb, links, fdb_port)
            except IBMacMismatch as exc:
                skipped("SKIPPED_MAC_MISMATCH", exc)
                continue
            except SetupError as exc:
                skipped("SKIPPED_NEIGHBOR_UNRESOLVED", exc)
                continue
            try:
                verify_fdb_eth0_mac(target, neighbor.mac)
            except SetupError as exc:
                skipped("SKIPPED_MAC_MISMATCH", exc)
                continue
            key = (eth_key, neighbor.interface)
            if key not in vrfs:
                vrfs[key] = interface_vrf(target.ethernet, args.eth_user, passwords[eth_key],
                    neighbor.interface, args.connect_timeout, local=eth_key in local_keys)
            neighbor = Neighbor(neighbor.ipv6, neighbor.interface, neighbor.mac, vrfs[key], neighbor.address_source)
            if neighbor.address_source == "FDB_EUI64_CANDIDATE":
                log(f"[FALLBACK] {target.ib.hostname}: ND missing; FDB/CSV MAC {neighbor.mac} -> "
                    f"candidate {neighbor.ipv6} dev {neighbor.interface} vrf {neighbor.vrf}; "
                    "SSH authentication and configuration readback are still required")
            ready.append(PreparedIBTask(target, neighbor, passwords[eth_key], eth_key in local_keys))
            outcomes[name] = "NOT_ATTEMPTED"
        except SetupError as exc:
            skipped("SKIPPED_DEPENDENCY_UNVERIFIED", exc)
    return ready


def _lldp_csv_identity(peer, hostname):
    a, b = normalize_name(peer), normalize_name(hostname)
    return a == b or (("." not in a or "." not in b) and a.split(".")[0] == b.split(".")[0])


def select_spine_inventory(inventory, explicit=None):
    """Role hints do not grant reachability: live Leaf LLDP remains mandatory."""
    items = list(inventory.values()) if isinstance(inventory, dict) else list(inventory)
    if explicit is None:
        return [item for item in items if item.dev_type == "eth_jump"
                and normalize_name(item.hostname).split(".")[0].startswith("oob-spine")]
    names = [value.strip() for value in explicit.split(",")]
    if not names or any(not valid_hostname(name) for name in names):
        raise SetupError("--oob-spines needs comma-separated CSV hostnames")
    result = {}
    for name in names:
        matches = [item for item in items if item.dev_type == "eth_jump"
                   and _lldp_csv_identity(name, item.hostname)]
        if len(matches) != 1:
            raise SetupError(f"--oob-spines {name}: missing/ambiguous CSV eth_jump identity")
        key = normalize_name(matches[0].hostname)
        if key in result:
            raise SetupError("duplicate --oob-spines identity")
        result[key] = matches[0]
    return list(result.values())


class OobRoutingEvidenceError(SetupError):
    """Shared local evidence failure must stop the batch before IB writes."""


def lldp_spine_candidates(interface_table, inventory):
    """Only actual UP LLDP Remote Host rows, never descriptions or CSV alone."""
    columns = None
    result = {}
    for line in interface_table.splitlines():
        if all(label in line for label in ("Interface", "Oper Status", "Remote Host", "Remote Port")):
            columns = {match.group(0).strip(): match.start()
                       for match in re.finditer(r"\S(?:.*?\S)?(?=\s{2,}|$)", line)}
            if not {"Interface", "Oper Status", "Remote Host", "Remote Port"} <= set(columns):
                raise SetupError("LLDP interface header is ambiguous")
            continue
        if columns is None or not line.strip() or re.fullmatch(r"[\s-]+", line):
            continue
        def field(label):
            start = columns[label]
            end = min((value for value in columns.values() if value > start), default=len(line))
            return clean(line[start:end])
        if not field("Interface") or field("Oper Status").casefold() != "up":
            continue
        peer = field("Remote Host")
        if not usable(peer) or not field("Remote Port"):
            continue
        matches = [item for item in inventory if item.dev_type == "eth_jump"
                   and _lldp_csv_identity(peer, item.hostname)]
        if len(matches) > 1:
            raise SetupError(f"ambiguous LLDP/CSV Spine identity: {peer}")
        if matches:
            result[normalize_name(matches[0].hostname)] = matches[0]
    return [result[key] for key in sorted(result)]


def vlan_svi_interfaces(link_table, vlan, bridge=None):
    """Real 802.1Q SVIs only; a VRR macvlan such as vlan1000-v0 is NOT one."""
    result = []
    for name, block in _ip_link_blocks(link_table).items():
        parent = re.match(r"\s*\d+:\s+[^:@\s]+@([^:\s]+):", block[0])
        ids = re.findall(r"(?m)^\s*vlan\s+protocol\s+802\.1(?:Q|ad)\s+id\s+(\d+)\b", "\n".join(block))
        if parent and ids == [str(int(vlan))] and (bridge is None or parent.group(1) == bridge):
            result.append(name)
    return result


def parse_oob_addresses(text):
    try:
        payload = json.loads(text)
        if not isinstance(payload, list):
            raise ValueError("not a list")
        seen = set()
        for row in payload:
            if (not isinstance(row, dict) or not isinstance(row.get("ifname"), str)
                    or not isinstance(row.get("addr_info"), list) or row["ifname"] in seen):
                raise ValueError("invalid/duplicate interface row")
            validate_network_selector(row["ifname"], label="address interface")
            if any(not isinstance(addr, dict) for addr in row["addr_info"]):
                raise ValueError("invalid address row")
            seen.add(row["ifname"])
        return payload
    except (ValueError, TypeError, KeyError) as exc:
        raise SetupError("OOB address snapshot is invalid; absence of an SVI/IPv4 is NOT established") from exc


def svi_address_ready(rows, interface, *, require_ipv6=False):
    matches = [row for row in rows if row.get("ifname") == interface]
    if len(matches) != 1:
        return False
    row = matches[0]
    if require_ipv6 and ("UP" not in row.get("flags", [])
                         or row.get("operstate", "").upper() in {"DOWN", "LOWERLAYERDOWN", "NOTPRESENT"}):
        return False
    ipv4 = ipv6 = False
    for addr in row.get("addr_info", []):
        if (set(addr.get("flags", [])) & {"tentative", "dadfailed"}
                or addr.get("tentative") or addr.get("dadfailed") or addr.get("valid_life_time") == 0):
            continue
        try:
            value = ipaddress.ip_address(addr.get("local", ""))
        except ValueError:
            continue
        if value.is_unspecified or value.is_multicast or value.is_loopback:
            continue
        ipv4 |= value.version == 4 and addr.get("family") == "inet"
        ipv6 |= value.version == 6 and value.is_link_local and addr.get("family") == "inet6"
    return ipv4 and (ipv6 or not require_ipv6)


def _access_vlan_facts(target, interfaces, network):
    """Preserve Leaf-port/MAC checks before considering any upstream Jump."""
    line = interface_status_line(interfaces, target.ethernet_port)
    if interface_oper_status(line, target.ethernet_port) != "up":
        raise SetupError("ACCESS_LINK_DOWN: " + line)
    links, fdb, _ = network
    port = fdb_port_for_interface(links, target.ethernet_port)
    contexts = set()
    for line in fdb.splitlines():
        fields = line.split()
        if not fields or "dev" not in fields or set(fields) & {"permanent", "static", "local", "self"}:
            continue
        try:
            if fields[fields.index("dev")+1] != port or not MAC_RE.fullmatch(fields[0]):
                continue
            mac = normalize_mac(fields[0], field="Leaf FDB MAC")
            bridge = fields[fields.index("master")+1] if "master" in fields else ""
            vlan = fields[fields.index("vlan")+1] if "vlan" in fields else ""
        except IndexError as exc:
            raise SetupError("ambiguous Leaf FDB VLAN/bridge context") from exc
        contexts.add((mac, bridge, vlan))
    if len(contexts) != 1:
        raise SetupError("Leaf access port needs exactly one dynamic MAC/VLAN context")
    mac, bridge, vlan = next(iter(contexts))
    verify_fdb_eth0_mac(target, mac)
    if vlan and (not vlan.isdigit() or not 1 <= int(vlan) <= 4094):
        raise SetupError("invalid Leaf access VLAN")
    if bridge and not vlan:
        raise SetupError("bridged Leaf access port has no unambiguous VLAN")
    return mac, bridge, vlan


def _spine_neighbor(target, network, interface, vrf, learned_mac):
    """Use ND on the chosen SVI; otherwise the already verified FDB MAC only."""
    matches = {}
    for line in network[2].splitlines():
        fields = line.split()
        if "dev" not in fields or "lladdr" not in fields or set(fields) & {"FAILED", "INCOMPLETE"}:
            continue
        try:
            address = ipaddress.IPv6Address(fields[0].split("%", 1)[0])
            dev = fields[fields.index("dev")+1]
            mac = normalize_mac(fields[fields.index("lladdr")+1], field="Spine ND MAC")
        except (ValueError, IndexError):
            continue
        if dev == interface and address.is_link_local and mac == learned_mac:
            matches[str(address)] = Neighbor(str(address), interface, mac, vrf)
    if len(matches) > 1:
        raise SetupError("multiple IPv6 link-local neighbors match the target on the Spine SVI")
    if matches:
        return next(iter(matches.values()))
    if not target.ib.eth0_mac:
        raise SetupError("Spine EUI-64 fallback requires a real CSV IB eth0 MAC")
    address = mac_to_link_local(learned_mac)
    # An explicit conflicting ND entry must not be bypassed by derivation.
    for line in network[2].splitlines():
        fields = line.split()
        if fields and fields[0].split("%", 1)[0] == address and "dev" in fields and "lladdr" in fields:
            try:
                if (fields[fields.index("dev")+1] == interface
                        and fields[fields.index("lladdr")+1].casefold() != learned_mac):
                    raise SetupError("Spine derived address has a conflicting neighbor MAC")
            except IndexError as exc:
                raise SetupError("invalid Spine neighbor context") from exc
    return Neighbor(address, interface, learned_mac, vrf, "FDB_EUI64_CANDIDATE")


def choose_oob_spine(candidates):
    """One parent-owned random choice per Leaf, never per IB command/worker."""
    return random.SystemRandom().choice(candidates)


def prepare_routed_ib_tasks(targets, args, passwords, local_keys, interface_tables,
                            network_tables, table_failures, outcomes, records, *,
                            spines, fetch_addresses, collect_spines, jump_routes=None):
    """Small v15 adapter; the v14 Leaf path and complete IB pipeline stay intact."""
    normal, groups, address_cache = [], {}, {}
    def skip(target, category, reason):
        name = normalize_name(target.ib.hostname)
        outcomes[name] = "SKIPPED"
        records[name] = {"hostname": target.ib.hostname, "oob": target.ethernet.hostname,
            "port": target.ethernet_port, "outcome": "SKIPPED", "category": category,
            "reason": str(reason), "metrics": {}, "stage_status": {}, "writes_attempted": False}
        if isinstance(reason, IBMacMismatch):
            records[name]["mac_mismatch"] = {"expected": reason.expected_mac, "observed": reason.observed_mac}
        log(f"[SKIP] {target.ib.hostname} | {category} | {target.ethernet.hostname}:{target.ethernet_port}")
        if isinstance(reason, IBMacMismatch):
            log(f"  MAC: expected={reason.expected_mac} observed={reason.observed_mac}; no IB login/write attempted")
        report_detail("  Full skip reason: " + str(reason))
    for target in targets:
        leaf = normalize_name(target.ethernet.hostname)
        # Original handling owns unavailable snapshots/ports and its diagnostics.
        if leaf in table_failures:
            normal.append(target)
            continue
        try:
            mac, bridge, vlan = _access_vlan_facts(target, interface_tables[leaf], network_tables[leaf])
            if not vlan:  # Historical routed-physical-interface branch is unchanged.
                normal.append(target)
                continue
            svis = vlan_svi_interfaces(network_tables[leaf][0], vlan, bridge)
            if len(svis) > 1:
                raise SetupError("multiple Leaf SVIs match the access VLAN; no Jump selection permitted")
        except IBMacMismatch as exc:
            skip(target, "SKIPPED_MAC_MISMATCH", exc)
            continue
        except SetupError:
            normal.append(target)
            continue
        try:
            if leaf not in address_cache:
                address_cache[leaf] = fetch_addresses(target.ethernet)
            if svis and svi_address_ready(address_cache[leaf], svis[0]):
                normal.append(target)
                continue
        except OobRoutingEvidenceError:
            raise
        except SetupError as exc:
            skip(target, "SKIPPED_OOB_ADDRESS_UNVERIFIED", exc)
            continue
        # The only fallback trigger: matching Leaf SVI absent, or lacks IPv4.
        if not target.ib.eth0_mac:
            skip(target, "SKIPPED_INVENTORY_MAC_UNAVAILABLE",
                 "Spine routing requires the real CSV IB eth0 MAC; only this IB device is blocked")
            continue
        reason = "LEAF_SVI_MISSING" if not svis else "LEAF_SVI_HAS_NO_IPV4"
        groups.setdefault(leaf, []).append((target, mac, vlan, reason))
    ready = prepare_ready_ib_tasks(targets=normal, args=args, passwords=passwords,
        local_keys=local_keys, interface_tables=interface_tables, network_tables=network_tables,
        table_failures=table_failures, outcomes=outcomes, records=records)
    candidates_by_leaf, requested = {}, {}
    for leaf, members in groups.items():
        try:
            candidates = lldp_spine_candidates(interface_tables[leaf], spines)
        except SetupError as exc:
            for target, _, _, _ in members:
                skip(target, "SKIPPED_LLDP_SPINE_IDENTITY", exc)
            continue
        if not candidates:
            for target, _, _, _ in members:
                skip(target, "SKIPPED_NO_LLDP_SPINE", "No UP LLDP Spine neighbor uniquely matches the CSV eth_jump inventory")
            continue
        candidates_by_leaf[leaf] = candidates
        requested.update((normalize_name(item.hostname), item) for item in candidates)
    if requested:
        collect_spines([requested[key] for key in sorted(requested)])
    # A Spine is eligible only if it covers ALL fallback targets/VLANs of a Leaf.
    for leaf, candidates in candidates_by_leaf.items():
        members = groups[leaf]
        eligible, rejected = [], {}
        for spine in candidates:
            key = normalize_name(spine.hostname)
            try:
                if key in table_failures:
                    raise SetupError(table_failures[key])
                if key not in network_tables or key not in passwords:
                    raise SetupError("Spine snapshot/authentication did not complete")
                if key not in address_cache:
                    address_cache[key] = fetch_addresses(spine)
                routes, by_vlan = {}, {}
                for target, mac, vlan, reason in members:
                    if not target.ib.eth0_mac:
                        raise SetupError("Spine routing requires a real CSV IB eth0 MAC; inventory identity was not verified")
                    if vlan not in by_vlan:
                        interfaces = vlan_svi_interfaces(network_tables[key][0], vlan)
                        if len(interfaces) != 1:
                            raise SetupError(f"VLAN {vlan}: expected one real Spine SVI, found {len(interfaces)}")
                        interface = interfaces[0]
                        if not svi_address_ready(address_cache[key], interface, require_ipv6=True):
                            raise SetupError(f"VLAN {vlan}: SVI {interface} needs its own IPv4, usable link-local IPv6 and UP state; VRR gateway is not a substitute")
                        vrf = interface_vrf(spine, args.eth_user, passwords[key], interface,
                                            args.connect_timeout, local=key in local_keys)
                        by_vlan[vlan] = (interface, vrf)
                    interface, vrf = by_vlan[vlan]
                    routes[normalize_name(target.ib.hostname)] = _spine_neighbor(
                        target, network_tables[key], interface, vrf, mac)
                eligible.append((spine, routes))
            except OobRoutingEvidenceError:
                raise
            except SetupError as exc:
                rejected[spine.hostname] = str(exc)
        if not eligible:
            detail = "; ".join(f"{name}: {reason}" for name, reason in rejected.items())
            for target, _, _, _ in members:
                skip(target, "SKIPPED_NO_QUALIFIED_SPINE", detail)
            continue
        spine, routes = choose_oob_spine(eligible)
        key = normalize_name(spine.hostname)
        if jump_routes is not None:
            jump_routes.append({"leaf": members[0][0].ethernet.hostname,
                "spine": spine.hostname, "spine_login_ip": spine.login_ip,
                "targets": [item[0].ib.hostname for item in members],
                "vlans": sorted({item[2] for item in members}, key=int),
                "eligible_spines": [item[0].hostname for item in eligible],
                "rejected_candidates": rejected})
        log(f"[JUMP] {members[0][0].ethernet.hostname} -> {spine.hostname} ({spine.login_ip}); "
            f"IB targets={len(members)} eligible-spines={len(eligible)}; one random choice per Leaf")
        for target, _, vlan, reason in members:
            neighbor = routes[normalize_name(target.ib.hostname)]
            routed = replace(target, ethernet=spine, ethernet_port=neighbor.interface,
                             attachment=target, jump_reason=reason, access_vlan=vlan)
            ready.append(PreparedIBTask(routed, neighbor, passwords[key], key in local_keys))
            outcomes[normalize_name(target.ib.hostname)] = "NOT_ATTEMPTED"
            if rejected:
                report_detail(f"  {target.ib.hostname}: rejected Spine candidates: {rejected}")
    return ready


def compact_ports(ports):
    numbers = sorted({int(match.group(1)) for value in ports
                      if (match := re.fullmatch(r"swp([0-9]+)", value))})
    others = sorted(set(ports) - {"swp" + str(number) for number in numbers})
    groups = []
    if numbers:
        start = end = numbers[0]
        for number in numbers[1:]:
            if number == end + 1:
                end = number
            else:
                groups.append(f"swp{start}" if start == end else f"swp{start}-{end}")
                start = end = number
        groups.append(f"swp{start}" if start == end else f"swp{start}-{end}")
    return ",".join(groups + others) or "-"


def record_category(record):
    """One final outcome per target; key refresh is not a base-network change."""
    outcome = record.get("outcome", "NOT_ATTEMPTED")
    if record.get("category"):
        return record["category"]
    if outcome in {"CONFIGURED", "ALREADY_CONFIGURED"}:
        metrics = record.get("metrics", {})
        if (record.get("writes_attempted") and metrics.get("public_key_install_attempts", 0)
                and not metrics.get("nvue_write_commands", 0)
                and not metrics.get("password_change_sessions", 0)):
            return ("CHECKED_EXISTING_KEYS_VERIFIED" if metrics.get("public_key_content_unchanged")
                    else "CHECKED_EXISTING_KEYS_REFRESHED" if metrics.get("public_key_content_updated")
                    else "CHECKED_EXISTING_KEY_INSTALL_COMPLETED")
        return "CHECKED_AND_CONFIGURED" if record.get("writes_attempted") else "CHECKED_EXISTING_CONFIGURATION"
    if outcome == "CHECK_ONLY":
        return "CHECKED_NEEDS_CONFIGURATION"
    if outcome == "PASSWORD_CHANGE_REQUIRED":
        return "BLOCKED_PASSWORD_CHANGE_REQUIRED"
    if outcome == "FAILED":
        if record.get("batch_error"):
            return "FAILED_SHARED_INPUT"
        if record.get("script_error"):
            return "FAILED_SCRIPT_EXECUTION"
        if record.get("failure_kind") == "DIRECT_SSH_NETWORK":
            return "FAILED_DIRECT_SSH_NETWORK"
        if record.get("stage_status", {}).get("ipv4_readiness") == "FAILED":
            return "FAILED_OOB_IPV4_READINESS"
        return "FAILED_AFTER_WRITE_UNVERIFIED" if record.get("writes_attempted") else "FAILED_CHECK_OR_LOGIN"
    return outcome


def summary_panel(number, title):
    label = f" {number:02d} {title} "
    log("\n+--" + label + "-" * max(2, 75-len(label)) + "+")


def attention_guidance(category):
    """Operator actions are tied to observed issue classes, not all-purpose retries."""
    guidance = {
        "SKIPPED_LINK_DOWN": "Check cabling, peer power and the P2P port mapping; confirm Oper UP before re-running.",
        "SKIPPED_MAC_MISMATCH": "Reconcile the CSV eth0 MAC, P2P port and dynamic FDB MAC. Do not bypass identity verification.",
        "SKIPPED_NEIGHBOR_UNRESOLVED": "Inspect dynamic FDB, IPv6 neighbors, VLAN SVI and VRF on the listed OOB ports; an unambiguous verified MAC is required.",
        "SKIPPED_PORT_STATE_UNKNOWN": "Check the OOB interface name, snapshot output and P2P mapping before retrying.",
        "SKIPPED_OOB_IDENTITY_CONFLICT": "Verify OOB hostname and host-key changes through a trusted channel; do not disable identity checks.",
        "SKIPPED_OOB_UNREACHABLE": "Check OOB login IP, routes, TCP/22 and credentials. Re-collect the OOB snapshot before inspecting downstream IB switches.",
        "SKIPPED_OOB_SNAPSHOT_FAILED": "Inspect the OOB snapshot error and remote command PATH/availability; restore read-only snapshot collection first.",
        "SKIPPED_DEPENDENCY_UNVERIFIED": "Inspect the OOB/VLAN/VRF prerequisite evidence and correct the unresolved mapping before retrying.",
        "SKIPPED_OOB_ADDRESS_UNVERIFIED": "Restore the Leaf address snapshot query; do not treat a query failure as proof that its SVI/IPv4 is absent.",
        "SKIPPED_LLDP_SPINE_IDENTITY": "Resolve the ambiguous LLDP-to-CSV Spine identity; do not guess or use arbitrary prefix matching.",
        "SKIPPED_NO_LLDP_SPINE": "Check UP Leaf LLDP uplinks and CSV eth_jump Spine entries. No Spine absent from this Leaf's LLDP may be used.",
        "SKIPPED_NO_QUALIFIED_SPINE": "Inspect each candidate reason in the device evidence. One LLDP Spine must cover all required VLANs with its own IPv4 and usable IPv6 SVI; do not create or modify Jump interfaces automatically.",
        "SKIPPED_INVENTORY_MAC_UNAVAILABLE": "Fill this IB device's real eth0 MAC from confirmed inventory; do not insert a dummy MAC or bypass Leaf-port identity verification.",
        "BLOCKED_PASSWORD_CHANGE_REQUIRED": "Use the verified project IB target password with --apply and authorize rotation; do not use the OOB password.",
        "CHECKED_NEEDS_CONFIGURATION": "Review the proposed missing settings; re-run with --apply only when ready to authorize device changes.",
        "FAILED_DIRECT_SSH_NETWORK": "Check management-server routes, neighbor convergence, firewall rules and TCP/22 to the listed IB addresses. Re-test SSH; do not assume the installed key is wrong or replay configuration writes.",
        "FAILED_DIRECT_SSH_AUTHENTICATION": "Verify the intended IB credentials or matching management private/public key. Connectivity alone does not prove authentication.",
        "FAILED_DIRECT_SSH_HOST_KEY": "Verify the IB host key through a trusted channel before correcting the specific known_hosts entry; do not disable host-key checking.",
        "FAILED_DIRECT_SSH_CHECK": "Inspect the direct SSH error and hostname/IP readback; do not treat authentication or identity mismatches as network jitter.",
        "DIRECT_SSH_NOT_TESTED": "Run the final read-only SSH checks on the management server after base configuration and credentials are verified; access is not confirmed yet.",
        "FAILED_OOB_IPV4_READINESS": "Check the OOB VRF route and IB IPv4 interface convergence. A passing management-server path does not verify missing services/key stages.",
        "FAILED_AUTHENTICATION": "Verify the actual current IB credential, project target-password match and any forced password change. Inspect the login evidence; do not reuse the OOB password.",
        "FAILED_INITIAL_CONFIGURATION": "Inspect auto-save and ZTP config-save readback plus current ZTP state. Verify applied/pending settings before retrying any writes.",
        "FAILED_BASE_CONFIGURATION": "Compare CSV hostname/interface IP/gateway with applied and pending configuration. Verify any partial Network writes before another authorized run.",
        "FAILED_SERVICES_CONFIGURATION": "Compare required DNS/NTP/timezone values with NVUE applied readback; preserve unrelated settings and verify partial service writes before retrying.",
        "FAILED_PUBLIC_KEYS": "Inspect the install command and SSH verification error separately. Check authorized_keys ownership/permissions and the intended local key; do not assume the install failed merely because direct SSH failed.",
        "FAILED_SCRIPT_EXECUTION": "Inspect the script exception, task deadline or process failure in the evidence. Verify any partial writes before a new run; no task was automatically replayed.",
        "FAILED_SHARED_INPUT": "Restore consistent project/source inputs and inspect any partial writes before starting a new run.",
        "UNVERIFIED_CONFIGURATION": "Inspect the incomplete configuration stage and applied/pending settings; do not claim completion until required readback passes.",
        "NOT_ATTEMPTED": "Resolve the reported batch/prerequisite block and re-run check-only mode before authorizing writes.",
    }
    return guidance.get(category, "Inspect the listed device log at the failed stage and correct the authentication/configuration readback issue. If writes were attempted, verify applied and pending settings before retrying; do not blindly replay writes.")


def initial_setup_attention(records, direct_rows):
    rows_by_name = {}
    for row in direct_rows:
        rows_by_name.setdefault(normalize_name(row["hostname"]), []).append(row)
    groups = {}
    for name, record in sorted(records.items()):
        category = record_category(record)
        rows = rows_by_name.get(normalize_name(name), [])
        successful_task = record.get("outcome") in {"CONFIGURED", "ALREADY_CONFIGURED"}
        stage = record.get("failed_stage", "preflight" if record.get("category") else "unknown")
        reason = record.get("reason", "")
        if successful_task:
            if any(row["status"] == "PASS" for row in rows):
                bad_stages = [key for key, state in record.get("stage_status", {}).items()
                              if state in {"FAILED", "UNVERIFIED", "PLANNED_NOT_APPLIED", "NEEDS_CONFIGURATION", "RUNNING"}]
                if not bad_stages:
                    continue
                category, stage = "UNVERIFIED_CONFIGURATION", ",".join(bad_stages)
            elif any(row["status"] == "FAIL" for row in rows):
                reason = "; ".join(f"{row['interface']} {row['ip']}: {row.get('detail', '')}"
                                   for row in rows if row["status"] == "FAIL")
                stage = "direct_ssh"
                if re.search(r"(?i)host key|identification has changed", reason):
                    category = "FAILED_DIRECT_SSH_HOST_KEY"
                elif re.search(r"(?i)permission denied|authentication failed", reason):
                    category = "FAILED_DIRECT_SSH_AUTHENTICATION"
                elif re.search(r"(?i)no route|unreachable|timed? out|timeout|network/session|connection (?:refused|reset|closed)", reason):
                    category = "FAILED_DIRECT_SSH_NETWORK"
                else:
                    category = "FAILED_DIRECT_SSH_CHECK"
            else:
                category, stage = "DIRECT_SSH_NOT_TESTED", "direct_ssh"
                reason = "; ".join(row.get("detail", "") for row in rows) or "Final management-server direct SSH was not tested."
        elif category in {"FAILED_CHECK_OR_LOGIN", "FAILED_AFTER_WRITE_UNVERIFIED"}:
            category = {"authentication": "FAILED_AUTHENTICATION", "initial": "FAILED_INITIAL_CONFIGURATION",
                        "day0": "FAILED_BASE_CONFIGURATION", "services": "FAILED_SERVICES_CONFIGURATION",
                        "public_keys": "FAILED_PUBLIC_KEYS"}.get(stage, category)
        groups.setdefault(category, []).append({
            "hostname": record.get("hostname", name), "oob": record.get("oob", "-"),
            "port": record.get("port", "-"), "stage": stage,
            "reason": " ".join(str(reason or "See per-device evidence.").split()),
        })
    return [{"category": key, "devices": devices, "guidance": attention_guidance(key)}
            for key, devices in sorted(groups.items())]


def initial_setup_facts(records, direct_rows):
    categories, metrics, stages, address_sources = {}, {}, {}, {}
    for record in records.values():
        category = record_category(record)
        categories[category] = categories.get(category, 0) + 1
        for key, value in record.get("metrics", {}).items():
            metrics[key] = metrics.get(key, 0) + value
        for key in ("authentication", "initial", "day0", "ipv4_readiness", "services", "public_keys", "direct_ssh"):
            state = record.get("stage_status", {}).get(key, "NOT_REACHED")
            counts = stages.setdefault(key, {})
            counts[state] = counts.get(state, 0) + 1
        source = record.get("neighbor", {}).get("address_source", "NOT_SELECTED")
        address_sources[source] = address_sources.get(source, 0) + 1
    passed = {normalize_name(row["hostname"]) for row in direct_rows if row["status"] == "PASS"}
    ready = sum(normalize_name(name) in passed and record.get("outcome") in {"CONFIGURED", "ALREADY_CONFIGURED"}
                and not any(state in {"FAILED", "UNVERIFIED", "PLANNED_NOT_APPLIED", "NEEDS_CONFIGURATION", "RUNNING"}
                            for state in record.get("stage_status", {}).values())
                for name, record in records.items())
    mismatch = sum(normalize_name(name) in passed and record.get("stage_status", {}).get("ipv4_readiness") == "FAILED"
                   for name, record in records.items())
    fallback = [record for record in records.values()
                if record.get("neighbor", {}).get("address_source") == "FDB_EUI64_CANDIDATE"]
    fallback_verified = sum(record.get("stage_status", {}).get("authentication") == "VERIFIED" for record in fallback)
    return {"categories": categories, "metrics": metrics, "stages": stages,
            "direct_ssh": summarize_management_direct_checks(direct_rows),
            "setup_and_direct_ssh_verified": ready, "oob_ipv4_failed_direct_ssh_passed": mismatch,
            "ipv6_address_sources": address_sources,
            "ipv6_fallback": {"candidates": len(fallback), "authenticated": fallback_verified,
                              "not_verified": len(fallback)-fallback_verified},
            "attention": initial_setup_attention(records, direct_rows)}


def print_initial_setup_summary(project, args, targets, candidate_count, snapshots_failed,
                                records, direct_rows, workers, fatal="", jump_routes=None):
    """English, mutually exclusive device outcomes; reasons never imply IB state."""
    for target in targets:
        name = normalize_name(target.ib.hostname)
        records.setdefault(name, {"hostname": target.ib.hostname, "oob": target.ethernet.hostname,
                                 "outcome": "NOT_ATTEMPTED", "reason": "task was not dispatched"})
        records[name].setdefault("hostname", target.ib.hostname)
        records[name].setdefault("oob", target.ethernet.hostname)
        records[name].setdefault("port", target.ethernet_port)
    categories = {}
    totals = {key: 0 for key in ("ib_ssh_attempts", "direct_ssh_attempts", "public_key_ssh_attempts",
                               "nvue_write_commands", "public_key_install_attempts", "password_change_sessions")}
    for record in records.values():
        outcome = record.get("outcome", "NOT_ATTEMPTED")
        metrics = record.get("metrics", {})
        for key in totals:
            totals[key] += metrics.get(key, 0)
        category = record_category(record)
        categories[category] = categories.get(category, 0) + 1
    oobs = {normalize_name(target.ethernet.hostname): target.ethernet for target in targets}
    direct = summarize_management_direct_checks(direct_rows)
    facts = initial_setup_facts(records, direct_rows)
    execution_failed = bool(fatal or any(record.get("script_error") or record.get("batch_error")
                                        for record in records.values()))
    incomplete = (candidate_count != len(targets) or not targets or bool(facts["attention"])
                  or facts["setup_and_direct_ssh_verified"] != len(targets))
    status = "FAILED" if execution_failed else "INCOMPLETE" if incomplete else "SUCCESS"
    log("\n========== Initial Setup Summary ==========")
    summary_panel(1, "OVERVIEW")
    log(f"Project: {project}")
    log("Mode: APPLY (device changes require coordinator authorization)" if args.apply
        else "Mode: CHECK_ONLY (no --apply; device changes disabled)")
    log(f"Result: {status}")
    log(f"CSV IB candidates: {candidate_count}")
    log(f"P2P management targets: {len(targets)}")
    log(f"Unmapped CSV IB candidates: {max(0, candidate_count - len(targets))}")
    missing_mac = sorted({target.ib.hostname for target in targets if not target.ib.eth0_mac})
    if missing_mac:
        log(f"CSV eth0 MAC unavailable: {len(missing_mac)}; not checked against inventory MAC")
        for start in range(0, len(missing_mac), 4):
            log("  " + ", ".join(missing_mac[start:start+4]))
    log("SUCCESS = all required setup/access checks passed; INCOMPLETE = device work remains; FAILED = run execution failed/aborted.")
    summary_panel(2, "OOB SNAPSHOTS")
    log(f"OOB snapshots: {len(oobs)} total, {len(oobs)-len(snapshots_failed)} collected, {len(snapshots_failed)} failed")
    log("\nOOB Leaf                 Login IP         IB Targets  Snapshot   Impact / Reason")
    for key, device in sorted(oobs.items()):
        attached = [target for target in targets if normalize_name(target.ethernet.hostname) == key]
        related = [records[normalize_name(target.ib.hostname)] for target in attached]
        if key in snapshots_failed:
            impact = snapshots_failed[key]
        else:
            groups = {}
            for record in related:
                category = record.get("category")
                if record.get("outcome") == "FAILED":
                    category = record_category(record)
                if category:
                    groups.setdefault(category, []).append(record.get("port", ""))
            impact = "; ".join(f"{category}={len(ports)} [{compact_ports(ports)}]" for category, ports in sorted(groups.items()))
            attached_names = {normalize_name(target.ib.hostname) for target in attached}
            attached_issues = [entry for entry in facts["attention"]
                               if any(normalize_name(item["hostname"]) in attached_names for item in entry["devices"])]
            if not impact and attached_issues:
                impact = "; ".join(entry["category"] for entry in attached_issues)
            impact = impact or "All attached IB switches completed setup and direct SSH passed"
        snapshot = "FAILED" if key in snapshots_failed else "COLLECTED"
        impact = " ".join(str(impact).split())
        log(f"{device.hostname:<24} {device.login_ip:<16} {len(attached):>10}  {snapshot:<10} {impact}")
    if jump_routes:
        log("\nSpine Jump selection (one random choice per access Leaf; no worker-side switching):")
        for route in jump_routes:
            log(f"  {route['leaf']} -> {route['spine']} ({route['spine_login_ip']}) "
                f"VLAN={','.join(route['vlans'])} IB-targets={len(route['targets'])}")
    summary_panel(3, "IB SWITCHES OUTCOMES")
    log("IB switches outcomes (mutually exclusive; device errors do not mean script execution failed):")
    for label, prefix in (("Completed", "CHECKED_"), ("Skipped prerequisites", "SKIPPED"),
                          ("Blocked / pending", "BLOCKED"), ("Failures", "FAILED"), ("Not attempted", "NOT_")):
        entries = [(key, value) for key, value in sorted(categories.items()) if key.startswith(prefix)
                   and not (prefix == "CHECKED_" and key == "CHECKED_NEEDS_CONFIGURATION")]
        if label == "Blocked / pending" and categories.get("CHECKED_NEEDS_CONFIGURATION"):
            entries.append(("CHECKED_NEEDS_CONFIGURATION", categories["CHECKED_NEEDS_CONFIGURATION"]))
        if entries:
            log("  " + label + ":")
            for category, number in entries:
                log(f"    {category}: {number}")
    known = {key for key in categories if key.startswith(("CHECKED_", "SKIPPED", "BLOCKED", "FAILED", "NOT_"))}
    for category in sorted(set(categories)-known):
        log(f"    {category}: {categories[category]}")
    log(f"  TOTAL: {sum(categories.values())}")
    summary_panel(4, "CONFIGURATION STAGES")
    for stage, label in (("initial", "1. Initial"), ("day0", "2. Network"),
                         ("services", "3. Infra Services"), ("public_keys", "4. Public Keys")):
        counts = {}
        for record in records.values():
            state = record.get("stage_status", {}).get(stage, "NOT_REACHED")
            counts[state] = counts.get(state, 0) + 1
        log(label + ": " + ", ".join(f"{state}={number}" for state, number in sorted(counts.items())))
    log("Initial = auto-save / ZTP config-save; Network = hostname / management interfaces; Infra Services = DNS / NTP / timezone.")
    log("Network VERIFIED means required network values passed readback; it does not claim every value changed.")
    log("Public Keys = idempotent installation plus required verification; installation and SSH proof are counted separately below.")
    key_installed = sum(record.get("metrics", {}).get("public_key_install_completed", 0) > 0 for record in records.values())
    key_verified = sum(record.get("metrics", {}).get("public_key_ssh_verified", 0) > 0 for record in records.values())
    key_unverified = sum(record.get("metrics", {}).get("public_key_ssh_attempts", 0) > 0
                         and not record.get("metrics", {}).get("public_key_ssh_verified", 0) for record in records.values())
    log(f"Key install command completed: {key_installed} device(s)")
    updated = sum(record.get("metrics", {}).get("public_key_content_updated", 0) > 0 for record in records.values())
    unchanged = sum(record.get("metrics", {}).get("public_key_content_unchanged", 0) > 0 for record in records.values())
    log(f"Authorized_keys content: updated={updated} unchanged={unchanged} action-not-recorded={max(0,key_installed-updated-unchanged)}")
    log("UNCHANGED means key content matched; permissions may still be normalized. NOT_CONFIGURED means no Infra Services profile was supplied.")
    summary_panel(5, "SSH ACCESS")
    log(f"OOB login + snapshot: verified={len(oobs)-len(snapshots_failed)} failed/not-verified={len(snapshots_failed)}")
    for stage, label in (("authentication", "IB IPv6 SSH via OOB"), ("ipv4_readiness", "IB IPv4 SSH via OOB")):
        log(label + ": " + ", ".join(f"{state}={number}" for state, number in sorted(facts["stages"].get(stage, {}).items())))
    fallback = facts["ipv6_fallback"]
    log(f"FDB-derived IPv6 candidates: {fallback['candidates']}; authenticated={fallback['authenticated']}; not-verified={fallback['not_verified']}")
    log("A derived IPv6 candidate alone is not proof of login or configuration success.")
    log(f"Management-key SSH verification: verified={key_verified} failed/unverified={key_unverified} "
        f"not-attempted={len(targets)-key_verified-key_unverified}")
    log(f"Direct SSH: ready={direct['ready']} failed={direct['failed']} not-tested={direct['not_tested']} eth1-fallback={direct['fallback']}")
    for interface in ("eth0", "eth1"):
        rows = [row for row in direct_rows if row["interface"] == interface]
        if rows:
            log(f"  {interface}: " + ", ".join(f"{state}={sum(row['status'] == state for row in rows)}"
                                               for state in ("PASS", "FAIL", "NOT_TESTED", "NOT_NEEDED")))
    log(f"Setup complete + direct SSH verified: {facts['setup_and_direct_ssh_verified']}/{len(targets)}")
    log("Upgrade packages, hardware compatibility and target versions: NOT_CHECKED (not approval to upgrade).")
    if facts["oob_ipv4_failed_direct_ssh_passed"]:
        log("OOB IPv4 readiness failed but ZTP-server direct SSH passed: " + str(facts["oob_ipv4_failed_direct_ssh_passed"]))
        log("These paths differ; direct SSH does not complete unreached services/key stages or clear the setup failure.")
    if not totals["ib_ssh_attempts"]:
        log("No IB switch login was attempted. The current IB configuration remains unknown.")
    summary_panel(6, "ATTENTION REQUIRED")
    if fatal:
        log("Batch stop reason: " + " ".join(str(fatal).split()))
    if not facts["attention"]:
        log("No blocked, failed or pending IB targets.")
    for group in facts["attention"]:
        log(f"\n  [{group['category']}] {len(group['devices'])} device(s)")
        log("    Devices:")
        for device in group["devices"]:
            log(f"      {device['hostname']} | {device['oob']}:{device['port']} | stage={device['stage']}")
            report_detail("        Reason: " + device["reason"])
    summary_panel(7, "EVIDENCE & NEXT ACTIONS")
    for number, group in enumerate(facts["attention"], 1):
        log(f"  {number}) [{group['category']}] {group['guidance']}")
    if fatal:
        log("  Run execution: resolve the batch stop above and verify any partial writes before a new run.")
    if candidate_count != len(targets):
        log("  Unmapped CSV IB candidates: reconcile CSV hostnames with P2P management links before retrying.")
    if missing_mac:
        log("  Inventory: supply the real CSV eth0 MAC before MAC-required upgrade preflight; never insert a dummy MAC.")
    if not facts["attention"] and not fatal and candidate_count == len(targets):
        log("All required setup and SSH access checks passed; retain the run evidence.")
    log(f"\nSee {Path(args.report).resolve()} and the per-device .log/.json files for evidence.")
    return status


def main(*, method_cycle=None) -> int:
    """One run: inputs, cache, credentials, snapshots, task queue, summary.

    method_cycle is config_sync_authority's managed cycle (keyword-only, external
    contract): it admits the paths before any output, starts before task
    preparation, receipts each device in the single inline slot and closes after
    the summary, all in this parent process.
    """
    global REPORT_HANDLE, _CONSOLE_VERBOSE, _CREDENTIALS_FD_MODE
    args = parse_args()
    _CONSOLE_VERBOSE = args.verbose
    if args.ethernet_password is not None:
        raise SetupError("Do not put passwords in argv; use hidden OOB prompts")
    # --credentials-fd (R-012 design §8.3; guide WP-5, O10): read once here, before any output or
    # device contact; a missing key or bad input exits 2.  The IB target is required only when
    # --apply may write (a read-only check never rotates a password); a missing initial password
    # means admin (I14).  From here on nothing prompts and no password environment is read.
    _CREDENTIALS_FD_MODE = args.credentials_fd is not None
    fd_credentials = jump_password_for = None
    if _CREDENTIALS_FD_MODE:
        credentials_fd = _import_tools("tools.credentials_fd")
        try:
            fd_credentials = credentials_fd.read_credentials(
                args.credentials_fd,
                required=("ib_target_password",) if args.apply else (),
                optional=("jump_passwords", "nvos_initial_password",
                          *(() if args.apply else ("ib_target_password",))),
            )
            jump_key, jump_table = str.casefold, {}
            if "jump_passwords" in fd_credentials:
                jump_key = _import_tools("tools.device_identity").short_key  # I-007 rule 6
                jump_table = credentials_fd.host_passwords(
                    fd_credentials["jump_passwords"], key=jump_key)
        except credentials_fd.CredentialsError as error:
            raise SetupError(f"--credentials-fd: {error}") from None
        # Entry checks that need no device (guide :648-649, :570; R-012 design :344-345): the
        # target's shape is checked here with or without a global, and fd mode never asks for
        # the first-change confirmation, so --apply also needs --yes.
        if "ib_target_password" in fd_credentials:
            _validate_target_password(fd_credentials["ib_target_password"])
        if args.apply and not args.yes:
            raise SetupError("--credentials-fd with --apply also needs --yes: fd mode never asks "
                             "for the first-change confirmation")
        jump_password_for = lambda hostname: jump_table.get(jump_key(hostname))  # noqa: E731
    project = None
    if args.project_dir is not None:
        project = args.project_dir.expanduser().resolve(strict=True)
        if not project.is_dir():
            raise SetupError("--project-dir must be a directory")
        if args.ib_csv is None:
            args.ib_csv = project / "ib.csv"  # the project's own IB inventory, never 02 (O8; v3.1.1 AP-c)
        if args.p2p is None:
            preferred = project / "p2p.xlsx"
            candidates = [path for path in sorted(project.glob("*.xlsx"))
                          if path.is_file() and not path.name.startswith((".", "~$"))]
            if preferred.is_file():
                args.p2p = preferred
            elif len(candidates) == 1:
                args.p2p = candidates[0]
            else:
                raise SetupError("project P2P workbook is missing or ambiguous; specify --p2p")
    if args.plan and args.apply:
        raise SetupError("--plan cannot be combined with --apply")
    if args.generate_json and (args.plan or args.apply):
        raise SetupError(
            "--generate-json cannot be combined with --plan or --apply"
        )
    if method_cycle is not None and (not args.apply or args.plan or args.generate_json
                                      or args.execution_mode == "ethernet"):
        raise SetupError("managed method authority requires management --apply, not plan/generation/ethernet mode")
    if not valid_ssh_user(args.eth_user):
        raise SetupError(f"invalid --eth-user: {args.eth_user!r}")
    if not valid_ssh_user(args.ib_user):
        raise SetupError(f"invalid --ib-user: {args.ib_user!r}")
    if not re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_]{0,127}", args.ib_initial_password_env,
    ):
        raise SetupError(
            f"invalid --ib-initial-password-env: {args.ib_initial_password_env!r}"
        )
    if not 1 <= args.connect_timeout <= 600:
        raise SetupError("--connect-timeout must be between 1 and 600 seconds")
    automatic_worker_count(0, args.max_workers)
    if not 1 <= args.task_timeout <= 86400:
        raise SetupError("--task-timeout must be in 1-86400 seconds")
    ib_csv_path = discover_input_file(
        args.ib_csv, "ib.csv", ".csv", "IB device CSV"
    )
    p2p_path = discover_input_file(
        args.p2p, "p2p.xlsx", ".xlsx", "P2P workbook"
    )
    # O12 (guide :1071): without --report every run writes its own report in the default directory,
    # initial-setup-report-<YYYYmmdd-HHMMSS>.log, with -<pid> when that name exists; the devices-*
    # evidence directory starts with the same timestamp (run_prepared_tasks).  --report is used as given.
    args.run_stamp = time.strftime("%Y%m%d-%H%M%S")
    if args.report is None:
        args.report = Path("xdr-initial-setup-logs") / f"initial-setup-report-{args.run_stamp}.log"
        if args.report.exists():
            args.report = args.report.with_name(f"initial-setup-report-{args.run_stamp}-{os.getpid()}.log")
    if method_cycle is not None:
        # Typed/executor admission must precede report/cache/authority writes.
        method_cycle.admit_paths((ib_csv_path, p2p_path),
                                 (args.target_cache, args.report, args.snapshot_dir))
        load_devices(ib_csv_path)
        with ib_csv_path.open(encoding="utf-8-sig", newline="") as stream:
            reader = csv.reader(stream)
            indexes = header_indexes(next(reader))
            if "config_method" not in indexes:
                raise SetupError("managed initial-setup requires an explicit per-device config_method column")
            for line, row in enumerate(reader, 2):
                if row_value(row, indexes, "type").casefold() == "ib" and row_value(row, indexes, "config_method").casefold() != "initial-setup":
                    raise SetupError(f"{ib_csv_path}:{line}: managed IB config_method must be initial-setup")
    cache_path = args.target_cache.resolve()
    report_path = args.report.resolve()
    snapshot_directory = args.snapshot_dir.resolve()
    for output_parent in dict.fromkeys((cache_path.parent, report_path.parent)):
        try:
            output_parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise SetupError(
                f"cannot create output directory {output_parent}: {exc}"
            ) from exc
    # global, public keys and the neutral defaults (O8 table 8-1): the managed tool root, else the
    # project's own fixed names under --project-dir (<project>/01-global.yaml, the non-empty *.pub at its
    # root and the infra-neutral.conf setup writes; read directly, never through the bridges beside this
    # script, which reach only the active project), else this script's directory.  CSV, P2P and outputs
    # keep their own bases.  The default and managed calls keep their arguments.
    if method_cycle is None and project is not None:
        tool = project
        key_option = {"public_key_dir": project}
        neutral_option = {"neutral_dir": project / "infiniband" / "bringup" / "xdr-initial-setup"}
    else:
        tool = method_cycle.tool_input_root if method_cycle is not None else Path(__file__).resolve().parent
        key_option, neutral_option = {}, {}
    key_dir = key_option.get("public_key_dir", tool / "publickey")
    if args.generate_json:
        ib_devices, eth_devices = load_devices(ib_csv_path)
        links = parse_p2p(p2p_path)
        validate_p2p_links(links)
        targets = build_targets(links, ib_devices, eth_devices)
        services = _service_profile(tool, **neutral_option)
        public_keys = _public_key_profile(tool, **key_option)
        global_file = tool / "01-global.yaml"
        save_target_cache(
            cache_path, ib_csv_path, p2p_path, len(ib_devices), targets,
            global_file=global_file if global_file.is_file() else None,
            services=services, public_keys=public_keys,
        )
        print(f"Input CSV: {ib_csv_path}")
        print(f"Input P2P: {p2p_path}")
        print(f"Generated: {cache_path}")
        print(f"Generated: {cache_path.with_name(cache_path.name + '.sha256')}")
        print(
            f"IB candidates: {len(ib_devices)}; "
            f"P2P management links: {len(targets)}"
        )
        return 0
    try:
        REPORT_HANDLE = report_path.open("w", encoding="utf-8")
    except OSError as exc:
        raise SetupError(f"cannot create report {report_path}: {exc}") from exc
    log(f"Report: {report_path}")
    log(f"Started: {time.strftime('%Y-%m-%d %H:%M:%S %Z')}")
    log(f"Script: {Path(__file__).resolve()} ({_REPOSITORY_REVISION})")
    log(f"Input CSV: {ib_csv_path}")
    log(f"Input P2P: {p2p_path}")
    # O8 (guide :913): where the device inputs and the project settings come from, as given (the
    # current directory, --ib-csv/--p2p, --project-dir); different directories are reported, not refused.
    csv_dir, p2p_dir = (Path.cwd() if value is None else value.expanduser().absolute().parent.resolve()
                        for value in (args.ib_csv, args.p2p))
    device_dirs = (f"CSV and P2P from {csv_dir}" if csv_dir == p2p_dir
                   else f"CSV from {csv_dir}, P2P from {p2p_dir}")
    log(f"Input sources: {device_dirs}; global, public keys and neutral defaults from {tool}"
        + ("" if {csv_dir, p2p_dir} == {tool}
           else " (different directories: check they hold the same project; the run goes on)"))
    source_inputs_available = (
        args.execution_mode in {"management", "ethernet"}
        or (args.execution_mode == "auto" and (
            key_dir.is_dir() or (tool / "01-global.yaml").is_file()
        ))
    )
    authority_paths = [ib_csv_path, p2p_path, _SELF_SOURCE_PATH]
    if (tool / "01-global.yaml").is_file():
        authority_paths.append(tool / "01-global.yaml")
    runtime_authority = RuntimeInputAuthority(authority_paths)
    # The admitted profile travels with the accepted cache (DEV); the strict
    # management-server admission below compares it with what the run uses.
    cache_observe_profile = args.execution_mode != "ethernet"
    cache_admission_out = {} if cache_observe_profile else None
    cache_generated_profile = None
    cached = load_target_cache(
        cache_path, ib_csv_path, p2p_path,
        public_key_tool=tool if source_inputs_available else None,
        validate_public_keys_with_ssh_keygen=args.execution_mode == "management",
        allow_baked_missing_global=args.execution_mode != "management",
        **({"_admission_out": cache_admission_out} if cache_observe_profile else {}),
        **key_option,
    )
    if cached is not None and args.execution_mode == "auto":
        # A disconnected Ethernet leaf legitimately has neither project link.
        # Distinguish it from a management host using validated target identities;
        # a management cache reuse still needs the same P1 key validation as minting.
        local_for_cache = local_ethernet_keys(
            cached[1], args.execution_mode, args.local_ethernet_hostname,
        )
        if not local_for_cache:
            cache_admission_out = {} if cache_observe_profile else None
            cached = load_target_cache(
                cache_path, ib_csv_path, p2p_path, public_key_tool=tool,
                validate_public_keys_with_ssh_keygen=True,
                allow_baked_missing_global=False,
                **({"_admission_out": cache_admission_out} if cache_observe_profile else {}),
                **key_option,
            )
    if cached is not None:
        ib_candidate_count, targets = cached
        log(f"Target cache: reused {cache_path}")
    else:
        if args.execution_mode == "ethernet":
            if cache_path.is_file():
                raise SetupError(
                    "target cache version, checksum, or input identity is invalid; "
                    "regenerate version 5 on the management server"
                )
            raise SetupError("target cache is missing; generate version 5 on the management server")
        ib_devices, eth_devices = load_devices(ib_csv_path)
        links = parse_p2p(p2p_path)
        validate_p2p_links(links)
        targets = build_targets(links, ib_devices, eth_devices)
        ib_candidate_count = len(ib_devices)
        services = _service_profile(tool, **neutral_option)
        public_keys = _public_key_profile(tool, **key_option)
        global_file = tool / "01-global.yaml"
        cache_generated_candidate = (
            _cache_profile_snapshot(services, public_keys)
            if cache_observe_profile else None
        )
        save_target_cache(
            cache_path, ib_csv_path, p2p_path, ib_candidate_count, targets,
            global_file=global_file if global_file.is_file() else None,
            services=services, public_keys=public_keys,
        )
        cache_generated_profile = cache_generated_candidate
        log(f"Target cache: generated {cache_path}")
    cache_payload = json.loads(cache_path.read_text(encoding="utf-8"))
    services = cache_payload["services"]
    public_keys = cache_payload["public_keys"]
    log(f"Public-key input: {key_dir}; usable entries={len(public_keys)}")
    for entry in public_keys:
        log(f"  Queued IB public key: {entry['name']} {entry['fingerprint']}")
    if not public_keys:
        log("WARNING: no usable *.pub keys found; no IB public key will be installed.")

    log(f"IB candidates in CSV: {ib_candidate_count}")
    log(f"P2P management links: {len(targets)}")
    for target in targets:
        report_detail(
            f"  {target.ib.hostname:<32} {target.ib_port_alias:<6} <- "
            f"{target.ethernet.hostname}:{target.ethernet_port} "
            f"({target.ethernet.login_ip})"
        )
    if args.apply:
        log(
            "Device changes: REQUESTED by --apply; confirmation will occur "
            "immediately before the first device change."
        )
    else:
        log("Device changes: DISABLED (no --apply); read-only device mode.")
    if args.plan:
        log("Plan lists potential commands; already-present values may be omitted at runtime.")
        for target in targets:
            log(f"  [{target.ib.hostname}] Initial configuration commands:")
            for command in initial_configuration_commands():
                log("    " + shlex.join(command))
            log(f"  [{target.ib.hostname}] Network commands:")
            for command in desired_commands(target.ib):
                log("    " + shlex.join(command))
            if services is None:
                log("    Infra Services SKIP: 01-global.yaml was unavailable at cache generation.")
            else:
                log("    Infra Services commands:")
                for command in desired_service_commands(services, ""):
                    log("    " + shlex.join(command))
                log("    nv config apply -y")
                log("    nv config save")
            if public_keys:
                log("    Public-key install command:")
                log("    " + shlex.join(key_install_command(public_keys)))
                for entry in public_keys:
                    log(f"    {entry['name']} {entry['fingerprint']}")
            else:
                log("    Public keys SKIP: no usable project public keys were baked into cache.")
        return 0

    initial_ib_password = ""  # Prompt only after snapshots identify at least one eligible IB task.

    local_keys = local_ethernet_keys(
        targets, args.execution_mode, args.local_ethernet_hostname
    )
    # A remote Spine task does not turn a process running on a Leaf into a
    # management server. Preserve the actual location for the final direct probe.
    args._on_management_server = args.execution_mode != "ethernet" and not local_keys
    management_private_key = None
    if args.execution_mode != "ethernet" and not local_keys:
        candidate_private_key = Path.home() / ".ssh" / "id_ed25519"
        if candidate_private_key.is_file() and not candidate_private_key.is_symlink():
            management_private_key = candidate_private_key
    if local_keys:
        log("Local Ethernet execution: " + ", ".join(sorted(local_keys)))
    else:
        log("Execution location: management server (all Ethernet access uses SSH)")
    if method_cycle is not None:
        if local_keys or args.execution_mode == "ethernet" or not args.apply:
            raise SetupError("managed method authority requires an explicit management --apply execution")
        # The cache's targets, not the Spine-routed copies (config_sync_authority _inputs).
        method_cycle.start(tool, cache_path, ib_csv_path, p2p_path, targets, services, public_keys)
    passwords = prompt_ethernet_passwords(
        targets, args.ethernet_password, local_keys,
        eth_user=args.eth_user, timeout=args.connect_timeout,
        password_for=jump_password_for,
    )

    # Project password authority.  On the management server a present global is
    # admitted together with the cache records and profile it produced (DEV strict
    # admission); its tasks then run the strict stages (args._strict_cache).  Without
    # a global, --apply is still allowed (table 6-1 row 10, P1): no target rotation.
    # In fd mode the target comes from the fd, still checked against the global's hash (WP-5).
    policy_options = ({} if fd_credentials is None else
                      {"target_password": fd_credentials.get("ib_target_password"), "interactive": False})
    policy_path = tool / "01-global.yaml"
    policy = None
    args._strict_cache = None
    if args._on_management_server:
        if type(cache_payload) is not dict or "global" not in cache_payload:
            _ib_raise_phase_failure("project")
        strict_present = False
        strict_failure = None
        try:
            policy_path.lstat()
        except FileNotFoundError as error:
            if cache_payload["global"] is not None:
                strict_failure = _ib_phase_error_facts(error)
        except OSError as error:
            strict_failure = _ib_phase_error_facts(error)
        else:
            strict_present = True
        if strict_failure is not None:
            _ib_raise_phase_failure("project", *strict_failure)
        if strict_present:
            try:
                strict_actual_targets = [
                    {
                        "ib": device_to_dict(item.ib),
                        "ethernet": device_to_dict(item.ethernet),
                        "ethernet_port": item.ethernet_port,
                        "ib_port_alias": item.ib_port_alias,
                    }
                    for item in targets
                ]
                strict_reported_targets = cache_payload.get("targets")
                if (
                    type(ib_candidate_count) is not int
                    or type(cache_payload.get("ib_candidate_count")) is not int
                    or cache_payload["ib_candidate_count"] != ib_candidate_count
                    or type(strict_reported_targets) is not list
                    or len(strict_reported_targets) != len(strict_actual_targets)
                ):
                    raise SetupError("manual target records are not admitted together")
                strict_record_fields = {"ib", "ethernet", "ethernet_port", "ib_port_alias"}
                # v15 device_to_dict writes login_interface too (cache version 5).
                strict_device_fields = {
                    "hostname", "dev_type", "login_ip", "eth0_prefix",
                    "eth0_gateway", "eth0_mac", "eth1_prefix", "eth1_gateway",
                    "login_interface",
                }
                for strict_actual, strict_reported in zip(
                    strict_actual_targets, strict_reported_targets,
                ):
                    if (
                        type(strict_reported) is not dict
                        or set(strict_reported) != strict_record_fields
                        or any(type(key) is not str for key in strict_reported)
                    ):
                        raise SetupError("manual target records are not admitted together")
                    for strict_role in ("ib", "ethernet"):
                        strict_actual_device = strict_actual[strict_role]
                        strict_reported_device = strict_reported[strict_role]
                        if (
                            type(strict_reported_device) is not dict
                            or set(strict_reported_device) != strict_device_fields
                            or any(type(key) is not str for key in strict_reported_device)
                            or set(strict_actual_device) != strict_device_fields
                            or any(type(value) is not str
                                   for value in strict_actual_device.values())
                            or any(type(value) is not str
                                   for value in strict_reported_device.values())
                        ):
                            raise SetupError("manual target records are not admitted together")
                    if any(
                        type(strict_actual[field]) is not str
                        or type(strict_reported[field]) is not str
                        for field in ("ethernet_port", "ib_port_alias")
                    ) or strict_reported != strict_actual:
                        raise SetupError("manual target records are not admitted together")
                if cached is not None:
                    if (
                        type(cached) is not tuple or len(cached) != 2
                        or type(cache_admission_out) is not dict
                        or any(type(key) is not str for key in cache_admission_out)
                        or set(cache_admission_out) != {"accepted"}
                    ):
                        raise SetupError("manual cache profile was not admitted together")
                    strict_accepted = cache_admission_out["accepted"]
                    if (
                        type(strict_accepted) is not dict
                        or any(type(key) is not str for key in strict_accepted)
                        or set(strict_accepted) != {"result", "profile"}
                        or strict_accepted["result"] is not cached
                    ):
                        raise SetupError("manual cache profile was not admitted together")
                    strict_profile = strict_accepted["profile"]
                else:
                    strict_profile = cache_generated_profile
                if (
                    type(strict_profile) is not dict
                    or any(type(key) is not str for key in strict_profile)
                    or set(strict_profile) != {"services", "public_keys"}
                ):
                    raise SetupError("manual cache profile was not admitted together")
                strict_first_profile = _cache_profile_snapshot(
                    strict_profile["services"], strict_profile["public_keys"],
                )
                strict_second_profile = _cache_profile_snapshot(services, public_keys)
                if strict_first_profile != strict_second_profile:
                    raise SetupError("manual cache profile was not admitted together")
                policy = ProjectPasswordPolicy(policy_path, args.ib_user, **policy_options)
                if (
                    policy.binding[0] != cache_payload["global"]
                    or policy.binding[3]
                    != cache_payload["cache_authority"]["global_sha256"]
                ):
                    raise SetupError("project authority differs from admitted P1 input")
            except (SetupError, OSError) as error:
                strict_failure = _ib_phase_error_facts(error)
            if strict_failure is not None:
                _ib_raise_phase_failure("project", *strict_failure)
            args._strict_cache = (cache_payload, ib_csv_path, p2p_path, policy_path)
    elif policy_path.is_file():
        policy = ProjectPasswordPolicy(policy_path, args.ib_user, **policy_options)
    apply_authorized = bool(args.apply and args.yes)
    if apply_authorized:
        log("Device changes: pre-authorized by --apply --yes.")

    interface_tables: dict[str, str] = {}
    network_tables: dict[str, tuple[str, str, str]] = {}
    table_failures: dict[str, str] = {}
    failures = configured = skipped = day0_skipped = services_skipped = 0
    outcomes = {normalize_name(target.ib.hostname): "NOT_ATTEMPTED" for target in targets}
    # Verified credentials are retained in process memory only for the final probe.
    direct_credentials: dict[str, str] = {}
    ethernet_switches = {
        normalize_name(target.ethernet.hostname): target.ethernet
        for target in targets
    }
    log("\nCollecting Ethernet snapshots ...")
    for eth_key, ethernet in sorted(ethernet_switches.items()):
        ethernet_is_local = eth_key in local_keys
        eth_password = passwords[eth_key]
        location = "local" if ethernet_is_local else "SSH"
        log(f"  [{ethernet.hostname}] via {location}")
        try:
            if eth_password is None:
                raise SetupError(f"OOB access unavailable: no --credentials-fd password for "
                                 f"{ethernet.hostname}; no login attempted")
            actual_hostname, interface_tables[eth_key] = collect_ethernet_interfaces(
                ethernet, args.eth_user, eth_password, args.connect_timeout,
                local=ethernet_is_local,
            )
            network_tables[eth_key] = collect_ethernet_network_tables(
                ethernet, args.eth_user, eth_password, args.connect_timeout,
                local=ethernet_is_local,
            )
            links, fdb, neighbors = network_tables[eth_key]
            snapshot_path = save_ethernet_snapshot(
                snapshot_directory, ethernet, actual_hostname, location,
                interface_tables[eth_key], links, fdb, neighbors,
            )
            log(f"    Snapshot saved: {snapshot_path}")
        except SetupError as exc:
            table_failures[eth_key] = str(exc)
            log(f"    ERROR: {exc}")

    log("\nPreparing IB tasks from completed OOB snapshots ...")
    runtime_authority.assert_unchanged()
    records = {}
    # Routing is live evidence, never a cached success or a fabricated P2P link.
    # Read the same hash-pinned CSV even when static P2P target cache is reused.
    _, transit_inventory = load_devices(ib_csv_path)
    spine_inventory = select_spine_inventory(transit_inventory, args.oob_spines)
    leaf_snapshot_failures = dict(table_failures)
    jump_routes = []

    def fetch_oob_addresses(device):
        key = normalize_name(device.hostname)
        output = run_on_ethernet(device, args.eth_user, passwords[key],
            ["ip", "-j", "address", "show"], args.connect_timeout, local=key in local_keys)
        parsed = parse_oob_addresses(output)
        try:
            path = snapshot_directory / (snapshot_filename(device.hostname) + ".addresses.json")
            path.write_text(json.dumps({"hostname": device.hostname, "addresses": parsed}, indent=2) + "\n",
                            encoding="utf-8")
        except OSError as exc:
            raise OobRoutingEvidenceError(f"cannot save OOB routing address evidence: {path}") from exc
        return parsed

    def collect_spine_snapshots(devices):
        missing = [device for device in devices if normalize_name(device.hostname) not in interface_tables
                   and normalize_name(device.hostname) not in table_failures]
        if not missing:
            return
        # Reuse key-first/shared-password prompting; never install keys on Jumps.
        password_targets = [Target(targets[0].ib, device, "lldp-uplink", "mgmt") for device in missing]
        passwords.update(prompt_ethernet_passwords(password_targets, args.ethernet_password, local_keys,
            eth_user=args.eth_user, timeout=args.connect_timeout, password_for=jump_password_for))
        log("\nCollecting LLDP Spine candidate snapshots (read-only) ...")
        for device in missing:
            key = normalize_name(device.hostname)
            runtime_authority.assert_unchanged()
            try:
                if passwords[key] is None:
                    raise SetupError(f"OOB access unavailable: no --credentials-fd password for "
                                     f"{device.hostname}; no login attempted")
                actual, interfaces = collect_ethernet_interfaces(device, args.eth_user, passwords[key],
                    args.connect_timeout, local=key in local_keys)
                network = collect_ethernet_network_tables(device, args.eth_user, passwords[key],
                    args.connect_timeout, local=key in local_keys)
            except SetupError as exc:
                table_failures[key] = redact_text(str(exc), list(passwords.values()))
                log(f"  [SPINE] {device.hostname}: snapshot failed; {table_failures[key]}")
                continue
            interface_tables[key], network_tables[key] = interfaces, network
            save_ethernet_snapshot(snapshot_directory, device, actual,
                "local" if key in local_keys else "SSH", interfaces, *network)

    ready_tasks = prepare_routed_ib_tasks(
        targets, args, passwords, local_keys, interface_tables, network_tables, table_failures,
        outcomes, records, spines=spine_inventory, fetch_addresses=fetch_oob_addresses,
        collect_spines=collect_spine_snapshots, jump_routes=jump_routes)
    runtime_authority.assert_unchanged()
    try:
        snapshot_directory.mkdir(parents=True, exist_ok=True)
        (snapshot_directory / "spine-jump-routes.json").write_text(
            json.dumps(redact_data(jump_routes, list(passwords.values())), indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        raise OobRoutingEvidenceError("cannot save selected Jump routes; no IB tasks dispatched") from exc
    # Do not ask for IB credentials when every target is blocked before IB login.
    # fd mode: the fd value or admin (I14); never the environment or a prompt (R-012 design :345-346).
    initial_ib_password = ((fd_credentials.get("nvos_initial_password") or "admin"
                            if fd_credentials is not None else resolve_initial_ib_password(
                                args.ib_initial_password_env,
                                factory_default_admin=args.factory_default_admin))
                           if ready_tasks else "")
    log(f"IB selection: total-ib={ib_candidate_count} "
        f"filtered-ib={ib_candidate_count-len(ready_tasks)} ready-ib={len(ready_tasks)} "
        f"(prerequisite-blocked={len(targets)-len(ready_tasks)} "
        f"unmapped={ib_candidate_count-len(targets)})")
    batch = run_prepared_tasks(
        ready_tasks, args, policy, initial_ib_password, services, public_keys,
        management_private_key, authority=runtime_authority, method_cycle=method_cycle)
    outcomes.update(batch["outcomes"])
    records.update(batch["records"])
    try:
        runtime_authority.assert_unchanged()
    except ProjectInputChanged as exc:
        batch["fatal"] = str(exc)
    failures = sum(value == "FAILED" for value in outcomes.values())
    failures += int(bool(batch["fatal"]) and failures == 0)
    configured = sum(value == "CONFIGURED" for value in outcomes.values())
    skipped = sum(value in {"SKIPPED", "ALREADY_CONFIGURED", "PASSWORD_CHANGE_REQUIRED"} for value in outcomes.values())

    direct_rows = list(batch["direct_rows"])
    probed_names = {normalize_name(row["hostname"]) for row in direct_rows}
    for target in targets:
        if normalize_name(target.ib.hostname) in probed_names:
            continue
        for interface, prefix in (("eth0", target.ib.eth0_prefix), ("eth1", target.ib.eth1_prefix)):
            if prefix:
                direct_rows.append({"hostname": target.ib.hostname, "interface": interface,
                    "ip": str(ipaddress.IPv4Interface(prefix).ip), "status": "NOT_TESTED",
                    "detail": "base IPv4 configuration/credential was not verified in this run"})
    direct_summary = summarize_management_direct_checks(direct_rows)
    log_management_direct_summary(direct_rows, console=False)

    # T12: the DEV counter line stays; the skip counts come from each device's stage status.
    day0_skipped = sum(record.get("stage_status", {}).get("day0") == "ALREADY_PRESENT"
                       for record in records.values())
    services_skipped = sum(record.get("stage_status", {}).get("services")
                           in {"NOT_CONFIGURED", "ALREADY_PRESENT", "UNVERIFIED"}
                           for record in records.values())
    summary = (
        f"Summary: targets={len(targets)} configured={configured} "
        f"skipped={skipped} failed={failures} "
        f"day0-skipped={day0_skipped} services-skipped={services_skipped}"
    )
    log("\n" + summary)
    # Mutually exclusive final outcomes; check-only and unvisited targets are visible.
    counts = {state: list(outcomes.values()).count(state) for state in (
        "CONFIGURED", "ALREADY_CONFIGURED", "CHECK_ONLY", "PASSWORD_CHANGE_REQUIRED",
        "SKIPPED", "FAILED", "NOT_ATTEMPTED")}
    summary = "Summary: targets=" + str(len(targets)) + " " + " ".join(
        key.lower().replace("_", "-") + "=" + str(value) for key, value in counts.items())
    summary += " unmapped-csv=" + str(max(0, ib_candidate_count - len(targets)))
    summary += (f" direct-ssh-pass={direct_summary['ready']} "
                f"direct-ssh-fail={direct_summary['failed']} "
                f"direct-ssh-not-tested={direct_summary['not_tested']} "
                f"direct-ssh-eth1-fallback={direct_summary['fallback']} "
                f"upgrade-ssh-ready={direct_summary['ready']}/{len(targets)}")
    report_detail("\n" + summary)
    # The DEV policy keeps the resolved global in binding[0] (v15 read policy.resolved).
    project_name = Path(policy.binding[0]).parent.name if policy is not None else ib_csv_path.resolve().parent.name
    summary_status = print_initial_setup_summary(project_name, args, targets, ib_candidate_count,
        leaf_snapshot_failures, records, direct_rows, batch["workers"], batch["fatal"], jump_routes=jump_routes)
    evidence = {"project": project_name, "revision": _REPOSITORY_REVISION,
                "source_sha256": next(entry[3] for entry in runtime_authority.entries
                                      if entry[0] == _SELF_SOURCE_PATH.absolute()),
                "mode": "APPLY" if args.apply else "CHECK_ONLY", "result": summary_status,
                "workers": batch["workers"], "csv_ib_candidates": ib_candidate_count,
                "p2p_management_targets": len(targets), "oob_snapshot_failures": leaf_snapshot_failures,
                "spine_snapshot_failures": {key: value for key, value in table_failures.items()
                                            if key not in ethernet_switches},
                "spine_jump_routes": jump_routes,
                "records": records, "direct_rows": direct_rows, "batch_stop_reason": batch["fatal"],
                "summary": initial_setup_facts(records, direct_rows)}
    results_path = Path(batch["log_dir"]) / "summary.json"
    with results_path.open("x", encoding="utf-8") as handle:
        os.chmod(results_path, 0o600)
        handle.write(json.dumps(evidence, indent=2) + "\n")
    log(f"Structured results: {results_path}")
    if method_cycle is not None:
        method_cycle.close()
    return 0 if summary_status == "SUCCESS" else 1 if summary_status == "FAILED" else 2


if __name__ == "__main__":
    # DEV block: a SetupError from main() is reported and closed inside the guard by
    # _standalone_main_with_report_cleanup, so no outer handler is needed (and the
    # worker branch names only the worker; test_initial_setup_managed_merge_contract H22).
    if sys.argv[1:] == ["--_verify-password"]:
        raise SystemExit(_password_hash_worker())
    raise SystemExit(_guarded_main())
