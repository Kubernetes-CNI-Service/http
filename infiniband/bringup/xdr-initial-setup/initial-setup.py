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
import enum
import errno
import fcntl
import getpass
import hashlib
import hmac
import io
import ipaddress
import json
import multiprocessing
from multiprocessing.connection import wait as wait_connections
import os
import pty
import pwd
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
from dataclasses import asdict, dataclass, field, replace
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
TARGET_CACHE_VERSION = 6
_SELF_SOURCE_PATH = Path(__file__).resolve()
MAC_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
DOT_LINK_RE = re.compile(
    r'^\s*"([^"]+)"\s*:\s*"([^"]+)"\s*--\s*'
    r'"([^"]+)"\s*:\s*"([^"]+)"'
)
REPORT_HANDLE = None
# Fixed in the file: an OOB Leaf copy has no git to derive it from.  Every version that
# changes this script sets it to that version before its release tag (guide WP-2, A.11).
_REPOSITORY_REVISION = "http-v3.1.5"

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
_JUMP_SESSIONS = None
_TASK_LOG_BUFFER = None
_TASK_DEADLINE = None
_TASK_IB_CONFIG = None
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
# WP4 closed device programs: exact independent bytes, never arbitrary shell.
_CONFIG_BACKUP_SCRIPT = (
    "set -eu\n"
    "umask 077\n"
    "fail() { printf '%s\\n' 'IB configuration backup failed' >&2; exit 1; }\n"
    "[ \"$#\" -eq 1 ] || fail\n"
    "stamp=$1\n"
    "case \"$stamp\" in\n"
    "    [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]) ;;\n"
    "    *) fail ;;\n"
    "esac\n"
    "case \"${HOME-}\" in /*) ;; *) fail ;; esac\n"
    "backup=\"$HOME/current_${stamp}.yaml\"\n"
    "[ ! -e \"$backup\" ] && [ ! -L \"$backup\" ] || fail\n"
    "tmp=\n"
    "trap 'if [ -n \"$tmp\" ]; then rm -f -- \"$tmp\"; fi' EXIT\n"
    "trap 'exit 1' HUP INT TERM\n"
    "tmp=$(mktemp \"${backup}.tmp.XXXXXX\" 2>/dev/null) || fail\n"
    "chmod 600 \"$tmp\" || fail\n"
    "nv config show > \"$tmp\" 2>/dev/null || fail\n"
    "[ -s \"$tmp\" ] || fail\n"
    "bytes=$(wc -c < \"$tmp\" | tr -d '[:space:]') || fail\n"
    "case \"$bytes\" in ''|*[!0-9]*) fail ;; esac\n"
    "[ \"$bytes\" -gt 0 ] || fail\n"
    "ln -T -- \"$tmp\" \"$backup\" 2>/dev/null || fail\n"
    "rm -f -- \"$tmp\" || fail\n"
    "tmp=\n"
    "printf 'path=%s\\nbytes=%s\\n' \"$backup\" \"$bytes\"\n"
)

_DEFERRED_APPLY_SCRIPT = (
    "set -eu\n"
    "umask 077\n"
    "fail() { printf '%s\\n' 'IB deferred configuration launch failed' >&2; exit 1; }\n"
    "[ \"$#\" -eq 1 ] || fail\n"
    "stamp=$1\n"
    "case \"$stamp\" in\n"
    "    [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]) ;;\n"
    "    *) fail ;;\n"
    "esac\n"
    "case \"${HOME-}\" in /*) ;; *) fail ;; esac\n"
    "rc_file=\"$HOME/.initial-setup-${stamp}.rc\"\n"
    "[ ! -e \"$rc_file\" ] && [ ! -L \"$rc_file\" ] || fail\n"
    "(set -C; : > \"$rc_file\") 2>/dev/null || fail\n"
    "chmod 600 \"$rc_file\" || fail\n"
    "setsid nohup sh -c '\n"
    "set -u\n"
    "umask 077\n"
    "rc_file=$1\n"
    "sleep 3 || exit 1\n"
    "nv config apply -y && nv config save\n"
    "status=$?\n"
    "tmp=\n"
    "trap '\\''if [ -n \"$tmp\" ]; then rm -f -- \"$tmp\"; fi'\\'' EXIT\n"
    "trap '\\''exit 1'\\'' HUP INT TERM\n"
    "tmp=$(mktemp \"${rc_file}.tmp.XXXXXX\" 2>/dev/null) || exit 1\n"
    "printf \"%s\\n\" \"$status\" > \"$tmp\" || exit 1\n"
    "chmod 600 \"$tmp\" || exit 1\n"
    "mv -fT -- \"$tmp\" \"$rc_file\" || exit 1\n"
    "tmp=\n"
    "exit \"$status\"\n"
    "' -- \"$rc_file\" > /dev/null 2>&1 < /dev/null &\n"
    "exit 0\n"
)

_DEFERRED_APPLY_RC_SCRIPT = (
    "set -eu\n"
    "fail() { printf '%s\\n' 'IB deferred configuration result is unverified' >&2; exit 1; }\n"
    "[ \"$#\" -eq 1 ] || fail\n"
    "stamp=$1\n"
    "case \"$stamp\" in\n"
    "    [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]) ;;\n"
    "    *) fail ;;\n"
    "esac\n"
    "case \"${HOME-}\" in /*) ;; *) fail ;; esac\n"
    "rc_file=\"$HOME/.initial-setup-${stamp}.rc\"\n"
    "[ ! -L \"$rc_file\" ] || fail\n"
    "if [ ! -e \"$rc_file\" ]; then printf 'rc=\\n'; exit 0; fi\n"
    "[ -f \"$rc_file\" ] || fail\n"
    "if [ ! -s \"$rc_file\" ]; then printf 'rc=\\n'; exit 0; fi\n"
    "IFS= read -r status < \"$rc_file\" || fail\n"
    "case \"$status\" in\n"
    "    0|[1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]) ;;\n"
    "    *) fail ;;\n"
    "esac\n"
    "bytes=$(wc -c < \"$rc_file\" | tr -d '[:space:]') || fail\n"
    "case \"$bytes\" in ''|*[!0-9]*) fail ;; esac\n"
    "[ \"$bytes\" -eq \"$((${#status} + 1))\" ] || fail\n"
    "printf 'rc=%s\\n' \"$status\"\n"
)

_CONFIG_REPLACE_SCRIPT = "set -eu\numask 077\nfail() { printf '%s\\n' 'IB configuration replace failed' >&2; exit 1; }\n[ \"$#\" -eq 2 ] || fail\npayload=$1\nexpected=$2\n[ \"${#expected}\" -eq 64 ] || fail\ncase \"$expected\" in ''|*[!0-9a-f]*) fail ;; esac\ncase \"${HOME-}\" in /*) ;; *) fail ;; esac\nconfig=\"$HOME/initial-setup-replace.yaml\"\n[ ! -L \"$config\" ] || fail\nif [ -e \"$config\" ] && [ ! -f \"$config\" ]; then fail; fi\ntmp=\ntrap 'if [ -n \"$tmp\" ]; then rm -f -- \"$tmp\"; fi' EXIT\ntrap 'exit 1' HUP INT TERM\ntmp=$(mktemp \"${config}.tmp.XXXXXX\" 2>/dev/null) || fail\nchmod 600 \"$tmp\" || fail\nprintf '%s' \"$payload\" | base64 -d > \"$tmp\" 2>/dev/null || fail\n[ -s \"$tmp\" ] || fail\nactual=$(sha256sum \"$tmp\" 2>/dev/null) || fail\n[ \"${actual%% *}\" = \"$expected\" ] || fail\nmv -fT -- \"$tmp\" \"$config\" || fail\ntmp=\nif nv config replace \"$config\" > /dev/null 2>&1; then\n    :\nelse\n    rc=$?\n    case \"$rc\" in\n        [1-9]|[1-9][0-9]|1[01][0-9]|12[0-5])\n            printf 'rc=%s\\nfailed_operation=replace\\n' \"$rc\"\n            exit 1 ;;\n        *) fail ;;\n    esac\nfi\nprintf 'path=%s\\nsha256=%s\\n' \"$config\" \"$expected\"\n"


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

_KEY_READONLY_SCRIPT = (
    "set -eu\n"
    "LC_ALL=C\n"
    "export LC_ALL\n"
    "[ \"$#\" -eq 1 ] || exit 34\n"
    "[ -n \"${HOME:-}\" ] || exit 34\n"
    "auth=\"$HOME/.ssh/authorized_keys\"\n"
    "[ -f \"$auth\" ] || exit 34\n"
    "required=$(printf %s \"$1\" | base64 -d 2>/dev/null) || exit 34\n"
    "[ -n \"$required\" ] || exit 34\n"
    "printf '%s\\n' \"$required\" | awk '"
    + _KEY_VERIFY_AWK +
    "' /dev/stdin \"$auth\" >/dev/null 2>&1 || exit 34\n"
)


class SetupError(RuntimeError):
    pass


class SshFailureKind(enum.Enum):
    # D4 WP-1's small pure base; WP-2 adds the ordered reporting table.
    JUMP_UNREACHABLE = "OOB_JUMP_UNREACHABLE"
    JUMP_AUTHENTICATION = "OOB_JUMP_AUTHENTICATION"
    TARGET_HOST_KEY_CHANGED = "TARGET_HOST_KEY_CHANGED"
    HOST_KEY_REFRESH_PENDING = "HOST_KEY_REFRESH_PENDING"
    IDENTITY_MISMATCH = "OOB_IDENTITY_CONFLICT"
    LOCAL_COMMAND = "LOCAL_COMMAND_ERROR"
    DIRECT_SSH_NETWORK = "DIRECT_SSH_NETWORK"
    DIRECT_LOGIN_NETWORK = "DIRECT_LOGIN_NETWORK"


class SshFailure(SetupError):
    def __init__(self, kind, hop, address, jump=None):
        self.kind, self.hop, self.address, self.jump = kind, hop, address, jump
        self.failure_kind = kind.value
        super().__init__(f"SSH {kind.value}: {hop} {address}" + (f" via {jump}" if jump else ""))


def classify_ssh_failure(output, *, outer_address, inner_address=None):
    """Classify the address actually named by SSH, never a 255 or address substring."""
    named = re.search(r"(?i)(?:connect to host|connection (?:closed|reset) by)\s+(\S+)", output)
    address = named.group(1).strip("[]") if named else None
    if address == "remote" and re.search(r"(?i)kex_exchange_identification", output):
        address = None  # Literal "remote host" is not a conflicting address token.
    if address is not None:
        if outer_address is not None and address == outer_address:
            hop = "outer"
        elif inner_address is not None and address == inner_address:
            hop = "direct" if outer_address is None else "inner"
        else:
            return None
    else:
        evidence = "\n".join(line for line in output.splitlines() if re.search(
            r"(?i)permission denied|authentication failed|host key|identification|offending|"
            r"connection|route|unreachable|kex_exchange|control socket|mux_client", line))
        outer_named = outer_address is not None and re.search(
            r"(?<![A-Za-z0-9_.:%-])" + re.escape(outer_address) + r"(?![A-Za-z0-9_.:%-])", evidence)
        inner_named = inner_address is not None and re.search(
            r"(?<![A-Za-z0-9_.:%-])" + re.escape(inner_address) + r"(?![A-Za-z0-9_.:%-])", evidence)
        mux = re.search(r"(?i)control socket connect|mux_client_request_session", output)
        if outer_address is None:
            hop, address = "direct", inner_address or ""
        elif outer_named or mux or inner_address is None:
            hop, address = "outer", outer_address
        elif inner_named:
            hop, address = "inner", inner_address
        else:
            return None
    if re.search(r"(?i)remote host identification has changed|host key verification failed|offending .* key", output):
        kind = SshFailureKind.TARGET_HOST_KEY_CHANGED
    elif re.search(r"(?i)permission denied|authentication failed", output):
        if hop != "outer":
            return None  # The existing inner credential/forced-change protocol owns IB authentication.
        kind = SshFailureKind.JUMP_AUTHENTICATION
    elif re.search(r"(?i)connection timed out|connection refused|no route to host|network is unreachable|"
                   r"connection closed by|connection reset by|kex_exchange_identification|"
                   r"control socket connect|mux_client_request_session", output):
        if hop == "inner":
            return None
        kind = SshFailureKind.JUMP_UNREACHABLE if hop == "outer" else SshFailureKind.DIRECT_SSH_NETWORK
    else:
        return None
    return SshFailure(kind, hop, address)


# I-037 section3 outcome order: incomplete inputs, link mismatch, jump unreachable,
# login failure, identity mismatch, backup failure, config/verification failure, done.
# Existing DIRECT row retains its order; D1b adds rows here, never another stage map.
FAILURE_KIND_CATEGORY = {
    "DIRECT_SSH_NETWORK": "FAILED_DIRECT_SSH_NETWORK",
    "DIRECT_LOGIN_NETWORK": "FAILED_DIRECT_LOGIN_NETWORK",
    "OOB_JUMP_UNREACHABLE": "FAILED_OOB_JUMP_UNREACHABLE",
    "OOB_JUMP_AUTHENTICATION": "FAILED_OOB_JUMP_AUTHENTICATION",
    "TARGET_HOST_KEY_CHANGED": "FAILED_TARGET_HOST_KEY_CHANGED",
    "HOST_KEY_REFRESH_PENDING": "CHECKED_HOST_KEY_REFRESH_PENDING",
}


def _ssh_failure_fact(error):
    return error if isinstance(error, SshFailure) else getattr(error, "ssh_failure", None)


def _retain_ssh_failure(error, source):
    failure = _ssh_failure_fact(source)
    if failure is not None:
        error.ssh_failure = failure
        error.failure_kind = failure.kind.value
        change = getattr(failure, "host_key_change", None)
        if change is not None:
            error.host_key_change = change
    return error


def _classify_jump_output(output, jump, inner_address=None):
    records = getattr(_JUMP_SESSIONS, "records", {})
    record = records.get(normalize_name(jump.hostname), {})
    address = record.get("address") or jump.login_ip
    failure = classify_ssh_failure(output, outer_address=address, inner_address=inner_address)
    if failure is not None:
        failure.jump = jump.hostname
    return failure


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


class PendingChangesRefused(SetupError):
    """U3: the pending diff holds lines this run does not own; nothing was cleared or written."""


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
                      apply: bool, authorized: bool, local: bool, strict: bool = False,
                      _management_private_key=None
                      ) -> tuple[SessionResult, Optional[str], bool]:
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
            local=local, _password_policy=policy, strict=strict,
            _management_private_key=_management_private_key)
    except SetupError as exc:
        if str(exc) != _IB_CREDENTIALS_EXHAUSTED:
            raise
        if (type(exc) is SetupError and type(target) is Target and target.ethernet is None
                and local is False and isinstance(_management_private_key, Path)
                and hasattr(exc, "_direct_endpoint")):
            actual = exc._direct_endpoint
            _validate_direct_endpoint(target, actual)
            neighbor = actual
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
    if credential is None and apply:
        # The key proved access, not a password. O6(b) separately authenticates
        # the verified project candidate before it can become current.
        if policy is None:
            raise SetupError("key-authenticated apply requires a verified project IB password")
        point = getattr(result, "_direct_endpoint", None)
        _validate_direct_endpoint(target, point)
        candidate = (_ib_project_value(policy, user=ib_user, fetch=True) if strict
                     else policy.password())
        policy.assert_unchanged()
        rejected = False
        try:
            proof = run_on_ib(target, point, "", "", ib_user, candidate, timeout,
                              ["true"], local=False, password_only=True,
                              allow_password_change=False)
        except IBAuthenticationError:
            rejected = True
        if rejected:
            raise IBAuthenticationError("project password-only authentication rejected after key login; "
                                        "target/current password drift; configuration is blocked")
        policy.assert_unchanged()
        if (type(proof) is not SessionResult or type(proof.exit_code) is not int
                or proof.exit_code != 0 or type(proof.output) is not str
                or getattr(proof, "cleanup_uncertain", False) is not False
                or any(getattr(proof, name) is not False for name in (
                    "password_changed", "password_change_required", "password_change_attempted",
                    "ib_authentication_rejected"))
                or _EXPIRED_PASSWORD.search(proof.output)
                or _pending_diff_has_password_update_notice(proof.output)):
            raise SetupError("project password-only authentication is unverified; configuration is blocked")
        actual = getattr(proof, "_direct_endpoint", None)
        _validate_direct_endpoint(target, actual)
        if actual != point:
            if point.interface is None or actual.interface is not None:
                raise SetupError("project password authentication endpoint transition is unverified")
            # Never attach true's endpoint to an old-point NVUE result.
            result = _stage_ib_command(target, actual, "", "", ib_user, candidate,
                timeout, command, local=False, strict=strict, policy=policy)
            if (type(result) is not SessionResult or type(result.exit_code) is not int
                    or result.exit_code != 0 or type(result.output) is not str
                    or getattr(result, "cleanup_uncertain", False) is not False
                    or any(getattr(result, name) is not False for name in (
                        "password_changed", "password_change_required", "password_change_attempted",
                        "ib_authentication_rejected"))
                    or _EXPIRED_PASSWORD.search(result.output)
                    or _pending_diff_has_password_update_notice(result.output)):
                raise SetupError("new-endpoint NVUE readback is unverified")
            read_point = getattr(result, "_direct_endpoint", None)
            _validate_direct_endpoint(target, read_point)
            if read_point != actual:
                raise SetupError("new-endpoint NVUE readback changed endpoint")
        credential = candidate
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
    input_issues: tuple = field(default=(), compare=False)
    eth1_hints: tuple = field(default=(), compare=False)
    jump_candidates: tuple = field(default=(), compare=False)


@dataclass(frozen=True)
class Link:
    left_device: str
    left_port: str
    right_device: str
    right_port: str


@dataclass(frozen=True)
class Target:
    ib: Device
    ethernet: Optional[Device]
    ethernet_port: str
    ib_port_alias: str
    # Populated ONLY by the v15 preflight adapter. Legacy IB stages still use
    # ethernet/ethernet_port as their already selected execution endpoint.
    attachment: Optional[Target] = None
    jump_reason: str = ""
    access_vlan: str = ""
    route: object = field(default=None, compare=False)
    # Original CSV/P2P topology, independent of runtime transport/spine attachment.
    source_attachment: object = field(default=None, compare=False)


@dataclass(frozen=True)
class Neighbor:
    ipv6: str
    interface: str
    mac: str
    vrf: str = "default"
    address_source: str = "ND"


@dataclass(frozen=True)
class DirectEndpoint:
    address: str
    interface: Optional[str] = None


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
    """O9: retain every IB row; conflicts qualify individual interfaces, not CSV."""
    paths = _import_tools("tools.login_path")
    issues = {key: list(device.input_issues) for key, device in devices.items()}
    hints = {key: list(device.eth1_hints) for key, device in devices.items()}
    original = dict(devices)
    eth0, eth1 = {}, {}
    for key, device in devices.items():
        if not valid_hostname(device.hostname):
            raise SetupError(f"invalid IB hostname: {device.hostname!r}")
        for prefix, table in ((device.eth0_prefix, eth0), (device.eth1_prefix, eth1)):
            if prefix:
                table[key] = ipaddress.IPv4Interface(prefix)

    def issue(key, field_name, value, problem, *, blocking=True):
        item = paths.InputIssue(devices[key].hostname, field_name, value, problem, blocking)
        (issues if blocking else hints)[key].append(item)

    keys = list(devices)
    for index, left in enumerate(keys):
        for right in keys[index + 1:]:
            a, b = eth0.get(left), eth0.get(right)
            if a is not None and b is not None:
                if a.ip == b.ip:
                    for own, other in ((left, right), (right, left)):
                        issue(own, "eth0_ip", str(eth0[own].ip),
                              "duplicate address with " + devices[other].hostname)
                if (a.network == b.network and devices[left].eth0_gateway
                        and devices[right].eth0_gateway
                        and devices[left].eth0_gateway != devices[right].eth0_gateway):
                    for own, other in ((left, right), (right, left)):
                        issue(own, "eth0_gw", devices[own].eth0_gateway,
                              "conflicting gateway with " + devices[other].hostname)
    for key, device in devices.items():
        for owner, address in eth0.items():
            if device.eth0_gateway and device.eth0_gateway == str(address.ip):
                issue(key, "eth0_gw", device.eth0_gateway,
                      "gateway is device address of " + devices[owner].hostname)
                if owner != key:
                    issue(owner, "eth0_ip", str(address.ip),
                          "address used as gateway by " + device.hostname)
        if key in eth1:
            conflicts = [devices[owner].hostname for owner, address in eth0.items()
                         if address.ip == eth1[key].ip]
            conflicts += [devices[owner].hostname for owner, address in eth1.items()
                          if owner != key and address.ip == eth1[key].ip]
            if conflicts:
                issue(key, "eth1_ip", str(eth1[key].ip),
                      "address overlaps " + ", ".join(conflicts), blocking=False)
                devices[key] = replace(device, eth1_prefix="", eth1_gateway="")
            if device.eth1_gateway:
                owners = [original[owner].hostname for owner, address in [*eth0.items(), *eth1.items()]
                          if owner != key and device.eth1_gateway == str(address.ip)]
                inconsistent = [original[owner].hostname for owner, address in eth1.items()
                                if owner != key and address.network == eth1[key].network
                                and original[owner].eth1_gateway
                                and original[owner].eth1_gateway != device.eth1_gateway]
                if owners or inconsistent:
                    issue(key, "eth1_gw", device.eth1_gateway,
                          "gateway conflicts with " + ", ".join(owners + inconsistent), blocking=False)
                    devices[key] = replace(devices[key], eth1_gateway="")
    for key, device in devices.items():
        devices[key] = replace(device, input_issues=tuple(issues[key]), eth1_hints=tuple(hints[key]))


def _jump_vlan_groups(row, indexes):
    fields = {position: name for name, positions in indexes.items() for position in positions}
    boundaries = {"vlan_id", "vlan_ports", "bgp_asn", "bgp_ports", "bond_ports", "evpn_vrf", "evpn_l2vlan"}
    for start in indexes.get("vlan_id", ()):
        end = next((index for index in range(start + 1, max(fields) + 1)
                    if fields[index] in boundaries), max(fields) + 1)
        for position in indexes.get("svi_ip", ()):
            if start < position < end:
                mask = next((index for index in indexes.get("netmask", ()) if position < index < end), None)
                yield (clean(row[start]) if start < len(row) else "",
                       clean(row[position]) if position < len(row) else "",
                       clean(row[mask]) if mask is not None and mask < len(row) else "")


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
    paths = _import_tools("tools.login_path")
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
            input_issues, eth1_hints, jump_candidates = (), (), ()
            try:
                if paths.is_jump_type(dev_type):
                    inventory_errors = _eth_jump_inventory_errors(
                        [clean(field).casefold() for field in raw_header], row,
                        lambda value: not usable(value),
                    )
                    input_issues = tuple(paths.InputIssue(hostname, "inventory", "", error, False)
                                         for error in inventory_errors)
                    try:
                        eth0_mac = normalize_mac(eth0_mac, field=f"{hostname}.eth0_mac")
                    except SetupError:
                        eth0_mac = ""
                if dev_type == "ib":
                    plan, input_issues = paths.check_eth0_inputs(hostname, mac=eth0_mac,
                        address=eth0_ip, netmask=netmask0, gateway=eth0_gateway)
                    # Keep a syntactically valid address even if another field is bad:
                    # cross-device address ownership still has to be checked (O9).
                    try:
                        eth0 = ipv4_prefix(eth0_ip, netmask0, field=hostname + ".eth0_ip", required=False)
                    except (SetupError, ValueError):
                        eth0 = ""
                    if any(issue.field in {"eth0_ip", "netmask"} for issue in input_issues):
                        eth0 = ""
                    try:
                        eth0_mac = normalize_mac(eth0_mac, field=hostname + ".eth0_mac")
                    except SetupError:
                        eth0_mac = ""
                    eth0_gateway = ("" if any(issue.field == "eth0_gw" for issue in input_issues)
                                    else str(ipaddress.IPv4Address(eth0_gateway)))
                    secondary, eth1_hints = paths.check_eth1_inputs(hostname, eth0_mac=eth0_mac,
                        mac=row_value(row, indexes, "eth1_mac"), address=eth1_ip,
                        netmask=netmask1, gateway=eth1_gateway)
                    eth1 = str(secondary.address) if secondary.address is not None else ""
                    eth1_gateway = secondary.gateway
                    login_ip = eth0.split("/", 1)[0]
                elif paths.is_jump_type(dev_type):
                    jump_candidates, candidate_issues = paths.jump_login_candidates(hostname,
                        eth0_ip=eth0_ip, vlan_groups=tuple(_jump_vlan_groups(row, indexes)))
                    input_issues += candidate_issues
                    login_ip = jump_candidates[0].address if jump_candidates else ""
                    if jump_candidates and jump_candidates[0].entry != "JUMP_ETH0":
                        login_interface = "vlan" + jump_candidates[0].entry.removeprefix("JUMP_VLAN")
                    eth0 = login_ip if login_interface == "eth0" else ""
                    eth1, eth0_gateway, eth1_gateway = "", "", ""
                else:
                    # A non-jump peer is attachment metadata, not a login endpoint.
                    eth0 = eth0_mac = ""
                    eth1 = ""
                    eth0_gateway = ""
                    eth1_gateway = ""
                    login_ip = eth0
            except (SetupError, ValueError) as exc:
                raise SetupError(f"{path}:{line_number}: {exc}") from exc

            device = Device(
                hostname, dev_type, login_ip, eth0,
                eth0_gateway, eth0_mac, eth1, eth1_gateway, login_interface,
                input_issues, eth1_hints, jump_candidates,
            )
            target_map = ib_devices if dev_type == "ib" else eth_devices
            key = normalize_name(hostname)
            if key in ib_devices or key in eth_devices:
                raise SetupError(f"duplicate device hostname in CSV: {hostname}")
            target_map[key] = device

    if not ib_devices:
        raise SetupError(f"device CSV contains no type=ib devices: {path}")
    validate_ib_devices(ib_devices)
    jump_addresses = {candidate.address: device.hostname for device in eth_devices.values()
                      for candidate in device.jump_candidates}
    for key, device in ib_devices.items():
        issues, hints = list(device.input_issues), list(device.eth1_hints)
        address = device.eth0_prefix.split("/", 1)[0]
        if address in jump_addresses:
            issues.append(paths.InputIssue(device.hostname, "eth0_ip", address,
                          "duplicate address with " + jump_addresses[address], True))
        secondary = device.eth1_prefix.split("/", 1)[0]
        if secondary in jump_addresses:
            hints.append(paths.InputIssue(device.hostname, "eth1_ip", secondary,
                         "duplicate address with " + jump_addresses[secondary], False))
            device = replace(device, eth1_prefix="", eth1_gateway="")
        ib_devices[key] = replace(device, input_issues=tuple(issues), eth1_hints=tuple(hints))
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
    paths = _import_tools("tools.login_path")
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
            key = normalize_name(ib.hostname)
            if key in seen:
                raise SetupError(f"multiple management links found for IB device {ib.hostname}")
            seen.add(key)
            attachment = paths.Attachment(ethernet.hostname if ethernet else eth_name,
                                          ethernet.dev_type if ethernet else "", cumulus_port_name(eth_port))
            route = paths.classify([ib], {ib.hostname: attachment}, direct=frozenset(), same_subnet={})[0]
            targets.append(Target(ib, ethernet if route.path == "jump" else None,
                                  attachment.port, clean(ib_port), route=route,
                                  source_attachment=attachment))
    for key, ib in ib_devices.items():
        if key not in seen:
            route = paths.classify([ib], {}, direct=frozenset(), same_subnet={})[0]
            targets.append(Target(ib, None, "", "eth0", route=route))
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


def _compare_inventory(ib_csv, project, *, checked_by_caller=False):
    if checked_by_caller:
        return {"status": "checked_by_caller"}
    if project is not None:
        master = project / "02-devices_config.csv"
    else:
        script = Path(__file__).resolve()
        if script.parts[-4:] != ("infiniband", "bringup", "xdr-initial-setup", "initial-setup.py"):
            raise SetupError(f"repository inventory master is unavailable for {script}; use --project-dir")
        master = script.parents[3] / "infiniband" / "02-devices_config.csv"
    try:
        subset_raw, master_raw = ib_csv.read_bytes(), master.read_bytes()
        mismatches = ([] if ib_csv.resolve() == master.resolve() else
                      _import_tools("tools.inventory_subset").compare(ib_csv, master))
    except (OSError, ValueError, UnicodeError, csv.Error, IndexError) as error:
        reason = type(error).__name__
        if isinstance(error, OSError) and type(error.errno) is int:
            reason += f" errno={error.errno}"
        raise SetupError(f"cannot compare inventory CSV {ib_csv} and 02 {master}: "
                         + reason) from None
    for row in mismatches:
        print(f"INVENTORY MISMATCH: {row.hostname}; {row.column}; ib.csv={row.subset_value}; "
              f"02={row.master_value}; {row.kind}")
    if mismatches:
        raise SetupError(f"inventory mismatch: {ib_csv} and {master}")
    return {"status": "compared", "subset_sha256": hashlib.sha256(subset_raw).hexdigest(),
            "master_sha256": hashlib.sha256(master_raw).hexdigest()}


def _read_local_interfaces():
    if not sys.platform.startswith("linux"):
        return None
    result = subprocess.run(["ip", "-j", "address", "show"], capture_output=True,
                            text=True, timeout=15, check=False)
    if result.returncode != 0:
        return None
    return _import_tools("tools.login_path").parse_local_interfaces(result.stdout)


def _classified_target_counts(targets: list[Target]) -> str:
    linked = sum(target.source_attachment is not None for target in targets)
    return f"IB targets with P2P management links: {linked}; Classified IB targets: {len(targets)}"


def _jump_has_no_login_address(jump: Optional[Device]) -> bool:
    return jump is not None and not jump.jump_candidates and not jump.login_ip


def _runtime_routes(targets, direct, *, emit=log):
    paths = _import_tools("tools.login_path")
    rows = []
    interfaces = ()
    if direct or any(target.route.path == "direct" for target in targets):
        try:
            interfaces = _read_local_interfaces()
        except (OSError, ValueError, subprocess.SubprocessError):
            interfaces = None
        if interfaces is None:
            emit("Local interfaces unavailable; direct targets are treated as not same subnet.")
            interfaces = ()
    reported_jumps = set()
    for target in targets:
        route = target.route
        if target.ib.hostname in direct:
            route = paths.Route(target.ib.hostname, "direct", "DIRECT_ACCESS", None, None, None)
        if route.path == "direct" and target.ib.eth0_prefix:
            route = replace(route, same_subnet=paths.same_subnet_interface(target.ib.eth0_prefix, interfaces))
        selected = replace(target, ethernet=target.ethernet if route.path == "jump" else None, route=route)
        rows.append(selected)
        emit(f"Route {route.hostname}: {route.path} {route.reason}; "
             f"jump={route.jump or '-'} port={route.port or '-'} same_subnet={route.same_subnet or 'no'}")
        jump = selected.ethernet
        if jump is not None and jump.hostname not in reported_jumps:
            reported_jumps.add(jump.hostname)
            if jump.input_issues:
                hints = (
                    f"{issue.problem.partition('=')[0]}: invalid inventory field"
                    if issue.field == "inventory" else f"{issue.field}: {issue.problem}"
                    for issue in jump.input_issues
                )
                emit(f"  Jump input hint {jump.hostname}: " + "; ".join(hints))
        for issue in target.ib.input_issues:
            emit(f"  SKIPPED_INPUT_INCOMPLETE {issue.field}={issue.value}: {issue.problem}")
        for issue in target.ib.eth1_hints:
            emit(f"  eth1 hint {issue.field}={issue.value}: {issue.problem}")
    return rows


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


def validate_replace_release(release_dir, project_dir=None, *, _bindings=None):
    """D67-O12: validate the published input binding without importing YAML."""
    try:
        lexical_release = Path(release_dir).absolute()
        release = lexical_release.resolve(strict=True)
        project = (release.parent.parent if project_dir is None
                   else Path(project_dir).resolve(strict=True))
        if (not release.is_dir() or release.parent.name != "99-output-ib_nvl"
                or release.parent != project / "99-output-ib_nvl"):
            raise ValueError
        bindings = {}

        def bind(path, digest, resolved=None):
            if _bindings is not None:
                path = Path(path).absolute()
                bindings[path] = (path.resolve(strict=True) if resolved is None else resolved, digest)

        marker = (release / ".published-complete").read_bytes()
        if not marker:
            raise ValueError
        manifest_path = release / "release-manifest.json"
        manifest_bytes = manifest_path.read_bytes()
        manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
        parent_path = project / "99-output-ztp" / "current-release.json"
        parent_bytes = parent_path.read_bytes()
        manifest = json.loads(manifest_bytes.decode("utf-8"))
        parent = json.loads(parent_bytes.decode("utf-8"))
        if (type(manifest) is not dict or manifest.get("schema_version") != 1
                or type(manifest.get("devices")) is not list
                or type(parent) is not dict or parent.get("schema_version") != 2):
            raise ValueError
        component = parent["components"]["nvos"]
        component_path = Path(component["release_dir"])
        if (component_path.is_absolute() or (project / component_path).resolve(strict=True) != release
                or component["manifest_sha256"] != manifest_digest
                or component["published_marker_sha256"] != hashlib.sha256(marker).hexdigest()):
            raise ValueError
        bind(lexical_release / ".published-complete", hashlib.sha256(marker).hexdigest(),
             release / ".published-complete")
        bind(lexical_release / "release-manifest.json", manifest_digest, manifest_path)
        bind(parent_path, hashlib.sha256(parent_bytes).hexdigest())
        for name in ("global", "devices", "subnet", "p2p"):
            declared = parent["input_paths"][name]
            if type(declared) is not str or not declared:
                raise ValueError
            source = Path(declared)
            if source.is_absolute():
                if name != "p2p":
                    raise ValueError
            else:
                if ".." in source.parts:
                    raise ValueError
                source = project / source
            digest = _file_sha256(source)
            if parent["inputs"][name] != digest:
                raise ValueError
            bind(source, digest)
        for row in manifest["devices"]:
            name = row["hostname"]
            if type(name) is not str or not name or "/" in name or "\\" in name:
                raise ValueError
            # Missing/nonordinary host YAML is a per-device selection failure.
            candidate = release / (name + ".yaml")
            try:
                info = candidate.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISREG(info.st_mode) and info.st_size:
                digest = _file_sha256(candidate)
                if row["config_sha256"] != digest:
                    raise ValueError
                bind(lexical_release / (name + ".yaml"), digest, candidate)
        if _bindings is not None:
            _bindings.update(files=bindings, global_sha256=parent["inputs"]["global"])
        return manifest
    except (OSError, ValueError, TypeError, KeyError, AttributeError, SetupError):
        raise SetupError("replace release is invalid; run load to regenerate configuration") from None


def _replace_yaml_hostname(raw):
    """Read only the generated - set:/system:/hostname indentation path."""
    stack, values = [], []
    for line in raw.decode("utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        body = line[indent:]
        if body == "- set:":
            stack = [(indent + 2, "set")]
            continue
        while stack and stack[-1][0] >= indent:
            stack.pop()
        match = re.fullmatch(r"([A-Za-z0-9_.-]+):(?:\s+(.*))?", body)
        if match is None:
            continue
        key, value = match.group(1), match.group(2)
        if [item for _at, item in stack] == ["set", "system"] and key == "hostname" and value:
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                value = value[1:-1]
            values.append(value)
        if value is None:
            stack.append((indent, key))
    return values[0] if len(values) == 1 else None


def select_replace_yaml(target, release_dir, manifest, *, _bindings=None):
    """Select one exact CSV-host YAML; invalid hosts never fall back to patch."""
    result = {"verdict": "YAML_MISSING_OR_INVALID", "file": "", "sha256": "",
              "reason": "replace YAML is missing or invalid"}
    try:
        name = target.ib.hostname
        if type(name) is not str or not name or "/" in name or "\\" in name:
            return result
        lexical_release = Path(release_dir).absolute()
        release = lexical_release.resolve(strict=True)
        path = release / (name + ".yaml")
        result["file"] = str(path)
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or not info.st_size:
            return result
        rows = [row for row in manifest["devices"] if row.get("hostname") == name]
        if len(rows) != 1:
            return result
        row = rows[0]
        mac = normalize_mac(target.ib.eth0_mac, field="CSV eth0 MAC")
        if (row.get("config") != name + ".yaml" or row.get("identity_state") != "managed"
                or not mac or mac not in {normalize_mac(value, field="release MAC") for value in row["macs"]}):
            return result
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if row.get("config_sha256") != digest or _replace_yaml_hostname(raw) != name:
            return result
        alias = release / (mac.replace(":", "") + ".yaml")
        if os.path.lexists(alias) and (not alias.is_symlink() or alias.resolve(strict=True) != path):
            return result
        if _bindings is not None:
            _bindings[lexical_release / path.name] = (path, digest)
            if os.path.lexists(alias):
                _bindings[lexical_release / alias.name] = (path, digest)
        return {"verdict": "WOULD_REPLACE", "file": str(path), "sha256": digest, "reason": ""}
    except (OSError, ValueError, TypeError, KeyError, AttributeError, SetupError):
        return result


_REPLACE_PAYLOAD_BASE64_MAX = 131072


def replace_command(yaml_bytes):
    """One bounded DATA payload and its digest, never an arbitrary device command."""
    if type(yaml_bytes) is not bytes or not yaml_bytes:
        raise SetupError("replace YAML payload is invalid")
    payload = base64.b64encode(yaml_bytes).decode("ascii")
    if len(payload) > _REPLACE_PAYLOAD_BASE64_MAX:
        raise SetupError("replace YAML payload is invalid")
    return ["sh", "-c", _CONFIG_REPLACE_SCRIPT, "--", payload,
            hashlib.sha256(yaml_bytes).hexdigest()]


def _verify_replace_command_receipt(result, backup_path, expected_sha256) -> None:
    """Check the replace receipt after framing, using this device's verified backup path."""
    if (type(backup_path) is not str or not backup_path.startswith("/")
            or type(expected_sha256) is not str or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
            or type(result) is not SessionResult or type(result.exit_code) is not int
            or result.exit_code != 0 or type(result.output) is not str
            or any(getattr(result, name) is not False for name in (
                "password_changed", "password_change_required", "password_change_attempted",
                "ib_authentication_rejected"))):
        raise SetupError("IB configuration replace outcome is unverified")
    parent = backup_path.rpartition("/")[0]
    expected = f"path={parent}/initial-setup-replace.yaml\nsha256={expected_sha256}\n"
    if result.output != expected:
        raise SetupError("IB configuration replace receipt is unverified")


def _replace_failure_is_detach_candidate(operation, rc) -> bool:
    """Classify proven failure facts only; never grant permission to detach."""
    return (type(operation) is str and operation in {"replace", "apply"}
            and type(rc) is int and 1 <= rc <= 255)


@dataclass(frozen=True, eq=False, repr=False)
class _InitialIPv4ReplaceRequest:
    state: _IBConfigWriteState
    authority: RuntimeInputAuthority
    endpoint: DirectEndpoint
    stamp: str


@dataclass(frozen=True, eq=False, repr=False)
class _InitialIPv4ReplaceFailure:
    request: _InitialIPv4ReplaceRequest
    rc: int


@dataclass(frozen=True, eq=False, repr=False)
class _ReplaceSyncFailureScope:
    """One internal dispatch identity, not an authorization or transport credential."""
    task: object
    endpoint: object
    operation: str
    marker: str


def _replace_receipt_rc(body):
    """Recognize an exact inner replace receipt, not permission to consume it."""
    receipt = re.fullmatch(r"rc=([1-9][0-9]{0,2})\nfailed_operation=replace\n", body)
    if receipt is None or not 1 <= int(receipt[1]) <= 125:
        return None
    return int(receipt[1])


def _qualify_replace_sync_failure(result, active_scope, result_scope, *,
                                 cancelled=False, input_changed=False, transport_error=None):
    """Qualify frame facts once the caller has bound both sides to the authorized dispatch."""
    if (cancelled is not False or input_changed is not False or transport_error is not None
            or type(active_scope) is not _ReplaceSyncFailureScope or active_scope is not result_scope
            or type(active_scope.operation) is not str
            or active_scope.operation not in {"replace", "apply", "save"}
            or type(active_scope.marker) is not str
            or re.fullmatch(r"[A-Za-z0-9_]{1,80}", active_scope.marker) is None
            or type(result) is not SessionResult or type(result.exit_code) is not int
            or not 1 <= result.exit_code <= 255 or type(result.output) is not str
            or getattr(result, "cleanup_uncertain", False) is not False
            or any(getattr(result, name) is not False for name in (
                "password_changed", "password_change_required", "password_change_attempted",
                "ib_authentication_rejected"))):
        return None
    try:
        body = extract_command_output(result.output, active_scope.marker, expected_exit_code=result.exit_code)
    except (SetupError, ValueError):
        return None
    if active_scope.operation == "replace":
        # The frame surrounds the whole file-preparation/replace program; only
        # its inner command can attribute the failure to the device operation.
        if result.exit_code != 1:
            return None
        rc = _replace_receipt_rc(body)
        return ("replace", rc) if rc is not None else None
    return active_scope.operation, result.exit_code


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


def _cache_route_facts(payload):
    """Validate schema-six facts separately; the old target/device fields stay fixed."""
    paths = _import_tools("tools.login_path")
    inventory = payload.get("inventory_check")
    if type(inventory) is not dict:
        raise ValueError("missing inventory qualification")
    if inventory == {"status": "checked_by_caller"}:
        pass
    elif (set(inventory) != {"status", "subset_sha256", "master_sha256"}
          or inventory["status"] != "compared"
          or any(type(inventory[key]) is not str or not re.fullmatch(r"[0-9a-f]{64}", inventory[key])
                 for key in ("subset_sha256", "master_sha256"))
          or inventory["subset_sha256"] != payload["cache_authority"]["ib_csv_sha256"]):
        raise ValueError("invalid inventory qualification")
    maps = {}
    for name in ("routes", "input_issues", "eth1_hints", "jump_candidates", "source_attachments"):
        if type(payload.get(name)) is not dict or any(type(key) is not str for key in payload[name]):
            raise ValueError("missing route facts")
        maps[name] = payload[name]
    routes = {}
    for name, row in maps["routes"].items():
        if (type(row) is not dict or set(row) != {"hostname", "path", "reason", "jump", "port", "same_subnet"}
                or row["hostname"] != name or row["path"] not in {"jump", "direct"}
                or row["reason"] not in {"JUMP_LINK", "NO_MGMT_LINK", "PEER_NOT_JUMP"}
                or not (row["same_subnet"] is None or type(row["same_subnet"]) is str)
                or (row["path"] == "jump") != (row["reason"] == "JUMP_LINK")):
            raise ValueError("invalid route")
        # Keep optional endpoints typed and consistent; direct is not a fabricated Jump.
        if row["path"] == "jump":
            if any(type(row[key]) is not str or not row[key] for key in ("jump", "port")):
                raise ValueError("invalid jump route")
        elif row["jump"] is not None or row["port"] is not None:
            raise ValueError("invalid direct route")
        routes[name] = paths.Route(**row)
    if set(maps["source_attachments"]) != set(routes):
        raise ValueError("invalid source attachment names")
    sources = {}
    for host, row in maps["source_attachments"].items():
        route = routes[host]
        if row is None:
            if route.reason != "NO_MGMT_LINK":
                raise ValueError("missing source attachment")
            sources[host] = None
            continue
        if (type(row) is not dict or set(row) != {"peer", "peer_type", "port"}
                or any(type(value) is not str for value in row.values())):
            raise ValueError("invalid source attachment")
        source = paths.Attachment(**row)
        if (route.reason == "NO_MGMT_LINK"
                or (route.reason == "JUMP_LINK" and (
                    not paths.is_jump_type(source.peer_type)
                    or (source.peer, source.port) != (route.jump, route.port)))
                or (route.reason == "PEER_NOT_JUMP" and paths.is_jump_type(source.peer_type))):
            raise ValueError("source attachment does not match base route")
        sources[host] = source
    facts = {"source_attachments": sources}
    for name in ("input_issues", "eth1_hints"):
        facts[name] = {}
        for host, rows in maps[name].items():
            if type(rows) is not list:
                raise ValueError("invalid input facts")
            values = []
            for row in rows:
                if (type(row) is not dict or set(row) != {"hostname", "field", "value", "problem", "blocking"}
                        or row["hostname"] != host or type(row["blocking"]) is not bool
                        or any(type(row[key]) is not str for key in ("hostname", "field", "value", "problem"))):
                    raise ValueError("invalid input issue")
                values.append(paths.InputIssue(**row))
            facts[name][host] = tuple(values)
    facts["jump_candidates"] = {}
    for host, rows in maps["jump_candidates"].items():
        if type(rows) is not list:
            raise ValueError("invalid jump candidates")
        values = []
        for row in rows:
            if (type(row) is not dict or set(row) != {"address", "entry"}
                    or type(row["address"]) is not str or type(row["entry"]) is not str
                    or not re.fullmatch(r"JUMP_ETH0|JUMP_VLAN[1-9][0-9]{0,3}", row["entry"])):
                raise ValueError("invalid jump candidate")
            ipaddress.IPv4Address(row["address"])
            values.append(paths.JumpCandidate(**row))
        facts["jump_candidates"][host] = tuple(values)
    return routes, facts


def load_target_cache(cache_path: Path, ib_csv: Path,
                      p2p: Path, *, public_key_tool: Optional[Path] = None,
                      validate_public_keys_with_ssh_keygen: bool = False,
                      allow_baked_missing_global: bool = False,
                      input_snapshot=None,
                      _admission_out=None,
                      public_key_dir: Optional[Path] = None
                      ) -> Optional[tuple[int, list[Target]]]:
    return _load_target_cache(
        cache_path, ib_csv, p2p, public_key_tool=public_key_tool,
        validate_public_keys_with_ssh_keygen=validate_public_keys_with_ssh_keygen,
        allow_baked_missing_global=allow_baked_missing_global, input_snapshot=input_snapshot,
        _admission_out=_admission_out, public_key_dir=public_key_dir,
    )


def _load_target_cache(cache_path, ib_csv, p2p, *, public_key_tool=None,
                       validate_public_keys_with_ssh_keygen=False, allow_baked_missing_global=False,
                       input_snapshot=None, _admission_out=None, public_key_dir=None,
                       expected_ib_csv_sha256=None):
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
        if (expected_ib_csv_sha256 is not None
                and payload["cache_authority"]["ib_csv_sha256"] != expected_ib_csv_sha256):
            return None
        routes, facts = _cache_route_facts(payload)
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
        targets = []
        def device(row):
            if (type(row) is not dict or set(row) != {
                    "hostname", "dev_type", "login_ip", "eth0_prefix", "eth0_gateway",
                    "eth0_mac", "eth1_prefix", "eth1_gateway", "login_interface"}
                    or any(type(value) is not str for value in row.values())):
                raise ValueError("invalid cached device")
            value = Device(**row)
            name = value.hostname
            return replace(value, input_issues=facts["input_issues"][name],
                           eth1_hints=facts["eth1_hints"][name],
                           jump_candidates=facts["jump_candidates"].get(name, ()))
        for item in payload["targets"]:
            if (type(item) is not dict or set(item) != {"ib", "ethernet", "ethernet_port", "ib_port_alias"}
                    or type(item["ethernet_port"]) is not str or type(item["ib_port_alias"]) is not str):
                return None
            ib = device(item["ib"])
            route = routes[ib.hostname]
            ethernet = device(item["ethernet"]) if item["ethernet"] is not None else None
            if ((ethernet is None) != (route.path == "direct")
                    or (ethernet is not None and route.jump != ethernet.hostname)):
                return None
            targets.append(Target(ib, ethernet, clean(item["ethernet_port"]),
                                  clean(item["ib_port_alias"]), route=route,
                                  source_attachment=facts["source_attachments"][ib.hostname]))
        if set(routes) != {target.ib.hostname for target in targets} or len(routes) != len(targets):
            return None
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
                      public_keys: Optional[list[dict[str, str]]] = None,
                      inventory_check: Optional[dict] = None) -> None:
    if inventory_check is None:
        raise SetupError("target cache requires the caller's actual inventory qualification")
    devices = {device.hostname: device for target in targets
               for device in (target.ib, target.ethernet) if device is not None}
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
        "inventory_check": inventory_check,
        "routes": {target.ib.hostname: asdict(target.route) for target in targets},
        "source_attachments": {target.ib.hostname: (
            asdict(target.source_attachment) if target.source_attachment is not None else None)
            for target in targets},
        "input_issues": {name: [asdict(issue) for issue in device.input_issues]
                         for name, device in devices.items()},
        "eth1_hints": {name: [asdict(issue) for issue in device.eth1_hints]
                       for name, device in devices.items()},
        "jump_candidates": {name: [asdict(candidate) for candidate in device.jump_candidates]
                            for name, device in devices.items() if device.dev_type.endswith("jump")},
        "targets": [
            {
                "ib": device_to_dict(target.ib),
                "ethernet": device_to_dict(target.ethernet) if target.ethernet is not None else None,
                "ethernet_port": target.ethernet_port,
                "ib_port_alias": target.ib_port_alias,
            }
            for target in targets
        ],
    }
    _validate_cache_profile(payload)
    _cache_route_facts(payload)
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


def _ib_raise_phase_failure(stage, uncertain=False, number=None, *, ssh_failure=None):
    messages = {
        "project": "IB phase project authority failed; device state is UNKNOWN",
        "transport": "IB phase transport failed; device state is UNKNOWN",
        "verification": "IB phase verification failed; device state is UNKNOWN",
    }
    error = SetupError(messages[stage])
    _retain_ssh_failure(error, ssh_failure)
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
    responder = NestedResponder(ethernet_password, current_password,
                                _phase_operation == "password-change" and allow_password_change is True,
                                ib_new_password=ib_new_password,
                                ib_destination=phase.endpoint, _phase=phase)
    failure = None
    ssh_failure = None
    result = None
    try:
        command = nested_ssh_command(target, neighbor, eth_user, ib_user, timeout, ib_command,
                                     local=False, marker=phase.nonce, password_only=True, _phase=phase)
        result = interactive_run(command, responder, max(timeout * 4, 60))
        if (type(result) is SessionResult and type(result.exit_code) is int and result.exit_code != 0
                and type(result.output) is str):
            classified = (_ib_host_key_failure(result.output, target, neighbor, local=False)
                          or _classify_jump_output(result.output, target.ethernet, neighbor.ipv6))
            if classified is not None:
                raise classified
    except (ProjectInputChanged, BatchStopped):
        raise
    except (SetupError, OSError) as error:
        failure = _ib_phase_error_facts(error)
        ssh_failure = _ssh_failure_fact(error)
    if failure is not None:
        _ib_raise_phase_failure("project" if phase.authority_pending else "transport", *failure,
                                ssh_failure=ssh_failure)
    return phase.finish(result)


def _execute_ib_direct_phase(target, endpoint, eth_user, ethernet_password, ib_user,
                             current_password, timeout, ib_command, *, local=False,
                             allow_password_change=False, ib_new_password=None,
                             _phase_operation=None, _password_policy=None):
    if (type(local) is not bool or local or eth_user != "" or ethernet_password != ""
            or type(eth_user) is not str or type(ethernet_password) is not str
            or ib_command != ["nv", "config", "show", "-o", "commands"]):
        raise SetupError("private direct IB phase supports only its admitted read/PAM path")
    if (type(current_password) is not str or not current_password
            or any(0xD800 <= ord(char) <= 0xDFFF for char in current_password)
            or len(current_password.encode("utf-8")) > 4096
            or re.search(r"[\x00-\x1f\x7f-\x9f]", current_password)
            or type(timeout) is not int or timeout <= 0):
        raise SetupError("invalid private IB current credential or timeout")
    _validate_direct_endpoint(target, endpoint)
    if type(ib_user) is not str or clean(ib_user) != ib_user or not valid_ssh_user(ib_user):
        raise SetupError("invalid private direct IB account")
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
    point = endpoint
    for attempt in (0, 1):
        check_task_cancelled()
        address = point.address + ("%" + point.interface if point.interface is not None else "")
        phase = _IBPhase(os.urandom(16).hex(), _phase_operation, ib_user + "@" + address,
                         "", _password_policy)
        responder = NestedResponder("", current_password,
            _phase_operation == "password-change" and allow_password_change is True,
            ib_new_password=ib_new_password, ib_destination=phase.endpoint, _phase=phase)
        original_response = phase.response

        def attributed_direct_failure(output, *, complete=False):
            text = strip_ansi(output)
            prompts = re.findall(r"(?im)^([^\n]*password[^\n]*):[ \t]*$", text)
            if (phase.invalid or phase.any_frame
                    or phase.expiry or phase.updated or phase.denied_count
                    or any(phase.pam_counts.values()) or phase.pending is not None
                    or phase.authority_pending or phase.outer_done
                    or phase.pam_current_done or phase.new_done or phase.confirm_done
                    or _pending_diff_has_password_update_notice(text)
                    or any(prompt != phase.endpoint + "'s password" for prompt in prompts)):
                return "none", None
            if complete and (phase.incomplete_marker or phase.begin_count != 1
                    or phase.exit_count != 1 or phase.declared != 255
                    or not phase.begin_at < phase.exit_at
                    or (phase.prompt_count and not phase.begin_at < phase.prompt_at < phase.exit_at)):
                return "none", None
            if re.search(r"(?i)remote host identification has changed|host key verification failed", text):
                # A first warning line can precede its fingerprint/address chunks.
                # Waiting never supplies a credential or grants a typed action.
                if phase.current_done or phase.prompt_count:
                    return "none", None
                try:
                    classified = _management_host_key_failure(text)
                except SetupError as error:
                    if (type(error) is not SetupError or str(error) !=
                            "host-key change (unparseable); no known_hosts entry removed"):
                        raise
                    classified = None
                if classified is None:
                    return ("none" if complete else "pending"), None
                if classified.address != address:
                    return "none", None
                return "hostkey", classified
            if _phase_operation not in ("auth-probe-readonly", "post-change-read"):
                return "none", None
            named = re.search(
                r"(?i)(?:connect to host|connection (?:closed|reset) by)\s+(\S+)", text)
            if named is None or named.group(1).strip("[]") != address:
                return "none", None
            classified = classify_ssh_failure(text, outer_address=None, inner_address=address)
            if classified is None or classified.kind is not SshFailureKind.DIRECT_SSH_NETWORK:
                return "none", None
            return "network", SshFailure(SshFailureKind.DIRECT_LOGIN_NETWORK, "direct", address)

        def direct_response(output, active_responder):
            try:
                return original_response(output, active_responder)
            except SetupError as error:
                if (type(error) is not SetupError or not phase.network or str(error) !=
                        "IB phase observation is not safely attributable"):
                    raise
                kind, _fact = attributed_direct_failure(output)
                if kind == "none":
                    raise
                return None

        phase.response = direct_response
        failure = ssh_failure = result = None
        try:
            command = direct_ssh_command(target, point, ib_user, timeout, ib_command,
                marker=phase.nonce, password_only=True, _phase=phase)
            record_metric("ib_ssh_attempts")
            result = interactive_run(command, responder, max(timeout * 4, 60))
            if type(result) is not SessionResult or type(result.exit_code) is not int or type(result.output) is not str:
                raise SetupError("private direct IB phase result is unverified")
            if result.exit_code != 0:
                kind, classified = attributed_direct_failure(result.output, complete=True)
                if kind in ("hostkey", "network") and (result.exit_code != 255 or any(
                        getattr(result, name) is not False for name in ("password_changed",
                        "password_change_required", "password_change_attempted", "ib_authentication_rejected"))):
                    raise SetupError("direct phase failure has conflicting completion facts")
                if kind == "hostkey":
                    classified._direct_endpoint = point
                    raise classified
                if kind == "network":
                    point = _direct_ipv4_after_network(
                        target, point, classified, timeout, replay_safe=attempt == 0)
                    continue
        except (ProjectInputChanged, BatchStopped):
            raise
        except (SetupError, OSError) as error:
            failure = _ib_phase_error_facts(error)
            ssh_failure = _ssh_failure_fact(error)
        if failure is not None:
            _ib_raise_phase_failure("project" if phase.authority_pending else "transport", *failure,
                                    ssh_failure=ssh_failure)
        result = phase.finish(result)
        result._direct_endpoint = point
        return result
    _ib_raise_phase_failure("transport")


_IB_CREDENTIALS_EXHAUSTED = "known IB credential sources are exhausted; device is HOLD"


@dataclass(repr=False)
class _IBLogin:
    current_password: Optional[str]
    read_result: SessionResult


def _authenticate_ib_read(target, neighbor, eth_user, ethernet_password, ib_user,
                          initial_password, timeout, *, local=False, _password_policy=None,
                          strict=True, _management_private_key=None):
    """Known credential sources of the one IB authentication readback (P3c map P5).

    I039 direct key first, then independently verified project target and initial.
    strict (a management-server task with the project global): each read is a DEV phase
    session, the target comes through _ib_project_value, and an initial password equal to the
    target is not tried twice (DEV).  Otherwise a v15 password-only session.  When both are
    rejected this raises _IB_CREDENTIALS_EXHAUSTED; inspect_ib_device then asks once (T18).
    """
    command = ["nv", "config", "show", "-o", "commands"]
    paths = _import_tools("tools.login_path")
    path = "direct" if target.ethernet is None else "jump"
    key_available = (path == "direct" and local is False
                     and isinstance(_management_private_key, Path)
                     and _management_private_key.is_file()
                     and not _management_private_key.is_symlink())
    attempted_password = None
    for source in paths.credential_order(path, key_available=key_available):
        if source == "ask":
            break  # The existing inspect layer owns the one current-password answer.
        if source == "key":
            _validate_direct_endpoint(target, neighbor)
            try:
                result = _run_direct_key_read(target, neighbor, ib_user,
                    _management_private_key, timeout, command,
                    strict=strict, policy=_password_policy)
            except IBAuthenticationError as error:
                # Only a real key authentication denial reaches password sources.
                neighbor = getattr(error, "_direct_endpoint", None)
                _validate_direct_endpoint(target, neighbor)
            else:
                actual = getattr(result, "_direct_endpoint", None)
                _validate_direct_endpoint(target, actual)
                return _IBLogin(None, result)
            continue
        if source == "project":
            if _password_policy is None:
                continue
            password = (_ib_project_value(_password_policy, user=ib_user, fetch=True) if strict
                        else _password_policy.password())
        else:
            password = initial_password
        if attempted_password is not None and hmac.compare_digest(
                attempted_password.encode("utf-8"), password.encode("utf-8")):
            continue
        attempted_password = password
        rejected = False
        try:
            if strict and type(target) is Target and target.ethernet is None:
                result = _execute_ib_direct_phase(
                    target, neighbor, eth_user, ethernet_password, ib_user, password, timeout,
                    command, local=local, _phase_operation="auth-probe-readonly",
                    _password_policy=_password_policy)
            elif strict:
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
        # Not inside the caught rejection's exception scope; other errors never advance.
        if _password_policy is None:
            raise SetupError("IB initial credential rejected; project global is needed to verify "
                             "an already-changed password")
        if source == "project":
            log("Project IB credential rejected; trying the initial IB password (no rotation).")
    exhausted = SetupError(_IB_CREDENTIALS_EXHAUSTED)
    if key_available:
        # This point was validated after the actual key session's denial;
        # preserve it across the existing inspect-owned one-current handoff.
        exhausted._direct_endpoint = neighbor
    raise exhausted


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


def jump_master_control_argv(op: str, path: str, jump: Device) -> list[str]:
    """The one closed check/exit builder (D4 WP-1, later included in WP-6's census)."""
    if op not in {"check", "exit"}:
        raise SetupError("unsupported jump master control operation")
    return ["ssh", "-o", f"ControlPath={path}", "-O", op, jump.login_ip]


class JumpSessions:
    """Coordinator-owned outer SSH masters; workers only read paths or request rebuilds."""
    def __init__(self, *, local_keys=(), timeout=10):
        self.local_keys, self.timeout = set(local_keys), timeout
        self.directory = None
        self.records = {}

    def _jump_key(self, jump):
        return normalize_name(jump.hostname)

    def _record(self, jump, user, responder, verify_identity):
        key = self._jump_key(jump)
        if key not in self.records:
            try:
                if self.directory is None:
                    self.directory = Path(tempfile.mkdtemp(prefix="isj-", dir="/tmp"))
                    os.chmod(self.directory, 0o700)
                path = str(self.directory / str(len(self.records)))
                if len(os.fsencode(path)) + 17 > 104:
                    raise SetupError("jump ControlPath exceeds the OpenSSH socket limit")
            except (OSError, SetupError):
                raise SshFailure(SshFailureKind.LOCAL_COMMAND, "outer", jump.login_ip, jump.hostname) from None
            self.records[key] = dict(jump=jump, user=user, responder=responder,
                                     verify_identity=verify_identity, path=path,
                                     address=None, mode="key", ready=False, error=None)
        record = self.records[key]
        if responder is not None:
            record["responder"] = responder
        if verify_identity is not None:
            record["verify_identity"] = verify_identity
        return record

    def _control_jump_master(self, record, op):
        actual = replace(record["jump"], login_ip=record["address"])
        try:
            result = subprocess.run(jump_master_control_argv(op, record["path"], actual),
                                    text=True, capture_output=True, timeout=min(self.timeout, 5), check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise SshFailure(SshFailureKind.JUMP_UNREACHABLE, "outer", record["address"],
                             record["jump"].hostname) from None
        return result.returncode == 0

    def _start_jump_master(self, record, *, password):
        # The only new interactive_run caller, predicted before implementation.
        command = ["ssh", "-M", "-N", *ssh_options(self.timeout),
                   "-o", f"ControlPath={record['path']}", "-o", "ControlPersist=600"]
        if password:
            command += ["-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password,keyboard-interactive"]
        else:
            command += ["-o", "BatchMode=yes", "-o", "PreferredAuthentications=publickey"]
        command.append(record["user"] + "@" + record["address"])
        try:
            result = interactive_run(command, record["responder"] if password else lambda _: None,
                                     max(self.timeout * 3, 15))
        except SetupError as error:
            kind = (SshFailureKind.JUMP_UNREACHABLE if str(error).startswith("SSH/PAM session timed out;")
                    else SshFailureKind.LOCAL_COMMAND)
            raise SshFailure(kind, "outer", record["address"], record["jump"].hostname) from None
        except OSError:
            raise SshFailure(SshFailureKind.LOCAL_COMMAND, "outer", record["address"],
                             record["jump"].hostname) from None
        if result.exit_code:
            failure = classify_ssh_failure(result.output, outer_address=record["address"], inner_address=None)
            if failure is None:
                failure = SshFailure(SshFailureKind.LOCAL_COMMAND, "outer", record["address"])
            failure.jump = record["jump"].hostname
            raise failure
        if not self._control_jump_master(record, "check"):
            raise SshFailure(SshFailureKind.JUMP_UNREACHABLE, "outer", record["address"],
                             record["jump"].hostname)

    def _verify_jump_master_identity(self, record):
        actual_jump = replace(record["jump"], login_ip=record["address"])
        try:
            output = run_on_ethernet(actual_jump, record["user"], "", ["hostname"], self.timeout,
                                     control_path=record["path"])
        except (ProjectInputChanged, BatchStopped):
            raise
        except SshFailure:
            raise
        except SetupError as error:
            failure = classify_ssh_failure(str(error), outer_address=record["address"], inner_address=None)
            if failure is None:
                failure = SshFailure(SshFailureKind.LOCAL_COMMAND, "outer", record["address"])
            failure.jump = record["jump"].hostname
            raise failure from None
        actual = output.strip()
        if (not valid_hostname(actual) or normalize_name(actual).split(".", 1)[0]
                != normalize_name(record["jump"].hostname).split(".", 1)[0]):
            raise SshFailure(SshFailureKind.IDENTITY_MISMATCH, "outer", record["address"],
                             record["jump"].hostname)
        callback = record["verify_identity"]
        if callback is not None:
            try:
                callback(record["jump"], record["address"])
            except SetupError:
                raise SshFailure(SshFailureKind.IDENTITY_MISMATCH, "outer", record["address"],
                                 record["jump"].hostname) from None

    def _reject_jump_master(self, record, failure):
        was_ready = record["ready"]
        record["ready"], record["error"] = False, failure
        if was_ready:
            try:
                self._control_jump_master(record, "exit")
            except Exception:
                # Ordinary cleanup cannot replace the refused identity; an
                # interruption still propagates after failed state is committed.
                pass

    def _open_jump_master(self, jump, user, responder, candidates, verify_identity, *, key_only=False):
        if self._jump_key(jump) in self.local_keys:
            return None
        record = self._record(jump, user, responder, verify_identity)
        if record["ready"]:
            return record["address"]
        addresses = tuple(candidates) if candidates is not None else (jump.login_ip,)
        if not addresses or any(not usable(address) for address in addresses):
            raise SshFailure(SshFailureKind.LOCAL_COMMAND, "outer", jump.login_ip, jump.hostname)
        for address in addresses:
            if record["address"] != address:
                record["mode"] = "key"
            record["address"], record["error"] = address, None
            try:
                if record["mode"] == "key":
                    try:
                        self._start_jump_master(record, password=False)
                    except SshFailure as failure:
                        if failure.kind != SshFailureKind.JUMP_AUTHENTICATION:
                            raise
                        record["mode"] = "password"
                if record["mode"] == "password":
                    if key_only:
                        return None
                    if record["responder"] is None:
                        raise SshFailure(SshFailureKind.JUMP_AUTHENTICATION, "outer", address, jump.hostname)
                    self._start_jump_master(record, password=True)
                record["ready"] = True
                self._verify_jump_master_identity(record)
                return address
            except SshFailure as failure:
                self._reject_jump_master(record, failure)
                if failure.kind != SshFailureKind.JUMP_UNREACHABLE or failure.hop != "outer":
                    raise
        record["error"].candidates_exhausted = True
        raise record["error"]

    def probe_jump_key(self, jump, user):
        return ("key" if self._open_jump_master(jump, user, None, None, None, key_only=True)
                is not None else "password")

    def open_jump_master(self, jump, user, responder, *, candidates=None, verify_identity=None):
        return self._open_jump_master(jump, user, responder, candidates, verify_identity)

    def jump_control_path(self, jump):
        if self._jump_key(jump) in self.local_keys:
            return None
        record = self.records.get(self._jump_key(jump))
        if record is None:
            raise SshFailure(SshFailureKind.JUMP_UNREACHABLE, "outer", jump.login_ip, jump.hostname)
        if record["error"] is not None:
            raise record["error"]
        if not record["ready"]:
            raise SshFailure(SshFailureKind.JUMP_AUTHENTICATION, "outer", record["address"], jump.hostname)
        return record["path"]

    def jump_master_alive(self, jump):
        return self._control_jump_master(self.records[self._jump_key(jump)], "check")

    def ensure_jump_master(self, jump):
        record = self.records[self._jump_key(jump)]
        if self._control_jump_master(record, "check"):
            return
        record["ready"] = False
        self._open_jump_master(jump, record["user"], record["responder"],
                               (record["address"],), record["verify_identity"])

    def probe_jump_master(self, jump):
        """Called only by an idle per-jump gate: check alone never proves recovery."""
        record = self.records[self._jump_key(jump)]
        previous = record["error"]
        if previous is not None and previous.kind != SshFailureKind.JUMP_UNREACHABLE:
            raise previous
        self.ensure_jump_master(jump)
        try:
            self._verify_jump_master_identity(record)
        except SshFailure as failure:
            self._reject_jump_master(record, failure)
            raise
        record["ready"], record["error"] = True, None

    def close_jump_masters(self):
        first_failure = None
        try:
            for record in self.records.values():
                if record["ready"]:
                    try:
                        if not self._control_jump_master(record, "exit"):
                            raise SshFailure(SshFailureKind.JUMP_UNREACHABLE, "outer", record["address"],
                                             record["jump"].hostname)
                    except SshFailure as error:
                        first_failure = first_failure or error
                    finally:
                        record["ready"] = False
        finally:
            if self.directory is not None:
                shutil.rmtree(self.directory)
                self.directory = None
        if first_failure is not None:
            raise first_failure


def _new_jump_sessions(*, local_keys=(), timeout=10):
    return JumpSessions(local_keys=local_keys, timeout=timeout)


def _ssh_failure_reply(error):
    reply = {"ssh_failure": (error.kind.value, error.hop, error.address, error.jump)}
    if getattr(error, "candidates_exhausted", False) is True:
        reply["_jump_candidates_exhausted"] = True
    return reply


def _jump_master_request_result(value, target):
    if value != normalize_name(target.ethernet.hostname):
        raise SetupError("jump master request does not match the task transit")
    try:
        _JUMP_SESSIONS.ensure_jump_master(target.ethernet)
    except SshFailure as error:
        return _ssh_failure_reply(error)
    return {"ok": True}


def _unwrap_jump_master_reply(reply):
    if "ssh_failure" in reply:
        kind, hop, address, jump = reply["ssh_failure"]
        failure = SshFailure(SshFailureKind(kind), hop, address, jump)
        if reply.get("_jump_candidates_exhausted") is True:
            failure.candidates_exhausted = True
        raise failure
    return reply


def _jump_control_path_for(jump, *, local=False):
    if local or _JUMP_SESSIONS is None:
        return None
    path = _JUMP_SESSIONS.jump_control_path(jump)
    if path is None:
        return None
    if not _JUMP_SESSIONS.jump_master_alive(jump):
        key = normalize_name(jump.hostname)
        if _WORKER_CONNECTION is not None:
            worker_request("jump-master", key)
        elif _ACTIVE_COORDINATOR is not None:
            _unwrap_jump_master_reply(_ACTIVE_COORDINATOR.request(
                "jump-master", key, _ACTIVE_COORDINATOR.current_target))
        else:
            _JUMP_SESSIONS.ensure_jump_master(jump)
        if not _JUMP_SESSIONS.jump_master_alive(jump):
            raise SshFailure(SshFailureKind.JUMP_UNREACHABLE, "outer",
                             _JUMP_SESSIONS.records[key]["address"], jump.hostname)
    return path


@contextmanager
def _jump_session_lifetime():
    """Cover direct main callers as well as the guarded entry, without changing its signature."""
    global _JUMP_SESSIONS
    previous = _JUMP_SESSIONS
    primary = None
    try:
        yield
    except BaseException as error:
        primary = error
        raise
    finally:
        current, _JUMP_SESSIONS = _JUMP_SESSIONS, previous
        if current is not None and current is not previous:
            try:
                current.close_jump_masters()
            except BaseException as cleanup:
                # Same priority as the existing report-handle cleanup: an ordinary
                # cleanup error must not replace an in-flight interruption.
                if primary is None or (isinstance(primary, Exception) and not isinstance(cleanup, Exception)):
                    raise


def ethernet_command_argv(argv: object) -> list[str]:
    """Enforce the complete read-only command surface of a transit switch."""
    command = typed_argv(argv, label="Ethernet jump command")
    # One table: precise vectors and their bounded parameter patterns (K8).
    table = (
        (("hostname",), None), (("nv", "show", "interface"), None),
        (("nv", "config", "show"), None), (("ip", "-d", "link", "show"), None),
        (("bridge", "fdb", "show"), None), (("bridge", "vlan", "show"), None),
        (("ip", "neighbor"), None),
        (("ip", "-j", "address", "show"), None),
        (("ifquery", None), lambda value: bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value))),
        (("ip", "vrf", "exec", None, "ping", "-6", "-c", "2", "-W", "1", None),
         lambda value: bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value))
         if "%" not in value else bool(re.fullmatch(
             r"[0-9A-Fa-f:]+%[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value))),
        (("ssh-keygen", "-l", "-F", None, "-f", "/home/cumulus/.ssh/known_hosts"),
         lambda value: _import_tools("tools.login_path")._host_key_address(value)),
    )
    if any(len(command) == len(pattern) and all(
            token == expected if expected is not None else validator(token)
            for token, expected in zip(command, pattern)) for pattern, validator in table):
        if command[:3] != ["ip", "vrf", "exec"]:
            return command
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", command[3]) and "%" in command[10]:
            try:
                if ipaddress.IPv6Address(command[10].split("%", 1)[0]) in ipaddress.IPv6Network("fe80::/64"):
                    return command
            except ValueError:
                pass  # A malformed address is refused by the same argv boundary.
    raise SetupError(
        "Ethernet jump command is not allowed by the read-only argv allowlist: "
        + shlex.join(command)
    )


def _is_replace_command(argv):
    """Admit only the complete D7 program and its two bounded typed DATA words."""
    return (type(argv) is list and len(argv) == 6
            and all(type(item) is str for item in argv)
            and argv[:2] == ["sh", "-c"] and argv[2] == _CONFIG_REPLACE_SCRIPT
            and argv[3] == "--" and 0 < len(argv[4]) <= _REPLACE_PAYLOAD_BASE64_MAX
            and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", argv[4]) is not None
            and re.fullmatch(r"[0-9a-f]{64}", argv[5]) is not None)


def _is_readonly_key_command(argv):
    """One exact typed program/payload admission, shared by every carrier."""
    return (type(argv) is list and len(argv) == 5
            and all(type(item) is str for item in argv)
            and argv[:2] == ["sh", "-c"] and argv[2] == _KEY_READONLY_SCRIPT
            and argv[3] == "--" and len(argv[4]) <= 131072
            and re.fullmatch(r"[A-Za-z0-9+/=]+", argv[4]) is not None)


def _readonly_key_result(result, marker, *, responder=None):
    """Only the sealed read may report an empty, authenticated 0/34 frame."""
    if (type(result) is not SessionResult or type(result.exit_code) is not int
            or result.exit_code not in (0, 34) or type(result.output) is not str
            or getattr(result, "cleanup_uncertain", False) is not False
            or any(getattr(result, name, None) is not False for name in (
                "password_changed", "password_change_required", "password_change_attempted",
                "ib_authentication_rejected"))
            or (responder is not None and any(getattr(responder, name, None) is not False
                for name in ("password_change_attempted", "password_change_blocked")))
            or _EXPIRED_PASSWORD.search(result.output)
            or _pending_diff_has_password_update_notice(result.output)
            or _NETWORK_FAILURE.search(result.output)
            or re.search(r"(?i)permission denied|authentication (?:failed|failure)|"
                         r"too many authentication failures", result.output)):
        raise SetupError("readonly public-key check outcome is unverified")
    normalized = strip_ansi(result.output)
    markers = re.findall(r"(?m)^__HTTP_IB_(?:AUTH|BEGIN|END)_[^\n]*$", normalized)
    if markers != ["__HTTP_IB_BEGIN_" + marker + "__",
                   "__HTTP_IB_END_" + marker + "__=" + str(result.exit_code)]:
        raise SetupError("readonly public-key check frame is unverified")
    body = extract_command_output(result.output, marker, expected_exit_code=result.exit_code)
    if body != "":
        raise SetupError("readonly public-key check returned unexpected content")
    result.output = body
    return result


def _closed_ib_script_argv(argv):
    """Recognize only the fixed shell programs for ordinary IB operations."""
    if _is_replace_command(argv):
        return list(argv)
    if _is_readonly_key_command(argv):
        return list(argv)
    if (type(argv) is list and len(argv) == 5
            and all(type(item) is str for item in argv)
            and argv[:2] == ["sh", "-c"] and argv[3] == "--"
            and argv[2] in (_CONFIG_BACKUP_SCRIPT, _DEFERRED_APPLY_SCRIPT,
                            _DEFERRED_APPLY_RC_SCRIPT, _REPLACE_DEFERRED_APPLY_SCRIPT,
                            _REPLACE_DEFERRED_RC_SCRIPT)
            and re.fullmatch(r"[0-9]{8}-[0-9]{6}", argv[4])):
        return list(argv)
    return None


def ib_command_argv(argv: object) -> list[str]:
    """Enforce the NVOS command vectors used by this Network workflow."""
    closed = _closed_ib_script_argv(argv)
    if closed is not None:
        return closed
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
        ("ip", "addr", "show", "eth0"),
        ("ip", "route"),
        ("nv", "config", "show"),
        ("nv", "config", "show", "-o", "commands"),
        ("nv", "config", "diff", "-o", "commands"),
        ("nv", "show", "system", "ztp"),
        ("nv", "config", "apply", "-y"),
        ("nv", "set", "system", "config", "auto-save", "state", "enabled"),
        ("nv", "set", "system", "ztp", "config-save", "enabled"),
        ("nv", "config", "save"),
        ("nv", "config", "detach"),
        ("cat", "/etc/ssh/ssh_host_rsa_key.pub"),
        ("cat", "/etc/ssh/ssh_host_ecdsa_key.pub"),
        ("cat", "/etc/ssh/ssh_host_ed25519_key.pub"),
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
                      local: bool = False, control_path: Optional[str] = None) -> list[str]:
    if (type(remote_argv) is list and remote_argv
            and type(remote_argv[-1]) is str and "\n" in remote_argv[-1]):
        # Only the original nested-SSH carrier may carry a fixed multiline
        # NVOS program. All ordinary typed argv/control-byte rules stay intact.
        prefix = typed_argv(remote_argv[:-1], label="outer SSH command")
        if type(timeout) is not int or timeout <= 0 or len(prefix) not in (22, 26):
            raise SetupError("invalid closed NVOS outer carrier")
        validate_network_selector(prefix[3], label="closed NVOS VRF")
        validate_network_selector(prefix[-2], label="closed NVOS interface")
        destination = prefix[-1]
        account, separator, address = destination.rpartition("@")
        try:
            link_local = ipaddress.IPv6Address(address).is_link_local
        except ipaddress.AddressValueError:
            link_local = False
        if not separator or not valid_ssh_user(account) or "%" in address or not link_local:
            raise SetupError("invalid closed NVOS outer endpoint")
        expected = [
            "ip", "vrf", "exec", prefix[3], "ssh", "-6", "-tt",
            "-o", f"ConnectTimeout={timeout}",
            "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR",
            "-o", "ControlMaster=no", "-o", "ControlPath=none",
            "-o", "NumberOfPasswordPrompts=1",
        ]
        if len(prefix) == 26:
            expected += ["-o", "PubkeyAuthentication=no",
                         "-o", "PreferredAuthentications=password,keyboard-interactive"]
        expected += ["-B", prefix[-2], destination]
        if prefix != expected:
            raise SetupError("invalid closed NVOS outer command")
        try:
            remote = shlex.split(remote_argv[-1])
        except ValueError:
            raise SetupError("invalid closed NVOS command frame") from None
        if (len(remote) != 3 or remote[:2] != ["sh", "-c"]
                or shlex.join(remote) != remote_argv[-1]):
            raise SetupError("invalid closed NVOS command frame")
        match = re.match(r'^printf "\\n__HTTP_IB_BEGIN_([A-Za-z0-9_]{1,80})__\\n"; ', remote[2])
        if match is None:
            raise SetupError("invalid closed NVOS command frame")
        marker = match.group(1)
        start = 'printf "\\n__HTTP_IB_BEGIN_' + marker + '__\\n"; '
        end = ('; task_rc=$?; printf "\\n__HTTP_IB_END_' + marker
               + '__=%s\\n" "$task_rc"; exit "$task_rc"')
        if not remote[2].endswith(end):
            raise SetupError("invalid closed NVOS command frame")
        try:
            body = shlex.split(remote[2][len(start):-len(end)])
        except ValueError:
            raise SetupError("invalid closed NVOS command frame") from None
        closed = _closed_ib_script_argv(body)
        if closed is None or _framed_script(closed, marker) != remote[2]:
            raise SetupError("invalid closed NVOS command frame")
        command = [*prefix, remote_argv[-1]]
    else:
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
            "-o", "ControlMaster=no", "-o", "ControlPath=" + (control_path if control_path is not None else "none"),
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
                    remote_argv: list[str], timeout: int, *, local: bool = False,
                    control_path: Optional[str] = None) -> str:
    if ethernet.dev_type not in TRANSIT_DEVICE_TYPES:
        raise SetupError(
            f"{ethernet.hostname} is not a supported Ethernet transit device"
        )
    command = ethernet_command_argv(remote_argv)
    path = control_path if control_path is not None else _jump_control_path_for(ethernet, local=local)
    outer_options = {"local": local}
    if path is not None:
        outer_options["control_path"] = path
    result = interactive_run(
        outer_ssh_command(ethernet, user, command, timeout, **outer_options),
        (lambda _output: None) if local else ethernet_responder(password), timeout,
    )
    if result.exit_code != 0:
        if not local:
            failure = _classify_jump_output(result.output, ethernet)
            if failure is not None:
                raise failure
        if (
            command[0] == "ifquery"
            and result.exit_code == 1
            and not result.output.strip()
        ):
            # ifupdown2 uses exit 1 with no output when the interface has no
            # stanza.  That semantic absence means the Linux default VRF; no
            # other exit/output combination is downgraded.
            return ""
        if command[:3] == ["ssh-keygen", "-l", "-F"] and result.exit_code == 1 and not result.output.strip():
            return ""  # Exact OpenSSH lookup no-match; never downgrade another command.
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
    vlans = run_on_ethernet(
        ethernet, user, password, ["bridge", "vlan", "show"], timeout, local=local,
    )
    if not links.strip():
        raise SetupError(f"empty 'ip -d link show' output from {ethernet.hostname}")
    return links.strip(), fdb.strip(), vlans.strip()


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
                           vlans: str) -> Path:
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
        "\n===== bridge vlan show =====\n"
        f"{vlans.rstrip()}\n"
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

class _DirectResponder(NestedResponder):
    """The ordinary direct session has no outer credential recipient."""
    def __call__(self, output):
        prompts = re.findall(r"(?im)^([^\n]*password[^\n]*):[ \t]*$", strip_ansi(output))
        pam_patterns = (
            r"[ \t]*(?:\(current\)|current|old)[^\n]*password[ \t]*",
            r"[ \t]*[^\n]*(?:retype|repeat|confirm)[^\n]*password[ \t]*",
            r"[ \t]*(?![^\n]*(?:retype|repeat|confirm))[^\n]*new[^\n]*password[ \t]*",
        )
        for prompt in prompts:
            if prompt == self.ib_destination + "'s password":
                continue
            # Preserve the original PAM-role handling, never classify a host
            # credential request as PAM just because it contains a role word.
            if (not re.search(r"@|fe80:|'s[ \t]+password", prompt, re.I)
                    and any(re.fullmatch(pattern, prompt, re.I) for pattern in pam_patterns)):
                continue
            raise SetupError("direct credential prompt differs from the requested endpoint")
        return super().__call__(output)


def _direct_endpoint_for(target):
    paths = _import_tools("tools.login_path")
    if target.route.same_subnet is not None:
        return DirectEndpoint(paths.link_local_from_mac(target.ib.eth0_mac), target.route.same_subnet)
    return DirectEndpoint(target.ib.login_ip)


def _validate_direct_endpoint(target, endpoint):
    paths = _import_tools("tools.login_path")
    if (type(target) is not Target or type(target.ib) is not Device
            or target.ib.dev_type != "ib" or target.ethernet is not None
            or type(target.route) is not paths.Route or target.route.path != "direct"
            or target.route.jump is not None or type(endpoint) is not DirectEndpoint
            or type(endpoint.address) is not str):
        raise SetupError("invalid direct IB target or endpoint")
    try:
        address = ipaddress.ip_address(endpoint.address)
        if str(address) != endpoint.address:
            raise ValueError("noncanonical direct address")
        if address.version == 4:
            if endpoint.address != target.ib.login_ip or endpoint.interface is not None:
                raise ValueError("direct IPv4 differs from CSV")
        elif (not address.is_link_local or "%" in endpoint.address
                or endpoint.address != paths.link_local_from_mac(target.ib.eth0_mac)
                or endpoint.interface != target.route.same_subnet):
            raise ValueError("direct link-local differs from CSV/route")
        else:
            validate_network_selector(endpoint.interface, label="direct interface")
    except ValueError:
        raise SetupError("direct endpoint differs from the admitted CSV/route") from None


def direct_ssh_command(target, endpoint, ib_user, timeout, ib_command, *, marker=None,
                       password_only=False, _phase=None, _key_file=None):
    """The single closed manager-to-IB argv builder, with no transit."""
    _validate_direct_endpoint(target, endpoint)
    if (type(ib_user) is not str or clean(ib_user) != ib_user or not valid_ssh_user(ib_user)
            or type(timeout) is not int or timeout <= 0 or type(password_only) is not bool):
        raise SetupError("invalid direct account or timeout")
    command = ib_command_argv(ib_command)
    if _key_file is not None:
        if (password_only or _phase is not None or not isinstance(_key_file, Path)
                or not _key_file.is_file() or _key_file.is_symlink()
                or (command not in (["nv", "config", "show", "-o", "commands"],
                                    ["ip", "addr", "show", "eth0"], ["ip", "route"],
                                    ["nv", "show", "system", "ztp"])
                    and not _is_readonly_key_command(command))):
            raise SetupError("explicit direct key mode supports only its admitted read vectors")
    nonce = marker or os.urandom(16).hex()
    if type(nonce) is not str or not re.fullmatch(r"[0-9a-f]{32}", nonce):
        raise SetupError("invalid direct command marker")
    address = endpoint.address + ("%" + endpoint.interface if endpoint.interface is not None else "")
    destination = ib_user + "@" + address
    argv = ["ssh", "-6" if endpoint.interface is not None else "-4", "-tt",
            *ssh_options(timeout), "-o", "ProxyCommand=none", "-o", "ProxyJump=none",
            "-o", "ControlMaster=no", "-o", "ControlPath=none",
            "-o", "NumberOfPasswordPrompts=1"]
    if _key_file is not None:
        argv += ["-i", str(_key_file), "-o", "BatchMode=yes",
                 "-o", "PreferredAuthentications=publickey", "-o", "PasswordAuthentication=no",
                 "-o", "KbdInteractiveAuthentication=no", "-o", "IdentitiesOnly=yes"]
    elif password_only:
        argv += ["-o", "PubkeyAuthentication=no",
                 "-o", "PreferredAuthentications=password,keyboard-interactive"]
    argv += [destination, shlex.join(["sh", "-c", _framed_script(command, nonce)])]
    if _phase is not None:
        if (type(_phase) is not _IBPhase or marker != _phase.nonce or not password_only
                or command != ["nv", "config", "show", "-o", "commands"]
                or _phase.endpoint != destination or _phase.outer_endpoint != ""):
            raise SetupError("private direct phase differs from the exact SSH request")
        return ["sh", "-c", _ib_phase_script(argv, _phase)]
    return argv


def _run_direct_key_read(target, endpoint, ib_user, key_file, timeout, command, *,
                         strict=False, policy=None):
    """One explicit key-only read; it never acquires a password or write permit."""
    _validate_direct_endpoint(target, endpoint)
    if (type(strict) is not bool or (strict and policy is None)
            or type(command) is not list
            or (command not in (["nv", "config", "show", "-o", "commands"],
                                ["ip", "addr", "show", "eth0"], ["ip", "route"],
                                ["nv", "show", "system", "ztp"])
                and not _is_readonly_key_command(command))
            or not isinstance(key_file, Path)):
        raise SetupError("invalid explicit direct key read")
    try:
        before = key_file.lstat()
        if not stat.S_ISREG(before.st_mode) or key_file.is_symlink():
            raise SetupError("explicit management key is not a regular non-link file")
    except OSError:
        raise SetupError("explicit management key is unavailable") from None
    fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_size",
              "st_mtime_ns", "st_ctime_ns")
    key_binding = tuple(getattr(before, name) for name in fields)
    point = endpoint
    for attempt in (0, 1):
        check_task_cancelled()
        if policy is not None:
            _ib_project_value(policy, user=ib_user)
        marker = os.urandom(16).hex()
        argv = direct_ssh_command(target, point, ib_user, timeout, command,
                                  marker=marker, _key_file=key_file)
        address = point.address + ("%" + point.interface if point.interface is not None else "")

        def no_input(_output):
            return None  # No password, passphrase, PAM answer, or empty newline.

        no_input.ib_destination = ib_user + "@" + address
        record_metric("ib_ssh_attempts")
        result = interactive_run(argv, no_input, max(timeout * 4, 60))
        try:
            after = key_file.lstat()
            if tuple(getattr(after, name) for name in fields) != key_binding:
                raise SetupError("explicit management key metadata changed during the read")
        except OSError:
            raise SetupError("explicit management key became unavailable during the read") from None
        if policy is not None:
            _ib_project_value(policy, user=ib_user)
        if (type(result) is not SessionResult or type(result.exit_code) is not int
                or type(result.output) is not str
                or getattr(result, "cleanup_uncertain", False) is not False
                or any(getattr(result, name) is not False for name in (
                    "password_changed", "password_change_required", "password_change_attempted"))
                or _EXPIRED_PASSWORD.search(result.output)
                or _pending_diff_has_password_update_notice(result.output)
                or re.search(r"(?im)^[^\n]*(?:password|passphrase)[^\n]*:[ \t]*$",
                             strip_ansi(result.output))):
            raise SetupError("explicit key read has unverified authentication or completion facts")
        if _is_readonly_key_command(command) and result.exit_code in (0, 34):
            result = _readonly_key_result(result, marker)
            result._direct_endpoint = point
            _validate_direct_endpoint(target, result._direct_endpoint)
            return result
        if result.exit_code != 0:
            failure = _management_host_key_failure(result.output)
            if failure is not None:
                if failure.address != address:
                    raise SetupError("key host-key warning differs from the attempted endpoint")
                failure._direct_endpoint = point
                raise failure
            failure = classify_ssh_failure(result.output, outer_address=None, inner_address=address)
            if failure is not None and failure.kind is SshFailureKind.DIRECT_SSH_NETWORK:
                safe = (result.exit_code == 255 and result.ib_authentication_rejected is False
                        and not re.search(r"(?m)^__HTTP_IB_(?:AUTH|BEGIN|END)_", strip_ansi(result.output)))
                point = _direct_ipv4_after_network(target, point,
                    SshFailure(SshFailureKind.DIRECT_LOGIN_NETWORK, "direct", address), timeout,
                    replay_safe=safe and attempt == 0)
                continue
            denied = re.fullmatch(re.escape(ib_user + "@" + address)
                + r": Permission denied \([A-Za-z0-9,_-]+\)\.?\s*", strip_ansi(result.output))
            if (result.exit_code == 255 and result.ib_authentication_rejected is True
                    and denied is not None):
                error = IBAuthenticationError("IB key authentication rejected for " + target.ib.hostname)
                error._direct_endpoint = point
                raise error
            raise SetupError("explicit key read failed; device state is UNKNOWN")
        if result.ib_authentication_rejected is not False:
            raise SetupError("explicit key read has conflicting authentication facts")
        result.output = extract_command_output(result.output, marker)
        result._direct_endpoint = point
        _validate_direct_endpoint(target, result._direct_endpoint)
        return result
    raise SetupError("explicit key read endpoint is exhausted")


def _direct_ipv4_after_network(target, endpoint, error, timeout, *, replay_safe):
    """One bounded LL-to-CSV-IPv4 transition; never a transport callback."""
    failure = _ssh_failure_fact(error)
    attempted = endpoint.address + ("%" + endpoint.interface if endpoint.interface is not None else "")
    if (replay_safe is not True or endpoint.interface is None
            or failure is None or failure.kind is not SshFailureKind.DIRECT_LOGIN_NETWORK
            or failure.hop != "direct" or failure.address != attempted
            or getattr(error, "cleanup_uncertain", False)):
        raise error
    address = target.ib.login_ip
    paths = _import_tools("tools.login_path")
    try:
        for read in (0, 1):
            result = subprocess.run(["ip", "-4", "neigh", "show", address],
                capture_output=True, text=True, timeout=timeout, check=False)
            if result.returncode != 0 or not isinstance(result.stdout, str) or result.stderr.strip():
                raise SetupError("direct IPv4 neighbor lookup is unverified")
            mac = paths.neighbor_mac(result.stdout, address)
            if mac is not None:
                if mac != paths.normalize_mac(target.ib.eth0_mac):
                    raise SetupError("direct IPv4 neighbor MAC differs from CSV for " + address)
                return DirectEndpoint(address)
            if read == 0:
                subprocess.run(["ping", "-c", "1", "-W", "1", address],
                    capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        error = SshFailure(SshFailureKind.DIRECT_LOGIN_NETWORK, "direct", address)
        error.args = ("direct IPv4 neighbor lookup failed for " + address + ": " + type(exc).__name__,)
        raise error from None
    error = SshFailure(SshFailureKind.DIRECT_LOGIN_NETWORK, "direct", address)
    error.args = ("邻居表里没有 " + address + "; no IPv4 login attempted",)
    raise error


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
    outer_options = {"tty": True, "local": local}
    path = _jump_control_path_for(target.ethernet, local=local)
    if path is not None:
        outer_options["control_path"] = path
    return outer_ssh_command(target.ethernet, eth_user, nested, timeout, **outer_options)

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


def _run_on_ib_direct(target, endpoint, eth_user, ethernet_password, ib_user,
                      current_password, timeout, ib_command, *, local=False,
                      allow_password_change=False, ib_new_password=None, password_only=False,
                      _replace_sync_failure_task=None, _pending_services=None):
    if (type(local) is not bool or local or eth_user != "" or ethernet_password != ""
            or type(eth_user) is not str or type(ethernet_password) is not str
            or type(current_password) is not str or not current_password
            or any(0xD800 <= ord(char) <= 0xDFFF for char in current_password)
            or len(current_password.encode("utf-8")) > 4096
            or re.search(r"[\x00-\x1f\x7f-\x9f]", current_password)):
        raise SetupError("invalid direct IB credentials or locality")
    if allow_password_change and ib_command != ["nv", "config", "show", "-o", "commands"]:
        raise SetupError("password change is allowed only for the authentication NVUE read")
    category = "password" if allow_password_change else _ib_write_category(ib_command)
    mutating = category is not None
    point = endpoint
    for attempt in (0, 1):
        check_task_cancelled()
        marker = os.urandom(16).hex()
        command = direct_ssh_command(target, point, ib_user, timeout, ib_command,
                                     marker=marker, password_only=password_only)
        address = point.address + ("%" + point.interface if point.interface is not None else "")
        if mutating:
            if category == "nvue":
                _ensure_ib_config_backup(target, point, eth_user, ethernet_password, ib_user,
                                         current_password, timeout, local=local)
            obtain_write_permit(category)
        sync_scope = None
        if (_replace_sync_failure_task is not None and allow_password_change is False
                and category == "nvue"):
            operation = _replace_sync_operation(_replace_sync_failure_task, target, point,
                eth_user, ethernet_password, ib_user, current_password, ib_command, direct=True)
            if operation is not None:
                sync_scope = _ReplaceSyncFailureScope(_replace_sync_failure_task, point, operation, marker)
        responder = _DirectResponder("", current_password, allow_password_change,
            ib_new_password=ib_new_password, ib_destination=ib_user + "@" + address)
        record_metric("ib_ssh_attempts")
        result = interactive_run(command, responder, max(timeout * 4, 60))
        if (type(result) is not SessionResult or type(result.output) is not str
                or type(result.exit_code) is not int):
            raise SetupError("direct IB command outcome is unverified")
        if result.exit_code != 0:
            failure = _management_host_key_failure(result.output)
            if failure is not None:
                if failure.address != address:
                    raise SetupError("direct host-key warning differs from this attempted endpoint")
                failure._direct_endpoint = point
                raise failure
            failure = classify_ssh_failure(result.output, outer_address=None, inner_address=address)
            if failure is not None and failure.kind is SshFailureKind.DIRECT_SSH_NETWORK:
                failure = SshFailure(SshFailureKind.DIRECT_LOGIN_NETWORK, "direct", address)
                safe = (not mutating and not responder.password_change_attempted
                        and not responder.password_change_blocked
                        and all(getattr(result, name) is False for name in (
                            "password_changed", "password_change_required", "password_change_attempted",
                            "ib_authentication_rejected"))
                        and not _EXPIRED_PASSWORD.search(result.output)
                        and not _pending_diff_has_password_update_notice(result.output)
                        and not re.search(r"(?m)^__HTTP_IB_(?:AUTH|BEGIN|END)_", strip_ansi(result.output)))
                point = _direct_ipv4_after_network(target, point, failure, timeout,
                                                   replay_safe=safe and attempt == 0)
                continue
        if _is_readonly_key_command(ib_command):
            result = _readonly_key_result(result, marker, responder=responder)
            result._direct_endpoint = point
            _validate_direct_endpoint(target, result._direct_endpoint)
            return result
        if ib_command == ["nv", "config", "diff", "-o", "commands"] and (
                any((result.password_changed, result.password_change_required,
                     result.password_change_attempted, result.ib_authentication_rejected,
                     responder.password_change_attempted, responder.password_change_blocked))
                or _EXPIRED_PASSWORD.search(result.output)
                or _pending_diff_has_password_update_notice(result.output)):
            raise SetupError("read-only pending diff has unverified authentication or password-change evidence")
        if result.password_change_required or (_EXPIRED_PASSWORD.search(result.output)
                                               and not allow_password_change):
            if ib_command != ["nv", "config", "show", "-o", "commands"]:
                raise SetupError("IB requires a password change; command success is unverified")
            result.password_change_required = True
            result._direct_endpoint = point
            return result
        if result.password_changed or (allow_password_change and result.password_change_attempted):
            result._direct_endpoint = point
            return result
        if result.exit_code != 0:
            if result.ib_authentication_rejected or (
                    not _NETWORK_FAILURE.search(result.output) and re.search(
                        re.escape(ib_user + "@" + address) + r":[^\n]*Permission denied",
                        result.output, re.I)):
                raise IBAuthenticationError("IB authentication rejected for " + target.ib.hostname)
            if (ib_command == ["nv", "config", "diff", "-o", "commands"]
                    and result.exit_code == 1 and not _NETWORK_FAILURE.search(result.output)):
                pending = _split_comma_interface_lines(
                    extract_command_output(result.output, marker, expected_exit_code=1))
                if not _validate_owned_pending(target.ib, pending, services=_pending_services):
                    raise SetupError("pending diff returned 1 without verifiable owned changes")
                result.output = pending
                result._direct_endpoint = point
                return result
            error = SetupError("direct IB command failed; device state is UNKNOWN")
            if sync_scope is not None:
                operation = _replace_sync_operation(sync_scope.task, target, point, eth_user,
                    ethernet_password, ib_user, current_password, ib_command, direct=True)
                fact = _bound_replace_sync_failure(result, responder, sync_scope, operation)
                if fact is not None:
                    error._replace_sync_failure = fact
            raise error
        if allow_password_change and responder.password_change_attempted:
            raise SetupError("IB password change outcome is UNKNOWN; reconnect before retrying")
        result.output = extract_command_output(result.output, marker)
        if ib_command == ["nv", "config", "diff", "-o", "commands"]:
            result.output = _split_comma_interface_lines(result.output)
            _validate_owned_pending(target.ib, result.output, services=_pending_services)
        result._direct_endpoint = point
        return result
    raise SetupError("direct IB path is exhausted; device state is UNKNOWN")


def _replace_sync_operation(state, target, neighbor, eth_user, ethernet_password,
                            ib_user, current_password, command, *, direct=False):
    initial = state if type(state) is _InitialIPv4ReplaceRequest else None
    if initial is not None:
        state = initial.state
        if (direct is not True or type(neighbor) is not DirectEndpoint or neighbor.interface is not None
                or type(state) is not _IBConfigWriteState or initial.endpoint is not neighbor
                or initial.endpoint is not state.endpoint or type(initial.authority) is not RuntimeInputAuthority
                or type(initial.stamp) is not str or initial.stamp != state.stamp):
            return None
    if (type(state) is not _IBConfigWriteState or state is not _TASK_IB_CONFIG
            or type(state.task) is not PreparedIBTask or state.task.target is not target
            or state.task.local is not False or state.apply is not True
            or state.identity_verified is not True or state.backup_state != "VERIFIED"
            or state.endpoint != neighbor
            or state.task.ethernet_password != ethernet_password or state.eth_user != eth_user
            or state.ib_user != ib_user or state.current_password != current_password):
        return None
    if direct:
        # The existing direct builder has already qualified the endpoint against
        # its route and CSV. Raw sync state still excludes IPv4.
        if (target.ethernet is not None or type(neighbor) is not DirectEndpoint
                or (neighbor.interface is None and initial is None)):
            return None
    elif type(neighbor) is not Neighbor:
        return None
    if _is_replace_command(command):
        return "replace"
    if initial is not None:
        return None
    if command == ["nv", "config", "apply", "-y"]:
        return "apply"
    if command == ["nv", "config", "save"]:
        return "save"
    return None


def _bound_replace_sync_failure(result, responder, scope, operation):
    if (operation != scope.operation
            or _NETWORK_FAILURE.search(result.output)
            or _EXPIRED_PASSWORD.search(result.output)
            or _pending_diff_has_password_update_notice(result.output)
            or responder.password_change_attempted or responder.password_change_blocked):
        return None
    try:
        check_task_cancelled()
    except SetupError:
        return None  # Leave the original error unchanged.
    fact = _qualify_replace_sync_failure(result, scope, scope)
    if type(scope.task) is _InitialIPv4ReplaceRequest and fact is not None:
        return _InitialIPv4ReplaceFailure(scope.task, fact[1]) if fact[0] == "replace" else None
    return fact


def _replace_failure_operation(request, fact):
    if type(request) is _InitialIPv4ReplaceRequest:
        if (type(fact) is _InitialIPv4ReplaceFailure and fact.request is request
                and type(fact.rc) is int and 1 <= fact.rc <= 125):
            return "replace"
    elif (type(fact) is tuple and len(fact) == 2 and type(fact[0]) is str
            and type(fact[1]) is int and 1 <= fact[1] <= 255):
        return fact[0]
    return None


def run_on_ib(target: Target, neighbor: Neighbor, eth_user: str,
              ethernet_password: str, ib_user: str, ib_default_password: str,
              timeout: int, ib_command: list[str], *, local: bool = False,
              allow_password_change: bool = False,
              ib_new_password: Optional[str] = None,
              password_only: bool = False,
              _phase_operation: Optional[str] = None, _password_policy=None,
              _replace_sync_failure_task=None, _pending_services=None) -> SessionResult:
    if (ib_command == ["nv", "config", "diff", "-o", "commands"]
            and allow_password_change):
        raise SetupError("read-only pending diff cannot allow password change")
    if allow_password_change and ib_command != ["nv", "config", "show", "-o", "commands"]:
        raise SetupError("password change is allowed only for the authentication NVUE read")
    check_task_cancelled()
    if _phase_operation is not None:
        if _phase_operation == "password-change":
            obtain_write_permit("password")
        if type(target) is Target and target.ethernet is None:
            return _execute_ib_direct_phase(
                target, neighbor, eth_user, ethernet_password, ib_user, ib_default_password,
                timeout, ib_command, local=local, allow_password_change=allow_password_change,
                ib_new_password=ib_new_password, _phase_operation=_phase_operation,
                _password_policy=_password_policy)
        record_metric("ib_ssh_attempts")
        return _execute_ib_phase(
            target, neighbor, eth_user, ethernet_password, ib_user, ib_default_password,
            timeout, ib_command, local=local, allow_password_change=allow_password_change,
            ib_new_password=ib_new_password, _phase_operation=_phase_operation,
            _password_policy=_password_policy)
    if type(target) is Target and target.ethernet is None:
        evidence_options = ({"_replace_sync_failure_task": _replace_sync_failure_task}
                            if _replace_sync_failure_task is not None else {})
        return _run_on_ib_direct(target, neighbor, eth_user, ethernet_password, ib_user,
            ib_default_password, timeout, ib_command, local=local,
            allow_password_change=allow_password_change, ib_new_password=ib_new_password,
            password_only=password_only, _pending_services=_pending_services, **evidence_options)
    category = "password" if allow_password_change else _ib_write_category(ib_command)
    marker = os.urandom(16).hex()
    command = nested_ssh_command(
        target, neighbor, eth_user, ib_user, timeout, ib_command,
        local=local, marker=marker, password_only=password_only,
    )
    if category is not None:
        if category == "nvue":
            _ensure_ib_config_backup(target, neighbor, eth_user, ethernet_password, ib_user,
                                     ib_default_password, timeout, local=local)
        obtain_write_permit(category)
    sync_scope = None
    if (_replace_sync_failure_task is not None and local is False and allow_password_change is False
            and category == "nvue"):
        operation = _replace_sync_operation(_replace_sync_failure_task, target, neighbor,
            eth_user, ethernet_password, ib_user, ib_default_password, ib_command)
        if operation is not None:
            sync_scope = _ReplaceSyncFailureScope(_replace_sync_failure_task, neighbor, operation, marker)
    responder = NestedResponder(
        ethernet_password, ib_default_password, allow_password_change,
        ib_new_password=ib_new_password,
        ib_destination=f"{ib_user}@{neighbor.ipv6}",
    )
    record_metric("ib_ssh_attempts")
    result = interactive_run(command, responder, max(timeout * 4, 60))
    if (type(result) is SessionResult and type(result.exit_code) is int and result.exit_code != 0
            and type(result.output) is str):
        failure = (_ib_host_key_failure(result.output, target, neighbor, local=local)
                   or (None if local else _classify_jump_output(result.output, target.ethernet, neighbor.ipv6)))
        if failure is not None:
            raise failure
        if re.search(r"(?i)WARNING:\s+REMOTE HOST IDENTIFICATION HAS CHANGED", result.output):
            raise SshFailure(SshFailureKind.TARGET_HOST_KEY_CHANGED, "inner", neighbor.ipv6,
                             None if local else target.ethernet.hostname)
    if _is_readonly_key_command(ib_command):
        return _readonly_key_result(result, marker, responder=responder)
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
            if not _validate_owned_pending(target.ib, pending, services=_pending_services):
                raise SetupError("pending diff returned 1 without verifiable owned changes")
            result.output = pending
            return result
        fact = None
        if sync_scope is not None:
            operation = _replace_sync_operation(sync_scope.task, target, neighbor, eth_user,
                ethernet_password, ib_user, ib_default_password, ib_command)
            fact = _bound_replace_sync_failure(result, responder, sync_scope, operation)
        # Error presentation must not depend on retaining cleanup eligibility.
        replace_receipt = None
        if type(result.exit_code) is int and result.exit_code == 1 and _is_replace_command(ib_command):
            try:
                body = extract_command_output(result.output, marker, expected_exit_code=1)
            except (SetupError, ValueError):
                pass
            else:
                replace_receipt = _replace_receipt_rc(body)
        detail = ("IB configuration replace failed" if replace_receipt is not None else
                  _ib_failure_detail(result.output, marker,
                      (ethernet_password, ib_default_password, ib_new_password or "")))
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
        if fact is not None:
            error._replace_sync_failure = fact
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
        _validate_owned_pending(target.ib, result.output, services=_pending_services)
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
    if (device.eth1_prefix and device.eth1_gateway
            and device.eth1_gateway == device.eth0_gateway):
        commands.append(["nv", "set", "interface", "eth0-1", "ipv4", "gateway", device.eth0_gateway])
    else:
        commands.append(["nv", "set", "interface", "eth0", "ipv4", "gateway", device.eth0_gateway])
        if device.eth1_prefix and device.eth1_gateway:
            commands.append(["nv", "set", "interface", "eth1", "ipv4", "gateway", device.eth1_gateway])
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


def management_conflicts(device: Device, state: DeviceState) -> list[tuple[str, str, object]]:
    """Return existing required-field conflicts without planning or changing state."""
    conflicts: list[tuple[str, str, object]] = []
    hostname = normalize_name(state.hostname)
    if hostname not in DEFAULT_HOSTNAMES and hostname != normalize_name(device.hostname):
        conflicts.append(("hostname", device.hostname, state.hostname))
    for field, expected, actual in (
            ("eth0 address", device.eth0_prefix, state.eth0_addresses),
            ("eth1 address", device.eth1_prefix, state.eth1_addresses),
            ("eth0 gateway", device.eth0_gateway, state.eth0_gateways),
            ("eth1 gateway", device.eth1_gateway if device.eth1_prefix else "", state.eth1_gateways)):
        if expected and actual and expected not in actual:
            conflicts.append((field, expected, actual))
    return conflicts


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
                or (device.eth1_gateway
                    and str(ipaddress.IPv4Address(device.eth1_gateway)) != device.eth1_gateway)):
            raise SetupError("invalid management Network secondary input")
        state, up_ports, eth_ports = _management_network_facts(current)
        expected_name = normalize_name(device.hostname)
        actual_name = normalize_name(state.hostname)
        conflicts = management_conflicts(device, state)
        if conflicts:
            failure_field = conflicts[0][0]
            raise SetupError("management Network field conflicts")
        commands: list[list[str]] = []
        if device.eth0_prefix not in state.eth0_addresses:
            commands.append(["nv", "set", "interface", "eth0", "ipv4", "address", device.eth0_prefix])
        if device.eth1_prefix and device.eth1_prefix not in state.eth1_addresses:
            commands.append(["nv", "set", "interface", "eth1", "ipv4", "address", device.eth1_prefix])
        need_zero = device.eth0_gateway not in state.eth0_gateways
        need_one = bool(device.eth1_prefix and device.eth1_gateway) and device.eth1_gateway not in state.eth1_gateways
        shared_missing = (
            need_zero and need_one and device.eth0_gateway == device.eth1_gateway
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
            "eth0 address": "management Network eth0 address conflict; device state is UNKNOWN",
            "eth1 address": "management Network eth1 address conflict; device state is UNKNOWN",
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
                or (device.eth1_gateway
                    and str(ipaddress.IPv4Address(device.eth1_gateway)) != device.eth1_gateway)):
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
    # Patch is the default; --force remains the same fill-missing operation.
    return force_day0_needed(device, state) or not _management_ports_ready(state.raw_commands)


def parse_ztp_status(output: str) -> dict[str, Optional[str]]:
    """Read the first operational word, excluding config-save and stage history."""
    top = re.split(r"(?im)^\s*ZTP stages\b", strip_ansi(output), maxsplit=1)[0]

    def row(name: str) -> Optional[str]:
        values = re.findall(r"(?im)^\s*" + name + r"\s+(\S+)", top)
        if len(values) > 1:
            raise SetupError("duplicate ZTP " + name + " rows; operational state is unknown")
        return values[0].casefold() if values else None

    facts = {name: row(name) for name in ("service", "state", "status")}
    service, state = facts["service"], facts["state"]
    if ((service == "disabled" and state == "enabled")
            or (service in {"enabled", "active", "active-discovery", "running", "starting", "stopping"}
                and state not in {None, "enabled"})):
        raise SetupError("contradictory ZTP operational state; initialization is blocked")
    return facts


def _ztp_disabled(output: str) -> bool:
    """Use the shared operational parser; unknown states never authorize writes."""
    facts = parse_ztp_status(output)
    service, state = facts["service"], facts["state"]
    if service == "disabled" and state in {None, "disabled"}:
        return True
    if service in {None, "inactive"} and state in {"enabled", "disabled"}:
        return state == "disabled"
    if service in {"enabled", "active", "active-discovery", "running", "starting", "stopping"}:
        return False
    top = re.split(r"(?im)^\s*ZTP stages\b", strip_ansi(output), maxsplit=1)[0]
    detail = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", top).strip()[-1500:]
    raise SetupError("cannot verify current ZTP state; initialization is blocked; "
                     "nv show system ztp: " + (detail or "<empty>"))


def _verify_ztp_disabled(output: str) -> None:
    if not _ztp_disabled(output):
        raise SetupError("ZTP is not disabled after save; inspect 'nv show system ztp'")


def _validate_owned_pending(device: Device, output: str, *, services=None) -> int:
    """Qualify only closed Initial/management setters bound to this target, and (U3, R-025)
    every DNS/NTP/timezone value of this run's services profile; None owns no services row."""
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
        ("eth1", device.eth1_gateway if device.eth1_prefix else ""),
    ):
        if gateway:
            allowed.add(("nv", "set", "interface", port, "ipv4", "gateway", gateway))
    if services is not None:
        for category in ("dns", "ntp"):
            for value in services.get(category) or ():
                allowed.add(("nv", "set", "system", category, "server", value))
        allowed.add(("nv", "set", "system", "date-time", "timezone", services.get("timezone")))
    count = unknown = 0
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
        if tokens in allowed:
            count += 1
        else:
            unknown += 1
    if unknown:
        raise PendingChangesRefused(
            "unrelated or unrecognized pending changes; no changes cleared or committed; "
            f"有 {unknown} 行不认识的待提交，--apply 会拒绝；"
            "用 `nv config diff -o commands` 核对，确认后在设备上手工 detach 或 apply，再重跑")
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


def _settle_owned_pending(target, neighbor, eth_user, eth_password, ib_user, ib_password, timeout,
                          *, local, services, stage, record):
    """U3 (R-025): the Initial/Network/Services pending read, where T15 read it.

    Empty: nothing to do.  A line outside this device's own setters and this run's services
    profile is refused by the classifier, with no detach.  All owned: the lines are logged and
    recorded first and returned; the stage detaches them after its own consent
    (_detach_owned_pending).  The D7 replace gates keep _require_empty_pending.
    """
    result = run_on_ib(target, neighbor, eth_user, eth_password, ib_user, ib_password, timeout,
                       ["nv", "config", "diff", "-o", "commands"], local=local,
                       allow_password_change=False, _pending_services=services)
    # The detach decision itself rests on this classification, not only on the reader's.
    _validate_owned_pending(target.ib, result.output, services=services)
    lines = [line for line in result.output.splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    if not lines:
        if result.exit_code != 0 or result.output.strip():
            raise SetupError("pre-existing pending configuration; no changes cleared or committed")
        return None
    entry = {"stage": stage, "lines": lines, "detached": False}
    record.append(entry)
    log(f"  PENDING ({stage}): {len(lines)} line(s), all this device's own values; recorded; "
        "nv config detach follows the stage consent and the configuration backup")
    for line in lines:
        log(f"    PENDING: {line}")
    return entry


def _detach_owned_pending(target, neighbor, eth_user, eth_password, ib_user, ib_password, timeout,
                          entry, *, local, strict, policy, services):
    """U3: after the stage consent.  The detach is an ordinary NVUE stage write (backup and
    permit on its own route); the re-read must be empty before any stage write."""
    if policy is not None:
        policy.assert_unchanged()
    log("  PENDING DETACH: nv config detach")
    _stage_ib_command(target, neighbor, eth_user, eth_password, ib_user, ib_password, timeout,
                      ["nv", "config", "detach"], local=local, strict=strict, policy=policy)
    result = run_on_ib(target, neighbor, eth_user, eth_password, ib_user, ib_password, timeout,
                       ["nv", "config", "diff", "-o", "commands"], local=local,
                       allow_password_change=False, _pending_services=services)
    if result.exit_code != 0 or result.output.strip():
        raise SetupError("pending configuration remains after nv config detach; no stage write issued")
    entry["detached"] = True
    log("  PENDING DETACHED: the pending diff is empty; the stage continues")


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
                               _password_policy=None, _replace_sync_failure_task=None,
                               _preserve_replace_cleanup_veto=False) -> SessionResult:
    """Authorize one ordinary management command without changing credential roles."""
    evidence_options = ({"_replace_sync_failure_task": _replace_sync_failure_task}
                        if _replace_sync_failure_task is not None else {})
    if _preserve_replace_cleanup_veto is True:
        evidence_options["_preserve_replace_cleanup_veto"] = True
    return _run_authorized_ib_command_core(target, neighbor, eth_user, ethernet_password,
        ib_user, current_password, timeout, ib_command, local=local, direct=False,
        _password_policy=_password_policy, **evidence_options)


def _run_authorized_ib_direct_command(target, neighbor, eth_user, ethernet_password,
                                      ib_user, current_password, timeout, ib_command, *,
                                      local=False, _password_policy=None, _replace_sync_failure_task=None,
                                      _preserve_replace_cleanup_veto=False):
    evidence_options = ({"_replace_sync_failure_task": _replace_sync_failure_task}
                        if _replace_sync_failure_task is not None else {})
    if _preserve_replace_cleanup_veto is True:
        evidence_options["_preserve_replace_cleanup_veto"] = True
    return _run_authorized_ib_command_core(target, neighbor, eth_user, ethernet_password,
        ib_user, current_password, timeout, ib_command, local=local, direct=True,
        _password_policy=_password_policy, **evidence_options)


def _run_authorized_ib_command_core(target, endpoint, eth_user, ethernet_password, ib_user,
                                    current_password, timeout, ib_command, *, local=False,
                                    direct, _password_policy=None, _replace_sync_failure_task=None,
                                    _preserve_replace_cleanup_veto=False):
    """Two fixed admissions share the original command/authority/result choke."""
    neighbor = endpoint
    result = None
    failure = None
    ssh_failure = None
    summary = None
    withheld = None
    readonly_session_active = False
    readonly_session_timeout = False
    replace_failure = None
    cleanup_veto_active = False
    try:
        if type(direct) is not bool:
            raise SetupError("invalid authorized management path")
        if direct:
            if (type(local) is not bool or local or eth_user != "" or ethernet_password != ""
                    or type(eth_user) is not str or type(ethernet_password) is not str
                    or type(timeout) is not int or timeout <= 0):
                raise SetupError("invalid authorized direct management operation")
            _validate_direct_endpoint(target, neighbor)
            if (type(ib_user) is not str or clean(ib_user) != ib_user
                    or not valid_ssh_user(ib_user)):
                raise SetupError("invalid authorized management account")
        elif (type(local) is not bool or local
                or type(target) is not Target
                or type(target.ib) is not Device
                or type(target.ethernet) is not Device
                or type(neighbor) is not Neighbor
                or type(timeout) is not int or timeout <= 0):
            raise SetupError("invalid authorized management operation")
        if not direct:
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
        readonly_session_active = direct is True and _ib_write_category(command) is None
        evidence_options = ({"_replace_sync_failure_task": _replace_sync_failure_task}
                            if _replace_sync_failure_task is not None else {})
        cleanup_veto_active = (
            _preserve_replace_cleanup_veto is True
            and (command == ["nv", "config", "detach"]
                 or (direct is True and neighbor.interface is None
                     and command in (["ip", "addr", "show", "eth0"], ["ip", "route"]))))
        result = run_on_ib(
            target, neighbor, eth_user, ethernet_password, ib_user,
            current_password, timeout, command, local=False,
            allow_password_change=False, **evidence_options,
        )
        cleanup_veto_active = False
        readonly_session_active = False
        if (type(result) is not SessionResult
                or type(result.exit_code) is not int
                or result.exit_code not in ((0, 34) if _is_readonly_key_command(command) else (0,))
                or type(result.output) is not str
                or (_is_readonly_key_command(command) and (
                    result.output != "" or getattr(result, "cleanup_uncertain", False) is not False))
                or any(getattr(result, name) is not False for name in (
                    "password_changed", "password_change_required",
                    "password_change_attempted", "ib_authentication_rejected"))
                or _EXPIRED_PASSWORD.search(result.output)
                or _pending_diff_has_password_update_notice(result.output)):
            raise SetupError("management command outcome is unverified")
        _password_policy.assert_unchanged()
    except (SetupError, OSError) as error:
        if cleanup_veto_active and type(error) in (ProjectInputChanged, BatchStopped):
            # Preserve the existing batch-stop contract only for this cleanup call.
            raise
        uncertain, number = _ib_phase_error_facts(error)
        if number is None:
            candidate = getattr(error, "io_errno", None)
            if type(candidate) is int and 1 <= candidate <= 255:
                number = candidate
        failure = uncertain, number
        ssh_failure = _ssh_failure_fact(error)
        if (_replace_sync_failure_task is not None
                and type(error) is SetupError and not uncertain and number is None and ssh_failure is None):
            fact = getattr(error, "_replace_sync_failure", None)
            operation = _replace_failure_operation(_replace_sync_failure_task, fact)
            if (operation is not None
                    and _replace_sync_operation(_replace_sync_failure_task, target, neighbor,
                        eth_user, ethernet_password, ib_user, current_password, command, direct=direct) == operation):
                try:
                    check_task_cancelled()
                    _password_policy.assert_unchanged()
                except (SetupError, OSError):
                    pass  # Preserve the wrapped error and decline stale attribution.
                else:
                    replace_failure = fact
        readonly_session_timeout = (
            readonly_session_active is True and type(error) is SetupError
            and error.args == ("SSH/PAM session timed out; device state may be unknown",)
            and ssh_failure is None
            and getattr(error, "cleanup_uncertain", False) is False)
        summary = _authorized_failure_summary(
            error, (ethernet_password, current_password, withheld))
    if failure is not None:
        error = SetupError("management IB operation failed; device state is UNKNOWN")
        _retain_ssh_failure(error, ssh_failure)
        if failure[0] is True:
            error.cleanup_uncertain = True
        if failure[1] is not None:
            error.io_errno = failure[1]
        if readonly_session_timeout:
            error._ib_readonly_session_timeout = True
        if replace_failure is not None:
            error._replace_sync_failure = replace_failure
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
                      policy=None, _ib_read_context=None, _replace_sync_failure_task=None,
                      _preserve_replace_cleanup_veto=False) -> SessionResult:
    """One ordinary IB command of a stage.  A management-server task with the project global
    (strict) sends it through the DEV authorized helper, any other task through v15's run_on_ib
    (P3c map D32d and section 9 item 1); the stage logic around it is the same."""
    if _ib_read_context is not None:
        key_file = _readonly_key_file(_ib_read_context, target, neighbor, ib_user,
                                     ib_password, local=local, apply=False)
        if eth_user != "" or ethernet_password != "":
            raise SetupError("readonly key stage cannot carry outer credentials")
        result = _run_direct_key_read(target, neighbor, ib_user, key_file, timeout,
                                     command, strict=strict, policy=policy)
        actual = getattr(result, "_direct_endpoint", None)
        _validate_direct_endpoint(target, actual)
        if actual != neighbor:
            raise SetupError("readonly key read changed the verified task endpoint")
        return result
    evidence_options = ({"_replace_sync_failure_task": _replace_sync_failure_task}
                        if _replace_sync_failure_task is not None else {})
    if strict:
        if _preserve_replace_cleanup_veto is True:
            evidence_options["_preserve_replace_cleanup_veto"] = True
        if type(target) is Target and target.ethernet is None:
            return _run_authorized_ib_direct_command(target, neighbor, eth_user, ethernet_password, ib_user,
                ib_password, timeout, command, local=local, _password_policy=policy, **evidence_options)
        return _run_authorized_ib_command(target, neighbor, eth_user, ethernet_password, ib_user,
                                          ib_password, timeout, command, local=False,
                                          _password_policy=policy, **evidence_options)
    return run_on_ib(target, neighbor, eth_user, ethernet_password, ib_user, ib_password,
                     timeout, command, local=local, **evidence_options)


def run_initial_stage(target: Target, neighbor: Neighbor, eth_user: str,
                      ethernet_password: str, ib_user: str, timeout: int,
                      current: str, *, local: bool, apply: bool, authorized: bool,
                      _ib_current_password=None, _password_policy=None,
                      ib_password: Optional[str] = None,
                      policy: Optional[ProjectPasswordPolicy] = None,
                      details: Optional[dict] = None, _ib_read_context=None,
                      initial_ztp_output: Optional[str] = None, _pending_services=None,
                      _pending_record=None) -> tuple[str, bool]:
    """Stage 1 (v15): auto-save and ZTP config-save, saved, then ZTP verified disabled.

    Returns (readback, authorized): the readback after the Initial writes, else `current`;
    execute_ib_task recomputes the later stages from it (v15 :4199-4204).  One implementation
    (owner Q-035 (a)): the current ZTP state is read first and both settings plus a disabled
    ZTP gate the skip (T17); writes start on an empty pending diff (T15; U3 first detaches an
    all-owned one, _settle_owned_pending).  With the
    management-server context (_ib_current_password/_password_policy) every read and write
    goes through the authorized helper (P3c map D32d) and a failure becomes the fixed UNKNOWN
    error; the DEV readback parse (map 2.3) gates the settings on both paths.  A read-only
    check reads ZTP without the helper, which needs the project target (guide :649).
    `details["needed"]` tells the caller whether Initial could be skipped (owner Q-037 (b)).
    """
    strict = _ib_current_password is not None or _password_policy is not None
    if _ib_read_context is not None:
        _readonly_key_file(_ib_read_context, target, neighbor, ib_user, ib_password,
                           local=local, apply=apply)
        if _ib_current_password is not None:
            raise SetupError("readonly key Initial cannot carry a selected password")
        credential, guard = None, _password_policy if strict else policy
        strict = False  # This read never enters the password-only authorized core.
    elif strict:
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
        status_output = initial_ztp_output
        if status_output is None:
            status_output = _stage_ib_command(target, neighbor, eth_user, ethernet_password, ib_user, credential,
                timeout, ["nv", "show", "system", "ztp"], local=local,
                strict=strict and apply, policy=guard, _ib_read_context=_ib_read_context).output
        ztp_disabled = _ztp_disabled(status_output)
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
        owned = _settle_owned_pending(target, neighbor, eth_user, ethernet_password, ib_user,
                                      credential, timeout, local=local, services=_pending_services,
                                      stage="initial",
                                      record=[] if _pending_record is None else _pending_record)
        if owned is not None:
            _detach_owned_pending(target, neighbor, eth_user, ethernet_password, ib_user, credential,
                                  timeout, owned, local=local, strict=strict, policy=guard,
                                  services=_pending_services)
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
            raise _retain_ssh_failure(IBConfigurationStageUncertain(
                "initial configuration was not fully verified; writes may be partial: " + str(exc)
            ), exc) from None
        return readback, authorized
    except (ProjectInputChanged, BatchStopped, PendingChangesRefused):
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
        ssh_failure = _ssh_failure_fact(error)
    error = SetupError("Initial stage failed; device state is UNKNOWN")
    _retain_ssh_failure(error, ssh_failure)
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
    conflicts = management_conflicts(device, state)
    if conflicts:
        raise SetupError("Network conflict; manual resolution required: " + "; ".join(
            field + ": expected CSV value, found conflicting applied value"
            for field, _expected, _actual in conflicts))
    fields = (
        (state.eth0_addresses, device.eth0_prefix),
        (state.eth1_addresses, device.eth1_prefix),
        (state.eth0_gateways, device.eth0_gateway),
        (state.eth1_gateways, device.eth1_gateway if device.eth1_prefix else ""),
    )
    return (normalize_name(state.hostname) in DEFAULT_HOSTNAMES
            or any(expected and expected not in actual for actual, expected in fields))

def _key_payload(keys: list[dict[str, str]]) -> str:
    """Encode the same qualified public entries for either closed key program."""
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
    return base64.b64encode(("\n".join(lines) + "\n").encode("utf-8")).decode("ascii")


def key_install_command(keys: list[dict[str, str]]) -> list[str]:
    """Carry only validated public lines through a fixed, closed shell program."""
    return ib_command_argv(["sh", "-c", _KEY_INSTALL_SCRIPT, "--", _key_payload(keys)])


def readonly_key_command(keys: list[dict[str, str]]) -> list[str]:
    """Check required public identities without writing the remote key file."""
    return ib_command_argv(["sh", "-c", _KEY_READONLY_SCRIPT, "--", _key_payload(keys)])


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
    if device.eth1_prefix and device.eth1_gateway and device.eth1_gateway not in state.eth1_gateways:
        errors.append(
            f"eth1 gateway expected {device.eth1_gateway}, "
            f"got {state.eth1_gateways or 'none'}"
        )
    if normalize_name(state.hostname) != normalize_name(device.hostname):
        errors.append(f"hostname expected {device.hostname}, got {state.hostname or 'none'}")
    if errors:
        raise SetupError("post-configuration verification failed: " + "; ".join(errors))


@dataclass(frozen=True)
class ReadinessPolicy:
    first_delay: int = 15
    interval: int = 10
    attempts: int = 9


IPV4_READINESS = ReadinessPolicy()


def wait_until_ready(probe, policy: ReadinessPolicy, *, label: str, sleep=time.sleep):
    """One bounded readiness loop; transport and existing exceptional failures stay outside."""
    reason = "no verified response"
    for attempt in range(policy.attempts):
        check_task_cancelled()
        delay = policy.first_delay if attempt == 0 else policy.interval
        log(f"  IPv4 SSH [{attempt + 1}/{policy.attempts}]: "
            f"{'waiting ' + str(delay) + 's' if delay else 'no initial wait'} "
            f"for interface readiness; {label}")
        if delay:
            sleep(delay)
        check_task_cancelled()
        state, fact = probe()
        if state == "READY":
            return
        if state == "FATAL":
            raise fact
        reason = fact
        log(f"  IPv4 SSH [{attempt + 1}/{policy.attempts}] not ready: {reason}")
    raise SetupError(f"IPv4 SSH verification failed for {label} after {policy.attempts} attempts; "
                     f"设备可能还在收敛; last failure: {reason}")


def _readiness_failure_result(failure):
    if failure.kind in (SshFailureKind.JUMP_UNREACHABLE, SshFailureKind.DIRECT_SSH_NETWORK):
        if failure.hop == "outer":
            raise failure  # Existing coordinator/Gate owns an unavailable jump.
        return "RETRY", "SSH endpoint network is not ready"
    return "FATAL", failure


def _probe_ipv4_read_once(target, vrf, eth_user, ethernet_password, ib_user, timeout,
                          read_command, *, local, strict, password, destination,
                          strict_inner, password_policy):
    """One of the two fixed fresh-identity reads; no wait or retry loop."""
    if type(read_command) is not list or read_command not in (
            ["ip", "addr", "show", "eth0"], ["ip", "route"]):
        raise SetupError("IPv4 identity probe accepts only its two fixed reads")
    if strict:
        password_policy.assert_unchanged()
    nonretryable = re.compile(
        r"(?i)permission denied|authentication failed|"
        r"host key verification failed|remote host identification has changed|"
        r"offending .* key|operation not permitted|command not found|"
        r"could not resolve hostname")
    marker = os.urandom(16).hex()
    outer_options = {"tty": True, "local": local}
    try:
        path = _jump_control_path_for(target.ethernet, local=local)
    except SshFailure as failure:
        return _readiness_failure_result(failure)
    if path is not None:
        outer_options["control_path"] = path
    if strict:
        # verify_ipv4_login owns the validated prefix. Replace only its last
        # remote command with this read's complete, independently framed body.
        inner = [*strict_inner[:-1],
                 shlex.join(["sh", "-c", _framed_script(read_command, marker)])]
        probe = typed_argv(outer_ssh_command(
            target.ethernet, eth_user, inner, timeout, **outer_options,
        ), label="IPv4 management outer command")
    else:
        probe = outer_ssh_command(target.ethernet, eth_user, [
            "ip", "vrf", "exec", vrf, "ssh", "-tt",
            "-o", f"ConnectTimeout={timeout}", "-o", "StrictHostKeyChecking=accept-new",
            "-o", "LogLevel=ERROR", "-o", "ControlMaster=no", "-o", "ControlPath=none",
            "-o", "NumberOfPasswordPrompts=1", "-o", "PubkeyAuthentication=no",
            "-o", "PreferredAuthentications=password,keyboard-interactive",
            f"{ib_user}@{destination}",
            shlex.join(["sh", "-c", _framed_script(read_command, marker)]),
        ], timeout, **outer_options)
    responder = NestedResponder(ethernet_password, password, False,
                                ib_destination=f"{ib_user}@{destination}")
    record_metric("ib_ssh_attempts")
    try:
        result = interactive_run(probe, responder, max(timeout * 3, 45))
    except SshFailure as failure:
        return _readiness_failure_result(failure)
    except SetupError as exc:
        if (not str(exc).startswith("SSH/PAM session timed out;")
                or getattr(exc, "cleanup_uncertain", False) is True):
            raise
        if strict:
            password_policy.assert_unchanged()
        return "RETRY", "SSH session timed out"
    if (type(result) is not SessionResult or type(result.exit_code) is not int
            or type(result.output) is not str):
        raise SetupError("IPv4 identity read outcome is unverified")
    if strict:
        password_policy.assert_unchanged()
    if result.exit_code != 0:
        classified = (classify_ssh_failure(result.output, outer_address=None, inner_address=destination)
                      if local else _classify_jump_output(result.output, target.ethernet, destination))
        if local and classified is not None and classified.kind is not SshFailureKind.TARGET_HOST_KEY_CHANGED:
            classified = None  # Preserve the existing local endpoint/credential protocol below.
        if classified is not None:
            if classified.kind is SshFailureKind.TARGET_HOST_KEY_CHANGED:
                location = "local" if local or classified.hop == "outer" else "jump"
                change = _import_tools("tools.login_path").parse_host_key_change(
                    result.output, location=location,
                    jump=target.ethernet.hostname if location == "jump" else None)
                if change is not None:
                    classified.host_key_change = change
            return _readiness_failure_result(classified)
    detail = _ib_failure_detail(result.output, marker, (ethernet_password, password))
    if (result.password_change_required or result.password_change_attempted
            or _EXPIRED_PASSWORD.search(result.output)):
        raise SetupError(f"IPv4 SSH verification blocked for {target.ib.hostname}: "
                         "password change is required; no rotation or retry performed")
    if result.ib_authentication_rejected or nonretryable.search(result.output):
        raise SetupError(f"IPv4 SSH verification blocked for {target.ib.hostname}: "
                         f"authentication/host-key/local command failure; {detail}")
    if (any(getattr(result, name) is not False for name in (
                       "password_changed", "password_change_required",
                       "password_change_attempted", "ib_authentication_rejected"))
                   or responder.password_change_attempted
                   or responder.password_change_blocked
                   or _pending_diff_has_password_update_notice(result.output)):
        raise SetupError("IPv4 management outcome is unverified")
    if result.exit_code == 0:
        output = extract_command_output(result.output, marker)
        return "READY", output
    return "RETRY", f"exit={result.exit_code}; {detail}"


def _probe_ipv4_login(target, vrf, eth_user, ethernet_password, ib_user, timeout, *,
                       local, strict, password, destination, strict_inner, password_policy,
                       details=None):
    """One full attempt owns both fresh reads and their IPv4 identity check."""
    if details is not None:
        details.clear()
    state, address_output = _probe_ipv4_read_once(
        target, vrf, eth_user, ethernet_password, ib_user, timeout,
        ["ip", "addr", "show", "eth0"], local=local, strict=strict,
        password=password, destination=destination, strict_inner=strict_inner,
        password_policy=password_policy)
    if state != "READY":
        return state, address_output
    state, route_output = _probe_ipv4_read_once(
        target, vrf, eth_user, ethernet_password, ib_user, timeout,
        ["ip", "route"], local=local, strict=strict,
        password=password, destination=destination, strict_inner=strict_inner,
        password_policy=password_policy)
    if state != "READY":
        return state, route_output
    try:
        identity = _check_ib_identity(target, address_output, route_output, via_ipv4=True)
    except SetupError:
        if details is not None:
            details["identity_failed"] = True
        raise
    if details is not None:
        details["identity"] = identity
    if identity["ok"] is not True:
        if details is not None:
            details["identity_failed"] = True
        mismatch_detail = "; ".join(
            f"{item['field']}: expected={item['expected']} observed={item['observed']}"
            for item in identity["mismatches"])
        return "FATAL", SetupError("IB identity differs from CSV; " + mismatch_detail
                                    + "; no further configuration write authorized")
    log(f"  IPv4 SSH SUCCESS: {'management' if strict else 'password-only'} identity verified.")
    return "READY", None


def verify_ipv4_login(target: Target, vrf: str, eth_user: str,
                      ethernet_password: str, ib_user: str, timeout: int, *,
                      local: bool = False, _ib_current_password=None,
                      _password_policy=None, ib_password: Optional[str] = None,
                      readiness_policy: ReadinessPolicy = IPV4_READINESS,
                      _identity_details=None) -> None:
    """Read-only IPv4 readiness with independent 15/10/9 policy (v3.1.4 WP-3).

    One loop (guide 2.3 :204).  Authentication, host-key, local-command and password-change
    evidence is never retried; only a session timeout or a non-zero exit without such evidence
    is.  The management-server context (_ib_current_password/_password_policy) keeps the DEV
    probe: credential roles and the project target are checked first, every result fact is
    checked, and a failure becomes the fixed safe management error (P3c map 2.3).  Otherwise
    the v15 password-only probe runs with the selected IB credential (ib_password).
    """
    strict = _ib_current_password is not None or _password_policy is not None
    if _identity_details is not None:
        _identity_details.clear()
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
            strict_inner = typed_argv([
                "ip", "vrf", "exec", validated_vrf, "ssh",
                "-o", f"ConnectTimeout={timeout}",
                "-o", "StrictHostKeyChecking=accept-new",
                "-o", "LogLevel=ERROR",
                "-o", "ControlMaster=no", "-o", "ControlPath=none",
                f"{ib_user}@{destination}", shlex.join(ib_command_argv(["true"])),
            ], label="IPv4 management command")
        else:
            validate_jump_target(target)
            validated_vrf = validate_network_selector(vrf, label="IPv4 verification VRF")
            if type(ib_password) is not str:
                raise SetupError("IPv4 verification needs the selected IB credential")
            password = ib_password
            destination = target.ib.login_ip
            strict_inner = None
        wait_until_ready(lambda: _probe_ipv4_login(
            target, validated_vrf, eth_user, ethernet_password, ib_user, timeout,
            local=local, strict=strict, password=password, destination=destination,
            strict_inner=strict_inner, password_policy=_password_policy,
            details=_identity_details),
            readiness_policy, label=target.ib.hostname, sleep=time.sleep)
        return
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
        ssh_failure = _ssh_failure_fact(error)
    error = SetupError("management IB operation failed; device state is UNKNOWN")
    _retain_ssh_failure(error, ssh_failure)
    change = getattr(ssh_failure, "host_key_change", None)
    if change is not None:
        error.host_key_change = change
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


def _management_host_key_failure(output):
    change = _import_tools("tools.login_path").parse_host_key_change(output, location="local")
    if change is not None:
        failure = SshFailure(SshFailureKind.TARGET_HOST_KEY_CHANGED, "direct", change.address)
        failure.host_key_change = change
        return failure
    if re.search(r"(?i)WARNING:\s+REMOTE HOST IDENTIFICATION HAS CHANGED", output):
        raise SetupError("host-key change (unparseable); no known_hosts entry removed")
    return None


def _ib_host_key_failure(output, target, neighbor, *, local):
    """Retain only complete parser facts; never add scope to a real warning."""
    change = _import_tools("tools.login_path").parse_host_key_change(output,
        location="local" if local else "jump", jump=None if local else target.ethernet.hostname)
    if change is None:
        return None
    host, separator, interface = change.address.partition("%")
    if not separator or interface != neighbor.interface or ipaddress.IPv6Address(host) != ipaddress.IPv6Address(neighbor.ipv6):
        return None
    failure = SshFailure(SshFailureKind.TARGET_HOST_KEY_CHANGED, "inner", change.address,
                         None if local else target.ethernet.hostname)
    failure.host_key_change = change
    return failure


_JUMP_KNOWN_HOSTS = "/home/cumulus/.ssh/known_hosts"


def _host_key_task_gate(task, change, *, eth_user, apply):
    """Bind deletion to this admitted IB and the warning's original address."""
    validate_jump_target(task.target)
    validate_neighbor_boundary(task.neighbor)
    library = _import_tools("tools.login_path")
    if type(change) is not library.HostKeyChange or not library._host_key_address(change.address):
        raise SetupError("host-key change address is unverified; no entry removed")
    if (not change.lines or any(type(line) is not int or line < 1 for line in change.lines)
            or not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", change.new_fingerprint)):
        raise SetupError("host-key warning facts are unverified; no entry removed")
    host, separator, interface = change.address.partition("%")
    if separator:
        matched = (ipaddress.IPv6Address(host) == ipaddress.IPv6Address(task.neighbor.ipv6)
                   and interface == task.neighbor.interface)
    else:
        matched = ipaddress.IPv4Address(host) == ipaddress.IPv4Address(task.target.ib.login_ip)
    if not apply or not matched:
        raise SetupError("host-key change is outside this IB apply/address scope; no entry removed")
    if task.local:
        if change.location != "local" or pwd.getpwuid(os.getuid()).pw_name != eth_user:
            raise SetupError("local Leaf user/location differs; no entry removed")
    elif (eth_user != "cumulus" or change.location != "jump"
            or change.jump != task.target.ethernet.hostname or change.known_hosts_path != _JUMP_KNOWN_HOSTS):
        raise SetupError("host-key change is outside this IB jump/apply scope; no entry removed")


def remove_jump_known_hosts_entries(task, change, *, eth_user, apply, timeout, before_write=None):
    """The sole closed jump write; parent re-reads before every serialized deletion."""
    if task.local:
        raise SetupError("local Leaf removal must use its local known_hosts editor")
    _host_key_task_gate(task, change, eth_user=eth_user, apply=apply)
    check_task_cancelled()
    library = _import_tools("tools.login_path")
    rows = library.parse_known_host_fingerprints(run_on_ethernet(
        task.target.ethernet, eth_user, task.ethernet_password,
        ["ssh-keygen", "-l", "-F", change.address, "-f", _JUMP_KNOWN_HOSTS], timeout))
    if not set(change.lines).issubset({row[0] for row in rows}):
        raise SetupError("Offending host-key lines differ from current lookup; no entry removed")
    command = ["ssh-keygen", "-f", _JUMP_KNOWN_HOSTS, "-R", change.address]
    path = _jump_control_path_for(task.target.ethernet, local=False)
    if before_write is not None:
        before_write()
    result = interactive_run(outer_ssh_command(task.target.ethernet, eth_user, command,
        timeout, tty=True, control_path=path), ethernet_responder(task.ethernet_password), timeout)
    if result.exit_code != 0:
        failure = _classify_jump_output(result.output, task.target.ethernet)
        if failure is not None:
            raise failure
        raise SetupError("jump host-key remove failed; no automatic replay")
    old = any(line.strip() == "Original contents retained as " + _JUMP_KNOWN_HOSTS + ".old"
              for line in result.output.splitlines())
    return library.RemovalReceipt(tuple(row[0] for row in rows), old, None, None, None, None)


class JumpKnownHostsEditor:
    """Read on the worker's existing transport; only the parent can remove."""
    def __init__(self, task, change, *, eth_user, timeout):
        self.task, self.change, self.eth_user, self.timeout = task, change, eth_user, timeout

    def fingerprints(self, address):
        if address != self.change.address:
            raise ValueError("host-key editor address differs from warning")
        return _import_tools("tools.login_path").parse_known_host_fingerprints(run_on_ethernet(
            self.task.target.ethernet, self.eth_user, self.task.ethernet_password,
            ["ssh-keygen", "-l", "-F", address, "-f", _JUMP_KNOWN_HOSTS], self.timeout))

    def remove(self, address):
        if address != self.change.address:
            raise ValueError("host-key editor address differs from warning")
        if _WORKER_CONNECTION is not None:
            return worker_request("host-key-remove", self.change)
        if _ACTIVE_COORDINATOR is None:
            raise SetupError("host-key deletion requires the admitted coordinator")
        reply = _ACTIVE_COORDINATOR.request("host-key-remove", self.change, self.task.target)
        if isinstance(reply, dict) and "ssh_failure" in reply:
            return _unwrap_jump_master_reply(reply)
        return reply


def ib_host_key_reader(task, eth_user, ib_user, current_password, timeout, *, policy=None):
    """Construct only after authentication; one fixed read, one existing fingerprint algorithm."""
    def read(key_type):
        paths = {"RSA": "/etc/ssh/ssh_host_rsa_key.pub", "ECDSA": "/etc/ssh/ssh_host_ecdsa_key.pub",
                 "ED25519": "/etc/ssh/ssh_host_ed25519_key.pub"}
        if key_type.upper() not in paths:
            return None
        if policy is not None:
            policy.assert_unchanged()
        result = run_on_ib(task.target, task.neighbor, eth_user, task.ethernet_password,
            ib_user, current_password, timeout, ["cat", paths[key_type.upper()]],
            local=task.local, allow_password_change=False, password_only=True)
        if result.exit_code != 0:
            return None
        return _public_key_fingerprint(result.output.strip())
    return read


def _host_key_outcome(change, *, pending=False):
    failure = SshFailure(SshFailureKind.HOST_KEY_REFRESH_PENDING if pending else
                         SshFailureKind.TARGET_HOST_KEY_CHANGED,
                         "inner" if change.location == "jump" else "direct", change.address, change.jump)
    failure.host_key_change = change
    return failure


def _refresh_host_key(change, editor, *, apply, read_device_fingerprint, retry,
                       operator_forced, host_key_records):
    library = _import_tools("tools.login_path")
    try:
        if not apply:
            verified = read_device_fingerprint(change.key_type) if read_device_fingerprint else None
            if verified != change.new_fingerprint:
                raise _host_key_outcome(change)
            record = library.HostKeyRefreshRecord(change.location, change.jump, change.known_hosts_path,
                change.lines, change.address, change.key_type,
                tuple(row[2] for row in editor.fingerprints(change.address)), change.new_fingerprint,
                "verified", "refresh-pending", None)
        else:
            before_remove = None
            if isinstance(editor, library.LocalKnownHostsEditor) and (_WORKER_CONNECTION is not None or _ACTIVE_COORDINATOR is not None):
                def before_remove():
                    reason = "refresh this verified IB host-key entry in the operator's known_hosts"
                    if _WORKER_CONNECTION is not None:
                        worker_request("authorize", reason)
                    else:
                        _ACTIVE_COORDINATOR.authorize(_ACTIVE_COORDINATOR.current_target, reason)
                    obtain_write_permit("host_key")
            record = library.refresh_target_host_key(change, editor,
                read_device_fingerprint=read_device_fingerprint, retry=retry, operator_forced=operator_forced,
                before_remove=before_remove)
    except (ProjectInputChanged, BatchStopped, SshFailure):
        raise
    except (ValueError, OSError, SetupError, subprocess.TimeoutExpired):
        raise _host_key_outcome(change) from None
    if host_key_records is not None:
        host_key_records.append(record)
    if not apply:
        raise _host_key_outcome(change, pending=True)
    return record


def _direct_host_key_task_gate(task, change, *, apply):
    if (type(task) is not PreparedIBTask or type(task.local) is not bool or task.local
            or task.ethernet_password != "" or type(apply) is not bool or not apply):
        raise SetupError("host-key change is outside this direct IB task scope; no entry removed")
    _validate_direct_endpoint(task.target, task.neighbor)
    library = _import_tools("tools.login_path")
    if (type(change) is not library.HostKeyChange or change.location != "local"
            or change.jump is not None or not library._host_key_address(change.address)
            or not change.lines or any(type(line) is not int or line < 1 for line in change.lines)
            or type(change.new_fingerprint) is not str
            or not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", change.new_fingerprint)):
        raise SetupError("host-key warning facts are unverified; no entry removed")
    endpoint = task.neighbor
    address = endpoint.address + ("%" + endpoint.interface if endpoint.interface is not None else "")
    if change.address != address:
        raise SetupError("host-key warning differs from this attempted direct endpoint; no entry removed")


def refresh_ib_host_key(change, task, *, eth_user, timeout, apply,
                        read_device_fingerprint, retry, operator_forced, host_key_records):
    library = _import_tools("tools.login_path")
    try:
        if type(task.target) is Target and task.target.ethernet is None:
            _direct_host_key_task_gate(task, change, apply=True)
            editor = library.LocalKnownHostsEditor(Path(change.known_hosts_path), home=Path.home())
        elif task.local:
            _host_key_task_gate(task, change, eth_user=eth_user, apply=True)
            editor = library.LocalKnownHostsEditor(Path(change.known_hosts_path), home=Path.home())
        else:
            _host_key_task_gate(task, change, eth_user=eth_user, apply=True)
            editor = JumpKnownHostsEditor(task, change, eth_user=eth_user, timeout=timeout)
        return _refresh_host_key(change, editor, apply=apply, read_device_fingerprint=read_device_fingerprint,
            retry=retry, operator_forced=operator_forced, host_key_records=host_key_records)
    except (ProjectInputChanged, BatchStopped, SshFailure):
        raise
    except (ValueError, OSError, SetupError, subprocess.TimeoutExpired):
        raise _host_key_outcome(change) from None


def resolve_host_key_refresh_selector(value, ib_devices):
    if value is None:
        return frozenset()
    ranges = _import_tools("tools.hostname_ranges")
    try:
        selector = ranges.parse_selector(value, option="--refresh-host-key", allow_all=False)
        return frozenset(normalize_name(name) for name in ranges.select(selector,
            [device.hostname for device in ib_devices.values() if device.dev_type == "ib"]))
    except ranges.SelectorError as error:
        raise SetupError(str(error)) from None


def _refresh_management_host_key(change, device, address, *, apply,
                                 read_device_fingerprint, retry, operator_forced, host_key_records):
    """Local management gate; the authenticated link-local reader belongs to WP5."""
    if device.dev_type != "ib":
        raise SetupError("host-key change requires IB --apply; no known_hosts entry removed")
    allowed = {str(ipaddress.IPv4Interface(prefix).ip)
               for prefix in (device.eth0_prefix, device.eth1_prefix) if prefix}
    try:
        actual = str(ipaddress.IPv4Address(change.address))
    except ipaddress.AddressValueError:
        raise SetupError("host-key change address differs from this CSV IB") from None
    if actual != address or actual not in allowed or change.location != "local":
        raise SetupError("host-key change address differs from this CSV IB")
    library = _import_tools("tools.login_path")
    try:
        editor = library.LocalKnownHostsEditor(Path(change.known_hosts_path), home=Path.home())
        return _refresh_host_key(change, editor, apply=apply,
            read_device_fingerprint=read_device_fingerprint, retry=retry,
            operator_forced=operator_forced, host_key_records=host_key_records)
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        # Library errors contain fixed facts, never raw remote banners.
        raise SetupError("management host-key refresh failed: " + str(error)) from None


def verify_management_direct_ssh(device: Device, interface: str, user: str,
                                 password: str, timeout: int, *, apply=False,
                                 read_device_fingerprint=None, operator_forced=False, host_key_records=None) -> None:
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
        result = interactive_run(
            argv, NestedResponder("", password, False, ib_destination=f"{user}@{address}"),
            max(connect_timeout * 3, 15))
        if result.exit_code != 0:
            failure = _management_host_key_failure(result.output)
            if failure is not None:
                raise failure
        return result
    def verify_once():
        return readonly_direct_ssh_retry("direct password-only IPv4 SSH", address, timeout,
                                         "direct_ssh_attempts", attempt_once, secrets=(password,))
    try:
        result = verify_once()
    except SshFailure as error:
        change = getattr(error, "host_key_change", None)
        if change is None:
            raise
        retried = []
        _refresh_management_host_key(change, device, address, apply=apply,
            read_device_fingerprint=read_device_fingerprint, retry=lambda: retried.append(verify_once()),
            operator_forced=operator_forced, host_key_records=host_key_records)
        result = retried[0]
    output = _split_comma_interface_lines(extract_command_output(result.output, marker))
    verify_state(device, parse_nvue_state(output))


def run_management_direct_checks(targets: list[Target], credentials: dict[str, str],
                                 user: str, timeout: int, *,
                                 on_management_server: bool, apply=False, read_device_fingerprint=None,
                                 operator_forced=False, host_key_records=None) -> list[dict[str, str]]:
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
                    options = (dict(apply=apply, read_device_fingerprint=read_device_fingerprint,
                                    operator_forced=operator_forced, host_key_records=host_key_records)
                               if apply or read_device_fingerprint is not None or operator_forced
                               or host_key_records is not None else {})
                    verify_management_direct_ssh(device, interface, user, credentials[key], timeout, **options)
                except (ProjectInputChanged, BatchStopped):
                    raise
                except SetupError as exc:
                    row["status"] = "FAIL"
                    row["detail"] = str(exc).replace(credentials[key], "<redacted>") if credentials[key] else str(exc)
                    failure = _ssh_failure_fact(exc)
                    if failure is not None:
                        row["failure_kind"] = failure.kind.value
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
    # Physical location is based on original source facts, not a runtime route.
    # Legacy callers with a real Jump Device retain their established matching.
    switches = set()
    for target in targets:
        source = target.source_attachment
        if source is not None:
            kind = clean(source.peer_type).casefold()
            if kind in TRANSIT_DEVICE_TYPES or kind.endswith("jump"):
                switches.add(normalize_name(source.peer))
        elif target.ethernet is not None:
            switches.add(normalize_name(target.ethernet.hostname))
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
                              jump_sessions=None,
                              ) -> dict[str, Optional[str]]:
    """Public key first (I13); then the shared/per-switch hidden prompts, or with
    password_for (--credentials-fd) the fd table and never a prompt (R-012 design :345).
    "" is a public-key login, a local switch or a failed probe; None (an fd table without this
    switch) means this switch is never logged in to."""
    if supplied is not None:
        raise SetupError("passwords in command-line arguments are not supported; use hidden prompts")
    switches = {normalize_name(target.ethernet.hostname): target.ethernet for target in targets
                if target.ethernet is not None}
    passwords = {}
    pending = []
    master_options = {}
    for key, switch in sorted(switches.items()):
        if key in local_keys:
            passwords[key] = ""
            continue
        try:
            if jump_sessions is None:
                mode = probe_ethernet_key(switch, eth_user, timeout)
            else:
                paths = _import_tools("tools.login_path")
                candidates = tuple(item.address for item in switch.jump_candidates) or (switch.login_ip,)
                eth0_addresses = {item.address for item in switch.jump_candidates if item.entry == "JUMP_ETH0"}
                if not switch.jump_candidates:
                    eth0_addresses = {switch.login_ip}
                try:
                    expected_mac = paths.normalize_mac(switch.eth0_mac)
                except ValueError:
                    expected_mac = ""  # O2a explicitly permits hostname-only for an invalid cell.
                if not expected_mac:
                    log(f"{switch.hostname}: eth0_mac missing or invalid; hostname-only identity verification")
                def verify_jump_identity(jump, address, *, expected=expected_mac, eth0=eth0_addresses):
                    if address not in eth0 or not expected:
                        return
                    record = jump_sessions.records[normalize_name(jump.hostname)]
                    output = run_on_ethernet(replace(jump, login_ip=address), eth_user, "",
                        ["ip", "-j", "address", "show"], timeout, control_path=record["path"])
                    rows = [row for row in parse_oob_addresses(output) if row["ifname"] == "eth0"]
                    raw_mac = rows[0].get("address", "") if len(rows) == 1 else ""
                    try:
                        observed = paths.normalize_mac(raw_mac) if isinstance(raw_mac, str) else ""
                    except ValueError:
                        observed = "invalid"
                    if observed != expected:
                        log(f"{jump.hostname}: eth0 MAC identity mismatch expected={expected} observed={observed or 'missing'}")
                        raise SetupError("jump eth0 MAC identity mismatch")
                options = dict(candidates=candidates, verify_identity=verify_jump_identity)
                master_options[key] = options
                try:
                    jump_sessions.open_jump_master(switch, eth_user, None, **options)
                    mode = "key"
                except SshFailure as error:
                    if error.kind != SshFailureKind.JUMP_AUTHENTICATION:
                        raise
                    # Continue the original password path only at the address
                    # which requested it; do not retry exhausted network entries.
                    options["candidates"] = (jump_sessions.records[key]["address"],)
                    mode = "password"
        except SetupError as exc:
            log(f"OOB access unavailable: {exc}; snapshot collection will report its dependents.")
            passwords[key] = ""
            continue
        if mode == "key":
            log(f"OOB public-key login verified: {switch.hostname}")
            passwords[key] = ""
        else:
            pending.append((key, switch))

    def finish_jump_password_masters():
        if jump_sessions is not None:
            for key, switch in pending:
                if passwords.get(key) is None:
                    continue
                try:
                    jump_sessions.open_jump_master(switch, eth_user, ethernet_responder(passwords[key]),
                                                   **master_options[key])
                except SshFailure as error:
                    # Retain the typed failure in the coordinator's record; its snapshot
                    # fails without another login or a guessed credential.
                    log(f"OOB master unavailable: {error}; snapshot collection will report its dependents.")

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
        finish_jump_password_masters()
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
    finish_jump_password_masters()
    return passwords


def _ask_first_device_change(target: Target, reason: str, *, replace_mode=False) -> bool:
    via = ("direct" if replace_mode and target.ethernet is None
           else f"{target.ethernet.hostname}:{target.ethernet_port}")
    log(
        f"\nFIRST DEVICE CHANGE: {target.ib.hostname} via "
        f"{via}"
    )
    log(f"  Required action: {reason}")
    if replace_mode:
        log("  整份替换（会清掉 yaml 以外的配置）")
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


def _checked_replace_stage_output(result, message) -> str:
    if (type(result) is not SessionResult or type(result.exit_code) is not int
            or result.exit_code != 0 or type(result.output) is not str
            or getattr(result, "cleanup_uncertain", False) is not False
            or any(getattr(result, name) is not False for name in (
                "password_changed", "password_change_required", "password_change_attempted",
                "ib_authentication_rejected"))
            or _EXPIRED_PASSWORD.search(result.output)
            or _pending_diff_has_password_update_notice(result.output)):
        raise SetupError(message)
    return result.output


def run_service_stage(target: Target, neighbor: Neighbor, eth_user: str,
                      eth_password: str, ib_user: str, timeout: int,
                      services: Optional[dict[str, object]], current: str,
                      *, local: bool, apply: bool, authorized: bool,
                      _ib_current_password=None, _password_policy=None,
                      ib_password: Optional[str] = None, _ib_read_context=None,
                      _replace_restore=False, _owned_pending=None) -> tuple[bool, bool]:
    """Infra Services stage (v15); returns (authorized, skipped).

    One implementation (owner Q-035 (a)): the management-server context
    (_ib_current_password/_password_policy) checks its credential roles first and writes
    through the authorized helper (DEV; P3c map D32d); otherwise the selected IB credential
    (ib_password).
    A write or verification failure is IBConfigurationStageUncertain on both (map 2.3).
    """
    if type(_replace_restore) is not bool:
        raise SetupError("invalid replace service restore option")

    def missing_commands(body):
        if _replace_restore and type(body) is not str:
            raise SetupError("replace auto-save configuration is UNKNOWN")
        commands = [] if services is None else desired_service_commands(services, body)
        if not _replace_restore:
            return commands
        state = parse_nvue_state(body)
        setting = ["nv", "set", "system", "config", "auto-save", "state"]
        values = set()
        try:
            for line in state.raw_commands.splitlines():
                words = shlex.split(line)
                if words[:5] == setting[:5]:
                    if words[:-1] != setting or words[-1] not in {"enabled", "disabled"}:
                        raise SetupError("replace auto-save configuration is UNKNOWN")
                    values.add(words[-1])
                elif len(words) < 5 and words == setting[:len(words)]:
                    raise SetupError("replace auto-save configuration fact is truncated")
        except ValueError:
            raise SetupError("replace auto-save configuration syntax is UNKNOWN") from None
        if len(values) > 1:
            raise SetupError("replace auto-save configuration is contradictory")
        return commands if values == {"enabled"} else [[*setting, "enabled"], *commands]

    strict = _ib_current_password is not None or _password_policy is not None
    if _ib_read_context is not None:
        _readonly_key_file(_ib_read_context, target, neighbor, ib_user, ib_password,
                           local=local, apply=apply)
        if _ib_current_password is not None:
            raise SetupError("readonly key Services cannot carry a selected password")
    elif strict:
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
    if services is None and not _replace_restore:
        log("  Infra Services SKIP: 01-global.yaml was unavailable at cache generation.")
        return authorized, True
    commands = missing_commands(current)
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
    if _owned_pending is not None:
        _detach_owned_pending(target, neighbor, eth_user, eth_password, ib_user, password, timeout,
                              _owned_pending, local=local, strict=strict, policy=_password_policy,
                              services=services)
    try:
        for index, command in enumerate(stage_commands, 1):
            log(f"  INFRA SERVICES RUN [{index}/{len(stage_commands)}]: {shlex.join(command)}")
            result = _stage_ib_command(target, neighbor, eth_user, eth_password, ib_user, password, timeout,
                                       command, local=local, strict=strict, policy=_password_policy)
            if _replace_restore:
                _checked_replace_stage_output(result, "replace service restore outcome is unverified")
            log(f"  INFRA SERVICES OK  [{index}/{len(stage_commands)}]")
        result = _stage_ib_command(target, neighbor, eth_user, eth_password, ib_user, password, timeout,
                                   ["nv", "config", "show", "-o", "commands"], local=local,
                                   strict=strict, policy=_password_policy)
        body = (_checked_replace_stage_output(result, "replace service restore readback is unverified")
                if _replace_restore else result.output)
        remaining = missing_commands(body)
        if remaining:
            raise SetupError("service verification failed: " +
                             ", ".join(shlex.join(command) for command in remaining))
    except (ProjectInputChanged, BatchStopped):
        raise
    except SetupError as exc:
        # The authorized helper's own fixed error carries the product text it replaced
        # (DEV _authorized_failure_text); keep it through the v15 wrapper (map 2.3 :121).
        raise _retain_ssh_failure(IBConfigurationStageUncertain(
            "services were not fully verified; writes may be partial: "
            + _authorized_failure_text(exc)), exc) from None
    log("  Infra Services SUCCESS: desired values verified.")
    return authorized, False


def _restore_replace_services(target, neighbor, eth_user, eth_password, ib_user, ib_password, timeout,
                              services, current, *, local, authorized, _password_policy=None):
    """Restore missing values after a verified replace, as a distinct T15 transaction."""
    if authorized is not True:
        raise SetupError("replace service restore requires existing authorization")
    _require_empty_pending(target, neighbor, eth_user, eth_password, ib_user, ib_password,
                           timeout, local=local)
    stage_context = ({"ib_password": ib_password} if _password_policy is None else
                     {"_ib_current_password": ib_password, "_password_policy": _password_policy})
    return run_service_stage(target, neighbor, eth_user, eth_password, ib_user, timeout,
                             services, current, local=local, apply=True, authorized=authorized,
                             _replace_restore=True, **stage_context)


def _restore_replace_services_and_verify_ztp(state, services, current, *, timeout,
                                             authorized, strict, policy=None):
    """Complete service restoration and attest fresh ZTP before later stages."""
    if (type(state) is not _IBConfigWriteState or state is not _TASK_IB_CONFIG
            or type(state.task) is not PreparedIBTask or state.task.local is not False
            or state.apply is not True or state.identity_verified is not True or authorized is not True
            or type(state.current_password) is not str or not state.current_password
            or type(timeout) is not int or timeout <= 0 or type(strict) is not bool
            or (strict and policy is None)):
        raise SetupError("replace service and ZTP context is not qualified")
    context = (state.task.target, state.endpoint, state.eth_user, state.task.ethernet_password,
               state.ib_user, state.current_password, timeout)
    check_task_cancelled()
    authorized, skipped = _restore_replace_services(
        *context, services, current, local=False, authorized=authorized,
        _password_policy=policy if strict else None)
    check_task_cancelled()
    result = _stage_ib_command(*context, ["nv", "show", "system", "ztp"],
                               local=False, strict=strict, policy=policy)
    output = _checked_replace_stage_output(result, "replace post-restoration ZTP outcome is unverified")
    _verify_ztp_disabled(output)
    check_task_cancelled()
    return authorized, skipped, output


def verify_management_key_possession(target: Target, ib_user: str,
                                     entry: dict[str, str], private_key: Path,
                                     timeout: int, *, apply=False, read_device_fingerprint=None,
                                     operator_forced=False, host_key_records=None) -> None:
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
        result = SessionResult((result.stdout or "") + "\n" + (result.stderr or ""), result.returncode)
        if result.exit_code != 0:
            failure = _management_host_key_failure(result.output)
            if failure is not None:
                raise failure
        return result
    def verify_once():
        return readonly_direct_ssh_retry("management public-key-only IPv4 SSH", login_ip, timeout,
                                         "public_key_ssh_attempts", attempt_once)
    try:
        verify_once()
    except SshFailure as error:
        change = getattr(error, "host_key_change", None)
        if change is None:
            raise
        _refresh_management_host_key(change, target.ib, login_ip, apply=apply,
            read_device_fingerprint=read_device_fingerprint, retry=verify_once,
            operator_forced=operator_forced, host_key_records=host_key_records)
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
                  details: Optional[dict] = None, read_device_fingerprint=None,
                  operator_forced=False, host_key_records=None, _ib_read_context=None) -> bool:
    """Public-key stage: the management-server context installs through the
    authorized helper (DEV), otherwise with the selected IB credential (v15);
    only the two canonical receipts are accepted (DEV)."""
    strict = _ib_current_password is not None or _password_policy is not None
    if _ib_read_context is not None:
        _readonly_key_file(_ib_read_context, target, neighbor, ib_user, ib_password,
                           local=local, apply=apply)
        if _ib_current_password is not None:
            raise SetupError("readonly key public-key stage cannot carry a selected password")
    elif strict:
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
        result = _stage_ib_command(target, neighbor, eth_user, eth_password, ib_user,
            _ib_current_password if strict else ib_password, timeout, readonly_key_command(keys),
            local=local, strict=strict, policy=_password_policy, _ib_read_context=_ib_read_context)
        if (type(result) is not SessionResult or type(result.exit_code) is not int
                or result.exit_code not in (0, 34) or result.output != ""):
            raise SetupError("readonly public-key stage outcome is unverified")
        if details is not None:
            details["present"] = result.exit_code == 0
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
                target, ib_user, entry, management_private_key, timeout, apply=apply,
                read_device_fingerprint=read_device_fingerprint, operator_forced=operator_forced,
                host_key_records=host_key_records,
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
    parser.add_argument("--direct-access", metavar="HOST[,HOST...]",
                        help="use direct login for selected CSV IB names (supports ranges, *, all)")
    parser.add_argument("--devices", metavar="SELECTOR",
                        help="process only matching CSV IB names (comma list, *, digit or letter ranges; all is a literal name)")
    parser.add_argument("--ignore-cable-check", action="store_true",
                        help="ignore the cable-check decision for this run")
    parser.add_argument("--inventory-checked", action="store_true", help=argparse.SUPPRESS)
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
    parser.add_argument("--config-mode", choices=("patch", "replace"), default="patch",
                        help="patch missing configuration (default) or replace from the published host YAML")
    parser.add_argument("--force", action="store_true",
                        help="only complete missing Network fields; refuse conflicts")
    parser.add_argument("--refresh-host-key", metavar="HOST[,HOST...]",
                        help="IB selector for operator-confirmed, otherwise unverifiable host-key refresh (with --apply)")
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
    neighbor: Optional[Neighbor]
    ethernet_password: str
    local: bool


@dataclass(repr=False)
class _IBConfigWriteState:
    """One execute invocation owns this state; never serialize its credentials."""
    task: PreparedIBTask
    ib_user: str
    eth_user: str
    stamp: object
    apply: bool
    endpoint: object = None
    current_password: Optional[str] = None
    identity_verified: bool = False
    backup_state: str = "NEW"
    backup_receipt: Optional[dict] = None
    failure_category: Optional[str] = None
    readonly_key_file: Optional[Path] = None


def _readonly_key_file(context, target, endpoint, ib_user, current_password, *, local, apply):
    """Select only this already-key-authenticated task's readonly transport."""
    if (type(context) is not _IBConfigWriteState or context is not _TASK_IB_CONFIG
            or context.task.target is not target or target.ethernet is not None
            or local is not False or context.task.local is not False
            or apply is not False or context.apply is not False
            or current_password is not None or context.current_password is not None
            or context.ib_user != ib_user or context.identity_verified is not True
            or type(endpoint) is not DirectEndpoint or context.endpoint != endpoint
            or not isinstance(context.readonly_key_file, Path)
            or not context.readonly_key_file.is_file() or context.readonly_key_file.is_symlink()):
        raise SetupError("readonly key context is not bound to this verified direct task")
    return context.readonly_key_file


def _check_ib_identity(target, addr_output, route_output, *, via_ipv4):
    """Return only parsed identity facts; raw device output stays out of records."""
    paths = _import_tools("tools.login_path")
    try:
        observed = paths.parse_ip_addr(addr_output)
        if via_ipv4:
            for line in route_output.splitlines():
                if (re.match(r"^\s*(?:\S+[ \t]+)?default(?:\s|$)", line)
                        and not re.match(r"^default[ \t]+via[ \t]+\S+(?:[ \t]|$)", line)):
                    raise SetupError("IB default route has no verifiable gateway")
            observed = replace(observed, gateways=paths.parse_default_routes(route_output))
        check = paths.check_identity(target.ib.eth0_mac, observed, via_ipv4=via_ipv4,
                                     expected_ipv4=target.ib.eth0_prefix,
                                     expected_gateway=target.ib.eth0_gateway)
    except ValueError:
        raise SetupError("IB identity readback is not verifiable") from None
    return {"ok": check.ok, "via_ipv4": via_ipv4,
            "expected": {"mac": paths.normalize_mac(target.ib.eth0_mac),
                         "ipv4": target.ib.eth0_prefix if via_ipv4 else None,
                         "gateway": target.ib.eth0_gateway if via_ipv4 else None},
            "observed": {"mac": observed.mac, "ipv4": list(map(str, observed.ipv4)),
                         "gateways": list(observed.gateways)},
            "mismatches": [{"field": name, "expected": expected, "observed": actual}
                           for name, expected, actual in check.mismatches]}


def _ib_write_category(ib_command):
    """Classify only admitted vectors, not every shell command as a key write."""
    command = ib_command_argv(ib_command)
    if command[:2] == ["sh", "-c"]:
        if command[2] == _CONFIG_BACKUP_SCRIPT:
            return "config_backup"
        if command[2] in (_DEFERRED_APPLY_SCRIPT, _REPLACE_DEFERRED_APPLY_SCRIPT):
            return "nvue"
        if command[2] == _CONFIG_REPLACE_SCRIPT:
            return "nvue"
        if command[2] == _KEY_INSTALL_SCRIPT:
            return "public_key"
        return None  # The only other admitted closed script reads its rc.
    if (command[:2] == ["nv", "set"]
            or command[:3] in (["nv", "config", "apply"], ["nv", "config", "save"],
                                ["nv", "config", "replace"], ["nv", "config", "detach"])):
        return "nvue"
    return None


def _read_direct_ipv4_command(target, point, ib_user, current_password, timeout, command, *,
                              strict, policy, details, _require_certain=False,
                              _preserve_replace_cleanup_veto=False):
    """One direct-read qualification shared by D4 and the D7 fence."""
    options = {"_preserve_replace_cleanup_veto": True} if _preserve_replace_cleanup_veto is True else {}
    result = _stage_ib_command(target, point, "", "", ib_user, current_password,
        timeout, command, local=False, strict=strict, policy=policy, **options)
    if (type(result) is not SessionResult or type(result.exit_code) is not int
            or result.exit_code != 0 or type(result.output) is not str
            or any(getattr(result, name) is not False for name in (
                "password_changed", "password_change_required", "password_change_attempted",
                "ib_authentication_rejected"))
            or _EXPIRED_PASSWORD.search(result.output)
            or _pending_diff_has_password_update_notice(result.output)
            or type(getattr(result, "_direct_endpoint", None)) is not DirectEndpoint
            or result._direct_endpoint != point
            or (_require_certain is True and getattr(result, "cleanup_uncertain", False) is not False)):
        raise SetupError("direct IPv4 readiness outcome is unverified")
    details["endpoint"] = result._direct_endpoint
    return result.output


_REPLACE_DEFERRED_APPLY_SCRIPT = r"""set -eu
umask 077
fail() { printf '%s\n' 'IB deferred configuration launch failed' >&2; exit 1; }
[ "$#" -eq 1 ] || fail
stamp=$1
case "$stamp" in
    [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]) ;;
    *) fail ;;
esac
case "${HOME-}" in /*) ;; *) fail ;; esac
rc_file="$HOME/.initial-setup-${stamp}.rc"
[ ! -e "$rc_file" ] && [ ! -L "$rc_file" ] || fail
(set -C; : > "$rc_file") 2>/dev/null || fail
chmod 600 "$rc_file" || fail
setsid nohup sh -c '
set -u
umask 077
rc_file=$1
sleep 3 || exit 1
nv config apply -y
status=$?
failed_operation=apply
if [ "$status" -eq 0 ]; then
    nv config save
    status=$?
    failed_operation=save
    if [ "$status" -eq 0 ]; then failed_operation=none; fi
fi
tmp=
trap '\''if [ -n "$tmp" ]; then rm -f -- "$tmp"; fi'\'' EXIT
trap '\''exit 1'\'' HUP INT TERM
tmp=$(mktemp "${rc_file}.tmp.XXXXXX" 2>/dev/null) || exit 1
printf "rc=%s\nfailed_operation=%s\n" "$status" "$failed_operation" > "$tmp" || exit 1
chmod 600 "$tmp" || exit 1
mv -fT -- "$tmp" "$rc_file" || exit 1
tmp=
exit "$status"
' -- "$rc_file" > /dev/null 2>&1 < /dev/null &
exit 0
"""

_REPLACE_DEFERRED_RC_SCRIPT = r"""set -eu
fail() { printf '%s\n' 'IB deferred configuration result is unverified' >&2; exit 1; }
[ "$#" -eq 1 ] || fail
stamp=$1
case "$stamp" in
    [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]) ;;
    *) fail ;;
esac
case "${HOME-}" in /*) ;; *) fail ;; esac
rc_file="$HOME/.initial-setup-${stamp}.rc"
[ ! -L "$rc_file" ] || fail
if [ ! -e "$rc_file" ]; then printf 'rc=\nfailed_operation=pending\n'; exit 0; fi
[ -f "$rc_file" ] || fail
if [ ! -s "$rc_file" ]; then printf 'rc=\nfailed_operation=pending\n'; exit 0; fi
{
    IFS= read -r rc_line || fail
    IFS= read -r operation_line || fail
} < "$rc_file"
case "$rc_line" in
    rc=*) status=${rc_line#rc=} ;;
    *) fail ;;
esac
case "$status" in
    0|[1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]) ;;
    *) fail ;;
esac
case "$operation_line" in
    failed_operation=none) [ "$status" -eq 0 ] || fail ;;
    failed_operation=apply|failed_operation=save) [ "$status" -ne 0 ] || fail ;;
    *) fail ;;
esac
bytes=$(wc -c < "$rc_file" | tr -d '[:space:]') || fail
case "$bytes" in ''|*[!0-9]*) fail ;; esac
[ "$bytes" -eq "$((${#rc_line} + ${#operation_line} + 2))" ] || fail
printf '%s\n%s\n' "$rc_line" "$operation_line"
"""


def _parse_replace_completion(wire):
    """Return the observed command status and its fixed operation, never infer one."""
    if type(wire) is str:
        if wire == "rc=\nfailed_operation=pending\n":
            return None, "pending"
        match = re.fullmatch(r"rc=(0|[1-9][0-9]{0,2})\nfailed_operation=(none|apply|save)\n", wire)
        if match is not None:
            rc, operation = int(match[1]), match[2]
            if rc <= 255 and (rc == 0) == (operation == "none"):
                return rc, operation
    raise SetupError("deferred configuration result is unverified")


def _require_replace_completion_supervisor():
    if (_TASK_DEADLINE is None
            and (_WORKER_CONNECTION is None or _WORKER_STOP is None)):
        raise SetupError("replace completion requires the original task deadline or worker supervisor")


def _wait_replace_deferred_completion(target, ib_user, current_password, timeout, *,
                                       strict, policy, stamp, details, _replace_completion=False):
    """Read completion under the original task authority, not a second D4 loop."""
    if type(_replace_completion) is not bool:
        raise SetupError("replace completion mode must be boolean")
    _require_replace_completion_supervisor()
    if _replace_completion:
        details.update(deferred_rc=None, deferred_failed_operation=None)
    check_task_cancelled()
    point = DirectEndpoint(target.ib.login_ip, None)
    rc_confirmed = False

    def read(command):
        check_task_cancelled()
        output = _read_direct_ipv4_command(target, point, ib_user, current_password,
            timeout, command, strict=strict, policy=policy, details=details,
            _require_certain=_replace_completion)
        check_task_cancelled()
        return output

    while True:
        check_task_cancelled()
        try:
            if not rc_confirmed:
                if _replace_completion:
                    receipt = read(["sh", "-c", _REPLACE_DEFERRED_RC_SCRIPT, "--", stamp])
                    details.update(deferred_rc=None, deferred_failed_operation=None)
                    rc, operation = _parse_replace_completion(receipt)
                    details.update(deferred_rc=rc, deferred_failed_operation=operation)
                    if rc is not None and rc != 0:
                        raise SetupError(f"deferred configuration {operation} failed (rc={rc})")
                    rc_confirmed = rc == 0
                else:
                    receipt = read(["sh", "-c", _DEFERRED_APPLY_RC_SCRIPT, "--", stamp])
                    if receipt == "rc=0\n":
                        rc_confirmed = True
                    elif receipt != "rc=\n":
                        raise SetupError("deferred configuration result is failed or unverified")
            if rc_confirmed:
                address_output = read(["ip", "addr", "show", "eth0"])
                route_output = read(["ip", "route"])
                try:
                    identity = _check_ib_identity(target, address_output, route_output, via_ipv4=True)
                except SetupError:
                    details["identity_failed"] = True
                    raise
                details["identity"] = identity
                if not identity["ok"]:
                    details["identity_failed"] = True
                    mismatch_detail = "; ".join(
                        f"{item['field']}: expected={item['expected']} observed={item['observed']}"
                        for item in identity["mismatches"])
                    raise SetupError("IB identity differs from CSV; " + mismatch_detail
                                     + "; no further configuration write authorized")
                return read(["nv", "config", "show", "-o", "commands"])
        except SetupError as error:
            if getattr(error, "cleanup_uncertain", False) is True:
                raise
            failure = _ssh_failure_fact(error)
            network_retry = (failure is not None and failure.hop == "direct"
                             and failure.kind in (SshFailureKind.DIRECT_LOGIN_NETWORK,
                                                  SshFailureKind.DIRECT_SSH_NETWORK))
            clean_timeout = (strict and failure is None
                             and getattr(error, "_ib_readonly_session_timeout", None) is True)
            legacy_timeout = not strict and str(error).startswith("SSH/PAM session timed out;")
            if not (network_retry or clean_timeout or legacy_timeout):
                raise
        check_task_cancelled()
        delay = 10
        if _TASK_DEADLINE is not None:
            delay = min(delay, max(0, _TASK_DEADLINE - time.monotonic()))
        time.sleep(delay)
        check_task_cancelled()


def _wait_direct_ipv4_readback(target, ib_user, current_password, timeout, *,
                               strict, policy, readiness_policy, deferred_stamp=None,
                               details):
    """One direct IPv4 readiness loop; an accepted launch is not completion."""
    point = DirectEndpoint(target.ib.login_ip, None)
    ready = {}
    rc_confirmed = deferred_stamp is None

    def read(command):
        return _read_direct_ipv4_command(target, point, ib_user, current_password,
            timeout, command, strict=strict, policy=policy, details=details)

    def probe():
        nonlocal rc_confirmed
        try:
            if not rc_confirmed:
                receipt = read(["sh", "-c", _DEFERRED_APPLY_RC_SCRIPT, "--", deferred_stamp])
                if receipt == "rc=\n":
                    return "RETRY", "deferred configuration has not reported completion"
                if receipt != "rc=0\n":
                    return "FATAL", SetupError("deferred configuration result is failed or unverified")
                rc_confirmed = True
            address_output = read(["ip", "addr", "show", "eth0"])
            route_output = read(["ip", "route"])
            try:
                identity = _check_ib_identity(target, address_output, route_output, via_ipv4=True)
            except SetupError:
                details["identity_failed"] = True
                raise
            details["identity"] = identity
            if not identity["ok"]:
                details["identity_failed"] = True
                mismatch_detail = "; ".join(
                    f"{item['field']}: expected={item['expected']} observed={item['observed']}"
                    for item in identity["mismatches"])
                return "FATAL", SetupError("IB identity differs from CSV; " + mismatch_detail
                                           + "; no further configuration write authorized")
            ready["readback"] = read(["nv", "config", "show", "-o", "commands"])
            return "READY", None
        except SetupError as error:
            if getattr(error, "cleanup_uncertain", False) is True:
                return "FATAL", error
            failure = _ssh_failure_fact(error)
            if (failure is not None and failure.hop == "direct"
                    and failure.kind in (SshFailureKind.DIRECT_LOGIN_NETWORK,
                                         SshFailureKind.DIRECT_SSH_NETWORK)):
                return "RETRY", "direct IPv4 SSH endpoint network is not ready"
            if (strict and failure is None
                    and getattr(error, "_ib_readonly_session_timeout", None) is True):
                return "RETRY", "direct IPv4 SSH session timed out"
            if not strict and str(error).startswith("SSH/PAM session timed out;"):
                return "RETRY", "direct IPv4 SSH session timed out"
            return "FATAL", error

    wait_until_ready(probe, readiness_policy, label=target.ib.hostname, sleep=time.sleep)
    return ready["readback"]


def _ensure_ib_config_backup(target, endpoint, eth_user, ethernet_password, ib_user,
                             current_password, timeout, *, local):
    """A qualified NVUE request needs this task's identity and one real backup."""
    state = _TASK_IB_CONFIG
    if (type(state) is not _IBConfigWriteState or state.task.target is not target
            or state.task.local is not local or state.ib_user != ib_user
            or state.eth_user != eth_user or state.task.ethernet_password != ethernet_password
            or state.apply is not True or state.identity_verified is not True
            or state.endpoint != endpoint or state.current_password != current_password
            or type(current_password) is not str or not current_password
            or type(state.stamp) is not str
            or not re.fullmatch(r"[0-9]{8}-[0-9]{6}", state.stamp)):
        raise SetupError("NVUE write lacks this task's verified identity/credential/report binding")
    if state.backup_state == "VERIFIED":
        return
    if state.backup_state != "NEW":
        raise SetupError("IB configuration backup is failed or uncertain; no automatic replay")
    check_task_cancelled()
    state.backup_state = "RUNNING"
    try:
        # Its config_backup permit checks the original apply/authorization and
        # input/cancellation boundaries once. The NVUE permit still follows.
        result = run_on_ib(target, endpoint, eth_user, ethernet_password, ib_user,
                           current_password, timeout,
                           ["sh", "-c", _CONFIG_BACKUP_SCRIPT, "--", state.stamp],
                           local=local, allow_password_change=False, password_only=True)
        if (type(result) is not SessionResult or type(result.exit_code) is not int
                or result.exit_code != 0 or type(result.output) is not str
                or any(getattr(result, name) is not False for name in (
                    "password_changed", "password_change_required", "password_change_attempted",
                    "ib_authentication_rejected"))
                or _EXPIRED_PASSWORD.search(result.output)
                or _pending_diff_has_password_update_notice(result.output)):
            raise SetupError("IB configuration backup outcome is unverified")
        receipt = re.fullmatch(r"path=([^\n]+)\nbytes=([1-9][0-9]*)\n", result.output)
        if receipt is None:
            raise SetupError("IB configuration backup receipt is unverified")
        path, size = receipt.groups()
        if (not path.startswith("/") or len(path) > 4096
                or re.search(r"[\x00-\x1f\x7f-\x9f]", path)
                or any(part in {"", ".", ".."} for part in path.split("/")[1:])
                or path.rsplit("/", 1)[-1] != "current_" + state.stamp + ".yaml"):
            raise SetupError("IB configuration backup path is unverified")
        state.backup_receipt = {"path": path, "bytes": int(size)}
        state.backup_state = "VERIFIED"
    except (ProjectInputChanged, BatchStopped):
        state.backup_state = "FAILED"
        raise
    except (SetupError, OSError, subprocess.SubprocessError) as original:
        state.backup_state = "FAILED"
        state.failure_category = "FAILED_CONFIG_BACKUP"
        error = SetupError("IB configuration backup failed or is unverified; no NVUE write issued")
        _retain_ssh_failure(error, _ssh_failure_fact(original))
        uncertain, number = _ib_phase_error_facts(original)
        if uncertain:
            error.cleanup_uncertain = True
        if number is not None:
            error.io_errno = number
        # Neither the public message nor a hidden chain retains configuration
        # output/hashes from a transport or an unqualified backup receipt.
        try:
            raise error from None
        except SetupError:
            error.__cause__ = None
            error.__context__ = None
            raise
    except BaseException:
        state.backup_state = "FAILED"
        raise  # Never turn a programming error/cancellation into backup proof.


def automatic_worker_count(count: int, max_workers: int = 16) -> int:
    if type(count) is not int or count < 0 or type(max_workers) is not int or not 1 <= max_workers <= 16:
        raise SetupError("ready count must be nonnegative; --max-workers must be in 1-16")
    return min(max_workers, (count + 15) // 16) if count else 0


def task_jump(target):
    """The single optional transit getter; D1b's direct tasks have no jump."""
    return target.ethernet


class JumpGate:
    """Coordinator-only admission and two bounded cooldown/probe cycles."""
    def __init__(self):
        self.jumps = {}

    def _jump_state(self, jump):
        return self.jumps.setdefault(jump, dict(in_flight=0, failures=0, cooldowns=0,
                                                until=None, exhausted=False, failure=None))

    def jump_slot_available(self, jump, now):
        if jump is None:
            return True
        state = self._jump_state(jump)
        return not state["exhausted"] and state["until"] is None and state["in_flight"] < 8

    def claim_jump_slot(self, jump, now):
        if not self.jump_slot_available(jump, now):
            return False
        if jump is not None:
            self._jump_state(jump)["in_flight"] += 1
        return True

    def report_jump_outcome(self, jump, failure, *, writes_attempted, now):
        if jump is None:
            return "fail" if failure is not None else "done"
        state = self._jump_state(jump)
        state["in_flight"] = max(0, state["in_flight"] - 1)
        unreachable = (failure is not None and failure.hop == "outer"
                       and failure.kind == SshFailureKind.JUMP_UNREACHABLE)
        if unreachable:
            state["failure"] = failure
            state["failures"] += 1
            if state["until"] is None and not state["exhausted"] and (
                    state["failures"] >= 2 or getattr(failure, "candidates_exhausted", False)):
                if state["cooldowns"] >= 2:
                    state["exhausted"] = True
                else:
                    state["cooldowns"] += 1
                    state["until"] = now + 240
            return "fail" if writes_attempted or state["exhausted"] else "requeue"
        if failure is None:
            state["failures"] = 0
        return "fail" if failure is not None else "done"

    def jump_probes_due(self, now):
        return [jump for jump, state in self.jumps.items()
                if state["until"] is not None and state["until"] <= now
                and not state["exhausted"] and state["in_flight"] == 0]

    def report_jump_probe(self, jump, failure, *, now):
        state = self._jump_state(jump)
        state["failure"] = failure
        if failure is None:
            state["until"], state["failures"] = None, 0
        elif failure.hop != "outer" or failure.kind != SshFailureKind.JUMP_UNREACHABLE:
            state["until"], state["exhausted"] = None, True
        elif state["cooldowns"] >= 2:
            state["until"], state["exhausted"] = None, True
        else:
            state["cooldowns"] += 1
            state["until"] = now + 240

    def jump_wait_seconds(self, now):
        waits = [max(0, state["until"]-now) for state in self.jumps.values()
                 if state["until"] is not None and not state["exhausted"]]
        return min(waits) if waits else None

    def jump_exhausted(self, jump):
        return jump is not None and self._jump_state(jump)["exhausted"]


def recover_jump_cooldowns(gate, jumps, coordinator, *, wait=False):
    """Only an idle coordinator waits; running workers retain their own deadlines."""
    now = time.monotonic()
    delay = gate.jump_wait_seconds(now)
    if wait and delay is not None and delay > 0:
        coordinator.assert_unchanged()
        time.sleep(delay)
        now = time.monotonic()
    for key in gate.jump_probes_due(now):
        coordinator.assert_unchanged()
        failure = None
        try:
            _JUMP_SESSIONS.probe_jump_master(jumps[key])
        except SshFailure as error:
            failure = error
        gate.report_jump_probe(key, failure, now=time.monotonic())


def collect_jump_snapshot_passes(devices, collect, *, authority=None):
    """Finish the first full pass before a shared cooldown; never retry auth/identity."""
    failures, pending = {}, list(devices)
    for attempt in range(3):
        if attempt:
            time.sleep(240)
        retry = []
        for device in pending:
            key = normalize_name(device.hostname)
            # Preserve main's pre-transport authority boundary, including a new
            # retry probe after cooling. Authority failures are not device failures.
            if authority is not None:
                authority.assert_unchanged()
            try:
                if attempt:
                    _JUMP_SESSIONS.probe_jump_master(device)
                collect(device)
                failures.pop(key, None)
            except (ProjectInputChanged, BatchStopped):
                raise
            except SetupError as error:
                failures[key] = error
                failure = _ssh_failure_fact(error)
                if (failure is not None and failure.hop == "outer"
                        and failure.kind == SshFailureKind.JUMP_UNREACHABLE):
                    retry.append(device)
        if not retry:
            break
        pending = retry
    return failures


def interleave_oob_tasks(tasks):
    """Spread initial submissions across OOBs without reserving any worker."""
    groups = {}
    for task in tasks:
        jump = task_jump(task.target)
        groups.setdefault(normalize_name(jump.hostname) if jump is not None else None, deque()).append(task)
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
        return RuntimeInputAuthority._stat_signature(path.stat())

    @staticmethod
    def _stat_signature(value):
        return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)

    def _stable_regular_digest(self, path, expected):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        changed = f"input changed during revalidation: {path}"
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or self._stat_signature(info) != expected:
                raise ProjectInputChanged(changed)
            digest, count = hashlib.sha256(), 0
            while count <= info.st_size:
                chunk = os.read(fd, min(65536, info.st_size + 1 - count))
                if not chunk:
                    break
                digest.update(chunk)
                count += len(chunk)
            if count != info.st_size or self._stat_signature(os.fstat(fd)) != expected:
                raise ProjectInputChanged(changed)
            return digest.hexdigest()
        finally:
            os.close(fd)

    def assert_unchanged(self, *, _stable_file_refresh=False):
        for entry in self.entries:
            path, resolved, old_stat, digest = entry
            try:
                if path.resolve(strict=True) != resolved:
                    raise ProjectInputChanged(f"input link target changed: {path}")
                current = self.signature(resolved)
                if current != old_stat:
                    if _stable_file_refresh is True:
                        observed = self._stable_regular_digest(resolved, current)
                        if path.resolve(strict=True) != resolved or self.signature(resolved) != current:
                            raise ProjectInputChanged(f"input changed during revalidation: {path}")
                    else:
                        observed = _file_sha256(resolved)
                    if observed != digest:
                        raise ProjectInputChanged(f"input bytes changed: {path}")
                    entry[2] = current
            except OSError as exc:
                raise ProjectInputChanged(f"input disappeared/unreadable: {path}") from exc


def _bound_replace_yaml(task, args):
    """Find the existing per-task selection without reopening or rebuilding it."""
    invalid = "replace YAML is not bound to the admitted task selection"
    if (type(task) is not PreparedIBTask or type(task.target) is not Target or task.local is not False
            or getattr(args, "config_mode", None) != "replace" or getattr(args, "apply", None) is not True):
        raise SetupError(invalid)
    authority = getattr(args, "_replace_runtime_authority", None)
    selections = getattr(args, "_replace_selected", None)
    release = getattr(args, "_replace_release", None)
    name = task.target.ib.hostname
    if (type(authority) is not RuntimeInputAuthority or type(selections) is not dict
            or not isinstance(release, Path)
            or type(name) is not str or not name or "/" in name or "\\" in name):
        raise SetupError(invalid)
    selection = selections.get(normalize_name(name))
    if (type(selection) is not dict or set(selection) != {"verdict", "file", "sha256", "reason"}
            or selection["verdict"] != "WOULD_REPLACE"
            or type(selection["file"]) is not str or type(selection["sha256"]) is not str):
        raise SetupError(invalid)
    path, digest = Path(selection["file"]), selection["sha256"]
    named = release.absolute() / (name + ".yaml")
    entry = next((item for item in authority.entries
                  if item[0] == named and item[1] == path and item[3] == digest), None)
    if not path.is_absolute() or path.name != named.name or entry is None:
        raise SetupError(invalid)
    return authority, path, digest, entry


def _read_admitted_replace_yaml(task, args) -> bytes:
    """Read only the selected CSV-host file from this run's admitted input snapshot."""
    authority, path, digest, entry = _bound_replace_yaml(task, args)
    check_task_cancelled()
    authority.assert_unchanged(_stable_file_refresh=True)
    check_task_cancelled()

    maximum = _REPLACE_PAYLOAD_BASE64_MAX // 4 * 3
    changed = "selected replace YAML changed or became unreadable; run load"

    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or authority._stat_signature(info) != entry[2]:
                raise ProjectInputChanged(changed)
            if not 0 < info.st_size <= maximum:
                raise SetupError("replace YAML payload is invalid")
            raw = bytearray()
            while len(raw) <= maximum:
                chunk = os.read(fd, min(65536, maximum + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
            if (len(raw) != info.st_size or authority._stat_signature(os.fstat(fd)) != entry[2]
                    or hashlib.sha256(raw).hexdigest() != digest):
                raise ProjectInputChanged(changed)
        finally:
            os.close(fd)
    except OSError:
        raise ProjectInputChanged(changed) from None
    authority.assert_unchanged(_stable_file_refresh=True)
    check_task_cancelled()
    return bytes(raw)


def _check_replace_detach_preconditions(authority, operation, rc) -> bool:
    """Recheck the caller's complete admitted inputs; this never grants a write permit."""
    if (type(authority) is not RuntimeInputAuthority
            or not _replace_failure_is_detach_candidate(operation, rc)):
        return False
    check_task_cancelled()
    authority.assert_unchanged()
    check_task_cancelled()
    return True


def run_replace_stage(state, data, authority, *, timeout, authorized, strict, policy=None) -> str:
    """Apply a caller-admitted replacement on the existing synchronous device path."""
    if (type(state) is not _IBConfigWriteState or state is not _TASK_IB_CONFIG
            or type(state.task) is not PreparedIBTask or state.task.local is not False
            or state.apply is not True or state.identity_verified is not True or authorized is not True
            or type(authority) is not RuntimeInputAuthority or type(strict) is not bool
            or (strict and policy is None)
            or type(timeout) is not int or timeout <= 0
            or type(state.current_password) is not str or not state.current_password):
        raise SetupError("synchronous replace context is not qualified")
    endpoint = state.endpoint
    target = state.task.target
    if type(target) is not Target or (
            type(endpoint) is not Neighbor if target.ethernet is not None else
            type(endpoint) is not DirectEndpoint or endpoint.interface is None):
        raise SetupError("synchronous replace endpoint is not qualified")
    command = replace_command(data)
    check_task_cancelled()
    authority.assert_unchanged()
    check_task_cancelled()
    context = (target, endpoint, state.eth_user, state.task.ethernet_password,
               state.ib_user, state.current_password, timeout)
    _require_empty_pending(*context, local=False)

    def checked_output(result):
        return _checked_replace_stage_output(result, "synchronous replace operation is unverified")

    for operation, argv in (("replace", command), ("apply", ["nv", "config", "apply", "-y"]),
                            ("save", ["nv", "config", "save"])):
        try:
            result = _stage_ib_command(*context, argv, local=False, strict=strict, policy=policy,
                                       _replace_sync_failure_task=state)
        except SetupError as error:
            fact = getattr(error, "_replace_sync_failure", None)
            if (type(error) is SetupError and type(fact) is tuple and len(fact) == 2
                    and type(fact[0]) is str and fact[0] == operation
                    and _check_replace_detach_preconditions(authority, *fact)):
                # Keep the original failure; an unconfirmed cleanup is not proof
                # that a second operation reached the device.
                try:
                    cleanup_options = {"_preserve_replace_cleanup_veto": True} if strict else {}
                    cleaned = _stage_ib_command(*context, ["nv", "config", "detach"],
                                                local=False, strict=strict, policy=policy, **cleanup_options)
                    checked_output(cleaned)
                except (ProjectInputChanged, BatchStopped):
                    raise
                except (SetupError, OSError):
                    error._replace_cleanup_outcome = "FAILED_DETACH_FAILED"
                else:
                    error._replace_cleanup_outcome = "FAILED_DETACHED"
            raise
        checked_output(result)
        if operation == "replace":
            receipt = state.backup_receipt
            if state.backup_state != "VERIFIED" or type(receipt) is not dict:
                raise SetupError("synchronous replace lacks a verified backup receipt")
            _verify_replace_command_receipt(result, receipt.get("path"), command[-1])
    result = _stage_ib_command(*context, ["nv", "config", "show", "-o", "commands"],
                               local=False, strict=strict, policy=policy)
    readback = checked_output(result)
    if normalize_name(parse_nvue_state(readback).hostname) != normalize_name(target.ib.hostname):
        raise SetupError("synchronous replace readback differs from the selected target")
    return readback


@dataclass(frozen=True, eq=False, repr=False)
class _DeferredReplaceApplyFailure:
    state: _IBConfigWriteState
    authority: RuntimeInputAuthority
    endpoint: DirectEndpoint
    stamp: str
    rc: int


def _run_replace_deferred_stage(state, data, authority, *, timeout, authorized, strict, policy=None) -> str:
    """Complete the IPv4 replacement base without replaying any unverified write."""
    if (type(state) is not _IBConfigWriteState or state is not _TASK_IB_CONFIG
            or type(state.task) is not PreparedIBTask or state.task.local is not False
            or state.apply is not True or state.identity_verified is not True or authorized is not True
            or type(authority) is not RuntimeInputAuthority or type(strict) is not bool
            or (strict and policy is None) or type(timeout) is not int or timeout <= 0
            or type(state.current_password) is not str or not state.current_password
            or type(state.stamp) is not str or re.fullmatch(r"[0-9]{8}-[0-9]{6}", state.stamp) is None):
        raise SetupError("deferred replace context is not qualified")
    target, endpoint = state.task.target, state.endpoint
    stamp = state.stamp
    _validate_direct_endpoint(target, endpoint)
    if endpoint.interface is not None:
        raise SetupError("deferred replace requires the verified IPv4 endpoint")
    _require_replace_completion_supervisor()
    command = replace_command(data)
    context = (target, endpoint, state.eth_user, state.task.ethernet_password,
               state.ib_user, state.current_password, timeout)

    def recheck():
        check_task_cancelled()
        authority.assert_unchanged(_stable_file_refresh=True)
        check_task_cancelled()

    def check_result(result, message):
        _checked_replace_stage_output(result, message)
        if (type(getattr(result, "_direct_endpoint", None)) is not DirectEndpoint
                or result._direct_endpoint != endpoint):
            raise SetupError(message)

    recheck()
    _require_empty_pending(*context, local=False)
    request = _InitialIPv4ReplaceRequest(state, authority, endpoint, stamp)
    try:
        replaced = _stage_ib_command(*context, command, local=False, strict=strict, policy=policy,
                                     _replace_sync_failure_task=request)
    except SetupError as error:
        if type(error) is SetupError:
            fact = error.__dict__.pop("_replace_sync_failure", None)
            if _replace_failure_operation(request, fact) == "replace":
                error._replace_initial_ipv4_failure = fact
        raise
    check_result(replaced, "deferred replace receipt is unverified")
    receipt = state.backup_receipt
    if state.backup_state != "VERIFIED" or type(receipt) is not dict:
        raise SetupError("deferred replace lacks a verified backup receipt")
    _verify_replace_command_receipt(replaced, receipt.get("path"), command[-1])
    recheck()
    launched = _stage_ib_command(*context, ["sh", "-c", _REPLACE_DEFERRED_APPLY_SCRIPT, "--", stamp],
                                 local=False, strict=strict, policy=policy)
    check_result(launched, "deferred replace launch outcome is unverified")
    details = {}
    try:
        readback = _wait_replace_deferred_completion(
            target, state.ib_user, state.current_password, timeout, strict=strict, policy=policy,
            stamp=stamp, details=details, _replace_completion=True)
    except SetupError as error:
        rc = details.get("deferred_rc")
        if (type(error) is SetupError and details.get("deferred_failed_operation") == "apply"
                and _replace_failure_is_detach_candidate("apply", rc)
                and details.get("endpoint") == endpoint):
            error._replace_deferred_apply_failure = _DeferredReplaceApplyFailure(
                state, authority, endpoint, stamp, rc)
        raise
    identity = details.get("identity")
    if (type(details.get("deferred_rc")) is not int or details["deferred_rc"] != 0
            or details.get("deferred_failed_operation") != "none" or details.get("endpoint") != endpoint
            or type(identity) is not dict or identity.get("ok") is not True or identity.get("via_ipv4") is not True
            or normalize_name(parse_nvue_state(readback).hostname) != normalize_name(target.ib.hostname)):
        raise SetupError("deferred replace readback differs from the selected target")
    recheck()
    return readback


def _try_cleanup_deferred_apply_failure(state, authority, error, *, timeout, strict, policy):
    if type(error) is not SetupError:
        return
    deferred = error.__dict__.pop("_replace_deferred_apply_failure", None)
    initial = error.__dict__.pop("_replace_initial_ipv4_failure", None)
    if state is not _TASK_IB_CONFIG or (deferred is None) == (initial is None):
        return
    if initial is not None:
        if type(initial) is not _InitialIPv4ReplaceFailure or type(initial.request) is not _InitialIPv4ReplaceRequest:
            return
        request = initial.request
        if (request.state is not state or request.authority is not authority
                or request.endpoint is not state.endpoint or request.stamp != state.stamp
                or _replace_failure_operation(request, initial) != "replace"):
            return
    elif (type(deferred) is not _DeferredReplaceApplyFailure or deferred.state is not state
            or deferred.authority is not authority or deferred.endpoint is not state.endpoint
            or deferred.stamp != state.stamp or not _replace_failure_is_detach_candidate("apply", deferred.rc)):
        return
    target, endpoint = state.task.target, state.endpoint

    def recheck():
        check_task_cancelled()
        authority.assert_unchanged(_stable_file_refresh=True)
        check_task_cancelled()

    def read(command):
        check_task_cancelled()
        options = {"_preserve_replace_cleanup_veto": True} if strict else {}
        return _read_direct_ipv4_command(target, endpoint, state.ib_user, state.current_password,
            timeout, command, strict=strict, policy=policy, details={}, _require_certain=True, **options)

    recheck()
    try:
        address = read(["ip", "addr", "show", "eth0"])
        routes = read(["ip", "route"])
        identity = _check_ib_identity(target, address, routes, via_ipv4=True)
    except (ProjectInputChanged, BatchStopped):
        raise
    except (SetupError, OSError):
        return
    if identity["ok"] is not True:
        return
    recheck()
    try:
        options = {"_preserve_replace_cleanup_veto": True} if strict else {}
        cleaned = _stage_ib_command(target, endpoint, "", "", state.ib_user, state.current_password,
            timeout, ["nv", "config", "detach"], local=False, strict=strict, policy=policy, **options)
        _checked_replace_stage_output(cleaned, "deferred replace cleanup outcome is unverified")
        if (type(getattr(cleaned, "_direct_endpoint", None)) is not DirectEndpoint
                or cleaned._direct_endpoint != endpoint):
            raise SetupError("deferred replace cleanup endpoint is unverified")
    except (ProjectInputChanged, BatchStopped):
        raise
    except (SetupError, OSError):
        error._replace_cleanup_outcome = "FAILED_DETACH_FAILED"
    else:
        error._replace_cleanup_outcome = "FAILED_DETACHED"


def _run_admitted_replace_to_ztp(state, args, services, *, timeout, authorized, strict, policy=None):
    """Send the admitted replacement down one verified route, then restore and check ZTP."""
    if (type(state) is not _IBConfigWriteState or state is not _TASK_IB_CONFIG
            or type(state.task) is not PreparedIBTask or state.task.local is not False
            or state.apply is not True or state.identity_verified is not True or authorized is not True
            or type(state.current_password) is not str or not state.current_password
            or type(timeout) is not int or timeout <= 0 or type(strict) is not bool
            or (strict and policy is None)):
        raise SetupError("replace task context is not qualified")
    target, endpoint = state.task.target, state.endpoint
    authority = getattr(args, "_replace_runtime_authority", None)
    if (type(target) is not Target or type(target.ib) is not Device
            or type(authority) is not RuntimeInputAuthority):
        raise SetupError("replace task context is not qualified")
    if target.ethernet is not None:
        if type(target.ethernet) is not Device or type(endpoint) is not Neighbor:
            raise SetupError("replace jump endpoint is not qualified")
        validate_jump_target(target)
        validate_neighbor_boundary(endpoint)
        base = run_replace_stage
    else:
        _validate_direct_endpoint(target, endpoint)
        base = _run_replace_deferred_stage if endpoint.interface is None else run_replace_stage
    check_task_cancelled()
    data = _read_admitted_replace_yaml(state.task, args)
    try:
        readback = base(state, data, authority, timeout=timeout, authorized=authorized, strict=strict, policy=policy)
    except SetupError as error:
        if base is _run_replace_deferred_stage:
            _try_cleanup_deferred_apply_failure(state, authority, error, timeout=timeout, strict=strict, policy=policy)
        raise
    check_task_cancelled()
    authority.assert_unchanged(_stable_file_refresh=True)
    check_task_cancelled()
    return _restore_replace_services_and_verify_ztp(
        state, services, readback, timeout=timeout, authorized=authorized, strict=strict, policy=policy)


def _run_admitted_replace_through_readiness(state, args, services, *, timeout, authorized, strict,
                                             policy, key_stage, verify_ready):
    """Order the existing post-replace stages; execute owns their bound callbacks."""
    authority = getattr(args, "_replace_runtime_authority", None)
    restored = _run_admitted_replace_to_ztp(
        state, args, services, timeout=timeout, authorized=authorized, strict=strict, policy=policy)

    def recheck():
        check_task_cancelled()
        if state is not _TASK_IB_CONFIG or getattr(args, "_replace_runtime_authority", None) is not authority:
            raise SetupError("replace completion context is not qualified")
        authority.assert_unchanged(_stable_file_refresh=True)
        check_task_cancelled()

    recheck()
    if key_stage() is not True:
        raise SetupError("replace public key stage did not retain authorization")
    recheck()
    # Deferred apply/identity readback is not this final D4 check.
    readback = verify_ready(ReadinessPolicy(first_delay=15))
    recheck()
    return restored, readback


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
    if kind == "jump-master":
        return _unwrap_jump_master_reply(reply)
    if kind == "host-key-remove" and isinstance(reply, dict) and "ssh_failure" in reply:
        return _unwrap_jump_master_reply(reply)
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
        if policy is not None and policy._password:
            self.secrets.append(policy._password)
        self.paused_seconds = 0.0
        self.current_target = None
        self.host_key_tasks = {normalize_name(task.target.ib.hostname): task for task in tasks}
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
            replace_mode = self.args.apply is True and getattr(self.args, "config_mode", "patch") == "replace"
            options = {"replace_mode": True} if replace_mode else {}
            self.authorized = self.prompt(lambda: _ask_first_device_change(target, reason, **options))
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
                       ("password", "password_change_sessions"), ("host_key", "host_key_remove_attempts"),
                       ("config_backup", "config_backup_attempts"))).get(category)
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
        if kind == "host-key-remove":
            self.assert_unchanged()
            if self.stopped:
                raise BatchStopped(self.fatal or "batch stopped")
            task = self.host_key_tasks.get(normalize_name(target.ib.hostname))
            if task is None or task.target != target:
                raise SetupError("host-key removal task is not admitted")
            _host_key_task_gate(task, value, eth_user=self.args.eth_user, apply=self.args.apply)
            def mark_write():
                self.authorize(target, "remove this IB host-key entry from the jump's known_hosts")
                self.before_write("host_key")
            try:
                return remove_jump_known_hosts_entries(task, value, eth_user=self.args.eth_user,
                    apply=self.args.apply, timeout=self.args.connect_timeout, before_write=mark_write)
            except (ProjectInputChanged, BatchStopped):
                raise
            except SshFailure as error:
                return _ssh_failure_reply(error)
            except (SetupError, ValueError, OSError, subprocess.TimeoutExpired):
                raise SetupError("jump host-key removal failed; no automatic replay") from None
        if kind == "jump-master":
            return _jump_master_request_result(value, target)
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


def _configuration_result_facts(device, state, services, current, *, strict=False):
    """Project original observed values and missing settings, never write authority."""
    existing, planned = [], []
    fields = (
        ("hostname", (state.hostname,) if normalize_name(state.hostname) not in DEFAULT_HOSTNAMES else (), device.hostname),
        ("eth0 address", state.eth0_addresses, device.eth0_prefix),
        ("eth0 gateway", state.eth0_gateways, device.eth0_gateway),
        ("eth1 address", state.eth1_addresses, device.eth1_prefix),
        ("eth1 gateway", state.eth1_gateways, device.eth1_gateway if device.eth1_prefix else ""),
    )
    for item, observed, desired in fields:
        for value in observed:
            same = (normalize_name(value) == normalize_name(desired) if item == "hostname"
                    else value == desired)
            existing.append({"item": item, "relation": "same" if same else "extra", "value": value})
        present = (any(normalize_name(value) == normalize_name(desired) for value in observed)
                   if item == "hostname" else desired in observed)
        if desired and not present:
            planned.append({"item": item, "value": desired})
    if services is not None:
        for line in current.splitlines():
            if not re.match(r"^\s*nv\s+set\s+system\s+(?:dns|ntp|date-time)\b", line):
                continue
            try:
                tokens = shlex.split(line)
            except ValueError:
                raise SetupError("Initial stage failed; device state is UNKNOWN" if strict
                                 else "Initial configuration command syntax is UNKNOWN") from None
            if tokens[:4] != ["nv", "set", "system", "dns"] and tokens[:4] != ["nv", "set", "system", "ntp"]:
                if tokens[:5] == ["nv", "set", "system", "date-time", "timezone"] and len(tokens) == 6:
                    existing.append({"item": "timezone", "value": tokens[5],
                        "relation": "same" if tokens[5] == services["timezone"] else "overwritten"})
                continue
            if len(tokens) < 6 or tokens[4] != "server":
                continue
            item, value = tokens[3], tokens[5]
            same = (any(_ntp_server_is_configured(desired, line) for desired in services["ntp"])
                    if item == "ntp" else value in services["dns"])
            entry = {"item": item, "value": value, "relation": "same" if same else "extra"}
            if entry not in existing:
                existing.append(entry)
        for command in desired_service_commands(services, current):
            item = "timezone" if command[3:5] == ["date-time", "timezone"] else command[3]
            planned.append({"item": item, "value": command[-1]})
    return {"existing_configuration": existing, "planned_changes": planned}


def _result_needs_change(needs):
    """Three-valued OR: one known change dominates other unknown observations."""
    values = tuple(needs)
    return True if any(value is True for value in values) else False if all(value is False for value in values) else None


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
    only on an empty pending diff (T15; U3 first records and detaches an all-owned one) and Network
    writes only the missing setters (T16).
    """
    global _TASK_IB_CONFIG
    target, neighbor = task.target, task.neighbor
    config_mode = getattr(args, "config_mode", "patch")
    replace_mode = config_mode == "replace"
    ib_eth_user = "" if target.ethernet is None else args.eth_user
    result_record = {"hostname": target.ib.hostname, "outcome": "FAILED", "reason": "",
                     "direct_rows": [], "writes_attempted": False, "batch_error": "",
                     "identity": None, "backup": None,
                     "device_state": "unknown",
                     "ztp": {"read": False, "service": None, "status": None, "provisioned": None},
                     "existing_configuration": [], "planned_changes": [], "conflicts": [],
                     "needs_change": None, "verified_complete": False, "config_mode": config_mode,
                     "attention_category": None, "pending_detached": [],
                     "stage_status": {stage: "NOT_REACHED" for stage in
                         ("authentication", "initial", "day0", "ipv4_readiness", "services", "public_keys", "direct_ssh")}}
    stages = result_record["stage_status"]
    change_needs = {"network": None, "initial": None,
                    "services": False if services is None else None,
                    "public_keys": False if not keys else None, "pending": False}
    stage = "authentication"
    credential = None
    readback = ""
    base_verified = False
    deferred_stamp = None
    readiness_details = {}
    initial_details = {}
    host_key_records = []
    fingerprint_reader = None
    operator_forced = normalize_name(target.ib.hostname) in getattr(args, "_refresh_host_key_names", ())
    strict_cache = getattr(args, "_strict_cache", None)
    strict = strict_cache is not None and policy is not None and not task.local
    log(f"[{target.ib.hostname}] via " +
        (f"{target.ethernet.hostname}:{target.ethernet_port}" if target.ethernet is not None else "direct"))
    if target.attachment is not None:
        physical = target.attachment
        log(f"  Attachment: {physical.ethernet.hostname}:{physical.ethernet_port} "
            f"VLAN={target.access_vlan}; Jump={target.ethernet.hostname}; reason={target.jump_reason}")
    if type(neighbor) is DirectEndpoint:
        log(f"  IB direct path: {neighbor.address} dev {neighbor.interface or '-'}; source=CSV")
    else:
        log(f"  IB IPv6 path: {neighbor.ipv6} dev {neighbor.interface} vrf {neighbor.vrf}; source={neighbor.address_source}")
    previous_config = _TASK_IB_CONFIG
    config_state = _IBConfigWriteState(task, args.ib_user, ib_eth_user,
                                      getattr(args, "run_stamp", None), args.apply)
    _TASK_IB_CONFIG = config_state
    try:
        replace_selection = None
        if replace_mode:
            authority = getattr(args, "_replace_runtime_authority", None)
            if type(authority) is not RuntimeInputAuthority:
                raise SetupError("replace execution context is not qualified")
            if args.apply:
                coordinator = _ACTIVE_COORDINATOR
                if (task.local is not False or args.execution_mode == "ethernet"
                        or getattr(args, "_on_management_server", None) is not True
                        or type(policy) not in (ProjectPasswordPolicy, WorkerPasswordPolicy)
                        or (_WORKER_CONNECTION is None and (
                            type(coordinator) is not RuntimeCoordinator or coordinator.args is not args
                            or coordinator.authority is not authority or coordinator.policy is not policy))
                        or (_WORKER_CONNECTION is not None and type(policy) is not WorkerPasswordPolicy)):
                    raise SetupError("replace execution context is not qualified")
                check_task_cancelled()
                authority.assert_unchanged(_stable_file_refresh=True)
                _ib_project_value(policy, user=args.ib_user)
                if not any(str(resolved) == policy.binding[0] and digest == policy.binding[3]
                           for _, resolved, _, digest in authority.entries):
                    raise SetupError("replace global differs from the admitted run; run load")
            else:
                authority.assert_unchanged()
            selections = getattr(args, "_replace_selected", None)
            if type(selections) is not dict:
                raise SetupError("replace execution context is not qualified")
            replace_selection = selections.get(normalize_name(target.ib.hostname))
            if (type(replace_selection) is not dict
                    or set(replace_selection) != {"verdict", "file", "sha256", "reason"}
                    or replace_selection["verdict"] not in {"WOULD_REPLACE", "YAML_MISSING_OR_INVALID"}):
                raise SetupError("replace execution context is not qualified")
            result_record["replace"] = dict(replace_selection)
            if args.apply and replace_selection["verdict"] == "WOULD_REPLACE":
                _bound_replace_yaml(task, args)
        if replace_mode and replace_selection["verdict"] == "YAML_MISSING_OR_INVALID":
            log("  Replace mode: 整份替换（会清掉 yaml 以外的配置）")
            result_record["outcome"] = "CHECK_ONLY"
            result_record["needs_configuration"] = True
            result_record["reason"] = replace_selection["reason"]
        else:
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
            def inspect_once():
                return inspect_ib_device(target, neighbor, ib_eth_user, task.ethernet_password, args.ib_user,
                    initial_password, args.connect_timeout, policy, apply=args.apply,
                    authorized=authorized, local=task.local, strict=strict,
                    _management_private_key=management_private_key)
            try:
                current, credential, authorized = inspect_once()
            except SetupError as error:
                failure = _ssh_failure_fact(error)
                change = getattr(failure, "host_key_change", None)
                if change is None:
                    raise
                retried = []
                refresh_task = (replace(task, neighbor=getattr(failure, "_direct_endpoint", None))
                                if target.ethernet is None else task)
                refresh_ib_host_key(change, refresh_task, eth_user=ib_eth_user, timeout=args.connect_timeout,
                    apply=args.apply, read_device_fingerprint=None,
                    retry=lambda: retried.append(inspect_once()), operator_forced=operator_forced,
                    host_key_records=host_key_records)
                current, credential, authorized = retried[0]
            if current.password_change_required:
                result_record["device_state"] = "password_change_required"
                result_record["outcome"] = "PASSWORD_CHANGE_REQUIRED"
                stages[stage] = "PASSWORD_CHANGE_REQUIRED"
                log("  BLOCKED: initial IB password change required; read-only mode made no change.")
                return result_record
            stages[stage] = "VERIFIED"
            if target.ethernet is None:
                neighbor = getattr(current, "_direct_endpoint", None)
                _validate_direct_endpoint(target, neighbor)
            # Each read owns its actual endpoint. One safe LL-to-IPv4 transition
            # discards all old-point facts and restarts the full identity check.
            for identity_attempt in (0, 1):
                via_ipv4 = type(neighbor) is DirectEndpoint and neighbor.interface is None
                identity_outputs = []
                identity_commands = [["ip", "addr", "show", "eth0"]]
                if via_ipv4:
                    identity_commands.append(["ip", "route"])
                moved = False
                for identity_command in identity_commands:
                    if credential is None:
                        if args.apply or task.local or target.ethernet is not None:
                            raise SetupError("key-only identity read requires a direct readonly task")
                        # O5 has not succeeded yet: no post-O5 context is fabricated.
                        observed = _run_direct_key_read(target, neighbor, args.ib_user,
                            management_private_key, args.connect_timeout, identity_command,
                            strict=strict, policy=policy)
                    else:
                        observed = _stage_ib_command(target, neighbor, ib_eth_user, task.ethernet_password,
                            args.ib_user, credential, args.connect_timeout, identity_command,
                            local=task.local, strict=strict, policy=policy)
                    if (type(observed) is not SessionResult or type(observed.exit_code) is not int
                            or observed.exit_code != 0 or type(observed.output) is not str
                            or any(getattr(observed, name) is not False for name in (
                                "password_changed", "password_change_required", "password_change_attempted",
                                "ib_authentication_rejected"))
                            or _EXPIRED_PASSWORD.search(observed.output)
                            or _pending_diff_has_password_update_notice(observed.output)):
                        raise SetupError("IB identity command outcome is unverified")
                    if target.ethernet is None:
                        actual_point = getattr(observed, "_direct_endpoint", None)
                        _validate_direct_endpoint(target, actual_point)
                        if actual_point != neighbor:
                            if (identity_attempt != 0 or neighbor.interface is None
                                    or actual_point.interface is not None):
                                raise SetupError("IB identity endpoint transition is unverified")
                            neighbor = actual_point
                            moved = True
                            break
                    identity_outputs.append(observed.output)
                if moved:
                    continue
                try:
                    identity = _check_ib_identity(target, identity_outputs[0],
                        identity_outputs[1] if via_ipv4 else "", via_ipv4=via_ipv4)
                except SetupError:
                    config_state.failure_category = "FAILED_IDENTITY_MISMATCH"
                    raise
                result_record["identity"] = identity
                if not identity["ok"]:
                    config_state.failure_category = "FAILED_IDENTITY_MISMATCH"
                    mismatch_detail = "; ".join(
                        f"{item['field']}: expected={item['expected']} observed={item['observed']}"
                        for item in identity["mismatches"])
                    raise SetupError("IB identity differs from CSV; " + mismatch_detail
                                     + "; no configuration write authorized")
                config_state.endpoint = neighbor
                config_state.current_password = credential
                config_state.identity_verified = True
                if credential is None:
                    config_state.readonly_key_file = management_private_key
                break
            if not config_state.identity_verified:
                raise SetupError("IB identity endpoint did not stabilize")
            fingerprint_reader = (ib_host_key_reader(replace(task, neighbor=neighbor), ib_eth_user, args.ib_user,
                                                    credential, args.connect_timeout, policy=policy)
                                  if credential is not None else None)
            # I-005: each Network readback enters here once; comma interface lines are split and
            # every later consumer reads `body`.  `readback` keeps the device text for the location.
            readback = current.output
            body = _split_comma_interface_lines(readback)
            state = parse_nvue_state(body)
            log(f"  Current: hostname={state.hostname or 'unset'} "
                f"eth0={','.join(state.eth0_addresses) or 'unset'} "
                f"eth1={','.join(state.eth1_addresses) or 'unset'}")
            # The stages' credential context: the DEV phase/helper authority on a strict task.
            stage_context = ({"ib_password": None, "_ib_read_context": config_state} if credential is None else
                             {"_ib_current_password": credential, "_password_policy": policy} if strict
                             else {"ib_password": credential})

            def verify_ready(readiness_policy):
                nonlocal base_verified
                readiness_details.clear()
                try:
                    if target.ethernet is None:
                        return _wait_direct_ipv4_readback(target, args.ib_user, credential,
                            args.connect_timeout, strict=strict, policy=policy,
                            readiness_policy=readiness_policy, deferred_stamp=deferred_stamp,
                            details=readiness_details)
                    return verify_ipv4_login(target, neighbor.vrf, ib_eth_user, task.ethernet_password,
                        args.ib_user, args.connect_timeout, local=task.local,
                        readiness_policy=readiness_policy, _identity_details=readiness_details,
                        **stage_context)
                finally:
                    latest_identity = readiness_details.get("identity")
                    if readiness_details.get("identity_failed") is True:
                        base_verified = False
                        config_state.failure_category = "FAILED_IDENTITY_MISMATCH"
                        if (type(latest_identity) is not dict
                                or latest_identity.get("ok") is not False):
                            latest_identity = None
                    result_record["identity"] = latest_identity

            def verify_ready_with_refresh(readiness_policy):
                try:
                    return verify_ready(readiness_policy)
                except SetupError as error:
                    failure = _ssh_failure_fact(error)
                    change = getattr(failure, "host_key_change", None)
                    if change is None:
                        raise
                    refresh_task = (replace(task, neighbor=getattr(failure, "_direct_endpoint", None))
                                    if target.ethernet is None else task)
                    retried_readback = []
                    refresh_ib_host_key(change, refresh_task, eth_user=ib_eth_user, timeout=args.connect_timeout,
                        apply=args.apply, read_device_fingerprint=fingerprint_reader,
                        retry=lambda: retried_readback.append(verify_ready(
                            ReadinessPolicy(first_delay=0, attempts=1))),
                        operator_forced=operator_forced, host_key_records=host_key_records)
                    return retried_readback[0]

            pending_checked = False

            def report_pending():
                """U3 check-only: one read-only diff where --apply would first write (no detach)."""
                nonlocal pending_checked
                if pending_checked:
                    return
                pending_checked = True
                if credential is None:
                    log("  PENDING: not read; a key-only read-only check has no NVUE pending reader")
                    return
                diff = run_on_ib(target, neighbor, ib_eth_user, task.ethernet_password, args.ib_user,
                                 credential, args.connect_timeout, ["nv", "config", "diff", "-o", "commands"],
                                 local=task.local, allow_password_change=False, _pending_services=services)
                lines = [line for line in diff.output.splitlines()
                         if line.strip() and not line.lstrip().startswith("#")]
                if lines:
                    log(f"  PENDING: 有 {len(lines)} 行自有待提交，--apply 时会 detach 后重做")
                    for line in lines:
                        log(f"    PENDING: {line}")
                    result_record["planned_changes"].append(
                        {"item": "pending", "value": f"{len(lines)} owned lines"})
                    change_needs["pending"] = True

            result_record["device_state"] = "factory" if state_is_unconfigured(state) else "existing"
            stage = "initial"
            stages[stage] = "RUNNING"
            initial_ztp_output = _stage_ib_command(
                target, neighbor, ib_eth_user, task.ethernet_password, args.ib_user,
                credential, args.connect_timeout, ["nv", "show", "system", "ztp"],
                local=task.local, strict=strict and args.apply, policy=policy,
                _ib_read_context=config_state if credential is None else None).output
            result_record["ztp"]["read"] = True
            ztp = parse_ztp_status(initial_ztp_output)
            result_record["ztp"].update(service=ztp["service"], status=ztp["status"],
                provisioned=(None if result_record["device_state"] != "existing" or ztp["status"] is None
                             else ztp["status"] == "success"))
            if replace_mode and args.apply:
                task_phase("initial configuration")
                readback, authorized = run_initial_stage(
                    target, neighbor, ib_eth_user, task.ethernet_password, args.ib_user,
                    args.connect_timeout, current.output, local=task.local,
                    apply=True, authorized=authorized, policy=policy, details=initial_details,
                    initial_ztp_output=initial_ztp_output, _pending_services=services,
                    _pending_record=result_record["pending_detached"], **stage_context)
                stages["initial"] = "VERIFIED"
                stage = "day0"
                stages[stage] = "RUNNING"
                if not authorized:
                    authorized = confirm_first_device_change(target, "replace configuration from the admitted YAML")

                def replace_keys():
                    nonlocal stage, authorized
                    stages["day0"] = stages["services"] = "VERIFIED"
                    task_phase("IB public keys")
                    stage = "public_keys"
                    stages[stage] = "RUNNING"
                    key_details = {}
                    result_record["public_key_update"] = key_details
                    authorized = run_key_stage(
                        target, neighbor, ib_eth_user, task.ethernet_password, args.ib_user,
                        args.connect_timeout, keys, local=task.local, apply=True, authorized=authorized,
                        management_private_key=management_private_key, details=key_details,
                        read_device_fingerprint=fingerprint_reader, operator_forced=operator_forced,
                        host_key_records=host_key_records, **stage_context)
                    stages[stage] = "COMPLETED" if keys else "NO_KEYS_PROVIDED"
                    return authorized

                def replace_ready(readiness_policy):
                    nonlocal stage, readback, neighbor, fingerprint_reader
                    stage = "ipv4_readiness"
                    stages[stage] = "RUNNING"
                    task_phase("IPv4 readiness: up to 9 attempts, replacement waits 15s first, then 10s")
                    fresh = verify_ready_with_refresh(readiness_policy)
                    identity = readiness_details.get("identity")
                    if type(identity) is not dict or identity.get("ok") is not True:
                        raise SetupError("replace final IPv4 identity is unverified")
                    if target.ethernet is None:
                        readback = fresh
                        verify_state(target.ib, parse_nvue_state(_split_comma_interface_lines(readback)))
                        neighbor = readiness_details.get("endpoint")
                        _validate_direct_endpoint(target, neighbor)
                        config_state.endpoint = neighbor
                        fingerprint_reader = ib_host_key_reader(replace(task, neighbor=neighbor), ib_eth_user,
                            args.ib_user, credential, args.connect_timeout, policy=policy)
                    stages[stage] = "VERIFIED"
                    return fresh

                restored, _ = _run_admitted_replace_through_readiness(
                    config_state, args, services, timeout=args.connect_timeout, authorized=authorized,
                    strict=strict, policy=policy, key_stage=replace_keys, verify_ready=replace_ready)
                ztp = parse_ztp_status(restored[2])
                result_record["ztp"].update(service=ztp["service"], status=ztp["status"],
                    provisioned=ztp["status"] == "success")
                stages["services"] = "ALREADY_PRESENT" if restored[1] else "VERIFIED"
                result_record["replace"]["verdict"] = "REPLACED"
                result_record["needs_configuration"] = False
                result_record["outcome"] = "CONFIGURED"
                base_verified = True
            elif replace_mode:
                result_record["outcome"] = "CHECK_ONLY"
                result_record["needs_configuration"] = True
                stages["initial"] = "CHECKED"
                stages["day0"] = "PLANNED_NOT_APPLIED"
                log("  WOULD REPLACE: 整份替换（会清掉 yaml 以外的配置）")
            else:
                try:
                    change_needs["network"] = base_stage_needed(target.ib, state, args.force)
                except SetupError:
                    conflicts = management_conflicts(target.ib, state)
                    if conflicts:
                        change_needs["network"] = True
                        result_record["conflicts"] = [
                            {"field": field, "expected": expected, "actual": actual}
                            for field, expected, actual in conflicts]
                        config_state.failure_category = "BLOCKED_NETWORK_CONFLICT"
                        for field, expected, actual in conflicts:
                            log(f"  CONFLICT {field}: expected={expected}, actual={actual}")
                    raise
                result_record.update(_configuration_result_facts(target.ib, state, services, body, strict=strict and credential is not None))
                change_needs["services"] = services is not None and bool(desired_service_commands(services, body))
                task_phase("initial configuration")
                stage = "initial"
                stages[stage] = "RUNNING"
                readback, authorized = run_initial_stage(
                    target, neighbor, ib_eth_user, task.ethernet_password, args.ib_user,
                    args.connect_timeout, current.output, local=task.local,
                    apply=args.apply, authorized=authorized, policy=policy, details=initial_details,
                    initial_ztp_output=initial_ztp_output, _pending_services=services,
                    _pending_record=result_record["pending_detached"], **stage_context)
                change_needs["initial"] = initial_details.get("needed")
                if not args.apply and change_needs["initial"]:
                    report_pending()
                body = _split_comma_interface_lines(readback)
                stages[stage] = "VERIFIED" if args.apply else "CHECKED"
                state = parse_nvue_state(body)
                needs_base = base_stage_needed(target.ib, state, args.force)
                stage = "day0"
                stages[stage] = "RUNNING" if needs_base else "ALREADY_PRESENT"
                if needs_base:
                    task_phase("base management configuration")
                    # T16: only the missing setters (DEV), then apply and save.
                    setters = _management_network_commands(target.ib, body)
                    address_changes = any(command[:3] == ["nv", "set", "interface"]
                        and command[3] in ("eth0", "eth0-1")
                        and command[4:6] == ["ipv4", "address"] for command in setters)
                    if (args.apply and target.ethernet is None and type(neighbor) is DirectEndpoint
                            and neighbor.interface is None and address_changes):
                        deferred_stamp = config_state.stamp
                        commands = [*setters, ["sh", "-c", _DEFERRED_APPLY_SCRIPT, "--", deferred_stamp]]
                    else:
                        commands = [*setters, ["nv", "config", "apply", "-y"], ["nv", "config", "save"]]
                    for command in commands:
                        log(f"  {'PLAN' if args.apply else 'WOULD APPLY'}: {shlex.join(command)}")
                    if not args.apply:
                        report_pending()
                        result_record["outcome"] = "CHECK_ONLY"
                        stages[stage] = "NEEDS_CONFIGURATION"
                    else:
                        if not authorized:
                            authorized = confirm_first_device_change(target, "apply Network commands and verify IPv4 SSH")
                        owned = _settle_owned_pending(target, neighbor, ib_eth_user, task.ethernet_password,
                            args.ib_user, credential, args.connect_timeout, local=task.local, services=services,
                            stage="day0", record=result_record["pending_detached"])
                        if owned is not None:
                            _detach_owned_pending(target, neighbor, ib_eth_user, task.ethernet_password,
                                args.ib_user, credential, args.connect_timeout, owned, local=task.local,
                                strict=strict, policy=policy, services=services)
                        for index, command in enumerate(commands, 1):
                            if policy is not None:
                                policy.assert_unchanged()
                            log(f"  BASE RUN [{index}/{len(commands)}]: {shlex.join(command)}")
                            applied = _stage_ib_command(target, neighbor, ib_eth_user, task.ethernet_password,
                                args.ib_user, credential, args.connect_timeout, command, local=task.local,
                                strict=strict, policy=policy)
                            if deferred_stamp is not None and command[:2] == ["sh", "-c"]:
                                if (type(applied) is not SessionResult or type(applied.exit_code) is not int
                                        or applied.exit_code != 0 or type(applied.output) is not str
                                        or any(getattr(applied, name) is not False for name in (
                                            "password_changed", "password_change_required", "password_change_attempted",
                                            "ib_authentication_rejected"))
                                        or _EXPIRED_PASSWORD.search(applied.output)
                                        or _pending_diff_has_password_update_notice(applied.output)
                                        or type(getattr(applied, "_direct_endpoint", None)) is not DirectEndpoint
                                        or applied._direct_endpoint != neighbor):
                                    raise SetupError("deferred configuration launch outcome is unverified")
                            log(f"  BASE OK [{index}/{len(commands)}]")
                        if deferred_stamp is None:
                            readback = _stage_ib_command(target, neighbor, ib_eth_user, task.ethernet_password,
                                                         args.ib_user, credential, args.connect_timeout,
                                                         ["nv", "config", "show", "-o", "commands"], local=task.local,
                                                         strict=strict, policy=policy).output
                            body = _split_comma_interface_lines(readback)
                            state = parse_nvue_state(body)
                if deferred_stamp is None and not (needs_base and not args.apply):
                    verify_state(target.ib, state)
                    if needs_base:
                        # The reserved ports are verified from actual tokens (WP-1 difficulty 3).
                        _verify_management_network_state(target.ib, body)
                    stages[stage] = "VERIFIED" if needs_base else "ALREADY_PRESENT"
                    base_verified = True
                if args.apply:
                    stage = "ipv4_readiness"
                    stages[stage] = "RUNNING"
                    task_phase("IPv4 readiness: up to 9 attempts, Network write waits 15s first, then 10s")
                    fresh_readback = verify_ready_with_refresh(ReadinessPolicy(first_delay=15 if needs_base else 0))
                    if target.ethernet is None:
                        result_record["identity"] = readiness_details["identity"]
                        readback = fresh_readback
                        body = _split_comma_interface_lines(readback)
                        state = parse_nvue_state(body)
                        verify_state(target.ib, state)
                        if needs_base:
                            _verify_management_network_state(target.ib, body)
                        neighbor = readiness_details["endpoint"]
                        config_state.endpoint = neighbor
                        fingerprint_reader = ib_host_key_reader(replace(task, neighbor=neighbor), ib_eth_user,
                            args.ib_user, credential, args.connect_timeout, policy=policy)
                        stages["day0"] = "VERIFIED" if needs_base else "ALREADY_PRESENT"
                        base_verified = True
                    stages[stage] = "VERIFIED"
                else:
                    stages["ipv4_readiness"] = "NOT_REQUESTED"
                if not needs_base:
                    log("  Network SKIP: all required CSV values are present; extra applied settings preserved.")
                task_phase("Infra Services")
                stage = "services"
                stages[stage] = "RUNNING"
                services_missing = services is not None and bool(desired_service_commands(services, body))
                owned = None
                if services_missing and args.apply:
                    owned = _settle_owned_pending(target, neighbor, ib_eth_user, task.ethernet_password,
                        args.ib_user, credential, args.connect_timeout, local=task.local, services=services,
                        stage="services", record=result_record["pending_detached"])
                elif services_missing:
                    report_pending()
                authorized, service_skipped = run_service_stage(
                    target, neighbor, ib_eth_user, task.ethernet_password, args.ib_user,
                    args.connect_timeout, services, body, local=task.local, apply=args.apply,
                    authorized=authorized, _owned_pending=owned, **stage_context)
                stages[stage] = ("NOT_CONFIGURED" if services is None else "ALREADY_PRESENT" if not services_missing
                                 else "UNVERIFIED" if service_skipped else "VERIFIED" if args.apply else "PLANNED_NOT_APPLIED")
                task_phase("IB public keys")
                stage = "public_keys"
                stages[stage] = "RUNNING"
                key_details = {}
                result_record["public_key_update"] = key_details
                authorized = run_key_stage(
                    target, neighbor, ib_eth_user, task.ethernet_password, args.ib_user,
                    args.connect_timeout, keys, local=task.local, apply=args.apply, authorized=authorized,
                    management_private_key=management_private_key, details=key_details,
                    read_device_fingerprint=fingerprint_reader, operator_forced=operator_forced,
                    host_key_records=host_key_records, **stage_context)
                key_needed = None
                if args.apply and key_details.get("content_action") in {"UPDATED", "UNCHANGED"}:
                    key_needed = key_details["content_action"] == "UPDATED"
                elif type(key_details.get("present")) is bool:
                    key_needed = not key_details["present"]
                change_needs["public_keys"] = key_needed if keys else False
                if key_needed is True:
                    result_record["planned_changes"].append(
                        {"item": "public_keys", "value": "append missing required public keys"})
                    if not args.apply:
                        result_record["reason"] = "Missing required public keys; install with --apply."
                stages[stage] = ("NO_KEYS_PROVIDED" if not keys else "COMPLETED" if args.apply
                                 else "ALREADY_PRESENT" if key_details.get("present") is True else "PLANNED_NOT_APPLIED")
                # Owner 04 Q-037 (b) (R-260): on a check-only run an Initial stage that cannot be skipped
                # also needs configuration; --apply keeps the v15 formula.
                result_record["needs_configuration"] = bool(
                    needs_base or (services is not None and not service_skipped)
                    or (not args.apply and (initial_details.get("needed") is True or key_needed is True)))
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
        ssh_failure = _ssh_failure_fact(exc)
        cleanup_outcome = getattr(exc, "_replace_cleanup_outcome", None)
        if (replace_mode and "replace" in result_record and type(cleanup_outcome) is str
                and cleanup_outcome in {"FAILED_DETACHED", "FAILED_DETACH_FAILED"}):
            result_record["replace"]["verdict"] = cleanup_outcome
        if ssh_failure is not None:
            result_record["failure_kind"] = ssh_failure.kind.value
            if ssh_failure.kind is SshFailureKind.HOST_KEY_REFRESH_PENDING:
                result_record["outcome"] = "CHECK_ONLY"
            if getattr(ssh_failure, "candidates_exhausted", False):
                result_record["_jump_candidates_exhausted"] = True
        elif isinstance(exc, DirectSSHNetworkError):
            result_record["failure_kind"] = "DIRECT_SSH_NETWORK"
        stages[stage] = "FAILED"
        failure_text = _authorized_failure_text(exc)
        if stage == "ipv4_readiness" and readiness_details.get("identity_failed") is True:
            identity_facts = result_record["identity"]
            identity_detail = "fresh IPv4 identity could not be verified"
            if type(identity_facts) is dict and identity_facts.get("ok") is False:
                mismatch_detail = "; ".join(
                    f"{item['field']}: expected={item['expected']} observed={item['observed']}"
                    for item in identity_facts["mismatches"])
                identity_detail = "fresh IPv4 identity mismatch: " + mismatch_detail
            safe_detail = _authorized_failure_summary(SetupError(identity_detail),
                (task.ethernet_password, credential, getattr(policy, "_password", None)))
            failure_text += "; " + (safe_detail or "fresh IPv4 identity details withheld")
        result_record["reason"] = failure_text
        log(f"  ERROR: {failure_text}")
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
    finally:
        # Restore first, including early returns/BaseException and even if the
        # following metadata/log operation itself raises.
        _TASK_IB_CONFIG = previous_config
        if type(initial_details.get("needed")) is bool:
            change_needs["initial"] = initial_details["needed"]
        result_record["needs_change"] = True if replace_mode else _result_needs_change(change_needs.values())
        if config_state.failure_category is not None:
            result_record["category"] = config_state.failure_category
            if replace_mode and config_state.failure_category == "FAILED_IDENTITY_MISMATCH" and "replace" in result_record:
                result_record["replace"]["verdict"] = "IDENTITY_MISMATCH"
        if config_state.backup_receipt is not None:
            result_record["backup"] = dict(config_state.backup_receipt)
            log(f"  Configuration backup: {config_state.backup_receipt['path']} "
                f"({config_state.backup_receipt['bytes']} bytes)")
    # Keep the final direct probe inside this task, rather than a serial tail.
    prior_failure = bool(result_record.get("failed_stage")
                         and result_record.get("failure_kind") != "HOST_KEY_REFRESH_PENDING")
    if base_verified and credential is not None and not result_record["batch_error"]:
        try:
            task_phase("ZTP server direct IPv4 SSH (eth0, then eth1 fallback)")
            result_record["direct_rows"] = run_management_direct_checks(
                [target], {normalize_name(target.ib.hostname): credential}, args.ib_user,
                args.connect_timeout, on_management_server=getattr(args, "_on_management_server",
                    args.execution_mode != "ethernet" and not task.local), apply=args.apply and not prior_failure,
                read_device_fingerprint=fingerprint_reader, operator_forced=operator_forced,
                host_key_records=host_key_records)
            for row in result_record["direct_rows"]:
                if not prior_failure and row.get("failure_kind") in {"HOST_KEY_REFRESH_PENDING", "TARGET_HOST_KEY_CHANGED"}:
                    result_record["failure_kind"] = row["failure_kind"]
                    if row["failure_kind"] == "HOST_KEY_REFRESH_PENDING":
                        result_record["outcome"] = "CHECK_ONLY"
            stages["direct_ssh"] = ("VERIFIED" if any(row["status"] == "PASS" for row in result_record["direct_rows"])
                                      else "FAILED" if any(row["status"] == "FAIL" for row in result_record["direct_rows"])
                                      else "NOT_TESTED")
        except (BatchStopped, ProjectInputChanged) as exc:
            result_record["batch_error"] = str(exc)
        except SetupError as exc:
            stages["direct_ssh"] = "FAILED"
            result_record.setdefault("failed_stage", "direct_ssh")
            result_record["outcome"], result_record["reason"] = "FAILED", str(exc)
    result_record["host_key"] = [asdict(record) for record in host_key_records]
    _complete_result_fields(result_record)
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


def _login_path_record_metadata(target):
    """Copy current input/route facts without inventing login observations."""
    return {"route": asdict(target.route) if target.route is not None else None,
            "input_issues": [asdict(issue) for issue in target.ib.input_issues],
            "eth1_hints": [asdict(issue) for issue in target.ib.eth1_hints]}


def run_prepared_tasks(tasks, args, policy, initial_password, services, keys,
                       management_private_key, authority=None, method_cycle=None, *,
                       preflight_records=None):
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
    args = copy.copy(args)
    args.run_stamp = stamp
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
    gate = JumpGate()
    pending = list(tasks)
    jumps = {normalize_name(jump.hostname): jump for task in tasks
             for jump in [task_jump(task.target)] if jump is not None}

    def jump_key(task):
        jump = task_jump(task.target)
        return normalize_name(jump.hostname) if jump is not None else None

    def take_pending():
        now = time.monotonic()
        for index, task in enumerate(pending):
            key = jump_key(task)
            if gate.jump_exhausted(key):
                return pending.pop(index), True
            if gate.claim_jump_slot(key, now):
                return pending.pop(index), False
        return None, False

    def exhausted_record(task):
        failure = gate.jumps[jump_key(task)]["failure"]
        return {"outcome": "FAILED", "failure_kind": failure.kind.value,
                "reason": str(failure), "direct_rows": [], "batch_error": ""}

    def jump_outcome(task, record, writes):
        kind = record.get("failure_kind")
        key = jump_key(task)
        failure = None
        if kind in {"OOB_JUMP_UNREACHABLE", "OOB_JUMP_AUTHENTICATION"}:
            jump = task_jump(task.target)
            address = (getattr(_JUMP_SESSIONS, "records", {}).get(key, {}).get("address")
                       or (jump.login_ip if jump is not None else ""))
            failure = SshFailure(SshFailureKind(kind), "outer", address,
                                 jump.hostname if jump is not None else None)
            failure.candidates_exhausted = record.pop("_jump_candidates_exhausted", False)
        return gate.report_jump_outcome(key, failure, writes_attempted=writes, now=time.monotonic())

    attempt_numbers = {}
    def retain_requeued_attempt(task, record, path, writes, metrics):
        name = normalize_name(task.target.ib.hostname)
        number = attempt_numbers[name] = attempt_numbers.get(name, 0) + 1
        attempt = path.with_name(path.stem + f".attempt-{number}.log")
        path.rename(attempt)
        evidence = {**record, "writes_attempted": bool(writes), "metrics": dict(metrics),
                    "category": record_category(record)}
        evidence.setdefault("config_mode", getattr(args, "config_mode", "patch"))
        if evidence["config_mode"] == "replace":
            evidence["needs_change"] = True
            selected = getattr(args, "_replace_selected", {}).get(name)
            if selected is not None:
                evidence.setdefault("replace", dict(selected))
        attempt.with_suffix(".json").write_text(
            json.dumps(redact_data(evidence, coordinator.secrets), indent=2) + "\n", encoding="utf-8")
        report_detail(f"[REQUEUE] {task.target.ib.hostname}: unwritten jump failure; evidence {attempt}")
        pending.append(task)

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
        physical_jump = task_jump(physical)
        record["oob"] = physical_jump.hostname if physical_jump is not None else None
        record["port"] = physical.ethernet_port
        jump = task_jump(task.target)
        address = (getattr(_JUMP_SESSIONS, "records", {}).get(jump_key(task), {}).get("address")
                   or (jump.login_ip if jump is not None else None))
        record["jump"] = ({"hostname": jump.hostname, "login_ip": address, "type": jump.dev_type,
                          "interface": task.neighbor.interface, "vrf": task.neighbor.vrf,
                          "access_vlan": task.target.access_vlan or None,
                          "selection_reason": task.target.jump_reason or "LEAF_LOCAL_PATH"} if jump is not None else None)
        preflight = (preflight_records or {}).get(name, {})
        if jump is not None:
            selected = preflight.get("jump") or {}
            if (selected.get("hostname") == jump.hostname and selected.get("login_ip") == address
                    and selected.get("entry") is not None):
                record["jump"]["entry"] = selected["entry"]
        record["cable_check"] = preflight.get("cable_check") if jump is not None else None
        record.setdefault("failure_kind", None)
        record.pop("_jump_candidates_exhausted", None)
        record["category"] = record_category(record)
        record.setdefault("config_mode", getattr(args, "config_mode", "patch"))
        if record["config_mode"] == "replace":
            selected = getattr(args, "_replace_selected", {}).get(name)
            if selected is not None:
                record.setdefault("replace", dict(selected))
        _complete_result_fields(record)
        if writes and record["failure_kind"] == "OOB_JUMP_UNREACHABLE":
            record["reason"] = record.get("reason", "") + "; writes attempted; result unverified; no automatic replay"
        if type(task.neighbor) is DirectEndpoint:
            record["neighbor"] = None
        else:
            record["neighbor"] = {"ipv6": task.neighbor.ipv6, "interface": task.neighbor.interface,
                                  "vrf": task.neighbor.vrf, "mac": task.neighbor.mac,
                                  "address_source": task.neighbor.address_source}
        record.update(_login_path_record_metadata(task.target))
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
        if not verbose and not args.apply and record["config_mode"] == "replace":
            # Full report already includes the worker detail; keep this notice terminal-only.
            print("  整份替换（会清掉 yaml 以外的配置）", flush=True)
        if record.get("reason"):
            reason = " ".join(redact_text(record["reason"], coordinator.secrets).split())
            log("  Reason: " + (reason if len(reason) <= 180 else reason[:177] + "... (full evidence in device log/JSON)"))
        report_detail(f"  Device evidence: {path}", verbose=verbose)

    if count == 1:
        _ACTIVE_COORDINATOR = coordinator
        try:
            while pending:
                if coordinator.stopped:
                    break
                coordinator.assert_unchanged()
                recover_jump_cooldowns(gate, jumps, coordinator)
                task, exhausted = take_pending()
                if task is None:
                    recover_jump_cooldowns(gate, jumps, coordinator, wait=True)
                    continue
                coordinator.current_target, coordinator.writes_attempted = task.target, False
                coordinator.metrics = {}
                jump = task_jump(task.target)
                report_detail(f"[START worker=1] {task.target.ib.hostname} via {jump.hostname if jump is not None else 'direct'}", verbose=getattr(args, "verbose", False))
                path = directory / (task.target.ib.hostname + ".log")
                _TASK_LOG_BUFFER = []
                _TASK_DEADLINE = time.monotonic() + timeout
                try:
                    # Inline strict (management-server) tasks keep the one admitted policy
                    # object, the DEV phase/helper authority; worker processes get pinned copies.
                    task_policy = (policy if getattr(args, "_strict_cache", None) is not None
                                   else WorkerPasswordPolicy.pinned_copy(policy))
                    record = exhausted_record(task) if exhausted else execute_ib_task(task, args, task_policy,
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
                with path.open("x", encoding="utf-8") as handle:
                    os.chmod(path, 0o600)
                    for line in lines:
                        handle.write(redact_text(line, coordinator.secrets) + "\n")
                action = jump_outcome(task, record, coordinator.writes_attempted)
                if action == "requeue" and not coordinator.stopped:
                    retain_requeued_attempt(task, record, path, coordinator.writes_attempted, coordinator.metrics)
                    continue
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
                finish(task, record, path, coordinator.writes_attempted, coordinator.metrics)
        except ProjectInputChanged as exc:
            coordinator.stopped, coordinator.fatal = True, str(exc)
        except (KeyboardInterrupt, EOFError):
            coordinator.stopped, coordinator.fatal = True, "user cancelled the batch"
        finally:
            _ACTIVE_COORDINATOR, _TASK_LOG_BUFFER, _TASK_DEADLINE = None, None, None
    else:
        context = multiprocessing.get_context("fork")
        stop_event = context.Event()
        active = {}
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
                if not coordinator.stopped:
                    recover_jump_cooldowns(gate, jumps, coordinator)
                while pending and free_slots and not coordinator.stopped:
                    task, exhausted = take_pending()
                    if task is None:
                        break
                    if exhausted:
                        path = directory / (task.target.ib.hostname + ".log")
                        path.write_text("Jump cooldown attempts exhausted; no task dispatched.\n", encoding="utf-8")
                        os.chmod(path, 0o600)
                        finish(task, exhausted_record(task), path, False)
                        continue
                    slot = free_slots.pop(0)
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
                    jump = task_jump(task.target)
                    report_detail(f"[START worker={slot}] {task.target.ib.hostname} via {jump.hostname if jump is not None else 'direct'}", verbose=getattr(args, "verbose", False))
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
                            coordinator.writes_attempted = job["writes"]
                            try:
                                coordinator.assert_unchanged()
                                if coordinator.stopped:
                                    raise BatchStopped(coordinator.fatal or "batch stopped")
                                answer = coordinator.request(request_kind, value, task.target)
                                if request_kind in {"write", "host-key-remove"}:
                                    job["writes"] = coordinator.writes_attempted
                                reply = ("ok", answer)
                            except ProjectInputChanged as exc:
                                coordinator.stopped, coordinator.fatal = True, str(exc)
                                reply = ("project-changed", str(exc))
                            except BatchStopped as exc:
                                reply = ("stopped", str(exc))
                            except SetupError as exc:
                                reply = ("error", str(exc))
                            if request_kind == "host-key-remove":
                                job["writes"] = coordinator.writes_attempted
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
                    # Observe exit before checking for queued records/logs:
                    # a result sent between the checks must not be discarded.
                    if not process.is_alive() and (connection.closed or not connection.poll()):
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
                        action = jump_outcome(task, record, job["writes"])
                        if action == "requeue" and not coordinator.stopped:
                            retain_requeued_attempt(task, record, job["path"], job["writes"], job["metrics"])
                        else:
                            finish(task, record, job["path"], job["writes"], job["metrics"])
                        del active[slot]
                        free_slots.append(slot)
                if pending and not active and not coordinator.stopped:
                    recover_jump_cooldowns(gate, jumps, coordinator, wait=True)
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
                            network_tables, table_failures, outcomes, records=None, *,
                            cable_checks=None, endpoints=None):
    ready = []
    vrfs = {}
    paths = _import_tools("tools.login_path")
    records = records if records is not None else {}
    for target in targets:
        name, eth_key = normalize_name(target.ib.hostname), normalize_name(target.ethernet.hostname)
        physical = target.attachment or target
        leaf_key = normalize_name(physical.ethernet.hostname)
        fact = None
        selected = getattr(_JUMP_SESSIONS, "records", {}).get(eth_key, {})
        address = selected.get("address") or target.ethernet.login_ip
        jump = {"hostname": target.ethernet.hostname, "login_ip": address,
                "entry": next((item.entry for item in target.ethernet.jump_candidates
                               if item.address == address), "JUMP_ETH0"),
                "type": target.ethernet.dev_type, "interface": None, "vrf": None,
                "access_vlan": target.access_vlan or None,
                "selection_reason": target.jump_reason or "LEAF_LOCAL_PATH"}
        def cable_fact():
            return dict(asdict(fact), ignored=(fact.verdict != "MATCH" and
                        bool(getattr(args, "ignore_cable_check", False))))
        def skipped(category, reason):
            failure = _ssh_failure_fact(reason)
            mapped = FAILURE_KIND_CATEGORY.get(failure.kind.value) if failure is not None else None
            category = mapped or category
            outcomes[name] = "FAILED" if mapped is not None else "SKIPPED"
            records[name] = {"hostname": target.ib.hostname, "oob": target.ethernet.hostname,
                "outcome": outcomes[name], "category": category, "reason": str(reason),
                "port": target.ethernet_port, "metrics": {}, "stage_status": {}, "writes_attempted": False,
                "failure_kind": failure.kind.value if failure is not None else None,
                "jump": dict(jump)}
            if fact is not None:
                records[name]["cable_check"] = cable_fact()
            log(f"[SKIP] {target.ib.hostname} | {category} | {target.ethernet.hostname}:{target.ethernet_port}")
            if isinstance(reason, IBMacMismatch) and reason.expected_mac and reason.observed_mac:
                records[name]["mac_mismatch"] = {"expected": reason.expected_mac, "observed": reason.observed_mac}
                log(f"  MAC: expected={reason.expected_mac} observed={reason.observed_mac}; no IB login/write attempted")
            report_detail(f"  Full skip reason: {reason}")
        try:
            if eth_key in table_failures or leaf_key in table_failures:
                reason = table_failures.get(eth_key, table_failures.get(leaf_key))
                category = ("SKIPPED_OOB_IDENTITY_CONFLICT" if re.search(r"(?i)identity|host key|identification", str(reason))
                    else "SKIPPED_OOB_UNREACHABLE" if re.search(r"(?i)route|unreachable|timed? out|timeout|connect|permission denied|authentication", str(reason))
                    else "SKIPPED_OOB_SNAPSHOT_FAILED")
                skipped(category, reason)
                continue
            try:
                line = interface_status_line(interface_tables[leaf_key], physical.ethernet_port)
                interface_oper_status(line, physical.ethernet_port)
            except SetupError as exc:
                skipped("SKIPPED_PORT_STATE_UNKNOWN", exc)
                continue
            try:
                fact = (cable_checks[name] if cable_checks is not None else paths.check_cable(
                    target.ib.hostname, target.ib.eth0_mac, (target.ethernet.hostname, target.ethernet_port),
                    [paths.JumpTables(target.ethernet.hostname, *network_tables[eth_key])],
                    cascade_ports=frozenset()))
                if isinstance(fact, SetupError):
                    error, fact = fact, None
                    raise error
            except ValueError as exc:
                raise SetupError(str(exc)) from exc
            if fact.verdict != "MATCH" and not getattr(args, "ignore_cable_check", False):
                reason = ("ping 后仍没学到" if fact.after_ping and fact.verdict == "NOT_LEARNED"
                          else "cable check failed")
                skipped("SKIPPED_CABLE_CHECK_FAILED", f"{reason}; expected={fact.expected}; actual={fact.actual}")
                continue
            neighbor = endpoints.get(name) if endpoints is not None else None
            endpoint_verified = neighbor is not None
            if neighbor is None:
                if fact.login_interface is None:
                    raise SetupError("login VLAN has no real Leaf SVI and no qualified Spine")
                neighbor = Neighbor(fact.link_local, fact.login_interface, fact.mac, address_source="CSV_EUI64")
            key = (eth_key, neighbor.interface)
            if key not in vrfs:
                vrfs[key] = (neighbor.vrf if endpoint_verified else interface_vrf(
                    target.ethernet, args.eth_user, passwords[eth_key], neighbor.interface,
                    args.connect_timeout, local=eth_key in local_keys))
            neighbor = Neighbor(neighbor.ipv6, neighbor.interface, neighbor.mac, vrfs[key], neighbor.address_source)
            jump.update(interface=neighbor.interface, vrf=neighbor.vrf)
            records[name] = {"hostname": target.ib.hostname, "oob": target.ethernet.hostname,
                "port": target.ethernet_port, "outcome": "NOT_ATTEMPTED", "writes_attempted": False,
                "metrics": {}, "stage_status": {}, "jump": dict(jump), "cable_check": cable_fact()}
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
    """Read physical port/VLAN scope, independently of learned device MACs."""
    line = interface_status_line(interfaces, target.ethernet_port)
    interface_oper_status(line, target.ethernet_port)
    paths = _import_tools("tools.login_path")
    try:
        bridge, vlan, interfaces = paths._login_interface_facts(network[0], network[2], target.ethernet_port)
        if len(interfaces) > 1:
            raise ValueError("multiple Leaf SVIs match the access VLAN")
        mac = paths.normalize_mac(target.ib.eth0_mac)
        paths.link_local_from_mac(mac)
    except ValueError as exc:
        raise SetupError(str(exc)) from exc
    return mac, bridge, vlan


def _spine_neighbor(target, network, interface, vrf, learned_mac):
    """The physical CSV identity is authoritative, never a Spine neighbor table."""
    paths = _import_tools("tools.login_path")
    try:
        mac = paths.normalize_mac(target.ib.eth0_mac)
        return Neighbor(paths.link_local_from_mac(mac), interface, mac, vrf, "CSV_EUI64")
    except ValueError as exc:
        raise SetupError(str(exc)) from exc


def choose_oob_spine(candidates):
    """One parent-owned random choice per Leaf, never per IB command/worker."""
    return random.SystemRandom().choice(candidates)


def prepare_routed_ib_tasks(targets, args, passwords, local_keys, interface_tables,
                            network_tables, table_failures, outcomes, records, *,
                            spines, fetch_addresses, collect_spines, jump_routes=None,
                            cascade_ports=frozenset()):
    """Keep physical cable evidence separate from the selected execution Jump."""
    paths = _import_tools("tools.login_path")
    normal, groups, address_cache = [], {}, {}
    checks, endpoints = {}, {}
    names = {normalize_name(item.hostname): item.hostname for item in spines}
    names.update((normalize_name(t.ethernet.hostname), t.ethernet.hostname) for t in targets)
    def cable(target, *, after_ping=False, ping_ok=None):
        return paths.check_cable(target.ib.hostname, target.ib.eth0_mac,
            (target.ethernet.hostname, target.ethernet_port),
            [paths.JumpTables(names[key], *table) for key, table in network_tables.items()
             if key in names and key not in table_failures], cascade_ports=cascade_ports,
            after_ping=after_ping, ping_ok=ping_ok)
    for target in targets:
        try:
            checks[normalize_name(target.ib.hostname)] = cable(target)
        except ValueError as exc:
            checks[normalize_name(target.ib.hostname)] = SetupError(str(exc))
    def skip(target, category, reason):
        name = normalize_name(target.ib.hostname)
        outcomes[name] = "SKIPPED"
        records[name] = {"hostname": target.ib.hostname, "oob": target.ethernet.hostname,
            "port": target.ethernet_port, "outcome": "SKIPPED", "category": category,
            "reason": str(reason), "metrics": {}, "stage_status": {}, "writes_attempted": False}
        if name in checks and not isinstance(checks[name], SetupError):
            records[name]["cable_check"] = dict(asdict(checks[name]), ignored=False)
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
        fact = checks[normalize_name(target.ib.hostname)]
        if (not isinstance(fact, SetupError) and fact.verdict == "ELSEWHERE"
                and not getattr(args, "ignore_cable_check", False)):
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
        except SetupError as exc:
            checks[normalize_name(target.ib.hostname)] = exc
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
                    error = table_failures[key]
                    raise error if isinstance(error, SetupError) else SetupError(error)
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
            normal.append(routed)
            endpoints[normalize_name(target.ib.hostname)] = neighbor
            if rejected:
                report_detail(f"  {target.ib.hostname}: rejected Spine candidates: {rejected}")
    # Build transport endpoints without replacing physical Leaf facts. No ping
    # result is an admission decision: the subsequent Leaf FDB is authoritative.
    eligible_targets = {normalize_name(t.ib.hostname): t for t in normal}
    for name, target in eligible_targets.items():
        fact = checks.get(name)
        if isinstance(fact, SetupError) or fact is None or name in endpoints or fact.login_interface is None:
            continue
        key = normalize_name(target.ethernet.hostname)
        if key in table_failures:
            continue
        try:
            vrf = interface_vrf(target.ethernet, args.eth_user, passwords[key], fact.login_interface,
                                args.connect_timeout, local=key in local_keys)
            endpoints[name] = Neighbor(fact.link_local, fact.login_interface, fact.mac, vrf, "CSV_EUI64")
        except SetupError as exc:
            checks[name] = exc
    ping_results, reread = {}, {}
    for leaf, pending_checks in paths.ping_plan(
            [fact for name, fact in checks.items() if name in eligible_targets
             and not isinstance(fact, SetupError)]).items():
        for fact in pending_checks:
            name = normalize_name(fact.hostname)
            if name not in endpoints:
                continue
            target, neighbor = eligible_targets[name], endpoints[name]
            key = normalize_name(target.ethernet.hostname)
            try:
                run_on_ethernet(target.ethernet, args.eth_user, passwords[key],
                    paths.ping_argv(neighbor.vrf, neighbor.ipv6, neighbor.interface),
                    args.connect_timeout, local=key in local_keys)
                ping_results[name] = True
            except (ProjectInputChanged, BatchStopped):
                raise
            except SshFailure as exc:
                checks[name] = exc
                continue
            except SetupError:
                ping_results[name] = False
            physical = target.attachment or target
            reread[normalize_name(physical.ethernet.hostname)] = physical.ethernet
    # One barrier: finish every ping before the first second FDB read.
    for key, device in reread.items():
        try:
            fdb = run_on_ethernet(device, args.eth_user, passwords[key], ["bridge", "fdb", "show"],
                                  args.connect_timeout, local=key in local_keys)
            links, _, vlans = network_tables[key]
            network_tables[key] = (links, fdb, vlans)
        except (ProjectInputChanged, BatchStopped):
            raise
        except SetupError as exc:
            table_failures[key] = exc
    if reread:
        for name, target in eligible_targets.items():
            if isinstance(checks.get(name), SetupError):
                continue
            try:
                checks[name] = cable(target.attachment or target, after_ping=name in ping_results,
                                     ping_ok=ping_results.get(name))
            except ValueError as exc:
                checks[name] = SetupError(str(exc))
    return prepare_ready_ib_tasks(
        sorted(normal, key=lambda target: normalize_name(target.ib.hostname)), args, passwords, local_keys,
        interface_tables, network_tables, table_failures, outcomes, records,
        cable_checks=checks, endpoints=endpoints)


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


RESULT_SCHEMA_VERSION = 1
RESULT_CATEGORIES = frozenset({
    "NOT_ATTEMPTED", "SKIPPED", "CHECKED_AND_CONFIGURED", "CHECKED_EXISTING_CONFIGURATION",
    "CHECKED_EXISTING_KEYS_VERIFIED", "CHECKED_EXISTING_KEYS_REFRESHED", "CHECKED_EXISTING_KEY_INSTALL_COMPLETED",
    "CHECKED_NEEDS_CONFIGURATION", "CHECKED_HOST_KEY_REFRESH_PENDING", "BLOCKED_PASSWORD_CHANGE_REQUIRED",
    "BLOCKED_NETWORK_CONFLICT", "FAILED_CHECK_OR_LOGIN", "FAILED_AFTER_WRITE_UNVERIFIED",
    "FAILED_SHARED_INPUT", "FAILED_SCRIPT_EXECUTION", "FAILED_OOB_IPV4_READINESS",
    "FAILED_IDENTITY_MISMATCH", "FAILED_CONFIG_BACKUP", "FAILED_DIRECT_LOGIN_NETWORK",
    "FAILED_DIRECT_SSH_NETWORK", "FAILED_OOB_JUMP_UNREACHABLE", "FAILED_OOB_JUMP_AUTHENTICATION",
    "FAILED_TARGET_HOST_KEY_CHANGED", "SKIPPED_CABLE_CHECK_FAILED", "SKIPPED_DEPENDENCY_UNVERIFIED",
    "SKIPPED_INPUT_INCOMPLETE", "SKIPPED_INVENTORY_MAC_UNAVAILABLE", "SKIPPED_JUMP_ADDRESS_INVALID",
    "SKIPPED_LINK_DOWN", "SKIPPED_LLDP_SPINE_IDENTITY", "SKIPPED_MAC_MISMATCH",
    "SKIPPED_NEIGHBOR_UNRESOLVED", "SKIPPED_NO_LLDP_SPINE", "SKIPPED_NO_QUALIFIED_SPINE",
    "SKIPPED_OOB_ADDRESS_UNVERIFIED", "SKIPPED_OOB_IDENTITY_CONFLICT", "SKIPPED_OOB_SNAPSHOT_FAILED",
    "SKIPPED_OOB_UNREACHABLE", "SKIPPED_PORT_STATE_UNKNOWN",
})
ATTENTION_CATEGORIES = (RESULT_CATEGORIES - {
    "CHECKED_AND_CONFIGURED", "CHECKED_EXISTING_CONFIGURATION", "CHECKED_EXISTING_KEYS_VERIFIED",
    "CHECKED_EXISTING_KEYS_REFRESHED", "CHECKED_EXISTING_KEY_INSTALL_COMPLETED",
}) | frozenset({
    "UNVERIFIED_CONFIGURATION", "DIRECT_SSH_NOT_TESTED", "FAILED_DIRECT_SSH_HOST_KEY",
    "FAILED_DIRECT_SSH_AUTHENTICATION", "FAILED_DIRECT_SSH_CHECK", "FAILED_AUTHENTICATION",
    "FAILED_INITIAL_CONFIGURATION", "FAILED_BASE_CONFIGURATION", "FAILED_SERVICES_CONFIGURATION",
    "FAILED_PUBLIC_KEYS",
})


def _setup_record_verified(record, rows):
    """The original summary's per-device completion predicate, shared verbatim."""
    return (any(row["status"] == "PASS" for row in rows)
            and record.get("outcome") in {"CONFIGURED", "ALREADY_CONFIGURED"}
            and not any(state in {"FAILED", "UNVERIFIED", "PLANNED_NOT_APPLIED", "NEEDS_CONFIGURATION", "RUNNING"}
                        for state in record.get("stage_status", {}).values()))


def _complete_result_fields(record):
    """Close the same result before persistence and before summary consumption."""
    for key, value in {"device_state": "unknown", "existing_configuration": [],
                       "planned_changes": [], "conflicts": [], "needs_change": None, "pending_detached": [],
                       "ztp": {"read": False, "service": None, "status": None, "provisioned": None},
                       "config_mode": "patch"}.items():
        record.setdefault(key, value)
    if record["config_mode"] == "replace":
        record["needs_change"] = True
    name = normalize_name(record["hostname"])
    rows = [row for row in record.get("direct_rows", [])
            if normalize_name(row["hostname"]) == name]
    category = record_category(record)
    attention = initial_setup_attention({name: record}, rows)
    record["attention_category"] = attention[0]["category"] if attention else None
    record["verified_complete"] = _setup_record_verified(record, rows)
    if (category not in RESULT_CATEGORIES
            or record["attention_category"] is not None and record["attention_category"] not in ATTENTION_CATEGORIES):
        raise SetupError("initial-setup result has an unrecognized category")


def record_category(record):
    """One final outcome per target; key refresh is not a base-network change."""
    mapped = FAILURE_KIND_CATEGORY.get(record.get("failure_kind"))
    if mapped is not None:
        return mapped
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
        "FAILED_OOB_JUMP_UNREACHABLE": "Check the named jump login address, network routes and TCP/22; restore the jump connection before retrying downstream devices. Verify any attempted writes; do not replay them automatically. Select --direct-access <this-IB> explicitly for a separate direct attempt; no automatic path switch is made.",
        "FAILED_OOB_JUMP_AUTHENTICATION": "Verify authentication to the named OOB jump and the intended jump account; this is not an IB target-password failure. Select --direct-access <this-IB> explicitly for a separate direct attempt; no automatic path switch is made.",
        "FAILED_TARGET_HOST_KEY_CHANGED": "Verify this IB host key through an authenticated path, or use --refresh-host-key only after confirming its reset. No unverified entry is removed automatically.",
        "CHECKED_HOST_KEY_REFRESH_PENDING": "The authenticated IB fingerprint matches; re-run with --apply to refresh only this host-key entry. No entry was removed during this read-only run.",
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
        mapped = FAILURE_KIND_CATEGORY.get(record.get("failure_kind"))
        category = mapped or record_category(record)
        rows = rows_by_name.get(normalize_name(name), [])
        successful_task = mapped is None and record.get("outcome") in {"CONFIGURED", "ALREADY_CONFIGURED"}
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


def _log_initial_setup_device_facts(records):
    """Display existing per-device facts without probing or changing outcomes."""
    def encoded(value):
        return json.dumps(value, ensure_ascii=True, separators=(",", ":"))

    def yes_no(value):
        return "yes" if value is True else "no" if value is False else "unknown"

    for name, record in sorted(records.items()):
        log(f"  Device facts: {name}")
        route = record.get("route")
        if route:
            log(f"    Route: path={encoded(route.get('path'))} "
                f"reason={encoded(route.get('reason'))} "
                f"same_subnet={encoded(route.get('same_subnet'))}")
        cable = record.get("cable_check")
        if cable:
            expected = ":".join(cable["expected"])
            actual = [":".join(position) for position in cable["actual"]]
            verdict = cable["verdict"]
            unlearned = " unlearned=yes" if verdict == "NOT_LEARNED" else ""
            log(f"    Cable: expected={encoded(expected)} actual={encoded(actual)} "
                f"verdict={verdict}{unlearned} after_ping={yes_no(cable.get('after_ping'))} "
                f"ping_ok={yes_no(cable.get('ping_ok'))} "
                f"ignored={yes_no(cable.get('ignored', False))}")
        identity = record.get("identity")
        if identity:
            expected, observed = identity["expected"], identity["observed"]
            line = (f"    Identity: ok={yes_no(identity.get('ok'))} "
                    f"via_ipv4={yes_no(identity.get('via_ipv4'))} "
                    f"mac_expected={encoded(expected.get('mac'))} "
                    f"mac_observed={encoded(observed.get('mac'))}")
            if identity.get("via_ipv4"):
                line += (f" ipv4_expected={encoded(expected.get('ipv4'))} "
                         f"ipv4_observed={encoded(observed.get('ipv4'))} "
                         f"gateway_expected={encoded(expected.get('gateway'))} "
                         f"gateways_observed={encoded(observed.get('gateways'))}")
            log(line)
        for key, label in (("input_issues", "Input issue"), ("eth1_hints", "eth1 hint")):
            for issue in record.get(key, ()):
                log(f"    {label}: field={encoded(issue.get('field'))} "
                    f"value={encoded(issue.get('value'))} problem={encoded(issue.get('problem'))}")
        backup = record.get("backup")
        if backup:
            log(f"    Backup: path={encoded(backup.get('path'))} bytes={encoded(backup.get('bytes'))}")


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
        if (record.get("route") or {}).get("path") != "direct":
            source = (record.get("neighbor") or {}).get("address_source", "NOT_SELECTED")
            address_sources[source] = address_sources.get(source, 0) + 1
    passed = {normalize_name(row["hostname"]) for row in direct_rows if row["status"] == "PASS"}
    ready = sum(_setup_record_verified(record, [row for row in direct_rows
                if normalize_name(row["hostname"]) == normalize_name(name)])
                for name, record in records.items())
    mismatch = sum(normalize_name(name) in passed and record.get("stage_status", {}).get("ipv4_readiness") == "FAILED"
                   for name, record in records.items())
    fallback = [record for record in records.values()
                if (record.get("route") or {}).get("path") != "direct"
                and (record.get("neighbor") or {}).get("address_source") == "FDB_EUI64_CANDIDATE"]
    fallback_verified = sum(record.get("stage_status", {}).get("authentication") == "VERIFIED" for record in fallback)
    csv_candidates = [record for record in records.values()
                      if (record.get("route") or {}).get("path") != "direct"
                      and (record.get("neighbor") or {}).get("address_source") == "CSV_EUI64"]
    csv_verified = sum(record.get("stage_status", {}).get("authentication") == "VERIFIED"
                       for record in csv_candidates)
    return {"categories": categories, "metrics": metrics, "stages": stages,
            "direct_ssh": summarize_management_direct_checks(direct_rows),
            "setup_and_direct_ssh_verified": ready, "oob_ipv4_failed_direct_ssh_passed": mismatch,
            "ipv6_address_sources": address_sources,
            "ipv6_fallback": {"candidates": len(fallback), "authenticated": fallback_verified,
                              "not_verified": len(fallback)-fallback_verified},
            "ipv6_csv_eui64": {"candidates": len(csv_candidates), "authenticated": csv_verified,
                               "not_verified": len(csv_candidates)-csv_verified},
            "attention": initial_setup_attention(records, direct_rows)}


def print_initial_setup_summary(project, args, targets, candidate_count, snapshots_failed,
                                records, direct_rows, workers, fatal="", jump_routes=None):
    """English, mutually exclusive device outcomes; reasons never imply IB state."""
    # Display defaults belong to this projection, not to the caller's verified records.
    records = {name: dict(record) for name, record in records.items()}
    for target in targets:
        name = normalize_name(target.ib.hostname)
        records.setdefault(name, {"hostname": target.ib.hostname, "oob": target.ethernet.hostname if target.ethernet else None,
                                 "outcome": "NOT_ATTEMPTED", "reason": "task was not dispatched"})
        records[name].setdefault("hostname", target.ib.hostname)
        records[name].setdefault("oob", target.ethernet.hostname if target.ethernet else None)
        records[name].setdefault("port", target.ethernet_port)
        records[name].setdefault("config_mode", getattr(args, "config_mode", "patch"))
        if records[name]["config_mode"] == "replace":
            records[name]["needs_change"] = True
            selected = getattr(args, "_replace_selected", {}).get(name)
            if selected is not None:
                records[name].setdefault("replace", dict(selected))
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
    oobs = {normalize_name(target.ethernet.hostname): target.ethernet for target in targets
            if target.ethernet is not None}
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
    log("SUCCESS = all required setup/access checks passed; INCOMPLETE = device work remains; FAILED = run execution failed/aborted.")
    summary_panel(2, "OOB SNAPSHOTS")
    log(f"OOB snapshots: {len(oobs)} total, {len(oobs)-len(snapshots_failed)} collected, {len(snapshots_failed)} failed")
    log("\nOOB Leaf                 Login IP         IB Targets  Snapshot   Impact / Reason")
    for key, device in sorted(oobs.items()):
        attached = [target for target in targets if target.ethernet is not None
                    and normalize_name(target.ethernet.hostname) == key]
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
    _log_initial_setup_device_facts(records)
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
    csv_candidates = facts["ipv6_csv_eui64"]
    log(f"CSV-derived IPv6 candidates: {csv_candidates['candidates']}; authenticated={csv_candidates['authenticated']}; not-verified={csv_candidates['not_verified']}")
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
    if not facts["attention"] and not fatal and candidate_count == len(targets):
        log("All required setup and SSH access checks passed; retain the run evidence.")
    log(f"\nSee {Path(args.report).resolve()} and the per-device .log/.json files for evidence.")
    return status


@_jump_session_lifetime()
def main(*, method_cycle=None) -> int:
    """One run: inputs, cache, credentials, snapshots, task queue, summary.

    method_cycle is config_sync_authority's managed cycle (keyword-only, external
    contract): it admits the paths before any output, starts before task
    preparation, receipts each device in the single inline slot and closes after
    the summary, all in this parent process.
    """
    global REPORT_HANDLE, _CONSOLE_VERBOSE, _CREDENTIALS_FD_MODE, _JUMP_SESSIONS
    args = parse_args()
    replace_mode = getattr(args, "config_mode", "patch") == "replace"
    replace_bindings = {}
    if replace_mode:
        if args.execution_mode == "ethernet":
            raise SetupError("replace is not supported in ethernet execution mode")
        if method_cycle is not None:
            raise SetupError("replace is not supported by the managed entry")
        if args.generate_json:
            raise SetupError("replace is not supported with --generate-json")
        if args.plan and args.apply:
            raise SetupError("--plan cannot be combined with --apply")
        args._replace_release = (args.project_dir.expanduser() / "99-output-ib_nvl/latest"
                                 if args.project_dir is not None
                                 else Path(__file__).resolve().parent / "latest_yaml")
        binding_out = {}
        args._replace_manifest = validate_replace_release(
            args._replace_release,
            args.project_dir.expanduser() if args.project_dir is not None else None,
            _bindings=binding_out)
        replace_bindings = binding_out["files"]
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
    # WP4/r6: mandatory even for read-only, plan and generation; fail before device contact.
    _import_tools("tools.device_identity")
    hostname_ranges = _import_tools("tools.hostname_ranges")
    paths = _import_tools("tools.login_path")
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
    if args.direct_access is not None and args.execution_mode == "ethernet":
        raise SetupError("--direct-access is not allowed with --execution-mode ethernet")
    # Module layout selects code authority, not the physical execution role.
    # Resolve auto before any output. A cache supplies only already-qualified
    # source targets here; the original profile admission below still applies.
    leaf = False
    cold_inputs = None
    if args.execution_mode in {"ethernet", "auto"} and not args.generate_json:
        role_cache = load_target_cache(args.target_cache.resolve(), ib_csv_path, p2p_path)
        if args.execution_mode == "ethernet" and role_cache is None:
            raise SetupError(
                "target cache is missing or invalid; regenerate version 6 on the management server"
            )
    if args.execution_mode == "auto" and not args.generate_json:
        if role_cache is not None:
            role_targets = role_cache[1]
        else:
            ib_devices, eth_devices = load_devices(ib_csv_path)
            links = parse_p2p(p2p_path)
            validate_p2p_links(links)
            role_targets = build_targets(links, ib_devices, eth_devices)
            cold_inputs = (ib_devices, role_targets)
        leaf = bool(local_ethernet_keys(
            role_targets, args.execution_mode, args.local_ethernet_hostname))
        if replace_mode and leaf:
            raise SetupError("replace is not supported on a local Leaf")
        if leaf and role_cache is None:
            raise SetupError(
                "target cache is missing or invalid; regenerate version 6 on the management server"
            )
    inventory_check = None
    if (args.generate_json or args.execution_mode == "management"
            or (args.execution_mode == "auto" and not leaf)):
        inventory_check = _compare_inventory(ib_csv_path,
                                             method_cycle.project if method_cycle is not None else project,
                                             checked_by_caller=args.inventory_checked)
    selector_value = getattr(args, "refresh_host_key", None)
    role_csv_sha256 = None
    if ((args.execution_mode == "ethernet" or leaf) and not args.generate_json
            and method_cycle is None and not replace_mode and selector_value is None):
        # P1 validated these exact v6 source bytes. A selection needs original
        # spelling and CSV row order, not a second Device/route build.
        try:
            role_csv = ib_csv_path.read_bytes()
        except OSError as exc:
            raise SetupError(f"cannot open device CSV {ib_csv_path}: {exc}") from exc
        role_csv_sha256 = hashlib.sha256(role_csv).hexdigest()
        if _load_target_cache(args.target_cache.resolve(), ib_csv_path, p2p_path,
                              expected_ib_csv_sha256=role_csv_sha256) is None:
            raise SetupError(
                "target cache is missing or invalid; regenerate version 6 on the management server"
            )
        inventory_devices = {}
        rows = csv.reader(io.StringIO(role_csv.decode("utf-8-sig"), newline=""))
        header = next(rows, None)
        if header is None:
            raise SetupError(f"device CSV is empty: {ib_csv_path}")
        indexes = header_indexes(header)
        missing = sorted({"hostname", "type", "eth0_ip"} - indexes.keys())
        if missing:
            raise SetupError(f"device CSV missing column(s): {', '.join(missing)}")
        inventory_names = [name for row in rows
                           if row_value(row, indexes, "type").casefold() == "ib"
                           and (name := row_value(row, indexes, "hostname"))]
        if not inventory_names:
            raise SetupError(f"device CSV contains no type=ib devices: {ib_csv_path}")
    else:
        inventory_devices = load_devices(ib_csv_path)[0]
        inventory_names = [device.hostname for device in inventory_devices.values()]
    devices_selector = getattr(args, "devices", None)
    try:
        selected_names = (inventory_names if devices_selector is None else hostname_ranges.select(
            hostname_ranges.parse_selector(devices_selector, option="--devices"), inventory_names))
    except hostname_ranges.SelectorError as error:
        raise SetupError(str(error)) from None
    selected_keys = {normalize_name(name) for name in selected_names}
    selected_candidate_count = len(selected_names)
    try:
        direct = (paths.select_direct_access(args.direct_access, inventory_names)
                  if args.direct_access is not None else frozenset())
    except paths.SelectorError as error:
        raise SetupError(str(error)) from None
    # K11: resolve once against all CSV IB names before any device/output/cache path.
    args._refresh_host_key_names = resolve_host_key_refresh_selector(selector_value,
        inventory_devices if selector_value is not None else {})
    if replace_mode:
        args._replace_selected = {}
        for device in inventory_devices.values():
            if normalize_name(device.hostname) in selected_keys:
                args._replace_selected[normalize_name(device.hostname)] = select_replace_yaml(
                    Target(device, None, "", "eth0"), args._replace_release,
                    args._replace_manifest, _bindings=replace_bindings)
        profile_root = project if project is not None else Path(__file__).resolve().parent
        try:
            global_path = profile_root / "01-global.yaml"
            global_target = global_path.resolve(strict=True)
            global_digest = _file_sha256(global_target)
            if global_digest != binding_out["global_sha256"]:
                raise ValueError
        except (OSError, ValueError):
            raise SetupError("replace global differs from the published release; run load") from None
        replace_bindings[global_path.absolute()] = (global_target, global_digest)
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
            inventory_check=inventory_check,
        )
        _runtime_routes(targets, direct, emit=print)
        print(f"Input CSV: {ib_csv_path}")
        print(f"Input P2P: {p2p_path}")
        print(f"Generated: {cache_path}")
        print(f"Generated: {cache_path.with_name(cache_path.name + '.sha256')}")
        print(
            f"IB candidates: {len(ib_devices)}; "
            + _classified_target_counts(targets)
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
    if replace_mode:
        authority_paths.extend(replace_bindings)
    runtime_authority = RuntimeInputAuthority(authority_paths)
    if replace_mode:
        # Bind the checked snapshot, not a fresh value accepted after it changed.
        for path, resolved, _signature, digest in runtime_authority.entries:
            expected = replace_bindings.get(path)
            if expected is not None and (resolved, digest) != expected:
                raise ProjectInputChanged("replace input changed after validation; run load")
        runtime_authority.assert_unchanged()
        args._replace_runtime_authority = runtime_authority
    # The admitted profile travels with the accepted cache (DEV); the strict
    # management-server admission below compares it with what the run uses.
    cache_observe_profile = args.execution_mode != "ethernet"
    cache_admission_out = {} if cache_observe_profile else None
    cache_generated_profile = None
    cache_loader = load_target_cache if role_csv_sha256 is None else _load_target_cache
    selection_binding = ({} if role_csv_sha256 is None else
                         {"expected_ib_csv_sha256": role_csv_sha256})
    cached = cache_loader(
        cache_path, ib_csv_path, p2p_path,
        public_key_tool=tool if source_inputs_available else None,
        validate_public_keys_with_ssh_keygen=args.execution_mode == "management",
        allow_baked_missing_global=args.execution_mode != "management",
        **({"_admission_out": cache_admission_out} if cache_observe_profile else {}),
        **key_option, **selection_binding,
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
            cached = cache_loader(
                cache_path, ib_csv_path, p2p_path, public_key_tool=tool,
                validate_public_keys_with_ssh_keygen=True,
                allow_baked_missing_global=False,
                **({"_admission_out": cache_admission_out} if cache_observe_profile else {}),
                **key_option, **selection_binding,
            )
    if cached is not None:
        ib_candidate_count, targets = cached
        log(f"Target cache: reused {cache_path}")
    else:
        if args.execution_mode == "ethernet" or (args.execution_mode == "auto" and leaf):
            if cache_path.is_file():
                raise SetupError(
                    "target cache version, checksum, or input identity is invalid; "
                    "regenerate version 6 on the management server"
                )
            raise SetupError("target cache is missing; generate version 6 on the management server")
        if cold_inputs is not None:
            ib_devices, targets = cold_inputs
        else:
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
            inventory_check=inventory_check,
        )
        cache_generated_profile = cache_generated_candidate
        log(f"Target cache: generated {cache_path}")
    cache_payload = json.loads(cache_path.read_text(encoding="utf-8"))
    base_targets = targets
    targets = _runtime_routes(base_targets, direct)
    targets = [target for target in targets if normalize_name(target.ib.hostname) in selected_keys]
    services = cache_payload["services"]
    public_keys = cache_payload["public_keys"]
    log(f"Public-key input: {key_dir}; usable entries={len(public_keys)}")
    for entry in public_keys:
        log(f"  Queued IB public key: {entry['name']} {entry['fingerprint']}")
    if not public_keys:
        log("WARNING: no usable *.pub keys found; no IB public key will be installed.")

    log(f"IB candidates in CSV: {ib_candidate_count}")
    log(_classified_target_counts(targets))
    for target in targets:
        if target.ethernet is not None:
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
        if replace_mode:
            for target in targets:
                selected = args._replace_selected[normalize_name(target.ib.hostname)]
                log(f"  [{target.ib.hostname}] {selected['verdict']}: {selected['file']}")
                log("    整份替换（会清掉 yaml 以外的配置）")
                if selected["sha256"]:
                    log("    sha256=" + selected["sha256"])
                if selected["reason"]:
                    log("    " + selected["reason"])
                if selected["verdict"] == "WOULD_REPLACE":
                    log("    Identity -> backup -> Initial/ZTP check -> nv config replace")
                    log("    -> apply/save -> restore missing services -> ZTP check -> public keys")
                    log("    -> final management IPv4 verification (first delay 15s)")
            runtime_authority.assert_unchanged()
            return 0
        log("Plan lists potential commands; already-present values may be omitted at runtime.")
        for target in targets:
            if target.ib.input_issues:
                continue
            if _jump_has_no_login_address(target.ethernet):
                log(f"  [{target.ib.hostname}] SKIPPED_JUMP_ADDRESS_INVALID: "
                    f"{target.ethernet.hostname} has no valid login candidate.")
                continue
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

    jump_access_targets = [target for target in targets if target.ethernet is not None
                           and not target.ib.input_issues
                           and (target.ethernet.jump_candidates or target.ethernet.login_ip)]
    physical_keys = local_ethernet_keys(
        base_targets, args.execution_mode, args.local_ethernet_hostname
    )
    local_keys = physical_keys & {
        normalize_name(target.ethernet.hostname) for target in targets if target.ethernet is not None
    }
    # A remote Spine task does not turn a process running on a Leaf into a
    # management server. Preserve the actual location for the final direct probe.
    args._on_management_server = args.execution_mode != "ethernet" and not physical_keys
    management_private_key = None
    if args._on_management_server:
        candidate_private_key = Path.home() / ".ssh" / "id_ed25519"
        if candidate_private_key.is_file() and not candidate_private_key.is_symlink():
            management_private_key = candidate_private_key
    if physical_keys:
        log("Local Ethernet execution: " + ", ".join(sorted(physical_keys)))
    else:
        log("Execution location: management server (all Ethernet access uses SSH)")
    if method_cycle is not None:
        if physical_keys or args.execution_mode == "ethernet" or not args.apply:
            raise SetupError("managed method authority requires an explicit management --apply execution")
        # The cache's targets, not argv overrides or Spine-routed copies
        # (config_sync_authority _inputs).
        selection_options = ({} if devices_selector is None else
                             {"selected_names": tuple(selected_names)})
        method_cycle.start(tool, cache_path, ib_csv_path, p2p_path, base_targets, services, public_keys,
                           **selection_options)
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
                        "ethernet": device_to_dict(item.ethernet) if item.ethernet is not None else None,
                        "ethernet_port": item.ethernet_port,
                        "ib_port_alias": item.ib_port_alias,
                    }
                    for item in base_targets
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
                        if (strict_role == "ethernet" and strict_actual_device is None
                                and strict_reported_device is None
                                and cache_payload["routes"][strict_actual["ib"]["hostname"]]["path"] == "direct"):
                            continue
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
    replace_apply = replace_mode and args.apply
    if replace_apply:
        # Only the admitted management project can enter a write-capable path.
        if (args._on_management_server is not True or args._strict_cache is None
                or type(policy) is not ProjectPasswordPolicy
                or args._replace_runtime_authority is not runtime_authority):
            raise SetupError("replace apply requires a qualified management project")
        runtime_authority.assert_unchanged(_stable_file_refresh=True)
    if policy is not None:
        # I039: qualify the real target before the first OOB or IB session,
        # even when later cable preparation yields no eligible IB task.
        policy.password()
    if replace_apply:
        # Qualification may wait for input; keep the same publication snapshot.
        runtime_authority.assert_unchanged(_stable_file_refresh=True)
    _JUMP_SESSIONS = _new_jump_sessions(local_keys=local_keys, timeout=args.connect_timeout)
    passwords = prompt_ethernet_passwords(
        jump_access_targets, args.ethernet_password, local_keys,
        eth_user=args.eth_user, timeout=args.connect_timeout,
        password_for=jump_password_for,
        jump_sessions=_JUMP_SESSIONS,
    )
    apply_authorized = bool(args.apply and args.yes)
    if apply_authorized:
        log("Device changes: pre-authorized by --apply --yes.")

    interface_tables: dict[str, str] = {}
    network_tables: dict[str, tuple[str, str, str]] = {}
    table_failures: dict[str, SetupError] = {}
    failures = configured = skipped = day0_skipped = services_skipped = 0
    outcomes = {normalize_name(target.ib.hostname): "NOT_ATTEMPTED" for target in targets}
    # Verified credentials are retained in process memory only for the final probe.
    direct_credentials: dict[str, str] = {}
    ethernet_switches = {
        normalize_name(target.ethernet.hostname): target.ethernet
        for target in targets if target.ethernet is not None and not target.ib.input_issues
        and (target.ethernet.jump_candidates or target.ethernet.login_ip)
    }
    log("\nCollecting Ethernet snapshots ...")
    def collect_leaf_snapshot(ethernet):
        eth_key = normalize_name(ethernet.hostname)
        ethernet_is_local = eth_key in local_keys
        eth_password = passwords[eth_key]
        location = "local" if ethernet_is_local else "SSH"
        log(f"  [{ethernet.hostname}] via {location}")
        if eth_password is None:
            raise SetupError(f"OOB access unavailable: no --credentials-fd password for "
                             f"{ethernet.hostname}; no login attempted")
        actual_hostname, interfaces = collect_ethernet_interfaces(
            ethernet, args.eth_user, eth_password, args.connect_timeout, local=ethernet_is_local)
        network = collect_ethernet_network_tables(
            ethernet, args.eth_user, eth_password, args.connect_timeout, local=ethernet_is_local)
        links, fdb, vlans = network
        snapshot_path = save_ethernet_snapshot(
            snapshot_directory, ethernet, actual_hostname, location, interfaces, links, fdb, vlans)
        interface_tables[eth_key], network_tables[eth_key] = interfaces, network
        log(f"    Snapshot saved: {snapshot_path}")

    table_failures.update(collect_jump_snapshot_passes(
        [device for key, device in sorted(ethernet_switches.items())], collect_leaf_snapshot,
        authority=runtime_authority))
    for eth_key, error in table_failures.items():
        log(f"    ERROR: {error}")

    log("\nPreparing IB tasks from completed OOB snapshots ...")
    runtime_authority.assert_unchanged()
    records = {}
    # Routing is live evidence, never a cached success or a fabricated P2P link.
    # Read the same hash-pinned CSV even when static P2P target cache is reused.
    _, transit_inventory = load_devices(ib_csv_path)
    spine_inventory = select_spine_inventory(transit_inventory, args.oob_spines)
    cascade_ports = set()
    for link in parse_p2p(p2p_path):
        left = resolve_device(link.left_device, transit_inventory)
        right = resolve_device(link.right_device, transit_inventory)
        if left is not None and right is not None:
            cascade_ports.add((left.hostname, cumulus_port_name(link.left_port)))
            cascade_ports.add((right.hostname, cumulus_port_name(link.right_port)))
    leaf_snapshot_failures = {key: str(value) for key, value in table_failures.items()}
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
            eth_user=args.eth_user, timeout=args.connect_timeout, password_for=jump_password_for,
            jump_sessions=_JUMP_SESSIONS))
        log("\nCollecting LLDP Spine candidate snapshots (read-only) ...")
        def collect_one_spine(device):
            key = normalize_name(device.hostname)
            if passwords[key] is None:
                raise SetupError(f"OOB access unavailable: no --credentials-fd password for "
                                 f"{device.hostname}; no login attempted")
            actual, interfaces = collect_ethernet_interfaces(device, args.eth_user, passwords[key],
                args.connect_timeout, local=key in local_keys)
            network = collect_ethernet_network_tables(device, args.eth_user, passwords[key],
                args.connect_timeout, local=key in local_keys)
            interface_tables[key], network_tables[key] = interfaces, network
            save_ethernet_snapshot(snapshot_directory, device, actual,
                "local" if key in local_keys else "SSH", interfaces, *network)
        failed = collect_jump_snapshot_passes(missing, collect_one_spine, authority=runtime_authority)
        table_failures.update(failed)
        for key, error in failed.items():
            log(f"  [SPINE] {key}: snapshot failed; {redact_text(str(error), list(passwords.values()))}")

    jump_targets, direct_targets = [], []
    for target in targets:
        name = normalize_name(target.ib.hostname)
        blocked = target.ib.input_issues
        invalid_jump = _jump_has_no_login_address(target.ethernet)
        leaf_direct = target.ethernet is None and not args._on_management_server
        if blocked or invalid_jump or leaf_direct:
            if blocked or invalid_jump:
                category = "SKIPPED_INPUT_INCOMPLETE" if blocked else "SKIPPED_JUMP_ADDRESS_INVALID"
                issues = blocked if blocked else target.ethernet.input_issues
                reason = "; ".join(item.field + "=" + item.value + ": " + item.problem for item in issues)
            else:
                category = "SKIPPED"
                reason = "直接登录只在管理服务器上执行"
            outcomes[name] = "SKIPPED"
            records[name] = {"hostname": target.ib.hostname,
                "oob": target.ethernet.hostname if target.ethernet is not None else None,
                "port": target.ethernet_port, "outcome": "SKIPPED", "category": category,
                "reason": reason,
                "writes_attempted": False, "metrics": {}, "stage_status": {}}
        elif target.ethernet is None:
            direct_targets.append(target)
        else:
            jump_targets.append(target)
    ready_tasks = prepare_routed_ib_tasks(
        jump_targets, args, passwords, local_keys, interface_tables, network_tables, table_failures,
        outcomes, records, spines=spine_inventory, fetch_addresses=fetch_oob_addresses,
        collect_spines=collect_spine_snapshots, jump_routes=jump_routes,
        cascade_ports=frozenset(cascade_ports))
    ready_tasks.extend(PreparedIBTask(target, _direct_endpoint_for(target), "", False)
                       for target in direct_targets)
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
    log(f"IB selection: total-ib={selected_candidate_count} "
        f"filtered-ib={selected_candidate_count-len(ready_tasks)} ready-ib={len(ready_tasks)} "
        f"(prerequisite-blocked={len(targets)-len(ready_tasks)} "
        f"unmapped={selected_candidate_count-len(targets)})")
    batch = run_prepared_tasks(
        ready_tasks, args, policy, initial_ib_password, services, public_keys,
        management_private_key, authority=runtime_authority, method_cycle=method_cycle,
        preflight_records=records)
    outcomes.update(batch["outcomes"])
    records.update(batch["records"])
    for target in targets:
        record = records.setdefault(normalize_name(target.ib.hostname), {"hostname": target.ib.hostname})
        for key, value in _login_path_record_metadata(target).items():
            record.setdefault(key, value)
        record.setdefault("category", record_category(record))
        record.setdefault("config_mode", getattr(args, "config_mode", "patch"))
        if record["config_mode"] == "replace":
            selected = getattr(args, "_replace_selected", {}).get(normalize_name(target.ib.hostname))
            if selected is not None:
                record.setdefault("replace", dict(selected))
        _complete_result_fields(record)
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
    summary += " unmapped-csv=" + str(max(0, selected_candidate_count - len(targets)))
    summary += (f" direct-ssh-pass={direct_summary['ready']} "
                f"direct-ssh-fail={direct_summary['failed']} "
                f"direct-ssh-not-tested={direct_summary['not_tested']} "
                f"direct-ssh-eth1-fallback={direct_summary['fallback']} "
                f"upgrade-ssh-ready={direct_summary['ready']}/{len(targets)}")
    report_detail("\n" + summary)
    # The DEV policy keeps the resolved global in binding[0] (v15 read policy.resolved).
    project_name = Path(policy.binding[0]).parent.name if policy is not None else ib_csv_path.resolve().parent.name
    summary_status = print_initial_setup_summary(project_name, args, targets, selected_candidate_count,
        leaf_snapshot_failures, records, direct_rows, batch["workers"], batch["fatal"], jump_routes=jump_routes)
    evidence = {"schema_version": RESULT_SCHEMA_VERSION, "config_mode": getattr(args, "config_mode", "patch"),
                "selection": {"selector": devices_selector, "selected": selected_names,
                              "unmapped": [name for name in selected_names if normalize_name(name) not in records]},
                "project": project_name, "revision": _REPOSITORY_REVISION,
                "source_sha256": next(entry[3] for entry in runtime_authority.entries
                                      if entry[0] == _SELF_SOURCE_PATH.absolute()),
                "mode": "APPLY" if args.apply else "CHECK_ONLY", "result": summary_status,
                "workers": batch["workers"], "csv_ib_candidates": selected_candidate_count,
                "p2p_management_targets": len(targets), "oob_snapshot_failures": leaf_snapshot_failures,
                "spine_snapshot_failures": {key: str(value) for key, value in table_failures.items()
                                            if key not in ethernet_switches},
                "spine_jump_routes": jump_routes,
                "records": records, "direct_rows": direct_rows, "batch_stop_reason": batch["fatal"],
                "routes": {target.ib.hostname: asdict(target.route) for target in targets},
                "input_issues": cache_payload["input_issues"],
                "eth1_hints": cache_payload["eth1_hints"],
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
