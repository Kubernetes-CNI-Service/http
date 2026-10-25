#!/usr/bin/env python3
"""Initialize NVOS management through Ethernet OOB switches.

The program runs on a management host.  It logs in to each Ethernet switch
listed in ib.csv, correlates P2P ports with ``ip -d link show``,
``bridge fdb show`` and ``ip neighbor``, then reaches the attached NVOS switch
through its IPv6 link-local address from that Ethernet switch.

Python 3 standard library only.  No sshpass, pexpect, Paramiko, or Excel module
is required.
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
import os
import pty
import re
import select
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
import weakref
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from contextlib import contextmanager
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Callable, Optional


NA_VALUES = {"", "na", "n/a", "none", "null", "tbd", "-"}
IB_PORT_ALIASES = {"eth0", "mgmt", "management", "bmc"}
DEFAULT_HOSTNAMES = {"", "nvos"}
TRANSIT_DEVICE_TYPES = frozenset({"eth", "eth_spx", "spx", "ethernet", "eth_jump"})
TARGET_CACHE_VERSION = 4
_SELF_SOURCE_PATH = Path(__file__).resolve()
MAC_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
DOT_LINK_RE = re.compile(
    r'^\s*"([^"]+)"\s*:\s*"([^"]+)"\s*--\s*'
    r'"([^"]+)"\s*:\s*"([^"]+)"'
)
REPORT_HANDLE = None
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


class ProjectInputChanged(SetupError):
    """The selected project's password authority changed during this run."""


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
        self._auto_authority_failed = False
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
                raise SetupError("auto credential lacks an explicit verified IB target; no change performed")
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


@dataclass(frozen=True)
class Neighbor:
    ipv6: str
    interface: str
    mac: str
    vrf: str = "default"


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
    print(message, flush=True)
    if REPORT_HANDLE is not None:
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
    """Read the initial NVOS credential without source/argv/log disclosure."""
    selected_name = (
        "NVOS_FACTORY_DEFAULT_ADMIN_PASSWORD"
        if factory_default_admin else environment_name
    )
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", selected_name):
        raise SetupError(f"invalid initial-password environment name: {selected_name!r}")
    supplied = os.environ.get(selected_name, "")
    if supplied:
        return supplied
    can_prompt = sys.stdin.isatty() if interactive is None else interactive
    if not can_prompt:
        raise SetupError(
            f"initial NVOS password is required; export {selected_name} "
            "or run interactively"
        )
    label = (
        "NVOS factory-default admin password"
        if factory_default_admin else "Initial NVOS password"
    )
    supplied = getpass.getpass(f"{label}: ")
    if not supplied:
        raise SetupError("initial NVOS password cannot be empty")
    return supplied


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
                elif dev_type == "eth_jump":
                    eth0 = str(ipaddress.IPv4Address(eth0_ip)) if usable(eth0_ip) else ""
                    eth1 = ""
                    eth0_gateway = ""
                    eth1_gateway = ""
                else:
                    if not usable(eth0_ip):
                        raise SetupError(f"{hostname}.eth0_ip login address is required")
                    eth0 = str(ipaddress.IPv4Address(eth0_ip.split("/", 1)[0]))
                    eth1 = ""
                    eth0_gateway = ""
                    eth1_gateway = ""
            except (SetupError, ValueError) as exc:
                raise SetupError(f"{path}:{line_number}: {exc}") from exc

            device = Device(
                hostname, dev_type, eth0.split("/", 1)[0], eth0,
                eth0_gateway, eth0_mac, eth1, eth1_gateway,
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


def require_auto_full_target_coverage(ib_candidate_count: int,
                                      targets: list[Target]) -> None:
    names = [normalize_name(target.ib.hostname) for target in targets]
    if ib_candidate_count < 1 or len(names) != ib_candidate_count or len(set(names)) != len(names):
        raise SetupError(
            "--auto requires one P2P management link for every CSV IB switch; "
            "fix CSV/P2P before starting a watch"
        )


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


def _service_profile(tool: Path) -> Optional[dict[str, object]]:
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
    neutral = _neutral_services(tool)
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

    def public_keys(self, tool):
        directory = tool / "publickey"
        return sorted(Path(name) for name in self.images
                      if Path(name).parent == directory and Path(name).name.endswith(".pub"))


def _public_key_profile(tool: Path, *, validate_with_ssh_keygen: bool = True,
                        input_snapshot: Optional[_CacheInputSnapshot] = None
                        ) -> list[dict[str, str]]:
    directory = tool / "publickey"
    if input_snapshot is None and not directory.is_dir():
        return []
    result: list[dict[str, str]] = []
    validator: Optional[str] = None
    paths = input_snapshot.public_keys(tool) if input_snapshot is not None else sorted(directory.glob("*.pub"))
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
                      _admission_out=None
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
            source_dir = public_key_tool / "publickey"
            source_available = captured is not None or source_dir.is_dir()
            paths = captured.public_keys(public_key_tool) if captured is not None else source_dir.glob("*.pub")
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

def strip_ansi(value: str) -> str:
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", value).replace("\r", "")



class IBAuthenticationError(SetupError):
    """Attributable completed inner password rejection; never an IO/PAM guess."""


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
        if type(policy) is not ProjectPasswordPolicy:
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
        if type(policy) is ProjectPasswordPolicy:
            policy._auto_authority_failed = True
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


@dataclass(repr=False)
class _IBLogin:
    current_password: str
    read_result: SessionResult


def _authenticate_ib_read(target, neighbor, eth_user, ethernet_password, ib_user,
                          initial_password, timeout, *, local=False, _password_policy=None):
    first_rejected = False
    result = None
    try:
        result = _execute_ib_phase(
            target, neighbor, eth_user, ethernet_password, ib_user, initial_password,
            timeout, ["nv", "config", "show", "-o", "commands"], local=local,
            _phase_operation="auth-probe-readonly", _password_policy=_password_policy)
    except IBAuthenticationError:
        first_rejected = True
    if not first_rejected:
        return _IBLogin(initial_password, result)
    # Not inside the caught rejection's exception scope; target is lazy.
    target_password = _ib_project_value(_password_policy, user=ib_user, fetch=True)
    if hmac.compare_digest(initial_password.encode("utf-8"), target_password.encode("utf-8")):
        if type(_password_policy) is ProjectPasswordPolicy:
            _password_policy._auto_authority_failed = True
        raise SetupError("known IB credential sources are exhausted; device is HOLD")
    second_rejected = False
    try:
        result = _execute_ib_phase(
            target, neighbor, eth_user, ethernet_password, ib_user, target_password,
            timeout, ["nv", "config", "show", "-o", "commands"], local=local,
            _phase_operation="auth-probe-readonly", _password_policy=_password_policy)
    except IBAuthenticationError:
        second_rejected = True
    if second_rejected:
        if type(_password_policy) is ProjectPasswordPolicy:
            _password_policy._auto_authority_failed = True
        raise SetupError("known IB credential sources are exhausted; device is HOLD")
    return _IBLogin(target_password, result)


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
    """Enforce the NVOS command vectors used by this Day-0 workflow."""
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
        ("nv", "config", "apply", "-y"),
        ("nv", "config", "diff", "-o", "commands"),
        ("nv", "show", "system", "ztp"),
        ("nv", "set", "system", "config", "auto-save", "state", "enabled"),
        ("nv", "set", "system", "ztp", "config-save", "enabled"),
        ("nv", "config", "save"),
    }:
        return command
    if len(command) == 7 and command[:3] == ["nv", "set", "interface"]:
        interface, family, operation, value = command[3:]
        if (interface in {"eth0", "eth1", "eth0-1"}
                and (family, operation, value) == ("link", "state", "up")):
            return command
        if interface not in {"eth0", "eth1", "eth0-1"} or family != "ipv4":
            raise SetupError(
                "NVOS command is not allowed by the Day-0 argv allowlist: "
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
        len(command) == 6 and command[:3] == ["nv", "set", "interface"]
        and command[3] in {"eth0", "eth1", "eth0-1"}
        and command[4:] == ["type", "eth"]
    ):
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
        "NVOS command is not allowed by the Day-0 argv allowlist: "
        + shlex.join(command)
    )


def outer_ssh_command(ethernet: Device, user: str, remote_argv: list[str],
                      timeout: int, *, tty: bool = False,
                      local: bool = False) -> list[str]:
    command = typed_argv(remote_argv, label="outer SSH command")
    if local:
        return command
    if not usable(ethernet.login_ip):
        raise SetupError(
            f"{ethernet.hostname}.eth0_ip login address is required for remote Ethernet access"
        )
    script = "export PATH=" + shlex.quote(_SAFE_PATH) + "; exec " + shlex.join(command)
    wrapper = ["sh", "-c", script]
    return ["ssh", *( ["-tt"] if tty else [] ), *ssh_options(timeout),
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
        raise SetupError(
            f"port {port} learned MAC(s) {', '.join(macs)}, but ip neighbor has no "
            "matching IPv6 link-local entry"
        )
    if len(matches) != 1:
        details = ", ".join(
            f"{item.ipv6}%{item.interface}/{item.mac}" for item in matches.values()
        )
        raise SetupError(f"multiple IPv6 neighbors match port {port}: {details}")
    return next(iter(matches.values()))


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
            f"{target.ib.hostname} is not a type=ib Day-0 target"
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
              _phase_operation: Optional[str] = None, _password_policy=None) -> SessionResult:
    if (ib_command == ["nv", "config", "diff", "-o", "commands"]
            and allow_password_change):
        raise SetupError("read-only pending diff cannot allow password change")
    if _phase_operation is not None:
        return _execute_ib_phase(
            target, neighbor, eth_user, ethernet_password, ib_user, ib_default_password,
            timeout, ib_command, local=local, allow_password_change=allow_password_change,
            ib_new_password=ib_new_password, _phase_operation=_phase_operation,
            _password_policy=_password_policy)
    marker = os.urandom(16).hex()
    command = nested_ssh_command(
        target, neighbor, eth_user, ib_user, timeout, ib_command,
        local=local, marker=marker,
    )
    responder = NestedResponder(
        ethernet_password, ib_default_password, allow_password_change,
        ib_new_password=ib_new_password,
        ib_destination=f"{ib_user}@{neighbor.ipv6}",
    )
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
    password_change_completed = (
        result.password_changed and _PASSWORD_UPDATED.search(result.output)
    )
    if ib_command == ["nv", "config", "diff", "-o", "commands"] and (
        type(result.exit_code) is not int or result.exit_code not in (0, 1)
        or _NETWORK_FAILURE.search(result.output)
    ):
        raise SetupError("pending diff transport evidence is UNKNOWN")
    if result.exit_code != 0 and not password_change_completed:
        if (
            ib_command == ["nv", "config", "diff", "-o", "commands"]
            and type(result.exit_code) is int and result.exit_code == 1
            and not _NETWORK_FAILURE.search(result.output)
        ):
            pending = extract_command_output(result.output, marker, expected_exit_code=1)
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
    if password_change_completed:
        return result
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
        _validate_owned_pending(target.ib, result.output)
    return result


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
        raise SetupError(
            f"eth0 MAC mismatch: CSV expected {device.eth0_mac}, "
            f"OOB Leaf FDB reports {actual}; "
            "the CSV MAC may be wrong, or the IB device may be connected to the wrong "
            f"OOB Leaf interface (expected {target.ethernet.hostname}:"
            f"{target.ethernet_port} for {device.hostname})"
        )
    log(f"  eth0 MAC verified from OOB Leaf FDB: {actual}")


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
    """Classify protected Day-0 fields without repairing partial configurations.

    A watch round may configure only the untouched factory state.  Existing
    fields must match the CSV exactly before services or keys are attempted;
    neither a missing field nor a contradictory field is silently complete.
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
    commands = [
        ["nv", "set", "interface", "eth0", "ipv4", "address", device.eth0_prefix],
    ]
    if device.eth1_prefix:
        commands.append(
            ["nv", "set", "interface", "eth1", "ipv4", "address", device.eth1_prefix]
        )
    if device.eth1_prefix and device.eth1_gateway != device.eth0_gateway:
        commands.extend([
            ["nv", "set", "interface", "eth0", "ipv4", "gateway", device.eth0_gateway],
            ["nv", "set", "interface", "eth1", "ipv4", "gateway", device.eth1_gateway],
        ])
    else:
        commands.append(
            [
                "nv", "set", "interface", "eth0-1", "ipv4", "gateway",
                device.eth0_gateway,
            ]
        )
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
    """Fill missing requested values; reject conflicting hostnames and gateways."""
    expected_eth1 = device.eth1_prefix
    expected_eth1_gateway = device.eth1_gateway if expected_eth1 else ""
    fields = (
        ("eth0 address", state.eth0_addresses, device.eth0_prefix),
        ("eth1 address", state.eth1_addresses, expected_eth1),
        ("eth0 gateway", state.eth0_gateways, device.eth0_gateway),
        ("eth1 gateway", state.eth1_gateways, expected_eth1_gateway),
    )
    missing = False
    conflicts: list[str] = []
    for label, actual, expected in fields:
        if not expected or expected in actual:
            continue
        if actual and "gateway" in label:
            conflicts.append(f"{label}: expected {expected}, found {actual}")
        else:
            missing = True
    hostname = normalize_name(state.hostname)
    if hostname in DEFAULT_HOSTNAMES:
        missing = True
    elif hostname != normalize_name(device.hostname):
        conflicts.append(f"hostname: expected {device.hostname}, found {state.hostname}")
    if conflicts:
        raise SetupError("Day-0 conflict; manual resolution required: " + "; ".join(conflicts))
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
                      _password_policy=None) -> None:
    if _ib_current_password is not None or _password_policy is not None:
        failure = None
        try:
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
            for credential in (ethernet_password, _ib_current_password):
                if (type(credential) is not str or not credential
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
            command = ib_command_argv(["true"])
            nested = typed_argv([
                "ip", "vrf", "exec", validated_vrf, "ssh",
                "-o", f"ConnectTimeout={timeout}",
                "-o", "StrictHostKeyChecking=accept-new",
                "-o", "LogLevel=ERROR",
                f"{ib_user}@{destination}", shlex.join(command),
            ], label="IPv4 management command")
            command = outer_ssh_command(
                target.ethernet, eth_user, nested, timeout, tty=True, local=False,
            )
            command = typed_argv(command, label="IPv4 management outer command")
            responder = NestedResponder(
                ethernet_password, _ib_current_password, False,
                ib_destination=f"{ib_user}@{destination}",
            )
            result = interactive_run(command, responder, max(timeout * 3, 45))
            if (type(result) is not SessionResult
                    or type(result.exit_code) is not int or result.exit_code != 0
                    or type(result.output) is not str
                    or any(getattr(result, name) is not False for name in (
                        "password_changed", "password_change_required",
                        "password_change_attempted", "ib_authentication_rejected"))
                    or responder.password_change_attempted
                    or responder.password_change_blocked
                    or _EXPIRED_PASSWORD.search(result.output)
                    or _pending_diff_has_password_update_notice(result.output)):
                raise SetupError("IPv4 management outcome is unverified")
            _password_policy.assert_unchanged()
        except (SetupError, OSError) as error:
            uncertain, number = _ib_phase_error_facts(error)
            if number is None:
                candidate = getattr(error, "io_errno", None)
                if type(candidate) is int and 1 <= candidate <= 255:
                    number = candidate
            failure = uncertain, number
        if failure is not None:
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
        return
    validate_jump_target(target)
    validated_vrf = validate_network_selector(vrf, label="IPv4 verification VRF")
    command = ib_command_argv(["true"])
    nested = [
        "ip", "vrf", "exec", validated_vrf, "ssh",
        "-o", f"ConnectTimeout={timeout}",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "LogLevel=ERROR",
        f"{ib_user}@{target.ib.login_ip}", shlex.join(command),
    ]
    command = outer_ssh_command(
        target.ethernet, eth_user, nested, timeout,
        tty=True, local=local,
    )
    result = interactive_run(
        command,
        NestedResponder(ethernet_password, ethernet_password, False),
        max(timeout * 3, 45),
    )
    if result.exit_code != 0:
        raise SetupError(
            f"IPv4 SSH verification failed for {target.ib.hostname} "
            f"({target.ib.login_ip}) via {target.ethernet.hostname}: "
            f"{result.output.strip()[-800:]}"
        )


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
                              local_keys: set[str]) -> dict[str, str]:
    passwords: dict[str, str] = {}
    switches: dict[str, Device] = {
        normalize_name(target.ethernet.hostname): target.ethernet for target in targets
    }
    if supplied is not None:
        return {key: supplied for key in switches}
    for key, switch in sorted(switches.items()):
        purpose = (
            ", local; also used as the new NVOS password"
            if key in local_keys else ""
        )
        passwords[key] = getpass.getpass(
            f"Ethernet password for {switch.hostname} ({switch.login_ip}{purpose}): "
        )
    return passwords


_AUTO_ENV_MAX_BYTES = 65536
_AUTO_CRON_MARKER = "# http-v3-req10c-auto"


def _required_auto_fd_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    if not nofollow or not cloexec:
        raise SetupError("auto.env safety requires O_NOFOLLOW and O_CLOEXEC")
    return nofollow | cloexec


def _auto_state_dir(tool: Path) -> Path:
    return tool / "xdr-initial-setup-logs"


def _auto_input_identity(*paths: Path) -> str:
    """Bind terminal outcomes to input bytes, not only mutable mtimes."""
    digest = hashlib.sha256()
    for path in paths:
        digest.update(str(path).encode("utf-8"))
        digest.update(b"\0")
        try:
            with path.open("rb") as source:
                for chunk in iter(lambda: source.read(65536), b""):
                    digest.update(chunk)
        except OSError as exc:
            raise SetupError(f"cannot bind auto input {path}: {exc}") from exc
        digest.update(b"\0")
    return digest.hexdigest()


def _load_auto_terminal(path: Path, identity: str) -> set[str]:
    flags = os.O_RDONLY | _required_auto_fd_flags()
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return set()
    except OSError as exc:
        raise SetupError(f"cannot safely read auto terminal state: {exc}") from exc
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != os.geteuid() or info.st_mode & 0o077
            or info.st_size > 65536
        ):
            raise SetupError("auto terminal state is not an owned 0600 regular file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(65537)
    finally:
        os.close(fd)
    if len(raw) > 65536:
        raise SetupError("auto terminal state exceeds bounded size")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SetupError("auto terminal state is malformed") from exc
    if (
        not isinstance(payload, dict) or set(payload) != {"version", "inputs", "terminal"}
        or payload["version"] != 1
        or not isinstance(payload["inputs"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", payload["inputs"])
        or not isinstance(payload["terminal"], list)
        or any(not isinstance(name, str) or not re.fullmatch(r"[a-z0-9_.-]+", name)
               for name in payload["terminal"])
        or len(payload["terminal"]) != len(set(payload["terminal"]))
    ):
        raise SetupError("auto terminal state schema is invalid")
    return set(payload["terminal"]) if payload["inputs"] == identity else set()


def _save_auto_terminal(path: Path, identity: str, names: set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        {"version": 1, "inputs": identity, "terminal": sorted(names)},
        separators=(",", ":"), sort_keys=True,
    ).encode("utf-8") + b"\n"
    if len(payload) > 65536:
        raise SetupError("auto terminal state exceeds bounded size")
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _required_auto_fd_flags()
    try:
        fd = os.open(temporary, flags, 0o600)
        try:
            os.write(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, path)
    except OSError as exc:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise SetupError(f"cannot safely publish auto terminal state: {exc}") from exc


def _auto_password_key(hostname: str) -> str:
    suffix = re.sub(r"[^A-Z0-9]", "_", hostname.upper())
    if not suffix or not re.fullmatch(r"[A-Z0-9_]+", suffix):
        raise SetupError(f"invalid OOB Leaf hostname for auto credential: {hostname!r}")
    return "ZTP_ETH_PASSWORD_" + suffix


def read_auto_credentials(path: Path) -> dict[str, str]:
    """Read one bounded, owned data file through a NOFOLLOW fd, never a shell."""
    flags = os.O_RDONLY | _required_auto_fd_flags()
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise SetupError(f"auto.env credential cannot be opened safely: {exc}") from exc
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
            or info.st_size > _AUTO_ENV_MAX_BYTES
        ):
            raise SetupError("auto.env credential has unsafe owner, mode, link or size")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(_AUTO_ENV_MAX_BYTES + 1)
        if len(raw) > _AUTO_ENV_MAX_BYTES:
            raise SetupError("auto.env credential exceeds bounded size")
    finally:
        os.close(fd)
    try:
        data = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SetupError("auto.env credential is not UTF-8") from exc
    values: dict[str, str] = {}
    for line in data.splitlines():
        match = re.fullmatch(r"([A-Z][A-Z0-9_]*)=([^\x00-\x1f\x7f]*)", line)
        if not match:
            raise SetupError("auto.env credential contains a malformed KEY=VALUE line")
        key, value = match.groups()
        if (
            key in values
            or not value
            or key not in {"NVOS_INITIAL_PASSWORD", "NVOS_TARGET_PASSWORD", "ZTP_ETH_PASSWORD"}
            and not re.fullmatch(r"ZTP_ETH_PASSWORD_[A-Z0-9_]+", key)
        ):
            raise SetupError("auto.env credential contains an unknown, repeated or empty key")
        if key == "NVOS_TARGET_PASSWORD":
            _validate_target_password(value)
        values[key] = value
    if not values.get("NVOS_INITIAL_PASSWORD"):
        raise SetupError("auto.env credential lacks NVOS_INITIAL_PASSWORD")
    if not any(key.startswith("ZTP_ETH_PASSWORD") for key in values):
        raise SetupError("auto.env credential lacks OOB Leaf password")
    return values


def _auto_passwords_for_targets(credentials: dict[str, str],
                                targets: list[Target]) -> dict[str, str]:
    passwords: dict[str, str] = {}
    normalized_keys: dict[str, str] = {}
    for target in targets:
        host = target.ethernet.hostname
        key = normalize_name(host)
        variable = _auto_password_key(host)
        previous = normalized_keys.setdefault(variable, key)
        if previous != key:
            raise SetupError("auto.env OOB Leaf hostname normalization collision")
        value = credentials.get(variable, credentials.get("ZTP_ETH_PASSWORD"))
        if not value:
            raise SetupError(f"auto.env credential lacks OOB Leaf password for {host}")
        passwords[key] = value
    return passwords


def install_oob_management_key(ethernet: Device, user: str, password: str,
                               entry: dict[str, str], timeout: int) -> None:
    """Install only the baked management key on a genuine OOB Leaf.

    The eth_jump transit type is intentionally not eligible: its owner-facing
    contract forbids any remote write.  This is a closed hard-coded installer,
    not a relaxation of the read-only Ethernet argv allowlist.
    """
    if ethernet.dev_type not in {"eth", "ethernet"}:
        raise SetupError(
            f"OOB key installation is not authorized for transit type {ethernet.dev_type}"
        )
    if entry.get("name") != "mgmt-server.pub":
        raise SetupError("OOB key installation accepts only mgmt-server.pub")
    command = key_install_command([entry])
    remote = outer_ssh_command(ethernet, user, command, timeout, tty=True)
    result = interactive_run(remote, ethernet_responder(password), max(timeout * 3, 45))
    if result.exit_code != 0:
        raise SetupError(
            f"OOB Leaf management-key installation failed for {ethernet.hostname} "
            f"(exit={result.exit_code})"
        )


def _write_verified_auto_credentials(path: Path, initial: str,
                                     passwords: dict[str, str],
                                     targets: list[Target], *,
                                     policy, user) -> None:
    """Publish verified role data once; a failed new file stays private for HOLD."""
    failure = None
    directory_fd = file_fd = None
    try:
        if (type(policy) is not ProjectPasswordPolicy or type(user) is not str
                or not valid_ssh_user(user) or policy.user != user):
            raise SetupError("verified auto credential authority is invalid")
        if type(passwords) is not dict or type(targets) is not list or not targets:
            raise SetupError("verified auto credential roles are invalid")
        if any(type(item) is not Target or type(item.ethernet) is not Device
               for item in targets):
            raise SetupError("verified auto credential targets are invalid")
        hostname_for_key = {
            normalize_name(item.ethernet.hostname): item.ethernet.hostname
            for item in targets
        }
        if (any(type(key) is not str for key in passwords)
                or set(passwords) != set(hostname_for_key)):
            raise SetupError("verified auto credential roles are incomplete")
        values = [initial] + list(passwords.values())
        if any(type(value) is not str or not value
               or any(ord(char) < 32 or ord(char) == 127
                      or 0xD800 <= ord(char) <= 0xDFFF for char in value)
               or value.splitlines() != [value] for value in values):
            raise SetupError("verified auto credential values are invalid")
        target_password = _ib_project_value(policy, user=user, fetch=True)
        lines = ["NVOS_INITIAL_PASSWORD=" + initial,
                 "NVOS_TARGET_PASSWORD=" + target_password]
        published_keys = {"NVOS_INITIAL_PASSWORD", "NVOS_TARGET_PASSWORD"}
        for key, password in sorted(passwords.items()):
            output_key = _auto_password_key(hostname_for_key[key])
            if output_key in published_keys:
                raise SetupError("verified auto credential keys collide")
            published_keys.add(output_key)
            lines.append(output_key + "=" + password)
        payload = ("\n".join(lines) + "\n").encode("utf-8")
        if len(payload) > _AUTO_ENV_MAX_BYTES:
            raise SetupError("verified auto credential exceeds bounded size")
        path = Path(os.path.abspath(path))
        path.parent.mkdir(parents=True, exist_ok=True)
        directory_flags = (getattr(os, "O_DIRECTORY", 0)
                           | getattr(os, "O_CLOEXEC", 0))
        if not getattr(os, "O_DIRECTORY", 0) or not getattr(os, "O_CLOEXEC", 0):
            raise SetupError("verified auto credential needs directory custody")
        directory_fd = os.open(path.parent, os.O_RDONLY | directory_flags)
        directory_info = os.fstat(directory_fd)
        if (not stat.S_ISDIR(directory_info.st_mode)
                or directory_info.st_uid != os.geteuid()
                or directory_info.st_mode & 0o022):
            raise SetupError("verified auto credential directory is unsafe")
        _ib_project_value(policy, user=user)
        file_fd = os.open(path.name,
                          os.O_RDWR | os.O_CREAT | os.O_EXCL | _required_auto_fd_flags(),
                          0o600, dir_fd=directory_fd)
        os.fchmod(file_fd, 0o600)
        opened = os.fstat(file_fd)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or opened.st_uid != os.geteuid()
                or stat.S_IMODE(opened.st_mode) != 0o600):
            raise SetupError("verified auto credential leaf is unsafe")
        position = 0
        while position < len(payload):
            count = os.write(file_fd, payload[position:])
            if type(count) is not int or not 0 < count <= len(payload) - position:
                raise SetupError("verified auto credential write made no valid progress")
            position += count
        os.fsync(file_fd)
        seal_fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid",
                       "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        seal_info = os.fstat(file_fd)
        sealed = tuple(getattr(seal_info, field) for field in seal_fields)
        os.lseek(file_fd, 0, os.SEEK_SET)
        content = bytearray()
        while len(content) <= len(payload):
            part = os.read(file_fd, min(65536, len(payload) + 1 - len(content)))
            if not part:
                break
            content.extend(part)
        _ib_project_value(policy, user=user)
        finished = os.fstat(file_fd)
        named = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
        held_directory = os.fstat(directory_fd)
        current_directory = os.stat(path.parent)
        if (bytes(content) != payload
                or finished.st_size != len(payload)
                or (finished.st_dev, finished.st_ino) != (opened.st_dev, opened.st_ino)
                or not stat.S_ISREG(finished.st_mode) or finished.st_nlink != 1
                or finished.st_uid != os.geteuid()
                or stat.S_IMODE(finished.st_mode) != 0o600
                or tuple(getattr(finished, field) for field in seal_fields) != sealed
                or tuple(getattr(named, field) for field in seal_fields) != sealed
                or any(getattr(current_directory, field) != getattr(held_directory, field)
                       for field in seal_fields)
                or (current_directory.st_dev, current_directory.st_ino)
                   != (directory_info.st_dev, directory_info.st_ino)
                or not stat.S_ISDIR(current_directory.st_mode)
                or current_directory.st_uid != os.geteuid()
                or current_directory.st_mode & 0o022):
            raise SetupError("verified auto credential publication changed")
    except BaseException as error:
        failure = error
    for descriptor in (file_fd, directory_fd):
        if descriptor is not None:
            try:
                os.close(descriptor)
            except BaseException as error:
                if (failure is None
                        or isinstance(failure, (SetupError, OSError))
                        and not isinstance(error, (SetupError, OSError))):
                    failure = error
    if isinstance(failure, (SetupError, OSError)):
        safe = SetupError(
            "auto.env credential cannot be published safely; operator HOLD; credentials preserved"
        )
        try:
            raise safe from None
        except SetupError:
            safe.__cause__ = None
            safe.__context__ = None
            raise
    if failure is not None:
        raise failure


def _write_auto_credentials(path: Path, initial: str,
                            passwords: dict[str, str], targets: list[Target], *,
                            _password_policy=None, _ib_user=None) -> None:
    if _password_policy is not None or _ib_user is not None:
        _write_verified_auto_credentials(
            path, initial, passwords, targets, policy=_password_policy, user=_ib_user,
        )
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["NVOS_INITIAL_PASSWORD=" + initial]
    hostname_for_key = {
        normalize_name(target.ethernet.hostname): target.ethernet.hostname
        for target in targets
    }
    for key, password in sorted(passwords.items()):
        if any(c in password for c in "\r\n\x00"):
            raise SetupError("auto.env credential contains an invalid password control")
        lines.append(_auto_password_key(hostname_for_key[key]) + "=" + password)
    payload = ("\n".join(lines) + "\n").encode("utf-8")
    if len(payload) > _AUTO_ENV_MAX_BYTES:
        raise SetupError("auto.env credential exceeds bounded size")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _required_auto_fd_flags()
    try:
        fd = os.open(path, flags, 0o600)
        try:
            os.write(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as exc:
        raise SetupError(f"auto.env credential cannot be published safely: {exc}") from exc


def _auto_marker(path: Path) -> None:
    """Persist nonsecret watch ownership even if auto.env is later missing."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _required_auto_fd_flags()
        try:
            fd = os.open(path, flags, 0o600)
            try:
                os.write(fd, b"http-v3-req10c-auto-v1\n")
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError as exc:
            raise SetupError(f"cannot create owned auto watch marker: {exc}") from exc
        return
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
        or info.st_size != len(b"http-v3-req10c-auto-v1\n")
        or path.read_bytes() != b"http-v3-req10c-auto-v1\n"
    ):
        raise SetupError("auto watch marker is not owned or valid")


@contextmanager
def _auto_crontab_lock(tool: Path):
    """Serialize this project's crontab RMW operations, not foreign clients.

    The lock inode is retained after cleanup: unlinking it while a process
    waits would allow two independent lock generations to enter together.
    The project's log directory may be a managed link, so pin and validate
    the opened destination directory before opening the lock relative to it.
    """
    state = _auto_state_dir(tool)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_CLOEXEC", 0)
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_CLOEXEC"):
        raise SetupError("secure project crontab lock requires directory/CLOEXEC flags")
    try:
        directory_fd = os.open(state, directory_flags)
    except OSError as exc:
        raise SetupError(f"cannot open project crontab lock directory: {exc}") from exc
    try:
        directory_info = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(directory_info.st_mode)
            or directory_info.st_uid != os.geteuid()
            or directory_info.st_mode & 0o022
        ):
            raise SetupError("project crontab lock directory is not safely owned")
        try:
            fd = os.open(
                "auto-crontab.lock",
                os.O_RDWR | os.O_CREAT | _required_auto_fd_flags(),
                0o600, dir_fd=directory_fd,
            )
        except OSError as exc:
            raise SetupError(f"cannot open project crontab lock safely: {exc}") from exc
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o777 != 0o600
            ):
                raise SetupError("project crontab lock is not an owned 0600 single-link file")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                linked = os.stat(
                    "auto-crontab.lock", dir_fd=directory_fd,
                    follow_symlinks=False,
                )
                if (linked.st_dev, linked.st_ino) != (info.st_dev, info.st_ino):
                    raise SetupError("project crontab lock pathname changed")
                current = os.stat(state)
                if (current.st_dev, current.st_ino) != (
                    directory_info.st_dev, directory_info.st_ino
                ):
                    raise SetupError("project crontab lock directory changed")
                yield
            except OSError as exc:
                raise SetupError(f"project crontab lock failed: {exc}") from exc
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
    finally:
        os.close(directory_fd)


def _read_auto_crontab() -> str:
    try:
        result = subprocess.run(
            ["crontab", "-l"], capture_output=True, text=True, timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SetupError(f"cannot read current-user crontab: {exc}") from exc
    if result.returncode == 0:
        return result.stdout
    if result.returncode == 1 and "no crontab" in result.stderr.casefold():
        return ""
    raise SetupError(f"cannot read current-user crontab (exit {result.returncode})")


def _read_stable_auto_crontab() -> str:
    """Return a byte-stable snapshot or stop before replacing the crontab.

    The project lock serializes our own writers only.  A second read catches
    an active same-UID writer that does not use that lock; writing from a
    changing snapshot would silently erase its entry.
    """
    first = _read_auto_crontab()
    second = _read_auto_crontab()
    if first != second:
        raise SetupError(
            "current-user crontab changed during the protected read window; "
            "refusing to replace it"
        )
    return second


def _write_auto_crontab(contents: str) -> None:
    try:
        result = subprocess.run(
            ["crontab", "-"], input=contents, capture_output=True,
            text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SetupError(f"cannot update current-user crontab: {exc}") from exc
    if result.returncode != 0:
        raise SetupError(f"cannot update current-user crontab (exit {result.returncode})")


def _own_auto_cron_line(line: str, tool: Path, credentials: Path) -> bool:
    if _AUTO_CRON_MARKER in line and str(tool / "initial-setup.py") in line:
        return True
    # Cleanup of the documented pre-marker shape remains exact to the known
    # script and credential path, never a generic 'initial-setup.py' match.
    return (
        line.startswith("*/10 * * * * ")
        and "initial-setup.py --auto --apply --yes --credentials-file " in line
        and str(credentials) in line
        and str(tool) in line
    )


def _auto_pause_owned_job(line: str, tool: Path, credentials: Path) -> bool:
    """Recognize only complete canonical or documented legacy job renderings."""
    def absolute_word(value):
        return (
            type(value) is str and bool(value) and os.path.isabs(value)
            and os.path.normpath(value) == value
            and not any(ord(char) < 32 or ord(char) == 127 or char == "%"
                        for char in value)
        )

    def python_word(value):
        return (
            absolute_word(value)
            and re.fullmatch(r"(?:python|Python)(?:[0-9]+(?:\.[0-9]+)*)?",
                             os.path.basename(value)) is not None
        )

    bare = line[:-1] if line.endswith("\n") else line
    prefix = "*/10 * * * * "
    script = str(tool / "initial-setup.py")
    candidate = _own_auto_cron_line(line, tool, credentials)
    try:
        tokens = shlex.split(bare, comments=False, posix=True)
    except ValueError:
        if (
            candidate or _AUTO_CRON_MARKER in bare
            or "initial-setup.py" in bare and "--auto" in bare and str(tool) in bare
        ):
            raise SetupError("auto watch pause ownership is not qualified")
        return False
    candidate = candidate or (
        "--auto" in tokens
        and (script in tokens or str(tool) in tokens and "initial-setup.py" in tokens)
    )
    if not candidate:
        return False
    if not bare.startswith(prefix):
        raise SetupError("auto watch pause ownership is not qualified")
    words = tokens[5:]
    state = _auto_state_dir(tool)
    start = ["cd", str(tool), "&&"]
    flock_start = start + ["flock", "-w", "0", str(state / "auto.lock")]
    marker_words = ["#", "http-v3-req10c-auto"]
    if words[:7] == flock_start:
        if words[-5:] == [
            ">>", str(state / "auto-cron.log"), "2>&1", *marker_words,
        ]:
            command = words[7:-5]
            if len(command) not in (19, 20):
                raise SetupError("auto watch pause ownership is not qualified")
            if not python_word(command[0]) or not all(
                absolute_word(command[index]) for index in (10, 12, 14, 16, 18)
            ):
                raise SetupError("auto watch pause ownership is not qualified")
            expected = [
                command[0], script, "--auto", "--apply", "--yes",
                "--credentials-file", str(credentials), "--execution-mode", "management",
                "--ib-csv", command[10], "--p2p", command[12],
                "--target-cache", command[14], "--report", command[16],
                "--snapshot-dir", command[18],
            ]
            if len(command) == 20:
                expected.append("--force")
            if command != expected:
                raise SetupError("auto watch pause ownership is not qualified")
            rendered = (
                "cd " + shlex.quote(str(tool)) + " && flock -w 0 "
                + shlex.quote(str(state / "auto.lock")) + " " + shlex.join(command)
                + " >> " + shlex.quote(str(state / "auto-cron.log"))
                + " 2>&1 " + _AUTO_CRON_MARKER
            )
            if bare != prefix + rendered:
                raise SetupError("auto watch pause ownership is not qualified")
            return True
        # Historical marked minimal-flock profile has no extra flags or suffix.
        if words[-2:] != marker_words:
            raise SetupError("auto watch pause ownership is not qualified")
        command = words[7:-2]
        if (
            len(command) != 5 or not python_word(command[0])
            or command[1:] != [script, "--auto", "--credentials-file", str(credentials)]
        ):
            raise SetupError("auto watch pause ownership is not qualified")
        rendered = (
            "cd " + shlex.quote(str(tool)) + " && flock -w 0 "
            + shlex.quote(str(state / "auto.lock")) + " "
            + shlex.join(command) + " " + _AUTO_CRON_MARKER
        )
        if bare != prefix + rendered:
            raise SetupError("auto watch pause ownership is not qualified")
        return True
    if words[:3] != start:
        raise SetupError("auto watch pause ownership is not qualified")
    marked = words[-2:] == marker_words
    command = words[3:-2] if marked else words[3:]
    if (
        len(command) != 7
        or not (command[0] == "python3" or python_word(command[0]))
        or command[1] not in (script, "initial-setup.py")
        or command[2:] != [
            "--auto", "--apply", "--yes", "--credentials-file", str(credentials),
        ]
    ):
        raise SetupError("auto watch pause ownership is not qualified")
    rendered = "cd " + shlex.quote(str(tool)) + " && " + shlex.join(command)
    if marked:
        rendered += " " + _AUTO_CRON_MARKER
    if bare != prefix + rendered:
        raise SetupError("auto watch pause ownership is not qualified")
    return True


def _auto_pause_retained(contents: str, tool: Path, credentials: Path) -> str:
    """Qualify the entire listing before proposing any single replacement."""
    if type(contents) is not str or len(contents) > 1048576:
        raise SetupError("auto watch pause listing is not qualified")
    if any(ord(char) < 32 and char not in "\t\n\r" or ord(char) == 127
           or char in "\u0085\u2028\u2029" for char in contents):
        raise SetupError("auto watch pause listing is not qualified")
    if "\r" in contents.replace("\r\n", ""):
        raise SetupError("auto watch pause listing is not qualified")
    try:
        encoded_size = len(contents.encode("utf-8"))
    except UnicodeError:
        raise SetupError("auto watch pause listing is not qualified") from None
    if encoded_size > 1048576:
        raise SetupError("auto watch pause listing is not qualified")
    retained = []
    for line in contents.splitlines(keepends=True):
        if not _auto_pause_owned_job(line, tool, credentials):
            retained.append(line)
    return "".join(retained)


def _pause_auto_watch(tool: Path, credentials: Path) -> None:
    """Confirm a bounded own-job pause without touching credentials or marker."""
    body_error = None
    release_error = None
    entered = False
    lock = None
    try:
        if not isinstance(tool, Path) or not isinstance(credentials, Path):
            raise SetupError("auto watch pause paths are not qualified")
        for value in (str(tool), str(credentials)):
            if (
                not os.path.isabs(value) or os.path.normpath(value) != value
                or any(ord(char) < 32 or ord(char) == 127 or char == "%"
                       for char in value)
            ):
                raise SetupError("auto watch pause paths are not qualified")
        lock = _auto_crontab_lock(tool)
        lock.__enter__()
        entered = True
    except BaseException as error:
        body_error = error
    if entered:
        try:
            existing = _read_stable_auto_crontab()
            retained = _auto_pause_retained(existing, tool, credentials)
            if retained != existing:
                _write_auto_crontab(retained)
                observed = _read_stable_auto_crontab()
                if (
                    type(observed) is not str or observed != retained
                    or _auto_pause_retained(observed, tool, credentials) != observed
                ):
                    raise SetupError("auto watch pause readback is not qualified")
        except BaseException as error:
            body_error = error
        try:
            # Body outcome is held separately; release cannot suppress it.
            lock.__exit__(None, None, None)
        except BaseException as error:
            release_error = error
    if body_error is not None and not isinstance(body_error, (SetupError, OSError)):
        raise body_error
    if release_error is not None and not isinstance(release_error, (SetupError, OSError)):
        raise release_error
    if body_error is not None or release_error is not None:
        safe = SetupError(
            "auto watch pause could not be confirmed; operator HOLD; credentials preserved"
        )
        try:
            raise safe from None
        except SetupError:
            safe.__cause__ = None
            safe.__context__ = None
            raise


def _install_auto_watch(tool: Path, credentials: Path, ib_csv: Path,
                        p2p: Path, cache: Path, report: Path,
                        snapshots: Path, *, force: bool) -> None:
    state = _auto_state_dir(tool)
    state.mkdir(parents=True, exist_ok=True)
    with _auto_crontab_lock(tool):
        _install_auto_watch_locked(
            tool, credentials, ib_csv, p2p, cache, report, snapshots, force=force,
        )


def _install_auto_watch_locked(tool: Path, credentials: Path, ib_csv: Path,
                               p2p: Path, cache: Path, report: Path,
                               snapshots: Path, *, force: bool) -> None:
    state = _auto_state_dir(tool)
    _auto_marker(state / "auto-watch.state")
    python = Path(sys.executable).resolve()
    if not python.is_absolute():
        raise SetupError("auto cron Python executable is not absolute")
    args = [
        str(python), str(tool / "initial-setup.py"), "--auto", "--apply", "--yes",
        "--credentials-file", str(credentials), "--execution-mode", "management",
        "--ib-csv", str(ib_csv), "--p2p", str(p2p), "--target-cache", str(cache),
        "--report", str(report), "--snapshot-dir", str(snapshots),
    ]
    if force:
        args.append("--force")
    shell = (
        "cd " + shlex.quote(str(tool)) + " && "
        + "flock -w 0 " + shlex.quote(str(state / "auto.lock")) + " "
        + shlex.join(args) + " >> " + shlex.quote(str(state / "auto-cron.log"))
        + " 2>&1 " + _AUTO_CRON_MARKER
    )
    job = "*/10 * * * * " + shell + "\n"
    existing = _read_stable_auto_crontab()
    retained = "".join(
        line for line in existing.splitlines(keepends=True)
        if not _own_auto_cron_line(line, tool, credentials)
    )
    if retained and not retained.endswith("\n"):
        retained += "\n"
    _write_auto_crontab(retained + job)


def _remove_auto_watch(tool: Path, credentials: Path) -> None:
    with _auto_crontab_lock(tool):
        _remove_auto_watch_locked(tool, credentials)


def _remove_auto_watch_locked(tool: Path, credentials: Path) -> None:
    existing = _read_stable_auto_crontab()
    retained = "".join(
        line for line in existing.splitlines(keepends=True)
        if not _own_auto_cron_line(line, tool, credentials)
    )
    if retained != existing:
        _write_auto_crontab(retained)
    if credentials.exists() or credentials.is_symlink():
        # A bad replacement is not deleted, because it could be a foreign
        # object.  Report a repairable failure instead of hiding it.
        read_auto_credentials(credentials)
        credentials.unlink()
    marker = _auto_state_dir(tool) / "auto-watch.state"
    if marker.exists() or marker.is_symlink():
        _auto_marker(marker)
        marker.unlink()


def confirm_first_device_change(target: Target, reason: str) -> bool:
    log(
        f"\nFIRST DEVICE CHANGE: {target.ib.hostname} via "
        f"{target.ethernet.hostname}:{target.ethernet_port}"
    )
    log(f"  Required action: {reason}")
    answer = input(
        "Authorize this change and subsequent eligible IB devices? [y/N]: "
    ).strip().casefold()
    return answer in {"y", "yes"}


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
            selector = tokens[3]
            if selector in {"eth0", "eth1", "eth0-1"}:
                ports = ("eth0", "eth1") if selector == "eth0-1" else (selector,)
            else:
                # This is a read-only disjointness proof, not a range expander.
                # Unknown aliases/groups might include reserved management ports.
                disjoint = (
                    re.fullmatch(r"eth(?:[2-9]|[1-9][0-9]+)", selector) is not None
                    or re.fullmatch(r"(?:swp|ibp|bond|vlan)[0-9]+(?:s[0-9]+)?", selector) is not None
                    or re.fullmatch(r"(?:swp|ibp|bond|vlan)[0-9]+-[0-9]+", selector) is not None
                    or selector == "lo"
                )
                eth_range = re.fullmatch(r"eth([0-9]+)-([0-9]+)", selector)
                if eth_range is not None:
                    lower, upper = (int(value) for value in eth_range.groups())
                    disjoint = 2 <= lower <= upper
                if not disjoint:
                    raise SetupError("management Network selector is not qualified")
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
        for credential in (ethernet_password, current_password):
            if (type(credential) is not str or not credential
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


def run_initial_stage(target: Target, neighbor: Neighbor, eth_user: str,
                      ethernet_password: str, ib_user: str, timeout: int,
                      current: str, *, local: bool, apply: bool, authorized: bool,
                      _ib_current_password=None, _password_policy=None) -> tuple[bool, bool]:
    """Commit only missing Initial values, then independently read them back."""
    failure = None
    try:
        if (type(local) is not bool or local or type(apply) is not bool
                or type(authorized) is not bool or type(current) is not str):
            raise SetupError("invalid Initial stage options or current state")
        initial = (
            ("nv", "set", "system", "config", "auto-save", "state", "enabled"),
            ("nv", "set", "system", "ztp", "config-save", "enabled"),
        )
        body = current
        # Pass zero examines supplied current state without acquiring a target.
        # Pass one examines only the actual ordinary command readback.
        for pass_index in (0, 1):
            state = parse_nvue_state(body)
            try:
                values = {command: set() for command in initial}
                for line in state.raw_commands.splitlines():
                    tokens = tuple(shlex.split(line))
                    for command in initial:
                        # Both owned namespaces have exactly five fixed tokens.
                        namespace = command[:5]
                        if tokens[:5] == namespace:
                            if (len(tokens) != len(command)
                                    or tokens[:-1] != command[:-1]
                                    or tokens[-1] not in {"enabled", "disabled"}):
                                raise SetupError("Initial configuration fact is UNKNOWN")
                            values[command].add(tokens[-1])
                        elif len(tokens) < 5 and command[:len(tokens)] == tokens:
                            raise SetupError("Initial configuration fact is truncated")
                if any(len(found) > 1 for found in values.values()):
                    raise SetupError("Initial configuration facts are contradictory")
            except ValueError:
                raise SetupError("Initial configuration command syntax is UNKNOWN") from None
            missing = tuple(command for command in initial if values[command] != {"enabled"})
            if pass_index == 1:
                if missing:
                    raise SetupError("Initial readback does not prove both enabled values")
                return authorized, False
            if not missing:
                return authorized, True
            if not apply:
                return authorized, False
            if not authorized:
                authorized = confirm_first_device_change(
                    target, "apply the missing Initial settings and verify them independently"
                )
                if not authorized:
                    return False, True
            for command in (*missing, ("nv", "config", "apply", "-y"),
                            ("nv", "config", "save")):
                _run_authorized_ib_command(
                    target, neighbor, eth_user, ethernet_password, ib_user,
                    _ib_current_password, timeout, list(command), local=False,
                    _password_policy=_password_policy,
                )
            result = _run_authorized_ib_command(
                target, neighbor, eth_user, ethernet_password, ib_user,
                _ib_current_password, timeout,
                ["nv", "config", "show", "-o", "commands"], local=False,
                _password_policy=_password_policy,
            )
            body = result.output
    except (SetupError, OSError) as error:
        uncertain, number = _ib_phase_error_facts(error)
        if number is None:
            candidate = getattr(error, "io_errno", None)
            if type(candidate) is int and 1 <= candidate <= 255:
                number = candidate
        failure = uncertain, number
    if failure is not None:
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


def run_service_stage(target: Target, neighbor: Neighbor, eth_user: str,
                      eth_password: str, ib_user: str, timeout: int,
                      services: Optional[dict[str, object]], current: str,
                      *, local: bool, apply: bool, authorized: bool,
                      _ib_current_password=None, _password_policy=None) -> tuple[bool, bool]:
    if _ib_current_password is not None or _password_policy is not None:
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
    if services is None:
        log("  Services SKIP: 01-global.yaml was unavailable at cache generation.")
        return authorized, True
    commands = desired_service_commands(services, current)
    if not commands:
        log("  Services SKIP: all desired values are already present; no flash save.")
        return authorized, True
    for command in commands:
        log(f"  Services {'APPLY' if apply else 'WOULD APPLY'}: {shlex.join(command)}")
    if not apply:
        return authorized, False
    if not authorized:
        authorized = confirm_first_device_change(
            target, "apply the missing NVOS services and verify them independently"
        )
        if not authorized:
            log("  Services SKIP: device changes were not authorized.")
            return False, True
    for command in (*commands, ["nv", "config", "apply", "-y"], ["nv", "config", "save"]):
        if _ib_current_password is None and _password_policy is None:
            run_on_ib(target, neighbor, eth_user, eth_password, ib_user,
                      eth_password, timeout, command, local=local)
        else:
            _run_authorized_ib_command(
                target, neighbor, eth_user, eth_password, ib_user,
                _ib_current_password, timeout, command, local=False,
                _password_policy=_password_policy,
            )
    if _ib_current_password is None and _password_policy is None:
        result = run_on_ib(
            target, neighbor, eth_user, eth_password, ib_user, eth_password, timeout,
            ["nv", "config", "show", "-o", "commands"], local=local,
        )
    else:
        result = _run_authorized_ib_command(
            target, neighbor, eth_user, eth_password, ib_user,
            _ib_current_password, timeout, ["nv", "config", "show", "-o", "commands"],
            local=False, _password_policy=_password_policy,
        )
    remaining = desired_service_commands(services, result.output)
    if remaining:
        raise SetupError("service verification failed: " +
                         ", ".join(shlex.join(command) for command in remaining))
    log("  Services SUCCESS: desired values verified.")
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
        probe = [
            "ssh", "-i", str(private_key),
            "-o", "BatchMode=yes",
            "-o", "PreferredAuthentications=publickey",
            "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            "-o", "IdentitiesOnly=yes",
            "-o", f"ConnectTimeout={timeout}",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "LogLevel=ERROR",
            f"{ib_user}@{login_ip}", "true",
        ]
        result = subprocess.run(
            probe, stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=max(timeout * 2, 30), check=False,
        )
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        raise SetupError("management public-key verification could not complete") from exc
    if result.returncode != 0:
        raise SetupError("management public-key-only IPv4 SSH verification failed")


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
        if classify_auto_day0(device, parse_nvue_state(current)) != "complete":
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
                  _ib_current_password=None, _password_policy=None) -> bool:
    if _ib_current_password is not None or _password_policy is not None:
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
    if not keys:
        log("  Public keys SKIP: no usable project public keys were baked into cache.")
        return authorized
    command = key_install_command(keys)
    for entry in keys:
        log(f"  Public key {'INSTALL' if apply else 'WOULD INSTALL'}: "
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
    if _ib_current_password is None and _password_policy is None:
        result = run_on_ib(target, neighbor, eth_user, eth_password, ib_user,
                           eth_password, timeout, command, local=local)
    else:
        result = _run_authorized_ib_command(
            target, neighbor, eth_user, eth_password, ib_user,
            _ib_current_password, timeout, command, local=False,
            _password_policy=_password_policy,
        )
    if (type(result.exit_code) is not int or result.exit_code != 0
            or type(result.output) is not str
            or result.output not in (
                "IBSW_PUBLIC_KEYS_UPDATED\n", "IBSW_PUBLIC_KEYS_UNCHANGED\n",
            )):
        raise SetupError("public-key installation receipt is unverified")
    for entry in keys:
        if entry["name"] == "mgmt-server.pub" and management_private_key is not None:
            verify_management_key_possession(
                target, ib_user, entry, management_private_key, timeout,
            )
            log(f"  Public key {entry['name']} {entry['fingerprint']}: 已验证")
        else:
            log(f"  Public key {entry['name']} {entry['fingerprint']}: 已写入，未验证")
    return authorized


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Initialize unconfigured NVOS switches through their Ethernet OOB peers."
    )
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
    parser.add_argument("--plan", action="store_true",
                        help="show targets and all potential Day-0, service and key commands without connecting")
    parser.add_argument("--apply", action="store_true",
                        help="configure devices that pass the all-unconfigured check")
    parser.add_argument("--force", action="store_true",
                        help="only complete missing Day-0 fields; refuse conflicts")
    parser.add_argument(
        "--auto", action="store_true",
        help="watch all CSV IB switches; retry every 10 minutes until configured",
    )
    parser.add_argument(
        "--credentials-file", type=Path,
        help="owned 0600 auto.env data file for non-interactive --auto rounds",
    )
    parser.add_argument("--yes", action="store_true",
                        help="with --apply, do not ask for final confirmation")
    parser.add_argument(
        "--report", type=Path,
        default=Path("xdr-initial-setup-logs/initial-setup-report.log"),
        help=("run report path (default: "
              "./xdr-initial-setup-logs/initial-setup-report.log)"),
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
    parser.add_argument("--ethernet-password", help=argparse.SUPPRESS)
    return parser.parse_args()


def _render_target_outcome_summary(*, target_results: tuple,
                                  ethernet_results: tuple) -> str:
    """Render closed, observed result facts without changing business state."""
    outcomes = (
        "COMPLETED", "CHECKED_ONLY", "SKIPPED_NO_WORK",
        "BLOCKED_PREREQUISITE", "FAILED_AFTER_ATTEMPT",
        "NOT_ATTEMPTED_AFTER_STOP",
    )
    facts = ("NOT_REACHED", "NO", "YES", "UNKNOWN")
    valid = type(target_results) is tuple and type(ethernet_results) is tuple
    target_names = set()
    ethernet_names = set()
    if valid:
        for row in target_results:
            if (type(row) is not tuple or len(row) != 7
                    or any(type(value) is not str for value in row)):
                valid = False
                break
            identity = normalize_name(row[0])
            if (not identity or not normalize_name(row[1])
                    or identity in target_names or row[2] not in outcomes
                    or any(value not in facts for value in row[3:])):
                valid = False
                break
            target_names.add(identity)
    if valid:
        for row in ethernet_results:
            if (type(row) is not tuple or len(row) != 2
                    or any(type(value) is not str for value in row)):
                valid = False
                break
            identity = normalize_name(row[0])
            if (not identity or identity in ethernet_names
                    or row[1] not in ("COLLECTED", "FAILED")):
                valid = False
                break
            ethernet_names.add(identity)
    if not valid:
        error = SetupError("invalid target outcome facts")
        try:
            raise error from None
        finally:
            # Raising under an unrelated active exception assigns its context.
            # Clear only this owned fixed error after that assignment.
            error.__cause__ = None
            error.__context__ = None
    counts = {outcome: 0 for outcome in outcomes}
    for row in target_results:
        counts[row[2]] += 1
    written = sum(row[3] == "YES" for row in target_results)
    verified = sum(row[4] == "YES" for row in target_results)
    ipv4_failed = sum(row[5] == "YES" for row in target_results)
    would_change = sum(row[6] == "YES" for row in target_results)
    collected = sum(row[1] == "COLLECTED" for row in ethernet_results)
    failed = sum(row[1] == "FAILED" for row in ethernet_results)
    lines = [
        "Target outcomes (authoritative):",
        f"  targets={len(target_results)} " + " ".join(
            f"{outcome}={counts[outcome]}" for outcome in outcomes),
        f"  OOB snapshots: total={len(ethernet_results)} "
        f"COLLECTED={collected} FAILED={failed}",
        f"  Network: written={written} readback_verified={verified}; "
        f"IPv4: failed={ipv4_failed}; would_change={would_change}",
    ]
    for name, oob, outcome, network, readback, ipv4, changed in target_results:
        lines.append(
            f"  {name} via {oob}: {outcome} Network.written={network} "
            f"Network.readback_verified={readback} IPv4.failed={ipv4} "
            f"would_change={changed}")
    return "\n".join(lines)


def main(*, method_cycle=None) -> int:
    global REPORT_HANDLE
    args = parse_args()
    auto_latched = False
    auto_pending_change = False
    auto_terminal_only = True
    auto_early = True
    auto_pause_eligible = False
    auto_tool = None
    auto_credentials_path = None
    auto_early_input_failure = None

    @contextmanager
    def auto_safety_scope():
        nonlocal auto_latched
        body_failure = None
        pause_failure = None
        try:
            yield
        except BaseException as error:
            body_failure = error
        # A local OOB Leaf never installs or owns the watch (§10C), so its own
        # identity-bound refusal is the one early failure with nothing to pause.
        local_leaf_refusal = (
            body_failure is not None
            and type(auto_early_input_failure) is tuple
            and len(auto_early_input_failure) == 2
            and auto_early_input_failure[0] == "local-leaf"
            and auto_early_input_failure[1] is body_failure
        )
        if args.auto and auto_pause_eligible and (
                auto_latched or (body_failure is not None and not local_leaf_refusal)):
            auto_latched = True
            try:
                _pause_auto_watch(auto_tool, auto_credentials_path)
            except BaseException as error:
                pause_failure = error
        if body_failure is not None and not isinstance(body_failure, (SetupError, OSError)):
            raise body_failure
        if pause_failure is not None and not isinstance(pause_failure, (SetupError, OSError)):
            try:
                raise pause_failure
            except BaseException:
                if (isinstance(body_failure, (SetupError, OSError))
                        and pause_failure.__context__ is body_failure):
                    pause_failure.__context__ = None
                raise
        if pause_failure is not None:
            safe = SetupError(
                "auto watch pause could not be confirmed; operator HOLD; credentials preserved"
            )
            try:
                raise safe from None
            except SetupError:
                safe.__cause__ = None
                safe.__context__ = None
                raise
        if body_failure is not None:
            if (args.auto and auto_pause_eligible and auto_early
                    and isinstance(body_failure, (SetupError, OSError))):
                uncertain, number = _ib_phase_error_facts(body_failure)
                if number is None:
                    candidate = getattr(body_failure, "io_errno", None)
                    if type(candidate) is int and 1 <= candidate <= 255:
                        number = candidate
                if (
                    type(auto_early_input_failure) is tuple
                    and len(auto_early_input_failure) == 2
                    and auto_early_input_failure[1] is body_failure
                    and type(auto_early_input_failure[0]) is str
                ):
                    message = {
                        "credentials-input": (
                            "auto.env credential input could not be safely validated; "
                            "private permissions/mode, a qualified owner, and no symbolic "
                            "links are required; device state is UNKNOWN"
                        ),
                        "target-coverage": (
                            "--auto requires one P2P management link for every CSV IB "
                            "switch; fix CSV/P2P before starting a watch; device state is UNKNOWN"
                        ),
                        "local-leaf": (
                            "--auto watch must run on the management server, not a local "
                            "OOB Leaf; no device, credential or watch was touched"
                        ),
                    }.get(auto_early_input_failure[0])
                    if message is not None:
                        safe = SetupError(message)
                        if uncertain is True:
                            safe.cleanup_uncertain = True
                        if type(number) is int and 1 <= number <= 255:
                            safe.io_errno = number
                        try:
                            raise safe from None
                        except SetupError:
                            safe.__cause__ = None
                            safe.__context__ = None
                            raise
                _ib_raise_phase_failure("project", uncertain, number)
            raise body_failure

    with auto_safety_scope():
        if method_cycle is not None and args.auto:
            raise SetupError(
                "managed method authority cannot be combined with --auto; "
                "the managed cycle runs one explicit management --apply execution"
            )
        if args.plan and args.apply:
            raise SetupError("--plan cannot be combined with --apply")
        if args.generate_json and (args.plan or args.apply):
            raise SetupError(
                "--generate-json cannot be combined with --plan or --apply"
            )
        if args.auto:
            if args.plan or args.generate_json or args.execution_mode == "ethernet":
                raise SetupError("--auto requires management execution, not plan or P1 generation")
            if args.ethernet_password is not None:
                raise SetupError("--auto forbids --ethernet-password in argv")
            if args.credentials_file is None and not sys.stdin.isatty():
                raise SetupError("interactive first --auto round requires a tty")
            args.apply = True
            args.yes = True
            auto_pause_eligible = True
            auto_tool = Path(__file__).resolve().parent
            auto_credentials_path = (
                Path(os.path.abspath(args.credentials_file))
                if args.credentials_file is not None else _auto_state_dir(auto_tool) / "auto.env"
            )
        elif args.credentials_file is not None:
            raise SetupError("--credentials-file is only valid with --auto")
        if method_cycle is not None and (not args.apply or args.plan or args.generate_json
                                          or args.execution_mode == "ethernet"):
            raise SetupError("managed method authority requires management --apply, not plan/generation/ethernet mode")
        try:
            auto_credentials = (
                read_auto_credentials(args.credentials_file)
                if args.credentials_file is not None else None
            )
        except (SetupError, OSError) as error:
            auto_early_input_failure = ("credentials-input", error)
            raise
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
        ib_csv_path = discover_input_file(
            args.ib_csv, "ib.csv", ".csv", "IB device CSV"
        )
        p2p_path = discover_input_file(
            args.p2p, "p2p.xlsx", ".xlsx", "P2P workbook"
        )
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
        if args.generate_json:
            ib_devices, eth_devices = load_devices(ib_csv_path)
            links = parse_p2p(p2p_path)
            validate_p2p_links(links)
            targets = build_targets(links, ib_devices, eth_devices)
            tool = Path(__file__).resolve().parent
            services = _service_profile(tool)
            public_keys = _public_key_profile(tool)
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
        log(f"Input CSV: {ib_csv_path}")
        log(f"Input P2P: {p2p_path}")
        if args.auto:
            log(
                "AUTO WATCH: --auto authorizes --apply --yes including future IB password "
                "changes, installs an OOB Leaf key when supported, and may write a "
                "0600 auto.env with all OOB Leaf and IB passwords.  Disclosure of "
                "that file exposes all of those devices.  Edit CSV to correct "
                "bad MACs; the next round revalidates inputs."
            )
        tool = (method_cycle.tool_input_root if method_cycle is not None
                else Path(__file__).resolve().parent)
        source_inputs_available = (
            args.execution_mode in {"management", "ethernet"}
            or (args.execution_mode == "auto" and (
                (tool / "publickey").is_dir() or (tool / "01-global.yaml").is_file()
            ))
        )
        cache_observe_profile = args.execution_mode != "ethernet"
        cache_admission_out = {} if cache_observe_profile else None
        cache_generated_profile = None
        cached = load_target_cache(
            cache_path, ib_csv_path, p2p_path,
            public_key_tool=tool if source_inputs_available else None,
            validate_public_keys_with_ssh_keygen=args.execution_mode == "management",
            allow_baked_missing_global=args.execution_mode != "management",
            **({"_admission_out": cache_admission_out} if cache_observe_profile else {}),
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
                )
        if cached is not None:
            ib_candidate_count, targets = cached
            log(f"Target cache: reused {cache_path}")
        else:
            if args.execution_mode == "ethernet":
                if cache_path.is_file():
                    raise SetupError(
                        "target cache version, checksum, or input identity is invalid; "
                        "regenerate version 4 on the management server"
                    )
                raise SetupError("target cache is missing; generate version 4 on the management server")
            ib_devices, eth_devices = load_devices(ib_csv_path)
            links = parse_p2p(p2p_path)
            validate_p2p_links(links)
            targets = build_targets(links, ib_devices, eth_devices)
            ib_candidate_count = len(ib_devices)
            services = _service_profile(tool)
            public_keys = _public_key_profile(tool)
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
        if args.auto:
            try:
                require_auto_full_target_coverage(ib_candidate_count, targets)
            except (SetupError, OSError) as error:
                auto_early_input_failure = ("target-coverage", error)
                raise
        cache_payload = json.loads(cache_path.read_text(encoding="utf-8"))
        services = cache_payload["services"]
        public_keys = cache_payload["public_keys"]
        auto_management_keys = (
            [entry for entry in public_keys if entry["name"] == "mgmt-server.pub"]
            if args.auto else []
        )
        if args.auto and not auto_management_keys:
            raise SetupError("--auto requires a validated mgmt-server.pub for OOB Leaf key install")

        log(f"IB candidates in CSV: {ib_candidate_count}")
        log(f"P2P management links: {len(targets)}")
        for target in targets:
            log(
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
                log(f"  [{target.ib.hostname}] Day-0 commands:")
                for command in desired_commands(target.ib):
                    log("    " + shlex.join(command))
                if services is None:
                    log("    Services SKIP: 01-global.yaml was unavailable at cache generation.")
                else:
                    log("    Services commands:")
                    for command in desired_service_commands(services, ""):
                        log("    " + shlex.join(command))
                    log("    nv config apply")
                    log("    nv config save")
                if public_keys:
                    log("    Public-key install command:")
                    log("    " + shlex.join(key_install_command(public_keys)))
                    for entry in public_keys:
                        log(f"    {entry['name']} {entry['fingerprint']}")
                else:
                    log("    Public keys SKIP: no usable project public keys were baked into cache.")
            return 0

        local_keys = local_ethernet_keys(
            targets, args.execution_mode, args.local_ethernet_hostname
        )
        if args.auto and local_keys:
            local_leaf_error = SetupError(
                "--auto watch must run on the management server, not a local OOB Leaf"
            )
            auto_early_input_failure = ("local-leaf", local_leaf_error)
            raise local_leaf_error
        # Only after the Leaf refusal: that refusal touches no credential.
        initial_ib_password = (
            auto_credentials["NVOS_INITIAL_PASSWORD"]
            if auto_credentials is not None else resolve_initial_ib_password(
                args.ib_initial_password_env,
                factory_default_admin=args.factory_default_admin,
            )
        )

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
            method_cycle.start(tool, cache_path, ib_csv_path, p2p_path, targets, services, public_keys)
        passwords = (
            _auto_passwords_for_targets(auto_credentials, targets)
            if auto_credentials is not None else prompt_ethernet_passwords(
                targets, args.ethernet_password, local_keys
            )
        )

        # Manual management uses present project authority without changing legacy modes.
        strict_manual = (
            not args.auto and args.execution_mode != "ethernet" and not local_keys
        )
        strict_auto = bool(args.auto and args.execution_mode != "ethernet" and not local_keys)
        strict_present = False
        strict_policy = None
        if strict_manual or strict_auto:
            if type(cache_payload) is not dict or "global" not in cache_payload:
                _ib_raise_phase_failure("project")
            strict_failure = None
            try:
                (tool / "01-global.yaml").lstat()
            except FileNotFoundError as error:
                if cache_payload["global"] is not None:
                    strict_failure = _ib_phase_error_facts(error)
            except OSError as error:
                strict_failure = _ib_phase_error_facts(error)
            else:
                strict_present = True
            if strict_failure is not None:
                _ib_raise_phase_failure("project", *strict_failure)
            if strict_auto and not strict_present:
                _ib_raise_phase_failure("project")
            if strict_present:
                strict_failure = None
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
                    strict_device_fields = {
                        "hostname", "dev_type", "login_ip", "eth0_prefix",
                        "eth0_gateway", "eth0_mac", "eth1_prefix", "eth1_gateway",
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
                    if strict_auto:
                        strict_policy = ProjectPasswordPolicy(
                            tool / "01-global.yaml", args.ib_user,
                            target_password=(auto_credentials.get("NVOS_TARGET_PASSWORD")
                                             if auto_credentials is not None else None),
                            interactive=auto_credentials is None,
                        )
                    else:
                        strict_policy = ProjectPasswordPolicy(tool / "01-global.yaml", args.ib_user)
                    if (
                        strict_policy.binding[0] != cache_payload["global"]
                        or strict_policy.binding[3]
                        != cache_payload["cache_authority"]["global_sha256"]
                    ):
                        raise SetupError("project authority differs from admitted P1 input")
                    if (strict_auto and auto_credentials is not None
                            and "NVOS_TARGET_PASSWORD" in auto_credentials):
                        _ib_project_value(strict_policy, user=args.ib_user, fetch=True)
                except (SetupError, OSError) as error:
                    strict_failure = _ib_phase_error_facts(error)
                if strict_failure is not None:
                    _ib_raise_phase_failure("project", *strict_failure)
        if args.auto and (not strict_auto or not strict_present
                          or type(strict_policy) is not ProjectPasswordPolicy):
            _ib_raise_phase_failure("project")
        auto_early = False
        apply_authorized = bool(args.apply and args.yes)
        if apply_authorized:
            log("Device changes: pre-authorized by --apply --yes.")

        manual_outcome_enabled = strict_manual and strict_present
        if manual_outcome_enabled:
            manual_outcome_rows = [
                [item.ib.hostname, item.ethernet.hostname,
                 "NOT_ATTEMPTED_AFTER_STOP", "NOT_REACHED", "NOT_REACHED",
                 "NOT_REACHED", "NOT_REACHED"]
                for item in targets
            ]
            manual_ethernet_outcomes = []
            manual_outcome_index = 0
            manual_outcome_supported = True

        interface_tables: dict[str, str] = {}
        network_tables: dict[str, tuple[str, str, str]] = {}
        table_failures: dict[str, str] = {}
        failures = configured = skipped = day0_skipped = services_skipped = 0
        completed_targets: set[str] = set()
        terminal_path = _auto_state_dir(tool) / "auto-terminal.json"
        terminal_identity = _auto_input_identity(ib_csv_path, p2p_path) if args.auto else ""
        terminal_targets = (
            _load_auto_terminal(terminal_path, terminal_identity) if args.auto else set()
        )
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
                if manual_outcome_enabled:
                    manual_ethernet_outcomes.append((ethernet.hostname, "COLLECTED"))
            except SetupError as exc:
                if manual_outcome_enabled:
                    manual_ethernet_outcomes.append((ethernet.hostname, "FAILED"))
                table_failures[eth_key] = str(exc)
                log(f"    ERROR: {exc}")

        log("\nEvaluating IB devices from local Ethernet snapshots ...")
        for target in targets:
            if manual_outcome_enabled:
                manual_outcome = manual_outcome_rows[manual_outcome_index]
                manual_outcome_index += 1
                manual_outcome[2] = "BLOCKED_PREREQUISITE"
            eth_key = normalize_name(target.ethernet.hostname)
            eth_password = passwords[eth_key]
            ethernet_is_local = eth_key in local_keys
            log(f"\n[{target.ib.hostname}] via {target.ethernet.hostname}:{target.ethernet_port}")
            ib_key = normalize_name(target.ib.hostname)
            if args.auto and ib_key in terminal_targets:
                failures += 1
                log(
                    "  Day-0 TERMINAL: recorded partial/conflicting configuration; "
                    "IB login and writes skipped until CSV/P2P change or operator "
                    "clears owned auto-terminal.json after manual repair."
                )
                continue
            try:
                if eth_key in table_failures:
                    raise SetupError(
                        "Ethernet snapshot collection failed: "
                        + table_failures[eth_key]
                    )
                interface_table = interface_tables[eth_key]
                try:
                    status_line = interface_status_line(
                        interface_table, target.ethernet_port
                    )
                    oper_status = interface_oper_status(
                        status_line, target.ethernet_port
                    )
                except SetupError as exc:
                    skipped += 1
                    log(f"  SKIP: Ethernet interface state is not verifiable: {exc}")
                    if strict_auto:
                        auto_terminal_only = False
                    continue
                log(f"  Ethernet interface: {status_line}")
                if oper_status != "up":
                    skipped += 1
                    log(
                        f"  SKIP: {target.ethernet_port} Oper Status is "
                        f"{oper_status!r}, not 'up'; local FDB/neighbor lookup and "
                        "IB login not attempted."
                    )
                    if strict_auto:
                        auto_terminal_only = False
                    continue
                links, fdb, neighbors = network_tables[eth_key]
                fdb_port = fdb_port_for_interface(links, target.ethernet_port)
                if fdb_port != target.ethernet_port:
                    log(
                        f"  Ethernet interface {target.ethernet_port} is a member of "
                        f"bond {fdb_port}; using {fdb_port} for FDB lookup."
                    )
                neighbor = neighbor_for_port(fdb, neighbors, fdb_port)
                verify_fdb_eth0_mac(target, neighbor.mac)
                vrf = interface_vrf(
                    target.ethernet, args.eth_user, eth_password,
                    neighbor.interface, args.connect_timeout,
                    local=ethernet_is_local,
                )
                neighbor = Neighbor(neighbor.ipv6, neighbor.interface, neighbor.mac, vrf)
                log(
                    f"  MAC {neighbor.mac} -> {neighbor.ipv6} "
                    f"dev {neighbor.interface} vrf {neighbor.vrf}"
                )


                if strict_auto and strict_present:
                    authority_failure = None
                    try:
                        if getattr(strict_policy, "_auto_authority_failed", None) is not False:
                            raise SetupError("automatic project authority is no longer qualified")
                        if not _valid_cache_authority(
                            cache_payload, ib_csv_path, p2p_path, tool / "01-global.yaml",
                        ):
                            raise SetupError("automatic target cache authority is stale")
                        _ib_project_value(strict_policy, user=args.ib_user)
                    except (SetupError, OSError) as error:
                        authority_failure = _ib_phase_error_facts(error)
                    if authority_failure is not None:
                        auto_latched = True
                        _ib_raise_phase_failure("project", *authority_failure)
                    auto_login = _authenticate_ib_read(
                        target, neighbor, args.eth_user, eth_password, args.ib_user,
                        initial_ib_password, args.connect_timeout, local=False,
                        _password_policy=strict_policy,
                    )
                    auto_current = auto_login.current_password
                    auto_result = auto_login.read_result
                    if auto_result.password_change_required:
                        auto_target = _ib_project_value(
                            strict_policy, user=args.ib_user, fetch=True,
                        )
                        auto_pending_change = True
                        run_on_ib(
                            target, neighbor, args.eth_user, eth_password, args.ib_user,
                            auto_current, args.connect_timeout,
                            ["nv", "config", "show", "-o", "commands"], local=False,
                            allow_password_change=True, ib_new_password=auto_target,
                            _phase_operation="password-change", _password_policy=strict_policy,
                        )
                        # The actual private PAM outcome, not a later readonly
                        # operation, closes this mutation's outstanding epoch.
                        auto_pending_change = False
                        auto_result = run_on_ib(
                            target, neighbor, args.eth_user, eth_password, args.ib_user,
                            auto_target, args.connect_timeout,
                            ["nv", "config", "show", "-o", "commands"], local=False,
                            allow_password_change=False, _phase_operation="post-change-read",
                            _password_policy=strict_policy,
                        )
                        auto_current = auto_target
                    auto_body = auto_result.output
                    try:
                        _, auto_initial_present = run_initial_stage(
                            target, neighbor, args.eth_user, eth_password, args.ib_user,
                            args.connect_timeout, auto_body, local=False, apply=False,
                            authorized=False, _ib_current_password=auto_current,
                            _password_policy=strict_policy,
                        )
                        auto_state, _, _ = _management_network_facts(auto_body)
                        auto_day0 = classify_auto_day0(target.ib, auto_state)
                    except (SetupError, OSError):
                        auto_latched = True
                        raise
                    if auto_day0 == "terminal":
                        failures += 1
                        terminal_targets.add(ib_key)
                        log("  Day-0 TERMINAL: protected fields require manual resolution; no write attempted.")
                        continue
                    auto_terminal_only = False
                    try:
                        auto_network = _management_network_commands(target.ib, auto_body)
                        # Qualify supplied Services before any configuration
                        # setter, not only after a successful Network commit.
                        if services is not None:
                            desired_service_commands(services, auto_body)
                    except (SetupError, OSError):
                        auto_latched = True
                        raise
                    if not auto_initial_present:
                        auto_diff = run_on_ib(
                            target, neighbor, args.eth_user, eth_password, args.ib_user,
                            auto_current, args.connect_timeout,
                            ["nv", "config", "diff", "-o", "commands"], local=False,
                            allow_password_change=False,
                        )
                        if auto_diff.exit_code != 0 or auto_diff.output:
                            auto_latched = True
                            raise SetupError("pre-existing pending configuration; no changes cleared or committed")
                        auto_pending_change = True
                        apply_authorized, auto_initial_skipped = run_initial_stage(
                            target, neighbor, args.eth_user, eth_password, args.ib_user,
                            args.connect_timeout, auto_body, local=False, apply=True,
                            authorized=apply_authorized, _ib_current_password=auto_current,
                            _password_policy=strict_policy,
                        )
                        if not apply_authorized or auto_initial_skipped:
                            raise SetupError("Initial completion is not qualified")
                        auto_result = _run_authorized_ib_command(
                            target, neighbor, args.eth_user, eth_password, args.ib_user,
                            auto_current, args.connect_timeout,
                            ["nv", "config", "show", "-o", "commands"], local=False,
                            _password_policy=strict_policy,
                        )
                        auto_body = auto_result.output
                        _, auto_initial_present = run_initial_stage(
                            target, neighbor, args.eth_user, eth_password, args.ib_user,
                            args.connect_timeout, auto_body, local=False, apply=False,
                            authorized=False, _ib_current_password=auto_current,
                            _password_policy=strict_policy,
                        )
                        if not auto_initial_present:
                            raise SetupError("refreshed Initial configuration is unverified")
                        auto_state, _, _ = _management_network_facts(auto_body)
                        auto_day0 = classify_auto_day0(target.ib, auto_state)
                        if auto_day0 == "terminal":
                            raise SetupError("post-Initial protected fields are unqualified")
                        auto_network = _management_network_commands(target.ib, auto_body)
                        auto_pending_change = False
                    auto_network_changed = False
                    if auto_day0 == "unconfigured" and auto_network:
                        auto_diff = run_on_ib(
                            target, neighbor, args.eth_user, eth_password, args.ib_user,
                            auto_current, args.connect_timeout,
                            ["nv", "config", "diff", "-o", "commands"], local=False,
                            allow_password_change=False,
                        )
                        if auto_diff.exit_code != 0 or auto_diff.output:
                            auto_latched = True
                            raise SetupError("pre-existing pending configuration; no changes cleared or committed")
                        auto_pending_change = True
                        for command in (*auto_network, ["nv", "config", "apply", "-y"],
                                        ["nv", "config", "save"]):
                            _run_authorized_ib_command(
                                target, neighbor, args.eth_user, eth_password, args.ib_user,
                                auto_current, args.connect_timeout, command, local=False,
                                _password_policy=strict_policy,
                            )
                        auto_result = _run_authorized_ib_command(
                            target, neighbor, args.eth_user, eth_password, args.ib_user,
                            auto_current, args.connect_timeout,
                            ["nv", "config", "show", "-o", "commands"], local=False,
                            _password_policy=strict_policy,
                        )
                        auto_body = auto_result.output
                        _verify_management_network_state(target.ib, auto_body)
                        auto_pending_change = False
                        auto_network_changed = True
                    else:
                        skipped += 1
                        day0_skipped += 1
                        log("  Day-0 SKIP: protected fields already configured; services remain eligible.")
                    auto_services = (
                        desired_service_commands(services, auto_body)
                        if services is not None else []
                    )
                    if auto_services:
                        auto_diff = run_on_ib(
                            target, neighbor, args.eth_user, eth_password, args.ib_user,
                            auto_current, args.connect_timeout,
                            ["nv", "config", "diff", "-o", "commands"], local=False,
                            allow_password_change=False,
                        )
                        if auto_diff.exit_code != 0 or auto_diff.output:
                            auto_latched = True
                            raise SetupError("pre-existing pending configuration; no changes cleared or committed")
                        auto_pending_change = True
                    apply_authorized, service_was_skipped = run_service_stage(
                        target, neighbor, args.eth_user, eth_password, args.ib_user,
                        args.connect_timeout, services, auto_body, local=False,
                        apply=True, authorized=apply_authorized,
                        _ib_current_password=auto_current, _password_policy=strict_policy,
                    )
                    services_skipped += int(service_was_skipped)
                    auto_pending_change = bool(public_keys)
                    apply_authorized = run_key_stage(
                        target, neighbor, args.eth_user, eth_password, args.ib_user,
                        args.connect_timeout, public_keys, local=False, apply=True,
                        authorized=apply_authorized, management_private_key=management_private_key,
                        _ib_current_password=auto_current, _password_policy=strict_policy,
                    )
                    auto_pending_change = False
                    try:
                        verify_ipv4_login(
                            target, neighbor.vrf, args.eth_user, eth_password,
                            args.ib_user, args.connect_timeout, local=False,
                            _ib_current_password=auto_current, _password_policy=strict_policy,
                        )
                    except SetupError:
                        auto_latched = True
                        raise
                    if auto_network_changed:
                        configured += 1
                        log(f"  SUCCESS: configuration verified; IPv4 SSH to {target.ib.login_ip} succeeded.")
                    completed_targets.add(normalize_name(target.ib.hostname))
                    continue

                if strict_manual and strict_present:
                    strict_failure = None
                    try:
                        if not _valid_cache_authority(
                            cache_payload, ib_csv_path, p2p_path, tool / "01-global.yaml",
                        ):
                            raise SetupError("manual target cache authority is stale")
                        _ib_project_value(strict_policy, user=args.ib_user)
                    except (SetupError, OSError) as error:
                        strict_failure = _ib_phase_error_facts(error)
                    if strict_failure is not None:
                        _ib_raise_phase_failure("project", *strict_failure)
                    strict_login = _authenticate_ib_read(
                        target, neighbor, args.eth_user, eth_password, args.ib_user,
                        initial_ib_password, args.connect_timeout, local=False,
                        _password_policy=strict_policy,
                    )
                    strict_current = strict_login.current_password
                    strict_result = strict_login.read_result
                    if strict_result.password_change_required:
                        manual_outcome_supported = False
                    if strict_result.password_change_required:
                        if not args.apply:
                            skipped += 1
                            log("  SKIP: initial password change required; read-only observation cancelled.")
                            continue
                        if not apply_authorized:
                            apply_authorized = confirm_first_device_change(
                                target, "change the initial NVOS password to the independently "
                                "verified project target, then inspect eligible configuration",
                            )
                            if not apply_authorized:
                                log("No device changes authorized; stopping.")
                                return 0
                        strict_target = _ib_project_value(
                            strict_policy, user=args.ib_user, fetch=True,
                        )
                        run_on_ib(
                            target, neighbor, args.eth_user, eth_password, args.ib_user,
                            strict_current, args.connect_timeout,
                            ["nv", "config", "show", "-o", "commands"], local=False,
                            allow_password_change=True, ib_new_password=strict_target,
                            _phase_operation="password-change", _password_policy=strict_policy,
                        )
                        strict_result = run_on_ib(
                            target, neighbor, args.eth_user, eth_password, args.ib_user,
                            strict_target, args.connect_timeout,
                            ["nv", "config", "show", "-o", "commands"], local=False,
                            allow_password_change=False, _phase_operation="post-change-read",
                            _password_policy=strict_policy,
                        )
                        strict_current = strict_target
                    strict_body = strict_result.output
                    _, strict_initial_present = run_initial_stage(
                        target, neighbor, args.eth_user, eth_password, args.ib_user,
                        args.connect_timeout, strict_body, local=False, apply=False,
                        authorized=False, _ib_current_password=strict_current,
                        _password_policy=strict_policy,
                    )
                    strict_network = _management_network_commands(target.ib, strict_body)
                    strict_state, _, _ = _management_network_facts(strict_body)
                    strict_network_eligible = state_is_unconfigured(strict_state)
                    if args.force and not strict_network_eligible:
                        strict_network_eligible = force_day0_needed(target.ib, strict_state)
                    strict_services = (
                        desired_service_commands(services, strict_body)
                        if services is not None else []
                    )
                    manual_outcome[3] = "NO"
                    manual_outcome[6] = (
                        "YES" if (not strict_initial_present
                                  or bool(strict_network_eligible and strict_network)
                                  or bool(strict_services)) else "NO"
                    )
                    if not args.apply:
                        strict_diff = run_on_ib(
                            target, neighbor, args.eth_user, eth_password, args.ib_user,
                            strict_current, args.connect_timeout,
                            ["nv", "config", "diff", "-o", "commands"], local=False,
                            allow_password_change=False,
                        )
                        log("  Check-only pending report: "
                            + ("present; nothing committed." if strict_diff.output
                               else "empty; nothing committed."))
                        manual_outcome[2] = "CHECKED_ONLY"
                        continue
                    strict_has_work = (
                        not strict_initial_present
                        or bool(strict_network_eligible and strict_network)
                        or bool(strict_services) or bool(public_keys)
                    )
                    if strict_has_work and not apply_authorized:
                        apply_authorized = confirm_first_device_change(
                            target, "apply eligible Initial, Network, Services and public-key "
                            "changes using independently verified project authority",
                        )
                        if not apply_authorized:
                            log("No device changes authorized; stopping.")
                            return 0
                    if not strict_initial_present:
                        strict_diff = run_on_ib(
                            target, neighbor, args.eth_user, eth_password, args.ib_user,
                            strict_current, args.connect_timeout,
                            ["nv", "config", "diff", "-o", "commands"], local=False,
                            allow_password_change=False,
                        )
                        if strict_diff.exit_code != 0 or strict_diff.output:
                            raise SetupError("pre-existing pending configuration; no changes cleared or committed")
                        manual_outcome[2] = "FAILED_AFTER_ATTEMPT"
                        try:
                            apply_authorized, strict_initial_skipped = run_initial_stage(
                                target, neighbor, args.eth_user, eth_password, args.ib_user,
                                args.connect_timeout, strict_body, local=False, apply=True,
                                authorized=apply_authorized,
                                _ib_current_password=strict_current, _password_policy=strict_policy,
                            )
                            if not apply_authorized or strict_initial_skipped:
                                raise SetupError("Initial completion is not qualified")
                            strict_result = _run_authorized_ib_command(
                                target, neighbor, args.eth_user, eth_password, args.ib_user,
                                strict_current, args.connect_timeout,
                                ["nv", "config", "show", "-o", "commands"], local=False,
                                _password_policy=strict_policy,
                            )
                            strict_body = strict_result.output
                            _, strict_initial_present = run_initial_stage(
                                target, neighbor, args.eth_user, eth_password, args.ib_user,
                                args.connect_timeout, strict_body, local=False, apply=False,
                                authorized=False, _ib_current_password=strict_current,
                                _password_policy=strict_policy,
                            )
                            if not strict_initial_present:
                                raise SetupError("refreshed Initial configuration is unverified")
                            strict_network = _management_network_commands(target.ib, strict_body)
                            strict_state, _, _ = _management_network_facts(strict_body)
                            strict_network_eligible = state_is_unconfigured(strict_state)
                            if args.force and not strict_network_eligible:
                                strict_network_eligible = force_day0_needed(target.ib, strict_state)
                        except SetupError as exc:
                            failures += 1
                            log(f"  ERROR after device change: {_authorized_failure_text(exc)}")
                            log("  STOP: Initial verification did not complete; no subsequent IB device will be configured.")
                            break
                    strict_network_changed = False
                    if strict_network_eligible and strict_network:
                        strict_diff = run_on_ib(
                            target, neighbor, args.eth_user, eth_password, args.ib_user,
                            strict_current, args.connect_timeout,
                            ["nv", "config", "diff", "-o", "commands"], local=False,
                            allow_password_change=False,
                        )
                        if strict_diff.exit_code != 0 or strict_diff.output:
                            raise SetupError("pre-existing pending configuration; no changes cleared or committed")
                        manual_outcome[2] = "FAILED_AFTER_ATTEMPT"
                        manual_outcome[3] = "UNKNOWN"
                        try:
                            for command in (*strict_network, ["nv", "config", "apply", "-y"],
                                            ["nv", "config", "save"]):
                                _run_authorized_ib_command(
                                    target, neighbor, args.eth_user, eth_password, args.ib_user,
                                    strict_current, args.connect_timeout, command, local=False,
                                    _password_policy=strict_policy,
                                )
                            manual_outcome[3] = "YES"
                            manual_outcome[4] = "UNKNOWN"
                            strict_result = _run_authorized_ib_command(
                                target, neighbor, args.eth_user, eth_password, args.ib_user,
                                strict_current, args.connect_timeout,
                                ["nv", "config", "show", "-o", "commands"], local=False,
                                _password_policy=strict_policy,
                            )
                            strict_body = strict_result.output
                            _verify_management_network_state(target.ib, strict_body)
                            manual_outcome[4] = "YES"
                        except SetupError as exc:
                            failures += 1
                            log(f"  ERROR after device change: {_authorized_failure_text(exc)}")
                            log("  STOP: post-configuration verification did not complete; no subsequent IB device will be configured.")
                            break
                        strict_network_changed = True
                    else:
                        skipped += 1
                        day0_skipped += 1
                        log("  Day-0 SKIP: no eligible Network changes; services remain eligible.")
                    strict_services = (
                        desired_service_commands(services, strict_body)
                        if services is not None else []
                    )
                    if strict_services:
                        strict_diff = run_on_ib(
                            target, neighbor, args.eth_user, eth_password, args.ib_user,
                            strict_current, args.connect_timeout,
                            ["nv", "config", "diff", "-o", "commands"], local=False,
                            allow_password_change=False,
                        )
                        if strict_diff.exit_code != 0 or strict_diff.output:
                            raise SetupError("pre-existing pending configuration; no changes cleared or committed")
                    if strict_services:
                        manual_outcome[2] = "FAILED_AFTER_ATTEMPT"
                    apply_authorized, service_was_skipped = run_service_stage(
                        target, neighbor, args.eth_user, eth_password, args.ib_user,
                        args.connect_timeout, services, strict_body, local=False, apply=True,
                        authorized=apply_authorized, _ib_current_password=strict_current,
                        _password_policy=strict_policy,
                    )
                    services_skipped += int(service_was_skipped)
                    if public_keys:
                        manual_outcome[2] = "FAILED_AFTER_ATTEMPT"
                    apply_authorized = run_key_stage(
                        target, neighbor, args.eth_user, eth_password, args.ib_user,
                        args.connect_timeout, public_keys, local=False, apply=True,
                        authorized=apply_authorized, management_private_key=management_private_key,
                        _ib_current_password=strict_current, _password_policy=strict_policy,
                    )
                    if strict_network_changed:
                        manual_outcome[5] = "UNKNOWN"
                        try:
                            verify_ipv4_login(
                                target, neighbor.vrf, args.eth_user, eth_password,
                                args.ib_user, args.connect_timeout, local=False,
                                _ib_current_password=strict_current, _password_policy=strict_policy,
                            )
                        except SetupError as exc:
                            manual_outcome[2] = "FAILED_AFTER_ATTEMPT"
                            manual_outcome[5] = "YES"
                            failures += 1
                            log(f"  ERROR after device change: {_authorized_failure_text(exc)}")
                            log("  STOP: IPv4 verification did not complete; no subsequent IB device will be configured.")
                            break
                        manual_outcome[5] = "NO"
                        configured += 1
                        log(f"  SUCCESS: configuration verified; IPv4 SSH to {target.ib.login_ip} succeeded.")
                    if method_cycle is not None:
                        if not apply_authorized or not method_cycle.complete(target, args.ib_user, management_private_key,
                                                                              args.connect_timeout, services, public_keys):
                            raise SetupError("managed current initial-setup configuration was not verified")
                    manual_outcome[2] = (
                        "COMPLETED" if strict_has_work else "SKIPPED_NO_WORK"
                    )
                    completed_targets.add(normalize_name(target.ib.hostname))
                    continue
                result = run_on_ib(
                    target, neighbor, args.eth_user, eth_password,
                    args.ib_user, initial_ib_password, args.connect_timeout,
                    ["nv", "config", "show", "-o", "commands"],
                    local=ethernet_is_local,
                    allow_password_change=apply_authorized,
                )
                if result.password_change_required:
                    if not args.apply:
                        skipped += 1
                        log(
                            "  SKIP: NVOS requires its initial password change; "
                            "check-only mode cancelled it. Re-run with --apply to "
                            "authorize device changes."
                        )
                        continue
                    if not apply_authorized:
                        apply_authorized = confirm_first_device_change(
                            target,
                            "change the initial NVOS admin password to the "
                            "corresponding Ethernet password, then inspect and "
                            "possibly configure Day-0 settings",
                        )
                        if not apply_authorized:
                            log("No device changes authorized; stopping.")
                            return 0
                    result = run_on_ib(
                        target, neighbor, args.eth_user, eth_password,
                        args.ib_user, initial_ib_password, args.connect_timeout,
                        ["nv", "config", "show", "-o", "commands"],
                        local=ethernet_is_local,
                        allow_password_change=True,
                    )
                if result.password_changed:
                    log("  Initial NVOS password changed to the Ethernet switch password.")
                    log("  Reconnecting with the new NVOS password ...")
                    result = run_on_ib(
                        target, neighbor, args.eth_user, eth_password,
                        args.ib_user, eth_password, args.connect_timeout,
                        ["nv", "config", "show", "-o", "commands"],
                        local=ethernet_is_local,
                    )
                state = parse_nvue_state(result.output)
                log(
                    "  Current: eth0={} eth0-gateway={} eth1={} "
                    "eth1-gateway={} hostname={}".format(
                        ",".join(state.eth0_addresses) or "unset",
                        ",".join(state.eth0_gateways) or "unset",
                        ",".join(state.eth1_addresses) or "unset",
                        ",".join(state.eth1_gateways) or "unset",
                        state.hostname or "unset",
                    )
                )
                if args.auto:
                    auto_day0 = classify_auto_day0(target.ib, state)
                    if auto_day0 == "terminal":
                        failures += 1
                        terminal_targets.add(ib_key)
                        log(
                            "  Day-0 TERMINAL: protected fields are partially configured "
                            "or conflict with CSV; manual resolution required; no write attempted."
                        )
                        continue
                    day0_required = auto_day0 == "unconfigured"
                else:
                    day0_required = state_is_unconfigured(state)
                if args.force and not day0_required:
                    try:
                        day0_required = force_day0_needed(target.ib, state)
                    except SetupError as exc:
                        log(f"  Day-0 SKIP: {exc}")
                        day0_required = False
                if not day0_required:
                    skipped += 1
                    day0_skipped += 1
                    log("  Day-0 SKIP: protected fields already configured; services remain eligible.")
                    apply_authorized, service_was_skipped = run_service_stage(
                        target, neighbor, args.eth_user, eth_password, args.ib_user,
                        args.connect_timeout, services, state.raw_commands,
                        local=ethernet_is_local, apply=args.apply,
                        authorized=apply_authorized,
                    )
                    services_skipped += int(service_was_skipped)
                    apply_authorized = run_key_stage(
                        target, neighbor, args.eth_user, eth_password, args.ib_user,
                        args.connect_timeout, public_keys, local=ethernet_is_local,
                        apply=args.apply, authorized=apply_authorized,
                        management_private_key=management_private_key,
                    )
                    completed_targets.add(normalize_name(target.ib.hostname))
                    if method_cycle is not None:
                        if not apply_authorized or not method_cycle.complete(target, args.ib_user, management_private_key,
                                                                              args.connect_timeout, services, public_keys):
                            raise SetupError("managed current initial-setup configuration was not verified")
                    continue

                commands = desired_commands(target.ib)
                for command in commands:
                    log(
                        f"  {'APPLY' if args.apply else 'WOULD APPLY'}: "
                        f"{shlex.join(command)}"
                    )
                if not args.apply:
                    log("  Check-only mode; use --apply to configure.")
                    continue

                if not apply_authorized:
                    apply_authorized = confirm_first_device_change(
                        target,
                        "apply the displayed NVUE Day-0 commands and then verify "
                        "configuration and IPv4 SSH",
                    )
                    if not apply_authorized:
                        log("No device changes authorized; stopping.")
                        return 0

                try:
                    for command in commands:
                        run_on_ib(
                            target, neighbor, args.eth_user, eth_password,
                            args.ib_user, eth_password, args.connect_timeout,
                            command, local=ethernet_is_local,
                        )
                    verify_result = run_on_ib(
                        target, neighbor, args.eth_user, eth_password,
                        args.ib_user, eth_password, args.connect_timeout,
                        ["nv", "config", "show", "-o", "commands"],
                        local=ethernet_is_local,
                    )
                    verify_state(target.ib, parse_nvue_state(verify_result.output))
                    verify_ipv4_login(
                        target, neighbor.vrf, args.eth_user, eth_password,
                        args.ib_user, args.connect_timeout, local=ethernet_is_local,
                    )
                except SetupError as exc:
                    failures += 1
                    log(f"  ERROR after device change: {_authorized_failure_text(exc)}")
                    log(
                        "  STOP: post-configuration verification did not complete; "
                        "no subsequent IB device will be configured."
                    )
                    break
                configured += 1
                log(f"  SUCCESS: configuration verified; IPv4 SSH to {target.ib.login_ip} succeeded.")
                apply_authorized, service_was_skipped = run_service_stage(
                    target, neighbor, args.eth_user, eth_password, args.ib_user,
                    args.connect_timeout, services, verify_result.output,
                    local=ethernet_is_local, apply=args.apply,
                    authorized=apply_authorized,
                )
                services_skipped += int(service_was_skipped)
                apply_authorized = run_key_stage(
                    target, neighbor, args.eth_user, eth_password, args.ib_user,
                    args.connect_timeout, public_keys, local=ethernet_is_local,
                    apply=args.apply, authorized=apply_authorized,
                    management_private_key=management_private_key,
                )
                completed_targets.add(normalize_name(target.ib.hostname))
                if method_cycle is not None:
                    if not apply_authorized or not method_cycle.complete(target, args.ib_user, management_private_key,
                                                                          args.connect_timeout, services, public_keys):
                        raise SetupError("managed current initial-setup configuration was not verified")
            except SetupError as exc:
                failures += 1
                log(f"  ERROR: {_authorized_failure_text(exc)}")
                if strict_auto:
                    auto_terminal_only = False
                    authority_failed = getattr(strict_policy, "_auto_authority_failed", None)
                    if (auto_latched or type(authority_failed) is not bool or authority_failed
                            or auto_pending_change
                            or getattr(exc, "cleanup_uncertain", None) is True):
                        auto_latched = True
                        break
            finally:
                if method_cycle is not None:
                    method_cycle.fail_unfinished(target)

        if method_cycle is not None:
            method_cycle.close()

        oob_key_pending = False
        if args.auto and not auto_latched:
            _ib_project_value(strict_policy, user=args.ib_user)
            if (not auto_terminal_only
                    and (len(completed_targets) != ib_candidate_count or failures != 0)
                    and getattr(strict_policy, "_password", None) is None):
                if auto_credentials is not None:
                    auto_latched = True
                else:
                    # A first interactive nonterminal retry needs verified
                    # role custody before the OOB tail or any new watch.
                    _ib_project_value(strict_policy, user=args.ib_user, fetch=True)
        if args.auto and not auto_latched:
            for eth_key, ethernet in sorted(ethernet_switches.items()):
                if ethernet.dev_type not in {"eth", "ethernet"}:
                    log(
                        f"  OOB key SKIP: {ethernet.hostname} is {ethernet.dev_type}; "
                        "transit write is not authorized."
                    )
                    continue
                if eth_key in table_failures:
                    oob_key_pending = True
                    log(f"  OOB key RETRY: {ethernet.hostname} snapshot was unavailable.")
                    continue
                for entry in auto_management_keys:
                    oob_installing = False
                    try:
                        _ib_project_value(strict_policy, user=args.ib_user)
                        auto_pending_change = True
                        oob_installing = True
                        install_oob_management_key(
                            ethernet, args.eth_user, passwords[eth_key], entry,
                            args.connect_timeout,
                        )
                        oob_installing = False
                    except SetupError as exc:
                        oob_key_pending = True
                        # An ordinary installer failure (timeout, refused or
                        # interrupted SSH, non-zero exit) retries next round
                        # with the watch kept.  A project authority failure
                        # (the re-check before the installer) and an UNKNOWN
                        # cleanup still latch.  The installer decides only by
                        # exit code; its output is not classified.
                        if (oob_installing
                                and getattr(exc, "cleanup_uncertain", None) is not True):
                            auto_pending_change = False
                            log(f"  OOB key RETRY: {ethernet.hostname}: {exc}")
                        else:
                            auto_latched = True
                            log(f"  OOB key HOLD: {ethernet.hostname}: {exc}")
                        break
                    else:
                        _ib_project_value(strict_policy, user=args.ib_user)
                        auto_pending_change = False
                        log(f"  OOB key installed: {ethernet.hostname} {entry['fingerprint']}")
                if auto_latched:
                    break

        summary = (
            f"Summary: targets={len(targets)} configured={configured} "
            f"skipped={skipped} failed={failures} "
            f"day0-skipped={day0_skipped} services-skipped={services_skipped}"
        )
        if args.auto:
            ib_names = {
                normalize_name(target.ib.hostname): target.ib.hostname
                for target in targets
            }
            terminal_names = [
                ib_names.get(name, name) for name in sorted(terminal_targets)
            ]
            summary += (
                f" terminal={len(terminal_names)} "
                f"terminal-devices={','.join(terminal_names) or '-'}"
            )
        log("\n" + summary)
        if manual_outcome_enabled and manual_outcome_supported:
            log("Legacy Summary counters: 原阶段计数，非目标终态")
            log(_render_target_outcome_summary(
                target_results=tuple(tuple(row) for row in manual_outcome_rows),
                ethernet_results=tuple(manual_ethernet_outcomes),
            ))
        if args.auto:
            if auto_latched:
                return 1
            _ib_project_value(strict_policy, user=args.ib_user)
            if terminal_targets:
                _save_auto_terminal(terminal_path, terminal_identity, terminal_targets)
            credentials_path = (
                Path(os.path.abspath(args.credentials_file)) if args.credentials_file is not None
                else _auto_state_dir(tool) / "auto.env"
            )
            if len(completed_targets) == ib_candidate_count and failures == 0 and not oob_key_pending:
                if args.credentials_file is not None:
                    _remove_auto_watch(tool, credentials_path)
                    log("AUTO WATCH: all CSV IB switches configured; own cron and auto.env removed.")
                else:
                    log("AUTO WATCH: all CSV IB switches configured; no cron installed.")
            else:
                created = False
                verified_target = getattr(strict_policy, "_password", None)
                if verified_target is None and not auto_terminal_only:
                    auto_latched = True
                    return 1
                if args.credentials_file is None:
                    if verified_target is not None:
                        _write_auto_credentials(
                            credentials_path, initial_ib_password, passwords, targets,
                            _password_policy=strict_policy, _ib_user=args.ib_user,
                        )
                    else:
                        _write_auto_credentials(
                            credentials_path, initial_ib_password, passwords, targets,
                        )
                    created = True
                try:
                    _install_auto_watch(
                        tool, credentials_path, ib_csv_path, p2p_path, cache_path,
                        report_path, snapshot_directory, force=args.force,
                    )
                except SetupError:
                    auto_latched = True
                    raise
                log("AUTO WATCH: unresolved CSV IB switches; 10-minute own cron installed.")
        return 1 if failures else 0


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
        with _runtime_instance_guard():
            return _standalone_main_with_report_cleanup()
    except _InstanceGuardError as exc:
        print(f"{exc.code}: {exc}", file=sys.stderr)
        return 75 if exc.code == "ALREADY_RUNNING" else 2



if __name__ == "__main__":
    if sys.argv[1:] == ["--_verify-password"]:
        raise SystemExit(_password_hash_worker())
    raise SystemExit(_guarded_main())
