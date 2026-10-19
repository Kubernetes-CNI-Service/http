#!/usr/bin/env python3
"""Fixed project public-key HOME template; generation is not an install permit.

The genuine live password-authenticated adapter alone consumes these bytes.
No password, caller command/DTO/permit, sudo, HA or vendor body is supplied.
"""
from __future__ import annotations
import base64
import secrets
import contextlib
import datetime as dt
import fcntl
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import shlex
import stat
import sys
import threading
import time

class ProjectKeyInstallHold(ValueError):
    """Unknown source/auth state; never an installation result."""

def require_new_password_authentication(reply,explicit_rejections):
    """Pure refusal only; returning None never proves a live resource."""
    if (type(reply) is not str or reply!="authenticated"
            or type(explicit_rejections) is not int or explicit_rejections!=0):
        raise ProjectKeyInstallHold("CHANGE_REQUIRED or unknown authentication; no key write")

def render_project_key_install_script(management_public,laptop_public):
    from tools.ufm_bootstrap_auth_adapter import _direct_public_identity
    try:
        identities=tuple(_direct_public_identity(raw) for raw in (management_public,laptop_public))
        if identities[0]==identities[1]:
            raise ProjectKeyInstallHold("project keys must be distinct")
        raw=b"".join(b" ".join(key.split()[:2])+b"\n" for key in (management_public,laptop_public))
        payload=base64.b64encode(raw).decode("ascii")
        run_id=secrets.token_hex(16) # Internal private attempt; never caller path/command.
    except ProjectKeyInstallHold:
        raise
    except Exception:
        raise ProjectKeyInstallHold("project public key bytes are unproved") from None
    # Existing ordinary initial-setup HOME file contract. Actual utilities and
    # base64 decode option are checked before any mutation, never presumed or
    # installed. No remote Python/GNU/proc requirement or permission is added.
    return (
        "#!/usr/bin/env bash\nset -euo pipefail\n"
        "umask 077\n"
        "test -n \"$HOME\" && test -d \"$HOME\" && test ! -L \"$HOME\" || exit 31\n"
        + "".join("command -v "+name+" >/dev/null || exit 30\n"
                  for name in ("mkdir","chmod","mktemp","cat","base64","awk","cmp","mv","rm"))
        + "printf %s '"+payload+"' | base64 -d >/dev/null || exit 30\n"
        "ssh_dir=\"$HOME/.ssh\"\n"
        "if test -L \"$ssh_dir\" || { test -e \"$ssh_dir\" && test ! -d \"$ssh_dir\"; }; then exit 32; fi\n"
        "mkdir -p \"$ssh_dir\"; chmod 700 \"$ssh_dir\"\n"
        "auth=\"$ssh_dir/authorized_keys\"\n"
        "if test -L \"$auth\" || { test -e \"$auth\" && test ! -f \"$auth\"; }; then exit 33; fi\n"
        "stage_dir=\"$HOME/.xdr-key-stage-"+run_id+"\"\n"
        "backup_blocked() { printf '%s\\n' F01_BLOCKED_BACKUP >&2; exit 34; }\n"
        "mkdir -m 700 \"$stage_dir\" || backup_blocked\n"
        "backup=\"$stage_dir/authorized_keys.original\"\n"
        "if test -f \"$auth\"; then\n"
        "  if ! (set -C; cat \"$auth\" > \"$backup\"); then backup_blocked; fi\n"
        "  if ! cmp -s \"$auth\" \"$backup\"; then backup_blocked; fi\n"
        "  (set -C; printf '%s\\n' BACKUP_VERIFIED > \"$stage_dir/backup.state\") || backup_blocked\n"
        "else\n"
        "  (set -C; printf '%s\\n' NO_PRIOR_CONFIG > \"$stage_dir/backup.state\") || backup_blocked\n"
        "fi\n"
        "tmp=\"$(mktemp \"$ssh_dir/.authorized_keys.XXXXXX\")\"\n"
        "trap 'rm -f \"$tmp\"' EXIT\n"
        "trap 'exit 129' HUP\n"
        "trap 'exit 130' INT\n"
        "trap 'exit 143' TERM\n"
        "{ if test -f \"$auth\"; then awk '1' \"$auth\"; fi; printf %s '"+payload+"' | base64 -d; } | "
        "awk 'function iskey(v) { return v ~ /^(ssh-|ecdsa-|sk-)[A-Za-z0-9@._+-]+$/ } "
        "{ identity=\"\"; for (i=1; i<NF; i++) if (iskey($i)) "
        "{ identity=$i SUBSEP $(i+1); break } "
        "if (identity==\"\" || !seen[identity]++) print }' >\"$tmp\"\n"
        "chmod 600 \"$tmp\"\n"
        "if test -f \"$auth\" && cmp -s \"$tmp\" \"$auth\"; then rm -f \"$tmp\"; trap - EXIT; "
        "printf '%s\\n' F01_PROJECT_KEYS_INSTALLED_NOT_DEPLOYED; exit 0; fi\n"
        "mv -f \"$tmp\" \"$auth\"; trap - EXIT\n"
        "printf '%s\\n' F01_PROJECT_KEYS_INSTALLED_NOT_DEPLOYED\n"
    ).encode("ascii")

def _project_key_install_templates(management_public,laptop_public):
    """Fixed generation only: no caller stage/path/command or execute permit.

    The public combined template remains a historical local composition test.
    A genuine future live consumer must instead retain the same actual scope,
    pull the original backup, sync its management-server original, and only
    then send this separate apply body. Neither tuple nor remote state is an
    authorization or a durability receipt.
    """
    combined=render_project_key_install_script(management_public,laptop_public)
    stage_start=combined.index(b'stage_dir="$HOME/.xdr-key-stage-')
    stage_end=combined.index(b'\n',stage_start)+1
    stage_line=combined[stage_start:stage_end]
    run_id=stage_line[len(b'stage_dir="$HOME/.xdr-key-stage-'):-2].decode('ascii')
    if len(run_id)!=32 or any(c not in '0123456789abcdef' for c in run_id):
        raise ProjectKeyInstallHold("internal attempt binding is unknown")
    candidate_start=combined.index(b'tmp="$(mktemp "$ssh_dir/.authorized_keys.XXXXXX")"\n')
    backup=combined[:candidate_start].replace(b'BACKUP_VERIFIED',b'REMOTE_COPY_MATCHED_NOT_DURABLE')
    backup+=(b'if test -f "$backup"; then printf \'%s\\n\' REMOTE_COPY_MATCHED_NOT_DURABLE; '
             b'else printf \'%s\\n\' NO_PRIOR_CONFIG; fi\n')
    apply=(combined[:stage_start]+stage_line+
        b'apply_blocked() { printf \'%s\\n\' F01_BLOCKED_APPLY >&2; exit 35; }\n'
        b'test -d "$stage_dir" && test ! -L "$stage_dir" || apply_blocked\n'
        b'backup="$stage_dir/authorized_keys.original"\n'
        b'state_file="$stage_dir/backup.state"\n'
        b'test -f "$state_file" && test ! -L "$state_file" || apply_blocked\n'
        b'backup_state="$(cat "$state_file")" || apply_blocked\n'
        b'case "$backup_state" in\n'
        b'REMOTE_COPY_MATCHED_NOT_DURABLE)\n'
        b'  test -f "$auth" && test ! -L "$auth" && test -f "$backup" && test ! -L "$backup" || apply_blocked\n'
        b'  cmp -s "$auth" "$backup" || apply_blocked ;;\n'
        b'NO_PRIOR_CONFIG)\n'
        b'  if test -e "$auth" || test -L "$auth" || test -e "$backup" || test -L "$backup"; then apply_blocked; fi ;;\n'
        b'*) apply_blocked ;;\nesac\n'+combined[candidate_start:])
    return run_id,backup,apply


def _cleanup_key_resources(primary, errors):
    """Keep an already selected interruption even if diagnostic attachment fails."""
    if not errors:
        return
    operator = next((error for error in errors if not isinstance(error, Exception)), None)
    preferred = (primary if primary is not None and not isinstance(primary, Exception)
                 else operator)
    if preferred is not None:
        targets = (primary,) if preferred is primary else (primary, preferred)
        for target in targets:
            if target is None:
                continue
            try:
                target.key_resource_cleanup_errors = tuple(errors)
            except BaseException:
                # Diagnostics cannot replace this already selected original
                # body/cleanup interruption. No resource operation occurs here.
                pass
        if preferred is primary:
            raise primary
        raise preferred from primary
    if primary is not None:
        primary.key_resource_cleanup_errors = tuple(errors)
        raise primary
    from tools.ufm_bootstrap_auth_adapter import BootstrapAuthError
    hold = BootstrapAuthError("key-access owned cleanup UNKNOWN")
    hold.key_resource_cleanup_errors = tuple(errors)
    raise hold from errors[0]


class _KeyOriginals:
    """Private lexical originals, never an issued holder/token/operation grant.

    Named expected identity controls both admission and conditional close;
    a first-fstat replacement is never adopted as our new cleanup authority.
    Every ancestor and complete original file is checked at each source gate.
    """
    def __init__(self):
        self.directories = []
        self.files = []
        self.parents = {}
        self.context = (os.getpid(), threading.get_ident())
        self.active = True

    def directory(self, path, *, private=False):
        from tools import ufm_deployment_script_builder as builder
        if not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts:
            raise ProjectKeyInstallHold("key source directory path is invalid")
        key = str(path)
        if key in self.parents:
            parent = self.parents[key]
        else:
            chain = []
            parent = None
            for name in ("/", *path.parts[1:]):
                named = os.stat(name, dir_fd=parent, follow_symlinks=False)
                expected = builder._dir_key(named)
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                             dir_fd=parent)
                record = (fd, name, parent, expected)
                self.directories.append(record)
                chain.append(record)
                actual = os.fstat(fd)
                if not stat.S_ISDIR(actual.st_mode) or builder._dir_key(actual) != expected:
                    raise ProjectKeyInstallHold("named directory was replaced at open")
                parent = fd
            self.parents[key] = parent
        actual = os.fstat(parent)
        if private and (actual.st_uid != os.geteuid() or stat.S_IMODE(actual.st_mode) != 0o700):
            raise ProjectKeyInstallHold("private key evidence directory must be owned 0700")
        self.verify()
        return parent

    def child(self, parent, name):
        from tools import ufm_deployment_script_builder as builder
        if type(name) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name):
            raise ProjectKeyInstallHold("key evidence component is invalid")
        self.verify()
        os.mkdir(name, 0o700, dir_fd=parent)  # exclusive attempt, never overwrite
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        expected = builder._dir_key(named)
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        self.directories.append((fd, name, parent, expected))
        actual = os.fstat(fd)
        if (builder._dir_key(actual) != expected or not stat.S_ISDIR(actual.st_mode)
                or actual.st_uid != os.geteuid() or stat.S_IMODE(actual.st_mode) != 0o700):
            raise ProjectKeyInstallHold("new evidence directory original is unproved")
        self.verify()
        return fd

    def capture(self, path, cap, *, private=False):
        from tools import ufm_deployment_script_builder as builder
        parent = self.directory(path.parent)
        named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        expected = builder._file_key(named)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        record = dict(fd=fd, parent=parent, name=path.name, expected=expected,
                      raw=None, cap=cap, flags=None)
        self.files.append(record)  # register original named expectation before fstat
        before = os.fstat(fd)
        record["flags"] = fcntl.fcntl(fd, fcntl.F_GETFL)
        if (builder._file_key(before) != expected or not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1 or not 0 <= before.st_size <= cap
                or before.st_uid not in {0, os.geteuid()} or before.st_mode & 0o022
                or private and before.st_mode & 0o077
                or record["flags"] & os.O_ACCMODE != os.O_RDONLY):
            raise ProjectKeyInstallHold("key input original ownership/type/mode differs")
        raw = os.pread(fd, cap + 1, 0)
        if len(raw) != before.st_size or len(raw) > cap:
            raise ProjectKeyInstallHold("key input whole original read is unproved")
        record["raw"] = raw
        self.verify()
        return raw

    def save(self, parent, name, raw):
        """Retain EXCL actual original bytes; failed sync leaves truthful evidence."""
        from tools import ufm_deployment_script_builder as builder
        if name not in {"authorized_keys.original", "backup.state", "receipt.json"}:
            raise ProjectKeyInstallHold("key evidence filename is not fixed")
        if type(raw) is not bytes or len(raw) > 131072:
            raise ProjectKeyInstallHold("key evidence bytes are unbounded")
        self.verify()
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                     dir_fd=parent)
        record = dict(fd=fd, parent=parent, name=name, expected=None,
                      raw=None, cap=131072, flags=None)
        self.files.append(record)  # acquisition precedes any fallible stat
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        record["expected"] = builder._file_key(named)
        actual = os.fstat(fd)
        record["flags"] = fcntl.fcntl(fd, fcntl.F_GETFL)
        if (builder._file_key(actual) != record["expected"] or not stat.S_ISREG(actual.st_mode)
                or actual.st_uid != os.geteuid() or actual.st_nlink != 1
                or stat.S_IMODE(actual.st_mode) != 0o600 or actual.st_size != 0
                or record["flags"] & os.O_ACCMODE != os.O_RDWR):
            raise ProjectKeyInstallHold("new local backup named original is unproved")
        offset = 0
        while offset < len(raw):
            written = os.write(fd, raw[offset:])
            if written <= 0:
                raise ProjectKeyInstallHold("original local backup short write")
            if sys.platform == "darwin":
                # XNU FWASWRITTEN: set by the kernel only after actual positive
                # write retval. Derive from our strict prior flags, never adopt
                # current F_GETFL or waive any other status/access bit.
                record["flags"] |= 0x00010000
            offset += written
        # Only this admitted FD was written. Its inode/owner/mode/nlink remain
        # original; size and timestamps are bound once after our own writes.
        final = os.fstat(fd)
        if (builder._file_key(final)[:6] != record["expected"][:6]
                or final.st_size != len(raw)
                or builder._file_key(os.stat(name, dir_fd=parent, follow_symlinks=False)) != builder._file_key(final)):
            raise ProjectKeyInstallHold("own local backup write changed its named edge")
        record["expected"] = builder._file_key(final)
        record["raw"] = raw
        self.verify()  # independent bounded same-FD actual readback before sync
        os.fsync(fd)
        self.verify()
        return record

    def verify(self):
        from tools import ufm_deployment_script_builder as builder
        if not self.active or self.context != (os.getpid(), threading.get_ident()):
            raise ProjectKeyInstallHold("key original scope is closed or foreign")
        for fd, name, parent, expected in self.directories:
            actual = os.fstat(fd)
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (not stat.S_ISDIR(actual.st_mode) or builder._dir_key(actual) != expected
                    or builder._dir_key(named) != expected):
                raise ProjectKeyInstallHold("key original ancestor/name changed")
        for record in self.files:
            actual = os.fstat(record["fd"])
            named = os.stat(record["name"], dir_fd=record["parent"], follow_symlinks=False)
            if (builder._file_key(actual) != record["expected"]
                    or builder._file_key(named) != record["expected"]
                    or fcntl.fcntl(record["fd"], fcntl.F_GETFL) != record["flags"]):
                raise ProjectKeyInstallHold("key original file/FD/name changed")
            if record["raw"] is not None:
                raw = os.pread(record["fd"], record["cap"] + 1, 0)
                if (raw != record["raw"]
                        or builder._file_key(os.fstat(record["fd"])) != record["expected"]):
                    raise ProjectKeyInstallHold("key original whole bytes changed")

    def close(self):
        self.active = False  # revoke lexical scope before any original FD close
        errors = []
        for record in reversed(self.files):
            try:
                actual = os.fstat(record["fd"])
                if record["expected"] is None or (actual.st_dev, actual.st_ino) != record["expected"][:2]:
                    raise ProjectKeyInstallHold("key file cleanup identity UNKNOWN")
                os.close(record["fd"])
            except BaseException as error:
                errors.append(error)
        for fd, _name, _parent, expected in reversed(self.directories):
            try:
                actual = os.fstat(fd)
                if (actual.st_dev, actual.st_ino) != expected[:2]:
                    raise ProjectKeyInstallHold("key directory cleanup identity UNKNOWN")
                os.close(fd)
            except BaseException as error:
                errors.append(error)
        self.files.clear()
        self.directories.clear()
        return errors


class _KeyCalls:
    """Internal captured password session calls; no public native owner/DTO."""
    def __init__(self, client, guard, work_deadline, deadline):
        from types import MappingProxyType
        self.native = MappingProxyType(dict(client=client, work_deadline=work_deadline,
                                           deadline=deadline))
        self.channel = None
        self.workers = []
        self._guard = guard
        self._original_guard = guard
        self._original_guard_code = guard.__code__
        self._client = client

    def check(self):
        if (self._guard is not self._original_guard or self._guard.__code__ is not self._original_guard_code
                or self.native["client"] is not self._client):
            raise ProjectKeyInstallHold("captured key session guard/client changed")
        self._original_guard()

    def call(self, function, *args):
        self.check()
        result, errors = [], []
        def invoke():
            try:
                result.append(function(*args))
            except BaseException as error:
                errors.append(error)
        worker = threading.Thread(target=invoke, name="f01-key-native-call", daemon=False)
        self.workers.append(worker)
        worker.start()
        while worker.is_alive():
            worker.join(timeout=min(.02, max(0, self.native["work_deadline"] - time.monotonic())))
            if worker.is_alive():
                self.check()
        self.check()
        if errors:
            raise errors[0]
        if len(result) != 1:
            raise ProjectKeyInstallHold("key native call result UNKNOWN")
        return result[0]

    def close(self):
        errors = []
        if self.channel is not None:
            try:
                self.channel.close()
            except BaseException as error:
                errors.append(error)
        pending = False
        for worker in self.workers:
            try:
                pending = worker.is_alive() or pending
            except BaseException as error:
                errors.append(error)
                pending = True
        if pending:
            try:
                self._client.close()
            except BaseException as error:
                errors.append(error)
        for worker in self.workers:
            try:
                worker.join(timeout=max(0, self.native["deadline"] - time.monotonic()))
                if worker.is_alive():
                    raise ProjectKeyInstallHold("key native worker termination UNKNOWN")
            except BaseException as error:
                errors.append(error)
        try:
            if self.channel is not None and not self.channel.closed:
                errors.append(ProjectKeyInstallHold("key native Channel close UNKNOWN"))
        except BaseException as error:
            errors.append(error)
        return errors


def _fixed_key_body(client, body, guard, work_deadline, deadline):
    """One internal fixed Bash stdin body, ACK then send EOF then both output EOF."""
    from tools import ufm_bootstrap_auth_adapter as auth
    channel = None
    calls = _KeyCalls(client, guard, work_deadline, deadline)
    try:
        calls.check()
        if type(body) is not bytes or not 0 < len(body) <= 131072:
            raise ProjectKeyInstallHold("fixed key body bound differs")
        channel = client.open_session(timeout=max(.001, work_deadline - time.monotonic()))
        calls.channel = channel
        if (type(channel) is not auth.paramiko.Channel or channel.get_transport() is not client
                or client._channels.get(channel.get_id()) is not channel):
            raise ProjectKeyInstallHold("key body original Channel differs")
        channel.settimeout(max(.001, work_deadline - time.monotonic()))
        calls.call(channel.exec_command, "bash --noprofile --norc -p -s --")
        calls.call(channel.sendall, body)
        calls.call(channel.shutdown_write)
        stdout, stderr = bytearray(), bytearray()
        while True:
            calls.check()
            if channel.recv_ready():
                stdout.extend(channel.recv(4097-len(stdout)))
            if channel.recv_stderr_ready():
                stderr.extend(channel.recv_stderr(4097-len(stderr)))
            if len(stdout) > 4096 or len(stderr) > 4096:
                raise ProjectKeyInstallHold("fixed key body output cap exceeded")
            if (channel.eof_received and not channel.recv_ready() and not channel.recv_stderr_ready()
                    and channel.exit_status_ready()):
                if channel.recv_exit_status() != 0 or stderr:
                    raise ProjectKeyInstallHold("fixed key body failed; backup/apply state UNKNOWN")
                calls.check()
                return bytes(stdout)
            time.sleep(min(.01, max(0, work_deadline-time.monotonic())))
    finally:
        _cleanup_key_resources(sys.exc_info()[1], calls.close())


def _pull_key_backup(client, remote_home, uid, run_id, guard, work_deadline, deadline):
    """Two fixed read-only handles, real FSTAT/bounded DATA EOF/STATUS CLOSE."""
    from tools import ufm_deployment_staging_sftp as sftp
    from paramiko.sftp import int64
    calls = _KeyCalls(client, guard, work_deadline, deadline)
    wire = None
    handles = []
    primary = None
    try:
        wire = sftp._Wire(calls)  # packet grammar only; no readonly native issuance
        def read_file(name):
            path = remote_home+"/.xdr-key-stage-"+run_id+"/"+name
            attrs = wire.attrs(7, path)
            sftp._attributes(attrs, uid=uid, mode=stat.S_IFREG | 0o600)
            if type(attrs.st_size) is not int or not 0 <= attrs.st_size <= 131072:
                raise ProjectKeyInstallHold("remote original backup size is unbounded")
            handle = wire.open_final(path)
            handles.append(handle)
            initial = wire.attrs(8, handle)
            sftp._attributes(initial, uid=uid, mode=stat.S_IFREG | 0o600, size=attrs.st_size)
            raw = bytearray()
            while True:
                packet, payload, request, message = wire.request(5, handle, int64(len(raw)), 32768)
                if packet == 101:
                    if sftp._status(payload, request) != 1:
                        raise ProjectKeyInstallHold("backup actual SFTP READ EOF missing")
                    break
                if packet != 103:
                    raise ProjectKeyInstallHold("backup actual SFTP DATA missing")
                chunk = message.get_string()
                if not chunk or len(chunk) > 32768 or message.get_remainder():
                    raise ProjectKeyInstallHold("backup actual DATA framing differs")
                raw.extend(chunk)
                if len(raw) > 131072:
                    raise ProjectKeyInstallHold("backup actual bytes exceed cap")
            final = wire.attrs(8, handle)
            sftp._attributes(final, uid=uid, mode=stat.S_IFREG | 0o600, size=len(raw))
            if (initial.st_size != len(raw) or initial.st_mtime != final.st_mtime
                    or initial.st_gid != final.st_gid):
                raise ProjectKeyInstallHold("backup same-handle attributes changed")
            wire.close_handle(handle)  # actual request-id bound CLOSE_STATUS_OK
            handles.remove(handle)
            return bytes(raw)
        state = read_file("backup.state")
        if state == b"REMOTE_COPY_MATCHED_NOT_DURABLE\n":
            raw = read_file("authorized_keys.original")
        elif state == b"NO_PRIOR_CONFIG\n":
            # Absence must be actual NO_SUCH_FILE, not an arbitrary error.
            path = remote_home+"/.xdr-key-stage-"+run_id+"/authorized_keys.original"
            packet, payload, request, _msg = wire.request(7, path)
            if packet != 101 or sftp._status(payload, request) != 2:
                raise ProjectKeyInstallHold("NO_PRIOR_CONFIG backup absence differs")
            raw = None
        else:
            raise ProjectKeyInstallHold("remote backup state is unknown")
        calls.check()
        return state, raw
    finally:
        primary = sys.exc_info()[1]
        errors = []
        if wire is not None:
            for handle in handles:
                try:
                    wire.close_handle(handle)
                except BaseException as error:
                    errors.append(error)
        errors.extend(calls.close())
        _cleanup_key_resources(primary, errors)


@contextlib.contextmanager
def _new_key_session(address, original_guard, pinned, work_deadline, deadline):
    """Own one fresh direct original Transport, revoke before close/join."""
    from tools import ufm_bootstrap_auth_adapter as auth
    stream = client = None
    session_id = None
    authenticated = False
    authenticated_handler = None
    authenticated_handler_fields = None
    active = True
    def guard():
        if not active or time.monotonic() >= work_deadline:
            raise ProjectKeyInstallHold("original key-access scope deadline expired")
        original_guard()
        if client is not None and session_id is not None:
            if (not client.is_active() or not client.initial_kex_done or client.server_mode
                    or client.session_id != session_id or client.get_remote_server_key() != pinned
                    or authenticated and (not client.is_authenticated() or client.get_username() != "admin"
                        or client.auth_handler is not authenticated_handler
                        or (authenticated_handler.reply, authenticated_handler.auth_method) != authenticated_handler_fields
                        or not authenticated_handler.is_authenticated())):
                raise ProjectKeyInstallHold("original signed key-access session changed")
    def mark_authenticated():
        nonlocal authenticated, authenticated_handler, authenticated_handler_fields
        authenticated_handler = client.auth_handler
        if type(authenticated_handler) not in {auth._ReplyAuthHandler, auth._StrictKeyAuthHandler}:
            raise ProjectKeyInstallHold("actual original authentication handler is unproved")
        authenticated_handler_fields = (authenticated_handler.reply, authenticated_handler.auth_method)
        if authenticated_handler_fields not in {("authenticated", "password"), ("authenticated", "publickey")}:
            raise ProjectKeyInstallHold("actual original authentication mode is unproved")
        authenticated = True
        guard()
    try:
        guard()
        stream = auth._direct_ipv4_connected_stream(address, max(.001, work_deadline-time.monotonic()))
        client = auth.paramiko.Transport(stream)
        if (type(client) is not auth.paramiko.Transport or client.server_mode
                or client.auth_handler is not None or client.is_authenticated()):
            raise ProjectKeyInstallHold("new key-access SDK client is not fresh")
        client.start_client(timeout=max(.001, work_deadline-time.monotonic()))
        session_id = client.session_id
        if type(session_id) is not bytes or not session_id:
            raise ProjectKeyInstallHold("key-access signed KEX is absent")
        guard()  # independent actual server key BEFORE password or public key
        yield client, guard, mark_authenticated
        guard()
    finally:
        primary = sys.exc_info()[1]
        active = False
        errors = []
        if client is not None:
            for close in (client.close, lambda: client.join(timeout=max(0, deadline-time.monotonic()))):
                try:
                    close()
                except BaseException as error:
                    errors.append(error)
            try:
                if client.is_alive() or client.is_active():
                    errors.append(ProjectKeyInstallHold("original key-access Transport termination UNKNOWN"))
            except BaseException as error:
                errors.append(error)
        if stream is not None:
            try:
                stream.close()
            except BaseException as error:
                errors.append(error)
        _cleanup_key_resources(primary, errors)


@contextlib.contextmanager
def _held_managed_key_root(originals, project, output_link):
    """Private local-file scope, never a returned/native/collection permit."""
    from tools import ufm_managed_output_binding as managed
    graph=managed._OriginalGraph()
    active=True;context=(os.getpid(),threading.get_ident())
    try:
        try:
            selected,directory,_inputs=managed._capture_layout(graph,managed.HTTP_ROOT,output_link)
            if selected!=project:
                raise ProjectKeyInstallHold("managed key evidence project is not current selection")
            fd=originals.directory(directory.path,private=True)
            expected=os.fstat(directory.fd);actual=os.fstat(fd)
            if (expected.st_dev,expected.st_ino)!=(actual.st_dev,actual.st_ino):
                raise ProjectKeyInstallHold("managed key destination is not the held original output")
        except (managed.ManagedOutputHold,managed.builder.ScriptBuildHold,OSError):
            raise ProjectKeyInstallHold("managed key evidence input/output originals are HOLD") from None
        def verify():
            if not active or context!=(os.getpid(),threading.get_ident()):
                raise ProjectKeyInstallHold("managed local evidence scope is closed or foreign")
            try:
                graph.verify()
                original=os.fstat(directory.fd);current=os.fstat(fd)
                if (original.st_dev,original.st_ino)!=(current.st_dev,current.st_ino):
                    raise ProjectKeyInstallHold("managed evidence destination FD changed")
            except (managed.ManagedOutputHold,OSError):
                raise ProjectKeyInstallHold("managed evidence selection/source originals changed") from None
        verify()
        yield directory.path,fd,verify
        verify()
    finally:
        primary=sys.exc_info()[1]
        active=False # revoke local data scope BEFORE any original FD close
        try:graph.close()
        except BaseException as cleanup:_cleanup_key_resources(primary,[cleanup])


def _establish_direct_keys(project, address, known_hosts, pin, management_identity, *,
                           new_password, default_password, timeout, private_logs_root,
                           managed_output_link=None):
    """Only fixed fresh password -> durable local backup -> apply -> fresh key."""
    from tools import ufm_bootstrap_auth_adapter as auth
    from tools import ufm_identity_binding as identity
    from tools import ufm_deployment_script_builder as builder
    from tools import ufm_deployment_staging_sftp as sftp
    started = time.monotonic()
    originals = _KeyOriginals()
    private_key = None
    managed_scope=None;managed_entered=False;managed_recheck=None
    try:
        if (type(timeout) not in {int, float} or not math.isfinite(timeout) or not 0 < timeout <= 1200
                or type(new_password) is not str or not new_password
                or type(default_password) is not str or not default_password or new_password == default_password
                or type(pin) is not str or not re.fullmatch(r"[0-9a-f]{64}", pin)
                or type(address) is not str or str(ipaddress.IPv4Address(address)) != address):
            raise ProjectKeyInstallHold("fixed live key-access scalar inputs are invalid")
        if (private_logs_root is None)==(managed_output_link is None):
            raise ProjectKeyInstallHold("exactly one historical or managed evidence root is required")
        paths = (project, known_hosts, management_identity,
                 managed_output_link if managed_output_link is not None else private_logs_root)
        if any(not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts for path in paths):
            raise ProjectKeyInstallHold("fixed key-access source paths are invalid")
        http = project.parent.parent if project.parent.name == "DAY0-Prepare" else project
        if managed_output_link is not None:
            managed_scope=_held_managed_key_root(originals,project,managed_output_link)
            evidence_root,log_fd,managed_recheck=managed_scope.__enter__()
            managed_entered=True
        else:
            if (private_logs_root.name != "xdr-initial-setup-logs"
                    or any(private_logs_root == root or root in private_logs_root.parents
                           for root in (builder.HTTP_ROOT, http, project))):
                raise ProjectKeyInstallHold("key evidence root cannot be a public HTTP/project descendant")
            log_fd = originals.directory(private_logs_root, private=True)
            evidence_root=private_logs_root
        nodes, interface, sources = identity._project_inputs(project)
        selected = [node for node in nodes if node.address == address]
        if len(selected) != 1:
            raise ProjectKeyInstallHold("key-access node is not an exact current CSV member")
        node = selected[0]
        for path, digest in sources:
            raw = originals.capture(path, identity._MAX_PROJECT_SOURCE_BYTES)
            if hashlib.sha256(raw).hexdigest() != digest:
                raise ProjectKeyInstallHold("key-access project source changed during capture")
        known = originals.capture(known_hosts, 262144, private=True)
        if hashlib.sha256(known).hexdigest() != pin:
            raise ProjectKeyInstallHold("independent key-access server pin differs")
        pinned = auth._host_key(known, address)
        management = originals.capture(project/"mgmt-server.pub", 65536)
        laptop = originals.capture(project/"laptop.pub", 65536)
        private_raw = originals.capture(management_identity, 65536, private=True)
        public = auth._direct_public_identity(management)
        if public == auth._direct_public_identity(laptop):
            raise ProjectKeyInstallHold("current project keys must be distinct")
        private_key = auth._private_key_from_bound_bytes(private_raw)
        if (private_key.get_name().encode("ascii"), private_key.asbytes()) != public:
            raise ProjectKeyInstallHold("management private key differs from current project public")
        run_id, backup_body, apply_body = _project_key_install_templates(management, laptop)
        deadline = started + float(timeout)
        work_deadline = deadline - min(.25, float(timeout)/5)
        with auth._held_direct_sdk_sources():
            sdk = auth._direct_sdk_identity()
            def source_guard():
                if time.monotonic() >= work_deadline:
                    raise ProjectKeyInstallHold("original key-access work deadline expired")
                originals.verify()
                if managed_recheck is not None:managed_recheck()
                if not identity._project_sources_still_bound(sources) or auth._direct_sdk_identity() != sdk:
                    raise ProjectKeyInstallHold("original key-access project/SDK identity changed")
            with _new_key_session(address, source_guard, pinned, work_deadline, deadline) as (client, guard, mark_auth):
                reply = auth._attempt(client, "admin", new_password, max(.001, work_deadline-time.monotonic()))
                guard()
                rejections = 0
                if reply == "rejected":
                    rejections = 1
                    reply = auth._attempt(client, "admin", default_password, max(.001, work_deadline-time.monotonic()))
                    guard()
                require_new_password_authentication(reply, rejections)  # default success: zero write
                mark_auth()
                def observe():
                    return identity._observe_direct_phase(node, interface, "bootstrap",
                        dt.datetime.now(dt.timezone.utc), pin,
                        lambda argv: auth._direct_owned_read(client, " ".join(argv), guard, work_deadline, deadline))
                initial = observe()
                home_raw = auth._direct_owned_read(client,
                    shlex.join(sftp._HOME_UID_ARGV), guard, work_deadline, deadline).encode("utf-8")
                remote_home, remote_uid = sftp._decode_home_uid(home_raw)
                backup_output = _fixed_key_body(client, backup_body, guard, work_deadline, deadline)
                if backup_output not in {
                        b"REMOTE_COPY_MATCHED_NOT_DURABLE\n", b"NO_PRIOR_CONFIG\n"}:
                    raise ProjectKeyInstallHold("backup-only fixed output is unknown")
                state, backup_raw = _pull_key_backup(client, remote_home, remote_uid, run_id,
                                                     guard, work_deadline, deadline)
                if state != backup_output:
                    raise ProjectKeyInstallHold("actual backup state differs from fixed body completion")
                # The local evidence scope remains original and data-only;
                # no remote action follows unless full file+dir sync succeeds.
                if managed_recheck is not None:managed_recheck()
                run_fd = originals.child(log_fd, run_id)
                evidence_fd=run_fd;evidence_path=evidence_root/run_id
                if managed_recheck is not None:
                    managed_recheck()
                    node_fd=originals.child(run_fd,node.hostname)
                    managed_recheck()
                    evidence_fd=originals.child(node_fd,"key-access")
                    evidence_path=evidence_path/node.hostname/"key-access"
                    managed_recheck()
                originals.save(evidence_fd, "backup.state", state)
                if managed_recheck is not None:managed_recheck()
                if backup_raw is not None:
                    originals.save(evidence_fd, "authorized_keys.original", backup_raw)
                    if managed_recheck is not None:managed_recheck()
                originals.verify()
                os.fsync(evidence_fd)
                if managed_recheck is not None:
                    os.fsync(node_fd);os.fsync(run_fd);managed_recheck()
                os.fsync(log_fd)  # the newly created private attempt name itself
                originals.verify()
                guard()
                before_apply = observe()
                if (before_apply.hostname != initial.hostname or before_apply.management_mac != initial.management_mac
                        or before_apply.address != initial.address):
                    raise ProjectKeyInstallHold("key installation source node changed before apply")
                if _fixed_key_body(client, apply_body, guard, work_deadline, deadline) != b"F01_PROJECT_KEYS_INSTALLED_NOT_DEPLOYED\n":
                    raise ProjectKeyInstallHold("fixed key apply completion is unknown")
                guard()
            # Password client is closed/reaped before entirely new key-only KEX.
            with _new_key_session(address, source_guard, pinned, work_deadline, deadline) as (client, guard, mark_auth):
                handler = auth._StrictKeyAuthHandler(client)
                event = threading.Event()
                with client.lock:
                    client.auth_handler = handler
                try:
                    handler.auth_publickey("admin", private_key, event)
                    if (not event.wait(max(0, work_deadline-time.monotonic())) or client.get_exception() is not None
                            or handler.reply != "authenticated" or not handler.is_authenticated()):
                        raise ProjectKeyInstallHold("fresh management key authentication is unproved")
                    mark_auth()
                finally:
                    handler.private_key = None
                    private_key = None
                final = identity._observe_direct_phase(node, interface, "bootstrap",
                    dt.datetime.now(dt.timezone.utc), pin,
                    lambda argv: auth._direct_owned_read(client, " ".join(argv), guard, work_deadline, deadline))
                if (final.hostname != initial.hostname or final.management_mac != initial.management_mac
                        or final.address != initial.address):
                    raise ProjectKeyInstallHold("fresh key-only actual node differs from password session")
                guard()
            source_guard()
            receipt = dict(state="PROJECT_KEY_ACCESS_ESTABLISHED_NOT_DEPLOYED", node=node.hostname,
                observed_hostname=final.hostname, address=address, project_root=str(project), run_id=run_id,
                backup_state=state.decode("ascii").strip(),
                backup_sha256=hashlib.sha256(backup_raw).hexdigest() if backup_raw is not None else None,
                known_hosts_sha256=pin, evidence_directory=str(evidence_path),
                execution_permitted=False, completion=False)
            originals.save(evidence_fd, "receipt.json",
                           (json.dumps(receipt, sort_keys=True, separators=(",", ":"))+"\n").encode())
            os.fsync(evidence_fd)
            originals.verify()
            source_guard()
            return receipt
    except auth.BootstrapAuthError:
        raise
    except Exception as error:
        raise auth.BootstrapAuthError("fixed project key access is HOLD; retained private backup is not deployment") from error
    finally:
        private_key = None
        primary=sys.exc_info()[1];cleanup=[]
        if managed_entered:
            try:managed_scope.__exit__(type(primary) if primary is not None else None,primary,
                                      primary.__traceback__ if primary is not None else None)
            except BaseException as error:cleanup.append(error)
        try:cleanup.extend(originals.close())
        except BaseException as error:cleanup.append(error)
        _cleanup_key_resources(primary, cleanup)
