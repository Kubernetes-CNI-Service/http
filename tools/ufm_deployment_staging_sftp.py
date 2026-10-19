#!/usr/bin/env python3
"""Fixed generated readonly stage -> one fresh deployment SFTP owner.

STAGED_NOT_EXECUTED is authenticated file-protocol evidence, not a command,
deployment permit, remote kernel inode proof or seven-step completion. No
collection read/download authority is adopted. Server non-overwrite conformance
and real UFM service capability remain separately NOT RUN.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import contextlib
import os
from pathlib import PurePosixPath
import shlex
import stat
import struct
import sys
import threading
import time
import uuid

from tools import ufm_deployment_staging_owner as owner

class StagingSftpHold(ValueError):
    """Unconfirmed stage/source/protocol/cleanup, never execution permission."""

_HOME_UID_ARGV = ("bash", "--noprofile", "--norc", "-p", "-c",
                  "printf '%s\\0' \"$HOME\" \"$UID\"")
_PART_OPEN_MODE = "x+"
_STANDARD_RENAME = 18
_CAP = 131072

@dataclass(frozen=True)
class StagedScript:
    state: str
    project_root: str
    node: str
    source_sha256: str
    remote_path: str
    remote_uid: int
    protocol_close_confirmed: bool
    execution_permitted: bool = False
    completion: bool = False

def _decode_home_uid(raw):
    if type(raw) is not bytes or len(raw) > 4096 or not raw.endswith(b"\0"):
        raise StagingSftpHold("fixed home/uid probe is unproved")
    fields = raw.split(b"\0")
    if len(fields) != 3 or fields[-1] or not fields[1].isdigit():
        raise StagingSftpHold("fixed home/uid fields differ")
    try:
        home = fields[0].decode("utf-8", "strict")
    except UnicodeError as error:
        raise StagingSftpHold("home path encoding is invalid") from error
    path = PurePosixPath(home)
    if (not home.startswith("/") or str(path) != home or home == "/"
            or ".." in path.parts or any(ord(char) < 32 or ord(char) == 127 for char in home)
            or len(fields[1]) > 10 or int(fields[1]) > 2**32 - 1):
        raise StagingSftpHold("fixed absolute home/uid rejected")
    return home, int(fields[1])

def _status(raw, expected):
    if type(raw) is not bytes or len(raw) < 16 or len(raw) > 8192:
        raise StagingSftpHold("bounded actual SFTP status absent")
    request, code, size = struct.unpack(">III", raw[:12])
    if request != expected or size > 4096 or 16 + size > len(raw):
        raise StagingSftpHold("actual SFTP status/request binding differs")
    offset = 12 + size
    language_size = struct.unpack(">I", raw[offset:offset+4])[0]
    if language_size > 4096 or offset + 4 + language_size != len(raw):
        raise StagingSftpHold("actual SFTP status framing differs")
    return code

def _close_status_ok(packet_type, raw, expected):
    if packet_type != 101 or _status(raw, expected) != 0:
        raise StagingSftpHold("owned SFTP CLOSE_STATUS_OK is unproved")
    return True

def _attributes(attrs, *, uid, mode, size=None):
    if (type(attrs) is not owner.auth.paramiko.SFTPAttributes
            or attrs.st_uid != uid or attrs.st_mode is None
            or stat.S_IFMT(attrs.st_mode) != stat.S_IFMT(mode)
            or stat.S_IMODE(attrs.st_mode) != stat.S_IMODE(mode)
            or size is not None and attrs.st_size != size):
        raise StagingSftpHold("authenticated SFTP type/uid/mode/size differs")

class _NativeCalls:
    """One owned non-daemon SDK call at a time, one original absolute budget."""
    def __init__(self, native):
        self.native = native
        self.workers = []
        self.channel = None

    def check(self):
        current = owner._issued_native_deployment_owner(self.native["owner"])
        if current is not self.native or time.monotonic() >= self.native["work_deadline"]:
            raise StagingSftpHold("current native owner/deadline is unproved")

    def call(self, function, *args):
        self.check()
        result, errors = [], []
        def invoke():
            try:
                result.append(function(*args))
            except BaseException as error:
                errors.append(error)
        worker = threading.Thread(target=invoke, name="f01-owned-sftp-call", daemon=False)
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
            raise StagingSftpHold("owned native call result is incomplete")
        return result[0]

    def close(self):
        errors = []
        if self.channel is not None:
            try:
                self.channel.close()
            except BaseException as error:
                errors.append(error)
        # A channel close normally wakes its pending SDK event/read. If not,
        # close this captured owner (no other sessions/PIDs) before final join.
        if any(worker.is_alive() for worker in self.workers):
            try:
                self.native["client"].close()
            except BaseException as error:
                errors.append(error)
        for worker in self.workers:
            try:
                worker.join(timeout=max(0, self.native["deadline"] - time.monotonic()))
                if worker.is_alive():
                    errors.append(StagingSftpHold("owned SFTP call termination UNKNOWN"))
            except BaseException as error:
                errors.append(error)
        if self.channel is not None and not self.channel.closed:
            errors.append(StagingSftpHold("owned SFTP channel close UNKNOWN"))
        return errors

class _Wire:
    """Serial fixed packet primitives on this one captured original Channel.

    No public command/handle/path injection. Raw matching request-id STATUS is
    retained independently of SFTPFile.close(), which can swallow close errors.
    """
    def __init__(self, calls):
        self.calls = calls
        calls.check()
        channel = calls.native["client"].open_session(
            timeout=max(.001, calls.native["work_deadline"] - time.monotonic()))
        calls.channel = channel
        channel.settimeout(max(.001, calls.native["work_deadline"] - time.monotonic()))
        calls.call(channel.invoke_subsystem, "sftp")
        self.client = calls.call(owner.auth.paramiko.SFTPClient, channel)

    def request(self, command, *args):
        from paramiko.message import Message
        self.calls.check()
        self.calls.channel.settimeout(max(.001,
            self.calls.native["work_deadline"] - time.monotonic()))
        def exchange():
            request = self.client._async_request(type(None), command, *args)
            packet, raw = self.client._read_packet()
            if type(raw) is not bytes or len(raw) < 4 or len(raw) > _CAP + 8192:
                raise StagingSftpHold("actual SFTP packet bound differs")
            if struct.unpack(">I", raw[:4])[0] != request:
                raise StagingSftpHold("actual owned SFTP request-id mismatch")
            with self.client._lock:
                if self.client._expecting.pop(request, None) is not type(None):
                    raise StagingSftpHold("owned serial SFTP response registry differs")
            return packet, raw, request
        packet, raw, request = self.calls.call(exchange)
        msg = Message(raw)
        if msg.get_int() != request:
            raise StagingSftpHold("actual packet parser request differs")
        return packet, raw, request, msg

    def ok(self, command, *args):
        packet, raw, request, _msg = self.request(command, *args)
        if packet != 101 or _status(raw, request) != 0:
            raise StagingSftpHold("owned fixed SFTP mutation STATUS_OK absent")

    def attrs(self, command, name):
        packet, _raw, _request, msg = self.request(command, name)
        if packet != 105:
            raise StagingSftpHold("actual SFTP attributes absent")
        attrs = owner.auth.paramiko.SFTPAttributes._from_msg(msg)
        if msg.get_remainder():
            raise StagingSftpHold("actual SFTP attributes have trailing data")
        return attrs

    def close_handle(self, handle):
        packet, raw, request, _msg = self.request(4, handle)
        return _close_status_ok(packet, raw, request)

    def readback(self, handle, expected):
        from paramiko.sftp import int64
        offset, actual = 0, bytearray()
        while True:
            packet, raw, request, msg = self.request(5, handle, int64(offset), 32768)
            if packet == 101:
                if _status(raw, request) != 1:
                    raise StagingSftpHold("actual bounded READ EOF absent")
                break
            if packet != 103:
                raise StagingSftpHold("actual SFTP DATA absent")
            chunk = msg.get_string()
            if not chunk or len(chunk) > 32768 or msg.get_remainder():
                raise StagingSftpHold("actual DATA length/framing differs")
            actual.extend(chunk)
            offset += len(chunk)
            if offset > _CAP:
                raise StagingSftpHold("same handle actual bytes exceed bound")
        if bytes(actual) != expected:
            raise StagingSftpHold("same-handle actual readback differs")
        return bytes(actual)

    def open_part(self, path):
        # READ|WRITE|CREATE|EXCL, not TRUNC; private mode accompanies CREATE.
        attrs = owner.auth.paramiko.SFTPAttributes()
        attrs.st_mode = 0o600
        packet, _raw, _request, msg = self.request(3, path, 1 | 2 | 8 | 32, attrs)
        if packet != 102:
            raise StagingSftpHold("exclusive original SFTP handle absent")
        handle = msg.get_string()
        if not handle or len(handle) > 256 or msg.get_remainder():
            raise StagingSftpHold("actual SFTP handle framing differs")
        return handle

    def open_final(self, path):
        packet, _raw, _request, msg = self.request(3, path, 1,
                                                   owner.auth.paramiko.SFTPAttributes())
        if packet != 102:
            raise StagingSftpHold("published readonly handle absent")
        handle = msg.get_string()
        if not handle or len(handle) > 256 or msg.get_remainder():
            raise StagingSftpHold("published handle framing differs")
        return handle

_ISSUED_STAGED_ORIGINALS = {}

class _StagedOriginal:
    """Opaque live same-final-handle scope; never a public permission DTO."""

def _issued_staged_original(staged):
    record = _ISSUED_STAGED_ORIGINALS.get(id(staged))
    if (type(staged) is not _StagedOriginal or record is None or record["object"] is not staged
            or staged.__dict__ or record["context"] != (os.getpid(), threading.get_ident())):
        raise StagingSftpHold("same staged original has no current issuance")
    native = owner._issued_native_deployment_owner(record["native"]["owner"])
    if (native is not record["native"] or owner._check_issued_stage(native["held"]) is not record["issued"]
            or type(record["wire"]) is not _Wire or type(record["calls"]) is not _NativeCalls
            or record["wire"].calls is not record["calls"] or record["calls"].native is not native
            or record["wire"].client is not record["client"] or record["calls"].channel is not record["channel"]
            or record["client"].sock is not record["channel"]
            or record["channel"].get_transport() is not native["client"] or record["channel"].closed):
        raise StagingSftpHold("captured native/source/SFTP original differs")
    record["calls"].check()
    if _ISSUED_STAGED_ORIGINALS.get(id(staged)) is not record:
        raise StagingSftpHold("same staged original was revoked")
    return record

@contextlib.contextmanager
def _staged_original_on_native(live):
    from paramiko.sftp import int64
    native = owner._issued_native_deployment_owner(live)
    issued = owner._check_issued_stage(native["held"])
    calls = _NativeCalls(native)
    wire = None
    handles = []
    remote_directory = staged = None
    try:
        raw_home = owner.auth._direct_owned_read(native["client"],
            shlex.join(_HOME_UID_ARGV), native["guard"],
            native["work_deadline"], native["deadline"])
        if type(raw_home) is not str:
            raise StagingSftpHold("fixed owned UTF-8 home probe result differs")
        home, uid = _decode_home_uid(raw_home.encode("utf-8", "strict"))
        calls.check()
        raw = os.pread(issued["fields"]["script_fd"], _CAP + 1, 0)
        if hashlib.sha256(raw).hexdigest() != issued["fields"]["script_sha256"] or len(raw) > _CAP:
            raise StagingSftpHold("actual held source bytes changed")
        wire = _Wire(calls)
        # Only authenticated attrs; these do not claim remote dev/ino/nlink.
        home_attrs = wire.attrs(7, home)
        if (home_attrs.st_uid != uid or home_attrs.st_mode is None
                or not stat.S_ISDIR(home_attrs.st_mode)
                or home_attrs.st_mode & 0o022):
            raise StagingSftpHold("actual admin home type/uid/writeability differs")
        remote_directory = home + "/.xdr-stage-" + uuid.uuid4().hex
        directory_attrs = owner.auth.paramiko.SFTPAttributes()
        directory_attrs.st_mode = 0o700
        wire.ok(14, remote_directory, directory_attrs)
        _attributes(wire.attrs(7, remote_directory), uid=uid, mode=stat.S_IFDIR | 0o700)
        part, final = remote_directory + "/stage.sh.part", remote_directory + "/stage.sh"
        handle = wire.open_part(part)
        handles.append(handle)
        _attributes(wire.attrs(8, handle), uid=uid, mode=stat.S_IFREG | 0o600, size=0)
        for offset in range(0, len(raw), 32768):
            wire.ok(6, handle, int64(offset), raw[offset:offset+32768])
        _attributes(wire.attrs(8, handle), uid=uid, mode=stat.S_IFREG | 0o600, size=len(raw))
        wire.readback(handle, raw)
        handles.remove(handle)
        # A failed CLOSE response is UNKNOWN, not grounds to resend a CLOSE
        # that might target a server-reused handle.
        wire.close_handle(handle)
        # The server's STANDARD_RENAME contract is non-overwrite. Never use
        # posix-rename, a caller rename or exists+overwrite rename as substitute.
        packet, status, request, _msg = wire.request(7, final)
        if packet != 101 or _status(status, request) != 2:
            raise StagingSftpHold("final name already exists or absence unknown")
        wire.ok(_STANDARD_RENAME, part, final)
        _attributes(wire.attrs(7, final), uid=uid, mode=stat.S_IFREG | 0o600, size=len(raw))
        handle = wire.open_final(final)
        handles.append(handle)
        _attributes(wire.attrs(8, handle), uid=uid, mode=stat.S_IFREG | 0o600, size=len(raw))
        actual = wire.readback(handle, raw)
        calls.check()
        staged = _StagedOriginal()
        record = {"object": staged, "context": (os.getpid(), threading.get_ident()),
            "native": native, "issued": issued, "wire": wire, "calls": calls,
            "client": wire.client, "channel": calls.channel, "handle": handle,
            "actual": actual, "final": final, "directory": remote_directory, "uid": uid}
        _ISSUED_STAGED_ORIGINALS[id(staged)] = record
        yield staged
        _ISSUED_STAGED_ORIGINALS.pop(id(staged), None) # revoke before original close
        handles.remove(handle)
        wire.close_handle(handle)
        calls.check()
    except StagingSftpHold as error:
        error.remote_residue = remote_directory
        error.remote_cleanup_confirmed = remote_directory is None
        raise
    except Exception as error:
        hold = StagingSftpHold("fixed SFTP stage remains HOLD")
        hold.remote_residue = remote_directory
        hold.remote_cleanup_confirmed = remote_directory is None
        raise hold from error
    finally:
        if staged is not None: _ISSUED_STAGED_ORIGINALS.pop(id(staged), None)
        primary = sys.exc_info()[1]
        cleanup = []
        # Close each remaining actual handle at most once. No file/dir remove:
        # standard SFTP cannot prove an unchanged original naming generation.
        for handle in handles:
            try:
                wire.close_handle(handle)
            except BaseException as error:
                cleanup.append(error)
        cleanup.extend(calls.close())
        owner._raise_cleanup(primary, cleanup, "SFTP owned resource cleanup UNKNOWN")

def _stage_on_native(live):
    # Previous public stage APIs retain their exact source/packet/close behavior.
    with _staged_original_on_native(live) as staged:
        record = _issued_staged_original(staged)
        issued = record["issued"]
        result = StagedScript("STAGED_NOT_EXECUTED", str(issued["fields"]["project"]),
            issued["node_fields"][0], hashlib.sha256(record["actual"]).hexdigest(),
            record["final"], record["uid"], True)
    return result

def stage_readonly_project_script(*, script_path, known_hosts,
        expected_known_hosts_sha256, management_identity, timeout=10):
    """Fixed current source -> fresh direct owner -> stage only, never execute."""
    try:
        with owner._held_project_stage(script_path=script_path, known_hosts=known_hosts,
                expected_known_hosts_sha256=expected_known_hosts_sha256,
                management_identity=management_identity, timeout=timeout) as held:
            issued = owner._check_issued_stage(held)
            # SAME admitted original readonly script FD, not a later path open.
            owner.syntax._run_syntax_child(script_fd=issued["fields"]["script_fd"],
                cwd=script_path.parent, deadline=issued["work_deadline"])
            owner._check_issued_stage(held)
            with owner._owned_direct_deployment_session(held) as live:
                result = _stage_on_native(live)
            owner._check_issued_stage(held)
        return result
    except StagingSftpHold:
        raise
    except Exception as error:
        raise StagingSftpHold("current fixed source/native stage is HOLD") from error

def stage_project_readonly_script(*, script_path, known_hosts,
        expected_known_hosts_sha256, management_identity, oob_username=None,
        oob_known_hosts=None, expected_oob_known_hosts_sha256=None,
        far_known_hosts=None, expected_far_known_hosts_sha256=None, timeout=10):
    """Independent default configured stage, not failed configuration recovery.

    The optional OOB group is complete or absent; absence does not force P2P
    discovery on a successful IPv4 route. No caller destination or session.
    """
    group = (oob_username, oob_known_hosts, expected_oob_known_hosts_sha256,
             far_known_hosts, expected_far_known_hosts_sha256)
    try:
        with owner._held_project_stage(script_path=script_path, known_hosts=known_hosts,
                expected_known_hosts_sha256=expected_known_hosts_sha256,
                management_identity=management_identity, timeout=timeout) as held:
            with owner._held_default_sources(held, group) as sources:
                issued = owner._check_issued_stage(held)
                owner.syntax._run_syntax_child(script_fd=issued["fields"]["script_fd"],
                    cwd=script_path.parent, deadline=issued["work_deadline"])
                owner._check_default_sources(sources)
                with owner._owned_default_deployment_session(held, sources) as live:
                    result = _stage_on_native(live)
                owner._check_default_sources(sources)
        return result
    except StagingSftpHold:
        raise
    except Exception as error:
        raise StagingSftpHold("fixed default deployment stage remains HOLD") from error
