#!/usr/bin/env python3
"""D67 project-bound bootstrap authentication observation, never stage-one GO.

The original password observer accepts an already established SSH Transport.
The legacy configured-address observer owns one supplied connected stream.
The direct non-DHCP entries own a fixed node IPv4 connection by default and
construct a fresh pinned Transport; they do not retry or switch addresses.
External known_hosts bytes, the cryptographic server key
and actual project inputs bind observations. Unknown input closes owned state.

Optional dependency: requirements-f01-ssh.lock. Paramiko's generic synchronous
AuthenticationException also represents timeout and EOF. Only the complete
encrypted USERAUTH_FAILURE received by the version-checked AuthHandler can
establish an explicit password rejection. No keyboard-interactive fallback.

The direct entries use explicitly approved admin. A separate fixed direct key
consumer owns its fresh password session and durable backup; password-change
mechanisms are not supplied. Default-password success is HOLD
with CHANGE_REQUIRED, not a changed password or permission for later operations.
"""
from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import getpass
import hashlib
import importlib.metadata
import inspect
import ipaddress
import io
import math
import errno
import sys
import time
import socket
import base64
from pathlib import Path
import re
import struct
import threading
import contextvars
import contextlib
import os
import warnings
from typing import Callable

import paramiko
from paramiko.auth_handler import AuthHandler
from paramiko.hostkeys import HostKeyEntry
from paramiko.ssh_exception import AuthenticationException

from infra.ufm_jump_transport import BoundFarEndpoint, JumpEndpoint
from tools import ufm_identity_binding as binding
from tools import f01_ssh_dependency_identity as dependency_identity


class BootstrapAuthError(ValueError):
    """Uncertain authentication: HOLD; no password fallback or remote mutation."""


class _ExplicitPasswordRejection(AuthenticationException):
    """Only a complete non-partial password-enabled failure packet creates this."""


_F01_LOCK_SHA256 = "16562dd9f3598038afc4c915c849d397fce86b4d902cb7f90db580a31a981d8a"
_SDK_SOURCE_SCOPE = contextvars.ContextVar("f01_sdk_source_scope", default=None)
_ISSUED_SDK_SOURCES = {}


def _sdk_member_bindings():
    classes = (paramiko.Transport, AuthHandler, paramiko.Message, paramiko.PKey,
               paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey, paramiko.Channel)
    members = (AuthHandler.auth_password, AuthHandler._parse_userauth_failure,
               AuthHandler._parse_userauth_success, AuthHandler.auth_publickey,
               paramiko.Transport.auth_password, paramiko.Transport.auth_publickey,
               *(getattr(paramiko.Channel, name) for name in
                 ("exec_command", "recv", "recv_stderr", "recv_ready", "recv_stderr_ready",
                  "exit_status_ready", "recv_exit_status", "close")))
    return classes, tuple((member, getattr(member, "__code__", None)) for member in members)


def _current_sdk_sources():
    pool = _SDK_SOURCE_SCOPE.get()
    if pool is None:
        return None
    record = _ISSUED_SDK_SOURCES.get(id(pool))
    if (type(pool) is not dependency_identity._LexicalOriginals or record is None
            or record["pool"] is not pool or not pool.active
            or record["context"] != (os.getpid(), threading.get_ident())
            or pool.context != record["context"]
            or record["runtime"] != (sys.prefix, sys.base_prefix, sys.executable)):
        raise BootstrapAuthError("original SDK source scope is unproved")
    if record["bindings"] is not None:
        classes, functions = _sdk_member_bindings()
        old_classes, old_functions = record["bindings"]
        if (any(a is not b for a, b in zip(classes, old_classes))
                or any(a is not b or code is not old_code
                       for (a, code), (b, old_code) in zip(functions, old_functions))):
            raise BootstrapAuthError("original SDK function binding changed")
    return record


@contextlib.contextmanager
def _held_direct_sdk_sources():
    """Empty lexical source holding, never authentication or operation authority."""
    if _SDK_SOURCE_SCOPE.get() is not None:
        raise BootstrapAuthError("SDK source scope cannot cross owner/route")
    pool = dependency_identity._LexicalOriginals()
    record = {"pool": pool, "context": (os.getpid(), threading.get_ident()),
              "runtime": (sys.prefix, sys.base_prefix, sys.executable), "bindings": None}
    _ISSUED_SDK_SOURCES[id(pool)] = record
    token = _SDK_SOURCE_SCOPE.set(pool)
    try:
        yield
    finally:
        primary = sys.exc_info()[1]
        _ISSUED_SDK_SOURCES.pop(id(pool), None) # revoke BEFORE any physical FD close
        errors = []
        try:
            _SDK_SOURCE_SCOPE.reset(token)
        except BaseException as cleanup:
            errors.append(cleanup)
        try:
            pool.close()
        except BaseException as cleanup:
            errors.append(cleanup)
        if errors:
            cleanup = errors[0]
            hold = BootstrapAuthError("original SDK source cleanup UNKNOWN")
            hold.__cause__ = cleanup
            hold.cleanup_errors = tuple(errors)
            if primary is not None and not isinstance(primary, Exception):
                raise primary from hold
            operator = next((error for error in errors if not isinstance(error, Exception)), None)
            if operator is not None:
                raise operator from hold
            if isinstance(primary, DirectConnectionUnreachable):
                # Source cleanup UNKNOWN cannot authorize a different address.
                raise hold from primary
            if primary is not None:
                raise primary from hold
            raise hold from cleanup


def _sdk_source_reads(role):
    record = _current_sdk_sources()
    return (dependency_identity._OriginalReads() if record is None
            else record["pool"].view(role))


def _factory_sdk_identity():
    """Actual locked environment plus RECORD-owned SDK implementation sources."""
    reads = _sdk_source_reads("FACTORY")
    try:
        root = Path(__file__).resolve().parents[1]
        if _current_sdk_sources() is None:
            environment = dependency_identity.f01_ssh_dependency_environment(
                root, expected_lock_sha256=_F01_LOCK_SHA256)
        else:
            environment = dependency_identity._environment_on_original_reads(
                root, expected_lock_sha256=_F01_LOCK_SHA256, reads=_sdk_source_reads("ENV"))
        info = next(item for item in environment["distributions"] if item["name"] == "paramiko")
        metadata_path = Path(info["metadata_path"])
        record = reads.read(metadata_path / "RECORD", 8 * 1024 * 1024)
        if hashlib.sha256(record).hexdigest() != info["record_sha256"]:
            raise BootstrapAuthError("SSH SDK implementation identity is unproved")
        entries = dependency_identity._record(record)
        sources = []
        for relative, member in (("paramiko/transport.py", paramiko.Transport),
                                 ("paramiko/auth_handler.py", AuthHandler),
                                 ("paramiko/message.py", paramiko.Message),
                                 ("paramiko/pkey.py", paramiko.PKey),
                                 ("paramiko/ed25519key.py", paramiko.Ed25519Key),
                                 ("paramiko/ecdsakey.py", paramiko.ECDSAKey),
                                 ("paramiko/rsakey.py", paramiko.RSAKey)):
            path, raw = dependency_identity._record_file(
                reads, metadata_path.parent, entries, relative, 4 * 1024 * 1024)
            if inspect.getsourcefile(member) != str(path):
                raise BootstrapAuthError("SSH SDK class origin is unproved")
            sources.append({"path": str(path), "sha256": hashlib.sha256(raw).hexdigest(),
                            "identity": reads.binding(path)})
        reads.verify()
        return {"environment": environment, "sdk_sources": sources}
    except Exception:
        raise BootstrapAuthError("SSH SDK implementation identity is unproved") from None
    finally:
        reads.close()


def _private_key_from_bound_bytes(raw):
    """Parse held original bytes in memory; no path reread or agent/default key."""
    if type(raw) is not bytes or not 0 < len(raw) <= 65536:
        raise BootstrapAuthError("bound jump private key is unproved")
    try:
        text = raw.decode("ascii")
    except UnicodeError:
        raise BootstrapAuthError("bound jump private key is unproved") from None
    # PEM armour headers are split so this format check is not itself key text.
    if not text.startswith(("-----BEGIN " + "OPENSSH PRIVATE KEY-----",
                            "-----BEGIN " + "EC PRIVATE KEY-----",
                            "-----BEGIN " + "RSA PRIVATE KEY-----")):
        raise BootstrapAuthError("bound jump private key is unproved")
    for key_class in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            key = key_class.from_private_key(io.StringIO(text), password=None)
            if not key.can_sign():
                raise BootstrapAuthError("bound jump private key cannot sign")
            return key
        except paramiko.PasswordRequiredException:
            raise BootstrapAuthError("encrypted jump private key requires a separate input contract") from None
        except (paramiko.SSHException, ValueError):
            continue
    raise BootstrapAuthError("bound jump private key is unproved")


class _StrictKeyAuthHandler(AuthHandler):
    """Owned jump key-auth: only the complete empty SUCCESS means authenticated."""
    def __init__(self, transport):
        super().__init__(transport)
        self.reply = None

    def _parse_userauth_success(self, message):
        if message.get_remainder() or self.auth_method != "publickey":
            self.reply = "unknown"
            self.transport.saved_exception = BootstrapAuthError("jump key authentication reply is unknown")
            if self.auth_event is not None:
                self.auth_event.set()
            return
        self.reply = "authenticated"
        super()._parse_userauth_success(message)

    def _parse_userauth_failure(self, message):
        # Every refusal/partial/malformed failure is HOLD. No fallback or
        # reauthentication is performed and no untrusted methods are logged.
        self.reply = "failed"
        self.authenticated = False
        self.username = None
        self.transport.saved_exception = BootstrapAuthError("jump key authentication was not established")
        if self.auth_event is not None:
            self.auth_event.set()


class _BoundJumpConnectFailure(paramiko.SSHException):
    """Created only by this owned session's complete bound failure handler."""


@dataclass(frozen=True)
class ConfiguredConnectionObservation:
    hostname: str
    address: str
    connection: str
    state: str = "HOLD"
    fallback_authorized: bool = False


def _decode_bound_channel_failure(raw: bytes, *, expected_channel: int) -> tuple[int, int]:
    """Strict complete wire grammar only, never transport/fallback authority.

    The message type has already been selected by the SSH packet dispatcher.
    Neither this diagnostic result nor a standalone SDK ChannelException proves
    an authenticated jump, session ownership, target binding or reachability.
    """
    error = "channel failure payload is unknown or unbound"
    if (type(raw) is not bytes or not 16 <= len(raw) <= 8192
            or type(expected_channel) is not int
            or not 0 <= expected_channel <= 0xFFFFFFFF):
        raise BootstrapAuthError(error)
    channel, reason = struct.unpack(">II", raw[:8])
    if channel != expected_channel or reason != 2:
        raise BootstrapAuthError(error)
    offset = 8
    for _field in range(2):  # description and language, both complete strings
        if len(raw) - offset < 4:
            raise BootstrapAuthError(error)
        width = struct.unpack(">I", raw[offset:offset + 4])[0]
        offset += 4
        if width > 4096 or width > len(raw) - offset:
            raise BootstrapAuthError(error)
        try:
            raw[offset:offset + width].decode("utf-8")
        except UnicodeError:
            raise BootstrapAuthError(error) from None
        offset += width
    if offset != len(raw):
        raise BootstrapAuthError(error)
    return channel, reason


class _ScopedChannelFailureHandler:
    """Private wire consumer, not an install/caller-Transport admission API.

    The adapter-owned factory supplies private original-source/session guards,
    owned close and original SDK event/cleanup closures. This consumer alone
    supplies no session or fallback authority. Local fake-I/O tests establish
    decoding and callback order only, not real encrypted jump evidence.
    In particular every result remains HOLD.
    """
    state = "HOLD"
    fallback_authorized = False

    def __init__(self, *, expected_channel, target, port, guard, finish, abort):
        try:
            address = str(ipaddress.IPv4Address(target))
        except (ValueError, TypeError):
            raise BootstrapAuthError("channel target must be a literal CSV IPv4 address") from None
        if (type(target) is not str or address != target
                or type(port) is not int or port != 22
                or type(expected_channel) is not int
                or not 0 <= expected_channel <= 0xFFFFFFFF
                or not all(callable(callback) for callback in (guard, finish, abort))):
            raise BootstrapAuthError("channel scope is incomplete")
        self.expected_channel, self.target, self.port = expected_channel, target, port
        self._guard, self._finish, self._abort = guard, finish, abort
        self._handled = False
        self.payload_sha256 = None

    def __call__(self, message):
        try:
            if self._handled:
                raise BootstrapAuthError("channel failure was already observed")
            self._handled = True
            if self._guard() is not None:
                raise BootstrapAuthError("channel scope guard is unknown")
            raw = message.get_remainder()  # never advance the SDK cursor
            channel, reason = _decode_bound_channel_failure(
                raw, expected_channel=self.expected_channel)
            # Never pass untrusted description/language to a log or error path.
            if self._finish(channel, reason) is not None:
                raise BootstrapAuthError("channel failure completion is unknown")
            if self._guard() is not None:
                raise BootstrapAuthError("channel scope guard is unknown")
            self.payload_sha256 = hashlib.sha256(raw).hexdigest()
        except BaseException as error:
            self.payload_sha256 = None
            self._abort()
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                raise
            raise BootstrapAuthError("bound channel rejection is unproved") from None


def observe_project_configured_connection(
    project: Path, jump: JumpEndpoint, far: BoundFarEndpoint,
    expected_known_hosts_sha256: str, *, connected_stream_boundary, timeout: float,
) -> ConfiguredConnectionObservation:
    return _observe_project_connection(
        project, jump, far, expected_known_hosts_sha256,
        connected_stream_boundary=connected_stream_boundary, timeout=timeout)


def _observe_project_connection(
    project: Path, jump: JumpEndpoint, far: BoundFarEndpoint,
    expected_known_hosts_sha256: str, *, connected_stream_boundary, timeout: float,
    _owned_channel_consumer=None,
):
    """Own one local supplied stream, KEX/key-auth and exact CSV channel probe.

    No socket is opened here. A supplied Transport, host tuple or default stream
    is not admitted. The returned fact is diagnostic HOLD: even reason 2 only
    means this pinned jump refused this channel, not licence or fallback GO.
    The existing no-follow reader binds original bytes, not continuous inode
    identity between separate reads. No secret is placed in argv or files.
    """
    stream = transport = channel = auth = scoped = dispatch = original_handler = None
    failure_event = None
    owned_stream = False
    cleanup_failed = False
    try:
        if (not callable(connected_stream_boundary)
                or type(timeout) not in {int, float} or not math.isfinite(timeout)
                or not 0 < timeout <= 1200
                or type(jump) is not JumpEndpoint or type(far) is not BoundFarEndpoint
                or far.jump != jump or jump.identity is None
                or type(expected_known_hosts_sha256) is not str
                or not re.fullmatch(r"[0-9a-f]{64}", expected_known_hosts_sha256)):
            raise BootstrapAuthError("configured connection inputs are incomplete")
        if str(ipaddress.IPv4Address(far.host)) != far.host:
            raise BootstrapAuthError("configured target is not literal IPv4")
        nodes, _interface, sources = binding._project_inputs(Path(project))
        selected = [node for node in nodes if node.address == far.host]
        if len(selected) != 1:
            raise BootstrapAuthError("configured address is not an exact project node")
        _sdk_contract()
        # Preserve the original password observer's API checks unchanged.
        for member, parameters in (
            (AuthHandler.auth_publickey, ("self", "username", "key", "event")),
            (paramiko.Transport.start_client, ("self", "event", "timeout")),
            (paramiko.Transport.open_channel,
             ("self", "kind", "dest_addr", "src_addr", "window_size", "max_packet_size", "timeout")),
        ):
            if tuple(inspect.signature(member).parameters) != parameters:
                raise BootstrapAuthError("owned SSH SDK API is unverified")
        sdk_identity = _factory_sdk_identity()
        known = binding._read_regular_no_follow(jump.known_hosts, limit=256 * 1024, private=True)
        if hashlib.sha256(known).hexdigest() != expected_known_hosts_sha256:
            raise BootstrapAuthError("configured pin differs from external authority")
        binding._pinned_hosts(known, jump.host, far.host)
        pinned = _host_key(known, jump.host)
        private_bytes = binding._read_regular_no_follow(jump.identity, limit=65536, private=True)
        private_key = _private_key_from_bound_bytes(private_bytes)
        session_id = None

        def guard():
            if (not binding._project_sources_still_bound(sources)
                    or binding._read_regular_no_follow(jump.known_hosts, limit=256 * 1024, private=True) != known
                    or binding._read_regular_no_follow(jump.identity, limit=65536, private=True) != private_bytes
                    or _factory_sdk_identity() != sdk_identity):
                raise BootstrapAuthError("owned connection inputs changed")
            if transport is not None and session_id is not None:
                if (not transport.is_active() or not transport.initial_kex_done
                        or transport.session_id != session_id
                        or transport.get_remote_server_key() != pinned):
                    raise BootstrapAuthError("owned pinned session changed")
                if auth is not None and (
                        transport.auth_handler is not auth or auth.reply != "authenticated"
                        or auth.auth_method != "publickey" or not auth.is_authenticated()
                        or not transport.is_authenticated() or transport.get_username() != jump.user):
                    raise BootstrapAuthError("owned key-auth session changed")
            if scoped is not None and transport._handler_table.get(92) is not dispatch:
                raise BootstrapAuthError("owned channel handler changed")

        guard()
        stream = connected_stream_boundary(jump)
        if (isinstance(stream, paramiko.Transport) or isinstance(stream, (str, tuple))
                or not all(callable(getattr(stream, name, None))
                           for name in ("recv", "send", "settimeout", "close"))):
            # A caller-owned Transport is neither adopted nor closed here.
            raise BootstrapAuthError("an exclusive connected stream is required")
        owned_stream = True
        guard()
        transport = paramiko.Transport(stream)
        if (type(transport) is not paramiko.Transport or transport.server_mode
                or transport.auth_handler is not None or transport.is_authenticated()):
            raise BootstrapAuthError("fresh owned SSH client is unproved")
        transport.start_client(timeout=timeout)
        session_id = transport.session_id
        if type(session_id) is not bytes or not session_id:
            raise BootstrapAuthError("owned KEX session is absent")
        guard()  # KEX key is checked BEFORE any authentication emission.
        event = threading.Event()
        auth = _StrictKeyAuthHandler(transport)
        with transport.lock:
            transport.auth_handler = auth
        try:
            auth.auth_publickey(jump.user, private_key, event)
            if (not event.wait(timeout) or transport.get_exception() is not None):
                raise BootstrapAuthError("owned key authentication is unproved")
            guard()
        finally:
            auth.private_key = None
            private_key = None
        with transport.lock:
            if (transport._channel_counter != 0 or len(transport._channels)
                    or transport.channel_events or transport.channels_seen):
                raise BootstrapAuthError("owned channel scope is not fresh")
            original_handler = transport._handler_table.get(92)
            if original_handler != transport._parse_channel_open_failure:
                raise BootstrapAuthError("owned SDK channel dispatcher is unproved")

        def finish(channel_id, reason):
            nonlocal failure_event
            with transport.lock:
                pending = transport._channels.get(channel_id)
                pending_event = transport.channel_events.get(channel_id)
                if (channel_id != 0 or reason != 2 or transport._channel_counter != 1
                        or not transport.channels_seen.get(channel_id)
                        or type(pending) is not paramiko.Channel
                        or pending.get_transport() is not transport
                        or pending.get_id() != channel_id
                        or type(pending_event) is not threading.Event
                        or pending_event.is_set() or transport.saved_exception is not None):
                    raise BootstrapAuthError("owned pending channel is unproved")
                # Preserve the SDK's failure event/map cleanup without logging
                # peer-controlled description or synthesizing a SDK packet.
                transport.saved_exception = _BoundJumpConnectFailure("bound jump connect refusal")
                transport._channels.delete(channel_id)
                failure_event = pending_event

        scoped = _ScopedChannelFailureHandler(expected_channel=0, target=far.host, port=22,
                                              guard=guard, finish=finish, abort=transport.close)
        def dispatch(message):
            scoped(message)
            # The SDK caller can wake immediately on Event.set(). Publish the
            # complete post-guarded payload BEFORE that signal, not after it.
            with transport.lock:
                if (failure_event is None or transport.channel_events.get(0) is not failure_event
                        or type(transport.saved_exception) is not _BoundJumpConnectFailure
                        or scoped.payload_sha256 is None):
                    raise BootstrapAuthError("owned channel completion is unproved")
                dispatch.payload_sha256 = scoped.payload_sha256
                failure_event.set()
                del transport.channel_events[0]
        dispatch.payload_sha256 = None
        transport._handler_table[92] = dispatch  # this instance only, never SDK class
        guard()
        try:
            channel = transport.open_channel("direct-tcpip", dest_addr=(far.host, 22),
                                             src_addr=("127.0.0.1", 0), timeout=timeout)
        except _BoundJumpConnectFailure as error:
            if (type(error) is not _BoundJumpConnectFailure or scoped.payload_sha256 is None
                    or dispatch.payload_sha256 != scoped.payload_sha256):
                raise BootstrapAuthError("bound connection refusal is unproved")
            guard()
            return ConfiguredConnectionObservation(selected[0].hostname, far.host,
                                                   "PINNED_JUMP_CONNECT_FAILED")
        guard()
        if (type(channel) is not paramiko.Channel or channel.get_transport() is not transport
                or channel.get_id() != 0 or transport._channels.get(0) is not channel
                or transport._channel_counter != 1 or transport.channel_events):
            raise BootstrapAuthError("owned opened channel is unproved")
        if _owned_channel_consumer is not None:
            # Only an internal closure consumes this invocation's original
            # channel. No caller receives a session, receipt or permission.
            return _owned_channel_consumer(channel, guard, known)
        return ConfiguredConnectionObservation(selected[0].hostname, far.host, "SSH_CHANNEL_OPENED")
    except Exception:
        raise BootstrapAuthError("configured connection observation is HOLD") from None
    finally:
        if auth is not None:
            auth.private_key = None
        if transport is not None:
            if scoped is not None and transport._handler_table.get(92) is dispatch:
                transport._handler_table[92] = original_handler
            if channel is not None:
                try:
                    if channel.get_transport() is transport:
                        channel.close()
                    else:
                        cleanup_failed = True
                except Exception:
                    cleanup_failed = True
            try:
                transport.close()
            except Exception:
                cleanup_failed = True
            try:
                transport.join(timeout=min(float(timeout), 1.0))
                if transport.is_alive():
                    cleanup_failed = True
            except Exception:
                cleanup_failed = True
        if owned_stream:
            try:
                stream.close()
            except Exception:
                cleanup_failed = True
        if cleanup_failed:
            raise BootstrapAuthError("owned connection cleanup is unproved") from None


def observe_project_prompted_bootstrap_authentication(
    project: Path, lease_path: Path, jump: JumpEndpoint, far: BoundFarEndpoint,
    expected_known_hosts_sha256: str, *, connected_stream_boundary,
    identity_runner, timeout: float,
    clock: Callable[[], dt.datetime] = lambda: dt.datetime.now(dt.timezone.utc),
) -> BootstrapAuthenticationObservation:
    """Prompt/confirm private runtime credentials before issuing any session.

    A getpass echo fallback is a failure, not permission to use stdin openly.
    Prompts contain no identity or input excerpts. Credentials are passed only
    in memory to our owned authentication observer; neither returned nor
    persisted. Clearing local references is not a claim of string zeroization.
    This does not change a password, install a key, or complete stage one.
    """
    default_password = new_password = confirmation = None
    try:
        if (not callable(connected_stream_boundary) or not callable(identity_runner)
                or not callable(clock)):
            raise BootstrapAuthError("prompted authentication boundaries are incomplete")
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            default_password = getpass.getpass("UFM default password: ")
            new_password = getpass.getpass("UFM new password: ")
            confirmation = getpass.getpass("Confirm UFM new password: ")
        if (type(default_password) is not str or not default_password
                or type(new_password) is not str or not new_password
                or type(confirmation) is not str or confirmation != new_password
                or default_password == new_password):
            raise BootstrapAuthError("prompted authentication inputs are invalid")
        confirmation = None
        return observe_project_owned_bootstrap_authentication(
            project=project, lease_path=lease_path, jump=jump, far=far,
            expected_known_hosts_sha256=expected_known_hosts_sha256,
            connected_stream_boundary=connected_stream_boundary,
            identity_runner=identity_runner, new_password=new_password,
            default_password=default_password, timeout=timeout, clock=clock)
    except (Exception, KeyboardInterrupt):
        raise BootstrapAuthError("prompted bootstrap authentication is HOLD") from None
    finally:
        default_password = new_password = confirmation = None


def observe_project_owned_bootstrap_authentication(
    project: Path, lease_path: Path, jump: JumpEndpoint, far: BoundFarEndpoint,
    expected_known_hosts_sha256: str, *, connected_stream_boundary,
    identity_runner, new_password: str, default_password: str, timeout: float,
    clock: Callable[[], dt.datetime] = lambda: dt.datetime.now(dt.timezone.utc),
) -> BootstrapAuthenticationObservation:
    """Issue jump and far sessions privately, then use the D67 password rule.

    The only stream boundary is the existing connection to the declared jump.
    The far session can only be created on our actual authenticated jump's
    original channel. Existing lease/key-only identity checks are retained:
    this is not a first-contact policy, password change or key installation.
    All results remain HOLD and neither Transport nor credentials are returned.
    """
    try:
        if (not callable(connected_stream_boundary) or not callable(identity_runner)
                or not callable(clock)
                or type(new_password) is not str or not new_password
                or type(default_password) is not str or not default_password
                or new_password == default_password):
            raise BootstrapAuthError("owned authentication inputs are incomplete")
        lease_bytes = binding._read_regular_no_follow(
            Path(lease_path), limit=32 * 1024 * 1024, private=False)

        def consume(channel, jump_guard, known):
            client = None
            cleanup_failed = False
            try:
                jump_guard()
                pinned = _host_key(known, far.host)
                session_id = None
                def guard():
                    jump_guard()
                    if binding._read_regular_no_follow(
                            Path(lease_path), limit=32 * 1024 * 1024, private=False) != lease_bytes:
                        raise BootstrapAuthError("owned authentication lease changed")
                    if client is not None and session_id is not None:
                        if (not client.is_active() or not client.initial_kex_done
                                or client.session_id != session_id
                                or client.get_remote_server_key() != pinned):
                            raise BootstrapAuthError("owned far KEX session changed")
                guard()
                client = paramiko.Transport(channel)
                if (type(client) is not paramiko.Transport or client.server_mode
                        or client.auth_handler is not None or client.is_authenticated()):
                    raise BootstrapAuthError("fresh owned far client is unproved")
                client.start_client(timeout=timeout)
                session_id = client.session_id
                if type(session_id) is not bytes or not session_id:
                    raise BootstrapAuthError("owned far KEX session is absent")
                guard()  # actual signed far key is pinned before any password
                def read_identity(argv):
                    guard()
                    result = identity_runner(argv)
                    guard()
                    return result
                result = observe_project_bootstrap_authentication(
                    project, lease_path, jump, far, expected_known_hosts_sha256, client,
                    new_password=new_password, default_password=default_password,
                    timeout=timeout, clock=clock, identity_runner=read_identity)
                guard()
                return result
            finally:
                if client is not None:
                    if isinstance(client.auth_handler, _ReplyAuthHandler):
                        client.auth_handler.password = None
                    try:
                        client.close()
                    except Exception:
                        cleanup_failed = True
                    try:
                        client.join(timeout=min(float(timeout), 1.0))
                        if client.is_alive():
                            cleanup_failed = True
                    except Exception:
                        cleanup_failed = True
                if cleanup_failed:
                    raise BootstrapAuthError("owned far cleanup is unproved") from None

        result = _observe_project_connection(
            project, jump, far, expected_known_hosts_sha256,
            connected_stream_boundary=connected_stream_boundary, timeout=timeout,
            _owned_channel_consumer=consume)
        if type(result) is not BootstrapAuthenticationObservation:
            # A precise jump refusal is still not password auth or DHCP GO.
            raise BootstrapAuthError("owned far authentication was not reached")
        return result
    except Exception:
        raise BootstrapAuthError("owned bootstrap authentication is HOLD") from None


class DirectConnectionUnreachable(BootstrapAuthError):
    """Only a connection-boundary result, not an IPv6/fallback permission."""


# Default-parent-only connection constraint. It is not an authentication
# grant, selector or caller callback. Original explicit direct calls retain
# their original budget when this private context is absent.
_default_connection_parent_deadline = contextvars.ContextVar(
    "ufm_default_connection_parent_deadline", default=None)


def _direct_ipv4_connected_stream(address, timeout):
    """One fixed node IPv4/22 TCP connection, exclusively owned until return.

    No DNS, ProxyCommand, VIP, retry or credential/address fallback. The caller
    has already bound the actual project and independent pin before this call.
    It still must verify actual signed KEX before any supplied password.
    """
    try:
        if (type(address) is not str or str(ipaddress.IPv4Address(address)) != address
                or type(timeout) not in {int, float} or not math.isfinite(timeout)
                or not 0 < timeout <= 1200):
            raise ValueError("fixed IPv4 connection inputs")
    except (ValueError, TypeError):
        raise BootstrapAuthError("fixed direct IPv4 connection inputs are unproved") from None
    parent_deadline = _default_connection_parent_deadline.get()
    if parent_deadline is not None:
        remaining = min(timeout, parent_deadline - time.monotonic())
        if remaining <= 0:
            # No actual connect occurred; never classify this as unreachable.
            raise BootstrapAuthError("default original connection deadline expired")
        timeout = min(1., remaining / 4)
    stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        stream.settimeout(timeout)
        stream.connect((address, 22))
        return stream
    except BaseException as primary:
        try:
            stream.close()
        except BaseException as cleanup:
            hold = BootstrapAuthError("original direct connection cleanup is unconfirmed")
            hold.__cause__ = cleanup
            if not isinstance(primary, Exception):
                raise primary from hold
            # Unconfirmed cleanup is HOLD, never classified as safely
            # unreachable and never permission to use another address.
            raise hold from cleanup
        raise


def _direct_sdk_identity():
    """Retain the original eight-package/SDK contract and bind Channel code."""
    _sdk_contract()
    scope = _current_sdk_sources()
    base = _factory_sdk_identity()
    reads = _sdk_source_reads("CHANNEL")
    try:
        info = next(item for item in base["environment"]["distributions"]
                    if item["name"] == "paramiko")
        metadata_path = Path(info["metadata_path"])
        record = reads.read(metadata_path / "RECORD", 8 * 1024 * 1024)
        if hashlib.sha256(record).hexdigest() != info["record_sha256"]:
            raise BootstrapAuthError("direct SDK record changed")
        path, raw = dependency_identity._record_file(
            reads, metadata_path.parent, dependency_identity._record(record),
            "paramiko/channel.py", 4 * 1024 * 1024)
        for name, parameters in (("exec_command", ("self", "command")),
                                 ("recv", ("self", "nbytes")),
                                 ("recv_stderr", ("self", "nbytes")),
                                 ("recv_ready", ("self",)),
                                 ("recv_stderr_ready", ("self",)),
                                 ("exit_status_ready", ("self",)),
                                 ("recv_exit_status", ("self",)),
                                 ("close", ("self",))):
            member = getattr(paramiko.Channel, name)
            if (inspect.getsourcefile(member) != str(path)
                    or tuple(inspect.signature(member).parameters) != parameters):
                raise BootstrapAuthError("direct SDK channel API is unproved")
        reads.verify()
        if scope is not None:
            if scope["bindings"] is None:
                scope["bindings"] = _sdk_member_bindings()
            _current_sdk_sources()
        return {"base": base, "channel": {"path": str(path),
                "sha256": hashlib.sha256(raw).hexdigest(), "identity": reads.binding(path)}}
    finally:
        reads.close()


def _direct_owned_read(client, command, guard, work_deadline, deadline):
    """Own one real session channel and one bounded original native exec call."""
    channel = worker = None
    ready = threading.Event()
    outcome = []
    try:
        guard()
        channel = client.open_session(timeout=max(0.001, work_deadline - time.monotonic()))
        if (type(channel) is not paramiko.Channel or channel.get_transport() is not client
                or client._channels.get(channel.get_id()) is not channel):
            raise BootstrapAuthError("direct original session channel is unproved")
        channel.settimeout(max(0.001, work_deadline - time.monotonic()))
        def execute():
            try:
                channel.exec_command(command)  # exactly one original SDK invocation
                outcome.append(None)
            except BaseException as error:
                outcome.append(error)
            finally:
                ready.set()
        worker = threading.Thread(target=execute, name="ufm-direct-native-read", daemon=False)
        worker.start()
        while not ready.wait(min(0.01, max(0, work_deadline - time.monotonic()))):
            guard()
        guard()
        worker.join(timeout=max(0, deadline - time.monotonic()))
        if worker.is_alive() or len(outcome) != 1 or outcome[0] is not None:
            raise BootstrapAuthError("direct native exec result is unproved")
        stdout = bytearray()
        stderr = bytearray()
        while True:
            guard()
            if channel.recv_ready():
                stdout.extend(channel.recv(16385 - len(stdout)))
            if channel.recv_stderr_ready():
                stderr.extend(channel.recv_stderr(16385 - len(stderr)))
            if len(stdout) > 16384 or len(stderr) > 16384:
                raise BootstrapAuthError("direct identity output exceeds its fixed bound")
            if (channel.eof_received and not channel.recv_ready()
                    and not channel.recv_stderr_ready() and channel.exit_status_ready()):
                if channel.recv_exit_status() != 0 or stderr:
                    raise BootstrapAuthError("direct identity command did not complete")
                guard()
                return bytes(stdout).decode("utf-8")
            time.sleep(min(0.01, max(0, work_deadline - time.monotonic())))
    finally:
        primary = sys.exc_info()[1]
        cleanup = None
        if channel is not None:
            try:
                channel.close()
            except BaseException as error:
                cleanup = error
        if worker is not None and worker.is_alive():
            try:
                client.close()  # release the original SDK channel event on timeout
            except BaseException as error:
                cleanup = cleanup or error
            try:
                worker.join(timeout=max(0, deadline - time.monotonic()))
                if worker.is_alive():
                    cleanup = cleanup or BootstrapAuthError("native call termination UNKNOWN")
            except BaseException as error:
                cleanup = cleanup or error
        if cleanup is not None:
            hold = BootstrapAuthError("direct native read cleanup is unconfirmed")
            hold.__cause__ = cleanup
            if primary is not None:
                raise primary from hold
            raise hold from cleanup


def observe_project_direct_bootstrap_authentication(
    project: Path, address: str, known_hosts: Path, expected_known_hosts_sha256: str,
    *, connected_stream_boundary=None, new_password: str, default_password: str,
    timeout: float, phase: str = "bootstrap",
) -> BootstrapAuthenticationObservation:
    """Own a direct pinned client; observe its post-auth MAC/IP without a lease.

    The connected-stream boundary is a controlled local transport prerequisite,
    not deployment approval. It must perform connection establishment only.
    Neither a caller identity record nor synthetic runner is accepted here.
    No key is presumed installed on the factory UFM, no password is changed,
    and even successful authentication remains HOLD, not stage completion.
    """
    stream = client = None
    started = time.monotonic()
    try:
        if ((connected_stream_boundary is not None and not callable(connected_stream_boundary))
                or type(phase) is not str or phase not in {"bootstrap", "configured"}
                or type(timeout) not in {float, int} or not math.isfinite(timeout)
                or not 0 < timeout <= 1200
                or type(new_password) is not str or not new_password
                or type(default_password) is not str or not default_password
                or new_password == default_password
                or type(expected_known_hosts_sha256) is not str
                or not re.fullmatch(r"[0-9a-f]{64}", expected_known_hosts_sha256)):
            raise BootstrapAuthError("direct bootstrap inputs are incomplete")
        if type(address) is not str or str(ipaddress.IPv4Address(address)) != address:
            raise BootstrapAuthError("direct bootstrap requires canonical CSV IPv4")
        nodes, interface, sources = binding._project_inputs(Path(project))
        selected = [node for node in nodes if node.address == address]
        if len(selected) != 1:
            raise BootstrapAuthError("direct bootstrap address is not an exact project member")
        known = binding._read_regular_no_follow(known_hosts, limit=256 * 1024, private=True)
        if hashlib.sha256(known).hexdigest() != expected_known_hosts_sha256:
            raise BootstrapAuthError("independent direct host pin is missing or changed")
        pinned = _host_key(known, address)
        sdk_identity = _direct_sdk_identity()
        deadline = started + float(timeout)
        work_deadline = deadline - min(0.25, float(timeout) / 5)
        session_id = None
        def guard():
            if (time.monotonic() >= work_deadline
                    or not binding._project_sources_still_bound(sources)
                    or binding._read_regular_no_follow(known_hosts, limit=256 * 1024,
                                                       private=True) != known
                    or _direct_sdk_identity() != sdk_identity):
                raise BootstrapAuthError("direct original source or deadline changed")
            if client is not None and session_id is not None:
                if (not client.is_active() or not client.initial_kex_done
                        or client.session_id != session_id
                        or client.get_remote_server_key() != pinned):
                    raise BootstrapAuthError("direct signed pinned session changed")
        guard()
        try:
            stream = (_direct_ipv4_connected_stream(address,
                        max(0.001, work_deadline - time.monotonic()))
                      if connected_stream_boundary is None
                      else connected_stream_boundary(address, 22))
        except OSError as error:
            if isinstance(error, TimeoutError) or error.errno in {errno.ECONNREFUSED, errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ETIMEDOUT}:
                raise DirectConnectionUnreachable("direct connection is explicitly unreachable") from None
            raise
        if (isinstance(stream, (str, tuple, paramiko.Transport))
                or not all(callable(getattr(stream, name, None))
                           for name in ("recv", "send", "settimeout", "close"))):
            # Do not adopt or close a caller's pre-existing Transport.
            stream = None
            raise BootstrapAuthError("direct fresh connected stream is absent")
        guard()
        client = paramiko.Transport(stream)
        if (type(client) is not paramiko.Transport or client.server_mode
                or client.auth_handler is not None or client.is_authenticated()):
            raise BootstrapAuthError("direct fresh SDK client is unproved")
        client.start_client(timeout=max(0.001, work_deadline - time.monotonic()))
        session_id = client.session_id
        if type(session_id) is not bytes or not session_id:
            raise BootstrapAuthError("direct signed KEX session is absent")
        guard()  # signed server key BEFORE either supplied credential
        reply = _attempt(client, "admin", new_password, max(0.001, work_deadline - time.monotonic()))
        guard()
        rejected = 0
        if reply == "rejected":
            rejected = 1
            guard()
            reply = _attempt(client, "admin", default_password, max(0.001, work_deadline - time.monotonic()))
            guard()
        if reply != "authenticated" or not client.is_authenticated():
            raise BootstrapAuthError("direct credential result is unknown or rejected")
        def read(argv):
            # Commands originate only in the shared fixed stage parser.
            command = " ".join(argv)
            return _direct_owned_read(client, command, guard, work_deadline, deadline)
        observed = binding._observe_direct_phase(selected[0], interface, phase,
            dt.datetime.now(dt.timezone.utc), expected_known_hosts_sha256, read)
        guard()
        return BootstrapAuthenticationObservation(observed.hostname, address,
            "DEFAULT_AUTHENTICATED_CHANGE_REQUIRED" if rejected else "NEW_AUTHENTICATED", rejected)
    except DirectConnectionUnreachable:
        raise
    except Exception:
        raise BootstrapAuthError("direct bootstrap authentication is HOLD") from None
    finally:
        primary = sys.exc_info()[1]
        cleanup = None
        if client is not None:
            for close in (client.close, lambda: client.join(timeout=min(1.0, max(0, deadline - time.monotonic())))):
                try:
                    close()
                except BaseException as error:
                    cleanup = cleanup or error
            try:
                if client.is_alive():
                    cleanup = cleanup or BootstrapAuthError("direct SDK client termination UNKNOWN")
            except BaseException as error:
                cleanup = cleanup or error
        if stream is not None:
            try:
                stream.close()
            except BaseException as error:
                cleanup = cleanup or error
        if cleanup is not None:
            hold = BootstrapAuthError("direct bootstrap cleanup is unconfirmed")
            hold.__cause__ = cleanup
            if primary is not None:
                raise primary from hold
            raise hold from cleanup


def establish_project_direct_management_key_access(
    project: Path, address: str, known_hosts: Path, expected_known_hosts_sha256: str,
    management_identity: Path, *, new_password: str, default_password: str,
    timeout: float, private_logs_root: Path | None = None,
    managed_output_link: Path | None = None,
):
    """Fixed HOME key installation, not configuration deployment or cycle GO.

    Own a new pinned password session, pull and durably retain its original
    configuration before apply, then independently reauthenticate with the
    actual current project management key. No caller session/FD/command or
    readonly observation is accepted; CHANGE_REQUIRED performs no key write.
    The current managed output alias and historical private root are mutually
    exclusive; the managed form stays bound to actual selected-project FDs.
    """
    from tools import ufm_project_key_install as keys
    return keys._establish_direct_keys(project, address, known_hosts,
        expected_known_hosts_sha256, management_identity, new_password=new_password,
        default_password=default_password, timeout=timeout,
        private_logs_root=private_logs_root, managed_output_link=managed_output_link)


def _direct_public_identity(raw):
    """Project static public-key grammar, preserving existing FIDO formats.

    Same finite one-line/type+wire contract as ssh_key_preparation.py:31–109;
    no private file read, agent, infra sample, key generation or publication.
    """
    if (type(raw) is not bytes or not 0 < len(raw) <= 65536 or not raw.endswith(b"\n")
            or b"\n" in raw[:-1] or any(c < 32 or c == 127 for c in raw[:-1])):
        raise BootstrapAuthError("project public key is not a complete bounded line")
    fields = raw[:-1].split(b" ", 2)
    if len(fields) < 2 or not fields[1]:
        raise BootstrapAuthError("project public key identity is incomplete")
    algorithm, encoded = fields[:2]
    allowed = {b"ssh-ed25519", b"ssh-rsa", b"ecdsa-sha2-nistp256", b"ecdsa-sha2-nistp384",
               b"ecdsa-sha2-nistp521", b"sk-ssh-ed25519@openssh.com", b"sk-ecdsa-sha2-nistp256@openssh.com"}
    if algorithm not in allowed:
        raise BootstrapAuthError("project public key type is unproved")
    try:
        blob = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error):
        raise BootstrapAuthError("project public key wire is unproved") from None
    if base64.b64encode(blob) != encoded:
        raise BootstrapAuthError("project public key wire is noncanonical")
    def field(offset):
        if offset + 4 > len(blob):
            raise BootstrapAuthError("project public key wire is truncated")
        size = struct.unpack_from(">I", blob, offset)[0]
        offset += 4
        if size > 65536 or offset + size > len(blob):
            raise BootstrapAuthError("project public key field is unproved")
        return blob[offset:offset + size], offset + size
    kind, offset = field(0)
    if kind != algorithm:
        raise BootstrapAuthError("project public key type differs from wire")
    if algorithm == b"ssh-ed25519":
        key, offset = field(offset)
        valid = len(key) == 32
    elif algorithm == b"ssh-rsa":
        exponent, offset = field(offset)
        modulus, offset = field(offset)
        valid = bool(exponent and modulus)
    elif algorithm.startswith(b"ecdsa-sha2-"):
        curve, offset = field(offset)
        point, offset = field(offset)
        valid = algorithm == b"ecdsa-sha2-" + curve and bool(point)
    elif algorithm == b"sk-ssh-ed25519@openssh.com":
        key, offset = field(offset)
        application, offset = field(offset)
        valid = len(key) == 32 and bool(application)
    else:
        curve, offset = field(offset)
        point, offset = field(offset)
        application, offset = field(offset)
        valid = curve == b"nistp256" and bool(point and application)
    if not valid or offset != len(blob):
        raise BootstrapAuthError("project public key wire fields are unproved")
    return algorithm, blob


def observe_project_direct_configured_management_identity(
    project: Path, address: str, known_hosts: Path, expected_known_hosts_sha256: str,
    management_identity: Path, *, timeout: float, connected_stream_boundary=None,
) -> binding.VerifiedDirectManagementIdentity:
    """Fresh key-only configured observations, never caller-record admission.

    Current project public files are actual authority for key selection, not
    deployment approval. This entry installs nothing, reads no lease, issues no
    grant and cannot authorize subsequent writes or collection by itself.
    """
    stream = client = auth = key = None
    started = time.monotonic()
    auth_confirmed = False
    try:
        if ((connected_stream_boundary is not None and not callable(connected_stream_boundary))
                or type(timeout) not in {float, int} or not math.isfinite(timeout)
                or not 0 < timeout <= 1200 or type(address) is not str
                or str(ipaddress.IPv4Address(address)) != address
                or type(expected_known_hosts_sha256) is not str
                or not re.fullmatch(r"[0-9a-f]{64}", expected_known_hosts_sha256)):
            raise BootstrapAuthError("configured direct inputs are incomplete")
        nodes, interface, sources = binding._project_inputs(Path(project))
        selected = [node for node in nodes if node.address == address]
        if len(selected) != 1:
            raise BootstrapAuthError("configured direct address is not an exact project member")
        sdk_identity = _direct_sdk_identity()
        if tuple(inspect.signature(AuthHandler.auth_publickey).parameters) != ("self", "username", "key", "event"):
            raise BootstrapAuthError("configured direct key API is unproved")
        known = binding._read_regular_no_follow(known_hosts, limit=256 * 1024, private=True)
        if hashlib.sha256(known).hexdigest() != expected_known_hosts_sha256:
            raise BootstrapAuthError("configured direct independent pin changed")
        pinned = _host_key(known, address)
        key_paths = (Path(project) / "mgmt-server.pub", Path(project) / "laptop.pub", management_identity)
        key_bytes = tuple(binding._read_regular_no_follow(path, limit=65536, private=(index == 2))
                          for index, path in enumerate(key_paths))
        management, laptop = (_direct_public_identity(raw) for raw in key_bytes[:2])
        if management == laptop:
            raise BootstrapAuthError("project management and laptop keys must be distinct")
        key = _private_key_from_bound_bytes(key_bytes[2])
        if (key.get_name().encode("ascii"), key.asbytes()) != management:
            raise BootstrapAuthError("explicit private key differs from actual project management key")
        deadline = started + float(timeout)
        work_deadline = deadline - min(0.25, float(timeout) / 5)
        session_id = None
        def guard():
            if (time.monotonic() >= work_deadline or not binding._project_sources_still_bound(sources)
                    or binding._read_regular_no_follow(known_hosts, limit=256 * 1024, private=True) != known
                    or any(binding._read_regular_no_follow(path, limit=65536, private=(index == 2)) != raw
                           for index, (path, raw) in enumerate(zip(key_paths, key_bytes)))
                    or _direct_sdk_identity() != sdk_identity):
                raise BootstrapAuthError("configured direct original source or deadline changed")
            if client is not None and session_id is not None:
                if (not client.is_active() or not client.initial_kex_done or client.session_id != session_id
                        or client.get_remote_server_key() != pinned):
                    raise BootstrapAuthError("configured direct signed session changed")
                if auth_confirmed and (client.auth_handler is not auth or auth.reply != "authenticated"
                        or auth.auth_method != "publickey" or not auth.is_authenticated()
                        or not client.is_authenticated() or client.get_username() != "admin"):
                    raise BootstrapAuthError("configured direct key-auth session changed")
        guard()
        try:
            stream = (_direct_ipv4_connected_stream(address, max(0.001, work_deadline - time.monotonic()))
                      if connected_stream_boundary is None else connected_stream_boundary(address, 22))
        except OSError as error:
            if isinstance(error, TimeoutError) or error.errno in {errno.ECONNREFUSED, errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ETIMEDOUT}:
                raise DirectConnectionUnreachable("configured direct connection is explicitly unreachable") from None
            raise
        if (isinstance(stream, (str, tuple, paramiko.Transport))
                or not all(callable(getattr(stream, name, None)) for name in ("recv", "send", "settimeout", "close"))):
            stream = None
            raise BootstrapAuthError("configured direct fresh connected stream is absent")
        guard()
        client = paramiko.Transport(stream)
        if (type(client) is not paramiko.Transport or client.server_mode
                or client.auth_handler is not None or client.is_authenticated()):
            raise BootstrapAuthError("configured direct fresh SDK client is unproved")
        client.start_client(timeout=max(0.001, work_deadline - time.monotonic()))
        session_id = client.session_id
        if type(session_id) is not bytes or not session_id:
            raise BootstrapAuthError("configured direct signed KEX is absent")
        guard()  # signed independent key BEFORE public-key authentication
        auth = _StrictKeyAuthHandler(client)
        event = threading.Event()
        with client.lock:
            client.auth_handler = auth
        try:
            auth.auth_publickey("admin", key, event)
            if (not event.wait(max(0, work_deadline - time.monotonic())) or client.get_exception() is not None
                    or auth.reply != "authenticated" or not auth.is_authenticated()):
                raise BootstrapAuthError("configured direct key authentication is unproved")
            auth_confirmed = True
            guard()
        finally:
            auth.private_key = None
            key = None
        def read(argv):
            return _direct_owned_read(client, " ".join(argv), guard, work_deadline, deadline)
        observed = binding._observe_direct_phase(selected[0], interface, "configured",
            dt.datetime.now(dt.timezone.utc), expected_known_hosts_sha256, read)
        guard()
        return observed
    except DirectConnectionUnreachable:
        raise
    except Exception:
        raise BootstrapAuthError("configured direct key identity is HOLD") from None
    finally:
        primary = sys.exc_info()[1]
        key = None
        if auth is not None:
            auth.private_key = None
        cleanup = None
        if client is not None:
            for close in (client.close, lambda: client.join(timeout=min(1.0, max(0, deadline - time.monotonic())))):
                try:
                    close()
                except BaseException as error:
                    cleanup = cleanup or error
            try:
                if client.is_alive():
                    cleanup = cleanup or BootstrapAuthError("configured direct client termination UNKNOWN")
            except BaseException as error:
                cleanup = cleanup or error
        if stream is not None:
            try:
                stream.close()
            except BaseException as error:
                cleanup = cleanup or error
        if cleanup is not None:
            hold = BootstrapAuthError("configured direct key identity cleanup is unconfirmed")
            hold.__cause__ = cleanup
            if primary is not None:
                raise primary from hold
            raise hold from cleanup


@dataclass(frozen=True)
class BootstrapAuthenticationObservation:
    hostname: str
    address: str
    authentication: str
    explicit_password_rejections: int
    state: str = "HOLD"
    stage1_complete: bool = False


class _ReplyAuthHandler(AuthHandler):
    """Per-Transport handler; no global SDK monkeypatch or message fabrication."""
    def __init__(self, transport):
        super().__init__(transport)
        self.reply = None

    def _parse_userauth_failure(self, message):
        # SDK get_boolean/get_string are intentionally permissive on truncated
        # input. Validate the complete original remaining payload first without
        # advancing its cursor; then preserve the SDK's parser/event behaviour.
        raw = message.get_remainder()
        valid = False
        if len(raw) >= 5 and self.auth_method == "password":
            width = struct.unpack(">I", raw[:4])[0]
            if width <= 2048 and len(raw) == width + 5 and raw[-1:] in {b"\x00", b"\x01"}:
                try:
                    text = raw[4:4 + width].decode("ascii")
                    methods = text.split(",") if text else []
                    valid = (bool(methods) and len(set(methods)) == len(methods)
                             and all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9@._+-]{0,127}", name)
                                     for name in methods))
                except UnicodeError:
                    valid = False
        if not valid:
            self.reply = "unknown"
            self.authenticated = False
            self.transport.saved_exception = BootstrapAuthError("authentication reply is unknown")
            if self.auth_event is not None:
                self.auth_event.set()
            return
        if raw[-1:] == b"\x01":
            self.reply = "partial"
        elif "password" not in methods:
            self.reply = "unsupported"
        else:
            self.reply = "rejected"
            self.transport.saved_exception = _ExplicitPasswordRejection("password explicitly rejected")
        super()._parse_userauth_failure(message)

    def _parse_userauth_success(self, message):
        if message.get_remainder() or self.auth_method != "password":
            self.reply = "unknown"
            self.transport.saved_exception = BootstrapAuthError("authentication reply is unknown")
            if self.auth_event is not None:
                self.auth_event.set()
            return
        self.reply = "authenticated"
        super()._parse_userauth_success(message)


def _sdk_contract():
    if (paramiko.__version__ != "5.0.0"
            or importlib.metadata.version("paramiko") != "5.0.0"
            or tuple(inspect.signature(AuthHandler.auth_password).parameters)
               != ("self", "username", "password", "event")
            or tuple(inspect.signature(AuthHandler._parse_userauth_failure).parameters)
               != ("self", "m")
            or tuple(inspect.signature(AuthHandler._parse_userauth_success).parameters)
               != ("self", "m")
            or tuple(inspect.signature(paramiko.Transport.auth_password).parameters)
               != ("self", "username", "password", "event", "fallback")):
        raise BootstrapAuthError("SSH library version or API is unverified")


def _host_key(known_bytes, address):
    keys = []
    for line in known_bytes.decode("ascii").splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) < 3:
            raise BootstrapAuthError("known_hosts entry is invalid")
        if address not in fields[0].split(","):
            continue
        if fields[1] not in {"ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384"}:
            raise BootstrapAuthError("known_hosts algorithm is unverified")
        entry = HostKeyEntry.from_line(line)
        if entry is None or entry.key is None or entry.key.get_name() != fields[1]:
            raise BootstrapAuthError("known_hosts key is invalid")
        keys.append(entry.key)
    if len(keys) != 1:
        raise BootstrapAuthError("known_hosts endpoint key is ambiguous")
    return keys[0]


def _attempt(transport, username, password, timeout):
    # The caller holds the per-Transport admission lock. The supplied Transport
    # must be exclusively owned for this observation; a replacement handler is
    # detected and cannot supply evidence for a fallback.
    if (not transport.is_active() or not transport.initial_kex_done
            or transport.is_authenticated() or transport.get_exception() is not None):
        raise BootstrapAuthError("SSH session is not an unambiguous pre-authentication session")
    event = threading.Event()
    handler = _ReplyAuthHandler(transport)
    with transport.lock:
        transport.auth_handler = handler
    try:
        handler.auth_password(username, password, event)
        if not event.wait(timeout):
            raise BootstrapAuthError("SSH authentication timed out")
        if transport.auth_handler is not handler or not transport.is_active():
            raise BootstrapAuthError("SSH authentication session changed or disconnected")
        error = transport.get_exception()
        if (handler.reply == "authenticated" and handler.is_authenticated()
                and transport.is_authenticated() and error is None):
            return "authenticated"
        if (handler.reply == "rejected" and not handler.is_authenticated()
                and not transport.is_authenticated()
                and type(error) is _ExplicitPasswordRejection):
            return "rejected"
        raise BootstrapAuthError("SSH authentication response is not an explicit password rejection")
    finally:
        # Do not retain supplied passwords in the transport's auth handler.
        handler.password = None


def observe_project_bootstrap_authentication(
    project: Path, lease_path: Path, jump: JumpEndpoint, far: BoundFarEndpoint,
    expected_known_hosts_sha256: str, transport: paramiko.Transport, *,
    new_password: str, default_password: str, timeout: float,
    clock: Callable[[], dt.datetime] = lambda: dt.datetime.now(dt.timezone.utc),
    identity_runner=None,
) -> BootstrapAuthenticationObservation:
    """Observe only; both credentials must be separately prompted in the caller.

    The caller must explicitly supply the existing, authorized identity-reader
    boundary; this adapter has no implicit SSH/subprocess runner. Existing
    key-only management identity is a prerequisite for this adapter,
    not a guessed first-contact policy. The transport itself never leaves this
    function for a different endpoint. No credential is written to argv, env,
    files or this module's logs. No password-change command is implemented.
    """
    try:
        _sdk_contract()
        if (type(transport) is not paramiko.Transport or transport.server_mode
                or not transport.is_active() or not transport.initial_kex_done
                or transport.is_authenticated() or transport.auth_handler is not None):
            raise BootstrapAuthError("SSH session is not a fresh encrypted client session")
        if (type(timeout) not in {int, float} or not math.isfinite(timeout) or timeout <= 0
                or not callable(identity_runner)
                or type(new_password) is not str or not new_password
                or type(default_password) is not str or not default_password
                or new_password == default_password):
            raise BootstrapAuthError("authentication inputs are invalid")
        if (type(far) is not BoundFarEndpoint or type(jump) is not JumpEndpoint
                or far.jump != jump or type(far.user) is not str
                or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", far.user)):
            raise BootstrapAuthError("authentication endpoint binding is invalid")
        _, _, sources = binding._project_inputs(Path(project))
        lease_bytes = binding._read_regular_no_follow(Path(lease_path), limit=32 * 1024 * 1024, private=False)
        known_bytes = binding._read_regular_no_follow(jump.known_hosts, limit=256 * 1024, private=True)
        if hashlib.sha256(known_bytes).hexdigest() != expected_known_hosts_sha256:
            raise BootstrapAuthError("known_hosts differs from the external pin")
        binding._pinned_hosts(known_bytes, jump.host, far.host)
        key = _host_key(known_bytes, far.host)
        # Verify KEX's real signed server key before either supplied password.
        if transport.get_remote_server_key() != key:
            raise BootstrapAuthError("SSH server key differs from the pinned endpoint")
        session_id = transport.session_id

        def rebind():
            if (not binding._project_sources_still_bound(sources)
                    or binding._read_regular_no_follow(Path(lease_path), limit=32 * 1024 * 1024, private=False) != lease_bytes
                    or binding._read_regular_no_follow(jump.known_hosts, limit=256 * 1024, private=True) != known_bytes
                    or not transport.is_active() or transport.session_id != session_id
                    or transport.get_remote_server_key() != key):
                raise BootstrapAuthError("authentication inputs or pinned session changed")
            identity = binding.verify_project_management_identity(
                project, lease_path, jump, far, expected_known_hosts_sha256,
                timeout=max(1, math.ceil(timeout)), now=clock(), runner=identity_runner)
            # The observation itself may have caused a source or lease change.
            if (not binding._project_sources_still_bound(sources)
                    or binding._read_regular_no_follow(Path(lease_path), limit=32 * 1024 * 1024, private=False) != lease_bytes
                    or binding._read_regular_no_follow(jump.known_hosts, limit=256 * 1024, private=True) != known_bytes
                    or not transport.is_active() or transport.session_id != session_id
                    or transport.get_remote_server_key() != key):
                raise BootstrapAuthError("authentication identity observation changed its inputs")
            return identity

        # Transport.lock belongs to the SDK and cannot be held while auth calls
        # acquire it. A distinct admission lock guards this adapter's two tries.
        with transport.lock:
            lock = getattr(transport, "_ufm_bootstrap_observation_lock", None)
            if lock is None:
                lock = threading.Lock()
                transport._ufm_bootstrap_observation_lock = lock
        if not lock.acquire(blocking=False):
            raise BootstrapAuthError("SSH authentication observation already in progress")
        try:
            if transport.auth_handler is not None or transport.is_authenticated():
                raise BootstrapAuthError("SSH session authentication was already started")
            identity = rebind()
            reply = _attempt(transport, far.user, new_password, timeout)
            identity = rebind()
            if reply == "authenticated":
                return BootstrapAuthenticationObservation(identity.hostname, identity.address,
                                                          "NEW_AUTHENTICATED", 0)
            # Only the precise handler's explicit typed rejection reaches here.
            identity = rebind()
            reply = _attempt(transport, far.user, default_password, timeout)
            identity = rebind()
            if reply != "authenticated":
                raise BootstrapAuthError("default authentication was not successful")
            return BootstrapAuthenticationObservation(identity.hostname, identity.address,
                                                      "DEFAULT_AUTHENTICATED_CHANGE_REQUIRED", 1)
        finally:
            lock.release()
    except Exception:
        if isinstance(transport, paramiko.Transport):
            transport.close()
        # Never echo SDK/SSH/YAML/CSV diagnostics that can contain customer data.
        raise BootstrapAuthError("bootstrap authentication is HOLD") from None
