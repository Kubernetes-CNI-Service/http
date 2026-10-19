#!/usr/bin/env python3
"""Private held-source and fresh deployment staging owner, not a write permit.

This separate scope does not adopt collection read/download owners, closed
identity records, caller channels, commands or permission dictionaries. The
only source admission is the actual current builder readonly artifact pair.
Native direct KEX/key auth and the separate fixed SFTP consumer have historical
LOCAL workflow evidence. This new default/OOB source has pure controls only;
its independent two-ended native/SFTP workflow and UFM conformance are NOT RUN.
Neither a source holder nor a live owner is execution/completion permission.
SFTP needs no remote Python/GNU/proc/sudo/bash body. OOB reuses the existing
conditional VRF relay capability; it is not assumed installed or authorized.
"""
from __future__ import annotations
import contextlib
import datetime as dt
import errno
import hashlib
import math
import os
from pathlib import Path
import re
import shlex
import stat
import sys
import threading
import time
from types import MappingProxyType

from tools import ufm_deployment_script_builder as builder
from tools import ufm_deployment_script_syntax as syntax
from tools import ufm_bootstrap_auth_adapter as auth
from tools import ufm_identity_binding as identity

class StagingOwnerHold(ValueError):
    """Source/session/cleanup unknown; never execution or upload permission."""

_ISSUED_STAGES = {}
_ISSUED_NATIVE_OWNERS = {}
_ISSUED_DEFAULT_SOURCES = {}
_ISSUANCE_LOCK = threading.RLock()

def _check_issued_stage(held):
    """Use only the genuine live factory's captured originals, not DTO methods."""
    with _ISSUANCE_LOCK:
        issued = _ISSUED_STAGES.get(id(held))
        if (type(held) is not _HeldStage or issued is None
                or issued["holder"] is not held
                or (os.getpid(), threading.get_ident()) != issued["context"]):
            raise StagingOwnerHold("deployment source has no live issuance")
    fields = issued["fields"]
    if (set(held.__dict__) != set(fields)
            or any(held.__dict__[name] is not value for name, value in fields.items())
            or _HeldStage.verify is not issued["method"]
            or _HeldStage.verify.__code__ is not issued["method_code"]
            or issued["verify"].__code__ is not issued["verify_code"]
            or (held.node.hostname, held.node.address, held.node.management_mac) != issued["node_fields"]
            or time.monotonic() >= issued["work_deadline"]):
        raise StagingOwnerHold("registered deployment source binding changed")
    try:
        # Factory-captured verifier is not fetched from mutable holder fields.
        issued["verify"]()
        for fd, expected, raw in issued["originals"]:
            before = os.fstat(fd)
            if builder._file_key(before) != expected:
                raise StagingOwnerHold("registered actual original FD changed")
            actual = os.pread(fd, builder._CAP + 1, 0)
            after = os.fstat(fd)
            if builder._file_key(after) != expected or actual != raw:
                raise StagingOwnerHold("registered actual original bytes changed")
        current = tuple(identity._read_regular_no_follow(path,
            limit=262144 if index == 0 else 65536, private=index in {0, 3})
            for index, path in enumerate(issued["key_paths"]))
        if (current != issued["key_bytes"]
                or hashlib.sha256(current[0]).hexdigest() != issued["pin"]
                or (issued["pinned"].get_name(), issued["pinned"].asbytes()) != issued["pinned_bytes"]):
            raise StagingOwnerHold("registered original key/pin identity changed")
        with _ISSUANCE_LOCK:
            if _ISSUED_STAGES.get(id(held)) is not issued:
                raise StagingOwnerHold("deployment source revoked during verification")
        return issued
    except StagingOwnerHold:
        raise
    except Exception as error:
        raise StagingOwnerHold("registered original staging source is HOLD") from error

def _raise_cleanup(primary, errors, message):
    if not errors:
        return
    hold = StagingOwnerHold(message)
    hold.cleanup_errors = tuple(errors)
    # First actual operator interruption wins over an ordinary work exception.
    # An original operator primary keeps priority over cleanup interruptions.
    operator = next((error for error in errors if not isinstance(error, Exception)), None)
    if primary is not None and not isinstance(primary, Exception):
        hold.__cause__ = next((error for error in errors if error is not primary), None)
        raise primary from hold
    if operator is not None:
        hold.__cause__ = primary or next((error for error in errors if error is not operator), None)
        raise operator from hold
    hold.__cause__ = errors[0]
    if primary is not None:
        raise primary from hold
    raise hold from errors[0]

class _NamedOriginals(syntax._OwnedFDs):
    def adopt(self, fd, *, fallback=None):
        # Named original controls admission AND cleanup. Do not adopt a first
        # fstat mismatch as owned when an acquired numeric slot was replaced.
        record = {"fd": fd, "identity": fallback, "closed": False}
        self.records.append(record)
        actual = os.fstat(fd)
        if fallback is None or (actual.st_dev, actual.st_ino) != fallback:
            raise StagingOwnerHold("held named original descriptor is unproved")
        return record, actual

class _HeldStage:
    state = "SOURCE_HELD_NOT_SESSION"
    execution_permitted = False
    completion = False
    def verify(self):
        _check_issued_stage(self)

@contextlib.contextmanager
def _held_project_stage(*, script_path, known_hosts,
        expected_known_hosts_sha256, management_identity, timeout):
    """Private fixed source admission; actual bytes remain held until exit.

    No caller project/address/node override or FD/source substitute is admitted.
    No syntax child, network, remote path, session, grant or write is issued.
    """
    originals = _NamedOriginals()
    directory = project_chain = None
    held = None
    entered = False
    deadline = time.monotonic() + float(timeout) if type(timeout) in {int, float} else 0.0
    try:
        if (type(timeout) not in {int, float} or not math.isfinite(timeout)
                or not 0 < timeout <= 10 or not isinstance(script_path, Path)
                or not script_path.is_absolute() or script_path.name != "stage.sh"
                or ".." in script_path.parts or len(script_path.parents) < 5
                or type(expected_known_hosts_sha256) is not str
                or not re.fullmatch(r"[0-9a-f]{64}", expected_known_hosts_sha256)
                or any(not isinstance(path, Path) or not path.is_absolute()
                       or ".." in path.parts for path in (known_hosts, management_identity))):
            raise StagingOwnerHold("fixed deployment staging inputs rejected")
        http = Path(builder.HTTP_ROOT)
        project = Path(builder.active_project_identity(http))
        logs = script_path.parents[4]
        if (not http.is_absolute() or http.resolve(strict=True) != http
                or project.parent != http / "DAY0-Prepare" or project.resolve(strict=True) != project
                or logs.name != "xdr-initial-setup-logs"
                or logs == http or http in logs.parents or logs == project or project in logs.parents):
            raise StagingOwnerHold("current private project/log root rejected")
        directory = builder._Directories(script_path.parent, private=True)
        for record in directory.records[-5:]:
            value = os.fstat(record["fd"])
            if value.st_uid != os.getuid() or stat.S_IMODE(value.st_mode) != 0o700:
                raise StagingOwnerHold("private staging ancestor permission rejected")
        project_chain = builder._Directories(project)
        script, manifest, metadata, binding, verify_stage = syntax._validate_held_stage(
            script_path=script_path, http=http, project=project, logs=logs,
            directory=directory, project_chain=project_chain, originals=originals, deadline=deadline)
        nodes, interface, sources = identity._project_inputs(project)
        selected = [node for node in nodes if node.hostname == binding["node"]
                    and node.address == binding["node_ipv4"]]
        if len(selected) != 1 or interface != metadata["management_interface"]:
            raise StagingOwnerHold("held stage is not exact current CSV member")
        key_paths = (known_hosts, project / "mgmt-server.pub",
                     project / "laptop.pub", management_identity)
        key_bytes = tuple(identity._read_regular_no_follow(path,
            limit=262144 if index == 0 else 65536, private=index in {0, 3})
            for index, path in enumerate(key_paths))
        if hashlib.sha256(key_bytes[0]).hexdigest() != expected_known_hosts_sha256:
            raise StagingOwnerHold("independently approved host pin differs")
        pinned = auth._host_key(key_bytes[0], selected[0].address)
        management, laptop = (auth._direct_public_identity(raw) for raw in key_bytes[1:3])
        if management == laptop:
            raise StagingOwnerHold("current project public keys must be distinct")
        private = auth._private_key_from_bound_bytes(key_bytes[3])
        try:
            if (private.get_name().encode("ascii"), private.asbytes()) != management:
                raise StagingOwnerHold("explicit private key differs from current management key")
        finally:
            private = None
        held = _HeldStage()
        held.active = True
        held.project, held.node, held.interface = project, selected[0], interface
        held.script_fd, held.script_sha256 = script["fd"], binding["script_sha256"]
        held.deadline, held.work_deadline = deadline, deadline - min(.25, float(timeout) / 5)
        held._key_paths, held._key_bytes = key_paths, key_bytes
        held._pin, held._pinned_key = expected_known_hosts_sha256, pinned
        held._sources, held._verify_stage = sources, verify_stage
        issued = {"holder": held, "fields": dict(held.__dict__),
            "method": _HeldStage.verify, "method_code": _HeldStage.verify.__code__,
            "verify": verify_stage, "verify_code": verify_stage.__code__,
            "originals": tuple((record["fd"], record["key"], record["raw"])
                               for record in (script, manifest)),
            "key_paths": key_paths, "key_bytes": key_bytes, "pin": expected_known_hosts_sha256,
            "pinned": pinned, "pinned_bytes": (pinned.get_name(), pinned.asbytes()),
            "context": (os.getpid(), threading.get_ident()),
            "node_fields": (selected[0].hostname, selected[0].address, selected[0].management_mac),
            "work_deadline": held.work_deadline, "deadline": deadline}
        with _ISSUANCE_LOCK:
            _ISSUED_STAGES[id(held)] = issued
        _check_issued_stage(held)
        entered = True
        yield held
    except StagingOwnerHold:
        raise
    except Exception as error:
        if entered:
            raise
        raise StagingOwnerHold("held deployment stage is HOLD") from error
    finally:
        primary = sys.exc_info()[1]
        cleanup = []
        if held is not None:
            # Revoke BEFORE modifying/closing any original resource.
            with _ISSUANCE_LOCK:
                _ISSUED_STAGES.pop(id(held), None)
            held.active = False
            held._key_bytes = None
        for owner in (originals, directory, project_chain):
            if owner is not None:
                try:
                    owner.close()
                except BaseException as error:
                    cleanup.append(error)
        _raise_cleanup(primary, cleanup, "held staging original cleanup UNKNOWN")

class _LiveDeploymentOwner:
    """Internal original owner only; no caller-facing command or upload API."""
    execution_permitted = False
    completion = False
    remote_upload_verified = False
    def verify(self):
        if not self._active:
            raise StagingOwnerHold("deployment owner is already closed")
        self._guard()
        current = self._fresh()
        before = self.observed
        if (current.hostname, current.address, current.management_mac, current.phase,
                current.known_hosts_sha256, current.interface) != (
                before.hostname, before.address, before.management_mac, before.phase,
                before.known_hosts_sha256, before.interface):
            raise StagingOwnerHold("live deployment hostname/MAC/IP/pin changed")
        self._guard()
        return current

def _issued_native_deployment_owner(live):
    """Only the actual original native issuer, never mutable display methods."""
    with _ISSUANCE_LOCK:
        record = _ISSUED_NATIVE_OWNERS.get(id(live))
        if (type(live) is not _LiveDeploymentOwner or record is None
                or record["owner"] is not live
                or record["context"] != (os.getpid(), threading.get_ident())):
            raise StagingOwnerHold("native staging owner has no current issuance")
    if (set(live.__dict__) != set(record["fields"])
            or any(live.__dict__[name] is not value
                   for name, value in record["fields"].items())
            or record["guard"].__code__ is not record["guard_code"]
            or record["fresh"].__code__ is not record["fresh_code"]):
        raise StagingOwnerHold("native staging owner display binding changed")
    _check_issued_stage(record["held"])
    record["guard"]()
    with _ISSUANCE_LOCK:
        if _ISSUED_NATIVE_OWNERS.get(id(live)) is not record:
            raise StagingOwnerHold("native staging owner revoked during check")
    return record

@contextlib.contextmanager
def _owned_direct_deployment_session(held):
    with auth._held_direct_sdk_sources():
        with _owned_direct_deployment_session_body(held) as live:
            yield live


@contextlib.contextmanager
def _owned_direct_deployment_session_body(held):
    """New deployment owner, NOT the collection scope or a closed observation.

    Direct IPv4 configured-key staging only. This does not recover configuration
    failure over IPv6. The separate default/OOB factory below is not an adopted
    collection scope and still needs its own actual two-ended workflow proof.
    """
    stream = client = handler = private = live = None
    confirmed = False
    entered = False
    try:
        if type(held) is not _HeldStage:
            raise StagingOwnerHold("caller record cannot substitute held deployment source")
        issued = _check_issued_stage(held)
        sdk_check = auth._direct_sdk_identity
        sdk = sdk_check()
        if tuple(auth.inspect.signature(auth.AuthHandler.auth_publickey).parameters) != (
                "self", "username", "key", "event"):
            raise StagingOwnerHold("native public-key API is unproved")
        # Native operations consume factory-captured values, not mutable
        # display fields after a successful check (no check-then-use DTO gap).
        node = issued["fields"]["node"]
        interface = issued["fields"]["interface"]
        deadline, work_deadline = issued["deadline"], issued["work_deadline"]
        pin, pinned_bytes = issued["pin"], issued["pinned_bytes"]
        private = auth._private_key_from_bound_bytes(issued["key_bytes"][3])
        session_id = None
        def guard():
            _check_issued_stage(held)
            if sdk_check() != sdk:
                raise StagingOwnerHold("original native SDK identity changed")
            if client is not None and session_id is not None:
                if (not client.is_active() or not client.initial_kex_done
                        or client.session_id != session_id
                        or (client.get_remote_server_key().get_name(),
                            client.get_remote_server_key().asbytes()) != pinned_bytes):
                    raise StagingOwnerHold("actual independently pinned signed session changed")
                if confirmed and (client.auth_handler is not handler
                        or handler.reply != "authenticated" or handler.auth_method != "publickey"
                        or not handler.is_authenticated() or not client.is_authenticated()
                        or client.get_username() != "admin"):
                    raise StagingOwnerHold("actual admin key-auth owner changed")
        guard()
        # Original helper owns/conditions close any actual connect failure.
        # No address/credential fallback is performed by this deployment scope.
        try:
            stream = auth._direct_ipv4_connected_stream(
                issued["node_fields"][1], max(.001, work_deadline - time.monotonic()))
        except OSError as error:
            # Only this original helper's actual connect boundary after its
            # original successful close, within the private default parent.
            if auth._default_connection_parent_deadline.get() is not None and (
                    isinstance(error, TimeoutError) or error.errno in {
                        errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ECONNREFUSED, errno.ETIMEDOUT}):
                raise auth.DirectConnectionUnreachable("original deployment TCP is explicitly unreachable") from None
            raise
        guard()
        client = auth.paramiko.Transport(stream)
        if (type(client) is not auth.paramiko.Transport or client.server_mode
                or client.auth_handler is not None or client.is_authenticated()):
            raise StagingOwnerHold("fresh original deployment Transport is unproved")
        client.start_client(timeout=max(.001, work_deadline - time.monotonic()))
        session_id = client.session_id
        if type(session_id) is not bytes or not session_id:
            raise StagingOwnerHold("actual signed KEX is absent")
        guard()  # Actual independently approved host key BEFORE authentication.
        handler = auth._StrictKeyAuthHandler(client)
        event = threading.Event()
        with client.lock:
            client.auth_handler = handler
        try:
            handler.auth_publickey("admin", private, event)
            if (not event.wait(max(0, work_deadline - time.monotonic()))
                    or client.get_exception() is not None
                    or handler.reply != "authenticated" or not handler.is_authenticated()):
                raise StagingOwnerHold("actual deployment key authentication is unproved")
            confirmed = True
            guard()
        finally:
            handler.private_key = None
            private = None
        def read(argv):
            # Only the fixed identity consumer below supplies these vectors.
            return auth._direct_owned_read(client, shlex.join(argv), guard,
                                           work_deadline, deadline)
        def fresh():
            guard()
            actual = identity._observe_direct_phase(node, interface,
                "configured", dt.datetime.now(dt.timezone.utc), pin, read)
            guard()
            return actual
        live = _LiveDeploymentOwner()
        live._active, live._guard, live._fresh = True, guard, fresh
        live._client, live._held = client, held
        initial = fresh()
        live.observed = initial
        observed_key = (initial.hostname, initial.expected_hostname, initial.address,
            initial.management_mac, initial.phase, initial.known_hosts_sha256,
            initial.interface, initial.address_source)
        native = {"owner": live, "context": (os.getpid(), threading.get_ident()),
            "fields": dict(live.__dict__), "held": held, "client": client,
            "handler": handler, "session_id": session_id, "pinned_bytes": pinned_bytes,
            "guard": guard, "guard_code": guard.__code__,
            "fresh": fresh, "fresh_code": fresh.__code__,
            "work_deadline": work_deadline, "deadline": deadline,
            "observed_key": observed_key}
        with _ISSUANCE_LOCK:
            _ISSUED_NATIVE_OWNERS[id(live)] = native
        entered = True
        yield live
        # Tail validation is an original captured native closure, never the
        # mutable display instance's verify/_guard/_fresh/observed methods.
        final = fresh()
        if (final.hostname, final.expected_hostname, final.address,
                final.management_mac, final.phase, final.known_hosts_sha256,
                final.interface, final.address_source) != observed_key:
            raise StagingOwnerHold("original live deployment identity changed")
        guard()
    except auth.DirectConnectionUnreachable:
        raise
    except StagingOwnerHold:
        raise
    except Exception as error:
        if entered:
            raise
        raise StagingOwnerHold("fresh direct deployment owner is HOLD") from error
    finally:
        primary = sys.exc_info()[1]
        cleanup = []
        private = None
        if live is not None:
            with _ISSUANCE_LOCK:
                _ISSUED_NATIVE_OWNERS.pop(id(live), None)
            live._active = False
        if handler is not None:
            handler.private_key = None
        if client is not None:
            for operation in (client.close, lambda: client.join(timeout=max(0,
                    deadline - time.monotonic()))):
                try:
                    operation()
                except BaseException as error:
                    cleanup.append(error)
            try:
                if client.is_alive():
                    cleanup.append(StagingOwnerHold("native deployment owner termination UNKNOWN"))
            except BaseException as error:
                cleanup.append(error)
        if stream is not None:
            try:
                stream.close()
            except BaseException as error:
                cleanup.append(error)
        _raise_cleanup(primary, cleanup, "deployment owner cleanup UNKNOWN")

class _DefaultSources:
    """Opaque original holding, not a live session or deployment permission."""

def _check_default_sources(sources):
    try:
        return _verify_default_sources(sources)
    except StagingOwnerHold:
        raise
    except Exception as error:
        raise StagingOwnerHold("original default source/name/FD remains HOLD") from error

def _verify_default_sources(sources):
    record = _ISSUED_DEFAULT_SOURCES.get(id(sources))
    if (type(sources) is not _DefaultSources or record is None or record["holder"] is not sources
            or record["context"] != (os.getpid(), threading.get_ident())):
        raise StagingOwnerHold("default original sources have no current issuance")
    _check_issued_stage(record["held"])
    for directory in record["directories"]:
        directory.verify()
    for item in (*record["originals"], *record["key_originals"]):
        before = os.fstat(item["fd"])
        named = os.stat(item["name"], dir_fd=item["parent_fd"], follow_symlinks=False)
        raw = os.pread(item["fd"], item["limit"] + 1, 0)
        after = os.fstat(item["fd"])
        if (builder._file_key(before) != item["key"] or builder._file_key(named) != item["key"]
                or builder._file_key(after) != item["key"] or raw != item["raw"]):
            raise StagingOwnerHold("held actual default source/name/bytes changed")
    selection = record["selection"]
    if selection is not None:
        path, expected, name = selection
        if builder._file_key(path.lstat()) != expected or os.readlink(path) != name:
            raise StagingOwnerHold("held setup P2P selection changed")
    if _ISSUED_DEFAULT_SOURCES.get(id(sources)) is not record:
        raise StagingOwnerHold("default sources revoked during check")
    return record

def _capture_default_file(record, path, *, private=False, limit=4 * 1024 * 1024):
    directory = builder._Directories(path.parent)
    record["directories"].append(directory)
    parent_fd = directory.records[-1]["fd"]
    named = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
    if (not stat.S_ISREG(named.st_mode) or named.st_nlink != 1
            or named.st_uid not in {0, os.geteuid()} or named.st_mode & 0o022
            or private and named.st_mode & 0o077 or named.st_size > limit):
        raise StagingOwnerHold("default original is not bounded/private regular data")
    fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
    _owned, first = record["owner"].adopt(fd, fallback=(named.st_dev, named.st_ino))
    if builder._file_key(first) != builder._file_key(named):
        raise StagingOwnerHold("default named original differs from actual FD")
    raw = os.pread(fd, limit + 1, 0)
    last = os.fstat(fd)
    named_after = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
    if (builder._file_key(first) != builder._file_key(last)
            or builder._file_key(last) != builder._file_key(named_after) or len(raw) > limit):
        raise StagingOwnerHold("default original changed during FD capture")
    return MappingProxyType({"name": path.name, "path": path, "fd": fd,
        "parent_fd": parent_fd, "key": builder._file_key(last), "raw": raw,
        "sha256": hashlib.sha256(raw).hexdigest(), "limit": limit})

@contextlib.contextmanager
def _held_default_sources(held, group):
    issued = _check_issued_stage(held)
    if type(group) is not tuple or len(group) != 5 or (any(item is None for item in group) and any(item is not None for item in group)):
        raise StagingOwnerHold("OOB group must be complete or absent")
    if group[0] is not None and (type(group[0]) is not str or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", group[0])
            or any(not isinstance(group[index], Path) or not group[index].is_absolute() or ".." in group[index].parts for index in (1, 3))
            or any(type(group[index]) is not str or not re.fullmatch(r"[0-9a-f]{64}", group[index]) for index in (2, 4))):
        raise StagingOwnerHold("fixed independent OOB input group rejected")
    source = _DefaultSources()
    record = {"holder": source, "held": held, "context": (os.getpid(), threading.get_ident()),
        "group": group, "originals": [], "key_originals": [], "directories": [],
        "owner": _NamedOriginals(), "selection": None, "target": None}
    entered = False
    try:
        project = issued["fields"]["project"]
        for name in ("01-global.yaml", "02-devices_config.csv"):
            record["originals"].append(_capture_default_file(record, project / name))
        for index, path in enumerate(issued["key_paths"]):
            item = _capture_default_file(record, path, private=index in {0, 3}, limit=262144 if index == 0 else 65536)
            if item["raw"] != issued["key_bytes"][index]:
                raise StagingOwnerHold("original staging key/pin changed")
            record["key_originals"].append(item)
        if group[0] is not None:
            for path, digest in ((group[1], group[2]), (group[3], group[4])):
                item = _capture_default_file(record, path, private=True, limit=131072)
                if item["sha256"] != digest:
                    raise StagingOwnerHold("independently approved OOB/far pin differs")
                entries = []
                for line in item["raw"].decode("ascii", "strict").splitlines():
                    if not line or line.startswith("#"):continue
                    entry = auth.HostKeyEntry.from_line(line)
                    if entry is None or entry.key is None or not entry.hostnames:
                        raise StagingOwnerHold("approved OOB pin file contains invalid key data")
                    entries.append(entry)
                if not entries:
                    raise StagingOwnerHold("approved OOB pin file has no keys")
                record["originals"].append(item)
        _ISSUED_DEFAULT_SOURCES[id(source)] = record
        _check_default_sources(source)
        entered = True
        yield source
    except StagingOwnerHold:
        raise
    except Exception as error:
        if entered:
            raise
        raise StagingOwnerHold("held default source remains HOLD") from error
    finally:
        primary = sys.exc_info()[1]
        _ISSUED_DEFAULT_SOURCES.pop(id(source), None) # revoke BEFORE any actual close
        cleanup = []
        for resource in (record["owner"], *reversed(record["directories"])):
            try:resource.close()
            except BaseException as error:cleanup.append(error)
        _raise_cleanup(primary, cleanup, "default held source cleanup UNKNOWN")

def _bind_oob_deployment_target(sources):
    record = _check_default_sources(sources)
    if record["group"][0] is None:
        raise StagingOwnerHold("unreachable direct path has no independent OOB group")
    issued = _check_issued_stage(record["held"])
    project = issued["fields"]["project"]
    if record["target"] is None:
        canonical = project / "p2p.xlsx"
        named = canonical.lstat()
        selected = canonical
        if stat.S_ISLNK(named.st_mode):
            name = os.readlink(canonical)
            if (named.st_uid not in {0, os.geteuid()} or Path(name).name != name
                    or name in {".", "..", "p2p.xlsx"} or Path(name).suffix.casefold() != ".xlsx"):
                raise StagingOwnerHold("setup P2P link is not one owned project-root XLSX")
            record["selection"] = (canonical, builder._file_key(named), name)
            selected = project / name
        item = _capture_default_file(record, selected)
        record["originals"].append(item)
        _check_default_sources(sources)
        target, actual_sources = identity._project_oob_target(project, issued["node_fields"][1])
        expected = {item["path"]: item["sha256"] for item in record["originals"]}
        for path, digest in actual_sources:
            if digest.startswith(identity._PROJECT_P2P_SELECTION):continue
            if expected.get(path) != digest:
                raise StagingOwnerHold("P2P/CSV derived target differs from held actual FD")
        if target[:2] != (issued["node_fields"][0], issued["node_fields"][2]):
            raise StagingOwnerHold("derived OOB target is not the selected UFM")
        record["target"] = target
    _check_default_sources(sources)
    return record["target"]

@contextlib.contextmanager
def _owned_default_deployment_session(held, sources):
    issued = _check_issued_stage(held)
    record = _check_default_sources(sources)
    if record["held"] is not held:
        raise StagingOwnerHold("default route source belongs to another holder")
    entered = False
    token = auth._default_connection_parent_deadline.set(issued["deadline"])
    try:
        with _owned_direct_deployment_session(held) as live:
            entered = True
            yield live
        return
    except auth.DirectConnectionUnreachable as error:
        if entered or error.__cause__ is not None or time.monotonic() >= issued["work_deadline"]:
            raise StagingOwnerHold("default deployment cannot retry an operation") from error
    except Exception as error:
        raise StagingOwnerHold("unknown/default native failure cannot change route") from error
    finally:
        auth._default_connection_parent_deadline.reset(token)
    _bind_oob_deployment_target(sources)
    with _owned_oob_deployment_session(held, sources) as live:
        yield live

@contextlib.contextmanager
def _owned_oob_deployment_session(held, sources):
    with auth._held_direct_sdk_sources():
        with _owned_oob_deployment_session_body(held, sources) as live:
            yield live


@contextlib.contextmanager
def _owned_oob_deployment_session_body(held, sources):
    """Build NEW two-ended native ownership; never adopt a collection scope."""
    import json
    import secrets
    from tools import ufm_deployment_access as access
    from tools import ufm_oob_relay as relay
    issued = _check_issued_stage(held)
    record = _check_default_sources(sources)
    target = _bind_oob_deployment_target(sources)
    hostname, wanted_mac, jump_hostname, jump_address, jump_mac, port = target
    username, _jump_path, jump_pin, _far_path, far_pin = record["group"]
    jump_raw, far_raw = record["originals"][2]["raw"], record["originals"][3]["raw"]
    jump_key = auth._host_key(jump_raw, jump_address)
    sdk_check = auth._direct_sdk_identity
    sdk = sdk_check()
    relay_source = _capture_default_file(record, Path(relay.__file__).absolute(), limit=131072)
    record["originals"].append(relay_source)
    interface = issued["fields"]["interface"]
    work_deadline, deadline = issued["work_deadline"], issued["deadline"]
    jump = far = stream = channel = carrier = private = jump_auth = far_auth = live = None
    buffer = bytearray()
    sessions = []
    jump_authenticated = far_authenticated = entered = False
    nonce = None
    try:
        def guard():
            _check_default_sources(sources)
            if sdk_check() != sdk:
                raise StagingOwnerHold("original two-ended SDK identity changed")
            for client, session, pinned in sessions:
                if (not client.is_active() or not client.initial_kex_done
                        or client.session_id != session or client.get_remote_server_key() != pinned):
                    raise StagingOwnerHold("original independently pinned signed OOB/far session changed")
            for client, handler, expected_user, authenticated in (
                    (jump, jump_auth, username, jump_authenticated),
                    (far, far_auth, "admin", far_authenticated)):
                if authenticated and (client.auth_handler is not handler or handler.reply != "authenticated"
                        or handler.auth_method != "publickey" or not handler.is_authenticated()
                        or not client.is_authenticated() or client.get_username() != expected_user):
                    raise StagingOwnerHold("actual two-ended key-auth owner changed")
        def authenticate(client, expected_user):
            nonlocal private
            private = auth._private_key_from_bound_bytes(issued["key_bytes"][3])
            handler = auth._StrictKeyAuthHandler(client)
            event = threading.Event()
            with client.lock:
                client.auth_handler = handler
            try:
                handler.auth_publickey(expected_user, private, event)
                if (not event.wait(max(0, work_deadline-time.monotonic())) or client.get_exception() is not None
                        or handler.reply != "authenticated" or not handler.is_authenticated()):
                    raise StagingOwnerHold("actual original OOB/far key authentication is unproved")
                return handler
            finally:
                handler.private_key = None
                private = None
        guard()
        stream = auth._direct_ipv4_connected_stream(jump_address, max(.001, work_deadline-time.monotonic()))
        jump = auth.paramiko.Transport(stream)
        if type(jump) is not auth.paramiko.Transport or jump.server_mode or jump.auth_handler is not None:
            raise StagingOwnerHold("fresh original OOB client is unproved")
        jump.start_client(timeout=max(.001, work_deadline-time.monotonic()))
        if type(jump.session_id) is not bytes or not jump.session_id:
            raise StagingOwnerHold("actual OOB signed KEX absent")
        sessions.append((jump, jump.session_id, jump_key))
        guard()  # independently approved jump key BEFORE credentials
        jump_auth = authenticate(jump, username)
        jump_authenticated = True
        guard()
        def jump_read(argv):
            return auth._direct_owned_read(jump, shlex.join(argv), guard, work_deadline, deadline)
        def route():
            guard()
            if jump_read(["hostname"]).strip().casefold() != jump_hostname.casefold():
                raise StagingOwnerHold("actual OOB hostname differs from held CSV/P2P")
            links = json.loads(jump_read(["ip", "-j", "link", "show"]))
            addresses = json.loads(jump_read(["ip", "-j", "address", "show"]))
            candidates = [row.get("ifname") for row in links if type(row) is dict
                and type(row.get("address")) is str and row["address"].casefold() == jump_mac]
            matches = [row for row in addresses if type(row) is dict and row.get("ifname") in candidates
                and sum(1 for entry in row.get("addr_info", []) if type(entry) is dict
                    and entry.get("family") == "inet" and entry.get("local") == jump_address) == 1]
            if len(candidates) != 1 or len(matches) != 1:
                raise StagingOwnerHold("actual OOB management MAC/IPv4 is not unique")
            ipv6, outlet, _ = identity._resolve_oob_neighbor(wanted_mac, port,
                jump_read(["ip", "-d", "link", "show"]), jump_read(["bridge", "fdb", "show"]),
                jump_read(["ip", "neighbor"]))
            vrf = identity._resolve_oob_vrf(outlet, jump_read(["ifquery", outlet]))
            if _bind_oob_deployment_target(sources) != target:
                raise StagingOwnerHold("held selected target changed during discovery")
            guard()
            return ipv6, outlet, vrf
        ipv6, outlet, vrf = route()
        # No caller alias. The only lookup is this selected UFM's MAC-derived
        # actual unique neighbor+outlet, followed by actual hostname/MAC reads.
        far_key = auth._host_key(far_raw, ipv6+"%"+outlet)
        guard()
        nonce = secrets.token_hex(16)
        command = shlex.join(relay.command_argv(relay_source["raw"].decode("utf-8"),
            nonce, ipv6, outlet, vrf, work_deadline-time.monotonic()))
        channel = access._native_relay_open(jump, command, guard, work_deadline, deadline)
        relay.decode_ready(access._control_line(channel, buffer, work_deadline, guard), nonce, ipv6, outlet, vrf)
        carrier = access._RelayStream(channel)
        far = auth.paramiko.Transport(carrier)
        if type(far) is not auth.paramiko.Transport or far.server_mode or far.auth_handler is not None:
            raise StagingOwnerHold("fresh original far client is unproved")
        far.start_client(timeout=max(.001, work_deadline-time.monotonic()))
        if type(far.session_id) is not bytes or not far.session_id:
            raise StagingOwnerHold("actual far signed KEX absent")
        sessions.append((far, far.session_id, far_key))
        guard()  # exact derived far independent pin BEFORE admin key-auth
        far_auth = authenticate(far, "admin")
        far_authenticated = True
        guard()
        def far_read(argv):
            return auth._direct_owned_read(far, shlex.join(argv), guard, work_deadline, deadline)
        def fresh():
            if route() != (ipv6, outlet, vrf):
                raise StagingOwnerHold("actual same-MAC neighbor/outlet/VRF changed")
            current = identity._observe_oob_collection_phase(target, interface, dt.datetime.now(dt.timezone.utc),
                far_pin, jump_pin, ipv6, outlet, vrf, issued["node_fields"][1], far_read)
            guard()
            return current
        def observed_key(current):
            return (current.hostname, current.expected_hostname, current.address, current.declared_ipv4,
                current.management_mac, current.known_hosts_sha256, current.jump_known_hosts_sha256,
                current.jump_hostname, current.jump_address, current.jump_mac, current.outlet,
                current.vrf, current.interface, current.phase, current.address_source)
        initial = fresh()
        live = _LiveDeploymentOwner()
        live._active, live._guard, live._fresh = True, guard, fresh
        live._client, live._held, live.observed = far, held, initial
        before = observed_key(initial)
        native = {"owner": live, "context": (os.getpid(), threading.get_ident()),
            "fields": dict(live.__dict__), "held": held, "client": far, "handler": far_auth,
            "session_id": far.session_id, "pinned_bytes": (far_key.get_name(), far_key.asbytes()),
            "guard": guard, "guard_code": guard.__code__, "fresh": fresh, "fresh_code": fresh.__code__,
            "work_deadline": work_deadline, "deadline": deadline, "observed_key": before}
        with _ISSUANCE_LOCK:
            _ISSUED_NATIVE_OWNERS[id(live)] = native
        entered = True
        yield live
        if observed_key(fresh()) != before:
            raise StagingOwnerHold("original OOB/far configured identity changed")
        guard()
    except StagingOwnerHold:
        raise
    except Exception as error:
        if entered:
            raise
        raise StagingOwnerHold("fresh two-ended deployment owner remains HOLD") from error
    finally:
        primary = sys.exc_info()[1]
        cleanup = []
        private = None
        if live is not None:
            with _ISSUANCE_LOCK:
                _ISSUED_NATIVE_OWNERS.pop(id(live), None)
            live._active = False
        for handler in (far_auth, jump_auth):
            if handler is not None:handler.private_key = None
        # Far close first; original relay DONE/EOF next; OOB close last.
        if far is not None:
            for operation in (far.close, lambda: far.join(timeout=max(0, deadline-time.monotonic()))):
                try:operation()
                except BaseException as error:cleanup.append(error)
            try:
                if far.is_alive():cleanup.append(StagingOwnerHold("far termination UNKNOWN"))
            except BaseException as error:cleanup.append(error)
        if carrier is not None:
            try:carrier.close()
            except BaseException as error:cleanup.append(error)
        if channel is not None:
            try:access._relay_finished(channel, buffer, nonce, deadline)
            except BaseException as error:cleanup.append(error)
            try:channel.close()
            except BaseException as error:cleanup.append(error)
        if jump is not None:
            for operation in (jump.close, lambda: jump.join(timeout=max(0, deadline-time.monotonic()))):
                try:operation()
                except BaseException as error:cleanup.append(error)
            try:
                if jump.is_alive():cleanup.append(StagingOwnerHold("OOB termination UNKNOWN"))
            except BaseException as error:cleanup.append(error)
        if stream is not None:
            try:stream.close()
            except BaseException as error:cleanup.append(error)
        _raise_cleanup(primary, cleanup, "two-ended deployment owner cleanup UNKNOWN")
