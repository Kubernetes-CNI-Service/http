"""Fail-closed local C-25 settings-event store, not an authenticated relay.

The caller must still supply a trusted actor, and publication / audit delivery
remain blocked until the relay, durable COMPLETE proof, and allocation journal
are implemented.  This module never opens a network connection or sends audit.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
import uuid

from monitor.issue_tracker_k_chain import (
    KChainHoldError, _actor, _canonical_line, _parse, _positive_int,
    _request_id, _revision, _time, validate_k_chain_snapshot,
)


_EVENT_NAME = re.compile(r"(?:0|[1-9][0-9]*)\.json\Z")
_OUTBOX_KEYS = {"schema_version", "revision", "event_sha256"}
_MAX_DOC_BYTES = 16 * 1024


@dataclass(frozen=True)
class KStoreReceipt:
    revision: int
    k: int
    event_sha256: str
    replay: bool = False


def _flags(directory=False):
    required = ("O_NOFOLLOW", "O_CLOEXEC") + (("O_DIRECTORY",) if directory else ())
    if any(not hasattr(os, name) for name in required):
        raise KChainHoldError("no-follow settings I/O unavailable")
    return (os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
            | getattr(os, "O_NONBLOCK", 0)
            | (os.O_DIRECTORY if directory else 0))


def _private(descriptor, directory):
    info = os.fstat(descriptor)
    if ((not stat.S_ISDIR(info.st_mode) if directory else not stat.S_ISREG(info.st_mode))
            or info.st_uid != os.getuid() or info.st_mode & 0o077
            or (not directory and info.st_nlink != 1)):
        raise KChainHoldError("settings path is not private regular authority")
    return info


def _safe_parent(descriptor):
    info = os.fstat(descriptor)
    # A normal project directory may be 0755, but must not be writable by
    # anyone except the same owner that creates its private .tracker child.
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o022):
        raise KChainHoldError("tracker parent is not owner-controlled")


def _open_dir(parent, name):
    descriptor = os.open(name, _flags(directory=True), dir_fd=parent)
    try:
        _private(descriptor, True)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _mkdir(parent, name):
    os.mkdir(name, 0o700, dir_fd=parent)
    os.fsync(parent)
    descriptor = _open_dir(parent, name)
    os.fsync(descriptor)
    return descriptor


def _read(parent, name):
    descriptor = os.open(name, _flags(), dir_fd=parent)
    try:
        info = _private(descriptor, False)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino):
            raise KChainHoldError("settings path changed during read")
        if info.st_size > _MAX_DOC_BYTES:
            raise KChainHoldError("settings document too large")
        result = bytearray()
        while len(result) <= _MAX_DOC_BYTES:
            chunk = os.read(descriptor, min(4096, _MAX_DOC_BYTES + 1 - len(result)))
            if not chunk:
                break
            result.extend(chunk)
        if len(result) != info.st_size or len(result) > _MAX_DOC_BYTES:
            raise KChainHoldError("settings document changed during read")
        return bytes(result)
    finally:
        os.close(descriptor)


def _write_temp(parent, raw):
    if not isinstance(raw, bytes) or len(raw) > _MAX_DOC_BYTES:
        raise KChainHoldError("invalid settings write")
    name = ".pending-" + uuid.uuid4().hex
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise KChainHoldError("settings short write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return name


def _install_immutable(parent, name, raw):
    temporary = _write_temp(parent, raw)
    # link(2) fails if an event/projection already exists; rename would replace it.
    os.link(temporary, name, src_dir_fd=parent, dst_dir_fd=parent,
            follow_symlinks=False)
    os.fsync(parent)  # The immutable name is the commit point only after this barrier.
    os.unlink(temporary, dir_fd=parent)
    os.fsync(parent)


def _replace_current(parent, raw):
    temporary = _write_temp(parent, raw)
    os.replace(temporary, "current", src_dir_fd=parent, dst_dir_fd=parent)
    os.fsync(parent)


def _root_path(root):
    try:
        path = Path(root)
    except (TypeError, ValueError) as exc:
        raise KChainHoldError("expected absolute .tracker state root") from exc
    if (not path.is_absolute() or path.name != ".tracker"
            or ".." in path.parts):
        raise KChainHoldError("expected absolute .tracker state root")
    return path


def _open_parent_without_symlinks(path):
    """Pin every ancestor by openat; O_NOFOLLOW on only the final parent is insufficient."""
    descriptor = os.open(os.sep, _flags(directory=True))
    try:
        for component in path.parts[1:]:
            if component in ("", ".", ".."):
                raise KChainHoldError("unsafe settings ancestor component")
            next_descriptor = os.open(component, _flags(directory=True),
                                      dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


@contextmanager
def _locked_root(root, *, create=False, token=None):
    path = _root_path(root)
    if token is not None:
        # The unified Stage-L caller already owns this exact .tracker/LOCK.
        # Re-opening and flocking it would create a second lock acquisition,
        # rather than prove ownership of the C-6 ACTIVE capability.
        from monitor.issue_tracker_local_commit import _owner

        try:
            owner = _owner(token)
            if path != owner.project / ".tracker":
                raise KChainHoldError("settings root differs from ACTIVE owner")
            _private(owner.root_fd, True)
            yield owner.root_fd
        except (OSError, TypeError, ValueError) as exc:
            if isinstance(exc, KChainHoldError):
                raise
            raise KChainHoldError("settings ACTIVE owner is invalid") from exc
        return
    parent = None
    root_fd = None
    lock_fd = None
    lock_held = False
    try:
        parent = _open_parent_without_symlinks(path.parent)
        _safe_parent(parent)
        if create:
            root_fd = _mkdir(parent, path.name)
            lock_fd = os.open("LOCK", os.O_RDWR | os.O_CREAT | os.O_EXCL
                              | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=root_fd)
            os.fsync(lock_fd)
            os.fsync(root_fd)
        else:
            root_fd = _open_dir(parent, path.name)
            lock_fd = os.open("LOCK", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
                              | getattr(os, "O_NONBLOCK", 0),
                              dir_fd=root_fd)
        _private(lock_fd, False)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        lock_held = True
        named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        pinned = os.fstat(root_fd)
        if (named.st_dev, named.st_ino) != (pinned.st_dev, pinned.st_ino):
            raise KChainHoldError("tracker root moved during lock acquisition")
        yield root_fd
    except (OSError, ValueError, TypeError) as exc:
        if isinstance(exc, KChainHoldError):
            raise
        raise KChainHoldError("settings filesystem/lock operation failed") from exc
    finally:
        if lock_fd is not None:
            if lock_held:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
        if root_fd is not None:
            os.close(root_fd)
        if parent is not None:
            os.close(parent)


def _state(root_fd):
    settings = _open_dir(root_fd, "settings")
    events_fd = outbox_fd = None
    try:
        if set(os.listdir(settings)) != {"events", "outbox", "current"}:
            raise KChainHoldError("settings subtree has missing or unexplained files")
        events_fd = _open_dir(settings, "events")
        outbox_fd = _open_dir(settings, "outbox")
        names = os.listdir(events_fd)
        if not names or any(_EVENT_NAME.fullmatch(name) is None for name in names):
            raise KChainHoldError("settings event tail is missing or unexplained")
        events = {int(name[:-5]): _read(events_fd, name) for name in names}
        if len(events) != len(names):
            raise KChainHoldError("duplicate settings event index")
        current = _read(settings, "current")
        initialized = _read(root_fd, "INITIALIZED")
        state = validate_k_chain_snapshot(events, current, initialized)
        expected_outbox = {f"{index}.json" for index in events}
        if set(os.listdir(outbox_fd)) != expected_outbox:
            # No COMPLETE+DELIVERED verifier exists yet, so every event must
            # retain its pending projection. Never guess that a missing one sent.
            raise KChainHoldError("settings outbox projection missing or unexplained")
        for index, raw in events.items():
            projection = _parse(_read(outbox_fd, f"{index}.json"), _OUTBOX_KEYS)
            if (type(projection["schema_version"]) is not int
                    or projection["schema_version"] != 1
                    or _revision(projection["revision"]) != index
                    or projection["event_sha256"] != hashlib.sha256(raw).hexdigest()):
                raise KChainHoldError("settings outbox projection mismatch")
        return state, events
    finally:
        if outbox_fd is not None:
            os.close(outbox_fd)
        if events_fd is not None:
            os.close(events_fd)
        os.close(settings)


def read_local_k_store(root, *, token=None):
    """Read only the highest, internally complete local K chain or STOP."""
    with _locked_root(root, token=token) as root_fd:
        state, _ = _state(root_fd)
        return state


def initialize_local_k_store(root, *, initialized_at, acquisition_id, token=None):
    """Initialize a NEW private tracker root; never reinterpret deletion as first use."""
    _time(initialized_at)
    _request_id(acquisition_id)
    with _locked_root(root, create=True, token=token) as root_fd:
        settings = _mkdir(root_fd, "settings")
        try:
            events = _mkdir(settings, "events")
            outbox = _mkdir(settings, "outbox")
            try:
                payload = {"new_k": 3, "actor": "system:default",
                           "expected_revision": None, "request_id": acquisition_id}
                event = _canonical_line({
                    "schema_version": 1, "revision": 0, "type": "init",
                    "old_k": None, "new_k": 3, "actor": "system:default",
                    "recorded_at": initialized_at, "request_id": acquisition_id,
                    "payload_sha256": hashlib.sha256(_canonical_line(payload)).hexdigest(),
                    "predecessor_sha256": None,
                })
                digest = hashlib.sha256(event).hexdigest()
                _install_immutable(events, "0.json", event)
                _install_immutable(outbox, "0.json", _canonical_line({
                    "schema_version": 1, "revision": 0, "event_sha256": digest,
                }))
                _replace_current(settings, _canonical_line({
                    "schema_version": 1, "revision": 0, "event_sha256": digest,
                }))
                _install_immutable(root_fd, "INITIALIZED", _canonical_line({
                    "schema_version": 1, "event0_sha256": digest,
                    "initialized_at": initialized_at,
                }))
            finally:
                os.close(outbox)
                os.close(events)
        finally:
            os.close(settings)
        state, _ = _state(root_fd)
        return state


def apply_local_k_change(root, *, new_k, actor, recorded_at, request_id,
                         expected_revision, token=None):
    """Commit a local event before acknowledging; actor authentication is external.

    This is not a CGI/root-worker entry point. Until a trusted typed relay uses
    this API under the *shared* project lock, online publication stays blocked.
    """
    _positive_int(new_k)
    _actor(actor)
    if actor == "system:default":
        raise KChainHoldError("system default cannot issue a K change")
    _time(recorded_at)
    _request_id(request_id)
    _revision(expected_revision)
    payload = {"new_k": new_k, "actor": actor,
               "expected_revision": expected_revision, "request_id": request_id}
    payload_digest = hashlib.sha256(_canonical_line(payload)).hexdigest()
    with _locked_root(root, token=token) as root_fd:
        state, events = _state(root_fd)  # Validate the locked predecessor first.
        for revision, raw in events.items():
            row = _parse(raw, {
                "schema_version", "revision", "type", "old_k", "new_k", "actor",
                "recorded_at", "request_id", "payload_sha256", "predecessor_sha256",
            })
            if row["request_id"] == request_id:
                if row["payload_sha256"] != payload_digest or revision == 0:
                    raise KChainHoldError("settings request ID reused with different payload")
                return KStoreReceipt(revision, row["new_k"],
                                     hashlib.sha256(raw).hexdigest(), replay=True)
        if expected_revision != state.revision:
            raise KChainHoldError("stale expected settings revision")
        revision = state.revision + 1
        event = _canonical_line({
            "schema_version": 1, "revision": revision, "type": "set_k",
            "old_k": state.k, "new_k": new_k, "actor": actor,
            "recorded_at": recorded_at, "request_id": request_id,
            "payload_sha256": payload_digest,
            "predecessor_sha256": state.event_sha256,
        })
        digest = hashlib.sha256(event).hexdigest()
        settings = _open_dir(root_fd, "settings")
        try:
            events_fd = _open_dir(settings, "events")
            outbox_fd = _open_dir(settings, "outbox")
            try:
                _install_immutable(events_fd, f"{revision}.json", event)
                _install_immutable(outbox_fd, f"{revision}.json", _canonical_line({
                    "schema_version": 1, "revision": revision, "event_sha256": digest,
                }))
                _replace_current(settings, _canonical_line({
                    "schema_version": 1, "revision": revision, "event_sha256": digest,
                }))
            finally:
                os.close(outbox_fd)
                os.close(events_fd)
        finally:
            os.close(settings)
        verified, _ = _state(root_fd)
        if (verified.revision, verified.k, verified.event_sha256) != (revision, new_k, digest):
            raise KChainHoldError("settings commit verification mismatch")
        return KStoreReceipt(revision, new_k, digest)
