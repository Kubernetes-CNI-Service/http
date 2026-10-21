#!/usr/bin/env python3
"""Shared cooldown gate for managed automatic and page Switch collection."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import fcntl
import json
import math
import os
from pathlib import Path
import stat
import tempfile
import time
from typing import Callable, Optional


HTTP_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_STATUS_DIR = HTTP_ROOT / "monitor/status"
COOLDOWN_SECONDS = 10 * 60
YAML_BACKUP_COLLECTION_KEY = "yaml-backup"
STATE_SCHEMA = 2
STATE_NAME = ".switch-collection-cooldown.json"
LOCK_NAME = ".switch-collection-cooldown.lock"
YAML_BACKUP_STATE_NAME = ".yaml-backup-cooldown.json"
YAML_BACKUP_LOCK_NAME = ".yaml-backup-cooldown.lock"
COLLECTION_KEYS_BY_SCOPE = {
    "air": ("air-ethernet",),
    "prod": ("prod-ethernet", "prod-infiniband", "prod-nvlink"),
    "all": (
        "air-ethernet", "prod-ethernet", "prod-infiniband", "prod-nvlink",
    ),
}
VALID_COLLECTION_KEYS = frozenset(
    (*COLLECTION_KEYS_BY_SCOPE["all"], YAML_BACKUP_COLLECTION_KEY)
)


class CollectionGateError(RuntimeError):
    """The shared gate could not be evaluated safely."""


class CollectionGateCancelled(CollectionGateError):
    """A caller cancelled while waiting for the shared gate."""


@dataclass(frozen=True)
class GateDecision:
    allowed: bool
    reason: str
    remaining_seconds: int = 0
    last_success_at: Optional[str] = None
    next_allowed_at: Optional[str] = None


def active_project_identity(http_root: Path = HTTP_ROOT) -> str:
    """Resolve the active project from the setup-managed inventory link."""
    inventory = http_root / "monitor/02-devices_config.csv"
    try:
        resolved = inventory.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise CollectionGateError(
            f"cannot resolve active project inventory: {inventory}: {exc}"
        ) from exc
    if not resolved.is_file():
        raise CollectionGateError(f"active inventory is not a regular file: {resolved}")
    return str(resolved.parent)


def _first_two_csv_fields(line: str) -> tuple[str, str]:
    """Parse the first two RFC-4180 fields without adding a runtime import."""
    fields: list[str] = []
    field: list[str] = []
    quoted = False
    index = 0
    while index < len(line):
        character = line[index]
        if quoted:
            if character == '"':
                if index + 1 < len(line) and line[index + 1] == '"':
                    field.append('"')
                    index += 1
                else:
                    quoted = False
            else:
                field.append(character)
        elif character == ",":
            fields.append("".join(field))
            field = []
            if len(fields) == 2:
                return fields[0], fields[1]
        elif character == '"':
            if field:
                raise CollectionGateError("invalid quote in active inventory")
            quoted = True
        else:
            field.append(character)
        index += 1
    if quoted:
        raise CollectionGateError("unterminated quote in active inventory")
    fields.append("".join(field))
    if len(fields) < 2:
        raise CollectionGateError("active inventory row lacks hostname/type fields")
    return fields[0], fields[1]


def project_inventory_targets(project: str, scope: str) -> Optional[tuple[str, ...]]:
    """Return collector-eligible inventory hostnames, excluding jump transports.

    ``None`` is reserved for synthetic/test identities whose inventory is not
    present.  A real active project is resolved through
    :func:`active_project_identity`, so a present but malformed inventory must
    still fail closed.
    """
    allowed = {
        "air": frozenset(("air",)),
        "prod": frozenset(("eth", "eth_spx", "spx", "ib", "nvl")),
        "all": frozenset(("air", "eth", "eth_spx", "spx", "ib", "nvl")),
    }
    try:
        accepted = allowed[scope]
    except KeyError as exc:
        raise CollectionGateError(f"invalid collection scope: {scope}") from exc
    inventory = Path(project) / "02-devices_config.csv"
    if not inventory.is_file():
        return None
    try:
        lines = inventory.read_text(encoding="utf-8-sig", errors="strict").splitlines()
        if not lines:
            raise CollectionGateError(f"active inventory is empty: {inventory}")
        header = tuple(
            value.strip().casefold() for value in _first_two_csv_fields(lines[0])
        )
        if header != ("hostname", "type"):
            raise CollectionGateError(
                f"active inventory must begin with hostname,type: {inventory}"
            )
        targets = []
        for line in lines[1:]:
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            hostname, device_type = _first_two_csv_fields(line)
            hostname = hostname.strip()
            device_type = device_type.strip().casefold()
            if hostname and not hostname.startswith("#") and device_type in accepted:
                targets.append(hostname)
    except CollectionGateError:
        raise
    except (OSError, UnicodeError) as exc:
        raise CollectionGateError(f"cannot read active inventory: {inventory}: {exc}") from exc
    return tuple(dict.fromkeys(targets))


def _iso_at(epoch: float) -> str:
    try:
        value = float(epoch)
        if not math.isfinite(value):
            raise ValueError("timestamp is not finite")
        return (
            datetime.fromtimestamp(value).astimezone()
            .isoformat(timespec="seconds")
        )
    except (OSError, OverflowError, ValueError) as exc:
        raise CollectionGateError(
            f"invalid collection timestamp epoch: {epoch!r}"
        ) from exc


def collection_keys_for_scope(scope: str) -> tuple[str, ...]:
    """Return the fixed collection domains covered by a page/manual scope."""
    try:
        return COLLECTION_KEYS_BY_SCOPE[scope]
    except KeyError as exc:
        raise CollectionGateError(f"invalid collection scope: {scope}") from exc


def _read_state(path: Path) -> Optional[dict]:
    descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > 64 * 1024
        ):
            raise CollectionGateError(f"invalid cooldown state file: {path}")
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            descriptor = -1
            payload = json.load(stream)
    except FileNotFoundError:
        return None
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise CollectionGateError(f"cannot read cooldown state {path}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    # Schema 1 stored one project-wide timestamp.  It cannot be mapped to the
    # four independent collection domains without guessing, so ignore it and
    # let the next collection rebuild trustworthy schema-2 state.
    if isinstance(payload, dict) and payload.get("schema_version") == 1:
        return None
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != STATE_SCHEMA
        or not isinstance(payload.get("project"), str)
        or not isinstance(payload.get("successes"), dict)
    ):
        raise CollectionGateError(f"invalid cooldown state schema: {path}")
    successes = payload["successes"]
    if any(key not in VALID_COLLECTION_KEYS for key in successes):
        raise CollectionGateError(f"invalid cooldown state collection key: {path}")
    for key, record in successes.items():
        raw_epoch = record.get("successful_epoch") if isinstance(record, dict) else None
        if (
            not isinstance(record, dict)
            or isinstance(raw_epoch, bool)
            or not isinstance(raw_epoch, (int, float))
            or not math.isfinite(float(raw_epoch))
            or not isinstance(record.get("successful_at"), str)
            or len(record["successful_at"]) > 128
        ):
            raise CollectionGateError(
                f"invalid cooldown state record for {key}: {path}"
            )
        try:
            _iso_at(float(raw_epoch))
        except CollectionGateError as exc:
            raise CollectionGateError(
                f"invalid cooldown state record for {key}: {path}"
            ) from exc
    return payload


def _write_state(path: Path, payload: dict) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix="." + path.name.removeprefix(".") + ".", dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


class CollectionGate:
    """Serialize one collection lane while cooling down its domains independently."""

    def __init__(
        self,
        project: str,
        scope: str,
        *,
        collection_keys: Optional[tuple[str, ...]] = None,
        enforce_cooldown: bool = True,
        status_dir: Path = DEFAULT_STATUS_DIR,
        cooldown_seconds: int = COOLDOWN_SECONDS,
        clock: Callable[[], float] = time.time,
        lock_wait_seconds: float = 0.0,
        cancel_check: Optional[Callable[[], bool]] = None,
        wait_callback: Optional[Callable[[GateDecision], None]] = None,
        sleeper: Callable[[float], None] = time.sleep,
        poll_seconds: float = 1.0,
        monotonic: Callable[[], float] = time.monotonic,
        lane: Optional[str] = None,
    ) -> None:
        if not project:
            raise CollectionGateError("collection project identity is empty")
        scope_keys = collection_keys_for_scope(scope)
        if cooldown_seconds < 0:
            raise CollectionGateError("collection cooldown cannot be negative")
        requested_keys = scope_keys if collection_keys is None else collection_keys
        selected = tuple(dict.fromkeys(requested_keys))
        regular_selection = bool(selected) and all(key in scope_keys for key in selected)
        yaml_backup_selection = selected == (YAML_BACKUP_COLLECTION_KEY,)
        if not (regular_selection or yaml_backup_selection):
            raise CollectionGateError(
                f"invalid collection keys for scope {scope}: {selected}"
            )
        self.project = project
        self.scope = scope
        self.collection_keys = selected
        inferred_lane = "backup" if yaml_backup_selection else "collection"
        self.lane = inferred_lane if lane is None else lane
        if self.lane not in {"collection", "backup"}:
            raise CollectionGateError(f"invalid collection gate lane: {self.lane}")
        if self.lane != inferred_lane:
            raise CollectionGateError(
                f"collection keys {selected} do not belong to {self.lane} lane"
            )
        self.state_name = (
            YAML_BACKUP_STATE_NAME if self.lane == "backup" else STATE_NAME
        )
        self.lock_name = (
            YAML_BACKUP_LOCK_NAME if self.lane == "backup" else LOCK_NAME
        )
        self.enforce_cooldown = bool(enforce_cooldown)
        self.status_dir = Path(status_dir)
        self.cooldown_seconds = int(cooldown_seconds)
        self.clock = clock
        try:
            self.lock_wait_seconds = float(lock_wait_seconds)
            self.poll_seconds = float(poll_seconds)
        except (TypeError, ValueError) as exc:
            raise CollectionGateError("invalid collection gate wait interval") from exc
        if (
            not math.isfinite(self.lock_wait_seconds)
            or self.lock_wait_seconds < 0
            or not math.isfinite(self.poll_seconds)
            or self.poll_seconds <= 0
        ):
            raise CollectionGateError("invalid collection gate wait interval")
        self.cancel_check = cancel_check
        self.wait_callback = wait_callback
        self.sleeper = sleeper
        self.poll_seconds = max(self.poll_seconds, 0.05)
        self.monotonic = monotonic
        self._lock_fd = -1
        self.decision = GateDecision(False, "not_entered")

    def _check_cancelled(self) -> None:
        if self.cancel_check is not None and self.cancel_check():
            raise CollectionGateCancelled("collection gate wait was cancelled")

    def _announce_wait(self) -> None:
        if self.wait_callback is not None:
            self.wait_callback(self.decision)

    def __enter__(self) -> "CollectionGate":
        lock_path = self.status_dir / self.lock_name
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            self.status_dir.mkdir(parents=True, exist_ok=True)
            self._lock_fd = os.open(lock_path, flags, 0o600)
            metadata = os.fstat(self._lock_fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise CollectionGateError(f"invalid collection gate lock: {lock_path}")
            os.fchmod(self._lock_fd, 0o600)
            wait_deadline = float(self.monotonic()) + self.lock_wait_seconds
            while True:
                try:
                    fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    now = float(self.monotonic())
                    wait_remaining = max(0.0, wait_deadline - now)
                    self.decision = GateDecision(
                        False, "busy", int(math.ceil(wait_remaining)),
                    )
                    if self.lock_wait_seconds <= 0 or wait_remaining <= 0:
                        os.close(self._lock_fd)
                        self._lock_fd = -1
                        return self
                    self._announce_wait()
                    self._check_cancelled()
                    self.sleeper(min(self.poll_seconds, wait_remaining))

            state = _read_state(self.status_dir / self.state_name)
            if state is None and self.lane == "backup":
                # Schema 2 originally stored YAML backup success beside Switch
                # collection successes.  Read that record once as a migration
                # fallback so an upgrade cannot erase an active backup cooldown.
                legacy = _read_state(self.status_dir / STATE_NAME)
                if (
                    legacy is not None
                    and YAML_BACKUP_COLLECTION_KEY in legacy["successes"]
                ):
                    state = {
                        **legacy,
                        "successes": {
                            YAML_BACKUP_COLLECTION_KEY:
                                legacy["successes"][YAML_BACKUP_COLLECTION_KEY],
                        },
                    }
            if (
                self.enforce_cooldown
                and state is not None
                and state["project"] == self.project
            ):
                now = float(self.clock())
                cooling: list[tuple[int, float, str]] = []
                for key in self.collection_keys:
                    record = state["successes"].get(key)
                    if record is None:
                        break
                    last_epoch = float(record["successful_epoch"])
                    remaining = max(
                        0,
                        int(math.ceil(
                            last_epoch + self.cooldown_seconds - now
                        )),
                    )
                    if remaining <= 0:
                        break
                    cooling.append((
                        remaining, last_epoch, record["successful_at"],
                    ))
                if len(cooling) == len(self.collection_keys):
                    # A multi-domain manual request is skipped only while all
                    # requested domains remain in cooldown.  Cooldown is never
                    # waited under the global lock; callers receive the skip
                    # immediately and can decide when to request another run.
                    remaining, last_epoch, successful_at = min(
                        cooling, key=lambda item: item[0],
                    )
                    self.decision = GateDecision(
                        False,
                        "cooldown",
                        remaining,
                        successful_at,
                        _iso_at(last_epoch + self.cooldown_seconds),
                    )
                    return self
            self.decision = GateDecision(True, "allowed")
            return self
        except OSError as exc:
            if self._lock_fd >= 0:
                try:
                    os.close(self._lock_fd)
                except OSError:
                    pass
                self._lock_fd = -1
            raise CollectionGateError(
                f"cannot acquire collection gate {lock_path}: {exc}"
            ) from exc
        except Exception:
            if self._lock_fd >= 0:
                try:
                    os.close(self._lock_fd)
                except OSError:
                    pass
                self._lock_fd = -1
            raise

    def mark_success(self) -> str:
        if self._lock_fd < 0 or not self.decision.allowed:
            raise CollectionGateError("cannot commit a collection without an active gate")
        try:
            epoch = float(self.clock())
            successful_at = _iso_at(epoch)
            state_path = self.status_dir / self.state_name
            state = _read_state(state_path)
            if state is None and self.lane == "backup":
                legacy = _read_state(self.status_dir / STATE_NAME)
                if (
                    legacy is not None
                    and YAML_BACKUP_COLLECTION_KEY in legacy["successes"]
                ):
                    state = {
                        **legacy,
                        "successes": {
                            YAML_BACKUP_COLLECTION_KEY:
                                legacy["successes"][YAML_BACKUP_COLLECTION_KEY],
                        },
                    }
            successes = {}
            if state is not None and state["project"] == self.project:
                successes.update(state["successes"])
            for key in self.collection_keys:
                successes[key] = {
                    "successful_epoch": epoch,
                    "successful_at": successful_at,
                }
            _write_state(
                state_path,
                {
                    "schema_version": STATE_SCHEMA,
                    "project": self.project,
                    "successes": successes,
                    "cooldown_seconds": self.cooldown_seconds,
                },
            )
            return successful_at
        except CollectionGateError:
            raise
        except OSError as exc:
            raise CollectionGateError(
                f"cannot write collection gate state: {exc}"
            ) from exc

    def __exit__(self, _type, _value, _traceback) -> None:
        if self._lock_fd >= 0:
            release_error = None
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            except OSError as exc:
                release_error = exc
            finally:
                try:
                    os.close(self._lock_fd)
                except OSError as exc:
                    release_error = release_error or exc
                self._lock_fd = -1
            if release_error is not None and _value is None:
                raise CollectionGateError(
                    f"cannot release collection gate: {release_error}"
                ) from release_error

# Distinct completed-evidence serialization; never collection admission.
from contextlib import contextmanager as _completed_read_contextmanager
import hashlib as _completed_read_hashlib
import threading as _completed_read_threading


class CompletedSourceReadHold(CollectionGateError):
    """Existing completed-source originals cannot be borrowed safely."""


_COMPLETED_SOURCE_READ_LEASES = {}


def _completed_read_identity(info, *, directory=False):
    fixed = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
    return fixed if directory else fixed + (
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _completed_read_registered(lease):
    if type(lease) is not _CompletedSourceReadLease:
        raise CompletedSourceReadHold('completed-source lease is not original')
    record = _COMPLETED_SOURCE_READ_LEASES.get(getattr(lease, '_registration', None))
    if (record is None or record['lease'] is not lease
            or record['execution'] != (os.getpid(), _completed_read_threading.get_ident())
            or record['failure'] is not None):
        raise CompletedSourceReadHold('completed-source lease is unavailable')
    return record


def _completed_read_field(lease, key):
    return _completed_read_registered(lease)['fields'][key]


class _CompletedSourceReadLease:
    __slots__ = ('_registration',)

    def __init__(self, registration):
        object.__setattr__(self, '_registration', registration)

    def __setattr__(self, name, value):
        raise AttributeError('completed-source lease bindings are immutable')

    def __copy__(self):
        # A copied shell is deliberately distinct and is NEVER registered.
        return _CompletedSourceReadLease(self._registration)

    project = property(lambda self: _completed_read_field(self, 'project'))
    scope = property(lambda self: _completed_read_field(self, 'scope'))
    status_dir = property(lambda self: _completed_read_field(self, 'status_dir'))
    lane = property(lambda self: _completed_read_field(self, 'lane'))
    collection_keys = property(lambda self: _completed_read_field(self, 'collection_keys'))
    state_name = property(lambda self: _completed_read_field(self, 'state_name'))
    lock_name = property(lambda self: _completed_read_field(self, 'lock_name'))
    _lock_fd = property(lambda self: _completed_read_field(self, '_lock_fd'))

    def verify(self):
        record = _completed_read_registered(self)
        try:
            _completed_read_verify_record(record)
        except BaseException as error:
            record['failure'] = error
            if not isinstance(error, Exception):
                raise
            raise CompletedSourceReadHold('completed-source originals changed') from None


def _completed_read_open(record, parent, name, *, directory=False, maximum=65536):
    # Every returned original is registered against the named preimage BEFORE
    # the first fstat. No first-fstat failure may strand an unregistered FD.
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if directory:
        if not stat.S_ISDIR(before.st_mode):
            raise CompletedSourceReadHold('completed-source parent is not a directory')
    elif (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) != 0o600
            or not 0 <= before.st_size <= maximum):
        raise CompletedSourceReadHold('completed-source file is unsafe')
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    if directory:
        flags |= os.O_DIRECTORY
    fd = os.open(name, flags, dir_fd=parent)
    record['slots'].append((fd, before.st_dev, before.st_ino))
    identity = _completed_read_identity(before, directory=directory)
    if _completed_read_identity(os.fstat(fd), directory=directory) != identity:
        raise CompletedSourceReadHold('completed-source open identity changed')
    raw = None
    if not directory:
        raw = os.pread(fd, before.st_size + 1, 0)
        if len(raw) != before.st_size:
            raise CompletedSourceReadHold('completed-source read is incomplete')
    record['originals'].append((parent, name, fd, directory, identity, raw))
    return fd, raw


def _completed_read_verify_record(record):
    for parent, name, fd, directory, identity, raw in record['originals']:
        if (_completed_read_identity(os.fstat(fd), directory=directory) != identity
                or _completed_read_identity(os.stat(name, dir_fd=parent,
                    follow_symlinks=False), directory=directory) != identity):
            raise CompletedSourceReadHold('completed-source original identity differs')
        if raw is not None and os.pread(fd, len(raw) + 1, 0) != raw:
            raise CompletedSourceReadHold('completed-source original bytes differ')


def _completed_read_json(raw, project):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise CompletedSourceReadHold('duplicate completed-source state key')
            value[key] = item
        return value
    def nonfinite(_value):
        raise CompletedSourceReadHold('nonfinite completed-source state')
    payload = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                         parse_constant=nonfinite)
    if (type(payload) is not dict
            or not {'schema_version', 'project', 'successes'}.issubset(payload)
            or set(payload) - {'schema_version', 'project', 'successes', 'cooldown_seconds'}
            or type(payload['schema_version']) is not int or payload['schema_version'] != 2
            or payload['project'] != project or type(payload['successes']) is not dict
            or any(key not in VALID_COLLECTION_KEYS for key in payload['successes'])):
        raise CompletedSourceReadHold('completed-source state is not same-project schema2')
    if 'cooldown_seconds' in payload and (type(payload['cooldown_seconds']) is not int
            or payload['cooldown_seconds'] < 0):
        raise CompletedSourceReadHold('completed-source cooldown shape differs')
    for item in payload['successes'].values():
        if (type(item) is not dict or set(item) != {'successful_epoch', 'successful_at'}
                or type(item['successful_epoch']) not in (int, float)
                or not math.isfinite(item['successful_epoch'])
                or type(item['successful_at']) is not str
                or not 1 <= len(item['successful_at']) <= 128):
            raise CompletedSourceReadHold('completed-source success shape differs')
        _iso_at(item['successful_epoch'])
    if not all(key in payload['successes'] for key in COLLECTION_KEYS_BY_SCOPE['prod']):
        raise CompletedSourceReadHold('completed-source prod successes are absent')


def _require_completed_source_read_lease(lease):
    _completed_read_registered(lease)
    lease.verify()


def _completed_source_reader_layout(lease):
    """Open only this lease's fixed EXISTING completed namespace, once."""
    _require_completed_source_read_lease(lease)
    record = _completed_read_registered(lease)
    if record['layout'] is not None:
        return record['layout']
    try:
        root = record['fields']['status_dir']
        project = record['fields']['project']
        key = _completed_read_hashlib.sha256(project.encode('utf-8')).hexdigest()
        current = record['status_fd']
        for part in ('collection-cycles', key, 'prod', 'switch_collection'):
            current, _raw = _completed_read_open(record, current, part, directory=True)
        records_fd, _raw = _completed_read_open(record, current, 'records', directory=True)
        _completed_read_open(record, current, 'high-water.json')
        base = root / 'collection-cycles' / key / 'prod/switch_collection'
        layout = (root, base, base / 'records', base / 'high-water.json',
                  project, key, 'prod', 'switch_collection')
        _completed_read_verify_record(record)
        record['layout'] = layout
        return layout
    except BaseException as error:
        record['failure'] = error
        if not isinstance(error, Exception):
            raise
        raise CompletedSourceReadHold('completed-source reader namespace is unavailable') from None


def _completed_read_cleanup(record):
    errors = []
    lock_fd = record['fields']['_lock_fd']
    for fd, device, inode in reversed(record['slots']):
        try:
            current = os.fstat(fd)
            if (current.st_dev, current.st_ino) != (device, inode):
                raise CompletedSourceReadHold('completed-source close identity is unknown')
        except BaseException as error:
            errors.append(error)
            continue  # Never close an unproved reused numeric slot.
        if fd == lock_fd and record['locked']:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except BaseException as error:
                errors.append(error)
        try:
            os.close(fd)  # Exactly one attempt; do not retry an unknown close.
        except BaseException as error:
            errors.append(error)
    return errors


@_completed_read_contextmanager
def _hold_completed_source_read_lease(project, *, status_dir):
    """Serialize existing prod evidence; no collection/cooldown/send grant."""
    registration = object()
    lease = _CompletedSourceReadLease(registration)
    record = {'lease': lease, 'execution': (os.getpid(), _completed_read_threading.get_ident()),
              'failure': None, 'slots': [], 'originals': [], 'locked': False,
              'layout': None, 'fields': {'_lock_fd': -1}}
    primary = None
    body_entered = False
    try:
        if type(project) is not str or not project or len(project.encode('utf-8')) > 4096:
            raise CompletedSourceReadHold('completed-source project locator is invalid')
        path = Path(status_dir)
        for locator in (Path(project), path):
            if (not locator.is_absolute() or '..' in locator.parts
                    or '\x00' in str(locator) or len(locator.parts) > 128
                    or len(str(locator).encode('utf-8')) > 4096):
                raise CompletedSourceReadHold('completed-source locator is not fixed absolute data')
        record['fields'] = {'project': project, 'scope': 'prod', 'status_dir': path,
            'lane': 'completed-source-read', 'collection_keys': COLLECTION_KEYS_BY_SCOPE['prod'],
            'state_name': STATE_NAME, 'lock_name': LOCK_NAME, '_lock_fd': -1}
        current, _raw = _completed_read_open(record, None, '/', directory=True)
        for part in path.parts[1:]:
            current, _raw = _completed_read_open(record, current, part, directory=True)
        record['status_fd'] = current
        status = os.fstat(current)
        if status.st_uid != os.geteuid() or status.st_mode & 0o022:
            raise CompletedSourceReadHold('completed-source status owner/mode is unsafe')
        lock_fd, _raw = _completed_read_open(record, current, LOCK_NAME)
        record['fields']['_lock_fd'] = lock_fd
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        record['locked'] = True
        _state_fd, raw = _completed_read_open(record, current, STATE_NAME)
        _completed_read_json(raw, project)
        _completed_read_verify_record(record)
        _COMPLETED_SOURCE_READ_LEASES[registration] = record
        lease.verify()
        body_entered = True
        yield lease
        lease.verify()
    except BaseException as error:
        if isinstance(error, Exception) and not body_entered and not isinstance(error, CompletedSourceReadHold):
            primary = CompletedSourceReadHold('completed-source lease acquisition refused')
        else:
            primary = error
    finally:
        _COMPLETED_SOURCE_READ_LEASES.pop(registration, None)  # Revoke BEFORE IO.
        if record['failure'] is None:
            record['failure'] = primary
        errors = _completed_read_cleanup(record)
        for error in errors:
            if primary is None:
                primary = (CompletedSourceReadHold('completed-source cleanup was not confirmed')
                           if isinstance(error, Exception) else error)
            elif isinstance(primary, Exception) and not isinstance(error, Exception):
                primary = error
    if primary is not None:
        if not isinstance(primary, Exception) or body_entered or isinstance(primary, CompletedSourceReadHold):
            raise primary
        raise CompletedSourceReadHold('completed-source cleanup was not confirmed') from None
