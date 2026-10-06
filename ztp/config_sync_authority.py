#!/usr/bin/env python3
"""Local single-writer F02 generations; not an independent rollback backend.

The held writer witness and replaceable pair detect partial replay/rollback.
Restoring all three images or their whole volume together is outside this
authority and must not be advertised as safe.
An interrupted publication leaves a persistent hold, not a previous success.
"""

from contextlib import contextmanager
from datetime import datetime
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import uuid


# v1 has ten fixed members, ASCII hostname <=253, operation ID <=512,
# generated trigger ID <=512+1+253=766, a
# uint64 dev:ino namespace, signed-64 generation and a 64-byte digest.
# The independent maximum compact JSON image is 1852 bytes; use a finite
# 2048-byte wire budget. Witness v1 is <512 bytes.
JOURNAL_MAX_BYTES = 2048
WITNESS_MAX_BYTES = 512
# Receipt v1 has 16 failed / 23 successful fixed fields. Its independent
# largest canonical image is 14331 B (1024 astral diagnostic code points,
# maximal identities and timestamps); 16 KiB bounds both canonical and
# indented writer images without truncating an input or a diagnostic.
RECEIPT_MAX_BYTES = 16384
MAX_GENERATION = 9223372036854775807
HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,252}\Z")
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9:._-]{0,511}\Z")
TRIGGER_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9:._-]{0,765}\Z")
NAMESPACE = re.compile(r"[0-9]{1,20}:[0-9]{1,20}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
SOURCES = {"manual_config_sync_cli", "manual_config_sync_web"}
JOURNAL_FIELDS = {
    "schema_version", "hostname", "generation", "operation_id", "trigger_id",
    "trigger_source", "source_identity", "state", "veto", "receipt_sha256",
}
RECEIPT_COMMON_FIELDS = {
    "schema_version", "hostname", "type", "state", "started_at",
    "command_started_at", "operation", "effective_operation", "requested_operation",
    "operation_id", "trigger_source", "trigger_id", "finished_at", "generation",
    "source_identity",
}
RECEIPT_SUCCESS_FIELDS = RECEIPT_COMMON_FIELDS | {
    "transport_ip", "interface", "action", "command_ztp_log_sha256",
    "command_ztp_complete", "batch_identity_verified", "batch_identity_verified_at",
    "live_state_sha256",
}
RECEIPT_ACTION = "nv config replace <latest-hostname.yaml>; nv config apply -y; nv config save"


class AuthorityError(ValueError):
    pass


def wire(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def receipt_digest(value):
    return hashlib.sha256(wire(value)).hexdigest()


def _members(pairs):
    value = dict(pairs)
    if len(value) != len(pairs):
        raise AuthorityError("duplicate authority member")
    return value


def _decode(raw, limit):
    if not raw or len(raw) > limit:
        raise AuthorityError("authority wire size is outside its versioned bound")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_members)
    except (ValueError, UnicodeError) as exc:
        raise AuthorityError("invalid authority JSON") from exc
    if not isinstance(value, dict):
        raise AuthorityError("authority is not a closed object")
    return value


def decode_receipt(raw):
    """Closed local completion v1; a failed receipt carries no success proof."""
    value = _decode(raw, RECEIPT_MAX_BYTES)
    success = value.get("state") == "triggered"
    fields = RECEIPT_SUCCESS_FIELDS if success else RECEIPT_COMMON_FIELDS | {"reason"}
    if (set(value) != fields or type(value["schema_version"]) is not int
            or value["schema_version"] != 1
            or value["state"] not in {"triggered", "failed"}
            or type(value["generation"]) is not int
            or not 1 <= value["generation"] <= MAX_GENERATION
            or not isinstance(value["type"], str)
            or value["type"] not in {"eth", "eth_spx", "spx", "air", "ib", "nvl"}
            or value["trigger_source"] not in SOURCES):
        raise AuthorityError("closed completion receipt schema mismatch")
    for name, pattern in (("hostname", HOST), ("operation_id", IDENTIFIER),
                          ("trigger_id", TRIGGER_IDENTIFIER), ("source_identity", NAMESPACE)):
        if not isinstance(value[name], str) or not pattern.fullmatch(value[name]):
            raise AuthorityError("invalid completion receipt identity")
    if any(int(part) > 2 ** 64 - 1 for part in value["source_identity"].split(":")):
        raise AuthorityError("completion receipt namespace exceeds uint64")
    if any(value[name] != "replace-config" for name in (
            "operation", "effective_operation", "requested_operation")):
        raise AuthorityError("completion receipt operation mismatch")

    def instant(name, *, empty=False):
        text = value[name]
        if text == "" and empty:
            return None
        if (not isinstance(text, str)
                or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?[+-][0-9]{2}:[0-9]{2}", text)):
            raise AuthorityError("invalid completion receipt timestamp")
        try:
            result = datetime.fromisoformat(text)
            if result.utcoffset() is None:
                raise ValueError("missing timezone")
            return result
        except ValueError as exc:
            raise AuthorityError("invalid completion receipt timestamp") from exc

    started = instant("started_at")
    command = instant("command_started_at", empty=not success)
    finished = instant("finished_at")
    if started > finished or (command is not None and not started <= command <= finished):
        raise AuthorityError("completion receipt execution window is inverted")
    if not success:
        if not isinstance(value["reason"], str) or len(value["reason"]) > 1024:
            raise AuthorityError("completion receipt diagnostic exceeds v1 bound")
        return value
    observed = instant("batch_identity_verified_at")
    if (value["batch_identity_verified"] is not True
            or type(value["command_ztp_complete"]) is not bool
            or not command <= observed <= finished
            or value["action"] != RECEIPT_ACTION
            or not isinstance(value["interface"], str)
            or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", value["interface"])
            or not isinstance(value["transport_ip"], str) or len(value["transport_ip"]) > 45
            or not isinstance(value["live_state_sha256"], str)
            or not DIGEST.fullmatch(value["live_state_sha256"])
            or not isinstance(value["command_ztp_log_sha256"], str)
            or (value["command_ztp_log_sha256"] and not DIGEST.fullmatch(value["command_ztp_log_sha256"]))):
        raise AuthorityError("invalid same-session completion proof")
    try:
        ipaddress.ip_address(value["transport_ip"])
    except ValueError as exc:
        raise AuthorityError("invalid completion receipt transport IP") from exc
    return value


def decode_journal(raw, namespace):
    value = _decode(raw, JOURNAL_MAX_BYTES)
    if (set(value) != JOURNAL_FIELDS
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or type(value["generation"]) is not int
            or not 1 <= value["generation"] <= MAX_GENERATION
            or type(value["veto"]) is not bool
            or not isinstance(value["state"], str)
            or value["state"] not in {"pending", "success", "failed"}
            or value["veto"] is not (value["state"] != "success")
            or not isinstance(value["trigger_source"], str)
            or value["trigger_source"] not in SOURCES
            or not isinstance(value["source_identity"], str)
            or not NAMESPACE.fullmatch(value["source_identity"])
            or value["source_identity"] != namespace):
        raise AuthorityError("closed authority schema/namespace/veto mismatch")
    for name, pattern in (("hostname", HOST), ("operation_id", IDENTIFIER), ("trigger_id", TRIGGER_IDENTIFIER)):
        if not isinstance(value[name], str) or not pattern.fullmatch(value[name]):
            raise AuthorityError("invalid authority identity")
    digest = value["receipt_sha256"]
    if not isinstance(digest, str) or (digest and not DIGEST.fullmatch(digest)) \
            or (value["state"] == "success" and not digest):
        raise AuthorityError("invalid authority receipt digest")
    return value


def decode_witness(raw, *, generation, namespace, journal_sha256):
    value = _decode(raw, WITNESS_MAX_BYTES)
    if (set(value) != {"schema_version", "generation", "source_identity", "journal_sha256"}
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or type(value["generation"]) is not int
            or value["generation"] != generation
            or value["source_identity"] != namespace
            or value["journal_sha256"] != journal_sha256):
        raise AuthorityError("authority witness mismatch: partial replay/rollback")
    return value


def _parent(path, create=False):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    path = Path(path).absolute()
    descriptor = os.open(path.anchor, flags)
    try:
        for component in path.parts[1:]:
            if component == "..":
                raise AuthorityError("unsafe authority path")
            if create:
                try:
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
                else:
                    # The new child's directory entry must be durable before
                    # a descendant journal can be advertised as durable.
                    os.fsync(descriptor)
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        metadata = os.fstat(descriptor)
        if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
            raise AuthorityError("unsafe authority namespace owner/mode")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_gid, value.st_nlink, value.st_size, value.st_mtime_ns,
            value.st_ctime_ns)


def _private_regular(value):
    return (stat.S_ISREG(value.st_mode) and value.st_nlink == 1
            and value.st_uid == os.geteuid() and stat.S_IMODE(value.st_mode) == 0o600)


def _storage_key(hostname):
    normalized = hostname.casefold()
    # Reserve room below NAME_MAX=255 for '.witness.json', the UUID staging
    # suffix and separators. '@' cannot begin any legal hostname, so hashed
    # and literal components occupy disjoint namespaces.
    return normalized if len(normalized) <= 200 else "@" + hashlib.sha256(normalized.encode("ascii")).hexdigest()


@contextmanager
def _scope(root, hostname, write=False):
    if not isinstance(hostname, str) or not HOST.fullmatch(hostname):
        raise AuthorityError("unsafe authority hostname")
    root = Path(root)
    root_fd = _parent(root, create=write)
    private_fd = lock_fd = None
    try:
        if write:
            try:
                os.mkdir(".authority", 0o700, dir_fd=root_fd)
                os.fsync(root_fd)
            except FileExistsError:
                pass
        private_fd = os.open(".authority", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        private = os.fstat(private_fd)
        if private.st_uid != os.geteuid() or stat.S_IMODE(private.st_mode) != 0o700:
            raise AuthorityError("unsafe private authority directory")
        key = _storage_key(hostname)
        lock_fd = os.open(
            key + ".lock", os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
            | (os.O_CREAT if write else 0), 0o600, dir_fd=private_fd,
        )
        if not _private_regular(os.fstat(lock_fd)):
            raise AuthorityError("unsafe authority lock")
        try:
            fcntl.flock(lock_fd, (fcntl.LOCK_EX if write else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise AuthorityError("authority writer is active") from exc
        held = os.fstat(root_fd)
        held_lock = os.fstat(lock_fd)
        namespace = f"{held.st_dev}:{held.st_ino}"

        def validate_scope():
            visible = _parent(root)
            try:
                current = os.fstat(visible)
                if (held.st_dev, held.st_ino) != (current.st_dev, current.st_ino):
                    raise AuthorityError("authority namespace rebound")
                named = os.stat(".authority", dir_fd=visible, follow_symlinks=False)
                if ((private.st_dev, private.st_ino, private.st_uid, private.st_mode)
                        != (named.st_dev, named.st_ino, named.st_uid, named.st_mode)):
                    raise AuthorityError("authority directory rebound")
                lock = os.stat(key + ".lock", dir_fd=private_fd, follow_symlinks=False)
                if _identity(held_lock) != _identity(lock) or not _private_regular(lock):
                    raise AuthorityError("authority lock rebound")
            finally:
                os.close(visible)

        def advance_writer_witness(raw, validate_transaction):
            nonlocal held_lock
            validate_transaction()
            os.ftruncate(lock_fd, 0)
            os.lseek(lock_fd, 0, os.SEEK_SET)
            remaining = memoryview(raw)
            while remaining:
                written = os.write(lock_fd, remaining)
                if written <= 0:
                    raise AuthorityError("writer witness did not progress")
                remaining = remaining[written:]
            held_lock = os.fstat(lock_fd)
            os.fsync(lock_fd)
            validate_transaction()

        validate_scope()
        yield private_fd, key, namespace, validate_scope, advance_writer_witness
        validate_scope()
    finally:
        if lock_fd is not None:
            os.close(lock_fd)
        if private_fd is not None:
            os.close(private_fd)
        os.close(root_fd)


def _read(descriptor, name, limit, allow_empty=False):
    try:
        file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise AuthorityError("unsafe authority file") from exc
    try:
        before = os.fstat(file_fd)
        minimum = 0 if allow_empty else 1
        if not _private_regular(before) or not minimum <= before.st_size <= limit:
            raise AuthorityError("unsafe authority file metadata/size")
        chunks, remaining = [], limit + 1
        while remaining:
            chunk = os.read(file_fd, min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(file_fd)
        named = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if len(raw) != before.st_size or _identity(before) != _identity(after) \
                or _identity(before) != _identity(named):
            raise AuthorityError("authority file changed during read")
        return raw
    finally:
        os.close(file_fd)


def _current(descriptor, key, namespace):
    try:
        os.stat(key + ".pending", dir_fd=descriptor, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise AuthorityError("interrupted authority transaction: persistent hold")
    raw = _read(descriptor, key + ".journal.json", JOURNAL_MAX_BYTES)
    witness_raw = _read(descriptor, key + ".witness.json", WITNESS_MAX_BYTES)
    writer_raw = _read(descriptor, key + ".lock", WITNESS_MAX_BYTES, allow_empty=True)
    if raw is None and witness_raw is None:
        if writer_raw:
            raise AuthorityError("authority history erased after writer initialization")
        return None
    if raw is None or witness_raw is None:
        raise AuthorityError("incomplete authority pair")
    value = decode_journal(raw, namespace)
    decode_witness(
        witness_raw, generation=value["generation"], namespace=namespace,
        journal_sha256=hashlib.sha256(raw).hexdigest(),
    )
    decode_witness(
        writer_raw, generation=value["generation"], namespace=namespace,
        journal_sha256=hashlib.sha256(raw).hexdigest(),
    )
    if _storage_key(value["hostname"]) != key:
        raise AuthorityError("authority hostname does not match its local key")
    return value


def read_current(root, hostname):
    try:
        with _scope(root, hostname) as (descriptor, key, namespace, _validate, _advance):
            return _current(descriptor, key, namespace)
    except FileNotFoundError:
        # Missing storage is unknown, never a receipt eligible for promotion.
        return None
    except OSError as exc:
        raise AuthorityError("authority storage could not be authenticated") from exc


def read_current_receipt(root, hostname, path):
    """Authenticate one existing receipt while holding its generation lock.

    Readers never create history, accept a path outside run/host/result.json,
    or infer the current generation from receipt/report wall clocks. A valid
    historical receipt is not current evidence; unsafe or contradictory images
    are explicit errors and are retained untouched.
    """
    root = Path(root).absolute()
    path = Path(path)
    path = path.absolute() if path.is_absolute() else root / path
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise AuthorityError("receipt path is outside authority namespace") from exc
    parts = relative.parts
    if (len(parts) != 3 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}", parts[0])
            or not isinstance(hostname, str) or not HOST.fullmatch(hostname)
            or parts[1].casefold() != hostname.casefold()
            or parts[2] != "result.json"):
        raise AuthorityError("receipt path is not a closed run/hostname/result.json")
    try:
        with _scope(root, hostname) as (descriptor, key, namespace, validate, _advance):
            current = _current(descriptor, key, namespace)
            if current is None or current["state"] != "success" or current["veto"] is not False:
                return None
            parent = _parent(path.parent)
            try:
                held = _identity(os.fstat(parent))
                receipt_image = _snapshot(parent, "result.json")
                raw = _read(parent, "result.json", RECEIPT_MAX_BYTES)
                if raw is None:
                    return None
                receipt = decode_receipt(raw)
                visible = _parent(path.parent)
                try:
                    if held != _identity(os.fstat(visible)):
                        raise AuthorityError("receipt parent rebound during read")
                finally:
                    os.close(visible)
                validate()
                if _current(descriptor, key, namespace) != current:
                    raise AuthorityError("receipt generation changed during read")
                if _snapshot(parent, "result.json") != receipt_image:
                    raise AuthorityError("receipt image changed after read")
                if (receipt["state"] != "triggered"
                        or any(receipt[field] != current[field] for field in (
                            "hostname", "generation", "source_identity", "operation_id",
                            "trigger_id", "trigger_source",
                        ))):
                    return None
                if receipt_digest(receipt) != current["receipt_sha256"]:
                    raise AuthorityError("current receipt digest disagrees with local authority")
                return receipt
            finally:
                os.close(parent)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise AuthorityError("receipt storage could not be authenticated") from exc


def _snapshot(descriptor, name):
    try:
        value = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not _private_regular(value):
        raise AuthorityError("unsafe authority destination")
    return _identity(value)


def _stage(descriptor, name, raw, expected, validate):
    temporary = "." + name + "." + uuid.uuid4().hex + ".tmp"
    file_fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                      0o600, dir_fd=descriptor)
    renamed = False
    staged = os.fstat(file_fd)
    held_fd = None
    try:
        with os.fdopen(file_fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fchmod(stream.fileno(), 0o600)
            staged = os.fstat(stream.fileno())
            os.fsync(stream.fileno())
            named = os.stat(temporary, dir_fd=descriptor, follow_symlinks=False)
            if (_identity(staged) != _identity(os.fstat(stream.fileno()))
                    or _identity(staged) != _identity(named) or not _private_regular(named)):
                raise AuthorityError("authority temporary changed during staging")
            held_fd = os.dup(stream.fileno())
        validate()
        if _snapshot(descriptor, name) != expected:
            raise AuthorityError("authority destination rebound during staging")
        if (_identity(os.fstat(held_fd)) != _identity(staged)
                or _snapshot(descriptor, temporary) != _identity(staged)):
            raise AuthorityError("authority temporary rebound before publication")
        os.replace(temporary, name, src_dir_fd=descriptor, dst_dir_fd=descriptor)
        renamed = True
        # Rename may legitimately advance ctime, but the held inode is still
        # the only source of publication identity. Never trust a named image
        # installed by another writer after the replacement.
        published = os.fstat(held_fd)
        if (_identity(staged)[:-1] != _identity(published)[:-1]
                or not _private_regular(published)
                or _snapshot(descriptor, name) != _identity(published)):
            raise AuthorityError("authority image changed during publication")
        os.fsync(descriptor)
        validate()
        if (_identity(os.fstat(held_fd)) != _identity(published)
                or _snapshot(descriptor, name) != _identity(published)):
            raise AuthorityError("authority image changed during directory sync")
        return _identity(published)
    finally:
        try:
            if not renamed:
                try:
                    named = os.stat(temporary, dir_fd=descriptor, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    # Clean only this unchanged staged image; never unlink a
                    # foreign file or alias occupying our controlled name.
                    if _private_regular(named) and _identity(named) == _identity(staged):
                        os.unlink(temporary, dir_fd=descriptor)
        finally:
            if held_fd is not None:
                os.close(held_fd)


def _publish(descriptor, key, value, validate, advance_writer_witness):
    raw = wire(value)
    decode_journal(raw, value["source_identity"])
    validate()
    names = (key + ".witness.json", key + ".journal.json")
    expected = {name: _snapshot(descriptor, name) for name in names}
    marker = key + ".pending"
    marker_fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600, dir_fd=descriptor)

    def retain_hold():
        try:
            hold_fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                              0o600, dir_fd=descriptor)
        except FileExistsError:
            # Any pre-existing guard remains HOLD; do not overwrite it.
            return
        try:
            os.write(hold_fd, b"F02 authority durability uncertain\n")
            os.fsync(hold_fd)
        finally:
            os.close(hold_fd)
        os.fsync(descriptor)

    try:
        with os.fdopen(marker_fd, "wb") as stream:
            stream.write(b"F02 authority transaction pending\n")
            stream.flush()
            guard = _identity(os.fstat(stream.fileno()))
            os.fsync(stream.fileno())

        def validate_transaction():
            validate()
            if _snapshot(descriptor, marker) != guard:
                raise AuthorityError("authority transaction guard rebound")

        validate_transaction()
        os.fsync(descriptor)
        validate_transaction()
        witness = {
            "schema_version": 1, "generation": value["generation"],
            "source_identity": value["source_identity"],
            "journal_sha256": hashlib.sha256(raw).hexdigest(),
        }
        # The held single-writer inode witnesses the current image before
        # the replaceable pair is published. Replaying both old members,
        # including a same-generation success after veto, cannot replace this
        # current witness. All three images still share a recovery domain.
        advance_writer_witness(wire(witness), validate_transaction)
        published = {}
        published[names[0]] = _stage(
            descriptor, names[0], wire(witness), expected[names[0]], validate_transaction,
        )
        published[names[1]] = _stage(
            descriptor, names[1], raw, expected[names[1]], validate_transaction,
        )

        def validate_published_pair():
            validate()
            for name, identity in published.items():
                if _snapshot(descriptor, name) != identity:
                    raise AuthorityError("authority pair changed before completion")

        validate_transaction()
        validate_published_pair()
        os.unlink(marker, dir_fd=descriptor)
        os.fsync(descriptor)
        # Earlier members can be rebound while the other member or final
        # directory sync runs. No positive completion may escape that window.
        validate_published_pair()
    except BaseException:
        # Even a removed/rebound marker or late cleanup failure must not
        # expose an earlier success as the current causal authority.
        retain_hold()
        raise


def begin(root, hostname, operation_id, trigger_id, trigger_source):
    with _scope(root, hostname, write=True) as (descriptor, key, namespace, validate, advance):
        previous = _current(descriptor, key, namespace)
        generation = previous["generation"] + 1 if previous else 1
        value = {
            "schema_version": 1, "hostname": hostname, "generation": generation,
            "operation_id": operation_id, "trigger_id": trigger_id,
            "trigger_source": trigger_source, "source_identity": namespace,
            "state": "pending", "veto": True, "receipt_sha256": "",
        }
        _publish(descriptor, key, value, validate, advance)
        return value


def revoke(root, hostname, *, expected=None):
    """Withdraw the existing configuration era before another mutating action.

    This negative transition cannot mint a new successful observation or borrow
    its old digest. Only begin/finish from a new actual config writer can later
    establish success in a strictly newer generation.
    """
    with _scope(root, hostname, write=True) as (descriptor, key, namespace, validate, advance):
        current = _current(descriptor, key, namespace)
        if expected is not None:
            # Observers must compare while holding the same writer lock. A
            # read-before-lock check could withdraw another writer's new era.
            decode_journal(wire(expected), namespace)
            if current != expected:
                return None
        if current is None:
            return None
        value = {**current, "state": "failed", "veto": True, "receipt_sha256": ""}
        if value != current:
            _publish(descriptor, key, value, validate, advance)
        return value


def finish(root, ticket, result):
    if not isinstance(ticket, dict):
        raise AuthorityError("completion ticket is not a closed object")
    try:
        result = decode_receipt(wire(result))
    except (TypeError, UnicodeError) as exc:
        raise AuthorityError("completion receipt is not serializable") from exc
    with _scope(root, ticket.get("hostname"), write=True) as (descriptor, key, namespace, validate, advance):
        # Python considers True == 1 (and 1.0 == 1); dictionary equality is
        # not a schema/type check for an incoming completion ticket.
        decode_journal(wire(ticket), namespace)
        current = _current(descriptor, key, namespace)
        if current != ticket or current["state"] != "pending":
            raise AuthorityError("completion is not the current pending generation")
        if (not isinstance(result, dict) or type(result.get("generation")) is not int
                or result.get("generation") != ticket["generation"]
                or any(result.get(field) != ticket[field] for field in (
                    "hostname", "operation_id", "trigger_id", "trigger_source", "source_identity",
                ))):
            raise AuthorityError("completion does not carry its own generation/identity")
        success = (result.get("state") == "triggered"
                   and result.get("batch_identity_verified") is True
                   and isinstance(result.get("live_state_sha256"), str)
                   and DIGEST.fullmatch(result["live_state_sha256"]) is not None)
        value = {**current, "state": "success" if success else "failed",
                 "veto": not success, "receipt_sha256": receipt_digest(result)}
        _publish(descriptor, key, value, validate, advance)
        return value
