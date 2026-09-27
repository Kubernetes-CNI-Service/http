"""Conservative C-6 local generation journal; no online eligibility issuer.

Only private local fixture roots are currently integrated.  A RECEIPT returned
by ``commit`` proves this module completed its local barriers; a later reader
must separately hold the owner-wide lock and complete the C-6 handoff/recovery
barrier before granting online eligibility. ``inspect`` NEVER grants it.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid


_GEN = re.compile(r"gen-([0-9]{20})-([0-9a-f]{32})\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_MAX_MANIFEST = 1024 * 1024
_MAX_XLSX = 32 * 1024 * 1024  # C-24 held workbook upper bound, not a journal limit.
_MAX_DOC = 16 * 1024
_ACTIVE = {}


class LocalCommitHold(ValueError):
    """Local evidence is incomplete/unsafe; never infer online eligibility."""


@dataclass(frozen=True)
class Generation:
    generation_id: str
    sequence: int
    manifest_id: str
    owner_token: object = field(repr=False, compare=False)


@dataclass(frozen=True)
class PreparedWitness:
    dev: int
    ino: int
    size: int
    sha256: str


@dataclass(frozen=True)
class LocalReceipt:
    generation_id: str
    sequence: int
    manifest_id: str
    published_sha256: str


@dataclass(frozen=True)
class LocalObservation:
    status: str
    prepared_observation: str


@dataclass
class _Owner:
    project: Path
    publication: Path
    pid: int
    project_fd: int
    root_fd: int
    publication_fd: int
    lock_fd: int
    lock_dev: int
    lock_ino: int
    handles: dict[int, Generation] = field(default_factory=dict)


def _flags(directory=False):
    if not all(hasattr(os, item) for item in ("O_NOFOLLOW", "O_CLOEXEC", "O_DIRECTORY")):
        raise LocalCommitHold("no-follow local filesystem support unavailable")
    return (os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
            | getattr(os, "O_NONBLOCK", 0) | (os.O_DIRECTORY if directory else 0))


def _open_absolute_directory(path):
    """Walk every component by held directory FD; reject ancestor aliases."""
    path = Path(path)
    if not path.is_absolute() or any(part in (".", "..") for part in path.parts):
        raise LocalCommitHold("local path is not canonical absolute")
    fd = os.open("/", _flags(directory=True))
    try:
        for component in path.parts[1:]:
            child = os.open(component, _flags(directory=True), dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _check(fd, *, directory, private=True):
    info = os.fstat(fd)
    if ((not stat.S_ISDIR(info.st_mode) if directory else not stat.S_ISREG(info.st_mode))
            or info.st_uid != os.getuid()
            or info.st_mode & (0o077 if private else 0o022)
            or (not directory and info.st_nlink != 1)):
        raise LocalCommitHold("unsafe local evidence type, owner or mode")
    return info


def _directory(parent, name, *, private=True):
    fd = os.open(name, _flags(directory=True), dir_fd=parent)
    try:
        _check(fd, directory=True, private=private)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _mkdir(parent, name):
    os.mkdir(name, 0o700, dir_fd=parent)
    os.fsync(parent)
    child = _directory(parent, name)
    os.fsync(child)
    return child


def _read(parent, name, limit=_MAX_DOC):
    fd = os.open(name, _flags(), dir_fd=parent)
    try:
        info = _check(fd, directory=False)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino) or info.st_size > limit:
            raise LocalCommitHold("local evidence identity or size changed")
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) != info.st_size or len(data) > limit:
            raise LocalCommitHold("local evidence changed during read")
        return bytes(data), info
    finally:
        os.close(fd)


def _canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def _pairs(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise LocalCommitHold("duplicate local evidence JSON key")
        result[name] = value
    return result


def _reject_constant(_):
    raise LocalCommitHold("nonfinite local evidence scalar")


def _json(raw, keys=None):
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=_reject_constant)
        if not isinstance(value, dict) or (keys is not None and set(value) != keys) \
                or _canonical(value) != raw:
            raise LocalCommitHold("local evidence is not exact canonical JSON")
        return value
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        if isinstance(exc, LocalCommitHold):
            raise
        raise LocalCommitHold("invalid local evidence JSON") from exc


def _rename_new(parent, source, destination, *, destination_parent=None):
    """Publish across held dirfds, atomically refusing an existing name."""
    if destination_parent is None:
        destination_parent = parent
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin" and hasattr(libc, "renameatx_np"):
        operation = libc.renameatx_np
        flag = 0x00000004  # Darwin RENAME_EXCL; local SDK sys/stdio.h.
    elif sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        operation = libc.renameat2
        flag = 1  # Linux RENAME_NOREPLACE; same primitive used by 01-a-setup.py.
    else:
        raise LocalCommitHold("atomic no-replace rename is unavailable")
    operation.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                          ctypes.c_char_p, ctypes.c_uint)
    operation.restype = ctypes.c_int
    ctypes.set_errno(0)
    if operation(parent, os.fsencode(source), destination_parent,
                 os.fsencode(destination), flag) != 0:
        error = ctypes.get_errno() or errno.EIO
        raise OSError(error, os.strerror(error), destination)


def _write_new(parent, name, raw):
    if not isinstance(raw, bytes) or len(raw) > _MAX_MANIFEST:
        raise LocalCommitHold("invalid local evidence write")
    temp = ".pending-" + uuid.uuid4().hex
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                 | os.O_CLOEXEC, 0o600, dir_fd=parent)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise LocalCommitHold("short local evidence write")
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        _rename_new(parent, temp, name)
    except FileExistsError:
        # Atomic no-replace proves only that the destination survived. There
        # is no conditional unlink-by-inode: a same-UID actor may replace the
        # pending name after a stat. Preserve it as evidence rather than risk
        # deleting someone else's bytes. Recovery must treat it as unexplained.
        raise
    os.fsync(parent)


def _validate_paths(project, publication):
    project = Path(project)
    publication = Path(publication)
    if (not project.is_absolute() or not publication.is_absolute()
            or publication.parent != project
            or publication.name not in {"publication", "99-output-monitor"}):
        raise LocalCommitHold("local commit paths must be a direct private project child")
    return project, publication


def create_local_commit_store(project, publication):
    """Create a NEW state root only; trusted project freshness is an integration hold."""
    project, publication = _validate_paths(project, publication)
    try:
        project_fd = _open_absolute_directory(project)
    except OSError as exc:
        raise LocalCommitHold("unsafe project ancestor") from exc
    try:
        _check(project_fd, directory=True, private=False)
        publication_fd = _directory(project_fd, publication.name, private=False)
        os.close(publication_fd)
        root_fd = _mkdir(project_fd, ".tracker")
        try:
            generations = _mkdir(root_fd, "generations")
            os.close(generations)
            quarantine = _mkdir(root_fd, "quarantine")
            os.close(quarantine)
            lock = os.open("LOCK", os.O_RDWR | os.O_CREAT | os.O_EXCL
                           | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=root_fd)
            os.fsync(lock)
            os.close(lock)
            os.fsync(root_fd)
        finally:
            os.close(root_fd)
    except (OSError, TypeError, ValueError) as exc:
        if isinstance(exc, LocalCommitHold):
            raise
        raise LocalCommitHold("cannot initialize local commit state") from exc
    finally:
        os.close(project_fd)


@contextmanager
def writer_owner(project, publication):
    """Issue an opaque single-use ACTIVE token for one flock ownership period."""
    project, publication = _validate_paths(project, publication)
    if any(active.pid == os.getpid() and active.project == project
           and active.publication == publication for active in _ACTIVE.values()):
        raise LocalCommitHold("local writer already active in this process; pass its token")
    try:
        project_fd = _open_absolute_directory(project)
    except OSError as exc:
        raise LocalCommitHold("unsafe project ancestor") from exc
    root_fd = publication_fd = lock_fd = None
    held = False
    token = object()
    try:
        _check(project_fd, directory=True, private=False)
        root_fd = _directory(project_fd, ".tracker")
        publication_fd = _directory(project_fd, publication.name, private=False)
        lock_fd = os.open("LOCK", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
                          | getattr(os, "O_NONBLOCK", 0), dir_fd=root_fd)
        info = _check(lock_fd, directory=False)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        held = True
        named = os.stat("LOCK", dir_fd=root_fd, follow_symlinks=False)
        if (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino):
            raise LocalCommitHold("writer lock identity changed")
        _ACTIVE[token] = _Owner(project, publication, os.getpid(), project_fd, root_fd,
                                publication_fd, lock_fd, info.st_dev, info.st_ino)
    except (OSError, TypeError, ValueError) as exc:
        if isinstance(exc, LocalCommitHold):
            raise
        raise LocalCommitHold("local writer ownership failed") from exc
    else:
        # Exceptions from the caller's body are not ownership failures.
        yield token
    finally:
        _ACTIVE.pop(token, None)  # REVOKE strictly before flock unlock and fd close.
        if lock_fd is not None:
            if held:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
        if publication_fd is not None:
            os.close(publication_fd)
        if root_fd is not None:
            os.close(root_fd)
        os.close(project_fd)


def _owner(token):
    try:
        owner = _ACTIVE[token]
    except (KeyError, TypeError) as exc:
        raise LocalCommitHold("generation token is not ACTIVE") from exc
    if owner.pid != os.getpid():
        raise LocalCommitHold("generation token belongs to another process")
    try:
        named_project_fd = _open_absolute_directory(owner.project)
        try:
            project = _check(owner.project_fd, directory=True, private=False)
            named_project = os.fstat(named_project_fd)
        finally:
            os.close(named_project_fd)
        root = _check(owner.root_fd, directory=True)
        named_root = os.stat(".tracker", dir_fd=owner.project_fd,
                             follow_symlinks=False)
        publication = _check(owner.publication_fd, directory=True, private=False)
        named_publication = os.stat(owner.publication.name,
                                    dir_fd=owner.project_fd, follow_symlinks=False)
        lock = _check(owner.lock_fd, directory=False)
        named_lock = os.stat("LOCK", dir_fd=owner.root_fd, follow_symlinks=False)
    except OSError as exc:
        raise LocalCommitHold("generation owner path or descriptor disappeared") from exc
    if (any((held.st_dev, held.st_ino) != (named.st_dev, named.st_ino)
            for held, named in ((project, named_project), (root, named_root),
                                (publication, named_publication), (lock, named_lock)))
            or (lock.st_dev, lock.st_ino) != (owner.lock_dev, owner.lock_ino)):
        raise LocalCommitHold("generation owner path or lock identity changed")
    return owner


def _generation_fd(owner, generation, *, token=None):
    if not isinstance(generation, Generation) or _GEN.fullmatch(generation.generation_id) is None:
        raise LocalCommitHold("invalid generation handle")
    if token is not None and (generation.owner_token is not token
                              or owner.handles.get(id(generation)) is not generation):
        raise LocalCommitHold("generation handle was not issued to this writer acquisition")
    generations = _directory(owner.root_fd, "generations")
    try:
        current = _directory(generations, generation.generation_id)
        try:
            state = _json(_read(current, "STATE")[0],
                          {"schema_version", "generation_id", "sequence", "manifest_id"})
            manifest = _read(current, "MANIFEST", _MAX_MANIFEST)[0]
            _json(manifest)
            if (type(state["schema_version"]) is not int or state["schema_version"] != 1
                    or state["generation_id"] != generation.generation_id
                    or type(state["sequence"]) is not int
                    or state["sequence"] != generation.sequence
                    or state["manifest_id"] != generation.manifest_id
                    or hashlib.sha256(manifest).hexdigest() != generation.manifest_id):
                raise LocalCommitHold("generation handle/state/manifest mismatch")
        except BaseException:
            os.close(current)
            raise
        return current
    finally:
        os.close(generations)


def begin_generation(token, manifest_body):
    owner = _owner(token)
    if not isinstance(manifest_body, bytes) or len(manifest_body) > _MAX_MANIFEST:
        raise LocalCommitHold("invalid manifest bytes")
    _json(manifest_body)
    manifest_id = hashlib.sha256(manifest_body).hexdigest()
    generations = _directory(owner.root_fd, "generations")
    try:
        names = os.listdir(generations)
        if any(_GEN.fullmatch(name) is None for name in names):
            raise LocalCommitHold("unexplained generation entry")
        sequence = max((int(_GEN.fullmatch(name).group(1)) for name in names), default=0) + 1
        generation_id = f"gen-{sequence:020d}-{uuid.uuid4().hex}"
        directory = _mkdir(generations, generation_id)
        try:
            _write_new(directory, "MANIFEST", manifest_body)
            _write_new(directory, "STATE", _canonical({
                "schema_version": 1, "generation_id": generation_id,
                "sequence": sequence, "manifest_id": manifest_id,
            }))
        finally:
            os.close(directory)
        handle = Generation(generation_id, sequence, manifest_id, token)
        owner.handles[id(handle)] = handle
        return handle
    finally:
        os.close(generations)


def _prepared_name(generation_id, kind):
    return ".prepared-" + generation_id + (".xlsx" if kind == "xlsx" else "")


def _published_name(generation_id, kind):
    return generation_id + (".xlsx" if kind == "xlsx" else ".bin")


def _prepared_limit(kind):
    return _MAX_XLSX if kind == "xlsx" else _MAX_MANIFEST


def record_intent(token, generation, prepared_bytes, *, kind="blob"):
    owner = _owner(token)
    if (kind not in ("blob", "xlsx") or not isinstance(prepared_bytes, bytes) or
            len(prepared_bytes) > _prepared_limit(kind)):
        raise LocalCommitHold("invalid prepared bytes")
    if kind == "xlsx":
        # This is a bounded package precondition, not approval of the workbook
        # edit or online eligibility. W1's bridge binds source/manifest cells.
        from monitor.issue_tracker_whitelist import WhitelistHoldError
        from monitor.issue_tracker_whitelist_workbook import _parse_xlsx_bytes
        try:
            _parse_xlsx_bytes(prepared_bytes)
        except WhitelistHoldError as exc:
            raise LocalCommitHold("prepared XLSX package is invalid") from exc
    directory = _generation_fd(owner, generation, token=token)
    try:
        if "INTENT" in os.listdir(directory) or "RECEIPT" in os.listdir(directory):
            raise LocalCommitHold("generation already has durable intent/receipt")
        prepared_name = _prepared_name(generation.generation_id, kind)
        fd = os.open(prepared_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                     dir_fd=owner.publication_fd)
        try:
            view = memoryview(prepared_bytes)
            while view:
                count = os.write(fd, view)
                if count <= 0:
                    raise LocalCommitHold("short prepared-file write")
                view = view[count:]
            os.fsync(fd)
            info = _check(fd, directory=False)
        finally:
            os.close(fd)
        os.fsync(owner.publication_fd)
        witness = PreparedWitness(info.st_dev, info.st_ino, info.st_size,
                                  hashlib.sha256(prepared_bytes).hexdigest())
        details = {"name": prepared_name, "dev": witness.dev,
                   "ino": witness.ino, "size": witness.size,
                   "sha256": witness.sha256}
        if kind == "xlsx":
            details["kind"] = "xlsx"
        _write_new(directory, "INTENT", _canonical({
            "schema_version": 1, "generation_id": generation.generation_id,
            "manifest_id": generation.manifest_id,
            "prepared": details,
        }))
        return witness
    finally:
        os.close(directory)


def _intent(owner, generation, directory):
    row = _json(_read(directory, "INTENT")[0],
                {"schema_version", "generation_id", "manifest_id", "prepared"})
    witness = row["prepared"]
    kind = witness.get("kind", "blob") if isinstance(witness, dict) else None
    expected_name = _prepared_name(generation.generation_id, kind)
    fields = {"name", "dev", "ino", "size", "sha256"}
    if kind == "xlsx":
        fields.add("kind")
    if (type(row["schema_version"]) is not int or row["schema_version"] != 1
            or row["generation_id"] != generation.generation_id
            or row["manifest_id"] != generation.manifest_id
            or not isinstance(witness, dict)
            or kind not in ("blob", "xlsx") or set(witness) != fields
            or witness["name"] != expected_name
            or any(type(witness[key]) is not int or witness[key] < 0
                   for key in ("dev", "ino", "size"))
            or not isinstance(witness["sha256"], str)
            or _SHA.fullmatch(witness["sha256"]) is None
            or witness["size"] > _prepared_limit(kind)):
        raise LocalCommitHold("invalid local INTENT witness")
    return witness


def commit(token, generation):
    owner = _owner(token)
    directory = _generation_fd(owner, generation, token=token)
    try:
        if "RECEIPT" in os.listdir(directory):
            raise LocalCommitHold("generation already has RECEIPT")
        witness = _intent(owner, generation, directory)
        kind = witness.get("kind", "blob")
        raw, info = _read(owner.publication_fd, witness["name"], _prepared_limit(kind))
        if ((info.st_dev, info.st_ino, info.st_size, hashlib.sha256(raw).hexdigest())
                != (witness["dev"], witness["ino"], witness["size"], witness["sha256"])):
            raise LocalCommitHold("prepared-file dev/ino/size/SHA witness mismatch")
        published = _published_name(generation.generation_id, kind)
        if published in os.listdir(owner.publication_fd):
            raise LocalCommitHold("published name already exists without receipt")
        _rename_new(owner.publication_fd, witness["name"], published)
        os.fsync(owner.publication_fd)
        # The source name may have been exchanged after the INTENT witness was
        # read. Never issue a receipt merely because the rename succeeded.
        actual, published_info = _read(owner.publication_fd, published, _prepared_limit(kind))
        if ((published_info.st_dev, published_info.st_ino, published_info.st_size,
             hashlib.sha256(actual).hexdigest())
                != (witness["dev"], witness["ino"], witness["size"], witness["sha256"])):
            raise LocalCommitHold("published file differs from prepared INTENT witness")
        receipt_doc = {
            "schema_version": 1, "generation_id": generation.generation_id,
            "sequence": generation.sequence, "manifest_id": generation.manifest_id,
            "published": published, "published_dev": witness["dev"],
            "published_ino": witness["ino"], "published_size": witness["size"],
            "published_sha256": witness["sha256"],
        }
        if kind == "xlsx":
            receipt_doc["kind"] = "xlsx"
        _write_new(directory, "RECEIPT", _canonical(receipt_doc))
        return LocalReceipt(generation.generation_id, generation.sequence,
                            generation.manifest_id, witness["sha256"])
    except (OSError, TypeError, ValueError) as exc:
        if isinstance(exc, LocalCommitHold):
            raise
        raise LocalCommitHold("local commit incomplete; preserve evidence") from exc
    finally:
        os.close(directory)


def quarantine_unresolved(token, generation):
    """Preserve an unresolved prepared file; never create a RECEIPT."""
    owner = _owner(token)
    directory = _generation_fd(owner, generation)
    quarantine = None
    try:
        names = set(os.listdir(directory))
        if "RECEIPT" in names or "OBSERVATION" in names:
            raise LocalCommitHold("quarantine is not valid for this generation")
        witness = _intent(owner, generation, directory)
        quarantine = _directory(owner.root_fd, "quarantine")
        kind = witness.get("kind", "blob")
        destination = _published_name(generation.generation_id, kind)
        if destination in os.listdir(quarantine):
            raise LocalCommitHold("quarantine destination already exists")
        source = witness["name"]
        # Require the same prepared object; changed contents are still evidence,
        # but a replaced inode cannot be attributed to this INTENT.
        _, info = _read(owner.publication_fd, source, _prepared_limit(kind))
        if (info.st_dev, info.st_ino) != (witness["dev"], witness["ino"]):
            raise LocalCommitHold("prepared evidence identity changed before quarantine")
        _rename_new(owner.publication_fd, source, destination,
                    destination_parent=quarantine)
        os.fsync(owner.publication_fd)
        os.fsync(quarantine)
        _write_new(directory, "OBSERVATION", _canonical({
            "schema_version": 1, "generation_id": generation.generation_id,
            "type": "QUARANTINED-OBSERVATION", "quarantine_name": destination,
            "intent_sha256": hashlib.sha256(_read(directory, "INTENT")[0]).hexdigest(),
        }))
        return "QUARANTINED-OBSERVATION"
    except (OSError, TypeError, ValueError) as exc:
        if isinstance(exc, LocalCommitHold):
            raise
        raise LocalCommitHold("quarantine incomplete; preserve unresolved evidence") from exc
    finally:
        if quarantine is not None:
            os.close(quarantine)
        os.close(directory)


def inspect_local_generation(project, publication, generation, *, token=None):
    """Observation only; even a genuine RECEIPT is not an eligibility grant."""
    if token is None:
        with writer_owner(project, publication) as acquired:
            return inspect_local_generation(project, publication, generation, token=acquired)
    project, publication = _validate_paths(project, publication)
    owner = _owner(token)
    if owner.project != project or owner.publication != publication:
        raise LocalCommitHold("observation token belongs to another local store")
    directory = _generation_fd(owner, generation)
    try:
        names = set(os.listdir(directory))
        if "RECEIPT" in names:
            receipt = _json(_read(directory, "RECEIPT")[0])
            intent = _intent(owner, generation, directory)
            kind = intent.get("kind", "blob")
            receipt_fields = {
                "schema_version", "generation_id", "sequence", "manifest_id",
                "published", "published_dev", "published_ino", "published_size",
                "published_sha256",
            }
            if kind == "xlsx":
                receipt_fields.add("kind")
            if (set(receipt) != receipt_fields
                    or receipt.get("kind", "blob") != kind
                    or type(receipt["schema_version"]) is not int
                    or receipt["schema_version"] != 1
                    or receipt["generation_id"] != generation.generation_id
                    or receipt["manifest_id"] != generation.manifest_id
                    or receipt["published"] != _published_name(generation.generation_id, kind)
                    or receipt["sequence"] != generation.sequence
                    or any(type(receipt[key]) is not int or receipt[key] < 0
                           for key in ("published_dev", "published_ino", "published_size"))
                    or receipt["published_dev"] != intent["dev"]
                    or receipt["published_ino"] != intent["ino"]
                    or receipt["published_size"] != intent["size"]
                    or receipt["published_sha256"] != intent["sha256"]):
                raise LocalCommitHold("RECEIPT identity mismatch")
            try:
                raw, info = _read(owner.publication_fd, receipt["published"],
                                  _prepared_limit(kind))
            except OSError as exc:
                raise LocalCommitHold("RECEIPT has no published file") from exc
            if ((info.st_dev, info.st_ino, info.st_size, hashlib.sha256(raw).hexdigest())
                    != (intent["dev"], intent["ino"], intent["size"], intent["sha256"])):
                raise LocalCommitHold("RECEIPT published witness mismatch")
            # A name can be visible before commit's directory barrier returns.
            # This is only an observation, and still requires recovery barriers.
            try:
                os.fsync(owner.publication_fd)
                os.fsync(directory)
            except OSError as exc:
                raise LocalCommitHold("RECEIPT recovery barrier incomplete") from exc
            return LocalObservation("RECEIPT-PRESENT-NOT-ELIGIBILITY", "NONE")
        if "INTENT" not in names:
            return LocalObservation("UNRESOLVED", "NO-INTENT")
        witness = _intent(owner, generation, directory)
        present = witness["name"] in os.listdir(owner.publication_fd)
        if not present:
            quarantine = _directory(owner.root_fd, "quarantine")
            try:
                if _published_name(generation.generation_id, witness.get("kind", "blob")) in os.listdir(quarantine):
                    return LocalObservation("UNRESOLVED", "QUARANTINED-PRESENT")
            finally:
                os.close(quarantine)
        return LocalObservation("UNRESOLVED",
                                    "PREPARED-PRESENT" if present else "PREPARED-NOT-OBSERVED")
    finally:
        os.close(directory)
