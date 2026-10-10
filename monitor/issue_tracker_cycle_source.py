"""Read-only C-23 cycle ledger projection for later REQ7 qualification.

This produces no activity observations, QualifiedSet, whitelist decision, K
settings, or send authority. Those remain separate fail-closed boundaries.
"""

from __future__ import annotations

from dataclasses import dataclass
from contextlib import contextmanager
from contextvars import ContextVar
import hashlib
import json
import os
from pathlib import Path
import stat

from tools.project_contract import collection_cycle_source_slots

_HELD_CYCLE_REPLAY = ContextVar('req7_held_cycle_replay', default=None)


class CycleSourceHoldError(ValueError):
    """A worker cycle chain is incomplete, corrupt, or not safely bound."""


class CycleSequenceGap(CycleSourceHoldError):
    """The allocated sequence witness names records missing from the archive."""


@dataclass(frozen=True)
class CycleEvidence:
    cycle_id: str
    sequence: int
    project_key: str
    scope: str
    source_slots: tuple
    qualifying: bool
    summary_sha256: str | None
    completion_sha256: str


def _canonical_line(value):
    return (json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ) + "\n").encode("utf-8")


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CycleSourceHoldError("duplicate cycle record JSON key")
        result[key] = value
    return result


def _reject_nonfinite(value):
    raise CycleSourceHoldError(f"nonfinite cycle record scalar: {value}")


def _read_record(path):
    descriptor = os.open(
        path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or metadata.st_size > 16 * 1024 * 1024):
            raise CycleSourceHoldError("cycle record is not a bounded regular file")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            raw = stream.read()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    document = json.loads(
        raw.decode("utf-8"), object_pairs_hook=_unique_pairs,
        parse_constant=_reject_nonfinite,
    )
    if raw != _canonical_line(document):
        raise CycleSourceHoldError("cycle record is not canonical")
    return document, hashlib.sha256(raw).hexdigest()


def _read_completed_cycle_evidence(store):
    """Validate a held worker store's complete chain without modifying it.

    Every allocated sequence must have a start, launch, and terminal completion.
    Nonqualifying completions remain visible so K cannot skip over a failure.
    No interpretation of per-device activity or durable tracker settings is made.
    """
    try:
        store._require_gate()
        records_dir = Path(store.records_dir)
        status_dir = Path(store.root_status_dir)
        if status_dir not in records_dir.parents or any(
            candidate.is_symlink() for candidate in (status_dir, *(
                parent for parent in records_dir.parents if status_dir in parent.parents
            ), records_dir)
        ):
            raise CycleSourceHoldError("cycle record path traverses a symlink")
        witness = store._read_witness()
        groups = store._record_groups()
        if witness is None:
            if groups:
                raise CycleSourceHoldError("cycle records exist without witness")
            return ()
        if sorted(groups) != list(range(1, witness + 1)):
            raise CycleSequenceGap("cycle record sequence or witness gap")
        output = []
        tokens = set()
        ids = set()
        for sequence in range(1, witness + 1):
            group = groups[sequence]
            if set(group) != {"start", "launch", "completion"}:
                raise CycleSourceHoldError("cycle chain is not terminal")
            start, _ = _read_record(group["start"])
            identity = store._validate_start_record(start, sequence)
            launch, _ = _read_record(group["launch"])
            store._validate_launch_record(launch, identity)
            completion, completion_sha256 = _read_record(group["completion"])
            validated = store._validate_completion_record(completion, identity)
            if identity["run_token"] in tokens or identity["cycle_id"] in ids:
                raise CycleSourceHoldError("duplicate collection cycle identity")
            tokens.add(identity["run_token"])
            ids.add(identity["cycle_id"])
            result = validated["run_result"]
            summary = None if result is None else result["summary"]
            qualifying = bool(
                validated["outcome"] == "cycle_completed"
                and summary is not None and summary["qualifying"] is True
            )
            output.append(CycleEvidence(
                cycle_id=identity["cycle_id"], sequence=sequence,
                project_key=identity["project_key"], scope=identity["scope"],
                source_slots=collection_cycle_source_slots(identity["scope"]),
                qualifying=qualifying,
                summary_sha256=(
                    None if summary is None
                    else hashlib.sha256(_canonical_line(summary)).hexdigest()
                ),
                completion_sha256=completion_sha256,
            ))
        return tuple(output)
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, RuntimeError, ValueError) as exc:
        if isinstance(exc, CycleSourceHoldError):
            raise
        raise CycleSourceHoldError("collection cycle source evidence is not safe") from exc


def read_completed_cycle_evidence(store):
    """Replay normally, or verify every original input in an actual held scope."""
    active = _HELD_CYCLE_REPLAY.get()
    if active is not None and active[0] is store:
        active[1]()
        result = active[2]
        active[1]()
        return result
    return _read_completed_cycle_evidence(store)


@contextmanager
def _hold_completed_cycle_replay(store):
    """One semantic replay while ALL actual worker inputs remain original.

    Every lookup still checks original parent/file FDs, complete record names,
    exact stat (including ctime), bytes, actual store binding and held gate.
    No caller witness/verifier, persistent cache, archive-read exemption or GO.
    Other native source readers must still replay their own provenance.
    """
    fds=[]; parents=[]; files=[]; key=None; failed=False
    def identity(info):
        return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,
                info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
    def directory_identity(info):
        return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid)
    def remember(fd):
        fds.append((fd,os.fstat(fd).st_dev,os.fstat(fd).st_ino))
        return fd
    def open_parent(path):
        if not path.is_absolute() or '..' in path.parts:
            raise CycleSourceHoldError('cycle input parent is not absolute')
        fd=remember(os.open('/',os.O_RDONLY|os.O_CLOEXEC|os.O_DIRECTORY|os.O_NOFOLLOW))
        for part in path.parts[1:]:
            child=remember(os.open(part,os.O_RDONLY|os.O_CLOEXEC|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd))
            parents.append((fd,part,child,directory_identity(os.fstat(child))))
            fd=child
        return fd
    def pin(parent,name):
        fd=remember(os.open(name,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent))
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or not 0<info.st_size<=16*1024*1024:
            raise CycleSourceHoldError('cycle input is not bounded and original')
        raw=os.pread(fd,info.st_size+1,0)
        if len(raw)!=info.st_size: raise CycleSourceHoldError('cycle input changed during pin')
        files.append((parent,name,fd,identity(info),raw))
    def binding():
        return (tuple(getattr(store,name) for name in (
            'root_status_dir','status_dir','records_dir','witness_path',
            'project_identity','project_key','scope','source')),
            tuple(getattr(store.gate,name) for name in (
                'project','scope','status_dir','lane','collection_keys','state_name','lock_name')))
    try:
        if _HELD_CYCLE_REPLAY.get() is not None:
            raise CycleSourceHoldError('nested cycle reuse is not supported')
        store._require_gate(); original_binding=binding()
        gate=store.gate; lock_fd=gate._lock_fd; lock_identity=directory_identity(os.fstat(lock_fd))
        records=Path(store.records_dir); witness=Path(store.witness_path)
        record_fd=open_parent(records); record_identity=identity(os.fstat(record_fd))
        names=frozenset(os.listdir(record_fd))
        for name in sorted(names): pin(record_fd,name)
        witness_parent=open_parent(witness.parent)
        witness_missing=witness.name not in os.listdir(witness_parent)
        if not witness_missing: pin(witness_parent,witness.name)
        def verify():
            store._require_gate()
            if (binding()!=original_binding or store.gate is not gate or gate._lock_fd!=lock_fd
                    or directory_identity(os.fstat(lock_fd))!=lock_identity):
                raise CycleSourceHoldError('cycle store or gate binding changed')
            for parent,name,fd,info in parents:
                if (directory_identity(os.fstat(fd))!=info
                        or directory_identity(os.stat(name,dir_fd=parent,follow_symlinks=False))!=info):
                    raise CycleSourceHoldError('cycle input ancestor changed')
            if identity(os.fstat(record_fd))!=record_identity or frozenset(os.listdir(record_fd))!=names:
                raise CycleSourceHoldError('complete cycle record namespace changed')
            if witness_missing and witness.name in os.listdir(witness_parent):
                raise CycleSourceHoldError('cycle witness appeared during replay')
            for parent,name,fd,info,raw in files:
                if (identity(os.fstat(fd))!=info
                        or identity(os.stat(name,dir_fd=parent,follow_symlinks=False))!=info
                        or os.pread(fd,len(raw)+1,0)!=raw):
                    raise CycleSourceHoldError('original cycle input changed')
            store._require_gate()
        verify(); result=_read_completed_cycle_evidence(store); verify()
        key=_HELD_CYCLE_REPLAY.set((store,verify,result))
        yield verify
        verify()
    except Exception:
        failed=True
    finally:
        if key is not None: _HELD_CYCLE_REPLAY.reset(key)
        for fd,device,inode in reversed(fds):
            try:
                info=os.fstat(fd)
                if (info.st_dev,info.st_ino)==(device,inode): os.close(fd)
                else: failed=True
            except OSError: failed=True
    if failed: raise CycleSourceHoldError('held cycle original replay is unsafe')
