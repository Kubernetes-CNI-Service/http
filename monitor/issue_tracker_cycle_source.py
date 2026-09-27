"""Read-only C-23 cycle ledger projection for later REQ7 qualification.

This produces no activity observations, QualifiedSet, whitelist decision, K
settings, or send authority. Those remain separate fail-closed boundaries.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat

from tools.project_contract import collection_cycle_source_slots


class CycleSourceHoldError(ValueError):
    """A worker cycle chain is incomplete, corrupt, or not safely bound."""


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


def read_completed_cycle_evidence(store):
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
            raise CycleSourceHoldError("cycle record sequence or witness gap")
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
