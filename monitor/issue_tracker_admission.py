"""C-23's shared local publication admission, independent of C6 writers.

The durable event reader/writer lives here so the runtime and C6 bridge can
share one sequence without importing one another for journal primitives.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
import time

import yaml

from monitor.issue_tracker_cycle_source import (
    CycleSourceHoldError, read_completed_cycle_evidence,
)
from monitor.issue_tracker_local_commit import (
    LocalCommitHold, _canonical, _directory, _json, _mkdir, _owner, _read,
    _write_new,
)
from tools.project_contract import (
    MIN_CONTINUOUS_INTERVAL_MINUTES, normalize_issue_tracker_policy,
    safe_load_global_yaml,
)


class AdmissionHold(ValueError):
    """A shared publication admission cannot be proved."""


class AdmissionCollectorAnomaly(AdmissionHold):
    """A publication was attempted below the shared collector interval."""


class AdmissionTerminalOrphan(AdmissionHold):
    """A durable C6/admission chain is inconsistent and cannot be repaired in place."""


_FLOOR_NS = MIN_CONTINUOUS_INTERVAL_MINUTES * 60 * 1_000_000_000
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ADMISSION = re.compile(r"admission-([0-9]{20})\.json\Z")
_GEN_ID = re.compile(r"gen-([0-9]{20})-([0-9a-f]{32})\Z")
_EVENT_FIELDS = {
    "schema_version", "lane", "generation_id", "published_sha256",
    "project_key", "scope", "cycle_id", "cycle_completion_sha256",
    "policy_sha256", "publish_every_cycles", "boot_id", "monotonic_ns",
}
_MAX_GLOBAL_BYTES = 1024 * 1024


def local_publish_interval(project):
    """Read independent N policy from one held regular global file."""
    project = Path(project)
    if not project.is_absolute() or project.is_symlink():
        raise AdmissionHold("automatic local project path is unsafe")
    path = project / "01-global.yaml"
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_size < 1 or before.st_size > _MAX_GLOBAL_BYTES):
                raise AdmissionHold("automatic local policy file is unsafe")
            raw = os.read(fd, before.st_size + 1)
            after = os.fstat(fd)
            named = path.lstat()
            identity = lambda info: (info.st_dev, info.st_ino, info.st_size,
                                     info.st_mtime_ns, info.st_ctime_ns)
            if (len(raw) != before.st_size or identity(before) != identity(after)
                    or identity(after) != identity(named)):
                raise AdmissionHold("automatic local policy changed during read")
        finally:
            os.close(fd)
        document = safe_load_global_yaml(raw.decode("utf-8"))
        policy = normalize_issue_tracker_policy(document)
        interval = policy["publish_every_cycles"]
        if type(interval) is not int or interval < 1:
            raise AdmissionHold("automatic local publish interval is invalid")
        return interval, hashlib.sha256(raw).hexdigest()
    except (OSError, UnicodeError, yaml.YAMLError, TypeError, ValueError) as exc:
        if isinstance(exc, AdmissionHold):
            raise
        raise AdmissionHold("automatic local policy is unavailable or invalid") from exc


def assess_shared_admission_step(prior: dict | None, current: dict,
                                 qualified_cycle_ids: tuple[str, ...]) -> bool:
    """Validate one adjacent local C6 transition in the shared event domain.

    N applies only to automatic admissions. Manual publications may use the
    current completed cycle, but an automatic successor counts only cycles
    strictly after that shared anchor. Retry is not a new local C6 event.
    """
    if (prior is not None and type(prior) is not dict
            or type(current) is not dict
            or type(qualified_cycle_ids) is not tuple
            or not qualified_cycle_ids
            or any(type(item) is not str or not item
                   for item in qualified_cycle_ids)
            or len(set(qualified_cycle_ids)) != len(qualified_cycle_ids)):
        raise AdmissionHold("shared admission inputs are invalid")
    for event in (() if prior is None else (prior,)) + (current,):
        if (event.get("lane") not in ("automatic", "manual")
                or type(event.get("cycle_id")) is not str
                or event["cycle_id"] not in qualified_cycle_ids
                or type(event.get("publish_every_cycles")) is not int
                or event["publish_every_cycles"] < 1
                or type(event.get("boot_id")) is not str
                or not event["boot_id"]
                or type(event.get("monotonic_ns")) is not int
                or event["monotonic_ns"] < 1):
            raise AdmissionHold("shared admission event is invalid")
    if prior is None:
        if (current["lane"] == "automatic"
                and qualified_cycle_ids.index(current["cycle_id"]) + 1
                    < current["publish_every_cycles"]):
            raise AdmissionHold("first automatic admission lacked cycles")
        return True
    if (current["boot_id"] != prior["boot_id"]
            or current["monotonic_ns"] < prior["monotonic_ns"]):
        raise AdmissionHold("shared admission restart interval is unverifiable")
    previous_position = qualified_cycle_ids.index(prior["cycle_id"])
    current_position = qualified_cycle_ids.index(current["cycle_id"])
    if current["lane"] == "automatic":
        if (current_position - previous_position
                < current["publish_every_cycles"]):
            raise AdmissionHold("automatic admission lacks new completed cycles")
    elif current_position < previous_position:
        raise AdmissionHold("manual admission moved the completed-cycle anchor backwards")
    if current["monotonic_ns"] - prior["monotonic_ns"] < _FLOOR_NS:
        raise AdmissionCollectorAnomaly("collector_interval_below_minimum")
    return True


def prepare_shared_local_admission(
    token, store, prior: dict | None, *, lane: str,
    policy_sha256: str, publish_every_cycles: int,
    boot_id: str, monotonic_ns: int,
) -> dict:
    """Bind a changed C6 candidate to the latest protected completed cycle.

    The C6 bridge calls this under LK-P before begin_generation.  It later
    records the returned event only after the matching durable RECEIPT.
    """
    if (lane not in ("automatic", "manual")
            or type(policy_sha256) is not str
            or _SHA256.fullmatch(policy_sha256) is None
            or type(publish_every_cycles) is not int
            or publish_every_cycles < 1
            or type(boot_id) is not str or not boot_id or len(boot_id) > 128
            or any(char.isspace() for char in boot_id)
            or type(monotonic_ns) is not int or monotonic_ns < 1):
        raise AdmissionHold("shared local admission witness is invalid")
    cycles = read_completed_cycle_evidence(store)
    qualified = tuple(cycle for cycle in cycles if cycle.qualifying)
    if (not qualified or qualified[-1].cycle_id != cycles[-1].cycle_id
            or qualified[-1].project_key != store.project_key
            or qualified[-1].scope != store.scope):
        raise AdmissionHold("shared local admission cycle is not proved")
    event = {
        "schema_version": 1, "lane": lane,
        "project_key": store.project_key, "scope": store.scope,
        "cycle_id": qualified[-1].cycle_id,
        "cycle_completion_sha256": qualified[-1].completion_sha256,
        "policy_sha256": policy_sha256,
        "publish_every_cycles": publish_every_cycles,
        "boot_id": boot_id, "monotonic_ns": monotonic_ns,
    }
    if prior is None:
        if lane == "automatic" and len(qualified) < publish_every_cycles:
            raise AdmissionHold("first automatic admission lacks completed cycles")
        try:
            os.stat("admissions", dir_fd=_owner(token).root_fd,
                    follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise AdmissionHold("prior shared admission evidence is unexplained")
        event["sequence"] = 1
    else:
        assess_shared_admission_step(
            prior, event, tuple(cycle.cycle_id for cycle in qualified),
        )
        match = _GEN_ID.fullmatch(prior.get("generation_id", ""))
        if match is None:
            raise AdmissionHold("prior shared admission generation is invalid")
        event["sequence"] = int(match.group(1)) + 1
    return event


def record_shared_local_admission(
    token, generation_id: str, published_sha256: str, prepared: dict,
) -> None:
    """Append only after re-reading the matching immutable C6 RECEIPT.

    A crash before this write leaves a visible unmatched RECEIPT.  Recovery
    never infers or backfills the missing event.
    """
    if (type(generation_id) is not str
            or _GEN_ID.fullmatch(generation_id) is None
            or type(published_sha256) is not str
            or _SHA256.fullmatch(published_sha256) is None
            or type(prepared) is not dict
            or set(prepared) != (_EVENT_FIELDS - {"generation_id", "published_sha256"})
               | {"sequence"}
            or type(prepared["sequence"]) is not int
            or prepared["sequence"] < 1
            or int(_GEN_ID.fullmatch(generation_id).group(1))
               != prepared["sequence"]):
        raise AdmissionHold("shared local admission result is invalid")
    owner = _owner(token)
    generations = _directory(owner.root_fd, "generations")
    try:
        generation = _directory(generations, generation_id)
        try:
            receipt = _json(_read(generation, "RECEIPT")[0])
        finally:
            os.close(generation)
    finally:
        os.close(generations)
    if (receipt.get("generation_id") != generation_id
            or receipt.get("published_sha256") != published_sha256):
        raise AdmissionHold("shared local admission differs from C6 RECEIPT")
    admitted_ns = time.monotonic_ns()
    if (type(admitted_ns) is not int
            or admitted_ns < prepared["monotonic_ns"]):
        raise AdmissionHold("shared local admission clock moved backwards")
    record = {key: value for key, value in prepared.items()
              if key != "sequence"}
    record.update({
        "monotonic_ns": admitted_ns,
        "generation_id": generation_id,
        "published_sha256": published_sha256,
    })
    if prepared["sequence"] == 1:
        directory = _mkdir(owner.root_fd, "admissions")
    else:
        directory = _directory(owner.root_fd, "admissions")
    try:
        _write_new(directory,
                   f"admission-{prepared['sequence']:020d}.json",
                   _canonical(record))
    finally:
        os.close(directory)


def read_shared_local_admission(token, store, prior_image: bytes | None) -> dict | None:
    """Verify the contiguous local C6 RECEIPT/event/completed-cycle chain.

    The caller injects the independently read latest C6 image; this leaf
    module does not import the C6 bridge or infer a missing event.
    """
    try:
        owner = _owner(token)
        try:
            directory = _directory(owner.root_fd, "admissions")
        except FileNotFoundError:
            if prior_image is None:
                return None
            raise AdmissionTerminalOrphan("C6 RECEIPT has no admission evidence")
        try:
            names = os.listdir(directory)
            if (not names or any(_ADMISSION.fullmatch(name) is None
                                 for name in names)
                    or {int(_ADMISSION.fullmatch(name).group(1))
                        for name in names} != set(range(1, len(names) + 1))):
                raise AdmissionTerminalOrphan(
                    "shared admission directory is incomplete")
            events = tuple(_json(_read(
                directory, f"admission-{number:020d}.json")[0], _EVENT_FIELDS)
                for number in range(1, len(names) + 1))
        finally:
            os.close(directory)
        if prior_image is None:
            raise AdmissionTerminalOrphan("admission has no C6 RECEIPT")
        generations = _directory(owner.root_fd, "generations")
        try:
            generation_names = os.listdir(generations)
            if (len(generation_names) != len(events)
                    or set(generation_names)
                    != {event["generation_id"] for event in events}):
                raise AdmissionTerminalOrphan(
                    "admission and C6 generation count differ")
            receipts = []
            for event in events:
                generation = _directory(generations, event["generation_id"])
                try:
                    receipts.append(_json(_read(generation, "RECEIPT")[0]))
                finally:
                    os.close(generation)
        finally:
            os.close(generations)
        cycles = tuple(cycle for cycle in read_completed_cycle_evidence(store)
                       if cycle.qualifying)
        ids = tuple(cycle.cycle_id for cycle in cycles)
        if len(set(ids)) != len(ids):
            raise AdmissionHold("completed cycle identity is duplicated")
        previous = None
        for index, (event, receipt) in enumerate(zip(events, receipts), 1):
            if (type(event["schema_version"]) is not int
                    or event["schema_version"] != 1
                    or event["lane"] not in ("automatic", "manual")
                    or event["project_key"] != store.project_key
                    or event["scope"] != store.scope
                    or type(event["cycle_id"]) is not str
                    or event["cycle_id"] not in ids
                    or type(event["cycle_completion_sha256"]) is not str
                    or _SHA256.fullmatch(event["cycle_completion_sha256"]) is None
                    or cycles[ids.index(event["cycle_id"])].completion_sha256
                       != event["cycle_completion_sha256"]
                    or type(event["policy_sha256"]) is not str
                    or _SHA256.fullmatch(event["policy_sha256"]) is None
                    or type(event["published_sha256"]) is not str
                    or _SHA256.fullmatch(event["published_sha256"]) is None
                    or type(event["generation_id"]) is not str
                    or _GEN_ID.fullmatch(event["generation_id"]) is None
                    or int(_GEN_ID.fullmatch(event["generation_id"]).group(1))
                       != index
                    or receipt.get("generation_id") != event["generation_id"]
                    or receipt.get("published_sha256")
                       != event["published_sha256"]):
                raise AdmissionTerminalOrphan(
                    "shared admission does not bind C6 and cycle")
            assess_shared_admission_step(previous, event, ids)
            previous = event
        if hashlib.sha256(prior_image).hexdigest() != events[-1]["published_sha256"]:
            raise AdmissionTerminalOrphan(
                "latest admission does not bind published C6")
        return events[-1]
    except (OSError, LocalCommitHold, CycleSourceHoldError, TypeError,
            AttributeError, KeyError, ValueError) as exc:
        if isinstance(exc, AdmissionHold):
            raise
        raise AdmissionHold("shared local admission evidence is unsafe") from exc
