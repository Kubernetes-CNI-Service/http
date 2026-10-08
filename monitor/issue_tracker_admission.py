"""C-23's shared local publication admission, independent of C6 writers.

The durable event reader/writer lives here so the runtime and C6 bridge can
share one sequence without importing one another for journal primitives.
"""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
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
_RETRY = re.compile(r"retry-([0-9]{20})-(intent|count)\.json\Z")
_GEN_ID = re.compile(r"gen-([0-9]{20})-([0-9a-f]{32})\Z")
_EVENT_FIELDS = {
    "schema_version", "lane", "generation_id", "published_sha256",
    "project_key", "scope", "cycle_id", "cycle_completion_sha256",
    "policy_sha256", "publish_every_cycles", "boot_id", "monotonic_ns",
}
_MAX_GLOBAL_BYTES = 1024 * 1024
_RETRY_FIELDS = _EVENT_FIELDS | {
    "sequence", "unit_id", "wire_sha256", "action_digest", "attempt_count",
    "original_generation_id", "original_publish_id", "previous_sha256",
}
_RETRY_COUNT_FIELDS = {
    "schema_version", "sequence", "unit_id", "attempt_count",
    "intent_sha256", "original_attempt_sha256",
}


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
        if (event.get("lane") not in ("automatic", "manual", "retry")
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
        if current["lane"] == "retry":
            raise AdmissionHold("retry has no original shared publication")
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


def _merge_shared_retry_events(directory, names, publications, cycles):
    """Replay durable retry INTENT/count pairs in the SAME publication domain.

    Incomplete pairs are a permanent visible barrier, never backfilled. Count
    links were recorded under both actual owners; this reader grants no send
    or COMPLETE authority and does not infer that a request actually occurred.
    """
    from monitor.issue_tracker_attempt_journal import _read as held_read
    retry_names = {name for name in names if _RETRY.fullmatch(name)}
    numbers = {int(_RETRY.fullmatch(name).group(1)) for name in retry_names}
    if (numbers != set(range(1,len(numbers)+1)) or retry_names != {
            f"retry-{number:020d}-{kind}.json" for number in numbers for kind in ('intent','count')}):
        raise AdmissionTerminalOrphan("shared retry admission is incomplete")
    records=[]; per_unit={}
    for number in sorted(numbers):
        raw=held_read(directory,f"retry-{number:020d}-intent.json",16*1024)
        intent=_json(raw,_RETRY_FIELDS)
        counted=_json(held_read(directory,f"retry-{number:020d}-count.json",16*1024),_RETRY_COUNT_FIELDS)
        if (type(intent['schema_version']) is not int or intent['schema_version']!=1
                or type(intent['sequence']) is not int or intent['sequence']!=number
                or intent['lane']!='retry' or type(intent['attempt_count']) is not int
                or not 2<=intent['attempt_count']<=6 or type(counted['schema_version']) is not int
                or counted['schema_version']!=1 or type(counted['sequence']) is not int
                or counted['sequence']!=number or type(counted['attempt_count']) is not int
                or counted['attempt_count']!=intent['attempt_count'] or counted['unit_id']!=intent['unit_id']
                or counted['intent_sha256']!=hashlib.sha256(raw).hexdigest()):
            raise AdmissionTerminalOrphan("shared retry count differs from admission")
        for value in (intent['unit_id'],intent['wire_sha256'],intent['action_digest'],intent['original_publish_id'],
                      intent['previous_sha256'],counted['original_attempt_sha256']):
            if type(value) is not str or _SHA256.fullmatch(value) is None:
                raise AdmissionTerminalOrphan("shared retry identity is invalid")
        original=next((event for event in publications if event['generation_id']==intent['original_generation_id']),None)
        if original is None or original['published_sha256']!=intent['original_publish_id']:
            raise AdmissionTerminalOrphan("shared retry original publication differs")
        signature=(intent['wire_sha256'],intent['action_digest'],intent['original_generation_id'],intent['original_publish_id'])
        previous=per_unit.get(intent['unit_id'],(1,signature))
        if previous!=(intent['attempt_count']-1,signature):
            raise AdmissionTerminalOrphan("shared retry original count has a gap or retarget")
        per_unit[intent['unit_id']]=(intent['attempt_count'],signature)
        records.append(intent)
    merged=sorted((*publications,*records),key=lambda event:event['monotonic_ns'])
    previous=None; latest_publication=None
    ids=tuple(cycle.cycle_id for cycle in cycles)
    for event in merged:
        if event['lane']=='retry':
            if (previous is None or latest_publication is None
                    or event['previous_sha256']!=hashlib.sha256(_canonical(previous)).hexdigest()
                    or any(event[field]!=latest_publication[field] for field in (
                        'generation_id','published_sha256','project_key','scope','policy_sha256','publish_every_cycles'))
                    or event['cycle_id'] not in ids
                    or event['cycle_completion_sha256']!=cycles[ids.index(event['cycle_id'])].completion_sha256):
                raise AdmissionTerminalOrphan("shared retry does not bind prior publication and cycle")
        else: latest_publication=event
        normalized={key:event[key] for key in _EVENT_FIELDS}
        assess_shared_admission_step(previous,normalized,ids)
        previous=normalized
    return previous,tuple(records)


def read_shared_local_admission(token, store, prior_image: bytes | None) -> dict | None:
    """Verify the contiguous local C6 RECEIPT/event/completed-cycle chain.

    The caller injects the independently read latest C6 image; this leaf
    module does not import the C6 bridge or infer a missing event.
    """
    from monitor.issue_tracker_attempt_journal import _identity, _named, _read as held_read
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
            directory_identity = _identity(os.fstat(directory))
            original_files = {name: (held_read(directory, name, 16*1024),
                _identity(os.stat(name, dir_fd=directory, follow_symlinks=False)))
                for name in names}
            publication_names=[name for name in names if _ADMISSION.fullmatch(name)]
            if (not publication_names or any(_ADMISSION.fullmatch(name) is None and _RETRY.fullmatch(name) is None
                                 for name in names)
                    or {int(_ADMISSION.fullmatch(name).group(1))
                        for name in publication_names} != set(range(1, len(publication_names) + 1))):
                raise AdmissionTerminalOrphan(
                    "shared admission directory is incomplete")
            events = tuple(_json(_read(
                directory, f"admission-{number:020d}.json")[0], _EVENT_FIELDS)
                for number in range(1, len(publication_names) + 1))
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
        directory=_directory(owner.root_fd,'admissions')
        try:
            _named(owner.root_fd, 'admissions', directory, directory=True)
            if (_identity(os.fstat(directory)) != directory_identity
                    or set(os.listdir(directory))!=set(names)
                    or any((held_read(directory, name, 16*1024),
                        _identity(os.stat(name, dir_fd=directory, follow_symlinks=False))) != saved
                        for name, saved in original_files.items())):
                raise AdmissionHold("shared admission changed during read")
            latest,_records=_merge_shared_retry_events(directory,names,events,cycles)
            _named(owner.root_fd, 'admissions', directory, directory=True)
            if (_identity(os.fstat(directory)) != directory_identity
                    or set(os.listdir(directory)) != set(names)
                    or any((held_read(directory, name, 16*1024),
                        _identity(os.stat(name, dir_fd=directory, follow_symlinks=False))) != saved
                        for name, saved in original_files.items())):
                raise AdmissionHold("shared admission changed during read")
        finally: os.close(directory)
        return latest
    except (OSError, LocalCommitHold, CycleSourceHoldError, TypeError,
            AttributeError, KeyError, ValueError) as exc:
        if isinstance(exc, AdmissionHold):
            raise
        raise AdmissionHold("shared local admission evidence is unsafe") from exc


@contextmanager
def _hold_shared_retry_opportunity(writer_token,sheet_token,binding,unit,store,prior_image,*,boot_id,monotonic_ns):
    """Reserve ONE R2 opportunity before its actual durable original count.

    Caller must run protected sources and live continuity inside this scope,
    before a fixed launch. This necessary current-C6 guard grants no GO. A
    fault leaves INTENT unpaired and blocks every lane; no repair/reset API.
    """
    from monitor import issue_tracker_global_attempt_journal as global_journal
    from monitor.issue_tracker_attempt_journal import _read as held_read, _identity, _named
    from monitor.issue_tracker_online_target import inspect_project_online_target
    directory=original=None; failed=False; anomaly=None
    try:
        project=_owner(writer_token)
        directory=_directory(project.root_fd,'admissions')
        _named(project.root_fd,'admissions',directory,directory=True)
        directory_identity=_identity(os.fstat(directory))
        prior=read_shared_local_admission(writer_token,store,prior_image)
        if prior is None: raise AdmissionHold("retry has no C6 publication")
        inspect_project_online_target(writer_token,binding)
        sheet,parent,name,header=global_journal._inputs(sheet_token,binding,unit)
        before=global_journal.inspect_global_unit(sheet_token,binding,unit)
        if not 1<=before.attempt_count<6: raise AdmissionHold("retry count unavailable or exhausted")
        admitted_ns = time.monotonic_ns()
        if (type(boot_id) is not str or not boot_id or len(boot_id)>128 or any(char.isspace() for char in boot_id)
                or type(admitted_ns) is not int or type(monotonic_ns) is not int
                or not 1<=monotonic_ns<=admitted_ns):
            raise AdmissionHold("retry clock provenance is invalid")
        actual_policy=local_publish_interval(project.project)
        if actual_policy!=(prior['publish_every_cycles'],prior['policy_sha256']):
            raise AdmissionHold("retry policy changed")
        cycles=tuple(cycle for cycle in read_completed_cycle_evidence(store) if cycle.qualifying)
        all_cycles=read_completed_cycle_evidence(store)
        if not cycles or cycles[-1].cycle_id!=all_cycles[-1].cycle_id:
            raise AdmissionHold("retry current completed cycle is unproved")
        event={**prior,'lane':'retry','cycle_id':cycles[-1].cycle_id,
               'cycle_completion_sha256':cycles[-1].completion_sha256,'boot_id':boot_id,'monotonic_ns':admitted_ns}
        assess_shared_admission_step(prior,event,tuple(cycle.cycle_id for cycle in cycles))
        _named(project.root_fd,'admissions',directory,directory=True)
        if _identity(os.fstat(directory))!=directory_identity:
            raise AdmissionHold("retry admission directory changed before count")
        names=os.listdir(directory)
        originals={item:(held_read(directory,item,16*1024),_identity(os.stat(item,dir_fd=directory,follow_symlinks=False))) for item in names}
        retries=tuple(_json(raw,_RETRY_FIELDS) for item,(raw,_stat) in originals.items()
                      if _RETRY.fullmatch(item) and _RETRY.fullmatch(item).group(2)=='intent')
        own=sorted((record for record in retries if record['unit_id']==unit.unit_id),key=lambda record:record['attempt_count'])
        if before.attempt_count!=(own[-1]['attempt_count'] if own else 1):
            raise AdmissionHold("original retry count lacks shared admission")
        action=json.loads(unit.action_preimage)['identity']
        original_event=next((_json(raw,_EVENT_FIELDS) for item,(raw,_stat) in originals.items()
                             if _ADMISSION.fullmatch(item) and _json(raw,_EVENT_FIELDS)['generation_id']==action['generation_id']),None)
        if original_event is None or original_event['published_sha256']!=action['publish_id']:
            raise AdmissionHold("retry original unit does not bind C6 publication")
        sequence=len(retries)+1; count=before.attempt_count+1
        final_admitted_ns=time.monotonic_ns()
        if type(final_admitted_ns) is not int or final_admitted_ns<admitted_ns:
            raise AdmissionHold("retry clock moved during original validation")
        event={**event,'monotonic_ns':final_admitted_ns}
        assess_shared_admission_step(prior,event,tuple(cycle.cycle_id for cycle in cycles))
        intent={**event,'sequence':sequence,'unit_id':unit.unit_id,'wire_sha256':unit.wire_sha256,
                'action_digest':unit.action_digest,'attempt_count':count,
                'original_generation_id':action['generation_id'],'original_publish_id':action['publish_id'],
                'previous_sha256':hashlib.sha256(_canonical(prior)).hexdigest()}
        raw=_canonical(intent); intent_name=f'retry-{sequence:020d}-intent.json'
        _write_new(directory,intent_name,raw)
        yield
        if global_journal.inspect_global_unit(sheet_token,binding,unit).attempt_count!=count:
            raise AdmissionHold("retry original count not completed exactly once")
        if tuple(read_completed_cycle_evidence(store))!=tuple(all_cycles):
            raise AdmissionHold("retry completed source changed during count")
        inspect_project_online_target(writer_token,binding)
        if (local_publish_interval(project.project)!=actual_policy or _owner(writer_token) is not project
                or global_journal.ownership._validated_owner(sheet_token,binding) is not sheet
                or set(os.listdir(directory))!=set(names)|{intent_name}
                or any((held_read(directory,item,16*1024),_identity(os.stat(item,dir_fd=directory,follow_symlinks=False)))!=saved
                       for item,saved in originals.items()) or held_read(directory,intent_name,16*1024)!=raw):
            raise AdmissionHold("retry original admission changed during count")
        original=_directory(parent,name); _named(parent,name,original,directory=True)
        if global_journal._inspect(original,unit,header)[0]!=count: raise AdmissionHold("retry count changed")
        counted={'schema_version':1,'sequence':sequence,'unit_id':unit.unit_id,'attempt_count':count,
                 'intent_sha256':hashlib.sha256(raw).hexdigest(),
                 'original_attempt_sha256':hashlib.sha256(held_read(original,f'ATTEMPT-{count}',16*1024)).hexdigest()}
        _write_new(directory,f'retry-{sequence:020d}-count.json',_canonical(counted))
        _named(project.root_fd,'admissions',directory,directory=True)
        if read_shared_local_admission(writer_token,store,prior_image)!=event:
            raise AdmissionHold("retry final shared anchor differs")
    except AdmissionCollectorAnomaly:
        anomaly=True; failed=True
    except Exception: failed=True
    finally:
        for descriptor in (original,directory):
            if descriptor is not None:
                try: os.close(descriptor)
                except OSError: failed=True
    if anomaly: raise AdmissionCollectorAnomaly('collector_interval_below_minimum')
    if failed: raise AdmissionHold('shared retry admission unproved')
