"""Uninstalled C25 original-event allocation under BOTH actual owners.

This conservative first journal retains one unit per project until a future
COMPLETE/DELIVERED verifier exists. It never sends, consumes an outbox event,
repairs a partial journal, authorizes a source, or proves remote delivery.
"""
import hashlib
import json
import os

from monitor import issue_tracker_local_commit as local
from monitor import issue_tracker_attempt_journal as journal
from monitor import issue_tracker_k_chain as chain
from monitor import issue_tracker_k_store as settings
from monitor import issue_tracker_global_attempt_journal as global_journal
from monitor import issue_tracker_spreadsheet_owner as ownership

_FOLDER = 'settings-audit-allocation'
_LIMIT = 1024 * 1024


class SettingsAuditHold(ValueError):
    def __init__(self): super().__init__('req7_settings_audit_unproved')


def _settings(writer_token):
    """Reopen actual original settings, never accept a caller queue/snapshot."""
    owner = local._owner(writer_token)
    opened = []
    try:
        folder = local._directory(owner.root_fd, 'settings'); opened.append(folder)
        if set(os.listdir(folder)) != {'events', 'outbox', 'current'}: raise SettingsAuditHold()
        events = local._directory(folder, 'events'); opened.append(events)
        outbox = local._directory(folder, 'outbox'); opened.append(outbox)
        names = set(os.listdir(events))
        if (not names or any(settings._EVENT_NAME.fullmatch(name) is None for name in names)
                or set(os.listdir(outbox)) != names):
            raise SettingsAuditHold()
        raw_events = {int(name[:-5]): journal._read(events, name, 16384) for name in names}
        current = journal._read(folder, 'current', 16384)
        initialized = journal._read(owner.root_fd, 'INITIALIZED', 16384)
        chain.validate_k_chain_snapshot(raw_events, current, initialized)
        result = []
        for revision, raw in sorted(raw_events.items()):
            digest = hashlib.sha256(raw).hexdigest()
            expected = chain._canonical_line({'schema_version': 1, 'revision': revision, 'event_sha256': digest})
            if journal._read(outbox, f'{revision}.json', 16384) != expected: raise SettingsAuditHold()
            event = chain._parse(raw, chain._EVENT_KEYS)
            result.append((revision, digest, {'event_id': f'settings:{revision}:{digest}',
                'recorded_at_utc': event['recorded_at'], 'details': raw.decode('utf-8').rstrip('\n')}))
        if (set(os.listdir(events)) != names or set(os.listdir(outbox)) != names
                or set(os.listdir(folder)) != {'events', 'outbox', 'current'}
                or journal._read(folder, 'current', 16384) != current
                or journal._read(owner.root_fd, 'INITIALIZED', 16384) != initialized):
            raise SettingsAuditHold()
        journal._named(folder, 'events', events, directory=True)
        journal._named(folder, 'outbox', outbox, directory=True)
        journal._named(owner.root_fd, 'settings', folder, directory=True)
        local._owner(writer_token)
        return tuple(result)
    finally:
        for descriptor in reversed(opened): os.close(descriptor)


def pending_settings_audits(writer_token):
    """ALL committed events remain pending; allocation is NOT consumption."""
    failed = False
    try: result = tuple(dict(row[2]) for row in _settings(writer_token))
    except Exception: failed = True
    if failed: raise SettingsAuditHold()
    return result


def _originals(writer_token, spreadsheet_token, binding, unit):
    owner = local._owner(writer_token)
    _sheet_owner, _parent, _name, header = global_journal._inputs(spreadsheet_token, binding, unit)
    global_journal.inspect_global_unit(spreadsheet_token, binding, unit)
    audits = json.loads(unit.action_preimage.decode('utf-8'))['audits']
    if not audits: raise SettingsAuditHold()
    actual = {row[2]['event_id']: row for row in _settings(writer_token)}
    selected = []
    for audit in audits:
        revision, digest, original = actual[audit['event_id']]
        if audit != original: raise SettingsAuditHold()
        selected.append({'revision': revision, 'event_sha256': digest, 'audit': original})
    revisions = [row['revision'] for row in selected]
    if revisions != sorted(set(revisions)): raise SettingsAuditHold()
    assignments = local._canonical(selected)
    if not 1 <= len(assignments) <= _LIMIT: raise SettingsAuditHold()
    project, tracker = os.fstat(owner.project_fd), os.fstat(owner.root_fd)
    header = local._canonical({**header, 'project_identity': [project.st_dev, project.st_ino],
        'tracker_identity': [tracker.st_dev, tracker.st_ino]})
    return owner, header, assignments


def _marker(header, assignments):
    return local._canonical({'schema_version': 1, 'state': 'INITIALIZED',
        'header_sha256': hashlib.sha256(header).hexdigest(),
        'assignments_sha256': hashlib.sha256(assignments).hexdigest()})


def _inspect(parent, folder, header, assignments):
    if (set(os.listdir(folder)) != {'HEADER', 'ASSIGNMENTS', 'INITIALIZED'}
            or journal._read(folder, 'HEADER', 16384) != header
            or journal._read(folder, 'ASSIGNMENTS', _LIMIT) != assignments
            or journal._read(folder, 'INITIALIZED', 16384) != _marker(header, assignments)):
        raise SettingsAuditHold()
    journal._named(parent, _FOLDER, folder, directory=True)


def _sync_marker(parent, folder, header, assignments):
    # Confirm the original post-image-barrier marker and its durability; never
    # create a missing one or use a coherent-looking partial image as authority.
    descriptor = os.open('INITIALIZED', local._flags(), dir_fd=folder)
    try:
        info = local._check(descriptor, directory=False)
        journal._named(folder, 'INITIALIZED', descriptor, directory=False)
        raw = os.read(descriptor, 16385)
        if len(raw) != info.st_size or raw != _marker(header, assignments): raise SettingsAuditHold()
        os.fsync(descriptor); os.fsync(folder); os.fsync(parent)
        journal._named(folder, 'INITIALIZED', descriptor, directory=False)
    finally: os.close(descriptor)


def _observe(writer_token, spreadsheet_token, binding, unit, *, create):
    folder = None; failed = False
    try:
        owner, header, assignments = _originals(writer_token, spreadsheet_token, binding, unit)
        if create:
            # Allocation must precede ANY attempt; UNKNOWN never gains audits.
            if global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count != 0:
                raise SettingsAuditHold()
            if _FOLDER in os.listdir(owner.root_fd): raise SettingsAuditHold()
            folder = global_journal._create_folder(owner.root_fd, _FOLDER)
            local._write_new(folder, 'HEADER', header)
            local._write_new(folder, 'ASSIGNMENTS', assignments)
            if _originals(writer_token, spreadsheet_token, binding, unit)[1:] != (header, assignments):
                raise SettingsAuditHold()
            if global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count != 0:
                raise SettingsAuditHold()
            journal._named(owner.root_fd, _FOLDER, folder, directory=True)
            # ALL six image barriers precede the initialization marker.
            local._write_new(folder, 'INITIALIZED', _marker(header, assignments))
        else:
            folder = local._directory(owner.root_fd, _FOLDER)
        _inspect(owner.root_fd, folder, header, assignments)
        _sync_marker(owner.root_fd, folder, header, assignments)
        if _originals(writer_token, spreadsheet_token, binding, unit)[1:] != (header, assignments):
            raise SettingsAuditHold()
        ownership._validated_owner(spreadsheet_token, binding)
        local._owner(writer_token)
        _inspect(owner.root_fd, folder, header, assignments)
        if create and global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count != 0:
            raise SettingsAuditHold()
    except Exception: failed = True
    finally:
        if folder is not None:
            try: os.close(folder)
            except OSError: failed = True
    if failed: raise SettingsAuditHold()
    return assignments


def prepare_settings_audit_allocation(writer_token, spreadsheet_token, binding, unit):
    """Allocate ORIGINAL audit rows to an existing unattempted nonempty unit."""
    return _observe(writer_token, spreadsheet_token, binding, unit, create=True)


def inspect_settings_audit_allocation(writer_token, spreadsheet_token, binding, unit):
    """Read only retained original assignments, including across UNKNOWN retries."""
    return _observe(writer_token, spreadsheet_token, binding, unit, create=False)
