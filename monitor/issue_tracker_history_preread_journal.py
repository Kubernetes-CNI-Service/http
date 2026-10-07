"""Uninstalled immutable pre-send History image under the spreadsheet owner.

Creation requires a genuine, unattempted global action/wire journal and one
complete fixed full-tail response. Original bytes and boundary survive UNKNOWN
and cold processes; no backfill, reset, cleanup, network or completion. This
necessary observation does not authenticate the remote source or confer fresh
admission/transport permission. The fixed launcher must still dominate sends.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from types import SimpleNamespace
from urllib.parse import urlsplit

from monitor import issue_tracker_local_commit as local
from monitor import issue_tracker_attempt_journal as journal
from monitor import issue_tracker_global_attempt_journal as global_journal
from monitor import issue_tracker_spreadsheet_owner as ownership
from monitor import issue_tracker_sheets_read_decode as decode
from monitor.issue_tracker_sheets_read_plan import PreparedSheetsRead


class HistoryPrereadHold(ValueError):
    def __init__(self): super().__init__('req7_history_preread_unproved')


@dataclass(frozen=True)
class HistoryPrereadObservation:
    history_last_row_before_send: int
    row_count: int
    history_sheet_id: int
    source_sha256: str
    action_digest: str
    wire_sha256: str


def _inputs(token, binding, unit):
    owner, parent, name, header = global_journal._inputs(token, binding, unit)
    state = global_journal.inspect_global_unit(token, binding, unit)
    action = json.loads(unit.action_preimage.decode('utf-8'))
    return parent, name[:-8] + '.history', header, action['history_sheet_id'], state


def _header(base, plan, observed):
    return {**base, 'history_sheet_id': observed.sheet_id, 'history_last_row_before_send': observed.last_data_row_index,
            'row_count': observed.row_count, 'source_sha256': observed.source_sha256, 'read_path': plan.path}


def _marker(header):
    return local._canonical({'schema_version': 1, 'state': 'INITIALIZED',
                             'header_sha256': hashlib.sha256(local._canonical(header)).hexdigest()})


def _inspect(parent, name, folder, base, sheet_id):
    if set(os.listdir(folder)) != {'HISTORY-RAW', 'HEADER', 'INITIALIZED'}: raise HistoryPrereadHold()
    raw = journal._read(folder, 'HISTORY-RAW', 2 * 1024 * 1024)
    header_raw = journal._read(folder, 'HEADER', 16384)
    header = json.loads(header_raw.decode('utf-8'))
    if type(header) is not dict or type(header.get('read_path')) is not str: raise HistoryPrereadHold()
    if urlsplit(header['read_path']).path != '/v4/spreadsheets/' + base['spreadsheet_id']: raise HistoryPrereadHold()
    # Reconstruct only the fixed decode shape, without credentials or network.
    # The INITIALIZED marker below is mandatory: raw files alone are not a
    # completed preread or a license to manufacture a missing marker.
    plan = PreparedSheetsRead('sheets.googleapis.com', header['read_path'], 'GET', (), b'')
    observed = decode.decode_history_tail(plan, SimpleNamespace(status=200, complete=True, data=raw), sheet_id=sheet_id)
    expected = _header(base, plan, observed)
    if header_raw != local._canonical(expected): raise HistoryPrereadHold()
    fd = os.open('INITIALIZED', local._flags(), dir_fd=folder)
    try:
        info = local._check(fd, directory=False)
        journal._named(folder, 'INITIALIZED', fd, directory=False)
        marker = os.read(fd, 16385)
        if len(marker) != info.st_size or marker != _marker(expected): raise HistoryPrereadHold()
        os.fsync(fd); os.fsync(folder); os.fsync(parent)
        journal._named(folder, 'INITIALIZED', fd, directory=False)
    finally: os.close(fd)
    journal._named(parent, name, folder, directory=True)
    if set(os.listdir(folder)) != {'HISTORY-RAW', 'HEADER', 'INITIALIZED'}: raise HistoryPrereadHold()
    return HistoryPrereadObservation(observed.last_data_row_index, observed.row_count, sheet_id,
                                     observed.source_sha256, base['action_digest'], base['wire_sha256'])


def prepare_history_preread(token, binding, unit, plan, response):
    """New image before ATTEMPT-1 only; never overwrite/adopt/backfill a store."""
    folder = None; failed = False
    try:
        parent, name, base, sheet_id, state = _inputs(token, binding, unit)
        if state.attempt_count != 0 or name in os.listdir(parent): raise HistoryPrereadHold()
        observed = decode.decode_history_tail(plan, response, sheet_id=sheet_id)
        # Strict decoder binds raw target to the path; bind that path to the
        # genuine global journal too, not just to a caller's coherent plan.
        if urlsplit(plan.path).path != '/v4/spreadsheets/' + binding.spreadsheet_id: raise HistoryPrereadHold()
        header = _header(base, plan, observed)
        folder = global_journal._create_folder(parent, name)
        local._write_new(folder, 'HISTORY-RAW', response.data)
        local._write_new(folder, 'HEADER', local._canonical(header))
        journal._named(parent, name, folder, directory=True)
        ownership._validated_owner(token, binding)
        # Folder+parent and RAW/HEADER file+folder: six image barriers must
        # precede this marker. Failure retains the image as unadoptable HOLD.
        local._write_new(folder, 'INITIALIZED', _marker(header))
        _inspect(parent, name, folder, base, sheet_id)
        ownership._validated_owner(token, binding)
    except Exception: failed = True
    finally:
        if folder is not None:
            try: os.close(folder)
            except OSError: failed = True
    if failed: raise HistoryPrereadHold()


def inspect_history_preread(token, binding, unit):
    """Re-decode private original bytes, never substitute a later tail image."""
    folder = None; failed = False
    try:
        parent, name, base, sheet_id, _state = _inputs(token, binding, unit)
        folder = local._directory(parent, name)
        journal._named(parent, name, folder, directory=True)
        result = _inspect(parent, name, folder, base, sheet_id)
        ownership._validated_owner(token, binding)
    except Exception: failed = True
    finally:
        if folder is not None:
            try: os.close(folder)
            except OSError: failed = True
    if failed: raise HistoryPrereadHold()
    return result
