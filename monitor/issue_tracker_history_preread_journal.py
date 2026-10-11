"""Uninstalled immutable pre-send History image under the spreadsheet owner.

Creation requires a genuine, unattempted global action/wire journal and one
complete fixed full-tail response. Original bytes and boundary survive UNKNOWN
and cold processes; no backfill, reset, cleanup, network or completion. This
necessary observation does not authenticate the remote source or confer fresh
admission/transport permission. The fixed launcher must still dominate sends.
"""
from dataclasses import dataclass
from contextlib import contextmanager, ExitStack
import errno
import hashlib
import json
import os
import sys
import base64
import uuid
import threading
import weakref
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


_BUSINESS_READ_GUARDS = weakref.WeakKeyDictionary()
_BUSINESS_READ_GUARD_LOCK = threading.RLock()


class _OriginalBusinessReadGuard:
    """Actual helper identity only: LIVE originals or postclose issued reads.

    Constructing/copying this private value gives no registry record. It never
    grants admission or sending and accepts no replacement proof/callback.
    """
    __slots__ = ('__weakref__',)

    def __call__(self):
        self._check(issued_only=False)

    def _verify_issued_only(self):
        self._check(issued_only=True)

    def _original_issued_inputs(self):
        """LIVE actual read handback, not count/claim or a write-aware scope.

        Preserve genuine response identities and original deadlines. Each
        result has new business dictionaries; caller edits cannot mutate the
        frozen helper packet. CLOSED/FAILED holders cannot hand back inputs.
        The consumer still needs its own protected original write/count scope.
        """
        self()
        with _BUSINESS_READ_GUARD_LOCK:
            state = _BUSINESS_READ_GUARDS.get(self)
            if (type(self) is not _OriginalBusinessReadGuard or state is None
                    or state[0] != 'LIVE' or state[3] is None):
                raise HistoryPrereadHold()
            identity, history, business = state[3]
            result = identity, history, tuple(dict(item) for item in business)
        self()
        with _BUSINESS_READ_GUARD_LOCK:
            if _BUSINESS_READ_GUARDS.get(self) is not state or state[0] != 'LIVE':
                raise HistoryPrereadHold()
        return result

    @contextmanager
    def _hold_original_images(self):
        """Overlap the actual two directories/seven images, never reacquire.

        The strict original reader must finish normally before a writer may
        use this graph. Its issued response identities/deadlines remain checked;
        only its global read-only namespace/count snapshot is not transferred.
        This helper does not count, claim, send or prove G1 permission.
        """
        from monitor import issue_tracker_unit_catalog as catalog
        images = catalog._Originals(); live = [True]; failed = False
        try:
            # One complete LIVE check before capture, and verify() below after
            # ALL nine duplications. Do not recursively hand back through the
            # public helper and replay the same strict reader five times inside
            # one acquisition. The public helper's contract is unchanged.
            self()
            with _BUSINESS_READ_GUARD_LOCK:
                state = _BUSINESS_READ_GUARDS.get(self)
                if state is None or state[0] != 'LIVE' or state[3] is None or state[4] is None:
                    raise HistoryPrereadHold()
                identity, history, business = state[3]
                packet = identity, history, tuple(dict(item) for item in business)
                original = state[4]
            if (len(original.directories) != 2 or len(original.files) != 7
                    or original.directories[1][1] != original.directories[0][1][:-9] + '.history'):
                raise HistoryPrereadHold()
            source_parents = tuple(item[2] for item in original.directories)
            if ({name for parent, name, *_rest in original.files if parent == source_parents[0]}
                    != {'MANIFEST','BUSINESS-RAW','HEADER','INITIALIZED'}
                    or {name for parent, name, *_rest in original.files if parent == source_parents[1]}
                    != {'HISTORY-RAW','HEADER','INITIALIZED'}):
                raise HistoryPrereadHold()
            parents = {}
            for parent, name, fd, identity, names in original.directories:
                duplicate = os.dup(fd)
                images.directories.append((parent, name, duplicate, identity, names))
                if journal._identity(os.fstat(duplicate)) != identity:
                    raise HistoryPrereadHold()
                parents[fd] = duplicate
            for parent, name, fd, identity, raw in original.files:
                duplicate = os.dup(fd)
                images.files.append((parents[parent], name, duplicate, identity, raw))
                if journal._identity(os.fstat(duplicate)) != identity:
                    raise HistoryPrereadHold()
            def verify():
                if not live[0]: raise HistoryPrereadHold()
                try:
                    # LIVE still dominates its complete strict reader; CLOSED
                    # checks only the same actual issued auth/read registry.
                    with _BUSINESS_READ_GUARD_LOCK:
                        current = _BUSINESS_READ_GUARDS.get(self)
                        if current is not state: raise HistoryPrereadHold()
                        phase = current[0]
                    if phase == 'LIVE': self()
                    elif phase == 'CLOSED': self._verify_issued_only()
                    else: raise HistoryPrereadHold()
                    images.verify()
                    self._verify_issued_only()
                except BaseException as error:
                    live[0] = False
                    if isinstance(error, Exception):
                        raise HistoryPrereadHold() from None
                    raise
            verify()
            yield packet, verify
            verify()
        except Exception:
            failed = True
        finally:
            live[0] = False
            images.close()
        if failed: raise HistoryPrereadHold() from None
        # The generic graph closes only confirmed original inode slots. A
        # foreign reuse or unconfirmed cleanup must not become success here;
        # inspect without closing any still-live slot, even if it is foreign.
        for record in (*images.files, *images.directories):
            try:
                os.fstat(record[2])
            except OSError as error:
                if error.errno != errno.EBADF: raise HistoryPrereadHold() from None
            else:
                raise HistoryPrereadHold()
        # Cleanup can itself revoke the original issued authorization. Do not
        # return success using the pre-cleanup check or reopen closed images.
        self._verify_issued_only()

    def _check(self, *, issued_only):
        failed = False
        try:
            with _BUSINESS_READ_GUARD_LOCK:
                state = _BUSINESS_READ_GUARDS.get(self)
                if (type(self) is not _OriginalBusinessReadGuard or state is None
                        or state[0] not in (('LIVE', 'CLOSED') if issued_only else ('LIVE',))):
                    raise HistoryPrereadHold()
                verify = state[2 if issued_only else 1]
            try:
                verify()
            except BaseException:
                with _BUSINESS_READ_GUARD_LOCK:
                    state[:] = ['FAILED', None, None, None, None]
                raise
            with _BUSINESS_READ_GUARD_LOCK:
                if _BUSINESS_READ_GUARDS.get(self) is not state or state[0] == 'FAILED':
                    raise HistoryPrereadHold()
        except Exception:
            failed = True
        if failed:
            raise HistoryPrereadHold() from None


@dataclass(frozen=True)
class HistoryPrereadObservation:
    history_last_row_before_send: int
    row_count: int
    history_sheet_id: int
    source_sha256: str
    action_digest: str
    wire_sha256: str


@dataclass(frozen=True)
class HistoryAppendReservation:
    first_row_index: int
    last_row_index: int
    rows_reserved: int
    remaining_rows: int
    row_count: int
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
    return (HistoryPrereadObservation(observed.last_data_row_index, observed.row_count, sheet_id,
                                      observed.source_sha256, base['action_digest'], base['wire_sha256']), observed)


def prepare_history_preread(token, binding, unit, plan, response):
    """New image before ATTEMPT-1 only; never overwrite/adopt/backfill a store."""
    return _prepare_history_preread(token,binding,unit,plan,response)


def prepare_owned_project_history_preread(writer_token,owner_token,binding,authentication,unit,*,
                                         identity_response,history_response):
    """Actual issued project reads create a NEW original, never send authority.

    No caller plan, project ID, coordinates, freshness flag or verifier is
    accepted. Both responses must belong to the same actual authentication
    and remain current inside the final original-image inspection and after
    cleanup. Partial/late-failed images stay retained HOLD, never backfilled.
    """
    failed=False
    try:
        from monitor.issue_tracker_history_read_launcher import require_current_owned_project_read
        def current():
            identity_plan,project,digest=require_current_owned_project_read(writer_token,owner_token,
                binding,identity_response,authentication,read_kind='template_identity')
            history_plan,other_project,other_digest=require_current_owned_project_read(writer_token,owner_token,
                binding,history_response,authentication,read_kind='history_tail')
            if (project,digest)!=(other_project,other_digest): raise HistoryPrereadHold()
            return identity_plan,history_plan
        identity_plan,history_plan=current()
        identity=decode.decode_template_identity(identity_plan,identity_response)
        action=local._json(unit.action_preimage)
        if (dict(identity.sheet_ids).get('Update_History')!=action['history_sheet_id'] or
                dict(identity.sheet_ids).get(action['identity']['sheet'])!=action['identity']['sheet_id']):
            raise HistoryPrereadHold()
        current()
        _prepare_history_preread(owner_token,binding,unit,history_plan,history_response,revalidate=current)
        current()
    except Exception: failed=True
    if failed: raise HistoryPrereadHold() from None


def _prepare_history_preread(token,binding,unit,plan,response,*,revalidate=None):
    """Legacy creation unchanged; owned creation also pins its final originals."""
    folder = None; first_directory = None; originals = None; failed = False
    try:
        parent, name, base, sheet_id, state = _inputs(token, binding, unit)
        if state.attempt_count != 0 or name in os.listdir(parent): raise HistoryPrereadHold()
        observed = decode.decode_history_tail(plan, response, sheet_id=sheet_id)
        # Strict decoder binds raw target to the path; bind that path to the
        # genuine global journal too, not just to a caller's coherent plan.
        if urlsplit(plan.path).path != '/v4/spreadsheets/' + binding.spreadsheet_id: raise HistoryPrereadHold()
        header = _header(base, plan, observed)
        if revalidate is None:
            folder = global_journal._create_folder(parent, name)
            journal._write_read_image(folder, 'HISTORY-RAW', response.data)
            local._write_new(folder, 'HEADER', local._canonical(header))
        else:
            from monitor import issue_tracker_unit_catalog as catalog
            originals=catalog._Originals()
            folder,first_directory=global_journal._create_folder(parent,name,_return_original=True)
            originals._written_file(folder,'HISTORY-RAW',
                journal._write_read_image(folder,'HISTORY-RAW',response.data,_return_original=True),response.data,2*1024*1024)
            raw=local._canonical(header)
            originals._written_file(folder,'HEADER',local._write_new(folder,'HEADER',raw,_return_original=True),raw,16384)
        journal._named(parent, name, folder, directory=True)
        ownership._validated_owner(token, binding)
        # Folder+parent and RAW/HEADER file+folder: six image barriers must
        # precede this marker. Failure retains the image as unadoptable HOLD.
        if revalidate is None:
            local._write_new(folder, 'INITIALIZED', _marker(header))
        else:
            raw=_marker(header)
            originals._written_file(folder,'INITIALIZED',local._write_new(folder,'INITIALIZED',raw,_return_original=True),raw,16384)
            originals._written_directory(parent,name,folder,first_directory)
        if revalidate is None:
            _inspect(parent, name, folder, base, sheet_id)
        else:
            originals.verify(); revalidate()
            _inspect(parent,name,folder,base,sheet_id)
            originals.verify(); revalidate(); originals.verify()
        ownership._validated_owner(token, binding)
    except Exception: failed = True
    finally:
        primary=sys.exc_info()[1]; cleanup=None; finishers=[]
        if folder is not None:
            finishers.append(lambda: os.close(folder) if first_directory is None
                else local._close_written_original(folder,first_directory))
        if originals is not None:
            finishers.extend((lambda: (originals.verify(),revalidate(),originals.verify()),originals.close))
        # Every owned cleanup is attempted even if the actual creator close
        # interrupts. Never replace an incoming interrupt with a later error.
        for finish in finishers:
            try: finish()
            except BaseException as error:
                failed=True
                if not isinstance(error,Exception) and (primary is None or isinstance(primary,Exception)):
                    primary=error
                elif cleanup is None: cleanup=error
        if primary is not None and not isinstance(primary,Exception):
            if cleanup is not None: raise primary from cleanup
            raise primary
    if not failed and revalidate is not None:
        try: revalidate()
        except Exception: failed = True
    if failed: raise HistoryPrereadHold()


def _read_preread(token, binding, unit):
    """Re-decode the genuine original image and its boundary under ownership."""
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


@contextmanager
def _hold_owned_original_business_history_reads(writer_token, owner_token, binding, unit,
                                                authentication, *, identity_response):
    """Acquire fixed fresh reads from continuously held catalog originals.

    ALL original operations (including NOOP/operator cells) determine reads.
    No caller plan/coordinate/factory, recompilation, count, send or G1 GO.
    Original project authentication/read deadlines dominate the whole scope;
    original business/History descriptors survive inventory finalizers too.
    This continuity observation does not authenticate the business source.
    """
    failed = False; guard = None; completed = False
    try:
        from monitor import issue_tracker_retained_inventory as inventory
        from monitor import issue_tracker_unit_catalog as catalog
        from monitor.issue_tracker_history_read_launcher import (
            OwnedProjectSheetsReadUnit, require_current_owned_project_read)
        acquisitions = [(identity_response, 'template_identity', None, None)]
        def current():
            result = None
            for response, kind, sheet, row in acquisitions:
                plan, project, digest = require_current_owned_project_read(
                    writer_token, owner_token, binding, response, authentication,
                    read_kind=kind, sheet=sheet, row=row)
                if result is None:
                    result = plan, project, digest
                elif (project, digest) != result[1:]:
                    raise HistoryPrereadHold()
            return result[0]
        identity = decode.decode_template_identity(current(), identity_response)
        owner = ownership._validated_owner(owner_token, binding)
        parent = owner.directories[-1][0]; stem = owner.lock_name[:-5]
        held = catalog._Originals()
        def verify_originals():
            current()
            if ownership._validated_owner(owner_token, binding) is not owner:
                raise HistoryPrereadHold()
            held.verify(); current()
        def close_originals():
            try:
                verify_originals()
            finally:
                held.close()
        with ExitStack() as scope:
            scope.callback(close_originals)
            rows, verify_inventory = scope.enter_context(
                inventory._hold_catalog_retained_inventory(owner_token, binding))
            selected = tuple(item for item in rows if item.unit == unit)
            if len(selected) != 1 or not {'business', 'history'} <= set(selected[0].families):
                raise HistoryPrereadHold()
            # Select the actual catalog unit, never a supplied independent plan.
            unit = selected[0].unit
            actual_parent, name, base, state = _business_inputs(owner_token, binding, unit)
            if actual_parent != parent or state.attempt_count != selected[0].attempt_count:
                raise HistoryPrereadHold()
            held.namespace = (parent, stem + '.',
                              {entry for entry in os.listdir(parent) if entry.startswith(stem + '.')})
            business = held.directory(parent, name)
            originals = {}
            for entry in ('MANIFEST', 'BUSINESS-RAW', 'HEADER', 'INITIALIZED'):
                originals[entry], _stat = held.file(business, entry,
                    _BUSINESS_LIMIT if entry == 'BUSINESS-RAW' else 1024*1024 if entry == 'MANIFEST' else 16384)
            history = held.directory(parent, name[:-9] + '.history')
            for entry in ('HISTORY-RAW', 'HEADER', 'INITIALIZED'):
                held.file(history, entry, 2*1024*1024 if entry == 'HISTORY-RAW' else 16384)
            original = _inspect_business(owner_token, binding, identity, unit,
                                         parent, name, business, base)
            reads = _unpack_business(originals['BUSINESS-RAW'])
            sheet = json.loads(unit.action_preimage)['identity']['sheet']
            verify_originals(); verify_inventory()
            def acquire(kind, *, sheet=None, row=None):
                current(); verify_originals(); verify_inventory()
                response = OwnedProjectSheetsReadUnit(writer_token, owner_token, binding,
                    authentication, read_kind=kind, sheet=sheet, row=row).read_once()
                acquisitions.append((response, kind, sheet, row))
                # Last native read may have replaced an original with same bytes.
                verify_originals(); verify_inventory()
                return response
            history_response = acquire('history_tail')
            shared = {}; fresh = []
            for reading in reads:
                observed = {'operation_id': reading['operation_id']}
                for role, kind in (('discovery', 'activity'), ('occupancy', 'insertion'), ('row', 'row')):
                    plan = reading[role+'_plan']
                    if plan is None:
                        if role != 'row': raise HistoryPrereadHold()
                        observed[role+'_response'] = None
                        continue
                    row = None
                    if kind == 'row':
                        target, title, geometry = decode._geometry(plan)
                        if target != binding.spreadsheet_id or title != sheet or len(geometry) != 1:
                            raise HistoryPrereadHold()
                        (first, _column), (last, _end) = next(iter(geometry.items()))
                        if first != last: raise HistoryPrereadHold()
                        row = first + 1
                    key = kind, sheet, row
                    if key not in shared:
                        shared[key] = acquire(kind, sheet=sheet, row=row)
                    observed[role+'_response'] = shared[key]
                fresh.append(observed)
            fresh = tuple(fresh)
            def verify():
                verify_originals(); verify_inventory()
                result = observe_owned_business_continuity(writer_token, owner_token,
                    binding, unit, identity_response=identity_response,
                    history_response=history_response, business_reads=fresh)
                if result != original or global_journal.inspect_global_unit(owner_token, binding, unit) != state:
                    raise HistoryPrereadHold()
                verify_inventory(); verify_originals()
            verify(); held.sync(); verify()
            # Freeze only this helper's actual issued acquisitions. A later
            # unit/finalizer cannot refresh or substitute these original reads.
            acquisitions = tuple(acquisitions)
            guard = _OriginalBusinessReadGuard()
            with _BUSINESS_READ_GUARD_LOCK:
                _BUSINESS_READ_GUARDS[guard] = ['LIVE', verify, current,
                    (identity_response, history_response, tuple(tuple(item.items()) for item in fresh)), held]
            yield original, guard
            guard()
        # All finalizers have run; do not reuse a closed originals verifier.
        current()
        with _BUSINESS_READ_GUARD_LOCK:
            state = _BUSINESS_READ_GUARDS[guard]
            if state[0] != 'LIVE': raise HistoryPrereadHold()
            state[0] = 'CLOSED'; state[1] = None; state[3] = None; state[4] = None
        completed = True
    except Exception:
        failed = True
    finally:
        # Consumer/finalizer interruption, including BaseException, can never
        # become a successfully CLOSED holder or revive after registry repair.
        if guard is not None and not completed:
            with _BUSINESS_READ_GUARD_LOCK:
                state = _BUSINESS_READ_GUARDS.get(guard)
                if state is not None: state[:] = ['FAILED', None, None, None, None]
    if failed:
        raise HistoryPrereadHold() from None


def inspect_history_preread(token, binding, unit):
    """Re-decode private original bytes, never substitute a later tail image."""
    return _read_preread(token, binding, unit)[0]


def require_history_append_capacity(token, binding, unit):
    """Reserve ALL actual business/audit rows from immutable original capacity.

    Global ownership already blocks every new unit. The original before image
    and original wire durably fix this sole pending unit's row demand; no caller
    row count, current tail, replacement image or new allocation is accepted.
    UNKNOWN retains exactly the same reservation, not another append window.
    This is a capacity condition, NOT current-row freshness, CAS or permission.
    """
    failed = False
    try:
        original = inspect_history_preread(token, binding, unit)
        # _read_preread binds the real compiled unit and both immutable wire/
        # action to the global journal, including all piggyback audit rows and
        # excluding NOOP business rows. No caller-provided demand is used.
        rows = unit.history_rows_expected
        first = original.history_last_row_before_send + 1
        last = first + rows - 1
        if type(rows) is not int or not 1 <= rows <= 1000 or not 2 <= first <= last < original.row_count:
            raise HistoryPrereadHold()
        result = HistoryAppendReservation(first, last, rows, original.row_count - last - 1,
            original.row_count, original.source_sha256, original.action_digest, original.wire_sha256)
        ownership._validated_owner(token, binding)
    except Exception: failed = True
    if failed: raise HistoryPrereadHold()
    return result


@dataclass(frozen=True)
class BusinessPrereadObservation:
    operations_retained: int
    noop_operations: int
    preread_sha256: str
    source_sha256: str
    action_digest: str
    wire_sha256: str


_BUSINESS_LIMIT = 16 * 1024 * 1024
_READ_FIELDS = {'operation_id', 'discovery_plan', 'discovery_response', 'occupancy_plan',
                'occupancy_response', 'row_plan', 'row_response'}


def _pack_business(reads):
    """Only fixed GET paths and entire bounded raw bodies; never auth headers.

    Deduplicate shared images without truncation or silent chunking. The whole
    envelope has a distinct finite 16 MiB bound; each response remains 2 MiB.
    """
    if type(reads) is not tuple or not 1 <= len(reads) <= 1000: raise HistoryPrereadHold()
    images, operations, known = [], [], {}
    for reading in reads:
        if type(reading) is not dict or set(reading) != _READ_FIELDS: raise HistoryPrereadHold()
        references = {'operation_id': reading['operation_id']}
        for role in ('discovery', 'occupancy', 'row'):
            plan, response = reading[role+'_plan'], reading[role+'_response']
            if role == 'row' and plan is None and response is None:
                references[role] = None; continue
            if (type(plan) is not PreparedSheetsRead or plan.host != 'sheets.googleapis.com' or plan.method != 'GET'
                    or type(plan.path) is not str or not 1 <= len(plan.path) <= 16384 or plan.body != b''
                    or type(plan.budget_seconds) is not float or plan.budget_seconds != 30.0
                    or type(response.status) is not int or response.status != 200 or response.complete is not True
                    or type(response.data) is not bytes or not 1 <= len(response.data) <= 2*1024*1024): raise HistoryPrereadHold()
            key = (plan.path, response.data)
            if key not in known:
                known[key] = len(images)
                images.append({'path': plan.path, 'raw_base64': base64.b64encode(response.data).decode('ascii')})
                if sum(len(item['raw_base64']) + len(item['path']) for item in images) > _BUSINESS_LIMIT: raise HistoryPrereadHold()
            references[role] = known[key]
        operations.append(references)
    raw = local._canonical({'schema_version': 1, 'images': images, 'operations': operations})
    if len(raw) > _BUSINESS_LIMIT: raise HistoryPrereadHold()
    return raw


def _unpack_business(raw):
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=local._pairs)
    if (type(value) is not dict or set(value) != {'schema_version', 'images', 'operations'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or type(value['images']) is not list or not 1 <= len(value['images']) <= 3000
            or type(value['operations']) is not list or not 1 <= len(value['operations']) <= 1000): raise HistoryPrereadHold()
    images = []
    for item in value['images']:
        if type(item) is not dict or set(item) != {'path', 'raw_base64'}: raise HistoryPrereadHold()
        images.append((PreparedSheetsRead('sheets.googleapis.com', item['path'], 'GET', (), b''),
            SimpleNamespace(status=200, complete=True, data=base64.b64decode(item['raw_base64'], validate=True))))
    reads = []
    for operation in value['operations']:
        if type(operation) is not dict or set(operation) != {'operation_id', 'discovery', 'occupancy', 'row'}: raise HistoryPrereadHold()
        reading = {'operation_id': operation['operation_id']}
        for role in ('discovery', 'occupancy', 'row'):
            index = operation[role]
            if role == 'row' and index is None: plan, response = None, None
            else:
                if type(index) is not int or not 0 <= index < len(images): raise HistoryPrereadHold()
                plan, response = images[index]
            reading[role+'_plan'], reading[role+'_response'] = plan, response
        reads.append(reading)
    result = tuple(reads)
    if _pack_business(result) != raw: raise HistoryPrereadHold()
    return result


def _request_literals(item, sheet_id, row_index):
    """Extract only literal cells; real C8 re-encoding below checks exact runs."""
    from monitor.issue_tracker_online_cells import _column
    values = {}
    for request in item['requests']:
        if type(request) is not dict or len(request) != 1: raise HistoryPrereadHold()
        if row_index is None:
            body = request['appendCells']; start = 0
            if set(body) != {'sheetId', 'rows', 'fields'} or type(body['sheetId']) is not int or body['sheetId'] != sheet_id: raise HistoryPrereadHold()
        else:
            body = request['updateCells']; position = body['start']
            if (set(body) != {'start', 'rows', 'fields'} or set(position) != {'sheetId', 'rowIndex', 'columnIndex'}
                    or any(type(position[name]) is not int for name in position)
                    or position['sheetId'] != sheet_id or position['rowIndex'] != row_index): raise HistoryPrereadHold()
            start = position['columnIndex']
        if (body['fields'] != 'userEnteredValue' or type(body['rows']) is not list or len(body['rows']) != 1
                or set(body['rows'][0]) != {'values'}): raise HistoryPrereadHold()
        for offset, cell in enumerate(body['rows'][0]['values']):
            if cell == {} and row_index is None: continue
            if (type(cell) is not dict or set(cell) != {'userEnteredValue'}
                    or type(cell['userEnteredValue']) is not dict or set(cell['userEnteredValue']) != {'stringValue'}): raise HistoryPrereadHold()
            column = start + offset
            letter = next((name for name in (*tuple(chr(65+i) for i in range(26)), 'AA', 'AB', 'AC') if _column(name) == column), None)
            if letter is None or letter in values: raise HistoryPrereadHold()
            values[letter] = cell['userEnteredValue']['stringValue']
    return values


def _business_image(token, binding, identity, unit, manifest, reads, *, source_rows=None):
    from monitor.issue_tracker_enrollment_journal import require_unit_enrollment
    from monitor.issue_tracker_nv_reservation import require_unit_nv_reservation
    from monitor.issue_tracker_manifest import _validated_operations, _runtime_operation
    from monitor.issue_tracker_online_cells import encode_tool_cells, source_tool_values
    require_unit_enrollment(token, binding, identity, unit)
    original_history = inspect_history_preread(token, binding, unit)
    _owner, parent, _name, _base = global_journal._inputs(token, binding, unit)
    history_folder = local._directory(parent, _name[:-8]+'.history')
    try: history_path = json.loads(journal._read(history_folder, 'HEADER', 16384))['read_path']
    finally: os.close(history_folder)
    action = json.loads(unit.action_preimage); target = action['identity']; sheet, sid = target['sheet'], target['sheet_id']
    if (type(manifest) is not bytes or not 1 <= len(manifest) <= 1024*1024
            or hashlib.sha256(manifest).hexdigest() != action['manifest_id']): raise HistoryPrereadHold()
    document = json.loads(manifest.decode('utf-8'), object_pairs_hook=local._pairs)
    if (local._canonical(document) != manifest or type(document['operations']) is not list or len(document['operations']) > 1000
            or type(document['schema_version']) is not int or document['schema_version'] != 1): raise HistoryPrereadHold()
    family = {'ETH&IB Switch': 'switch', 'ETH Cabling': 'eth_cabling', 'IB Cabling': 'ib_cabling'}[sheet]
    all_operations = _validated_operations(document['operations'], 'original business', validator=_runtime_operation)
    operations = [op for op in all_operations if op['activity_key'][0] == family]
    sources = None
    if source_rows is not None:
        if type(source_rows) is not tuple or not 1 <= len(source_rows) <= 1000: raise HistoryPrereadHold()
        sources = {row.activity_key: row for row in source_rows}
        if (len(sources) != len(source_rows) or set(sources) != {tuple(op['activity_key']) for op in all_operations}):
            raise HistoryPrereadHold()
        for row in source_rows: source_tool_values(row, 'update')
    if len(operations) != len(reads) or len(operations) != len(action['decisions']): raise HistoryPrereadHold()
    missing, shared, classified = [], None, []
    for operation, reading in zip(operations, reads):
        key = tuple(operation['activity_key'])
        if operation['operation_id'] != reading['operation_id']: raise HistoryPrereadHold()
        found, cells, actual_target = decode._activity_sheet_image(reading['discovery_plan'], reading['discovery_response'], sheet_id=sid, activity_key=key)
        occupied, capacity, occupancy_sha = decode._insertion_sheet_image(reading['occupancy_plan'], reading['occupancy_response'], sheet_id=sid, title=sheet, target=binding.spreadsheet_id)
        originals = {(index, column): value for index, column, value in occupied}
        if actual_target != binding.spreadsheet_id or found.sheet_title != sheet or capacity != found.row_count or any(originals.get((index, column)) != value for index, column, value in cells): raise HistoryPrereadHold()
        current = (reading['discovery_plan'].path, found.source_sha256, reading['occupancy_plan'].path, occupancy_sha)
        if shared is not None and shared != current: raise HistoryPrereadHold()
        shared = current
        if not found.active_rows: missing.append(key)
        classified.append((operation, reading, found))
    nv = require_unit_nv_reservation(token, binding, identity, unit) if sheet != 'ETH&IB Switch' and missing else None
    if nv is not None and (nv.eth_source_sha256 if sheet == 'ETH Cabling' else nv.ib_source_sha256) != shared[1]: raise HistoryPrereadHold()
    sent = {item['operation_id']: item for item in action['business']}; reservations, images, noops = [], [], 0
    for (operation, reading, found), decision in zip(classified, action['decisions']):
        if decision['operation_id'] != operation['operation_id']: raise HistoryPrereadHold()
        action_type = 'update' if found.active_rows else 'insert'; key = tuple(operation['activity_key'])
        if action_type == 'update':
            seen = decode.observe_active_row(reading['discovery_plan'], reading['discovery_response'], reading['row_plan'], reading['row_response'], sheet_id=sid, activity_key=key)
        else:
            seen = decode.observe_insertion_position(reading['discovery_plan'], reading['discovery_response'], reading['occupancy_plan'], reading['occupancy_response'], sheet_id=sid, activity_key=key,
                reserved_row_indexes=tuple(reservations) if sheet == 'ETH&IB Switch' else (), append_rows=1 if sheet == 'ETH&IB Switch' else len(missing), row_plan=reading['row_plan'], row_response=reading['row_response'])
        if sheet == 'ETH&IB Switch' or action_type == 'update':
            if seen.row_index in reservations: raise HistoryPrereadHold()
            reservations.append(seen.row_index)
        row_index = None if sheet != 'ETH&IB Switch' and action_type == 'insert' else seen.row_index
        original_cells = {column: dict(value) for _index, column, value in seen.cells}
        item = sent.get(operation['operation_id'])
        if item is None:
            if action_type != 'update' or decision['outcome'] != 'OBSERVED-SATISFIED-AT-READ': raise HistoryPrereadHold()
            columns = ('L',) if sheet == 'ETH&IB Switch' else ('G', 'M', 'N', 'S', 'T')
            if any(set(original_cells[column]) != {'stringValue'} for column in columns): raise HistoryPrereadHold()
            values = {column: original_cells[column]['stringValue'] for column in columns}; noops += 1
        else:
            if item['activity_key'] != operation['activity_key'] or item['action'] != action_type: raise HistoryPrereadHold()
            values = _request_literals(item, sid, row_index)
            if row_index is None and values['A'] != dict(nv.reservations)[key]: raise HistoryPrereadHold()
        if sources is not None:
            source = sources[key]
            required = source_tool_values(source, action_type,
                reserved_id=dict(nv.reservations)[key] if row_index is None else None)
            if values != required or (item is not None and item['recorded_at_utc'] != source.recorded_at_utc):
                raise HistoryPrereadHold()
        encoded = encode_tool_cells(sheet, sid, action_type, values, row_index=row_index,
            observed_values=None if row_index is None else {column: original_cells[column] for column in values})
        if encoded.intended_sha256 != decision['intended_sha256'] or encoded.outcome != decision['outcome'] or (item is not None and json.loads(encoded.requests_json) != item['requests']): raise HistoryPrereadHold()
        image = {'operation_id': operation['operation_id'], 'discovery_path': reading['discovery_plan'].path,
            'discovery_sha256': found.source_sha256, 'occupancy_path': reading['occupancy_plan'].path,
            'occupancy_sha256': shared[3], 'row_path': reading['row_plan'].path if row_index is not None else None, 'row_sha256': seen.row_sha256}
        if sheet != 'ETH&IB Switch': image['append_start_row_index'] = seen.row_index if action_type == 'insert' else None
        images.append(image)
    combined = {'schema_version': 1, 'spreadsheet_id': binding.spreadsheet_id, 'sheet': sheet, 'sheet_id': sid,
        'history_sheet_id': original_history.history_sheet_id, 'history_path': history_path, 'history_sha256': original_history.source_sha256, 'business': images}
    if sheet != 'ETH&IB Switch': combined['nv_journal_sha256'] = nv.journal_sha256 if nv else None
    digest = hashlib.sha256(local._canonical(combined)).hexdigest()
    if digest != action['preread_sha256'] or inspect_history_preread(token, binding, unit) != original_history: raise HistoryPrereadHold()
    return len(operations), noops, digest


def _write_business_image(folder, raw, *, _return_original=False):
    # Narrow fixed filename/bound; never broaden the original 1 MiB wire or
    # four-name 2 MiB raw-image writer. Partial files remain fail-closed.
    if type(raw) is not bytes or not 1 <= len(raw) <= _BUSINESS_LIMIT or type(_return_original) is not bool: raise HistoryPrereadHold()
    if _return_original:
        return journal._write_first_read_image(folder,'BUSINESS-RAW',raw)
    pending = '.pending-'+uuid.uuid4().hex
    fd = os.open(pending, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC, 0o600, dir_fd=folder)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            if count <= 0: raise HistoryPrereadHold()
            view = view[count:]
        os.fsync(fd)
    finally: os.close(fd)
    local._rename_new(folder, pending, 'BUSINESS-RAW'); os.fsync(folder)


def _business_inputs(token, binding, unit):
    _owner, parent, name, base = global_journal._inputs(token, binding, unit)
    state = global_journal.inspect_global_unit(token, binding, unit)
    return parent, name[:-8]+'.business', base, state


def _inspect_business(token, binding, identity, unit, parent, name, folder, base, *, source_rows=None):
    if set(os.listdir(folder)) != {'MANIFEST', 'BUSINESS-RAW', 'HEADER', 'INITIALIZED'}: raise HistoryPrereadHold()
    names = ('MANIFEST', 'BUSINESS-RAW', 'HEADER', 'INITIALIZED')
    originals = tuple(journal._identity(os.stat(item, dir_fd=folder, follow_symlinks=False)) for item in names)
    manifest = journal._read(folder, 'MANIFEST', 1024*1024); raw = journal._read(folder, 'BUSINESS-RAW', _BUSINESS_LIMIT)
    count, noops, digest = _business_image(token, binding, identity, unit, manifest, _unpack_business(raw), source_rows=source_rows)
    header = {**base, 'preread_sha256': digest, 'source_sha256': hashlib.sha256(raw).hexdigest(), 'operations_retained': count, 'noop_operations': noops}
    if journal._read(folder, 'HEADER', 16384) != local._canonical(header): raise HistoryPrereadHold()
    global_journal._sync_initialization(parent, folder, header)
    journal._named(parent, name, folder, directory=True)
    if set(os.listdir(folder)) != {'MANIFEST', 'BUSINESS-RAW', 'HEADER', 'INITIALIZED'}: raise HistoryPrereadHold()
    ownership._validated_owner(token, binding)
    # Observation spans decoding and final durability/owner checks. Reopening
    # current bytes alone cannot detect same-byte pathname replacement; retain
    # original inode/stat identities too, and never silently adopt the new file.
    if (journal._read(folder, 'MANIFEST', 1024*1024) != manifest
            or journal._read(folder, 'BUSINESS-RAW', _BUSINESS_LIMIT) != raw
            or journal._read(folder, 'HEADER', 16384) != local._canonical(header)
            or journal._read(folder, 'INITIALIZED', 16384) != _marker(header)
            or _business_image(token, binding, identity, unit, manifest, _unpack_business(raw), source_rows=source_rows) != (count, noops, digest)
            or tuple(journal._identity(os.stat(item, dir_fd=folder, follow_symlinks=False)) for item in names) != originals): raise HistoryPrereadHold()
    journal._named(parent, name, folder, directory=True)
    return BusinessPrereadObservation(count, noops, digest, header['source_sha256'], unit.action_digest, unit.wire_sha256)


def prepare_business_preread(token, binding, identity, unit, *, manifest, business_reads, **claims):
    """NEW original observation, before ATTEMPT-1; not provenance/send authority.

    Re-decode ALL original operations including NOOP, bind original History,
    enrollment/NV and exact frozen action/wire. No regeneration after UNKNOWN,
    arbitrary coordinate/credential storage, row settlement or COMPLETE.
    """
    return _prepare_business_preread(token,binding,identity,unit,
        manifest=manifest,business_reads=business_reads,claims=claims)


def prepare_owned_project_business_preread(writer_token,owner_token,binding,authentication,generation,unit,*,
                                          identity_response,business_reads):
    """NEW original C6 manifest plus actual same-project ALL business reads.

    Plans/coordinates derive from issued responses and immutable operations;
    no caller manifest, verifier or freshness/admission claim is accepted. C6
    original FD overlap remains live through creator and C6-scope cleanup.
    This stores observations, never COUNT, CLAIM, COMPLETE or send authority.
    """
    failed=False; originals=None
    try:
        from monitor import issue_tracker_remote_history_match as remote, issue_tracker_unit_catalog as catalog
        from monitor.issue_tracker_history_read_launcher import require_current_owned_project_read
        action=local._json(unit.action_preimage); sheet=action['identity']['sheet']
        def issued(response,kind,*,sheet=None,row=None):
            return require_current_owned_project_read(writer_token,owner_token,binding,response,
                authentication,read_kind=kind,sheet=sheet,row=row)
        def current_reads():
            identity_plan,project,digest=issued(identity_response,'template_identity')
            if type(business_reads) is not tuple or not 1<=len(business_reads)<=1000:
                raise HistoryPrereadHold()
            result=[]
            for reading in business_reads:
                if (type(reading) is not dict or set(reading)!=
                        {'operation_id','discovery_response','occupancy_response','row_response'}):
                    raise HistoryPrereadHold()
                converted={'operation_id':reading['operation_id']}
                for role,kind in (('discovery','activity'),('occupancy','insertion'),('row','row')):
                    response=reading[role+'_response']; row=None
                    if response is None:
                        if role!='row' or sheet=='ETH&IB Switch': raise HistoryPrereadHold()
                        plan=None
                    else:
                        if role=='row':
                            # Actual response coordinate, not a caller plan.
                            # Issuer and full business decoder both validate it.
                            document=json.loads(response.data.decode('utf-8','strict'),
                                object_pairs_hook=decode._pairs,parse_constant=decode._nonfinite)
                            first=document['sheets'][0]['data'][0]['startRow']
                            if type(first) is not int or first<2: raise HistoryPrereadHold()
                            row=first+1
                        plan,other_project,other_digest=issued(response,kind,sheet=sheet,row=row)
                        if (other_project,other_digest)!=(project,digest): raise HistoryPrereadHold()
                    converted[role+'_plan']=plan; converted[role+'_response']=response
                result.append(converted)
            return decode.decode_template_identity(identity_plan,identity_response),tuple(result)
        identity,actual=current_reads()
        originals=catalog._Originals()
        with remote._hold_applied_generation(writer_token,generation,unit) as (owner,verify_c6,facts,_operations):
            verify_c6()
            ancestors=originals.directory(owner.root_fd,'generations')
            folder=originals.directory(ancestors,generation.generation_id)
            if list(journal._identity(os.fstat(folder)))!=facts['generation_directory_identity']:
                raise HistoryPrereadHold()
            manifest=None; receipt=None
            for entry in ('STATE','MANIFEST','INTENT','RECEIPT'):
                raw,image_identity=originals.file(folder,entry,1024*1024)
                if (list(image_identity)!=facts['files'][entry]['identity'] or
                        hashlib.sha256(raw).hexdigest()!=facts['files'][entry]['sha256']): raise HistoryPrereadHold()
                if entry=='MANIFEST': manifest=raw
                elif entry=='RECEIPT': receipt=local._json(raw)
            published=receipt['published']
            raw,image_identity=originals.file(owner.publication_fd,published,local._MAX_XLSX)
            if (list(image_identity)!=facts['files'][published]['identity'] or
                    hashlib.sha256(raw).hexdigest()!=facts['files'][published]['sha256']): raise HistoryPrereadHold()
            def current():
                if local._owner(writer_token) is not owner: raise HistoryPrereadHold()
                current_reads(); originals.verify(); verify_c6(); originals.verify()
            current()
            _prepare_business_preread(owner_token,binding,identity,unit,
                manifest=manifest,business_reads=actual,claims={},revalidate=current,created_originals=originals)
            current()
        # The overlap graph was acquired while the old C6 FDs were still live;
        # it detects substitution during their finalizers without reopening.
        originals.verify(); current_reads(); originals.verify()
    except Exception: failed=True
    finally:
        if originals is not None:
            try: originals.close()
            except Exception: failed=True
    if not failed:
        try: current_reads()
        except Exception: failed=True
    if failed: raise HistoryPrereadHold() from None


def _prepare_business_preread(token,binding,identity,unit,*,manifest,business_reads,claims,
                             revalidate=None,created_originals=None):
    """Legacy contract plus internal actual-source final-boundary checking."""
    folder = None; first_directory = None; originals = None; failed = False
    try:
        parent, name, base, state = _business_inputs(token, binding, unit)
        if claims or state.attempt_count or name in os.listdir(parent): raise HistoryPrereadHold()
        raw = _pack_business(business_reads); reads = _unpack_business(raw)
        count, noops, digest = _business_image(token, binding, identity, unit, manifest, reads)
        header = {**base, 'preread_sha256': digest, 'source_sha256': hashlib.sha256(raw).hexdigest(), 'operations_retained': count, 'noop_operations': noops}
        if revalidate is None:
            folder = global_journal._create_folder(parent, name)
            local._write_new(folder, 'MANIFEST', manifest); _write_business_image(folder, raw)
            local._write_new(folder, 'HEADER', local._canonical(header))
        else:
            from monitor import issue_tracker_unit_catalog as catalog
            originals=created_originals if created_originals is not None else catalog._Originals()
            folder,first_directory=global_journal._create_folder(parent,name,_return_original=True)
            originals._written_file(folder,'MANIFEST',local._write_new(folder,'MANIFEST',manifest,_return_original=True),manifest,1024*1024)
            originals._written_file(folder,'BUSINESS-RAW',_write_business_image(folder,raw,_return_original=True),raw,_BUSINESS_LIMIT)
            header_raw=local._canonical(header)
            originals._written_file(folder,'HEADER',local._write_new(folder,'HEADER',header_raw,_return_original=True),header_raw,16384)
        if (_pack_business(business_reads) != raw or _business_image(token, binding, identity, unit, manifest, reads) != (count, noops, digest)
                or global_journal.inspect_global_unit(token, binding, unit) != state): raise HistoryPrereadHold()
        journal._named(parent, name, folder, directory=True); ownership._validated_owner(token, binding)
        if revalidate is None:
            local._write_new(folder, 'INITIALIZED', _marker(header))
        else:
            marker=_marker(header)
            originals._written_file(folder,'INITIALIZED',local._write_new(folder,'INITIALIZED',marker,_return_original=True),marker,16384)
            originals._written_directory(parent,name,folder,first_directory)
        if revalidate is None:
            _inspect_business(token,binding,identity,unit,parent,name,folder,base)
        else:
            originals.verify(); revalidate()
            _inspect_business(token,binding,identity,unit,parent,name,folder,base)
            originals.verify(); revalidate(); originals.verify()
    except Exception: failed = True
    finally:
        primary=sys.exc_info()[1]; cleanup=None; finishers=[]
        if folder is not None:
            finishers.append(lambda: os.close(folder) if first_directory is None
                else local._close_written_original(folder,first_directory))
        if originals is not None and created_originals is None:
            finishers.extend((lambda: (originals.verify(),revalidate(),originals.verify()),originals.close))
        # Borrowed C6 originals remain owned by the outer creator; do not
        # close them here or skip its finalizer when the folder interrupts.
        for finish in finishers:
            try: finish()
            except BaseException as error:
                failed=True
                if not isinstance(error,Exception) and (primary is None or isinstance(primary,Exception)):
                    primary=error
                elif cleanup is None: cleanup=error
        if primary is not None and not isinstance(primary,Exception):
            if cleanup is not None: raise primary from cleanup
            raise primary
    if not failed and revalidate is not None:
        try: revalidate()
        except Exception: failed = True
    if failed: raise HistoryPrereadHold()


def inspect_business_preread(token, binding, identity, unit):
    """Cold re-decode from genuine originals only, never re-read current rows."""
    folder = None; failed = False
    try:
        parent, name, base, _state = _business_inputs(token, binding, unit)
        folder = local._directory(parent, name); journal._named(parent, name, folder, directory=True)
        result = _inspect_business(token, binding, identity, unit, parent, name, folder, base)
    except Exception: failed = True
    finally:
        if folder is not None:
            try: os.close(folder)
            except OSError: failed = True
    if failed: raise HistoryPrereadHold()
    return result


def inspect_business_source_projection(token, binding, identity, unit, source_rows):
    """Compare ALL original wire/NOOP values with a supplied source projection.

    Typed rows alone are NOT provenance. The original-count gate must first
    replay protected C5, derive these rows itself, and recheck after inspection.
    Re-decode original four files and original coordinates/nonces/NV only;
    compare real C8 source values and original timestamps without recompiling,
    modifying or shrinking wire/decisions after UNKNOWN. No remote read,
    permit, fresh admission, APPLIED, settlement or COMPLETE is issued.
    """
    folder = None; failed = False
    try:
        if source_rows is None: raise HistoryPrereadHold()
        parent, name, base, _state = _business_inputs(token, binding, unit)
        folder = local._directory(parent, name); journal._named(parent, name, folder, directory=True)
        result = _inspect_business(token, binding, identity, unit, parent, name, folder, base, source_rows=source_rows)
    except Exception: failed = True
    finally:
        if folder is not None:
            try: os.close(folder)
            except OSError: failed = True
    if failed: raise HistoryPrereadHold()
    return result


def observe_owned_business_continuity(writer_token, owner_token, binding, unit, *,
                                      identity_response, history_response, business_reads):
    """Fresh actual fixed reads versus ALL immutable originals, never GO.

    Includes NOOP and operator cells, retains original coordinates/action/wire.
    Conservative whole-response equality (ignoring JSON serialization only)
    refuses any edit or changed capacity, rather than rebuilding after UNKNOWN.
    Non-atomic reads cannot supply CAS, hidden quota, cadence or COMPLETE.
    No caller plan, identity, row coordinate or freshness flag is accepted.
    """
    folder = None; history_folder = None; failed = False
    try:
        from monitor.issue_tracker_history_read_launcher import require_current_owned_read
        def issued(response, kind, *, sheet=None, row=None):
            return require_current_owned_read(writer_token,owner_token,binding,response,
                                              read_kind=kind,sheet=sheet,row=row)
        identity_plan = issued(identity_response,'template_identity')
        history_plan = issued(history_response,'history_tail')
        identity = decode.decode_template_identity(identity_plan,identity_response)
        parent,name,base,state = _business_inputs(owner_token,binding,unit)
        folder = local._directory(parent,name); journal._named(parent,name,folder,directory=True)
        names = ('MANIFEST','BUSINESS-RAW','HEADER','INITIALIZED')
        identities = tuple(journal._identity(os.stat(item,dir_fd=folder,follow_symlinks=False)) for item in names)
        result = _inspect_business(owner_token,binding,identity,unit,parent,name,folder,base)
        raw = journal._read(folder,'BUSINESS-RAW',_BUSINESS_LIMIT)
        originals = _unpack_business(raw)
        if type(business_reads) is not tuple or len(business_reads) != len(originals): raise HistoryPrereadHold()
        action = json.loads(unit.action_preimage); sheet = action['identity']['sheet']
        history_name = name[:-9]+'.history'
        history_folder = local._directory(parent,history_name)
        journal._named(parent,history_name,history_folder,directory=True)
        history_names = ('HISTORY-RAW','HEADER','INITIALIZED')
        history_identities = tuple(journal._identity(os.stat(item,dir_fd=history_folder,follow_symlinks=False)) for item in history_names)
        old_history,old_tail = _read_preread(owner_token,binding,unit)
        new_tail = decode.decode_history_tail(history_plan,history_response,sheet_id=action['history_sheet_id'])
        if (new_tail.row_count != old_tail.row_count or new_tail.last_data_row_index != old_tail.last_data_row_index
                or new_tail.cells != old_tail.cells): raise HistoryPrereadHold()
        def document(body):
            value = json.loads(body.decode('utf-8','strict'),object_pairs_hook=decode._pairs,parse_constant=decode._nonfinite)
            # Canonical bytes distinguish JSON booleans/numbers/string types.
            return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8')
        checks = []
        for original,current in zip(originals,business_reads):
            fields = {'operation_id','discovery_response','occupancy_response','row_response'}
            if (type(current) is not dict or set(current) != fields
                    or current['operation_id'] != original['operation_id']): raise HistoryPrereadHold()
            for role,kind in (('discovery','activity'),('occupancy','insertion'),('row','row')):
                plan,response = original[role+'_plan'],current[role+'_response']
                if plan is None:
                    if role != 'row' or response is not None: raise HistoryPrereadHold()
                    continue
                row = None
                if role == 'row':
                    _target,title,geometry = decode._geometry(plan)
                    if title != sheet or len(geometry) != 1: raise HistoryPrereadHold()
                    (first,_column),(last,_end) = next(iter(geometry.items()))
                    if first != last: raise HistoryPrereadHold()
                    row = first+1
                actual_plan = issued(response,kind,sheet=sheet,row=row)
                if (actual_plan.path != plan.path
                        or document(response.data) != document(original[role+'_response'].data)): raise HistoryPrereadHold()
                checks.append((response,kind,row))
        # Originals and acquisition identity must survive the entire observation.
        for response,kind,row in checks: issued(response,kind,sheet=sheet,row=row)
        issued(identity_response,'template_identity'); issued(history_response,'history_tail')
        if (_inspect_business(owner_token,binding,identity,unit,parent,name,folder,base) != result
                or _read_preread(owner_token,binding,unit) != (old_history,old_tail)
                or global_journal.inspect_global_unit(owner_token,binding,unit) != state
                or journal._read(folder,'BUSINESS-RAW',_BUSINESS_LIMIT) != raw
                or tuple(journal._identity(os.stat(item,dir_fd=folder,follow_symlinks=False)) for item in names) != identities
                or tuple(journal._identity(os.stat(item,dir_fd=history_folder,follow_symlinks=False)) for item in history_names) != history_identities):
            raise HistoryPrereadHold()
        journal._named(parent,name,folder,directory=True)
        journal._named(parent,history_name,history_folder,directory=True)
        for response,kind,row in checks: issued(response,kind,sheet=sheet,row=row)
        issued(identity_response,'template_identity'); issued(history_response,'history_tail')
    except Exception: failed = True
    finally:
        for handle in (folder,history_folder):
            if handle is not None:
                try: os.close(handle)
                except OSError: failed = True
    if failed: raise HistoryPrereadHold()
    return result
