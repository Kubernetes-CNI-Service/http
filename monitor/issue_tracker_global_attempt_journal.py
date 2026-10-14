"""Uninstalled conservative spreadsheet-wide immutable attempt evidence.

One retained unit blocks ALL new units in this spreadsheet, across projects.
The sole unit's action, binding and wire are immutable; at most six durable
UNKNOWN intents survive cold processes. No completion, reset, reclamation or
network here. A typed/coherent unit is not authenticated job/admission authority,
nor does an intent alone bound real sends: fixed launcher, single consumption,
fresh checks, reservations, FIFO and COMPLETE still need integration.
"""
from contextlib import contextmanager, ExitStack
from dataclasses import dataclass, field
from contextvars import ContextVar
import hashlib
import json
import os
import threading
import weakref

from monitor import issue_tracker_local_commit as local
from monitor import issue_tracker_attempt_journal as journal
from monitor import issue_tracker_spreadsheet_owner as ownership
from monitor import issue_tracker_send_intent as compiled

_LIVE_WIRE_CLAIMS = weakref.WeakKeyDictionary()
_WIRE_CLAIM_GUARD = threading.Lock()
_HELD_CATALOG_REPLAY = ContextVar('req7_original_catalog_replay', default=None)
_LIVE_CATALOG_REPLAYS = {}
_HELD_COUNT_CLAIM_ORIGINALS = ContextVar('req7_count_claim_originals', default=None)
_LIVE_COUNT_CLAIM_ORIGINALS = {}
_LIVE_COUNT_PROJECT_C6 = {}
_LIVE_COUNT_SOURCE_GRAPHS = {}
_LIVE_COUNT_SOURCE_RAW_TAILS = {}
_COUNT_SOURCE_RAW_TAIL_CONTEXT = ContextVar('req7_count_source_raw_tail',default=None)
_FIRST_ORIGINAL_SOURCE_PREFIX = ContextVar('req7_first_original_source_prefix', default=None)
_LIVE_FIRST_ORIGINAL_SOURCE_PREFIXES = {}


class _FirstOriginalSourcePrefixAnchor:
    """Lexical issuer's independent identity/lifecycle anchor, not a permit."""
    def __init__(self,packet):
        self.packet=packet
        self.fields=frozenset(packet)
        self.originals=tuple(packet[name] for name in
            ('writer','project','token','owner','binding','last','context','_count_scope'))
        self.prepared=None;self.count=None;self.count_fields=None
        self.used=self.succeeded=self.failed=self.exit_attempted=False
        self.prefetch_scope=packet['_count_scope'];self.prefetched=None
        self.prefetch_attempted=self.prefetch_failed=False


class GlobalAttemptHold(ValueError):
    def __init__(self): super().__init__('req7_global_attempt_unproved')


class _CountSourceRawTail:
    """Original Count issuer owns cleanup, never a source/K/send grant."""
    def __init__(self,key,packet,record,verify_raw):
        self.key,self.packet,self.record=key,packet,record
        self.verify_raw=verify_raw;self.receiver=None;self.finish_receiver=None;self.closing=False
        self._raw_binding=(verify_raw,getattr(verify_raw,'__code__',None))
        self._binding=None
        self._received_source=None
        self.originals=tuple(packet[name] for name in
            ('writer','token','binding','unit','project','owner','context','verify'))

    def attach(self,receiver):
        from monitor import issue_tracker_settings_audit_allocation as allocation
        if (self._binding is not None or self.receiver is not None or self.closing
                or type(receiver) is not allocation._CountSourceRawOriginals
                or _LIVE_COUNT_SOURCE_RAW_TAILS.get(self.key) is not self
                or _HELD_COUNT_CLAIM_ORIGINALS.get() is not self.key
                or _count_claim_original_packet() is not self.packet
                or _LIVE_COUNT_SOURCE_GRAPHS.get(self.key) is not self.record
                or receiver.key is not self.key or receiver.packet is not self.packet
                or receiver.record is not self.record or receiver._count_tail_owner is not None):
            raise GlobalAttemptHold()
        _same_first_count_original_fields(self.packet,self.originals)
        receiver.verify()
        self.receiver=receiver;self.finish_receiver=receiver._finish_from_count_tail
        # Create the recipient before any source scope is moved. This strong
        # original slot cannot be replaced by an exposed receiver attribute.
        self._binding=(receiver,self.finish_receiver,receiver.raw,tuple(receiver.owned_slots),ExitStack())
        receiver._count_tail_owner=self

    def check_tail(self,receiver):
        if (not self.closing or _COUNT_SOURCE_RAW_TAIL_CONTEXT.get() is not self
                or _LIVE_COUNT_SOURCE_RAW_TAILS.get(self.key) is not self
                or self._binding is None or self._binding[0] is not receiver
                or (len(self._binding)==6 and self._received_source is not self._binding[5])
                or self.receiver is not receiver or self.finish_receiver is not self._binding[1]
                or receiver._count_tail_owner is not self or receiver.closed
                or self.verify_raw is not self._raw_binding[0]
                or getattr(self.verify_raw,'__code__',None) is not self._raw_binding[1]
                or self.key in _LIVE_COUNT_CLAIM_ORIGINALS
                or self.key in _LIVE_COUNT_SOURCE_GRAPHS
                or self.packet['context']!=(os.getpid(),threading.get_ident())):raise GlobalAttemptHold()
        _same_first_count_original_fields(self.packet,self.originals)

    def finish(self):
        # Once-bound original identity cannot be downgraded by deleting its
        # exposed receiver slot. Call the independently captured original.
        if self._binding is None:return
        if (self.closing or self.key in _LIVE_COUNT_CLAIM_ORIGINALS
                or self.key in _LIVE_COUNT_SOURCE_GRAPHS):raise GlobalAttemptHold()
        from monitor import issue_tracker_settings_audit_allocation as allocation
        original_binding=self._binding
        original_close=allocation._CountSourceRawOriginals._close_owned
        reset=None;entered=False;problem=None
        try:
            self.closing=True
            reset=_COUNT_SOURCE_RAW_TAIL_CONTEXT.set(self)
            entered=True
            original_binding[1](self)
        except BaseException as error:problem=error
        finally:
            if not entered:
                # Phase acquisition failed after ownership had transferred.
                # Clean only the independently captured originals; no forged
                # phase, closed Count/C6 verifier, K or source permission.
                allocation._LIVE_COUNT_RECEIVED_SOURCES.pop(self.key,None)
                original_binding[0].source_failed=True
                try:original_binding[4].close()
                except BaseException as error:
                    if problem is None or (isinstance(problem,Exception) and not isinstance(error,Exception)):
                        problem=error
                try:original_close(original_binding[0],problem,originals=original_binding[2:4])
                except BaseException as error:
                    if problem is None or (isinstance(problem,Exception) and not isinstance(error,Exception)):
                        problem=error
            self.closing=False
            if reset is not None:
                try:_COUNT_SOURCE_RAW_TAIL_CONTEXT.reset(reset)
                except BaseException as error:
                    if problem is None or (isinstance(problem,Exception) and not isinstance(error,Exception)):
                        problem=error
        if problem is not None:raise problem


def _register_count_source_raw_receiver(receiver):
    """Enroll only typed original raw cleanup; not a callable permission."""
    key=_HELD_COUNT_CLAIM_ORIGINALS.get()
    anchor=_LIVE_COUNT_SOURCE_RAW_TAILS.get(key)
    if type(anchor) is not _CountSourceRawTail:raise GlobalAttemptHold()
    anchor.attach(receiver)


@dataclass(frozen=True)
class GlobalIntentObservation:
    attempt_count: int
    wire_sha256: str
    action_digest: str
    outcome: str


@dataclass(frozen=True,eq=False)
class CountedOriginalWireObservation:
    """Borrowed CLOEXEC read-only FD, NOT fresh admission or a send permit."""
    attempt_count: int
    wire_sha256: str
    fd: int = field(repr=False)
    action_fd: int = field(repr=False)


def _consume_original_wire_launch_attempt(writer_token,token,binding,unit,image):
    """Spend the original once, returning no fresh admission or send grant.

    Only issuance DATA is checked here. The complete original verifier must
    still run at the actual launch fence, after read-only private preparation.
    Startup or final validation failure never rolls this consumption back.
    """
    failed = False
    try:
        if type(image) is not CountedOriginalWireObservation: raise GlobalAttemptHold()
        with _WIRE_CLAIM_GUARD:
            issued = _LIVE_WIRE_CLAIMS.get(image)
            if issued is None: raise GlobalAttemptHold()
            writer,owner,target,original,wire,action,count,_verify,used = issued
            if (writer is not writer_token or owner is not token or target != binding or original is not unit
                    or type(image.fd) is not int or image.fd != wire
                    or type(image.action_fd) is not int or image.action_fd != action
                    or type(image.attempt_count) is not int or image.attempt_count != count
                    or image.wire_sha256 != unit.wire_sha256 or used): raise GlobalAttemptHold()
            _LIVE_WIRE_CLAIMS[image] = issued[:-1]+(True,)
    except Exception: failed = True
    if failed: raise GlobalAttemptHold()


def _require_original_wire_launch(writer_token,token,binding,unit,image,*,consume):
    """Original active object only; a coherent/copyable FD tuple is not issued.

    Consume before Popen, including startup/final validation failure. Durable
    CLAIM already forbids cold reuse. This adds no fresh cadence/quota authority.
    """
    failed = False
    try:
        if type(image) is not CountedOriginalWireObservation: raise GlobalAttemptHold()
        with _WIRE_CLAIM_GUARD:
            issued = _LIVE_WIRE_CLAIMS.get(image)
            if issued is None: raise GlobalAttemptHold()
            writer,owner,target,original,wire,action,count,verify,used = issued
            if (writer is not writer_token or owner is not token or target != binding or original is not unit
                    or type(image.fd) is not int or image.fd != wire
                    or type(image.action_fd) is not int or image.action_fd != action
                    or type(image.attempt_count) is not int or image.attempt_count != count
                    or image.wire_sha256 != unit.wire_sha256
                    or (consume and used) or (not consume and not used)): raise GlobalAttemptHold()
            if consume: _LIVE_WIRE_CLAIMS[image] = issued[:-1]+(True,)
        verify()
    except Exception: failed = True
    if failed: raise GlobalAttemptHold()


def _inspect_wire_claims(claims, original, unit, header):
    if (journal._read(claims,'HEADER',16384) != local._canonical(header)
            or journal._read(claims,'INITIALIZED',16384) != _initialization(header)):
        raise GlobalAttemptHold()
    names = set(os.listdir(claims)); count = len(names)-2
    if not 0 <= count <= 6 or names != {'HEADER','INITIALIZED',*(f'CLAIM-{i}' for i in range(1,count+1))}:
        raise GlobalAttemptHold()
    previous = hashlib.sha256(local._canonical(header)).hexdigest()
    for index in range(1,count+1):
        raw = journal._read(claims,f'CLAIM-{index}',16384)
        expected = {'schema_version':1,'unit_id':unit.unit_id,'wire_sha256':unit.wire_sha256,
            'attempt_count':index,'original_intent_sha256':hashlib.sha256(journal._read(original,f'ATTEMPT-{index}',16384)).hexdigest(),
            'previous_sha256':previous,'outcome':'CONSUMED_UNKNOWN_NOT_SEND_PROOF'}
        if raw != local._canonical(expected): raise GlobalAttemptHold()
        previous = hashlib.sha256(raw).hexdigest()
    return count,previous


def _count_claim_original_packet():
    key = _HELD_COUNT_CLAIM_ORIGINALS.get()
    if key is None:
        return None
    packet = _LIVE_COUNT_CLAIM_ORIGINALS.get(key)
    if (packet is None or packet['context'] != (os.getpid(), threading.get_ident())
            or local._owner(packet['writer']) is not packet['project']
            or ownership._validated_owner(packet['token'], packet['binding']) is not packet['owner']):
        raise GlobalAttemptHold()
    return packet


def _verify_count_source_original_overlap(source, graphs, *, _namespace_originals=()):
    """Necessary raw overlap, NOT a K/COUNT loan or semantic retirement.

    All three receiving graphs and the old source must still be LIVE and
    strictly unchanged. Prove every actual shared named edge against original
    FD/fullstat/bytes/names, not a locator, equal-content substitute or selected
    subset. Unshared project/settings/C19 originals remain in the source and
    are independently verified before and after. This check never edits a
    graph, relaxes its namespace, returns authority or survives COUNT/CLAIM.
    The fixed coordinator must separately bind the genuine issued COUNT graph
    and retain each semantic/owner tail before any eventual transfer.
    """
    from monitor import issue_tracker_unit_catalog as catalog
    try:
        if (type(source) is not catalog._Originals or type(graphs) is not tuple
                or len(graphs)!=3 or len({id(graph) for graph in graphs})!=3
                or any(type(graph) is not catalog._Originals for graph in graphs)
                or source in graphs or source.namespace is None
                or graphs[0].namespace is None or type(_namespace_originals) is not tuple):raise GlobalAttemptHold()
        source.verify()
        for graph in graphs:graph.verify()
        def identity(fd):return journal._identity(os.fstat(fd))
        source_parent,prefix,names=source.namespace
        receiver_parent,receiver_prefix,receiver_names=graphs[0].namespace
        if (identity(source_parent)[:2]!=identity(receiver_parent)[:2]
                or prefix!=receiver_prefix or set(names)!=set(receiver_names)):
            raise GlobalAttemptHold()
        # The issuer's actual lock is separately held by the OS owner, never
        # silently ignored by suffix. Every other namespace member needs a
        # root edge in BOTH graphs. Missing shared parent records cannot turn
        # their still-open children into an alleged unshared project graph.
        anchors={}
        for name,fd in _namespace_originals:
            if name in anchors or name not in names:raise GlobalAttemptHold()
            journal._named(source_parent,name,fd,directory=False)
            anchors[name]=(fd,identity(fd))
        root_identity=identity(source_parent)[:2]
        def root_names(originals):
            return {row[1] for graph in originals for row in (*graph.directories,*graph.files)
                if identity(row[0])[:2]==root_identity}
        if (root_names((source,))|set(anchors)!=set(names)
                or root_names(graphs)|set(anchors)!=set(names)):raise GlobalAttemptHold()
        # Classify by actual directory lineage, not suffix/family allowlists.
        # The shared root is the held original namespace parent. Every source
        # child beneath it needs full coverage; other raw graphs remain strict.
        shared={identity(source_parent)[:2]}
        remaining=list(source.directories)
        shared_directories=[]
        while remaining:
            added=[]
            for row in remaining:
                if identity(row[0])[:2] in shared:
                    shared_directories.append(row);shared.add(identity(row[2])[:2]);added.append(row)
            if not added:break
            remaining=[row for row in remaining if row not in added]
        receiver_directories={}
        receiver_files={}
        for graph in graphs:
            for row in graph.directories:
                receiver_directories.setdefault((identity(row[0])[:2],row[1]),[]).append(row)
            for row in graph.files:
                receiver_files.setdefault((identity(row[0])[:2],row[1]),[]).append(row)
        for parent,name,fd,original,entries in shared_directories:
            matches=receiver_directories.get((identity(parent)[:2],name),())
            if (len(matches)!=1 or matches[0][3]!=original
                    or identity(matches[0][2])!=identity(fd)
                    or matches[0][4]!=entries):raise GlobalAttemptHold()
        for parent,name,fd,original,raw in source.files:
            if identity(parent)[:2] not in shared:continue
            matches=receiver_files.get((identity(parent)[:2],name),())
            if (len(matches)!=1 or matches[0][3]!=original
                    or identity(matches[0][2])!=identity(fd)
                    or matches[0][4]!=raw):raise GlobalAttemptHold()
        for graph in graphs:graph.verify()
        source.verify()
        for name,(fd,original) in anchors.items():
            journal._named(source_parent,name,fd,directory=False)
            if identity(fd)!=original:raise GlobalAttemptHold()
    except Exception as error:
        raise GlobalAttemptHold() from error


def _verify_issued_count_source_original_overlap(writer,token,binding,unit,source):
    """Fixed live COUNT issuer plus necessary original shared-edge overlap.

    This is NOT the continuous K handoff. In particular it cannot replace a
    strict old source snapshot after the legitimate creator has appended.
    The actual issuer's independent closure owns the registry record and its
    three graph objects; a supplied equal-content tuple cannot register them.
    """
    packet=_count_claim_original_packet()
    if (packet is None or packet['writer'] is not writer or packet['token'] is not token
            or packet['binding']!=binding or packet['unit'] is not unit):raise GlobalAttemptHold()
    key=_HELD_COUNT_CLAIM_ORIGINALS.get()
    record=_LIVE_COUNT_SOURCE_GRAPHS.get(key)
    if (type(record) is not tuple or len(record)!=2 or record[0] is not packet
            or packet.get('_source_graphs') is not record):raise GlobalAttemptHold()
    original_verify=packet['verify']
    def current():
        if (_HELD_COUNT_CLAIM_ORIGINALS.get() is not key
                or _count_claim_original_packet() is not packet
                or _LIVE_COUNT_SOURCE_GRAPHS.get(key) is not record
                or packet.get('_source_graphs') is not record
                or packet['verify'] is not original_verify or packet['unit'] is not unit
                or packet['writer'] is not writer or packet['token'] is not token
                or packet['binding']!=binding):raise GlobalAttemptHold()
    current();original_verify();current()
    owner=packet['owner']
    _verify_count_source_original_overlap(source,record[1],
        _namespace_originals=((owner.lock_name,owner.lock_fd),))
    current();original_verify();current()


@contextmanager
def _hold_count_claim_project_c6(writer, token, binding, units):
    """Borrow the issuer's still-held ALL C6, never cold rows as authority.

    Only the short completed-source reader uses this internal join. No live
    COUNT issuer leaves the ordinary cold path unchanged. Every borrow checks
    the actual owners, raw graph and original C6 verifier before and after;
    it cannot outlive this domain or the actual issuer's first revocation.
    """
    packet = _count_claim_original_packet()
    if packet is None:
        yield None
        return
    key = _HELD_COUNT_CLAIM_ORIGINALS.get()
    record = _LIVE_COUNT_PROJECT_C6.get(key)
    if record is None or record[0] is not packet:
        raise GlobalAttemptHold()
    if (packet['writer'] is not writer or packet['token'] is not token
            or packet['binding'] != binding):
        raise GlobalAttemptHold()
    if record[2] is None:  # Original legacy COUNT graph has no project C6.
        yield None
        return
    from monitor import issue_tracker_unit_catalog as catalog
    original_units, rows, verify_c6 = record[1:]
    selected = packet['unit']; verify_count = packet['verify']; live = True
    if (type(rows) is not tuple or original_units != tuple(units)
            or any(type(row) is not catalog.CatalogProjectC6 for row in rows)
            or tuple(row.unit for row in rows) != original_units):
        raise GlobalAttemptHold()
    def same_join():
        if (not live or _HELD_COUNT_CLAIM_ORIGINALS.get() is not key
                or _LIVE_COUNT_PROJECT_C6.get(key) is not record
                or _count_claim_original_packet() is not packet
                or packet['writer'] is not writer or packet['token'] is not token
                or packet['binding'] != binding or packet['unit'] is not selected
                or packet['verify'] is not verify_count):
            raise GlobalAttemptHold()
    def verify():
        # A C6 recheck is not an unrelated ALL COUNT graph reconstruction.
        # The original COUNT verifier still dominates both loan boundaries;
        # every intermediate call checks the real live join and original C6.
        same_join(); verify_c6(); same_join()
    def count_boundary():
        same_join(); verify_count(); same_join()
    primary = None
    try:
        count_boundary()
        verify()
        yield rows, verify
        verify()
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            count_boundary()
            verify()
        except BaseException as error:
            if primary is not None and error is not primary:
                if isinstance(primary, Exception) and not isinstance(error, Exception):
                    raise error from primary
                raise primary from error
            raise
        finally:
            live = False


@contextmanager
def _hold_selected_last_catalog_write_originals(writer_token, token, binding, unit):
    """Original ALL families before COUNT through CLAIM/consumer/last exit.

    Private fixed last-unit join, not admission, settlement or a send permit.
    Three append-aware graphs share ONE fixed unique-image budget. Only the
    actual exclusive creators may introduce the derived next ATTEMPT/CLAIM;
    their readers overlap the live writer FD, never adopt a closed writer's
    pathname. Every OTHER family and every old selected image stays immutable.
    """
    from monitor import issue_tracker_unit_catalog as catalog
    from monitor import issue_tracker_retained_inventory as inventory
    graphs = []; scope = ExitStack(); owner_tail = ExitStack()
    key = reset = None; problem = None; verify_raw = None; source_tail=None
    try:
        project = local._owner(writer_token)
        owner = ownership._validated_owner(token, binding)
        overlap = _count_claim_original_packet()
        if overlap is not None:
            # Receive only the already issued original graph. Never put its
            # key/reset in this borrower's cleanup slots, reacquire paths or
            # derive a second ATTEMPT/CLAIM allowance from the changed count.
            borrowed_verify = overlap['verify']
            def current_borrow():
                if (_count_claim_original_packet() is not overlap
                        or overlap['writer'] is not writer_token or overlap['token'] is not token
                        or overlap['binding'] != binding or overlap['unit'] is not unit
                        or overlap['verify'] is not borrowed_verify):
                    raise GlobalAttemptHold()
            def verify_borrow():
                current_borrow(); borrowed_verify(); current_borrow()
            primary = cleanup_problem = None
            try:
                verify_borrow()
                yield borrowed_verify
            except BaseException as error:
                primary = error
            finally:
                try: verify_borrow()
                except BaseException as error:
                    cleanup_problem = error
                    if primary is None or (isinstance(primary, Exception) and not isinstance(error, Exception)):
                        primary = error
            if primary is not None:
                if cleanup_problem is not None and cleanup_problem is not primary:
                    raise primary from cleanup_problem
                raise primary
            return
        if not _catalog_present(owner):
            def legacy_verify():
                if (local._owner(writer_token) is not project
                        or ownership._validated_owner(token, binding) is not owner):
                    raise GlobalAttemptHold()
            legacy_verify(); yield legacy_verify; legacy_verify()
            return
        budget = catalog._OriginalImageBudget()
        immutable, counted, dispatched = graphs = [catalog._Originals(_image_budget=budget) for _ in range(3)]
        _catalog, units, _previous = catalog._inspect(token, binding, immutable)
        if not units or units[-1] != unit:
            raise GlobalAttemptHold()
        parent = owner.directories[-1][0]; stem = owner.lock_name[:-5]
        name = stem + '.unit-' + unit.unit_id + '.journal'
        dispatch_name = stem + '.unit-' + unit.unit_id + '.dispatch'
        actual = {child for child in os.listdir(parent) if child.startswith(stem + '.')}
        allowed = {stem+'.lock', stem+'.enrollment', stem+'.units', stem+'.units-started',
            *(stem+'.units-position-%020d' % index for index in range(1, len(units)+1))}
        allowed.update(stem+'.unit-'+original.unit_id+'.'+family
            for original in units for family in inventory._CATALOG_FAMILIES if family != 'enrollment')
        if actual - allowed or name not in actual:
            raise GlobalAttemptHold()
        captured = {child for p, child, *_rest in immutable.files if p == parent}
        for child in sorted(actual - captured - {stem+'.lock', stem+'.units'}):
            if child.endswith('-started') or child.startswith(stem+'.units-position-'):
                immutable.file(parent, child, 16384)
                continue
            graph = counted if child == name else dispatched if child == dispatch_name else immutable
            old = [folder for p, entry, folder, _identity, _names in graph.directories
                if p == parent and entry == child]
            if len(old) > 1:
                raise GlobalAttemptHold()
            folder = old[0] if old else graph.directory(parent, child)
            family = child.rsplit('.', 1)[-1]; entries = tuple(os.listdir(folder))
            if family == 'nv':
                from monitor import issue_tracker_nv_reservation as nv
                if frozenset(entries) != nv._CATALOG_NAMES:
                    raise GlobalAttemptHold()
            else:
                inventory._family_entries(family, entries)
            held_names = {entry for p, entry, *_rest in graph.files if p == folder}
            for entry in sorted(set(entries) - held_names):
                graph.file(folder, entry, inventory._limit(family, entry))
        selected = [folder for p, child, folder, _identity, _names in counted.directories
            if p == parent and child == name]
        if len(selected) != 1:
            raise GlobalAttemptHold()
        folder = selected[0]
        _current, _parent, _name, header = _inputs(token, binding, unit)
        if _current is not owner or _parent != parent or _name != name:
            raise GlobalAttemptHold()
        for graph in graphs:
            graph.verify()
        count, previous = _inspect(folder, unit, header)
        if not 0 <= count < 6:
            raise GlobalAttemptHold()
        _require_no_completion(parent, name)
        wire_identity = next(image for p, entry, _fd, image, _raw in counted.files
            if p == folder and entry == 'WIRE')
        action_identity = next(image for p, entry, _fd, image, _raw in counted.files
            if p == folder and entry == 'ACTION-PREIMAGE')
        claim_header = {'schema_version':1, 'unit_id':unit.unit_id, 'wire_sha256':unit.wire_sha256,
            'action_digest':unit.action_digest, 'journal_header_sha256':hashlib.sha256(local._canonical(header)).hexdigest(),
            'wire_identity':wire_identity, 'action_identity':action_identity}
        dispatch_folders = [child for p, entry, child, _identity, _names in dispatched.directories
            if p == parent and entry == dispatch_name]
        if len(dispatch_folders) > 1 or bool(dispatch_folders) != bool(count):
            raise GlobalAttemptHold()
        dispatch_folder = dispatch_folders[0] if dispatch_folders else None
        claim_previous = hashlib.sha256(local._canonical(claim_header)).hexdigest()
        if dispatch_folder is not None:
            used, claim_previous = _inspect_wire_claims(dispatch_folder, folder, unit, claim_header)
            if used != count:
                raise GlobalAttemptHold()
        project_verifiers = []; c6_rows = c6_original_verify = None
        if any(child.endswith('.project-origin') for child in actual):
            with catalog.hold_pending_project_origins(token, binding) as (origins, verify_origins):
                if (tuple(row.unit for row in origins) != units
                        or origins[-1].project_identity != journal._identity(os.fstat(project.project_fd))[:2]):
                    raise GlobalAttemptHold()
                _rows, verify_c6 = scope.enter_context(catalog._hold_project_c6_from_origins(
                    token, binding, origins, _owner_tail=owner_tail))
                c6_rows, c6_original_verify = _rows, verify_c6
                project_verifiers.append(verify_c6)
                verify_origins()
            if len(units) > 1:
                _superseded, verify_other = scope.enter_context(_hold_catalog_other_settlements(token, binding, unit))
                project_verifiers.append(verify_other)
        additions = set(); count_additions = set(); claim_additions = set(); completed = set()
        attempt_name = 'ATTEMPT-%d' % (count+1); claim_name = 'CLAIM-%d' % (count+1)
        attempt_raw = local._canonical({**header, 'attempt_count':count+1,
            'previous_sha256':previous, 'outcome':'UNKNOWN'})
        claim_raw = local._canonical({'schema_version':1, 'unit_id':unit.unit_id,
            'wire_sha256':unit.wire_sha256, 'attempt_count':count+1,
            'original_intent_sha256':hashlib.sha256(attempt_raw).hexdigest(),
            'previous_sha256':claim_previous, 'outcome':'CONSUMED_UNKNOWN_NOT_SEND_PROOF'})
        def verify_raw():
            if (local._owner(writer_token) is not project
                    or ownership._validated_owner(token, binding) is not owner):
                raise GlobalAttemptHold()
            immutable.verify(parent_additions=additions)
            counted.verify(appended_to=(folder, count_additions) if count_additions else None)
            dispatched.verify(appended_to=(dispatch_folder, claim_additions) if claim_additions else None)
        def verify():
            verify_raw()
            for check in project_verifiers:
                check()
            immutable.verify(parent_additions=additions)
            counted.verify(appended_to=(folder, count_additions) if count_additions else None)
            dispatched.verify(appended_to=(dispatch_folder, claim_additions) if claim_additions else None)
        def created_directory(actual_parent, entry, creator, first_identity):
            nonlocal dispatch_folder
            if (actual_parent != parent or entry != dispatch_name or dispatch_folder is not None
                    or completed != {attempt_name}):
                raise GlobalAttemptHold()
            journal._named(parent, entry, creator, directory=True)
            if journal._identity(os.fstat(creator)) != first_identity or os.listdir(creator):
                raise GlobalAttemptHold()
            dispatch_folder = dispatched.directory(parent, entry)
            if journal._identity(os.fstat(dispatch_folder)) != first_identity:
                raise GlobalAttemptHold()
            additions.add(entry); verify()
        def created_file(actual_parent, entry, creator, identity, raw):
            if (journal._identity(os.fstat(actual_parent))[:2] == journal._identity(os.fstat(folder))[:2]
                    and entry == attempt_name and not completed):
                graph, destination, expected, allowance = counted, folder, attempt_raw, count_additions
            elif (dispatch_folder is not None
                    and journal._identity(os.fstat(actual_parent))[:2] == journal._identity(os.fstat(dispatch_folder))[:2]):
                required = {attempt_name} if dispatch_folders else {attempt_name, 'HEADER', 'INITIALIZED'}
                if entry == 'HEADER' and not dispatch_folders and completed == {attempt_name}:
                    expected = local._canonical(claim_header)
                elif entry == 'INITIALIZED' and not dispatch_folders and completed == {attempt_name, 'HEADER'}:
                    expected = _initialization(claim_header)
                elif entry == claim_name and completed == required:
                    expected = claim_raw
                else:
                    raise GlobalAttemptHold()
                graph, destination, allowance = dispatched, dispatch_folder, claim_additions
            else:
                raise GlobalAttemptHold()
            if raw != expected or entry in completed:
                raise GlobalAttemptHold()
            journal._named(actual_parent, entry, creator, directory=False)
            if journal._identity(os.fstat(creator)) != identity:
                raise GlobalAttemptHold()
            image, captured_identity = graph.file(destination, entry, 16384)
            if image != expected or captured_identity != identity or journal._identity(os.fstat(creator)) != identity:
                raise GlobalAttemptHold()
            journal._named(actual_parent, entry, creator, directory=False)
            allowance.add(entry); completed.add(entry); verify()
        verify()
        key = object()
        packet = {'writer':writer_token, 'project':project, 'token':token,
            'binding':binding, 'owner':owner, 'unit':unit, 'context':(os.getpid(),threading.get_ident()),
            'created_file':created_file, 'created_directory':created_directory}
        source_graphs=tuple(graphs)
        source_graph_record=(packet,source_graphs)
        packet['_source_graphs']=source_graph_record
        def issued_verify():
            failed = False
            try:
                if (_HELD_COUNT_CLAIM_ORIGINALS.get() is not key
                        or _count_claim_original_packet() is not packet
                        or _LIVE_COUNT_SOURCE_GRAPHS.get(key) is not source_graph_record
                        or packet.get('_source_graphs') is not source_graph_record
                        or len(graphs)!=3
                        or any(actual is not original for actual,original in zip(graphs,source_graphs))):
                    raise GlobalAttemptHold()
                verify()
                if (_HELD_COUNT_CLAIM_ORIGINALS.get() is not key
                        or _count_claim_original_packet() is not packet
                        or _LIVE_COUNT_SOURCE_GRAPHS.get(key) is not source_graph_record
                        or packet.get('_source_graphs') is not source_graph_record
                        or len(graphs)!=3
                        or any(actual is not original for actual,original in zip(graphs,source_graphs))):
                    raise GlobalAttemptHold()
            except Exception:
                failed = True
            if failed:
                raise GlobalAttemptHold() from None
        packet['verify'] = issued_verify
        source_tail=_CountSourceRawTail(key,packet,source_graph_record,verify_raw)
        _LIVE_COUNT_CLAIM_ORIGINALS[key] = packet
        _LIVE_COUNT_SOURCE_GRAPHS[key] = source_graph_record
        _LIVE_COUNT_SOURCE_RAW_TAILS[key] = source_tail
        _LIVE_COUNT_PROJECT_C6[key] = (packet, units, c6_rows, c6_original_verify)
        reset = _HELD_COUNT_CLAIM_ORIGINALS.set(key)
        issued_verify()
        yield issued_verify
        issued_verify()
    except BaseException as error:
        problem = error
    finally:
        if key is not None:
            _LIVE_COUNT_SOURCE_GRAPHS.pop(key, None)
            _LIVE_COUNT_PROJECT_C6.pop(key, None)
            _LIVE_COUNT_CLAIM_ORIGINALS.pop(key, None)
        if reset is not None:
            try:
                _HELD_COUNT_CLAIM_ORIGINALS.reset(reset)
            except BaseException as error:
                if problem is None or (isinstance(problem, Exception) and not isinstance(error, Exception)):
                    problem = error
        # Revoke first. All semantic C6/OTHER finalizers finish while the
        # independently acquired actual owners still remain held. Then check
        # our raw shared graphs once more; never call a closed semantic scope.
        for close in (scope.close, *((verify_raw,) if verify_raw is not None else ()),
                *((source_tail.finish,) if source_tail is not None else ()),
                *(graph.close for graph in reversed(graphs)), owner_tail.close):
            try:
                close()
            except BaseException as error:
                if problem is None or (isinstance(problem, Exception) and not isinstance(error, Exception)):
                    problem = error
        if key is not None:_LIVE_COUNT_SOURCE_RAW_TAILS.pop(key,None)
    if problem is not None:
        if not isinstance(problem, Exception):
            raise problem
        raise GlobalAttemptHold() from None


@contextmanager
def _hold_counted_original_wire(writer_token,token,binding,unit):
    """Consume this original count once BEFORE eventual child launch.

    Private necessary handoff only: no Popen/socket/permission or counter reset.
    Both actual owners remain held. Immutable dispatch records survive cold
    owners, never backfill a missing/partial prefix, and cannot prove a send.
    Borrow the original read-only WIRE FD only inside this context; do not
    close/modify it. A caller/post-check failure retains consumed UNKNOWN.
    Real fresh admission, shared cadence and quota must dominate any launcher.
    """
    original = claims = wire = action = image = None; wire_identity = action_identity = None; failed = False
    prefix_originals = []; catalog_scope = ExitStack(); verify_catalog = lambda: None
    catalog_created = catalog_claimed = None; catalog_dispatch_present = None
    catalog_settled = False; new_images = []
    try:
        project = local._owner(writer_token)
        sheet_owner = ownership._validated_owner(token, binding)
        overlap = _count_claim_original_packet()
        if overlap is not None:
            if (overlap['writer'] is not writer_token or overlap['token'] is not token
                    or overlap['binding'] != binding or overlap['unit'] != unit):
                raise GlobalAttemptHold()
            overlap['verify']()
        if _catalog_present(sheet_owner):
            verify_catalog, catalog_dispatch_present, catalog_created, catalog_claimed, catalog_settled = catalog_scope.enter_context(
                _hold_catalog_counted_originals(writer_token, token, binding, unit))
        owner,parent,name,base = _inputs(token,binding,unit)
        _require_no_completion(parent,name)
        original = local._directory(parent,name)
        journal._named(parent,name,original,directory=True)
        # The count is witnessed by the immutable ORIGINAL prefix, not merely
        # coherent bytes reopened after interpreting it. Pin every image and
        # the namespace BEFORE the first semantic count read, not only CLAIM.
        original_identity = journal._identity(os.fstat(original))
        names = set(os.listdir(original)); count = len(names)-4
        if (not 1 <= count <= 6 or names != {'ACTION-PREIMAGE','WIRE','HEADER','INITIALIZED',
                *(f'ATTEMPT-{i}' for i in range(1,count+1))}): raise GlobalAttemptHold()
        for entry in ('HEADER','INITIALIZED',*(f'ATTEMPT-{i}' for i in range(1,count+1))):
            fd = os.open(entry,local._flags()|os.O_NONBLOCK,dir_fd=original)
            prefix_originals.append((entry,fd,None))
            identity = journal._identity(os.fstat(fd))
            prefix_originals[-1] = (entry,fd,identity)
            journal._named(original,entry,fd,directory=False)
            raw = os.pread(fd,16385,0)
            if (len(raw) > 16384 or len(raw) != identity[6]
                    or raw != journal._read(original,entry,16384)
                    or journal._identity(os.fstat(fd)) != identity): raise GlobalAttemptHold()
        if journal._identity(os.fstat(original)) != original_identity: raise GlobalAttemptHold()
        wire = os.open('WIRE',local._flags()|os.O_NONBLOCK,dir_fd=original)
        journal._named(original,'WIRE',wire,directory=False)
        wire_identity = journal._identity(os.fstat(wire))
        if os.pread(wire,1024*1024+1,0) != unit.wire_bytes: raise GlobalAttemptHold()
        action = os.open('ACTION-PREIMAGE',local._flags()|os.O_NONBLOCK,dir_fd=original)
        journal._named(original,'ACTION-PREIMAGE',action,directory=False)
        action_identity = journal._identity(os.fstat(action))
        if os.pread(action,1024*1024+1,0) != unit.action_preimage: raise GlobalAttemptHold()
        if _inspect(original,unit,base)[0] != count: raise GlobalAttemptHold()
        for entry,fd,identity in prefix_originals:
            journal._named(original,entry,fd,directory=False)
            if journal._identity(os.fstat(fd)) != identity: raise GlobalAttemptHold()
        if (journal._identity(os.fstat(original)) != original_identity
                or journal._identity(os.fstat(wire)) != wire_identity
                or journal._identity(os.fstat(action)) != action_identity): raise GlobalAttemptHold()
        header = {'schema_version':1,'unit_id':unit.unit_id,'wire_sha256':unit.wire_sha256,
            'action_digest':unit.action_digest,'journal_header_sha256':hashlib.sha256(local._canonical(base)).hexdigest(),
            'wire_identity':wire_identity,'action_identity':action_identity}
        claim_name = name[:-len('.journal')]+'.dispatch'
        verify_catalog()
        if (catalog_dispatch_present is not None
                and (claim_name in os.listdir(parent)) != catalog_dispatch_present):
            raise GlobalAttemptHold()
        if claim_name not in os.listdir(parent):
            if count != 1: raise GlobalAttemptHold()
            claims = _create_folder(parent,claim_name)
            if catalog_settled or overlap is not None:
                new_images.append(catalog_scope.enter_context(_write_global_start(claims,'HEADER',local._canonical(header))))
                new_images[-1]()
                new_images.append(catalog_scope.enter_context(_write_global_start(claims,'INITIALIZED',_initialization(header))))
                for verify_new in new_images: verify_new()
            else:
                local._write_new(claims,'HEADER',local._canonical(header))
                # Never mark initialized before every prior image barrier succeeds.
                local._write_new(claims,'INITIALIZED',_initialization(header))
            if catalog_created is not None:
                catalog_created(claims)
        else: claims = local._directory(parent,claim_name)
        journal._named(parent,claim_name,claims,directory=True)
        used,previous = _inspect_wire_claims(claims,original,unit,header)
        if used != count-1: raise GlobalAttemptHold()
        _sync_initialization(parent,claims,header)
        if local._owner(writer_token) is not project or ownership._validated_owner(token,binding) is not owner:
            raise GlobalAttemptHold()
        journal._named(original,'WIRE',wire,directory=False)
        journal._named(original,'ACTION-PREIMAGE',action,directory=False)
        if (journal._identity(os.fstat(wire)) != wire_identity
                or journal._identity(os.fstat(action)) != action_identity): raise GlobalAttemptHold()
        verify_catalog()
        claim_raw = local._canonical({'schema_version':1,
            'unit_id':unit.unit_id,'wire_sha256':unit.wire_sha256,'attempt_count':count,
            'original_intent_sha256':hashlib.sha256(journal._read(original,f'ATTEMPT-{count}',16384)).hexdigest(),
            'previous_sha256':previous,'outcome':'CONSUMED_UNKNOWN_NOT_SEND_PROOF'})
        if catalog_settled or overlap is not None:
            new_images.append(catalog_scope.enter_context(_write_global_start(claims,f'CLAIM-{count}',claim_raw)))
            for verify_new in new_images: verify_new()
        else:
            local._write_new(claims,f'CLAIM-{count}',claim_raw)
        if catalog_claimed is not None:
            catalog_claimed(claims, count)
        if _inspect_wire_claims(claims,original,unit,header)[0] != count: raise GlobalAttemptHold()
        claims_identity = journal._identity(os.fstat(claims))
        names = tuple(sorted(os.listdir(claims)))
        identities = tuple(journal._identity(os.stat(item,dir_fd=claims,follow_symlinks=False)) for item in names)
        if _inspect(original,unit,base)[0] != count: raise GlobalAttemptHold()
        journal._named(parent,name,original,directory=True)
        journal._named(parent,claim_name,claims,directory=True)
        if (local._owner(writer_token) is not project or ownership._validated_owner(token,binding) is not owner
                or journal._identity(os.fstat(wire)) != wire_identity
                or journal._identity(os.fstat(action)) != action_identity): raise GlobalAttemptHold()
        def verify():
            if overlap is not None:
                overlap['verify']()
            for verify_new in new_images: verify_new()
            verify_catalog()
            _require_no_completion(parent,name)
            if (journal._identity(os.fstat(original)) != original_identity
                    or journal._identity(os.fstat(claims)) != claims_identity): raise GlobalAttemptHold()
            for entry,fd,identity in prefix_originals:
                journal._named(original,entry,fd,directory=False)
                if journal._identity(os.fstat(fd)) != identity: raise GlobalAttemptHold()
            if (_inspect(original,unit,base)[0] != count
                or _inspect_wire_claims(claims,original,unit,header)[0] != count
                or tuple(sorted(os.listdir(claims))) != names
                or tuple(journal._identity(os.stat(item,dir_fd=claims,follow_symlinks=False)) for item in names) != identities
                or os.pread(wire,1024*1024+1,0) != unit.wire_bytes
                or journal._identity(os.fstat(wire)) != wire_identity
                or os.pread(action,1024*1024+1,0) != unit.action_preimage
                or journal._identity(os.fstat(action)) != action_identity
                or local._owner(writer_token) is not project or ownership._validated_owner(token,binding) is not owner):
                raise GlobalAttemptHold()
            journal._named(original,'WIRE',wire,directory=False)
            journal._named(original,'ACTION-PREIMAGE',action,directory=False)
            journal._named(parent,name,original,directory=True)
            journal._named(parent,claim_name,claims,directory=True)
            # Semantic replays above reopen the journal. A held prefix must
            # still be the original AFTER those reads, including an in-place
            # byte/mtime restoration during the last pre-Popen verification.
            for entry,fd,identity in prefix_originals:
                journal._named(original,entry,fd,directory=False)
                if journal._identity(os.fstat(fd)) != identity: raise GlobalAttemptHold()
            if (journal._identity(os.fstat(original)) != original_identity
                    or journal._identity(os.fstat(claims)) != claims_identity): raise GlobalAttemptHold()
            # ALL catalog/count originals must still be held AFTER the last
            # semantic replay, not merely at entry or eventual scope exit.
            verify_catalog()
            for verify_new in new_images: verify_new()
            if overlap is not None:
                overlap['verify']()
        verify()
        image = CountedOriginalWireObservation(count,unit.wire_sha256,wire,action)
        with _WIRE_CLAIM_GUARD:
            _LIVE_WIRE_CLAIMS[image] = (writer_token,token,binding,unit,wire,action,count,verify,False)
        yield image
        verify()
    except Exception: failed = True
    finally:
        if image is not None:
            with _WIRE_CLAIM_GUARD: _LIVE_WIRE_CLAIMS.pop(image,None)
        try:
            catalog_scope.close()
        except Exception:
            failed = True
        for held,identity in ((wire,wire_identity),(action,action_identity),
                              *((fd,identity) for _entry,fd,identity in prefix_originals)):
            if held is None: continue
            try:
                # Never close a foreign FD that replaced a violated borrow.
                # Full metadata drift is still HOLD above, but it does not
                # transfer ownership of this descriptor to a different inode.
                # Close our original even after chmod/write; never a reused FD.
                if identity is None or journal._identity(os.fstat(held))[:2] == identity[:2]: os.close(held)
                else: failed = True
            except OSError: failed = True
        for handle in (claims,original):
            if handle is not None:
                try: os.close(handle)
                except OSError: failed = True
    if failed: raise GlobalAttemptHold()


def _catalog_present(owner):
    stem = owner.lock_name[:-5]
    return any(name == stem + '.units' or name.startswith(stem + '.units-')
               or name.startswith(stem + '.unit-')
               for name in os.listdir(owner.directories[-1][0]))


@contextmanager
def _hold_native_catalog_replay(token, binding, selected_unit):
    """Interpret ONE catalog while its ALL immutable originals stay held.

    This only avoids reopening/reparsing identical catalog locators. Every
    borrowed read still checks the actual owner, all named/held full stat and
    bytes, complete catalog/origin/NV/audit graph and exact namespace. C6,
    current source qualification, mutable counts/claims and issued deadlines
    remain independent actual observations. No caller cache/verifier or GO.
    """
    from monitor import issue_tracker_unit_catalog as catalog
    held=catalog._Originals();key=None;issued=None;packet=None
    alive=False;failed=False;primary=None
    try:
        if _HELD_CATALOG_REPLAY.get() is not None:raise GlobalAttemptHold()
        owner=ownership._validated_owner(token,binding)
        if not _catalog_present(owner):
            def verify_legacy():
                if ownership._validated_owner(token,binding) is not owner or _catalog_present(owner):
                    raise GlobalAttemptHold()
            yield verify_legacy
            verify_legacy()
        else:
            _folder,units,_previous=catalog._inspect(token,binding,held)
            if selected_unit not in units:raise GlobalAttemptHold()
            # Independently validate all origin records while retaining our
            # own ALL graph, including the explicit older C6 bridge whose
            # HEADER never contained a native project_origin anchor.
            with _hold_catalog_originals(token,binding) as (observed,check):
                if observed!=units:raise GlobalAttemptHold()
                parent=owner.directories[-1][0];stem=owner.lock_name[:-5]
                if any(name.endswith('.project-origin') for name in held.namespace[2]):
                    with catalog.hold_pending_project_origins(token,binding) as (origins,check_origins):
                        if tuple(row.unit for row in origins)!=units:raise GlobalAttemptHold()
                        captured={name for p,name,*_rest in held.directories if p==parent}
                        for unit in units:
                            name=stem+'.unit-'+unit.unit_id+'.project-origin'
                            if name not in captured:
                                folder=held.directory(parent,name)
                                for entry in ('WITNESS','STARTED','ORIGIN'):
                                    held.file(folder,entry,local._MAX_MANIFEST)
                        check_origins();check();held.verify()
                check();held.verify()
            before=held.namespace[2]
            dispatch=stem+'.unit-'+selected_unit.unit_id+'.dispatch'
            alive=True
            def verify_graph():
                if (not alive or ownership._validated_owner(token,binding) is not owner):
                    raise GlobalAttemptHold()
                # This exact name allowance grants no count/claim. Mutable
                # originals remain independently checked by their real holders.
                additions={dispatch} if dispatch not in before and dispatch in os.listdir(parent) else set()
                held.verify(parent_additions=additions)
            def require_issuer():
                if (not alive or issued is None or packet is None
                        or _HELD_CATALOG_REPLAY.get() is not issued
                        or _LIVE_CATALOG_REPLAYS.get(issued) is not packet
                        or packet[6:]!=(os.getpid(),threading.get_ident())):
                    raise GlobalAttemptHold()
            def verify():
                require_issuer();verify_graph();require_issuer()
            held.sync();verify_graph()
            issued=object()
            packet=(token,binding,owner,units,verify,selected_unit,os.getpid(),threading.get_ident())
            _LIVE_CATALOG_REPLAYS[issued]=packet
            key=_HELD_CATALOG_REPLAY.set(issued)
            verify()
            yield verify
            verify()
    except Exception:failed=True
    except BaseException as exc:primary=exc
    finally:
        alive=False
        # Revoke first. A Token from another Context cannot be reset there,
        # but that refusal must never skip owned original descriptor cleanup.
        if issued is not None:_LIVE_CATALOG_REPLAYS.pop(issued,None)
        try:
            if key is not None:_HELD_CATALOG_REPLAY.reset(key)
        except Exception:failed=True
        except BaseException as exc:
            if primary is None:primary=exc
        try:held.close()
        except Exception:failed=True
        except BaseException as exc:
            if primary is None:primary=exc
    if primary is not None:raise primary
    if failed:raise GlobalAttemptHold() from None


@contextmanager
def _hold_native_catalog_write_replay(token,binding,selected_unit):
    """Fixed count path borrows its SAME issued original catalog selection.

    Public issuance remains non-nestable. An outer native writer may already
    hold ALL immutable catalog/origin/NV/audit originals before strict input
    readers close. Count must not reopen or issue a second graph at that edge.
    Borrow only the actual registry/owner/thread/context and selected unit;
    membership alone cannot switch the writer or its fixed dispatch allowance.
    Mutable count/CLAIM, C6, FIFO, quota, sources and freshness remain the
    original independent checks. No caller callback, image or flag is used.
    """
    failed=False
    try:
        active=_HELD_CATALOG_REPLAY.get()
        if active is None:
            with _hold_native_catalog_replay(token,binding,selected_unit) as verify:
                yield verify
            return
        owner=ownership._validated_owner(token,binding)
        original=_LIVE_CATALOG_REPLAYS.get(active)
        if (original is None or original[0] is not token or original[1]!=binding
                or original[2] is not owner or original[5]!=selected_unit
                or original[6:]!=(os.getpid(),threading.get_ident())):
            raise GlobalAttemptHold()
        with _hold_catalog_originals(token,binding) as (units,verify):
            if selected_unit not in units:raise GlobalAttemptHold()
            # Membership can invoke equality; keep this last original check
            # before handing the borrower its body. The enclosing context
            # already checks the original again at body exit, without an
            # intervening call or I/O that needs a second adjacent replay.
            verify(); yield verify
    except Exception:failed=True
    if failed:raise GlobalAttemptHold() from None


@contextmanager
def _hold_catalog_originals(token, binding):
    """Fixed native catalog only; ALL origin images or no prefix, never paths."""
    from monitor import issue_tracker_unit_catalog as catalog
    failed = False
    try:
        owner = ownership._validated_owner(token, binding)
        active=_HELD_CATALOG_REPLAY.get()
        if active is not None:
            original=_LIVE_CATALOG_REPLAYS.get(active)
            if (original is None or original[0] is not token or original[1]!=binding
                    or original[2] is not owner
                    or original[6:]!=(os.getpid(),threading.get_ident())):
                raise GlobalAttemptHold()
            verify=original[4]
            verify()
            yield original[3],verify
            verify()
            return
        stem = owner.lock_name[:-5]; parent = owner.directories[-1][0]
        with ExitStack() as scope:
            units, verify_catalog = scope.enter_context(catalog.hold_pending_units(token, binding))
            allowed = {stem + '.lock', stem + '.enrollment', stem + '.units', stem + '.units-started',
                       *(stem + '.units-position-%020d' % index for index in range(1, len(units) + 1))}
            families = ('journal', 'journal-started', 'history', 'business', 'metadata', 'nv', 'nv-started',
                        'dispatch', 'completion', 'completion-started', 'project-origin',
                        'settings-audit', 'settings-audit-started')
            allowed.update(stem + '.unit-' + unit.unit_id + '.' + family
                           for unit in units for family in families)
            actual = {name for name in os.listdir(parent) if name.startswith(stem + '.')}
            # Legacy/foreign/unknown families are never silently ignored.
            # Origin rows are ALL immutable locators, not C6 or settlement.
            if actual - allowed:
                raise GlobalAttemptHold()
            verify_origins = lambda: None
            if any(name.endswith('.project-origin') for name in actual):
                origins, verify_origins = scope.enter_context(catalog.hold_pending_project_origins(token, binding))
                if tuple(row.unit for row in origins) != units:
                    raise GlobalAttemptHold()
            def verify():
                if ownership._validated_owner(token, binding) is not owner:
                    raise GlobalAttemptHold()
                verify_catalog(); verify_origins(); verify_catalog()
            verify()
            yield units, verify
            verify()
    except Exception:
        failed = True
    if failed:
        raise GlobalAttemptHold() from None


@contextmanager
def _hold_catalog_counted_originals(writer_token, token, binding, selected_unit):
    """ALL count/catalog originals dominate counted-wire consume and exit.

    Only the selected unit's genuine dispatch initialization and ONE exact
    claim append may extend this scope's namespaces. Every old file remains
    pinned before interpretation, including old dispatch claims. No public
    path/list/verification callback or count override is accepted. This is
    necessary original evidence, not fresh admission or a launch permit.
    """
    from monitor import issue_tracker_unit_catalog as catalog
    held = catalog._Originals(); failed = False; settlement_scope = ExitStack()
    try:
        project = local._owner(writer_token)
        owner = ownership._validated_owner(token, binding)
        parent = owner.directories[-1][0]; stem = owner.lock_name[:-5]
        _catalog, units, _previous = catalog._inspect(token, binding, held)
        if selected_unit not in units:
            raise GlobalAttemptHold()
        origin_prefix = stem + '.unit-'
        if any(name.startswith(origin_prefix) and name.endswith('.project-origin')
               for name in os.listdir(parent)):
            # Pin ALL origin images before their semantic reader. Its temporary
            # scope cannot dominate the later CLAIM/consumer by itself. These
            # originals stay in this exact append-aware scope so only our one
            # dispatch creation/claim is permitted; origin drift never is.
            for unit in units:
                origin = held.directory(parent, origin_prefix + unit.unit_id + '.project-origin')
                if set(os.listdir(origin)) != {'STARTED', 'ORIGIN', 'WITNESS'}:
                    raise GlobalAttemptHold()
                for entry in ('STARTED', 'ORIGIN', 'WITNESS'):
                    held.file(origin, entry, local._MAX_MANIFEST)
            held.verify()
            with catalog.hold_pending_project_origins(token, binding) as (origins, verify_origins):
                if tuple(row.unit for row in origins) != units:
                    raise GlobalAttemptHold()
                verify_origins(); held.verify()
            held.verify()
        observations = []
        for unit in units:
            _current, _parent, name, header = _inputs(token, binding, unit)
            folder = held.directory(parent, name)
            names = set(os.listdir(folder)); count = len(names) - 4
            if not 0 <= count <= 6 or names != {'HEADER', 'INITIALIZED', 'ACTION-PREIMAGE', 'WIRE',
                    *(f'ATTEMPT-{index}' for index in range(1, count + 1))}:
                raise GlobalAttemptHold()
            started = name[:-len('.journal')] + '.journal-started'
            raw, _stat = held.file(parent, started, 16384)
            if raw != local._canonical({'schema_version': 1, 'state': 'GLOBAL-UNIT-STARTED',
                    'unit_id': unit.unit_id, 'header_sha256': hashlib.sha256(local._canonical(header)).hexdigest()}):
                raise GlobalAttemptHold()
            images = {}
            for entry in sorted(names):
                images[entry] = held.file(folder, entry,
                    1024 * 1024 if entry in ('ACTION-PREIMAGE', 'WIRE') else 16384)[0]
            held.verify()
            if (images['ACTION-PREIMAGE'] != unit.action_preimage or images['WIRE'] != unit.wire_bytes
                    or _inspect(folder, unit, header)[0] != count):
                raise GlobalAttemptHold()
            held.verify(); observations.append((unit, count))
        position = units.index(selected_unit)
        selected_count = observations[position][1]
        if not 1 <= selected_count <= 6:
            raise GlobalAttemptHold()
        successor = any(count and unit != selected_unit for unit, count in observations)
        verify_settlement = lambda: None
        if successor:
            # Every existing family is pinned before actual settlement replay.
            # This scope's later allowance remains only the selected dispatch
            # initialization and ONE derived CLAIM; nothing else may change.
            from monitor import issue_tracker_retained_inventory as inventory
            captured = {name for p,name,*_rest in held.files if p == parent}
            captured.update(name for p,name,*_rest in held.directories if p == parent)
            actual = {name for name in os.listdir(parent) if name.startswith(stem + '.')}
            allowed = {stem+'.lock',stem+'.enrollment',stem+'.units',stem+'.units-started',
                *(stem+'.units-position-%020d' % index for index in range(1,len(units)+1))}
            allowed.update(stem+'.unit-'+unit.unit_id+'.'+family
                for unit in units for family in inventory._CATALOG_FAMILIES if family != 'enrollment')
            if actual - allowed: raise GlobalAttemptHold()
            for name in sorted(actual - captured - {stem+'.lock'}):
                if name.endswith('-started'): held.file(parent,name,16384)
                else:
                    folder = held.directory(parent,name); family = name.rsplit('.',1)[-1]
                    entries = tuple(os.listdir(folder))
                    if family == 'nv':
                        from monitor import issue_tracker_nv_reservation as nv
                        if frozenset(entries) != nv._CATALOG_NAMES: raise GlobalAttemptHold()
                    else: inventory._family_entries(family,entries)
                    for entry in sorted(entries): held.file(folder,entry,inventory._limit(family,entry))
            held.verify()
            verify_settlement = settlement_scope.enter_context(
                _hold_settled_catalog_claim_inputs(writer_token,token,binding,selected_unit))
            verify_settlement(); held.verify()
        else:
            _guard_catalog_transition(token,binding,selected_unit,preparing=False)
        dispatch = stem + '.unit-' + selected_unit.unit_id + '.dispatch'
        present = dispatch in os.listdir(parent); retained_dispatch = None
        if present:
            captured_dispatch = [folder for p,name,folder,_identity,_names in held.directories
                if p == parent and name == dispatch]
            if len(captured_dispatch) > 1: raise GlobalAttemptHold()
            retained_dispatch = captured_dispatch[0] if captured_dispatch else held.directory(parent,dispatch)
            names = set(os.listdir(retained_dispatch)); used = len(names) - 2
            if not 0 <= used <= 6 or names != {'HEADER', 'INITIALIZED',
                    *(f'CLAIM-{index}' for index in range(1, used + 1))}:
                raise GlobalAttemptHold()
            for name in sorted(names):
                held.file(retained_dispatch, name, 16384)
        held.sync(); additions = set(); appended = None; created = claimed = False
        def verify():
            if local._owner(writer_token) is not project or ownership._validated_owner(token, binding) is not owner:
                raise GlobalAttemptHold()
            held.verify(parent_additions=additions, appended_to=appended)
            verify_settlement()
            held.verify(parent_additions=additions, appended_to=appended)
        def created_dispatch(folder):
            nonlocal created, retained_dispatch
            if present or created or claimed:
                raise GlobalAttemptHold()
            journal._named(parent, dispatch, folder, directory=True)
            additions.add(dispatch); created = True; verify()
            # Pin our genuine initialization BEFORE its first semantic read.
            # Capturing it after CLAIM would adopt a same-byte replacement.
            retained_dispatch = held.directory(parent, dispatch)
            if (journal._identity(os.fstat(folder))[:2] != journal._identity(os.fstat(retained_dispatch))[:2]
                    or set(os.listdir(retained_dispatch)) != {'HEADER', 'INITIALIZED'}):
                raise GlobalAttemptHold()
            for name in ('HEADER', 'INITIALIZED'):
                held.file(retained_dispatch, name, 16384)
            verify()
        def claimed_dispatch(folder, count):
            nonlocal appended, claimed
            if claimed or count != selected_count or (not present and not created):
                raise GlobalAttemptHold()
            journal._named(parent, dispatch, folder, directory=True)
            entry = 'CLAIM-%d' % count
            if (retained_dispatch is None
                    or journal._identity(os.fstat(folder))[:2] != journal._identity(os.fstat(retained_dispatch))[:2]):
                raise GlobalAttemptHold()
            appended = (retained_dispatch, {entry}); verify()
            held.file(retained_dispatch, entry, 16384)
            claimed = True; verify()
        verify()
        yield verify, present, created_dispatch, claimed_dispatch, successor
        verify()
        if not claimed:
            raise GlobalAttemptHold()
    except Exception:
        failed = True
    finally:
        try: settlement_scope.close()
        except Exception: failed = True
        held.close()
    if failed:
        raise GlobalAttemptHold() from None


@contextmanager
def _hold_catalog_other_settlements(token, binding, unit):
    """Original OTHER APPLIED/key or committed count-zero UNSENT through IO.

    Only the fixed final catalog unit is selected. This private join runs
    underneath the count/CLAIM writer's append-aware ALL shared-image holder;
    it never exempts the read-only inventory verifier from namespace changes.
    Every OTHER zero-count unit needs its original immutable disposition and
    same-project strictly later APPLIED/key witnesses. Counted UNKNOWN cannot
    be relabelled UNSENT. Selected UNKNOWN is not interpreted as settlement.
    No caller rows, classification, paths, maxima or callbacks are accepted.
    """
    failed = False
    try:
        owner = ownership._validated_owner(token, binding)
        from monitor import issue_tracker_unit_catalog as catalog
        from monitor import issue_tracker_retained_inventory as inventory
        from monitor import issue_tracker_remote_history_match as remote
        with ExitStack() as scope:
            originals = catalog._Originals(); scope.callback(originals.close)
            with _hold_catalog_attempts(token, binding) as (observed, verify_counts):
                units = tuple(original for original, _state in observed)
                if (len(units) < 2 or units[-1] != unit
                        or any(state.outcome == 'PENDING_NO_JOURNAL' for _original, state in observed)):
                    raise GlobalAttemptHold()
                verify_counts()
            with catalog.hold_pending_project_origins(token, binding) as (origins, verify_origins):
                if tuple(row.unit for row in origins) != units:
                    raise GlobalAttemptHold()
                rows, verify_c6 = scope.enter_context(catalog._hold_project_c6_from_origins(token, binding, origins))
                verify_origins(); verify_c6()
            if tuple(row.unit for row in rows) != units:
                raise GlobalAttemptHold()
            projects = {}; applied_rows = []; validators = []; prior_keys = []
            for row, (original, state) in zip(rows, observed):
                if original != row.unit:
                    raise GlobalAttemptHold()
                if row.project_identity not in projects:
                    matches = [(writer, local._owner(writer)) for writer, active in tuple(local._ACTIVE.items())
                        if active.pid == os.getpid()
                        and journal._identity(os.fstat(active.project_fd))[:2] == row.project_identity]
                    if len(matches) != 1:
                        raise GlobalAttemptHold()
                    projects[row.project_identity] = matches[0]
                writer, project = projects[row.project_identity]
                keys = ()
                if original != unit and state.attempt_count:
                    facts = local._json(row.c6_facts)
                    generation = local.Generation(facts['generation_id'], facts['sequence'], facts['manifest_id'], writer)
                    actual, verify_inputs, body, keys = scope.enter_context(
                        remote._hold_settled_catalog_key_watermarks(writer, token, binding, original, generation))
                    if (actual is not project or tuple(body['project_identity']) != row.project_identity
                            or body['binding']['unit_id'] != original.unit_id):
                        raise GlobalAttemptHold()
                    validators.append(verify_inputs); prior_keys.append((row.project_identity, keys))
                # The selected UNKNOWN must not supply a false later witness.
                applied_rows.append(inventory.CatalogUnitAppliedKeys(original,
                    state.attempt_count if original != unit else 0, keys, row.project_identity))
            prefixes = ('REMOTE-UNSENT-SUPERSESSION-STARTED-', 'REMOTE-UNSENT-SUPERSESSION-',
                        'REMOTE-UNSENT-SUPERSESSION-WITNESS-')
            namespaces = {}; superseded = []
            def disposition_names(project):
                return frozenset(name for name in os.listdir(project.root_fd)
                    if name.startswith('REMOTE-UNSENT-SUPERSESSION-') or name.startswith('.pending-'))
            for identity, (_writer, project) in projects.items():
                project_rows = tuple(row for row in applied_rows if row.project_identity == identity)
                old_rows = tuple(row for row in project_rows if row.unit != unit and row.attempt_count == 0)
                names = disposition_names(project); namespaces[identity] = names
                expected = frozenset(prefix + row.unit.unit_id for prefix in prefixes for row in old_rows)
                if names != expected:
                    raise GlobalAttemptHold()
                for row in old_rows:
                    pair = tuple(prefix + row.unit.unit_id for prefix in prefixes[:2])
                    witness = prefixes[2] + row.unit.unit_id
                    # Capture all three fixed originals BEFORE interpreting any
                    # body. Pair semantic replay overlaps these same held bytes.
                    captured = {name: originals.file(project.root_fd, name, local._MAX_MANIFEST)
                                for name in (*pair, witness)}
                    body, _observation = inventory._unsent_disposition_body(project, binding, row,
                        project_rows, local._json(captured[pair[1]][0]))
                    if body is None:
                        raise GlobalAttemptHold()
                    expected_witness = local._canonical({'schema_version': 1, 'unit_id': row.unit.unit_id,
                        'state': 'UNSENT-SUPERSESSION-WRITE-STARTED-NOT-AUTHORITY',
                        'body_sha256': hashlib.sha256(local._canonical(body)).hexdigest()})
                    raw, image = captured[witness]
                    if raw != expected_witness:
                        raise GlobalAttemptHold()
                    body = {**body, 'write_witness': {'identity': list(image),
                        'sha256': hashlib.sha256(raw).hexdigest()}}
                    validators.append(scope.enter_context(remote._hold_applied_records(project.root_fd,
                        pair, body, states=('UNSENT-SUPERSESSION-STARTED', 'SUPERSEDED-NOT-SENT'))))
                    superseded.append(row.unit.unit_id)
            selected = rows[-1]; sequence = local._json(selected.c6_facts)['sequence']
            keys = {tuple(item['activity_key']) for item in local._json(unit.action_preimage)['business']}
            if any(identity == selected.project_identity and key in keys and maximum >= sequence
                    for identity, watermarks in prior_keys for key, maximum in watermarks):
                raise GlobalAttemptHold()
            def verify():
                if ownership._validated_owner(token, binding) is not owner:
                    raise GlobalAttemptHold()
                verify_c6(); originals.verify()
                for identity, (writer, project) in projects.items():
                    if (local._owner(writer) is not project
                            or journal._identity(os.fstat(project.project_fd))[:2] != identity
                            or disposition_names(project) != namespaces[identity]):
                        raise GlobalAttemptHold()
                for validate in validators:
                    validate()
                verify_c6(); originals.verify()
            verify(); originals.sync()
            yield tuple(superseded), verify
            verify()
    except Exception:
        failed = True
    if failed:
        raise GlobalAttemptHold()


@contextmanager
def _hold_settled_catalog_claim_inputs(writer_token,token,binding,unit):
    """Actual OTHER settlement/C6 originals through CLAIM consumers and exit.

    Fixed last-unit join, not a count writer, FIFO bypass or fresh admission.
    The outer append-aware holder pins ALL shared originals before entry;
    these project/COMPLETE/APPLIED/key scopes never reopen or adopt replacements.
    Selected count/UNKNOWN is retained, and its actual C6 project must belong
    to this exact original writer. No caller path/mode/label/verifier is used.
    """
    failed = False
    try:
        project = local._owner(writer_token)
        owner = ownership._validated_owner(token,binding)
        from monitor import issue_tracker_unit_catalog as catalog
        from monitor import issue_tracker_remote_history_match as remote
        with ExitStack() as scope:
            with _hold_catalog_attempts(token,binding) as (observed,verify_counts):
                units = tuple(original for original,_state in observed)
                if (len(units) < 2 or units[-1] != unit
                        or not 1 <= observed[-1][1].attempt_count <= 6
                        or any(state.outcome == 'PENDING_NO_JOURNAL' for _original,state in observed[:-1])):
                    raise GlobalAttemptHold()
                verify_counts()
            with catalog.hold_pending_project_origins(token,binding) as (origins,verify_origins):
                if tuple(row.unit for row in origins) != units: raise GlobalAttemptHold()
                rows,verify_c6 = scope.enter_context(catalog._hold_project_c6_from_origins(token,binding,origins))
                verify_origins(); verify_c6()
            if (tuple(row.unit for row in rows) != units
                    or rows[-1].project_identity != journal._identity(os.fstat(project.project_fd))[:2]):
                raise GlobalAttemptHold()
            _superseded, verify_other = scope.enter_context(_hold_catalog_other_settlements(token, binding, unit))
            parent = owner.directories[-1][0]
            name = owner.lock_name[:-5]+'.unit-'+unit.unit_id+'.journal'
            def verify():
                if local._owner(writer_token) is not project or ownership._validated_owner(token,binding) is not owner:
                    raise GlobalAttemptHold()
                _require_no_completion(parent,name); verify_c6()
                verify_other()
                verify_c6(); _require_no_completion(parent,name)
            verify()
            yield verify
            verify()
    except Exception: failed = True
    if failed: raise GlobalAttemptHold()


def _inputs(token, binding, unit):
    owner = ownership._validated_owner(token, binding)
    header = compiled._projection(unit)
    identity = json.loads(unit.action_preimage.decode('utf-8'))['identity']
    if identity['spreadsheet_id'] != binding.spreadsheet_id: raise GlobalAttemptHold()
    header.update(spreadsheet_id=binding.spreadsheet_id, allowlist_sha256=binding.allowlist_sha256,
                  policy_sha256=binding.policy_sha256)
    name = owner.lock_name[:-5] + '.journal'
    if _catalog_present(owner):
        with _hold_catalog_originals(token, binding) as (units, verify):
            if unit not in units:
                raise GlobalAttemptHold()
            # Its real ENTER/EXIT bracket the membership comparison. Return
            # only after EXIT; no third adjacent original replay is needed.
        name = owner.lock_name[:-5] + '.unit-' + unit.unit_id + '.journal'
    return owner, owner.directories[-1][0], name, header


@contextmanager
def _hold_catalog_attempts(token, binding):
    """Hold ALL catalog originals/counts; never settlement or send authority."""
    with ExitStack() as scope:
        units, verify_catalog = scope.enter_context(_hold_catalog_originals(token, binding))
        owner = ownership._validated_owner(token, binding)
        parent = owner.directories[-1][0]; names = set(os.listdir(parent))
        observations = []; validators = []
        for unit in units:
            name = owner.lock_name[:-5] + '.unit-' + unit.unit_id + '.journal'
            started = name[:-len('.journal')] + '.journal-started'
            if name not in names and started not in names:
                # Necessary diagnostic distinction, not a proven first use.
                # No caller can turn this into admission or a wire capability.
                observed = GlobalIntentObservation(0, unit.wire_sha256, unit.action_digest,
                                                   'PENDING_NO_JOURNAL')
            elif name not in names or started not in names:
                raise GlobalAttemptHold()
            else:
                original, observed, verify = scope.enter_context(
                    _hold_original_global_unit(token, binding, selected_unit=unit))
                if original != unit:
                    raise GlobalAttemptHold()
                validators.append(verify)
            observations.append((unit, observed))
        def verify_all():
            if ownership._validated_owner(token, binding) is not owner:
                raise GlobalAttemptHold()
            verify_catalog()
            for validate in validators:
                validate()
            verify_catalog()
        verify_all()
        yield tuple(observations), verify_all
        verify_all()


def inspect_catalog_global_units(token, binding):
    """Original diagnostic counts only; UNKNOWN is NEVER cleared by this read."""
    failed = False
    try:
        with _hold_catalog_attempts(token, binding) as (observed, verify):
            verify()
    except Exception:
        failed = True
    if failed:
        raise GlobalAttemptHold() from None
    return observed


def _guard_catalog_transition(token, binding, unit, *, preparing):
    owner = ownership._validated_owner(token, binding)
    if not _catalog_present(owner):
        return
    with _hold_catalog_attempts(token, binding) as (observations, verify):
        selected = [index for index, (original, _state) in enumerate(observations) if original == unit]
        if len(selected) != 1:
            raise GlobalAttemptHold()
        position = selected[0]
        if any(state.attempt_count > 0 and (preparing or original != unit)
               for original, state in observations):
            # COMPLETE/APPLIED/G1/FIFO release integration is still separate.
            # A label/fence/caller assertion never releases this conservative
            # barrier; only the blocking unit may add its identical R2 intent.
            raise GlobalAttemptHold()
        if not preparing:
            keys = {tuple(row['activity_key']) for row in local._json(unit.action_preimage)['business']}
            for original, _state in observations[:position]:
                prior = {tuple(row['activity_key']) for row in local._json(original.action_preimage)['business']}
                if keys & prior:
                    raise GlobalAttemptHold()
        verify()


def _require_no_completion(parent,journal_name,*,marker_only=False):
    """Conservative no-resend boundary, not proof of remote settlement.

    An in-progress/partial proof store blocks WIRE claims. Raw diagnostic
    intent counting is not transport; it additionally refuses any COMPLETE
    marker, even malformed. Neither absence nor presence grants admission,
    APPLIED, cleanup, capacity reclamation or a replacement generation.
    """
    key=journal_name[:-len('.journal')]
    name=key+'.completion'; names=os.listdir(parent)
    # The sibling survives a lost/displaced proof directory. Even malformed
    # bytes are only a conservative STOP, never settlement/admission evidence.
    if key+'.completion-started' in names and (not marker_only or name not in names):
        raise GlobalAttemptHold()
    if name not in names: return
    if not marker_only: raise GlobalAttemptHold()
    folder=local._directory(parent,name)
    try:
        journal._named(parent,name,folder,directory=True)
        identity=journal._identity(os.fstat(folder))
        if 'COMPLETE' in os.listdir(folder): raise GlobalAttemptHold()
        journal._named(parent,name,folder,directory=True)
        if journal._identity(os.fstat(folder))!=identity: raise GlobalAttemptHold()
    finally: os.close(folder)


def _create_folder(parent, name, *, _return_original=False):
    # Partial creation is retained HOLD, but no owned descriptor may leak when
    # a directory fsync or interruption happens before returning the handle.
    os.mkdir(name, 0o700, dir_fd=parent); os.fsync(parent)
    original = journal._identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
    fd = local._directory(parent, name)
    try:
        identity = journal._identity(os.fstat(fd))
        if identity != original:
            raise GlobalAttemptHold()
        journal._named(parent, name, fd, directory=True)
        os.fsync(fd)
        journal._named(parent, name, fd, directory=True)
        if journal._identity(os.fstat(fd)) != identity:
            raise GlobalAttemptHold()
        overlap = _count_claim_original_packet()
        if overlap is not None:
            overlap['created_directory'](parent, name, fd, identity)
    except BaseException:
        try:
            if journal._identity(os.fstat(fd))[:2] == original[:2]:
                os.close(fd)
        except OSError:
            pass
        raise
    # The exclusive creator already checked this actual named/opened original.
    # Transfer its cleanup provenance with the FD, before a caller's first stat
    # can fail. Default callers retain the existing descriptor-only contract.
    return (fd, identity) if _return_original else fd


def _inspect(folder, unit, header):
    if (journal._read(folder, 'ACTION-PREIMAGE', 1024 * 1024) != unit.action_preimage
            or journal._read(folder, 'WIRE', 1024 * 1024) != unit.wire_bytes
            or journal._read(folder, 'HEADER', 16384) != local._canonical(header)
            or journal._read(folder, 'INITIALIZED', 16384) != _initialization(header)):
        raise GlobalAttemptHold()
    names = set(os.listdir(folder)); count = len(names) - 4
    if not 0 <= count <= 6 or names != {'ACTION-PREIMAGE', 'WIRE', 'HEADER', 'INITIALIZED', *(f'ATTEMPT-{i}' for i in range(1, count + 1))}:
        raise GlobalAttemptHold()
    previous = hashlib.sha256(local._canonical(header)).hexdigest()
    for index in range(1, count + 1):
        raw = journal._read(folder, f'ATTEMPT-{index}', 16384)
        expected = {**header, 'attempt_count': index, 'previous_sha256': previous, 'outcome': 'UNKNOWN'}
        if raw != local._canonical(expected): raise GlobalAttemptHold()
        previous = hashlib.sha256(raw).hexdigest()
    return count, previous


def _initialization(header):
    return local._canonical({'schema_version': 1, 'state': 'INITIALIZED',
                            'header_sha256': hashlib.sha256(local._canonical(header)).hexdigest()})


def _sync_initialization(parent, folder, header):
    """Confirm genuine post-image-barrier marker under ownership, never create it.

    A present marker means this writer previously completed ALL eight image
    barriers before it was written. Synchronize its held file and directories
    before an intent; pathname existence alone, or a fully shaped HEADER whose
    final fsync failed, must not stand in for those preceding barriers.
    """
    fd = os.open('INITIALIZED', local._flags(), dir_fd=folder)
    try:
        info = local._check(fd, directory=False)
        journal._named(folder, 'INITIALIZED', fd, directory=False)
        raw = os.read(fd, 16385)
        if len(raw) != info.st_size or raw != _initialization(header): raise GlobalAttemptHold()
        os.fsync(fd); os.fsync(folder); os.fsync(parent)
        journal._named(folder, 'INITIALIZED', fd, directory=False)
    finally: os.close(fd)


@contextmanager
def _write_global_start(parent, name, raw):
    """Create the permanent STOP name before any byte or durability barrier.

    Partial/empty witnesses stay retained on failure. They are never positive
    evidence, repaired, replaced or removed by this initializer.
    """
    if type(raw) is not bytes or not 1 <= len(raw) <= 16384:
        raise GlobalAttemptHold()
    local._flags()
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
    initial = cleanup_identity = None; problem = None
    try:
        # Named preimage is ONLY a cleanup candidate if the first real fstat
        # refuses. It is never admitted evidence or a replacement FD license.
        cleanup_identity = journal._identity(os.stat(name,dir_fd=parent,follow_symlinks=False))
        initial = journal._identity(os.fstat(fd))
        if (initial != cleanup_identity or journal._identity(local._check(fd, directory=False)) != initial):
            raise GlobalAttemptHold()
        journal._named(parent, name, fd, directory=False)
        remaining = memoryview(raw)
        while remaining:
            written = os.write(fd, remaining)
            if not 0 < written <= len(remaining): raise GlobalAttemptHold()
            remaining = remaining[written:]
        identity = journal._identity(os.fstat(fd))
        if identity[:5] != initial[:5]:
            raise GlobalAttemptHold()
        def verify():
            journal._named(parent, name, fd, directory=False)
            if journal._identity(os.fstat(fd)) != identity: raise GlobalAttemptHold()
        os.fsync(fd)
        verify()
        os.fsync(parent)
        verify()
        overlap = _count_claim_original_packet()
        if overlap is not None:
            overlap['created_file'](parent, name, fd, identity, raw)
            verify()
        yield verify
        verify()
    except BaseException as error:
        problem = error
    finally:
        candidate = initial if initial is not None else cleanup_identity
        if candidate is not None:
            try:
                if journal._identity(os.fstat(fd))[:2] == candidate[:2]:
                    os.close(fd)
            except OSError:
                pass
            except BaseException as error:
                if problem is None:
                    problem = error
    if problem is not None:
        raise problem


@contextmanager
def _hold_settled_successor_preparation(token, binding, unit):
    """Original APPLIED/key evidence for ONE new diagnostic GLOBAL store.

    No count is cleared and no send/FIFO/cadence/NEW capability is returned.
    The fixed public creator alone consumes this private verifier. All prior
    shared images, project C6, COMPLETE, APPLIED and key pairs survive the
    actual write. Only its two derived exclusive names may extend the root;
    no caller paths, settlement labels or refreshed prior originals are used.
    Legacy/unattempted creation retains its existing conservative guard.
    """
    held = None; failed = False
    try:
        owner = ownership._validated_owner(token, binding)
        if not _catalog_present(owner):
            yield None
            return
        from monitor import issue_tracker_unit_catalog as catalog
        from monitor import issue_tracker_retained_inventory as inventory
        from monitor import issue_tracker_remote_history_match as remote
        # The old unattempted branch must leave its read-only namespace scope
        # before the creator appends its own names. No settlement scope is
        # needed there, and keeping that reader open would reject our writes.
        with _hold_catalog_attempts(token, binding) as (probe, verify_probe):
            if unit not in tuple(original for original, _state in probe):
                raise GlobalAttemptHold()
            needs_settlement = any(state.attempt_count for _original, state in probe)
            verify_probe()
        if not needs_settlement:
            yield None
            return
        with ExitStack() as scope:
            held = catalog._Originals(); scope.callback(held.close)
            _catalog, units, _previous = catalog._inspect(token, binding, held)
            with _hold_catalog_attempts(token, binding) as (observations, verify_counts):
                if tuple(original for original, _state in observations) != units or unit not in units:
                    raise GlobalAttemptHold()
                if not any(state.attempt_count for _original, state in observations):
                    raise GlobalAttemptHold()
                if (units[-1] != unit or observations[-1][1].attempt_count
                        or observations[-1][1].outcome != 'PENDING_NO_JOURNAL'
                        or any(state.outcome == 'PENDING_NO_JOURNAL' for _original,state in observations[:-1])):
                    raise GlobalAttemptHold()
                parent = owner.directories[-1][0]; stem = owner.lock_name[:-5]
                captured = {name for p,name,*_rest in held.files if p == parent}
                captured.update(name for p,name,*_rest in held.directories if p == parent)
                names = {name for name in os.listdir(parent) if name.startswith(stem + '.')}
                allowed = {stem + '.lock', stem + '.enrollment', stem + '.units', stem + '.units-started',
                    *(stem + '.units-position-%020d' % index for index in range(1,len(units)+1))}
                allowed.update(stem + '.unit-' + original.unit_id + '.' + family
                    for original in units for family in inventory._CATALOG_FAMILIES if family != 'enrollment')
                if names - allowed:
                    raise GlobalAttemptHold()
                # Capture BEFORE semantic settlement. Temporary readers cannot
                # replace these originals after their scopes have returned.
                for name in sorted(names - captured - {stem + '.lock'}):
                    if name.endswith('-started'):
                        held.file(parent,name,16384)
                    else:
                        folder = held.directory(parent,name)
                        family = name.rsplit('.',1)[-1]
                        entries = tuple(os.listdir(folder))
                        if family == 'nv':
                            from monitor import issue_tracker_nv_reservation as nv
                            if frozenset(entries) != nv._CATALOG_NAMES:
                                raise GlobalAttemptHold()
                        else:
                            inventory._family_entries(family,entries)
                        for entry in sorted(entries):
                            held.file(folder,entry,2*1024*1024 if entry.endswith('-RAW') else local._MAX_MANIFEST)
                verify_counts(); held.verify()
            with catalog.hold_pending_project_origins(token,binding) as (origins,verify_origins):
                if tuple(row.unit for row in origins) != units:
                    raise GlobalAttemptHold()
                rows,verify_c6 = scope.enter_context(catalog._hold_project_c6_from_origins(token,binding,origins))
                verify_origins(); held.verify(); verify_c6()
            validators = []
            for row, (original,state) in zip(rows,observations):
                if row.unit != original:
                    raise GlobalAttemptHold()
                if not state.attempt_count:
                    continue
                matches = [(writer,local._owner(writer)) for writer,active in tuple(local._ACTIVE.items())
                    if active.pid == os.getpid()
                    and journal._identity(os.fstat(active.project_fd))[:2] == row.project_identity]
                if len(matches) != 1:
                    raise GlobalAttemptHold()
                writer,project = matches[0]; facts = local._json(row.c6_facts)
                generation = local.Generation(facts['generation_id'],facts['sequence'],facts['manifest_id'],writer)
                actual,verify_inputs,body,_keys = scope.enter_context(
                    remote._hold_original_applied_key_watermark_inputs(writer,token,binding,original,generation))
                if (actual is not project or tuple(body['project_identity']) != row.project_identity
                        or body['binding']['unit_id'] != original.unit_id):
                    raise GlobalAttemptHold()
                verify_keys = scope.enter_context(remote._hold_applied_records(project.root_fd,
                    ('REMOTE-KEY-HIGH-WATER-STARTED-'+original.unit_id,'REMOTE-KEY-HIGH-WATER-'+original.unit_id),
                    body,states=('KEY-HIGH-WATER-STARTED','KEY-HIGH-WATER')))
                validators.extend((verify_inputs,verify_keys))
            new_name = stem + '.unit-' + unit.unit_id + '.journal'
            permitted = frozenset((new_name,new_name[:-len('.journal')]+'.journal-started'))
            if names & permitted:
                raise GlobalAttemptHold()
            def verify():
                if ownership._validated_owner(token,binding) is not owner:
                    raise GlobalAttemptHold()
                additions = permitted & set(os.listdir(parent))
                held.verify(parent_additions=additions); verify_c6()
                for validate in validators:
                    validate()
                held.verify(parent_additions=additions); verify_c6()
            verify()
            yield verify
            verify()
            if not permitted <= set(os.listdir(parent)):
                raise GlobalAttemptHold()
    except Exception:
        failed = True
    if failed:
        raise GlobalAttemptHold() from None


def prepare_global_unit(token, binding, unit):
    """Fixed creator with continuously held original settlement when needed."""
    failed = False
    try:
        with _hold_settled_successor_preparation(token,binding,unit) as verify:
            _prepare_global_unit(token,binding,unit,_verify_settlement=verify)
    except Exception:
        failed = True
    # A contextmanager can retain the injected internal exception even with
    # ``from None``. Raise only outside that handling, preserving the original
    # public no-context error contract and never exposing paths or raw images.
    if failed:
        raise GlobalAttemptHold()


def _prepare_global_unit(token, binding, unit, *, _verify_settlement=None):
    """New coherent images only; never adopt a partial/existing global store."""
    folder = None; failed = False
    try:
        if _verify_settlement is None:
            _guard_catalog_transition(token, binding, unit, preparing=True)
        else:
            _verify_settlement()
        owner, parent, name, header = _inputs(token, binding, unit)
        _require_no_completion(parent,name)
        # A retained store is a conservative barrier even before ATTEMPT-1.
        # New generations/sheets/projects cannot bypass it by another key.
        started=name[:-len('.journal')]+'.journal-started'
        names=set(os.listdir(parent))
        if name in names or started in names: raise GlobalAttemptHold()
        # A separate retained STOP precedes the whole unit namespace. Losing
        # the journal must never turn UNKNOWN or an exhausted count into a
        # fresh first use. Even empty/malformed/partial STARTED blocks creation;
        # it is not completion, inventory, high-water or a send permission.
        with _write_global_start(parent,started,local._canonical({
            'schema_version':1,'state':'GLOBAL-UNIT-STARTED','unit_id':unit.unit_id,
            'header_sha256':hashlib.sha256(local._canonical(header)).hexdigest()})) as verify_start:
            ownership._validated_owner(token,binding)
            verify_start()
            if _verify_settlement is not None: _verify_settlement()
            folder = _create_folder(parent, name)
            local._write_new(folder, 'ACTION-PREIMAGE', unit.action_preimage)
            local._write_new(folder, 'WIRE', unit.wire_bytes)
            local._write_new(folder, 'HEADER', local._canonical(header))
            journal._named(parent, name, folder, directory=True)
            ownership._validated_owner(token, binding)
            # Never create this marker until ALL eight required image barriers
            # succeeded. A failed final HEADER directory fsync otherwise leaves
            # coherent-looking bytes which must not be adopted by a later owner.
            local._write_new(folder, 'INITIALIZED', _initialization(header))
            journal._named(parent, name, folder, directory=True)
            ownership._validated_owner(token, binding)
            count, _previous = _inspect(folder, unit, header)
            if count: raise GlobalAttemptHold()
            verify_start()
            if _verify_settlement is not None: _verify_settlement()
    except Exception: failed = True
    finally:
        if folder is not None:
            try: os.close(folder)
            except OSError: failed = True
    if failed: raise GlobalAttemptHold()


def _observe(token, binding, unit, append):
    folder = None; failed = False
    try:
        if append:
            _guard_catalog_transition(token, binding, unit, preparing=False)
        owner, parent, name, header = _inputs(token, binding, unit)
        folder = local._directory(parent, name)
        journal._named(parent, name, folder, directory=True)
        count, previous = _inspect(folder, unit, header)
        if append:
            _require_no_completion(parent,name,marker_only=True)
            if count == 6: raise GlobalAttemptHold()
            _sync_initialization(parent, folder, header)
            ownership._validated_owner(token, binding)
            journal._named(parent, name, folder, directory=True)
            count += 1
            raw = local._canonical({**header, 'attempt_count': count,
                'previous_sha256': previous, 'outcome': 'UNKNOWN'})
            if _count_claim_original_packet() is not None:
                with _write_global_start(folder, f'ATTEMPT-{count}', raw) as verify_written:
                    verify_written()
            else:
                local._write_new(folder, f'ATTEMPT-{count}', raw)
            _require_no_completion(parent,name,marker_only=True)
        journal._named(parent, name, folder, directory=True)
        ownership._validated_owner(token, binding)
        verified, _previous = _inspect(folder, unit, header)
        if verified != count: raise GlobalAttemptHold()
        result = GlobalIntentObservation(count, unit.wire_sha256, unit.action_digest,
                                         'UNKNOWN' if count else 'UNATTEMPTED_OBSERVATION')
    except Exception: failed = True
    finally:
        if folder is not None:
            try: os.close(folder)
            except OSError: failed = True
    if failed: raise GlobalAttemptHold()
    return result


def inspect_global_unit(token, binding, unit):
    """Read-only global barrier/count observation; never COMPLETE or a permit."""
    # Existing readers must not bypass the original history scope simply by
    # supplying a coherent current/cached unit. This compares images only;
    # original C6, freshness and all send gates remain separate obligations.
    with _hold_original_global_unit(token, binding, selected_unit=unit) as (original, seen, verify):
        compiled._projection(unit)
        if unit != original: raise GlobalAttemptHold()
        verify()
    return seen


@contextmanager
def _hold_original_global_unit(token, binding, *, selected_unit=None):
    """Read the retained single-unit namespace without a caller's unit image.

    Keep every original descriptor before interpreting ACTION/WIRE and through
    the consumer. This does not certify a complete multi-unit inventory, C6,
    current qualification, APPLIED, FIFO, quota or a send capability. Absent or
    partial evidence is HOLD, never an empty inventory or a first-use permit.
    """
    folder = None; folder_object = None; held = []; owned_objects = {}; failed = False
    try:
        owner = ownership._validated_owner(token, binding)
        parent = owner.directories[-1][0]
        name = (owner.lock_name[:-5] + '.journal' if selected_unit is None
                else _inputs(token, binding, selected_unit)[2])
        started = name[:-len('.journal')] + '.journal-started'
        parent_identity = journal._identity(os.fstat(parent))
        folder = local._directory(parent, name)
        opened = os.fstat(folder); folder_object = (opened.st_dev, opened.st_ino)
        journal._named(parent, name, folder, directory=True)
        folder_identity = journal._identity(os.fstat(folder))
        names = frozenset(os.listdir(folder)); count = len(names) - 4
        if (not 0 <= count <= 6 or names != {'ACTION-PREIMAGE', 'WIRE', 'HEADER', 'INITIALIZED',
                *(f'ATTEMPT-{i}' for i in range(1, count + 1))}):
            raise GlobalAttemptHold()
        images = {}
        for directory, entry, limit in (
                (parent, started, 16384),
                *((folder, entry, 1024 * 1024 if entry in ('ACTION-PREIMAGE', 'WIRE') else 16384)
                  for entry in sorted(names))):
            fd = os.open(entry, local._flags(), dir_fd=directory)
            held.append((directory, entry, fd, None, None))
            opened = os.fstat(fd); owned_objects[fd] = (opened.st_dev, opened.st_ino)
            info = local._check(fd, directory=False)
            journal._named(directory, entry, fd, directory=False)
            identity = journal._identity(info)
            raw = os.pread(fd, limit + 1, 0)
            if (not raw or len(raw) != info.st_size or len(raw) > limit
                    or journal._identity(os.fstat(fd)) != identity):
                raise GlobalAttemptHold()
            held[-1] = (directory, entry, fd, identity, raw)
            images[entry] = raw
        def verify():
            if ownership._validated_owner(token, binding) is not owner:
                raise GlobalAttemptHold()
            journal._named(parent, name, folder, directory=True)
            if (journal._identity(os.fstat(parent)) != parent_identity
                    or journal._identity(os.fstat(folder)) != folder_identity
                    or frozenset(os.listdir(folder)) != names):
                raise GlobalAttemptHold()
            for directory, entry, fd, identity, raw in held:
                journal._named(directory, entry, fd, directory=False)
                if (journal._identity(os.fstat(fd)) != identity
                        or os.pread(fd, len(raw) + 1, 0) != raw):
                    raise GlobalAttemptHold()
        verify()
        from monitor.issue_tracker_send_unit import _original_unit
        unit = _original_unit(images['ACTION-PREIMAGE'], images['WIRE'])
        if selected_unit is not None and unit != selected_unit:
            raise GlobalAttemptHold()
        verify()
        _owner, _parent, _name, header = _inputs(token, binding, unit)
        if (_owner is not owner or _parent != parent or _name != name
                or images[started] != local._canonical({
                    'schema_version': 1, 'state': 'GLOBAL-UNIT-STARTED', 'unit_id': unit.unit_id,
                    'header_sha256': hashlib.sha256(local._canonical(header)).hexdigest()})
                or _inspect(folder, unit, header)[0] != count):
            raise GlobalAttemptHold()
        for _directory, _entry, fd, _identity, _raw in held:
            os.fsync(fd)
        os.fsync(folder); os.fsync(parent); verify()
        seen = GlobalIntentObservation(count, unit.wire_sha256, unit.action_digest,
                                       'UNKNOWN' if count else 'UNATTEMPTED_OBSERVATION')
        yield unit, seen, verify
        verify()
    except Exception:
        failed = True
    finally:
        for _directory, _entry, fd, _identity, _raw in reversed(held):
            try:
                current = os.fstat(fd)
                if (current.st_dev, current.st_ino) == owned_objects.get(fd):
                    os.close(fd)
                else:
                    failed = True
            except OSError: failed = True
        if folder is not None:
            try:
                current = os.fstat(folder)
                if (current.st_dev, current.st_ino) == folder_object:
                    os.close(folder)
                else:
                    failed = True
            except OSError: failed = True
    if failed: raise GlobalAttemptHold()


def inspect_original_global_unit(token, binding):
    """Original historical bytes/count only; no reconstruction from a new cycle."""
    with _hold_original_global_unit(token, binding) as (unit, seen, verify):
        verify()
    return unit, seen


def record_global_attempt_intent(token, binding, unit):
    """Persist count BEFORE any eventual send, still not a transport capability."""
    failed = False
    try:
        owner = ownership._validated_owner(token, binding)
        successor = False
        if _catalog_present(owner):
            with _hold_catalog_attempts(token, binding) as (observations, verify):
                successor = any(original != unit and state.attempt_count
                                for original, state in observations)
                verify()
        result = (_record_settled_successor_attempt(token, binding, unit) if successor
                  else _observe(token, binding, unit, True))
    except Exception:
        failed = True
    if failed:
        raise GlobalAttemptHold()
    return result


def _record_settled_successor_attempt(token, binding, unit):
    """One immutable diagnostic count under continuously held real settlement.

    This bounded join handles the final catalog unit only, with every OTHER
    unit genuinely counted and APPLIED/key-settled or count-zero with its
    original committed UNSENT disposition. Uncovered pending units stay HOLD.
    First count uses the actual all-project FIFO reader before the write;
    identical retries retain selected UNKNOWN and compare actual prior keys
    only within their original project. No claim/send/current-source/G1 or
    shared-cadence capability is granted and no prior count is ever cleared.
    Only this fixed function writes its derived ATTEMPT-n; there are no caller
    paths, settlement labels, count overrides or verification callbacks.
    """
    failed = False; result = None
    try:
        owner = ownership._validated_owner(token, binding)
        from monitor import issue_tracker_unit_catalog as catalog
        from monitor import issue_tracker_retained_inventory as inventory
        from monitor import issue_tracker_remote_history_match as remote
        with ExitStack() as scope:
            held = catalog._Originals(); scope.callback(held.close)
            _catalog, units, _previous = catalog._inspect(token, binding, held)
            if len(units) < 2 or units[-1] != unit:
                raise GlobalAttemptHold()
            parent = owner.directories[-1][0]; stem = owner.lock_name[:-5]
            name = stem + '.unit-' + unit.unit_id + '.journal'
            with _hold_catalog_attempts(token, binding) as (observations, verify_counts):
                if (tuple(original for original, _state in observations) != units
                        or any(state.outcome == 'PENDING_NO_JOURNAL' for _original, state in observations[:-1])
                        or observations[-1][1].outcome == 'PENDING_NO_JOURNAL'):
                    raise GlobalAttemptHold()
                count = observations[-1][1].attempt_count
                if not 0 <= count < 6:
                    raise GlobalAttemptHold()
                # Pin ALL old shared images before settlement interpretation.
                # The temporary count reader alone cannot dominate our append.
                captured = {child for p, child, *_rest in held.files if p == parent}
                captured.update(child for p, child, *_rest in held.directories if p == parent)
                names = {child for child in os.listdir(parent) if child.startswith(stem + '.')}
                allowed = {stem + '.lock', stem + '.enrollment', stem + '.units', stem + '.units-started',
                    *(stem + '.units-position-%020d' % index for index in range(1, len(units) + 1))}
                allowed.update(stem + '.unit-' + original.unit_id + '.' + family
                    for original in units for family in inventory._CATALOG_FAMILIES if family != 'enrollment')
                if names - allowed:
                    raise GlobalAttemptHold()
                for child in sorted(names - captured - {stem + '.lock'}):
                    if child.endswith('-started'):
                        held.file(parent, child, 16384)
                    else:
                        folder = held.directory(parent, child); family = child.rsplit('.', 1)[-1]
                        entries = tuple(os.listdir(folder))
                        if family == 'nv':
                            from monitor import issue_tracker_nv_reservation as nv
                            if frozenset(entries) != nv._CATALOG_NAMES:
                                raise GlobalAttemptHold()
                        else:
                            inventory._family_entries(family, entries)
                        for entry in sorted(entries):
                            held.file(folder, entry, inventory._limit(family, entry))
                verify_counts(); held.verify()
            selected = [folder for p, child, folder, _stat, _names in held.directories
                        if p == parent and child == name]
            if len(selected) != 1:
                raise GlobalAttemptHold()
            folder = selected[0]
            _current, _parent, actual_name, header = _inputs(token, binding, unit)
            if _current is not owner or _parent != parent or actual_name != name:
                raise GlobalAttemptHold()
            actual_count, previous = _inspect(folder, unit, header)
            if actual_count != count:
                raise GlobalAttemptHold()
            _require_no_completion(parent, name)
            with catalog.hold_pending_project_origins(token, binding) as (origins, verify_origins):
                if tuple(row.unit for row in origins) != units:
                    raise GlobalAttemptHold()
                rows, verify_c6 = scope.enter_context(catalog._hold_project_c6_from_origins(token, binding, origins))
                verify_origins(); held.verify(); verify_c6()
            if tuple(row.unit for row in rows) != units:
                raise GlobalAttemptHold()
            superseded, verify_other = scope.enter_context(_hold_catalog_other_settlements(token, binding, unit))
            if not count:
                with inventory._hold_all_project_fifo_frontier(token, binding) as (frontier, verify_fifo):
                    if (frontier.frontier != (unit.unit_id,) or frontier.blocked
                            or set(frontier.superseded) != set(superseded)):
                        raise GlobalAttemptHold()
                    # Transfer while both scopes overlap: the fixed disposition
                    # FDs and every shared image already stay held in our own
                    # append-aware scopes. Do not extend read-only FIFO across IO.
                    verify_fifo(); verify_other(); held.verify(); verify_c6()
            appended = None
            def verify():
                if ownership._validated_owner(token, binding) is not owner:
                    raise GlobalAttemptHold()
                held.verify(appended_to=appended); verify_c6()
                verify_other()
                held.verify(appended_to=appended); verify_c6()
            verify(); held.sync(); _sync_initialization(parent, folder, header); verify()
            entry = 'ATTEMPT-%d' % (count + 1)
            raw = local._canonical({**header, 'attempt_count': count + 1,
                                    'previous_sha256': previous, 'outcome': 'UNKNOWN'})
            # Creator FD stays alive across reader capture and every consumer
            # barrier. An interrupted exclusive image stays STOP, never fixed.
            with _write_global_start(folder, entry, raw) as verify_written:
                appended = (folder, {entry})
                verify_written(); verify()
                image, _identity = held.file(folder, entry, 16384)
                if image != raw:
                    raise GlobalAttemptHold()
                verify_written(); verify()
                if _inspect(folder, unit, header)[0] != count + 1:
                    raise GlobalAttemptHold()
                _require_no_completion(parent, name); verify_written(); verify()
            verify()
            result = GlobalIntentObservation(count + 1, unit.wire_sha256, unit.action_digest, 'UNKNOWN')
    except Exception:
        failed = True
    if failed:
        raise GlobalAttemptHold()
    return result


def _reserved_images(token, binding, identity, unit):
    """Reopen actual original stores, not caller-supplied counts or snapshots."""
    from monitor.issue_tracker_enrollment_journal import require_unit_enrollment, inspect_enrollment_journal
    from monitor.issue_tracker_history_preread_journal import require_history_append_capacity
    from monitor.issue_tracker_metadata_reservation import inspect_metadata_reservation
    from monitor.issue_tracker_nv_reservation import require_unit_nv_reservation

    _inputs(token, binding, unit)
    require_unit_enrollment(token, binding, identity, unit)
    original = inspect_enrollment_journal(token, binding, identity)
    history = require_history_append_capacity(token, binding, unit)
    quota = inspect_metadata_reservation(token, binding, identity, unit)
    action = json.loads(unit.action_preimage)
    nv = None
    if action['identity']['sheet'] in ('ETH Cabling', 'IB Cabling') and any(
            item['action'] == 'insert' for item in action['business']):
        nv = require_unit_nv_reservation(token, binding, identity, unit)
    ownership._validated_owner(token, binding)
    return original, history, quota, nv


@contextmanager
def _hold_reserved_quota_originals(token,binding,identity,unit):
    """Retain the actual quota directory/four image FDs across durable count.

    Content equality after reopening is not original-namespace continuity.
    This does not create a quota, reclaim UNKNOWN or establish G1 inventory.
    """
    from monitor import issue_tracker_metadata_reservation as quota
    folder=None
    try:
        parent,name,_base,_state,_sheet,_fence=quota._inputs(token,binding,identity,unit)
        folder=local._directory(parent,name)
        with quota._hold_quota_originals(parent,name,folder) as verify:
            yield verify
    finally:
        if folder is not None: os.close(folder)


def record_reserved_attempt_intent(token, binding, identity, unit):
    """Count only after the exact original reservation chain, then recheck it.

    This necessary local gate is NOT a send permit or fresh admission. It does
    not launch a worker, bound actual wire attempts, discharge hidden PROJECT
    quota, prove row continuity/FIFO, settle UNKNOWN or grant COMPLETE. The
    primitive record_global_attempt_intent remains evidence-only and cannot
    authorize transport. A failed post-count barrier leaves counted UNKNOWN;
    never decrement, repair, replace a reservation or treat the count as send.
    """
    failed = False
    try:
        with _hold_reserved_quota_originals(token,binding,identity,unit) as verify_quota:
            before = inspect_global_unit(token, binding, unit)
            if before.attempt_count == 6: raise GlobalAttemptHold()
            images = _reserved_images(token, binding, identity, unit)
            verify_quota()
            result = record_global_attempt_intent(token, binding, unit)
            verify_quota()
            if (_reserved_images(token, binding, identity, unit) != images
                    or result.attempt_count != before.attempt_count + 1
                    or inspect_global_unit(token, binding, unit) != result):
                raise GlobalAttemptHold()
    except Exception: failed = True
    if failed: raise GlobalAttemptHold()
    return result


def record_original_business_reserved_attempt_intent(token, binding, identity, unit):
    """Bind ALL original business images to the necessary reservation count.

    This is still evidence, NOT fresh admission, a launcher capability, FIFO
    settlement or COMPLETE. Never recreate a missing original. A post-count
    failure retains UNKNOWN; quota's hidden PROJECT limitation is unchanged.
    """
    from monitor.issue_tracker_history_preread_journal import inspect_business_preread

    def originals():
        reservations = _reserved_images(token, binding, identity, unit)
        business = inspect_business_preread(token, binding, identity, unit)
        ownership._validated_owner(token, binding)
        return reservations, business

    failed = False
    try:
        with _hold_reserved_quota_originals(token,binding,identity,unit) as verify_quota:
            before = inspect_global_unit(token, binding, unit)
            if before.attempt_count == 6: raise GlobalAttemptHold()
            images = originals()
            verify_quota()
            result = record_global_attempt_intent(token, binding, unit)
            verify_quota()
            if (originals() != images or result.attempt_count != before.attempt_count + 1
                    or inspect_global_unit(token, binding, unit) != result):
                raise GlobalAttemptHold()
    except Exception: failed = True
    if failed: raise GlobalAttemptHold()
    return result


def _same_first_count_original_fields(count,originals):
    names=('writer','token','binding','unit','project','owner','context','verify')
    if type(count) is not dict or any(name not in count for name in names):raise GlobalAttemptHold()
    if any(count[name]!=original if name in ('binding','context') else count[name] is not original
            for name,original in zip(names,originals)):raise GlobalAttemptHold()


def _first_original_source_prefix_packet():
    key=_FIRST_ORIGINAL_SOURCE_PREFIX.get()
    if key is None:return None
    packet=_LIVE_FIRST_ORIGINAL_SOURCE_PREFIXES.get(key)
    if (type(key) is not _FirstOriginalSourcePrefixAnchor or packet is not key.packet
            or type(packet) is not dict or frozenset(packet)!=key.fields
            or packet['context']!=(os.getpid(),threading.get_ident())
            or local._owner(packet['writer']) is not packet['project']
            or ownership._validated_owner(packet['token'],packet['binding']) is not packet['owner']):
        raise GlobalAttemptHold()
    if key.prefetch_failed:raise GlobalAttemptHold()
    for name,original in zip(('writer','project','token','owner','binding','last','context','_count_scope'),key.originals):
        if (packet[name]!=original if name in ('binding','context') else packet[name] is not original):
            raise GlobalAttemptHold()
    if key.prefetch_scope is not packet['_count_scope']:raise GlobalAttemptHold()
    if packet['used'] is not key.used or packet['count'] is not key.count:raise GlobalAttemptHold()
    if key.prepared is None:
        if any(packet[name] is not None for name in ('row','arguments','body','observe')):raise GlobalAttemptHold()
    else:
        row,unit,body,observe,arguments,snapshot=key.prepared
        if (packet['row'] is not row or row.unit is not unit or packet['arguments'] is not arguments
                or tuple(arguments)!=tuple(name for name,_value in snapshot)
                or any(arguments[name] is not value for name,value in snapshot)):
            raise GlobalAttemptHold()
        expected_body=None if key.exit_attempted else body
        expected_observe=None if key.exit_attempted else observe
        if packet['body'] is not expected_body or packet['observe'] is not expected_observe:raise GlobalAttemptHold()
    if key.count is not None:
        if key.count_fields is None:raise GlobalAttemptHold()
        _same_first_count_original_fields(key.count,key.count_fields)
        if _count_claim_original_packet() is not key.count:raise GlobalAttemptHold()
    if key.prefetched is not None:
        row,unit,count_key,count,record,verify,originals=key.prefetched
        if (key.prepared is None or key.prepared[0] is not row or row.unit is not unit
                or _HELD_COUNT_CLAIM_ORIGINALS.get() is not count_key
                or _count_claim_original_packet() is not count
                or _LIVE_COUNT_SOURCE_GRAPHS.get(count_key) is not record
                or record[0] is not count or count.get('_source_graphs') is not record
                or count['verify'] is not verify):raise GlobalAttemptHold()
        _same_first_count_original_fields(count,originals)
    return packet


@contextmanager
def _hold_first_original_source_prefix(writer,token,binding,last):
    """Fixed receiver-owned lexical prefix, not a returned observation/permit.

    The independent original body starts while core C6/source/K are live. The
    selected COUNT graph overlaps those originals before core closure. Only
    that same live graph can receive the one-use body; its full suffix runs in
    a NEW short source K and finishes before COUNT. No old K escapes the core.
    """
    if _FIRST_ORIGINAL_SOURCE_PREFIX.get() is not None:raise GlobalAttemptHold()
    count_scope=ExitStack()
    packet={'writer':writer,'token':token,'binding':binding,'last':last,
        'project':local._owner(writer),'owner':ownership._validated_owner(token,binding),
        'context':(os.getpid(),threading.get_ident()),'row':None,'arguments':None,
        'body':None,'observe':None,'count':None,'used':False,'_count_scope':count_scope}
    key=_FirstOriginalSourcePrefixAnchor(packet)
    _LIVE_FIRST_ORIGINAL_SOURCE_PREFIXES[key]=packet
    reset=_FIRST_ORIGINAL_SOURCE_PREFIX.set(key)
    primary=cleanup_problem=None
    try:
        _first_original_source_prefix_packet()
        yield
        _first_original_source_prefix_packet()
    except BaseException as error:
        primary=error
    finally:
        # Revoke first; an unconsumed body is interrupted, not completed or
        # replayed after COUNT. Outer original owners/graphs still dominate.
        _LIVE_FIRST_ORIGINAL_SOURCE_PREFIXES.pop(key,None)
        body=(key.prepared[2] if key.prepared is not None and not key.exit_attempted else None)
        key.exit_attempted=True;packet['body']=packet['observe']=None
        for close in (lambda:_FIRST_ORIGINAL_SOURCE_PREFIX.reset(reset),
                *((lambda:body.__exit__(GeneratorExit,GeneratorExit(),None),) if body is not None else ()),
                count_scope.close):
            try:close()
            except BaseException as error:
                cleanup_problem=error
                if primary is None or (isinstance(primary,Exception) and not isinstance(error,Exception)):
                    primary=error
    if primary is not None:
        if cleanup_problem is not None and cleanup_problem is not primary:raise primary from cleanup_problem
        raise primary


def _prepare_first_original_source_prefix(row,observation,**arguments):
    packet=_first_original_source_prefix_packet()
    if packet is None:return
    last=packet['last']
    if (row.unit!=last.unit or row.project_identity!=last.project_identity
            or row.c6_facts!=last.c6_facts or observation.attempt_count!=0):return
    if (packet['row'] is not None or packet['used'] or arguments['writer_token'] is not packet['writer']
            or arguments.get('_shared_retry') is not False):raise GlobalAttemptHold()
    # No K wrapper here: the actual input core owns its strict original K.
    body=_hold_receipted_original_source_inputs_body(packet['token'],packet['binding'],row.unit,**arguments)
    packet['observe']=body.__enter__()
    packet['body']=body;packet['row']=row;packet['arguments']=dict(arguments)
    key=_FIRST_ORIGINAL_SOURCE_PREFIX.get()
    key.prepared=(row,row.unit,body,packet['observe'],packet['arguments'],tuple(arguments.items()))
    _first_original_source_prefix_packet()


def _prefetch_first_original_count_graph():
    """Cold read-only graph entry before IO, never early COUNT/K/CLAIM.

    Core source/business scopes have already entered with no COUNT join and
    keep their original strict K and close order. Only the fixed FIRST receiver
    owns this longer graph scope. R2 and input-only diagnostic paths are not
    silently converted. Failed acquisition never retries or adopts a later
    graph; actual selected row/unit/key/packet/three graphs are anchored once.
    """
    packet=_first_original_source_prefix_packet()
    if packet is None:return
    key=_FIRST_ORIGINAL_SOURCE_PREFIX.get()
    if key.prepared is None:return
    if key.prefetch_attempted:raise GlobalAttemptHold()
    key.prefetch_attempted=True
    row,unit=key.prepared[:2]
    try:
        if _HELD_COUNT_CLAIM_ORIGINALS.get() is not None:raise GlobalAttemptHold()
        verify=key.prefetch_scope.enter_context(_hold_selected_last_catalog_write_originals(
            packet['writer'],packet['token'],packet['binding'],unit))
        count=_count_claim_original_packet();count_key=_HELD_COUNT_CLAIM_ORIGINALS.get()
        record=_LIVE_COUNT_SOURCE_GRAPHS.get(count_key)
        if (count is None or count_key is None or type(record) is not tuple or len(record)!=2
                or record[0] is not count or count.get('_source_graphs') is not record
                or type(record[1]) is not tuple or len(record[1])!=3
                or count['writer'] is not packet['writer'] or count['token'] is not packet['token']
                or count['binding']!=packet['binding'] or count['unit'] is not unit
                or count['project'] is not packet['project'] or count['owner'] is not packet['owner']
                or count['verify'] is not verify):raise GlobalAttemptHold()
        originals=tuple(count[name] for name in ('writer','token','binding','unit','project','owner','context','verify'))
        verify();_same_first_count_original_fields(count,originals)
        key.prefetched=(row,unit,count_key,count,record,verify,originals)
        if _first_original_source_prefix_packet() is not packet:raise GlobalAttemptHold()
        from monitor import issue_tracker_settings_audit_allocation as allocation
        # An actual still-LIVE source factory selects this overlap, never a
        # caller event list or existence of a folder as permission. Ordinary
        # first use without archived deliveries has no source to transfer.
        if any(source.packet['writer'] is packet['writer']
                for source in allocation._LIVE_SOURCE_K_SETTINGS.values()):
            allocation._receive_first_original_count_source(packet['writer'],packet['token'],packet['binding'],unit)
        if _first_original_source_prefix_packet() is not packet:raise GlobalAttemptHold()
    except BaseException:
        key.prefetch_failed=True
        raise


def _bind_first_original_source_prefix(row):
    packet=_first_original_source_prefix_packet()
    if packet is None:raise GlobalAttemptHold()
    count=_count_claim_original_packet()
    if (count is None or count['writer'] is not packet['writer'] or count['token'] is not packet['token']
            or count['binding']!=packet['binding'] or count['unit'] is not row.unit
            or count['project'] is not packet['project'] or count['owner'] is not packet['owner']
            or packet['count'] is not None):raise GlobalAttemptHold()
    if packet['row'] is None:
        if inspect_global_unit(packet['token'],packet['binding'],row.unit).attempt_count==0:
            raise GlobalAttemptHold()
        return
    if packet['row'] is not row or packet['used'] or packet['body'] is None:raise GlobalAttemptHold()
    originals=tuple(count[name] for name in ('writer','token','binding','unit','project','owner','context','verify'))
    originals[-1]()
    _same_first_count_original_fields(count,originals)
    if _first_original_source_prefix_packet() is not packet:raise GlobalAttemptHold()
    key=_FIRST_ORIGINAL_SOURCE_PREFIX.get();key.count=count;key.count_fields=originals
    packet['count']=count
    _first_original_source_prefix_packet()


def _consume_first_original_source_prefix(writer,token,binding,unit,identity,**arguments):
    packet=_first_original_source_prefix_packet()
    key=_FIRST_ORIGINAL_SOURCE_PREFIX.get()
    count=_count_claim_original_packet()
    if (packet is None or packet['used'] or packet['body'] is None or packet['count'] is not count
            or count is None or packet['writer'] is not writer or packet['token'] is not token
            or packet['binding']!=binding or packet['row'].unit is not unit
            or count['unit'] is not unit):raise GlobalAttemptHold()
    # Consume BEFORE observation, including argument drift and suffix failure.
    key.used=True;packet['used']=True
    expected=packet['arguments']
    pending=key.prepared[2]
    try:
        if (set(arguments)!=set(expected) or any(arguments[name] is not expected[name]
                for name in ('qualified_source','store','writer_token','settings','whitelist_snapshot'))
                or any(arguments[name]!=expected[name] for name in
                    ('expected_template_sha256','http_root','whitelist_path','_shared_retry'))):raise GlobalAttemptHold()
        with _hold_receipted_count_source_k(writer,token,binding,unit):
            count['verify']()
            if _first_original_source_prefix_packet() is not packet:raise GlobalAttemptHold()
            observe=key.prepared[3];body=pending
            result=observe(identity)
            if _first_original_source_prefix_packet() is not packet:raise GlobalAttemptHold()
            # Remove cleanup slot before executing the real full suffix. A
            # failed suffix cannot replay the observer or turn into cold PASS.
            key.exit_attempted=True;packet['body']=packet['observe']=None;pending=None
            body.__exit__(None,None,None)
            count['verify']()
            if _first_original_source_prefix_packet() is not packet:raise GlobalAttemptHold()
        # Only a successful COMPLETE suffix, COUNT tail and short-K exit allow
        # subsequent independent full facts. Used/failed alone never do.
        if _first_original_source_prefix_packet() is not packet:raise GlobalAttemptHold()
        key.succeeded=True
    except BaseException as primary:
        key.failed=True;key.exit_attempted=True;packet['body']=packet['observe']=None
        if pending is not None:
            try:pending.__exit__(GeneratorExit,GeneratorExit(),None)
            except BaseException as cleanup:
                if isinstance(primary,Exception) and not isinstance(cleanup,Exception):raise
                raise primary from cleanup
        raise
    return result


def _receipted_original_facts(
    token, binding, identity, unit, *, qualified_source, store, writer_token,
    settings, whitelist_snapshot, expected_template_sha256, http_root, whitelist_path,
    _shared_retry=False,
):
    """Read-only actual original C5/C6 facts, never admission or recompilation."""
    arguments=dict(qualified_source=qualified_source,store=store,writer_token=writer_token,
        settings=settings,whitelist_snapshot=whitelist_snapshot,
        expected_template_sha256=expected_template_sha256,http_root=http_root,
        whitelist_path=whitelist_path,_shared_retry=_shared_retry)
    prefix=_first_original_source_prefix_packet()
    if prefix is not None:
        key=_FIRST_ORIGINAL_SOURCE_PREFIX.get()
        if key.prepared is not None:
            if key.failed or (key.used and not key.succeeded):raise GlobalAttemptHold()
            if not key.used:
                return _consume_first_original_source_prefix(writer_token,token,binding,unit,identity,**arguments)
    with _hold_receipted_original_source_inputs(token,binding,unit,
            qualified_source=qualified_source,store=store,writer_token=writer_token,
            settings=settings,whitelist_snapshot=whitelist_snapshot,
            expected_template_sha256=expected_template_sha256,http_root=http_root,
            whitelist_path=whitelist_path,_shared_retry=_shared_retry) as observe:
        result=observe(identity)
    if prefix is not None and _first_original_source_prefix_packet() is not prefix:raise GlobalAttemptHold()
    return result


@contextmanager
def _hold_receipted_count_source_k(writer,token,binding,unit):
    """Short source-read domain under the actual COUNT/CLAIM original join.

    No join keeps ordinary strict K. This never carries a strict count snapshot
    across an ATTEMPT/CLAIM write or issues any write/send permission: the fixed
    native ALL completed-settings reader owns only this lexical facts replay.
    """
    packet=_count_claim_original_packet()
    if packet is None:
        yield
        return
    def same_join():
        if (_count_claim_original_packet() is not packet or packet['writer'] is not writer
                or packet['token'] is not token or packet['binding']!=binding
                or packet['unit'] is not unit):raise GlobalAttemptHold()
    def current():
        same_join()
        packet['verify']()
        same_join()
    current()
    from monitor import issue_tracker_settings_audit_allocation as allocation
    claims=tuple(name for name in os.listdir(packet['project'].root_fd)
        if name in (allocation._DELIVERY_FOLDER,allocation._DELIVERY_STARTED)
        or name.startswith(allocation._DELIVERY_FOLDER+'-')
        or name.startswith(allocation._DELIVERY_STARTED+'-'))
    # The actual ALL factory proves complete paired claims. Their names alone
    # neither supply event IDs nor authorize an archived projection exception.
    primary=None
    try:
        with ExitStack() as scope:
            try:
                if claims:
                    key=_HELD_COUNT_CLAIM_ORIGINALS.get()
                    if key in allocation._LIVE_COUNT_RECEIVED_SOURCES:
                        scope.enter_context(allocation._hold_received_count_source_k(writer,token,binding,unit))
                    else:
                        prefix=_first_original_source_prefix_packet()
                        first=_FIRST_ORIGINAL_SOURCE_PREFIX.get()
                        if prefix is not None and first.prefetched is not None:raise GlobalAttemptHold()
                        scope.enter_context(allocation._hold_owned_native_completed_source_k(writer,token,binding))
                current()
                yield
                current()
            except BaseException as error:
                # Capture the body interruption before any reader finalizer
                # can replace it with a secondary ordinary HOLD.
                primary=error
                raise
    except BaseException as error:
        if primary is None:primary=error
        elif error is not primary:
            if isinstance(primary,Exception) and not isinstance(error,Exception):
                # A real reader-finalizer interruption dominates an ordinary
                # body refusal, and must also survive the final original check.
                primary=error
            else:raise primary from error
        raise
    finally:
        # Last original check follows the native K issuer's actual revocation
        # and ALL/settings/raw finalizers, including an incoming interruption.
        try:current()
        except BaseException as error:
            if primary is not None:
                if isinstance(primary,Exception) and not isinstance(error,Exception):
                    raise error from primary
                raise primary from error
            raise


@contextmanager
def _hold_receipted_original_source_inputs(
    token,binding,unit,*,qualified_source,store,writer_token,settings,
    whitelist_snapshot,expected_template_sha256,http_root,whitelist_path,
    _shared_retry=False,
):
    with _hold_receipted_count_source_k(writer_token,token,binding,unit), \
            _hold_receipted_original_source_inputs_body(token,binding,unit,
                qualified_source=qualified_source,store=store,writer_token=writer_token,settings=settings,
                whitelist_snapshot=whitelist_snapshot,expected_template_sha256=expected_template_sha256,
                http_root=http_root,whitelist_path=whitelist_path,_shared_retry=_shared_retry) as observe:
        yield observe


@contextmanager
def _hold_receipted_original_source_inputs_body(
    token,binding,unit,*,qualified_source,store,writer_token,settings,
    whitelist_snapshot,expected_template_sha256,http_root,whitelist_path,
    _shared_retry=False,
):
    """Same-call local prefix before reads; no qualification/send handoff.

    Only the first actual local source/receipt observations move. A genuine
    fresh source and receipt are still replayed after the identity-dependent
    business/reservation IO. Both original source calls and all four K graphs
    remain. The fixed one-use observer cannot be used after this lexical scope
    or from another process/thread; no caller verifier/graph/cache is accepted.
    """
    from monitor.issue_tracker_send_unit import _original_receipt_identity, _read_original_generation_identity
    from monitor.issue_tracker_history_preread_journal import inspect_business_preread, inspect_business_source_projection
    from monitor.issue_tracker_stage_l_consumer import qualify_prod_stage_l, replay_original_receipted_prod_source
    from monitor.issue_tracker_cycle_source import read_completed_cycle_evidence
    from monitor.issue_tracker_local_workbook_commit import _source_rows
    from monitor.issue_tracker_online_target import inspect_project_online_target
    from monitor.issue_tracker_settings_audit_allocation import inspect_settings_audit_allocation

    _inputs(token, binding, unit)
    inspect_project_online_target(writer_token, binding)
    action = json.loads(unit.action_preimage)
    audits = (inspect_settings_audit_allocation(writer_token, token, binding, unit)
              if action['audits'] else b'')
    target = action['identity']
    cycles = read_completed_cycle_evidence(store)
    if not cycles or not qualified_source.cycle_ids: raise GlobalAttemptHold()
    older = qualified_source.cycle_ids[-1] != cycles[-1].cycle_id
    if older and _shared_retry is not True: raise GlobalAttemptHold()
    arguments = dict(http_root=http_root, settings=settings,
        whitelist_snapshot=whitelist_snapshot, whitelist_path=whitelist_path,
        writer_token=writer_token)
    def source():
        from monitor.issue_tracker_settings_audit_allocation import (
            _LIVE_COUNT_RECEIVED_SOURCES,_evaluate_received_count_source,_NATIVE_CATALOG_K_CONTEXT)
        relation=_LIVE_COUNT_RECEIVED_SOURCES.get(_HELD_COUNT_CLAIM_ORIGINALS.get())
        if relation is not None and (relation[2]._short_k_original is not None
                or _NATIVE_CATALOG_K_CONTEXT.get() is not relation[2].original.issued):
            return _evaluate_received_count_source(writer_token,token,binding,unit,store,
                http_root=http_root,settings=settings,whitelist_snapshot=whitelist_snapshot,
                whitelist_path=whitelist_path,
                local_generation_id=target['generation_id'] if older else None,
                expected_template_sha256=expected_template_sha256 if older else None)
        if older:
            return replay_original_receipted_prod_source(store, **arguments,
                expected_template_sha256=expected_template_sha256,
                local_generation_id=target['generation_id'])
        return qualify_prod_stage_l(store, **arguments)
    def receipt_identity():
        if older:
            return _read_original_generation_identity(target['generation_id'], writer_token)
        from monitor.issue_tracker_settings_audit_allocation import (
            _LIVE_COUNT_RECEIVED_SOURCES,_evaluate_received_count_receipt,_NATIVE_CATALOG_K_CONTEXT)
        relation=_LIVE_COUNT_RECEIVED_SOURCES.get(_HELD_COUNT_CLAIM_ORIGINALS.get())
        if relation is not None and (relation[2]._short_k_original is not None
                or _NATIVE_CATALOG_K_CONTEXT.get() is not relation[2].original.issued):
            return _evaluate_received_count_receipt(writer_token,token,binding,unit,store,
                qualified_source=qualified_source,generation_id=target['generation_id'],settings=settings,
                whitelist_snapshot=whitelist_snapshot,expected_template_sha256=expected_template_sha256)
        return _original_receipt_identity(qualified_source, store, target['generation_id'],
            writer_token, settings, whitelist_snapshot, expected_template_sha256)
    # A caller's old qualified object does not establish provenance. Replay
    # the actual admitted original before observing its raw C6 identity.
    actual_source = source()
    if actual_source != qualified_source: raise GlobalAttemptHold()
    receipt = receipt_identity()
    if receipt[:3] != (target['generation_id'], target['publish_id'], action['manifest_id']):
        raise GlobalAttemptHold()
    live=True;used=False;completed=False
    origin=(os.getpid(),threading.get_ident())
    def observe(identity):
        nonlocal used,completed
        if not live or used or origin!=(os.getpid(),threading.get_ident()):raise GlobalAttemptHold()
        used=True
        _inputs(token,binding,unit)
        inspect_project_online_target(writer_token,binding)
        reservations = _reserved_images(token, binding, identity, unit)
        business = inspect_business_preread(token, binding, identity, unit)
        cabling_rows, switch_rows = _source_rows(actual_source)
        if inspect_business_source_projection(token, binding, identity, unit, (*cabling_rows, *switch_rows)) != business:
            raise GlobalAttemptHold()
        completed=True
        return receipt, actual_source, reservations, business, audits
    try:
        yield observe
        if (not completed or origin!=(os.getpid(),threading.get_ident())
                or source() != actual_source or read_completed_cycle_evidence(store) != cycles):
            raise GlobalAttemptHold()
        if receipt_identity() != receipt:
            raise GlobalAttemptHold()
        inspect_project_online_target(writer_token, binding)
        ownership._validated_owner(token, binding)
    finally:
        live=False


@contextmanager
def _hold_receipted_audit_originals(writer_token, token, binding, unit):
    """Keep original C25 identities, not two separately reopened snapshots."""
    _inputs(token,binding,unit)
    if json.loads(unit.action_preimage)['audits']:
        from monitor.issue_tracker_settings_audit_allocation import _hold_counted_audit_originals
        with _hold_counted_audit_originals(writer_token,token,binding,unit) as verify:
            yield verify
    else:
        yield lambda: None


def record_receipted_original_attempt_intent(
    token, binding, identity, unit, *, qualified_source, store, writer_token,
    settings, whitelist_snapshot, expected_template_sha256, http_root, whitelist_path,
):
    """Original protected C5/C6, business/reservations/audits around count.

    Both actual owners stay held. No inferred receipt, source recompilation of
    UNKNOWN, repair, count reset or rollback; post-count drift retains UNKNOWN.
    Still no older-cycle R2, cadence, transport, COMPLETE or FIFO authority.
    """
    from monitor.issue_tracker_receipt_snapshot import _hold_history_originals
    def originals():
        return _receipted_original_facts(token,binding,identity,unit,
            qualified_source=qualified_source,store=store,writer_token=writer_token,settings=settings,
            whitelist_snapshot=whitelist_snapshot,expected_template_sha256=expected_template_sha256,
            http_root=http_root,whitelist_path=whitelist_path)

    failed = False
    try:
        with _hold_receipted_audit_originals(writer_token,token,binding,unit) as verify_audits, \
                _hold_history_originals(writer_token) as verify_receipts, \
                _hold_reserved_quota_originals(token,binding,identity,unit) as verify_quota:
            before = inspect_global_unit(token, binding, unit)
            if before.attempt_count == 6: raise GlobalAttemptHold()
            images = originals()
            verify_audits(); verify_receipts(); verify_quota()
            result = record_global_attempt_intent(token, binding, unit)
            verify_audits(); verify_receipts(); verify_quota()
            if (originals() != images or result.attempt_count != before.attempt_count + 1
                    or inspect_global_unit(token, binding, unit) != result):
                raise GlobalAttemptHold()
    except Exception: failed = True
    if failed: raise GlobalAttemptHold()
    return result


def record_shared_retry_continuous_owned_attempt_intent(
    token,binding,unit,*,writer_token,identity_response,history_response,business_reads,
    qualified_source,store,settings,whitelist_snapshot,expected_template_sha256,
    http_root,whitelist_path,headers_response,whitelist_response,metadata_response,
    boot_id,monotonic_ns,
):
    """Original admitted C6 R2 count shares the automatic/manual limiter; not GO.

    Actual issued reads and original C5/C6/reservations dominate the durable
    opportunity INTENT. Counter executes once inside it, then pairs with the
    exact original ATTEMPT before all fresh facts are checked again. Failure
    never rolls back count, deletes an orphan or clears UNKNOWN. Hidden G1,
    fixed launcher/FIFO/COMPLETE still must dominate GO.
    """
    with _hold_shared_retry_counted_sources(
        token,binding,unit,writer_token=writer_token,identity_response=identity_response,
        history_response=history_response,business_reads=business_reads,qualified_source=qualified_source,
        store=store,settings=settings,whitelist_snapshot=whitelist_snapshot,
        expected_template_sha256=expected_template_sha256,http_root=http_root,whitelist_path=whitelist_path,
        headers_response=headers_response,whitelist_response=whitelist_response,metadata_response=metadata_response,
        boot_id=boot_id,monotonic_ns=monotonic_ns,
    ) as (result,_verify_sources):
        return result


@contextmanager
def _hold_shared_retry_counted_sources(
    token,binding,unit,*,writer_token,identity_response,history_response,business_reads,
    qualified_source,store,settings,whitelist_snapshot,expected_template_sha256,
    http_root,whitelist_path,headers_response,whitelist_response,metadata_response,
    boot_id,monotonic_ns,
):
    """Original R2 opportunity/count owners, retained across optional fixed launch.

    The legitimate paired COUNT changes the admission namespace. Pin its new
    complete original prefix only AFTER the real opportunity closes; all
    worker/config/W1/audit/quota owners remain held across that transition.
    This grants neither GO nor completion and never accepts a caller verifier.
    """
    from monitor.issue_tracker_admission import _hold_shared_retry_opportunity
    from monitor.issue_tracker_history_preread_journal import observe_owned_business_continuity
    from monitor.issue_tracker_remote_history_match import observe_owned_unit_read_gates
    from monitor.issue_tracker_local_workbook_commit import _latest_receipted_prod_xlsx
    from monitor.issue_tracker_stage_l_consumer import _hold_original_replay_inputs
    from monitor.issue_tracker_receipt_snapshot import _hold_history_originals
    from monitor.issue_tracker_send_unit import _read_original_generation_identity
    from monitor.issue_tracker_cycle_source import _hold_current_completed_cycle_replay
    from tools.ufm_collection_pipeline import (
        _hold_reusable_directory_reads, _hold_reusable_source_reads,
    )
    from pathlib import Path
    def facts():
        continuity=observe_owned_business_continuity(writer_token,token,binding,unit,
            identity_response=identity_response,history_response=history_response,business_reads=business_reads)
        gates=observe_owned_unit_read_gates(writer_token,token,binding,unit,
            whitelist_snapshot=whitelist_snapshot.whitelist,identity_response=identity_response,
            headers_response=headers_response,whitelist_response=whitelist_response,metadata_response=metadata_response)
        originals=_receipted_original_facts(token,binding,gates.identity,unit,
            qualified_source=qualified_source,store=store,writer_token=writer_token,settings=settings,
            whitelist_snapshot=whitelist_snapshot,expected_template_sha256=expected_template_sha256,
            http_root=http_root,whitelist_path=whitelist_path,_shared_retry=True)
        if (observe_owned_business_continuity(writer_token,token,binding,unit,
                identity_response=identity_response,history_response=history_response,business_reads=business_reads)!=continuity
                or observe_owned_unit_read_gates(writer_token,token,binding,unit,
                    whitelist_snapshot=whitelist_snapshot.whitelist,identity_response=identity_response,
                    headers_response=headers_response,whitelist_response=whitelist_response,metadata_response=metadata_response)!=gates):
            raise GlobalAttemptHold()
        return continuity,gates,originals
    failed=False
    try:
        with _hold_reusable_directory_reads(), _hold_reusable_source_reads(), \
                _hold_original_replay_inputs(store,Path(store.project_identity),whitelist_path) as verify_inputs, \
                _hold_current_completed_cycle_replay(store) as verify_cycles, \
                _hold_receipted_audit_originals(writer_token,token,binding,unit) as verify_audits:
            before=inspect_global_unit(token,binding,unit)
            if not 1<=before.attempt_count<6: raise GlobalAttemptHold()
            original=facts()
            with _hold_reserved_quota_originals(token,binding,original[1].identity,unit) as verify_quota:
                image=_latest_receipted_prod_xlsx(writer_token,expected_template_sha256)
                with _hold_shared_retry_opportunity(writer_token,token,binding,unit,store,image,
                                                     boot_id=boot_id,monotonic_ns=monotonic_ns):
                    # The opportunity INTENT is already durable. Pin its exact
                    # namespace now; close before the legitimate paired COUNT.
                    # Semantic admission replay must not adopt an orphan here.
                    with _hold_history_originals(writer_token) as verify_receipts:
                        def verify_originals():
                            verify_inputs(); verify_cycles(); verify_receipts(); verify_audits(); verify_quota()
                            if _read_original_generation_identity(original[2][0][0],writer_token) != original[2][0]:
                                raise GlobalAttemptHold()
                        verify_originals()
                        result=record_global_attempt_intent(token,binding,unit)
                        # Post-count drift preserves UNKNOWN and an unpaired
                        # opportunity, never repairs or rolls back the counter.
                        verify_originals()
                with _hold_history_originals(writer_token) as verify_paired_receipts:
                    def verify_originals():
                        verify_inputs(); verify_cycles(); verify_paired_receipts(); verify_audits(); verify_quota()
                    def verify_sources():
                        verify_originals()
                        if (facts()!=original or inspect_global_unit(token,binding,unit)!=result):
                            raise GlobalAttemptHold()
                        verify_originals()
                    if result.attempt_count!=before.attempt_count+1: raise GlobalAttemptHold()
                    verify_sources()
                    yield result,verify_sources
                    verify_originals()
    except Exception: failed=True
    if failed: raise GlobalAttemptHold()


@contextmanager
def _hold_shared_retry_owned_attempt_wire(
    token,binding,unit,*,writer_token,identity_response,history_response,business_reads,
    qualified_source,store,settings,whitelist_snapshot,expected_template_sha256,
    http_root,whitelist_path,headers_response,whitelist_response,metadata_response,
    boot_id,monotonic_ns,
):
    """One original admitted identical R2 count through fixed launch, not GO.

    Fresh ALL-business/History/W1 reads and held original C6 sources dominate
    the shared cadence opportunity and one durable count. They remain current
    at consume/pre-Popen/post-send/exit; UNKNOWN and every consumed count/claim
    survive failure. First-count/exhausted units cannot enter this retry lane.
    """
    failed=False
    try:
        local._owner(writer_token)
        if not 1<=inspect_global_unit(token,binding,unit).attempt_count<6: raise GlobalAttemptHold()
        # As in FIRST, retain the actual immutable catalog/origin graph across
        # the entire R2 transition. Borrowers still reread its held stat/bytes;
        # COUNT/CLAIM, source qualification and read deadlines stay independent.
        # Reopening and reparsing this same graph at every nested boundary can
        # otherwise consume the original read budget before native dispatch.
        with _hold_native_catalog_write_replay(token,binding,unit) as verify_catalog, \
                _hold_selected_last_catalog_write_originals(writer_token,token,binding,unit) as verify_all, \
                _hold_shared_retry_counted_sources(
            token,binding,unit,writer_token=writer_token,identity_response=identity_response,
            history_response=history_response,business_reads=business_reads,qualified_source=qualified_source,
            store=store,settings=settings,whitelist_snapshot=whitelist_snapshot,
            expected_template_sha256=expected_template_sha256,http_root=http_root,whitelist_path=whitelist_path,
            headers_response=headers_response,whitelist_response=whitelist_response,metadata_response=metadata_response,
            boot_id=boot_id,monotonic_ns=monotonic_ns,
        ) as (result,verify_sources):
            with _hold_counted_original_wire(writer_token,token,binding,unit) as image:
                if image.attempt_count!=result.attempt_count: raise GlobalAttemptHold()
                with _WIRE_CLAIM_GUARD:
                    issued=_LIVE_WIRE_CLAIMS.get(image)
                    if issued is None: raise GlobalAttemptHold()
                    verify_wire=issued[-2]
                    def verify():
                        verify_catalog(); verify_all(); verify_wire(); verify_sources(); verify_wire(); verify_all(); verify_catalog()
                    _LIVE_WIRE_CLAIMS[image]=issued[:-2]+(verify,issued[-1])
                verify_catalog(); verify_all(); verify_wire()
                yield image
                verify()
    except Exception: failed=True
    if failed: raise GlobalAttemptHold()


def record_owned_receipted_attempt_intent(
    token, binding, unit, *, qualified_source, store, writer_token,
    settings, whitelist_snapshot, expected_template_sha256, http_root, whitelist_path,
    identity_response, headers_response, whitelist_response, metadata_response,
):
    """Issued live read gates around the original C5/C6 durable count, NOT GO.

    No caller template identity/plan/freshness flag is accepted. W1 equality,
    strict template headers, both original enrollment nonces and absence of an
    existing unit fence must survive the original protected count. Read expiry
    or post-count policy drift retains UNKNOWN, never rolls back a count. This
    observation still does not prove hidden PROJECT quota, fresh business/History
    rows, older-cycle R2, shared cadence or any actual mutation/COMPLETE permit.
    """
    from monitor.issue_tracker_remote_history_match import observe_owned_unit_read_gates

    def gates():
        return observe_owned_unit_read_gates(
            writer_token, token, binding, unit, whitelist_snapshot=whitelist_snapshot.whitelist,
            identity_response=identity_response, headers_response=headers_response,
            whitelist_response=whitelist_response, metadata_response=metadata_response)

    failed = False
    try:
        original_gates = gates()
        result = record_receipted_original_attempt_intent(
            token, binding, original_gates.identity, unit, qualified_source=qualified_source,
            store=store, writer_token=writer_token, settings=settings,
            whitelist_snapshot=whitelist_snapshot, expected_template_sha256=expected_template_sha256,
            http_root=http_root, whitelist_path=whitelist_path)
        if gates() != original_gates or inspect_global_unit(token,binding,unit) != result:
            raise GlobalAttemptHold()
    except Exception: failed = True
    if failed: raise GlobalAttemptHold()
    return result


@contextmanager
def _hold_continuous_owned_attempt_wire(
    token,binding,unit,*,writer_token,identity_response,history_response,business_reads,
    qualified_source,store,settings,whitelist_snapshot,expected_template_sha256,
    http_root,whitelist_path,headers_response,whitelist_response,metadata_response,
):
    """First original C6 count through fixed launch; necessary, NOT GO.

    The original source/receipt/audit/quota descriptors and actual issued read
    deadlines remain held through every live wire check, including pre-Popen.
    No caller verifier/permission flag is accepted. Existing UNKNOWN requires
    the separate shared retry cadence; this scope cannot bypass it. Neither
    visible quota nor a consumed claim proves G1, FIFO or COMPLETE.
    """
    from pathlib import Path
    from monitor.issue_tracker_stage_l_consumer import _hold_original_replay_inputs
    from monitor.issue_tracker_receipt_snapshot import _hold_history_originals
    from monitor.issue_tracker_history_preread_journal import observe_owned_business_continuity
    from monitor.issue_tracker_remote_history_match import observe_owned_unit_read_gates
    from monitor.issue_tracker_cycle_source import _hold_current_completed_cycle_replay
    from tools.ufm_collection_pipeline import (
        _hold_reusable_directory_reads, _hold_reusable_source_reads,
    )
    failed=False
    try:
        local._owner(writer_token)
        if inspect_global_unit(token,binding,unit).attempt_count != 0: raise GlobalAttemptHold()
        def facts():
            continuity=observe_owned_business_continuity(writer_token,token,binding,unit,
                identity_response=identity_response,history_response=history_response,business_reads=business_reads)
            gates=observe_owned_unit_read_gates(writer_token,token,binding,unit,
                whitelist_snapshot=whitelist_snapshot.whitelist,identity_response=identity_response,
                headers_response=headers_response,whitelist_response=whitelist_response,metadata_response=metadata_response)
            originals=_receipted_original_facts(token,binding,gates.identity,unit,
                qualified_source=qualified_source,store=store,writer_token=writer_token,settings=settings,
                whitelist_snapshot=whitelist_snapshot,expected_template_sha256=expected_template_sha256,
                http_root=http_root,whitelist_path=whitelist_path)
            if (observe_owned_business_continuity(writer_token,token,binding,unit,
                    identity_response=identity_response,history_response=history_response,business_reads=business_reads)!=continuity
                    or observe_owned_unit_read_gates(writer_token,token,binding,unit,
                        whitelist_snapshot=whitelist_snapshot.whitelist,identity_response=identity_response,
                        headers_response=headers_response,whitelist_response=whitelist_response,metadata_response=metadata_response)!=gates):
                raise GlobalAttemptHold()
            return continuity,gates,originals
        with _hold_reusable_directory_reads(), _hold_reusable_source_reads(), \
                _hold_original_replay_inputs(store,Path(store.project_identity),whitelist_path) as verify_inputs, \
                _hold_current_completed_cycle_replay(store) as verify_cycles, \
                _hold_history_originals(writer_token) as verify_receipts, \
                _hold_receipted_audit_originals(writer_token,token,binding,unit) as verify_audits, \
                _hold_native_catalog_write_replay(token,binding,unit) as verify_catalog, \
                _hold_selected_last_catalog_write_originals(writer_token,token,binding,unit) as verify_all:
            original=facts()
            with _hold_reserved_quota_originals(token,binding,original[1].identity,unit) as verify_quota:
                def verify_originals():
                    verify_inputs(); verify_cycles(); verify_receipts(); verify_audits(); verify_quota(); verify_catalog()
                    verify_all()
                def verify_sources():
                    verify_originals()
                    if facts()!=original: raise GlobalAttemptHold()
                    verify_originals()
                # facts() has just replayed the actual native source and both
                # issued-read gates. Count once under those original owners;
                # nesting the separate count primitive would replay the same
                # unchanged chain again and consume the original read budget.
                verify_originals()
                result=record_global_attempt_intent(token,binding,unit)
                if (result.attempt_count!=1 or
                        inspect_global_unit(token,binding,unit)!=result): raise GlobalAttemptHold()
                verify_sources()
                with _hold_counted_original_wire(writer_token,token,binding,unit) as image:
                    with _WIRE_CLAIM_GUARD:
                        issued=_LIVE_WIRE_CLAIMS.get(image)
                        if issued is None: raise GlobalAttemptHold()
                        verify_wire=issued[-2]
                        def verify():
                            verify_wire(); verify_sources(); verify_wire()
                        _LIVE_WIRE_CLAIMS[image]=issued[:-2]+(verify,issued[-1])
                    # The post-count full replay above remains current only
                    # while every original stays held. Actual consumption,
                    # last pre-Popen, post-send and scope exit still replay
                    # full sources and check issued deadlines independently.
                    verify_wire(); verify_originals(); verify_wire()
                    yield image
                    verify()
    except Exception: failed=True
    if failed: raise GlobalAttemptHold()


def record_continuous_owned_attempt_intent(
    token,binding,unit,*,writer_token,identity_response,history_response,business_reads,
    qualified_source,store,settings,whitelist_snapshot,expected_template_sha256,
    http_root,whitelist_path,headers_response,whitelist_response,metadata_response,
):
    """Actual ALL business/History reads around original C6 count, not GO.

    Never recompile an UNKNOWN unit, ignore NOOP, reset a count, settle a fence
    or accept a caller freshness flag. Post-count expiry/drift keeps UNKNOWN.
    Shared cadence, actual one-use mutation and hidden PROJECT quota remain
    separate requirements, so this necessary counter yields no send capability.
    """
    from monitor.issue_tracker_history_preread_journal import observe_owned_business_continuity
    def continuity():
        return observe_owned_business_continuity(writer_token,token,binding,unit,
            identity_response=identity_response,history_response=history_response,business_reads=business_reads)
    failed = False
    try:
        original = continuity()
        result = record_owned_receipted_attempt_intent(token,binding,unit,
            qualified_source=qualified_source,store=store,writer_token=writer_token,
            settings=settings,whitelist_snapshot=whitelist_snapshot,
            expected_template_sha256=expected_template_sha256,http_root=http_root,whitelist_path=whitelist_path,
            identity_response=identity_response,headers_response=headers_response,
            whitelist_response=whitelist_response,metadata_response=metadata_response)
        if continuity() != original or inspect_global_unit(token,binding,unit) != result: raise GlobalAttemptHold()
    except Exception: failed = True
    if failed: raise GlobalAttemptHold()
    return result
