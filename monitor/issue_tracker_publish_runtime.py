"""REQ7 Stage-L status and protected local-only C5-to-C6 entrypoint.

Qualification is not a browser confirmation, local RECEIPT, or online permit.
The root worker owns the trigger; this module never sends to Google.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import math
import os
from pathlib import Path
from contextlib import contextmanager, ExitStack
import stat
import sys
from types import FunctionType, MappingProxyType
from contextvars import ContextVar
import threading

from monitor.issue_tracker_cycle_source import (
    CycleSequenceGap, CycleSourceHoldError, read_completed_cycle_evidence,
)
from monitor.issue_tracker_k_chain import KChainHoldError, assess_k_window
from monitor.issue_tracker_manifest import (
    _runtime_skip, selected_panel_decision_sha256,
)
from monitor.issue_tracker_state_owner import (
    TrackerStateHold, current_k, tracker_writer, tracker_settings_writer, tracker_local_c6_writer,
)
from monitor.issue_tracker_switch_runtime import (
    SwitchRuntimeHoldError, read_switch_runtime_window,
)
from monitor.issue_tracker_whitelist_workbook import (
    WhitelistHoldError, read_whitelist_workbook,
)
from tools.project_contract import MIN_CONTINUOUS_INTERVAL_MINUTES


class StageLHold(ValueError):
    """No local admission or publication authority can be inferred."""


class CableSourceHold(StageLHold):
    """The current local-only Cable source scope is unavailable or revoked."""


_CABLE_SOURCE_SCOPES = {}
_CABLE_NATIVE_BORROWS = {}
_CABLE_NATIVE_CURRENT = ContextVar('req7_cable_native_originals', default=None)
_CABLE_ETH_INFO_CUSTODIES = {}
_CABLE_ETH_INFO_CURRENT = ContextVar('req7_cable_eth_info_custody', default=None)
_CABLE_W1_CUSTODIES = {}
_CABLE_W1_CURRENT = ContextVar('req7_cable_w1_custody', default=None)
_CABLE_N_CUSTODIES = {}
_CABLE_N_CURRENT = ContextVar('req7_cable_n_policy_custody', default=None)


def _cable_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_uid, info.st_gid, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _cable_require_completed_reader(store, root):
    """Borrow the actual existing-only reader/lease, still strictly NO_SEND."""
    from monitor.issue_tracker_stage_l_consumer import qualify_prod_stage_l
    try:
        cls = type(store)
        method = vars(cls).get('_require_gate')
        worker = Path(qualify_prod_stage_l.__code__.co_filename).with_name('switch-collection-worker.py')
        if type(method) is not FunctionType:
            raise CableSourceHold('Cable completed reader method is not original')
        namespace = method.__globals__
        constructor = vars(cls).get('__init__')
        provider_method = vars(cls).get('_provider')
        if (namespace.get('CompletedCollectionCycleReader') is not cls
                or Path(namespace.get('__file__', '')) != worker
                or Path(method.__code__.co_filename) != worker
                or type(constructor) is not FunctionType
                or constructor.__globals__ is not namespace
                or Path(constructor.__code__.co_filename) != worker
                or type(provider_method) is not staticmethod
                or type(provider_method.__func__) is not FunctionType
                or provider_method.__func__.__globals__ is not namespace
                or Path(provider_method.__func__.__code__.co_filename) != worker):
            raise CableSourceHold('Cable completed reader class binding differs')
        collecting_class = namespace.get('CollectionGate')
        if not isinstance(collecting_class, type):
            raise CableSourceHold('Cable completed reader provider is absent')
        provider = sys.modules.get(collecting_class.__module__)
        gate_path = worker.with_name('switch_collection_gate.py')
        if (provider is None or getattr(provider, 'CollectionGate', None) is not collecting_class
                or Path(provider.__file__) != gate_path
                or collecting_class.__init__.__globals__ is not provider.__dict__):
            raise CableSourceHold('Cable completed reader gate provider differs')
        for name in ('_require_completed_source_read_lease',
                     '_completed_read_registered', '_completed_source_reader_layout'):
            function = getattr(provider, name, None)
            if (type(function) is not FunctionType
                    or function.__globals__ is not provider.__dict__
                    or Path(function.__code__.co_filename) != gate_path):
                raise CableSourceHold('Cable completed reader registry source differs')
        lease = store.gate
        provider._require_completed_source_read_lease(lease)
        method(store)  # Actual Reader guard, never an allowed collecting gate.
        record = provider._completed_read_registered(lease)
        project = lease.project
        key = hashlib.sha256(project.encode('utf-8')).hexdigest()
        root_status = root / 'monitor/status'
        status = root_status / 'collection-cycles' / key / 'prod/switch_collection'
        expected = (root_status, status, status / 'records', status / 'high-water.json',
                    project, key, 'prod', 'switch_collection')
        if (provider._completed_source_reader_layout(lease) != expected
                or tuple(getattr(store, name) for name in (
                    'root_status_dir', 'status_dir', 'records_dir', 'witness_path',
                    'project_identity', 'project_key', 'scope', 'source')) != expected
                or lease.scope != 'prod' or lease.lane != 'completed-source-read'
                or lease.status_dir != root_status
                or lease.collection_keys != ('prod-ethernet', 'prod-infiniband', 'prod-nvlink')
                or lease.state_name != '.switch-collection-cooldown.json'
                or lease.lock_name != '.switch-collection-cooldown.lock'
                or record['lease'] is not lease or record['locked'] is not True
                or record['execution'] != (os.getpid(), threading.get_ident())):
            raise CableSourceHold('Cable completed reader layout or lease differs')
        fd = lease._lock_fd
        if type(fd) is not int or fd < 0 or record['fields']['_lock_fd'] != fd:
            raise CableSourceHold('Cable completed reader lock is unavailable')
        held = os.fstat(fd)
        named = os.stat(lease.lock_name, dir_fd=record['status_fd'], follow_symlinks=False)
        if (not stat.S_ISREG(held.st_mode) or held.st_nlink != 1
                or held.st_uid != os.geteuid() or stat.S_IMODE(held.st_mode) != 0o600
                or (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino)
                or not any(slot == (fd, held.st_dev, held.st_ino) for slot in record['slots'])):
            raise CableSourceHold('Cable completed reader LOCK original differs')
        provider._require_completed_source_read_lease(lease)
        return cls, lease, fd, _cable_identity(held)
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        raise CableSourceHold('Cable completed reader source is unavailable') from None


def _cable_require_store(store, root):
    """Reject DTO/duck stores; this remains NO_SEND, not native-origin proof."""
    reader_method = vars(type(store)).get('_require_gate')
    if (type(reader_method) is FunctionType
            and reader_method.__globals__.get('CompletedCollectionCycleReader') is type(store)):
        return _cable_require_completed_reader(store, root)
    from monitor.issue_tracker_stage_l_consumer import qualify_prod_stage_l
    fields = {'gate', 'source', 'scope', 'project_identity', 'project_key',
              'root_status_dir', 'status_dir', 'records_dir', 'witness_path'}
    cls = type(store)
    method = vars(cls).get('_require_gate')
    worker = Path(qualify_prod_stage_l.__code__.co_filename).with_name('switch-collection-worker.py')
    if (set(vars(store)) != fields or type(method) is not FunctionType
            or Path(method.__code__.co_filename) != worker
            or method.__globals__.get('CollectionCycleStore') is not cls):
        raise CableSourceHold('Cable source requires the actual worker store')
    gate_module = sys.modules.get('switch_collection_gate')
    gate = store.gate
    if (gate_module is None or type(gate) is not gate_module.CollectionGate
            or method.__globals__.get('CollectionGate') is not type(gate)):
        raise CableSourceHold('Cable source requires the actual collection gate')
    method(store)
    project = Path(gate.project)
    key = hashlib.sha256(str(project).encode('utf-8')).hexdigest()
    status = root / 'monitor/status/collection-cycles' / key / 'prod/switch_collection'
    if (gate.scope != 'prod' or gate.lane != 'collection'
            or Path(gate.status_dir) != root / 'monitor/status'
            or store.source != 'switch_collection' or store.scope != 'prod'
            or store.project_identity != gate.project or store.project_key != key
            or Path(store.root_status_dir) != root / 'monitor/status'
            or Path(store.status_dir) != status
            or Path(store.records_dir) != status / 'records'
            or Path(store.witness_path) != status / 'high-water.json'):
        raise CableSourceHold('Cable worker/store/gate paths do not agree')
    held = os.fstat(gate._lock_fd)
    named = os.stat(Path(gate.status_dir) / gate.lock_name, follow_symlinks=False)
    if (not stat.S_ISREG(held.st_mode) or held.st_nlink != 1
            or (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino)):
        raise CableSourceHold('Cable collection gate original is unavailable')
    return cls, gate, gate._lock_fd, _cable_identity(held)


class _CableOriginals:
    """Bounded original FD reads, never a source/path/permission DTO issuer.

    Every opened slot is registered against its named preimage BEFORE fstat.
    A replaced/unknown numeric slot is not adopted or retried during cleanup.
    Directory ancestry retains inode/mode/owner; selected namespaces additionally
    retain full stat and names, including change-and-restore witnesses.
    """
    def __init__(self, root, project_key):
        from monitor.issue_tracker_stage_l_consumer import qualify_prod_stage_l
        from monitor import collection_ib_producer as producer
        self.root = Path(root)
        code = Path(qualify_prod_stage_l.__code__.co_filename).parents[1]
        # Fixed actual native code roles, NOT a caller-supplied root list.
        self.code_files = frozenset((
            code / 'ztp/config/nvos/template/P2P/p2p-to-validation.py',
            code / 'ztp/config/topology_rules.py',
            code / 'ztp/config/ib_topology_provenance.py',
            code / 'tools/ibdiagnet-analyze-tool/config/port_profiles.csv',
            code / 'monitor/issue_tracker_switch_info_source.py',
            code / 'monitor/issue_tracker_publish_runtime.py',
            code / 'monitor/issue_tracker_whitelist_workbook.py',
            code / 'monitor/issue_tracker_admission.py',
            code / 'tools/project_contract.py',
        ))
        self.authority_path = producer._AUTHORITY_DIR / (project_key + '.json')
        self.attestation_root = producer._ATTESTATION_DIR / project_key
        self.directories = {}
        self.files = {}
        self.links = {}
        self.namespaces = {}
        self.slots = []
        self.total = 0
        self.closed = False
        self.preflights = {}
        self.native_paths = set()
        self.native_aliases = {}

    def require_path(self, value, *, directory=False, view=os, protected=False):
        path = Path(value)
        if (not path.is_absolute() or '..' in path.parts
                or '\x00' in str(path)):
            raise CableSourceHold('Cable source path is not canonical absolute data')
        if not protected:
            if view is not os:
                raise CableSourceHold('Cable data source has a foreign OS view')
            allowed = path.is_relative_to(self.root) or path in self.code_files
            if directory:
                allowed = allowed or self.root.is_relative_to(path) or any(
                    item.is_relative_to(path) for item in self.code_files)
        else:
            # Only the native producer's fixed protected selectors use its
            # module-local OS view; no sidecar may select a protected filename.
            from monitor import collection_ib_producer as producer
            allowed = (view is producer.os and (path == self.authority_path
                or (path.parent == self.attestation_root
                    and len(path.stem) == 64
                    and all(char in '0123456789abcdef' for char in path.stem)
                    and path.suffix == '.json')))
            if directory and view is producer.os:
                allowed = (self.authority_path.parent.is_relative_to(path)
                           or self.attestation_root.is_relative_to(path))
        if not allowed:
            raise CableSourceHold('Cable source path is outside its fixed role roots')
        return path

    def _register(self, view, fd, before):
        if len(self.slots) >= 2048:
            # The just-returned original is still registered for real cleanup.
            self.slots.append((view, fd, (before.st_dev, before.st_ino)))
            raise CableSourceHold('Cable source descriptor budget exceeded')
        self.slots.append((view, fd, (before.st_dev, before.st_ino)))

    def directory(self, path, view=os, *, protected=False):
        path = self.require_path(path, directory=True, view=view, protected=protected)
        key = (id(view), path)
        if key in self.directories:
            return self.directories[key][0]
        flags = view.O_RDONLY | view.O_NOFOLLOW | view.O_CLOEXEC | view.O_DIRECTORY
        flags |= getattr(view, 'O_NONBLOCK', 0)
        if path == Path('/'):
            before = view.stat('/', follow_symlinks=False)
            fd = view.open('/', flags)
            parent = None
        else:
            parent = self.directory(path.parent, view, protected=protected)
            before = view.stat(path.name, dir_fd=parent, follow_symlinks=False)
            fd = view.open(path.name, flags, dir_fd=parent)
        self._register(view, fd, before)
        current = view.fstat(fd)
        if (not stat.S_ISDIR(current.st_mode)
                or _cable_identity(current) != _cable_identity(before)):
            raise CableSourceHold('Cable source directory changed during open')
        identity = (current.st_dev, current.st_ino, current.st_mode,
                    current.st_uid, current.st_gid)
        self.directories[key] = (fd, parent, identity, view)
        return fd

    def file(self, path, *, expected=None, view=os, protected=False):
        path = self.require_path(path, view=view, protected=protected)
        parent = self.directory(path.parent, view, protected=protected)
        key = (id(view), path)
        if key not in self.files:
            before = view.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if (view is os and path in self.preflights
                    and _cable_identity(before) != self.preflights[path]):
                raise CableSourceHold('Cable provenance changed after path preflight')
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or not 0 <= before.st_size <= 512 * 1024 * 1024
                    or (protected and (before.st_uid != 0
                        or stat.S_IMODE(before.st_mode) != 0o600))):
                raise CableSourceHold('Cable original is not bounded regular data')
            if self.total + before.st_size > 1024 * 1024 * 1024:
                raise CableSourceHold('Cable source byte budget exceeded')
            flags = (view.O_RDONLY | view.O_NOFOLLOW | view.O_CLOEXEC
                     | getattr(view, 'O_NONBLOCK', 0))
            fd = view.open(path.name, flags, dir_fd=parent)
            self._register(view, fd, before)
            if _cable_identity(view.fstat(fd)) != _cable_identity(before):
                raise CableSourceHold('Cable original changed during open')
            digest = self._digest(view, fd, before.st_size)
            self.files[key] = (fd, parent, _cable_identity(before), digest, view)
            self.total += before.st_size
        fd, parent, identity, digest, view = self.files[key]
        if expected is not None and digest != expected:
            raise CableSourceHold('Cable original digest differs from validated source')
        self._verify_file(path, self.files[key])
        return fd

    @staticmethod
    def _digest(view, fd, size):
        digest, position = hashlib.sha256(), 0
        while position < size:
            part = view.pread(fd, min(1024 * 1024, size - position), position)
            if not part:
                raise CableSourceHold('Cable original shortened during read')
            digest.update(part)
            position += len(part)
        if view.pread(fd, 1, position):
            raise CableSourceHold('Cable original grew during read')
        return digest.hexdigest()

    def raw(self, path, *, view=os, maximum=16 * 1024 * 1024, protected=False,
            _existing_record=None):
        if _existing_record is None:
            fd = self.file(path, view=view, protected=protected)
        else:
            # Strict internal reuse: never acquire an unknown path or adopt
            # an equal tuple/numeric FD supplied in place of the actual record.
            path = Path(path)
            if (self.closed or view is not os or protected
                    or self.files.get((id(view), path)) is not _existing_record):
                raise CableSourceHold('Cable existing original record is unavailable')
            caller = sys._getframe(1)
            eth = _CABLE_ETH_INFO_CURRENT.get()
            w1 = _CABLE_W1_CURRENT.get()
            policy = _CABLE_N_CURRENT.get()
            if (type(eth) is _CableEthInfoCustody
                    and caller.f_code is _CableEthInfoCustody.read.__code__):
                custody = eth
            elif (type(w1) is _CableW1Custody
                    and caller.f_code is _CableW1Custody.read.__code__):
                custody = w1
            elif (type(policy) is _CablePolicyCustody
                    and caller.f_code is _CablePolicyCustody.read.__code__):
                custody = policy
            else:
                raise CableSourceHold('Cable existing original has no active fixed reader')
            if (caller.f_globals is not globals()
                    or caller.f_locals.get('self') is not custody
                    or custody.originals is not self):
                raise CableSourceHold('Cable existing original reader differs')
            custody.require_live()
            custody._bindings()
            self._verify_file(path, _existing_record)
            fd = _existing_record[0]
        size = view.fstat(fd).st_size
        if size > maximum:
            raise CableSourceHold('Cable source document exceeds its bound')
        raw = view.pread(fd, size + 1, 0)
        if len(raw) != size:
            raise CableSourceHold('Cable source document changed during read')
        self._verify_file(Path(path), self.files[(id(view), Path(path))])
        return raw

    def document(self, path, *, view=os, protected=False):
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise CableSourceHold('Cable source duplicate JSON member')
                result[key] = value
            return result
        def constant(_value):
            raise CableSourceHold('Cable source nonfinite JSON member')
        return json.loads(self.raw(path, view=view, protected=protected).decode('utf-8'),
                          object_pairs_hook=pairs, parse_constant=constant)

    def namespace(self, path, *, view=os):
        path = Path(path)
        fd = self.directory(path, view)
        key = (id(view), path)
        names = tuple(sorted(view.listdir(fd)))
        if (len(names) > 2048 or any(name in ('', '.', '..') or '/' in name
                                   for name in names)):
            raise CableSourceHold('Cable source namespace exceeds its bound')
        saved = (_cable_identity(view.fstat(fd)), names)
        if key in self.namespaces and self.namespaces[key] != saved:
            raise CableSourceHold('Cable source namespace changed')
        self.namespaces[key] = saved
        return names

    def tree(self, path, *, depth=0, view=os):
        if depth > 16:
            raise CableSourceHold('Cable source tree exceeds its bound')
        path = Path(path)
        fd = self.directory(path, view)
        for name in self.namespace(path, view=view):
            info = view.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                self.tree(path / name, depth=depth + 1, view=view)
            elif stat.S_ISREG(info.st_mode):
                self.file(path / name, view=view)
            else:
                raise CableSourceHold('Cable source tree contains an alias or special file')

    def preflight_provenance_identity(self, item):
        # SHA-bound sidecar syntax/path screen only. No source file contents
        # are read here. This precedes holding source contents and native replay.
        if type(item) is not dict or set(item) != {'path', 'resolved_path', 'kind', 'sha256'}:
            raise CableSourceHold('Cable provenance identity is incomplete')
        if (type(item['path']) is not str or type(item['resolved_path']) is not str
                or item['kind'] != 'file' or type(item['sha256']) is not str
                or len(item['sha256']) != 64
                or any(char not in '0123456789abcdef' for char in item['sha256'])):
            raise CableSourceHold('Cable provenance file identity is malformed')
        lexical = self.require_path(item['path'])
        resolved = self.require_path(item['resolved_path'])
        path = lexical
        for _ in range(8):
            parent = self.directory(path.parent)
            info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISLNK(info.st_mode):
                break
            target = os.readlink(path.name, dir_fd=parent)
            saved_link = (parent, _cable_identity(info), target)
            if path in self.links and self.links[path] != saved_link:
                raise CableSourceHold('Cable provenance selector was rebound')
            self.links[path] = saved_link
            # Reject escape BEFORE any stat/open at the next link target.
            next_path = self.require_path(Path(os.path.abspath(path.parent / target)))
            fixed_p2p = self.root / 'ztp/config/nvos/template/P2P/p2p.xlsx'
            if lexical == fixed_p2p:
                expected = (resolved.parent / 'p2p.xlsx' if path == fixed_p2p else resolved)
                if next_path != expected:
                    raise CableSourceHold('Cable P2P link differs from the fixed two-link selection')
            path = next_path
        else:
            raise CableSourceHold('Cable provenance alias depth exceeds its bound')
        if (path != resolved or not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1):
            raise CableSourceHold('Cable provenance resolution differs')
        saved = _cable_identity(info)
        if path in self.preflights and self.preflights[path] != saved:
            raise CableSourceHold('Cable provenance source was rebound')
        self.preflights[path] = saved

    def provenance_identity(self, item):
        # Called ONLY after the authority-bound pure schema/role/path screen.
        # Re-run the link screen, then require the same preflight inode before
        # the first held hash read. Native strict replay is still mandatory.
        self.preflight_provenance_identity(item)
        self.file(Path(item['resolved_path']), expected=item['sha256'])
        lexical, resolved = Path(item['path']), Path(item['resolved_path'])
        prior = self.native_aliases.get(lexical)
        if prior is not None and prior != resolved:
            raise CableSourceHold('Cable native alias cannot adopt a different original')
        self.native_aliases[lexical] = resolved
        self.native_aliases[resolved] = resolved
        self.native_paths.add(resolved)

    def _verify_file(self, path, record):
        fd, parent, identity, digest, view = record
        if (_cable_identity(view.fstat(fd)) != identity
                or _cable_identity(view.stat(path.name, dir_fd=parent,
                                            follow_symlinks=False)) != identity
                or self._digest(view, fd, identity[6]) != digest
                or _cable_identity(view.fstat(fd)) != identity):
            raise CableSourceHold('Cable original identity or bytes changed')

    def verify(self):
        if self.closed:
            raise CableSourceHold('Cable originals are closed')
        for (_view_id, path), (fd, parent, identity, view) in self.directories.items():
            held = view.fstat(fd)
            named = view.stat(path.name, dir_fd=parent, follow_symlinks=False) if parent is not None else view.stat('/', follow_symlinks=False)
            project = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
            if project(held) != identity or project(named) != identity:
                raise CableSourceHold('Cable original directory was rebound')
        for (view_id, path), (identity, names) in self.namespaces.items():
            fd, _parent, _identity, view = self.directories[(view_id, path)]
            if _cable_identity(view.fstat(fd)) != identity or tuple(sorted(view.listdir(fd))) != names:
                raise CableSourceHold('Cable original namespace changed')
        for path, (parent, identity, target) in self.links.items():
            if (_cable_identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) != identity
                    or os.readlink(path.name, dir_fd=parent) != target):
                raise CableSourceHold('Cable original topology selector changed')
        for (_view_id, path), record in self.files.items():
            self._verify_file(path, record)

    def close(self):
        if self.closed:
            raise CableSourceHold('Cable original cleanup cannot be replayed')
        self.closed = True
        errors = []
        for view, fd, key in reversed(self.slots):
            try:
                info = view.fstat(fd)
                if (info.st_dev, info.st_ino) != key:
                    raise CableSourceHold('Cable original cleanup identity is unknown')
                view.close(fd)  # One attempt only; no numeric retry or rescue.
            except BaseException as error:
                errors.append(error)
        if errors:
            interrupt = next((error for error in errors if not isinstance(error, Exception)), None)
            if interrupt is not None:
                raise interrupt
            raise CableSourceHold('Cable original critical cleanup is uncertain') from None


class _CableEthInfoCustody:
    """Provisional fixed ETH/NV info custody; never IB, SDK or source authority."""
    def __init__(self, registration, originals, token, owner, store, store_binding):
        caller = sys._getframe(1)
        root_method = _hold_current_cable_cycle_source.__wrapped__
        if (caller.f_code is not root_method.__code__
                or caller.f_globals is not globals()
                or type(originals) is not _CableOriginals):
            raise CableSourceHold('Cable ETH custody requires the actual source root')
        self.registration = registration
        self.originals = originals
        self.file_table, self.original_root = originals.files, originals.root
        self.token, self.owner, self.store = token, owner, store
        self.store_binding = store_binding
        self.owner_binding = tuple(getattr(owner, name) for name in (
            'project', 'publication', 'pid', 'project_fd', 'root_fd',
            'publication_fd', 'lock_fd', 'lock_dev', 'lock_ino'))
        self.execution_owner = (os.getpid(), threading.get_ident())
        self.active, self.failure = True, None
        from monitor import issue_tracker_switch_info_source as info
        from monitor import issue_tracker_switch_runtime as switch
        self.info, self.switch = info, switch
        self.source_path = Path(__file__).parent / 'issue_tracker_switch_info_source.py'
        originals.file(self.source_path)
        self.source_record = originals.files[(id(os), self.source_path)]
        self.runtime_path = Path(__file__)
        originals.file(self.runtime_path)
        self.runtime_record = originals.files[(id(os), self.runtime_path)]
        # Compile the held image only; never execute cached provider code.
        expected = compile(originals.raw(self.source_path), str(self.source_path),
                           'exec', dont_inherit=True)
        codes = {value.co_name: value for value in expected.co_consts
                 if isinstance(value, type(expected))}
        functions = (info._exact_archive_bytes, info.read_switch_info_preview)
        if (getattr(info, '_CABLE_EXACT_ARCHIVE_ORIGINAL', None) is not functions[0]
                or getattr(info, '_CABLE_INFO_PREVIEW_ORIGINAL', None) is not functions[1]):
            raise CableSourceHold('Cable ETH consumer original is unavailable')
        for function, name in zip(functions, (
                '_exact_archive_bytes', 'read_switch_info_preview')):
            if (type(function) is not FunctionType
                    or function.__globals__ is not vars(info)
                    or function.__code__.co_filename != str(self.source_path)
                    or function.__code__ != codes.get(name)
                    or function.__closure__ is not None
                    or function.__defaults__ is not None):
                raise CableSourceHold('Cable ETH consumer differs from held source')
        if (functions[0].__kwdefaults__ is not None
                or functions[1].__kwdefaults__ != {
                    'max_archive_bytes': 8 * 1024 * 1024,
                    'max_member_bytes': 1024 * 1024}
                or switch.read_switch_info_preview is not functions[1]):
            raise CableSourceHold('Cable ETH consumer call boundary changed')
        runtime_image = compile(originals.raw(self.runtime_path), str(self.runtime_path),
                                'exec', dont_inherit=True)
        runtime_codes = {value.co_name: value for value in runtime_image.co_consts
                         if isinstance(value, type(runtime_image))}
        class_code = runtime_codes.get('_CableEthInfoCustody')
        if class_code is None:
            raise CableSourceHold('Cable ETH custody source is absent')
        class_codes = {value.co_name: value for value in class_code.co_consts
                       if isinstance(value, type(runtime_image))}
        original_class = runtime_codes.get('_CableOriginals')
        if original_class is None:
            raise CableSourceHold('Cable original reader source is absent')
        raw_codes = {value.co_name: value for value in original_class.co_consts
                     if isinstance(value, type(runtime_image))}
        audit = [(root_method, runtime_codes.get('_hold_current_cable_cycle_source')),
                 (_CableOriginals.raw, raw_codes.get('raw')),
                 (_read_cable_eth_info_if_current,
                  runtime_codes.get('_read_cable_eth_info_if_current'))]
        audit.append((_cable_known_nv_info_reader,
                      runtime_codes.get('_cable_known_nv_info_reader')))
        audit.extend((vars(_CableEthInfoCustody)[name], class_codes.get(name))
                     for name in ('__init__', 'require_live', '_bindings',
                                  '_known_nv_legacy', 'read'))
        self.runtime_functions = tuple(function for function, _code in audit)
        if any(type(function) is not FunctionType
               or function.__globals__ is not globals()
               or function.__code__ != expected_code
               or function.__code__.co_filename != str(self.runtime_path)
               or function.__closure__ is not None
               for function, expected_code in audit):
            raise CableSourceHold('Cable ETH runtime differs from held source')
        self.runtime_codes = tuple(function.__code__ for function in self.runtime_functions)
        self.runtime_defaults = tuple((function.__defaults__,
                                       None if function.__kwdefaults__ is None
                                       else dict(function.__kwdefaults__))
                                      for function in self.runtime_functions)
        self.functions = functions
        self.codes = tuple(function.__code__ for function in functions)
        self.preview_defaults = functions[1].__kwdefaults__

    def require_live(self):
        from monitor import issue_tracker_local_commit as local
        if (not self.active or self.failure is not None or self.originals.closed
                or self.originals.files is not self.file_table
                or self.originals.root is not self.original_root
                or _CABLE_ETH_INFO_CUSTODIES.get(self.registration) is not self
                or _CABLE_ETH_INFO_CURRENT.get() is not self
                or self.execution_owner != (os.getpid(), threading.get_ident())
                or local._ACTIVE.get(self.token) is not self.owner):
            raise CableSourceHold('Cable ETH custody is unavailable')

    def _bindings(self):
        from monitor import issue_tracker_local_commit as local
        self.require_live()
        if _cable_require_store(self.store, self.originals.root) != self.store_binding:
            raise CableSourceHold('Cable ETH completion lease changed')
        owner = self.owner
        if (tuple(getattr(owner, name) for name in (
                'project', 'publication', 'pid', 'project_fd', 'root_fd',
                'publication_fd', 'lock_fd', 'lock_dev', 'lock_ino')) != self.owner_binding
                or owner.pid != os.getpid()
                or str(owner.project) != self.store.project_identity
                or owner.publication != owner.project / '99-output-monitor'):
            raise CableSourceHold('Cable ETH writer original changed')
        local._check(owner.project_fd, directory=True, private=False)
        local._check(owner.root_fd, directory=True)
        local._check(owner.publication_fd, directory=True, private=False)
        held = local._check(owner.lock_fd, directory=False)
        for fd, parent, name in (
                (owner.root_fd, owner.project_fd, '.tracker'),
                (owner.publication_fd, owner.project_fd, owner.publication.name),
                (owner.lock_fd, owner.root_fd, 'LOCK')):
            current = os.fstat(fd)
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (named.st_dev, named.st_ino):
                raise CableSourceHold('Cable ETH writer name was rebound')
        if (held.st_dev, held.st_ino) != (owner.lock_dev, owner.lock_ino):
            raise CableSourceHold('Cable ETH writer lock differs')
        for (_view_id, path), (fd, parent, identity, view) in self.originals.directories.items():
            current = view.fstat(fd)
            named = (view.stat(path.name, dir_fd=parent, follow_symlinks=False)
                     if parent is not None else view.stat('/', follow_symlinks=False))
            key = lambda value: (value.st_dev, value.st_ino, value.st_mode,
                                 value.st_uid, value.st_gid)
            if key(current) != identity or key(named) != identity:
                raise CableSourceHold('Cable ETH original parent was rebound')
        for (view_id, path), (identity, names) in self.originals.namespaces.items():
            fd, _parent, _original, view = self.originals.directories[(view_id, path)]
            if (_cable_identity(view.fstat(fd)) != identity
                    or tuple(sorted(view.listdir(fd))) != names):
                raise CableSourceHold('Cable ETH selected namespace changed')
        info, switch = self.info, self.switch
        first, second = self.functions
        if (sys.modules.get('monitor.issue_tracker_switch_info_source') is not info
                or sys.modules.get('monitor.issue_tracker_switch_runtime') is not switch
                or info._exact_archive_bytes is not first
                or info._CABLE_EXACT_ARCHIVE_ORIGINAL is not first
                or info.read_switch_info_preview is not second
                or info._CABLE_INFO_PREVIEW_ORIGINAL is not second
                or switch.read_switch_info_preview is not second
                or first.__globals__ is not vars(info) or second.__globals__ is not vars(info)
                or first.__code__ is not self.codes[0] or second.__code__ is not self.codes[1]
                or first.__defaults__ is not None or first.__kwdefaults__ is not None
                or second.__defaults__ is not None
                or second.__kwdefaults__ is not self.preview_defaults
                or self.preview_defaults != {'max_archive_bytes': 8 * 1024 * 1024,
                                             'max_member_bytes': 1024 * 1024}
                or first.__closure__ is not None or second.__closure__ is not None
                or _read_cable_eth_info_if_current is not _CABLE_ETH_INFO_READ_ORIGINAL):
            raise CableSourceHold('Cable ETH consumer object changed')
        if self.originals.files.get((id(os), self.source_path)) is not self.source_record:
            raise CableSourceHold('Cable ETH held consumer source changed')
        self.originals._verify_file(self.source_path, self.source_record)
        current_runtime = (_hold_current_cable_cycle_source.__wrapped__,
                           _CableOriginals.raw, _read_cable_eth_info_if_current,
                           _cable_known_nv_info_reader,
                           *tuple(vars(_CableEthInfoCustody)[name] for name in (
                               '__init__', 'require_live', '_bindings',
                               '_known_nv_legacy', 'read')))
        if (len(current_runtime) != len(self.runtime_functions)
                or any(current is not original or current.__code__ is not code
                       or current.__globals__ is not globals()
                       or current.__closure__ is not None
                       or current.__defaults__ != defaults[0]
                       or current.__kwdefaults__ != defaults[1]
                       for current, original, code, defaults in zip(
                           current_runtime, self.runtime_functions,
                           self.runtime_codes, self.runtime_defaults))
                or self.originals.files.get((id(os), self.runtime_path))
                   is not self.runtime_record):
            raise CableSourceHold('Cable ETH runtime object changed')
        self.originals._verify_file(self.runtime_path, self.runtime_record)
        self.require_live()

    def _known_nv_legacy(self, path, expected_sha256, expected_size_bytes, maximum):
        """Guard one fixed pre-existing NV caller; never return archive data."""
        try:
            self.require_live()
            if type(path) is not type(self.originals.root):
                raise CableSourceHold('Cable NV selector is not a lexical original')
            record = self.originals.files.get((id(os), path))
            if (path.parent != self.originals.root / 'nvlink/monitor/nvsw-info'
                    or record is None or type(expected_sha256) is not str
                    or expected_sha256 != record[3]
                    or type(expected_size_bytes) is not int
                    or expected_size_bytes != record[2][6]
                    or type(maximum) is not int or maximum <= 0
                    or expected_size_bytes <= 0 or expected_size_bytes > maximum):
                raise CableSourceHold('Cable NV legacy selector is not an already held role')
            caller, preview = sys._getframe(2), sys._getframe(3)
            if (caller.f_code is not self.codes[0] or caller.f_globals is not vars(self.info)
                    or preview.f_code is not self.codes[1]
                    or preview.f_globals is not vars(self.info)
                    or preview.f_locals.get('path') != path
                    or preview.f_locals.get('source_slot') != 'nvlink/prod'):
                raise CableSourceHold('Cable NV legacy caller is not the fixed preview')
            self._bindings()
            self.originals._verify_file(path, record)
            # This guard returns no bytes/FD grant. The fixed actual archive
            # consumer must next use the current original reader, never treat
            # a successful guard as permission to reopen a pathname.
            return True
        except BaseException as error:
            self.failure = error
            raise

    def read(self, path, expected_sha256, expected_size_bytes, maximum):
        try:
            self.require_live()
            # Lexical membership and bounds precede every verification IO.
            if type(path) is not Path:
                # Path's platform-specific concrete type is accepted below.
                if type(path) is not type(self.originals.root):
                    raise CableSourceHold('Cable ETH path is not a lexical original')
            path = Path(path)
            record = self.originals.files.get((id(os), path))
            slots = {self.originals.root / 'ethernet/monitor/eth-info': 'ethernet/prod',
                     self.originals.root / 'nvlink/monitor/nvsw-info': 'nvlink/prod'}
            slot = slots.get(path.parent)
            if (record is None or slot is None
                    or type(expected_sha256) is not str
                    or expected_sha256 != record[3]
                    or type(expected_size_bytes) is not int
                    or expected_size_bytes != record[2][6]
                    or type(maximum) is not int or maximum <= 0
                    or expected_size_bytes <= 0 or expected_size_bytes > maximum):
                raise CableSourceHold('Cable ETH archive is not an already held role')
            caller = sys._getframe(2)
            preview = sys._getframe(3)
            if (caller.f_code is not self.codes[0] or caller.f_globals is not vars(self.info)
                    or preview.f_code is not self.codes[1]
                    or preview.f_globals is not vars(self.info)
                    or preview.f_locals.get('path') != path
                    or preview.f_locals.get('source_slot') != slot):
                raise CableSourceHold('Cable ETH consumer call is not the fixed preview')
            self._bindings()
            self.originals._verify_file(path, record)
            raw = self.originals.raw(path, maximum=maximum, _existing_record=record)
            if (len(raw) != expected_size_bytes
                    or hashlib.sha256(raw).hexdigest() != expected_sha256):
                raise CableSourceHold('Cable ETH original bytes disagree')
            self._bindings()
            self.originals._verify_file(path, record)
            return raw
        except BaseException as error:
            self.failure = error
            raise


def _read_cable_eth_info_if_current(path, *, expected_sha256,
                                    expected_size_bytes, maximum):
    custody = _CABLE_ETH_INFO_CURRENT.get()
    if custody is None:
        return None
    if type(custody) is not _CableEthInfoCustody:
        raise CableSourceHold('Cable ETH current custody is invalid')
    return custody.read(path, expected_sha256, expected_size_bytes, maximum)


def _cable_known_nv_info_reader(path, *, expected_sha256,
                                 expected_size_bytes, maximum):
    custody = _CABLE_ETH_INFO_CURRENT.get()
    if custody is None:
        return False
    if type(custody) is not _CableEthInfoCustody:
        raise CableSourceHold('Cable NV legacy custody is invalid')
    return custody._known_nv_legacy(path, expected_sha256, expected_size_bytes, maximum)


_CABLE_NV_INFO_GUARD_ORIGINAL = _cable_known_nv_info_reader
_CABLE_NV_INFO_GUARD_CODE = _cable_known_nv_info_reader.__code__
_CABLE_ETH_INFO_READ_ORIGINAL = _read_cable_eth_info_if_current
_CABLE_ETH_INFO_READ_CODE = _read_cable_eth_info_if_current.__code__


class _CableW1Custody:
    """One fixed template content borrower; no standalone, SDK or send grant."""
    def __init__(self, registration, eth, template):
        caller = sys._getframe(1)
        root_method = _hold_current_cable_cycle_source.__wrapped__
        if (caller.f_code is not root_method.__code__
                or caller.f_globals is not globals()
                or type(eth) is not _CableEthInfoCustody):
            raise CableSourceHold('Cable W1 custody requires the actual source root')
        eth._bindings()
        from monitor import issue_tracker_whitelist_workbook as workbook
        self.registration, self.eth = registration, eth
        self.originals, self.workbook = eth.originals, workbook
        self.template = self.originals.root / 'monitor/Issue_Tracker_Template_v1.xlsx'
        if type(template) is not type(self.template) or template != self.template:
            raise CableSourceHold('Cable W1 template selector differs')
        self.record = self.originals.files.get((id(os), self.template))
        if self.record is None or not 0 < self.record[2][6] <= 32 * 1024 * 1024:
            raise CableSourceHold('Cable W1 lacks a bounded previously held template')
        self.active, self.failure = True, None
        self.source_path = Path(__file__).with_name('issue_tracker_whitelist_workbook.py')
        self.originals.file(self.source_path)
        self.source_record = self.originals.files[(id(os), self.source_path)]
        image = compile(self.originals.raw(self.source_path), str(self.source_path),
                        'exec', dont_inherit=True)
        codes = {value.co_name: value for value in image.co_consts
                 if isinstance(value, type(image))}
        self.consumer_names = ('read_whitelist_workbook', '_parse_xlsx_bytes',
            '_rows', '_cell_text', '_worksheet_path', '_shared_strings',
            '_get_member', '_safe_xml')
        self.consumer_functions = tuple(vars(workbook).get(name)
                                        for name in self.consumer_names)
        if (read_whitelist_workbook is not self.consumer_functions[0]
                or workbook._CABLE_W1_CONSUMER_ORIGINAL is not self.consumer_functions[0]
                or workbook._CABLE_W1_PARSER_ORIGINAL is not self.consumer_functions[1]):
            raise CableSourceHold('Cable W1 original consumer differs')
        for function, name in zip(self.consumer_functions, self.consumer_names):
            if (type(function) is not FunctionType
                    or function.__globals__ is not vars(workbook)
                    or function.__code__.co_filename != str(self.source_path)
                    or function.__code__ != codes.get(name)
                    or function.__closure__ is not None
                    or function.__defaults__ is not None
                    or function.__kwdefaults__ is not None):
                raise CableSourceHold('Cable W1 consumer differs from held source')
        self.consumer_codes = tuple(function.__code__ for function in self.consumer_functions)
        runtime_image = compile(self.originals.raw(eth.runtime_path), str(eth.runtime_path),
                                'exec', dont_inherit=True)
        runtime_codes = {value.co_name: value for value in runtime_image.co_consts
                         if isinstance(value, type(runtime_image))}
        class_code = runtime_codes.get('_CableW1Custody')
        if class_code is None:
            raise CableSourceHold('Cable W1 runtime source is absent')
        class_codes = {value.co_name: value for value in class_code.co_consts
                       if isinstance(value, type(runtime_image))}
        self.runtime_names = ('__init__', 'require_live', '_bindings', 'read')
        audit = [(_read_cable_w1_if_current, runtime_codes.get('_read_cable_w1_if_current'))]
        audit.extend((vars(_CableW1Custody)[name], class_codes.get(name))
                     for name in self.runtime_names)
        if any(type(function) is not FunctionType
               or function.__globals__ is not globals()
               or function.__code__ != expected
               or function.__code__.co_filename != str(eth.runtime_path)
               or function.__closure__ is not None
               or function.__defaults__ is not None
               or function.__kwdefaults__ is not None
               for function, expected in audit):
            raise CableSourceHold('Cable W1 runtime differs from held source')
        self.runtime_functions = tuple(function for function, _expected in audit)
        self.runtime_codes = tuple(function.__code__ for function in self.runtime_functions)

    def require_live(self):
        if (not self.active or self.failure is not None
                or _CABLE_W1_CUSTODIES.get(self.registration) is not self
                or _CABLE_W1_CURRENT.get() is not self
                or self.originals is not self.eth.originals):
            raise CableSourceHold('Cable W1 custody is unavailable')
        self.eth.require_live()

    def _bindings(self):
        self.require_live()
        self.eth._bindings()  # Actual writer/store/Reader, parents and source joints.
        workbook = self.workbook
        if (sys.modules.get('monitor.issue_tracker_whitelist_workbook') is not workbook
                or read_whitelist_workbook is not self.consumer_functions[0]
                or workbook._CABLE_W1_CONSUMER_ORIGINAL is not self.consumer_functions[0]
                or workbook._CABLE_W1_PARSER_ORIGINAL is not self.consumer_functions[1]
                or self.originals.files.get((id(os), self.template)) is not self.record
                or self.originals.files.get((id(os), self.source_path)) is not self.source_record):
            raise CableSourceHold('Cable W1 original binding changed')
        current = tuple(vars(workbook).get(name) for name in self.consumer_names)
        if any(now is not original or now.__code__ is not code
               or now.__globals__ is not vars(workbook)
               or now.__closure__ is not None or now.__defaults__ is not None
               or now.__kwdefaults__ is not None
               for now, original, code in zip(current, self.consumer_functions, self.consumer_codes)):
            raise CableSourceHold('Cable W1 consumer object changed')
        runtime = (_read_cable_w1_if_current,
                   *tuple(vars(_CableW1Custody)[name] for name in self.runtime_names))
        if any(now is not original or now.__code__ is not code
               or now.__globals__ is not globals() or now.__closure__ is not None
               or now.__defaults__ is not None or now.__kwdefaults__ is not None
               for now, original, code in zip(runtime, self.runtime_functions, self.runtime_codes)):
            raise CableSourceHold('Cable W1 runtime object changed')
        self.originals._verify_file(self.source_path, self.source_record)
        self.originals._verify_file(self.template, self.record)
        self.require_live()

    def read(self, path):
        try:
            self.require_live()
            if type(path) is not type(self.template) or path != self.template:
                raise CableSourceHold('Cable W1 active selector is not the fixed template')
            caller = sys._getframe(2)
            if (caller.f_code is not self.consumer_codes[0]
                    or caller.f_globals is not vars(self.workbook)
                    or caller.f_locals.get('path') != self.template):
                raise CableSourceHold('Cable W1 caller is not its actual semantic consumer')
            self._bindings()
            raw = self.originals.raw(self.template, maximum=32 * 1024 * 1024,
                                     _existing_record=self.record)
            if (len(raw) != self.record[2][6]
                    or hashlib.sha256(raw).hexdigest() != self.record[3]):
                raise CableSourceHold('Cable W1 held template bytes changed')
            self._bindings()
            return raw, self.record[2]
        except BaseException as error:
            self.failure = error
            raise


def _read_cable_w1_if_current(path):
    custody = _CABLE_W1_CURRENT.get()
    if custody is None:
        return None
    if type(custody) is not _CableW1Custody:
        raise CableSourceHold('Cable W1 current custody is invalid')
    return custody.read(path)


_CABLE_W1_READ_ORIGINAL = _read_cable_w1_if_current
_CABLE_W1_READ_CODE = _read_cable_w1_if_current.__code__


class _CablePolicyCustody:
    """One current global-policy original borrower; never a send capability."""
    def __init__(self, registration, eth):
        caller = sys._getframe(1)
        root_method = _hold_current_cable_cycle_source.__wrapped__
        if (caller.f_code is not root_method.__code__
                or caller.f_globals is not globals()
                or type(eth) is not _CableEthInfoCustody):
            raise CableSourceHold('Cable N custody requires the actual source root')
        eth._bindings()
        from monitor import issue_tracker_admission as admission
        from tools import project_contract as contract
        self.registration, self.eth = registration, eth
        self.originals, self.admission, self.contract = eth.originals, admission, contract
        self.project = eth.owner.project
        self.path = self.project / '01-global.yaml'
        self.record = self.originals.files.get((id(os), self.path))
        if self.record is None or not 0 < self.record[2][6] <= 1024 * 1024:
            raise CableSourceHold('Cable N lacks a bounded previously held global')
        self.active, self.failure = True, None
        source_path = Path(__file__).with_name('issue_tracker_admission.py')
        contract_path = Path(__file__).parents[1] / 'tools/project_contract.py'
        self.source_records = []
        expected = {}
        for module, path in ((admission, source_path), (contract, contract_path)):
            self.originals.file(path)
            record = self.originals.files[(id(os), path)]
            self.source_records.append((path, record))
            image = compile(self.originals.raw(path), str(path), 'exec', dont_inherit=True)
            expected[module] = {value.co_name: value for value in image.co_consts
                                if isinstance(value, type(image))}
        functions = ((admission, 'local_publish_interval', source_path),
                     (contract, 'safe_load_global_yaml', contract_path),
                     (contract, 'normalize_issue_tracker_policy', contract_path))
        self.functions = []
        for module, name, path in functions:
            function = vars(module).get(name)
            if (type(function) is not FunctionType
                    or function.__globals__ is not vars(module)
                    or function.__code__.co_filename != str(path)
                    or function.__code__ != expected[module].get(name)
                    or function.__closure__ is not None
                    or function.__defaults__ is not None
                    or function.__kwdefaults__ is not None):
                raise CableSourceHold('Cable N consumer differs from held source')
            self.functions.append((module, name, function, function.__code__))
        if (admission._CABLE_N_CONSUMER_ORIGINAL is not self.functions[0][2]
                or admission.safe_load_global_yaml is not self.functions[1][2]
                or admission.normalize_issue_tracker_policy is not self.functions[2][2]):
            raise CableSourceHold('Cable N semantic aliases differ')
        runtime_image = compile(self.originals.raw(eth.runtime_path), str(eth.runtime_path),
                                'exec', dont_inherit=True)
        codes = {value.co_name: value for value in runtime_image.co_consts
                 if isinstance(value, type(runtime_image))}
        class_code = codes.get('_CablePolicyCustody')
        if class_code is None:
            raise CableSourceHold('Cable N runtime source is absent')
        class_codes = {value.co_name: value for value in class_code.co_consts
                       if isinstance(value, type(runtime_image))}
        self.runtime_names = ('__init__', 'require_live', '_bindings', 'read')
        audit = [(_read_cable_policy_if_current, codes.get('_read_cable_policy_if_current'))]
        audit.extend((vars(_CablePolicyCustody)[name], class_codes.get(name))
                     for name in self.runtime_names)
        if any(type(function) is not FunctionType
               or function.__globals__ is not globals()
               or function.__code__ != wanted
               or function.__code__.co_filename != str(eth.runtime_path)
               or function.__closure__ is not None or function.__defaults__ is not None
               or function.__kwdefaults__ is not None
               for function, wanted in audit):
            raise CableSourceHold('Cable N runtime differs from held source')
        self.runtime_functions = tuple(function for function, _wanted in audit)
        self.runtime_codes = tuple(function.__code__ for function in self.runtime_functions)

    def require_live(self):
        if (not self.active or self.failure is not None
                or _CABLE_N_CUSTODIES.get(self.registration) is not self
                or _CABLE_N_CURRENT.get() is not self
                or self.originals is not self.eth.originals
                or self.project is not self.eth.owner.project):
            raise CableSourceHold('Cable N custody is unavailable')
        self.eth.require_live()

    def _bindings(self):
        self.require_live()
        self.eth._bindings()
        if (sys.modules.get('monitor.issue_tracker_admission') is not self.admission
                or sys.modules.get('tools.project_contract') is not self.contract
                or self.originals.files.get((id(os), self.path)) is not self.record
                or self.admission._CABLE_N_CONSUMER_ORIGINAL is not self.functions[0][2]
                or self.admission.safe_load_global_yaml is not self.functions[1][2]
                or self.admission.normalize_issue_tracker_policy is not self.functions[2][2]):
            raise CableSourceHold('Cable N semantic original binding changed')
        for module, name, function, code in self.functions:
            current = vars(module).get(name)
            if (current is not function or current.__code__ is not code
                    or current.__globals__ is not vars(module)
                    or current.__closure__ is not None
                    or current.__defaults__ is not None or current.__kwdefaults__ is not None):
                raise CableSourceHold('Cable N semantic consumer object changed')
        current = (_read_cable_policy_if_current,
                   *tuple(vars(_CablePolicyCustody)[name] for name in self.runtime_names))
        if any(now is not function or now.__code__ is not code
               or now.__globals__ is not globals() or now.__closure__ is not None
               or now.__defaults__ is not None or now.__kwdefaults__ is not None
               for now, function, code in zip(current, self.runtime_functions, self.runtime_codes)):
            raise CableSourceHold('Cable N runtime object changed')
        for path, record in self.source_records:
            if self.originals.files.get((id(os), path)) is not record:
                raise CableSourceHold('Cable N held consumer source changed')
            self.originals._verify_file(path, record)
        self.originals._verify_file(self.path, self.record)
        self.require_live()

    def read(self, project):
        try:
            self.require_live()
            if not ((type(project) is type(self.project) and project == self.project)
                    or (type(project) is str and project == str(self.project))):
                raise CableSourceHold('Cable N active selector is not the fixed project')
            caller = sys._getframe(2)
            if (caller.f_code is not self.functions[0][3]
                    or caller.f_globals is not vars(self.admission)
                    or caller.f_locals.get('project') is not project):
                raise CableSourceHold('Cable N caller is not its actual semantic consumer')
            self._bindings()
            raw = self.originals.raw(self.path, maximum=1024 * 1024,
                                     _existing_record=self.record)
            if (len(raw) != self.record[2][6]
                    or hashlib.sha256(raw).hexdigest() != self.record[3]):
                raise CableSourceHold('Cable N held global bytes changed')
            self._bindings()
            return raw, self.record[2]
        except BaseException as error:
            self.failure = error
            raise


def _read_cable_policy_if_current(project):
    custody = _CABLE_N_CURRENT.get()
    if custody is None:
        return None
    if type(custody) is not _CablePolicyCustody:
        raise CableSourceHold('Cable N current custody is invalid')
    return custody.read(project)


_CABLE_N_READ_ORIGINAL = _read_cable_policy_if_current
_CABLE_N_READ_CODE = _read_cable_policy_if_current.__code__


class _CableNativeBorrow:
    """Sealed IB-only borrowed originals, not authority or cached semantics."""
    def __init__(self, registration, originals, token, owner, store, store_binding):
        self.registration = registration
        self.originals = originals
        self.token = token
        self.owner = owner
        self.store = store
        self.store_binding = store_binding
        self.owner_binding = tuple(getattr(owner, name) for name in (
            'project', 'publication', 'pid', 'project_fd', 'root_fd',
            'publication_fd', 'lock_fd', 'lock_dev', 'lock_ino'))
        self.execution_owner = (os.getpid(), threading.get_ident())
        self.active = True
        self.failure = None
        # Actual acquisitions are finished. These exact lookup tables can
        # never grow during native borrowing; unknown paths never fall back.
        self.aliases = MappingProxyType(dict(originals.native_aliases))
        self.files = MappingProxyType({path: originals.files[(id(os), path)]
                                      for path in originals.native_paths})
        if (not self.files or any(path not in self.files
                                  for path in self.aliases.values())):
            raise CableSourceHold('Cable native original selection is incomplete')

    def require_live(self):
        from monitor import issue_tracker_local_commit as local
        if (not self.active or self.failure is not None or self.originals.closed
                or _CABLE_NATIVE_BORROWS.get(self.registration) is not self
                or _CABLE_NATIVE_CURRENT.get() is not self
                or self.execution_owner != (os.getpid(), threading.get_ident())
                or local._ACTIVE.get(self.token) is not self.owner):
            raise CableSourceHold('Cable native original borrower is unavailable')

    def _bindings(self):
        """No opens/resolves: verify retained named/held topology and namespace."""
        from monitor import issue_tracker_local_commit as local
        self.require_live()
        if _cable_require_store(self.store, self.originals.root) != self.store_binding:
            raise CableSourceHold('Cable native store/gate binding changed')
        owner = self.owner
        if (tuple(getattr(owner, name) for name in (
                'project', 'publication', 'pid', 'project_fd', 'root_fd',
                'publication_fd', 'lock_fd', 'lock_dev', 'lock_ino')) != self.owner_binding
                or owner.pid != os.getpid()
                or str(owner.project) != self.store.project_identity
                or owner.publication != owner.project / '99-output-monitor'):
            raise CableSourceHold('Cable native local owner binding changed')
        project = local._check(owner.project_fd, directory=True, private=False)
        root = local._check(owner.root_fd, directory=True)
        publication = local._check(owner.publication_fd, directory=True, private=False)
        lock = local._check(owner.lock_fd, directory=False)
        key = lambda info: (info.st_dev, info.st_ino)
        for held, parent, name in (
                (root, owner.project_fd, '.tracker'),
                (publication, owner.project_fd, owner.publication.name),
                (lock, owner.root_fd, 'LOCK')):
            if key(held) != key(os.stat(name, dir_fd=parent, follow_symlinks=False)):
                raise CableSourceHold('Cable native local owner name was rebound')
        if (key(lock) != (owner.lock_dev, owner.lock_ino)
                or key(project) != key(os.fstat(
                    self.originals.directories[(id(os), owner.project)][0]))):
            raise CableSourceHold('Cable native local owner original differs')
        for (_view_id, path), (fd, parent, identity, view) in self.originals.directories.items():
            held = view.fstat(fd)
            named = (view.stat(path.name, dir_fd=parent, follow_symlinks=False)
                     if parent is not None else view.stat('/', follow_symlinks=False))
            project = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
            if project(held) != identity or project(named) != identity:
                raise CableSourceHold('Cable native original parent was rebound')
        for (view_id, path), (identity, names) in self.originals.namespaces.items():
            fd, _parent, _original, view = self.originals.directories[(view_id, path)]
            if (_cable_identity(view.fstat(fd)) != identity
                    or tuple(sorted(view.listdir(fd))) != names):
                raise CableSourceHold('Cable native original namespace changed')
        for path, (parent, identity, target) in self.originals.links.items():
            if (_cable_identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) != identity
                    or os.readlink(path.name, dir_fd=parent) != target):
                raise CableSourceHold('Cable native original selector was rebound')
        for path, (fd, parent, identity, _digest, view) in self.files.items():
            if (_cable_identity(view.fstat(fd)) != identity
                    or _cable_identity(view.stat(path.name, dir_fd=parent,
                                                follow_symlinks=False)) != identity):
                raise CableSourceHold('Cable native original file was rebound')
        self.require_live()

    def _record(self, value):
        # Membership is decided BEFORE any path traversal/verification IO.
        # Path() is lexical only; unlike native standalone _identity, neither
        # expanduser() nor resolve() is called for an active borrower.
        self.require_live()
        path = Path(value)
        resolved = self.aliases.get(path)
        if resolved is None or resolved not in self.files:
            self.failure = CableSourceHold('Cable native path was not sealed')
            raise self.failure
        try:
            self._bindings()
        except BaseException as error:
            self.failure = error
            raise
        return path, resolved, self.files[resolved]

    def read(self, value, maximum):
        try:
            _path, resolved, record = self._record(value)
            fd, _parent, identity, _digest, view = record
            size = identity[6]
            if size > maximum:
                raise CableSourceHold('Cable borrowed native bytes exceed their bound')
            parts, position = [], 0
            while position < size:
                part = view.pread(fd, min(1024 * 1024, size - position), position)
                if not part:
                    raise CableSourceHold('Cable borrowed native original shortened')
                parts.append(part)
                position += len(part)
            if view.pread(fd, 1, position):
                raise CableSourceHold('Cable borrowed native original grew')
            self._bindings()
            return b''.join(parts)
        except BaseException as error:
            self.failure = error
            raise

    def identity(self, value):
        try:
            lexical, resolved, record = self._record(value)
            fd, _parent, identity, _expected_digest, view = record
            # Always hash the actual current held FD. The saved digest is NOT
            # returned as successful evidence or a renewed qualification.
            digest = self.originals._digest(view, fd, identity[6])
            self._bindings()
            return {'path': str(lexical), 'resolved_path': str(resolved),
                    'kind': 'file', 'sha256': digest}
        except BaseException as error:
            self.failure = error
            raise


def _current_cable_native_borrow():
    """No caller arguments, FD/checker/path DTO or fallback authorization."""
    current = _CABLE_NATIVE_CURRENT.get()
    if type(current) is not _CableNativeBorrow:
        raise CableSourceHold('Cable native original owner is unavailable')
    current.require_live()
    return current


@contextmanager
def _cable_hold_initial_native_reads(originals, store, root, token, owner, store_binding):
    """Per-cycle original-FD reads only, before C5/receipt/target qualification.

    Acquisitions for this replay have finished. Freeze that finite selection,
    borrow from the actual A project writer, and revoke before any reset.
    This is not a completed _CableCycleSource or an SDK/send permission.
    """
    from monitor import issue_tracker_local_commit as local

    registration = object()
    borrowed = None
    current_key = None
    contexts = []
    primary = None
    cleanup_errors = []
    try:
        if (type(originals) is not _CableOriginals or originals.closed
                or originals.root != Path(root)
                or _CABLE_NATIVE_CURRENT.get() is not None
                or local._owner(token) is not owner
                or _cable_require_store(store, root) != store_binding
                or owner.project != Path(store.project_identity)):
            raise CableSourceHold('Cable initial native owner binding differs')
        modules = _cable_native_consumer_modules(originals)
        borrowed = _CableNativeBorrow(registration, originals, token,
                                      owner, store, store_binding)
        _CABLE_NATIVE_BORROWS[registration] = borrowed
        current_key = _CABLE_NATIVE_CURRENT.set(borrowed)
        for native_module in modules:
            context = native_module._hold_current_cable_originals()
            context.__enter__()
            contexts.append(context)
        borrowed._bindings()
        yield
        borrowed._bindings()
        current_modules = _cable_native_consumer_modules(originals)
        if (len(current_modules) != len(modules)
                or any(current is not original for current, original
                       in zip(current_modules, modules))):
            raise CableSourceHold('Cable initial native consumers changed')
    except BaseException as error:
        primary = error
    finally:
        # Invalidate the registered original before either native namespace or
        # runtime current binding resets. No original FD is closed here.
        if borrowed is not None:
            borrowed.active = False
        _CABLE_NATIVE_BORROWS.pop(registration, None)
        for context in reversed(contexts):
            try:
                context.__exit__(None, None, None)
            except BaseException as error:
                cleanup_errors.append(error)
        if current_key is not None:
            try:
                _CABLE_NATIVE_CURRENT.reset(current_key)
            except BaseException as error:
                cleanup_errors.append(error)
        # Preserve an actual first NI (and its existing cause) over ordinary
        # cleanup; attempt every reset. Do not execute exception truthiness.
        for error in cleanup_errors:
            if primary is None or (isinstance(primary, Exception)
                                   and not isinstance(error, Exception)):
                primary = error
    if primary is not None:
        raise primary


def _cable_hold_cycle_roles(originals, store, root, project, cycles, *,
                            token, owner, store_binding):
    """Select actual native completion roles, not panel-only or caller paths."""
    from monitor import collection_ib_producer as producer
    from monitor.collection_ib_cycle_binding import inspect_completed_ib_cycle_roles, IbCycleRoleSource
    from monitor.issue_tracker_switch_runtime import (
        read_prod_switch_cycle_source, read_prod_eth_activity_cycle_source,
    )

    authority_path = producer._AUTHORITY_DIR / (store.project_key + '.json')
    originals.file(authority_path, view=producer.os, protected=True)
    authority = producer.load_ib_producer_authority(
        project_key=store.project_key, project_root=project)
    if hashlib.sha256(originals.raw(authority_path, view=producer.os, protected=True)).hexdigest() != authority.sha256:
        raise CableSourceHold('Cable IB authority differs from its original record')
    for cycle in cycles:
        area = (root / 'monitor/status/collection-cycles' / store.project_key
                / 'prod/switch_collection/artifacts' / f'{cycle.sequence:020d}')
        # Fixed completion namespace holds frozen inventories/plans/runtime rows,
        # topology/DOT/aliases/derivation files and all private evidence/envelopes.
        originals.tree(area)
        identity = store._validate_start_record(
            originals.document(store.start_path(cycle.sequence)), cycle.sequence)
        completion = store._validate_completion_record(
            originals.document(store.completion_path(cycle.sequence)), identity)
        outcomes = completion['run_result']['outcomes']
        if (tuple(item['source_slot'] for item in outcomes) != cycle.source_slots
                or any(item['outcome'] != 'accepted' for item in outcomes)):
            raise CableSourceHold('Cable completion children are not accepted originals')
        for outcome in outcomes:
            slot = outcome['source_slot'].replace('/', '-')
            child = outcome['child_result']
            for name, field in (('evidence-manifest.json', 'evidence'),
                                ('identity-envelope.json', 'envelope')):
                originals.file(area / slot / name, expected=child[field]['sha256'])
        ib_roles = None
        for slot in ('ethernet-prod', 'infiniband-prod', 'nvlink-prod'):
            evidence = originals.document(area / slot / 'evidence-manifest.json')
            if slot == 'infiniband-prod':
                ib_roles = evidence['roles']
            for role in evidence['roles']:
                if role['state'] != 'present':
                    continue  # Native readers below must validate every such role.
                relative = Path(role['relative_path'])
                if relative.is_absolute() or '..' in relative.parts:
                    raise CableSourceHold('Cable completion role escaped the HTTP root')
                if role['role'] == 'expected_cvt' and role['sha256'] != authority.authority.cvt_sha256:
                    raise CableSourceHold('Cable CVT role differs from protected authority')
                originals.file(root / relative, expected=role['sha256'])
        activity = originals.document(area / 'ethernet-prod/activity-observation.json')
        for item in tuple(activity['sources'].values()) + (activity['report'],):
            path = Path(item['path'])
            if not path.is_relative_to(root):
                raise CableSourceHold('Cable ETH source escaped its native root')
            originals.file(path, expected=item['sha256'])
        # Pin candidate completion-selected dependencies BEFORE native replay.
        # These reads grant nothing: replay below must validate the exact role
        # sequence/path selection and protected source/attestation digests.
        role_paths = {role['role']: root / role['relative_path'] for role in ib_roles}
        cvt = role_paths['expected_cvt']
        report = role_paths['validation_report']
        originals.file(cvt, expected=authority.authority.cvt_sha256)
        originals.file(producer.sidecar_path(cvt),
                       expected=authority.authority.cvt_provenance_sha256)
        originals.file(producer.sidecar_path(report))
        cvt_record = originals.document(producer.sidecar_path(cvt))
        report_record = originals.document(producer.sidecar_path(report))
        # Pure schema/role/path screening BEFORE any source path stat/open.
        # Native provenance helpers themselves follow recorded absolute paths;
        # their eventual refusal is not a safe substitute for this screen.
        if (type(cvt_record) is not dict
                or set(cvt_record) != {'schema', 'cvt', 'cvt_sha256', 'sources'}
                or cvt_record['schema'] != 'ib-cvt-provenance-v1'
                or cvt_record['cvt_sha256'] != authority.authority.cvt_sha256
                or type(cvt_record['sources']) is not dict
                or set(cvt_record['sources']) != {'p2p', 'inventory', 'port_map',
                    'splitter', 'converter', 'topology_rules'}
                or type(report_record) is not dict
                or set(report_record) != {'schema', 'report', 'cvt',
                    'expected_topology_sha256', 'cvt_provenance_sha256', 'actual', 'profile'}
                or report_record['schema'] != 'ib-report-provenance-v1'
                or report_record['cvt'] != cvt_record['cvt']
                or report_record['expected_topology_sha256'] != authority.authority.cvt_sha256
                or report_record['cvt_provenance_sha256'] != authority.authority.cvt_provenance_sha256):
            raise CableSourceHold('Cable provenance is not the protected native schema')
        roles_by_name = {role['role']: role for role in ib_roles}
        def fixed_identity(item, path, digest=None):
            if (type(item) is not dict
                    or set(item) != {'path', 'resolved_path', 'kind', 'sha256'}
                    or item['path'] != str(path) or item['resolved_path'] != str(path)
                    or item['kind'] != 'file'
                    or (digest is not None and item['sha256'] != digest)):
                raise CableSourceHold('Cable provenance role path differs from its fixed source')
        fixed_identity(cvt_record['cvt'], cvt, authority.authority.cvt_sha256)
        fixed_identity(report_record['report'], report, roles_by_name['validation_report']['sha256'])
        fixed_identity(report_record['actual'], role_paths['ufm_actual_log'],
                       roles_by_name['ufm_actual_log']['sha256'])
        code = Path(producer.read_cvt_provenance.__code__.co_filename).parents[2]
        fixed_identity(cvt_record['sources']['converter'],
            code / 'ztp/config/nvos/template/P2P/p2p-to-validation.py')
        fixed_identity(cvt_record['sources']['topology_rules'],
            code / 'ztp/config/topology_rules.py')
        fixed_identity(report_record['profile'],
            code / 'tools/ibdiagnet-analyze-tool/config/port_profiles.csv')
        p2p = cvt_record['sources']['p2p']
        if (type(p2p) is not dict
                or set(p2p) != {'path', 'resolved_path', 'kind', 'sha256'}
                or p2p['path'] != str(root / 'ztp/config/nvos/template/P2P/p2p.xlsx')
                or type(p2p['resolved_path']) is not str
                or Path(p2p['resolved_path']).parent != project
                or Path(p2p['resolved_path']).suffix.lower() != '.xlsx'
                or p2p['kind'] != 'file' or p2p['sha256'] != authority.authority.p2p_sha256):
            raise CableSourceHold('Cable P2P provenance differs from protected project selection')
        for name in ('inventory', 'port_map', 'splitter'):
            item = cvt_record['sources'][name]
            if (type(item) is not dict or type(item.get('path')) is not str
                    or type(item.get('resolved_path')) is not str
                    or not Path(item['path']).is_relative_to(root)
                    or not Path(item['resolved_path']).is_relative_to(root)):
                raise CableSourceHold('Cable data provenance escaped the fixed HTTP root')
        dependencies = (cvt_record['cvt'], *cvt_record['sources'].values(),
                        report_record['report'], report_record['cvt'],
                        report_record['actual'], report_record['profile'])
        # Screen ALL identity fields before the first dependency path IO.
        for item in dependencies:
            if type(item) is not dict or set(item) != {'path', 'resolved_path', 'kind', 'sha256'}:
                raise CableSourceHold('Cable provenance identity is incomplete')
            if (type(item['path']) is not str or type(item['resolved_path']) is not str
                    or type(item['sha256']) is not str or len(item['sha256']) != 64
                    or any(char not in '0123456789abcdef' for char in item['sha256'])):
                raise CableSourceHold('Cable provenance identity scalar is malformed')
            originals.require_path(item['path'])
            originals.require_path(item['resolved_path'])
            if item['kind'] != 'file':
                raise CableSourceHold('Cable native provenance requires file roles')
        for item in dependencies:
            originals.preflight_provenance_identity(item)
        for item in dependencies:
            originals.provenance_identity(item)
        for sidecar in (producer.sidecar_path(cvt), producer.sidecar_path(report)):
            originals.native_paths.add(sidecar)
            originals.native_aliases[sidecar] = sidecar
        # Both fixed selector links are independently checked by native replay;
        # the p2p provenance lexical path traverses and pins these two links.
        attestation = (producer._ATTESTATION_DIR / store.project_key
                       / producer._attestation_name(cycle.cycle_id))
        envelope = originals.document(area / 'infiniband-prod/identity-envelope.json')
        ib_binding = envelope['ib_analysis_binding']
        originals.file(attestation, view=producer.os, protected=True,
                       expected=ib_binding['attestation_sha256'])
        record = originals.document(attestation, view=producer.os, protected=True)
        retrieved = Path(record['retrieved_archive_relative_path'])
        fixed_retrieved = authority.authority.retrieval_dir / (
            'iblinkinfo_' + ib_binding['run_id'] + '.tar.gz')
        if (retrieved.is_absolute() or '..' in retrieved.parts
                or root / retrieved != fixed_retrieved):
            raise CableSourceHold('Cable IB retrieved role escaped its root')
        originals.file(root / retrieved, expected=record['retrieved_sha256'])
        for slot in ('ethernet/prod', 'nvlink/prod'):
            read_prod_switch_cycle_source(store, http_root=root,
                sequence=cycle.sequence, source_slot=slot)
        read_prod_eth_activity_cycle_source(store, http_root=root,
                                           sequence=cycle.sequence)
        # All completion-selected native roles already have actual original
        # FDs, in addition to the screened provenance dependencies and sidecars.
        # Add their fixed aliases before snapshotting this cycle's read closure.
        for name in producer.IB_ROLE_NAMES:
            path = role_paths[name]
            originals.native_paths.add(path)
            originals.native_aliases[path] = path
        with _cable_hold_initial_native_reads(
                originals, store, root, token, owner, store_binding):
            ib = inspect_completed_ib_cycle_roles(store, http_root=root,
                                                  sequence=cycle.sequence)
            if type(ib) is not IbCycleRoleSource:
                raise CableSourceHold('Cable IB completion has no protected roles')
            originals.file(attestation, view=producer.os, protected=True,
                           expected=ib.attestation_sha256)
            producer.read_cvt_provenance(cvt)
            producer.read_report_provenance(report)
            originals.verify()
        for name in producer.IB_ROLE_NAMES:
            path = role_paths[name]
            originals.native_paths.add(path)
            originals.native_aliases[path] = path
    producer.recheck_ib_producer_authority(authority)


@dataclass(frozen=True)
class _CableCycleSource:
    """Revocable NO_SEND projection; never an SDK, credential or send grant."""
    outcome: str
    changes: object
    binding: object
    local_generation_id: str
    local_published_sha256: str
    _registration: object

    def verify(self):
        registered = _CABLE_SOURCE_SCOPES.get(self._registration)
        if registered is None or registered[0] is not self:
            raise CableSourceHold('Cable source scope is not active')
        registered[1]()


def _cable_native_consumer_modules(originals):
    """Select only the actual fixed producer/Stage-L/pipeline read bindings."""
    from monitor import collection_ib_producer as producer
    from monitor import issue_tracker_stage_l_consumer as stage_l
    from monitor import issue_tracker_ib_runtime as ib_runtime
    from tools import ufm_collection_pipeline as pipeline

    # These are real captured consumers, not an inventory of sys.modules.
    if (stage_l.qualify_prod_stage_l.__globals__ is not stage_l.__dict__
            or stage_l.read_prod_ib_k_window is not ib_runtime.read_prod_ib_k_window
            or stage_l.read_whitelisted_ib_k_window is not ib_runtime.read_whitelisted_ib_k_window
            or stage_l.validate_prod_ib_k_window is not ib_runtime.validate_prod_ib_k_window
            or producer.validated_receipts is not pipeline.validated_receipts):
        raise CableSourceHold('Cable native consumer bindings differ')
    fixed = Path(stage_l.__file__).parent.parent / 'ztp/config/ib_topology_provenance.py'
    bindings = (
        (producer.read_cvt_provenance, 'read_cvt_provenance', 'ib_topology_provenance'),
        (producer.read_report_provenance, 'read_report_provenance', 'ib_topology_provenance'),
        (ib_runtime.read_report_provenance, 'read_report_provenance',
         'ztp.config.ib_topology_provenance'),
        (pipeline.read_report_provenance, 'read_report_provenance',
         'ztp.config.ib_topology_provenance'),
    )
    modules = []
    for reader, attribute, module_name in bindings:
        module = sys.modules.get(module_name)
        if (type(reader) is not FunctionType or module is None
                or reader.__globals__ is not module.__dict__
                or getattr(module, attribute, None) is not reader
                or reader.__module__ != module_name
                or Path(reader.__code__.co_filename) != fixed
                or Path(module.__file__) != fixed):
            raise CableSourceHold('Cable native read source differs')
        context = getattr(module, '_hold_current_cable_originals', None)
        inner = getattr(context, '__wrapped__', None)
        if (type(inner) is not FunctionType
                or inner.__globals__ is not module.__dict__
                or Path(inner.__code__.co_filename) != fixed):
            raise CableSourceHold('Cable native borrow source differs')
        if not any(module is original for original in modules):
            modules.append(module)
    # Both spellings must refer to the same actual held source original.
    # No new pathname/FD map is exposed to a caller or the native context.
    originals.file(fixed)
    return tuple(modules)


@contextmanager
def _hold_current_cable_cycle_source(store, *, http_root):
    """Reacquire CURRENT real C5 + durable C6 originals, with no online IO.

    Missing state is a refusal, not first-use initialization or a NOOP permit.
    This does not process historical pending receipts and issues no SDK/token,
    deadline, retry, publication, transport or worker authority.
    """
    from monitor import issue_tracker_local_commit as local
    from monitor.issue_tracker_credential_shape import _hold_private_file, parse_service_account_info
    from monitor.issue_tracker_online_target import (
        _hold_current_project_online_target,
        _require_held_current_project_online_target,
    )
    from monitor.issue_tracker_admission import local_publish_interval, read_shared_local_admission
    from monitor.issue_tracker_local_workbook_commit import _latest_receipted_prod_xlsx
    from monitor.issue_tracker_stage_l_consumer import (
        qualify_prod_stage_l, _require_original_source_projection,
    )
    from monitor.issue_tracker_collected_source import collected_changes

    stack = ExitStack()
    cleanup_errors = []

    def cleanup(callback):
        try:
            callback()
        except BaseException as error:
            # Let every remaining original/owner close run, without allowing
            # a later ordinary close to mask an earlier NI (ExitStack alone
            # would only expose its final exception).
            cleanup_errors.append(error)

    def enter(context):
        value = context.__enter__()
        stack.callback(cleanup, lambda: context.__exit__(None, None, None))
        return value

    registration = object()
    primary = None
    failure = None
    result = None
    native_key = None
    native_borrow = None
    eth_custody = None
    eth_key = None
    w1_custody = None
    w1_key = None
    policy_custody = None
    policy_key = None
    try:
        project = Path(store.project_identity)
        root, project, publication, template = _paths(store, http_root, project,
            project / '99-output-monitor', Path(http_root) / 'monitor/Issue_Tracker_Template_v1.xlsx')
        if store.scope != 'prod' or root != Path(http_root):
            raise CableSourceHold('Cable source is not the fixed current prod project')
        store_binding = _cable_require_store(store, root)
        token = enter(tracker_writer(project, publication))
        owner = local._owner(token)
        originals = _CableOriginals(root, store.project_key)
        stack.callback(cleanup, originals.close)
        # Hold settings/admission/generation originals before any qualification.
        # These are read-only fixed namespaces; no journal creation/repair.
        originals.file(project / '.tracker/INITIALIZED')
        originals.tree(project / '.tracker/settings')
        originals.tree(project / '.tracker/admissions')
        originals.tree(project / '.tracker/generations')
        originals.tree(Path(store.records_dir))
        originals.file(Path(store.witness_path))
        originals.file(project / '01-global.yaml')
        originals.file(template)
        originals.namespace(publication)
        if (_CABLE_ETH_INFO_CURRENT.get() is not None
                or _CABLE_W1_CURRENT.get() is not None
                or _CABLE_N_CURRENT.get() is not None):
            raise CableSourceHold('Cable read-only custodians cannot nest')
        eth_custody = _CableEthInfoCustody(
            registration, originals, token, owner, store, store_binding)
        _CABLE_ETH_INFO_CUSTODIES[registration] = eth_custody
        eth_key = _CABLE_ETH_INFO_CURRENT.set(eth_custody)
        w1_custody = _CableW1Custody(registration, eth_custody, template)
        _CABLE_W1_CUSTODIES[registration] = w1_custody
        w1_key = _CABLE_W1_CURRENT.set(w1_custody)
        policy_custody = _CablePolicyCustody(registration, eth_custody)
        _CABLE_N_CUSTODIES[registration] = policy_custody
        policy_key = _CABLE_N_CURRENT.set(policy_custody)
        settings = current_k(token)
        policy = local_publish_interval(project)
        whitelist = read_whitelist_workbook(template)
        cycles = read_completed_cycle_evidence(store)
        if (not cycles or not cycles[-1].qualifying or len(cycles) < settings.k
                or any(not item.qualifying for item in cycles[-settings.k:])):
            raise CableSourceHold('Cable current K lacks complete native cycles')
        selected_cycles = cycles[-settings.k:]
        _cable_hold_cycle_roles(originals, store, root, project, selected_cycles,
                                token=token, owner=owner, store_binding=store_binding)
        prior = _latest_receipted_prod_xlsx(token, whitelist.workbook_sha256)
        if prior is None:
            raise CableSourceHold('Cable current source has no durable local receipt')
        event = read_shared_local_admission(token, store, prior)
        if (type(event) is not dict
                or event['cycle_id'] != cycles[-1].cycle_id
                or event['cycle_completion_sha256'] != cycles[-1].completion_sha256
                or (event['publish_every_cycles'], event['policy_sha256']) != policy):
            raise CableSourceHold('Cable current local admission does not bind current cycle/N')
        generation = project / '.tracker/generations' / event['generation_id']
        manifest = originals.document(generation / 'MANIFEST')
        receipt = originals.document(generation / 'RECEIPT')
        if ('selected_panel' in manifest.get('qualified_source', {})
                or receipt['generation_id'] != event['generation_id']
                or receipt['published_sha256'] != event['published_sha256']):
            raise CableSourceHold('Cable current receipt lacks complete three-panel qualification')
        # All historical referenced publication images used by the strict reader
        # stay pinned too; the current image is never inferred from an API result.
        for name in originals.namespace(project / '.tracker/generations'):
            row = originals.document(project / '.tracker/generations' / name / 'RECEIPT')
            originals.file(publication / row['published'], expected=row['published_sha256'])
        current_image = publication / receipt['published']
        originals.file(current_image, expected=event['published_sha256'])
        if hashlib.sha256(prior).hexdigest() != event['published_sha256']:
            raise CableSourceHold('Cable current workbook differs from its actual receipt')
        binding = enter(_hold_current_project_online_target(token))
        credential_raw, verify_credential = enter(_hold_private_file('cre.json'))
        parse_service_account_info(credential_raw)  # Shape only; no key use/SDK.
        # Raw roles, local receipt/workbooks, policy, target and credential are
        # now actually held. Only now seal; actual C5 replay below consumes the
        # existing IB originals. Initial acquisition replay above stays distinct.
        if _CABLE_NATIVE_CURRENT.get() is not None:
            raise CableSourceHold('Cable native original owners cannot nest')
        native_modules = _cable_native_consumer_modules(originals)
        native_borrow = _CableNativeBorrow(registration, originals, token,
                                          owner, store, store_binding)
        _CABLE_NATIVE_BORROWS[registration] = native_borrow
        native_key = _CABLE_NATIVE_CURRENT.set(native_borrow)
        for native_module in native_modules:
            enter(native_module._hold_current_cable_originals())
        arguments = dict(http_root=root, settings=settings,
            whitelist_snapshot=whitelist, whitelist_path=template, writer_token=token)
        qualified = qualify_prod_stage_l(store, **arguments)
        if tuple(item.cycle_id for item in selected_cycles) != qualified.cycle_ids:
            raise CableSourceHold('Cable current cycle differs from actual C5')
        _require_original_source_projection(manifest['qualified_source'], qualified)
        changes = collected_changes(qualified.candidates)

        def verify():
            nonlocal failure
            if failure is not None:
                raise CableSourceHold('Cable source scope has a prior failure') from None
            try:
                eth_custody._bindings()
                w1_custody._bindings()
                policy_custody._bindings()
                store._require_gate()
                if _cable_require_store(store, root) != store_binding:
                    raise CableSourceHold('Cable worker/store/gate original changed')
                if local._owner(token) is not owner:
                    raise CableSourceHold('Cable writer owner was replaced')
                originals.verify()
                current_modules = _cable_native_consumer_modules(originals)
                if (len(current_modules) != len(native_modules)
                        or any(current is not original for current, original
                               in zip(current_modules, native_modules))):
                    raise CableSourceHold('Cable native consumer registration changed')
                verify_credential()
                _require_held_current_project_online_target(token, binding)
                if (current_k(token) != settings
                        or local_publish_interval(project) != policy
                        or read_whitelist_workbook(template) != whitelist
                        or read_completed_cycle_evidence(store) != cycles
                        or qualify_prod_stage_l(store, **arguments) != qualified
                        or read_shared_local_admission(token, store,
                            _latest_receipted_prod_xlsx(token, whitelist.workbook_sha256)) != event):
                    raise CableSourceHold('Cable current source qualification changed')
                originals.verify()
                verify_credential()
                _require_held_current_project_online_target(token, binding)
            except BaseException as error:
                failure = error  # Sticky revocation, never adoption or renewal.
                if not isinstance(error, Exception):
                    raise
                raise CableSourceHold('Cable current source is unavailable') from None

        result = _CableCycleSource('NO_SEND', changes, binding,
            event['generation_id'], event['published_sha256'], registration)
        _CABLE_SOURCE_SCOPES[registration] = (result, verify)
        result.verify()
        yield result
        result.verify()
    except BaseException as error:
        primary = error
    finally:
        _CABLE_SOURCE_SCOPES.pop(registration, None)  # Revoke before any close.
        if policy_custody is not None:
            policy_custody.active = False
        _CABLE_N_CUSTODIES.pop(registration, None)
        if policy_key is not None:
            try:
                _CABLE_N_CURRENT.reset(policy_key)
            except BaseException as error:
                cleanup_errors.append(error)
        if w1_custody is not None:
            w1_custody.active = False
        _CABLE_W1_CUSTODIES.pop(registration, None)
        if w1_key is not None:
            try:
                _CABLE_W1_CURRENT.reset(w1_key)
            except BaseException as error:
                cleanup_errors.append(error)
        if eth_custody is not None:
            eth_custody.active = False
        _CABLE_ETH_INFO_CUSTODIES.pop(registration, None)
        if eth_key is not None:
            try:
                _CABLE_ETH_INFO_CURRENT.reset(eth_key)
            except BaseException as error:
                cleanup_errors.append(error)
        if native_borrow is not None:
            native_borrow.active = False
        _CABLE_NATIVE_BORROWS.pop(registration, None)
        if native_key is not None:
            try:
                _CABLE_NATIVE_CURRENT.reset(native_key)
            except BaseException as error:
                cleanup_errors.append(error)
        try:
            # A pending body exception is kept outside generator finalizers, so
            # ordinary tail errors cannot replace an original NI or its cause.
            stack.close()
        except BaseException as error:
            if primary is None or (isinstance(primary, Exception)
                                   and not isinstance(error, Exception)):
                primary = error
        for error in cleanup_errors:
            if primary is None or (isinstance(primary, Exception)
                                   and not isinstance(error, Exception)):
                primary = error
    if primary is not None:
        if not isinstance(primary, Exception):
            raise primary
        raise CableSourceHold('Cable current source scope is unavailable') from None


class AutoLocalCollectorAnomaly(StageLHold):
    """Enough fresh cycles appeared before the shared publication floor."""


class TerminalC6AdmissionHold(StageLHold):
    """The current project has a RECEIPT without matching admission."""


@dataclass(frozen=True)
class AutoLocalNotDue:
    """A held source with no C23 automatic publication admission yet."""

    reason: str


def _validate_auto_clock(boot_id, monotonic_ns):
    if (type(boot_id) is not str or not boot_id
            or len(boot_id) > 128 or any(char.isspace() for char in boot_id)
            or type(monotonic_ns) is not int or monotonic_ns < 1):
        raise StageLHold("automatic admission clock provenance is invalid")


# The C6 bridge and runtime both read the same durable local event sequence.
# Keep this three-argument entry for existing runtime consumers while the
# journal implementation itself lives in the leaf admission module.
def read_auto_local_admission(token, store, expected_template_sha256):
    from monitor.issue_tracker_admission import (
        AdmissionHold, AdmissionTerminalOrphan, read_shared_local_admission,
    )
    from monitor.issue_tracker_local_workbook_commit import (
        _latest_receipted_prod_xlsx,
    )

    prior_image = _latest_receipted_prod_xlsx(
        token, expected_template_sha256)
    try:
        return read_shared_local_admission(token, store, prior_image)
    except AdmissionTerminalOrphan as exc:
        raise TerminalC6AdmissionHold(str(exc)) from exc
    except AdmissionHold as exc:
        raise StageLHold(str(exc)) from exc


def assess_auto_local_due(
    cycle_ids, *, interval, last_admitted_cycle_id,
    elapsed_seconds, minimum_seconds,
):
    """Evaluate C-23's relative event count and shared time floor.

    The caller must supply a validated durable admission witness and a
    trustworthy elapsed interval; this pure check never creates that witness.
    """
    if (type(cycle_ids) is not tuple or not cycle_ids
            or any(type(item) is not str or not item for item in cycle_ids)
            or len(set(cycle_ids)) != len(cycle_ids)
            or type(interval) is not int or interval < 1
            or type(minimum_seconds) is not int or minimum_seconds < 1):
        raise StageLHold("automatic local cadence input is invalid")
    if last_admitted_cycle_id is None:
        if elapsed_seconds is not None:
            raise StageLHold("first admission has unexpected prior time")
        return len(cycle_ids) >= interval
    if (type(last_admitted_cycle_id) is not str
            or last_admitted_cycle_id not in cycle_ids
            or type(elapsed_seconds) not in (int, float)
            or elapsed_seconds < 0):
        raise StageLHold("prior admission identity or time is unverifiable")
    try:
        finite_elapsed = math.isfinite(elapsed_seconds)
    except OverflowError as exc:
        raise StageLHold("prior admission elapsed time overflows") from exc
    if not finite_elapsed:
        raise StageLHold("prior admission elapsed time is nonfinite")
    after = len(cycle_ids) - cycle_ids.index(last_admitted_cycle_id) - 1
    if after < interval:
        return False
    if elapsed_seconds < minimum_seconds:
        raise AutoLocalCollectorAnomaly("collector_interval_below_minimum")
    return True


_PANELS = ("Switch Status", "Eth Link Validation", "IB Link Validation")
_NO_SEND = "disabled_no_send_authority"


def _panel(state, reason):
    return {"state": state, "reason": reason}


def local_publish_interval(project):
    """Retain the runtime API while the leaf owns policy and admission."""
    from monitor.issue_tracker_admission import (
        AdmissionHold, local_publish_interval as leaf_interval,
    )
    try:
        return leaf_interval(project)
    except AdmissionHold as exc:
        raise StageLHold(str(exc)) from exc


def _paths(store, http_root, project, publication, template_path):
    root = Path(http_root).resolve(strict=True)
    project = Path(project)
    publication = Path(publication)
    template = Path(template_path)
    if (not root.is_dir() or not project.is_absolute() or project.is_symlink()
            or publication != project / "99-output-monitor"
            or template.is_symlink() or not template.is_absolute()
            or Path(store.project_identity) != project
            or Path(store.root_status_dir) != root / "monitor/status"):
        raise StageLHold("Stage L path or collector authority mismatch")
    return root, project, publication, template


def _qualified_key_progress_matches(required_keys, panels, k):
    """Pure consistency check; a true result is never source or write authority."""
    if (type(k) is not int or k < 1 or type(required_keys) is not tuple
            or type(panels) is not dict or set(panels) != set(_PANELS)):
        return False
    observed = {}
    for name, panel in panels.items():
        if (type(panel) is not dict or panel.get("state") == "hold"
                or type(panel.get("per_key")) is not list):
            return False
        for item in panel["per_key"]:
            if (type(item) is not dict or type(item.get("activity_key")) is not list
                    or len(item["activity_key"]) != 4
                    or any(type(part) is not str or not part or chr(0) in part
                           for part in item["activity_key"])
                    or type(item.get("observed")) is not int
                    or not 0 <= item["observed"] <= k
                    or type(item.get("required")) is not int
                    or item["required"] != k
                    or item.get("state") not in ("pending", "source_window_complete")):
                return False
            key = (name, tuple(item["activity_key"]))
            if key in observed:
                return False
            observed[key] = item
    for panel_key in required_keys:
        if (type(panel_key) is not tuple or len(panel_key) != 2
                or type(panel_key[0]) is not str or panel_key[0] not in _PANELS
                or type(panel_key[1]) is not tuple):
            return False
        row = observed.get(panel_key)
        if (row is None or row["state"] != "source_window_complete"
                or row["observed"] != k):
            return False
    # Other pending/inactive keys do not erase the independently qualified subset.
    return True


def _qualified_panel_status(panel, k):
    """Render a previously proven source subset, not a qualification decision."""
    pending = [item for item in panel["per_key"]
               if 0 < item["observed"] < item["required"]]
    progress = (f"qualified subset; pending {min(item['observed'] for item in pending)}/{k}"
                if pending else f"qualified {k}/{k}")
    return {**panel, "state": "qualified",
            "reason": "source_set_qualified_no_local_receipt",
            "progress_text": progress,
            "per_key": [
                {**item, "progress_text":
                 (f"source complete {item['observed']}/{item['required']}"
                  if item["state"] == "source_window_complete"
                  else item["progress_text"])}
                for item in panel["per_key"]]}


def _stage_l_per_key_panels(store, root, settings, cycles, token):
    """Local diagnostics only; every key comes from reopened protected roles."""
    from monitor.issue_tracker_ib_per_key_source import (
        IbPerKeySourceHold, IbSourceAuthorityChanged, _row_key, read_prod_ib_per_key_source,
    )
    from monitor.issue_tracker_ib_runtime import (
        IbRuntimeHoldError, IbRuntimeInputChanged, read_completed_ib_cycle_report,
    )
    from monitor.issue_tracker_per_key_source import (
        EthSourceAuthorityChanged, PerKeySourceHold, _key_for_link,
        read_prod_eth_per_key_source,
    )
    from monitor.issue_tracker_switch_per_key_source import (
        SwitchPerKeySourceHold, read_prod_switch_per_key_source,
    )
    from monitor.issue_tracker_switch_runtime import (
        read_prod_eth_activity_cycle_source, read_prod_switch_cycle_source,
    )

    def pending(reason):
        return {**_panel("pending", reason), "per_key": [],
                "progress_text": f"pending 0/{settings.k}"}

    def held(reason):
        return {**_panel("hold", reason), "per_key": [],
                "progress_text": None}

    def entries(keys, reader, key_of=lambda item: item):
        rows = []
        for item in sorted(keys):
            key = key_of(item)
            result = reader(item)
            if (result.qualified is not False or result.key != key
                    or result.k_event_sha256 != settings.event_sha256):
                raise StageLHold("per-key source tried to grant authority")
            rows.append({
                "activity_key": list(key), "state": result.state,
                "observed": result.observed, "required": result.required, "reason": result.reason,
                "progress_text": ("inactive in latest cycle"
                    if result.reason == "latest_absent" else
                    f"pending {result.observed}/{result.required}"),
            })
        return rows

    def panel(rows):
        observed = min((item["observed"] for item in rows), default=0)
        return {**_panel("pending", "per_key_source_only"), "per_key": rows,
                "progress_text": f"pending {observed}/{settings.k}"}

    panels = {name: pending("cold_start") for name in _PANELS}
    if not cycles:
        return panels
    tail = cycles[-settings.k:]
    if any(cycle.qualifying is not True for cycle in tail):
        return {name: held("nonqualifying_cycle") for name in _PANELS}
    try:
        switch_keys = set()
        for cycle in tail:
            for slot in ("ethernet/prod", "nvlink/prod"):
                source = read_prod_switch_cycle_source(
                    store, http_root=root, sequence=cycle.sequence,
                    source_slot=slot,
                )
                switch_keys.update((
                    slot, ("switch", row.hostname, row.category,
                           row.component_or_sensor),
                ) for row in source.rows)
        switch_rows = entries(switch_keys, lambda item:
            read_prod_switch_per_key_source(
                store, http_root=root, settings=settings, key=item[1],
                source_slot=item[0], writer_token=token,
            ), key_of=lambda item: item[1])
        panels["Switch Status"] = panel(switch_rows)
    except (SwitchRuntimeHoldError, SwitchPerKeySourceHold, StageLHold):
        panels["Switch Status"] = held("source_evidence_incomplete")
    try:
        eth_keys = set()
        for cycle in tail:
            source = read_prod_eth_activity_cycle_source(
                store, http_root=root, sequence=cycle.sequence,
            )
            eth_keys.update(key for link in source.links
                            if (key := _key_for_link(link)) is not None)
        panels["Eth Link Validation"] = panel(entries(
            eth_keys, lambda key: read_prod_eth_per_key_source(
                store, http_root=root, settings=settings, key=key,
                writer_token=token,
            ),
        ))
    except EthSourceAuthorityChanged:
        # Keep the O-4 operator action distinct from waiting for first use or
        # investigating missing roles. Never expose raw source paths/errors
        # or invent an observation count across two different authorities.
        panels["Eth Link Validation"] = {
            **held("source_authority_changed"),
            "progress_text": "unknown — source authority changed; confirm input change",
        }
    except (SwitchRuntimeHoldError, PerKeySourceHold, StageLHold):
        panels["Eth Link Validation"] = held("source_evidence_incomplete")
    try:
        ib_keys = set()
        for cycle in tail:
            report = read_completed_ib_cycle_report(
                store, http_root=root, sequence=cycle.sequence,
            )
            ib_keys.update(_row_key(row) for row in report.rows)
        panels["IB Link Validation"] = panel(entries(
            ib_keys, lambda key: read_prod_ib_per_key_source(
                store, http_root=root, settings=settings, key=key,
                writer_token=token,
            ),
        ))
    except (IbSourceAuthorityChanged, IbRuntimeInputChanged):
        panels["IB Link Validation"] = {
            **held("source_authority_changed"),
            "progress_text": "unknown — source authority changed; confirm input change",
        }
    except (IbRuntimeHoldError, IbPerKeySourceHold, StageLHold):
        panels["IB Link Validation"] = held(
            "ib_report_not_bound_to_completed_cycle")
    return panels


def _qualified_manual_fingerprint(qualified, settings, panel):
    return {
        "project_key": qualified.project_key, "scope": qualified.scope, "k": qualified.k,
        "k_revision": settings.revision,
        "latest_cycle_id": qualified.cycle_ids[-1] if qualified.cycle_ids else None,
        "window_cycle_ids": qualified.cycle_ids,
        "whitelist_sha256": qualified.whitelist_sha256,
        "template_sha256": qualified.template_sha256,
        "source_authority_sha256": qualified.source_authority_sha256,
        "observations_sha256": qualified.observations_sha256,
        "selected_decision_sha256": selected_panel_decision_sha256(qualified, panel),
    }


def _prepare_manual_snapshot(token, qualified, store, root, settings, snapshot, template, panel):
    """Reopen sources and project a bound workbook under the caller's LK-P."""
    from monitor.issue_tracker_local_workbook_commit import (
        _latest_receipted_prod_xlsx, project_manual_panel_preview,
    )
    from monitor.issue_tracker_local_workbook import _read_bound_source
    from monitor.issue_tracker_manifest import freeze_prod_stage_l_manifest
    from monitor.issue_tracker_state_owner import require_current_k
    from monitor.issue_tracker_stage_l_consumer import (
        read_prod_stage_l_panel_source_files, validate_prod_stage_l_panel_source_files,
    )

    arguments = dict(http_root=root, settings=settings, whitelist_snapshot=snapshot,
                     whitelist_path=template, writer_token=token)
    sources = read_prod_stage_l_panel_source_files(qualified, store, panel=panel, **arguments)
    _, manifest_id = freeze_prod_stage_l_manifest(
        qualified, store, selected_panel=panel,
        expected_template_sha256=snapshot.workbook_sha256,
        metadata={"project_id": store.project_identity, "schema_version": 1,
                  "producer_version": "stage-l-runtime-v1",
                  "template_contract_version": "local-xlsx-v1",
                  "template_sha256": snapshot.workbook_sha256}, **arguments,
    )
    prior = _latest_receipted_prod_xlsx(token, snapshot.workbook_sha256)
    source = prior if prior is not None else _read_bound_source(template, snapshot)
    detail = project_manual_panel_preview(source, qualified, panel, manifest_id)
    public = {key: detail[key] for key in (
        "qualified_operation_count", "whitelist_skip_count", "new_count", "update_count",
        "skip_count", "row_digests")}
    public["source_files"] = [{"path": item.path, "recorded_at_utc": item.recorded_at_utc,
                               "sha256": item.sha256} for item in sources]
    binding = {"manifest_id": manifest_id, "source_files": [asdict(item) for item in sources],
               "detail": detail}
    digest = hashlib.sha256(json.dumps(binding, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n").hexdigest()
    validate_prod_stage_l_panel_source_files(sources, qualified, store, panel=panel, **arguments)
    require_current_k(token, Path(store.project_identity),
                      Path(store.project_identity) / "99-output-monitor", settings)
    if (read_whitelist_workbook(template) != snapshot
            or _latest_receipted_prod_xlsx(token, snapshot.workbook_sha256) != prior
            or (prior is None and _read_bound_source(template, snapshot) != source)):
        raise StageLHold("manual preview workbook or policy changed before readback")
    return public, digest


def inspect_manual_stage_l_preview(store, *, panel, http_root, project, publication, template_path):
    """Complete local-only worker snapshot; does not mint a token or mutate."""
    from monitor.issue_tracker_manual_preview import ManualPreviewHold, _bound_status
    from monitor.issue_tracker_stage_l_consumer import qualify_prod_stage_l

    if type(panel) is not str or panel not in _PANELS:
        raise ManualPreviewHold("manual preview panel is invalid")
    root, project, publication, template = _paths(
        store, http_root, project, publication, template_path)
    if store.scope != "prod" or template != root / "monitor/Issue_Tracker_Template_v1.xlsx":
        raise StageLHold("complete manual preview template or scope is unbound")
    status = inspect_stage_l(store, http_root=root, project=project,
                             publication=publication, template_path=template)
    prior = _bound_status(status, panel)
    with tracker_settings_writer(project, publication) as token:
        settings = current_k(token)
        snapshot = read_whitelist_workbook(template)
        qualified = qualify_prod_stage_l(store, http_root=root, settings=settings,
            whitelist_snapshot=snapshot, whitelist_path=template, writer_token=token)
        if prior != _qualified_manual_fingerprint(qualified, settings, panel):
            raise ManualPreviewHold("manual source changed before complete preview")
        public, digest = _prepare_manual_snapshot(
            token, qualified, store, root, settings, snapshot, template, panel)
    return {**status, "manual_preview": public, "manual_snapshot_sha256": digest}


def inspect_stage_l(store, *, http_root, project, publication, template_path):
    """Expose pending/hold/qualified source state, never APPLIED or online GO."""
    from monitor.issue_tracker_admission import AdmissionTerminalOrphan
    from monitor.issue_tracker_receipt_snapshot import LocalReceiptSnapshotHold

    try:
        root, project, publication, template = _paths(
            store, http_root, project, publication, template_path)
        if store.scope == "air":
            # AIR's read-only preview acquires LK-P itself. Preserve that
            # existing lock boundary; the shared snapshot below is prod only.
            with tracker_writer(project, publication) as token:
                settings = current_k(token)
            snapshot = read_whitelist_workbook(template)
            cycles = read_completed_cycle_evidence(store)
            window = assess_k_window(cycles, settings)
            status = {
                "schema_version": 1, "state": "pending",
                "project_key": store.project_key, "scope": store.scope,
                "latest_cycle_id": cycles[-1].cycle_id if cycles else None,
                "completed_cycles": len(cycles),
                "window_cycle_ids": [item.cycle_id for item in cycles[-settings.k:]],
                "k": settings.k, "k_revision": settings.revision,
                "whitelist_sha256": snapshot.whitelist.sha256,
                "online": _NO_SEND,
            }
            if window.status != "history_sufficient":
                status["panels"] = {
                    name: _panel("pending", window.reason)
                    for name in _PANELS}
                return status
            panels = {name: _panel("hold", "source_contract_unimplemented")
                      for name in _PANELS}
            try:
                preview = read_switch_runtime_window(
                    store, http_root=root, settings=settings,
                    whitelist_snapshot=snapshot, whitelist_path=template)
            except SwitchRuntimeHoldError:
                panels["Switch Status"] = _panel(
                    "hold", "source_evidence_incomplete")
            else:
                if preview.qualified is not False:
                    raise StageLHold("preview unexpectedly granted authority")
                panels["Switch Status"] = _panel(
                    "hold", "preview_is_not_qualification")
            status["state"] = "hold"
            status["panels"] = panels
            return status
        if store.scope != "prod":
            raise StageLHold("Stage L scope is unsupported")
        # Read-only status may recover K from continuously held originals
        # after legal delivered-projection archive. This does not change the
        # separate C6 commit owner or confer publication/send authority.
        with tracker_settings_writer(project, publication) as token:
            settings = current_k(token)
            snapshot = read_whitelist_workbook(template)
            try:
                cycles = read_completed_cycle_evidence(store)
            except CycleSequenceGap:
                # No readable complete chain means no provable count or
                # source window. Keep the cause distinct from legitimate
                # first use, without granting qualification or repairing it.
                if (current_k(token) != settings
                        or read_whitelist_workbook(template) != snapshot):
                    raise StageLHold("gap status K/W1 authority changed")
                return {
                    "schema_version": 1, "state": "hold",
                    "reason": "archive_sequence_gap",
                    "project_key": store.project_key, "scope": store.scope,
                    "latest_cycle_id": None, "completed_cycles": None,
                    "window_cycle_ids": [], "k": settings.k,
                    "k_revision": settings.revision,
                    "whitelist_sha256": snapshot.whitelist.sha256,
                    "panels": {name: {
                        **_panel("hold", "archive_sequence_gap"), "per_key": [],
                        "progress_text": f"pending ?/{settings.k} — archive sequence gap",
                    } for name in _PANELS},
                    "cycle_summary": {"published": None, "skipped": None,
                                      "pending": None, "pending_count_complete": False},
                    "online": _NO_SEND,
                }
            window = assess_k_window(cycles, settings)
            status = {
                "schema_version": 1, "state": "pending",
                "project_key": store.project_key, "scope": store.scope,
                "latest_cycle_id": cycles[-1].cycle_id if cycles else None,
                "completed_cycles": len(cycles),
                "window_cycle_ids": [item.cycle_id for item in cycles[-settings.k:]],
                "k": settings.k, "k_revision": settings.revision,
                "whitelist_sha256": snapshot.whitelist.sha256,
                "online": _NO_SEND,
            }
            qualified = None
            if store.scope == "prod":
                from monitor.issue_tracker_receipt_snapshot import (
                    read_current_cycle_local_receipts,
                )
                from monitor.issue_tracker_stage_l_consumer import (
                    ProdStageLQualifiedSet, StageLConsumerHold,
                    inspect_prod_stage_l_composed_sources, qualify_prod_stage_l,
                )
                panels = _stage_l_per_key_panels(
                    store, root, settings, cycles, token)
                if window.status == "history_sufficient":
                    try:
                        source = inspect_prod_stage_l_composed_sources(
                            store, http_root=root, settings=settings,
                            whitelist_snapshot=snapshot, whitelist_path=template,
                            writer_token=token)
                    except StageLConsumerHold:
                        status["reason"] = "prod_source_evidence_incomplete"
                    else:
                        if (source.qualified is not False
                                or source.switch_ib_source.switch_source.cycle_ids
                                != tuple(status["window_cycle_ids"])):
                            raise StageLHold("prod preview attempted to grant authority")
                        status["reason"] = source.reason
                        try:
                            qualified = qualify_prod_stage_l(
                                store, http_root=root, settings=settings,
                                whitelist_snapshot=snapshot,
                                whitelist_path=template, writer_token=token)
                        except StageLConsumerHold:
                            pass
                        else:
                            if (type(qualified) is not ProdStageLQualifiedSet
                                    or qualified.qualified is not True
                                    or qualified.cycle_ids
                                    != tuple(status["window_cycle_ids"])
                                    or qualified.project_key != store.project_key
                                    or qualified.scope != store.scope
                                    or qualified.k != settings.k
                                    or qualified.template_sha256
                                    != snapshot.workbook_sha256
                                    or qualified.whitelist_sha256
                                    != snapshot.whitelist.sha256):
                                raise StageLHold(
                                    "prod qualification differs from worker authority")
                            if not _qualified_key_progress_matches(
                                tuple((item.panel, item.activity_key)
                                      for item in qualified.candidates),
                                panels, settings.k,
                            ):
                                status["reason"] = "per_key_source_evidence_incomplete"
                            else:
                                status.update({
                                    "state": "qualified",
                                    "reason": "source_set_qualified_no_local_receipt",
                                    "qualified_operation_count": len(qualified.candidates),
                                    "whitelist_skip_count": len(qualified.whitelist_skips),
                                    "whitelist_skips": [
                                        _runtime_skip(item)
                                        for item in qualified.whitelist_skips],
                                    "template_sha256": qualified.template_sha256,
                                    "source_authority_sha256":
                                        qualified.source_authority_sha256,
                                    "observations_sha256": qualified.observations_sha256,
                                    "selected_decision_sha256": {
                                        panel: selected_panel_decision_sha256(
                                            qualified, panel)
                                        for panel in _PANELS
                                    },
                                })
                                panels = {
                                    name: _qualified_panel_status(panel, settings.k)
                                    for name, panel in panels.items()
                                }
                receipt = read_current_cycle_local_receipts(
                    token, store,
                    expected_template_sha256=snapshot.workbook_sha256,
                    settings=settings,
                    whitelist_sha256=snapshot.whitelist.sha256,
                    qualified_source=qualified)
                if status["state"] == "qualified" and receipt.published:
                    status["reason"] = "source_set_qualified_local_receipt"
                    for panel in panels.values():
                        panel["reason"] = status["reason"]
                status["cycle_summary"] = {
                    "published": receipt.published,
                    "skipped": (len(qualified.whitelist_skips)
                                if status["state"] == "qualified" else None),
                    "pending": sum(
                        0 < item["observed"] < item["required"]
                        for panel in panels.values()
                        for item in panel["per_key"]),
                    # A numeric zero with a held or cold panel is only a
                    # lower bound: its keys have not all been proven readable.
                    "pending_count_complete": all(
                        panel["state"] == "qualified"
                        for panel in panels.values()),
                }
                if (window.status != "history_sufficient"
                        and all(panels[name]["state"] == "pending"
                                for name in _PANELS[:2])):
                    status["state"] = "pending"
                elif status["state"] != "qualified":
                    status["state"] = "hold"
                status["panels"] = panels
            else:
                raise StageLHold("Stage L scope is unsupported")
            if (current_k(token) != settings
                    or read_completed_cycle_evidence(store) != cycles
                    or read_whitelist_workbook(template).workbook_sha256
                       != snapshot.workbook_sha256):
                raise StageLHold("Stage L snapshot changed during inspection")
            return status
    except (OSError, TypeError, AttributeError, RuntimeError, ValueError,
            CycleSourceHoldError, KChainHoldError, TrackerStateHold,
            WhitelistHoldError) as exc:
        if isinstance(exc, StageLHold):
            raise
        if (isinstance(exc, LocalReceiptSnapshotHold)
                and isinstance(exc.__cause__, AdmissionTerminalOrphan)):
            raise TerminalC6AdmissionHold(str(exc.__cause__)) from exc
        raise StageLHold("Stage L authority is incomplete or unsafe") from exc


def commit_qualified_prod_local(
    store, *, http_root, project, publication, template_path,
    refuse_prior_without_admission=False, auto_admission=None,
    manual_admission=None, expected_manual_preview=None,
    selected_panel=None,
):
    """Requalify protected prod sources under one writer and commit C6 only."""
    from monitor.issue_tracker_local_commit import LocalCommitHold
    from monitor.issue_tracker_local_workbook import LocalWorkbookHold
    from monitor.issue_tracker_local_workbook_commit import commit_prod_stage_l_workbook
    from monitor.issue_tracker_stage_l_consumer import (
        StageLConsumerHold, qualify_prod_stage_l,
    )

    try:
        root, project, publication, template = _paths(
            store, http_root, project, publication, template_path)
        if (store.scope != "prod"
                or template != root / "monitor/Issue_Tracker_Template_v1.xlsx"):
            raise StageLHold("C5-to-C6 template or scope is unbound")
        if type(refuse_prior_without_admission) is not bool:
            raise StageLHold("automatic admission guard must be explicit")
        if refuse_prior_without_admission != (auto_admission is not None):
            raise StageLHold("automatic admission witness must be explicit")
        if auto_admission is not None and (
                type(auto_admission) is not tuple or len(auto_admission) != 4):
            raise StageLHold("automatic admission witness shape is invalid")
        if manual_admission is not None and (
                auto_admission is not None or type(manual_admission) is not tuple
                or len(manual_admission) != 4):
            raise StageLHold("manual admission witness shape is invalid")
        if expected_manual_preview is not None and (
                manual_admission is None or type(expected_manual_preview) is not dict):
            raise StageLHold("manual preview requires a manual admission witness")
        if (expected_manual_preview is None) != (selected_panel is None):
            raise StageLHold("manual preview and one selected panel must be bound together")
        if selected_panel is not None and (
                type(selected_panel) is not str or selected_panel not in _PANELS):
            raise StageLHold("manual selected panel is invalid")
        with tracker_local_c6_writer(project, publication) as token:
            settings = current_k(token)
            snapshot = read_whitelist_workbook(template)
            if auto_admission is None and manual_admission is None:
                # The manual/ retry UI has not supplied a shared-domain
                # admission witness yet. It cannot create a new C6 generation
                # after an automatic event and bypass that event's limiter.
                from monitor.issue_tracker_local_commit import _owner
                try:
                    os.stat("admissions", dir_fd=_owner(token).root_fd,
                            follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    # Validate the existing chain before HOLD; a corrupt
                    # record must retain its specific failure evidence.
                    # A witness-bearing manual C6 uses the shared admission
                    # journal and floor in the C6 bridge. This no-witness
                    # entry stays HOLD; Stage O retry remains unimplemented.
                    read_auto_local_admission(
                        token, store, snapshot.workbook_sha256,
                    )
                    raise StageLHold(
                        "manual C6 lacks shared admission witness"
                    )
            if auto_admission is not None:
                policy_sha, interval, boot_id, now_ns = auto_admission
                if local_publish_interval(project) != (interval, policy_sha):
                    raise StageLHold("automatic local policy changed before C6")
                _validate_auto_clock(boot_id, now_ns)
                prior_admission = read_auto_local_admission(
                    token, store, snapshot.workbook_sha256,
                )
                if prior_admission is not None:
                    if (prior_admission["boot_id"] != boot_id
                            or now_ns < prior_admission["monotonic_ns"]):
                        raise StageLHold(
                            "automatic admission restart interval is unverifiable"
                        )
                    cycles = read_completed_cycle_evidence(store)
                    cycle_ids = tuple(cycle.cycle_id for cycle in cycles
                                      if cycle.qualifying)
                    due = assess_auto_local_due(
                        cycle_ids, interval=interval,
                        last_admitted_cycle_id=prior_admission["cycle_id"],
                        elapsed_seconds=(
                            now_ns - prior_admission["monotonic_ns"]
                        ) / 1_000_000_000,
                        minimum_seconds=MIN_CONTINUOUS_INTERVAL_MINUTES * 60,
                    )
                    if not due:
                        return AutoLocalNotDue("awaiting_new_cycle_or_time_floor")
            qualified = qualify_prod_stage_l(
                store, http_root=root, settings=settings,
                whitelist_snapshot=snapshot, whitelist_path=template,
                writer_token=token,
            )
            if expected_manual_preview is not None:
                # This comparison remains inside LK-P and follows a fresh
                # protected-source qualification.  A browser token alone can
                # never authorize the subsequent C6 generation.
                actual_preview = _qualified_manual_fingerprint(qualified, settings, selected_panel)
                if "manual_snapshot_sha256" in expected_manual_preview:
                    _, digest = _prepare_manual_snapshot(
                        token, qualified, store, root, settings, snapshot, template, selected_panel)
                    actual_preview["manual_snapshot_sha256"] = digest
                if expected_manual_preview != actual_preview:
                    raise StageLHold("manual preview source changed before C6")
            metadata = {
                "project_id": str(project), "schema_version": 1,
                "producer_version": "stage-l-runtime-v1",
                "template_contract_version": "local-xlsx-v1",
                "template_sha256": snapshot.workbook_sha256,
            }
            result = commit_prod_stage_l_workbook(
                token, qualified, store, http_root=root, settings=settings,
                whitelist_snapshot=snapshot, whitelist_path=template,
                template_path=template, metadata=metadata,
                expected_template_sha256=snapshot.workbook_sha256,
                auto_admission=auto_admission,
                manual_admission=manual_admission,
                selected_panel=selected_panel,
            )
            return result
    except (OSError, TypeError, AttributeError, RuntimeError, ValueError,
            LocalCommitHold, LocalWorkbookHold, StageLConsumerHold,
            TrackerStateHold, WhitelistHoldError) as exc:
        if isinstance(exc, StageLHold):
            raise
        from monitor.issue_tracker_admission import (
            AdmissionCollectorAnomaly, AdmissionTerminalOrphan,
        )
        if isinstance(exc, AdmissionTerminalOrphan):
            raise TerminalC6AdmissionHold(str(exc)) from exc
        if isinstance(exc, AdmissionCollectorAnomaly):
            raise AutoLocalCollectorAnomaly(str(exc)) from exc
        raise StageLHold("C5-to-C6 local authority is incomplete or unsafe") from exc
