"""Fixed test-only cold ETH consumption window; SOURCE / NOT RUN."""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import sys
import threading
from unittest import mock

from test_cases import cold_completed_original_attach_fixture as base

PROGRAM = (
    "import sys\n"
    "sys.path.insert(0,sys.argv[1])\n"
    "from test_cases.eth_info_held_window_fixture import child_entry\n"
    "raise SystemExit(child_entry(sys.argv[2],sys.argv[3]))\n")


def child_entry(data_root, manifest_path):
    # Startup imports are outside the deny-only audit; no general startup-IO claim.
    from monitor import issue_tracker_publish_runtime as runtime
    from monitor import issue_tracker_switch_info_source as info
    from monitor import collection_ib_producer as producer
    from monitor import issue_tracker_credential_shape as credential
    from monitor import issue_tracker_online_target as target
    from monitor import issue_tracker_local_commit as local
    root = Path(data_root)
    manifest = Path(manifest_path)
    payload = json.loads(manifest.read_bytes())
    relative = Path(payload['relative'])
    if (relative.is_absolute() or '..' in relative.parts
            or not relative.as_posix().startswith('ethernet/monitor/eth-info/')):
        raise RuntimeError('selected fixture role escaped fixed ETH namespace')
    selected = root / payload['relative']
    saved = manifest.parent / 'held-original'
    project = root / 'DAY0-Prepare/fabric-a'
    lock = project / '.tracker/LOCK'
    lock_parent = os.lstat(lock.parent)
    lock_identity = base.identity(os.lstat(lock))
    writer_code = local._writer_owner.__wrapped__.__code__
    facts = {'observer_errors': [], 'healthy_complete': False,
        'audit_armed': False, 'arm_count': 0, 'actual_pin_live': False,
        'same_bytes_new_inode': False, 'restored_original': False,
        'consumer_returned': False, 'consumer_read_completed': False,
        'foreign_open_count': 0, 'foreign_read_count': 0,
        'pin_consumption_witness': False, 'network': 0, 'nested_children': 0,
        'profile_restored': False, 'window_error_type': None,
        'healthy_pin_consumption_witness': False, 'healthy_semantic_reads': [],
        'fault_originals_closed': False, 'fault_slots_closed': False,
        'fault_local_token_revoked': False, 'lock_rdwr_allowed': 0}
    if sys.getprofile() is not None:
        raise RuntimeError('existing profile observer cannot be replaced')
    mutating = False
    armed = False
    pin = None
    pin_key = None
    replacement_key = None
    opened = {}
    read_calls = {}
    read_keys = []
    phase = 'healthy'
    healthy_originals = None
    fault_originals = None
    fault_token = None
    raw_method = runtime._CableOriginals.raw
    actual_pread = os.pread
    original_raw = None
    role_frame = None
    consumer = info._exact_archive_bytes
    roles = runtime._cable_hold_cycle_roles
    real_os = info.os

    def deny(event, args):
        if event.startswith('socket.'):
            facts['network'] += 1
            raise AssertionError('fixture network forbidden')
        if event == 'subprocess.Popen':
            facts['nested_children'] += 1
            raise AssertionError('fixture nested child forbidden')
        if event in ('os.rename', 'os.remove', 'os.mkdir', 'os.rmdir',
                     'os.chmod', 'os.link', 'os.symlink', 'os.truncate',
                     'os.utime', 'os.chown'):
            if mutating and event == 'os.rename' and len(args) >= 2:
                if (Path(args[0]), Path(args[1])) in ((selected, saved), (saved, selected)):
                    return
            if mutating and event == 'os.chmod' and Path(args[0]) == selected:
                return
            raise AssertionError('fixture mutation outside exact fault forbidden')
        if event == 'open' and len(args) >= 3 and type(args[2]) is int:
            flags = args[2]
            if flags & os.O_ACCMODE == os.O_RDWR and not flags & (
                    os.O_CREAT | os.O_TRUNC | os.O_APPEND | os.O_EXCL):
                caller = sys._getframe(1)
                # Audit args omit dir_fd: verify the real original caller frame
                # and its actual original directory FD before allowing LOCK.
                root_fd = caller.f_locals.get('root_fd')
                if (caller.f_code is writer_code and caller.f_globals is local.__dict__
                        and args[0] == 'LOCK' and type(root_fd) is int
                        and caller.f_locals.get('project') == project
                        and (os.fstat(root_fd).st_dev, os.fstat(root_fd).st_ino)
                            == (lock_parent.st_dev, lock_parent.st_ino)
                        and base.identity(os.stat('LOCK', dir_fd=root_fd,
                                                 follow_symlinks=False)) == lock_identity
                        and base.identity(os.lstat(lock)) == lock_identity):
                    facts['lock_rdwr_allowed'] += 1
                    return  # Existing original LOCK flock only; never create/write.
            if flags & (os.O_CREAT | os.O_TRUNC | os.O_APPEND | os.O_WRONLY | os.O_RDWR):
                if mutating and Path(args[0]) == selected and flags & os.O_EXCL:
                    return
                raise AssertionError('fixture write outside exact fault forbidden')

    sys.addaudithook(deny)
    facts['audit_armed'] = True

    def restore():
        nonlocal mutating, armed
        if armed:
            mutating = True
            try:
                os.replace(saved, selected)
                facts['restored_original'] = (
                    (os.lstat(selected).st_dev, os.lstat(selected).st_ino) == pin_key)
            finally:
                mutating = False
                armed = False

    class InfoOS:
        # Only this consumer module's actual readonly open syscall is observed.
        # No replacement result, successful verifier, registry or FD is supplied.
        def __getattr__(self, name):
            return getattr(real_os, name)
        def open(self, path, flags, *args, **kwargs):
            fd = real_os.open(path, flags, *args, **kwargs)
            if Path(path) == selected and armed:
                held = os.fstat(fd)
                key = (held.st_dev, held.st_ino)
                opened[fd] = key
                facts.setdefault('consumer_open_keys', []).append(list(key))
                if key != pin_key:
                    facts['foreign_open_count'] += 1
            return fd

    def observe(frame, event, value):
        nonlocal mutating, armed, pin, pin_key, replacement_key, original_raw, role_frame
        nonlocal healthy_originals, fault_originals, fault_token
        try:
            is_consumer = (frame.f_code is consumer.__code__
                           and frame.f_globals is consumer.__globals__)
            is_raw = (frame.f_code is raw_method.__code__
                      and frame.f_globals is raw_method.__globals__)
            if not is_consumer and not (is_raw and event in ('c_call', 'c_return')):
                return
            if is_consumer and Path(frame.f_locals.get('path', '')) != selected:
                return
            # Observe the actual primitive regardless of which module owns os.
            # Exact consumer ancestry + exact actual raw() code distinguish
            # semantic bytes from Originals.file/_digest prehash/verification.
            ancestor = frame
            semantic = False
            while ancestor is not None:
                if (ancestor.f_code is consumer.__code__
                        and ancestor.f_globals is consumer.__globals__
                        and Path(ancestor.f_locals.get('path', '')) == selected):
                    semantic = True
                    break
                ancestor = ancestor.f_back
            if semantic and event in ('c_call', 'c_return'):
                # If a later implementation opens via runtime.os rather than
                # info.os, original consumer fstat still exposes its actual FD.
                if (armed and event == 'c_call' and value is os.fstat
                        and frame.f_code is consumer.__code__
                        and frame.f_globals is consumer.__globals__):
                    actual_fd = frame.f_locals.get('descriptor', frame.f_locals.get('fd'))
                    if type(actual_fd) is int and actual_fd not in opened:
                        opened_info = os.fstat(actual_fd)
                        opened_key = (opened_info.st_dev, opened_info.st_ino)
                        opened[actual_fd] = opened_key
                        if opened_key != pin_key:
                            facts['foreign_open_count'] += 1
                descriptor = None
                primitive = None
                if (value is actual_pread and
                        ((frame.f_code is raw_method.__code__
                          and frame.f_globals is raw_method.__globals__)
                         or (frame.f_code is consumer.__code__
                             and frame.f_globals is consumer.__globals__))):
                    descriptor = frame.f_locals.get('fd', frame.f_locals.get('descriptor'))
                    primitive = 'pread'
                elif (frame.f_code is consumer.__code__
                        and frame.f_globals is consumer.__globals__
                        and getattr(value, '__name__', None) == 'read'):
                    stream = getattr(value, '__self__', None)
                    candidate = frame.f_locals.get('descriptor')
                    if stream is not None and stream.fileno() == candidate:
                        descriptor, primitive = candidate, 'read'
                if type(descriptor) is int and primitive is not None:
                    tag = (id(frame), descriptor, primitive, phase)
                    if event == 'c_call':
                        read_calls[tag] = True
                    elif read_calls.get(tag) is True:
                        actual = os.fstat(descriptor)
                        key = (actual.st_dev, actual.st_ino)
                        if phase == 'healthy':
                            facts['healthy_semantic_reads'].append({
                                'fd': descriptor, 'pin_fd': pin, 'key': list(key),
                                'pin_key': list(pin_key), 'primitive': primitive})
                        elif armed:
                            facts['consumer_read_completed'] = True
                            if key != pin_key:
                                facts['foreign_read_count'] += 1
                        read_keys.append((phase, descriptor, key))
            if (frame.f_code is not consumer.__code__
                    or frame.f_globals is not consumer.__globals__
                    or Path(frame.f_locals.get('path', '')) != selected):
                return
            if event == 'call':
                if phase != 'healthy' and facts['arm_count'] != 0:
                    return
                ancestor = frame.f_back
                role_frame = None
                while ancestor is not None:
                    if ancestor.f_code is roles.__code__ and ancestor.f_globals is roles.__globals__:
                        role_frame = ancestor
                        break
                    ancestor = ancestor.f_back
                if role_frame is not None:
                    originals = role_frame.f_locals['originals']
                    if phase == 'healthy':
                        healthy_originals = originals
                elif phase == 'healthy' and healthy_originals is not None:
                    originals = healthy_originals
                else:
                    return
                record = originals.files.get((id(runtime.os), selected))
                if record is None:
                    raise RuntimeError('selected ETH role not actually pinned before consumer')
                pin, parent, identity, digest, view = record
                before = os.fstat(pin)
                pin_key = (before.st_dev, before.st_ino)
                live = (base.identity(before) == tuple(str(item) for item in identity)
                    and base.identity(os.lstat(selected)) == base.identity(before))
                if not live:
                    raise RuntimeError('actual pinned identity prerequisite absent')
                if phase == 'healthy':
                    return  # Observe real healthy consumption, never mutate.
                if role_frame is None:
                    raise RuntimeError('fault original roles frame prerequisite absent')
                fault_originals = originals  # Observation only; no registry insertion.
                fault_token = role_frame.f_locals['token']
                facts['actual_pin_live'] = live
                original_raw = os.pread(pin, before.st_size + 1, 0)
                if len(original_raw) != before.st_size or hashlib.sha256(original_raw).hexdigest() != digest:
                    raise RuntimeError('actual original bytes prerequisite absent')
                facts['pin_key'] = list(pin_key)
                facts['original_sha256'] = digest
                mutating = True
                try:
                    os.rename(selected, saved)
                    armed = True
                    with selected.open('xb') as stream:
                        stream.write(original_raw)
                    selected.chmod(before.st_mode & 0o7777)
                    changed = os.lstat(selected)
                    replacement_key = (changed.st_dev, changed.st_ino)
                    facts['replacement_key'] = list(replacement_key)
                    facts['same_bytes_new_inode'] = (
                        replacement_key != pin_key and selected.read_bytes() == original_raw)
                finally:
                    mutating = False
                facts['arm_count'] += 1
            elif event == 'return':
                if phase == 'healthy':
                    if type(value) is bytes:
                        facts['healthy_pin_consumption_witness'] = (
                            facts['healthy_pin_consumption_witness']
                            or (hashlib.sha256(value).hexdigest() ==
                                healthy_originals.files[(id(runtime.os), selected)][3]
                                and any(stage == 'healthy' and fd == pin and key == pin_key
                                        for stage, fd, key in read_keys)))
                elif armed:
                    facts['consumer_returned'] = type(value) is bytes
                    if type(value) is bytes:
                        facts['consumer_sha256'] = hashlib.sha256(value).hexdigest()
                    restore()  # A legitimate early refusal need not return/read bytes.
        except BaseException as error:
            facts['observer_errors'].append(type(error).__name__)
            try:
                restore()
            except BaseException as cleanup:
                facts['observer_errors'].append(type(cleanup).__name__)

    try:
        if base.graph(root) != payload['graph']:
            raise RuntimeError('original cold graph prerequisite mismatch')
        project = root / 'DAY0-Prepare/fabric-a'
        acquire = base.completed.GATE._hold_completed_source_read_lease
        Reader = base.completed.WORKER.CompletedCollectionCycleReader
        with ExitStack() as stack:
            for module in (producer, credential, target):
                stack.enter_context(mock.patch.object(module, 'os', base.PrivateRootOS(root)))
            with acquire(str(project), status_dir=root / 'monitor/status') as lease:
                reader = Reader(lease=lease)
                before_health = base.graph(root)
                stack.enter_context(mock.patch.object(info, 'os', InfoOS()))
                prior = sys.getprofile()
                try:
                    sys.setprofile(observe)
                    with runtime._hold_current_cable_cycle_source(reader, http_root=root) as healthy:
                        actual = runtime._CABLE_NATIVE_CURRENT.get()
                        actual.require_live()
                        facts['healthy_outcome'] = healthy.outcome
                        facts['healthy_target'] = healthy.binding.spreadsheet_id
                        facts['healthy_keys'] = sorted([list(row.activity_key) for row in (
                            *healthy.changes.cabling, *healthy.changes.switch)])
                    facts['healthy_graph_unchanged'] = base.graph(root) == before_health
                    facts['healthy_complete'] = True
                    if (not facts['healthy_graph_unchanged']
                            or facts['healthy_outcome'] != 'NO_SEND'
                            or facts['healthy_target'] != 'synthetic_spreadsheet_id_0001'
                            or facts['healthy_keys'] != sorted([
                                ['eth_cabling', 'leaf-a', 'swp1', 'Mis-wiring'],
                                ['ib_cabling', 'leaf01', 'sw1p1', 'Mis-wiring'],
                                ['switch', 'leaf-a', 'fan', 'PSU1/FAN1'],
                                ['switch', 'nvsw01', 'asic_temp', 'ASIC1'],
                            ])):
                        raise RuntimeError('healthy prerequisite missing; fault not reached')
                    phase = 'fault'
                    try:
                        with runtime._hold_current_cable_cycle_source(reader, http_root=root):
                            pass
                    except BaseException as error:
                        facts['window_error_type'] = type(error).__name__
                    # Genuine A context has completed ALL its finally cleanup.
                    # These known slots are only observed; never rescued/reclosed.
                    if fault_originals is not None:
                        facts['fault_originals_closed'] = fault_originals.closed is True
                        facts['fault_slots_closed'] = (
                            bool(fault_originals.slots)
                            and all(base.closed(fd) for view, fd, key in fault_originals.slots))
                        facts['fault_slot_count'] = len(fault_originals.slots)
                        facts['fault_local_token_revoked'] = fault_token not in local._ACTIVE
                finally:
                    sys.setprofile(prior)
                    facts['profile_restored'] = sys.getprofile() is prior
                    restore()
    except BaseException as error:
        facts['carrier_error_type'] = type(error).__name__
    # All behavior assertions live in parent AFTER actual owners/finalizers.
    print('COLD_ORIGINAL_ATTACH_RESULT=' + json.dumps(facts, sort_keys=True), flush=True)
    return 0


def run_workflow(test):
    result = {}
    def after(case, committed, artifacts, parent, events):
        if parent._lock_fd != -1 or tuple(row[0] for row in events) != (
                'mark_success_return', 'exit_call', 'exit_return'):
            raise base.FixturePrerequisiteError('actual parent exit prerequisite absent')
        with base.old.fixed_inputs(test, case):
            local = base.old.local_evidence(case, committed)
            selected = Path(artifacts['ethernet/prod']['info'])
            relative = selected.relative_to(case.root).as_posix()
            if not relative.startswith('ethernet/monitor/eth-info/'):
                raise base.FixturePrerequisiteError('actual ETH role namespace mismatch')
            control = Path(base.tempfile.mkdtemp(prefix='req7-eth-info-control-', dir=case.root.parent))
            control.chmod(0o700)
            print('ETH_INFO_CONTROL_ROOT=' + str(control), flush=True)
            manifest = control / 'original-graph.json'
            with manifest.open('xb') as stream:
                stream.write(json.dumps({'graph': base.graph(case.root),
                    'relative': relative}, separators=(',', ':')).encode('ascii'))
            manifest.chmod(0o600)
            with mock.patch.object(base, 'CHILD_PROGRAM', PROGRAM):
                status, child, _raw = base.launch(case.root, manifest)
            if status != 0:
                raise base.FixturePrerequisiteError('cold child terminal facts unavailable')
            result.update(child)
            result['local_unchanged'] = base.old.local_evidence(case, committed) == local
    base.completed.run_protected_after_parent_exit(test, after)
    return result
