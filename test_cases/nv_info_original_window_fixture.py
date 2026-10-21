"""Fixed test-only cold NV consumption window; SOURCE / NOT RUN."""
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
    "from test_cases.nv_info_original_window_fixture import child_entry\n"
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
            or relative.parent.as_posix() != 'nvlink/monitor/nvsw-info'):
        raise RuntimeError('selected fixture role escaped fixed NV namespace')
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
        'fault_local_token_revoked': False, 'lock_rdwr_allowed': 0,
        'healthy_nv_semantics': [], 'healthy_slots_closed': False,
        'healthy_local_revoked': False, 'lease_closed': False,
        'arm_route': None, 'same_mode': False}
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
    healthy_token = None
    fault_originals = None
    fault_token = None
    raw_method = runtime._CableOriginals.raw
    actual_pread = os.pread
    original_raw = None
    role_frame = None
    consumer = info._exact_archive_bytes
    preview = info.read_switch_info_preview
    nv_guard = runtime._CableEthInfoCustody._known_nv_legacy
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

    def consumer_frame(frame):
        while frame is not None:
            if (frame.f_code is consumer.__code__ and frame.f_globals is consumer.__globals__
                    and Path(frame.f_locals.get('path', '')) == selected):
                return frame
            frame = frame.f_back
        return None

    def actual_preview_frame(frame):
        while frame is not None:
            if (frame.f_code is preview.__code__ and frame.f_globals is preview.__globals__
                    and frame.f_locals.get('source_slot') == 'nvlink/prod'
                    and Path(frame.f_locals.get('archive_path', '')) == selected):
                return frame
            frame = frame.f_back
        return None

    def capture_pin(frame):
        nonlocal pin, pin_key, healthy_originals, healthy_token, fault_originals, fault_token
        ancestor = frame
        actual_roles = None
        while ancestor is not None:
            if ancestor.f_code is roles.__code__ and ancestor.f_globals is roles.__globals__:
                actual_roles = ancestor
                break
            ancestor = ancestor.f_back
        if actual_roles is not None:
            originals = actual_roles.f_locals['originals']
            token = actual_roles.f_locals['token']
            if phase == 'healthy':
                healthy_originals, healthy_token = originals, token
            else:
                fault_originals, fault_token = originals, token
        elif phase == 'healthy' and healthy_originals is not None:
            originals = healthy_originals
        else:
            raise RuntimeError('actual NV role holder prerequisite absent')
        record = originals.files.get((id(runtime.os), selected))
        if record is None:
            raise RuntimeError('actual NV archive was not already held')
        pin, parent, identity, digest, view = record
        before = os.fstat(pin)
        pin_key = (before.st_dev, before.st_ino)
        if (base.identity(before) != tuple(str(item) for item in identity)
                or base.identity(os.lstat(selected)) != base.identity(before)):
            raise RuntimeError('actual NV pin/named identity prerequisite absent')
        return originals, record, before

    def arm_actual_window(frame, route):
        nonlocal mutating, armed, original_raw, replacement_key
        if phase != 'fault' or facts['arm_count'] != 0:
            return
        if consumer_frame(frame) is None or actual_preview_frame(frame) is None:
            raise RuntimeError('actual NV consumer/preview ancestor missing')
        originals, record, before = capture_pin(frame)
        if route == 'actual_original_raw_call':
            if (frame.f_locals.get('self') is not originals
                    or frame.f_locals.get('_existing_record') is not record):
                raise RuntimeError('NV raw call is not the already held original')
        facts['actual_pin_live'] = True
        original_raw = os.pread(pin, before.st_size + 1, 0)
        if len(original_raw) != before.st_size or hashlib.sha256(original_raw).hexdigest() != record[3]:
            raise RuntimeError('actual NV original bytes prerequisite absent')
        facts['pin_key'] = list(pin_key)
        facts['original_sha256'] = record[3]
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
            facts['same_mode'] = (changed.st_mode & 0o7777) == (before.st_mode & 0o7777)
            facts['arm_route'] = route
            facts['arm_count'] += 1
        finally:
            mutating = False

    def observe(frame, event, value):
        try:
            is_consumer = frame.f_code is consumer.__code__ and frame.f_globals is consumer.__globals__
            is_raw = frame.f_code is raw_method.__code__ and frame.f_globals is raw_method.__globals__
            is_preview = frame.f_code is preview.__code__ and frame.f_globals is preview.__globals__
            is_guard = frame.f_code is nv_guard.__code__ and frame.f_globals is nv_guard.__globals__
            if is_preview and event == 'return' and value is not None:
                if (frame.f_locals.get('source_slot') == 'nvlink/prod'
                        and Path(frame.f_locals.get('archive_path', '')) == selected
                        and phase == 'healthy'):
                    if healthy_originals is None:
                        raise RuntimeError('NV semantic result lacks prior actual pin')
                    record = healthy_originals.files[(id(runtime.os), selected)]
                    facts['healthy_nv_semantics'].append({
                        'source_slot': value.source_slot,
                        'selected_hosts': list(value.selected_hosts),
                        'abnormal_keys': [list(row) for row in value.abnormal_keys],
                        'not_applicable': [[host, list(kinds)] for host, kinds in value.not_applicable_by_host],
                        'raw_matches_actual_pin': value.archive_sha256 == record[3]
                            and facts.get('healthy_last_raw_sha256') == record[3],
                    })
                return
            # Crucially do NOT mutate at consumer CALL before the existing guard.
            # The current legacy branch must first actually return True.
            if (is_guard and event == 'return' and value is True
                    and Path(frame.f_locals.get('path', '')) == selected
                    and consumer_frame(frame) is not None):
                arm_actual_window(frame, 'actual_nv_guard_return')
                return
            # A future real retained-FD branch may omit the legacy path guard.
            # This alternative hooks only its actual existing-record raw call.
            if (is_raw and event == 'call'
                    and Path(frame.f_locals.get('path', '')) == selected
                    and consumer_frame(frame) is not None):
                arm_actual_window(frame, 'actual_original_raw_call')
                return
            if not is_consumer and not (is_raw and event in ('c_call', 'c_return')):
                return
            current = consumer_frame(frame)
            if current is None:
                return
            if is_consumer and Path(frame.f_locals.get('path', '')) != selected:
                return
            if event in ('c_call', 'c_return'):
                if armed and event == 'c_call' and value is os.fstat and is_consumer:
                    fd = frame.f_locals.get('descriptor', frame.f_locals.get('fd'))
                    if type(fd) is int and fd not in opened:
                        st = os.fstat(fd)
                        key = (st.st_dev, st.st_ino)
                        opened[fd] = key
                        if key != pin_key:
                            facts['foreign_open_count'] += 1
                fd, primitive = None, None
                if value is actual_pread and (is_raw or is_consumer):
                    fd = frame.f_locals.get('fd', frame.f_locals.get('descriptor'))
                    primitive = 'pread'
                elif is_consumer and getattr(value, '__name__', None) == 'read':
                    stream = getattr(value, '__self__', None)
                    candidate = frame.f_locals.get('descriptor')
                    if stream is not None and stream.fileno() == candidate:
                        fd, primitive = candidate, 'read'
                if type(fd) is int and primitive is not None:
                    tag = (id(frame), fd, primitive, phase)
                    if event == 'c_call':
                        read_calls[tag] = True
                    elif read_calls.get(tag) is True:
                        st = os.fstat(fd)
                        key = (st.st_dev, st.st_ino)
                        if phase == 'healthy':
                            facts['healthy_semantic_reads'].append({
                                'fd': fd, 'pin_fd': pin, 'key': list(key),
                                'pin_key': list(pin_key), 'primitive': primitive})
                        elif armed:
                            facts['consumer_read_completed'] = True
                            if key != pin_key:
                                facts['foreign_read_count'] += 1
                        read_keys.append((phase, fd, key))
            if not is_consumer:
                return
            if event == 'call':
                if phase == 'fault' and facts['arm_count'] != 0:
                    return
                capture_pin(frame)
            elif event == 'return':
                if phase == 'healthy' and type(value) is bytes:
                    digest = hashlib.sha256(value).hexdigest()
                    facts['healthy_last_raw_sha256'] = digest
                    facts['healthy_pin_consumption_witness'] = (
                        facts['healthy_pin_consumption_witness']
                        or (healthy_originals is not None
                            and digest == healthy_originals.files[(id(runtime.os), selected)][3]
                            and any(stage == 'healthy' and fd == pin and key == pin_key
                                    for stage, fd, key in read_keys)))
                elif phase == 'fault' and armed:
                    facts['consumer_returned'] = type(value) is bytes
                    restore()
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
                lease_fd = lease._lock_fd
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
                    facts['healthy_slots_closed'] = (healthy_originals is not None
                        and healthy_originals.closed and bool(healthy_originals.slots)
                        and all(base.closed(fd) for view, fd, key in healthy_originals.slots))
                    facts['healthy_local_revoked'] = (healthy_token is not None
                        and healthy_token not in local._ACTIVE)
                    semantic_ok = bool(facts['healthy_nv_semantics']) and all(row == {
                        'source_slot': 'nvlink/prod', 'selected_hosts': ['nvsw01'],
                        'abnormal_keys': [['nvsw01', 'asic_temp', 'ASIC1']],
                        'not_applicable': [['nvsw01', ['fan', 'psu']]],
                        'raw_matches_actual_pin': True,
                    } for row in facts['healthy_nv_semantics'])
                    if (facts['observer_errors'] or not semantic_ok
                            or not facts['healthy_slots_closed']
                            or not facts['healthy_local_revoked']
                            or not facts['healthy_graph_unchanged']
                            or facts['healthy_outcome'] != 'NO_SEND'
                            or facts['healthy_target'] != 'synthetic_spreadsheet_id_0001'
                            or facts['healthy_keys'] != sorted([
                                ['eth_cabling', 'leaf-a', 'swp1', 'Mis-wiring'],
                                ['ib_cabling', 'leaf01', 'sw1p1', 'Mis-wiring'],
                                ['switch', 'leaf-a', 'fan', 'PSU1/FAN1'],
                                ['switch', 'nvsw01', 'asic_temp', 'ASIC1'],
                            ])):
                        raise RuntimeError('healthy prerequisite missing; fault not reached')
                    facts['healthy_complete'] = True
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
            facts['lease_closed'] = base.closed(lease_fd)
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
        result['parent_closed'] = True
        result['parent_events'] = [row[0] for row in events]
        with base.old.fixed_inputs(test, case):
            local = base.old.local_evidence(case, committed)
            # Select only the exact already-produced NV role; no directory scan.
            if type(artifacts) is not dict or 'nvlink/prod' not in artifacts:
                raise base.FixturePrerequisiteError('unique actual NV artifact slot missing')
            slot = artifacts['nvlink/prod']
            if type(slot) is not dict or 'info' not in slot:
                raise base.FixturePrerequisiteError('actual NV info role missing')
            selected = Path(slot['info'])
            relative = selected.relative_to(case.root).as_posix()
            if Path(relative).parent.as_posix() != 'nvlink/monitor/nvsw-info':
                raise base.FixturePrerequisiteError('actual NV role namespace mismatch')
            control = Path(base.tempfile.mkdtemp(prefix='req7-nv-info-original-control-', dir=case.root.parent))
            control.chmod(0o700)
            print('NV_INFO_ORIGINAL_CONTROL_ROOT=' + str(control), flush=True)
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
