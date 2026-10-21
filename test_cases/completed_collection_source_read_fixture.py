"""NOT RUN: retained private read-lease fixtures, no source/send authority."""
from contextlib import contextmanager
import errno
from hashlib import sha256
import importlib
import inspect
import json
import os
from pathlib import Path
import select
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest import mock

from test_cases import test_collection_cycle_persistence as persistence

WORKER = persistence.WORKER
GATE = importlib.import_module(WORKER.CollectionGate.__module__)
PROD_SLOTS = ('ethernet/prod', 'infiniband/prod', 'nvlink/prod')
STAT_FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
               'st_size', 'st_mtime_ns', 'st_ctime_ns')


def api(test):
    hold = getattr(GATE, 'CompletedSourceReadHold', None)
    acquire = getattr(GATE, '_hold_completed_source_read_lease', None)
    reader = getattr(WORKER, 'CompletedCollectionCycleReader', None)
    test.assertTrue(callable(acquire), 'MISSING_COMPLETED_SOURCE_READ_LEASE')
    test.assertTrue(isinstance(hold, type) and issubclass(hold, GATE.CollectionGateError),
                    'MISSING_TYPED_COMPLETED_SOURCE_READ_HOLD')
    test.assertTrue(isinstance(reader, type), 'MISSING_COMPLETED_COLLECTION_CYCLE_READER')
    return acquire, reader, hold


def retained_root(prefix):
    root = Path(tempfile.mkdtemp(prefix=prefix, dir='/private/tmp')).resolve(strict=True)
    print('COMPLETED_SOURCE_READ_OWNED_ROOT=' + str(root), flush=True)
    return root


def stat9(info):
    return tuple(getattr(info, key) for key in STAT_FIELDS)


def snapshot(root):
    root = Path(root)
    if not os.path.lexists(root):
        return ('absent',)
    rows = []
    for path in (root, *sorted(root.rglob('*'))):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            value = ('link', os.readlink(path))
        elif stat.S_ISREG(info.st_mode):
            value = ('file', path.read_bytes())
        elif stat.S_ISDIR(info.st_mode):
            value = ('directory',)
        else:
            raise AssertionError('nonordinary private fixture artifact')
        rows.append((str(path.relative_to(root)), stat9(info), value))
    return tuple(rows)


def fd_closed(fd):
    try:
        os.fstat(fd)
    except OSError as error:
        return error.errno == errno.EBADF
    return False


def rebind(path):
    path = Path(path)
    old = path.lstat()
    raw = path.read_bytes()
    retained = path.with_name(path.name + '.test-retained-original')
    if os.path.lexists(retained):
        raise AssertionError('private retained-original collision')
    path.rename(retained)
    path.write_bytes(raw)
    path.chmod(stat.S_IMODE(old.st_mode))
    new = path.lstat()
    return ((old.st_dev, old.st_ino), (new.st_dev, new.st_ino), raw, retained)


def make_completed_unit():
    """Real persistence of literal UNIT result, not native IB qualification."""
    root = retained_root('req7-completed-read-unit-')
    project = root / 'project'
    project.mkdir(mode=0o700)
    status = root / 'monitor/status'
    parent = WORKER.CollectionGate(str(project), 'prod', status_dir=status)
    with parent as actual:
        if actual.decision.allowed is not True or actual.enforce_cooldown is not True:
            raise AssertionError('ordinary private parent gate did not admit first collection')
        store = WORKER.CollectionCycleStore(gate=actual)
        # The empty real chain never invokes any process inspector.
        start = store.allocate_start()
        store.publish_launch(start, pid=4321, boot_id='private-unit-boot',
            process_start_time='9000', argv=['private-unit-collector'],
            context={'scope': 'prod'}, credential_argv_positions=(),
            credential_context_names=())
        # This old literal fixture creates three accepted summary DATA rows;
        # no device, source qualification or process observation is claimed.
        store.publish_completion(start, persistence.successful_cycle_result(start))
        actual.mark_success()
    if parent._lock_fd != -1:
        raise AssertionError('ordinary parent gate has not exited')
    with WORKER.CollectionGate(str(project), 'prod', status_dir=status) as ordinary:
        cooldown = (ordinary.decision.allowed, ordinary.decision.reason)
    # Ordinary contender fchmod can change LOCK ctime. Snapshot only AFTER it.
    completion = store.completion_path(1)
    raw = completion.read_bytes()
    document = json.loads(raw)
    summary = document['run_result']['summary']
    summary_raw = (json.dumps(summary, ensure_ascii=False, sort_keys=True,
                             separators=(',', ':'), allow_nan=False) + '\n').encode()
    return SimpleNamespace(root=root, project=project, status=status, store=store,
        start=start, cooldown=cooldown, completion=completion,
        completion_sha=sha256(raw).hexdigest(), summary_sha=sha256(summary_raw).hexdigest(),
        lock=status / '.switch-collection-cooldown.lock',
        state=status / '.switch-collection-cooldown.json')


RAW_CONTENDER = r'''
import fcntl,os,sys
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
try:
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:
        print('BUSY',flush=True)
    else:
        print('ACQUIRED',flush=True)
        fcntl.flock(fd,fcntl.LOCK_UN)
finally:
    os.close(fd)
'''


def raw_contender(lock):
    """Own stdlib-only child, no old gate/permission/mode mutation."""
    result = subprocess.run([sys.executable, '-I', '-B', '-c', RAW_CONTENDER, str(lock)],
        stdin=subprocess.DEVNULL, capture_output=True, timeout=10, check=False)
    if result.returncode != 0 or result.stderr or result.stdout not in (b'BUSY\n', b'ACQUIRED\n'):
        raise AssertionError('owned raw flock contender failed')
    return result.stdout


RAW_HOLDER = r'''
import fcntl,os,sys
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
try:
    fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    print('HELD',flush=True)
    sys.stdin.buffer.read(1)
    fcntl.flock(fd,fcntl.LOCK_UN)
finally:
    os.close(fd)
'''


@contextmanager
def raw_holder(lock):
    process = subprocess.Popen([sys.executable, '-I', '-B', '-c', RAW_HOLDER, str(lock)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    primary = None
    try:
        ready, _, _ = select.select([process.stdout], [], [], 10)
        if not ready or process.stdout.readline(32) != b'HELD\n':
            raise AssertionError('owned raw holder failed to acquire')
        yield
    except BaseException as error:
        primary = error
    cleanup = None
    try:
        _out, error = process.communicate(b'x', timeout=10)
        if process.returncode != 0 or error:
            raise AssertionError('owned raw holder failed to close')
    except subprocess.TimeoutExpired:
        cleanup = AssertionError('owned raw holder timeout; not product deadline proof')
        try:
            process.kill()  # Only this retained, self-created stdlib child.
            process.communicate(timeout=10)
        except BaseException as error:
            cleanup = error
    except BaseException as error:
        cleanup = error
    if primary is not None:
        if cleanup is not None:
            try:
                sys.stderr.write('COMPLETED_READ_FIXTURE_CLEANUP_FAILED_BODY_EXCEPTION_PRESERVED\n')
            except BaseException:
                pass
        raise primary
    if cleanup is not None:
        raise cleanup


def run_protected_after_parent_exit(test, body):
    """Compose old qualified real-IO carrier with NEW opt-in gate close seam."""
    from test_cases import issue_tracker_cable_post_c6_fixture as old
    from test_cases import test_issue_tracker_switch_runtime_workflow as base_fixture
    from test_cases.test_issue_tracker_stage_l_consumer_workflow import ProdStageLConsumerWorkflowTests
    original = ProdStageLConsumerWorkflowTests('runTest')
    test.assertIn('post_c6_parent_gate_exit', inspect.signature(
        original._exercise_real_protected_three_panel_fixture).parameters,
        'MISSING_COMPLETED_READ_PARENT_EXIT_TEST_CARRIER')
    events = []
    mark = WORKER.CollectionGate.mark_success
    exit_method = WORKER.CollectionGate.__exit__
    prior = sys.getprofile()
    if prior is not None:
        raise AssertionError('cannot replace an existing profile observer')
    def observe(frame, event, value):
        if frame.f_globals is not mark.__globals__:
            return
        actual = frame.f_locals.get('self')
        if frame.f_code is mark.__code__ and event == 'return' and type(value) is str:
            events.append(('mark_success_return', actual, value))
        if frame.f_code is exit_method.__code__ and event == 'call':
            fd = actual._lock_fd
            if fd >= 0:
                info = os.fstat(fd)
                events.append(('exit_call', actual, fd, (info.st_dev, info.st_ino)))
        if frame.f_code is exit_method.__code__ and event == 'return':
            calls = [row for row in events if row[0] == 'exit_call' and row[1] is actual]
            if calls:
                events.append(('exit_return', actual, fd_closed(calls[-1][2])))
    class RetainedTemporaryDirectory:
        def __init__(self, *args, **kwargs):
            self.name = str(retained_root('req7-completed-read-protected-'))
        def cleanup(self):
            print('COMPLETED_SOURCE_READ_RETAINED_ROOT=' + self.name, flush=True)
    facade = SimpleNamespace(**{name: getattr(tempfile, name) for name in dir(tempfile)})
    facade.TemporaryDirectory = RetainedTemporaryDirectory
    entered = []
    def after(case, committed, artifacts):
        entered.append(True)
        parent = case.store.gate
        body(case, committed, artifacts, parent, tuple(row for row in events if row[1] is parent))
    def action():
        # Only this test fixture module's temp directory allocation is retained;
        # real FD/owner/producer cleanup remains fully active and observable.
        with mock.patch.object(base_fixture, 'tempfile', facade):
            original.setUp()
        original._exercise_real_protected_three_panel_fixture(skip_history=False,
            post_c6_fixture=after, post_c6_parent_gate_exit=True)
    try:
        sys.setprofile(observe)
        old._run_fixture_action_with_cleanup(original, action)
    finally:
        sys.setprofile(prior)
    test.assertEqual([True], entered)
