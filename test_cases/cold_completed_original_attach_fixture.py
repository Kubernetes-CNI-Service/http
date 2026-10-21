"""NOT RUN. Fixed cold-child, existing-only original graph IO carrier.

Graph manifest is TEST expected DATA, never a production qualification grant.
"""
from contextlib import ExitStack
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import threading
from unittest import mock

import test_cases
from test_cases import completed_collection_source_read_fixture as completed
from test_cases import issue_tracker_cable_post_c6_fixture as old

ROOT = Path(test_cases.__file__).resolve().parents[1]
REAL_POPEN = subprocess.Popen  # Captured before old fixed_inputs deny guard.
LAUNCHED = []  # Actual original handles only; no production permission registry.
CHILD_PROGRAM = (
    "import sys\n"
    "sys.path.insert(0,sys.argv[1])\n"
    "from test_cases.cold_completed_original_attach_fixture import cold_entry\n"
    "raise SystemExit(cold_entry(sys.argv[2],sys.argv[3]))\n")
MAX_FILES = 2048
MAX_FILE = 64 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024


class GraphRefusal(ValueError):
    pass


class MissingSourceCapability(ValueError):
    pass


class FixturePrerequisiteError(RuntimeError):
    """Carrier health absent: fault NOT REACHED, not a product vulnerability."""
    pass


def identity(info):
    return tuple(str(value) for value in (info.st_dev, info.st_ino, info.st_mode,
        info.st_nlink, info.st_uid, info.st_gid, info.st_size,
        info.st_mtime_ns, info.st_ctime_ns))


def graph(root):
    """Finite own-tree scan, no link traversal or unknown-directory search."""
    rows = []
    total = 0
    def visit(path, relative):
        nonlocal total
        if len(rows) >= MAX_FILES:
            raise GraphRefusal('fixture graph count bound')
        before = path.lstat()
        row = {'path': relative, 'identity': list(identity(before))}
        rows.append(row)
        if stat.S_ISLNK(before.st_mode):
            first = os.readlink(path)
            middle = path.lstat()
            second = os.readlink(path)
            after = path.lstat()
            if (first != second or identity(middle) != identity(before)
                    or identity(after) != identity(before)):
                raise GraphRefusal('fixture link changed between complete checks')
            row['kind'], row['target'] = 'link', first
            if len(first.encode('utf-8')) > 4096:
                raise GraphRefusal('fixture link size bound')
        elif stat.S_ISDIR(before.st_mode):
            row['kind'] = 'directory'
            for entry in sorted(os.scandir(path), key=lambda value: value.name):
                visit(path / entry.name, entry.name if relative == '.'
                      else relative + '/' + entry.name)
        elif stat.S_ISREG(before.st_mode):
            row['kind'] = 'file'
            if not 0 <= before.st_size <= MAX_FILE or before.st_nlink != 1:
                raise GraphRefusal('fixture ordinary file bound')
            total += before.st_size
            if total > MAX_TOTAL:
                raise GraphRefusal('fixture graph byte bound')
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            failure = None
            try:
                digests = []
                for pass_number in (0, 1):
                    if (identity(os.fstat(fd)) != identity(before)
                            or identity(path.lstat()) != identity(before)):
                        raise GraphRefusal('fixture named-held pre-read identity differs')
                    if pass_number and os.lseek(fd, 0, os.SEEK_SET) != 0:
                        raise GraphRefusal('fixture original rewind failed')
                    digest = hashlib.sha256()
                    amount = 0
                    while True:
                        data = os.read(fd, min(65536, before.st_size + 1 - amount))
                        if not data:  # Actual EOF for EACH complete same-FD read.
                            break
                        amount += len(data)
                        if amount > before.st_size:
                            raise GraphRefusal('fixture file grew')
                        digest.update(data)
                    if (amount != before.st_size
                            or identity(os.fstat(fd)) != identity(before)
                            or identity(path.lstat()) != identity(before)):
                        raise GraphRefusal('fixture named-held post-read identity differs')
                    digests.append(digest.hexdigest())
                if digests[0] != digests[1]:
                    raise GraphRefusal('fixture original double read differs')
                row['sha256'] = digests[0]
            except BaseException as error:
                failure = error
            finally:
                try:
                    os.close(fd)  # One original close attempt, no numeric rescue.
                except BaseException as error:
                    if (failure is None or (isinstance(failure, Exception)
                            and not isinstance(error, Exception))):
                        failure = error
            if failure is not None:
                raise failure
        else:
            raise GraphRefusal('fixture special file refused')
        if identity(path.lstat()) != identity(before):
            raise GraphRefusal('fixture named original changed')
    visit(root, '.')
    return rows


def capture(call):
    try:
        return call(), None
    except BaseException as error:
        return None, error


class PrivateRootOS:
    """Module-local IO view, same native bytes/fds; no successful checker."""
    def __init__(self, root):
        self.root = root

    def __getattr__(self, name):
        return getattr(os, name)

    def _path(self, path):
        return self.root if path == '/' else path

    def _metadata(self, value):
        from types import SimpleNamespace
        result = SimpleNamespace(**{name: getattr(value, name) for name in dir(value)
                                    if name.startswith('st_')})
        result.st_uid = 0
        return result

    def open(self, name, flags, *args, **kwargs):
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            raise AssertionError('private source attach attempted write-open')
        return os.open(self._path(name), flags, *args, **kwargs)

    def stat(self, path, *args, **kwargs):
        return self._metadata(os.stat(self._path(path), *args, **kwargs))

    def fstat(self, fd):
        return self._metadata(os.fstat(fd))

    def geteuid(self):
        return 0

    def getuid(self):
        return 0


def closed(fd):
    try:
        os.fstat(fd)
    except OSError as error:
        return error.errno == errno.EBADF
    return False


def cold_entry(data_root, manifest_path):
    """Fixed TEST entry, not native actor, SDK issuer, public launcher or permit."""
    facts = {'state': 'FIXTURE_ERROR', 'a_calls': 0, 'borrow_calls': 0,
             'c5_returns': [], 'network': 0, 'children': 0,
             'profile_armed': False, 'profile_restored': False, 'audit_armed': False}
    root = Path(data_root)
    project = root / 'DAY0-Prepare/fabric-a'
    prior = sys.getprofile()
    if prior is not None:
        return 65
    try:
        raw = Path(manifest_path).read_bytes()
        if not 0 < len(raw) <= 4 * 1024 * 1024:
            raise GraphRefusal('fixture manifest bound')
        expected = json.loads(raw.decode('ascii'))
        from monitor import issue_tracker_publish_runtime as runtime
        from monitor import issue_tracker_stage_l_consumer as stage_l
        from monitor import collection_ib_producer as producer
        from monitor import issue_tracker_credential_shape as credential
        from monitor import issue_tracker_online_target as target
        if (Path(runtime.__file__).resolve().parents[1] != ROOT
                or not callable(getattr(runtime, '_hold_current_cable_cycle_source', None))):
            raise MissingSourceCapability()
        def deny_io(event, args):
            if event.startswith('socket.'):
                facts['network'] += 1
                raise AssertionError('cold source fixture network forbidden')
            if event == 'subprocess.Popen':
                facts['children'] += 1
                raise AssertionError('nested source fixture child forbidden')
            if event in ('os.mkdir', 'os.remove', 'os.rename', 'os.rmdir', 'os.chmod',
                         'os.link', 'os.symlink', 'os.truncate', 'os.utime', 'os.chown'):
                raise AssertionError('cold source fixture mutation forbidden')
            if event == 'open' and len(args) >= 3 and type(args[2]) is int:
                if args[2] & (os.O_CREAT | os.O_TRUNC | os.O_APPEND):
                    raise AssertionError('cold source fixture creation forbidden')
        sys.addaudithook(deny_io)
        facts['audit_armed'] = True
        a = runtime._hold_current_cable_cycle_source.__wrapped__
        borrow = runtime._CableNativeBorrow.require_live
        qualify = stage_l.qualify_prod_stage_l
        a_frames = []  # Generator resumes are NOT additional acquisitions.
        def observe(frame, event, value):
            if event == 'call' and frame.f_code is a.__code__ and frame.f_globals is a.__globals__:
                if not any(frame is original for original in a_frames):
                    a_frames.append(frame)
                    facts['a_calls'] += 1
            elif event == 'call' and frame.f_code is borrow.__code__ and frame.f_globals is borrow.__globals__:
                facts['borrow_calls'] += 1
            elif event == 'return' and frame.f_code is qualify.__code__ and frame.f_globals is qualify.__globals__:
                if value is not None:
                    facts['c5_returns'].append(getattr(value, 'qualified', None) is True)
        sys.setprofile(observe)
        facts['profile_armed'] = True
        # Test preimage guard; mismatch is fixture attach refusal, NOT a product
        # native vulnerability or a substitute for real C5/held validation.
        if graph(root) != expected:
            raise GraphRefusal('fixture graph is not original')
        lease_fd = None
        slots = []
        source = None
        with ExitStack() as stack:
            for module in (producer, credential, target):
                stack.enter_context(mock.patch.object(module, 'os', PrivateRootOS(root)))
            acquire = completed.GATE._hold_completed_source_read_lease
            Reader = completed.WORKER.CompletedCollectionCycleReader
            with acquire(str(project), status_dir=root / 'monitor/status') as lease:
                lease_fd = lease._lock_fd
                reader = Reader(lease=lease)
                facts['reader_current_child'] = (reader.gate is lease
                    and lease.lane == 'completed-source-read')
                with runtime._hold_current_cable_cycle_source(reader, http_root=root) as source:
                    actual = runtime._CABLE_NATIVE_CURRENT.get()
                    actual.require_live()
                    facts['native_current_child'] = actual.execution_owner == (os.getpid(), threading.get_ident())
                    facts['outcome'] = source.outcome
                    facts['target'] = source.binding.spreadsheet_id
                    facts['keys'] = sorted([list(item.activity_key) for item in
                        (*source.changes.cabling, *source.changes.switch)])
                    facts['source_live'] = runtime._CABLE_SOURCE_SCOPES.get(source._registration)[0] is source
                    slots = tuple((fd, key) for _view, fd, key in actual.originals.slots)
                    facts['all_pins_live'] = all((os.fstat(fd).st_dev, os.fstat(fd).st_ino) == key
                                                  for fd, key in slots)
                facts['all_pins_closed'] = bool(slots) and all(closed(fd) for fd, _key in slots)
                _unused, revoked = capture(source.verify)
                facts['source_revoked'] = isinstance(revoked, runtime.CableSourceHold)
                lease.verify()
            facts['lease_closed'] = closed(lease_fd)
        facts['graph_unchanged'] = graph(root) == expected
        facts['state'] = 'NO_SEND_ATTACHED'
    except MissingSourceCapability:
        facts['state'] = 'MISSING_HELD_SOURCE_CAPABILITY'
    except GraphRefusal:
        facts['state'] = 'GRAPH_REFUSED_BEFORE_BORROW'
    except BaseException as error:
        facts['error_type'] = type(error).__name__  # No exception data or rawbody.
    finally:
        sys.setprofile(prior)
        facts['profile_restored'] = sys.getprofile() is prior
    return emit(facts, 0 if facts['state'] == 'NO_SEND_ATTACHED' else 3)


def emit(facts, status):
    print('COLD_ORIGINAL_ATTACH_RESULT=' + json.dumps(facts, sort_keys=True), flush=True)
    return status


def launch(root, manifest):
    argv = (sys.executable, '-B', '-c', CHILD_PROGRAM, str(ROOT), str(root), str(manifest))
    process = REAL_POPEN(argv, cwd=str(ROOT), env={'LC_ALL': 'C', 'HOME': os.path.expanduser('~')},
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        close_fds=True, pass_fds=(), start_new_session=True)
    genuine = type(process) is REAL_POPEN
    # Retain the ORIGINAL objects, never adopt a later changed Popen slot.
    pipes = ((process.stdin, process.stdout, process.stderr) if genuine else ())
    primary = cleanup_error = result = None
    terminal = False

    def remember(error):
        nonlocal cleanup_error
        if (cleanup_error is None or (isinstance(cleanup_error, Exception)
                and not isinstance(error, Exception))):
            cleanup_error = error

    try:
        if not genuine or process.args != argv:
            raise AssertionError('cold fixture requires its actual fixed Popen')
        LAUNCHED.append(process)
        try:
            stdout, stderr = process.communicate(timeout=420)
        except subprocess.TimeoutExpired:
            raise AssertionError('COLD_ORIGINAL_ATTACH_TIMEOUT_UNKNOWN') from None
        if len(stdout) + len(stderr) > 65536:
            raise AssertionError('cold source diagnostic bound')
        lines = [line for line in stdout.splitlines() if line.startswith(b'COLD_ORIGINAL_ATTACH_RESULT=')]
        if len(lines) != 1:
            raise AssertionError('cold source result missing; fixture not qualified')
        result = (process.returncode, json.loads(lines[0].split(b'=', 1)[1]), stdout)
    except BaseException as error:
        primary = error
    finally:
        if genuine:
            # Covers TimeoutError AND arbitrary incoming NI/ordinary failures.
            # kill() is only the retained genuine original direct-child handle.
            # No signalling a scanned/reported/reaped residual numeric group.
            if process.returncode is None:
                try:
                    process.kill()
                except BaseException as error:
                    remember(error)
                try:
                    process.wait(timeout=5)
                except BaseException as error:
                    remember(error)
            try:
                if process.returncode is not None:
                    try:
                        os.killpg(process.pid, 0)  # Observation of THIS owned group only.
                    except ProcessLookupError:
                        terminal = True
                if not terminal:
                    remember(AssertionError('COLD_ORIGINAL_CHILD_TERMINATION_UNKNOWN'))
            except BaseException as error:
                remember(error)
        else:
            remember(AssertionError('COLD_ORIGINAL_PROCESS_IDENTITY_UNKNOWN'))
        # communicate may already have closed these exact originals on EOF.
        # Do not retry a prior actual close; still inspect/settle every known pipe
        # independently so one close fault never skips another or masks a NI.
        for stream in pipes:
            if stream is not None:
                try:
                    if not stream.closed:
                        stream.close()  # At most one explicit attempt here.
                    if not stream.closed:
                        raise AssertionError('COLD_ORIGINAL_PIPE_CLOSE_UNKNOWN')
                except BaseException as error:
                    remember(error)
        if cleanup_error is not None:
            # Constant evidence only; diagnostics must never mask original NI.
            try:
                print('COLD_ORIGINAL_CLEANUP_UNKNOWN', flush=True)
            except BaseException:
                pass
    if primary is not None and not isinstance(primary, Exception):
        raise primary  # Same incoming NI object and preexisting cause.
    if cleanup_error is not None and not isinstance(cleanup_error, Exception):
        raise cleanup_error
    if primary is not None:
        raise primary
    if cleanup_error is not None:
        raise cleanup_error
    if not terminal or result is None:
        raise AssertionError('COLD_ORIGINAL_ATTACH_NOT_SETTLED')
    return result


def run_case(test, fault):
    result = {}
    def after(case, committed, artifacts, parent, events):
        prior_launches = len(LAUNCHED)
        result['parent_closed'] = parent._lock_fd == -1
        result['parent_events'] = tuple(row[0] for row in events)
        with old.fixed_inputs(test, case) as inputs:
            local_before = old.local_evidence(case, committed)
            expected = graph(case.root)
            control = Path(tempfile.mkdtemp(prefix='req7-cold-attach-control-', dir=case.root.parent))
            control.chmod(0o700)
            print('COLD_ATTACH_CONTROL_ROOT=' + str(control), flush=True)
            manifest = control / 'original-graph.json'
            with manifest.open('xb') as stream:
                stream.write(json.dumps(expected, ensure_ascii=True, separators=(',', ':')).encode('ascii'))
            manifest.chmod(0o600)
            result['healthy'] = launch(case.root, manifest)
            result['after_health'] = graph(case.root) == expected
            healthy_status, healthy, _healthy_raw = result['healthy']
            # launch() returns only after actual EOF/reap/group absence/pipe
            # closure. These are fault-execution safety prerequisites, not the
            # final business-key oracle (which remains only in the old test).
            result['fault_prerequisites'] = {
                'parent_closed': result['parent_closed'] is True,
                'parent_exit': result['parent_events'] == (
                    'mark_success_return', 'exit_call', 'exit_return'),
                'status_zero': healthy_status == 0,
                'attached': healthy.get('state') == 'NO_SEND_ATTACHED',
                'no_send': healthy.get('outcome') == 'NO_SEND',
                'real_qualification': healthy.get('a_calls') == 1
                    and type(healthy.get('borrow_calls')) is int
                    and healthy['borrow_calls'] > 0
                    and type(healthy.get('c5_returns')) is list
                    and bool(healthy['c5_returns'])
                    and all(value is True for value in healthy['c5_returns']),
                'graph_unchanged': result['after_health'] is True
                    and healthy.get('graph_unchanged') is True,
                'local_unchanged': old.local_evidence(case, committed) == local_before,
                'source_cleanup': all(healthy.get(field) is True for field in (
                    'reader_current_child', 'native_current_child', 'source_live',
                    'all_pins_live', 'all_pins_closed', 'source_revoked', 'lease_closed',
                    'profile_armed', 'profile_restored')),
                'no_network_or_nested_child': healthy.get('network') == 0
                    and healthy.get('children') == 0,
            }
            if not all(result['fault_prerequisites'].values()):
                result['fault_stage'] = 'FAULT_NOT_REACHED'
                return  # Normal original parent finalizers MUST still execute.
            # Negative paths are fixed genuine fixture roles, not caller auth.
            changed = (case.root / 'ztp/config/nvos/template/P2P/output-p2p/fabric-blue-cvt.xlsx.provenance.json'
                       if fault == 'same-byte-inode' else artifacts['ethernet/prod']['info'])
            changed = Path(changed)
            if not changed.is_relative_to(case.root):
                raise AssertionError('fault role outside this actual private graph')
            before = changed.lstat()
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise AssertionError('fault role is not this actual ordinary original')
            raw = changed.read_bytes()
            saved = control / 'retained-original'
            changed.rename(saved)
            if fault == 'same-byte-inode':
                with changed.open('xb') as stream:
                    stream.write(raw)
                changed.chmod(stat.S_IMODE(before.st_mode))
                result['same_bytes_new_inode'] = (changed.read_bytes() == raw
                    and (changed.stat().st_dev, changed.stat().st_ino) != (before.st_dev, before.st_ino))
            else:
                result['really_missing'] = not changed.exists()
            fault_graph = graph(case.root)
            result['negative'] = launch(case.root, manifest)
            result['after_negative'] = graph(case.root) == fault_graph
            result['original_preserved'] = (saved.read_bytes() == raw
                and (saved.stat().st_dev, saved.stat().st_ino) == (before.st_dev, before.st_ino))
            result['local_unchanged'] = old.local_evidence(case, committed) == local_before
            result['old_parent_network_children'] = (inputs['network'].call_count, inputs['children'].call_count)
            result['actual_cold_child_count'] = len(LAUNCHED) - prior_launches
    completed.run_protected_after_parent_exit(test, after)
    if result.get('fault_stage') == 'FAULT_NOT_REACHED':
        # Outside original parent owners/finalizers: preserve actual sanitized
        # child facts, without manufacturing a negative result or success.
        print(result['healthy'][2].decode('ascii'), end='', flush=True)
        print('COLD_ATTACH_FAULT_NOT_REACHED=' + json.dumps({
            'state': 'FAULT_NOT_REACHED',
            'healthy_status': result['healthy'][0],
            'parent_after_health': result['after_health'],
            'prerequisites': result['fault_prerequisites'],
        }, sort_keys=True), flush=True)
        raise FixturePrerequisiteError('COLD_SOURCE_FIXTURE_HEALTH_NOT_REACHED')
    return result
