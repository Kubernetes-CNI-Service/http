"""NOTRUN finite native OS Channel IO double; no production permission API.

Independent image/generated-source safety gates precede every fixed expression.
The frozen literal WAIT qualification module is NOT changed or reused as a grant.
"""
import base64
import importlib
import json
import math
import os
from pathlib import Path
import secrets
import select
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import time


RETAINED_ROOTS = []
UNKNOWN_SESSIONS = []
NATIVE_DIAGNOSTIC_BUDGET = 60.0

def _environment(root):
    return dict(PATH='/usr/bin:/bin', HOME=str(root), TMPDIR=str(root),
                LC_ALL='C', PYTHONDONTWRITEBYTECODE='1')


def _pairs(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise RuntimeError('duplicate private IPC key UNKNOWN')
        result[name] = value
    return result


def _line(fd, deadline):
    raw = bytearray()
    while b'\n' not in raw:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
            raise RuntimeError('private IPC deadline UNKNOWN')
        # One fixed frame at a time, no overread into the next RPC.
        part = os.read(fd, 1)
        if not part:
            raise RuntimeError('private IPC EOF UNKNOWN')
        raw.extend(part)
        if len(raw) > 8192:
            raise RuntimeError('private IPC frame exceeded UNKNOWN')
    return json.loads(raw, object_pairs_hook=_pairs)


def _frame(fd, value, deadline):
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')
    if len(raw) > 8192:
        raise RuntimeError('private IPC frame exceeded UNKNOWN')
    position = 0
    while position < len(raw):
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([], [fd], [], remaining)[1]:
            raise RuntimeError('private IPC write deadline UNKNOWN')
        count = os.write(fd, raw[position:])
        if count <= 0:
            raise RuntimeError('private IPC short write UNKNOWN')
        position += count


def _facts(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def _root_check(root, expected):
    if (root.resolve() != root or root.parent != Path('/private/tmp')
            or not root.name.startswith('native-os-bridge-owned-')):
        raise RuntimeError('native OS own root refused UNKNOWN')
    for name, path in (('root', root), ('switch', root / 'switch')):
        value = path.lstat()
        if (path.resolve() != path or not stat.S_ISDIR(value.st_mode)
                or stat.S_IMODE(value.st_mode) != 0o700 or value.st_uid != os.geteuid()
                or list(_facts(value)) != expected[name]):
            raise RuntimeError('native OS actual directory identity changed UNKNOWN')


def _checked_command(image, root, role, command, *, cold):
    if str(image) not in sys.path:
        sys.path.insert(0, str(image))
    for name in ('native_os_safe_image', 'native_cpld_safe_image',
                 'native_cpld_physical_io', 'native_os_stub_sources'):
        module = importlib.import_module('test_cases.' + name)
        path = Path(module.__file__).resolve()
        expected = image / 'test_cases' / (name + '.py')
        if (cold and path != expected) or path.read_bytes() != expected.read_bytes():
            raise RuntimeError('native OS fixed IO gate dependency differs')
    safe = importlib.import_module('test_cases.native_os_safe_image')
    words = shlex.split(command)
    actual_role = safe.require_safe_command(image, words, root)
    if actual_role != role:
        raise RuntimeError('native OS fixed expression role differs')
    return words


def _relay(nonce, data_fd, output_fd, error_fd, terminal_fd):
    """Real process: multiplex raw input/output, then exit actual expression rc."""
    owned = {data_fd, output_fd, error_fd, terminal_fd}
    for descriptor in (0, 1, 2, *owned):
        os.set_blocking(descriptor, False)
    deadline = time.monotonic() + NATIVE_DIAGNOSTIC_BUDGET
    incoming, output, error, terminal = bytearray(), bytearray(), bytearray(), bytearray()
    input_eof = output_eof = error_eof = terminal_eof = False
    data_closed = False
    status = None
    total_input = total_output = 0
    try:
        while True:
            if input_eof and not incoming and not data_closed:
                owned.remove(data_fd); data_closed = True; os.close(data_fd)
            if terminal_eof and status is None:
                if len(terminal) > 1024 or terminal.count(b'\n') != 1 or not terminal.endswith(b'\n'):
                    raise RuntimeError('actual terminal frame absent UNKNOWN')
                value = json.loads(terminal, object_pairs_hook=_pairs)
                if (type(value) is not dict or set(value) != {'nonce', 'status'}
                        or value['nonce'] != nonce or type(value['status']) is not int
                        or not 0 <= value['status'] <= 255):
                    raise RuntimeError('actual terminal frame refused UNKNOWN')
                status = value['status']
            if status is not None and output_eof and error_eof and not output and not error:
                return status
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError('relay qualification deadline UNKNOWN')
            reads, writes = [], []
            if not input_eof and not data_closed and len(incoming) < 65537:
                reads.append(0)
            if not output_eof and len(output) < 131072:
                reads.append(output_fd)
            if not error_eof and len(error) < 131072:
                reads.append(error_fd)
            if not terminal_eof:
                reads.append(terminal_fd)
            if incoming and not data_closed:
                writes.append(data_fd)
            if output:
                writes.append(1)
            if error:
                writes.append(2)
            ready, writable, _ = select.select(reads, writes, [], remaining)
            if not ready and not writable:
                raise RuntimeError('relay stalled UNKNOWN')
            for descriptor in ready:
                try:
                    raw = os.read(descriptor, 4096)
                except BlockingIOError:
                    continue
                if descriptor == 0:
                    if not raw:
                        input_eof = True
                    else:
                        total_input += len(raw)
                        if total_input > 65537:
                            raise RuntimeError('qualification input exceeded UNKNOWN')
                        incoming.extend(raw)
                elif descriptor == output_fd:
                    if not raw: output_eof = True
                    else: output.extend(raw); total_output += len(raw)
                elif descriptor == error_fd:
                    if not raw: error_eof = True
                    else: error.extend(raw); total_output += len(raw)
                else:
                    if not raw: terminal_eof = True
                    else: terminal.extend(raw)
                    if len(terminal) > 1024:
                        raise RuntimeError('actual terminal frame exceeded UNKNOWN')
                if total_output > 262144:
                    raise RuntimeError('qualification output exceeded UNKNOWN')
            for descriptor in writable:
                pending = incoming if descriptor == data_fd else output if descriptor == 1 else error
                try:
                    count = os.write(descriptor, pending)
                except BlockingIOError:
                    continue
                if count <= 0:
                    raise RuntimeError('raw relay short write UNKNOWN')
                del pending[:count]
    finally:
        # Remove before attempting close: uncertain numeric slots are not retried.
        for descriptor in tuple(owned):
            owned.remove(descriptor)
            os.close(descriptor)


def _signal_original(child, children, selected):
    if (not any(child is item for item in children) or type(child) is not subprocess.Popen
            or child.poll() is not None or os.getpgid(child.pid) != child.pid):
        raise RuntimeError('no live original private leader UNKNOWN')
    os.killpg(child.pid, selected)


def _finish_children(children, *, cancel, deadline):
    codes, absent, closed = [], True, True
    unknown = False
    for child in children:
        if child.poll() is None:
            if cancel:
                _signal_original(child, children, signal.SIGTERM)
            else:
                try:
                    child.wait(timeout=max(.001, deadline - time.monotonic() - 4))
                except subprocess.TimeoutExpired:
                    unknown = True
                    _signal_original(child, children, signal.SIGTERM)
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                _signal_original(child, children, signal.SIGKILL)
                child.wait(timeout=2)
        codes.append(child.wait(timeout=.1))
        for stream in (child.stdin, child.stdout, child.stderr):
            if stream is not None and not stream.closed:
                stream.close()
            closed = closed and (stream is None or stream.closed)
        # Read-only observation of this exact known group. Never signal after
        # original leader exited, even if descendants remain: then UNKNOWN.
        gone = False
        until = min(deadline, time.monotonic() + 1)
        while time.monotonic() < until:
            try:
                os.killpg(child.pid, 0)
            except ProcessLookupError:
                gone = True; break
            time.sleep(.01)
        absent = absent and gone
    return dict(runner_returncodes=codes, groups_absent=absent,
        runner_streams_closed=closed, unknown=unknown or not absent)


def _coordinate(image, root, role, nonce, command, root_facts, control_fd, reply_fd, terminal_fd):
    deadline = time.monotonic() + NATIVE_DIAGNOSTIC_BUDGET
    children, failures, constructor_shapes, standard_rows = [], [], [], []
    status, expression_finished, finalized = 70, False, False
    constructor = subprocess.Popen.__init__
    words = None
    if sys.getprofile() is not None:
        raise RuntimeError('existing profile refused')

    def observe(frame, event, result):
        if (event == 'return' and frame.f_code is constructor.__code__
                and frame.f_globals is constructor.__globals__):
            child = frame.f_locals.get('self')
            if (type(child) is subprocess.Popen and type(getattr(child, 'pid', None)) is int
                    and not any(child is item for item in children)):
                children.append(child)  # Passive original constructor observation.
                values = frame.f_locals
                constructor_shapes.append(
                    values.get('args') == ['/bin/bash', '-p', str(Path(words[3]).parent / 'runner.sh')]
                    and values.get('env') == {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'TMPDIR': str(Path(words[3]).parent)}
                    and values.get('stdin') == subprocess.PIPE
                    and values.get('close_fds') is True
                    and values.get('start_new_session') is True
                    and values.get('cwd') == str(Path(words[3]).parent))

    receipt = dict(unknown=True)
    try:
        _root_check(root, root_facts)
        # Retain original actual Popen standard pipes BEFORE fixed expression
        # execution; never adopt a slot first observed after expression return.
        for expected_fd, stream in enumerate((sys.stdin, sys.stdout, sys.stderr)):
            descriptor = stream.fileno()
            raw = stream.buffer.raw
            info = os.fstat(descriptor)
            if (descriptor != expected_fd or raw.fileno() != descriptor
                    or raw.closefd is not False or not stat.S_ISFIFO(info.st_mode)):
                raise RuntimeError('original standard pipe owner UNKNOWN')
            standard_rows.append([descriptor, stream, raw,
                (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)), False])
        words = _checked_command(image, root, role, command, cold=True)
        sys.argv = ['-c', *words[3:]]
        sys.setprofile(observe)
        try:
            exec(compile(words[2], '<actual-reviewed-fixed-expression>', 'exec'), {'__name__': '__main__'})
            status = 0
        except SystemExit as caught:
            status = caught.code if type(caught.code) is int else 0 if caught.code is None else 2
        except KeyboardInterrupt:
            status = 130
        except BaseException as caught:
            failures.append(type(caught).__name__); status = 70
        finally:
            sys.setprofile(None)
        if not 0 <= status <= 255:
            raise RuntimeError('actual expression status outside byte range UNKNOWN')
        # CPython's original standard FileIO uses closefd=False. Closing its
        # wrapper alone is NOT real pipe EOF. Hold all known original pipe keys
        # before any wrapper close, then explicitly close each numeric slot ONCE.
        standard_failure = None
        def remember_standard(caught):
            nonlocal standard_failure
            if (standard_failure is None or isinstance(standard_failure, Exception)
                    and not isinstance(caught, Exception)):
                standard_failure = caught  # First NI object/cause wins tail errors.
        for row in standard_rows:
            descriptor, stream, raw, original, attempted = row
            try:
                info = os.fstat(descriptor)
                if ((sys.stdin, sys.stdout, sys.stderr)[descriptor] is not stream
                        or stream.buffer.raw is not raw or stream.fileno() != descriptor
                        or (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)) != original):
                    raise RuntimeError('original standard pipe owner changed UNKNOWN')
            except BaseException as caught:
                remember_standard(caught)
                continue  # Unknown slot is never adopted or closed; other known slots continue.
            try:
                stream.flush()
                stream.close()
            except BaseException as caught:
                remember_standard(caught)
            try:
                info = os.fstat(descriptor)
                if (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)) != original:
                    raise RuntimeError('original standard pipe slot changed UNKNOWN')
                row[4] = True  # Before actual close; never retry an uncertain slot.
                os.close(descriptor)
            except BaseException as caught:
                remember_standard(caught)
        if standard_failure is not None:
            raise standard_failure
        _frame(terminal_fd, dict(nonce=nonce, status=status), deadline)
        os.close(terminal_fd); terminal_fd = None
        expression_finished = True
        while True:
            message = _line(control_fd, deadline)
            if (type(message) is not dict or set(message) != {'nonce', 'op'}
                    or message['nonce'] != nonce
                    or message['op'] not in ('STATE', 'FINISH', 'CANCEL')):
                raise RuntimeError('fixed coordinator RPC refused UNKNOWN')
            operation = message['op']
            _root_check(root, root_facts)
            if operation == 'STATE':
                # Returning current Popen.poll is not a permission or status-file inference.
                value = dict(returncodes=[child.poll() for child in children])
            else:
                cancelled_live = operation == 'CANCEL' and any(child.poll() is None for child in children)
                receipt = _finish_children(children, cancel=operation == 'CANCEL', deadline=deadline)
                receipt.update(cancelled=cancelled_live, business_outcome=(
                    'UNKNOWN_TEST_OWNER_CANCELLED' if cancelled_live else 'ACTUAL_RUNNER_OBSERVED_ONLY'))
                finalized = True
                receipt.update(expression_status=status, expression_finished=expression_finished,
                    original_popen_count=len(children), original_popen_shape=all(constructor_shapes),
                    failures=failures, unknown=receipt['unknown'] or bool(failures) or not all(constructor_shapes))
                value = receipt
            _frame(reply_fd, dict(nonce=nonce, op=operation, value=value), deadline)
            if operation in ('FINISH', 'CANCEL'):
                break
        return 1 if receipt['unknown'] else 0
    except BaseException as caught:
        failures.append(type(caught).__name__)
        return 1
    finally:
        sys.setprofile(None)
        if not finalized:
            try:
                _finish_children(children, cancel=True, deadline=deadline)
            except BaseException:
                pass  # Exit remains failure; no false clean proof or numeric rescue.
        for descriptor in (terminal_fd, control_fd, reply_fd):
            if descriptor is not None:
                os.close(descriptor)


class _Channel:
    def __init__(self, owner, process):
        self.owner, self.process = owner, process
        self.out_eof = self.err_eof = False
        self.close_attempted, self.close_error = False, None
        self.deadline = owner.deadline
        os.set_blocking(process.stdin.fileno(), False)

    def settimeout(self, seconds):
        if type(seconds) not in (int, float) or not math.isfinite(seconds) or seconds <= 0:
            raise ValueError('finite positive SDK timeout required')
        self.deadline = min(self.deadline, time.monotonic() + seconds)

    def send(self, value):
        if type(value) is not bytes or not value:
            raise ValueError('nonempty raw bytes required')
        descriptor = self.process.stdin.fileno()
        # Existing source sender requires count>0. EAGAIN waits only this exact
        # pipe; the independent relay still drains all other directions.
        while True:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0 or not select.select([], [descriptor], [], remaining)[1]:
                raise RuntimeError('original relay stdin deadline UNKNOWN')
            try:
                count = os.write(descriptor, value[:7])
            except BlockingIOError:
                continue
            if count <= 0:
                raise RuntimeError('original relay stdin short write UNKNOWN')
            return count

    def sendall(self, value):
        raise RuntimeError('partial original send required')

    def shutdown_write(self):
        self.process.stdin.close()

    def recv_ready(self):
        return not self.out_eof and bool(select.select([self.process.stdout], [], [], 0)[0])

    def recv_stderr_ready(self):
        return not self.err_eof and bool(select.select([self.process.stderr], [], [], 0)[0])

    def recv(self, size):
        raw = os.read(self.process.stdout.fileno(), size)
        if not raw: self.out_eof = True
        return raw

    def recv_stderr(self, size):
        raw = os.read(self.process.stderr.fileno(), size)
        if not raw: self.err_eof = True
        return raw

    def exit_status_ready(self):
        return self.process.poll() is not None

    def recv_exit_status(self):
        return self.process.wait(timeout=max(.001, self.deadline - time.monotonic()))

    @property
    def eof_received(self):
        return self.out_eof and self.err_eof

    @property
    def closed(self):
        return self.close_attempted or (self.exit_status_ready() and self.eof_received)

    def close(self):
        if self.close_attempted:
            if self.close_error is not None: raise self.close_error
            return
        self.close_attempted = True
        try:
            if not self.process.stdin.closed:
                self.process.stdin.close()
            self.process.wait(timeout=max(.001, self.deadline - time.monotonic()))
            for stream in (self.process.stdout, self.process.stderr):
                stream.close()
        except BaseException as caught:
            self.close_error = caught
            raise
        # Deliberately no coordinator wait, runner wait, gate, signal or ACK.


class _Session:
    def __init__(self, image, root, role):
        if role not in ('probe', 'native-os-launcher'):
            raise ValueError('fixed native OS IO role required')
        self.image, self.role = Path(image).resolve(), role
        self.root = Path(root)
        self.root_facts = {'root': list(_facts(self.root.lstat())),
                           'switch': list(_facts((self.root / 'switch').lstat()))}
        _root_check(self.root, self.root_facts)
        RETAINED_ROOTS.append(str(self.root))
        self.nonce = secrets.token_hex(16)
        self.deadline = time.monotonic() + NATIVE_DIAGNOSTIC_BUDGET
        self.fds, self.coordinator, self.relay, self.channel, self.receipt = set(), None, None, None, None

    def __enter__(self):
        return self

    def _pipe(self):
        ends = os.pipe()
        self.fds.update(ends)
        return ends

    def _close(self, descriptor):
        if descriptor in self.fds:
            self.fds.remove(descriptor)
            os.close(descriptor)

    def start(self, command):
        if self.coordinator is not None or self.channel is not None:
            raise RuntimeError('one original wire per qualification owner')
        _root_check(self.root, self.root_facts)
        _checked_command(self.image, self.root, self.role, command, cold=False)
        data_r, data_w = self._pipe()
        out_r, out_w = self._pipe()
        err_r, err_w = self._pipe()
        terminal_r, terminal_w = self._pipe()
        control_r, self.control_w = self._pipe()
        self.reply_r, reply_w = self._pipe()
        helper = str(Path(__file__).resolve())
        try:
            args = [sys.executable, '-B', helper, '--coordinate', str(self.image), str(self.root),
                self.role, self.nonce, command, json.dumps(self.root_facts),
                str(control_r), str(reply_w), str(terminal_w)]
            self.coordinator = subprocess.Popen(args, cwd=self.root, env=_environment(self.root),
                stdin=data_r, stdout=out_w, stderr=err_w, close_fds=True,
                pass_fds=(control_r, reply_w, terminal_w))
            for descriptor in (data_r, out_w, err_w, control_r, reply_w, terminal_w):
                self._close(descriptor)
            self.relay = subprocess.Popen([sys.executable, '-B', helper, '--relay', self.nonce,
                str(data_w), str(out_r), str(err_r), str(terminal_r)], cwd=self.root,
                env=_environment(self.root), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, close_fds=True, pass_fds=(data_w, out_r, err_r, terminal_r))
            self.channel = _Channel(self, self.relay)
            for descriptor in (data_w, out_r, err_r, terminal_r):
                self._close(descriptor)
            return self.channel
        except BaseException:
            UNKNOWN_SESSIONS.append(self)
            # Let exact source fd0 see EOF on handoff failure. Original handles
            # remain owned by this session and __exit__ attempts bounded cleanup.
            for descriptor in tuple(self.fds):
                if descriptor not in (getattr(self, 'control_w', None), getattr(self, 'reply_r', None)):
                    try: self._close(descriptor)
                    except BaseException: pass
            raise

    def _rpc(self, operation):
        if self.coordinator is None:
            raise RuntimeError('original coordinator absent UNKNOWN')
        _frame(self.control_w, dict(nonce=self.nonce, op=operation), self.deadline)
        message = _line(self.reply_r, self.deadline)
        if (type(message) is not dict or set(message) != {'nonce', 'op', 'value'}
                or message['nonce'] != self.nonce or message['op'] != operation):
            raise RuntimeError('original coordinator reply UNKNOWN')
        return message['value']

    def original_runner_state(self):
        if (self.channel is None or not self.channel.close_attempted
                or self.channel.close_error is not None or self.channel.process.poll() is None):
            raise RuntimeError('original wire not complete')
        return self._rpc('STATE')

    def finish_originals(self, *, cancel=False):
        if self.receipt is not None:
            if self.receipt['unknown']: raise RuntimeError('sticky original cleanup UNKNOWN')
            return self.receipt
        value = self._rpc('CANCEL' if cancel else 'FINISH')
        code = self.coordinator.wait(timeout=max(.001, self.deadline - time.monotonic()))
        if (type(value) is not dict or code != 0 or value.get('unknown') is not False
                or value.get('expression_finished') is not True):
            raise RuntimeError('original coordinator/runner cleanup UNKNOWN')
        value['all_original_streams_closed'] = False  # Only __exit__ may set True.
        self.receipt = value
        return value

    def _drain_relay(self):
        # Cleanup never uses communicate() after an already closed stdin (which
        # can itself raise a flush-of-closed-file fixture error). Drain only the
        # original retained process streams; secret/raw bytes are not recorded.
        process = self.relay
        if process is None:
            return
        if not process.stdin.closed:
            process.stdin.close()
        active = [stream for stream in (process.stdout, process.stderr) if not stream.closed]
        while active:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError('owned relay cleanup deadline UNKNOWN')
            ready, _, _ = select.select(active, [], [], remaining)
            if not ready:
                raise RuntimeError('owned relay cleanup stalled UNKNOWN')
            for stream in ready:
                if not os.read(stream.fileno(), 65536):
                    active.remove(stream)
        process.wait(timeout=max(.001, self.deadline - time.monotonic()))

    def __exit__(self, kind, error, traceback):
        cleanup = None
        try:
            if self.coordinator is not None and self.receipt is None:
                if self.relay is not None:
                    # Drain actual wire independently; do not wait coordinator first.
                    self._drain_relay()
                    if self.channel is not None:
                        self.channel.close()
                self.finish_originals(cancel=True)
        except BaseException as caught:
            cleanup = caught
        finally:
            for descriptor in tuple(self.fds):
                try: self._close(descriptor)
                except BaseException as caught: cleanup = cleanup or caught
            streams = []
            for process in (self.coordinator, self.relay):
                if process is not None:
                    streams.extend((process.stdin, process.stdout, process.stderr))
            for stream in streams:
                if stream is not None and not stream.closed:
                    try: stream.close()
                    except BaseException as caught: cleanup = cleanup or caught
            if self.receipt is not None:
                self.receipt['all_original_streams_closed'] = (cleanup is None and not self.fds
                    and self.receipt['runner_streams_closed']
                    and all(stream is None or stream.closed for stream in streams))
        if cleanup is not None:
            if not any(self is item for item in UNKNOWN_SESSIONS): UNKNOWN_SESSIONS.append(self)
            if error is None: raise cleanup
            sys.stderr.write('FIXTURE_DUAL_CLEANUP_UNKNOWN=' + type(cleanup).__name__
                             + ' ROOT=' + str(self.root) + '\n')
        return False


def native_os_expression_session(image, root, *, role):
    return _Session(image, root, role)


if __name__ == '__main__':
    if len(sys.argv) == 7 and sys.argv[1] == '--relay':
        try:
            result = _relay(sys.argv[2], *map(int, sys.argv[3:]))
        except BaseException:
            result = 70  # No exception text/raw secret is printed by relay.
        raise SystemExit(result)
    if len(sys.argv) == 11 and sys.argv[1] == '--coordinate':
        raise SystemExit(_coordinate(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4],
            sys.argv[5], sys.argv[6], json.loads(sys.argv[7]), *map(int, sys.argv[8:])))
    raise SystemExit('fixed qualification role only')
