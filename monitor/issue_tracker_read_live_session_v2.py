"""Fixed-read v2 retained process/pipe control; not a native launcher/permit.

The future fixed launcher must bind honest prelaunch time and argv/origins.
Python cannot promise interruption of arbitrary kernel calls or an external
reaper; unknown cleanup stays failure, never inferred termination.
"""
import copy
import math
import os
import selectors
import signal
import stat
import subprocess
import threading
import time
import weakref
from . import issue_tracker_read_live_protocol_v2 as codec

_POPEN = subprocess.Popen
_killpg = os.killpg
_USED = weakref.WeakKeyDictionary()
_GUARD = threading.Lock()


class SessionHold(ValueError):
    def __init__(self):
        super().__init__('fixed_read_v2_session_denied')



def _now():
    # Shared POSIX domain across parent and child, never a caller callback.
    try:
        value = time.clock_gettime(time.CLOCK_MONOTONIC)
    except Exception:
        raise SessionHold() from None
    if (type(value) not in (int, float) or not math.isfinite(value)
            or not 0 <= value < 1e15):
        raise SessionHold()
    return value

def _close_stream(stream):
    stream.close()


def _gone(process):
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return True
    except OSError:
        pass
    return False


def _owned(process):
    if process.returncode is not None:
        return False
    try:
        return (os.getpgid(process.pid) == os.getsid(process.pid) == process.pid
                and process.pid != os.getpgrp())
    except OSError:
        return False


def _identity(fd):
    value = os.fstat(fd)
    return value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode)


class _Session:
    def __init__(self, process, started, nonce):
        self.process, self.started, self.nonce = process, started, nonce
        self.streams = (process.stdin, process.stdout, process.stderr)
        self.slots = tuple((s, s.fileno(), _identity(s.fileno())) for s in self.streams)
        self.cv = threading.Condition()
        self.state, self.error = 'NEW', None
        self.consumed = self.request = self.check_pending = False
        self.check_serial = self.check_done = 0
        self.data = None
        self.digest = None
        self.expiry = None
        self.thread = None
        self._startup_aborted = False
        self._acquisition_returned = False

    def _start(self):
        # Caller retains cv until startup either returns or aborts. A thread
        # created just before start() raises cannot enter IO behind cleanup.
        try:
            self.thread = threading.Thread(target=self._pump, daemon=True)
            self.thread.start()
        except BaseException as error:
            self._startup_aborted = True
            self._finish(error, False, False, None)

    def _copy_ready(self, data, *, acquiring=False):
        try:
            value = copy.deepcopy(data)  # Never block pump by holding cv here.
        except BaseException as original:
            cleanup = None
            try:
                self.close()
            except BaseException as error:
                cleanup = error
            if not isinstance(original, Exception):
                raise original
            if cleanup is not None and not isinstance(cleanup, Exception):
                raise cleanup
            raise SessionHold() from None
        with self.cv:
            invalid = (self.state != 'READY' or _now() >= self.expiry
                       or acquiring and _now() >= self.started + 30)
            if not invalid and acquiring:
                self._acquisition_returned = True
        if invalid:
            try:
                self.close()
            except Exception:
                pass
            raise SessionHold()
        return value

    def _raise(self):
        if self.error is not None:
            raise self.error
        raise SessionHold()

    def read_once(self):
        with self.cv:
            if self.consumed or self.state != 'NEW':
                raise SessionHold()
            self.consumed = True
            self.state = 'ACQUIRING'
            self._start()
            while self.state in ('ACQUIRING', 'CLOSING'):
                self.cv.wait(0.05)
            if self.state != 'READY':
                self._raise()
            data = self.data
        return self._copy_ready(data, acquiring=True)

    def current_ready(self):
        with self.cv:
            if self.state != 'READY' or _now() >= self.expiry or self.check_pending:
                raise SessionHold()
            self.check_pending = True
            self.check_serial += 1
            serial = self.check_serial
            self.cv.notify_all()
            while self.state == 'READY' and self.check_done < serial:
                self.cv.wait(0.05)
            if self.state != 'READY' or _now() >= self.expiry:
                self._raise()
            data = self.data
        return self._copy_ready(data)

    def close(self):
        with self.cv:
            if self.state == 'CLOSED':
                return
            if self.state == 'NEW':
                self.consumed = True
                self.state = 'ACQUIRING'
                self.request = True
                self._start()
            elif self.state == 'FAILED':
                self._raise()
            else:
                self.request = True
            self.cv.notify_all()
            while self.state not in ('CLOSED', 'FAILED'):
                self.cv.wait(0.05)
            if self.state != 'CLOSED':
                self._raise()

    def _originals(self):
        if (self.process.stdin, self.process.stdout, self.process.stderr) != self.streams:
            raise SessionHold()
        for stream, fd, identity in self.slots:
            if stream.closed or stream.fileno() != fd or _identity(fd) != identity:
                raise SessionHold()

    def _stop(self, deadline):
        p = self.process
        for sig in (signal.SIGTERM, signal.SIGKILL):
            if p.poll() is not None:
                return _gone(p)
            if not _owned(p):
                # A just-exited retained child may be reaped, never signalled
                # by a new numeric identity after the ownership check failed.
                return p.poll() is not None and _gone(p)
            if _now() >= deadline:
                return False
            try:
                _killpg(p.pid, sig)
            except ProcessLookupError:
                pass
            except OSError:
                return False
            try:
                p.wait(timeout=max(0.001, min(0.15, deadline - _now())))
            except subprocess.TimeoutExpired:
                continue
            return _gone(p)
        return p.returncode is not None and _gone(p)

    def _pump(self):
        with self.cv:
            if self._startup_aborted:
                return
        selector = None
        primary = None
        closed_frame = False
        eof = set()
        output = bytearray()
        pending = bytearray()
        stdout_count = stderr_count = control_count = 0
        close_deadline = check_deadline = None
        terminal = False
        ready_candidate = None
        live_candidate = False
        try:
            self._originals()
            selector = selectors.DefaultSelector()
            for channel, stream in (('out', self.streams[1]), ('err', self.streams[2])):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, channel)
            os.set_blocking(self.streams[0].fileno(), False)
            while True:
                self._originals()
                now = _now()
                with self.cv:
                    if self.state == 'ACQUIRING' and (now >= self.started + 28 or self.request):
                        raise SessionHold()
                    # READY wire data does not end the original acquisition
                    # while the first caller copy/return is still pending.
                    acquisition_expired = not self._acquisition_returned and now >= self.started + 28
                    if self.state == 'READY' and (self.request or now >= self.expiry or acquisition_expired):
                        self.state = 'CLOSING'
                        close_deadline = now + 1.0
                        command = codec.encode_command(self.nonce, 'CLOSE')
                        control_count += len(command)
                        if control_count > codec.CONTROL_LIMIT:
                            raise SessionHold()
                        pending.extend(command)
                    elif self.state == 'READY' and self.check_pending and check_deadline is None:
                        check_deadline = self.expiry
                        command = codec.encode_command(self.nonce, 'CHECK', self.check_serial)
                        control_count += len(command)
                        if control_count > codec.CONTROL_LIMIT - codec.CONTROL_RESERVE:
                            raise SessionHold()
                        pending.extend(command)
                    if close_deadline is not None and now >= close_deadline:
                        raise SessionHold()
                    if check_deadline is not None and now >= check_deadline:
                        raise SessionHold()
                if pending:
                    try:
                        size = os.write(self.streams[0].fileno(), pending[:4096])
                        if size <= 0:
                            raise SessionHold()
                        del pending[:size]
                    except BlockingIOError:
                        pass
                for key, _mask in selector.select(0.01):
                    count = stdout_count if key.data == 'out' else stderr_count
                    limit = codec.READY_LIMIT + codec.CONTROL_LIMIT if key.data == 'out' else 65536
                    try:
                        chunk = os.read(key.fileobj.fileno(), min(65536, limit + 1 - count))
                    except BlockingIOError:
                        continue
                    if not chunk:
                        eof.add(key.data)
                        selector.unregister(key.fileobj)
                        continue
                    if key.data == 'err':
                        stderr_count += len(chunk)
                        if stderr_count > limit:
                            raise SessionHold()
                        continue  # Never retain or expose diagnostic bytes.
                    stdout_count += len(chunk)
                    if stdout_count > limit or closed_frame:
                        raise SessionHold()
                    output.extend(chunk)
                    while b'\n' in output:
                        if closed_frame:
                            raise SessionHold()
                        at = output.index(b'\n') + 1
                        frame = codec.decode_event(bytes(output[:at]), self.nonce)
                        event = frame['event']
                        if event != 'READY':
                            control_count += at
                            limit_control = (codec.CONTROL_LIMIT if event == 'CLOSED'
                                             else codec.CONTROL_LIMIT - codec.CONTROL_RESERVE)
                            if control_count > limit_control:
                                raise SessionHold()
                        del output[:at]
                        with self.cv:
                            if event == 'READY' and self.state == 'ACQUIRING' and ready_candidate is None:
                                receipt = _now()
                                if (receipt >= self.started + 28
                                        or not self.started <= frame['ready_at'] <= receipt
                                        or frame['expires_at'] <= receipt
                                        or not _owned(self.process) or self.process.poll() is not None):
                                    raise SessionHold()
                                ready_candidate = frame
                            elif (event == 'LIVE' and self.state == 'READY'
                                  and check_deadline is not None and not live_candidate
                                  and frame['serial'] == self.check_serial
                                  and frame['digest'] == self.digest):
                                live_candidate = True
                            elif event == 'CLOSED' and self.state == 'CLOSING':
                                closed_frame = True
                            else:
                                raise SessionHold()
                    # A partial control frame consumes bounded space too;
                    # do not wait for LF before enforcing its wire budget.
                    if self.state != 'ACQUIRING' or ready_candidate is not None:
                        if (len(output) > codec.CONTROL_FRAME_LIMIT
                                or control_count + len(output) > codec.CONTROL_LIMIT):
                            raise SessionHold()
                status = self.process.poll()
                if status is not None:
                    if status != 0 or not closed_frame:
                        raise SessionHold()
                    if eof == {'out', 'err'}:
                        if output or pending or not _gone(self.process):
                            raise SessionHold()
                        terminal = True
                        break
                elif ('out' in eof or self.state == 'ACQUIRING' and eof) and not (closed_frame and self.state == 'CLOSING'):
                    raise SessionHold()
                if ready_candidate is not None:
                    # Publish only after all already-read batch input and
                    # buffered bytes, EOF/exit, limits and final originals.
                    self._originals()
                    with self.cv:
                        if (output or pending or eof or status is not None
                                or self.request or _now() >= self.started + 28
                                or not _owned(self.process)):
                            raise SessionHold()
                        publication = _now()
                        self.expiry = min(ready_candidate['expires_at'], publication + 60.0)
                        if publication >= self.expiry:
                            raise SessionHold()
                        self.data = ready_candidate['data']
                        self.digest = ready_candidate['digest']
                        ready_candidate = None
                        self.state = 'READY'
                        self.cv.notify_all()
                if live_candidate:
                    self._originals()
                    with self.cv:
                        if (output or pending or status is not None or self.request
                                or self.state != 'READY' or _now() >= self.expiry
                                or not _owned(self.process)):
                            raise SessionHold()
                        live_candidate = False
                        self.check_pending = False
                        self.check_done = self.check_serial
                        check_deadline = None
                        self.cv.notify_all()
        except BaseException as error:
            primary = error
        finally:
            self._finish(primary, terminal, closed_frame, selector)

    def _finish(self, primary, terminal, closed_frame, selector):
        if isinstance(primary, Exception):
            primary = SessionHold()
        def remember(error):
            nonlocal primary
            if primary is None or isinstance(primary, Exception) and not isinstance(error, Exception):
                primary = error if not isinstance(error, Exception) else SessionHold()
        if not terminal:
            try:
                deadline = self.started + 30 if not self._acquisition_returned else _now() + 1.0
                terminal = self._stop(deadline)
            except BaseException as error:
                remember(error)
            if not terminal:
                remember(SessionHold())
        if selector is not None:
            try:
                selector.close()
            except BaseException as error:
                remember(error)
        for stream, fd, identity in self.slots:
            try:
                if not stream.closed:
                    if stream.fileno() != fd or _identity(fd) != identity:
                        raise SessionHold()  # No close of a rebound numeric FD.
                    _close_stream(stream)
                if not stream.closed:
                    raise SessionHold()
            except BaseException as error:
                remember(error)
        with self.cv:
            self.error = primary
            self.state = 'CLOSED' if primary is None and terminal and closed_frame else 'FAILED'
            self.cv.notify_all()


def adopt_owned_read_session(process, *, started_monotonic, nonce):
    now = _now()
    if (type(process) is not _POPEN or type(started_monotonic) not in (int, float)
            or not -1e300 <= started_monotonic <= now or not math.isfinite(started_monotonic)
            or not _owned(process)):
        raise SessionHold()
    codec.encode_command(nonce, 'CHECK', 1)
    if any(stream is None or stream.closed for stream in (process.stdin, process.stdout, process.stderr)):
        raise SessionHold()
    with _GUARD:
        if process in _USED:
            raise SessionHold()
        session = _Session(process, started_monotonic, nonce)
        _USED[process] = True
        return session
