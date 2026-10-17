"""Fixed bounded command boundary for the backup collector.

Only the fixed sibling launcher is spawned. The real argv/env travel over an
original private request pipe, never launcher argv/log/repr. This is not a
sandbox or a proof against external waiters/descriptor writers.
"""
from __future__ import annotations

from dataclasses import dataclass
import errno
import json
import math
import os
from pathlib import Path
import secrets
import selectors
import signal
import stat
import struct
import subprocess
import sys
import time


_Popen = subprocess.Popen
LAUNCHER = Path(__file__).with_name("_bounded_process_launcher.py")
REQUEST_LIMIT = 1048576
OUTPUT_LIMIT = 65536
FRAME = struct.Struct("!4s16sII")
_SPAWN_TOKEN = object()


class AnchorUnknown(ValueError):
    pass


def pack_request(argv, env):
    if not isinstance(argv, (list, tuple)) or not argv or not argv[0] or any(
            not isinstance(item, str) or "\0" in item for item in argv):
        raise ValueError("invalid command argv")
    if env is not None and not isinstance(env, dict):
        raise ValueError("invalid command environment")
    actual = dict(os.environ) if env is None else dict(env)
    if any(not isinstance(k, str) or not isinstance(v, str)
           or not k or "=" in k or "\0" in k or "\0" in v
           for k, v in actual.items()):
        raise ValueError("invalid command environment")
    value = {"argv": list(argv), "env": actual,
             "env_mode": "INHERITED_SNAPSHOT" if env is None else "EXPLICIT"}
    payload = json.dumps(value, ensure_ascii=True, sort_keys=True,
                         separators=(",", ":")).encode("ascii")
    if not 0 < len(payload) <= REQUEST_LIMIT:
        raise ValueError("request exceeds fixed bound")
    return len(payload).to_bytes(4, "big") + payload


def parse_status(raw, nonce):
    if not isinstance(nonce, bytes) or len(nonce) != 16 or len(raw) != FRAME.size:
        raise ValueError("incomplete or trailing status frame")
    magic, actual_nonce, pid, status = FRAME.unpack(raw)
    if (magic != b"HAP1" or actual_nonce != nonce or pid <= 0
            or status > 65535 or not (os.WIFEXITED(status) or os.WIFSIGNALED(status))):
        raise ValueError("invalid original command status")
    # PID here is diagnostic data only, never a wait/signal permission.
    return {"command_pid": pid, "wait_status": status,
            "returncode": os.waitstatus_to_exitcode(status)}


class DrainState:
    def __init__(self, nonce):
        self.nonce = nonce
        self.stdout = bytearray()
        self.stderr = bytearray()
        self.status_bytes = bytearray()
        self.eof = set()
        self.command_status = None
        self.stop_reason = None

    @property
    def output_EOF(self):
        return {"stdout", "stderr"} <= self.eof

    @property
    def command_exited(self):
        return self.command_status is not None

    def feed(self, role, chunk):
        if role not in {"stdout", "stderr", "status"} or not isinstance(chunk, bytes):
            raise ValueError("unknown stream role")
        if not chunk:
            self.eof.add(role)
            if role == "status" and self.command_status is None:
                raise AnchorUnknown("status EOF without original command result")
            return
        if role == "status":
            self.status_bytes.extend(chunk)
            if len(self.status_bytes) > FRAME.size:
                raise ValueError("duplicate or trailing status")
            if len(self.status_bytes) == FRAME.size:
                self.command_status = parse_status(bytes(self.status_bytes), self.nonce)
        else:
            retained = self.stdout if role == "stdout" else self.stderr
            available = OUTPUT_LIMIT - len(retained)
            retained.extend(chunk[:available])
            if len(chunk) > available:
                self.stop_reason = "overflow"


def outer_kwargs(request_read, status_write, stdin_text):
    return dict(stdin=subprocess.DEVNULL if stdin_text is None else subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                start_new_session=True, close_fds=True,
                pass_fds=(request_read, status_write))


class CleanupLog:
    def __init__(self):
        self.errors = []
        self.first_NI = None
        self.capture_incomplete = False
        self.unrecorded_error = None
        self.capture_error = None
        self.residues = []
        self.fd_events = []

    def fd_event(self, phase, state, fd):
        try:
            self.fd_events.append((phase, state, fd))
        except BaseException as error:
            self.record("record_" + phase, error)

    def record(self, phase, error):
        if not isinstance(error, Exception) and self.first_NI is None:
            self.first_NI = error
        try:
            self.errors.append((phase, error))
        except BaseException as capture:
            self.capture_incomplete = True
            self.unrecorded_error = error
            self.capture_error = capture
            if not isinstance(capture, Exception) and self.first_NI is None:
                self.first_NI = capture


class Reservation:
    def __init__(self, process, *, _token=None):
        if _token is not _SPAWN_TOKEN:
            raise AnchorUnknown("reservation requires original spawn boundary")
        self.process = process
        self.pid = getattr(process, "pid", None)
        self.signal_attempted = False
        self.wait_started = False
        self.reaped = False
        self.lost = False
        if (type(process) is not _Popen or not getattr(process, "_child_created", False)
                or type(self.pid) is not int or self.pid <= 0
                or process.returncode is not None):
            self.lost = True
            raise AnchorUnknown("original successful spawn not held")

    def held(self):
        if (self.lost or self.reaped or self.wait_started
                or type(self.process) is not _Popen
                or self.process.pid != self.pid or self.process.returncode is not None):
            self.lost = True
            raise AnchorUnknown("original anchor reservation lost")


def signal_original_group(reservation):
    reservation.held()
    if reservation.signal_attempted:
        return
    # Mark BEFORE the syscall; an interrupted outcome is never retried as a
    # fresh permission. No poll/getpgid/numeric re-adoption/fallback kill.
    reservation.signal_attempted = True
    os.killpg(reservation.pid, signal.SIGKILL)


def wait_original_anchor(reservation, timeout=1):
    if reservation.lost or reservation.reaped or not reservation.signal_attempted:
        raise AnchorUnknown("wait outside original cleanup order")
    reservation.wait_started = True
    deadline = time.monotonic() + timeout
    while True:
        try:
            pid, status = os.waitpid(reservation.pid, os.WNOHANG)
        except ChildProcessError:
            reservation.lost = True
            raise  # Never inherit Popen's ECHILD -> fabricated status0.
        if pid == reservation.pid:
            reservation.reaped = True
            reservation.process.returncode = os.waitstatus_to_exitcode(status)
            return reservation.process.returncode
        if pid != 0:
            reservation.lost = True
            raise AnchorUnknown("unexpected wait result")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired("original launcher wait", timeout)
        time.sleep(min(0.01, remaining))


def _identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode,
            metadata.st_uid, metadata.st_gid)


def _close_fd(hold, log, phase):
    if hold[2]:
        return
    fd, original, _closed = hold
    if original is None or _identity(os.fstat(fd)) != original:
        log.residues.append(hold)
        log.fd_event(phase, "UNKNOWN_NOT_CLOSED", fd)
        raise AnchorUnknown("unknown descriptor not closed")
    log.fd_event(phase, "CLOSE_ATTEMPT", fd)
    os.close(fd)
    hold[2] = True
    log.fd_event(phase, "CLOSE_RETURN", fd)


def _close_stream(stream, original, log):
    if stream.closed:
        return
    if original is None or _identity(os.fstat(stream.fileno())) != original:
        log.residues.append(stream)
        raise AnchorUnknown("unknown stream descriptor not closed")
    stream.close()


def finish(reservation, primary, log, fd_holds, streams):
    if reservation is not None:
        try:
            signal_original_group(reservation)
        except BaseException as error:
            log.record("group", error)
        if not reservation.lost:
            try:
                wait_original_anchor(reservation, timeout=1)
            except BaseException as error:
                log.record("anchor_wait", error)
    for phase, hold in fd_holds:
        try:
            _close_fd(hold, log, phase)
        except BaseException as error:
            log.record(phase, error)
    for phase, stream, original in streams:
        try:
            _close_stream(stream, original, log)
        except BaseException as error:
            log.record(phase, error)
    chosen = (primary if primary is not None and not isinstance(primary, Exception)
              else log.first_NI or primary or (log.errors[0][1] if log.errors else None))
    if chosen is not None:
        try:
            chosen.anchor_cleanup_errors = (None if log.capture_incomplete
                                            else tuple(log.errors))
            chosen.anchor_cleanup_capture = ("NOT_CAPTURED" if log.capture_incomplete
                                             else "CAPTURED")
            chosen.anchor_protocol_fd_events = tuple(log.fd_events)
        except BaseException as error:
            log.record("attach_diagnostics", error)
            # Attachment inability is NOT_CAPTURED. Preserve original NI;
            # an ordinary primary still yields to the first new cleanup NI.
            if isinstance(chosen, Exception) and log.first_NI is not None:
                chosen = log.first_NI
        raise chosen


def effective_returncode(command_status, stop_reason):
    if stop_reason == "timeout":
        return 124
    if stop_reason == "overflow":
        return 125
    if command_status is None:
        raise AnchorUnknown("no original command result")
    return command_status["returncode"]


def _drive(process, reservation, request_write, status_read, request,
           stdin_text, deadline, state, log):
    selector = selectors.DefaultSelector()
    primary = None
    request_view = memoryview(request)
    input_view = memoryview(b"" if stdin_text is None else stdin_text.encode("utf-8"))
    streams = [(process.stdout.fileno(), "stdout"),
               (process.stderr.fileno(), "stderr"),
               (status_read, "status"), (request_write, "request")]
    if process.stdin is not None:
        streams.append((process.stdin.fileno(), "stdin"))
    try:
        for fd, role in streams:
            os.set_blocking(fd, False)
            selector.register(fd, selectors.EVENT_WRITE if role in {"request", "stdin"}
                              else selectors.EVENT_READ, role)
        while True:
            if state.command_exited and state.command_status["command_pid"] == reservation.pid:
                raise AnchorUnknown("status describes anchor instead of real command")
            # A real leader status does not mean descendant-held pipes ended.
            # Preserve original drain/deadline semantics: wait for both output
            # EOFs, otherwise report timeout124, THEN cleanup original group.
            if state.stop_reason:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                state.stop_reason = "timeout"
                break
            if state.command_exited and state.output_EOF:
                break
            for event, _mask in selector.select(min(0.1, remaining)):
                fd, role = event.fd, event.data
                if role in {"request", "stdin"}:
                    view = request_view if role == "request" else input_view
                    try:
                        written = os.write(fd, view[:4096]) if view else 0
                    except BlockingIOError:
                        continue
                    except BrokenPipeError:
                        if role == "request":
                            raise AnchorUnknown("launcher lost during request transfer")
                        written = len(view)
                    view = view[written:]
                    if role == "request":
                        request_view = view
                    else:
                        input_view = view
                    if not view:
                        selector.unregister(fd)
                        if role == "stdin":
                            process.stdin.close()
                        # Keep request writer open as the original lifetime end.
                else:
                    try:
                        chunk = os.read(fd, 8192 if role != "status" else 64)
                    except BlockingIOError:
                        continue
                    # A selected EOF may arrive exactly when the original
                    # deadline expires. Preserve earlier stop reasons and do
                    # not let no-frame EOF replace timeout124 with UNKNOWN.
                    if state.stop_reason:
                        break
                    if (role == "status" and not chunk
                            and state.command_status is None
                            and time.monotonic() >= deadline):
                        state.stop_reason = "timeout"
                        break
                    state.feed(role, chunk)
                    if not chunk:
                        selector.unregister(fd)
    except BaseException as error:
        primary = error
    finally:
        try:
            selector.close()
        except BaseException as error:
            log.record("selector", error)
    if primary is not None:
        raise primary


@dataclass(frozen=True)
class AnchoredObservation:
    stdout: bytes
    stderr: bytes
    command_status: dict | None
    anchor_returncode: int | None
    returncode: int
    stop_reason: str | None
    protocol_fd_events: tuple
    protocol_fd_counts: tuple


def run_bounded_anchored(argv, timeout, env=None, stdin_text=None):
    """Run one command with separate true status and held original group anchor.

    Requires SIGCHLD default, no competing waiters/reapers for this child,
    no concurrent FD replacement and reviewed exact Python/launcher sources.
    These checks cannot prove arbitrary native threads never wait elsewhere.
    """
    # Read only, also valid from the existing ten worker threads. No new
    # signal handler, preexec_fn, global environment or shared status slot.
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        raise AnchorUnknown("unsupported signal/reaper context")
    request = pack_request(argv, env)
    if (type(timeout) not in {int, float} or not math.isfinite(timeout)
            or timeout <= 0):
        raise ValueError("invalid original timeout")
    deadline = time.monotonic() + timeout
    nonce = secrets.token_bytes(16)
    log = CleanupLog()
    holds = []
    streams = []
    reservation = None
    process = None
    state = DrainState(nonce)
    primary = None
    try:
        for prefix in ("request", "status"):
            ends = os.pipe()
            for suffix, fd in zip(("read", "write"), ends):
                hold = [fd, None, False]
                holds.append((prefix + "_" + suffix, hold))
            for _phase, hold in holds[-2:]:
                fd = hold[0]
                hold[1] = _identity(os.fstat(fd))
                os.set_inheritable(fd, False)
        rr, rw, sr, sw = [hold[0] for _phase, hold in holds]
        process = _Popen.__new__(_Popen)
        # Strong reference exists before __init__. No partial-init PID adoption.
        process.__init__([sys.executable, "-I", "-B", str(LAUNCHER), str(rr),
                          str(sw), nonce.hex(), str(deadline)],
                         **outer_kwargs(rr, sw, stdin_text))
        reservation = Reservation(process, _token=_SPAWN_TOKEN)
        stream_capture_error = None
        for role in ("stdin", "stdout", "stderr"):
            stream = getattr(process, role, None)
            if stream is not None:
                slot = [role, stream, None]
                streams.append(slot)
                try:
                    slot[2] = _identity(os.fstat(stream.fileno()))
                except BaseException as error:
                    log.record("capture_" + role, error)
                    if (stream_capture_error is None or
                            isinstance(stream_capture_error, Exception)
                            and not isinstance(error, Exception)):
                        stream_capture_error = error
        if stream_capture_error is not None:
            raise stream_capture_error
        _close_fd(holds[0][1], log, "request_read")
        _close_fd(holds[3][1], log, "status_write")
        _drive(process, reservation, rw, sr, request, stdin_text, deadline, state, log)
    except BaseException as error:
        primary = error
        if process is not None and reservation is None:
            log.record("partial_spawn_UNKNOWN", AnchorUnknown("spawn was not admitted"))
            log.residues.append(process)
    finish(reservation, primary, log, holds, streams)
    if reservation is None or not reservation.reaped or process.returncode != -signal.SIGKILL:
        raise AnchorUnknown("original launcher cleanup not confirmed")
    if log.capture_incomplete:
        raise AnchorUnknown("cleanup evidence NOT_CAPTURED")
    if len(holds) != 4 or not all(hold[2] for _phase, hold in holds):
        raise AnchorUnknown("protocol descriptor cleanup unknown")
    counts = (len(holds), sum(event[1] == "CLOSE_ATTEMPT" for event in log.fd_events),
              sum(event[1] == "CLOSE_RETURN" for event in log.fd_events),
              sum(event[1] == "UNKNOWN_NOT_CLOSED" for event in log.fd_events))
    return AnchoredObservation(bytes(state.stdout), bytes(state.stderr),
                               state.command_status, process.returncode,
                               effective_returncode(state.command_status, state.stop_reason),
                               state.stop_reason, tuple(log.fd_events), counts)
