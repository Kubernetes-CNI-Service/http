"""Uninstalled owned-process supervision primitive, not an online send entry.

The caller must launch its fixed audited worker in a fresh session, start the
clock BEFORE launch and arrange child inheritance of the held spreadsheet lock.
This helper neither launches a command nor accepts a PID or unlocks a lock. It
does not establish child-code, credential, target or mutation-permit authority.
Fake-child tests are not native DNS/TLS or complete REQ7 transport proof.
"""
from dataclasses import dataclass, field
import math
import os
import selectors
import signal
import subprocess
import sys
import threading
import time
import weakref

_BUDGETS = {"token": 30.0, "read": 30.0, "mutation": 60.0}
_RESPONSE_LIMIT = 2 * 1024 * 1024
_PRIVATE_INPUT_LIMIT = 32768
_USED = weakref.WeakKeyDictionary()
_GUARD = threading.Lock()


class AttemptHold(ValueError):
    def __init__(self, termination_confirmed=False):
        super().__init__("req7_attempt_denied")
        self.termination_confirmed = termination_confirmed


@dataclass(frozen=True)
class SupervisedCompletion:
    data: bytes = field(repr=False)
    termination_confirmed: bool = True


def _group_alive(group):
    try:
        os.killpg(group, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True  # A permission error is NOT evidence of termination.
    return True


def _stop_owned_group(process):
    """Bounded termination cleanup, never permission to repeat a mutation."""
    for operation in (signal.SIGTERM, signal.SIGKILL):
        if _group_alive(process.pid):
            # Entry-time ownership is not permanent. A poll/wait in the read
            # loop or between escalation steps may already have reaped the
            # leader. A remaining numeric group is not authority to signal a
            # possibly reused identity; keep termination unconfirmed/HOLD.
            if process.poll() is not None:
                return False
            try:
                if (os.getpgid(process.pid) != process.pid or os.getsid(process.pid) != process.pid
                        or process.pid == os.getpgrp()):
                    return False
            except OSError:
                return False
            try: os.killpg(process.pid, operation)
            except ProcessLookupError: pass
            except OSError: return False
        try: process.wait(timeout=0.15)
        except subprocess.TimeoutExpired: pass
    finish = time.monotonic() + 1.0
    while _group_alive(process.pid) and time.monotonic() < finish:
        time.sleep(0.01)
    return process.poll() is not None and not _group_alive(process.pid)


def supervise_owned_attempt(process, *, started_monotonic, kind, request_bytes=None):
    """One bounded private response; uncertain termination is explicit HOLD.

The fixed total budget includes time already spent starting the child; socket
timeouts cannot restart it. No complete response is returned until the owned
child/session is absent. Optional bounded private input is written nonblocking
under this same original deadline, then closed to deliver EOF. It is not a
mutation wire channel or authority. Callers retain their lock on uncertain paths.
"""
    now = time.monotonic()
    if (type(kind) is not str or kind not in _BUDGETS
            or type(started_monotonic) not in (int, float)
            # Monotonic epochs are arbitrary, not Unix timestamps. An earlier
            # negative timestamp only shortens the remaining budget. Bound
            # native integers before isfinite's float conversion can overflow.
            or not -sys.float_info.max <= started_monotonic <= now or not math.isfinite(started_monotonic)
            or type(process) is not subprocess.Popen or process.stdout is None or process.stderr is None
            or (request_bytes is not None and (type(request_bytes) is not bytes
                or not 1 <= len(request_bytes) <= _PRIVATE_INPUT_LIMIT or process.stdin is None))):
        raise AttemptHold()
    owned = False
    try:
        if process.poll() is not None:
            # An absent group permits reading this terminal child's pipes.
            # A still-live numeric group after its leader was reaped cannot
            # establish signal ownership: PID/PGID/SID may already be reused.
            # Refuse unconfirmed without signalling, unlocking or retrying.
            owned = not _group_alive(process.pid)
        else:
            owned = (os.getpgid(process.pid) == process.pid and os.getsid(process.pid) == process.pid
                     and process.pid != os.getpgrp())
    except OSError:
        owned = process.poll() is not None and not _group_alive(process.pid)
    if not owned:
        raise AttemptHold()
    with _GUARD:
        if process in _USED: raise AttemptHold()
        _USED[process] = True
    deadline = started_monotonic + _BUDGETS[kind]
    data = bytearray(); failed = False; confirmed = False
    selector = None
    input_cursor = 0
    try:
        selector = selectors.DefaultSelector()
        for channel, stream in (("response", process.stdout), ("error", process.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, channel)
        if request_bytes is not None:
            os.set_blocking(process.stdin.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE, "request")
        while selector.get_map() or process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise AttemptHold()
            events = selector.select(min(remaining, 0.05))
            for key, _event in events:
                if time.monotonic() >= deadline: raise AttemptHold()
                if key.data == "request":
                    try:
                        written = os.write(key.fileobj.fileno(), request_bytes[input_cursor:input_cursor + 4096])
                    except BlockingIOError:
                        continue
                    if written <= 0: raise AttemptHold()
                    input_cursor += written
                    if input_cursor == len(request_bytes):
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                    continue
                limit = min(65536, _RESPONSE_LIMIT + 1 - len(data)) if key.data == "response" else 1
                chunk = os.read(key.fileobj.fileno(), limit)
                if not chunk:
                    selector.unregister(key.fileobj)
                elif key.data == "error":
                    raise AttemptHold()  # Never retain or expose child diagnostics.
                else:
                    data.extend(chunk)
                    if len(data) > _RESPONSE_LIMIT: raise AttemptHold()
        if (time.monotonic() > deadline or process.returncode != 0 or not data or _group_alive(process.pid)
                or (request_bytes is not None and input_cursor != len(request_bytes))):
            raise AttemptHold()
        confirmed = True
        result = SupervisedCompletion(bytes(data))
    except Exception:
        failed = True
        try:
            confirmed = _stop_owned_group(process)
        except Exception:
            # Cleanup failures prove neither termination nor permission to
            # unlock/retry. Never leak their chained private diagnostics.
            confirmed = False
    finally:
        if selector is not None:
            try: selector.close()
            except OSError: failed = True
        streams = (process.stdout, process.stderr) + ((process.stdin,) if request_bytes is not None else ())
        for stream in streams:
            try: stream.close()
            except OSError: failed = True
    if failed:
        # Raise outside except: no secret stdout or child error __context__.
        raise AttemptHold(confirmed)
    return result
