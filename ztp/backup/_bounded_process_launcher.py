"""Fixed sibling launcher for the backup bounded command boundary.

No command/env is accepted on argv. Only original request/status FD numbers,
nonce and original deadline are passed. No stdout/stderr diagnostic output.
"""
from __future__ import annotations

import json
import math
import os
import selectors
import signal
import stat
import struct
import subprocess
import sys
import time


LIMIT = 1048576
FRAME = struct.Struct("!4s16sII")
_Popen = subprocess.Popen


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate request field")
        result[key] = value
    return result


def parse_request(raw):
    if len(raw) < 4:
        raise ValueError("partial request header")
    size = int.from_bytes(raw[:4], "big")
    if not 0 < size <= LIMIT or len(raw) != size + 4:
        raise ValueError("request length or trailing data")
    value = json.loads(raw[4:].decode("ascii"), object_pairs_hook=_unique)
    if not isinstance(value, dict) or set(value) != {"argv", "env", "env_mode"}:
        raise ValueError("request schema")
    argv, env = value["argv"], value["env"]
    if (not isinstance(argv, list) or not argv
            or not argv[0] or any(not isinstance(x, str) or "\0" in x for x in argv)
            or not isinstance(env, dict)
            or any(not isinstance(k, str) or not isinstance(v, str)
                   or not k or "=" in k or "\0" in k or "\0" in v for k, v in env.items())
            or value["env_mode"] not in {"EXPLICIT", "INHERITED_SNAPSHOT"}):
        raise ValueError("request values")
    canonical = json.dumps(value, ensure_ascii=True, sort_keys=True,
                           separators=(",", ":")).encode("ascii")
    if raw[4:] != canonical:
        raise ValueError("noncanonical or trailing request JSON")
    return value


def command_kwargs(request):
    return dict(stdin=0, stdout=1, stderr=2, text=False, env=request["env"],
                close_fds=True, pass_fds=(), start_new_session=False)


def status_frame(nonce, pid, status):
    if (not isinstance(nonce, bytes) or len(nonce) != 16 or type(pid) is not int
            or pid <= 0 or type(status) is not int or not 0 <= status <= 65535
            or not (os.WIFEXITED(status) or os.WIFSIGNALED(status))):
        raise ValueError("invalid real child wait status")
    return FRAME.pack(b"HAP1", nonce, pid, status)


def _kill_own_original_group(own_pid):
    # This process is itself the still-existing original group/session leader.
    # Never discover/adopt some other numeric process group.
    if os.getpid() != own_pid or os.getpgrp() != own_pid or os.getsid(0) != own_pid:
        os._exit(126)
    os.killpg(own_pid, signal.SIGKILL)
    os._exit(126)  # Signal failure cannot become normal command success.


def parse_launch_arguments(argv):
    if len(argv) != 5:
        raise ValueError("fixed launcher arguments required")
    request_fd, status_fd = int(argv[1]), int(argv[2])
    nonce = bytes.fromhex(argv[3])
    deadline = float(argv[4])
    if (request_fd < 3 or status_fd < 3 or request_fd == status_fd or len(nonce) != 16
            or not math.isfinite(deadline) or deadline <= 0):
        raise ValueError("invalid private descriptors")
    return request_fd, status_fd, nonce, deadline


def main():
    request_fd, status_fd, nonce, deadline = parse_launch_arguments(sys.argv)
    own_pid = os.getpid()
    if (os.getpgrp() != own_pid or os.getsid(0) != own_pid
            or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL):
        raise ValueError("original session/default child wait required")
    for fd in (request_fd, status_fd):
        if not stat.S_ISFIFO(os.fstat(fd).st_mode):
            raise ValueError("original pipe required")
        os.set_inheritable(fd, False)
        os.set_blocking(fd, False)
    selector = selectors.DefaultSelector()
    child = None
    raw = bytearray()
    request = None
    command_done = False
    status_open = True
    error = None
    try:
        selector.register(request_fd, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _kill_own_original_group(own_pid)
            for _event, _mask in selector.select(min(0.05, remaining)):
                try:
                    chunk = os.read(request_fd, 8192)
                except BlockingIOError:
                    continue
                if not chunk:  # Original parent lifetime end disappeared.
                    _kill_own_original_group(own_pid)
                if request is not None:
                    raise ValueError("trailing request after fixed frame")
                raw.extend(chunk)
                if len(raw) > LIMIT + 4:
                    raise ValueError("request bound")
                if len(raw) >= 4:
                    size = int.from_bytes(raw[:4], "big")
                    if not 0 < size <= LIMIT:
                        raise ValueError("request bound")
                    if len(raw) >= size + 4:
                        request = parse_request(bytes(raw))
                        child = _Popen.__new__(_Popen)
                        child.__init__(request["argv"], **command_kwargs(request))
                        # Real command now has the only copies of captured stdio.
                        for fd in (0, 1, 2):
                            os.close(fd)
            if child is not None and not command_done:
                pid, status = os.waitpid(child.pid, os.WNOHANG)
                if pid not in {0, child.pid}:
                    raise ValueError("unexpected real child wait result")
                if pid == child.pid:
                    child.returncode = os.waitstatus_to_exitcode(status)
                    frame = status_frame(nonce, pid, status)
                    # One <=PIPE_BUF write; never a blocking protocol transfer.
                    if os.write(status_fd, frame) != len(frame):
                        raise ValueError("partial status transfer")
                    command_done = True
                    # Remain original anchor; do not exit/release group number.
    except BaseException as primary:
        error = primary
    finally:
        try:
            selector.close()
        except BaseException as cleanup:
            if error is None or (isinstance(error, Exception)
                                 and not isinstance(cleanup, Exception)):
                error = cleanup
        # Closing status signals UNKNOWN, never a synthetic exit0 frame.
        if status_open:
            try:
                os.close(status_fd)
            except BaseException as cleanup:
                if error is None or (isinstance(error, Exception)
                                     and not isinstance(cleanup, Exception)):
                    error = cleanup
    # The launcher must not exit and abandon running group members on a local
    # protocol/constructor/wait/NI failure. It still owns this live original
    # group itself; terminate it, not a rediscovered foreign numeric group.
    _kill_own_original_group(own_pid)


if __name__ == "__main__":
    main()
