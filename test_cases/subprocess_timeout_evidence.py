"""Private fixture diagnostics; never proof, retry permission or process cleanup."""

from contextlib import contextmanager
import os
import subprocess
import time
from unittest import mock


def collect_process_state(child, native_popen):
    """Read only the private child's observed ancestry, within a 0.75s budget.

    No argv/environment, whole-host dump, signal, descendant cleanup or retry.
    An exited/reaped root cannot license inspection of a possibly recycled PID.
    A process snapshot does not establish the shell's application-level stage.
    """
    state = {
        "capture_phase": "before_cleanup", "stage": "unknown", "pid": child.pid,
        "returncode": child.poll(), "root": None, "descendants": [],
        "descendant_state": "unknown", "errors": [],
    }
    if state["returncode"] is not None:
        state["errors"].append("root already exited; descendants/pipe ownership unknown")
        return state
    deadline = time.monotonic() + 0.75

    def probe(argv):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise OSError("private process observation budget exhausted")
        process = native_popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               close_fds=True)
        try:
            output, _errors = process.communicate(timeout=max(0.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            process.kill()  # Only this newly-created diagnostic command.
            process.communicate(timeout=0.1)
            raise OSError("private diagnostic command timed out")
        if len(output) > 8192:
            raise OSError("private diagnostic output exceeded bound")
        return process.returncode, output.decode("utf-8", errors="replace")

    def node(pid, parent):
        code, output = probe(["/bin/ps", "-p", str(pid), "-o", "pid=,ppid=,stat=,comm="])
        rows = output.splitlines()
        if code != 0 or len(rows) != 1:
            raise OSError("private process identity unavailable")
        fields = rows[0].split(None, 3)
        if len(fields) != 4 or int(fields[0]) != pid or int(fields[1]) != parent:
            raise OSError("private process ancestry changed")
        return {"pid": pid, "ppid": parent, "state": fields[2][:32], "comm": fields[3][:256]}

    try:
        state["root"] = node(child.pid, os.getpid())
        queue, seen = [child.pid], {child.pid}
        while queue and len(seen) < 16:
            parent = queue.pop(0)
            code, output = probe(["/usr/bin/pgrep", "-P", str(parent)])
            if code not in (0, 1):
                raise OSError("private child enumeration unavailable")
            for raw in output.splitlines():
                pid = int(raw)
                if pid <= 0 or pid in seen:
                    continue
                if len(seen) >= 16:
                    state["errors"].append("private descendant count bound reached")
                    break
                seen.add(pid)
                state["descendants"].append(node(pid, parent))
                queue.append(pid)
        state["descendant_state"] = "partial" if state["errors"] or queue else "observed snapshot only"
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        state["errors"].append(f"{type(error).__name__}: {error}"[:256])
        state["descendant_state"] = "partial" if state["root"] else "unknown"
    return state


@contextmanager
def capture_timeout_before_cleanup(*, expected_command=None, collector=None):
    """Attach live evidence to the same TimeoutExpired before run() cleanup.

    communicate(), not a private stdlib timer hook, is the observation boundary.
    The original argv/input/check/timeout and run() kill/reap behavior remain.
    This scoped Popen patch is for these serial private test fixtures only.
    """
    native = subprocess.Popen
    observe = collect_process_state if collector is None else collector
    expected = None if expected_command is None else tuple(expected_command)

    class EvidencePopen(native):
        def communicate(self, *args, **kwargs):
            try:
                return super().communicate(*args, **kwargs)
            except subprocess.TimeoutExpired as error:
                if expected is not None and tuple(self.args) != expected:
                    raise  # Never observe unrelated children in the scoped context.
                try:
                    evidence = observe(self, native)
                except Exception as diagnostic_error:
                    evidence = {"capture_phase": "before_cleanup", "stage": "unknown",
                                "pid": self.pid, "error": str(diagnostic_error)[:256]}
                error.prekill_process_evidence = evidence
                raise

    with mock.patch.object(subprocess, "Popen", EvidencePopen):
        yield
