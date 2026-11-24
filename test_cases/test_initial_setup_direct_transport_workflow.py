"""r660 WP3 real MAIN/LP/task/transport and single-endpoint PUBLIC PTY.

All expectations precede implementation. This is not WP4 credential ordering,
post-login network identity, configuration completion or WP5 final summary.
The phase wire uses real original _IBPhase/PTY and a PUBLIC protocol peer.
Management/remote argv binding is static; no actual management shell lifecycle
is claimed. Only a point-named own Python child replaces its checked boundary.
"""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import csv
import errno
import io
import json
import os
from pathlib import Path
import pty
import re
import shlex
import signal
import sys
import time
import unittest
from unittest import mock

from test_cases.test_initial_setup_direct_transport import (
    DirectWorld, _Facade, HEADER, INITIAL, ROOT, IB1, MAC1, LL1,
    IP, IFACE, SCOPED, READ, BODY, PUBLIC_REPLY, ssh_words, require_api,
)

_REAL_EXECVE = os.execve
_REAL_FORK = pty.fork
_REAL_KILL, _REAL_KILLPG, _REAL_WAIT = os.kill, os.killpg, os.waitpid
_REAL_WRITE = os.write


class _PtySignalCustody:
    """One synchronous local fixture attempt owns its original fork.

    The original fork's PID is usable only while we still own its wait
    result. The original terminal wait consumes that authority, and an
    interruption during wait can consume it without handing us a result.
    """

    def __init__(self):
        self._state = {}

    def fork(self):
        """Invoke the original native fork, then bind the returned child."""
        if self._state:
            raise AssertionError("PTY fixture attempt already launched its child")
        pair = _REAL_FORK()
        if pair[0] > 0:
            self.record_fork(pair[0])
        return pair

    def record_fork(self, pid):
        if type(pid) is not int or pid <= 0 or self._state:
            raise AssertionError("one original positive child per PTY fixture attempt")
        self._state[pid] = "owned"

    def wait(self, pid, flags):
        state = self._state.get(pid)
        if state != "owned" and (state != "uncertain" or flags != os.WNOHANG):
            raise ChildProcessError(errno.ECHILD, "PTY fixture does not own this wait")
        # Fence before entering the native call, not after getting its
        # result. Only an unambiguous nohang observation on a still-owned
        # path restores permission. Following interruption the serial
        # fixture can record one final nonblocking wait, never rearm.
        self._state[pid] = "waiting"
        try:
            result = _REAL_WAIT(pid, flags)
        except ChildProcessError:
            self._state[pid] = "spent"
            raise
        except BaseException:
            self._state[pid] = "uncertain" if state == "owned" else "spent"
            raise
        if state == "owned" and flags == os.WNOHANG and result == (0, 0):
            self._state[pid] = "owned"
        else:
            self._state[pid] = "spent"
        return result

    def send(self, pid, sig, *, group):
        if self._state.get(pid) != "owned":
            raise ProcessLookupError(errno.ESRCH, "PTY fixture no longer owns this signal")
        endpoint = _REAL_KILLPG if group else _REAL_KILL
        return endpoint(pid, sig)


class PtyWaitCustodyTests(unittest.TestCase):
    def test_duplicate_attempt_is_refused_before_calling_native_fork(self):
        custody = _PtySignalCustody()
        pid, master = 12345, 465
        with mock.patch(__name__ + "._REAL_FORK", side_effect=[(pid, master), (pid + 1, master + 1)]) as fork:
            self.assertEqual((pid, master), custody.fork())
            with self.assertRaises(AssertionError):
                custody.fork()
            fork.assert_called_once_with()

    def test_uncertain_wait_never_authorizes_a_former_group_or_pid(self):
        pid = 12345  # purely synthetic; no fork, native wait, or signal
        for group, wait_error in ((True, KeyboardInterrupt), (False, ChildProcessError)):
            with self.subTest(group=group, wait_error=wait_error.__name__):
                custody = _PtySignalCustody()
                custody.record_fork(pid)
                with mock.patch(__name__ + "._REAL_WAIT", side_effect=wait_error) as wait, \
                     mock.patch(__name__ + "._REAL_KILL") as single, \
                     mock.patch(__name__ + "._REAL_KILLPG") as joined:
                    with self.assertRaises(wait_error):
                        custody.wait(pid, os.WNOHANG)
                    wait.assert_called_once_with(pid, os.WNOHANG)
                    with self.assertRaises(ProcessLookupError):
                        custody.send(pid, signal.SIGKILL, group=group)
                    single.assert_not_called()
                    joined.assert_not_called()

    def test_reaped_child_cannot_be_signalled_or_waited_as_a_new_child(self):
        custody = _PtySignalCustody()
        pid = 12345
        custody.record_fork(pid)
        with mock.patch(__name__ + "._REAL_WAIT", return_value=(pid, 0)) as wait, \
             mock.patch(__name__ + "._REAL_KILLPG") as joined:
            self.assertEqual((pid, 0), custody.wait(pid, os.WNOHANG))
            with self.assertRaises(ProcessLookupError):
                custody.send(pid, signal.SIGKILL, group=True)
            with self.assertRaises(ChildProcessError):
                custody.wait(pid, 0)
            wait.assert_called_once_with(pid, os.WNOHANG)
            joined.assert_not_called()

    def test_nohang_liveness_restores_signal_for_the_original_child_only(self):
        custody = _PtySignalCustody()
        pid = 12345
        custody.record_fork(pid)
        with mock.patch(__name__ + "._REAL_WAIT", return_value=(0, 0)) as wait, \
             mock.patch(__name__ + "._REAL_KILL") as single, \
             mock.patch(__name__ + "._REAL_KILLPG") as joined:
            self.assertEqual((0, 0), custody.wait(pid, os.WNOHANG))
            custody.send(pid, signal.SIGTERM, group=False)
            custody.send(pid, signal.SIGTERM, group=True)
            wait.assert_called_once_with(pid, os.WNOHANG)
            single.assert_called_once_with(pid, signal.SIGTERM)
            joined.assert_called_once_with(pid, signal.SIGTERM)

    def test_wait_boundary_revokes_signal_before_syscall_and_after_uncertainty(self):
        custody = _PtySignalCustody()
        pid = 12345
        custody.record_fork(pid)

        def interrupted_wait(child, flags):
            self.assertEqual((pid, os.WNOHANG), (child, flags))
            for group in (False, True):
                with self.assertRaises(ProcessLookupError):
                    custody.send(pid, signal.SIGKILL, group=group)
            raise KeyboardInterrupt()

        with mock.patch(__name__ + "._REAL_WAIT", side_effect=interrupted_wait) as wait, \
             mock.patch(__name__ + "._REAL_KILL") as single, \
             mock.patch(__name__ + "._REAL_KILLPG") as joined:
            with self.assertRaises(KeyboardInterrupt):
                custody.wait(pid, os.WNOHANG)
            # A last nonblocking wait may still gather terminal evidence.
            # A not-ready result must not grant signal rights again.
            wait.side_effect = [(0, 0)]
            self.assertEqual((0, 0), custody.wait(pid, os.WNOHANG))
            with self.assertRaises(ProcessLookupError):
                custody.send(pid, signal.SIGKILL, group=True)
            with self.assertRaises(ChildProcessError):
                custody.wait(pid, os.WNOHANG)
            self.assertEqual([mock.call(pid, os.WNOHANG)] * 2, wait.call_args_list)
            single.assert_not_called()
            joined.assert_not_called()


def assert_phase_argv_binding(case, argv, *, nonce, operation, endpoint):
    """Independent literal wire grammar, never SUT frame/script helpers.

    The peer is permitted only after proving the BEGIN/EXIT are at the manager
    and the SSH remote contains only the command frame, with the SAME nonce.
    This is an argv oracle, not execution of any shell or transport engine.
    """
    case.assertIs(type(argv), list)
    case.assertEqual(["sh", "-c"], argv[:2], "phase requires manager-side shell, not plain SSH")
    case.assertEqual(3, len(argv))
    case.assertRegex(nonce, r"^[0-9a-f]{32}$")
    case.assertIn(operation, ("auth-probe-readonly", "password-change", "post-change-read"))
    prefix = 'printf "\\n__HTTP_IB_AUTH_' + nonce + '_' + operation + '__=BEGIN\\n"; '
    suffix = ('; inner_rc=$?; printf "\\n__HTTP_IB_AUTH_' + nonce + '_' + operation
              + '__=EXIT:%s\\n" "$inner_rc"; exit "$inner_rc"')
    case.assertTrue(argv[2].startswith(prefix), "exact management BEGIN nonce/operation binding")
    case.assertTrue(argv[2].endswith(suffix), "exact management EXIT nonce/operation/status binding")
    ssh_text = argv[2][len(prefix):-len(suffix)]
    words = shlex.split(ssh_text)
    case.assertEqual(ssh_text, shlex.join(words), "only the single canonical SSH argv lies between manager markers")
    case.assertEqual("ssh", words[0])
    case.assertEqual([endpoint], [word for word in words if word.startswith("admin@")])
    case.assertEqual(endpoint, words[-2])
    remote = shlex.split(words[-1])
    frame = ('printf "\\n__HTTP_IB_BEGIN_' + nonce + '__\\n"; nv config show -o commands'
             + '; task_rc=$?; printf "\\n__HTTP_IB_END_' + nonce
             + '__=%s\\n" "$task_rc"; exit "$task_rc"')
    case.assertEqual(["sh", "-c", frame], remote, "remote command frame is exact and contains NO phase BEGIN/EXIT")
    return words, endpoint


def _public_phase_vector():
    """Hand-written PUBLIC positive, independent of every product builder."""
    remote_frame = (r'printf "\n__HTTP_IB_BEGIN_0123456789abcdef0123456789abcdef__\n"; nv config show -o commands'
                    r'; task_rc=$?; printf "\n__HTTP_IB_END_0123456789abcdef0123456789abcdef__=%s\n" "$task_rc"; exit "$task_rc"')
    ssh = ["ssh", "-6", "-tt", "-o", "ConnectTimeout=2", "admin@fe80::ff:fe00:10%en-public7",
           shlex.join(["sh", "-c", remote_frame])]
    begin = r'printf "\n__HTTP_IB_AUTH_0123456789abcdef0123456789abcdef_auth-probe-readonly__=BEGIN\n"; '
    end = (r'; inner_rc=$?; printf "\n__HTTP_IB_AUTH_0123456789abcdef0123456789abcdef_auth-probe-readonly__=EXIT:%s\n" '
           r'"$inner_rc"; exit "$inner_rc"')
    return ["sh", "-c", begin + shlex.join(ssh) + end], ssh

# This child is data-only PUBLIC SSH/PAM modelling. It never starts a process,
# opens a socket, consults a home, or imports repository code. It reports roles,
# not credential values. All paths come from its explicit owned config parent.
PEER = r'''import json, os, re, select, sys, termios, time
from pathlib import Path
config = Path(sys.argv[1]); c = json.loads(config.read_text()); root = config.parent
def emit(text): os.write(1, text.encode())
def event(kind, **facts):
    path = root / "peer-events.jsonl"
    raw = (json.dumps(dict(kind=kind, **facts), sort_keys=True) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        if os.fstat(fd).st_size > 65536 or len(raw) > 2048: raise RuntimeError("PUBLIC cap")
        os.write(fd, raw)
    finally: os.close(fd)
def receive():
    deadline = time.monotonic() + 8; raw = b""
    while len(raw) <= 4097:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([0], [], [], remaining)[0]: return None
        part = os.read(0, 4098 - len(raw))
        if not part: return None
        raw += part
        if b"\n" in raw:
            if raw.count(b"\n") != 1 or not raw.endswith(b"\n"): return None
            return raw[:-1].rstrip(b"\r").decode()
    return None
def ask(prompt, role):
    emit(prompt); value = receive()
    event(role, complete=value is not None, current=value == c["current"], target=value == c["target"])
    return value
def run():
    state = termios.tcgetattr(0); state[3] &= ~(termios.ECHO | termios.ECHONL); termios.tcsetattr(0, termios.TCSANOW, state)
    nonce, op, endpoint, case = c["nonce"], c["op"], c["endpoint"], c["case"]
    base = "\n__HTTP_IB_AUTH_" + nonce + "_" + op + "__="
    if case == "bare-outer":
        got = ask("\n's password: ", "foreign-input")
        return 255
    marker = base.replace(nonce, "f" * 32) if case == "wrong-nonce" else base
    if case == "wrong-operation": marker = base.replace(op, "post-change-read" if op != "post-change-read" else "password-change")
    emit(marker + "BEGIN\n")
    if case in ("foreign-ipv4", "foreign-ipv6"):
        foreign = "admin@203.0.113.99" if case == "foreign-ipv4" else "admin@fe80::999%en-other"
        ask("\n" + foreign + "'s password: ", "foreign-input")
        return 255
    current = ask("\n" + endpoint + "'s password: ", "current-input")
    if current != c["current"]: return 83
    if case == "reject":
        emit("\n" + endpoint + ": Permission denied (password).\n" + base + "EXIT:255\n")
        return 255
    if case == "wrong-endpoint":
        emit("\nadmin@203.0.113.99: Permission denied (password).\n" + base + "EXIT:255\n")
        return 255
    if case == "bare255": return 255
    if case in ("pam", "expiry-readonly"):
        emit("\nYou are required to change your password immediately (administrator enforced).\n")
        old = ask("\n(current) UNIX password: ", "pam-current")
        if case == "expiry-readonly": return 84
        new = ask("\nNew password: ", "pam-new")
        confirm = ask("\nRetype new password: ", "pam-confirm")
        if old != c["current"] or new != c["target"] or confirm != c["target"]: return 85
        emit("\npasswd: all authentication tokens updated successfully\n" + base + "EXIT:0\n")
        event("finish", status=0); return 0
    emit("\n__HTTP_IB_BEGIN_" + nonce + "__\n" + c["body"] + "\n__HTTP_IB_END_" + nonce + "__=0\n")
    if case != "missing-exit": emit(base + "EXIT:0\n")
    event("finish", status=0); return 0
try: rc = run()
except BaseException as exc:
    event("adapter-error", exception_type=type(exc).__name__); rc = 86
raise SystemExit(rc)
'''


class _WP3Checkpoint(BaseException):
    """Only a test observation after execute consumed its real read result."""


class PhaseWorld(DirectWorld):
    def drive(self, case="success", operation="auth-probe-readonly", *, policy=None,
              current=PUBLIC_REPLY, allow=False, new=None, write_fault=None,
              budget_short=False, change_project=False):
        require_api(self.app)
        peer = self.root / "wp3-direct-peer.py"
        peer.write_text(PEER, encoding="utf-8")
        peer.chmod(0o600)
        config = self.root / "peer-config.json"
        events = self.root / "peer-events.jsonl"
        if events.exists():
            events.unlink()  # exact own model output from the preceding drive only
        owned = set()
        custody = _PtySignalCustody()
        masters = set()
        reaps, writes, phases = [], [], []
        # Captured at the original source loader return, before the owned
        # world's external SSH model is installed; no copied source execution.
        real_interactive = self._original_interactive
        def fork():
            pid, fd = custody.fork()
            if pid > 0:
                owned.add(pid); masters.add(fd)
            return pid, fd
        def execute(name, argv):
            # Called only in the freshly forked owned child. No arbitrary
            # executable: exact reviewed vector -> one fixed own PUBLIC peer.
            if name != "sh" or argv != self.expected_argv:
                os._exit(87)
            _REAL_EXECVE(sys.executable,
                [sys.executable, "-I", "-S", "-B", str(peer), str(config)],
                {"PATH": os.defpath, "HOME": str(self.home), "LC_ALL": "C", "LANG": "C",
                 "PYTHONDONTWRITEBYTECODE": "1"})
        def kill(pid, sig):
            self.case.assertIn(pid, owned)
            return custody.send(pid, sig, group=False)
        def killpg(pid, sig):
            self.case.assertIn(pid, owned)
            return custody.send(pid, sig, group=True)
        def wait(pid, flags):
            self.case.assertIn(pid, owned)
            result = custody.wait(pid, flags)
            if result[0]:
                reaps.append(result)
            return result
        fault_used = False
        clock_offset = 0.0
        def write(fd, raw):
            nonlocal fault_used, clock_offset
            self.case.assertIn(fd, masters)
            raw = bytes(raw)
            if write_fault == "short-zero" and raw == current.encode() + b"\n" and not fault_used:
                fault_used = True
                amount = _REAL_WRITE(fd, raw[:2])
                writes.append(("partial-current", amount))
                return amount
            if write_fault == "short-zero" and fault_used:
                writes.append(("zero-current", 0))
                return 0
            amount = _REAL_WRITE(fd, raw)
            writes.append(("current" if raw == current.encode() + b"\n" else
                           "target" if new is not None and raw == new.encode() + b"\n" else "other", amount))
            if raw == current.encode() + b"\n" and amount == len(raw):
                if budget_short:
                    clock_offset = 53.0  # original 60s session: less than the fixed 8s reserve
                if change_project:
                    self.case.assertIsNotNone(policy)
                    with policy.path.open("a") as handle:
                        handle.write("\n# PUBLIC same-project mutation at the current/PAM boundary\n")
            return amount
        def interactive(argv, responder, timeout, **kwargs):
            phase = getattr(responder, "_phase", None)
            self.case.assertIs(type(responder), self.app.NestedResponder)
            self.case.assertIs(type(phase), self.app._IBPhase)
            self.case.assertEqual(operation, phase.operation, "requested operation, not a peer-generated substitute")
            _words, endpoint = assert_phase_argv_binding(self.case, argv, nonce=phase.nonce,
                operation=operation, endpoint="admin@" + SCOPED)
            self.case.assertEqual((endpoint, "", ""),
                (phase.endpoint, phase.outer_endpoint, responder.ethernet_password))
            phases.append(phase)
            self.expected_argv = list(argv)
            config.write_text(json.dumps({"nonce": phase.nonce, "op": phase.operation,
                "endpoint": endpoint, "case": case, "current": current,
                "target": new or current, "body": BODY}), encoding="utf-8")
            config.chmod(0o600)
            return real_interactive(argv, responder, timeout, **kwargs)
        completed_return = False
        try:
            with mock.patch.object(self.app, "pty", _Facade(pty, fork=fork)), \
                 mock.patch.object(self.app, "os", _Facade(os, execvp=execute, kill=kill,
                     killpg=killpg, waitpid=wait, write=write)), \
                 mock.patch.object(self.app, "time", _Facade(time, monotonic=lambda: time.monotonic() + clock_offset)), \
                 mock.patch.object(self.app, "interactive_run", side_effect=interactive):
                result = self.call(current=current, _phase_operation=operation, _password_policy=policy,
                    allow_password_change=allow, ib_new_password=new)
                completed_return = True
                return result
        finally:
            self.phase_facts = {"phases": phases, "reaps": reaps, "writes": writes,
                "events": [json.loads(line) for line in events.read_text().splitlines()] if events.exists() else []}
            # Product cleanup owns termination/reap. This observer never sends
            # an extra signal or masks a missing reap with fixture success.
            # A pre-fork primary error (including binding AssertionError) must
            # remain that error, not be replaced by a fictional missing child.
            # A successful no-fork return is NOT allowed. Once actually forked,
            # retain the original exact one-child/one-reap assertions, even
            # while a primary exception propagates (its context is preserved).
            if owned or completed_return:
                self.case.assertEqual(1, len(owned))
                self.case.assertEqual(1, len(reaps), "real interactive finally must reap its own child exactly once")
                self.case.assertFalse(any(event["kind"] == "adapter-error" for event in self.phase_facts["events"]))

ACTIVE_READ_PEER = r'''import json, os, select, sys, termios, time
from pathlib import Path
config = Path(sys.argv[1]); c = json.loads(config.read_text()); root = config.parent
def emit(text): os.write(1, text.encode())
def event(kind, **facts):
    raw = (json.dumps(dict(kind=kind, **facts), sort_keys=True) + "\n").encode()
    fd = os.open(root / "events.jsonl", os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        if os.fstat(fd).st_size > 65536 or len(raw) > 2048: raise RuntimeError("PUBLIC cap")
        os.write(fd, raw)
    finally: os.close(fd)
def run():
    state = termios.tcgetattr(0); state[3] &= ~(termios.ECHO | termios.ECHONL); termios.tcsetattr(0, termios.TCSANOW, state)
    base = "\n__HTTP_IB_AUTH_" + c["nonce"] + "_auth-probe-readonly__="
    if c.get("parts") is not None:
        emit(base + "BEGIN\n")
        deadline = time.monotonic() + 8
        for index, part in enumerate(c["parts"]):
            event("diagnostic-part", index=index)
            emit(part)
            ack = root / ("read." + str(index) + ".ack")
            while not ack.exists():
                if time.monotonic() >= deadline: raise RuntimeError("PUBLIC part acknowledgement missing")
                time.sleep(0.01)
            if ack.read_bytes() != b"1\n": raise RuntimeError("PUBLIC part acknowledgement invalid")
            event("part-acknowledged", index=index)
        if not c.get("truncated_tail", False): emit(base + "EXIT:255\n")
        return 255
    if c["diagnostic"]:
        event("diagnostic", endpoint=c["endpoint"])
        emit(base + "BEGIN\n" + c["diagnostic"])
        deadline = time.monotonic() + 8
        ack = root / "read.ack"
        while not ack.exists():
            if time.monotonic() >= deadline: raise RuntimeError("PUBLIC active-read acknowledgement missing")
            time.sleep(0.01)
        if ack.read_bytes() != b"1\n": raise RuntimeError("PUBLIC acknowledgement invalid")
        event("acknowledged")
        emit(base + "EXIT:255\n")
        return 255
    emit(base + "BEGIN\n\n" + c["endpoint"] + "'s password: ")
    raw = b""; deadline = time.monotonic() + 8
    while b"\n" not in raw and len(raw) <= 4097:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([0], [], [], remaining)[0]: raise RuntimeError("PUBLIC current input missing")
        part = os.read(0, 4098 - len(raw))
        if not part: raise RuntimeError("PUBLIC current input closed")
        raw += part
    complete = raw.count(b"\n") == 1 and raw.endswith(b"\n")
    correct = complete and raw[:-1].rstrip(b"\r").decode() == c["current"]
    event("current-input", complete=complete, correct=correct)
    if not correct: return 83
    emit("\n__HTTP_IB_BEGIN_" + c["nonce"] + "__\n" + c["body"]
         + "__HTTP_IB_END_" + c["nonce"] + "__=0\n" + base + "EXIT:0\n")
    event("finish")
    return 0
try: rc = run()
except BaseException as exc:
    event("adapter-error", exception_type=type(exc).__name__); rc = 86
raise SystemExit(rc)
'''


class ActiveReadWorld(DirectWorld):
    """Real phase/PTY with a passive, owned active-read barrier, not fake results."""
    def __init__(self, case):
        super().__init__(case)
        self.attempts, self.timeline, self.metric_calls = [], [], []

    def control(self, argv, **kwargs):
        if argv == ["ip", "-4", "neigh", "show", IP]:
            self.timeline.append(("neighbor", IP))
        return super().control(argv, **kwargs)

    def drive_active(self, mode, *, ipv4=False, split_warning=False, close_error=False, conflict=None):
        require_api(self.app)
        real_read, real_close = os.read, os.close
        peer = self.root / "active-read-peer.py"
        peer.write_text(ACTIVE_READ_PEER, encoding="utf-8"); peer.chmod(0o600)
        allowed = ["admin@" + IP] if ipv4 else ["admin@" + SCOPED]
        if mode == "network":
            self.case.assertFalse(ipv4)
            allowed.append("admin@" + IP)
        else:
            self.case.assertEqual("hostkey", mode)
            if conflict is not None and not ipv4:
                allowed.append("admin@" + IP)  # observe an erroneous retry, never fake an earlier argv error
        known = self.home / ".ssh" / "known_hosts"
        if mode == "hostkey":
            known.parent.mkdir(mode=0o700, exist_ok=True)
            known.write_text("PUBLIC own original known-hosts entry\n", encoding="utf-8")
            known.chmod(0o600)
        self.known_hosts = known
        self.known_before = known.read_bytes() if mode == "hostkey" else None
        active = None
        def fork():
            pid, fd = active["custody"].fork()
            if pid > 0:
                active["children"].add(pid); active["fds"].add(fd)
                self.timeline.append(("fork", active["index"]))
            return pid, fd
        def execute(name, argv):
            if name != "sh" or argv != active["argv"]:
                os._exit(87)
            _REAL_EXECVE(sys.executable,
                [sys.executable, "-I", "-S", "-B", str(peer), str(active["config"])],
                {"PATH": os.defpath, "HOME": str(self.home), "LC_ALL": "C", "LANG": "C",
                 "PYTHONDONTWRITEBYTECODE": "1"})
        def read(fd, limit):
            self.case.assertIn(fd, active["fds"])
            raw = real_read(fd, limit)
            active["read_bytes"] += raw
            self.case.assertLessEqual(len(active["read_bytes"]), 65536)
            diagnostic = active["diagnostic"].encode()
            if active["parts"] is not None:
                prefix = ""
                for index, part in enumerate(active["parts"]):
                    prefix += part
                    if prefix.encode() in active["read_bytes"].replace(b"\r\n", b"\n") and index not in active["parts_seen"]:
                        active["parts_seen"].append(index)
                        fd_ack = os.open(active["directory"] / ("read." + str(index) + ".ack"),
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                        try: self.case.assertEqual(2, _REAL_WRITE(fd_ack, b"1\n"))
                        finally: os.close(fd_ack)
                active["observed"] = len(active["parts_seen"]) == len(active["parts"])
            if active["parts"] is None and diagnostic and diagnostic in active["read_bytes"].replace(b"\r\n", b"\n") and not active["observed"]:
                active["observed"] = True
                self.timeline.append(("active-read", active["index"]))
                fd_ack = os.open(active["directory"] / "read.ack",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                try:
                    self.case.assertEqual(2, _REAL_WRITE(fd_ack, b"1\n"))
                finally: os.close(fd_ack)
            return raw
        def write(fd, raw):
            self.case.assertIn(fd, active["fds"])
            raw = bytes(raw)
            amount = _REAL_WRITE(fd, raw)
            active["writes"].append((raw == PUBLIC_REPLY.encode() + b"\n", amount))
            return amount
        def close(fd):
            self.case.assertIn(fd, active["fds"])
            real_close(fd)
            active["real_close"] = True
            if close_error and active["index"] == 0 and active["reaps"]:
                self.case.assertEqual(1, len(active["reaps"]))
                active["close_injected"] = True
                raise OSError(5, "PUBLIC owned master close failure after actual close/reap")
        def kill(pid, sig):
            self.case.assertIn(pid, active["children"])
            return active["custody"].send(pid, sig, group=False)
        def killpg(pid, sig):
            self.case.assertIn(pid, active["children"])
            return active["custody"].send(pid, sig, group=True)
        def wait(pid, flags):
            self.case.assertIn(pid, active["children"])
            result = active["custody"].wait(pid, flags)
            if result[0]:
                active["reaps"].append(result)
                self.timeline.append(("reap", active["index"]))
            return result
        def interactive(argv, responder, timeout, **kwargs):
            nonlocal active
            index = len(self.attempts)
            self.case.assertLess(index, len(allowed), "no third/foreign endpoint is modeled")
            phase = getattr(responder, "_phase", None)
            self.case.assertIs(type(responder), self.app.NestedResponder)
            self.case.assertIs(type(phase), self.app._IBPhase)
            self.case.assertEqual("auth-probe-readonly", phase.operation)
            _words, endpoint = assert_phase_argv_binding(self.case, argv, nonce=phase.nonce,
                operation="auth-probe-readonly", endpoint=allowed[index])
            self.case.assertEqual((endpoint, "", ""),
                (phase.endpoint, phase.outer_endpoint, responder.ethernet_password))
            directory = self.root / ("active-attempt-" + str(index))
            directory.mkdir(mode=0o700)
            self.case.assertEqual(self.root, directory.resolve().parent)
            self.case.assertEqual(os.geteuid(), directory.stat().st_uid)
            self.case.assertEqual(0o700, directory.stat().st_mode & 0o777)
            diagnostic = ""
            if mode == "network" and index == 0:
                diagnostic = "ssh: connect to host fe80::ff:fe00:10%en-public7 port 22: Connection timed out\n"
            if mode == "hostkey" and index == 0:
                diagnostic = ("WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\n"
                    "The fingerprint for the ED25519 key sent by the remote host is\nSHA256:" + "B" * 43 + ".\n"
                    "Offending ED25519 key in " + str(known) + ":1\n"
                    "Host key for " + endpoint[6:] + " has changed\nHost key verification failed.\n")
            parts, truncated_tail = None, False
            if index == 0 and conflict is not None:
                if mode == "hostkey":
                    changed_address = {"foreign-ipv4": "203.0.113.99", "same-ib-ipv4": IP,
                        "foreign-scope": LL1 + "%en-other"}
                    if conflict == "partial":
                        diagnostic = "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\n"
                    else:
                        self.case.assertIn(conflict, changed_address)
                        diagnostic = diagnostic.replace("Host key for " + endpoint[6:] + " has changed",
                            "Host key for " + changed_address[conflict] + " has changed")
                else:
                    other_nonce = ("0" if phase.nonce[0] != "0" else "1") + phase.nonce[1:]
                    mixtures = {
                        "updated": "passwd: all authentication tokens updated successfully\n",
                        "pam": "You are required to change your password immediately (administrator enforced).\n(current) UNIX password: ",
                        "frame": "__HTTP_IB_BEGIN_" + phase.nonce + "__\nPUBLIC command data\n__HTTP_IB_END_" + phase.nonce + "__=0\n",
                        "wrong-nonce": "__HTTP_IB_AUTH_" + other_nonce + "_auth-probe-readonly__=BEGIN\n",
                        "wrong-operation": "__HTTP_IB_AUTH_" + phase.nonce + "_password-change__=BEGIN\n",
                        "truncated-marker": "__HTTP_IB_AUTH_" + phase.nonce + "_auth-probe-readonly__=EX",
                        "foreign-prompt": "admin@203.0.113.99's password: ",
                        "password-for": "Password for admin@fe80::999%en-other: ",
                    }
                    self.case.assertIn(conflict, mixtures)
                    diagnostic += mixtures[conflict]
                    truncated_tail = conflict == "truncated-marker"
                parts = [diagnostic]
            if index == 0 and split_warning:
                self.case.assertEqual("hostkey", mode)
                self.case.assertIsNone(conflict)
                first, rest = diagnostic.split("\n", 1)
                parts = [first + "\n", rest]
            config = directory / "config.json"
            config.write_text(json.dumps({"nonce": phase.nonce, "endpoint": endpoint,
                "diagnostic": diagnostic, "current": PUBLIC_REPLY, "body": BODY,
                "parts": parts, "truncated_tail": truncated_tail}), encoding="utf-8")
            config.chmod(0o600)
            active = {"index": index, "endpoint": endpoint, "phase": phase, "argv": list(argv),
                "directory": directory, "config": config, "diagnostic": diagnostic,
                "children": set(), "fds": set(), "reaps": [], "writes": [],
                "custody": _PtySignalCustody(),
                "read_bytes": b"", "observed": False, "result": None, "closed": False,
                "parts": parts, "parts_seen": [], "real_close": False, "close_injected": False}
            self.attempts.append(active)
            self.timeline.append(("ssh", endpoint))
            try:
                result = self._original_interactive(argv, responder, timeout, **kwargs)
                active["result"] = result
                return result
            finally:
                active["closed"] = True
                self.timeline.append(("finally", index))
        with mock.patch.object(self.app, "pty", _Facade(pty, fork=fork)), \
             mock.patch.object(self.app, "os", _Facade(os, execvp=execute, read=read,
                 write=write, close=close, kill=kill, killpg=killpg, waitpid=wait)), \
             mock.patch.object(self.app, "interactive_run", side_effect=interactive), \
             mock.patch.object(self.app, "record_metric", wraps=self.app.record_metric) as metrics:
            try:
                return self.call(endpoint=self.endpoint(IP, None) if ipv4 else self.endpoint(),
                    _phase_operation="auth-probe-readonly")
            finally:
                self.metric_calls = list(metrics.call_args_list)

    def assert_real_cleanup(self):
        """Check only actually created children; do not mask primary with wanted two."""
        for attempt in self.attempts:
            self.case.assertTrue(attempt["closed"])
            self.case.assertEqual(1, len(attempt["children"]))
            self.case.assertEqual(list(attempt["children"]), [pid for pid, _status in attempt["reaps"]])
            self.case.assertEqual(1, len(attempt["reaps"]))
            try:
                os.fstat(next(iter(attempt["fds"])))
            except OSError as error:
                self.case.assertEqual(9, error.errno, "only closed-fd EBADF proves real close")
            else:
                self.case.fail("original interactive finally left its owned PTY open")
            events_file = attempt["directory"] / "events.jsonl"
            attempt["events"] = ([json.loads(line) for line in events_file.read_text().splitlines()]
                                  if events_file.exists() else [])
            self.case.assertFalse(any(event["kind"] == "adapter-error" for event in attempt["events"]))


class DirectTransportWorkflowTests(unittest.TestCase):
    def test_real_phase_split_hostkey_warning_requires_both_active_reads(self):
        for ipv4, address in ((False, SCOPED), (True, IP)):
            with self.subTest(address=address), ActiveReadWorld(self) as world:
                caught = None
                try:
                    world.drive_active("hostkey", ipv4=ipv4, split_warning=True)
                except world.app.SetupError as error:
                    caught = error
                world.assert_real_cleanup()
                self.assertEqual(["admin@" + address], [a["endpoint"] for a in world.attempts])
                self.assertIsNotNone(caught)
                failure = world.app._ssh_failure_fact(caught)
                change = getattr(failure, "host_key_change", None)
                self.assertIsNotNone(change, "an early warning phrase must not prevent completing the bound warning")
                attempt = world.attempts[0]
                self.assertEqual([0, 1], attempt["parts_seen"])
                self.assertTrue(attempt["observed"])
                self.assertEqual([("diagnostic-part", 0), ("part-acknowledged", 0),
                    ("diagnostic-part", 1), ("part-acknowledged", 1)],
                    [(event["kind"], event["index"]) for event in attempt["events"]])
                self.assertEqual([], attempt["writes"])
                self.assertEqual(0, attempt["phase"].current_done)
                self.assertEqual({"current": 0, "new": 0, "retype": 0}, attempt["phase"].pam_counts)
                self.assertIs(type(change), world.paths.HostKeyChange)
                self.assertEqual((address, "ED25519", "SHA256:" + "B" * 43,
                    str(world.known_hosts), (1,), "local", None),
                    (change.address, change.key_type, change.new_fingerprint,
                     change.known_hosts_path, change.lines, change.location, change.jump))
                endpoint = failure._direct_endpoint
                self.assertEqual((IP, None) if ipv4 else (LL1, IFACE), (endpoint.address, endpoint.interface))
                records = []
                with self.assertRaises(world.app.SshFailure) as readonly:
                    world.app.refresh_ib_host_key(change,
                        world.app.PreparedIBTask(world.target(), endpoint, "", False),
                        eth_user="", timeout=2, apply=False, read_device_fingerprint=None,
                        retry=world.deny, operator_forced=False, host_key_records=records)
                self.assertIs(world.app.SshFailureKind.TARGET_HOST_KEY_CHANGED, readonly.exception.kind)
                self.assertIs(change, readonly.exception.host_key_change)
                self.assertEqual((0, [], [], world.known_before),
                    (world.neighbor_reads, world.keygen_calls, records, world.known_hosts.read_bytes()))

    def test_real_phase_network_close_failure_is_unknown_without_address_retry(self):
        with ActiveReadWorld(self) as world:
            caught = None
            try:
                world.drive_active("network", close_error=True)
            except world.app.SetupError as error:
                caught = error
            world.assert_real_cleanup()
            self.assertEqual(["admin@" + SCOPED], [a["endpoint"] for a in world.attempts])
            attempt = world.attempts[0]
            self.assertTrue(attempt["observed"])
            self.assertTrue(attempt["real_close"])
            self.assertTrue(attempt["close_injected"], "EIO is injected only after actual normal reap and close")
            self.assertEqual(255, os.waitstatus_to_exitcode(attempt["reaps"][0][1]))
            self.assertIsNotNone(caught, "network evidence cannot turn failed cleanup into successful replay")
            self.assertNotIsInstance(caught, world.app.IBAuthenticationError)
            self.assertIn("UNKNOWN", str(caught))
            self.assertEqual(5, getattr(caught, "io_errno", None))
            self.assertIsNone(getattr(world.app._ssh_failure_fact(caught), "host_key_change", None))
            self.assertEqual(([], 0, []), (attempt["writes"], world.neighbor_reads, world.keygen_calls))
            self.assertEqual([], [event for event in world.events if event[0] == "local"])

    def test_real_phase_foreign_or_partial_hostkey_warning_never_authorizes_refresh(self):
        for variant in ("foreign-ipv4", "same-ib-ipv4", "foreign-scope", "partial"):
            with self.subTest(variant=variant), ActiveReadWorld(self) as world:
                caught = None
                try:
                    world.drive_active("hostkey", conflict=variant)
                except world.app.SetupError as error:
                    caught = error
                world.assert_real_cleanup()
                self.assertEqual(["admin@" + SCOPED], [a["endpoint"] for a in world.attempts])
                attempt = world.attempts[0]
                self.assertTrue(attempt["observed"], "this complete variant must reach the real read")
                self.assertEqual([0], attempt["parts_seen"])
                self.assertIsNotNone(caught)
                self.assertNotIsInstance(caught, world.app.IBAuthenticationError)
                self.assertIn("UNKNOWN", str(caught))
                self.assertIsNone(getattr(world.app._ssh_failure_fact(caught), "host_key_change", None))
                self.assertEqual(([], 0, 0, [], world.known_before), (attempt["writes"],
                    attempt["phase"].current_done, world.neighbor_reads, world.keygen_calls, world.known_hosts.read_bytes()))
                self.assertEqual([], [event for event in world.events if event[0] == "local"])

    def test_real_phase_network_with_one_conflicting_fact_never_retries_or_sends_input(self):
        for variant in ("updated", "pam", "frame", "wrong-nonce", "wrong-operation",
                        "truncated-marker", "foreign-prompt", "password-for"):
            with self.subTest(variant=variant), ActiveReadWorld(self) as world:
                caught = None
                try:
                    world.drive_active("network", conflict=variant)
                except world.app.SetupError as error:
                    caught = error
                world.assert_real_cleanup()
                self.assertEqual(["admin@" + SCOPED], [a["endpoint"] for a in world.attempts])
                attempt = world.attempts[0]
                self.assertTrue(attempt["observed"], "named network AND this single conflicting payload must be read")
                self.assertEqual([0], attempt["parts_seen"])
                self.assertIsNotNone(caught)
                self.assertNotIsInstance(caught, world.app.IBAuthenticationError)
                self.assertIn("UNKNOWN", str(caught))
                self.assertIsNone(getattr(world.app._ssh_failure_fact(caught), "host_key_change", None))
                self.assertEqual(([], 0, 0, []), (attempt["writes"], attempt["phase"].current_done,
                    world.neighbor_reads, world.keygen_calls))
                self.assertEqual([], [event for event in world.events if event[0] == "local"])

    def test_real_phase_named_network_failure_falls_back_after_clean_reap(self):
        with ActiveReadWorld(self) as world:
            failure, result = None, None
            try:
                result = world.drive_active("network")
            except world.app.SetupError as error:
                failure = error
            world.assert_real_cleanup()
            self.assertTrue(world.attempts)
            first = world.attempts[0]
            self.assertTrue(first["read_bytes"], "real child must be read before its ack-gated exit")
            self.assertTrue(first["phase"].network, "original phase must have recognized the named diagnostic")
            self.assertEqual([], first["writes"])
            self.assertEqual(0, first["phase"].current_done)
            self.assertIsNone(failure, "safe named network failure must not terminate at generic phase refusal")
            self.assertTrue(first["observed"], "complete named failure must traverse active read before success")
            self.assertEqual(["admin@" + SCOPED, "admin@" + IP], [a["endpoint"] for a in world.attempts])
            self.assertEqual(2, len(world.attempts))
            second = world.attempts[1]
            self.assertNotEqual(first["phase"].nonce, second["phase"].nonce)
            self.assertEqual([(True, len(PUBLIC_REPLY.encode()) + 1)], second["writes"])
            self.assertEqual(1, second["phase"].current_done)
            self.assertEqual(1, world.neighbor_reads)
            self.assertEqual([("local", ("ip", "-4", "neigh", "show", IP))],
                [event for event in world.events if event[0] == "local"])
            self.assertEqual([("ssh", "admin@" + SCOPED), ("fork", 0), ("active-read", 0),
                ("reap", 0), ("finally", 0), ("neighbor", IP),
                ("ssh", "admin@" + IP), ("fork", 1), ("reap", 1), ("finally", 1)], world.timeline)
            self.assertEqual(2, sum(call == mock.call("ib_ssh_attempts") for call in world.metric_calls))
            self.assertIs(type(result), world.app.SessionResult)
            self.assertEqual((BODY, 0), (result.output, result.exit_code))
            self.assertEqual((False, False, False, False), (result.password_changed,
                result.password_change_required, result.password_change_attempted, result.ib_authentication_rejected))
            self.assertEqual((IP, None), (result._direct_endpoint.address, result._direct_endpoint.interface))
            for attempt in world.attempts:
                self.assertEqual({"current": 0, "new": 0, "retype": 0}, attempt["phase"].pam_counts)
            self.assertEqual(["current-input", "finish"], [event["kind"] for event in second["events"]])

    def test_real_phase_hostkey_warning_preserves_attempt_and_readonly_never_removes(self):
        for ipv4, address in ((False, SCOPED), (True, IP)):
            with self.subTest(address=address), ActiveReadWorld(self) as world:
                caught = None
                try:
                    world.drive_active("hostkey", ipv4=ipv4)
                except world.app.SetupError as error:
                    caught = error
                world.assert_real_cleanup()
                self.assertEqual(["admin@" + address], [a["endpoint"] for a in world.attempts])
                self.assertTrue(world.attempts[0]["read_bytes"], "real child must be read before its ack-gated exit")
                self.assertTrue(world.attempts[0]["phase"].network, "original phase must recognize warning diagnostic")
                self.assertEqual([], world.attempts[0]["writes"])
                self.assertEqual(0, world.attempts[0]["phase"].current_done)
                self.assertEqual(0, world.neighbor_reads)
                self.assertEqual([], [event for event in world.events if event[0] == "local"])
                self.assertIsNotNone(caught, "host-key warning is not a successful read")
                failure = world.app._ssh_failure_fact(caught)
                change = getattr(failure, "host_key_change", None)
                self.assertIsNotNone(change, "real phase must preserve parsed current host-key facts, not generic refusal")
                self.assertTrue(world.attempts[0]["observed"], "complete warning must traverse active PTY read")
                self.assertIs(type(change), world.paths.HostKeyChange)
                self.assertEqual((address, "ED25519", "SHA256:" + "B" * 43, str(world.known_hosts), (1,), "local", None),
                    (change.address, change.key_type, change.new_fingerprint, change.known_hosts_path,
                     change.lines, change.location, change.jump))
                endpoint = failure._direct_endpoint
                self.assertIs(type(endpoint), world.app.DirectEndpoint)
                self.assertEqual((IP, None) if ipv4 else (LL1, IFACE), (endpoint.address, endpoint.interface))
                records = []
                task = world.app.PreparedIBTask(world.target(), endpoint, "", False)
                with self.assertRaises(world.app.SshFailure) as readonly:
                    world.app.refresh_ib_host_key(change, task, eth_user="", timeout=2, apply=False,
                        read_device_fingerprint=None, retry=world.deny, operator_forced=False, host_key_records=records)
                self.assertIs(world.app.SshFailureKind.TARGET_HOST_KEY_CHANGED, readonly.exception.kind)
                self.assertIs(change, readonly.exception.host_key_change)
                self.assertEqual(world.known_before, world.known_hosts.read_bytes())
                self.assertEqual([], world.keygen_calls)
                self.assertEqual([], records)
                self.assertEqual(1, sum(call == mock.call("ib_ssh_attempts") for call in world.metric_calls))

    def test_public_phase_argv_binding_accepts_only_manager_and_remote_frame_roles(self):
        argv, ssh = _public_phase_vector()
        words, endpoint = assert_phase_argv_binding(self, argv,
            nonce="0123456789abcdef0123456789abcdef", operation="auth-probe-readonly",
            endpoint="admin@fe80::ff:fe00:10%en-public7")
        self.assertEqual(ssh, words)
        self.assertEqual("admin@fe80::ff:fe00:10%en-public7", endpoint)

    def test_public_phase_argv_binding_rejects_relocated_or_misbound_markers(self):
        argv, ssh = _public_phase_vector()
        correct_nonce = "0123456789abcdef0123456789abcdef"
        wrong_nonce = "fedcba9876543210fedcba9876543210"
        begin, remainder = argv[2].split("; ", 1)
        suffix = argv[2][len(begin + "; ") + len(shlex.join(ssh)):]
        relocated = list(ssh)
        relocated[-1] = shlex.join(["sh", "-c", begin + "; " + shlex.split(ssh[-1])[2]])
        models = [
            ("plain-ssh", ssh, "phase requires manager-side shell"),
            ("begin-moved-to-remote", ["sh", "-c", shlex.join(relocated) + suffix], "exact management BEGIN"),
            ("manager-prefix-nonce", ["sh", "-c", begin.replace(correct_nonce, wrong_nonce) + "; " + remainder], "exact management BEGIN"),
            ("manager-prefix-op", ["sh", "-c", begin.replace("auth-probe-readonly", "password-change") + "; " + remainder], "exact management BEGIN"),
            ("manager-suffix-nonce", ["sh", "-c", argv[2].rsplit("__HTTP_IB_AUTH_", 1)[0]
                + "__HTTP_IB_AUTH_" + argv[2].rsplit("__HTTP_IB_AUTH_", 1)[1].replace(correct_nonce, wrong_nonce)], "exact management EXIT"),
        ]
        remote_bad = list(ssh)
        remote_bad[-1] = shlex.join(["sh", "-c", shlex.split(ssh[-1])[2].replace(correct_nonce, wrong_nonce)])
        models.append(("remote-frame-nonce", ["sh", "-c", argv[2].replace(shlex.join(ssh), shlex.join(remote_bad), 1)], "remote command frame is exact"))
        remote_phase = list(ssh)
        remote_phase[-1] = shlex.join(["sh", "-c", begin + "; " + shlex.split(ssh[-1])[2]])
        models.append(("extra-begin-in-remote", ["sh", "-c", argv[2].replace(shlex.join(ssh), shlex.join(remote_phase), 1)], "remote command frame is exact"))
        for model, candidate, first_binding in models:
            with self.subTest(model=model), self.assertRaisesRegex(AssertionError, first_binding):
                assert_phase_argv_binding(self, candidate, nonce=correct_nonce,
                    operation="auth-probe-readonly", endpoint="admin@fe80::ff:fe00:10%en-public7")

    def test_real_main_csv_m4_login_path_task_and_execute_consume_direct_read(self):
        with DirectWorld(self) as world:
            require_api(world.app)
            main_body = ("nv set system hostname example-ib01\n"
                "nv set service lldp state enabled\n"
                "nv set interface eth0 ipv4 address 192.0.2.10/24\n"
                "nv set interface eth0 ipv4 gateway 192.0.2.1\n"
                "nv set interface eth0-1 link state up\n"
                "nv set interface eth0-1 type eth\n")
            issued = []
            def main_readback(argv, responder, timeout, **kwargs):
                return world.main_readback(argv, responder, timeout, nv_config=main_body,
                                           seen=issued, **kwargs)
            row = [IB1, "ib", IP, "24", "192.0.2.1", MAC1]
            for path in (world.csv, world.master):
                with path.open("w", newline="") as handle:
                    writer = csv.writer(handle); writer.writerow(HEADER)
                    writer.writerow(row + [""] * (len(HEADER) - len(row)))
            world.p2p.write_text("a-node,a-port,z-node,z-port\nexample-unselected-ib99,eth0,example-unselected-leaf99,swp7\n", encoding="utf-8")
            observed, reads, entered = {}, [], set()
            required_callers = {"tools.device_identity": "main", "tools.hostname_ranges": "main",
                "tools.login_path": "main", "tools.inventory_subset": "_compare_inventory"}
            module_returns = {}
            def profile(frame, event, value):
                name = frame.f_code.co_name
                if event == "call" and frame.f_code.co_filename.startswith(str(ROOT / "tools") + os.sep):
                    entered.add(Path(frame.f_code.co_filename).name)
                if frame.f_globals is not world.app.__dict__:
                    return
                if event == "return" and name == "_import_tools":
                    requested = frame.f_locals.get("name")
                    caller = frame.f_back
                    if (requested in required_callers and caller is not None
                            and caller.f_globals is world.app.__dict__
                            and caller.f_code.co_name == required_callers[requested]):
                        module_returns.setdefault(requested, []).append(value)
                if event == "call" and name == "run_prepared_tasks":
                    observed["tasks"] = tuple(frame.f_locals["tasks"])
                    world.expected_device_prefix = "devices-" + frame.f_locals["args"].run_stamp + "-"
                if event == "call" and name == "execute_ib_task":
                    observed["execute"] = frame.f_locals["task"]
                if (event == "return" and name == "run_on_ib" and type(value) is world.app.SessionResult
                        and frame.f_locals["ib_command"] == READ):
                    reads.append(value)
                if event == "call" and name == "run_initial_stage":
                    observed["consumed"] = frame.f_locals["current"]
                    raise _WP3Checkpoint()
            output, previous = io.StringIO(), sys.getprofile()
            argv = [str(INITIAL), "--project-dir", str(world.project), "--p2p", str(world.p2p),
                "--report", str(world.root / "report.log"), "--target-cache", str(world.root / "targets.json"),
                "--snapshot-dir", str(world.root / "snapshots"), "--execution-mode", "management", "--max-workers", "1"]
            try:
                with mock.patch.object(sys, "argv", argv), \
                     mock.patch.object(world.app, "interactive_run", side_effect=main_readback), \
                     redirect_stdout(output), redirect_stderr(output):
                    sys.setprofile(profile)
                    with self.assertRaises(_WP3Checkpoint):
                        world.app.main()
            finally:
                sys.setprofile(previous)
                if world.app.REPORT_HANDLE is not None:
                    world.app.REPORT_HANDLE.close(); world.app.REPORT_HANDLE = None
            self.assertEqual(1, len(observed["tasks"]))
            task = observed["tasks"][0]
            self.assertIs(task, observed["execute"])
            self.assertIsNone(task.target.ethernet)
            self.assertEqual("", task.ethernet_password)
            self.assertFalse(task.local, "management direct is not a pretend Leaf-local task")
            self.assertIs(type(task.neighbor), world.app.DirectEndpoint)
            self.assertEqual((LL1, IFACE), (task.neighbor.address, task.neighbor.interface))
            self.assertEqual(1, len(reads))
            self.assertIs(type(reads[0]), world.app.SessionResult)
            self.assertEqual(main_body, observed["consumed"])
            self.assertEqual(main_body, reads[0].output)
            self.assertEqual((LL1, IFACE), (reads[0]._direct_endpoint.address, reads[0]._direct_endpoint.interface))
            self.assertEqual(set(required_callers), set(module_returns), "each mandatory tool needs this run's real loader return")
            for module_name, values in module_returns.items():
                self.assertEqual(1, len(values), "one qualified mandatory load per fixed caller")
                module = values[0]
                self.assertIs(type(module), type(sys))
                self.assertEqual(module_name, module.__name__)
                self.assertIs(module, sys.modules[module_name])
                self.assertEqual((ROOT / "tools" / (module_name.split(".")[1] + ".py")).resolve(),
                    Path(module.__file__).resolve())
            self.assertTrue({"inventory_subset.py", "device_identity.py", "login_path.py"} <= entered)
            self.assertEqual([("admin@" + SCOPED, READ),
                              ("admin@" + SCOPED, ["ip", "addr", "show", "eth0"]),
                              ("admin@" + SCOPED, ["nv", "show", "system", "ztp"])], issued)
            self.assertEqual(["admin@" + SCOPED] * 3, world.ssh_calls)
            self.assertFalse(any(event[0] == "master" for event in world.events))
            self.assertIsNone(world.app._ACTIVE_COORDINATOR)
            self.assertIsNone(world.app._TASK_DEADLINE)
            self.assertIsNone(world.app._TASK_LOG_BUFFER)

    def test_real_phase_authentication_and_post_change_read_each_use_one_endpoint(self):
        for operation in ("auth-probe-readonly", "post-change-read"):
            with self.subTest(operation=operation), PhaseWorld(self) as world:
                policy = world.policy() if operation == "post-change-read" else None
                current = world.kat["PASSWORD"] if policy else PUBLIC_REPLY
                result = world.drive(operation=operation, policy=policy, current=current)
                self.assertEqual(BODY, result.output)
                self.assertEqual(0, result.exit_code)
                self.assertFalse(any((result.password_changed, result.password_change_required, result.password_change_attempted)))
                self.assertEqual(1, world.phase_facts["phases"][0].current_done)
                self.assertEqual(["current-input", "finish"], [event["kind"] for event in world.phase_facts["events"]])
                self.assertIs(type(result._direct_endpoint), world.app.DirectEndpoint)

    def test_real_phase_rejects_only_completed_endpoint_attributable_denial(self):
        with PhaseWorld(self) as world:
            with self.assertRaises(world.app.IBAuthenticationError):
                world.drive("reject")
            self.assertEqual([("current", len(PUBLIC_REPLY.encode()) + 1)], world.phase_facts["writes"])
            self.assertEqual(1, world.phase_facts["phases"][0].current_done)

    def test_real_phase_bare255_wrong_markers_endpoint_and_missing_exit_are_unknown(self):
        for case in ("bare255", "wrong-nonce", "wrong-operation", "wrong-endpoint", "missing-exit"):
            with self.subTest(case=case), PhaseWorld(self) as world:
                with self.assertRaises(world.app.SetupError) as caught:
                    world.drive(case)
                self.assertNotIsInstance(caught.exception, world.app.IBAuthenticationError)
                self.assertEqual(0, world.neighbor_reads, "unknown phase result cannot authorize IPv4 replay")

    def test_real_phase_foreign_or_bare_outer_prompt_never_receives_input(self):
        for case in ("foreign-ipv4", "foreign-ipv6", "bare-outer"):
            with self.subTest(case=case), PhaseWorld(self) as world:
                with self.assertRaises(world.app.SetupError) as caught:
                    world.drive(case)
                self.assertNotIsInstance(caught.exception, world.app.IBAuthenticationError)
                self.assertEqual([], world.phase_facts["writes"], "not even newline/empty outer credential")
                self.assertEqual(0, world.phase_facts["phases"][0].current_done)

    def test_real_phase_incomplete_current_write_is_unknown_not_authentication_rejection(self):
        with PhaseWorld(self) as world:
            with self.assertRaises(world.app.SetupError) as caught:
                world.drive("reject", write_fault="short-zero")
            self.assertNotIsInstance(caught.exception, world.app.IBAuthenticationError)
            self.assertEqual(0, world.phase_facts["phases"][0].current_done)
            self.assertEqual([("partial-current", 2), ("zero-current", 0)], world.phase_facts["writes"])

    def test_real_readonly_expiry_cancels_before_pam_writes(self):
        with PhaseWorld(self) as world:
            result = world.drive("expiry-readonly")
            self.assertTrue(result.password_change_required)
            self.assertFalse(result.password_changed)
            self.assertEqual([("current", len(PUBLIC_REPLY.encode()) + 1)], world.phase_facts["writes"])
            self.assertFalse(any(event["kind"] in {"pam-new", "pam-confirm"} for event in world.phase_facts["events"]))

    def test_real_password_change_retains_same_project_pam_and_current_input(self):
        with PhaseWorld(self) as world:
            policy = world.policy()
            result = world.drive("pam", "password-change", policy=policy,
                allow=True, new=world.kat["PASSWORD"])
            self.assertTrue(result.password_changed)
            self.assertFalse(result.password_change_required)
            self.assertEqual(["current-input", "pam-current", "pam-new", "pam-confirm", "finish"],
                [event["kind"] for event in world.phase_facts["events"]])
            self.assertEqual(["current", "current", "target", "target"], [kind for kind, _amount in world.phase_facts["writes"]])
            self.assertGreater(world.real_native_calls, 0)

    def test_real_pam_fixed_eight_second_reserve_refuses_before_pam_input(self):
        with PhaseWorld(self) as world:
            policy = world.policy()
            with self.assertRaises(world.app.SetupError) as caught:
                world.drive("pam", "password-change", policy=policy, allow=True,
                    new=world.kat["PASSWORD"], budget_short=True)
            self.assertNotIsInstance(caught.exception, world.app.IBAuthenticationError)
            self.assertEqual([("current", len(PUBLIC_REPLY.encode()) + 1)], world.phase_facts["writes"])
            self.assertFalse(world.phase_facts["phases"][0].pam_current_done)

    def test_real_pam_rechecks_changed_project_before_any_pam_input(self):
        with PhaseWorld(self) as world:
            policy = world.policy()
            before = policy.path.read_bytes()
            with self.assertRaises(world.app.SetupError) as caught:
                world.drive("pam", "password-change", policy=policy, allow=True,
                    new=world.kat["PASSWORD"], change_project=True)
            error = caught.exception
            self.assertIs(type(error), world.app.SetupError)
            self.assertEqual(("IB phase project authority failed; device state is UNKNOWN",), error.args)
            self.assertNotIsInstance(error, world.app.IBAuthenticationError)
            self.assertIsNone(error.__cause__)
            self.assertIsNone(error.__context__)
            self.assertTrue(policy.path.read_bytes() == before
                + b"\n# PUBLIC same-project mutation at the current/PAM boundary\n",
                "this drive must actually change its owned project before the first PAM input")
            self.assertEqual([("current", len(PUBLIC_REPLY.encode()) + 1)], world.phase_facts["writes"])
            self.assertFalse(world.phase_facts["phases"][0].pam_current_done)

    def test_model_does_not_mutate_shared_clock_or_euid(self):
        sleep, monotonic, geteuid = time.sleep, time.monotonic, os.geteuid
        with DirectWorld(self) as world:
            self.assertIs(sleep, time.sleep)
            self.assertIs(monotonic, time.monotonic)
            self.assertIs(geteuid, os.geteuid)
            self.assertIsNot(world.app.time, time)
            self.assertEqual(world.root.parent, Path(os.environ["HTTP_TEST_OWNED_ROOT"]))
        self.assertIs(sleep, time.sleep)
        self.assertIs(monotonic, time.monotonic)
        self.assertIs(geteuid, os.geteuid)


if __name__ == "__main__":
    unittest.main()
