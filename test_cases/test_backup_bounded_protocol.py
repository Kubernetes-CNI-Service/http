"""Independent literal contracts for the canonical bounded backup peers.

Protocol10, attachment priority1 and deadline/EOF2 retain their original
handwritten expectations. Subject paths select fixed repository siblings only.
"""
from contextlib import ExitStack
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / "ztp/backup"
SOURCE = HERE / "_bounded_process.py"


def candidate(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        del sys.modules[name]
    return module


class TrustedProbeProtocolCandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parent = candidate("_h_parent_candidate", "_bounded_process.py")
        cls.launcher = candidate("_h_launcher_candidate", "_bounded_process_launcher.py")

    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)

        def forbidden(*_args, **_kwargs):
            raise AssertionError("real kernel/process/network/thread/sleep forbidden")

        for module, name in (
            (subprocess, "Popen"), (subprocess, "run"),
            (os, "pipe"), (os, "fork"), (os, "posix_spawn"),
            (os, "posix_spawnp"), (os, "execv"), (os, "execve"),
            (os, "kill"), (os, "killpg"), (os, "waitpid"),
            (os, "getpid"), (os, "getppid"), (os, "getpgid"),
            (os, "getsid"), (os, "setsid"), (os, "setpgid"),
            (os, "write"), (os, "close"), (os, "read"),
            (socket, "socket"), (socket, "create_connection"),
            (threading.Thread, "__init__"), (threading.Thread, "start"),
            (time, "sleep"),
        ):
            if hasattr(module, name):
                stack.enter_context(mock.patch.object(module, name, forbidden))

    def test_independent_wait17_frame_and_no_numeric_authority(self):
        nonce = b"0123456789abcdef"
        # Hand-written wire: HAP1, nonce16, child PID81235, waitstatus17<<8.
        wire = b"HAP10123456789abcdef\x00\x01\x3d\x53\x00\x00\x11\x00"
        expected = {"command_pid": 81235, "wait_status": 4352, "returncode": 17}
        self.assertEqual(expected, self.parent.parse_status(wire, nonce))
        self.assertEqual(wire, self.launcher.status_frame(nonce, 81235, 4352))
        for invalid in (wire[:-1], wire + b"X", b"BAD!" + wire[4:]):
            with self.subTest(invalid_length=len(invalid)), self.assertRaises(ValueError):
                self.parent.parse_status(invalid, nonce)
        with self.assertRaises(ValueError):
            self.parent.parse_status(wire, b"xxxxxxxxxxxxxxxx")

    def test_request_literal_schema_duplicate_trailing_and_env_semantics(self):
        # This independent length is deliberately computed from the literal,
        # not from an implementation encoder or a runtime command result.
        payload = b'{"argv":["/literal","-V"],"env":{},"env_mode":"EXPLICIT"}'
        raw = len(payload).to_bytes(4, "big") + payload
        self.assertEqual({"argv": ["/literal", "-V"], "env": {},
                          "env_mode": "EXPLICIT"}, self.launcher.parse_request(raw))
        with mock.patch.dict(self.parent.os.environ, {"ONLY": "parent"}, clear=True):
            inherited = self.launcher.parse_request(self.parent.pack_request(["/literal"], None))
            explicit = self.launcher.parse_request(self.parent.pack_request(["/literal"], {}))
        self.assertEqual({"ONLY": "parent"}, inherited["env"])
        self.assertEqual("INHERITED_SNAPSHOT", inherited["env_mode"])
        self.assertEqual({}, explicit["env"])
        self.assertEqual("EXPLICIT", explicit["env_mode"])
        original_argv = ["/literal", "", "--", "space 'quote' \\slash"]
        self.assertEqual(original_argv, self.launcher.parse_request(
            self.parent.pack_request(original_argv, {}))["argv"])
        for invalid_argv in ([""], ["/literal", "bad\0arg"]):
            with self.subTest(invalid_argv_length=len(invalid_argv)), self.assertRaises(ValueError):
                self.parent.pack_request(invalid_argv, {})
        duplicate = b'{"argv":["/literal"],"env":{},"env":{},"env_mode":"EXPLICIT"}'
        for invalid in (raw + b"X", raw[:-1],
                        (len(payload) + 1).to_bytes(4, "big") + payload + b"\n",
                        len(duplicate).to_bytes(4, "big") + duplicate,
                        (1048577).to_bytes(4, "big") + b"x"):
            with self.subTest(length=len(invalid)), self.assertRaises(ValueError):
                self.launcher.parse_request(invalid)
        with self.assertRaises(ValueError):
            self.parent.pack_request(["/literal"], {"X": "x" * 1048577})

    def test_stdio_EOF_alone_is_not_command_exit_or_group_cleanup(self):
        state = self.parent.DrainState(b"0123456789abcdef")
        state.feed("stdout", b"")
        state.feed("stderr", b"")
        self.assertTrue(state.output_EOF)
        self.assertFalse(state.command_exited)
        self.assertIsNone(state.command_status)
        state.feed("status", b"HAP10123456789abcdef\x00\x01\x3d\x53\x00\x00\x11\x00")
        self.assertTrue(state.command_exited)
        self.assertEqual(17, state.command_status["returncode"])
        overflow = self.parent.DrainState(b"0123456789abcdef")
        overflow.feed("stdout", b"x" * 65537)
        self.assertEqual(65536, len(overflow.stdout))
        self.assertEqual("overflow", overflow.stop_reason)

    def test_outer_private_two_fds_inner_zero_and_original_env(self):
        outer = self.parent.outer_kwargs(10, 13, None)
        self.assertEqual((10, 13), outer["pass_fds"])
        self.assertIs(outer["close_fds"], True)
        self.assertIs(outer["start_new_session"], True)
        request = {"argv": ["/literal", "-G"], "env": {"ONLY": "original"},
                   "env_mode": "EXPLICIT"}
        inner = self.launcher.command_kwargs(request)
        self.assertEqual((), inner["pass_fds"])
        self.assertIs(inner["close_fds"], True)
        self.assertIs(inner["start_new_session"], False)
        self.assertEqual({"ONLY": "original"}, inner["env"])
        self.assertEqual((0, 1, 2), (inner["stdin"], inner["stdout"], inner["stderr"]))

    def test_signal_before_anchor_wait_keeps_command17_separate(self):
        events = []

        class Process:
            pid = 81234
            returncode = None
            _child_created = True

        process = Process()
        with mock.patch.object(self.parent, "_Popen", Process):
            reservation = self.parent.Reservation(process, _token=self.parent._SPAWN_TOKEN)

            def killpg(pid, sig):
                self.assertEqual((81234, signal.SIGKILL), (pid, sig))
                self.assertFalse(reservation.wait_started)
                events.append("GROUP_SIGKILL")

            def waitpid(pid, flags):
                self.assertEqual(["GROUP_SIGKILL"], events)
                self.assertEqual((81234, self.parent.os.WNOHANG), (pid, flags))
                events.append("ANCHOR_WAIT")
                return 81234, 9

            log = self.parent.CleanupLog()
            with mock.patch.object(self.parent.os, "killpg", side_effect=killpg), \
                    mock.patch.object(self.parent.os, "waitpid", side_effect=waitpid):
                self.parent.finish(reservation, None, log, [], [])
        self.assertEqual(["GROUP_SIGKILL", "ANCHOR_WAIT"], events)
        self.assertTrue(reservation.reaped)
        self.assertEqual(-9, process.returncode)
        command = {"command_pid": 81235, "wait_status": 4352, "returncode": 17}
        self.assertEqual(17, self.parent.effective_returncode(command, None))
        self.assertEqual(124, self.parent.effective_returncode(None, "timeout"))
        self.assertEqual(125, self.parent.effective_returncode(None, "overflow"))
        self.assertEqual([], log.errors)

    def test_lost_anchor_never_resignals_and_cleanup_NI_priority(self):
        class Process:
            pid = 81234
            returncode = None
            _child_created = True

        with mock.patch.object(self.parent, "_Popen", Process):
            process = Process()
            with self.assertRaises(ValueError):
                self.parent.Reservation(process)
            reservation = self.parent.Reservation(process, _token=self.parent._SPAWN_TOKEN)
            process.returncode = 17  # Original reservation was already reaped.
            primary = ValueError("original ordinary")
            log = self.parent.CleanupLog()
            with mock.patch.object(self.parent.os, "killpg") as kill, \
                    mock.patch.object(self.parent.os, "waitpid") as wait:
                with self.assertRaises(ValueError) as raised:
                    self.parent.finish(reservation, primary, log, [], [])
            self.assertIs(primary, raised.exception)
            kill.assert_not_called()
            wait.assert_not_called()
            self.assertTrue(reservation.lost)

        with mock.patch.object(self.parent, "_Popen", Process):
            process = Process()
            reservation = self.parent.Reservation(process, _token=self.parent._SPAWN_TOKEN)
            lost = ChildProcessError(10, "literal ECHILD")
            log = self.parent.CleanupLog()
            with mock.patch.object(self.parent.os, "killpg") as kill, \
                    mock.patch.object(self.parent.os, "waitpid", side_effect=lost) as wait:
                with self.assertRaises(ChildProcessError) as raised:
                    self.parent.finish(reservation, None, log, [], [])
            self.assertIs(lost, raised.exception)
            self.assertEqual(1, kill.call_count)
            self.assertEqual(1, wait.call_count)
            self.assertTrue(reservation.lost)
            self.assertIsNone(process.returncode)

        for original_interrupt in (False, True):
            with self.subTest(original_interrupt=original_interrupt), \
                    mock.patch.object(self.parent, "_Popen", Process):
                process = Process()
                reservation = self.parent.Reservation(process, _token=self.parent._SPAWN_TOKEN)
                cause = RuntimeError("literal cause")
                original = KeyboardInterrupt() if original_interrupt else ValueError("primary")
                original.__cause__ = cause
                group_error = OSError("group")
                new_NI = KeyboardInterrupt()
                events = []
                stdout = types.SimpleNamespace(closed=False, fileno=lambda: 71,
                    close=lambda: (_ for _ in ()).throw(new_NI))
                stderr = types.SimpleNamespace(closed=False, fileno=lambda: 72,
                    close=lambda: events.append("stderr closed"))
                def literal_fstat(fd):
                    return types.SimpleNamespace(st_dev=7, st_ino=fd, st_mode=4480,
                                                 st_uid=501, st_gid=20)
                log = self.parent.CleanupLog()
                with mock.patch.object(self.parent.os, "killpg", side_effect=group_error), \
                        mock.patch.object(self.parent.os, "waitpid", return_value=(81234, 9)), \
                        mock.patch.object(self.parent.os, "fstat", side_effect=literal_fstat):
                    with self.assertRaises(KeyboardInterrupt) as raised:
                        self.parent.finish(reservation, original, log, [],
                            [("stdout", stdout, (7,71,4480,501,20)),
                             ("stderr", stderr, (7,72,4480,501,20))])
                self.assertIs(original if original_interrupt else new_NI, raised.exception)
                self.assertIs(cause, original.__cause__)
                self.assertEqual(["stderr closed"], events)
                self.assertEqual([("group", group_error), ("stdout", new_NI)], log.errors)

    def test_partial_request_writes_are_nonblocking_inside_original_deadline(self):
        events = []
        registered = {}

        class Selector:
            def register(self, fd, event, role):
                registered[fd] = role

            def unregister(self, fd):
                del registered[fd]

            def select(self, timeout):
                self_timeout = timeout
                events.append(("SELECT", self_timeout))
                return [(types.SimpleNamespace(fd=11, data="request"), 2)]

            def close(self):
                events.append(("SELECTOR_CLOSE",))

        process = types.SimpleNamespace(stdin=None,
            stdout=types.SimpleNamespace(fileno=lambda: 71),
            stderr=types.SimpleNamespace(fileno=lambda: 72))
        reservation = types.SimpleNamespace(signal_attempted=False, pid=81234)
        state = self.parent.DrainState(b"0123456789abcdef")
        writes = []

        def write(fd, part):
            writes.append((fd, bytes(part)))
            events.append(("WRITE", fd))
            if len(writes) == 1:
                return 3
            raise BlockingIOError()

        log = self.parent.CleanupLog()
        with mock.patch.object(self.parent.selectors, "DefaultSelector", return_value=Selector()), \
                mock.patch.object(self.parent.os, "set_blocking") as blocking, \
                mock.patch.object(self.parent.os, "write", side_effect=write), \
                mock.patch.object(self.parent.time, "monotonic", side_effect=[0.0, 0.2, 1.0]):
            self.parent._drive(process, reservation, 11, 12, b"literal-request",
                               None, 1.0, state, log)
        self.assertEqual([(11, b"literal-request"), (11, b"eral-request")], writes)
        self.assertEqual([mock.call(71, False), mock.call(72, False),
                          mock.call(12, False), mock.call(11, False)], blocking.call_args_list)
        self.assertEqual(["SELECT", "WRITE", "SELECT", "WRITE", "SELECTOR_CLOSE"],
                         [item[0] for item in events])
        self.assertEqual("timeout", state.stop_reason)
        self.assertIsNone(state.command_status)
        self.assertEqual(124, self.parent.effective_returncode(None, state.stop_reason))
        self.assertEqual([], log.errors)

        original_NI = KeyboardInterrupt()
        cause = RuntimeError("literal request interruption cause")
        original_NI.__cause__ = cause
        events.clear()
        interrupted = self.parent.DrainState(b"0123456789abcdef")
        with mock.patch.object(self.parent.selectors, "DefaultSelector", return_value=Selector()), \
                mock.patch.object(self.parent.os, "set_blocking"), \
                mock.patch.object(self.parent.os, "write", side_effect=original_NI), \
                mock.patch.object(self.parent.time, "monotonic", return_value=0.0):
            with self.assertRaises(KeyboardInterrupt) as raised:
                self.parent._drive(process, reservation, 11, 12, b"literal-request",
                                   None, 1.0, interrupted, self.parent.CleanupLog())
        self.assertIs(original_NI, raised.exception)
        self.assertIs(cause, original_NI.__cause__)
        self.assertEqual("SELECTOR_CLOSE", events[-1][0])

    def test_all_four_protocol_fd_closes_attempted_without_losing_primary_NI(self):
        primary = KeyboardInterrupt()
        cause = ValueError("literal cause")
        primary.__cause__ = cause
        first_close = OSError("request read close")
        later_NI = KeyboardInterrupt()
        labels = ["request_read", "request_write", "status_read", "status_write"]
        holds = [(name, [fd, (7, fd, 4480, 501, 20), False])
                 for name, fd in zip(labels, (10, 11, 12, 13))]
        def fstat(fd):
            return types.SimpleNamespace(st_dev=7, st_ino=fd, st_mode=4480,
                                         st_uid=501, st_gid=20)
        log = self.parent.CleanupLog()
        with mock.patch.object(self.parent.os, "fstat", side_effect=fstat), \
                mock.patch.object(self.parent.os, "close",
                                  side_effect=[first_close, None, later_NI, None]) as close:
            with self.assertRaises(KeyboardInterrupt) as raised:
                self.parent.finish(None, primary, log, holds, [])
        self.assertIs(primary, raised.exception)
        self.assertIs(cause, primary.__cause__)
        self.assertEqual([mock.call(10), mock.call(11), mock.call(12), mock.call(13)],
                         close.call_args_list)
        self.assertEqual([("request_read", first_close), ("status_read", later_NI)], log.errors)
        self.assertEqual([("request_read", "CLOSE_ATTEMPT", 10),
                          ("request_write", "CLOSE_ATTEMPT", 11),
                          ("request_write", "CLOSE_RETURN", 11),
                          ("status_read", "CLOSE_ATTEMPT", 12),
                          ("status_write", "CLOSE_ATTEMPT", 13),
                          ("status_write", "CLOSE_RETURN", 13)], log.fd_events)

    def test_observed_command_exit_with_open_descendant_pipe_keeps_timeout_contract(self):
        frame = b"HAP10123456789abcdef\x00\x01\x3d\x53\x00\x00\x11\x00"
        selected = [12, 71]
        class Selector:
            def register(self, *_args):
                pass
            def select(self, _timeout):
                fd = selected.pop(0)
                return [(types.SimpleNamespace(fd=fd,
                         data="status" if fd == 12 else "stdout"), 1)]
            def close(self):
                pass
        process = types.SimpleNamespace(stdin=None,
            stdout=types.SimpleNamespace(fileno=lambda: 71),
            stderr=types.SimpleNamespace(fileno=lambda: 72))
        reservation = types.SimpleNamespace(signal_attempted=False, pid=81234)
        state = self.parent.DrainState(b"0123456789abcdef")
        with mock.patch.object(self.parent.selectors, "DefaultSelector", return_value=Selector()), \
                mock.patch.object(self.parent.os, "set_blocking"), \
                mock.patch.object(self.parent.os, "read", side_effect=[frame, b"literal-output\n"]), \
                mock.patch.object(self.parent.time, "monotonic", side_effect=[0.0, 0.2, 1.0]), \
                mock.patch.object(self.parent, "signal_original_group") as signal_group:
            self.parent._drive(process, reservation, 11, 12, b"literal-request",
                               None, 1.0, state, self.parent.CleanupLog())
        self.assertEqual(17, state.command_status["returncode"])
        self.assertFalse(state.output_EOF)
        self.assertEqual("timeout", state.stop_reason)
        self.assertEqual(124, self.parent.effective_returncode(state.command_status,
                                                            state.stop_reason))
        signal_group.assert_not_called()

    def test_nonfinite_timeout_and_launcher_deadline_refuse_before_resources(self):
        nonce = "30313233343536373839616263646566"
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(nonfinite=True), \
                    mock.patch.object(self.parent.signal, "getsignal", return_value=signal.SIG_DFL), \
                    mock.patch.object(self.parent.os, "pipe") as pipe:
                with self.assertRaises(ValueError):
                    self.parent.run_bounded_anchored(["/literal"], value, env={})
                pipe.assert_not_called()
                with self.assertRaises(ValueError):
                    self.launcher.parse_launch_arguments(
                        ["launcher", "10", "13", nonce, str(value)])


class AnchorAttachPriorityLiteralTests(unittest.TestCase):
    def test_new_attach_NI_supersedes_ordinary_but_not_original_NI(self):
        path = SOURCE
        spec = importlib.util.spec_from_file_location("_h_attach_subject", path)
        subject = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = subject
        try:
            spec.loader.exec_module(subject)
        finally:
            del sys.modules[spec.name]

        def forbidden(*_args, **_kwargs):
            raise AssertionError("real kernel/process/network/thread/sleep forbidden")

        for original_interrupt in (False, True):
            with self.subTest(original_interrupt=original_interrupt):
                events = []
                new_attach_NI = KeyboardInterrupt()
                cause = RuntimeError("literal original cause")

                class Ordinary(ValueError):
                    def __setattr__(self, name, value):
                        if name.startswith("anchor_"):
                            events.append("ATTACH_REJECTED_BY_SAME_NEW_NI")
                            raise new_attach_NI
                        BaseException.__setattr__(self, name, value)

                class OriginalNI(KeyboardInterrupt):
                    def __setattr__(self, name, value):
                        if name.startswith("anchor_"):
                            events.append("ATTACH_REJECTED_BY_SAME_NEW_NI")
                            raise new_attach_NI
                        BaseException.__setattr__(self, name, value)

                original = OriginalNI() if original_interrupt else Ordinary("ordinary")
                original.__cause__ = cause
                stream = types.SimpleNamespace(closed=False, fileno=lambda: 71,
                    close=lambda: events.append("ORIGINAL_STREAM_CLOSED"))
                log = subject.CleanupLog()
                with ExitStack() as stack:
                    for module, name in (
                        (subprocess, "Popen"), (subprocess, "run"),
                        (os, "pipe"), (os, "fork"), (os, "posix_spawn"),
                        (os, "posix_spawnp"), (os, "execv"), (os, "execve"),
                        (os, "kill"), (os, "killpg"), (os, "waitpid"),
                        (os, "getpid"), (os, "getppid"), (os, "getpgid"),
                        (os, "getsid"), (os, "setsid"), (os, "setpgid"),
                        (os, "read"), (os, "write"), (os, "close"),
                        (socket, "socket"), (socket, "create_connection"),
                        (threading.Thread, "__init__"), (threading.Thread, "start"),
                        (time, "sleep"),
                    ):
                        if hasattr(module, name):
                            stack.enter_context(mock.patch.object(module, name, forbidden))
                    stack.enter_context(mock.patch.object(subject.os, "fstat",
                        return_value=types.SimpleNamespace(st_dev=7, st_ino=71,
                            st_mode=4480, st_uid=501, st_gid=20)))
                    with self.assertRaises(BaseException) as raised:
                        subject.finish(None, original, log, [],
                                       [("stdout", stream, (7,71,4480,501,20))])

                # Independent hand-written ordering and exception identities.
                # Current candidate ordinary lane should FAIL the last assert;
                # original-NI lane may already PASS and must remain unchanged.
                self.assertEqual(["ORIGINAL_STREAM_CLOSED",
                                  "ATTACH_REJECTED_BY_SAME_NEW_NI"], events)
                self.assertEqual(1, len(log.errors))
                self.assertEqual("attach_diagnostics", log.errors[0][0])
                self.assertIs(new_attach_NI, log.errors[0][1])
                self.assertIs(cause, original.__cause__)
                self.assertIs(original if original_interrupt else new_attach_NI,
                              raised.exception)


class StatusEOFDeadlineLiteralTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        name = "_h_status_eof_deadline_subject"
        spec = importlib.util.spec_from_file_location(name, SOURCE)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
        finally:
            sys.modules.pop(name, None)
        cls.parent = module

    def test_no_frame_status_EOF_before_deadline_is_UNKNOWN_but_at_deadline_is_timeout124(self):
        parent = self.parent
        for selected_at in (0.75, 1.0):
            with self.subTest(selected_at=selected_at):
                clock = {"now": 0.5}
                events, feeds = [], []
                state = parent.DrainState(b"0123456789abcdef")
                log = parent.CleanupLog()
                process = types.SimpleNamespace(stdin=None,
                    stdout=types.SimpleNamespace(fileno=lambda: 10),
                    stderr=types.SimpleNamespace(fileno=lambda: 11))
                reservation = types.SimpleNamespace(pid=81234)

                class Selector:
                    def __init__(self):
                        self.calls = 0
                    def register(self, fd, mode, role):
                        events.append(("REGISTER", fd, role))
                    def select(self, timeout):
                        self.calls += 1
                        if self.calls != 1 or not 0 < timeout <= 0.1:
                            raise AssertionError("unexpected select or changed deadline")
                        clock["now"] = selected_at
                        events.append(("SELECT_STATUS_EOF_READY", selected_at))
                        return [(types.SimpleNamespace(fd=13, data="status"), 1)]
                    def unregister(self, fd):
                        events.append(("UNREGISTER", fd))
                    def close(self):
                        events.append(("SELECTOR_CLOSE",))

                selector = Selector()
                def read(fd, size):
                    if (fd, size) != (13, 64):
                        raise AssertionError("unknown mocked descriptor/read")
                    events.append(("STATUS_READ_EOF", clock["now"]))
                    return b""  # Never invent a real command status frame.
                real_feed = state.feed
                def feed(role, chunk):
                    feeds.append((role, len(chunk), clock["now"]))
                    return real_feed(role, chunk)
                def forbidden(*_a, **_k):
                    raise AssertionError("real process/FD/PID/network/thread/sleep forbidden")

                original_clock = parent.time.monotonic
                caught = None
                with ExitStack() as stack:
                    for obj, name in ((subprocess.Popen, "__init__"), (subprocess, "run"),
                            (os, "pipe"), (os, "fork"), (os, "posix_spawn"), (os, "posix_spawnp"),
                            (os, "execv"), (os, "execve"), (os, "kill"), (os, "killpg"),
                            (os, "waitpid"), (os, "getpid"), (os, "getppid"), (os, "getpgid"),
                            (os, "getpgrp"), (os, "getsid"), (os, "setsid"), (os, "setpgid"),
                            (os, "fstat"), (os, "set_blocking"), (os, "read"), (os, "write"), (os, "close"),
                            (socket, "socket"), (socket, "create_connection"),
                            (threading.Thread, "__init__"), (threading.Thread, "start"), (time, "sleep")):
                        if hasattr(obj, name):
                            stack.enter_context(mock.patch.object(obj, name, forbidden))
                    stack.enter_context(mock.patch.object(parent.selectors, "DefaultSelector", return_value=selector))
                    blocking = stack.enter_context(mock.patch.object(parent.os, "set_blocking"))
                    stack.enter_context(mock.patch.object(parent.os, "read", side_effect=read))
                    stack.enter_context(mock.patch.object(parent.time, "monotonic", side_effect=lambda: clock["now"]))
                    stack.enter_context(mock.patch.object(state, "feed", side_effect=feed))
                    try:
                        parent._drive(process, reservation, 12, 13, b"", None, 1.0, state, log)
                    except BaseException as error:
                        caught = error

                # Independent premises precede the expected behavioral assertion.
                self.assertIs(parent.time.monotonic, original_clock)
                self.assertEqual(selector.calls, 1)
                self.assertEqual(clock["now"], selected_at)
                self.assertIn(("SELECT_STATUS_EOF_READY", selected_at), events)
                self.assertEqual(events[-1], ("SELECTOR_CLOSE",))
                self.assertEqual(blocking.call_args_list, [mock.call(10, False), mock.call(11, False),
                    mock.call(13, False), mock.call(12, False)])
                self.assertIsNone(state.command_status)
                self.assertFalse(state.output_EOF)
                self.assertEqual(log.errors, [])
                print("STATUS_EOF_FACTS " + json.dumps({"deadline": 1.0,
                    "status_EOF_ready_at": selected_at, "select_calls": selector.calls,
                    "feeds": feeds, "command_status": state.command_status,
                    "stop_reason": state.stop_reason,
                    "caught_type": type(caught).__name__ if caught is not None else None,
                    "selector_closed": events[-1] == ("SELECTOR_CLOSE",)}), flush=True)
                if selected_at < 1.0:
                    self.assertIs(type(caught), parent.AnchorUnknown)
                    self.assertEqual(feeds, [("status", 0, 0.75)])
                    self.assertIsNone(state.stop_reason)
                else:
                    self.assertIsNone(caught, "deadline status EOF must not replace timeout124 with UNKNOWN")
                    self.assertEqual(state.stop_reason, "timeout")
                    self.assertEqual(parent.effective_returncode(None, state.stop_reason), 124)


class LateEOFDeadlineLiteralTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        name = "_h_late_eof_subject"
        spec = importlib.util.spec_from_file_location(name, HERE / "_bounded_process.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
        finally:
            sys.modules.pop(name, None)
        cls.parent = module

    def test_status17_then_two_EOFs_after_deadline_is_timeout124(self):
        parent = self.parent
        clock = {"now": 0.5}
        events = []
        wire = b"HAP10123456789abcdef\x00\x01\x3d\x53\x00\x00\x11\x00"
        state = parent.DrainState(b"0123456789abcdef")
        log = parent.CleanupLog()
        process = types.SimpleNamespace(stdin=None,
            stdout=types.SimpleNamespace(fileno=lambda: 10),
            stderr=types.SimpleNamespace(fileno=lambda: 11))
        reservation = types.SimpleNamespace(pid=81234, signal_attempted=False)

        class Selector:
            def __init__(self):
                self.calls = 0
            def register(self, fd, mode, role):
                events.append(("REGISTER", fd, role))
            def select(self, timeout):
                self.calls += 1
                if not 0 < timeout <= 0.25:
                    raise AssertionError("select outside remaining literal deadline")
                if self.calls == 1:
                    clock["now"] = 0.75
                    events.append(("SELECT_STATUS", clock["now"]))
                    return [(types.SimpleNamespace(fd=13, data="status"), 1)]
                if self.calls == 2:
                    clock["now"] = 1.25
                    events.append(("SELECT_LATE_EOFS", clock["now"]))
                    return [(types.SimpleNamespace(fd=10, data="stdout"), 1),
                            (types.SimpleNamespace(fd=11, data="stderr"), 1)]
                raise AssertionError("unexpected extra select after completed late EOFs")
            def unregister(self, fd):
                events.append(("UNREGISTER", fd))
            def close(self):
                events.append(("SELECTOR_CLOSE",))

        selector = Selector()
        def read(fd, size):
            events.append(("READ", fd, size, clock["now"]))
            if fd == 13:
                return wire
            if fd in (10, 11):
                return b""
            raise AssertionError("unknown mock descriptor")
        real_feed = state.feed
        feeds = []
        def feed(role, chunk):
            feeds.append((role, chunk, clock["now"]))
            return real_feed(role, chunk)
        def forbidden(*_a, **_k):
            raise AssertionError("real process/pipe/PID/network/thread/sleep forbidden")

        # All inner data/FD/process objects are doubles. Fixed-source imports
        # are ordinary readonly I/O; numbers10..13 are interpreted only by
        # doubles, never as permission for real descriptor syscalls.
        original_clock_binding = parent.time.monotonic
        with ExitStack() as stack:
            for obj, name in ((subprocess.Popen, "__init__"), (subprocess, "run"),
                              (os, "pipe"), (os, "fork"), (os, "posix_spawn"),
                              (os, "posix_spawnp"), (os, "execv"), (os, "execve"),
                              (os, "kill"), (os, "killpg"), (os, "waitpid"),
                              (os, "getpid"), (os, "getppid"), (os, "getpgid"),
                              (os, "getpgrp"), (os, "getsid"), (os, "setsid"), (os, "setpgid"),
                              (os, "fstat"), (os, "set_blocking"),
                              (os, "read"), (os, "write"), (os, "close"),
                              (socket, "socket"), (socket, "create_connection"),
                              (threading.Thread, "__init__"), (threading.Thread, "start"),
                              (time, "sleep")):
                if hasattr(obj, name):
                    stack.enter_context(mock.patch.object(obj, name, forbidden))
            stack.enter_context(mock.patch.object(parent.selectors, "DefaultSelector", return_value=selector))
            blocking = stack.enter_context(mock.patch.object(parent.os, "set_blocking"))
            stack.enter_context(mock.patch.object(parent.os, "read", side_effect=read))
            stack.enter_context(mock.patch.object(parent.time, "monotonic", side_effect=lambda: clock["now"]))
            stack.enter_context(mock.patch.object(state, "feed", side_effect=feed))
            parent._drive(process, reservation, 12, 13, b"", None, 1.0, state, log)

        # Premise/real-source work must pass BEFORE the expected behavior fails.
        self.assertIs(parent.time.monotonic, original_clock_binding)
        self.assertEqual(selector.calls, 2)
        self.assertEqual(clock["now"], 1.25)
        self.assertEqual(feeds, [("status", wire, 0.75), ("stdout", b"", 1.25), ("stderr", b"", 1.25)])
        self.assertTrue(state.output_EOF)
        self.assertEqual(state.command_status, {"command_pid": 81235, "wait_status": 4352, "returncode": 17})
        self.assertEqual(blocking.call_args_list, [mock.call(10, False), mock.call(11, False), mock.call(13, False), mock.call(12, False)])
        self.assertEqual(events[-1], ("SELECTOR_CLOSE",))
        self.assertEqual(log.errors, [])
        actual = parent.effective_returncode(state.command_status, state.stop_reason)
        print("LATE_EOF_FACTS " + json.dumps({"deadline": 1.0, "last_eof_time": clock["now"],
            "command_status": state.command_status, "output_EOF": state.output_EOF,
            "stop_reason": state.stop_reason, "effective_returncode": actual,
            "select_calls": selector.calls, "selector_closed": events[-1] == ("SELECTOR_CLOSE",)}), flush=True)
        self.assertEqual((state.stop_reason, actual), ("timeout", 124))


if __name__ == "__main__":
    unittest.main()
