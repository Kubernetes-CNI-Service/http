"""NOTRUN: finite remote Channel/SFTP IO doubles, never a manager or ACK writer.

The same physical switch paths are used by actual Bash and SFTP. Only the
three documented target ancestors and synthetic SSH-home view are metadata
doubles. Each channel retains an actual relay and a separate runner owner.
"""
import shlex
import math
import time
from pathlib import Path

from test_cases.native_cpld_physical_io import PhysicalSwitchSFTP
from test_cases.native_os_dual_channel import native_os_expression_session
from test_cases.native_os_safe_image import require_safe_command


class NativeChannel:
    def __init__(self, bridge):
        self.bridge = bridge
        self.owner = self.inner = self.process = None
        self.timeout = None
        self.send_calls = self.close_calls = 0
        self.collected = [bytearray(), bytearray()]
        self.owner_entered = self.owner_exited = False

    def settimeout(self, seconds):
        if type(seconds) not in (int, float) or not math.isfinite(seconds) or seconds <= 0:
            raise ValueError('finite positive SDK timeout required')
        self.timeout = seconds
        if self.inner is not None:
            self.inner.settimeout(seconds)

    def exec_command(self, command):
        if self.owner is not None:
            raise AssertionError('one fixed expression per actual channel')
        words = shlex.split(command)
        role = require_safe_command(self.bridge.image, words, self.bridge.root)
        self.owner = native_os_expression_session(self.bridge.image, self.bridge.root, role=role)
        self.owner.__enter__()
        self.owner_entered = True
        # Retain before start: handoff failure is still this owner's UNKNOWN.
        self.bridge.channels.append(self)
        self.inner = self.owner.start(command)
        self.process = self.inner.process
        if self.timeout is not None:
            self.inner.settimeout(self.timeout)

    def send(self, raw):
        self.send_calls += 1
        return self.inner.send(raw)

    def sendall(self, raw):
        raise AssertionError('original partial-send protocol required')

    def shutdown_write(self): return self.inner.shutdown_write()
    def recv_ready(self): return self.inner.recv_ready()
    def recv_stderr_ready(self): return self.inner.recv_stderr_ready()
    def exit_status_ready(self): return self.inner.exit_status_ready()
    def recv_exit_status(self): return self.inner.recv_exit_status()

    def recv(self, size):
        raw = self.inner.recv(size)
        self.collected[0].extend(raw)
        return raw

    def recv_stderr(self, size):
        raw = self.inner.recv_stderr(size)
        self.collected[1].extend(raw)
        return raw

    @property
    def eof_received(self): return self.inner is not None and self.inner.eof_received

    @property
    def closed(self): return self.inner is not None and self.inner.closed

    def close(self):
        self.close_calls += 1
        if self.inner is not None:
            self.inner.close()  # Wire only; never block waiting for ACK/runner.


class NativeOsPhysicalBridge:
    def __init__(self, root, image):
        self.root, self.image = Path(root), Path(image)
        self.switch = self.root / 'switch'
        self.switch.mkdir(mode=0o700)
        self.channels = []
        self.sftp = None
        self.before_lstat = lambda path: None
        self.after_ack = lambda old, new, started, finished: None

    def remote(self, home):
        physical = PhysicalSwitchSFTP(self.switch, home)
        original_lstat, original_rename = physical.lstat, physical.rename

        def lstat(name):
            self.before_lstat(Path(name))
            return original_lstat(name)

        def rename(old, new):
            # This is an interval lower bound, NOT a fake publication timestamp.
            # A successful real rename plus the real shell's ACK consumption is
            # the publication fact; NV can race the Python post-call observer.
            started = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
            value = original_rename(old, new)
            finished = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
            if Path(new).name == 'download-ack':
                self.after_ack(Path(old), Path(new), started, finished)
            return value

        physical.lstat = lstat
        physical.stat = lstat
        physical.rename = rename
        self.sftp = physical
        return physical

    def open_channel(self, **kwargs):
        # Paramiko open_session timeout is an IO setting, not a new authority.
        if set(kwargs) - {'timeout'}:
            raise AssertionError('unknown actual session option')
        return NativeChannel(self)

    def query(self, leaf, transport, command, deadline):
        raise AssertionError('generic observer must never execute secret launcher')

    def finish(self):
        receipts, cancelled = [], False
        first = None
        for channel in self.channels:
            owner = channel.owner
            if owner is None or channel.owner_exited:
                continue
            try:
                if channel.inner is None:
                    raise RuntimeError('original channel handoff UNKNOWN')
                if not channel.inner.close_attempted:
                    channel.close()
                state = owner.original_runner_state()
                if type(state) is not dict or set(state) != {'returncodes'}:
                    raise RuntimeError('original runner state shape UNKNOWN')
                live = any(code is None for code in state['returncodes'])
                receipt = owner.finish_originals(cancel=live)
                cancelled = cancelled or receipt['cancelled']
                receipts.append(receipt)
            except BaseException as error:
                first = first or error
            finally:
                try:
                    owner.__exit__(None, None, None)
                    channel.owner_exited = True
                except BaseException as error:
                    first = first or error
        if first is not None:
            raise first
        return receipts, cancelled
