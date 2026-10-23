"""UNRUN protocol UNIT + real local helper/PTY; neither is native admission."""
import ast
import base64
import contextlib
import io
import inspect
import json
import os
from pathlib import Path
import select
import shlex
import subprocess
import sys
import tempfile
import time
import unittest

from test_cases import test_ibsw3_scp_source_binding as BASE

SECRET = b'SYNTHETIC_ONLY'
MARKER = b'IBSW_SCP_SOURCE_VERIFIED\n'


class UnitLeaf:
    """Synthetic protocol-only original checks, never an upgrade leaf/grant."""
    def __init__(self, channel, post_error=None):
        self.channel, self.post_error = channel, post_error
        self.checks = self.tail_checks = 0

    def verify(self):
        self.checks += 1
        if self.channel.close_calls: self.tail_checks += 1
        if self.channel.close_calls and self.post_error is not None:
            raise self.post_error

    verify_io_identity = verify


class UnitChannel:
    def __init__(self, *, out=MARKER, err=b'', status=0, eof=True,
                 primary=None, close_error=None, close_delay=0):
        self.out, self.err, self.status, self.eof_received = out, err, status, eof
        self.primary, self.close_error, self.close_delay = primary, close_error, close_delay
        self.sent = bytearray(); self.send_calls = self.close_calls = 0
        self.shutdown = False; self.command = None
        self.events = []

    def settimeout(self, timeout): self.events.append('timeout')
    def exec_command(self, command):
        self.command = command; self.events.append('exec')
    def send(self, value):
        self.send_calls += 1
        if self.command is None or self.shutdown:
            raise AssertionError('secret send requires fixed exec and must precede write EOF')
        if self.primary is not None: raise self.primary
        count = min(3, len(value)); self.sent.extend(value[:count]); return count
    def sendall(self, value):
        raise AssertionError('fixed role must bound each partial channel.send, not use sendall')
    def shutdown_write(self): self.shutdown = True; self.events.append('shutdown')
    def recv_ready(self): return self.shutdown and bool(self.out)
    def recv(self, size):
        value, self.out = self.out[:min(size,7)], self.out[min(size,7):]; return value
    def recv_stderr_ready(self): return self.shutdown and bool(self.err)
    def recv_stderr(self, size):
        value, self.err = self.err[:size], self.err[size:]; return value
    def exit_status_ready(self): return self.shutdown and not self.out and not self.err
    def recv_exit_status(self): self.events.append('status'); return self.status
    @property
    def closed(self): return self.close_calls > 0 or self.exit_status_ready()
    def close(self):
        self.close_calls += 1; self.events.append('close')
        if self.close_delay: time.sleep(self.close_delay)
        if self.close_error is not None: raise self.close_error


class UnitTransport:
    def __init__(self, channel): self.channel, self.opens = channel, 0
    def open_session(self, *, timeout): self.opens += 1; return self.channel
    def is_active(self): return True


class LocalProbeChannel:
    """Actual Python helper child; sole executable substitution is private SSH."""
    def __init__(self, root, ssh):
        self.root, self.ssh = root, ssh
        self.process = None; self.close_calls = self.send_calls = 0
        self.out_eof = self.err_eof = False; self.sent = bytearray()

    def settimeout(self, timeout): pass
    def exec_command(self, command):
        argv = shlex.split(command)
        if len(argv) != 4 or argv[:2] != ['/usr/bin/python3','-c'] or argv[3] != 'probe':
            raise AssertionError('only fixed source probe command is allowed')
        if SECRET.decode() in command: raise AssertionError('secret in remote argv')
        tree = ast.parse(argv[2])
        decoders = [n for n in ast.walk(tree) if isinstance(n,ast.Call)
                    and isinstance(n.func,ast.Attribute) and n.func.attr == 'b64decode'
                    and isinstance(n.func.value,ast.Name) and n.func.value.id == 'base64']
        if len(decoders) != 1 or len(decoders[0].args) != 1:
            raise AssertionError('one fixed generated helper encoding required')
        value = ast.literal_eval(decoders[0].args[0])
        script = base64.b64decode(value,validate=True)
        needle = b"SSH = '/usr/bin/ssh'"
        if script.count(needle) != 1:
            raise AssertionError('one independently reviewed SSH executable seam required')
        script = script.replace(needle,('SSH = '+repr(str(self.ssh))).encode())
        # Deliberately poisoned inherited context. Current stdin must win;
        # the source-only generated command must neutralize this old env seam.
        environment = dict(PATH='/usr/bin:/bin', HOME=str(self.root), TMPDIR=str(self.root),
                           LC_ALL='C', PYTHONDONTWRITEBYTECODE='1',
                           IBSW_SCP_AUTH=json.dumps(dict(host='203.0.113.250',user='wrong_source',
                               port=2201,password='secret-value',host_keys='not-current-trust',
                               paths={},timeout_seconds=1)))
        self.process = subprocess.Popen([argv[0],'-c',script.decode(),'probe'],
            cwd=self.root,env=environment,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,close_fds=True)
    def send(self, value):
        self.send_calls += 1; count = min(5,len(value))
        self.process.stdin.write(value[:count]); self.process.stdin.flush()
        self.sent.extend(value[:count]); return count
    def sendall(self, value):
        raise AssertionError('fixed role must bound each partial channel.send, not use sendall')
    def shutdown_write(self): self.process.stdin.close()
    def recv_ready(self):
        return not self.out_eof and bool(select.select([self.process.stdout],[],[],0)[0])
    def recv(self, size):
        value = os.read(self.process.stdout.fileno(),size)
        if not value: self.out_eof = True
        return value
    def recv_stderr_ready(self):
        return not self.err_eof and bool(select.select([self.process.stderr],[],[],0)[0])
    def recv_stderr(self, size):
        value = os.read(self.process.stderr.fileno(),size)
        if not value: self.err_eof = True
        return value
    def exit_status_ready(self): return self.process is not None and self.process.poll() is not None
    def recv_exit_status(self): return self.process.wait(timeout=5)
    @property
    def eof_received(self): return self.out_eof and self.err_eof
    @property
    def closed(self): return self.exit_status_ready() and self.eof_received
    def close(self):
        self.close_calls += 1
        self.cleanup_owned()
    def cleanup_owned(self):
        # Only the test's retained Popen object; never scan/remember foreign PIDs.
        if self.process is None: return
        if not self.process.stdin.closed: self.process.stdin.close()
        if self.process.poll() is None:
            try: self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill(); self.process.wait(timeout=5)
        for handle in (self.process.stdout,self.process.stderr):
            if not handle.closed: handle.close()


class ScpSourceProbeChannelTests(unittest.TestCase):
    def api(self):
        module = BASE.ScpSourceBindingTests().module()
        function = getattr(module,'_probe_source_channel',None)
        self.assertTrue(callable(function),
                        'MISSING_FIXED_SOURCE_CHANNEL_CAPABILITY; secret/preflight/native=NOT_REACHED')
        self.assertEqual(('leaf','transport','deadline','source'),
                         tuple(inspect.signature(function).parameters),
                         'fixed role must not accept caller command/payload/program')
        return module,function

    def test_protocol_unit_requires_exact_complete_reply_cleanup_and_first_ni(self):
        module,function = self.api()
        cases = ('healthy','stdout_echo','stderr_echo','wrong_status','missing_eof',
                 'close_failure','close_after_deadline','expired_before_open','keyboard','systemexit',
                 'keyboard_cleanup_exit','systemexit_cleanup_keyboard')
        for name in cases:
            with self.subTest(case=name), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve()
                trust,source = BASE.ScpSourceBindingTests().source(root,module)
                primary = None; cause = RuntimeError('existing UNIT cause')
                if name.startswith(('keyboard','systemexit')):
                    primary = KeyboardInterrupt('UNIT interruption') if name.startswith('keyboard') else SystemExit(17)
                    primary.__cause__ = cause
                close_error = (SystemExit(23) if name == 'keyboard_cleanup_exit' else
                               KeyboardInterrupt('later cleanup interruption') if name == 'systemexit_cleanup_keyboard' else
                               OSError('UNIT critical close') if name == 'close_failure' or primary is not None else None)
                channel = UnitChannel(out=SECRET+b'\n' if name == 'stdout_echo' else MARKER,
                    err=SECRET if name == 'stderr_echo' else b'',status=1 if name == 'wrong_status' else 0,
                    eof=name != 'missing_eof',primary=primary,
                    close_error=close_error,
                    close_delay=.04 if name == 'close_after_deadline' else 0)
                leaf = UnitLeaf(channel,OSError('UNIT tail verification') if primary is not None else None)
                transport = UnitTransport(channel)
                deadline = time.monotonic()+(.02 if name == 'close_after_deadline' else 5)
                if name == 'expired_before_open': deadline = time.monotonic()-1
                result = object(); failure = None; out,err = io.StringIO(),io.StringIO()
                checks = dict(before=0,after_close=0)
                verify = source.verify
                self.assertIsNone(sys.getprofile())
                def observe(frame,event,argument):
                    if (event == 'call' and frame.f_code is verify.__func__.__code__
                            and frame.f_globals is verify.__func__.__globals__
                            and frame.f_locals.get('self') is source):
                        checks['after_close' if channel.close_calls else 'before'] += 1
                try:
                    sys.setprofile(observe)
                    with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
                        try: result = function(leaf,transport,deadline,source)
                        except BaseException as error: failure = error
                finally:
                    sys.setprofile(None)
                if name == 'healthy':
                    self.assertIsNone(failure)
                    self.assertIsNone(result, 'only None diagnostic completion, no raw/permission result')
                    self.assertGreater(channel.send_calls,1)
                    self.assertTrue(channel.shutdown)
                    self.assertEqual(1,channel.close_calls)
                    self.assertEqual(1,transport.opens)
                    self.assertGreaterEqual(leaf.checks,2)
                    self.assertGreaterEqual(leaf.tail_checks,1)
                    self.assertGreaterEqual(checks['before'],1)
                    self.assertGreaterEqual(checks['after_close'],1)
                    context = json.loads(bytes(channel.sent))
                    self.assertEqual({'host','user','port','host_keys','password','paths','timeout_seconds'},set(context))
                    self.assertEqual(('192.0.2.254','sourceuser',22),
                                     (context['host'],context['user'],context['port']))
                    self.assertTrue(context['password'].encode() == SECRET)
                    self.assertEqual({},context['paths'])
                    self.assertEqual(trust.read_bytes(),context['host_keys'].encode())
                elif primary is not None:
                    self.assertIs(primary,failure)
                    self.assertIs(cause,failure.__cause__)
                    self.assertEqual(1,channel.close_calls)
                else:
                    self.assertIsInstance(failure,Exception)
                    if name == 'expired_before_open': self.assertEqual(0,transport.opens)
                    else: self.assertGreaterEqual(channel.close_calls,1)
                    if name == 'close_failure': self.assertEqual(1,channel.close_calls)
                self.assertLessEqual(transport.opens,1,'fixed source probe must not retry')
                self.assertFalse(SECRET.decode() in out.getvalue()+err.getvalue())
                if failure is not None:
                    self.assertFalse(SECRET.decode() in str(failure))

    def test_generated_probe_python_pty_uses_current_stdin_not_inherited_auth(self):
        module,function = self.api()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            trust,source = BASE.ScpSourceBindingTests().source(root,module)
            ssh,events = root/'ssh-stub',root/'events'
            # Fixture expectation contains a synthetic token, not a production
            # credential or a new sender/program/executable authority argument.
            ssh.write_text('#!/usr/bin/python3\nimport sys\nfrom pathlib import Path\n'
                +'a=sys.argv[1:]\n'
                +'if a[:2]!=["-F","/dev/null"] or a[-4:]!=["-p","22","sourceuser@192.0.2.254","/bin/true"]: raise SystemExit(91)\n'
                +'for flag in ("StrictHostKeyChecking=yes","GlobalKnownHostsFile=/dev/null","UpdateHostKeys=no","ConnectionAttempts=1"):\n'
                +' if flag not in a: raise SystemExit(92)\n'
                +'Path('+repr(str(events))+').write_text("SSH\\n")\n'
                +'sys.stdout.write("Password: ");sys.stdout.flush()\n'
                +'if sys.stdin.readline().rstrip("\\n")!="SYNTHETIC_ONLY": raise SystemExit(93)\n'
                +'print("SYNTHETIC_ONLY")\n')
            ssh.chmod(0o700)
            channel = LocalProbeChannel(root,ssh)
            transport,leaf = UnitTransport(channel),UnitLeaf(channel)
            out,err = io.StringIO(),io.StringIO()
            try:
                with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
                    result = function(leaf,transport,time.monotonic()+30,source)
                self.assertIsNone(result)
                self.assertEqual('SSH\n',events.read_text())
                self.assertEqual(0,channel.process.returncode)
                self.assertEqual(1,channel.close_calls)
                self.assertGreater(channel.send_calls,1)
                self.assertTrue(json.loads(bytes(channel.sent))['password'].encode() == SECRET)
                self.assertFalse(SECRET.decode() in out.getvalue()+err.getvalue())
                self.assertEqual([],list(root.glob('.ibsw-scp-*')))
            finally:
                channel.cleanup_owned()
