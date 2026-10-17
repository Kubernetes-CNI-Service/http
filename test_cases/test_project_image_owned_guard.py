"""Independent owned-image fixture input, runtime and source-context contracts.

These controls never start a process, socket, thread, Docker or remote endpoint.
The two original image workflows separately exercise the real installer chain.
"""
import contextlib
import errno
import inspect
import json
import os
from pathlib import Path
import shutil
import stat
import signal
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases import project_image_owned_guard_outer as SUBJECT
from test_cases.test_project_image_bundle import OWNED_NATIVE_GUARD_BOOTSTRAP_SOURCE as BOOTSTRAP

FACTS = []

class HeldInputsTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(callable(getattr(SUBJECT, 'HeldGuardInputs', None)),
                        'HELD_INPUTS_AUTHORITY_API_ABSENT')
        self.parent = Path(tempfile.mkdtemp(prefix='root-held-inputs-')).resolve()
        self.parent.chmod(0o700)
        self.root_key = (self.parent.stat().st_dev, self.parent.stat().st_ino)
        self.directory = self.parent/'owned-native-guard.literal'
        self.directory.mkdir(mode=0o700)
        self.archive = self.parent/'original-archive'
        self.archive.write_bytes(b'literal independent archive\n')
        self.archive.chmod(0o600)
        self.handles = []
        for path in (self.directory, self.archive):
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            self.handles.append((fd, (os.fstat(fd).st_dev, os.fstat(fd).st_ino)))

    def tearDown(self):
        if not hasattr(self, 'handles'):
            return
        errors = []
        for fd, key in reversed(self.handles):
            try:
                self.assertEqual(key, (os.fstat(fd).st_dev, os.fstat(fd).st_ino))
                os.close(fd)
            except BaseException as error:
                errors.append(error)
        if not errors:
            self.assertEqual(self.root_key, (self.parent.stat().st_dev, self.parent.stat().st_ino))
            shutil.rmtree(self.parent)
        FACTS.append(dict(errors=[type(e).__name__ for e in errors],
                          root_absent=not self.parent.exists()))
        if errors:
            raise errors[0]

    def authority(self, *, archive=None):
        return SUBJECT.HeldGuardInputs(parent=self.parent, directory=self.directory,
            directory_fd=self.handles[0][0], archive=self.archive if archive is None else archive,
            archive_fd=self.handles[1][0])

    def test_original_two_borrowed_descriptors_are_verified_not_owned_or_closed(self):
        authority = self.authority()
        directory = authority._fd(self.handles[0][0])
        archive = authority._fd(self.handles[1][0], named=False)
        self.assertEqual(dict(directory=True, path=str(self.directory)), directory)
        self.assertEqual(dict(directory=False, path=str(self.archive)), archive)
        self.assertTrue(authority._inside(str(self.archive)))
        self.assertFalse(authority._inside(str(self.parent)+'-outside/original-archive'))
        for fd, key in self.handles:
            self.assertEqual(key, (os.fstat(fd).st_dev, os.fstat(fd).st_ino))

    def test_same_bytes_named_rebinding_never_adopts_new_original(self):
        authority = self.authority()
        original = self.archive.with_name('retained-original')
        self.archive.rename(original)
        self.archive.write_bytes(b'literal independent archive\n')
        self.archive.chmod(0o600)
        with self.assertRaises(SUBJECT.GuardOuterHold):
            authority._fd(self.handles[1][0], named=False)
        self.assertEqual(b'literal independent archive\n', os.pread(self.handles[1][0], 64, 0))

    def test_unknown_fd_and_outside_name_have_no_authority(self):
        authority = self.authority()
        with self.assertRaises(SUBJECT.GuardOuterHold):
            authority._fd(123456789)
        with self.assertRaises(SUBJECT.GuardOuterHold):
            self.authority(archive=self.parent.parent/'outside-original')

    def test_public_parent_or_wrong_role_is_refused(self):
        self.parent.chmod(0o755)
        with self.assertRaises(SUBJECT.GuardOuterHold):
            self.authority()
        self.parent.chmod(0o700)
        with self.assertRaises(SUBJECT.GuardOuterHold):
            SUBJECT.HeldGuardInputs(parent=self.parent, directory=self.directory,
                directory_fd=self.handles[1][0], archive=self.archive,
                archive_fd=self.handles[0][0])

    def test_original_staged_snapshot_yield_names_its_actual_borrowed_file(self):
        import contextlib
        self.assertTrue(callable(getattr(SUBJECT, 'borrowed_snapshot_path', None)),
                        'ORIGINAL_SNAPSHOT_CONTEXT_API_ABSENT')
        @contextlib.contextmanager
        def original_snapshot():
            destination = self.archive
            output = self.handles[1][0]
            yield output
        manager = original_snapshot()
        with manager as descriptor:
            self.assertEqual(str(self.archive), SUBJECT.borrowed_snapshot_path(
                manager, original_snapshot, descriptor, self.parent))
            self.assertEqual(b'literal independent archive\n', os.pread(descriptor, 64, 0))

    def test_same_values_foreign_or_closed_generator_cannot_supply_archive_path(self):
        import contextlib
        self.assertTrue(callable(getattr(SUBJECT, 'borrowed_snapshot_path', None)),
                        'ORIGINAL_SNAPSHOT_CONTEXT_API_ABSENT')
        @contextlib.contextmanager
        def original_snapshot():
            destination = self.archive
            output = self.handles[1][0]
            yield output
        @contextlib.contextmanager
        def foreign_snapshot():
            destination = self.archive
            output = self.handles[1][0]
            yield output
        foreign = foreign_snapshot()
        with foreign as descriptor:
            with self.assertRaises(SUBJECT.GuardOuterHold):
                SUBJECT.borrowed_snapshot_path(foreign, original_snapshot, descriptor, self.parent)
        closed = original_snapshot()
        with closed:
            pass
        with self.assertRaises(SUBJECT.GuardOuterHold):
            SUBJECT.borrowed_snapshot_path(closed, original_snapshot, self.handles[1][0], self.parent)

def interpreter_fixture(interpreter):
    key = (17, 901, 0o100600, 1, 501, 20, 37, 11, 12)
    root = '/literal-owned/live'
    directory = '/literal-owned/owned-native-guard.literal'
    domain = ['--lock', root+'/.deployment.lock', '--root', root,
        '--runtime', 'native', '--archive-fd', '77',
        '--archive-sha256', 'a'*64, '--source-manifest-sha256', 'b'*64]
    argv = [interpreter, '-I', '-S', '-B', '-c', BOOTSTRAP, *domain]
    binding = dict(parent='/literal-owned', root=root, directory=directory,
        bootstrap_sha256='cd1802da572565c837228ca21a294584d073369d2e4eacf34579f1c0509db120',
        guard_sha256='46af60b5b4ed3c3df6e3ad0f0a0b1fee5c8af60ceea8c6e60e08de5580481256',
        archive_key=[str(n) for n in key], domain_argv=domain, phase='OWNED_PARAMETERS')
    env = dict(PATH=directory+'/bin', TMPDIR=directory+'/tmp',
        PYTHONDONTWRITEBYTECODE='1', HTTP_TEST_GUARD_BINDING=json.dumps(binding, sort_keys=True))
    return argv, env, key


class InterpreterAdmissionTests(unittest.TestCase):
    def test_only_current_runtime_interpreter_is_accepted_without_install_specific_path(self):
        # Literal values are deliberate simulation inputs, never executed.
        for interpreter in ('/literal/python39/bin/python3', '/literal/python312/bin/python3'):
            with self.subTest(interpreter=interpreter):
                argv, env, key = interpreter_fixture(interpreter)
                with mock.patch.object(SUBJECT, '_RUNTIME_INTERPRETER', interpreter, create=True):
                    caught = result = None
                    try:
                        result = SUBJECT._exact_launch(argv, env, 77, key)
                    except SUBJECT.GuardOuterHold as error:
                        caught = error
                    self.assertIsNone(caught, 'CURRENT_RUNTIME_CANNOT_REQUIRE_ANOTHER_INSTALLATION')
                    self.assertEqual(tuple(argv), result[0])
                    self.assertEqual(env, result[1])

    def test_other_interpreter_and_relaxed_isolation_are_rejected(self):
        current = '/literal/python39/bin/python3'
        for change in ('interpreter', 'isolation', 'environment'):
            with self.subTest(change=change):
                argv, env, key = interpreter_fixture(current)
                if change == 'interpreter':
                    argv[0] = '/unapproved/python3'
                elif change == 'isolation':
                    argv[1] = '-E'
                else:
                    env['PYTHONPATH'] = '/unapproved'
                with mock.patch.object(SUBJECT, '_RUNTIME_INTERPRETER', current, create=True):
                    with self.assertRaises(SUBJECT.GuardOuterHold):
                        SUBJECT._exact_launch(argv, env, 77, key)

    def test_runtime_binding_does_not_follow_later_sys_alias(self):
        current = '/literal/original/python3'
        argv, env, key = interpreter_fixture(current)
        with mock.patch.object(SUBJECT, '_RUNTIME_INTERPRETER', current, create=True), mock.patch.object(SUBJECT, 'sys', SimpleNamespace(executable='/unapproved/later/python3')):
            caught = result = None
            try:
                result = SUBJECT._exact_launch(argv, env, 77, key)
            except SUBJECT.GuardOuterHold as error:
                caught = error
            self.assertIsNone(caught, 'ORIGINAL_RUNTIME_MUST_NOT_FOLLOW_LATER_ALIAS')
            self.assertEqual(tuple(argv), result[0])
            argv[0] = '/unapproved/later/python3'
            with self.assertRaises(SUBJECT.GuardOuterHold):
                SUBJECT._exact_launch(argv, env, 77, key)

def phase_fixture(phase):
    key=(17,901,0o100600,1,501,20,37,11,12)
    root='/literal-owned/live';directory='/literal-owned/owned-native-guard.literal'
    domain=['--lock',root+'/.deployment.lock','--root',root,'--runtime','native','--archive-fd','77','--archive-sha256','a'*64,'--source-manifest-sha256','b'*64]
    argv=[sys.executable,'-I','-S','-B','-c',BOOTSTRAP,*domain]
    binding=dict(parent='/literal-owned',root=root,directory=directory,
        bootstrap_sha256='cd1802da572565c837228ca21a294584d073369d2e4eacf34579f1c0509db120',
        guard_sha256='46af60b5b4ed3c3df6e3ad0f0a0b1fee5c8af60ceea8c6e60e08de5580481256',
        archive_key=[str(n) for n in key],domain_argv=domain,phase=phase)
    env=dict(PATH=directory+'/bin',TMPDIR=directory+'/tmp',PYTHONDONTWRITEBYTECODE='1',HTTP_TEST_GUARD_BINDING=json.dumps(binding,sort_keys=True))
    return argv,env,key

class OwnedPhaseTests(unittest.TestCase):
    def test_two_literal_fixture_phases_preserve_exact_domain(self):
        for phase in ('OBSERVE_DEFAULTS','OWNED_PARAMETERS'):
            with self.subTest(phase=phase):
                argv,env,key=phase_fixture(phase);caught=None;result=None
                try:result=SUBJECT._exact_launch(argv,env,77,key)
                except BaseException as error:caught=error
                self.assertIsNone(caught,'FIXED_OWNED_PARAMETERS_MUST_HAVE_EXPLICIT_ADMISSION')
                self.assertEqual(tuple(argv),result[0]);self.assertEqual(env,result[1])
                self.assertEqual('/literal-owned/owned-native-guard.literal',result[2])
    def test_unknown_phase_and_extra_authority_remain_refused(self):
        for phase in ('SYSTEM','',None):
            with self.subTest(phase=phase):
                argv,env,key=phase_fixture(phase)
                with self.assertRaises(SUBJECT.GuardOuterHold):SUBJECT._exact_launch(argv,env,77,key)
        argv,env,key=phase_fixture('OWNED_PARAMETERS');env['PYTHONPATH']='/forbidden'
        with self.assertRaises(SUBJECT.GuardOuterHold):SUBJECT._exact_launch(argv,env,77,key)


# Reuse the original independently reviewed memory actors and all 16 controls.
# Only fixture namespace and current-runtime input wiring replace candidate paths.
subject = SUBJECT
fixture = sys.modules[__name__]
EVENTS = []
MODE = 'PARENT_DEFAULT_ARM'
MISSING = object()

class UnboundedWaitObserved(RuntimeError):
    pass


class MemoryWorld:
    def __init__(self, lane='normal', close_error=None):
        self.now = 0.0; self.lane = lane; self.close_error = close_error
        self.waits = []; self.signals = []; self.raw_closes = []; self.stream_closes = []
        self.archive_open = True; self.instances = []; self.init_calls = 0; self.init_kwargs = []
        self.archive = SimpleNamespace(st_dev=17, st_ino=901, st_mode=0o100600,
            st_uid=501, st_gid=20, st_nlink=1, st_size=37, st_mtime_ns=11, st_ctime_ns=12)
        self.pipe = SimpleNamespace(st_dev=17, st_ino=902, st_mode=0o10600,
            st_uid=501, st_gid=20, st_nlink=1, st_size=0, st_mtime_ns=13, st_ctime_ns=14)
        world = self
        class Stream:
            def __init__(self, fd): self.fd = fd; self.closed = False
            def fileno(self): return self.fd
            def close(self):
                world.stream_closes.append(self.fd); self.closed = True
                if self.fd == 61 and world.close_error is not None: raise world.close_error
        class Process:
            def __init__(self, argv, **kwargs):
                world.init_calls += 1; world.init_kwargs.append(dict(kwargs)); self.pid = 7101; self._child_created = True
                self.returncode = None; self.args = argv
                self.stdout = Stream(61); self.stderr = Stream(62); self.stdin = None
                world.instances.append(self)
            def kill(self): world.signals.append(self.pid)
            def wait(self, timeout=None):
                world.waits.append((self.pid, timeout))
                if self.returncode is not None: return self.returncode
                if world.lane in ('timeout', 'overflow'):
                    if timeout is None: raise UnboundedWaitObserved('literal unbounded original wait')
                    world.now += timeout
                    raise subprocess.TimeoutExpired('literal owned guard', timeout)
                self.returncode = 0; return 0
            def _internal_poll(self): return self.returncode
        self.process = Process
        self.backend = SimpleNamespace(Popen=Process, PIPE=-1, DEVNULL=-3,
            TimeoutExpired=subprocess.TimeoutExpired, _active=[])
        def fstat(fd):
            if fd == 77:
                if not self.archive_open: raise OSError('literal borrowed FD closed')
                return self.archive
            if fd in (61, 62): return self.pipe
            raise OSError('unknown memory FD')
        def close(fd):
            self.raw_closes.append(fd)
            if fd == 77: self.archive_open = False
        self.os = SimpleNamespace(fstat=fstat, close=close)
        self.clock = SimpleNamespace(monotonic=lambda: self.now)
        self.argv = [sys.executable,
            '-I','-S','-B','-c',BOOTSTRAP,
            '--lock','/literal-owned/live/.deployment.lock','--root','/literal-owned/live',
            '--runtime','native','--archive-fd','77','--archive-sha256','a'*64,
            '--source-manifest-sha256','b'*64]
        binding=dict(parent='/literal-owned',root='/literal-owned/live',
            directory='/literal-owned/owned-native-guard.literal',
            bootstrap_sha256='cd1802da572565c837228ca21a294584d073369d2e4eacf34579f1c0509db120',
            guard_sha256='46af60b5b4ed3c3df6e3ad0f0a0b1fee5c8af60ceea8c6e60e08de5580481256',
            archive_key=[str(getattr(self.archive,n)) for n in ('st_dev','st_ino','st_mode',
                'st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')],
            domain_argv=list(self.argv[6:]),phase='OBSERVE_DEFAULTS')
        self.env = {'PATH':'/literal-owned/owned-native-guard.literal/bin',
            'TMPDIR':'/literal-owned/owned-native-guard.literal/tmp',
            'PYTHONDONTWRITEBYTECODE':'1',
            'HTTP_TEST_GUARD_BINDING':json.dumps(binding,sort_keys=True)}
        self.original_result = SimpleNamespace(returncode=0, stdout=b'', stderr=b'')
    def create(self):
        return self.backend.Popen(self.argv, stdin=-3, stdout=-1, stderr=-1,
            shell=False, bufsize=0, env=self.env, pass_fds=(77,))
    @contextlib.contextmanager
    def installed(self):
        bindings = [(self.process, name, inspect.getattr_static(self.process, name))
                    for name in ('__init__', 'wait', 'kill', '_internal_poll')]
        original_close = self.os.close
        originals = (subject.subprocess, subject.os, subject.time)
        subject.FACTS.clear(); subject.HELD.clear()
        try:
            subject.subprocess, subject.os, subject.time = self.backend, self.os, self.clock
            yield
        finally:
            subject.subprocess, subject.os, subject.time = originals
            EVENTS.append(dict(lane=self.lane, waits=list(self.waits), signals=list(self.signals),
                raw_closes=list(self.raw_closes), stream_closes=list(self.stream_closes),
                archive_open=self.archive_open, elapsed=self.now,
                restored=all(inspect.getattr_static(obj, name) is value for obj,name,value in bindings)
                    and self.os.close is original_close,
                real_resources=False))


def capture(call, literal_operators=()):
    try: return ('return', call())
    except BaseException as error:
        if not isinstance(error, Exception) and not any(error is x for x in literal_operators): raise
        return ('error', error)


class ProjectImageOwnedGuardOuterTests(unittest.TestCase):
    def invoke(self, world, guard):
        return subject.run_project_image_guard(guard, world.argv,
            env=world.env, archive_fd=77, timeout=5)

    def test_timeout_and_overflow_never_enter_unbounded_wait_or_return_success(self):
        for lane in ('timeout', 'overflow'):
            with self.subTest(lane=lane):
                w = MemoryWorld(lane)
                def guard(*args, **kwargs):
                    p = w.create()
                    try:
                        p.kill(); p.wait()  # Existing timeout/overflow unbounded seam.
                    except subprocess.TimeoutExpired:
                        p.kill(); p.wait()
                    finally:
                        p.stdout.close(); p.stderr.close()
                    return w.original_result
                with w.installed(): status, error = capture(lambda: self.invoke(w, guard))
                self.assertEqual('error', status)
                self.assertTrue(w.waits)
                self.assertTrue(all(type(t) in (int, float) and 0 <= t <= 20 for _,t in w.waits),
                                'ORIGINAL_WAIT_WAS_NOT_BOUNDED')
                self.assertLessEqual(w.now, 20)
                self.assertNotIsInstance(error, UnboundedWaitObserved)
                self.assertTrue(w.archive_open)

    def test_borrowed_archive_close_is_rejected_without_delegate(self):
        w = MemoryWorld()
        def guard(*args, **kwargs):
            subject.os.close(77); return w.original_result
        with w.installed(): status, _error = capture(lambda: self.invoke(w, guard))
        self.assertTrue(w.archive_open, 'BORROWED_ARCHIVE_CAPABILITY_CLOSED')
        self.assertEqual([], w.raw_closes)
        self.assertEqual('error', status)

    def test_foreign_object_and_changed_pid_cannot_signal_or_reap(self):
        for mode in ('foreign', 'changed_pid'):
            with self.subTest(mode=mode):
                w = MemoryWorld()
                foreign = w.process(w.argv)
                foreign.pid = 8002
                w.instances.clear(); w.init_calls = 0
                def guard(*args, **kwargs):
                    p = w.create()
                    target = foreign if mode == 'foreign' else p
                    if mode == 'changed_pid': p.pid = 9999
                    try: target.kill(); target.wait(timeout=1)
                    finally: p.stdout.close(); p.stderr.close()
                    return w.original_result
                with w.installed(): status, _error = capture(lambda: self.invoke(w, guard))
                self.assertEqual([], [n for n in w.signals if n == (8002 if mode == 'foreign' else 9999)],
                                 'UNOWNED_SIGNAL_DELEGATED')
                self.assertFalse(any(pid == (8002 if mode == 'foreign' else 9999) for pid,_ in w.waits),
                                 'UNOWNED_REAP_DELEGATED')
                self.assertEqual('error', status)

    def test_original_operator_and_cleanup_operator_keep_objects_and_causes(self):
        for incoming_operator in (True, False):
            with self.subTest(incoming_operator=incoming_operator):
                body = KeyboardInterrupt('literal original operator') if incoming_operator else ValueError('literal body')
                body_cause = LookupError('literal original cause'); body.__cause__ = body_cause
                cleanup = OSError('literal stream cleanup') if incoming_operator else SystemExit('literal cleanup operator')
                cleanup_cause = ArithmeticError('literal cleanup cause'); cleanup.__cause__ = cleanup_cause
                w = MemoryWorld(close_error=cleanup)
                def guard(*args, **kwargs): w.create(); raise body
                expected = body if incoming_operator else cleanup
                with w.installed(): status, actual = capture(lambda: self.invoke(w, guard), (body, cleanup))
                self.assertEqual('error', status)
                self.assertIs(expected, actual, 'ORIGINAL_OPERATOR_PRIORITY_LOST')
                self.assertIs(body_cause if incoming_operator else cleanup_cause, actual.__cause__)
                self.assertIs(body_cause, body.__cause__)
                self.assertEqual([61, 62], w.stream_closes, 'LATER_ORIGINAL_STREAM_NOT_ATTEMPTED')
                self.assertTrue(w.archive_open)

    def test_normal_result_is_original_and_no_cleanup_assistance_is_hidden(self):
        w = MemoryWorld()
        def guard(*args, **kwargs):
            p = w.create(); p.wait(timeout=1)
            p.stdout.close(); p.stderr.close(); return w.original_result
        with w.installed(): result = self.invoke(w, guard)
        self.assertIs(w.original_result, result)
        self.assertEqual([], w.signals)
        self.assertEqual([(7101, 1)], w.waits)
        self.assertEqual([61, 62], w.stream_closes)
        self.assertTrue(w.archive_open)

    def test_original_operator_outranks_metadata_attachment_operator(self):
        attachment = SystemExit('literal metadata attachment operator')
        attachment_cause = ArithmeticError('literal attachment cause')
        attachment.__cause__ = attachment_cause
        class OriginalOperator(KeyboardInterrupt):
            def __setattr__(self, name, value):
                if name == 'project_image_guard_cleanup_errors': raise attachment
                return super().__setattr__(name, value)
        body = OriginalOperator('literal original refused attachment')
        body_cause = LookupError('literal original operator cause')
        body.__cause__ = body_cause
        ordinary = OSError('literal ordinary stream cleanup')
        w = MemoryWorld(close_error=ordinary)
        def guard(*args, **kwargs): w.create(); raise body
        with w.installed(): status, actual = capture(lambda: self.invoke(w, guard), (body, attachment))
        self.assertEqual('error', status)
        self.assertEqual([61, 62], w.stream_closes)
        self.assertTrue(EVENTS[-1]['restored'])
        self.assertTrue(w.archive_open)
        self.assertIs(body_cause, body.__cause__)
        self.assertIs(attachment_cause, attachment.__cause__)
        self.assertIs(body, actual, 'ATTACHMENT_OPERATOR_MASKED_ORIGINAL_OPERATOR')

    def test_exact_launch_adds_only_owned_child_cwd_and_retains_domain_archive(self):
        w = MemoryWorld()
        def guard(*args, **kwargs):
            p = w.create(); p.wait(timeout=1)
            p.stdout.close(); p.stderr.close(); return w.original_result
        with w.installed(): result = self.invoke(w, guard)
        self.assertIs(w.original_result, result)
        self.assertEqual(1,w.init_calls)
        self.assertEqual('/literal-owned/owned-native-guard.literal',w.init_kwargs[0].get('cwd'),
                         'FIXED_OWNED_CHILD_CWD_NOT_INSTALLED')
        self.assertEqual((77,),w.init_kwargs[0]['pass_fds'])
        self.assertEqual(w.argv,w.instances[0].args)
        self.assertTrue(w.archive_open)

    def test_unapproved_prefix_environment_or_archive_declaration_never_constructs(self):
        for fault in ('prefix','extra-env','archive-domain','bootstrap'):
            with self.subTest(fault=fault):
                w = MemoryWorld()
                if fault=='prefix':w.argv[1]='-B'
                elif fault=='extra-env':w.env['PYTHONPATH']='/literal-forbidden'
                elif fault=='archive-domain':w.argv[w.argv.index('--archive-fd')+1]='78'
                else:w.argv[5]='literal unpinned source'
                def guard(*args, **kwargs):
                    p = w.create(); p.wait(timeout=1)
                    p.stdout.close(); p.stderr.close(); return w.original_result
                with w.installed(): status,error = capture(lambda:self.invoke(w,guard))
                self.assertEqual(0,w.init_calls,'UNAPPROVED_CHILD_CONSTRUCTOR_DELEGATED')
                self.assertEqual('error',status)
                self.assertTrue(w.archive_open)
                self.assertTrue(EVENTS[-1]['restored'])


class ParentWorld(fixture.MemoryWorld):
    def __init__(self,lane='normal',close_error=None):
        super().__init__(lane,close_error)
        world=self
        self.hooks=[];self.audit_frame=None;self.other_calls=[];self.virtual_waits=[]
        self.poll_returns=[];self.parent_rows=[];self.assisted=[];self.body=None
        class Stream:
            def __init__(self,fd):self.fd=fd;self.closed=False
            def fileno(self):return self.fd
            def close(self):
                world.stream_closes.append(self.fd);self.closed=True
                if self.fd==61 and world.close_error is not None:raise world.close_error
        def native_waitpid(pid,flags):
            world.virtual_waits.append((pid,flags))
            if world.lane.startswith('echild'):
                raise ChildProcessError(errno.ECHILD,'literal no kernel status')
            if world.lane=='body' and not world.signals:return (0,0)
            return (pid,0)
        class Process:
            def __init__(self,argv,**kwargs):
                world.init_calls+=1;world.init_kwargs.append(dict(kwargs))
                self.returncode=None;self._child_created=False;self.args=argv
                self.stdout=Stream(61);self.stderr=Stream(62);self.stdin=None
                world.instances.append(self)
                self._execute_child(argv,cwd=kwargs.get('cwd'),env=kwargs.get('env'))
            def _execute_child(self,args,cwd=None,env=None):
                world.audit_frame=SimpleNamespace(f_code=execute_code,f_locals={'self':self})
                try:world.emit('subprocess.Popen',(args[0],list(args),cwd,env))
                finally:world.audit_frame=None
                self.pid=7101;self._child_created=True
            def _try_wait(self,flags):
                try:return world.os.waitpid(self.pid,flags)
                except ChildProcessError:return (self.pid,0)
            def wait(self,timeout=None):
                world.waits.append((self.pid,timeout))
                if self.returncode is None:
                    pid,status=self._try_wait(0)
                    if pid==self.pid:self.returncode=status
                return self.returncode
            def _internal_poll(self,_deadstate=None,_waitpid=native_waitpid,_WNOHANG=1,_ECHILD=errno.ECHILD):
                if self.returncode is None:
                    try:
                        pid,status=_waitpid(self.pid,_WNOHANG)
                        if pid==self.pid:self.returncode=status
                    except OSError as error:
                        if error.errno==_ECHILD:self.returncode=0
                        else:raise
                world.poll_returns.append(self.returncode);return self.returncode
            def poll(self):return self._internal_poll()
            def send_signal(self,sig):
                self.poll()
                if self.returncode is None:world.os.kill(self.pid,sig)
            def kill(self):self.send_signal(signal.SIGKILL)
            def terminate(self):self.send_signal(signal.SIGTERM)
        execute_code=Process._execute_child.__code__
        self.process=Process
        self.backend=SimpleNamespace(Popen=Process,PIPE=-1,DEVNULL=-3,
            TimeoutExpired=fixture.subprocess.TimeoutExpired,_active=[])
        def other(*a,**k):self.other_calls.append('unapproved-delegate')
        for name in ('run','call','check_call','check_output'):setattr(self.backend,name,other)
        for name in ('system','fork','forkpty','posix_spawn','posix_spawnp','execv','execve','killpg'):
            setattr(self.os,name,other)
        def kill(pid,sig):
            self.emit('os.kill',(pid,sig));self.signals.append(pid)
        self.os.kill=kill;self.os.waitpid=native_waitpid;self.os.WNOHANG=1
        self.socket=SimpleNamespace(socket=other,socketpair=other)
        class Thread:
            def __init__(self,*a,**k):other()
            def start(self):other()
        class Timer(Thread):pass
        self.threading=SimpleNamespace(Thread=Thread,Timer=Timer)
        self.lowthread=SimpleNamespace(start_new_thread=other)
        self.signal=SimpleNamespace(SIGKILL=signal.SIGKILL,signal=other,alarm=other,setitimer=other)
        def frame(n):
            if self.audit_frame is not None:return self.audit_frame
            return sys._getframe(n+1)
        self.sys=SimpleNamespace(addaudithook=self.hooks.append,_getframe=frame)
        def fd(value,named=True):
            if value==88:return dict(directory=True,path='/literal-owned/owned-native-guard.literal')
            if value==77:return dict(directory=False,path='/literal-owned/archive')
            raise AssertionError('literal unknown held FD')
        self.fs=SimpleNamespace(_fd=fd,_inside=lambda p:p.startswith('/literal-owned/'))
    def emit(self,event,args):
        for hook in self.hooks:hook(event,args)
    @contextlib.contextmanager
    def installed(self):
        names=('sys','socket','threading','_thread','signal')
        values=(self.sys,self.socket,self.threading,self.lowthread,self.signal)
        before=[(n,getattr(subject,n,MISSING)) for n in names]
        attrs=[(o,n,n in vars(o),inspect.getattr_static(o,n)) for o,ns in (
            (self.process,('__new__','__init__','_execute_child','wait','kill','_internal_poll','_try_wait','send_signal','terminate')),
            (self.threading.Thread,('__init__','start')),(self.threading.Timer,('__init__','start')))
            for n in ns]
        try:
            for n,v in zip(names,values):setattr(subject,n,v)
            if hasattr(subject,'PARENT_FACTS'):subject.PARENT_FACTS.clear()
            with super().installed():yield
        finally:
            self.parent_rows=list(getattr(subject,'PARENT_FACTS',[]))
            for n,v in reversed(before):
                if v is MISSING:delattr(subject,n)
                else:setattr(subject,n,v)
            restored=all((n in vars(o))==own and inspect.getattr_static(o,n) is v for o,n,own,v in attrs)
            # Assistance is separate and never used by the positive product oracle.
            for p in self.instances:
                for stream in (p.stdout,p.stderr):
                    if not stream.closed:stream.closed=True;self.assisted.append(stream.fd)
            if EVENTS:
                EVENTS[-1].update(restored=EVENTS[-1]['restored'] and restored,
                    virtual_waits=list(self.virtual_waits),other_delegates=list(self.other_calls),
                    audit_hooks=len(self.hooks),parent_rows=self.parent_rows,
                    fake_assistance=list(self.assisted))


@contextlib.contextmanager
def policy(w):
    if MODE=='BASELINE_NO_POLICY':
        # Explicit initial compatibility bridge: existing seam, no invented product policy.
        def admit(guard,argv,*,env,archive_fd,timeout=5):
            return subject.run_project_image_guard(guard,argv,env=env,archive_fd=archive_fd,timeout=timeout)
        admit.bind_helper=lambda code:None
        yield admit
    elif MODE=='PARENT_DEFAULT_ARM':
        with subject.parent_launch_boundary(w.fs) as admit:yield admit
    else:raise AssertionError('unreviewed test source mode')


def guard_for(w):
    def guard(argv,*,env,archive_fd,timeout):
        p=w.backend.Popen(argv,stdin=-3,stdout=-1,stderr=-1,shell=False,
                          bufsize=0,env=env,pass_fds=(archive_fd,))
        if w.body is not None:raise w.body
        if w.lane in ('poll','echild-poll'):p.poll()
        else:p.wait(timeout=1)
        p.stdout.close();p.stderr.close();return w.original_result
    return guard


def helper_call(w,admit,guard):
    activated=w.argv;environment=w.env;archive_fd=77;directory_fd=88;original_guard=guard
    return admit(original_guard,activated,env=environment,archive_fd=archive_fd,timeout=5)


def foreign_helper(w,admit,guard):
    activated=w.argv;environment=w.env;archive_fd=77;directory_fd=88;original_guard=guard
    return admit(original_guard,activated,env=environment,archive_fd=archive_fd,timeout=5)


class ParentDefaultArmTests(unittest.TestCase):
    def test_default_capabilities_have_zero_fake_delegate(self):
        for action in ('popen','socket','thread','fork','signal'):
            with self.subTest(action=action):
                w=ParentWorld()
                def invoke():
                    with policy(w):
                        if action=='popen':return w.create()
                        if action=='socket':return w.socket.socketpair()
                        if action=='thread':return w.threading.Thread()
                        if action=='fork':return w.os.fork()
                        return w.os.kill(9999,signal.SIGKILL)
                with w.installed():status,error=fixture.capture(invoke)
                self.assertEqual(0,w.init_calls,'DEFAULT_POPEN_DELEGATED')
                self.assertEqual([],w.other_calls,'DEFAULT_CAPABILITY_DELEGATED')
                self.assertEqual([],w.signals,'DEFAULT_FOREIGN_SIGNAL_DELEGATED')
                self.assertEqual('error',status)
                self.assertTrue(EVENTS[-1]['restored'])
    def test_exact_helper_single_arm_and_inactive_audit(self):
        w=ParentWorld();guard=guard_for(w);first=[]
        def invoke():
            with policy(w) as admit:
                admit.bind_helper(helper_call.__code__)
                first.append(helper_call(w,admit,guard))
                self.assertIs(w.original_result,first[0])
                status,error=fixture.capture(lambda:helper_call(w,admit,guard))
                self.assertEqual('error',status,'SECOND_ARM_WAS_ACCEPTED')
        with w.installed():status,error=fixture.capture(invoke)
        self.assertEqual(1,len(first),'FIRST_ARM_DID_NOT_RETURN')
        self.assertIs(w.original_result,first[0],'FIRST_ARM_ORIGINAL_RESULT_LOST')
        self.assertEqual(1,w.init_calls,'SECOND_CONSTRUCTOR_DELEGATED')
        self.assertEqual([(7101,0)],w.virtual_waits)
        self.assertTrue(w.archive_open)
        self.assertEqual(1,len(w.hooks),'PARENT_AUDIT_NOT_INSTALLED')
        w.emit('socket.__new__',())
        self.assertFalse(w.parent_rows[-1]['audit_active'])
        self.assertTrue(w.parent_rows[-1]['restored'])
        self.assertEqual('/literal-owned/owned-native-guard.literal',w.init_kwargs[0]['cwd'])
    def test_same_values_foreign_helper_never_constructs(self):
        w=ParentWorld();guard=guard_for(w)
        def invoke():
            with policy(w) as admit:
                admit.bind_helper(helper_call.__code__)
                return foreign_helper(w,admit,guard)
        with w.installed():status,error=fixture.capture(invoke)
        self.assertEqual(0,w.init_calls,'FOREIGN_HELPER_CONSTRUCTED')
        self.assertEqual('error',status)
        self.assertTrue(w.archive_open)
    def test_original_operator_survives_cleanup_and_parent_restoration(self):
        body=KeyboardInterrupt('literal parent body')
        cause=LookupError('literal parent body cause');body.__cause__=cause
        cleanup=OSError('literal stream close fault')
        w=ParentWorld('body',cleanup);w.body=body;guard=guard_for(w)
        def invoke():
            with policy(w) as admit:
                admit.bind_helper(helper_call.__code__)
                return helper_call(w,admit,guard)
        with w.installed():status,error=fixture.capture(invoke,(body,))
        self.assertEqual('error',status);self.assertIs(body,error);self.assertIs(cause,error.__cause__)
        self.assertEqual([61,62],w.stream_closes);self.assertTrue(EVENTS[-1]['restored'])
        self.assertEqual([7101],w.signals);self.assertEqual([(7101,1),(7101,0)],w.virtual_waits)
        self.assertEqual(1,len(w.hooks),'PARENT_AUDIT_NOT_INSTALLED')
        self.assertEqual([],w.assisted)
    def test_echild_synthetic_returncode_is_never_success(self):
        for lane in ('echild-wait','echild-poll'):
            with self.subTest(lane=lane):
                w=ParentWorld(lane);guard=guard_for(w)
                def invoke():
                    with policy(w) as admit:
                        admit.bind_helper(helper_call.__code__)
                        return helper_call(w,admit,guard)
                with w.installed():status,error=fixture.capture(invoke)
                self.assertEqual('error',status,'ECHILD_SYNTHETIC_ZERO_ACCEPTED')
                self.assertEqual([61,62],w.stream_closes)
                self.assertTrue(w.archive_open);self.assertTrue(EVENTS[-1]['restored'])
    def test_poll_default_waitpid_requires_original_receipt(self):
        w=ParentWorld('poll');guard=guard_for(w)
        def invoke():
            with policy(w) as admit:
                admit.bind_helper(helper_call.__code__)
                return helper_call(w,admit,guard)
        with w.installed():status,value=fixture.capture(invoke)
        self.assertEqual('return',status);self.assertIs(w.original_result,value)
        self.assertEqual([(7101,1)],w.virtual_waits)
        self.assertEqual(1,len(w.parent_rows),'PARENT_WAITPID_RECEIPT_ABSENT')
        self.assertEqual([dict(origin='_internal_poll',pid=7101,status=0)],w.parent_rows[-1]['reaped'])
        self.assertEqual([],w.parent_rows[-1]['wait_errors'])
        self.assertEqual([],w.assisted)


class RealPopenAllocatorTests(unittest.TestCase):
    def exercise(self):
        P=subprocess.Popen
        original_new=inspect.getattr_static(P,'__new__');new_own='__new__' in vars(P)
        original_init=inspect.getattr_static(P,'__init__')
        synthetic=[];observed={};object_result=None
        def synthetic_init(process,args,**keywords):
            # No original init or backend entry: only Python fields.
            process._child_created=False;process.returncode=0
            synthetic.append(process)
        P.__init__=synthetic_init
        subject.PARENT_FACTS.clear()
        try:
            try:
                with subject.parent_launch_boundary(SimpleNamespace()):
                    observed['allocator_untouched']=inspect.getattr_static(P,'__new__') is original_new
                    try:P(['literal-never-executed'])
                    except Exception as error:observed['default_refusal']=isinstance(error,subject.GuardOuterHold)
                    else:observed['default_refusal']=False
                    observed['default_delegates']=len(synthetic)
            except subject.GuardOuterHold:
                observed['unused_or_rejected_arm_hold']=True
            # Descriptor equality alone is deliberately not the behavioral oracle.
            observed['allocator_identity_restored']=(inspect.getattr_static(P,'__new__') is original_new
                                                      and ('__new__' in vars(P))==new_own)
            try:object_result=P(['literal-never-executed-after-restoration'])
            except Exception as error:
                observed['after_constructor']='error';observed['after_error']=type(error).__name__
            else:
                observed['after_constructor']='return';observed['after_error']=None
            observed['after_synthetic_count']=len(synthetic)
            observed['after_exact_type']=type(object_result) is P
            observed['after_no_child']=all(p._child_created is False for p in synthetic)
        finally:
            P.__init__=original_init
            observed['init_restored']=inspect.getattr_static(P,'__init__') is original_init
            observed['parent_restore']=all(r['restored'] and not r['audit_active']
                                          for r in subject.PARENT_FACTS)
            EVENTS.append(dict(lane='real-Popen-type-no-native-init',restored=observed['init_restored']
                               and observed.get('allocator_identity_restored',False)
                               and observed['parent_restore'],real_resources=False,
                               real_type_only=True,observed=observed))
        return observed
    def test_real_popen_allocator_is_never_modified_and_remains_callable(self):
        observed=self.exercise()
        self.assertTrue(observed['allocator_identity_restored'])
        self.assertEqual('return',observed['after_constructor'],'REAL_POPEN_SLOT_CHANGED')
        self.assertEqual(1,observed['after_synthetic_count'])
        self.assertTrue(observed['after_exact_type'])
        self.assertTrue(observed['allocator_untouched'],'REAL_POPEN_ALLOCATOR_WAS_PATCHED')
        self.assertTrue(observed['after_no_child'])
    def test_default_real_popen_type_refuses_before_synthetic_init(self):
        observed=self.exercise()
        self.assertTrue(observed['default_refusal'])
        self.assertEqual(0,observed['default_delegates'])
        self.assertTrue(observed['parent_restore'])
        self.assertTrue(observed['init_restored'])
