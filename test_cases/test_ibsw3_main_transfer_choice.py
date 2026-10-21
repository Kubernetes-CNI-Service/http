"""UNRUN real guarded entry/menu and natural password rejection workflow.

Only menu/hidden-input and original remote IO fixture are controlled. No selector
return, bound verifier, factory result, dispatch or ACK is fabricated.
"""
import contextlib
import fcntl
import os
from pathlib import Path
import select
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from test_cases import scp_main_selector_fixture as FIXTURE


class MenuTTY:
    def __init__(self, answers, tty=True):
        self.answers, self.tty, self.reads = list(answers), tty, 0

    def isatty(self):
        return self.tty

    def readline(self, limit):
        self.reads += 1
        if not self.answers:
            raise AssertionError('unexpected repeated transfer menu or source prompt')
        return self.answers.pop(0)


@contextlib.contextmanager
def owned_guard_inode(root):
    path=root/'private-bringup-runtime.lock'
    fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        info=os.fstat(fd)
        identity=(info.st_dev,info.st_ino,info.st_mode,info.st_nlink,info.st_uid,
                  info.st_gid,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
        yield path,fd,identity
    finally:
        os.close(fd)


class MainTransferChoiceTests(unittest.TestCase):
    def exercise(self, root, *, answer='', readable=True, tty=True, explicit=None, retry=False):
        with owned_guard_inode(root) as (lock,holder,identity):
            # Independent fixture boundary control: an unrelated own inode
            # must still be rejected, never a new project-lock allowance.
            foreign=os.open(root/'forbidden-project-lock',os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
            try:
                with FIXTURE._private_guard_locks(lock,holder,identity):
                    with self.assertRaises(AssertionError):
                        fcntl.flock(foreign,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    fcntl.flock(holder,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    fcntl.flock(holder,fcntl.LOCK_UN)
            finally:
                os.close(foreign)
            return self._exercise(root,answer=answer,readable=readable,tty=tty,
                explicit=explicit,retry=retry,guard_holder=holder,guard_identity=identity)

    def _exercise(self, root, *, answer='', readable=True, tty=True, explicit=None,
                  retry=False,guard_holder,guard_identity):
        app, driver = FIXTURE.app, FIXTURE.driver
        chooser = getattr(app, '_choose_transfer_method', None)
        self.assertTrue(callable(chooser), 'reviewed selector helper prerequisite')
        lock = root/'private-bringup-runtime.lock'
        stdin = MenuTTY([answer, 'http\n', 'http\n'], tty)
        events, waits, busy, attempts, methods = [], [], [], [], []
        main, scope_init = app.main, driver._PreparedRunScope.__init__
        inventory = driver.preflight_inventory_selection
        def guard_busy(label):
            # Probe only this test's exact private guard inode, not shared /tmp.
            fd = os.open(lock,os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
            held = False
            try:
                try:
                    fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                except BlockingIOError:
                    held = True
                else:
                    fcntl.flock(fd,fcntl.LOCK_UN)
            finally:
                os.close(fd)
            busy.append((label,held))
        def ready(read, write, exceptional, timeout):
            waits.append((list(read),list(write),list(exceptional),timeout))
            events.append('menu')
            guard_busy('menu')
            return (read if readable else [],[],[])
        def password():
            events.append('target-password')
            guard_busy('target-password')
            return 'SYNTHETIC'
        def observe(frame,event,argument):
            if event == 'call' and frame.f_code is main.__code__ and frame.f_globals is main.__globals__:
                attempts.append(frame.f_locals['_password_attempt'])
            elif (event == 'return' and argument is not None
                    and frame.f_code is inventory.__code__ and frame.f_globals is inventory.__globals__):
                events.append('input-inventory')
            elif (event == 'return' and frame.f_code is scope_init.__code__
                    and frame.f_globals is scope_init.__globals__):
                current = frame.f_locals.get('self')
                if type(current) is driver._PreparedRunScope and hasattr(current,'parsed'):
                    methods.append(current.parsed.method)
        self.assertIsNone(sys.getprofile())
        self.assertIsNone(threading.getprofile())
        source_prompt = None
        fixture = FIXTURE.ThreeComponentWorkflowTests()
        try:
            sys.setprofile(observe)
            threading.setprofile(observe)
            with patch.object(app._runtime_guard_owner,'_RUNTIME_GUARD_PATH',lock), \
                 patch.object(sys,'stdin',stdin), \
                 patch.object(select,'select',side_effect=ready), \
                 patch.object(app.getpass,'getpass',side_effect=AssertionError('no source secret in this slice')) as source_prompt:
                result = fixture.invoke(root,selection=('--os-only',),controlled_grace=True,
                    inspect=not retry,explicit_method=explicit,password_hook=password,
                    initial_keys_missing=retry,bad_password=retry,
                    password_prompt_attempts=3 if retry else 1,
                    guard_path=lock,guard_holder=guard_holder,guard_identity=guard_identity)
        finally:
            threading.setprofile(None)
            sys.setprofile(None)
        # Original guarded entry has now returned. Verify private lock released.
        fd=os.open(lock,os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            fcntl.flock(fd,fcntl.LOCK_UN)
        finally:
            os.close(fd)
        return result,fixture,dict(events=events,waits=waits,busy=busy,attempts=attempts,
            methods=methods,reads=stdin.reads,source_prompts=source_prompt.call_count)

    def test_guarded_main_actually_selects_once_and_passes_method_into_original_scopes(self):
        cases = (('enter','\n',True,True,None,'http'),
                 ('timeout','',False,True,None,'http'),
                 ('scp','scp\n',True,True,None,'scp'),
                 ('explicit_http','',False,True,'http','http'),
                 ('explicit_scp','',False,True,'scp','scp'),
                 ('non_tty','',False,False,None,'http'),
                 ('https','',False,True,'https',None))
        for label,answer,readable,tty,explicit,expected in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as raw:
                result, fixture, facts = self.exercise(Path(raw).resolve(),answer=answer,
                    readable=readable,tty=tty,explicit=explicit)
                code,report,error,queries,installs=result
                should_wait=explicit is None and tty
                self.assertEqual(int(should_wait),len(facts['waits']),
                    'helper existence cannot replace actual main menu invocation')
                for read,write,exceptional,timeout in facts['waits']:
                    self.assertEqual(1,len(read))
                    self.assertEqual([],write)
                    self.assertEqual([],exceptional)
                    self.assertEqual(15.0,timeout)
                self.assertEqual(int(should_wait and readable),facts['reads'])
                self.assertTrue(all(value for _,value in facts['busy']),facts['busy'])
                self.assertEqual(0,facts['source_prompts'])
                self.assertEqual([],installs)
                self.assertNotIn('target-password',facts['events'])
                if expected is None:
                    self.assertNotEqual(0,code,'HTTPS must not become an HTTP observation')
                    self.assertEqual([],queries)
                    self.assertEqual([],facts['methods'])
                else:
                    self.assertEqual(0,code,error+repr(report))
                    self.assertTrue(queries,'real original readonly workflow must actually run')
                    self.assertTrue(facts['methods'])
                    self.assertEqual({expected},set(facts['methods']))

    def test_natural_password_reentry_retains_first_scp_choice_without_another_menu(self):
        with tempfile.TemporaryDirectory() as raw:
            result,fixture,facts=self.exercise(Path(raw).resolve(),answer='scp\n',retry=True)
            code,report,error,queries,installs=result
            self.assertEqual(1,len(facts['waits']),'one initial menu; password retry must not reselect transport')
            self.assertEqual(15.0,facts['waits'][0][3])
            self.assertEqual(1,facts['reads'])
            self.assertEqual([1,2,3],facts['attempts'],'original bounded natural rejection/reentry path')
            self.assertEqual(['menu']+['target-password']*3,
                             [item for item in facts['events'] if item != 'input-inventory'])
            self.assertEqual(3,facts['events'].count('input-inventory'))
            pending_inventory=False
            for event in facts['events']:
                if event == 'input-inventory':
                    pending_inventory=True
                elif event == 'target-password':
                    self.assertTrue(pending_inventory,'actual original input preflight must precede each target password')
                    pending_inventory=False
            self.assertTrue(facts['busy'])
            self.assertTrue(all(value for _,value in facts['busy']),facts['busy'])
            self.assertTrue(facts['methods'])
            self.assertEqual({'scp'},set(facts['methods']),'SCP cannot silently become default HTTP on retry')
            self.assertEqual(0,facts['source_prompts'],'target password rejection precedes source credentials')
            self.assertEqual(3,code,error+repr(report))
            self.assertEqual([],installs)
            self.assertEqual(b'',fixture._last_access_snapshot,'no imported management key after rejection')
            self.assertEqual(['PASSWORD_PREFLIGHT_REJECTED'],report['skipped_devices'][0]['reasons'])
            self.assertEqual(3,report['password_attempt'])
            self.assertEqual(2,len(report['previous_password_attempt_runs']))
            self.assertEqual(2,error.count('[AUTH] Existing password was explicitly rejected'))
