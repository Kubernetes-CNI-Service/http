"""Fixed auth-only entry, real owned children/flock and loopback TLS; no activation."""
from contextlib import ExitStack
import fcntl
import importlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_req7_spreadsheet_owner import binding, scoped_fixture
import test_req7_native_tls_wire as native_tls_fixture

ROOT = Path(__file__).resolve().parents[1]
NAME = 'monitor.issue_tracker_token_launcher'


def load():
    if not (ROOT / 'monitor/issue_tracker_token_launcher.py').is_file():
        raise AssertionError('REQ7 fixed owned token launcher missing')
    return importlib.import_module(NAME)


class Req7TokenLauncherDirectTests(unittest.TestCase):
    def test_fixed_project_program_executes_its_imported_entry_without_traceback_or_input_reads(self):
        module=load()
        # Execute the shipped entry text under -I, not a fixture that invokes
        # launcher._project_token_child directly and hides import-name drift.
        prelude='''import sys
sys.path[:0]=[sys.argv[1],sys.argv[1]+"/tools"]
from types import SimpleNamespace
from monitor import issue_tracker_token_launcher as launcher
launcher.os=SimpleNamespace(geteuid=lambda:501)
'''
        result=subprocess.run([str(Path(sys.executable).resolve()),'-I','-B','-c',
            prelude+module._PROJECT_CHILD_PROGRAM,str(ROOT),'a'*64],stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'LC_ALL':'C'},timeout=5)
        self.assertEqual(1,result.returncode)
        self.assertEqual(b'',result.stdout)
        self.assertEqual(b'',result.stderr,'fixed nonroot denial must not fail at an unimported entry symbol')

    def test_g1_project_protocol_is_separate_and_decoding_or_copying_does_not_issue_authority(self):
        self.assertTrue(hasattr(load(), '_decode_project_completion'),
                        'G1 needs project identity from the actual supervised auth child')
        module=load(); nonce='a'*64
        image={'schema_version':2,'nonce':nonce,'token':'synthetic-token',
               'expires_at':time.time()+3600,'runtime_warnings':[],
               'cloud_project_id':'synthetic-cloud-project','credential_sha256':'b'*64}
        raw=module._canonical(image); value=module._decode_project_completion(raw,nonce)
        self.assertEqual('synthetic-cloud-project',value.cloud_project_id)
        self.assertEqual('b'*64,value.credential_sha256)
        self.assertNotIn('synthetic-token',repr(value)); self.assertNotIn('synthetic-cloud-project',repr(value))
        self.assertFalse(hasattr(value,'permit')); self.assertFalse(hasattr(value,'inventory_complete'))
        with self.assertRaises(module.TokenLauncherHold): module._decode_completion(raw,nonce)
        from monitor import issue_tracker_credential_shape as private
        with mock.patch.object(private,'_read_private_file') as reader:
            with self.assertRaises(module.TokenLauncherHold) as caught:
                module.require_current_owned_project_token(object(),binding(),value)
            self.assertIsNone(caught.exception.__context__); reader.assert_not_called()
        for field,bad in (('schema_version',1),('cloud_project_id',True),('cloud_project_id',''),
                           ('cloud_project_id','foreign project'),('credential_sha256','b'*63),
                           ('credential_sha256',True),('nonce','c'*64),('expires_at',0)):
            altered=dict(image); altered[field]=bad
            with self.subTest(field=field),self.assertRaises(module.TokenLauncherHold):
                module._decode_project_completion(module._canonical(altered),nonce)

    def test_g1_project_unit_requires_actual_owner_before_credential_or_child(self):
        module=load()
        self.assertTrue(hasattr(module,'OwnedProjectTokenRefreshUnit'))
        from monitor import issue_tracker_credential_shape as private
        with mock.patch.object(private,'_read_private_file') as reader, mock.patch.object(module.subprocess,'Popen') as launch:
            with self.assertRaises(module.TokenLauncherHold): module.OwnedProjectTokenRefreshUnit(object(),binding())
            reader.assert_not_called(); launch.assert_not_called()

    def test_unheld_owner_refuses_before_child_creation_or_credential_import(self):
        module = load()
        for token in (None, object(), {'owner': 'caller'}):
            with self.subTest(type=type(token).__name__), mock.patch.object(module.subprocess, 'Popen') as launch:
                with self.assertRaises(module.TokenLauncherHold) as caught:
                    module.OwnedTokenRefreshUnit(token, binding())
                self.assertIsNone(caught.exception.__context__)
                self.assertEqual('req7_owned_token_refresh_denied', str(caught.exception))
                launch.assert_not_called()

    def test_correlated_token_result_is_bounded_typed_canonical_and_private(self):
        module = load(); nonce = 'a' * 64
        image = {'schema_version': 1, 'nonce': nonce, 'token': 'synthetic-token',
                 'expires_at': time.time() + 3600, 'runtime_warnings': []}
        raw = (json.dumps(image, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
        value = module._decode_completion(raw, nonce)
        self.assertEqual('synthetic-token', value.token.value)
        self.assertEqual((), value.runtime_warnings)
        self.assertIs(True, value.termination_confirmed)
        self.assertNotIn('synthetic-token', repr(value))
        variants = [b'', b'x' * 32769, raw + raw, raw.replace(b'"schema_version":1', b'"schema_version":true'),
                    raw.replace(b'"token":"synthetic-token"', b'"token":"synthetic-token","token":"foreign"')]
        for key, bad in (('nonce', 'b' * 64), ('expires_at', True), ('expires_at', -1),
                         ('expires_at', float('nan')), ('token', 'secret\r\nheader'),
                         ('runtime_warnings', ['unknown-private-warning']), ('schema_version', 2)):
            altered = dict(image); altered[key] = bad
            variants.append((json.dumps(altered, sort_keys=True, separators=(',', ':')) + '\n').encode())
        for raw in variants:
            with self.subTest(size=len(raw)), self.assertRaises(module.TokenLauncherHold) as caught:
                module._decode_completion(raw, nonce)
            self.assertIsNone(caught.exception.__context__)
            self.assertNotIn('secret', str(caught.exception))

    def test_fixed_child_entry_rejects_nonce_or_nonroot_without_reading_private_inputs(self):
        module = load()
        from monitor import issue_tracker_credential_shape as private
        with mock.patch.object(private, 'read_service_account_info') as reader:
            with mock.patch.object(module.os, 'geteuid', return_value=501):
                self.assertEqual(1, module._token_child('a' * 64))
            for bad in ('../caller', 'b' * 63, None, True):
                self.assertEqual(1, module._token_child(bad))
            reader.assert_not_called()


class Req7FixedTokenLauncherWorkflowTests(unittest.TestCase):
    # Reuse owned TLS fixture machinery, not its tests or patched transport.
    setUp = native_tls_fixture.Req7NativeTlsWireTests.setUp
    fixture = native_tls_fixture.Req7NativeTlsWireTests.fixture
    certificates = native_tls_fixture.Req7NativeTlsWireTests.certificates
    server = native_tls_fixture.Req7NativeTlsWireTests.server

    def owner(self, stack):
        from monitor import issue_tracker_spreadsheet_owner as ownership
        locks = self.root / 'var/lib/http-ztp-container/issue-tracker'
        locks.mkdir(parents=True, mode=0o700, exist_ok=True); locks.chmod(0o700)
        stack.enter_context(scoped_fixture(self.root, ownership))
        token = stack.enter_context(ownership.spreadsheet_owner(binding()))
        return ownership, token

    def intercept(self, stack, program=None, *, token=None, ownership=None, project_scope=False):
        module = load(); native = subprocess.Popen; observed = []; children = []
        def launch(argv, **kwargs):
            self.assertEqual([str(Path(sys.executable).resolve()), '-I', '-B', '-c'], argv[:4])
            self.assertEqual(module._PROJECT_CHILD_PROGRAM if project_scope else module._CHILD_PROGRAM, argv[4])
            self.assertEqual(str(ROOT), argv[5]); self.assertRegex(argv[6], r'^[0-9a-f]{64}$')
            self.assertEqual(7, len(argv))
            self.assertIs(kwargs['stdin'], subprocess.DEVNULL)
            self.assertIs(kwargs['stdout'], subprocess.PIPE); self.assertIs(kwargs['stderr'], subprocess.PIPE)
            self.assertIs(kwargs['start_new_session'], True); self.assertIs(kwargs['close_fds'], True)
            self.assertEqual({'LC_ALL': 'C'}, kwargs['env'])
            self.assertIsNone(kwargs.get('shell')); self.assertEqual(str(ROOT), kwargs['cwd'])
            self.assertEqual((ownership.owner_lock_fd(token, binding()),), kwargs['pass_fds'])
            observed.append((tuple(argv), dict(kwargs)))
            fixture_argv = list(argv)
            if program is not None: fixture_argv[4] = program
            child = native(fixture_argv, **kwargs); children.append(child); return child
        from types import SimpleNamespace
        stack.enter_context(mock.patch.object(module, 'subprocess', SimpleNamespace(
            Popen=launch, DEVNULL=subprocess.DEVNULL, PIPE=subprocess.PIPE)))
        def cleanup():
            for child in children:
                if child.poll() is None:
                    self.assertEqual(child.pid, os.getpgid(child.pid))
                    self.assertEqual(child.pid, os.getsid(child.pid))
                    os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=3)
                for stream in (child.stdout, child.stderr):
                    if stream is not None: stream.close()
        self.addCleanup(cleanup)
        return observed, children

    def test_actual_fixed_entry_without_valid_nonce_refuses_no_credentials_no_retries(self):
        module = load()
        with ExitStack() as stack:
            ownership, token = self.owner(stack)
            # Same actual fixed entry, with only a malformed nonce injected at
            # the owned launch boundary. It refuses before root/private reads
            # on both nonroot macOS and root Linux proof environments.
            program=module._CHILD_PROGRAM.replace('_token_child(sys.argv[2])','_token_child("invalid")')
            observed, children = self.intercept(stack,program,token=token,ownership=ownership)
            unit = module.OwnedTokenRefreshUnit(token, binding())
            with self.assertRaises(module.TokenLauncherHold) as caught: unit.refresh_once()
            self.assertIs(True, caught.exception.termination_confirmed)
            with self.assertRaises(module.TokenLauncherHold): unit.refresh_once()
            self.assertEqual(1, len(observed)); self.assertEqual(1, children[0].returncode)
            self.assertIsNone(caught.exception.__context__)
            ownership.owner_lock_fd(token, binding())

    def test_launcher_output_corruption_cannot_become_authentication_or_reuse_unit(self):
        module = load()
        images = (b'{}\n', b'private secret stderr')
        for image in images:
            with tempfile.TemporaryDirectory() as owned:
                previous_root = self.root; self.root = Path(owned)
                try:
                    with ExitStack() as stack:
                        ownership, token = self.owner(stack)
                        program = 'import os; os.write(%d,%r)' % (2 if image == images[1] else 1, image)
                        observed, children = self.intercept(stack, program, token=token, ownership=ownership)
                        unit = module.OwnedTokenRefreshUnit(token, binding())
                        with self.assertRaises(module.TokenLauncherHold) as caught: unit.refresh_once()
                        self.assertIsNone(caught.exception.__context__)
                        self.assertNotIn('secret', str(caught.exception))
                        with self.assertRaises(module.TokenLauncherHold): unit.refresh_once()
                        self.assertEqual(1, len(observed)); self.assertIsNotNone(children[0].poll())
                finally: self.root = previous_root

    def test_revoked_owner_or_launch_failure_cannot_restart_or_resolve_credentials(self):
        module = load()
        with ExitStack() as stack:
            ownership, token = self.owner(stack)
            unit = module.OwnedTokenRefreshUnit(token, binding())
        with mock.patch.object(module.subprocess, 'Popen') as child:
            with self.assertRaises(module.TokenLauncherHold): unit.refresh_once()
            with self.assertRaises(module.TokenLauncherHold): unit.refresh_once()
            child.assert_not_called()

    def test_launch_failure_consumes_unit_without_disclosing_error_or_retrying(self):
        module = load()
        from types import SimpleNamespace
        with ExitStack() as stack:
            ownership, token = self.owner(stack)
            launch = mock.Mock(side_effect=OSError('synthetic private launch error'))
            stack.enter_context(mock.patch.object(module, 'subprocess', SimpleNamespace(
                Popen=launch, DEVNULL=subprocess.DEVNULL, PIPE=subprocess.PIPE)))
            unit = module.OwnedTokenRefreshUnit(token,binding())
            with self.assertRaises(module.TokenLauncherHold) as caught: unit.refresh_once()
            self.assertIsNone(caught.exception.__context__); self.assertIsNone(caught.exception.__cause__)
            self.assertIs(False,caught.exception.termination_confirmed)
            with self.assertRaises(module.TokenLauncherHold): unit.refresh_once()
            self.assertEqual(1,launch.call_count)
            ownership.owner_lock_fd(token,binding())

    def test_startup_is_not_a_fresh_budget_and_owned_child_is_reaped(self):
        module = load()
        from types import SimpleNamespace
        with ExitStack() as stack:
            ownership, token = self.owner(stack)
            observed, children = self.intercept(stack, 'import time; time.sleep(100)', token=token, ownership=ownership)
            # Only the launcher clock is offset; the real supervisor's clock,
            # 30-second budget, child startup/cleanup and assertions are intact.
            stack.enter_context(mock.patch.object(module,'time',SimpleNamespace(monotonic=lambda:time.monotonic()-29.8)))
            unit = module.OwnedTokenRefreshUnit(token,binding()); started=time.monotonic()
            with self.assertRaises(module.TokenLauncherHold) as caught: unit.refresh_once()
            self.assertLess(time.monotonic()-started,3)
            self.assertIs(True,caught.exception.termination_confirmed)
            self.assertIsNotNone(children[0].poll()); self.assertEqual(1,len(observed))
            with self.assertRaises(module.TokenLauncherHold): unit.refresh_once()
            self.assertEqual(1,len(observed)); ownership.owner_lock_fd(token,binding())

    def test_exhausted_prelaunch_budget_never_creates_a_requesting_child(self):
        module=load()
        from types import SimpleNamespace
        with ExitStack() as stack:
            ownership,token=self.owner(stack)
            observed,children=self.intercept(stack,'import time; time.sleep(100)',token=token,ownership=ownership)
            stack.enter_context(mock.patch.object(module,'time',SimpleNamespace(monotonic=lambda:time.monotonic()-30)))
            unit=module.OwnedTokenRefreshUnit(token,binding())
            with self.assertRaises(module.TokenLauncherHold): unit.refresh_once()
            self.assertEqual([],observed,'expired auth budget must stop before Popen')
            self.assertEqual([],children)

    def test_unconfirmed_auth_child_retains_actual_inherited_lock_after_owner_exit(self):
        module=load()
        from types import SimpleNamespace
        from monitor import issue_tracker_attempt_supervision as supervision
        with ExitStack() as stack:
            ownership,token=self.owner(stack)
            fd=ownership.owner_lock_fd(token,binding())
            observed,children=self.intercept(stack,'import time; time.sleep(100)',token=token,ownership=ownership)
            stack.enter_context(mock.patch.object(module,'time',SimpleNamespace(monotonic=lambda:time.monotonic()-29.9)))
            stack.enter_context(mock.patch.object(supervision,'_stop_owned_group',return_value=False))
            unit=module.OwnedTokenRefreshUnit(token,binding())
            with self.assertRaises(module.TokenLauncherHold) as caught: unit.refresh_once()
            self.assertIs(False,caught.exception.termination_confirmed)
            self.assertIsNone(children[0].poll()); self.assertEqual(1,len(observed))
            lock_path=self.root/'var/lib/http-ztp-container/issue-tracker'/ownership._binding(binding())
        with self.assertRaises(OSError): os.fstat(fd)
        contender=os.open(lock_path,os.O_RDWR)
        try:
            with self.assertRaises(BlockingIOError): fcntl.flock(contender,fcntl.LOCK_EX|fcntl.LOCK_NB)
            child=children[0]
            self.assertEqual(child.pid,os.getpgid(child.pid)); self.assertEqual(child.pid,os.getsid(child.pid))
            child.kill(); child.wait(timeout=3)  # Only the owned unreaped fixture leader.
            fcntl.flock(contender,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.assertEqual(b'',lock_path.read_bytes())
        finally: os.close(contender)

    def test_manifest_maps_fixed_launcher_and_every_actual_auth_boundary(self):
        manifest=json.loads((ROOT/'test_cases/script_test_manifest.json').read_text())
        path='monitor/issue_tracker_token_launcher.py'
        direct=next((rule for rule in manifest['test_rules'] if path in rule['paths']),None)
        self.assertIsNotNone(direct,'new fixed launcher has no direct mapping')
        self.assertIn('test_cases.test_req7_token_launcher',direct['tests'])
        workflow=next((rule for rule in manifest['workflows'] if rule['id']=='req7_fixed_owned_auth_launcher'),None)
        self.assertIsNotNone(workflow,'new auth process boundary has no genuine workflow mapping')
        self.assertTrue({path,'monitor/issue_tracker_attempt_supervision.py','monitor/issue_tracker_spreadsheet_owner.py',
                         'monitor/issue_tracker_credential_shape.py','monitor/issue_tracker_sdk_authentication.py',
                         'monitor/issue_tracker_tls_inputs.py','tools/req7_dependency_contract.py'} <= set(workflow['members']))

    def child_fixture(self, port, *, project_scope=False):
        # Inject only fixed-file ownership/path and DNS at owned boundaries.
        # Public SDK, signing, one-shot adapter, HTTPS/SSL and supervision stay real.
        from importlib import metadata
        names=('google-auth','cryptography','cffi','pyasn1-modules','pyasn1','pycparser')
        if sys.version_info[:2] < (3,11): names += ('typing_extensions',)
        dependency_roots = sorted({str(metadata.distribution(name).locate_file('')) for name in names})
        program='''import sys, os, socket
sys.path[:0]=[sys.argv[1],sys.argv[1]+"/tools"]
sys.path.extend(%r)
from types import SimpleNamespace
from unittest import mock
from contextlib import ExitStack
from monitor import issue_tracker_token_launcher as launcher
from monitor import issue_tracker_credential_shape as private
from monitor import issue_tracker_tls_inputs as tls
from monitor import issue_tracker_sdk_authentication as sdk
def metadata(value):
    fields=("st_dev","st_ino","st_mode","st_uid","st_gid","st_nlink","st_size","st_mtime_ns","st_ctime_ns")
    result=SimpleNamespace(**{name:getattr(value,name) for name in fields}); result.st_uid=0; return result
def facade():
    value=SimpleNamespace(**{name:getattr(os,name) for name in dir(os)})
    value.geteuid=lambda:0
    value.open=lambda name,flags,*a,**k:os.open(%r if name=="/" else name,flags,*a,**k)
    value.fstat=lambda fd:metadata(os.fstat(fd))
    value.stat=lambda *a,**k:metadata(os.stat(*a,**k))
    return value
def resolve(host,port,*a,**k):
    if (host,port)!=("oauth2.googleapis.com",443): raise AssertionError("foreign DNS forbidden")
    return [(socket.AF_INET,socket.SOCK_STREAM,6,"",("127.0.0.1",%d))]
with ExitStack() as stack:
    stack.enter_context(mock.patch.object(private,"os",facade()))
    stack.enter_context(mock.patch.object(tls,"os",facade()))
    stack.enter_context(mock.patch.object(launcher,"os",facade()))
    stack.enter_context(mock.patch.object(sdk,"os",facade()))
    stack.enter_context(mock.patch("socket.getaddrinfo",side_effect=resolve))
    result=launcher._token_child(sys.argv[2])
raise SystemExit(result)
''' % (dependency_roots, str(self.root), port)
        entry=load()._PROJECT_CHILD_PROGRAM if project_scope else load()._CHILD_PROGRAM
        return program.replace('result=launcher._token_child(sys.argv[2])','exec(%r)'%entry)

    def test_g1_real_fixed_sdk_tls_child_issues_owner_bound_project_not_copyable_or_stale(self):
        from dataclasses import replace
        import hashlib
        from types import SimpleNamespace
        from test_req7_sdk_authentication import fresh_info
        from monitor import issue_tracker_credential_shape as private_module
        module=load()
        self.assertTrue(hasattr(module,'OwnedProjectTokenRefreshUnit'),
                        'dedicated-project contract needs original live auth provenance')
        directory=self.root/'var/lib/http-ztp-container/service-account'
        directory.mkdir(parents=True,mode=0o700); directory.chmod(0o700)
        credential=directory/'cre.json'
        info=fresh_info(); info['project_id']='synthetic-cloud-project'
        original=json.dumps(info).encode(); credential.write_bytes(original); credential.chmod(0o600)
        fixture_token='synthetic-token'
        payload=json.dumps({'access_token':fixture_token,'expires_in':3600},
                           separators=(',',':')).encode('ascii')
        reply=('HTTP/1.1 200 Synthetic\r\nContent-Length: %d\r\nConnection: close\r\n\r\n'%len(payload)).encode()+payload
        with self.server(reply) as (records,errors),ExitStack() as stack:
            ownership,owner=self.owner(stack)
            observed,children=self.intercept(stack,self.child_fixture(socket_address_port(),project_scope=True),
                token=owner,ownership=ownership,project_scope=True)
            unit=module.OwnedProjectTokenRefreshUnit(owner,binding())
            with self.assertWarnsRegex(FutureWarning,'Python version 3.9 past its end of life') if sys.version_info[:2]==(3,9) else ExitStack():
                value=unit.refresh_once()
            self.assertEqual('synthetic-cloud-project',value.cloud_project_id)
            self.assertEqual(hashlib.sha256(original).hexdigest(),value.credential_sha256)
            self.assertEqual('synthetic-token',value.token.value)
            with self.assertRaises(module.TokenLauncherHold): unit.refresh_once()
            # Synthetic root metadata only at the existing fixed-file reader;
            # genuine FD reads and the issued object/owner registry stay real.
            stack.enter_context(scoped_fixture(self.root,private_module))
            sdk_module=importlib.import_module('monitor.issue_tracker_sdk_authentication')
            stack.enter_context(scoped_fixture(self.root,sdk_module))
            self.assertEqual(('synthetic-cloud-project',hashlib.sha256(original).hexdigest()),
                module.require_current_owned_project_token(owner,binding(),value))
            for forged in (replace(value),replace(value,cloud_project_id='foreign-cloud-project')):
                with self.assertRaises(module.TokenLauncherHold): module.require_current_owned_project_token(owner,binding(),forged)
            with self.assertRaises(module.TokenLauncherHold): module.require_current_owned_project_token(object(),binding(),value)
            with mock.patch.object(module,'os',SimpleNamespace(getpid=lambda:os.getpid()+1)),self.assertRaises(module.TokenLauncherHold):
                module.require_current_owned_project_token(owner,binding(),value)
            changed=dict(info); changed['project_id']='foreign-cloud-project'
            credential.write_bytes(json.dumps(changed).encode())
            with self.assertRaises(module.TokenLauncherHold): module.require_current_owned_project_token(owner,binding(),value)
            credential.write_bytes(original)
            self.assertEqual(('synthetic-cloud-project',hashlib.sha256(original).hexdigest()),
                module.require_current_owned_project_token(owner,binding(),value))
            with mock.patch.object(module,'time',SimpleNamespace(time=lambda:value.token.expires_at)),self.assertRaises(module.TokenLauncherHold):
                module.require_current_owned_project_token(owner,binding(),value)
            self.assertEqual(1,len(observed)); self.assertEqual(0,children[0].returncode)
        with self.assertRaises(module.TokenLauncherHold): module.require_current_owned_project_token(owner,binding(),value)
        self.assertEqual([],errors); self.assertEqual(1,len(records)); self.assertEqual(original,credential.read_bytes())

    def test_g1_auth_rejection_keeps_one_real_oauth_attempt_without_project_issue_or_retry(self):
        from test_req7_sdk_authentication import fresh_info
        module=load()
        directory=self.root/'var/lib/http-ztp-container/service-account'
        directory.mkdir(parents=True,mode=0o700); directory.chmod(0o700)
        credential=directory/'cre.json'; info=fresh_info(); info['project_id']='synthetic-cloud-project'
        original=json.dumps(info).encode(); credential.write_bytes(original); credential.chmod(0o600)
        for status in (401,503):
            payload=b'{"error":"temporarily_unavailable"}'
            reply=('HTTP/1.1 %d Synthetic\r\nContent-Length: %d\r\nConnection: close\r\n\r\n'%(status,len(payload))).encode()+payload
            with self.subTest(status=status),self.server(reply) as (records,errors),ExitStack() as stack:
                ownership,owner=self.owner(stack)
                observed,children=self.intercept(stack,self.child_fixture(socket_address_port(),project_scope=True),
                    token=owner,ownership=ownership,project_scope=True)
                unit=module.OwnedProjectTokenRefreshUnit(owner,binding())
                with module._PROJECT_GUARD: before=tuple(module._PROJECT_TOKENS)
                with self.assertRaises(module.TokenLauncherHold) as caught: unit.refresh_once()
                self.assertIsNone(caught.exception.__context__)
                self.assertIs(True,caught.exception.termination_confirmed)
                with self.assertRaises(module.TokenLauncherHold): unit.refresh_once()
                with module._PROJECT_GUARD: self.assertEqual(before,tuple(module._PROJECT_TOKENS))
                self.assertEqual(1,len(observed)); self.assertEqual(1,children[0].returncode)
            self.assertEqual([],errors); self.assertEqual(1,len(records)); self.assertEqual(original,credential.read_bytes())

    def test_fixed_auth_child_uses_real_sdk_native_tls_and_one_inherited_lock(self):
        module = load()
        from test_req7_sdk_authentication import fresh_info
        private = self.root / 'var/lib/http-ztp-container/service-account'
        private.mkdir(parents=True, mode=0o700); private.chmod(0o700)
        credential = private / 'cre.json'
        credential.write_text(json.dumps(fresh_info()), encoding='utf-8'); credential.chmod(0o600)
        original = credential.read_bytes()
        for status in (200, 401, 503):
            fixture_token = 'synthetic-token'
            payload = json.dumps({'access_token':fixture_token,'expires_in':3600},
                                 separators=(',',':')).encode('ascii')
            reply = ('HTTP/1.1 %d Synthetic\r\nContent-Length: %d\r\nConnection: close\r\n\r\n' % (status,len(payload))).encode()+payload
            # Existing server supplies native TLS; extract owned address from
            # its exact DNS fixture, never open a real endpoint.
            with self.subTest(status=status), self.server(reply) as (records, errors):
                port = socket_address_port()
                with ExitStack() as stack:
                    ownership, token = self.owner(stack)
                    observed, children = self.intercept(stack, self.child_fixture(port), token=token, ownership=ownership)
                    unit = module.OwnedTokenRefreshUnit(token, binding())
                    if status == 200:
                        with self.assertWarnsRegex(FutureWarning, 'Python version 3.9 past its end of life') if sys.version_info[:2] == (3,9) else ExitStack():
                            completion = unit.refresh_once()
                        self.assertEqual('synthetic-token', completion.token.value)
                        self.assertNotIn('synthetic-token', repr(completion))
                        self.assertIs(True, completion.termination_confirmed)
                    else:
                        with self.assertRaises(module.TokenLauncherHold) as caught: unit.refresh_once()
                        self.assertIsNone(caught.exception.__context__)
                    with self.assertRaises(module.TokenLauncherHold): unit.refresh_once()
                    self.assertEqual(1, len(observed)); self.assertIsNotNone(children[0].poll())
            self.assertEqual([], errors); self.assertEqual(1,len(records))
            self.assertEqual(b'POST /token HTTP/1.1\r\n', records[0][0])
            self.assertEqual(original, credential.read_bytes())


def socket_address_port():
    import socket
    return socket.getaddrinfo('oauth2.googleapis.com',443)[0][4][1]


if __name__ == '__main__': unittest.main()
