"""Fixed read-only entry with actual locks and owned loopback TLS, no online use."""
from contextlib import ExitStack
import fcntl
import hashlib
import importlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_req7_native_tls_wire as native_fixture
from test_req7_spreadsheet_owner import scoped_fixture
from test_issue_tracker_online_target import TARGET, document

ROOT = Path(__file__).resolve().parents[1]
NAME = 'monitor.issue_tracker_history_read_launcher'


def load():
    if not (ROOT/'monitor/issue_tracker_history_read_launcher.py').is_file():
        raise AssertionError('fixed owned History read launcher missing')
    return importlib.import_module(NAME)


class Req7HistoryReadLauncherDirectTests(unittest.TestCase):
    def test_unheld_project_or_sheet_refuses_before_launch(self):
        module = load()
        from monitor.issue_tracker_online_target import OnlineTargetBinding
        from monitor.issue_tracker_sdk_authentication import AuthenticatedToken
        binding = OnlineTargetBinding(TARGET, 'a'*64, 'b'*64)
        with mock.patch.object(module.subprocess, 'Popen') as launch:
            for writer, owner in ((None,None),(object(),object()),({'owner':True},{'owner':True})):
                with self.subTest(writer=type(writer).__name__), self.assertRaises(module.HistoryReadLauncherHold) as caught:
                    module.OwnedHistoryTailReadUnit(writer, owner, binding, AuthenticatedToken('synthetic-token',time.time()+3600))
                self.assertIsNone(caught.exception.__context__)
            launch.assert_not_called()

    def test_private_completion_correlates_nonce_path_digest_body_and_exact_framing(self):
        module = load(); nonce = 'a'*64; path_digest = 'b'*64; body = b'{"owned":"history"}'
        value = {'schema_version':1,'nonce':nonce,'request_path_sha256':path_digest,
                 'status':200,'body_sha256':hashlib.sha256(body).hexdigest(),'body_bytes':len(body)}
        raw = (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()+body
        result = module._decode_completion(raw,nonce,path_digest)
        self.assertEqual(body,result.data); self.assertEqual(200,result.status); self.assertTrue(result.complete)
        self.assertNotIn('history',repr(result)); self.assertFalse(hasattr(result,'permit'))
        variants = [b'',b'x'*(2*1024*1024+1),raw+body,raw[:-1],raw.replace(body,b'{"owned":"foreign"}')]
        for key,bad in (('schema_version',True),('nonce','c'*64),('request_path_sha256','d'*64),
                        ('body_bytes',True),('status',201),('body_sha256','e'*64)):
            wrong=dict(value); wrong[key]=bad
            variants.append((json.dumps(wrong,sort_keys=True,separators=(',',':'))+'\n').encode()+body)
        variants.append(raw.replace(b'"status":200',b'"status":200,"status":200'))
        for raw in variants:
            with self.subTest(size=len(raw)), self.assertRaises(module.HistoryReadLauncherHold) as caught:
                module._decode_completion(raw,nonce,path_digest)
            self.assertIsNone(caught.exception.__context__)

    def test_fixed_child_refuses_bad_nonce_or_nonroot_before_reading_private_stdin(self):
        module=load()
        with mock.patch.object(module.os,'read') as reading:
            for bad in ('invalid',None,True,'a'*63): self.assertEqual(1,module._history_child(bad))
            with mock.patch.object(module.os,'geteuid',return_value=501): self.assertEqual(1,module._history_child('a'*64))
            reading.assert_not_called()

    def test_fixed_child_invalid_private_input_never_reaches_native_send(self):
        module=load(); nonce='a'*64
        image={'schema_version':1,'nonce':nonce,'spreadsheet_id':TARGET,'policy_sha256':'b'*64,
               'allowlist_sha256':'c'*64,'token':'synthetic-token','expires_at':time.time()+3600}
        raw=(json.dumps(image,sort_keys=True,separators=(',',':'))+'\n').encode()
        variants=[b'',b'{}\n',raw+raw,b'x'*32769,raw.replace(b'"schema_version":1',b'"schema_version":true')]
        for key,bad in (('nonce','d'*64),('token','private\r\nheader'),('expires_at',True),
                        ('expires_at',0),('spreadsheet_id','../foreign'),('policy_sha256',False)):
            wrong=dict(image); wrong[key]=bad
            variants.append((json.dumps(wrong,sort_keys=True,separators=(',',':'))+'\n').encode())
        from monitor import issue_tracker_tls_inputs as tls
        for raw in variants:
            chunks=[raw[index:index+4096] for index in range(0,len(raw),4096)]+[b'']
            with self.subTest(size=len(raw)),mock.patch.object(module.os,'geteuid',return_value=0), \
                    mock.patch.object(module.os,'read',side_effect=chunks),mock.patch.object(tls.NativeHistoryTailReadUnit,'send_once') as send:
                self.assertEqual(1,module._history_child(nonce)); send.assert_not_called()


class Req7HistoryReadLauncherWorkflowTests(unittest.TestCase):
    setUp = native_fixture.Req7NativeTlsWireTests.setUp
    certificates = native_fixture.Req7NativeTlsWireTests.certificates
    server = native_fixture.Req7NativeTlsWireTests.server

    def owners(self,stack):
        from monitor import issue_tracker_spreadsheet_owner as ownership, issue_tracker_online_target as target
        from monitor import issue_tracker_credential_shape as private, issue_tracker_local_commit as local
        self.root=self.root.resolve()
        project=self.root/'project'; project.mkdir(); publication=project/'publication'; publication.mkdir()
        local.create_local_commit_store(project,publication)
        config=project/'01-global.yaml'; config.write_text(json.dumps(document(cycles=3))); config.chmod(0o644)
        credential_dir=self.root/'var/lib/http-ztp-container/service-account'; credential_dir.mkdir(parents=True,mode=0o700)
        listing=credential_dir/'issue-tracker-spreadsheet-whitelist.json'; listing.write_text(json.dumps([TARGET])); listing.chmod(0o600)
        locks=self.root/'var/lib/http-ztp-container/issue-tracker'; locks.mkdir(mode=0o700)
        binding=target.bind_online_target(document(cycles=3),target.freeze_target_allowlist(listing.read_bytes()))
        for module in (ownership,target,private): stack.enter_context(scoped_fixture(self.root,module))
        writer=stack.enter_context(local.writer_owner(project,publication))
        owner=stack.enter_context(ownership.spreadsheet_owner(binding))
        from monitor.issue_tracker_sdk_authentication import AuthenticatedToken
        return local,ownership,writer,owner,binding,AuthenticatedToken('owned-private-token',time.time()+3600),config

    def intercept(self,stack,program,writer,owner,binding):
        module=load(); native=subprocess.Popen; calls=[]; children=[]
        from monitor import issue_tracker_local_commit as local, issue_tracker_spreadsheet_owner as ownership
        def launch(argv,**kwargs):
            self.assertEqual([str(Path(sys.executable).resolve()),'-I','-B','-c'],argv[:4])
            self.assertEqual(module._CHILD_PROGRAM,argv[4]); self.assertEqual(str(ROOT),argv[5]); self.assertEqual(7,len(argv))
            self.assertRegex(argv[6],r'^[0-9a-f]{64}$'); self.assertNotIn('owned-private-token',repr(argv))
            self.assertEqual({'LC_ALL':'C'},kwargs['env']); self.assertIsNone(kwargs.get('shell'))
            self.assertIs(kwargs['stdin'],subprocess.PIPE); self.assertIs(kwargs['stdout'],subprocess.PIPE)
            self.assertIs(kwargs['stderr'],subprocess.PIPE); self.assertIs(kwargs['start_new_session'],True)
            self.assertIs(kwargs['close_fds'],True); self.assertEqual(str(ROOT),kwargs['cwd'])
            self.assertEqual((local._owner(writer).lock_fd,ownership.owner_lock_fd(owner,binding)),kwargs['pass_fds'])
            calls.append(tuple(argv)); changed=list(argv); changed[4]=program
            child=native(changed,**kwargs); children.append(child); return child
        stack.enter_context(mock.patch.object(module,'subprocess',SimpleNamespace(Popen=launch,PIPE=subprocess.PIPE)))
        def cleanup():
            for child in children:
                if child.poll() is None:
                    self.assertEqual(child.pid,os.getpgid(child.pid)); self.assertEqual(child.pid,os.getsid(child.pid))
                    os.killpg(child.pid,signal.SIGKILL)
                child.wait(timeout=3)
                for stream in (child.stdin,child.stdout,child.stderr): stream.close()
        self.addCleanup(cleanup)
        return calls,children

    def child_fixture(self,port):
        # Only synthetic root/CA and owned DNS. Production child/parser/planner,
        # native HTTPS and parent supervision remain unmodified.
        return '''import sys,os,socket
sys.path[:0]=[sys.argv[1],sys.argv[1]+"/tools"]
from types import SimpleNamespace
from unittest import mock
from contextlib import ExitStack
from monitor import issue_tracker_history_read_launcher as launcher, issue_tracker_tls_inputs as tls
def metadata(value):
 fields=("st_dev","st_ino","st_mode","st_uid","st_gid","st_nlink","st_size","st_mtime_ns","st_ctime_ns")
 result=SimpleNamespace(**{name:getattr(value,name) for name in fields}); result.st_uid=0; return result
def facade():
 value=SimpleNamespace(**{name:getattr(os,name) for name in dir(os)}); value.geteuid=lambda:0
 value.open=lambda name,flags,*a,**k:os.open(%r if name=="/" else name,flags,*a,**k)
 value.fstat=lambda fd:metadata(os.fstat(fd)); value.stat=lambda *a,**k:metadata(os.stat(*a,**k)); return value
def resolve(host,port,*a,**k):
 if (host,port)!=("sheets.googleapis.com",443): raise AssertionError("foreign DNS forbidden")
 return [(socket.AF_INET,socket.SOCK_STREAM,6,"",("127.0.0.1",%d))]
with ExitStack() as stack:
 stack.enter_context(mock.patch.object(launcher,"os",facade())); stack.enter_context(mock.patch.object(tls,"os",facade()))
 stack.enter_context(mock.patch("socket.getaddrinfo",side_effect=resolve))
 result=launcher._history_child(sys.argv[2])
raise SystemExit(result)
''' % (str(self.root),port)

    def test_fixed_private_read_uses_native_tls_once_and_both_locks_remain_held(self):
        module=load(); body=b'{"spreadsheetId":"synthetic","sheets":[]}'
        reply=b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body
        with self.server(reply,hostname='sheets.googleapis.com',destination='sheets.googleapis.com') as (records,errors), ExitStack() as stack:
            port=socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
            local,ownership,writer,owner,binding,token,config=self.owners(stack)
            calls,children=self.intercept(stack,self.child_fixture(port),writer,owner,binding)
            unit=module.OwnedHistoryTailReadUnit(writer,owner,binding,token); result=unit.read_once()
            self.assertEqual(body,result.data); self.assertTrue(result.complete); self.assertEqual(1,len(calls))
            self.assertEqual(0,children[0].returncode); self.assertTrue(children[0].stdin.closed)
            project_other=os.open('LOCK',os.O_RDWR,dir_fd=local._owner(writer).root_fd)
            sheet_other=os.open(self.root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(TARGET.encode()).hexdigest()+'.lock'),os.O_RDWR)
            for other in (project_other,sheet_other):
                try:
                    with self.assertRaises(BlockingIOError): fcntl.flock(other,fcntl.LOCK_EX|fcntl.LOCK_NB)
                finally: os.close(other)
            with self.assertRaises(module.HistoryReadLauncherHold): unit.read_once()
        self.assertEqual([],errors); self.assertEqual(1,len(records)); self.assertTrue(records[0][0].startswith(b'GET /v4/spreadsheets/'+TARGET.encode()+b'?'))
        self.assertIn(b'Authorization: Bearer owned-private-token\r\n',records[0][1]); self.assertEqual(b'',records[0][2])
        self.assertFalse(hasattr(result,'complete_unit')); self.assertFalse(hasattr(result,'permit'))

    def test_revoked_policy_before_launch_consumes_unit_without_network(self):
        module=load()
        with ExitStack() as stack:
            _local,_ownership,writer,owner,binding,token,config=self.owners(stack)
            unit=module.OwnedHistoryTailReadUnit(writer,owner,binding,token)
            config.write_text(json.dumps(document(status='disabled')))
            with mock.patch.object(module.subprocess,'Popen') as launch:
                with self.assertRaises(module.HistoryReadLauncherHold) as caught: unit.read_once()
                with self.assertRaises(module.HistoryReadLauncherHold): unit.read_once()
                launch.assert_not_called(); self.assertIsNone(caught.exception.__context__)

    def test_prelaunch_budget_exhaustion_or_expired_token_never_launches(self):
        module=load()
        with ExitStack() as stack:
            _local,_ownership,writer,owner,binding,token,_config=self.owners(stack)
            with mock.patch.object(module.subprocess,'Popen') as launch:
                unit=module.OwnedHistoryTailReadUnit(writer,owner,binding,token)
                with mock.patch.object(module,'_monotonic',return_value=time.monotonic()+31):
                    with self.assertRaises(module.HistoryReadLauncherHold): unit.read_once()
                with self.assertRaises(module.HistoryReadLauncherHold): unit.read_once()
                unit=module.OwnedHistoryTailReadUnit(writer,owner,binding,token)
                with mock.patch('monitor.issue_tracker_sheets_read_plan.time.time',return_value=token.expires_at+1):
                    with self.assertRaises(module.HistoryReadLauncherHold): unit.read_once()
                launch.assert_not_called()

    def test_complete_native_reply_cannot_survive_policy_change_during_request(self):
        module=load(); body=b'{"owned":"history"}'; config=None
        def respond(transport):
            config.write_text(json.dumps(document(status='disabled')))
            transport.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body)
        with self.server(respond,hostname='sheets.googleapis.com',destination='sheets.googleapis.com') as (records,errors), ExitStack() as stack:
            port=socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
            _local,ownership,writer,owner,binding,token,config=self.owners(stack)
            calls,children=self.intercept(stack,self.child_fixture(port),writer,owner,binding)
            unit=module.OwnedHistoryTailReadUnit(writer,owner,binding,token)
            with self.assertRaises(module.HistoryReadLauncherHold) as caught: unit.read_once()
            self.assertTrue(caught.exception.termination_confirmed); self.assertIsNone(caught.exception.__context__)
            self.assertEqual(0,children[0].returncode); self.assertEqual(1,len(calls))
            with self.assertRaises(module.HistoryReadLauncherHold): unit.read_once()
            ownership.owner_lock_fd(owner,binding)
            self.assertEqual('disabled',json.loads(config.read_text())['common']['mgmt']['issue-tracker']['status'])
        self.assertEqual([],errors); self.assertEqual(1,len(records))

    def test_native_401_is_never_refreshed_replayed_or_returned_complete(self):
        module=load()
        reply=b'HTTP/1.1 401 Denied\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}'
        with self.server(reply,hostname='sheets.googleapis.com',destination='sheets.googleapis.com') as (records,errors), ExitStack() as stack:
            port=socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
            _local,ownership,writer,owner,binding,token,_config=self.owners(stack)
            calls,children=self.intercept(stack,self.child_fixture(port),writer,owner,binding)
            unit=module.OwnedHistoryTailReadUnit(writer,owner,binding,token)
            with self.assertRaises(module.HistoryReadLauncherHold) as caught: unit.read_once()
            self.assertTrue(caught.exception.termination_confirmed); self.assertIsNone(caught.exception.__context__)
            with self.assertRaises(module.HistoryReadLauncherHold): unit.read_once()
            self.assertEqual(1,len(calls)); self.assertEqual(1,children[0].returncode); ownership.owner_lock_fd(owner,binding)
        self.assertEqual([],errors); self.assertEqual(1,len(records))

    def test_uncorrelated_private_child_output_is_hold_and_consumed_without_unlock(self):
        module=load()
        with ExitStack() as stack:
            _local,ownership,writer,owner,binding,token,_config=self.owners(stack)
            program='import sys,os; sys.stdin.buffer.read(); os.write(1,b"private-secret-invalid-output")'
            calls,children=self.intercept(stack,program,writer,owner,binding)
            unit=module.OwnedHistoryTailReadUnit(writer,owner,binding,token)
            with self.assertRaises(module.HistoryReadLauncherHold) as caught: unit.read_once()
            self.assertTrue(caught.exception.termination_confirmed); self.assertIsNone(caught.exception.__context__)
            self.assertNotIn('secret',str(caught.exception)); self.assertEqual(0,children[0].returncode)
            with self.assertRaises(module.HistoryReadLauncherHold): unit.read_once()
            self.assertEqual(1,len(calls)); ownership.owner_lock_fd(owner,binding)

    def test_unconfirmed_read_child_termination_retains_both_actual_locks_until_owned_cleanup(self):
        module=load(); native_kill=os.killpg
        with ExitStack() as stack:
            local,ownership,writer,owner,binding,token,_config=self.owners(stack)
            program='import sys,time; sys.stdin.buffer.read(); time.sleep(100)'
            calls,children=self.intercept(stack,program,writer,owner,binding)
            unit=module.OwnedHistoryTailReadUnit(writer,owner,binding,token)
            def denied(group,operation):
                if operation == 0: return native_kill(group,operation)
                raise PermissionError('owned child termination denied')
            # Keep the original 30-second deadline and actual cleanup. Only the
            # already-spent startup portion is injected at the clock boundary.
            clock=SimpleNamespace(monotonic=lambda:time.monotonic()-29.6)
            with mock.patch.object(module,'time',clock), mock.patch('os.killpg',side_effect=denied):
                with self.assertRaises(module.HistoryReadLauncherHold) as caught: unit.read_once()
            self.assertFalse(caught.exception.termination_confirmed); self.assertIsNone(caught.exception.__context__)
            self.assertEqual(1,len(calls)); child=children[0]; self.assertIsNone(child.poll())
            project_other=os.open('LOCK',os.O_RDWR,dir_fd=local._owner(writer).root_fd)
            sheet_other=os.open(self.root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(TARGET.encode()).hexdigest()+'.lock'),os.O_RDWR)
            try:
                for other in (project_other,sheet_other):
                    with self.assertRaises(BlockingIOError): fcntl.flock(other,fcntl.LOCK_EX|fcntl.LOCK_NB)
                self.assertEqual(child.pid,os.getpgid(child.pid)); self.assertEqual(child.pid,os.getsid(child.pid))
                native_kill(child.pid,signal.SIGKILL); child.wait(timeout=3)
                with self.assertRaises(module.HistoryReadLauncherHold): unit.read_once()
                local._owner(writer); ownership.owner_lock_fd(owner,binding)
            finally: os.close(project_other); os.close(sheet_other)

    def test_manifest_binds_actual_read_launch_target_tls_and_locks(self):
        load(); manifest=json.loads((ROOT/'test_cases/script_test_manifest.json').read_text())
        path='monitor/issue_tracker_history_read_launcher.py'; name='test_cases.test_req7_history_read_launcher'
        self.assertEqual(path,manifest['scripts'].get(path))
        self.assertTrue(any(path in rule['paths'] and name in rule['tests'] for rule in manifest['test_rules']))
        members={path,'monitor/issue_tracker_online_target.py','monitor/issue_tracker_local_commit.py',
                 'monitor/issue_tracker_spreadsheet_owner.py','monitor/issue_tracker_attempt_supervision.py',
                 'monitor/issue_tracker_sheets_read_plan.py','monitor/issue_tracker_tls_inputs.py'}
        self.assertTrue(any(members <= set(rule['members']) and name in rule['tests'] for rule in manifest['workflows']))


if __name__=='__main__': unittest.main()
