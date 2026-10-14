"""Fixed uninstalled original-count launcher, owned native TLS only; not GO."""
from contextlib import ExitStack
from dataclasses import replace
import hashlib
import importlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load():
    path = ROOT/'monitor/issue_tracker_mutation_launcher.py'
    if not path.is_file(): raise AssertionError('fixed original-count mutation launcher missing')
    return importlib.import_module('monitor.issue_tracker_mutation_launcher')


class Req7MutationLauncherDirectTests(unittest.TestCase):
    def test_forged_or_absent_claim_never_launches_any_program(self):
        module = load()
        with mock.patch.object(module.subprocess,'Popen') as launch:
            with self.assertRaises(module.MutationLauncherHold) as caught:
                module._send_counted_original_once(None,None,None,None,None,object())
            launch.assert_not_called(); self.assertIsNone(caught.exception.__context__)

    def test_child_bad_nonce_descriptors_or_nonroot_never_reads_private_input(self):
        module = load()
        with mock.patch.object(module.os,'read') as reading:
            for nonce,a,w in ((None,3,4),('a'*64,True,4),('a'*64,0,4),('a'*64,4,4)):
                self.assertEqual(1,module._mutation_child(nonce,a,w))
            with mock.patch.object(module.os,'geteuid',return_value=501):
                self.assertEqual(1,module._mutation_child('a'*64,3,4))
            reading.assert_not_called()

    def test_complete_observation_requires_exact_original_count_nonce_and_wire_correlation(self):
        module = load(); nonce='a'*64; digest='b'*64
        value = {'schema_version':1,'nonce':nonce,'attempt_count':1,'wire_sha256':digest,
                 'status':401,'response_sha256':'c'*64,'outcome':'UNKNOWN'}
        raw = (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
        result = module._decode_completion(raw,nonce,1,digest)
        self.assertEqual((1,401,'UNKNOWN'),(result.attempt_count,result.status,result.outcome))
        self.assertFalse(hasattr(result,'applied')); self.assertFalse(hasattr(result,'permit'))
        variants=[b'',raw+raw,raw+b' ',raw.replace(b'"status":401',b'"status":401,"status":401')]
        for key,bad in (('nonce','d'*64),('attempt_count',2),('attempt_count',True),('wire_sha256','e'*64),
                        ('status',True),('status',600),('outcome','APPLIED'),('response_sha256','foreign')):
            wrong=dict(value); wrong[key]=bad
            variants.append((json.dumps(wrong,sort_keys=True,separators=(',',':'))+'\n').encode())
        for candidate in variants:
            with self.assertRaises(module.MutationLauncherHold) as caught:
                module._decode_completion(candidate,nonce,1,digest)
            self.assertIsNone(caught.exception.__context__)

    def test_bad_private_controls_cannot_reach_original_native_constructor(self):
        import time
        from monitor import issue_tracker_tls_inputs as tls
        module=load(); nonce='a'*64
        value={'schema_version':1,'nonce':nonce,'spreadsheet_id':'synthetic_spreadsheet_id_0001',
               'policy_sha256':'b'*64,'allowlist_sha256':'c'*64,'token':'owned-synthetic-token',
               'expires_at':time.time()+3600,'unit_id':'d'*64,'wire_sha256':'e'*64,
               'action_digest':'f'*64,'attempt_count':1}
        raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
        variants=[b'',b'{}\n',raw+raw,b'x'*32769]
        for key,bad in (('nonce','b'*64),('attempt_count',True),('attempt_count',7),('token','x\r\ninjected'),
                        ('expires_at',True),('expires_at',0),('unit_id',False),('spreadsheet_id','../foreign'),
                        ('url','https://foreign.invalid'),('budget_seconds',120),('body','arbitrary')):
            wrong=dict(value); wrong[key]=bad
            variants.append((json.dumps(wrong,sort_keys=True,separators=(',',':'))+'\n').encode())
        for candidate in variants:
            chunks=[candidate[i:i+4096] for i in range(0,len(candidate),4096)]+[b'']
            with mock.patch.object(module.os,'geteuid',return_value=0),mock.patch.object(module.os,'read',side_effect=chunks), \
                    mock.patch.object(tls,'NativeOriginalSheetsMutationUnit') as native:
                self.assertEqual(1,module._mutation_child(nonce,3,4)); native.assert_not_called()

    def test_manifest_direct_workflow_and_real_env_mapping_are_closed(self):
        manifest=json.loads((ROOT/'test_cases/script_test_manifest.json').read_text())
        source='monitor/issue_tracker_mutation_launcher.py'; test='test_cases.test_req7_mutation_launcher'
        self.assertEqual(source,manifest['scripts'].get(source))
        self.assertTrue(any(source in rule['paths'] and test in rule['tests'] for rule in manifest['test_rules']))
        self.assertTrue(any({source,'monitor/issue_tracker_global_attempt_journal.py','monitor/issue_tracker_tls_inputs.py',
                             'monitor/issue_tracker_attempt_supervision.py'} <= set(rule['members']) and test in rule['tests']
                            for rule in manifest['workflows']))
        card=(ROOT/'test_cases/REAL_ENVIRONMENT.md').read_text()
        start=card.index('## TC-REAL-REQ7-COUNTED-MUTATION-LAUNCHER-001'); end=card.find('\n## ',start+1)
        card=card[start:] if end<0 else card[start:end]
        for text in ('NOT RUN / REAL_ENV REQUIRED','前置条件','证据','清理','60','UNKNOWN','shared cadence','Stage O'):
            self.assertIn(text,card)


class Req7MutationLauncherWorkflowTests(unittest.TestCase):
    from test_cases.test_req7_native_tls_wire import Req7NativeTlsWireTests as native
    setUp = native.setUp
    certificates = native.certificates
    server = native.server

    def test_private_preparation_interruption_spends_original_before_fresh_launch_fence(self):
        class PreparationInterrupted(BaseException): pass
        primary = PreparationInterrupted(); facts = []; module = load()
        with ExitStack() as stack:
            _local, _ownership, journal, writer, owner, target, token, unit, image = self.owners(stack)
            original_parse = module._parse_private; original_inspect = journal._inspect
            with mock.patch.object(journal, '_inspect', wraps=original_inspect) as inspected:
                def preparing(raw, nonce):
                    original_parse(raw, nonce)
                    facts.append((journal._LIVE_WIRE_CLAIMS[image][-1], inspected.call_count))
                    raise primary
                with mock.patch.object(module, '_parse_private', side_effect=preparing), \
                        mock.patch.object(module.subprocess, 'Popen') as launch:
                    with self.assertRaises(PreparationInterrupted) as caught:
                        module._send_counted_original_once(writer, owner, target, token, unit, image)
                    self.assertIs(primary, caught.exception)
                    with self.assertRaises(module.MutationLauncherHold):
                        module._send_counted_original_once(writer, owner, target, token, unit, image)
                    launch.assert_not_called()
            current = journal.inspect_global_unit(owner, target, unit)
            outcome = (current.attempt_count, current.outcome)
        self.assertEqual([(True, 0)], facts,
            'original use is spent before preparation, but complete fresh verification belongs to final launch fence')
        self.assertEqual((1, 'UNKNOWN'), outcome)

    def test_private_preparation_wire_drift_is_refused_by_actual_final_fence_without_launch(self):
        module = load(); changed = []; refusal = None
        with ExitStack() as stack:
            _local, _ownership, journal, writer, owner, target, token, unit, _image = self.owners(stack, claim=False)
            with self.assertRaises(journal.GlobalAttemptHold):
                with journal._hold_counted_original_wire(writer, owner, target, unit) as image:
                    before = journal.inspect_global_unit(owner, target, unit)
                    outcome = (before.attempt_count, before.outcome)
                    actual_parse = module._parse_private
                    def preparing(raw, nonce):
                        result = actual_parse(raw, nonce)
                        os.fchmod(image.fd, 0o400); changed.append(True)
                        return result
                    with mock.patch.object(module, '_parse_private', side_effect=preparing), \
                            mock.patch.object(module.subprocess, 'Popen') as launch:
                        try:
                            module._send_counted_original_once(writer, owner, target, token, unit, image)
                        except BaseException as error:
                            refusal = error
                        launch_count = launch.call_count
                        spent = journal._LIVE_WIRE_CLAIMS[image][-1]
                        retained_count = image.attempt_count
                        mode = os.fstat(image.fd).st_mode & 0o777
                        with self.assertRaises(journal.GlobalAttemptHold):
                            journal.inspect_global_unit(owner, target, unit)
        self.assertEqual([True], changed)
        self.assertIs(type(refusal), module.MutationLauncherHold,
            'the sender itself must refuse; original-scope cleanup HOLD is not a substitute')
        self.assertEqual(0, launch_count)
        self.assertIs(True, spent)
        self.assertEqual(0o400, mode)
        self.assertEqual((1, 'UNKNOWN'), outcome)
        self.assertEqual(1, retained_count)

    def owners(self,stack,*,claim=True):
        from test_cases.test_req7_history_read_launcher import Req7HistoryReadLauncherWorkflowTests as reads
        from test_cases.test_req7_global_attempt_journal import load as load_global
        from test_cases.test_req7_send_unit import load as load_unit, inputs, TARGET
        local,ownership,writer,owner,target,token,_config = reads.owners(self,stack,target_id=TARGET)
        unit = load_unit().freeze_send_unit(**inputs()); journal=load_global()
        journal.prepare_global_unit(owner,target,unit); journal.record_global_attempt_intent(owner,target,unit)
        image = stack.enter_context(journal._hold_counted_original_wire(writer,owner,target,unit)) if claim else None
        return local,ownership,journal,writer,owner,target,token,unit,image

    def child_fixture(self,port):
        # Only test-boundary root/CA/UID and local DNS are synthetic. Actual
        # fixed child parsing, original FD reads, TLS and supervision are real.
        return '''import sys,os,socket
sys.path[:0]=[sys.argv[1],sys.argv[1]+"/tools"]
from types import SimpleNamespace
from unittest import mock
from contextlib import ExitStack
from monitor import issue_tracker_mutation_launcher as launcher, issue_tracker_tls_inputs as tls
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
 result=launcher._mutation_child(sys.argv[2],int(sys.argv[3]),int(sys.argv[4]))
if "yaml" in sys.modules or "openpyxl" in sys.modules: raise AssertionError("parent-only dependency in isolated child")
raise SystemExit(result)
'''%(str(self.root),port)

    def intercept(self,stack,local,ownership,writer,owner,target,image,port):
        module=load(); native_popen=subprocess.Popen; calls=[]; children=[]
        def launch(argv,**options):
            self.assertEqual([str(Path(sys.executable).resolve()),'-I','-B','-c',module._CHILD_PROGRAM,str(ROOT)],argv[:6])
            self.assertEqual(9,len(argv)); self.assertRegex(argv[6],r'^[0-9a-f]{64}$')
            self.assertEqual([str(image.action_fd),str(image.fd)],argv[7:]); self.assertNotIn('owned-private-token',repr(argv))
            self.assertEqual({'LC_ALL':'C'},options['env']); self.assertEqual(str(ROOT),options['cwd'])
            self.assertEqual((local._owner(writer).lock_fd,ownership.owner_lock_fd(owner,target),image.action_fd,image.fd),options['pass_fds'])
            self.assertTrue(options['start_new_session']); self.assertTrue(options['close_fds'])
            self.assertIs(options['stdin'],subprocess.PIPE); self.assertIsNone(options.get('shell'))
            calls.append(argv); changed=list(argv); changed[4]=self.child_fixture(port)
            child=native_popen(changed,**options); children.append(child)
            from test_cases.test_req7_native_supervised_workflow import cleanup_owned_fixture_child
            self.addCleanup(cleanup_owned_fixture_child,child)
            return child
        stack.enter_context(mock.patch.object(module,'subprocess',SimpleNamespace(Popen=launch,PIPE=subprocess.PIPE)))
        return calls,children

    def test_fixed_actual_native_launch_accepts_only_live_issued_claim_once(self):
        module=load()
        response=b'HTTP/1.1 401 Denied\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}'
        with self.server(response,hostname='sheets.googleapis.com',destination='sheets.googleapis.com') as (records,errors), ExitStack() as stack:
            port=socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
            local,ownership,journal,writer,owner,target,token,unit,image=self.owners(stack)
            calls,children=self.intercept(stack,local,ownership,writer,owner,target,image,port)
            forged=replace(image)
            with self.assertRaises(module.MutationLauncherHold):
                module._send_counted_original_once(writer,owner,target,token,unit,forged)
            self.assertEqual([],calls)
            result=module._send_counted_original_once(writer,owner,target,token,unit,image)
            self.assertEqual((1,401,'UNKNOWN'),(result.attempt_count,result.status,result.outcome))
            self.assertTrue(result.termination_confirmed); self.assertEqual(0,children[0].returncode)
            with self.assertRaises(module.MutationLauncherHold):
                module._send_counted_original_once(writer,owner,target,token,unit,image)
            self.assertEqual(1,len(calls)); self.assertEqual(1,journal.inspect_global_unit(owner,target,unit).attempt_count)
        self.assertEqual([],errors); self.assertEqual(1,len(records)); self.assertEqual(unit.wire_bytes,records[0][2])

    def test_same_byte_count_witness_replacement_cannot_start_native_child_or_send(self):
        module = load()
        response = b'HTTP/1.1 401 Denied\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}'
        with self.server(response,hostname='sheets.googleapis.com',destination='sheets.googleapis.com') as (records,errors), ExitStack() as stack:
            port = socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
            local,ownership,journal,writer,owner,target,token,unit,_image = self.owners(stack,claim=False)
            path = self.root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(target.spreadsheet_id.encode()).hexdigest()+'.journal')/'ATTEMPT-1'
            raw, inode = path.read_bytes(), path.stat().st_ino
            rejected = []
            with self.assertRaises(journal.GlobalAttemptHold):
                with journal._hold_counted_original_wire(writer,owner,target,unit) as image:
                    calls,children = self.intercept(stack,local,ownership,writer,owner,target,image,port)
                    path.rename(path.parent.parent/'owned-retained-original-attempt')
                    path.write_bytes(raw); path.chmod(0o600)
                    self.assertNotEqual(inode, path.stat().st_ino); self.assertEqual(raw,path.read_bytes())
                    with self.assertRaises(module.MutationLauncherHold):
                        module._send_counted_original_once(writer,owner,target,token,unit,image)
                    self.assertEqual([],calls); self.assertEqual([],children)
                    rejected.append(True)
            self.assertEqual([True],rejected,('actual fixed launcher must stop before Popen',len(calls),len(children),len(records)))
            retained = journal.inspect_global_unit(owner,target,unit)
            self.assertEqual((1,'UNKNOWN'),(retained.attempt_count,retained.outcome))
            self.assertFalse((path.parent/'ATTEMPT-2').exists())
        self.assertEqual([],errors); self.assertEqual([],records)

    def test_count_read_to_pin_replacement_never_reaches_actual_native_launcher(self):
        module=load()
        response=b'HTTP/1.1 401 Denied\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}'
        with self.server(response,hostname='sheets.googleapis.com',destination='sheets.googleapis.com') as (records,errors), ExitStack() as stack:
            port=socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
            local,ownership,journal,writer,owner,target,token,unit,_image=self.owners(stack,claim=False)
            path=self.root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(target.spreadsheet_id.encode()).hexdigest()+'.journal')/'ATTEMPT-1'
            raw=path.read_bytes(); original=path.stat(); real_inspect=journal._inspect
            injected=[]; issued=[]; calls=[]; children=[]
            def after_count(*args):
                result=real_inspect(*args)
                if not injected:
                    path.rename(path.parent.parent/'owned-read-to-pin-attempt')
                    path.write_bytes(raw); path.chmod(0o600)
                    injected.append(result[0])
                return result
            with mock.patch.object(journal,'_inspect',side_effect=after_count), self.assertRaises(journal.GlobalAttemptHold):
                with journal._hold_counted_original_wire(writer,owner,target,unit) as image:
                    issued.append(image)
                    calls,children=self.intercept(stack,local,ownership,writer,owner,target,image,port)
                    with self.assertRaises(module.MutationLauncherHold):
                        module._send_counted_original_once(writer,owner,target,token,unit,image)
            self.assertEqual([1],injected)
            self.assertEqual([],issued,('count-read drift must not issue a live image',len(calls),len(children),len(records)))
            self.assertEqual([],calls); self.assertEqual([],children)
            self.assertNotEqual(original.st_ino,path.stat().st_ino); self.assertEqual(raw,path.read_bytes())
            seen=journal.inspect_global_unit(owner,target,unit)
            self.assertEqual((1,'UNKNOWN'),(seen.attempt_count,seen.outcome))
            self.assertFalse((path.parent/'ATTEMPT-2').exists())
        self.assertEqual([],errors); self.assertEqual([],records)

    def test_last_prelaunch_semantic_read_drift_stops_before_actual_native_popen(self):
        module=load()
        response=b'HTTP/1.1 401 Denied\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}'
        with self.server(response,hostname='sheets.googleapis.com',destination='sheets.googleapis.com') as (records,errors), ExitStack() as stack:
            port=socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
            local,ownership,journal,writer,owner,target,token,unit,_image=self.owners(stack,claim=False)
            path=self.root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(target.spreadsheet_id.encode()).hexdigest()+'.journal')/'ATTEMPT-1'
            raw=path.read_bytes(); original=path.stat(); real_inspect=journal._inspect
            read_counts=[]; injected=[]; rejected=[]; at_prelaunch=[]
            original_fence=journal._require_original_wire_launch
            def at_actual_fence(*args,**kwargs):
                # Locate the real nonconsuming pre-Popen boundary, not a
                # global ordinal that also counts an earlier DATA mark or
                # the post-send verifier. Delegate the complete original.
                before_launch=not kwargs['consume'] and not calls
                at_prelaunch.append(before_launch)
                try:return original_fence(*args,**kwargs)
                finally:at_prelaunch.pop()
            def after_read(*args):
                result=real_inspect(*args); read_counts.append(result[0])
                if at_prelaunch and at_prelaunch[-1] and not injected:
                    path.write_bytes(b'x'*len(raw)); path.write_bytes(raw)
                    os.utime(path,ns=(original.st_atime_ns,original.st_mtime_ns))
                    injected.append(result[0])
                return result
            with self.assertRaises(journal.GlobalAttemptHold):
                with journal._hold_counted_original_wire(writer,owner,target,unit) as image:
                    calls,children=self.intercept(stack,local,ownership,writer,owner,target,image,port)
                    with mock.patch.object(journal,'_require_original_wire_launch',side_effect=at_actual_fence), \
                            mock.patch.object(journal,'_inspect',side_effect=after_read), self.assertRaises(module.MutationLauncherHold) as caught:
                        module._send_counted_original_once(writer,owner,target,token,unit,image)
                    if not caught.exception.termination_confirmed: rejected.append(True)
            self.assertEqual([1],injected)
            self.assertEqual([],calls,('final prelaunch drift must cause zero Popen/child/request',len(calls),len(children),len(records)))
            self.assertEqual([],children); self.assertEqual([True],rejected)
            self.assertEqual(original.st_ino,path.stat().st_ino); self.assertEqual(original.st_mtime_ns,path.stat().st_mtime_ns)
            self.assertNotEqual(original.st_ctime_ns,path.stat().st_ctime_ns); self.assertEqual(raw,path.read_bytes())
            seen=journal.inspect_global_unit(owner,target,unit)
            self.assertEqual((1,'UNKNOWN'),(seen.attempt_count,seen.outcome)); self.assertFalse((path.parent/'ATTEMPT-2').exists())
        self.assertEqual([],errors); self.assertEqual([],records)

    def test_count_witness_drift_after_actual_send_keeps_unknown_and_correlated_child_termination(self):
        module = load(); paths = []; changed = []
        def reply(transport):
            path = paths[0]; raw = path.read_bytes(); inode = path.stat().st_ino
            path.rename(path.parent.parent/'owned-retained-postsend-attempt')
            path.write_bytes(raw); path.chmod(0o600)
            changed.append((inode,path.stat().st_ino,raw))
            transport.sendall(b'HTTP/1.1 401 Denied\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}')
        with self.server(reply,hostname='sheets.googleapis.com',destination='sheets.googleapis.com') as (records,errors), ExitStack() as stack:
            port = socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
            local,ownership,journal,writer,owner,target,token,unit,_image = self.owners(stack,claim=False)
            path = self.root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(target.spreadsheet_id.encode()).hexdigest()+'.journal')/'ATTEMPT-1'
            paths.append(path); rejected = []
            with self.assertRaises(journal.GlobalAttemptHold):
                with journal._hold_counted_original_wire(writer,owner,target,unit) as image:
                    calls,children = self.intercept(stack,local,ownership,writer,owner,target,image,port)
                    with self.assertRaises(module.MutationLauncherHold) as caught:
                        module._send_counted_original_once(writer,owner,target,token,unit,image)
                    self.assertTrue(caught.exception.termination_confirmed)
                    self.assertEqual(1,len(calls)); self.assertEqual(0,children[0].returncode)
                    rejected.append(True)
            self.assertEqual([True],rejected,('post-send original drift must not become a valid completion result',len(calls),len(records),len(changed)))
            self.assertEqual(1,len(changed)); self.assertNotEqual(changed[0][0],changed[0][1])
            self.assertEqual(changed[0][2],path.read_bytes())
            retained = journal.inspect_global_unit(owner,target,unit)
            self.assertEqual((1,'UNKNOWN'),(retained.attempt_count,retained.outcome))
            self.assertFalse((path.parent/'ATTEMPT-2').exists())
        self.assertEqual([],errors); self.assertEqual(1,len(records)); self.assertEqual(unit.wire_bytes,records[0][2])

    def test_dispatch_directory_aba_cannot_start_actual_native_child(self):
        module = load()
        response = b'HTTP/1.1 401 Denied\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}'
        with self.server(response,hostname='sheets.googleapis.com',destination='sheets.googleapis.com') as (records,errors), ExitStack() as stack:
            port = socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
            local,ownership,journal,writer,owner,target,token,unit,_image = self.owners(stack,claim=False)
            root = self.root/'var/lib/http-ztp-container/issue-tracker'
            dispatch = root/(hashlib.sha256(target.spreadsheet_id.encode()).hexdigest()+'.dispatch')
            rejected = []
            with self.assertRaises(journal.GlobalAttemptHold):
                with journal._hold_counted_original_wire(writer,owner,target,unit) as image:
                    calls,children = self.intercept(stack,local,ownership,writer,owner,target,image,port)
                    original = dispatch.stat(); raw = {p.name:p.read_bytes() for p in dispatch.iterdir()}
                    moved = root/'owned-retained-dispatch'
                    dispatch.rename(moved); moved.rename(dispatch)
                    self.assertEqual(original.st_ino,dispatch.stat().st_ino)
                    self.assertNotEqual(original.st_ctime_ns,dispatch.stat().st_ctime_ns)
                    self.assertEqual(raw,{p.name:p.read_bytes() for p in dispatch.iterdir()})
                    with self.assertRaises(module.MutationLauncherHold):
                        module._send_counted_original_once(writer,owner,target,token,unit,image)
                    self.assertEqual([],calls); self.assertEqual([],children); rejected.append(True)
            self.assertEqual([True],rejected,('dispatch ABA must stop before Popen',len(calls),len(records)))
            self.assertEqual(raw,{p.name:p.read_bytes() for p in dispatch.iterdir()})
            self.assertEqual({'HEADER','INITIALIZED','CLAIM-1'},set(raw))
            retained = journal.inspect_global_unit(owner,target,unit)
            self.assertEqual((1,'UNKNOWN'),(retained.attempt_count,retained.outcome))
        self.assertEqual([],errors); self.assertEqual([],records)

    def test_six_durable_counts_reach_exactly_six_native_original_requests_without_hidden_resend(self):
        module=load(); total=[]
        with ExitStack() as outer:
            local,ownership,journal,writer,owner,target,token,unit,_image=self.owners(outer,claim=False)
            for count in range(1,7):
                if count>1: journal.record_global_attempt_intent(owner,target,unit)
                response=b'HTTP/1.1 503 Denied\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}'
                with self.server(response,hostname='sheets.googleapis.com',destination='sheets.googleapis.com') as (records,errors), ExitStack() as stack:
                    image=stack.enter_context(journal._hold_counted_original_wire(writer,owner,target,unit))
                    port=socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
                    calls,_children=self.intercept(stack,local,ownership,writer,owner,target,image,port)
                    result=module._send_counted_original_once(writer,owner,target,token,unit,image)
                    self.assertEqual((count,503,'UNKNOWN'),(result.attempt_count,result.status,result.outcome))
                    with self.assertRaises(module.MutationLauncherHold): module._send_counted_original_once(writer,owner,target,token,unit,image)
                    self.assertEqual(1,len(calls))
                self.assertEqual([],errors); self.assertEqual(1,len(records)); self.assertEqual(unit.wire_bytes,records[0][2]); total.extend(records)
            self.assertEqual(6,len(total))
            with self.assertRaises(journal.GlobalAttemptHold): journal.record_global_attempt_intent(owner,target,unit)
            self.assertEqual((6,'UNKNOWN'),(journal.inspect_global_unit(owner,target,unit).attempt_count,journal.inspect_global_unit(owner,target,unit).outcome))

    def test_fixed_parent_total_deadline_kills_slow_native_child_retaining_unknown_and_dual_owners(self):
        import fcntl
        import threading
        import time
        module=load(); stop=threading.Event(); reached=threading.Event()
        def slow(transport):
            transport.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{')
            reached.set(); stop.wait(75)
        try:
            with self.server(slow,hostname='sheets.googleapis.com',destination='sheets.googleapis.com') as (records,errors), ExitStack() as stack:
                local,ownership,journal,writer,owner,target,token,unit,image=self.owners(stack)
                port=socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
                calls,children=self.intercept(stack,local,ownership,writer,owner,target,image,port)
                started=time.monotonic()
                try:
                    with self.assertRaises(module.MutationLauncherHold) as caught: module._send_counted_original_once(writer,owner,target,token,unit,image)
                finally: stop.set()
                self.assertTrue(reached.is_set(),'native child never reached the actual slow TLS response')
                self.assertTrue(caught.exception.termination_confirmed); self.assertIsNotNone(children[0].poll())
                self.assertGreaterEqual(time.monotonic()-started,59.5); self.assertLess(time.monotonic()-started,63.0)
                for path in (self.root/'project/.tracker/LOCK',self.root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(target.spreadsheet_id.encode()).hexdigest()+'.lock')):
                    fd=os.open(path,os.O_RDWR)
                    try:
                        with self.assertRaises(BlockingIOError): fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    finally: os.close(fd)
                with self.assertRaises(module.MutationLauncherHold): module._send_counted_original_once(writer,owner,target,token,unit,image)
                self.assertEqual(1,len(calls)); self.assertEqual(1,journal.inspect_global_unit(owner,target,unit).attempt_count)
            self.assertEqual([],errors); self.assertEqual(1,len(records)); self.assertEqual(unit.wire_bytes,records[0][2])
        finally: stop.set()

    def test_popen_failure_consumes_live_claim_and_never_launches_it_again(self):
        module=load()
        with ExitStack() as stack:
            _local,_ownership,journal,writer,owner,target,token,unit,image=self.owners(stack)
            with mock.patch.object(module.subprocess,'Popen',side_effect=OSError('owned startup fault')) as launch:
                with self.assertRaises(module.MutationLauncherHold): module._send_counted_original_once(writer,owner,target,token,unit,image)
                with self.assertRaises(module.MutationLauncherHold): module._send_counted_original_once(writer,owner,target,token,unit,image)
                self.assertEqual(1,launch.call_count)
            self.assertEqual(1,journal.inspect_global_unit(owner,target,unit).attempt_count)

    def test_token_expiring_at_final_target_check_never_launches_consumed_claim(self):
        from monitor import issue_tracker_online_target as targets, issue_tracker_sheets_read_plan as plans
        module=load()
        with ExitStack() as stack:
            _local,_ownership,journal,writer,owner,target,token,unit,image=self.owners(stack)
            now=[token.expires_at-1]; checks=[]; inspect=targets.inspect_project_online_target
            def check(*args):
                result=inspect(*args); checks.append(result)
                if len(checks)==2: now[0]=token.expires_at+1
                return result
            with mock.patch.object(plans,'time',SimpleNamespace(time=lambda:now[0])), \
                    mock.patch.object(targets,'inspect_project_online_target',side_effect=check), \
                    mock.patch.object(module.subprocess,'Popen',side_effect=OSError('must not launch expired token')) as launch:
                with self.assertRaises(module.MutationLauncherHold): module._send_counted_original_once(writer,owner,target,token,unit,image)
                launch.assert_not_called()
                with self.assertRaises(module.MutationLauncherHold): module._send_counted_original_once(writer,owner,target,token,unit,image)
                launch.assert_not_called()
            self.assertEqual(1,journal.inspect_global_unit(owner,target,unit).attempt_count)

    def test_closed_claim_scope_revokes_original_object_without_any_launch(self):
        module=load()
        with ExitStack() as owners:
            _local,_ownership,journal,writer,owner,target,token,unit,_image=self.owners(owners,claim=False)
            with journal._hold_counted_original_wire(writer,owner,target,unit) as image: pass
            with mock.patch.object(module.subprocess,'Popen') as launch:
                with self.assertRaises(module.MutationLauncherHold): module._send_counted_original_once(writer,owner,target,token,unit,image)
                launch.assert_not_called()
            self.assertEqual(1,journal.inspect_global_unit(owner,target,unit).attempt_count)

    def test_unconfirmed_supervisor_hold_preserves_unknown_claim_and_both_owner_locks(self):
        import fcntl
        module=load()
        with ExitStack() as stack:
            local,ownership,journal,writer,owner,target,token,unit,image=self.owners(stack)
            # Inject only the explicit supervisor fault result. Actual native
            # timeout/termination is covered separately; this checks propagation.
            process=SimpleNamespace(stdin=None,stdout=None,stderr=None)
            with mock.patch.object(module.subprocess,'Popen',return_value=process) as launch, \
                    mock.patch.object(module,'supervise_owned_attempt',side_effect=module.AttemptHold(False)):
                with self.assertRaises(module.MutationLauncherHold) as caught: module._send_counted_original_once(writer,owner,target,token,unit,image)
                self.assertFalse(caught.exception.termination_confirmed); self.assertIsNone(caught.exception.__context__)
                with self.assertRaises(module.MutationLauncherHold): module._send_counted_original_once(writer,owner,target,token,unit,image)
                self.assertEqual(1,launch.call_count)
            for path in (self.root/'project/.tracker/LOCK',self.root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(target.spreadsheet_id.encode()).hexdigest()+'.lock')):
                fd=os.open(path,os.O_RDWR)
                try:
                    with self.assertRaises(BlockingIOError): fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                finally: os.close(fd)
            self.assertEqual((1,'UNKNOWN'),(journal.inspect_global_unit(owner,target,unit).attempt_count,journal.inspect_global_unit(owner,target,unit).outcome))
