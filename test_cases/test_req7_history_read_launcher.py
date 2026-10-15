"""Fixed read-only entry with actual locks and owned loopback TLS, no online use."""
from contextlib import ExitStack, contextmanager
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
    @contextmanager
    def issuance_fixture(self, *, project_auth=False, close_fault=None, final_fault=None, terminated=True):
        """Direct lifecycle seam only; no genuine child or authentication claim."""
        module=load()
        from monitor import issue_tracker_local_commit as local, issue_tracker_spreadsheet_owner as ownership
        from monitor import issue_tracker_online_target as target, issue_tracker_token_launcher as auth
        from monitor.issue_tracker_sdk_authentication import AuthenticatedToken
        from monitor.issue_tracker_online_target import OnlineTargetBinding
        writer=object(); owner=object(); project=SimpleNamespace(lock_fd=21)
        binding=OnlineTargetBinding(TARGET,'a'*64,'b'*64)
        token=AuthenticatedToken('literal-direct-token',time.time()+3600)
        authentication=auth.ProjectTokenRefreshCompletion(token,'literal-cloud-project','d'*64,())
        authentication_packet=(os.getpid(),owner,binding,project,token,
            (token.value,token.expires_at),'literal-cloud-project','d'*64,())
        clock=[1000.0]; issued=[]; closes=[]; launches=[]; supervision=[]
        class Stream:
            closed=False
            def __init__(self,name): self.name=name
            def close(self):
                response=issued[0] if issued else None
                closes.append((self.name,response in module._READS,response in module._PROJECT_READS))
                self.closed=True;clock[0]+=1.0
                if self.name=='stdin' and close_fault is not None: raise close_fault
        process=SimpleNamespace(stdin=Stream('stdin'),stdout=Stream('stdout'),stderr=Stream('stderr'))
        original_decode=module._decode_completion
        def decode(*args):
            result=original_decode(*args);issued.append(result);return result
        def launch(*args,**kwargs): launches.append((args,kwargs));return process
        def supervise(child,**kwargs):
            self.assertIs(process,child);supervision.append(kwargs)
            request=json.loads(kwargs['request_bytes']);body=b'{"independent":"read"}'
            path=module._prepare(binding,token,'metadata',None,None).path
            header={'schema_version':1,'nonce':request['nonce'],
                'request_path_sha256':hashlib.sha256(path.encode('ascii')).hexdigest(),
                'status':200,'body_sha256':hashlib.sha256(body).hexdigest(),'body_bytes':len(body)}
            clock[0]=1008.0
            return SimpleNamespace(data=module._canonical(header)+body,termination_confirmed=terminated)
        def inspect(*args):
            if all(getattr(process,name).closed for name in ('stdin','stdout','stderr')):
                if final_fault=='target':raise module.HistoryReadLauncherHold()
                if final_fault=='acquisition_deadline':clock[0]=1030.0
            return binding
        def authenticate(*args):
            if final_fault=='token' and all(getattr(process,n).closed for n in ('stdin','stdout','stderr')):
                raise module.HistoryReadLauncherHold()
            return project,'d'*64
        with ExitStack() as stack:
            if project_auth:
                with auth._PROJECT_GUARD:auth._PROJECT_TOKENS[authentication]=authentication_packet
                stack.callback(auth._PROJECT_TOKENS.pop,authentication,None)
            stack.enter_context(mock.patch.object(local,'_owner',return_value=project))
            stack.enter_context(mock.patch.object(ownership,'owner_lock_fd',return_value=32))
            stack.enter_context(mock.patch.object(target,'inspect_project_online_target',side_effect=inspect))
            stack.enter_context(mock.patch.object(auth,'require_current_owned_project_token',side_effect=authenticate))
            stack.enter_context(mock.patch.object(module,'subprocess',SimpleNamespace(Popen=launch,PIPE=subprocess.PIPE)))
            stack.enter_context(mock.patch.object(module,'supervise_owned_attempt',side_effect=supervise))
            stack.enter_context(mock.patch.object(module,'_decode_completion',side_effect=decode))
            stack.enter_context(mock.patch.object(module,'time',SimpleNamespace(monotonic=lambda:1000.0)))
            stack.enter_context(mock.patch.object(module,'_monotonic',side_effect=lambda:clock[0]))
            unit=(module.OwnedProjectSheetsReadUnit(writer,owner,binding,authentication,read_kind='metadata')
                  if project_auth else module.OwnedSheetsReadUnit(writer,owner,binding,token,read_kind='metadata'))
            yield SimpleNamespace(module=module,unit=unit,writer=writer,owner=owner,binding=binding,
                authentication=authentication,clock=clock,issued=issued,closes=closes,
                launches=launches,supervision=supervision,process=process)

    def test_observation_has_fixed_sixty_seconds_after_successful_cleanup_without_renewal(self):
        with self.issuance_fixture() as f:
            actual=f.unit.read_once()
            self.assertEqual([('stdin',False,False),('stdout',False,False),('stderr',False,False)],f.closes)
            self.assertEqual(1071.0,f.module._READS[actual][-1],
                '8 seconds reading + 3 cleanup seconds, then exactly 60 observation seconds')
            self.assertEqual((1000.0,'read'),(f.supervision[0]['started_monotonic'],f.supervision[0]['kind']))
            self.assertEqual(30.0,f.module._BUDGETS['read']);self.assertEqual(60.0,f.module._BUDGETS['mutation'])
            packet=f.module._READS[actual]
            f.clock[0]=1031.0
            f.module.require_current_owned_read(f.writer,f.owner,f.binding,actual,read_kind='metadata')
            self.assertEqual(1071.0,f.module._READS[actual][-1])
            group=(('metadata',None,None,actual),)
            f.clock[0]=1070.0
            plan=f.module.require_current_owned_read(f.writer,f.owner,f.binding,actual,read_kind='metadata')
            self.assertIs(plan,f.module._require_current_owned_read_group(f.writer,f.owner,f.binding,group)[0])
            self.assertIs(packet,f.module._READS[actual])
            self.assertEqual(1071.0,packet[-1])
            f.clock[0]=1071.0
            with self.assertRaises(f.module.HistoryReadLauncherHold):
                f.module.require_current_owned_read(f.writer,f.owner,f.binding,actual,read_kind='metadata')
            with self.assertRaises(f.module.HistoryReadLauncherHold):
                f.module._require_current_owned_read_group(f.writer,f.owner,f.binding,group)
            self.assertIs(packet,f.module._READS[actual])
            with self.assertRaises(f.module.HistoryReadLauncherHold):f.unit.read_once()
            self.assertEqual(1,len(f.launches));self.assertEqual(1,len(f.supervision))

    def test_cleanup_refusal_or_interrupt_never_registers_a_read_observation(self):
        for project_auth in (False,True):
            for fault in (OSError('literal close failure'),KeyboardInterrupt('literal close interrupt')):
                with self.subTest(project=project_auth,fault=type(fault).__name__), \
                        self.issuance_fixture(project_auth=project_auth,close_fault=fault) as f:
                    with self.assertRaises(type(fault) if not isinstance(fault,Exception)
                                           else f.module.HistoryReadLauncherHold) as caught:
                        f.unit.read_once()
                    if not isinstance(fault,Exception):self.assertIs(fault,caught.exception)
                    self.assertEqual(1,len(f.issued));response=f.issued[0]
                    self.assertNotIn(response,f.module._READS);self.assertNotIn(response,f.module._PROJECT_READS)
                    self.assertTrue(all(getattr(f.process,n).closed for n in ('stdin','stdout','stderr')))

    def test_final_original_target_or_acquisition_deadline_refusal_never_issues_after_cleanup(self):
        for fault in ('target','token','acquisition_deadline'):
            with self.subTest(fault=fault),self.issuance_fixture(project_auth=True,final_fault=fault) as f:
                with self.assertRaises(f.module.HistoryReadLauncherHold):f.unit.read_once()
                self.assertTrue(all(getattr(f.process,n).closed for n in ('stdin','stdout','stderr')))
                response=f.issued[0]
                self.assertNotIn(response,f.module._READS);self.assertNotIn(response,f.module._PROJECT_READS)

    def test_partial_project_registry_interrupt_retracts_both_observation_entries(self):
        import weakref
        incoming=KeyboardInterrupt('literal registry interruption')
        original=weakref.WeakKeyDictionary.__setitem__
        with self.issuance_fixture(project_auth=True) as f:
            def put(registry,key,value):
                original(registry,key,value)
                if registry is f.module._PROJECT_READS:raise incoming
            with mock.patch.object(weakref.WeakKeyDictionary,'__setitem__',new=put), \
                    self.assertRaises(KeyboardInterrupt) as caught:f.unit.read_once()
            self.assertIs(incoming,caught.exception);response=f.issued[0]
            self.assertNotIn(response,f.module._READS);self.assertNotIn(response,f.module._PROJECT_READS)
            self.assertTrue(all(getattr(f.process,n).closed for n in ('stdin','stdout','stderr')))

    def test_unconfirmed_termination_cannot_issue_complete_read_evidence(self):
        with self.issuance_fixture(terminated=False) as f:
            before=(tuple(f.module._READS),tuple(f.module._PROJECT_READS))
            with self.assertRaises(f.module.HistoryReadLauncherHold):f.unit.read_once()
            self.assertEqual(before,(tuple(f.module._READS),tuple(f.module._PROJECT_READS)))
            self.assertTrue(all(getattr(f.process,n).closed for n in ('stdin','stdout','stderr')))

    def test_read_group_unissued_or_malformed_data_never_opens_sources(self):
        module=load()
        self.assertTrue(hasattr(module,'_require_current_owned_read_group'))
        from monitor import issue_tracker_online_target as target
        with mock.patch.object(target,'inspect_project_online_target') as opening:
            for wrong in ((),[],(('metadata',None,None,object()),),((False,None,None,object()),)):
                with self.subTest(kind=type(wrong).__name__),self.assertRaises(module.HistoryReadLauncherHold):
                    module._require_current_owned_read_group(object(),object(),object(),wrong)
            opening.assert_not_called()

    def test_g1_project_read_requires_original_issued_auth_not_decoded_or_caller_project(self):
        module=load()
        self.assertTrue(hasattr(module,'OwnedProjectSheetsReadUnit'),
                        'G1 fixed read must bind the original live Cloud authentication')
        self.assertTrue(hasattr(module,'require_current_owned_project_read'))
        from monitor import issue_tracker_token_launcher as auth
        from monitor.issue_tracker_online_target import OnlineTargetBinding
        nonce='a'*64
        value=auth._decode_project_completion(auth._canonical({'schema_version':2,'nonce':nonce,
            'token':'synthetic-token','expires_at':time.time()+3600,'runtime_warnings':[],
            'cloud_project_id':'synthetic-cloud-project','credential_sha256':'b'*64}),nonce)
        binding=OnlineTargetBinding(TARGET,'a'*64,'b'*64)
        with mock.patch.object(module.subprocess,'Popen') as launch:
            for candidate in (value,value.token,SimpleNamespace(token=value.token,cloud_project_id=value.cloud_project_id)):
                with self.subTest(candidate=type(candidate).__name__),self.assertRaises(module.HistoryReadLauncherHold) as caught:
                    module.OwnedProjectSheetsReadUnit(object(),object(),binding,candidate,read_kind='metadata')
                self.assertIsNone(caught.exception.__context__)
            with self.assertRaises(module.HistoryReadLauncherHold):
                module.require_current_owned_project_read(object(),object(),binding,object(),value,read_kind='metadata')
            launch.assert_not_called()

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
        image={'schema_version':2,'nonce':nonce,'spreadsheet_id':TARGET,'policy_sha256':'b'*64,
               'allowlist_sha256':'c'*64,'token':'synthetic-token','expires_at':time.time()+3600,
               'read_kind':'history_tail','sheet':None,'row':None}
        raw=(json.dumps(image,sort_keys=True,separators=(',',':'))+'\n').encode()
        variants=[b'',b'{}\n',raw+raw,b'x'*32769,raw.replace(b'"schema_version":2',b'"schema_version":true')]
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
    prepared_server_certificate = native_fixture.Req7NativeTlsWireTests.prepared_server_certificate
    _server_material_originals = native_fixture.Req7NativeTlsWireTests._server_material_originals
    server = native_fixture.Req7NativeTlsWireTests.server

    def test_original_auth_revocation_at_final_target_return_never_issues_a_project_read(self):
        module=load()
        from monitor import issue_tracker_token_launcher as auth, issue_tracker_online_target as target
        body=b'{"matchedDeveloperMetadata":[]}'
        reply=b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body
        for fault in ('token_expiry','auth_registry_revocation'):
            with self.subTest(fault=fault),ExitStack() as stack:
                if fault=='auth_registry_revocation':self.setUp();stack.callback(self.doCleanups)
                _local,ownership,writer,owner,binding,_token,_config=self.owners(stack)
                authentication,_credential,_original=self.project_auth(stack,ownership,owner,binding)
                with auth._PROJECT_GUARD:packet=auth._PROJECT_TOKENS[authentication]
                expiry=authentication.token.expires_at;decoded=[];mutated=[];target_visits=[]
                original_decode=module._decode_completion;original_target=target.inspect_project_online_target
                def decode(*args):
                    result=original_decode(*args);decoded.append(result);return result
                try:
                    with self.server(reply,hostname='sheets.googleapis.com',destination='sheets.googleapis.com') as (records,errors),ExitStack() as launched:
                        port=socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
                        calls,children=self.intercept(launched,self.child_fixture(port),writer,owner,binding)
                        def inspect(*args):
                            result=original_target(*args)
                            target_visits.append(True)
                            # The real supervisor already closes its streams.
                            # Parent-finalizer RETURN is the fourth target
                            # check: PRE, supervised POST, project POST, final.
                            if len(target_visits)==4:
                                self.assertTrue(all(getattr(children[0],n).closed for n in ('stdin','stdout','stderr')))
                                self.assertEqual([],mutated);mutated.append(True)
                                if fault=='token_expiry':object.__setattr__(authentication.token,'expires_at',0)
                                else:
                                    with auth._PROJECT_GUARD:auth._PROJECT_TOKENS.pop(authentication)
                            return result
                        unit=module.OwnedProjectSheetsReadUnit(writer,owner,binding,authentication,read_kind='metadata')
                        with mock.patch.object(target,'inspect_project_online_target',side_effect=inspect), \
                                mock.patch.object(module,'_decode_completion',side_effect=decode), \
                                self.assertRaises(module.HistoryReadLauncherHold):unit.read_once()
                        self.assertEqual(4,len(target_visits));self.assertEqual([True],mutated);self.assertEqual(1,len(decoded))
                        self.assertNotIn(decoded[0],module._READS);self.assertNotIn(decoded[0],module._PROJECT_READS)
                        self.assertEqual((1,0),(len(calls),children[0].returncode))
                        self.assertTrue(all(getattr(children[0],n).closed for n in ('stdin','stdout','stderr')))
                    self.assertEqual((1,[]),(len(records),errors))
                finally:
                    object.__setattr__(authentication.token,'expires_at',expiry)
                    with auth._PROJECT_GUARD:auth._PROJECT_TOKENS[authentication]=packet

    def test_real_original_project_and_legacy_reads_keep_fixed_post_completion_observation_window(self):
        module=load();body=b'{"matchedDeveloperMetadata":[]}'
        reply=b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body
        for project_auth in (False,True):
            # Separate actual owners/registries, TLS and supervised child each
            # time. Controlled clock only; native supervisor keeps real time.
            with self.subTest(project=project_auth),ExitStack() as stack:
                if project_auth:
                    # Each subcase needs an independent actual project fixture.
                    self.setUp();stack.callback(self.doCleanups)
                _local,ownership,writer,owner,binding,token,_config=self.owners(stack)
                authentication=None
                if project_auth:authentication,_credential,_original=self.project_auth(stack,ownership,owner,binding)
                with self.server(reply,hostname='sheets.googleapis.com',destination='sheets.googleapis.com') as (records,errors),ExitStack() as launched:
                    port=socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
                    calls,children=self.intercept(launched,self.child_fixture(port),writer,owner,binding)
                    started=time.monotonic();clock=[started+8.0]
                    unit=(module.OwnedProjectSheetsReadUnit(writer,owner,binding,authentication,read_kind='metadata')
                          if project_auth else module.OwnedSheetsReadUnit(writer,owner,binding,token,read_kind='metadata'))
                    with mock.patch.object(module,'time',SimpleNamespace(monotonic=lambda:started)), \
                            mock.patch.object(module,'_monotonic',side_effect=lambda:clock[0]):
                        actual=unit.read_once()
                        self.assertEqual(started+68.0,module._READS[actual][-1],
                            'observation is a fixed60s from successful completion, not initial read start')
                        self.assertEqual((body,1,0),(actual.data,len(calls),children[0].returncode))
                        self.assertTrue(all(getattr(children[0],n).closed for n in ('stdin','stdout','stderr')))
                        clock[0]=started+31.0
                        module.require_current_owned_read(writer,owner,binding,actual,read_kind='metadata')
                        if project_auth:
                            module.require_current_owned_project_read(writer,owner,binding,actual,authentication,read_kind='metadata')
                        packet=module._READS[actual]
                        self.assertEqual(started+68.0,packet[-1])
                        group=(('metadata',None,None,actual),)
                        clock[0]=started+67.0
                        for _ in range(2):
                            module._require_current_owned_read_group(writer,owner,binding,group,
                                _authentication=authentication)
                            self.assertIs(packet,module._READS[actual])
                            self.assertEqual(started+68.0,packet[-1])
                        clock[0]=started+68.0
                        with self.assertRaises(module.HistoryReadLauncherHold):
                            module.require_current_owned_read(writer,owner,binding,actual,read_kind='metadata')
                        with self.assertRaises(module.HistoryReadLauncherHold):
                            module._require_current_owned_read_group(writer,owner,binding,group,
                                _authentication=authentication)
                        if project_auth:
                            with self.assertRaises(module.HistoryReadLauncherHold):
                                module.require_current_owned_project_read(writer,owner,binding,actual,authentication,read_kind='metadata')
                        self.assertIs(packet,module._READS[actual])
                        with self.assertRaises(module.HistoryReadLauncherHold):unit.read_once()
                        self.assertEqual(1,len(calls))
                self.assertEqual((1,[]),(len(records),errors))

    def test_original_read_group_has_one_fresh_auth_target_pair_at_each_boundary(self):
        module=load()
        self.assertTrue(hasattr(module,'_require_current_owned_project_read_group'),
                        'fixed non-yield group must check genuine originals, not cache individual PASS')
        from monitor import issue_tracker_token_launcher as auth, issue_tracker_online_target as target
        with ExitStack() as stack:
            _local,ownership,writer,owner,binding,_token,_config=self.owners(stack)
            value,credential,original=self.project_auth(stack,ownership,owner,binding)
            responses=[]
            for kind,body in (('template_identity',b'{"independent":"identity"}'),
                              ('metadata',b'{"matchedDeveloperMetadata":[]}')):
                reply=b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body
                with self.server(reply,hostname='sheets.googleapis.com',destination='sheets.googleapis.com') as (records,errors),ExitStack() as launched:
                    port=socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
                    calls,children=self.intercept(launched,self.child_fixture(port),writer,owner,binding)
                    actual=module.OwnedProjectSheetsReadUnit(writer,owner,binding,value,read_kind=kind).read_once()
                    self.assertEqual((body,1,0),(actual.data,len(calls),children[0].returncode))
                self.assertEqual((1,[]),(len(records),errors))
                responses.append((kind,None,None,actual))
            expected=tuple(module.require_current_owned_project_read(writer,owner,binding,item[3],value,read_kind=item[0])
                           for item in responses)
            original_token=auth.require_current_owned_project_token
            original_target=target.inspect_project_online_target
            visits=[]
            def token(*args):
                visits.append('auth');return original_token(*args)
            def policy(*args):
                visits.append('target');return original_target(*args)
            with mock.patch.object(auth,'require_current_owned_project_token',side_effect=token), \
                    mock.patch.object(target,'inspect_project_online_target',side_effect=policy):
                actual=module._require_current_owned_project_read_group(writer,owner,binding,value,tuple(responses))
            self.assertEqual(expected,actual)
            self.assertTrue(all(a[0] is b[0] for a,b in zip(expected,actual)))
            self.assertEqual(['auth','target','auth','target'],visits)
            self.assertEqual(original,credential.read_bytes())
            # No reusable aggregate observation, callback, or extra read/send.
            self.assertIs(type(actual),tuple)
            self.assertTrue(hasattr(module,'_require_current_owned_read_group'))
            visits.clear()
            with mock.patch.object(target,'inspect_project_online_target',side_effect=policy):
                plans=module._require_current_owned_read_group(writer,owner,binding,tuple(responses))
            self.assertTrue(all(a[0] is b for a,b in zip(expected,plans)))
            self.assertEqual(['target','target'],visits)
            with module._READ_GUARD:first_deadline=module._READS[responses[0][3]][-1]
            with mock.patch.object(module,'_monotonic',side_effect=[first_deadline-1]*6+[first_deadline]), \
                    self.assertRaises(module.HistoryReadLauncherHold):
                module._require_current_owned_read_group(writer,owner,binding,tuple(responses))

    def test_original_read_group_refuses_equal_copy_revocation_and_expiry_at_return(self):
        module=load()
        self.assertTrue(hasattr(module,'_require_current_owned_project_read_group'))
        from dataclasses import replace
        from monitor import issue_tracker_online_target as target
        with ExitStack() as stack:
            _local,ownership,writer,owner,binding,_token,_config=self.owners(stack)
            value,_credential,_original=self.project_auth(stack,ownership,owner,binding)
            body=b'{"matchedDeveloperMetadata":[]}'
            reply=b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body
            with self.server(reply,hostname='sheets.googleapis.com',destination='sheets.googleapis.com') as (records,errors),ExitStack() as launched:
                port=socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
                calls,children=self.intercept(launched,self.child_fixture(port),writer,owner,binding)
                actual=module.OwnedProjectSheetsReadUnit(writer,owner,binding,value,read_kind='metadata').read_once()
                self.assertEqual((body,1,0),(actual.data,len(calls),children[0].returncode))
            self.assertEqual((1,[]),(len(records),errors))
            group=(('metadata',None,None,actual),)
            for wrong in ((('metadata',None,None,replace(actual)),),
                          (('metadata',None,True,actual),),(),list(group)):
                with self.subTest(wrong=type(wrong).__name__),self.assertRaises(module.HistoryReadLauncherHold):
                    module._require_current_owned_project_read_group(writer,owner,binding,value,wrong)
            with module._READ_GUARD:packet=module._READS[actual]
            with module._PROJECT_READ_GUARD:project_auth=module._PROJECT_READS[actual]
            original_target=target.inspect_project_online_target
            for fault in ('equal_registry_copy','auth_revoked','read_expired'):
                visits=[]
                def policy(*args):
                    result=original_target(*args);visits.append(True)
                    if len(visits)==2:
                        if fault=='equal_registry_copy':
                            with module._READ_GUARD:module._READS[actual]=tuple(list(packet))
                        elif fault=='auth_revoked':
                            with module._PROJECT_READ_GUARD:module._PROJECT_READS.pop(actual)
                        else:
                            # Fault is a deterministic deadline crossing, not
                            # a replacement read or a longer production limit.
                            module._monotonic=lambda:packet[-1]
                    return result
                try:
                    with mock.patch.object(module,'_monotonic',wraps=module._monotonic), \
                            mock.patch.object(target,'inspect_project_online_target',side_effect=policy), \
                            self.assertRaises(module.HistoryReadLauncherHold):
                        module._require_current_owned_project_read_group(writer,owner,binding,value,group)
                    self.assertEqual(2,len(visits))
                finally:
                    with module._READ_GUARD:module._READS[actual]=packet
                    with module._PROJECT_READ_GUARD:module._PROJECT_READS[actual]=project_auth
            module._require_current_owned_project_read_group(writer,owner,binding,value,group)
            from monitor import issue_tracker_token_launcher as auth
            original_token=auth.require_current_owned_project_token
            original_token_object=value.token
            original_expiry=value.token.expires_at
            original_config=_config.read_bytes()
            for fault in ('target_after_last_auth','equal_token_object','token_expiry_after_last_auth'):
                visits=[]
                def token(*args):
                    result=original_token(*args);visits.append(True)
                    if len(visits)==2:
                        if fault=='target_after_last_auth':
                            _config.write_text(json.dumps(document(status='disabled')))
                        elif fault=='equal_token_object':
                            object.__setattr__(value,'token',replace(original_token_object))
                        else:
                            object.__setattr__(original_token_object,'expires_at',0)
                    return result
                try:
                    with mock.patch.object(auth,'require_current_owned_project_token',side_effect=token), \
                            self.subTest(return_fault=fault),self.assertRaises(module.HistoryReadLauncherHold):
                        module._require_current_owned_project_read_group(writer,owner,binding,value,group)
                    self.assertEqual(2,len(visits))
                finally:
                    object.__setattr__(value,'token',original_token_object)
                    object.__setattr__(original_token_object,'expires_at',original_expiry)
                    _config.write_bytes(original_config)

    def owners(self,stack,*,target_id=TARGET):
        from monitor import issue_tracker_spreadsheet_owner as ownership, issue_tracker_online_target as target
        from monitor import issue_tracker_credential_shape as private, issue_tracker_local_commit as local
        self.root=self.root.resolve()
        project=self.root/'project'; project.mkdir(); publication=project/'publication'; publication.mkdir()
        local.create_local_commit_store(project,publication)
        config=project/'01-global.yaml'; config.write_text(json.dumps(document(target=target_id,cycles=3))); config.chmod(0o644)
        credential_dir=self.root/'var/lib/http-ztp-container/service-account'; credential_dir.mkdir(parents=True,mode=0o700)
        listing=credential_dir/'issue-tracker-spreadsheet-whitelist.json'; listing.write_text(json.dumps([target_id])); listing.chmod(0o600)
        locks=self.root/'var/lib/http-ztp-container/issue-tracker'; locks.mkdir(mode=0o700)
        binding=target.bind_online_target(document(target=target_id,cycles=3),target.freeze_target_allowlist(listing.read_bytes()))
        for module in (ownership,target,private): stack.enter_context(scoped_fixture(self.root,module))
        writer=stack.enter_context(local.writer_owner(project,publication))
        owner=stack.enter_context(ownership.spreadsheet_owner(binding))
        from monitor.issue_tracker_sdk_authentication import AuthenticatedToken
        return local,ownership,writer,owner,binding,AuthenticatedToken('owned-private-token',time.time()+3600),config

    def intercept(self,stack,program,writer,owner,binding,*,template_cohort=False):
        module=load(); native=subprocess.Popen; calls=[]; children=[]
        from monitor import issue_tracker_local_commit as local, issue_tracker_spreadsheet_owner as ownership
        def launch(argv,**kwargs):
            self.assertEqual([str(Path(sys.executable).resolve()),'-I','-B','-c'],argv[:4])
            expected_program=module._TEMPLATE_COHORT_CHILD_PROGRAM if template_cohort else module._CHILD_PROGRAM
            self.assertEqual(expected_program,argv[4]); self.assertEqual(str(ROOT),argv[5]); self.assertEqual(7,len(argv))
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

    def test_fixed_template_group_boundary_rechecks_last_actual_auth_source_and_retains_no_permit(self):
        self._template_cohort_actual_tls_workflow(consumer=True,group_boundary=True)

    def _template_cohort_actual_tls_workflow(self,*,partial=False,consumer=False,group_boundary=False):
        # Four real native requests inside one actual original supervised
        # child. The only test substitutions remain owned root/CA and DNS.
        module=load();kinds=('template_identity','template_headers','whitelist','metadata')
        bodies=(b'{"literal":"identity"}',b'{"literal":"headers"}',
                b'{"literal":"whitelist"}',b'{"matchedDeveloperMetadata":[]}')
        replies=tuple(b'HTTP/1.1 200 OK\r\nContent-Length: '+
            str(len(body)+(1 if partial and index==3 else 0)).encode()+
            b'\r\nConnection: close\r\n\r\n'+body for index,body in enumerate(bodies))
        with ExitStack() as stack:
            _local,ownership,writer,owner,binding,_token,_config=self.owners(stack)
            authentication,credential,original=self.project_auth(stack,ownership,owner,binding)
            before=set(module._READS);before_auth=set(module._PROJECT_READS)
            with self.server(replies,hostname='sheets.googleapis.com',destination='sheets.googleapis.com') as (records,errors),ExitStack() as launched:
                port=socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
                old=self.child_fixture(port)
                needle='result=launcher._history_child(sys.argv[2])'
                self.assertEqual(1,old.count(needle))
                program=old.replace(needle,'result=launcher._history_template_cohort_child(sys.argv[2])')
                calls,children=self.intercept(launched,program,writer,owner,binding,template_cohort=True)
                unit=None if consumer else module.OwnedProjectTemplateReadCohort(writer,owner,binding,authentication)
                if consumer:
                    from monitor import issue_tracker_remote_history_match as remote
                    acquire=getattr(remote,'_acquire_current_project_template_reads',None)
                    self.assertTrue(callable(acquire),'actual fixed consumer boundary is missing')
                def read():
                    if consumer:
                        result=acquire(writer,owner,binding,authentication)
                        self.assertEqual(kinds,tuple(result))
                        return tuple(result.values())
                    return unit.read_once()
                if partial:
                    with self.assertRaises(module.HistoryReadLauncherHold) as caught:read()
                    self.assertTrue(caught.exception.termination_confirmed)
                    self.assertEqual(before,set(module._READS));self.assertEqual(before_auth,set(module._PROJECT_READS))
                    self.assertNotEqual(0,children[0].returncode)
                else:
                    results=read()
                    if group_boundary:
                        from monitor import issue_tracker_remote_history_match as remote
                        from monitor import issue_tracker_online_target as target
                        verify=getattr(remote,'_verify_current_project_template_reads',None)
                        self.assertTrue(callable(verify),'fixed template original group boundary is absent')
                        responses=dict(zip(kinds,results));visits=[]
                        original_target=target.inspect_project_online_target
                        def policy(*args):
                            value=original_target(*args);visits.append(True)
                            if len(visits)==2:
                                with module._PROJECT_READ_GUARD:module._PROJECT_READS.pop(results[-1])
                            return value
                        self.assertIsNone(verify(writer,owner,binding,authentication,responses))
                        with mock.patch.object(target,'inspect_project_online_target',side_effect=policy), \
                                self.assertRaises(module.HistoryReadLauncherHold):
                            verify(writer,owner,binding,authentication,responses)
                        self.assertEqual(2,len(visits))
                        with module._PROJECT_READ_GUARD:module._PROJECT_READS[results[-1]]=authentication
                    self.assertEqual(bodies,tuple(result.data for result in results))
                    deadlines=tuple(module._READS[result][-1] for result in results)
                    self.assertEqual((deadlines[0],)*4,deadlines)
                    for kind,result in zip(kinds,results):
                        module.require_current_owned_project_read(writer,owner,binding,result,authentication,read_kind=kind)
                        self.assertFalse(hasattr(result,'permit'))
                    self.assertEqual(0,children[0].returncode)
                self.assertEqual((1,1),(len(calls),len(children)))
                self.assertTrue(all(getattr(children[0],name).closed for name in ('stdin','stdout','stderr')))
                if not consumer:
                    with self.assertRaises(module.HistoryReadLauncherHold):unit.read_once()
                self.assertEqual(1,len(calls))
            self.assertEqual((4,[]),(len(records),errors))
            self.assertEqual(('GET','GET','GET','POST'),tuple(row[0].split(b' ',1)[0].decode() for row in records))
            self.assertTrue(all(b'Host: sheets.googleapis.com\r\n' in row[1] for row in records))
            self.assertTrue(all(b'Authorization: Bearer owned-project-token\r\n' in row[1] for row in records))
            self.assertEqual((b'',b'',b'',b'{"dataFilters":[{"developerMetadataLookup":{}}]}'),tuple(row[2] for row in records))
            self.assertEqual(original,credential.read_bytes())
            ownership.owner_lock_fd(owner,binding)

    def test_fixed_template_cohort_one_actual_child_four_tls_requests_complete_before_issue(self):
        self._template_cohort_actual_tls_workflow()

    def test_fixed_template_cohort_partial_fourth_tls_response_never_issues_or_retries(self):
        self._template_cohort_actual_tls_workflow(partial=True)

    def test_fixed_consumer_boundary_uses_actual_one_child_and_four_tls_completions(self):
        self._template_cohort_actual_tls_workflow(consumer=True)

    def test_fixed_consumer_boundary_partial_fourth_tls_never_returns_observations(self):
        self._template_cohort_actual_tls_workflow(partial=True,consumer=True)

    def project_auth(self,stack,ownership,owner,binding):
        """Real fixed FD -> public SDK -> native OAuth TLS -> owned child."""
        from test_req7_sdk_authentication import fresh_info
        from test_req7_token_launcher import Req7FixedTokenLauncherWorkflowTests
        from monitor import issue_tracker_token_launcher as auth
        # Canonical reloads in SDK direct tests may leave a stale package
        # attribute. Scope the actual module used by qualified production
        # imports; never relax its root-only check or mutate a stale object.
        sdk=importlib.import_module('monitor.issue_tracker_sdk_authentication')
        stack.enter_context(scoped_fixture(self.root,sdk))
        credential=self.root/'var/lib/http-ztp-container/service-account/cre.json'
        if credential.exists(): original=credential.read_bytes()
        else:
            info=fresh_info(); info['project_id']='synthetic-cloud-project'
            original=json.dumps(info).encode(); credential.write_bytes(original); credential.chmod(0o600)
        # Synthetic response only; preserve the original wire bytes rather
        # than granting the public audit an exception for credential JSON.
        fixture_token='owned-project-token'
        body=json.dumps({'access_token':fixture_token,'expires_in':3600},
                        separators=(',',':')).encode('ascii')
        reply=b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body
        with self.server(reply) as (records,errors),ExitStack() as launched:
            port=socket.getaddrinfo('oauth2.googleapis.com',443)[0][4][1]
            program=Req7FixedTokenLauncherWorkflowTests.child_fixture(self,port,project_scope=True)
            native=subprocess.Popen; children=[]
            def launch(argv,**kwargs):
                self.assertEqual([str(Path(sys.executable).resolve()),'-I','-B','-c'],argv[:4])
                self.assertEqual(auth._PROJECT_CHILD_PROGRAM,argv[4]); self.assertEqual(str(ROOT),argv[5])
                self.assertEqual(7,len(argv)); self.assertEqual({'LC_ALL':'C'},kwargs['env'])
                self.assertIs(kwargs['stdin'],subprocess.DEVNULL)
                self.assertEqual((ownership.owner_lock_fd(owner,binding),),kwargs['pass_fds'])
                changed=list(argv); changed[4]=program
                child=native(changed,**kwargs); children.append(child); return child
            launched.enter_context(mock.patch.object(auth,'subprocess',SimpleNamespace(Popen=launch,PIPE=subprocess.PIPE,DEVNULL=subprocess.DEVNULL)))
            with self.assertWarnsRegex(FutureWarning,'Python version 3.9 past its end of life') if sys.version_info[:2]==(3,9) else ExitStack():
                value=auth.OwnedProjectTokenRefreshUnit(owner,binding).refresh_once()
            self.assertEqual(1,len(children)); self.assertEqual(0,children[0].returncode)
            self.assertTrue(children[0].stdout.closed); self.assertTrue(children[0].stderr.closed)
        self.assertEqual([],errors); self.assertEqual(1,len(records)); self.assertEqual(original,credential.read_bytes())
        return value,credential,original

    def test_g1_fixture_patches_current_sdk_not_stale_parent_package_attribute(self):
        import monitor
        from monitor import issue_tracker_token_launcher as auth
        current=importlib.import_module('monitor.issue_tracker_sdk_authentication')
        # Equivalent to a loader that refreshes sys.modules without updating
        # the package attribute. No production guard or source is patched.
        stale=SimpleNamespace(os=os)
        with ExitStack() as stack:
            _local,ownership,writer,owner,binding,_token,_config=self.owners(stack)
            with mock.patch.object(monitor,'issue_tracker_sdk_authentication',stale):
                value,_credential,_original=self.project_auth(stack,ownership,owner,binding)
                self.assertEqual(0,current.os.geteuid(),'owned root facade must target the active canonical SDK')
                self.assertIs(os,stale.os,'a stale module must remain untouched')
                self.assertEqual(('synthetic-cloud-project',value.credential_sha256),
                                 auth.require_current_owned_project_token(owner,binding,value))

    def test_g1_real_auth_and_metadata_read_share_original_project_not_equal_token_or_copy(self):
        from dataclasses import replace
        module=load()
        self.assertTrue(hasattr(module,'OwnedProjectSheetsReadUnit'))
        from monitor import issue_tracker_token_launcher as auth
        with ExitStack() as stack:
            _local,ownership,writer,owner,binding,_token,config=self.owners(stack)
            value,credential,original=self.project_auth(stack,ownership,owner,binding)
            body=b'{"matchedDeveloperMetadata":[]}'
            reply=b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body
            with self.server(reply,hostname='sheets.googleapis.com',destination='sheets.googleapis.com') as (records,errors),ExitStack() as launched:
                port=socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
                calls,children=self.intercept(launched,self.child_fixture(port),writer,owner,binding)
                unit=module.OwnedProjectSheetsReadUnit(writer,owner,binding,value,read_kind='metadata')
                result=unit.read_once()
                plan,project,digest=module.require_current_owned_project_read(writer,owner,binding,result,value,read_kind='metadata')
                self.assertEqual('synthetic-cloud-project',project); self.assertEqual(hashlib.sha256(original).hexdigest(),digest)
                self.assertEqual(('Authorization','Bearer owned-project-token'),plan.headers[1])
                self.assertEqual(body,result.data); self.assertFalse(hasattr(result,'inventory_complete'))
                for response,authentication in ((replace(result),value),(result,replace(value)),(result,replace(value,cloud_project_id='foreign-cloud-project'))):
                    with self.assertRaises(module.HistoryReadLauncherHold):
                        module.require_current_owned_project_read(writer,owner,binding,response,authentication,read_kind='metadata')
                # A second valid auth acquisition with the same returned token
                # is not the original auth acquisition bound to this read.
                second,_credential,_original=self.project_auth(stack,ownership,owner,binding)
                self.assertEqual(value.token.value,second.token.value)
                auth.require_current_owned_project_token(owner,binding,value)
                auth.require_current_owned_project_token(owner,binding,second)
                with self.assertRaises(module.HistoryReadLauncherHold):
                    module.require_current_owned_project_read(writer,owner,binding,result,second,read_kind='metadata')
                with self.assertRaises(module.HistoryReadLauncherHold): unit.read_once()
                self.assertEqual(1,len(calls)); self.assertEqual(0,children[0].returncode)
            self.assertEqual([],errors); self.assertEqual(1,len(records)); self.assertEqual(b'{"dataFilters":[{"developerMetadataLookup":{}}]}',records[0][2])
            self.assertIn(b'Authorization: Bearer owned-project-token\r\n',records[0][1])
            with mock.patch.object(module,'_monotonic',return_value=time.monotonic()+61),self.assertRaises(module.HistoryReadLauncherHold):
                module.require_current_owned_project_read(writer,owner,binding,result,value,read_kind='metadata')
            with mock.patch.object(auth,'time',SimpleNamespace(time=lambda:value.token.expires_at)),self.assertRaises(module.HistoryReadLauncherHold):
                module.require_current_owned_project_read(writer,owner,binding,result,value,read_kind='metadata')
            # Even a real legacy read using the exact issued token cannot be
            # retroactively tagged as an original project-bound read.
            with self.server(reply,hostname='sheets.googleapis.com',destination='sheets.googleapis.com') as (records,errors),ExitStack() as launched:
                port=socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
                calls,children=self.intercept(launched,self.child_fixture(port),writer,owner,binding)
                legacy=module.OwnedSheetsReadUnit(writer,owner,binding,value.token,read_kind='metadata').read_once()
                module.require_current_owned_read(writer,owner,binding,legacy,read_kind='metadata')
                with self.assertRaises(module.HistoryReadLauncherHold):
                    module.require_current_owned_project_read(writer,owner,binding,legacy,value,read_kind='metadata')
                self.assertEqual(1,len(calls)); self.assertEqual(0,children[0].returncode)
            self.assertEqual([],errors); self.assertEqual(1,len(records)); self.assertEqual(body,legacy.data)
            credential.write_bytes(original+b'\n')
            with self.assertRaises(module.HistoryReadLauncherHold):
                module.require_current_owned_project_read(writer,owner,binding,result,value,read_kind='metadata')
            credential.write_bytes(original)
            config.write_text(json.dumps(document(status='disabled')))
            with self.assertRaises(module.HistoryReadLauncherHold):
                module.require_current_owned_project_read(writer,owner,binding,result,value,read_kind='metadata')
        with self.assertRaises(module.HistoryReadLauncherHold):
            module.require_current_owned_project_read(writer,owner,binding,result,value,read_kind='metadata')

    def test_g1_credential_drift_before_or_during_read_never_issues_project_observation(self):
        module=load()
        self.assertTrue(hasattr(module,'OwnedProjectSheetsReadUnit'))
        with ExitStack() as stack:
            _local,ownership,writer,owner,binding,_token,_config=self.owners(stack)
            value,credential,original=self.project_auth(stack,ownership,owner,binding)
            unit=module.OwnedProjectSheetsReadUnit(writer,owner,binding,value,read_kind='metadata')
            credential.write_bytes(original+b'\n')
            with mock.patch.object(module.subprocess,'Popen') as launch:
                with self.assertRaises(module.HistoryReadLauncherHold): unit.read_once()
                with self.assertRaises(module.HistoryReadLauncherHold): unit.read_once()
                launch.assert_not_called()
            credential.write_bytes(original)
            def respond(transport):
                credential.write_bytes(original+b'\n')
                transport.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}')
            with self.server(respond,hostname='sheets.googleapis.com',destination='sheets.googleapis.com') as (records,errors),ExitStack() as launched:
                port=socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
                calls,children=self.intercept(launched,self.child_fixture(port),writer,owner,binding)
                unit=module.OwnedProjectSheetsReadUnit(writer,owner,binding,value,read_kind='metadata')
                with module._PROJECT_READ_GUARD: before=tuple(module._PROJECT_READS)
                with self.assertRaises(module.HistoryReadLauncherHold): unit.read_once()
                with module._PROJECT_READ_GUARD: self.assertEqual(before,tuple(module._PROJECT_READS))
                with self.assertRaises(module.HistoryReadLauncherHold): unit.read_once()
                self.assertEqual(1,len(calls)); self.assertEqual(0,children[0].returncode)
            self.assertEqual([],errors); self.assertEqual(1,len(records)); self.assertEqual(original+b'\n',credential.read_bytes())
            credential.write_bytes(original)

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

    def test_delayed_owned_child_start_keeps_real_read_deadline_and_single_native_request(self):
        module=load(); body=b'{"spreadsheetId":"synthetic","sheets":[]}'
        reply=b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body
        with ExitStack() as stack:
            _local,_ownership,writer,owner,binding,token,_config=self.owners(stack)
            with self.server(reply,hostname='sheets.googleapis.com',destination='sheets.googleapis.com') as (records,errors),ExitStack() as launched:
                port=socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
                # Controlled startup lag exceeds the fixture's transport wait,
                # but not the unchanged production 30-second read deadline.
                program='import time\ntime.sleep(3.25)\n'+self.child_fixture(port)
                calls,children=self.intercept(launched,program,writer,owner,binding)
                unit=module.OwnedHistoryTailReadUnit(writer,owner,binding,token)
                result=unit.read_once()
                self.assertEqual((body,True,1,0),(result.data,result.complete,len(calls),children[0].returncode))
                self.assertTrue(children[0].stdin.closed); self.assertTrue(children[0].stdout.closed)
                self.assertTrue(children[0].stderr.closed)
                with self.assertRaises(module.HistoryReadLauncherHold): unit.read_once()
            self.assertEqual([],errors); self.assertEqual(1,len(records)); self.assertEqual(b'',records[0][2])

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

    def test_all_required_fixed_read_shapes_share_supervision_and_private_input(self):
        module=load()
        self.assertTrue(hasattr(module,'OwnedSheetsReadUnit'),'other fixed reads still lack supervised dual-owner entry')
        with ExitStack() as stack:
            _local,ownership,writer,owner,binding,token,_config=self.owners(stack)
            cases=(('history_tail',None,None,"'Update_History'!A3:E5002",'GET'),
                   ('whitelist',None,None,"'Whitelist'!A1:F10000",'GET'),
                   ('template_identity',None,None,None,'GET'),
                   ('template_headers',None,None,"'ETH&IB Switch'!A2:U2",'GET'),
                   ('activity','ETH Cabling',None,"'ETH Cabling'!A3:A5002",'GET'),
                   ('insertion','IB Cabling',None,"'IB Cabling'!AC3:AC5002",'GET'),
                   ('row','ETH&IB Switch',7,"'ETH&IB Switch'!A7:U7",'GET'),
                   ('metadata',None,None,None,'POST'))
            from urllib.parse import parse_qs,urlsplit
            for kind,sheet,row,expected_range,method in cases:
                # Owned child validates the actual private input with the real
                # planner and emits its exact path correlation. Not native TLS;
                # separate native cases below establish the wire boundaries.
                program='''import sys,os,hashlib
sys.path[:0]=[sys.argv[1],sys.argv[1]+"/tools"]
from monitor import issue_tracker_history_read_launcher as entry
binding,token,plan=entry._parse_request(sys.stdin.buffer.read(),sys.argv[2])
body=b'{"owned":"shape"}'
header=entry._canonical({'schema_version':1,'nonce':sys.argv[2],'request_path_sha256':hashlib.sha256(plan.path.encode('ascii')).hexdigest(),'status':200,'body_sha256':hashlib.sha256(body).hexdigest(),'body_bytes':len(body)})
os.write(1,header+body)
'''
                with self.subTest(kind=kind), ExitStack() as owned_stack:
                    calls,children=self.intercept(owned_stack,program,writer,owner,binding)
                    unit=module.OwnedSheetsReadUnit(writer,owner,binding,token,read_kind=kind,sheet=sheet,row=row)
                    result=unit.read_once(); self.assertEqual(b'{"owned":"shape"}',result.data)
                    plan=module._prepare(binding,token,kind,sheet,row)
                    query=parse_qs(urlsplit(plan.path).query)
                    self.assertEqual(method,plan.method); self.assertEqual('sheets.googleapis.com',plan.host)
                    if expected_range is not None: self.assertIn(expected_range,query['ranges'])
                    if kind=='template_identity': self.assertNotIn('ranges',query)
                    if kind=='metadata':
                        self.assertTrue(urlsplit(plan.path).path.endswith('/developerMetadata:search'))
                        self.assertEqual(b'{"dataFilters":[{"developerMetadataLookup":{}}]}',plan.body)
                    self.assertEqual(1,len(calls)); self.assertEqual(0,children[0].returncode)
                    with self.assertRaises(module.HistoryReadLauncherHold): unit.read_once()
                    ownership.owner_lock_fd(owner,binding)

    def test_arbitrary_kind_sheet_row_or_url_never_launches(self):
        module=load()
        self.assertTrue(hasattr(module,'OwnedSheetsReadUnit'),'strict fixed read dispatch missing')
        with ExitStack() as stack:
            _local,_ownership,writer,owner,binding,token,_config=self.owners(stack)
            with mock.patch.object(module.subprocess,'Popen') as launch:
                for kind,sheet,row in (('mutation',None,None),('https://foreign.invalid/',None,None),
                                       ('history_tail','ETH Cabling',None),('whitelist',None,3),
                                       ('activity','foreign',None),('insertion','ETH Cabling',True),
                                       ('row','IB Cabling',True),('row','IB Cabling',2),('row','IB Cabling',None)):
                    with self.subTest(kind=kind),self.assertRaises(module.HistoryReadLauncherHold):
                        module.OwnedSheetsReadUnit(writer,owner,binding,token,read_kind=kind,sheet=sheet,row=row)
                launch.assert_not_called()

    def test_only_original_issued_read_under_current_exact_owners_and_shape_can_supply_plan(self):
        module=load()
        self.assertTrue(hasattr(module,'require_current_owned_read'),'private read provenance bridge missing')
        from dataclasses import replace
        with ExitStack() as stack:
            _local,_ownership,writer,owner,binding,token,config=self.owners(stack)
            program='''import sys,os,hashlib
sys.path[:0]=[sys.argv[1],sys.argv[1]+"/tools"]
from monitor import issue_tracker_history_read_launcher as entry
binding,token,plan=entry._parse_request(sys.stdin.buffer.read(),sys.argv[2])
body=b'{"owned":"history"}'
header=entry._canonical({'schema_version':1,'nonce':sys.argv[2],'request_path_sha256':hashlib.sha256(plan.path.encode('ascii')).hexdigest(),'status':200,'body_sha256':hashlib.sha256(body).hexdigest(),'body_bytes':len(body)})
os.write(1,header+body)
'''
            self.intercept(stack,program,writer,owner,binding)
            result=module.OwnedHistoryTailReadUnit(writer,owner,binding,token).read_once()
            plan=module.require_current_owned_read(writer,owner,binding,result,read_kind='history_tail')
            self.assertEqual(result.request_path_sha256,hashlib.sha256(plan.path.encode('ascii')).hexdigest())
            for candidate in (replace(result),SimpleNamespace(data=result.data,status=200,complete=True),
                              module._decode_completion((json.dumps({'schema_version':1,'nonce':'a'*64,
                                  'request_path_sha256':result.request_path_sha256,'status':200,
                                  'body_sha256':hashlib.sha256(result.data).hexdigest(),'body_bytes':len(result.data)},
                                  sort_keys=True,separators=(',',':'))+'\n').encode()+result.data,'a'*64,result.request_path_sha256)):
                with self.subTest(type=type(candidate).__name__),self.assertRaises(module.HistoryReadLauncherHold):
                    module.require_current_owned_read(writer,owner,binding,candidate,read_kind='history_tail')
            for changed in ({'writer_token':object()},{'owner_token':object()}, {'read_kind':'metadata'},
                            {'sheet':'ETH Cabling'},{'row':3}):
                arguments={'writer_token':writer,'owner_token':owner,'binding':binding,'completion':result,
                           'read_kind':'history_tail',**changed}
                with self.subTest(changed=list(changed)),self.assertRaises(module.HistoryReadLauncherHold):
                    module.require_current_owned_read(**arguments)
            with mock.patch.object(module,'_monotonic',return_value=time.monotonic()+61):
                with self.assertRaises(module.HistoryReadLauncherHold):
                    module.require_current_owned_read(writer,owner,binding,result,read_kind='history_tail')
            original=result.data
            object.__setattr__(result,'data',b'{"different":"response"}')
            with self.assertRaises(module.HistoryReadLauncherHold):
                module.require_current_owned_read(writer,owner,binding,result,read_kind='history_tail')
            object.__setattr__(result,'data',original)
            row_read=module.OwnedSheetsReadUnit(writer,owner,binding,token,read_kind='row',sheet='ETH Cabling',row=7).read_once()
            module.require_current_owned_read(writer,owner,binding,row_read,read_kind='row',sheet='ETH Cabling',row=7)
            with self.assertRaises(module.HistoryReadLauncherHold):
                module.require_current_owned_read(writer,owner,binding,row_read,read_kind='row',sheet='ETH Cabling',row=7.0)
            config.write_text(json.dumps(document(status='disabled')))
            with self.assertRaises(module.HistoryReadLauncherHold):
                module.require_current_owned_read(writer,owner,binding,result,read_kind='history_tail')
        with self.assertRaises(module.HistoryReadLauncherHold):
            module.require_current_owned_read(writer,owner,binding,result,read_kind='history_tail')

    def test_actual_supervised_native_whitelist_template_and_readonly_metadata_are_typed_not_admission(self):
        module=load()
        from test_req7_online_whitelist_read import document as whitelist_document, HEADER
        from test_req7_sheets_read_decode import identity_response, header_response, TEMPLATE_SHEETS, HEADERS
        from monitor import issue_tracker_sheets_read_decode as decode, issue_tracker_online_whitelist_read as whitelist
        from monitor import issue_tracker_metadata_capacity as metadata
        from monitor.issue_tracker_whitelist import freeze_whitelist_sheet
        local_rules=freeze_whitelist_sheet([HEADER,(None,None,None,None,'leaf-01',None),
                                          (None,None,None,None,'spine-*',None)])
        expected_local=local_rules.canonical_bytes; identity=None; seen_kinds=[]
        documents=[('whitelist',whitelist_document()),('template_identity',identity_response()),
                   ('template_headers',header_response()),('metadata',{})]
        with ExitStack() as stack:
            _local,ownership,writer,owner,binding,token,_config=self.owners(stack)
            for kind,value in documents:
                if kind!='metadata': value['spreadsheetId']=TARGET
                body=json.dumps(value,separators=(',',':')).encode()
                reply=b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body
                with self.subTest(kind=kind),self.server(reply,hostname='sheets.googleapis.com',destination='sheets.googleapis.com') as (records,errors),ExitStack() as launched:
                    port=socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
                    calls,children=self.intercept(launched,self.child_fixture(port),writer,owner,binding)
                    unit=module.OwnedSheetsReadUnit(writer,owner,binding,token,read_kind=kind)
                    result=unit.read_once()
                    plan=module.require_current_owned_read(writer,owner,binding,result,read_kind=kind)
                    self.assertEqual(body,result.data); self.assertEqual(1,len(calls)); self.assertEqual(0,children[0].returncode)
                    if kind=='whitelist':
                        observed=whitelist.compare_online_whitelist_read(plan,result,local_rules)
                        self.assertEqual(local_rules.sha256,observed.rules_sha256)
                        self.assertEqual(expected_local,local_rules.canonical_bytes)
                    elif kind=='template_identity':
                        identity=decode.decode_template_identity(plan,result)
                        self.assertEqual(tuple((title,100+i) for i,title in enumerate(TEMPLATE_SHEETS)),identity.sheet_ids)
                    elif kind=='template_headers':
                        observed=decode.decode_template_headers(plan,result,identity)
                        self.assertEqual(tuple((title,len(header)) for title,header in HEADERS.items()),observed.checked_headers)
                    else:
                        observed=metadata.observe_metadata_capacity(plan,result,identity,reservations=())
                        self.assertEqual('VISIBLE_ONLY_UNPROVED',observed.outcome)
                        self.assertFalse(observed.inventory_complete)
                    ownership.owner_lock_fd(owner,binding); seen_kinds.append(kind)
                self.assertEqual([],errors); self.assertEqual(1,len(records))
                self.assertIn(b'Host: sheets.googleapis.com\r\n',records[0][1])
                if kind=='metadata':
                    self.assertTrue(records[0][0].startswith(b'POST /v4/spreadsheets/'+TARGET.encode()+b'/developerMetadata:search?'))
                    self.assertEqual(b'{"dataFilters":[{"developerMetadataLookup":{}}]}',records[0][2])
                else:
                    self.assertTrue(records[0][0].startswith(b'GET /v4/spreadsheets/'+TARGET.encode()+b'?'))
                    self.assertEqual(b'',records[0][2])
            self.assertEqual(['whitelist','template_identity','template_headers','metadata'],seen_kinds)


class Req7TemplateCohortDirectTests(unittest.TestCase):
    """Fixed cohort codec/lifecycle only; mocked transport is NOT native proof."""
    issuance_fixture = Req7HistoryReadLauncherDirectTests.issuance_fixture
    kinds = ('template_identity', 'template_headers', 'whitelist', 'metadata')

    def required(self, name):
        actual = getattr(load(), name, None)
        self.assertTrue(callable(actual), 'fixed template cohort ' + name + ' missing')
        return actual

    @staticmethod
    def frame(nonce, paths, bodies, *, kinds=None):
        kinds = kinds or Req7TemplateCohortDirectTests.kinds
        # Independent literal protocol, never generated by the tested codec.
        parts = [dict(read_kind=kind, request_path_sha256=hashlib.sha256(path.encode('ascii')).hexdigest(),
                      status=200, body_sha256=hashlib.sha256(body).hexdigest(), body_bytes=len(body))
                 for kind, path, body in zip(kinds, paths, bodies)]
        header = dict(schema_version=3, nonce=nonce, parts=parts)
        return (json.dumps(header, sort_keys=True, separators=(',', ':'), ensure_ascii=True)+'\n').encode('ascii') + b''.join(bodies)

    def test_fixed_four_frame_whole_bytes_order_and_paths_not_permission(self):
        decode = self.required('_decode_template_cohort_completion')
        nonce = '1'*64
        paths = ('/literal/identity', '/literal/headers', '/literal/whitelist', '/literal/metadata')
        bodies = (b'identity-literal', b'headers\x00literal', b'whitelist\r\nliteral', b'metadata-literal')
        plans = tuple(SimpleNamespace(path=path) for path in paths)
        results = decode(self.frame(nonce, paths, bodies), nonce, plans)
        self.assertIs(type(results), tuple)
        self.assertEqual(4, len(results))
        self.assertEqual(bodies, tuple(result.data for result in results))
        self.assertEqual(tuple(hashlib.sha256(path.encode('ascii')).hexdigest() for path in paths),
                         tuple(result.request_path_sha256 for result in results))
        for result in results:
            self.assertNotIn(result, load()._READS)
            self.assertNotIn(result, load()._PROJECT_READS)

    def test_wrong_role_order_nonce_digest_partial_or_trailing_data_refuses(self):
        decode = self.required('_decode_template_cohort_completion')
        nonce='2'*64; paths=('/literal/id','/literal/headers','/literal/wl','/literal/meta')
        plans=tuple(SimpleNamespace(path=path) for path in paths); bodies=(b'id',b'headers',b'wl',b'meta')
        raw=self.frame(nonce,paths,bodies)
        for changed in (raw[:-1], raw+b'x', self.frame('3'*64,paths,bodies),
                        self.frame(nonce,paths,bodies,kinds=tuple(reversed(self.kinds))),
                        self.frame(nonce,paths[:-1]+('/foreign',),bodies),
                        self.frame(nonce,paths,(b'id',b'headers',b'wl',b'Meta'))[:-1]+b'X'):
            with self.subTest(change=hashlib.sha256(changed).hexdigest()), self.assertRaises(load().HistoryReadLauncherHold):
                decode(changed,nonce,plans)
        with self.assertRaises(load().HistoryReadLauncherHold):
            decode(b'x'*(2*1024*1024+1),nonce,plans)

    def reply(self, f, *, partial=False):
        bodies=(b'identity-original',b'headers-original',b'whitelist-original',b'metadata-original')
        def supervise(child, **kwargs):
            self.assertIs(child,f.process); f.supervision.append(kwargs)
            request=json.loads(kwargs['request_bytes'])
            self.assertEqual(3,request['schema_version'])
            self.assertNotIn('read_kind',request)
            self.assertNotIn('plans',request)
            paths=tuple(f.module._prepare(f.binding,f.authentication.token,kind,None,None).path for kind in self.kinds)
            raw=self.frame(request['nonce'],paths,bodies)
            f.clock[0]=1008.0
            return SimpleNamespace(data=raw[:-1] if partial else raw, termination_confirmed=True)
        return bodies,supervise

    def test_one_owned_acquisition_cleanup_then_four_once_issued_observations(self):
        cohort=self.required('OwnedProjectTemplateReadCohort')
        with self.issuance_fixture(project_auth=True) as f:
            bodies,supervise=self.reply(f)
            with mock.patch.object(f.module,'supervise_owned_attempt',side_effect=supervise):
                unit=cohort(f.writer,f.owner,f.binding,f.authentication)
                results=unit.read_once()
            self.assertEqual(bodies,tuple(result.data for result in results))
            self.assertEqual(1,len(f.launches));self.assertEqual(1,len(f.supervision))
            self.assertEqual((1000.0,'read'),(f.supervision[0]['started_monotonic'],f.supervision[0]['kind']))
            self.assertEqual([('stdin',False,False),('stdout',False,False),('stderr',False,False)],f.closes)
            for kind,result in zip(self.kinds,results):
                self.assertEqual(1071.0,f.module._READS[result][-1])
                self.assertIs(f.authentication,f.module._PROJECT_READS[result])
                f.module.require_current_owned_project_read(f.writer,f.owner,f.binding,result,f.authentication,read_kind=kind)
                self.assertEqual(1071.0,f.module._READS[result][-1])
            packets=tuple(f.module._READS[result] for result in results)
            group=tuple((kind,None,None,result) for kind,result in zip(self.kinds,results))
            f.clock[0]=1070.0
            for _ in range(2):
                f.module._require_current_owned_project_read_group(
                    f.writer,f.owner,f.binding,f.authentication,group)
                for result,packet in zip(results,packets):
                    self.assertIs(packet,f.module._READS[result])
                    self.assertEqual(1071.0,packet[-1])
            with self.assertRaises(f.module.HistoryReadLauncherHold):unit.read_once()
            self.assertEqual(1,len(f.launches))
            f.clock[0]=1071.0
            for kind,result in zip(self.kinds,results):
                with self.assertRaises(f.module.HistoryReadLauncherHold):
                    f.module.require_current_owned_read(f.writer,f.owner,f.binding,result,read_kind=kind)
            with self.assertRaises(f.module.HistoryReadLauncherHold):
                f.module._require_current_owned_project_read_group(
                    f.writer,f.owner,f.binding,f.authentication,group)
            self.assertEqual((30.0,60.0),(f.module._BUDGETS['read'],f.module._BUDGETS['mutation']))

    def test_partial_final_response_or_final_owner_fault_issues_nothing(self):
        cohort=self.required('OwnedProjectTemplateReadCohort')
        for fault in ('partial','target','token','acquisition_deadline'):
            with self.subTest(fault=fault),self.issuance_fixture(project_auth=True,
                    final_fault=None if fault=='partial' else fault) as f:
                before=set(f.module._READS);before_auth=set(f.module._PROJECT_READS)
                _bodies,supervise=self.reply(f,partial=fault=='partial')
                with mock.patch.object(f.module,'supervise_owned_attempt',side_effect=supervise):
                    unit=cohort(f.writer,f.owner,f.binding,f.authentication)
                    with self.assertRaises(f.module.HistoryReadLauncherHold):unit.read_once()
                    with self.assertRaises(f.module.HistoryReadLauncherHold):unit.read_once()
                self.assertEqual(before,set(f.module._READS));self.assertEqual(before_auth,set(f.module._PROJECT_READS))
                self.assertEqual(1,len(f.launches))
                self.assertTrue(all(getattr(f.process,name).closed for name in ('stdin','stdout','stderr')))

    def test_interrupted_second_registration_retracts_the_entire_cohort(self):
        cohort=self.required('OwnedProjectTemplateReadCohort')
        primary=KeyboardInterrupt('literal direct control')
        with self.issuance_fixture(project_auth=True) as f:
            _bodies,supervise=self.reply(f)
            class Registry(dict):
                def __setitem__(self,key,value):
                    if len(self)==1:raise primary
                    return super().__setitem__(key,value)
            registry=Registry();auth_registry={}
            with mock.patch.object(f.module,'supervise_owned_attempt',side_effect=supervise), \
                    mock.patch.object(f.module,'_READS',registry),mock.patch.object(f.module,'_PROJECT_READS',auth_registry):
                unit=cohort(f.writer,f.owner,f.binding,f.authentication)
                with self.assertRaises(KeyboardInterrupt) as caught:unit.read_once()
                self.assertIs(primary,caught.exception)
                self.assertEqual({},registry);self.assertEqual({},auth_registry)
                with self.assertRaises(f.module.HistoryReadLauncherHold):unit.read_once()


if __name__=='__main__': unittest.main()
