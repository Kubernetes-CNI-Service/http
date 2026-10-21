"""Independent owner/source-custody contracts; never SDK or send permission."""
from contextlib import ExitStack,contextmanager
import errno,fcntl,json,os,sys,unittest
from unittest import mock
from test_cases import completed_collection_source_read_fixture as completed
from test_cases import issue_tracker_cable_post_c6_fixture as old
from test_cases.test_req7_spreadsheet_owner import scoped_fixture

KEYS=sorted([['eth_cabling','leaf-a','swp1','Mis-wiring'],
 ['ib_cabling','leaf01','sw1p1','Mis-wiring'],['switch','leaf-a','fan','PSU1/FAN1'],
 ['switch','nvsw01','asic_temp','ASIC1']])

class CableReadOwnerCoreTests(unittest.TestCase):
    @contextmanager
    def observed_owners(self,sheet):
        from monitor import issue_tracker_state_owner as state
        from monitor import issue_tracker_local_commit as local
        previous=sys.getprofile();tokens=[];order=[];errors=[]
        def observer(frame,event,value):
            if previous is not None:previous(frame,event,value)
            try:
                if event=='call' and frame.f_code is state.current_k.__code__ and frame.f_globals is state.current_k.__globals__:
                    token=frame.f_locals.get('token')
                    if token is not None:tokens.append(token)
                if event=='call' and frame.f_code is sheet._acquire.__code__ and frame.f_globals is sheet.__dict__:
                    active=[]
                    for token in tokens:
                        try:active.append(local._owner(token))
                        except local.LocalCommitHold:pass
                    order.append(bool(active))
            except BaseException as error:errors.append(type(error).__name__)
        sys.setprofile(observer)
        try:yield tokens,order,errors
        finally:sys.setprofile(previous)

    def healthy_source(self,runtime,reader,case):
        with runtime._hold_current_cable_cycle_source(reader,http_root=case.root) as source:
            source.verify();self.assertEqual('NO_SEND',source.outcome)
            self.assertEqual(old.TARGET,source.binding.spreadsheet_id)
            self.assertEqual(KEYS,sorted([list(row.activity_key) for row in (*source.changes.cabling,*source.changes.switch)]))
        with self.assertRaises(runtime.CableSourceHold):source.verify()
        print('OWNER_CORE_OLD_A_HEALTH='+json.dumps(dict(outcome='NO_SEND',keys=KEYS,revoked=True,no_SDK=True)),flush=True)

    def exercise(self,body):
        from monitor import issue_tracker_publish_runtime as runtime
        from monitor import issue_tracker_spreadsheet_owner as sheet
        def after(case,committed,artifacts,parent,events):
            self.assertEqual(-1,parent._lock_fd)
            self.assertEqual(('mark_success_return','exit_call','exit_return'),tuple(row[0] for row in events))
            locks=case.root/'var/lib/http-ztp-container/issue-tracker'
            locks.mkdir(parents=True,mode=0o700);locks.chmod(0o700)
            with old.fixed_inputs(self,case) as inputs,scoped_fixture(case.root,sheet):
                local_before=old.local_evidence(case,committed)
                with completed.GATE._hold_completed_source_read_lease(str(case.project),status_dir=case.root/'monitor/status') as lease:
                    reader=completed.WORKER.CompletedCollectionCycleReader(lease=lease)
                    # Actual old A health, before new capability assertion/fault.
                    self.healthy_source(runtime,reader,case)
                    core=getattr(runtime,'_hold_current_cable_read_owner_core',None)
                    self.assertTrue(callable(core),'MISSING_ACTUAL_CURRENT_SOURCE_DUAL_OWNER_CORE')
                    self.assertEqual({},sheet._ACTIVE)
                    body(runtime,core,reader,sheet,case,inputs)
                    lease.verify()
                self.assertEqual({},sheet._ACTIVE)
                self.assertEqual(local_before,old.local_evidence(case,committed))
                self.assertEqual((0,0),(inputs['network'].call_count,inputs['children'].call_count))
        completed.run_protected_after_parent_exit(self,after)

    def test_real_source_local_before_sheet_no_send_custody_and_revoke_without_reopen(self):
        from monitor import issue_tracker_local_commit as local
        def body(runtime,core,reader,sheet,case,inputs):
            start=len(inputs['opened']);handle=None;sheet_fds=()
            with self.observed_owners(sheet) as (tokens,order,errors):
                with core(reader,http_root=case.root) as handle:
                    self.assertEqual('NO_SEND',handle.outcome)
                    self.assertEqual(old.TARGET,handle.binding.spreadsheet_id)
                    self.assertEqual(KEYS,sorted([list(row.activity_key) for row in (*handle.changes.cabling,*handle.changes.switch)]))
                    handle.verify();handle.verify()
                    self.assertEqual([True],order,'SHEET_MUST_HAVE_AN_ACTUAL_ACTIVE_LOCAL_OWNER_FIRST')
                    self.assertEqual([],errors)
                    self.assertEqual(1,len(sheet._ACTIVE))
                    token,owner=next(iter(sheet._ACTIVE.items()))
                    self.assertIs(owner,sheet._validated_owner(token,handle.binding))
                    sheet_fds=owner.descriptors
                    self.assertTrue(all(not completed.fd_closed(fd) for fd in sheet_fds))
                    for name in ('credential_raw','credential','writer_token','sheet_token','verify_credential','sdk','transport'):
                        self.assertFalse(hasattr(handle,name),'NO_SEND_MUST_NOT_EXPORT_'+name)
                    opened=inputs['opened'][start:]
                    self.assertEqual(['issue-tracker-spreadsheet-whitelist.json','cre.json'],[name for name,fd,key in opened])
                    # An independently opened real OFD contends even in one process.
                    lock=case.root/'var/lib/http-ztp-container/issue-tracker'/owner.lock_name
                    contender=os.open(lock,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
                    try:
                        with self.assertRaises(BlockingIOError):fcntl.flock(contender,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    finally:os.close(contender)
                # First-result resource facts, before any reuse or fixture cleanup.
                self.assertTrue(all(completed.fd_closed(fd) for fd in sheet_fds))
                self.assertEqual({},sheet._ACTIVE)
                self.assertTrue(all(closed for name,closed in old.fds_closed(opened)))
                with self.assertRaises(runtime.CableSourceHold):handle.verify()
                for token in tokens:
                    with self.assertRaises(local.LocalCommitHold):local._owner(token)
            print('OWNER_CORE_CUSTODY_COMPLETE='+json.dumps(dict(sheet_closed=True,source_revoked=True,local_revoked=True,local_before_sheet=order,credential_acquisitions=1,no_SDK=True)),flush=True)
        self.exercise(body)

    def test_same_byte_original_rebinding_is_sticky_and_keeps_local_receipt_and_known_cleanup(self):
        for role in ('cre','allow','global'):
            with self.subTest(role=role):
                def body(runtime,core,reader,sheet,case,inputs):
                    # New core health must succeed before this literal fault.
                    with core(reader,http_root=case.root) as healthy:
                        healthy.verify();self.assertEqual('NO_SEND',healthy.outcome)
                    start=len(inputs['opened']);handle=None;sheet_fds=()
                    with self.assertRaises(runtime.CableSourceHold):
                        with core(reader,http_root=case.root) as handle:
                            handle.verify();self.assertEqual(1,len(sheet._ACTIVE))
                            _token,owner=next(iter(sheet._ACTIVE.items()));sheet_fds=owner.descriptors
                            path=case.project/'01-global.yaml' if role=='global' else inputs[role]
                            before,after,raw,saved=old.rebind(path)
                            self.assertNotEqual(before,after);self.assertEqual(raw,path.read_bytes());self.assertEqual(raw,saved.read_bytes())
                            for attempt in (1,2):
                                with self.assertRaises(runtime.CableSourceHold):handle.verify()
                    self.assertTrue(all(completed.fd_closed(fd) for fd in sheet_fds))
                    self.assertEqual({},sheet._ACTIVE)
                    self.assertTrue(all(closed for name,closed in old.fds_closed(inputs['opened'][start:])))
                    with self.assertRaises(runtime.CableSourceHold):handle.verify()
                    print('OWNER_CORE_REBIND_REFUSED='+json.dumps(dict(role=role,same_bytes_new_inode=True,known_cleanup=True,sticky=True,no_SDK=True)),flush=True)
                self.exercise(body)
