"""C23 retry shares actual local admission and durable original count.

Owned C6/locks/counter are real; collector completion and clock are fixtures.
This necessary cadence workflow is not protected C5 or online GO evidence.
"""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

from tools.project_contract import MIN_CONTINUOUS_INTERVAL_MINUTES

FLOOR_NS=MIN_CONTINUOUS_INTERVAL_MINUTES*60*1_000_000_000


class SharedRetryAdmissionDirectTests(unittest.TestCase):
    def test_retry_uses_same_floor_and_resets_shared_cycle_anchor_without_n_gate(self):
        from monitor import issue_tracker_admission as admission
        cycles=('one','two','three','four','five')
        event=lambda lane,cycle,now:dict(lane=lane,cycle_id=cycle,publish_every_cycles=2,
                                         boot_id='owned-boot',monotonic_ns=now)
        first=event('automatic','two',1)
        retry=event('retry','three',1+FLOOR_NS)
        self.assertTrue(admission.assess_shared_admission_step(first,retry,cycles))
        with self.assertRaises(admission.AdmissionCollectorAnomaly):
            admission.assess_shared_admission_step(first,{**retry,'monotonic_ns':FLOOR_NS},cycles)
        with self.assertRaises(admission.AdmissionHold):
            admission.assess_shared_admission_step(retry,event('automatic','four',1+2*FLOOR_NS),cycles)
        self.assertTrue(admission.assess_shared_admission_step(retry,event('automatic','five',1+2*FLOOR_NS),cycles))
        with self.assertRaises(admission.AdmissionHold):
            admission.assess_shared_admission_step(retry,{**retry,'boot_id':'foreign-boot','monotonic_ns':1+2*FLOOR_NS},cycles)

    def test_missing_owners_cannot_create_retry_record_or_count(self):
        from monitor import issue_tracker_admission as admission
        self.assertTrue(hasattr(admission,'_hold_shared_retry_opportunity'),'durable shared retry admission missing')
        with mock.patch.object(admission,'_mkdir') as creating:
            with self.assertRaises(admission.AdmissionHold):
                with admission._hold_shared_retry_opportunity(None,None,None,None,None,None,
                                                              boot_id='owned-boot',monotonic_ns=1): self.fail('forged owner')
            creating.assert_not_called()

    def test_shared_retry_counter_refuses_forged_live_reads_before_any_admission_write(self):
        from monitor import issue_tracker_global_attempt_journal as journal, issue_tracker_admission as admission
        self.assertTrue(hasattr(journal,'record_shared_retry_continuous_owned_attempt_intent'),
                        'protected continuity must dominate the shared retry count')
        with mock.patch.object(admission,'_write_new') as writing:
            with self.assertRaises(journal.GlobalAttemptHold):
                journal.record_shared_retry_continuous_owned_attempt_intent(None,None,None,
                    boot_id='owned-boot',monotonic_ns=1,writer_token=None,identity_response=None,
                    history_response=None,business_reads=(),qualified_source=None,store=None,settings=None,
                    whitelist_snapshot=None,expected_template_sha256='a'*64,http_root=None,whitelist_path=None,
                    headers_response=None,whitelist_response=None,metadata_response=None)
            writing.assert_not_called()


class SharedRetryAdmissionWorkflowTests(unittest.TestCase):
    from test_cases.test_req7_native_tls_wire import Req7NativeTlsWireTests as native
    setUp=native.setUp

    def owned(self,stack):
        from test_cases.test_req7_history_read_launcher import Req7HistoryReadLauncherWorkflowTests as reads
        from test_cases.test_req7_send_unit import load as load_unit, inputs, TARGET
        from monitor import issue_tracker_admission as admission, issue_tracker_global_attempt_journal as journal
        local,ownership,writer,owner,target,_token,_config=reads.owners(self,stack,target_id=TARGET)
        cycle=SimpleNamespace(qualifying=True,cycle_id='actual-owned-cycle',completion_sha256='a'*64,
                              project_key='owned-project',scope='prod')
        store=SimpleNamespace(project_key='owned-project',scope='prod')
        stack.enter_context(mock.patch.object(admission,'read_completed_cycle_evidence',return_value=(cycle,)))
        start=FLOOR_NS*10
        clock=SimpleNamespace(monotonic_ns=lambda:start)
        stack.enter_context(mock.patch.object(admission,'time',clock))
        policy=admission.local_publish_interval(local._owner(writer).project)
        prepared=admission.prepare_shared_local_admission(writer,store,None,lane='manual',
            policy_sha256=policy[1],publish_every_cycles=policy[0],boot_id='owned-boot',monotonic_ns=start)
        generation=local.begin_generation(writer,local._canonical({'schema_version':1,'fixture':'C6 cadence only, not C5'}))
        image=b'actual immutable owned publication bytes'
        local.record_intent(writer,generation,image); receipt=local.commit(writer,generation)
        admission.record_shared_local_admission(writer,generation.generation_id,receipt.published_sha256,prepared)
        arguments=inputs(); arguments.update(generation_id=generation.generation_id,publish_id=receipt.published_sha256)
        unit=load_unit().freeze_send_unit(**arguments)
        journal.prepare_global_unit(owner,target,unit); journal.record_global_attempt_intent(owner,target,unit)
        return admission,local,journal,writer,owner,target,unit,store,image,start,clock

    def test_actual_retry_count_advances_shared_anchor_and_blocks_manual_and_auto_before_floor(self):
        with ExitStack() as stack:
            admission,local,journal,writer,owner,target,unit,store,image,start,clock=self.owned(stack)
            self.assertTrue(hasattr(admission,'_hold_shared_retry_opportunity'),'shared retry context missing')
            clock.monotonic_ns=lambda:start+FLOOR_NS-1
            with self.assertRaises(admission.AdmissionCollectorAnomaly):
                with admission._hold_shared_retry_opportunity(writer,owner,target,unit,store,image,
                    boot_id='owned-boot',monotonic_ns=start+FLOOR_NS-1): self.fail('subfloor')
            self.assertEqual(1,journal.inspect_global_unit(owner,target,unit).attempt_count)
            clock.monotonic_ns=lambda:start+FLOOR_NS
            with admission._hold_shared_retry_opportunity(writer,owner,target,unit,store,image,
                    boot_id='owned-boot',monotonic_ns=start+FLOOR_NS):
                self.assertEqual(2,journal.record_global_attempt_intent(owner,target,unit).attempt_count)
            prior=admission.read_shared_local_admission(writer,store,image)
            self.assertEqual(('retry',start+FLOOR_NS), (prior['lane'],prior['monotonic_ns']))
            for lane in ('manual','automatic'):
                with self.assertRaises(admission.AdmissionHold):
                    admission.prepare_shared_local_admission(writer,store,prior,lane=lane,
                        policy_sha256=target.policy_sha256,publish_every_cycles=1,
                        boot_id='owned-boot',monotonic_ns=start+2*FLOOR_NS-1)
            with self.assertRaises(admission.AdmissionHold):
                with admission._hold_shared_retry_opportunity(writer,owner,target,unit,store,image,
                    boot_id='foreign-boot',monotonic_ns=start+2*FLOOR_NS): self.fail('unproved restart')
            self.assertEqual(2,journal.inspect_global_unit(owner,target,unit).attempt_count)
            # A later local publication uses the same retry anchor, not a
            # separate additive limiter. Manual may use the same actual cycle.
            next_event=admission.prepare_shared_local_admission(writer,store,prior,lane='manual',
                policy_sha256=target.policy_sha256,publish_every_cycles=1,
                boot_id='owned-boot',monotonic_ns=start+2*FLOOR_NS)
            self.assertEqual(2,next_event['sequence'])

    def test_interrupted_retry_admission_remains_terminal_without_counter_reset_or_repair(self):
        with ExitStack() as stack:
            admission,local,journal,writer,owner,target,unit,store,image,start,clock=self.owned(stack)
            self.assertTrue(hasattr(admission,'_hold_shared_retry_opportunity'))
            clock.monotonic_ns=lambda:start+FLOOR_NS
            with self.assertRaises(admission.AdmissionHold):
                with admission._hold_shared_retry_opportunity(writer,owner,target,unit,store,image,
                        boot_id='owned-boot',monotonic_ns=start+FLOOR_NS):
                    raise OSError('owned interruption before original count')
            retained={p.name:p.read_bytes() for p in (self.root/'project/.tracker/admissions').iterdir()}
            with self.assertRaises(admission.AdmissionHold): admission.read_shared_local_admission(writer,store,image)
            clock.monotonic_ns=lambda:start+2*FLOOR_NS
            with self.assertRaises(admission.AdmissionHold):
                with admission._hold_shared_retry_opportunity(writer,owner,target,unit,store,image,
                    boot_id='owned-boot',monotonic_ns=start+2*FLOOR_NS): self.fail('orphan adopted')
            self.assertEqual(retained,{p.name:p.read_bytes() for p in (self.root/'project/.tracker/admissions').iterdir()})
            self.assertEqual((1,'UNKNOWN'),(journal.inspect_global_unit(owner,target,unit).attempt_count,journal.inspect_global_unit(owner,target,unit).outcome))

    def test_retry_records_do_not_become_new_local_receipt_events(self):
        from monitor.issue_tracker_receipt_snapshot import _events
        with ExitStack() as stack:
            admission,local,journal,writer,owner,target,unit,store,image,start,clock=self.owned(stack)
            original=_events(local._owner(writer)); self.assertEqual(1,len(original))
            clock.monotonic_ns=lambda:start+FLOOR_NS
            with admission._hold_shared_retry_opportunity(writer,owner,target,unit,store,image,
                    boot_id='owned-boot',monotonic_ns=start+FLOOR_NS):
                journal.record_global_attempt_intent(owner,target,unit)
            self.assertEqual(original,_events(local._owner(writer)))

    def test_retry_stamps_actual_admission_clock_not_the_callers_earlier_probe(self):
        with ExitStack() as stack:
            admission,local,journal,writer,owner,target,unit,store,image,start,clock=self.owned(stack)
            clock.monotonic_ns=lambda:start+2*FLOOR_NS
            with admission._hold_shared_retry_opportunity(writer,owner,target,unit,store,image,
                    boot_id='owned-boot',monotonic_ns=start+FLOOR_NS):
                journal.record_global_attempt_intent(owner,target,unit)
            self.assertEqual(start+2*FLOOR_NS,admission.read_shared_local_admission(writer,store,image)['monotonic_ns'])

    def test_retry_clock_is_sampled_after_policy_and_original_validation(self):
        with ExitStack() as stack:
            admission,local,journal,writer,owner,target,unit,store,image,start,clock=self.owned(stack)
            clock.monotonic_ns=lambda:start+FLOOR_NS
            read_policy=admission.local_publish_interval
            def policy_finished(project):
                result=read_policy(project)
                clock.monotonic_ns=lambda:start+2*FLOOR_NS
                return result
            with mock.patch.object(admission,'local_publish_interval',side_effect=policy_finished):
                with admission._hold_shared_retry_opportunity(writer,owner,target,unit,store,image,
                        boot_id='owned-boot',monotonic_ns=start+FLOOR_NS):
                    journal.record_global_attempt_intent(owner,target,unit)
            self.assertEqual(start+2*FLOOR_NS,admission.read_shared_local_admission(writer,store,image)['monotonic_ns'])

    def test_identical_admission_bytes_in_displaced_directory_are_not_adopted_during_read(self):
        with ExitStack() as stack:
            admission,local,journal,writer,owner,target,unit,store,image,start,clock=self.owned(stack)
            directory=admission._directory; calls=[]
            def opening(parent,name,*args,**kwargs):
                if name=='admissions':
                    calls.append(name)
                    if len(calls)==2:
                        current=self.root/'project/.tracker/admissions'
                        retained={p.name:p.read_bytes() for p in current.iterdir()}
                        current.rename(self.root/'preserved-original-admissions')
                        current.mkdir(mode=0o700)
                        for entry,raw in retained.items():
                            path=current/entry; path.write_bytes(raw); path.chmod(0o600)
                return directory(parent,name,*args,**kwargs)
            with mock.patch.object(admission,'_directory',side_effect=opening):
                with self.assertRaises(admission.AdmissionHold): admission.read_shared_local_admission(writer,store,image)
            self.assertEqual(2,len(calls)); self.assertEqual(1,journal.inspect_global_unit(owner,target,unit).attempt_count)

    def test_admission_directory_displaced_after_read_cannot_reach_original_count(self):
        with ExitStack() as stack:
            admission,local,journal,writer,owner,target,unit,store,image,start,clock=self.owned(stack)
            clock.monotonic_ns=lambda:start+FLOOR_NS
            read_policy=admission.local_publish_interval; displaced=[]
            def policy_after_read(project):
                result=read_policy(project)
                if not displaced:
                    current=self.root/'project/.tracker/admissions'
                    retained={p.name:p.read_bytes() for p in current.iterdir()}
                    current.rename(self.root/'preserved-admissions-before-count')
                    current.mkdir(mode=0o700)
                    for name,raw in retained.items():
                        path=current/name; path.write_bytes(raw); path.chmod(0o600)
                    displaced.append(True)
                return result
            with mock.patch.object(admission,'local_publish_interval',side_effect=policy_after_read):
                with self.assertRaises(admission.AdmissionHold):
                    with admission._hold_shared_retry_opportunity(writer,owner,target,unit,store,image,
                            boot_id='owned-boot',monotonic_ns=start+FLOOR_NS):
                        self.fail('displaced directory reached original counter scope')
            self.assertEqual([True],displaced)
            self.assertEqual(1,journal.inspect_global_unit(owner,target,unit).attempt_count)
            self.assertEqual({'admission-00000000000000000001.json'},
                {p.name for p in (self.root/'project/.tracker/admissions').iterdir()})

    def test_retry_and_next_real_c6_publication_share_one_floor_without_counting_retry_as_c6(self):
        from monitor.issue_tracker_receipt_snapshot import _events
        with ExitStack() as stack:
            admission,local,journal,writer,owner,target,unit,store,image,start,clock=self.owned(stack)
            clock.monotonic_ns=lambda:start+FLOOR_NS
            with admission._hold_shared_retry_opportunity(writer,owner,target,unit,store,image,
                    boot_id='owned-boot',monotonic_ns=start+FLOOR_NS): journal.record_global_attempt_intent(owner,target,unit)
            prior=admission.read_shared_local_admission(writer,store,image)
            clock.monotonic_ns=lambda:start+2*FLOOR_NS
            next_event=admission.prepare_shared_local_admission(writer,store,prior,lane='manual',
                policy_sha256=prior['policy_sha256'],publish_every_cycles=prior['publish_every_cycles'],
                boot_id='owned-boot',monotonic_ns=start+2*FLOOR_NS)
            generation=local.begin_generation(writer,local._canonical({'schema_version':1,'fixture':'next owned C6'}))
            changed=b'actual next immutable publication'
            local.record_intent(writer,generation,changed); receipt=local.commit(writer,generation)
            admission.record_shared_local_admission(writer,generation.generation_id,receipt.published_sha256,next_event)
            latest=admission.read_shared_local_admission(writer,store,changed)
            self.assertEqual(('manual',start+2*FLOOR_NS),(latest['lane'],latest['monotonic_ns']))
            self.assertEqual(2,len(_events(local._owner(writer))))
            self.assertEqual(2,journal.inspect_global_unit(owner,target,unit).attempt_count)

    def test_retry_chain_keeps_original_bytes_and_six_total_counts_then_exhausts(self):
        with ExitStack() as stack:
            admission,local,journal,writer,owner,target,unit,store,image,start,clock=self.owned(stack)
            self.assertTrue(hasattr(admission,'_hold_shared_retry_opportunity'))
            for count in range(2,7):
                now=start+(count-1)*FLOOR_NS; clock.monotonic_ns=lambda:now
                with admission._hold_shared_retry_opportunity(writer,owner,target,unit,store,image,
                        boot_id='owned-boot',monotonic_ns=now):
                    self.assertEqual(count,journal.record_global_attempt_intent(owner,target,unit).attempt_count)
            retained={p.name:p.read_bytes() for p in (self.root/'project/.tracker/admissions').iterdir()}
            with self.assertRaises(admission.AdmissionHold):
                with admission._hold_shared_retry_opportunity(writer,owner,target,unit,store,image,
                    boot_id='owned-boot',monotonic_ns=start+6*FLOOR_NS): self.fail('seventh attempt')
            self.assertEqual(retained,{p.name:p.read_bytes() for p in (self.root/'project/.tracker/admissions').iterdir()})
            self.assertEqual(start+5*FLOOR_NS,admission.read_shared_local_admission(writer,store,image)['monotonic_ns'])
            self.assertEqual(6,journal.inspect_global_unit(owner,target,unit).attempt_count)
            original=self.root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(target.spreadsheet_id.encode()).hexdigest()+'.journal')
            self.assertEqual(unit.wire_bytes,(original/'WIRE').read_bytes())
            self.assertEqual(unit.action_preimage,(original/'ACTION-PREIMAGE').read_bytes())
