"""Independent cooperative dispatch contract; no external network/devices."""

# NEW canonical test-header binding; original named bodies below are unchanged.
import unittest as _ibsw225_unittest
from test_cases.ibsw225_fixture_support.runtime_source_support import support as _ibsw225_support
_ibsw225_runtime = _ibsw225_support(_ibsw225_unittest.TestCase())
from test_cases.ibsw225_fixture_support.fixed_fixture_registry import install_fixed_fixtures as _ibsw225_install_fixed_fixtures
_ibsw225_fixed_fixture_modules = _ibsw225_install_fixed_fixtures()

import errno
import contextlib
import io
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import ibsw_upgrade_pipeline as pipeline


class LimitsAndStabilityTests(unittest.TestCase):
    def test_independently_specified_two_pool_limits(self):
        for n, upgrade, verify in ((0,0,0),(1,1,1),(2,1,1),(3,2,1),
                                  (9,5,2),(18,9,3),(32,16,4),(63,32,8),(192,32,8)):
            with self.subTest(n=n):
                self.assertEqual(pipeline.worker_limits(n),(upgrade,verify))

    def test_preboot_ssh_cannot_start_service_readiness_and_new_boot_does_not_wait_120(self):
        gate=pipeline.BootStability('00000000-0000-0000-0000-020000000001')
        self.assertEqual(gate.observe('00000000-0000-0000-0000-020000000001',10),'WAIT_BOOT')
        self.assertIsNone(gate.epoch)
        self.assertEqual(gate.observe('00000000-0000-0000-0000-020000000002',20),'READY')
        self.assertEqual(gate.epoch,'00000000-0000-0000-0000-020000000002')

    def test_another_actual_boot_requires_new_service_readiness_not_a_timer(self):
        gate=pipeline.BootStability('00000000-0000-0000-0000-020000000001')
        gate.observe('00000000-0000-0000-0000-020000000002',10)
        self.assertEqual(gate.observe('00000000-0000-0000-0000-020000000003',125),'READY')
        self.assertEqual(gate.epoch,'00000000-0000-0000-0000-020000000003')

    def test_wait_queue_is_due_ordered_and_deduplicates_devices(self):
        q=pipeline.WaitingQueue()
        q.put('A',100,'AUTH')
        q.put('B',10,'AUTH')
        q.put('A',120,'VERIFY')
        self.assertEqual(q.pop_due(10),('B','AUTH'))
        self.assertIsNone(q.pop_due(100))
        self.assertEqual(q.pop_due(120),('A','VERIFY'))
        self.assertIsNone(q.pop_due(999))


class ParentTCPTests(unittest.TestCase):
    def test_parent_probe_is_nonblocking_and_does_not_authenticate(self):
        connection=SimpleNamespace(setblocking=lambda value:self.assertFalse(value),
            connect_ex=lambda endpoint:errno.EINPROGRESS,
            getsockopt=lambda *a:0,close=lambda:closed.append(True))
        registered=[]
        selector=SimpleNamespace(register=lambda conn,events,data:registered.append(data),
            unregister=lambda conn:None,close=lambda:None,
            select=lambda timeout:[(SimpleNamespace(data=registered[0]),1)])
        closed=[]
        job=SimpleNamespace(address='192.0.2.10',deadline=100)
        with patch.object(pipeline.socket,'socket',return_value=connection), \
             patch.object(pipeline.selectors,'DefaultSelector',return_value=selector), \
             patch.object(pipeline,'_now',return_value=0):
            probes=pipeline.ParentTCPProbes()
            probes.request(job)
            self.assertEqual(probes.poll(),[(job,True)])
            self.assertEqual(probes.pending,{})
            probes.close()
        self.assertEqual(len(closed),1)
        self.assertFalse(hasattr(job,'boot'))

    def test_tcp_timeout_closes_socket_and_returns_not_ready(self):
        closed=[]
        connection=SimpleNamespace(setblocking=lambda value:None,connect_ex=lambda endpoint:errno.EINPROGRESS,
                                   close=lambda:closed.append(True))
        selector=SimpleNamespace(register=lambda *a,**k:None,unregister=lambda *a:None,
                                 select=lambda timeout:[],close=lambda:None)
        clock=SimpleNamespace(now=0)
        job=SimpleNamespace(address='192.0.2.10',deadline=20)
        with patch.object(pipeline.socket,'socket',return_value=connection), \
             patch.object(pipeline.selectors,'DefaultSelector',return_value=selector), \
             patch.object(pipeline,'_now',lambda:clock.now):
            probes=pipeline.ParentTCPProbes(); probes.request(job)
            clock.now=10
            self.assertEqual(probes.poll(),[(job,False)])
            probes.close()
        self.assertEqual(len(closed),1)


class CollectorDiagnosticsTests(unittest.TestCase):
    def test_native_sftp_exception_is_not_leaked_or_collapsed_to_generic(self):
        import ibsw_upgrade_executor as executor
        from ibsw_upgrade_observer import _NativeObservationHold
        from test_manual_execution import MemorySFTP
        remote=MemorySFTP()
        remote.modes['/home/admin/private']=0o40700
        remote.modes['/home/admin/private/owned-exit.record']=0o100644
        remote.files['/home/admin/private/owned-exit.record']=b'x'
        leaf=SimpleNamespace(verify=lambda:None)
        with patch.object(executor,'_verify_component_leaf'),self.assertRaises(_NativeObservationHold) as captured:
            executor._read_stable_component_file(leaf,remote,'/home/admin/private/owned-exit.record',1000,10**15,512,nonempty=True)
        self.assertEqual(captured.exception.reason_code,'COMPONENT_FILE_UNSAFE')
        self.assertEqual(captured.exception.capture_raw['safe_diagnostic']['file'],'owned-exit.record')
        self.assertNotIn('SYNTHETIC-SECRET',str(captured.exception))

    def test_no_retry_is_authorized_by_missing_exit_evidence(self):
        gate=pipeline.BootStability('00000000-0000-0000-0000-020000000001')
        gate.observe('00000000-0000-0000-0000-020000000002',0)
        self.assertEqual(gate.observe('00000000-0000-0000-0000-020000000002',120),'READY')
        # Readiness is only a scheduling stage, never installation success.
        self.assertFalse(hasattr(gate,'verified'))


class CooperativeQueueTests(unittest.TestCase):
    def run_case(self,*,count=9,deadline=1800,fail=False,unknown_active=False,skip=False):
        clock=SimpleNamespace(now=1000.0)
        events=[]
        barrier=threading.Barrier(8 if count==64 else 2)
        probe_peaks=SimpleNamespace(active=0,peak=0)
        lock=threading.Lock()
        class Probes:
            def __init__(self): self.pending={}
            def poll(self): return []
            def close(self): pass
        class Adapter:
            def verify(self): pass
            def choose_canary(self,component,names): return names[0] if names else None
            def requires_flash(self,*a): return True
            def blocked(self,name,component,reason): events.append(('BLOCK',name,clock.now,reason))
            def begin(self,name,component,canary,stop):
                events.append(('BEGIN',name,clock.now,threading.current_thread().name))
                job=SimpleNamespace(name=name,component=component,address='192.0.2.1',phase='AUTH',
                    deadline=clock.now+deadline,boot=None,remote_may_be_active=unknown_active)
                job.close=lambda:events.append(('CLOSE',name,clock.now,''))
                return job,pipeline.Event('WAIT',clock.now,'AUTH')
            def advance(self,job):
                with lock:
                    probe_peaks.active+=1; probe_peaks.peak=max(probe_peaks.peak,probe_peaks.active)
                try:
                    events.append(('VERIFY',job.name,clock.now,threading.current_thread().name))
                    first_wave=tuple(f'ib{i}' for i in range(1,9 if count==64 else 3))
                    if count in (9,64) and job.name in first_wave and job.boot is None:
                        barrier.wait(3)
                    if job.boot is None:
                        job.boot=SimpleNamespace(until=clock.now+120)
                        return pipeline.Event('WAIT',job.boot.until,'AUTH')
                    self_test.assertGreaterEqual(clock.now,job.boot.until)
                    state='UNKNOWN' if unknown_active else 'FAIL' if fail and job.name=='ib0' else 'COMPLETE'
                    events.append(('RESULT',job.name,clock.now,state))
                    return pipeline.Event('FINISHED',row=dict(hostname=job.name,component=job.component,state=state,
                        action='UPGRADE_PERFORMED_AND_VERIFIED'))
                finally:
                    with lock: probe_peaks.active-=1
            def abort(self,job,reason):
                events.append(('ABORT',job.name,clock.now,reason))
                return pipeline.Event('FINISHED',row=dict(hostname=job.name,component=job.component,
                    state='UNKNOWN',reason=reason))
        self_test=self
        with patch.object(pipeline,'_now',lambda:clock.now), \
             patch.object(pipeline,'_idle',lambda seconds:setattr(clock,'now',clock.now+seconds)), \
             contextlib.redirect_stderr(io.StringIO()):
            result=pipeline.run_pipeline([f'ib{i}' for i in range(count)],('os',),Adapter(),
                probe_factory=Probes,skip_canary=skip)
        return result,events,probe_peaks

    def test_grace_releases_threads_and_canary_completes_before_peer_dispatch(self):
        result,events,peak=self.run_case()
        self.assertEqual(result['state'],'COMPLETE')
        self.assertEqual(result['workers'],5)
        self.assertEqual(result['verification_workers'],2)
        self.assertEqual(peak.peak,2)
        canary_end=next(t for kind,name,t,_ in events if kind=='RESULT' and name=='ib0')
        self.assertTrue(all(t>=canary_end for kind,name,t,_ in events if kind=='BEGIN' and name!='ib0'))
        self.assertTrue(all(thread.startswith('ib-upgrade') for kind,_,_,thread in events if kind=='BEGIN'))
        self.assertTrue(all(thread.startswith('ib-verify') for kind,_,_,thread in events if kind=='VERIFY'))
        self.assertEqual(len([1 for kind,_,_,_ in events if kind=='BEGIN']),9)

    def test_stabilization_does_not_extend_original_deadline(self):
        result,events,_=self.run_case(count=1,deadline=100)
        self.assertEqual(result['targets'][0]['state'],'UNKNOWN')
        self.assertFalse(any(kind=='RESULT' for kind,_,_,_ in events))
        self.assertEqual(next(t for kind,_,t,_ in events if kind=='ABORT'),1100)

    def test_failed_canary_never_releases_other_installers(self):
        result,events,_=self.run_case(count=2,fail=True)
        self.assertEqual([name for kind,name,_,_ in events if kind=='BEGIN'],['ib0'])
        self.assertEqual(result['targets'][1]['state'],'BLOCKED_CANARY')

    def test_unknown_remote_installer_retains_capacity_without_resend(self):
        result,events,_=self.run_case(count=2,unknown_active=True,skip=True)
        self.assertEqual([name for kind,name,_,_ in events if kind=='BEGIN'],['ib0'])
        self.assertEqual(result['targets'][1]['state'],'NOT_EXECUTED')
        self.assertEqual(result['unresolved_in_flight'],['ib0'])

    def test_zero_devices_do_not_submit_any_tasks(self):
        result,events,_=self.run_case(count=0)
        self.assertEqual(events,[])
        self.assertEqual((result['workers'],result['verification_workers']),(0,0))

    def test_real_verification_pool_reaches_but_never_exceeds_eight_threads(self):
        result,events,peak=self.run_case(count=64)
        self.assertEqual(result['state'],'COMPLETE')
        self.assertEqual((result['workers'],result['verification_workers']),(32,8))
        self.assertEqual(peak.peak,8)


if __name__=='__main__':
    unittest.main()
