"""Independent timing/reader/transaction regressions. No real network or devices."""
import contextlib
import io
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_upgrade_cli as fixtures
import test_known_hosts as trust
import test_access_recovery as access
import test_three_component_workflow as native
import test_grouped_summary as summaries
import ibsw_upgrade_observer as observer
import ibsw_upgrade_executor as executor
from ibsw_upgrade_contract import SharedUpgradeHold, record_readonly_query

app, driver = fixtures.app, fixtures.driver


class Channel:
    """Exercise the production reader, not a replacement _read_channel."""
    def __init__(self, payload=b'answer\n', stderr=b'', status=0, on_exec=None, delayed=0):
        self.output, self.error, self.status = payload, stderr, status
        self.closed = self.eof_received = False
        self.on_exec, self.delayed = on_exec, delayed
        self.closed_count = 0
    def settimeout(self, value): self.timeout = value
    def exec_command(self, command):
        self.command = command
        if self.on_exec: self.on_exec(command)
        self.closed, self.eof_received = not self.delayed, True
    def recv_ready(self):
        if self.delayed:
            self.delayed -= 1
            if not self.delayed: self.closed = True
            return False
        return bool(self.output)
    def recv(self, size): result, self.output = self.output[:size], self.output[size:]; return result
    def recv_stderr_ready(self): return bool(self.error)
    def recv_stderr(self, size): result, self.error = self.error[:size], self.error[size:]; return result
    def exit_status_ready(self): return self.status is not None
    def recv_exit_status(self): return self.status
    def close(self): self.closed_count += 1; self.closed = True


class ReaderDirectTests(unittest.TestCase):
    def test_polling_does_not_repeat_full_content_verification(self):
        counts = dict(full=0, fast=0)
        leaf = SimpleNamespace(
            verify=lambda: counts.__setitem__('full', counts['full']+1),
            verify_io_identity=lambda: counts.__setitem__('fast', counts['fast']+1))
        channel = Channel(delayed=12)
        transport = SimpleNamespace(open_session=lambda **kw: channel, is_active=lambda: True)
        with patch.object(observer.time, 'sleep', return_value=None):
            result = observer._read_channel(leaf, transport, 'nv show system version', time.monotonic()+60)
        self.assertEqual(result, (b'answer\n', b'', 0, True))
        self.assertLessEqual(counts['full'], 4)
        self.assertGreater(counts['fast'], 5)
        self.assertEqual(channel.closed_count, 1)

    def test_shared_input_failure_cannot_become_device_query_failure(self):
        def changed(): raise SharedUpgradeHold('SYNTHETIC_SOURCE_CHANGED')
        leaf=SimpleNamespace(verify=lambda:None, verify_io_identity=changed)
        channel=Channel()
        transport=SimpleNamespace(open_session=lambda **kw:channel,is_active=lambda:True)
        with self.assertRaises(SharedUpgradeHold):
            observer._read_channel(leaf,transport,'nv show system version',time.monotonic()+30)
        self.assertEqual(channel.closed_count,1)

    def test_native_query_timeout_keeps_safe_phase_diagnostic(self):
        clock=SimpleNamespace(now=100.0)
        leaf=SimpleNamespace(verify=lambda:None,verify_io_identity=lambda:None)
        channel=Channel(on_exec=lambda command:setattr(clock,'now',126.0))
        transport=SimpleNamespace(open_session=lambda **kw:channel,is_active=lambda:True)
        with patch.object(observer.time,'monotonic',lambda:clock.now):
            result=observer._read_channel(leaf,transport,'nv show system version',220.0)
        self.assertFalse(result[3])
        self.assertEqual(leaf._last_query_diagnostic['reason_code'],'READONLY_QUERY_TIMEOUT')
        self.assertEqual(leaf._last_query_diagnostic['command'],'nv show system version')
        self.assertEqual(leaf._last_query_diagnostic['budget_seconds'],25.0)
        self.assertEqual(channel.closed_count,1)

    def test_result_arriving_after_wire_deadline_is_not_complete_even_with_exit_zero(self):
        clock=SimpleNamespace(now=100.0)
        class LateChannel(Channel):
            def recv(self,size):
                clock.now=126.0
                return super().recv(size)
        leaf=SimpleNamespace(verify=lambda:None,verify_io_identity=lambda:None)
        channel=LateChannel()
        transport=SimpleNamespace(open_session=lambda **kw:channel,is_active=lambda:True)
        with patch.object(observer.time,'monotonic',lambda:clock.now):
            result=observer._read_channel(leaf,transport,'nv show system version',220.0)
        self.assertFalse(result[3])
        self.assertEqual(leaf._last_query_diagnostic['reason_code'],'READONLY_QUERY_TIMEOUT')

    def test_changed_original_identity_during_drain_stops_batch_not_one_device(self):
        def changed(): raise ValueError('SYNTHETIC_ORIGINAL_FILE_CHANGED')
        leaf=SimpleNamespace(verify=lambda:None,verify_io_identity=changed)
        channel=Channel()
        transport=SimpleNamespace(open_session=lambda **kw:channel,is_active=lambda:True)
        with self.assertRaises(SharedUpgradeHold):
            observer._read_channel(leaf,transport,'nv show system version',time.monotonic()+30)
        self.assertEqual(channel.closed_count,1)

    def test_32_production_readers_keep_independent_channels_and_streams(self):
        barrier=threading.Barrier(32)
        def run(number):
            channel=Channel(payload=('node-%d\n'%number).encode(),on_exec=lambda cmd:barrier.wait(timeout=8))
            leaf=SimpleNamespace(verify=lambda:None,verify_io_identity=lambda:None)
            transport=SimpleNamespace(open_session=lambda **kw:channel,is_active=lambda:True)
            result=observer._read_channel(leaf,transport,'nv show system version',time.monotonic()+30)
            return number,result,channel.closed_count
        with ThreadPoolExecutor(max_workers=32) as pool: rows=list(pool.map(run,range(32)))
        self.assertEqual(len(rows),32)
        for number,result,closed in rows:
            self.assertEqual(result,(('node-%d\n'%number).encode(),b'',0,True))
            self.assertEqual(closed,1)


class BudgetWorkflowTests(unittest.TestCase):
    def test_connection_timeout_is_specific_but_shared_and_fd_faults_stop_batch(self):
        for failure,expected in ((TimeoutError('PRIVATE_NATIVE_TEXT'),observer._NativeObservationHold),
                                 (SharedUpgradeHold('SYNTHETIC_SHARED_FAULT'),SharedUpgradeHold),
                                 (OSError(24,'SYNTHETIC_FD_EXHAUSTED'),OSError)):
            with self.subTest(kind=type(failure).__name__),tempfile.TemporaryDirectory() as directory:
                project,home,known=fixtures.WorkflowTests().fixture(Path(directory).resolve())
                args=('--project',str(project),'--os-only')
                prepared=driver.prepare_manual_run(app.__file__,str(project),args)
                def fail(target): raise failure
                connection=SimpleNamespace(connect=fail,settimeout=lambda value:None,close=lambda:None)
                with driver.open_manual_run(app.__file__,str(project),args,prepared['run_directory']) as scope:
                    with scope.open_readonly_query_inputs(native.HOST,known_hosts_path=str(known),
                            identity_path=None,management_public_path=None) as leaf:
                        with patch.object(observer.socket,'socket',return_value=connection), \
                             patch.object(observer,'_fixed_sdk',return_value=SimpleNamespace()):
                            with self.assertRaises(expected) as caught:
                                leaf.observe_initial_plan_once(password='secret-value')
                        if isinstance(failure,TimeoutError):
                            self.assertEqual(caught.exception.reason_code,'SSH_CONNECT_TIMEOUT')
                            self.assertNotIn('PRIVATE',str(caught.exception))
                            self.assertNotIn('secret-value',str(caught.exception))

    def test_real_session_and_reader_get_fresh_command_budget_after_slow_login(self):
        clock=SimpleNamespace(now=100.0)
        channels=[]
        def step(seconds): clock.now+=seconds
        class Rejected(Exception): pass
        class Protocol(Exception): pass
        with tempfile.TemporaryDirectory() as directory:
            project,home,known=fixtures.WorkflowTests().fixture(Path(directory).resolve())
            access.install_pair(home)
            args=('--project',str(project),'--os-only')
            prepared=driver.prepare_manual_run(app.__file__,str(project),args)
            connection=SimpleNamespace(connect=lambda target:step(8),settimeout=lambda value:None,close=lambda:None)
            def open_channel(**kw):
                payload=(b'ew-spine01.example\n02:00:00:00:00:01\n' if not channels else
                         fixtures.OS_TABLE if len(channels)==1 else fixtures.HEALTH_TABLE)
                channel=Channel(payload=payload,on_exec=lambda command:step(3))
                channels.append(channel); return channel
            transport=SimpleNamespace(start_client=lambda **kw:step(8),
                get_remote_server_key=lambda:SimpleNamespace(asbytes=lambda:trust.WIRE),
                auth_password=lambda *a,**kw:step(8),is_authenticated=lambda:True,
                get_username=lambda:'admin',is_active=lambda:True,close=lambda:None,open_session=open_channel)
            sdk=SimpleNamespace(Transport=lambda connection:transport,AuthenticationException=Rejected,SSHException=Protocol)
            with driver.open_manual_run(app.__file__,str(project),args,prepared['run_directory']) as scope:
                with scope.open_readonly_query_inputs(native.HOST,known_hosts_path=str(known),
                    identity_path=str(home/'.ssh/id_ed25519'),management_public_path=str(home/'.ssh/id_ed25519.pub')) as leaf:
                    with patch.object(observer.time,'monotonic',lambda:clock.now), \
                         patch.object(observer.socket,'socket',return_value=connection), \
                         patch.object(observer,'_fixed_sdk',return_value=sdk):
                        result=leaf.observe_initial_plan_once(password='secret-value')
            self.assertEqual(result['initial_plan']['state'],'INITIAL_NATIVE_DATA_PLAN')
            self.assertEqual([c.command for c in channels],
                [observer._IDENTITY_COMMAND,'nv show system version','nv show system health'])
            self.assertGreaterEqual(channels[1].timeout,25.0)
            self.assertGreaterEqual(channels[2].timeout,25.0)
            self.assertGreater(clock.now-100,25)

    def test_remote_component_queries_do_not_hold_global_journal_transaction(self):
        original=executor._component_query
        barrier=threading.Barrier(2)
        visited=set()
        def query(leaf,*args,**kwargs):
            self.assertIsNone(leaf.scope._active_request_lease,'remote waits must not serialize other device journals')
            if leaf.node.hostname not in visited:
                visited.add(leaf.node.hostname); barrier.wait(timeout=8)
            return original(leaf,*args,**kwargs)
        with tempfile.TemporaryDirectory() as directory, patch.object(executor,'_component_query',query):
            code,report,err,calls,installs=native.ThreeComponentWorkflowTests().invoke(
                Path(directory).resolve(),skip_canary=True,selection=('--os-only',),
                os_branch_case={'currents':['25.02.8008']*4,'available':['25.03.1014']})
        self.assertEqual(code,0,err)
        self.assertEqual(len(installs),4)
        self.assertEqual(report['result'],'SUCCESS')


class PresentationAndHealthTests(unittest.TestCase):
    def test_health_na_is_specific_and_never_a_pass(self):
        baseline=record_readonly_query(('nv','show','system','health'),
            b'            operational  applied\n----------  -----------  -------\nstatus      OK\nstatus-led  green\nHealth Issues\n============\nNo Data\n',b'',0)
        unavailable=record_readonly_query(('nv','show','system','health'),
            b'        operational  applied\n------  -----------  -------\nstatus  N/A\nHealth Issues\n============\nNo Data\n',b'',0)
        with self.assertRaises(observer._NativeObservationHold) as caught:
            observer._assess_component_health(baseline,unavailable)
        self.assertEqual(caught.exception.reason_code,'HEALTH_STATUS_UNAVAILABLE')

    def test_postcheck_completion_heartbeat_reports_record_commit_not_device_wait(self):
        clock=SimpleNamespace(now=100.0)
        with patch.object(app.time,'monotonic',lambda:clock.now),contextlib.redirect_stderr(io.StringIO()) as output:
            bus=app._ProgressBus(); bus.emit('ib-1','os','POSTCHECK_VERIFIED'); bus.drain({'ib-1'})
            clock.now=131.0; bus.drain({'ib-1'})
        self.assertNotIn('POSTCHECK_VERIFIED: still waiting',output.getvalue())
        self.assertIn('COMMITTING_EVIDENCE',output.getvalue())

    def test_ssd_overview_does_not_imply_unchecked_devices_passed(self):
        report=summaries.inspection()
        report['ssd_checks']=[dict(hostname=n,state=state,status=status,observed_version=value,
            expected_version='CE00A474',reason_code=reason) for n,state,status,value,reason in (
                (summaries.NAMES[0],'PASS','MATCH','CE00A474',None),
                (summaries.NAMES[1],'NOT_CHECKED','OS_NOT_AT_TARGET',None,'OS_FINAL_NOT_REACHED'),
                (summaries.NAMES[2],'NOT_CHECKED','NOT_REACHED',None,'OS_POSTCHECK_NOT_REACHED'))]
        text=app._render_summary(report)
        self.assertIn('SSD checks: passed=1 warnings=0 not-checked=2 total=3',text)
        self.assertIn('SSD not checked: os-not-at-target=1 not-reached=1 preflight-skipped=0',text)
        self.assertIn(summaries.NAMES[2],text)


if __name__=='__main__': unittest.main()
