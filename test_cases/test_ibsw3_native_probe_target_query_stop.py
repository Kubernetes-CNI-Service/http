"""SOURCE-only phase witness; real source probe, test-owned target SDK query IO.

No source producer/guard/result is replaced. Transparent profile registration
composition observes the existing carrier's original observer in every thread.
The modeled target query timeout is not a real 25-second wait or device event.
"""
import dis
import sys
import threading
from types import CodeType
import unittest
from unittest.mock import patch

from test_cases import test_ibsw3_native_source_preflight_workflow as HEALTHY


class NativeProbeTargetQueryStopTests(unittest.TestCase):
    def test_actual_source_probe_precedes_bounded_target_query_stop_and_drift_stops_earlier(self):
        fixture = HEALTHY.FIXTURE
        executor, observer = fixture.executor, fixture.observer
        wrapper = HEALTHY.NativeScpSourcePreflightWorkflowTests().capability()
        query_codes = [item for item in fixture.ThreeComponentWorkflowTests.invoke.__code__.co_consts
                       if type(item) is CodeType and item.co_name == 'query']
        self.assertEqual(1, len(query_codes))
        query_code = query_codes[0]
        query_globals = fixture.ThreeComponentWorkflowTests.invoke.__globals__
        provider = HEALTHY.importlib.import_module('ibsw_upgrade_scp')
        probe = provider._probe_source_channel
        component_query = executor._component_query
        execute = executor._execute_component_once
        single = observer._signed_session_single.__wrapped__
        outer = observer._signed_session.__wrapped__
        real_sys_profile, real_thread_profile = sys.setprofile, threading.setprofile

        def normal_return(frame):
            return (frame.f_lasti >= 0 and
                    dis.opname[frame.f_code.co_code[frame.f_lasti]] in ('RETURN_VALUE', 'RETURN_CONST'))

        for drift in (False, True):
            with self.subTest(source_drift=drift):
                events, queries, waiting = [], [], {}
                sessions, outers = {}, {}
                own_wrappers = []

                def witness(frame, event, value):
                    code, namespace = frame.f_code, frame.f_globals
                    if ((code is single.__code__ and namespace is single.__globals__) or
                            (code is outer.__code__ and namespace is outer.__globals__)):
                        active = sessions if code is single.__code__ else outers
                        if event == 'call':
                            for key in [key for key, row in active.items() if row['frame'] == id(frame)]:
                                del active[key]
                        elif event == 'return' and type(value) is tuple and len(value) == 5:
                            active[id(value[0])] = dict(frame=id(frame), leaf=frame.f_locals['leaf'],
                                transport=value[0], authentication=value[3],
                                entered=frame.f_locals.get('operation_entered'))
                    if (code is probe.__code__ and namespace is probe.__globals__ and
                            event == 'return' and normal_return(frame)):
                        events.append('source_probe_return')
                    if code is query_code and namespace is query_globals:
                        if event == 'call' and frame.f_locals['command'] == 'nv show system version':
                            caller = frame.f_back
                            component_frame = None
                            for _ in range(12):
                                if caller is None:
                                    break
                                if (caller.f_code is component_query.__code__ and
                                        caller.f_globals is component_query.__globals__):
                                    component_frame = caller
                                    break
                                caller = caller.f_back
                            if component_frame is not None:
                                leaf, transport = frame.f_locals['leaf'], frame.f_locals['transport']
                                direct = component_frame.f_back
                                waiting[id(frame)] = dict(leaf=leaf, transport=transport,
                                    component=component_frame.f_locals['component'],
                                    command=frame.f_locals['command'], session=sessions.get(id(transport)),
                                    outer=outers.get(id(transport)),
                                    execute_joint=(direct.f_code is execute.__code__ and
                                                   direct.f_globals is execute.__globals__))
                        elif event == 'return' and id(frame) in waiting:
                            row = waiting.pop(id(frame))
                            diagnostic = getattr(row['leaf'], '_last_query_diagnostic', {})
                            row['diagnostic'] = {key: diagnostic.get(key) for key in (
                                'command', 'reason_code', 'budget_seconds', 'elapsed_seconds')}
                            row['result'] = value
                            queries.append(row)
                            events.append('target_query_return')

                def composed(original):
                    if original is None:
                        return None
                    if any(original is owned for owned in own_wrappers):
                        return original
                    def profile(frame, event, value):
                        original(frame, event, value)
                        witness(frame, event, value)
                    own_wrappers.append(profile)
                    return profile

                def install_main(original):
                    return real_sys_profile(composed(original))

                def install_threads(original):
                    return real_thread_profile(composed(original))

                control = HEALTHY.NativeScpSourcePreflightWorkflowTests()
                self.assertIsNone(sys.getprofile())
                self.assertIsNone(getattr(threading, 'getprofile', lambda: None)())
                try:
                    with patch.object(sys, 'setprofile', new=install_main), \
                         patch.object(threading, 'setprofile', new=install_threads):
                        state = control.exercise(wrapper, drift=drift)
                finally:
                    real_sys_profile(None)
                    real_thread_profile(None)
                self.assertIsNone(sys.getprofile())
                self.assertIsNone(getattr(threading, 'getprofile', lambda: None)())
                self.assertIsNone(sys.gettrace())
                self.assertIsNone(getattr(threading, 'gettrace', lambda: None)())
                self.assertEqual([], state['authority_calls'])
                code, report, error, calls, installs = state['result']
                self.assertNotEqual(0, code)
                self.assertEqual([], installs)
                self.assertEqual(1, len(state['channels']))
                self.assertEqual(1, state['channels'][0].close_calls)
                self.assertEqual([False, False], state['factory_calls'])
                self.assertEqual({}, waiting)
                self.assertNotIn(HEALTHY.SOURCE_SECRET, error + repr(report))
                self.assertNotIn(HEALTHY.SOURCE_SECRET, state['channels'][0].command)
                if drift:
                    self.assertEqual([], queries)
                    self.assertEqual([], events)
                    self.assertEqual(0, state['channels'][0].send_calls)
                    self.assertEqual(b'', bytes(state['channels'][0].sent))
                    self.assertTrue(state['channels'][0].trust_mutated)
                    self.assertTrue(any(isinstance(error, fixture.driver.SharedUpgradeHold)
                        for row in (*state['wrappers'], *state['probes']) for error in row['errors']))
                    self.assertIsInstance(state['binds'][0][0]._package_source_lifecycle_failure,
                                          fixture.driver.SharedUpgradeHold)
                else:
                    self.assertEqual(['source_probe_return', 'target_query_return'], events)
                    self.assertEqual(1, len(queries))
                    row = queries[0]
                    self.assertEqual(('os', 'nv show system version'), (row['component'], row['command']))
                    self.assertTrue(row['execute_joint'])
                    self.assertEqual((b'', b'', None, False), row['result'])
                    self.assertEqual({'command': 'nv show system version',
                        'reason_code': 'READONLY_QUERY_TIMEOUT', 'budget_seconds': 25.0,
                        'elapsed_seconds': 25.1}, row['diagnostic'])
                    self.assertTrue(row['leaf']._native_observation_consumed)
                    self.assertIsNotNone(row['session'])
                    self.assertTrue(row['session']['entered'])
                    for signed in (row['session'], row['outer']):
                        self.assertIsNotNone(signed)
                        self.assertIs(row['leaf'], signed['leaf'])
                        self.assertIs(row['transport'], signed['transport'])
                        self.assertEqual('publickey', signed['authentication'])
                    self.assertTrue(state['wrappers'][0]['normal'])
                    self.assertTrue(state['probes'][0]['normal'])
                    self.assertIsNone(state['wrappers'][0]['returned'])
                    self.assertIsNone(state['probes'][0]['returned'])
                    self.assertEqual([], state['wrappers'][0]['errors'])
                    self.assertEqual([], state['probes'][0]['errors'])
                    self.assertGreater(state['channels'][0].send_calls, 1)
                    self.assertEqual(0, state['channels'][0].process.returncode)
                control.assert_real_probe_chain(state)


if __name__ == '__main__':
    unittest.main()
