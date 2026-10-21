"""UNRUN additional regression; do not disable audit to manufacture initial RED."""
import unittest

from test_cases import test_ibsw3_native_source_preflight_workflow as HEALTHY
from test_cases import scp_foreign_probe_fixture as FAULT


class NativeForeignProbeRegressionTests(unittest.TestCase):
    def test_real_bound_native_flow_refuses_foreign_probe_before_any_channel(self):
        # Full original healthy control, including its independent original
        # positive assertions, runs unchanged. Not a second reported whole.
        control = HEALTHY.NativeScpSourcePreflightWorkflowTests()
        control.test_real_native_session_sends_only_source_secret_to_actual_probe_helper_then_holds()
        wrapper = FAULT.NativeProbeFaultSupport.capability(self)
        state = FAULT.NativeProbeFaultSupport.exercise(self,wrapper,foreign_probe=True)
        self.assertTrue(state['foreign_installed'], 'must reach actual native wrapper before injecting fault')
        self.assertTrue(all(state['foreign_joint']), 'real bound/frozen registered original parent/child joint')
        self.assertTrue(state['foreign_restored'])
        self.assertEqual([],state['foreign_calls'],'same metadata cannot authorize foreign probe globals')
        self.assertEqual([],state['channels'],'audit must reject before opening a secret channel')
        self.assertEqual([],state['probes'],'actual original probe must not be delegated into after refusal')
        self.assertEqual([False,False],state['factory_calls'],'never refresh source after fault')
        self.assertEqual(2,len(state['sources']))
        self.assertEqual(1,len(state['binds']))
        self.assertEqual(1,len(state['wrappers']))
        parent,source = state['binds'][0]
        row = state['wrappers'][0]
        self.assertIs(parent,row['parent'])
        self.assertIs(source,state['sources'][1])
        self.assertTrue(all(row['controls']))
        self.assertEqual(('os',1),(row['component'],row['index']))
        self.assertTrue(any(value is source for value in state['getter_returns']),
                        'original native source getter must pass before producer rejection')
        signed,outer = row['session'],row['outer']
        self.assertIsNotNone(signed)
        self.assertIsNotNone(outer)
        self.assertTrue(signed['entered'])
        self.assertEqual('publickey',signed['authentication'])
        self.assertIs(row['leaf'],signed['leaf'])
        self.assertIs(row['transport'],signed['transport'])
        self.assertIs(row['leaf'],outer['leaf'])
        self.assertIs(row['transport'],outer['transport'])
        self.assertFalse(row['normal'])
        self.assertIsNone(row['returned'])
        self.assertTrue(any(isinstance(error,FAULT.FIXTURE.driver.SharedUpgradeHold)
                            for error in row['errors']))
        self.assertIsInstance(parent._package_source_lifecycle_failure,FAULT.FIXTURE.driver.SharedUpgradeHold)
        code,report,error,queries,installs=state['result']
        self.assertNotEqual(0,code)
        self.assertEqual([],installs)
        self.assertEqual([],state['authority_calls'],'zero original request/publish/dispatch entries')
        self.assertIsNone(state['ssh_events'],'no source SSH executable stub before producer admission')
        self.assertEqual(state['trust_before'],state['trust_after'])
        self.assertEqual([],state['leftover_helpers'])
        self.assertNotIn(FAULT.SOURCE_SECRET,error+repr(report))
