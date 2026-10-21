"""Additional actual-interpreter finite producer audit regression, LOCAL only."""
import sys,unittest
from test_cases import test_ibsw3_scp_stage_scope as BASE

class ScpProbeApiPythonModelTests(unittest.TestCase):
    def test_actual_runtime_supports_exact_default_and_probe_source_joints(self):
        self.assertIn(sys.version_info[:2],((3,9),(3,12)))
        with BASE.StagePackageSourceBoundaryV3Tests().original_graph() as graph:
            parent=graph[0]
            default=BASE.driver._fixed_scp_source_api(parent)
            joint=BASE.driver._fixed_scp_source_api(parent,probe=True)
            self.assertIs(type(joint),tuple); self.assertEqual(2,len(joint))
            source,probe=joint
            self.assertIs(type(source),tuple); self.assertEqual(19,len(source))
            self.assertTrue(all(a is b for a,b in zip(default,source)))
            self.assertIs(type(probe),tuple); self.assertEqual(32,len(probe))
            self.assertIs(probe[0],source[0]._probe_source_channel)
            self.assertIs(probe[5],sys.modules['ibsw_upgrade_observer'])
            self.assertIs(probe[6].__wrapped__,probe[7])
            self.assertIs(probe[8],probe[5]._remaining)
            for value in (0,1,None,'true'):
                with self.subTest(invalid_mode=value), self.assertRaises(BASE.driver.SharedUpgradeHold):
                    BASE.driver._fixed_scp_source_api(parent,probe=value)
            parent.verify()
