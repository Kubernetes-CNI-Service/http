"""Actual supported interpreter model through a genuine LOCAL original graph."""
import sys,unittest
from test_cases import test_ibsw3_scp_stage_scope as BASE

class ScpSourceApiPythonModelTests(unittest.TestCase):
    def test_actual_runtime_model_admits_genuine_generated_source_class(self):
        self.assertIn(sys.version_info[:2],((3,9),(3,12)))
        with BASE.StagePackageSourceBoundaryV3Tests().original_graph() as graph:
            api=BASE.driver._fixed_scp_source_api(graph[0])
            self.assertIs(type(api),tuple)
            self.assertEqual(19,len(api))
            self.assertIs(api[0],sys.modules['ibsw_upgrade_scp'])
            self.assertIs(api[2],api[0].ScpSource)
            self.assertEqual(('host','user','port','known_hosts_path','host_keys','password','_identity'),
                             tuple(api[2].__dataclass_fields__))
            self.assertTrue(api[2].__dataclass_params__.frozen)
            self.assertIs(api[6],vars(api[2])['__init__'])
            graph[0].verify()
