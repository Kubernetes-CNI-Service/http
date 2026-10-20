"""Supplementary census consumes indexed sources, never evidence artifacts."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
from test_cases import test_monitor_writer_quiesce_workflow as SUBJECT

CALLERS={
    'DAY0-Prepare/01-a-setup.py':('_main_locked',),
    'DAY0-Prepare/02-unsetup.py':('main',),
    'DAY0-Prepare/11-load.py':('main','quiesce_services','stop_other_ztp_monitors'),
    'DAY0-Prepare/13-unload.py':('stop_monitor',),
    'tools/deployment_prewrite_guard.py':('quiesce_for_source_update',),
    'tools/password-update.py':('rotate_project_passwords',),
    'ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py':('main',),
    'ztp/config/isc-dhcp-server/c1-generate_dhcp.py':('main',),
    'ztp/optimize/feedback.py':('main',),
}

class QuiesceCensusSourceTests(unittest.TestCase):
    def test_evidence_copy_is_not_source_but_tracked_extra_caller_still_fails(self):
        with tempfile.TemporaryDirectory(prefix='h-census-source-') as directory:
            root=Path(directory)
            subprocess.run(['git','init','-q',str(root)],check=True,capture_output=True)
            (root/'.gitignore').write_text('outputs/\n')
            for relative,names in CALLERS.items():
                path=root/relative;path.parent.mkdir(parents=True,exist_ok=True)
                path.write_text(''.join('def '+name+'():\n    stop_native_ztp_monitors()\n' for name in names))
            artifact=root/'outputs/received.py';artifact.parent.mkdir()
            artifact.write_text('def unrelated_evidence_copy():\n    stop_native_ztp_monitors()\n')
            subprocess.run(['git','-C',str(root),'add','--','.gitignore',*CALLERS],check=True,capture_output=True)
            def run_original():
                result=unittest.TestResult()
                case=SUBJECT.MonitorWriterQuiesceWorkflowTests('test_no_quiesce_caller_escapes_the_sink_derived_contract_set')
                with mock.patch.object(SUBJECT,'ROOT',root):
                    case.run(result)
                return result
            first=run_original()
            self.assertEqual(1,first.testsRun)
            self.assertEqual([],first.errors)
            self.assertEqual([],first.failures,'evidence copy is not indexed production source')
            hostile=root/'tools/new_quiesce.py'
            hostile.write_text('def covert():\n    stop_native_ztp_monitors()\n')
            subprocess.run(['git','-C',str(root),'add','--','tools/new_quiesce.py'],check=True,capture_output=True)
            second=run_original()
            self.assertEqual(1,second.testsRun)
            self.assertEqual([],second.errors)
            self.assertEqual(1,len(second.failures),'new indexed caller must remain fail closed')
            self.assertIn('tools/new_quiesce.py',second.failures[0][1])
