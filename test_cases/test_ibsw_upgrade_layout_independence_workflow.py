"""R-015: a real v2 plan against simulated switches with no v1-only sources."""
from pathlib import Path
import shutil
import tempfile
import unittest
from test_cases import test_ibsw_upgrade_layout_independence as layout


class UpgradeLayoutIndependenceWorkflowTests(unittest.TestCase):
    def test_real_plan_in_trimmed_layout_never_reads_v1_files(self):
        with tempfile.TemporaryDirectory(prefix="upgrade-layout-workflow-") as directory:
            root = Path(directory).resolve()
            layout.trimmed_tree(root)
            tests = root / "test_cases"
            tests.mkdir()
            # SimFleet's test-only clean environment reuses this existing
            # stdlib root checker; it is not a v1 production dependency.
            for name in ("test_ibsw_v2_entry.py", "test_ibsw_v2_device.py", "ibsw_v2_switch_sim.py",
                         "native_cpld_physical_io.py"):
                shutil.copyfile(layout.ROOT / "test_cases" / name, tests / name)
            done = layout.child(root, '''import sys,os
from pathlib import Path
root=Path(sys.argv[1]); sys.path.insert(0,str(root/'test_cases')); sys.path.insert(0,str(root/'tools'))
forbidden={'upgrade.py','upgrade.sh','requirements.txt',
           'ibsw_upgrade_driver.py','ibsw_upgrade_inputs.py','ibsw_upgrade_pipeline.py',
           'ibsw_upgrade_scp.py','_package_common.py'}
def audit(event,args):
 if event=='open' and isinstance(args[0],(str,bytes)):
  path=Path(os.fsdecode(args[0]))
  if path.name in forbidden and root in path.resolve().parents:
   raise AssertionError('v1-only source was read: '+path.name)
sys.addaudithook(audit)
import test_ibsw_v2_entry as fixtures
case=fixtures.EntryTest('test_plan_reads_only_and_reports_every_switch')
try:
 case.setUp()
 case.test_plan_reads_only_and_reports_every_switch()
finally:
 case.doCleanups()
assert not any((root/'tools'/name).exists() for name in forbidden)
print('real trimmed v2 plan OK; simulated switches untouched')
''')
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertIn("real trimmed v2 plan OK; simulated switches untouched", done.stdout)
