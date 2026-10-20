"""Cold flat-layout direct/entry-driver-executor rendering; never app.main or SSH."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import json
from test_cases import __file__ as TEST_CASES_FILE

ROOT = Path(TEST_CASES_FILE).resolve().parents[1]
ENTRY_DIR = 'infiniband/bringup/xdr-upgrade/'
MEMBERS = tuple(ENTRY_DIR + name for name in (
    'upgrade.py', 'upgrade.sh', 'upgrade-component.sh', 'upgrade-owned-runner.sh', 'requirements.txt')) + tuple(
    'tools/' + name for name in (
        'ibsw_upgrade_contract.py', 'ibsw_upgrade_inputs.py', 'ibsw_upgrade_schedule.py',
        'ibsw_upgrade_component.py', 'ibsw_upgrade_driver.py', 'ibsw_upgrade_executor.py',
        'ibsw_upgrade_observer.py', 'ibsw_upgrade_access.py', 'ibsw_upgrade_pipeline.py',
        'project_contract.py', '_package_common.py', 'ssh_key_preparation.py', 'ib_bringup_runtime_guard.py'))

class FlatToolsBasenameTests(unittest.TestCase):
    def test_layout_regression_is_bound_to_direct_and_real_workflow(self):
        manifest=json.loads((ROOT/'test_cases/script_test_manifest.json').read_text())
        name='test_cases.test_ibsw225_flat_tools_layout'
        self.assertEqual(1,sum(suite['tests'].count(name) for suite in manifest['test_suites']))
        for section,rule_id in (('test_rules','ibsw225_entry_render_component_direct'),
                                ('workflows','ibsw225_native_component_lifecycle')):
            with self.subTest(rule=rule_id):
                rules=[rule for rule in manifest[section] if rule['id']==rule_id]
                self.assertEqual(1,len(rules))
                self.assertIn(name,rules[0]['tests'])

    def exercise(self, program):
        with tempfile.TemporaryDirectory(prefix='ibsw-flat-tools-name-') as directory:
            bundle = Path(directory) / 'tools'
            bundle.mkdir()
            for relative in MEMBERS:
                original = ROOT / relative
                self.assertTrue(original.is_file(), relative)
                raw = original.read_bytes()
                self.assertTrue(raw, relative)
                (bundle / original.name).write_bytes(raw)
            # Fresh interpreter prevents canonical sys.modules masking the
            # actual flat imports. No guarded entry/main/SSH/installer call.
            result = subprocess.run([sys.executable, '-B', '-c', program, str(bundle)],
                cwd=bundle, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15)
            self.assertEqual(0, result.returncode, result.stderr)

    def test_component_uses_its_flat_sibling_even_when_folder_is_named_tools(self):
        self.exercise('''import sys
from pathlib import Path
bundle=Path(sys.argv[1]).resolve()
sys.path.insert(0,str(bundle))
import ibsw_upgrade_component as component
assert Path(component.__file__).resolve()==bundle/'ibsw_upgrade_component.py'
assert component._TEMPLATE==bundle/'upgrade-component.sh'
assert component._TEMPLATE.read_bytes()==(bundle/'upgrade-component.sh').read_bytes()
''')

    def test_real_entry_driver_executor_consumes_same_flat_owned_runner(self):
        self.exercise('''import sys,importlib.util
from pathlib import Path
bundle=Path(sys.argv[1]).resolve()
sys.path.insert(0,str(bundle))
spec=importlib.util.spec_from_file_location('owned_flat_entry',bundle/'upgrade.py')
entry=importlib.util.module_from_spec(spec)
spec.loader.exec_module(entry)
driver=entry._fixed_driver()
assert Path(driver.__file__).resolve()==bundle/'ibsw_upgrade_driver.py'
import ibsw_upgrade_executor as executor
assert Path(executor.__file__).resolve()==bundle/'ibsw_upgrade_executor.py'
binding={'run_id':'literal-run','node':{'hostname':'literal-node'},'stage':'os-0001',
         'component':'os','script_sha256':'a'*64}
remote='/home/admin/.ibsw-literal-run-literal-node-os-0001-'+'b'*32+'/step.sh'
rendered=executor._owned_runner_bytes(binding,remote)
assert rendered.endswith((bundle/'upgrade-owned-runner.sh').read_bytes())
assert b'IBSW_RUN_ID=literal-run\\n' in rendered
''')
class FixedTemplateLayoutNegativeTests(unittest.TestCase):
    def run_child(self, root, tools, program):
        result = subprocess.run([sys.executable, '-B', '-c',
            'import sys\nfrom pathlib import Path\n'
            'root=Path(sys.argv[1]); tools=Path(sys.argv[2]); sys.path.insert(0,str(tools))\n'
            + program, str(root), str(tools)], cwd=root,
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15)
        self.assertEqual(0, result.returncode, result.stderr)

    def canonical(self, root):
        for relative in MEMBERS:
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            raw = (ROOT / relative).read_bytes()
            self.assertTrue(raw)
            target.write_bytes(raw)
        return root / 'tools', root / 'infiniband/bringup/xdr-upgrade'

    def test_canonical_and_local_entry_collision_is_explicitly_held(self):
        with tempfile.TemporaryDirectory(prefix='ibsw-canonical-decoy-') as directory:
            root=Path(directory).resolve(); tools,scripts=self.canonical(root)
            (tools/'upgrade.py').write_bytes(b'raise AssertionError("decoy entry executed")\n')
            (tools/'upgrade-component.sh').write_bytes(b'LOCAL_COMPONENT_DECOY\n')
            (tools/'upgrade-owned-runner.sh').write_bytes(b'LOCAL_RUNNER_DECOY\n')
            self.run_child(root,tools,'''import importlib.util
spec=importlib.util.spec_from_file_location('real_canonical_entry',root/'infiniband/bringup/xdr-upgrade/upgrade.py')
entry=importlib.util.module_from_spec(spec);spec.loader.exec_module(entry)
try:
 entry._fixed_driver()
except ValueError as error:
 assert str(error)=='ambiguous fixed runtime layouts'
else:
 raise AssertionError('two entry identities must HOLD rather than guess template ownership')
''')

    def test_canonical_without_local_entry_ignores_local_shell_decoys(self):
        with tempfile.TemporaryDirectory(prefix='ibsw-canonical-shell-decoys-') as directory:
            root=Path(directory).resolve();tools,scripts=self.canonical(root)
            (tools/'upgrade-component.sh').write_bytes(b'LOCAL_COMPONENT_DECOY\n')
            (tools/'upgrade-owned-runner.sh').write_bytes(b'LOCAL_RUNNER_DECOY\n')
            self.run_child(root,tools,'''import ibsw_upgrade_component as component
assert component._TEMPLATE==root/'infiniband/bringup/xdr-upgrade/upgrade-component.sh'
import ibsw_upgrade_executor as executor
binding={'run_id':'literal-run','node':{'hostname':'literal-node'},'stage':'os-0001',
         'component':'os','script_sha256':'a'*64}
remote='/home/admin/.ibsw-literal-run-literal-node-os-0001-'+'b'*32+'/step.sh'
raw=executor._owned_runner_bytes(binding,remote)
assert raw.endswith((root/'infiniband/bringup/xdr-upgrade/upgrade-owned-runner.sh').read_bytes())
assert b'LOCAL_RUNNER_DECOY' not in raw
''')

    def test_both_complete_layout_entries_refuse_to_mix_sources(self):
        with tempfile.TemporaryDirectory(prefix='ibsw-complete-layout-collision-') as directory:
            root=Path(directory).resolve();tools,scripts=self.canonical(root)
            for relative in MEMBERS:
                (tools/Path(relative).name).write_bytes((ROOT/relative).read_bytes())
            for relative in ('infiniband/bringup/xdr-upgrade/upgrade.py', 'tools/upgrade.py'):
                with self.subTest(entry=relative):
                    self.run_child(root,tools,'''import importlib.util
path=root/''' + repr(relative) + '''
spec=importlib.util.spec_from_file_location('selected_real_entry',path)
entry=importlib.util.module_from_spec(spec);spec.loader.exec_module(entry)
try:
 entry._fixed_driver()
except ValueError as error:
 assert str(error)=='ambiguous fixed runtime layouts'
else:
 raise AssertionError('complete dual layouts must not mix entry/modules/templates')
''')

    def test_cached_component_does_not_bypass_new_entry_collision(self):
        with tempfile.TemporaryDirectory(prefix='ibsw-cached-entry-collision-') as directory:
            root=Path(directory).resolve();tools,scripts=self.canonical(root)
            self.run_child(root,tools,'''import importlib.util
spec=importlib.util.spec_from_file_location('cached_real_entry',root/'infiniband/bringup/xdr-upgrade/upgrade.py')
entry=importlib.util.module_from_spec(spec);spec.loader.exec_module(entry)
entry._fixed_driver()
import ibsw_upgrade_component as component
assert component._TEMPLATE==root/'infiniband/bringup/xdr-upgrade/upgrade-component.sh'
(tools/'upgrade.py').write_bytes(b'# newly appeared conflicting entry\\n')
try:
 entry._fixed_driver()
except ValueError as error:
 assert str(error)=='ambiguous fixed runtime layouts'
else:
 raise AssertionError('cached imports cannot bypass source-layout admission')
''')

    def test_missing_canonical_template_refuses_local_flat_decoy(self):
        with tempfile.TemporaryDirectory(prefix='ibsw-canonical-missing-') as directory:
            root=Path(directory).resolve();tools,scripts=self.canonical(root)
            (scripts/'upgrade-component.sh').unlink()
            (tools/'upgrade.py').write_bytes(b'# must not select this layout\n')
            (tools/'upgrade-component.sh').write_bytes(b'LOCAL_COMPONENT_DECOY\n')
            self.run_child(root,tools,'''try:
 import ibsw_upgrade_component as component
 component._TEMPLATE.read_bytes()
except (OSError,ValueError):
 pass
else:
 raise AssertionError('missing selected canonical shell must not adopt flat decoy')
''')

    def test_cached_renderer_refuses_a_change_to_another_complete_layout(self):
        with tempfile.TemporaryDirectory(prefix='ibsw-cached-template-layout-') as directory:
            root=Path(directory).resolve();tools,scripts=self.canonical(root)
            self.run_child(root,tools,'''import ibsw_upgrade_contract as contract
import ibsw_upgrade_component as component
document={'schema_version':2,'common':{'mgmt':{'http':{'status':'enabled',
 'address':'192.0.2.254','port':8088,'http_root':'/srv/ibsw-http'}}},
 'switches':[{'ib':{'version':'25.02.8008','upgrade':{'package_dir':'/srv/ibsw-http','packages':{'os':{
 'files':[{'file':'nvos-amd64-25.02.8008.bin'}]}}}}}]}
policy=contract.normalize_upgrade(document,selected=('os',),method='http')
node=contract.InventoryDevice('literal-node','192.0.2.21','02:00:00:00:00:21')
before=component.render_declared_step(policy,node,component='os',run_id='literal-run',method='http')
assert 'nv action install system image' in before.script
scripts=root/'infiniband/bringup/xdr-upgrade'
for name in ('upgrade.py','upgrade.sh','upgrade-component.sh','upgrade-owned-runner.sh','requirements.txt'):
 (tools/name).write_bytes((scripts/name).read_bytes())
(scripts/'upgrade.py').unlink()
try:
 component.render_declared_step(policy,node,component='os',run_id='literal-run',method='http')
except ValueError as error:
 assert 'layout' in str(error)
else:
 raise AssertionError('cached renderer must not retain or switch a changed template layout')
''')

    def test_cached_executor_refuses_a_change_to_another_complete_layout(self):
        with tempfile.TemporaryDirectory(prefix='ibsw-cached-runner-layout-') as directory:
            root=Path(directory).resolve();tools,scripts=self.canonical(root)
            self.run_child(root,tools,'''import importlib.util
spec=importlib.util.spec_from_file_location('cached_runner_entry',root/'infiniband/bringup/xdr-upgrade/upgrade.py')
entry=importlib.util.module_from_spec(spec);spec.loader.exec_module(entry)
entry._fixed_driver()
import ibsw_upgrade_executor as executor
assert Path(executor.__file__).resolve()==tools/'ibsw_upgrade_executor.py'
binding={'run_id':'literal-run','node':{'hostname':'literal-node'},'stage':'os-0001',
         'component':'os','script_sha256':'a'*64}
remote='/home/admin/.ibsw-literal-run-literal-node-os-0001-'+'b'*32+'/step.sh'
scripts=root/'infiniband/bringup/xdr-upgrade'
before=executor._owned_runner_bytes(binding,remote)
assert before.endswith((scripts/'upgrade-owned-runner.sh').read_bytes())
for name in ('upgrade.py','upgrade.sh','upgrade-component.sh','upgrade-owned-runner.sh','requirements.txt'):
 (tools/name).write_bytes((scripts/name).read_bytes())
(scripts/'upgrade.py').unlink()
# Same shell bytes, different complete layout. Do not replace an original
# runner's bytes or invent an unsafe installer. Cached ownership must refuse.
try:
 executor._owned_runner_bytes(binding,remote)
except ValueError as error:
 assert 'layout' in str(error)
else:
 raise AssertionError('cached executor must not switch to a different complete runner layout')
''')

    def test_canonical_registry_does_not_hide_flat_contract_bindings_in_cached_consumers(self):
        with tempfile.TemporaryDirectory(prefix='ibsw-transitive-cache-') as directory:
            root=Path(directory).resolve();tools,scripts=self.canonical(root)
            flat=root/'flat';flat.mkdir()
            for relative in MEMBERS:
                (flat/Path(relative).name).write_bytes((ROOT/relative).read_bytes())
            self.run_child(root,tools,'''import importlib,importlib.util
flat=root/'flat'
scripts=root/'infiniband/bringup/xdr-upgrade'
sys.path.insert(0,str(flat))
old_contract=importlib.import_module('ibsw_upgrade_contract')
assert Path(old_contract.__file__).resolve()==flat/'ibsw_upgrade_contract.py'
# Genuine imports only: let canonical consumers import while the prior flat
# contract remains cached, then replace that cache entry with the genuine
# canonical contract. No __file__/function/global attribute is forged.
assert Path(sys.modules['project_contract'].__file__).resolve()==flat/'project_contract.py'
sys.modules.pop('project_contract')
sys.path.insert(0,str(tools))
driver=importlib.import_module('ibsw_upgrade_driver')
component=importlib.import_module('ibsw_upgrade_component')
assert Path(driver.__file__).resolve()==tools/'ibsw_upgrade_driver.py'
assert Path(component.__file__).resolve()==tools/'ibsw_upgrade_component.py'
assert driver.normalize_upgrade is old_contract.normalize_upgrade
assert component.UpgradePolicy is old_contract.UpgradePolicy
assert sys.modules.pop('ibsw_upgrade_contract') is old_contract
current_contract=importlib.import_module('ibsw_upgrade_contract')
assert Path(current_contract.__file__).resolve()==tools/'ibsw_upgrade_contract.py'
assert current_contract is not old_contract
assert component.UpgradePolicy is not current_contract.UpgradePolicy
spec=importlib.util.spec_from_file_location('canonical_cached_dependency_entry',scripts/'upgrade.py')
entry=importlib.util.module_from_spec(spec);spec.loader.exec_module(entry)
refused=False
try:
 entry._fixed_driver()
except entry._InspectionHold:
 refused=True
assert refused,'canonical registry paths cannot authorize cached consumers bound to a flat contract'
''')

    def test_healthy_canonical_and_flat_registry_aliases_remain_same_object_reusable(self):
        for layout in ('canonical', 'flat'):
            with self.subTest(layout=layout), tempfile.TemporaryDirectory(prefix='ibsw-genuine-abi-') as directory:
                root=Path(directory).resolve();tools,scripts=self.canonical(root)
                if layout == 'flat':
                    flat=root/'flat';flat.mkdir()
                    for relative in MEMBERS:
                        (flat/Path(relative).name).write_bytes((ROOT/relative).read_bytes())
                    tools=scripts=flat
                self.run_child(root,tools,'''import importlib,importlib.util
entry_path=tools/'upgrade.py' if (tools/'upgrade.py').is_file() else root/'infiniband/bringup/xdr-upgrade/upgrade.py'
spec=importlib.util.spec_from_file_location('healthy_registry_entry',entry_path)
entry=importlib.util.module_from_spec(spec);spec.loader.exec_module(entry)
first=entry._fixed_driver()
contract=importlib.import_module('ibsw_upgrade_contract')
component=importlib.import_module('ibsw_upgrade_component')
project=importlib.import_module('project_contract')
assert first.InventoryDevice is contract.InventoryDevice
assert component.UpgradePolicy is contract.UpgradePolicy
assert first.render_declared_step is component.render_declared_step
assert contract._mapping is project._ibsw_mapping
assert entry._fixed_driver() is first
# Same genuine object, independently named alias/re-export: must not be
# rejected merely because its consumer binding name differs from __name__.
first._test_owned_render_alias=component.render_declared_step
first._test_owned_policy_alias=contract.UpgradePolicy
first._test_owned_module_alias=contract
try:
 assert entry._fixed_driver() is first
 assert first._test_owned_render_alias is component.render_declared_step
 assert first._test_owned_policy_alias is contract.UpgradePolicy
finally:
 del first._test_owned_render_alias
 del first._test_owned_policy_alias
 del first._test_owned_module_alias
''')

    def test_missing_flat_template_refuses_other_tree_template(self):
        with tempfile.TemporaryDirectory(prefix='ibsw-flat-missing-') as directory:
            root=Path(directory).resolve();tools=root/'tools';tools.mkdir()
            for relative in MEMBERS:
                (tools/Path(relative).name).write_bytes((ROOT/relative).read_bytes())
            (tools/'upgrade-component.sh').unlink()
            other=root/'infiniband/bringup/xdr-upgrade';other.mkdir(parents=True)
            # Shell alone is not a canonical entry/layout and cannot rescue flat.
            (other/'upgrade-component.sh').write_bytes(b'FOREIGN_TEMPLATE_DECOY\n')
            self.run_child(root,tools,'''try:
 import ibsw_upgrade_component as component
 component._TEMPLATE.read_bytes()
except (OSError,ValueError):
 pass
else:
 raise AssertionError('missing selected flat shell must not consume other-tree shell')
''')
