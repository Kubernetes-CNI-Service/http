"""R-015 / v3.1.4 WP-A1: v2 uses shared templates, not the v1 bundle."""
from pathlib import Path
import hashlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = Path("infiniband/bringup/xdr-upgrade")
V1_ONLY = ("ibsw_upgrade_driver.py", "ibsw_upgrade_inputs.py",
           "ibsw_upgrade_pipeline.py", "ibsw_upgrade_scp.py", "_package_common.py")
TEMPLATES = ("upgrade-component.sh", "upgrade-owned-runner.sh")


def trimmed_tree(root, *, flat=False):
    """Copy real v2 sources; deliberately omit the declared v1-only files."""
    tools = root / "tools"
    scripts = tools if flat else root / SCRIPTS
    tools.mkdir(parents=True)
    scripts.mkdir(parents=True, exist_ok=True)
    for source in (ROOT / "tools").glob("*.py"):
        if source.name not in V1_ONLY:
            shutil.copyfile(source, tools / source.name)
    for name in (*TEMPLATES, "upgrade2.py", "ibsw-v2-check.sh"):
        shutil.copyfile(ROOT / SCRIPTS / name, scripts / name)
    # fleet_distribution reuses the real initial-setup P2P parser (not v1 upgrade).
    setup = root / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
    setup.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py", setup)
    return tools, scripts


def child(root, program):
    return subprocess.run([sys.executable, "-B", "-c", program, str(root)],
                          cwd=root, stdin=subprocess.DEVNULL, capture_output=True,
                          text=True, timeout=60)


class UpgradeLayoutIndependenceTests(unittest.TestCase):
    def test_v2_imports_renders_and_builds_runner_without_v1_files(self):
        # R-015, approved WP-A1: import, render and runner all work without v1.
        with tempfile.TemporaryDirectory(prefix="upgrade-layout-") as directory:
            root = Path(directory).resolve()
            trimmed_tree(root)
            done = child(root, '''import sys
from pathlib import Path
root=Path(sys.argv[1]); sys.path.insert(0,str(root/'tools'))
import ibsw_v2_device
import ibsw_upgrade_component as component
import ibsw_upgrade_executor as executor
from ibsw_upgrade_contract import InventoryDevice, load_global_text, normalize_upgrade
document=load_global_text(''' + repr("""schema_version: 2
switches:
- ib:
    version: '25.02.8008'
    upgrade:
      package_dir: /images
      packages:
        os:
          sub_dir: image
          files:
          - file: nvos-amd64-25.02.7002.bin
          - file: nvos-amd64-25.02.8008.bin
""") + ''')
policy=normalize_upgrade(document, selected=('os',), method='local')
device=InventoryDevice('literal-node','192.0.2.41','02:00:00:00:00:41')
step=component.render_declared_step(policy,device,component='os',run_id='literal-run',method='local')
assert 'IBSW_COMPONENT=os' in step.script
binding={'run_id':'literal-run','node':{'hostname':'literal-node'},'stage':'os-0001',
         'component':'os','script_sha256':'a'*64}
remote='/home/admin/.ibsw-literal-run-literal-node-os-0001-'+'b'*32+'/step.sh'
runner=executor._owned_runner_bytes(binding,remote)
assert runner.endswith((root/'infiniband/bringup/xdr-upgrade/upgrade-owned-runner.sh').read_bytes())
print('v2 render and runner OK')
''')
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertIn("v2 render and runner OK", done.stdout)

    def test_v2_layout_refuses_template_only_decoy(self):
        with tempfile.TemporaryDirectory(prefix="upgrade-decoy-") as directory:
            root = Path(directory).resolve()
            tools, scripts = trimmed_tree(root)
            (scripts / "upgrade2.py").unlink()
            done = child(root, '''import sys
from pathlib import Path
root=Path(sys.argv[1]); sys.path.insert(0,str(root/'tools'))
try:
 import ibsw_upgrade_component
except (OSError,ValueError):
 pass
else:
 raise AssertionError('templates without v2 entry must not select a layout')
''')
            self.assertEqual(done.returncode, 0, done.stderr)

    def test_v2_missing_selected_template_refuses_other_tree_template(self):
        for name in TEMPLATES:
            with self.subTest(template=name), tempfile.TemporaryDirectory(prefix="upgrade-selected-") as directory:
                root = Path(directory).resolve()
                tools, scripts = trimmed_tree(root)
                (scripts / name).unlink()
                shutil.copyfile(ROOT / SCRIPTS / name, tools / name)
                done = child(root, '''import sys
from pathlib import Path
root=Path(sys.argv[1]); sys.path.insert(0,str(root/'tools'))
try:
 import ibsw_upgrade_component, ibsw_upgrade_executor
except (OSError,ValueError):
 pass
else:
 raise AssertionError('missing selected template must not use local decoy')
''')
                self.assertEqual(done.returncode, 0, done.stderr)

    def test_v1_layouts_still_refuse_missing_v1_files(self):
        from test_cases import test_ibsw225_flat_tools_layout as old
        sys.path.insert(0, str(ROOT / "tools"))
        from ibsw_upgrade_contract import _fixed_layout
        for flat in (False, True):
            for missing in CurrentPointerLayoutCompatibilityTests.CORE:
                with self.subTest(flat=flat, missing=missing), tempfile.TemporaryDirectory(prefix="upgrade-v1-") as directory:
                    root = Path(directory).resolve()
                    for relative in old.MEMBERS:
                        target = root / (Path(relative).name if flat else relative)
                        target.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copyfile(ROOT / relative, target)
                    (root / (Path(missing).name if flat else missing)).unlink()
                    module = root / ("ibsw_upgrade_contract.py" if flat else "tools/ibsw_upgrade_contract.py")
                    message = ("complete fixed flat runtime entry required"
                               if missing.endswith("/upgrade.py") else "incomplete selected fixed runtime bundle")
                    with self.assertRaisesRegex(ValueError, "^" + message + "$"):
                        _fixed_layout(module)

    def test_v2_rejects_distinct_layout_entries_and_mixed_sources(self):
        for local_entry in ("upgrade.py", "upgrade2.py", None):
            with self.subTest(local_entry=local_entry), tempfile.TemporaryDirectory(prefix="upgrade-conflict-") as directory:
                root = Path(directory).resolve()
                tools, scripts = trimmed_tree(root)
                if local_entry:
                    shutil.copyfile(ROOT / SCRIPTS / local_entry, tools / local_entry)
                    expected = "ambiguous fixed runtime layouts"
                else:
                    shutil.copyfile(ROOT / "tools/ibsw_upgrade_driver.py", scripts / "ibsw_upgrade_driver.py")
                    expected = "fixed runtime layout/source disagreement"
                done = child(root, '''import sys
from pathlib import Path
root=Path(sys.argv[1]); sys.path.insert(0,str(root/'tools'))
try:
 import ibsw_upgrade_component
except ValueError as error:
 print(str(error))
else:
 raise AssertionError('distinct layouts or mixed canonical source must refuse')
''')
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertEqual(done.stdout.strip(), expected)

    def test_v1_and_v2_entries_in_same_directory_are_not_distinct_layouts(self):
        with tempfile.TemporaryDirectory(prefix="upgrade-coexisting-") as directory:
            root = Path(directory).resolve()
            tools, scripts = trimmed_tree(root)
            shutil.copyfile(ROOT / SCRIPTS / "upgrade.py", scripts / "upgrade.py")
            done = child(root, '''import sys
from pathlib import Path
root=Path(sys.argv[1]); sys.path.insert(0,str(root/'tools'))
import ibsw_v2_device, ibsw_upgrade_component, ibsw_upgrade_executor
assert ibsw_upgrade_component._TEMPLATE.parent == root/'infiniband/bringup/xdr-upgrade'
assert ibsw_upgrade_executor._RUNNER.parent == root/'infiniband/bringup/xdr-upgrade'
''')
            self.assertEqual(done.returncode, 0, done.stderr)

    def test_v1_audit_sees_the_same_layout_objects(self):
        sys.path.insert(0, str(ROOT / "tools"))
        import ibsw_upgrade_contract as contract
        import ibsw_upgrade_component as component
        import ibsw_upgrade_executor as executor
        self.assertIs(component._fixed_layout, contract._fixed_layout)
        self.assertIs(executor._fixed_layout, contract._fixed_layout)

    def test_legacy_v1_shared_consumers_keep_complete_bundle_checks(self):
        # The v2 exception must not weaken a selected legacy-only v1 bundle.
        from test_cases import test_ibsw225_flat_tools_layout as old
        for flat in (False, True):
            for missing in ("tools/ibsw_upgrade_driver.py", "tools/ibsw_upgrade_inputs.py",
                            "infiniband/bringup/xdr-upgrade/requirements.txt"):
                with self.subTest(flat=flat, missing=missing), tempfile.TemporaryDirectory(prefix="upgrade-legacy-") as directory:
                    root = Path(directory).resolve()
                    for relative in old.MEMBERS:
                        target = root / (Path(relative).name if flat else relative)
                        target.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copyfile(ROOT / relative, target)
                    (root / (Path(missing).name if flat else missing)).unlink()
                    done = child(root, '''import sys
from pathlib import Path
root=Path(sys.argv[1]); sys.path.insert(0,str(root/'tools' if (root/'tools').is_dir() else root))
try:
 import ibsw_upgrade_component
except ValueError as error:
 assert str(error)=='incomplete selected fixed runtime bundle',str(error)
else:
 raise AssertionError('v1-only shared consumer must retain full v1 integrity checks')
''')
                    self.assertEqual(done.returncode, 0, done.stderr)

    def test_v2_flat_templates_render_and_build_runner_without_v1(self):
        # Same shared-layout contract; this tests the renderer, not a flat v2 entry workflow.
        with tempfile.TemporaryDirectory(prefix="upgrade-v2-flat-") as directory:
            root = Path(directory).resolve()
            trimmed_tree(root, flat=True)
            done = child(root, '''import sys
from pathlib import Path
root=Path(sys.argv[1]); tools=root/'tools'; sys.path.insert(0,str(tools))
import ibsw_upgrade_component as component
import ibsw_upgrade_executor as executor
from ibsw_upgrade_contract import UpgradePolicy, Package, InventoryDevice
assert component._TEMPLATE == tools/'upgrade-component.sh'
assert executor._RUNNER == tools/'upgrade-owned-runner.sh'
package=Package('nvos-amd64-25.02.8008.bin','25.02.8008','/images/nvos-amd64-25.02.8008.bin')
policy=UpgradePolicy('/images','25.02.8008',(package,))
device=InventoryDevice('literal-node','192.0.2.41','02:00:00:00:00:41')
step=component.render_declared_step(policy,device,component='os',run_id='literal-run',method='local')
assert step.target_version == '25.02.8008'
assert 'nv action install system image' in step.script
binding={'run_id':'literal-run','node':{'hostname':'literal-node'},'stage':'os-0001',
         'component':'os','script_sha256':'a'*64}
remote='/home/admin/.ibsw-literal-run-literal-node-os-0001-'+'b'*32+'/step.sh'
assert executor._owned_runner_bytes(binding,remote).endswith((tools/'upgrade-owned-runner.sh').read_bytes())
''')
            self.assertEqual(done.returncode, 0, done.stderr)

    def test_v2_flat_missing_selected_template_refuses_canonical_template_decoy(self):
        for name in TEMPLATES:
            with self.subTest(template=name), tempfile.TemporaryDirectory(prefix="upgrade-v2-flat-decoy-") as directory:
                root = Path(directory).resolve()
                tools, scripts = trimmed_tree(root, flat=True)
                (scripts / name).unlink()
                other = root / SCRIPTS
                other.mkdir(parents=True)
                for template in TEMPLATES:
                    shutil.copyfile(ROOT / SCRIPTS / template, other / template)
                done = child(root, '''import sys
from pathlib import Path
root=Path(sys.argv[1]); sys.path.insert(0,str(root/'tools'))
try:
 import ibsw_upgrade_component, ibsw_upgrade_executor
except (ValueError,OSError):
 pass
else:
 raise AssertionError('v2 flat missing selected template must not adopt canonical decoy')
''')
                self.assertEqual(done.returncode, 0, done.stderr)


class UpgradeLayoutSourceInverseTests(unittest.TestCase):
    # Independent whole preimages read from the unchanged v3.1.3 tag before A1.
    EXPECTED_PREVIOUS = {
        "tools/ibsw_upgrade_contract.py": "e9163ecf5363db5401377d1e044cc36750b0045168d119a9f40bf5dd9d1f616b",
        "tools/ibsw_upgrade_component.py": "95339d60968b36ccf6139e0349d0e0cdfcd8a0d5829c7039b4e41852c817795d",
        "tools/ibsw_upgrade_executor.py": "6edf4f6655a6b18e137f5447abe36999eddbcf80000a6b1c47dbe771baab022e",
    }

    def test_exact_outer_inverse_recovers_all_three_previous_sources(self):
        from test_cases import native_os_safe_image as source
        restore = getattr(source, "_restore_upgrade_layout_layer", None)
        self.assertTrue(callable(restore), "approved A1 outer source inverse required")
        for relative, expected in self.EXPECTED_PREVIOUS.items():
            with self.subTest(source=relative):
                original = restore(relative, (ROOT / relative).read_bytes())
                self.assertEqual(hashlib.sha256(original).hexdigest(), expected)

    def test_outer_inverse_refuses_unchanged_partial_duplicate_and_external_drift(self):
        from test_cases import native_os_safe_image as source
        restore = getattr(source, "_restore_upgrade_layout_layer", None)
        self.assertTrue(callable(restore), "approved A1 outer source inverse required")
        for relative in self.EXPECTED_PREVIOUS:
            current = (ROOT / relative).read_bytes()
            previous = restore(relative, current)
            mutations = {
                "unchanged-previous": previous,
                "partial": current[:-1],
                "duplicate": current + current,
                "outside-prefix": b"# foreign prefix\n" + current,
                "outside-suffix": current + b"# foreign suffix\n",
                "changed-call": current.replace(b"_shared_script_layout", b"_shared_script_layout_drift", 1),
                "wrong-type": bytearray(current),
            }
            for label, payload in mutations.items():
                with self.subTest(source=relative, fault=label), self.assertRaises(AssertionError):
                    restore(relative, payload)


class CurrentPointerLayoutCompatibilityTests(unittest.TestCase):
    # Old fixed-layout integrity contract: 5 entry/assets plus 13 tool modules.
    CORE = tuple("infiniband/bringup/xdr-upgrade/" + name for name in (
        "upgrade.py", "upgrade.sh", "upgrade-component.sh", "upgrade-owned-runner.sh", "requirements.txt")) + tuple(
        "tools/" + name for name in (
            "ibsw_upgrade_contract.py", "ibsw_upgrade_inputs.py", "ibsw_upgrade_schedule.py",
            "ibsw_upgrade_component.py", "ibsw_upgrade_driver.py", "ibsw_upgrade_executor.py",
            "ibsw_upgrade_observer.py", "ibsw_upgrade_access.py", "ibsw_upgrade_pipeline.py",
            "project_contract.py", "_package_common.py", "ssh_key_preparation.py", "ib_bringup_runtime_guard.py"))

    def test_current_members_are_old_eighteen_core_plus_one_pointer(self):
        from test_cases import test_ibsw225_flat_tools_layout as old
        self.assertEqual(18, len(self.CORE))
        self.assertEqual(18, len(set(self.CORE)))
        self.assertEqual(self.CORE + ("tools/project_pointer.py",), old.MEMBERS)
        self.assertEqual(19, len(old.MEMBERS))

    def test_current_cold_contract_requires_pointer_in_both_complete_layouts(self):
        from test_cases import test_ibsw225_flat_tools_layout as old
        import yaml
        runtime_site = str(Path(yaml.__file__).resolve().parents[1])
        program = '''import importlib.util, sys
from pathlib import Path
tools=Path(sys.argv[1]).resolve(); canonical=Path(sys.argv[2]).resolve()
runtime_site=sys.argv[3]; missing=sys.argv[4]=='missing'
sys.path[:]=[str(tools),runtime_site]+[p for p in sys.path if p and
 Path(p).resolve() not in {canonical,canonical/'tools',tools,tools.parent} and p!=runtime_site]
def no_external(event,args):
 if event in {'subprocess.Popen','os.system','os.exec','socket.connect','socket.bind'}:
  raise AssertionError('unexpected external effect in cold import')
sys.addaudithook(no_external)
spec=importlib.util.find_spec('project_pointer')
if missing:
 assert spec is None,'foreign pointer spec must not be executed'
else:
 assert spec is not None and Path(spec.origin).resolve()==tools/'project_pointer.py'
try:
 import project_contract
except ModuleNotFoundError as error:
 assert missing and error.name=='project_pointer',type(error).__name__
 print('CURRENT_POINTER_MISSING_REJECTED')
else:
 assert not missing,'current contract silently accepted a missing dependency'
 import project_pointer
 assert Path(project_contract.__file__).resolve()==tools/'project_contract.py'
 assert Path(project_pointer.__file__).resolve()==tools/'project_pointer.py'
 assert project_contract.ActiveProjectPointerError is project_pointer.ActiveProjectPointerError
 print('CURRENT_POINTER_SAME_TREE_OK')
'''
        for flat in (False, True):
            for missing in (False, True):
                with self.subTest(flat=flat, missing=missing), tempfile.TemporaryDirectory(prefix="v1-current-pointer-") as folder:
                    root = Path(folder).resolve()
                    for relative in old.MEMBERS:
                        target = root / (Path(relative).name if flat else relative)
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes((ROOT / relative).read_bytes())
                    tools = root if flat else root / "tools"
                    if missing:
                        (tools / "project_pointer.py").unlink()
                    done = subprocess.run(
                        [sys.executable, "-B", "-c", program, str(tools), str(ROOT), runtime_site,
                         "missing" if missing else "complete"], cwd=root,
                        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15)
                    self.assertEqual(0, done.returncode, done.stderr)
                    self.assertEqual("CURRENT_POINTER_MISSING_REJECTED" if missing else "CURRENT_POINTER_SAME_TREE_OK",
                                     done.stdout.strip())
