"""Two real validators share FD checks but never dependency identity types."""
from contextlib import ExitStack
from importlib import metadata
from pathlib import Path
import sys,tempfile,unittest
from unittest import mock

from test_cases import test_req7_cable_dependency as cases

class CableDependencyWorkflowTests(unittest.TestCase):
    def test_real_legacy_and_cable_contracts_coexist_with_actual_local_metadata_without_sdk_import(self):
        module=cases.load()
        from tools import req7_dependency_contract as legacy
        root=Path(legacy.__file__).resolve().parents[1]
        old=legacy.load_dependency_contract(root)
        old_identity=legacy.installed_dependency_identity(old)
        new=module.load_cable_dependency_contract(cases.ROOT)
        with mock.patch('importlib.import_module',side_effect=AssertionError('SDK import forbidden')):
            new_identity=module.installed_cable_dependency_identity(new)
        expected=cases.PINS+((('typing_extensions','4.16.0'),) if sys.version_info[:2]<(3,11) else ())
        self.assertEqual(new_identity.versions,expected)
        self.assertEqual(old_identity.versions[:6],legacy.PINS)
        self.assertNotEqual(type(new_identity),type(old_identity))
        self.assertNotEqual(new_identity.policy_sha256,old_identity.policy_sha256)
        self.assertEqual(len(legacy.PINS),6)
        for name,version in legacy.PINS:self.assertEqual(dict(cases.PINS)[name],version)
        self.assertFalse(hasattr(new_identity,'permit'))

    def test_shared_real_fd_reader_refuses_same_byte_policy_rebind_between_pair_and_final_read(self):
        module=cases.load()
        from tools import req7_dependency_contract as legacy
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve(strict=True)
            policy=root/cases.POLICY_PATH;lock=root/cases.LOCK_PATH
            policy.parent.mkdir(parents=True)
            policy.write_bytes(cases.policy_bytes());lock.write_bytes(cases.lock_bytes())
            original=legacy.os.read;changed=[]
            def interleaved(fd,size):
                raw=original(fd,size)
                if raw==cases.lock_bytes() and not changed:
                    replacement=root/'new-policy.json';replacement.write_bytes(cases.policy_bytes())
                    replacement.replace(policy);changed.append(True)
                return raw
            with mock.patch.object(legacy.os,'read',side_effect=interleaved),self.assertRaises(module.CableDependencyContractError):
                module.load_cable_dependency_contract(root)
            self.assertEqual(changed,[True])

if __name__=='__main__':unittest.main()
