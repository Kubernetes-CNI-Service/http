"""Independent local DATA fixtures; no ambient private SOURCE packet required."""
import hashlib
from pathlib import Path
import unittest
from test_cases import test_native_os_source_inverse as OS
from test_cases import test_native_display_source_inverse as DISPLAY

EXPECTED = {
 'os22/before/tools/ibsw_upgrade_driver.py.txt':'887a3faf2808cfd2107849825cea2a14fe041f9468987249c5bba07c39030f01',
 'os22/before/tools/ibsw_upgrade_executor.py.txt':'1736c076376873e2de2a2ce14639cde357bf15f058f0e486fcbf176b5ef02f51',
 'os22/before/tools/ibsw_upgrade_component.py.txt':'1ab3b4b6bb75f11a01816f35ef788b701df2e16489e4c8054709502fd8f2f2d1',
 'os22/before/infiniband/bringup/xdr-upgrade/upgrade-component.sh.txt':'a2bde38c42ff14cc73ed5c5cbd3859701e93a8193eb78ae67f2bd5575393b502',
 'os22/candidate/tools/ibsw_upgrade_driver.py.txt':'0f3670ad74a46147bd13d29d894aa5bb554ed8574ba4bd51239e0913d99a0dd5',
 'os22/candidate/tools/ibsw_upgrade_executor.py.txt':'31bb2577b9817a7cf3e105e64119bc6b1d49f3fbc8531e83ae1664526741036f',
 'os22/candidate/tools/ibsw_upgrade_component.py.txt':'95339d60968b36ccf6139e0349d0e0cdfcd8a0d5829c7039b4e41852c817795d',
 'os22/candidate/infiniband/bringup/xdr-upgrade/upgrade-component.sh.txt':'53de009cb6031d2892b631475797c64238bff0599d8c062214b33107ee3cbc5f',
 'display/before/infiniband/bringup/xdr-upgrade/upgrade.py.txt':'95f325fadff8d294b3917e23efbdf5540413c12b0d0571911dc268b89a94596f',
 'display/candidate/infiniband/bringup/xdr-upgrade/upgrade.py.txt':'5fc48f933cdeaa4defd4414941c5e29d2f7e4836095dae4bb97b31ed29232efe',
}

class SourceInverseFixturePortabilityTests(unittest.TestCase):
    def test_exact_ten_local_data_sources_replace_ambient_tmp_inputs(self):
        base=Path(__file__).resolve().parent/'fixtures/ibsw3-source-inverse'
        self.assertEqual(base/'os22',OS.SOURCE,'OS inverse must not depend on ambient private packet')
        self.assertEqual(base/'display',DISPLAY.SOURCE,'display inverse must not depend on ambient private packet')
        self.assertEqual(10,len(EXPECTED))
        actual={str(p.relative_to(base)) for p in base.rglob('*') if p.is_file()}
        self.assertEqual(set(EXPECTED),actual)
        for rel,wanted in EXPECTED.items():
            with self.subTest(original=rel):
                p=base/rel
                self.assertTrue(p.is_file() and not p.is_symlink())
                self.assertEqual(p,p.resolve())
                self.assertEqual(wanted,hashlib.sha256(p.read_bytes()).hexdigest())
        original=OS.NativeOsSourceInverseTests()
        for epoch in ('before','candidate'):
            values=original.inputs(epoch)
            for name,value in values.items():
                self.assertEqual((base/'os22'/epoch/(name+'.txt')).read_bytes(),value)
        self.assertEqual(tuple((base/'display'/epoch/(DISPLAY.ENTRY+'.txt')).read_bytes()
                              for epoch in ('before','candidate')),
                         DISPLAY.NativeDisplaySourceInverseTests().inputs())
