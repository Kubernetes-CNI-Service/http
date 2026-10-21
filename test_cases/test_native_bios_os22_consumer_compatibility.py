"""SOURCE ONLY DATA regression: old OS22 UNIT seam remains independent of B2."""
import hashlib
import unittest
from unittest.mock import patch
from test_cases import test_ibsw225_runtime_source_manifest_contract as SUBJECT

D = 'tools/ibsw_upgrade_driver.py'
E = 'tools/ibsw_upgrade_executor.py'
C = 'tools/ibsw_upgrade_component.py'
T = 'infiniband/bringup/xdr-upgrade/upgrade-component.sh'
PATHS = (D, E, C, T)

class BiosOs22ConsumerCompatibilityTests(unittest.TestCase):
    def test_independent_os22_literals_coexist_with_strict_optional_bios_layer(self):
        function = getattr(SUBJECT, '_native_os_sources_before_native34', None)
        self.assertTrue(callable(function), 'source DATA consumer required')
        # Explicit synthetic UNIT tables: not production files, native permit,
        # caller verifier or a replacement compiled-source producer.
        u = b'left\nU-A\nmid\nU-B\nright\n'
        p = b'left\nP-A\nmid\nP-B\nright\n'
        b2 = b'left\nB-A-X\nmid\nP-B\nright\n'
        os_regions = (
            (1, 5, 5, b'U-A\n', b'P-A\n', 0),
            (2, 13, 13, b'U-B\n', b'P-B\n', 0),
        )
        bios_regions = ((1, 5, 5, b'P-A\n', b'B-A-X\n', 0),)
        originals = {path: u for path in PATHS}
        previous = {path: p for path in PATHS}
        bios = {D: b2, E: b2, C: p, T: p}
        with patch.dict(SUBJECT._NATIVE_OS_EXPECTED_U,
                        {path: hashlib.sha256(u).hexdigest() for path in PATHS}, clear=True), \
                patch.dict(SUBJECT._NATIVE_OS_REGIONS,
                        {path: os_regions for path in PATHS}, clear=True), \
                patch.dict(SUBJECT._BIOS_TARGETS,
                        {path: hashlib.sha256(p).hexdigest() for path in (D, E)}, clear=True), \
                patch.dict(SUBJECT._BIOS_REGIONS,
                        {D: bios_regions, E: bios_regions}, clear=True):
            self.assertEqual(originals, function(originals))
            self.assertEqual(originals, function(previous))
            self.assertEqual(originals, function(bios))
            mutations = {
                'mixed-P-B2': {D: p, E: b2, C: p, T: p},
                'mixed-U-B2': {D: u, E: b2, C: p, T: p},
                'truncated-no-complete-B2-region': dict(bios, **{D: b2.replace(b'B-A-X\n', b'B-A-X', 1),
                                                              E: b2.replace(b'B-A-X\n', b'B-A-X', 1)}),
                'missing-no-complete-B2-region': dict(bios, **{D: b2.replace(b'B-A-X\n', b'', 1),
                                                            E: b2.replace(b'B-A-X\n', b'', 1)}),
                'duplicate-B2-region': dict(bios, **{D: b2 + b'B-A-X\n'}),
                'extra-old-region': dict(bios, **{D: b2 + b'P-A\n'}),
                'B2-outside-prefix': dict(bios, **{D: b'!' + b2[1:]}),
                'B2-outside-middle': dict(bios, **{D: b2.replace(b'mid\n', b'Mid\n', 1)}),
                'B2-outside-suffix': dict(bios, **{D: b2[:-1] + b'!'}),
                'P-outside-suffix': dict(previous, **{D: p[:-1] + b'!'}),
            }
            for label, vector in mutations.items():
                with self.subTest(mutation=label), self.assertRaises(AssertionError):
                    function(vector)
