"""SOURCE ONLY: display2 inverse expectations, not display or native execution."""
import hashlib
from pathlib import Path
import unittest
from test_cases import native_os_safe_image as SUBJECT

SOURCE = Path(__file__).resolve().parent / 'fixtures/ibsw3-source-inverse/display'
ENTRY = 'infiniband/bringup/xdr-upgrade/upgrade.py'
ORIGINAL_SHA = '95f325fadff8d294b3917e23efbdf5540413c12b0d0571911dc268b89a94596f'
# Independent root-reviewed diff literals, not SUBJECT table discovery.
REGIONS = [
    [
        60975,
        583,
        60975,
        743,
        "b9679900bfb5a955819be72dcc665391f3cba50ac958f739db852c5a9038992c",
        "84d4d2a84738d6b5b597f395428db25107a4e7b1c6f4ed7d21b71d4a9d13c14c"
    ],
    [
        103439,
        1027,
        103599,
        1337,
        "80a8982430db3cf32027f17bee84b0d7bc665232847b42beb9353be6ea8b7b00",
        "20c8e6ee045fd4978251b8622e3f0bb9fde1bc07a5f396dbc0059ddcddf1274e"
    ]
]


class NativeDisplaySourceInverseTests(unittest.TestCase):
    def inputs(self):
        return ((SOURCE / 'before' / (ENTRY + '.txt')).read_bytes(),
                (SOURCE / 'candidate' / (ENTRY + '.txt')).read_bytes())

    def api(self):
        function = getattr(SUBJECT, '_restore_native_display_layer', None)
        self.assertTrue(callable(function), 'finite display2 source inverse required')
        return function

    def test_exact_display_two_hunks_restore_complete_original_entry(self):
        inverse = self.api()
        old, new = self.inputs()
        self.assertEqual(2, len(REGIONS))
        self.assertEqual(ORIGINAL_SHA, hashlib.sha256(old).hexdigest())
        self.assertEqual(old, inverse(new))
        self.assertEqual(ORIGINAL_SHA, hashlib.sha256(inverse(new)).hexdigest())
        self.assertEqual(self.inputs()[1], new)

    def test_incomplete_duplicate_reordered_or_external_changes_refuse(self):
        inverse = self.api()
        old, new = self.inputs()
        with self.assertRaises(AssertionError):
            inverse(old)
        for oldoff, oldlen, newoff, newlen, oldhash, newhash in REGIONS:
            oldpart, newpart = old[oldoff:oldoff + oldlen], new[newoff:newoff + newlen]
            self.assertEqual(oldhash, hashlib.sha256(oldpart).hexdigest())
            self.assertEqual(newhash, hashlib.sha256(newpart).hexdigest())
            cases = {
                'missing': new[:newoff] + new[newoff + newlen:],
                'truncated': new[:newoff + newlen - 1] + new[newoff + newlen:],
                'duplicate': new + newpart,
                'extra_old': new + oldpart,
                'partial_old': new[:newoff] + oldpart + new[newoff + newlen:],
            }
            for name, raw in cases.items():
                with self.subTest(region=newoff, mutation=name):
                    with self.assertRaises(AssertionError):
                        inverse(raw)
        a, alen, b, blen = REGIONS[0][2], REGIONS[0][3], REGIONS[1][2], REGIONS[1][3]
        for name, raw in (
                ('reordered', new[:a] + new[b:b + blen] + new[a + alen:b]
                 + new[a:a + alen] + new[b + blen:]),
                ('prefix', b'UNREVIEWED PREFIX' + new),
                ('middle', new[:80000] + bytes([new[80000] ^ 1]) + new[80001:]),
                ('suffix', new + b'UNREVIEWED SUFFIX')):
            with self.subTest(mutation=name):
                with self.assertRaises(AssertionError):
                    inverse(raw)
        self.assertTrue(all(not (row[2] <= 80000 < row[2] + row[3]) for row in REGIONS))


# New wording contract is a separate pre-layer, not a change to display2 pins.
WORDING_REGIONS = (
    (6210, 6210,
     b'                "Same-source input symlinks are supported; load/setup is not required. HTTP only. "\n',
     b'                "Same-source input symlinks are supported; load/setup is not required. "\n'
     b'                "HTTP is the default transfer; SCP requires explicit selection. "\n'
     b'                "HTTPS is unsupported; no automatic transport fallback. "\n'),
    (30250, 30395,
     b'    "project HTTP is not enabled": ("HTTP_POLICY", "HTTP is disabled in global; enable the approved project HTTP configuration before continuing. This entry supports HTTP only; HTTPS, SCP and local are not fallback transports."),\n',
     b'    "project HTTP is not enabled": ("HTTP_POLICY", "HTTP is disabled in global; enable the approved project HTTP configuration before continuing. HTTP mode does not fall back to SCP, HTTPS or local transport."),\n'),
)
WORDING_BEFORE_SHA = '5fc48f933cdeaa4defd4414941c5e29d2f7e4836095dae4bb97b31ed29232efe'


class NativeTransferWordingInverseTests(unittest.TestCase):
    def inputs(self):
        old = (SOURCE / 'candidate' / (ENTRY + '.txt')).read_bytes()
        new = (Path(__file__).resolve().parents[1] / ENTRY).read_bytes()
        self.assertEqual(WORDING_BEFORE_SHA, hashlib.sha256(old).hexdigest())
        return old, new

    def inverse(self):
        function = getattr(SUBJECT, '_restore_native_transfer_wording_layer', None)
        self.assertTrue(callable(function), 'strict independent wording2 pre-inverse is required')
        return function

    def test_exact_two_wording_regions_restore_whole_previous_entry(self):
        inverse = self.inverse()
        old, new = self.inputs()
        self.assertNotEqual(old, new)
        for a, b, before, after in WORDING_REGIONS:
            self.assertEqual(before, old[a:a + len(before)])
            self.assertEqual(after, new[b:b + len(after)])
            self.assertEqual(1, new.count(after))
            self.assertEqual(0, new.count(before))
        self.assertEqual(old, inverse(new))
        self.assertEqual(WORDING_BEFORE_SHA, hashlib.sha256(inverse(new)).hexdigest())

    def test_old_partial_duplicate_reordered_and_external_wording_changes_refuse(self):
        inverse = self.inverse()
        old, new = self.inputs()
        with self.assertRaises(AssertionError):
            inverse(old)
        for _a, b, before, after in WORDING_REGIONS:
            for label, raw in (
                ('missing', new[:b] + new[b + len(after):]),
                ('truncated', new[:b + len(after) - 1] + new[b + len(after):]),
                ('partial_old', new[:b] + before + new[b + len(after):]),
                ('duplicate', new + after), ('extra_old', new + before),
            ):
                with self.subTest(offset=b, mutation=label), self.assertRaises(AssertionError):
                    inverse(raw)
        a, b = WORDING_REGIONS
        for label, raw in (
            ('reordered', new[:a[1]] + b[3] + new[a[1] + len(a[3]):b[1]] + a[3] + new[b[1] + len(b[3]):]),
            ('prefix', b'OUTSIDE PREFIX' + new),
            ('middle', new[:50000] + bytes([new[50000] ^ 1]) + new[50001:]),
            ('suffix', new + b'OUTSIDE SUFFIX'),
        ):
            with self.subTest(mutation=label), self.assertRaises(AssertionError):
                inverse(raw)
        self.assertTrue(all(not b <= 50000 < b + len(after) for _, b, _, after in WORDING_REGIONS))
