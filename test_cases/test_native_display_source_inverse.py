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

# Operator-usability pre-layer above wording2: independent review table of the
# diff from the previous entry, generated from git (not from SUBJECT tables).
# BEGIN GENERATED USABILITY REVIEW TABLE
# context=3 lines, 11 hunks. Never edit by hand.
# [previous offset, previous length, candidate offset, candidate length,
#  previous sha256, candidate sha256]
USABILITY_BEFORE_SHA = 'a09290b10ec18886fe61bce831739f51642f1a702e76511be88cff23c120b358'
USABILITY_REGIONS = [
    [6637, 961, 6637, 1396, '2fcd7f5d910ef61ab63f768d3795b6bbf3b6bfb6b0d352a6a5128a9f1fa48e62', '9f62144891b4ca38708891646ab10be821b2a00d8db1aec40efd8711927b1dc5'],
    [25216, 347, 25651, 9523, '0677aa8aa0ab2134fd0729376ebe0a8b1114899e5765829ef4285e4e16fe5343', 'a0ae6566a59c072af2fa0e104a5a92ad0b6f012a7b6998d7e202197932d91354'],
    [37270, 205, 46881, 3047, '71f6f4f97763c34942a28cd7dc5812b7277ebc35b3946726c3dcfc09703e4468', '1da30ad6218d8545a8fd7024573ec0d1659394c6f4ce0d60f31fe53959c7b223'],
    [51345, 527, 63798, 716, '867a279b7686bd17134ed0e8a7e86a4f2f591bc78098919bd02341c3633d13c0', '9b06910826ca551896a66554198cd5b9f486ca4e0958ea4bf9bda04a34727057'],
    [109306, 348, 121948, 6929, '6c5ad6517a5725eb17cf7f259922a00066defaab7ebb834748602f6e84031a68', 'c23e9e3309ffc76767961536c1c9c7e947a5de838c52b53797924eed3b4852ac'],
    [116255, 380, 135478, 394, '57343328d6b8ca3f7d1166073fb9f73534f57042f2e467a2ea9c80a8176a9c01', 'dd61f0dcf9b64731bada0324d31b8f094ec1244527340d43e4793d1c14fec726'],
    [117953, 491, 137190, 647, '3c97b940b55f8cf90ad4707fbc06fe4fe1e254ed35549f0f65add6eb14403804', '9e4809574144b90a2dd1082493e18c492089d21cfae868511289f20c0acd7399'],
    [120910, 372, 140303, 534, '13578c01632f75d076c6fef799a5ae2356350e842f848898dbb365a84234e007', '3cab175b041d0a6e212d446788d012446dbc6d3b6e97d16250abf11c1139f0ed'],
    [125527, 408, 145082, 794, '800ca2d4639258ff48461e0ba62e5e96115b1fd96ec9b5661ef64ecd7cfe1479', 'c46f39d216c2be453b1e04bc02a3f4e947c1dcfb03481358c439f0b46eca0b39'],
    [130664, 724, 150605, 1093, '4f36e953db0c1367589ec163a391ca90c262a38640c5a1cf2bd5b423154cf6d0', 'b64892e8a280dde54026fa559ca3e2241d4f26afef8c09ab3f04b13b30f172ad'],
    [132250, 168, 152560, 202, '15bdbed4b0411d04f00bb8a65b6f28186ebd6e34e7d3eccff55257f1d6cb9c9c', '1ad90429c9772a1a77a8d0729c1344a6557fcc834a11945a86a2ed3a84c9297f'],
]
# END GENERATED USABILITY REVIEW TABLE


def _live_entry():
    return (Path(__file__).resolve().parents[1] / ENTRY).read_bytes()


class NativeTransferWordingInverseTests(unittest.TestCase):
    def inputs(self):
        old = (SOURCE / 'candidate' / (ENTRY + '.txt')).read_bytes()
        # wording2's candidate is the previous entry under the reviewed
        # usability pre-layer; remove exactly that layer first.
        new = SUBJECT._restore_native_usability_layer(_live_entry())
        self.assertEqual(USABILITY_BEFORE_SHA, hashlib.sha256(new).hexdigest())
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


class NativeUsabilityInverseTests(unittest.TestCase):
    """The live entry is the previous entry plus exactly the reviewed usability hunks."""

    def inverse(self):
        function = getattr(SUBJECT, '_restore_native_usability_layer', None)
        self.assertTrue(callable(function), 'strict usability pre-inverse is required')
        return function

    def inputs(self):
        new = _live_entry()
        old = self.inverse()(new)
        self.assertEqual(USABILITY_BEFORE_SHA, hashlib.sha256(old).hexdigest())
        return old, new

    def test_exact_usability_hunks_restore_the_whole_previous_entry(self):
        old, new = self.inputs()
        self.assertTrue(USABILITY_REGIONS, 'reviewed usability table required')
        self.assertEqual(len(USABILITY_REGIONS), len(SUBJECT._NATIVE_USABILITY_REGIONS))
        self.assertEqual(USABILITY_BEFORE_SHA, SUBJECT._NATIVE_USABILITY_BEFORE_SHA256)
        rebuilt, cursor = [], 0
        for oldoff, oldlen, newoff, newlen, oldhash, newhash in USABILITY_REGIONS:
            oldpart, newpart = old[oldoff:oldoff + oldlen], new[newoff:newoff + newlen]
            self.assertEqual(oldhash, hashlib.sha256(oldpart).hexdigest())
            self.assertEqual(newhash, hashlib.sha256(newpart).hexdigest())
            self.assertEqual(1, new.count(newpart))
            self.assertEqual(0, new.count(oldpart))
            rebuilt.extend((old[cursor:oldoff], newpart))
            cursor = oldoff + oldlen
        rebuilt.append(old[cursor:])
        # Forward: outside the reviewed hunks the live entry is byte-identical.
        self.assertEqual(new, b''.join(rebuilt))
        # The restored entry is exactly wording2's candidate, so the older
        # layers and the unchanged U pin still apply underneath.
        self.assertEqual(WORDING_BEFORE_SHA,
                         hashlib.sha256(SUBJECT._restore_native_transfer_wording_layer(old)).hexdigest())
        self.assertEqual(ORIGINAL_SHA, hashlib.sha256(SUBJECT._restore_native_display_layer(
            SUBJECT._restore_native_transfer_wording_layer(old))).hexdigest())

    def test_previous_partial_duplicate_reordered_and_external_changes_refuse(self):
        inverse = self.inverse()
        old, new = self.inputs()
        with self.assertRaises(AssertionError):
            inverse(old)
        for oldoff, oldlen, newoff, newlen, _oldhash, _newhash in USABILITY_REGIONS:
            oldpart, newpart = old[oldoff:oldoff + oldlen], new[newoff:newoff + newlen]
            for label, raw in (
                ('missing', new[:newoff] + new[newoff + newlen:]),
                ('truncated', new[:newoff + newlen - 1] + new[newoff + newlen:]),
                ('partial_old', new[:newoff] + oldpart + new[newoff + newlen:]),
                ('duplicate', new + newpart), ('extra_old', new + oldpart),
            ):
                with self.subTest(offset=newoff, mutation=label), self.assertRaises(AssertionError):
                    inverse(raw)
        outside = 1000
        self.assertTrue(all(not row[2] <= outside < row[2] + row[3] for row in USABILITY_REGIONS))
        for label, raw in (
            ('prefix', b'OUTSIDE PREFIX' + new),
            ('middle', new[:outside] + bytes([new[outside] ^ 1]) + new[outside + 1:]),
            ('suffix', new + b'OUTSIDE SUFFIX'),
        ):
            with self.subTest(mutation=label), self.assertRaises(AssertionError):
                inverse(raw)
        if len(USABILITY_REGIONS) > 1:
            first, second = USABILITY_REGIONS[0], USABILITY_REGIONS[1]
            a, alen, b, blen = first[2], first[3], second[2], second[3]
            reordered = new[:a] + new[b:b + blen] + new[a + alen:b] + new[a:a + alen] + new[b + blen:]
            with self.subTest(mutation='reordered'), self.assertRaises(AssertionError):
                inverse(reordered)
