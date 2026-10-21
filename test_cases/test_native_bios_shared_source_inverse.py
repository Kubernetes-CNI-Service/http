"""SOURCE ONLY shared B2 pre-layer independent DATA UNIT2, never IO/grant."""
import hashlib
import unittest
from unittest.mock import patch
from test_cases import native_os_safe_image as IMAGE
from test_cases import test_ibsw225_runtime_source_manifest_contract as ORACLE

D = 'tools/ibsw_upgrade_driver.py'
E = 'tools/ibsw_upgrade_executor.py'
U = {
    D: '887a3faf2808cfd2107849825cea2a14fe041f9468987249c5bba07c39030f01',
    E: '1736c076376873e2de2a2ce14639cde357bf15f058f0e486fcbf176b5ef02f51',
}
P = {
    D: '0f3670ad74a46147bd13d29d894aa5bb554ed8574ba4bd51239e0913d99a0dd5',
    E: '31bb2577b9817a7cf3e105e64119bc6b1d49f3fbc8531e83ae1664526741036f',
}
# Copied approved B2-REGIONS.json from zDh packet, not runtime output.
LITERAL_ROSTER = [
    {
        "path": "tools/ibsw_upgrade_driver.py",
        "ordinal": 1,
        "old_offset": 49121,
        "new_offset": 49121,
        "old_length": 676,
        "new_length": 694,
        "old_sha256": "86d3cd8001a00352a8a2240b9e874d1df93dbdaa5f58ef26b5c2d77dd2f83cde",
        "new_sha256": "ec5a3aa26d796cf1f0502d52e339bc4dc5439805aef3f6573b9a7655a2dc1418",
        "retained_old": 0
    },
    {
        "path": "tools/ibsw_upgrade_driver.py",
        "ordinal": 2,
        "old_offset": 143900,
        "new_offset": 143918,
        "old_length": 439,
        "new_length": 447,
        "old_sha256": "db462ade871c505c882e0de7036bc3d26c8fcbe902b49ab2f76a493b70ab0e20",
        "new_sha256": "96bc26f568bb15e992e9f61965b548586e7b44bf86e1546cbf320efe602d90c9",
        "retained_old": 0
    },
    {
        "path": "tools/ibsw_upgrade_driver.py",
        "ordinal": 3,
        "old_offset": 205677,
        "new_offset": 205703,
        "old_length": 652,
        "new_length": 670,
        "old_sha256": "08d641fb6dd29c0d867f16955ce1ecd307db64ef866fe2f67fe45c714a162f7a",
        "new_sha256": "2975b025d545c5fef99a5ab57e9f246f089d97e47411da70f7b9c974e5fea5e4",
        "retained_old": 0
    },
    {
        "path": "tools/ibsw_upgrade_driver.py",
        "ordinal": 4,
        "old_offset": 302564,
        "new_offset": 302608,
        "old_length": 548,
        "new_length": 572,
        "old_sha256": "41bca89b8d91ca5aee6f3d1688d6cb867b2fb9849c663041776ec29d7393e05f",
        "new_sha256": "88e3773604677270109162471403f92dce1b49a077dd81267a3722bfd1eeb345",
        "retained_old": 0
    },
    {
        "path": "tools/ibsw_upgrade_executor.py",
        "ordinal": 1,
        "old_offset": 58414,
        "new_offset": 58414,
        "old_length": 532,
        "new_length": 540,
        "old_sha256": "1e9dbd8776f01e677490244cce1fd04d2988ac914720c7acb409de492f630e10",
        "new_sha256": "ef8e35f60272ef7de8d4948f650839cb563538c8a339477c2ec58515ed54bf3e",
        "retained_old": 0
    },
    {
        "path": "tools/ibsw_upgrade_executor.py",
        "ordinal": 2,
        "old_offset": 72379,
        "new_offset": 72387,
        "old_length": 721,
        "new_length": 744,
        "old_sha256": "01158651fe7206384dcd6fccd0bf4c05dc185b17b78dd0c1cf9d10875f5911e3",
        "new_sha256": "6ba6549884435ed675188cfbf119abaa50d8e9f61a84ee4dff4f51eeb9d06842",
        "retained_old": 0
    }
]

class SharedBiosPrelayerTests(unittest.TestCase):
    def API(self, subject):
        function = getattr(subject, '_strip_bios_source_layer', None)
        self.assertTrue(callable(function), 'MISSING_SHARED_B2_PRELAYER_API: DATA capability only')
        return function

    def literal_inputs(self, subject):
        u = {D: b'UPSTREAM-DRIVER\n', E: b'UPSTREAM-EXECUTOR\n'}
        p = {D: b'left\nOLD-A\nmid\nOLD-B\nright\n', E: b'left\nOLD-A\nmid\nOLD-B\nright\n'}
        b2 = {D: b'left\nNEW-A-X\nmid\nNEW-B-X\nright\n', E: b'left\nNEW-A-X\nmid\nNEW-B-X\nright\n'}
        regions = (
            (1, 5, 5, b'OLD-A\n', b'NEW-A-X\n', 0),
            (2, 15, 17, b'OLD-B\n', b'NEW-B-X\n', 0),
        )
        return u, p, b2, regions

    def test_literal_old_pins_six_regions_and_all_u_all_p_b2_branches(self):
        for subject in (IMAGE, ORACLE):
            with self.subTest(subject=subject.__name__):
                function = self.API(subject)
                self.assertEqual(U, subject._BIOS_U_TARGETS)
                self.assertEqual(P, subject._BIOS_TARGETS)
                self.assertEqual((4, 2), tuple(map(len, subject._BIOS_REGIONS.values())))
                actual = []
                for path, regions in subject._BIOS_REGIONS.items():
                    for ordinal, old_offset, new_offset, old, new, retained in regions:
                        actual.append(dict(path=path, ordinal=ordinal, old_offset=old_offset,
                            new_offset=new_offset, old_length=len(old), new_length=len(new),
                            old_sha256=hashlib.sha256(old).hexdigest(),
                            new_sha256=hashlib.sha256(new).hexdigest(), retained_old=retained))
                self.assertEqual(LITERAL_ROSTER, actual)
                u, p, b2, regions = self.literal_inputs(subject)
                upins = {path: hashlib.sha256(raw).hexdigest() for path, raw in u.items()}
                ppins = {path: hashlib.sha256(raw).hexdigest() for path, raw in p.items()}
                with patch.dict(subject._BIOS_U_TARGETS, upins, clear=True), \
                        patch.dict(subject._BIOS_TARGETS, ppins, clear=True), \
                        patch.dict(subject._BIOS_REGIONS, {D: regions, E: regions}, clear=True):
                    self.assertEqual(u, function(u))
                    self.assertEqual(p, function(p))
                    self.assertEqual(p, function(b2))
                    with self.assertRaises(AssertionError):
                        subject._restore_bios_layer(u)
                    with self.assertRaises(AssertionError):
                        subject._restore_bios_layer(p)

    def test_mixed_missing_partial_duplicate_reordered_and_outside_changes_refuse(self):
        for subject in (IMAGE, ORACLE):
            with self.subTest(subject=subject.__name__):
                function = self.API(subject)
                u, p, b2, regions = self.literal_inputs(subject)
                with patch.dict(subject._BIOS_U_TARGETS,
                                {k: hashlib.sha256(v).hexdigest() for k, v in u.items()}, clear=True), \
                        patch.dict(subject._BIOS_TARGETS,
                                {k: hashlib.sha256(v).hexdigest() for k, v in p.items()}, clear=True), \
                        patch.dict(subject._BIOS_REGIONS, {D: regions, E: regions}, clear=True):
                    vectors = {
                        'U-P': {D: u[D], E: p[E]}, 'P-U': {D: p[D], E: u[E]},
                        'U-B2': {D: u[D], E: b2[E]}, 'B2-U': {D: b2[D], E: u[E]},
                        'P-B2': {D: p[D], E: b2[E]}, 'B2-P': {D: b2[D], E: p[E]},
                        'missing': {D: b2[D]},
                        'foreign': dict(b2, **{'tools/foreign.py': b'foreign'}),
                        'wrongtype': {D: bytearray(b2[D]), E: b2[E]},
                    }
                    mutations = {
                        'missing-region': b2[D].replace(b'NEW-A-X\n', b'', 1),
                        'truncated-region': b2[D].replace(b'NEW-A-X\n', b'NEW-A-X', 1),
                        'duplicate-region': b2[D] + b'NEW-A-X\n',
                        'extra-old-region': b2[D] + b'OLD-A\n',
                        'reordered': b'left\nNEW-B-X\nmid\nNEW-A-X\nright\n',
                        'outside-prefix': b'!' + b2[D][1:],
                        'outside-middle': b2[D].replace(b'mid\n', b'Mid\n', 1),
                        'outside-suffix': b2[D][:-1] + b'!',
                    }
                    vectors.update({k: {D: v, E: b2[E]} for k, v in mutations.items()})
                    for label, vector in vectors.items():
                        with self.subTest(mutation=label), self.assertRaises(AssertionError):
                            function(vector)
