"""SOURCE ONLY: independent finite22-hunk inverse expectations; NOT RUN.
Inputs are the fixed reviewed SOURCE packet, never imported production.
"""
import hashlib
from pathlib import Path
import unittest
from test_cases import native_os_safe_image as SUBJECT

SOURCE = Path(__file__).resolve().parent / 'fixtures/ibsw3-source-inverse/os22'
# Independent literals from root-reviewed diff42b166, not SUBJECT's runtime table.
EXPECTED_U = {
    "infiniband/bringup/xdr-upgrade/upgrade-component.sh": "a2bde38c42ff14cc73ed5c5cbd3859701e93a8193eb78ae67f2bd5575393b502",
    "tools/ibsw_upgrade_component.py": "1ab3b4b6bb75f11a01816f35ef788b701df2e16489e4c8054709502fd8f2f2d1",
    "tools/ibsw_upgrade_driver.py": "887a3faf2808cfd2107849825cea2a14fe041f9468987249c5bba07c39030f01",
    "tools/ibsw_upgrade_executor.py": "1736c076376873e2de2a2ce14639cde357bf15f058f0e486fcbf176b5ef02f51"
}
# path, ordinal, Uoffset,Ulength,newOffset,newLength,oldRegionSHA,newRegionSHA
LITERAL_REGIONS = [
    [
        "tools/ibsw_upgrade_driver.py",
        1,
        1211,
        467,
        1211,
        802,
        "015f12e9c5578390915987201696d51ecc5eb7ab55a5a17e90fb9bc287ec18c0",
        "c1f76e35d5103ce44c2d58e3c802dd51b46ecb040b43f511c545bd7d3f4b82c6"
    ],
    [
        "tools/ibsw_upgrade_driver.py",
        2,
        29442,
        124,
        29777,
        3673,
        "fb137f901b950f767d362f32e554e9f6ba610da8bb03c0f52d711bc906b58e23",
        "3a59f9261ce300b80c536bd4dffc1345d8a5e3c6cc77c8de1c9070e42c7170ac"
    ],
    [
        "tools/ibsw_upgrade_driver.py",
        3,
        45237,
        655,
        49121,
        777,
        "a647c57d1d5071cc1943e756c424a704bf045710d1b4ce9bc8f0b16a2409ebc6",
        "3e0998cb0c782015bea97f6ac5dde81be5aa40b781c6962404876e512ae02076"
    ],
    [
        "tools/ibsw_upgrade_driver.py",
        4,
        47200,
        643,
        51206,
        1019,
        "2b0229a3ecdcfa5c6b5d689a8439d205a3dc5d3349c5bd2fa11fd12903d7938e",
        "0de437c49dc63a9c83deda04a1483a0216ebae993253b945046cf909b2ec7446"
    ],
    [
        "tools/ibsw_upgrade_driver.py",
        5,
        139518,
        415,
        143900,
        439,
        "bc349786ccb427ffc7b555145ecd75b800b49b24098fb20a21e52e265cfbf0de",
        "db462ade871c505c882e0de7036bc3d26c8fcbe902b49ab2f76a493b70ab0e20"
    ],
    [
        "tools/ibsw_upgrade_driver.py",
        6,
        144230,
        504,
        148636,
        5994,
        "331b0d32425c345b2f61d88a90711f1d9fe162b9d1c85a71c3068d783a52a622",
        "6b539848e69bc9b78bffa2adf0ee860476e59db3032a78aa9af1cf03ffe9c5e1"
    ],
    [
        "tools/ibsw_upgrade_driver.py",
        7,
        152689,
        580,
        162585,
        590,
        "e7334e65d8916d9bd251d8cacc47cb46c965439af81406b77780f4e3e83525bc",
        "5a76ba402b3bc561307f6fd94a38b87bd01864214bd4ecf905cb9acc9c5b5862"
    ],
    [
        "tools/ibsw_upgrade_driver.py",
        8,
        157167,
        325,
        167073,
        2662,
        "9bf6fe939a54a9c6ab3bc11ddc63f325179bcc2660d6a8cb61b1d299067f3a8b",
        "8985df377fc275d8a522c98113e9edd7a2983ed500ffe20a5a9d8c9934a1ccb4"
    ],
    [
        "tools/ibsw_upgrade_driver.py",
        9,
        188132,
        375,
        200375,
        384,
        "93c16831bfabd4899753d1306b91b15ed44ae4ae09cfdb471c940e2ab21fea71",
        "ede91a8b472b4e48865895a9e9cc41b8188669da1e96cf8e1671342dc5fbffaa"
    ],
    [
        "tools/ibsw_upgrade_driver.py",
        10,
        193425,
        589,
        205677,
        744,
        "d9346dac1c466b101a7806ea4a27ddadabd7e29542134d0c85b146d336ef2e1e",
        "feb2fd7e0dcbfbb7d950f2cb2a4e638b4b407be30271e6c042370b11e6285643"
    ],
    [
        "tools/ibsw_upgrade_driver.py",
        11,
        290157,
        446,
        302564,
        548,
        "2593c6401d6ab6e60076ac870b018e4a8ecc7e151d175c869341f3b8363ad22d",
        "41bca89b8d91ca5aee6f3d1688d6cb867b2fb9849c663041776ec29d7393e05f"
    ],
    [
        "tools/ibsw_upgrade_driver.py",
        12,
        301874,
        315,
        314383,
        10625,
        "b55b90cd00dd36838c3f0aadc45fd1218c15091e0b7a89dcfe278c6b99b140d7",
        "8155ce6736184302fd61df253af8051bf7de9972087bc67c21fcc54562d66d48"
    ],
    [
        "tools/ibsw_upgrade_driver.py",
        13,
        302190,
        266,
        325009,
        893,
        "9bbd207c8fc21fa0d7c41cd9b6eb9a7b23038da9eccbb628d382229d081f30ec",
        "f55309c823d90b96ed4fe0ae8f41d87d5663d52d57c523b4098a41804ce61824"
    ],
    [
        "tools/ibsw_upgrade_executor.py",
        1,
        58414,
        524,
        58414,
        532,
        "b692bc4e89061c2ed9434f48b0ae59a868e892192e178d84a4876c3d13279792",
        "1e9dbd8776f01e677490244cce1fd04d2988ac914720c7acb409de492f630e10"
    ],
    [
        "tools/ibsw_upgrade_executor.py",
        2,
        72371,
        589,
        72379,
        721,
        "2afda40482a352348f9c9e876fb6ed0f71b7d84af44f66ca1a477f4b7004a99c",
        "01158651fe7206384dcd6fccd0bf4c05dc185b17b78dd0c1cf9d10875f5911e3"
    ],
    [
        "tools/ibsw_upgrade_executor.py",
        3,
        93612,
        286,
        93752,
        2046,
        "23f517086270f2388b5a37207ce6d60526df834629ef85ee8df6c6f8fe92abcf",
        "24771c7e8de3be163ecef9d8375397f3698c1c9dc918dcb7c6f7aaf3368da1ac"
    ],
    [
        "tools/ibsw_upgrade_executor.py",
        4,
        97675,
        538,
        99575,
        7465,
        "608b885d643d58447fb15d587803e0221292fffad6d103be7c4e309a3afdebb2",
        "3946f6e85e92c751c23a0e240509008c284b49a32551f661a24797e2821da49c"
    ],
    [
        "tools/ibsw_upgrade_executor.py",
        5,
        102362,
        785,
        111189,
        1039,
        "82ecf8e5ca5e23cc77ae4bcdcc24de4dc553a84c8b2f36144473b69b21e75211",
        "1571f95a87b996ced9a60141cf10a13e720a2d01124d9f1473e0760fb8f1d20e"
    ],
    [
        "tools/ibsw_upgrade_component.py",
        1,
        2744,
        141,
        2744,
        5110,
        "28840fae9e845ac21e740f8128a71f849579424737331a7c2c0ee3955c89f63f",
        "c03dafcad7af6bda281af565fdb5677153d051b989bce22a5c0e72fc655d64ca"
    ],
    [
        "infiniband/bringup/xdr-upgrade/upgrade-component.sh",
        1,
        4813,
        314,
        4813,
        262,
        "a057c0008336a2b051453a0d1aa41b71d313800c8aef1961d99f7eef5d2daa4f",
        "89219e907db7bf6696948a11658855883428649a5ff5013333dc30221a0e9fc5"
    ],
    [
        "infiniband/bringup/xdr-upgrade/upgrade-component.sh",
        2,
        6537,
        221,
        6485,
        1239,
        "8161eab25011de7df58bead05a344afb118a764e21652ce0dbc054a42be2df3d",
        "a450d05b68d218e4ebeeb0d46293b7e2b48e4312e9eb1695638d74ebbebf1e92"
    ],
    [
        "infiniband/bringup/xdr-upgrade/upgrade-component.sh",
        3,
        6948,
        299,
        7914,
        260,
        "21e0a9042d2ef6ed8332fbf5bb6ef76fa4aa8594504d3b566b7a2d31f6972ba4",
        "2b35780a611233545a58b0faa1b18867d9c975fcef079f0bf6d031d00499066c"
    ]
]
OUTSIDE_MIDDLE = {
    "infiniband/bringup/xdr-upgrade/upgrade-component.sh": 5780,
    "tools/ibsw_upgrade_component.py": 12988,
    "tools/ibsw_upgrade_driver.py": 185055,
    "tools/ibsw_upgrade_executor.py": 65662
}


class NativeOsSourceInverseTests(unittest.TestCase):
    def api(self):
        function = getattr(SUBJECT, '_restore_native_os_layer', None)
        self.assertTrue(callable(function), 'finite reviewed native OS inverse API required')
        return function

    def inputs(self, directory):
        return {name: (SOURCE / directory / (name + '.txt')).read_bytes() for name in EXPECTED_U}

    def test_exact_reviewed_four_file_layer_restores_whole_u_bytes(self):
        inverse = self.api()
        before, candidate = self.inputs('before'), self.inputs('candidate')
        self.assertEqual(22, len(LITERAL_REGIONS))
        self.assertEqual([13, 5, 1, 3],
            [sum(row[0] == name for row in LITERAL_REGIONS) for name in (
                'tools/ibsw_upgrade_driver.py', 'tools/ibsw_upgrade_executor.py',
                'tools/ibsw_upgrade_component.py',
                'infiniband/bringup/xdr-upgrade/upgrade-component.sh')])
        for name, pin in EXPECTED_U.items():
            self.assertEqual(pin, hashlib.sha256(before[name]).hexdigest())
        restored = inverse(candidate)
        self.assertEqual(before, restored)
        self.assertEqual(set(EXPECTED_U), set(restored))
        for name, pin in EXPECTED_U.items():
            self.assertEqual(pin, hashlib.sha256(restored[name]).hexdigest())
        self.assertEqual(self.inputs('candidate'), candidate, 'input bytes/map not mutated')

    def test_missing_truncated_duplicate_old_or_reordered_regions_refuse(self):
        inverse = self.api()
        before, candidate = self.inputs('before'), self.inputs('candidate')
        with self.assertRaises(AssertionError):
            inverse(before)  # Layer must not pretend unchanged U has native OS.
        for name, ordinal, oldoff, oldlen, newoff, newlen, oldhash, newhash in LITERAL_REGIONS:
            old = before[name][oldoff:oldoff + oldlen]
            new = candidate[name][newoff:newoff + newlen]
            self.assertEqual(oldhash, hashlib.sha256(old).hexdigest())
            self.assertEqual(newhash, hashlib.sha256(new).hexdigest())
            raw = candidate[name]
            mutations = {
                'missing': raw[:newoff] + raw[newoff + newlen:],
                'truncated': raw[:newoff + newlen - 1] + raw[newoff + newlen:],
                'duplicate': raw + new,
                'extra_old': raw + old,
            }
            for kind, replacement in mutations.items():
                with self.subTest(path=name, ordinal=ordinal, mutation=kind):
                    data = dict(candidate); data[name] = replacement
                    with self.assertRaises(AssertionError):
                        inverse(data)
        for name in EXPECTED_U:
            ordered = [row for row in LITERAL_REGIONS if row[0] == name]
            if len(ordered) < 2:
                continue
            first, second = ordered[:2]
            a, alen, b, blen = first[4], first[5], second[4], second[5]
            raw = candidate[name]
            data = dict(candidate)
            data[name] = (raw[:a] + raw[b:b + blen] + raw[a + alen:b]
                          + raw[a:a + alen] + raw[b + blen:])
            with self.subTest(path=name, mutation='reordered'):
                with self.assertRaises(AssertionError):
                    inverse(data)

    def test_external_prefix_middle_suffix_or_partial_layer_refuse(self):
        inverse = self.api()
        before, candidate = self.inputs('before'), self.inputs('candidate')
        for name in EXPECTED_U:
            raw = candidate[name]
            offset = OUTSIDE_MIDDLE[name]
            self.assertTrue(all(not (row[4] <= offset < row[4] + row[5])
                                for row in LITERAL_REGIONS if row[0] == name))
            mutations = {
                'prefix': b'# UNREVIEWED EXTERNAL PREFIX\\n' + raw,
                'middle': raw[:offset] + bytes([raw[offset] ^ 1]) + raw[offset + 1:],
                'suffix': raw + b'# UNREVIEWED EXTERNAL SUFFIX\\n',
                'partial_layer': before[name],
            }
            for kind, replacement in mutations.items():
                with self.subTest(path=name, mutation=kind):
                    data = dict(candidate); data[name] = replacement
                    with self.assertRaises(AssertionError):
                        inverse(data)
        foreign = dict(candidate); foreign['tools/foreign.py'] = b''
        with self.assertRaises(AssertionError):
            inverse(foreign)
