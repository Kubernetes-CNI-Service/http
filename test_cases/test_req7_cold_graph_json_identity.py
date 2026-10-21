"""Independent graph JSON-shape fixture regression SOURCE; NOT RUN."""
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

from test_cases import cold_completed_original_attach_fixture as f


class ColdGraphJsonIdentityTests(unittest.TestCase):
    def test_graph_stat9_is_original_decimal_json_list_and_roundtrips_exactly(self):
        with tempfile.TemporaryDirectory(prefix='req7-graph-json-direct-') as name:
            root = Path(name)
            payload = root / 'payload'
            payload.write_bytes(b'FIXED-GRAPH-CONTENT')
            payload.chmod(0o600)
            (root / 'alias').symlink_to('payload')
            before = {relative: os.lstat(root if relative == '.' else root / relative)
                      for relative in ('.', 'alias', 'payload')}
            rows = f.graph(root)
            self.assertEqual(['.', 'alias', 'payload'], [row['path'] for row in rows])
            for row in rows:
                actual = before[row['path']]
                expected = [
                    str(actual.st_dev), str(actual.st_ino), str(actual.st_mode),
                    str(actual.st_nlink), str(actual.st_uid), str(actual.st_gid),
                    str(actual.st_size), str(actual.st_mtime_ns), str(actual.st_ctime_ns),
                ]
                self.assertIs(type(row['identity']), list)
                self.assertEqual(9, len(row['identity']))
                self.assertTrue(all(type(value) is str for value in row['identity']))
                self.assertEqual(expected, row['identity'])
                self.assertEqual(expected, [
                    str(getattr(os.lstat(root if row['path'] == '.' else root / row['path']), key))
                    for key in ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid',
                                'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
                ])
            self.assertEqual(rows, json.loads(json.dumps(rows)))
            self.assertEqual(rows, f.graph(root))

    def test_same_bytes_replacement_cannot_equal_original_json_graph(self):
        with tempfile.TemporaryDirectory(prefix='req7-graph-inode-direct-') as name:
            root = Path(name)
            payload = root / 'payload'
            replacement = root / 'replacement'
            literal = b'FIXED-GRAPH-CONTENT'
            payload.write_bytes(literal)
            payload.chmod(0o600)
            original = json.loads(json.dumps(f.graph(root)))
            original_info = os.lstat(payload)
            replacement.write_bytes(literal)
            replacement.chmod(stat.S_IMODE(original_info.st_mode))
            replacement_info = os.lstat(replacement)
            self.assertNotEqual((original_info.st_dev, original_info.st_ino),
                                (replacement_info.st_dev, replacement_info.st_ino))
            os.replace(replacement, payload)
            self.assertEqual(literal, payload.read_bytes())
            observed = f.graph(root)
            original_file = next(row for row in original if row['path'] == 'payload')
            observed_file = next(row for row in observed if row['path'] == 'payload')
            self.assertEqual(original_file['sha256'], observed_file['sha256'])
            self.assertNotEqual(original_file['identity'], observed_file['identity'])
            self.assertNotEqual(original, observed)
