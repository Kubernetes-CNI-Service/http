"""Independent delivery expectation for both fixed backup peers.

This exercises only the real staging function, not a worker/collector import.
It is not a substitute for the real staged-worker workflow.
"""
from __future__ import annotations

import ast
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'test_cases/test_backup_auth_transport_workflow.py'
OWNED_ROOTS = []


class BoundedStagedSiblingDeliveryTests(unittest.TestCase):
    def test_staging_copies_both_fixed_siblings_as_original_regular_files(self):
        # Literal expected set and bytes, never generated from the staging loop.
        expected = {
            'ztp/backup/yaml-collect.py': b'# literal collector marker\n',
            'ztp/backup/_bounded_process.py': b'# literal parent marker\n',
            'ztp/backup/_bounded_process_launcher.py': b'# literal launcher marker\n',
            'ztp/environment_probe.py': b'# literal environment marker\n',
            'ztp/dynamic_air_inventory.py': b'# literal inventory marker\n',
        }
        tree = ast.parse(SOURCE.read_bytes(), filename=str(SOURCE))
        cls = [n for n in tree.body if isinstance(n, ast.ClassDef)
               and n.name == 'BackupAuthenticationWorkflowTests']
        self.assertEqual(len(cls), 1)
        selected = [n for n in cls[0].body if isinstance(n, ast.FunctionDef)
                    and n.name == '_stage_real_collector']
        self.assertEqual(len(selected), 1)
        method = selected[0]
        self.assertEqual([ast.dump(n) for n in method.decorator_list],
                         [ast.dump(ast.Name(id='staticmethod', ctx=ast.Load()))])
        method.decorator_list = []  # Descriptor wrapper only; original body intact.
        with tempfile.TemporaryDirectory(prefix='http-bounded-delivery-') as directory:
            root = Path(directory).resolve()
            value = root.lstat()
            self.assertEqual(stat.S_IMODE(value.st_mode), 0o700)
            self.assertEqual(value.st_uid, os.geteuid())
            OWNED_ROOTS.append((root, (value.st_dev, value.st_ino, value.st_uid)))
            source_root, staged_root = root / 'source', root / 'staged'
            for relative, payload in expected.items():
                path = source_root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)
                path.chmod(0o644)
            namespace = {'ROOT': source_root, 'Path': Path, 'shutil': shutil}
            unit = ast.Module(body=[ast.ImportFrom(module='__future__',
                names=[ast.alias(name='annotations')], level=0), method], type_ignores=[])
            exec(compile(ast.fix_missing_locations(unit), str(SOURCE), 'exec'), namespace)
            collector, output = namespace['_stage_real_collector'](staged_root)
            self.assertEqual(collector, staged_root / 'ztp/backup/yaml-collect.py')
            self.assertTrue(output.is_dir())
            actual = {relative: (staged_root / relative).read_bytes()
                      for relative in expected if (staged_root / relative).is_file()}
            self.assertEqual(actual, expected, 'both fixed helper originals must be staged')
            for relative, payload in expected.items():
                source, target = source_root / relative, staged_root / relative
                image = target.lstat()
                self.assertTrue(stat.S_ISREG(image.st_mode))
                self.assertEqual(image.st_nlink, 1)
                self.assertEqual(image.st_uid, os.geteuid())
                self.assertNotEqual((image.st_dev, image.st_ino),
                                    (source.stat().st_dev, source.stat().st_ino))
                self.assertEqual(target.read_bytes(), payload)
                self.assertEqual(source.read_bytes(), payload)
