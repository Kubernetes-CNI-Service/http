"""REQ7 IB expected-topology identity is the CVT bytes, not a release ID."""

from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


class IbCvtProvenanceDirectTests(unittest.TestCase):
    def test_standalone_digest_refuses_nonregular_leaf_before_attempting_open(self):
        from ztp.config import ib_topology_provenance as provenance
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); source = root / 'owned-pipe'
            os.mkfifo(source, mode=0o600)
            original_open = os.open; attempts = []
            def opening(path, flags, *args, **kwargs):
                if str(path) in (str(source), source.name):
                    attempts.append(str(path))
                    raise AssertionError('a blocking nonregular leaf open was attempted')
                return original_open(path, flags, *args, **kwargs)
            with mock.patch.object(os, 'open', side_effect=opening):
                with self.assertRaises(provenance.ProvenanceError):
                    provenance._regular_digest(source)
            self.assertEqual([], attempts)

    def test_regular_digest_borrows_live_ancestors_without_reopening_each_read(self):
        from tools import ufm_collection_pipeline as pipeline
        from ztp.config import ib_topology_provenance as provenance
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); source = root / 'independent-input'
            source.write_bytes(b'independent input bytes')
            expected = hashlib.sha256(b'independent input bytes').hexdigest()
            real_open = os.open; opened = []
            def opening(path, flags, *args, **kwargs):
                descriptor = real_open(path, flags, *args, **kwargs)
                opened.append(descriptor); return descriptor
            with mock.patch.object(provenance.os, 'open', side_effect=opening):
                with pipeline._hold_reusable_directory_reads():
                    for _ in range(32): self.assertEqual(expected, provenance._regular_digest(source))
                self.assertEqual(len(root.parts) + 32, len(opened),
                    'each original ancestor opens once; each actual file read still opens its own FD')

    def test_regular_digest_scope_does_not_reuse_old_content_after_inplace_write(self):
        from tools import ufm_collection_pipeline as pipeline
        from ztp.config import ib_topology_provenance as provenance
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); source = root / 'independent-input'
            source.write_bytes(b'original'); before = source.stat()
            with pipeline._hold_reusable_directory_reads():
                self.assertEqual(hashlib.sha256(b'original').hexdigest(), provenance._regular_digest(source))
                source.write_bytes(b'modified'); os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns))
                self.assertEqual(before.st_ino, source.stat().st_ino)
                self.assertEqual(hashlib.sha256(b'modified').hexdigest(), provenance._regular_digest(source))

    def test_regular_digest_borrow_refuses_same_leaf_after_original_parent_rebind(self):
        from tools import ufm_collection_pipeline as pipeline
        from ztp.config import ib_topology_provenance as provenance
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); parent = root / 'parent'; parent.mkdir()
            source = parent / 'independent-input'; source.write_bytes(b'original')
            original = source.stat().st_ino; reached = []
            with self.assertRaises(pipeline.PipelineError):
                with pipeline._hold_reusable_directory_reads():
                    self.assertEqual(hashlib.sha256(b'original').hexdigest(), provenance._regular_digest(source))
                    moved = root / 'moved'; parent.rename(moved); parent.mkdir()
                    (moved / source.name).rename(source)
                    self.assertEqual(original, source.stat().st_ino)
                    with self.assertRaises(provenance.ProvenanceError): provenance._regular_digest(source)
                    reached.append(True)
            self.assertEqual([True], reached)

    def test_diagnostic_cvt_cannot_replace_day0_project_authority(self):
        source = ROOT / "ztp/config/nvos/template/P2P/p2p-to-validation.py"
        spec = importlib.util.spec_from_file_location("req7_cvt_authority", source)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        converter = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = converter
        try:
            spec.loader.exec_module(converter)
        finally:
            sys.modules.pop(spec.name, None)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_root = root / "ztp/config"
            config_root.mkdir(parents=True)
            project = root / "DAY0-Prepare/demo"
            project.mkdir(parents=True)
            authority = project / "01-global.yaml"
            authority.write_bytes(b"PRESERVE-DAY0-AUTHORITY\n")
            with mock.patch.object(converter, "CONFIG_ROOT", config_root):
                with self.assertRaises(converter.ConversionError):
                    converter.publish_cvt_workbook(authority, [], [], [], [])
                private = root / "private-output"
                private.mkdir()
                (project / "99-output-ztp").symlink_to(
                    private, target_is_directory=True,
                )
                lexical_output = project / "99-output-ztp/report.xlsx"
                with self.assertRaises(converter.ConversionError):
                    converter.publish_cvt_workbook(
                        lexical_output, [], [], [], [],
                    )
            self.assertEqual(b"PRESERVE-DAY0-AUTHORITY\n", authority.read_bytes())
            self.assertFalse(Path(f"{authority}.bak").exists())
            self.assertFalse((private / "report.xlsx").exists())

    def test_cvt_sidecar_binds_exact_source_and_output_bytes(self):
        from ztp.config.ib_topology_provenance import (
            ProvenanceError, read_cvt_provenance, sidecar_path,
            write_cvt_provenance,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cvt = root / "expected-cvt.xlsx"
            cvt.write_bytes(b"literal-cvt-v1")
            sources = {}
            for role in (
                "p2p", "inventory", "port_map", "splitter",
                "converter", "topology_rules",
            ):
                path = root / role
                path.write_bytes(("literal-" + role).encode("ascii"))
                sources[role] = path
            written = write_cvt_provenance(cvt, sources)
            self.assertTrue(sidecar_path(cvt).is_file())
            self.assertEqual(
                hashlib.sha256(b"literal-cvt-v1").hexdigest(),
                written["cvt_sha256"],
            )
            self.assertEqual(written, read_cvt_provenance(cvt))

            old_time = cvt.stat().st_mtime_ns
            cvt.write_bytes(b"literal-cvt-v2")
            os.utime(cvt, ns=(old_time, old_time))
            with self.assertRaises(ProvenanceError):
                read_cvt_provenance(cvt)


if __name__ == "__main__":
    unittest.main()
