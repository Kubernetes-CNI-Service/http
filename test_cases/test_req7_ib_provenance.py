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
