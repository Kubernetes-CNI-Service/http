"""Real LLDP analyzer -> local activity reader flow, never a qualified cycle."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

from monitor.issue_tracker_activity_source import (
    ActivitySourceHoldError,
    load_eth_activity_evidence,
)


ROOT = Path(__file__).resolve().parents[1]
ANALYZER = ROOT / "tools/lldp-analyze-tool/analyze_lldp.py"


def _info(local_port: str, remote_host: str, remote_port: str) -> bytes:
    widths = (16, 16, 16, 12, 12, 12, 22, 16, 12)
    headers = ("Interface", "Admin Status", "Oper Status", "Speed", "MTU",
               "Type", "Remote Host", "Remote Port", "Other")
    values = (local_port, "up", "up", "100G", "9216", "swp",
              remote_host, remote_port, "-")
    row = lambda items: "".join(str(item).ljust(width) for item, width in zip(items, widths))
    text = ("# Execute Command: nv show interface\n" + row(headers) + "\n"
            + row("-" * (width - 1) for width in widths) + "\n"
            + row(values) + "\n")
    return text.encode("utf-8")


class EthActivitySourceWorkflowTests(unittest.TestCase):
    def test_analyzer_frozen_input_rejects_same_size_midcopy_rewrite(self):
        spec = importlib.util.spec_from_file_location("eth_activity_analyzer", ANALYZER)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "planned.dot"
            source.write_bytes(b"alpha")
            destination = base / "private"
            destination.mkdir()
            before = source.stat()
            real_read = module.os.read
            changed = False

            def rewrite_after_first_read(descriptor, length):
                nonlocal changed
                chunk = real_read(descriptor, length)
                if chunk and not changed:
                    changed = True
                    source.write_bytes(b"ALPHA")
                    os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns))
                return chunk

            with mock.patch.object(module.os, "read", side_effect=rewrite_after_first_read):
                with self.assertRaisesRegex(ValueError, "changed during snapshot"):
                    module.freeze_evidence_input(source, destination)
            self.assertTrue(changed)

    def test_real_analyzer_and_reader_bind_four_literal_inputs_without_cycle_promotion(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            dot = base / "planned-lldpq.dot"
            dot.write_bytes(b'"leaf-a":"swp1" -- "leaf-z":"swp2"\n')
            archive = base / "exact-cycle-ethernet.tar.gz"
            with tarfile.open(archive, "w:gz") as bundle:
                for name, body in (
                    ("leaf-a.info", _info("swp1", "leaf-z", "swp2")),
                    ("leaf-z.info", _info("swp2", "leaf-a", "swp1")),
                ):
                    member = tarfile.TarInfo(name)
                    member.size = len(body)
                    bundle.addfile(member, io.BytesIO(body))
            inventory = base / "inventory.log"
            inventory.write_bytes(b"[Eth-SW]\nleaf-*\n")
            aliases = base / "aliases.json"
            aliases.write_bytes(b'{"schema_version":1,"canonical_to_aliases":{}}')
            output_dir = base / "reports"
            evidence = base / "observation.json"
            command = [
                sys.executable, "-B", str(ANALYZER),
                "--dot", str(dot), "--archive", str(archive),
                "--inventory", str(inventory), "--device-aliases", str(aliases),
                "--output-dir", str(output_dir),
                "--activity-evidence-output", str(evidence),
            ]
            completed = subprocess.run(command, capture_output=True, text=True,
                                       check=False, cwd=base)
            self.assertEqual(0, completed.returncode, completed.stderr or completed.stdout)
            report = (output_dir / "exact-cycle-ethernet-ethernet-topology-validation.xlsx").resolve()
            self.assertTrue(report.is_file())
            self.assertTrue(evidence.is_file())
            sources = {
                "dot": dot.resolve(), "archive": archive.resolve(),
                "inventory": inventory.resolve(), "device_aliases": aliases.absolute(),
            }
            witness = load_eth_activity_evidence(
                evidence, sources=sources, report_path=report,
                expected_evidence_sha256=hashlib.sha256(evidence.read_bytes()).hexdigest(),
            )
            self.assertEqual("CONFIRMED_BOTH_SIDE", witness.links[0].status)
            self.assertEqual(("leaf-a", "leaf-z"),
                             (witness.links[0].device_a, witness.links[0].device_b))
            self.assertEqual("leaf-z", witness.links[0].observation_a.remote_host)
            self.assertEqual("leaf-a", witness.links[0].observation_b.remote_host)
            self.assertEqual({role: hashlib.sha256(path.read_bytes()).hexdigest()
                              for role, path in sources.items()}, witness.source_sha256)
            with self.assertRaises(ActivitySourceHoldError):
                load_eth_activity_evidence(
                    evidence, sources=sources, report_path=report,
                    expected_cycle_completion_sha256="b" * 64,
                )


if __name__ == "__main__":
    unittest.main()
