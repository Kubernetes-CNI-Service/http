#!/usr/bin/env python3
"""Direct contract for explicit finished-record rehydration."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/rehydrate-finished.py"


def load_module():
    name = "finished_rehydrate_under_test"
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class FinishedProjectRehydrateTests(unittest.TestCase):
    def _record(self, root: Path) -> tuple[Path, str]:
        record_id = "20260916T083250Z-0123456789ab"
        record = root / "Finished-projects/customer" / record_id
        final = record / "reconstructed-final"
        output = final / "99-output-ztp"
        output.mkdir(parents=True)
        (final / "01-global.yaml").write_text("project: customer\n", encoding="utf-8")
        (final / "02-devices_config.csv").write_text("name,ip\nleaf,1.2.3.4\n", encoding="utf-8")
        (output / "result.txt").write_text("done\n", encoding="utf-8")
        (output / "worker.pid").write_text("123\n", encoding="utf-8")
        (output / "latest").symlink_to("run-1")
        report = {
            "schema_version": 1,
            "project": "customer",
            "record_id": record_id,
            "content_sha256": "a" * 64,
        }
        (record / "import-report.json").write_text(
            json.dumps(report, sort_keys=True) + "\n", encoding="utf-8",
        )
        entries: list[dict[str, str]] = []
        for path in sorted(record.rglob("*"), key=lambda p: p.relative_to(record).as_posix()):
            relative = path.relative_to(record).as_posix()
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                kind, identity = "symlink", os.readlink(path)
            elif stat.S_ISDIR(metadata.st_mode):
                kind, identity = "directory", "directory"
            else:
                kind, identity = "file", sha256(path)
            entries.append({"path": relative, "type": kind, "identity": identity})
        inventory = {
            "schema_version": 1,
            "entries": entries,
            "entries_sha256": hashlib.sha256(json.dumps(
                entries, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            ).encode("ascii")).hexdigest(),
        }
        (record / "record-inventory.json").write_text(
            json.dumps(inventory, sort_keys=True) + "\n", encoding="utf-8",
        )
        for path in sorted(record.rglob("*"), reverse=True):
            if not path.is_symlink():
                path.chmod(0o555 if path.is_dir() else 0o444)
        record.chmod(0o555)
        return record, record_id

    def test_default_materializes_only_working_inputs_and_source_receipt(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            record, record_id = self._record(root)
            day0 = root / "DAY0-Prepare"
            day0.mkdir()
            target = module.rehydrate_record(
                record=record, day0_root=day0, new_project="customer-rehydrated",
                include_history=False,
            )
            self.assertEqual(b"project: customer\n", (target / "01-global.yaml").read_bytes())
            self.assertFalse((target / "99-output-ztp").exists())
            receipt = json.loads((target / ".finished-source.json").read_text())
            self.assertEqual(record_id, receipt["record_id"])
            self.assertEqual("a" * 64, receipt["content_sha256"])
            self.assertFalse(any(path.is_symlink() for path in target.rglob("*")))
            source_inode = (record / "reconstructed-final/01-global.yaml").stat().st_ino
            self.assertNotEqual(source_inode, (target / "01-global.yaml").stat().st_ino)

    def test_include_history_copies_safe_output_but_excludes_runtime_controls(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            record, _record_id = self._record(root)
            day0 = root / "DAY0-Prepare"
            day0.mkdir()
            target = module.rehydrate_record(
                record=record, day0_root=day0, new_project="with-history",
                include_history=True,
            )
            output = target / "99-output-ztp"
            self.assertEqual(b"done\n", (output / "result.txt").read_bytes())
            self.assertFalse((output / "worker.pid").exists())
            self.assertFalse(os.path.lexists(output / "latest"))

    def test_existing_target_or_tampered_record_fails_without_partial_project(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            record, _record_id = self._record(root)
            day0 = root / "DAY0-Prepare"
            day0.mkdir()
            existing = day0 / "existing"
            existing.mkdir()
            with self.assertRaisesRegex(module.RehydrateError, "already exists"):
                module.rehydrate_record(
                    record=record, day0_root=day0, new_project="existing",
                    include_history=False,
                )
            source = record / "reconstructed-final/01-global.yaml"
            source.chmod(0o644)
            source.write_text("tampered\n", encoding="utf-8")
            source.chmod(0o444)
            with self.assertRaisesRegex(module.RehydrateError, "inventory"):
                module.rehydrate_record(
                    record=record, day0_root=day0, new_project="new-project",
                    include_history=False,
                )
            self.assertFalse((day0 / "new-project").exists())


if __name__ == "__main__":
    unittest.main()
