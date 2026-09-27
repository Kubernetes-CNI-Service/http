#!/usr/bin/env python3
"""Direct contract for explicit finished-record rehydration."""

from __future__ import annotations

import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unittest
from unittest import mock


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


def load_day0_module():
    name = "finished_rehydrate_day0_eligibility_under_test"
    spec = importlib.util.spec_from_file_location(name, ROOT / "DAY0-Prepare/11-load.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot import DAY0 load entrypoint")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def load_package_module():
    """Load the real shared selector used by upload and download workflows."""
    tools_dir = str(ROOT / "tools")
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    name = "finished_rehydrate_package_selector_under_test"
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools/_package_common.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot import shared package selector")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class FinishedProjectRehydrateTests(unittest.TestCase):
    def test_public_cli_explains_record_destination_and_history_scope(self):
        module = load_module()
        with mock.patch.object(module.argparse.ArgumentParser, "parse_args", autospec=True) as parse:
            module.parse_args(["record", "new-project"])
            parser = parse.call_args.args[0]
        actions = {action.dest: action for action in parser._actions}
        expected = {
            "record": "verified finished record",
            "new_project": "new DAY0 project",
            "day0_root": "DAY0 project root",
            "include_history": "history files",
        }
        for destination, phrase in expected.items():
            with self.subTest(destination=destination):
                self.assertIn(phrase, actions[destination].help or "")

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

    def test_verified_reconstruction_rebound_cannot_change_copied_bytes(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            record, _record_id = self._record(root)
            day0 = root / "DAY0-Prepare"
            day0.mkdir()
            source = record / "reconstructed-final"
            original = (source / "01-global.yaml").read_bytes()
            original_digest = hashlib.sha256(original).hexdigest()
            inventory = json.loads((record / "record-inventory.json").read_text())
            self.assertEqual(
                original_digest,
                next(entry["identity"] for entry in inventory["entries"]
                     if entry["path"] == "reconstructed-final/01-global.yaml"),
            )

            replacement = root / "rebound-source"
            shutil.copytree(source, replacement, symlinks=True)
            replacement.chmod(0o755)
            rebound_file = replacement / "01-global.yaml"
            rebound_file.chmod(0o644)
            rebound_file.write_text("project: REBOUND\n", encoding="utf-8")
            rebound_file.chmod(0o444)
            rebound = rebound_file.read_bytes()
            self.assertNotEqual(original, rebound)
            verified_original = record / "verified-original"
            real_verify = module.verify_record
            callbacks = []

            def verify_then_rebind(path):
                report = real_verify(path)
                callbacks.append("verified")
                record.chmod(0o755)
                try:
                    source.rename(verified_original)
                    replacement.rename(source)
                finally:
                    record.chmod(0o555)
                callbacks.append("rebound")
                return report

            target = day0 / "rehydrated"
            with mock.patch.object(module, "verify_record", side_effect=verify_then_rebind):
                try:
                    actual = module.rehydrate_record(
                        record=record, day0_root=day0,
                        new_project=target.name, include_history=False,
                    )
                except (module.RehydrateError, OSError):
                    self.assertFalse(os.path.lexists(target))
                else:
                    self.assertEqual(["verified", "rebound"], callbacks)
                    self.assertEqual(
                        original,
                        (verified_original / "01-global.yaml").read_bytes(),
                    )
                    self.assertEqual(target, actual)
                    copied = (target / "01-global.yaml").read_bytes()
                    self.assertEqual(original_digest, hashlib.sha256(copied).hexdigest())
                    self.assertEqual(original, copied)
                    self.assertNotEqual(rebound, copied)
            self.assertEqual(["verified", "rebound"], callbacks)
            self.assertEqual(original, (verified_original / "01-global.yaml").read_bytes())

    def test_stage_name_rebind_at_real_file_create_cannot_write_outside(self):
        module = load_module()
        with tempfile.TemporaryDirectory(prefix="rehydrate-stage-race-") as name:
            root = Path(name)
            record, record_id = self._record(root)
            control_day0 = root / "control-DAY0-Prepare"
            control_day0.mkdir()
            control = module.rehydrate_record(
                record=record, day0_root=control_day0,
                new_project="control-restored", include_history=False,
            )
            self.assertEqual(
                b"project: customer\n", (control / "01-global.yaml").read_bytes(),
            )
            self.assertEqual(
                record_id,
                json.loads((control / ".finished-source.json").read_text())["record_id"],
            )

            day0 = root / "DAY0-Prepare"
            day0.mkdir()
            outside = root / "outside"
            outside.mkdir()
            sentinel = outside / "untouched.txt"
            sentinel.write_bytes(b"outside sentinel must not change\n")
            target = day0 / "race-restored"
            real_open = os.open
            injections: list[str] = []
            restorations: list[bool] = []

            def rebind_at_real_open(path, flags, *args, **kwargs):
                if (
                    not injections and isinstance(path, (str, bytes, Path))
                    and Path(path).name == "01-global.yaml"
                    and flags & os.O_CREAT
                ):
                    stages = list(day0.glob(".race-restored.rehydrate-*"))
                    self.assertEqual(1, len(stages), "real staging directory must exist")
                    stage = stages[0]
                    held = day0 / "stage-held-for-injection"
                    self.assertFalse(os.path.lexists(held))
                    stage.rename(held)
                    try:
                        stage.symlink_to(outside, target_is_directory=True)
                        injections.append("real-file-create")
                        return real_open(path, flags, *args, **kwargs)
                    finally:
                        if stage.is_symlink():
                            stage.unlink()
                        held.rename(stage)
                        restorations.append(stage.is_dir() and not stage.is_symlink())
                return real_open(path, flags, *args, **kwargs)

            with mock.patch.object(module.os, "open", side_effect=rebind_at_real_open):
                with self.assertRaises((module.RehydrateError, OSError)):
                    module.rehydrate_record(
                        record=record, day0_root=day0,
                        new_project=target.name, include_history=False,
                    )
            self.assertEqual(["real-file-create"], injections)
            self.assertEqual([True], restorations)
            self.assertEqual(b"outside sentinel must not change\n", sentinel.read_bytes())
            self.assertFalse(os.path.lexists(target), "failed restore must not publish a project")
            self.assertEqual([], list(day0.glob(".race-restored.rehydrate-*")))
            self.assertFalse(os.path.lexists(day0 / "stage-held-for-injection"))
            self.assertFalse(
                os.path.lexists(outside / "01-global.yaml"),
                "real staged-file creation must never write through a rebound name",
            )

    def test_post_publish_parent_fsync_failure_never_exposes_eligible_project(self):
        rehydrate = load_module()
        day0_load = load_day0_module()
        with tempfile.TemporaryDirectory(prefix="rehydrate-parent-fsync-") as name:
            root = Path(name)
            record, _record_id = self._record(root)
            source = record / "reconstructed-final/01-global.yaml"
            source_identity = (source.stat().st_ino, source.read_bytes())
            inventory_identity = (record / "record-inventory.json").read_bytes()

            day0 = root / "DAY0-Prepare"
            day0.mkdir()
            preexisting = day0 / "preexisting"
            preexisting.mkdir()
            existing_sentinel = preexisting / "sentinel.txt"
            existing_sentinel.write_bytes(b"preexisting project must not change\n")
            outside = root / "outside"
            outside.mkdir()
            outside_sentinel = outside / "sentinel.txt"
            outside_sentinel.write_bytes(b"outside must not change\n")
            target = day0 / "restored"
            parent_identity = (day0.stat().st_dev, day0.stat().st_ino)
            real_fsync = os.fsync
            injections: list[str] = []

            def fail_after_publication(descriptor):
                held = os.fstat(descriptor)
                if (
                    not injections
                    and (held.st_dev, held.st_ino) == parent_identity
                    and os.path.lexists(target)
                ):
                    injections.append("post-rename-parent-fsync")
                    raise OSError(errno.EIO, "injected parent directory fsync failure")
                return real_fsync(descriptor)

            with mock.patch.object(rehydrate.os, "fsync", side_effect=fail_after_publication):
                with self.assertRaises(OSError) as failed:
                    rehydrate.rehydrate_record(
                        record=record, day0_root=day0,
                        new_project=target.name, include_history=False,
                    )
            self.assertEqual(errno.EIO, failed.exception.errno)
            self.assertEqual(["post-rename-parent-fsync"], injections)
            self.assertEqual(source_identity, (source.stat().st_ino, source.read_bytes()))
            self.assertEqual(inventory_identity, (record / "record-inventory.json").read_bytes())
            self.assertEqual(
                b"preexisting project must not change\n", existing_sentinel.read_bytes(),
            )
            self.assertEqual(b"outside must not change\n", outside_sentinel.read_bytes())

            # A retained inode is safer than deleting an uncertain publication,
            # but it must not be accepted as an ordinary completed DAY0 project.
            if os.path.lexists(target):
                self.assertTrue(target.is_dir() and not target.is_symlink())
                with mock.patch.object(day0_load, "HERE", day0):
                    with self.assertRaises(day0_load.LoadError):
                        day0_load.resolve_project(str(target))

    def test_post_publish_prefsync_window_rejects_real_day0_load(self):
        rehydrate = load_module()
        day0_load = load_day0_module()
        with tempfile.TemporaryDirectory(prefix="rehydrate-visible-window-") as name:
            root = Path(name)
            record, _record_id = self._record(root)
            source = record / "reconstructed-final/01-global.yaml"
            source_bytes = source.read_bytes()
            day0 = root / "DAY0-Prepare"
            day0.mkdir()
            ordinary = day0 / "ordinary"
            ordinary.mkdir()
            ordinary_sentinel = ordinary / "sentinel.txt"
            ordinary_sentinel.write_bytes(b"ordinary project unchanged\n")
            outside_sentinel = root / "outside-sentinel.txt"
            outside_sentinel.write_bytes(b"outside unchanged\n")
            target = day0 / "restored"
            parent_identity = (day0.stat().st_dev, day0.stat().st_ino)
            real_fsync = os.fsync
            observed: list[str] = []

            def inspect_before_parent_fsync(descriptor):
                held = os.fstat(descriptor)
                if (
                    not observed
                    and (held.st_dev, held.st_ino) == parent_identity
                    and os.path.lexists(target)
                ):
                    with mock.patch.object(day0_load, "HERE", day0):
                        try:
                            day0_load.resolve_project(str(target))
                        except day0_load.LoadError:
                            observed.append("rejected-before-fsync")
                        else:
                            observed.append("accepted-before-fsync")
                    raise OSError(errno.EIO, "injected parent directory fsync failure")
                return real_fsync(descriptor)

            with mock.patch.object(rehydrate.os, "fsync", side_effect=inspect_before_parent_fsync):
                with self.assertRaises(OSError) as failed:
                    rehydrate.rehydrate_record(
                        record=record, day0_root=day0,
                        new_project=target.name, include_history=False,
                    )
            self.assertEqual(errno.EIO, failed.exception.errno)
            self.assertEqual(["rejected-before-fsync"], observed)
            self.assertEqual(source_bytes, source.read_bytes())
            self.assertEqual(b"ordinary project unchanged\n", ordinary_sentinel.read_bytes())
            self.assertEqual(b"outside unchanged\n", outside_sentinel.read_bytes())

    def test_completed_restored_project_requires_valid_receipt_and_ordinary_project_does_not(self):
        rehydrate = load_module()
        day0_load = load_day0_module()
        with tempfile.TemporaryDirectory(prefix="rehydrate-receipt-eligibility-") as name:
            root = Path(name)
            record, _record_id = self._record(root)
            source = record / "reconstructed-final/01-global.yaml"
            source_bytes = source.read_bytes()
            day0 = root / "DAY0-Prepare"
            day0.mkdir()
            ordinary = day0 / "ordinary"
            ordinary.mkdir()
            ordinary_sentinel = ordinary / "sentinel.txt"
            ordinary_sentinel.write_bytes(b"ordinary project unchanged\n")
            outside_sentinel = root / "outside-sentinel.txt"
            outside_sentinel.write_bytes(b"outside unchanged\n")
            target = rehydrate.rehydrate_record(
                record=record, day0_root=day0,
                new_project="restored", include_history=False,
            )
            receipt = target / ".finished-source.json"
            completed = json.loads(receipt.read_text(encoding="utf-8"))

            with mock.patch.object(day0_load, "HERE", day0):
                self.assertEqual(ordinary.resolve(), day0_load.resolve_project(str(ordinary)))
                self.assertEqual(target.resolve(), day0_load.resolve_project(str(target)))

                pending = dict(completed, state="PENDING")
                wrong_identity = dict(completed, record_id="20260916T083250Z-bbbbbbbbbbbb")
                for label, payload in (
                    ("pending", (json.dumps(pending, sort_keys=True) + "\n").encode()),
                    ("malformed", b"{not-json\n"),
                    ("mismatched-record-identity", (
                        json.dumps(wrong_identity, sort_keys=True) + "\n"
                    ).encode()),
                ):
                    with self.subTest(receipt=label):
                        receipt.write_bytes(payload)
                        with self.assertRaises(day0_load.LoadError):
                            day0_load.resolve_project(str(target))
                        self.assertEqual(
                            ordinary.resolve(), day0_load.resolve_project(str(ordinary)),
                        )
            self.assertEqual(source_bytes, source.read_bytes())
            self.assertEqual(b"ordinary project unchanged\n", ordinary_sentinel.read_bytes())
            self.assertEqual(b"outside unchanged\n", outside_sentinel.read_bytes())

    def test_pending_restored_project_is_not_an_explicit_archive_project(self):
        rehydrate = load_module()
        package = load_package_module()
        with tempfile.TemporaryDirectory(prefix="rehydrate-archive-explicit-") as name:
            root = Path(name)
            record, _record_id = self._record(root)
            source = record / "reconstructed-final/01-global.yaml"
            source_bytes = source.read_bytes()
            day0 = root / "DAY0-Prepare"
            day0.mkdir()
            ordinary = day0 / "ordinary"
            ordinary.mkdir()
            (ordinary / "01-global.yaml").write_bytes(b"project: ordinary\n")
            (ordinary / "02-devices_config.csv").write_bytes(b"name,ip\n")
            target = rehydrate.rehydrate_record(
                record=record, day0_root=day0,
                new_project="restored", include_history=False,
            )
            receipt = target / ".finished-source.json"
            completed = json.loads(receipt.read_text(encoding="utf-8"))
            with mock.patch.object(package, "DAY0", day0):
                self.assertEqual(ordinary.resolve(), package.resolve_project(str(ordinary)))
                self.assertEqual(target.resolve(), package.resolve_project(str(target)))

                pending = dict(completed, state="PENDING")
                receipt.write_text(json.dumps(pending, sort_keys=True) + "\n", encoding="utf-8")
                with self.assertRaises(ValueError):
                    package.resolve_project(str(target))
                self.assertEqual(ordinary.resolve(), package.resolve_project(str(ordinary)))
            self.assertEqual(source_bytes, source.read_bytes())

    def test_pending_restored_project_is_not_in_bulk_archive_projects(self):
        rehydrate = load_module()
        package = load_package_module()
        with tempfile.TemporaryDirectory(prefix="rehydrate-archive-bulk-") as name:
            root = Path(name)
            record, _record_id = self._record(root)
            day0 = root / "DAY0-Prepare"
            day0.mkdir()
            ordinary = day0 / "ordinary"
            ordinary.mkdir()
            (ordinary / "01-global.yaml").write_bytes(b"project: ordinary\n")
            (ordinary / "02-devices_config.csv").write_bytes(b"name,ip\n")
            target = rehydrate.rehydrate_record(
                record=record, day0_root=day0,
                new_project="restored", include_history=False,
            )
            receipt = target / ".finished-source.json"
            completed = json.loads(receipt.read_text(encoding="utf-8"))
            with mock.patch.object(package, "DAY0", day0):
                self.assertEqual([ordinary, target], package.project_directories())
                receipt.write_text(
                    json.dumps(dict(completed, state="PENDING"), sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                try:
                    candidates = package.project_directories()
                except ValueError:
                    # A bulk archive may reject the entire selection instead.
                    pass
                else:
                    self.assertNotIn(target, candidates)

    def test_final_commit_rename_error_after_effect_is_reported_committed(self):
        rehydrate = load_module()
        day0_load = load_day0_module()
        with tempfile.TemporaryDirectory(prefix="rehydrate-commit-ambiguous-") as name:
            root = Path(name)
            record, record_id = self._record(root)
            day0 = root / "DAY0-Prepare"
            day0.mkdir()
            actual_rename = rehydrate._rename_noreplace
            injected: list[str] = []

            def rename_then_error(source, destination, *, directory_fd):
                actual_rename(source, destination, directory_fd=directory_fd)
                if destination.name == ".finished-commit.json":
                    injected.append("marker-renamed-before-eio")
                    raise OSError(errno.EIO, "injected ambiguous marker rename")

            warnings: list[str] = []
            with mock.patch.object(rehydrate, "_rename_noreplace", side_effect=rename_then_error):
                with mock.patch.object(rehydrate, "_warn_nonfatal", side_effect=warnings.append):
                    target = rehydrate.rehydrate_record(
                        record=record, day0_root=day0,
                        new_project="restored", include_history=False,
                    )
            self.assertEqual(["marker-renamed-before-eio"], injected)
            self.assertEqual(day0 / "restored", target)
            self.assertFalse((target / ".finished-commit.ready").exists())
            marker = json.loads((target / ".finished-commit.json").read_text())
            receipt = (target / ".finished-source.json").read_bytes()
            self.assertEqual("COMMITTED", marker["state"])
            self.assertEqual(hashlib.sha256(receipt).hexdigest(), marker["receipt_sha256"])
            self.assertEqual(record_id, json.loads(receipt)["record_id"])
            self.assertTrue(any("marker became visible" in warning for warning in warnings))
            with mock.patch.object(day0_load, "HERE", day0):
                self.assertEqual(target.resolve(), day0_load.resolve_project(str(target)))

    def test_final_commit_rename_error_before_effect_keeps_pending_target(self):
        rehydrate = load_module()
        day0_load = load_day0_module()
        with tempfile.TemporaryDirectory(prefix="rehydrate-commit-pending-") as name:
            root = Path(name)
            record, _ = self._record(root)
            source = record / "reconstructed-final/01-global.yaml"
            source_identity = (source.stat().st_ino, source.read_bytes())
            day0 = root / "DAY0-Prepare"
            day0.mkdir()
            target = day0 / "restored"
            actual_rename = rehydrate._rename_noreplace
            injected: list[str] = []

            def reject_marker_rename(source_name, destination, *, directory_fd):
                if destination.name == ".finished-commit.json":
                    injected.append("marker-not-renamed")
                    raise OSError(errno.EIO, "injected pre-effect marker rename")
                return actual_rename(source_name, destination, directory_fd=directory_fd)

            with mock.patch.object(rehydrate, "_rename_noreplace", side_effect=reject_marker_rename):
                with self.assertRaises(rehydrate.RehydrateError):
                    rehydrate.rehydrate_record(
                        record=record, day0_root=day0,
                        new_project=target.name, include_history=False,
                    )
            self.assertEqual(["marker-not-renamed"], injected)
            self.assertTrue(target.is_dir() and not target.is_symlink())
            self.assertTrue((target / ".finished-commit.ready").is_file())
            self.assertFalse(os.path.lexists(target / ".finished-commit.json"))
            target_identity = target.stat().st_ino
            with mock.patch.object(day0_load, "HERE", day0):
                with self.assertRaises(day0_load.LoadError):
                    day0_load.resolve_project(str(target))
            with self.assertRaises(rehydrate.RehydrateError):
                rehydrate.rehydrate_record(
                    record=record, day0_root=day0,
                    new_project=target.name, include_history=False,
                )
            self.assertEqual(target_identity, target.stat().st_ino)
            self.assertEqual(source_identity, (source.stat().st_ino, source.read_bytes()))

    def test_postcommit_close_error_does_not_reclassify_restore_as_failed(self):
        rehydrate = load_module()
        day0_load = load_day0_module()
        with tempfile.TemporaryDirectory(prefix="rehydrate-close-after-commit-") as name:
            root = Path(name)
            record, _ = self._record(root)
            day0 = root / "DAY0-Prepare"
            day0.mkdir()
            target = day0 / "restored"
            actual_close = os.close
            injected: list[int] = []
            warnings: list[str] = []

            def close_then_error(descriptor):
                if not injected and (target / ".finished-commit.json").is_file():
                    actual_close(descriptor)
                    injected.append(descriptor)
                    raise OSError(errno.EIO, "injected postcommit close error")
                return actual_close(descriptor)

            with mock.patch.object(rehydrate.os, "close", side_effect=close_then_error):
                with mock.patch.object(rehydrate, "_warn_nonfatal", side_effect=warnings.append):
                    actual = rehydrate.rehydrate_record(
                        record=record, day0_root=day0,
                        new_project=target.name, include_history=False,
                    )
            self.assertEqual(target, actual)
            self.assertEqual(1, len(injected))
            self.assertTrue(any("committed rehydrate" in warning for warning in warnings))
            with mock.patch.object(day0_load, "HERE", day0):
                self.assertEqual(target.resolve(), day0_load.resolve_project(str(target)))

    def test_cli_success_output_error_does_not_reclassify_restore_as_failed(self):
        rehydrate = load_module()
        day0_load = load_day0_module()
        with tempfile.TemporaryDirectory(prefix="rehydrate-output-after-commit-") as name:
            root = Path(name)
            record, _ = self._record(root)
            day0 = root / "DAY0-Prepare"
            day0.mkdir()
            target = day0 / "restored"
            printed: list[str] = []
            warnings: list[str] = []
            actual_print = print

            def fail_success_output(*args, **kwargs):
                if args and str(args[0]).startswith("[OK] rehydrated"):
                    printed.append("success-output-attempted")
                    raise OSError(errno.EIO, "injected success-output error")
                return actual_print(*args, **kwargs)

            with mock.patch("builtins.print", side_effect=fail_success_output):
                with mock.patch.object(rehydrate, "_warn_nonfatal", side_effect=warnings.append):
                    status = rehydrate.main([
                        str(record), target.name, "--day0-root", str(day0),
                    ])
            self.assertEqual(0, status)
            self.assertEqual(["success-output-attempted"], printed)
            self.assertTrue(any("success output failed" in warning for warning in warnings))
            with mock.patch.object(day0_load, "HERE", day0):
                self.assertEqual(target.resolve(), day0_load.resolve_project(str(target)))


if __name__ == "__main__":
    unittest.main()
