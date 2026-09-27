"""REQ-19 direct, fixed-expectation contract for project-owned infra logs."""

from __future__ import annotations

from contextlib import ExitStack, redirect_stdout
import hashlib
import io
from itertools import product
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
SETUP = load_script("req19_direct_setup", ROOT / "DAY0-Prepare/01-a-setup.py")
UNSETUP = load_script("req19_direct_unsetup", ROOT / "DAY0-Prepare/02-unsetup.py")
CONTRACT = load_script("req19_direct_contract", ROOT / "tools/project_contract.py")
MAPPING = ("infra/logs", "99-output-infra", "dir")
EXPECTED_OUTPUTS = {
    "99-output-backup", "99-output-dhcp", "99-output-eth",
    "99-output-ib_nvl", "99-output-infra", "99-output-monitor",
    "99-output-p2p", "99-output-ztp",
}


class Req19InfraLogContractTests(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory).resolve() / "http"
        logs = root / "infra/logs"
        logs.parent.mkdir(parents=True)
        template = root / "DAY0-Prepare/template/99-output-infra"
        template.mkdir(parents=True)
        (template / ".gitkeep").write_bytes(b"")
        projects = [root / "DAY0-Prepare/site-a", root / "DAY0-Prepare/site-b"]
        for project in projects:
            (project / "99-output-infra").mkdir(parents=True)
            (project / "p2p.xlsx").write_bytes(b"isolated fixture")
        return root, logs, *projects

    def bind(self, root, project, *, manifest_failure=False):
        unrelated = (
            "_initialize_project_from_template", "_prepare_laptop_public_key",
            "_remove_legacy_nvos_output_links", "_process_bin_files",
            "_process_xlsx_files", "_process_bringup_links",
            "_process_analyzer_links", "_process_pubkeys",
            "_process_latest_yaml", "_process_optimize_sample",
            "_process_net_csv_links", "_process_monitor_links",
            "_print_next_steps",
        )
        with ExitStack() as patches:
            patches.enter_context(mock.patch.multiple(
                SETUP, HTTP_BASE=str(root), HERE=str(root / "DAY0-Prepare"),
                ZTP=str(root / "ztp"), TEMPLATE_DIR=str(root / "DAY0-Prepare/template"),
                MANIFEST_FILE=str(root / "ztp/.setup_manifest"),
                IMAGE_DIR=str(root / "image"), MAPPINGS=[], _NET_CSV_LINKS=[],
                P2P_INPUT_LINKS=[], P2P_OUTPUT_LINKS=[],
                P2P_AIR_JSON_LINK=str(root / "ztp/p2p-air.json"),
                BRINGUP_OUTPUT_MAPPINGS=[], ANALYZER_INPUT_MAPPINGS=[],
                ANALYZER_OUTPUT_MAPPINGS=[], _CSV_DIR=None, _DRY_RUN=False,
                _AUTO_YES=True, _CONFIRM_PROJECT_SWITCH=True, _LINK_TRANSACTION=None,
            ))
            for name in unrelated:
                patches.enter_context(mock.patch.object(SETUP, name))
            if manifest_failure:
                patches.enter_context(mock.patch.object(
                    SETUP, "_write_manifest", side_effect=OSError("injected manifest failure"),
                ))
            else:
                patches.enter_context(mock.patch.object(SETUP, "_write_manifest"))
            patches.enter_context(mock.patch.object(
                SETUP, "_select_p2p_source", return_value=str(project / "p2p.xlsx"),
            ))
            patches.enter_context(mock.patch.object(SETUP, "_validate_project", return_value=True))
            patches.enter_context(mock.patch.object(
                SETUP, "_ensure_project_p2p_link", return_value=str(project / "p2p.xlsx"),
            ))
            patches.enter_context(mock.patch.object(SETUP, "_confirm_overwrite", return_value=True))
            with redirect_stdout(io.StringIO()):
                SETUP.setup(str(project))

    def assert_rejected(self, root, project):
        with self.assertRaises((OSError, ValueError, SystemExit)):
            self.bind(root, project)

    def assert_recovery_receipt(self, root, logs, project, payloads):
        receipt = root / "infra/.logs-migration.json"
        self.assertTrue(stat.S_ISREG(receipt.lstat().st_mode))
        data = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(1, data["schema_version"])
        self.assertEqual(str(logs), data["source"]["path"])
        self.assertEqual(logs.lstat().st_dev, data["source"]["dev"])
        self.assertEqual(logs.lstat().st_ino, data["source"]["ino"])
        self.assertEqual(str(project / "99-output-infra"), data["destination"]["path"])
        for name, payload in payloads.items():
            self.assertEqual(len(payload), data["entries"][name]["size"])
            self.assertEqual(hashlib.sha256(payload).hexdigest(),
                             data["entries"][name]["sha256"])
        return receipt

    def seed_pending_backup(self, root, logs, project, payload=b"original log bytes\n"):
        """Build a fixed-format interrupted migration with no infra/logs leaf."""
        destination = project / "99-output-infra"
        backup = destination / ".logs-migration-source"
        backup.mkdir()
        (backup / "owned.log").write_bytes(payload)
        identity = backup.lstat()
        receipt = root / "infra/.logs-migration.json"
        receipt.write_text(json.dumps({
            "schema_version": 1,
            "source": {"path": str(logs), "dev": identity.st_dev, "ino": identity.st_ino},
            "destination": {"path": str(destination)},
            "directories": [],
            "entries": {"owned.log": {
                "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest(),
            }},
        }), encoding="utf-8")
        return backup, receipt

    def seed_committing_backup(self, root, logs, project, payload=b"committed log bytes\n"):
        backup, receipt = self.seed_pending_backup(root, logs, project, payload)
        destination = project / "99-output-infra"
        os.link(backup / "owned.log", destination / "owned.log")
        logs.symlink_to(os.path.relpath(destination, logs.parent))
        return backup, receipt

    def test_eight_output_skeleton_and_exact_managed_mapping(self):
        template = ROOT / "DAY0-Prepare/template"
        self.assertEqual(EXPECTED_OUTPUTS, {p.name for p in template.glob("99-output-*") if p.is_dir()})
        self.assertFalse((template / "99-output-infra").is_symlink())
        keep = template / "99-output-infra/.gitkeep"
        self.assertTrue(stat.S_ISREG(keep.lstat().st_mode))
        self.assertEqual(
            b"# Retain this empty runtime-output skeleton in source checkouts.\n",
            keep.read_bytes(),
        )
        for mapping in (CONTRACT.SETUP_WORKSPACE_INPUT_MAPPINGS, SETUP.WORKSPACE_INPUT_MAPPINGS):
            self.assertEqual([MAPPING], [row for row in mapping if row[0] == "infra/logs"])
        self.assertIn("99-output-infra", SETUP.OUTPUT_DIRS)
        self.assertNotIn("/infra/logs/", (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines())

    def test_absent_state_creates_exact_project_link(self):
        with tempfile.TemporaryDirectory(prefix="req19-absent-") as tmp:
            root, logs, a, _ = self.fixture(tmp)
            self.assertFalse(os.path.lexists(logs))
            self.bind(root, a)
            self.assertTrue(logs.is_symlink())
            self.assertEqual(os.path.relpath(a / "99-output-infra", logs.parent), os.readlink(logs))
            self.assertEqual((a / "99-output-infra").resolve(), logs.resolve())

    def test_real_directory_migrates_all_bytes_before_link(self):
        with tempfile.TemporaryDirectory(prefix="req19-real-") as tmp:
            root, logs, a, _ = self.fixture(tmp)
            logs.mkdir()
            payloads = {
                "one.log": b"first\n",
                "two.log": b"second\n",
                "clients/run-1/deploy.log": b"nested client run\n",
            }
            for name, data in payloads.items():
                (logs / name).parent.mkdir(parents=True, exist_ok=True)
                (logs / name).write_bytes(data)
            self.bind(root, a)
            self.assertTrue(logs.is_symlink())
            for name, data in payloads.items():
                self.assertEqual(data, (a / "99-output-infra" / name).read_bytes())

    def test_backup_name_collision_moves_zero_source_bytes(self):
        for variant in ("file", "directory", "symlink"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory(prefix="req19-backup-collision-") as tmp:
                root, logs, a, _ = self.fixture(tmp)
                logs.mkdir()
                source = logs / "one.log"
                source.write_bytes(b"original source\n")
                original_inode = logs.lstat().st_ino
                backup = a / "99-output-infra/.logs-migration-source"
                if variant == "file":
                    backup.write_bytes(b"foreign backup name\n")
                elif variant == "directory":
                    backup.mkdir()
                    (backup / "foreign.log").write_bytes(b"foreign backup bytes\n")
                else:
                    foreign = Path(tmp) / "foreign"
                    foreign.mkdir()
                    backup.symlink_to(foreign)
                backup_inode = backup.lstat().st_ino
                with self.assertRaisesRegex(ValueError, "日志迁移备份位置冲突"):
                    self.bind(root, a)
                self.assertTrue(logs.is_dir() and not logs.is_symlink())
                self.assertEqual(original_inode, logs.lstat().st_ino)
                self.assertEqual(b"original source\n", source.read_bytes())
                self.assertEqual(backup_inode, backup.lstat().st_ino)
                self.assertFalse((a / "99-output-infra/one.log").exists())

    def test_backup_created_after_precheck_is_never_replaced(self):
        with tempfile.TemporaryDirectory(prefix="req19-backup-race-") as tmp:
            root, logs, a, _ = self.fixture(tmp)
            logs.mkdir()
            (logs / "one.log").write_bytes(b"source survives race\n")
            source_inode = logs.lstat().st_ino
            backup = a / "99-output-infra/.logs-migration-source"
            original_lexists = os.path.lexists
            checks = []
            competitor_inode = []

            def create_competitor_after_negative_probe(path):
                exists = original_lexists(path)
                if os.path.abspath(os.fspath(path)) == str(backup):
                    checks.append(exists)
                    if len(checks) == 2 and not exists:
                        backup.mkdir()
                        competitor_inode.append(backup.lstat().st_ino)
                return exists

            with mock.patch.object(os.path, "lexists", side_effect=create_competitor_after_negative_probe):
                self.assert_rejected(root, a)
            self.assertEqual(2, len(checks))
            self.assertEqual(1, len(competitor_inode))
            self.assertTrue(logs.is_dir() and not logs.is_symlink())
            self.assertEqual(source_inode, logs.lstat().st_ino)
            self.assertEqual(b"source survives race\n", (logs / "one.log").read_bytes())
            self.assertEqual(competitor_inode[0], backup.lstat().st_ino)
            self.assertTrue((root / "infra/.logs-migration.json").is_file())

    def test_unavailable_atomic_rename_fails_closed_with_real_source(self):
        with tempfile.TemporaryDirectory(prefix="req19-no-rename-excl-") as tmp:
            root, logs, a, _ = self.fixture(tmp)
            logs.mkdir()
            (logs / "one.log").write_bytes(b"original source\n")
            source_inode = logs.lstat().st_ino
            with mock.patch.object(SETUP.sys, "platform", "unsupported-no-rename-excl"):
                with self.assertRaisesRegex(OSError, "atomic no-replace rename is unavailable"):
                    self.bind(root, a)
            self.assertTrue(logs.is_dir() and not logs.is_symlink())
            self.assertEqual(source_inode, logs.lstat().st_ino)
            self.assertEqual(b"original source\n", (logs / "one.log").read_bytes())
            self.assertFalse(os.path.lexists(a / "99-output-infra/.logs-migration-source"))
            self.assertTrue((root / "infra/.logs-migration.json").is_file())

    def test_pending_backup_restore_never_replaces_raced_empty_log_root(self):
        with tempfile.TemporaryDirectory(prefix="req19-restore-race-") as tmp:
            root, logs, a, _ = self.fixture(tmp)
            payload = b"backup survives restore race\n"
            backup, receipt = self.seed_pending_backup(root, logs, a, payload)
            backup_inode, receipt_bytes = backup.lstat().st_ino, receipt.read_bytes()
            original_lexists = os.path.lexists
            competitor = []

            def create_competitor_after_negative_probe(path):
                exists = original_lexists(path)
                if os.path.abspath(os.fspath(path)) == str(logs) and not exists and not competitor:
                    # An empty directory is deliberate: ordinary POSIX rename
                    # can replace it, unlike a nonempty directory.
                    logs.mkdir()
                    competitor.append(logs.lstat().st_ino)
                return exists

            with mock.patch.multiple(SETUP, HTTP_BASE=str(root), HERE=str(root / "DAY0-Prepare")), \
                    mock.patch.object(os.path, "lexists", side_effect=create_competitor_after_negative_probe):
                with self.assertRaises(OSError):
                    SETUP._restore_pending_infra_log_backup(str(logs), str(a / "99-output-infra"))
            self.assertEqual(1, len(competitor))
            self.assertEqual(competitor[0], logs.lstat().st_ino)
            self.assertEqual(backup_inode, backup.lstat().st_ino)
            self.assertEqual(payload, (backup / "owned.log").read_bytes())
            self.assertEqual(receipt_bytes, receipt.read_bytes())

    def test_pending_backup_restore_requires_atomic_noreplace_primitive(self):
        with tempfile.TemporaryDirectory(prefix="req19-restore-no-primitive-") as tmp:
            root, logs, a, _ = self.fixture(tmp)
            payload = b"backup survives missing primitive\n"
            backup, receipt = self.seed_pending_backup(root, logs, a, payload)
            backup_inode, receipt_bytes = backup.lstat().st_ino, receipt.read_bytes()
            with mock.patch.multiple(SETUP, HTTP_BASE=str(root), HERE=str(root / "DAY0-Prepare")), \
                    mock.patch.object(SETUP.sys, "platform", "unsupported-no-rename-excl"):
                with self.assertRaisesRegex(OSError, "atomic no-replace rename is unavailable"):
                    SETUP._restore_pending_infra_log_backup(str(logs), str(a / "99-output-infra"))
            self.assertFalse(os.path.lexists(logs))
            self.assertEqual(backup_inode, backup.lstat().st_ino)
            self.assertEqual(payload, (backup / "owned.log").read_bytes())
            self.assertEqual(receipt_bytes, receipt.read_bytes())

    def test_failed_link_publication_restore_never_replaces_raced_log_root(self):
        with tempfile.TemporaryDirectory(prefix="req19-link-restore-race-") as tmp:
            root, logs, a, _ = self.fixture(tmp)
            logs.mkdir()
            payload = b"source survives link restore race\n"
            (logs / "owned.log").write_bytes(payload)
            source_inode = logs.lstat().st_ino
            backup = a / "99-output-infra/.logs-migration-source"
            original_symlink, original_lexists = os.symlink, os.path.lexists
            competitor = []

            def interrupt_log_publication(target, link_name, *args, **kwargs):
                if os.path.abspath(os.fspath(link_name)) == str(logs):
                    raise OSError("injected log link publication failure")
                return original_symlink(target, link_name, *args, **kwargs)

            def create_competitor_after_negative_probe(path):
                exists = original_lexists(path)
                if (os.path.abspath(os.fspath(path)) == str(logs)
                        and not exists and backup.is_dir() and not competitor):
                    logs.mkdir()
                    competitor.append(logs.lstat().st_ino)
                return exists

            with mock.patch.object(os, "symlink", side_effect=interrupt_log_publication), \
                    mock.patch.object(os.path, "lexists", side_effect=create_competitor_after_negative_probe):
                self.assert_rejected(root, a)
            self.assertEqual(1, len(competitor))
            self.assertEqual(competitor[0], logs.lstat().st_ino)
            self.assertEqual(source_inode, backup.lstat().st_ino)
            self.assertEqual(payload, (backup / "owned.log").read_bytes())
            self.assertTrue((root / "infra/.logs-migration.json").is_file())

    def test_manifest_rollback_never_replaces_raced_empty_log_root(self):
        with tempfile.TemporaryDirectory(prefix="req19-rollback-race-") as tmp:
            # A failed rollback intentionally leaves process-local migration
            # state pending; only this hermetic test may clear its own fixture.
            self.addCleanup(setattr, SETUP, "_INFRA_LOG_MIGRATION", None)
            root, logs, a, _ = self.fixture(tmp)
            logs.mkdir()
            payload = b"source survives manifest rollback race\n"
            (logs / "owned.log").write_bytes(payload)
            source_inode = logs.lstat().st_ino
            backup = a / "99-output-infra/.logs-migration-source"
            original_remove = os.remove
            competitor = []

            def create_competitor_after_managed_link_removal(path, *args, **kwargs):
                result = original_remove(path, *args, **kwargs)
                if os.path.abspath(os.fspath(path)) == str(logs):
                    logs.mkdir()
                    competitor.append(logs.lstat().st_ino)
                return result

            with mock.patch.object(os, "remove", side_effect=create_competitor_after_managed_link_removal):
                with self.assertRaises(OSError):
                    self.bind(root, a, manifest_failure=True)
            self.assertEqual(1, len(competitor))
            self.assertEqual(competitor[0], logs.lstat().st_ino)
            self.assertEqual(source_inode, backup.lstat().st_ino)
            self.assertEqual(payload, (backup / "owned.log").read_bytes())
            self.assertTrue((root / "infra/.logs-migration.json").is_file())

    def test_valid_managed_link_repoints_without_misattributing_old_bytes(self):
        with tempfile.TemporaryDirectory(prefix="req19-switch-") as tmp:
            root, logs, a, b = self.fixture(tmp)
            old = a / "99-output-infra/owned.log"
            old.write_bytes(b"site-a-only\n")
            logs.symlink_to(os.path.relpath(old.parent, logs.parent))
            original_remove = os.remove

            def forbid_unlinking_log_root(path, *args, **kwargs):
                if os.path.abspath(os.fspath(path)) == str(logs):
                    raise AssertionError("setup must not unlink the prior log owner before atomic re-point")
                return original_remove(path, *args, **kwargs)

            with mock.patch.object(os, "remove", side_effect=forbid_unlinking_log_root):
                self.bind(root, b)
            self.assertEqual((b / "99-output-infra").resolve(), logs.resolve())
            self.assertEqual(b"site-a-only\n", old.read_bytes())
            self.assertFalse((b / "99-output-infra/owned.log").exists())

    def test_real_prebinder_stages_never_unlink_managed_or_foreign_log_root(self):
        # Seed the independently fixed REQ-19 tuple to expose pre-binder behavior
        # even while the production registration test remains RED.
        mapping = [row for row in SETUP.WORKSPACE_INPUT_MAPPINGS if row[0] != "infra/logs"] + [MAPPING]
        for variant in ("managed", "foreign"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory(prefix="req19-prebind-") as tmp:
                root, logs, a, b = self.fixture(tmp)
                old = a / "99-output-infra/owned.log"
                old.write_bytes(b"original owner\n")
                if variant == "managed":
                    target = os.path.relpath(old.parent, logs.parent)
                else:
                    outside = Path(tmp) / "outside"
                    outside.mkdir()
                    target = os.path.relpath(outside, logs.parent)
                logs.symlink_to(target)
                removed = []
                original_remove, original_unlink = os.remove, os.unlink

                def observe(operation, label):
                    def recorded(path, *args, **kwargs):
                        if os.path.abspath(os.fspath(path)) == str(logs):
                            removed.append(label)
                        return operation(path, *args, **kwargs)
                    return recorded

                error = None
                with mock.patch.object(SETUP, "WORKSPACE_INPUT_MAPPINGS", mapping), \
                        mock.patch.object(os, "remove", side_effect=observe(original_remove, "remove")), \
                        mock.patch.object(os, "unlink", side_effect=observe(original_unlink, "unlink")):
                    try:
                        self.bind(root, b)
                    except (OSError, ValueError, SystemExit) as caught:
                        error = caught
                self.assertEqual([], removed, "generic cleanup/conflict stages must not unlink infra/logs")
                self.assertEqual(b"original owner\n", old.read_bytes())
                if variant == "managed":
                    self.assertIsNone(error)
                    self.assertEqual((b / "99-output-infra").resolve(), logs.resolve())
                else:
                    self.assertIsNotNone(error)
                    self.assertEqual(target, os.readlink(logs))

    def test_foreign_chained_broken_and_cycle_symlinks_fail_closed(self):
        for variant in ("foreign", "chain", "broken", "cycle"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory(prefix="req19-badlink-") as tmp:
                root, logs, a, b = self.fixture(tmp)
                old = a / "99-output-infra/owned.log"
                old.write_bytes(b"original\n")
                if variant == "foreign":
                    outside = Path(tmp) / "outside"
                    outside.mkdir()
                    target = os.path.relpath(outside, logs.parent)
                elif variant == "chain":
                    intermediate = root / "infra/intermediate"
                    intermediate.symlink_to(os.path.relpath(old.parent, intermediate.parent))
                    target = "intermediate"
                elif variant == "broken":
                    target = "../DAY0-Prepare/gone/99-output-infra"
                else:
                    target = "logs"
                logs.symlink_to(target)
                self.assert_rejected(root, b)
                self.assertTrue(logs.is_symlink())
                self.assertEqual(target, os.readlink(logs))
                self.assertEqual(b"original\n", old.read_bytes())

    def test_file_and_fifo_other_state_fail_closed(self):
        for variant in ("file", "fifo"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory(prefix="req19-other-") as tmp:
                root, logs, a, _ = self.fixture(tmp)
                if variant == "file":
                    logs.write_bytes(b"unowned\n")
                else:
                    os.mkfifo(logs)
                old_ino = logs.lstat().st_ino
                self.assert_rejected(root, a)
                self.assertEqual(old_ino, logs.lstat().st_ino)
                if variant == "file":
                    self.assertEqual(b"unowned\n", logs.read_bytes())

    def test_collision_preflight_moves_zero_objects(self):
        with tempfile.TemporaryDirectory(prefix="req19-collision-") as tmp:
            root, logs, a, _ = self.fixture(tmp)
            logs.mkdir()
            (logs / "first.log").write_bytes(b"source first\n")
            (logs / "second.log").write_bytes(b"source second\n")
            target = a / "99-output-infra/second.log"
            target.write_bytes(b"destination second\n")
            old_first_ino = (logs / "first.log").stat().st_ino
            self.assert_rejected(root, a)
            self.assertFalse(logs.is_symlink())
            self.assertEqual(old_first_ino, (logs / "first.log").stat().st_ino)
            self.assertEqual(b"source second\n", (logs / "second.log").read_bytes())
            self.assertEqual(b"destination second\n", target.read_bytes())
            self.assertFalse((a / "99-output-infra/first.log").exists())

    def test_nested_collision_preflight_moves_zero_objects(self):
        with tempfile.TemporaryDirectory(prefix="req19-nested-collision-") as tmp:
            root, logs, a, _ = self.fixture(tmp)
            logs.mkdir()
            first = logs / "first.log"
            first.write_bytes(b"source first\n")
            source = logs / "clients/run-1/deploy.log"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"source nested\n")
            target = a / "99-output-infra/clients/run-1/deploy.log"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"destination nested\n")
            first_ino = first.stat().st_ino
            self.assert_rejected(root, a)
            self.assertTrue(logs.is_dir() and not logs.is_symlink())
            self.assertEqual(first_ino, first.stat().st_ino)
            self.assertEqual(b"source nested\n", source.read_bytes())
            self.assertEqual(b"destination nested\n", target.read_bytes())
            self.assertFalse((a / "99-output-infra/first.log").exists())

    def test_symlink_source_is_rejected_before_any_migration(self):
        with tempfile.TemporaryDirectory(prefix="req19-source-link-") as tmp:
            root, logs, a, _ = self.fixture(tmp)
            logs.mkdir()
            (logs / "first.log").write_bytes(b"safe source\n")
            outside = Path(tmp) / "outside.log"
            outside.write_bytes(b"not a migration source\n")
            (logs / "second.log").symlink_to(outside)
            self.assert_rejected(root, a)
            self.assertTrue(logs.is_dir() and not logs.is_symlink())
            self.assertEqual(b"safe source\n", (logs / "first.log").read_bytes())
            self.assertFalse((a / "99-output-infra/first.log").exists())
            self.assertEqual(b"not a migration source\n", outside.read_bytes())

    def test_durable_receipt_binds_source_destination_before_first_transfer(self):
        with tempfile.TemporaryDirectory(prefix="req19-receipt-first-") as tmp:
            root, logs, a, _ = self.fixture(tmp)
            logs.mkdir()
            payloads = {"first.log": b"one\n", "clients/run-1/deploy.log": b"nested\n"}
            for name, payload in payloads.items():
                path = logs / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)
            destination = a / "99-output-infra"
            observed = []
            originals = (os.rename, os.replace, os.link, shutil.copyfile)

            def guard(operation):
                def wrapped(source, target, *args, **kwargs):
                    source_path = Path(os.fspath(source))
                    target_path = Path(os.fspath(target))
                    if (source_path == logs or logs in source_path.parents) and (
                            target_path == destination or destination in target_path.parents):
                        self.assert_recovery_receipt(root, logs, a, payloads)
                        observed.append(source_path)
                    return operation(source, target, *args, **kwargs)
                return wrapped

            with mock.patch.object(os, "rename", side_effect=guard(originals[0])), \
                    mock.patch.object(os, "replace", side_effect=guard(originals[1])), \
                    mock.patch.object(os, "link", side_effect=guard(originals[2])), \
                    mock.patch.object(shutil, "copyfile", side_effect=guard(originals[3])):
                self.bind(root, a)
            self.assertTrue(observed, "at least one real source entry must cross the transfer boundary")
            self.assertTrue(logs.is_symlink())
            self.assertFalse((root / "infra/.logs-migration.json").exists())

    def test_injected_move_failure_keeps_a_recoverable_real_directory(self):
        with tempfile.TemporaryDirectory(prefix="req19-fault-") as tmp:
            root, logs, a, _ = self.fixture(tmp)
            logs.mkdir()
            payloads = {"first.log": b"one\n", "second.log": b"two\n"}
            for name, data in payloads.items():
                (logs / name).write_bytes(data)
            destination = a / "99-output-infra"
            attempted = []
            original_rename, original_replace = os.rename, os.replace
            original_link, original_copyfile = os.link, shutil.copyfile

            def fail_second_entry_transfer(operation):
                def guarded(source, target, *args, **kwargs):
                    source_path = Path(os.fspath(source))
                    target_path = Path(os.fspath(target))
                    if source_path.parent == logs and target_path.parent == destination:
                        if source_path.name not in attempted:
                            attempted.append(source_path.name)
                        if len(attempted) >= 2:
                            raise OSError("injected second-entry transfer failure")
                    return operation(source, target, *args, **kwargs)
                return guarded

            # Exercise the observable file-transfer boundary; no private
            # product helper or one mandatory no-clobber primitive is assumed.
            with mock.patch.object(os, "rename", side_effect=fail_second_entry_transfer(original_rename)), \
                    mock.patch.object(os, "replace", side_effect=fail_second_entry_transfer(original_replace)), \
                    mock.patch.object(os, "link", side_effect=fail_second_entry_transfer(original_link)), \
                    mock.patch.object(shutil, "copyfile", side_effect=fail_second_entry_transfer(original_copyfile)):
                self.assert_rejected(root, a)
            self.assertEqual(2, len(attempted), "the second source entry must reach the injected transfer boundary")
            self.assertTrue(logs.is_dir() and not logs.is_symlink())
            self.assert_recovery_receipt(root, logs, a, payloads)
            for name, data in payloads.items():
                copies = [path for path in (logs / name, destination / name) if path.exists()]
                self.assertTrue(copies, f"{name}: interrupted transfer lost both copies")
                for copy in copies:
                    self.assertEqual(data, copy.read_bytes())

    def test_interrupted_transfer_retries_without_overwriting_or_losing_bytes(self):
        with tempfile.TemporaryDirectory(prefix="req19-resume-") as tmp:
            root, logs, a, _ = self.fixture(tmp)
            logs.mkdir()
            payloads = {"first.log": b"one\n", "second.log": b"two\n"}
            for name, payload in payloads.items():
                (logs / name).write_bytes(payload)
            destination = a / "99-output-infra"
            attempted = []
            originals = (os.rename, os.replace, os.link, shutil.copyfile)

            def interrupt_second(operation):
                def guarded(source, target, *args, **kwargs):
                    source_path = Path(os.fspath(source))
                    if source_path.parent == logs and Path(os.fspath(target)).parent == destination:
                        if source_path.name not in attempted:
                            attempted.append(source_path.name)
                        if len(attempted) >= 2:
                            raise OSError("injected second transfer failure")
                    return operation(source, target, *args, **kwargs)
                return guarded

            with mock.patch.object(os, "rename", side_effect=interrupt_second(originals[0])), \
                    mock.patch.object(os, "replace", side_effect=interrupt_second(originals[1])), \
                    mock.patch.object(os, "link", side_effect=interrupt_second(originals[2])), \
                    mock.patch.object(shutil, "copyfile", side_effect=interrupt_second(originals[3])):
                self.assert_rejected(root, a)
            self.assertEqual(2, len(attempted))
            self.assert_recovery_receipt(root, logs, a, payloads)
            self.bind(root, a)
            self.assertTrue(logs.is_symlink())
            for name, payload in payloads.items():
                self.assertEqual(payload, (destination / name).read_bytes())
            self.assertFalse((root / "infra/.logs-migration.json").exists())

    def test_manifest_failure_after_migration_restores_real_root_without_loss(self):
        with tempfile.TemporaryDirectory(prefix="req19-manifest-rollback-") as tmp:
            root, logs, a, _ = self.fixture(tmp)
            logs.mkdir()
            payloads = {"one.log": b"one\n", "clients/run-1/deploy.log": b"nested\n"}
            for name, payload in payloads.items():
                path = logs / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)
            original_inode = logs.lstat().st_ino
            with self.assertRaisesRegex(OSError, "injected manifest failure"):
                self.bind(root, a, manifest_failure=True)
            self.assertTrue(logs.is_dir() and not logs.is_symlink())
            self.assertEqual(original_inode, logs.lstat().st_ino)
            for name, payload in payloads.items():
                self.assertEqual(payload, (logs / name).read_bytes())
            destination = a / "99-output-infra"
            self.assertFalse(os.path.lexists(destination / ".logs-migration-source"))
            if any((destination / name).exists() for name in payloads):
                self.assert_recovery_receipt(root, logs, a, payloads)

    def test_interrupted_link_publication_recovers_receipt_bound_backup(self):
        with tempfile.TemporaryDirectory(prefix="req19-backup-resume-") as tmp:
            root, logs, a, _ = self.fixture(tmp)
            logs.mkdir()
            (logs / "one.log").write_bytes(b"source bytes\n")
            original_inode = logs.lstat().st_ino
            backup = a / "99-output-infra/.logs-migration-source"
            original_symlink = os.symlink

            def interrupt_link(target, link_name, *args, **kwargs):
                if os.path.abspath(os.fspath(link_name)) == str(logs):
                    raise OSError("injected log link publication failure")
                return original_symlink(target, link_name, *args, **kwargs)

            with mock.patch.object(os, "symlink", side_effect=interrupt_link):
                with self.assertRaisesRegex(OSError, "injected log link publication failure"):
                    self.bind(root, a)
            self.assertTrue(logs.is_dir() and not logs.is_symlink())
            self.assertEqual(original_inode, logs.lstat().st_ino)
            self.assertFalse(os.path.lexists(backup))
            self.assertEqual(b"source bytes\n", (logs / "one.log").read_bytes())
            receipt = root / "infra/.logs-migration.json"
            self.assertTrue(receipt.is_file())
            document = json.loads(receipt.read_text(encoding="utf-8"))
            self.assertEqual(original_inode, document["source"]["ino"])
            self.assertEqual(str(a / "99-output-infra"), document["destination"]["path"])
            self.bind(root, a)
            self.assertTrue(logs.is_symlink())
            self.assertEqual(b"source bytes\n", (a / "99-output-infra/one.log").read_bytes())
            self.assertFalse(os.path.lexists(backup))
            self.assertFalse(os.path.lexists(receipt))

    def test_successful_commit_excludes_backup_from_published_logs(self):
        with tempfile.TemporaryDirectory(prefix="req19-backup-commit-") as tmp:
            root, logs, a, _ = self.fixture(tmp)
            logs.mkdir()
            (logs / "one.log").write_bytes(b"project log\n")
            self.bind(root, a)
            self.assertTrue(logs.is_symlink())
            self.assertEqual({"one.log"}, {entry.name for entry in logs.iterdir()})
            self.assertFalse(os.path.lexists(a / "99-output-infra/.logs-migration-source"))
            self.assertFalse(os.path.lexists(root / "infra/.logs-migration.json"))

    def test_interrupted_backup_cleanup_retries_without_partial_real_root(self):
        with tempfile.TemporaryDirectory(prefix="req19-backup-cleanup-") as tmp:
            root, logs, a, _ = self.fixture(tmp)
            logs.mkdir()
            payloads = {"first.log": b"first source\n", "second.log": b"second source\n"}
            for name, payload in payloads.items():
                (logs / name).write_bytes(payload)
            backup = a / "99-output-infra/.logs-migration-source"
            original_unlink = os.unlink
            removed = []

            def fail_second_backup_entry(path, *args, **kwargs):
                item = Path(os.fspath(path))
                if item.parent == backup:
                    removed.append(item.name)
                    if len(removed) == 2:
                        raise OSError("injected second backup cleanup failure")
                return original_unlink(path, *args, **kwargs)

            with mock.patch.object(os, "unlink", side_effect=fail_second_backup_entry):
                with self.assertRaisesRegex(OSError, "injected second backup cleanup failure"):
                    self.bind(root, a)
            self.assertEqual(2, len(removed))
            receipt = root / "infra/.logs-migration.json"
            self.assertTrue(receipt.is_file())
            if logs.is_symlink():
                for name, payload in payloads.items():
                    self.assertEqual(payload, (logs / name).read_bytes())
            else:
                self.assertTrue(logs.is_dir())
                for name, payload in payloads.items():
                    self.assertEqual(payload, (logs / name).read_bytes())
            self.bind(root, a)
            self.assertTrue(logs.is_symlink())
            for name, payload in payloads.items():
                self.assertEqual(payload, (logs / name).read_bytes())
            self.assertFalse(os.path.lexists(backup))
            self.assertFalse(os.path.lexists(receipt))

    def test_interrupted_receipt_cleanup_retries_after_backup_is_gone(self):
        with tempfile.TemporaryDirectory(prefix="req19-receipt-cleanup-") as tmp:
            root, logs, a, _ = self.fixture(tmp)
            logs.mkdir()
            (logs / "one.log").write_bytes(b"committed source\n")
            receipt = root / "infra/.logs-migration.json"
            backup = a / "99-output-infra/.logs-migration-source"
            original_unlink = os.unlink

            def interrupt_receipt_remove(path, *args, **kwargs):
                if os.path.abspath(os.fspath(path)) == str(receipt):
                    raise OSError("injected receipt cleanup failure")
                return original_unlink(path, *args, **kwargs)

            with mock.patch.object(os, "unlink", side_effect=interrupt_receipt_remove):
                with self.assertRaisesRegex(OSError, "injected receipt cleanup failure"):
                    self.bind(root, a)
            self.assertTrue(logs.is_symlink())
            self.assertEqual(b"committed source\n", (logs / "one.log").read_bytes())
            self.assertFalse(os.path.lexists(backup))
            self.assertTrue(receipt.is_file())
            self.bind(root, a)
            self.assertTrue(logs.is_symlink())
            self.assertFalse(os.path.lexists(receipt))

    def test_process_crash_before_receipt_replace_preserves_orphan_for_offline_restore(self):
        with tempfile.TemporaryDirectory(prefix="req19-crash-pre-replace-") as tmp:
            root, logs, a, _ = self.fixture(tmp)
            payload = b"pre-replace original bytes\n"
            backup, receipt = self.seed_committing_backup(root, logs, a, payload)
            backup_inode, receipt_inode = backup.lstat().st_ino, receipt.lstat().st_ino
            receipt_bytes = receipt.read_bytes()
            original_replace = os.replace
            child = os.fork()
            if child == 0:
                def crash_before_replace(source, destination, *args, **kwargs):
                    if os.path.abspath(os.fspath(destination)) == str(receipt):
                        os._exit(73)
                    return original_replace(source, destination, *args, **kwargs)
                try:
                    with mock.patch.object(SETUP, "HTTP_BASE", str(root)), \
                            mock.patch.object(os, "replace", side_effect=crash_before_replace):
                        SETUP._mark_infra_log_receipt_finalizing(json.loads(receipt_bytes))
                except BaseException:
                    os._exit(99)
                os._exit(98)
            _pid, status = os.waitpid(child, 0)
            self.assertTrue(os.WIFEXITED(status))
            self.assertEqual(73, os.WEXITSTATUS(status))
            orphans = sorted(path for path in (root / "infra").iterdir()
                             if path.name.startswith(".logs-migration.")
                             and path.name != ".logs-migration.json")
            self.assertEqual(1, len(orphans), "crash must leave the fsynced atomic temp visible")
            orphan = orphans[0]
            orphan_inode, orphan_bytes = orphan.lstat().st_ino, orphan.read_bytes()
            self.assertEqual("finalizing", json.loads(orphan_bytes)["phase"])
            self.assertEqual(receipt_inode, receipt.lstat().st_ino)
            self.assertEqual(receipt_bytes, receipt.read_bytes())
            self.assertEqual(backup_inode, backup.lstat().st_ino)
            self.assertEqual(payload, (backup / "owned.log").read_bytes())
            self.assertEqual(payload, (logs / "owned.log").read_bytes())

            # A newer temp is ambiguous, not an instruction to commit or
            # discard it.  Inventory it and refuse setup until an offline
            # operator has retained its exact bytes outside the worktree.
            with self.assertRaises(ValueError) as rejected:
                self.bind(root, a)
            self.assertIn(orphan.name, str(rejected.exception))
            self.assertEqual(orphan_inode, orphan.lstat().st_ino)
            self.assertEqual(orphan_bytes, orphan.read_bytes())
            self.assertEqual(receipt_bytes, receipt.read_bytes())
            self.assertEqual(backup_inode, backup.lstat().st_ino)
            evidence = Path(tmp) / "offline-orphan-evidence"
            evidence.mkdir()
            quarantined = evidence / orphan.name
            os.rename(orphan, quarantined)
            self.assertEqual(orphan_inode, quarantined.lstat().st_ino)
            self.assertEqual(orphan_bytes, quarantined.read_bytes())
            self.bind(root, a)
            self.assertTrue(logs.is_symlink())
            self.assertEqual(payload, (logs / "owned.log").read_bytes())
            self.assertFalse(os.path.lexists(backup))
            self.assertFalse(os.path.lexists(receipt))
            self.assertEqual(orphan_bytes, quarantined.read_bytes())

    def test_orphan_without_receipt_is_inventory_blocker_not_auto_deleted(self):
        with tempfile.TemporaryDirectory(prefix="req19-orphan-alone-") as tmp:
            root, logs, a, _ = self.fixture(tmp)
            orphan = root / "infra/.logs-migration.ABC123"
            orphan.write_bytes(b"untrusted interrupted receipt bytes\n")
            near_match = root / "infra/.logs-migrationx"
            near_match.write_bytes(b"unrelated near-match bytes\n")
            orphan_inode, orphan_bytes = orphan.lstat().st_ino, orphan.read_bytes()
            with self.assertRaises(ValueError) as rejected:
                self.bind(root, a)
            self.assertIn(orphan.name, str(rejected.exception))
            self.assertFalse(os.path.lexists(logs))
            self.assertEqual(orphan_inode, orphan.lstat().st_ino)
            self.assertEqual(orphan_bytes, orphan.read_bytes())
            self.assertEqual(b"unrelated near-match bytes\n", near_match.read_bytes())
            evidence = Path(tmp) / "retained-orphan"
            os.rename(orphan, evidence)
            self.bind(root, a)
            self.assertTrue(logs.is_symlink())
            self.assertEqual(orphan_bytes, evidence.read_bytes())
            self.assertEqual(b"unrelated near-match bytes\n", near_match.read_bytes())

    def test_pending_hoststate_inventory_is_exact_and_never_follows_entries(self):
        with tempfile.TemporaryDirectory(prefix="req19-pending-inventory-") as tmp:
            root, _, _, _ = self.fixture(tmp)
            infra = root / "infra"
            (infra / ".logs-migration.json").write_bytes(b"pending receipt\n")
            (infra / ".logs-migration.file").write_bytes(b"pending temp\n")
            (infra / ".logs-migration.directory").mkdir()
            foreign = Path(tmp) / "foreign"
            foreign.write_bytes(b"foreign bytes stay outside\n")
            (infra / ".logs-migration.symlink").symlink_to(foreign)
            (infra / ".logs-migration.dangling").symlink_to("missing")
            (infra / ".logs-migrationx").write_bytes(b"near match\n")
            (infra / ".logs-migration-backup").write_bytes(b"near match\n")
            self.assertEqual(
                tuple(sorted((
                    ".logs-migration.json", ".logs-migration.file",
                    ".logs-migration.directory", ".logs-migration.symlink",
                    ".logs-migration.dangling",
                ))),
                CONTRACT.infra_log_pending_state_names(root),
            )
            self.assertEqual(b"foreign bytes stay outside\n", foreign.read_bytes())

    def test_process_crash_after_receipt_replace_recovers_without_false_commit(self):
        with tempfile.TemporaryDirectory(prefix="req19-crash-post-replace-") as tmp:
            root, logs, a, _ = self.fixture(tmp)
            payload = b"post-replace original bytes\n"
            backup, receipt = self.seed_committing_backup(root, logs, a, payload)
            backup_inode = backup.lstat().st_ino
            original_fsync = os.fsync
            child = os.fork()
            if child == 0:
                def crash_before_parent_directory_fsync(descriptor):
                    if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                        os._exit(74)
                    return original_fsync(descriptor)
                try:
                    with mock.patch.object(SETUP, "HTTP_BASE", str(root)), \
                            mock.patch.object(os, "fsync", side_effect=crash_before_parent_directory_fsync):
                        SETUP._mark_infra_log_receipt_finalizing(json.loads(receipt.read_bytes()))
                except BaseException:
                    os._exit(99)
                os._exit(98)
            _pid, status = os.waitpid(child, 0)
            self.assertTrue(os.WIFEXITED(status))
            self.assertEqual(74, os.WEXITSTATUS(status))
            self.assertEqual("finalizing", json.loads(receipt.read_bytes())["phase"])
            self.assertEqual(backup_inode, backup.lstat().st_ino)
            self.assertEqual(payload, (backup / "owned.log").read_bytes())
            self.assertEqual(payload, (logs / "owned.log").read_bytes())
            self.assertFalse(any(path.name.startswith(".logs-migration.")
                                 and path.name != ".logs-migration.json"
                                 for path in (root / "infra").iterdir()))
            self.bind(root, a)
            self.assertTrue(logs.is_symlink())
            self.assertEqual(payload, (logs / "owned.log").read_bytes())
            self.assertFalse(os.path.lexists(backup))
            self.assertFalse(os.path.lexists(receipt))

    def test_receipt_path_traversal_is_rejected_before_recovery(self):
        for field in ("entries", "directories"):
            with self.subTest(field=field), tempfile.TemporaryDirectory(prefix="req19-receipt-path-") as tmp:
                root, logs, a, _ = self.fixture(tmp)
                receipt = root / "infra/.logs-migration.json"
                document = {
                    "schema_version": 1,
                    "phase": "finalizing",
                    "source": {"path": str(logs), "dev": 1, "ino": 2},
                    "destination": {"path": str(a / "99-output-infra")},
                    "entries": {}, "directories": [],
                }
                if field == "entries":
                    document[field]["../../outside.log"] = {"size": 1, "sha256": "0" * 64}
                else:
                    document[field].append("../../outside")
                receipt.write_text(json.dumps(document), encoding="utf-8")
                with mock.patch.object(SETUP, "HTTP_BASE", str(root)):
                    with self.assertRaisesRegex(ValueError, "不安全"):
                        SETUP._read_infra_log_receipt()

    def test_log_lock_rejects_symlink_and_hardlink_substitution(self):
        for variant in ("symlink", "hardlink"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory(prefix="req19-lock-owner-") as tmp:
                root, logs, a, _ = self.fixture(tmp)
                foreign = Path(tmp) / "foreign.lock"
                foreign.write_bytes(b"do not lock or rewrite this object\n")
                lock = root / "infra/.logs.lock"
                if variant == "symlink":
                    lock.symlink_to(foreign)
                else:
                    os.link(foreign, lock)
                old_inode = foreign.stat().st_ino
                self.assert_rejected(root, a)
                self.assertFalse(os.path.lexists(logs))
                self.assertEqual(old_inode, foreign.stat().st_ino)
                self.assertEqual(b"do not lock or rewrite this object\n", foreign.read_bytes())

    def test_partial_migration_keeps_real_dir_and_recovery_evidence(self):
        with tempfile.TemporaryDirectory(prefix="req19-partial-") as tmp:
            root, logs, a, _ = self.fixture(tmp)
            logs.mkdir()
            (logs / "remaining.log").write_bytes(b"unverified source\n")
            already_moved = a / "99-output-infra/moved.log"
            already_moved.write_bytes(b"verified destination\n")
            self.assert_rejected(root, a)
            self.assertTrue(logs.is_dir() and not logs.is_symlink())
            self.assertEqual(b"unverified source\n", (logs / "remaining.log").read_bytes())
            self.assertEqual(b"verified destination\n", already_moved.read_bytes())

    def test_real_unsetup_preserves_foreign_chained_broken_and_cycle_log_links(self):
        for variant, with_manifest in product(("foreign", "chain", "broken", "cycle"), (False, True)):
            with self.subTest(variant=variant, with_manifest=with_manifest), tempfile.TemporaryDirectory(prefix="req19-unsetup-bad-") as tmp:
                root, logs, a, _ = self.fixture(tmp)
                owned = a / "99-output-infra/owned.log"
                owned.write_bytes(b"owned by site-a\n")
                if variant == "foreign":
                    outside = Path(tmp) / "foreign"
                    outside.mkdir()
                    target = os.path.relpath(outside, logs.parent)
                elif variant == "chain":
                    bridge = root / "infra/bridge"
                    bridge.symlink_to(os.path.relpath(owned.parent, bridge.parent))
                    target = "bridge"
                elif variant == "broken":
                    target = "../DAY0-Prepare/missing/99-output-infra"
                else:
                    target = "logs"
                logs.symlink_to(target)
                old_ino = logs.lstat().st_ino
                manifest = root / "ztp/.setup_manifest"
                manifest_bytes = f"# setup manifest — proj: {a}\n{logs}\n".encode()
                if with_manifest:
                    manifest.parent.mkdir(parents=True)
                    manifest.write_bytes(manifest_bytes)
                with mock.patch.multiple(
                    UNSETUP, HTTP_BASE=str(root), HERE=str(root / "DAY0-Prepare"),
                    ZTP=str(root / "ztp"), MANIFEST_FILE=str(manifest),
                    _AUTO_YES=True, _DRY_RUN=False,
                ), redirect_stdout(io.StringIO()):
                    # Call the real filesystem decision stage, not main(), which
                    # would stop host services outside this hermetic fixture.
                    UNSETUP._main_locked(SimpleNamespace(project=None))
                self.assertTrue(logs.is_symlink())
                self.assertEqual(old_ino, logs.lstat().st_ino)
                self.assertEqual(target, os.readlink(logs))
                if with_manifest:
                    self.assertEqual(manifest_bytes, manifest.read_bytes())
                else:
                    self.assertFalse(manifest.exists())
                self.assertEqual(b"owned by site-a\n", owned.read_bytes())

    def test_real_unsetup_removes_only_valid_managed_log_link_not_project_bytes(self):
        for with_manifest in (False, True):
            with self.subTest(with_manifest=with_manifest), tempfile.TemporaryDirectory(prefix="req19-unsetup-owned-") as tmp:
                root, logs, a, _ = self.fixture(tmp)
                owned = a / "99-output-infra/owned.log"
                owned.write_bytes(b"owned by site-a\n")
                logs.symlink_to(os.path.relpath(owned.parent, logs.parent))
                manifest = root / "ztp/.setup_manifest"
                if with_manifest:
                    manifest.parent.mkdir(parents=True)
                    manifest.write_text(f"# setup manifest — proj: {a}\n{logs}\n", encoding="utf-8")
                with mock.patch.multiple(
                    UNSETUP, HTTP_BASE=str(root), HERE=str(root / "DAY0-Prepare"),
                    ZTP=str(root / "ztp"), MANIFEST_FILE=str(manifest),
                    _AUTO_YES=True, _DRY_RUN=False,
                ), redirect_stdout(io.StringIO()):
                    result = UNSETUP._main_locked(SimpleNamespace(project=str(a)))
                self.assertEqual(0, result)
                self.assertFalse(os.path.lexists(logs))
                self.assertFalse(manifest.exists())
                self.assertEqual(b"owned by site-a\n", owned.read_bytes())

    def test_real_unsetup_preserves_finalizing_receipt_and_managed_owner(self):
        for pending in (True, False):
            with self.subTest(pending=pending), tempfile.TemporaryDirectory(prefix="req19-unsetup-receipt-") as tmp:
                root, logs, a, _ = self.fixture(tmp)
                destination = a / "99-output-infra"
                owned = destination / "owned.log"
                owned.write_bytes(b"committed project bytes\n")
                logs.symlink_to(os.path.relpath(destination, logs.parent))
                link_inode = logs.lstat().st_ino
                manifest = root / "ztp/.setup_manifest"
                manifest.parent.mkdir(parents=True)
                manifest_bytes = f"# setup manifest — proj: {a}\n{logs}\n".encode()
                manifest.write_bytes(manifest_bytes)
                receipt = root / "infra/.logs-migration.json"
                backup = destination / ".logs-migration-source"
                if pending:
                    backup.mkdir()
                    os.link(owned, backup / "owned.log")
                    backup_inode = backup.lstat().st_ino
                    payload = owned.read_bytes()
                    receipt.write_text(json.dumps({
                        "schema_version": 1, "phase": "finalizing",
                        "source": {"path": str(logs), "dev": backup.lstat().st_dev,
                                   "ino": backup_inode},
                        "destination": {"path": str(destination)},
                        "directories": [],
                        "entries": {"owned.log": {
                            "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest(),
                        }},
                    }), encoding="utf-8")
                    receipt_inode, receipt_bytes = receipt.lstat().st_ino, receipt.read_bytes()
                with mock.patch.multiple(
                    UNSETUP, HTTP_BASE=str(root), HERE=str(root / "DAY0-Prepare"),
                    ZTP=str(root / "ztp"), MANIFEST_FILE=str(manifest),
                    _AUTO_YES=True, _DRY_RUN=False,
                ), redirect_stdout(io.StringIO()):
                    result = UNSETUP._main_locked(SimpleNamespace(project=str(a)))
                if pending:
                    self.assertNotEqual(0, result)
                    self.assertTrue(logs.is_symlink())
                    self.assertEqual(link_inode, logs.lstat().st_ino)
                    self.assertEqual(manifest_bytes, manifest.read_bytes())
                    self.assertEqual(receipt_inode, receipt.lstat().st_ino)
                    self.assertEqual(receipt_bytes, receipt.read_bytes())
                    self.assertEqual(backup_inode, backup.lstat().st_ino)
                    self.assertEqual(b"committed project bytes\n", (backup / "owned.log").read_bytes())
                else:
                    self.assertEqual(0, result)
                    self.assertFalse(os.path.lexists(logs))
                    self.assertFalse(manifest.exists())
                self.assertEqual(b"committed project bytes\n", owned.read_bytes())


if __name__ == "__main__":
    unittest.main()
