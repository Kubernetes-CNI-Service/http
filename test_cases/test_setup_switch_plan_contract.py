#!/usr/bin/env python3
"""Read-only P→Q setup inventory; it is not publication authority."""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
from types import SimpleNamespace
import unittest
from contextlib import redirect_stdout
from unittest import mock

from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]


def _tree_snapshot(root: Path) -> dict[str, tuple[object, ...]]:
    """Detect an inventory call changing any private fixture byte or link."""
    result = {}
    pending = [root]
    while pending:
        path = pending.pop()
        named = path.lstat()
        relative = path.relative_to(root).as_posix()
        identity = (
            stat.S_IFMT(named.st_mode), stat.S_IMODE(named.st_mode),
            named.st_dev, named.st_ino, named.st_size, named.st_mtime_ns,
        )
        if stat.S_ISDIR(named.st_mode):
            children = sorted(path.iterdir(), reverse=True)
            pending.extend(children)
            result[relative] = identity
        elif stat.S_ISLNK(named.st_mode):
            result[relative] = (*identity, os.readlink(path))
        elif stat.S_ISREG(named.st_mode):
            result[relative] = (*identity, hashlib.sha256(path.read_bytes()).hexdigest())
        else:
            result[relative] = identity
    return result


class SetupSwitchPlanContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="r22-setup-plan-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        day0 = self.root / "DAY0-Prepare"
        day0.mkdir()
        shutil.copy2(ROOT / "DAY0-Prepare/01-a-setup.py", day0 / "01-a-setup.py")
        shutil.copytree(ROOT / "tools", self.root / "tools")
        optimize = self.root / "ztp/optimize"
        optimize.mkdir(parents=True)
        shutil.copy2(ROOT / "ztp/optimize/sample_links.py", optimize / "sample_links.py")
        self.setup = load_script(
            "r22_private_setup_switch_plan", day0 / "01-a-setup.py",
        )
        self.p, self.q = day0 / "p", day0 / "q"
        self.p.mkdir()
        self.q.mkdir()
        for project in (self.p, self.q):
            (project / "01-global.yaml").write_bytes(project.name.encode() + b" global\n")
        (self.p / "p-only.pub").write_bytes(b"p-only\n")
        (self.q / "q-only.pub").write_bytes(b"q-only\n")
        self.common = self.root / "ztp/config/cumulus/template/01-global.yaml"
        self.p_only = self.root / "ztp/config/publickey/p-only.pub"
        self.q_only = self.root / "ztp/config/publickey/q-only.pub"
        for path in (self.common, self.p_only, self.q_only):
            path.parent.mkdir(parents=True, exist_ok=True)
        self.common.symlink_to(os.path.relpath(self.p / "01-global.yaml", self.common.parent))
        self.p_only.symlink_to(os.path.relpath(self.p / "p-only.pub", self.p_only.parent))
        self.manifest = self.root / "ztp/.setup_manifest"
        self.manifest.write_text(
            f"# setup manifest — proj: {self.p}\n{self.common}\n{self.p_only}\n",
            encoding="utf-8",
        )

    def test_inventory_reports_p_only_and_dynamic_q_only_without_writing(self) -> None:
        before = _tree_snapshot(self.root)
        expected_manifest = self.manifest.lstat()
        expected_common = self.common.lstat()
        expected_p_only = self.p_only.lstat()
        plan = self.setup.inventory_setup_switch_shared_paths(str(self.p), str(self.q))
        self.assertEqual(before, _tree_snapshot(self.root))
        self.assertIs(plan["complete"], False)
        self.assertTrue(plan["blockers"])
        self.assertEqual(str(self.p), plan["old_project"])
        self.assertEqual(str(self.q), plan["new_project"])
        self.assertEqual(
            {
                "dev": expected_manifest.st_dev,
                "ino": expected_manifest.st_ino,
                "mode": stat.S_IMODE(expected_manifest.st_mode),
                "size": expected_manifest.st_size,
                "sha256": hashlib.sha256(self.manifest.read_bytes()).hexdigest(),
            },
            plan["p_manifest_state"],
        )
        self.assertIn(str(self.p_only), plan["p_only"])
        self.assertIn(str(self.q_only), plan["q_only_candidates"])
        for path in (self.common, self.p_only, self.q_only):
            self.assertIn(str(path), plan["managed_paths"])
        self.assertEqual(
            {
                str(self.common): {
                    "dev": expected_common.st_dev,
                    "ino": expected_common.st_ino,
                    "mode": stat.S_IMODE(expected_common.st_mode),
                    "raw_target": os.readlink(self.common),
                },
                str(self.p_only): {
                    "dev": expected_p_only.st_dev,
                    "ino": expected_p_only.st_ino,
                    "mode": stat.S_IMODE(expected_p_only.st_mode),
                    "raw_target": os.readlink(self.p_only),
                },
            },
            plan["p_link_state"],
        )
        self.assertFalse(os.path.lexists(self.q_only))

    def test_exact_link_replacement_rejects_missing_wal_before_temp_write(self) -> None:
        """An exact pointer's temporary and final writes require durable authority."""
        target = self.q / "01-global.yaml"
        previous = os.readlink(self.common)
        calls = []

        def reject(_journal, link, _target, **_kwargs):
            calls.append(Path(link))
            raise ValueError("no durable WAL row")

        load_api = {
            "register_setup_switch_journal_link": reject,
            "service_runtime_backend": lambda: SimpleNamespace(name="supervisor"),
            "LoadError": ValueError,
        }
        with mock.patch.object(self.setup, "_AUTO_YES", True), \
             mock.patch.object(self.setup, "_SETUP_SWITCH_WAL_CONTEXT", (load_api, 9)):
            with self.assertRaisesRegex(ValueError, "WAL"):
                self.setup._make_exact_link(str(self.common), str(target))
        self.assertTrue(calls)
        self.assertEqual(previous, os.readlink(self.common))
        self.assertEqual([], list(self.common.parent.glob(f".{self.common.name}.tmp.*")))

    def test_exact_link_registers_final_and_temp_values_before_replace(self) -> None:
        target = self.q / "01-global.yaml"
        calls = []

        def record(_journal, link, registered_target, **_kwargs):
            calls.append((Path(link), Path(registered_target)))

        load_api = {
            "register_setup_switch_journal_link": record,
            "service_runtime_backend": lambda: SimpleNamespace(name="supervisor"),
            "LoadError": ValueError,
        }
        with mock.patch.object(self.setup, "_AUTO_YES", True), \
             mock.patch.object(self.setup, "_SETUP_SWITCH_WAL_CONTEXT", (load_api, 9)):
            self.assertEqual("linked", self.setup._make_exact_link(str(self.common), str(target)))
        self.assertEqual(2, len(calls))
        self.assertEqual(self.common, calls[0][0])
        self.assertEqual(
            self.common.with_name(f".{self.common.name}.tmp.{os.getpid()}"),
            calls[1][0],
        )
        self.assertEqual(calls[0][1], calls[1][1])
        self.assertEqual(os.path.relpath(target, self.common.parent), os.readlink(self.common))
        self.assertFalse(os.path.lexists(calls[1][0]))

    def test_legacy_p2p_cleanup_requires_wal_authority_before_unlink(self) -> None:
        legacy = self.root / "ztp/config/cumulus/template/P2P/legacy.xlsx"
        legacy.parent.mkdir(parents=True, exist_ok=True)
        legacy.symlink_to(os.path.relpath(self.p / "01-global.yaml", legacy.parent))
        original = os.readlink(legacy)
        with mock.patch.object(self.setup, "_SETUP_SWITCH_WAL_CONTEXT", ({}, 9)):
            with self.assertRaisesRegex(ValueError, "WAL"):
                self.setup._remove_legacy_p2p_links()
        self.assertEqual(original, os.readlink(legacy))

    def test_generic_cleanup_refuses_link_inserted_after_wal_preflight(self) -> None:
        """A later P-looking link absent from the frozen WAL must survive cleanup."""
        late = self.root / "ztp/config/publickey/late.pub"
        late.symlink_to(os.path.relpath(self.p / "p-only.pub", late.parent))
        raw = os.readlink(late)
        frozen = {str(self.p_only): (os.readlink(self.p_only), {})}
        with mock.patch.object(self.setup, "_SETUP_SWITCH_WAL_CONTEXT", ({}, 9, frozen)), \
             mock.patch.object(self.setup, "_previous_project_links_to_remove", return_value=[str(late)]), \
             mock.patch.object(self.setup, "_authorize_project_switch", return_value=True), \
             redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ValueError, "WAL|frozen|清理"):
                self.setup._unsetup_previous(str(self.q))
        self.assertEqual(raw, os.readlink(late))
        self.assertEqual(os.readlink(self.p_only), frozen[str(self.p_only)][0])

    def test_inventory_identifies_real_latest_and_infra_logs_without_migration(self) -> None:
        latest = self.q / "99-output-eth/latest"
        latest.mkdir(parents=True)
        (latest / ".published-complete").write_bytes(b"complete\n")
        (latest / "leaf.yaml").write_bytes(b"hostname: leaf\n")
        logs = self.root / "infra/logs"
        logs.mkdir(parents=True)
        (logs / "audit.log").write_bytes(b"retain exact old log\n")
        before = _tree_snapshot(self.root)

        plan = self.setup.inventory_setup_switch_shared_paths(str(self.p), str(self.q))

        self.assertEqual(before, _tree_snapshot(self.root))
        self.assertIs(plan["complete"], False)
        self.assertIn(str(latest), plan["materialized_latest"])
        self.assertEqual(
            {
                "path": str(logs), "kind": "real-directory",
                "receipt_path": str(self.root / "infra/.logs-migration.json"),
                "receipt_pending": False,
            },
            plan["infra_logs"],
        )
        self.assertIn(str(logs), plan["managed_paths"])
        self.assertTrue(any("materialized" in item for item in plan["blockers"]))
        self.assertTrue(any("infra logs" in item for item in plan["blockers"]))

    def test_inventory_flags_pending_infra_receipt_without_consuming_it(self) -> None:
        receipt = self.root / "infra/.logs-migration.json"
        receipt.parent.mkdir(parents=True)
        receipt.write_bytes(b"unverified pending receipt\n")
        receipt.chmod(0o600)
        before = _tree_snapshot(self.root)

        plan = self.setup.inventory_setup_switch_shared_paths(str(self.p), str(self.q))

        self.assertEqual(before, _tree_snapshot(self.root))
        self.assertIs(plan["complete"], False)
        self.assertEqual(str(receipt), plan["infra_logs"]["receipt_path"])
        self.assertTrue(plan["infra_logs"]["receipt_pending"])
        self.assertTrue(any("pending" in item for item in plan["blockers"]))

    def test_cross_project_setup_preserves_pending_p_infra_receipt(self) -> None:
        """REQ19 may resume P, but Q must not consume P's pending receipt."""
        (self.q / "02-dhcp-subnet_config.csv").write_bytes(b"fixture\n")
        logs = self.root / "infra/logs"
        logs.mkdir(parents=True)
        payload = b"P-owned audit bytes\n"
        (logs / "audit.log").write_bytes(payload)
        identity = logs.lstat()
        receipt = self.root / "infra/.logs-migration.json"
        receipt.write_text(json.dumps({
            "schema_version": 1,
            "source": {"path": str(logs), "dev": identity.st_dev, "ino": identity.st_ino},
            "destination": {"path": str(self.p / "99-output-infra")},
            "directories": [],
            "entries": {"audit.log": {
                "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest(),
            }},
        }), encoding="utf-8")
        before_receipt = receipt.read_bytes()
        before_manifest = self.manifest.read_bytes()
        before_common = os.readlink(self.common)
        before_p_only = os.readlink(self.p_only)

        with mock.patch.object(self.setup, "_initialize_project_from_template"), \
             mock.patch.object(self.setup, "_prepare_laptop_public_key"), \
             mock.patch.object(self.setup, "_select_p2p_source", return_value=str(self.q / "p2p.xlsx")), \
             mock.patch.object(self.setup, "_validate_project", return_value=True), \
             mock.patch.object(self.setup, "_check_p2p_source_identity", return_value=True), \
             mock.patch.object(self.setup, "_DRY_RUN", False), \
             redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ValueError, "待恢复日志凭据不属于所选项目"):
                self.setup._setup_impl(str(self.q))

        self.assertEqual(before_receipt, receipt.read_bytes())
        self.assertEqual(before_manifest, self.manifest.read_bytes())
        self.assertEqual(before_common, os.readlink(self.common))
        self.assertEqual(before_p_only, os.readlink(self.p_only))
        self.assertFalse(os.path.lexists(self.q_only))
        self.assertEqual(payload, (logs / "audit.log").read_bytes())

    def test_q_local_preparation_returns_p2p_source_without_shared_publication(self) -> None:
        """The pre-WAL stage prepares Q only; it is not a link switch."""
        (self.q / "02-dhcp-subnet_config.csv").write_bytes(b"fixture\n")
        chosen = str(self.q / "Site-P2P-v1.0.xlsx")
        before_manifest = self.manifest.read_bytes()
        before_common = os.readlink(self.common)
        before_p_only = os.readlink(self.p_only)

        with mock.patch.object(self.setup, "_initialize_project_from_template"), \
             mock.patch.object(self.setup, "_prepare_laptop_public_key"), \
             mock.patch.object(self.setup, "_select_p2p_source", return_value=chosen), \
             mock.patch.object(self.setup, "_validate_project", return_value=True), \
             mock.patch.object(self.setup, "_check_p2p_source_identity", return_value=True), \
             mock.patch.object(self.setup, "_DRY_RUN", False), \
             redirect_stdout(io.StringIO()):
            selected = self.setup._prepare_setup_local_inputs(str(self.q))

        self.assertEqual(chosen, selected)
        for name in self.setup.OUTPUT_DIRS:
            path = self.q / name
            self.assertTrue(path.is_dir() and not path.is_symlink(), name)
        self.assertEqual(before_manifest, self.manifest.read_bytes())
        self.assertEqual(before_common, os.readlink(self.common))
        self.assertEqual(before_p_only, os.readlink(self.p_only))
        self.assertFalse(os.path.lexists(self.q_only))

    def test_management_prepare_only_returns_before_monitor_stop(self) -> None:
        """Preparing Q is not authority to stop the active P service."""
        args = SimpleNamespace(
            project=str(self.q), csv_dir=None, p2p_file=None, create=False,
            prepare_only=True, host_role="management-server", _server_delegated=True,
        )
        before_manifest = self.manifest.read_bytes()
        with mock.patch.object(self.setup, "require_project_eligible"), \
             mock.patch.object(self.setup, "_prepare_setup_local_inputs", return_value="p2p") as prepare, \
             mock.patch.object(self.setup, "stop_native_ztp_monitors") as stop, \
             redirect_stdout(io.StringIO()):
            self.assertEqual(0, self.setup._main_locked(args))
        prepare.assert_called_once_with(str(self.q), server_delegated=True)
        stop.assert_not_called()
        self.assertEqual(before_manifest, self.manifest.read_bytes())

    def test_programmatic_cross_project_setup_without_wal_stops_before_impl(self) -> None:
        """Importing setup() directly must not bypass the CLI's WAL fence."""
        before_manifest = self.manifest.read_bytes()
        before_common = os.readlink(self.common)
        before_p_only = os.readlink(self.p_only)
        with mock.patch.object(self.setup, "require_project_eligible"), \
             mock.patch.object(self.setup, "_setup_impl",
                               side_effect=AssertionError("shared setup entered")) as impl, \
             mock.patch.object(self.setup, "infra_log_root_lock",
                               side_effect=AssertionError("infra lock entered")) as infra_lock:
            with self.assertRaisesRegex(ValueError, "WAL"):
                self.setup.setup(str(self.q))
        impl.assert_not_called()
        infra_lock.assert_not_called()
        self.assertEqual(before_manifest, self.manifest.read_bytes())
        self.assertEqual(before_common, os.readlink(self.common))
        self.assertEqual(before_p_only, os.readlink(self.p_only))
        self.assertFalse(os.path.lexists(self.q_only))

    def test_inventory_rejects_relative_project_names_without_writing(self) -> None:
        before = _tree_snapshot(self.root)
        relative_p = os.path.relpath(self.p, Path.cwd())
        with self.assertRaisesRegex(ValueError, "real direct project"):
            self.setup.inventory_setup_switch_shared_paths(relative_p, str(self.q))
        self.assertEqual(before, _tree_snapshot(self.root))

    def test_q_output_dirs_exist_before_pending_infra_restore_first_shared_write(self) -> None:
        """Q-local preparation must precede the earliest possible root mutation."""
        (self.q / "02-dhcp-subnet_config.csv").write_bytes(b"fixture\n")
        before_manifest = self.manifest.read_bytes()
        before_common = os.readlink(self.common)
        before_p_only = os.readlink(self.p_only)
        observed = []

        class StopAtSharedWrite(Exception):
            pass

        def stop_before_infra_restore(_source, _destination):
            observed.extend(
                (self.q / name).is_dir() and not (self.q / name).is_symlink()
                for name in self.setup.OUTPUT_DIRS
            )
            raise StopAtSharedWrite

        with mock.patch.object(self.setup, "_initialize_project_from_template"), \
             mock.patch.object(self.setup, "_prepare_laptop_public_key"), \
             mock.patch.object(self.setup, "_select_p2p_source", return_value=str(self.q / "p2p.xlsx")), \
             mock.patch.object(self.setup, "_validate_project", return_value=True), \
             mock.patch.object(self.setup, "_check_p2p_source_identity", return_value=True), \
             mock.patch.object(self.setup, "_restore_pending_infra_log_backup", side_effect=stop_before_infra_restore), \
             mock.patch.object(self.setup, "_DRY_RUN", False), \
             redirect_stdout(io.StringIO()):
            with self.assertRaises(StopAtSharedWrite):
                self.setup._setup_impl(str(self.q))

        self.assertEqual(len(self.setup.OUTPUT_DIRS), len(observed))
        self.assertTrue(all(observed), observed)
        self.assertEqual(before_manifest, self.manifest.read_bytes())
        self.assertEqual(before_common, os.readlink(self.common))
        self.assertEqual(before_p_only, os.readlink(self.p_only))

    def test_q_output_symlink_is_rejected_before_pending_infra_restore(self) -> None:
        """An externalized Q output must not become a shared-write target."""
        (self.q / "02-dhcp-subnet_config.csv").write_bytes(b"fixture\n")
        outside = self.root / "outside-output"
        outside.mkdir()
        sentinel = outside / "sentinel"
        sentinel.write_bytes(b"keep outside bytes\n")
        (self.q / self.setup.OUTPUT_DIRS[0]).symlink_to(outside)
        before_manifest = self.manifest.read_bytes()
        before_common = os.readlink(self.common)

        with mock.patch.object(self.setup, "_initialize_project_from_template"), \
             mock.patch.object(self.setup, "_prepare_laptop_public_key"), \
             mock.patch.object(self.setup, "_select_p2p_source", return_value=str(self.q / "p2p.xlsx")), \
             mock.patch.object(self.setup, "_validate_project", return_value=True), \
             mock.patch.object(self.setup, "_check_p2p_source_identity", return_value=True), \
             mock.patch.object(self.setup, "_restore_pending_infra_log_backup") as restore, \
             mock.patch.object(self.setup, "_DRY_RUN", False), \
             redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ValueError, "输出目录.*实际目录"):
                self.setup._setup_impl(str(self.q))

        restore.assert_not_called()
        self.assertEqual(b"keep outside bytes\n", sentinel.read_bytes())
        self.assertEqual(before_manifest, self.manifest.read_bytes())
        self.assertEqual(before_common, os.readlink(self.common))
