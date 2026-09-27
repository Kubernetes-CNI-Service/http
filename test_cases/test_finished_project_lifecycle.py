#!/usr/bin/env python3
"""Workflow contracts for finished-record import and deployment isolation."""

from __future__ import annotations

import argparse
import contextlib
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

from test_cases.test_finished_project_import import build_finished_bundle
from test_cases.test_finished_project_rehydrate import FinishedProjectRehydrateTests


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


IMPORTER = load_module("finished_lifecycle_importer", ROOT / "tools/import-from-download.py")
PACKAGE = load_module("finished_lifecycle_package", ROOT / "tools/_package_common.py")
CONTRACT = load_module("finished_lifecycle_contract", ROOT / "tools/project_contract.py")
FINISH = load_module("finished_lifecycle_finish", ROOT / "tools/finish-project.py")


class FinishedProjectLifecycleWorkflowTests(unittest.TestCase):
    def test_detached_finished_bundle_import_rehydrates_without_original_source(self):
        global_bytes = b"site: A\n"
        csv_bytes = b"name,ip\nleaf,1.2.3.4\n"
        history_bytes = b"saved output\n"
        with tempfile.TemporaryDirectory(prefix="finished-detached-source-") as directory:
            base = Path(directory)
            source = base / "source-workspace"
            source.mkdir()
            original_archive = source / "finished.tar.gz"
            record_id, _ = build_finished_bundle(
                original_archive,
                extra_base_files={
                    "01-global.yaml": global_bytes,
                    "02-devices_config.csv": csv_bytes,
                    "99-output-ztp/result.txt": history_bytes,
                    "99-output-ztp/worker.pid": b"123\n",
                },
            )
            recovery = base / "recovery-workspace"
            recovery.mkdir()
            copied_archive = recovery / "transferred-finished.tar.gz"
            shutil.copyfile(original_archive, copied_archive)
            self.assertEqual(
                hashlib.sha256(original_archive.read_bytes()).digest(),
                hashlib.sha256(copied_archive.read_bytes()).digest(),
            )
            shutil.rmtree(source)
            self.assertFalse(source.exists(), "recovery must not consult the original workspace")

            day0 = recovery / "DAY0-Prepare"
            day0.mkdir()
            finished_root = recovery / "Finished-projects"
            output = io.StringIO()
            with (
                mock.patch.object(IMPORTER, "ROOT", recovery),
                mock.patch.object(IMPORTER, "DAY0", day0),
                mock.patch.object(IMPORTER, "FINISHED_ROOT", finished_root, create=True),
                redirect_stdout(output),
                redirect_stderr(output),
            ):
                result = IMPORTER.main([
                    str(copied_archive), "--review-root", str(recovery / "reviews"), "--finish",
                ])
            self.assertEqual(0, result, output.getvalue())
            record = finished_root / "customer" / record_id
            self.assertTrue(record.is_dir())
            self.assertEqual(global_bytes, (record / "reconstructed-final/01-global.yaml").read_bytes())
            rehydrate = load_module(
                "finished_lifecycle_detached_rehydrate", ROOT / "tools/rehydrate-finished.py"
            )
            for include_history, name in ((False, "restored-default"), (True, "restored-history")):
                with self.subTest(include_history=include_history):
                    target = rehydrate.rehydrate_record(
                        record=record, day0_root=day0, new_project=name,
                        include_history=include_history,
                    )
                    self.assertEqual(global_bytes, (target / "01-global.yaml").read_bytes())
                    self.assertEqual(csv_bytes, (target / "02-devices_config.csv").read_bytes())
                    self.assertEqual(
                        include_history, (target / "99-output-ztp/result.txt").exists(),
                    )
                    self.assertFalse((target / "99-output-ztp/worker.pid").exists())
                    CONTRACT.require_project_eligible(target)

            # Same-size, mode-restored corruption after import must not be
            # interpreted as a valid detached record or publish a target.
            member = record / "reconstructed-final/01-global.yaml"
            member.chmod(0o644)
            member.write_bytes(b"site: B\n")
            member.chmod(0o444)
            self.assertEqual(len(global_bytes), member.stat().st_size)
            with self.assertRaises(rehydrate.RehydrateError):
                rehydrate.rehydrate_record(
                    record=record, day0_root=day0,
                    new_project="restored-corrupt", include_history=False,
                )
            self.assertFalse(os.path.lexists(day0 / "restored-corrupt"))
            self.assertEqual(global_bytes, (day0 / "restored-default/01-global.yaml").read_bytes())

    def test_real_rehydrate_must_commit_before_setup_stops_monitor_or_links(self):
        with tempfile.TemporaryDirectory(prefix="finished-rehydrate-setup-") as directory:
            workspace = Path(directory) / "http"
            day0 = workspace / "DAY0-Prepare"
            day0.mkdir(parents=True)
            record, _record_id = FinishedProjectRehydrateTests(
                "test_default_materializes_only_working_inputs_and_source_receipt"
            )._record(workspace)
            rehydrate = load_module(
                "finished_lifecycle_setup_rehydrate", ROOT / "tools/rehydrate-finished.py"
            )
            setup = load_module(
                "finished_lifecycle_setup", ROOT / "DAY0-Prepare/01-a-setup.py"
            )
            project = rehydrate.rehydrate_record(
                record=record, day0_root=day0,
                new_project="customer-restored", include_history=False,
            )
            # This input is normally supplied during project preparation. It
            # keeps the restored fixture eligible for setup's older core-input
            # contract without changing the receipt or commit marker.
            (project / "02-dhcp-subnet_config.csv").write_bytes(b"subnet\n")
            original_receipt = (project / ".finished-source.json").read_bytes()
            self.assertTrue((project / ".finished-commit.json").is_file())
            ordinary = day0 / "ordinary"
            ordinary.mkdir()
            for target in (ordinary,):
                for input_name in (
                    "01-global.yaml", "02-devices_config.csv", "02-dhcp-subnet_config.csv",
                ):
                    (target / input_name).touch(exist_ok=True)
            sentinel = workspace / "outside.txt"
            sentinel.write_bytes(b"outside unchanged\n")

            with mock.patch.object(setup, "HERE", str(day0)), \
                 mock.patch.object(setup, "HTTP_BASE", str(workspace)), \
                 mock.patch.object(setup, "_DRY_RUN", False), \
                 mock.patch.object(setup, "infra_log_root_lock", return_value=contextlib.nullcontext()), \
                 mock.patch.object(setup, "infra_log_pending_state_names", return_value=()), \
                 mock.patch.object(setup, "_rollback_infra_log_migration"):
                for target in (project, ordinary):
                    args = argparse.Namespace(
                        project=str(target), csv_dir=None, p2p_file=None,
                        create=False, _server_delegated=False,
                        host_role="management-server",
                    )
                    with self.subTest(target=target.name, phase="admitted"):
                        with mock.patch.object(setup, "stop_native_ztp_monitors") as stop, \
                             mock.patch.object(setup, "setup") as enter_setup:
                            self.assertEqual(0, setup._main_locked(args))
                        stop.assert_called_once_with(str(workspace))
                        enter_setup.assert_called_once_with(str(target.resolve()))
                        with mock.patch.object(setup, "_setup_impl", return_value="admitted") as impl:
                            self.assertEqual("admitted", setup.setup(str(target)))
                        impl.assert_called_once_with(str(target), server_delegated=False)

                receipt = project / ".finished-source.json"
                pending = json.loads(original_receipt.decode("ascii"))
                pending["state"] = "PENDING"
                args.project = str(project)
                for label, payload in (
                    ("pending", (json.dumps(pending, sort_keys=True) + "\n").encode("ascii")),
                    ("malformed", b"{not-json\n"),
                ):
                    with self.subTest(phase=label):
                        receipt.write_bytes(payload)
                        before_paths = sorted(
                            path.relative_to(project).as_posix() for path in project.rglob("*")
                        )
                        with mock.patch.object(
                            setup, "stop_native_ztp_monitors",
                            side_effect=AssertionError("monitor stopped before restore admission"),
                        ) as stop, mock.patch.object(
                            setup, "setup",
                            side_effect=AssertionError("setup entered before restore admission"),
                        ) as enter_setup:
                            with self.assertRaises(ValueError):
                                setup._main_locked(args)
                        stop.assert_not_called()
                        enter_setup.assert_not_called()
                        with mock.patch.object(
                            setup, "_setup_impl",
                            side_effect=AssertionError("link transaction entered before restore admission"),
                        ) as impl:
                            with self.assertRaises(ValueError):
                                setup.setup(str(project))
                        impl.assert_not_called()
                        self.assertEqual(before_paths, sorted(
                            path.relative_to(project).as_posix() for path in project.rglob("*")
                        ))
                        self.assertEqual(b"outside unchanged\n", sentinel.read_bytes())

    def test_real_rehydrate_must_commit_before_finish_creates_state(self):
        with tempfile.TemporaryDirectory(prefix="finished-rehydrate-finish-") as directory:
            workspace = Path(directory) / "http"
            day0 = workspace / "DAY0-Prepare"
            day0.mkdir(parents=True)
            record, _record_id = FinishedProjectRehydrateTests(
                "test_default_materializes_only_working_inputs_and_source_receipt"
            )._record(workspace)
            rehydrate = load_module(
                "finished_lifecycle_finish_rehydrate", ROOT / "tools/rehydrate-finished.py"
            )
            project = rehydrate.rehydrate_record(
                record=record, day0_root=day0,
                new_project="customer-restored", include_history=False,
            )
            state_root = workspace / "finish-state"
            self.assertEqual(project.resolve(), FINISH.resolve_project(workspace, project.name))
            plan = FINISH.build_plan(
                repository=workspace, project_name=project.name,
                runtime="native", state_root=state_root,
            )
            self.assertEqual(project.name, plan["project"])
            self.assertFalse(state_root.exists())

            receipt = project / ".finished-source.json"
            original_receipt = receipt.read_bytes()
            pending = json.loads(original_receipt.decode("ascii"))
            pending["state"] = "PENDING"
            receipt.write_bytes(
                (json.dumps(pending, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
            )
            original_content = (project / "01-global.yaml").read_bytes()
            before_paths = sorted(path.relative_to(project).as_posix() for path in project.rglob("*"))
            # Reuse the finish suite's local owner identity fixture and put a
            # hard stop at the first transaction write. A pending restore must
            # be rejected by the real selector before that boundary.
            with mock.patch.object(FINISH.state, "_required_owner_uid", return_value=os.getuid()), \
                 mock.patch.object(FINISH.state, "_required_owner_gid", return_value=os.getgid()), \
                 mock.patch.object(
                     FINISH.state, "create_transaction",
                     side_effect=AssertionError("finish created state before restore admission"),
                 ) as create_transaction, \
                 mock.patch.object(FINISH, "stop_runtime") as stop:
                with self.assertRaises(FINISH.FinishProjectError):
                    FINISH.execute_finish(
                        repository=workspace, project_name=project.name,
                        runtime="native", state_root=state_root,
                        transaction_id="finish-20260916T082220Z-abcdefabcdefabcd",
                        created_at="2026-09-16T08:22:20Z",
                        runtime_only_stop=True,
                    )
            create_transaction.assert_not_called()
            stop.assert_not_called()
            self.assertFalse(state_root.exists(), "finish must reject before transaction writes")
            self.assertEqual(original_content, (project / "01-global.yaml").read_bytes())
            self.assertEqual(
                before_paths,
                sorted(path.relative_to(project).as_posix() for path in project.rglob("*")),
            )

            receipt.write_bytes(original_receipt)
            self.assertEqual(project.resolve(), FINISH.resolve_project(workspace, project.name))
            ordinary = day0 / "ordinary"
            ordinary.mkdir()
            self.assertEqual(ordinary.resolve(), FINISH.resolve_project(workspace, ordinary.name))
            (day0 / "alias").symlink_to(project.name, target_is_directory=True)
            with self.assertRaisesRegex(FINISH.FinishProjectError, "real direct child"):
                FINISH.resolve_project(workspace, "alias")

    def test_rehydrated_project_transfer_controls_never_enter_deployment_archive(self):
        control_names = (
            ".finished-source.json",
            ".finished-commit.ready",
            ".finished-commit.json",
        )
        with tempfile.TemporaryDirectory(prefix="finished-transfer-controls-") as directory:
            workspace = Path(directory) / "http"
            day0 = workspace / "DAY0-Prepare"
            day0.mkdir(parents=True)
            record, _record_id = FinishedProjectRehydrateTests(
                "test_default_materializes_only_working_inputs_and_source_receipt"
            )._record(workspace)
            rehydrate = load_module(
                "finished_lifecycle_rehydrate", ROOT / "tools/rehydrate-finished.py"
            )
            project = rehydrate.rehydrate_record(
                record=record, day0_root=day0,
                new_project="customer-restored", include_history=False,
            )
            self.assertTrue((project / ".finished-source.json").is_file())
            self.assertTrue((project / ".finished-commit.json").is_file())

            output_archive = workspace / "restored-upload.tar.gz"
            with mock.patch.multiple(
                PACKAGE,
                ROOT=workspace,
                DAY0=day0,
                MANIFEST=workspace / "ztp/.setup_manifest",
            ):
                self.assertEqual(project.resolve(), PACKAGE.resolve_project(str(project)))
                package_filter = PACKAGE.PackageFilter(
                    project,
                    output_archive,
                    include_images=False,
                    include_apps=False,
                    include_firmware=False,
                    max_file_size=1024 * 1024,
                    day0_all=False,
                    artifact_kind="upload",
                )
                with tarfile.open(output_archive, "w:gz") as outgoing:
                    outgoing.add(
                        project, arcname=f"./DAY0-Prepare/{project.name}",
                        recursive=True, filter=package_filter,
                    )
            with tarfile.open(output_archive, "r:gz") as outgoing:
                names = {member.name.removeprefix("./") for member in outgoing.getmembers()}
            self.assertIn(f"DAY0-Prepare/{project.name}/01-global.yaml", names)
            self.assertIn(f"DAY0-Prepare/{project.name}/02-devices_config.csv", names)

            # A staging control may appear after selection; the transfer filter
            # must not serialize it even if the source changes during packaging.
            ready = project / ".finished-commit.ready"
            ready.write_bytes(b"private precommit control\n")
            ready_archive = workspace / "ready-control-upload.tar.gz"
            with tarfile.open(ready_archive, "w:gz") as outgoing:
                outgoing.add(
                    ready, arcname=f"./DAY0-Prepare/{project.name}/{ready.name}",
                    filter=package_filter,
                )
            with tarfile.open(ready_archive, "r:gz") as outgoing:
                ready_names = {
                    member.name.removeprefix("./") for member in outgoing.getmembers()
                }
            self.assertNotIn(f"DAY0-Prepare/{project.name}/{ready.name}", ready_names)

            for control in control_names:
                relative = PurePosixPath(f"DAY0-Prepare/{project.name}/{control}")
                with self.subTest(control=control, gate="archive"):
                    self.assertNotIn(relative.as_posix(), names)
                with self.subTest(control=control, gate="classification"):
                    self.assertEqual(
                        "metadata", PACKAGE.classify_project_entry(PurePosixPath(control))
                    )
                with self.subTest(control=control, gate="transfer"):
                    self.assertIsNotNone(CONTRACT.transfer_exclude_reason(relative))
                with self.subTest(control=control, gate="rsync"):
                    self.assertIn(control, CONTRACT.rsync_excludes())

    def test_sync_project_selector_rejects_pending_restore_before_network(self):
        with tempfile.TemporaryDirectory(prefix="finished-sync-selector-") as directory:
            workspace = Path(directory) / "http"
            day0 = workspace / "DAY0-Prepare"
            day0.mkdir(parents=True)
            record, _record_id = FinishedProjectRehydrateTests(
                "test_default_materializes_only_working_inputs_and_source_receipt"
            )._record(workspace)
            rehydrate = load_module(
                "finished_lifecycle_sync_rehydrate", ROOT / "tools/rehydrate-finished.py"
            )
            sync = load_module("finished_lifecycle_sync", ROOT / "tools/sync-code.py")
            project = rehydrate.rehydrate_record(
                record=record, day0_root=day0,
                new_project="customer-restored", include_history=False,
            )
            ordinary = day0 / "ordinary"
            ordinary.mkdir()
            (ordinary / "02-devices_config.csv").write_bytes(b"name,ip\n")

            with mock.patch.multiple(sync, ROOT=workspace, DAY0=day0):
                self.assertEqual(project.resolve(), sync.resolve_project(str(project)))
                self.assertEqual(ordinary.resolve(), sync.resolve_project(str(ordinary)))
                receipt = project / ".finished-source.json"
                pending = json.loads(receipt.read_text(encoding="utf-8"))
                pending["state"] = "PENDING"
                receipt.write_text(json.dumps(pending, sort_keys=True) + "\n", encoding="utf-8")
                with self.assertRaises(ValueError):
                    sync.resolve_project(str(project))
                self.assertEqual(ordinary.resolve(), sync.resolve_project(str(ordinary)))

    def test_finished_record_is_excluded_after_real_import_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "http"
            day0 = workspace / "DAY0-Prepare"
            project = day0 / "customer"
            review_root = workspace / "package-imports"
            finished_root = workspace / "Finished-projects"
            project.mkdir(parents=True)
            (project / "02-devices_config.csv").write_text("hostname,type\n", encoding="utf-8")
            archive = workspace / "incoming-finished.tar.gz"
            record_id, _manifest = build_finished_bundle(archive)
            output = io.StringIO()
            with (
                mock.patch.object(IMPORTER, "ROOT", workspace),
                mock.patch.object(IMPORTER, "DAY0", day0),
                mock.patch.object(IMPORTER, "FINISHED_ROOT", finished_root, create=True),
                redirect_stdout(output),
                redirect_stderr(output),
            ):
                result = IMPORTER.main([
                    str(archive), "--review-root", str(review_root), "--finish",
                ])
            self.assertEqual(0, result, output.getvalue())
            record = finished_root / "customer" / record_id
            self.assertTrue(record.is_dir())
            history = project / "finished-history" / record_id
            self.assertTrue(history.is_symlink())
            self.assertEqual(record.resolve(), history.resolve())

            relative = PurePosixPath(
                f"Finished-projects/customer/{record_id}/bundle-manifest.json"
            )
            self.assertEqual("finished project archive", CONTRACT.transfer_exclude_reason(relative))
            self.assertIn("Finished-projects/", CONTRACT.rsync_excludes())
            self.assertIn("finished-history/", CONTRACT.rsync_excludes())
            self.assertEqual(
                "finished project history link",
                PACKAGE.classify_project_entry(PurePosixPath(f"finished-history/{record_id}")),
            )

            output_archive = workspace / "workspace-upload.tar.gz"
            with mock.patch.multiple(
                PACKAGE,
                ROOT=workspace,
                DAY0=day0,
                MANIFEST=workspace / "ztp/.setup_manifest",
            ):
                package_filter = PACKAGE.PackageFilter(
                    project,
                    output_archive,
                    include_images=False,
                    include_apps=False,
                    include_firmware=False,
                    max_file_size=1024 * 1024,
                    day0_all=True,
                )
                with tarfile.open(output_archive, "w:gz") as outgoing:
                    for source in sorted(workspace.iterdir()):
                        outgoing.add(
                            source,
                            arcname=f"./{source.name}",
                            recursive=True,
                            filter=package_filter,
                        )
            with tarfile.open(output_archive, "r:gz") as outgoing:
                names = set(outgoing.getnames())
            self.assertFalse(
                any(name.removeprefix("./").startswith("Finished-projects") for name in names)
            )
            self.assertFalse(any("finished-history" in name for name in names))

    def test_finished_root_is_not_a_deployment_project_or_docker_context(self):
        load = load_module("finished_lifecycle_load", ROOT / "DAY0-Prepare/11-load.py")
        with self.assertRaises(load.LoadError):
            load.resolve_project(str(ROOT / "Finished-projects/customer/record"))
        dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")
        self.assertIn("Finished-projects/**", dockerignore)
        self.assertNotIn("!Finished-projects", dockerignore)


if __name__ == "__main__":
    unittest.main()
