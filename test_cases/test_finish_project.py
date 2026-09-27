#!/usr/bin/env python3
"""Direct tests for the finished-project producer orchestration."""

from __future__ import annotations

import importlib.util
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

from tools import finished_project_state as state
from tools import finished_bundle


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/finish-project.py"


def load_finish_project():
    name = "finish_project_under_test"
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(name)
    sys.modules[name] = module
    sys.path.insert(0, str(ROOT / "tools"))
    try:
        spec.loader.exec_module(module)
    finally:
        del sys.path[0]
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
    return module


class FinishProjectTests(unittest.TestCase):
    def test_public_cli_explains_transaction_actions_and_runtime_boundary(self):
        module = load_finish_project()
        with mock.patch.object(module.argparse.ArgumentParser, "parse_args", autospec=True) as parse:
            module.parse_args(["plan", "customer", "--runtime", "native"])
            parser = parse.call_args.args[0]
        actions = {action.dest: action for action in parser._actions}
        expected = {
            "action": "plan, finish, or resume",
            "project": "DAY0 project",
            "runtime": "deployment runtime",
            "transaction_id": "existing transaction",
            "runtime_only_stop": "legacy project",
        }
        for destination, phrase in expected.items():
            with self.subTest(destination=destination):
                self.assertIn(phrase, actions[destination].help or "")

    def _tree(self, base: Path) -> tuple[Path, Path]:
        repository = base / "repository"
        day0 = repository / "DAY0-Prepare"
        project = day0 / "customer"
        project.mkdir(parents=True)
        (project / "01-global.yaml").write_text("project: customer\n", encoding="utf-8")
        (project / "99-output-ztp").mkdir()
        (project / "99-output-ztp/result.txt").write_text("ready\n", encoding="utf-8")
        return repository, project

    def _identity_patches(self):
        return (
            mock.patch.object(state, "_required_owner_uid", return_value=os.getuid()),
            mock.patch.object(state, "_required_owner_gid", return_value=os.getgid()),
        )

    def test_project_must_be_a_real_direct_child(self):
        module = load_finish_project()
        with tempfile.TemporaryDirectory() as name:
            repository, project = self._tree(Path(name))
            self.assertEqual(project.resolve(), module.resolve_project(repository, "customer"))
            (repository / "DAY0-Prepare/alias").symlink_to("customer")
            with self.assertRaisesRegex(module.FinishProjectError, "real direct child"):
                module.resolve_project(repository, "alias")
            with self.assertRaisesRegex(module.FinishProjectError, "project name"):
                module.resolve_project(repository, "../customer")

    def test_restored_project_requires_local_commit_before_finish_admission(self):
        module = load_finish_project()
        with tempfile.TemporaryDirectory(prefix="finish-restore-admission-") as name:
            base = Path(name)
            repository, project = self._tree(base)
            receipt_path = project / ".finished-source.json"
            marker_path = project / ".finished-commit.json"
            state_root = base / "finish-state"
            original = (project / "01-global.yaml").read_bytes()

            # No controls is an ordinary pre-restore project, not a pending one.
            self.assertEqual(project.resolve(), module.resolve_project(repository, "customer"))
            receipt = {
                "schema_version": 1,
                "state": "PREPARED",
                "source_record": "/offline/Finished-projects/source/record",
                "project": "source",
                "record_id": "20260916T083250Z-0123456789ab",
                "content_sha256": "a" * 64,
                "include_history": False,
            }
            receipt_bytes = (
                json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode("ascii")
            receipt_path.write_bytes(receipt_bytes)
            with self.assertRaises(module.FinishProjectError):
                module.resolve_project(repository, "customer")
            self.assertFalse(state_root.exists())

            marker = {
                "schema_version": 1,
                "state": "COMMITTED",
                "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
                "target_project": "customer",
                "target_dev": project.stat().st_dev,
                "target_ino": project.stat().st_ino,
            }
            marker_path.write_bytes(
                (json.dumps(marker, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
            )
            self.assertEqual(project.resolve(), module.resolve_project(repository, "customer"))

            marker["receipt_sha256"] = "0" * 64
            marker_path.write_bytes(
                (json.dumps(marker, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
            )
            with self.assertRaises(module.FinishProjectError):
                module.resolve_project(repository, "customer")
            self.assertEqual(original, (project / "01-global.yaml").read_bytes())
            self.assertFalse(state_root.exists())

    def test_plan_is_read_only_and_marks_missing_footprint_legacy(self):
        module = load_finish_project()
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            repository, _project = self._tree(base)
            finish_root = base / "finish-state"
            before = sorted(path.relative_to(repository).as_posix() for path in repository.rglob("*"))
            plan = module.build_plan(
                repository=repository,
                project_name="customer",
                runtime="native",
                state_root=finish_root,
            )
            after = sorted(path.relative_to(repository).as_posix() for path in repository.rglob("*"))
            self.assertEqual(before, after)
            self.assertFalse(finish_root.exists())
            self.assertTrue(plan["legacy_without_footprint"])
            self.assertEqual("CONDITIONAL", plan["deletion_class"])

    def test_legacy_finish_requires_explicit_runtime_only_stop_before_state(self):
        module = load_finish_project()
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            repository, _project = self._tree(base)
            finish_root = base / "finish-state"
            with mock.patch.object(module, "stop_runtime") as stop:
                with self.assertRaisesRegex(
                    module.FinishProjectError, "--runtime-only-stop",
                ):
                    module.execute_finish(
                        repository=repository,
                        project_name="customer",
                        runtime="native",
                        state_root=finish_root,
                        transaction_id="finish-20260916T082220Z-abcdefabcdefabcd",
                        created_at="2026-09-16T08:22:20Z",
                    )
            stop.assert_not_called()
            self.assertFalse(finish_root.exists())
            args = module.parse_args([
                "finish", "customer", "--runtime", "native",
                "--runtime-only-stop",
            ])
            self.assertTrue(args.runtime_only_stop)

    def test_finish_commits_pending_before_stop_and_clears_only_after_bundle(self):
        module = load_finish_project()
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            repository, project = self._tree(base)
            finish_root = base / "finish-state"
            events: list[str] = []

            def stop_runtime(**kwargs):
                self.assertEqual("native", kwargs["runtime"])
                self.assertEqual("customer", kwargs["project_name"])
                pending = state.read_finish_pending(finish_root)
                self.assertEqual(kwargs["transaction_id"], pending["transaction_id"])
                events.append("stop")
                (project / "99-output-ztp/result.txt").write_text(
                    "stopped\n", encoding="utf-8",
                )
                return {"stopped": True, "backend": "systemd"}

            original_bundle = module.create_finished_bundle

            def bundle(**kwargs):
                self.assertIsNotNone(state.read_finish_pending(finish_root))
                events.append("bundle")
                return original_bundle(**kwargs)

            uid_patch, gid_patch = self._identity_patches()
            with uid_patch, gid_patch, \
                    mock.patch.object(state, "FINISH_STATE_ROOT", finish_root), \
                    mock.patch.object(module, "stop_runtime", side_effect=stop_runtime), \
                    mock.patch.object(module, "create_finished_bundle", side_effect=bundle):
                result = module.execute_finish(
                    repository=repository,
                    project_name="customer",
                    runtime="native",
                    state_root=finish_root,
                    runtime_only_stop=True,
                    transaction_id="finish-20260916T082220Z-0123456789abcdef",
                    created_at="2026-09-16T08:22:20Z",
                )

            self.assertEqual(["stop", "bundle"], events)
            self.assertTrue(result.bundle_path.is_file())
            uid_patch, gid_patch = self._identity_patches()
            with uid_patch, gid_patch:
                self.assertIsNone(state.read_finish_pending(finish_root))
                receipt = state.read_transaction(result.transaction_id, root=finish_root)
            self.assertEqual("completed", receipt["state"])
            self.assertEqual(
                [
                    "planned", "pre_stop_archiving", "pre_stop_complete",
                    "pending_committed", "runtime_stopping", "runtime_stopped",
                    "final_delta_building", "final_delta_complete",
                    "bundle_finalizing", "completed",
                ],
                [row["state"] for row in receipt["history"]],
            )

    def test_stop_failure_keeps_pending_and_durable_failed_receipt(self):
        module = load_finish_project()
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            repository, _project = self._tree(base)
            finish_root = base / "finish-state"
            transaction_id = "finish-20260916T082220Z-fedcba9876543210"
            uid_patch, gid_patch = self._identity_patches()
            with uid_patch, gid_patch, \
                    mock.patch.object(state, "FINISH_STATE_ROOT", finish_root), \
                    mock.patch.object(module, "stop_runtime", side_effect=RuntimeError("boom")):
                with self.assertRaisesRegex(RuntimeError, "boom"):
                    module.execute_finish(
                        repository=repository,
                        project_name="customer",
                        runtime="docker",
                        state_root=finish_root,
                        runtime_only_stop=True,
                        transaction_id=transaction_id,
                        created_at="2026-09-16T08:22:20Z",
                    )
            uid_patch, gid_patch = self._identity_patches()
            with uid_patch, gid_patch:
                self.assertEqual(
                    transaction_id,
                    state.read_finish_pending(finish_root)["transaction_id"],
                )
                self.assertEqual(
                    "failed",
                    state.read_transaction(transaction_id, root=finish_root)["state"],
                )

    def test_resume_after_stop_failure_reuses_pre_stop_and_finishes(self):
        module = load_finish_project()
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            repository, project = self._tree(base)
            finish_root = base / "finish-state"
            transaction_id = "finish-20260916T082220Z-aabbccddeeff0011"
            calls = 0

            def stop_runtime(**_kwargs):
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise RuntimeError("injected stop failure")
                (project / "99-output-ztp/result.txt").write_text(
                    "stopped after resume\n", encoding="utf-8",
                )
                return {"stopped": True, "backend": "systemd"}

            uid_patch, gid_patch = self._identity_patches()
            with uid_patch, gid_patch, \
                    mock.patch.object(state, "FINISH_STATE_ROOT", finish_root), \
                    mock.patch.object(module, "stop_runtime", side_effect=stop_runtime):
                with self.assertRaisesRegex(RuntimeError, "injected"):
                    module.execute_finish(
                        repository=repository,
                        project_name="customer",
                        runtime="native",
                        state_root=finish_root,
                        runtime_only_stop=True,
                        transaction_id=transaction_id,
                        created_at="2026-09-16T08:22:20Z",
                    )
                snapshot = (
                    finish_root / "transactions" / transaction_id
                    / "components/pre-stop-project/01-global.yaml"
                )
                before = (snapshot.stat().st_ino, snapshot.read_bytes())
                result = module.execute_resume(
                    repository=repository,
                    transaction_id=transaction_id,
                    state_root=finish_root,
                )
                after = (snapshot.stat().st_ino, snapshot.read_bytes())

            self.assertEqual(2, calls)
            self.assertEqual(before, after, "resume must not rebuild committed pre-stop")
            self.assertTrue(result.bundle_path.is_file())
            uid_patch, gid_patch = self._identity_patches()
            with uid_patch, gid_patch:
                self.assertIsNone(state.read_finish_pending(finish_root))
                receipt = state.read_transaction(transaction_id, root=finish_root)
            self.assertEqual("completed", receipt["state"])
            states = [row["state"] for row in receipt["history"]]
            self.assertEqual(1, states.count("pre_stop_archiving"))
            self.assertEqual(1, states.count("pre_stop_complete"))
            self.assertEqual(2, states.count("runtime_stopping"))

    def test_resume_after_pre_stop_receipt_failure_reuses_atomic_snapshot(self):
        module = load_finish_project()
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            repository, _project = self._tree(base)
            finish_root = base / "finish-state"
            transaction_id = "finish-20260916T082220Z-0102030405060708"
            original_advance = state.advance_transaction
            failed = False

            def advance(transaction, new_state, **kwargs):
                nonlocal failed
                if new_state == "pre_stop_complete" and not failed:
                    failed = True
                    raise RuntimeError("injected pre-stop receipt failure")
                return original_advance(transaction, new_state, **kwargs)

            uid_patch, gid_patch = self._identity_patches()
            with uid_patch, gid_patch, \
                    mock.patch.object(state, "FINISH_STATE_ROOT", finish_root), \
                    mock.patch.object(module.state, "advance_transaction", side_effect=advance), \
                    mock.patch.object(
                        module, "stop_runtime",
                        return_value={"stopped": True, "backend": "systemd"},
                    ) as stop:
                with self.assertRaisesRegex(RuntimeError, "pre-stop receipt"):
                    module.execute_finish(
                        repository=repository,
                        project_name="customer",
                        runtime="native",
                        state_root=finish_root,
                        runtime_only_stop=True,
                        transaction_id=transaction_id,
                        created_at="2026-09-16T08:22:20Z",
                    )
                snapshot = (
                    finish_root / "transactions" / transaction_id
                    / "components/pre-stop-project/01-global.yaml"
                )
                before = (snapshot.stat().st_ino, snapshot.read_bytes())
                result = module.execute_resume(
                    repository=repository,
                    transaction_id=transaction_id,
                    state_root=finish_root,
                )
                after = (snapshot.stat().st_ino, snapshot.read_bytes())

            self.assertEqual(before, after)
            self.assertEqual(1, stop.call_count)
            self.assertTrue(result.bundle_path.is_file())

    def test_interrupted_pre_stop_copy_leaves_no_partial_and_resume_rebuilds(self):
        module = load_finish_project()
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            repository, _project = self._tree(base)
            finish_root = base / "finish-state"
            transaction_id = "finish-20260916T082220Z-0011223344556677"

            calls = []

            def partial_copy(_source_fd, output_fd):
                calls.append(output_fd)
                descriptor = os.open(
                    "01-global.yaml", os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600, dir_fd=output_fd,
                )
                try:
                    os.write(descriptor, b"partial\n")
                finally:
                    os.close(descriptor)
                raise RuntimeError("injected copy interruption")

            uid_patch, gid_patch = self._identity_patches()
            with uid_patch, gid_patch, \
                    mock.patch.object(state, "FINISH_STATE_ROOT", finish_root), \
                    mock.patch.object(module, "_copy_snapshot_entries", side_effect=partial_copy), \
                    mock.patch.object(
                        module, "stop_runtime",
                        return_value={"stopped": True, "backend": "systemd"},
                    ):
                with self.assertRaisesRegex(RuntimeError, "copy interruption"):
                    module.execute_finish(
                        repository=repository,
                        project_name="customer",
                        runtime="native",
                        state_root=finish_root,
                        runtime_only_stop=True,
                        transaction_id=transaction_id,
                        created_at="2026-09-16T08:22:20Z",
                    )
            self.assertEqual(1, len(calls), "the anchored partial-copy hook must run")
            snapshot = (
                finish_root / "transactions" / transaction_id
                / "components/pre-stop-project"
            )
            self.assertFalse(snapshot.exists(), "partial snapshot must not publish")
            uid_patch, gid_patch = self._identity_patches()
            with uid_patch, gid_patch, \
                    mock.patch.object(state, "FINISH_STATE_ROOT", finish_root), \
                    mock.patch.object(
                        module, "stop_runtime",
                        return_value={"stopped": True, "backend": "systemd"},
                    ):
                result = module.execute_resume(
                    repository=repository,
                    transaction_id=transaction_id,
                    state_root=finish_root,
                )
            self.assertTrue((snapshot / "99-output-ztp/result.txt").is_file())
            self.assertTrue(result.bundle_path.is_file())

    def test_pre_stop_snapshot_rejects_symlinked_components_parent(self):
        """A private transaction's components name must not redirect a snapshot."""
        module = load_finish_project()
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            _repository, project = self._tree(base)
            transaction = base / "finish-state/transactions/finish-test"
            transaction.mkdir(parents=True)
            outside = base / "outside"
            outside.mkdir()
            sentinel = outside / "sentinel"
            sentinel.write_bytes(b"outside-unchanged")
            components = transaction / "components"
            components.symlink_to(outside, target_is_directory=True)
            error = None
            try:
                try:
                    module._copy_snapshot(project, components / "pre-stop-project")
                except Exception as exc:
                    error = exc
                self.assertEqual(b"outside-unchanged", sentinel.read_bytes())
                self.assertEqual(["sentinel"], sorted(p.name for p in outside.iterdir()))
                self.assertIsInstance(error, module.FinishProjectError)
                self.assertRegex(str(error), r"unsafe|identity|symlink")
            finally:
                components.unlink()

    def test_pre_stop_snapshot_copy_parent_rebind_cannot_write_outside(self):
        """A real copy callback must not follow a rebound components name."""
        module = load_finish_project()
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            _repository, project = self._tree(base)
            components = base / "finish-state/transactions/finish-test/components"
            components.mkdir(parents=True)
            held = components.with_name("components-held")
            outside = base / "outside"
            outside.mkdir()
            sentinel = outside / "sentinel"
            sentinel.write_bytes(b"outside-unchanged")
            real_copy = module._copy_snapshot_entries
            calls = []

            def rebind_then_copy(source_fd, output_fd):
                if not calls:
                    calls.append((source_fd, output_fd))
                    components.rename(held)
                    components.symlink_to(outside, target_is_directory=True)
                return real_copy(source_fd, output_fd)

            error = None
            try:
                with mock.patch.object(module, "_copy_snapshot_entries", side_effect=rebind_then_copy):
                    try:
                        module._copy_snapshot(project, components / "pre-stop-project")
                    except Exception as exc:
                        error = exc
                self.assertEqual(1, len(calls), "the copy rebind callback must run")
                self.assertEqual(b"outside-unchanged", sentinel.read_bytes())
                self.assertEqual(["sentinel"], sorted(p.name for p in outside.iterdir()))
                self.assertIsNotNone(error, "a rebound parent must fail closed")
            finally:
                if components.is_symlink():
                    components.unlink()
                if held.exists():
                    held.rename(components)

    def test_pre_stop_snapshot_failed_copy_cannot_delete_outside_staging(self):
        """Failure cleanup must not remove an outsider's same-named directory."""
        module = load_finish_project()
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            _repository, project = self._tree(base)
            components = base / "finish-state/transactions/finish-test/components"
            components.mkdir(parents=True)
            held = components.with_name("components-held")
            outside = base / "outside"
            outside.mkdir()
            real_copy = module._copy_snapshot_entries
            calls = []
            sentinels = []

            def partial_copy_then_rebind(source_fd, output_fd):
                if calls:
                    return real_copy(source_fd, output_fd)
                calls.append((source_fd, output_fd))
                real_copy(source_fd, output_fd)
                stage_names = [
                    item.name for item in components.iterdir()
                    if item.name.startswith(".pre-stop-project.staging-")
                ]
                self.assertEqual(1, len(stage_names))
                outsider_stage = outside / stage_names[0]
                outsider_stage.mkdir()
                sentinel = outsider_stage / "sentinel"
                sentinel.write_bytes(b"outside-unchanged")
                sentinels.append(sentinel)
                components.rename(held)
                components.symlink_to(outside, target_is_directory=True)
                raise RuntimeError("injected copy interruption after parent rebind")

            try:
                with mock.patch.object(module, "_copy_snapshot_entries", side_effect=partial_copy_then_rebind):
                    with self.assertRaisesRegex(RuntimeError, "injected copy interruption"):
                        module._copy_snapshot(project, components / "pre-stop-project")
                self.assertEqual(1, len(calls), "the failure rebind callback must run")
                self.assertEqual(1, len(sentinels))
                sentinel = sentinels[0]
                self.assertTrue(sentinel.is_file(), "failure cleanup deleted outsider sentinel")
                self.assertEqual(b"outside-unchanged", sentinel.read_bytes())
                self.assertTrue(sentinel.parent.is_dir())
            finally:
                if components.is_symlink():
                    components.unlink()
                if held.exists():
                    held.rename(components)

    def test_pre_stop_snapshot_publish_parent_rebind_cannot_move_outside_staging(self):
        """Publication must not rename an outsider's same-named staging tree."""
        module = load_finish_project()
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            _repository, project = self._tree(base)
            components = base / "finish-state/transactions/finish-test/components"
            components.mkdir(parents=True)
            held = components.with_name("components-held")
            outside = base / "outside"
            outside.mkdir()
            destination = components / "pre-stop-project"
            real_rename = module.os.rename
            calls = []
            sentinels = []

            def rebind_then_rename(source, target, *args, **kwargs):
                if (
                    isinstance(source, str)
                    and source.startswith(".pre-stop-project.staging-")
                    and target == destination.name
                    and kwargs.get("src_dir_fd") is not None
                    and kwargs.get("dst_dir_fd") is not None
                ):
                    calls.append((source, target))
                    outsider_stage = outside / source
                    outsider_stage.mkdir()
                    sentinel = outsider_stage / "sentinel"
                    sentinel.write_bytes(b"outside-unchanged")
                    sentinels.append(sentinel)
                    real_rename(components, held)
                    components.symlink_to(outside, target_is_directory=True)
                return real_rename(source, target, *args, **kwargs)

            error = None
            try:
                with mock.patch.object(module.os, "rename", side_effect=rebind_then_rename):
                    try:
                        module._copy_snapshot(project, destination)
                    except Exception as exc:
                        error = exc
                self.assertEqual(1, len(calls), "the publish rebind callback must run")
                self.assertEqual(1, len(sentinels))
                sentinel = sentinels[0]
                self.assertTrue(sentinel.is_file(), "publish moved outsider staging")
                self.assertEqual(b"outside-unchanged", sentinel.read_bytes())
                self.assertFalse((outside / "pre-stop-project").exists())
                self.assertIsNotNone(error, "a rebound parent must fail closed")
            finally:
                if components.is_symlink():
                    components.unlink()
                if held.exists():
                    held.rename(components)

    def test_finish_rejects_components_rebind_after_real_snapshot_before_bundle(self):
        """A completed snapshot cannot authorize later writes through a rebound name."""
        module = load_finish_project()
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            repository, project = self._tree(base)
            finish_root = base / "finish-state"
            transaction_id = "finish-20260925T013800Z-aabbccddeeff0011"
            components = finish_root / "transactions" / transaction_id / "components"
            held = components.with_name("components-held")
            outside = base / "outside"
            outside.mkdir()
            shutil.copytree(project, outside / "pre-stop-project", symlinks=True)
            marker = outside / "pre-stop-project/01-global.yaml"
            marker.write_bytes(b"project: OUTSIDE-MARKER\n")
            real_copy = module._copy_snapshot
            callbacks = []

            def copy_then_rebind(source, destination):
                real_copy(source, destination)
                destination.parent.rename(held)
                destination.parent.symlink_to(outside, target_is_directory=True)
                callbacks.append(destination)

            receipt_state = None
            try:
                uid_patch, gid_patch = self._identity_patches()
                with uid_patch, gid_patch, \
                        mock.patch.object(state, "FINISH_STATE_ROOT", finish_root), \
                        mock.patch.object(module, "_copy_snapshot", side_effect=copy_then_rebind), \
                        mock.patch.object(
                            module, "stop_runtime",
                            return_value={"stopped": True, "backend": "systemd", "status": 0},
                        ):
                    try:
                        module.execute_finish(
                            repository=repository,
                            project_name="customer",
                            runtime="native",
                            state_root=finish_root,
                            runtime_only_stop=True,
                            transaction_id=transaction_id,
                            created_at="2026-09-25T01:38:00Z",
                        )
                    except Exception:
                        pass  # Fail-closed is acceptable; outside writes are not.
                    try:
                        receipt_state = state.read_transaction(
                            transaction_id, root=finish_root,
                        )["state"]
                    except (FileNotFoundError, state.FinishStateError):
                        pass
                self.assertEqual(1, len(callbacks), "the real-snapshot rebind must run")
                self.assertEqual(b"project: OUTSIDE-MARKER\n", marker.read_bytes())
                self.assertEqual(
                    [], list(outside.glob("http-ztp-finished-*.tar.gz")),
                    "a rebound components name wrote an outside finished bundle",
                )
                self.assertNotEqual("completed", receipt_state)
            finally:
                if components.is_symlink():
                    components.unlink()
                if held.exists():
                    held.rename(components)

    def test_resume_rejects_components_rebind_after_receipt_before_bundle(self):
        """Resume must not trust a components name changed after receipt reading."""
        module = load_finish_project()
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            repository, project = self._tree(base)
            finish_root = base / "finish-state"
            transaction_id = "finish-20260925T013900Z-aabbccddeeff0022"
            components = finish_root / "transactions" / transaction_id / "components"
            held = components.with_name("components-held")
            outside = base / "outside"
            outside.mkdir()
            shutil.copytree(project, outside / "pre-stop-project", symlinks=True)
            marker = outside / "pre-stop-project/01-global.yaml"
            marker.write_bytes(b"project: OUTSIDE-RESUME\n")
            uid_patch, gid_patch = self._identity_patches()
            with uid_patch, gid_patch, \
                    mock.patch.object(state, "FINISH_STATE_ROOT", finish_root), \
                    mock.patch.object(
                        module, "stop_runtime", side_effect=RuntimeError("injected stop failure"),
                    ):
                with self.assertRaisesRegex(RuntimeError, "injected stop failure"):
                    module.execute_finish(
                        repository=repository,
                        project_name="customer",
                        runtime="native",
                        state_root=finish_root,
                        runtime_only_stop=True,
                        transaction_id=transaction_id,
                        created_at="2026-09-25T01:39:00Z",
                    )
            real_read = state.read_transaction
            callbacks = []

            def read_then_rebind(*args, **kwargs):
                receipt = real_read(*args, **kwargs)
                if not callbacks:
                    components.rename(held)
                    components.symlink_to(outside, target_is_directory=True)
                    callbacks.append(receipt["state"])
                return receipt

            receipt_state = None
            try:
                uid_patch, gid_patch = self._identity_patches()
                with uid_patch, gid_patch, \
                        mock.patch.object(state, "FINISH_STATE_ROOT", finish_root), \
                        mock.patch.object(module.state, "read_transaction", side_effect=read_then_rebind), \
                        mock.patch.object(
                            module, "stop_runtime",
                            return_value={"stopped": True, "backend": "systemd", "status": 0},
                        ):
                    try:
                        module.execute_resume(
                            repository=repository,
                            transaction_id=transaction_id,
                            state_root=finish_root,
                        )
                    except Exception:
                        pass  # Fail-closed is acceptable; outside writes are not.
                    receipt_state = real_read(transaction_id, root=finish_root)["state"]
                self.assertEqual(["failed"], callbacks)
                self.assertEqual(b"project: OUTSIDE-RESUME\n", marker.read_bytes())
                self.assertEqual(
                    [], list(outside.glob("http-ztp-finished-*.tar.gz")),
                    "resume wrote a finished bundle through rebound components",
                )
                self.assertNotEqual("completed", receipt_state)
            finally:
                if components.is_symlink():
                    components.unlink()
                if held.exists():
                    held.rename(components)

    def test_finish_rejects_real_directory_swap_of_private_mirror(self):
        """A held inventory cannot justify bundling a different real mirror."""
        module = load_finish_project()
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            repository, project = self._tree(base)
            finish_root = base / "finish-state"
            transaction_id = "finish-20260925T020500Z-aabbccddeeff0099"
            outside = base / "outside"
            shutil.copytree(project, outside, symlinks=True)
            outside_marker = outside / "01-global.yaml"
            outside_marker.write_bytes(b"project: OUTSIDE-MIRROR\n")
            real_open = module.os.open
            real_inventory = module._snapshot_inventory_fd
            mirror = [None]
            mirror_inode = [None]
            callbacks = []

            def capture_mirror_open(path, *args, **kwargs):
                descriptor = real_open(path, *args, **kwargs)
                if (
                    isinstance(path, Path)
                    and path.name == "pre-stop-project"
                    and "http-finish-held-" in str(path)
                ):
                    mirror[0] = path
                    mirror_inode[0] = os.fstat(descriptor).st_ino
                return descriptor

            def substitute_after_real_inventory(descriptor):
                inventory = real_inventory(descriptor)
                if (
                    mirror[0] is not None
                    and not callbacks
                    and os.fstat(descriptor).st_ino == mirror_inode[0]
                ):
                    mirror[0].rename(mirror[0].with_name("pre-stop-project-held"))
                    shutil.copytree(outside, mirror[0], symlinks=True)
                    callbacks.append(inventory)
                return inventory

            receipt_state = None
            result = None
            uid_patch, gid_patch = self._identity_patches()
            with uid_patch, gid_patch, \
                    mock.patch.object(state, "FINISH_STATE_ROOT", finish_root), \
                    mock.patch.object(module.os, "open", side_effect=capture_mirror_open), \
                    mock.patch.object(
                        module, "_snapshot_inventory_fd",
                        side_effect=substitute_after_real_inventory,
                    ), \
                    mock.patch.object(
                        module, "stop_runtime",
                        return_value={"stopped": True, "backend": "systemd", "status": 0},
                    ):
                try:
                    result = module.execute_finish(
                        repository=repository,
                        project_name="customer",
                        runtime="native",
                        state_root=finish_root,
                        runtime_only_stop=True,
                        transaction_id=transaction_id,
                        created_at="2026-09-25T02:05:00Z",
                    )
                except Exception:
                    pass  # Failing closed is valid; a wrong completed bundle is not.
                receipt_state = state.read_transaction(
                    transaction_id, root=finish_root,
                )["state"]
            self.assertEqual(1, len(callbacks), "the held-mirror swap must run")
            self.assertEqual(b"project: OUTSIDE-MIRROR\n", outside_marker.read_bytes())
            held_global = (
                finish_root / "transactions" / transaction_id
                / "components/pre-stop-project/01-global.yaml"
            ).read_bytes()
            self.assertEqual(b"project: customer\n", held_global)
            bundle_path = (
                finish_root / "transactions" / transaction_id / "components"
                / f"http-ztp-finished-customer-{transaction_id}.tar.gz"
            )
            if receipt_state == "completed":
                self.assertIsNotNone(result)
                self.assertTrue(bundle_path.is_file())
            if bundle_path.is_file():
                with tarfile.open(bundle_path, "r:gz") as outer:
                    payload = outer.extractfile(
                        f"{finished_bundle.BUNDLE_ROOT}/pre-stop/project.tar.gz"
                    ).read()
                with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as inner:
                    bundled_global = inner.extractfile("project/01-global.yaml").read()
                self.assertEqual(
                    held_global, bundled_global,
                    "completed bundle used a swapped private mirror, not held snapshot",
                )

    def test_finish_rejects_components_rebind_after_real_bundle_helper(self):
        """A held publication cannot complete a now-unreachable public receipt."""
        module = load_finish_project()
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            repository, _project = self._tree(base)
            finish_root = base / "finish-state"
            transaction_id = "finish-20260925T020600Z-aabbccddeeff0088"
            components = finish_root / "transactions" / transaction_id / "components"
            held = components.with_name("components-held")
            outside = base / "outside"
            outside.mkdir()
            marker = outside / "marker"
            marker.write_bytes(b"OUTSIDE-UNCHANGED")
            real_helper = module._build_or_verify_anchored_bundle
            callbacks = []

            def rebind_after_real_helper(**kwargs):
                result = real_helper(**kwargs)
                components.rename(held)
                components.symlink_to(outside, target_is_directory=True)
                callbacks.append(result)
                return result

            returned = None
            receipt_state = None
            try:
                uid_patch, gid_patch = self._identity_patches()
                with uid_patch, gid_patch, \
                        mock.patch.object(state, "FINISH_STATE_ROOT", finish_root), \
                        mock.patch.object(
                            module, "_build_or_verify_anchored_bundle",
                            side_effect=rebind_after_real_helper,
                        ), \
                        mock.patch.object(
                            module, "stop_runtime",
                            return_value={"stopped": True, "backend": "systemd", "status": 0},
                        ):
                    try:
                        returned = module.execute_finish(
                            repository=repository,
                            project_name="customer",
                            runtime="native",
                            state_root=finish_root,
                            runtime_only_stop=True,
                            transaction_id=transaction_id,
                            created_at="2026-09-25T02:06:00Z",
                        )
                    except Exception:
                        pass  # A changed public binding should fail closed.
                    receipt_state = state.read_transaction(
                        transaction_id, root=finish_root,
                    )["state"]
                self.assertEqual(1, len(callbacks), "the post-bundle rebind must run")
                self.assertEqual(b"OUTSIDE-UNCHANGED", marker.read_bytes())
                self.assertEqual([], list(outside.glob("http-ztp-finished-*.tar.gz")))
                self.assertNotEqual(
                    "completed", receipt_state,
                    "completed receipt names a bundle outside its held components",
                )
                self.assertIsNone(returned, "finish returned success after public rebind")
            finally:
                if components.is_symlink():
                    components.unlink()
                if held.exists():
                    held.rename(components)

    def test_resume_after_pending_receipt_failure_reuses_pending_and_snapshot(self):
        module = load_finish_project()
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            repository, _project = self._tree(base)
            finish_root = base / "finish-state"
            transaction_id = "finish-20260916T082220Z-1020304050607080"
            original_advance = state.advance_transaction
            failed = False

            def advance(transaction, new_state, **kwargs):
                nonlocal failed
                if new_state == "pending_committed" and not failed:
                    failed = True
                    raise RuntimeError("injected pending receipt failure")
                return original_advance(transaction, new_state, **kwargs)

            uid_patch, gid_patch = self._identity_patches()
            with uid_patch, gid_patch, \
                    mock.patch.object(state, "FINISH_STATE_ROOT", finish_root), \
                    mock.patch.object(module.state, "advance_transaction", side_effect=advance), \
                    mock.patch.object(
                        module, "stop_runtime",
                        return_value={"stopped": True, "backend": "systemd"},
                    ) as stop:
                with self.assertRaisesRegex(RuntimeError, "pending receipt"):
                    module.execute_finish(
                        repository=repository,
                        project_name="customer",
                        runtime="native",
                        state_root=finish_root,
                        runtime_only_stop=True,
                        transaction_id=transaction_id,
                        created_at="2026-09-16T08:22:20Z",
                    )
                pending_before = state.read_finish_pending(finish_root)
                snapshot = (
                    finish_root / "transactions" / transaction_id
                    / "components/pre-stop-project/01-global.yaml"
                )
                snapshot_before = (snapshot.stat().st_ino, snapshot.read_bytes())
                result = module.execute_resume(
                    repository=repository,
                    transaction_id=transaction_id,
                    state_root=finish_root,
                )
                snapshot_after = (snapshot.stat().st_ino, snapshot.read_bytes())

            self.assertEqual(transaction_id, pending_before["transaction_id"])
            self.assertEqual(snapshot_before, snapshot_after)
            self.assertEqual(1, stop.call_count)
            self.assertTrue(result.bundle_path.is_file())

    def test_resume_after_bundle_failure_does_not_stop_runtime_twice(self):
        module = load_finish_project()
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            repository, _project = self._tree(base)
            finish_root = base / "finish-state"
            transaction_id = "finish-20260916T082220Z-1122334455667788"
            stop_calls = 0
            bundle_calls = 0
            original_bundle = module.create_finished_bundle

            def stop_runtime(**_kwargs):
                nonlocal stop_calls
                stop_calls += 1
                return {"stopped": True, "backend": "systemd"}

            def bundle(**kwargs):
                nonlocal bundle_calls
                bundle_calls += 1
                if bundle_calls == 1:
                    raise RuntimeError("injected bundle failure")
                return original_bundle(**kwargs)

            uid_patch, gid_patch = self._identity_patches()
            with uid_patch, gid_patch, \
                    mock.patch.object(state, "FINISH_STATE_ROOT", finish_root), \
                    mock.patch.object(module, "stop_runtime", side_effect=stop_runtime), \
                    mock.patch.object(module, "create_finished_bundle", side_effect=bundle):
                with self.assertRaisesRegex(RuntimeError, "bundle failure"):
                    module.execute_finish(
                        repository=repository,
                        project_name="customer",
                        runtime="native",
                        state_root=finish_root,
                        runtime_only_stop=True,
                        transaction_id=transaction_id,
                        created_at="2026-09-16T08:22:20Z",
                    )
                result = module.execute_resume(
                    repository=repository,
                    transaction_id=transaction_id,
                    state_root=finish_root,
                )

            self.assertEqual(1, stop_calls)
            self.assertEqual(2, bundle_calls)
            self.assertTrue(result.bundle_path.is_file())

    def test_resume_after_bundle_receipt_failures_reuses_verified_bundle(self):
        module = load_finish_project()
        for failed_stage in (
            "final_delta_complete", "bundle_finalizing", "completed",
        ):
            with self.subTest(failed_stage=failed_stage), \
                    tempfile.TemporaryDirectory() as name:
                base = Path(name)
                repository, _project = self._tree(base)
                finish_root = base / "finish-state"
                transaction_id = (
                    "finish-20260916T082220Z-"
                    + {"final_delta_complete": "1111111111111111",
                       "bundle_finalizing": "2222222222222222",
                       "completed": "3333333333333333"}[failed_stage]
                )
                original_advance = state.advance_transaction
                original_bundle = module.create_finished_bundle
                injected = False
                bundle_calls = 0
                stop_calls = 0

                def advance(transaction, new_state, **kwargs):
                    nonlocal injected
                    if new_state == failed_stage and not injected:
                        injected = True
                        raise RuntimeError(f"injected {failed_stage} receipt failure")
                    return original_advance(transaction, new_state, **kwargs)

                def bundle(**kwargs):
                    nonlocal bundle_calls
                    bundle_calls += 1
                    return original_bundle(**kwargs)

                def stop_runtime(**_kwargs):
                    nonlocal stop_calls
                    stop_calls += 1
                    return {"stopped": True, "backend": "systemd"}

                uid_patch, gid_patch = self._identity_patches()
                with uid_patch, gid_patch, \
                        mock.patch.object(state, "FINISH_STATE_ROOT", finish_root), \
                        mock.patch.object(module.state, "advance_transaction", side_effect=advance), \
                        mock.patch.object(module, "stop_runtime", side_effect=stop_runtime), \
                        mock.patch.object(module, "create_finished_bundle", side_effect=bundle):
                    with self.assertRaisesRegex(RuntimeError, failed_stage):
                        module.execute_finish(
                            repository=repository,
                            project_name="customer",
                            runtime="native",
                            state_root=finish_root,
                            runtime_only_stop=True,
                            transaction_id=transaction_id,
                            created_at="2026-09-16T08:22:20Z",
                        )
                    bundle_path = next(
                        (finish_root / "transactions" / transaction_id / "components").glob(
                            "http-ztp-finished-*.tar.gz"
                        )
                    )
                    before = (bundle_path.stat().st_ino, bundle_path.read_bytes())
                    result = module.execute_resume(
                        repository=repository,
                        transaction_id=transaction_id,
                        state_root=finish_root,
                    )
                    after = (bundle_path.stat().st_ino, bundle_path.read_bytes())

                self.assertEqual(1, stop_calls)
                self.assertEqual(1, bundle_calls)
                self.assertEqual(before, after)
                self.assertEqual(bundle_path, result.bundle_path)

    def test_completed_resume_reverifies_bundle_before_pending_cleanup(self):
        module = load_finish_project()
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            repository, _project = self._tree(base)
            finish_root = base / "finish-state"
            transaction_id = "finish-20260916T082220Z-8877665544332211"
            uid_patch, gid_patch = self._identity_patches()
            with uid_patch, gid_patch, \
                    mock.patch.object(state, "FINISH_STATE_ROOT", finish_root), \
                    mock.patch.object(
                        module, "stop_runtime",
                        return_value={"stopped": True, "backend": "systemd"},
                    ), mock.patch.object(
                        module.state, "clear_finish_pending",
                        side_effect=RuntimeError("cleanup interrupted"),
                    ):
                with self.assertRaisesRegex(RuntimeError, "cleanup interrupted"):
                    module.execute_finish(
                        repository=repository,
                        project_name="customer",
                        runtime="native",
                        state_root=finish_root,
                        runtime_only_stop=True,
                        transaction_id=transaction_id,
                        created_at="2026-09-16T08:22:20Z",
                    )
            uid_patch, gid_patch = self._identity_patches()
            with uid_patch, gid_patch:
                receipt = state.read_transaction(transaction_id, root=finish_root)
                bundle_path = Path(receipt["evidence"]["bundle_path"])
                original = bundle_path.read_bytes()
                bundle_path.write_bytes(original + b"tampered")
                with self.assertRaisesRegex(module.FinishProjectError, "hash changed"):
                    module.execute_resume(
                        repository=repository,
                        transaction_id=transaction_id,
                        state_root=finish_root,
                    )
                self.assertIsNotNone(state.read_finish_pending(finish_root))
                bundle_path.write_bytes(original)
                result = module.execute_resume(
                    repository=repository,
                    transaction_id=transaction_id,
                    state_root=finish_root,
                )
                self.assertIsNone(state.read_finish_pending(finish_root))
            self.assertEqual(bundle_path, result.bundle_path)


if __name__ == "__main__":
    unittest.main()
