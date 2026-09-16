#!/usr/bin/env python3
"""Direct tests for the finished-project producer orchestration."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from tools import finished_project_state as state


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

            def partial_copy(source, destination, **_kwargs):
                destination.mkdir()
                (destination / "01-global.yaml").write_text(
                    "partial\n", encoding="utf-8",
                )
                raise RuntimeError("injected copy interruption")

            uid_patch, gid_patch = self._identity_patches()
            with uid_patch, gid_patch, \
                    mock.patch.object(state, "FINISH_STATE_ROOT", finish_root), \
                    mock.patch.object(module.shutil, "copytree", side_effect=partial_copy), \
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
