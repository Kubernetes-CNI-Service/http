#!/usr/bin/env python3
"""Hermetic workflow for sample links, Feedback and the deployment lock."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SAMPLE_LINKS = load_module(
    "feedback_writeback_sample_links", ROOT / "ztp/optimize/sample_links.py",
)
FEEDBACK = load_module(
    "feedback_writeback_workflow", ROOT / "ztp/optimize/feedback.py",
)
DEPLOYMENT_LOCK = load_module(
    "feedback_writeback_deployment_lock", ROOT / "tools/deployment_lock.py",
)


class FeedbackGlobalWritebackWorkflowTests(unittest.TestCase):
    def _project(self, workspace: Path, *, authority: bytes = b"common: {}\n"):
        """Build the smallest real project understood by sample_links.py."""
        optimize = workspace / "ztp/optimize"
        optimize.mkdir(parents=True)
        project = workspace / "DAY0-Prepare/demo"
        project.mkdir(parents=True)
        (project / "01-global.yaml").write_bytes(authority)
        (project / "02-devices_config.csv").write_text(
            "hostname,type\nleaf01,eth\nair01,air\n", encoding="utf-8",
        )
        generated = project / "99-output-eth/20260911_010203_combine"
        generated.mkdir(parents=True)
        (generated / ".published-complete").write_text("ok\n", encoding="utf-8")
        (generated / "leaf01.yaml").write_text(
            "- set:\n    system:\n      hostname: leaf01\n", encoding="utf-8",
        )
        return optimize, project

    def _module_at(self, workspace: Path):
        return mock.patch.object(
            FEEDBACK, "__file__", str(workspace / "ztp/optimize/feedback.py"),
        )

    @staticmethod
    def _tree_snapshot(root: Path):
        result = {}
        for path in sorted(root.rglob("*")):
            relative = str(path.relative_to(root))
            value = os.lstat(path)
            payload = None
            if os.path.isfile(path) and not os.path.islink(path):
                payload = path.read_bytes()
            elif os.path.islink(path):
                payload = os.readlink(path)
            result[relative] = (
                value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                value.st_size, payload,
            )
        return result

    def test_manifest_registers_direct_and_real_cross_script_workflow(self):
        manifest = json.loads(
            (ROOT / "test_cases/script_test_manifest.json").read_text(
                encoding="utf-8",
            )
        )
        direct = next(
            rule for rule in manifest["test_rules"]
            if rule["id"] == "optimization_feedback"
        )
        required = {
            "test_cases.test_feedback_global_writeback",
            "test_cases.test_feedback_global_writeback_workflow",
        }
        self.assertTrue(required.issubset(set(direct["tests"])))
        workflow = next(
            item for item in manifest["workflows"]
            if item["id"] == "config_generate_publish_compare"
        )
        self.assertTrue(required.issubset(set(workflow["tests"])))
        self.assertIn("tools/deployment_lock.py", workflow["members"])
        self.assertIn("ztp/optimize/*", workflow["members"])
        suite = next(
            item for item in manifest["test_suites"]
            if item["id"] == "configuration-generation"
        )
        self.assertTrue(required.issubset(set(suite["tests"])))

    def test_real_main_lock_contention_is_bounded_and_precedes_all_mutation(self):
        original = (
            b"common:\n  switch:\n    system:\n      date-time:\n"
            b"        timezone: {}\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            _optimize, project = self._project(workspace, authority=original)
            lock = DEPLOYMENT_LOCK.acquire_lock_descriptor(workspace)
            before = self._tree_snapshot(workspace)
            stderr = io.StringIO()
            try:
                with self._module_at(workspace), redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as raised:
                        FEEDBACK.main([str(project), "--type", "prod"])
            finally:
                DEPLOYMENT_LOCK.release_lock_descriptor(lock)

            self.assertEqual(2, raised.exception.code)
            self.assertEqual(before, self._tree_snapshot(workspace))
            self.assertFalse((workspace / "ztp/optimize/demo-sample").exists())
            self.assertFalse((project / "99-output-ztp").exists())
            self.assertIn("deployment-lock", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_real_main_invalid_yaml_is_rejected_before_real_sample_refresh(self):
        canary = "".join(("SENSITIVE", "-CANARY-NOT-FOR-LOG"))
        invalid = (
            "common:\n  switch:\n    password: [" + canary + "\n"
        ).encode("utf-8")
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            _optimize, project = self._project(workspace, authority=invalid)
            # Make the lock an existing part of the pre-tree so the assertion
            # covers every other inode and byte created by the real CLI.
            lock_path = workspace / ".deployment.lock"
            lock_path.write_bytes(b"")
            before = self._tree_snapshot(workspace)
            stderr = io.StringIO()
            with self._module_at(workspace), redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as raised:
                    FEEDBACK.main([str(project), "--type", "prod"])

            self.assertEqual(2, raised.exception.code)
            self.assertEqual(before, self._tree_snapshot(workspace))
            self.assertFalse((workspace / "ztp/optimize/demo-sample").exists())
            self.assertFalse((project / "99-output-ztp").exists())
            self.assertNotIn(canary, stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_real_main_rejects_unsafe_output_or_sample_root_before_any_mutation(self):
        original = (
            b"common:\n  switch:\n    system:\n      date-time:\n"
            b"        timezone: {}\n"
        )
        for attack in (
                "project-mode", "optimize-mode", "output-symlink",
                "output-mode", "output-leaf-symlink", "output-leaf-mode",
                "sample-symlink", "sample-mode"):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as directory:
                workspace = Path(directory)
                optimize, project = self._project(workspace, authority=original)
                (workspace / ".deployment.lock").write_bytes(b"")
                output_root = project / "99-output-ztp"
                sample = optimize / "demo-sample"
                if attack == "project-mode":
                    project.chmod(0o777)
                elif attack == "optimize-mode":
                    optimize.chmod(0o777)
                elif attack == "output-symlink":
                    external = workspace / "external-output"
                    external.mkdir()
                    output_root.symlink_to(external, target_is_directory=True)
                elif attack == "output-mode":
                    output_root.mkdir()
                    output_root.chmod(0o777)
                elif attack in {"output-leaf-symlink", "output-leaf-mode"}:
                    output_root.mkdir()
                    output_leaf = output_root / "optimize"
                    if attack == "output-leaf-symlink":
                        external = workspace / "external-output"
                        external.mkdir()
                        output_leaf.symlink_to(external, target_is_directory=True)
                    else:
                        output_leaf.mkdir()
                        output_leaf.chmod(0o777)
                elif attack == "sample-symlink":
                    external = workspace / "external-sample"
                    external.mkdir()
                    sample.symlink_to(external, target_is_directory=True)
                else:
                    sample.mkdir()
                    sample.chmod(0o777)
                before = self._tree_snapshot(workspace)
                stderr = io.StringIO()
                with self._module_at(workspace), redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as raised:
                        FEEDBACK.main([str(project), "--type", "prod"])

                self.assertEqual(2, raised.exception.code)
                self.assertEqual(before, self._tree_snapshot(workspace))
                self.assertNotIn("Traceback", stderr.getvalue())

    def test_real_main_owner_mismatch_is_rejected_before_sample_mutation(self):
        original = b"common: {}\n"
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            _optimize, project = self._project(workspace, authority=original)
            output_root = project / "99-output-ztp"
            output_root.mkdir()
            (workspace / ".deployment.lock").write_bytes(b"")
            target = os.lstat(output_root)
            before = self._tree_snapshot(workspace)
            real_fstat = os.fstat

            def wrong_owner(descriptor):
                value = real_fstat(descriptor)
                if (value.st_dev, value.st_ino) != (target.st_dev, target.st_ino):
                    return value
                attributes = {
                    name: getattr(value, name) for name in (
                        "st_dev", "st_ino", "st_mode", "st_nlink",
                        "st_uid", "st_gid", "st_size", "st_mtime_ns",
                        "st_ctime_ns",
                    )
                }
                attributes["st_uid"] += 1
                return SimpleNamespace(**attributes)

            stderr = io.StringIO()
            with (
                self._module_at(workspace), redirect_stderr(stderr),
                mock.patch.object(os, "fstat", side_effect=wrong_owner),
            ):
                with self.assertRaises(SystemExit) as raised:
                    FEEDBACK.main([str(project), "--type", "prod"])

            self.assertEqual(2, raised.exception.code)
            self.assertEqual(before, self._tree_snapshot(workspace))
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_real_main_output_rebind_before_legacy_migration_changes_no_program_bytes(self):
        original = b"common: {}\n"
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            optimize, project = self._project(workspace, authority=original)
            sample = optimize / "demo-sample"
            legacy = sample / "comparison"
            legacy.mkdir(parents=True)
            (legacy / "keep.txt").write_text("legacy\n", encoding="utf-8")
            output_root = project / "99-output-ztp"
            output_root.mkdir()
            (workspace / ".deployment.lock").write_bytes(b"")
            real_plan = FEEDBACK.plan_sample_mutations
            attacked_snapshot = None

            def bind_then_rebind(*args, **kwargs):
                nonlocal attacked_snapshot
                plan = real_plan(*args, **kwargs)
                output_root.rename(project / "displaced-output-root")
                output_root.mkdir()
                attacked_snapshot = self._tree_snapshot(workspace)
                return plan

            stderr = io.StringIO()
            with (
                self._module_at(workspace), redirect_stderr(stderr),
                mock.patch.object(
                    FEEDBACK, "plan_sample_mutations",
                    side_effect=bind_then_rebind,
                ),
            ):
                with self.assertRaises(SystemExit) as raised:
                    FEEDBACK.main([str(project), "--type", "prod"])

            self.assertEqual(2, raised.exception.code)
            self.assertIsNotNone(attacked_snapshot)
            self.assertEqual(attacked_snapshot, self._tree_snapshot(workspace))
            self.assertEqual(b"legacy\n", (legacy / "keep.txt").read_bytes())
            self.assertFalse((output_root / "optimize").exists())
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_real_main_migrates_legacy_output_through_held_parents(self):
        original = b"common: {}\n"
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            optimize, project = self._project(workspace, authority=original)
            sample = optimize / "demo-sample"
            legacy = sample / "comparison"
            legacy.mkdir(parents=True)
            legacy_file = legacy / "operator-history.txt"
            legacy_file.write_text("preserve-exactly\n", encoding="utf-8")

            with self._module_at(workspace):
                self.assertEqual(
                    0, FEEDBACK.main([str(project), "--type", "prod"]),
                )

            target = project / "99-output-ztp/optimize"
            self.assertTrue((sample / "comparison").is_symlink())
            self.assertEqual(target.resolve(), (sample / "comparison").resolve())
            self.assertEqual(
                b"preserve-exactly\n",
                (target / "operator-history.txt").read_bytes(),
            )

    def test_real_main_missing_comparison_inputs_do_not_echo_untrusted_paths(self):
        canary = "".join(("SENSITIVE", "-MISSING-PATH-CANARY"))
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            first = workspace / f"first-{canary}.yaml"
            second = workspace / f"second-{canary}.yaml"
            stderr = io.StringIO()
            with self._module_at(workspace), redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as raised:
                    FEEDBACK.main([str(first), str(second)])

            self.assertEqual(2, raised.exception.code)
            self.assertNotIn(canary, stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_real_refresh_race_cannot_authorize_external_same_basename_root(self):
        original = (
            b"common:\n  switch:\n    system:\n      date-time:\n"
            b"        timezone: {}\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            _optimize, project = self._project(workspace, authority=original)
            external = workspace / "external/demo"
            external.mkdir(parents=True)
            external_authority = external / "01-global.yaml"
            external_authority.write_bytes(original)
            real_refresh = FEEDBACK.update_sample_links

            def refresh_then_redirect(optimize_dir, project_dir, **kwargs):
                sample = real_refresh(optimize_dir, project_dir, **kwargs)
                link = sample / "01-global.yaml"
                link.unlink()
                link.symlink_to(os.path.relpath(external_authority, sample))
                return sample

            stderr = io.StringIO()
            with (
                self._module_at(workspace),
                mock.patch.object(
                    FEEDBACK, "update_sample_links", side_effect=refresh_then_redirect,
                ),
                redirect_stderr(stderr),
            ):
                with self.assertRaises(SystemExit) as raised:
                    FEEDBACK.main([str(project), "--type", "prod"])

            self.assertEqual(2, raised.exception.code)
            self.assertEqual(original, (project / "01-global.yaml").read_bytes())
            self.assertEqual(original, external_authority.read_bytes())
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_real_main_manual_recovery_clears_only_verified_published_state(self):
        original = b"common: {}\n"
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            authority = workspace / "01-global.yaml"
            authority.write_bytes(original)
            state = (
                workspace / "99-output-ztp/optimize"
                / FEEDBACK.GLOBAL_WRITEBACK_STATE_NAME
            )
            state.parent.mkdir(parents=True)
            record = {
                "authority_path": str(authority.absolute()),
                "expected_after_sha256": FEEDBACK.hashlib.sha256(original).hexdigest(),
                "published": True,
                "schema": 1,
                "timestamp": "2026-09-11T00:00:00Z",
            }
            state.write_text(
                json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            state.chmod(0o600)
            with self._module_at(workspace):
                self.assertEqual(0, FEEDBACK.main([
                    "--recover-global-writeback-state",
                    "--global-config", str(authority),
                ]))
            self.assertFalse(state.exists())

            record["published"] = False
            state.write_text(
                json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            state.chmod(0o600)
            stderr = io.StringIO()
            with self._module_at(workspace), redirect_stderr(stderr):
                with self.assertRaises(SystemExit):
                    FEEDBACK.main([
                        "--recover-global-writeback-state",
                        "--global-config", str(authority),
                    ])
            self.assertTrue(state.exists())
            self.assertIn("state-blocked", stderr.getvalue())

    def test_real_prod_air_main_refreshes_once_commits_once_and_preserves_link_identity(self):
        original = (
            b"# exact project authority\n"
            b"common:\n"
            b"  switch:\n"
            b"    system:\n"
            b"      date-time:\n"
            b"        timezone: {} # first evidence wins\n"
            b"switches:\n"
            b"  - eth: {}\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            optimize, project = self._project(workspace, authority=original)
            authority = project / "01-global.yaml"
            refresh_count = 0
            live_replace_count = 0
            authority_snapshot_count = 0
            refreshed_link_identity = None
            real_refresh = FEEDBACK.update_sample_links
            real_replace = FEEDBACK.os.replace
            real_snapshot = FEEDBACK.GlobalWritebackTransaction._snapshot_authority

            def counted_refresh(*args, **kwargs):
                nonlocal refresh_count, refreshed_link_identity
                refresh_count += 1
                sample = real_refresh(*args, **kwargs)
                refreshed_link_identity = os.lstat(sample / "01-global.yaml")
                return sample

            def counted_replace(source, destination, *args, **kwargs):
                nonlocal live_replace_count
                if destination == "01-global.yaml" and kwargs.get("dst_dir_fd"):
                    live_replace_count += 1
                return real_replace(source, destination, *args, **kwargs)

            def counted_snapshot(transaction):
                nonlocal authority_snapshot_count
                authority_snapshot_count += 1
                return real_snapshot(transaction)

            def staged_convert(_source, destination, *_args, **kwargs):
                destination = Path(destination)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text("hostname,type\n", encoding="utf-8")
                transaction = kwargs["global_writeback"]
                scope = kwargs["environment_scope"]
                if scope == "air":
                    transaction.stage(
                        {"common": {"switch": {"system": {"date-time": {
                            "timezone": "UTC",
                        }}}}},
                        {("common", "switch", "system", "date-time", "timezone")},
                        source_scope="air", source_ref="air-runtime",
                    )
                return destination

            output = io.StringIO()
            with (
                self._module_at(workspace),
                redirect_stdout(output),
                mock.patch.object(
                    FEEDBACK, "update_sample_links", side_effect=counted_refresh,
                ),
                mock.patch.object(FEEDBACK.os, "replace", side_effect=counted_replace),
                mock.patch.object(
                    FEEDBACK.GlobalWritebackTransaction, "_snapshot_authority",
                    counted_snapshot,
                ),
                mock.patch.object(FEEDBACK, "convert_one", side_effect=staged_convert),
                mock.patch.object(FEEDBACK, "discover_comparison_sources", return_value=[]),
            ):
                self.assertEqual(0, FEEDBACK.main([str(project)]))

            sample = optimize / "demo-sample"
            link = sample / "01-global.yaml"
            self.assertEqual(1, refresh_count)
            self.assertEqual(1, authority_snapshot_count)
            self.assertEqual(1, live_replace_count)
            after = os.lstat(link)
            self.assertEqual(
                (refreshed_link_identity.st_dev, refreshed_link_identity.st_ino),
                (after.st_dev, after.st_ino),
            )
            self.assertTrue(link.is_symlink())
            self.assertIn(b"timezone: UTC # first evidence wins", authority.read_bytes())
            records = [
                json.loads(line) for line in output.getvalue().splitlines()
                if line.startswith("{") and '"source_scope"' in line
            ]
            self.assertEqual(1, len(records))
            self.assertEqual("air", records[0]["source_scope"])
            self.assertNotIn("UTC", output.getvalue())

    def test_real_deployment_lock_contention_blocks_before_mutation(self):
        original = b"common: {}\n"
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            authority = workspace / "01-global.yaml"
            authority.write_bytes(original)
            held = DEPLOYMENT_LOCK.acquire_lock_descriptor(workspace)
            try:
                with self.assertRaisesRegex(Exception, "operation is active"):
                    with FEEDBACK.GlobalWritebackTransaction(
                        authority, workspace_root=workspace,
                    ):
                        self.fail("authority snapshot must not run under contention")
            finally:
                DEPLOYMENT_LOCK.release_lock_descriptor(held)
            self.assertEqual(original, authority.read_bytes())


if __name__ == "__main__":
    unittest.main()
