#!/usr/bin/env python3
"""Independent contracts for immutable Monitor root-workflow source export."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
GUARD_PATH = ROOT / "test_cases/monitor_authority_source_guard.py"


def load_guard():
    spec = importlib.util.spec_from_file_location(
        "monitor_authority_source_guard_under_test", GUARD_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("source guard import spec is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        if sys.modules.get(spec.name) is module:
            del sys.modules[spec.name]
        raise
    return module


class MonitorAuthoritySourceGuardTests(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        self.guard = load_guard()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name) / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "user.email", "monitor-source@example.invalid")
        self.git("config", "user.name", "Monitor Source Test")

    def git(self, *arguments: str) -> str:
        git_environment = {
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "HOME": self.temporary.name,
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
        }
        result = subprocess.run(
            [
                "/usr/bin/git",
                "-c", "commit.gpgsign=false",
                "-c", "core.hooksPath=/dev/null",
                "-C", os.fspath(self.repo),
                *arguments,
            ],
            check=True,
            env=git_environment,
            stdin=subprocess.DEVNULL,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10.0,
        )
        return result.stdout.strip()

    def test_fixture_git_helper_has_a_fixed_local_deadline(self):
        completed = subprocess.CompletedProcess(
            ["git"], 0, stdout="fixture-output\n", stderr="",
        )
        with mock.patch.object(subprocess, "run", return_value=completed) as runner:
            self.assertEqual("fixture-output", self.git("status", "--short"))
        self.assertEqual(10.0, runner.call_args.kwargs["timeout"])
        self.assertEqual("/usr/bin/git", runner.call_args.args[0][0])
        self.assertIs(subprocess.DEVNULL, runner.call_args.kwargs["stdin"])
        self.assertEqual(
            {
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_TERMINAL_PROMPT": "0",
                "HOME": self.temporary.name,
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
            },
            runner.call_args.kwargs["env"],
        )
        self.assertEqual(
            [
                "/usr/bin/git",
                "-c", "commit.gpgsign=false",
                "-c", "core.hooksPath=/dev/null",
                "-C", os.fspath(self.repo),
                "status", "--short",
            ],
            runner.call_args.args[0],
        )

    def test_fixture_git_ignores_ambient_configuration_and_pins_executable(self):
        hostile_environment = {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "commit.gpgsign",
            "GIT_CONFIG_VALUE_0": "true",
            "GIT_CONFIG_GLOBAL": os.fspath(self.repo / "hostile-global-config"),
            "GIT_CONFIG_SYSTEM": os.fspath(self.repo / "hostile-system-config"),
        }
        with mock.patch.dict(os.environ, hostile_environment, clear=False):
            tree_id = self.commit_base()
        self.assertRegex(tree_id, r"\A[0-9a-f]{40}\Z")

    def write(self, relative: str, payload: bytes, mode: int = 0o644) -> Path:
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        path.chmod(mode)
        return path

    def commit_base(self) -> str:
        self.write("bin/run.sh", b"#!/bin/sh\nprintf 'tree-only\\n'\n", 0o755)
        self.write("data/value.txt", b"literal-value\n")
        os.symlink("../data/value.txt", self.repo / "bin/value-link")
        self.write(".gitignore", b"ignored.txt\n__pycache__/\n")
        self.git("add", "--all")
        self.git("commit", "-qm", "base")
        return self.git("rev-parse", "--verify", "HEAD^{tree}")

    def export(self, tree_id: str, name: str = "export"):
        destination = Path(self.temporary.name) / name
        manifest = self.guard.export_tree(
            self.repo,
            tree_id,
            destination,
            required_uid=os.geteuid(),
            required_gid=os.getegid(),
        )
        return destination, manifest

    def test_exports_exact_immutable_tree_not_ignored_or_untracked_bytes(self):
        tree_id = self.commit_base()
        self.write("untracked.py", b"raise SystemExit('must not export')\n")
        self.write("ignored.txt", b"ignored-mutable-byte\n")

        destination, manifest = self.export(tree_id)

        self.assertEqual(b"literal-value\n", (destination / "data/value.txt").read_bytes())
        self.assertEqual(0o755, stat.S_IMODE((destination / "bin/run.sh").stat().st_mode))
        self.assertEqual("../data/value.txt", os.readlink(destination / "bin/value-link"))
        self.assertFalse((destination / "untracked.py").exists())
        self.assertFalse((destination / "ignored.txt").exists())
        self.guard.verify_export(
            destination, manifest,
            expected_tree_id=tree_id,
            required_uid=os.geteuid(), required_gid=os.getegid(),
        )
        document = json.loads(manifest)
        self.assertEqual({"entries", "schema_version", "tree_id"}, set(document))
        self.assertEqual(1, document["schema_version"])
        self.assertEqual(tree_id, document["tree_id"])
        expected_paths = {".gitignore", "bin/run.sh", "bin/value-link", "data/value.txt"}
        self.assertEqual(expected_paths, {item["path"] for item in document["entries"]})
        value = next(item for item in document["entries"] if item["path"] == "data/value.txt")
        self.assertEqual(hashlib.sha256(b"literal-value\n").hexdigest(), value["sha256"])

    def test_clean_head_guard_rejects_index_worktree_untracked_and_ignored_drift(self):
        tree_id = self.commit_base()
        (self.repo / "ignored.txt").write_text("allowed outside export\n", encoding="utf-8")
        with self.assertRaises(self.guard.SourceGuardError):
            self.guard.require_clean_head_tree(self.repo, tree_id)
        (self.repo / "ignored.txt").unlink()

        cache = self.repo / "test_cases/__pycache__/test_monitor_authority_entrypoints.cpython-312.pyc"
        cache.parent.mkdir(parents=True)
        cache.write_bytes(b"ignored importable bytecode")
        with self.assertRaises(self.guard.SourceGuardError):
            self.guard.require_clean_head_tree(self.repo, tree_id)
        cache.unlink()
        cache.parent.rmdir()
        cache.parent.parent.rmdir()
        self.guard.require_clean_head_tree(self.repo, tree_id)

        cases = (
            ("tracked", lambda: (self.repo / "data/value.txt").write_text("drift\n")),
            ("untracked", lambda: (self.repo / "new.txt").write_text("new\n")),
            ("index", lambda: (self.write("index.txt", b"index\n"), self.git("add", "index.txt"))),
        )
        for label, mutate in cases:
            with self.subTest(label=label):
                self.git("reset", "--hard", "-q", "HEAD")
                candidate = self.repo / "new.txt"
                if candidate.exists():
                    candidate.unlink()
                candidate = self.repo / "index.txt"
                if candidate.exists():
                    candidate.unlink()
                mutate()
                with self.assertRaises(self.guard.SourceGuardError):
                    self.guard.require_clean_head_tree(self.repo, tree_id)

    def test_tree_parser_rejects_special_modes_duplicate_and_unsafe_path_bytes(self):
        oid = b"1" * 40
        invalid = (
            b"160000 commit " + oid + b"\tsubmodule",
            b"100664 blob " + oid + b"\twrong-mode",
            b"100644 blob " + oid + b"\t/absolute",
            b"100644 blob " + oid + b"\t../escape",
            b"100644 blob " + oid + b"\tcontrol\nname",
            b"100644 blob " + oid + b"\tbad-\xff-name",
        )
        for record in invalid:
            with self.subTest(record=record), self.assertRaises(
                self.guard.SourceGuardError
            ):
                self.guard.parse_ls_tree_record(record)
        entry = self.guard.parse_ls_tree_record(
            b"100644 blob " + oid + b"\tsafe.txt"
        )
        with self.assertRaises(self.guard.SourceGuardError):
            self.guard.validate_entries((entry, entry))

    def test_tree_rejects_dangling_looping_and_outside_symlinks(self):
        for label, links in (
            ("outside", {"link": "../outside"}),
            ("dangling", {"link": "missing"}),
            ("loop", {"one": "two", "two": "one"}),
        ):
            with self.subTest(label=label):
                self.git("reset", "--hard", "-q")
                self.git("clean", "-fdq")
                for stale in ("link", "one", "two"):
                    stale_path = self.repo / stale
                    if os.path.lexists(stale_path):
                        stale_path.unlink()
                for name, target in links.items():
                    os.symlink(target, self.repo / name)
                self.git("add", "--all")
                self.git("commit", "-qm", label)
                tree_id = self.git("rev-parse", "HEAD^{tree}")
                with self.assertRaises(self.guard.SourceGuardError):
                    self.guard.read_tree(self.repo, tree_id)

    def test_destination_walk_rejects_extra_missing_type_mode_content_and_target_drift(self):
        tree_id = self.commit_base()
        mutators = (
            ("extra", lambda root: (root / "extra").write_bytes(b"x")),
            ("missing", lambda root: (root / "data/value.txt").unlink()),
            ("type", lambda root: ((root / "data/value.txt").unlink(), (root / "data/value.txt").mkdir())),
            ("mode", lambda root: (root / "data/value.txt").chmod(0o600)),
            ("content", lambda root: (root / "data/value.txt").write_bytes(b"changed\n")),
            (
                "target",
                lambda root: (
                    (root / "bin/value-link").unlink(),
                    os.symlink("../bin/run.sh", root / "bin/value-link"),
                ),
            ),
        )
        for index, (label, mutate) in enumerate(mutators):
            destination, manifest = self.export(tree_id, f"export-{index}")
            mutate(destination)
            with self.subTest(label=label), self.assertRaises(
                self.guard.SourceGuardError
            ):
                self.guard.verify_export(
                    destination, manifest,
                    expected_tree_id=tree_id,
                    required_uid=os.geteuid(), required_gid=os.getegid(),
                )

    def test_manifest_tree_id_is_cryptographically_bound_to_entries(self):
        tree_id = self.commit_base()
        destination, manifest = self.export(tree_id)
        document = json.loads(manifest)
        document["tree_id"] = "0" * 40
        forged = (
            json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("ascii")
        with self.assertRaises(self.guard.SourceGuardError):
            self.guard.verify_export(
                destination, forged, expected_tree_id=tree_id,
                required_uid=os.geteuid(), required_gid=os.getegid(),
            )

    def test_final_recheck_rejects_late_set_metadata_and_content_races(self):
        tree_id = self.commit_base()
        cases = ("late-extra", "late-root-mode", "late-content")
        for index, label in enumerate(cases):
            destination, manifest = self.export(tree_id, f"race-{index}")
            if label == "late-content":
                original = self.guard._read_regular_at
                fired = False

                def mutate_after_read(root_fd, path, expected_size):
                    nonlocal fired
                    result = original(root_fd, path, expected_size)
                    if not fired and path == "data/value.txt":
                        fired = True
                        (destination / path).write_bytes(b"changed-value\n")
                    return result

                patcher = mock.patch.object(
                    self.guard, "_read_regular_at", side_effect=mutate_after_read,
                )
            else:
                original = self.guard._walk_destination
                fired = False

                def mutate_after_walk(root_fd):
                    nonlocal fired
                    result = original(root_fd)
                    if not fired:
                        fired = True
                        if label == "late-extra":
                            (destination / "late-extra").write_bytes(b"x")
                        else:
                            destination.chmod(0o700)
                    return result

                patcher = mock.patch.object(
                    self.guard, "_walk_destination", side_effect=mutate_after_walk,
                )
            with self.subTest(label=label), patcher, self.assertRaises(
                self.guard.SourceGuardError
            ):
                self.guard.verify_export(
                    destination, manifest, expected_tree_id=tree_id,
                    required_uid=os.geteuid(), required_gid=os.getegid(),
                )

    def test_clean_guard_ignores_neither_assume_unchanged_nor_skip_worktree(self):
        tree_id = self.commit_base()
        path = self.repo / "data/value.txt"
        for flag in ("--assume-unchanged", "--skip-worktree"):
            with self.subTest(flag=flag):
                self.git("reset", "--hard", "-q", "HEAD")
                self.git("update-index", "--no-assume-unchanged", "data/value.txt")
                self.git("update-index", "--no-skip-worktree", "data/value.txt")
                self.git("update-index", flag, "data/value.txt")
                path.write_bytes(b"hidden-drift\n")
                with self.assertRaises(self.guard.SourceGuardError):
                    self.guard.require_clean_head_tree(self.repo, tree_id)

    def test_git_execution_is_absolute_identity_bound_and_ignores_path(self):
        tree_id = self.commit_base()
        fake_root = Path(self.temporary.name) / "fake-bin"
        fake_root.mkdir()
        marker = Path(self.temporary.name) / "fake-git-ran"
        fake_git = fake_root / "git"
        fake_git.write_text(
            f"#!/bin/sh\nprintf ran > {marker}\nexit 91\n", encoding="utf-8",
        )
        fake_git.chmod(0o755)
        with mock.patch.dict(os.environ, {"PATH": os.fspath(fake_root)}):
            self.guard.require_clean_head_tree(self.repo, tree_id)
        self.assertFalse(marker.exists())
        self.assertEqual("/usr/bin/git", self.guard.TRUSTED_GIT_PATH)

    def test_git_execution_has_a_fixed_direct_child_deadline(self):
        tree_id = self.commit_base()
        with mock.patch.object(
            self.guard.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(["git"], 30.0),
        ) as runner, self.assertRaises(self.guard.SourceGuardError):
            self.guard.require_clean_head_tree(self.repo, tree_id)
        self.assertEqual(30.0, runner.call_args.kwargs["timeout"])

    def test_source_directory_identity_is_held_across_all_git_operations(self):
        tree_id = self.commit_base()
        moved = Path(self.temporary.name) / "moved-repo"
        original_status = self.guard._git_status
        fired = False

        def rebind_after_status(repository, arguments):
            nonlocal fired
            self.assertTrue(hasattr(repository, "descriptor"))
            result = original_status(repository, arguments)
            if not fired:
                fired = True
                self.repo.rename(moved)
                self.repo.mkdir()
            return result

        with mock.patch.object(
            self.guard, "_git_status", side_effect=rebind_after_status,
        ), self.assertRaises(self.guard.SourceGuardError):
            self.guard.require_clean_head_tree(self.repo, tree_id)

    def test_source_descriptor_remains_verifiable_after_old_root_detach(self):
        self.commit_base()
        held = self.guard.hold_repository(self.repo)
        self.addCleanup(held.close)
        moved = Path(self.temporary.name) / "detached-old-root"
        self.repo.rename(moved)
        self.repo.mkdir()
        held.verify_descriptor()
        with self.assertRaises(self.guard.SourceGuardError):
            held.verify_binding()

    def test_required_authority_leaf_set_includes_every_real_consumer(self):
        self.assertEqual(
            {
                "test_cases/monitor_authority_source_guard.py",
                "test_cases/monitor_authority_root_warden.py",
                "test_cases/run_monitor_authority_entrypoints.sh",
                "tools/control-auth.py", "monitor/ztp-monitor-control.cgi",
                "infra/infra-setup.sh", "infra/infra-teardown.sh",
                "infra/docker/deploy.sh", "infra/docker/hostlock.py",
                "infra/docker/activate.py", "infra/docker/healthcheck.py",
                "infra/docker/apache-ztp.conf",
            },
            set(self.guard.REQUIRED_AUTHORITY_LEAVES),
        )

    def test_opened_worktree_metadata_and_symlink_identity_are_rechecked(self):
        tree_id = self.commit_base()
        original_open = self.guard.os.open
        fired = False

        def chmod_after_open(path, *args, **kwargs):
            nonlocal fired
            descriptor = original_open(path, *args, **kwargs)
            if not fired and path == "value.txt" and kwargs.get("dir_fd") is not None:
                fired = True
                (self.repo / "data/value.txt").chmod(0o600)
            return descriptor

        with mock.patch.object(
            self.guard.os, "open", side_effect=chmod_after_open,
        ), self.assertRaises(self.guard.SourceGuardError):
            self.guard.require_clean_head_tree(self.repo, tree_id)

        self.git("reset", "--hard", "-q", "HEAD")
        original_readlink = self.guard.os.readlink
        fired = False

        def replace_after_readlink(path, *args, **kwargs):
            nonlocal fired
            target = original_readlink(path, *args, **kwargs)
            if not fired and path == "value-link" and kwargs.get("dir_fd") is not None:
                fired = True
                link = self.repo / "bin/value-link"
                link.unlink()
                os.symlink("../bin/run.sh", link)
            return target

        with mock.patch.object(
            self.guard.os, "readlink", side_effect=replace_after_readlink,
        ), self.assertRaises(self.guard.SourceGuardError):
            self.guard.require_clean_head_tree(self.repo, tree_id)

    def test_held_export_survives_path_rebind_and_detects_post_use_mutation(self):
        tree_id = self.commit_base()
        destination, manifest = self.export(tree_id)
        held = self.guard.hold_export(
            destination, manifest, expected_tree_id=tree_id,
            required_uid=os.geteuid(), required_gid=os.getegid(),
            require_readonly=False,
        )
        self.addCleanup(held.close)
        moved = destination.with_name("held-export")
        destination.rename(moved)
        destination.mkdir()
        held.verify()
        (moved / "data/value.txt").write_bytes(b"post-use-drift\n")
        with self.assertRaises(self.guard.SourceGuardError):
            held.verify()

    def test_authoritative_held_export_can_require_a_readonly_mount(self):
        tree_id = self.commit_base()
        destination, manifest = self.export(tree_id)
        with self.assertRaises(self.guard.SourceGuardError):
            self.guard.hold_export(
                destination, manifest, expected_tree_id=tree_id,
                required_uid=os.geteuid(), required_gid=os.getegid(),
                require_readonly=True,
            )

    def test_component_walk_refuses_a_symlinked_export_parent(self):
        tree_id = self.commit_base()
        outside = Path(self.temporary.name) / "outside"
        outside.mkdir()
        alias = Path(self.temporary.name) / "alias"
        alias.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(self.guard.SourceGuardError):
            self.guard.export_tree(
                self.repo, tree_id, alias / "export",
                required_uid=os.geteuid(), required_gid=os.getegid(),
            )
        self.assertEqual([], list(outside.iterdir()))


if __name__ == "__main__":
    unittest.main()
