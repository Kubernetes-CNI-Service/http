#!/usr/bin/env python3
"""Independent contracts for immutable Monitor root-workflow source export."""

from __future__ import annotations

import contextlib
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

    def _commit_batch_corpus(self):
        expected = {
            "objects/%02d" % i: (b"payload/%02d\x00\n" % i, "100644")
            for i in range(65)
        }
        expected.update({
            "duplicate": (b"payload/00\x00\n", "100644"),
            "empty": (b"", "100644"),
            "script": (b"#!/bin/sh\nexit 0\n", "100755"),
            "link": (b"objects/00", "120000"),
        })
        for name, (payload, mode) in expected.items():
            if mode == "120000":
                os.symlink(payload.decode("ascii"), self.repo / name)
            else:
                self.write(name, payload, 0o755 if mode == "100755" else 0o644)
        self.git("add", "--all")
        self.git("commit", "-qm", "independent binary batch corpus")
        return self.git("rev-parse", "HEAD^{tree}"), expected

    def test_immutable_tree_uses_bounded_unique_object_batches_without_leaf_children(self):
        tree_id, expected = self._commit_batch_corpus()
        calls = []
        original = self.guard._run_git

        def observe(repository, arguments, **kwargs):
            calls.append((tuple(arguments), kwargs.get("input_bytes")))
            return original(repository, arguments, **kwargs)

        with mock.patch.object(self.guard, "_run_git", side_effect=observe):
            actual = self.guard.read_tree(self.repo, tree_id)
        self.assertEqual(
            expected, {entry.path: (entry.payload, entry.git_mode) for entry in actual},
        )
        self.assertEqual(69, len(actual))
        expected_ids = list(dict.fromkeys(
            hashlib.sha1(b"blob " + str(len(payload)).encode("ascii") + b"\x00" + payload).hexdigest()
            for name, (payload, _mode) in sorted(expected.items())
        ))
        self.assertEqual(68, len(expected_ids))
        self.assertEqual(("ls-tree", "-rz", "--full-tree", "--full-name", tree_id), calls[0][0])
        batches = calls[1:]
        self.assertEqual(3, len(batches))
        self.assertEqual([32, 32, 4], [len(data.splitlines()) for _args, data in batches])
        self.assertTrue(all(args == ("cat-file", "--batch") for args, _data in batches))
        self.assertEqual(
            expected_ids, [line.decode("ascii") for _args, data in batches for line in data.splitlines()],
        )
        self.assertTrue(all(data.endswith(b"\n") for _args, data in batches))

    def test_batch_decoder_preserves_literal_empty_binary_and_sha256_objects(self):
        for algorithm in (hashlib.sha1, hashlib.sha256):
            payloads = (b"", b"literal\x00\npayload\n", b"\xff\x00binary")
            pairs = [
                (algorithm(b"blob " + str(len(payload)).encode("ascii") + b"\x00" + payload).hexdigest(), payload)
                for payload in payloads
            ]
            raw = b"".join(
                oid.encode("ascii") + b" blob " + str(len(payload)).encode("ascii") + b"\n" + payload + b"\n"
                for oid, payload in pairs
            )
            self.assertEqual(dict(pairs), self.guard._decode_blob_batch(raw, [oid for oid, _payload in pairs]))

    def test_batch_decoder_rejects_unrequested_noncanonical_corrupt_or_incomplete_frames(self):
        payload = b"literal\x00\npayload\n"
        oid = hashlib.sha1(b"blob " + str(len(payload)).encode("ascii") + b"\x00" + payload).hexdigest()
        prefix = oid.encode("ascii") + b" blob "
        frame = prefix + str(len(payload)).encode("ascii") + b"\n" + payload + b"\n"
        mutations = (
            b"", frame[:-1], frame[:-2], frame + b"\n", frame + frame,
            oid.encode("ascii") + b" missing\n", frame.replace(b" blob ", b" tree ", 1),
            frame.replace(oid.encode("ascii"), b"f" * 40, 1),
            prefix + b"0" + str(len(payload)).encode("ascii") + b"\n" + payload + b"\n",
            prefix + b"+17\n" + payload + b"\n", prefix + b"-1\n" + payload + b"\n",
            prefix + b" 17\n" + payload + b"\n", prefix + b"999999999999999999999999\n",
            frame.replace(b"literal", b"Literal"),
            prefix + b"7" * 128 + b"\n", frame[:-1] + b"\x00",
        )
        for raw in mutations:
            with self.subTest(raw=raw[:100]), self.assertRaises(self.guard.SourceGuardError):
                self.guard._decode_blob_batch(raw, (oid,))
        with self.assertRaises(self.guard.SourceGuardError):
            self.guard._decode_blob_batch(frame + frame, (oid, oid))
        with self.assertRaises(self.guard.SourceGuardError):
            self.guard._decode_blob_batch(b"", ())

    def test_blob_batch_transport_preserves_original_execution_guards(self):
        self.commit_base()
        oid = hashlib.sha1(b"blob 4\x00data").hexdigest()
        request = oid.encode("ascii") + b"\n"
        output = oid.encode("ascii") + b" blob 4\ndata\n"
        completed = subprocess.CompletedProcess(["git"], 0, stdout=output, stderr=b"")
        with contextlib.closing(self.guard.hold_repository(self.repo)) as held:
            with mock.patch.object(self.guard.subprocess, "run", return_value=completed) as runner:
                self.assertEqual((0, output, b""), self.guard._run_git(
                    held, ("cat-file", "--batch"), input_bytes=request))
            options = runner.call_args.kwargs
            self.assertEqual(request, options["input"])
            self.assertNotIn("stdin", options, "do not supply stdin and input together")
            self.assertEqual(30.0, options["timeout"])
            self.assertTrue(options["close_fds"])
            self.assertEqual(2, len(options["pass_fds"]))
            self.assertEqual(held.descriptor, options["pass_fds"][0])
            self.assertEqual({
                "HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin",
                "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_NO_REPLACE_OBJECTS": "1", "GIT_TERMINAL_PROMPT": "0",
            }, options["env"])
            self.assertEqual(["cat-file", "--batch"], runner.call_args.args[0][-2:])
            self.assertEqual(
                "/usr/bin/git" if not sys.platform.startswith("linux") else
                "/proc/self/fd/" + str(options["pass_fds"][1]),
                runner.call_args.args[0][0],
            )

    def test_blob_batch_transport_rejects_open_or_unbounded_stdin_before_child(self):
        self.commit_base()
        oid = hashlib.sha1(b"blob 4\x00data").hexdigest().encode("ascii")
        mutations = [
            b"", oid, b"\n", oid + b"\n\n", oid + b"\r\n",
            oid.upper() + b"\n", oid[:-1] + b"\n", b"g" * 40 + b"\n",
            oid + b"\x00\n", b" ".join([oid, oid]) + b"\n",
            oid + b"\n" + oid + b"\n", bytearray(oid + b"\n"), "not-binary",
            b"".join(hashlib.sha1(("blob 0\x00" + str(i)).encode()).hexdigest().encode() + b"\n"
                     for i in range(33)),
        ]
        with contextlib.closing(self.guard.hold_repository(self.repo)) as held:
            for request in mutations:
                with self.subTest(request=repr(request)[:100]), \
                        mock.patch.object(self.guard.subprocess, "run") as runner:
                    with self.assertRaises(self.guard.SourceGuardError):
                        self.guard._run_git(held, ("cat-file", "--batch"), input_bytes=request)
                    runner.assert_not_called()
            with mock.patch.object(self.guard.subprocess, "run") as runner:
                with self.assertRaises(self.guard.SourceGuardError):
                    self.guard._run_git(held, ("cat-file", "blob", oid.decode()),
                                        input_bytes=oid + b"\n")
                runner.assert_not_called()

    def test_blob_batch_rejects_private_repository_rebind_before_export(self):
        tree_id = self.commit_base()
        real_run = self.guard.subprocess.run
        moved = Path(self.temporary.name) / "rebound-original-repo"
        destination = Path(self.temporary.name) / "must-not-export"
        fired = []
        def rebind(command, **kwargs):
            completed = real_run(command, **kwargs)
            if command[-2:] == ["cat-file", "--batch"]:
                fired.append(True)
                self.repo.rename(moved)
                self.repo.mkdir()
            return completed
        with mock.patch.object(self.guard.subprocess, "run", side_effect=rebind):
            with self.assertRaisesRegex(self.guard.SourceGuardError, "source directory identity was rebound"):
                self.guard.export_tree(self.repo, tree_id, destination,
                                       required_uid=os.geteuid(), required_gid=os.getegid())
        self.assertEqual([True], fired)
        self.assertFalse(os.path.lexists(destination))
        self.assertEqual(b"literal-value\n", (moved / "data/value.txt").read_bytes())

    def test_corrupt_later_blob_chunk_prevents_any_destination_creation(self):
        tree_id, expected = self._commit_batch_corpus()
        original = self.guard._run_git
        destination = Path(self.temporary.name) / "no-partial-export"
        batches = []
        def corrupt(repository, arguments, **kwargs):
            code, stdout, stderr = original(repository, arguments, **kwargs)
            if tuple(arguments) == ("cat-file", "--batch"):
                batches.append(kwargs["input_bytes"])
                if len(batches) == 2:
                    stdout = stdout[:-1]
            return code, stdout, stderr
        with mock.patch.object(self.guard, "_run_git", side_effect=corrupt):
            with self.assertRaises(self.guard.SourceGuardError):
                self.guard.export_tree(self.repo, tree_id, destination,
                                       required_uid=os.geteuid(), required_gid=os.getegid())
        self.assertEqual(2, len(batches))
        self.assertFalse(os.path.lexists(destination))
        for name, (payload, mode) in expected.items():
            observed = os.fsencode(os.readlink(self.repo / name)) if mode == "120000" else (self.repo / name).read_bytes()
            self.assertEqual(payload, observed)

    def test_blob_batch_executable_rebind_is_detected_after_child_before_export(self):
        self.commit_base()
        trusted = Path(self.temporary.name) / "private-trusted-exec"
        trusted.write_bytes(b"private executable identity fixture\n")
        trusted.chmod(0o755)
        original_stat = self.guard._metadata_fingerprint(trusted.stat())
        oid = hashlib.sha1(b"blob 4\x00data").hexdigest()
        def opened():
            descriptor = os.open(trusted, os.O_RDONLY | os.O_NOFOLLOW)
            return descriptor, self.guard._metadata_fingerprint(os.fstat(descriptor))
        def replace_after_child(command, **kwargs):
            replacement = trusted.with_name("replacement-exec")
            replacement.write_bytes(b"private executable identity fixture\n")
            replacement.chmod(0o755)
            replacement.replace(trusted)
            return subprocess.CompletedProcess(command, 0, stdout=oid.encode() + b" blob 4\ndata\n", stderr=b"")
        with contextlib.closing(self.guard.hold_repository(self.repo)) as held:
            with mock.patch.object(self.guard, "TRUSTED_GIT_PATH", str(trusted)), \
                    mock.patch.object(self.guard, "_open_trusted_git", side_effect=opened), \
                    mock.patch.object(self.guard.subprocess, "run", side_effect=replace_after_child):
                with self.assertRaisesRegex(self.guard.SourceGuardError, "trusted absolute Git executable identity changed"):
                    self.guard._run_git(held, ("cat-file", "--batch"),
                                        input_bytes=oid.encode() + b"\n")
        self.assertNotEqual(original_stat, self.guard._metadata_fingerprint(trusted.stat()))

    def test_blob_batch_has_the_original_fixed_child_deadline(self):
        self.commit_base()
        oid = hashlib.sha1(b"blob 4\x00data").hexdigest()
        with contextlib.closing(self.guard.hold_repository(self.repo)) as held:
            with mock.patch.object(self.guard.subprocess, "run",
                    side_effect=subprocess.TimeoutExpired(["git"], 30.0)) as runner:
                with self.assertRaisesRegex(self.guard.SourceGuardError, "fixed deadline"):
                    self.guard._run_git(held, ("cat-file", "--batch"),
                                        input_bytes=oid.encode() + b"\n")
            self.assertEqual(30.0, runner.call_args.kwargs["timeout"])
            self.assertEqual(oid.encode() + b"\n", runner.call_args.kwargs["input"])

    def test_empty_immutable_tree_requires_no_blob_subprocess(self):
        self.git("commit", "--allow-empty", "-qm", "independent empty tree")
        tree_id = self.git("rev-parse", "HEAD^{tree}")
        original = self.guard._run_git
        calls = []

        def observe(repository, arguments, **kwargs):
            calls.append((tuple(arguments), kwargs))
            return original(repository, arguments, **kwargs)

        with mock.patch.object(self.guard, "_run_git", side_effect=observe):
            self.assertEqual((), self.guard.read_tree(self.repo, tree_id))
        self.assertEqual(
            [(("ls-tree", "-rz", "--full-tree", "--full-name", tree_id), {})],
            calls,
        )

    def test_batch_decoder_rejects_two_valid_objects_in_wrong_order(self):
        payloads = (b"independent-first\x00", b"independent-second\n")
        pairs = [
            (hashlib.sha1(b"blob " + str(len(payload)).encode("ascii") + b"\x00" + payload).hexdigest(), payload)
            for payload in payloads
        ]
        raw = b"".join(
            oid.encode("ascii") + b" blob " + str(len(payload)).encode("ascii") + b"\n" + payload + b"\n"
            for oid, payload in reversed(pairs)
        )
        with self.assertRaises(self.guard.SourceGuardError):
            self.guard._decode_blob_batch(raw, [oid for oid, _payload in pairs])

    def test_blob_batch_rechecks_source_binding_before_next_child(self):
        tree_id, expected = self._commit_batch_corpus()
        original_git = self.guard._run_git
        original_run = self.guard.subprocess.run
        destination = Path(self.temporary.name) / "forbidden-between-batches-export"
        moved = Path(self.temporary.name) / "held-original-between-batches"
        batches = []
        children = []

        def observe_child(command, **kwargs):
            if command[-2:] == ["cat-file", "--batch"]:
                children.append(tuple(command))
            return original_run(command, **kwargs)

        def replace_between(repository, arguments, **kwargs):
            result = original_git(repository, arguments, **kwargs)
            if tuple(arguments) == ("cat-file", "--batch"):
                batches.append(kwargs["input_bytes"])
                if len(batches) == 1:
                    self.repo.rename(moved)
                    self.repo.mkdir()
                    (self.repo / "foreign-marker").write_bytes(b"foreign namespace retained\n")
            return result

        with mock.patch.object(self.guard.subprocess, "run", side_effect=observe_child), \
                mock.patch.object(self.guard, "_run_git", side_effect=replace_between):
            with self.assertRaisesRegex(self.guard.SourceGuardError, "source directory identity was rebound"):
                self.guard.export_tree(
                    self.repo, tree_id, destination,
                    required_uid=os.geteuid(), required_gid=os.getegid(),
                )
        self.assertEqual(1, len(batches), "do not consume a second batch after a rebind")
        self.assertEqual(1, len(children), "pre-child identity guard must stop the second Git child")
        self.assertFalse(os.path.lexists(destination))
        self.assertEqual(b"foreign namespace retained\n", (self.repo / "foreign-marker").read_bytes())
        for name, (payload, mode) in expected.items():
            path = moved / name
            observed = os.fsencode(os.readlink(path)) if mode == "120000" else path.read_bytes()
            self.assertEqual(payload, observed)

    def test_real_sha256_repository_preserves_all_paths_and_batch_identity(self):
        self.repo = Path(self.temporary.name) / "sha256-repository"
        self.repo.mkdir()
        self.git("init", "-q", "--object-format=sha256")
        self.git("config", "user.email", "sha256-batch@example.invalid")
        self.git("config", "user.name", "Independent SHA256 Batch")
        tree, expected = self._commit_batch_corpus()
        self.assertEqual(64, len(tree))
        original = self.guard._run_git
        batches = []

        def observe(repository, arguments, **kwargs):
            if tuple(arguments) == ("cat-file", "--batch"):
                batches.append(kwargs["input_bytes"])
            return original(repository, arguments, **kwargs)

        with mock.patch.object(self.guard, "_run_git", side_effect=observe):
            entries = self.guard.read_tree(self.repo, tree)
        self.assertEqual(expected, {
            entry.path: (entry.payload, entry.git_mode) for entry in entries
        })
        expected_ids = list(dict.fromkeys(
            hashlib.sha256(b"blob " + str(len(payload)).encode("ascii") + b"\x00" + payload).hexdigest()
            for _name, (payload, _mode) in sorted(expected.items())
        ))
        self.assertEqual([32, 32, 4], [len(batch.splitlines()) for batch in batches])
        self.assertEqual(expected_ids, [
            line.decode("ascii") for batch in batches for line in batch.splitlines()
        ])
        self.assertTrue(all(len(entry.blob_id) == 64 for entry in entries))

    def test_failed_blob_child_never_creates_destination_even_with_valid_stdout(self):
        tree = self.commit_base()
        destination = Path(self.temporary.name) / "failed-child-no-export"
        original = self.guard._run_git

        def failed(repository, arguments, **kwargs):
            code, output, errors = original(repository, arguments, **kwargs)
            if tuple(arguments) == ("cat-file", "--batch"):
                return 73, output, b"independent child failure\n"
            return code, output, errors

        with mock.patch.object(self.guard, "_run_git", side_effect=failed):
            with self.assertRaisesRegex(self.guard.SourceGuardError, "independent child failure"):
                self.guard.export_tree(self.repo, tree, destination,
                    required_uid=os.geteuid(), required_gid=os.getegid())
        self.assertFalse(os.path.lexists(destination))
        self.assertEqual(b"literal-value\n", (self.repo / "data/value.txt").read_bytes())

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
                "infra/infra-setup.py", "infra/ubuntu24_host.py", "infra/infra-teardown.sh",
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
