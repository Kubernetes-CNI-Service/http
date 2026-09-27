"""Undecorated V3 witnesses for Q01 hostile publication boundaries.

All processes and Git repositories here are private, local and bounded.  These
tests deliberately do not replay the historical published-P test module.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from test_cases import test_public_publication_workflow as publication


class PublicPublicationV3OverlapWorkflowTests(unittest.TestCase):
    def _git(self, repository, *arguments, input_bytes=None):
        result = subprocess.run(
            [publication.GIT_BINARY, "-C", str(repository), *arguments],
            input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={
                **publication._canonical_git_environment(),
                "GIT_AUTHOR_NAME": "Q01 local witness",
                "GIT_AUTHOR_EMAIL": "q01@example.invalid",
                "GIT_COMMITTER_NAME": "Q01 local witness",
                "GIT_COMMITTER_EMAIL": "q01@example.invalid",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_TERMINAL_PROMPT": "0",
            },
            timeout=10, check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        return result.stdout

    def _repository(self, directory):
        repository = Path(directory) / "repository"
        repository.mkdir()
        self._git(repository, "init", "-q")
        (repository / "payload.txt").write_bytes(b"original private payload\n")
        self._git(repository, "add", "--", "payload.txt")
        self._git(repository, "-c", "commit.gpgsign=false", "commit", "-qm", "private witness")
        head = self._git(repository, "rev-parse", "HEAD").decode().strip()
        records = publication._verified_commit_records(repository, head)
        self.assertEqual(b"original private payload\n", records["payload.txt"][3])
        return repository, head, records["payload.txt"][2]

    def test_formal_child_prunes_near_root_and_unowned_fd_and_kills_late_writer(self):
        with tempfile.TemporaryDirectory(prefix="q01-v3-capsule-") as directory:
            base = Path(directory)
            snapshot, repository, near = (base / name for name in ("snapshot", "repository", "stdlib-near"))
            for path in (snapshot, repository, near):
                path.mkdir()
            owned_path, unowned_path = base / "owned", base / "unowned"
            owned_path.write_bytes(b"owned")
            unowned_path.write_bytes(b"unowned")
            owned = os.open(owned_path, os.O_RDONLY)
            unowned = os.open(unowned_path, os.O_RDONLY)
            self.addCleanup(os.close, owned)
            self.addCleanup(os.close, unowned)
            owned_identity = (os.fstat(owned).st_dev, os.fstat(owned).st_ino)
            unowned_identity = (os.fstat(unowned).st_dev, os.fstat(unowned).st_ino)
            environment = {
                **os.environ,
                "Q01_OWNED_FD": str(owned), "Q01_UNOWNED_FD": str(unowned),
                "Q01_NEAR_ROOT": str(near), "PYTHONHOSTILE": "1", "GIT_CONFIG_SYSTEM": str(near),
            }
            probe = (
                "import json,os,sys\n"
                "def identity(fd):\n"
                " try:\n  s=os.fstat(fd); return [s.st_dev,s.st_ino]\n"
                " except OSError:\n  return None\n"
                "print(json.dumps({'path':sys.path,'owned':identity(int(os.environ['Q01_OWNED_FD'])),"
                "'unowned':identity(int(os.environ['Q01_UNOWNED_FD'])),"
                "'pythonhostile':'PYTHONHOSTILE' in os.environ,"
                "'git_system':'GIT_CONFIG_SYSTEM' in os.environ}))\n"
            )

            def child(bootstrap, passed):
                prelude = f"import sys; sys.path.insert(0, {str(near)!r})\n"
                return publication._run_bounded_process(
                    [sys.executable, "-I", "-S", "-B", "-c", prelude + bootstrap,
                     str(snapshot), str(repository), json.dumps(["-c", probe])],
                    cwd=base, environment=environment, pass_fds=passed, timeout=5,
                )

            def assert_isolated(result):
                self.assertEqual(0, result.returncode, result.stderr)
                state = json.loads(result.stdout)
                self.assertEqual(str(snapshot.resolve()), state["path"][0])
                self.assertEqual(str(repository.resolve()), state["path"][1])
                self.assertNotIn(
                    str(near.resolve()), [str(Path(entry).resolve()) for entry in state["path"]],
                )
                self.assertEqual(list(owned_identity), state["owned"])
                self.assertNotEqual(list(unowned_identity), state["unowned"])
                self.assertFalse(state["pythonhostile"])
                self.assertFalse(state["git_system"])

            assert_isolated(child(publication.P_CAPSULE_BOOTSTRAP, (owned,)))
            hostile_bootstrap = publication.P_CAPSULE_BOOTSTRAP.replace(
                "\nsys.path[:] = [str(snapshot), str(repository), *trusted]\n",
                "\nsys.path[:] = [str(snapshot), str(repository), os.environ['Q01_NEAR_ROOT'], *trusted]\n",
                1,
            )
            self.assertNotEqual(publication.P_CAPSULE_BOOTSTRAP, hostile_bootstrap)
            hostile_result = child(hostile_bootstrap, (owned,))
            self.assertEqual(0, hostile_result.returncode, hostile_result.stderr)
            self.assertIn(
                str(near.resolve()),
                [str(Path(entry).resolve()) for entry in json.loads(hostile_result.stdout)["path"]],
            )
            with self.assertRaises(AssertionError):
                assert_isolated(hostile_result)
            with self.assertRaises(AssertionError):
                assert_isolated(child(publication.P_CAPSULE_BOOTSTRAP, (owned, unowned)))

            late = base / "late-marker"
            with self.assertRaises(subprocess.TimeoutExpired):
                publication._run_bounded_process(
                    [sys.executable, "-B", "-c",
                     f"import pathlib,time; time.sleep(.7); pathlib.Path({str(late)!r}).write_text('late')"],
                    cwd=base, environment=os.environ.copy(), pass_fds=(), timeout=.15,
                )
            time.sleep(.8)
            self.assertFalse(late.exists())

    def test_private_pack_to_loose_and_both_alternates_are_rejected(self):
        with tempfile.TemporaryDirectory(prefix="q01-v3-loose-") as directory:
            repository, head, _blob = self._repository(directory)
            self._git(repository, "repack", "-a", "-d")
            pack_directory = repository / ".git/objects/pack"
            packs = sorted(pack_directory.glob("*.pack"))
            self.assertTrue(packs)
            held = Path(directory) / "held-packs"
            pack_directory.rename(held)
            pack_directory.mkdir()
            for packed in packs:
                self._git(repository, "unpack-objects", "-r", input_bytes=(held / packed.name).read_bytes())
            self.assertEqual([], list(pack_directory.iterdir()))
            self.assertEqual(
                b"original private payload\n",
                publication._verified_commit_records(repository, head)["payload.txt"][3],
            )
            info = repository / ".git/objects/info"
            real_lexists = os.path.lexists
            for name in ("alternates", "http-alternates"):
                marker = info / name
                marker.write_text(str(held), encoding="utf-8")
                with self.assertRaisesRegex(AssertionError, "alternate"):
                    publication._verified_commit_records(repository, head)
                with mock.patch.object(
                    publication.os.path, "lexists",
                    side_effect=lambda path: False if str(path) == str(marker) else real_lexists(path),
                ):
                    with self.assertRaises(AssertionError):
                        with self.assertRaisesRegex(AssertionError, "alternate"):
                            publication._verified_commit_records(repository, head)
                marker.unlink()

    def test_postverification_loose_object_swap_is_rechecked_without_ledger_fallback(self):
        with tempfile.TemporaryDirectory(prefix="q01-v3-race-") as directory:
            repository, head, blob_id = self._repository(directory)
            before = publication._read_raw_git_object(repository, blob_id, "blob")
            publication._write_loose_object_fixture(repository, blob_id, "blob", b"hostile replacement\n")
            real_reader = publication._read_raw_git_object
            real_git = publication._git_run
            rereads, forbidden = [], []

            def observe(repo, object_id, kind):
                if object_id == blob_id:
                    rereads.append((object_id, kind))
                return real_reader(repo, object_id, kind)

            def reject_ledger_fallback(repo, args, *positional, **keywords):
                if tuple(args[:1]) == ("show",):
                    forbidden.append(tuple(args))
                    raise AssertionError("ledger fallback attempted")
                return real_git(repo, args, *positional, **keywords)

            with mock.patch.object(publication, "_read_raw_git_object", side_effect=observe), mock.patch.object(
                publication, "_git_run", side_effect=reject_ledger_fallback,
            ), self.assertRaisesRegex(AssertionError, "object id"):
                publication._verified_commit_records(repository, head)
            self.assertEqual([(blob_id, "blob")], rereads)
            self.assertEqual([], forbidden)

            def stale_reader(repo, object_id, kind):
                if object_id == blob_id:
                    return before
                return real_reader(repo, object_id, kind)

            with mock.patch.object(publication, "_read_raw_git_object", side_effect=stale_reader):
                with self.assertRaises(AssertionError):
                    with self.assertRaisesRegex(AssertionError, "object id"):
                        publication._verified_commit_records(repository, head)

    def test_corrupt_commit_rejected_before_any_runner(self):
        with tempfile.TemporaryDirectory(prefix="q01-v3-commit-") as directory:
            repository, head, _blob = self._repository(directory)
            original = publication._read_raw_git_object(repository, head, "commit")
            publication._write_loose_object_fixture(repository, head, "commit", b"hostile commit\n")
            runner_calls = []

            def runner(*args, **kwargs):
                runner_calls.append((args, kwargs))
                return None

            def verify_then_run():
                publication._verified_commit_records(repository, head)
                publication._python_run(repository, ["-B", "test_cases/run_related_tests.py", "--all"])

            with mock.patch.object(publication, "_python_run", side_effect=runner), self.assertRaisesRegex(
                AssertionError, "object id",
            ):
                verify_then_run()
            self.assertEqual([], runner_calls)

            real_reader = publication._read_raw_git_object

            def stale_commit(repo, object_id, kind):
                if object_id == head:
                    return original
                return real_reader(repo, object_id, kind)

            with mock.patch.object(publication, "_read_raw_git_object", side_effect=stale_commit), mock.patch.object(
                publication, "_python_run", side_effect=runner,
            ):
                with self.assertRaises(AssertionError):
                    with self.assertRaisesRegex(AssertionError, "object id"):
                        verify_then_run()
            self.assertEqual(1, len(runner_calls))
