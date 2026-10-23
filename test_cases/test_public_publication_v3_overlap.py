"""Undecorated V3 witnesses for Q01 hostile publication boundaries.

All processes and Git repositories here are private, local and bounded.  These
tests deliberately do not replay the historical published-P test module.
"""

import hashlib
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

    # ---- C09: bounded, closed-stdin batch reads behind the unchanged single-object primitive ----
    def _literal_tree_repository(self, directory):
        repository = Path(directory) / "repository"
        repository.mkdir()
        self._git(repository, "init", "-q")
        expected = {"a.txt": b"alpha\n"}
        expected.update({f"bulk/f{i:02d}": f"bulk {i}\n".encode() for i in range(40)})
        expected.update({f"zz/c{i}": f"zz {i}\n".encode() for i in range(3)})
        for relative, payload in expected.items():
            path = repository / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        self._git(repository, "add", "-A")
        self._git(repository, "-c", "commit.gpgsign=false", "commit", "-qm", "literal batch witness")
        head = self._git(repository, "rev-parse", "HEAD").decode().strip()
        records = {
            relative: ("100644", "blob", hashlib.sha1(b"blob %d\0" % len(payload) + payload).hexdigest(), payload)
            for relative, payload in expected.items()
        }
        return repository, head, records

    def _observed_cat_file_runs(self):
        real_run = subprocess.run
        runs = []

        def observe(*args, **kwargs):
            argv = tuple(os.fspath(value) for value in (args[0] if args else kwargs["args"]))
            if argv[-2:] == ("cat-file", "--batch"):
                runs.append({"argv": argv, "input": kwargs.get("input"), "timeout": kwargs.get("timeout"),
                             "env": kwargs.get("env"), "text": kwargs.get("text"), "check": kwargs.get("check")})
            return real_run(*args, **kwargs)

        return runs, observe

    def test_verified_walk_reads_objects_in_bounded_closed_batches(self):
        with tempfile.TemporaryDirectory(prefix="q01-v3-batch-") as directory:
            repository, head, expected = self._literal_tree_repository(directory)
            runs, observe = self._observed_cat_file_runs()
            with mock.patch.object(subprocess, "run", side_effect=observe):
                self.assertEqual(expected, publication._verified_commit_records(repository, head))
            # Literal shape: commit, root tree, 3 root entries, then 43 grandchildren.
            # serve planning: commit, root, [a.txt bulk zz], bulk 32, bulk 8, zz 3
            self.assertLessEqual(len(runs), 6)
            single_argv = (publication.GIT_BINARY, "--no-replace-objects", "-c",
                           f"core.hooksPath={os.devnull}", "-C", str(repository), "cat-file", "--batch")
            for run in runs:
                self.assertEqual(single_argv, run["argv"])
                lines = run["input"].split(b"\n")
                self.assertEqual(b"", lines[-1])
                self.assertTrue(1 <= len(lines) - 1 <= 32)
                self.assertEqual(publication.RAW_OBJECT_TIMEOUT_SECONDS, run["timeout"])
                self.assertIs(False, run["text"])
                self.assertIs(False, run["check"])
                self.assertEqual(publication.SYSTEM_EXECUTABLE_PATH, run["env"]["PATH"])
                self.assertEqual([], [key for key in run["env"] if key.startswith(("LD_", "DYLD_"))])
                self.assertEqual(
                    {"GIT_CONFIG": os.devnull, "GIT_CONFIG_GLOBAL": os.devnull,
                     "GIT_CONFIG_NOSYSTEM": "1", "GIT_NO_REPLACE_OBJECTS": "1"},
                    {key: value for key, value in run["env"].items() if key.startswith("GIT_")},
                )
            self.assertTrue(any(len(run["input"].split(b"\n")) - 1 > 1 for run in runs))

    def test_failed_batch_only_falls_back_to_original_single_reads(self):
        with tempfile.TemporaryDirectory(prefix="q01-v3-batch-fallback-") as directory:
            repository, head, expected = self._literal_tree_repository(directory)
            real_run = subprocess.run
            multi, single = [], []

            def fail_batches(*args, **kwargs):
                payload = kwargs.get("input") or b""
                if payload.count(b"\n") > 1:
                    multi.append(payload)
                    raise subprocess.TimeoutExpired("git cat-file --batch", kwargs.get("timeout"))
                if payload:
                    single.append((payload, kwargs.get("timeout")))
                return real_run(*args, **kwargs)

            with mock.patch.object(subprocess, "run", side_effect=fail_batches):
                self.assertEqual(expected, publication._verified_commit_records(repository, head))
            self.assertTrue(multi)
            self.assertEqual(48, len(single))  # 1 commit + 1 root + 3 entries + 43 grandchildren
            self.assertTrue(all(timeout == 1 for _payload, timeout in single))

    def test_prefetch_scope_is_call_local(self):
        with tempfile.TemporaryDirectory(prefix="q01-v3-batch-scope-") as directory:
            repository, head, expected = self._literal_tree_repository(directory)
            self.assertEqual(expected, publication._verified_commit_records(repository, head))
            publication._write_loose_object_fixture(
                repository, expected["bulk/f07"][2], "blob", b"hostile replacement\n",
            )
            with self.assertRaisesRegex(AssertionError, "object id"):
                publication._verified_commit_records(repository, head)
            self.assertIsNone(publication._C09_SCOPE.get())
            oid = expected["a.txt"][2]
            run = mock.Mock(return_value=subprocess.CompletedProcess((), 0, b"%s blob 6\nalpha\n\n" % oid.encode(), b""))
            with mock.patch.object(subprocess, "run", run):
                publication._read_raw_git_object(repository, oid, "blob")
            self.assertEqual(1, run.call_count)
            self.assertEqual((oid + "\n").encode(), run.call_args.kwargs["input"])

    def test_first_parent_chain_prefetch_hint_cannot_change_the_raw_chain(self):
        with tempfile.TemporaryDirectory(prefix="q01-v3-chain-") as directory:
            repository = Path(directory) / "repository"
            repository.mkdir()
            self._git(repository, "init", "-q")
            commits = []
            for index in range(42):
                (repository / "n.txt").write_bytes(f"{index}\n".encode())
                self._git(repository, "add", "-A")
                self._git(repository, "-c", "commit.gpgsign=false", "commit", "-qm", f"c{index}")
                commits.append(self._git(repository, "rev-parse", "HEAD").decode().strip())
            literal_chain = tuple(reversed(commits[2:]))
            runs, observe = self._observed_cat_file_runs()
            with mock.patch.object(publication, "S_COMMIT", commits[0]), mock.patch.object(
                subprocess, "run", side_effect=observe,
            ):
                self.assertEqual(
                    literal_chain,
                    publication._raw_v3_first_parent_chain(repository, commits[-1], commits[1]),
                )
            self.assertLessEqual(len(runs), 2)  # 40 raw commit reads in ceil(40/32) closed batches
            def lying(repo, head):
                return tuple(commits[::3] + ["f" * 40] + commits[1::3])

            with mock.patch.object(publication, "S_COMMIT", commits[0]), mock.patch.object(
                publication, "_c09_first_parent_hint", side_effect=lying,
            ):
                self.assertEqual(
                    literal_chain,
                    publication._raw_v3_first_parent_chain(repository, commits[-1], commits[1]),
                )
            with mock.patch.object(publication, "S_COMMIT", commits[0]), mock.patch.object(
                publication, "P_V3_FIRST_PARENT_LIMIT", 8,
            ), self.assertRaisesRegex(AssertionError, "exceeds the reviewed bound"):
                publication._raw_v3_first_parent_chain(repository, commits[-1], commits[1])

    def test_single_object_primitive_outside_a_walk_is_one_closed_run(self):
        with tempfile.TemporaryDirectory(prefix="q01-v3-primitive-") as directory:
            repository, _head, expected = self._literal_tree_repository(directory)
            oid = expected["a.txt"][2]
            run = mock.Mock(return_value=subprocess.CompletedProcess((), 0, b"%s blob 6\nalpha\n\n" % oid.encode(), b""))
            with mock.patch.object(subprocess, "run", run), mock.patch.object(
                subprocess, "Popen", side_effect=AssertionError("persistent/split object read forbidden"),
            ):
                self.assertEqual((oid, "blob", 6, b"alpha\n"),
                                 publication._read_raw_git_object(repository, oid, "blob"))
            self.assertEqual(1, run.call_count)
            self.assertEqual((oid + "\n").encode(), run.call_args.kwargs["input"])
            self.assertEqual(1, run.call_args.kwargs["timeout"])

    def test_real_v3_authority_reads_every_object_through_the_primitive_in_few_children(self):
        requests = []
        primitive = publication._read_raw_git_object

        def counted(repository, object_id, kind):
            requests.append((object_id, kind))
            return primitive(repository, object_id, kind)

        runs, observe = self._observed_cat_file_runs()
        with mock.patch.object(publication, "_read_raw_git_object", side_effect=counted), mock.patch.object(
            subprocess, "run", side_effect=observe,
        ):
            publication._assert_v3_child_authority(publication.ROOT)
        self.assertGreater(len(requests), 1000)
        self.assertLessEqual(len(runs) * 4, len(requests))

    def test_malformed_batch_outputs_fall_back_to_identical_single_results(self):
        corpus = {
            "rc1": lambda real: subprocess.CompletedProcess((), 1, real.stdout, b""),
            "rc-9": lambda real: subprocess.CompletedProcess((), -9, real.stdout, b""),
            "stderr-on-success": lambda real: subprocess.CompletedProcess((), 0, real.stdout, b"warning\n"),
            "truncated": lambda real: subprocess.CompletedProcess((), 0, real.stdout[:-7], b""),
            "trailing": lambda real: subprocess.CompletedProcess((), 0, real.stdout + b"x", b""),
            "bad-size": lambda real: subprocess.CompletedProcess((), 0, real.stdout.replace(b" blob ", b" blob 0", 1), b""),
            "kind-swap": lambda real: subprocess.CompletedProcess((), 0, real.stdout.replace(b" blob ", b" tree ", 1), b""),
            "missing": lambda real: subprocess.CompletedProcess((), 0, real.stdout.split(b"\n", 1)[0].split(b" ")[0] + b" missing\n", b""),
            "empty": lambda real: subprocess.CompletedProcess((), 0, b"", b""),
        }
        raising = {
            "oserror": OSError("injected"),
            "timeout": subprocess.TimeoutExpired("git cat-file --batch", 1),
        }
        with tempfile.TemporaryDirectory(prefix="q01-v3-batch-malformed-") as directory:
            repository, head, expected = self._literal_tree_repository(directory)
            real_run = subprocess.run
            for name in [*corpus, *raising]:
                with self.subTest(name=name):
                    singles = []

                    def tamper(*args, **kwargs):
                        payload = kwargs.get("input") or b""
                        if payload.count(b"\n") > 1:
                            if name in raising:
                                raise raising[name]
                            return corpus[name](real_run(*args, **kwargs))
                        if payload:
                            singles.append(payload)
                        return real_run(*args, **kwargs)

                    with mock.patch.object(subprocess, "run", side_effect=tamper):
                        self.assertEqual(expected, publication._verified_commit_records(repository, head))
                    self.assertTrue(singles)
                    self.assertIsNone(publication._C09_SCOPE.get())

    def test_fifo_commit_in_first_parent_chain_stays_bounded(self):
        with tempfile.TemporaryDirectory(prefix="q01-v3-chain-fifo-") as directory:
            repository = Path(directory) / "repository"
            repository.mkdir()
            self._git(repository, "init", "-q")
            commits = []
            for index in range(10):
                (repository / "n.txt").write_bytes(f"{index}\n".encode())
                self._git(repository, "add", "-A")
                self._git(repository, "-c", "commit.gpgsign=false", "commit", "-qm", f"c{index}")
                commits.append(self._git(repository, "rev-parse", "HEAD").decode().strip())
            fifo_commit = commits[5]
            loose = repository / ".git/objects" / fifo_commit[:2] / fifo_commit[2:]
            loose.chmod(0o600)
            loose.unlink()
            os.mkfifo(loose)
            child = (
                "import sys\n"
                f"sys.path.insert(0, {str(publication.ROOT)!r})\n"
                "from pathlib import Path\n"
                "from test_cases import test_public_publication_workflow as publication\n"
                f"publication.S_COMMIT = {commits[0]!r}\n"
                "try:\n"
                f"    publication._raw_v3_first_parent_chain(Path({str(repository)!r}), {commits[-1]!r}, {commits[1]!r})\n"
                "except AssertionError as error:\n"
                "    print('REJECTED', error)\n"
                "else:\n"
                "    print('ACCEPTED')\n"
            )
            started = time.monotonic()
            result = subprocess.run(
                [sys.executable, "-B", "-c", child], cwd=publication.ROOT,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30,
            )
            elapsed = time.monotonic() - started
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("REJECTED P raw object authority read failed\n", result.stdout)
            self.assertLess(elapsed, 20.0)

    def test_first_failed_batch_disables_prefetch_for_the_rest_of_the_walk(self):
        with tempfile.TemporaryDirectory(prefix="q01-v3-batch-first-failure-") as directory:
            repository, head, expected = self._literal_tree_repository(directory)
            real_run = subprocess.run
            multi, single = [], []

            def fail_first_batch(*args, **kwargs):
                payload = kwargs.get("input") or b""
                if payload.count(b"\n") > 1:
                    multi.append(payload)
                    if len(multi) == 1:
                        raise subprocess.TimeoutExpired("git cat-file --batch", kwargs.get("timeout"))
                elif payload:
                    single.append(payload)
                return real_run(*args, **kwargs)

            with mock.patch.object(subprocess, "run", side_effect=fail_first_batch):
                self.assertEqual(expected, publication._verified_commit_records(repository, head))
            # commit + root tree are one-key reads; the first multi-key batch [a.txt, bulk, zz]
            # fails, so the remaining 46 objects are read one by one: 48 single reads in total.
            self.assertEqual(1, len(multi))
            self.assertEqual(48, len(single))
            self.assertIsNone(publication._C09_SCOPE.get())

    def test_one_object_children_come_only_from_the_unchanged_single_reader(self):
        with tempfile.TemporaryDirectory(prefix="q01-v3-batch-single-path-") as directory:
            repository, head, expected = self._literal_tree_repository(directory)
            runs, observe = self._observed_cat_file_runs()
            single_reader = publication._read_raw_git_object_single
            single_calls = []

            def counted_single(repo, object_id, kind):
                single_calls.append((object_id, kind))
                return single_reader(repo, object_id, kind)

            with mock.patch.object(subprocess, "run", side_effect=observe), mock.patch.object(
                publication, "_read_raw_git_object_single", side_effect=counted_single,
            ):
                self.assertEqual(expected, publication._verified_commit_records(repository, head))
            one_key_runs = [run for run in runs if run["input"].count(b"\n") == 1]
            self.assertEqual(len(single_calls), len(one_key_runs))
            self.assertEqual(2, len(single_calls))  # the commit and the root tree

    def test_first_parent_prefetch_never_reads_the_anchor_or_s(self):
        with tempfile.TemporaryDirectory(prefix="q01-v3-chain-anchor-") as directory:
            repository = Path(directory) / "repository"
            repository.mkdir()
            self._git(repository, "init", "-q")
            commits = []
            for index in range(42):
                (repository / "n.txt").write_bytes(f"{index}\n".encode())
                self._git(repository, "add", "-A")
                self._git(repository, "-c", "commit.gpgsign=false", "commit", "-qm", f"c{index}")
                commits.append(self._git(repository, "rev-parse", "HEAD").decode().strip())
            runs, observe = self._observed_cat_file_runs()
            with mock.patch.object(publication, "S_COMMIT", commits[0]), mock.patch.object(
                subprocess, "run", side_effect=observe,
            ):
                self.assertEqual(
                    tuple(reversed(commits[2:])),
                    publication._raw_v3_first_parent_chain(repository, commits[-1], commits[1]),
                )
            requested = b"".join(run["input"] for run in runs)
            self.assertNotIn(commits[1].encode(), requested)
            self.assertNotIn(commits[0].encode(), requested)
            self.assertLessEqual(len(runs), 2)  # 40 commits in ceil(40/32) closed batches

    def test_v2_malformed_response_shapes_in_a_batch_fall_back_identically(self):
        # Guard (expected GREEN before and after): the V2 primitive corpus shapes
        # (test_public_publication_workflow.py:5433-5442) that T6 does not already cover.
        def first_header(stdout):
            header = stdout.split(b"\n", 1)[0]
            oid, kind, size = header.split(b" ")
            return header, oid, kind, int(size)

        def resize(stdout, delta):
            header, oid, kind, size = first_header(stdout)
            return oid + b" " + kind + b" " + str(size + delta).encode() + stdout[len(header):]

        def flip_payload(stdout):
            start = len(first_header(stdout)[0]) + 1
            return stdout[:start] + bytes([stdout[start] ^ 1]) + stdout[start + 1:]

        corpus = {
            "duplicate-frames": lambda out: out + out,
            "size-plus-one": lambda out: resize(out, 1),
            "size-minus-one": lambda out: resize(out, -1),
            "payload-sha-mismatch": flip_payload,
            "echoed-oid-wrong": lambda out: b"0" * 40 + out[40:],
        }
        with tempfile.TemporaryDirectory(prefix="q01-v3-batch-v2-corpus-") as directory:
            repository, head, expected = self._literal_tree_repository(directory)
            real_run = subprocess.run
            for name, transform in corpus.items():
                with self.subTest(name=name):
                    singles = []

                    def tamper(*args, **kwargs):
                        payload = kwargs.get("input") or b""
                        result = real_run(*args, **kwargs)
                        if payload.count(b"\n") > 1:
                            return subprocess.CompletedProcess(result.args, 0, transform(result.stdout), b"")
                        if payload:
                            singles.append(payload)
                        return result

                    with mock.patch.object(subprocess, "run", side_effect=tamper):
                        self.assertEqual(expected, publication._verified_commit_records(repository, head))
                    self.assertTrue(singles)
                    self.assertIsNone(publication._C09_SCOPE.get())
