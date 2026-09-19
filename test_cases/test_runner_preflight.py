"""PF1–4: selection-aware capability gates, before children or approvals.

Historical identities below are independent reviewed fixtures, not calculated
from the runner. Git workflows use a disposable repository and the real clean
predicate; no remote, sshd, production deployment or operator input is used.
"""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "pf_runner", ROOT / "test_cases/run_related_tests.py",
)
RUNNER = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = RUNNER
spec.loader.exec_module(RUNNER)
GIT = shutil.which("git", path=os.confstr("CS_PATH") or "/usr/bin:/bin")
P = "test_cases.test_public_publication_workflow"
C = "test_cases.test_public_publication_contract"
F = "test_cases.test_public_project_fixture_workflow"
S = "test_cases.test_public_s_phase_workflow"
Z = "test_cases.test_ztp_release_core_review"
D = "test_cases.test_dummy"
HISTORICAL = {
    P: ("ce21fef142ace4541f47ce8ceb53078a09c8f8e6",
        "1bb652bb15f97e03e568270a57ee0a56515bc526cecd5034c6a99c031102358e"),
    C: ("ce21fef142ace4541f47ce8ceb53078a09c8f8e6",
        "3bc97396dd627830080b3bfcb0b3a340ce6cd9d19fdb377983edd26ca152db64"),
    F: ("ce21fef142ace4541f47ce8ceb53078a09c8f8e6",
        "aae51daa9f67eedd7701764289517c41defe6f264c48268e92faded9ee60849d"),
    S: ("991a64476cfe1de2a0ab45bca8b7b6d75d5e9149",
        "81c3a2606c66aa1b9cee320bfeb0366fb28ff2b865abd7c7e8f577f1e0766e4f"),
}


def module_path(root, name):
    return root / (name.replace(".", "/") + ".py")


class PreflightFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="http-pf-test-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "repository"
        self.root.mkdir()
        self.marker = self.base / "child-started"
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith("GIT_")}
        self.env.update({"GIT_CONFIG_NOSYSTEM": "1",
                         "GIT_CONFIG_GLOBAL": os.devnull,
                         "PYTHONPYCACHEPREFIX": str(self.base / "pycache"),
                         "PF_CHILD_MARKER": str(self.marker)})
        self.write("test_cases/__init__.py", "")
        for relative in ("tools/project_contract.py", "test_cases/run_related_tests.py",
                         "test_cases/test_public_publication_workflow.py",
                         "requirements-container-top-level.lock"):
            self.write(relative, (ROOT / relative).read_bytes())
        marker_test = (
            "import os, unittest\nfrom pathlib import Path\n"
            "class Marker(unittest.TestCase):\n"
            "    def test_child(self):\n"
            "        Path(os.environ['PF_CHILD_MARKER']).write_text('executed')\n"
        )
        for name in (C, F, S, Z, D):
            self.write(name.replace(".", "/") + ".py", marker_test)
        # Finite selector fixtures: the real runner still imports and validates
        # each selector and their source/direct/workflow mappings.
        self.write("tools/sync-code.py", "ROOT_CODE_PATTERNS = ()\n"
                   "def matching_files(root, patterns): return ()\n")
        self.write("infra/docker/activate.py",
                   "def image_source_paths(root): return ()\n")
        self.write("tools/_package_common.py",
                   "def deployment_archive_source_paths(root): return ()\n")
        scripts = {p: p for p in ("tools/project_contract.py", "tools/sync-code.py",
                                  "infra/docker/activate.py", "tools/_package_common.py")}
        manifest = {
            "schema_version": 1, "baseline_tests": [D], "scripts": scripts,
            "test_suites": [
                {"id": key, "description": key, "tests": [name]}
                for key, name in (("authority", C), ("public", P), ("fixture", F),
                                  ("s-phase", S), ("socket", Z), ("direct", D))
            ],
            "test_rules": [{"id": "fixture-direct", "paths": list(scripts), "tests": [D]}],
            "workflows": [{"id": "fixture-workflow", "members": list(scripts), "tests": [D]}],
            "tracked_support": ["test_cases/run_related_tests.py", "requirements-container-top-level.lock"],
            "path_rules": [{"paths": ["test_cases/run_related_tests.py", "requirements-container-top-level.lock"],
                            "full_suite": True}],
        }
        self.write("test_cases/script_test_manifest.json", json.dumps(manifest))
        self.ledger = self.root / "test_cases/script_test_approved_hashes.json"
        # Only the normal runner writer establishes this throwaway fixture's
        # approval state. It is not an attestation for the development checkout.
        checked = RUNNER.load_and_validate_manifest(
            self.root, self.root / "test_cases/script_test_manifest.json",
        )
        snapshot = RUNNER.make_snapshot(
            self.root, self.root / "test_cases/script_test_manifest.json", checked,
        )
        RUNNER.atomic_write_approvals(self.ledger, snapshot)
        self.git("init", "--quiet")
        self.git("config", "user.name", "PF Fixture")
        self.git("config", "user.email", "pf-fixture@example.invalid")
        self.git("config", "core.hooksPath", str(self.base / "no-hooks"))
        self.git("config", "commit.gpgsign", "false")
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "independent PF fixture")

    def write(self, relative, value):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value if isinstance(value, bytes) else value.encode())

    def git(self, *args, root=None):
        result = subprocess.run([GIT, *args], cwd=root or self.root, env=self.env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual(0, result.returncode, result.stderr.decode(errors="replace"))
        return result.stdout

    def selection(self, *names, full=False):
        return RUNNER.Selection(tests=set(names), full_suite=full)

    def cli(self, *args, deny_bind=False, watch=False, audit_checks=False):
        command = [sys.executable, "-B", "test_cases/run_related_tests.py", *args]
        if deny_bind or audit_checks:
            audit = (
                "import runpy, sys\n"
                "def audit(event, args):\n"
                "    if event == 'socket.bind' or (event == 'subprocess.Popen' and "
                "'diff-index' in args[1] and '--cached' not in args[1]):\n"
                f"        with open({str(self.base / 'probe-events')!r}, 'a') as trace: trace.write(event + '\\n')\n"
                f"    if event == 'socket.bind' and {deny_bind!r}: raise PermissionError('PF fixture bind denied')\n"
                "sys.addaudithook(audit)\n"
                "sys.argv = ['test_cases/run_related_tests.py'] + sys.argv[1:]\n"
                "runpy.run_path(sys.argv[0], run_name='__main__')\n"
            )
            command = [sys.executable, "-B", "-c", audit, *args]
        if watch:
            with subprocess.Popen(command, cwd=self.root, env=self.env, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
                try:
                    out, err = child.communicate(timeout=2)
                    self.fail("watch exited unexpectedly: " + (out + err).decode(errors="replace"))
                except subprocess.TimeoutExpired:
                    child.terminate()
                    out, err = child.communicate(timeout=10)
            return subprocess.CompletedProcess(command, child.returncode, out.decode(), err.decode())
        return subprocess.run(command, cwd=self.root, env=self.env, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                              check=False, timeout=30)

    def assert_no_child_or_approval(self, before, result, tag):
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn(tag, result.stderr)
        self.assertFalse(self.marker.exists(), result.stdout + result.stderr)
        self.assertEqual(before, self.ledger.read_bytes())


class PreflightDirectTests(PreflightFixture):
    def test_finite_module_predicates_and_historical_pins_match_reviewed_authority(self):
        from test_cases import test_public_publication_workflow as authority
        from test_cases import test_public_s_phase_contract as s_authority
        self.assertEqual({name: record[1] for name, record in HISTORICAL.items()},
                         RUNNER.PREFLIGHT_HISTORICAL_TESTS)
        self.assertEqual({P, Z, "test_cases.test_runner_preflight"}, RUNNER.PREFLIGHT_INET_TESTS)
        self.assertEqual({name.replace(".", "/") + ".py": HISTORICAL[name][1] for name in (P, C, F)},
                         authority.P_HISTORICAL_MODULE_SHA256)
        self.assertEqual(HISTORICAL[S][1], s_authority.S_HISTORICAL_BLOBS[
            "test_cases/test_public_s_phase_workflow.py"])

    def test_exact_historical_module_bytes_defer_to_existing_stage_contract(self):
        for name, (commit, digest) in HISTORICAL.items():
            with self.subTest(module=name):
                path = module_path(self.root, name)
                previous = path.read_bytes()
                historical = self.git("show", commit + ":" + name.replace(".", "/") + ".py", root=ROOT)
                self.assertEqual(digest, hashlib.sha256(historical).hexdigest())
                path.write_bytes(historical)
                self.git("add", str(path.relative_to(self.root)))
                with mock.patch.object(RUNNER, "_preflight_loopback_bind"):
                    RUNNER.preflight_selection(self.root, self.selection(name))
                # One byte is enough to require ordinary V3 clean authority;
                # no environment variable or stage-name string grants a bypass.
                path.write_bytes(historical + b"\n# unreviewed candidate\n")
                with self.assertRaisesRegex(RUNNER.ImpactError, "EFF E-3"):
                    RUNNER.preflight_selection(self.root, self.selection(name))
                path.write_bytes(previous)
                self.git("add", str(path.relative_to(self.root)))

    def test_historical_sibling_does_not_exempt_selected_current_module(self):
        historical = self.git("show", HISTORICAL[C][0] + ":test_cases/test_public_publication_contract.py", root=ROOT)
        module_path(self.root, C).write_bytes(historical)
        with self.assertRaisesRegex(RUNNER.ImpactError, "EFF E-3"):
            RUNNER.preflight_selection(self.root, self.selection(C, F))

    def test_clean_predicate_is_the_existing_imported_function(self):
        from test_cases import test_public_publication_workflow as authority
        with mock.patch.object(RUNNER, "_load_preflight_authority", return_value=authority), \
                mock.patch.object(authority, "_assert_clean_and_ledger",
                                  wraps=authority._assert_clean_and_ledger) as clean:
            RUNNER.preflight_selection(self.root, self.selection(C))
        clean.assert_called_once_with(self.root, self.ledger.read_bytes(),
                                      self.git("rev-parse", "HEAD").decode().strip())

    def test_required_git_failure_and_unavailable_authority_fail_closed(self):
        from test_cases import test_public_publication_workflow as authority
        with mock.patch.object(RUNNER, "_load_preflight_authority", return_value=authority):
            for failure in (OSError("unavailable Git"), AssertionError("Git returned nonzero")):
                with self.subTest(failure=str(failure)), \
                        mock.patch.object(authority, "_head", side_effect=failure), \
                        self.assertRaisesRegex(RUNNER.ImpactError, "EFF E-3"):
                    RUNNER.preflight_selection(self.root, self.selection(C))
        module_path(self.root, P).unlink()
        with self.assertRaisesRegex(RUNNER.ImpactError, "EFF E-3"):
            RUNNER.preflight_selection(self.root, self.selection(C))

    def test_linked_worktree_has_distinct_main_checkout_remedy(self):
        git_dir = self.root / ".git"
        moved = self.base / "main-git-directory"
        git_dir.rename(moved)
        git_dir.write_text("gitdir: ../main-git-directory/worktrees/fixture\n")
        with self.assertRaisesRegex(
            RUNNER.ImpactError, "EFF E-3.*linked Git worktree.*main checkout",
        ):
            RUNNER.preflight_selection(self.root, self.selection(C))

    def test_loopback_exact_selection_bind_close_and_no_connect_or_listen(self):
        for name in (P, Z, "test_cases.test_runner_preflight"):
            for failure in (None, PermissionError("denied")):
                fake = mock.Mock()
                fake.bind.side_effect = failure
                with self.subTest(module=name, failure=failure), \
                        mock.patch.object(RUNNER, "_preflight_clean_candidate"), \
                        mock.patch.object(RUNNER.socket, "socket", return_value=fake) as factory:
                    if failure:
                        with self.assertRaisesRegex(RUNNER.ImpactError, "EFF E-1.*scoped"):
                            RUNNER.preflight_selection(self.root, self.selection(name))
                    else:
                        RUNNER.preflight_selection(self.root, self.selection(name))
                factory.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
                self.assertEqual([mock.call.bind(("127.0.0.1", 0)), mock.call.close()], fake.mock_calls)
        with mock.patch.object(RUNNER.socket, "socket", side_effect=OSError("socket unavailable")), \
                self.assertRaisesRegex(RUNNER.ImpactError, "EFF E-1"):
            RUNNER.preflight_selection(self.root, self.selection(Z))

    def test_unrelated_and_unix_socket_modules_do_not_probe_inet_or_git(self):
        for name in (D, "test_cases.test_docker_management_ssh_key", "test_cases.test_monitor_stack_review"):
            with self.subTest(module=name), mock.patch.object(RUNNER, "_preflight_clean_candidate") as clean, \
                    mock.patch.object(RUNNER.socket, "socket") as bind:
                RUNNER.preflight_selection(self.base, self.selection(name))
                clean.assert_not_called()
                bind.assert_not_called()

    def test_full_selection_expands_discovery_not_only_baseline(self):
        with mock.patch.object(RUNNER, "_preflight_clean_candidate") as clean, \
                mock.patch.object(RUNNER, "_preflight_loopback_bind") as bind:
            RUNNER.preflight_selection(self.root, self.selection(D, full=True))
            clean.assert_called_once()
            self.assertEqual({P, C, F, S}, set(clean.call_args.args[1]))
            bind.assert_called_once_with()


class PreflightRunnerWorkflowTests(PreflightFixture):
    def test_successful_real_loopback_preflight_does_not_start_test_child(self):
        before = self.ledger.read_bytes()
        result = self.cli("--suite", "socket", "--preflight", audit_checks=True)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual("socket.bind\n", (self.base / "probe-events").read_text())
        self.assertFalse(self.marker.exists())
        self.assertEqual(before, self.ledger.read_bytes())

    def test_clean_suite_executes_real_child_without_changing_approvals(self):
        before = self.ledger.read_bytes()
        result = self.cli("--suite", "authority")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual("executed", self.marker.read_text())
        self.assertEqual(before, self.ledger.read_bytes())

    def test_dirty_variants_fail_before_child_with_commit_remedy(self):
        for kind in (
            "staged", "staged-worktree-restored", "unstaged", "untracked",
            "ledger-only",
        ):
            with self.subTest(kind=kind):
                path = self.ledger if kind == "ledger-only" else self.root / (
                    "untracked.txt" if kind == "untracked" else "tools/project_contract.py")
                original = path.read_bytes() if path.exists() else None
                path.write_bytes((original or b"") + b"\n")
                if kind in ("staged", "staged-worktree-restored"):
                    self.git("add", str(path.relative_to(self.root)))
                if kind == "staged-worktree-restored":
                    path.write_bytes(original)
                    self.assertEqual(
                        b"MM tools/project_contract.py\n",
                        self.git("status", "--porcelain=v1"),
                    )
                    index = self.root / ".git/index"
                    index_before = (
                        index.stat().st_ino,
                        hashlib.sha256(index.read_bytes()).hexdigest(),
                    )
                before = self.ledger.read_bytes()
                result = self.cli("--suite", "authority")
                self.assert_no_child_or_approval(before, result, "EFF E-3")
                self.assertIn(
                    "staged, unstaged, untracked, or ledger changes", result.stderr,
                )
                self.assertIn("commit the reviewed source/test candidate", result.stderr)
                self.assertNotIn("content-identical stat dirt", result.stderr)
                if kind == "staged-worktree-restored":
                    self.assertEqual(
                        index_before,
                        (index.stat().st_ino,
                         hashlib.sha256(index.read_bytes()).hexdigest()),
                    )
                    self.assertEqual(
                        b"MM tools/project_contract.py\n",
                        self.git("status", "--porcelain=v1"),
                    )
                if original is None:
                    path.unlink()
                else:
                    path.write_bytes(original)
                    self.git("add", str(path.relative_to(self.root)))

    def test_content_identical_stat_dirt_requires_explicit_index_refresh(self):
        path = self.root / "tools/project_contract.py"
        original = path.read_bytes()
        metadata = path.stat()
        os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 2_000_000_000))
        index = self.root / ".git/index"
        index_before = (
            index.stat().st_ino,
            hashlib.sha256(index.read_bytes()).hexdigest(),
        )
        before = self.ledger.read_bytes()
        for attempt in range(2):
            with self.subTest(attempt=attempt):
                refused = self.cli("--suite", "authority")
                self.assert_no_child_or_approval(before, refused, "EFF E-3")
                self.assertIn("content-identical stat dirt", refused.stderr)
                self.assertIn("run `git status` to refresh the index", refused.stderr)
                self.assertNotIn(
                    "staged, unstaged, untracked, or ledger changes", refused.stderr,
                )
                self.assertEqual(
                    index_before,
                    (index.stat().st_ino,
                     hashlib.sha256(index.read_bytes()).hexdigest()),
                )
        status = subprocess.run(
            [GIT, "status", "--porcelain=v1"], cwd=self.root, env=self.env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
        )
        self.assertEqual(0, status.returncode, status.stderr)
        self.assertEqual("", status.stdout)
        accepted = self.cli("--suite", "authority")
        self.assertEqual(0, accepted.returncode, accepted.stdout + accepted.stderr)
        self.assertEqual(original, path.read_bytes())

    def test_real_git_metadata_failure_not_misread_as_clean(self):
        (self.root / ".git/HEAD").write_text("ref: refs/heads/nonexistent\n")
        before = self.ledger.read_bytes()
        self.assert_no_child_or_approval(before, self.cli("--suite", "authority"), "EFF E-3")

    def test_nongit_direct_suite_still_runs(self):
        (self.root / ".git").rename(self.base / "fixture-git")
        result = self.cli("--suite", "direct", deny_bind=True)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertTrue(self.marker.exists())

    def test_bind_denial_and_explicit_preflight_are_read_only(self):
        before = self.ledger.read_bytes()
        for args in (("--suite", "socket"), ("--suite", "socket", "--preflight")):
            with self.subTest(args=args):
                self.assert_no_child_or_approval(before, self.cli(*args, deny_bind=True), "EFF E-1")
        result = self.cli("--suite", "authority", "--preflight")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("Git/capability preflight passed", result.stdout)
        self.assertFalse(self.marker.exists())
        self.assertEqual(before, self.ledger.read_bytes())

    def test_public_suite_clean_gate_precedes_bind_gate_and_uses_one_prefix(self):
        before = self.ledger.read_bytes()
        self.write("untracked.txt", "dirty")
        dirty = self.cli("--suite", "public", deny_bind=True, audit_checks=True)
        self.assert_no_child_or_approval(before, dirty, "EFF E-3")
        self.assertIn("preflight failed; approved hashes were not changed:", dirty.stderr)
        events = self.base / "probe-events"
        self.assertEqual("subprocess.Popen\n", events.read_text(),
                         "the clean gate must refuse before any bind")
        (self.root / "untracked.txt").unlink()
        denied = self.cli("--suite", "public", deny_bind=True, audit_checks=True)
        self.assert_no_child_or_approval(before, denied, "EFF E-1")
        self.assertIn("preflight failed; approved hashes were not changed:", denied.stderr)
        self.assertEqual(
            "subprocess.Popen\nsubprocess.Popen\nsocket.bind\n",
            events.read_text(),
            "the clean attempt must finish its Git gate before exactly one bind",
        )

    def test_read_only_modes_never_bind_even_when_dirty(self):
        self.write("untracked.txt", "dirty")
        before = self.ledger.read_bytes()
        for args, code in ((("--all", "--list"), 0), (("--list-suites",), 0),
                           (("--check", "--require-full"), 5)):
            with self.subTest(args=args):
                result = self.cli(*args, deny_bind=True)
                self.assertEqual(code, result.returncode, result.stdout + result.stderr)
                self.assertNotIn("EFF E-", result.stderr)
                self.assertFalse(self.marker.exists())
                self.assertEqual(before, self.ledger.read_bytes())

    def test_all_and_broad_fallback_fail_before_any_discovery_child(self):
        self.write("untracked.txt", "dirty")
        before = self.ledger.read_bytes()
        for args in (("--all",), ("--changed", "unknown-authority.txt"),
                     ("--all", "--preflight")):
            with self.subTest(args=args):
                self.assert_no_child_or_approval(before, self.cli(*args), "EFF E-3")

    def test_clean_all_explicit_preflight_qualifies_what_was_not_checked(self):
        before = self.ledger.read_bytes()
        result = self.cli("--all", "--preflight")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("Git/capability preflight passed", result.stdout)
        self.assertIn("full-suite runtime environment not checked", result.stdout)
        self.assertFalse(self.marker.exists())
        self.assertEqual(before, self.ledger.read_bytes())

    def test_watch_applies_gate_to_pending_selection(self):
        module_path(self.root, C).write_bytes(module_path(self.root, C).read_bytes() + b"\n")
        before = self.ledger.read_bytes()
        result = self.cli("--watch", "--interval", "0.2", watch=True, audit_checks=True)
        self.assert_no_child_or_approval(before, result, "EFF E-3")
        self.assertEqual("subprocess.Popen\n", (self.base / "probe-events").read_text(),
                         "an unchanged failed watch selection must not be attempted repeatedly")
        self.assertEqual(-15, result.returncode)

    def test_watch_requires_relaunch_after_git_authority_repair(self):
        module = module_path(self.root, C)
        module.write_bytes(module.read_bytes() + b"\n# pending committed bytes\n")
        command = [
            sys.executable, "-B", "-c",
            "import runpy,sys\n"
            "def audit(event,args):\n"
            "    if event == 'subprocess.Popen' and 'diff-index' in args[1] and "
            "'--cached' not in args[1]:\n"
            f"        open({str(self.base / 'probe-events')!r},'a').write(event+'\\n')\n"
            "sys.addaudithook(audit)\n"
            "sys.argv=['test_cases/run_related_tests.py']+sys.argv[1:]\n"
            "runpy.run_path(sys.argv[0],run_name='__main__')\n",
            "--watch", "--interval", "0.2",
        ]
        child = subprocess.Popen(
            command, cwd=self.root, env=self.env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.addCleanup(lambda: child.poll() is None and child.kill())
        trace = self.base / "probe-events"
        for _ in range(50):
            if trace.exists() and trace.read_text().count("subprocess.Popen\n") == 1:
                break
            import time
            time.sleep(0.1)
        else:
            child.kill()
            self.fail("watch never attempted the dirty selection")
        self.git("add", str(module.relative_to(self.root)))
        self.git("commit", "--quiet", "-m", "repair authority without changing bytes")
        import time
        time.sleep(1.0)
        self.assertEqual(1, trace.read_text().count("subprocess.Popen\n"),
                         "Git-only repair must require an operator relaunch")
        child.terminate()
        child.communicate(timeout=10)
        self.assertEqual(-15, child.returncode)

    def test_explicit_preflight_checks_no_change_selection_and_rejects_mode_conflicts(self):
        before = self.ledger.read_bytes()
        result = self.cli("--preflight", audit_checks=True)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("Git/capability preflight passed", result.stdout)
        self.assertFalse((self.base / "probe-events").exists())
        for other in ("--watch", "--list", "--check", "--list-suites"):
            result = self.cli("--preflight", other)
            self.assertEqual(2, result.returncode, result.stdout + result.stderr)
        self.assertFalse(self.marker.exists())
        self.assertEqual(before, self.ledger.read_bytes())


if __name__ == "__main__":
    unittest.main()
