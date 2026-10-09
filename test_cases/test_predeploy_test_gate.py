#!/usr/bin/env python3
"""Fail-closed, pre-connection test gates for the two deployment entrypoints."""

from __future__ import annotations

import argparse
from contextlib import ExitStack, nullcontext, redirect_stderr, redirect_stdout
import importlib.util
import io
import json
import os
import shlex
import stat
import tarfile
from pathlib import Path
import subprocess
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest import mock
import uuid


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
    return module


SYNC = load_module("predeploy_gate_sync", TOOLS / "sync-code.py")
UPLOAD = load_module("predeploy_gate_upload", TOOLS / "tar-for-upload.py")
INSTALLER = load_module(
    "predeploy_gate_relay_installer", TOOLS / "deploy-upload-archive.py",
)
LOAD = load_module("predeploy_gate_load", ROOT / "DAY0-Prepare/11-load.py")
RUNNER = load_module(
    "predeploy_gate_runner", ROOT / "test_cases/run_related_tests.py",
)
PRE_PUSH = load_module(
    "predeploy_gate_pre_push", TOOLS / "pre-push-proof.py",
)


def sync_args(*, dry_run: bool = False) -> argparse.Namespace:
    return argparse.Namespace(
        project="customer", host="ubuntu@worker.example", port=24995,
        identity=None, remote_root="/var/www/html", sudo=True,
        dry_run=dry_run, include_ztp_runtime=False,
        runtime="native",
    )


def upload_args(*, deploy: bool, dry_run: bool) -> argparse.Namespace:
    return argparse.Namespace(
        project="customer", deploy=deploy, dry_run=dry_run,
        deploy_uploaded=None,
        output=Path("/tmp/customer-upload.tar.gz"),
        host="ubuntu@worker.example", port=24995, identity=None,
        remote_root="/var/www/html", no_sudo=False, runtime="native",
    )


class GateCommandTests(unittest.TestCase):
    def test_native_upload_next_command_declares_server_role_to_real_load_parser(self):
        args = upload_args(deploy=True, dry_run=False)
        command = UPLOAD.recommended_remote_load_command(
            args, Path("/tmp/customer"),
        )
        remote = shlex.split(command[-1])
        self.assertEqual(["ssh", "-t", args.host], [command[0], command[-3], command[-2]])
        requested = remote[remote.index("11-load.py") + 1:]
        self.assertEqual(
            "management-server",
            LOAD.resolve_host_role(LOAD.parse_args(requested).host_role, "Linux"),
        )

    def test_invalid_load_scope_stops_before_macos_full_test_gate(self):
        events = []
        stderr = io.StringIO()
        with mock.patch.object(
            LOAD, "runtime_os", return_value="Darwin",
        ), mock.patch.object(
            LOAD, "run_local_full_test_gate",
            side_effect=lambda: events.append("full"),
        ), mock.patch.object(
            LOAD, "configure_local_pre_push_proof_gate",
            side_effect=lambda: events.append("hook"),
        ), mock.patch.object(
            LOAD, "acquire_deployment_lock",
            side_effect=AssertionError("invalid CLI must not acquire lock"),
        ), redirect_stdout(io.StringIO()), redirect_stderr(stderr):
            self.assertEqual(
                1, LOAD.cli(["example-project", "--prod", "--mini"]),
            )

        self.assertEqual([], events)
        self.assertRegex(stderr.getvalue(), "--mini.*AIR|--prod")

    def test_macos_real_load_resolves_full_proof_before_work_and_rechecks_after_success(self):
        events = []
        args = SimpleNamespace(dry_run=False)
        with mock.patch.object(
            LOAD, "parse_args", return_value=args,
        ), mock.patch.object(
            LOAD, "runtime_os", return_value="Darwin",
        ), mock.patch.object(
            LOAD, "run_local_full_test_gate",
            side_effect=lambda: events.append("full"),
        ), mock.patch.object(
            LOAD, "configure_local_pre_push_proof_gate",
            side_effect=lambda: events.append("hook"),
        ), mock.patch.object(
            LOAD, "main", side_effect=lambda _argv: events.append("load") or 0,
        ), mock.patch.object(
            LOAD, "verify_local_full_test_attestation",
            side_effect=lambda: events.append("post-check"),
        ):
            self.assertEqual(0, LOAD.cli(["customer"]))
        self.assertEqual(["full", "hook", "load", "post-check"], events)

    def test_current_full_proof_is_reused_without_running_full_suite(self):
        calls = []

        def run(arguments, label, **kwargs):
            calls.append((arguments, label, kwargs))
            return 0

        with mock.patch.object(
            LOAD, "_run_local_test_runner", side_effect=run,
        ), redirect_stdout(io.StringIO()):
            LOAD.run_local_full_test_gate()

        self.assertEqual([
            (
                ["--check", "--require-full"],
                "本机正式 load 前全量测试证明检查",
                {"accepted_returncodes": frozenset({0, 4, 5})},
            ),
        ], calls)

    def test_only_stale_or_missing_full_proof_falls_back_to_full_suite(self):
        conditions = (
            ("managed source changed", 4),
            ("managed test changed", 4),
            ("impact manifest changed", 4),
            ("proof missing or execution environment changed", 5),
        )
        for condition, status in conditions:
            with self.subTest(condition=condition):
                calls = []

                def run(arguments, label, **kwargs):
                    calls.append((arguments, label, kwargs))
                    if len(calls) == 1:
                        return status
                    return 0

                with mock.patch.object(
                    LOAD, "_run_local_test_runner", side_effect=run,
                ), redirect_stdout(io.StringIO()):
                    LOAD.run_local_full_test_gate()

                self.assertEqual([
                    (
                        ["--check", "--require-full"],
                        "本机正式 load 前全量测试证明检查",
                        {"accepted_returncodes": frozenset({0, 4, 5})},
                    ),
                    (["--all"], "本机正式 load 前全量测试", {}),
                    (
                        ["--check", "--require-full"],
                        "本机 load 全量测试证明复核",
                        {},
                    ),
                ], calls)

    def test_governance_safety_error_never_falls_back_to_full_suite(self):
        calls = []

        def run(arguments, label, **kwargs):
            calls.append((arguments, label, kwargs))
            return 2

        with mock.patch.object(
            LOAD, "_run_local_test_runner", side_effect=run,
        ), redirect_stdout(io.StringIO()), self.assertRaisesRegex(
            LOAD.LoadError, "exit=2",
        ):
            LOAD.run_local_full_test_gate()

        self.assertEqual(1, len(calls))

    def test_air_validation_load_passes_explicit_intent_to_both_full_gates(self):
        requested = ["customer", "--air", "--validation-only"]
        args = SimpleNamespace(
            dry_run=False, deployment_scope="air", validation_only=True,
        )
        with mock.patch.object(
            LOAD, "parse_args", return_value=args,
        ), mock.patch.object(
            LOAD, "runtime_os", return_value="Darwin",
        ), mock.patch.object(
            LOAD, "run_local_full_test_gate",
        ) as full, mock.patch.object(
            LOAD, "configure_local_pre_push_proof_gate",
        ) as hook, mock.patch.object(
            LOAD, "main", return_value=0,
        ) as work, mock.patch.object(
            LOAD, "verify_local_full_test_attestation",
        ) as verify:
            self.assertEqual(0, LOAD.cli(requested))
        work.assert_called_once_with(requested)
        full.assert_called_once_with(validation_only=True)
        hook.assert_called_once_with()
        verify.assert_called_once_with(validation_only=True)

    def test_linux_load_and_macos_dry_run_never_run_development_tests(self):
        for host_os, dry_run in (("Linux", False), ("Darwin", True)):
            with self.subTest(host_os=host_os, dry_run=dry_run), \
                 mock.patch.object(
                     LOAD, "parse_args", return_value=SimpleNamespace(dry_run=dry_run),
                 ), mock.patch.object(
                     LOAD, "runtime_os", return_value=host_os,
                 ), mock.patch.object(
                     LOAD, "run_local_full_test_gate",
                 ) as full, mock.patch.object(
                     LOAD, "configure_local_pre_push_proof_gate",
                 ) as hook, mock.patch.object(
                     LOAD, "verify_local_full_test_attestation",
                 ) as verify, mock.patch.object(
                     LOAD, "main", return_value=0,
                 ):
                self.assertEqual(0, LOAD.cli(["customer"]))
            full.assert_not_called()
            hook.assert_not_called()
            verify.assert_not_called()

    def test_failed_macos_full_gate_stops_before_load(self):
        with mock.patch.object(
            LOAD, "parse_args", return_value=SimpleNamespace(dry_run=False),
        ), mock.patch.object(
            LOAD, "runtime_os", return_value="Darwin",
        ), mock.patch.object(
            LOAD, "run_local_full_test_gate",
            side_effect=RuntimeError("full tests failed"),
        ), mock.patch.object(
            LOAD, "configure_local_pre_push_proof_gate",
        ) as hook, mock.patch.object(LOAD, "main") as load:
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                self.assertEqual(1, LOAD.cli(["customer"]))
        load.assert_not_called()
        hook.assert_not_called()
        self.assertIn("full tests failed", stderr.getvalue())

    def test_day0_project_inputs_do_not_change_governed_full_snapshot(self):
        manifest = RUNNER.load_and_validate_manifest(ROOT, RUNNER.DEFAULT_MANIFEST)
        before = RUNNER.make_snapshot(ROOT, RUNNER.DEFAULT_MANIFEST, manifest)
        project = ROOT / "DAY0-Prepare" / f"proof-project-{uuid.uuid4().hex}"
        try:
            project.mkdir()
            (project / "01-global.yaml").write_text("schema_version: 2\n", encoding="utf-8")
            (project / "02-devices_config.csv").write_text(
                "hostname,type\nleaf01,eth\n", encoding="utf-8",
            )
            (project / "02-dhcp-subnet_config.csv").write_text(
                "shared_network,subnet\noob,192.0.2.0\n", encoding="utf-8",
            )
            after = RUNNER.make_snapshot(ROOT, RUNNER.DEFAULT_MANIFEST, manifest)
        finally:
            for child in project.iterdir() if project.exists() else ():
                child.unlink()
            if project.exists():
                project.rmdir()
        self.assertEqual(before, after)

    def test_load_configures_tracked_pre_push_gate_with_exact_python(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            hook = repository / ".githooks/pre-push"
            gate = repository / "tools/pre-push-proof.py"
            hook.parent.mkdir()
            gate.parent.mkdir()
            hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            gate.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
            hook.chmod(0o755)
            subprocess.run(["git", "init", "-q", repository], check=True)
            subprocess.run(
                ["git", "-C", repository, "add", ".githooks/pre-push", "tools/pre-push-proof.py"],
                check=True,
            )
            with mock.patch.object(LOAD, "HTTP_ROOT", repository), \
                    mock.patch.object(LOAD, "LOCAL_PRE_PUSH_HOOK", hook), \
                    redirect_stdout(io.StringIO()):
                LOAD.configure_local_pre_push_proof_gate()
            hooks_path = subprocess.run(
                ["git", "-C", repository, "config", "--local", "--get", "core.hooksPath"],
                text=True, stdout=subprocess.PIPE, check=True,
            ).stdout.strip()
            proof_python = subprocess.run(
                ["git", "-C", repository, "config", "--local", "--get", "http.fullProofPython"],
                text=True, stdout=subprocess.PIPE, check=True,
            ).stdout.strip()
            self.assertEqual(".githooks", hooks_path)
            self.assertEqual(str(Path(sys.executable).resolve()), proof_python)

    def _proof_repository(
        self, directory: Path, *, runner_exit: int = 0,
        validation_proof: bool = False, intent_sensitive: bool = False,
    ) -> Path:
        repository = directory / "source"
        (repository / "tools").mkdir(parents=True)
        (repository / "test_cases").mkdir()
        (repository / "DAY0-Prepare/customer").mkdir(parents=True)
        (repository / "tools/pre-push-proof.py").write_bytes(
            (TOOLS / "pre-push-proof.py").read_bytes()
        )
        runner_source = f"raise SystemExit({runner_exit})\n"
        if intent_sensitive:
            runner_source = (
                "import json, pathlib, sys\n"
                "value=json.loads(pathlib.Path('test_cases/script_test_approved_hashes.json').read_text())\n"
                "is_validation='validation_only' in value['full_suite_attestation']\n"
                "requested='--validation-only' in sys.argv\n"
                "raise SystemExit(0 if is_validation == requested else 5)\n"
            )
        (repository / "test_cases/run_related_tests.py").write_text(
            runner_source, encoding="utf-8",
        )
        validation_fragment = ',"validation_only":{"issue":"ISSUE-0016"}' \
            if validation_proof else ""
        (repository / "test_cases/script_test_approved_hashes.json").write_text(
            '{"full_suite_attestation":{"synthetic":true'
            + validation_fragment + '}}\n', encoding="utf-8",
        )
        (repository / "DAY0-Prepare/customer/01-global.yaml").write_text(
            "schema_version: 2\n", encoding="utf-8",
        )
        subprocess.run(["git", "init", "-q", repository], check=True)
        subprocess.run(["git", "-C", repository, "config", "user.name", "Proof Test"], check=True)
        subprocess.run(["git", "-C", repository, "config", "user.email", "proof@example.invalid"], check=True)
        subprocess.run(["git", "-C", repository, "add", "."], check=True)
        subprocess.run(["git", "-C", repository, "commit", "-qm", "proof"], check=True)
        clone = directory / "clone"
        subprocess.run(["git", "clone", "-q", repository, clone], check=True)
        return clone

    def _run_cloned_push_gate(
        self, clone: Path, *, validation_only: bool = False,
    ) -> subprocess.CompletedProcess:
        head = subprocess.run(
            ["git", "-C", clone, "rev-parse", "HEAD"],
            text=True, stdout=subprocess.PIPE, check=True,
        ).stdout.strip()
        environment = os.environ.copy()
        if validation_only:
            environment["HTTP_VALIDATION_ONLY"] = "1"
        else:
            environment.pop("HTTP_VALIDATION_ONLY", None)
        return subprocess.run(
            [sys.executable, "-B", str(clone / "tools/pre-push-proof.py")],
            input=f"refs/heads/main {head} refs/heads/main {'0' * 40}\n",
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=environment, check=False,
        )

    def test_fresh_clone_with_only_project_input_changes_reuses_committed_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            clone = self._proof_repository(Path(directory))
            (clone / "DAY0-Prepare/customer/01-global.yaml").write_text(
                "schema_version: 2\nsite: changed-only-project-input\n",
                encoding="utf-8",
            )
            subprocess.run(["git", "-C", clone, "config", "user.name", "Proof Test"], check=True)
            subprocess.run(["git", "-C", clone, "config", "user.email", "proof@example.invalid"], check=True)
            subprocess.run(
                ["git", "-C", clone, "add", "DAY0-Prepare/customer/01-global.yaml"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", clone, "commit", "-qm", "project input only"],
                check=True,
            )
            result = self._run_cloned_push_gate(clone)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("有效的精确 release full proof", result.stdout)

    def test_push_blocks_uncommitted_or_stale_full_proof(self):
        for condition in ("uncommitted-ledger", "stale-proof"):
            with self.subTest(condition=condition), tempfile.TemporaryDirectory() as directory:
                clone = self._proof_repository(
                    Path(directory), runner_exit=5 if condition == "stale-proof" else 0,
                )
                if condition == "uncommitted-ledger":
                    ledger = clone / "test_cases/script_test_approved_hashes.json"
                    ledger.write_text("{}\n", encoding="utf-8")
                result = self._run_cloned_push_gate(clone)
            self.assertNotEqual(0, result.returncode)
            if condition == "uncommitted-ledger":
                self.assertIn("尚未提交", result.stderr)
            else:
                self.assertIn("没有与当前受管字节", result.stderr)

    def test_push_blocks_a_tip_other_than_checked_out_head(self):
        with tempfile.TemporaryDirectory() as directory:
            clone = self._proof_repository(Path(directory))
            result = subprocess.run(
                [sys.executable, "-B", str(clone / "tools/pre-push-proof.py")],
                input=(
                    f"refs/heads/other {'a' * 40} "
                    f"refs/heads/other {'0' * 40}\n"
                ),
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("当前 checkout 的 HEAD", result.stderr)

    def test_deleting_a_remote_ref_does_not_require_a_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            clone = self._proof_repository(Path(directory), runner_exit=5)
            result = subprocess.run(
                [sys.executable, "-B", str(clone / "tools/pre-push-proof.py")],
                input=(
                    f"(delete) {'0' * 40} refs/heads/old {'a' * 40}\n"
                ),
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
        self.assertEqual(0, result.returncode, result.stderr)

    def test_validation_push_requires_explicit_matching_intent(self):
        scenarios = (
            (True, False, 1, "default rejects validation proof"),
            (True, True, 0, "explicit validation accepts validation proof"),
            (False, True, 1, "validation intent rejects release proof"),
        )
        for proof_is_validation, requested_validation, expected, label in scenarios:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                clone = self._proof_repository(
                    Path(directory), validation_proof=proof_is_validation,
                    intent_sensitive=True,
                )
                result = self._run_cloned_push_gate(
                    clone, validation_only=requested_validation,
                )
            self.assertEqual(expected, result.returncode, result.stderr)
            if expected == 0:
                self.assertIn("validation-only full proof", result.stdout)

    def test_preapproved_full_attestation_is_reused_by_both_entrypoints(self):
        manifest = RUNNER.load_and_validate_manifest(ROOT, RUNNER.DEFAULT_MANIFEST)
        snapshot = RUNNER.make_snapshot(ROOT, RUNNER.DEFAULT_MANIFEST, manifest)
        real_run = subprocess.run
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            approvals = root / "approved.json"
            RUNNER.atomic_write_approvals(
                approvals, snapshot, full_suite=True,
            )
            before = approvals.read_bytes()
            declared_scripts = set(manifest["scripts"])
            self.assertEqual(declared_scripts, set(json.loads(before)["scripts"]))
            wrapper = root / "run_related_tests.py"
            wrapper.write_text(
                "import runpy, sys\n"
                f"sys.argv[1:1] = ['--approvals', {str(approvals)!r}]\n"
                f"runpy.run_path({str(ROOT / 'test_cases/run_related_tests.py')!r}, run_name='__main__')\n",
                encoding="utf-8",
            )
            calls = []
            results = []

            def execute(command, **kwargs):
                calls.append((command, dict(kwargs)))
                completed = real_run(
                    command, **kwargs, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True,
                )
                results.append(completed)
                return completed

            for module in (SYNC, UPLOAD):
                with self.subTest(module=module.__name__), \
                     mock.patch.object(module, "PREDEPLOY_TEST_RUNNER", wrapper), \
                     mock.patch.object(module.subprocess, "run", side_effect=execute), \
                     redirect_stdout(io.StringIO()):
                    module.run_predeploy_test_gate()

            expected = [
                sys.executable, "-B", str(wrapper), "--check", "--require-full",
            ]
            expected_kwargs = {
                "cwd": ROOT, "shell": False, "check": False,
            }
            self.assertEqual(
                [(expected, expected_kwargs), (expected, expected_kwargs)], calls,
            )
            self.assertEqual(2, len(results))
            for completed in results:
                self.assertEqual(0, completed.returncode)
                self.assertEqual(
                    f"impact manifest and {len(declared_scripts)} scripts are approved\n",
                    completed.stdout,
                )
                self.assertEqual("", completed.stderr)
            self.assertEqual(before, approvals.read_bytes())

    def test_local_load_full_gate_reaches_a_noninteractive_unittest_child(self):
        unittest_calls = []
        proof_checks = 0

        def dispatch(command, **kwargs):
            nonlocal proof_checks
            if command == [
                sys.executable, "-B", str(LOAD.LOCAL_TEST_RUNNER),
                "--check", "--require-full",
            ]:
                proof_checks += 1
                return subprocess.CompletedProcess(
                    command, 5 if proof_checks == 1 else 0,
                )
            if command == [
                sys.executable, "-B", str(LOAD.LOCAL_TEST_RUNNER), "--all",
            ]:
                code = RUNNER.run_selection(
                    ROOT, RUNNER.Selection(full_suite=True), verbose=False,
                )
                return subprocess.CompletedProcess(command, code)
            if command[:4] == [sys.executable, "-B", "-m", "unittest"]:
                unittest_calls.append((command, kwargs))
                return subprocess.CompletedProcess(command, 0)
            raise AssertionError(f"unexpected subprocess: {command!r}")

        with mock.patch.object(RUNNER, "preflight_selection"), \
                mock.patch.object(
                    LOAD.subprocess, "run", side_effect=dispatch,
                ), redirect_stdout(io.StringIO()):
            LOAD.run_local_full_test_gate()

        self.assertEqual(1, len(unittest_calls))
        _command, kwargs = unittest_calls[0]
        self.assertEqual(
            subprocess.DEVNULL, kwargs.get("stdin"),
            "local load -> test runner must detach unittest from operator stdin",
        )

    def test_valid_full_attestation_skips_redundant_full_suite(self):
        for module in (SYNC, UPLOAD):
            with self.subTest(module=module.__name__), tempfile.TemporaryDirectory() as directory:
                runner_path = Path(directory) / "run_related_tests.py"
                runner_path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
                with mock.patch.object(module, "PREDEPLOY_TEST_RUNNER", runner_path), \
                     mock.patch.object(
                         module.subprocess, "run",
                         return_value=SimpleNamespace(returncode=0),
                     ) as execute, redirect_stdout(io.StringIO()):
                    module.run_predeploy_test_gate()
                execute.assert_called_once_with(
                    [
                        sys.executable, "-B", str(runner_path),
                        "--check", "--require-full",
                    ],
                    cwd=module.ROOT, shell=False, check=False,
                )

    def test_missing_full_attestation_blocks_transfer_without_running_full(self):
        for module in (SYNC, UPLOAD):
            with self.subTest(module=module.__name__), tempfile.TemporaryDirectory() as directory:
                runner_path = Path(directory) / "run_related_tests.py"
                runner_path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
                with mock.patch.object(module, "PREDEPLOY_TEST_RUNNER", runner_path), \
                     mock.patch.object(
                         module.subprocess, "run",
                         return_value=SimpleNamespace(returncode=5),
                     ) as execute, redirect_stdout(io.StringIO()):
                    with self.assertRaisesRegex(RuntimeError, "exit=5"):
                        module.run_predeploy_test_gate()
                self.assertEqual(
                    [
                        mock.call(
                            [sys.executable, "-B", str(runner_path), "--check", "--require-full"],
                            cwd=module.ROOT, shell=False, check=False,
                        ),
                    ],
                    execute.call_args_list,
                )

    def test_both_commands_use_canonical_runner_and_current_python_without_shell(self):
        with tempfile.TemporaryDirectory() as directory:
            runner_path = Path(directory) / "run_related_tests.py"
            runner_path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
            with mock.patch.object(SYNC, "PREDEPLOY_TEST_RUNNER", runner_path), \
                 mock.patch.object(
                     SYNC.subprocess, "run",
                     return_value=SimpleNamespace(returncode=0),
                 ) as execute, redirect_stdout(io.StringIO()):
                SYNC.run_predeploy_test_gate()
            self.assertEqual(
                [
                    mock.call(
                        [sys.executable, "-B", str(runner_path), "--check", "--require-full"],
                        cwd=SYNC.ROOT, shell=False, check=False,
                    ),
                ],
                execute.call_args_list,
            )

            with mock.patch.object(UPLOAD, "PREDEPLOY_TEST_RUNNER", runner_path), \
                 mock.patch.object(
                     UPLOAD.subprocess, "run",
                     return_value=SimpleNamespace(returncode=0),
                 ) as execute, redirect_stdout(io.StringIO()):
                UPLOAD.run_predeploy_test_gate()
                UPLOAD.verify_predeploy_test_approval()
            self.assertEqual(
                [
                    mock.call(
                        [sys.executable, "-B", str(runner_path), "--check", "--require-full"],
                        cwd=UPLOAD.ROOT, shell=False, check=False,
                    ),
                    mock.call(
                        [sys.executable, "-B", str(runner_path), "--check", "--require-full"],
                        cwd=UPLOAD.ROOT, shell=False, check=False,
                    ),
                ],
                execute.call_args_list,
            )

    def test_missing_or_nonzero_runner_fails_closed(self):
        for module in (SYNC, UPLOAD):
            with self.subTest(module=module.__name__, condition="missing"):
                with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                    stack.enter_context(mock.patch.object(
                        module, "PREDEPLOY_TEST_RUNNER", Path(directory) / "missing.py"
                    ))
                    execute = stack.enter_context(
                        mock.patch.object(module.subprocess, "run")
                    )
                    with self.assertRaises(RuntimeError):
                        module.run_predeploy_test_gate()
                    execute.assert_not_called()

            with self.subTest(module=module.__name__, condition="invalid-manifest"):
                with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                    runner_path = Path(directory) / "run_related_tests.py"
                    runner_path.write_text(
                        "#!/usr/bin/env python3\n", encoding="utf-8"
                    )
                    stack.enter_context(mock.patch.object(
                        module, "PREDEPLOY_TEST_RUNNER", runner_path
                    ))
                    stack.enter_context(mock.patch.object(
                        module.subprocess, "run",
                        return_value=SimpleNamespace(returncode=2),
                    ))
                    stack.enter_context(redirect_stdout(io.StringIO()))
                    with self.assertRaisesRegex(RuntimeError, "exit=2"):
                        module.run_predeploy_test_gate()


class SyncGateTests(unittest.TestCase):
    def _exact_native_metadata_holder(self):
        # A real lock protocol holder, not None masquerading as acquisition.
        # The production parser consumes independently specified wire bytes.
        process = SimpleNamespace(
            poll=lambda: None, stdin=io.StringIO(),
            stdout=io.StringIO("HTTP_ZTP_NATIVE_METADATA_READY EXACT\n"),
            stderr=io.StringIO(),
        )
        holder = SYNC.RemoteDeploymentLock(process, "/var/www/html/.deployment.lock")

        def ready(readers, writers, errors, timeout):
            self.assertEqual([process.stdout], readers)
            self.assertEqual([], writers)
            self.assertEqual([], errors)
            self.assertEqual(SYNC.DEPLOYMENT_PREWRITE_TIMEOUT, timeout)
            return readers, [], []

        return holder, mock.patch.object(SYNC.select, "select", side_effect=ready)

    def _assert_exact_native_read_only_probe(self, holder):
        self.assertEqual("HTTP_ZTP_NATIVE_METADATA_PROBE\n", holder.process.stdin.getvalue())
        self.assertFalse(holder.prewrite_ready)
        self.assertFalse(holder.source_committed)

    def _main_patches(self, args: argparse.Namespace, **extra):
        job = SYNC.SyncJob("one", (Path("/tmp/source"),), "/var/www/html/one")

        def write_manifest(path: Path) -> None:
            path.write_bytes(b"independently frozen manifest fixture\n")

        defaults = {
            "parse_args": mock.patch.object(SYNC, "parse_args", return_value=args),
            "validate_args": mock.patch.object(SYNC, "validate_args"),
            "resolve_project": mock.patch.object(
                SYNC, "resolve_project", return_value=Path("/tmp/customer")
            ),
            "build_jobs": mock.patch.object(SYNC, "build_jobs", return_value=[job]),
            # P2P source selection and byte transfer have separate direct and
            # workflow contracts.  These cases isolate the predeploy gate.
            "selected_p2p": mock.patch.object(
                SYNC, "stage_selected_p2p",
                return_value=(
                    Path("/tmp/customer/Site-P2P-v1.0.xlsx"),
                    Path("/tmp/selected-p2p-stage.xlsx"),
                    "0" * 64,
                ),
            ),
            "p2p_probe": mock.patch.object(
                SYNC, "remote_p2p_action", return_value="CURRENT",
            ),
            "prepare_global_sync": mock.patch.object(
                SYNC, "prepare_global_sync",
                return_value=SimpleNamespace(changed=False),
            ),
            "commit_remote_global": mock.patch.object(
                SYNC, "commit_remote_global",
            ),
            "ensure_remote_directories": mock.patch.object(
                SYNC, "ensure_remote_directories"
            ),
            "assert_remote_deployment_lock": mock.patch.object(
                SYNC, "assert_remote_deployment_lock"
            ),
            "set_remote_sync_marker": mock.patch.object(SYNC, "set_remote_sync_marker"),
            "run_job": mock.patch.object(SYNC, "run_job"),
            "ensure_remote_management_placeholder": mock.patch.object(
                SYNC, "ensure_remote_management_placeholder"
            ),
            "release_remote_deployment_lock": mock.patch.object(
                SYNC, "release_remote_deployment_lock"
            ),
            "write_manifest": mock.patch.object(
                SYNC.project_contract, "write_deployment_source_manifest",
                side_effect=write_manifest,
            ),
            "freeze_guard": mock.patch.object(
                SYNC.project_contract, "deployment_prewrite_guard_source",
                return_value="frozen guard fixture",
            ),
            "freeze_password_contract": mock.patch.object(
                SYNC, "load_frozen_password_contract", return_value=object(),
            ),
            "approval": mock.patch.object(
                SYNC, "verify_predeploy_test_approval",
            ),
            "preview": mock.patch.object(
                SYNC, "sync_jobs_have_changes", return_value=(),
            ),
            "placeholder": mock.patch.object(
                SYNC, "remote_management_placeholder_needed", return_value=False,
            ),
        }
        defaults.update(extra)
        return defaults

    def test_native_success_next_command_declares_server_role_to_real_load_parser(self):
        args = sync_args()
        patches = self._main_patches(args)
        patches.update({
            "gate": mock.patch.object(SYNC, "run_predeploy_test_gate"),
            "lock": mock.patch.object(
                SYNC, "acquire_remote_deployment_lock", return_value=object(),
            ),
            "preview": mock.patch.object(
                SYNC, "sync_jobs_have_changes", return_value=(object(),),
            ),
            "prewrite": mock.patch.object(
                SYNC, "prepare_remote_source_write", return_value=False,
            ),
            "commit_source": mock.patch.object(SYNC, "commit_remote_source_write"),
        })
        output = io.StringIO()
        with ExitStack() as stack:
            entered = {name: stack.enter_context(patch) for name, patch in patches.items()}
            stack.enter_context(redirect_stdout(output))
            self.assertEqual(0, SYNC.main([]))
        entered["run_job"].assert_called_once()
        entered["commit_source"].assert_called_once()
        next_lines = [
            line.strip() for line in output.getvalue().splitlines()
            if "11-load.py" in line and line.lstrip().startswith("cd ")
        ]
        self.assertEqual(1, len(next_lines))
        remote = shlex.split(next_lines[0])
        requested = remote[remote.index("11-load.py") + 1:]
        self.assertEqual(
            "management-server",
            LOAD.resolve_host_role(LOAD.parse_args(requested).host_role, "Linux"),
        )

    def test_formal_sync_tests_freezes_authority_and_rechecks_before_remote_lock(self):
        events: list[str] = []
        holder, readiness = self._exact_native_metadata_holder()
        patches = self._main_patches(sync_args())
        patches["metadata_readiness"] = readiness
        patches["gate"] = mock.patch.object(
            SYNC, "run_predeploy_test_gate",
            side_effect=lambda: events.append("test-all"),
        )

        def freeze_manifest(path: Path) -> None:
            events.append("freeze-manifest")
            path.write_bytes(b"independently frozen manifest fixture\n")

        patches["write_manifest"] = mock.patch.object(
            SYNC.project_contract, "write_deployment_source_manifest",
            side_effect=freeze_manifest,
        )
        patches["freeze_guard"] = mock.patch.object(
            SYNC.project_contract, "deployment_prewrite_guard_source",
            side_effect=lambda _manifest: events.append("freeze-guard")
            or "frozen guard fixture",
        )
        patches["freeze_password_contract"] = mock.patch.object(
            SYNC, "load_frozen_password_contract",
            side_effect=lambda _manifest: events.append("freeze-password-contract")
            or object(),
        )
        patches["approval"] = mock.patch.object(
            SYNC, "verify_predeploy_test_approval",
            side_effect=lambda: events.append("check"),
        )
        patches["lock"] = mock.patch.object(
            SYNC, "acquire_remote_deployment_lock",
            side_effect=lambda _args: events.append("remote-lock") or holder,
        )
        with ExitStack() as stack:
            for patcher in patches.values():
                stack.enter_context(patcher)
            stack.enter_context(redirect_stdout(io.StringIO()))
            stack.enter_context(redirect_stderr(io.StringIO()))
            result = SYNC.main([])
        self.assertEqual(0, result)
        self._assert_exact_native_read_only_probe(holder)
        self.assertEqual(
            [
                "test-all", "freeze-manifest", "freeze-guard",
                "freeze-password-contract", "check",
                "remote-lock",
            ],
            events,
        )

    def test_validation_sync_entrypoint_passes_intent_to_both_full_checks(self):
        args = sync_args()
        args.validation_only = True
        patches = self._main_patches(args)
        holder, readiness = self._exact_native_metadata_holder()
        patches["metadata_readiness"] = readiness
        patches["gate"] = mock.patch.object(SYNC, "run_predeploy_test_gate")
        patches["approval"] = mock.patch.object(SYNC, "verify_predeploy_test_approval")
        patches["lock"] = mock.patch.object(
            SYNC, "acquire_remote_deployment_lock", return_value=holder,
        )
        with ExitStack() as stack:
            entered = {
                name: stack.enter_context(patcher)
                for name, patcher in patches.items()
            }
            stack.enter_context(redirect_stdout(io.StringIO()))
            stack.enter_context(redirect_stderr(io.StringIO()))
            self.assertEqual(0, SYNC.main(["customer", "host", "--validation-only"]))
        entered["gate"].assert_called_once_with(validation_only=True)
        entered["approval"].assert_called_once_with(validation_only=True)
        self._assert_exact_native_read_only_probe(holder)

    def test_failed_sync_gate_has_no_remote_side_effect(self):
        patches = self._main_patches(sync_args())
        patches["gate"] = mock.patch.object(
            SYNC, "run_predeploy_test_gate", side_effect=RuntimeError("tests failed")
        )
        patches["lock"] = mock.patch.object(SYNC, "acquire_remote_deployment_lock")
        with ExitStack() as stack:
            entered = {
                name: stack.enter_context(patcher)
                for name, patcher in patches.items()
            }
            stack.enter_context(redirect_stdout(io.StringIO()))
            stack.enter_context(redirect_stderr(io.StringIO()))
            result = SYNC.main([])
        self.assertEqual(1, result)
        entered["lock"].assert_not_called()
        entered["write_manifest"].assert_not_called()
        entered["freeze_guard"].assert_not_called()
        entered["approval"].assert_not_called()
        entered["ensure_remote_directories"].assert_not_called()
        entered["set_remote_sync_marker"].assert_not_called()
        entered["run_job"].assert_not_called()

    def test_sync_dry_run_does_not_run_gate(self):
        events: list[str] = []
        patches = self._main_patches(sync_args(dry_run=True))
        patches["gate"] = mock.patch.object(SYNC, "run_predeploy_test_gate")
        patches["approval"] = mock.patch.object(
            SYNC, "verify_predeploy_test_approval",
        )

        def freeze_manifest(path: Path) -> None:
            events.append("freeze-manifest")
            path.write_bytes(b"independently frozen manifest fixture\n")

        patches["write_manifest"] = mock.patch.object(
            SYNC.project_contract, "write_deployment_source_manifest",
            side_effect=freeze_manifest,
        )
        patches["freeze_guard"] = mock.patch.object(
            SYNC.project_contract, "deployment_prewrite_guard_source",
            side_effect=lambda _manifest: events.append("freeze-guard")
            or "frozen guard fixture",
        )
        patches["freeze_password_contract"] = mock.patch.object(
            SYNC, "load_frozen_password_contract",
            side_effect=lambda _manifest: events.append("freeze-password-contract")
            or object(),
        )
        patches["lock"] = mock.patch.object(
            SYNC, "acquire_remote_deployment_lock",
            side_effect=lambda _args: events.append("dry-lock-plan") or None,
        )
        patches["prepare_global_sync"] = mock.patch.object(
            SYNC, "prepare_global_sync",
            side_effect=lambda _project, _args: events.append("first-remote-read")
            or SimpleNamespace(
                changed=False,
            ),
        )
        with ExitStack() as stack:
            entered = {
                name: stack.enter_context(patcher)
                for name, patcher in patches.items()
            }
            stack.enter_context(redirect_stdout(io.StringIO()))
            stack.enter_context(redirect_stderr(io.StringIO()))
            result = SYNC.main([])
        self.assertEqual(0, result)
        entered["gate"].assert_not_called()
        entered["approval"].assert_not_called()
        self.assertEqual(
            [
                "freeze-manifest", "freeze-guard", "freeze-password-contract",
                "dry-lock-plan",
                "first-remote-read",
            ],
            events,
        )

    def test_docker_dry_run_previews_global_change_without_rebuild_marker(self):
        args = sync_args(dry_run=True)
        args.runtime = "docker"
        patches = self._main_patches(args)
        patches["prepare_global_sync"] = mock.patch.object(
            SYNC, "prepare_global_sync",
            return_value=SimpleNamespace(changed=True),
        )
        with ExitStack() as stack:
            for patcher in patches.values():
                stack.enter_context(patcher)
            stack.enter_context(redirect_stdout(io.StringIO()))
            stack.enter_context(redirect_stderr(io.StringIO()))
            result = SYNC.main([])
        self.assertEqual(0, result)


class UploadGateTests(unittest.TestCase):
    def _run_private_preview(self) -> tuple[Path, int, str]:
        args = upload_args(deploy=False, dry_run=True)
        args.output = None
        observed: dict[str, object] = {}

        def create_preview(actual_args, *, day0_all, artifact_kind):
            self.assertFalse(day0_all)
            self.assertEqual("preview", artifact_kind)
            archive = actual_args.output
            self.assertIsInstance(archive, Path)
            observed["archive"] = archive
            observed["mode"] = stat.S_IMODE(archive.parent.stat().st_mode)
            with tarfile.open(archive, "w:gz") as stream:
                payload = b"preview only\n"
                member = tarfile.TarInfo("preview.txt")
                member.size = len(payload)
                stream.addfile(member, io.BytesIO(payload))
            try:
                INSTALLER.verify_inputs(
                    archive,
                    TOOLS / "deploy-upload-archive.py",
                    required_uid=os.getuid(),
                )
            except INSTALLER.InstallError as exc:
                observed["live_installer_error"] = str(exc)
            else:
                self.fail("a live preview archive was accepted by the installer")
            return archive

        with mock.patch.object(UPLOAD, "parse_args", return_value=args), \
             mock.patch.object(
                 UPLOAD.package_core, "resolve_project",
                 return_value=Path("/tmp/customer"),
             ), mock.patch.object(UPLOAD, "resolve_apps_policy"), \
             mock.patch.object(
                 UPLOAD.package_core, "create_package", side_effect=create_preview,
             ), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(0, UPLOAD.main([]))

        return (
            observed["archive"], observed["mode"],
            observed["live_installer_error"],
        )

    def test_dry_run_preview_directory_is_private_and_removed_on_exit(self):
        preview, directory_mode, installer_error = self._run_private_preview()
        self.assertEqual(0o700, directory_mode)
        self.assertRegex(installer_error, "archive is missing (?:installer|guard|source manifest)")
        self.assertNotIn("No such file", installer_error)
        self.assertFalse(preview.exists())
        self.assertFalse(preview.parent.exists())

    def test_deleted_dry_run_preview_is_unconsumable_by_relay_installer(self):
        preview, _directory_mode, _installer_error = self._run_private_preview()
        with self.assertRaisesRegex(
            INSTALLER.InstallError, "upload archive|No such file",
        ):
            INSTALLER.verify_inputs(
                preview, TOOLS / "deploy-upload-archive.py",
                required_uid=os.getuid(),
            )

    def test_dry_run_cannot_publish_a_deployable_archive(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            UPLOAD.parse_args([
                "customer", "--dry-run", "--output",
                "/tmp/customer-preview-upload.tar.gz",
            ])
        self.assertEqual(2, raised.exception.code)

    def test_relay_bundle_cli_needs_no_host_and_rejects_mixed_transport_modes(self):
        destination = "/tmp/customer-upload-release"
        args = UPLOAD.parse_args([
            "customer", "--runtime", "docker", "--relay-bundle", destination,
        ])
        self.assertIsNone(args.host)
        self.assertEqual(Path(destination), args.relay_bundle)
        self.assertFalse(args.deploy)
        self.assertFalse(args.dry_run)

        conflicts = (
            ["ubuntu@worker.example"],
            ["--host", "ubuntu@worker.example"],
            ["--deploy"],
            ["--deploy-uploaded", "/tmp/reviewed.tar.gz"],
            ["--dry-run"],
            ["--output", "/tmp/archive.tar.gz"],
            ["--include-images"],
            ["--include-apps", "--target-os", "ubuntu-24.04",
             "--target-arch", "amd64"],
            ["--include-firmware"],
        )
        for conflict in conflicts:
            with self.subTest(conflict=conflict), redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as raised:
                UPLOAD.parse_args([
                    "customer", "--runtime", "docker",
                    "--relay-bundle", destination, *conflict,
                ])
            self.assertEqual(2, raised.exception.code)

    def test_relay_bundle_runs_attestation_and_packaging_without_any_ssh(self):
        args = upload_args(deploy=False, dry_run=False)
        args.host = None
        args.relay_bundle = Path("/tmp/customer-upload-release")
        events = []
        project = ROOT / "DAY0-Prepare/customer"
        with mock.patch.object(UPLOAD, "parse_args", return_value=args), \
             mock.patch.object(
                 UPLOAD.package_core, "resolve_project", return_value=project,
             ), mock.patch.object(
                 UPLOAD, "run_predeploy_test_gate",
                 side_effect=lambda: events.append("attestation"),
             ), mock.patch.object(
                 UPLOAD, "build_relay_bundle",
                 side_effect=lambda actual_args, actual_project:
                 events.append(("bundle", actual_args, actual_project))
                 or args.relay_bundle,
             ), mock.patch.object(UPLOAD, "resolve_apps_policy") as apps, \
             mock.patch.object(UPLOAD, "upload") as upload, \
             redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(0, UPLOAD.main([]))

        self.assertEqual("attestation", events[0])
        self.assertEqual(("bundle", args, project), events[1])
        apps.assert_not_called()
        upload.assert_not_called()

    def test_deploy_uploaded_cli_is_reuse_only_and_rejects_package_options(self):
        base = [
            "customer", "--host", "ubuntu@worker.example",
            "--runtime", "native", "--deploy-uploaded", "/tmp/reviewed.tar.gz",
        ]
        args = UPLOAD.parse_args(base)
        self.assertTrue(args.deploy)
        self.assertEqual(Path("/tmp/reviewed.tar.gz"), args.deploy_uploaded)
        self.assertIsNone(args.output)

        conflicts = (
            ["--deploy"], ["--dry-run"], ["--include-images"],
            ["--exclude-apps"], ["--force"], ["--output", "/tmp/new.tar.gz"],
        )
        for conflict in conflicts:
            with self.subTest(conflict=conflict), redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as raised:
                UPLOAD.parse_args(base + conflict)
            self.assertEqual(2, raised.exception.code)

    def test_deploy_uploaded_requires_current_manifest_and_project_inputs(self):
        manifest = b'{"schema_version":1,"files":[]}\n'
        project = ROOT / "DAY0-Prepare/customer"

        def write_archive(path: Path, *, omit: str | None = None) -> None:
            members = {
                "./infra/docker/deployment-source-manifest.json": manifest,
                "./tools/deployment_prewrite_guard.py": b"guard\n",
                "./DAY0-Prepare/customer/01-global.yaml": b"global: true\n",
                "./DAY0-Prepare/customer/02-devices_config.csv": b"hostname\n",
                "./DAY0-Prepare/customer/02-dhcp-subnet_config.csv": b"subnet\n",
            }
            if omit is not None:
                members.pop(omit)
            with tarfile.open(path, "w:gz") as archive:
                for name, payload in members.items():
                    info = tarfile.TarInfo(name)
                    info.size = len(payload)
                    archive.addfile(info, io.BytesIO(payload))

        def manifest_writer(payload: bytes):
            def write(path: Path) -> Path:
                path.write_bytes(payload)
                return path
            return write

        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "reviewed.tar.gz"
            write_archive(archive)
            with mock.patch.object(
                UPLOAD.package_core, "write_deployment_source_manifest",
                side_effect=manifest_writer(manifest),
            ):
                UPLOAD.validate_uploaded_archive_for_deploy(archive, project)

            with mock.patch.object(
                UPLOAD.package_core, "write_deployment_source_manifest",
                side_effect=manifest_writer(b"different\n"),
            ), self.assertRaisesRegex(RuntimeError, "current tested production source"):
                UPLOAD.validate_uploaded_archive_for_deploy(archive, project)

            missing = "./DAY0-Prepare/customer/02-dhcp-subnet_config.csv"
            write_archive(archive, omit=missing)
            with self.assertRaisesRegex(RuntimeError, "missing required deployment members"):
                UPLOAD.validate_uploaded_archive_for_deploy(archive, project)

    def test_deploy_uploaded_warns_on_local_b_but_preserves_reviewed_a(self):
        """A reviewed upload stays A after local edits, with visible drift notice."""
        manifest = b'{"schema_version":1,"files":[]}\n'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "http"
            project = root / "DAY0-Prepare/customer"
            project.mkdir(parents=True)
            original = {
                "01-global.yaml": b"global: A\n",
                "02-devices_config.csv": b"hostname,type\nA,air\n",
                "02-dhcp-subnet_config.csv": b"subnet-A\n",
            }
            for name, payload in original.items():
                (project / name).write_bytes(payload)
            archive_path = Path(directory) / "reviewed-A.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                members = {
                    "./infra/docker/deployment-source-manifest.json": manifest,
                    "./tools/deployment_prewrite_guard.py": b"guard\n",
                    **{
                        f"./DAY0-Prepare/customer/{name}": payload
                        for name, payload in original.items()
                    },
                }
                for name, payload in members.items():
                    info = tarfile.TarInfo(name)
                    info.size = len(payload)
                    archive.addfile(info, io.BytesIO(payload))
            (project / "02-devices_config.csv").write_bytes(b"hostname,type\nB,air\n")
            output = io.StringIO()

            def write_current_manifest(path):
                path.write_bytes(manifest)
                return path

            with mock.patch.object(UPLOAD, "ROOT", root), mock.patch.object(
                UPLOAD.package_core, "ROOT", root,
            ), mock.patch.object(
                UPLOAD.package_core, "write_deployment_source_manifest",
                side_effect=write_current_manifest,
            ), redirect_stdout(output):
                UPLOAD.validate_uploaded_archive_for_deploy(archive_path, project)
            notice = output.getvalue()
            self.assertIn("[WARN]", notice)
            self.assertIn("02-devices_config.csv", notice)
            self.assertIn("归档", notice)
            self.assertIn("本地", notice)
            self.assertEqual(b"hostname,type\nB,air\n", (
                project / "02-devices_config.csv"
            ).read_bytes())
            with tarfile.open(archive_path, "r:gz") as archive:
                member = archive.extractfile(
                    "./DAY0-Prepare/customer/02-devices_config.csv"
                )
                self.assertIsNotNone(member)
                self.assertEqual(original["02-devices_config.csv"], member.read())

    def test_every_real_upload_tests_packages_rechecks_then_connects(self):
        for deploy in (False, True):
            with self.subTest(deploy=deploy):
                args = upload_args(deploy=deploy, dry_run=False)
                events: list[str] = []

                def remote_upload(
                    actual_args: argparse.Namespace, archive: Path, *,
                    expected_sha256: str,
                ) -> None:
                    self.assertIs(args, actual_args)
                    self.assertEqual(Path("/tmp/frozen-upload.tar.gz"), archive)
                    self.assertEqual("f" * 64, expected_sha256)
                    events.append("remote-upload")

                def create_upload(
                    actual_args: argparse.Namespace, *, day0_all: bool,
                    artifact_kind: str,
                ) -> Path:
                    self.assertIs(args, actual_args)
                    self.assertFalse(day0_all)
                    self.assertEqual("upload", artifact_kind)
                    events.append("package:upload")
                    return Path("/tmp/customer-upload.tar.gz")

                with (
                    mock.patch.object(UPLOAD, "parse_args", return_value=args),
                    mock.patch.object(
                        UPLOAD.package_core, "resolve_project",
                        return_value=Path("/tmp/customer"),
                    ),
                    mock.patch.object(
                        UPLOAD, "run_predeploy_test_gate",
                        side_effect=lambda: events.append("test-all"),
                    ),
                    mock.patch.object(
                        UPLOAD, "verify_predeploy_test_approval",
                        side_effect=lambda: events.append("check"),
                    ),
                    mock.patch.object(
                        UPLOAD, "resolve_apps_policy",
                        side_effect=lambda _args: events.append("policy"),
                    ),
                    mock.patch.object(
                        UPLOAD.package_core, "create_package",
                        side_effect=create_upload,
                    ),
                    mock.patch.object(
                        UPLOAD, "frozen_archive_for_upload",
                        side_effect=lambda _archive: events.append("freeze-archive")
                        or nullcontext((Path("/tmp/frozen-upload.tar.gz"), "f" * 64)),
                    ),
                    mock.patch.object(
                        UPLOAD, "deployment_guard_source_from_archive",
                        side_effect=lambda _archive: events.append("read-frozen-guard")
                        or "frozen guard fixture",
                    ),
                    mock.patch.object(
                        UPLOAD, "deployment_source_manifest_sha256_from_archive",
                        side_effect=lambda _archive: events.append("read-frozen-manifest")
                        or "d" * 64,
                    ),
                    mock.patch.object(
                        UPLOAD, "upload",
                        side_effect=remote_upload,
                    ),
                    redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()),
                ):
                    result = UPLOAD.main([])
                self.assertEqual(0, result)
                self.assertEqual(
                    [
                        "policy", "test-all", "package:upload", "freeze-archive",
                        "check", "read-frozen-guard", "read-frozen-manifest",
                        "remote-upload",
                    ],
                    events,
                )

    def test_validation_upload_entrypoint_passes_intent_to_both_full_checks(self):
        args = upload_args(deploy=False, dry_run=False)
        args.validation_only = True
        with (
            mock.patch.object(UPLOAD, "parse_args", return_value=args),
            mock.patch.object(
                UPLOAD.package_core, "resolve_project",
                return_value=Path("/tmp/customer"),
            ),
            mock.patch.object(UPLOAD, "run_predeploy_test_gate") as gate,
            mock.patch.object(UPLOAD, "verify_predeploy_test_approval") as verify,
            mock.patch.object(UPLOAD, "resolve_apps_policy"),
            mock.patch.object(
                UPLOAD.package_core, "create_package",
                return_value=Path("/tmp/customer-upload.tar.gz"),
            ),
            mock.patch.object(
                UPLOAD, "frozen_archive_for_upload",
                return_value=nullcontext((Path("/tmp/frozen-upload.tar.gz"), "f" * 64)),
            ),
            mock.patch.object(
                UPLOAD, "deployment_guard_source_from_archive",
                return_value="frozen guard fixture",
            ),
            mock.patch.object(
                UPLOAD, "deployment_source_manifest_sha256_from_archive",
                return_value="d" * 64,
            ),
            mock.patch.object(UPLOAD, "upload"),
            redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(0, UPLOAD.main(["customer", "host", "--validation-only"]))
        gate.assert_called_once_with(validation_only=True)
        verify.assert_called_once_with(validation_only=True)

    def test_failed_upload_gate_never_builds_or_connects(self):
        args = upload_args(deploy=False, dry_run=False)
        with (
            mock.patch.object(UPLOAD, "parse_args", return_value=args),
            mock.patch.object(
                UPLOAD.package_core, "resolve_project", return_value=Path("/tmp/customer")
            ),
            mock.patch.object(
                UPLOAD, "run_predeploy_test_gate", side_effect=RuntimeError("failed")
            ),
            mock.patch.object(UPLOAD, "verify_predeploy_test_approval") as check,
            mock.patch.object(UPLOAD, "resolve_apps_policy") as policy,
            mock.patch.object(UPLOAD.package_core, "create_package") as create,
            mock.patch.object(UPLOAD, "upload") as remote,
            redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()),
        ):
            result = UPLOAD.main([])
        self.assertEqual(1, result)
        policy.assert_called_once_with(args)
        check.assert_not_called()
        create.assert_not_called()
        remote.assert_not_called()

    def test_post_package_check_failure_never_connects(self):
        args = upload_args(deploy=False, dry_run=False)
        with (
            mock.patch.object(UPLOAD, "parse_args", return_value=args),
            mock.patch.object(
                UPLOAD.package_core, "resolve_project", return_value=Path("/tmp/customer")
            ),
            mock.patch.object(UPLOAD, "run_predeploy_test_gate"),
            mock.patch.object(
                UPLOAD, "verify_predeploy_test_approval",
                side_effect=RuntimeError("source changed"),
            ),
            mock.patch.object(UPLOAD, "resolve_apps_policy"),
            mock.patch.object(
                UPLOAD.package_core, "create_package",
                return_value=Path("/tmp/customer-upload.tar.gz"),
            ),
            mock.patch.object(
                UPLOAD, "frozen_archive_for_upload",
                return_value=nullcontext(
                    (Path("/tmp/frozen-upload.tar.gz"), "f" * 64),
                ),
            ),
            mock.patch.object(
                UPLOAD, "deployment_guard_source_from_archive",
            ) as guard,
            mock.patch.object(
                UPLOAD, "deployment_source_manifest_sha256_from_archive",
            ) as manifest,
            mock.patch.object(UPLOAD, "upload") as remote,
            redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()),
        ):
            result = UPLOAD.main([])
        self.assertEqual(1, result)
        guard.assert_not_called()
        manifest.assert_not_called()
        remote.assert_not_called()

    def test_only_dry_run_skips_both_test_gates(self):
        for deploy in (False, True):
            with self.subTest(deploy=deploy):
                args = upload_args(deploy=deploy, dry_run=True)
                with (
                    mock.patch.object(UPLOAD, "parse_args", return_value=args),
                    mock.patch.object(
                        UPLOAD.package_core, "resolve_project",
                        return_value=Path("/tmp/customer"),
                    ),
                    mock.patch.object(UPLOAD, "run_predeploy_test_gate") as gate,
                    mock.patch.object(
                        UPLOAD, "verify_predeploy_test_approval"
                    ) as check,
                    mock.patch.object(UPLOAD, "resolve_apps_policy"),
                    mock.patch.object(
                        UPLOAD.package_core, "create_package",
                        return_value=Path("/tmp/customer-upload.tar.gz"),
                    ),
                    mock.patch.object(UPLOAD, "print_archive_manifest"),
                    mock.patch.object(UPLOAD, "upload"),
                    redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()),
                ):
                    result = UPLOAD.main([])
                self.assertEqual(0, result)
                gate.assert_not_called()
                check.assert_not_called()

    def test_short_next_command_replaces_raw_remote_shell(self):
        args = SimpleNamespace(
            project="DAY0-Prepare/customer project", host="ubuntu@worker.example",
            port=21079, identity=None, transport="auto", upload_retries=3,
            transfer_timeout=3600, remote_dir="/tmp", remote_root="/var/www/html",
            deploy=False, no_sudo=False, include_images=False, include_apps=False,
            target_os=None, target_arch=None, client_platform=[],
            include_firmware=False,
            max_file_size_mib=UPLOAD.package_core.DEFAULT_MAX_FILE_MIB,
            output=Path("/tmp/customer-reviewed-upload.tar.gz"),
        )
        command = UPLOAD.recommended_deploy_rerun_command(args)
        self.assertEqual("python3", command[0])
        self.assertIn("--deploy-uploaded", command)
        self.assertIn(str(args.output), command)
        self.assertNotIn("--deploy", command)
        self.assertNotIn("--host", command)
        self.assertEqual(args.host, command[3])
        self.assertNotIn("--exclude-apps", command)
        rendered = __import__("shlex").join(command)
        self.assertIn("'DAY0-Prepare/customer project'", rendered)
        self.assertNotIn("deployment.lock", rendered)
        self.assertNotIn("sh -c", rendered)

        load_command = UPLOAD.recommended_remote_load_command(
            args, Path("/tmp/customer"),
        )
        self.assertEqual("ssh", load_command[0])
        self.assertIn("-t", load_command)
        self.assertEqual("ubuntu@worker.example", load_command[-2])
        self.assertEqual(
            "cd /var/www/html/DAY0-Prepare && "
            "sudo -n python3 11-load.py customer --host-role=management-server",
            load_command[-1],
        )

        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "customer-upload.tar.gz"
            archive.write_bytes(b"approved payload")
            with mock.patch.object(
                UPLOAD, "remote_sha256",
                return_value=UPLOAD.package_core.sha256(archive),
            ), redirect_stdout(io.StringIO()) as output:
                UPLOAD.upload(args, archive)
        text = output.getvalue()
        self.assertIn("[STATE] 已上传并校验，但尚未部署", text)
        self.assertIn("[NEXT A]", text)
        self.assertIn("[NEXT B]", text)
        self.assertIn("--deploy-uploaded", text)
        self.assertIn("deploy-upload-archive.py", text)
        self.assertIn("--verify-only", text)
        self.assertIn("sudo install -o root -g root -m 0600", text)
        self.assertIn(str(args.output), text)
        self.assertIn("不会重新打包", text)
        self.assertIn("不会重新传输", text)
        self.assertNotIn("deployment.lock", text)
        self.assertNotIn("sudo -n sh -c", text)

    def test_deploy_uploaded_reuses_exact_archive_without_repackaging(self):
        args = upload_args(deploy=False, dry_run=False)
        args.deploy_uploaded = Path("/tmp/reviewed-upload.tar.gz")
        args.include_apps = None
        project = ROOT / "DAY0-Prepare/customer"
        frozen = Path("/private/tmp/frozen-reviewed-upload.tar.gz")
        events = []

        def frozen_archive(path):
            self.assertEqual(args.deploy_uploaded, path)
            events.append("freeze")
            return nullcontext((frozen, "a" * 64))

        with mock.patch.object(UPLOAD, "parse_args", return_value=args), \
             mock.patch.object(UPLOAD.package_core, "resolve_project", return_value=project), \
             mock.patch.object(UPLOAD, "resolve_apps_policy") as apps, \
             mock.patch.object(UPLOAD.package_core, "create_package") as package, \
             mock.patch.object(
                 UPLOAD, "run_predeploy_test_gate",
                 side_effect=lambda: events.append("gate"),
             ), mock.patch.object(
                 UPLOAD, "frozen_archive_for_upload", side_effect=frozen_archive,
             ), mock.patch.object(
                 UPLOAD, "verify_predeploy_test_approval",
                 side_effect=lambda: events.append("check"),
             ), mock.patch.object(
                 UPLOAD, "validate_uploaded_archive_for_deploy",
                 side_effect=lambda path, selected: events.append(
                     ("validate", path, selected)
                 ),
             ), mock.patch.object(
                 UPLOAD, "deployment_guard_source_from_archive", return_value="guard",
             ), mock.patch.object(
                 UPLOAD, "deployment_source_manifest_sha256_from_archive",
                 return_value="b" * 64,
             ), mock.patch.object(
                 UPLOAD, "upload", side_effect=lambda *_args, **_kwargs: events.append("deploy"),
             ), mock.patch.object(
                 UPLOAD, "recommended_remote_load_command", return_value=["ssh", "load"],
             ), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(0, UPLOAD.main([]))

        apps.assert_not_called()
        package.assert_not_called()
        self.assertEqual(
            [
                "gate", "freeze", "check", ("validate", frozen, project), "deploy",
            ],
            events,
        )
        self.assertTrue(args.deploy)


if __name__ == "__main__":
    unittest.main()
