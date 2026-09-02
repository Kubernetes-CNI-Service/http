#!/usr/bin/env python3
"""Fail-closed, pre-connection test gates for the two deployment entrypoints."""

from __future__ import annotations

import argparse
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import importlib.util
import io
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest import mock


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


def sync_args(*, dry_run: bool = False) -> argparse.Namespace:
    return argparse.Namespace(
        project="customer", host="ubuntu@worker.example", port=24995,
        identity=None, remote_root="/var/www/html", sudo=True,
        dry_run=dry_run, include_ztp_runtime=False,
    )


def upload_args(*, deploy: bool, dry_run: bool) -> argparse.Namespace:
    return argparse.Namespace(
        project="customer", deploy=deploy, dry_run=dry_run,
        output=Path("/tmp/customer-upload.tar.gz"),
        host="ubuntu@worker.example", port=24995, identity=None,
        remote_root="/var/www/html", no_sudo=False,
    )


class GateCommandTests(unittest.TestCase):
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
                        [sys.executable, "-B", str(runner_path), "--all"],
                        cwd=SYNC.ROOT, shell=False, check=False,
                    ),
                    mock.call(
                        [sys.executable, "-B", str(runner_path), "--check"],
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
                        [sys.executable, "-B", str(runner_path), "--all"],
                        cwd=UPLOAD.ROOT, shell=False, check=False,
                    ),
                    mock.call(
                        [sys.executable, "-B", str(runner_path), "--check"],
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
    def _main_patches(self, args: argparse.Namespace, **extra):
        job = SYNC.SyncJob("one", (Path("/tmp/source"),), "/var/www/html/one")
        defaults = {
            "parse_args": mock.patch.object(SYNC, "parse_args", return_value=args),
            "validate_args": mock.patch.object(SYNC, "validate_args"),
            "resolve_project": mock.patch.object(
                SYNC, "resolve_project", return_value=Path("/tmp/customer")
            ),
            "build_jobs": mock.patch.object(SYNC, "build_jobs", return_value=[job]),
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
        }
        defaults.update(extra)
        return defaults

    def test_formal_sync_tests_before_remote_lock(self):
        events: list[str] = []
        patches = self._main_patches(sync_args())
        patches["gate"] = mock.patch.object(
            SYNC, "run_predeploy_test_gate",
            side_effect=lambda: events.append("test"),
        )
        patches["lock"] = mock.patch.object(
            SYNC, "acquire_remote_deployment_lock",
            side_effect=lambda _args: events.append("remote-lock") or None,
        )
        with ExitStack() as stack:
            for patcher in patches.values():
                stack.enter_context(patcher)
            stack.enter_context(redirect_stdout(io.StringIO()))
            stack.enter_context(redirect_stderr(io.StringIO()))
            result = SYNC.main([])
        self.assertEqual(0, result)
        self.assertEqual(["test", "remote-lock"], events)

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
        entered["ensure_remote_directories"].assert_not_called()
        entered["set_remote_sync_marker"].assert_not_called()
        entered["run_job"].assert_not_called()

    def test_sync_dry_run_does_not_run_gate(self):
        patches = self._main_patches(sync_args(dry_run=True))
        patches["gate"] = mock.patch.object(SYNC, "run_predeploy_test_gate")
        patches["lock"] = mock.patch.object(
            SYNC, "acquire_remote_deployment_lock", return_value=None
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


class UploadGateTests(unittest.TestCase):
    def test_every_real_upload_tests_packages_rechecks_then_connects(self):
        for deploy in (False, True):
            with self.subTest(deploy=deploy):
                args = upload_args(deploy=deploy, dry_run=False)
                events: list[str] = []
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
                        side_effect=lambda _args, day0_all: events.append("package")
                        or Path("/tmp/customer-upload.tar.gz"),
                    ),
                    mock.patch.object(
                        UPLOAD, "upload",
                        side_effect=lambda _args, _archive: events.append("remote-upload"),
                    ),
                    redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()),
                ):
                    result = UPLOAD.main([])
                self.assertEqual(0, result)
                self.assertEqual(
                    ["policy", "test-all", "package", "check", "remote-upload"],
                    events,
                )

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
            mock.patch.object(UPLOAD, "upload") as remote,
            redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()),
        ):
            result = UPLOAD.main([])
        self.assertEqual(1, result)
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
        )
        command = UPLOAD.recommended_deploy_rerun_command(args)
        self.assertEqual("python3", command[0])
        self.assertIn("--deploy", command)
        self.assertIn("--exclude-apps", command)
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
            "sudo -n python3 11-load.py customer",
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
        self.assertIn("[NEXT]", text)
        self.assertIn("--deploy", text)
        self.assertNotIn("deployment.lock", text)
        self.assertNotIn("sudo -n sh -c", text)


if __name__ == "__main__":
    unittest.main()
