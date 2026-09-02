#!/usr/bin/env python3
"""Isolated contracts for remote code-tree deployment writers."""

from __future__ import annotations

import argparse
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import shlex
import subprocess
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


SYNC = load_module("deployment_writer_sync", TOOLS / "sync-code.py")
UPLOAD = load_module("deployment_writer_upload", TOOLS / "tar-for-upload.py")


def sync_args(**overrides):
    values = {
        "project": "customer",
        "host": "ubuntu@worker.example",
        "port": 24995,
        "identity": None,
        "remote_root": "/var/www/html",
        "sudo": True,
        "dry_run": False,
        "include_ztp_runtime": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def upload_args(**overrides):
    values = {
        "host": "ubuntu@worker.example",
        "port": 24995,
        "identity": None,
        "remote_dir": "/tmp",
        "remote_root": "/var/www/html",
        "deploy": False,
        "no_sudo": False,
        "transport": "auto",
        "upload_retries": 3,
        "transfer_timeout": 3600,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


class SyncDeploymentLockTests(unittest.TestCase):
    def test_remote_holder_uses_same_nonblocking_flock_as_load(self):
        command = SYNC.remote_deployment_lock_command(sync_args())
        self.assertEqual("ssh", command[0])
        self.assertIn("ServerAliveInterval=15", command)
        remote = shlex.split(command[-1])
        self.assertEqual(["sudo", "-n", "sh", "-c"], remote[:4])
        self.assertEqual("/var/www/html/.deployment.lock", remote[-1])
        self.assertIn("exec 9>>", remote[4])
        self.assertIn("stat -Lc %h", remote[4])
        self.assertIn("flock -n -E 75 9", remote[4])
        self.assertIn(SYNC.DEPLOYMENT_LOCK_READY, remote[4])
        self.assertIn("cat >/dev/null", remote[4])

    def test_dry_run_never_opens_remote_lock_connection(self):
        with mock.patch.object(SYNC.subprocess, "Popen") as popen:
            result = SYNC.acquire_remote_deployment_lock(sync_args(dry_run=True))
        self.assertIsNone(result)
        popen.assert_not_called()

    def test_remote_marker_command_survives_openssh_shell_round_trip(self):
        """The command after the SSH host must be one fully quoted string."""
        with tempfile.TemporaryDirectory() as directory:
            args = sync_args(remote_root=directory, sudo=False)
            marker = Path(directory) / ".sync-code-in-progress"
            # Production runs on GNU/Linux; provide the one GNU stat operation
            # used by the guard so this wire-format test is also portable to
            # the macOS development host.
            fake_bin = Path(directory) / "bin"
            fake_bin.mkdir()
            fake_stat = fake_bin / "stat"
            fake_stat.write_text("#!/bin/sh\nprintf '1\\n'\n", encoding="utf-8")
            fake_stat.chmod(0o755)
            environment = dict(os.environ)
            environment["PATH"] = f"{fake_bin}:{environment.get('PATH', '')}"

            create = SYNC.remote_sync_marker_command(args, present=True)
            self.assertEqual(args.host, create[-2])
            self.assertEqual(len(create), create.index(args.host) + 2)
            create_remote = shlex.split(create[-1])
            self.assertEqual(["sh", "-c"], create_remote[:2])
            self.assertEqual("sync-marker", create_remote[-2])
            self.assertEqual(str(marker), create_remote[-1])
            created = subprocess.run(
                ["sh", "-c", create[-1]], check=False,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                env=environment,
            )
            self.assertEqual(0, created.returncode, created.stderr)
            self.assertTrue(marker.is_file())

            remove = SYNC.remote_sync_marker_command(args, present=False)
            removed = subprocess.run(
                ["sh", "-c", remove[-1]], check=False,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                env=environment,
            )
            self.assertEqual(0, removed.returncode, removed.stderr)
            self.assertFalse(marker.exists())

    def test_main_holds_lock_through_final_marker_promotion_and_requires_load(self):
        events: list[str] = []
        args = sync_args()
        project = Path("/tmp/customer")
        job = SYNC.SyncJob("one", (Path("/tmp/source"),), "/var/www/html/one")
        lock = object()

        with (
            mock.patch.object(SYNC, "parse_args", return_value=args),
            mock.patch.object(SYNC, "validate_args"),
            mock.patch.object(SYNC, "resolve_project", return_value=project),
            mock.patch.object(SYNC, "build_jobs", return_value=[job]),
            mock.patch.object(SYNC, "run_predeploy_test_gate"),
            mock.patch.object(
                SYNC, "acquire_remote_deployment_lock",
                side_effect=lambda _args: events.append("lock") or lock,
            ),
            mock.patch.object(
                SYNC, "ensure_remote_directories",
                side_effect=lambda _jobs, _args: events.append("directories"),
            ),
            mock.patch.object(
                SYNC, "assert_remote_deployment_lock",
                side_effect=lambda _lock: events.append("held"),
            ),
            mock.patch.object(
                SYNC, "set_remote_sync_marker",
                side_effect=lambda _args, *, present: events.append(
                    "marker:on" if present else "marker:off"
                ),
            ),
            mock.patch.object(
                SYNC, "run_job",
                side_effect=lambda _job, _args: events.append("rsync"),
            ),
            mock.patch.object(
                SYNC, "ensure_remote_management_placeholder",
                side_effect=lambda _project, _args: events.append("placeholder"),
            ),
            mock.patch.object(
                SYNC, "release_remote_deployment_lock",
                side_effect=lambda _lock: events.append("unlock"),
            ),
        ):
            output = io.StringIO()
            with redirect_stdout(output):
                result = SYNC.main([])

        self.assertEqual(0, result)
        self.assertEqual(
            [
                "lock", "directories", "held", "marker:on", "held", "rsync",
                "held", "placeholder", "held", "marker:off", "unlock",
            ],
            events,
        )
        text = output.getvalue()
        self.assertIn("resident worker", text)
        self.assertIn("必须重新执行", text)
        self.assertNotIn("按需要", text)

    def test_failed_sync_releases_lock_but_keeps_persistent_marker(self):
        events: list[str] = []
        args = sync_args()
        job = SYNC.SyncJob("one", (Path("/tmp/source"),), "/var/www/html/one")
        with (
            mock.patch.object(SYNC, "parse_args", return_value=args),
            mock.patch.object(SYNC, "validate_args"),
            mock.patch.object(SYNC, "resolve_project", return_value=Path("/tmp/customer")),
            mock.patch.object(SYNC, "build_jobs", return_value=[job]),
            mock.patch.object(SYNC, "run_predeploy_test_gate"),
            mock.patch.object(SYNC, "acquire_remote_deployment_lock", return_value=object()),
            mock.patch.object(SYNC, "ensure_remote_directories"),
            mock.patch.object(SYNC, "assert_remote_deployment_lock"),
            mock.patch.object(
                SYNC, "set_remote_sync_marker",
                side_effect=lambda _args, *, present: events.append(
                    "marker:on" if present else "marker:off"
                ),
            ),
            mock.patch.object(SYNC, "run_job", side_effect=RuntimeError("broken rsync")),
            mock.patch.object(
                SYNC, "release_remote_deployment_lock",
                side_effect=lambda _lock: events.append("unlock"),
            ),
        ):
            with redirect_stdout(io.StringIO()):
                result = SYNC.main([])
        self.assertEqual(1, result)
        self.assertEqual(["marker:on", "unlock"], events)


class ArchiveDeploymentLockTests(unittest.TestCase):
    def test_extract_payload_holds_lock_and_clears_marker_only_after_tar(self):
        payload = UPLOAD.deployment_payload_command(
            upload_args(), "/tmp/customer-upload.tar.gz",
        )
        remote = shlex.split(payload)
        self.assertEqual(["sudo", "-n", "sh", "-c"], remote[:4])
        self.assertEqual("/var/www/html/.deployment.lock", remote[-1])
        script = remote[4]
        marker = "/var/www/html/.sync-code-in-progress"
        self.assertLess(script.index(f"install -m 0644 /dev/null {marker}"), script.index("tar "))
        self.assertLess(script.index("tar "), script.index(f"rm -f -- {marker}"))
        self.assertTrue(script.startswith("set -eu;"))

    def test_upload_without_deploy_does_not_execute_remote_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "customer-upload.tar.gz"
            archive.write_bytes(b"payload")
            digest = hashlib.sha256(b"payload").hexdigest()
            args = upload_args(deploy=False)
            with (
                mock.patch.object(UPLOAD, "remote_sha256", return_value=digest),
                mock.patch.object(UPLOAD, "run") as run,
                redirect_stdout(io.StringIO()),
            ):
                UPLOAD.upload(args, archive)
        run.assert_not_called()

    def test_deploy_executes_one_locked_remote_command(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "customer-upload.tar.gz"
            archive.write_bytes(b"payload")
            digest = hashlib.sha256(b"payload").hexdigest()
            args = upload_args(deploy=True)
            with (
                mock.patch.object(UPLOAD, "remote_sha256", return_value=digest),
                mock.patch.object(UPLOAD, "run", return_value="") as run,
                redirect_stdout(io.StringIO()),
            ):
                UPLOAD.upload(args, archive)
        run.assert_called_once()
        command = run.call_args.args[0]
        self.assertEqual("ssh", command[0])
        remote = shlex.split(command[-1])
        self.assertIn("flock -n -E 75 9", remote[4])
        self.assertIn("/var/www/html/.deployment.lock", remote)
        self.assertIn("/var/www/html/.sync-code-in-progress", remote[4])


if __name__ == "__main__":
    unittest.main()
