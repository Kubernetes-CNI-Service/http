#!/usr/bin/env python3
"""Workflow contract for the Docker finished-project stop-only boundary."""

from __future__ import annotations

from contextlib import contextmanager
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases.test_docker_destructive_confirmation import (
    CONTAINER_ID,
    load_hostctl,
    run_dispatch,
)
from test_cases.test_ztp_container_runtime import load_script


TRANSACTION_ID = "finish-20260916T080220Z-0123456789abcdef"


class DockerFinishStopOnlyWorkflowTests(unittest.TestCase):
    def test_finish_authority_is_the_same_durable_bind_for_compose_and_plain_run(self):
        repository = Path(__file__).resolve().parents[1]
        compose = (repository / "infra/docker/compose.yaml").read_text()
        deploy = (repository / "infra/docker/deploy.sh").read_text()

        host = "/var/lib/http-ztp-finish"
        container = "/var/lib/http-ztp-finish"
        compose_mount = f"{host}:{container}"
        plain_mount = f"type=bind,src={host},dst={container}"

        self.assertEqual(1, compose.count(compose_mount))
        plain_run = deploy.split("plain_docker_run() {", 1)[1].split("\n}", 1)[0]
        self.assertEqual(1, plain_run.count(plain_mount))
        self.assertNotIn(plain_mount + ",readonly", plain_run)

    def test_runtime_identity_check_requires_exact_finish_authority_bind(self):
        hostlock = load_script("hostlock.py")

        def record(finish_mount):
            mounts = [
                {
                    "Type": "bind", "Source": "/var/www/html",
                    "Destination": "/var/www/html", "RW": True,
                },
                {
                    "Type": "bind",
                    "Source": "/var/lib/http-ztp-container/control-auth",
                    "Destination": "/etc/http-ztp", "RW": False,
                },
                {
                    "Type": "bind",
                    "Source": "/var/lib/http-ztp-container/monitor-auth",
                    "Destination": "/var/lib/http-ztp-monitor-auth", "RW": True,
                },
            ]
            if finish_mount is not None:
                mounts.append(finish_mount)
            return [{
                "Id": "a" * 64,
                "Image": "sha256:" + "b" * 64,
                "Name": "/http-ztp",
                "Config": {"Labels": {
                    "com.nvidia.http-ztp.managed": "true",
                    "com.nvidia.http-ztp.http-root": "/var/www/html",
                    "com.nvidia.http-ztp.image": "true",
                    "com.nvidia.http-ztp.image-contract": "3",
                    "com.nvidia.http-ztp.base-os": "ubuntu-24.04",
                }},
                "Mounts": mounts,
                "State": {},
            }]

        exact = {
            "Type": "bind", "Source": "/var/lib/http-ztp-finish",
            "Destination": "/var/lib/http-ztp-finish", "RW": True,
        }
        runner = mock.Mock(return_value=SimpleNamespace(
            returncode=0, stdout=json.dumps(record(exact)), stderr="",
        ))
        self.assertEqual("a" * 64, hostlock.inspect_owned_container(runner)["Id"])

        for invalid in (None, {**exact, "RW": False}, {
            **exact, "Source": "/var/lib/http-ztp-container/finish",
        }):
            with self.subTest(invalid=invalid):
                runner = mock.Mock(return_value=SimpleNamespace(
                    returncode=0, stdout=json.dumps(record(invalid)), stderr="",
                ))
                with self.assertRaisesRegex(
                    hostlock.HostLockError, "finish-state.*RW bind",
                ):
                    hostlock.inspect_owned_container(runner)

    def test_hostctl_validates_pending_transaction_before_any_cleanup(self):
        hostctl = load_hostctl()
        with tempfile.TemporaryDirectory() as name:
            state_root = Path(name)
            pending = state_root / "finish-pending.json"
            pending.write_text(json.dumps({
                "schema_version": 1,
                "transaction_id": TRANSACTION_ID,
                "project": "h28-project",
                "runtime": "docker",
            }) + "\n", encoding="utf-8")
            pending.chmod(0o600)
            settings = SimpleNamespace(
                http_root=Path("/var/www/html"), project_name="h28-project",
            )
            events: list[str] = []

            @contextmanager
            def held(_root):
                yield 9

            real_lstat = Path.lstat

            def root_owned_lstat(path):
                metadata = real_lstat(path)
                return SimpleNamespace(
                    st_uid=0,
                    st_nlink=metadata.st_nlink,
                    st_mode=metadata.st_mode,
                    st_size=metadata.st_size,
                )

            with mock.patch.object(hostctl, "FINISH_STATE_ROOT", state_root), \
                    mock.patch.object(hostctl.Path, "lstat", root_owned_lstat), \
                    mock.patch.object(
                        hostctl, "_lock_contract",
                        return_value=(hostctl.hostlock.HostLockError, held, lambda _fd: {}),
                    ), mock.patch.object(
                        hostctl.activate, "clear_activation",
                        side_effect=lambda _settings: events.append("clear"),
                    ), mock.patch.object(
                        hostctl, "stop_managed_services",
                        side_effect=lambda: events.append("stop"),
                    ), mock.patch.object(hostctl, "clear_quarantine"), \
                    mock.patch.object(hostctl, "clear_guardian_fault"):
                hostctl.deactivate(
                    settings, finish_transaction=TRANSACTION_ID,
                )
                self.assertEqual(["clear", "stop"], events)

                pending.write_text(json.dumps({
                    "schema_version": 1,
                    "transaction_id": "another-transaction",
                    "project": "h28-project",
                    "runtime": "docker",
                }) + "\n", encoding="utf-8")
                pending.chmod(0o600)
                with self.assertRaisesRegex(
                    hostctl.ControllerError, "another transaction",
                ):
                    hostctl.deactivate(
                        settings, finish_transaction=TRANSACTION_ID,
                    )
                self.assertEqual(["clear", "stop"], events)

    def test_stop_calls_deactivate_with_transaction_and_retains_container(self):
        with tempfile.TemporaryDirectory() as name:
            result, events = run_dispatch(
                Path(name), "stop", TRANSACTION_ID, answer=None,
            )

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn(
            "docker:exec " + CONTAINER_ID
            + " /opt/http-ztp/hostctl.py deactivate --finish-transaction "
            + TRANSACTION_ID,
            events,
        )
        self.assertFalse(any(" unload" in event for event in events), events)
        self.assertFalse(any("remove-clear" in event for event in events), events)
        self.assertFalse(any(event.startswith("docker:rm") for event in events), events)
        self.assertNotIn("Type literal yes", result.stdout)
        self.assertIn("container and persistent data remain available", result.stdout)

    def test_stop_requires_exactly_one_safe_transaction_id(self):
        invalid = (
            (),
            ("two", "arguments"),
            ("../escape",),
            ("contains space",),
            ("",),
        )
        for arguments in invalid:
            with self.subTest(arguments=arguments), tempfile.TemporaryDirectory() as name:
                result, events = run_dispatch(
                    Path(name), "stop", *arguments, answer=None,
                )
                self.assertNotEqual(0, result.returncode)
                self.assertEqual([], events)

    def test_stop_help_is_distinct_from_unload_and_down(self):
        deploy = (
            Path(__file__).resolve().parents[1] / "infra/docker/deploy.sh"
        ).read_text(encoding="utf-8")
        usage = deploy.split("usage() {", 1)[1].split("EOF\n}", 1)[0]
        self.assertIn("stop TRANSACTION_ID", usage)
        self.assertIn("hostctl deactivate", usage)


if __name__ == "__main__":
    unittest.main()
