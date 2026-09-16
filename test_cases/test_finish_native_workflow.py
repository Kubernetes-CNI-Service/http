#!/usr/bin/env python3
"""Workflow contract for the Native finished-project stop-only boundary."""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
UNLOAD_PATH = ROOT / "DAY0-Prepare/13-unload.py"


def load_unload():
    name = "finish_native_unload"
    spec = importlib.util.spec_from_file_location(name, UNLOAD_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {UNLOAD_PATH}")
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(name)
    sys.modules[name] = module
    sys.path.insert(0, str(ROOT / "tools"))
    try:
        spec.loader.exec_module(module)
    finally:
        del sys.path[0]
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
    return module


class NativeFinishStopOnlyWorkflowTests(unittest.TestCase):
    def test_stop_only_uses_the_shared_lock_and_only_stops_managed_runtime(self):
        unload = load_unload()
        project = ROOT / "DAY0-Prepare/example-project"
        events: list[str] = []

        @contextmanager
        def held(_root, *, dry_run=False, finish_transaction_id=None):
            self.assertFalse(dry_run)
            self.assertIsNone(finish_transaction_id)
            events.append("lock-enter")
            yield 41
            events.append("lock-exit")

        backend = mock.Mock(name="native-backend")
        backend.name = "systemd"
        forbidden = (
            "unmanaged_dhcp_runtime_files",
            "remove_ztp_prefix_publication",
            "remove_dhcp_runtime_files",
            "remove_project_links",
            "clear_ztp_status",
            "teardown_infra",
        )
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                unload, "resolve_project", return_value=project,
            ))
            stack.enter_context(mock.patch.object(unload.os, "geteuid", return_value=0))
            stack.enter_context(mock.patch.object(unload, "confirm", return_value=True))
            stack.enter_context(mock.patch.object(unload, "deployment_lock", held))
            stack.enter_context(mock.patch.object(
                unload, "service_runtime_backend", return_value=backend,
            ))
            stack.enter_context(mock.patch.object(
                unload, "stop_monitor",
                side_effect=lambda *_a, **_k: events.append("monitor"),
            ))
            stack.enter_context(mock.patch.object(
                unload, "stop_monitor_workers",
                side_effect=lambda *_a, **_k: events.append("workers"),
            ))
            stack.enter_context(mock.patch.object(
                unload, "stop_services",
                side_effect=lambda *_a, **_k: events.append("services"),
            ))
            stack.enter_context(mock.patch.object(unload, "ok"))
            stack.enter_context(mock.patch.object(unload, "info"))
            stack.enter_context(mock.patch.object(unload, "warn"))
            forbidden_mocks = {
                name: stack.enter_context(mock.patch.object(unload, name))
                for name in forbidden
            }
            self.assertEqual(
                0,
                unload.main([project.name, "--stop-only", "--yes"]),
            )

        self.assertEqual(
            ["lock-enter", "monitor", "workers", "services", "lock-exit"],
            events,
        )
        for operation in forbidden_mocks.values():
            operation.assert_not_called()

    def test_stop_only_rejects_every_cleanup_option(self):
        unload = load_unload()
        for option in ("--force-dhcp", "--clear-ztp-status", "--teardown-infra"):
            with self.subTest(option=option), self.assertRaises(SystemExit):
                unload.parse_args(["project", "--stop-only", option])

    def test_stop_only_dry_run_does_not_require_root(self):
        unload = load_unload()
        project = ROOT / "DAY0-Prepare/example-project"

        @contextmanager
        def held(_root, *, dry_run=False, finish_transaction_id=None):
            self.assertTrue(dry_run)
            self.assertIsNone(finish_transaction_id)
            yield None

        with mock.patch.object(unload, "resolve_project", return_value=project), \
                mock.patch.object(unload.os, "geteuid", return_value=501), \
                mock.patch.object(unload, "deployment_lock", held), \
                mock.patch.object(unload, "service_runtime_backend") as backend, \
                mock.patch.object(unload, "stop_monitor"), \
                mock.patch.object(unload, "stop_monitor_workers"), \
                mock.patch.object(unload, "stop_services"):
            backend.return_value.name = "systemd"
            self.assertEqual(
                0,
                unload.main([project.name, "--stop-only", "--dry-run"]),
            )


if __name__ == "__main__":
    unittest.main()
