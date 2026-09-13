#!/usr/bin/env python3
"""Direct contracts for resilient ZTP monitor watch cycles."""

from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MONITOR_PATH = ROOT / "DAY0-Prepare/12-ztp-monitor.py"
WATCH_STATE_NAME = ".ztp-monitor-watch-state.json"
WATCH_STATE_KEYS = {
    "schema_version", "project", "scope", "pid", "state",
    "consecutive_failures", "last_success_at", "last_failure_at",
    "next_retry_at", "category", "message",
}


def load_script(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


MONITOR = load_script("ztp_monitor_watch_resilience_contract", MONITOR_PATH)


class MonitorWatchResilienceDirectTests(unittest.TestCase):
    def _args(self, output_root: Path, *, watch: int | None = 7):
        return argparse.Namespace(
            project="site-a", since=1440, watch=watch,
            stall_warning_minutes=60, output_dir=output_root,
            offline=False, apache_log=None, dhcp_log=None,
            dhcp_leases=None, air_json=None, no_ssh=False,
            ssh_timeout=8, jobs=12, scope="prod", identity=None,
            known_hosts=output_root / "known-hosts", generate_html=True,
            html_script=Path("/monitor/generate-monitor-html.py"),
            collect_on_complete=True, collector_timeout=1200,
        )

    @contextmanager
    def _main_context(
        self, output_root: Path, effects, *, watch: int | None = 7,
        control_states=("running",), state_writer=None,
    ):
        args = self._args(output_root, watch=watch)
        project = output_root.parent / "site-a"
        project.mkdir(exist_ok=True)
        run_dir = output_root / "successful-snapshot"
        parser_driver = mock.Mock()
        parser_driver.parse_args.return_value = args
        monitor_once = mock.Mock(side_effect=effects)
        controlled_sleep = mock.Mock()
        paused_sleep = mock.Mock()
        html = mock.Mock(return_value=True)
        handoff = mock.Mock(return_value=({}, {}, {}))
        cleanup = mock.Mock()
        log = mock.Mock()
        control = mock.Mock(side_effect=list(control_states))
        report = {
            "project": project.name, "scope": args.scope,
            "devices": [], "generated_at": "2026-09-12T12:00:00+08:00",
        }

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(MONITOR, "parser", return_value=parser_driver))
            stack.enter_context(mock.patch.object(MONITOR, "resolve_project", return_value=project))
            stack.enter_context(mock.patch.object(MONITOR, "validate_monitor_mode"))
            stack.enter_context(mock.patch.object(
                MONITOR, "load_completion_handoff_signatures", return_value={},
            ))
            stack.enter_context(mock.patch.object(MONITOR, "monitor_once", monitor_once))
            stack.enter_context(mock.patch.object(MONITOR, "read_report", return_value=report))
            stack.enter_context(mock.patch.object(MONITOR, "print_environment_summary"))
            stack.enter_context(mock.patch.object(MONITOR, "generate_monitor_html", html))
            stack.enter_context(mock.patch.object(
                MONITOR, "process_ready_completion_handoffs", handoff,
            ))
            stack.enter_context(mock.patch.object(
                MONITOR, "controlled_sleep", controlled_sleep,
            ))
            stack.enter_context(mock.patch.object(MONITOR, "paused_sleep", paused_sleep))
            stack.enter_context(mock.patch.object(
                MONITOR, "monitor_control_state", control,
            ))
            stack.enter_context(mock.patch.object(MONITOR, "remove_own_pid_file", cleanup))
            stack.enter_context(mock.patch.object(MONITOR, "log", log))
            if state_writer is not None:
                stack.enter_context(mock.patch.object(
                    MONITOR, "_write_watch_state_atomic", side_effect=state_writer,
                ))
            yield {
                "args": args, "project": project, "run_dir": run_dir,
                "monitor_once": monitor_once, "sleep": controlled_sleep,
                "paused_sleep": paused_sleep, "html": html,
                "handoff": handoff, "cleanup": cleanup, "log": log,
            }

    @staticmethod
    def _state(output_root: Path) -> dict:
        return json.loads(
            (output_root / WATCH_STATE_NAME).read_text(encoding="utf-8")
        )

    def test_only_explicit_transient_type_is_retryable(self):
        self.assertTrue(issubclass(MONITOR.MonitorTransientCycleError, Exception))
        failure = MONITOR.MonitorTransientCycleError(
            "report-publication", "temporary output failure",
        )
        self.assertEqual("report-publication", failure.category)
        self.assertEqual("temporary output failure", failure.message)

        for unexpected in (
            OSError("temporary output failure"),
            RuntimeError("temporary output failure"),
            ValueError("temporary output failure"),
        ):
            with self.subTest(exception=type(unexpected).__name__), \
                    tempfile.TemporaryDirectory() as directory:
                output_root = Path(directory) / "status"
                with self._main_context(output_root, [unexpected]) as context:
                    self.assertEqual(2, MONITOR.main([]))
                self.assertEqual(1, context["monitor_once"].call_count)
                context["sleep"].assert_not_called()
                self.assertEqual("unhealthy", self._state(output_root)["state"])
                context["html"].assert_called_once()

    def test_named_runtime_and_publication_boundaries_raise_exact_transient_type(self):
        backend = mock.Mock(name="supervisor-backend")
        backend.name = "supervisor"
        backend.read_log.side_effect = MONITOR.RuntimeContractError(
            "temporary supervisor transport failure",
        )
        with self.assertRaises(MONITOR.MonitorTransientCycleError) as transported:
            MONITOR.collect_dhcp(1440, runtime_backend=backend)
        self.assertEqual("runtime-transport", transported.exception.category)

        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "status"
            report = {"devices": []}
            with mock.patch.object(
                Path, "replace", side_effect=OSError("temporary latest failure"),
            ), self.assertRaises(MONITOR.MonitorTransientCycleError) as published:
                MONITOR.write_report(report, output_root, {})
        self.assertEqual("report-publication", published.exception.category)

        with mock.patch.object(
            MONITOR,
            "runtime_backend_from_environment",
            side_effect=MONITOR.RuntimeContractError("invalid backend identity"),
        ), self.assertRaises(ValueError) as permanent:
            MONITOR.service_runtime_backend()
        self.assertNotIsInstance(
            permanent.exception, MONITOR.MonitorTransientCycleError,
        )

    def test_real_main_and_monitor_once_retry_actual_publication_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            project = base / "site-a"
            project.mkdir()
            output_root = base / "status"
            args = self._args(output_root)
            args.no_ssh = True
            args.collect_on_complete = False
            parser_driver = mock.Mock()
            parser_driver.parse_args.return_value = args
            device = {
                "hostname": "switch-a", "type": "eth",
                "environment": "prod", "ip": "192.0.2.10",
                "mac": "02:00:00:00:00:10", "ztp_round": 1,
                "overall": "pending", "issues": [],
                "progress": {"done": 0, "total": len(MONITOR.STAGE_NAMES), "percent": 0},
                "stages": {
                    name: {"status": "pending", "detail": "", "success_index": 0}
                    for name in MONITOR.STAGE_NAMES
                },
            }
            backend = SimpleNamespace(name="systemd")
            empty_tail = MONITOR.TailRead("", "", "fixture")
            real_replace = Path.replace
            replaces = 0

            def fail_once_then_publish(path, target):
                nonlocal replaces
                replaces += 1
                if replaces == 1:
                    raise OSError("injected latest publication failure")
                args.watch = None
                return real_replace(path, target)

            html = mock.Mock(return_value=True)
            slept = mock.Mock()
            with mock.patch.multiple(
                MONITOR,
                parser=mock.Mock(return_value=parser_driver),
                resolve_project=mock.Mock(return_value=project),
                validate_monitor_mode=mock.Mock(),
                load_completion_handoff_signatures=mock.Mock(return_value={}),
                monitor_control_state=mock.Mock(return_value="running"),
                service_runtime_backend=mock.Mock(return_value=backend),
                load_release_identity=mock.Mock(return_value={
                    "release_id": "a" * 20,
                    "generated_at": "2026-09-12T12:00:00+08:00",
                }),
                _previous_report=mock.Mock(return_value={}),
                project_timezone=mock.Mock(return_value=None),
                read_devices=mock.Mock(return_value=[device]),
                collect_dhcp=mock.Mock(return_value=empty_tail),
                parse_dhcp=mock.Mock(return_value=[]),
                apply_static_runtime_lease_fallbacks=mock.Mock(),
                runtime_unknown_devices=mock.Mock(return_value=[]),
                apply_dynamic_dhcp_addresses=mock.Mock(),
                merge_previous_unbound_identities=mock.Mock(
                    side_effect=lambda _previous, devices: devices,
                ),
                read_tail=mock.Mock(return_value=empty_tail),
                parse_apache=mock.Mock(return_value=[]),
                bind_apache_ztp_identities=mock.Mock(return_value={}),
                correlate_server_events=mock.Mock(return_value={}),
                latest_manual_trigger_markers=mock.Mock(return_value={}),
                assign_ztp_rounds=mock.Mock(),
                assign_stage_success_indices=mock.Mock(),
                annotate_progress_stall=mock.Mock(),
                finalize_device=mock.Mock(),
                earliest_observed_timestamp=mock.Mock(return_value=""),
                service_state=mock.Mock(return_value={
                    "active": "active", "enabled": "enabled", "error": "",
                }),
                print_environment_summary=mock.Mock(),
                generate_monitor_html=html,
                controlled_sleep=slept,
                remove_own_pid_file=mock.Mock(),
                log=mock.Mock(),
            ), mock.patch.object(
                Path, "replace", autospec=True, side_effect=fail_once_then_publish,
            ), mock.patch.object(MONITOR.signal, "signal"):
                self.assertEqual(0, MONITOR.main([]))
            self.assertEqual(2, replaces)
            slept.assert_called_once_with(7)
            self.assertEqual(2, html.call_count)
            self.assertEqual("healthy", self._state(output_root)["state"])

    def test_single_transient_recovers_in_same_process_and_resets_state(self):
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "status"
            transient = MONITOR.MonitorTransientCycleError(
                "runtime-transport", "lease source temporarily unavailable",
            )
            calls = 0

            def cycle(_args, _project):
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise transient
                context["args"].watch = None
                return context["run_dir"]

            with self._main_context(output_root, cycle) as context:
                self.assertEqual(0, MONITOR.main([]))

            self.assertEqual(2, context["monitor_once"].call_count)
            context["sleep"].assert_called_once_with(7)
            self.assertEqual(2, context["html"].call_count)
            context["handoff"].assert_called_once()
            state = self._state(output_root)
            self.assertEqual(WATCH_STATE_KEYS, set(state))
            self.assertEqual(1, state["schema_version"])
            self.assertEqual("site-a", state["project"])
            self.assertEqual("prod", state["scope"])
            self.assertEqual(os.getpid(), state["pid"])
            self.assertEqual("healthy", state["state"])
            self.assertEqual(0, state["consecutive_failures"])
            self.assertTrue(state["last_success_at"])
            self.assertTrue(state["last_failure_at"])
            self.assertEqual("", state["next_retry_at"])
            self.assertEqual("", state["category"])
            self.assertEqual("", state["message"])

    def test_fifth_consecutive_transient_exits_without_a_fifth_sleep(self):
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "status"
            transient = MONITOR.MonitorTransientCycleError(
                "report-publication", "filesystem temporarily unavailable",
            )
            with self._main_context(output_root, transient) as context:
                self.assertEqual(2, MONITOR.main([]))

            self.assertEqual(5, context["monitor_once"].call_count)
            self.assertEqual(
                [mock.call(7)] * 4, context["sleep"].call_args_list,
            )
            self.assertEqual(5, context["html"].call_count)
            context["handoff"].assert_not_called()
            state = self._state(output_root)
            self.assertEqual("unhealthy", state["state"])
            self.assertEqual(5, state["consecutive_failures"])
            self.assertEqual("report-publication", state["category"])
            self.assertEqual("", state["next_retry_at"])

    def test_success_resets_the_consecutive_failure_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "status"
            transient = MONITOR.MonitorTransientCycleError(
                "runtime-transport", "temporary read failure",
            )
            outcomes = [transient, transient, "success"] + [transient] * 5

            def cycle(_args, _project):
                outcome = outcomes.pop(0)
                if isinstance(outcome, BaseException):
                    raise outcome
                return context["run_dir"]

            with self._main_context(output_root, cycle) as context:
                self.assertEqual(2, MONITOR.main([]))

            self.assertEqual(8, context["monitor_once"].call_count)
            self.assertEqual(7, context["sleep"].call_count)
            self.assertEqual(8, context["html"].call_count)
            context["handoff"].assert_called_once()
            state = self._state(output_root)
            self.assertEqual(5, state["consecutive_failures"])
            self.assertTrue(state["last_success_at"])

    def test_paused_cycles_are_not_failures_and_do_not_consume_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "status"

            def success(_args, _project):
                context["args"].watch = None
                return context["run_dir"]

            with self._main_context(
                output_root, success, control_states=("paused", "running"),
            ) as context:
                self.assertEqual(0, MONITOR.main([]))

            context["paused_sleep"].assert_called_once_with(7)
            self.assertEqual(1, context["monitor_once"].call_count)
            state = self._state(output_root)
            self.assertEqual("healthy", state["state"])
            self.assertEqual(0, state["consecutive_failures"])

    def test_same_process_rejects_governed_identity_drift_before_next_cycle(self):
        for drift in (
            "current-release", "global-yaml", "inventory-bytes", "p2p-air",
            "setup-manifest", "active-inventory",
        ):
            with self.subTest(drift=drift), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                day0 = base / "DAY0-Prepare"
                project = day0 / "site-a"
                output_root = project / "99-output-ztp"
                output_root.mkdir(parents=True)
                inventory = project / "02-devices_config.csv"
                inventory.write_text("hostname\n", encoding="utf-8")
                global_yaml = project / "01-global.yaml"
                global_yaml.write_text(
                    "project: site-a\ntimezone: Asia/Shanghai\n", encoding="utf-8",
                )
                alternate_inventory = project / "02-alternate.csv"
                alternate_inventory.write_text("hostname\n", encoding="utf-8")
                release = output_root / "current-release.json"
                release.write_text(json.dumps({
                    "schema_version": 1, "project": "site-a",
                    "release_id": "a" * 20,
                    "generated_at": "2026-09-12T12:00:00+08:00",
                    "validation": "passed",
                }) + "\n", encoding="utf-8")
                active_inventory = base / "ztp/config/isc-dhcp-server/02-devices_config.csv"
                active_inventory.parent.mkdir(parents=True)
                active_inventory.symlink_to(os.path.relpath(inventory, active_inventory.parent))
                runtime_air = base / "ztp/config/isc-dhcp-server/p2p-air.json"
                runtime_air.write_text(
                    '{"schema_version":1,"devices":[]}\n', encoding="utf-8",
                )
                status_link = base / "ztp/status"
                status_link.symlink_to(os.path.relpath(output_root, status_link.parent))
                setup_manifest = base / "ztp/.setup_manifest"
                manifest_bytes = (
                    f"# setup manifest — proj: {project.resolve()}\n"
                    f"{active_inventory}\n{status_link}\n"
                ).encode("utf-8")
                setup_manifest.write_bytes(manifest_bytes)
                args = self._args(output_root)
                parser_driver = mock.Mock()
                parser_driver.parse_args.return_value = args
                run_dir = output_root / "successful-snapshot"
                monitor_once = mock.Mock(
                    side_effect=[run_dir, AssertionError("cycle ran after identity drift")],
                )
                html = mock.Mock(return_value=True)
                handoff = mock.Mock(return_value=({}, {}, {}))

                def atomic_replace(path, payload):
                    replacement = path.with_name("." + path.name + ".replacement")
                    replacement.write_bytes(payload)
                    os.replace(replacement, path)

                def mutate_identity(_seconds):
                    if drift == "current-release":
                        atomic_replace(release, (json.dumps({
                            "schema_version": 1, "project": "site-a",
                            "release_id": "b" * 20,
                            "generated_at": "2026-09-12T12:00:01+08:00",
                            "validation": "passed",
                        }) + "\n").encode("utf-8"))
                    elif drift == "global-yaml":
                        atomic_replace(
                            global_yaml,
                            b"project: site-a\ntimezone: UTC\n",
                        )
                    elif drift == "inventory-bytes":
                        atomic_replace(
                            inventory,
                            b"hostname,type\nswitch-a,eth\n",
                        )
                    elif drift == "p2p-air":
                        atomic_replace(
                            runtime_air,
                            b'{"schema_version":1,"devices":[{"hostname":"air-a"}]}\n',
                        )
                    elif drift == "setup-manifest":
                        setup_manifest.write_bytes(
                            manifest_bytes + b"/still-structurally-valid-extra-link\n"
                        )
                    else:
                        active_inventory.unlink()
                        active_inventory.symlink_to(os.path.relpath(
                            alternate_inventory, active_inventory.parent,
                        ))

                slept = mock.Mock(side_effect=mutate_identity)
                with mock.patch.multiple(
                    MONITOR,
                    HERE=day0,
                    SETUP_MANIFEST=setup_manifest,
                    ACTIVE_INVENTORY=active_inventory,
                    ACTIVE_AIR_JSON=runtime_air,
                    ZTP_STATUS_DIR=status_link,
                    parser=mock.Mock(return_value=parser_driver),
                    resolve_project=mock.Mock(return_value=project),
                    load_completion_handoff_signatures=mock.Mock(return_value={}),
                    monitor_control_state=mock.Mock(return_value="running"),
                    monitor_once=monitor_once,
                    read_report=mock.Mock(return_value={
                        "project": "site-a", "scope": "prod", "devices": [],
                    }),
                    print_environment_summary=mock.Mock(),
                    generate_monitor_html=html,
                    process_ready_completion_handoffs=handoff,
                    controlled_sleep=slept,
                    remove_own_pid_file=mock.Mock(),
                    log=mock.Mock(),
                ), mock.patch.object(MONITOR.signal, "signal"):
                    self.assertEqual(2, MONITOR.main([]))
                self.assertEqual(1, monitor_once.call_count)
                self.assertEqual(1, slept.call_count)
                self.assertEqual(2, html.call_count)
                self.assertEqual(1, handoff.call_count)
                state = self._state(output_root)
                self.assertEqual("unhealthy", state["state"])

    def test_one_shot_transient_does_not_retry_or_create_watch_state(self):
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "status"
            transient = MONITOR.MonitorTransientCycleError(
                "runtime-transport", "temporary read failure",
            )
            with self._main_context(
                output_root, transient, watch=None,
            ) as context:
                self.assertEqual(2, MONITOR.main([]))
            self.assertEqual(1, context["monitor_once"].call_count)
            context["sleep"].assert_not_called()
            self.assertFalse((output_root / WATCH_STATE_NAME).exists())

    def test_signal_and_baseexception_paths_are_never_counted_as_failures(self):
        cases = (
            (SystemExit(37), "raise", SystemExit),
            (GeneratorExit(), "raise", GeneratorExit),
        )
        for raised, behavior, expected in cases:
            with self.subTest(exception=type(raised).__name__), \
                    tempfile.TemporaryDirectory() as directory:
                output_root = Path(directory) / "status"
                with self._main_context(output_root, raised) as context:
                    if behavior == "return":
                        self.assertEqual(expected, MONITOR.main([]))
                    else:
                        with self.assertRaises(expected) as stopped:
                            MONITOR.main([])
                        if isinstance(raised, SystemExit):
                            self.assertEqual(37, stopped.exception.code)
                self.assertEqual(1, context["monitor_once"].call_count)
                context["sleep"].assert_not_called()
                context["cleanup"].assert_called_once()
                self.assertFalse((output_root / WATCH_STATE_NAME).exists())

    def test_signal_handler_maps_sigint_and_sigterm_to_shell_exit_codes(self):
        with self.assertRaises(KeyboardInterrupt):
            MONITOR.monitor_signal_handler(signal.SIGINT, None)
        with self.assertRaises(SystemExit) as stopped:
            MONITOR.monitor_signal_handler(signal.SIGTERM, None)
        self.assertEqual(143, stopped.exception.code)

    def test_main_registers_exact_signal_handler_before_monitor_cycle(self):
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "status"
            with self._main_context(output_root, KeyboardInterrupt()) as context, \
                    mock.patch.object(MONITOR.signal, "signal") as registered:
                self.assertEqual(130, MONITOR.main([]))
            self.assertGreaterEqual(len(registered.call_args_list), 2)
            self.assertEqual(
                [
                    mock.call(signal.SIGINT, MONITOR.monitor_signal_handler),
                    mock.call(signal.SIGTERM, MONITOR.monitor_signal_handler),
                ],
                registered.call_args_list[:2],
            )
            context["cleanup"].assert_called_once()
            self.assertFalse((output_root / WATCH_STATE_NAME).exists())

    def test_real_signals_use_registered_handlers_cleanup_pid_and_never_count_failure(self):
        child_source = r'''
import argparse, importlib.util, os, pathlib, sys, time
module_path = pathlib.Path(sys.argv[1])
output = pathlib.Path(sys.argv[2])
ready = pathlib.Path(sys.argv[3])
spec = importlib.util.spec_from_file_location("monitor_signal_child", module_path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
output.mkdir(parents=True)
module.ZTP_STATUS_DIR = output
(output / "ztp-monitor.pid").write_text(str(os.getpid()) + "\n", encoding="ascii")
project = output.parent / "site-a"
project.mkdir(exist_ok=True)
args = argparse.Namespace(
    project="site-a", since=1440, watch=7, stall_warning_minutes=60,
    output_dir=output, offline=False, apache_log=None, dhcp_log=None,
    dhcp_leases=None, air_json=None, no_ssh=False, ssh_timeout=8, jobs=1,
    scope="prod", identity=None, known_hosts=output / "known-hosts",
    generate_html=True, html_script=output / "generate-monitor-html.py",
    collect_on_complete=False, collector_timeout=1200,
)
class Driver:
    def parse_args(self, _argv): return args
module.parser = lambda: Driver()
module.resolve_project = lambda _value: project
module.validate_monitor_mode = lambda *_args: None
module.load_completion_handoff_signatures = lambda *_args: {}
module.monitor_control_state = lambda *_args: "running"
def block(*_args):
    ready.write_text("ready\n", encoding="ascii")
    while True: time.sleep(1)
module.monitor_once = block
raise SystemExit(module.main([]))
'''
        for sent, expected in ((signal.SIGINT, 130), (signal.SIGTERM, 143)):
            with self.subTest(signal=sent), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                output = base / "status"
                ready = base / "ready"
                environment = os.environ.copy()
                environment["PYTHONPYCACHEPREFIX"] = os.fspath(base / "pycache")
                child = subprocess.Popen(
                    [
                        sys.executable, "-B", "-c", child_source,
                        os.fspath(MONITOR_PATH), os.fspath(output), os.fspath(ready),
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=environment,
                )
                try:
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline and not ready.exists():
                        if child.poll() is not None:
                            break
                        time.sleep(0.02)
                    if not ready.exists():
                        stdout, stderr = child.communicate(timeout=2)
                        self.fail(f"signal child did not become ready: {stdout!r} {stderr!r}")
                    child.send_signal(sent)
                    stdout, stderr = child.communicate(timeout=5)
                finally:
                    if child.poll() is None:
                        child.kill()
                        child.communicate()
                self.assertEqual(expected, child.returncode, (stdout, stderr))
                self.assertFalse((output / "ztp-monitor.pid").exists())
                state = output / WATCH_STATE_NAME
                if state.exists():
                    self.assertEqual(
                        0,
                        json.loads(state.read_text(encoding="utf-8"))[
                            "consecutive_failures"
                        ],
                    )

    def test_pid_cleanup_removes_only_the_current_process_record(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "ztp-monitor.pid"
            pid_file.write_text(f"{os.getpid() + 1}\n", encoding="ascii")
            MONITOR.remove_own_pid_file(pid_file)
            self.assertTrue(pid_file.exists())
            pid_file.write_text(f"{os.getpid()}\n", encoding="ascii")
            MONITOR.remove_own_pid_file(pid_file)
            self.assertFalse(pid_file.exists())

    def test_pid_cleanup_never_unlinks_a_rebound_new_process_record(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "ztp-monitor.pid"
            pid_file.write_text(f"{os.getpid()}\n", encoding="ascii")
            replacement = f"{os.getpid() + 1}\n"
            original_read = Path.read_text
            rebound = False

            def read_then_rebind(path, *args, **kwargs):
                nonlocal rebound
                content = original_read(path, *args, **kwargs)
                if Path(path) == pid_file and not rebound:
                    rebound = True
                    pid_file.unlink()
                    pid_file.write_text(replacement, encoding="ascii")
                return content

            with mock.patch.object(
                Path, "read_text", autospec=True, side_effect=read_then_rebind,
            ):
                MONITOR.remove_own_pid_file(pid_file)
            self.assertTrue(rebound)
            self.assertEqual(replacement, pid_file.read_text(encoding="ascii"))

    def test_pid_cleanup_serializes_with_supported_writer_and_preserves_new_record(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "ztp-monitor.pid"
            pid_file.write_text(f"{os.getpid()}\n", encoding="ascii")
            replacement = f"{os.getpid() + 1}\n"
            writer_started = threading.Event()
            writer_entered = threading.Event()
            writer_errors = []
            real_read = Path.read_text

            def supported_writer():
                try:
                    writer_started.wait(2)
                    with MONITOR.monitor_pid_lock(pid_file):
                        writer_entered.set()
                        MONITOR.write_monitor_pid_record_locked(
                            pid_file, os.getpid() + 1,
                        )
                except BaseException as exc:
                    writer_errors.append(exc)

            def read_while_locked(path, *args, **kwargs):
                content = real_read(path, *args, **kwargs)
                writer_started.set()
                self.assertFalse(writer_entered.wait(0.1))
                return content

            writer = threading.Thread(target=supported_writer)
            writer.start()
            with mock.patch.object(
                Path, "read_text", autospec=True, side_effect=read_while_locked,
            ):
                MONITOR.remove_own_pid_file(pid_file)
            writer.join(2)
            self.assertFalse(writer.is_alive())
            self.assertEqual([], writer_errors)
            self.assertTrue(writer_entered.is_set())
            self.assertEqual(replacement, pid_file.read_text(encoding="ascii"))
            self.assertEqual(0o644, stat.S_IMODE(pid_file.stat().st_mode))
            self.assertEqual(1, pid_file.stat().st_nlink)

    def test_pid_lock_creation_uses_exact_nofollow_private_persistent_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "ztp-monitor.pid"
            lock_file = Path(directory) / ".ztp-monitor.pid.lock"
            real_open = os.open
            real_fchmod = os.fchmod
            opened = []

            def record_open(path, flags, *args, **kwargs):
                descriptor = real_open(path, flags, *args, **kwargs)
                if Path(path) == lock_file:
                    opened.append((flags, descriptor))
                return descriptor

            with mock.patch.object(MONITOR.os, "open", side_effect=record_open), \
                    mock.patch.object(
                        MONITOR.os, "fchmod", wraps=real_fchmod,
                    ) as fchmod:
                with MONITOR.monitor_pid_lock(pid_file):
                    metadata = lock_file.lstat()
                    self.assertTrue(stat.S_ISREG(metadata.st_mode))
                    self.assertEqual(1, metadata.st_nlink)
                    self.assertEqual(os.geteuid(), metadata.st_uid)
                    self.assertEqual(0o600, stat.S_IMODE(metadata.st_mode))
                    first_identity = (metadata.st_dev, metadata.st_ino)
                with MONITOR.monitor_pid_lock(pid_file):
                    metadata = lock_file.lstat()
                    self.assertEqual(
                        first_identity, (metadata.st_dev, metadata.st_ino),
                    )
            self.assertTrue(lock_file.exists())
            self.assertTrue(opened)
            flags = opened[0][0]
            for required in (
                os.O_RDWR, os.O_CREAT, getattr(os, "O_CLOEXEC", 0),
                getattr(os, "O_NOFOLLOW", 0),
            ):
                self.assertEqual(required, flags & required)
            self.assertTrue(any(call.args[1] == 0o600 for call in fchmod.call_args_list))

    def test_pid_lock_rejects_hostile_objects_and_rebind_without_pid_mutation(self):
        for hostile in (
            "symlink", "hardlink", "directory", "fifo",
            "wrong-mode", "wrong-owner", "rebind",
        ):
            with self.subTest(hostile=hostile), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                pid_file = root / "ztp-monitor.pid"
                pid_bytes = f"{os.getpid()}\n"
                pid_file.write_text(pid_bytes, encoding="ascii")
                lock_file = root / ".ztp-monitor.pid.lock"
                outside = root / "outside-lock"
                outside.write_text("lock\n", encoding="ascii")
                outside.chmod(0o600)
                if hostile == "symlink":
                    lock_file.symlink_to(outside)
                elif hostile == "hardlink":
                    os.link(outside, lock_file)
                elif hostile == "directory":
                    lock_file.mkdir()
                elif hostile == "fifo":
                    os.mkfifo(lock_file, 0o600)
                else:
                    lock_file.write_text("lock\n", encoding="ascii")
                    lock_file.chmod(0o600 if hostile != "wrong-mode" else 0o644)
                patches = ExitStack()
                with patches:
                    if hostile == "wrong-owner":
                        patches.enter_context(mock.patch.object(
                            MONITOR.os, "geteuid", return_value=os.geteuid() + 1,
                        ))
                    elif hostile == "rebind":
                        real_lstat = Path.lstat

                        def rebind_before_lstat(path, *args, **kwargs):
                            if Path(path) == lock_file and lock_file.exists():
                                moved = root / "held-lock"
                                if not moved.exists():
                                    os.replace(lock_file, moved)
                                    lock_file.write_text("new\n", encoding="ascii")
                                    lock_file.chmod(0o600)
                            return real_lstat(path, *args, **kwargs)

                        patches.enter_context(mock.patch.object(
                            Path, "lstat", autospec=True,
                            side_effect=rebind_before_lstat,
                        ))
                    MONITOR.remove_own_pid_file(pid_file)
                self.assertTrue(pid_file.exists())
                if pid_file.exists():
                    self.assertEqual(pid_bytes, pid_file.read_text(encoding="ascii"))
                self.assertTrue(lock_file.exists() or lock_file.is_symlink())

    def test_pid_publish_parent_fsync_failure_rolls_back_only_own_record(self):
        for prior, hostile_rebind in ((None, False), (43100, False), (None, True)):
            with self.subTest(prior=prior, hostile_rebind=hostile_rebind), \
                    tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                pid_file = root / "ztp-monitor.pid"
                if prior is not None:
                    pid_file.write_text(f"{prior}\n", encoding="ascii")
                lock_file = root / ".ztp-monitor.pid.lock"
                replacement = root / "replacement.pid"
                replacement.write_text("49999\n", encoding="ascii")
                real_fsync = os.fsync
                fsync_calls = 0

                def fail_parent_after_publish(descriptor):
                    nonlocal fsync_calls
                    fsync_calls += 1
                    if fsync_calls == 2:
                        self.assertEqual(
                            f"{os.getpid()}\n",
                            pid_file.read_text(encoding="ascii"),
                        )
                        if hostile_rebind:
                            os.replace(replacement, pid_file)
                        raise OSError("injected PID parent fsync failure")
                    return real_fsync(descriptor)

                with MONITOR.monitor_pid_lock(pid_file):
                    lock_identity = (
                        lock_file.stat().st_dev, lock_file.stat().st_ino,
                    )
                    with mock.patch.object(
                        MONITOR.os, "fsync", side_effect=fail_parent_after_publish,
                    ), self.assertRaises(OSError):
                        MONITOR.write_monitor_pid_record_locked(
                            pid_file, os.getpid(),
                        )
                if hostile_rebind:
                    self.assertEqual("49999\n", pid_file.read_text(encoding="ascii"))
                elif prior is None:
                    self.assertFalse(pid_file.exists())
                else:
                    self.assertEqual(f"{prior}\n", pid_file.read_text(encoding="ascii"))
                metadata = lock_file.stat()
                self.assertEqual(lock_identity, (metadata.st_dev, metadata.st_ino))
                self.assertEqual(0o600, stat.S_IMODE(metadata.st_mode))
                self.assertEqual(
                    [lock_file.name] + ([pid_file.name] if pid_file.exists() else []),
                    sorted(
                        item.name for item in root.iterdir()
                        if item != replacement
                    ),
                )

    def test_failed_cycles_leave_last_good_snapshot_and_latest_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "status"
            snapshot = output_root / "20260912_120000"
            snapshot.mkdir(parents=True)
            report = snapshot / "report.json"
            report.write_bytes(b'{"last_good":true}\n')
            latest = output_root / "latest"
            latest.symlink_to(snapshot.name)
            before_names = sorted(item.name for item in output_root.iterdir())
            before_target = os.readlink(latest)
            before_report = report.read_bytes()
            transient = MONITOR.MonitorTransientCycleError(
                "report-publication", "temporary publish failure",
            )

            with self._main_context(output_root, transient) as context:
                self.assertEqual(2, MONITOR.main([]))

            self.assertEqual(before_target, os.readlink(latest))
            self.assertEqual(before_report, report.read_bytes())
            self.assertEqual(
                before_names,
                sorted(
                    item.name for item in output_root.iterdir()
                    if item.name != WATCH_STATE_NAME
                ),
            )
            self.assertEqual(5, context["html"].call_count)
            context["handoff"].assert_not_called()

    def test_retryable_failure_writes_unhealthy_state_before_refreshing_last_good_html(self):
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "status"
            snapshot = output_root / "20260912_120000"
            snapshot.mkdir(parents=True)
            report_path = snapshot / "report.json"
            report_path.write_bytes(b'{"last_good":true}\n')
            latest = output_root / "latest"
            latest.symlink_to(snapshot.name)
            transient = MONITOR.MonitorTransientCycleError(
                "runtime-transport", "temporary transport failure",
            )
            calls = 0

            def cycle(_args, _project):
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise transient
                context["args"].watch = None
                return context["run_dir"]

            def inspect_before_retry(_seconds):
                state = self._state(output_root)
                self.assertEqual("unhealthy", state["state"])
                self.assertEqual(1, state["consecutive_failures"])
                self.assertEqual("runtime-transport", state["category"])
                self.assertEqual(1, context["html"].call_count)
                self.assertEqual(snapshot.name, os.readlink(latest))
                self.assertEqual(b'{"last_good":true}\n', report_path.read_bytes())

            with self._main_context(output_root, cycle) as context:
                context["sleep"].side_effect = inspect_before_retry
                self.assertEqual(0, MONITOR.main([]))
            self.assertEqual(2, context["html"].call_count)

    def _watch_state_payload(self):
        return {
            "schema_version": 1, "project": "site-a", "scope": "prod",
            "pid": os.getpid(), "state": "unhealthy",
            "consecutive_failures": 1, "last_success_at": "",
            "last_failure_at": "2026-09-12T12:00:00+08:00",
            "next_retry_at": "2026-09-12T12:00:07+08:00",
            "category": "report-publication", "message": "temporary failure",
        }

    def test_atomic_sidecar_has_exact_schema_mode_and_durable_replace(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / WATCH_STATE_NAME
            real_fsync = os.fsync
            with mock.patch.object(
                MONITOR.os, "fsync", wraps=real_fsync,
            ) as fsync:
                MONITOR._write_watch_state_atomic(path, self._watch_state_payload())
            self.assertGreaterEqual(fsync.call_count, 2)
            self.assertEqual(0o644, stat.S_IMODE(path.stat().st_mode))
            self.assertEqual(WATCH_STATE_KEYS, set(json.loads(path.read_text())))
            self.assertEqual([path.name], [item.name for item in path.parent.iterdir()])

    def test_atomic_sidecar_file_fsync_or_replace_fault_preserves_previous_bytes(self):
        for fault in ("fsync", "replace"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / WATCH_STATE_NAME
                previous = b'{"schema_version":1,"state":"healthy"}\n'
                path.write_bytes(previous)
                patcher = mock.patch.object(
                    MONITOR.os, fault, side_effect=OSError(f"injected {fault}"),
                )
                with patcher, self.assertRaises(OSError):
                    MONITOR._write_watch_state_atomic(
                        path, self._watch_state_payload(),
                    )
                self.assertEqual(previous, path.read_bytes())
                self.assertEqual(
                    [path.name], [item.name for item in path.parent.iterdir()],
                )

    def test_atomic_sidecar_parent_fsync_fault_rolls_back_previous_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / WATCH_STATE_NAME
            previous = b'{"schema_version":1,"state":"healthy"}\n'
            path.write_bytes(previous)
            real_fsync = os.fsync
            calls = 0

            def fail_parent(descriptor):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("injected parent fsync")
                return real_fsync(descriptor)

            with mock.patch.object(MONITOR.os, "fsync", side_effect=fail_parent), \
                    self.assertRaises(OSError):
                MONITOR._write_watch_state_atomic(path, self._watch_state_payload())
            self.assertEqual(previous, path.read_bytes())
            self.assertEqual([path.name], [item.name for item in path.parent.iterdir()])

    def test_sidecar_write_failure_logs_once_and_does_not_abort_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "status"
            transient = MONITOR.MonitorTransientCycleError(
                "runtime-transport", "temporary read failure",
            )
            real_writer = MONITOR._write_watch_state_atomic
            writer_calls = 0

            def flaky_writer(path, payload):
                nonlocal writer_calls
                writer_calls += 1
                if writer_calls == 1:
                    raise OSError("injected sidecar fsync failure")
                return real_writer(path, payload)

            cycles = 0

            def cycle(_args, _project):
                nonlocal cycles
                cycles += 1
                if cycles == 1:
                    raise transient
                context["args"].watch = None
                return context["run_dir"]

            with self._main_context(
                output_root, cycle, state_writer=flaky_writer,
            ) as context:
                self.assertEqual(0, MONITOR.main([]))
            self.assertEqual(2, writer_calls)
            self.assertEqual("healthy", self._state(output_root)["state"])
            self.assertEqual(2, context["html"].call_count)
            sidecar_errors = [
                str(call.args[0]) for call in context["log"].call_args_list
                if "sidecar" in str(call.args[0]).casefold()
                or "watch-state" in str(call.args[0]).casefold()
            ]
            self.assertEqual(1, len(sidecar_errors))

    def test_sidecar_message_is_bounded_utf8_without_traceback(self):
        sentinel = "MWR-CREDENTIAL-SENTINEL-7f31"
        credentials = (
            f"password={sentinel}",
            f"password: {sentinel}",
            f"Authorization: Bearer {sentinel}",
            f"https://operator:{sentinel}@example.invalid/status",
        )
        for credential in credentials:
            with self.subTest(credential=credential.split(":", 1)[0]), \
                    tempfile.TemporaryDirectory() as directory:
                output_root = Path(directory) / "status"
                message = (
                    credential + " " + "瞬时失败🙂" * 400
                    + "\nTraceback (most recent call last): secret"
                )
                self.assertNotIn(
                    sentinel, MONITOR._bounded_watch_message(message),
                )
                transient = MONITOR.MonitorTransientCycleError(
                    "runtime-transport", message,
                )
                with self._main_context(output_root, transient) as context:
                    self.assertEqual(2, MONITOR.main([]))
                stored = self._state(output_root)["message"]
                self.assertLessEqual(len(stored.encode("utf-8")), 1024)
                self.assertNotIn("Traceback", stored)
                self.assertNotIn(sentinel, stored)
                rendered_logs = "\n".join(
                    str(call.args[0]) for call in context["log"].call_args_list
                )
                self.assertNotIn(sentinel, rendered_logs)
                stored.encode("utf-8").decode("utf-8")

    def test_failure_log_limiter_is_bounded_only_within_one_process(self):
        limiter = MONITOR.WatchFailureLogLimiter(watch_seconds=7)
        first = limiter.record_failure(
            "runtime-transport", "same failure", now=0,
        )
        self.assertIn("same failure", first)
        self.assertIsNone(limiter.record_failure(
            "runtime-transport", "same failure", now=1,
        ))
        self.assertIsNone(limiter.record_failure(
            "runtime-transport", "same failure", now=2,
        ))
        summary = limiter.record_failure(
            "runtime-transport", "same failure", now=300,
        )
        self.assertIn("suppressed_count=2", summary)
        changed = limiter.record_failure(
            "report-publication", "different failure", now=301,
        )
        self.assertIn("different failure", changed)
        recovery = limiter.record_recovery(now=302)
        self.assertIn("recovered", recovery.casefold())

        restarted_process = MONITOR.WatchFailureLogLimiter(watch_seconds=7)
        self.assertIn(
            "same failure",
            restarted_process.record_failure(
                "runtime-transport", "same failure", now=303,
            ),
        )

    def test_failure_log_summary_boundary_scales_with_watch_interval(self):
        for watch_seconds, boundary in ((7, 300), (31, 310), (60, 600)):
            with self.subTest(watch_seconds=watch_seconds):
                limiter = MONITOR.WatchFailureLogLimiter(
                    watch_seconds=watch_seconds,
                )
                self.assertIsNotNone(limiter.record_failure(
                    "runtime-transport", "same failure", now=0,
                ))
                self.assertIsNone(limiter.record_failure(
                    "runtime-transport", "same failure", now=boundary - 1,
                ))
                emitted = limiter.record_failure(
                    "runtime-transport", "same failure", now=boundary,
                )
                self.assertIn("suppressed_count=1", emitted)

    def test_main_uses_per_process_limiter_while_refreshing_every_sidecar(self):
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "status"
            same = MONITOR.MonitorTransientCycleError(
                "runtime-transport", "same failure",
            )
            changed = MONITOR.MonitorTransientCycleError(
                "report-publication", "different failure",
            )
            outcomes = [same, same, same, changed, "success"]

            def cycle(_args, _project):
                outcome = outcomes.pop(0)
                if isinstance(outcome, BaseException):
                    raise outcome
                context["args"].watch = None
                return context["run_dir"]

            with self._main_context(output_root, cycle) as context, \
                    mock.patch.object(
                        MONITOR.time, "monotonic",
                        side_effect=[0, 1, 300, 301, 302],
                    ), mock.patch.object(
                        MONITOR, "_write_watch_state_atomic",
                        wraps=MONITOR._write_watch_state_atomic,
                    ) as writer:
                self.assertEqual(0, MONITOR.main([]))
                self.assertEqual(5, writer.call_count)

            messages = [str(call.args[0]) for call in context["log"].call_args_list]
            same_logs = [item for item in messages if "same failure" in item]
            self.assertEqual(2, len(same_logs), messages)
            self.assertTrue(
                any("suppressed_count=1" in item for item in same_logs), messages,
            )
            self.assertEqual(
                1, sum("different failure" in item for item in messages),
            )
            self.assertEqual(
                1, sum("recovered" in item.casefold() for item in messages),
            )
            self.assertEqual(5, context["html"].call_count)


if __name__ == "__main__":
    unittest.main()
