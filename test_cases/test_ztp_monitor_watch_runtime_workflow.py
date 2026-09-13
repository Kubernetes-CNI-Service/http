#!/usr/bin/env python3
"""Real-script workflow contracts for ZTP monitor watch resilience."""

from __future__ import annotations

from contextlib import redirect_stdout
from contextlib import contextmanager
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
for import_root in (ROOT, ROOT / "tools", ROOT / "monitor"):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))


def load_script(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


MONITOR = load_script(
    "ztp_monitor_watch_workflow_monitor",
    ROOT / "DAY0-Prepare/12-ztp-monitor.py",
)
LOAD = load_script(
    "ztp_monitor_watch_workflow_load",
    ROOT / "DAY0-Prepare/11-load.py",
)
ACTIVATE = load_script(
    "ztp_monitor_watch_workflow_activate",
    ROOT / "infra/docker/activate.py",
)
HTML = load_script(
    "ztp_monitor_watch_workflow_html",
    ROOT / "monitor/generate-monitor-html.py",
)


class MonitorWatchRuntimeWorkflowTests(unittest.TestCase):
    @staticmethod
    def _native_argv(project: Path, *, scope="prod", interval=7) -> list[str]:
        output = io.StringIO()
        backend = SimpleNamespace(name="systemd")
        with mock.patch.object(LOAD, "verify_control_auth"), \
                mock.patch.object(LOAD, "verify_apache_publication_boundary"), \
                redirect_stdout(output):
            LOAD.start_ztp_monitor(
                project, interval=interval, scope=scope, dry_run=True,
                runtime_backend=backend,
            )
        line = next(
            item for item in output.getvalue().splitlines()
            if item.startswith("[DRY] 后台启动：")
        )
        command = shlex.split(line.split("：", 1)[1])
        return command[3:]

    @staticmethod
    def _docker_argv(*, scope="prod", interval=7) -> list[str]:
        settings = ACTIVATE.Settings(
            http_root=Path("/var/www/html"), project_name="site-a",
            scope=scope, monitor_interval=interval,
        )
        return list(ACTIVATE.worker_spec("ztp-monitor", settings).argv[3:])

    @staticmethod
    def _build_html(ztp_status: dict) -> str:
        stats = {"changed": 0, "new": 0, "removed": 0, "same": 0}
        return HTML.build_html(
            {}, "", 0, "", "", 0, {}, "",
            "", "", stats, None, 0,
            "", "", stats, None, 0,
            "", "", 0, "",
            "", "", stats, None, 0,
            {}, {}, {}, {}, ztp_status,
        )

    def test_native_and_docker_launch_argv_use_the_same_parser_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "site-a"
            project.mkdir()
            native = MONITOR.parser().parse_args(self._native_argv(project))
            docker = MONITOR.parser().parse_args(self._docker_argv())

        for label, parsed in (("native", native), ("docker", docker)):
            with self.subTest(backend=label):
                self.assertEqual(7, parsed.watch)
                self.assertEqual("prod", parsed.scope)
                self.assertTrue(parsed.generate_html)
                self.assertFalse(parsed.offline)
                self.assertIsNone(parsed.dhcp_log)
        self.assertTrue(native.collect_on_complete)
        self.assertFalse(docker.collect_on_complete)

    def test_both_launch_paths_recover_transient_inside_one_main_call(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            project = base / "site-a"
            project.mkdir()
            launch_argv = {
                "native": self._native_argv(project),
                "docker": self._docker_argv(),
            }
            for backend, argv in launch_argv.items():
                with self.subTest(backend=backend):
                    output_root = base / backend / "status"
                    output_root.mkdir(parents=True)
                    run_dir = output_root / "successful-snapshot"
                    calls = 0

                    def cycle(_args, _project):
                        nonlocal calls
                        calls += 1
                        if calls == 1:
                            raise MONITOR.MonitorTransientCycleError(
                                "runtime-transport", "temporary read failure",
                            )
                        return run_dir

                    sleeps = 0

                    def sleep_then_stop(_seconds):
                        nonlocal sleeps
                        sleeps += 1
                        if sleeps == 2:
                            raise SystemExit(0)

                    report = {
                        "project": "site-a", "scope": "prod", "devices": [],
                    }
                    with mock.patch.multiple(
                        MONITOR,
                        ZTP_STATUS_DIR=output_root,
                        resolve_project=mock.Mock(return_value=project),
                        validate_monitor_mode=mock.Mock(),
                        load_completion_handoff_signatures=mock.Mock(return_value={}),
                        monitor_control_state=mock.Mock(return_value="running"),
                        monitor_once=mock.Mock(side_effect=cycle),
                        read_report=mock.Mock(return_value=report),
                        print_environment_summary=mock.Mock(),
                        generate_monitor_html=mock.Mock(return_value=True),
                        process_ready_completion_handoffs=mock.Mock(
                            return_value=({}, {}, {}),
                        ),
                        controlled_sleep=mock.Mock(side_effect=sleep_then_stop),
                        remove_own_pid_file=mock.Mock(),
                        log=mock.Mock(),
                    ), self.assertRaises(SystemExit) as stopped:
                        MONITOR.main(argv)
                    self.assertEqual(0, stopped.exception.code)
                    self.assertEqual(2, calls)
                    state = json.loads(
                        (output_root / ".ztp-monitor-watch-state.json").read_text(
                            encoding="utf-8"
                        )
                    )
                    self.assertEqual("healthy", state["state"])
                    self.assertEqual(0, state["consecutive_failures"])

    def test_permanent_failure_does_not_depend_on_backend_restart_policy(self):
        supervisor = (ROOT / "infra/docker/supervisord.conf").read_text(
            encoding="utf-8"
        )
        monitor_section = supervisor.split("[program:ztp-monitor]", 1)[1].split(
            "[program:", 1,
        )[0]
        self.assertIn("autorestart=true", monitor_section)
        self.assertIn("startsecs=3", monitor_section)
        self.assertIn("startretries=3", monitor_section)
        self.assertIn("stdout_logfile_maxbytes=20MB", monitor_section)
        self.assertIn("stdout_logfile_backups=5", monitor_section)

        native_source = (ROOT / "DAY0-Prepare/11-load.py").read_text(
            encoding="utf-8"
        )
        native_start = native_source.split("def start_ztp_monitor(", 1)[1].split(
            "\ndef ", 1,
        )[0]
        self.assertIn("start_new_session=True", native_start)
        self.assertIn("ztp-monitor-background.log", native_source)
        native_units = [
            path for path in ROOT.rglob("*.service")
            if "12-ztp-monitor.py" in path.read_text(
                encoding="utf-8", errors="replace",
            )
        ]
        self.assertFalse(native_units)
        self.assertFalse(list(ROOT.rglob("*.timer")))

    def test_unhealthy_banner_preserves_and_labels_last_good_report(self):
        status = {
            "available": True, "project": "site-a", "scope": "prod",
            "release_id": "0123456789abcdefabcd",
            "release_generated_at": "2026-09-12T11:00:00+08:00",
            "generated_at": "2026-09-12T11:30:00+08:00",
            "counts": {}, "environment_updates": {}, "devices": [],
            "watch_state": {
                "schema_version": 1, "project": "site-a", "scope": "prod",
                "pid": 123, "state": "unhealthy", "consecutive_failures": 4,
                "last_success_at": "2026-09-12T11:30:00+08:00",
                "last_failure_at": "2026-09-12T12:00:00+08:00",
                "next_retry_at": "2026-09-12T12:00:07+08:00",
                "category": "runtime-transport",
                "message": "temporary <transport> failure",
            },
        }
        rendered = self._build_html(status)
        self.assertIn('id="ztp-watch-unhealthy-banner"', rendered)
        self.assertIn("页面显示的是上次成功结果", rendered)
        self.assertIn("可能已过期", rendered)
        self.assertIn("runtime-transport", rendered)
        self.assertIn("temporary &lt;transport&gt; failure", rendered)
        self.assertNotIn("temporary <transport> failure", rendered)
        self.assertIn("0123456789abcdefabcd", rendered)

        healthy = dict(status)
        healthy["watch_state"] = dict(status["watch_state"], state="healthy")
        self.assertNotIn(
            'id="ztp-watch-unhealthy-banner"', self._build_html(healthy),
        )

    def test_real_sidecar_loader_reaches_html_banner_for_last_good_report(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            status_root = base / "status"
            snapshot = status_root / "20260912_113000"
            snapshot.mkdir(parents=True)
            report = {
                "schema_version": 1,
                "project": "site-a",
                "scope": "prod",
                "release_id": "0123456789abcdefabcd",
                "release_generated_at": "2026-09-12T11:00:00+08:00",
                "generated_at": "2026-09-12T11:30:00+08:00",
                "devices": [{
                    "hostname": "switch-a", "type": "eth", "ip": "192.0.2.10",
                    "mac": "02:00:00:00:00:10", "stages": {}, "issues": [],
                }],
            }
            (snapshot / "report.json").write_text(
                json.dumps(report) + "\n", encoding="utf-8",
            )
            sidecar = {
                "schema_version": 1, "project": "site-a", "scope": "prod",
                "pid": 123, "state": "unhealthy", "consecutive_failures": 4,
                "last_success_at": "2026-09-12T11:30:00+08:00",
                "last_failure_at": "2026-09-12T12:00:00+08:00",
                "next_retry_at": "2026-09-12T12:00:07+08:00",
                "category": "runtime-transport",
                "message": "temporary <transport> failure",
            }
            (status_root / ".ztp-monitor-watch-state.json").write_text(
                json.dumps(sidecar) + "\n", encoding="utf-8",
            )
            inventory = base / "02-devices_config.csv"
            inventory.write_text("hostname\n", encoding="utf-8")
            current = {
                "switch-a": {
                    "hostname": "switch-a", "type": "eth", "template": "leaf",
                    "eth0_ip": "192.0.2.10", "eth0_mac": "02:00:00:00:00:10",
                },
            }
            with (
                mock.patch.object(HTML, "load_ztp_inventory", return_value=current),
                mock.patch.object(HTML, "load_dynamic_air_inventory", return_value=[]),
            ):
                loaded = HTML.load_ztp_status(
                    status_root, inventory=inventory, scope="prod",
                )
            self.assertTrue(loaded["available"])
            self.assertEqual(sidecar, loaded["watch_state"])
            loaded["devices"] = []
            rendered = self._build_html(loaded)
            self.assertIn('id="ztp-watch-unhealthy-banner"', rendered)
            self.assertIn("页面显示的是上次成功结果", rendered)
            self.assertIn("temporary &lt;transport&gt; failure", rendered)
            for field, value in (("project", "other-site"), ("scope", "air")):
                with self.subTest(mismatched_sidecar=field):
                    mismatched = dict(sidecar, **{field: value})
                    (status_root / ".ztp-monitor-watch-state.json").write_text(
                        json.dumps(mismatched) + "\n", encoding="utf-8",
                    )
                    with (
                        mock.patch.object(
                            HTML, "load_ztp_inventory", return_value=current,
                        ),
                        mock.patch.object(
                            HTML, "load_dynamic_air_inventory", return_value=[],
                        ),
                    ):
                        rejected = HTML.load_ztp_status(
                            status_root, inventory=inventory, scope="prod",
                        )
                    self.assertNotIn("watch_state", rejected)

    def test_limiter_resets_across_supervisor_process_restarts_by_contract(self):
        first_process = MONITOR.WatchFailureLogLimiter(watch_seconds=7)
        second_process = MONITOR.WatchFailureLogLimiter(watch_seconds=7)
        first = first_process.record_failure(
            "runtime-transport", "same failure", now=0,
        )
        self.assertIsNone(first_process.record_failure(
            "runtime-transport", "same failure", now=1,
        ))
        restarted = second_process.record_failure(
            "runtime-transport", "same failure", now=2,
        )
        self.assertIn("same failure", first)
        self.assertIn("same failure", restarted)

    def test_native_pid_writer_holds_shared_lock_through_spawn_and_atomic_publish(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            status = root / "status"
            status.mkdir()
            pid_file = status / "ztp-monitor.pid"
            log_file = status / "ztp-monitor-background.log"
            project = root / "site-a"
            project.mkdir()
            events = []
            process = mock.Mock(pid=43120)
            process.poll.return_value = None

            @contextmanager
            def locked(path):
                self.assertEqual(pid_file, path)
                events.append("lock-enter")
                yield
                events.append("lock-exit")

            def spawn(*args, **kwargs):
                events.append("spawn")
                return process

            def publish(path, pid):
                self.assertEqual((pid_file, process.pid), (path, pid))
                events.append("publish")

            backend = SimpleNamespace(name="systemd")
            with mock.patch.multiple(
                LOAD,
                _ztp_monitor_paths=mock.Mock(return_value=(status, pid_file, log_file)),
                verify_control_auth=mock.Mock(),
                verify_apache_publication_boundary=mock.Mock(),
                run=mock.Mock(),
                _reload_apache_if_active=mock.Mock(),
                _start_supervisor_program=mock.Mock(return_value=False),
                stop_other_ztp_monitors=mock.Mock(return_value=[]),
                ztp_monitor_running=mock.Mock(return_value=(False, None)),
                _popen_subprocess=mock.Mock(side_effect=spawn),
                monitor_pid_lock=locked,
                write_monitor_pid_record_locked=mock.Mock(side_effect=publish),
                print_ztp_monitor_access=mock.Mock(),
                ok=mock.Mock(),
                create=True,
            ), mock.patch.object(LOAD, "ZTP_MONITOR_CONTROL_SOURCE", Path(__file__)):
                LOAD.start_ztp_monitor(
                    project, interval=7, scope="prod",
                    runtime_backend=backend,
                )
            self.assertEqual(
                ["lock-enter", "spawn", "publish", "lock-exit"], events,
            )

    def test_native_pid_publish_failure_terminates_and_reaps_spawned_monitor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            status = root / "status"
            status.mkdir()
            pid_file = status / "ztp-monitor.pid"
            log_file = status / "ztp-monitor-background.log"
            project = root / "site-a"
            project.mkdir()
            process = mock.Mock(pid=43121)
            process.poll.return_value = None
            process.wait.side_effect = [
                subprocess.TimeoutExpired("ztp-monitor", 5), None,
            ]
            backend = SimpleNamespace(name="systemd")
            with mock.patch.multiple(
                LOAD,
                _ztp_monitor_paths=mock.Mock(return_value=(status, pid_file, log_file)),
                verify_control_auth=mock.Mock(),
                verify_apache_publication_boundary=mock.Mock(),
                run=mock.Mock(),
                _reload_apache_if_active=mock.Mock(),
                _start_supervisor_program=mock.Mock(return_value=False),
                stop_other_ztp_monitors=mock.Mock(return_value=[]),
                ztp_monitor_running=mock.Mock(return_value=(False, None)),
                _popen_subprocess=mock.Mock(return_value=process),
                write_monitor_pid_record_locked=mock.Mock(
                    side_effect=OSError("injected PID publication failure"),
                ),
                print_ztp_monitor_access=mock.Mock(),
                ok=mock.Mock(),
                create=True,
            ), mock.patch.object(LOAD, "ZTP_MONITOR_CONTROL_SOURCE", Path(__file__)), \
                    self.assertRaises(Exception):
                LOAD.start_ztp_monitor(
                    project, interval=7, scope="prod",
                    runtime_backend=backend,
                )
            process.terminate.assert_called_once()
            process.kill.assert_called_once()
            self.assertEqual(
                [mock.call(timeout=5), mock.call(timeout=5)],
                process.wait.call_args_list,
            )
            self.assertFalse(pid_file.exists())

    def test_native_pid_lock_failure_never_spawns_or_publishes_monitor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            status = root / "status"
            status.mkdir()
            pid_file = status / "ztp-monitor.pid"
            log_file = status / "ztp-monitor-background.log"
            project = root / "site-a"
            project.mkdir()
            spawn = mock.Mock()
            publish = mock.Mock()

            @contextmanager
            def failed_lock(_path):
                raise OSError("injected PID lock failure")
                yield

            backend = SimpleNamespace(name="systemd")
            with mock.patch.multiple(
                LOAD,
                _ztp_monitor_paths=mock.Mock(return_value=(status, pid_file, log_file)),
                verify_control_auth=mock.Mock(),
                verify_apache_publication_boundary=mock.Mock(),
                run=mock.Mock(),
                _reload_apache_if_active=mock.Mock(),
                _start_supervisor_program=mock.Mock(return_value=False),
                stop_other_ztp_monitors=mock.Mock(return_value=[]),
                ztp_monitor_running=mock.Mock(return_value=(False, None)),
                _popen_subprocess=spawn,
                monitor_pid_lock=failed_lock,
                write_monitor_pid_record_locked=publish,
                print_ztp_monitor_access=mock.Mock(),
                ok=mock.Mock(),
                create=True,
            ), mock.patch.object(LOAD, "ZTP_MONITOR_CONTROL_SOURCE", Path(__file__)), \
                    self.assertRaises(Exception):
                LOAD.start_ztp_monitor(
                    project, interval=7, scope="prod",
                    runtime_backend=backend,
                )
            spawn.assert_not_called()
            publish.assert_not_called()
            self.assertFalse(pid_file.exists())

    def test_native_post_replace_fsync_failure_reaps_child_and_leaves_no_pid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            status = root / "status"
            status.mkdir()
            pid_file = status / "ztp-monitor.pid"
            log_file = status / "ztp-monitor-background.log"
            project = root / "site-a"
            project.mkdir()
            process = mock.Mock(pid=43122)
            process.poll.return_value = None
            process.wait.side_effect = [
                subprocess.TimeoutExpired("ztp-monitor", 5), None,
            ]
            backend = SimpleNamespace(name="systemd")
            runtime_module = sys.modules[LOAD.monitor_pid_lock.__module__]
            real_fsync = os.fsync
            fsync_calls = 0

            def fail_parent(descriptor):
                nonlocal fsync_calls
                fsync_calls += 1
                if fsync_calls == 2:
                    self.assertEqual(
                        f"{process.pid}\n", pid_file.read_text(encoding="ascii"),
                    )
                    raise OSError("injected native PID parent fsync failure")
                return real_fsync(descriptor)

            with mock.patch.multiple(
                LOAD,
                _ztp_monitor_paths=mock.Mock(return_value=(status, pid_file, log_file)),
                verify_control_auth=mock.Mock(),
                verify_apache_publication_boundary=mock.Mock(),
                run=mock.Mock(),
                _reload_apache_if_active=mock.Mock(),
                _start_supervisor_program=mock.Mock(return_value=False),
                stop_other_ztp_monitors=mock.Mock(return_value=[]),
                ztp_monitor_running=mock.Mock(return_value=(False, None)),
                _popen_subprocess=mock.Mock(return_value=process),
                print_ztp_monitor_access=mock.Mock(),
                ok=mock.Mock(),
            ), mock.patch.object(LOAD, "ZTP_MONITOR_CONTROL_SOURCE", Path(__file__)), \
                    mock.patch.object(
                        runtime_module.os, "fsync", side_effect=fail_parent,
                    ), self.assertRaises(OSError):
                LOAD.start_ztp_monitor(
                    project, interval=7, scope="prod", runtime_backend=backend,
                )
            process.terminate.assert_called_once()
            process.kill.assert_called_once()
            self.assertEqual(
                [mock.call(timeout=5), mock.call(timeout=5)],
                process.wait.call_args_list,
            )
            self.assertFalse(pid_file.exists())
            lock_file = status / ".ztp-monitor.pid.lock"
            self.assertTrue(lock_file.exists())
            self.assertEqual(0o600, lock_file.stat().st_mode & 0o777)

    def test_container_pid_writer_uses_the_same_shared_lock_protocol(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "ztp-monitor.pid"
            events = []

            @contextmanager
            def locked(path):
                self.assertEqual(pid_file, path)
                events.append("lock-enter")
                yield
                events.append("lock-exit")

            runtime = SimpleNamespace(
                monitor_pid_lock=locked,
                write_monitor_pid_record_locked=lambda path, pid: events.append(
                    ("publish", path, pid)
                ),
            )
            with mock.patch.object(ACTIVATE.os, "chown", side_effect=lambda *_: events.append("chown")):
                ACTIVATE._write_worker_pid(pid_file, runtime_backend=runtime)
            self.assertEqual("lock-enter", events[0])
            self.assertEqual(("publish", pid_file, os.getpid()), events[1])
            self.assertEqual("chown", events[2])
            self.assertEqual("lock-exit", events[3])

    def test_container_pid_lock_failure_precedes_publish_and_chown(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "ztp-monitor.pid"
            publish = mock.Mock()

            @contextmanager
            def failed_lock(_path):
                raise OSError("injected container PID lock failure")
                yield

            runtime = SimpleNamespace(
                monitor_pid_lock=failed_lock,
                write_monitor_pid_record_locked=publish,
            )
            with mock.patch.object(ACTIVATE.os, "chown") as chown, \
                    self.assertRaises(OSError):
                ACTIVATE._write_worker_pid(pid_file, runtime_backend=runtime)
            publish.assert_not_called()
            chown.assert_not_called()
            self.assertFalse(pid_file.exists())

    def test_container_post_replace_fsync_failure_has_no_pid_or_chown(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "ztp-monitor.pid"
            runtime_module = sys.modules[LOAD.monitor_pid_lock.__module__]
            real_fsync = os.fsync
            fsync_calls = 0

            def fail_parent(descriptor):
                nonlocal fsync_calls
                fsync_calls += 1
                if fsync_calls == 2:
                    self.assertEqual(
                        f"{os.getpid()}\n", pid_file.read_text(encoding="ascii"),
                    )
                    raise OSError("injected container PID parent fsync failure")
                return real_fsync(descriptor)

            with mock.patch.object(
                runtime_module.os, "fsync", side_effect=fail_parent,
            ), mock.patch.object(ACTIVATE.os, "chown") as chown, \
                    self.assertRaises(OSError):
                ACTIVATE._write_worker_pid(
                    pid_file, runtime_backend=runtime_module,
                )
            chown.assert_not_called()
            self.assertFalse(pid_file.exists())


if __name__ == "__main__":
    unittest.main()
