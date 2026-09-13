#!/usr/bin/env python3
"""Direct fail-closed contracts for detached Native ZTP Monitor quiescence.

All process state lives below a temporary fake ``/proc`` tree and every signal
is captured by a Python callback.  These tests never inspect or signal a real
host process.
"""

from __future__ import annotations

import importlib.util
import inspect
import os
from pathlib import Path
import signal
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
RUNTIME_PATH = ROOT / "tools/ztp_service_runtime.py"
GUARD_PATH = ROOT / "tools/deployment_prewrite_guard.py"
_RUNTIME = None
_GUARD = None


def load_runtime():
    global _RUNTIME
    if _RUNTIME is not None:
        return _RUNTIME
    spec = importlib.util.spec_from_file_location(
        "monitor_writer_quiesce_runtime", RUNTIME_PATH,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _RUNTIME = module
    return _RUNTIME


def load_guard():
    global _GUARD
    if _GUARD is not None:
        return _GUARD
    spec = importlib.util.spec_from_file_location(
        "monitor_writer_quiesce_embedded_guard", GUARD_PATH,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _GUARD = module
    return _GUARD


class NativeMonitorQuiesceDirectTests(unittest.TestCase):
    CONTRACT = (
        "MONITOR-WRITER-QUIESCE-R1",
        "direct-project-only",
        "fixed-monitor-argv-grammar",
        "single-regular-pid-authority",
        "bounded-complete-proc-scan",
        "all-identities-before-first-signal",
        "sigterm-only",
        "bounded-confirmed-exit",
        "identity-bound-pid-cleanup",
    )

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.http_root = self.root / "http"
        self.proc_root = self.root / "proc"
        self.project = self.http_root / "DAY0-Prepare/customer-a"
        self.output = self.project / "99-output-ztp"
        self.output.mkdir(parents=True)
        self.proc_root.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def monitor_argv(self, project: Path | None = None) -> tuple[str, ...]:
        selected = project or self.project
        return (
            "/usr/bin/python3",
            os.fspath(self.http_root / "DAY0-Prepare/12-ztp-monitor.py"),
            os.fspath(selected),
            "--watch",
            "30",
        )

    def spoofed_monitor_argv(self) -> dict[str, tuple[str, ...]]:
        script = os.fspath(self.http_root / "DAY0-Prepare/12-ztp-monitor.py")
        project = os.fspath(self.project)
        return {
            "non_python_executable": ("/bin/sh", script, project, "--watch", "30"),
            "prefix_before_interpreter": (
                "/usr/bin/env", "/usr/bin/python3", script, project,
                "--watch", "30",
            ),
            "extra_before_script": (
                "/usr/bin/python3", "-c", script, project, "--watch", "30",
            ),
            "duplicate_script": (
                "/usr/bin/python3", script, project, script, "--watch", "30",
            ),
            "duplicate_project": (
                "/usr/bin/python3", script, project, project, "--watch", "30",
            ),
            "duplicate_watch": (
                "/usr/bin/python3", script, project,
                "--watch", "30", "--watch", "60",
            ),
            "shell_command_arguments": (
                "/bin/sh", "-c", "python3", script, project, "--watch", "30",
            ),
            "script_as_ordinary_argument": (
                "/usr/bin/helper", "/tmp/worker.py", "--target", script,
                project, "--watch", "30",
            ),
            "unknown_option": (
                "/usr/bin/python3", script, project,
                "--watch", "30", "--unknown", "value",
            ),
            "known_option_without_value": (
                "/usr/bin/python3", script, project, "--watch", "30", "--scope",
            ),
            "watch_without_value": ("/usr/bin/python3", script, project, "--watch"),
            "watch_with_invalid_value": (
                "/usr/bin/python3", script, project, "--watch", "not-seconds",
            ),
            "watch_with_zero_value": (
                "/usr/bin/python3", script, project, "--watch", "0",
            ),
        }

    def add_process(self, pid: int, argv: tuple[str, ...]) -> Path:
        process = self.proc_root / str(pid)
        process.mkdir()
        (process / "cmdline").write_bytes(
            b"\0".join(part.encode("utf-8") for part in argv) + b"\0"
        )
        return process

    def write_pid(self, value: str) -> Path:
        path = self.output / "ztp-monitor.pid"
        path.write_text(value, encoding="ascii")
        return path

    def stop(self, **kwargs):
        runtime = load_runtime()
        return runtime.stop_native_ztp_monitors(
            self.http_root,
            proc_root=self.proc_root,
            timeout=0.05,
            sleep=lambda _seconds: None,
            **kwargs,
        )

    def add_project_pid(self, project_name: str, value: str) -> Path:
        output = self.http_root / "DAY0-Prepare" / project_name / "99-output-ztp"
        output.mkdir(parents=True)
        path = output / "ztp-monitor.pid"
        path.write_text(value, encoding="ascii")
        return path

    def test_valid_project_bound_pid_is_terminated_confirmed_and_cleaned(self) -> None:
        process = self.add_process(4321, self.monitor_argv())
        pid_path = self.write_pid("4321\n")
        signals = []

        def fake_kill(pid: int, sig: int) -> None:
            signals.append((pid, sig))
            (process / "cmdline").unlink()
            process.rmdir()

        stopped = self.stop(kill=fake_kill)

        self.assertEqual((4321,), stopped)
        self.assertEqual([(4321, signal.SIGTERM)], signals)
        self.assertFalse(pid_path.exists())

    def test_exact_detached_monitor_is_discovered_without_pid_file(self) -> None:
        process = self.add_process(987, self.monitor_argv())
        signals = []

        def fake_kill(pid: int, sig: int) -> None:
            signals.append((pid, sig))
            (process / "cmdline").unlink()
            process.rmdir()

        self.assertEqual((987,), self.stop(kill=fake_kill))
        self.assertEqual([(987, signal.SIGTERM)], signals)

    def test_wrong_or_reused_pid_fails_before_any_signal(self) -> None:
        self.add_process(4321, ("/usr/bin/python3", "/tmp/not-the-monitor.py"))
        self.write_pid("4321\n")
        signals = []

        with self.assertRaisesRegex(
            load_runtime().RuntimeContractError, "identity|cmdline|monitor",
        ):
            self.stop(kill=lambda pid, sig: signals.append((pid, sig)))

        self.assertEqual([], signals)

    def test_malformed_pid_authority_fails_before_any_signal(self) -> None:
        self.write_pid("not-a-pid\n")
        signals = []

        with self.assertRaisesRegex(
            load_runtime().RuntimeContractError, "PID|pid",
        ):
            self.stop(kill=lambda pid, sig: signals.append((pid, sig)))

        self.assertEqual([], signals)

    def test_monitor_outside_direct_project_scope_is_rejected(self) -> None:
        outside = self.root / "outside-project"
        outside.mkdir()
        self.add_process(4321, self.monitor_argv(outside))
        self.write_pid("4321\n")
        signals = []

        with self.assertRaisesRegex(
            load_runtime().RuntimeContractError, "project|scope|identity",
        ):
            self.stop(kill=lambda pid, sig: signals.append((pid, sig)))

        self.assertEqual([], signals)

    def test_sigterm_failure_is_fail_closed(self) -> None:
        self.add_process(4321, self.monitor_argv())
        self.write_pid("4321\n")

        def denied(_pid: int, _sig: int) -> None:
            raise PermissionError("denied by fixture")

        with self.assertRaisesRegex(
            load_runtime().RuntimeContractError, "signal|SIGTERM|terminate",
        ):
            self.stop(kill=denied)

    def test_exit_timeout_is_fail_closed_and_pid_file_remains(self) -> None:
        self.add_process(4321, self.monitor_argv())
        pid_path = self.write_pid("4321\n")

        with self.assertRaisesRegex(
            load_runtime().RuntimeContractError, "timeout|exit",
        ):
            self.stop(kill=lambda _pid, _sig: None)

        self.assertTrue(pid_path.exists())

    def test_pid_file_changed_during_stop_is_not_removed(self) -> None:
        process = self.add_process(4321, self.monitor_argv())
        pid_path = self.write_pid("4321\n")

        def fake_kill(_pid: int, _sig: int) -> None:
            pid_path.write_text("9999\n", encoding="ascii")
            (process / "cmdline").unlink()
            process.rmdir()

        self.assertEqual((4321,), self.stop(kill=fake_kill))
        self.assertEqual("9999\n", pid_path.read_text(encoding="ascii"))

    def test_no_proc_and_no_pid_file_is_a_safe_noop(self) -> None:
        self.proc_root.rmdir()
        self.assertEqual((), self.stop(kill=lambda _pid, _sig: None))

    def test_pid_authority_without_proc_is_fail_closed(self) -> None:
        pid_path = self.write_pid("4321\n")
        self.proc_root.rmdir()
        signals = []

        with self.assertRaisesRegex(
            load_runtime().RuntimeContractError, "PID|pid|/proc|process",
        ):
            self.stop(kill=lambda pid, sig: signals.append((pid, sig)))

        self.assertEqual([], signals)
        self.assertTrue(pid_path.exists())

    def test_all_discovered_identities_are_validated_before_first_signal(self) -> None:
        self.add_process(4321, self.monitor_argv())
        self.write_pid("4321\n")
        self.add_project_pid("customer-b", "9999\n")
        signals = []

        with self.assertRaises(load_runtime().RuntimeContractError):
            self.stop(kill=lambda pid, sig: signals.append((pid, sig)))

        self.assertEqual([], signals)

    def test_pid_authority_symlink_and_hardlink_are_rejected(self) -> None:
        self.add_process(4321, self.monitor_argv())
        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind):
                pid_path = self.output / "ztp-monitor.pid"
                pid_path.unlink(missing_ok=True)
                authority = self.output / f"{kind}.authority"
                authority.unlink(missing_ok=True)
                authority.write_text("4321\n", encoding="ascii")
                if kind == "symlink":
                    pid_path.symlink_to(authority.name)
                else:
                    os.link(authority, pid_path)
                signals = []
                with self.assertRaises(load_runtime().RuntimeContractError):
                    self.stop(kill=lambda pid, sig: signals.append((pid, sig)))
                self.assertEqual([], signals)

    def test_pid_authority_rebind_before_signal_is_fail_closed(self) -> None:
        self.add_process(4321, self.monitor_argv())
        pid_path = self.write_pid("4321\n")
        signals = []

        def rebind() -> None:
            pid_path.unlink()
            pid_path.write_text("4321\n", encoding="ascii")

        with self.assertRaisesRegex(
            load_runtime().RuntimeContractError, "PID|pid|changed|identity",
        ):
            self.stop(
                kill=lambda pid, sig: signals.append((pid, sig)),
                _before_signal=rebind,
            )
        self.assertEqual([], signals)

    def test_cmdline_identity_drift_before_signal_is_fail_closed(self) -> None:
        process = self.add_process(4321, self.monitor_argv())
        self.write_pid("4321\n")
        signals = []

        def change_cmdline() -> None:
            (process / "cmdline").write_bytes(
                b"/usr/bin/python3\0/tmp/reused.py\0"
            )

        with self.assertRaisesRegex(
            load_runtime().RuntimeContractError, "cmdline|changed|identity",
        ):
            self.stop(
                kill=lambda pid, sig: signals.append((pid, sig)),
                _before_signal=change_cmdline,
            )
        self.assertEqual([], signals)

    def test_cmdline_unreadable_before_signal_is_fail_closed(self) -> None:
        process = self.add_process(4321, self.monitor_argv())
        self.write_pid("4321\n")
        signals = []

        def remove_cmdline_authority() -> None:
            (process / "cmdline").unlink()

        with self.assertRaisesRegex(
            load_runtime().RuntimeContractError, "cmdline|read|identity|PID",
        ):
            self.stop(
                kill=lambda pid, sig: signals.append((pid, sig)),
                _before_signal=remove_cmdline_authority,
            )
        self.assertEqual([], signals)

    def test_process_directory_identity_drift_before_signal_is_fail_closed(self) -> None:
        process = self.add_process(4321, self.monitor_argv())
        self.write_pid("4321\n")
        signals = []

        def replace_process_directory() -> None:
            (process / "cmdline").unlink()
            process.rmdir()
            self.add_process(4321, self.monitor_argv())

        with self.assertRaisesRegex(
            load_runtime().RuntimeContractError, "process|changed|identity|PID",
        ):
            self.stop(
                kill=lambda pid, sig: signals.append((pid, sig)),
                _before_signal=replace_process_directory,
            )
        self.assertEqual([], signals)

    def test_embedded_remote_guard_is_bound_to_the_exact_native_policy(self) -> None:
        runtime = load_runtime()
        guard = load_guard()
        self.assertEqual(self.CONTRACT, runtime.NATIVE_MONITOR_QUIESCE_CONTRACT)
        self.assertEqual(self.CONTRACT, guard.NATIVE_MONITOR_QUIESCE_CONTRACT)
        self.assertEqual(
            inspect.getsource(runtime._native_monitor_project_from_argv),
            inspect.getsource(guard._native_monitor_project_from_argv),
        )

    def test_embedded_remote_guard_matches_canonical_success_and_failure_behavior(self) -> None:
        implementations = (
            (load_runtime().stop_native_ztp_monitors, load_runtime().RuntimeContractError),
            (load_guard().stop_native_ztp_monitors, load_guard().GuardError),
        )
        for implementation, error_type in implementations:
            with self.subTest(implementation=implementation.__module__, case="success"):
                process = self.add_process(7001, self.monitor_argv())
                pid_path = self.write_pid("7001\n")
                signals = []

                def terminate(pid: int, sig: int) -> None:
                    signals.append((pid, sig))
                    (process / "cmdline").unlink()
                    process.rmdir()

                self.assertEqual(
                    (7001,),
                    implementation(
                        self.http_root, proc_root=self.proc_root,
                        kill=terminate, sleep=lambda _seconds: None,
                    ),
                )
                self.assertEqual([(7001, signal.SIGTERM)], signals)
                self.assertFalse(pid_path.exists())

            with self.subTest(implementation=implementation.__module__, case="malformed"):
                self.write_pid("not-a-pid\n")
                signals = []
                with self.assertRaises(error_type):
                    implementation(
                        self.http_root, proc_root=self.proc_root,
                        kill=lambda pid, sig: signals.append((pid, sig)),
                        sleep=lambda _seconds: None,
                    )
                self.assertEqual([], signals)
                (self.output / "ztp-monitor.pid").unlink()

    def test_monitor_identity_rejects_argv_spoofs_without_pid_authority(self) -> None:
        implementations = (
            load_runtime().stop_native_ztp_monitors,
            load_guard().stop_native_ztp_monitors,
        )
        for implementation in implementations:
            for case, argv in self.spoofed_monitor_argv().items():
                with self.subTest(implementation=implementation.__module__, case=case):
                    process = self.add_process(8001, argv)
                    signals = []
                    try:
                        self.assertEqual(
                            (),
                            implementation(
                                self.http_root, proc_root=self.proc_root,
                                kill=lambda pid, sig: signals.append((pid, sig)),
                                sleep=lambda _seconds: None, timeout=0.05,
                            ),
                        )
                        self.assertEqual([], signals)
                    finally:
                        (process / "cmdline").unlink(missing_ok=True)
                        process.rmdir()

    def test_referenced_argv_spoof_fails_before_any_monitor_is_signalled(self) -> None:
        implementations = (
            (load_runtime().stop_native_ztp_monitors, load_runtime().RuntimeContractError),
            (load_guard().stop_native_ztp_monitors, load_guard().GuardError),
        )
        for implementation, error_type in implementations:
            for case, argv in self.spoofed_monitor_argv().items():
                with self.subTest(implementation=implementation.__module__, case=case):
                    valid_process = self.add_process(8100, self.monitor_argv())
                    spoofed_process = self.add_process(8101, argv)
                    pid_path = self.write_pid("8101\n")
                    signals = []
                    try:
                        with self.assertRaises(error_type):
                            implementation(
                                self.http_root, proc_root=self.proc_root,
                                kill=lambda pid, sig: signals.append((pid, sig)),
                                sleep=lambda _seconds: None, timeout=0.05,
                            )
                        self.assertEqual([], signals)
                    finally:
                        pid_path.unlink(missing_ok=True)
                        for process in (valid_process, spoofed_process):
                            (process / "cmdline").unlink(missing_ok=True)
                            process.rmdir()

    def test_supported_fixed_monitor_argv_grammar_matches_both_implementations(self) -> None:
        script = os.fspath(self.http_root / "DAY0-Prepare/12-ztp-monitor.py")
        project = os.fspath(self.project)
        supported_argv = {
            "project_before_watch": (
                "/usr/bin/python3", script, project, "--watch", "30",
            ),
            "watch_before_project": (
                "/usr/bin/python3", script, "--watch", "30", project,
            ),
            "load_u_and_known_options": (
                "/usr/bin/python3", "-u", script, project,
                "--watch", "30", "--generate-html", "--collect-on-complete",
                "--known-hosts", "/tmp/known-hosts", "--scope", "all",
            ),
            "documented_b_and_type": (
                "/usr/bin/python3", "-B", script,
                "--watch", "30", project, "--type", "prod",
            ),
        }
        implementations = (
            load_runtime().stop_native_ztp_monitors,
            load_guard().stop_native_ztp_monitors,
        )
        for implementation in implementations:
            for case, argv in supported_argv.items():
                with self.subTest(implementation=implementation.__module__, case=case):
                    process = self.add_process(8201, argv)
                    signals = []

                    def terminate(pid: int, sig: int) -> None:
                        signals.append((pid, sig))
                        (process / "cmdline").unlink()
                        process.rmdir()

                    self.assertEqual(
                        (8201,),
                        implementation(
                            self.http_root, proc_root=self.proc_root,
                            kill=terminate, sleep=lambda _seconds: None,
                        ),
                    )
                    self.assertEqual([(8201, signal.SIGTERM)], signals)


if __name__ == "__main__":
    unittest.main()
