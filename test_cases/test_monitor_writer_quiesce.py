#!/usr/bin/env python3
"""Direct fail-closed contracts for detached Native ZTP Monitor quiescence.

All process state lives below a temporary fake ``/proc`` tree and every signal
is captured by a Python callback.  These tests never inspect or signal a real
host process.
"""

from __future__ import annotations

import importlib.util
import inspect
import itertools
import os
from pathlib import Path
import signal
import tempfile
import unittest
from unittest import mock


ROOT =Path(__file__).resolve().parents[1]
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

    # ----- WP-NS1 (R-034 / P052): unrelated processes must not block the stop -----
    # Every expectation below is written by hand from the v3.1.6 guide WP-NS1
    # (guide :670-:699, owner 「别的进程或者服务不应该挡住 load」); none is
    # produced by comparing the two implementations.

    NS1_MONITOR_PID = 9100

    def ns1_implementations(self):
        return (
            ("runtime", load_runtime().stop_native_ztp_monitors,
             load_runtime().RuntimeContractError),
            ("guard", load_guard().stop_native_ztp_monitors,
             load_guard().GuardError),
        )

    def ns1_reset(self) -> None:
        for process in tuple(self.proc_root.iterdir()):
            for child in tuple(process.iterdir()):
                child.unlink()
            process.rmdir()
        for pid_path in self.http_root.glob("DAY0-Prepare/*/99-output-ztp/ztp-monitor.pid"):
            pid_path.unlink()

    def add_raw_process(self, pid: int, raw: bytes) -> Path:
        process = self.proc_root / str(pid)
        process.mkdir()
        (process / "cmdline").write_bytes(raw)
        return process

    def ns1_monitor_raw(self, *extra: str) -> bytes:
        argv = self.monitor_argv() + extra
        return b"\0".join(part.encode("utf-8") for part in argv) + b"\0"

    @staticmethod
    def ns1_cmdline(prefix: bytes, total: int, unit: bytes) -> bytes:
        """``prefix`` followed by repeated ``unit`` bytes; exactly ``total`` bytes, NUL-terminated."""
        fill = (unit * (total // len(unit) + 1))[: total - len(prefix) - 1]
        raw = prefix + fill + b"\0"
        assert len(raw) == total, (len(raw), total)
        return raw

    def ns1_stop(self, implementation, signals: list, *, terminate=(NS1_MONITOR_PID,)):
        def kill(pid: int, sig: int) -> None:
            signals.append((pid, sig))
            if pid in terminate:
                process = self.proc_root / str(pid)
                (process / "cmdline").unlink()
                process.rmdir()

        # An advancing injected clock: an unexpected exit wait ends in the
        # bounded 5 s timeout instead of spinning; nothing really sleeps.
        clock = itertools.count()
        return implementation(
            self.http_root, proc_root=self.proc_root, kill=kill,
            monotonic=lambda: float(next(clock)), sleep=lambda _seconds: None,
        )

    def ns1_project_pid(self, project_name: str, value: str) -> Path:
        output = self.http_root / "DAY0-Prepare" / project_name / "99-output-ztp"
        output.mkdir(parents=True, exist_ok=True)
        path = output / "ztp-monitor.pid"
        path.write_text(value, encoding="ascii")
        return path

    def ns1_assert_only_monitor_stopped(
        self, implementation, error_type, pid_path: Path | None,
    ) -> None:
        signals: list = []
        try:
            stopped = self.ns1_stop(implementation, signals)
        except error_type as exc:
            self.fail(f"an unrelated process blocked the Native Monitor stop: {exc}")
        self.assertEqual((self.NS1_MONITOR_PID,), stopped)
        self.assertEqual([(self.NS1_MONITOR_PID, signal.SIGTERM)], signals)
        if pid_path is not None:
            self.assertFalse(pid_path.exists())

    def ns1_assert_refused(self, implementation, error_type, pid_path: Path | None) -> None:
        before = None
        if pid_path is not None:
            status = pid_path.stat()
            before = (pid_path.read_bytes(), status.st_dev, status.st_ino)
        signals: list = []
        with self.assertRaises(error_type):
            self.ns1_stop(implementation, signals)
        self.assertEqual([], signals)
        if pid_path is not None:
            status = pid_path.stat()
            self.assertEqual(before, (pid_path.read_bytes(), status.st_dev, status.st_ino))

    def test_ns1_unrelated_long_cmdline_never_blocks_the_monitor_stop(self) -> None:
        # Guide :671-:674 rules A/B and :689-:693: argv0 ssh/java, or python with a
        # different script in the script slot, is not the monitor at any length or
        # tail encoding; the real monitor 9100 alone gets exactly one SIGTERM.
        prefixes = {
            "ssh": b"ssh\0",
            "java": b"/usr/bin/java\0",
            "python3_other": b"/usr/bin/python3\0/opt/tools/other.py\0",
            "python3_u_other": b"/usr/bin/python3\0-u\0/opt/tools/other.py\0",
            "python3_B_other": b"/usr/bin/python3\0-B\0/opt/tools/other.py\0",
        }
        tails = {"ascii": b"-oSetting=value\0", "bad_utf8": b"\xff\xfe\x80\0"}
        for name, implementation, error_type in self.ns1_implementations():
            for kind, prefix in prefixes.items():
                for total in (65535, 65536, 65537, 70000):
                    for tail, unit in tails.items():
                        with self.subTest(implementation=name, kind=kind, total=total, tail=tail):
                            self.ns1_reset()
                            self.add_raw_process(self.NS1_MONITOR_PID, self.ns1_monitor_raw())
                            pid_path = self.write_pid("9100\n")
                            self.add_raw_process(9200, self.ns1_cmdline(prefix, total, unit))
                            self.ns1_assert_only_monitor_stopped(implementation, error_type, pid_path)

    def test_ns1_empty_cmdlines_are_not_monitors_but_a_referenced_one_is_refused(self) -> None:
        # Guide :672 rule a and :694: unreferenced 0-byte cmdlines (kernel threads,
        # zombies) are not monitors and never HOLD; a PID file naming one is refused.
        for name, implementation, error_type in self.ns1_implementations():
            with self.subTest(implementation=name, case="unreferenced"):
                self.ns1_reset()
                for pid in (2, 3, 57):
                    self.add_raw_process(pid, b"")
                self.add_raw_process(self.NS1_MONITOR_PID, self.ns1_monitor_raw())
                self.ns1_assert_only_monitor_stopped(implementation, error_type, None)
            with self.subTest(implementation=name, case="referenced"):
                self.ns1_reset()
                self.add_raw_process(self.NS1_MONITOR_PID, self.ns1_monitor_raw())
                self.add_raw_process(9300, b"")
                pid_path = self.ns1_project_pid("customer-b", "9300\n")
                self.ns1_assert_refused(implementation, error_type, pid_path)

    def test_ns1_candidate_monitor_keeps_the_complete_64k_contract(self) -> None:
        # Guide :675 rule d and :695: the expected script in the script slot is a
        # candidate; it is read completely.  A legal long --output-dir value with a
        # total of 65536 bytes is stopped; 65537, 70000 or bad UTF-8 are refused with
        # zero signals even next to a legal monitor.
        head = self.ns1_monitor_raw("--output-dir")
        for name, implementation, error_type in self.ns1_implementations():
            with self.subTest(implementation=name, total=65536):
                self.ns1_reset()
                self.add_raw_process(
                    self.NS1_MONITOR_PID, self.ns1_cmdline(head + b"/", 65536, b"d"),
                )
                self.ns1_assert_only_monitor_stopped(implementation, error_type, None)
            for case, raw in (
                ("65537", self.ns1_cmdline(head + b"/", 65537, b"d")),
                ("70000", self.ns1_cmdline(head + b"/", 70000, b"d")),
                ("bad_utf8_short", head + b"/data/\xff\xfe\0"),
                ("bad_utf8_65536", self.ns1_cmdline(head + b"/data/", 65536, b"\xff")),
            ):
                with self.subTest(implementation=name, case=case):
                    self.ns1_reset()
                    self.add_raw_process(self.NS1_MONITOR_PID, self.ns1_monitor_raw())
                    pid_path = self.write_pid("9100\n")
                    self.add_raw_process(9400, raw)
                    self.ns1_assert_refused(implementation, error_type, pid_path)

    def test_ns1_budget_cut_inside_an_undecided_token_keeps_the_original_error(self) -> None:
        # Guide :671 (read until EOF or 65537 bytes) and :696: a token cut by the
        # budget cannot be judged, so the original size error stays; argv0 whose
        # NUL is the 65537th byte is complete and is excluded by rule A.
        refused = {
            "argv0_70000": b"/usr/bin/" + b"p" * 70000 + b"\0",
            "argv0_exactly_65537": b"p" * 65537 + b"\0tail\0",
            "flag_cut": b"/usr/bin/python3\0-" + b"u" * 70000 + b"\0",
            "slot_cut": b"/usr/bin/python3\0/opt/" + b"s" * 70000 + b"\0",
            "slot_cut_after_u": b"/usr/bin/python3\0-u\0/opt/" + b"s" * 70000 + b"\0",
        }
        for name, implementation, error_type in self.ns1_implementations():
            for case, raw in refused.items():
                with self.subTest(implementation=name, case=case):
                    self.ns1_reset()
                    self.add_raw_process(self.NS1_MONITOR_PID, self.ns1_monitor_raw())
                    pid_path = self.write_pid("9100\n")
                    self.add_raw_process(9500, raw)
                    self.ns1_assert_refused(implementation, error_type, pid_path)
            with self.subTest(implementation=name, case="argv0_nul_is_byte_65537"):
                self.ns1_reset()
                self.add_raw_process(self.NS1_MONITOR_PID, self.ns1_monitor_raw())
                pid_path = self.write_pid("9100\n")
                self.add_raw_process(9500, b"p" * 65536 + b"\0" + b"t" * 5000 + b"\0")
                self.ns1_assert_only_monitor_stopped(implementation, error_type, pid_path)

    def test_ns1_final_token_without_nul_keeps_the_original_complete_grammar(self) -> None:
        # Guide :696: a last token without its NUL goes to the original complete
        # judgement: a legal monitor without a trailing NUL or with several trailing
        # NULs is still the monitor; an empty middle token makes a second positional
        # (two positionals are not the grammar), so that process is not a monitor.
        monitor = self.ns1_monitor_raw()
        for name, implementation, error_type in self.ns1_implementations():
            for case, raw in (
                ("no_trailing_nul", monitor[:-1]),
                ("several_trailing_nuls", monitor + b"\0\0"),
            ):
                with self.subTest(implementation=name, case=case):
                    self.ns1_reset()
                    self.add_raw_process(self.NS1_MONITOR_PID, raw)
                    self.ns1_assert_only_monitor_stopped(implementation, error_type, None)
            script = os.fspath(self.http_root / "DAY0-Prepare/12-ztp-monitor.py").encode()
            project = os.fspath(self.project).encode()
            for case, raw in (
                ("empty_middle_token",
                 b"/usr/bin/python3\0" + script + b"\0" + project + b"\0\0--watch\x0030\0"),
                ("ssh_without_nul", b"ssh"),
                ("python3_u_only", b"/usr/bin/python3\0-u"),
            ):
                with self.subTest(implementation=name, case=case):
                    self.ns1_reset()
                    self.add_raw_process(8301, raw)
                    signals: list = []
                    self.assertEqual((), self.ns1_stop(implementation, signals))
                    self.assertEqual([], signals)

    def test_ns1_referenced_pid_stays_strict_for_unrelated_processes(self) -> None:
        # Guide :670 item 1 and :697: a PID file naming ssh, another script, an
        # oversized or a bad-tail process is refused with zero signals and the PID
        # file bytes and inode stay unchanged.
        referenced = {
            "ssh": b"ssh\0-T\0host\0",
            "other_script": b"/usr/bin/python3\0/opt/tools/other.py\0",
            "oversized": self.ns1_cmdline(b"ssh\0", 70000, b"-oSetting=value\0"),
            "bad_tail": b"ssh\0\xff\xfe\0",
        }
        for name, implementation, error_type in self.ns1_implementations():
            for case, raw in referenced.items():
                with self.subTest(implementation=name, case=case):
                    self.ns1_reset()
                    self.add_raw_process(self.NS1_MONITOR_PID, self.ns1_monitor_raw())
                    self.add_raw_process(9600, raw)
                    pid_path = self.ns1_project_pid("customer-b", "9600\n")
                    self.ns1_assert_refused(implementation, error_type, pid_path)

    def test_ns1_process_gone_while_reading_is_gone_but_unreadable_stays_refused(self) -> None:
        # Guide :676 rule e and :698: when the read fails and /proc/<pid> no longer
        # exists the process has exited ("gone"); when the directory is still there
        # the original error stays (as test_cmdline_unreadable_before_signal_is_fail_closed).
        real_open = os.open
        for name, implementation, error_type in self.ns1_implementations():
            for case in ("directory_gone", "cmdline_unreadable"):
                with self.subTest(implementation=name, case=case):
                    self.ns1_reset()
                    self.add_raw_process(self.NS1_MONITOR_PID, self.ns1_monitor_raw())
                    pid_path = self.write_pid("9100\n")
                    vanishing = self.add_raw_process(9700, b"ssh\0-T\0host\0")
                    target = os.fspath(vanishing / "cmdline")

                    def opening(path, flags, *args, **kwargs):
                        if os.fspath(path) == target and (vanishing / "cmdline").exists():
                            (vanishing / "cmdline").unlink()
                            if case == "directory_gone":
                                vanishing.rmdir()
                        return real_open(path, flags, *args, **kwargs)

                    with mock.patch.object(os, "open", opening):
                        if case == "directory_gone":
                            self.ns1_assert_only_monitor_stopped(implementation, error_type, pid_path)
                        else:
                            self.ns1_assert_refused(implementation, error_type, pid_path)

    def test_ns1_original_grammar_vectors_keep_their_results(self) -> None:
        # Guide :699 and 8.22.1: python basenames (str.isdigit semantics, including a
        # Unicode digit suffix), a non-standard directory and a single -u/-B flag are
        # the monitor; other names, a second flag, an unsupported flag in the script
        # slot and a duplicate script as an option value are not.
        script = os.fspath(self.http_root / "DAY0-Prepare/12-ztp-monitor.py")
        project = os.fspath(self.project)
        tail = (project, "--watch", "30")
        accepted = {
            "python": ("python", script) + tail,
            "python3": ("python3", script) + tail,
            "python3_9": ("python3.9", script) + tail,
            "python3_12_custom_dir": ("/opt/custom/bin/python3.12", script) + tail,
            "python3_unicode_digit": ("/usr/bin/python3.٣", script) + tail,
            "single_u_flag": ("/usr/local/bin/python3.11", "-u", script) + tail,
            "single_B_flag": ("python3", "-B", script) + tail,
        }
        rejected = {
            "python2": ("/usr/bin/python2", script) + tail,
            "python3_dot_only": ("/usr/bin/python3.", script) + tail,
            "python3_letter_suffix": ("/usr/bin/python3.x", script) + tail,
            "pypy3": ("/usr/bin/pypy3", script) + tail,
            "python3_config": ("/usr/bin/python3-config", script) + tail,
            "unsupported_flag": ("/usr/bin/python3", "-I", script) + tail,
            "two_flags": ("/usr/bin/python3", "-u", "-B", script) + tail,
            "duplicate_script_as_option_value": (
                "/usr/bin/python3", script, project, "--watch", "30",
                "--html-script", script,
            ),
        }
        for name, implementation, error_type in self.ns1_implementations():
            for case, argv in accepted.items():
                with self.subTest(implementation=name, case=case, expected="monitor"):
                    self.ns1_reset()
                    self.add_process(self.NS1_MONITOR_PID, argv)
                    self.ns1_assert_only_monitor_stopped(implementation, error_type, None)
            for case, argv in rejected.items():
                with self.subTest(implementation=name, case=case, expected="not-monitor"):
                    self.ns1_reset()
                    self.add_process(8301, argv)
                    signals: list = []
                    self.assertEqual((), self.ns1_stop(implementation, signals))
                    self.assertEqual([], signals)


if __name__ == "__main__":
    unittest.main()
