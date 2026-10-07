#!/usr/bin/env python3
"""Direct contract tests for required per-device bootstrap configuration fetches."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import tempfile
import textwrap
from typing import Optional
import unittest
from unittest import mock

from test_cases.subprocess_timeout_evidence import capture_timeout_before_cleanup


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_PATH = ROOT / "ztp/templates/ztp-bootstrap.sh"
MAC = "02:00:00:00:00:31"
MAC_FILE = MAC.replace(":", "") + ".yaml"
EXPECTED_FETCH_OPTIONS = {
    "--retry": "5",
    "--retry-delay": "3",
    "--connect-timeout": "5",
    "--max-time": "120",
}


def _write_executable(directory: Path, name: str, source: str) -> None:
    path = directory / name
    path.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
    path.chmod(0o755)


class BootstrapFetchTimeout(subprocess.TimeoutExpired):
    """Keep the original timeout failure and private fixture evidence after cleanup."""

    def __init__(self, original: subprocess.TimeoutExpired, diagnostic: dict):
        super().__init__(original.cmd, original.timeout, output=original.output, stderr=original.stderr)
        self.bootstrap_diagnostics = diagnostic

    def __str__(self) -> str:
        evidence = json.dumps(self.bootstrap_diagnostics, ensure_ascii=False, sort_keys=True)
        return super().__str__() + "; bootstrap fixture evidence=" + evidence[:16000]


def _partial_output_tail(value, limit: int = 2048) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value[-limit:].decode("utf-8", errors="replace")
    return value[-limit:]


def _timeout_event_evidence(events: Path) -> dict:
    """Only read the bounded tail of a held regular fixture file; label races."""
    try:
        fd = os.open(events, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                return {"stable": False, "error": "events is not a regular file"}
            os.lseek(fd, max(0, before.st_size - 8192), os.SEEK_SET)
            tail = os.read(fd, 8192)
            after = os.fstat(fd)
            named = events.lstat()
            identity = lambda value: (
                value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                value.st_size, value.st_mtime_ns, value.st_ctime_ns,
            )
            stable = identity(before) == identity(after) == identity(named)
            return {
                "stable": stable, "inode": before.st_ino, "size": before.st_size,
                "mtime_ns": before.st_mtime_ns, "ctime_ns": before.st_ctime_ns,
                "tail": tail.decode("utf-8", errors="replace") if stable else "",
            }
        finally:
            os.close(fd)
    except OSError as error:
        return {"stable": False, "error": f"{type(error).__name__}: {error}"}


def run_bootstrap_fetch(
    root: Path,
    *,
    response_codes: tuple[str, ...],
    payload: str = "valid",
    product_name: str = "SN5600",
    dedicated_apply_fail: bool = False,
    default_available: bool = True,
    template_source: Optional[str] = None,
) -> tuple[subprocess.CompletedProcess[str], list[str], Path, Path]:
    """Run the real Cumulus bootstrap with a deterministic HTTP/NVUE boundary."""
    root.mkdir(parents=True, exist_ok=True)
    runtime_root = root / "run"
    state_root = root / "state"
    switch_home = root / "home/cumulus"
    fake_bin = root / "bin"
    runtime_root.mkdir()
    switch_home.mkdir(parents=True)
    fake_bin.mkdir()
    events = root / "events.log"
    attempt_file = root / "dedicated-attempts"

    _write_executable(fake_bin, "ip", """
        #!/bin/sh
        if [ "$1" = vrf ] && [ "$2" = exec ]; then
            shift 3
            exec "$@"
        fi
        exit 1
    """)
    _write_executable(fake_bin, "chown", """
        #!/bin/sh
        exit 0
    """)
    _write_executable(fake_bin, "sleep", """
        #!/bin/sh
        printf 'sleep:%s\n' "$*" >> "$EVENTS"
        exit 0
    """)
    _write_executable(fake_bin, "nv", """
        #!/bin/sh
        printf 'nv:%s\n' "$*" >> "$EVENTS"
        if [ "$NV_REPLACE_FAIL" = 1 ] && [ "$1 $2" = "config replace" ]; then
            exit 1
        fi
        exit 0
    """)
    _write_executable(fake_bin, "curl", r"""
        #!/bin/sh
        printf 'curl-argv:%s\n' "$*" >> "$EVENTS"
        output=
        write_out=
        url=
        retry=0
        retry_delay=
        retry_connrefused=0
        while [ "$#" -gt 0 ]; do
            case "$1" in
                -o|--output) output=$2; shift 2 ;;
                -w|--write-out) write_out=$2; shift 2 ;;
                --retry) retry=$2; shift 2 ;;
                --retry-delay) retry_delay=$2; shift 2 ;;
                --retry-connrefused) retry_connrefused=1; shift ;;
                --connect-timeout|--max-time|--range) shift 2 ;;
                -*) shift ;;
                *) url=$1; shift ;;
            esac
        done
        printf 'curl:%s\n' "$url" >> "$EVENTS"
        body='- set:\n    system:\n      hostname: leaf31\n'
        case "$url" in
            */020000000031.yaml)
                used=0
                while [ "$used" -le "$retry" ]; do
                    used=$((used + 1))
                    count=0
                    if [ -f "$ATTEMPT_FILE" ]; then count=$(cat "$ATTEMPT_FILE"); fi
                    count=$((count + 1))
                    printf '%s\n' "$count" > "$ATTEMPT_FILE"
                    old_ifs=$IFS
                    IFS=,
                    set -- $RESPONSE_CODES
                    IFS=$old_ifs
                    eval "code=\${$count:-}"
                    if [ -z "$code" ]; then eval "code=\${$#}"; fi
                    printf 'http-attempt:%s:%s:%s\n' "$url" "$count" "$code" >> "$EVENTS"
                    if [ "$code" = 200 ]; then
                        if [ "$DEDICATED_PAYLOAD" = empty ]; then body=; fi
                        if [ -n "$output" ] && [ "$output" != /dev/null ]; then
                            printf '%b' "$body" > "$output"
                        fi
                        if [ -n "$write_out" ]; then printf '%s' "$code"; fi
                        exit 0
                    fi
                    case "$code" in
                        000) retryable=$retry_connrefused ;;
                        5??) retryable=1 ;;
                        *) retryable=0 ;;
                    esac
                    if [ "$retryable" != 1 ] || [ "$used" -gt "$retry" ]; then break; fi
                    printf 'retry-delay:%s\n' "$retry_delay" >> "$EVENTS"
                done
                rm -f -- "$output"
                if [ -n "$write_out" ]; then printf '%s' "$code"; fi
                if [ "$code" = 000 ]; then exit 28; fi
                exit 22
                ;;
            *.mode) code=200; body='patch\n' ;;
            *.spx) code=404; body= ;;
            *.pub) code=200; body='ssh-ed25519 AAAATEST bootstrap-contract\n' ;;
            *)
                case "$url" in
                    */config/nvos/latest_yaml/default_*.yaml)
                        if [ "$DEFAULT_AVAILABLE" = 1 ]; then code=200; else code=404; body=; fi
                        ;;
                    *) code=200 ;;
                esac
                ;;
        esac
        if [ -n "$output" ] && [ "$output" != /dev/null ]; then
            if [ "$code" = 200 ]; then printf '%b' "$body" > "$output"; else rm -f -- "$output"; fi
        fi
        if [ -n "$write_out" ]; then printf '%s' "$code"; fi
        case "$code" in
            2??) exit 0 ;;
            000) exit 28 ;;
            *) exit 22 ;;
        esac
    """)

    source = (
        TEMPLATE_PATH.read_text(encoding="utf-8")
        if template_source is None
        else template_source
    )
    source = source.replace(
        'RUNTIME_WORK_ROOT="/run"',
        f"RUNTIME_WORK_ROOT={shlex.quote(str(runtime_root))}", 1,
    ).replace(
        'APPLIED_STATE_DIR="/var/lib/nvidia-ztp"',
        f"APPLIED_STATE_DIR={shlex.quote(str(state_root))}", 1,
    ).replace(
        "PROD_NAME=$(decode-syseeprom 2>/dev/null | grep '^Product Name' | awk '{print $NF}' || echo \"unknown\")",
        f'PROD_NAME={shlex.quote(product_name)}', 1,
    ).replace(
        "IMG_VER=$(grep '^IMAGE_RELEASE=' /etc/image-release | awk -F'=' '{print $2}')",
        'IMG_VER="5.16.4"', 1,
    ).replace(
        "RUN_VER=$(grep '^DISTRIB_RELEASE=' /etc/lsb-release | awk -F'=' '{print $2}')",
        'RUN_VER="5.16.4"', 1,
    ).replace(
        'ETH0_RAW_MAC=$(cat /sys/class/net/eth0/address)',
        f'ETH0_RAW_MAC="{MAC}"',
    ).replace(
        'USER_HOME=/home/${USER_NAME}', 'USER_HOME="${TEST_HOME}"',
    ).replace(
        '        install_manual_ztp_helper\n',
        '        : # helper installation tested independently\n', 1,
    ).replace(
        '        install_applied_config_helper "${USER_NAME}"\n',
        '        : # helper installation tested independently\n',
    ).replace(
        '        install_time_sync_helper "${USER_NAME}"\n',
        '        : # helper installation tested independently\n',
    )
    source = re.sub(
        r'if ! select_ztp_network_path; then\n.*?\nfi\n\n'
        r'if ! check_network "\$\{ZTP_SERVER_HOST\}"; then\n.*?\nfi',
        'ZTP_VRF="default"\nZTP_INTERFACE="eth0"',
        source, count=1, flags=re.S,
    )
    source = re.sub(
        r'if ! sync_management_clock_for_ztp; then\n.*?\nfi\n'
        r'log "\[ZTP\] Network check passed after management-server time sync:.*?"',
        'log "[ZTP] Network/time prerequisites mocked for fetch contract"',
        source, count=1, flags=re.S,
    )
    script = root / "bootstrap.sh"
    script.write_text(source, encoding="utf-8")
    script.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ.get('PATH', '')}",
        "EVENTS": str(events),
        "ATTEMPT_FILE": str(attempt_file),
        "RESPONSE_CODES": ",".join(response_codes),
        "DEDICATED_PAYLOAD": payload,
        "NV_REPLACE_FAIL": "1" if dedicated_apply_fail else "0",
        "DEFAULT_AVAILABLE": "1" if default_available else "0",
        "TEST_HOME": str(switch_home),
    }
    try:
        with capture_timeout_before_cleanup(expected_command=["bash", str(script)]):
            result = subprocess.run(
                ["bash", str(script)], text=True, capture_output=True,
                check=False, env=env, timeout=15,
            )
    except subprocess.TimeoutExpired as error:
        process_evidence = getattr(error, "prekill_process_evidence", None)
        raise BootstrapFetchTimeout(error, {
            "events": _timeout_event_evidence(events),
            "stdout_tail": _partial_output_tail(error.output),
            "stderr_tail": _partial_output_tail(error.stderr),
            "response_codes": response_codes,
            "descendant_state": (process_evidence.get("descendant_state", "unknown")
                                 if isinstance(process_evidence, dict)
                                 else "not captured by subprocess.run; unknown"),
            "prekill_process": process_evidence,
        }) from error
    lines = events.read_text(encoding="utf-8").splitlines() if events.exists() else []
    return result, lines, state_root, switch_home


def dedicated_fetches(events: list[str]) -> list[str]:
    suffix = f"/ztp/config/cumulus/latest_yaml/{MAC_FILE}"
    return [
        event for event in events
        if event.startswith("http-attempt:http://") and f"{suffix}:" in event
    ]


def dedicated_curl_argv(events: list[str]) -> list[list[str]]:
    return [
        shlex.split(event.removeprefix("curl-argv:"))
        for event in events
        if event.startswith("curl-argv:") and MAC_FILE in event
    ]


def managed_config_curl_argv(events: list[str]) -> list[list[str]]:
    return [
        shlex.split(event.removeprefix("curl-argv:"))
        for event in events
        if event.startswith("curl-argv:") and "/ztp/config/cumulus/" in event
    ]


def assert_exact_fetch_policy(testcase: unittest.TestCase, events: list[str]) -> None:
    commands = managed_config_curl_argv(events)
    testcase.assertGreaterEqual(len(commands), 6, commands)
    for args in commands:
        testcase.assertEqual(1, args.count("--retry-connrefused"), args)
        testcase.assertNotIn("--no-retry-connrefused", args)
        testcase.assertFalse(
            any(token.startswith("--retry-connrefused=") for token in args),
            args,
        )
        testcase.assertNotIn("--retry-all-errors", args)
        testcase.assertNotIn("--no-fail", args)
        testcase.assertNotIn("--no-fail-with-body", args)
        testcase.assertFalse(
            any(token.startswith("--fail=") for token in args),
            args,
        )
        testcase.assertTrue(
            "--fail" in args
            or "--fail-with-body" in args
            or any(
                token.startswith("-")
                and not token.startswith("--")
                and "f" in token[1:]
                for token in args
            ),
            args,
        )
        testcase.assertFalse(
            any(
                token.startswith("-")
                and not token.startswith("--")
                and "m" in token[1:]
                for token in args
            ),
            args,
        )
        for option, value in EXPECTED_FETCH_OPTIONS.items():
            testcase.assertEqual(1, args.count(option), args)
            testcase.assertFalse(
                any(token.startswith(option + "=") for token in args),
                args,
            )
            testcase.assertEqual(value, args[args.index(option) + 1], args)


def config_mutations(events: list[str]) -> list[str]:
    return [event for event in events if event.startswith("nv:config ")]


def default_mutations(events: list[str]) -> list[str]:
    return [
        event for event in config_mutations(events)
        if event.startswith("nv:config patch ") and MAC_FILE not in event
    ]


class BootstrapFetchHarnessDiagnosticsTests(unittest.TestCase):
    def test_timeout_retains_precleanup_snapshot_without_changing_original_failure(self):
        snapshot = {"capture_phase": "before_cleanup", "pid": 7301, "returncode": None,
                    "root": {"pid": 7301, "state": "S"}, "descendants": [], "stage": "unknown"}
        original = subprocess.TimeoutExpired(["bash", "private-script"], 15, output=b"original partial output")
        original.prekill_process_evidence = snapshot
        with tempfile.TemporaryDirectory(prefix="bootstrap-precleanup-diagnostic-") as name:
            with mock.patch.object(subprocess, "run", side_effect=original):
                with self.assertRaises(subprocess.TimeoutExpired) as caught:
                    run_bootstrap_fetch(Path(name), response_codes=("401",))
        diagnostic = caught.exception.bootstrap_diagnostics
        self.assertIn("prekill_process", diagnostic)
        self.assertIs(snapshot, diagnostic["prekill_process"])
        self.assertIs(original, caught.exception.__cause__)
        self.assertIs(original.output, caught.exception.output)
        self.assertEqual(15, caught.exception.timeout)

    def test_timeout_event_same_inode_aba_is_not_stable_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            events = Path(directory) / "events.log"
            original = b"last-event:401\n"
            events.write_bytes(original)
            metadata = events.stat()
            real_read = os.read
            observed = []

            def mutate_after_read(descriptor, count):
                payload = real_read(descriptor, count)
                opened = os.fstat(descriptor)
                if not observed and (opened.st_dev, opened.st_ino) == (metadata.st_dev, metadata.st_ino):
                    observed.append(True)
                    events.write_bytes(b"last-event:403\n")
                    events.write_bytes(original)
                    os.utime(events, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
                    after = events.stat()
                    self.assertEqual((metadata.st_ino, metadata.st_size, metadata.st_mtime_ns),
                                     (after.st_ino, after.st_size, after.st_mtime_ns))
                    self.assertNotEqual(metadata.st_ctime_ns, after.st_ctime_ns)
                return payload

            with mock.patch.object(os, "read", side_effect=mutate_after_read):
                diagnostic = _timeout_event_evidence(events)
            self.assertTrue(observed)
            self.assertFalse(diagnostic["stable"], "same-inode ABA cannot be frozen failure evidence")
            self.assertEqual("", diagnostic["tail"], "do not emit an untrusted event tail as evidence")
            self.assertEqual(original, events.read_bytes())

    def test_timeout_keeps_fifteen_second_limit_and_original_partial_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def timeout(command, **options):
                self.assertEqual(15, options["timeout"])
                (root / "events.log").write_text("last-event:401\n", encoding="utf-8")
                raise subprocess.TimeoutExpired(
                    command, 15, output=b"fixture-stage-before-auth\n",
                    stderr=b"fixture-child-stderr\n",
                )

            with mock.patch.object(subprocess, "run", side_effect=timeout):
                with self.assertRaises(subprocess.TimeoutExpired) as caught:
                    run_bootstrap_fetch(root, response_codes=("401", "200"))
            error = caught.exception
            self.assertEqual(15, error.timeout)
            self.assertEqual(b"fixture-stage-before-auth\n", error.output)
            self.assertEqual(b"fixture-child-stderr\n", error.stderr)
            diagnostic = getattr(error, "bootstrap_diagnostics", None)
            self.assertIsNotNone(diagnostic, "timeout discarded its private fixture evidence")
            self.assertEqual("last-event:401\n", diagnostic["events"]["tail"])
            self.assertIn("fixture-stage-before-auth", str(error))
            self.assertIn("fixture-child-stderr", str(error))
            self.assertIn("last-event:401", str(error))

    def test_timeout_evidence_is_bounded_and_includes_last_not_first_event(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def timeout(command, **options):
                (root / "events.log").write_bytes(b"old-event\n" * 10000 + b"last-event:401\n")
                raise subprocess.TimeoutExpired(command, 15, output=b"s" * 100000, stderr=b"e" * 100000)

            with mock.patch.object(subprocess, "run", side_effect=timeout):
                with self.assertRaises(subprocess.TimeoutExpired) as caught:
                    run_bootstrap_fetch(root, response_codes=("401",))
            diagnostic = getattr(caught.exception, "bootstrap_diagnostics", None)
            self.assertIsNotNone(diagnostic, "timeout has no bounded failure report")
            self.assertLessEqual(len(diagnostic["events"]["tail"].encode()), 8192)
            self.assertTrue(diagnostic["events"]["tail"].endswith("last-event:401\n"))
            self.assertLess(len(str(caught.exception)), 18000)
            self.assertEqual(100000, len(caught.exception.output))
            self.assertEqual(100000, len(caught.exception.stderr))


class RequiredDeviceConfigFetchTests(unittest.TestCase):
    def test_nvos_default_fetch_is_release_bound_and_family_selected(self):
        source = TEMPLATE_PATH.read_text(encoding="utf-8")
        nvos = source.split(
            'elif [[ "${PROD_NAME}" == ${IBSW}', 1,
        )[1].split('else\n    USER_NAME="root"', 1)[0]
        self.assertIn("latest_yaml/default_ib.yaml", nvos)
        self.assertIn("latest_yaml/default_nvl.yaml", nvos)
        self.assertNotIn('GLOBAL_BASE_CFG="${CFG_BASE_URL}/default.yaml"', nvos)

    def test_nvos_family_release_default_crosses_real_bootstrap_fallback(self):
        for product, family_name in (("QM9700", "default_ib.yaml"), ("NVL-SW", "default_nvl.yaml")):
            for response_codes, apply_fail, expected_source in (
                (("404",), False, "default"),
                (("200",), True, "fallback_default"),
            ):
                with self.subTest(product=product, apply_fail=apply_fail):
                    result, events, state, _home = self.run_case(
                        response_codes=response_codes,
                        product_name=product,
                        dedicated_apply_fail=apply_fail,
                    )
                    self.assertEqual(0, result.returncode, result.stderr + result.stdout)
                    urls = [event for event in events if event.startswith("curl:http://")]
                    selected = [event for event in urls if family_name in event]
                    self.assertEqual(1, len(selected), events)
                    self.assertFalse(any("/config/nvos/default.yaml" in event for event in urls), urls)
                    self.assertLess(events.index(selected[0]), next(
                        index for index, event in enumerate(events)
                        if event.startswith("curl-argv:") and MAC_FILE in event
                    ))
                    self.assertTrue(any(event.startswith("nv:config patch ") for event in events), events)
                    receipt = (state / "receipt.env").read_text(encoding="utf-8")
                    self.assertIn(f"source_kind={expected_source}", receipt)
                    self.assertIn(f"source_name={family_name}", receipt)

    def test_nvos_fallback_fails_closed_without_selected_release_default(self):
        for product, family_name in (("QM9700", "default_ib.yaml"), ("NVL-SW", "default_nvl.yaml")):
            with self.subTest(product=product):
                result, events, state, _home = self.run_case(
                    response_codes=("404",), product_name=product,
                    default_available=False,
                )
                self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
                self.assertTrue(any(family_name in event for event in events), events)
                self.assertFalse(any("/config/nvos/default.yaml" in event for event in events), events)
                self.assertFalse((state / "receipt.env").exists())
                self.assertFalse(any(event.startswith("nv:config patch ") for event in events), events)

    def run_case(self, **kwargs):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        return run_bootstrap_fetch(Path(directory.name), **kwargs)

    def assert_fetch_policy(self, events: list[str]) -> None:
        commands = dedicated_curl_argv(events)
        self.assertEqual(1, len(commands), commands)
        assert_exact_fetch_policy(self, events)

    def assert_no_success_side_effects(
        self, events: list[str], state: Path, home: Path,
    ) -> None:
        self.assertEqual([], [event for event in events if event.startswith("nv:")], events)
        self.assertFalse((state / "receipt.env").exists())
        self.assertFalse((state / "last-success.yaml").exists())
        self.assertFalse((home / ".ssh/authorized_keys").exists())

    def test_policy_oracle_rejects_bundled_short_max_time_override(self):
        base = (
            "curl-argv:--retry 5 --retry-delay 3 --retry-connrefused "
            "--connect-timeout 5 --max-time 120 {short} "
            "http://127.0.0.1/ztp/config/cumulus/default.yaml -o /tmp/default"
        )
        for short in ("-sfm0", "-sm0f"):
            with self.subTest(short=short):
                events = [base.format(short=short)] * 6
                with self.assertRaises(AssertionError):
                    assert_exact_fetch_policy(self, events)

    def test_transport_failure_recovers_within_curl_retry_bound(self):
        result, events, _state, _home = self.run_case(response_codes=("000", "200"))
        self.assertEqual(0, result.returncode, result.stderr + result.stdout)
        self.assert_fetch_policy(events)
        self.assertEqual(2, len(dedicated_fetches(events)), events)
        self.assertTrue(
            any(event.startswith("nv:config patch ") and MAC_FILE in event for event in events),
            events,
        )
        self.assertEqual([], default_mutations(events), events)

    def test_each_retryable_server_error_recovers_without_default_mutation(self):
        for status in ("500", "502", "503", "504"):
            with self.subTest(status=status):
                result, events, _state, _home = self.run_case(
                    response_codes=(status, "200"),
                )
                self.assertEqual(0, result.returncode, result.stderr + result.stdout)
                self.assert_fetch_policy(events)
                self.assertEqual(2, len(dedicated_fetches(events)), events)
                self.assertEqual([], default_mutations(events), events)

    def test_transport_exhaustion_is_six_attempts_and_has_no_post_final_delay(self):
        result, events, state, home = self.run_case(
            response_codes=("000", "000", "000", "000", "000", "000", "200"),
        )
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assert_fetch_policy(events)
        self.assertEqual(6, len(dedicated_fetches(events)), events)
        self.assertEqual(5, events.count("retry-delay:3"), events)
        self.assert_no_success_side_effects(events, state, home)
        self.assertRegex(
            result.stdout + result.stderr,
            r"CONFIG_FETCH_V1[^\n]*class=transient-exhausted[^\n]*attempts=6",
        )

    def test_server_error_exhaustion_fails_instead_of_applying_default(self):
        result, events, state, home = self.run_case(
            response_codes=("503", "503", "503", "503", "503", "503", "200"),
        )
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assert_fetch_policy(events)
        self.assertEqual(6, len(dedicated_fetches(events)), events)
        self.assertEqual(5, events.count("retry-delay:3"), events)
        self.assert_no_success_side_effects(events, state, home)
        self.assertRegex(
            result.stdout + result.stderr,
            r"CONFIG_FETCH_V1[^\n]*class=transient-exhausted[^\n]*attempts=6",
        )

    def test_http_404_uses_default_but_marks_provisioning_degraded(self):
        result, events, state, _home = self.run_case(response_codes=("404",))
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assert_fetch_policy(events)
        self.assertEqual(1, len(dedicated_fetches(events)), events)
        self.assertEqual(1, len(default_mutations(events)), events)
        self.assertIn("[ZTP] PROVISION_DEGRADED", result.stdout + result.stderr)
        receipt = (state / "receipt.env").read_text(encoding="utf-8")
        self.assertIn("source_kind=default\n", receipt)

    def test_authentication_or_authorization_errors_fail_permanently(self):
        for status in ("401", "403"):
            with self.subTest(status=status):
                result, events, state, home = self.run_case(response_codes=(status, "200"))
                self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
                self.assert_fetch_policy(events)
                self.assertEqual(1, len(dedicated_fetches(events)), events)
                self.assert_no_success_side_effects(events, state, home)
                self.assertRegex(result.stdout + result.stderr, r"CONFIG_FETCH_V1[^\n]*class=auth")

    def test_empty_success_response_is_an_integrity_error(self):
        result, events, state, home = self.run_case(response_codes=("200",), payload="empty")
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assert_fetch_policy(events)
        self.assertEqual(1, len(dedicated_fetches(events)), events)
        self.assert_no_success_side_effects(events, state, home)
        self.assertRegex(result.stdout + result.stderr, r"CONFIG_FETCH_V1[^\n]*class=integrity")


if __name__ == "__main__":
    unittest.main()
