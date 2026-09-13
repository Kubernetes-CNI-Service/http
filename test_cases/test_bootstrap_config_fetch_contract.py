#!/usr/bin/env python3
"""Direct contract tests for required per-device bootstrap configuration fetches."""

from __future__ import annotations

import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import textwrap
from typing import Optional
import unittest


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


def run_bootstrap_fetch(
    root: Path,
    *,
    response_codes: tuple[str, ...],
    payload: str = "valid",
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
            *) code=200 ;;
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
        'PROD_NAME="SN5600"', 1,
    ).replace(
        "IMG_VER=$(grep '^IMAGE_RELEASE=' /etc/image-release | awk -F'=' '{print $2}')",
        'IMG_VER="5.16.4"', 1,
    ).replace(
        "RUN_VER=$(grep '^DISTRIB_RELEASE=' /etc/lsb-release | awk -F'=' '{print $2}')",
        'RUN_VER="5.16.4"', 1,
    ).replace(
        'ETH0_RAW_MAC=$(cat /sys/class/net/eth0/address)',
        f'ETH0_RAW_MAC="{MAC}"', 1,
    ).replace(
        'USER_HOME=/home/${USER_NAME}', 'USER_HOME="${TEST_HOME}"', 1,
    ).replace(
        '        install_manual_ztp_helper\n',
        '        : # helper installation tested independently\n', 1,
    ).replace(
        '        install_applied_config_helper "${USER_NAME}"\n',
        '        : # helper installation tested independently\n', 1,
    ).replace(
        '        install_time_sync_helper "${USER_NAME}"\n',
        '        : # helper installation tested independently\n', 1,
    )
    source = re.sub(
        r'if ! select_ztp_network_path; then\n.*?\nfi\n\n'
        r'if ! check_network "\$\{ZTP_SERVER##\*/\}"; then\n.*?\nfi',
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
        "TEST_HOME": str(switch_home),
    }
    result = subprocess.run(
        ["bash", str(script)], text=True, capture_output=True,
        check=False, env=env, timeout=15,
    )
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


class RequiredDeviceConfigFetchTests(unittest.TestCase):
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
