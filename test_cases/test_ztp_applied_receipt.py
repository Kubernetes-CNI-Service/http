"""Bootstrap persistent logs, applied receipts, helpers, and key contracts."""

import hashlib
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_PATH = ROOT / "ztp/templates/ztp-bootstrap.sh"
TEMPLATE = TEMPLATE_PATH.read_text(encoding="utf-8")
MAIN_MARKER = "if ! initialize_runtime_workspace; then"
MAC = "02:00:00:00:00:01"


def run_bash(path, *args, env=None):
    return subprocess.run(
        ["bash", str(path), *map(str, args)], text=True,
        capture_output=True, check=False, env=env,
    )


def library_harness(directory: Path, body: str) -> Path:
    """Build a non-root harness from the template's function-only prefix."""
    runtime_root = directory / "run"
    runtime_root.mkdir(exist_ok=True)
    state_dir = directory / "state"
    source = TEMPLATE.split(MAIN_MARKER, 1)[0]
    source = source.replace(
        'RUNTIME_WORK_ROOT="/run"',
        f"RUNTIME_WORK_ROOT={shlex.quote(str(runtime_root))}", 1,
    ).replace(
        'APPLIED_STATE_DIR="/var/lib/nvidia-ztp"',
        f"APPLIED_STATE_DIR={shlex.quote(str(state_dir))}", 1,
    )
    harness = directory / "harness.sh"
    harness.write_text(
        source + "\n" + textwrap.dedent(f"""
            TEST_LOG={shlex.quote(str(directory / 'test.log'))}
            log() {{ printf '%s\\n' "$*" >> "$TEST_LOG"; }}
            chown() {{ [[ "${{TEST_CHOWN_FAIL:-0}}" == "0" ]]; }}
            {body}
        """),
        encoding="utf-8",
    )
    return harness


def helper_source() -> str:
    match = re.search(
        r"<<'EOF'\n(#!/bin/sh\n.*?\n)EOF\n    then",
        TEMPLATE, re.S,
    )
    if not match:
        raise AssertionError("applied-config helper heredoc not found")
    return match.group(1)


class AppliedReceiptPersistenceTests(unittest.TestCase):
    def test_canonical_template_is_bash_syntax_valid_and_uses_persistent_logs(self):
        result = subprocess.run(
            ["bash", "-n", str(TEMPLATE_PATH)], text=True,
            capture_output=True, check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn(
            'PERSISTENT_LOG_DIR="${APPLIED_STATE_DIR}/logs"', TEMPLATE,
        )
        self.assertIn("initialize_persistent_log", TEMPLATE)
        self.assertNotIn(
            'LOG_FILE_PATH="${TMP_DIR}/${LOG_FILE_NAME}"', TEMPLATE,
        )
        self.assertNotRegex(
            TEMPLATE,
            r'cp "\$\{LOG_FILE_PATH\}" "\$\{USER_HOME\}/\$\{LOG_FILE_NAME\}',
        )
        self.assertIn('APPLIED_STATE_DIR="/var/lib/nvidia-ztp"', TEMPLATE)
        self.assertIn('RUNTIME_WORK_ROOT="/run"', TEMPLATE)
        self.assertNotIn('TMP_DIR="/tmp/ztp"', TEMPLATE)
        self.assertIn('PERSISTENT_LOG_POINTER="${PERSISTENT_LOG_DIR}/latest-log"', TEMPLATE)
        self.assertIn('chmod 0600 "${yaml_tmp}"', TEMPLATE)
        self.assertIn('chmod 0600 "${receipt_tmp}"', TEMPLATE)
        self.assertLess(
            TEMPLATE.index('mv -f -- "${yaml_tmp}" "${APPLIED_YAML_PATH}"'),
            TEMPLATE.index('mv -f -- "${receipt_tmp}" "${APPLIED_RECEIPT_PATH}"'),
        )

    def test_success_receipt_preserves_exact_bytes_hash_and_modes(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            raw = b"- set:\n    system:\n      hostname: leaf01\n"
            source = root / "020000000001.yaml"
            source.write_bytes(raw)
            harness = library_harness(root, """
                persist_applied_receipt \
                    "$1" success dedicated replace 020000000001.yaml \
                    02:00:00:00:00:01
            """)
            result = run_bash(harness, source)
            self.assertEqual(0, result.returncode, result.stderr)

            state = root / "state"
            applied = state / "last-success.yaml"
            receipt = state / "receipt.env"
            self.assertEqual(raw, applied.read_bytes())
            self.assertEqual(0o711, stat.S_IMODE(state.stat().st_mode))
            self.assertEqual(0o600, stat.S_IMODE(applied.stat().st_mode))
            self.assertEqual(0o600, stat.S_IMODE(receipt.stat().st_mode))
            fields = dict(
                line.split("=", 1)
                for line in receipt.read_text(encoding="utf-8").splitlines()
            )
            self.assertEqual("1", fields["schema"])
            self.assertEqual("success", fields["status"])
            self.assertEqual("dedicated", fields["source_kind"])
            self.assertEqual("replace", fields["apply_mode"])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), fields["raw_sha256"])
            self.assertEqual("020000000001.yaml", fields["source_name"])
            self.assertEqual(MAC, fields["eth0_mac"])
            self.assertRegex(fields["applied_at"], r"^\d{4}-.*(?:Z|[+-]\d\d:\d\d)$")
            self.assertNotIn("failed_raw_sha256", fields)
            self.assertGreaterEqual(receipt.stat().st_mtime_ns, applied.stat().st_mtime_ns)

    def test_persistent_log_is_unique_regular_and_written_from_first_line(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            harness = library_harness(root, """
                initialize_persistent_log
                printf '%s\n' \
                    "======================== ZTP START ========================" \
                    "[ZTP] first durable event" | tee -a "$LOG_FILE_PATH"
                printf '%s\n' "$LOG_FILE_PATH"
            """)
            result = run_bash(harness)
            self.assertEqual(0, result.returncode, result.stderr)

            state = root / "state"
            logs = state / "logs"
            files = list(logs.glob("ztp-result.log_*"))
            self.assertEqual(1, len(files))
            log_file = files[0]
            self.assertFalse(log_file.is_symlink())
            self.assertTrue(log_file.is_file())
            self.assertEqual(0o711, stat.S_IMODE(state.stat().st_mode))
            self.assertEqual(0o755, stat.S_IMODE(logs.stat().st_mode))
            self.assertEqual(0o644, stat.S_IMODE(log_file.stat().st_mode))
            text = log_file.read_text(encoding="utf-8")
            self.assertIn("ZTP START", text)
            self.assertIn("first durable event", text)
            self.assertNotIn(str(root / "tmp"), str(log_file))
            pointer = logs / "latest-log"
            self.assertTrue(pointer.is_file())
            self.assertFalse(pointer.is_symlink())
            self.assertEqual(0o644, stat.S_IMODE(pointer.stat().st_mode))
            self.assertEqual(log_file.name, pointer.read_text(encoding="utf-8").strip())

    def test_runtime_workspace_ignores_precreated_names_and_is_private(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            runtime_root = root / "run"
            runtime_root.mkdir()
            attacker = runtime_root / "nvidia-ztp.ATTACK"
            attacker.mkdir()
            sentinel = attacker / "do-not-touch"
            sentinel.write_text("attacker", encoding="utf-8")
            harness = library_harness(root, """
                initialize_runtime_workspace
                printf '%s\n' "$TMP_DIR"
                ls -ld "$TMP_DIR"
                cleanup_runtime_workspace
            """)
            result = run_bash(harness)
            self.assertEqual(0, result.returncode, result.stderr)
            workspace, mode_line = result.stdout.splitlines()
            self.assertTrue(mode_line.startswith("drwx------"), mode_line)
            self.assertEqual(runtime_root, Path(workspace).parent)
            self.assertNotEqual(attacker, Path(workspace))
            self.assertFalse(Path(workspace).exists())
            self.assertEqual("attacker", sentinel.read_text(encoding="utf-8"))

    def test_runtime_workspace_refuses_symlinked_runtime_root(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            outside = root / "outside"
            outside.mkdir()
            runtime_root = root / "run"
            runtime_root.symlink_to(outside, target_is_directory=True)
            state_dir = root / "state"
            source = TEMPLATE.split(MAIN_MARKER, 1)[0].replace(
                'RUNTIME_WORK_ROOT="/run"',
                f"RUNTIME_WORK_ROOT={shlex.quote(str(runtime_root))}", 1,
            ).replace(
                'APPLIED_STATE_DIR="/var/lib/nvidia-ztp"',
                f"APPLIED_STATE_DIR={shlex.quote(str(state_dir))}", 1,
            )
            harness = root / "harness.sh"
            harness.write_text(source + "\ninitialize_runtime_workspace\n", encoding="utf-8")
            result = run_bash(harness)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("Refusing unsafe ZTP runtime root", result.stderr)
            self.assertEqual([], list(outside.iterdir()))

    def test_persistent_log_refuses_symlinked_latest_pointer(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            state = root / "state"
            logs = state / "logs"
            logs.mkdir(parents=True)
            outside = root / "outside"
            outside.write_text("do-not-touch", encoding="utf-8")
            (logs / "latest-log").symlink_to(outside)
            harness = library_harness(root, """
                initialize_persistent_log
            """)
            result = run_bash(harness)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("Refusing unsafe persistent ZTP latest-log pointer", result.stderr)
            self.assertEqual("do-not-touch", outside.read_text(encoding="utf-8"))

    def test_persistent_log_refuses_symlinked_log_directory(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            state = root / "state"
            state.mkdir()
            outside = root / "outside"
            outside.mkdir()
            (state / "logs").symlink_to(outside, target_is_directory=True)
            harness = library_harness(root, """
                initialize_persistent_log
            """)
            result = run_bash(harness)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("Refusing unsafe persistent ZTP log directory", result.stderr)
            self.assertEqual([], list(outside.iterdir()))

    def test_failed_dedicated_fallback_keeps_root_state_and_failed_hash(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            default_raw = b"- set:\n    system:\n      timezone: Etc/UTC\n"
            failed_raw = b"- set:\n    interface:\n      swp2:\n        ipv4:\n"
            default = root / "default.yaml"
            failed = root / "020000000001.yaml"
            default.write_bytes(default_raw)
            failed.write_bytes(failed_raw)
            harness = library_harness(root, """
                persist_applied_receipt \
                    "$1" success fallback_default patch default.yaml \
                    02:00:00:00:00:01 "$2"
            """)
            result = run_bash(harness, default, failed)
            self.assertEqual(0, result.returncode, result.stderr)
            state = root / "state"
            self.assertEqual(
                failed_raw, (state / "last-failed-dedicated.yaml").read_bytes(),
            )
            self.assertEqual(
                0o600,
                stat.S_IMODE((state / "last-failed-dedicated.yaml").stat().st_mode),
            )
            receipt = dict(
                line.split("=", 1)
                for line in (state / "receipt.env").read_text().splitlines()
            )
            self.assertEqual("success", receipt["status"])
            self.assertEqual("fallback_default", receipt["source_kind"])
            self.assertEqual(
                hashlib.sha256(failed_raw).hexdigest(),
                receipt["failed_raw_sha256"],
            )

    def test_unsafe_or_unwritable_receipt_warns_without_failing_ztp(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            source = root / "source.yaml"
            target = root / "target.yaml"
            target.write_text("- set: {}\n", encoding="utf-8")
            source.symlink_to(target)
            harness = library_harness(root, """
                persist_applied_receipt \
                    "$1" success dedicated replace source.yaml \
                    02:00:00:00:00:01
                printf 'survived\\n'
            """)
            result = run_bash(harness, source)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("survived\n", result.stdout)
            self.assertFalse((root / "state/receipt.env").exists())
            self.assertIn("WARN", (root / "test.log").read_text())

            source.unlink()
            source.write_text("- set: {}\n", encoding="utf-8")
            env = {**os.environ, "TEST_CHOWN_FAIL": "1"}
            result = run_bash(harness, source, env=env)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("survived\n", result.stdout)


class AppliedConfigHelperTests(unittest.TestCase):
    def write_helper(self, root: Path) -> Path:
        state = root / "state"
        source = helper_source().replace(
            "STATE_DIR=/var/lib/nvidia-ztp",
            f"STATE_DIR={shlex.quote(str(state))}",
            1,
        )
        # The production helper deliberately uses GNU stat and root uid.  Adapt
        # only those platform assertions for the macOS unit-test host.
        source = source.replace("stat -c '%u'", "stat -f '%u'")
        source = source.replace("stat -c '%a'", "stat -f '%Lp'")
        source = source.replace('= "0" ]', f'= "{os.getuid()}" ]')
        helper = root / "helper.sh"
        helper.write_text(source, encoding="utf-8")
        helper.chmod(0o755)
        return helper

    def prepare_state(self, root: Path, raw: bytes, *, fallback=False):
        state = root / "state"
        state.mkdir(mode=0o711)
        state.chmod(0o711)
        applied = state / "last-success.yaml"
        applied.write_bytes(raw)
        applied.chmod(0o600)
        lines = [
            "schema=1",
            "status=success",
            f"source_kind={'fallback_default' if fallback else 'dedicated'}",
            f"apply_mode={'patch' if fallback else 'replace'}",
            f"raw_sha256={hashlib.sha256(raw).hexdigest()}",
            f"source_name={'default.yaml' if fallback else '020000000001.yaml'}",
            f"eth0_mac={MAC}",
            "applied_at=2026-08-31T12:34:56+00:00",
        ]
        if fallback:
            failed_raw = b"- set:\n    broken: true\n"
            failed = state / "last-failed-dedicated.yaml"
            failed.write_bytes(failed_raw)
            failed.chmod(0o600)
            lines.append(
                f"failed_raw_sha256={hashlib.sha256(failed_raw).hexdigest()}"
            )
        receipt = state / "receipt.env"
        receipt.write_text("\n".join(lines) + "\n", encoding="utf-8")
        receipt.chmod(0o600)
        return receipt, applied

    def test_helper_emits_exact_validated_protocol_and_rejects_arguments(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            raw = b"- set:\n    system:\n      hostname: leaf01\n"
            receipt, _applied = self.prepare_state(root, raw)
            helper = self.write_helper(root)
            result = run_bash(helper)
            self.assertEqual(0, result.returncode, result.stderr)
            expected = (
                b"ZTP_APPLIED_CONFIG_V1\n" + receipt.read_bytes()
                + b"---\n" + raw
            )
            self.assertEqual(expected, result.stdout.encode("utf-8"))
            denied = run_bash(helper, "unexpected")
            self.assertNotEqual(0, denied.returncode)
            self.assertIn("accepts no arguments", denied.stderr)

    def test_helper_fails_closed_on_hash_mismatch_symlink_or_unsafe_receipt(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            raw = b"- set:\n    system:\n      hostname: leaf01\n"
            receipt, applied = self.prepare_state(root, raw)
            helper = self.write_helper(root)

            applied.write_bytes(raw + b"# tampered\n")
            applied.chmod(0o600)
            result = run_bash(helper)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("hash mismatch", result.stderr)
            self.assertEqual("", result.stdout)

            applied.unlink()
            target = root / "target.yaml"
            target.write_bytes(raw)
            applied.symlink_to(target)
            result = run_bash(helper)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("unsafe or missing", result.stderr)

            applied.unlink()
            applied.write_bytes(raw)
            applied.chmod(0o600)
            with receipt.open("a", encoding="utf-8") as stream:
                stream.write("unknown_key=value\n")
            result = run_bash(helper)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("unknown receipt key", result.stderr)


class PrefetchBeforeApplyTests(unittest.TestCase):
    def test_install_phase_is_network_free_and_default_consumers_use_cache(self):
        install_start = TEMPLATE.index("install_ssh_pubkeys() {")
        install_end = TEMPLATE.index("# 检查网络可达性", install_start)
        install = TEMPLATE[install_start:install_end]
        self.assertIsNone(
            re.search(r"^\s*(?:ztp_curl|curl)\b", install, re.M), install,
        )
        self.assertIn('pub_cache="${TMP_DIR}/pubkey.${index}.cache"', install)

        cumulus_start = TEMPLATE.index("load_default_cfg(){")
        cumulus_end = TEMPLATE.index("CUMULUS_DEFAULT_PREFETCHED=0", cumulus_start)
        cumulus_consumer = TEMPLATE[cumulus_start:cumulus_end]
        self.assertNotIn("ztp_curl", cumulus_consumer)
        self.assertIn("RELEASE_VER_DEF_CACHE", cumulus_consumer)

        nvos_start = TEMPLATE.index("load_nvos_default_cfg() {")
        nvos_end = TEMPLATE.index("## 尝试加载", nvos_start)
        nvos_consumer = TEMPLATE[nvos_start:nvos_end]
        self.assertNotIn("ztp_curl", nvos_consumer)
        self.assertIn("GLOBAL_DEF_CACHE", nvos_consumer)

    def test_apply_failure_uses_prefetched_keys_and_defaults_without_post_apply_http(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            tmp = root / "tmp"
            state = root / "state"
            home = root / "home/cumulus"
            fake_bin = root / "bin"
            events = root / "events.log"
            applied_marker = root / "apply-started"
            fake_bin.mkdir()
            home.mkdir(parents=True)

            def executable(name, content):
                path = fake_bin / name
                path.write_text(textwrap.dedent(content), encoding="utf-8")
                path.chmod(0o755)

            executable("ip", """
                #!/bin/sh
                if [ "$1" = vrf ] && [ "$2" = exec ]; then
                    shift 3
                    exec "$@"
                fi
                exit 1
            """)
            executable("chown", """
                #!/bin/sh
                exit 0
            """)
            executable("curl", """
                #!/bin/sh
                url=
                output=
                while [ "$#" -gt 0 ]; do
                    case "$1" in
                        -o) output=$2; shift 2 ;;
                        -*) shift ;;
                        *) url=$1; shift ;;
                    esac
                done
                if [ -e "$APPLY_MARKER" ]; then
                    printf 'post:%s\n' "$url" >> "$EVENTS"
                    exit 99
                fi
                printf 'pre:%s\n' "$url" >> "$EVENTS"
                case "$url" in
                    *.spx) exit 22 ;;
                    *.mode) printf 'replace\n' > "$output" ;;
                    *.pub) printf 'ssh-ed25519 AAAATEST ztp-test\n' > "$output" ;;
                    *) printf '%s\n' '- set:' '    system:' '      hostname: leaf01' > "$output" ;;
                esac
            """)
            executable("nv", """
                #!/bin/sh
                printf 'nv:%s\n' "$*" >> "$EVENTS"
                if [ "$1" = config ] && [ "$2" = apply ] && [ ! -e "$APPLY_MARKER" ]; then
                    : > "$APPLY_MARKER"
                    exit 1
                fi
                exit 0
            """)

            runtime_root = root / "run"
            runtime_root.mkdir()
            source = TEMPLATE.replace(
                'RUNTIME_WORK_ROOT="/run"',
                f"RUNTIME_WORK_ROOT={shlex.quote(str(runtime_root))}", 1,
            ).replace(
                'APPLIED_STATE_DIR="/var/lib/nvidia-ztp"',
                f"APPLIED_STATE_DIR={shlex.quote(str(state))}", 1,
            ).replace(
                "PROD_NAME=$(decode-syseeprom 2>/dev/null | grep '^Product Name' | awk '{print $NF}' || echo \"unknown\")",
                'PROD_NAME="SN5600"',
                1,
            ).replace(
                'IMG_VER=$(grep \'^IMAGE_RELEASE=\' /etc/image-release | awk -F\'=\' \'{print $2}\')',
                'IMG_VER="5.16.4"',
                1,
            ).replace(
                'RUN_VER=$(grep \'^DISTRIB_RELEASE=\' /etc/lsb-release | awk -F\'=\' \'{print $2}\')',
                'RUN_VER="5.16.4"',
                1,
            ).replace(
                'ETH0_RAW_MAC=$(cat /sys/class/net/eth0/address)',
                f'ETH0_RAW_MAC="{MAC}"',
            ).replace(
                'USER_HOME=/home/${USER_NAME}', 'USER_HOME="${TEST_HOME}"',
            ).replace(
                '        install_manual_ztp_helper\n',
                '        : # helper installation is covered by static contract tests\n',
                1,
            ).replace(
                '        install_applied_config_helper "${USER_NAME}"\n',
                '        : # helper installation is covered by static contract tests\n',
                1,
            )
            source = re.sub(
                r'if ! select_ztp_network_path; then\n.*?\nfi\n\n'
                r'if ! check_network "\$\{ZTP_SERVER##\*/\}"; then\n.*?\nfi',
                'ZTP_VRF="default"\nZTP_INTERFACE="eth0"',
                source, count=1, flags=re.S,
            )
            # This test exercises prefetch/fallback ordering, not the independent
            # management-server clock gate.  Keep it hermetic: setting the host
            # clock is neither permitted nor meaningful in the test process.
            source = re.sub(
                r'if ! sync_management_clock_for_ztp; then\n.*?\nfi\n'
                r'log "\[ZTP\] Network check passed after management-server time sync:.*?"',
                'log "[ZTP] Network/time prerequisites mocked for prefetch test"',
                source, count=1, flags=re.S,
            )
            script = root / "bootstrap.sh"
            script.write_text(source, encoding="utf-8")
            script.chmod(0o755)
            env = {
                **os.environ,
                "PATH": f"{fake_bin}:{os.environ.get('PATH', '')}",
                "EVENTS": str(events),
                "APPLY_MARKER": str(applied_marker),
                "TEST_HOME": str(home),
            }
            result = run_bash(script, env=env)
            self.assertEqual(0, result.returncode, result.stderr + result.stdout)
            event_lines = events.read_text(encoding="utf-8").splitlines()
            self.assertTrue(any("laptop.pub" in line for line in event_lines))
            self.assertTrue(any("/default_" in line for line in event_lines))
            self.assertTrue(applied_marker.exists())
            self.assertFalse(any(line.startswith("post:") for line in event_lines))
            self.assertIn(
                "ssh-ed25519 AAAATEST ztp-test",
                (home / ".ssh/authorized_keys").read_text(encoding="utf-8"),
            )
            receipt = dict(
                line.split("=", 1)
                for line in (state / "receipt.env").read_text().splitlines()
            )
            self.assertEqual("success", receipt["status"])
            self.assertEqual("fallback_default", receipt["source_kind"])
            self.assertRegex(receipt["failed_raw_sha256"], r"^[0-9a-f]{64}$")
            self.assertTrue((state / "last-failed-dedicated.yaml").is_file())
            self.assertEqual([], list(runtime_root.iterdir()))


if __name__ == "__main__":
    unittest.main()
