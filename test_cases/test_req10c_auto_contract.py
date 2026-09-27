"""REQ10C direct contract for --auto, cache origin, and credential safety.

Values and safety predicates come from requirements §10C, not the implementation.
"""

from __future__ import annotations

from contextlib import redirect_stderr
import io
import os
from pathlib import Path
import base64
import hashlib
import json
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases.module_loader import load_script


ROOT = Path(os.environ.get("REQ10C_TEST_ROOT") or Path(__file__).resolve().parents[1])
INITIAL = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"


class Req10CAutoDirectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.initial = load_script("req10c_auto_direct_initial", INITIAL)

    def test_real_environment_card_has_title_and_remains_not_run(self) -> None:
        document = (ROOT / "test_cases/REAL_ENVIRONMENT.md").read_text(
            encoding="utf-8"
        )
        card_id = "TC-REAL-REQ10C-AUTO-001"
        marker = f"## {card_id}"
        self.assertEqual(document.count(marker), 1)
        section = document.split(marker, 1)[1].split("\n## ", 1)[0]
        self.assertTrue(
            section.startswith(" — 自动部署与同 UID crontab 静默验证\n"),
            "REQ10C real-environment card needs a nonempty fixed title",
        )
        status_lines = [
            line for line in section.splitlines() if line.startswith("- Status:")
        ]
        self.assertEqual(
            status_lines,
            ["- Status: OPEN / NOT RUN. Hermetic tests do not satisfy real cron UID, OOB Leaf, or IB device claims."],
        )
        self.assertIn("Same-user crontab writer exclusion", section)
        self.assertIn("owner explicitly selects", section)
        self.assertIn("foreign crontab", section)

    def parse(self, *extra: str):
        with mock.patch.object(sys, "argv", ["initial-setup.py", *extra]):
            with redirect_stderr(io.StringIO()):
                try:
                    return self.initial.parse_args()
                except SystemExit as exc:
                    self.fail(f"REQ10C flags must parse, got exit {exc.code}")

    def cache_fixture(self, base: Path):
        p1 = base / "management-tool"
        p2 = base / "leaf-tool"
        p1.mkdir()
        p2.mkdir()
        global_file = p1 / "01-global.yaml"
        global_file.write_text("system:\n  timezone: UTC\n", encoding="ascii")
        csv = base / "ib.csv"
        csv.write_text("fixture CSV\n", encoding="ascii")
        p2p = base / "p2p.dot"
        p2p.write_text("fixture P2P\n", encoding="ascii")
        cache = base / "targets.json"
        ib = self.initial.Device(
            "EXAMPLE-IB01", "ib", "203.0.113.2", "203.0.113.2/24",
            "203.0.113.1", "", "", "",
        )
        eth = self.initial.Device(
            "EXAMPLE-LEAF01", "eth", "192.0.2.10", "192.0.2.10/24",
            "192.0.2.1", "", "", "",
        )
        target = self.initial.Target(ib, eth, "swp7", "eth0")
        self.initial.save_target_cache(
            cache, csv, p2p, 1, [target], global_file=global_file,
            services=None, public_keys=[],
        )
        return p1, p2, global_file, csv, p2p, cache

    @staticmethod
    def resign_cache(cache: Path, payload: dict) -> None:
        raw = (json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        cache.write_bytes(raw)
        cache.with_name(cache.name + ".sha256").write_text(
            f"{hashlib.sha256(raw).hexdigest()}  {cache.name}\n",
            encoding="ascii",
        )

    def test_watch_auto_is_distinct_from_execution_location_auto(self) -> None:
        args = self.parse("--auto")
        self.assertTrue(args.auto, "--auto is watch mode, not --execution-mode auto")
        self.assertEqual("auto", args.execution_mode)

    def test_credentials_file_is_a_path_not_a_password_argv(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10c-cli-") as directory:
            credentials = Path(directory) / "auto.env"
            args = self.parse("--auto", "--credentials-file", str(credentials))
            self.assertEqual(credentials, args.credentials_file)

    def test_non_tty_watch_rejects_world_readable_credentials_before_network(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10c-unsafe-creds-") as directory:
            base = Path(directory)
            csv = base / "ib.csv"
            csv.write_text(
                "hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,"
                "eth1_ip,netmask,eth1_gw\n"
                "EXAMPLE-IB01,ib,203.0.113.2,24,203.0.113.1,,,,\n"
                "EXAMPLE-LEAF01,eth,192.0.2.10,,,,,,\n",
                encoding="utf-8",
            )
            p2p = base / "p2p.dot"
            p2p.write_text('"EXAMPLE-IB01":"eth0" -- "EXAMPLE-LEAF01":"7";\n')
            credentials = base / "auto.env"
            credentials.write_text(
                "NVOS_INITIAL_PASSWORD=fixture-initial\n"
                "ZTP_ETH_PASSWORD=fixture-ethernet\n",
                encoding="ascii",
            )
            credentials.chmod(0o644)
            argv = [
                "initial-setup.py", "--auto", "--credentials-file", str(credentials),
                "--ib-csv", str(csv), "--p2p", str(p2p),
                "--target-cache", str(base / "targets.json"),
                "--report", str(base / "report.log"),
                "--snapshot-dir", str(base / "snapshots"),
            ]
            with mock.patch.object(sys, "argv", argv), mock.patch.object(
                sys.stdin, "isatty", return_value=False
            ), mock.patch.object(
                self.initial, "collect_ethernet_interfaces",
                side_effect=AssertionError("network must not start"),
            ), mock.patch.object(
                self.initial, "run_on_ib",
                side_effect=AssertionError("network must not start"),
            ), redirect_stderr(io.StringIO()):
                try:
                    with self.assertRaises(self.initial.SetupError) as caught:
                        self.initial.main()
                except SystemExit as exc:
                    self.fail(f"unsafe credential guard is unreachable: exit {exc.code}")
                finally:
                    if self.initial.REPORT_HANDLE is not None:
                        self.initial.REPORT_HANDLE.close()
                        self.initial.REPORT_HANDLE = None
            message = str(caught.exception).casefold()
            self.assertTrue("auto.env" in message or "credential" in message)
            self.assertTrue(
                any(token in message for token in ("permission", "mode", "owner", "unsafe")),
                message,
            )

    def test_auto_env_fd_rejects_symlink_hardlink_and_broad_mode(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10c-fd-") as directory:
            base = Path(directory)
            secret = base / "auto.env"
            secret.write_text(
                "NVOS_INITIAL_PASSWORD=initial\nZTP_ETH_PASSWORD=ethernet\n",
                encoding="utf-8",
            )
            secret.chmod(0o600)
            self.assertEqual("initial", self.initial.read_auto_credentials(secret)["NVOS_INITIAL_PASSWORD"])
            secret.chmod(0o644)
            with self.assertRaises(self.initial.SetupError):
                self.initial.read_auto_credentials(secret)
            secret.chmod(0o600)
            hardlink = base / "hardlink"
            os.link(secret, hardlink)
            with self.assertRaises(self.initial.SetupError):
                self.initial.read_auto_credentials(secret)
            hardlink.unlink()
            symlink = base / "symlink"
            symlink.symlink_to(secret)
            with self.assertRaises(self.initial.SetupError):
                self.initial.read_auto_credentials(symlink)

    def test_project_crontab_lock_is_owned_single_link_and_nofollow(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10c-cron-lock-") as directory:
            base = Path(directory)
            tool = base / "xdr-initial-setup"
            state = tool / "xdr-initial-setup-logs"
            state.mkdir(parents=True, mode=0o700)
            lock = state / "auto-crontab.lock"
            with self.initial._auto_crontab_lock(tool):
                self.assertTrue(lock.is_file())
                self.assertEqual(os.geteuid(), lock.stat().st_uid)
                self.assertEqual(1, lock.stat().st_nlink)
                self.assertEqual(0o600, lock.stat().st_mode & 0o777)
            state.chmod(0o777)
            with self.assertRaises(self.initial.SetupError):
                with self.initial._auto_crontab_lock(tool):
                    self.fail("group/world-writable lock directory was admitted")
            state.chmod(0o700)
            lock.chmod(0o644)
            with self.assertRaises(self.initial.SetupError):
                with self.initial._auto_crontab_lock(tool):
                    self.fail("broad lock file was admitted")
            lock.chmod(0o600)
            alias = state / "alias"
            os.link(lock, alias)
            with self.assertRaises(self.initial.SetupError):
                with self.initial._auto_crontab_lock(tool):
                    self.fail("hardlinked lock file was admitted")
            alias.unlink()
            lock.unlink()
            foreign = base / "foreign"
            foreign.write_text("MUST PRESERVE\n", encoding="ascii")
            lock.symlink_to(foreign)
            with self.assertRaises(self.initial.SetupError):
                with self.initial._auto_crontab_lock(tool):
                    self.fail("symlink lock file was admitted")
            self.assertEqual("MUST PRESERVE\n", foreign.read_text(encoding="ascii"))
            lock.unlink()
            with self.initial._auto_crontab_lock(tool):
                pass
            real_flock = self.initial.fcntl.flock

            def replace_after_acquire(fd: int, operation: int) -> None:
                real_flock(fd, operation)
                if operation == self.initial.fcntl.LOCK_EX:
                    lock.unlink()
                    lock.write_bytes(b"")
                    lock.chmod(0o600)

            with mock.patch.object(self.initial.fcntl, "flock", side_effect=replace_after_acquire):
                with self.assertRaises(self.initial.SetupError):
                    with self.initial._auto_crontab_lock(tool):
                        self.fail("rebound lock pathname was admitted")

    def test_cli_preserves_credential_symlink_for_nofollow_validation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10c-cli-symlink-") as directory:
            base = Path(directory)
            real = base / "real.env"
            real.write_text(
                "NVOS_INITIAL_PASSWORD=initial\nZTP_ETH_PASSWORD=ethernet\n",
                encoding="ascii",
            )
            real.chmod(0o600)
            link = base / "auto.env"
            link.symlink_to(real)
            with mock.patch.object(
                sys, "argv", ["initial-setup.py", "--auto", "--credentials-file", str(link)]
            ), mock.patch.object(sys.stdin, "isatty", return_value=False), \
                 redirect_stderr(io.StringIO()):
                with self.assertRaises(self.initial.SetupError) as caught:
                    self.initial.main()
            self.assertIn("auto.env", str(caught.exception).casefold())
            self.assertIn("symbolic links", str(caught.exception).casefold())

    def test_fd_reader_fails_closed_without_required_flags_or_current_owner(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10c-fd-flags-") as directory:
            secret = Path(directory) / "auto.env"
            secret.write_text(
                "NVOS_INITIAL_PASSWORD=initial\nZTP_ETH_PASSWORD=ethernet\n",
                encoding="ascii",
            )
            secret.chmod(0o600)
            with mock.patch.object(self.initial.os, "geteuid",
                                   return_value=os.geteuid() + 1):
                with self.assertRaises(self.initial.SetupError):
                    self.initial.read_auto_credentials(secret)
            with mock.patch.object(self.initial.os, "O_NOFOLLOW", 0):
                with self.assertRaises(self.initial.SetupError):
                    self.initial.read_auto_credentials(secret)
            with mock.patch.object(self.initial.os, "O_CLOEXEC", 0):
                with self.assertRaises(self.initial.SetupError):
                    self.initial.read_auto_credentials(secret)

    def test_auto_env_strict_grammar_rejects_unknown_duplicate_case_and_oversize(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10c-grammar-") as directory:
            secret = Path(directory) / "auto.env"
            valid = "NVOS_INITIAL_PASSWORD=initial\nZTP_ETH_PASSWORD=ethernet\n"
            invalid = (
                valid + "ARBITRARY_SHELL=sh -c rm\n",
                valid + "NVOS_INITIAL_PASSWORD=duplicate\n",
                valid + "nvos_initial_password=lowercase-collision\n",
                valid + "source other-file\n",
                valid + "X=" + "x" * 65536 + "\n",
            )
            for value in invalid:
                with self.subTest(shape=value[:35]):
                    secret.write_text(value, encoding="utf-8")
                    secret.chmod(0o600)
                    with self.assertRaises(self.initial.SetupError):
                        self.initial.read_auto_credentials(secret)

    def test_host_specific_ethernet_password_precedes_global_fallback(self) -> None:
        targets = [
            SimpleNamespace(ethernet=SimpleNamespace(hostname="EXAMPLE-LEAF01")),
            SimpleNamespace(ethernet=SimpleNamespace(hostname="EXAMPLE-LEAF02")),
        ]
        values = {
            "NVOS_INITIAL_PASSWORD": "initial",
            "ZTP_ETH_PASSWORD": "fallback",
            "ZTP_ETH_PASSWORD_EXAMPLE_LEAF01": "specific",
        }
        self.assertEqual(
            {"example-leaf01": "specific", "example-leaf02": "fallback"},
            self.initial._auto_passwords_for_targets(values, targets),
        )

    def test_oob_leaf_key_install_is_exact_and_eth_jump_never_receives_write(self) -> None:
        def field(value: bytes) -> bytes:
            return struct.pack(">I", len(value)) + value

        blob = field(b"ssh-ed25519") + field(b"k" * 32)
        line = "ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + " fixture"
        digest = base64.b64encode(hashlib.sha256(blob).digest()).rstrip(b"=").decode("ascii")
        entry = {
            "name": "mgmt-server.pub", "line": line,
            "fingerprint": "SHA256:" + digest,
        }

        def ethernet(kind: str):
            return self.initial.Device(
                "EXAMPLE-LEAF01", kind, "192.0.2.10", "192.0.2.10/24",
                "192.0.2.1", "", "", "",
            )

        with mock.patch.object(self.initial, "interactive_run") as remote:
            remote.return_value = self.initial.SessionResult("", 0)
            self.initial.install_oob_management_key(
                ethernet("eth"), "cumulus", "fixture-ethernet", entry, 10,
            )
            remote.assert_called_once()
            args = remote.call_args.args
            self.assertEqual("ssh", args[0][0])
            self.assertIn("authorized_keys", " ".join(args[0]))
            self.assertNotIn("fixture-ethernet", " ".join(args[0]))

        with mock.patch.object(
            self.initial, "interactive_run",
            side_effect=AssertionError("eth_jump must not receive any write"),
        ):
            with self.assertRaises(self.initial.SetupError):
                self.initial.install_oob_management_key(
                    ethernet("eth_jump"), "cumulus", "fixture-ethernet", entry, 10,
                )

    def test_auto_day0_classification_never_treats_partial_config_as_complete(self) -> None:
        device = self.initial.Device(
            "EXAMPLE-IB01", "ib", "203.0.113.2", "203.0.113.2/24",
            "203.0.113.1", "", "", "",
        )
        state = self.initial.DeviceState
        empty = state((), (), (), (), "nvos", "")
        complete = state(("203.0.113.2/24",), (), ("203.0.113.1",), (),
                         "EXAMPLE-IB01", "")
        partial = state(("203.0.113.2/24",), (), (), (), "EXAMPLE-IB01", "")
        conflict = state(("203.0.113.99/24",), (), ("203.0.113.1",), (),
                         "EXAMPLE-IB01", "")
        self.assertEqual("unconfigured", self.initial.classify_auto_day0(device, empty))
        self.assertEqual("complete", self.initial.classify_auto_day0(device, complete))
        self.assertEqual("terminal", self.initial.classify_auto_day0(device, partial))
        self.assertEqual("terminal", self.initial.classify_auto_day0(device, conflict))

    def test_auto_rejects_unlinked_csv_ib_instead_of_installing_endless_watch(self) -> None:
        ib = self.initial.Device(
            "EXAMPLE-IB01", "ib", "203.0.113.2", "203.0.113.2/24",
            "203.0.113.1", "", "", "",
        )
        eth = self.initial.Device(
            "EXAMPLE-LEAF01", "eth", "192.0.2.10", "192.0.2.10/24",
            "192.0.2.1", "", "", "",
        )
        target = self.initial.Target(ib, eth, "swp7", "eth0")
        with self.assertRaises(self.initial.SetupError) as caught:
            self.initial.require_auto_full_target_coverage(2, [target])
        self.assertIn("csv", str(caught.exception).casefold())
        self.assertIn("p2p", str(caught.exception).casefold())
        self.initial.require_auto_full_target_coverage(1, [target])

    def test_p1_missing_current_global_invalidates_cache(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10c-cache-p1-") as directory:
            p1, _, global_file, csv, p2p, cache = self.cache_fixture(Path(directory))
            global_file.unlink()
            self.assertIsNone(self.initial.load_target_cache(
                cache, csv, p2p, public_key_tool=p1,
                allow_baked_missing_global=False,
            ))

    def test_p2_baked_global_remains_valid_without_local_yaml(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10c-cache-p2-") as directory:
            _, p2, _, csv, p2p, cache = self.cache_fixture(Path(directory))
            with mock.patch.object(
                self.initial, "_global_yaml_subset",
                side_effect=AssertionError("Leaf must not parse global YAML"),
            ):
                cached = self.initial.load_target_cache(
                    cache, csv, p2p, public_key_tool=p2,
                    allow_baked_missing_global=True,
                )
            self.assertIsNotNone(cached, "P2 uses authenticated baked global")
            self.assertEqual(1, cached[0])

    def test_p2_changed_input_still_invalidates_baked_cache(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10c-cache-stale-") as directory:
            _, p2, _, csv, p2p, cache = self.cache_fixture(Path(directory))
            newer = cache.stat().st_mtime + 30
            os.utime(csv, (newer, newer))
            self.assertIsNone(self.initial.load_target_cache(
                cache, csv, p2p, public_key_tool=p2,
                allow_baked_missing_global=True,
            ))

    def test_cache3_attestation_binds_source_generator_and_runtime(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10c-cache3-fields-") as directory:
            _, p2, global_file, csv, p2p, cache = self.cache_fixture(Path(directory))
            payload = json.loads(cache.read_text(encoding="utf-8"))
            authority = payload["cache_authority"]
            self.assertEqual(
                hashlib.sha256(csv.read_bytes()).hexdigest(), authority["ib_csv_sha256"]
            )
            self.assertEqual(
                hashlib.sha256(p2p.read_bytes()).hexdigest(), authority["p2p_sha256"]
            )
            self.assertEqual(
                hashlib.sha256(global_file.read_bytes()).hexdigest(),
                authority["global_sha256"],
            )
            self.assertEqual("initial-setup.py", authority["generator"])
            self.assertEqual(
                hashlib.sha256(INITIAL.read_bytes()).hexdigest(),
                authority["generator_sha256"],
            )
            self.assertEqual(
                f"{sys.implementation.name}:{sys.version_info.major}.{sys.version_info.minor}",
                authority["python"],
            )
            self.assertFalse(authority["pyyaml_required"])
            self.assertEqual("not-required", authority["pyyaml_version"])
            self.assertIsNotNone(self.initial.load_target_cache(
                cache, csv, p2p, public_key_tool=p2,
                allow_baked_missing_global=True,
            ))

    def test_cache3_content_changes_invalidate_even_when_mtime_is_older(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10c-cache3-content-") as directory:
            _, p2, _, csv, p2p, cache = self.cache_fixture(Path(directory))
            older = cache.stat().st_mtime - 30
            csv.write_text("changed CSV but old mtime\n", encoding="ascii")
            os.utime(csv, (older, older))
            self.assertIsNone(self.initial.load_target_cache(
                cache, csv, p2p, public_key_tool=p2,
                allow_baked_missing_global=True,
            ))
        with tempfile.TemporaryDirectory(prefix="req10c-cache3-global-content-") as directory:
            p1, _, global_file, csv, p2p, cache = self.cache_fixture(Path(directory))
            older = cache.stat().st_mtime - 30
            global_file.write_text("system:\n  timezone: Europe/Paris\n", encoding="ascii")
            os.utime(global_file, (older, older))
            self.assertIsNone(self.initial.load_target_cache(
                cache, csv, p2p, public_key_tool=p1,
                allow_baked_missing_global=False,
            ))

    def test_cache3_resigned_identity_mismatch_fails_closed(self) -> None:
        for field, value in (
            ("generator_sha256", "0" * 64),
            ("python", "cpython:0.0"),
            ("pyyaml_required", True),
            ("pyyaml_version", "6.0"),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory(
                prefix="req10c-cache3-mutated-"
            ) as directory:
                _, p2, _, csv, p2p, cache = self.cache_fixture(Path(directory))
                payload = json.loads(cache.read_text(encoding="utf-8"))
                payload["cache_authority"][field] = value
                self.resign_cache(cache, payload)
                self.assertIsNone(self.initial.load_target_cache(
                    cache, csv, p2p, public_key_tool=p2,
                    allow_baked_missing_global=True,
                ))


if __name__ == "__main__":
    unittest.main()
