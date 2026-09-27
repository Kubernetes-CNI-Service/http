"""Real-script REQ-10-B P1 service/key RED workflow, without device operations."""

from __future__ import annotations

import base64
from contextlib import ExitStack
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
INITIAL = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
GENERATOR = ROOT / "ztp/config/nvos/template/90-c2-generate_configs.py"
LOADER = ROOT / "DAY0-Prepare/11-load.py"

GLOBAL = """\
schema_version: 2
common:
  switch:
    system:
      dns:
        server:
        - 192.0.2.53
        - 198.51.100.53
      ntp:
        server:
        - ntp.ubuntu.com
        - time.common.example.test
      date-time:
        timezone: Etc/UTC
switches:
- ib:
    system:
      dns:
        server:
        - 203.0.113.53
      ntp:
        server:
        - ntp.ubuntu.com
        - time.ib.example.test
      date-time:
        timezone: Asia/Taipei
- nvl:
    system:
      dns:
        server:
        - 203.0.113.54
"""
EXPECTED_IB = {
    "dns": ("203.0.113.53",),
    "ntp": ("ntp.ubuntu.com", "time.ib.example.test"),
    "timezone": "Asia/Taipei",
}


def public_key(seed: int, comment: str) -> str:
    """Build a deterministic valid OpenSSH public line, with no private key."""
    def field(value: bytes) -> bytes:
        return struct.pack(">I", len(value)) + value

    blob = field(b"ssh-ed25519") + field(bytes([seed]) * 32)
    return "ssh-ed25519 " + base64.b64encode(blob).decode() + " " + comment + "\n"


def fingerprint(public_line: str) -> str:
    blob = base64.b64decode(public_line.split()[1], validate=True)
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).rstrip(b"=").decode()


def scalar_strings(value: object):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for member in value.values():
            yield from scalar_strings(member)
    elif isinstance(value, list):
        for member in value:
            yield from scalar_strings(member)


class Req10BServicesKeysWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.initial = load_script("req10b_services_keys_workflow_initial", INITIAL)
        with mock.patch.object(sys, "argv", ["90-c2-generate_configs.py"]):
            cls.generator = load_script("req10b_services_keys_workflow_generator", GENERATOR)
        cls.loader = load_script("req10b_services_keys_workflow_loader", LOADER)

    def fixture(self, directory: str):
        root = Path(directory)
        tool = root / "infiniband/bringup/xdr-initial-setup"
        tool.mkdir(parents=True)
        global_path = tool / "01-global.yaml"
        global_path.write_text(GLOBAL, encoding="utf-8")
        neutral = root / "infra/infra-neutral.conf"
        neutral.parent.mkdir(parents=True)
        neutral.write_text("DNS=8.8.8.8\nNTP=ntp.ubuntu.com\nTIMEZONE=Etc/UTC\n", encoding="ascii")
        ib_csv = root / "ib.csv"
        ib_csv.write_text(
            "hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,"
            "eth1_ip,netmask,eth1_gw\n"
            "EXAMPLE-IB01,ib,203.0.113.2,24,203.0.113.1,,,,\n"
            "EXAMPLE-JUMP01,eth_jump,192.0.2.10,,,,,,\n",
            encoding="utf-8",
        )
        p2p = root / "p2p.dot"
        p2p.write_text('"EXAMPLE-IB01":"eth0" -- "EXAMPLE-JUMP01":"7";\n', encoding="utf-8")
        pubdir = root / "infiniband/publickey"
        pubdir.mkdir(parents=True)
        (tool / "publickey").symlink_to("../../publickey")
        laptop = public_key(17, "laptop")
        management = public_key(18, "management")
        (pubdir / "laptop.pub").write_text(laptop, encoding="ascii")
        (pubdir / "mgmt-server.pub").write_text(management, encoding="ascii")
        cache = root / "out/targets.json"
        return root, tool, global_path, ib_csv, p2p, pubdir, cache, laptop, management

    def run_initial(self, tool: Path, ib_csv: Path, p2p: Path,
                    cache: Path, *extra: str) -> int:
        argv = [
            "initial-setup.py", "--ib-csv", str(ib_csv), "--p2p", str(p2p),
            "--target-cache", str(cache), "--report", str(cache.parent / "report.log"),
            "--snapshot-dir", str(cache.parent / "snapshots"), *extra,
        ]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(
            self.initial, "__file__", str(tool / "initial-setup.py")
        ), mock.patch.object(Path, "home", return_value=tool.parents[2]), \
             redirect_stdout(io.StringIO()):
            try:
                return self.initial.main()
            finally:
                report = self.initial.REPORT_HANDLE
                if report is not None:
                    report.close()
                    self.initial.REPORT_HANDLE = None

    def drive_one_device(self, first_state: str, verified_state: str,
                         *extra: str, remove_global_before_p1: bool = False,
                         remove_global_before_p2: bool = False,
                         post_service_state: str | None = None):
        """Exercise real P1/cache/P2 control flow with only the network boundary faked."""
        with tempfile.TemporaryDirectory(prefix="req10b-device-flow-") as directory:
            _, tool, global_path, ib_csv, p2p, _, cache, laptop, management = self.fixture(directory)
            if remove_global_before_p1:
                global_path.unlink()
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            if remove_global_before_p2 and global_path.exists():
                global_path.unlink()
            commands: list[tuple[str, ...]] = []
            shows = 0

            def device_boundary(*args, **_kwargs):
                nonlocal shows
                command = tuple(args[7])
                commands.append(command)
                if command == ("nv", "config", "show", "-o", "commands"):
                    shows += 1
                    output = first_state if shows == 1 else verified_state
                    if shows > 2 and post_service_state is not None:
                        output = post_service_state
                    return self.initial.SessionResult(output, 0)
                return self.initial.SessionResult("", 0)

            neighbor = self.initial.Neighbor("fe80::1", "swp7", "02:00:00:00:00:17")
            local_jump = {"example-jump01"} if "ethernet" in extra else set()
            with ExitStack() as stack:
                stack.enter_context(mock.patch.dict("os.environ", {"NVOS_INITIAL_PASSWORD": "initial-password"}))
                for name, value in (
                    ("local_ethernet_keys", local_jump),
                    ("prompt_ethernet_passwords", {"example-jump01": "eth-password"}),
                    ("collect_ethernet_interfaces", ("EXAMPLE-JUMP01", "interface table")),
                    ("collect_ethernet_network_tables", ("links", "fdb", "neighbors")),
                    ("save_ethernet_snapshot", cache.parent / "snapshot.txt"),
                    ("interface_status_line", "swp7 up"),
                    ("interface_oper_status", "up"),
                    ("fdb_port_for_interface", "swp7"),
                    ("neighbor_for_port", neighbor),
                    ("interface_vrf", "default"),
                    ("verify_ipv4_login", None),
                ):
                    stack.enter_context(mock.patch.object(self.initial, name, return_value=value))
                stack.enter_context(mock.patch.object(self.initial, "run_on_ib", side_effect=device_boundary))
                try:
                    result = self.run_initial(
                        tool, ib_csv, p2p, cache, "--apply", "--yes",
                        "--ethernet-password", "eth-password", *extra,
                    )
                finally:
                    report = self.initial.REPORT_HANDLE
                    if report is not None:
                        report.close()
                        self.initial.REPORT_HANDLE = None
            return result, commands, (cache.parent / "report.log").read_text(encoding="utf-8"), laptop, management

    @staticmethod
    def rewrite_cache_with_matching_sidecar(cache: Path, payload: dict) -> None:
        raw = (json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        cache.write_bytes(raw)
        cache.with_name(cache.name + ".sha256").write_text(
            f"{hashlib.sha256(raw).hexdigest()}  {cache.name}\n", encoding="ascii"
        )

    def test_real_generator_and_initial_p1_agree_on_whitelisted_ib_values(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-service-p1-") as directory:
            _, tool, global_path, ib_csv, p2p, _, cache, _, _ = self.fixture(directory)
            with mock.patch.object(self.generator, "_GLOBAL_FILE", str(global_path)):
                merged = self.generator.load_global("ib")
            self.assertEqual(list(EXPECTED_IB["dns"]), merged["system"]["dns"]["server"])
            self.assertEqual(list(EXPECTED_IB["ntp"]), merged["system"]["ntp"]["server"])
            self.assertEqual(EXPECTED_IB["timezone"], merged["system"]["date-time"]["timezone"])
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            payload = json.loads(cache.read_text(encoding="utf-8"))
            self.assertEqual(4, payload["version"])
            values = set(scalar_strings(payload))
            for expected in (*EXPECTED_IB["dns"], *EXPECTED_IB["ntp"], EXPECTED_IB["timezone"]):
                self.assertIn(expected, values)
            for superseded in ("192.0.2.53", "198.51.100.53", "time.common.example.test"):
                self.assertNotIn(superseded, values, "deep merge replaces an entire key, not its members")
            self.assertNotIn("domain", json.dumps(payload))
            self.assertNotIn("search", json.dumps(payload))

    def test_p1_cache_bakes_full_valid_public_lines_and_fingerprints(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-key-p1-") as directory:
            _, tool, _, ib_csv, p2p, pubdir, cache, laptop, management = self.fixture(directory)
            self.loader.validate_pubkey(pubdir / "laptop.pub")
            self.loader.validate_pubkey(pubdir / "mgmt-server.pub")
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            values = set(scalar_strings(json.loads(cache.read_text(encoding="utf-8"))))
            for line in (laptop, management):
                self.assertIn(line.strip(), {value.strip() for value in values})
                self.assertIn(fingerprint(line), values)

    def test_newer_project_public_key_invalidates_management_cache(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-pubkey-freshness-") as directory:
            _, tool, _, ib_csv, p2p, pubdir, cache, laptop, _ = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            old_cache = cache.read_bytes()
            replacement = public_key(25, "rotated-laptop")
            path = pubdir / "laptop.pub"
            path.write_text(replacement, encoding="ascii")
            newer = cache.stat().st_mtime_ns + 2_000_000_000
            os.utime(path, ns=(newer, newer))
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache,
                                                 "--plan", "--execution-mode", "management"))
            report = (cache.parent / "report.log").read_text(encoding="utf-8")
            self.assertIn("Target cache: generated", report)
            self.assertNotEqual(old_cache, cache.read_bytes())
            values = set(scalar_strings(json.loads(cache.read_text(encoding="utf-8"))))
            self.assertIn(fingerprint(replacement), values)
            self.assertNotIn(fingerprint(laptop), values)

    def test_management_never_reuses_cache_baked_from_open_ssh_invalid_rsa(self) -> None:
        """A matching v4 checksum and old mtime do not waive P1 key validation."""
        def field(data: bytes) -> bytes:
            return struct.pack(">I", len(data)) + data

        malformed = "ssh-rsa " + base64.b64encode(
            field(b"ssh-rsa") + field(b"\x01")
        ).decode("ascii") + " malformed-rsa\n"
        for mode in ("management", "auto"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(
                prefix="req10b-rsa-cached-"
            ) as directory:
                _, tool, _, ib_csv, p2p, pubdir, cache, _, _ = self.fixture(directory)
                self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
                rogue = pubdir / "other.pub"
                rogue.write_text(malformed, encoding="ascii")
                payload = json.loads(cache.read_text(encoding="utf-8"))
                payload["public_keys"].append({
                    "name": "other.pub", "line": malformed.strip(),
                    "fingerprint": fingerprint(malformed),
                })
                self.rewrite_cache_with_matching_sidecar(cache, payload)
                older = cache.stat().st_mtime_ns - 2_000_000_000
                os.utime(rogue, ns=(older, older))
                before = (cache.stat().st_ino, cache.read_bytes())
                extra = ("--plan", "--execution-mode", "management") if mode == "management" else ("--plan",)
                with mock.patch.object(self.initial.socket, "gethostname", return_value="MGMT-SERVER"), \
                     mock.patch.object(self.initial.socket, "getfqdn", return_value="MGMT-SERVER"):
                    with self.assertRaises(self.initial.SetupError):
                        self.run_initial(tool, ib_csv, p2p, cache, *extra)
                self.assertEqual(before, (cache.stat().st_ino, cache.read_bytes()))

    def test_newer_global_invalidates_management_cache_and_rebakes_services(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-global-freshness-") as directory:
            _, tool, global_path, ib_csv, p2p, _, cache, _, _ = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            original = json.loads(cache.read_text(encoding="utf-8"))
            self.assertEqual(str(global_path.resolve()), original["global"])
            global_path.write_text(GLOBAL.replace("203.0.113.53", "203.0.113.66"),
                                   encoding="utf-8")
            newer = cache.stat().st_mtime_ns + 2_000_000_000
            os.utime(global_path, ns=(newer, newer))
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache,
                                                 "--plan", "--execution-mode", "management"))
            report = (cache.parent / "report.log").read_text(encoding="utf-8")
            self.assertIn("Target cache: generated", report)
            payload = json.loads(cache.read_text(encoding="utf-8"))
            self.assertEqual(str(global_path.resolve()), payload["global"])
            self.assertIn("203.0.113.66", set(scalar_strings(payload)))
            self.assertNotIn("203.0.113.53", set(scalar_strings(payload)))

    def test_management_rejects_rechecksummed_cache_with_wrong_global_source(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-global-binding-") as directory:
            _, tool, global_path, ib_csv, p2p, _, cache, _, _ = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            payload = json.loads(cache.read_text(encoding="utf-8"))
            payload["global"] = str(global_path.with_name("different-global.yaml"))
            self.rewrite_cache_with_matching_sidecar(cache, payload)
            before = cache.read_bytes()
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache,
                                                 "--plan", "--execution-mode", "management"))
            report = (cache.parent / "report.log").read_text(encoding="utf-8")
            self.assertIn("Target cache: generated", report)
            self.assertNotEqual(before, cache.read_bytes())
            self.assertEqual(str(global_path.resolve()),
                             json.loads(cache.read_text(encoding="utf-8"))["global"])

    def test_global_retarget_to_older_project_file_invalidates_cache(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-global-retarget-") as directory:
            root, tool, global_path, ib_csv, p2p, _, cache, _, _ = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            replacement = root / "old-project-global.yaml"
            replacement.write_text(GLOBAL.replace("203.0.113.53", "203.0.113.67"),
                                   encoding="utf-8")
            older = cache.stat().st_mtime_ns - 2_000_000_000
            os.utime(replacement, ns=(older, older))
            global_path.unlink()
            global_path.symlink_to(replacement)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache,
                                                 "--plan", "--execution-mode", "management"))
            report = (cache.parent / "report.log").read_text(encoding="utf-8")
            self.assertIn("Target cache: generated", report)
            payload = json.loads(cache.read_text(encoding="utf-8"))
            self.assertEqual(str(replacement.resolve()), payload["global"])
            self.assertIn("203.0.113.67", set(scalar_strings(payload)))

    def test_ethernet_leaf_keeps_baked_keys_when_project_key_link_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-leaf-baked-keys-") as directory:
            _, tool, _, ib_csv, p2p, _, cache, laptop, management = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            before = (cache.stat().st_ino, cache.read_bytes())
            (tool / "publickey").unlink()
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache,
                                                 "--plan", "--execution-mode", "ethernet"))
            report = (cache.parent / "report.log").read_text(encoding="utf-8")
            self.assertIn("Target cache: reused", report)
            self.assertIn(fingerprint(laptop), report)
            self.assertIn(fingerprint(management), report)
            self.assertEqual(before, (cache.stat().st_ino, cache.read_bytes()))

    def test_ethernet_p2_reuses_baked_keys_without_ssh_keygen_even_if_source_is_visible(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-leaf-no-keygen-") as directory:
            _, tool, _, ib_csv, p2p, _, cache, laptop, management = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            with mock.patch.object(self.initial.subprocess, "run", side_effect=AssertionError(
                "P2 cache consumption must not spawn ssh-keygen"
            )) as external:
                self.assertEqual(0, self.run_initial(
                    tool, ib_csv, p2p, cache, "--plan", "--execution-mode", "ethernet"
                ))
            external.assert_not_called()
            report = (cache.parent / "report.log").read_text(encoding="utf-8")
            self.assertIn("Target cache: reused", report)
            self.assertIn(fingerprint(laptop), report)
            self.assertIn(fingerprint(management), report)

    def test_auto_manager_missing_both_sources_rebakes_instead_of_using_stale_cache(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-auto-manager-") as directory:
            _, tool, global_path, ib_csv, p2p, _, cache, _, _ = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            original = cache.read_bytes()
            global_path.unlink()
            (tool / "publickey").unlink()
            with mock.patch.object(self.initial.socket, "gethostname", return_value="MGMT-SERVER"), \
                 mock.patch.object(self.initial.socket, "getfqdn", return_value="MGMT-SERVER"):
                self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--plan"))
            report = (cache.parent / "report.log").read_text(encoding="utf-8")
            self.assertIn("Target cache: generated", report)
            self.assertNotEqual(original, cache.read_bytes())
            payload = json.loads(cache.read_text(encoding="utf-8"))
            self.assertIsNone(payload["global"])
            self.assertIsNone(payload["services"])
            self.assertEqual([], payload["public_keys"])
            self.assertIn("Services SKIP: 01-global.yaml was unavailable", report)

    def test_auto_leaf_missing_both_sources_reuses_baked_cache(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-auto-leaf-") as directory:
            _, tool, global_path, ib_csv, p2p, _, cache, laptop, management = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            before = (cache.stat().st_ino, cache.read_bytes())
            global_path.unlink()
            (tool / "publickey").unlink()
            with mock.patch.object(self.initial.socket, "gethostname", return_value="EXAMPLE-JUMP01"), \
                 mock.patch.object(self.initial.socket, "getfqdn", return_value="EXAMPLE-JUMP01"):
                self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--plan"))
            report = (cache.parent / "report.log").read_text(encoding="utf-8")
            self.assertIn("Target cache: reused", report)
            self.assertIn(fingerprint(laptop), report)
            self.assertIn(fingerprint(management), report)
            self.assertEqual(before, (cache.stat().st_ino, cache.read_bytes()))

    def test_p1_rejects_a_public_key_rejected_by_real_loader(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-key-invalid-") as directory:
            _, tool, _, ib_csv, p2p, pubdir, cache, _, _ = self.fixture(directory)
            invalid = pubdir / "other.pub"
            invalid.write_text("ssh-ed25519 invalid!!!\n", encoding="ascii")
            with self.assertRaises(self.loader.LoadError):
                self.loader.validate_pubkey(invalid)
            with self.assertRaises(self.initial.SetupError):
                self.run_initial(tool, ib_csv, p2p, cache, "--generate-json")
            self.assertFalse(cache.exists(), "invalid project key must not publish a target cache")

    def test_p1_refuses_rsa_shape_rejected_by_real_loader_before_cache_publication(self) -> None:
        """Real load acceptance and real P1 publication must agree for RSA."""
        def field(data: bytes) -> bytes:
            return struct.pack(">I", len(data)) + data

        malformed = "ssh-rsa " + base64.b64encode(
            field(b"ssh-rsa") + field(b"\x01")
        ).decode("ascii") + " malformed-rsa\n"
        with tempfile.TemporaryDirectory(prefix="req10b-rsa-p1-") as directory:
            _, tool, _, ib_csv, p2p, pubdir, cache, _, _ = self.fixture(directory)
            key = pubdir / "other.pub"
            key.write_text(malformed, encoding="ascii")
            with self.assertRaises(self.loader.LoadError):
                self.loader.validate_pubkey(key)
            with self.assertRaises(self.initial.SetupError):
                self.run_initial(tool, ib_csv, p2p, cache, "--generate-json")
            self.assertFalse(cache.exists(), "P1 must not bake a key that load rejects")

    def test_p1_refuses_valid_then_invalid_multiline_key_before_cache_publication(self) -> None:
        """P1 must validate every public line before publishing a shared cache."""
        def field(data: bytes) -> bytes:
            return struct.pack(">I", len(data)) + data

        malformed = "ssh-rsa " + base64.b64encode(
            field(b"ssh-rsa") + field(b"\x01")
        ).decode("ascii") + " malformed-rsa\n"
        with tempfile.TemporaryDirectory(prefix="req10b-mixed-p1-") as directory:
            _, tool, _, ib_csv, p2p, pubdir, cache, laptop, _ = self.fixture(directory)
            (pubdir / "laptop.pub").write_text(laptop + malformed, encoding="ascii")
            with self.assertRaises(self.initial.SetupError):
                self.run_initial(tool, ib_csv, p2p, cache, "--generate-json")
            self.assertFalse(cache.exists(), "a bad second line must not enter target cache")

    def test_plan_lists_day0_services_and_complete_key_install_without_dispatch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-plan-") as directory:
            _, tool, _, ib_csv, p2p, _, cache, laptop, management = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            with mock.patch.object(self.initial, "run_on_ib") as network:
                self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--plan"))
            network.assert_not_called()
            report = (cache.parent / "report.log").read_text(encoding="utf-8")
            for command in (
                "nv set interface eth0 ipv4 address 203.0.113.2/24",
                "nv set interface eth0-1 ipv4 gateway 203.0.113.1",
                "nv set system hostname EXAMPLE-IB01",
                "nv set system dns server 203.0.113.53",
                "nv set system ntp server ntp.ubuntu.com",
                "nv set system ntp server time.ib.example.test",
                "nv set system date-time timezone Asia/Taipei",
                "nv config apply",
                "nv config save",
            ):
                with self.subTest(command=command):
                    self.assertIn(command, report)
            expected_public_payload = base64.b64encode(
                (laptop + management).encode("utf-8")
            ).decode("ascii")
            self.assertIn("authorized_keys", report)
            self.assertIn(expected_public_payload, report,
                          "the plan must retain both complete public lines, not just fingerprints")

    def test_configured_day0_still_enters_independent_service_transaction(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-configured-p2-") as directory:
            _, tool, _, ib_csv, p2p, _, cache, _, _ = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            commands: list[tuple[str, ...]] = []
            current = (
                "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
                "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
                "nv set system hostname EXAMPLE-IB01\n"
            )
            services = (
                "nv set system dns server 203.0.113.53\n"
                "nv set system ntp server ntp.ubuntu.com\n"
                "nv set system ntp server time.ib.example.test\n"
                "nv set system date-time timezone Asia/Taipei\n"
            )

            def device_boundary(*args, **_kwargs):
                command = tuple(args[7])
                commands.append(command)
                if command == ("nv", "config", "show", "-o", "commands"):
                    applied = ("nv", "config", "apply") in commands
                    return self.initial.SessionResult(current + (services if applied else ""), 0)
                return self.initial.SessionResult("", 0)

            neighbor = self.initial.Neighbor("fe80::1", "swp7", "02:00:00:00:00:17")
            with mock.patch.dict("os.environ", {"NVOS_INITIAL_PASSWORD": "initial-password"}), \
                 mock.patch.object(self.initial, "local_ethernet_keys", return_value=set()), \
                 mock.patch.object(self.initial, "prompt_ethernet_passwords", return_value={"example-jump01": "eth-password"}), \
                 mock.patch.object(self.initial, "collect_ethernet_interfaces", return_value=("EXAMPLE-JUMP01", "interface table")), \
                 mock.patch.object(self.initial, "collect_ethernet_network_tables", return_value=("links", "fdb", "neighbors")), \
                 mock.patch.object(self.initial, "save_ethernet_snapshot", return_value=cache.parent / "snapshot.txt"), \
                 mock.patch.object(self.initial, "interface_status_line", return_value="swp7 up"), \
                 mock.patch.object(self.initial, "interface_oper_status", return_value="up"), \
                 mock.patch.object(self.initial, "fdb_port_for_interface", return_value="swp7"), \
                 mock.patch.object(self.initial, "neighbor_for_port", return_value=neighbor), \
                 mock.patch.object(self.initial, "interface_vrf", return_value="default"), \
                 mock.patch.object(self.initial, "run_on_ib", side_effect=device_boundary):
                try:
                    self.run_initial(
                        tool, ib_csv, p2p, cache, "--apply", "--yes",
                        "--ethernet-password", "eth-password",
                    )
                finally:
                    report = self.initial.REPORT_HANDLE
                    if report is not None:
                        report.close()
                        self.initial.REPORT_HANDLE = None
            self.assertNotIn(
                ("nv", "set", "system", "hostname", "EXAMPLE-IB01"), commands,
                "configured Day-0 fields must not be rewritten",
            )
            self.assertIn(
                ("nv", "set", "system", "dns", "server", "203.0.113.53"), commands,
                "configured Day-0 must not skip missing services",
            )
            self.assertIn(("nv", "config", "apply"), commands)
            self.assertIn(("nv", "config", "save"), commands)
            self.assertIn("day0-skipped=1", (cache.parent / "report.log").read_text(encoding="utf-8"))
            self.assertIn("services-skipped=0", (cache.parent / "report.log").read_text(encoding="utf-8"))

    def _exercise_upgrade_rerun(self, missing_services: tuple[str, ...],
                                *, suppress_service_stage: bool = False,
                                wipe_day0: bool = False,
                                suppress_day0_detection: bool = False) -> None:
        """Run the real setup three times against one isolated device state."""
        with tempfile.TemporaryDirectory(prefix="req10b-upgrade-rerun-") as directory:
            root, tool, _, ib_csv, p2p, _, cache, laptop, management = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            day0 = [
                "nv set interface eth0 ipv4 address 203.0.113.2/24",
                "nv set interface eth0-1 ipv4 gateway 203.0.113.1",
                "nv set system hostname EXAMPLE-IB01",
            ]
            day0_argv = [tuple(line.split()) for line in day0]
            service_argv = [
                ("nv", "set", "system", "dns", "server", "203.0.113.53"),
                ("nv", "set", "system", "ntp", "server", "ntp.ubuntu.com"),
                ("nv", "set", "system", "ntp", "server", "time.ib.example.test"),
                ("nv", "set", "system", "date-time", "timezone", "Asia/Taipei"),
            ]
            service_lines = [" ".join(command) for command in service_argv]
            self.assertTrue(set(missing_services) <= set(service_lines))
            running = day0 + service_lines
            pending: list[str] = []
            rounds: list[list[tuple[str, ...]]] = []
            device_home = root / "fake-device-home"
            device_home.mkdir()
            ssh_dir = device_home / ".ssh"
            ssh_dir.mkdir()
            authorized = ssh_dir / "authorized_keys"
            authorized.write_text(laptop + management, encoding="ascii")
            original_keys = (authorized.stat().st_ino, authorized.read_bytes())

            def device_boundary(*args, **_kwargs):
                command = tuple(args[7])
                rounds[-1].append(command)
                if command == ("nv", "config", "show", "-o", "commands"):
                    return self.initial.SessionResult("\n".join(running) + "\n", 0)
                if command in service_argv or command in day0_argv:
                    pending.append(" ".join(command))
                elif command == ("nv", "config", "apply"):
                    for line in pending:
                        if line not in running:
                            running.append(line)
                    pending.clear()
                elif command[:2] == ("sh", "-c"):
                    result = subprocess.run(
                        command, cwd=root,
                        env={"HOME": str(device_home), "PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                        capture_output=True, text=True, timeout=10, check=False,
                    )
                    self.assertEqual(0, result.returncode, result.stderr)
                return self.initial.SessionResult("", 0)

            neighbor = self.initial.Neighbor("fe80::1", "swp7", "02:00:00:00:00:17")
            with ExitStack() as stack:
                stack.enter_context(mock.patch.dict("os.environ", {"NVOS_INITIAL_PASSWORD": "initial-password"}))
                ipv4_verify = stack.enter_context(mock.patch.object(self.initial, "verify_ipv4_login"))
                for name, value in (
                    ("local_ethernet_keys", set()),
                    ("prompt_ethernet_passwords", {"example-jump01": "eth-password"}),
                    ("collect_ethernet_interfaces", ("EXAMPLE-JUMP01", "interface table")),
                    ("collect_ethernet_network_tables", ("links", "fdb", "neighbors")),
                    ("save_ethernet_snapshot", cache.parent / "snapshot.txt"),
                    ("interface_status_line", "swp7 up"),
                    ("interface_oper_status", "up"),
                    ("fdb_port_for_interface", "swp7"),
                    ("neighbor_for_port", neighbor),
                    ("interface_vrf", "default"),
                    ("run_on_ib", mock.DEFAULT),
                ):
                    if name == "run_on_ib":
                        stack.enter_context(mock.patch.object(self.initial, name, side_effect=device_boundary))
                    else:
                        stack.enter_context(mock.patch.object(self.initial, name, return_value=value))

                def invoke() -> str:
                    rounds.append([])
                    self.assertEqual(0, self.run_initial(
                        tool, ib_csv, p2p, cache, "--apply", "--yes",
                        "--ethernet-password", "eth-password",
                    ))
                    return (cache.parent / "report.log").read_text(encoding="utf-8")

                first_report = invoke()
                self.assertIn("day0-skipped=1", first_report)
                self.assertIn("services-skipped=1", first_report)
                self.assertFalse(any(command in day0_argv for command in rounds[0]))
                self.assertFalse(any(command in service_argv for command in rounds[0]))
                self.assertNotIn(("nv", "config", "apply"), rounds[0])
                self.assertNotIn(("nv", "config", "save"), rounds[0])
                self.assertEqual(original_keys, (authorized.stat().st_ino, authorized.read_bytes()))

                if wipe_day0:
                    running.clear()
                else:
                    running[:] = [line for line in running if line not in missing_services]
                if suppress_service_stage:
                    with mock.patch.object(self.initial, "run_service_stage", return_value=(True, True)):
                        second_report = invoke()
                elif suppress_day0_detection:
                    with mock.patch.object(self.initial, "state_is_unconfigured", return_value=False):
                        second_report = invoke()
                else:
                    second_report = invoke()
                self.assertEqual(day0, running[:len(day0)],
                                 "upgrade rerun did not restore Day-0 state")
                self.assertEqual(
                    set(service_lines), set(running) - set(day0),
                    "upgrade rerun did not restore all desired service state",
                )
                self.assertEqual(len(day0) + len(service_lines), len(running),
                                 "upgrade rerun must not duplicate desired service values")
                self.assertIn(f"day0-skipped={0 if wipe_day0 else 1}", second_report)
                self.assertIn("services-skipped=0", second_report)
                if wipe_day0:
                    self.assertEqual(day0_argv, [command for command in rounds[1]
                                                  if command in day0_argv])
                    transaction_commands = set(day0_argv + service_argv) | {
                        ("nv", "config", "apply"), ("nv", "config", "save")
                    }
                    self.assertEqual(
                        day0_argv + [("nv", "config", "apply"), ("nv", "config", "save")]
                        + service_argv + [("nv", "config", "apply"), ("nv", "config", "save")],
                        [command for command in rounds[1] if command in transaction_commands],
                        "upgrade rerun must commit Day-0 before the separate service transaction",
                    )
                    self.assertEqual(1, ipv4_verify.call_count)
                else:
                    self.assertFalse(any(command in day0_argv for command in rounds[1]))
                    self.assertEqual(0, ipv4_verify.call_count)
                self.assertEqual(
                    [command for command in service_argv if " ".join(command) in missing_services],
                    [command for command in rounds[1] if command in service_argv],
                    "upgrade rerun must write only missing service values",
                )
                self.assertEqual(2 if wipe_day0 else 1,
                                 rounds[1].count(("nv", "config", "apply")))
                self.assertEqual(2 if wipe_day0 else 1,
                                 rounds[1].count(("nv", "config", "save")))
                self.assertEqual(original_keys, (authorized.stat().st_ino, authorized.read_bytes()))

                third_report = invoke()
                self.assertIn("day0-skipped=1", third_report)
                self.assertIn("services-skipped=1", third_report)
                self.assertFalse(any(command in day0_argv for command in rounds[2]))
                self.assertFalse(any(command in service_argv for command in rounds[2]))
                self.assertNotIn(("nv", "config", "apply"), rounds[2])
                self.assertNotIn(("nv", "config", "save"), rounds[2])
                self.assertEqual(day0, running[:len(day0)])
                self.assertEqual(set(service_lines), set(running[len(day0):]))
                self.assertEqual(len(day0) + len(service_lines), len(running))
                self.assertEqual(original_keys, (authorized.stat().st_ino, authorized.read_bytes()))
                self.assertEqual(1 if wipe_day0 else 0, ipv4_verify.call_count)

    def test_upgrade_wipe_then_rerun_restores_only_missing_services_and_keeps_keys(self) -> None:
        services = (
            "nv set system dns server 203.0.113.53",
            "nv set system ntp server ntp.ubuntu.com",
            "nv set system ntp server time.ib.example.test",
            "nv set system date-time timezone Asia/Taipei",
        )
        for missing in (services, (services[0], services[-1])):
            with self.subTest(missing=missing):
                self._exercise_upgrade_rerun(missing)

    def test_upgrade_rerun_oracle_rejects_skipping_missing_services(self) -> None:
        with self.assertRaisesRegex(AssertionError, "upgrade rerun did not restore"):
            self._exercise_upgrade_rerun(
                ("nv set system dns server 203.0.113.53",),
                suppress_service_stage=True,
            )

    def test_upgrade_full_day0_and_services_wipe_restores_two_transactions_then_is_idempotent(self) -> None:
        services = (
            "nv set system dns server 203.0.113.53",
            "nv set system ntp server ntp.ubuntu.com",
            "nv set system ntp server time.ib.example.test",
            "nv set system date-time timezone Asia/Taipei",
        )
        self._exercise_upgrade_rerun(services, wipe_day0=True)

    def test_upgrade_full_wipe_oracle_rejects_skipping_day0_restoration(self) -> None:
        services = (
            "nv set system dns server 203.0.113.53",
            "nv set system ntp server ntp.ubuntu.com",
            "nv set system ntp server time.ib.example.test",
            "nv set system date-time timezone Asia/Taipei",
        )
        with self.assertRaisesRegex(AssertionError, "upgrade rerun did not restore Day-0 state"):
            self._exercise_upgrade_rerun(
                services, wipe_day0=True, suppress_day0_detection=True,
            )

    def test_day0_verification_failure_never_enters_services(self) -> None:
        _, commands, report, _, _ = self.drive_one_device("", "")
        self.assertIn("post-configuration verification failed", report)
        self.assertFalse(any(command[:4] == ("nv", "set", "system", "dns")
                             for command in commands))
        self.assertFalse(any(command[:4] == ("nv", "set", "system", "ntp")
                             for command in commands))

    def test_fresh_day0_success_flows_into_service_transaction(self) -> None:
        day0 = (
            "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
            "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
            "nv set system hostname EXAMPLE-IB01\n"
        )
        services = (
            "nv set system dns server 203.0.113.53\n"
            "nv set system ntp server ntp.ubuntu.com\n"
            "nv set system ntp server time.ib.example.test\n"
            "nv set system date-time timezone Asia/Taipei\n"
        )
        result, commands, report, _, _ = self.drive_one_device(
            "", day0, post_service_state=day0 + services,
        )
        self.assertEqual(0, result, report)
        self.assertIn(("nv", "set", "interface", "eth0", "ipv4", "address",
                       "203.0.113.2/24"), commands)
        self.assertIn(("nv", "set", "system", "dns", "server", "203.0.113.53"), commands)
        self.assertIn("Services SUCCESS: desired values verified", report)

    def test_missing_global_permits_day0_and_reports_service_skip(self) -> None:
        verified = (
            "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
            "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
            "nv set system hostname EXAMPLE-IB01\n"
        )
        result, commands, report, _, _ = self.drive_one_device(
            "", verified, remove_global_before_p1=True,
        )
        self.assertEqual(0, result, report)
        self.assertIn("Services SKIP: 01-global.yaml was unavailable", report)
        self.assertIn("services-skipped=1", report)
        self.assertFalse(any(command[:4] == ("nv", "set", "system", "dns")
                             for command in commands))

    def test_ethernet_p2_uses_baked_services_without_global_or_yaml_library(self) -> None:
        configured = (
            "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
            "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
            "nv set system hostname EXAMPLE-IB01\n"
        )
        services = (
            "nv set system dns server 203.0.113.53\n"
            "nv set system ntp server ntp.ubuntu.com\n"
            "nv set system ntp server time.ib.example.test\n"
            "nv set system date-time timezone Asia/Taipei\n"
        )
        result, commands, report, _, _ = self.drive_one_device(
            configured, configured + services,
            "--execution-mode", "ethernet", remove_global_before_p2=True,
        )
        self.assertEqual(0, result, report)
        self.assertIn(("nv", "set", "system", "dns", "server", "203.0.113.53"), commands)
        self.assertIn("Services SUCCESS: desired values verified", report)
        self.assertIn("Local Ethernet execution: example-jump01", report)

    def test_ethernet_mode_names_stale_v3_cache_and_preserves_both_inodes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-leaf-v3-") as directory:
            _, tool, _, ib_csv, p2p, _, cache, _, _ = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            payload = json.loads(cache.read_text(encoding="utf-8"))
            payload["version"] = 3
            raw = (json.dumps(payload, sort_keys=True) + "\n").encode()
            cache.write_bytes(raw)
            sidecar = cache.with_name(cache.name + ".sha256")
            sidecar.write_text(f"{hashlib.sha256(raw).hexdigest()}  {cache.name}\n", encoding="ascii")
            before = (cache.stat().st_ino, cache.read_bytes(), sidecar.stat().st_ino, sidecar.read_bytes())
            with self.assertRaisesRegex(self.initial.SetupError, "(?i)version|版本"):
                self.run_initial(tool, ib_csv, p2p, cache, "--plan", "--execution-mode", "ethernet")
            after = (cache.stat().st_ino, cache.read_bytes(), sidecar.stat().st_ino, sidecar.read_bytes())
            self.assertEqual(before, after, "stale cache evidence must not be silently rewritten")

    def test_force_fills_missing_day0_fields_without_rewriting_matching_fields(self) -> None:
        services = (
            "nv set system dns server 203.0.113.53\n"
            "nv set system ntp server ntp.ubuntu.com\n"
            "nv set system ntp server time.ib.example.test\n"
            "nv set system date-time timezone Asia/Taipei\n"
        )
        first = "nv set interface eth0 ipv4 address 203.0.113.2/24\n" + services
        verified = (
            "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
            "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
            "nv set system hostname EXAMPLE-IB01\n" + services
        )
        result, commands, report, _, _ = self.drive_one_device(first, verified, "--force")
        self.assertEqual(0, result, report)
        self.assertIn(("nv", "set", "system", "hostname", "EXAMPLE-IB01"), commands)
        self.assertIn(("nv", "config", "apply"), commands)
        self.assertIn(("nv", "config", "save"), commands)

    def test_force_refuses_mismatching_existing_eth0_without_day0_writes(self) -> None:
        state = (
            "nv set interface eth0 ipv4 address 198.51.100.2/24\n"
            "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
            "nv set system hostname EXAMPLE-IB01\n"
            "nv set system dns server 203.0.113.53\n"
            "nv set system ntp server ntp.ubuntu.com\n"
            "nv set system ntp server time.ib.example.test\n"
            "nv set system date-time timezone Asia/Taipei\n"
        )
        _, commands, report, _, _ = self.drive_one_device(state, state, "--force")
        self.assertFalse(any(command[:3] == ("nv", "set", "interface") for command in commands))
        self.assertNotIn(("nv", "config", "apply"), commands)
        self.assertNotIn(("nv", "config", "save"), commands)
        self.assertRegex(report.lower(), "mismatch|conflict|differs")

    def test_p2_installs_baked_keys_through_nested_device_boundary(self) -> None:
        state = (
            "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
            "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
            "nv set system hostname EXAMPLE-IB01\n"
            "nv set system dns server 203.0.113.53\n"
            "nv set system ntp server ntp.ubuntu.com\n"
            "nv set system ntp server time.ib.example.test\n"
            "nv set system date-time timezone Asia/Taipei\n"
        )
        result, commands, report, laptop, management = self.drive_one_device(state, state)
        self.assertEqual(0, result, report)
        self.assertTrue(any("authorized_keys" in " ".join(command) for command in commands),
                        "the keys must be installed over the existing nested SSH boundary")
        self.assertIn(fingerprint(laptop), report)
        self.assertIn(fingerprint(management), report)

    def test_key_stage_verifies_only_matching_local_management_private_key(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-possession-") as directory:
            private = Path(directory) / "id_ed25519"
            private.write_text("test-only private-key placeholder\n", encoding="ascii")
            laptop = public_key(17, "laptop").strip()
            management = public_key(18, "management").strip()
            keys = [
                {"name": "laptop.pub", "line": laptop, "fingerprint": fingerprint(laptop)},
                {"name": "mgmt-server.pub", "line": management,
                 "fingerprint": fingerprint(management)},
            ]
            ib = self.initial.Device("EXAMPLE-IB01", "ib", "203.0.113.2",
                                     "203.0.113.2/24", "203.0.113.1", "", "", "")
            transit = self.initial.Device("EXAMPLE-JUMP01", "eth_jump", "192.0.2.10",
                                          "192.0.2.10", "", "", "", "")
            target = self.initial.Target(ib, transit, "swp7", "eth0")
            neighbor = self.initial.Neighbor("fe80::1", "swp7", "02:00:00:00:00:17")
            calls: list[list[str]] = []

            def key_boundary(argv, **_kwargs):
                calls.append(argv)
                if argv[0] == "ssh-keygen":
                    return subprocess.CompletedProcess(argv, 0, management + "\n", "")
                if argv[0] == "ssh":
                    return subprocess.CompletedProcess(argv, 0, "", "")
                self.fail(f"unexpected local command {argv}")

            with mock.patch.object(self.initial, "run_on_ib", return_value=self.initial.SessionResult("", 0)) as installer, \
                 mock.patch.object(subprocess, "run", side_effect=key_boundary), \
                 redirect_stdout(io.StringIO()) as output:
                self.assertTrue(self.initial.run_key_stage(
                    target, neighbor, "cumulus", "ethernet-password", "admin", 10,
                    keys, local=False, apply=True, authorized=True,
                    management_private_key=private,
                ))
            installer.assert_called_once()
            self.assertEqual(["ssh-keygen", "ssh"], [call[0] for call in calls])
            ssh = calls[1]
            self.assertIn("BatchMode=yes", ssh)
            self.assertIn("PreferredAuthentications=publickey", ssh)
            self.assertIn("PasswordAuthentication=no", ssh)
            self.assertIn("IdentitiesOnly=yes", ssh)
            self.assertEqual("true", ssh[-1])
            self.assertIn("laptop.pub", output.getvalue())
            self.assertIn("已写入，未验证", output.getvalue())
            self.assertIn("mgmt-server.pub", output.getvalue())
            self.assertIn("已验证", output.getvalue())

            with mock.patch.object(self.initial, "run_on_ib", return_value=self.initial.SessionResult("", 0)), \
                 mock.patch.object(subprocess, "run") as local_command, \
                 redirect_stdout(io.StringIO()) as no_private_output:
                self.initial.run_key_stage(
                    target, neighbor, "cumulus", "ethernet-password", "admin", 10,
                    keys, local=False, apply=True, authorized=True,
                    management_private_key=None,
                )
            local_command.assert_not_called()
            self.assertEqual(2, no_private_output.getvalue().count("已写入，未验证"))

            with mock.patch.object(self.initial, "run_on_ib", return_value=self.initial.SessionResult("", 0)), \
                 mock.patch.object(subprocess, "run", return_value=subprocess.CompletedProcess(
                     ["ssh-keygen"], 0, laptop + "\n", ""
                 )) as wrong_key:
                with self.assertRaises(self.initial.SetupError):
                    self.initial.run_key_stage(
                        target, neighbor, "cumulus", "ethernet-password", "admin", 10,
                        keys, local=False, apply=True, authorized=True,
                        management_private_key=private,
                    )
            self.assertEqual(1, wrong_key.call_count,
                             "mismatched local private identity must fail before SSH")

    def test_key_failure_on_first_device_does_not_block_second_device(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-key-continue-") as directory:
            _, tool, _, ib_csv, p2p, _, cache, _, _ = self.fixture(directory)
            with ib_csv.open("a", encoding="utf-8") as stream:
                stream.write("EXAMPLE-IB02,ib,203.0.113.3,24,203.0.113.1,,,,\n")
            with p2p.open("a", encoding="utf-8") as stream:
                stream.write('"EXAMPLE-IB02":"eth0" -- "EXAMPLE-JUMP01":"8";\n')
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            attempted: list[str] = []
            state = (
                "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
                "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
                "nv set system hostname EXAMPLE-IB01\n"
                "nv set system dns server 203.0.113.53\n"
                "nv set system ntp server ntp.ubuntu.com\n"
                "nv set system ntp server time.ib.example.test\n"
                "nv set system date-time timezone Asia/Taipei\n"
            )

            def boundary(target, *_args, **_kwargs):
                command = tuple(_args[6])
                if "authorized_keys" in " ".join(command):
                    attempted.append(target.ib.hostname)
                    if target.ib.hostname == "EXAMPLE-IB01":
                        raise self.initial.SetupError("injected key installation failure")
                output = state.replace("203.0.113.2/24", target.ib.eth0_prefix).replace(
                    "EXAMPLE-IB01", target.ib.hostname
                )
                return self.initial.SessionResult(output, 0)

            neighbor = self.initial.Neighbor("fe80::1", "swp7", "02:00:00:00:00:17")
            with ExitStack() as stack:
                stack.enter_context(mock.patch.dict("os.environ", {"NVOS_INITIAL_PASSWORD": "initial-password"}))
                for name, value in (
                    ("local_ethernet_keys", set()),
                    ("prompt_ethernet_passwords", {"example-jump01": "eth-password"}),
                    ("collect_ethernet_interfaces", ("EXAMPLE-JUMP01", "interface table")),
                    ("collect_ethernet_network_tables", ("links", "fdb", "neighbors")),
                    ("save_ethernet_snapshot", cache.parent / "snapshot.txt"),
                    ("interface_status_line", "swp7 up"),
                    ("interface_oper_status", "up"),
                    ("fdb_port_for_interface", "swp7"),
                    ("neighbor_for_port", neighbor),
                    ("interface_vrf", "default"),
                ):
                    stack.enter_context(mock.patch.object(self.initial, name, return_value=value))
                stack.enter_context(mock.patch.object(self.initial, "run_on_ib", side_effect=boundary))
                try:
                    self.run_initial(tool, ib_csv, p2p, cache, "--apply", "--yes",
                                     "--ethernet-password", "eth-password")
                finally:
                    report = self.initial.REPORT_HANDLE
                    if report is not None:
                        report.close()
                        self.initial.REPORT_HANDLE = None
            self.assertEqual(["EXAMPLE-IB01", "EXAMPLE-IB02"], attempted)

    def test_service_failure_on_first_device_continues_to_second_device(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-service-continue-") as directory:
            _, tool, _, ib_csv, p2p, _, cache, _, _ = self.fixture(directory)
            with ib_csv.open("a", encoding="utf-8") as stream:
                stream.write("EXAMPLE-IB02,ib,203.0.113.3,24,203.0.113.1,,,,\n")
            with p2p.open("a", encoding="utf-8") as stream:
                stream.write('"EXAMPLE-IB02":"eth0" -- "EXAMPLE-JUMP01":"8";\n')
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            attempted: list[str] = []
            applied: set[str] = set()
            day0 = (
                "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
                "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
                "nv set system hostname EXAMPLE-IB01\n"
            )
            services = (
                "nv set system dns server 203.0.113.53\n"
                "nv set system ntp server ntp.ubuntu.com\n"
                "nv set system ntp server time.ib.example.test\n"
                "nv set system date-time timezone Asia/Taipei\n"
            )

            def boundary(target, *_args, **_kwargs):
                command = tuple(_args[6])
                name = target.ib.hostname
                if command[:5] == ("nv", "set", "system", "dns", "server"):
                    attempted.append(name)
                    if name == "EXAMPLE-IB01":
                        raise self.initial.SetupError("injected service failure")
                if command == ("nv", "config", "apply"):
                    applied.add(name)
                output = day0.replace("203.0.113.2/24", target.ib.eth0_prefix).replace(
                    "EXAMPLE-IB01", name
                )
                if name in applied:
                    output += services
                return self.initial.SessionResult(output, 0)

            neighbor = self.initial.Neighbor("fe80::1", "swp7", "02:00:00:00:00:17")
            with ExitStack() as stack:
                stack.enter_context(mock.patch.dict("os.environ", {"NVOS_INITIAL_PASSWORD": "initial-password"}))
                for name, value in (
                    ("local_ethernet_keys", set()),
                    ("prompt_ethernet_passwords", {"example-jump01": "eth-password"}),
                    ("collect_ethernet_interfaces", ("EXAMPLE-JUMP01", "interface table")),
                    ("collect_ethernet_network_tables", ("links", "fdb", "neighbors")),
                    ("save_ethernet_snapshot", cache.parent / "snapshot.txt"),
                    ("interface_status_line", "swp7 up"),
                    ("interface_oper_status", "up"),
                    ("fdb_port_for_interface", "swp7"),
                    ("neighbor_for_port", neighbor),
                    ("interface_vrf", "default"),
                ):
                    stack.enter_context(mock.patch.object(self.initial, name, return_value=value))
                stack.enter_context(mock.patch.object(self.initial, "run_on_ib", side_effect=boundary))
                result = self.run_initial(tool, ib_csv, p2p, cache, "--apply", "--yes",
                                          "--ethernet-password", "eth-password")
            report = (cache.parent / "report.log").read_text(encoding="utf-8")
            self.assertEqual(1, result, report)
            self.assertEqual(["EXAMPLE-IB01", "EXAMPLE-IB02"], attempted)
            self.assertIn("injected service failure", report)
            self.assertIn("[EXAMPLE-IB02]", report)
            self.assertIn("Services SUCCESS: desired values verified", report)

    def test_leaf_rejects_rechecksummed_semantically_invalid_v4_before_dispatch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-hostile-cache-") as directory:
            _, tool, _, ib_csv, p2p, _, cache, _, _ = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            valid = json.loads(cache.read_text(encoding="utf-8"))
            cases = {
                "key_type_blob_mismatch": lambda value: value["public_keys"][0].update(
                    line=value["public_keys"][0]["line"].replace("ssh-ed25519 ", "ssh-rsa ", 1)
                ),
                "key_comment_nul": lambda value: value["public_keys"][0].update(
                    line=value["public_keys"][0]["line"] + "\x00comment"
                ),
                "dns_control_carrier": lambda value: value["services"].update(
                    dns=["203.0.113.53\nnv set system aaa user admin"]
                ),
                "unexpected_service_category": lambda value: value["services"].update(
                    aaa={"user": "admin"}
                ),
            }
            for label, mutate in cases.items():
                with self.subTest(label=label):
                    payload = json.loads(json.dumps(valid))
                    mutate(payload)
                    self.rewrite_cache_with_matching_sidecar(cache, payload)
                    before = (cache.stat().st_ino, cache.read_bytes())
                    with mock.patch.object(self.initial, "run_on_ib") as network:
                        with self.assertRaises(self.initial.SetupError):
                            self.run_initial(tool, ib_csv, p2p, cache,
                                             "--apply", "--yes", "--execution-mode", "ethernet")
                    network.assert_not_called()
                    self.assertEqual(before, (cache.stat().st_ino, cache.read_bytes()))


if __name__ == "__main__":
    unittest.main()
