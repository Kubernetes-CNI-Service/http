"""Direct, implementation-independent entry contracts for REQ-10-B.

These are deliberately RED until the service/key implementation exists.  The
expected command vectors and cache version come from requirements 10B, not
from a generated output of the script under test.
"""

from __future__ import annotations

import ast
import base64
import hashlib
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
SCRIPT = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"


class Req10BServicesKeysContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.initial = load_script("req10b_services_keys_direct", SCRIPT)

    def test_target_cache_version_is_four(self) -> None:
        self.assertEqual(4, self.initial.TARGET_CACHE_VERSION)

    def test_f02_cache_snapshot_missing_member_never_falls_back_to_filesystem(self):
        """A finite immutable input map is closed, not a best-effort read cache."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            cache, csv_path, p2p = (root / name for name in ("cache.json", "ib.csv", "p2p.dot"))
            snapshot = {str(cache): (str(cache), 1000000000, b"{}")}
            with mock.patch.object(Path, "open", side_effect=AssertionError("snapshot fallback opened filesystem")):
                self.assertIsNone(self.initial.load_target_cache(
                    cache, csv_path, p2p, input_snapshot=snapshot))
            for malformed in (None, True, (str(cache), True, b"{}"),
                              ("relative/path", 1000000000, b"{}"),
                              (str(cache), 1000000000, "not bytes")):
                with self.subTest(malformed=malformed), mock.patch.object(
                        Path, "open", side_effect=AssertionError("malformed snapshot fallback")):
                    self.assertIsNone(self.initial.load_target_cache(
                        cache, csv_path, p2p, input_snapshot={str(cache): malformed}))

    def test_f02_cache_snapshot_freezes_bytes_names_times_and_exact_byte_bound(self):
        snapshot_type = getattr(self.initial, "_CacheInputSnapshot", None)
        self.assertTrue(callable(snapshot_type))
        root = Path("/independent/project")
        cache, key = root / "cache.json", root / "tool/publickey/management.pub"
        literal = b"independent captured bytes"
        images = {str(cache): (str(cache), 1000000000, literal),
                  str(key): (str(root / "owned-keys/management.pub"), 2000000000, b"independent key bytes")}
        with mock.patch.object(Path, "open", side_effect=AssertionError("captured snapshot reopened a path")):
            captured = snapshot_type(images)
            images[str(cache)] = (str(root / "foreign"), 9000000000, b"later caller mutation")
            self.assertEqual(literal, captured.read(cache))
            self.assertEqual(str(cache), captured.canonical(cache))
            self.assertEqual(1000000000, captured.mtime_ns(cache))
            with self.assertRaises(TypeError):
                captured.images[str(cache)] = (str(root / "foreign"), 9000000000, b"later internal mutation")
            self.assertEqual([key], captured.public_keys(root / "tool"))
            with self.assertRaises(ValueError): captured.read(root / "missing")
            maximum = b"x" * (8 * 1024 * 1024)
            self.assertEqual(maximum, snapshot_type({str(cache): (str(cache), 0, maximum)}).read(cache))
            for invalid in (b"", maximum + b"x"):
                with self.subTest(size=len(invalid)), self.assertRaises(ValueError):
                    snapshot_type({str(cache): (str(cache), 0, invalid)})

    def test_f02_initial_method_compares_own_batch_identity_day0_services_and_keys(self):
        observe = getattr(self.initial, "observe_managed_initial_configuration", None)
        self.assertTrue(callable(observe), "key possession alone is not current method configuration proof")
        device = self.initial.Device("IB01", "ib", "192.0.2.10", "192.0.2.10/24", "192.0.2.1",
                                     "02:00:00:00:00:01", "", "")
        transit = self.initial.Device("jump", "eth_jump", "192.0.2.2", "", "", "", "", "")
        target = self.initial.Target(device, transit, "swp1", "eth0")
        services = {"dns": ["192.0.2.53"], "ntp": ["time.example.test"], "timezone": "Etc/UTC"}
        blob = (len(b"ssh-ed25519").to_bytes(4, "big") + b"ssh-ed25519" + (32).to_bytes(4, "big") + b"x" * 32)
        key = "ssh-ed25519 " + base64.b64encode(blob).decode() + " independent-fixture"
        fp = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
        keys = [{"name": "mgmt-server.pub", "line": key, "fingerprint": fp}]
        current = ("nv set interface eth0 ipv4 address 192.0.2.10/24\n"
                   "nv set interface eth0-1 ipv4 gateway 192.0.2.1\n"
                   "nv set system hostname IB01\n"
                   "nv set system dns server 192.0.2.53\n"
                   "nv set system ntp server time.example.test\n"
                   "nv set system date-time timezone Etc/UTC\n")
        def framed(config=current, auth=key + "\n", host="IB01", mac="02:00:00:00:00:01", rc="0"):
            return ("__HTTP_INITIAL_METHOD_V1_IDENTITY_BEGIN__\n" + host + "\n" + mac + "\n"
                    "__HTTP_INITIAL_METHOD_V1_IDENTITY_END__\n"
                    "__HTTP_INITIAL_METHOD_V1_CONFIG_BEGIN__\n" + config + "__HTTP_INITIAL_METHOD_V1_CONFIG_END__=" + rc + "\n"
                    "__HTTP_INITIAL_METHOD_V1_KEYS_BEGIN__\n" + auth + "__HTTP_INITIAL_METHOD_V1_KEYS_END__=0\n")
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
                self.initial.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, framed(), "")):
            private = Path(directory).resolve() / "management-key"
            private.write_text("fixture-not-a-real-private-key")
            private.chmod(0o600)
            with mock.patch.object(self.initial, "_run_initial_observation", create=True, return_value=subprocess.CompletedProcess([], 0, framed(), "")) as transport:
                proof = observe(target, "admin", private, 5, services, keys)
            self.assertIs(True, proof["batch_identity_verified"])
            self.assertIs(True, proof["config_verified"])
            self.assertEqual("IB01", proof["hostname"])
            self.assertEqual("020000000001", proof["mac_plain"])
            self.assertEqual(hashlib.sha256(current.encode()).hexdigest(), proof["live_state_sha256"])
            basis = {"schema_version": 1, "type": "ib", "config_method": "initial-setup", "hostname": "IB01",
                     "eth0": "192.0.2.10/24", "eth0_gateway": "192.0.2.1", "eth1": "", "eth1_gateway": "",
                     "eth0_mac": "02:00:00:00:00:01", "dns": ["192.0.2.53"], "ntp": ["time.example.test"],
                     "timezone": "Etc/UTC", "key_fingerprints": [fp]}
            self.assertEqual(hashlib.sha256(json.dumps(basis, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=False).encode()).hexdigest(), proof["input_sha256"])
            self.assertNotIn("generation", proof)
            self.assertNotIn("complete", proof)
            self.assertEqual(1, transport.call_count, "identity, live state and keys must be one connection")
            command = transport.call_args.args[0]
            self.assertIn("BatchMode=yes", command)
            self.assertIn("PasswordAuthentication=no", command)
            self.assertIn("admin@192.0.2.10", command)
            self.assertIn("nv config show -o commands", command[-1])
            for output in (framed(config=current.replace("192.0.2.53", "192.0.2.54")),
                           framed(config=current.replace("time.example.test", "other.example.test")),
                           framed(config=current.replace("Etc/UTC", "Asia/Shanghai")),
                           framed(config=current.replace("192.0.2.10/24", "192.0.2.11/24")),
                           framed(auth=""), framed(host="foreign"), framed(mac="02:00:00:00:00:02"),
                           framed(config=current + "nv set interface eth0 ipv4 address 192.0.2.99/24\n"),
                           framed(rc="1"), framed() + framed(), "old interactive log: SUCCESS\n"):
                with self.subTest(output=output[:90]), mock.patch.object(self.initial, "_run_initial_observation", create=True,
                        return_value=subprocess.CompletedProcess([], 0, output, "")):
                    self.assertIs(False, observe(target, "admin", private, 5, services, keys)["config_verified"])
            with mock.patch.object(self.initial, "_run_initial_observation", create=True, return_value=subprocess.CompletedProcess([], True, framed(), "")):
                self.assertIs(False, observe(target, "admin", private, 5, services, keys)["config_verified"])
            def changed_key(*args, **kwargs):
                private.write_text("different-key-during-observation")
                return subprocess.CompletedProcess([], 0, framed(), "")
            with mock.patch.object(self.initial, "_run_initial_observation", create=True, side_effect=changed_key):
                self.assertIs(False, observe(target, "admin", private, 5, services, keys)["config_verified"],
                              "a replaced or edited private identity must withdraw this observation")
            private.chmod(0o644)
            with mock.patch.object(self.initial, "_run_initial_observation", create=True) as unsafe_transport:
                self.assertIs(False, observe(target, "admin", private, 5, services, keys)["config_verified"])
            unsafe_transport.assert_not_called()
            private.chmod(0o600)
            with mock.patch.object(self.initial, "_run_initial_observation", return_value=subprocess.CompletedProcess([], 0, framed(), "")) as invalid_timeout:
                self.assertIs(False, observe(target, "admin", private, 601, services, keys)["config_verified"])
            invalid_timeout.assert_not_called()
            for shape in ("symlink", "hardlink", "fifo"):
                alternative = private.parent / shape
                if shape == "symlink":
                    alternative.symlink_to(private)
                elif shape == "hardlink":
                    os.link(private, alternative)
                else:
                    os.mkfifo(alternative, 0o600)
                try:
                    with mock.patch.object(self.initial, "_run_initial_observation") as unsafe_transport:
                        self.assertIs(False, observe(target, "admin", alternative, 5, services, keys)["config_verified"])
                    unsafe_transport.assert_not_called()
                finally:
                    alternative.unlink()
            def changed_profile(*args, **kwargs):
                services["dns"] = ["192.0.2.54"]
                return subprocess.CompletedProcess([], 0, framed(config=current.replace("192.0.2.53", "192.0.2.54")), "")
            with mock.patch.object(self.initial, "_run_initial_observation", create=True, side_effect=changed_profile):
                self.assertIs(False, observe(target, "admin", private, 5, services, keys)["config_verified"],
                              "changing the expected profile during the session cannot return an old input digest")

    def test_f02_initial_observation_has_bounded_dual_pipe_capture(self):
        capture = getattr(self.initial, "_run_initial_observation", None)
        self.assertTrue(callable(capture), "post-hoc output length is not bounded capture")
        result = capture([sys.executable, "-c", "import sys; print('literal-frame'); print('diagnostic', file=sys.stderr)"], 5)
        self.assertEqual((0, "literal-frame\n", "diagnostic\n"), (result.returncode, result.stdout, result.stderr))
        # Both streams share one budget, and the child must be reaped on overflow.
        with mock.patch.object(self.initial, "INITIAL_OBSERVATION_MAX_BYTES", 1024):
            for channel in ("stdout", "stderr"):
                with self.subTest(channel=channel), self.assertRaises(self.initial.SetupError):
                    capture([sys.executable, "-c", "import sys; sys." + channel + ".write('x'*2048)"], 5)
        with self.assertRaises(self.initial.SetupError):
            capture([sys.executable, "-c", "import time; time.sleep(10)"], 0.05)

    def test_public_key_profile_rejects_wire_valid_but_ssh_keygen_invalid_rsa(self) -> None:
        """B10-8 requires real ssh-keygen validation, not just SSH field framing."""
        def field(data: bytes) -> bytes:
            return struct.pack(">I", len(data)) + data

        # The outer SSH wire framing and type match, but RSA needs an exponent
        # and modulus.  A one-byte second field is not a valid RSA public key.
        malformed = "ssh-rsa " + base64.b64encode(
            field(b"ssh-rsa") + field(b"\x01")
        ).decode("ascii") + " malformed-rsa\n"
        with tempfile.TemporaryDirectory(prefix="req10b-rsa-shape-") as directory:
            tool = Path(directory)
            pubdir = tool / "publickey"
            pubdir.mkdir()
            key = pubdir / "other.pub"
            key.write_text(malformed, encoding="ascii")
            probe = subprocess.run(
                ["ssh-keygen", "-l", "-f", str(key)],
                capture_output=True, text=True, check=False, timeout=10,
            )
            self.assertNotEqual(0, probe.returncode, "fixture must be rejected by OpenSSH")
            with self.assertRaises(self.initial.SetupError):
                self.initial._public_key_profile(tool)

    def test_public_key_profile_validates_every_line_in_mixed_pub_file(self) -> None:
        """A good first line must not launder a bad later key in one .pub file."""
        def field(data: bytes) -> bytes:
            return struct.pack(">I", len(data)) + data

        valid = "ssh-ed25519 " + base64.b64encode(
            field(b"ssh-ed25519") + field(b"v" * 32)
        ).decode("ascii") + " valid\n"
        malformed = "ssh-rsa " + base64.b64encode(
            field(b"ssh-rsa") + field(b"\x01")
        ).decode("ascii") + " malformed-rsa\n"
        with tempfile.TemporaryDirectory(prefix="req10b-mixed-shape-") as directory:
            tool = Path(directory)
            pubdir = tool / "publickey"
            pubdir.mkdir()
            key = pubdir / "other.pub"
            for order in ((valid, malformed), (malformed, valid)):
                with self.subTest(order=order[0].split()[0]):
                    key.write_text("".join(order), encoding="ascii")
                    with self.assertRaises(self.initial.SetupError):
                        self.initial._public_key_profile(tool)

    def test_public_key_profile_fails_closed_without_p1_key_validator(self) -> None:
        def field(data: bytes) -> bytes:
            return struct.pack(">I", len(data)) + data

        valid = "ssh-ed25519 " + base64.b64encode(
            field(b"ssh-ed25519") + field(b"v" * 32)
        ).decode("ascii") + " valid\n"
        with tempfile.TemporaryDirectory(prefix="req10b-no-keygen-") as directory:
            tool = Path(directory)
            pubdir = tool / "publickey"
            pubdir.mkdir()
            (pubdir / "laptop.pub").write_text(valid, encoding="ascii")
            with mock.patch.object(self.initial.shutil, "which", return_value=None):
                with self.assertRaises(self.initial.SetupError):
                    self.initial._public_key_profile(tool)

    def test_ib_argv_admits_only_the_three_typed_service_paths(self) -> None:
        required = (
            ["nv", "set", "system", "dns", "server", "192.0.2.53"],
            ["nv", "set", "system", "ntp", "server", "time.example.test"],
            ["nv", "set", "system", "date-time", "timezone", "Etc/UTC"],
        )
        for command in required:
            with self.subTest(command=command):
                self.assertEqual(command, self.initial.ib_command_argv(command))
        forbidden = (
            ["nv", "set", "system", "aaa", "user", "admin"],
            ["nv", "set", "system", "dns", "domain", "example.test"],
            ["nv", "set", "system", "dns", "search", "example.test"],
            ["nv", "unset", "system", "dns", "server", "192.0.2.53"],
        )
        for command in forbidden:
            with self.subTest(forbidden=command):
                with self.assertRaises(self.initial.SetupError):
                    self.initial.ib_command_argv(command)

    def test_force_is_a_deliberate_completion_only_cli_flag(self) -> None:
        with mock.patch.object(sys, "argv", ["initial-setup.py", "--force"]):
            args = self.initial.parse_args()
        self.assertTrue(args.force)

    def test_leaf_program_remains_single_file_and_stdlib_only(self) -> None:
        tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
        imports = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imports.update(
            node.module.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        )
        self.assertFalse({"yaml", "importlib", "openpyxl"} & imports)
        self.assertFalse(
            any(
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Attribute)
                and isinstance(node.value.value, ast.Name)
                and node.value.value.id == "sys"
                and node.value.attr == "path"
                and node.attr in {"append", "insert", "extend"}
                for node in ast.walk(tree)
            ),
            "the leaf script must not add local module lookup paths",
        )

    def test_bounded_global_subset_rejects_excessive_nesting(self) -> None:
        source = "\n".join("  " * level + f"level{level}:" for level in range(72)) + "\n"
        with self.assertRaises(self.initial.SetupError):
            self.initial._global_yaml_subset(source)

    def test_offline_key_installer_preserves_existing_identity_and_is_idempotent(self) -> None:
        def public(seed: int, comment: str) -> tuple[str, str]:
            def field(data: bytes) -> bytes:
                return struct.pack(">I", len(data)) + data
            blob = field(b"ssh-ed25519") + field(bytes([seed]) * 32)
            line = "ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + " " + comment
            digest = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).rstrip(b"=").decode("ascii")
            return line, digest

        first, first_fp = public(19, "new-comment")
        second, second_fp = public(20, "second")
        old_comment = first.rsplit(" ", 1)[0] + " old-comment\n"
        unrelated = "# retain owner note\n"
        entries = [
            {"name": "laptop.pub", "line": first, "fingerprint": first_fp},
            {"name": "mgmt-server.pub", "line": second, "fingerprint": second_fp},
        ]
        with tempfile.TemporaryDirectory(prefix="req10b-auth-offline-") as directory:
            home = Path(directory) / "home"
            home.mkdir()
            ssh = home / ".ssh"
            ssh.mkdir()
            authorized = ssh / "authorized_keys"
            authorized.write_text(unrelated + old_comment, encoding="ascii")
            command = self.initial.key_install_command(entries)
            self.assertEqual(command, self.initial.ib_command_argv(command))
            env = {"HOME": str(home), "PATH": os.environ["PATH"]}
            first_run = subprocess.run(command, env=env, capture_output=True, text=True,
                                       timeout=10, check=False)
            self.assertEqual(0, first_run.returncode, first_run.stderr)
            actual = authorized.read_text(encoding="ascii")
            self.assertIn(unrelated, actual)
            self.assertIn(old_comment, actual, "first key identity keeps its original comment")
            self.assertNotIn(first, actual, "changed comment must not append a duplicate identity")
            self.assertIn(second, actual)
            self.assertEqual(0o700, ssh.stat().st_mode & 0o777)
            self.assertEqual(0o600, authorized.stat().st_mode & 0o777)
            identity = (authorized.stat().st_ino, authorized.read_bytes())
            second_run = subprocess.run(command, env=env, capture_output=True, text=True,
                                        timeout=10, check=False)
            self.assertEqual(0, second_run.returncode, second_run.stderr)
            self.assertEqual(identity, (authorized.stat().st_ino, authorized.read_bytes()),
                             "repeat installation must not rewrite the key file")

    def test_offline_key_installer_rejects_symlinked_authorized_keys(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-auth-link-") as directory:
            home = Path(directory) / "home"
            home.mkdir()
            ssh = home / ".ssh"
            ssh.mkdir()
            foreign = Path(directory) / "foreign"
            foreign.write_text("OWNER\n", encoding="ascii")
            (ssh / "authorized_keys").symlink_to(foreign)
            blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + b"x" * 32
            line = "ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + " laptop"
            digest = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).rstrip(b"=").decode("ascii")
            command = self.initial.key_install_command(
                [{"name": "laptop.pub", "line": line, "fingerprint": digest}]
            )
            completed = subprocess.run(
                command, env={"HOME": str(home), "PATH": os.environ["PATH"]},
                capture_output=True, text=True, timeout=10, check=False,
            )
            self.assertNotEqual(0, completed.returncode)
            self.assertEqual("OWNER\n", foreign.read_text(encoding="ascii"))

    def test_force_fill_missing_accepts_independent_membership_literals(self) -> None:
        device = self.initial.Device(
            "EXAMPLE-IB01", "ib", "203.0.113.2", "203.0.113.2/24",
            "203.0.113.1", "", "", "",
        )
        # These are supplied readback facts, not output from desired_commands().
        cases = (
            ("no_eth0_yet", (), (), (), (), "nvos", True),
            ("extra_eth0_target_missing", ("198.51.100.2/24",), (),
             ("203.0.113.1",), (), "EXAMPLE-IB01", True),
            ("target_and_extra_eth0", ("198.51.100.2/24", "203.0.113.2/24"), (),
             ("203.0.113.1",), (), "EXAMPLE-IB01", False),
            ("target_and_extra_gateway", ("203.0.113.2/24",), (),
             ("198.51.100.1", "203.0.113.1"), (), "EXAMPLE-IB01", False),
            ("unrequested_eth1_is_not_an_obligation", ("203.0.113.2/24",),
             ("198.51.100.22/24",), ("203.0.113.1",),
             ("198.51.100.21",), "EXAMPLE-IB01", False),
            ("only_unrequested_eth1_does_not_supply_eth0", (),
             ("198.51.100.22/24",), (), ("198.51.100.21",), "EXAMPLE-IB01", True),
            ("empty_requested_gateway_can_be_filled", ("203.0.113.2/24",), (),
             (), (), "EXAMPLE-IB01", True),
            ("default_hostname_can_be_filled", ("203.0.113.2/24",), (),
             ("203.0.113.1",), (), "nvos", True),
        )
        for name, eth0, eth1, gateway0, gateway1, hostname, expected in cases:
            with self.subTest(case=name):
                state = self.initial.DeviceState(
                    eth0, eth1, gateway0, gateway1, hostname, "PUBLIC supplied readback",
                )
                self.assertIs(expected, self.initial.force_day0_needed(device, state))

        dual = self.initial.Device(
            "EXAMPLE-IB01", "ib", "203.0.113.2", "203.0.113.2/24",
            "203.0.113.1", "", "192.0.2.2/24", "192.0.2.1",
        )
        dual_cases = (
            ("requested_eth1_target_missing", ("198.51.100.22/24",), True),
            ("requested_eth1_membership", ("198.51.100.22/24", "192.0.2.2/24"), False),
        )
        for name, actual_eth1, expected in dual_cases:
            with self.subTest(case=name):
                state = self.initial.DeviceState(
                    ("203.0.113.2/24",), actual_eth1, ("203.0.113.1",),
                    ("192.0.2.1",), "EXAMPLE-IB01", "PUBLIC supplied readback",
                )
                self.assertIs(expected, self.initial.force_day0_needed(dual, state))

    def test_force_fill_missing_keeps_actual_hostname_and_gateway_conflicts(self) -> None:
        device = self.initial.Device(
            "EXAMPLE-IB01", "ib", "203.0.113.2", "203.0.113.2/24",
            "203.0.113.1", "", "192.0.2.2/24", "192.0.2.1",
        )
        cases = (
            ("wrong_eth0_gateway", ("198.51.100.1",), ("192.0.2.1",),
             "EXAMPLE-IB01", "eth0 gateway"),
            ("wrong_requested_eth1_gateway", ("203.0.113.1",), ("198.51.100.21",),
             "EXAMPLE-IB01", "eth1 gateway"),
            ("wrong_nondefault_hostname", ("203.0.113.1",), ("192.0.2.1",),
             "OTHER-IB01", "hostname"),
        )
        for name, gateway0, gateway1, hostname, field in cases:
            with self.subTest(case=name):
                state = self.initial.DeviceState(
                    ("203.0.113.2/24",), ("192.0.2.2/24",),
                    gateway0, gateway1, hostname, "PUBLIC supplied readback",
                )
                with self.assertRaisesRegex(self.initial.SetupError, field):
                    self.initial.force_day0_needed(device, state)

    def test_force_does_not_qualify_unknown_empty_readback(self) -> None:
        for raw in ("", " \n\t", "PUBLIC login banner only\n"):
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(self.initial.SetupError, "UNKNOWN|verifiable"):
                    self.initial.parse_nvue_state(raw)

    def test_authorized_failure_summary_never_carries_a_credential_or_device_output(self) -> None:
        """A1: the report text added after a failed authorized IB operation.

        It is the product's own SetupError text: never an OSError text, never a
        credential (checked on the text as raised, before any whitespace is
        folded), and the product-written summary replaces a message that embeds
        device output.
        """
        summary = self.initial._authorized_failure_summary
        credential = "PUBLIC  spaced\tcredential"
        self.assertIsNone(
            summary(self.initial.SetupError("fixture " + credential), ("PUBLIC-OOB", credential)),
            "a credential must be withheld even when folding whitespace would hide it",
        )
        embedded = self.initial.SetupError("nested SSH failed, exit=1: PUBLIC-DEVICE-LINE")
        embedded.report_summary = "nested SSH failed, exit=1; device output withheld"
        self.assertEqual("nested SSH failed, exit=1; device output withheld",
                         summary(embedded, ("PUBLIC-OOB",)))
        self.assertIsNone(summary(OSError(5, "PUBLIC-IO-TEXT"), ("PUBLIC-OOB",)))
        self.assertEqual("PUBLIC product text",
                         summary(self.initial.SetupError("PUBLIC\nproduct\x1b text"), ("PUBLIC-OOB",)))



if __name__ == "__main__":
    unittest.main()
