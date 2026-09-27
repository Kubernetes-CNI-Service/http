"""Direct, implementation-independent entry contracts for REQ-10-B.

These are deliberately RED until the service/key implementation exists.  The
expected command vectors and cache version come from requirements 10B, not
from a generated output of the script under test.
"""

from __future__ import annotations

import ast
import base64
import hashlib
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


if __name__ == "__main__":
    unittest.main()
