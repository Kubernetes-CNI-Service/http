#!/usr/bin/env python3
"""REQ-16 direct contracts, specified independently of the new shared helper."""

from __future__ import annotations

import base64
from contextlib import redirect_stderr, redirect_stdout
import fcntl
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = ROOT / "tools/ssh_key_preparation.py"
SETUP_PATH = ROOT / "DAY0-Prepare/01-a-setup.py"
LOAD_PATH = ROOT / "DAY0-Prepare/11-load.py"


def public_line(algorithm: str, seed: int, comment: str = "fixture") -> bytes:
    """Make a valid OpenSSH public line without generating or reading a private key."""
    def field(value: bytes) -> bytes:
        return struct.pack(">I", len(value)) + value

    if algorithm == "ssh-ed25519":
        blob = field(b"ssh-ed25519") + field(bytes([seed]) * 32)
    elif algorithm == "ssh-rsa":
        blob = (
            field(b"ssh-rsa") + field(b"\x01\x00\x01")
            + field(b"\x00\x80" + bytes([seed]) * 255)
        )
    else:
        raise ValueError(algorithm)
    return algorithm.encode() + b" " + base64.b64encode(blob) + b" " + comment.encode() + b"\n"


def fingerprint(line: bytes) -> str:
    blob = base64.b64decode(line.split()[1], validate=True)
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).rstrip(b"=").decode()


def extended_public_line(algorithm: bytes, *fields: bytes) -> bytes:
    """Independent SSH-wire fixture for existing static ECDSA/SK support."""
    values = (algorithm, *fields)
    blob = b"".join(struct.pack(">I", len(value)) + value for value in values)
    return algorithm + b" " + base64.b64encode(blob) + b" fixture\n"


def helper_module():
    if not HELPER_PATH.is_file():
        raise AssertionError("REQ-16 shared helper tools/ssh_key_preparation.py is absent")
    spec = importlib.util.spec_from_file_location("r16_ssh_key_preparation", HELPER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def setup_module(name: str):
    spec = importlib.util.spec_from_file_location(name, SETUP_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def load_module(name: str):
    spec = importlib.util.spec_from_file_location(name, LOAD_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class ConfigOnlyLaptopLoadContract(unittest.TestCase):
    def test_linux_service_helpers_reject_unknown_role_before_runtime_access(self):
        """Internal service helpers cannot reinterpret missing role as server."""
        loader = load_module("r16_linux_service_helper_role")
        for helper in (loader.active_managed_services, loader.quiesce_services):
            with self.subTest(helper=helper.__name__), \
                 mock.patch.object(loader, "runtime_os", return_value="Linux"), \
                 mock.patch.object(loader, "service_runtime_backend") as backend, \
                 mock.patch.object(loader, "stop_native_ztp_monitors") as stop, \
                 mock.patch.object(loader, "_run_subprocess") as child, \
                 mock.patch.object(loader.shutil, "which", return_value=None):
                backend.return_value = SimpleNamespace(name="systemd")
                with self.assertRaisesRegex(loader.LoadError, "role|角色|身份"):
                    helper(host_role=None)
                backend.assert_not_called()
                stop.assert_not_called()
                child.assert_not_called()

    def test_linux_missing_role_in_minimal_parser_namespace_reports_role_before_write(self):
        """A sparse embedding must fail with the role gate, not AttributeError."""
        loader = load_module("r16_linux_sparse_namespace")
        with tempfile.TemporaryDirectory(prefix="r16-linux-sparse-role-") as temporary:
            root = Path(temporary).resolve()
            laptop = root / "laptop.pub"
            management = root / "mgmt-server.pub"
            laptop.write_bytes(public_line("ssh-ed25519", 131, "synthetic-laptop"))
            management.write_bytes(b"")
            before = {
                path: (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
                for path in (laptop, management)
            }
            error = io.StringIO()
            with mock.patch.object(loader, "parse_args", return_value=SimpleNamespace()), \
                 mock.patch.object(loader, "runtime_os", return_value="Linux"), \
                 mock.patch.object(loader, "acquire_deployment_lock") as lock, \
                 mock.patch.object(loader, "prepare_pubkeys") as keys, \
                 redirect_stderr(error):
                result = loader.main([])
            self.assertEqual(1, result)
            self.assertIn("requires explicit --host-role", error.getvalue())
            self.assertNotIn("AttributeError", error.getvalue())
            lock.assert_not_called()
            keys.assert_not_called()
            for path in (laptop, management):
                self.assertEqual(before[path], (
                    path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns,
                ))

    @unittest.skipUnless(Path("/usr/bin/ssh-keygen").is_file(),
                         "requires pinned synthetic Ed25519 key generator")
    def test_ambiguous_linux_input_gate_stops_before_project_pub_write(self):
        """Linux by itself is not authority to inject a management key.

        This directly exercises the real input/key gate, with no host-role
        declaration and an otherwise valid synthetic server HOME pair. A role
        error must precede any project public-key mutation; a generic parsing
        failure is not an acceptable substitute for that decision.
        """
        loader = load_module("r16_ambiguous_linux_direct")
        with tempfile.TemporaryDirectory(prefix="r16-ambiguous-linux-direct-") as temporary:
            root = Path(temporary).resolve()
            ssh = root / "synthetic-home/.ssh"
            ssh.mkdir(parents=True, mode=0o700)
            subprocess.run(
                ["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                 "-C", "synthetic@ambiguous", "-f", str(ssh / "id_ed25519")],
                check=True, capture_output=True,
            )
            project = root / "project"
            project.mkdir(mode=0o700)
            for name in (
                "01-global.yaml", "02-devices_config.csv",
                "02-dhcp-subnet_config.csv", "p2p.xlsx",
            ):
                (project / name).write_bytes(name.encode("ascii") + b"\n")
            laptop = project / "laptop.pub"
            management = project / "mgmt-server.pub"
            laptop.write_bytes(public_line("ssh-ed25519", 111, "synthetic-laptop"))
            management.write_bytes(b"")
            (project / ".management-pubkeys").write_bytes(b"mgmt-server.pub\n")
            before = {
                path: (path.read_bytes(), path.stat().st_dev, path.stat().st_ino,
                       path.stat().st_mtime_ns)
                for path in (laptop, management)
            }
            args = SimpleNamespace(
                mini=None, no_upgrade=True, p2p_file=None,
                deployment_scope="all", switch_scope="all",
                ssh_dir=ssh, dry_run=False,
            )
            settings = SimpleNamespace(schema_version=1)
            with mock.patch.object(loader, "_load_global_document", return_value={}), \
                 mock.patch.object(loader, "load_global", return_value=settings), \
                 mock.patch.object(loader, "find_placeholder_password_sections", return_value=()), \
                 mock.patch.object(loader, "apply_subnet_service_ips", return_value=settings), \
                 mock.patch.object(loader, "load_device_types", return_value=frozenset()), \
                 mock.patch.object(loader, "select_p2p", return_value=project / "p2p.xlsx"), \
                 mock.patch.object(loader, "validate_subnet_file"), \
                 mock.patch.object(loader, "project_air_topology_policy", return_value=None), \
                 mock.patch.object(loader, "project_mini_air_devices", return_value=(None, None)), \
                 mock.patch.object(loader, "validate_shared_artifact_receipts"), \
                 mock.patch.object(loader, "runtime_os", return_value="Linux"), \
                 redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(loader.LoadError, "role|角色|身份"):
                    loader.validate_inputs(
                        project, args, allow_management_key_generation=False,
                    )
            for path in (laptop, management):
                self.assertEqual(before[path], (
                    path.read_bytes(), path.stat().st_dev, path.stat().st_ino,
                    path.stat().st_mtime_ns,
                ))

    def test_macos_input_prevalidation_preserves_two_empty_template_keys_for_setup(self):
        """The real input/key gate plans empty template keys before laptop setup.

        Unrelated customer inputs are synthetic and independently validated by
        their own suites; the REQ-16 key selector itself is not mocked here.
        """
        loader = load_module("r16_macos_empty_input_gate")
        with tempfile.TemporaryDirectory(prefix="r16-macos-empty-input-") as temporary:
            root = Path(temporary).resolve()
            ssh = root / "laptop-home/.ssh"
            ssh.mkdir(parents=True, mode=0o700)
            # A new laptop need not have a HOME key yet. Only the later setup
            # step may generate one; load's input preflight remains read-only.
            project = root / "project"
            project.mkdir(mode=0o700)
            for name in (
                "01-global.yaml", "02-devices_config.csv",
                "02-dhcp-subnet_config.csv", "p2p.xlsx",
            ):
                (project / name).write_bytes(name.encode("ascii") + b"\n")
            laptop = project / "laptop.pub"
            management = project / "mgmt-server.pub"
            laptop.write_bytes(b"")
            management.write_bytes(b"")
            (project / ".management-pubkeys").write_bytes(b"mgmt-server.pub\n")
            before = {
                path: (path.stat().st_dev, path.stat().st_ino, path.stat().st_mtime_ns)
                for path in (laptop, management)
            }
            settings = SimpleNamespace(schema_version=1)
            args = SimpleNamespace(
                mini=None, no_upgrade=True, p2p_file=None,
                deployment_scope="all", switch_scope="all",
                ssh_dir=ssh, dry_run=False,
            )
            with mock.patch.object(loader, "_load_global_document", return_value={}), \
                 mock.patch.object(loader, "load_global", return_value=settings), \
                 mock.patch.object(loader, "find_placeholder_password_sections", return_value=()), \
                 mock.patch.object(loader, "apply_subnet_service_ips", return_value=settings), \
                 mock.patch.object(loader, "load_device_types", return_value=frozenset()), \
                 mock.patch.object(loader, "select_p2p", return_value=project / "p2p.xlsx"), \
                 mock.patch.object(loader, "validate_subnet_file"), \
                 mock.patch.object(loader, "project_air_topology_policy", return_value=None), \
                 mock.patch.object(loader, "project_mini_air_devices", return_value=(None, None)), \
                 mock.patch.object(loader, "validate_shared_artifact_receipts"), \
                 mock.patch.object(loader, "supports_local_ztp_services", return_value=False), \
                 mock.patch.object(loader, "ensure_management_key", side_effect=AssertionError("not a laptop key")), \
                 redirect_stdout(io.StringIO()):
                inputs, images = loader.validate_inputs(
                    project, args, allow_management_key_generation=False,
                    host_role="workstation",
                )

            self.assertEqual({}, images)
            self.assertEqual((laptop, management), inputs.pubkeys)
            for path in (laptop, management):
                self.assertEqual(b"", path.read_bytes())
                self.assertEqual(before[path], (
                    path.stat().st_dev, path.stat().st_ino, path.stat().st_mtime_ns,
                ))
            self.assertFalse((ssh / "id_ed25519.pub").exists())
            self.assertFalse((ssh / "id_ed25519").exists())

    def test_empty_project_pub_placeholders_reach_setup_without_preflight_write(self):
        """Config-only preflight plans the named empty laptop key for setup."""
        loader = load_module("r16_config_only_empty_laptop")
        with tempfile.TemporaryDirectory(prefix="r16-config-empty-") as temporary:
            root = Path(temporary).resolve()
            ssh = root / "laptop-home/.ssh"
            ssh.mkdir(parents=True, mode=0o700)
            public = public_line("ssh-ed25519", 83, "laptop")
            (ssh / "id_ed25519.pub").write_bytes(public)
            project = root / "project"
            project.mkdir(mode=0o700)
            laptop = project / "laptop.pub"
            management = project / "mgmt-server.pub"
            laptop.write_bytes(b"")
            management.write_bytes(b"")
            laptop_before = laptop.stat()
            management_before = management.stat()

            for dry_run in (True, False):
                with redirect_stdout(io.StringIO()):
                    selected = loader.prepare_pubkeys(
                        project, ssh_dir=ssh, dry_run=dry_run,
                        inject_management_key=False,
                        allow_management_key_generation=False,
                    )
                self.assertIn(laptop, selected)
                self.assertIn(management, selected)
                self.assertEqual(b"", laptop.read_bytes())
                self.assertEqual(b"", management.read_bytes())
                self.assertEqual(
                    (laptop_before.st_dev, laptop_before.st_ino, laptop_before.st_mtime_ns),
                    (laptop.stat().st_dev, laptop.stat().st_ino, laptop.stat().st_mtime_ns),
                )
                self.assertEqual(
                    (management_before.st_dev, management_before.st_ino, management_before.st_mtime_ns),
                    (management.stat().st_dev, management.stat().st_ino, management.stat().st_mtime_ns),
                )
            self.assertEqual(public, (ssh / "id_ed25519.pub").read_bytes())
            self.assertFalse((ssh / "id_ed25519").exists())

    def test_malformed_nonempty_project_laptop_key_is_not_treated_as_empty(self):
        loader = load_module("r16_config_only_malformed_laptop")
        with tempfile.TemporaryDirectory(prefix="r16-config-malformed-") as temporary:
            root = Path(temporary).resolve()
            ssh = root / "laptop-home/.ssh"
            ssh.mkdir(parents=True, mode=0o700)
            (ssh / "id_ed25519.pub").write_bytes(public_line("ssh-ed25519", 84))
            project = root / "project"
            project.mkdir(mode=0o700)
            laptop = project / "laptop.pub"
            malformed = b"not-an-openssh-public-key\n"
            laptop.write_bytes(malformed)
            (project / "mgmt-server.pub").write_bytes(b"")

            with self.assertRaises(loader.LoadError):
                loader.prepare_pubkeys(
                    project, ssh_dir=ssh, dry_run=False,
                    inject_management_key=False,
                    allow_management_key_generation=False,
                )
            self.assertEqual(malformed, laptop.read_bytes())
            self.assertFalse((ssh / "id_ed25519").exists())


class ExistingProjectKeyNoTouchContract(unittest.TestCase):
    """An existing valid but foreign project key is not silently rotated."""

    def test_standalone_setup_refuses_foreign_real_laptop_key_without_write(self):
        setup = setup_module("r16_no_touch_laptop_setup")
        with tempfile.TemporaryDirectory(prefix="r16-no-touch-laptop-") as temporary:
            root = Path(temporary).resolve()
            home = root / "laptop-home"
            ssh = home / ".ssh"
            ssh.mkdir(parents=True, mode=0o700)
            selected = public_line("ssh-ed25519", 101, "current-laptop")
            foreign = public_line("ssh-ed25519", 102, "other-laptop")
            (ssh / "id_ed25519.pub").write_bytes(selected)
            project = root / "project"
            project.mkdir(mode=0o700)
            target = project / "laptop.pub"
            target.write_bytes(foreign)
            before = target.stat()
            narration = io.StringIO()
            with mock.patch.dict(os.environ, {"HOME": str(home)}), \
                 mock.patch.object(setup, "_DRY_RUN", False), \
                 redirect_stdout(narration):
                with self.assertRaises(SystemExit) as refusal:
                    setup._prepare_laptop_public_key(project)
            self.assertEqual(1, refusal.exception.code)
            self.assertEqual(foreign, target.read_bytes())
            after = target.stat()
            self.assertEqual((before.st_dev, before.st_ino, before.st_size),
                             (after.st_dev, after.st_ino, after.st_size))
            self.assertIn("laptop.pub", narration.getvalue())
            self.assertIn("mismatch", narration.getvalue().casefold())
            self.assertFalse((ssh / "id_ed25519").exists())

    @unittest.skipUnless(Path("/usr/bin/ssh-keygen").is_file(),
                         "requires pinned synthetic Ed25519 key generator")
    def test_server_load_refuses_foreign_real_management_key_without_write(self):
        loader = load_module("r16_no_touch_server_load")
        with tempfile.TemporaryDirectory(prefix="r16-no-touch-server-") as temporary:
            root = Path(temporary).resolve()
            ssh = root / "server-home/.ssh"
            ssh.mkdir(parents=True, mode=0o700)
            subprocess.run(
                ["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                 "-C", "root@management-server", "-f", str(ssh / "id_ed25519")],
                check=True, capture_output=True,
            )
            selected = (ssh / "id_ed25519.pub").read_bytes()
            laptop = public_line("ssh-ed25519", 103, "laptop")
            foreign = public_line("ssh-ed25519", 104, "other-server")
            self.assertNotEqual(selected, foreign)
            project = root / "project"
            project.mkdir(mode=0o700)
            marker = project / ".management-pubkeys"
            marker.write_bytes(b"mgmt-server.pub\n")
            marker.chmod(0o644)
            laptop_target = project / "laptop.pub"
            laptop_target.write_bytes(laptop)
            laptop_target.chmod(0o644)
            target = project / "mgmt-server.pub"
            target.write_bytes(foreign)
            target.chmod(0o644)
            before = {path: path.stat() for path in (laptop_target, target)}
            narration = io.StringIO()
            with redirect_stdout(narration):
                with self.assertRaises(loader.LoadError):
                    loader.prepare_pubkeys(
                        project, ssh_dir=ssh, dry_run=False,
                        inject_management_key=True,
                        allow_management_key_generation=False,
                    )
            for path, contents in ((laptop_target, laptop), (target, foreign)):
                after = path.stat()
                self.assertEqual(contents, path.read_bytes())
                self.assertEqual((before[path].st_dev, before[path].st_ino, before[path].st_size),
                                 (after.st_dev, after.st_ino, after.st_size))
            self.assertIn("mgmt-server.pub", narration.getvalue())
            self.assertIn("mismatch", narration.getvalue().casefold())


class SharedSshKeyPreparationContract(unittest.TestCase):
    def test_existing_static_public_types_share_one_identity_parser(self):
        helper = helper_module()
        cases = (
            extended_public_line(b"ecdsa-sha2-nistp256", b"nistp256", b"\x04" + b"\x11" * 64),
            extended_public_line(b"sk-ssh-ed25519@openssh.com", b"\x22" * 32, b"ssh:fixture"),
            extended_public_line(b"sk-ecdsa-sha2-nistp256@openssh.com", b"nistp256", b"\x04" + b"\x33" * 64, b"ssh:fixture"),
        )
        for line in cases:
            with self.subTest(key_type=line.split(b" ", 1)[0]):
                identity = helper.public_key_identity_bytes(line)
                self.assertEqual(line.split(b" ", 1)[0], identity[0])
                self.assertEqual(base64.b64decode(line.split(b" ", 2)[1]), identity[1])
                self.assertEqual(identity, helper.public_key_identity_bytes(line.replace(b"fixture\n", b"second\n")))
                with self.assertRaises(helper.SshKeyPreparationError):
                    helper.public_key_identity_bytes(line + b"extra\n")

    def test_ed25519_priority_then_rsa_public_only_fallback(self):
        with tempfile.TemporaryDirectory(prefix="r16-choice-") as temporary:
            ssh_dir = Path(temporary) / ".ssh"
            ssh_dir.mkdir(mode=0o700)
            ed = ssh_dir / "id_ed25519.pub"
            rsa = ssh_dir / "id_rsa.pub"
            ed.write_bytes(public_line("ssh-ed25519", 17))
            rsa.write_bytes(public_line("ssh-rsa", 19))
            helper = helper_module()
            self.assertEqual(ed, helper.select_public_key(ssh_dir))
            ed.unlink()
            # No id_rsa private file exists: public selection is not possession proof.
            self.assertFalse((ssh_dir / "id_rsa").exists())
            self.assertEqual(rsa, helper.select_public_key(ssh_dir))

    def test_identity_ignores_comment_but_not_key_type_or_blob(self):
        with tempfile.TemporaryDirectory(prefix="r16-identity-") as temporary:
            root = Path(temporary)
            first = root / "first.pub"
            comment_only = root / "comment.pub"
            other_blob = root / "other.pub"
            other_type = root / "rsa.pub"
            first.write_bytes(public_line("ssh-ed25519", 21, "alice"))
            comment_only.write_bytes(public_line("ssh-ed25519", 21, "另一台笔记本"))
            other_blob.write_bytes(public_line("ssh-ed25519", 22, "alice"))
            other_type.write_bytes(public_line("ssh-rsa", 21, "alice"))
            helper = helper_module()
            self.assertEqual(helper.public_key_identity(first), helper.public_key_identity(comment_only))
            self.assertNotEqual(helper.public_key_identity(first), helper.public_key_identity(other_blob))
            self.assertNotEqual(helper.public_key_identity(first), helper.public_key_identity(other_type))

    def test_generation_conflict_is_fail_closed_and_comment_is_literal_allowlist(self):
        with tempfile.TemporaryDirectory(prefix="r16-generate-") as temporary:
            root = Path(temporary)
            ssh_dir = root / ".ssh"
            ssh_dir.mkdir(mode=0o700)
            private = ssh_dir / "id_ed25519"
            private.write_bytes(b"private-sentinel-do-not-read-or-overwrite")
            private.chmod(0o600)
            before = private.stat()
            helper = helper_module()
            with self.assertRaises(Exception):
                helper.ensure_public_key(ssh_dir, comment="operator@laptop")
            after = private.stat()
            self.assertEqual((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns),
                             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns))
            self.assertFalse((ssh_dir / "id_ed25519.pub").exists())

            empty = root / "empty-ssh"
            empty.mkdir(mode=0o700)
            with self.assertRaises(Exception):
                helper.ensure_public_key(empty, comment="dynamic@hostname")
            self.assertEqual([], list(empty.iterdir()))

            generated = helper.ensure_public_key(empty, comment="operator@laptop")
            self.assertEqual(empty / "id_ed25519.pub", generated)
            self.assertTrue((empty / "id_ed25519").is_file())
            self.assertEqual(0o600, stat.S_IMODE((empty / "id_ed25519").stat().st_mode))
            self.assertEqual(0o644, stat.S_IMODE(generated.stat().st_mode))
            self.assertEqual(b"ssh-ed25519", generated.read_bytes().split()[0])
            self.assertTrue(generated.read_bytes().rstrip().endswith(b"operator@laptop"))

            rsa_only = root / "rsa-private-only"
            rsa_only.mkdir(mode=0o700)
            rsa_private = rsa_only / "id_rsa"
            rsa_private.write_bytes(b"unpaired-rsa-private-sentinel")
            rsa_private.chmod(0o600)
            rsa_before = rsa_private.stat()
            self.assertEqual(rsa_only / "id_ed25519.pub",
                             helper.ensure_public_key(rsa_only, comment="operator@laptop"))
            rsa_after = rsa_private.stat()
            self.assertEqual((rsa_before.st_dev, rsa_before.st_ino, rsa_before.st_size),
                             (rsa_after.st_dev, rsa_after.st_ino, rsa_after.st_size))

    def test_mismatch_publication_is_atomic_no_follow_and_reports_both_fingerprints(self):
        with tempfile.TemporaryDirectory(prefix="r16-publish-") as temporary:
            root = Path(temporary)
            project = root / "project"
            project.mkdir(mode=0o700)
            source = root / "source.pub"
            source.write_bytes(public_line("ssh-ed25519", 31))
            destination = project / "laptop.pub"
            old = public_line("ssh-ed25519", 32)
            destination.write_bytes(old)
            before = destination.stat()
            helper = helper_module()
            source_stat = source.stat()
            with self.assertRaises(helper.SshKeyPreparationError):
                helper.prepare_project_public_key(
                    project, "laptop.pub", source,
                    expected_source_identity=(source_stat.st_dev, source_stat.st_ino + 1),
                )
            self.assertEqual(old, destination.read_bytes())
            self.assertEqual(before.st_ino, destination.stat().st_ino)
            output = io.StringIO()
            with redirect_stdout(output):
                helper.prepare_project_public_key(
                    project, "laptop.pub", source, on_mismatch="replace",
                )
            after = destination.stat()
            self.assertEqual(source.read_bytes(), destination.read_bytes())
            self.assertNotEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
            self.assertEqual(0o644, stat.S_IMODE(after.st_mode))
            self.assertIn(str(source), output.getvalue())
            self.assertIn(fingerprint(old), output.getvalue())
            self.assertIn(fingerprint(source.read_bytes()), output.getvalue())

            alternate_comment = root / "alternate-comment.pub"
            alternate_comment.write_bytes(public_line("ssh-ed25519", 31, "different-comment"))
            matching = destination.stat()
            helper.prepare_project_public_key(project, "laptop.pub", alternate_comment)
            self.assertEqual((matching.st_dev, matching.st_ino),
                             (destination.stat().st_dev, destination.stat().st_ino))
            self.assertEqual(source.read_bytes(), destination.read_bytes())

            outside = root / "outside.pub"
            outside.write_bytes(old)
            symlink = project / "mgmt-server.pub"
            symlink.symlink_to(outside)
            with self.assertRaises(Exception):
                helper.prepare_project_public_key(project, "mgmt-server.pub", source)
            self.assertEqual(old, outside.read_bytes())
            self.assertTrue(symlink.is_symlink())

            source_link = root / "source-link.pub"
            source_link.symlink_to(source)
            with self.assertRaises(Exception):
                helper.prepare_project_public_key(project, "laptop.pub", source_link)
            self.assertEqual(source.read_bytes(), destination.read_bytes())

            with self.assertRaises(Exception):
                helper.prepare_project_public_key(project, "../outside.pub", source)
            self.assertEqual(old, outside.read_bytes())

    def test_explicit_rotation_rejects_target_rebind_without_touching_outside(self):
        """The retained explicit rotation primitive still detects a leaf race."""
        helper = helper_module()
        with tempfile.TemporaryDirectory(prefix="r16-rotate-rebind-") as temporary:
            root = Path(temporary).resolve()
            project = root / "project"
            project.mkdir(mode=0o700)
            source = root / "source.pub"
            source.write_bytes(public_line("ssh-ed25519", 111, "new"))
            old = public_line("ssh-ed25519", 112, "old")
            target = project / "laptop.pub"
            target.write_bytes(old)
            outside = root / "outside.pub"
            outside.write_bytes(old)
            original_read = helper._read_project_leaf
            calls = 0

            def rebind_before_second_read(directory_fd, name):
                nonlocal calls
                if name == "laptop.pub":
                    calls += 1
                    if calls == 2:
                        target.rename(project / "held-original.pub")
                        target.symlink_to(outside)
                return original_read(directory_fd, name)

            with mock.patch.object(helper, "_read_project_leaf", side_effect=rebind_before_second_read):
                with self.assertRaises(helper.SshKeyPreparationError):
                    helper.prepare_project_public_key(
                        project, "laptop.pub", source, on_mismatch="replace",
                    )
            self.assertEqual(2, calls)
            self.assertTrue(target.is_symlink())
            self.assertEqual(old, outside.read_bytes())
            self.assertEqual(old, (project / "held-original.pub").read_bytes())
            self.assertEqual([], list(project.glob(".laptop.pub.*.tmp")))

    def test_empty_placeholder_fill_on_same_inode_is_never_overwritten(self):
        """A real key arriving in the old leaf before publish wins the race."""
        helper = helper_module()
        with tempfile.TemporaryDirectory(prefix="r16-same-inode-fill-") as temporary:
            root = Path(temporary).resolve()
            project = root / "project"
            project.mkdir(mode=0o700)
            source = root / "source.pub"
            source.write_bytes(public_line("ssh-ed25519", 121, "generated"))
            injected = public_line("ssh-ed25519", 122, "owner-arrived")
            target = project / "laptop.pub"
            target.write_bytes(b"")
            original_identity = target.stat().st_dev, target.stat().st_ino
            original_read = helper._read_project_leaf
            calls = 0

            def fill_before_second_read(directory_fd, name):
                nonlocal calls
                if name == "laptop.pub":
                    calls += 1
                    if calls == 2:
                        fd = os.open(target, os.O_WRONLY | os.O_NOFOLLOW)
                        try:
                            os.ftruncate(fd, 0)
                            self.assertEqual(len(injected), os.write(fd, injected))
                            os.fsync(fd)
                        finally:
                            os.close(fd)
                        self.assertEqual(
                            original_identity,
                            (target.stat().st_dev, target.stat().st_ino),
                        )
                return original_read(directory_fd, name)

            narration = io.StringIO()
            with mock.patch.object(
                helper, "_read_project_leaf", side_effect=fill_before_second_read,
            ), redirect_stdout(narration):
                with self.assertRaises(helper.SshKeyPreparationError):
                    helper.prepare_project_public_key(project, "laptop.pub", source)
            self.assertEqual(2, calls)
            self.assertEqual(injected, target.read_bytes())
            self.assertEqual(
                original_identity, (target.stat().st_dev, target.stat().st_ino),
            )
            self.assertEqual([], list(project.glob(".laptop.pub.*.tmp")))
            self.assertNotIn("[CHANGE]", narration.getvalue())

    @unittest.skipUnless(
        os.name == "posix" and Path("/usr/bin/ssh-keygen").is_file(),
        "requires the pinned POSIX /usr/bin/ssh-keygen -lf external oracle",
    )
    def test_reported_sha256_matches_ssh_keygen_lf_external_oracle(self):
        def oracle(path: Path) -> str:
            result = subprocess.run(
                ["/usr/bin/ssh-keygen", "-lf", str(path)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            fields = result.stdout.strip().split()
            self.assertGreaterEqual(len(fields), 2, result.stdout)
            self.assertTrue(fields[1].startswith("SHA256:"), result.stdout)
            return fields[1]

        with tempfile.TemporaryDirectory(prefix="r16-fingerprint-oracle-") as temporary:
            root = Path(temporary)
            project = root / "project"
            project.mkdir(mode=0o700)
            source = root / "source.pub"
            source.write_bytes(public_line("ssh-ed25519", 71, "new"))
            destination = project / "laptop.pub"
            destination.write_bytes(public_line("ssh-ed25519", 72, "old"))
            # Both expectations come from the pinned external OpenSSH binary,
            # not this test's fingerprint recipe or the helper under test.
            old_expected, new_expected = oracle(destination), oracle(source)
            self.assertNotEqual(old_expected, new_expected)
            helper = helper_module()
            output = io.StringIO()
            with redirect_stdout(output):
                helper.prepare_project_public_key(
                    project, "laptop.pub", source, on_mismatch="replace",
                )
            self.assertIn(f"old={old_expected}", output.getvalue())
            self.assertIn(f"new={new_expected}", output.getvalue())


class DelegatedSetupPublicKeyContract(unittest.TestCase):
    """Direct setup key gate; every HOME, project, and lock is private."""

    def _invoke(self, setup, root: Path, project: Path, home: Path,
                *, delegated: bool, inherited_fd: bool) -> tuple[str, int]:
        class BeforeP2p(Exception):
            pass

        lock_path = root / ".deployment.lock"
        lock_path.touch(mode=0o600)
        parent_fd = child_fd = None
        if inherited_fd:
            parent_fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
            fcntl.flock(parent_fd, fcntl.LOCK_EX)
            child_fd = os.dup(parent_fd)
        environment = {"HOME": str(home)}
        if delegated:
            environment["HTTP_SETUP_KEY_MODE"] = "server-delegated"
        if child_fd is not None:
            environment["HTTP_DEPLOYMENT_LOCK_FD"] = str(child_fd)
        try:
            with mock.patch.dict(os.environ, environment), \
                 mock.patch("platform.system", return_value="Linux"), \
                 mock.patch.object(setup, "HTTP_BASE", str(root)), \
                 mock.patch.object(setup, "stop_native_ztp_monitors"), \
                 mock.patch.object(setup, "_initialize_project_from_template"), \
                 mock.patch.object(setup, "_select_p2p_source", side_effect=BeforeP2p) as p2p, \
                 mock.patch.dict(setup.deployment_lock.__globals__, {"assert_writer_allowed": lambda **_kw: None}), \
                 redirect_stdout(io.StringIO()):
                if child_fd is None:
                    os.environ.pop("HTTP_DEPLOYMENT_LOCK_FD", None)
                if not delegated:
                    os.environ.pop("HTTP_SETUP_KEY_MODE", None)
                try:
                    declared_role = "management-server" if delegated else "workstation"
                    result = setup.main(["-y", "--strict", "--confirm-project-switch",
                                         f"--host-role={declared_role}", str(project)])
                except BeforeP2p:
                    outcome = "before-p2p"
                except SystemExit as exc:
                    outcome = f"exit:{exc.code}"
                else:
                    outcome = f"return:{result}"
            return outcome, p2p.call_count
        finally:
            if child_fd is not None:
                try:
                    os.close(child_fd)
                except OSError:
                    pass  # A real child closes its own copy of the lock FD.
            if parent_fd is not None:
                fcntl.flock(parent_fd, fcntl.LOCK_UN)
                os.close(parent_fd)

    def _fixture(self, root: Path, *, laptop: bytes | None):
        # setup's log-root lock requires the real infra parent present in a
        # checkout; create it instead of mocking the lock out of the test.
        (root / "infra").mkdir()
        home = root / "server-home"
        (home / ".ssh").mkdir(parents=True, mode=0o700)
        server = public_line("ssh-ed25519", 82, "server")
        (home / ".ssh/id_ed25519.pub").write_bytes(server)
        project = root / "project"
        project.mkdir(mode=0o700)
        (project / "mgmt-server.pub").write_bytes(server)
        if laptop is not None:
            (project / "laptop.pub").write_bytes(laptop)
        return home, project, server

    def test_delegated_setup_preserves_real_laptop_without_reading_server_home(self):
        setup = setup_module("r16_direct_delegated_valid")
        with tempfile.TemporaryDirectory(prefix="r16-direct-delegated-") as temporary:
            root = Path(temporary).resolve()
            laptop_key = public_line("ssh-ed25519", 81, "laptop")
            home, project, server = self._fixture(root, laptop=laptop_key)
            target = project / "laptop.pub"
            before = target.stat()
            outcome, p2p_calls = self._invoke(
                setup, root, project, home, delegated=True, inherited_fd=True,
            )
            self.assertEqual("before-p2p", outcome)
            self.assertEqual(1, p2p_calls)
            self.assertEqual(laptop_key, target.read_bytes())
            self.assertEqual((before.st_dev, before.st_ino),
                             (target.stat().st_dev, target.stat().st_ino))
            self.assertEqual(server, (project / "mgmt-server.pub").read_bytes())
            self.assertFalse((home / ".ssh/id_ed25519").exists())

    def test_delegated_setup_rejects_invalid_laptop_before_p2p(self):
        setup = setup_module("r16_direct_delegated_invalid")
        cases = {
            "missing": None,
            "empty": b"",
            "malformed": b"ssh-ed25519 invalid!!!\n",
            "same-as-management": public_line("ssh-ed25519", 82, "server"),
        }
        for label, payload in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory(prefix=f"r16-{label}-") as temporary:
                root = Path(temporary).resolve()
                home, project, server = self._fixture(root, laptop=payload)
                target = project / "laptop.pub"
                before_ino = target.stat().st_ino if target.exists() else None
                outcome, p2p_calls = self._invoke(
                    setup, root, project, home, delegated=True, inherited_fd=True,
                )
                self.assertIn(outcome, ("exit:1", "return:1"))
                self.assertEqual(0, p2p_calls)
                self.assertEqual(payload, target.read_bytes() if target.exists() else None)
                self.assertEqual(before_ino, target.stat().st_ino if target.exists() else None)
                self.assertEqual(server, (project / "mgmt-server.pub").read_bytes())

    def test_delegated_mode_without_inherited_lock_fd_fails_before_key_write(self):
        setup = setup_module("r16_direct_delegated_no_fd")
        with tempfile.TemporaryDirectory(prefix="r16-delegated-no-fd-") as temporary:
            root = Path(temporary).resolve()
            laptop_key = public_line("ssh-ed25519", 81, "laptop")
            home, project, _server = self._fixture(root, laptop=laptop_key)
            target = project / "laptop.pub"
            before = target.stat()
            outcome, p2p_calls = self._invoke(
                setup, root, project, home, delegated=True, inherited_fd=False,
            )
            self.assertIn(outcome, ("exit:1", "return:1"))
            self.assertEqual(0, p2p_calls)
            self.assertEqual(laptop_key, target.read_bytes())
            self.assertEqual(before.st_ino, target.stat().st_ino)

    def test_standalone_setup_still_prepares_laptop_key_from_own_home(self):
        setup = setup_module("r16_direct_standalone")
        with tempfile.TemporaryDirectory(prefix="r16-standalone-") as temporary:
            root = Path(temporary).resolve()
            home, project, _server = self._fixture(root, laptop=b"")
            local_key = public_line("ssh-ed25519", 81, "laptop")
            (home / ".ssh/id_ed25519.pub").write_bytes(local_key)
            outcome, p2p_calls = self._invoke(
                setup, root, project, home, delegated=False, inherited_fd=False,
            )
            self.assertEqual("before-p2p", outcome)
            self.assertEqual(1, p2p_calls)
            self.assertEqual(local_key, (project / "laptop.pub").read_bytes())


if __name__ == "__main__":
    unittest.main()
