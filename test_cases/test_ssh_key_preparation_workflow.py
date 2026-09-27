#!/usr/bin/env python3
"""REQ-16 setup/load entrypoint contracts; no host key or project is touched."""

from __future__ import annotations

import argparse
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import fcntl
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases.test_ssh_key_preparation_contract import (
    extended_public_line, fingerprint, public_line,
)


ROOT = Path(__file__).resolve().parents[1]
SETUP_PATH = ROOT / "DAY0-Prepare/01-a-setup.py"
LOAD_PATH = ROOT / "DAY0-Prepare/11-load.py"


def load_script(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def project_with_marker(path: Path, laptop: bytes, management: bytes) -> Path:
    path.mkdir(mode=0o700)
    marker = path / ".management-pubkeys"
    marker.write_bytes(b"mgmt-server.pub\n")
    marker.chmod(0o644)
    for name, payload in (("laptop.pub", laptop), ("mgmt-server.pub", management)):
        leaf = path / name
        leaf.write_bytes(payload)
        leaf.chmod(0o644)
    return path


class SshKeyPreparationWorkflow(unittest.TestCase):
    def test_darwin_sparse_setup_namespace_defaults_workstation_before_transaction(self):
        """Older embedding Namespace objects remain safe on Darwin."""
        setup = load_script("r16_darwin_sparse_setup", SETUP_PATH)
        args = argparse.Namespace(
            project="synthetic", status=False, list_projects=False,
            dry_run=True, auto_yes=False, force=False, strict=False,
            confirm_project_switch=False, create=False,
        )
        with mock.patch("platform.system", return_value="Darwin"), \
             mock.patch.object(setup, "_parse_args", return_value=args), \
             mock.patch.object(setup, "deployment_lock", return_value=mock.MagicMock()), \
             mock.patch.object(setup, "_main_locked", return_value=0) as transaction:
            self.assertEqual(0, setup.main([]))
        self.assertEqual("workstation", args.host_role)
        transaction.assert_called_once_with(args)

    def test_linux_setup_create_without_role_stops_before_project_creation(self):
        """Direct setup has no authority to infer a Linux host role."""
        setup = load_script("r16_ambiguous_linux_create_setup", SETUP_PATH)
        with tempfile.TemporaryDirectory(prefix="r16-linux-create-role-") as temporary:
            root = Path(temporary).resolve()
            target = root / "new-project"
            output = io.StringIO()
            with mock.patch("platform.system", return_value="Linux"), \
                 mock.patch.object(setup, "HERE", str(root)), \
                 mock.patch.object(setup, "HTTP_BASE", str(root)), \
                 mock.patch.object(setup, "deployment_lock", return_value=mock.MagicMock()), \
                 mock.patch.object(setup, "_initialize_project_from_template") as template, \
                 mock.patch.object(setup, "_prepare_laptop_public_key") as key_writer, \
                 redirect_stdout(output):
                result = setup.main(["--create", str(target)])
            self.assertEqual(1, result)
            self.assertRegex(output.getvalue(), "role|角色|身份")
            self.assertFalse(target.exists())
            template.assert_not_called()
            key_writer.assert_not_called()

    def test_linux_workstation_setup_does_not_quiesce_server_monitors(self):
        """A declared workstation can prepare config without server actions."""
        setup = load_script("r16_linux_workstation_setup", SETUP_PATH)
        with tempfile.TemporaryDirectory(prefix="r16-workstation-monitor-") as temporary:
            root = Path(temporary).resolve()
            project = root / "project"
            project.mkdir(mode=0o700)
            with mock.patch("platform.system", return_value="Linux"), \
                 mock.patch.object(setup, "HERE", str(root)), \
                 mock.patch.object(setup, "HTTP_BASE", str(root)), \
                 mock.patch.object(setup, "deployment_lock", return_value=mock.MagicMock()), \
                 mock.patch.object(setup, "require_project_eligible"), \
                 mock.patch.object(setup, "stop_native_ztp_monitors") as stop, \
                 mock.patch.object(setup, "setup") as setup_transaction, \
                 redirect_stdout(io.StringIO()):
                result = setup.main(["--host-role=workstation", str(project)])
            self.assertEqual(0, result)
            stop.assert_not_called()
            setup_transaction.assert_called_once_with(str(project))

    @unittest.skipUnless(Path("/usr/bin/ssh-keygen").is_file(),
                         "requires pinned synthetic Ed25519 key generator")
    def test_ambiguous_linux_load_stops_before_key_write_or_delegated_setup(self):
        """Real Linux-shaped load→setup must not infer server role from OS.

        All inputs are private synthetic fixtures; unrelated generation and
        service stages are stopped before they can act. No role is declared.
        A remote HTTP root/listener makes service readiness false, but that
        fact alone is not used to call this host a laptop either.
        """
        loader = load_script("r16_ambiguous_linux_main_load", LOAD_PATH)
        setup = load_script("r16_ambiguous_linux_main_setup", SETUP_PATH)

        class StopAfterKeyBoundary(Exception):
            pass

        with tempfile.TemporaryDirectory(prefix="r16-ambiguous-linux-main-") as temporary:
            root = Path(temporary).resolve()
            (root / "infra").mkdir(mode=0o700)
            home = root / "synthetic-home"
            ssh = home / ".ssh"
            ssh.mkdir(parents=True, mode=0o700)
            subprocess.run(
                ["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                 "-C", "synthetic@ambiguous", "-f", str(ssh / "id_ed25519")],
                check=True, capture_output=True,
            )
            project = project_with_marker(
                root / "project", public_line("ssh-ed25519", 112, "laptop"), b"",
            )
            for name in (
                "01-global.yaml", "02-devices_config.csv",
                "02-dhcp-subnet_config.csv", "p2p.xlsx",
            ):
                (project / name).write_bytes(name.encode("ascii") + b"\n")
            laptop = project / "laptop.pub"
            management = project / "mgmt-server.pub"
            before = {
                path: (hashlib.sha256(path.read_bytes()).hexdigest(),
                       path.stat().st_dev, path.stat().st_ino,
                       path.stat().st_mtime_ns)
                for path in (laptop, management)
            }
            settings = SimpleNamespace(
                schema_version=1, http_root=Path("/remote-management-root"),
                http_listener_ips=("198.51.100.77",),
                http_address="198.51.100.77", http_enabled=True,
                dhcp_enabled=False,
            )
            reached: list[Path] = []
            child_modes: list[str | None] = []

            def run_real_setup(command, **kwargs):
                reached.append(Path(command[1]).resolve())
                child_env = kwargs.get("env") or {}
                child_modes.append(child_env.get("HTTP_SETUP_KEY_MODE"))
                with mock.patch.dict(os.environ, child_env, clear=True):
                    setup.main(command[2:])
                return subprocess.CompletedProcess(command, 0)

            lock_path = root / ".deployment.lock"
            lock_path.touch(mode=0o600)
            parent_fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
            fcntl.flock(parent_fd, fcntl.LOCK_EX)
            child_fd = os.dup(parent_fd)
            try:
                with ExitStack() as stack:
                    stack.enter_context(mock.patch.dict(os.environ, {"HOME": str(home)}))
                    stack.enter_context(mock.patch.object(loader, "runtime_os", return_value="Linux"))
                    stack.enter_context(mock.patch.object(
                        loader, "service_runtime_backend",
                        return_value=SimpleNamespace(name="systemd"),
                    ))
                    stack.enter_context(mock.patch.object(loader, "stop_native_ztp_monitors"))
                    stack.enter_context(mock.patch.object(loader, "acquire_deployment_lock", return_value=child_fd))
                    stack.enter_context(mock.patch.object(loader, "release_deployment_lock"))
                    stack.enter_context(mock.patch.object(loader, "resolve_project", return_value=project))
                    stack.enter_context(mock.patch.object(loader, "sync_marker_present", return_value=False))
                    stack.enter_context(mock.patch.object(loader, "initialize_from_template"))
                    stack.enter_context(mock.patch.object(loader, "_load_global_document", return_value={}))
                    stack.enter_context(mock.patch.object(loader, "load_global", return_value=settings))
                    stack.enter_context(mock.patch.object(loader, "find_placeholder_password_sections", return_value=()))
                    stack.enter_context(mock.patch.object(loader, "apply_subnet_service_ips", return_value=settings))
                    stack.enter_context(mock.patch.object(loader, "load_device_types", return_value=frozenset()))
                    stack.enter_context(mock.patch.object(loader, "select_p2p", return_value=project / "p2p.xlsx"))
                    stack.enter_context(mock.patch.object(loader, "validate_subnet_file"))
                    stack.enter_context(mock.patch.object(loader, "project_air_topology_policy", return_value=None))
                    stack.enter_context(mock.patch.object(loader, "project_mini_air_devices", return_value=(None, None)))
                    stack.enter_context(mock.patch.object(loader, "validate_shared_artifact_receipts"))
                    stack.enter_context(mock.patch.object(loader, "local_ipv4_addresses", return_value={"127.0.0.1"}))
                    stack.enter_context(mock.patch.object(loader, "active_project", return_value=None))
                    stack.enter_context(mock.patch.object(loader, "_run_subprocess", side_effect=run_real_setup))
                    stack.enter_context(mock.patch.object(setup, "HTTP_BASE", str(root)))
                    stack.enter_context(mock.patch.dict(
                        setup.deployment_lock.__globals__,
                        {"assert_writer_allowed": lambda **_kw: None},
                    ))
                    stack.enter_context(mock.patch.object(setup, "stop_native_ztp_monitors"))
                    stack.enter_context(mock.patch.object(setup, "_initialize_project_from_template"))
                    stack.enter_context(mock.patch.object(
                        setup, "_select_p2p_source", side_effect=StopAfterKeyBoundary,
                    ))
                    stack.enter_context(redirect_stdout(io.StringIO()))
                    stack.enter_context(redirect_stderr(io.StringIO()))
                    result = loader.main([
                        str(project), "--no-upgrade", "--skip-infra",
                        "--ssh-dir", str(ssh),
                    ])
            finally:
                try:
                    os.close(child_fd)
                except OSError:
                    pass  # real setup may close its inherited same-process copy.
                fcntl.flock(parent_fd, fcntl.LOCK_UN)
                os.close(parent_fd)

            self.assertEqual(1, result, "ambiguous Linux role must stop visibly")
            with self.subTest("no project public-key write"):
                for path in (laptop, management):
                    self.assertEqual(before[path], (
                        hashlib.sha256(path.read_bytes()).hexdigest(),
                        path.stat().st_dev, path.stat().st_ino,
                        path.stat().st_mtime_ns,
                    ))
            with self.subTest("no server-delegated setup child"):
                self.assertEqual([], reached)
                self.assertEqual([], child_modes)

    def test_true_server_internal_delegation_is_not_defined_by_ip_readiness(self):
        """A held-lock server-role call remains server-role if its IP is down.

        This calibrates an already trusted internal role boundary, not a new
        CLI/host-role carrier. The future role resolver must not use this
        service-readiness failure to select the laptop path.
        """
        loader = load_script("r16_down_ip_server_load", LOAD_PATH)
        setup = load_script("r16_down_ip_server_setup", SETUP_PATH)

        class StopAfterKeyBoundary(Exception):
            pass

        with tempfile.TemporaryDirectory(prefix="r16-down-ip-server-") as temporary:
            root = Path(temporary).resolve()
            (root / "infra").mkdir(mode=0o700)
            project = project_with_marker(
                root / "project", public_line("ssh-ed25519", 113, "laptop"),
                public_line("ssh-ed25519", 114, "server"),
            )
            before = {
                name: (project / name).read_bytes()
                for name in ("laptop.pub", "mgmt-server.pub")
            }
            settings = SimpleNamespace(
                http_root=Path("/remote-management-root"),
                http_listener_ips=("198.51.100.77",),
                http_address="198.51.100.77", http_enabled=True,
                dhcp_enabled=False,
            )
            with mock.patch.object(loader, "local_ipv4_addresses", return_value={"127.0.0.1"}), \
                 redirect_stdout(io.StringIO()):
                self.assertFalse(loader.validate_management_host(settings, dry_run=True))

            modes: list[str | None] = []

            def run_real_setup(command, **kwargs):
                child_env = kwargs.get("env") or {}
                modes.append(child_env.get("HTTP_SETUP_KEY_MODE"))
                with mock.patch.dict(os.environ, child_env, clear=True):
                    setup.main(command[2:])

            lock_path = root / ".deployment.lock"
            lock_path.touch(mode=0o600)
            parent_fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
            fcntl.flock(parent_fd, fcntl.LOCK_EX)
            child_fd = os.dup(parent_fd)
            try:
                with mock.patch.object(loader, "_run_subprocess", side_effect=run_real_setup), \
                     mock.patch("platform.system", return_value="Linux"), \
                     mock.patch.object(setup, "HTTP_BASE", str(root)), \
                     mock.patch.dict(
                         setup.deployment_lock.__globals__,
                         {"assert_writer_allowed": lambda **_kw: None},
                     ), \
                     mock.patch.object(setup, "stop_native_ztp_monitors"), \
                     mock.patch.object(setup, "_initialize_project_from_template"), \
                     mock.patch.object(setup, "_select_p2p_source", side_effect=StopAfterKeyBoundary), \
                     redirect_stdout(io.StringIO()):
                    with self.assertRaises(StopAfterKeyBoundary):
                        loader.run(
                            [sys.executable, str(SETUP_PATH), "-y",
                             "--confirm-project-switch", "--host-role=management-server",
                             str(project)],
                            inherited_lock_descriptor=child_fd,
                            setup_key_context=True,
                        )
            finally:
                try:
                    os.close(child_fd)
                except OSError:
                    pass  # real setup may close its inherited same-process copy.
                fcntl.flock(parent_fd, fcntl.LOCK_UN)
                os.close(parent_fd)
            self.assertEqual(["server-delegated"], modes)
            for name, payload in before.items():
                self.assertEqual(payload, (project / name).read_bytes())

    @unittest.skipUnless(Path("/usr/bin/ssh-keygen").is_file(),
                         "requires pinned synthetic Ed25519 key generator")
    def test_laptop_setup_then_server_load_rejects_foreign_real_management_key(self):
        """Two actual scripts cannot publish an unknown valid management identity."""
        setup = load_script("r16_no_touch_workflow_setup", SETUP_PATH)
        loader = load_script("r16_no_touch_workflow_load", LOAD_PATH)
        with tempfile.TemporaryDirectory(prefix="r16-no-touch-workflow-") as temporary:
            root = Path(temporary).resolve()
            laptop_home = root / "laptop-home"
            laptop_ssh = laptop_home / ".ssh"
            laptop_ssh.mkdir(parents=True, mode=0o700)
            laptop_key = public_line("ssh-ed25519", 105, "laptop")
            (laptop_ssh / "id_ed25519.pub").write_bytes(laptop_key)
            server_ssh = root / "server-home/.ssh"
            server_ssh.mkdir(parents=True, mode=0o700)
            subprocess.run(
                ["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                 "-C", "root@management-server", "-f", str(server_ssh / "id_ed25519")],
                check=True, capture_output=True,
            )
            stale_management = public_line("ssh-ed25519", 106, "foreign-server")
            project = project_with_marker(root / "project", b"", stale_management)
            laptop = project / "laptop.pub"
            management = project / "mgmt-server.pub"
            with mock.patch.dict(os.environ, {"HOME": str(laptop_home)}), \
                 mock.patch.object(setup, "_DRY_RUN", False), \
                 redirect_stdout(io.StringIO()):
                setup._prepare_laptop_public_key(project)
            self.assertEqual(laptop_key, laptop.read_bytes())
            before = {path: path.stat() for path in (laptop, management)}
            narration = io.StringIO()
            with mock.patch.dict(os.environ, {"HOME": str(server_ssh.parent)}), \
                 mock.patch.object(loader, "_run_subprocess", side_effect=AssertionError("setup child may not run")) as child, \
                 redirect_stdout(narration):
                with self.assertRaises(loader.LoadError):
                    loader.prepare_pubkeys(
                        project, ssh_dir=server_ssh, dry_run=False,
                        inject_management_key=True,
                        allow_management_key_generation=False,
                    )
            child.assert_not_called()
            for path, contents in ((laptop, laptop_key), (management, stale_management)):
                after = path.stat()
                self.assertEqual(contents, path.read_bytes())
                self.assertEqual((before[path].st_dev, before[path].st_ino, before[path].st_size),
                                 (after.st_dev, after.st_ino, after.st_size))
            self.assertIn("mgmt-server.pub", narration.getvalue())
            self.assertIn("mismatch", narration.getvalue().casefold())

    def test_macos_load_main_reaches_real_setup_with_two_empty_template_keys(self):
        """Real load prevalidation precedes the real setup child's laptop key bind.

        An explicit synthetic stop at P2P selection keeps this two-script test
        away from links, services, generation, and any production environment.
        """
        loader = load_script("r16_macos_empty_main_load", LOAD_PATH)
        setup = load_script("r16_macos_empty_main_setup", SETUP_PATH)

        class StopAfterKeyPreparation(Exception):
            pass

        with tempfile.TemporaryDirectory(prefix="r16-macos-empty-main-") as temporary:
            root = Path(temporary).resolve()
            (root / "infra").mkdir(mode=0o700)
            home = root / "laptop-home"
            ssh = home / ".ssh"
            ssh.mkdir(parents=True, mode=0o700)
            host_key = public_line("ssh-ed25519", 87, "operator-laptop")
            (ssh / "id_ed25519.pub").write_bytes(host_key)
            project = project_with_marker(root / "project", b"", b"")
            for name in (
                "01-global.yaml", "02-devices_config.csv",
                "02-dhcp-subnet_config.csv", "p2p.xlsx",
            ):
                (project / name).write_bytes(name.encode("ascii") + b"\n")
            laptop = project / "laptop.pub"
            management = project / "mgmt-server.pub"
            before = {
                path: (path.stat().st_dev, path.stat().st_ino, path.stat().st_mtime_ns)
                for path in (laptop, management)
            }
            settings = SimpleNamespace(schema_version=1)
            reached: list[Path] = []

            def run_real_setup(command, **kwargs):
                reached.append(Path(command[1]).resolve())
                self.assertEqual(SETUP_PATH, reached[-1])
                child_env = kwargs.get("env") or {}
                self.assertNotEqual("server-delegated", child_env.get("HTTP_SETUP_KEY_MODE"))
                # The real loader must leave both placeholders unchanged until
                # the real setup child makes its authorized HOME selection.
                self.assertEqual(b"", laptop.read_bytes())
                self.assertEqual(b"", management.read_bytes())
                for path in (laptop, management):
                    self.assertEqual(before[path], (
                        path.stat().st_dev, path.stat().st_ino, path.stat().st_mtime_ns,
                    ))
                with mock.patch.dict(os.environ, child_env, clear=True):
                    setup.main(command[2:])
                return subprocess.CompletedProcess(command, 0)

            with ExitStack() as stack:
                stack.enter_context(mock.patch.dict(os.environ, {"HOME": str(home)}))
                stack.enter_context(mock.patch.object(loader, "runtime_os", return_value="Darwin"))
                stack.enter_context(mock.patch.object(loader, "print_macos_client_requirements"))
                stack.enter_context(mock.patch.object(loader, "validate_macos_client_requirements"))
                stack.enter_context(mock.patch.object(loader, "supports_local_ztp_services", return_value=False))
                stack.enter_context(mock.patch.object(loader, "acquire_deployment_lock", return_value=None))
                stack.enter_context(mock.patch.object(loader, "release_deployment_lock"))
                stack.enter_context(mock.patch.object(loader, "resolve_project", return_value=project))
                stack.enter_context(mock.patch.object(loader, "sync_marker_present", return_value=False))
                stack.enter_context(mock.patch.object(loader, "initialize_from_template"))
                stack.enter_context(mock.patch.object(loader, "_load_global_document", return_value={}))
                stack.enter_context(mock.patch.object(loader, "load_global", return_value=settings))
                stack.enter_context(mock.patch.object(loader, "find_placeholder_password_sections", return_value=()))
                stack.enter_context(mock.patch.object(loader, "apply_subnet_service_ips", return_value=settings))
                stack.enter_context(mock.patch.object(loader, "load_device_types", return_value=frozenset()))
                stack.enter_context(mock.patch.object(loader, "select_p2p", return_value=project / "p2p.xlsx"))
                stack.enter_context(mock.patch.object(loader, "validate_subnet_file"))
                stack.enter_context(mock.patch.object(loader, "project_air_topology_policy", return_value=None))
                stack.enter_context(mock.patch.object(loader, "project_mini_air_devices", return_value=(None, None)))
                stack.enter_context(mock.patch.object(loader, "validate_shared_artifact_receipts"))
                stack.enter_context(mock.patch.object(loader, "ensure_management_key", side_effect=AssertionError("not a laptop key")))
                stack.enter_context(mock.patch.object(loader, "active_project", return_value=None))
                stack.enter_context(mock.patch.object(loader, "_run_subprocess", side_effect=run_real_setup))
                stack.enter_context(mock.patch.object(setup, "HTTP_BASE", str(root)))
                stack.enter_context(mock.patch.dict(setup.deployment_lock.__globals__, {"assert_writer_allowed": lambda **_kw: None}))
                stack.enter_context(mock.patch.object(setup, "stop_native_ztp_monitors"))
                stack.enter_context(mock.patch.object(setup, "_initialize_project_from_template"))
                stack.enter_context(mock.patch.object(setup, "_select_p2p_source", side_effect=StopAfterKeyPreparation))
                stack.enter_context(redirect_stdout(io.StringIO()))
                stack.enter_context(redirect_stderr(io.StringIO()))
                result = loader.main([str(project), "--no-upgrade"])

            self.assertEqual(1, result, "synthetic stop must be inside setup, not load prevalidation")
            self.assertEqual([SETUP_PATH], reached)
            self.assertEqual(host_key, laptop.read_bytes())
            self.assertEqual(b"", management.read_bytes())
            self.assertFalse((ssh / "id_ed25519").exists())

    def test_config_only_laptop_load_leaves_empty_pub_for_real_setup_child(self):
        """Preflight is read-only; the real setup child prepares the laptop key."""
        loader = load_script("r16_config_only_load", LOAD_PATH)
        setup = load_script("r16_config_only_setup", SETUP_PATH)

        class StopAfterKeyPreparation(Exception):
            pass

        with tempfile.TemporaryDirectory(prefix="r16-config-only-load-") as temporary:
            root = Path(temporary).resolve()
            (root / "infra").mkdir(mode=0o700)
            home = root / "laptop-home"
            ssh = home / ".ssh"
            ssh.mkdir(parents=True, mode=0o700)
            laptop_key = public_line("ssh-ed25519", 85, "laptop")
            (ssh / "id_ed25519.pub").write_bytes(laptop_key)
            project = project_with_marker(root / "project", b"", b"")
            laptop_target = project / "laptop.pub"
            management_target = project / "mgmt-server.pub"
            laptop_before = laptop_target.stat()
            management_before = management_target.stat()
            invoked: list[Path] = []

            def run_real_setup(command, **kwargs):
                invoked.append(Path(command[1]).resolve())
                self.assertEqual(SETUP_PATH, invoked[-1])
                self.assertNotEqual(
                    "server-delegated",
                    (kwargs.get("env") or {}).get("HTTP_SETUP_KEY_MODE"),
                )
                with mock.patch.dict(os.environ, kwargs.get("env") or {}, clear=True):
                    setup.main(command[2:])

            with mock.patch.dict(os.environ, {"HOME": str(home)}), \
                 mock.patch.object(loader, "supports_local_ztp_services", return_value=False), \
                 mock.patch.object(loader, "_run_subprocess", side_effect=run_real_setup), \
                 mock.patch.object(setup, "HTTP_BASE", str(root)), \
                 mock.patch.dict(setup.deployment_lock.__globals__, {"assert_writer_allowed": lambda **_kw: None}), \
                 mock.patch.object(setup, "stop_native_ztp_monitors"), \
                 mock.patch.object(setup, "_initialize_project_from_template"), \
                 mock.patch.object(setup, "_select_p2p_source", side_effect=StopAfterKeyPreparation), \
                 redirect_stdout(io.StringIO()):
                selected = loader.prepare_pubkeys(
                    project, ssh_dir=ssh, dry_run=False,
                    inject_management_key=False,
                    allow_management_key_generation=False,
                )
                self.assertIn(laptop_target, selected)
                self.assertEqual(b"", laptop_target.read_bytes())
                self.assertEqual(b"", management_target.read_bytes())
                self.assertEqual(
                    (laptop_before.st_dev, laptop_before.st_ino, laptop_before.st_mtime_ns),
                    (laptop_target.stat().st_dev, laptop_target.stat().st_ino, laptop_target.stat().st_mtime_ns),
                )
                self.assertEqual(
                    (management_before.st_dev, management_before.st_ino, management_before.st_mtime_ns),
                    (management_target.stat().st_dev, management_target.stat().st_ino, management_target.stat().st_mtime_ns),
                )
                with self.assertRaises(StopAfterKeyPreparation):
                    loader.activate_project(
                        project, project / "p2p.xlsx", strict=False,
                        host_role="workstation",
                    )

            self.assertEqual([SETUP_PATH], invoked)
            self.assertEqual(laptop_key, laptop_target.read_bytes())
            self.assertEqual(b"", management_target.read_bytes())
            self.assertFalse((ssh / "id_ed25519").exists())

    def test_server_load_mismatch_refuses_before_setup_and_preserves_both_keys(self):
        """An unknown real management C stops server B before delegated setup.

        A/B/C are independently chosen synthetic inputs. The adjacent matched
        two-HOME test still proves the real load→setup child non-writer path.
        """
        loader = load_script("r16_two_home_mismatch_load", LOAD_PATH)
        setup = load_script("r16_two_home_mismatch_setup", SETUP_PATH)

        class StopAfterKeyPreparation(Exception):
            pass

        with tempfile.TemporaryDirectory(prefix="r16-two-home-mismatch-") as temporary:
            root = Path(temporary).resolve()
            (root / "infra").mkdir(mode=0o700)
            laptop_home = root / "laptop-home"
            server_home = root / "server-home"
            for home in (laptop_home, server_home):
                (home / ".ssh").mkdir(parents=True, mode=0o700)
            laptop_key = public_line("ssh-ed25519", 91, "laptop")
            stale_management_key = public_line("ssh-ed25519", 92, "old-server")
            (laptop_home / ".ssh/id_ed25519.pub").write_bytes(laptop_key)
            server_ssh = server_home / ".ssh"
            subprocess.run(
                ["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
                 "root@management-server", "-f", str(server_ssh / "id_ed25519")],
                check=True, capture_output=True,
            )
            server_key = (server_ssh / "id_ed25519.pub").read_bytes()
            self.assertNotEqual(laptop_key, server_key)
            self.assertNotEqual(stale_management_key, server_key)
            project = project_with_marker(
                root / "project", laptop_key, stale_management_key,
            )
            laptop_target = project / "laptop.pub"
            management_target = project / "mgmt-server.pub"
            laptop_before = laptop_target.stat()
            management_before = management_target.stat()
            output = io.StringIO()
            invoked: list[Path] = []
            child_environment: dict[str, str] = {}

            def run_real_setup(command, **kwargs):
                invoked.append(Path(command[1]).resolve())
                self.assertEqual(SETUP_PATH, invoked[-1])
                self.assertEqual((child_fd,), kwargs.get("pass_fds"))
                child_environment.update(kwargs.get("env") or {})
                self.assertEqual(str(child_fd), child_environment.get("HTTP_DEPLOYMENT_LOCK_FD"))
                with mock.patch.dict(os.environ, child_environment, clear=True):
                    setup.main(command[2:])

            lock_path = root / ".deployment.lock"
            lock_path.touch(mode=0o600)
            parent_fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
            fcntl.flock(parent_fd, fcntl.LOCK_EX)
            child_fd = os.dup(parent_fd)
            try:
                with mock.patch.dict(os.environ, {"HOME": str(server_home)}), \
                     mock.patch.object(loader, "active_project", return_value=None), \
                     mock.patch.object(loader, "supports_local_ztp_services", return_value=True), \
                     mock.patch.object(loader, "_run_subprocess", side_effect=run_real_setup), \
                     mock.patch.object(setup, "HTTP_BASE", str(root)), \
                     mock.patch.dict(setup.deployment_lock.__globals__, {"assert_writer_allowed": lambda **_kw: None}), \
                     mock.patch.object(setup, "stop_native_ztp_monitors"), \
                     mock.patch.object(setup, "_initialize_project_from_template"), \
                     mock.patch.object(setup, "_prepare_laptop_public_key", side_effect=AssertionError("server HOME cannot prepare laptop.pub")) as laptop_preparation, \
                     mock.patch.object(setup, "_select_p2p_source", side_effect=StopAfterKeyPreparation), \
                     redirect_stdout(output):
                    with self.assertRaisesRegex(loader.LoadError, "management public key mismatch"):
                        loader.prepare_pubkeys(
                            project, ssh_dir=server_ssh, dry_run=False,
                            inject_management_key=True,
                            allow_management_key_generation=False,
                        )
                    self.assertEqual(laptop_key, laptop_target.read_bytes())
                    self.assertEqual(
                        (laptop_before.st_dev, laptop_before.st_ino),
                        (laptop_target.stat().st_dev, laptop_target.stat().st_ino),
                    )
                laptop_preparation.assert_not_called()
            finally:
                try:
                    os.close(child_fd)
                except OSError:
                    pass  # setup closed its inherited child copy.
                fcntl.flock(parent_fd, fcntl.LOCK_UN)
                os.close(parent_fd)

            self.assertEqual([], invoked)
            self.assertEqual({}, child_environment)
            self.assertEqual(laptop_key, laptop_target.read_bytes())
            self.assertEqual(
                (laptop_before.st_dev, laptop_before.st_ino),
                (laptop_target.stat().st_dev, laptop_target.stat().st_ino),
            )
            self.assertEqual(stale_management_key, management_target.read_bytes())
            self.assertEqual(
                (management_before.st_dev, management_before.st_ino),
                (management_target.stat().st_dev, management_target.stat().st_ino),
            )
            self.assertIn(str(server_ssh / "id_ed25519.pub"), output.getvalue())
            self.assertIn(fingerprint(stale_management_key), output.getvalue())
            self.assertIn(fingerprint(server_key), output.getvalue())
            self.assertFalse((laptop_home / ".ssh/id_ed25519").exists())

    def test_server_load_setup_does_not_rebind_laptop_key_from_server_home(self):
        """A server's setup child cannot turn its own HOME key into laptop.pub."""
        loader = load_script("r16_two_home_load", LOAD_PATH)
        setup = load_script("r16_two_home_setup", SETUP_PATH)

        class StopAfterKeyPreparation(Exception):
            pass

        with tempfile.TemporaryDirectory(prefix="r16-two-home-") as temporary:
            root = Path(temporary).resolve()
            (root / "infra").mkdir(mode=0o700)
            laptop_home = root / "laptop-home"
            server_home = root / "server-home"
            for home in (laptop_home, server_home):
                (home / ".ssh").mkdir(parents=True, mode=0o700)
            laptop_key = public_line("ssh-ed25519", 81, "laptop")
            server_key = public_line("ssh-ed25519", 82, "server")
            (laptop_home / ".ssh/id_ed25519.pub").write_bytes(laptop_key)
            (server_home / ".ssh/id_ed25519.pub").write_bytes(server_key)
            project = project_with_marker(root / "project", laptop_key, server_key)
            laptop_target = project / "laptop.pub"
            management_target = project / "mgmt-server.pub"
            laptop_identity = (laptop_target.stat().st_dev, laptop_target.stat().st_ino)
            management_identity = (management_target.stat().st_dev, management_target.stat().st_ino)
            invoked: list[Path] = []
            child_environment: dict[str, str] = {}

            def run_real_setup(command, **kwargs):
                invoked.append(Path(command[1]).resolve())
                self.assertEqual(SETUP_PATH, invoked[-1])
                self.assertEqual((child_fd,), kwargs.get("pass_fds"))
                child_environment.update(kwargs.get("env") or {})
                self.assertEqual(str(child_fd), child_environment.get("HTTP_DEPLOYMENT_LOCK_FD"))
                with mock.patch.dict(os.environ, child_environment, clear=True):
                    setup.main(command[2:])

            # Keep a real private lock FD, run real load.run's env/pass_fds
            # construction, and enter real setup.main; only the process launch
            # is bridged in-memory so links, services and production stay inert.
            lock_path = root / ".deployment.lock"
            lock_path.touch(mode=0o600)
            parent_fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
            fcntl.flock(parent_fd, fcntl.LOCK_EX)
            child_fd = os.dup(parent_fd)
            try:
                with mock.patch.dict(os.environ, {"HOME": str(server_home)}), \
                     mock.patch("platform.system", return_value="Linux"), \
                     mock.patch.object(loader, "active_project", return_value=None), \
                     mock.patch.object(loader, "supports_local_ztp_services", return_value=True), \
                     mock.patch.object(loader, "_run_subprocess", side_effect=run_real_setup), \
                     mock.patch.object(setup, "HTTP_BASE", str(root)), \
                     mock.patch.dict(setup.deployment_lock.__globals__, {"assert_writer_allowed": lambda **_kw: None}), \
                     mock.patch.object(setup, "stop_native_ztp_monitors"), \
                     mock.patch.object(setup, "_initialize_project_from_template"), \
                     mock.patch.object(setup, "_select_p2p_source", side_effect=StopAfterKeyPreparation), \
                     redirect_stdout(io.StringIO()):
                    with self.assertRaises(StopAfterKeyPreparation):
                        loader.activate_project(
                            project, project / "p2p.xlsx", strict=False,
                            deployment_lock_descriptor=child_fd,
                            host_role="management-server",
                        )
            finally:
                try:
                    os.close(child_fd)
                except OSError:
                    pass  # setup closed its inherited child copy.
                fcntl.flock(parent_fd, fcntl.LOCK_UN)
                os.close(parent_fd)

            self.assertEqual([SETUP_PATH], invoked)
            self.assertEqual(laptop_key, laptop_target.read_bytes())
            self.assertEqual(laptop_identity, (laptop_target.stat().st_dev, laptop_target.stat().st_ino))
            self.assertEqual(server_key, management_target.read_bytes())
            self.assertEqual(management_identity, (management_target.stat().st_dev, management_target.stat().st_ino))
            self.assertFalse((laptop_home / ".ssh/id_ed25519").exists())
            self.assertFalse((server_home / ".ssh/id_ed25519").exists())
            self.assertEqual("server-delegated", child_environment.get("HTTP_SETUP_KEY_MODE"))

    def test_setup_create_does_not_copy_template_when_host_pair_is_incomplete(self):
        setup = load_script("r16_setup_incomplete_host", SETUP_PATH)
        with tempfile.TemporaryDirectory(prefix="r16-setup-incomplete-") as temporary:
            root = Path(temporary).resolve()
            home = root / "home"
            ssh = home / ".ssh"
            ssh.mkdir(parents=True, mode=0o700)
            private = ssh / "id_ed25519"
            private.write_bytes(b"private-sentinel")
            private.chmod(0o600)
            template = root / "template"
            template.mkdir()
            (template / "laptop.pub").write_bytes(public_line("ssh-ed25519", 43, "template"))
            project = root / "new-project"
            args = argparse.Namespace(project=str(project), create=True,
                                      csv_dir=None, p2p_file=None)
            with mock.patch.dict(os.environ, {"HOME": str(home)}), \
                 mock.patch.object(setup, "TEMPLATE_DIR", str(template)), \
                 mock.patch.object(setup, "_DRY_RUN", False), \
                 redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    setup._main_locked(args)
            self.assertFalse((project / "laptop.pub").exists())
            self.assertEqual(b"private-sentinel", private.read_bytes())
            self.assertFalse((ssh / "id_ed25519.pub").exists())

    def test_load_preserves_legacy_static_ecdsa_and_security_key_identity(self):
        loader = load_script("r16_load_static_types", LOAD_PATH)
        static_keys = (
            extended_public_line(b"ecdsa-sha2-nistp256", b"nistp256", b"\x04" + b"\x11" * 64),
            extended_public_line(b"sk-ssh-ed25519@openssh.com", b"\x22" * 32, b"ssh:fixture"),
            extended_public_line(b"sk-ecdsa-sha2-nistp256@openssh.com", b"nistp256", b"\x04" + b"\x33" * 64, b"ssh:fixture"),
        )
        with tempfile.TemporaryDirectory(prefix="r16-static-types-") as temporary:
            root = Path(temporary).resolve()
            service = root / "service-ssh"
            service.mkdir(mode=0o700)
            subprocess.run(
                ["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
                 "root@management-server", "-f", str(service / "id_ed25519")],
                check=True, capture_output=True,
            )
            for index, static_key in enumerate(static_keys):
                with self.subTest(key_type=static_key.split(b" ", 1)[0]):
                    project = project_with_marker(root / f"project-{index}", static_key, b"")
                    result = loader.prepare_pubkeys(
                        project, ssh_dir=service, dry_run=False,
                        inject_management_key=True, allow_management_key_generation=False,
                    )
                    self.assertIn(project / "laptop.pub", result)
                    self.assertEqual(static_key, (project / "laptop.pub").read_bytes())

    def test_setup_create_uses_laptop_public_key_not_template_material(self):
        setup = load_script("r16_setup_create", SETUP_PATH)
        with tempfile.TemporaryDirectory(prefix="r16-setup-") as temporary:
            root = Path(temporary).resolve()
            home = root / "home"
            ssh = home / ".ssh"
            ssh.mkdir(parents=True, mode=0o700)
            host_public = public_line("ssh-rsa", 41, "host-rsa-public-only")
            (ssh / "id_rsa.pub").write_bytes(host_public)
            self.assertFalse((ssh / "id_rsa").exists())
            template = root / "template"
            template.mkdir()
            # A stale, nonempty template key must not become a project's laptop key.
            (template / "laptop.pub").write_bytes(public_line("ssh-ed25519", 42, "template"))
            project = root / "new-project"
            args = argparse.Namespace(project=str(project), create=True,
                                      csv_dir=None, p2p_file=None)
            with mock.patch.dict(os.environ, {"HOME": str(home)}), \
                 mock.patch.object(setup, "TEMPLATE_DIR", str(template)), \
                 mock.patch.object(setup, "_DRY_RUN", False), \
                 mock.patch("ssh_key_preparation.ensure_public_key", wraps=__import__("ssh_key_preparation").ensure_public_key) as selection, \
                 mock.patch("ssh_key_preparation.prepare_project_public_key", wraps=__import__("ssh_key_preparation").prepare_project_public_key) as publication, \
                 redirect_stdout(io.StringIO()):
                self.assertEqual(0, setup._main_locked(args))
            selection.assert_called_once_with(ssh, comment="operator@laptop")
            self.assertEqual("laptop.pub", publication.call_args.args[1])
            self.assertEqual(host_public, (project / "laptop.pub").read_bytes())
            self.assertFalse((ssh / "id_ed25519").exists())

    def test_server_rsa_only_fails_closed_without_private_read_or_wrong_home_key(self):
        """RSA-only server HOME must not trigger an unproved key publication.

        A public-only RSA fallback is valid for laptop setup, but the server's
        management path cannot silently generate/publish a different Ed25519
        identity when RSA is present and RSA pair proof is out of scope.
        """
        loader = load_script("r16_server_rsa_only", LOAD_PATH)
        with tempfile.TemporaryDirectory(prefix="r16-server-rsa-only-") as temporary:
            root = Path(temporary).resolve()
            laptop_home = root / "laptop-home"
            laptop_ssh = laptop_home / ".ssh"
            laptop_ssh.mkdir(parents=True, mode=0o700)
            laptop_key = public_line("ssh-ed25519", 91, "laptop-home")
            (laptop_ssh / "id_ed25519.pub").write_bytes(laptop_key)

            for allow_generation in (False, True):
                with self.subTest(allow_generation=allow_generation):
                    server_home = root / f"server-home-{allow_generation}"
                    server_ssh = server_home / ".ssh"
                    server_ssh.mkdir(parents=True, mode=0o700)
                    rsa_public = public_line("ssh-rsa", 92, "server-home")
                    (server_ssh / "id_rsa.pub").write_bytes(rsa_public)
                    rsa_private = server_ssh / "id_rsa"
                    rsa_private.write_bytes(b"synthetic-private-do-not-read")
                    rsa_private.chmod(0o600)
                    private_stat = rsa_private.stat()
                    private_identity = private_stat.st_dev, private_stat.st_ino
                    project = project_with_marker(
                        root / f"project-{allow_generation}", laptop_key, b"",
                    )
                    laptop_target = project / "laptop.pub"
                    management_target = project / "mgmt-server.pub"
                    laptop_stat = laptop_target.stat()
                    management_stat = management_target.stat()
                    original_os_open = os.open
                    original_path_open = Path.open
                    original_run = subprocess.run
                    original_popen = loader._popen_subprocess
                    original_bounded = loader._run_bounded_management_command
                    private_open_attempts: list[str] = []

                    def reject_rsa_private_path(path):
                        if isinstance(path, (str, bytes, os.PathLike)) and Path(path).name == "id_rsa":
                            private_open_attempts.append(os.fspath(path))
                            raise AssertionError("server RSA private key must not be opened")

                    def reject_rsa_private_command(argv, pass_fds=()):
                        if isinstance(argv, (list, tuple)) and any(
                            str(rsa_private) == os.fspath(item) for item in argv
                        ):
                            private_open_attempts.append(str(rsa_private))
                            raise AssertionError("server RSA private key must not reach a child")
                        for descriptor in pass_fds:
                            held = os.fstat(descriptor)
                            if (held.st_dev, held.st_ino) == private_identity:
                                private_open_attempts.append(f"held-fd:{descriptor}")
                                raise AssertionError("server RSA private FD must not reach a child")

                    def guarded_os_open(path, *args, **kwargs):
                        reject_rsa_private_path(path)
                        return original_os_open(path, *args, **kwargs)

                    def guarded_path_open(path, *args, **kwargs):
                        reject_rsa_private_path(path)
                        return original_path_open(path, *args, **kwargs)

                    def guarded_run(argv, *args, **kwargs):
                        reject_rsa_private_command(argv, kwargs.get("pass_fds", ()))
                        return original_run(argv, *args, **kwargs)

                    def guarded_popen(argv, *args, **kwargs):
                        reject_rsa_private_command(argv, kwargs.get("pass_fds", ()))
                        return original_popen(argv, *args, **kwargs)

                    def guarded_bounded(argv, *args, **kwargs):
                        reject_rsa_private_command(argv, kwargs.get("pass_fds", ()))
                        return original_bounded(argv, *args, **kwargs)

                    failure = None
                    with mock.patch.dict(os.environ, {"HOME": str(server_home)}), \
                         mock.patch("os.open", side_effect=guarded_os_open), \
                         mock.patch.object(Path, "open", guarded_path_open), \
                         mock.patch("subprocess.run", side_effect=guarded_run), \
                         mock.patch.object(loader, "_popen_subprocess", side_effect=guarded_popen), \
                         mock.patch.object(loader, "_run_bounded_management_command", side_effect=guarded_bounded), \
                         redirect_stdout(io.StringIO()):
                        try:
                            loader.prepare_pubkeys(
                                project, ssh_dir=server_ssh, dry_run=False,
                                inject_management_key=True,
                                allow_management_key_generation=allow_generation,
                            )
                        except loader.LoadError as exc:
                            failure = exc

                    self.assertEqual([], private_open_attempts)
                    self.assertEqual(laptop_key, laptop_target.read_bytes())
                    self.assertEqual(
                        (laptop_stat.st_dev, laptop_stat.st_ino),
                        (laptop_target.stat().st_dev, laptop_target.stat().st_ino),
                    )
                    self.assertEqual(b"", management_target.read_bytes())
                    self.assertEqual(
                        (management_stat.st_dev, management_stat.st_ino),
                        (management_target.stat().st_dev, management_target.stat().st_ino),
                    )
                    self.assertFalse((server_ssh / "id_ed25519").exists())
                    self.assertFalse((server_ssh / "id_ed25519.pub").exists())
                    self.assertEqual(rsa_public, (server_ssh / "id_rsa.pub").read_bytes())
                    after_private = rsa_private.stat()
                    self.assertEqual(
                        (private_stat.st_dev, private_stat.st_ino,
                         private_stat.st_size, private_stat.st_mtime_ns),
                        (after_private.st_dev, after_private.st_ino,
                         after_private.st_size, after_private.st_mtime_ns),
                    )
                    self.assertIsNotNone(failure, "RSA-only server must fail closed")

    def test_load_mismatch_refuses_existing_real_management_key_without_write(self):
        loader = load_script("r16_load_mismatch", LOAD_PATH)
        with tempfile.TemporaryDirectory(prefix="r16-load-") as temporary:
            root = Path(temporary).resolve()
            service = root / "service-ssh"
            service.mkdir(mode=0o700)
            subprocess.run(
                ["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
                 "root@management-server", "-f", str(service / "id_ed25519")],
                check=True, capture_output=True,
            )
            service_public = (service / "id_ed25519.pub").read_bytes()
            old = public_line("ssh-ed25519", 51, "old-server")
            project = project_with_marker(
                root / "project", public_line("ssh-ed25519", 52, "laptop"), old,
            )
            target = project / "mgmt-server.pub"
            before = target.stat()
            output = io.StringIO()
            with mock.patch("ssh_key_preparation.prepare_project_public_key", wraps=__import__("ssh_key_preparation").prepare_project_public_key) as publication, redirect_stdout(output):
                with self.assertRaisesRegex(loader.LoadError, "management public key mismatch"):
                    loader.prepare_pubkeys(
                        project, ssh_dir=service, dry_run=False,
                        inject_management_key=True, allow_management_key_generation=False,
                    )
            publication.assert_not_called()
            self.assertEqual(old, target.read_bytes())
            self.assertEqual((before.st_dev, before.st_ino),
                             (target.stat().st_dev, target.stat().st_ino))
            self.assertIn(str(service / "id_ed25519.pub"), output.getvalue())
            self.assertIn(fingerprint(old), output.getvalue())
            self.assertIn(fingerprint(service_public), output.getvalue())

    def test_load_revalidates_held_project_leaf_before_mismatch_publication(self):
        loader = load_script("r16_load_rebinding", LOAD_PATH)
        with tempfile.TemporaryDirectory(prefix="r16-race-") as temporary:
            root = Path(temporary).resolve()
            service = root / "service-ssh"
            service.mkdir(mode=0o700)
            subprocess.run(
                ["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
                 "root@management-server", "-f", str(service / "id_ed25519")],
                check=True, capture_output=True,
            )
            old = public_line("ssh-ed25519", 61, "old-server")
            project = project_with_marker(
                root / "project", public_line("ssh-ed25519", 62, "laptop"), old,
            )
            target = project / "mgmt-server.pub"
            outside = root / "outside.pub"
            outside.write_bytes(old)
            stages: list[str] = []

            def rebind(stage: str) -> None:
                stages.append(stage)
                if stage == "project-placeholder-held":
                    target.rename(project / "held-original.pub")
                    target.symlink_to(outside)

            with mock.patch.object(loader, "_management_key_checkpoint", side_effect=rebind):
                with self.assertRaises(loader.LoadError):
                    loader.prepare_pubkeys(
                        project, ssh_dir=service, dry_run=False,
                        inject_management_key=True, allow_management_key_generation=False,
                    )
            # A pre-existing mismatch error cannot satisfy this race contract.
            self.assertIn("project-placeholder-held", stages)
            self.assertEqual(old, outside.read_bytes())
            self.assertTrue(target.is_symlink())


if __name__ == "__main__":
    unittest.main()
