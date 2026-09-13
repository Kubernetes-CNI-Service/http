"""Deployment, packaging, setup, unload, and infrastructure review cases."""

from __future__ import annotations

import argparse
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


PACKAGE = load_module("ops_review_package_common", TOOLS / "_package_common.py")
DOWNLOAD = load_module("ops_review_download", TOOLS / "tar-for-download.py")
UPLOAD = load_module("ops_review_upload", TOOLS / "tar-for-upload.py")
SYNC = load_module("ops_review_sync", TOOLS / "sync-code.py")
IMPORTER = load_module(
    "ops_review_importer", TOOLS / "import-from-download.py"
)
LOCKS = load_module("ops_review_deployment_lock", TOOLS / "deployment_lock.py")
SETUP = load_module("ops_review_setup", ROOT / "DAY0-Prepare/01-a-setup.py")
UNSETUP = load_module("ops_review_unsetup", ROOT / "DAY0-Prepare/02-unsetup.py")
LOAD = load_module("ops_review_load", ROOT / "DAY0-Prepare/11-load.py")
UNLOAD = load_module("ops_review_unload", ROOT / "DAY0-Prepare/13-unload.py")
DEPLOY = load_module("ops_review_deploy_infra", ROOT / "infra/deploy_infra.py")
LLDP = load_module(
    "ops_review_lldp", TOOLS / "lldp-analyze-tool/analyze_lldp.py"
)

NVOS_IMAGE_NAMES = (
    "nvos-amd64-25.03.1010.bin",
    "nvosv25-03-1010amd64.bin",
)


def nvos_image_settings():
    """Fixed version contract; accepted filenames are asserted independently."""
    return LOAD.GlobalSettings(
        dhcp_enabled=True,
        dhcp_package="isc-dhcp-server",
        http_enabled=True,
        http_package="apache2",
        http_root=Path("/var/www/html"),
        ztp_enabled=True,
        ztp_prefix="/ztp",
        ztp_ips={},
        versions={"ib": "25.03.1010"},
    )


def write_valid_switch_image(path: Path, marker: bytes = b"") -> None:
    """Create a sparse self-extracting image payload with stable test content."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as stream:
        stream.write(b"#!/bin/sh")
        stream.write(marker)
        stream.truncate(1024 * 1024)


class ScopedSourceAndEntryPointTests(unittest.TestCase):
    def test_macos_bootstrap_reports_missing_generation_module_without_traceback(
        self,
    ) -> None:
        load_path = ROOT / "DAY0-Prepare/11-load.py"
        probe = "\n".join((
            "import importlib.util, platform, runpy",
            "real_find_spec = importlib.util.find_spec",
            "platform.system = lambda: 'Darwin'",
            "importlib.util.find_spec = lambda name: "
            "None if name == 'yaml' else real_find_spec(name)",
            f"runpy.run_path({str(load_path)!r}, run_name='dependency_probe')",
        ))
        result = subprocess.run(
            [sys.executable, "-B", "-c", probe],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        self.assertEqual(1, result.returncode)
        output = result.stdout + result.stderr
        self.assertIn("macOS 配置生成缺少必需依赖：PyYAML", output)
        self.assertIn(
            "python3 -m pip install -r requirements-dev.txt Jinja2==3.1.6",
            output,
        )
        self.assertNotIn("Traceback", output)

    def test_macos_client_requirement_report_lists_every_supported_tool_tier(self):
        commands = {
            "git": None,
            "ssh": "/usr/bin/ssh",
            "scp": "/usr/bin/scp",
            "ssh-keygen": "/usr/bin/ssh-keygen",
            "rsync": None,
            "mkpasswd": None,
            "brew": None,
        }
        modules = {
            "yaml": object(),
            "jinja2": object(),
            "openpyxl": None,
            "pandas": object(),
            "xlsxwriter": None,
        }
        brew = Path("/opt/homebrew/bin/brew")
        lines = []

        status = LOAD.print_macos_client_requirements(
            update_passwords=True,
            printer=lines.append,
            command_resolver=lambda name: commands.get(name),
            module_resolver=lambda name: modules.get(name),
            regular_file=lambda path: path == brew,
            python_version=(3, 9, 6),
        )

        self.assertEqual(("git", "rsync"), status.missing_commands)
        self.assertEqual(("openpyxl",), status.missing_generation_modules)
        self.assertEqual(("XlsxWriter",), status.missing_validation_modules)
        self.assertIsNone(status.password_backend)
        self.assertEqual(str(brew), status.homebrew)
        output = "\n".join(lines)
        for expected in (
            "Python 3.9+", "PyYAML", "Jinja2", "openpyxl",
            "Git", "OpenSSH", "ssh", "scp", "ssh-keygen", "rsync",
            "pandas", "XlsxWriter", "Homebrew", "libxcrypt", "mkpasswd",
            "xcode-select --install",
            "python3 -m pip install -r requirements-dev.txt Jinja2==3.1.6",
            "brew install libxcrypt",
            "Apache", "ISC DHCP", "systemd", "iproute2", "Ubuntu",
        ):
            self.assertIn(expected, output)
        self.assertIn("[MISSING] 配置生成模块：openpyxl", output)
        self.assertIn("[MISSING] 上传/同步命令：git, rsync", output)
        self.assertIn("[MISSING] 全量测试/报表模块：XlsxWriter", output)
        self.assertIn("[MISSING] 密码更新后端", output)
        self.assertIn("VirtualBox/Docker/Excel 不是代码必需依赖", output)
        self.assertIn("[INSTALL] xcode-select --install", output)
        self.assertIn("[INSTALL] brew install rsync", output)
        self.assertIn(
            "[INSTALL] python3 -m pip install -r requirements-dev.txt Jinja2==3.1.6",
            output,
        )
        with self.assertRaisesRegex(LOAD.LoadError, "openpyxl.*先安装"):
            LOAD.validate_macos_client_requirements(status)

        ancillary_only = LOAD.MacOSClientRequirementStatus(
            python_version="3.9.6",
            python_supported=True,
            missing_generation_modules=(),
            missing_commands=("rsync",),
            missing_validation_modules=("XlsxWriter",),
            password_backend=None,
            homebrew=None,
        )
        LOAD.validate_macos_client_requirements(ancillary_only)

        healthy_lines = []
        LOAD.print_macos_client_requirements(
            update_passwords=False,
            printer=healthy_lines.append,
            command_resolver=lambda name: f"/usr/bin/{name}",
            module_resolver=lambda _name: object(),
            regular_file=lambda _path: False,
            python_version=(3, 12, 7),
        )
        self.assertNotIn("[INSTALL]", "\n".join(healthy_lines))

    def test_all_scoped_python_sources_compile(self):
        sources = list(TOOLS.rglob("*.py")) + list((ROOT / "infra").glob("*.py"))
        sources += [
            ROOT / "DAY0-Prepare/01-a-setup.py",
            ROOT / "DAY0-Prepare/02-unsetup.py",
            ROOT / "DAY0-Prepare/13-unload.py",
        ]
        for path in sorted(set(sources)):
            with self.subTest(path=path.relative_to(ROOT)):
                compile(path.read_text(encoding="utf-8"), str(path), "exec")

    def test_every_python_entry_point_has_a_safe_help_or_usage_gate(self):
        entries = [
            ROOT / "infra/check_infra.py",
            ROOT / "infra/deploy_infra.py",
            ROOT / "DAY0-Prepare/01-a-setup.py",
            ROOT / "DAY0-Prepare/02-unsetup.py",
            ROOT / "DAY0-Prepare/13-unload.py",
            TOOLS / "collect-ztp-diagnostics.py",
            TOOLS / "import-from-download.py",
            TOOLS / "sync-code.py",
            TOOLS / "tar-for-download.py",
            TOOLS / "tar-for-upload.py",
            TOOLS / "lldp-analyze-tool/analyze_lldp.py",
            TOOLS / "lldp-analyze-tool/build_report.py",
            TOOLS / "ibdiagnet-analyze-tool/analyze.py",
        ]
        entries += sorted((TOOLS / "ib-tool-Jie/ib_tool_box/scripts").glob("*.py"))
        entries += sorted((TOOLS / "ibdiagnet-analyze-tool/scripts").glob("*.py"))
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        for path in entries:
            with self.subTest(path=path.relative_to(ROOT)):
                result = subprocess.run(
                    [sys.executable, "-B", str(path), "--help"], cwd=ROOT,
                    text=True, capture_output=True, timeout=20, env=environment,
                )
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertIn("usage", (result.stdout + result.stderr).casefold())


    def test_public_transfer_and_diagnostic_help_uses_neutral_examples(self):
        entries = [
            TOOLS / "collect-ztp-diagnostics.py",
            TOOLS / "import-from-download.py",
            TOOLS / "sync-code.py",
            TOOLS / "tar-for-download.py",
            TOOLS / "tar-for-upload.py",
        ]
        remote_entries = {
            "sync-code.py", "tar-for-download.py", "tar-for-upload.py",
        }
        forbidden = (
            "legacy-transfer-host", "corp.example.invalid",
            "2098-private-site",
        )
        for path in entries:
            with self.subTest(path=path.name):
                result = subprocess.run(
                    [sys.executable, "-B", str(path), "--help"], cwd=ROOT,
                    text=True, capture_output=True, timeout=20,
                )
                self.assertEqual(0, result.returncode, result.stderr)
                help_text = result.stdout + result.stderr
                self.assertIn("2099-example-site", help_text)
                if path.name in remote_entries:
                    self.assertIn("ztp-admin.example", help_text)
                for marker in forbidden:
                    self.assertNotIn(marker, help_text.casefold())

    def test_report_builder_refuses_missing_arguments(self):
        result = subprocess.run(
            [sys.executable, "-B", str(TOOLS / "lldp-analyze-tool/build_report.py")],
            cwd=ROOT, text=True, capture_output=True, timeout=20,
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("usage", (result.stdout + result.stderr).casefold())

    def test_importer_source_and_review_output_are_separate(self):
        self.assertEqual(ROOT, IMPORTER.ROOT)
        self.assertEqual(ROOT / "package-imports", IMPORTER.DEFAULT_REVIEW_ROOT)
        self.assertEqual(
            ROOT / "tools/import-from-download.py",
            Path(IMPORTER.__file__).resolve(),
        )

    def test_infra_shell_entries_parse_and_show_help_without_root(self):
        for path in (ROOT / "infra/infra-setup.sh", ROOT / "infra/infra-teardown.sh"):
            with self.subTest(path=path.name):
                syntax = subprocess.run(
                    ["bash", "-n", str(path)], text=True, capture_output=True,
                )
                self.assertEqual(0, syntax.returncode, syntax.stderr)
                help_result = subprocess.run(
                    ["bash", str(path), "--help"], text=True, capture_output=True,
                )
                self.assertEqual(0, help_result.returncode, help_result.stderr)
                self.assertIn("usage", (help_result.stdout + help_result.stderr).casefold())


class NvosImageLoadContractTests(unittest.TestCase):
    """Direct DAY0 load contracts for exact, version-bound image aliases."""

    def test_setup_classifies_only_the_two_exact_nvos_filename_formats(self):
        for filename in NVOS_IMAGE_NAMES:
            with self.subTest(filename=filename):
                self.assertEqual("nvos", SETUP._image_platform(filename))

        for filename in (
            "NOTNVOS.bin",
            "NVOS-AMD64-25.03.1010.bin",
            "evil-nvos-amd64-25.03.1010.bin",
            "nvos-amd64-25.03.1010-extra.bin",
            "nvosv25-03-1010amd64-extra.bin",
        ):
            with self.subTest(filename=filename):
                self.assertIsNone(SETUP._image_platform(filename))

    def test_setup_does_not_publish_a_symlinked_nvos_image_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shared = root / "image"
            ztp = root / "ztp"
            outside = root / "outside.bin"
            write_valid_switch_image(outside)
            shared.mkdir()
            candidate = shared / NVOS_IMAGE_NAMES[0]
            candidate.symlink_to(outside)

            with mock.patch.multiple(
                SETUP,
                HTTP_BASE=str(root),
                IMAGE_DIR=str(shared),
                ZTP=str(ztp),
                _DRY_RUN=False,
                _LINK_ERRORS=0,
            ):
                SETUP._process_bin_files()
                self.assertEqual(1, SETUP._LINK_ERRORS)

            self.assertFalse((ztp / "image/nvos" / candidate.name).exists())

    def resolve_nvos_image(self, project: Path, shared: Path) -> dict[str, Path]:
        with mock.patch.object(LOAD, "IMAGE_DIR", shared):
            return LOAD.prepare_images(
                project,
                LOAD.expected_images(nvos_image_settings(), frozenset({"ib"})),
                quiet=True,
            )

    def test_each_supported_nvos_filename_resolves_the_same_global_version(self):
        for filename in NVOS_IMAGE_NAMES:
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                project = root / "project"
                shared = root / "image"
                project.mkdir()
                image = shared / filename
                write_valid_switch_image(image)

                resolved = self.resolve_nvos_image(project, shared)

                self.assertEqual(image, resolved["ib"])
                self.assertEqual(filename, resolved["ib"].name)

    def test_nvos_version_aliases_are_exact_three_part_versions(self):
        dotted = LOAD.expected_images(nvos_image_settings(), frozenset({"ib"}))
        hyphen_settings = LOAD.replace(
            nvos_image_settings(), versions={"ib": "25-03-1010"},
        )
        hyphenated = LOAD.expected_images(hyphen_settings, frozenset({"ib"}))
        self.assertEqual(dotted, hyphenated)

        for version in (
            "25.03",
            "25.03.1010.1",
            "25-03.1010",
            "../../25.03.1010",
            "25.03.1010.sig",
        ):
            with self.subTest(version=version):
                settings = LOAD.replace(
                    nvos_image_settings(), versions={"ib": version},
                )
                with self.assertRaises(LOAD.LoadError):
                    LOAD.expected_images(settings, frozenset({"ib"}))

    def test_different_payloads_under_both_nvos_aliases_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            shared = root / "image"
            project.mkdir()
            write_valid_switch_image(shared / NVOS_IMAGE_NAMES[0], b"modern")
            write_valid_switch_image(shared / NVOS_IMAGE_NAMES[1], b"legacy")

            with self.assertRaises(LOAD.LoadError) as caught:
                self.resolve_nvos_image(project, shared)

            message = str(caught.exception)
            for filename in NVOS_IMAGE_NAMES:
                self.assertIn(filename, message)

    def test_identical_nvos_aliases_prefer_the_modern_filename(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            shared = root / "image"
            project.mkdir()
            modern = shared / NVOS_IMAGE_NAMES[0]
            legacy = shared / NVOS_IMAGE_NAMES[1]
            write_valid_switch_image(modern, b"same-payload")
            legacy.write_bytes(modern.read_bytes())

            resolved = self.resolve_nvos_image(project, shared)

            self.assertEqual(modern, resolved["ib"])

    def test_project_modern_nvos_image_is_copied_to_shared_store(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            shared = root / "image"
            project.mkdir()
            source = project / NVOS_IMAGE_NAMES[0]
            write_valid_switch_image(source, b"project-payload")

            resolved = self.resolve_nvos_image(project, shared)

            copied = shared / NVOS_IMAGE_NAMES[0]
            self.assertEqual(copied, resolved["ib"])
            self.assertEqual(source.read_bytes(), copied.read_bytes())
            self.assertFalse((shared / NVOS_IMAGE_NAMES[1]).exists())

    def test_project_only_nvos_image_dry_run_resolves_the_existing_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            shared = root / "image"
            project.mkdir()
            source = project / NVOS_IMAGE_NAMES[0]
            write_valid_switch_image(source, b"dry-run-project-payload")

            with mock.patch.object(LOAD, "IMAGE_DIR", shared):
                resolved = LOAD.prepare_images(
                    project,
                    LOAD.expected_images(nvos_image_settings(), frozenset({"ib"})),
                    dry_run=True,
                    quiet=True,
                )

            self.assertEqual(source, resolved["ib"])
            self.assertTrue(resolved["ib"].is_file())
            self.assertFalse((shared / NVOS_IMAGE_NAMES[0]).exists())

    def test_symlinked_supported_candidate_fails_closed_in_project_or_shared(self):
        for candidate_root in ("project", "shared"):
            for symlink_name in NVOS_IMAGE_NAMES:
                with self.subTest(
                    candidate_root=candidate_root, symlink_name=symlink_name,
                ), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    project = root / "project"
                    shared = root / "image"
                    project.mkdir()
                    shared.mkdir()
                    other_name = next(
                        name for name in NVOS_IMAGE_NAMES if name != symlink_name
                    )
                    selected_root = project if candidate_root == "project" else shared
                    target = root / "outside-image.bin"
                    write_valid_switch_image(target, b"same-payload")
                    regular = selected_root / other_name
                    regular.write_bytes(target.read_bytes())
                    candidate = selected_root / symlink_name
                    candidate.symlink_to(target)
                    target_before = target.read_bytes()

                    with self.assertRaises(LOAD.LoadError) as caught:
                        self.resolve_nvos_image(project, shared)

                    self.assertIn(symlink_name, str(caught.exception))
                    self.assertTrue(candidate.is_symlink())
                    self.assertEqual(target_before, target.read_bytes())

    def test_wrong_version_and_near_match_remain_unexpected_project_images(self):
        filenames = (
            "nvos-amd64-25.03.1011.bin",
            "nvos-amd64-25.03.1010-extra.bin",
        )
        for filename in filenames:
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                project = root / "project"
                shared = root / "image"
                project.mkdir()
                write_valid_switch_image(project / filename)

                with self.assertRaises(LOAD.LoadError) as caught:
                    self.resolve_nvos_image(project, shared)

                self.assertIn(filename, str(caught.exception))
                self.assertIn("不符合当前 global/device type", str(caught.exception))

    def test_cumulus_keeps_its_single_existing_filename(self):
        settings = LOAD.GlobalSettings(
            dhcp_enabled=True,
            dhcp_package="isc-dhcp-server",
            http_enabled=True,
            http_package="apache2",
            http_root=Path("/var/www/html"),
            ztp_enabled=True,
            ztp_prefix="/ztp",
            ztp_ips={},
            versions={"eth": "5.16.4"},
        )
        expected = LOAD.expected_images(settings, frozenset({"eth"}))
        self.assertEqual(
            {"eth": "cumulus-linux-5.16.4-mlx-amd64.bin"}, expected,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            shared = root / "image"
            project.mkdir()
            image = shared / "cumulus-linux-5.16.4-mlx-amd64.bin"
            write_valid_switch_image(image)
            with mock.patch.object(LOAD, "IMAGE_DIR", shared):
                resolved = LOAD.prepare_images(project, expected, quiet=True)
            self.assertEqual(image, resolved["eth"])


class SharedDeploymentLockTests(unittest.TestCase):
    def test_actual_writers_exclude_a_second_open_description(self):
        with tempfile.TemporaryDirectory() as directory:
            with LOCKS.deployment_lock(directory):
                with self.assertRaises(LOCKS.DeploymentLockError) as caught:
                    with LOCKS.deployment_lock(directory):
                        pass
            message = str(caught.exception)
            lock = str(Path(directory) / ".deployment.lock")
            self.assertIn(lock, message)
            self.assertIn(f"lsof {lock}", message)
            self.assertIn(f"fuser {lock}", message)

    def test_dry_run_does_not_create_a_missing_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".deployment.lock"
            with LOCKS.deployment_lock(directory, dry_run=True) as descriptor:
                self.assertIsNone(descriptor)
            self.assertFalse(os.path.lexists(path))

    def test_broken_symlink_is_rejected_in_dry_and_actual_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".deployment.lock"
            path.symlink_to("missing-target")
            for dry_run in (True, False):
                with self.subTest(dry_run=dry_run):
                    with self.assertRaises(LOCKS.DeploymentLockError):
                        with LOCKS.deployment_lock(directory, dry_run=dry_run):
                            pass

    def test_hardlinked_lock_and_load_symlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / ".deployment.lock"
            lock.touch()
            os.link(lock, root / "second-name")
            with self.assertRaises(LOCKS.DeploymentLockError):
                with LOCKS.deployment_lock(root):
                    pass
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "target").touch()
            (root / ".deployment.lock").symlink_to("target")
            with mock.patch.object(LOAD, "DEPLOYMENT_LOCK", root / ".deployment.lock"):
                with self.assertRaises(LOAD.LoadError):
                    LOAD.acquire_deployment_lock()

    def test_only_matching_inherited_descriptor_is_reentrant(self):
        with tempfile.TemporaryDirectory() as directory:
            with LOCKS.deployment_lock(directory) as parent_descriptor:
                inherited_copy = os.dup(parent_descriptor)
                with mock.patch.dict(
                    os.environ, {LOCKS.LOCK_FD_ENV: str(inherited_copy)}, clear=False,
                ):
                    with LOCKS.deployment_lock(directory) as child_descriptor:
                        self.assertEqual(inherited_copy, child_descriptor)
                with self.assertRaises(LOCKS.DeploymentLockError):
                    with LOCKS.deployment_lock(directory):
                        pass

    def test_load_reuses_valid_inherited_descriptor_without_unlocking_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            lock_path = Path(directory) / ".deployment.lock"
            with LOCKS.deployment_lock(directory) as parent_descriptor:
                inherited_copy = os.dup(parent_descriptor)
                with mock.patch.object(
                    LOAD, "DEPLOYMENT_LOCK", lock_path,
                ), mock.patch.dict(
                    os.environ,
                    {LOCKS.LOCK_FD_ENV: str(inherited_copy)},
                    clear=False,
                ):
                    child_descriptor = LOAD.acquire_deployment_lock()
                    self.assertEqual(inherited_copy, child_descriptor)
                    LOAD.release_deployment_lock(child_descriptor)

                # Releasing the child copy must not unlock the parent's shared
                # open-file description while the management wrapper is still
                # completing health checks and committing activation.
                with self.assertRaises(LOCKS.DeploymentLockError):
                    with LOCKS.deployment_lock(directory):
                        pass

    def test_forged_unrelated_descriptor_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            unrelated = Path(directory) / "unrelated"
            unrelated.write_text("x", encoding="utf-8")
            descriptor = os.open(unrelated, os.O_RDONLY)
            try:
                with mock.patch.dict(
                    os.environ, {LOCKS.LOCK_FD_ENV: str(descriptor)}, clear=False,
                ):
                    with self.assertRaises(LOCKS.DeploymentLockError):
                        with LOCKS.deployment_lock(directory):
                            pass
            finally:
                os.close(descriptor)

    def test_load_passes_held_descriptor_to_setup_subprocess(self):
        with tempfile.TemporaryDirectory() as directory:
            with LOCKS.deployment_lock(directory) as descriptor:
                completed = SimpleNamespace(returncode=0)
                with mock.patch.object(
                    LOAD.subprocess, "run", return_value=completed,
                ) as runner, redirect_stdout(io.StringIO()):
                    LOAD.run(["child"], inherited_lock_descriptor=descriptor)
        kwargs = runner.call_args.kwargs
        self.assertEqual((descriptor,), kwargs["pass_fds"])
        self.assertEqual(str(descriptor), kwargs["env"][LOCKS.LOCK_FD_ENV])

    def test_load_flushes_operator_output_before_spawning_child(self):
        events = []

        class RecordingStream(io.StringIO):
            def __init__(self, label):
                super().__init__()
                self.label = label

            def flush(self):
                events.append(self.label)
                return super().flush()

        completed = SimpleNamespace(returncode=0)

        def run_child(*_args, **_kwargs):
            events.append("child")
            return completed

        stdout = RecordingStream("stdout")
        stderr = RecordingStream("stderr")
        with mock.patch.object(LOAD.sys, "stdout", stdout), \
                mock.patch.object(LOAD.sys, "stderr", stderr), \
                mock.patch.object(LOAD.subprocess, "run", side_effect=run_child):
            LOAD.run(["child"])

        self.assertEqual(["stdout", "stderr", "child"], events)

    def test_load_routes_direct_subprocess_spawns_through_flushing_wrappers(self):
        source = (ROOT / "DAY0-Prepare/11-load.py").read_text(encoding="utf-8")

        # Keep one raw call inside each wrapper.  Every production call site
        # must use the wrapper so buffered operator narration precedes child
        # stdout/stderr, including rollback and cleanup failures.
        self.assertEqual(1, source.count("subprocess.run("))
        self.assertEqual(1, source.count("subprocess.Popen("))

    def test_load_help_and_dry_run_guidance_are_actionable(self):
        help_text = LOAD._build_parser().format_help()
        self.assertIn("AIR", help_text)
        self.assertIn("type=air", help_text)
        self.assertIn("p2p-air.json", help_text)
        self.assertIn("USER_MANUAL.md", help_text)

        with redirect_stdout(io.StringIO()) as output, self.assertRaises(
            SystemExit,
        ) as help_exit:
            UNLOAD.parse_args(["--help"])
        self.assertEqual(0, help_exit.exception.code)
        self.assertIn("USER_MANUAL.md", output.getvalue())

        self.assertTrue(LOAD.parse_args(["sample", "--dry-run"]).dry_run)
        for abbreviated in ("--dry", "--dry-r", "--dry-ru"):
            with self.subTest(option=abbreviated), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    LOAD.parse_args(["sample", abbreviated])

        command = LOAD.actual_run_command([
            "sample", "--dry-run", "--no-upgrade",
            "--ztp-monitor-scope", "air",
        ])
        self.assertNotIn("--dry-run", command)
        self.assertIn("--no-upgrade", command)
        self.assertIn("--ztp-monitor-scope", command)
        self.assertIn("air", command)

        rendered = LOAD.dry_run_next_step([
            "sample", "--dry-run", "--no-upgrade",
            "--ztp-monitor-scope", "air",
        ])
        self.assertTrue(rendered.startswith("[NEXT] dry-run 已完成；"))
        self.assertNotIn(" --dry-run", rendered)
        self.assertIn(" --no-upgrade", rendered)
        self.assertIn(" --ztp-monitor-scope air", rendered)

    def test_inherited_descriptor_survives_exec_without_self_deadlock(self):
        with tempfile.TemporaryDirectory() as directory:
            with LOCKS.deployment_lock(directory) as descriptor:
                code = (
                    f"import sys; sys.path.insert(0, {str(TOOLS)!r})\n"
                    "from deployment_lock import deployment_lock\n"
                    f"with deployment_lock({directory!r}):\n    pass\n"
                )
                result = subprocess.run(
                    [sys.executable, "-c", code], cwd=ROOT, text=True,
                    capture_output=True,
                    **LOCKS.inherited_lock_subprocess_kwargs(descriptor),
                )
                self.assertEqual(0, result.returncode, result.stderr)
                with self.assertRaises(LOCKS.DeploymentLockError):
                    with LOCKS.deployment_lock(directory):
                        pass

    def test_unload_passes_held_descriptor_to_unsetup_subprocess(self):
        with tempfile.TemporaryDirectory() as directory:
            with LOCKS.deployment_lock(directory) as descriptor:
                completed = SimpleNamespace(returncode=0)
                with mock.patch.object(
                    UNLOAD.subprocess, "run", return_value=completed,
                ) as runner, redirect_stdout(io.StringIO()):
                    UNLOAD.remove_project_links(
                        None, dry_run=False,
                        deployment_lock_descriptor=descriptor,
                    )
        kwargs = runner.call_args.kwargs
        self.assertEqual((descriptor,), kwargs["pass_fds"])
        self.assertEqual(str(descriptor), kwargs["env"][LOCKS.LOCK_FD_ENV])

    def test_setup_and_unsetup_fail_before_body_when_lock_is_busy(self):
        with tempfile.TemporaryDirectory() as directory:
            for module, argv in ((SETUP, ["project"]), (UNSETUP, ["-y"])):
                body = mock.Mock(return_value=0)
                with self.subTest(entry=module.__name__), LOCKS.deployment_lock(directory):
                    with (
                        mock.patch.object(module, "HTTP_BASE", directory),
                        mock.patch.object(module, "_main_locked", body),
                        redirect_stdout(io.StringIO()),
                    ):
                        self.assertEqual(1, module.main(argv))
                body.assert_not_called()

    def test_unload_fails_before_mutation_when_lock_is_busy(self):
        with tempfile.TemporaryDirectory() as directory:
            stop = mock.Mock()
            with LOCKS.deployment_lock(directory):
                with (
                    mock.patch.object(UNLOAD, "HTTP_ROOT", Path(directory)),
                    mock.patch.object(UNLOAD, "resolve_project", return_value=None),
                    mock.patch.object(UNLOAD, "confirm", return_value=True),
                    mock.patch.object(UNLOAD, "stop_monitor", stop),
                    mock.patch.object(UNLOAD.os, "geteuid", return_value=0),
                    redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()),
                ):
                    self.assertEqual(1, UNLOAD.main(["-y"]))
            stop.assert_not_called()


class AtomicArchiveAndImportTests(unittest.TestCase):
    @staticmethod
    def regular(name: str) -> tarfile.TarInfo:
        member = tarfile.TarInfo(name)
        member.size = 0
        return member

    def test_reproducible_tarinfo_normalizes_every_supported_member_type(self):
        cases = (
            ("regular", tarfile.REGTYPE, 0o600, tarfile.REGTYPE, 0o644),
            ("executable", tarfile.REGTYPE, 0o700, tarfile.REGTYPE, 0o755),
            ("directory", tarfile.DIRTYPE, 0o700, tarfile.DIRTYPE, 0o755),
            ("symlink", tarfile.SYMTYPE, 0o600, tarfile.SYMTYPE, 0o777),
        )
        for label, member_type, mode, expected_type, expected_mode in cases:
            with self.subTest(label=label):
                member = tarfile.TarInfo(f"tree/{label}")
                member.type = member_type
                member.mode = mode
                member.mtime = 1_700_000_000
                member.uid = 501
                member.gid = 20
                member.uname = "host-user"
                member.gname = "host-group"
                if member.issym():
                    member.linkname = "target"

                normalized = PACKAGE._reproducible_tarinfo(member)

                self.assertEqual(expected_type, normalized.type)
                self.assertEqual(expected_mode, normalized.mode)
                self.assertEqual(0, normalized.mtime)
                self.assertEqual(0, normalized.uid)
                self.assertEqual(0, normalized.gid)
                self.assertEqual("", normalized.uname)
                self.assertEqual("", normalized.gname)
                if label == "symlink":
                    self.assertEqual("target", normalized.linkname)

        hardlink = tarfile.TarInfo("tree/hardlink")
        hardlink.type = tarfile.LNKTYPE
        hardlink.linkname = "tree/regular"
        hardlink.mode = 0o600
        normalized = PACKAGE._reproducible_tarinfo(hardlink)
        self.assertEqual(tarfile.REGTYPE, normalized.type)
        self.assertEqual("", normalized.linkname)
        self.assertEqual(0o644, normalized.mode)

    def test_reproducible_tarinfo_rejects_special_nodes_without_root(self):
        for label, member_type in (
            ("fifo", tarfile.FIFOTYPE),
            ("character-device", tarfile.CHRTYPE),
            ("block-device", tarfile.BLKTYPE),
        ):
            with self.subTest(label=label):
                member = tarfile.TarInfo(f"tree/{label}")
                member.type = member_type
                member.mode = 0o666
                with self.assertRaises(ValueError):
                    PACKAGE._reproducible_tarinfo(member)

    def test_deployment_archive_rejects_escape_duplicate_and_special_members(self):
        escape = tarfile.TarInfo("dir/link")
        escape.type = tarfile.SYMTYPE
        escape.linkname = "../../outside"
        fifo = tarfile.TarInfo("pipe")
        fifo.type = tarfile.FIFOTYPE
        bad_sets = [
            [self.regular("../outside")],
            [self.regular("./same"), self.regular("same")],
            [escape],
            [fifo],
        ]
        for members in bad_sets:
            with self.subTest(member=members[-1].name):
                with self.assertRaises(RuntimeError):
                    PACKAGE.validate_deployment_archive_members(members)

    def test_deployment_archive_accepts_contained_relative_symlink(self):
        link = tarfile.TarInfo("dir/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../target"
        PACKAGE.validate_deployment_archive_members([
            self.regular("target"), link,
        ])

    def test_download_force_keeps_old_archive_until_atomic_replace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            output = root / "result.tar.gz"
            output.write_bytes(b"old")
            resolved = DOWNLOAD.resolve_output(output, "x", source, force=True)
            self.assertEqual(output.resolve(), resolved)
            self.assertEqual(b"old", output.read_bytes())

    def test_download_rejects_symlink_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            target = root / "target"
            target.write_bytes(b"secret")
            output = root / "result.tar.gz"
            output.symlink_to(target)
            with self.assertRaises(ValueError):
                DOWNLOAD.resolve_output(output, "x", source, force=True)
            self.assertEqual(b"secret", target.read_bytes())

    def test_download_archive_has_operator_requested_read_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "DAY0-Prepare/customer"
            project.mkdir(parents=True)
            (project / "02-devices_config.csv").write_text("hostname,type\n", encoding="utf-8")
            output = root / "download.tar.gz"
            args = argparse.Namespace(all_day0=False, project="customer", output=output, force=False)
            with (
                mock.patch.object(DOWNLOAD.package_core, "resolve_project", return_value=project),
                mock.patch.object(DOWNLOAD.package_core, "managed_pubkey_paths", return_value=[]),
                redirect_stdout(io.StringIO()),
            ):
                DOWNLOAD.create_day0_archive(args)
            self.assertEqual(0o644, stat.S_IMODE(output.stat().st_mode))

    def test_review_snapshot_and_extracted_files_are_private(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "download.tar.gz"
            archive_path.write_bytes(b"placeholder")
            review = IMPORTER.unique_review_dir(root / "reviews", archive_path)
            payload = io.BytesIO()
            with tarfile.open(fileobj=payload, mode="w") as archive:
                directory_member = tarfile.TarInfo("DAY0-Prepare/customer")
                directory_member.type = tarfile.DIRTYPE
                directory_member.mode = 0o755
                archive.addfile(directory_member)
                data = b"password: example\n"
                file_member = tarfile.TarInfo("DAY0-Prepare/customer/01-global.yaml")
                file_member.mode = 0o644
                file_member.size = len(data)
                archive.addfile(file_member, io.BytesIO(data))
            payload.seek(0)
            with tarfile.open(fileobj=payload, mode="r") as archive:
                members = archive.getmembers()
                IMPORTER.safe_extract(
                    archive, [(member, member.name) for member in members], review,
                )
            extracted = review / "DAY0-Prepare/customer/01-global.yaml"
            self.assertEqual(0o700, stat.S_IMODE(review.stat().st_mode))
            self.assertEqual(0o700, stat.S_IMODE(extracted.parent.stat().st_mode))
            self.assertEqual(0o600, stat.S_IMODE(extracted.stat().st_mode))

    def test_import_validation_rejects_project_symlink_escape(self):
        link = tarfile.TarInfo("DAY0-Prepare/customer/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../../outside"
        with self.assertRaises(IMPORTER.ImportErrorSafe):
            IMPORTER.validate_members([link], ["customer"], 1024)


class SetupUnloadAndTransportTests(unittest.TestCase):
    @staticmethod
    def _fresh_monitor_inventory_fixture(root: Path):
        project = root / "DAY0-Prepare/customer"
        inventory = project / "02-devices_config.csv"
        inventory.parent.mkdir(parents=True)
        inventory.write_text(
            "hostname,type,eth0_ip\n",
            encoding="utf-8",
        )
        sources = {
            "ethernet/eth.csv": inventory,
            "infiniband/ib.csv": inventory,
            "nvlink/nvsw.csv": inventory,
        }
        for relative, target in sources.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.symlink_to(os.path.relpath(target, path.parent))
        return project, inventory

    def test_setup_recreates_fixed_monitor_inventory_aliases_with_exact_targets(
        self,
    ):
        expected = {
            "ethernet/monitor/eth.csv": "../eth.csv",
            "infiniband/monitor/ib.csv": "../ib.csv",
            "nvlink/monitor/nvsw.csv": "../nvsw.csv",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project, inventory = self._fresh_monitor_inventory_fixture(root)
            with mock.patch.multiple(
                SETUP,
                HTTP_BASE=str(root),
                ZTP=str(root / "ztp"),
                _DRY_RUN=False,
                _LINK_ERRORS=0,
            ), redirect_stdout(io.StringIO()):
                managed = set(SETUP._collect_expected_links(str(project)))
                SETUP._process_monitor_links(str(project))

            self.assertTrue(
                {os.fspath(root / relative) for relative in expected} <= managed,
            )
            for relative, target in expected.items():
                with self.subTest(alias=relative):
                    alias = root / relative
                    self.assertTrue(alias.is_symlink(), relative)
                    self.assertEqual(target, os.readlink(alias))
                    self.assertEqual(inventory.resolve(), alias.resolve(strict=True))

    def test_upload_omits_monitor_aliases_and_setup_recreates_them_before_collection(
        self,
    ):
        expected = {
            "ethernet/monitor/eth.csv": "../eth.csv",
            "infiniband/monitor/ib.csv": "../ib.csv",
            "nvlink/monitor/nvsw.csv": "../nvsw.csv",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package_filter = PACKAGE.PackageFilter(
                ROOT / "DAY0-Prepare/template",
                root / "upload.tar.gz",
                include_images=False,
                include_apps=False,
                include_firmware=False,
                max_file_size=50 * 1024 * 1024,
                day0_all=False,
            )
            for relative in expected:
                member = tarfile.TarInfo(relative)
                member.type = tarfile.SYMTYPE
                member.linkname = expected[relative]
                with self.subTest(archive_member=relative):
                    self.assertIsNone(package_filter(member))
            self.assertEqual(
                3,
                package_filter.reasons.get("setup-managed runtime link"),
            )

            project, inventory = self._fresh_monitor_inventory_fixture(root)
            with mock.patch.multiple(
                SETUP,
                HTTP_BASE=str(root),
                ZTP=str(root / "ztp"),
                _DRY_RUN=False,
                _LINK_ERRORS=0,
            ), redirect_stdout(io.StringIO()):
                SETUP._process_monitor_links(str(project))

            for relative, target in expected.items():
                with self.subTest(restored_alias=relative):
                    alias = root / relative
                    self.assertTrue(alias.is_symlink(), relative)
                    self.assertEqual(target, os.readlink(alias))
                    self.assertEqual(inventory.resolve(), alias.resolve(strict=True))

    def test_setup_refuses_dangling_monitor_aliases_without_network_inventory(
        self,
    ):
        expected = (
            "ethernet/monitor/eth.csv",
            "infiniband/monitor/ib.csv",
            "nvlink/monitor/nvsw.csv",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "DAY0-Prepare/customer"
            project.mkdir(parents=True)
            with mock.patch.multiple(
                SETUP,
                HTTP_BASE=str(root),
                ZTP=str(root / "ztp"),
                _DRY_RUN=False,
                _LINK_ERRORS=0,
            ), redirect_stdout(io.StringIO()):
                SETUP._process_monitor_links(str(project))
                errors = SETUP._LINK_ERRORS

            self.assertEqual(3, errors)
            for relative in expected:
                with self.subTest(alias=relative):
                    self.assertFalse(os.path.lexists(root / relative))

    @staticmethod
    def _write_project_contract(day0: Path, name: str) -> Path:
        project = day0 / name
        project.mkdir(parents=True)
        for filename in (
            "01-global.yaml", "02-devices_config.csv",
            "02-dhcp-subnet_config.csv",
        ):
            (project / filename).write_text(filename + "\n", encoding="utf-8")
        (project / "99-output-ztp").mkdir()
        return project

    @staticmethod
    def _publish_active_identity(root: Path, project: Path) -> tuple[Path, list[Path]]:
        ztp = root / "ztp"
        targets = {
            ztp / "config/cumulus/template/01-global.yaml": project / "01-global.yaml",
            ztp / "config/cumulus/template/02-devices_config.csv": (
                project / "02-devices_config.csv"
            ),
            ztp / "config/isc-dhcp-server/02-subnet_config.csv": (
                project / "02-dhcp-subnet_config.csv"
            ),
            ztp / "status": project / "99-output-ztp",
        }
        for link, target in targets.items():
            link.parent.mkdir(parents=True, exist_ok=True)
            link.symlink_to(os.path.relpath(target, link.parent))
        manifest = ztp / ".setup_manifest"
        manifest.write_text(
            f"# setup manifest — proj: {project.resolve()}\n"
            + "".join(f"{path}\n" for path in sorted(targets)),
            encoding="utf-8",
        )
        return manifest, sorted(targets)

    def test_native_status_and_project_list_are_read_only_and_identity_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            day0 = root / "DAY0-Prepare"
            active = self._write_project_contract(day0, "active")
            inactive = self._write_project_contract(day0, "inactive")
            incomplete = day0 / "incomplete"
            incomplete.mkdir()
            (day0 / "template").mkdir()
            (day0 / "alias").symlink_to(active.name)
            manifest, links = self._publish_active_identity(root, active)
            lock = root / ".deployment.lock"

            with mock.patch.multiple(
                SETUP,
                HERE=str(day0), HTTP_BASE=str(root), ZTP=str(root / "ztp"),
                MANIFEST_FILE=str(manifest),
            ):
                identity = SETUP.inspect_active_project()
                self.assertEqual(active, identity["project"])
                self.assertEqual(len(links), identity["managed_link_count"])
                projects = SETUP.discover_projects()
                self.assertEqual(
                    [("active", True), ("inactive", False)],
                    [(item["name"], item["active"]) for item in projects],
                )

                with mock.patch.object(
                    SETUP, "deployment_lock",
                    side_effect=AssertionError("read-only discovery must not lock"),
                ):
                    with redirect_stdout(io.StringIO()):
                        self.assertEqual(0, SETUP.main(["--status"]))
                        self.assertEqual(0, SETUP.main(["--list-projects"]))
                self.assertFalse(os.path.lexists(lock))

                links[1].unlink()
                links[1].symlink_to(os.path.relpath(
                    inactive / "02-devices_config.csv", links[1].parent,
                ))
                with self.assertRaisesRegex(ValueError, "活动项目身份"):
                    SETUP.inspect_active_project()

    def test_native_status_rejects_linked_or_oversized_identity_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            day0 = root / "DAY0-Prepare"
            active = self._write_project_contract(day0, "active")
            manifest, _links = self._publish_active_identity(root, active)
            original = manifest.read_bytes()
            forged = root / "forged-manifest"
            forged.write_bytes(original)

            with mock.patch.multiple(
                SETUP,
                HERE=str(day0), HTTP_BASE=str(root), ZTP=str(root / "ztp"),
                MANIFEST_FILE=str(manifest),
            ):
                manifest.unlink()
                manifest.symlink_to(forged)
                with self.assertRaisesRegex(ValueError, "安全读取"):
                    SETUP.inspect_active_project()

                manifest.unlink()
                manifest.write_bytes(
                    b"x" * (SETUP.MAX_DISCOVERY_METADATA_BYTES + 1)
                )
                with self.assertRaisesRegex(ValueError, "不超过"):
                    SETUP.inspect_active_project()

            fifo = root / "fifo-manifest"
            os.mkfifo(fifo)
            probe = "\n".join((
                "import importlib.util, pathlib, sys",
                f"sys.path.insert(0, {str(TOOLS)!r})",
                f"path = pathlib.Path({str(ROOT / 'DAY0-Prepare/01-a-setup.py')!r})",
                "spec = importlib.util.spec_from_file_location('fifo_setup_probe', path)",
                "module = importlib.util.module_from_spec(spec)",
                "sys.modules[spec.name] = module",
                "spec.loader.exec_module(module)",
                "try:",
                f"    module._read_bounded_regular_text({str(fifo)!r}, 'setup manifest')",
                "except ValueError:",
                "    raise SystemExit(0)",
                "raise SystemExit(9)",
            ))
            try:
                result = subprocess.run(
                    [sys.executable, "-B", "-c", probe], cwd=ROOT,
                    text=True, capture_output=True, timeout=2, check=False,
                )
            except subprocess.TimeoutExpired:
                self.fail("FIFO manifest blocked instead of failing closed")
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)

        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            SETUP._parse_args(["--status", "active"])

    def test_output_usage_is_bounded_to_real_project_outputs_and_never_prunes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            project = self._write_project_contract(root, "project")
            output = project / "99-output-eth"
            output.mkdir()
            (output / "first.yaml").write_bytes(b"a" * 11)
            nested = output / "release"
            nested.mkdir()
            (nested / "second.yaml").write_bytes(b"b" * 13)
            outside = root / "outside.bin"
            outside.write_bytes(b"x" * 1000)
            (output / "outside-link").symlink_to(outside)

            with mock.patch.object(SETUP, "HERE", str(root)):
                usage = SETUP.measure_output_usage(project)

            self.assertEqual(24, usage["bytes"])
            self.assertEqual(2, usage["files"])
            self.assertEqual(1, usage["skipped_links"])
            self.assertTrue(outside.exists())
            self.assertEqual([], usage["unsafe"])

            with mock.patch.object(SETUP, "OUTPUT_USAGE_WARNING_BYTES", 20):
                rendered = SETUP.format_output_usage(project, usage)
            self.assertIn("24 B", rendered)
            self.assertIn("WARN", rendered)
            self.assertIn("不会自动删除", rendered)

    def test_missing_setup_project_requires_explicit_create_and_never_activates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            template = root / "template"
            template.mkdir()
            (template / "required.txt").write_text("template\n", encoding="utf-8")
            project = root / "typo-project"
            setup = mock.Mock()
            base_args = argparse.Namespace(
                project=project.name,
                csv_dir=None,
                p2p_file=None,
                create=False,
            )

            with mock.patch.multiple(
                SETUP,
                HERE=str(root),
                TEMPLATE_DIR=str(template),
                HTTP_BASE=str(root),
            ), mock.patch.object(SETUP, "setup", setup):
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(1, SETUP._main_locked(base_args))
                self.assertFalse(project.exists())
                setup.assert_not_called()
                self.assertIn("--create", output.getvalue())

                create_args = argparse.Namespace(**{
                    **vars(base_args), "create": True,
                })
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(0, SETUP._main_locked(create_args))
                self.assertEqual(
                    "template\n",
                    (project / "required.txt").read_text(encoding="utf-8"),
                )
                setup.assert_not_called()
                self.assertIn("已创建但未激活", output.getvalue())

    def test_setup_create_dry_run_previews_template_without_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            template = root / "template"
            template.mkdir()
            (template / "required.txt").write_text("template\n", encoding="utf-8")
            project = root / "new-project"
            args = argparse.Namespace(
                project=project.name,
                csv_dir=None,
                p2p_file=None,
                create=True,
            )

            with mock.patch.multiple(
                SETUP,
                HERE=str(root),
                TEMPLATE_DIR=str(template),
                HTTP_BASE=str(root),
                _DRY_RUN=True,
            ), mock.patch.object(SETUP, "setup") as setup:
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(0, SETUP._main_locked(args))

            self.assertFalse(project.exists())
            setup.assert_not_called()
            self.assertIn("[DRY] 从模板复制 required.txt", output.getvalue())
            self.assertIn("不会激活", output.getvalue())

    def test_project_switch_needs_exact_yes_or_dedicated_automation_ack(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            day0 = root / "DAY0-Prepare"
            old_project = day0 / "old"
            new_project = day0 / "new"
            old_project.mkdir(parents=True)
            new_project.mkdir()
            target = old_project / "01-global.yaml"
            target.write_text("old\n", encoding="utf-8")
            managed = root / "ztp/config/01-global.yaml"
            managed.parent.mkdir(parents=True)

            def restore_link():
                managed.unlink(missing_ok=True)
                managed.symlink_to(target)

            patches = (
                mock.patch.multiple(
                    SETUP,
                    HERE=str(day0),
                    HTTP_BASE=str(root),
                    ZTP=str(root / "ztp"),
                    _NET_CSV_LINKS=[],
                    _DRY_RUN=False,
                ),
                mock.patch.object(
                    SETUP, "_managed_ztp_link_candidates",
                    return_value=[str(managed)],
                ),
                mock.patch.object(SETUP, "_monitor_link_paths", return_value=[]),
                mock.patch.object(SETUP, "_bringup_link_pairs", return_value=[]),
                mock.patch.object(SETUP, "_analyzer_input_pairs", return_value=[]),
                mock.patch.object(SETUP, "_analyzer_output_pairs", return_value=[]),
                mock.patch.object(
                    SETUP, "_legacy_project_monitor_csv_links", return_value=[],
                ),
            )

            with ExitStack() as stack:
                for patcher in patches:
                    stack.enter_context(patcher)

                restore_link()
                with mock.patch.object(SETUP, "_AUTO_YES", True), \
                        mock.patch.object(
                            SETUP, "_CONFIRM_PROJECT_SWITCH", False,
                            create=True,
                        ), redirect_stdout(io.StringIO()):
                    self.assertFalse(SETUP._unsetup_previous(str(new_project)))
                self.assertTrue(managed.is_symlink())

                restore_link()
                with mock.patch.object(SETUP, "_AUTO_YES", False), \
                        mock.patch.object(
                            SETUP, "_CONFIRM_PROJECT_SWITCH", False,
                            create=True,
                        ), mock.patch.object(
                            SETUP.sys.stdin, "isatty", return_value=True,
                        ), mock.patch("builtins.input", return_value="y"), \
                        redirect_stdout(io.StringIO()):
                    self.assertFalse(SETUP._unsetup_previous(str(new_project)))
                self.assertTrue(managed.is_symlink())

                restore_link()
                with mock.patch.object(SETUP, "_AUTO_YES", False), \
                        mock.patch.object(
                            SETUP, "_CONFIRM_PROJECT_SWITCH", False,
                            create=True,
                        ), mock.patch.object(
                            SETUP.sys.stdin, "isatty", return_value=True,
                        ), mock.patch("builtins.input", return_value="yes"), \
                        redirect_stdout(io.StringIO()):
                    self.assertTrue(SETUP._unsetup_previous(str(new_project)))
                self.assertFalse(managed.exists())

                restore_link()
                with mock.patch.object(SETUP, "_AUTO_YES", True), \
                        mock.patch.object(
                            SETUP, "_CONFIRM_PROJECT_SWITCH", True,
                            create=True,
                        ), redirect_stdout(io.StringIO()):
                    self.assertTrue(SETUP._unsetup_previous(str(new_project)))
                self.assertFalse(managed.exists())

    def test_unload_supervisor_backend_stops_all_programs_without_systemctl(self):
        calls = []

        class Backend:
            name = "supervisor"

            @staticmethod
            def is_active(service):
                calls.append(("active", service))
                return True

            @staticmethod
            def stop(service):
                calls.append(("stop", service))

        backend = Backend()
        with mock.patch.object(
            UNLOAD.subprocess, "run",
            side_effect=AssertionError(
                "supervisor unload path must not invoke systemctl"
            ),
        ), mock.patch.object(
            UNLOAD, "process_cmdline",
            side_effect=AssertionError(
                "supervisor unload path must not inspect detached PID files"
            ),
        ):
            UNLOAD.stop_monitor(None, dry_run=False, runtime_backend=backend)
            UNLOAD.stop_monitor_workers(dry_run=False, runtime_backend=backend)
            UNLOAD.stop_services(dry_run=False, runtime_backend=backend)

        self.assertEqual(
            [
                ("stop", "ztp-monitor"),
                ("stop", "switch-collection"),
                ("stop", "manual-ztp"),
                ("stop", "isc-dhcp-server"),
                ("stop", "apache2"),
            ],
            [call for call in calls if call[0] == "stop"],
        )

    def test_unload_supervisor_rejects_systemd_infra_teardown(self):
        with self.assertRaisesRegex(UNLOAD.UnloadError, "--teardown-infra"):
            UNLOAD.validate_runtime_options(
                SimpleNamespace(teardown_infra=True),
                SimpleNamespace(name="supervisor"),
            )
        UNLOAD.validate_runtime_options(
            SimpleNamespace(teardown_infra=True),
            SimpleNamespace(name="systemd"),
        )

    def test_setup_manifest_is_atomic_and_failure_preserves_previous_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / ".setup_manifest"
            manifest.write_text("old\n", encoding="utf-8")
            link = root / "managed-link"
            link.symlink_to("target")
            with (
                mock.patch.object(SETUP, "MANIFEST_FILE", str(manifest)),
                mock.patch.object(SETUP, "_collect_expected_links", return_value=[str(link)]),
                mock.patch.object(SETUP.os, "replace", side_effect=OSError("disk full")),
            ):
                with self.assertRaises(OSError):
                    SETUP._write_manifest(str(root))
            self.assertEqual("old\n", manifest.read_text(encoding="utf-8"))
            self.assertEqual([], list(root.glob(".setup_manifest.*")))

    def test_setup_manifest_success_has_stable_private_safe_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / ".setup_manifest"
            link = root / "managed-link"
            link.symlink_to("target")
            with (
                mock.patch.object(SETUP, "MANIFEST_FILE", str(manifest)),
                mock.patch.object(SETUP, "_collect_expected_links", return_value=[str(link)]),
                redirect_stdout(io.StringIO()),
            ):
                SETUP._write_manifest(str(root))
            self.assertIn(str(link), manifest.read_text(encoding="utf-8"))
            self.assertEqual(0o644, stat.S_IMODE(manifest.stat().st_mode))

    def test_unsetup_rolls_back_links_after_mid_delete_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first"
            second = root / "second"
            first.symlink_to("target-one")
            second.symlink_to("target-two")
            real_remove = os.remove

            def fail_second(path):
                if os.fspath(path) == os.fspath(second):
                    raise OSError("injected unlink failure")
                return real_remove(path)

            args = SimpleNamespace(project=None)
            with (
                mock.patch.object(UNSETUP, "HTTP_BASE", str(root)),
                mock.patch.object(UNSETUP, "_read_manifest", return_value=(None, None)),
                mock.patch.object(
                    UNSETUP, "_known_ztp_project_links", return_value=[str(first), str(second)],
                ),
                mock.patch.object(UNSETUP, "_known_workspace_links", return_value=[]),
                mock.patch.object(UNSETUP.os, "remove", side_effect=fail_second),
                redirect_stdout(io.StringIO()),
            ):
                UNSETUP._AUTO_YES = True
                UNSETUP._DRY_RUN = False
                self.assertEqual(1, UNSETUP._main_locked(args))
            self.assertTrue(first.is_symlink())
            self.assertEqual("target-one", os.readlink(first))
            self.assertTrue(second.is_symlink())
            self.assertEqual("target-two", os.readlink(second))

    def test_unload_dhcp_mismatch_preflight_makes_no_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            mutations = {
                name: mock.Mock()
                for name in (
                    "stop_monitor", "stop_monitor_workers", "stop_services",
                    "remove_ztp_prefix_publication", "remove_project_links",
                )
            }
            with (
                mock.patch.multiple(UNLOAD, **mutations),
                mock.patch.object(UNLOAD, "HTTP_ROOT", Path(directory)),
                mock.patch.object(UNLOAD, "resolve_project", return_value=None),
                mock.patch.object(UNLOAD, "confirm", return_value=True),
                mock.patch.object(
                    UNLOAD, "unmanaged_dhcp_runtime_files",
                    return_value=[Path("/etc/dhcp/dhcpd.conf")],
                ),
                mock.patch.object(UNLOAD.os, "geteuid", return_value=0),
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(1, UNLOAD.main(["-y"]))
            for mutation in mutations.values():
                mutation.assert_not_called()

    def test_locked_deployment_rechecks_checksum_before_publication_marker(self):
        digest = hashlib.sha256(b"payload").hexdigest()
        args = SimpleNamespace(
            remote_root="/var/www/html", no_sudo=False, runtime="native",
            deployment_guard_source=(
                ROOT / "tools/deployment_prewrite_guard.py"
            ).read_text(encoding="utf-8"),
            deployment_source_manifest_sha256="b" * 64,
        )
        command = UPLOAD.deployment_payload_command(args, "/tmp/payload.tar.gz", digest)
        remote = __import__("shlex").split(command)
        script = remote[4]
        self.assertIn("O_NOFOLLOW", script)
        self.assertIn("_write_sync_marker", script)
        self.assertIn("_extract_archive_staging", script)
        self.assertIn("_preflight_live_overlay", script)
        self.assertEqual(digest, remote[remote.index("--archive-sha256") + 1])
        self.assertEqual(
            "b" * 64, remote[remote.index("--source-manifest-sha256") + 1],
        )

    def test_upload_host_validation_and_offline_jq_contract(self):
        self.assertIn("jq", UPLOAD.REQUIRED_OFFLINE_PACKAGES)
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "payload.tar.gz"
            archive.write_bytes(b"payload")
            args = SimpleNamespace(
                host="user@host;touch", remote_dir="/tmp", remote_root="/var/www/html",
                upload_retries=3, transfer_timeout=3600, port=22,
            )
            with self.assertRaises(ValueError):
                UPLOAD.upload(args, archive)

    def test_broken_sync_marker_blocks_load_and_remote_marker_uses_type_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / ".sync-code-in-progress"
            marker.symlink_to("missing")
            self.assertTrue(LOAD.sync_marker_present(marker))
        args = SimpleNamespace(
            remote_root="/var/www/html", dry_run=False, host="host", sudo=True,
            port=22, identity=None,
        )
        completed = SimpleNamespace(returncode=0)
        with mock.patch.object(SYNC.subprocess, "run", return_value=completed) as runner:
            SYNC.set_remote_sync_marker(args, present=True)
        command = runner.call_args.args[0]
        self.assertEqual("host", command[-2])
        remote = __import__("shlex").split(command[-1])
        self.assertEqual(["sudo", "-n", "sh", "-c"], remote[:4])
        self.assertEqual("sync-marker", remote[-2])
        self.assertEqual("/var/www/html/.sync-code-in-progress", remote[-1])
        marker_script = remote[4]
        self.assertIn('[ -L "$marker" ]', marker_script)
        self.assertIn("stat -Lc %h", marker_script)

    def test_infra_teardown_can_restore_setup_managed_hosts(self):
        teardown = (ROOT / "infra/infra-teardown.sh").read_text(encoding="utf-8")
        setup = (ROOT / "infra/infra-setup.sh").read_text(encoding="utf-8")
        self.assertIn("/etc/hosts|/etc/systemd/resolved.conf", teardown)
        self.assertIn("restore_file /etc/hosts", teardown)
        self.assertLess(teardown.index("flock -x 9"), teardown.index('mkdir -p "$log_dir"'))
        self.assertLess(setup.index("flock -x 9"), setup.index('mkdir -p "$log_dir"'))


class InfraAndAnalysisParserTests(unittest.TestCase):
    def test_infra_global_parser_and_source_ip_consistency_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            global_file = Path(directory) / "01-global.yaml"
            global_file.write_text(
                """common:\n  switch:\n    system:\n      dns:\n        server: [1.1.1.1]\n      ntp:\n        server: [2.2.2.2]\n      date-time:\n        timezone: Asia/Taipei\n""",
                encoding="utf-8",
            )
            self.assertEqual(
                (["1.1.1.1"], ["2.2.2.2"], "Asia/Taipei"),
                DEPLOY.load_common(global_file),
            )
        servers = [
            {"hostname": "a", "address": "192.0.2.1"},
            {"hostname": "b", "address": "192.0.2.2"},
        ]
        with mock.patch.object(
            DEPLOY, "detect_route_source_ipv4",
            side_effect=["192.0.2.10", "192.0.2.11"],
        ), redirect_stdout(io.StringIO()):
            with self.assertRaises(DEPLOY.DeployError):
                DEPLOY.determine_http_source_ip(servers)

    def test_ib_shared_tool_copy_contract_and_explicit_extensions(self):
        left = TOOLS / "ib-tool-Jie/ib_tool_box"
        right = TOOLS / "ibdiagnet-analyze-tool"
        left_files = {path.relative_to(left).as_posix(): path for path in left.rglob("*.py")}
        right_files = {path.relative_to(right).as_posix(): path for path in right.rglob("*.py")}
        self.assertEqual(set(), set(left_files) - set(right_files))
        self.assertEqual(
            {"analyze.py", "lib/parsers/iblinkinfo.py", "lib/snapshot.py", "lib/topology.py"},
            set(right_files) - set(left_files),
        )
        differing = set()
        for relative in set(left_files) & set(right_files):
            if left_files[relative].read_bytes() != right_files[relative].read_bytes():
                differing.add(relative)
        self.assertEqual({"scripts/validate_ib_topology.py"}, differing)

    def test_ib_parser_normalization_and_snapshot_traversal_gate(self):
        base = TOOLS / "ibdiagnet-analyze-tool/lib"
        partitions = load_module(
            "ops_review_partitions", base / "parsers/partitions_conf.py"
        )
        net_dump_ext = load_module(
            "ops_review_net_dump_ext", base / "parsers/net_dump_ext.py"
        )
        snapshot = load_module("ops_review_snapshot", base / "snapshot.py")
        self.assertEqual("0x115", partitions._normalize_pkey("0x0115"))
        self.assertEqual("0x0000000000000001", partitions._normalize_guid("0x1"))
        with self.assertRaises(ValueError):
            partitions._normalize_pkey("0x8000")
        self.assertEqual(17, net_dump_ext._parse_lid("17 (0x11)"))
        self.assertTrue(net_dump_ext._parse_ber("1e-12") < 1e-11)
        with self.assertRaises(ValueError):
            snapshot._safe_member_name("../../etc/passwd")

    def test_lldp_dot_parser_deduplicates_canonical_links(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "topology.dot"
            path.write_text(
                '"leaf01":"swp1" -- "spine01":"swp1"\n', encoding="utf-8"
            )
            links = LLDP.parse_dot(path)
            self.assertEqual(1, len(links))
            path.write_text(
                '"leaf01":"swp1" -- "spine01":"swp1"\n'
                '"spine01":"swp1" -- "leaf01":"swp1"\n',
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                LLDP.parse_dot(path)


if __name__ == "__main__":
    unittest.main()
