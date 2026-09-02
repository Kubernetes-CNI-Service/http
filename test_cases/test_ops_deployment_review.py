"""Deployment, packaging, setup, unload, and infrastructure review cases."""

from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
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


class ScopedSourceAndEntryPointTests(unittest.TestCase):
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


class SharedDeploymentLockTests(unittest.TestCase):
    def test_actual_writers_exclude_a_second_open_description(self):
        with tempfile.TemporaryDirectory() as directory:
            with LOCKS.deployment_lock(directory):
                with self.assertRaises(LOCKS.DeploymentLockError):
                    with LOCKS.deployment_lock(directory):
                        pass

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
        args = SimpleNamespace(remote_root="/var/www/html", no_sudo=False)
        command = UPLOAD.deployment_payload_command(args, "/tmp/payload.tar.gz", digest)
        remote = __import__("shlex").split(command)
        script = remote[4]
        self.assertIn("stat -Lc %h", script)
        self.assertIn("unsafe sync marker", script)
        self.assertLess(script.index("sha256sum -c"), script.index("install -m 0644"))
        self.assertLess(script.index("install -m 0644"), script.index("tar "))

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
