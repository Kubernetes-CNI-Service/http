#!/usr/bin/env python3
"""Upload archive deployment-input and image-free XLSX contracts."""

from __future__ import annotations

import argparse
import errno
import hashlib
import importlib.util
import inspect
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET
import zipfile

from test_cases.public_project_fixture import materialized_public_project


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import _package_common as package


UPLOAD_SPEC = importlib.util.spec_from_file_location(
    "tar_for_upload_contract", TOOLS / "tar-for-upload.py"
)
assert UPLOAD_SPEC and UPLOAD_SPEC.loader
upload_tool = importlib.util.module_from_spec(UPLOAD_SPEC)
UPLOAD_SPEC.loader.exec_module(upload_tool)

DOWNLOAD_SPEC = importlib.util.spec_from_file_location(
    "tar_for_download_contract", TOOLS / "tar-for-download.py"
)
assert DOWNLOAD_SPEC and DOWNLOAD_SPEC.loader
download_tool = importlib.util.module_from_spec(DOWNLOAD_SPEC)
DOWNLOAD_SPEC.loader.exec_module(download_tool)

INSTALLER_SPEC = importlib.util.spec_from_file_location(
    "upload_package_relay_installer_contract",
    TOOLS / "deploy-upload-archive.py",
)
assert INSTALLER_SPEC and INSTALLER_SPEC.loader
installer_tool = importlib.util.module_from_spec(INSTALLER_SPEC)
sys.modules[INSTALLER_SPEC.name] = installer_tool
INSTALLER_SPEC.loader.exec_module(installer_tool)

LOAD_SPEC = importlib.util.spec_from_file_location(
    "upload_package_real_load_contract", ROOT / "DAY0-Prepare/11-load.py"
)
assert LOAD_SPEC and LOAD_SPEC.loader
load_tool = importlib.util.module_from_spec(LOAD_SPEC)
sys.modules[LOAD_SPEC.name] = load_tool
LOAD_SPEC.loader.exec_module(load_tool)


REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
OFFICE_REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
XDR_NS = "http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing"
A_NS = "http://schemas.openxmlformats.org/drawingml/2006/main"

REQUIRED_UPLOAD_SOURCES = (
    ".dockerignore",
    "infra/docker/Dockerfile",
    "infra/docker/Dockerfile.dockerignore",
    "infra/docker/compose.yaml",
    "infra/docker/activate.py",
    "infra/docker/entrypoint.py",
    "infra/docker/healthcheck.py",
    "infra/docker/hostctl.py",
    "infra/docker/hostlock.py",
    "infra/docker/management_ssh_key.py",
    "infra/docker/deploy.sh",
    "infra/docker/supervisord.conf",
    "infra/docker/apache-ztp.conf",
    "infra/docker/rsyslog-dhcp.conf",
    "infra/docker/logrotate-http-ztp.conf",
    "infra/docker/container.env.example",
    "tools/_package_common.py",
    "tools/control-auth.py",
    "tools/deploy-upload-archive.py",
    "tools/deployment_prewrite_guard.py",
    "tools/deployment_lock.py",
    "tools/tar-for-upload.py",
    "tools/tar-for-download.py",
    "tools/sync-code.py",
    "tools/password-update.py",
    "DAY0-Prepare/11-load.py",
    "DAY0-Prepare/12-ztp-monitor.py",
    "DAY0-Prepare/13-unload.py",
    "ztp/nvue_normalizer.py",
    "ztp/config/topology_rules.py",
    "ztp/optimize/feedback.py",
    "ztp/optimize/sample_links.py",
    "ztp/templates/ztp-bootstrap.sh",
    "ztp/templates/ztp.json",
)


def write_picture_workbook(path: Path, marker: str = "cells") -> None:
    drawing = f"""<?xml version="1.0" encoding="UTF-8"?>
<xdr:wsDr xmlns:xdr="{XDR_NS}" xmlns:a="{A_NS}"
 xmlns:r="{OFFICE_REL_NS}">
 <xdr:oneCellAnchor><xdr:from/><xdr:pic><xdr:blipFill>
  <a:blip r:embed="rIdImage"/>
 </xdr:blipFill></xdr:pic><xdr:clientData/></xdr:oneCellAnchor>
 <xdr:twoCellAnchor><xdr:from/><xdr:to/><xdr:sp/><xdr:clientData/></xdr:twoCellAnchor>
</xdr:wsDr>""".encode()
    relationships = f"""<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="{REL_NS}">
 <Relationship Id="rIdImage" Type="{OFFICE_REL_NS}/image" Target="../media/image1.png"/>
</Relationships>""".encode()
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr(
            "xl/workbook.xml",
            f"<workbook><keep>{marker}</keep></workbook>",
        )
        archive.writestr("xl/drawings/drawing1.xml", drawing)
        archive.writestr("xl/drawings/_rels/drawing1.xml.rels", relationships)
        archive.writestr("xl/media/image1.png", b"not-a-real-png-but-an-image-payload" * 200)


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_sparse_self_extracting_image(path: Path) -> None:
    """Create a cheap fixture that still satisfies load's real image checks."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as stream:
        stream.write(b"#!/bin/sh")
        stream.seek(1024 * 1024)
        stream.write(b"\n")


class UploadPackageContractTests(unittest.TestCase):
    @staticmethod
    def _minimal_package_workspace(base: Path) -> tuple[Path, Path, Path]:
        workspace = (base / "http").resolve()
        day0 = workspace / "DAY0-Prepare"
        project = day0 / "customer"
        project.mkdir(parents=True)
        (workspace / "ztp").mkdir()
        (workspace / "tools").mkdir()
        (project / "01-global.yaml").write_text(
            "schema_version: 2\ncommon: {}\n", encoding="utf-8",
        )
        (project / "02-devices_config.csv").write_text(
            "hostname,type\nleaf01,eth\n", encoding="utf-8",
        )
        (project / "02-dhcp-subnet_config.csv").write_text(
            "shared_network,subnet\nmgmt,192.0.2.0\n", encoding="utf-8",
        )
        for relative in REQUIRED_UPLOAD_SOURCES:
            path = workspace / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                path.write_text(f"fixture for {relative}\n", encoding="utf-8")
        return workspace, day0, project

    @staticmethod
    def _stable_source_manifest(destination: Path) -> Path:
        destination.write_bytes(
            b'{"schema_version":1,"sources":{"runtime.py":"fixed"}}\n',
        )
        return destination

    def setUp(self):
        super().setUp()
        self.real_source_manifest_builder = package.write_deployment_source_manifest

        def isolated_manifest(path):
            path.write_text(
                '{"schema_version":1,"files":[]}\n', encoding="ascii",
            )
            return path

        self.manifest_builder_patch = mock.patch.object(
            package, "write_deployment_source_manifest",
            side_effect=isolated_manifest,
        )
        self.manifest_builder_patch.start()

    def tearDown(self):
        self.manifest_builder_patch.stop()
        super().tearDown()

    def test_common_builder_requires_keyword_only_artifact_kind(self):
        parameter = inspect.signature(package.create_package).parameters.get(
            "artifact_kind",
        )
        self.assertIsNotNone(parameter)
        self.assertEqual(inspect.Parameter.KEYWORD_ONLY, parameter.kind)
        self.assertIs(inspect.Parameter.empty, parameter.default)

    def test_common_builder_separates_deployment_authorities_by_artifact_kind(self):
        deployment_authorities = {
            "infra/docker/deployment-source-manifest.json",
            "tools/deployment_prewrite_guard.py",
            "tools/deploy-upload-archive.py",
        }
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            workspace, day0, project = self._minimal_package_workspace(base)
            common_args = dict(
                project=str(project), force=False, max_file_size_mib=50,
                include_images=False, include_apps=False, apps_platform=None,
                apps_platforms=set(), include_firmware=False,
                exclude_project_images=False,
            )
            for artifact_kind in ("upload", "preview", "download"):
                with self.subTest(artifact_kind=artifact_kind):
                    output = base / f"{artifact_kind}.tar.gz"
                    args = argparse.Namespace(output=output, **common_args)
                    with mock.patch.multiple(
                        package,
                        ROOT=workspace,
                        DAY0=day0,
                        MANIFEST=workspace / "ztp/.setup_manifest",
                        TOOLS_DIR=workspace / "tools",
                    ):
                        package.create_package(
                            args, day0_all=True,
                            artifact_kind=artifact_kind,
                        )
                    with tarfile.open(output, "r:gz") as archive:
                        names = {
                            member.name.removeprefix("./")
                            for member in archive.getmembers()
                        }
                    if artifact_kind == "upload":
                        self.assertLessEqual(deployment_authorities, names)
                    else:
                        self.assertTrue(deployment_authorities.isdisjoint(names))

    def test_common_builder_rejects_unknown_artifact_kind_before_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            workspace, day0, project = self._minimal_package_workspace(base)
            common_args = dict(
                project=str(project), force=False, max_file_size_mib=50,
                include_images=False, include_apps=False, apps_platform=None,
                apps_platforms=set(), include_firmware=False,
                exclude_project_images=False,
            )
            invalid_output = base / "invalid-kind.tar.gz"
            invalid_args = argparse.Namespace(output=invalid_output, **common_args)
            with mock.patch.multiple(
                package,
                ROOT=workspace,
                DAY0=day0,
                MANIFEST=workspace / "ztp/.setup_manifest",
                TOOLS_DIR=workspace / "tools",
            ), self.assertRaisesRegex(ValueError, "artifact.kind"):
                    package.create_package(
                        invalid_args, day0_all=True,
                        artifact_kind="deployable-preview",
                    )
            self.assertFalse(invalid_output.exists())

    def test_real_builder_archives_are_accepted_by_installer_only_for_upload(self):
        deployment_authorities = (
            "tools/deploy-upload-archive.py",
            "tools/deployment_prewrite_guard.py",
        )

        def write_bound_manifest(destination: Path) -> Path:
            records = []
            for relative in deployment_authorities:
                records.append({
                    "path": relative,
                    "type": "file",
                    "target": None,
                    "sha256": hashlib.sha256(
                        (workspace / relative).read_bytes(),
                    ).hexdigest(),
                })
            destination.write_text(
                __import__("json").dumps({
                    "schema_version": 1,
                    "files": records,
                }, sort_keys=True) + "\n",
                encoding="ascii",
            )
            return destination

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            workspace, day0, project = self._minimal_package_workspace(base)
            common_args = dict(
                project=str(project), force=False, max_file_size_mib=50,
                include_images=False, include_apps=False, apps_platform=None,
                apps_platforms=set(), include_firmware=False,
                exclude_project_images=False,
            )
            results = {}
            for artifact_kind in ("upload", "preview", "download"):
                output = base / f"installer-{artifact_kind}.tar.gz"
                args = argparse.Namespace(output=output, **common_args)
                with mock.patch.multiple(
                    package,
                    ROOT=workspace,
                    DAY0=day0,
                    MANIFEST=workspace / "ztp/.setup_manifest",
                    TOOLS_DIR=workspace / "tools",
                ), mock.patch.object(
                    package, "write_deployment_source_manifest",
                    side_effect=write_bound_manifest,
                ):
                    package.create_package(
                        args, day0_all=True, artifact_kind=artifact_kind,
                    )
                if artifact_kind == "upload":
                    verified = installer_tool.verify_inputs(
                        output, workspace / "tools/deploy-upload-archive.py",
                        required_uid=os.getuid(),
                    )
                    results[artifact_kind] = verified.project
                else:
                    with self.assertRaisesRegex(
                        installer_tool.InstallError,
                        "archive is missing (?:installer|guard|source manifest)",
                    ) as raised:
                        installer_tool.verify_inputs(
                            output, workspace / "tools/deploy-upload-archive.py",
                            required_uid=os.getuid(),
                        )
                    self.assertNotIn("No such file", str(raised.exception))
                    results[artifact_kind] = "rejected"
            self.assertEqual({
                "upload": "customer",
                "preview": "rejected",
                "download": "rejected",
            }, results)

    def test_local_authority_manifest_covers_lifecycle_and_never_self_includes(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "deployment-source-manifest.json"
            self.real_source_manifest_builder(destination)
            payload = __import__("json").loads(destination.read_text(encoding="ascii"))
        paths = {record["path"] for record in payload["files"]}
        self.assertIn("DAY0-Prepare/11-load.py", paths)
        self.assertIn("infra/docker/hostctl.py", paths)
        self.assertIn("tools/control-auth.py", paths)
        self.assertIn("tools/deployment_prewrite_guard.py", paths)
        self.assertNotIn(
            "infra/docker/deployment-source-manifest.json", paths,
        )

    def test_real_upload_archive_exactly_satisfies_packaged_source_manifest(self):
        fixture = materialized_public_project(ROOT)
        project = fixture.__enter__()
        self.addCleanup(fixture.__exit__, None, None, None)
        manual_updater = ROOT / "tools/update-user-manual.py"
        self.assertTrue(manual_updater.is_file())
        manual_spec = importlib.util.spec_from_file_location(
            "upload_user_manual_workflow", manual_updater,
        )
        self.assertIsNotNone(manual_spec)
        self.assertIsNotNone(manual_spec.loader)
        manual_module = importlib.util.module_from_spec(manual_spec)
        manual_spec.loader.exec_module(manual_module)
        self.assertEqual(
            (ROOT / "user-manual.html").read_text(encoding="utf-8"),
            manual_module.render_manual(ROOT),
        )
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            archive_path = base / "docker-source-contract.tar.gz"
            args = argparse.Namespace(
                project=str(project), output=archive_path, force=False,
                max_file_size_mib=50, include_images=False,
                include_apps=False, apps_platform=None, apps_platforms=set(),
                include_firmware=False,
            )
            with mock.patch.object(
                package, "write_deployment_source_manifest",
                side_effect=self.real_source_manifest_builder,
            ):
                package.create_package(
                    args, day0_all=False, artifact_kind="upload",
                )
            extracted = base / "extracted"
            extracted.mkdir()
            with tarfile.open(archive_path, "r:gz") as archive:
                packaged_names = {
                    member.name.removeprefix("./") for member in archive.getmembers()
                }
                self.assertIn(".dockerignore", packaged_names)
                self.assertIn(
                    "requirements-container-top-level.lock", packaged_names,
                )
                self.assertIn("user-manual.html", packaged_names)
                self.assertIn("tools/control-auth.py", packaged_names)
                self.assertNotIn(
                    "etc/http-ztp/control-users.htpasswd", packaged_names,
                )
                self.assertFalse(any(
                    name.endswith("/control-users.htpasswd")
                    or name == "control-users.htpasswd"
                    for name in packaged_names
                ))
                packaged_manual = archive.extractfile("./user-manual.html")
                self.assertIsNotNone(packaged_manual)
                self.assertEqual(
                    (ROOT / "user-manual.html").read_bytes(),
                    packaged_manual.read(),
                )
                packaged_lock = archive.extractfile(
                    "./requirements-container-top-level.lock"
                )
                self.assertIsNotNone(packaged_lock)
                self.assertEqual(
                    (ROOT / "requirements-container-top-level.lock").read_bytes(),
                    packaged_lock.read(),
                )
                legacy_ignore = archive.extractfile("./.dockerignore")
                buildkit_ignore = archive.extractfile(
                    "./infra/docker/Dockerfile.dockerignore"
                )
                self.assertIsNotNone(legacy_ignore)
                self.assertIsNotNone(buildkit_ignore)
                self.assertEqual(legacy_ignore.read(), buildkit_ignore.read())
                for runtime_path in (
                    "ethernet/monitor/cron.lock",
                    "monitor/.generate-monitor-html.lock",
                    "monitor/status/.switch-collection-cooldown.lock",
                    "monitor/status/.yaml-backup-cooldown.lock",
                    "ethernet/monitor/eth.csv",
                    "infiniband/monitor/ib.csv",
                    "nvlink/monitor/nvsw.csv",
                    "infiniband/bringup/xdr-upgrade/ib.csv",
                    "infiniband/bringup/xdr-initial-setup/ib.csv",
                ):
                    with self.subTest(runtime_path=runtime_path):
                        self.assertNotIn(runtime_path, packaged_names)
                archive.extractall(extracted)
            manifest = extracted / "infra/docker/deployment-source-manifest.json"
            result = subprocess.run(
                [
                    sys.executable, "-B",
                    os.fspath(extracted / "infra/docker/activate.py"),
                    "verify-source-manifest", "--source-root", os.fspath(extracted),
                    "--manifest", os.fspath(manifest),
                ],
                cwd=extracted, capture_output=True, text=True, check=False,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            )
            payload = __import__("json").loads(manifest.read_text(encoding="ascii"))
            records = {record["path"]: record for record in payload["files"]}
            preloaded_workflow = (
                "requirements-container-top-level.lock",
                "infra/docker/Dockerfile",
                "infra/docker/activate.py",
                "infra/docker/deploy.sh",
                "infra/docker/hostlock.py",
            )
            for relative in preloaded_workflow:
                with self.subTest(preloaded_source=relative):
                    packaged = extracted / relative
                    self.assertTrue(packaged.is_file())
                    self.assertEqual(
                        hashlib.sha256(packaged.read_bytes()).hexdigest(),
                        records[relative]["sha256"],
                    )
            self.assertIn(
                "deploy-preloaded",
                (extracted / "infra/docker/deploy.sh").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "verify_preloaded_image",
                (extracted / "infra/docker/hostlock.py").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "verify-deployment-image",
                (extracted / "infra/docker/activate.py").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "com.nvidia.http-ztp.image-contract",
                (extracted / "infra/docker/Dockerfile").read_text(encoding="utf-8"),
            )
        self.assertEqual(0, result.returncode, result.stderr or result.stdout)

    def test_help_documents_optional_air_topology_policy(self):
        self.assertIn("03-air-topology-policy.json", upload_tool.HELP_EPILOG)
        self.assertIn("存在时", upload_tool.HELP_EPILOG)

    def test_help_forbids_manual_live_extraction_and_requires_deploy_guard(self):
        help_text = upload_tool.HELP_EPILOG
        self.assertNotIn("校验归档后直接解压即可", help_text)
        self.assertIn("禁止对 live /var/www/html 手工解压", help_text)
        self.assertIn("--deploy", help_text)
        self.assertIn("deployment_prewrite_guard.py", help_text)
        self.assertIn("共享 deployment lock", help_text)

    def test_relay_release_externalizes_project_switch_images(self):
        fixture = materialized_public_project(ROOT)
        project = fixture.__enter__()
        self.addCleanup(fixture.__exit__, None, None, None)
        package_filter = package.PackageFilter(
            project,
            Path("/tmp/relay-release.tar.gz"),
            include_images=False,
            include_apps=False,
            include_firmware=False,
            max_file_size=50 * 1024 * 1024,
            day0_all=False,
            exclude_project_images=True,
        )
        member = tarfile.TarInfo(
            f"./DAY0-Prepare/{project.name}/"
            "cumulus-linux-5.18.1-mlx-amd64.bin",
        )
        member.size = 1024 * 1024
        self.assertIsNone(package_filter(member))
        self.assertEqual(1, package_filter.reasons["shared switch image externalized"])

    @staticmethod
    def upload_args(**overrides):
        values = {
            "project": "customer",
            "port": 24995,
            "host": "ubuntu@worker.example",
            "identity": None,
            "remote_dir": "/tmp",
            "remote_root": "/var/www/html",
            "deploy": False,
            "deploy_uploaded": None,
            "output": Path("/tmp/project-upload.tar.gz"),
            "no_sudo": False,
            "runtime": "native",
            "transport": "auto",
            "upload_retries": 3,
            "transfer_timeout": 3600,
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def test_upload_prefers_resumable_rsync_and_atomically_publishes(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "project-upload.tar.gz"
            archive.write_bytes(b"payload")
            digest = hashlib.sha256(b"payload").hexdigest()
            args = self.upload_args()

            with (
                mock.patch.object(upload_tool, "remote_rsync_available", return_value=True),
                mock.patch.object(
                    upload_tool, "remote_sha256", side_effect=(None, digest)
                ),
                mock.patch.object(upload_tool, "run_streaming") as streaming,
                mock.patch.object(upload_tool, "run", return_value="") as run,
            ):
                remote = upload_tool.upload(args, archive)

            self.assertEqual("/tmp/project-upload.tar.gz", remote)
            command = streaming.call_args.args[0]
            self.assertEqual("rsync", command[0])
            self.assertIn("--partial", command)
            self.assertIn("--append", command)
            self.assertIn("--progress", command)
            self.assertEqual(
                "ubuntu@worker.example:/tmp/project-upload.tar.gz.partial",
                command[-1],
            )
            rsh = command[command.index("-e") + 1]
            self.assertIn("ServerAliveInterval=15", rsh)
            move = run.call_args_list[-1].args[0]
            self.assertEqual(
                [
                    "ubuntu@worker.example", "mv", "-f", "--",
                    "/tmp/project-upload.tar.gz.partial",
                    "/tmp/project-upload.tar.gz",
                ],
                move[-6:],
            )

    def test_upload_falls_back_to_live_progress_scp_with_partial_name(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "project-upload.tar.gz"
            archive.write_bytes(b"payload")
            digest = hashlib.sha256(b"payload").hexdigest()
            args = self.upload_args()

            with (
                mock.patch.object(upload_tool, "remote_rsync_available", return_value=False),
                mock.patch.object(
                    upload_tool, "remote_sha256", side_effect=(None, digest)
                ),
                mock.patch.object(upload_tool, "run_streaming") as streaming,
                mock.patch.object(upload_tool, "run", return_value=""),
            ):
                upload_tool.upload(args, archive)

            command = streaming.call_args.args[0]
            self.assertEqual("scp", command[0])
            self.assertIn("ServerAliveCountMax=4", command)
            self.assertEqual(
                "ubuntu@worker.example:/tmp/project-upload.tar.gz.partial",
                command[-1],
            )

    def test_corrupt_resumed_prefix_is_removed_and_retransmitted_without_append(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "project-upload.tar.gz"
            archive.write_bytes(b"payload")
            digest = hashlib.sha256(b"payload").hexdigest()
            args = self.upload_args(transport="rsync")

            with (
                mock.patch.object(upload_tool, "remote_rsync_available", return_value=True),
                mock.patch.object(
                    upload_tool, "remote_sha256",
                    side_effect=(None, "0" * 64, digest),
                ),
                mock.patch.object(upload_tool, "run_streaming") as streaming,
                mock.patch.object(upload_tool, "run", return_value="") as run,
            ):
                upload_tool.upload(args, archive)

            self.assertEqual(2, streaming.call_count)
            self.assertIn("--append", streaming.call_args_list[0].args[0])
            self.assertNotIn("--append", streaming.call_args_list[1].args[0])
            self.assertTrue(
                any("rm" in call.args[0] for call in run.call_args_list)
            )

    def test_transfer_retry_keeps_partial_and_retries_after_interruption(self):
        command = ["rsync", "source", "host:/tmp/file.partial"]
        with (
            mock.patch.object(
                upload_tool, "run_streaming",
                side_effect=(RuntimeError("connection reset"), None),
            ) as streaming,
            mock.patch.object(upload_tool.time, "sleep") as sleep,
        ):
            upload_tool.transfer_with_retries(
                lambda: command,
                attempts=3,
                timeout=3600,
                resumable=True,
            )
        self.assertEqual(2, streaming.call_count)
        sleep.assert_called_once_with(2)

    def test_image_stripping_removes_media_relationship_and_only_picture_anchor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "Customer P2P.xlsx"
            output = root / "image-free.xlsx"
            write_picture_workbook(source)
            before = file_digest(source)

            stats = package.strip_xlsx_images(source, output)

            self.assertEqual(before, file_digest(source), "source workbook must be read-only")
            self.assertEqual(1, stats["images"])
            self.assertEqual(1, stats["relationships"])
            self.assertEqual(1, stats["drawing_nodes"])
            with zipfile.ZipFile(output) as archive:
                self.assertIsNone(archive.testzip())
                self.assertNotIn("xl/media/image1.png", archive.namelist())
                relations = ET.fromstring(
                    archive.read("xl/drawings/_rels/drawing1.xml.rels")
                )
                self.assertFalse(list(relations))
                drawing = ET.fromstring(archive.read("xl/drawings/drawing1.xml"))
                self.assertEqual(0, len(drawing.findall(f"{{{XDR_NS}}}oneCellAnchor")))
                self.assertEqual(1, len(drawing.findall(f"{{{XDR_NS}}}twoCellAnchor")))

    def test_upload_contains_only_consumed_project_inputs_and_sanitized_p2p(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = (Path(directory) / "http").resolve()
            day0 = workspace / "DAY0-Prepare"
            project = day0 / "customer"
            project.mkdir(parents=True)
            for relative in REQUIRED_UPLOAD_SOURCES:
                target = workspace / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("# deployable\n", encoding="utf-8")
            (workspace / "README.md").write_text("operator documentation\n", encoding="utf-8")
            (workspace / "cross-review.log").write_text(
                "local reviewer coordination\n", encoding="utf-8",
            )
            (workspace / ".deployment.lock").touch()
            management_private_sentinel = (
                b"DOCKER_MGMT_SECRET_SENTINEL_7f92b6f3fce34de4\n"
            )
            root_local_artifacts = (
                ".git", "outputs", ".codex", ".agents", ".claude",
                ".codex_tmp_analysis", ".Ssh",
            )
            for name in root_local_artifacts:
                local_artifact = workspace / name
                local_artifact.mkdir()
                (local_artifact / "private.txt").write_text(
                    "workstation only\n", encoding="utf-8",
                )
            (workspace / ".Ssh/id_ed25519").write_bytes(
                management_private_sentinel,
            )
            for name in (
                ".git", ".codex", ".agents", ".claude", ".codex_tmp_analysis",
            ):
                nested_metadata = (
                    workspace / "tools/lldp-analyze-tool" / name / "private.py"
                )
                nested_metadata.parent.mkdir(parents=True, exist_ok=True)
                nested_metadata.write_text("# workstation only\n", encoding="utf-8")
            lldp_tool = workspace / "tools/lldp-analyze-tool"
            for name in ("analyze_lldp.py", "build_report.py"):
                (lldp_tool / name).write_text("# deployable runtime\n", encoding="utf-8")
            (lldp_tool / "04-lldp-device-aliases.json").write_text(
                '{"schema_version":1,"canonical_to_aliases":{}}\n',
                encoding="utf-8",
            )
            (lldp_tool / "secrets.json").write_text(
                '{"must_not_ship":true}\n', encoding="utf-8",
            )
            (lldp_tool / "README.md").write_text(
                "operator documentation\n", encoding="utf-8",
            )
            (lldp_tool / "node_modules").mkdir()
            (lldp_tool / "node_modules/private.js").write_text(
                "// local dependency cache\n", encoding="utf-8",
            )
            (lldp_tool / "99-output-p2p").symlink_to(
                "../../DAY0-Prepare/customer/99-output-p2p",
            )
            (lldp_tool / "99-output-monitor").symlink_to(
                "../../DAY0-Prepare/customer/99-output-monitor",
            )
            # Root-only exclusions must not turn into an unanchored filter for
            # a legitimate same-named directory in a deployable code tree.
            nested_runtime = workspace / "ethernet/outputs/runtime.py"
            nested_runtime.parent.mkdir(parents=True)
            nested_runtime.write_text("# deployable\n", encoding="utf-8")
            (workspace / "ztp/ztp.json").write_text(
                '{"service_ip": "192.0.2.99"}\n', encoding="utf-8",
            )
            field_dir = workspace / "infiniband/bringup/ndr"
            field_dir.mkdir(parents=True, exist_ok=True)
            for name in (
                "How to do initial config for IB switches.log",
                "IB-SW-show-2024-10-15.log", "IB-switches-IP.log",
                "MLNX-OS_IB_switch_wizard_initialization_quick_guide_EN.docx",
            ):
                (field_dir / name).write_text("field reference\n", encoding="utf-8")
            (field_dir / "data-collect-IB.sh").write_text(
                "#!/bin/sh\n", encoding="utf-8",
            )
            for name in package.PROJECT_DEPLOYMENT_INPUTS:
                (project / name).write_text("input\n", encoding="utf-8")
            policy_payload = b'{"node_allowlist": ["AIR-example-leaf01"]}\n'
            (project / "03-air-topology-policy.json").write_bytes(policy_payload)
            mini_payload = (
                b"[minimum-required]\nexample-leaf01\n\n"
                b"[customer-provided]\nexample-leaf01\nexample-leaf02\n"
            )
            (project / "04-air-mini-devices.txt").write_bytes(mini_payload)
            selected = project / "Customer P2P.xlsx"
            write_picture_workbook(selected)
            (project / "p2p.xlsx").symlink_to(selected.name)
            write_picture_workbook(project / "ip-vlan design.xlsx")
            (project / "README.txt").write_text("workstation notes\n", encoding="utf-8")
            (project / "laptop.pub").write_text("ssh-ed25519 test\n", encoding="utf-8")
            (project / "switch.bin").touch()
            before = file_digest(selected)
            output = workspace / "upload.tar.gz"
            args = argparse.Namespace(
                project=str(project), output=output, force=False,
                max_file_size_mib=50, include_images=False, include_apps=False,
                apps_platform=None, apps_platforms=set(), include_firmware=False,
            )
            with mock.patch.multiple(
                package,
                ROOT=workspace,
                DAY0=day0,
                MANIFEST=workspace / "ztp/.setup_manifest",
                TOOLS_DIR=workspace / "tools",
            ):
                package.create_package(
                    args, day0_all=False, artifact_kind="upload",
                )

            self.assertEqual(before, file_digest(selected), "packaging changed source XLSX")
            self.assertEqual(0o600, stat.S_IMODE(output.stat().st_mode))
            with tarfile.open(output, "r:gz") as archive:
                names = set(archive.getnames())
                prefix = "./DAY0-Prepare/customer/"
                self.assertIn(prefix + "Customer P2P.xlsx", names)
                self.assertIn(prefix + "01-global.yaml", names)
                self.assertIn(prefix + "02-devices_config.csv", names)
                self.assertIn(prefix + "02-dhcp-subnet_config.csv", names)
                self.assertIn(prefix + "03-air-topology-policy.json", names)
                self.assertIn(prefix + "04-air-mini-devices.txt", names)
                self.assertIn(prefix + "laptop.pub", names)
                self.assertIn(prefix + "switch.bin", names)
                self.assertNotIn(prefix + "p2p.xlsx", names)
                self.assertNotIn(prefix + "ip-vlan design.xlsx", names)
                self.assertNotIn(prefix + "README.txt", names)
                self.assertNotIn("./README.md", names)
                self.assertNotIn("./cross-review.log", names)
                self.assertNotIn("./.deployment.lock", names)
                for root_name in root_local_artifacts:
                    with self.subTest(root_local_artifact=root_name):
                        prefix_name = f"./{root_name}"
                        self.assertFalse(any(
                            name == prefix_name or name.startswith(prefix_name + "/")
                            for name in names
                        ))
                self.assertFalse(any(
                    part in {".git", ".codex", ".agents", ".claude"}
                    or part.startswith(".codex_tmp")
                    for name in names for part in Path(name).parts
                ))
                packaged_payloads = b"".join(
                    archive.extractfile(member).read()
                    for member in archive.getmembers()
                    if member.isfile()
                )
                self.assertNotIn(management_private_sentinel, packaged_payloads)
                self.assertIn("./ethernet/outputs/runtime.py", names)
                self.assertIn("./ztp/templates/ztp.json", names)
                self.assertIn("./tools/password-update.py", names)
                self.assertIn("./tools/deploy-upload-archive.py", names)
                self.assertIn("./infra/docker/management_ssh_key.py", names)
                self.assertIn("./tools/lldp-analyze-tool/analyze_lldp.py", names)
                self.assertIn("./tools/lldp-analyze-tool/build_report.py", names)
                self.assertIn("./tools/lldp-analyze-tool/04-lldp-device-aliases.json", names)
                self.assertIn("./ztp/config/topology_rules.py", names)
                self.assertNotIn("./tools/lldp-analyze-tool/secrets.json", names)
                self.assertNotIn("./tools/lldp-analyze-tool/README.md", names)
                self.assertFalse(any(
                    name == "./tools/lldp-analyze-tool/node_modules"
                    or name.startswith("./tools/lldp-analyze-tool/node_modules/")
                    or name in {
                        "./tools/lldp-analyze-tool/99-output-p2p",
                        "./tools/lldp-analyze-tool/99-output-monitor",
                    }
                    for name in names
                ))
                self.assertIn("./infiniband/bringup/ndr/data-collect-IB.sh", names)
                for name in (
                    "How to do initial config for IB switches.log",
                    "IB-SW-show-2024-10-15.log", "IB-switches-IP.log",
                    "MLNX-OS_IB_switch_wizard_initialization_quick_guide_EN.docx",
                ):
                    self.assertNotIn(f"./infiniband/bringup/ndr/{name}", names)
                self.assertNotIn("./ztp/ztp.json", names)
                self.assertFalse(
                    any(Path(name).name.startswith(".http-air-package-") for name in names)
                )
                payload = archive.extractfile(prefix + "Customer P2P.xlsx")
                self.assertIsNotNone(payload)
                with zipfile.ZipFile(io.BytesIO(payload.read())) as workbook:
                    self.assertFalse(
                        any(name.startswith("xl/media/") for name in workbook.namelist())
                    )
                reopened_project = workspace / "reopened-project"
                reopened_project.mkdir()
                policy_member = archive.extractfile(
                    prefix + "03-air-topology-policy.json"
                )
                self.assertIsNotNone(policy_member)
                (reopened_project / "03-air-topology-policy.json").write_bytes(
                    policy_member.read()
                )

            discovered = load_tool.project_air_topology_policy(reopened_project)
            self.assertEqual(
                reopened_project / "03-air-topology-policy.json", discovered,
            )
            self.assertEqual(policy_payload, discovered.read_bytes())
            with tarfile.open(output, "r:gz") as archive:
                mini_member = archive.extractfile(
                    "./DAY0-Prepare/customer/04-air-mini-devices.txt"
                )
                self.assertIsNotNone(mini_member)
                self.assertEqual(mini_payload, mini_member.read())

    def test_shared_nvos_image_aliases_round_trip_through_upload_into_load(self):
        accepted_names = (
            "nvos-amd64-25.03.1010.bin",
            "nvosv25-03-1010amd64.bin",
        )
        for image_name in accepted_names:
            with self.subTest(image_name=image_name), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                workspace = (base / "http").resolve()
                day0 = workspace / "DAY0-Prepare"
                project = day0 / "customer"
                project.mkdir(parents=True)
                for relative in REQUIRED_UPLOAD_SOURCES:
                    target = workspace / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text("# deployable\n", encoding="utf-8")
                for name in package.PROJECT_DEPLOYMENT_INPUTS:
                    (project / name).write_text("input\n", encoding="utf-8")
                write_picture_workbook(project / "Customer P2P.xlsx")
                write_sparse_self_extracting_image(workspace / "image" / image_name)

                archives = {}
                for include_images in (True, False):
                    output = base / f"include-images-{include_images}.tar.gz"
                    args = argparse.Namespace(
                        project=str(project), output=output, force=False,
                        max_file_size_mib=1, include_images=include_images,
                        include_apps=False, apps_platform=None, apps_platforms=set(),
                        include_firmware=False,
                    )
                    with mock.patch.multiple(
                        package,
                        ROOT=workspace,
                        DAY0=day0,
                        MANIFEST=workspace / "ztp/.setup_manifest",
                        TOOLS_DIR=workspace / "tools",
                    ):
                        package.create_package(
                            args, day0_all=False, artifact_kind="upload",
                        )
                    archives[include_images] = output

                    with tarfile.open(output, "r:gz") as archive:
                        names = set(archive.getnames())
                    member = f"./image/{image_name}"
                    if include_images:
                        self.assertIn(member, names)
                    else:
                        self.assertNotIn(member, names)

                extracted = base / "extracted"
                extracted.mkdir()
                with tarfile.open(archives[True], "r:gz") as archive:
                    archive.extractall(extracted)

                settings = load_tool.GlobalSettings(
                    dhcp_enabled=False,
                    dhcp_package="",
                    http_enabled=False,
                    http_package="",
                    http_root=extracted,
                    ztp_enabled=False,
                    ztp_prefix="ztp",
                    ztp_ips={},
                    versions={"ib": "25.03.1010"},
                )
                expected = load_tool.expected_images(settings, frozenset({"ib"}))
                self.assertEqual(
                    {"ib": "nvosv25-03-1010amd64.bin"}, expected,
                )
                with mock.patch.object(load_tool, "IMAGE_DIR", extracted / "image"):
                    resolved = load_tool.prepare_images(
                        extracted / "DAY0-Prepare/customer",
                        expected,
                        dry_run=True,
                        quiet=True,
                    )

                self.assertEqual(image_name, resolved["ib"].name)
                self.assertEqual(extracted / "image" / image_name, resolved["ib"])

    def test_upload_succeeds_without_optional_air_topology_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = (Path(directory) / "http").resolve()
            day0 = workspace / "DAY0-Prepare"
            project = day0 / "customer"
            project.mkdir(parents=True)
            for relative in REQUIRED_UPLOAD_SOURCES:
                target = workspace / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("# deployable\n", encoding="utf-8")
            for name in package.PROJECT_DEPLOYMENT_INPUTS:
                (project / name).write_text("input\n", encoding="utf-8")
            write_picture_workbook(project / "Customer P2P.xlsx")
            output = workspace / "upload.tar.gz"
            args = argparse.Namespace(
                project=str(project), output=output, force=False,
                max_file_size_mib=50, include_images=False, include_apps=False,
                apps_platform=None, apps_platforms=set(), include_firmware=False,
            )
            with mock.patch.multiple(
                package,
                ROOT=workspace,
                DAY0=day0,
                MANIFEST=workspace / "ztp/.setup_manifest",
                TOOLS_DIR=workspace / "tools",
            ):
                package.create_package(
                    args, day0_all=False, artifact_kind="upload",
                )

            with tarfile.open(output, "r:gz") as archive:
                names = set(archive.getnames())
            self.assertNotIn(
                "./DAY0-Prepare/customer/03-air-topology-policy.json", names,
            )

    def test_upload_reopen_requires_policy_when_source_contains_it(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = (Path(directory) / "http").resolve()
            day0 = workspace / "DAY0-Prepare"
            project = day0 / "customer"
            project.mkdir(parents=True)
            for relative in REQUIRED_UPLOAD_SOURCES:
                target = workspace / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("# deployable\n", encoding="utf-8")
            for name in package.PROJECT_DEPLOYMENT_INPUTS:
                (project / name).write_text("input\n", encoding="utf-8")
            write_picture_workbook(project / "Customer P2P.xlsx")
            (project / "03-air-topology-policy.json").write_text(
                "{}\n", encoding="utf-8",
            )
            output = workspace / "upload.tar.gz"
            args = argparse.Namespace(
                project=str(project), output=output, force=False,
                max_file_size_mib=50, include_images=False, include_apps=False,
                apps_platform=None, apps_platforms=set(), include_firmware=False,
            )
            original_filter = package.PackageFilter.__call__

            def omit_policy(filter_self, info):
                if Path(info.name).name == "03-air-topology-policy.json":
                    filter_self.reject(info, "injected policy omission")
                    return None
                return original_filter(filter_self, info)

            with mock.patch.multiple(
                package,
                ROOT=workspace,
                DAY0=day0,
                MANIFEST=workspace / "ztp/.setup_manifest",
                TOOLS_DIR=workspace / "tools",
            ), mock.patch.object(
                package.PackageFilter, "__call__", omit_policy,
            ), self.assertRaisesRegex(
                RuntimeError,
                r"package verification missing: .*03-air-topology-policy\.json",
            ):
                package.create_package(
                    args, day0_all=False, artifact_kind="upload",
                )

            self.assertFalse(output.exists())

    def test_upload_rejects_nonregular_air_topology_policy_path(self):
        for path_kind in ("symlink", "directory"):
            with self.subTest(path_kind=path_kind), tempfile.TemporaryDirectory() as directory:
                workspace = (Path(directory) / "http").resolve()
                day0 = workspace / "DAY0-Prepare"
                project = day0 / "customer"
                project.mkdir(parents=True)
                for relative in REQUIRED_UPLOAD_SOURCES:
                    target = workspace / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text("# deployable\n", encoding="utf-8")
                for name in package.PROJECT_DEPLOYMENT_INPUTS:
                    (project / name).write_text("input\n", encoding="utf-8")
                write_picture_workbook(project / "Customer P2P.xlsx")
                policy = project / "03-air-topology-policy.json"
                if path_kind == "symlink":
                    (project / "policy-target.json").write_text("{}\n", encoding="utf-8")
                    policy.symlink_to("policy-target.json")
                else:
                    policy.mkdir()
                args = argparse.Namespace(
                    project=str(project), output=workspace / "upload.tar.gz",
                    force=False, max_file_size_mib=50, include_images=False,
                    include_apps=False, apps_platform=None, apps_platforms=set(),
                    include_firmware=False,
                )
                with mock.patch.multiple(
                    package,
                    ROOT=workspace,
                    DAY0=day0,
                    MANIFEST=workspace / "ztp/.setup_manifest",
                    TOOLS_DIR=workspace / "tools",
                ), self.assertRaisesRegex(
                    ValueError, r"03-air-topology-policy\.json.*regular file",
                ):
                    package.create_package(
                        args, day0_all=False, artifact_kind="upload",
                    )

    def test_upload_fails_closed_without_canonical_nvos_ztp_template(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = (Path(directory) / "http").resolve()
            day0 = workspace / "DAY0-Prepare"
            project = day0 / "customer"
            project.mkdir(parents=True)
            for relative in REQUIRED_UPLOAD_SOURCES:
                if relative == "ztp/templates/ztp.json":
                    continue
                target = workspace / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("# deployable\n", encoding="utf-8")
            for name in package.PROJECT_DEPLOYMENT_INPUTS:
                (project / name).write_text("input\n", encoding="utf-8")
            write_picture_workbook(project / "Customer P2P.xlsx")
            args = argparse.Namespace(
                project=str(project), output=workspace / "upload.tar.gz",
                force=False, max_file_size_mib=50, include_images=False,
                include_apps=False, apps_platform=None, apps_platforms=set(),
                include_firmware=False,
            )
            with mock.patch.multiple(
                package,
                ROOT=workspace,
                DAY0=day0,
                MANIFEST=workspace / "ztp/.setup_manifest",
                TOOLS_DIR=workspace / "tools",
            ):
                with self.assertRaisesRegex(
                    RuntimeError, r"ztp/templates/ztp\.json",
                ):
                    package.create_package(
                        args, day0_all=False, artifact_kind="upload",
                    )

    def test_download_and_full_workspace_archives_exclude_all_readmes(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = (Path(directory) / "http").resolve()
            day0 = workspace / "DAY0-Prepare"
            project = day0 / "customer"
            nested = project / "99-output-monitor"
            nested.mkdir(parents=True)
            (project / "01-global.yaml").write_text("common: {}\n", encoding="utf-8")
            (project / "02-devices_config.csv").write_text(
                "hostname,type\nleaf01,eth\n", encoding="utf-8",
            )
            (project / "README.txt").write_text("excluded\n", encoding="utf-8")
            (nested / "readme.MD").write_text("excluded\n", encoding="utf-8")
            (nested / "report.json").write_text("{}\n", encoding="utf-8")
            output = workspace / "download.tar.gz"
            args = argparse.Namespace(
                all_day0=False,
                project=str(project),
                output=output,
                force=False,
            )
            with mock.patch.multiple(
                package,
                ROOT=workspace,
                DAY0=day0,
                MANIFEST=workspace / "ztp/.setup_manifest",
            ):
                download_tool.create_day0_archive(args)
                with tarfile.open(output, "r:gz") as archive:
                    names = set(archive.getnames())
                prefix = "DAY0-Prepare/customer/"
                self.assertNotIn(prefix + "README.txt", names)
                self.assertNotIn(prefix + "99-output-monitor/readme.MD", names)
                self.assertIn(prefix + "99-output-monitor/report.json", names)

                package_filter = package.PackageFilter(
                    project,
                    workspace / "full.tar.gz",
                    include_images=False,
                    include_apps=False,
                    include_firmware=False,
                    max_file_size=1024,
                    day0_all=True,
                )
                readme = tarfile.TarInfo(prefix + "nested/README.md")
                readme.size = 10
                self.assertIsNone(package_filter(readme))
                self.assertEqual(
                    1, package_filter.reasons.get("README documentation", 0),
                )

    def test_package_bytes_are_reproducible_across_clock_and_output_name(self):
        """The same governed tree produces one byte-identical tar.gz."""
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            workspace, day0, project = self._minimal_package_workspace(base)
            outputs = (base / "first.tar.gz", base / "second.tar.gz")
            payloads = []
            for index, output in enumerate(outputs, 1):
                source_timestamp = 1_600_000_000 + index
                os.utime(
                    workspace / "DAY0-Prepare/11-load.py",
                    (source_timestamp, source_timestamp),
                )
                os.utime(
                    project / "01-global.yaml",
                    (source_timestamp, source_timestamp),
                )
                args = argparse.Namespace(
                    project=str(project), output=output, force=False,
                    max_file_size_mib=50, include_images=False,
                    include_apps=False, apps_platform=None,
                    apps_platforms=set(), include_firmware=False,
                    exclude_project_images=False,
                )
                with mock.patch.multiple(
                    package,
                    ROOT=workspace,
                    DAY0=day0,
                    MANIFEST=workspace / "ztp/.setup_manifest",
                    TOOLS_DIR=workspace / "tools",
                    write_deployment_source_manifest=self._stable_source_manifest,
                ), mock.patch("gzip.time.time", return_value=1_700_000_000 + index):
                    package.create_package(
                        args, day0_all=True, artifact_kind="download",
                    )
                payloads.append(output.read_bytes())

            self.assertEqual(payloads[0], payloads[1])
            with tarfile.open(outputs[0], "r:gz") as archive:
                members = archive.getmembers()
            self.assertTrue(members)
            for member in members:
                with self.subTest(member=member.name):
                    self.assertEqual(0, member.mtime)
                    self.assertEqual(0, member.uid)
                    self.assertEqual(0, member.gid)
                    self.assertEqual("", member.uname)
                    self.assertEqual("", member.gname)

    def test_upload_package_honors_canonical_p2p_pointer_across_mtime_changes(self):
        """A setup-managed canonical pointer, not fallback discovery, binds upload."""
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            workspace, day0, project = self._minimal_package_workspace(base)
            versions = project / "p2p"
            versions.mkdir()
            first = versions / "A-p2p.xlsx"
            second = versions / "B-p2p.xlsx"
            write_picture_workbook(first, "literal-first")
            write_picture_workbook(second, "literal-second")
            (project / "p2p.xlsx").symlink_to(Path("p2p") / first.name)
            outputs = (base / "mtime-first.tar.gz", base / "mtime-second.tar.gz")
            payloads = []
            for index, output in enumerate(outputs):
                older, newer = ((first, second), (second, first))[index]
                os.utime(older, (1_600_000_000, 1_600_000_000))
                os.utime(newer, (1_700_000_000, 1_700_000_000))
                args = argparse.Namespace(
                    project=str(project), output=output, force=False,
                    max_file_size_mib=50, include_images=False,
                    include_apps=False, apps_platform=None,
                    apps_platforms=set(), include_firmware=False,
                    exclude_project_images=False,
                )
                with mock.patch.multiple(
                    package,
                    ROOT=workspace,
                    DAY0=day0,
                    MANIFEST=workspace / "ztp/.setup_manifest",
                    TOOLS_DIR=workspace / "tools",
                    write_deployment_source_manifest=self._stable_source_manifest,
                ):
                    package.create_package(
                        args, day0_all=False, artifact_kind="upload",
                    )
                payloads.append(output.read_bytes())

            self.assertEqual(
                payloads[0], payloads[1],
                "the setup-managed p2p.xlsx pointer must bind production upload",
            )
            (project / "p2p.xlsx").unlink()
            os.utime(first, (1_600_000_000, 1_600_000_000))
            os.utime(second, (1_700_000_000, 1_700_000_000))
            self.assertEqual(
                second.resolve(),
                package.select_upload_p2p(project),
                "without the canonical pointer, fallback retains setup/load mtime order",
            )

    def test_archive_member_modes_are_canonical_across_source_umask(self):
        """Host umask metadata cannot alter an otherwise identical archive."""
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            workspace, day0, project = self._minimal_package_workspace(base)
            source = project / "01-global.yaml"
            outputs = (base / "mode-first.tar.gz", base / "mode-second.tar.gz")
            payloads = []
            for mode, output in zip((0o600, 0o644), outputs):
                source.chmod(mode)
                project.chmod(0o700 if mode == 0o600 else 0o755)
                args = argparse.Namespace(
                    project=str(project), output=output, force=False,
                    max_file_size_mib=50, include_images=False,
                    include_apps=False, apps_platform=None,
                    apps_platforms=set(), include_firmware=False,
                    exclude_project_images=False,
                )
                with mock.patch.multiple(
                    package,
                    ROOT=workspace,
                    DAY0=day0,
                    MANIFEST=workspace / "ztp/.setup_manifest",
                    TOOLS_DIR=workspace / "tools",
                    write_deployment_source_manifest=self._stable_source_manifest,
                ):
                    package.create_package(
                        args, day0_all=True, artifact_kind="download",
                    )
                payloads.append(output.read_bytes())

            self.assertEqual(payloads[0], payloads[1])
            with tarfile.open(outputs[0], "r:gz") as archive:
                self.assertEqual(
                    0o644,
                    archive.getmember(
                        "./DAY0-Prepare/customer/01-global.yaml"
                    ).mode,
                )
                self.assertEqual(
                    0o755,
                    archive.getmember("./DAY0-Prepare/customer").mode,
                )

    def test_real_package_materializes_hardlinks_as_reproducible_regular_files(self):
        """Host inode sharing cannot change upload/download archive identity."""
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            archives = {}
            expected_payload = b"H02-hardlink-materialized-content\n"
            expected_digest = hashlib.sha256(expected_payload).hexdigest()
            selected_members = (
                "./DAY0-Prepare/customer/payload-a.txt",
                "./DAY0-Prepare/customer/payload-b.txt",
                "./apps/ubuntu-24.04/amd64/runtime_1.0_all.deb",
                "./apps/ubuntu-24.04/arm64/runtime_1.0_all.deb",
            )

            for label, use_hardlinks in (
                ("independent", False),
                ("hardlinked", True),
            ):
                workspace, day0, project = self._minimal_package_workspace(
                    base / label,
                )
                first_project = project / "payload-a.txt"
                second_project = project / "payload-b.txt"
                first_project.write_bytes(expected_payload)
                if use_hardlinks:
                    os.link(first_project, second_project)
                else:
                    second_project.write_bytes(expected_payload)

                first_deb = (
                    workspace / "apps/ubuntu-24.04/amd64/runtime_1.0_all.deb"
                )
                second_deb = (
                    workspace / "apps/ubuntu-24.04/arm64/runtime_1.0_all.deb"
                )
                first_deb.parent.mkdir(parents=True)
                second_deb.parent.mkdir(parents=True)
                first_deb.write_bytes(expected_payload)
                if use_hardlinks:
                    os.link(first_deb, second_deb)
                else:
                    second_deb.write_bytes(expected_payload)

                output = base / f"{label}.tar.gz"
                args = argparse.Namespace(
                    project=str(project), output=output, force=False,
                    max_file_size_mib=50, include_images=False,
                    include_apps=True, apps_platform=None,
                    apps_platforms={
                        "ubuntu-24.04/amd64", "ubuntu-24.04/arm64",
                    },
                    include_firmware=False, exclude_project_images=False,
                )
                with mock.patch.multiple(
                    package,
                    ROOT=workspace,
                    DAY0=day0,
                    MANIFEST=workspace / "ztp/.setup_manifest",
                    TOOLS_DIR=workspace / "tools",
                    write_deployment_source_manifest=self._stable_source_manifest,
                ):
                    package.create_package(
                        args, day0_all=True, artifact_kind="download",
                    )
                archives[label] = output

                with tarfile.open(output, "r:gz") as archive:
                    for member_name in selected_members:
                        with self.subTest(tree=label, member=member_name):
                            member = archive.getmember(member_name)
                            self.assertTrue(member.isreg())
                            self.assertEqual(0o644, member.mode)
                            self.assertEqual("", member.linkname)
                            stream = archive.extractfile(member)
                            self.assertIsNotNone(stream)
                            self.assertEqual(
                                expected_digest,
                                hashlib.sha256(stream.read()).hexdigest(),
                            )

            self.assertEqual(
                archives["independent"].read_bytes(),
                archives["hardlinked"].read_bytes(),
            )

    def test_real_package_rejects_selected_file_rebind_at_tar_open_boundary(self):
        """A validated source cannot be rebound before tar reads its bytes."""
        trusted_payload = b"H02-trusted-selected-payload\n"
        hostile_payload = b"H02-hostile-selected-payload\n"
        self.assertEqual(len(trusted_payload), len(hostile_payload))

        for source_layout in ("regular", "hardlink"):
            for replacement_kind in (
                None,
                "outside-symlink",
                "other-regular",
                "same-inode-write",
            ):
                with self.subTest(
                    source_layout=source_layout,
                    replacement_kind=replacement_kind,
                ), tempfile.TemporaryDirectory() as directory:
                    base = Path(directory)
                    workspace, day0, project = self._minimal_package_workspace(base)
                    first = workspace / "payload-a.txt"
                    second = workspace / "payload-b.txt"
                    first.write_bytes(trusted_payload)
                    if source_layout == "hardlink":
                        os.link(first, second)
                    else:
                        second.write_bytes(trusted_payload)

                    outside = base / "outside-sentinel.txt"
                    outside.write_bytes(hostile_payload)
                    staged_replacement = base / "staged-replacement"
                    if replacement_kind == "outside-symlink":
                        staged_replacement.symlink_to(outside)
                    elif replacement_kind == "other-regular":
                        staged_replacement.write_bytes(hostile_payload)

                    output = base / (
                        f"rebind-{source_layout}-{replacement_kind}.tar.gz"
                    )
                    args = argparse.Namespace(
                        project=str(project), output=output, force=False,
                        max_file_size_mib=50, include_images=False,
                        include_apps=False, apps_platform=None,
                        apps_platforms=set(), include_firmware=False,
                        exclude_project_images=False,
                    )
                    real_os_open = package.os.open
                    real_addfile = package.tarfile.TarFile.addfile
                    open_attempts = []
                    held_descriptors = []
                    target_addfile_descriptors = []
                    swapped = []

                    def bind_then_replace(name, flags, *open_args, **open_kwargs):
                        candidate = Path(os.path.abspath(os.fspath(name)))
                        if candidate != second:
                            return real_os_open(
                                name, flags, *open_args, **open_kwargs,
                            )
                        open_attempts.append(flags)
                        descriptor = real_os_open(
                            name, flags, *open_args, **open_kwargs,
                        )
                        held_descriptors.append((
                            descriptor,
                            os.fstat(descriptor).st_dev,
                            os.fstat(descriptor).st_ino,
                        ))
                        if (
                            replacement_kind in {
                                "outside-symlink", "other-regular",
                            }
                            and not swapped
                        ):
                            os.replace(staged_replacement, second)
                            swapped.append(replacement_kind)
                        return descriptor

                    def record_addfile(
                        archive, tarinfo, fileobj=None,
                    ):
                        if tarinfo.name == "./payload-b.txt":
                            target_addfile_descriptors.append(
                                None if fileobj is None else fileobj.fileno()
                            )
                            if (
                                replacement_kind == "same-inode-write"
                                and not swapped
                            ):
                                second.write_bytes(hostile_payload)
                                swapped.append(replacement_kind)
                        return real_addfile(archive, tarinfo, fileobj)

                    failure = None
                    with mock.patch.multiple(
                        package,
                        ROOT=workspace,
                        DAY0=day0,
                        MANIFEST=workspace / "ztp/.setup_manifest",
                        TOOLS_DIR=workspace / "tools",
                        write_deployment_source_manifest=self._stable_source_manifest,
                    ), mock.patch.object(
                        package.os, "open", side_effect=bind_then_replace,
                    ), mock.patch.object(
                        package.tarfile.TarFile,
                        "addfile",
                        autospec=True,
                        side_effect=record_addfile,
                    ):
                        try:
                            package.create_package(
                                args, day0_all=True, artifact_kind="download",
                            )
                        except Exception as exc:
                            failure = exc

                    self.assertEqual(
                        1, len(open_attempts),
                        "each selected source must be opened exactly once",
                    )
                    flags = open_attempts[0]
                    self.assertEqual(package.os.O_RDONLY, flags & package.os.O_ACCMODE)
                    self.assertEqual(package.os.O_NOFOLLOW, flags & package.os.O_NOFOLLOW)
                    self.assertEqual(package.os.O_CLOEXEC, flags & package.os.O_CLOEXEC)
                    self.assertEqual(package.os.O_NONBLOCK, flags & package.os.O_NONBLOCK)
                    for prohibited_flag in (
                        package.os.O_WRONLY,
                        package.os.O_RDWR,
                        package.os.O_CREAT,
                        package.os.O_TRUNC,
                        package.os.O_APPEND,
                    ):
                        self.assertEqual(0, flags & prohibited_flag)
                    self.assertEqual(1, len(held_descriptors))
                    for descriptor, _device, _inode in held_descriptors:
                        with self.assertRaises(OSError) as closed:
                            os.fstat(descriptor)
                        self.assertEqual(errno.EBADF, closed.exception.errno)
                    self.assertEqual(hostile_payload, outside.read_bytes())
                    if replacement_kind is not None:
                        self.assertEqual([replacement_kind], swapped)
                        if target_addfile_descriptors:
                            self.assertEqual(
                                [held_descriptors[0][0]],
                                target_addfile_descriptors,
                                "tar must read only through the held source stream",
                            )
                        self.assertIsNotNone(
                            failure,
                            "a source rebound after validation must fail closed",
                        )
                        if output.exists():
                            with tarfile.open(output, "r:gz") as archive:
                                archived_payloads = [
                                    stream.read()
                                    for member in archive.getmembers()
                                    if member.isfile()
                                    for stream in [archive.extractfile(member)]
                                    if stream is not None
                                ]
                            self.assertNotIn(hostile_payload, archived_payloads)
                        self.assertFalse(output.exists())
                        self.assertEqual(
                            [], list(base.glob(".http-air-package-*")),
                        )
                    else:
                        self.assertEqual(
                            [held_descriptors[0][0]],
                            target_addfile_descriptors,
                            "tar must consume the same descriptor opened nofollow",
                        )
                        self.assertIsNone(failure)
                        with tarfile.open(output, "r:gz") as archive:
                            stream = archive.extractfile("./payload-b.txt")
                            self.assertIsNotNone(stream)
                            self.assertEqual(trusted_payload, stream.read())

    def test_real_package_binds_directory_traversal_against_path_replacement(self):
        """Recursive selection stays rooted in one held directory identity."""
        trusted_payload = b"H02-trusted-directory-child\n"
        hostile_payload = b"H02-hostile-directory-child\n"
        self.assertEqual(len(trusted_payload), len(hostile_payload))

        rows = ((None, None),) + tuple(
            (depth, replacement)
            for depth in ("top", "nested")
            for replacement in ("outside-symlink", "other-directory")
        )
        for attack_depth, replacement_kind in rows:
            with self.subTest(
                attack_depth=attack_depth,
                replacement_kind=replacement_kind,
            ), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                workspace, day0, project = self._minimal_package_workspace(base)
                selected_dir = workspace / "payload-dir"
                selected_dir.mkdir()
                nested_dir = selected_dir / "nested"
                nested_dir.mkdir()
                (nested_dir / "trusted.txt").write_bytes(trusted_payload)
                saved_dir = base / "saved-original-directory"

                outside_dir = base / "outside-directory"
                outside_dir.mkdir()
                (outside_dir / "secret.txt").write_bytes(hostile_payload)
                staged_replacement = base / "staged-directory-replacement"
                if replacement_kind == "outside-symlink":
                    staged_replacement.symlink_to(outside_dir, target_is_directory=True)
                elif replacement_kind == "other-directory":
                    staged_replacement.mkdir()
                    (staged_replacement / "secret.txt").write_bytes(hostile_payload)

                output = base / f"directory-rebind-{replacement_kind}.tar.gz"
                args = argparse.Namespace(
                    project=str(project), output=output, force=False,
                    max_file_size_mib=50, include_images=False,
                    include_apps=False, apps_platform=None,
                    apps_platforms=set(), include_firmware=False,
                    exclude_project_images=False,
                )
                real_os_open = package.os.open
                real_addfile = package.tarfile.TarFile.addfile
                directory_open_records = []
                child_open_records = []
                directory_add_events = []
                attack_events = []

                def record_bound_open(name, flags, *open_args, **open_kwargs):
                    raw_name = os.fspath(name)
                    candidate = (
                        Path(os.path.abspath(raw_name))
                        if os.path.isabs(raw_name)
                        else None
                    )
                    if candidate == selected_dir:
                        descriptor = real_os_open(
                            name, flags, *open_args, **open_kwargs,
                        )
                        directory_open_records.append((
                            "top", raw_name, open_kwargs.get("dir_fd"),
                            flags, descriptor,
                        ))
                        return descriptor
                    if raw_name == "nested":
                        descriptor = real_os_open(
                            name, flags, *open_args, **open_kwargs,
                        )
                        directory_open_records.append((
                            "nested", raw_name, open_kwargs.get("dir_fd"),
                            flags, descriptor,
                        ))
                        return descriptor
                    if Path(raw_name).name == "trusted.txt":
                        child_open_records.append((
                            raw_name,
                            open_kwargs.get("dir_fd"),
                        ))
                    return real_os_open(name, flags, *open_args, **open_kwargs)

                def replace_after_directory_header(
                    archive, tarinfo, fileobj=None,
                ):
                    result = real_addfile(archive, tarinfo, fileobj)
                    if tarinfo.name in {
                        "./payload-dir", "./payload-dir/nested",
                    }:
                        directory_add_events.append(tarinfo.name)
                    attacked_name = (
                        "./payload-dir"
                        if attack_depth == "top"
                        else "./payload-dir/nested"
                    )
                    if (
                        replacement_kind is not None
                        and tarinfo.name == attacked_name
                    ):
                        attack_events.append(tarinfo.name)
                        attacked_path = (
                            selected_dir if attack_depth == "top" else nested_dir
                        )
                        os.replace(attacked_path, saved_dir)
                        if attack_depth == "top":
                            os.replace(staged_replacement, selected_dir)
                        else:
                            os.replace(staged_replacement, nested_dir)
                    return result

                failure = None
                with mock.patch.multiple(
                    package,
                    ROOT=workspace,
                    DAY0=day0,
                    MANIFEST=workspace / "ztp/.setup_manifest",
                    TOOLS_DIR=workspace / "tools",
                    write_deployment_source_manifest=self._stable_source_manifest,
                ), mock.patch.object(
                    package.os, "open", side_effect=record_bound_open,
                ), mock.patch.object(
                    package.tarfile.TarFile,
                    "addfile",
                    autospec=True,
                    side_effect=replace_after_directory_header,
                ):
                    try:
                        package.create_package(
                            args, day0_all=True, artifact_kind="download",
                        )
                    except Exception as exc:
                        failure = exc

                by_depth = {
                    record[0]: record for record in directory_open_records
                }
                self.assertIn("top", by_depth)
                top_record = by_depth["top"]
                if attack_depth != "top":
                    self.assertIn("nested", by_depth)
                if "nested" in by_depth:
                    nested_record = by_depth["nested"]
                    self.assertEqual("nested", nested_record[1])
                    self.assertEqual(top_record[4], nested_record[2])
                for _depth, _name, _parent_fd, flags, _descriptor in (
                    directory_open_records
                ):
                    self.assertEqual(
                        package.os.O_RDONLY, flags & package.os.O_ACCMODE,
                    )
                    self.assertEqual(
                        package.os.O_DIRECTORY, flags & package.os.O_DIRECTORY,
                    )
                    self.assertEqual(
                        package.os.O_NOFOLLOW, flags & package.os.O_NOFOLLOW,
                    )
                    self.assertEqual(
                        package.os.O_CLOEXEC, flags & package.os.O_CLOEXEC,
                    )
                    self.assertEqual(
                        package.os.O_NONBLOCK, flags & package.os.O_NONBLOCK,
                    )
                for _depth, _name, _parent_fd, _flags, descriptor in (
                    directory_open_records
                ):
                    with self.assertRaises(OSError) as closed:
                        os.fstat(descriptor)
                    self.assertEqual(errno.EBADF, closed.exception.errno)

                if replacement_kind is None:
                    self.assertEqual([], attack_events)
                    self.assertEqual([
                        "./payload-dir", "./payload-dir/nested",
                    ], directory_add_events)
                    self.assertIsNone(failure)
                    self.assertEqual(
                        [("trusted.txt", by_depth["nested"][4])],
                        child_open_records,
                        "children must be opened relative to the held directory",
                    )
                    with tarfile.open(output, "r:gz") as archive:
                        stream = archive.extractfile(
                            "./payload-dir/nested/trusted.txt",
                        )
                        self.assertIsNotNone(stream)
                        self.assertEqual(trusted_payload, stream.read())
                        self.assertNotIn(
                            "./payload-dir/nested/secret.txt",
                            archive.getnames(),
                        )
                else:
                    attacked_name = (
                        "./payload-dir"
                        if attack_depth == "top"
                        else "./payload-dir/nested"
                    )
                    self.assertEqual([attacked_name], attack_events)
                    self.assertIsNotNone(failure)
                    self.assertEqual(hostile_payload, (
                        outside_dir / "secret.txt"
                    ).read_bytes())
                    self.assertFalse(output.exists())
                    self.assertEqual([], list(base.glob(".http-air-package-*")))

    def test_held_regular_stream_owns_its_descriptor_without_double_close(self):
        """Error cleanup never closes an unrelated descriptor that reused its FD."""
        for fault in ("stream-exception", "fdopen-construction"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                workspace, day0, project = self._minimal_package_workspace(base)
                selected = workspace / "zz-held-source.txt"
                selected.write_bytes(b"H02-held-source\n")
                sentinel = base / "unrelated-sentinel.txt"
                sentinel_payload = b"H02-unrelated-descriptor\n"
                sentinel.write_bytes(sentinel_payload)
                sentinel_fd = os.open(sentinel, os.O_RDONLY | os.O_CLOEXEC)
                output = base / f"fd-ownership-{fault}.tar.gz"
                args = argparse.Namespace(
                    project=str(project), output=output, force=False,
                    max_file_size_mib=50, include_images=False,
                    include_apps=False, apps_platform=None,
                    apps_platforms=set(), include_firmware=False,
                    exclude_project_images=False,
                )
                real_os_open = package.os.open
                real_os_close = package.os.close
                real_fdopen = package.os.fdopen
                real_addfile = package.tarfile.TarFile.addfile
                selected_fds = []
                raw_close_calls = []
                reuse_events = []

                def record_selected_open(name, flags, *open_args, **open_kwargs):
                    descriptor = real_os_open(
                        name, flags, *open_args, **open_kwargs,
                    )
                    if Path(os.path.abspath(os.fspath(name))) == selected:
                        selected_fds.append(descriptor)
                    return descriptor

                def record_raw_close(descriptor):
                    if descriptor in selected_fds:
                        raw_close_calls.append(descriptor)
                    return real_os_close(descriptor)

                class ReusingStream:
                    def __init__(self, stream, descriptor):
                        self._stream = stream
                        self._descriptor = descriptor

                    def __getattr__(self, name):
                        return getattr(self._stream, name)

                    def __enter__(self):
                        return self

                    def __exit__(self, exc_type, exc, traceback):
                        self._stream.close()
                        os.dup2(sentinel_fd, self._descriptor)
                        reuse_events.append(self._descriptor)
                        return False

                def controlled_fdopen(descriptor, *fdopen_args, **fdopen_kwargs):
                    if descriptor not in selected_fds:
                        return real_fdopen(
                            descriptor, *fdopen_args, **fdopen_kwargs,
                        )
                    if fault == "fdopen-construction":
                        raise OSError("injected fdopen construction failure")
                    return ReusingStream(
                        real_fdopen(
                            descriptor, *fdopen_args, **fdopen_kwargs,
                        ),
                        descriptor,
                    )

                def fail_selected_addfile(archive, tarinfo, fileobj=None):
                    if (
                        fault == "stream-exception"
                        and tarinfo.name == "./zz-held-source.txt"
                    ):
                        raise RuntimeError("injected tar read failure")
                    return real_addfile(archive, tarinfo, fileobj)

                try:
                    with mock.patch.multiple(
                        package,
                        ROOT=workspace,
                        DAY0=day0,
                        MANIFEST=workspace / "ztp/.setup_manifest",
                        TOOLS_DIR=workspace / "tools",
                        write_deployment_source_manifest=self._stable_source_manifest,
                    ), mock.patch.object(
                        package.os, "open", side_effect=record_selected_open,
                    ), mock.patch.object(
                        package.os, "close", side_effect=record_raw_close,
                    ), mock.patch.object(
                        package.os, "fdopen", side_effect=controlled_fdopen,
                    ), mock.patch.object(
                        package.tarfile.TarFile,
                        "addfile",
                        autospec=True,
                        side_effect=fail_selected_addfile,
                    ), self.assertRaisesRegex(
                        (RuntimeError, OSError),
                        "injected (?:tar read|fdopen construction) failure",
                    ):
                        package.create_package(
                            args, day0_all=True, artifact_kind="download",
                        )

                    self.assertEqual(1, len(selected_fds))
                    selected_fd = selected_fds[0]
                    if fault == "stream-exception":
                        self.assertEqual([selected_fd], reuse_events)
                        os.fstat(selected_fd)
                        self.assertEqual(
                            sentinel_payload,
                            os.read(selected_fd, len(sentinel_payload)),
                        )
                        self.assertEqual([], raw_close_calls)
                    else:
                        self.assertEqual([], reuse_events)
                        with self.assertRaises(OSError) as closed:
                            os.fstat(selected_fd)
                        self.assertEqual(errno.EBADF, closed.exception.errno)
                        self.assertEqual([selected_fd], raw_close_calls)
                    self.assertFalse(output.exists())
                    self.assertEqual([], list(base.glob(".http-air-package-*")))
                finally:
                    for descriptor in selected_fds:
                        try:
                            os.close(descriptor)
                        except OSError:
                            pass
                    os.close(sentinel_fd)

    def test_hardlinks_obey_the_same_fixed_file_size_boundary_as_regular_files(self):
        """Inode sharing cannot bypass or double-count the 1 MiB policy."""
        limit = 1024 * 1024
        boundary_payloads = {
            "below": b"B" * (limit - 1),
            "equal": b"E" * limit,
            "above": b"A" * (limit + 1),
        }
        archives = {}
        outcomes = {}

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for label, use_hardlinks in (
                ("independent", False),
                ("hardlinked", True),
            ):
                workspace, day0, project = self._minimal_package_workspace(
                    base / label,
                )
                payload_root = workspace / "payloads"
                payload_root.mkdir()
                for boundary, payload in boundary_payloads.items():
                    first = payload_root / f"{boundary}-a.txt"
                    second = payload_root / f"{boundary}-b.txt"
                    first.write_bytes(payload)
                    if use_hardlinks:
                        os.link(first, second)
                    else:
                        second.write_bytes(payload)

                output = base / f"size-boundary-{label}.tar.gz"
                args = argparse.Namespace(
                    project=str(project), output=output, force=False,
                    max_file_size_mib=1, include_images=False,
                    include_apps=False, apps_platform=None,
                    apps_platforms=set(), include_firmware=False,
                    exclude_project_images=False,
                )
                real_filter = package.PackageFilter
                filters = []

                def build_filter(*filter_args, **filter_kwargs):
                    instance = real_filter(*filter_args, **filter_kwargs)
                    filters.append(instance)
                    return instance

                with mock.patch.multiple(
                    package,
                    ROOT=workspace,
                    DAY0=day0,
                    MANIFEST=workspace / "ztp/.setup_manifest",
                    TOOLS_DIR=workspace / "tools",
                    write_deployment_source_manifest=self._stable_source_manifest,
                ), mock.patch.object(
                    package, "PackageFilter", side_effect=build_filter,
                ):
                    package.create_package(
                        args, day0_all=True, artifact_kind="download",
                    )

                self.assertEqual(1, len(filters))
                package_filter = filters[0]
                self.assertEqual(
                    2,
                    package_filter.reasons.get("generic large file"),
                    "both above-limit names must be counted exactly once",
                )
                archives[label] = output.read_bytes()
                with tarfile.open(output, "r:gz") as archive:
                    members = archive.getmembers()
                    payload_members = {
                        member.name: member
                        for member in members
                        if member.name.startswith("./payloads/")
                    }
                    for boundary in ("below", "equal"):
                        expected_payload = boundary_payloads[boundary]
                        for suffix in ("a", "b"):
                            name = f"./payloads/{boundary}-{suffix}.txt"
                            member = payload_members[name]
                            self.assertTrue(member.isreg())
                            self.assertEqual(len(expected_payload), member.size)
                            stream = archive.extractfile(member)
                            self.assertIsNotNone(stream)
                            self.assertEqual(expected_payload, stream.read())
                    self.assertNotIn("./payloads/above-a.txt", payload_members)
                    self.assertNotIn("./payloads/above-b.txt", payload_members)
                    outcomes[label] = (
                        tuple(sorted(payload_members)),
                        dict(package_filter.reasons),
                        package_filter.excluded_files,
                        package_filter.excluded_bytes,
                    )

            self.assertEqual(outcomes["independent"], outcomes["hardlinked"])
            self.assertEqual(archives["independent"], archives["hardlinked"])

    def test_real_package_rejects_fifo_before_archive_publication(self):
        """A selected special node fails before output or temp publication."""
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            workspace, day0, project = self._minimal_package_workspace(base)
            fifo = project / "selected-runtime.pipe"
            os.mkfifo(fifo, 0o600)
            output = base / "special-node.tar.gz"
            publication_events = []
            real_replace = package.os.replace

            def record_replace(source, destination, *args, **kwargs):
                publication_events.append(
                    (Path(source).name, Path(destination).resolve()),
                )
                return real_replace(source, destination, *args, **kwargs)

            args = argparse.Namespace(
                project=str(project), output=output, force=False,
                max_file_size_mib=50, include_images=False,
                include_apps=False, apps_platform=None, apps_platforms=set(),
                include_firmware=False, exclude_project_images=False,
            )
            with mock.patch.multiple(
                package,
                ROOT=workspace,
                DAY0=day0,
                MANIFEST=workspace / "ztp/.setup_manifest",
                TOOLS_DIR=workspace / "tools",
                write_deployment_source_manifest=self._stable_source_manifest,
            ), mock.patch.object(
                package.os, "replace", side_effect=record_replace,
            ), mock.patch.object(
                package, "validate_deployment_archive_members",
                wraps=package.validate_deployment_archive_members,
            ) as final_validator, self.assertRaises(ValueError):
                package.create_package(
                    args, day0_all=True, artifact_kind="download",
                )

            final_validator.assert_not_called()
            self.assertEqual([], publication_events)
            self.assertFalse(output.exists())
            self.assertEqual([], list(base.glob(".http-air-package-*")))

    def test_zero_byte_project_bin_does_not_disable_deflate(self):
        """A shipped empty image placeholder is shape, not payload authority."""
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            workspace, day0, project = self._minimal_package_workspace(base)
            (project / "switch-image-placeholder.bin").write_bytes(b"")
            output = base / "zero-placeholder.tar.gz"
            levels = []
            real_gzip_file = package.gzip.GzipFile

            def recording_gzip_file(*args, **kwargs):
                if kwargs.get("mode") == "wb":
                    levels.append(kwargs.get("compresslevel"))
                return real_gzip_file(*args, **kwargs)

            args = argparse.Namespace(
                project=str(project), output=output, force=False,
                max_file_size_mib=50, include_images=False,
                include_apps=False, apps_platform=None,
                apps_platforms=set(), include_firmware=False,
                exclude_project_images=False,
            )
            with mock.patch.multiple(
                package,
                ROOT=workspace,
                DAY0=day0,
                MANIFEST=workspace / "ztp/.setup_manifest",
                TOOLS_DIR=workspace / "tools",
                write_deployment_source_manifest=self._stable_source_manifest,
            ), mock.patch.object(
                package.gzip, "GzipFile", side_effect=recording_gzip_file,
            ):
                package.create_package(
                    args, day0_all=True, artifact_kind="download",
                )

            self.assertEqual([6], levels)

    def test_large_binary_package_variants_use_stored_gzip_without_deflate(self):
        """Every supported binary namespace avoids recompressing its payload."""
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            workspace, day0, project = self._minimal_package_workspace(base)
            variants = (
                (
                    "images", workspace / "image/switch-image.bin",
                    {"include_images": True, "include_apps": False,
                     "include_firmware": False},
                ),
                (
                    "apps", workspace / "apps/offline-package.bin",
                    {"include_images": False, "include_apps": True,
                     "include_firmware": False},
                ),
                (
                    "firmware", workspace / "firmware/switch-fw.bin",
                    {"include_images": False, "include_apps": False,
                     "include_firmware": True},
                ),
                (
                    "project-bin", project / "switch-image.bin",
                    {"include_images": False, "include_apps": False,
                     "include_firmware": False},
                ),
            )
            real_gzip_file = package.gzip.GzipFile

            for label, payload, flags in variants:
                with self.subTest(label=label):
                    payload.parent.mkdir(parents=True, exist_ok=True)
                    payload.write_bytes(b"\0" * (512 * 1024))
                    output = base / f"{label}.tar.gz"
                    levels = []

                    def recording_gzip_file(*args, **kwargs):
                        if kwargs.get("mode") == "wb":
                            levels.append(kwargs.get("compresslevel"))
                        return real_gzip_file(*args, **kwargs)

                    package_args = argparse.Namespace(
                        project=str(project), output=output, force=False,
                        max_file_size_mib=50, apps_platform=None,
                        apps_platforms=set(), exclude_project_images=False,
                        **flags,
                    )
                    with mock.patch.multiple(
                        package,
                        ROOT=workspace,
                        DAY0=day0,
                        MANIFEST=workspace / "ztp/.setup_manifest",
                        TOOLS_DIR=workspace / "tools",
                        write_deployment_source_manifest=self._stable_source_manifest,
                    ), mock.patch.object(
                        package.gzip, "GzipFile", side_effect=recording_gzip_file,
                    ):
                        package.create_package(
                            package_args, day0_all=True,
                            artifact_kind="download",
                        )

                    self.assertEqual([0], levels)
                    self.assertGreater(output.stat().st_size, payload.stat().st_size)
                    with tarfile.open(output, "r:gz") as archive:
                        archived = archive.extractfile(
                            "./" + payload.relative_to(workspace).as_posix()
                        ).read()
                    self.assertEqual(payload.read_bytes(), archived)

            excluded = project / "switch-image.bin"
            write_picture_workbook(project / "p2p.xlsx")
            output = base / "project-image-excluded.tar.gz"
            levels = []

            def recording_excluded_gzip_file(*args, **kwargs):
                if kwargs.get("mode") == "wb":
                    levels.append(kwargs.get("compresslevel"))
                return real_gzip_file(*args, **kwargs)

            package_args = argparse.Namespace(
                project=str(project), output=output, force=False,
                max_file_size_mib=50, include_images=False,
                include_apps=False, apps_platform=None,
                apps_platforms=set(), include_firmware=False,
                exclude_project_images=True,
            )
            with mock.patch.multiple(
                package,
                ROOT=workspace,
                DAY0=day0,
                MANIFEST=workspace / "ztp/.setup_manifest",
                TOOLS_DIR=workspace / "tools",
                write_deployment_source_manifest=self._stable_source_manifest,
            ), mock.patch.object(
                package.gzip, "GzipFile", side_effect=recording_excluded_gzip_file,
            ):
                package.create_package(
                    package_args, day0_all=False, artifact_kind="upload",
                )

            self.assertEqual([6], levels)
            with tarfile.open(output, "r:gz") as archive:
                self.assertNotIn(
                    "./" + excluded.relative_to(workspace).as_posix(),
                    archive.getnames(),
                )


if __name__ == "__main__":
    unittest.main()
