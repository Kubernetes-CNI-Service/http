#!/usr/bin/env python3
"""Upload archive deployment-input and image-free XLSX contracts."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET
import zipfile


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


REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
OFFICE_REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
XDR_NS = "http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing"
A_NS = "http://schemas.openxmlformats.org/drawingml/2006/main"

REQUIRED_UPLOAD_SOURCES = (
    "tools/_package_common.py",
    "tools/deployment_lock.py",
    "tools/tar-for-upload.py",
    "tools/tar-for-download.py",
    "tools/sync-code.py",
    "DAY0-Prepare/11-load.py",
    "DAY0-Prepare/12-ztp-monitor.py",
    "DAY0-Prepare/13-unload.py",
    "ztp/nvue_normalizer.py",
    "ztp/optimize/feedback.py",
    "ztp/optimize/sample_links.py",
    "ztp/templates/ztp-bootstrap.sh",
    "ztp/templates/ztp.json",
)


def write_picture_workbook(path: Path) -> None:
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
        archive.writestr("xl/workbook.xml", "<workbook><keep>cells</keep></workbook>")
        archive.writestr("xl/drawings/drawing1.xml", drawing)
        archive.writestr("xl/drawings/_rels/drawing1.xml.rels", relationships)
        archive.writestr("xl/media/image1.png", b"not-a-real-png-but-an-image-payload" * 200)


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class UploadPackageContractTests(unittest.TestCase):
    @staticmethod
    def upload_args(**overrides):
        values = {
            "port": 24995,
            "host": "ubuntu@worker.example",
            "identity": None,
            "remote_dir": "/tmp",
            "remote_root": "/var/www/html",
            "deploy": False,
            "no_sudo": False,
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
            (workspace / ".deployment.lock").touch()
            for name in package.PROJECT_DEPLOYMENT_INPUTS:
                (project / name).write_text("input\n", encoding="utf-8")
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
                package.create_package(args, day0_all=False)

            self.assertEqual(before, file_digest(selected), "packaging changed source XLSX")
            self.assertEqual(0o600, stat.S_IMODE(output.stat().st_mode))
            with tarfile.open(output, "r:gz") as archive:
                names = set(archive.getnames())
                prefix = "./DAY0-Prepare/customer/"
                self.assertIn(prefix + "Customer P2P.xlsx", names)
                self.assertIn(prefix + "01-global.yaml", names)
                self.assertIn(prefix + "02-devices_config.csv", names)
                self.assertIn(prefix + "02-dhcp-subnet_config.csv", names)
                self.assertIn(prefix + "laptop.pub", names)
                self.assertIn(prefix + "switch.bin", names)
                self.assertNotIn(prefix + "p2p.xlsx", names)
                self.assertNotIn(prefix + "ip-vlan design.xlsx", names)
                self.assertNotIn(prefix + "README.txt", names)
                self.assertNotIn("./README.md", names)
                self.assertNotIn("./.deployment.lock", names)
                self.assertIn("./ztp/templates/ztp.json", names)
                self.assertFalse(
                    any(Path(name).name.startswith(".http-air-package-") for name in names)
                )
                payload = archive.extractfile(prefix + "Customer P2P.xlsx")
                self.assertIsNotNone(payload)
                with zipfile.ZipFile(io.BytesIO(payload.read())) as workbook:
                    self.assertFalse(
                        any(name.startswith("xl/media/") for name in workbook.namelist())
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
                    package.create_package(args, day0_all=False)

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


if __name__ == "__main__":
    unittest.main()
