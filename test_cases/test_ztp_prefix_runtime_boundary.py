#!/usr/bin/env python3
"""Targeted tests for custom ZTP prefix runtime ownership boundaries."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(path.parent))
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
    return module


PACKAGE = load_module("prefix_boundary_package", ROOT / "tools/_package_common.py")
CONTRACT = sys.modules["project_contract"]
SYNC = load_module("prefix_boundary_sync", ROOT / "tools/sync-code.py")
UNLOAD = load_module("prefix_boundary_unload", ROOT / "DAY0-Prepare/13-unload.py")


def write_publication(
    root: Path, prefix: str = "/published/ztp", *, create_link: bool = True,
) -> tuple[Path, Path]:
    root = root.resolve()
    target = root / "ztp"
    target.mkdir(parents=True, exist_ok=True)
    leaf = root.joinpath(*prefix.lstrip("/").split("/"))
    leaf.parent.mkdir(parents=True, exist_ok=True)
    if create_link:
        leaf.symlink_to(os.path.relpath(target, leaf.parent))
    marker = root / CONTRACT.ZTP_PREFIX_PUBLICATION_MARKER
    marker.write_text(json.dumps({
        "schema_version": 1,
        "prefix": prefix,
        "path": str(leaf),
        "target": str(target),
    }), encoding="utf-8")
    return marker, leaf


class ZtpPrefixTransferBoundaryTests(unittest.TestCase):
    def test_marker_and_declared_symlink_are_excluded_from_upload_contract(self):
        self.assertIsNotNone(CONTRACT.transfer_exclude_reason(
            CONTRACT.ZTP_PREFIX_PUBLICATION_MARKER
        ))
        self.assertIn(
            CONTRACT.ZTP_PREFIX_PUBLICATION_MARKER,
            CONTRACT.rsync_excludes(),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "DAY0-Prepare/project"
            project.mkdir(parents=True)
            marker, leaf = write_publication(root)
            manifest = root / "ztp/.setup_manifest"
            manifest.write_text(
                str(marker.parent / "monitor/01-global.yaml") + "\n",
                encoding="utf-8",
            )
            with mock.patch.multiple(
                PACKAGE,
                ROOT=root,
                DAY0=root / "DAY0-Prepare",
                MANIFEST=manifest,
            ):
                links = PACKAGE.setup_managed_links()
                self.assertIn("published/ztp", links)
                self.assertIn("monitor/01-global.yaml", links)

                package_filter = PACKAGE.PackageFilter(
                    project,
                    root / "output.tar.gz",
                    include_images=False,
                    include_apps=False,
                    include_firmware=False,
                    max_file_size=1024,
                    day0_all=False,
                )
                member = tarfile.TarInfo("published/ztp")
                member.type = tarfile.SYMTYPE
                member.linkname = os.readlink(leaf)
                self.assertIsNone(package_filter(member))
                self.assertEqual(
                    1, package_filter.reasons["setup-managed runtime link"]
                )
            self.assertTrue(marker.is_file())
            self.assertTrue(leaf.is_symlink())

    def test_invalid_marker_and_conflicting_leaf_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker, leaf = write_publication(root)
            marker.write_text("{not-json", encoding="utf-8")
            with mock.patch.multiple(
                PACKAGE,
                ROOT=root,
                DAY0=root / "DAY0-Prepare",
                MANIFEST=root / "ztp/.setup_manifest",
            ):
                with self.assertRaisesRegex(ValueError, "invalid ZTP prefix marker"):
                    PACKAGE.setup_managed_links()

            marker.unlink()
            leaf.unlink()
            marker, leaf = write_publication(root)
            leaf.unlink()
            other = root / "other"
            other.mkdir()
            leaf.symlink_to(os.path.relpath(other, leaf.parent))
            with self.assertRaisesRegex(ValueError, "unexpected target"):
                CONTRACT.ztp_prefix_publication_relative(root)
            self.assertTrue(marker.is_file())
            self.assertTrue(leaf.is_symlink())

    def test_percent_encoded_prefix_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_publication(root, "/published%2Fshadow/ztp")
            with self.assertRaisesRegex(ValueError, "unsafe custom ZTP prefix"):
                CONTRACT.ztp_prefix_publication_relative(root)

    def test_sync_consumes_runtime_link_set_and_common_marker_exclude(self):
        project = ROOT / "DAY0-Prepare/template"
        with mock.patch.object(
            SYNC,
            "package_setup_managed_links",
            return_value={
                "monitor/published/ztp",
                "tools/lldp-analyze-tool/published/ztp",
                "DAY0-Prepare/template/published/ztp",
            },
        ):
            jobs = SYNC.build_jobs(project, "/var/www/html")
        monitor = next(job for job in jobs if job.label == "code:monitor")
        self.assertIn("/published/ztp", monitor.excludes)
        self.assertIn(CONTRACT.ZTP_PREFIX_PUBLICATION_MARKER, monitor.excludes)
        ztp = next(job for job in jobs if job.label == "code:ztp")
        self.assertIn("/ztp.json", ztp.excludes)
        self.assertNotIn("/templates/ztp.json", ztp.excludes)
        self.assertTrue((ROOT / "ztp/templates/ztp.json").is_file())
        lldp = next(
            job for job in jobs if job.label == "code:tools/lldp-analyze-tool"
        )
        self.assertIn("/published/ztp", lldp.excludes)
        template = next(job for job in jobs if job.label == "DAY0:template")
        selected_project = next(
            job for job in jobs if job.label == "project:template"
        )
        self.assertIn("/published/ztp", template.excludes)
        self.assertIn("/published/ztp", selected_project.excludes)


class ZtpPrefixUnloadBoundaryTests(unittest.TestCase):
    def test_dry_run_then_unload_removes_only_leaf_and_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker, leaf = write_publication(root)
            parent = leaf.parent
            with mock.patch.multiple(UNLOAD, HTTP_ROOT=root, ZTP_DIR=root / "ztp"):
                UNLOAD.remove_ztp_prefix_publication(dry_run=True)
                self.assertTrue(marker.is_file())
                self.assertTrue(leaf.is_symlink())

                UNLOAD.remove_ztp_prefix_publication(dry_run=False)
            self.assertFalse(os.path.lexists(marker))
            self.assertFalse(os.path.lexists(leaf))
            self.assertTrue(parent.is_dir())
            self.assertTrue((root / "ztp").is_dir())

    def test_missing_or_conflicting_leaf_is_not_touched(self):
        for case in ("missing", "wrong-target", "real-directory"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                marker, leaf = write_publication(root, create_link=case != "missing")
                if case == "wrong-target":
                    leaf.unlink()
                    other = root / "other"
                    other.mkdir()
                    leaf.symlink_to(os.path.relpath(other, leaf.parent))
                elif case == "real-directory":
                    leaf.unlink()
                    leaf.mkdir()
                with mock.patch.multiple(UNLOAD, HTTP_ROOT=root, ZTP_DIR=root / "ztp"):
                    with self.assertRaises(UNLOAD.UnloadError):
                        UNLOAD.remove_ztp_prefix_publication(dry_run=False)
                self.assertTrue(marker.is_file())
                if case == "missing":
                    self.assertFalse(os.path.lexists(leaf))
                elif case == "wrong-target":
                    self.assertTrue(leaf.is_symlink())
                else:
                    self.assertTrue(leaf.is_dir())

    def test_unload_calls_prefix_cleanup_after_services_stop(self):
        source = (ROOT / "DAY0-Prepare/13-unload.py").read_text(encoding="utf-8")
        main = source.split("def main(", 1)[1]
        self.assertLess(
            main.index("stop_services("),
            main.index("remove_ztp_prefix_publication("),
        )


if __name__ == "__main__":
    unittest.main()
