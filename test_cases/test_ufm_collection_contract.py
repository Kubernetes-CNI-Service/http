#!/usr/bin/env python3
"""D-70 UFM collection artifact contract on synthetic local inputs only."""

from __future__ import annotations

import datetime as dt
from dataclasses import replace
import io
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
from unittest import mock

from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
COLLECTION = load_script(
    "ufm_collection_contract_direct", ROOT / "tools/ufm_collection_contract.py"
)


def synthetic_archive(path: Path, content: bytes) -> bytes:
    with tarfile.open(path, "w:gz") as archive:
        member = tarfile.TarInfo("artifact")
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))
    return path.read_bytes()


class UfmCollectionContractTests(unittest.TestCase):
    def test_single_deployment_run_id_drives_both_exact_archive_names(self):
        run_id = COLLECTION.make_run_id(
            dt.datetime(2026, 9, 26, 3, 15, tzinfo=dt.timezone.utc),
            "prod", "0123456789abcdef",
        )
        self.assertEqual("20260926-0315-prod-0123456789abcdef", run_id)
        diag = COLLECTION.collection_plan("ibdiagnet", run_id)
        link = COLLECTION.collection_plan("iblinkinfo", run_id)
        self.assertEqual(f"ibdiagnet2_{run_id}.tar.gz", diag.archive_name)
        self.assertEqual(f"iblinkinfo_{run_id}.tar.gz", link.archive_name)
        self.assertEqual(diag.archive_name + ".part", diag.part_name)
        self.assertEqual(link.archive_name + ".part", link.part_name)
        self.assertEqual("/var/tmp/ibdiagnet2", diag.ufm_source_path)
        self.assertEqual("/opt/ufm/files", diag.ufm_staging_path)
        self.assertEqual("/root/monitor/ibdiagnet", diag.ufm_final_directory)
        self.assertEqual("/root/monitor/iblinkinfo", link.ufm_final_directory)
        self.assertEqual((
            "/opt/ufm/opensm/bin/ibdiagnet", "--sc", "--extended_speeds", "all",
            "-P", "all=1", "--pm_per_lane", "--get_cable_info",
            "--cable_info_disconnected", "--get_phy_info", "--routing",
            "--sharp", "--phy_cable_disconnected", "--rail_validation",
        ), diag.vendor_argv)
        self.assertEqual(("/opt/ufm/opensm/sbin/iblinkinfo",), link.vendor_argv)
        self.assertEqual(
            f"/root/monitor/ibdiagnet/ibdiagnet2_{run_id}.tar.gz",
            diag.ufm_remote_path,
        )

    def test_invalid_run_id_kind_or_clock_rejects_before_any_artifact(self):
        for bad in ("", "../../escape", "20260926-0315-prod-*", "20260926-0315-prod"):
            with self.subTest(bad=bad), self.assertRaises(COLLECTION.CollectionError):
                COLLECTION.collection_plan("ibdiagnet", bad)
        with self.assertRaises(COLLECTION.CollectionError):
            COLLECTION.collection_plan("other", "20260926-0315-prod-0123456789abcdef")
        with self.assertRaises(COLLECTION.CollectionError):
            COLLECTION.make_run_id(dt.datetime(2026, 9, 26, 3, 15), "prod", "0123456789abcdef")
        with self.assertRaises(COLLECTION.CollectionError):
            COLLECTION.make_run_id(
                dt.datetime(2026, 9, 26, 3, 15, tzinfo=dt.timezone.utc),
                "prod;touch /tmp/x", "0123456789abcdef",
            )

    def test_part_is_complete_before_atomic_no_overwrite_final_publication(self):
        run_id = "20260926-0315-prod-0123456789abcdef"
        plan = COLLECTION.collection_plan("ibdiagnet", run_id)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "ibdiagnet2"
            source.mkdir()
            (source / "ibdiagnet2.net_dump").write_bytes(b"synthetic-topology\n")
            output = root / "out"
            output.mkdir()
            actual_link = os.link
            seen = []

            def inspect_before_publish(part, final, **kwargs):
                if "src_dir_fd" in kwargs:
                    with self.assertRaises(FileNotFoundError):
                        os.stat(final, dir_fd=kwargs["dst_dir_fd"])
                    part_fd = os.open(part, os.O_RDONLY,
                                      dir_fd=kwargs["src_dir_fd"])
                    with os.fdopen(part_fd, "rb") as stream, tarfile.open(
                        fileobj=stream, mode="r:gz"
                    ) as archive:
                        members = archive.getmembers()
                        self.assertIn("artifact/ibdiagnet2.net_dump", [m.name for m in members])
                        self.assertEqual(b"synthetic-topology\n", archive.extractfile(
                            "artifact/ibdiagnet2.net_dump").read())
                else:
                    self.assertFalse(Path(final).exists())
                    with tarfile.open(part, "r:gz") as archive:
                        members = archive.getmembers()
                        self.assertIn("artifact/ibdiagnet2.net_dump", [m.name for m in members])
                        self.assertEqual(b"synthetic-topology\n", archive.extractfile(
                            "artifact/ibdiagnet2.net_dump").read())
                seen.append((Path(part).name, Path(final).name))
                return actual_link(part, final, **kwargs)

            with mock.patch.object(COLLECTION.os, "link", side_effect=inspect_before_publish):
                final = COLLECTION.publish_local_archive(plan, source, output)
            self.assertEqual([(plan.part_name, plan.archive_name)], seen)
            self.assertEqual(output / plan.archive_name, final)
            self.assertFalse((output / plan.part_name).exists())
            self.assertGreater(final.stat().st_size, 0)
            with self.assertRaises(COLLECTION.CollectionError):
                COLLECTION.publish_local_archive(plan, source, output)
            with tarfile.open(final, "r:gz") as archive:
                self.assertEqual(b"synthetic-topology\n", archive.extractfile(
                    "artifact/ibdiagnet2.net_dump"
                ).read())

    def test_empty_or_symlinked_synthetic_source_has_zero_final_product(self):
        plan = COLLECTION.collection_plan(
            "iblinkinfo", "20260926-0315-prod-0123456789abcdef"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            output = root / "out"
            output.mkdir()
            empty = root / "empty"
            empty.mkdir()
            secret = root / "synthetic-secret"
            secret.write_bytes(b"not-for-archive")
            linked = root / "linked"
            linked.symlink_to(secret)
            nested = root / "nested"
            nested.mkdir()
            (nested / "unsafe-link").symlink_to(secret)
            for source in (empty, linked, nested):
                with self.subTest(source=source), self.assertRaises(COLLECTION.CollectionError):
                    COLLECTION.publish_local_archive(plan, source, output)
                self.assertFalse((output / plan.archive_name).exists())
                self.assertFalse((output / plan.part_name).exists())

    def test_forged_plan_cannot_publish_or_escape_destination(self):
        plan = COLLECTION.collection_plan(
            "ibdiagnet", "20260926-0315-prod-0123456789abcdef"
        )
        forged = replace(plan, archive_name="forged.tar.gz")
        traversal = replace(plan, archive_name="../../outside.tar.gz")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "source"
            source.write_bytes(b"synthetic-topology")
            output = root / "out"
            output.mkdir()
            with self.assertRaises(COLLECTION.CollectionError):
                COLLECTION.publish_local_archive(forged, source, output)
            with self.assertRaises(COLLECTION.CollectionError):
                _ = traversal.ufm_remote_path
            self.assertFalse((output / "forged.tar.gz").exists())

    def test_corrupted_part_never_gets_a_completion_name(self):
        plan = COLLECTION.collection_plan(
            "ibdiagnet", "20260926-0315-prod-0123456789abcdef"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "source"
            source.write_bytes(b"synthetic-topology")
            output = root / "out"
            output.mkdir()
            real_fsync = os.fsync
            corrupted = False

            def corrupt_after_file_sync(fd):
                nonlocal corrupted
                real_fsync(fd)
                part = output / plan.part_name
                if not corrupted and part.exists():
                    part.write_bytes(b"synthetic-corrupted-archive")
                    corrupted = True

            with mock.patch.object(COLLECTION.os, "fsync", side_effect=corrupt_after_file_sync):
                with self.assertRaises(COLLECTION.CollectionError):
                    COLLECTION.publish_local_archive(plan, source, output)
            self.assertTrue(corrupted, "injection must reach the completed .part")
            self.assertFalse((output / plan.archive_name).exists())
            self.assertFalse((output / plan.part_name).exists())

    def test_missing_nofollow_capability_never_starts_local_publication(self):
        plan = COLLECTION.collection_plan(
            "iblinkinfo", "20260926-0315-prod-0123456789abcdef"
        )
        for flag in ("O_DIRECTORY", "O_NOFOLLOW"):
            with self.subTest(flag=flag), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                source = root / "source"
                source.write_bytes(b"synthetic")
                output = root / "output"
                output.mkdir()
                with mock.patch.object(COLLECTION.os, flag, 0):
                    with self.assertRaises(COLLECTION.CollectionError):
                        COLLECTION.publish_local_archive(plan, source, output)
                self.assertEqual([], list(output.iterdir()))

    def test_missing_fd_relative_link_capability_never_starts_publication(self):
        plan = COLLECTION.collection_plan(
            "iblinkinfo", "20260926-0315-prod-0123456789abcdef"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "source"
            source.write_bytes(b"synthetic")
            output = root / "output"
            output.mkdir()
            supported = set(os.supports_dir_fd) - {os.link}
            with mock.patch.object(COLLECTION.os, "supports_dir_fd", supported):
                with self.assertRaises(COLLECTION.CollectionError):
                    COLLECTION.publish_local_archive(plan, source, output)
            self.assertEqual([], list(output.iterdir()))

    def test_missing_fd_relative_inode_check_never_starts_publication(self):
        plan = COLLECTION.collection_plan(
            "iblinkinfo", "20260926-0315-prod-0123456789abcdef")
        for capability in ("supports_dir_fd", "supports_follow_symlinks"):
            with self.subTest(capability=capability), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                source = root / "source"
                source.write_bytes(b"synthetic")
                output = root / "output"
                output.mkdir()
                supported = set(getattr(os, capability)) - {os.stat}
                with mock.patch.object(COLLECTION.os, capability, supported):
                    with self.assertRaises(COLLECTION.CollectionError):
                        COLLECTION.publish_local_archive(plan, source, output)
                self.assertEqual([], list(output.iterdir()))

    def test_symlinked_source_or_output_ancestor_cannot_import_or_export(self):
        plan = COLLECTION.collection_plan(
            "iblinkinfo", "20260926-0315-prod-0123456789abcdef"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            outside = root / "outside"
            outside.mkdir()
            (root / "alias").symlink_to(outside, target_is_directory=True)
            source = outside / "source"
            source.write_bytes(b"external-synthetic-sentinel")
            output = root / "output"
            output.mkdir()
            with self.assertRaises(COLLECTION.CollectionError):
                COLLECTION.publish_local_archive(
                    plan, root / "alias" / "source", output
                )
            self.assertEqual([], list(output.iterdir()))
            with self.assertRaises(COLLECTION.CollectionError):
                COLLECTION.publish_local_archive(
                    plan, source, root / "alias"
                )
            self.assertEqual([source], list(outside.iterdir()))
            self.assertEqual(b"external-synthetic-sentinel", source.read_bytes())

    def test_destination_parent_rebind_after_validation_cannot_write_outside(self):
        plan = COLLECTION.collection_plan(
            "iblinkinfo", "20260926-0315-prod-0123456789abcdef"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "source"
            source.write_bytes(b"intended-synthetic-data")
            output = root / "output"
            output.mkdir()
            outside = root / "outside"
            outside.mkdir()
            sentinel = outside / "sentinel"
            sentinel.write_bytes(b"preserve-me")
            part = output / plan.part_name
            original_open = os.open
            swapped = False

            def swap_parent_at_part_creation(path, flags, *args, **kwargs):
                nonlocal swapped
                if (not swapped and flags & os.O_CREAT and
                        (Path(path) == part or
                         (path == plan.part_name and kwargs.get("dir_fd") is not None))):
                    output.rename(root / "original-output")
                    output.symlink_to(outside, target_is_directory=True)
                    swapped = True
                return original_open(path, flags, *args, **kwargs)

            with mock.patch.object(COLLECTION.os, "open",
                                   side_effect=swap_parent_at_part_creation):
                try:
                    COLLECTION.publish_local_archive(plan, source, output)
                except COLLECTION.CollectionError:
                    pass
            self.assertTrue(swapped, "injection must occur after source/destination checks")
            self.assertEqual(b"preserve-me", sentinel.read_bytes())
            self.assertEqual([sentinel], list(outside.iterdir()),
                             "rebound external directory must receive no part or final")

    def test_source_parent_rebind_after_validation_cannot_import_outside(self):
        plan = COLLECTION.collection_plan(
            "iblinkinfo", "20260926-0315-prod-0123456789abcdef"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            parent = root / "source-parent"
            parent.mkdir()
            source = parent / "artifact"
            source.write_bytes(b"intended-synthetic-data")
            outside = root / "outside"
            outside.mkdir()
            (outside / "artifact").write_bytes(b"external-secret-not-for-archive")
            output = root / "output"
            output.mkdir()
            part = output / plan.part_name
            original_open = os.open
            swapped = False

            def swap_source_at_part_creation(path, flags, *args, **kwargs):
                nonlocal swapped
                if (not swapped and flags & os.O_CREAT and
                        (Path(path) == part or
                         (path == plan.part_name and kwargs.get("dir_fd") is not None))):
                    parent.rename(root / "original-source-parent")
                    parent.symlink_to(outside, target_is_directory=True)
                    swapped = True
                return original_open(path, flags, *args, **kwargs)

            with mock.patch.object(COLLECTION.os, "open",
                                   side_effect=swap_source_at_part_creation):
                try:
                    final = COLLECTION.publish_local_archive(plan, source, output)
                except COLLECTION.CollectionError:
                    final = None
            self.assertTrue(swapped, "injection must occur before archive source traversal")
            if final is not None:
                with tarfile.open(final, "r:gz") as archive:
                    self.assertNotIn(b"external-secret-not-for-archive",
                                     archive.extractfile("artifact").read())

    def test_part_name_replacement_cannot_publish_foreign_archive_or_delete_it(self):
        plan = COLLECTION.collection_plan(
            "iblinkinfo", "20260926-0315-prod-0123456789abcdef")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "source"
            source.write_bytes(b"intended-archive-source")
            output = root / "output"
            output.mkdir()
            part = output / plan.part_name
            incoming = output / "incoming"
            foreign_bytes = synthetic_archive(incoming, b"foreign-archive-data")
            real_fsync = os.fsync
            swapped = False

            def replace_part_after_stream_sync(fd):
                nonlocal swapped
                real_fsync(fd)
                if not swapped and part.exists() and stat.S_ISREG(os.fstat(fd).st_mode):
                    os.replace(incoming, part)
                    swapped = True

            with mock.patch.object(COLLECTION.os, "fsync",
                                   side_effect=replace_part_after_stream_sync):
                with self.assertRaises(COLLECTION.CollectionError):
                    COLLECTION.publish_local_archive(plan, source, output)
            self.assertTrue(swapped, "part replacement must occur after original fd sync")
            self.assertEqual(foreign_bytes, part.read_bytes(),
                             "cleanup must not unlink another writer's replacement")
            self.assertFalse((output / plan.archive_name).exists())

    def test_final_name_replacement_cannot_be_reported_as_our_product(self):
        plan = COLLECTION.collection_plan(
            "iblinkinfo", "20260926-0315-prod-0123456789abcdef")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "source"
            source.write_bytes(b"intended-archive-source")
            output = root / "output"
            output.mkdir()
            final = output / plan.archive_name
            incoming = output / "incoming"
            foreign_bytes = synthetic_archive(incoming, b"foreign-final-data")
            real_fsync = os.fsync
            swapped = False

            def replace_final_before_directory_sync(fd):
                nonlocal swapped
                if (not swapped and final.exists()
                        and stat.S_ISDIR(os.fstat(fd).st_mode)):
                    os.replace(incoming, final)
                    swapped = True
                real_fsync(fd)

            with mock.patch.object(COLLECTION.os, "fsync",
                                   side_effect=replace_final_before_directory_sync):
                with self.assertRaises(COLLECTION.CollectionError):
                    COLLECTION.publish_local_archive(plan, source, output)
            self.assertTrue(swapped, "final replacement must occur after original link")
            self.assertEqual(foreign_bytes, final.read_bytes(),
                             "cleanup must preserve another writer's replacement")


if __name__ == "__main__":
    unittest.main()
