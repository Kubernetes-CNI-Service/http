#!/usr/bin/env python3
"""Direct contract for LOAD-owned, unpublished DHCP generation candidates."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from test_cases.test_dhcp_switch_scope_preservation import (
    DHCP,
    FAMILY_HOST,
    ScopedDhcpFixture,
)


FILES = (
    "dhcpd.conf",
    "dhcpd_eth.hosts",
    "dhcpd_ib.hosts",
    "dhcpd_nvl.hosts",
    "dhcp-release-manifest.json",
)


def private_project(root: Path):
    """Model setup's canonical project files and exact public symlinks."""
    fixture = ScopedDhcpFixture(root)
    project = root / "DAY0-Prepare" / "site"
    project.mkdir(parents=True)
    output = project / "99-output-dhcp"
    output.mkdir()
    for source, name in (
        (fixture.global_file, "01-global.yaml"),
        (fixture.devices_file, "02-devices_config.csv"),
        (fixture.subnet_file, "02-subnet_config.csv"),
    ):
        destination = project / name
        source.rename(destination)
        source.symlink_to(destination)
    for source in fixture.outputs.values():
        destination = output / source.name
        source.rename(destination)
        source.symlink_to(destination)
    candidate = output / ".load-dhcp-candidate-0123456789abcdef"
    candidate.mkdir(mode=0o700)
    return fixture, project, output, candidate


def flat_snapshot(fixture: ScopedDhcpFixture):
    return {
        name: (
            path.read_bytes(), path.lstat().st_ino, os.readlink(path),
        )
        for name, path in fixture.outputs.items()
    }


class DeferredDhcpCandidateDirectTests(unittest.TestCase):
    def test_all_family_candidate_rebuilds_three_hosts_without_publishing(self):
        with tempfile.TemporaryDirectory(prefix="dhcp-deferred-all-") as name:
            fixture, _project, _output, candidate = private_project(Path(name))
            before = flat_snapshot(fixture)
            fixture.execute([
                "c1-generate_dhcp.py", "-y", "--preserve-input-csv",
                "--candidate-dir", str(candidate),
            ])
            self.assertEqual(before, flat_snapshot(fixture))
            self.assertEqual(set(FILES), {item.name for item in candidate.iterdir()})
            for family, hostname in FAMILY_HOST.items():
                self.assertIn(
                    hostname.encode("ascii"),
                    (candidate / f"dhcpd_{family}.hosts").read_bytes(),
                )
            receipt = json.loads(
                (candidate / "dhcp-release-manifest.json").read_text()
            )
            self.assertEqual("all", receipt["switch_scope"])
            self.assertEqual(3, receipt["counts"]["host_declarations"])

    def test_scoped_candidate_is_complete_and_does_not_publish_flat_outputs(self):
        with tempfile.TemporaryDirectory(prefix="dhcp-deferred-contract-") as name:
            fixture, _project, _output, candidate = private_project(Path(name))
            before = flat_snapshot(fixture)
            old_eth = fixture.outputs["eth"].read_bytes()
            old_nvl = fixture.outputs["nvl"].read_bytes()

            fixture.execute([
                "c1-generate_dhcp.py", "-y", "--preserve-input-csv",
                "--deployment-scope", "prod", "--switch", "ib",
                "--candidate-dir", str(candidate),
            ])

            self.assertEqual(before, flat_snapshot(fixture))
            self.assertEqual(set(FILES), {item.name for item in candidate.iterdir()})
            self.assertEqual(0o700, stat.S_IMODE(candidate.stat().st_mode))
            for item in candidate.iterdir():
                info = item.lstat()
                self.assertTrue(stat.S_ISREG(info.st_mode), item)
                self.assertEqual(1, info.st_nlink, item)
            self.assertEqual(old_eth, (candidate / "dhcpd_eth.hosts").read_bytes())
            self.assertEqual(old_nvl, (candidate / "dhcpd_nvl.hosts").read_bytes())
            self.assertIn(
                FAMILY_HOST["ib"].encode("ascii"),
                (candidate / "dhcpd_ib.hosts").read_bytes(),
            )
            receipt = json.loads(
                (candidate / "dhcp-release-manifest.json").read_text()
            )
            self.assertEqual("ib", receipt["switch_scope"])
            self.assertEqual(
                {"eth": 1, "ib": 1, "nvl": 1},
                receipt["counts"]["host_declarations_by_family"],
            )
            for filename in FILES[:-1]:
                self.assertEqual(
                    hashlib.sha256((candidate / filename).read_bytes()).hexdigest(),
                    receipt["outputs"][filename]["sha256"],
                )

    def test_candidate_requires_project_local_private_empty_directory(self):
        with tempfile.TemporaryDirectory(prefix="dhcp-deferred-safety-") as name:
            fixture, project, output, candidate = private_project(Path(name))
            before = flat_snapshot(fixture)
            outside = fixture.root / "outside"
            outside.mkdir(mode=0o700)
            permissive = output / ".load-dhcp-candidate-permissive"
            permissive.mkdir(mode=0o755)
            occupied = output / ".load-dhcp-candidate-occupied"
            occupied.mkdir(mode=0o700)
            (occupied / "sentinel").write_bytes(b"do not replace")
            alias = output / ".load-dhcp-candidate-alias"
            alias.symlink_to(outside, target_is_directory=True)
            for bad in (outside, permissive, occupied, alias, project):
                with self.subTest(path=bad):
                    with self.assertRaises((OSError, ValueError, SystemExit)):
                        fixture.execute([
                            "c1-generate_dhcp.py", "-y", "--switch", "ib",
                            "--candidate-dir", str(bad),
                        ])
                    self.assertEqual(before, flat_snapshot(fixture))
            self.assertEqual(b"do not replace", (occupied / "sentinel").read_bytes())
            self.assertEqual([], list(outside.iterdir()))
            self.assertEqual([], list(candidate.iterdir()))

    def test_candidate_writer_failure_does_not_touch_old_authority(self):
        with tempfile.TemporaryDirectory(prefix="dhcp-deferred-failure-") as name:
            fixture, _project, _output, candidate = private_project(Path(name))
            before = flat_snapshot(fixture)
            original_write = DHCP.write_hosts

            def fail_after_eth(path, records, **kwargs):
                if Path(path).name == "dhcpd_ib.hosts":
                    raise OSError("injected candidate host failure")
                return original_write(path, records, **kwargs)

            with mock.patch.object(DHCP, "write_hosts", side_effect=fail_after_eth):
                with self.assertRaisesRegex(OSError, "injected candidate host failure"):
                    fixture.execute([
                        "c1-generate_dhcp.py", "-y", "--switch", "ib",
                        "--candidate-dir", str(candidate),
                    ])
            self.assertEqual(before, flat_snapshot(fixture))
            self.assertEqual([], list(candidate.iterdir()))

    def test_directory_fsync_failure_cleans_candidate_and_preserves_old(self):
        with tempfile.TemporaryDirectory(prefix="dhcp-deferred-fsync-") as name:
            fixture, _project, _output, candidate = private_project(Path(name))
            before = flat_snapshot(fixture)
            candidate_inode = candidate.stat().st_ino
            real_fsync = os.fsync
            injected = False

            def fail_once_on_candidate(fd):
                nonlocal injected
                if not injected and os.fstat(fd).st_ino == candidate_inode:
                    injected = True
                    raise OSError("injected candidate directory fsync failure")
                return real_fsync(fd)

            with mock.patch.object(os, "fsync", side_effect=fail_once_on_candidate):
                with self.assertRaisesRegex(OSError, "injected candidate directory fsync failure"):
                    fixture.execute([
                        "c1-generate_dhcp.py", "-y", "--switch", "ib",
                        "--candidate-dir", str(candidate),
                    ])
            self.assertTrue(injected)
            self.assertEqual(before, flat_snapshot(fixture))
            self.assertEqual([], list(candidate.iterdir()))

    def test_candidate_rejects_rebound_directory_without_foreign_writes(self):
        with tempfile.TemporaryDirectory(prefix="dhcp-deferred-rebind-") as name:
            fixture, _project, output, candidate = private_project(Path(name))
            before = flat_snapshot(fixture)
            foreign = fixture.root / "foreign"
            foreign.mkdir(mode=0o700)
            detached = output / ".load-dhcp-candidate-detached"
            original_fstat = os.fstat
            injected = False

            def fstat_and_rebind(fd):
                nonlocal injected
                result = original_fstat(fd)
                if not injected and stat.S_ISDIR(result.st_mode) and result.st_ino == candidate.stat().st_ino:
                    injected = True
                    candidate.rename(detached)
                    candidate.symlink_to(foreign, target_is_directory=True)
                return result

            with mock.patch.object(os, "fstat", side_effect=fstat_and_rebind):
                with self.assertRaises((OSError, ValueError)):
                    fixture.execute([
                        "c1-generate_dhcp.py", "-y", "--switch", "ib",
                        "--candidate-dir", str(candidate),
                    ])
            self.assertTrue(injected)
            self.assertEqual(before, flat_snapshot(fixture))
            self.assertEqual([], list(foreign.iterdir()))
