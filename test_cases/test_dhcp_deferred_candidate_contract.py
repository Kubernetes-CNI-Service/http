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


def bound(fixture: ScopedDhcpFixture):
    """The module bindings ScopedDhcpFixture.execute applies, for direct calls."""
    return mock.patch.multiple(
        DHCP,
        HTTP_ROOT=str(fixture.root),
        SCRIPT_DIR=str(fixture.dhcp),
        OUTPUT_ETH=str(fixture.outputs["eth"]),
        OUTPUT_IB=str(fixture.outputs["ib"]),
        OUTPUT_NVL=str(fixture.outputs["nvl"]),
        OUTPUT_CONF=str(fixture.outputs["conf"]),
        OUTPUT_MANIFEST=str(fixture.outputs["manifest"]),
        GLOBAL_YAML=str(fixture.global_file),
    )


def identity(path: Path):
    info = path.lstat()
    return info.st_dev, info.st_ino


class DevCandidateGuaranteeTests(unittest.TestCase):
    """DEV ad4bc3c candidate guarantees carried onto --candidate-dir (T+).

    G10, G15 and #11 keep the assertions of the DEV methods named in each
    test, changing only the call form (--candidate-output-dir next to the
    flat outputs becomes the LOAD-owned project candidate).  G14 has no DEV
    test; its expectation is DEV c1's rule that the candidate directory's
    owner equals the effective uid (exit 2, nothing written).
    """

    def test_c1_private_candidate_flag_rejects_foreign_directory_before_writes(self):
        # DEV test_load_release_transaction::ReleaseTransactionTests::
        # test_c1_private_candidate_flag_rejects_foreign_directory_before_writes
        with tempfile.TemporaryDirectory(prefix="dhcp-deferred-foreign-") as name:
            fixture, _project, _output, candidate = private_project(Path(name))
            public = fixture.outputs["conf"]
            for foreign_name in (".load-dhcp-foreign", ".load-dhcp-candidate-foreign01"):
                with self.subTest(foreign=foreign_name):
                    foreign = fixture.root / foreign_name
                    foreign.mkdir(mode=0o700)
                    before = (public.stat().st_ino, public.read_bytes())
                    with self.assertRaises(SystemExit) as caught:
                        fixture.execute([
                            "c1-generate_dhcp.py", "-y",
                            "--candidate-dir", str(foreign),
                        ])
                    self.assertEqual(2, caught.exception.code)
                    self.assertEqual(before, (public.stat().st_ino, public.read_bytes()))
                    self.assertEqual([], list(foreign.iterdir()))
            self.assertEqual([], list(candidate.iterdir()))

    def test_generator_candidate_option_targets_protected_sibling_before_inputs(self):
        # DEV test_req22_runtime_contract::Req22RuntimeInputTests::
        # test_generator_candidate_option_targets_protected_sibling_before_inputs
        with tempfile.TemporaryDirectory(prefix="dhcp-deferred-inputs-") as name:
            fixture, project, output, candidate = private_project(Path(name))
            public = fixture.outputs["conf"]
            accepted = public.read_bytes()
            (project / "02-subnet_config.csv").unlink()
            with self.assertRaises(SystemExit) as caught:
                fixture.execute([
                    "c1-generate_dhcp.py", "-y", "--candidate-dir", str(candidate),
                ])
            self.assertEqual(1, caught.exception.code)
            self.assertEqual(accepted, public.read_bytes())
            self.assertEqual([], list(candidate.iterdir()))
            # DEV's witness that the candidate was checked before the first
            # input was its OUTPUT_* rebinding.  T+ never rebinds the flat
            # outputs, so the witness is the exit status: with the same
            # missing input, an unprotected candidate is refused first (2).
            permissive = output / ".load-dhcp-candidate-permissive"
            permissive.mkdir()
            permissive.chmod(0o755)
            with self.assertRaises(SystemExit) as caught:
                fixture.execute([
                    "c1-generate_dhcp.py", "-y", "--candidate-dir", str(permissive),
                ])
            self.assertEqual(2, caught.exception.code)
            self.assertEqual(accepted, public.read_bytes())
            self.assertEqual([], list(permissive.iterdir()))

    def test_invalid_candidate_directories_exit_2_before_reading_inputs(self):
        with tempfile.TemporaryDirectory(prefix="dhcp-deferred-exit2-") as name:
            fixture, project, output, candidate = private_project(Path(name))
            before = flat_snapshot(fixture)
            outside = fixture.root / "outside"
            outside.mkdir(mode=0o700)
            permissive = output / ".load-dhcp-candidate-permissive"
            permissive.mkdir()
            permissive.chmod(0o755)
            occupied = output / ".load-dhcp-candidate-occupied"
            occupied.mkdir(mode=0o700)
            (occupied / "sentinel").write_bytes(b"do not replace")
            alias = output / ".load-dhcp-candidate-alias0000"
            alias.symlink_to(outside, target_is_directory=True)
            absent = output / ".load-dhcp-candidate-absent00"
            cases = {
                label: ["c1-generate_dhcp.py", "-y", "--candidate-dir", str(path)]
                for label, path in (
                    ("outside", outside), ("permissive", permissive),
                    ("occupied", occupied), ("alias", alias),
                    ("project", project), ("absent", absent),
                )
            }
            cases["relative"] = [
                "c1-generate_dhcp.py", "-y", "--candidate-dir",
                ".load-dhcp-candidate-0123456789abcdef",
            ]
            cases["missing-value"] = ["c1-generate_dhcp.py", "-y", "--candidate-dir"]
            unread = AssertionError("the candidate gate must precede every input read")
            for label, argv in cases.items():
                with self.subTest(case=label), \
                        mock.patch.object(DHCP, "load_project_global", side_effect=unread), \
                        mock.patch.object(DHCP, "load_subnet_csv", side_effect=unread), \
                        mock.patch.object(DHCP, "load_csv", side_effect=unread):
                    with self.assertRaises(SystemExit) as caught:
                        fixture.execute(argv)
                    self.assertEqual(2, caught.exception.code)
                    self.assertEqual(before, flat_snapshot(fixture))
            self.assertEqual(b"do not replace", (occupied / "sentinel").read_bytes())
            self.assertEqual([], list(outside.iterdir()))
            self.assertEqual([], list(permissive.iterdir()))
            self.assertFalse(absent.exists())
            self.assertEqual([], list(candidate.iterdir()))

    def test_candidate_owned_by_another_user_is_refused_before_writes(self):
        with tempfile.TemporaryDirectory(prefix="dhcp-deferred-owner-") as name:
            fixture, _project, _output, candidate = private_project(Path(name))
            before = flat_snapshot(fixture)
            other_uid = candidate.lstat().st_uid + 1
            with mock.patch.object(DHCP.os, "geteuid", return_value=other_uid):
                with self.assertRaises(SystemExit) as caught:
                    fixture.execute([
                        "c1-generate_dhcp.py", "-y", "--switch", "ib",
                        "--candidate-dir", str(candidate),
                    ])
            self.assertEqual(2, caught.exception.code)
            self.assertEqual(before, flat_snapshot(fixture))
            self.assertEqual([], list(candidate.iterdir()))

    def test_held_candidate_rechecks_owner_before_first_write(self):
        with tempfile.TemporaryDirectory(prefix="dhcp-deferred-held-owner-") as name:
            fixture, _project, _output, candidate = private_project(Path(name))
            other_uid = candidate.lstat().st_uid + 1
            with bound(fixture), mock.patch.object(
                DHCP.os, "geteuid", return_value=other_uid,
            ):
                with self.assertRaises((OSError, ValueError)):
                    with DHCP._held_private_candidate(str(candidate)):
                        self.fail("a foreign-owned candidate must not be held for writing")
            self.assertEqual([], list(candidate.iterdir()))

    def test_candidate_prior_hosts_copy_rejects_source_rebind_before_open(self):
        # DEV test_load_release_transaction::ReleaseTransactionTests::
        # test_deferred_dhcp_copy_rejects_source_rebind_before_open
        with tempfile.TemporaryDirectory(prefix="dhcp-deferred-copy-rebind-") as name:
            fixture, _project, output, candidate = private_project(Path(name))
            source = output / "dhcpd_eth.hosts"
            previous = source.lstat()
            alternate = source.with_name("dhcpd_eth.hosts.alternate")
            alternate.write_bytes(b"X" * previous.st_size)
            os.utime(alternate, ns=(previous.st_atime_ns, previous.st_mtime_ns))
            destination = candidate / source.name
            output_identity = identity(output)
            open_file = os.open
            rebound = False

            def swap_before_open(path, *args, **kwargs):
                nonlocal rebound
                directory = kwargs.get("dir_fd")
                if (not rebound and os.fspath(path) == source.name
                        and directory is not None):
                    held = os.fstat(directory)
                    if (held.st_dev, held.st_ino) == output_identity:
                        rebound = True
                        os.replace(alternate, source)
                return open_file(path, *args, **kwargs)

            with mock.patch.object(DHCP.os, "open", side_effect=swap_before_open):
                with self.assertRaisesRegex(OSError, "changed before copy"):
                    fixture.execute([
                        "c1-generate_dhcp.py", "-y", "--switch", "ib",
                        "--candidate-dir", str(candidate),
                    ])
            self.assertTrue(rebound)
            self.assertFalse(destination.exists())
            self.assertEqual([], list(candidate.iterdir()))

    def _read_hook(self, source: Path, mutate):
        read = os.read
        source_identity = identity(source)
        state = {"mutated": False}

        def mutate_after_first_read(fd, size):
            data = read(fd, size)
            if not state["mutated"] and data:
                held = os.fstat(fd)
                if (held.st_dev, held.st_ino) == source_identity:
                    state["mutated"] = True
                    mutate()
            return data

        return mutate_after_first_read, state

    def test_candidate_prior_hosts_copy_rejects_growth_during_read(self):
        with tempfile.TemporaryDirectory(prefix="dhcp-deferred-copy-grow-") as name:
            fixture, _project, output, candidate = private_project(Path(name))
            source = output / "dhcpd_eth.hosts"

            def grow():
                with open(source, "ab") as stream:
                    stream.write(b"# appended while the generator was reading\n")

            hook, state = self._read_hook(source, grow)
            with mock.patch.object(DHCP.os, "read", side_effect=hook):
                with self.assertRaisesRegex(OSError, "grew during copy"):
                    fixture.execute([
                        "c1-generate_dhcp.py", "-y", "--switch", "ib",
                        "--candidate-dir", str(candidate),
                    ])
            self.assertTrue(state["mutated"])
            self.assertEqual([], list(candidate.iterdir()))

    def test_candidate_prior_hosts_copy_rejects_same_size_rewrite_during_read(self):
        with tempfile.TemporaryDirectory(prefix="dhcp-deferred-copy-rewrite-") as name:
            fixture, _project, output, candidate = private_project(Path(name))
            source = output / "dhcpd_eth.hosts"
            previous = source.lstat()

            def rewrite_in_place():
                with open(source, "r+b") as stream:
                    stream.write(b"X" * previous.st_size)
                os.utime(source, ns=(previous.st_atime_ns, previous.st_mtime_ns))

            hook, state = self._read_hook(source, rewrite_in_place)
            with mock.patch.object(DHCP.os, "read", side_effect=hook):
                with self.assertRaisesRegex(OSError, "changed during copy"):
                    fixture.execute([
                        "c1-generate_dhcp.py", "-y", "--switch", "ib",
                        "--candidate-dir", str(candidate),
                    ])
            self.assertTrue(state["mutated"])
            self.assertEqual([], list(candidate.iterdir()))

    def test_candidate_prior_hosts_copy_rejects_unsafe_source_before_open(self):
        limit = 128 * 1024 * 1024
        # A symlinked flat file is refused earlier by the project binding of
        # the five flat outputs (exit 2), so only reader-level shapes remain.
        for kind in ("oversized", "hard-linked"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(
                prefix="dhcp-deferred-copy-unsafe-",
            ) as name:
                fixture, _project, output, candidate = private_project(Path(name))
                source = output / "dhcpd_eth.hosts"
                if kind == "oversized":
                    os.truncate(source, limit + 1)
                else:
                    os.link(source, fixture.root / "second-name.hosts")
                with self.assertRaisesRegex(OSError, "unsafe prior DHCP output"):
                    fixture.execute([
                        "c1-generate_dhcp.py", "-y", "--switch", "ib",
                        "--candidate-dir", str(candidate),
                    ])
                self.assertEqual([], list(candidate.iterdir()))
