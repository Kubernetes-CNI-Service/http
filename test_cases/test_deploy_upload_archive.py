#!/usr/bin/env python3
"""Contracts for the relay-safe server-side upload archive installer."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases.public_project_fixture import materialized_public_project


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import _package_common as package


INSTALLER_PATH = ROOT / "tools/deploy-upload-archive.py"
GUARD_PATH = ROOT / "tools/deployment_prewrite_guard.py"

UPLOAD_SPEC = importlib.util.spec_from_file_location(
    "relay_bundle_upload_contract", ROOT / "tools/tar-for-upload.py",
)
assert UPLOAD_SPEC is not None and UPLOAD_SPEC.loader is not None
UPLOAD = importlib.util.module_from_spec(UPLOAD_SPEC)
UPLOAD_SPEC.loader.exec_module(UPLOAD)


def load_installer():
    if not INSTALLER_PATH.is_file():
        raise AssertionError("server-side relay archive installer is missing")
    spec = importlib.util.spec_from_file_location(
        "deploy_upload_archive_contract", INSTALLER_PATH,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(spec.name)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        if previous is None:
            sys.modules.pop(spec.name, None)
        else:
            sys.modules[spec.name] = previous
    return module


def add_bytes(archive: tarfile.TarFile, name: str, payload: bytes, mode: int = 0o644):
    info = tarfile.TarInfo(name)
    info.size = len(payload)
    info.mode = mode
    archive.addfile(info, io.BytesIO(payload))


def make_archive(
    path: Path, installer_bytes: bytes, *, guard_bytes: bytes | None = None,
    project: str = "customer", mutate_manifest=None, extra_members=(),
) -> bytes:
    guard = GUARD_PATH.read_bytes() if guard_bytes is None else guard_bytes
    records = [
        {
            "path": "tools/deploy-upload-archive.py", "type": "file",
            "target": None, "sha256": hashlib.sha256(installer_bytes).hexdigest(),
        },
        {
            "path": "tools/deployment_prewrite_guard.py", "type": "file",
            "target": None, "sha256": hashlib.sha256(guard).hexdigest(),
        },
    ]
    if mutate_manifest is not None:
        mutate_manifest(records)
    manifest = json.dumps(
        {"schema_version": 1, "files": records},
        ensure_ascii=True, sort_keys=True,
    ).encode("ascii") + b"\n"
    members = {
        "./tools/deploy-upload-archive.py": installer_bytes,
        "./tools/deployment_prewrite_guard.py": guard,
        "./infra/docker/deployment-source-manifest.json": manifest,
        f"./DAY0-Prepare/{project}/01-global.yaml": b"schema_version: 2\n",
        f"./DAY0-Prepare/{project}/02-devices_config.csv": b"hostname,type\nleaf01,eth\n",
        f"./DAY0-Prepare/{project}/02-dhcp-subnet_config.csv": b"subnet,netmask\n192.0.2.0,255.255.255.0\n",
    }
    with tarfile.open(path, "w:gz") as archive:
        for name, payload in members.items():
            add_bytes(archive, name, payload, 0o500 if name.endswith("deploy-upload-archive.py") else 0o644)
        for item in extra_members:
            if isinstance(item, tarfile.TarInfo):
                archive.addfile(item)
            else:
                name, payload = item
                add_bytes(archive, name, payload)
    return manifest


class RelayArchiveInstallerTests(unittest.TestCase):
    def setUp(self):
        self.installer = load_installer()

    def _load_verified_guard(self, archive: Path, base: Path, module_name: str):
        verified = self.installer.verify_inputs(
            archive, INSTALLER_PATH, required_uid=os.getuid(),
        )
        embedded_path = base / f"{module_name}.py"
        embedded_path.write_text(verified.guard_source, encoding="utf-8")
        spec = importlib.util.spec_from_file_location(module_name, embedded_path)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        embedded_guard = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(embedded_guard)
        return embedded_guard

    def test_cli_has_one_required_archive_and_safe_defaults(self):
        with self.assertRaises(SystemExit):
            self.installer.parser().parse_args([])
        args = self.installer.parser().parse_args(["/tmp/project-upload.tar.gz"])
        self.assertEqual(Path("/tmp/project-upload.tar.gz"), args.archive)
        self.assertEqual(Path("/var/www/html"), args.root)
        self.assertEqual("native", args.runtime)
        self.assertFalse(args.verify_only)
        docker = self.installer.parser().parse_args([
            "/tmp/project-upload.tar.gz", "--runtime", "docker", "--verify-only",
        ])
        self.assertEqual("docker", docker.runtime)
        self.assertTrue(docker.verify_only)
        help_text = self.installer.parser().format_help()
        self.assertNotIn("--archive-sha256", help_text)
        self.assertNotIn("--force", help_text)
        self.assertNotIn("--skip-verify", help_text)

    def test_archive_and_installer_are_hash_bound_before_guard(self):
        installer_bytes = INSTALLER_PATH.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "upload.tar.gz"
            manifest = make_archive(archive, installer_bytes)
            verified = self.installer.verify_inputs(
                archive, INSTALLER_PATH, required_uid=os.getuid(),
            )
            self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), verified.archive_sha256)
            self.assertEqual(hashlib.sha256(manifest).hexdigest(), verified.source_manifest_sha256)
            self.assertEqual("customer", verified.project)
            self.assertEqual(GUARD_PATH.read_text(encoding="utf-8"), verified.guard_source)

            make_archive(archive, b"different installer\n")
            with self.assertRaisesRegex(self.installer.InstallError, "installer.*match"):
                self.installer.verify_inputs(
                    archive, INSTALLER_PATH, required_uid=os.getuid(),
                )

    def test_user_relay_bundle_contains_only_upload_release_authorities(self):
        installer_bytes = INSTALLER_PATH.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            archive = base / "source-upload.tar.gz"
            make_archive(archive, installer_bytes, project="customer")
            archive.chmod(0o600)
            destination = base / "customer-release"
            published = UPLOAD.publish_relay_bundle(
                destination,
                archive,
                project_name="customer",
                runtime="docker",
                expected_archive_sha256=hashlib.sha256(
                    archive.read_bytes(),
                ).hexdigest(),
                installer_path=INSTALLER_PATH,
            )

            self.assertEqual(destination.resolve(), published)
            self.assertEqual(
                {
                    "customer-upload.tar.gz",
                    "deploy-upload-archive.py",
                    "upload-metadata.json",
                    "SHA256SUMS",
                },
                {item.name for item in destination.iterdir()},
            )
            self.assertEqual(0o700, stat.S_IMODE(destination.stat().st_mode))
            expected_modes = {
                "customer-upload.tar.gz": 0o600,
                "deploy-upload-archive.py": 0o500,
                "upload-metadata.json": 0o600,
                "SHA256SUMS": 0o600,
            }
            for name, expected_mode in expected_modes.items():
                item = destination / name
                with self.subTest(name=name):
                    self.assertTrue(item.is_file())
                    self.assertFalse(item.is_symlink())
                    self.assertEqual(1, item.stat().st_nlink)
                    self.assertEqual(expected_mode, stat.S_IMODE(item.stat().st_mode))

            metadata = json.loads(
                (destination / "upload-metadata.json").read_text(encoding="ascii"),
            )
            self.assertEqual("http-ztp-upload-release", metadata["artifact_type"])
            self.assertEqual("customer", metadata["project"])
            self.assertEqual("docker", metadata["runtime"])
            self.assertNotIn("image_id", metadata)
            self.assertNotIn("image", metadata)
            self.assertNotIn("shared_artifacts", metadata)
            copied_archive = destination / "customer-upload.tar.gz"
            verified = self.installer.verify_inputs(
                copied_archive,
                destination / "deploy-upload-archive.py",
                required_uid=os.getuid(),
            )
            self.assertEqual("customer", verified.project)
            self.assertEqual(
                verified.source_manifest_sha256,
                metadata["source_manifest_sha256"],
            )
            checksums = {}
            for line in (destination / "SHA256SUMS").read_text(
                encoding="ascii",
            ).splitlines():
                digest, name = line.split("  ", 1)
                checksums[name] = digest
            self.assertEqual(
                {
                    "customer-upload.tar.gz",
                    "deploy-upload-archive.py",
                    "upload-metadata.json",
                },
                set(checksums),
            )
            for name, expected in checksums.items():
                self.assertEqual(
                    expected,
                    hashlib.sha256((destination / name).read_bytes()).hexdigest(),
                )

    def test_relay_bundle_rejects_a_symlink_in_the_output_parent(self):
        installer_bytes = INSTALLER_PATH.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            archive = base / "source-upload.tar.gz"
            make_archive(archive, installer_bytes, project="customer")
            archive.chmod(0o600)
            real_parent = base / "real-parent"
            real_parent.mkdir(mode=0o700)
            linked_parent = base / "linked-parent"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            destination = linked_parent / "customer-release"

            with self.assertRaisesRegex(RuntimeError, "symlink"):
                UPLOAD.publish_relay_bundle(
                    destination,
                    archive,
                    project_name="customer",
                    runtime="docker",
                    expected_archive_sha256=hashlib.sha256(
                        archive.read_bytes(),
                    ).hexdigest(),
                    installer_path=INSTALLER_PATH,
                )
            self.assertFalse((real_parent / destination.name).exists())

    def test_relay_bundle_parent_swap_cannot_redirect_publish_or_leak_stage(self):
        installer_bytes = INSTALLER_PATH.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            archive = base / "source-upload.tar.gz"
            make_archive(archive, installer_bytes, project="customer")
            archive.chmod(0o600)
            parent = base / "owner-parent"
            parent.mkdir(mode=0o700)
            displaced = base / "displaced-parent"
            outside = base / "outside"
            outside.mkdir(mode=0o700)
            destination = parent / "customer-release"
            real_fsync = os.fsync
            swapped = False

            def swap_parent_after_staging_sync(descriptor):
                nonlocal swapped
                real_fsync(descriptor)
                if swapped or not stat.S_ISDIR(os.fstat(descriptor).st_mode):
                    return
                swapped = True
                os.rename(parent, displaced)
                parent.symlink_to(outside, target_is_directory=True)
                stages = [
                    item for item in displaced.iterdir()
                    if item.name.startswith(f".{destination.name}.tmp.")
                ]
                self.assertEqual(1, len(stages))
                attacker_stage = outside / stages[0].name
                attacker_stage.mkdir(mode=0o700)
                (attacker_stage / "attacker-marker").write_text(
                    "must not publish\n", encoding="ascii",
                )

            try:
                with mock.patch.object(
                    UPLOAD.os, "fsync", side_effect=swap_parent_after_staging_sync,
                ), self.assertRaisesRegex(RuntimeError, "parent.*changed"):
                    UPLOAD.publish_relay_bundle(
                        destination,
                        archive,
                        project_name="customer",
                        runtime="docker",
                        expected_archive_sha256=hashlib.sha256(
                            archive.read_bytes(),
                        ).hexdigest(),
                        installer_path=INSTALLER_PATH,
                    )
                self.assertFalse((outside / destination.name).exists())
                self.assertFalse(any(
                    item.name.startswith(f".{destination.name}.tmp.")
                    for item in displaced.iterdir()
                ))
            finally:
                if parent.is_symlink():
                    parent.unlink()
                if displaced.exists():
                    os.rename(displaced, parent)

    def test_relay_bundle_destination_directory_race_is_not_clobbered(self):
        installer_bytes = INSTALLER_PATH.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            archive = base / "source-upload.tar.gz"
            make_archive(archive, installer_bytes, project="customer")
            archive.chmod(0o600)
            parent = base / "owner-parent"
            parent.mkdir(mode=0o700)
            destination = parent / "customer-release"
            real_lexists = os.path.lexists
            real_stat = os.stat
            destination_checks = 0
            injected = False
            raced_identity = None

            def inject_after_legacy_check(path):
                nonlocal destination_checks, injected, raced_identity
                exists = real_lexists(path)
                if Path(path) == destination:
                    destination_checks += 1
                    if destination_checks == 2 and not exists and not injected:
                        destination.mkdir(mode=0o700)
                        raced_identity = destination.lstat()
                        injected = True
                        return False
                return exists

            def inject_after_descriptor_check(path, *args, **kwargs):
                nonlocal injected, raced_identity
                try:
                    return real_stat(path, *args, **kwargs)
                except FileNotFoundError:
                    descriptor = kwargs.get("dir_fd")
                    if (
                        not injected
                        and descriptor is not None
                        and os.fspath(path) == destination.name
                    ):
                        os.mkdir(destination.name, mode=0o700, dir_fd=descriptor)
                        raced_identity = real_stat(
                            destination.name,
                            dir_fd=descriptor,
                            follow_symlinks=False,
                        )
                        injected = True
                    raise

            with mock.patch.object(
                UPLOAD.os.path, "lexists", side_effect=inject_after_legacy_check,
            ), mock.patch.object(
                UPLOAD.os, "stat", side_effect=inject_after_descriptor_check,
            ), self.assertRaises(FileExistsError):
                UPLOAD.publish_relay_bundle(
                    destination,
                    archive,
                    project_name="customer",
                    runtime="docker",
                    expected_archive_sha256=hashlib.sha256(
                        archive.read_bytes(),
                    ).hexdigest(),
                    installer_path=INSTALLER_PATH,
                )
            self.assertTrue(injected, "destination race was not exercised")
            current = destination.lstat()
            self.assertTrue(stat.S_ISDIR(current.st_mode))
            self.assertEqual(
                (raced_identity.st_dev, raced_identity.st_ino),
                (current.st_dev, current.st_ino),
            )

    def test_archive_verification_never_requests_a_global_size_allocation(self):
        """Small members must not trigger one read sized from the 8 GiB ceiling."""
        installer_bytes = INSTALLER_PATH.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "bounded-reads.tar.gz"
            make_archive(archive_path, installer_bytes)
            real_extractfile = self.installer.tarfile.TarFile.extractfile
            requests = []

            class BoundedReader:
                def __init__(self, stream, member):
                    self.stream = stream
                    self.member = member

                def read(self, size=-1):
                    requests.append((self.member.name, size, self.member.size))
                    if size < 0 or size > self.member.size + 1:
                        raise AssertionError(
                            "archive verifier requested memory from a global bound: "
                            f"{self.member.name} read={size} member={self.member.size}"
                        )
                    return self.stream.read(size)

            def bounded_extractfile(open_archive, member):
                stream = real_extractfile(open_archive, member)
                if stream is None:
                    return None
                return BoundedReader(stream, member)

            with mock.patch.object(
                self.installer.tarfile.TarFile,
                "extractfile",
                new=bounded_extractfile,
            ):
                verified = self.installer.verify_inputs(
                    archive_path, INSTALLER_PATH, required_uid=os.getuid(),
                )
            self.assertEqual("customer", verified.project)
            self.assertTrue(requests)

    def test_archive_member_memory_failure_is_reported_as_install_error(self):
        member = tarfile.TarInfo("./small")
        member.size = 1
        record = self.installer.MemberRecord(member, ("small",), "file")

        class FailingReader:
            def read(self, _size=-1):
                raise MemoryError("simulated constrained verifier")

        archive = SimpleNamespace(extractfile=lambda _member: FailingReader())
        with self.assertRaisesRegex(
            self.installer.InstallError, "cannot read.*memory",
        ):
            self.installer._extract_bytes(
                archive, record, "small authority", maximum_size=16,
            )

    def test_manifest_missing_duplicate_and_hash_mismatch_fail_closed(self):
        installer_bytes = INSTALLER_PATH.read_bytes()
        mutations = {
            "missing": lambda records: records.pop(0),
            "duplicate": lambda records: records.append(dict(records[0])),
            "hash": lambda records: records[1].update(sha256="0" * 64),
        }
        with tempfile.TemporaryDirectory() as directory:
            for label, mutation in mutations.items():
                with self.subTest(label=label):
                    archive = Path(directory) / f"{label}.tar.gz"
                    make_archive(archive, installer_bytes, mutate_manifest=mutation)
                    with self.assertRaises(self.installer.InstallError):
                        self.installer.verify_inputs(
                            archive, INSTALLER_PATH, required_uid=os.getuid(),
                        )

    def test_archive_identity_permissions_and_project_shape_fail_closed(self):
        installer_bytes = INSTALLER_PATH.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            archive = base / "upload.tar.gz"
            make_archive(archive, installer_bytes)
            alias = base / "alias.tar.gz"
            alias.symlink_to(archive.name)
            with self.assertRaises(self.installer.InstallError):
                self.installer.verify_inputs(
                    alias, INSTALLER_PATH, required_uid=os.getuid(),
                )
            hard = base / "hard.tar.gz"
            os.link(archive, hard)
            with self.assertRaises(self.installer.InstallError):
                self.installer.verify_inputs(
                    archive, INSTALLER_PATH, required_uid=os.getuid(),
                )
            hard.unlink()
            archive.chmod(0o620)
            with self.assertRaises(self.installer.InstallError):
                self.installer.verify_inputs(
                    archive, INSTALLER_PATH, required_uid=os.getuid(),
                )
            archive.chmod(0o600)
            with self.assertRaises(self.installer.InstallError):
                self.installer.verify_inputs(
                    archive, INSTALLER_PATH, required_uid=os.getuid() + 1,
                )

            multiple = base / "multiple.tar.gz"
            make_archive(
                multiple, installer_bytes,
                extra_members=(
                    ("./DAY0-Prepare/other/01-global.yaml", b"global\n"),
                    ("./DAY0-Prepare/other/02-devices_config.csv", b"devices\n"),
                    ("./DAY0-Prepare/other/02-dhcp-subnet_config.csv", b"subnet\n"),
                ),
            )
            with self.assertRaisesRegex(self.installer.InstallError, "exactly one"):
                self.installer.verify_inputs(
                    multiple, INSTALLER_PATH, required_uid=os.getuid(),
                )

            missing = base / "missing.tar.gz"
            make_archive(missing, installer_bytes, project="template")
            with self.assertRaisesRegex(self.installer.InstallError, "exactly one"):
                self.installer.verify_inputs(
                    missing, INSTALLER_PATH, required_uid=os.getuid(),
                )

    def test_archive_change_during_stable_read_is_rejected(self):
        installer_bytes = INSTALLER_PATH.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory).resolve() / "upload.tar.gz"
            make_archive(archive, installer_bytes)
            real_hash = self.installer._hash_descriptor

            def mutate_after_hash(descriptor, size, label):
                digest = real_hash(descriptor, size, label)
                with archive.open("ab") as stream:
                    stream.write(b"changed")
                return digest

            with mock.patch.object(
                self.installer, "_hash_descriptor", side_effect=mutate_after_hash,
            ), self.assertRaisesRegex(self.installer.InstallError, "changed"):
                self.installer.verify_inputs(
                    archive, INSTALLER_PATH, required_uid=os.getuid(),
                )

    def test_unsafe_member_types_paths_and_symlinks_are_rejected(self):
        installer_bytes = INSTALLER_PATH.read_bytes()
        bad_members = []
        absolute = tarfile.TarInfo("/absolute")
        absolute.size = 0
        bad_members.append(("absolute", absolute))
        traversal = tarfile.TarInfo("./safe/../escape")
        traversal.size = 0
        bad_members.append(("traversal", traversal))
        hardlink = tarfile.TarInfo("./hard")
        hardlink.type = tarfile.LNKTYPE
        hardlink.linkname = "./tools/deploy-upload-archive.py"
        bad_members.append(("hardlink", hardlink))
        fifo = tarfile.TarInfo("./fifo")
        fifo.type = tarfile.FIFOTYPE
        bad_members.append(("fifo", fifo))
        escaping = tarfile.TarInfo("./links/out")
        escaping.type = tarfile.SYMTYPE
        escaping.linkname = "../../outside"
        bad_members.append(("escaping-symlink", escaping))
        missing = tarfile.TarInfo("./links/missing")
        missing.type = tarfile.SYMTYPE
        missing.linkname = "../absent"
        bad_members.append(("missing-symlink", missing))
        with tempfile.TemporaryDirectory() as directory:
            for label, member in bad_members:
                with self.subTest(label=label):
                    archive = Path(directory) / f"{label}.tar.gz"
                    make_archive(archive, installer_bytes, extra_members=(member,))
                    with self.assertRaises(self.installer.InstallError):
                        self.installer.verify_inputs(
                            archive, INSTALLER_PATH, required_uid=os.getuid(),
                        )

    def test_in_archive_relative_symlink_may_resolve_to_a_verified_directory(self):
        installer_bytes = INSTALLER_PATH.read_bytes()
        tool_directory = tarfile.TarInfo("./tools/lldp-analyze-tool/")
        tool_directory.type = tarfile.DIRTYPE
        tool_directory.mode = 0o755
        directory_link = tarfile.TarInfo(
            "./ztp/config/cumulus/template/P2P/lldp-analyze-tool"
        )
        directory_link.type = tarfile.SYMTYPE
        directory_link.mode = 0o777
        directory_link.linkname = "../../../../../tools/lldp-analyze-tool"
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "directory-link.tar.gz"
            make_archive(
                archive,
                installer_bytes,
                extra_members=(
                    tool_directory,
                    ("./tools/lldp-analyze-tool/analyze_lldp.py", b"# runtime\n"),
                    directory_link,
                ),
            )
            verified = self.installer.verify_inputs(
                archive, INSTALLER_PATH, required_uid=os.getuid(),
            )
            records = {record.parts: record for record in verified.members}
            resolved = self.installer._resolve_archive_target(
                tuple(directory_link.name.removeprefix("./").split("/")),
                records,
                set(),
            )
            self.assertEqual("dir", resolved.kind)
            self.assertEqual(("tools", "lldp-analyze-tool"), resolved.parts)

    def test_source_manifest_may_bind_an_intentional_empty_regular_placeholder(self):
        installer_bytes = INSTALLER_PATH.read_bytes()

        def bind_placeholder(records):
            records.append({
                "path": "DAY0-Prepare/template/switch-image.bin",
                "type": "file",
                "target": None,
                "sha256": hashlib.sha256(b"").hexdigest(),
            })

        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "empty-placeholder.tar.gz"
            make_archive(
                archive,
                installer_bytes,
                mutate_manifest=bind_placeholder,
                extra_members=((
                    "./DAY0-Prepare/template/switch-image.bin", b"",
                ),),
            )
            verified = self.installer.verify_inputs(
                archive, INSTALLER_PATH, required_uid=os.getuid(),
            )
            self.assertEqual("customer", verified.project)

    def test_guard_argv_uses_automatic_digests_and_no_shell(self):
        verified = SimpleNamespace(
            archive_sha256="a" * 64, source_manifest_sha256="b" * 64,
            guard_source="verified guard", project="customer",
        )
        command = self.installer.guard_argv(
            verified, 37, Path("/var/www/html"),
            "docker", python_executable="/usr/bin/python3",
        )
        self.assertEqual(["/usr/bin/python3", "-c", "verified guard"], command[:3])
        self.assertEqual("a" * 64, command[command.index("--archive-sha256") + 1])
        self.assertEqual("b" * 64, command[command.index("--source-manifest-sha256") + 1])
        self.assertEqual("docker", command[command.index("--runtime") + 1])
        self.assertEqual("37", command[command.index("--archive-fd") + 1])
        self.assertNotIn("--archive", command)
        self.assertNotIn("/private/staged.tar.gz", command)
        self.assertNotIn("sh", command[:3])

    def test_run_guard_inherits_the_exact_archive_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "snapshot.tar.gz"
            archive.write_bytes(b"descriptor-bound-snapshot")
            descriptor = os.open(archive, os.O_RDWR)
            try:
                completed = self.installer.run_guard(
                    [
                        sys.executable, "-c",
                        (
                            "import os,sys; fd=int(sys.argv[1]); "
                            "os.lseek(fd,0,0); sys.stdout.buffer.write(os.read(fd,4096))"
                        ),
                        str(descriptor),
                    ],
                    archive_fd=descriptor,
                )
            finally:
                os.close(descriptor)
        self.assertEqual(0, completed.returncode)
        self.assertEqual(b"descriptor-bound-snapshot", completed.stdout)

    def test_run_guard_derives_and_validates_the_descriptor_declared_in_argv(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "snapshot.tar.gz"
            archive.write_bytes(b"argv-bound-snapshot")
            descriptor = os.open(archive, os.O_RDWR)
            try:
                command = [
                    sys.executable, "-c",
                    (
                        "import os,sys; "
                        "fd=int(sys.argv[sys.argv.index('--archive-fd')+1]); "
                        "os.lseek(fd,0,0); sys.stdout.buffer.write(os.read(fd,4096))"
                    ),
                    "--archive-fd", str(descriptor),
                ]
                completed = self.installer.run_guard(command)
                self.assertEqual(0, completed.returncode)
                self.assertEqual(b"argv-bound-snapshot", completed.stdout)

                invalid_cases = (
                    (command[:-1], None),
                    (command[:-1] + ["not-an-fd"], None),
                    (command + ["--archive-fd", str(descriptor)], None),
                    (command[:-1] + [str(descriptor + 1)], descriptor),
                )
                for invalid_command, explicit_fd in invalid_cases:
                    with self.subTest(
                        command=invalid_command, explicit_fd=explicit_fd,
                    ), self.assertRaisesRegex(
                        self.installer.InstallError,
                        "archive descriptor|archive-fd|does not match",
                    ):
                        self.installer.run_guard(
                            invalid_command, archive_fd=explicit_fd,
                        )
            finally:
                os.close(descriptor)

    def test_authenticated_deploy_passes_the_open_snapshot_fd_not_its_path(self):
        installer_bytes = INSTALLER_PATH.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            archive = base / "upload.tar.gz"
            make_archive(archive, installer_bytes)
            live = base / "live"
            live.mkdir()
            observed = {}

            def inspect_handoff(command, *, archive_fd, **_kwargs):
                observed["fd"] = archive_fd
                observed["command"] = list(command)
                status = os.fstat(archive_fd)
                self.assertTrue(stat.S_ISREG(status.st_mode))
                self.assertEqual(0o600, stat.S_IMODE(status.st_mode))
                self.assertEqual(1, status.st_nlink)
                os.lseek(archive_fd, 0, os.SEEK_SET)
                digest = hashlib.sha256()
                while True:
                    block = os.read(archive_fd, 1024 * 1024)
                    if not block:
                        break
                    digest.update(block)
                self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), digest.hexdigest())
                self.assertEqual(str(archive_fd), command[command.index("--archive-fd") + 1])
                self.assertNotIn("--archive", command)
                self.assertNotIn(os.fspath(archive), command)
                return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

            with mock.patch.object(
                self.installer, "run_guard", side_effect=inspect_handoff,
            ):
                self.installer.deploy_archive(
                    archive, root=live, runtime="native", verify_only=False,
                    installer_path=INSTALLER_PATH, required_uid=os.getuid(),
                    staging_parent=base,
                    python_executable=sys.executable,
                )
            self.assertIn("fd", observed)

    def test_guard_timeout_signal_and_output_overflow_fail_closed(self):
        with self.assertRaisesRegex(self.installer.InstallError, "timed out"):
            self.installer.run_guard(
                [sys.executable, "-c", "import time; time.sleep(2)"],
                timeout=1,
            )
        signaled = self.installer.run_guard([
            sys.executable, "-c", "import os,signal; os.kill(os.getpid(), signal.SIGTERM)",
        ])
        self.assertLess(signaled.returncode, 0)
        with self.assertRaisesRegex(self.installer.InstallError, "exceeded"):
            self.installer.run_guard([
                sys.executable, "-c",
                "import sys; sys.stdout.write('x' * (1024 * 1024 + 1))",
            ])

    def test_verify_only_never_runs_guard_or_touches_live_root(self):
        installer_bytes = INSTALLER_PATH.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            archive = base / "upload.tar.gz"
            root = base / "live"
            root.mkdir()
            make_archive(archive, installer_bytes)
            before = tuple(root.iterdir())
            with mock.patch.object(self.installer, "run_guard") as runner:
                result = self.installer.deploy_archive(
                    archive, root=root, runtime="native", verify_only=True,
                    installer_path=INSTALLER_PATH, required_uid=os.getuid(),
                )
            runner.assert_not_called()
            self.assertEqual(before, tuple(root.iterdir()))
            self.assertEqual("customer", result.project)
            self.assertEqual(archive.stat().st_size, result.archive_size)

    def test_verify_only_rejects_live_symlink_and_hardlink_conflicts(self):
        installer_bytes = INSTALLER_PATH.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            archive = base / "upload.tar.gz"
            make_archive(archive, installer_bytes)
            live = base / "live"
            outside = base / "outside"
            live.mkdir()
            outside.mkdir()
            (live / "tools").symlink_to(outside)
            with self.assertRaisesRegex(self.installer.InstallError, "ancestor"):
                self.installer.deploy_archive(
                    archive, root=live, runtime="native", verify_only=True,
                    installer_path=INSTALLER_PATH, required_uid=os.getuid(),
                )
            (live / "tools").unlink()
            (live / "tools").mkdir()
            target = live / "tools/deploy-upload-archive.py"
            target.write_bytes(b"old")
            os.link(target, base / "second-link")
            with self.assertRaisesRegex(self.installer.InstallError, "unsafe live"):
                self.installer.deploy_archive(
                    archive, root=live, runtime="native", verify_only=True,
                    installer_path=INSTALLER_PATH, required_uid=os.getuid(),
                )

    def test_real_embedded_guard_workflow_overlays_only_inside_temp_root(self):
        installer_bytes = INSTALLER_PATH.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            archive = base / "upload.tar.gz"
            live = base / "live"
            live.mkdir()
            make_archive(archive, installer_bytes)
            result = self.installer.deploy_archive(
                archive, root=live, runtime="native", verify_only=False,
                installer_path=INSTALLER_PATH, required_uid=os.getuid(),
                python_executable=sys.executable, staging_parent=base,
                guard_environment={"PATH": "/nonexistent"},
            )
            self.assertEqual("customer", result.project)
            self.assertTrue((live / "DAY0-Prepare/customer/01-global.yaml").is_file())
            manifest = json.loads((live / "infra/docker/deployment-source-manifest.json").read_text())
            for record in manifest["files"]:
                target = live / record["path"]
                self.assertEqual(record["sha256"], hashlib.sha256(target.read_bytes()).hexdigest())
            self.assertFalse((live / ".sync-code-in-progress").exists())

    def test_authenticated_upload_workflow_rejects_archive_lock_member_without_live_write(self):
        installer_bytes = INSTALLER_PATH.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            archive = base / "upload-with-control-path.tar.gz"
            live = base / "live"
            live.mkdir()
            make_archive(
                archive, installer_bytes,
                extra_members=(("./.deployment.lock", b"attacker-lock-inode\n"),),
            )
            with self.assertRaisesRegex(
                self.installer.InstallError, "reserved|control|guard.*74",
            ):
                self.installer.deploy_archive(
                    archive, root=live, runtime="native", verify_only=False,
                    installer_path=INSTALLER_PATH, required_uid=os.getuid(),
                    python_executable=sys.executable, staging_parent=base,
                    guard_environment={"PATH": "/nonexistent"},
                )
            self.assertEqual([], list(live.iterdir()))

    def test_verified_embedded_guard_contains_live_root_swap_at_publish(self):
        installer_bytes = INSTALLER_PATH.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            archive = base / "upload.tar.gz"
            make_archive(archive, installer_bytes)
            verified = self.installer.verify_inputs(
                archive, INSTALLER_PATH, required_uid=os.getuid(),
            )
            embedded_path = base / "verified-embedded-guard.py"
            embedded_path.write_text(verified.guard_source, encoding="utf-8")
            spec = importlib.util.spec_from_file_location(
                "verified_embedded_guard_root_swap", embedded_path,
            )
            self.assertIsNotNone(spec)
            self.assertIsNotNone(spec.loader)
            embedded_guard = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(embedded_guard)

            live = base / "live"
            live.mkdir()
            displaced = base / "live.displaced"
            attacker = base / "attacker"
            (attacker / "tools").mkdir(parents=True)
            (attacker / "infra" / "docker").mkdir(parents=True)
            (attacker / "DAY0-Prepare" / "customer").mkdir(parents=True)
            real_mkstemp = embedded_guard.tempfile.mkstemp
            real_replace = embedded_guard.os.replace
            swapped = False

            def swap_root_once():
                nonlocal swapped
                if not swapped:
                    live.rename(displaced)
                    live.symlink_to(attacker, target_is_directory=True)
                    swapped = True

            def swap_root_then_mkstemp(*args, **kwargs):
                swap_root_once()
                return real_mkstemp(*args, **kwargs)

            def swap_root_then_replace(*args, **kwargs):
                swap_root_once()
                return real_replace(*args, **kwargs)

            try:
                with mock.patch.object(
                    embedded_guard.tempfile,
                    "mkstemp",
                    side_effect=swap_root_then_mkstemp,
                ), mock.patch.object(
                    embedded_guard.os,
                    "replace",
                    side_effect=swap_root_then_replace,
                ):
                    with self.assertRaisesRegex(
                        embedded_guard.GuardError,
                        "root.*(changed|identity)",
                    ):
                        embedded_guard.apply_archive_overlay(
                            live,
                            archive,
                            hashlib.sha256(archive.read_bytes()).hexdigest(),
                            lock_path=live / ".deployment.lock",
                        )
            finally:
                if live.is_symlink():
                    live.unlink()
                if displaced.exists():
                    displaced.rename(live)

            self.assertTrue(swapped)
            self.assertEqual(
                [],
                [
                    path.relative_to(attacker).as_posix()
                    for path in attacker.rglob("*")
                    if path.is_file() or path.is_symlink()
                ],
            )
            self.assertFalse((live / "tools" / "deploy-upload-archive.py").exists())
            self.assertFalse((live / "tools" / "deployment_prewrite_guard.py").exists())

    def test_wrapper_snapshot_capacity_does_not_duplicate_expanded_payload_budget(self):
        installer_bytes = INSTALLER_PATH.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            archive = base / "upload.tar.gz"
            make_archive(
                archive,
                installer_bytes,
                extra_members=((
                    "DAY0-Prepare/customer/highly-compressible.bin",
                    b"0" * (2 * 1024 * 1024),
                ),),
            )
            live = base / "live"
            live.mkdir()
            staging_parent = base / "staging"
            staging_parent.mkdir()
            available = archive.stat().st_size + 65 * 1024 * 1024
            filesystem = SimpleNamespace(
                f_bavail=available, f_frsize=1,
                f_files=1_000_000, f_favail=1_000_000,
            )
            self.assertGreater(available, archive.stat().st_size + 16 * 1024 * 1024)

            with mock.patch.object(
                self.installer.os, "fstatvfs", return_value=filesystem,
            ), mock.patch.object(
                self.installer, "run_guard",
            ) as guard:
                guard.return_value = subprocess.CompletedProcess(
                    [], 0, stdout=b"", stderr=b"",
                )
                result = self.installer.deploy_archive(
                    archive,
                    root=live,
                    runtime="docker",
                    verify_only=False,
                    installer_path=INSTALLER_PATH,
                    required_uid=os.getuid(),
                    staging_parent=staging_parent,
                )

            guard.assert_called_once()
            self.assertEqual("docker", result.next_runtime)
            self.assertEqual([], list(live.iterdir()))
            self.assertEqual([], list(staging_parent.iterdir()))

    def test_wrapper_snapshot_inode_exhaustion_precedes_guard_start(self):
        installer_bytes = INSTALLER_PATH.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            archive = base / "upload.tar.gz"
            make_archive(archive, installer_bytes)
            live = base / "live"
            live.mkdir()
            staging_parent = base / "staging"
            staging_parent.mkdir()
            filesystem = SimpleNamespace(
                f_bavail=1024 * 1024 * 1024, f_frsize=1,
                f_files=1_000_000, f_favail=4097,
            )
            with mock.patch.object(
                self.installer.os, "fstatvfs", return_value=filesystem,
            ), mock.patch.object(
                self.installer, "run_guard",
            ) as guard, self.assertRaisesRegex(
                self.installer.InstallError, "inode",
            ):
                self.installer.deploy_archive(
                    archive, root=live, runtime="native", verify_only=False,
                    installer_path=INSTALLER_PATH, required_uid=os.getuid(),
                    staging_parent=staging_parent,
                )
            guard.assert_not_called()
            self.assertEqual([], list(staging_parent.iterdir()))

    def test_wrapper_snapshot_block_exhaustion_precedes_guard_start(self):
        installer_bytes = INSTALLER_PATH.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            archive = base / "upload.tar.gz"
            make_archive(archive, installer_bytes)
            live = base / "live"
            live.mkdir()
            staging_parent = base / "staging"
            staging_parent.mkdir()
            filesystem = SimpleNamespace(
                f_bavail=1, f_frsize=4096,
                f_files=1_000_000, f_favail=1_000_000,
            )
            with mock.patch.object(
                self.installer.os, "fstatvfs", return_value=filesystem,
            ), mock.patch.object(
                self.installer, "run_guard",
            ) as guard, self.assertRaisesRegex(
                self.installer.InstallError, "space|snapshot|capacity",
            ):
                self.installer.deploy_archive(
                    archive, root=live, runtime="native", verify_only=False,
                    installer_path=INSTALLER_PATH, required_uid=os.getuid(),
                    staging_parent=staging_parent,
                )
            guard.assert_not_called()
            self.assertEqual([], list(staging_parent.iterdir()))

    def test_wrapper_zero_zero_inode_accounting_skips_inode_only(self):
        installer_bytes = INSTALLER_PATH.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            archive = base / "upload.tar.gz"
            make_archive(archive, installer_bytes)
            live = base / "live"
            live.mkdir()
            staging_parent = base / "staging"
            staging_parent.mkdir()
            filesystem = SimpleNamespace(
                f_bavail=1024 * 1024 * 1024, f_frsize=1,
                f_files=0, f_favail=0,
            )
            completed = subprocess.CompletedProcess([], 0, stdout=b"", stderr=b"")
            output = io.StringIO()
            with mock.patch.object(
                self.installer.os, "fstatvfs", return_value=filesystem,
            ), mock.patch.object(
                self.installer, "run_guard", return_value=completed,
            ) as guard, mock.patch("sys.stdout", output):
                self.installer.deploy_archive(
                    archive, root=live, runtime="native", verify_only=False,
                    installer_path=INSTALLER_PATH, required_uid=os.getuid(),
                    staging_parent=staging_parent,
                )
            guard.assert_called_once()
            self.assertRegex(output.getvalue(), "inode.*(unreported|skip)")

    def test_snapshot_enospc_and_edquot_cleanup_before_guard(self):
        installer_bytes = INSTALLER_PATH.read_bytes()
        for error_number in (__import__("errno").ENOSPC, __import__("errno").EDQUOT):
            with self.subTest(error_number=error_number), tempfile.TemporaryDirectory() as directory:
                base = Path(directory).resolve()
                archive = base / "upload.tar.gz"
                make_archive(archive, installer_bytes)
                live = base / "live"
                live.mkdir()
                staging_parent = base / "staging"
                staging_parent.mkdir()
                with mock.patch.object(
                    self.installer.os, "write",
                    side_effect=OSError(error_number, "injected snapshot allocation failure"),
                ), mock.patch.object(
                    self.installer, "run_guard",
                ) as guard, self.assertRaises(self.installer.InstallError):
                    self.installer.deploy_archive(
                        archive, root=live, runtime="native", verify_only=False,
                        installer_path=INSTALLER_PATH, required_uid=os.getuid(),
                        staging_parent=staging_parent,
                    )
                guard.assert_not_called()
                self.assertEqual([], list(staging_parent.iterdir()))

    def test_verified_embedded_guard_checks_expanded_capacity_before_overlay(self):
        installer_bytes = INSTALLER_PATH.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            archive = base / "upload.tar.gz"
            make_archive(
                archive,
                installer_bytes,
                extra_members=((
                    "DAY0-Prepare/customer/highly-compressible.bin",
                    b"0" * (2 * 1024 * 1024),
                ),),
            )
            verified = self.installer.verify_inputs(
                archive, INSTALLER_PATH, required_uid=os.getuid(),
            )
            embedded_path = base / "verified-capacity-guard.py"
            embedded_path.write_text(verified.guard_source, encoding="utf-8")
            spec = importlib.util.spec_from_file_location(
                "verified_embedded_guard_capacity", embedded_path,
            )
            self.assertIsNotNone(spec)
            self.assertIsNotNone(spec.loader)
            embedded_guard = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(embedded_guard)

            live = base / "live"
            live.mkdir()
            staging_parent = base / "staging"
            staging_parent.mkdir()
            filesystem = SimpleNamespace(
                f_bavail=65 * 1024 * 1024, f_frsize=1,
                f_files=1_000_000, f_favail=1_000_000,
            )
            real_mkdtemp = tempfile.mkdtemp

            def private_stage(*, prefix):
                return real_mkdtemp(prefix=prefix, dir=staging_parent)

            with mock.patch.object(
                embedded_guard.tempfile, "mkdtemp", side_effect=private_stage,
            ), mock.patch.object(
                embedded_guard.os, "fstatvfs", return_value=filesystem,
            ), self.assertRaisesRegex(
                embedded_guard.GuardError, "expanded.*(space|capacity)",
            ):
                embedded_guard.apply_archive_overlay(
                    live,
                    archive,
                    hashlib.sha256(archive.read_bytes()).hexdigest(),
                    lock_path=live / ".deployment.lock",
                )

            self.assertEqual([], list(live.iterdir()))
            self.assertEqual([], list(staging_parent.iterdir()))

    def test_authenticated_embedded_guard_enforces_tiny_inode_and_live_budgets(self):
        installer_bytes = INSTALLER_PATH.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()

            tiny_archive = base / "tiny-upload.tar.gz"
            make_archive(
                tiny_archive, installer_bytes,
                extra_members=tuple(
                    (f"tiny/{index:05d}", b"x") for index in range(20_001)
                ),
            )
            tiny_guard = self._load_verified_guard(
                tiny_archive, base, "authenticated_tiny_guard",
            )
            live = base / "tiny-live"
            live.mkdir()
            tiny_filesystem = SimpleNamespace(
                f_bavail=67_129_344 // 4096, f_frsize=4096,
                f_files=1_000_000, f_favail=1_000_000,
            )
            with mock.patch.object(
                tiny_guard.os, "fstatvfs", return_value=tiny_filesystem,
            ), self.assertRaisesRegex(tiny_guard.GuardError, "capacity|blocks"):
                tiny_guard.apply_archive_overlay(
                    live, tiny_archive,
                    hashlib.sha256(tiny_archive.read_bytes()).hexdigest(),
                    lock_path=live / ".deployment.lock",
                )
            self.assertEqual([], list(live.iterdir()))

            ordinary_archive = base / "ordinary-upload.tar.gz"
            make_archive(ordinary_archive, installer_bytes)
            ordinary_guard = self._load_verified_guard(
                ordinary_archive, base, "authenticated_domain_guard",
            )
            inode_live = base / "inode-live"
            inode_live.mkdir()
            inode_filesystem = SimpleNamespace(
                f_bavail=2 * 1024 * 1024 * 1024, f_frsize=1,
                f_files=1_000_000, f_favail=4096,
            )
            with mock.patch.object(
                ordinary_guard.os, "fstatvfs", return_value=inode_filesystem,
            ), self.assertRaisesRegex(ordinary_guard.GuardError, "inode"):
                ordinary_guard.apply_archive_overlay(
                    inode_live, ordinary_archive,
                    hashlib.sha256(ordinary_archive.read_bytes()).hexdigest(),
                    lock_path=inode_live / ".deployment.lock",
                )
            self.assertEqual([], list(inode_live.iterdir()))

            capacity_live = base / "capacity-live"
            capacity_live.mkdir()
            capacity_sequence = [
                SimpleNamespace(
                    f_bavail=2 * 1024 * 1024 * 1024, f_frsize=1,
                    f_files=1_000_000, f_favail=1_000_000,
                ),
                SimpleNamespace(
                    f_bavail=1024, f_frsize=1,
                    f_files=1_000_000, f_favail=1_000_000,
                ),
            ]
            with mock.patch.object(
                ordinary_guard.os, "fstatvfs", side_effect=capacity_sequence,
            ) as capacity_check, self.assertRaisesRegex(
                ordinary_guard.GuardError, "live-root.*(capacity|blocks)",
            ):
                ordinary_guard.apply_archive_overlay(
                    capacity_live, ordinary_archive,
                    hashlib.sha256(ordinary_archive.read_bytes()).hexdigest(),
                    lock_path=capacity_live / ".deployment.lock",
                )
            self.assertEqual(2, capacity_check.call_count)
            self.assertEqual([], list(capacity_live.iterdir()))

    def test_staging_parent_swap_cannot_redirect_private_archive_snapshot(self):
        installer_bytes = INSTALLER_PATH.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            archive = base / "upload.tar.gz"
            make_archive(archive, installer_bytes)
            live = base / "live"
            live.mkdir()
            parent = base / "private-parent"
            parent.mkdir(mode=0o700)
            displaced = base / "displaced-parent"
            attacker = base / "attacker-parent"
            attacker.mkdir(mode=0o700)
            real_mkdir = os.mkdir
            swapped_name = None

            def swap_after_private_stage_creation(path, mode=0o777, *args, **kwargs):
                nonlocal swapped_name
                result = real_mkdir(path, mode, *args, **kwargs)
                name = Path(os.fspath(path)).name
                if swapped_name is None and name.startswith("http-upload-archive."):
                    swapped_name = name
                    os.rename(parent, displaced)
                    parent.symlink_to(attacker, target_is_directory=True)
                    real_mkdir(attacker / name, 0o700)
                    (attacker / name / "attacker-marker").write_bytes(b"preserve")
                return result

            completed = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
            try:
                with mock.patch.object(
                    self.installer.os, "mkdir",
                    side_effect=swap_after_private_stage_creation,
                ), mock.patch.object(
                    self.installer, "run_guard", return_value=completed,
                ) as guard, self.assertRaisesRegex(
                    self.installer.InstallError, "parent.*changed|identity",
                ):
                    self.installer.deploy_archive(
                        archive, root=live, runtime="native", verify_only=False,
                        installer_path=INSTALLER_PATH, required_uid=os.getuid(),
                        staging_parent=parent,
                    )
                guard.assert_not_called()
                self.assertIsNotNone(swapped_name, "private stage race was not exercised")
                attacker_stage = attacker / swapped_name
                self.assertEqual(
                    ["attacker-marker"],
                    sorted(item.name for item in attacker_stage.iterdir()),
                )
                self.assertEqual(b"preserve", (attacker_stage / "attacker-marker").read_bytes())
                self.assertFalse(any(
                    item.name.startswith("http-upload-archive.")
                    for item in displaced.iterdir()
                ))
            finally:
                if parent.is_symlink():
                    parent.unlink()
                if displaced.exists():
                    os.rename(displaced, parent)

    def test_snapshot_cleanup_is_bound_to_the_opened_directory_inode(self):
        installer_bytes = INSTALLER_PATH.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            archive = base / "upload.tar.gz"
            make_archive(archive, installer_bytes)
            live = base / "live"
            live.mkdir()
            parent = base / "private-parent"
            parent.mkdir(mode=0o700)
            moved_stage = base / "moved-private-stage"
            real_fsync = os.fsync
            original_stage = None

            def replace_stage_after_snapshot_sync(descriptor):
                nonlocal original_stage
                real_fsync(descriptor)
                if original_stage is not None:
                    return
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode):
                    return
                stages = [
                    item for item in parent.iterdir()
                    if item.name.startswith("http-upload-archive.")
                ]
                if len(stages) != 1:
                    return
                original_stage = stages[0]
                os.rename(original_stage, moved_stage)
                original_stage.mkdir(mode=0o700)
                (original_stage / "attacker-marker").write_bytes(b"preserve")

            completed = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
            with mock.patch.object(
                self.installer.os, "fsync",
                side_effect=replace_stage_after_snapshot_sync,
            ), mock.patch.object(
                self.installer, "run_guard", return_value=completed,
            ) as guard, self.assertRaisesRegex(
                self.installer.InstallError, "staging.*identity|identity.*staging",
            ):
                self.installer.deploy_archive(
                    archive, root=live, runtime="native", verify_only=False,
                    installer_path=INSTALLER_PATH, required_uid=os.getuid(),
                    staging_parent=parent,
                )
            guard.assert_not_called()
            self.assertIsNotNone(original_stage, "staging replacement was not exercised")
            self.assertEqual(
                ["attacker-marker"],
                sorted(item.name for item in original_stage.iterdir()),
            )
            self.assertEqual(b"preserve", (original_stage / "attacker-marker").read_bytes())
            self.assertFalse(
                any(item.is_file() for item in moved_stage.rglob("*")),
                "verified archive bytes remained in the displaced staging inode",
            )

    def test_real_packager_relay_copy_installer_and_embedded_guard_workflow(self):
        fixture = materialized_public_project(ROOT)
        project = fixture.__enter__()
        self.addCleanup(fixture.__exit__, None, None, None)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            built = base / "built-upload.tar.gz"
            args = argparse.Namespace(
                project=str(project), output=built, force=False,
                max_file_size_mib=50, include_images=False,
                include_apps=False, apps_platform=None, apps_platforms=set(),
                include_firmware=False,
            )
            package.create_package(
                args, day0_all=False, artifact_kind="upload",
            )

            relayed = base / "relayed-upload.tar.gz"
            installer_copy = base / "deploy-upload-archive.py"
            shutil.copyfile(built, relayed)
            shutil.copyfile(INSTALLER_PATH, installer_copy)
            relayed.chmod(0o600)
            installer_copy.chmod(0o500)
            live = base / "live"
            live.mkdir()

            result = self.installer.deploy_archive(
                relayed, root=live, runtime="native", verify_only=False,
                installer_path=installer_copy, required_uid=os.getuid(),
                python_executable=sys.executable, staging_parent=base,
                guard_environment={"PATH": "/nonexistent"},
            )
            self.assertEqual(project.name, result.project)
            manifest_path = live / "infra/docker/deployment-source-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="ascii"))
            for record in manifest["files"]:
                target = live / record["path"]
                self.assertTrue(target.exists() or target.is_symlink(), record["path"])
                if record["type"] == "file":
                    payload = target.read_bytes()
                else:
                    self.assertEqual(record["target"], os.readlink(target))
                    payload = target.resolve(strict=True).read_bytes()
                self.assertEqual(record["sha256"], hashlib.sha256(payload).hexdigest())
            self.assertFalse((live / ".sync-code-in-progress").exists())

    def test_guard_failure_or_docker_marker_controls_next_step(self):
        installer_bytes = INSTALLER_PATH.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            archive = base / "upload.tar.gz"
            root = base / "live"
            root.mkdir()
            make_archive(archive, installer_bytes)
            failed = SimpleNamespace(returncode=74, stdout=b"", stderr=b"refused")
            with mock.patch.object(self.installer, "run_guard", return_value=failed):
                with self.assertRaisesRegex(self.installer.InstallError, "guard.*74"):
                    self.installer.deploy_archive(
                        archive, root=root, runtime="native", verify_only=False,
                        installer_path=INSTALLER_PATH, required_uid=os.getuid(),
                        staging_parent=base,
                    )
            docker = SimpleNamespace(
                returncode=0,
                stdout=b"HTTP_ZTP_DOCKER_REBUILD_REQUIRED\n", stderr=b"",
            )
            with mock.patch.object(self.installer, "run_guard", return_value=docker):
                result = self.installer.deploy_archive(
                    archive, root=root, runtime="native", verify_only=False,
                    installer_path=INSTALLER_PATH, required_uid=os.getuid(),
                    staging_parent=base,
                )
            self.assertEqual("docker", result.next_runtime)
            self.assertEqual(
                ("cd /var/www/html", "sudo ./infra/docker/deploy.sh deploy"),
                self.installer.next_commands(result, Path("/var/www/html")),
            )

            busy = SimpleNamespace(returncode=75, stdout=b"", stderr=b"busy")
            with mock.patch.object(self.installer, "run_guard", return_value=busy):
                with self.assertRaisesRegex(self.installer.InstallError, "75"):
                    self.installer.deploy_archive(
                        archive, root=root, runtime="native", verify_only=False,
                        installer_path=INSTALLER_PATH, required_uid=os.getuid(),
                        staging_parent=base,
                    )

    def test_archive_identity_is_rechecked_when_guard_fails(self):
        installer_bytes = INSTALLER_PATH.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            archive = base / "upload.tar.gz"
            root = base / "live"
            root.mkdir()
            make_archive(archive, installer_bytes)

            def mutate_then_fail(_command, **_kwargs):
                with archive.open("ab") as stream:
                    stream.write(b"changed-during-guard")
                return SimpleNamespace(returncode=74, stdout=b"", stderr=b"refused")

            with mock.patch.object(
                self.installer, "run_guard", side_effect=mutate_then_fail,
            ), self.assertRaisesRegex(
                self.installer.InstallError, "changed while being read",
            ):
                self.installer.deploy_archive(
                    archive, root=root, runtime="native", verify_only=False,
                    installer_path=INSTALLER_PATH, required_uid=os.getuid(),
                    staging_parent=base,
                )

    def test_cli_requires_root_before_archive_or_subprocess_work(self):
        with mock.patch.object(self.installer.os, "geteuid", return_value=501), \
                mock.patch.object(self.installer, "deploy_archive") as deploy:
            stderr = io.StringIO()
            with mock.patch("sys.stderr", stderr):
                self.assertEqual(1, self.installer.main(["/tmp/archive.tar.gz"]))
        deploy.assert_not_called()
        self.assertIn("root", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
