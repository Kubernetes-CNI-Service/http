#!/usr/bin/env python3
"""Direct and workflow contracts for independent shared-artifact bundles."""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
PACKAGER_PATH = ROOT / "tools/package-shared-artifacts.py"
INSTALLER_PATH = ROOT / "tools/deploy-shared-artifacts.py"
LOAD_PATH = ROOT / "DAY0-Prepare/11-load.py"

# This expectation is intentionally owned by the test.  It mirrors the
# management-server package roots required by the supported offline workflow;
# the packager must not be able to bless an arbitrary, incomplete APT index.
REQUIRED_APT_PACKAGES = {
    "wget", "lldpd", "tzdata", "ipmitool", "sshpass", "docker.io",
    "unzip", "nfs-common", "arping", "python3", "python3-yaml",
    "python3-jinja2", "python3-openpyxl", "python3-pandas",
    "python3-xlsxwriter", "openssh-client", "curl", "apache2",
    "ssl-cert", "isc-dhcp-server", "jq",
}


def load_script(path: Path, name: str):
    if not path.is_file():
        raise AssertionError(f"required production script is missing: {path}")
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
    return module


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def global_yaml() -> str:
    return """\
schema_version: 1
common:
  mgmt:
    dhcp-server:
      status: enabled
      package: isc-dhcp-server
    http:
      status: enabled
      package: apache2
      http_root: /var/www/html
    ztp:
      status: enabled
      ztp_url_prefix: /ztp
  switch:
    system:
      dns: []
      ntp: []
      date-time: {}
switches:
  - eth:
      version: 5.18.1
  - ib:
      version: 25.03.1010
  - nvl:
      version: 25.02.4282
"""


DEVICE_HEADER = (
    "hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac,"
    "eth1_ip,netmask,eth1_gw,eth1_mac\n"
)


def prepare_repository(base: Path) -> tuple[Path, Path]:
    repository = base / "repo"
    project = repository / "DAY0-Prepare/customer"
    project.mkdir(parents=True)
    (repository / "image").mkdir()
    (repository / "apps").mkdir()
    (repository / "firmware").mkdir()
    (project / "01-global.yaml").write_text(global_yaml(), encoding="utf-8")
    (project / "02-devices_config.csv").write_text(
        DEVICE_HEADER
        + "leaf01,eth,oob,192.0.2.11,255.255.255.0,192.0.2.1,02:00:00:00:00:11,,,,\n"
        + "ib01,ib,NA,192.0.2.12,255.255.255.0,192.0.2.1,02:00:00:00:00:12,,,,\n"
        + "nvl01,nvl,NA,192.0.2.13,255.255.255.0,192.0.2.1,02:00:00:00:00:13,,,,\n"
        + "AIR-leaf01,air,oob,192.0.2.14,255.255.255.0,192.0.2.1,02:00:00:00:00:14,,,,\n",
        encoding="utf-8",
    )
    (project / "04-air-mini-devices.txt").write_text(
        "AIR-leaf01\n", encoding="utf-8",
    )
    return repository, project


def image_payload(marker: bytes) -> bytes:
    return b"#!/bin/sh\n" + marker + b"\n" + b"x" * (1024 * 1024)


def add_switch_images(repository: Path) -> dict[str, Path]:
    images = {
        "eth": repository / "image/cumulus-linux-5.18.1-mlx-amd64.bin",
        "ib": repository / "image/nvos-amd64-25.03.1010.bin",
        "nvl": repository / "image/nvosv25-02-4282amd64.bin",
    }
    for family, path in images.items():
        path.write_bytes(image_payload(family.encode("ascii")))
        path.chmod(0o644)
    return images


def add_apps(repository: Path, platform: str = "ubuntu-24.04/amd64") -> Path:
    directory = repository / "apps" / platform
    directory.mkdir(parents=True, exist_ok=True)
    architecture = platform.rsplit("/", 1)[1]
    records = []
    for name in sorted(REQUIRED_APT_PACKAGES):
        filename = name.replace(".", "-") + f"_1.0_{architecture}.deb"
        package = directory / filename
        package.write_bytes(("deb:" + name).encode("ascii"))
        records.append(
            f"Package: {name}\nArchitecture: {architecture}\n"
            f"Filename: ./{filename}\n"
            f"Size: {package.stat().st_size}\nSHA256: {sha256(package)}\n"
            "Description: test package\n continued description\n\n"
        )
    packages = "".join(records).encode("ascii")
    (directory / "Packages").write_bytes(packages)
    with (directory / "Packages.gz").open("wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as stream:
            stream.write(packages)
    (directory / "repository.meta").write_text(
        "schema_version=1\nos_id=ubuntu\nos_version=24.04\narchitecture=amd64\n",
        encoding="ascii",
    )
    return directory


def rewrite_bundle_metadata_bytes(bundle, metadata: bytes) -> None:
    """Replace external and embedded metadata with exact test-controlled bytes."""
    captured = []
    with tarfile.open(bundle.archive, "r:gz") as archive:
        for member in archive.getmembers():
            payload = archive.extractfile(member).read() if member.isfile() else None
            captured.append((member.name, member.isdir(), member.mode, payload))
    replacement = bundle.archive.with_suffix(".replacement")
    with tarfile.open(replacement, "w:gz") as archive:
        for name, is_directory, mode, payload in captured:
            info = tarfile.TarInfo(name)
            info.uid = info.gid = 0
            info.mode = mode
            info.mtime = 0
            if is_directory:
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
                continue
            if name == "artifact-metadata.json":
                payload = metadata
            assert payload is not None
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    replacement.chmod(0o600)
    os.replace(replacement, bundle.archive)
    bundle.metadata.write_bytes(metadata)
    bundle.metadata.chmod(0o600)


def rewrite_bundle_metadata(bundle, mutate) -> None:
    """Rewrite test metadata both externally and in-tar without signing it."""
    value = json.loads(bundle.metadata.read_text(encoding="ascii"))
    mutate(value)
    metadata = json.dumps(
        value, ensure_ascii=True, indent=2, sort_keys=True,
    ).encode("ascii") + b"\n"
    rewrite_bundle_metadata_bytes(bundle, metadata)


def rewrite_bundle_payload(bundle, target: str, payload: bytes) -> None:
    """Make a self-consistent metadata/tar payload mutation for negative tests."""
    captured = []
    with tarfile.open(bundle.archive, "r:gz") as archive:
        for member in archive.getmembers():
            value = archive.extractfile(member).read() if member.isfile() else None
            captured.append((member.name, member.isdir(), member.mode, value))
    metadata = json.loads(bundle.metadata.read_text(encoding="ascii"))
    record = next(item for item in metadata["artifacts"] if item["target"] == target)
    record["size"] = len(payload)
    record["sha256"] = hashlib.sha256(payload).hexdigest()
    metadata_bytes = json.dumps(
        metadata, ensure_ascii=True, indent=2, sort_keys=True,
    ).encode("ascii") + b"\n"
    replacement = bundle.archive.with_suffix(".payload-replacement")
    with tarfile.open(replacement, "w:gz") as archive:
        for name, is_directory, mode, value in captured:
            info = tarfile.TarInfo(name)
            info.uid = info.gid = 0
            info.mode = mode
            info.mtime = 0
            if is_directory:
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
                continue
            if name == "artifact-metadata.json":
                value = metadata_bytes
            elif name == "payload/" + target:
                value = payload
            assert value is not None
            info.size = len(value)
            archive.addfile(info, io.BytesIO(value))
    replacement.chmod(0o600)
    os.replace(replacement, bundle.archive)
    bundle.metadata.write_bytes(metadata_bytes)
    bundle.metadata.chmod(0o600)


class PackagerDirectTests(unittest.TestCase):
    def setUp(self):
        self.packager = load_script(PACKAGER_PATH, "shared_artifact_packager_contract")

    def test_cli_is_project_driven_and_large_payloads_are_opt_in(self):
        parser = self.packager.parser()
        with self.assertRaises(SystemExit):
            parser.parse_args([])
        args = parser.parse_args(["customer", "--no-upgrade"])
        self.assertEqual("customer", args.project)
        self.assertEqual("all", args.deployment_scope)
        self.assertIsNone(args.switch_scope)
        self.assertTrue(args.no_upgrade)
        self.assertEqual([], args.apps_platform)
        self.assertEqual([], args.firmware)
        help_text = parser.format_help()
        self.assertNotIn("--include-images", help_text)
        self.assertNotIn("--include-apps", help_text)
        self.assertNotIn("--include-firmware", help_text)

    def test_air_mini_uses_real_load_parser_and_selects_only_eth(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository, _project = prepare_repository(Path(temporary))
            images = add_switch_images(repository)
            output = repository / "outputs/artifacts/air-mini"
            result = self.packager.build_bundle(
                "customer", output=output, repository_root=repository,
                deployment_scope="all", mini=True,
                installer_path=INSTALLER_PATH, load_script_path=LOAD_PATH,
            )
            self.assertTrue(result.created)
            metadata = json.loads(result.metadata.read_text(encoding="ascii"))
            self.assertEqual("air", metadata["deployment_scope"])
            self.assertEqual("eth", metadata["switch_scope"])
            self.assertTrue(metadata["mini"])
            records = metadata["artifacts"]
            self.assertEqual(
                [[{"family": "eth", "version": "5.18.1"}]],
                [item["consumers"] for item in records],
            )
            self.assertEqual(sha256(images["eth"]), records[0]["sha256"])
            self.assertEqual(
                "image/cumulus-linux-5.18.1-mlx-amd64.bin",
                records[0]["target"],
            )

    def test_prod_switch_scope_uses_modern_nvos_alias(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository, _project = prepare_repository(Path(temporary))
            images = add_switch_images(repository)
            output = repository / "outputs/artifacts/prod-ib"
            result = self.packager.build_bundle(
                "customer", output=output, repository_root=repository,
                deployment_scope="prod", switch_scope="ib",
                installer_path=INSTALLER_PATH, load_script_path=LOAD_PATH,
            )
            metadata = json.loads(result.metadata.read_text(encoding="ascii"))
            self.assertEqual("prod", metadata["deployment_scope"])
            self.assertEqual("ib", metadata["switch_scope"])
            self.assertEqual(
                [([{"family": "ib", "version": "25.03.1010"}], images["ib"].name)],
                [(item["consumers"], Path(item["target"]).name)
                 for item in metadata["artifacts"]],
            )

    def test_same_nvos_payload_is_one_artifact_with_both_consumers(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository, project = prepare_repository(Path(temporary))
            (project / "01-global.yaml").write_text(
                global_yaml().replace("version: 25.02.4282", "version: 25.03.1010"),
                encoding="utf-8",
            )
            images = add_switch_images(repository)
            images["nvl"].unlink()
            result = self.packager.build_bundle(
                "customer", output=repository / "outputs/artifacts/shared-nvos",
                repository_root=repository, deployment_scope="prod",
                installer_path=INSTALLER_PATH, load_script_path=LOAD_PATH,
            )
            metadata = json.loads(result.metadata.read_text(encoding="ascii"))
            switch_records = [
                item for item in metadata["artifacts"]
                if item["kind"] == "switch-image"
            ]
            nvos = [item for item in switch_records if Path(item["target"]).name == images["ib"].name]
            self.assertEqual(1, len(nvos))
            self.assertEqual(
                [
                    {"family": "ib", "version": "25.03.1010"},
                    {"family": "nvl", "version": "25.03.1010"},
                ],
                nvos[0]["consumers"],
            )

    def test_no_upgrade_with_no_explicit_payload_creates_no_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository, _project = prepare_repository(Path(temporary))
            images = add_switch_images(repository)
            os.link(images["eth"], repository / "image/ignored-hardlink.bin")
            output = repository / "outputs/artifacts/empty"
            result = self.packager.build_bundle(
                "customer", output=output, repository_root=repository,
                no_upgrade=True, installer_path=INSTALLER_PATH,
                load_script_path=LOAD_PATH,
            )
            self.assertFalse(result.created)
            self.assertEqual((), result.artifacts)
            self.assertFalse(output.exists())

    def test_existing_output_is_never_replaced(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository, _project = prepare_repository(Path(temporary))
            add_switch_images(repository)
            output = repository / "outputs/artifacts/existing"
            output.mkdir(parents=True)
            sentinel = output / "sentinel"
            sentinel.write_bytes(b"preserve")
            with self.assertRaisesRegex(self.packager.PackageError, "exists|overwrite"):
                self.packager.build_bundle(
                    "customer", output=output, repository_root=repository,
                    deployment_scope="air", installer_path=INSTALLER_PATH,
                    load_script_path=LOAD_PATH,
                )
            self.assertEqual(b"preserve", sentinel.read_bytes())

    def test_output_parent_rejects_an_ancestor_symlink_without_following_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            repository, _project = prepare_repository(base)
            add_switch_images(repository)
            attacker = base / "attacker-output"
            attacker.mkdir(mode=0o700)
            (repository / "outputs").symlink_to(
                attacker, target_is_directory=True,
            )
            output = repository / "outputs/artifacts/shared"

            with self.assertRaisesRegex(
                self.packager.PackageError, "symlink|ancestor|output parent",
            ):
                self.packager.build_bundle(
                    "customer", output=output, repository_root=repository,
                    deployment_scope="air", installer_path=INSTALLER_PATH,
                    load_script_path=LOAD_PATH,
                )
            self.assertFalse((attacker / "artifacts/shared").exists())
            self.assertEqual([], list(attacker.iterdir()))

    def test_output_parent_swap_cannot_redirect_publish_or_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            repository, _project = prepare_repository(base)
            add_switch_images(repository)
            parent = repository / "outputs/artifacts"
            parent.mkdir(parents=True, mode=0o700)
            output = parent / "shared"
            moved_parent = base / "moved-artifacts"
            attacker = base / "attacker-output"
            attacker.mkdir(mode=0o700)
            hook_reached = []

            def swap_parent():
                hook_reached.append(True)
                parent.rename(moved_parent)
                parent.symlink_to(attacker, target_is_directory=True)

            with mock.patch.object(
                self.packager, "_TEST_BEFORE_OUTPUT_PUBLISH", swap_parent,
                create=True,
            ), self.assertRaisesRegex(
                self.packager.PackageError, "output parent|publish",
            ):
                self.packager.build_bundle(
                    "customer", output=output, repository_root=repository,
                    deployment_scope="air", installer_path=INSTALLER_PATH,
                    load_script_path=LOAD_PATH,
                )
            self.assertEqual([True], hook_reached, "publication hook was not reached")
            self.assertEqual([], list(attacker.iterdir()))
            self.assertFalse((moved_parent / output.name).exists())
            self.assertEqual([], list(moved_parent.iterdir()))

    def test_output_publish_is_atomic_no_clobber_under_destination_race(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            repository, _project = prepare_repository(base)
            add_switch_images(repository)
            parent = repository / "outputs/artifacts"
            parent.mkdir(parents=True, mode=0o700)
            output = parent / "shared"
            hook_reached = []

            def claim_destination():
                hook_reached.append(True)
                output.mkdir(mode=0o700)
                (output / "sentinel").write_bytes(b"preserve")

            with mock.patch.object(
                self.packager, "_TEST_BEFORE_OUTPUT_PUBLISH", claim_destination,
                create=True,
            ), self.assertRaisesRegex(
                self.packager.PackageError, "output|publish|exists|appeared",
            ):
                self.packager.build_bundle(
                    "customer", output=output, repository_root=repository,
                    deployment_scope="air", installer_path=INSTALLER_PATH,
                    load_script_path=LOAD_PATH,
                )
            self.assertEqual([True], hook_reached, "publication hook was not reached")
            self.assertEqual(b"preserve", (output / "sentinel").read_bytes())
            self.assertEqual(
                [output],
                sorted(parent.iterdir()),
                "private staging directory leaked after the failed publish",
            )

    def test_output_publish_rechecks_sha256sums_after_final_freeze_hook(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            repository, _project = prepare_repository(base)
            add_switch_images(repository)
            parent = repository / "outputs/artifacts"
            parent.mkdir(parents=True, mode=0o700)
            output = parent / "shared"
            hook_reached = []

            def mutate_frozen_sums():
                stages = [
                    item for item in parent.iterdir()
                    if item.name.startswith(".shared.")
                    or item.name.startswith(".http-ztp-shared.")
                ]
                self.assertEqual(1, len(stages))
                sums = stages[0] / "SHA256SUMS"
                value = sums.read_bytes()
                self.assertGreater(len(value), 1)
                with sums.open("r+b", buffering=0) as stream:
                    stream.write(bytes([value[0] ^ 1]))
                    os.fsync(stream.fileno())
                hook_reached.append(True)

            with mock.patch.object(
                self.packager, "_TEST_BEFORE_OUTPUT_PUBLISH",
                mutate_frozen_sums, create=True,
            ), self.assertRaisesRegex(
                self.packager.PackageError,
                "SHA256SUMS|staged.*(?:hash|changed)|output.*content",
            ):
                self.packager.build_bundle(
                    "customer", output=output, repository_root=repository,
                    deployment_scope="air", installer_path=INSTALLER_PATH,
                    load_script_path=LOAD_PATH,
                )
            self.assertEqual([True], hook_reached)
            self.assertFalse(output.exists())
            self.assertEqual([], list(parent.iterdir()))

    def test_member_count_preflight_rejects_exact_10002_member_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            repository, _project = prepare_repository(base)
            firmware = []
            for number in range(4_999):
                relative = Path(f"component-{number:04d}/fw.bin")
                source = repository / "firmware" / relative
                source.parent.mkdir(parents=True)
                source.write_bytes(b"x")
                firmware.append(relative)
            output = repository / "outputs/artifacts/too-many-members"

            with self.assertRaisesRegex(
                self.packager.PackageError, "member.*count|10000|10,000",
            ):
                self.packager.build_bundle(
                    "customer", output=output, repository_root=repository,
                    no_upgrade=True, firmware=tuple(firmware),
                    installer_path=INSTALLER_PATH,
                    load_script_path=LOAD_PATH,
                )
            self.assertFalse(output.exists())

    def test_no_upgrade_does_not_require_switch_versions(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository, project = prepare_repository(Path(temporary))
            (project / "01-global.yaml").write_text(
                global_yaml()
                .replace("version: 5.18.1", "version: ''")
                .replace("version: 25.03.1010", "version: ''")
                .replace("version: 25.02.4282", "version: ''"),
                encoding="utf-8",
            )
            output = repository / "outputs/artifacts/no-versions"
            result = self.packager.build_bundle(
                "customer", output=output, repository_root=repository,
                no_upgrade=True, installer_path=INSTALLER_PATH,
                load_script_path=LOAD_PATH,
            )
            self.assertFalse(result.created)
            self.assertFalse(output.exists())

    def test_valid_production_mini_alias_freezes_canonical_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository, project = prepare_repository(Path(temporary))
            add_switch_images(repository)
            (project / "mini-alias.txt").symlink_to("04-air-mini-devices.txt")
            output = repository / "outputs/artifacts/mini-alias"
            result = self.packager.build_bundle(
                "customer", output=output, repository_root=repository,
                mini="mini-alias.txt", installer_path=INSTALLER_PATH,
                load_script_path=LOAD_PATH,
            )
            metadata = json.loads(result.metadata.read_text(encoding="ascii"))
            self.assertIn("04-air-mini-devices.txt", metadata["inputs"])
            self.assertNotIn("mini-alias.txt", metadata["inputs"])

    def test_apps_and_firmware_are_included_only_when_explicit(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository, _project = prepare_repository(Path(temporary))
            apps = add_apps(repository)
            firmware = repository / "firmware/card/fw.bin"
            firmware.parent.mkdir(parents=True)
            firmware.write_bytes(b"firmware-payload")
            output = repository / "outputs/artifacts/offline"
            result = self.packager.build_bundle(
                "customer", output=output, repository_root=repository,
                no_upgrade=True, apps_platforms=("ubuntu-24.04/amd64",),
                firmware=(Path("firmware/card/fw.bin"),),
                installer_path=INSTALLER_PATH, load_script_path=LOAD_PATH,
            )
            metadata = json.loads(result.metadata.read_text(encoding="ascii"))
            targets = {item["target"] for item in metadata["artifacts"]}
            expected_apps = {
                path.relative_to(repository).as_posix()
                for path in apps.rglob("*") if path.is_file()
            }
            self.assertTrue(expected_apps <= targets)
            self.assertIn("firmware/card/fw.bin", targets)
            self.assertFalse(any(target.startswith("image/") for target in targets))

    def test_apps_reject_incomplete_index_and_undeclared_regular_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository, _project = prepare_repository(Path(temporary))
            apps = add_apps(repository)
            packages = (apps / "Packages").read_text(encoding="ascii")
            first = sorted(REQUIRED_APT_PACKAGES)[0]
            filtered = "\n\n".join(
                stanza for stanza in packages.strip().split("\n\n")
                if not stanza.startswith(f"Package: {first}\n")
            ) + "\n\n"
            (apps / "Packages").write_text(filtered, encoding="ascii")
            with (apps / "Packages.gz").open("wb") as raw:
                with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as stream:
                    stream.write(filtered.encode("ascii"))
            with self.assertRaisesRegex(self.packager.PackageError, "required|unindexed"):
                self.packager.build_bundle(
                    "customer", output=repository / "outputs/artifacts/incomplete-apps",
                    repository_root=repository, no_upgrade=True,
                    apps_platforms=("ubuntu-24.04/amd64",),
                    installer_path=INSTALLER_PATH, load_script_path=LOAD_PATH,
                )

            # Restore a valid repository, then prove unrelated bytes cannot be
            # smuggled into the explicitly selected apps namespace.
            for item in apps.iterdir():
                item.unlink()
            add_apps(repository)
            (apps / "secret.env").write_text("TOKEN=do-not-package\n", encoding="ascii")
            with self.assertRaisesRegex(self.packager.PackageError, "undeclared"):
                self.packager.build_bundle(
                    "customer", output=repository / "outputs/artifacts/extra-apps",
                    repository_root=repository, no_upgrade=True,
                    apps_platforms=("ubuntu-24.04/amd64",),
                    installer_path=INSTALLER_PATH, load_script_path=LOAD_PATH,
                )

    def test_apps_accept_only_fully_enumerated_internal_hardlink_aliases(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository, _project = prepare_repository(Path(temporary))
            apps = add_apps(repository)
            alias_root = repository / "apps/ubuntu-24.04/arm64"
            alias_root.mkdir(parents=True)
            package = next(path for path in apps.glob("*.deb"))
            os.link(package, alias_root / package.name)
            result = self.packager.build_bundle(
                "customer", output=repository / "outputs/artifacts/internal-links",
                repository_root=repository, no_upgrade=True,
                apps_platforms=("ubuntu-24.04/amd64",),
                installer_path=INSTALLER_PATH, load_script_path=LOAD_PATH,
            )
            with tarfile.open(result.archive, "r:gz") as archive:
                member = archive.getmember(
                    "payload/" + package.relative_to(repository).as_posix(),
                )
                self.assertTrue(member.isfile())
                self.assertFalse(member.islnk())

            outside = Path(temporary) / "outside-alias.deb"
            os.link(package, outside)
            with self.assertRaisesRegex(self.packager.PackageError, "hardlink alias"):
                self.packager.build_bundle(
                    "customer", output=repository / "outputs/artifacts/external-link",
                    repository_root=repository, no_upgrade=True,
                    apps_platforms=("ubuntu-24.04/amd64",),
                    installer_path=INSTALLER_PATH, load_script_path=LOAD_PATH,
                )

    def test_hardlinked_selected_image_fails_before_output_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository, _project = prepare_repository(Path(temporary))
            images = add_switch_images(repository)
            os.link(images["eth"], repository / "image/extra-hardlink.bin")
            output = repository / "outputs/artifacts/unsafe"
            with self.assertRaisesRegex(
                self.packager.PackageError, "single-link",
            ):
                self.packager.build_bundle(
                    "customer", output=output, repository_root=repository,
                    deployment_scope="air", installer_path=INSTALLER_PATH,
                    load_script_path=LOAD_PATH,
                )
            self.assertFalse(output.exists())

    def test_production_image_gate_rejects_unexpected_nonempty_project_bin(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository, project = prepare_repository(Path(temporary))
            add_switch_images(repository)
            (project / "wrong-version.bin").write_bytes(image_payload(b"wrong"))
            output = repository / "outputs/artifacts/unexpected"
            with self.assertRaisesRegex(
                self.packager.PackageError, "wrong-version.bin",
            ):
                self.packager.build_bundle(
                    "customer", output=output, repository_root=repository,
                    deployment_scope="air", installer_path=INSTALLER_PATH,
                    load_script_path=LOAD_PATH,
                )
            self.assertFalse(output.exists())

    def test_firmware_and_image_source_roots_cannot_escape_via_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            repository, _project = prepare_repository(base)
            outside = base / "outside"
            outside.mkdir()
            (outside / "secret.bin").write_bytes(b"secret")
            (repository / "firmware/link").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(self.packager.PackageError, "ancestor"):
                self.packager.build_bundle(
                    "customer", output=repository / "outputs/artifacts/fw-escape",
                    repository_root=repository, no_upgrade=True,
                    firmware=(Path("firmware/link/secret.bin"),),
                    installer_path=INSTALLER_PATH, load_script_path=LOAD_PATH,
                )

            (repository / "image").rmdir()
            (repository / "image").symlink_to(outside, target_is_directory=True)
            (outside / "cumulus-linux-5.18.1-mlx-amd64.bin").write_bytes(
                image_payload(b"outside"),
            )
            with self.assertRaisesRegex(self.packager.PackageError, "source root"):
                self.packager.build_bundle(
                    "customer", output=repository / "outputs/artifacts/image-escape",
                    repository_root=repository, deployment_scope="air",
                    installer_path=INSTALLER_PATH, load_script_path=LOAD_PATH,
                )


class InstallerDirectTests(unittest.TestCase):
    def setUp(self):
        self.packager = load_script(PACKAGER_PATH, "shared_artifact_packager_installer")
        self.installer = load_script(INSTALLER_PATH, "shared_artifact_installer_contract")

    def make_bundle(self, directory: Path):
        repository, _project = prepare_repository(directory)
        add_switch_images(repository)
        output = repository / "outputs/artifacts/bundle"
        result = self.packager.build_bundle(
            "customer", output=output, repository_root=repository,
            deployment_scope="air", installer_path=INSTALLER_PATH,
            load_script_path=LOAD_PATH,
        )
        return repository, result

    def test_cli_has_one_archive_and_verify_only_safe_default(self):
        parser = self.installer.parser()
        with self.assertRaises(SystemExit):
            parser.parse_args([])
        args = parser.parse_args(["shared-artifacts.tar.gz"])
        self.assertEqual(Path("shared-artifacts.tar.gz"), args.archive)
        self.assertEqual(Path("/var/www/html"), args.root)
        self.assertFalse(args.verify_only)
        help_text = parser.format_help()
        self.assertNotIn("--force", help_text)
        self.assertNotIn("--skip-verify", help_text)

    def test_verify_only_does_not_touch_live_root_or_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            _repository, bundle = self.make_bundle(base)
            live = base / "live"
            live.mkdir()
            sentinel = live / "sentinel"
            sentinel.write_text("unchanged", encoding="ascii")
            before = (sentinel.stat().st_ino, sha256(sentinel), tuple(live.iterdir()))
            result = self.installer.deploy_archive(
                bundle.archive, root=live, verify_only=True,
                installer_path=bundle.installer,
                metadata_path=bundle.metadata, required_uid=os.getuid(),
            )
            self.assertTrue(result.verify_only)
            after = (sentinel.stat().st_ino, sha256(sentinel), tuple(live.iterdir()))
            self.assertEqual(before, after)
            self.assertFalse((live / ".deployment.lock").exists())

    def test_identical_but_non_readable_live_file_is_not_skipped(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            _repository, bundle = self.make_bundle(base)
            verified = self.installer.verify_bundle(
                bundle.archive, installer_path=bundle.installer,
                metadata_path=bundle.metadata, required_uid=os.getuid(),
            )
            record = verified.artifacts[0]
            live = base / "live"
            destination = live / record.target
            destination.parent.mkdir(parents=True)
            with tarfile.open(bundle.archive, "r:gz") as archive:
                destination.write_bytes(
                    archive.extractfile("payload/" + record.target).read(),
                )
            destination.chmod(0o600)
            with self.assertRaisesRegex(self.installer.InstallError, "mode|unsafe"):
                self.installer.deploy_archive(
                    bundle.archive, root=live, verify_only=False,
                    installer_path=bundle.installer,
                    metadata_path=bundle.metadata, required_uid=os.getuid(),
                    staging_parent=base,
                )

    def test_publish_race_never_replaces_a_new_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            source = base / "source"
            destination = base / "destination"
            source.write_bytes(b"verified")
            source.chmod(0o644)

            def inject_conflict():
                destination.write_bytes(b"sentinel")

            with mock.patch.object(
                self.installer, "_TEST_BEFORE_PUBLISH", inject_conflict,
                create=True,
            ):
                with self.assertRaisesRegex(self.installer.InstallError, "changed|exists"):
                    self.installer._publish_link(source, destination)
            self.assertEqual(b"sentinel", destination.read_bytes())
            self.assertEqual(b"verified", source.read_bytes())

    def test_live_root_swap_cannot_redirect_artifacts_or_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            _repository, bundle = self.make_bundle(base)
            live = base / "live"
            live.mkdir(mode=0o755)
            displaced = base / "displaced-live"
            attacker = base / "attacker-live"
            (attacker / "image").mkdir(parents=True, mode=0o755)
            (attacker / ".shared-artifact-receipts").mkdir(mode=0o755)
            swapped = False

            def swap_live_root():
                nonlocal swapped
                if swapped:
                    return
                swapped = True
                live.rename(displaced)
                live.symlink_to(attacker, target_is_directory=True)

            try:
                with mock.patch.object(
                    self.installer, "_TEST_BEFORE_PUBLISH", swap_live_root,
                    create=True,
                ), self.assertRaisesRegex(
                    self.installer.InstallError, "root.*changed|identity",
                ):
                    self.installer.deploy_archive(
                        bundle.archive, root=live, verify_only=False,
                        installer_path=bundle.installer,
                        metadata_path=bundle.metadata,
                        required_uid=os.getuid(), staging_parent=base,
                    )
                self.assertTrue(swapped, "live-root publish race was not exercised")
                self.assertTrue(live.is_symlink())
                self.assertEqual([], list((attacker / "image").iterdir()))
                self.assertEqual(
                    [], list((attacker / ".shared-artifact-receipts").iterdir()),
                )
                self.assertFalse(any(
                    item.is_file()
                    for namespace in (
                        "image", "apps", "firmware",
                        ".shared-artifact-receipts",
                    )
                    for item in (displaced / namespace).rglob("*")
                    if (displaced / namespace).exists()
                ))
                self.assertFalse(any(base.glob(".http-ztp-shared.*")))
            finally:
                if live.is_symlink():
                    live.unlink()
                if displaced.exists():
                    displaced.rename(live)

    def test_live_child_swap_after_first_publish_fails_and_rolls_back(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            _repository, bundle = self.make_bundle(base)
            live = base / "live"
            live.mkdir(mode=0o755)
            displaced_image = base / "displaced-image"
            calls = 0

            def swap_image_before_receipt():
                nonlocal calls
                calls += 1
                if calls != 2:
                    return
                (live / "image").rename(displaced_image)
                (live / "image").mkdir(mode=0o755)

            with mock.patch.object(
                self.installer, "_TEST_BEFORE_PUBLISH",
                swap_image_before_receipt, create=True,
            ), self.assertRaisesRegex(
                self.installer.InstallError,
                "destination parent|changed|identity",
            ):
                self.installer.deploy_archive(
                    bundle.archive, root=live, verify_only=False,
                    installer_path=bundle.installer,
                    metadata_path=bundle.metadata,
                    required_uid=os.getuid(), staging_parent=base,
                )
            self.assertEqual(2, calls, "child-directory race was not exercised")
            self.assertFalse(any(item.is_file() for item in displaced_image.rglob("*")))
            self.assertFalse(any(item.is_file() for item in (live / "image").rglob("*")))
            receipt_dir = live / ".shared-artifact-receipts"
            self.assertFalse(any(item.is_file() for item in receipt_dir.rglob("*")))
            self.assertFalse(any(base.glob(".http-ztp-shared.*")))

    def test_receipt_publish_cannot_commit_a_mutated_new_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            _repository, bundle = self.make_bundle(base)
            verified = self.installer.verify_bundle(
                bundle.archive, installer_path=bundle.installer,
                metadata_path=bundle.metadata, required_uid=os.getuid(),
            )
            self.assertEqual(1, len(verified.artifacts))
            record = verified.artifacts[0]
            live = base / "live"
            live.mkdir(mode=0o755)
            calls = 0

            def mutate_artifact_before_receipt_publish():
                nonlocal calls
                calls += 1
                if calls != 2:
                    return
                destination = live / record.target
                value = destination.read_bytes()
                self.assertGreater(len(value), 0)
                with destination.open("r+b", buffering=0) as stream:
                    stream.write(bytes([value[0] ^ 1]))
                    os.fsync(stream.fileno())

            with mock.patch.object(
                self.installer, "_TEST_BEFORE_PUBLISH",
                mutate_artifact_before_receipt_publish, create=True,
            ), self.assertRaisesRegex(
                self.installer.InstallError, "hash|content|changed|commit",
            ):
                self.installer.deploy_archive(
                    bundle.archive, root=live, verify_only=False,
                    installer_path=bundle.installer,
                    metadata_path=bundle.metadata,
                    required_uid=os.getuid(), staging_parent=base,
                )
            self.assertEqual(2, calls, "receipt publication hook was not reached")
            self.assertFalse((live / record.target).exists())
            receipt_dir = live / ".shared-artifact-receipts"
            self.assertFalse(any(item.is_file() for item in receipt_dir.rglob("*")))

    def test_mutated_preverified_skipped_artifact_fails_final_commit(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            _repository, bundle = self.make_bundle(base)
            live = base / "live"
            live.mkdir(mode=0o755)
            first = self.installer.deploy_archive(
                bundle.archive, root=live, verify_only=False,
                installer_path=bundle.installer,
                metadata_path=bundle.metadata, required_uid=os.getuid(),
                staging_parent=base,
            )
            self.assertGreater(len(first.installed), 0)
            verified = self.installer.verify_bundle(
                bundle.archive, installer_path=bundle.installer,
                metadata_path=bundle.metadata, required_uid=os.getuid(),
            )
            record = verified.artifacts[0]
            destination = live / record.target
            original_assert = self.installer._assert_publication_state_at
            mutated = []

            def mutate_skipped_then_assert(*args, **kwargs):
                value = destination.read_bytes()
                self.assertGreater(len(value), 0)
                with destination.open("r+b", buffering=0) as stream:
                    stream.write(bytes([value[0] ^ 1]))
                    os.fsync(stream.fileno())
                mutated.append(True)
                return original_assert(*args, **kwargs)

            with mock.patch.object(
                self.installer, "_assert_publication_state_at",
                mutate_skipped_then_assert,
            ), self.assertRaisesRegex(
                self.installer.InstallError, "hash|content|changed|commit",
            ):
                self.installer.deploy_archive(
                    bundle.archive, root=live, verify_only=False,
                    installer_path=bundle.installer,
                    metadata_path=bundle.metadata,
                    required_uid=os.getuid(), staging_parent=base,
                )
            self.assertEqual([True], mutated)

    def test_staging_parent_swap_cannot_redirect_private_payloads(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            _repository, bundle = self.make_bundle(base)
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
                if swapped_name is None and name.startswith(".http-ztp-shared."):
                    swapped_name = name
                    os.rename(parent, displaced)
                    parent.symlink_to(attacker, target_is_directory=True)
                    real_mkdir(attacker / name, 0o700)
                    (attacker / name / "attacker-marker").write_bytes(b"preserve")
                return result

            try:
                with mock.patch.object(
                    self.installer.os, "mkdir",
                    side_effect=swap_after_private_stage_creation,
                ), self.assertRaisesRegex(
                    self.installer.InstallError, "parent.*changed|identity",
                ):
                    self.installer.deploy_archive(
                        bundle.archive, root=live, verify_only=False,
                        installer_path=bundle.installer,
                        metadata_path=bundle.metadata, required_uid=os.getuid(),
                        staging_parent=parent,
                )
                self.assertIsNotNone(swapped_name, "private stage race was not exercised")
                attacker_stage = attacker / swapped_name
                self.assertTrue(
                    attacker_stage.is_dir(),
                    "installer recursively removed the parent-swap replacement",
                )
                self.assertEqual(
                    ["attacker-marker"],
                    sorted(item.name for item in attacker_stage.iterdir()),
                )
                self.assertEqual(b"preserve", (attacker_stage / "attacker-marker").read_bytes())
                self.assertFalse(any(
                    item.name.startswith(".http-ztp-shared.")
                    for item in displaced.iterdir()
                ))
                self.assertFalse((live / "image").exists())
            finally:
                if parent.is_symlink():
                    parent.unlink()
                if displaced.exists():
                    os.rename(displaced, parent)

    def test_staging_cleanup_is_bound_to_the_opened_directory_inode(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            _repository, bundle = self.make_bundle(base)
            live = base / "live"
            live.mkdir()
            parent = base / "private-parent"
            parent.mkdir(mode=0o700)
            moved_stage = base / "moved-private-stage"
            real_fsync = os.fsync
            original_stage = None

            def replace_stage_after_first_payload_sync(descriptor):
                nonlocal original_stage
                real_fsync(descriptor)
                if original_stage is not None:
                    return
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode):
                    return
                stages = [
                    item for item in parent.iterdir()
                    if item.name.startswith(".http-ztp-shared.")
                ]
                if len(stages) != 1:
                    return
                original_stage = stages[0]
                os.rename(original_stage, moved_stage)
                original_stage.mkdir(mode=0o700)
                (original_stage / "attacker-marker").write_bytes(b"preserve")

            with mock.patch.object(
                self.installer.os, "fsync",
                side_effect=replace_stage_after_first_payload_sync,
            ), self.assertRaisesRegex(
                self.installer.InstallError, "staging.*identity|identity.*staging",
            ):
                self.installer.deploy_archive(
                    bundle.archive, root=live, verify_only=False,
                    installer_path=bundle.installer,
                    metadata_path=bundle.metadata, required_uid=os.getuid(),
                    staging_parent=parent,
                )
            self.assertIsNotNone(original_stage, "staging replacement was not exercised")
            self.assertEqual(
                ["attacker-marker"],
                sorted(item.name for item in original_stage.iterdir()),
            )
            self.assertEqual(b"preserve", (original_stage / "attacker-marker").read_bytes())
            self.assertFalse(
                any(item.is_file() for item in moved_stage.rglob("*")),
                "verified payload bytes remained in the displaced staging inode",
            )
            self.assertFalse((live / "image").exists())

    def test_tampered_external_installer_or_metadata_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            _repository, bundle = self.make_bundle(base)
            copied_installer = base / "installer.py"
            copied_installer.write_bytes(bundle.installer.read_bytes() + b"\n# changed\n")
            with self.assertRaisesRegex(self.installer.InstallError, "installer"):
                self.installer.verify_bundle(
                    bundle.archive, installer_path=copied_installer,
                    metadata_path=bundle.metadata, required_uid=os.getuid(),
                )
            copied_metadata = base / "metadata.json"
            copied_metadata.write_bytes(bundle.metadata.read_bytes() + b" ")
            with self.assertRaisesRegex(self.installer.InstallError, "metadata"):
                self.installer.verify_bundle(
                    bundle.archive, installer_path=bundle.installer,
                    metadata_path=copied_metadata, required_uid=os.getuid(),
                )

    def test_hardlinked_archive_and_escaping_metadata_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            _repository, bundle = self.make_bundle(base)
            alias = base / "archive-alias.tar.gz"
            os.link(bundle.archive, alias)
            with self.assertRaisesRegex(self.installer.InstallError, "single-link"):
                self.installer.verify_bundle(
                    bundle.archive, installer_path=bundle.installer,
                    metadata_path=bundle.metadata, required_uid=os.getuid(),
                )
            alias.unlink()

            rewrite_bundle_metadata(
                bundle,
                lambda value: value["artifacts"][0].update({
                    "source": "../../escape", "target": "../../escape",
                }),
            )
            with self.assertRaisesRegex(self.installer.InstallError, "path"):
                self.installer.verify_bundle(
                    bundle.archive, installer_path=bundle.installer,
                    metadata_path=bundle.metadata, required_uid=os.getuid(),
                )

    def test_selection_and_consumer_metadata_cannot_claim_impossible_scope(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            _repository, bundle = self.make_bundle(base)
            rewrite_bundle_metadata(
                bundle, lambda value: value.update({"switch_scope": "ib"}),
            )
            with self.assertRaisesRegex(self.installer.InstallError, "AIR"):
                self.installer.verify_bundle(
                    bundle.archive, installer_path=bundle.installer,
                    metadata_path=bundle.metadata, required_uid=os.getuid(),
                )

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            _repository, bundle = self.make_bundle(base)

            def mismatch(value):
                value["deployment_scope"] = "prod"
                value["switch_scope"] = "all"
                value["artifacts"][0]["consumers"] = [
                    {"family": "ib", "version": "25.03.1010"},
                ]

            rewrite_bundle_metadata(bundle, mismatch)
            with self.assertRaisesRegex(self.installer.InstallError, "filename"):
                self.installer.verify_bundle(
                    bundle.archive, installer_path=bundle.installer,
                    metadata_path=bundle.metadata, required_uid=os.getuid(),
                )

    def test_directory_member_with_payload_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            _repository, bundle = self.make_bundle(base)
            captured = []
            with tarfile.open(bundle.archive, "r:gz") as archive:
                for member in archive.getmembers():
                    payload = archive.extractfile(member).read() if member.isfile() else None
                    captured.append((member, payload))
            replacement = base / "directory-body.tar.gz"
            changed = False
            with tarfile.open(replacement, "w:gz") as archive:
                for original, payload in captured:
                    info = tarfile.TarInfo(original.name)
                    info.uid = info.gid = 0
                    info.mode = original.mode
                    info.mtime = 0
                    if original.isdir():
                        info.type = tarfile.DIRTYPE
                        if not changed:
                            changed = True
                            info.size = 1
                            archive.addfile(info, io.BytesIO(b"x"))
                        else:
                            archive.addfile(info)
                    else:
                        assert payload is not None
                        info.size = len(payload)
                        archive.addfile(info, io.BytesIO(payload))
            replacement.chmod(0o600)
            with self.assertRaisesRegex(self.installer.InstallError, "directory metadata"):
                self.installer.verify_bundle(
                    replacement, installer_path=bundle.installer,
                    metadata_path=bundle.metadata, required_uid=os.getuid(),
                )

    def test_duplicate_json_authority_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            _repository, bundle = self.make_bundle(base)
            metadata = bundle.metadata.read_bytes().replace(
                b'  "schema_version": 1,\n',
                b'  "schema_version": 1,\n  "schema_version": true,\n',
                1,
            )
            rewrite_bundle_metadata_bytes(bundle, metadata)
            with self.assertRaisesRegex(self.installer.InstallError, "repeats JSON key"):
                self.installer.verify_bundle(
                    bundle.archive, installer_path=bundle.installer,
                    metadata_path=bundle.metadata, required_uid=os.getuid(),
                )

    def test_self_consistent_but_invalid_apt_payload_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            repository, _project = prepare_repository(base)
            add_apps(repository)
            bundle = self.packager.build_bundle(
                "customer", output=repository / "outputs/artifacts/apps",
                repository_root=repository, no_upgrade=True,
                apps_platforms=("ubuntu-24.04/amd64",),
                installer_path=INSTALLER_PATH, load_script_path=LOAD_PATH,
            )
            target = "apps/ubuntu-24.04/amd64/Packages"
            rewrite_bundle_payload(bundle, target, b"invalid-index\n")
            with self.assertRaisesRegex(
                self.installer.InstallError, "Packages and Packages.gz differ",
            ):
                self.installer.verify_bundle(
                    bundle.archive, installer_path=bundle.installer,
                    metadata_path=bundle.metadata, required_uid=os.getuid(),
                )

class SharedArtifactWorkflowTests(unittest.TestCase):
    """Crosses the real packager and installer rather than mocking either one."""

    def setUp(self):
        self.packager = load_script(PACKAGER_PATH, "shared_artifact_packager_workflow")
        self.installer = load_script(INSTALLER_PATH, "shared_artifact_installer_workflow")
        self.load = load_script(LOAD_PATH, "shared_artifact_load_workflow")

    def test_installed_receipt_is_consumed_by_the_real_load_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            repository, project = prepare_repository(base)
            images = add_switch_images(repository)
            bundle = self.packager.build_bundle(
                "customer", output=repository / "outputs/artifacts/load-gate",
                repository_root=repository, deployment_scope="air",
                installer_path=INSTALLER_PATH, load_script_path=LOAD_PATH,
            )
            live = base / "live"
            live.mkdir(mode=0o755)
            installed = self.installer.deploy_archive(
                bundle.archive, root=live, verify_only=False,
                installer_path=bundle.installer,
                metadata_path=bundle.metadata, required_uid=os.getuid(),
                staging_parent=base,
            )
            settings = self.load.load_global(project / "01-global.yaml")
            inputs = self.load.ProjectInputs(
                global_file=project / "01-global.yaml",
                devices_file=project / "02-devices_config.csv",
                subnet_file=project / "02-dhcp-subnet_config.csv",
                p2p_file=project / "p2p.xlsx",
                device_types=frozenset({"eth", "air"}),
                pubkeys=(), settings=settings,
                deployment_scope="air", switch_scope="eth",
            )
            selected = live / "image" / images["eth"].name
            self.assertEqual(
                installed.receipt,
                self.load.validate_shared_artifact_receipts(
                    project, inputs, {"eth": selected},
                    upgrade_enabled=True, root=live,
                ),
            )

            original_global = (project / "01-global.yaml").read_bytes()
            (project / "01-global.yaml").write_bytes(
                original_global + b"# input drift after artifact selection\n"
            )
            with self.assertRaisesRegex(
                self.load.LoadError, "共享制品 receipt.*不一致",
            ):
                self.load.validate_shared_artifact_receipts(
                    project, inputs, {"eth": selected},
                    upgrade_enabled=True, root=live,
                )
            (project / "01-global.yaml").write_bytes(original_global)

            selected.write_bytes(selected.read_bytes() + b"tampered")
            selected.chmod(0o644)
            with self.assertRaisesRegex(
                self.load.LoadError, "共享制品.*(hash|大小|不一致)",
            ):
                self.load.validate_shared_artifact_receipts(
                    project, inputs, {"eth": selected},
                    upgrade_enabled=True, root=live,
                )

    def test_package_verify_install_idempotent_and_conflict_safe(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            repository, _project = prepare_repository(base)
            images = add_switch_images(repository)
            apps = add_apps(repository)
            shared_package = next(path for path in apps.glob("*.deb"))
            alias_root = repository / "apps/ubuntu-24.04/arm64"
            alias_root.mkdir(parents=True)
            os.link(shared_package, alias_root / shared_package.name)
            firmware = repository / "firmware/card/fw.bin"
            firmware.parent.mkdir(parents=True)
            firmware.write_bytes(b"firmware-payload")
            bundle = self.packager.build_bundle(
                "customer", output=repository / "outputs/artifacts/full",
                repository_root=repository, deployment_scope="air",
                apps_platforms=("ubuntu-24.04/amd64",),
                firmware=(Path("firmware/card/fw.bin"),),
                installer_path=INSTALLER_PATH, load_script_path=LOAD_PATH,
            )
            live = base / "live"
            live.mkdir()
            unrelated = live / "image/unrelated.bin"
            unrelated.parent.mkdir()
            unrelated.write_bytes(b"keep")

            first = self.installer.deploy_archive(
                bundle.archive, root=live, verify_only=False,
                installer_path=bundle.installer,
                metadata_path=bundle.metadata, required_uid=os.getuid(),
                staging_parent=base,
            )
            expected_image = live / "image" / images["eth"].name
            self.assertEqual(sha256(images["eth"]), sha256(expected_image))
            self.assertTrue((live / "apps/ubuntu-24.04/amd64/Packages.gz").is_file())
            installed_shared = live / shared_package.relative_to(repository)
            self.assertEqual(1, installed_shared.stat().st_nlink)
            self.assertEqual(sha256(shared_package), sha256(installed_shared))
            self.assertEqual(b"firmware-payload", (live / "firmware/card/fw.bin").read_bytes())
            self.assertEqual(b"keep", unrelated.read_bytes())
            self.assertTrue(first.receipt.is_file())
            self.assertGreater(len(first.installed), 0)
            receipt = json.loads(first.receipt.read_text(encoding="ascii"))
            self.assertEqual("air", receipt["selection"]["deployment_scope"])
            self.assertEqual("eth", receipt["selection"]["switch_scope"])
            self.assertEqual("enabled", receipt["selection"]["upgrade_policy"])
            self.assertEqual(
                {"01-global.yaml", "02-devices_config.csv"},
                set(receipt["selection"]["inputs"]),
            )
            switch_records = [
                item for item in receipt["artifacts"]
                if item["kind"] == "switch-image"
            ]
            self.assertEqual(
                [[{"family": "eth", "version": "5.18.1"}]],
                [item["consumers"] for item in switch_records],
            )

            second = self.installer.deploy_archive(
                bundle.archive, root=live, verify_only=False,
                installer_path=bundle.installer,
                metadata_path=bundle.metadata, required_uid=os.getuid(),
                staging_parent=base,
            )
            self.assertEqual((), second.installed)
            self.assertEqual(
                {item.target for item in bundle.artifacts}, set(second.skipped),
            )

            expected_image.write_bytes(b"different-safe-file")
            sibling_before = (live / "firmware/card/fw.bin").read_bytes()
            with self.assertRaisesRegex(self.installer.InstallError, "conflict"):
                self.installer.deploy_archive(
                    bundle.archive, root=live, verify_only=False,
                    installer_path=bundle.installer,
                    metadata_path=bundle.metadata, required_uid=os.getuid(),
                    staging_parent=base,
                )
            self.assertEqual(b"different-safe-file", expected_image.read_bytes())
            self.assertEqual(sibling_before, (live / "firmware/card/fw.bin").read_bytes())
            self.assertEqual(b"keep", unrelated.read_bytes())

    def test_archive_contains_only_declared_regular_payloads(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            repository, _project = prepare_repository(base)
            add_switch_images(repository)
            bundle = self.packager.build_bundle(
                "customer", output=repository / "outputs/artifacts/bundle",
                repository_root=repository, deployment_scope="air",
                installer_path=INSTALLER_PATH, load_script_path=LOAD_PATH,
            )
            metadata = json.loads(bundle.metadata.read_text(encoding="ascii"))
            declared = {"payload/" + item["target"] for item in metadata["artifacts"]}
            with tarfile.open(bundle.archive, "r:gz") as archive:
                files = {item.name for item in archive.getmembers() if item.isfile()}
                self.assertEqual(
                    {"artifact-metadata.json", "deploy-shared-artifacts.py"} | declared,
                    files,
                )
                self.assertTrue(all(item.isfile() or item.isdir() for item in archive.getmembers()))

    def test_publish_failure_rolls_back_only_new_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            repository, _project = prepare_repository(base)
            add_switch_images(repository)
            firmware = repository / "firmware/card/fw.bin"
            firmware.parent.mkdir(parents=True)
            firmware.write_bytes(b"firmware-payload")
            bundle = self.packager.build_bundle(
                "customer", output=repository / "outputs/artifacts/rollback",
                repository_root=repository, deployment_scope="air",
                firmware=(Path("firmware/card/fw.bin"),),
                installer_path=INSTALLER_PATH, load_script_path=LOAD_PATH,
            )
            live = base / "live"
            live.mkdir()
            real_publish = self.installer._publish_staged_link
            calls = 0

            def fail_second(*args, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise self.installer.InstallError("injected publish failure")
                return real_publish(*args, **kwargs)

            with mock.patch.object(
                self.installer, "_publish_staged_link", side_effect=fail_second,
            ):
                with self.assertRaisesRegex(self.installer.InstallError, "injected"):
                    self.installer.deploy_archive(
                        bundle.archive, root=live, verify_only=False,
                        installer_path=bundle.installer,
                        metadata_path=bundle.metadata, required_uid=os.getuid(),
                        staging_parent=base,
                    )
            self.assertFalse((live / "image").exists())
            self.assertFalse((live / "firmware").exists())
            self.assertFalse((live / ".shared-artifact-receipts").exists())
            self.assertFalse(any(base.glob(".http-ztp-shared.*")))


if __name__ == "__main__":
    unittest.main()
