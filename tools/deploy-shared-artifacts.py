#!/usr/bin/env python3
"""Verify and atomically install one independent shared-artifact bundle."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
from dataclasses import dataclass
import errno
import fcntl
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import sys
import tarfile
from typing import Iterator, Optional, Sequence


INSTALLER_NAME = "deploy-shared-artifacts.py"
METADATA_NAME = "artifact-metadata.json"
PAYLOAD_PREFIX = "payload"
RECEIPT_DIRECTORY = ".shared-artifact-receipts"
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024 * 1024
MAX_MEMBER_BYTES = 16 * 1024 * 1024 * 1024
MAX_EXPANDED_BYTES = 64 * 1024 * 1024 * 1024
MAX_CONTROL_BYTES = 64 * 1024 * 1024
MAX_MEMBER_COUNT = 10_000
MAX_MEMBER_NAME_BYTES = 1024
MAX_PAX_BYTES = 16 * 1024
ALLOWED_TARGET_ROOTS = frozenset({"image", "apps", "firmware"})
VALID_KINDS = frozenset({"switch-image", "apps", "firmware"})
VALID_APPS_PLATFORMS = frozenset({
    "ubuntu-22.04/amd64", "ubuntu-22.04/arm64",
    "ubuntu-24.04/amd64", "ubuntu-24.04/arm64",
})
REQUIRED_OFFLINE_PACKAGES = frozenset({
    "wget", "lldpd", "tzdata", "ipmitool", "sshpass", "docker.io",
    "unzip", "nfs-common", "arping", "python3", "python3-yaml",
    "python3-jinja2", "python3-openpyxl", "python3-pandas",
    "python3-xlsxwriter", "openssh-client", "curl", "apache2",
    "ssl-cert", "isc-dhcp-server", "jq",
})
HEX = frozenset("0123456789abcdef")


class InstallError(RuntimeError):
    """The artifact bundle or live destination is unsafe or incompatible."""


@dataclass(frozen=True)
class ArtifactRecord:
    target: str
    kind: str
    size: int
    sha256: str
    mode: int
    consumers: tuple[tuple[str, str], ...]
    platform: Optional[str]
    member: tarfile.TarInfo


@dataclass(frozen=True)
class Verification:
    archive: Path
    archive_size: int
    archive_sha256: str
    metadata_sha256: str
    project: str
    artifacts: tuple[ArtifactRecord, ...]
    metadata_bytes: bytes
    metadata: dict[str, object]


@dataclass(frozen=True)
class DeployResult:
    verify_only: bool
    archive_sha256: str
    metadata_sha256: str
    project: str
    installed: tuple[str, ...]
    skipped: tuple[str, ...]
    receipt: Path


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description=(
            "Verify and install one shared-artifact archive into only the "
            "image/, apps/, and firmware/ namespaces."
        ),
        allow_abbrev=False,
    )
    result.add_argument("archive", type=Path, metavar="ARCHIVE")
    result.add_argument("--root", type=Path, default=Path("/var/www/html"))
    result.add_argument("--verify-only", action="store_true")
    return result


def _absolute_unresolved(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _stable_fields(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev, value.st_ino, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    )


@contextmanager
def _open_stable_regular(
    path: Path, label: str, *, required_uid: int, maximum_size: int,
    allow_empty: bool = False,
) -> Iterator[tuple[int, os.stat_result]]:
    path = _absolute_unresolved(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        before = path.lstat()
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or before.st_nlink != 1
            or opened.st_nlink != 1
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
            or opened.st_uid != required_uid
            or opened.st_mode & 0o022
        ):
            raise InstallError(
                f"{label} must be an owner-controlled NOFOLLOW single-link regular file"
            )
        if (not allow_empty and opened.st_size == 0) or opened.st_size > maximum_size:
            raise InstallError(f"{label} has an unsafe size: {opened.st_size}")
        yield descriptor, opened
        after = os.fstat(descriptor)
        current = path.lstat()
        if _stable_fields(after) != _stable_fields(opened):
            raise InstallError(f"{label} changed while being read")
        if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
            raise InstallError(f"{label} path changed while being read")
    except InstallError:
        raise
    except OSError as exc:
        raise InstallError(f"cannot safely open {label}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _hash_descriptor(descriptor: int, size: int, label: str) -> str:
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    remaining = size
    while remaining:
        block = os.read(descriptor, min(remaining, 4 * 1024 * 1024))
        if not block:
            raise InstallError(f"{label} was truncated while hashing")
        digest.update(block)
        remaining -= len(block)
    if os.read(descriptor, 1):
        raise InstallError(f"{label} grew while hashing")
    return digest.hexdigest()


def _read_descriptor(descriptor: int, size: int, label: str) -> bytes:
    if size > MAX_CONTROL_BYTES:
        raise InstallError(f"{label} exceeds its control-file bound")
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        block = os.read(descriptor, min(remaining, 1024 * 1024))
        if not block:
            raise InstallError(f"{label} was truncated while reading")
        chunks.append(block)
        remaining -= len(block)
    if os.read(descriptor, 1):
        raise InstallError(f"{label} grew while reading")
    try:
        return b"".join(chunks)
    except (MemoryError, OverflowError) as exc:
        raise InstallError(f"cannot read {label} within its memory bound") from exc


def _safe_parts(name: str, label: str) -> tuple[str, ...]:
    if not name or "\\" in name or any(ord(character) < 32 or ord(character) == 127 for character in name):
        raise InstallError(f"{label} has an unsafe path: {name!r}")
    path = PurePosixPath(name)
    parts = tuple(path.parts)
    if (
        path.is_absolute() or not parts
        or any(part in {"", ".", ".."} for part in parts)
        or "/".join(parts) != name
    ):
        raise InstallError(f"{label} has a non-canonical path: {name!r}")
    return parts


def _valid_sha(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(item in HEX for item in value)


def _extract_small(archive: tarfile.TarFile, member: tarfile.TarInfo, label: str) -> bytes:
    if not member.isfile() or member.size <= 0 or member.size > MAX_CONTROL_BYTES:
        raise InstallError(f"{label} must be one non-empty bounded regular member")
    stream = archive.extractfile(member)
    if stream is None:
        raise InstallError(f"{label} is unreadable")
    try:
        payload = stream.read(member.size + 1)
    except (MemoryError, OverflowError) as exc:
        raise InstallError(f"cannot read {label} within its memory bound") from exc
    if len(payload) != member.size:
        raise InstallError(f"{label} size changed while reading")
    return payload


def _hash_member(archive: tarfile.TarFile, member: tarfile.TarInfo, label: str) -> str:
    if not member.isfile() or member.size <= 0 or member.size > MAX_MEMBER_BYTES:
        raise InstallError(f"{label} must be one non-empty bounded regular member")
    stream = archive.extractfile(member)
    if stream is None:
        raise InstallError(f"{label} is unreadable")
    digest = hashlib.sha256()
    remaining = member.size
    while remaining:
        try:
            block = stream.read(min(remaining, 1024 * 1024))
        except (MemoryError, OverflowError) as exc:
            raise InstallError(f"cannot hash {label} within its memory bound") from exc
        if not block:
            raise InstallError(f"{label} was truncated while hashing")
        if len(block) > remaining:
            raise InstallError(f"{label} exceeds its declared size")
        digest.update(block)
        remaining -= len(block)
    if stream.read(1):
        raise InstallError(f"{label} exceeds its declared size")
    return digest.hexdigest()


def _reject_duplicate_json_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise InstallError(f"artifact metadata repeats JSON key: {key}")
        value[key] = item
    return value


def _parse_metadata(
    payload: bytes,
) -> tuple[dict[str, object], tuple[dict[str, object], ...]]:
    try:
        value = json.loads(
            payload.decode("ascii"), object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise InstallError(f"artifact metadata is invalid: {exc}") from exc
    expected_keys = {
        "artifact_type", "artifacts", "deployment_scope", "inputs", "installer",
        "mini", "mini_input", "project", "schema_version", "switch_scope",
        "upgrade_policy",
    }
    if (
        not isinstance(value, dict) or set(value) != expected_keys
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or value.get("artifact_type") != "http-ztp-shared-artifacts"
        or value.get("deployment_scope") not in {"all", "prod", "air"}
        or value.get("switch_scope") not in {"all", "eth", "ib", "nvl"}
        or value.get("upgrade_policy") not in {"enabled", "disabled"}
        or not isinstance(value.get("mini"), bool)
        or value.get("mini_input") is not None
        and not isinstance(value.get("mini_input"), str)
        or not isinstance(value.get("project"), str)
        or not value["project"]
        or any(ord(character) < 32 or ord(character) == 127 for character in value["project"])
        or "/" in value["project"] or "\\" in value["project"]
        or not isinstance(value.get("artifacts"), list)
        or not value["artifacts"]
        or not isinstance(value.get("inputs"), dict)
        or not isinstance(value.get("installer"), dict)
    ):
        raise InstallError("artifact metadata schema is invalid")
    installer = value["installer"]
    if (
        set(installer) != {"name", "sha256", "size"}
        or installer.get("name") != INSTALLER_NAME
        or not _valid_sha(installer.get("sha256"))
        or type(installer.get("size")) is not int
        or installer["size"] <= 0
    ):
        raise InstallError("artifact metadata installer identity is invalid")
    for name, identity in value["inputs"].items():
        if (
            not isinstance(name, str) or not name
            or "/" in name or "\\" in name
            or any(ord(character) < 32 or ord(character) == 127 for character in name)
            or not isinstance(identity, dict)
            or set(identity) != {"sha256", "size"}
            or not _valid_sha(identity.get("sha256"))
            or type(identity.get("size")) is not int
            or identity["size"] <= 0
        ):
            raise InstallError("artifact metadata input identity is invalid")
    base_inputs = {"01-global.yaml", "02-devices_config.csv"}
    if value["mini"]:
        mini_input = value["mini_input"]
        if (
            value["deployment_scope"] != "air"
            or value["switch_scope"] != "eth"
            or not isinstance(mini_input, str)
            or not mini_input or "/" in mini_input or "\\" in mini_input
            or set(value["inputs"]) != base_inputs | {mini_input}
        ):
            raise InstallError("mini artifact selection metadata is inconsistent")
    elif value["mini_input"] is not None or set(value["inputs"]) != base_inputs:
        raise InstallError("artifact input identity set is inconsistent")
    if value["deployment_scope"] == "air" and value["switch_scope"] != "eth":
        raise InstallError("AIR artifact selection must use the eth switch scope")
    return value, tuple(value["artifacts"])


def _artifact_records(
    metadata: dict[str, object], members: dict[str, tarfile.TarInfo],
) -> tuple[ArtifactRecord, ...]:
    records: list[ArtifactRecord] = []
    seen: set[str] = set()
    expected_fields = {
        "consumers", "kind", "mode", "platform", "sha256",
        "size", "source", "target",
    }
    for raw in metadata["artifacts"]:
        if (
            not isinstance(raw, dict) or set(raw) != expected_fields
            or raw.get("kind") not in VALID_KINDS
            or not isinstance(raw.get("target"), str)
            or raw.get("source") != raw.get("target")
            or raw["target"] in seen
            or type(raw.get("size")) is not int or raw["size"] <= 0
            or raw["size"] > MAX_MEMBER_BYTES
            or not _valid_sha(raw.get("sha256"))
            or raw.get("mode") != 0o644
        ):
            raise InstallError("artifact metadata contains an invalid or duplicate record")
        parts = _safe_parts(raw["target"], "artifact target")
        if parts[0] not in ALLOWED_TARGET_ROOTS:
            raise InstallError(f"artifact target namespace is forbidden: {raw['target']}")
        kind = raw["kind"]
        consumers_raw = raw.get("consumers")
        if not isinstance(consumers_raw, list):
            raise InstallError("artifact consumers must be one list")
        consumers: list[tuple[str, str]] = []
        for consumer in consumers_raw:
            if (
                not isinstance(consumer, dict)
                or set(consumer) != {"family", "version"}
                or consumer.get("family") not in {"eth", "ib", "nvl"}
                or not isinstance(consumer.get("version"), str)
                or not consumer["version"]
            ):
                raise InstallError("switch artifact consumer metadata is invalid")
            consumers.append((consumer["family"], consumer["version"]))
        if consumers != sorted(set(consumers)):
            raise InstallError("artifact consumers must be sorted and unique")
        if kind == "switch-image":
            if (
                parts[0] != "image" or len(parts) != 2
                or not consumers
                or raw.get("platform") is not None
            ):
                raise InstallError("switch-image artifact metadata is invalid")
            for family, version in consumers:
                normalized = version.replace(".", "-")
                if not re.fullmatch(r"[0-9]+-[0-9]+-[0-9]+", normalized):
                    raise InstallError("switch artifact version is invalid")
                accepted = (
                    {f"cumulus-linux-{version}-mlx-amd64.bin"}
                    if family == "eth" else {
                        f"nvosv{normalized}amd64.bin",
                        f"nvos-amd64-{normalized.replace('-', '.')}.bin",
                    }
                )
                if parts[1] not in accepted:
                    raise InstallError("switch artifact filename does not match its consumer")
        elif kind == "apps":
            platform = raw.get("platform")
            if (
                parts[0] != "apps" or len(parts) < 4
                or platform not in VALID_APPS_PLATFORMS
                or "/".join(parts[1:3]) != platform
                or consumers
            ):
                raise InstallError("apps artifact metadata is invalid")
        else:
            if (
                parts[0] != "firmware" or len(parts) < 2
                or consumers
                or raw.get("platform") is not None
            ):
                raise InstallError("firmware artifact metadata is invalid")
        member_name = f"{PAYLOAD_PREFIX}/{raw['target']}"
        member = members.get(member_name)
        if member is None or not member.isfile() or member.size != raw["size"]:
            raise InstallError(f"artifact payload is missing or changed: {raw['target']}")
        seen.add(raw["target"])
        records.append(ArtifactRecord(
            raw["target"], kind, raw["size"], raw["sha256"], raw["mode"],
            tuple(consumers), raw.get("platform"), member,
        ))
    if metadata["upgrade_policy"] == "disabled" and any(
        record.kind == "switch-image" for record in records
    ):
        raise InstallError("upgrade-disabled metadata must not contain switch images")
    seen_families: set[str] = set()
    selected_scope = metadata["switch_scope"]
    allowed_families = (
        {"eth", "ib", "nvl"} if selected_scope == "all" else {selected_scope}
    )
    for record in records:
        for family, _version in record.consumers:
            if family not in allowed_families or family in seen_families:
                raise InstallError("switch artifact consumers conflict with selection scope")
            seen_families.add(family)
    return tuple(sorted(records, key=lambda item: item.target))


def _parse_deb822(payload: bytes, label: str) -> tuple[dict[str, str], ...]:
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise InstallError(f"{label} is not UTF-8: {exc}") from exc
    records: list[dict[str, str]] = []
    for stanza in re.split(r"\n\s*\n", text.strip()):
        if not stanza:
            continue
        record: dict[str, str] = {}
        previous_key: Optional[str] = None
        for line in stanza.splitlines():
            if line[:1].isspace():
                if previous_key is None:
                    raise InstallError(f"{label} contains an orphan continuation line")
                record[previous_key] += "\n" + line
                continue
            key, separator, value = line.partition(":")
            key = key.strip()
            if not separator or not key or key in record:
                raise InstallError(f"{label} contains an invalid or duplicate field")
            previous_key = key
            record[key] = value.strip()
        records.append(record)
    if not records:
        raise InstallError(f"{label} contains no package records")
    return tuple(records)


def _gunzip_bounded(payload: bytes, label: str) -> bytes:
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(payload), mode="rb") as stream:
            expanded = stream.read(MAX_CONTROL_BYTES + 1)
    except (OSError, EOFError, MemoryError, OverflowError) as exc:
        raise InstallError(f"{label} is not a bounded valid gzip stream: {exc}") from exc
    if len(expanded) > MAX_CONTROL_BYTES:
        raise InstallError(f"{label} expands beyond its safety bound")
    return expanded


def _validate_archived_apps(
    archive: tarfile.TarFile, records: tuple[ArtifactRecord, ...],
) -> None:
    by_target = {record.target: record for record in records}
    platforms = sorted({
        record.platform for record in records
        if record.kind == "apps" and record.platform is not None
    })
    for platform in platforms:
        prefix = f"apps/{platform}/"
        required = {
            name: by_target.get(prefix + name)
            for name in ("Packages", "Packages.gz", "repository.meta")
        }
        if any(record is None for record in required.values()):
            raise InstallError(f"apps/{platform} is missing repository authority files")
        packages_record = required["Packages"]
        compressed_record = required["Packages.gz"]
        metadata_record = required["repository.meta"]
        assert packages_record is not None
        assert compressed_record is not None
        assert metadata_record is not None
        packages = _extract_small(
            archive, packages_record.member, f"apps/{platform}/Packages",
        )
        compressed = _extract_small(
            archive, compressed_record.member, f"apps/{platform}/Packages.gz",
        )
        if _gunzip_bounded(compressed, f"apps/{platform}/Packages.gz") != packages:
            raise InstallError(f"apps/{platform} Packages and Packages.gz differ")
        expected_os, expected_arch = platform.split("/", 1)
        expected_metadata = {
            "schema_version": "1", "os_id": "ubuntu",
            "os_version": expected_os.removeprefix("ubuntu-"),
            "architecture": expected_arch,
        }
        try:
            repository_metadata = {}
            for line in _extract_small(
                archive, metadata_record.member,
                f"apps/{platform}/repository.meta",
            ).decode("ascii", errors="strict").splitlines():
                key, separator, value = line.partition("=")
                if separator:
                    repository_metadata[key.strip()] = value.strip()
        except UnicodeError as exc:
            raise InstallError(f"apps/{platform}/repository.meta is not ASCII") from exc
        if any(
            repository_metadata.get(key) != value
            for key, value in expected_metadata.items()
        ):
            raise InstallError(f"apps/{platform}/repository.meta does not match its platform")
        referenced: set[str] = set()
        package_names: set[str] = set()
        for stanza in _parse_deb822(packages, f"apps/{platform}/Packages"):
            package_name = stanza.get("Package", "")
            if not package_name:
                raise InstallError(f"apps/{platform} has a record without Package")
            package_names.add(package_name)
            filename = stanza.get("Filename", "")
            if filename.startswith("./"):
                filename = filename[2:]
            relative = "/".join(_safe_parts(filename, "APT Filename"))
            target = prefix + relative
            if target in referenced:
                raise InstallError(f"apps/{platform} repeats indexed payload {relative}")
            referenced.add(target)
            record = by_target.get(target)
            if record is None or record.kind != "apps":
                raise InstallError(f"apps/{platform} is missing indexed payload {relative}")
            try:
                expected_size = int(stanza.get("Size", ""), 10)
            except ValueError as exc:
                raise InstallError(f"apps/{platform} has invalid Size for {relative}") from exc
            expected_hash = stanza.get("SHA256", "")
            if (
                expected_size != record.size or expected_hash != record.sha256
                or stanza.get("Architecture") not in {expected_arch, "all"}
            ):
                raise InstallError(f"apps/{platform} indexed identity mismatch for {relative}")
        archived_debs = {
            record.target for record in records
            if record.kind == "apps" and record.platform == platform
            and record.target.casefold().endswith(".deb")
        }
        if archived_debs != referenced:
            raise InstallError(f"apps/{platform} contains unindexed package payloads")
        missing_packages = sorted(REQUIRED_OFFLINE_PACKAGES - package_names)
        if missing_packages:
            raise InstallError(
                f"apps/{platform} is missing required offline packages: "
                + ", ".join(missing_packages)
            )
        platform_targets = {
            record.target for record in records
            if record.kind == "apps" and record.platform == platform
        }
        authority_targets = {prefix + name for name in required}
        if platform_targets != authority_targets | referenced:
            raise InstallError(f"apps/{platform} contains undeclared repository files")


def _bounded_members(archive: tarfile.TarFile) -> dict[str, tarfile.TarInfo]:
    """Parse members incrementally so count/expanded limits apply promptly."""
    members: dict[str, tarfile.TarInfo] = {}
    expanded = 0
    while True:
        if len(members) >= MAX_MEMBER_COUNT:
            raise InstallError("artifact archive member count is unsafe")
        member = archive.next()
        if member is None:
            break
        if len(member.name.encode("utf-8", errors="surrogatepass")) > MAX_MEMBER_NAME_BYTES:
            raise InstallError("artifact archive member name is too long")
        if sum(
            len(str(key).encode("utf-8", errors="surrogatepass"))
            + len(str(value).encode("utf-8", errors="surrogatepass"))
            for key, value in member.pax_headers.items()
        ) > MAX_PAX_BYTES:
            raise InstallError(f"archive PAX metadata is too large: {member.name}")
        _safe_parts(member.name, "archive member")
        if member.name in members:
            raise InstallError(f"duplicate archive member: {member.name}")
        if member.mode < 0 or member.mode & ~0o777:
            raise InstallError(f"archive member mode is unsafe: {member.name}")
        if member.isdir():
            if member.mode != 0o755 or member.size != 0:
                raise InstallError(f"archive directory metadata is unsafe: {member.name}")
        elif member.isfile():
            if member.size <= 0 or member.size > MAX_MEMBER_BYTES:
                raise InstallError(f"archive member size is unsafe: {member.name}")
            expanded += member.size
            if expanded > MAX_EXPANDED_BYTES:
                raise InstallError("artifact archive expanded size is unsafe")
        else:
            raise InstallError(f"unsupported archive member type: {member.name}")
        if member.uid != 0 or member.gid != 0:
            raise InstallError(f"archive member owner is unsafe: {member.name}")
        members[member.name] = member
    if not members:
        raise InstallError("artifact archive contains no members")
    return members


def _inspect_archive(
    descriptor: int, archive_path: Path, archive_size: int,
    archive_sha256: str, installer_bytes: bytes, metadata_bytes: bytes,
) -> Verification:
    os.lseek(descriptor, 0, os.SEEK_SET)
    try:
        with os.fdopen(os.dup(descriptor), "rb") as stream, \
                tarfile.open(fileobj=stream, mode="r:gz") as archive:
            members = _bounded_members(archive)
            embedded_installer = members.get(INSTALLER_NAME)
            embedded_metadata = members.get(METADATA_NAME)
            if embedded_installer is None or embedded_metadata is None:
                raise InstallError("artifact archive is missing its installer or metadata")
            if _extract_small(archive, embedded_installer, "embedded installer") != installer_bytes:
                raise InstallError("running installer does not match the archive installer")
            if _extract_small(archive, embedded_metadata, "embedded metadata") != metadata_bytes:
                raise InstallError("external metadata does not match the archive metadata")
            metadata, _raw_records = _parse_metadata(metadata_bytes)
            project = metadata["project"]
            installer_identity = metadata["installer"]
            if (
                len(installer_bytes) != installer_identity["size"]
                or hashlib.sha256(installer_bytes).hexdigest() != installer_identity["sha256"]
            ):
                raise InstallError("installer does not match the metadata identity")
            artifacts = _artifact_records(metadata, members)
            expected_files = {
                INSTALLER_NAME, METADATA_NAME,
                *(f"{PAYLOAD_PREFIX}/{record.target}" for record in artifacts),
            }
            actual_files = {name for name, member in members.items() if member.isfile()}
            if actual_files != expected_files:
                raise InstallError("artifact archive contains undeclared regular files")
            expected_directories: set[str] = set()
            for name in expected_files:
                parts = PurePosixPath(name).parts
                expected_directories.update(
                    "/".join(parts[:length]) for length in range(1, len(parts))
                )
            actual_directories = {name for name, member in members.items() if member.isdir()}
            if actual_directories != expected_directories:
                raise InstallError("artifact archive contains missing or undeclared directories")
            for record in artifacts:
                digest = _hash_member(archive, record.member, f"artifact {record.target}")
                if digest != record.sha256:
                    raise InstallError(f"artifact payload hash mismatch: {record.target}")
            _validate_archived_apps(archive, artifacts)
    except InstallError:
        raise
    except (OSError, tarfile.TarError, MemoryError, OverflowError) as exc:
        raise InstallError(f"artifact archive is unreadable: {exc}") from exc
    return Verification(
        archive_path, archive_size, archive_sha256,
        hashlib.sha256(metadata_bytes).hexdigest(), project,
        artifacts, metadata_bytes, metadata,
    )


@contextmanager
def _verified_inputs(
    archive: Path, installer_path: Path, metadata_path: Path, *, required_uid: int,
) -> Iterator[tuple[Verification, int]]:
    with _open_stable_regular(
        installer_path, "installer", required_uid=required_uid,
        maximum_size=MAX_CONTROL_BYTES,
    ) as (installer_fd, installer_status):
        installer_bytes = _read_descriptor(
            installer_fd, installer_status.st_size, "installer",
        )
        with _open_stable_regular(
            metadata_path, "metadata", required_uid=required_uid,
            maximum_size=MAX_CONTROL_BYTES,
        ) as (metadata_fd, metadata_status):
            metadata_bytes = _read_descriptor(
                metadata_fd, metadata_status.st_size, "metadata",
            )
            with _open_stable_regular(
                archive, "artifact archive", required_uid=required_uid,
                maximum_size=MAX_ARCHIVE_BYTES,
            ) as (archive_fd, archive_status):
                archive_digest = _hash_descriptor(
                    archive_fd, archive_status.st_size, "artifact archive",
                )
                verified = _inspect_archive(
                    archive_fd, _absolute_unresolved(archive), archive_status.st_size,
                    archive_digest, installer_bytes, metadata_bytes,
                )
                yield verified, archive_fd


def verify_bundle(
    archive: Path, *, installer_path: Optional[Path] = None,
    metadata_path: Optional[Path] = None, required_uid: int = 0,
) -> Verification:
    archive = _absolute_unresolved(archive)
    if installer_path is None:
        installer_path = Path(os.path.abspath(__file__))
    if metadata_path is None:
        metadata_path = archive.parent / METADATA_NAME
    with _verified_inputs(
        archive, installer_path, metadata_path, required_uid=required_uid,
    ) as (verified, _descriptor):
        return verified


def _preflight_root(root: Path, required_uid: int) -> os.stat_result:
    root = _absolute_unresolved(root)
    try:
        metadata = root.lstat()
    except OSError as exc:
        raise InstallError(f"installation root is missing or unsafe: {exc}") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or root.resolve(strict=True) != root
        or metadata.st_uid != required_uid
        or stat.S_IMODE(metadata.st_mode) != 0o755
    ):
        raise InstallError("installation root must be one owner-controlled canonical directory")
    try:
        parent = root.parent.lstat()
    except OSError as exc:
        raise InstallError(f"installation root parent is unsafe: {exc}") from exc
    if (
        not stat.S_ISDIR(parent.st_mode)
        or root.parent.resolve(strict=True) != root.parent
        or parent.st_uid != required_uid
        or parent.st_mode & 0o022
    ):
        raise InstallError("installation root parent must be owner-controlled")
    return metadata


def _assert_directory_identity(
    path: Path, expected: os.stat_result, label: str, required_uid: int,
    *, exact_mode: Optional[int] = None,
) -> None:
    try:
        current = path.lstat()
    except OSError as exc:
        raise InstallError(f"{label} changed or disappeared: {exc}") from exc
    if (
        not stat.S_ISDIR(current.st_mode)
        or (current.st_dev, current.st_ino) != (expected.st_dev, expected.st_ino)
        or current.st_uid != required_uid
        or current.st_mode & 0o022
        or exact_mode is not None and stat.S_IMODE(current.st_mode) != exact_mode
    ):
        raise InstallError(f"{label} identity or permissions changed")


def _open_directory_nofollow(
    path: Path, label: str,
) -> tuple[int, os.stat_result]:
    """Open every absolute path component without following a symlink."""
    path = _absolute_unresolved(path)
    flags = (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    success = False
    try:
        descriptor = os.open("/", flags)
        for component in path.parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        opened = os.fstat(descriptor)
        current = path.lstat()
        if (
            not stat.S_ISDIR(opened.st_mode)
            or not stat.S_ISDIR(current.st_mode)
            or opened.st_nlink < 2 or current.st_nlink < 2
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise InstallError(f"{label} is not one NOFOLLOW directory identity")
        success = True
        return descriptor, opened
    except InstallError:
        raise
    except OSError as exc:
        raise InstallError(f"cannot safely open {label}: {exc}") from exc
    finally:
        if descriptor >= 0 and not success:
            os.close(descriptor)


def _assert_open_directory_path(
    path: Path, descriptor: int, expected: os.stat_result, label: str,
    required_uid: int, *, exact_mode: Optional[int] = None,
) -> None:
    try:
        opened = os.fstat(descriptor)
        current = path.lstat()
    except OSError as exc:
        raise InstallError(f"{label} path changed or disappeared: {exc}") from exc
    if (
        not stat.S_ISDIR(opened.st_mode)
        or not stat.S_ISDIR(current.st_mode)
        or opened.st_nlink < 2 or current.st_nlink < 2
        or (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino)
        or (current.st_dev, current.st_ino) != (expected.st_dev, expected.st_ino)
        or opened.st_uid != required_uid or current.st_uid != required_uid
        or opened.st_mode & 0o022 or current.st_mode & 0o022
        or exact_mode is not None and (
            stat.S_IMODE(opened.st_mode) != exact_mode
            or stat.S_IMODE(current.st_mode) != exact_mode
        )
    ):
        raise InstallError(f"{label} identity or permissions changed")


@contextmanager
def _held_installation_root(
    root: Path, expected: os.stat_result, required_uid: int,
) -> Iterator[int]:
    descriptor, opened = _open_directory_nofollow(root, "installation root")
    try:
        if (
            (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino)
            or opened.st_uid != required_uid
            or stat.S_IMODE(opened.st_mode) != 0o755
        ):
            raise InstallError("installation root identity or permissions changed")
        _assert_open_directory_path(
            root, descriptor, expected, "installation root", required_uid,
            exact_mode=0o755,
        )
        yield descriptor
    finally:
        os.close(descriptor)


def _make_private_staging(
    parent_descriptor: int, *, prefix: str, required_uid: int,
) -> tuple[str, int, os.stat_result]:
    flags = (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    for _attempt in range(128):
        name = prefix + secrets.token_hex(12)
        try:
            os.mkdir(name, 0o700, dir_fd=parent_descriptor)
        except FileExistsError:
            continue
        descriptor = -1
        try:
            descriptor = os.open(name, flags, dir_fd=parent_descriptor)
            opened = os.fstat(descriptor)
            named = os.stat(
                name, dir_fd=parent_descriptor, follow_symlinks=False,
            )
            if (
                not stat.S_ISDIR(opened.st_mode)
                or not stat.S_ISDIR(named.st_mode)
                or opened.st_nlink < 2 or named.st_nlink < 2
                or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
                or opened.st_uid != required_uid or named.st_uid != required_uid
                or stat.S_IMODE(opened.st_mode) != 0o700
                or stat.S_IMODE(named.st_mode) != 0o700
            ):
                raise InstallError("private staging identity is unsafe")
            return name, descriptor, opened
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.rmdir(name, dir_fd=parent_descriptor)
            except OSError:
                pass
            raise
    raise InstallError("cannot allocate one unique private staging directory")


def _open_private_subdirectory(
    parent_descriptor: int, name: str, required_uid: int,
) -> int:
    try:
        os.mkdir(name, 0o700, dir_fd=parent_descriptor)
    except FileExistsError:
        pass
    flags = (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    opened = os.fstat(descriptor)
    named = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    if (
        not stat.S_ISDIR(opened.st_mode) or not stat.S_ISDIR(named.st_mode)
        or opened.st_nlink < 2 or named.st_nlink < 2
        or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
        or opened.st_uid != required_uid or named.st_uid != required_uid
        or stat.S_IMODE(opened.st_mode) != 0o700
        or stat.S_IMODE(named.st_mode) != 0o700
    ):
        os.close(descriptor)
        raise InstallError("private staging child identity is unsafe")
    return descriptor


def _open_private_parent_chain(
    staging_descriptor: int, parts: tuple[str, ...], required_uid: int,
) -> int:
    current = os.dup(staging_descriptor)
    try:
        for part in parts:
            next_descriptor = _open_private_subdirectory(
                current, part, required_uid,
            )
            os.close(current)
            current = next_descriptor
        return current
    except BaseException:
        os.close(current)
        raise


@contextmanager
def _deployment_lock(
    root: Path, required_uid: int, *, root_descriptor: Optional[int] = None,
) -> Iterator[int]:
    lock_path = root / ".deployment.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        if root_descriptor is None:
            descriptor = os.open(lock_path, flags, 0o600)
            current = lock_path.lstat()
        else:
            descriptor = os.open(
                ".deployment.lock", flags, 0o600, dir_fd=root_descriptor,
            )
            current = os.stat(
                ".deployment.lock", dir_fd=root_descriptor,
                follow_symlinks=False,
            )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode) or not stat.S_ISREG(current.st_mode)
            or opened.st_nlink != 1 or current.st_nlink != 1
            or opened.st_uid != required_uid
            or opened.st_mode & 0o022
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise InstallError("deployment lock is unsafe")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise InstallError("another deployment operation owns .deployment.lock") from exc
        yield descriptor
    except InstallError:
        raise
    except OSError as exc:
        raise InstallError(f"cannot acquire deployment lock: {exc}") from exc
    finally:
        if descriptor >= 0:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)


def _hash_live_file(path: Path, label: str, required_uid: int) -> tuple[int, str]:
    with _open_stable_regular(
        path, label, required_uid=required_uid,
        maximum_size=MAX_MEMBER_BYTES,
    ) as (descriptor, metadata):
        return metadata.st_ino, _hash_descriptor(descriptor, metadata.st_size, label)


def _inspect_target(
    root: Path, record: ArtifactRecord, required_uid: int,
) -> tuple[str, Optional[int]]:
    parts = PurePosixPath(record.target).parts
    for length in range(1, len(parts)):
        directory = root.joinpath(*parts[:length])
        try:
            metadata = directory.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise InstallError(f"cannot inspect destination ancestor {directory}: {exc}") from exc
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != required_uid
            or stat.S_IMODE(metadata.st_mode) != 0o755
        ):
            raise InstallError(f"destination ancestor is unsafe: {directory}")
    destination = root.joinpath(*parts)
    try:
        metadata = destination.lstat()
    except FileNotFoundError:
        return "install", None
    except OSError as exc:
        raise InstallError(f"cannot inspect artifact destination {destination}: {exc}") from exc
    if (
        not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
        or metadata.st_uid != required_uid
        or stat.S_IMODE(metadata.st_mode) != record.mode
    ):
        raise InstallError(f"artifact destination is unsafe: {destination}")
    inode, digest = _hash_live_file(destination, f"existing {record.target}", required_uid)
    if metadata.st_size == record.size and digest == record.sha256:
        return "skip", inode
    raise InstallError(f"artifact destination conflict: {record.target}")


def _receipt_bytes(verified: Verification) -> bytes:
    selection = {
        key: verified.metadata[key]
        for key in (
            "deployment_scope", "inputs", "mini", "mini_input", "switch_scope",
            "upgrade_policy",
        )
    }
    value = {
        "archive_sha256": verified.archive_sha256,
        "artifact_type": "http-ztp-shared-artifact-receipt",
        "artifacts": [
            {
                "consumers": [
                    {"family": family, "version": version}
                    for family, version in item.consumers
                ],
                "kind": item.kind,
                "platform": item.platform, "sha256": item.sha256,
                "size": item.size, "target": item.target,
            }
            for item in verified.artifacts
        ],
        "metadata_sha256": verified.metadata_sha256,
        "project": verified.project,
        "schema_version": 1,
        "selection": selection,
    }
    return json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True).encode("ascii") + b"\n"


def _receipt_path(root: Path, verified: Verification) -> Path:
    return root / RECEIPT_DIRECTORY / f"{verified.archive_sha256}.json"


def _preflight_receipt(
    root: Path, verified: Verification, payload: bytes, required_uid: int,
) -> tuple[str, Optional[int]]:
    directory = root / RECEIPT_DIRECTORY
    try:
        metadata = directory.lstat()
    except FileNotFoundError:
        metadata = None
    except OSError as exc:
        raise InstallError(f"cannot inspect artifact receipt directory: {exc}") from exc
    if metadata is not None and (
        not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != required_uid
        or metadata.st_mode & 0o022
    ):
        raise InstallError("artifact receipt directory is unsafe")
    path = _receipt_path(root, verified)
    try:
        current = path.lstat()
    except FileNotFoundError:
        return "install", None
    except OSError as exc:
        raise InstallError(f"cannot inspect artifact receipt: {exc}") from exc
    if (
        not stat.S_ISREG(current.st_mode) or current.st_nlink != 1
        or current.st_uid != required_uid
        or stat.S_IMODE(current.st_mode) != 0o600
    ):
        raise InstallError("artifact receipt is unsafe")
    inode, digest = _hash_live_file(path, "artifact receipt", required_uid)
    if current.st_size == len(payload) and digest == hashlib.sha256(payload).hexdigest():
        return "skip", inode
    raise InstallError("artifact receipt conflicts with this verified archive")


def _stage_payloads(
    archive_descriptor: int, verified: Verification, staging: Path,
    staging_descriptor: int, receipt_payload: bytes, required_uid: int,
) -> dict[str, Path]:
    result: dict[str, Path] = {}
    os.lseek(archive_descriptor, 0, os.SEEK_SET)
    with os.fdopen(os.dup(archive_descriptor), "rb") as stream, \
            tarfile.open(fileobj=stream, mode="r:gz") as archive:
        members = _bounded_members(archive)
        for record in verified.artifacts:
            member = members.get(f"{PAYLOAD_PREFIX}/{record.target}")
            if member is None:
                raise InstallError(f"verified artifact disappeared: {record.target}")
            source = archive.extractfile(member)
            if source is None:
                raise InstallError(f"verified artifact is unreadable: {record.target}")
            parts = (PAYLOAD_PREFIX,) + tuple(PurePosixPath(record.target).parts)
            parent_descriptor = _open_private_parent_chain(
                staging_descriptor, parts[:-1], required_uid,
            )
            descriptor = -1
            digest = hashlib.sha256()
            remaining = record.size
            try:
                descriptor = os.open(
                    parts[-1],
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    record.mode, dir_fd=parent_descriptor,
                )
                while remaining:
                    block = source.read(min(remaining, 1024 * 1024))
                    if not block:
                        raise InstallError(f"artifact truncated during staging: {record.target}")
                    view = memoryview(block)
                    while view:
                        written = os.write(descriptor, view)
                        if written <= 0:
                            raise InstallError(f"short write staging artifact: {record.target}")
                        view = view[written:]
                    digest.update(block)
                    remaining -= len(block)
                if source.read(1):
                    raise InstallError(f"artifact grew during staging: {record.target}")
                os.fchmod(descriptor, record.mode)
                os.fsync(descriptor)
                opened = os.fstat(descriptor)
                named = os.stat(
                    parts[-1], dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or not stat.S_ISREG(named.st_mode)
                    or opened.st_nlink != 1 or named.st_nlink != 1
                    or (opened.st_dev, opened.st_ino)
                    != (named.st_dev, named.st_ino)
                    or opened.st_uid != required_uid
                    or named.st_uid != required_uid
                    or stat.S_IMODE(opened.st_mode) != record.mode
                    or stat.S_IMODE(named.st_mode) != record.mode
                    or opened.st_size != record.size
                    or named.st_size != record.size
                ):
                    raise InstallError(
                        f"private staged artifact identity is unsafe: {record.target}"
                    )
                os.fsync(parent_descriptor)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
                os.close(parent_descriptor)
            if digest.hexdigest() != record.sha256:
                raise InstallError(f"artifact staging hash mismatch: {record.target}")
            result[record.target] = staging.joinpath(*parts)
    receipt_name = "receipt.json"
    descriptor = os.open(
        receipt_name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        0o600, dir_fd=staging_descriptor,
    )
    try:
        view = memoryview(receipt_payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise InstallError("short write staging artifact receipt")
            view = view[written:]
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        opened = os.fstat(descriptor)
        named = os.stat(
            receipt_name, dir_fd=staging_descriptor, follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(named.st_mode)
            or opened.st_nlink != 1 or named.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
            or opened.st_uid != required_uid or named.st_uid != required_uid
            or stat.S_IMODE(opened.st_mode) != 0o600
            or stat.S_IMODE(named.st_mode) != 0o600
            or opened.st_size != len(receipt_payload)
            or named.st_size != len(receipt_payload)
        ):
            raise InstallError("private staged artifact receipt identity is unsafe")
    finally:
        os.close(descriptor)
    os.fsync(staging_descriptor)
    result["@receipt"] = staging / receipt_name
    return result


def _open_owned_directory_at(
    parent_descriptor: int, name: str, required_uid: int, *, mode: int,
    create: bool, label: str,
) -> tuple[int, os.stat_result, bool]:
    created = False
    if create:
        try:
            os.mkdir(name, mode, dir_fd=parent_descriptor)
            created = True
        except FileExistsError:
            pass
        except OSError as exc:
            raise InstallError(f"cannot create {label}: {exc}") from exc
    flags = (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
        if created:
            os.fchmod(descriptor, mode)
        opened = os.fstat(descriptor)
        named = os.stat(
            name, dir_fd=parent_descriptor, follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(opened.st_mode)
            or not stat.S_ISDIR(named.st_mode)
            or opened.st_nlink < 2 or named.st_nlink < 2
            or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
            or opened.st_uid != required_uid or named.st_uid != required_uid
            or stat.S_IMODE(opened.st_mode) != mode
            or stat.S_IMODE(named.st_mode) != mode
        ):
            raise InstallError(f"{label} identity or permissions are unsafe")
        return descriptor, opened, created
    except InstallError:
        if descriptor >= 0:
            os.close(descriptor)
        if created:
            try:
                os.rmdir(name, dir_fd=parent_descriptor)
            except OSError:
                pass
        raise
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        if created:
            try:
                os.rmdir(name, dir_fd=parent_descriptor)
            except OSError:
                pass
        raise InstallError(f"cannot safely open {label}: {exc}") from exc


def _open_directory_chain_at(
    root_descriptor: int, parts: tuple[str, ...], required_uid: int,
    *, mode: int, create: bool, label: str,
    created: Optional[list[tuple[tuple[str, ...], tuple[int, int]]]] = None,
) -> int:
    descriptor = os.dup(root_descriptor)
    prefix: tuple[str, ...] = ()
    try:
        for part in parts:
            prefix += (part,)
            child, metadata, was_created = _open_owned_directory_at(
                descriptor, part, required_uid, mode=mode, create=create,
                label=f"{label} {'/'.join(prefix)}",
            )
            os.close(descriptor)
            descriptor = child
            if was_created and created is not None:
                created.append((prefix, (metadata.st_dev, metadata.st_ino)))
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _ensure_directories_at(
    root_descriptor: int, records: tuple[ArtifactRecord, ...], required_uid: int,
    created: list[tuple[tuple[str, ...], tuple[int, int]]],
) -> None:
    required: set[tuple[str, ...]] = {(RECEIPT_DIRECTORY,)}
    for record in records:
        parts = PurePosixPath(record.target).parts
        required.update(parts[:length] for length in range(1, len(parts)))
    for parts in sorted(required, key=lambda item: (len(item), item)):
        descriptor = _open_directory_chain_at(
            root_descriptor, parts, required_uid, mode=0o755, create=True,
            label="artifact destination directory", created=created,
        )
        os.close(descriptor)


def _assert_directory_chain_at(
    root_descriptor: int, parts: tuple[str, ...], descriptor: int,
    required_uid: int, *, mode: int, label: str,
) -> None:
    reopened = _open_directory_chain_at(
        root_descriptor, parts, required_uid, mode=mode, create=False,
        label=label,
    )
    try:
        held = os.fstat(descriptor)
        current = os.fstat(reopened)
        if (
            not stat.S_ISDIR(held.st_mode)
            or held.st_nlink < 2
            or held.st_uid != required_uid
            or stat.S_IMODE(held.st_mode) != mode
            or (held.st_dev, held.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise InstallError(f"{label} identity or permissions changed")
    finally:
        os.close(reopened)


_TEST_BEFORE_PUBLISH = None


def _rename_noreplace(source: Path, destination: Path) -> None:
    """Atomically publish without replacing a concurrently created target."""
    if sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is not None:
            renameat2.argtypes = (
                ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
                ctypes.c_uint,
            )
            renameat2.restype = ctypes.c_int
            result = renameat2(
                -100, os.fsencode(source), -100, os.fsencode(destination), 1,
            )
            if result == 0:
                return
            number = ctypes.get_errno()
            if number not in {errno.ENOSYS, errno.EINVAL}:
                raise OSError(number, os.strerror(number), os.fspath(destination))
    # Portable fallback: link creation is itself no-clobber and makes the
    # complete staged inode visible in one operation.  The staging alias is
    # removed immediately, restoring the required single-link identity.
    os.link(source, destination, follow_symlinks=False)
    try:
        source.unlink()
    except BaseException:
        destination.unlink(missing_ok=True)
        raise


def _rename_noreplace_at(
    source_descriptor: int, source_name: str,
    destination_descriptor: int, destination_name: str,
) -> None:
    """Atomically publish one inode between two held directory identities."""
    libc = ctypes.CDLL(None, use_errno=True)
    result: Optional[int] = None
    if sys.platform.startswith("linux"):
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is not None:
            renameat2.argtypes = (
                ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
                ctypes.c_uint,
            )
            renameat2.restype = ctypes.c_int
            result = renameat2(
                source_descriptor, os.fsencode(source_name),
                destination_descriptor, os.fsencode(destination_name), 1,
            )
    elif sys.platform == "darwin":
        renameatx = getattr(libc, "renameatx_np", None)
        if renameatx is not None:
            renameatx.argtypes = (
                ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
                ctypes.c_uint,
            )
            renameatx.restype = ctypes.c_int
            result = renameatx(
                source_descriptor, os.fsencode(source_name),
                destination_descriptor, os.fsencode(destination_name),
                0x00000004,
            )
    if result == 0:
        return
    if result not in {None, 0}:
        number = ctypes.get_errno()
        if number not in {errno.ENOSYS, errno.EINVAL, errno.ENOTSUP}:
            raise OSError(number, os.strerror(number), destination_name)
    os.link(
        source_name, destination_name,
        src_dir_fd=source_descriptor, dst_dir_fd=destination_descriptor,
        follow_symlinks=False,
    )
    try:
        os.unlink(source_name, dir_fd=source_descriptor)
    except BaseException:
        os.unlink(destination_name, dir_fd=destination_descriptor)
        raise


def _publish_link(source: Path, destination: Path) -> int:
    # Every destination ancestor is root-owned and non-writable by group/other,
    # and the cooperative deployment lock excludes supported writers.  Rename
    # from the same filesystem avoids any crash window with a second hard link.
    try:
        destination.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise InstallError(f"cannot inspect artifact destination before publish: {exc}") from exc
    else:
        raise InstallError(f"artifact destination changed before publish: {destination}")
    source_metadata = source.lstat()
    renamed = False
    try:
        hook = _TEST_BEFORE_PUBLISH
        if hook is not None:
            hook()
        _rename_noreplace(source, destination)
        renamed = True
        metadata = destination.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or (metadata.st_dev, metadata.st_ino)
            != (source_metadata.st_dev, source_metadata.st_ino)
        ):
            raise InstallError(f"published artifact identity is unsafe: {destination}")
        directory_fd = os.open(
            destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return metadata.st_ino
    except BaseException as exc:
        if renamed:
            try:
                current = destination.lstat()
                if (
                    stat.S_ISREG(current.st_mode)
                    and (current.st_dev, current.st_ino)
                    == (source_metadata.st_dev, source_metadata.st_ino)
                ):
                    destination.unlink()
            except FileNotFoundError:
                pass
        if isinstance(exc, OSError) and exc.errno == errno.EEXIST:
            raise InstallError(
                f"artifact destination changed or exists: {destination}"
            ) from exc
        if isinstance(exc, OSError):
            raise InstallError(f"cannot publish artifact {destination}: {exc}") from exc
        raise


def _publish_staged_link(
    staging_descriptor: int, source_parts: tuple[str, ...],
    root_descriptor: int, destination_parts: tuple[str, ...],
    *, source: Path, destination: Path, expected_mode: int,
    root: Path, root_status: os.stat_result, required_uid: int,
    destination_parent_descriptor: Optional[int] = None,
) -> tuple[int, int]:
    source_parent = _open_directory_chain_at(
        staging_descriptor, source_parts[:-1], required_uid,
        mode=0o700, create=False, label="private staged artifact parent",
    )
    close_destination_parent = destination_parent_descriptor is None
    destination_parent = (
        _open_directory_chain_at(
            root_descriptor, destination_parts[:-1], required_uid,
            mode=0o755, create=False, label="artifact destination parent",
        )
        if destination_parent_descriptor is None
        else destination_parent_descriptor
    )
    renamed = False
    source_identity: Optional[tuple[int, int]] = None
    try:
        _assert_directory_chain_at(
            staging_descriptor, source_parts[:-1], source_parent,
            required_uid, mode=0o700, label="private staged artifact parent",
        )
        _assert_directory_chain_at(
            root_descriptor, destination_parts[:-1], destination_parent,
            required_uid, mode=0o755, label="artifact destination parent",
        )
        source_metadata = os.stat(
            source_parts[-1], dir_fd=source_parent, follow_symlinks=False,
        )
        source_identity = (source_metadata.st_dev, source_metadata.st_ino)
        if (
            not stat.S_ISREG(source_metadata.st_mode)
            or source_metadata.st_nlink != 1
            or source_metadata.st_uid != required_uid
            or stat.S_IMODE(source_metadata.st_mode) != expected_mode
        ):
            raise InstallError(f"private staged artifact is unsafe: {source}")
        try:
            os.stat(
                destination_parts[-1], dir_fd=destination_parent,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            raise InstallError(
                f"artifact destination changed before publish: {destination}"
            )
        hook = _TEST_BEFORE_PUBLISH
        if hook is not None:
            hook()
        _assert_open_directory_path(
            root, root_descriptor, root_status, "installation root",
            required_uid, exact_mode=0o755,
        )
        _assert_directory_chain_at(
            staging_descriptor, source_parts[:-1], source_parent,
            required_uid, mode=0o700, label="private staged artifact parent",
        )
        _assert_directory_chain_at(
            root_descriptor, destination_parts[:-1], destination_parent,
            required_uid, mode=0o755, label="artifact destination parent",
        )
        _rename_noreplace_at(
            source_parent, source_parts[-1],
            destination_parent, destination_parts[-1],
        )
        renamed = True
        metadata = os.stat(
            destination_parts[-1], dir_fd=destination_parent,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or (metadata.st_dev, metadata.st_ino) != source_identity
            or metadata.st_uid != required_uid
            or stat.S_IMODE(metadata.st_mode) != expected_mode
        ):
            raise InstallError(f"published artifact identity is unsafe: {destination}")
        os.fsync(destination_parent)
        os.fsync(source_parent)
        _assert_open_directory_path(
            root, root_descriptor, root_status, "installation root",
            required_uid, exact_mode=0o755,
        )
        _assert_directory_chain_at(
            root_descriptor, destination_parts[:-1], destination_parent,
            required_uid, mode=0o755, label="artifact destination parent",
        )
        return source_identity
    except BaseException as exc:
        if renamed and source_identity is not None:
            try:
                current = os.stat(
                    destination_parts[-1], dir_fd=destination_parent,
                    follow_symlinks=False,
                )
                if (
                    stat.S_ISREG(current.st_mode)
                    and (current.st_dev, current.st_ino) == source_identity
                ):
                    os.unlink(destination_parts[-1], dir_fd=destination_parent)
                    os.fsync(destination_parent)
            except FileNotFoundError:
                pass
        if isinstance(exc, InstallError):
            raise
        if isinstance(exc, OSError) and exc.errno in {errno.EEXIST, errno.ENOTEMPTY}:
            raise InstallError(
                f"artifact destination changed or exists: {destination}"
            ) from exc
        if isinstance(exc, OSError):
            raise InstallError(f"cannot publish artifact {destination}: {exc}") from exc
        raise
    finally:
        if close_destination_parent:
            os.close(destination_parent)
        os.close(source_parent)


def _rollback(paths: list[tuple[Path, int]], directories: list[Path]) -> None:
    for path, inode in reversed(paths):
        try:
            metadata = path.lstat()
            if stat.S_ISREG(metadata.st_mode) and metadata.st_ino == inode:
                path.unlink()
        except FileNotFoundError:
            pass
    for directory in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        try:
            directory.rmdir()
        except OSError:
            pass


def _assert_publication_state_at(
    root_descriptor: int,
    parents: dict[tuple[str, ...], tuple[int, tuple[int, int]]],
    paths: list[tuple[int, str, tuple[int, int]]],
    required_uid: int,
) -> None:
    for parts, (descriptor, identity) in parents.items():
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != identity
        ):
            raise InstallError("artifact destination parent identity changed")
        _assert_directory_chain_at(
            root_descriptor, parts, descriptor, required_uid,
            mode=0o755, label="artifact destination parent",
        )
    for descriptor, name, identity in paths:
        try:
            current = os.stat(
                name, dir_fd=descriptor, follow_symlinks=False,
            )
        except OSError as exc:
            raise InstallError(
                "published artifact changed before transaction commit"
            ) from exc
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
            or (current.st_dev, current.st_ino) != identity
        ):
            raise InstallError(
                "published artifact identity changed before transaction commit"
            )


def _verify_live_file_at(
    root_descriptor: int, parts: tuple[str, ...], required_uid: int, *,
    expected_mode: int, expected_size: int, expected_sha256: str, label: str,
) -> None:
    """Bind the final commit decision to one stable NOFOLLOW live inode."""
    parent_descriptor = _open_directory_chain_at(
        root_descriptor, parts[:-1], required_uid, mode=0o755, create=False,
        label=f"{label} parent",
    )
    descriptor = -1
    flags = (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        named = os.stat(
            parts[-1], dir_fd=parent_descriptor, follow_symlinks=False,
        )
        descriptor = os.open(parts[-1], flags, dir_fd=parent_descriptor)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(named.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or named.st_nlink != 1 or opened.st_nlink != 1
            or named.st_uid != required_uid or opened.st_uid != required_uid
            or stat.S_IMODE(named.st_mode) != expected_mode
            or stat.S_IMODE(opened.st_mode) != expected_mode
            or named.st_size != expected_size or opened.st_size != expected_size
            or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise InstallError(
                f"{label} identity, ownership, mode, link count, or size "
                "changed before transaction commit"
            )
        digest = _hash_descriptor(descriptor, expected_size, label)
        after = os.fstat(descriptor)
        current = os.stat(
            parts[-1], dir_fd=parent_descriptor, follow_symlinks=False,
        )
        if (
            _stable_fields(after) != _stable_fields(opened)
            or (current.st_dev, current.st_ino)
            != (opened.st_dev, opened.st_ino)
            or current.st_nlink != 1
            or current.st_uid != required_uid
            or stat.S_IMODE(current.st_mode) != expected_mode
            or current.st_size != expected_size
        ):
            raise InstallError(f"{label} changed during final commit verification")
        if digest != expected_sha256:
            raise InstallError(f"{label} hash changed before transaction commit")
    except InstallError:
        raise
    except OSError as exc:
        raise InstallError(f"cannot verify {label} at transaction commit: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_descriptor)


def _verify_final_live_state(
    root_descriptor: int, verified: Verification, receipt_payload: bytes,
    required_uid: int,
) -> None:
    """Content-verify every installed or skipped artifact before success."""
    for record in verified.artifacts:
        _verify_live_file_at(
            root_descriptor, PurePosixPath(record.target).parts, required_uid,
            expected_mode=record.mode, expected_size=record.size,
            expected_sha256=record.sha256,
            label=f"live artifact {record.target}",
        )
    _verify_live_file_at(
        root_descriptor,
        (RECEIPT_DIRECTORY, f"{verified.archive_sha256}.json"),
        required_uid, expected_mode=0o600,
        expected_size=len(receipt_payload),
        expected_sha256=hashlib.sha256(receipt_payload).hexdigest(),
        label="live artifact receipt",
    )


def _rollback_at(
    root_descriptor: int,
    paths: list[tuple[int, str, tuple[int, int]]],
    directories: list[tuple[tuple[str, ...], tuple[int, int]]],
    required_uid: int,
) -> None:
    for parent, name, identity in reversed(paths):
        try:
            current = os.stat(
                name, dir_fd=parent, follow_symlinks=False,
            )
            if (
                stat.S_ISREG(current.st_mode)
                and (current.st_dev, current.st_ino) == identity
            ):
                os.unlink(name, dir_fd=parent)
                os.fsync(parent)
        except (FileNotFoundError, OSError):
            pass
    for parts, identity in sorted(
        directories, key=lambda item: len(item[0]), reverse=True,
    ):
        parent = -1
        try:
            parent = _open_directory_chain_at(
                root_descriptor, parts[:-1], required_uid,
                mode=0o755, create=False,
                label="artifact directory rollback parent",
            )
            current = os.stat(
                parts[-1], dir_fd=parent, follow_symlinks=False,
            )
            if (
                stat.S_ISDIR(current.st_mode)
                and (current.st_dev, current.st_ino) == identity
            ):
                os.rmdir(parts[-1], dir_fd=parent)
                os.fsync(parent)
        except (FileNotFoundError, InstallError, OSError):
            pass
        finally:
            if parent >= 0:
                os.close(parent)


def _clear_private_directory(descriptor: int) -> None:
    for name in os.listdir(descriptor):
        try:
            metadata = os.stat(
                name, dir_fd=descriptor, follow_symlinks=False,
            )
        except FileNotFoundError:
            continue
        if stat.S_ISDIR(metadata.st_mode):
            flags = (
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            child = os.open(name, flags, dir_fd=descriptor)
            try:
                opened = os.fstat(child)
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or (opened.st_dev, opened.st_ino)
                    != (metadata.st_dev, metadata.st_ino)
                ):
                    raise InstallError(
                        "private staging child identity changed during cleanup"
                    )
                _clear_private_directory(child)
                current = os.stat(
                    name, dir_fd=descriptor, follow_symlinks=False,
                )
                if (
                    not stat.S_ISDIR(current.st_mode)
                    or (current.st_dev, current.st_ino)
                    != (opened.st_dev, opened.st_ino)
                ):
                    raise InstallError(
                        "private staging child identity changed during cleanup"
                    )
            finally:
                os.close(child)
            os.rmdir(name, dir_fd=descriptor)
        else:
            os.unlink(name, dir_fd=descriptor)


def _remove_staging(
    parent_descriptor: int, staging_name: str, staging_descriptor: int,
    expected: os.stat_result,
) -> None:
    opened = os.fstat(staging_descriptor)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino)
        or opened.st_uid != expected.st_uid
    ):
        raise InstallError("private staging descriptor identity changed")
    _clear_private_directory(staging_descriptor)
    os.fsync(staging_descriptor)
    try:
        named = os.stat(
            staging_name, dir_fd=parent_descriptor, follow_symlinks=False,
        )
    except FileNotFoundError as exc:
        raise InstallError(
            "private staging identity changed; opened contents were cleared"
        ) from exc
    if (
        not stat.S_ISDIR(named.st_mode)
        or (named.st_dev, named.st_ino) != (expected.st_dev, expected.st_ino)
    ):
        raise InstallError(
            "private staging identity changed; replacement was not touched"
        )
    os.rmdir(staging_name, dir_fd=parent_descriptor)
    os.fsync(parent_descriptor)


def deploy_archive(
    archive: Path, *, root: Path, verify_only: bool,
    installer_path: Optional[Path] = None, metadata_path: Optional[Path] = None,
    required_uid: int = 0, staging_parent: Optional[Path] = None,
) -> DeployResult:
    archive = _absolute_unresolved(archive)
    root = _absolute_unresolved(root)
    if installer_path is None:
        installer_path = Path(os.path.abspath(__file__))
    if metadata_path is None:
        metadata_path = archive.parent / METADATA_NAME
    with _verified_inputs(
        archive, installer_path, metadata_path, required_uid=required_uid,
    ) as (verified, archive_descriptor):
        receipt = _receipt_path(root, verified)
        if verify_only:
            return DeployResult(
                True, verified.archive_sha256, verified.metadata_sha256,
                verified.project, (), (), receipt,
            )
        root_status = _preflight_root(root, required_uid)
        receipt_payload = _receipt_bytes(verified)
        with _held_installation_root(
            root, root_status, required_uid,
        ) as root_descriptor, _deployment_lock(
            root, required_uid, root_descriptor=root_descriptor,
        ):
            _assert_directory_identity(
                root, root_status, "installation root", required_uid,
                exact_mode=0o755,
            )
            plans = {
                record.target: _inspect_target(root, record, required_uid)
                for record in verified.artifacts
            }
            receipt_plan = _preflight_receipt(
                root, verified, receipt_payload, required_uid,
            )
            parent = _absolute_unresolved(staging_parent or root.parent)
            parent_descriptor, parent_status = _open_directory_nofollow(
                parent, "private staging parent",
            )
            if (
                not stat.S_ISDIR(parent_status.st_mode)
                or parent_status.st_dev != root_status.st_dev
                or parent_status.st_uid != required_uid
                or parent_status.st_mode & 0o022
                or parent_status.st_nlink < 2
            ):
                os.close(parent_descriptor)
                raise InstallError(
                    "private staging must be an owner-controlled real directory "
                    "on the live filesystem"
                )
            required_bytes = sum(record.size for record in verified.artifacts)
            try:
                filesystem = os.fstatvfs(parent_descriptor)
            except OSError as exc:
                os.close(parent_descriptor)
                raise InstallError(f"cannot inspect private staging capacity: {exc}") from exc
            available_bytes = filesystem.f_bavail * filesystem.f_frsize
            if available_bytes < required_bytes + 16 * 1024 * 1024:
                os.close(parent_descriptor)
                raise InstallError(
                    "private staging filesystem lacks space for verified artifacts"
                )
            staging_descriptor = -1
            try:
                staging_name, staging_descriptor, staging_status = (
                    _make_private_staging(
                        parent_descriptor, prefix=".http-ztp-shared.",
                        required_uid=required_uid,
                    )
                )
                staging = parent / staging_name
                publication_parents: dict[
                    tuple[str, ...], tuple[int, tuple[int, int]]
                ] = {}
                published: list[tuple[int, str, tuple[int, int]]] = []
                created_directories: list[
                    tuple[tuple[str, ...], tuple[int, int]]
                ] = []
                installed: list[str] = []
                try:
                    _assert_open_directory_path(
                        parent, parent_descriptor, parent_status,
                        "private staging parent", required_uid,
                    )
                    _assert_open_directory_path(
                        staging, staging_descriptor, staging_status,
                        "private staging", required_uid, exact_mode=0o700,
                    )
                    staged = _stage_payloads(
                        archive_descriptor, verified, staging,
                        staging_descriptor, receipt_payload, required_uid,
                    )
                    _assert_directory_identity(
                        root, root_status, "installation root", required_uid,
                        exact_mode=0o755,
                    )
                    _assert_open_directory_path(
                        parent, parent_descriptor, parent_status,
                        "private staging parent", required_uid,
                    )
                    _assert_open_directory_path(
                        staging, staging_descriptor, staging_status,
                        "private staging", required_uid, exact_mode=0o700,
                    )
                    second_plans = {
                        record.target: _inspect_target(root, record, required_uid)
                        for record in verified.artifacts
                    }
                    second_receipt = _preflight_receipt(
                        root, verified, receipt_payload, required_uid,
                    )
                    if second_plans != plans or second_receipt != receipt_plan:
                        raise InstallError(
                            "live artifact destinations changed during verification"
                        )
                    _ensure_directories_at(
                        root_descriptor, verified.artifacts, required_uid,
                        created_directories,
                    )
                    for record in verified.artifacts:
                        if plans[record.target][0] == "skip":
                            continue
                        destination = root / record.target
                        destination_parts = PurePosixPath(record.target).parts
                        parent_parts = destination_parts[:-1]
                        parent_entry = publication_parents.get(parent_parts)
                        if parent_entry is None:
                            destination_parent = _open_directory_chain_at(
                                root_descriptor, parent_parts, required_uid,
                                mode=0o755, create=False,
                                label="artifact destination parent",
                            )
                            parent_metadata = os.fstat(destination_parent)
                            parent_entry = (
                                destination_parent,
                                (parent_metadata.st_dev, parent_metadata.st_ino),
                            )
                            publication_parents[parent_parts] = parent_entry
                        identity = _publish_staged_link(
                            staging_descriptor,
                            (PAYLOAD_PREFIX,) + destination_parts,
                            root_descriptor, destination_parts,
                            source=staged[record.target], destination=destination,
                            expected_mode=record.mode, root=root,
                            root_status=root_status, required_uid=required_uid,
                            destination_parent_descriptor=parent_entry[0],
                        )
                        published.append(
                            (parent_entry[0], destination_parts[-1], identity)
                        )
                        installed.append(record.target)
                    if receipt_plan[0] == "install":
                        receipt_parts = (
                            RECEIPT_DIRECTORY, f"{verified.archive_sha256}.json",
                        )
                        receipt_parent_parts = receipt_parts[:-1]
                        receipt_parent_entry = publication_parents.get(
                            receipt_parent_parts
                        )
                        if receipt_parent_entry is None:
                            receipt_parent = _open_directory_chain_at(
                                root_descriptor, receipt_parent_parts,
                                required_uid, mode=0o755, create=False,
                                label="artifact destination parent",
                            )
                            receipt_parent_metadata = os.fstat(receipt_parent)
                            receipt_parent_entry = (
                                receipt_parent,
                                (
                                    receipt_parent_metadata.st_dev,
                                    receipt_parent_metadata.st_ino,
                                ),
                            )
                            publication_parents[
                                receipt_parent_parts
                            ] = receipt_parent_entry
                        identity = _publish_staged_link(
                            staging_descriptor, ("receipt.json",),
                            root_descriptor, receipt_parts,
                            source=staged["@receipt"], destination=receipt,
                            expected_mode=0o600, root=root,
                            root_status=root_status, required_uid=required_uid,
                            destination_parent_descriptor=receipt_parent_entry[0],
                        )
                        published.append(
                            (receipt_parent_entry[0], receipt_parts[-1], identity)
                        )
                    _assert_open_directory_path(
                        root, root_descriptor, root_status,
                        "installation root", required_uid, exact_mode=0o755,
                    )
                    _assert_publication_state_at(
                        root_descriptor, publication_parents, published,
                        required_uid,
                    )
                    _verify_final_live_state(
                        root_descriptor, verified, receipt_payload,
                        required_uid,
                    )
                except BaseException:
                    _rollback_at(
                        root_descriptor, published, created_directories,
                        required_uid,
                    )
                    raise
                finally:
                    try:
                        _remove_staging(
                            parent_descriptor, staging_name, staging_descriptor,
                            staging_status,
                        )
                    finally:
                        for descriptor, _identity in publication_parents.values():
                            os.close(descriptor)
                installed_set = set(installed)
                skipped = tuple(
                    record.target for record in verified.artifacts
                    if record.target not in installed_set
                )
                return DeployResult(
                    False, verified.archive_sha256, verified.metadata_sha256,
                    verified.project, tuple(installed), skipped, receipt,
                )
            finally:
                if staging_descriptor >= 0:
                    os.close(staging_descriptor)
                os.close(parent_descriptor)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parser().parse_args(argv)
    if os.geteuid() != 0:
        print("[ERROR] run deploy-shared-artifacts.py as root", file=sys.stderr)
        return 1
    try:
        result = deploy_archive(
            args.archive, root=args.root, verify_only=args.verify_only,
        )
        print(f"[OK] artifact archive SHA-256: {result.archive_sha256}")
        print(f"[OK] artifact metadata SHA-256: {result.metadata_sha256}")
        print(f"[OK] project derivation: {result.project}")
        if result.verify_only:
            print("[OK] verify-only completed; no lock, staging, receipt, or live write occurred")
            return 0
        print(f"[OK] installed artifacts: {len(result.installed)}")
        print(f"[OK] identical artifacts skipped: {len(result.skipped)}")
        print(f"[OK] receipt: {result.receipt}")
        print("[NEXT] run the supported unified load for the selected Native/Docker runtime")
        return 0
    except (InstallError, OSError, tarfile.TarError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
