#!/usr/bin/env python3
"""Build or install one immutable, project-specific HTTP ZTP Docker image.

The normal developer image remains project-independent.  This optional image
is derived offline from one already verified generic image and embeds exactly
one independently generated upload-release bundle plus, optionally, one
independently generated shared-artifact bundle.  Installation is bootstrap-only;
routine updates continue through tar-for-upload.py or sync-code.py.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
from dataclasses import dataclass
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import stat
import subprocess
import sys
import tarfile
from types import ModuleType
from typing import Iterator, Optional, Sequence


SCRIPT = Path(__file__).resolve()
ROOT = SCRIPT.parent.parent
HOSTLOCK = ROOT / "infra/docker/hostlock.py"
UPLOAD_INSTALLER = ROOT / "tools/deploy-upload-archive.py"
SHARED_INSTALLER = ROOT / "tools/deploy-shared-artifacts.py"
DEFAULT_SOURCE_MANIFEST = ROOT / "infra/docker/deployment-source-manifest.json"
BUNDLED_ROOT = Path("/opt/http-ztp/bundled-project")
PROJECT_BOOTSTRAP_ROOT = Path("/opt/http-ztp/project-bootstrap")
PROJECT_BOOTSTRAP_TOOLS = PROJECT_BOOTSTRAP_ROOT / "tools"
BOOTSTRAP_TOOL_SOURCES = {
    "package-project-image.py": SCRIPT,
    "deploy-upload-archive.py": UPLOAD_INSTALLER,
    "deploy-shared-artifacts.py": SHARED_INSTALLER,
}
BOOTSTRAP_TOOL_LABELS = {
    "package-project-image.py": (
        "com.nvidia.http-ztp.project-bootstrap-package-sha256"
    ),
    "deploy-upload-archive.py": (
        "com.nvidia.http-ztp.project-bootstrap-upload-sha256"
    ),
    "deploy-shared-artifacts.py": (
        "com.nvidia.http-ztp.project-bootstrap-shared-sha256"
    ),
}
IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
MAX_AUTHORITY = 16 * 1024 * 1024
MAX_PROJECT_INPUT = 64 * 1024 * 1024
MAX_UPLOAD = 8 * 1024 * 1024 * 1024
MAX_IMAGE = 64 * 1024 * 1024 * 1024
SAFE_BOOTSTRAP_DIRECTORIES = frozenset({"image", "apps", "firmware"})
SAFE_DEPLOYMENT_LOCK_MODES = frozenset({0o600, 0o644})
SAFE_EXEC_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
IMAGE_CONTRACT = "3"


class ProjectImageError(RuntimeError):
    """A project image input or lifecycle boundary is unsafe."""


def _absolute_unresolved(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _reject_symlink_ancestors(path: Path, label: str) -> Path:
    """Return one absolute path only when every existing component is real."""
    absolute = _absolute_unresolved(path)
    cursor = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        cursor /= part
        try:
            metadata = cursor.lstat()
        except FileNotFoundError:
            raise ProjectImageError(f"{label} is missing: {cursor}")
        except OSError as exc:
            raise ProjectImageError(
                f"cannot inspect {label} ancestor {cursor}: {exc}"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise ProjectImageError(f"{label} has a symlink ancestor: {cursor}")
    return absolute


@dataclass(frozen=True)
class UploadAuthority:
    bundle: Path
    project: str
    archive: Path
    installer: Path
    metadata: Path
    archive_size: int
    archive_sha256: str
    source_manifest_sha256: str
    installer_sha256: str


@dataclass(frozen=True)
class SharedAuthority:
    bundle: Path
    project: str
    archive: Path
    installer: Path
    metadata: Path
    archive_size: int
    archive_sha256: str
    installer_sha256: str
    metadata_value: dict[str, object]


@dataclass(frozen=True)
class BuildResult:
    output: Path
    project: str
    image_id: str
    image_archive_sha256: str
    deployment_scope: Optional[str] = None
    switch_scope: Optional[str] = None
    mini: bool = False
    upgrade_policy: str = "enabled"


@dataclass(frozen=True)
class InstallResult:
    project: str
    upload_archive_sha256: str
    source_manifest_sha256: str
    shared_archive_sha256: Optional[str]
    bootstrap_tools: dict[str, str]
    verify_only: bool
    upgrade_policy: str = "enabled"
    image_contract: str = IMAGE_CONTRACT


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    actions = result.add_subparsers(dest="action", required=True)
    build = actions.add_parser(
        "build", help="derive and export one offline project-specific image",
    )
    build.add_argument("upload_bundle", type=Path, metavar="UPLOAD_BUNDLE")
    build.add_argument("--base-image", required=True, metavar="IMAGE_ID")
    build.add_argument("--output", required=True, type=Path, metavar="DIRECTORY")
    build.add_argument("--shared-bundle", type=Path, metavar="DIRECTORY")
    build.add_argument(
        "--no-upgrade", action="store_true",
        help="bind this project image to the no-switch-upgrade deployment path",
    )
    build.add_argument(
        "--source-manifest", type=Path, default=DEFAULT_SOURCE_MANIFEST,
        help=argparse.SUPPRESS,
    )
    build.add_argument(
        "--architecture", choices=("amd64", "arm64"), help=argparse.SUPPRESS,
    )
    install = actions.add_parser(
        "install", help="verify or bootstrap the release embedded in this image",
    )
    install.add_argument("--root", type=Path, default=Path("/var/www/html"))
    install.add_argument("--verify-only", action="store_true")
    install.add_argument(
        "--machine-readable", action="store_true", help=argparse.SUPPRESS,
    )
    return result


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short write")
        view = view[written:]


def _stable_file(
    path: Path, *, required_uid: int, maximum_size: int,
    allow_empty: bool = False,
) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        direct = os.lstat(path)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != required_uid
            or before.st_mode & 0o022
            or (not allow_empty and before.st_size <= 0)
            or before.st_size < 0
            or before.st_size > maximum_size
            or (before.st_dev, before.st_ino) != (direct.st_dev, direct.st_ino)
        ):
            raise ProjectImageError(f"unsafe project-image authority: {path}")
        remaining = before.st_size
        blocks = []
        while remaining:
            block = os.read(descriptor, min(remaining, 4 * 1024 * 1024))
            if not block:
                raise ProjectImageError(f"authority was truncated: {path}")
            blocks.append(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise ProjectImageError(f"authority grew while reading: {path}")
        after = os.fstat(descriptor)
        current = os.lstat(path)
        keys = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, key) != getattr(after, key) for key in keys):
            raise ProjectImageError(f"authority changed while reading: {path}")
        if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
            raise ProjectImageError(f"authority path changed while reading: {path}")
        return b"".join(blocks), before
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def sha256_file(
    path: Path, *, required_uid: Optional[int] = None,
    maximum_size: int = MAX_IMAGE,
) -> str:
    if required_uid is None:
        required_uid = os.geteuid()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        direct = os.lstat(path)
        if (
            not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_uid != required_uid or before.st_mode & 0o022
            or before.st_size <= 0 or before.st_size > maximum_size
            or (before.st_dev, before.st_ino) != (direct.st_dev, direct.st_ino)
        ):
            raise ProjectImageError(f"unsafe file for stable hash: {path}")
        digest = hashlib.sha256()
        total = 0
        while True:
            block = os.read(descriptor, 4 * 1024 * 1024)
            if not block:
                break
            total += len(block)
            digest.update(block)
        after = os.fstat(descriptor)
        current = os.lstat(path)
        keys = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if total != before.st_size or any(
            getattr(before, key) != getattr(after, key) for key in keys
        ) or (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
            raise ProjectImageError(f"file changed while hashing: {path}")
        return digest.hexdigest()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _private_write(path: Path, payload: bytes, mode: int = 0o600) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        os.fchmod(descriptor, mode)
    finally:
        os.close(descriptor)


def _load_module(
    name: str, path: Path, *, required_uid: int,
    expected_sha256: str,
) -> ModuleType:
    """Compile only the exact, stably read local installer bytes we trusted."""
    if not DIGEST.fullmatch(expected_sha256):
        raise ProjectImageError("trusted installer digest is invalid")
    path = _reject_symlink_ancestors(path, "trusted installer")
    payload, _ = _stable_file(
        path, required_uid=required_uid, maximum_size=MAX_AUTHORITY,
    )
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise ProjectImageError(
            f"trusted installer changed before execution: {path}"
        )
    module = ModuleType(name)
    module.__file__ = os.fspath(path)
    module.__package__ = ""
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        code = compile(payload, os.fspath(path), "exec", dont_inherit=True)
        exec(code, module.__dict__)
    except Exception as exc:
        raise ProjectImageError(f"cannot load bundled authority {path}: {exc}") from exc
    finally:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
    return module


def _bundle_directory(
    path: Path, *, required_uid: int, expected_names: set[str],
) -> Path:
    raw = _reject_symlink_ancestors(path, "project-image bundle directory")
    direct = os.lstat(raw)
    if (
        not stat.S_ISDIR(direct.st_mode) or stat.S_ISLNK(direct.st_mode)
        or direct.st_uid != required_uid or direct.st_mode & 0o022
    ):
        raise ProjectImageError(f"unsafe project-image bundle directory: {raw}")
    path = raw.resolve(strict=True)
    resolved = os.lstat(path)
    if (direct.st_dev, direct.st_ino) != (resolved.st_dev, resolved.st_ino):
        raise ProjectImageError(f"project-image bundle directory identity changed: {raw}")
    names = {item.name for item in path.iterdir()}
    if names != expected_names:
        raise ProjectImageError(
            f"bundle members do not match contract: expected={sorted(expected_names)} "
            f"actual={sorted(names)}"
        )
    return path


def _parse_sums(payload: bytes, expected: set[str]) -> dict[str, str]:
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise ProjectImageError(f"SHA256SUMS is not ASCII: {exc}") from exc
    result = {}
    for line in lines:
        fields = line.split("  ", 1)
        if len(fields) != 2 or not DIGEST.fullmatch(fields[0]) or fields[1] in result:
            raise ProjectImageError("SHA256SUMS contains an invalid record")
        if not SAFE_NAME.fullmatch(fields[1]):
            raise ProjectImageError("SHA256SUMS contains an unsafe filename")
        result[fields[1]] = fields[0]
    if set(result) != expected:
        raise ProjectImageError("SHA256SUMS does not cover the exact bundle")
    return result


def verify_upload_bundle(path: Path, *, required_uid: int = 0) -> UploadAuthority:
    names = {
        "deploy-upload-archive.py", "upload-metadata.json", "SHA256SUMS",
    }
    preliminary = _reject_symlink_ancestors(
        path, "project-image upload bundle directory",
    )
    candidates = [item.name for item in preliminary.iterdir() if item.name.endswith("-upload.tar.gz")]
    if len(candidates) != 1:
        raise ProjectImageError("upload bundle must contain exactly one upload archive")
    archive_name = candidates[0]
    names.add(archive_name)
    bundle = _bundle_directory(path, required_uid=required_uid, expected_names=names)
    metadata_bytes, _ = _stable_file(
        bundle / "upload-metadata.json", required_uid=required_uid,
        maximum_size=MAX_AUTHORITY,
    )
    sums_bytes, _ = _stable_file(
        bundle / "SHA256SUMS", required_uid=required_uid,
        maximum_size=MAX_AUTHORITY,
    )
    try:
        metadata = json.loads(metadata_bytes.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProjectImageError(f"upload metadata is invalid: {exc}") from exc
    required_keys = {
        "artifact_type", "schema_version", "project", "runtime",
        "source_manifest_sha256", "upload_archive", "installer",
    }
    if not isinstance(metadata, dict) or set(metadata) != required_keys:
        raise ProjectImageError("upload metadata schema does not match")
    project = metadata.get("project")
    source_sha = metadata.get("source_manifest_sha256")
    if (
        metadata.get("artifact_type") != "http-ztp-upload-release"
        or metadata.get("schema_version") != 1
        or metadata.get("runtime") != "docker"
        or not isinstance(project, str) or not SAFE_NAME.fullmatch(project)
        or not isinstance(source_sha, str) or not DIGEST.fullmatch(source_sha)
    ):
        raise ProjectImageError("upload metadata identity does not match")
    archive_meta = metadata.get("upload_archive")
    installer_meta = metadata.get("installer")
    for value, expected_name in (
        (archive_meta, archive_name),
        (installer_meta, "deploy-upload-archive.py"),
    ):
        if (
            not isinstance(value, dict)
            or set(value) != {"name", "size", "sha256"}
            or value.get("name") != expected_name
            or type(value.get("size")) is not int or value["size"] <= 0
            or not isinstance(value.get("sha256"), str)
            or not DIGEST.fullmatch(value["sha256"])
        ):
            raise ProjectImageError("upload metadata file authority does not match")
    sums = _parse_sums(
        sums_bytes,
        {archive_name, "deploy-upload-archive.py", "upload-metadata.json"},
    )
    paths = {
        archive_name: bundle / archive_name,
        "deploy-upload-archive.py": bundle / "deploy-upload-archive.py",
        "upload-metadata.json": bundle / "upload-metadata.json",
    }
    for name, item in paths.items():
        observed = sha256_file(
            item, required_uid=required_uid,
            maximum_size=MAX_UPLOAD if name == archive_name else MAX_AUTHORITY,
        )
        if sums[name] != observed:
            raise ProjectImageError(f"upload bundle checksum mismatch: {name}")
    if (
        archive_meta["sha256"] != sums[archive_name]
        or archive_meta["size"] != paths[archive_name].stat().st_size
        or installer_meta["sha256"] != sums["deploy-upload-archive.py"]
        or installer_meta["size"] != paths["deploy-upload-archive.py"].stat().st_size
    ):
        raise ProjectImageError("upload metadata does not match bundle bytes")
    canonical_installer = _reject_symlink_ancestors(
        UPLOAD_INSTALLER, "trusted upload installer",
    )
    canonical_installer_sha = sha256_file(
        canonical_installer, required_uid=required_uid, maximum_size=MAX_AUTHORITY,
    )
    if canonical_installer_sha != installer_meta["sha256"]:
        raise ProjectImageError(
            "upload bundle installer does not match the trusted local installer"
        )
    installer = _load_module(
        "_http_ztp_project_upload_installer", canonical_installer,
        required_uid=required_uid,
        expected_sha256=installer_meta["sha256"],
    )
    try:
        verified = installer.verify_inputs(
            paths[archive_name], paths["deploy-upload-archive.py"],
            required_uid=required_uid,
        )
    except Exception as exc:
        raise ProjectImageError(f"upload archive/installer verification failed: {exc}") from exc
    if (
        verified.project != project
        or verified.archive_sha256 != archive_meta["sha256"]
        or verified.source_manifest_sha256 != source_sha
    ):
        raise ProjectImageError("upload archive authority differs from metadata")
    return UploadAuthority(
        bundle=bundle, project=project,
        archive=paths[archive_name], installer=paths["deploy-upload-archive.py"],
        metadata=paths["upload-metadata.json"],
        archive_size=archive_meta["size"], archive_sha256=archive_meta["sha256"],
        source_manifest_sha256=source_sha,
        installer_sha256=installer_meta["sha256"],
    )


def verify_shared_bundle(path: Path, *, required_uid: int = 0) -> SharedAuthority:
    names = {
        "shared-artifacts.tar.gz", "deploy-shared-artifacts.py",
        "artifact-metadata.json", "SHA256SUMS",
    }
    bundle = _bundle_directory(path, required_uid=required_uid, expected_names=names)
    installer_path = bundle / "deploy-shared-artifacts.py"
    metadata_path = bundle / "artifact-metadata.json"
    archive_path = bundle / "shared-artifacts.tar.gz"
    sums_bytes, _ = _stable_file(
        bundle / "SHA256SUMS", required_uid=required_uid,
        maximum_size=MAX_AUTHORITY,
    )
    sums = _parse_sums(
        sums_bytes,
        {
            "shared-artifacts.tar.gz", "deploy-shared-artifacts.py",
            "artifact-metadata.json",
        },
    )
    observed = {
        "shared-artifacts.tar.gz": sha256_file(
            archive_path, required_uid=required_uid, maximum_size=MAX_UPLOAD,
        ),
        "deploy-shared-artifacts.py": sha256_file(
            installer_path, required_uid=required_uid,
            maximum_size=MAX_AUTHORITY,
        ),
        "artifact-metadata.json": sha256_file(
            metadata_path, required_uid=required_uid,
            maximum_size=MAX_AUTHORITY,
        ),
    }
    if sums != observed:
        raise ProjectImageError("shared-artifact bundle checksum mismatch")
    bundled_installer_sha = sha256_file(
        installer_path, required_uid=required_uid, maximum_size=MAX_AUTHORITY,
    )
    canonical_installer = _reject_symlink_ancestors(
        SHARED_INSTALLER, "trusted shared-artifact installer",
    )
    canonical_installer_sha = sha256_file(
        canonical_installer, required_uid=required_uid, maximum_size=MAX_AUTHORITY,
    )
    if bundled_installer_sha != canonical_installer_sha:
        raise ProjectImageError(
            "shared-artifact bundle installer does not match the trusted local installer"
        )
    installer = _load_module(
        "_http_ztp_project_shared_installer", canonical_installer,
        required_uid=required_uid, expected_sha256=bundled_installer_sha,
    )
    try:
        verified = installer.verify_bundle(
            archive_path,
            installer_path=installer_path,
            metadata_path=metadata_path,
            required_uid=required_uid,
        )
    except Exception as exc:
        raise ProjectImageError(f"shared-artifact bundle verification failed: {exc}") from exc
    metadata_bytes, _ = _stable_file(
        metadata_path, required_uid=required_uid, maximum_size=MAX_AUTHORITY,
    )
    try:
        metadata = json.loads(metadata_bytes.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProjectImageError(f"shared-artifact metadata is invalid: {exc}") from exc
    project = metadata.get("project") if isinstance(metadata, dict) else None
    archive_sha = observed["shared-artifacts.tar.gz"]
    if not isinstance(project, str) or not SAFE_NAME.fullmatch(project):
        raise ProjectImageError("shared-artifact project identity is invalid")
    if getattr(verified, "archive_sha256", archive_sha) != archive_sha:
        raise ProjectImageError("shared-artifact verifier returned a different digest")
    return SharedAuthority(
        bundle=bundle, project=project, archive=archive_path,
        installer=installer_path, metadata=metadata_path,
        archive_size=archive_path.stat().st_size, archive_sha256=archive_sha,
        installer_sha256=bundled_installer_sha,
        metadata_value=metadata,
    )


def _upload_project_input_identities(
    upload: UploadAuthority, names: set[str], *, required_uid: int,
) -> dict[str, dict[str, object]]:
    """Read only the shared-selection inputs from one already verified upload."""
    expected = {
        f"DAY0-Prepare/{upload.project}/{name}": name for name in names
    }
    identities: dict[str, dict[str, object]] = {}
    try:
        with tarfile.open(upload.archive, "r|gz") as archive:
            for member in archive:
                normalized = member.name
                while normalized.startswith("./"):
                    normalized = normalized[2:]
                name = expected.get(normalized)
                if name is None:
                    continue
                if name in identities or not member.isfile():
                    raise ProjectImageError(
                        f"upload project input is duplicate or not regular: {name}"
                    )
                if member.size <= 0 or member.size > MAX_PROJECT_INPUT:
                    raise ProjectImageError(
                        f"upload project input size is unsafe: {name}"
                    )
                stream = archive.extractfile(member)
                if stream is None:
                    raise ProjectImageError(f"cannot read upload project input: {name}")
                digest = hashlib.sha256()
                total = 0
                while True:
                    block = stream.read(1024 * 1024)
                    if not block:
                        break
                    digest.update(block)
                    total += len(block)
                if total != member.size:
                    raise ProjectImageError(f"upload project input was truncated: {name}")
                identities[name] = {"sha256": digest.hexdigest(), "size": total}
    except (OSError, tarfile.TarError) as exc:
        raise ProjectImageError(f"cannot inspect upload project inputs: {exc}") from exc
    if set(identities) != names:
        missing = ", ".join(sorted(names - set(identities)))
        raise ProjectImageError(f"upload release is missing shared project input: {missing}")
    return identities


def validate_shared_upload_binding(
    upload: UploadAuthority, shared: SharedAuthority, *, required_uid: int,
) -> None:
    """Bind an optional shared selection to the exact upload project bytes."""
    if shared.project != upload.project:
        raise ProjectImageError("upload and shared-artifact projects do not match")
    inputs = shared.metadata_value.get("inputs")
    if not isinstance(inputs, dict) or not inputs:
        raise ProjectImageError("shared-artifact project input authority is missing")
    observed = _upload_project_input_identities(
        upload, set(inputs), required_uid=required_uid,
    )
    if observed != inputs:
        raise ProjectImageError(
            "shared-artifact project inputs do not match the upload release"
        )


def resolve_upgrade_policy(
    shared: Optional[SharedAuthority], no_upgrade: bool,
) -> str:
    """Bind one explicit project-image policy to any optional shared bundle."""
    requested = "disabled" if no_upgrade else "enabled"
    if shared is None:
        return requested
    bundled = shared.metadata_value.get("upgrade_policy")
    if bundled not in {"enabled", "disabled"}:
        raise ProjectImageError("shared-artifact upgrade policy is invalid")
    if bundled != requested:
        required = "--no-upgrade" if bundled == "disabled" else "no --no-upgrade"
        raise ProjectImageError(
            "project-image upgrade policy conflicts with the shared-artifact "
            f"bundle; rebuild with {required}"
        )
    return requested


def _validate_bootstrap_tool_map(value: object) -> dict[str, str]:
    if (
        not isinstance(value, dict)
        or set(value) != set(BOOTSTRAP_TOOL_SOURCES)
        or any(
            not isinstance(digest, str) or not DIGEST.fullmatch(digest)
            for digest in value.values()
        )
    ):
        raise ProjectImageError("project bootstrap tool hash authority is invalid")
    return dict(value)


def _freeze_bootstrap_tools(
    context: Path, *, required_uid: int,
) -> dict[str, str]:
    """Copy exact trusted build-time tools into the immutable project layer."""
    destination = context / "bootstrap-tools"
    destination.mkdir(mode=0o700)
    identities: dict[str, str] = {}
    for name, source in BOOTSTRAP_TOOL_SOURCES.items():
        source = _reject_symlink_ancestors(source, f"trusted bootstrap tool {name}")
        payload, _ = _stable_file(
            source, required_uid=required_uid, maximum_size=MAX_AUTHORITY,
        )
        digest = hashlib.sha256(payload).hexdigest()
        target = destination / name
        _private_write(target, payload, 0o500)
        copied, _ = _stable_file(
            target, required_uid=required_uid, maximum_size=MAX_AUTHORITY,
        )
        if copied != payload or hashlib.sha256(copied).hexdigest() != digest:
            raise ProjectImageError(f"frozen bootstrap tool changed: {name}")
        identities[name] = digest
    return identities


def _verify_bootstrap_tools(
    expected: object, *, required_uid: int,
) -> dict[str, str]:
    identities = _validate_bootstrap_tool_map(expected)
    for name, source in BOOTSTRAP_TOOL_SOURCES.items():
        source = _reject_symlink_ancestors(source, f"embedded bootstrap tool {name}")
        payload, _ = _stable_file(
            source, required_uid=required_uid, maximum_size=MAX_AUTHORITY,
        )
        if hashlib.sha256(payload).hexdigest() != identities[name]:
            raise ProjectImageError(f"embedded bootstrap tool hash mismatch: {name}")
    return identities


def render_project_dockerfile(
    base_image: str, upload: UploadAuthority,
    shared: Optional[SharedAuthority],
    *, upgrade_policy: str, bootstrap_tools: dict[str, str],
) -> str:
    if not IMAGE_ID.fullmatch(base_image):
        raise ProjectImageError("base image must be one full lowercase immutable ID")
    if upgrade_policy not in {"enabled", "disabled"}:
        raise ProjectImageError("project-image upgrade policy is invalid")
    bootstrap_tools = _validate_bootstrap_tool_map(bootstrap_tools)
    labels = [
        f'com.nvidia.http-ztp.image-contract="{IMAGE_CONTRACT}"',
        'com.nvidia.http-ztp.image-flavor="project"',
        f'com.nvidia.http-ztp.project="{upload.project}"',
        f'com.nvidia.http-ztp.upload-sha256="{upload.archive_sha256}"',
        f'com.nvidia.http-ztp.source-manifest-sha256="{upload.source_manifest_sha256}"',
        f'com.nvidia.http-ztp.upgrade-policy="{upgrade_policy}"',
    ]
    labels.extend(
        f'{BOOTSTRAP_TOOL_LABELS[name]}="{bootstrap_tools[name]}"'
        for name in BOOTSTRAP_TOOL_SOURCES
    )
    if shared is not None:
        labels.append(
            f'com.nvidia.http-ztp.shared-artifacts-sha256="{shared.archive_sha256}"',
        )
    label_lines = " \\\n      ".join(labels)
    shared_copy = (
        "COPY shared/ /opt/http-ztp/bundled-project/shared/\n"
        if shared is not None else ""
    )
    return (
        f"FROM {base_image}\n\n"
        f"LABEL {label_lines}\n\n"
        "COPY upload/ /opt/http-ztp/bundled-project/upload/\n"
        f"{shared_copy}"
        "COPY project-payload.json /opt/http-ztp/bundled-project/project-payload.json\n"
        "COPY bootstrap-tools/ /opt/http-ztp/project-bootstrap/tools/\n"
        "RUN chown -R 0:0 /opt/http-ztp/bundled-project "
        "/opt/http-ztp/project-bootstrap \\\n"
        "    && chmod 0700 /opt/http-ztp/bundled-project \\\n"
        "    && chmod 0700 /opt/http-ztp/project-bootstrap "
        "/opt/http-ztp/project-bootstrap/tools \\\n"
        "    && chmod 0500 /opt/http-ztp/project-bootstrap/tools/* \\\n"
        "    && chmod 0700 /opt/http-ztp/bundled-project/upload \\\n"
        "    && chmod 0500 /opt/http-ztp/bundled-project/upload/deploy-upload-archive.py \\\n"
        "    && chmod 0600 /opt/http-ztp/bundled-project/upload/* \\\n"
        "    && chmod 0500 /opt/http-ztp/bundled-project/upload/deploy-upload-archive.py \\\n"
        "    && chmod 0600 /opt/http-ztp/bundled-project/project-payload.json"
        + (
            " \\\n    && chmod 0700 /opt/http-ztp/bundled-project/shared"
            " \\\n    && chmod 0600 /opt/http-ztp/bundled-project/shared/*"
            " \\\n    && chmod 0500 /opt/http-ztp/bundled-project/shared/deploy-shared-artifacts.py"
            if shared is not None else ""
        )
        + "\n"
    )


def _copy_bundle(
    source: Path,
    destination: Path,
    *,
    required_uid: int,
    expected_names: Optional[set[str]] = None,
) -> None:
    destination.mkdir(mode=0o700)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_DIRECTORY", 0)
    source_descriptor = os.open(source, flags)
    try:
        directory_before = os.fstat(source_descriptor)
        direct = os.lstat(source)
        if (
            not stat.S_ISDIR(directory_before.st_mode)
            or directory_before.st_uid != required_uid
            or directory_before.st_mode & 0o022
            or (directory_before.st_dev, directory_before.st_ino)
            != (direct.st_dev, direct.st_ino)
        ):
            raise ProjectImageError(f"unsafe bundle source directory: {source}")
        names = set(os.listdir(source_descriptor))
        if expected_names is not None and names != expected_names:
            raise ProjectImageError("bundle source members changed before copy")
        for name in sorted(names):
            if not SAFE_NAME.fullmatch(name):
                raise ProjectImageError(f"unsafe bundle member name: {name}")
            maximum_size = (
                MAX_UPLOAD if name.endswith((".tar", ".tar.gz")) else MAX_AUTHORITY
            )
            member_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            member_flags |= getattr(os, "O_NOFOLLOW", 0)
            source_fd = os.open(name, member_flags, dir_fd=source_descriptor)
            destination_fd = -1
            try:
                before = os.fstat(source_fd)
                named = os.stat(name, dir_fd=source_descriptor, follow_symlinks=False)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_nlink != 1
                    or before.st_uid != required_uid
                    or before.st_mode & 0o022
                    or before.st_size <= 0
                    or before.st_size > maximum_size
                    or (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino)
                ):
                    raise ProjectImageError(f"unsafe bundle member: {source / name}")
                mode = stat.S_IMODE(before.st_mode)
                destination_fd = os.open(
                    destination / name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                    mode,
                )
                copied = 0
                while True:
                    block = os.read(source_fd, 4 * 1024 * 1024)
                    if not block:
                        break
                    _write_all(destination_fd, block)
                    copied += len(block)
                os.fsync(destination_fd)
                os.fchmod(destination_fd, mode)
                after = os.fstat(source_fd)
                current = os.stat(name, dir_fd=source_descriptor, follow_symlinks=False)
                keys = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
                if (
                    copied != before.st_size
                    or any(getattr(before, key) != getattr(after, key) for key in keys)
                    or (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino)
                ):
                    raise ProjectImageError(f"bundle member changed while copying: {source / name}")
            finally:
                if destination_fd >= 0:
                    os.close(destination_fd)
                os.close(source_fd)
        directory_after = os.fstat(source_descriptor)
        current_directory = os.lstat(source)
        directory_keys = ("st_dev", "st_ino", "st_mtime_ns", "st_ctime_ns")
        if (
            set(os.listdir(source_descriptor)) != names
            or any(
                getattr(directory_before, key) != getattr(directory_after, key)
                for key in directory_keys
            )
            or (current_directory.st_dev, current_directory.st_ino)
            != (directory_before.st_dev, directory_before.st_ino)
        ):
            raise ProjectImageError(f"bundle source directory changed while copying: {source}")
    finally:
        os.close(source_descriptor)


def _run(
    runner, command: list[str], label: str, *,
    timeout: float = 900, capture_output: bool = True,
):
    try:
        completed = runner(
            command, capture_output=capture_output, text=True, check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProjectImageError(f"{label} could not run: {exc}") from exc
    if completed.returncode != 0:
        detail = str(completed.stderr or completed.stdout or "").strip()
        raise ProjectImageError(
            f"{label} failed (exit={completed.returncode})"
            + (f": {detail}" if detail else "")
        )
    return completed


def _architecture(value: Optional[str]) -> str:
    if value in {"amd64", "arm64"}:
        return value
    machine = platform.machine().casefold()
    if machine in {"x86_64", "amd64"}:
        return "amd64"
    if machine in {"aarch64", "arm64"}:
        return "arm64"
    raise ProjectImageError(f"unsupported build architecture: {machine}")


_TEST_BEFORE_OUTPUT_PUBLISH = None
_TEST_AFTER_OUTPUT_PARENT_OPEN = None
_TEST_BEFORE_OUTPUT_STAGE_CLEANUP = None


def _open_directory_components(path: Path) -> int:
    """Open an absolute directory component by component without following links."""
    absolute = _absolute_unresolved(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(absolute.anchor, flags)
    try:
        for part in absolute.parts[1:]:
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_output_authority(
    output: Path, *, required_uid: int,
) -> tuple[Path, int, os.stat_result]:
    raw = _absolute_unresolved(output)
    if not raw.is_absolute() or not SAFE_NAME.fullmatch(raw.name):
        raise ProjectImageError(
            "project-image output must be one absolute safe directory name"
        )
    descriptor = -1
    try:
        try:
            descriptor = _open_directory_components(raw.parent)
        except OSError as exc:
            raise ProjectImageError(
                "project-image output parent has a symlink ancestor or invalid "
                f"directory component: {exc}"
            ) from exc
        opened = os.fstat(descriptor)
        named = raw.parent.lstat()
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != required_uid
            or opened.st_mode & 0o022
            or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
        ):
            raise ProjectImageError("project-image output parent identity is unsafe")
        try:
            os.stat(raw.name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError(f"project-image output already exists: {raw}")
        return raw, descriptor, opened
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def _assert_output_parent_identity(
    output: Path, expected: os.stat_result,
) -> None:
    descriptor = -1
    try:
        descriptor = _open_directory_components(output.parent)
        current = os.fstat(descriptor)
    except OSError as exc:
        raise ProjectImageError(
            f"project-image output parent changed: {exc}"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not stat.S_ISDIR(current.st_mode) or (
        current.st_dev, current.st_ino
    ) != (expected.st_dev, expected.st_ino):
        raise ProjectImageError("project-image output parent identity changed")


def _create_output_stage(
    parent_descriptor: int, prefix: str, *, required_uid: int,
) -> tuple[str, int, os.stat_result]:
    for _attempt in range(128):
        name = f"{prefix}{secrets.token_hex(16)}"
        try:
            os.mkdir(name, 0o700, dir_fd=parent_descriptor)
        except FileExistsError:
            continue
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = -1
        try:
            descriptor = os.open(name, flags, dir_fd=parent_descriptor)
            opened = os.fstat(descriptor)
            named = os.stat(
                name, dir_fd=parent_descriptor, follow_symlinks=False,
            )
            if (
                not stat.S_ISDIR(opened.st_mode)
                or opened.st_uid != required_uid
                or stat.S_IMODE(opened.st_mode) != 0o700
                or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
            ):
                raise ProjectImageError("project-image staging directory is unsafe")
            return name, descriptor, opened
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.rmdir(name, dir_fd=parent_descriptor)
            except OSError:
                pass
            raise
    raise ProjectImageError("cannot allocate a unique project-image staging directory")


@contextmanager
def _working_directory(descriptor: int) -> Iterator[None]:
    """Run path-only tooling from one already opened directory identity."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    target = os.fstat(descriptor)
    if not stat.S_ISDIR(target.st_mode):
        raise ProjectImageError("project-image working directory is not a directory")
    previous = os.open(".", flags)
    changed = False
    try:
        changed = True
        os.fchdir(descriptor)
        current = os.stat(".", follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (target.st_dev, target.st_ino):
            raise ProjectImageError("project-image working directory identity changed")
        yield
    finally:
        try:
            if changed:
                os.fchdir(previous)
        finally:
            os.close(previous)


def _detach_directory_for_cleanup(
    parent_descriptor: int,
    name: str,
    descriptor: int,
    identity: os.stat_result,
    *,
    required_uid: int,
    label: str,
) -> str:
    """Move the exact held directory to an unpredictable cleanup name.

    The no-replace rename is followed by an inode check.  If the source name
    was replaced in the final lookup window, the moved replacement is restored
    and never removed.  Callers clear the held inode before this operation, so
    a displaced original cannot retain a large private payload.
    """
    if not SAFE_NAME.fullmatch(name):
        raise ProjectImageError(f"unsafe {label} cleanup name")
    opened = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or opened.st_uid != required_uid
        or opened.st_mode & 0o022
        or (opened.st_dev, opened.st_ino) != (identity.st_dev, identity.st_ino)
    ):
        raise ProjectImageError(f"{label} descriptor identity changed during cleanup")
    try:
        named = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError as exc:
        raise ProjectImageError(
            f"{label} identity changed during cleanup; opened contents were cleared"
        ) from exc
    if (
        not stat.S_ISDIR(named.st_mode)
        or (named.st_dev, named.st_ino) != (identity.st_dev, identity.st_ino)
    ):
        raise ProjectImageError(
            f"{label} identity changed during cleanup; replacement was not touched"
        )

    detached_name = f".http-ztp-project-cleanup.{secrets.token_hex(16)}"
    _rename_directory_noreplace(
        Path(name), Path(detached_name), directory_fd=parent_descriptor,
    )
    moved = os.stat(
        detached_name, dir_fd=parent_descriptor, follow_symlinks=False,
    )
    if (moved.st_dev, moved.st_ino) != (identity.st_dev, identity.st_ino):
        try:
            _rename_directory_noreplace(
                Path(detached_name), Path(name), directory_fd=parent_descriptor,
            )
            restored = os.stat(
                name, dir_fd=parent_descriptor, follow_symlinks=False,
            )
        except (OSError, ProjectImageError) as rollback_error:
            raise ProjectImageError(
                f"{label} source changed during cleanup and replacement rollback failed"
            ) from rollback_error
        if (restored.st_dev, restored.st_ino) != (moved.st_dev, moved.st_ino):
            raise ProjectImageError(
                f"{label} replacement rollback changed identity"
            )
        raise ProjectImageError(
            f"{label} source changed during cleanup; replacement was restored"
        )
    return detached_name


def _remove_detached_directory(
    parent_descriptor: int,
    detached_name: str,
    descriptor: int,
    identity: os.stat_result,
    *,
    label: str,
) -> None:
    """Remove an empty directory only under its fresh random detached name."""
    opened = os.fstat(descriptor)
    current = os.stat(
        detached_name, dir_fd=parent_descriptor, follow_symlinks=False,
    )
    if (
        not stat.S_ISDIR(opened.st_mode)
        or not stat.S_ISDIR(current.st_mode)
        or (opened.st_dev, opened.st_ino) != (identity.st_dev, identity.st_ino)
        or (current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino)
    ):
        raise ProjectImageError(f"{label} detached identity changed before removal")
    os.rmdir(detached_name, dir_fd=parent_descriptor)
    os.fsync(parent_descriptor)


def _detach_regular_file_for_cleanup(
    parent_descriptor: int,
    name: str,
    descriptor: int,
    identity: os.stat_result,
    *,
    required_uid: int,
    label: str,
) -> str:
    """Detach the exact held regular inode or restore a raced replacement."""
    if not SAFE_NAME.fullmatch(name):
        raise ProjectImageError(f"unsafe {label} cleanup name")
    opened = os.fstat(descriptor)
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_uid != required_uid
        or opened.st_nlink != 1
        or opened.st_mode & 0o022
        or (opened.st_dev, opened.st_ino) != (identity.st_dev, identity.st_ino)
    ):
        raise ProjectImageError(f"{label} descriptor identity changed during cleanup")
    try:
        named = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError as exc:
        raise ProjectImageError(
            f"{label} identity changed during cleanup; opened contents were cleared"
        ) from exc
    if (
        not stat.S_ISREG(named.st_mode)
        or (named.st_dev, named.st_ino) != (identity.st_dev, identity.st_ino)
    ):
        raise ProjectImageError(
            f"{label} identity changed during cleanup; replacement was not touched"
        )

    detached_name = f".http-ztp-project-cleanup.{secrets.token_hex(16)}"
    _rename_directory_noreplace(
        Path(name), Path(detached_name), directory_fd=parent_descriptor,
    )
    moved = os.stat(
        detached_name, dir_fd=parent_descriptor, follow_symlinks=False,
    )
    if (moved.st_dev, moved.st_ino) != (identity.st_dev, identity.st_ino):
        try:
            _rename_directory_noreplace(
                Path(detached_name), Path(name), directory_fd=parent_descriptor,
            )
            restored = os.stat(
                name, dir_fd=parent_descriptor, follow_symlinks=False,
            )
        except (OSError, ProjectImageError) as rollback_error:
            raise ProjectImageError(
                f"{label} source changed during cleanup and replacement rollback failed"
            ) from rollback_error
        if (restored.st_dev, restored.st_ino) != (moved.st_dev, moved.st_ino):
            raise ProjectImageError(
                f"{label} replacement rollback changed identity"
            )
        raise ProjectImageError(
            f"{label} source changed during cleanup; replacement was restored"
        )
    return detached_name


def _remove_detached_regular_file(
    parent_descriptor: int,
    detached_name: str,
    descriptor: int,
    identity: os.stat_result,
    *,
    label: str,
) -> None:
    opened = os.fstat(descriptor)
    current = os.stat(
        detached_name, dir_fd=parent_descriptor, follow_symlinks=False,
    )
    if (
        not stat.S_ISREG(opened.st_mode)
        or not stat.S_ISREG(current.st_mode)
        or (opened.st_dev, opened.st_ino) != (identity.st_dev, identity.st_ino)
        or (current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino)
    ):
        raise ProjectImageError(f"{label} detached identity changed before removal")
    os.unlink(detached_name, dir_fd=parent_descriptor)
    os.fsync(parent_descriptor)


def _clear_private_regular_file(
    parent_descriptor: int,
    name: str,
    identity: os.stat_result,
    *,
    required_uid: int,
    label: str,
) -> None:
    """Zero and remove one private file without unlinking a name replacement."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    original_mode: Optional[int] = None
    mode_changed = False
    try:
        opened = os.fstat(descriptor)
        named = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != required_uid
            or opened.st_nlink != 1
            or opened.st_mode & 0o022
            or (opened.st_dev, opened.st_ino) != (identity.st_dev, identity.st_ino)
            or (named.st_dev, named.st_ino) != (identity.st_dev, identity.st_ino)
        ):
            raise ProjectImageError(f"{label} identity changed before cleanup")
        original_mode = stat.S_IMODE(opened.st_mode)
        if not original_mode & stat.S_IWUSR:
            os.fchmod(descriptor, original_mode | stat.S_IWUSR)
            mode_changed = True
        writer = os.open(
            name,
            os.O_WRONLY | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_descriptor,
        )
        try:
            writable = os.fstat(writer)
            current = os.stat(
                name, dir_fd=parent_descriptor, follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(writable.st_mode)
                or (writable.st_dev, writable.st_ino)
                != (identity.st_dev, identity.st_ino)
                or (current.st_dev, current.st_ino)
                != (identity.st_dev, identity.st_ino)
            ):
                raise ProjectImageError(f"{label} identity changed before clearing")
            os.ftruncate(writer, 0)
            os.fsync(writer)
        finally:
            os.close(writer)
        if mode_changed:
            os.fchmod(descriptor, original_mode)
            mode_changed = False
        detached_name = _detach_regular_file_for_cleanup(
            parent_descriptor,
            name,
            descriptor,
            identity,
            required_uid=required_uid,
            label=label,
        )
        _remove_detached_regular_file(
            parent_descriptor,
            detached_name,
            descriptor,
            identity,
            label=label,
        )
    finally:
        if mode_changed and original_mode is not None:
            os.fchmod(descriptor, original_mode)
        os.close(descriptor)


def _clear_private_directory(
    descriptor: int, *, required_uid: int,
) -> None:
    """Remove only verified members below one held private directory fd."""
    for name in sorted(os.listdir(descriptor)):
        if not SAFE_NAME.fullmatch(name):
            raise ProjectImageError(
                "project-image private context contains an unsafe member name"
            )
        member = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if member.st_uid != required_uid:
            raise ProjectImageError(
                "project-image private context contains a foreign-owned member"
            )
        if stat.S_ISREG(member.st_mode):
            if member.st_nlink != 1 or member.st_mode & 0o022:
                raise ProjectImageError(
                    "project-image private context contains an unsafe regular file"
                )
            _clear_private_regular_file(
                descriptor,
                name,
                member,
                required_uid=required_uid,
                label="project-image private context file",
            )
            continue
        if not stat.S_ISDIR(member.st_mode) or member.st_mode & 0o022:
            raise ProjectImageError(
                "project-image private context contains an unsupported member"
            )
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        child = os.open(name, flags, dir_fd=descriptor)
        try:
            opened = os.fstat(child)
            if (opened.st_dev, opened.st_ino) != (member.st_dev, member.st_ino):
                raise ProjectImageError(
                    "project-image private context member identity changed"
                )
            _clear_private_directory(child, required_uid=required_uid)
            current = os.stat(
                name, dir_fd=descriptor, follow_symlinks=False,
            )
            if (
                not stat.S_ISDIR(current.st_mode)
                or (current.st_dev, current.st_ino)
                != (member.st_dev, member.st_ino)
            ):
                raise ProjectImageError(
                    "project-image private context member changed during cleanup"
                )
            detached_name = _detach_directory_for_cleanup(
                descriptor,
                name,
                child,
                opened,
                required_uid=required_uid,
                label="project-image private context member",
            )
            _remove_detached_directory(
                descriptor,
                detached_name,
                child,
                opened,
                label="project-image private context member",
            )
        finally:
            os.close(child)
    if os.listdir(descriptor):
        raise ProjectImageError("project-image private context changed during cleanup")
    os.fsync(descriptor)


def _cleanup_private_context(
    parent_descriptor: int,
    context_name: str,
    context_descriptor: int,
    context_identity: os.stat_result,
    *,
    required_uid: int,
) -> None:
    """Clear the held context, then detach only its exact original name."""
    opened = os.fstat(context_descriptor)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or opened.st_uid != required_uid
        or stat.S_IMODE(opened.st_mode) != 0o700
        or (opened.st_dev, opened.st_ino)
        != (context_identity.st_dev, context_identity.st_ino)
    ):
        raise ProjectImageError(
            "project-image private context descriptor identity changed before cleanup"
        )
    _clear_private_directory(context_descriptor, required_uid=required_uid)
    detached_name = _detach_directory_for_cleanup(
        parent_descriptor,
        context_name,
        context_descriptor,
        context_identity,
        required_uid=required_uid,
        label="project-image private context",
    )
    _remove_detached_directory(
        parent_descriptor,
        detached_name,
        context_descriptor,
        context_identity,
        label="project-image private context",
    )


def _private_write_at(
    directory_descriptor: int, name: str, payload: bytes, mode: int = 0o600,
) -> None:
    if not SAFE_NAME.fullmatch(name):
        raise ProjectImageError("unsafe project-image staged filename")
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        mode,
        dir_fd=directory_descriptor,
    )
    try:
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        os.fchmod(descriptor, mode)
    finally:
        os.close(descriptor)


def _cleanup_output_stage(
    parent_descriptor: int, stage_name: str, stage_identity: os.stat_result,
    *, required_uid: int, stage_descriptor: Optional[int] = None,
) -> None:
    hook = _TEST_BEFORE_OUTPUT_STAGE_CLEANUP
    if hook is not None:
        hook(parent_descriptor, stage_name, stage_identity)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    owns_descriptor = stage_descriptor is None
    if owns_descriptor:
        try:
            descriptor = os.open(stage_name, flags, dir_fd=parent_descriptor)
        except FileNotFoundError:
            return
    else:
        descriptor = stage_descriptor
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != required_uid
            or (opened.st_dev, opened.st_ino) != (
                stage_identity.st_dev, stage_identity.st_ino,
            )
        ):
            raise ProjectImageError(
                "project-image staging identity changed before cleanup"
            )
        for name in os.listdir(descriptor):
            member = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if not stat.S_ISREG(member.st_mode) or member.st_uid != required_uid:
                raise ProjectImageError(
                    "project-image staging cleanup found an unsafe member"
                )
            _clear_private_regular_file(
                descriptor,
                name,
                member,
                required_uid=required_uid,
                label="project-image staging file",
            )
        os.fsync(descriptor)
        detached_name = _detach_directory_for_cleanup(
            parent_descriptor,
            stage_name,
            descriptor,
            stage_identity,
            required_uid=required_uid,
            label="project-image staging",
        )
        _remove_detached_directory(
            parent_descriptor,
            detached_name,
            descriptor,
            stage_identity,
            label="project-image staging",
        )
    finally:
        if owns_descriptor:
            os.close(descriptor)


def _rename_directory_noreplace(
    source: Path, destination: Path, *, directory_fd: Optional[int] = None,
) -> None:
    """Use an OS no-replace rename; fail closed when it is unavailable."""
    encoded_source = os.fsencode(source.name if directory_fd is not None else source)
    encoded_destination = os.fsencode(
        destination.name if directory_fd is not None else destination
    )
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform.startswith("linux"):
        operation = getattr(libc, "renameat2", None)
        if operation is not None:
            operation.argtypes = (
                ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
                ctypes.c_uint,
            )
            operation.restype = ctypes.c_int
            descriptor = -100 if directory_fd is None else directory_fd
            result = operation(
                descriptor, encoded_source, descriptor, encoded_destination, 1,
            )
            if result == 0:
                return
            number = ctypes.get_errno()
            if number not in {errno.ENOSYS, errno.EINVAL}:
                raise OSError(number, os.strerror(number), os.fspath(destination))
    elif sys.platform == "darwin":
        operation = getattr(
            libc, "renameatx_np" if directory_fd is not None else "renamex_np",
            None,
        )
        if operation is not None:
            if directory_fd is None:
                operation.argtypes = (
                    ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint,
                )
                arguments = (encoded_source, encoded_destination, 0x00000004)
            else:
                operation.argtypes = (
                    ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                    ctypes.c_char_p, ctypes.c_uint,
                )
                arguments = (
                    directory_fd, encoded_source, directory_fd,
                    encoded_destination, 0x00000004,
                )
            operation.restype = ctypes.c_int
            result = operation(*arguments)
            if result == 0:
                return
            number = ctypes.get_errno()
            if number not in {errno.ENOSYS, errno.EINVAL, errno.ENOTSUP}:
                raise OSError(number, os.strerror(number), os.fspath(destination))
    raise ProjectImageError(
        "atomic no-clobber directory publication is unavailable on this platform"
    )


def _rollback_unverified_publication(
    parent_descriptor: int,
    output_name: str,
    preferred_restore_name: str,
    published_identity: os.stat_result,
) -> str:
    """Remove an unverified inode from the public name without deleting it."""
    restore_name = preferred_restore_name
    try:
        os.stat(
            restore_name, dir_fd=parent_descriptor, follow_symlinks=False,
        )
    except FileNotFoundError:
        pass
    else:
        restore_name = (
            f".{output_name}.rejected.{secrets.token_hex(16)}"
        )
    try:
        _rename_directory_noreplace(
            Path(output_name), Path(restore_name),
            directory_fd=parent_descriptor,
        )
        restored = os.stat(
            restore_name, dir_fd=parent_descriptor, follow_symlinks=False,
        )
    except (OSError, ProjectImageError) as exc:
        raise ProjectImageError(
            "cannot remove an unverified project-image inode from the public output"
        ) from exc
    if (restored.st_dev, restored.st_ino) != (
        published_identity.st_dev, published_identity.st_ino,
    ):
        raise ProjectImageError(
            "unverified project-image publication changed during rollback"
        )
    try:
        os.stat(output_name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return restore_name
    raise ProjectImageError(
        "unverified project-image output remained public after rollback"
    )


def _publish_held_output(
    *,
    output: Path,
    parent_descriptor: int,
    parent_identity: os.stat_result,
    stage_name: str,
    stage_descriptor: int,
    stage_identity: os.stat_result,
    required_uid: int,
) -> None:
    """Publish one fd-bound stage without ever resolving its pathname again."""
    _assert_output_parent_identity(output, parent_identity)
    opened_stage = os.fstat(stage_descriptor)
    named_stage = os.stat(
        stage_name, dir_fd=parent_descriptor, follow_symlinks=False,
    )
    if (
        not stat.S_ISDIR(opened_stage.st_mode)
        or opened_stage.st_uid != required_uid
        or stat.S_IMODE(opened_stage.st_mode) != 0o700
        or (opened_stage.st_dev, opened_stage.st_ino)
        != (stage_identity.st_dev, stage_identity.st_ino)
        or (named_stage.st_dev, named_stage.st_ino)
        != (stage_identity.st_dev, stage_identity.st_ino)
    ):
        raise ProjectImageError("project-image staging identity changed before publish")
    try:
        os.stat(output.name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise ProjectImageError(f"project-image output changed before publish: {output}")
    os.fsync(stage_descriptor)
    hook = _TEST_BEFORE_OUTPUT_PUBLISH
    if hook is not None:
        hook()
    _assert_output_parent_identity(output, parent_identity)
    current_stage = os.stat(
        stage_name, dir_fd=parent_descriptor, follow_symlinks=False,
    )
    if (current_stage.st_dev, current_stage.st_ino) != (
        stage_identity.st_dev, stage_identity.st_ino,
    ):
        raise ProjectImageError("project-image staging identity changed before publish")
    try:
        _rename_directory_noreplace(
            Path(stage_name), Path(output.name), directory_fd=parent_descriptor,
        )
    except OSError as exc:
        if exc.errno in {errno.EEXIST, errno.ENOTEMPTY}:
            raise ProjectImageError(
                f"project-image output changed during no-clobber publish: {output}"
            ) from exc
        raise ProjectImageError(f"cannot publish project-image output: {exc}") from exc
    published = os.stat(
        output.name, dir_fd=parent_descriptor, follow_symlinks=False,
    )
    if (
        not stat.S_ISDIR(published.st_mode)
        or published.st_uid != required_uid
        or stat.S_IMODE(published.st_mode) != 0o700
        or (published.st_dev, published.st_ino)
        != (stage_identity.st_dev, stage_identity.st_ino)
    ):
        _rollback_unverified_publication(
            parent_descriptor,
            output.name,
            stage_name,
            published,
        )
        raise ProjectImageError("published project-image output identity is unsafe")
    try:
        _assert_output_parent_identity(output, parent_identity)
    except ProjectImageError as parent_error:
        try:
            _rename_directory_noreplace(
                Path(output.name), Path(stage_name),
                directory_fd=parent_descriptor,
            )
        except (OSError, ProjectImageError) as rollback_error:
            raise ProjectImageError(
                "project-image output parent changed after publish and rollback failed"
            ) from rollback_error
        raise ProjectImageError(
            "project-image output parent changed during publish"
        ) from parent_error
    os.fsync(parent_descriptor)


def build_project_image(
    upload_bundle: Path,
    *,
    base_image: str,
    output: Path,
    shared_bundle: Optional[Path],
    no_upgrade: bool = False,
    source_manifest: Path = DEFAULT_SOURCE_MANIFEST,
    expected_architecture: Optional[str] = None,
    required_uid: int = 0,
    runner=subprocess.run,
) -> BuildResult:
    if not IMAGE_ID.fullmatch(base_image):
        raise ProjectImageError("base image must be one full lowercase immutable ID")
    upload = verify_upload_bundle(upload_bundle, required_uid=required_uid)
    shared = (
        verify_shared_bundle(shared_bundle, required_uid=required_uid)
        if shared_bundle is not None else None
    )
    if shared is not None and shared.project != upload.project:
        raise ProjectImageError("upload and shared-artifact projects do not match")
    if shared is not None:
        validate_shared_upload_binding(
            upload, shared, required_uid=required_uid,
        )
    upgrade_policy = resolve_upgrade_policy(shared, no_upgrade)
    source_manifest = _reject_symlink_ancestors(
        source_manifest, "image build source manifest",
    )
    manifest_payload, _ = _stable_file(
        source_manifest, required_uid=required_uid, maximum_size=MAX_AUTHORITY,
    )
    if hashlib.sha256(manifest_payload).hexdigest() != upload.source_manifest_sha256:
        raise ProjectImageError(
            "upload release does not match the current image build source manifest"
        )
    architecture = _architecture(expected_architecture)
    verified = _run(
        runner,
        [
            sys.executable, os.fspath(HOSTLOCK),
            "--verify-preloaded-image", base_image,
            "--expected-architecture", architecture,
            "--expected-image-flavor", "generic",
        ],
        "generic base-image verification",
    )
    if str(verified.stdout or "").strip() != base_image:
        raise ProjectImageError("generic base-image verifier changed immutable identity")

    parent_descriptor = -1
    parent_identity: Optional[os.stat_result] = None
    stage_name: Optional[str] = None
    stage_descriptor = -1
    stage_identity: Optional[os.stat_result] = None
    context_name: Optional[str] = None
    context_descriptor = -1
    context_identity: Optional[os.stat_result] = None
    previous_directory_descriptor = -1
    working_directory_changed = False
    try:
        output, parent_descriptor, parent_identity = _open_output_authority(
            output, required_uid=required_uid,
        )
        hook = _TEST_AFTER_OUTPUT_PARENT_OPEN
        if hook is not None:
            hook()
        _assert_output_parent_identity(output, parent_identity)
        stage_name, stage_descriptor, stage_identity = _create_output_stage(
            parent_descriptor, f".{output.name}.tmp.",
            required_uid=required_uid,
        )
        context_name, context_descriptor, context_identity = _create_output_stage(
            parent_descriptor, f".{output.name}.context.",
            required_uid=required_uid,
        )
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        previous_directory_descriptor = os.open(".", flags)
        working_directory_changed = True
        os.fchdir(context_descriptor)
        current_context = os.stat(".", follow_symlinks=False)
        if (current_context.st_dev, current_context.st_ino) != (
            context_identity.st_dev, context_identity.st_ino,
        ):
            raise ProjectImageError("project-image private context identity changed")
    except BaseException:
        try:
            if working_directory_changed:
                os.fchdir(previous_directory_descriptor)
        finally:
            working_directory_changed = False
            if previous_directory_descriptor >= 0:
                os.close(previous_directory_descriptor)
                previous_directory_descriptor = -1
            try:
                if (
                    context_descriptor >= 0
                    and context_name is not None
                    and context_identity is not None
                ):
                    _cleanup_private_context(
                        parent_descriptor,
                        context_name,
                        context_descriptor,
                        context_identity,
                        required_uid=required_uid,
                    )
            finally:
                if context_descriptor >= 0:
                    os.close(context_descriptor)
                    context_descriptor = -1
                try:
                    if (
                        parent_descriptor >= 0
                        and stage_descriptor >= 0
                        and stage_name is not None
                        and stage_identity is not None
                    ):
                        _cleanup_output_stage(
                            parent_descriptor, stage_name, stage_identity,
                            required_uid=required_uid,
                            stage_descriptor=stage_descriptor,
                        )
                finally:
                    if stage_descriptor >= 0:
                        os.close(stage_descriptor)
                        stage_descriptor = -1
                    if parent_descriptor >= 0:
                        os.close(parent_descriptor)
        raise

    assert parent_identity is not None
    assert stage_name is not None
    assert stage_identity is not None
    assert context_name is not None
    assert context_identity is not None
    assert context_descriptor >= 0
    assert previous_directory_descriptor >= 0
    context = Path(".")
    completed = False
    try:
        _copy_bundle(
            upload.bundle,
            context / "upload",
            required_uid=required_uid,
            expected_names={
                upload.archive.name,
                "deploy-upload-archive.py",
                "upload-metadata.json",
                "SHA256SUMS",
            },
        )
        try:
            copied_upload = verify_upload_bundle(
                context / "upload", required_uid=required_uid,
            )
        except (OSError, ProjectImageError) as exc:
            raise ProjectImageError(
                f"copied upload authority is invalid: {exc}"
            ) from exc
        if (
            copied_upload.project != upload.project
            or copied_upload.archive_size != upload.archive_size
            or copied_upload.archive_sha256 != upload.archive_sha256
            or copied_upload.source_manifest_sha256 != upload.source_manifest_sha256
            or copied_upload.installer_sha256 != upload.installer_sha256
        ):
            raise ProjectImageError("copied upload authority differs from the frozen input")
        upload = copied_upload
        if shared is not None:
            _copy_bundle(
                shared.bundle,
                context / "shared",
                required_uid=required_uid,
                expected_names={
                    "shared-artifacts.tar.gz",
                    "deploy-shared-artifacts.py",
                    "artifact-metadata.json",
                    "SHA256SUMS",
                },
            )
            try:
                copied_shared = verify_shared_bundle(
                    context / "shared", required_uid=required_uid,
                )
            except (OSError, ProjectImageError) as exc:
                raise ProjectImageError(
                    f"copied shared-artifact authority is invalid: {exc}"
                ) from exc
            if (
                copied_shared.project != shared.project
                or copied_shared.archive_size != shared.archive_size
                or copied_shared.archive_sha256 != shared.archive_sha256
            ):
                raise ProjectImageError(
                    "copied shared-artifact authority differs from the frozen input"
                )
            shared = copied_shared
        bootstrap_tools = _freeze_bootstrap_tools(
            context, required_uid=required_uid,
        )
        if bootstrap_tools["deploy-upload-archive.py"] != upload.installer_sha256:
            raise ProjectImageError(
                "frozen upload bootstrap installer differs from the upload release"
            )
        if (
            shared is not None
            and bootstrap_tools["deploy-shared-artifacts.py"]
            != shared.installer_sha256
        ):
            raise ProjectImageError(
                "frozen shared bootstrap installer differs from the shared bundle"
            )
        payload = {
            "artifact_type": "http-ztp-project-image-payload",
            "schema_version": 1,
            "image_contract": IMAGE_CONTRACT,
            "project": upload.project,
            "upload_bundle": "upload",
            "shared_bundle": "shared" if shared is not None else None,
            "upgrade_policy": upgrade_policy,
            "bootstrap_tools": bootstrap_tools,
        }
        _private_write(
            context / "project-payload.json",
            (json.dumps(payload, sort_keys=True) + "\n").encode("ascii"),
        )
        _private_write(
            context / "Dockerfile",
            render_project_dockerfile(
                base_image, upload, shared,
                upgrade_policy=upgrade_policy,
                bootstrap_tools=bootstrap_tools,
            ).encode("ascii"),
            0o600,
        )
        tag = f"http-ztp-project-{upload.project}:bundled"
        iidfile = context / "image.id"
        _run(
            runner,
            [
                "docker", "build", "--network", "none", "--pull=false",
                "--iidfile", os.fspath(iidfile),
                "--file", os.fspath(context / "Dockerfile"),
                "--tag", tag, os.fspath(context),
            ],
            "offline project-image build",
            timeout=7200,
            capture_output=False,
        )
        iid_bytes, _ = _stable_file(
            iidfile, required_uid=required_uid, maximum_size=256,
        )
        try:
            image_id = iid_bytes.decode("ascii").strip()
        except UnicodeError as exc:
            raise ProjectImageError("project-image iidfile is not ASCII") from exc
        if not IMAGE_ID.fullmatch(image_id):
            raise ProjectImageError("project-image build returned an invalid immutable ID")
        verified_project = _run(
            runner,
            [
                sys.executable, os.fspath(HOSTLOCK),
                "--verify-preloaded-image", image_id,
                "--expected-architecture", architecture,
                "--expected-image-flavor", "project",
                "--expected-project", upload.project,
                "--expected-upgrade-policy", upgrade_policy,
            ],
            "project-image contract verification",
        )
        if str(verified_project.stdout or "").strip() != image_id:
            raise ProjectImageError("project-image verifier changed immutable identity")
        archive_name = f"http-ztp-project-{upload.project}.tar"
        with _working_directory(stage_descriptor):
            archive = Path(archive_name)
            _run(
                runner,
                ["docker", "save", "--output", archive_name, image_id],
                "project-image export",
                timeout=3600,
                capture_output=False,
            )
            os.chmod(archive, 0o600)
            archive_sha = sha256_file(
                archive, required_uid=required_uid, maximum_size=MAX_IMAGE,
            )
            archive_size = archive.stat().st_size
        metadata = {
            "artifact_type": "http-ztp-project-image",
            "schema_version": 1,
            "image_contract": IMAGE_CONTRACT,
            "project": upload.project,
            "base_image_id": base_image,
            "image_id": image_id,
            "os": "linux",
            "architecture": architecture,
            "image_archive": archive_name,
            "image_archive_size": archive_size,
            "image_archive_sha256": archive_sha,
            "upload_archive_sha256": upload.archive_sha256,
            "source_manifest_sha256": upload.source_manifest_sha256,
            "upgrade_policy": upgrade_policy,
            "bootstrap_tools": bootstrap_tools,
            "shared_artifacts": (
                {
                    "archive_sha256": shared.archive_sha256,
                    "upgrade_policy": upgrade_policy,
                }
                if shared is not None else None
            ),
        }
        metadata_name = "project-image-metadata.json"
        metadata_payload = (
            json.dumps(metadata, sort_keys=True, indent=2) + "\n"
        ).encode("ascii")
        _private_write_at(
            stage_descriptor, metadata_name, metadata_payload,
        )
        metadata_sha = hashlib.sha256(metadata_payload).hexdigest()
        sums = (
            f"{archive_sha}  {archive_name}\n"
            f"{metadata_sha}  {metadata_name}\n"
        ).encode("ascii")
        _private_write_at(stage_descriptor, "SHA256SUMS", sums)
        os.fchdir(previous_directory_descriptor)
        working_directory_changed = False
        os.close(previous_directory_descriptor)
        previous_directory_descriptor = -1
        _cleanup_private_context(
            parent_descriptor,
            context_name,
            context_descriptor,
            context_identity,
            required_uid=required_uid,
        )
        os.close(context_descriptor)
        context_descriptor = -1
        _publish_held_output(
            output=output,
            parent_descriptor=parent_descriptor,
            parent_identity=parent_identity,
            stage_name=stage_name,
            stage_descriptor=stage_descriptor,
            stage_identity=stage_identity,
            required_uid=required_uid,
        )
        completed = True
        print(f"[OK] project image bundle: {output}")
        print(f"[OK] IMAGE_ID={image_id}")
        print(f"[OK] project={upload.project} upload SHA-256={upload.archive_sha256}")
        print("[INFO] this image is bootstrap-only and cannot replace generic images")
        return BuildResult(
            output=output,
            project=upload.project,
            image_id=image_id,
            image_archive_sha256=archive_sha,
            deployment_scope=(
                shared.metadata_value["deployment_scope"]
                if shared is not None else None
            ),
            switch_scope=(
                shared.metadata_value["switch_scope"]
                if shared is not None else None
            ),
            mini=bool(shared.metadata_value["mini"]) if shared is not None else False,
            upgrade_policy=upgrade_policy,
        )
    finally:
        try:
            if working_directory_changed:
                os.fchdir(previous_directory_descriptor)
        finally:
            working_directory_changed = False
            if previous_directory_descriptor >= 0:
                os.close(previous_directory_descriptor)
                previous_directory_descriptor = -1
            try:
                if context_descriptor >= 0:
                    _cleanup_private_context(
                        parent_descriptor,
                        context_name,
                        context_descriptor,
                        context_identity,
                        required_uid=required_uid,
                    )
            finally:
                if context_descriptor >= 0:
                    os.close(context_descriptor)
                    context_descriptor = -1
                try:
                    if not completed:
                        _cleanup_output_stage(
                            parent_descriptor, stage_name, stage_identity,
                            required_uid=required_uid,
                            stage_descriptor=stage_descriptor,
                        )
                finally:
                    if stage_descriptor >= 0:
                        os.close(stage_descriptor)
                    stage_descriptor = -1
                    os.close(parent_descriptor)
                    parent_descriptor = -1


def _validate_bootstrap_directory(path: Path, *, required_uid: int) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ProjectImageError(f"cannot inspect fresh bootstrap member {path}: {exc}") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != required_uid
        or stat.S_IMODE(metadata.st_mode) != 0o755
        or metadata.st_nlink < 2
    ):
        raise ProjectImageError(
            f"fresh bootstrap member must be one owner-controlled 0755 real directory: {path}"
        )


def _validate_bootstrap_lock(path: Path, *, required_uid: int) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ProjectImageError(f"cannot inspect deployment lock: {exc}") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != required_uid
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) not in SAFE_DEPLOYMENT_LOCK_MODES
    ):
        raise ProjectImageError(
            "deployment lock must be one owner-controlled single-link regular "
            "file with mode 0600 or 0644"
        )


def _validate_recoverable_shared_receipt(
    root: Path, shared: SharedAuthority, *, required_uid: int,
) -> None:
    directory = root / ".shared-artifact-receipts"
    _validate_bootstrap_directory(directory, required_uid=required_uid)
    expected_name = f"{shared.archive_sha256}.json"
    try:
        names = {item.name for item in directory.iterdir()}
    except OSError as exc:
        raise ProjectImageError(f"cannot inspect recoverable shared receipt: {exc}") from exc
    if names != {expected_name}:
        raise ProjectImageError(
            "recoverable shared receipt set does not match the embedded bundle"
        )
    receipt = directory / expected_name
    metadata = receipt.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != required_uid
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size <= 0
        or metadata.st_size > MAX_AUTHORITY
    ):
        raise ProjectImageError("recoverable shared receipt authority is unsafe")


def _safe_live_root(
    root: Path, *, required_uid: int, require_fresh: bool,
    recoverable_shared: Optional[SharedAuthority] = None,
) -> Path:
    raw = _reject_symlink_ancestors(root, "bootstrap root")
    direct = os.lstat(raw)
    if (
        not stat.S_ISDIR(direct.st_mode)
        or stat.S_ISLNK(direct.st_mode)
        or direct.st_uid != required_uid
        or stat.S_IMODE(direct.st_mode) != 0o755
        or direct.st_nlink < 2
    ):
        raise ProjectImageError(f"unsafe bootstrap root: {raw}")
    root = raw.resolve(strict=True)
    resolved = os.lstat(root)
    if (direct.st_dev, direct.st_ino) != (resolved.st_dev, resolved.st_ino):
        raise ProjectImageError(f"bootstrap root identity changed: {raw}")
    if require_fresh:
        allowed = set(SAFE_BOOTSTRAP_DIRECTORIES) | {".deployment.lock"}
        if recoverable_shared is not None:
            allowed.add(".shared-artifact-receipts")
        unexpected = sorted(item.name for item in root.iterdir() if item.name not in allowed)
        if unexpected:
            raise ProjectImageError(
                "project-specific image install is bootstrap-only; live root is not fresh: "
                + ", ".join(unexpected[:10])
            )
        for name in sorted(SAFE_BOOTSTRAP_DIRECTORIES):
            path = root / name
            if os.path.lexists(path):
                _validate_bootstrap_directory(path, required_uid=required_uid)
        lock = root / ".deployment.lock"
        if os.path.lexists(lock):
            _validate_bootstrap_lock(lock, required_uid=required_uid)
        receipt_directory = root / ".shared-artifact-receipts"
        if os.path.lexists(receipt_directory):
            if recoverable_shared is None:
                raise ProjectImageError(
                    "project-specific image install is bootstrap-only; unexpected shared receipt"
                )
            _validate_recoverable_shared_receipt(
                root, recoverable_shared, required_uid=required_uid,
            )
    return root


def _fresh_bootstrap_root(
    root: Path, *, required_uid: Optional[int] = None,
) -> Path:
    if required_uid is None:
        required_uid = os.geteuid()
    return _safe_live_root(root, required_uid=required_uid, require_fresh=True)


def _safe_bundled_root(
    root: Path, *, required_uid: int, shared_expected: Optional[bool] = None,
) -> Path:
    """Open the embedded payload only through its exact, immutable root shape."""
    raw = _reject_symlink_ancestors(root, "project-image payload root")
    direct = os.lstat(raw)
    if (
        not stat.S_ISDIR(direct.st_mode)
        or stat.S_ISLNK(direct.st_mode)
        or direct.st_uid != required_uid
        or direct.st_mode & 0o022
    ):
        raise ProjectImageError(f"unsafe project-image payload root: {raw}")
    resolved = raw.resolve(strict=True)
    current = os.lstat(resolved)
    if (direct.st_dev, direct.st_ino) != (current.st_dev, current.st_ino):
        raise ProjectImageError(f"project-image payload root identity changed: {raw}")
    if shared_expected is not None:
        expected = {"project-payload.json", "upload"}
        if shared_expected:
            expected.add("shared")
        actual = {item.name for item in resolved.iterdir()}
        if actual != expected:
            raise ProjectImageError(
                "project-image payload root members do not match metadata: "
                f"expected={sorted(expected)} actual={sorted(actual)}"
            )
    return resolved


def install_bundled_project(
    *,
    bundled_root: Path = BUNDLED_ROOT,
    root: Path = Path("/var/www/html"),
    verify_only: bool,
    required_uid: int = 0,
) -> InstallResult:
    bundled_root = _safe_bundled_root(
        bundled_root, required_uid=required_uid,
    )
    payload_bytes, _ = _stable_file(
        bundled_root / "project-payload.json",
        required_uid=required_uid,
        maximum_size=MAX_AUTHORITY,
    )
    try:
        payload = json.loads(payload_bytes.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProjectImageError(f"project payload metadata is invalid: {exc}") from exc
    if (
        not isinstance(payload, dict)
        or set(payload) != {
            "artifact_type", "schema_version", "image_contract", "project",
            "upload_bundle", "shared_bundle", "upgrade_policy",
            "bootstrap_tools",
        }
        or payload.get("artifact_type") != "http-ztp-project-image-payload"
        or payload.get("schema_version") != 1
        or not isinstance(payload.get("project"), str)
        or not SAFE_NAME.fullmatch(payload["project"])
        or payload.get("upload_bundle") != "upload"
        or payload.get("shared_bundle") not in {None, "shared"}
    ):
        raise ProjectImageError("project payload metadata schema does not match")
    if payload.get("image_contract") != IMAGE_CONTRACT:
        raise ProjectImageError(
            "project payload image contract must be exactly " + IMAGE_CONTRACT
        )
    if payload.get("upgrade_policy") not in {"enabled", "disabled"}:
        raise ProjectImageError("project payload upgrade policy is invalid")
    bootstrap_tools = _verify_bootstrap_tools(
        payload["bootstrap_tools"], required_uid=required_uid,
    )
    bundled_root = _safe_bundled_root(
        bundled_root,
        required_uid=required_uid,
        shared_expected=payload["shared_bundle"] == "shared",
    )
    upload = verify_upload_bundle(
        bundled_root / "upload", required_uid=required_uid,
    )
    if upload.project != payload["project"]:
        raise ProjectImageError("embedded upload project does not match image payload")
    shared = None
    if payload["shared_bundle"] == "shared":
        shared = verify_shared_bundle(
            bundled_root / "shared", required_uid=required_uid,
        )
        if shared.project != upload.project:
            raise ProjectImageError("embedded shared-artifact project does not match")
        validate_shared_upload_binding(
            upload, shared, required_uid=required_uid,
        )
        if shared.metadata_value.get("upgrade_policy") != payload["upgrade_policy"]:
            raise ProjectImageError(
                "embedded project upgrade policy does not match shared artifacts"
            )
    root = _safe_live_root(
        root, required_uid=required_uid, require_fresh=not verify_only,
        recoverable_shared=shared,
    )
    if shared is not None:
        shared_installer = _load_module(
            "_http_ztp_embedded_shared_installer", SHARED_INSTALLER,
            required_uid=required_uid,
            expected_sha256=shared.installer_sha256,
        )
        try:
            shared_installer.deploy_archive(
                shared.archive,
                root=root,
                verify_only=verify_only,
                installer_path=shared.installer,
                metadata_path=shared.metadata,
                required_uid=required_uid,
                # The live HTTP root can be a host bind mount while /tmp is a
                # container tmpfs.  Shared-artifact publication uses atomic
                # no-replace renames, so its private staging must stay on the
                # live root's filesystem.
                staging_parent=root,
            )
        except Exception as exc:
            raise ProjectImageError(f"embedded shared-artifact install failed: {exc}") from exc
        if not verify_only:
            root = _safe_live_root(
                root, required_uid=required_uid, require_fresh=True,
                recoverable_shared=shared,
            )
    upload_installer = _load_module(
        "_http_ztp_embedded_upload_installer", UPLOAD_INSTALLER,
        required_uid=required_uid,
        expected_sha256=upload.installer_sha256,
    )
    try:
        result = upload_installer.deploy_archive(
            upload.archive,
            root=root,
            runtime="docker",
            verify_only=verify_only,
            installer_path=upload.installer,
            required_uid=required_uid,
            python_executable=sys.executable,
            # The accepted upload can exceed the fixed /tmp tmpfs size.  Keep
            # both its stable snapshot and the guard staging on the live bind
            # mount's filesystem, under private installer-managed directories.
            staging_parent=root,
            guard_environment={
                "PATH": SAFE_EXEC_PATH,
                "PYTHONDONTWRITEBYTECODE": "1",
                "TMPDIR": os.fspath(root),
            },
        )
    except Exception as exc:
        raise ProjectImageError(f"embedded upload release install failed: {exc}") from exc
    if not verify_only and getattr(result, "next_runtime", None) != "docker":
        raise ProjectImageError("embedded upload release did not select Docker lifecycle")
    return InstallResult(
        project=upload.project,
        upload_archive_sha256=upload.archive_sha256,
        source_manifest_sha256=upload.source_manifest_sha256,
        shared_archive_sha256=(
            shared.archive_sha256 if shared is not None else None
        ),
        bootstrap_tools=bootstrap_tools,
        verify_only=verify_only,
        upgrade_policy=payload["upgrade_policy"],
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parser().parse_args(argv)
    if os.geteuid() != 0:
        print("[ERROR] run package-project-image.py as root", file=sys.stderr)
        return 1
    try:
        if args.action == "build":
            result = build_project_image(
                args.upload_bundle,
                base_image=args.base_image,
                output=args.output,
                shared_bundle=args.shared_bundle,
                no_upgrade=args.no_upgrade,
                source_manifest=args.source_manifest,
                expected_architecture=args.architecture,
            )
            print("[NEXT] copy this image bundle to the same-architecture target")
            print("       sha256sum --check SHA256SUMS")
            print(f"       sudo docker load --input http-ztp-project-{result.project}.tar")
            print("[NEXT] bootstrap the embedded release from the loaded immutable ID:")
            print(
                "       sudo docker run --rm --network none --read-only "
                "--cap-drop ALL --security-opt no-new-privileges:true "
                "--mount type=bind,src=/var/www/html,dst=/var/www/html "
                "--mount type=bind,src=/var/lib/http-ztp-container/runtime,"
                "dst=/var/lib/http-ztp-container/runtime "
                "--tmpfs /tmp:rw,nosuid,nodev,noexec,size=1g "
                "--entrypoint /usr/bin/python3 "
                f"{result.image_id} /opt/http-ztp/project-bootstrap/tools/"
                "package-project-image.py install"
            )
            if result.deployment_scope is not None:
                mini_option = " --mini" if result.mini else ""
                print(
                    f"       sudo ./infra/docker/deploy.sh init --project {result.project} "
                    f"--scope {result.deployment_scope} "
                    f"--switch {result.switch_scope}{mini_option}"
                )
            else:
                print("[NEXT] choose the deployment scope explicitly, then run:")
                print(
                    f"       sudo ./infra/docker/deploy.sh init --project {result.project} "
                    "--scope SCOPE [--switch SWITCH] [--mini]"
                )
            print(
                f"       sudo ./infra/docker/deploy.sh deploy-project-preloaded "
                f"{result.image_id}"
                + (" --no-upgrade" if result.upgrade_policy == "disabled" else "")
            )
            return 0
        installed = install_bundled_project(
            root=args.root, verify_only=args.verify_only,
        )
        if args.machine_readable:
            if not args.verify_only:
                raise ProjectImageError(
                    "--machine-readable is valid only with --verify-only"
                )
            print(json.dumps({
                "project": installed.project,
                "image_contract": installed.image_contract,
                "bootstrap_tools": installed.bootstrap_tools,
                "shared_archive_sha256": installed.shared_archive_sha256,
                "source_manifest_sha256": installed.source_manifest_sha256,
                "upload_archive_sha256": installed.upload_archive_sha256,
                "upgrade_policy": installed.upgrade_policy,
                "verified": True,
            }, ensure_ascii=True, sort_keys=True))
            return 0
        print(f"[OK] embedded project={installed.project}")
        print(f"[OK] upload SHA-256={installed.upload_archive_sha256}")
        if installed.shared_archive_sha256:
            print(f"[OK] shared artifacts SHA-256={installed.shared_archive_sha256}")
        if args.verify_only:
            print("[OK] verify-only completed; live root was not modified")
        else:
            print("[OK] project-specific image bootstrap completed")
        return 0
    except (OSError, ValueError, ProjectImageError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
