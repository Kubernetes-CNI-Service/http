#!/usr/bin/env python3
"""Deterministic, fail-closed finished-project bundle construction."""

from __future__ import annotations

from dataclasses import dataclass
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import tempfile
from typing import Any


BUNDLE_ROOT = "http-ztp-finished"
FINAL_STATE = "FINISHED_BACKUP_VERIFIED_RUNTIME_STOPPED"
TRANSACTION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
PROJECT_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
CREATED_PATTERN = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z\Z"
)
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
RECORD_PATTERN = re.compile(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}\Z")
REQUIRED_COMPONENTS = frozenset({
    "pre-stop/project.tar.gz",
    "pre-stop/deployment-source.tar.gz",
    "final-delta/delta.tar.gz",
    "final-delta/delta-manifest.json",
    "host-state/runtime.json",
    "deployment-footprint.json",
    "deletion-plan.json",
    "deletion-plan.md",
})
CONTROL_PAYLOAD_LIMIT = 4 * 1024 * 1024
MAX_OUTER_MEMBERS = 64


class BundleError(RuntimeError):
    """A source tree or bundle publication boundary is unsafe."""


@dataclass(frozen=True)
class BundleResult:
    path: Path
    record_id: str
    content_sha256: str


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _json_object(payload: bytes, label: str) -> dict[str, Any]:
    def reject_duplicates(pairs):
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise BundleError(f"{label} contains duplicate key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            payload.decode("utf-8"), object_pairs_hook=reject_duplicates,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise BundleError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise BundleError(f"{label} must be a JSON object")
    return value


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev, metadata.st_ino, metadata.st_mode,
        metadata.st_nlink, metadata.st_size, metadata.st_mtime_ns,
    )


def verify_finished_bundle(
    path: Path, *, expected_project: str, expected_transaction_id: str,
    expected_runtime: str, expected_created_at: str,
) -> BundleResult:
    """Re-derive a published bundle identity from its bytes and fixed schema."""
    path = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise BundleError(f"published bundle is unsafe or unreadable: {path}") from exc
    try:
        before = os.fstat(descriptor)
        lexical = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(lexical.st_mode)
            or before.st_nlink != 1
            or lexical.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or (before.st_dev, before.st_ino) != (lexical.st_dev, lexical.st_ino)
        ):
            raise BundleError("published bundle identity is unsafe")

        file_rows: dict[str, dict[str, Any]] = {}
        control: dict[str, bytes] = {}
        directories: set[str] = set()
        names: set[str] = set()
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            try:
                with tarfile.open(fileobj=stream, mode="r:gz") as archive:
                    members = archive.getmembers()
                    if len(members) > MAX_OUTER_MEMBERS:
                        raise BundleError("published bundle has too many members")
                    for member in members:
                        raw_name = member.name
                        candidate = PurePosixPath(raw_name)
                        if (
                            not raw_name
                            or candidate.is_absolute()
                            or ".." in candidate.parts
                            or candidate.as_posix() != raw_name
                            or not candidate.parts
                            or candidate.parts[0] != BUNDLE_ROOT
                        ):
                            raise BundleError(f"unsafe published bundle path: {raw_name!r}")
                        if raw_name in names:
                            raise BundleError(f"duplicate published bundle path: {raw_name}")
                        names.add(raw_name)
                        if member.uid != 0 or member.gid != 0 or member.mtime != 0:
                            raise BundleError(f"non-canonical metadata: {raw_name}")
                        if member.isdir():
                            if stat.S_IMODE(member.mode) != 0o700:
                                raise BundleError(f"directory mode is not 0700: {raw_name}")
                            directories.add(raw_name)
                            continue
                        if not member.isfile() or stat.S_IMODE(member.mode) != 0o600:
                            raise BundleError(f"unsafe published bundle member: {raw_name}")
                        relative = PurePosixPath(*candidate.parts[1:]).as_posix()
                        source = archive.extractfile(member)
                        if source is None:
                            raise BundleError(f"published bundle member is unreadable: {raw_name}")
                        digest = hashlib.sha256()
                        size = 0
                        retained = bytearray()
                        with source:
                            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                                size += len(chunk)
                                if relative in {"bundle-manifest.json", "SHA256SUMS"}:
                                    if size > CONTROL_PAYLOAD_LIMIT:
                                        raise BundleError(f"control payload is too large: {relative}")
                                    retained.extend(chunk)
                                digest.update(chunk)
                        if size != member.size:
                            raise BundleError(f"published bundle member size changed: {relative}")
                        file_rows[relative] = {
                            "size": size,
                            "sha256": digest.hexdigest(),
                        }
                        if retained:
                            control[relative] = bytes(retained)
                stream.seek(0)
                with gzip.GzipFile(fileobj=stream, mode="rb") as compressed:
                    for _chunk in iter(lambda: compressed.read(1024 * 1024), b""):
                        pass
            except (OSError, EOFError, gzip.BadGzipFile, tarfile.TarError) as exc:
                raise BundleError("published bundle archive is invalid") from exc

        expected_directories = {
            BUNDLE_ROOT,
            f"{BUNDLE_ROOT}/pre-stop",
            f"{BUNDLE_ROOT}/final-delta",
            f"{BUNDLE_ROOT}/host-state",
        }
        if directories != expected_directories:
            raise BundleError("published bundle directory set is not canonical")
        expected_files = REQUIRED_COMPONENTS | {"bundle-manifest.json", "SHA256SUMS"}
        if set(file_rows) != expected_files:
            raise BundleError("published bundle file set is not canonical")
        try:
            manifest_payload = control["bundle-manifest.json"]
            checksum_payload = control["SHA256SUMS"]
        except KeyError as exc:
            raise BundleError("published bundle control payload is missing") from exc

        manifest = _json_object(manifest_payload, "bundle-manifest.json")
        if set(manifest) != {
            "schema_version", "bundle_type", "project", "record_id",
            "transaction_id", "runtime", "state", "created_at",
            "content_sha256", "components",
        }:
            raise BundleError("bundle manifest schema is invalid")
        if manifest.get("schema_version") != 1 or manifest.get("bundle_type") != BUNDLE_ROOT:
            raise BundleError("bundle manifest type is invalid")
        if (
            manifest.get("project") != expected_project
            or manifest.get("transaction_id") != expected_transaction_id
            or manifest.get("runtime") != expected_runtime
            or manifest.get("created_at") != expected_created_at
            or manifest.get("state") != FINAL_STATE
        ):
            raise BundleError("bundle manifest identity does not match transaction")
        if (
            not PROJECT_PATTERN.fullmatch(expected_project)
            or not TRANSACTION_PATTERN.fullmatch(expected_transaction_id)
            or expected_runtime not in {"native", "docker"}
            or not CREATED_PATTERN.fullmatch(expected_created_at)
            or not SHA256_PATTERN.fullmatch(str(manifest.get("content_sha256", "")))
            or not RECORD_PATTERN.fullmatch(str(manifest.get("record_id", "")))
        ):
            raise BundleError("bundle manifest identity format is invalid")

        rows = manifest.get("components")
        if not isinstance(rows, list):
            raise BundleError("bundle components must be an array")
        normalized_rows: list[dict[str, Any]] = []
        component_paths: set[str] = set()
        for row in rows:
            if not isinstance(row, dict) or set(row) != {
                "path", "size", "sha256", "mode", "schema_version", "stage",
            }:
                raise BundleError("bundle component schema is invalid")
            component_path = row.get("path")
            if (
                not isinstance(component_path, str)
                or PurePosixPath(component_path).as_posix() != component_path
                or PurePosixPath(component_path).is_absolute()
                or ".." in PurePosixPath(component_path).parts
                or component_path in component_paths
                or component_path not in REQUIRED_COMPONENTS
            ):
                raise BundleError("bundle component path is unsafe or unexpected")
            component_paths.add(component_path)
            actual = file_rows[component_path]
            if (
                isinstance(row.get("size"), bool)
                or not isinstance(row.get("size"), int)
                or row.get("size") != actual["size"]
                or row.get("sha256") != actual["sha256"]
                or row.get("mode") != 0o600
                or row.get("schema_version") != 1
                or row.get("stage") != _stage(component_path)
            ):
                raise BundleError(f"bundle component identity is invalid: {component_path}")
            normalized_rows.append(dict(row))
        if component_paths != REQUIRED_COMPONENTS:
            raise BundleError("bundle required component set is incomplete")
        if normalized_rows != sorted(normalized_rows, key=lambda row: row["path"]):
            raise BundleError("bundle components are not sorted")

        identity = {
            "schema_version": 1,
            "project": expected_project,
            "transaction_id": expected_transaction_id,
            "runtime": expected_runtime,
            "state": FINAL_STATE,
            "components": normalized_rows,
        }
        content_sha256 = _sha256(json.dumps(
            identity, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode("ascii"))
        if manifest["content_sha256"] != content_sha256:
            raise BundleError("bundle content identity does not match components")
        created = CREATED_PATTERN.fullmatch(expected_created_at)
        assert created is not None
        year, month, day, hour, minute, second = created.groups()
        timestamp = f"{year}{month}{day}T{hour}{minute}{second}Z"
        record_id = f"{timestamp}-{content_sha256[:12]}"
        if manifest["record_id"] != record_id:
            raise BundleError("bundle record identity does not match content")

        try:
            checksum_text = checksum_payload.decode("ascii")
        except UnicodeError as exc:
            raise BundleError("bundle checksums are not ASCII") from exc
        if not checksum_text.endswith("\n"):
            raise BundleError("bundle checksums are not newline terminated")
        checksum_rows: dict[str, str] = {}
        raw_lines = checksum_text.splitlines()
        for line in raw_lines:
            match = re.fullmatch(r"([0-9a-f]{64})  ([^\x00-\x1f\x7f]+)", line)
            if match is None:
                raise BundleError("bundle checksum line is not canonical")
            checksum, relative = match.groups()
            if relative in checksum_rows or relative not in set(file_rows) - {"SHA256SUMS"}:
                raise BundleError("bundle checksum path is duplicate or unexpected")
            checksum_rows[relative] = checksum
        if raw_lines != sorted(raw_lines, key=lambda line: line[66:]):
            raise BundleError("bundle checksum lines are not sorted")
        if set(checksum_rows) != set(file_rows) - {"SHA256SUMS"}:
            raise BundleError("bundle checksum set is incomplete")
        for relative, checksum in checksum_rows.items():
            if checksum != file_rows[relative]["sha256"]:
                raise BundleError(f"bundle checksum failed: {relative}")

        after = os.fstat(descriptor)
        lexical_after = path.lstat()
        if (
            _file_identity(before) != _file_identity(after)
            or _file_identity(before) != _file_identity(lexical_after)
        ):
            raise BundleError("published bundle changed while verifying")
        return BundleResult(path, record_id, content_sha256)
    finally:
        os.close(descriptor)


def inventory_tree(root: Path) -> dict[str, dict[str, Any]]:
    root = Path(root)
    root_metadata = root.lstat()
    if root.is_symlink() or not stat.S_ISDIR(root_metadata.st_mode):
        raise BundleError(f"tree root must be a real directory: {root}")
    canonical = root.resolve(strict=True)
    result: dict[str, dict[str, Any]] = {}
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISDIR(metadata.st_mode):
            if path.is_symlink():
                raise BundleError(f"unsafe symlink directory: {relative}")
            result[relative] = {"type": "directory", "mode": mode}
            continue
        if stat.S_ISREG(metadata.st_mode):
            if metadata.st_nlink != 1:
                raise BundleError(f"hard link is not allowed: {relative}")
            payload = path.read_bytes()
            after = path.lstat()
            if (
                (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            ):
                raise BundleError(f"file changed while reading: {relative}")
            result[relative] = {
                "type": "file", "mode": mode, "size": len(payload),
                "sha256": _sha256(payload),
            }
            continue
        if stat.S_ISLNK(metadata.st_mode):
            target = os.readlink(path)
            try:
                resolved = path.resolve(strict=True)
                resolved.relative_to(canonical)
            except (OSError, ValueError) as exc:
                raise BundleError(f"escaping or dangling symlink is not allowed: {relative}") from exc
            result[relative] = {
                "type": "symlink", "mode": mode, "target": target,
            }
            continue
        raise BundleError(f"special file is not allowed: {relative}")
    return result


def _tar_bytes(root: Path, archive_root: str, *, allow_symlinks: bool) -> bytes:
    inventory = inventory_tree(root)
    stream = io.BytesIO()
    with gzip.GzipFile(fileobj=stream, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            top = tarfile.TarInfo(archive_root)
            top.type = tarfile.DIRTYPE
            top.mode = 0o700
            top.uid = top.gid = 0
            top.mtime = 0
            archive.addfile(top)
            for relative, record in inventory.items():
                name = f"{archive_root}/{relative}"
                info = tarfile.TarInfo(name)
                info.uid = info.gid = 0
                info.mtime = 0
                info.mode = int(record["mode"])
                if record["type"] == "directory":
                    info.type = tarfile.DIRTYPE
                    archive.addfile(info)
                elif record["type"] == "symlink":
                    if not allow_symlinks:
                        raise BundleError(f"symlink is not allowed in {archive_root}: {relative}")
                    info.type = tarfile.SYMTYPE
                    info.linkname = str(record["target"])
                    archive.addfile(info)
                else:
                    payload = (root / relative).read_bytes()
                    if _sha256(payload) != record["sha256"]:
                        raise BundleError(f"file changed before archive: {relative}")
                    info.size = len(payload)
                    archive.addfile(info, io.BytesIO(payload))
    return stream.getvalue()


def _write_private(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise BundleError(f"published component identity is unsafe: {path}")
    finally:
        os.close(descriptor)


def build_final_delta(
    before_root: Path, after_root: Path, output: Path,
) -> tuple[Path, Path]:
    before = inventory_tree(before_root)
    after = inventory_tree(after_root)
    output = Path(output)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    payload_root = output / ".payload"
    payload_root.mkdir(mode=0o700)
    changes: list[dict[str, Any]] = []
    for relative in sorted(set(before) | set(after)):
        old = before.get(relative)
        new = after.get(relative)
        if old == new:
            continue
        if (old and old["type"] != "file") or (new and new["type"] != "file"):
            raise BundleError(
                f"final delta cannot safely express non-file change: {relative}"
            )
        if old is None:
            action = "create"
        elif new is None:
            action = "delete"
        else:
            action = "replace"
        row = {
            "path": relative,
            "action": action,
            "before_sha256": old.get("sha256") if old else None,
            "sha256": new.get("sha256") if new else None,
            "size": new.get("size") if new else None,
        }
        changes.append(row)
        if new is not None:
            destination = payload_root / PurePosixPath(relative)
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            _write_private(destination, (after_root / relative).read_bytes())
    manifest = {
        "schema_version": 1,
        "base_component": "pre-stop/project.tar.gz",
        "changes": changes,
    }
    manifest_path = output / "delta-manifest.json"
    _write_private(manifest_path, _canonical_json(manifest))
    archive_path = output / "delta.tar.gz"
    archive_payload = _tar_bytes(payload_root, "delta", allow_symlinks=False)
    _write_private(archive_path, archive_payload)
    for child in sorted(payload_root.rglob("*"), reverse=True):
        child.unlink() if child.is_file() else child.rmdir()
    payload_root.rmdir()
    return manifest_path, archive_path


def _stage(path: str) -> str:
    if path.startswith("pre-stop/"):
        return "pre-stop"
    if path.startswith("final-delta/"):
        return "final-delta"
    if path.startswith("host-state/"):
        return "host-state"
    if path == "deployment-footprint.json":
        return "footprint"
    if path.startswith("deletion-plan."):
        return "deletion-plan"
    raise BundleError(f"unknown finished component stage: {path}")


def create_finished_bundle(
    *, project: str, transaction_id: str, runtime: str, created_at: str,
    pre_stop_project: Path, post_stop_project: Path, deployment_source: Path,
    host_state: dict[str, Any], deployment_footprint: dict[str, Any],
    deletion_plan: dict[str, Any], output: Path,
) -> BundleResult:
    if not PROJECT_PATTERN.fullmatch(project):
        raise BundleError("project name is unsafe")
    if not TRANSACTION_PATTERN.fullmatch(transaction_id):
        raise BundleError("transaction ID is unsafe")
    if runtime not in {"native", "docker"}:
        raise BundleError("runtime must be native or docker")
    created_match = CREATED_PATTERN.fullmatch(created_at)
    if created_match is None:
        raise BundleError("created_at must be UTC RFC3339 seconds")
    with tempfile.TemporaryDirectory(prefix="http-finished-") as temporary_name:
        temporary = Path(temporary_name)
        delta_dir = temporary / "delta"
        delta_manifest, delta_archive = build_final_delta(
            Path(pre_stop_project), Path(post_stop_project), delta_dir,
        )
        components: dict[str, bytes] = {
            "pre-stop/project.tar.gz": _tar_bytes(
                Path(pre_stop_project), "project", allow_symlinks=True,
            ),
            "pre-stop/deployment-source.tar.gz": _tar_bytes(
                Path(deployment_source), "source", allow_symlinks=True,
            ),
            "final-delta/delta.tar.gz": delta_archive.read_bytes(),
            "final-delta/delta-manifest.json": delta_manifest.read_bytes(),
            "host-state/runtime.json": _canonical_json(host_state),
            "deployment-footprint.json": _canonical_json(deployment_footprint),
            "deletion-plan.json": _canonical_json(deletion_plan),
            "deletion-plan.md": (
                "# Deletion plan\n\nNo automatic deletion. Review JSON categories.\n"
            ).encode("utf-8"),
        }
        rows = [
            {
                "path": path,
                "size": len(payload),
                "sha256": _sha256(payload),
                "mode": 0o600,
                "schema_version": 1,
                "stage": _stage(path),
            }
            for path, payload in sorted(components.items())
        ]
        identity = {
            "schema_version": 1,
            "project": project,
            "transaction_id": transaction_id,
            "runtime": runtime,
            "state": FINAL_STATE,
            "components": rows,
        }
        content_sha256 = _sha256(json.dumps(
            identity, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode("ascii"))
        year, month, day, hour, minute, second = created_match.groups()
        timestamp = f"{year}{month}{day}T{hour}{minute}{second}Z"
        record_id = f"{timestamp}-{content_sha256[:12]}"
        manifest = {
            **identity,
            "bundle_type": BUNDLE_ROOT,
            "created_at": created_at,
            "record_id": record_id,
            "content_sha256": content_sha256,
        }
        manifest_payload = _canonical_json(manifest)
        checksummed = {**components, "bundle-manifest.json": manifest_payload}
        checksum_payload = "".join(
            f"{_sha256(payload)}  {path}\n"
            for path, payload in sorted(checksummed.items())
        ).encode("ascii")
        files = {
            **components,
            "bundle-manifest.json": manifest_payload,
            "SHA256SUMS": checksum_payload,
        }
        outer = io.BytesIO()
        directories = {
            BUNDLE_ROOT,
            f"{BUNDLE_ROOT}/pre-stop",
            f"{BUNDLE_ROOT}/final-delta",
            f"{BUNDLE_ROOT}/host-state",
        }
        with gzip.GzipFile(fileobj=outer, mode="wb", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                for directory in sorted(directories):
                    info = tarfile.TarInfo(directory)
                    info.type = tarfile.DIRTYPE
                    info.mode = 0o700
                    info.uid = info.gid = 0
                    info.mtime = 0
                    archive.addfile(info)
                for relative, payload in sorted(files.items()):
                    info = tarfile.TarInfo(f"{BUNDLE_ROOT}/{relative}")
                    info.mode = 0o600
                    info.uid = info.gid = 0
                    info.mtime = 0
                    info.size = len(payload)
                    archive.addfile(info, io.BytesIO(payload))
        output = Path(output)
        _write_private(output, outer.getvalue())
        return BundleResult(output, record_id, content_sha256)
