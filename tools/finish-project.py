#!/usr/bin/env python3
"""Create a resumable, fail-closed finished-project bundle."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import uuid
from typing import Any

REPOSITORY = Path(__file__).resolve().parents[1]
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from tools.deployment_lock import deployment_lock
from tools.finished_bundle import (
    BUNDLE_ROOT,
    BundleResult,
    create_finished_bundle,
    inventory_tree,
    verify_finished_bundle,
)
from tools import finished_project_state as state
from tools.project_contract import require_project_eligible


FOOTPRINT_NAME = "deployment-footprint.json"


class FinishProjectError(RuntimeError):
    """The requested project cannot be safely planned or finished."""


@dataclass(frozen=True)
class FinishResult:
    transaction_id: str
    bundle_path: Path
    record_id: str
    content_sha256: str


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_project(repository: Path, project_name: str) -> Path:
    repository = Path(repository).resolve(strict=True)
    if not state.PROJECT_PATTERN.fullmatch(project_name):
        raise FinishProjectError("project name is invalid")
    day0 = repository / "DAY0-Prepare"
    try:
        day0_real = day0.resolve(strict=True)
        candidate = day0 / project_name
        metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise FinishProjectError("project must be a real direct child of DAY0-Prepare") from exc
    if (
        candidate.is_symlink()
        or not candidate.is_dir()
        or resolved.parent != day0_real
        or resolved != candidate.absolute()
        or not os.path.isdir(candidate)
        or not metadata.st_nlink
    ):
        raise FinishProjectError("project must be a real direct child of DAY0-Prepare")
    try:
        require_project_eligible(resolved)
    except ValueError as exc:
        raise FinishProjectError(f"project is not eligible for finish: {exc}") from exc
    return resolved


def _read_footprint(state_root: Path, project_name: str) -> tuple[dict[str, Any], bool]:
    path = Path(state_root) / FOOTPRINT_NAME
    if not os.path.lexists(path):
        return ({
            "schema_version": 1,
            "project": project_name,
            "legacy_without_footprint": True,
            "paths": [],
        }, True)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FinishProjectError(f"deployment footprint is invalid: {exc}") from exc
    if not isinstance(value, dict) or value.get("project") != project_name:
        raise FinishProjectError("deployment footprint project identity does not match")
    return value, False


def build_plan(
    *, repository: Path, project_name: str, runtime: str,
    state_root: Path = state.FINISH_STATE_ROOT,
) -> dict[str, Any]:
    if runtime not in {"native", "docker"}:
        raise FinishProjectError("runtime must be native or docker")
    project = resolve_project(repository, project_name)
    project_inventory = inventory_tree(project)
    footprint, legacy = _read_footprint(Path(state_root), project_name)
    total_bytes = sum(
        int(row.get("size", 0)) for row in project_inventory.values()
        if row["type"] == "file"
    )
    return {
        "schema_version": 1,
        "project": project_name,
        "project_path": str(project),
        "runtime": runtime,
        "project_objects": len(project_inventory),
        "project_bytes": total_bytes,
        "legacy_without_footprint": legacy,
        "requires_runtime_only_stop": legacy,
        "deletion_class": "CONDITIONAL" if legacy else "SAFE_TO_REVIEW",
        "footprint_sha256": hashlib.sha256(_canonical_json(footprint)).hexdigest(),
        "automatic_deletion": False,
        "installed_packages_retained": True,
    }


def _snapshot_directory_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise FinishProjectError("no-follow directory operations are unavailable")
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _same_directory_name(parent: int, name: str, descriptor: int) -> bool:
    named = os.stat(name, dir_fd=parent, follow_symlinks=False)
    opened = os.fstat(descriptor)
    return (
        stat.S_ISDIR(named.st_mode)
        and stat.S_ISDIR(opened.st_mode)
        and (named.st_dev, named.st_ino) == (opened.st_dev, opened.st_ino)
    )


def _snapshot_parent_descriptors(destination: Path) -> tuple[Path, list[int]]:
    """Hold the state-root/transaction/components chain without following children."""
    destination = Path(destination)
    if (
        destination.name != "pre-stop-project"
        or destination.parent.name != "components"
        or destination.parents[2].name != state.TRANSACTIONS_NAME
        or not state.TRANSACTION_PATTERN.fullmatch(destination.parents[1].name)
    ):
        raise FinishProjectError("pre-stop snapshot destination is not a transaction component")
    root = destination.parents[3]
    descriptors: list[int] = []
    try:
        root_fd = os.open(root, _snapshot_directory_flags())
        descriptors.append(root_fd)
        named_root = root.lstat()
        opened_root = os.fstat(root_fd)
        if (
            not stat.S_ISDIR(named_root.st_mode)
            or (named_root.st_dev, named_root.st_ino)
            != (opened_root.st_dev, opened_root.st_ino)
        ):
            raise FinishProjectError("pre-stop state root identity is unsafe")
        for name in (
            state.TRANSACTIONS_NAME, destination.parents[1].name, "components",
        ):
            parent = descriptors[-1]
            child = os.open(name, _snapshot_directory_flags(), dir_fd=parent)
            descriptors.append(child)
            if not _same_directory_name(parent, name, child):
                raise FinishProjectError("pre-stop destination directory identity is unsafe")
        return root, descriptors
    except OSError as exc:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise FinishProjectError("pre-stop destination directory identity is unsafe") from exc
    except BaseException:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise


def _assert_snapshot_parent_binding(root: Path, descriptors: list[int], transaction: str) -> None:
    named = root.lstat()
    opened = os.fstat(descriptors[0])
    if (
        not stat.S_ISDIR(named.st_mode)
        or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
        or not all(
            _same_directory_name(parent, name, child)
            for parent, name, child in zip(
                descriptors, (state.TRANSACTIONS_NAME, transaction, "components"),
                descriptors[1:],
            )
        )
    ):
        raise FinishProjectError("pre-stop destination directory identity changed")


def _copy_snapshot_entries(source_fd: int, output_fd: int) -> None:
    """Copy source entries by descriptor; never interpret a public output path."""
    flags = _snapshot_directory_flags()
    for name in sorted(os.listdir(source_fd)):
        metadata = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISDIR(metadata.st_mode):
            source_child = os.open(name, flags, dir_fd=source_fd)
            try:
                if not _same_directory_name(source_fd, name, source_child):
                    raise FinishProjectError("snapshot source directory changed")
                os.mkdir(name, 0o700, dir_fd=output_fd)
                output_child = os.open(name, flags, dir_fd=output_fd)
                try:
                    _copy_snapshot_entries(source_child, output_child)
                    os.fchmod(output_child, mode)
                    os.fsync(output_child)
                finally:
                    os.close(output_child)
            finally:
                os.close(source_child)
        elif stat.S_ISREG(metadata.st_mode):
            if metadata.st_nlink != 1:
                raise FinishProjectError("snapshot source hard link is unsafe")
            source_file = os.open(
                name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                dir_fd=source_fd,
            )
            try:
                opened = os.fstat(source_file)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
                ):
                    raise FinishProjectError("snapshot source file changed")
                output_file = os.open(
                    name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                    | getattr(os, "O_CLOEXEC", 0),
                    0o600, dir_fd=output_fd,
                )
                try:
                    while chunk := os.read(source_file, 1024 * 1024):
                        view = memoryview(chunk)
                        while view:
                            written = os.write(output_file, view)
                            if written <= 0:
                                raise FinishProjectError("snapshot file copy made no progress")
                            view = view[written:]
                    os.fchmod(output_file, mode)
                    os.fsync(output_file)
                finally:
                    os.close(output_file)
                after = os.fstat(source_file)
                if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
                    after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                ):
                    raise FinishProjectError("snapshot source file changed during copy")
            finally:
                os.close(source_file)
        elif stat.S_ISLNK(metadata.st_mode):
            target = os.readlink(name, dir_fd=source_fd)
            if os.path.isabs(target):
                raise FinishProjectError("absolute snapshot symlink cannot be relocated")
            os.symlink(target, name, dir_fd=output_fd)
        else:
            raise FinishProjectError("special snapshot source entry is unsafe")


def _snapshot_inventory_fd(root_fd: int) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}

    def visit(parent_fd: int, prefix: str) -> None:
        for name in sorted(os.listdir(parent_fd)):
            relative = f"{prefix}/{name}" if prefix else name
            metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            mode = stat.S_IMODE(metadata.st_mode)
            if stat.S_ISDIR(metadata.st_mode):
                child = os.open(name, _snapshot_directory_flags(), dir_fd=parent_fd)
                try:
                    if not _same_directory_name(parent_fd, name, child):
                        raise FinishProjectError("snapshot directory changed during inventory")
                    rows[relative] = {"type": "directory", "mode": mode}
                    visit(child, relative)
                finally:
                    os.close(child)
            elif stat.S_ISREG(metadata.st_mode):
                if metadata.st_nlink != 1:
                    raise FinishProjectError("snapshot hard link is unsafe")
                descriptor = os.open(
                    name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=parent_fd,
                )
                try:
                    opened = os.fstat(descriptor)
                    if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                        raise FinishProjectError("snapshot file changed during inventory")
                    digest = hashlib.sha256()
                    size = 0
                    while chunk := os.read(descriptor, 1024 * 1024):
                        digest.update(chunk)
                        size += len(chunk)
                    after = os.fstat(descriptor)
                    if (opened.st_size, opened.st_mtime_ns) != (
                        after.st_size, after.st_mtime_ns,
                    ):
                        raise FinishProjectError("snapshot file changed during inventory")
                    rows[relative] = {
                        "type": "file", "mode": mode, "size": size,
                        "sha256": digest.hexdigest(),
                    }
                finally:
                    os.close(descriptor)
            elif stat.S_ISLNK(metadata.st_mode):
                rows[relative] = {
                    "type": "symlink", "mode": mode,
                    "target": os.readlink(name, dir_fd=parent_fd),
                }
            else:
                raise FinishProjectError("special snapshot entry is unsafe")

    visit(root_fd, "")
    return rows


def _remove_snapshot_tree(parent_fd: int, name: str, expected: os.stat_result) -> None:
    """Best-effort cleanup inside the held parent, never through its public name."""
    directory = os.open(name, _snapshot_directory_flags(), dir_fd=parent_fd)
    try:
        opened = os.fstat(directory)
        if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
            raise FinishProjectError("pre-stop staging identity changed before cleanup")
        for child_name in os.listdir(directory):
            child = os.stat(child_name, dir_fd=directory, follow_symlinks=False)
            if stat.S_ISDIR(child.st_mode):
                _remove_snapshot_tree(directory, child_name, child)
            else:
                os.unlink(child_name, dir_fd=directory)
        if not _same_directory_name(parent_fd, name, directory):
            raise FinishProjectError("pre-stop staging identity changed during cleanup")
        os.rmdir(name, dir_fd=parent_fd)
    finally:
        os.close(directory)


def _copy_snapshot(source: Path, destination: Path) -> None:
    expected = inventory_tree(source)
    root, parents = _snapshot_parent_descriptors(destination)
    stage_name: str | None = None
    stage_identity: os.stat_result | None = None
    stage_fd = -1
    source_fd = -1
    transaction = destination.parents[1].name
    try:
        _assert_snapshot_parent_binding(root, parents, transaction)
        try:
            os.stat(destination.name, dir_fd=parents[-1], follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FinishProjectError("pre-stop snapshot already exists")
        source_fd = os.open(source, _snapshot_directory_flags())
        source_named = source.lstat()
        source_opened = os.fstat(source_fd)
        if (
            not stat.S_ISDIR(source_named.st_mode)
            or (source_named.st_dev, source_named.st_ino)
            != (source_opened.st_dev, source_opened.st_ino)
        ):
            raise FinishProjectError("snapshot source root identity changed")
        stage_name = f".{destination.name}.staging-{secrets.token_hex(12)}"
        os.mkdir(stage_name, 0o700, dir_fd=parents[-1])
        stage_fd = os.open(stage_name, _snapshot_directory_flags(), dir_fd=parents[-1])
        stage_identity = os.fstat(stage_fd)
        _copy_snapshot_entries(source_fd, stage_fd)
        os.fsync(stage_fd)
        if _snapshot_inventory_fd(stage_fd) != expected:
            raise FinishProjectError("pre-stop snapshot differs from source inventory")
        _assert_snapshot_parent_binding(root, parents, transaction)
        if not _same_directory_name(parents[-1], stage_name, stage_fd):
            raise FinishProjectError("pre-stop staging identity changed")
        try:
            os.stat(destination.name, dir_fd=parents[-1], follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FinishProjectError("pre-stop snapshot appeared during publication")
        os.rename(
            stage_name, destination.name,
            src_dir_fd=parents[-1], dst_dir_fd=parents[-1],
        )
        stage_name = None
        if not _same_directory_name(parents[-1], destination.name, stage_fd):
            raise FinishProjectError("pre-stop published snapshot identity changed")
        os.fsync(parents[-1])
        _assert_snapshot_parent_binding(root, parents, transaction)
        if _snapshot_inventory_fd(stage_fd) != expected:
            raise FinishProjectError("pre-stop published snapshot inventory changed")
    finally:
        pending_exception = sys.exc_info()[0] is not None
        if stage_fd >= 0:
            os.close(stage_fd)
        if source_fd >= 0:
            os.close(source_fd)
        try:
            if stage_name is not None and stage_identity is not None:
                _remove_snapshot_tree(parents[-1], stage_name, stage_identity)
        except BaseException:
            if not pending_exception:
                raise
        finally:
            for descriptor in reversed(parents):
                os.close(descriptor)


def _anchored_pre_stop_inventory(pre_stop: Path) -> dict[str, dict[str, Any]]:
    """Inventory only the snapshot named by the held transaction components."""
    root, parents = _snapshot_parent_descriptors(pre_stop)
    try:
        snapshot_fd = os.open(pre_stop.name, _snapshot_directory_flags(), dir_fd=parents[-1])
        try:
            _assert_snapshot_parent_binding(root, parents, pre_stop.parents[1].name)
            if not _same_directory_name(parents[-1], pre_stop.name, snapshot_fd):
                raise FinishProjectError("pre-stop snapshot identity changed")
            result = _snapshot_inventory_fd(snapshot_fd)
            _assert_snapshot_parent_binding(root, parents, pre_stop.parents[1].name)
            if not _same_directory_name(parents[-1], pre_stop.name, snapshot_fd):
                raise FinishProjectError("pre-stop snapshot identity changed")
            return result
        finally:
            os.close(snapshot_fd)
    finally:
        for descriptor in reversed(parents):
            os.close(descriptor)


def _copy_file_descriptors(source_fd: int, destination_fd: int) -> None:
    while chunk := os.read(source_fd, 1024 * 1024):
        view = memoryview(chunk)
        while view:
            written = os.write(destination_fd, view)
            if written <= 0:
                raise FinishProjectError("finished bundle copy made no progress")
            view = view[written:]
    os.fsync(destination_fd)


def _private_bundle_copy(components_fd: int, name: str, destination: Path) -> None:
    source_fd = os.open(
        name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        dir_fd=components_fd,
    )
    try:
        source_metadata = os.fstat(source_fd)
        if not stat.S_ISREG(source_metadata.st_mode) or source_metadata.st_nlink != 1:
            raise FinishProjectError("finished bundle identity is unsafe")
        destination_fd = os.open(
            destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        try:
            _copy_file_descriptors(source_fd, destination_fd)
        finally:
            os.close(destination_fd)
        after = os.fstat(source_fd)
        if (source_metadata.st_dev, source_metadata.st_ino, source_metadata.st_size,
                source_metadata.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
        ):
            raise FinishProjectError("finished bundle changed during verification copy")
    finally:
        os.close(source_fd)


def _publish_private_bundle(source: Path, components_fd: int, name: str) -> None:
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        output_fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
            0o600, dir_fd=components_fd,
        )
        try:
            _copy_file_descriptors(source_fd, output_fd)
        finally:
            os.close(output_fd)
        os.fsync(components_fd)
    finally:
        os.close(source_fd)


def _bundled_pre_stop_inventory(bundle_path: Path) -> dict[str, dict[str, Any]]:
    """Derive source identity from the actual nested bytes, not bundle metadata."""
    result: dict[str, dict[str, Any]] = {}
    names: set[str] = set()
    with tarfile.open(bundle_path, "r:gz") as outer:
        component = outer.extractfile(f"{BUNDLE_ROOT}/pre-stop/project.tar.gz")
        if component is None:
            raise FinishProjectError("finished bundle has no pre-stop project archive")
        with component, tarfile.open(fileobj=component, mode="r:gz") as inner:
            for member in inner:
                path = PurePosixPath(member.name)
                if (
                    path.as_posix() != member.name or not path.parts
                    or path.parts[0] != "project" or ".." in path.parts
                    or member.name in names
                ):
                    raise FinishProjectError("finished bundle pre-stop path is unsafe")
                names.add(member.name)
                if member.name == "project":
                    if not member.isdir():
                        raise FinishProjectError("finished bundle pre-stop root is unsafe")
                    continue
                relative = PurePosixPath(*path.parts[1:]).as_posix()
                mode = stat.S_IMODE(member.mode)
                if member.isdir():
                    result[relative] = {"type": "directory", "mode": mode}
                elif member.issym():
                    result[relative] = {
                        "type": "symlink", "mode": mode, "target": member.linkname,
                    }
                elif member.isfile():
                    stream = inner.extractfile(member)
                    if stream is None:
                        raise FinishProjectError("finished bundle pre-stop file is unreadable")
                    digest = hashlib.sha256()
                    size = 0
                    with stream:
                        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                            size += len(chunk)
                            digest.update(chunk)
                    if size != member.size:
                        raise FinishProjectError("finished bundle pre-stop file size changed")
                    result[relative] = {
                        "type": "file", "mode": mode, "size": size,
                        "sha256": digest.hexdigest(),
                    }
                else:
                    raise FinishProjectError("finished bundle pre-stop entry is unsafe")
    if "project" not in names:
        raise FinishProjectError("finished bundle pre-stop root is missing")
    return result


def _build_or_verify_anchored_bundle(
    *, pre_stop: Path, bundle_path: Path, project: Path, project_name: str,
    transaction_id: str, runtime: str, created_at: str, repository: Path,
    stopped: dict[str, Any], footprint: dict[str, Any],
    deletion_plan: dict[str, Any], resumable_stage: str,
) -> tuple[BundleResult, str, int]:
    """Keep the public components name out of bundle reads and writes."""
    root, parents = _snapshot_parent_descriptors(pre_stop)
    transaction = pre_stop.parents[1].name
    snapshot_fd = -1
    try:
        _assert_snapshot_parent_binding(root, parents, transaction)
        snapshot_fd = os.open(
            pre_stop.name, _snapshot_directory_flags(), dir_fd=parents[-1],
        )
        if not _same_directory_name(parents[-1], pre_stop.name, snapshot_fd):
            raise FinishProjectError("pre-stop snapshot identity changed")
        with tempfile.TemporaryDirectory(prefix="http-finish-held-") as temporary_name:
            temporary = Path(temporary_name)
            mirror = temporary / "pre-stop-project"
            mirror.mkdir(mode=0o700)
            mirror_fd = os.open(mirror, _snapshot_directory_flags())
            try:
                before = _snapshot_inventory_fd(snapshot_fd)
                _copy_snapshot_entries(snapshot_fd, mirror_fd)
                os.fsync(mirror_fd)
                if _snapshot_inventory_fd(mirror_fd) != before:
                    raise FinishProjectError("private pre-stop mirror differs from held snapshot")
                temporary_fd = os.open(temporary, _snapshot_directory_flags())
                try:
                    if not _same_directory_name(
                        temporary_fd, mirror.name, mirror_fd,
                    ):
                        raise FinishProjectError("private pre-stop mirror identity changed")
                finally:
                    os.close(temporary_fd)
            finally:
                os.close(mirror_fd)
            temporary_bundle = temporary / bundle_path.name
            try:
                named = os.stat(
                    bundle_path.name, dir_fd=parents[-1], follow_symlinks=False,
                )
            except FileNotFoundError:
                named = None
            if named is None:
                if resumable_stage != "final_delta_building":
                    raise FinishProjectError("durable finished bundle is missing")
                create_finished_bundle(
                    project=project_name,
                    transaction_id=transaction_id,
                    runtime=runtime,
                    created_at=created_at,
                    pre_stop_project=mirror,
                    post_stop_project=project,
                    deployment_source=repository,
                    host_state={
                        "schema_version": 1,
                        "project": project_name,
                        "runtime": runtime,
                        "runtime_stopped": True,
                        "stop_evidence": stopped,
                        "installed_packages_retained": True,
                        "infra_state_retained": True,
                    },
                    deployment_footprint=footprint,
                    deletion_plan=deletion_plan,
                    output=temporary_bundle,
                )
            else:
                if not stat.S_ISREG(named.st_mode) or named.st_nlink != 1:
                    raise FinishProjectError("durable finished bundle identity is unsafe")
                _private_bundle_copy(parents[-1], bundle_path.name, temporary_bundle)
            verified = verify_finished_bundle(
                temporary_bundle,
                expected_project=project_name,
                expected_transaction_id=transaction_id,
                expected_runtime=runtime,
                expected_created_at=created_at,
            )
            if _bundled_pre_stop_inventory(temporary_bundle) != before:
                raise FinishProjectError(
                    "finished bundle pre-stop differs from held snapshot"
                )
            bundle_sha256 = _sha256_file(temporary_bundle)
            bundle_size = temporary_bundle.stat().st_size
            _assert_snapshot_parent_binding(root, parents, transaction)
            if not _same_directory_name(parents[-1], pre_stop.name, snapshot_fd):
                raise FinishProjectError("pre-stop snapshot identity changed")
            if named is None:
                _publish_private_bundle(temporary_bundle, parents[-1], bundle_path.name)
            else:
                current = os.stat(
                    bundle_path.name, dir_fd=parents[-1], follow_symlinks=False,
                )
                if (current.st_dev, current.st_ino) != (named.st_dev, named.st_ino):
                    raise FinishProjectError("durable finished bundle identity changed")
            _assert_snapshot_parent_binding(root, parents, transaction)
            return (
                BundleResult(bundle_path, verified.record_id, verified.content_sha256),
                bundle_sha256, bundle_size,
            )
    finally:
        if snapshot_fd >= 0:
            os.close(snapshot_fd)
        for descriptor in reversed(parents):
            os.close(descriptor)


def stop_runtime(
    *, repository: Path, project_name: str, runtime: str,
    transaction_id: str,
) -> dict[str, Any]:
    if runtime == "native":
        command = [
            sys.executable,
            str(Path(repository) / "DAY0-Prepare/13-unload.py"),
            project_name,
            "--stop-only",
            "--yes",
            "--finish-transaction",
            transaction_id,
        ]
        backend = "systemd"
    elif runtime == "docker":
        command = [
            str(Path(repository) / "infra/docker/deploy.sh"),
            "stop",
            transaction_id,
        ]
        backend = "supervisor"
    else:
        raise FinishProjectError("runtime must be native or docker")
    completed = subprocess.run(
        command, cwd=repository, check=False, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if completed.returncode != 0:
        raise FinishProjectError(
            f"{runtime} stop-only failed with status {completed.returncode}: "
            f"{completed.stdout[-2000:]}"
        )
    return {"stopped": True, "backend": backend, "status": completed.returncode}


def _pending(
    *, transaction_id: str, project_name: str, runtime: str, created_at: str,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "transaction_id": transaction_id,
        "project": project_name,
        "runtime": runtime,
        "source_manifest_sha256": None,
        "release_sha256": None,
        "created_at": created_at,
    }


def _finish_after_runtime_stopping(
    *, repository: Path, project: Path, project_name: str, runtime: str,
    transaction_id: str, created_at: str, state_root: Path,
    transaction_dir: Path, pre_stop: Path, footprint: dict[str, Any],
    legacy: bool, runtime_already_stopped: bool = False,
    resumable_stage: str = "final_delta_building",
) -> FinishResult:
    if runtime_already_stopped:
        receipt = state.read_transaction(transaction_id, root=state_root)
        stopped = receipt["evidence"].get("runtime")
        if not isinstance(stopped, dict) or stopped.get("stopped") is not True:
            raise FinishProjectError("durable stopped evidence is missing")
    else:
        stopped = stop_runtime(
            repository=repository,
            project_name=project_name,
            runtime=runtime,
            transaction_id=transaction_id,
        )
        if stopped.get("stopped") is not True:
            raise FinishProjectError("stop backend did not provide stopped evidence")
        state.advance_transaction(
            transaction_id, "runtime_stopped", root=state_root,
            evidence={"runtime": stopped},
        )
        state.advance_transaction(
            transaction_id, "final_delta_building", root=state_root,
        )
        resumable_stage = "final_delta_building"
    components = transaction_dir / "components"
    bundle_path = components / f"http-ztp-finished-{project_name}-{transaction_id}.tar.gz"
    deletion_plan = {
        "schema_version": 1,
        "project": project_name,
        "legacy_without_footprint": legacy,
        "categories": {
            "SAFE_TO_REVIEW": [] if legacy else footprint.get("paths", []),
            "CONDITIONAL": footprint.get("paths", []) if legacy else [],
            "PRESERVE": [str(bundle_path), str(transaction_dir)],
        },
        "automatic_deletion": False,
    }
    if resumable_stage not in {
        "final_delta_building", "final_delta_complete", "bundle_finalizing",
    }:
        raise FinishProjectError(
            f"cannot finalize bundle from stage {resumable_stage}"
        )
    bundle, bundle_sha256, bundle_size = _build_or_verify_anchored_bundle(
        pre_stop=pre_stop, bundle_path=bundle_path, project=project,
        project_name=project_name, transaction_id=transaction_id,
        runtime=runtime, created_at=created_at, repository=repository,
        stopped=stopped, footprint=footprint, deletion_plan=deletion_plan,
        resumable_stage=resumable_stage,
    )
    _anchored_pre_stop_inventory(pre_stop)
    bundle_evidence = {
        "bundle_path": str(bundle.path),
        "bundle_sha256": bundle_sha256,
        "record_id": bundle.record_id,
        "content_sha256": bundle.content_sha256,
        "bundle_size": bundle_size,
    }
    if resumable_stage == "final_delta_building":
        state.advance_transaction(
            transaction_id, "final_delta_complete", root=state_root,
            evidence=bundle_evidence,
        )
        resumable_stage = "final_delta_complete"
    else:
        receipt = state.read_transaction(transaction_id, root=state_root)
        for key, expected in bundle_evidence.items():
            if receipt["evidence"].get(key) != expected:
                raise FinishProjectError(
                    f"durable bundle evidence does not match bytes: {key}"
                )
    if resumable_stage == "final_delta_complete":
        state.advance_transaction(
            transaction_id, "bundle_finalizing", root=state_root,
        )
        resumable_stage = "bundle_finalizing"
    _anchored_pre_stop_inventory(pre_stop)
    state.advance_transaction(
        transaction_id, "completed", root=state_root,
        evidence=bundle_evidence,
    )
    state.clear_finish_pending(transaction_id, root=state_root)
    return FinishResult(
        transaction_id, bundle.path, bundle.record_id, bundle.content_sha256,
    )


def execute_finish(
    *, repository: Path, project_name: str, runtime: str,
    state_root: Path = state.FINISH_STATE_ROOT,
    transaction_id: str, created_at: str,
    runtime_only_stop: bool = False,
) -> FinishResult:
    repository = Path(repository).resolve(strict=True)
    state_root = Path(state_root)
    project = resolve_project(repository, project_name)
    footprint, legacy = _read_footprint(state_root, project_name)
    if legacy and not runtime_only_stop:
        raise FinishProjectError(
            "no trustworthy deployment footprint; inspect plan and explicitly "
            "select --runtime-only-stop to archive and stop without cleanup claims"
        )
    receipt = state.create_transaction(
        transaction_id=transaction_id,
        project=project_name,
        runtime=runtime,
        created_at=created_at,
        root=state_root,
    )
    if receipt["state"] != "planned":
        raise FinishProjectError(
            f"transaction already exists in state {receipt['state']}; use resume"
        )
    transaction_dir = state_root / state.TRANSACTIONS_NAME / transaction_id
    components = transaction_dir / "components"
    components.mkdir(mode=0o700)
    pre_stop = components / "pre-stop-project"
    try:
        state.advance_transaction(
            transaction_id, "pre_stop_archiving", root=state_root,
        )
        _copy_snapshot(project, pre_stop)
        pre_inventory = _anchored_pre_stop_inventory(pre_stop)
        state.advance_transaction(
            transaction_id, "pre_stop_complete", root=state_root,
            evidence={
                "pre_stop_objects": len(pre_inventory),
                "legacy_without_footprint": legacy,
            },
        )
        with deployment_lock(repository):
            state.create_finish_pending(
                _pending(
                    transaction_id=transaction_id,
                    project_name=project_name,
                    runtime=runtime,
                    created_at=created_at,
                ),
                root=state_root,
            )
            state.advance_transaction(
                transaction_id, "pending_committed", root=state_root,
            )
        state.advance_transaction(
            transaction_id, "runtime_stopping", root=state_root,
        )
        return _finish_after_runtime_stopping(
            repository=repository,
            project=project,
            project_name=project_name,
            runtime=runtime,
            transaction_id=transaction_id,
            created_at=created_at,
            state_root=state_root,
            transaction_dir=transaction_dir,
            pre_stop=pre_stop,
            footprint=footprint,
            legacy=legacy,
        )
    except BaseException:
        try:
            current = state.read_transaction(transaction_id, root=state_root)
            if current["state"] not in {"failed", "completed"}:
                state.advance_transaction(
                    transaction_id, "failed", root=state_root,
                    evidence={"failure_recorded": True},
                )
        except BaseException:
            pass
        raise


def execute_resume(
    *, repository: Path, transaction_id: str,
    state_root: Path = state.FINISH_STATE_ROOT,
) -> FinishResult:
    repository = Path(repository).resolve(strict=True)
    state_root = Path(state_root)
    receipt = state.read_transaction(transaction_id, root=state_root)
    if receipt["state"] == "completed":
        bundle_path = Path(str(receipt["evidence"].get("bundle_path", "")))
        if not bundle_path.is_file():
            raise FinishProjectError("completed transaction bundle is missing")
        if _sha256_file(bundle_path) != receipt["evidence"].get("bundle_sha256"):
            raise FinishProjectError("completed transaction bundle hash changed")
        bundle = verify_finished_bundle(
            bundle_path,
            expected_project=str(receipt["project"]),
            expected_transaction_id=transaction_id,
            expected_runtime=str(receipt["runtime"]),
            expected_created_at=str(receipt["created_at"]),
        )
        if (
            bundle.record_id != receipt["evidence"].get("record_id")
            or bundle.content_sha256 != receipt["evidence"].get("content_sha256")
            or bundle.path.stat().st_size != receipt["evidence"].get("bundle_size")
        ):
            raise FinishProjectError("completed transaction bundle evidence changed")
        state.clear_finish_pending(transaction_id, root=state_root)
        return FinishResult(
            transaction_id,
            bundle_path,
            bundle.record_id,
            bundle.content_sha256,
        )
    if receipt["state"] != "failed":
        raise FinishProjectError(
            f"transaction is not failed/completed: {receipt['state']}"
        )
    previous = [
        row.get("state") for row in receipt["history"]
        if isinstance(row, dict) and row.get("state") != "failed"
    ]
    resumable_stage = previous[-1] if previous else "unknown"
    if resumable_stage not in {
        "pre_stop_archiving", "pre_stop_complete", "pending_committed",
        "runtime_stopping", "final_delta_building", "final_delta_complete",
        "bundle_finalizing",
    }:
        raise FinishProjectError(
            f"resume from stage {resumable_stage} is not yet safe"
        )
    project_name = str(receipt["project"])
    runtime = str(receipt["runtime"])
    project = resolve_project(repository, project_name)
    transaction_dir = state_root / state.TRANSACTIONS_NAME / transaction_id
    pre_stop = transaction_dir / "components/pre-stop-project"
    footprint, legacy = _read_footprint(state_root, project_name)
    resume_evidence = {"resume_count": sum(
        1 for row in receipt["history"] if row.get("state") == "failed"
    )}
    try:
        state.advance_transaction(
            transaction_id, resumable_stage, root=state_root,
            evidence=resume_evidence,
        )
        if resumable_stage == "pre_stop_archiving":
            if not os.path.lexists(pre_stop):
                _copy_snapshot(project, pre_stop)
            pre_inventory = _anchored_pre_stop_inventory(pre_stop)
            state.advance_transaction(
                transaction_id, "pre_stop_complete", root=state_root,
                evidence={
                    "pre_stop_objects": len(pre_inventory),
                    "legacy_without_footprint": legacy,
                },
            )
            resumable_stage = "pre_stop_complete"
        if resumable_stage == "pre_stop_complete":
            with deployment_lock(
                repository, finish_transaction_id=transaction_id,
            ):
                state.create_finish_pending(
                    _pending(
                        transaction_id=transaction_id,
                        project_name=project_name,
                        runtime=runtime,
                        created_at=str(receipt["created_at"]),
                    ),
                    root=state_root,
                )
                state.advance_transaction(
                    transaction_id, "pending_committed", root=state_root,
                )
            resumable_stage = "pending_committed"
        pending = state.read_finish_pending(state_root)
        if pending is None or pending["transaction_id"] != transaction_id:
            raise FinishProjectError(
                "matching finish-pending authority is required for resume"
            )
        _anchored_pre_stop_inventory(pre_stop)
        if resumable_stage == "pending_committed":
            state.advance_transaction(
                transaction_id, "runtime_stopping", root=state_root,
            )
            resumable_stage = "runtime_stopping"
        return _finish_after_runtime_stopping(
            repository=repository,
            project=project,
            project_name=project_name,
            runtime=runtime,
            transaction_id=transaction_id,
            created_at=str(receipt["created_at"]),
            state_root=state_root,
            transaction_dir=transaction_dir,
            pre_stop=pre_stop,
            footprint=footprint,
            legacy=legacy,
            runtime_already_stopped=resumable_stage in {
                "final_delta_building", "final_delta_complete", "bundle_finalizing",
            },
            resumable_stage=resumable_stage,
        )
    except BaseException:
        current = state.read_transaction(transaction_id, root=state_root)
        if current["state"] not in {"failed", "completed"}:
            state.advance_transaction(
                transaction_id, "failed", root=state_root,
                evidence={"failure_recorded": True},
            )
        raise


def _new_identity() -> tuple[str, str]:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    created_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    transaction_id = f"finish-{now.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:16]}"
    return transaction_id, created_at


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", choices=("plan", "finish", "resume"),
        help="Choose plan, finish, or resume for a finished-project transaction",
    )
    parser.add_argument(
        "project", help="Existing DAY0 project to finish or inspect",
    )
    parser.add_argument(
        "--runtime", choices=("native", "docker"), required=True,
        help="Choose the deployment runtime of the project (native or docker)",
    )
    parser.add_argument(
        "--transaction-id",
        help="ID of an existing transaction; required for resume, not finish",
    )
    parser.add_argument(
        "--runtime-only-stop", action="store_true",
        help="Allow runtime-only stop for a legacy project without a recorded footprint",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.action == "plan":
        print(json.dumps(build_plan(
            repository=REPOSITORY,
            project_name=args.project,
            runtime=args.runtime,
        ), sort_keys=True, indent=2))
        return 0
    if os.geteuid() != 0:
        raise FinishProjectError("finish and resume require root")
    if args.action == "resume":
        if args.transaction_id is None:
            raise FinishProjectError("resume requires --transaction-id")
        result = execute_resume(
            repository=REPOSITORY,
            transaction_id=args.transaction_id,
        )
        print(f"bundle: {result.bundle_path}")
        print(f"record: {result.record_id}")
        return 0
    transaction_id, created_at = _new_identity()
    if args.transaction_id is not None:
        raise FinishProjectError("finish creates a new transaction ID; use resume for an existing one")
    result = execute_finish(
        repository=REPOSITORY,
        project_name=args.project,
        runtime=args.runtime,
        transaction_id=transaction_id,
        created_at=created_at,
        runtime_only_stop=args.runtime_only_stop,
    )
    print(f"bundle: {result.bundle_path}")
    print(f"record: {result.record_id}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FinishProjectError, state.FinishStateError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
