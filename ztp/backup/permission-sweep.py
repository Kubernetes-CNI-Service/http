#!/usr/bin/env python3
"""Inventory and narrowly tighten an existing managed backup tree.

The operation is deliberately two phase: ``freeze_manifest`` publishes an
exact digest in a private directory outside the managed tree; only an explicit
``apply_manifest`` call bearing that digest may change modes.  A durable
append-only journal supports explicit resume without widening permissions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any


class SweepError(RuntimeError):
    pass


_OPEN_DIRECTORY = (
    os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
)
_OPEN_FILE = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
_MANIFEST_NAME = "backup-permission-manifest.json"


def _mode(metadata: os.stat_result) -> str:
    return f"{stat.S_IMODE(metadata.st_mode):04o}"


def _sha256_fd(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def _sha256_path(path: Path, expected: os.stat_result) -> str:
    descriptor = os.open(path, _OPEN_FILE)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or (before.st_dev, before.st_ino) != (expected.st_dev, expected.st_ino)
        ):
            raise SweepError(f"unsafe regular file: {path}")
        digest = _sha256_fd(descriptor)
        after = os.fstat(descriptor)
        stable = ("st_dev", "st_ino", "st_nlink", "st_uid", "st_gid", "st_mode",
                  "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, key) != getattr(after, key) for key in stable):
            raise SweepError(f"file changed while hashing: {path}")
        return digest
    finally:
        os.close(descriptor)


def _entry(root: Path, path: Path, project_name: str) -> dict[str, Any]:
    metadata = os.lstat(path)
    relative = path.relative_to(root)
    parts = relative.parts
    if stat.S_ISLNK(metadata.st_mode):
        raise SweepError(f"symlink in managed backup tree: {relative}")
    if metadata.st_uid != os.geteuid():
        raise SweepError(f"owner differs from sweep identity: {relative}")
    if stat.S_ISDIR(metadata.st_mode):
        kind = "directory"
        digest = None
        target = "0700"
    elif stat.S_ISREG(metadata.st_mode):
        if metadata.st_nlink != 1:
            raise SweepError(f"hardlinked file in managed backup tree: {relative}")
        kind = "file"
        digest = _sha256_path(path, metadata)
        target = "0600"
    else:
        raise SweepError(f"special file in managed backup tree: {relative}")
    return {
        "canonical_root": str(root),
        "project": project_name,
        "batch": parts[0] if parts else None,
        "family": parts[1] if len(parts) >= 2 else None,
        "path": relative.as_posix() if parts else ".",
        "dev": metadata.st_dev,
        "ino": metadata.st_ino,
        "type": kind,
        "nlink": metadata.st_nlink,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": _mode(metadata),
        "size": metadata.st_size,
        "mtime_ns": metadata.st_mtime_ns,
        "ctime_ns": metadata.st_ctime_ns,
        "sha256": digest,
        "target_mode": target,
    }


def _snapshot(root: Path, project_name: str) -> list[dict[str, Any]]:
    root_lstat = os.lstat(root)
    if not stat.S_ISDIR(root_lstat.st_mode) or stat.S_ISLNK(root_lstat.st_mode):
        raise SweepError("managed backup root must be a real directory")
    if root_lstat.st_uid != os.geteuid():
        raise SweepError("managed backup root owner differs from sweep identity")
    entries = [_entry(root, root, project_name)]
    for current, directory_names, file_names in os.walk(root, followlinks=False):
        directory_names.sort()
        file_names.sort()
        current_path = Path(current)
        for name in directory_names:
            entries.append(_entry(root, current_path / name, project_name))
        for name in file_names:
            entries.append(_entry(root, current_path / name, project_name))
    entries.sort(key=lambda item: item["path"])
    paths = [item["path"] for item in entries]
    if len(paths) != len(set(paths)):
        raise SweepError("duplicate path in managed backup inventory")
    return entries


def _private_state_directory(path: Path) -> Path:
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        pass
    metadata = os.lstat(path)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise SweepError("sweep state directory must be owned real 0700")
    return path.resolve(strict=True)


def _exclusive_write(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise SweepError("new sweep authority file is unsafe")
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise SweepError("short write while persisting sweep authority")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    parent = os.open(path.parent, _OPEN_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def freeze_manifest(root: Path | str, state_directory: Path | str,
                    *, project_name: str) -> dict[str, str]:
    root_path = Path(root).resolve(strict=True)
    state = _private_state_directory(Path(state_directory))
    if state == root_path or state.is_relative_to(root_path):
        raise SweepError("sweep state must be outside the managed backup tree")
    manifest_path = state / _MANIFEST_NAME
    entries = _snapshot(root_path, project_name)
    document = {
        "schema_version": 1,
        "canonical_root": str(root_path),
        "canonical_project": str(root_path.parent.resolve(strict=True)),
        "project": project_name,
        "entries": entries,
    }
    payload = (
        json.dumps(document, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    _exclusive_write(manifest_path, payload)
    if _snapshot(root_path, project_name) != entries:
        raise SweepError("managed backup tree changed while freezing manifest")
    return {
        "manifest_path": str(manifest_path),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def _read_manifest(path: Path, expected_digest: str) -> dict[str, Any]:
    metadata = os.lstat(path)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise SweepError("manifest authority is unsafe")
    payload = path.read_bytes()
    actual = hashlib.sha256(payload).hexdigest()
    if actual != expected_digest:
        raise SweepError("manifest digest does not match published authority")
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SweepError("manifest is not valid JSON") from exc
    if document.get("schema_version") != 1 or not isinstance(document.get("entries"), list):
        raise SweepError("manifest schema is invalid")
    return document


def _journal_records(path: Path, resume: bool) -> tuple[int, dict[str, dict[str, Any]]]:
    flags = os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    if resume:
        flags |= os.O_APPEND
        try:
            descriptor = os.open(path, flags)
        except FileNotFoundError as exc:
            raise SweepError("explicit resume requires an existing journal") from exc
        payload = path.read_bytes()
    else:
        flags |= os.O_CREAT | os.O_EXCL | os.O_APPEND
        descriptor = os.open(path, flags, 0o600)
        payload = b""
    os.fchmod(descriptor, 0o600)
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        os.close(descriptor)
        raise SweepError("sweep journal is unsafe")
    completed: dict[str, dict[str, Any]] = {}
    try:
        for raw in payload.splitlines():
            record = json.loads(raw)
            if record.get("status") not in {"completed", "reconciled"}:
                raise SweepError("journal contains an invalid status")
            relative = record.get("path")
            if not isinstance(relative, str) or relative in completed:
                raise SweepError("journal contains a duplicate or invalid path")
            completed[relative] = record
    except SweepError:
        os.close(descriptor)
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        os.close(descriptor)
        raise SweepError("journal is not valid append-only JSONL") from exc
    return descriptor, completed


def _same_unchanged(entry: dict[str, Any], current: dict[str, Any], *, strict: bool) -> bool:
    keys = ("dev", "ino", "type", "nlink", "uid", "gid", "size", "mtime_ns", "sha256")
    if any(entry[key] != current[key] for key in keys):
        return False
    if strict and (entry["mode"] != current["mode"] or entry["ctime_ns"] != current["ctime_ns"]):
        return False
    return True


def _open_held(root_fd: int, relative: str, kind: str) -> int:
    if relative == ".":
        return os.dup(root_fd)
    parts = Path(relative).parts
    parent = os.dup(root_fd)
    try:
        for component in parts[:-1]:
            child = os.open(component, _OPEN_DIRECTORY, dir_fd=parent)
            os.close(parent)
            parent = child
        flags = _OPEN_DIRECTORY if kind == "directory" else _OPEN_FILE
        return os.open(parts[-1], flags, dir_fd=parent)
    finally:
        os.close(parent)


def _append_record(descriptor: int, record: dict[str, Any]) -> None:
    payload = (
        json.dumps(record, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise SweepError("short write while appending sweep journal")
        view = view[written:]
    os.fsync(descriptor)


def apply_manifest(manifest_path: Path | str, expected_digest: str,
                   journal_path: Path | str, *, resume: bool) -> None:
    manifest = _read_manifest(Path(manifest_path), expected_digest)
    root = Path(manifest["canonical_root"])
    project_name = manifest["project"]
    expected = {item["path"]: item for item in manifest["entries"]}
    current_list = _snapshot(root, project_name)
    current = {item["path"]: item for item in current_list}
    if set(current) != set(expected):
        raise SweepError("managed backup tree changed; re-inventory is required")

    journal = Path(journal_path)
    journal_parent = _private_state_directory(journal.parent)
    if journal_parent == root or journal_parent.is_relative_to(root):
        raise SweepError("sweep journal must be outside the managed tree")
    descriptor, completed = _journal_records(journal, resume)
    try:
        for relative, entry in expected.items():
            now = current[relative]
            prior = completed.get(relative)
            if prior is not None:
                after = prior.get("after")
                if not isinstance(after, dict) or any(now.get(key) != value for key, value in after.items()):
                    raise SweepError("completed journal entry no longer matches the managed tree")
                continue
            strict = not resume
            if not _same_unchanged(entry, now, strict=strict):
                raise SweepError("managed backup metadata/content drift requires re-inventory")
            target = int(entry["target_mode"], 8)
            current_mode = int(now["mode"], 8)
            original_mode = int(entry["mode"], 8)
            if resume and current_mode != original_mode:
                if current_mode != (original_mode & target):
                    raise SweepError("unjournalled mode drift requires re-inventory")
            elif resume and now["ctime_ns"] != entry["ctime_ns"]:
                raise SweepError("unjournalled metadata drift requires re-inventory")

        root_fd = os.open(root, _OPEN_DIRECTORY)
        try:
            pending = [item for item in manifest["entries"] if item["path"] not in completed]
            pending.sort(key=lambda item: (0 if item["type"] == "file" else 1, item["path"]))
            for entry in pending:
                relative = entry["path"]
                held = _open_held(root_fd, relative, entry["type"])
                try:
                    before_stat = os.fstat(held)
                    before = _entry(root, root if relative == "." else root / relative, project_name)
                    if (before_stat.st_dev, before_stat.st_ino) != (entry["dev"], entry["ino"]):
                        raise SweepError("held object identity differs from manifest")
                    target = int(entry["target_mode"], 8)
                    before_mode = stat.S_IMODE(before_stat.st_mode)
                    desired = before_mode & target
                    if desired != before_mode:
                        os.fchmod(held, desired)
                        os.fsync(held)
                    after_stat = os.fstat(held)
                    if stat.S_IMODE(after_stat.st_mode) != desired:
                        raise SweepError("post-chmod mode verification failed")
                    after = {
                        "dev": after_stat.st_dev,
                        "ino": after_stat.st_ino,
                        "type": entry["type"],
                        "nlink": after_stat.st_nlink,
                        "uid": after_stat.st_uid,
                        "gid": after_stat.st_gid,
                        "mode": f"{stat.S_IMODE(after_stat.st_mode):04o}",
                        "size": after_stat.st_size,
                        "mtime_ns": after_stat.st_mtime_ns,
                        "ctime_ns": after_stat.st_ctime_ns,
                        "sha256": _sha256_fd(held) if entry["type"] == "file" else None,
                    }
                    if not _same_unchanged(entry, after, strict=False):
                        raise SweepError("post-chmod identity/content verification failed")
                    _append_record(descriptor, {
                        "path": relative,
                        "status": "completed" if desired != before_mode else "reconciled",
                        "before_mode": before["mode"],
                        "after": after,
                    })
                finally:
                    os.close(held)
        finally:
            os.close(root_fd)
        final_list = _snapshot(root, project_name)
        final = {item["path"]: item for item in final_list}
        if set(final) != set(expected):
            raise SweepError("managed backup tree changed during sweep")
        for relative, entry in expected.items():
            after = final[relative]
            if not _same_unchanged(entry, after, strict=False):
                raise SweepError("managed backup identity/content changed during sweep")
            desired = int(entry["mode"], 8) & int(entry["target_mode"], 8)
            if int(after["mode"], 8) != desired:
                raise SweepError("final permission invariant failed")
    except OSError as exc:
        raise SweepError(str(exc)) from exc
    finally:
        os.close(descriptor)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Freeze and apply an exact backup permission sweep",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    inventory = commands.add_parser("inventory")
    inventory.add_argument("--root", required=True, help="待盘点的备份根目录")
    inventory.add_argument("--state-dir", required=True, help="保存冻结清单与状态的私有目录")
    inventory.add_argument("--project", required=True, help="归属该备份根的项目名")
    for name in ("apply", "resume"):
        command = commands.add_parser(name)
        command.add_argument("--manifest", required=True, help="已冻结的权限清单路径")
        command.add_argument("--sha256", required=True, help="清单的预期 SHA-256 摘要")
        command.add_argument("--journal", required=True, help="仅追加的清扫执行日志路径")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "inventory":
            frozen = freeze_manifest(
                args.root, args.state_dir, project_name=args.project,
            )
            print(json.dumps(frozen, ensure_ascii=True, sort_keys=True))
        else:
            apply_manifest(
                args.manifest, args.sha256, args.journal,
                resume=args.command == "resume",
            )
            print(json.dumps({"status": "complete"}, sort_keys=True))
    except (OSError, SweepError) as exc:
        print(f"permission-sweep: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
