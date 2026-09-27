#!/usr/bin/env python3
"""Materialize one verified finished record as a new DAY0 project."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import sys
from typing import Any


PROJECT_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
PRODUCTION_PREFIXES = ("99-output-",)
EXCLUDED_TOP_LEVEL = frozenset({"finished-history"})
CONTROL_NAMES = frozenset({
    "latest", "activation.json", "precommit.json", ".deployment.lock",
    ".sync-code-in-progress",
})
REHYDRATE_CONTROL_NAMES = frozenset({
    ".finished-source.json", ".finished-commit.ready", ".finished-commit.json",
})


class RehydrateError(RuntimeError):
    """The finished record or destination is unsafe."""


class _VerifiedReport(dict[str, Any]):
    """Import report paired with the object identities verified with it."""

    def __init__(self, report: dict[str, Any], entries: list[dict[str, str]]) -> None:
        super().__init__(report)
        self.entries = tuple(
            (entry["path"], entry["type"], entry["identity"])
            for entry in entries
        )


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _stable_bytes(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RehydrateError(f"record file is unsafe: {path}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        lexical = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(lexical.st_mode)
            or before.st_nlink != 1
            or lexical.st_nlink != 1
            or (before.st_dev, before.st_ino) != (lexical.st_dev, lexical.st_ino)
        ):
            raise RehydrateError(f"record file identity is unsafe: {path}")
        payload = b""
        while len(payload) < before.st_size:
            chunk = os.read(descriptor, min(1024 * 1024, before.st_size - len(payload)))
            if not chunk:
                break
            payload += chunk
        after = os.fstat(descriptor)
        if (
            len(payload) != before.st_size
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        ):
            raise RehydrateError(f"record file changed while reading: {path}")
        return payload
    finally:
        os.close(descriptor)


def _record_entries(record: Path) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    for path in sorted(record.rglob("*"), key=lambda item: item.relative_to(record).as_posix()):
        relative = path.relative_to(record).as_posix()
        if relative == "record-inventory.json":
            continue
        metadata = path.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISLNK(metadata.st_mode):
            kind, identity = "symlink", os.readlink(path)
        elif stat.S_ISDIR(metadata.st_mode) and mode == 0o555:
            kind, identity = "directory", "directory"
        elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1 and mode == 0o444:
            kind, identity = "file", _sha256_bytes(_stable_bytes(path))
        else:
            raise RehydrateError(f"record inventory object is unsafe: {relative}")
        entries.append({"path": relative, "type": kind, "identity": identity})
    return entries


def verify_record(record: Path) -> _VerifiedReport:
    record = Path(record)
    try:
        metadata = record.lstat()
        record.resolve(strict=True)
        project_metadata = record.parent.lstat()
        finished_root_metadata = record.parent.parent.lstat()
    except OSError as exc:
        raise RehydrateError(f"finished record is unavailable: {exc}") from exc
    if (
        record.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o555
        or stat.S_ISLNK(project_metadata.st_mode)
        or not stat.S_ISDIR(project_metadata.st_mode)
        or stat.S_ISLNK(finished_root_metadata.st_mode)
        or not stat.S_ISDIR(finished_root_metadata.st_mode)
        or record.parent.parent.name != "Finished-projects"
    ):
        raise RehydrateError("finished record must be a frozen real record directory")
    inventory_path = record / "record-inventory.json"
    try:
        inventory = json.loads(_stable_bytes(inventory_path).decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RehydrateError(f"record inventory is invalid: {exc}") from exc
    entries = _record_entries(record)
    digest = _sha256_bytes(json.dumps(
        entries, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii"))
    if inventory != {
        "schema_version": 1, "entries": entries, "entries_sha256": digest,
    }:
        raise RehydrateError("record inventory does not match frozen objects")
    report_path = record / "import-report.json"
    try:
        report = json.loads(_stable_bytes(report_path).decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RehydrateError(f"record import report is invalid: {exc}") from exc
    if (
        not isinstance(report, dict)
        or report.get("record_id") != record.name
        or not isinstance(report.get("project"), str)
        or not SHA256_PATTERN.fullmatch(str(report.get("content_sha256", "")))
    ):
        raise RehydrateError("record import report identity is invalid")
    source = record / "reconstructed-final"
    if source.is_symlink() or not source.is_dir():
        raise RehydrateError("record reconstructed-final is missing or unsafe")
    return _VerifiedReport(report, entries)


def _is_runtime_control(relative: PurePosixPath) -> bool:
    name = relative.name
    lowered = name.casefold()
    return (
        name in CONTROL_NAMES
        or lowered.endswith(".pid")
        or lowered.endswith(".lock")
        or "activation" in lowered
        or "precommit" in lowered
    )


def _include(relative: PurePosixPath, include_history: bool) -> bool:
    top = relative.parts[0]
    if top in EXCLUDED_TOP_LEVEL:
        return False
    production = top.startswith(PRODUCTION_PREFIXES)
    if production and not include_history:
        return False
    if production and _is_runtime_control(relative):
        return False
    return True


_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_FILE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)


class _HeldStage:
    """Confine destination mutations to one held DAY0/stage directory pair."""

    def __init__(self, root: Path, root_fd: int, name: str, stage_fd: int) -> None:
        self.root, self.root_fd = root, root_fd
        self.name, self.stage_fd = name, stage_fd
        parent = os.fstat(root_fd)
        self.parent_identity = (parent.st_dev, parent.st_ino)
        # Own child writes never alter the DAY0 directory. A rename/rebind of
        # the public stage name does, even if the name is immediately restored.
        self.parent_ctime_ns = parent.st_ctime_ns
        held_stage = os.fstat(stage_fd)
        self.stage_identity = (held_stage.st_dev, held_stage.st_ino)

    def check(self, *, require_unchanged_parent: bool = True) -> None:
        try:
            visible_root = os.lstat(self.root)
            held_root = os.fstat(self.root_fd)
            visible_stage = os.stat(self.name, dir_fd=self.root_fd, follow_symlinks=False)
            held_stage = os.fstat(self.stage_fd)
        except OSError as exc:
            raise RehydrateError("rehydrate staging directory is unavailable") from exc
        if (
            not stat.S_ISDIR(visible_root.st_mode)
            or not stat.S_ISDIR(visible_stage.st_mode)
            or (visible_root.st_dev, visible_root.st_ino) != self.parent_identity
            or (held_root.st_dev, held_root.st_ino) != self.parent_identity
            or (require_unchanged_parent and held_root.st_ctime_ns != self.parent_ctime_ns)
            or (visible_stage.st_dev, visible_stage.st_ino) != self.stage_identity
            or (held_stage.st_dev, held_stage.st_ino) != self.stage_identity
        ):
            raise RehydrateError("rehydrate staging directory rebound")


def _open_staged_directory(stage: _HeldStage, parts: tuple[str, ...]) -> int:
    descriptor = os.dup(stage.stage_fd)
    try:
        for name in parts:
            stage.check()
            try:
                os.mkdir(name, 0o700, dir_fd=descriptor)
            except FileExistsError:
                pass
            child = os.open(name, _DIR_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            stage.check()
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _write_staged_file(
    stage: _HeldStage, relative: PurePosixPath, payload: bytes, executable: bool,
) -> None:
    parent_fd = _open_staged_directory(stage, relative.parts[:-1])
    descriptor = -1
    try:
        stage.check()
        descriptor = os.open(
            relative.name, _FILE_FLAGS | getattr(os, "O_CLOEXEC", 0),
            0o700 if executable else 0o600, dir_fd=parent_fd,
        )
        # Check *before* the first byte write. The held parent fd keeps even
        # the O_CREAT leaf inside the original stage if its public name moves.
        stage.check()
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(parent_fd)
        stage.check()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_fd)


def _remove_staged_entries(stage: _HeldStage, directory_fd: int) -> None:
    """Remove only children of a held directory; never follow a rebound name."""
    with os.scandir(directory_fd) as entries:
        names = [entry.name for entry in entries]
    for name in names:
        stage.check(require_unchanged_parent=False)
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(metadata.st_mode):
            child = os.open(name, _DIR_FLAGS, dir_fd=directory_fd)
            try:
                _remove_staged_entries(stage, child)
            finally:
                os.close(child)
            stage.check(require_unchanged_parent=False)
            os.rmdir(name, dir_fd=directory_fd)
        else:
            stage.check(require_unchanged_parent=False)
            os.unlink(name, dir_fd=directory_fd)


def _selected_entries(
    entries: tuple[tuple[str, str, str], ...], include_history: bool,
) -> dict[str, tuple[str, str]]:
    expected: dict[str, tuple[str, str]] = {}
    if ("reconstructed-final", "directory", "directory") not in entries:
        raise RehydrateError("verified reconstructed-final root is missing")
    for name, kind, identity in entries:
        parts = PurePosixPath(name).parts
        if not parts or parts[0] != "reconstructed-final" or len(parts) == 1:
            continue
        relative = PurePosixPath(*parts[1:])
        if not _include(relative, include_history):
            continue
        key = relative.as_posix()
        if key in REHYDRATE_CONTROL_NAMES:
            raise RehydrateError(f"source contains reserved rehydrate control: {key}")
        if key in expected:
            raise RehydrateError(f"duplicate verified source entry: {key}")
        expected[key] = (kind, identity)
    return expected


def _verify_materialized_stage(
    stage: _HeldStage, expected: dict[str, tuple[str, str]],
) -> None:
    seen: set[str] = set()

    def walk(directory_fd: int, prefix: tuple[str, ...]) -> None:
        with os.scandir(directory_fd) as entries:
            names = sorted(entry.name for entry in entries)
        for name in names:
            relative = PurePosixPath(*prefix, name).as_posix()
            identity = expected.get(relative)
            if identity is None or relative in seen:
                raise RehydrateError(f"materialized stage has an unexpected object: {relative}")
            seen.add(relative)
            kind, digest = identity
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if kind == "directory" and stat.S_ISDIR(metadata.st_mode):
                child = os.open(name, _DIR_FLAGS, dir_fd=directory_fd)
                try:
                    walk(child, (*prefix, name))
                finally:
                    os.close(child)
                continue
            if kind == "file" and stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
                try:
                    held = os.fstat(descriptor)
                    if (held.st_dev, held.st_ino) != (metadata.st_dev, metadata.st_ino):
                        raise RehydrateError(f"materialized stage file rebound: {relative}")
                    hasher = hashlib.sha256()
                    while chunk := os.read(descriptor, 1024 * 1024):
                        hasher.update(chunk)
                    after = os.fstat(descriptor)
                    if (
                        hasher.hexdigest() == digest
                        and (held.st_dev, held.st_ino, held.st_size, held.st_mtime_ns)
                        == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                    ):
                        continue
                finally:
                    os.close(descriptor)
            raise RehydrateError(f"materialized stage differs from verified record: {relative}")

    stage.check()
    walk(stage.stage_fd, ())
    stage.check()
    if seen != expected.keys():
        raise RehydrateError("materialized stage is missing verified objects")


def _copy_materialized(
    source: Path, stage: _HeldStage, include_history: bool,
    verified_entries: tuple[tuple[str, str, str], ...],
) -> None:
    expected = _selected_entries(verified_entries, include_history)
    seen: set[str] = set()
    for path in sorted(source.rglob("*"), key=lambda item: item.relative_to(source).as_posix()):
        relative = PurePosixPath(path.relative_to(source).as_posix())
        if not _include(relative, include_history):
            continue
        key = relative.as_posix()
        identity = expected.get(key)
        if identity is None or key in seen:
            raise RehydrateError(f"rehydrate source differs from verified record: {relative}")
        seen.add(key)
        kind, digest = identity
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise RehydrateError(f"rehydrate source contains a non-control symlink: {relative}")
        if stat.S_ISDIR(metadata.st_mode):
            if kind != "directory" or stat.S_IMODE(metadata.st_mode) != 0o555:
                raise RehydrateError(f"rehydrate directory differs from verified record: {relative}")
            directory_fd = _open_staged_directory(stage, relative.parts)
            os.close(directory_fd)
            continue
        if (
            kind != "file" or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o444
        ):
            raise RehydrateError(f"rehydrate source contains an unsafe object: {relative}")
        payload = _stable_bytes(path)
        if _sha256_bytes(payload) != digest:
            raise RehydrateError(f"rehydrate source bytes differ from verified record: {relative}")
        _write_staged_file(stage, relative, payload, bool(metadata.st_mode & 0o111))
    if seen != expected.keys():
        raise RehydrateError("rehydrate source is missing verified objects")
    _verify_materialized_stage(stage, expected)


def _rename_noreplace(source: Path, destination: Path, *, directory_fd: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source.name)
    destination_bytes = os.fsencode(destination.name)
    if sys.platform == "darwin" and hasattr(libc, "renameatx_np"):
        result = libc.renameatx_np(
            ctypes.c_int(directory_fd), ctypes.c_char_p(source_bytes),
            ctypes.c_int(directory_fd), ctypes.c_char_p(destination_bytes),
            ctypes.c_uint(0x00000004),
        )
    elif sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        result = libc.renameat2(
            ctypes.c_int(directory_fd), ctypes.c_char_p(source_bytes),
            ctypes.c_int(directory_fd), ctypes.c_char_p(destination_bytes),
            ctypes.c_uint(1),
        )
    else:
        raise RehydrateError("platform lacks atomic no-replace rename")
    if result == 0:
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise RehydrateError(f"target already exists: {destination}")
    raise RehydrateError(f"cannot publish rehydrated project: {os.strerror(error)}")


def _canonical_json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def _bound_commit_is_visible(
    *, day0_root: Path, root_fd: int, target: Path, stage: _HeldStage,
    expected: bytes,
) -> bool:
    """Resolve an indeterminate final rename without trusting its exception."""
    try:
        named_root = os.lstat(day0_root)
        named_target = os.lstat(target)
        held_target = os.stat(target.name, dir_fd=root_fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(named_root.st_mode)
            or (named_root.st_dev, named_root.st_ino) != stage.parent_identity
            or not stat.S_ISDIR(named_target.st_mode)
            or (named_target.st_dev, named_target.st_ino) != stage.stage_identity
            or (held_target.st_dev, held_target.st_ino) != stage.stage_identity
        ):
            return False
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(".finished-commit.json", flags, dir_fd=stage.stage_fd)
        matches = False
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_size != len(expected)
            ):
                return False
            payload = os.read(descriptor, len(expected) + 1)
            after = os.fstat(descriptor)
            matches = (
                payload == expected
                and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            )
            return matches
        finally:
            try:
                os.close(descriptor)
            except OSError as exc:
                if not matches:
                    raise
                _warn_nonfatal(f"[WARN] bound commit marker close failed: {exc}")
    except OSError:
        return False


def _warn_nonfatal(message: str) -> None:
    try:
        print(message, file=sys.stderr)
    except (OSError, ValueError):
        pass


def rehydrate_record(
    *, record: Path, day0_root: Path, new_project: str,
    include_history: bool,
) -> Path:
    if not PROJECT_PATTERN.fullmatch(new_project):
        raise RehydrateError("new project name is invalid")
    day0_root = Path(day0_root)
    metadata = day0_root.lstat()
    if day0_root.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise RehydrateError("DAY0 root must be a real directory")
    target = day0_root / new_project
    if os.path.lexists(target):
        raise RehydrateError(f"target already exists: {target}")
    report = verify_record(Path(record))
    if not isinstance(report, _VerifiedReport):
        raise RehydrateError("record verification did not bind object identities")
    source = Path(record) / "reconstructed-final"
    root_fd = os.open(day0_root, _DIR_FLAGS)
    stage_fd = -1
    stage: _HeldStage | None = None
    stage_name: str | None = None
    created_stage_identity: tuple[int, int] | None = None
    published = False
    committed = False
    try:
        held_root = os.fstat(root_fd)
        visible_root = os.lstat(day0_root)
        if (
            not stat.S_ISDIR(held_root.st_mode)
            or (held_root.st_dev, held_root.st_ino)
            != (visible_root.st_dev, visible_root.st_ino)
        ):
            raise RehydrateError("DAY0 root rebound before staging")
        stage_name = f".{new_project}.rehydrate-{secrets.token_hex(16)}"
        os.mkdir(stage_name, 0o700, dir_fd=root_fd)
        created = os.stat(stage_name, dir_fd=root_fd, follow_symlinks=False)
        created_stage_identity = (created.st_dev, created.st_ino)
        stage_fd = os.open(stage_name, _DIR_FLAGS, dir_fd=root_fd)
        stage = _HeldStage(day0_root, root_fd, stage_name, stage_fd)
        if stage.stage_identity != created_stage_identity:
            raise RehydrateError("rehydrate stage rebound during open")
        stage.check()
        _copy_materialized(source, stage, include_history, report.entries)
        receipt = {
            "schema_version": 1,
            "state": "PREPARED",
            "source_record": str(Path(record).resolve(strict=True)),
            "project": report["project"],
            "record_id": report["record_id"],
            "content_sha256": report["content_sha256"],
            "include_history": bool(include_history),
        }
        receipt_bytes = _canonical_json_bytes(receipt)
        _write_staged_file(
            stage, PurePosixPath(".finished-source.json"),
            receipt_bytes,
            False,
        )
        commit_bytes = _canonical_json_bytes({
            "schema_version": 1,
            "state": "COMMITTED",
            "receipt_sha256": _sha256_bytes(receipt_bytes),
            "target_project": new_project,
            "target_dev": stage.stage_identity[0],
            "target_ino": stage.stage_identity[1],
        })
        _write_staged_file(
            stage, PurePosixPath(".finished-commit.ready"), commit_bytes, False,
        )
        stage.check()
        os.fsync(stage_fd)
        try:
            _rename_noreplace(Path(stage.name), target, directory_fd=root_fd)
            published = True
        except (OSError, RehydrateError) as exc:
            # A no-replace rename can have taken effect even if its caller saw
            # an error.  Keep the possibly published inode and its evidence.
            try:
                named = os.stat(target.name, dir_fd=root_fd, follow_symlinks=False)
                if (named.st_dev, named.st_ino) == stage.stage_identity:
                    published = True
            except OSError:
                pass
            if published:
                raise RehydrateError(
                    "rehydrate publication outcome indeterminate; pending target retained"
                ) from exc
            raise
        os.fsync(root_fd)
        named_root = os.lstat(day0_root)
        named_target = os.lstat(target)
        held_target = os.stat(target.name, dir_fd=root_fd, follow_symlinks=False)
        if (
            (named_root.st_dev, named_root.st_ino) != stage.parent_identity
            or not stat.S_ISDIR(named_target.st_mode)
            or (named_target.st_dev, named_target.st_ino) != stage.stage_identity
            or (held_target.st_dev, held_target.st_ino) != stage.stage_identity
        ):
            raise RehydrateError("rehydrated project rebound after publication")
        try:
            _rename_noreplace(
                Path(".finished-commit.ready"), Path(".finished-commit.json"),
                directory_fd=stage_fd,
            )
            committed = True
        except (OSError, RehydrateError) as exc:
            if _bound_commit_is_visible(
                day0_root=day0_root, root_fd=root_fd, target=target,
                stage=stage, expected=commit_bytes,
            ):
                committed = True
                _warn_nonfatal(
                    f"[WARN] rehydrate commit rename reported an error after "
                    f"the bound marker became visible: {exc}"
                )
            else:
                raise RehydrateError(
                    "rehydrate commit outcome indeterminate; pending target retained"
                ) from exc
        # The marker rename is the logical commit point.  No later durability
        # syscall may turn this committed outcome into a reported failure.
        return target
    finally:
        try:
            if stage is not None and not published:
                stage.check(require_unchanged_parent=False)
                _remove_staged_entries(stage, stage.stage_fd)
                stage.check(require_unchanged_parent=False)
                os.rmdir(stage.name, dir_fd=root_fd)
            elif stage is None and stage_name is not None and created_stage_identity is not None:
                try:
                    named = os.stat(stage_name, dir_fd=root_fd, follow_symlinks=False)
                    if (named.st_dev, named.st_ino) == created_stage_identity:
                        os.rmdir(stage_name, dir_fd=root_fd)
                except FileNotFoundError:
                    pass
        finally:
            close_error: OSError | None = None
            for descriptor, label in ((stage_fd, "stage"), (root_fd, "parent")):
                if descriptor < 0:
                    continue
                try:
                    os.close(descriptor)
                except OSError as exc:
                    if committed:
                        _warn_nonfatal(f"[WARN] committed rehydrate {label} close failed: {exc}")
                    elif close_error is None:
                        close_error = exc
            if close_error is not None:
                raise close_error


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "record", type=Path, help="Path to a verified finished record",
    )
    parser.add_argument(
        "new_project", help="Name for the new DAY0 project materialized from the record",
    )
    parser.add_argument(
        "--day0-root", type=Path, default=Path("DAY0-Prepare"),
        help="Existing DAY0 project root (default: DAY0-Prepare)",
    )
    parser.add_argument(
        "--include-history", action="store_true",
        help="Also restore history files that are omitted by default",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        target = rehydrate_record(
            record=args.record.expanduser().absolute(),
            day0_root=args.day0_root.expanduser().absolute(),
            new_project=args.new_project,
            include_history=args.include_history,
        )
    except (OSError, RehydrateError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    try:
        print(f"[OK] rehydrated finished record to {target}", flush=True)
        print("[NEXT] validate and load it as a normal DAY0 project", flush=True)
    except (OSError, ValueError) as exc:
        _warn_nonfatal(f"[WARN] rehydrate committed but success output failed: {exc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
