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
import shutil
import stat
import sys
import tempfile
from typing import Any


PROJECT_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
PRODUCTION_PREFIXES = ("99-output-",)
EXCLUDED_TOP_LEVEL = frozenset({"finished-history"})
CONTROL_NAMES = frozenset({
    "latest", "activation.json", "precommit.json", ".deployment.lock",
    ".sync-code-in-progress",
})


class RehydrateError(RuntimeError):
    """The finished record or destination is unsafe."""


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


def verify_record(record: Path) -> dict[str, Any]:
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
    return report


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


def _write_file(path: Path, payload: bytes, executable: bool) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o700 if executable else 0o600,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def _copy_materialized(source: Path, stage: Path, include_history: bool) -> None:
    for path in sorted(source.rglob("*"), key=lambda item: item.relative_to(source).as_posix()):
        relative = PurePosixPath(path.relative_to(source).as_posix())
        if not _include(relative, include_history):
            continue
        target = stage.joinpath(*relative.parts)
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise RehydrateError(f"rehydrate source contains a non-control symlink: {relative}")
        if stat.S_ISDIR(metadata.st_mode):
            target.mkdir(mode=0o700, parents=True, exist_ok=True)
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise RehydrateError(f"rehydrate source contains an unsafe object: {relative}")
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        payload = _stable_bytes(path)
        _write_file(target, payload, bool(metadata.st_mode & 0o111))


def _rename_noreplace(source: Path, destination: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source)
    destination_bytes = os.fsencode(destination)
    if sys.platform == "darwin" and hasattr(libc, "renamex_np"):
        result = libc.renamex_np(
            ctypes.c_char_p(source_bytes), ctypes.c_char_p(destination_bytes),
            ctypes.c_uint(0x00000004),
        )
    elif sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        result = libc.renameat2(
            ctypes.c_int(-100), ctypes.c_char_p(source_bytes),
            ctypes.c_int(-100), ctypes.c_char_p(destination_bytes),
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
    source = Path(record) / "reconstructed-final"
    stage = Path(tempfile.mkdtemp(prefix=f".{new_project}.rehydrate-", dir=day0_root))
    stage.chmod(0o700)
    try:
        _copy_materialized(source, stage, include_history)
        receipt = {
            "schema_version": 1,
            "source_record": str(Path(record).resolve(strict=True)),
            "project": report["project"],
            "record_id": report["record_id"],
            "content_sha256": report["content_sha256"],
            "include_history": bool(include_history),
        }
        _write_file(
            stage / ".finished-source.json",
            (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"),
            False,
        )
        _rename_noreplace(stage, target)
        descriptor = os.open(day0_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return target
    finally:
        if os.path.lexists(stage):
            shutil.rmtree(stage)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("record", type=Path)
    parser.add_argument("new_project")
    parser.add_argument("--day0-root", type=Path, default=Path("DAY0-Prepare"))
    parser.add_argument("--include-history", action="store_true")
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
    print(f"[OK] rehydrated finished record to {target}")
    print("[NEXT] validate and load it as a normal DAY0 project")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
