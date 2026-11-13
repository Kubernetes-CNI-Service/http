"""Read-only project pointer and local restore eligibility, without optional SDKs.

One standard-library authority. Compatibility callers pass their current callables
explicitly; public wrappers resolve this module\'s current hooks on every call.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat

_RECEIPT_SHA256 = re.compile(r"^[0-9a-f]{64}$")

REHYDRATE_RECEIPT_NAME = ".finished-source.json"
REHYDRATE_READY_NAME = ".finished-commit.ready"
REHYDRATE_COMMIT_NAME = ".finished-commit.json"
_REHYDRATE_RECEIPT_MAX_BYTES = 64 * 1024
_REHYDRATE_MARKER_MAX_BYTES = 4096
_REHYDRATE_RECEIPT_KEYS = frozenset({
    "schema_version", "state", "source_record", "project", "record_id",
    "content_sha256", "include_history",
})
_REHYDRATE_MARKER_KEYS = frozenset({
    "schema_version", "state", "receipt_sha256", "target_project",
    "target_dev", "target_ino",
})


def _read_rehydrate_control(directory_fd: int, name: str, limit: int) -> bytes | None:
    """Read one local restore control without following links or accepting a race."""
    try:
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ValueError(f"restore control cannot be inspected: {name}") from exc
    if (
        not stat.S_ISREG(named.st_mode) or named.st_nlink != 1
        or not 0 < named.st_size <= limit
    ):
        raise ValueError(f"restore control has an unsafe shape: {name}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except OSError as exc:
        raise ValueError(f"restore control cannot be opened: {name}") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            != (named.st_dev, named.st_ino, named.st_size, named.st_mtime_ns)
        ):
            raise ValueError(f"restore control was replaced: {name}")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        try:
            named_after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            raise ValueError(f"restore control disappeared: {name}") from exc
        identity = lambda item: (
            item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns
        )
        if remaining or identity(opened) != identity(after) or identity(opened) != identity(named_after):
            raise ValueError(f"restore control changed while reading: {name}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _require_project_eligible(project: Path, read_control) -> None:
    """Reject a restore until its local, inode-bound commit marker is present.

    Ordinary projects predating this protocol have none of its three controls.
    A copied receipt or marker is not a portable authorization: the finished
    record is the provenance authority on another host.  Callers must also
    bind their selected path and recheck before irreversible work.
    """
    project = Path(project)
    # sync-code publishes this workspace-root marker before its first remote
    # write and clears it only after the final source authority receipt.  A
    # copied project without local restore controls is still ineligible while
    # its receiving tree is incomplete.
    sync_marker = project.parent.parent / ".sync-code-in-progress"
    try:
        sync_marker.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise ValueError(f"project sync state cannot be inspected: {sync_marker}") from exc
    else:
        raise ValueError(f"project sync is incomplete: {sync_marker}")
    try:
        named_project = project.lstat()
        if not stat.S_ISDIR(named_project.st_mode):
            raise ValueError(f"project must be a real directory: {project}")
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        directory_fd = os.open(project, flags)
    except OSError as exc:
        raise ValueError(f"project cannot be inspected: {project}") from exc
    try:
        opened_project = os.fstat(directory_fd)
        if (opened_project.st_dev, opened_project.st_ino) != (
            named_project.st_dev, named_project.st_ino
        ):
            raise ValueError(f"project was replaced: {project}")
        receipt_bytes = read_control(
            directory_fd, REHYDRATE_RECEIPT_NAME, _REHYDRATE_RECEIPT_MAX_BYTES,
        )
        ready_bytes = read_control(
            directory_fd, REHYDRATE_READY_NAME, _REHYDRATE_MARKER_MAX_BYTES,
        )
        marker_bytes = read_control(
            directory_fd, REHYDRATE_COMMIT_NAME, _REHYDRATE_MARKER_MAX_BYTES,
        )
        if receipt_bytes is None and ready_bytes is None and marker_bytes is None:
            return
        if receipt_bytes is None or ready_bytes is not None or marker_bytes is None:
            raise ValueError(f"restored project has no completed commit: {project}")
        try:
            receipt = json.loads(receipt_bytes.decode("ascii"))
            marker = json.loads(marker_bytes.decode("ascii"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"restored project has malformed commit controls: {project}") from exc
        if (
            not isinstance(receipt, dict) or set(receipt) != _REHYDRATE_RECEIPT_KEYS
            or type(receipt["schema_version"]) is not int or receipt["schema_version"] != 1
            or receipt["state"] != "PREPARED"
            or not isinstance(receipt["source_record"], str)
            or not receipt["source_record"].startswith("/")
            or not isinstance(receipt["project"], str) or not receipt["project"]
            or not isinstance(receipt["record_id"], str) or not receipt["record_id"]
            or not isinstance(receipt["content_sha256"], str)
            or not _RECEIPT_SHA256.fullmatch(receipt["content_sha256"])
            or type(receipt["include_history"]) is not bool
        ):
            raise ValueError(f"restored project has an invalid receipt: {project}")
        if (
            not isinstance(marker, dict) or set(marker) != _REHYDRATE_MARKER_KEYS
            or type(marker["schema_version"]) is not int or marker["schema_version"] != 1
            or marker["state"] != "COMMITTED"
            or marker["receipt_sha256"] != hashlib.sha256(receipt_bytes).hexdigest()
            or marker["target_project"] != project.name
            or type(marker["target_dev"]) is not int
            or type(marker["target_ino"]) is not int
            or (marker["target_dev"], marker["target_ino"])
            != (opened_project.st_dev, opened_project.st_ino)
        ):
            raise ValueError(f"restored project has a mismatched commit marker: {project}")
        named_after = project.lstat()
        opened_after = os.fstat(directory_fd)
        if (
            (named_after.st_dev, named_after.st_ino)
            != (opened_project.st_dev, opened_project.st_ino)
            or (opened_after.st_dev, opened_after.st_ino)
            != (opened_project.st_dev, opened_project.st_ino)
        ):
            raise ValueError(f"project was replaced during commit check: {project}")
    finally:
        os.close(directory_fd)


# R-016 §2: the one link that changes with the project.
ACTIVE_PROJECT_POINTER = "DAY0-Prepare/activate-project"
# R-016 §2, §4.2 细节 (R16-19): DAY0-Prepare entries the pointer never selects.
ACTIVE_PROJECT_EXCLUDED_NAMES = frozenset({"template", "activate-project", "tests", "test_cases", "dumps"})


class ActiveProjectPointerError(ValueError):
    """DAY0-Prepare/activate-project exists but does not select an eligible project (R-016 §2)."""


def _active_project_dir(http_root: str | os.PathLike[str], require_eligible) -> Path | None:
    """The real directory of the project DAY0-Prepare/activate-project selects (R-016 §5.1).

    None when there is no pointer.  The pointer is valid only when it is a link whose text is one plain
    name, not in ACTIVE_PROJECT_EXCLUDED_NAMES and not starting with ".", DAY0-Prepare/<name> is a real
    directory by lstat, and require_project_eligible accepts it; otherwise ActiveProjectPointerError names
    the reason.  Read-only and lock-free: resolve once per run, then read project files through the result.
    """
    day0 = Path(http_root) / "DAY0-Prepare"
    pointer = day0 / "activate-project"
    try:
        pointer_mode = pointer.lstat().st_mode
    except FileNotFoundError:
        return None
    if not stat.S_ISLNK(pointer_mode):
        raise ActiveProjectPointerError(f"{ACTIVE_PROJECT_POINTER} is not a link: {pointer}")
    name = os.readlink(pointer)
    if "/" in name or name.startswith(".") or name in ACTIVE_PROJECT_EXCLUDED_NAMES:
        raise ActiveProjectPointerError(
            f"{ACTIVE_PROJECT_POINTER} -> {name} is not a project name (one plain name; not "
            f"{', '.join(sorted(ACTIVE_PROJECT_EXCLUDED_NAMES))}; no leading '.')"
        )
    project = day0 / name
    try:
        project_mode = project.lstat().st_mode
    except FileNotFoundError:
        raise ActiveProjectPointerError(
            f"{ACTIVE_PROJECT_POINTER} -> {name}: DAY0-Prepare/{name} does not exist") from None
    if not stat.S_ISDIR(project_mode):
        raise ActiveProjectPointerError(
            f"{ACTIVE_PROJECT_POINTER} -> {name}: DAY0-Prepare/{name} is not a real directory")
    try:
        require_eligible(project)
    except ValueError as exc:
        raise ActiveProjectPointerError(f"{ACTIVE_PROJECT_POINTER} -> {name}: {exc}") from exc
    return Path(os.path.realpath(project))


def require_project_eligible(project: Path) -> None:
    """Use the current local control-reader hook for the unique eligibility core."""
    return _require_project_eligible(project, _read_rehydrate_control)


def active_project_dir(http_root: str | os.PathLike[str]) -> Path | None:
    """Resolve the complete pointer using this module\'s current eligibility hook."""
    return _active_project_dir(http_root, require_project_eligible)
