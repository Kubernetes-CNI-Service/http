#!/usr/bin/env python3
"""Export and attest one immutable Git tree for the root authority workflow.

The implementation deliberately reads object bytes with ``git ls-tree`` and
``git cat-file``.  It never treats mutable worktree bytes as source.  Every
filesystem traversal uses dirfd operations with O_NOFOLLOW, and every leaf is
created exclusively with O_EXCL.  Verification is an independent walk with
exact set equality against the canonical manifest.  The caller supplies the
already recorded ``HEAD^{tree}`` identity.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, replace
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
from typing import Iterable, Mapping, Sequence
import unicodedata


_ALLOWED_MODES = frozenset(("100644", "100755", "120000"))
_REGULAR_MODES = {"100644": 0o644, "100755": 0o755}
_DIRECTORY_MODE = 0o755
_MAX_MANIFEST_BYTES = 64 * 1024 * 1024
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
TRUSTED_GIT_PATH = "/usr/bin/git"
GIT_COMMAND_DEADLINE_SECONDS = 30.0
REQUIRED_AUTHORITY_LEAVES: Mapping[str, str] = {
    "test_cases/monitor_authority_source_guard.py": "100644",
    "test_cases/monitor_authority_root_warden.py": "100644",
    "test_cases/run_monitor_authority_entrypoints.sh": "100755",
    "tools/control-auth.py": "100755",
    "infra/infra-setup.sh": "100755",
    "infra/docker/deploy.sh": "100755",
    "infra/infra-teardown.sh": "100755",
    "infra/docker/hostlock.py": "100755",
    "infra/docker/activate.py": "100755",
    "infra/docker/healthcheck.py": "100755",
    "infra/docker/apache-ztp.conf": "100644",
    "monitor/ztp-monitor-control.cgi": "100755",
}


class SourceGuardError(RuntimeError):
    """The immutable source contract could not be proven."""


@dataclass(frozen=True)
class TreeEntry:
    """One accepted Git leaf and, after ``read_tree``, its immutable bytes."""

    path: str
    git_mode: str
    blob_id: str
    payload: bytes | None = None

    @property
    def kind(self) -> str:
        return "symlink" if self.git_mode == "120000" else "file"


@dataclass
class HeldRepository:
    """One source-directory identity retained across every Git operation."""

    path: str
    descriptor: int
    identity: tuple[int, int, int, int, int]
    closed: bool = False

    @property
    def command_path(self) -> str:
        if sys.platform.startswith("linux"):
            return f"/proc/self/fd/{self.descriptor}"
        # Darwin does not expose an opened directory as a traversable /dev/fd
        # path.  The held descriptor is nevertheless retained and the fixed
        # absolute name is compared with it before and after every read-only
        # Git command; any rebind therefore fails before caller side effects.
        return self.path

    def verify_binding(self) -> None:
        self.verify_descriptor()
        held = os.fstat(self.descriptor)
        try:
            named = os.stat(self.path, follow_symlinks=False)
        except OSError as exc:
            raise _fail("source directory name no longer resolves safely") from exc
        current = (
            held.st_dev, held.st_ino, held.st_mode, held.st_uid, held.st_gid,
        )
        named_identity = (
            named.st_dev, named.st_ino, named.st_mode, named.st_uid, named.st_gid,
        )
        if current != self.identity or named_identity != self.identity:
            raise _fail("source directory identity was rebound")

    def verify_descriptor(self) -> None:
        """Verify the held identity when the old root name is intentionally gone."""

        if self.closed:
            raise _fail("held source directory is closed")
        held = os.fstat(self.descriptor)
        current = (
            held.st_dev, held.st_ino, held.st_mode, held.st_uid, held.st_gid,
        )
        if current != self.identity:
            raise _fail("held source directory identity changed")

    def close(self) -> None:
        if not self.closed:
            os.close(self.descriptor)
            self.closed = True


@dataclass
class HeldExport:
    """A held export root re-attested before and after its consumer runs."""

    descriptor: int
    manifest: bytes
    expected_tree_id: str
    required_uid: int
    required_gid: int
    readonly: bool
    closed: bool = False

    def verify(self) -> None:
        if self.closed:
            raise _fail("held source export is closed")
        if self.readonly and not (
            os.fstatvfs(self.descriptor).f_flag & os.ST_RDONLY
        ):
            raise _fail("held source export is no longer read-only")
        verify_export(
            Path("."), self.manifest,
            expected_tree_id=self.expected_tree_id,
            required_uid=self.required_uid,
            required_gid=self.required_gid,
            _root_descriptor=self.descriptor,
        )

    def close(self) -> None:
        if not self.closed:
            os.close(self.descriptor)
            self.closed = True


def _fail(message: str) -> SourceGuardError:
    return SourceGuardError(message)


def _validate_object_id(value: str, label: str) -> str:
    if not isinstance(value, str) or len(value) not in (40, 64):
        raise _fail(f"{label} is not a supported full Git object ID")
    if any(character not in "0123456789abcdef" for character in value):
        raise _fail(f"{label} is not lowercase hexadecimal")
    return value


def _validate_safe_text(value: str, label: str) -> None:
    if not isinstance(value, str):
        raise _fail(f"{label} is not text")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError as exc:
        raise _fail(f"{label} is not valid UTF-8") from exc
    if not encoded or len(encoded) > 4096:
        raise _fail(f"{label} has an unsafe byte length")
    if "\x00" in value or "\\" in value:
        raise _fail(f"{label} contains an unsafe character")
    for character in value:
        if unicodedata.category(character) in {"Cc", "Cf", "Cs"}:
            raise _fail(f"{label} contains a control character")


def _validate_path(path: str) -> tuple[str, ...]:
    _validate_safe_text(path, "tree path")
    if path.startswith("/") or path.endswith("/") or "//" in path:
        raise _fail("tree path is not a canonical relative path")
    parts = tuple(path.split("/"))
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise _fail("tree path contains an unsafe component")
    for part in parts:
        if part == ".git":
            raise _fail("tree path exposes Git administrative state")
        if len(part.encode("utf-8")) > 255:
            raise _fail("tree path component is too long")
    return parts


def parse_ls_tree_record(record: bytes) -> TreeEntry:
    """Parse one NUL-delimited ``ls-tree`` record without lossy decoding."""

    if not isinstance(record, bytes) or not record or b"\x00" in record:
        raise _fail("malformed Git tree record")
    if record.count(b"\t") != 1:
        raise _fail("malformed Git tree record header")
    header, raw_path = record.split(b"\t", 1)
    fields = header.split(b" ")
    if len(fields) != 3 or any(not field for field in fields):
        raise _fail("malformed Git tree record fields")
    try:
        mode = fields[0].decode("ascii", "strict")
        object_type = fields[1].decode("ascii", "strict")
        blob_id = fields[2].decode("ascii", "strict")
        path = raw_path.decode("utf-8", "strict")
    except UnicodeError as exc:
        raise _fail("Git tree record has invalid text encoding") from exc
    if mode not in _ALLOWED_MODES or object_type != "blob":
        raise _fail("Git tree record has a forbidden type or mode")
    _validate_object_id(blob_id, "blob ID")
    _validate_path(path)
    return TreeEntry(path=path, git_mode=mode, blob_id=blob_id)


def validate_entries(entries: Iterable[TreeEntry]) -> tuple[TreeEntry, ...]:
    """Validate uniqueness and the leaf/parent shape, returning path order."""

    materialized = tuple(entries)
    seen: set[str] = set()
    for entry in materialized:
        if not isinstance(entry, TreeEntry):
            raise _fail("tree entry has an unexpected representation")
        _validate_path(entry.path)
        if entry.git_mode not in _ALLOWED_MODES:
            raise _fail("tree entry has a forbidden mode")
        _validate_object_id(entry.blob_id, "blob ID")
        if entry.path in seen:
            raise _fail(f"duplicate tree path: {entry.path}")
        seen.add(entry.path)

    for path in seen:
        parts = path.split("/")
        for index in range(1, len(parts)):
            if "/".join(parts[:index]) in seen:
                raise _fail("a Git leaf is also used as a directory")
    return tuple(sorted(materialized, key=lambda item: item.path.encode("utf-8")))


def _secure_absolute_directory(path: Path) -> int:
    """Open an existing directory while refusing every symlink component."""

    raw = os.path.abspath(os.fspath(path))
    # macOS presents temporary paths through two root-owned compatibility
    # aliases.  Translate only those fixed aliases; resolving the whole path
    # here would silently accept an attacker-controlled intermediate symlink.
    for alias, physical in (("/var", "/private/var"), ("/tmp", "/private/tmp")):
        if raw == alias or raw.startswith(alias + "/"):
            try:
                alias_metadata = os.lstat(alias)
                alias_target = os.readlink(alias)
            except OSError:
                break
            expected_target = physical.lstrip("/")
            if (
                stat.S_ISLNK(alias_metadata.st_mode)
                and alias_metadata.st_uid == 0
                and alias_target == expected_target
            ):
                raw = physical + raw[len(alias):]
            break
    if not os.path.isabs(raw):
        raise _fail("directory path is not absolute")
    components = [component for component in raw.split(os.sep) if component]
    flags = os.O_RDONLY | _O_DIRECTORY | os.O_NOFOLLOW | _O_CLOEXEC
    try:
        descriptor = os.open(os.sep, flags)
    except OSError as exc:
        raise _fail("cannot open filesystem root") from exc
    try:
        for component in components:
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except OSError as exc:
                raise _fail(f"unsafe or unavailable directory component: {component}") from exc
            os.close(descriptor)
            descriptor = child
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def hold_repository(repo: os.PathLike[str] | str) -> HeldRepository:
    """Open and retain one safe source-directory identity."""

    absolute = os.path.abspath(os.fspath(repo))
    descriptor = _secure_absolute_directory(Path(absolute))
    metadata = os.fstat(descriptor)
    held = HeldRepository(
        path=absolute,
        descriptor=descriptor,
        identity=(
            metadata.st_dev, metadata.st_ino, metadata.st_mode,
            metadata.st_uid, metadata.st_gid,
        ),
    )
    try:
        held.verify_binding()
    except Exception:
        held.close()
        raise
    return held


@contextmanager
def _repository_scope(
    repo: os.PathLike[str] | str | HeldRepository,
):
    owned = not isinstance(repo, HeldRepository)
    held = hold_repository(repo) if owned else repo
    assert isinstance(held, HeldRepository)
    held.verify_binding()
    try:
        yield held
        held.verify_binding()
    finally:
        if owned:
            held.close()


def _open_trusted_git() -> tuple[int, tuple[int, ...]]:
    try:
        descriptor = os.open(
            TRUSTED_GIT_PATH,
            os.O_RDONLY | os.O_NOFOLLOW | _O_CLOEXEC,
        )
    except OSError as exc:
        raise _fail("trusted absolute Git executable is unavailable") from exc
    metadata = os.fstat(descriptor)
    identity = _metadata_fingerprint(metadata)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not stat.S_IMODE(metadata.st_mode) & 0o111
    ):
        os.close(descriptor)
        raise _fail("trusted absolute Git executable metadata is unsafe")
    return descriptor, identity


def _git_executable_path(descriptor: int) -> str:
    if sys.platform.startswith("linux"):
        return f"/proc/self/fd/{descriptor}"
    # Darwin's kernel rejects execve(2) through /dev/fd even when the held
    # descriptor is passed to the child.  The fixed root-owned pathname is
    # still checked against the held identity immediately before and after
    # execution; caller PATH is never consulted.
    return TRUSTED_GIT_PATH


def _run_git(
    repo: HeldRepository,
    arguments: Sequence[str],
) -> tuple[int, bytes, bytes]:
    repo.verify_binding()
    git_descriptor, git_identity = _open_trusted_git()
    command = [
        _git_executable_path(git_descriptor),
        "-c", f"safe.directory={repo.path}", "-c", "core.fsmonitor=false",
        "-C", repo.command_path, *arguments,
    ]
    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env={
                "HOME": "/nonexistent",
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_NO_REPLACE_OBJECTS": "1",
                "GIT_TERMINAL_PROMPT": "0",
            },
            close_fds=True,
            pass_fds=(repo.descriptor, git_descriptor),
            timeout=GIT_COMMAND_DEADLINE_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise _fail("Git object command exceeded its fixed deadline") from exc
    except (OSError, ValueError) as exc:
        raise _fail("Git object command could not be executed") from exc
    finally:
        try:
            current_git = os.fstat(git_descriptor)
            named_git = os.stat(TRUSTED_GIT_PATH, follow_symlinks=False)
            if (
                _metadata_fingerprint(current_git) != git_identity
                or _metadata_fingerprint(named_git) != git_identity
            ):
                raise _fail("trusted absolute Git executable identity changed")
        finally:
            os.close(git_descriptor)
    repo.verify_binding()
    return result.returncode, result.stdout, result.stderr


def _git(
    repo: HeldRepository, arguments: Sequence[str], *, allow_status: bool = False,
) -> bytes:
    returncode, stdout, stderr = _run_git(repo, arguments)
    if returncode != 0 and not allow_status:
        diagnostic = stderr[:512].decode("utf-8", "replace").strip()
        raise _fail(f"Git object command failed: {diagnostic or returncode}")
    return stdout if returncode == 0 else b""


def _git_status(
    repo: HeldRepository, arguments: Sequence[str],
) -> tuple[int, bytes, bytes]:
    return _run_git(repo, arguments)


def require_clean_head_tree(
    repo: os.PathLike[str] | str | HeldRepository,
    expected_tree_id: str,
) -> str:
    """Require a clean index/worktree bound to the exact ``HEAD^{tree}``."""

    expected = _validate_object_id(expected_tree_id, "expected tree ID")
    with _repository_scope(repo) as repository:
        resolved_bytes = _git(repository, ("rev-parse", "--verify", "HEAD^{tree}"))
        try:
            resolved = resolved_bytes.decode("ascii", "strict").strip()
        except UnicodeError as exc:
            raise _fail("HEAD tree identity is not ASCII") from exc
        _validate_object_id(resolved, "HEAD tree ID")
        if resolved != expected:
            raise _fail("HEAD tree identity does not match the recorded tree")

        index_tree_bytes = _git(repository, ("write-tree",))
        try:
            index_tree = index_tree_bytes.decode("ascii", "strict").strip()
        except UnicodeError as exc:
            raise _fail("index tree identity is not ASCII") from exc
        if index_tree != expected:
            raise _fail("index tree differs from the recorded HEAD tree")

        status, output, diagnostic = _git_status(
            repository,
            (
                "status", "--porcelain=v1", "-z", "--untracked-files=all",
                "--ignored=matching", "--ignore-submodules=none",
            ),
        )
        if status != 0:
            text = diagnostic[:512].decode("utf-8", "replace").strip()
            raise _fail(f"Git cleanliness check failed: {text or status}")
        if output:
            raise _fail("index, worktree, untracked, or ignored drift exists")
        _require_worktree_matches_entries(repository, read_tree(repository, expected))
        return resolved


def _require_worktree_matches_entries(
    repository: HeldRepository, entries: Sequence[TreeEntry],
) -> None:
    """Compare every immutable tree leaf with mutable worktree bytes directly.

    This intentionally does not trust Git's assume-unchanged or skip-worktree
    status hints.  Untracked and ignored paths are rejected by the independent
    porcelain check above and are never source-exported.
    """

    repository.verify_binding()
    root_fd = os.dup(repository.descriptor)
    try:
        for entry in entries:
            if entry.payload is None:
                raise _fail("immutable worktree comparison lacks blob bytes")
            parts = entry.path.split("/")
            parent_fd = _open_relative_directory(root_fd, parts[:-1])
            try:
                metadata = os.stat(
                    parts[-1], dir_fd=parent_fd, follow_symlinks=False,
                )
                if entry.kind == "file":
                    expected_mode = _REGULAR_MODES[entry.git_mode]
                    if (
                        not stat.S_ISREG(metadata.st_mode)
                        or stat.S_IMODE(metadata.st_mode) != expected_mode
                    ):
                        raise _fail(f"tracked worktree mode/type drift: {entry.path}")
                    descriptor = os.open(
                        parts[-1], os.O_RDONLY | os.O_NOFOLLOW | _O_CLOEXEC,
                        dir_fd=parent_fd,
                    )
                    try:
                        opened = os.fstat(descriptor)
                        chunks: list[bytes] = []
                        while True:
                            chunk = os.read(descriptor, 1024 * 1024)
                            if not chunk:
                                break
                            chunks.append(chunk)
                        after = os.fstat(descriptor)
                    finally:
                        os.close(descriptor)
                    if (
                        (metadata.st_dev, metadata.st_ino)
                        != (opened.st_dev, opened.st_ino)
                        or not stat.S_ISREG(opened.st_mode)
                        or not stat.S_ISREG(after.st_mode)
                        or stat.S_IMODE(opened.st_mode) != expected_mode
                        or stat.S_IMODE(after.st_mode) != expected_mode
                        or _metadata_fingerprint(opened)
                        != _metadata_fingerprint(after)
                        or b"".join(chunks) != entry.payload
                    ):
                        raise _fail(f"tracked worktree byte/identity drift: {entry.path}")
                else:
                    if not stat.S_ISLNK(metadata.st_mode):
                        raise _fail(f"tracked worktree symlink type drift: {entry.path}")
                    target = os.readlink(parts[-1], dir_fd=parent_fd)
                    after = os.stat(
                        parts[-1], dir_fd=parent_fd, follow_symlinks=False,
                    )
                    if (
                        target.encode("utf-8", "strict") != entry.payload
                        or _metadata_fingerprint(after)
                        != _metadata_fingerprint(metadata)
                    ):
                        raise _fail(f"tracked worktree symlink target drift: {entry.path}")
            except OSError as exc:
                raise _fail(f"cannot safely compare tracked worktree leaf: {entry.path}") from exc
            finally:
                os.close(parent_fd)
    finally:
        os.close(root_fd)
        repository.verify_binding()


def _git_object_digest(payload: bytes, width: int) -> str:
    framed = b"blob " + str(len(payload)).encode("ascii") + b"\x00" + payload
    if width == 40:
        return hashlib.sha1(framed).hexdigest()
    if width == 64:
        return hashlib.sha256(framed).hexdigest()
    raise _fail("unsupported Git object ID width")


def _derived_directories(paths: Iterable[str]) -> set[str]:
    directories: set[str] = set()
    for path in paths:
        parts = path.split("/")
        for index in range(1, len(parts)):
            directories.add("/".join(parts[:index]))
    return directories


def _normalize_virtual(parts: Iterable[str]) -> tuple[str, ...]:
    result: list[str] = []
    for part in parts:
        if part in ("", "."):
            continue
        if part == "..":
            if not result:
                raise _fail("symlink target escapes the source root")
            result.pop()
            continue
        result.append(part)
    return tuple(result)


def _validate_symlink_target_text(target: str) -> None:
    _validate_safe_text(target, "symlink target")
    if target.startswith("/") or target.endswith("/") or "//" in target:
        raise _fail("symlink target is not a safe relative target")
    for part in target.split("/"):
        if part not in ("", ".", "..") and len(part.encode("utf-8")) > 255:
            raise _fail("symlink target component is too long")


def _validate_symlinks(entries: Sequence[TreeEntry]) -> None:
    by_path = {entry.path: entry for entry in entries}
    directories = _derived_directories(by_path)
    existing = set(by_path) | directories | {""}

    def resolve(link_path: str) -> tuple[str, ...]:
        original = by_path[link_path]
        if original.payload is None:
            raise _fail("symlink blob bytes are unavailable")
        try:
            initial_target = original.payload.decode("utf-8", "strict")
        except UnicodeError as exc:
            raise _fail("symlink target is not valid UTF-8") from exc
        _validate_symlink_target_text(initial_target)

        resolved = link_path.split("/")[:-1]
        pending = initial_target.split("/")
        visited: set[str] = {link_path}
        while pending:
            component = pending.pop(0)
            if component in ("", "."):
                continue
            if component == "..":
                if not resolved:
                    raise _fail("symlink target escapes the source root")
                resolved.pop()
                continue
            resolved.append(component)
            candidate = "/".join(resolved)
            target_entry = by_path.get(candidate)
            if target_entry is not None and target_entry.kind == "symlink":
                if candidate in visited:
                    raise _fail("looping symlink in Git tree")
                visited.add(candidate)
                if target_entry.payload is None:
                    raise _fail("symlink blob bytes are unavailable")
                try:
                    nested = target_entry.payload.decode("utf-8", "strict")
                except UnicodeError as exc:
                    raise _fail("symlink target is not valid UTF-8") from exc
                _validate_symlink_target_text(nested)
                resolved.pop()
                pending = nested.split("/") + pending
                continue
            if candidate not in existing:
                raise _fail("dangling symlink in Git tree")
            if target_entry is not None and pending:
                raise _fail("symlink traverses through a non-directory leaf")
        final = "/".join(resolved)
        if final not in existing:
            raise _fail("dangling symlink in Git tree")
        return tuple(resolved)

    for entry in entries:
        if entry.kind == "symlink":
            resolve(entry.path)


def read_tree(
    repo: os.PathLike[str] | str | HeldRepository,
    tree_id: str,
) -> tuple[TreeEntry, ...]:
    """Read, hash, and validate every leaf of one immutable Git tree object."""

    accepted_tree_id = _validate_object_id(tree_id, "tree ID")
    with _repository_scope(repo) as repository:
        raw = _git(
            repository,
            ("ls-tree", "-rz", "--full-tree", "--full-name", accepted_tree_id),
        )
        records: list[bytes]
        if raw:
            if not raw.endswith(b"\x00"):
                raise _fail("Git tree output is not NUL terminated")
            records = raw[:-1].split(b"\x00")
        else:
            records = []
        entries = validate_entries(parse_ls_tree_record(record) for record in records)

        populated: list[TreeEntry] = []
        for entry in entries:
            payload = _git(repository, ("cat-file", "blob", entry.blob_id))
            actual_id = _git_object_digest(payload, len(entry.blob_id))
            if actual_id != entry.blob_id:
                raise _fail(f"Git blob bytes do not match object ID: {entry.path}")
            populated.append(replace(entry, payload=payload))
        result = validate_entries(populated)
        _validate_symlinks(result)
        return result


def _manifest_bytes(tree_id: str, entries: Sequence[TreeEntry]) -> bytes:
    document_entries: list[dict[str, object]] = []
    for entry in entries:
        if entry.payload is None:
            raise _fail("cannot manifest an unread Git entry")
        target: str | None = None
        if entry.kind == "symlink":
            try:
                target = entry.payload.decode("utf-8", "strict")
            except UnicodeError as exc:
                raise _fail("symlink target is not valid UTF-8") from exc
        document_entries.append({
            "blob_id": entry.blob_id,
            "git_mode": entry.git_mode,
            "kind": entry.kind,
            "path": entry.path,
            "sha256": hashlib.sha256(entry.payload).hexdigest(),
            "target": target,
        })
    document = {
        "entries": document_entries,
        "schema_version": 1,
        "tree_id": tree_id,
    }
    return (
        json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _reconstruct_tree_id(
    entries: Sequence[Mapping[str, object]], width: int,
) -> str:
    """Rebuild the Git tree object graph from manifested modes and blob IDs."""

    hierarchy: dict[str, object] = {}
    for entry in entries:
        parts = str(entry["path"]).split("/")
        node = hierarchy
        for part in parts[:-1]:
            existing = node.setdefault(part, {})
            if not isinstance(existing, dict):
                raise _fail("manifest tree topology is ambiguous")
            node = existing
        if parts[-1] in node:
            raise _fail("manifest tree contains a duplicate leaf")
        node[parts[-1]] = ("leaf", entry)

    algorithm = hashlib.sha1 if width == 40 else hashlib.sha256

    def digest_node(node: Mapping[str, object]) -> bytes:
        records: list[tuple[bytes, bytes]] = []
        for name, value in node.items():
            encoded = name.encode("utf-8", "strict")
            if isinstance(value, dict):
                object_id = digest_node(value)
                record = b"40000 " + encoded + b"\x00" + object_id
                ordering = encoded + b"/"
            else:
                if (
                    not isinstance(value, tuple) or len(value) != 2
                    or value[0] != "leaf" or not isinstance(value[1], Mapping)
                ):
                    raise _fail("manifest tree topology is invalid")
                leaf = value[1]
                mode = str(leaf["git_mode"]).encode("ascii")
                object_id = bytes.fromhex(str(leaf["blob_id"]))
                record = mode + b" " + encoded + b"\x00" + object_id
                ordering = encoded
            records.append((ordering, record))
        payload = b"".join(record for _key, record in sorted(records))
        framed = b"tree " + str(len(payload)).encode("ascii") + b"\x00" + payload
        return algorithm(framed).digest()

    return digest_node(hierarchy).hex()


def _open_relative_directory(root_fd: int, parts: Sequence[str]) -> int:
    flags = os.O_RDONLY | _O_DIRECTORY | os.O_NOFOLLOW | _O_CLOEXEC
    descriptor = os.dup(root_fd)
    try:
        for part in parts:
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _set_fd_metadata(fd: int, mode: int, uid: int, gid: int) -> None:
    os.fchmod(fd, mode)
    current = os.fstat(fd)
    if (current.st_uid, current.st_gid) != (uid, gid):
        os.fchown(fd, uid, gid)
    current = os.fstat(fd)
    if stat.S_IMODE(current.st_mode) != mode:
        raise _fail("created path mode could not be fixed exactly")
    if (current.st_uid, current.st_gid) != (uid, gid):
        raise _fail("created path owner could not be fixed exactly")


def _write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    written = 0
    while written < len(view):
        count = os.write(fd, view[written:])
        if count <= 0:
            raise _fail("short write while exporting Git blob")
        written += count


def _create_destination(destination: Path, uid: int, gid: int) -> int:
    absolute = os.path.abspath(os.fspath(destination))
    parent, name = os.path.split(absolute)
    if not name or name in (".", ".."):
        raise _fail("destination must name a new directory")
    parent_fd = _secure_absolute_directory(Path(parent))
    try:
        try:
            os.mkdir(name, _DIRECTORY_MODE, dir_fd=parent_fd)
        except OSError as exc:
            raise _fail("destination is not a new safe directory") from exc
        try:
            destination_fd = os.open(
                name,
                os.O_RDONLY | _O_DIRECTORY | os.O_NOFOLLOW | _O_CLOEXEC,
                dir_fd=parent_fd,
            )
        except OSError as exc:
            raise _fail("new destination directory cannot be opened safely") from exc
    finally:
        os.close(parent_fd)
    try:
        _set_fd_metadata(destination_fd, _DIRECTORY_MODE, uid, gid)
        return destination_fd
    except Exception:
        os.close(destination_fd)
        raise


def _validate_identity(uid: int, gid: int) -> tuple[int, int]:
    if isinstance(uid, bool) or not isinstance(uid, int) or uid < 0:
        raise _fail("required UID is invalid")
    if isinstance(gid, bool) or not isinstance(gid, int) or gid < 0:
        raise _fail("required GID is invalid")
    return uid, gid


def export_tree(
    repo: os.PathLike[str] | str | HeldRepository,
    tree_id: str,
    destination: os.PathLike[str] | str,
    *,
    required_uid: int,
    required_gid: int,
) -> bytes:
    """Create a new exact filesystem export and return its canonical manifest."""

    uid, gid = _validate_identity(required_uid, required_gid)
    accepted_tree_id = _validate_object_id(tree_id, "tree ID")
    with _repository_scope(repo) as repository:
        entries = read_tree(repository, accepted_tree_id)
        manifest = _manifest_bytes(accepted_tree_id, entries)
    root_fd = _create_destination(Path(destination), uid, gid)
    try:
        directories = sorted(
            _derived_directories(entry.path for entry in entries),
            key=lambda value: (value.count("/"), value.encode("utf-8")),
        )
        for relative in directories:
            parts = relative.split("/")
            parent_fd = _open_relative_directory(root_fd, parts[:-1])
            try:
                os.mkdir(parts[-1], _DIRECTORY_MODE, dir_fd=parent_fd)
                child_fd = os.open(
                    parts[-1],
                    os.O_RDONLY | _O_DIRECTORY | os.O_NOFOLLOW | _O_CLOEXEC,
                    dir_fd=parent_fd,
                )
                try:
                    _set_fd_metadata(child_fd, _DIRECTORY_MODE, uid, gid)
                finally:
                    os.close(child_fd)
            except OSError as exc:
                raise _fail(f"cannot create source directory: {relative}") from exc
            finally:
                os.close(parent_fd)

        for entry in entries:
            if entry.payload is None:
                raise _fail("Git leaf bytes disappeared before export")
            parts = entry.path.split("/")
            parent_fd = _open_relative_directory(root_fd, parts[:-1])
            try:
                if entry.kind == "file":
                    mode = _REGULAR_MODES[entry.git_mode]
                    try:
                        leaf_fd = os.open(
                            parts[-1],
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL
                            | os.O_NOFOLLOW | _O_CLOEXEC,
                            mode,
                            dir_fd=parent_fd,
                        )
                    except OSError as exc:
                        raise _fail(f"cannot exclusively create source leaf: {entry.path}") from exc
                    try:
                        _write_all(leaf_fd, entry.payload)
                        _set_fd_metadata(leaf_fd, mode, uid, gid)
                        os.fsync(leaf_fd)
                    finally:
                        os.close(leaf_fd)
                else:
                    target = entry.payload.decode("utf-8", "strict")
                    try:
                        os.symlink(target, parts[-1], dir_fd=parent_fd)
                    except OSError as exc:
                        raise _fail(f"cannot exclusively create source symlink: {entry.path}") from exc
                    linked = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
                    if (linked.st_uid, linked.st_gid) != (uid, gid):
                        os.chown(
                            parts[-1], uid, gid, dir_fd=parent_fd,
                            follow_symlinks=False,
                        )
                    linked = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
                    if (linked.st_uid, linked.st_gid) != (uid, gid):
                        raise _fail("created symlink owner could not be fixed exactly")
            finally:
                os.close(parent_fd)
        os.fsync(root_fd)
    except OSError as exc:
        raise _fail("secure source export failed") from exc
    finally:
        os.close(root_fd)

    verify_export(
        destination,
        manifest,
        expected_tree_id=accepted_tree_id,
        required_uid=uid,
        required_gid=gid,
    )
    return manifest


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _fail(f"duplicate manifest key: {key}")
        result[key] = value
    return result


def _parse_manifest(manifest: bytes) -> tuple[str, tuple[Mapping[str, object], ...]]:
    if not isinstance(manifest, bytes) or not manifest or len(manifest) > _MAX_MANIFEST_BYTES:
        raise _fail("source manifest has an invalid size")
    try:
        text = manifest.decode("ascii", "strict")
        document = json.loads(text, object_pairs_hook=_reject_duplicate_json_keys)
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        if isinstance(exc, SourceGuardError):
            raise
        raise _fail("source manifest is not canonical JSON") from exc
    if not isinstance(document, dict) or set(document) != {
        "entries", "schema_version", "tree_id",
    }:
        raise _fail("source manifest top-level schema is invalid")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise _fail("source manifest schema version is invalid")
    tree_id = _validate_object_id(document["tree_id"], "manifest tree ID")
    raw_entries = document["entries"]
    if not isinstance(raw_entries, list):
        raise _fail("source manifest entries are invalid")

    entries: list[Mapping[str, object]] = []
    previous: bytes | None = None
    paths: set[str] = set()
    for item in raw_entries:
        if not isinstance(item, dict) or set(item) != {
            "blob_id", "git_mode", "kind", "path", "sha256", "target",
        }:
            raise _fail("source manifest entry schema is invalid")
        path = item["path"]
        if not isinstance(path, str):
            raise _fail("source manifest path is invalid")
        _validate_path(path)
        ordering = path.encode("utf-8")
        if previous is not None and ordering <= previous:
            raise _fail("source manifest entries are not uniquely sorted")
        previous = ordering
        if path in paths:
            raise _fail("source manifest contains a duplicate path")
        paths.add(path)
        mode = item["git_mode"]
        kind = item["kind"]
        if not isinstance(mode, str) or mode not in _ALLOWED_MODES:
            raise _fail("source manifest mode is invalid")
        expected_kind = "symlink" if mode == "120000" else "file"
        if not isinstance(kind, str) or kind != expected_kind:
            raise _fail("source manifest kind and mode disagree")
        blob_id = item["blob_id"]
        _validate_object_id(blob_id, "manifest blob ID")
        if len(blob_id) != len(tree_id):
            raise _fail("manifest object ID algorithms disagree")
        digest = item["sha256"]
        if (
            not isinstance(digest, str) or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise _fail("source manifest SHA-256 is invalid")
        target = item["target"]
        if expected_kind == "symlink":
            if not isinstance(target, str):
                raise _fail("source manifest symlink target is invalid")
            _validate_symlink_target_text(target)
        elif target is not None:
            raise _fail("regular source entry unexpectedly has a target")
        entries.append(item)

    topology = tuple(
        TreeEntry(
            path=item["path"],
            git_mode=item["git_mode"],
            blob_id=item["blob_id"],
            payload=(
                item["target"].encode("utf-8")
                if item["kind"] == "symlink" else None
            ),
        )
        for item in entries
    )
    validate_entries(topology)
    _validate_symlinks(topology)

    canonical = (
        json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")
    if manifest != canonical:
        raise _fail("source manifest bytes are not canonical")
    if _reconstruct_tree_id(entries, len(tree_id)) != tree_id:
        raise _fail("source manifest entries do not reconstruct its Git tree ID")
    return tree_id, tuple(entries)


def _metadata_fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev, metadata.st_ino, metadata.st_mode,
        metadata.st_uid, metadata.st_gid, metadata.st_nlink, metadata.st_size,
        getattr(metadata, "st_mtime_ns", int(metadata.st_mtime * 1_000_000_000)),
        getattr(metadata, "st_ctime_ns", int(metadata.st_ctime * 1_000_000_000)),
    )


def _walk_destination(root_fd: int) -> dict[str, os.stat_result]:
    discovered: dict[str, os.stat_result] = {}

    def walk(directory_fd: int, prefix: tuple[str, ...]) -> None:
        try:
            names = os.listdir(directory_fd)
        except OSError as exc:
            raise _fail("cannot enumerate destination directory") from exc
        for name in sorted(names, key=lambda item: os.fsencode(item)):
            relative = "/".join((*prefix, name))
            _validate_path(relative)
            if relative in discovered:
                raise _fail("destination walk found a duplicate path")
            try:
                metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as exc:
                raise _fail(f"cannot inspect destination path: {relative}") from exc
            discovered[relative] = metadata
            if stat.S_ISDIR(metadata.st_mode):
                try:
                    child_fd = os.open(
                        name,
                        os.O_RDONLY | _O_DIRECTORY | os.O_NOFOLLOW | _O_CLOEXEC,
                        dir_fd=directory_fd,
                    )
                except OSError as exc:
                    raise _fail(f"cannot safely enter destination directory: {relative}") from exc
                try:
                    opened = os.fstat(child_fd)
                    if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                        raise _fail("destination directory changed during verification")
                    walk(child_fd, (*prefix, name))
                finally:
                    os.close(child_fd)
    walk(root_fd, ())
    return discovered


def _expected_directory_links(
    directory: str,
    directories: set[str],
    leaves: set[str],
) -> int:
    prefix = f"{directory}/" if directory else ""
    children = 0
    candidates = directories | (leaves if sys.platform == "darwin" else set())
    for candidate in candidates:
        if not candidate.startswith(prefix):
            continue
        remainder = candidate[len(prefix):]
        if remainder and "/" not in remainder:
            children += 1
    return 2 + children


def _check_common_metadata(
    metadata: os.stat_result,
    *,
    path: str,
    uid: int,
    gid: int,
    links: int,
) -> None:
    if (metadata.st_uid, metadata.st_gid) != (uid, gid):
        raise _fail(f"destination owner mismatch: {path}")
    if metadata.st_nlink != links:
        raise _fail(f"destination link-count mismatch: {path}")


def _read_regular_at(root_fd: int, path: str, expected_size: int) -> tuple[bytes, os.stat_result]:
    parts = path.split("/")
    parent_fd = _open_relative_directory(root_fd, parts[:-1])
    try:
        descriptor = os.open(
            parts[-1], os.O_RDONLY | os.O_NOFOLLOW | _O_CLOEXEC,
            dir_fd=parent_fd,
        )
    except OSError as exc:
        os.close(parent_fd)
        raise _fail(f"cannot safely open destination file: {path}") from exc
    os.close(parent_fd)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise _fail(f"destination file changed type: {path}")
        if metadata.st_size != expected_size:
            raise _fail(f"destination file size mismatch: {path}")
        chunks: list[bytes] = []
        remaining = expected_size + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) != expected_size:
            raise _fail(f"destination file changed while being read: {path}")
        return payload, metadata
    finally:
        os.close(descriptor)


def _readlink_at(root_fd: int, path: str) -> str:
    parts = path.split("/")
    parent_fd = _open_relative_directory(root_fd, parts[:-1])
    try:
        try:
            return os.readlink(parts[-1], dir_fd=parent_fd)
        except OSError as exc:
            raise _fail(f"cannot read destination symlink: {path}") from exc
    finally:
        os.close(parent_fd)


def verify_export(
    destination: os.PathLike[str] | str,
    manifest: bytes,
    *,
    expected_tree_id: str,
    required_uid: int,
    required_gid: int,
    _root_descriptor: int | None = None,
) -> None:
    """Independently prove exact paths, metadata, contents, and link targets."""

    uid, gid = _validate_identity(required_uid, required_gid)
    accepted_tree_id = _validate_object_id(expected_tree_id, "expected tree ID")
    manifest_tree_id, entries = _parse_manifest(manifest)
    if manifest_tree_id != accepted_tree_id:
        raise _fail("source manifest is not bound to the expected Git tree")
    root_fd = (
        _secure_absolute_directory(Path(destination))
        if _root_descriptor is None else os.dup(_root_descriptor)
    )
    try:
        root_metadata = os.fstat(root_fd)
        if not stat.S_ISDIR(root_metadata.st_mode):
            raise _fail("destination root is not a directory")
        directories = _derived_directories(item["path"] for item in entries)
        leaves = {item["path"] for item in entries}
        expected_paths = directories | leaves
        discovered = _walk_destination(root_fd)
        if set(discovered) != expected_paths:
            raise _fail("destination does not have exact set equality with the manifest")

        _check_common_metadata(
            root_metadata,
            path=".", uid=uid, gid=gid,
            links=_expected_directory_links("", directories, leaves),
        )
        if stat.S_IMODE(root_metadata.st_mode) != _DIRECTORY_MODE:
            raise _fail("destination root mode mismatch")

        for directory in directories:
            metadata = discovered[directory]
            if not stat.S_ISDIR(metadata.st_mode):
                raise _fail(f"destination parent changed type: {directory}")
            if stat.S_IMODE(metadata.st_mode) != _DIRECTORY_MODE:
                raise _fail(f"destination directory mode mismatch: {directory}")
            _check_common_metadata(
                metadata,
                path=directory, uid=uid, gid=gid,
                links=_expected_directory_links(directory, directories, leaves),
            )

        for item in entries:
            path = item["path"]
            metadata = discovered[path]
            kind = item["kind"]
            if kind == "file":
                if not stat.S_ISREG(metadata.st_mode):
                    raise _fail(f"destination leaf type mismatch: {path}")
                expected_mode = _REGULAR_MODES[item["git_mode"]]
                if stat.S_IMODE(metadata.st_mode) != expected_mode:
                    raise _fail(f"destination leaf mode mismatch: {path}")
                _check_common_metadata(metadata, path=path, uid=uid, gid=gid, links=1)
                expected_size = metadata.st_size
                payload, opened = _read_regular_at(root_fd, path, expected_size)
                if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                    raise _fail(f"destination leaf changed during verification: {path}")
                if hashlib.sha256(payload).hexdigest() != item["sha256"]:
                    raise _fail(f"destination content mismatch: {path}")
                if _git_object_digest(payload, len(item["blob_id"])) != item["blob_id"]:
                    raise _fail(f"destination Git blob identity mismatch: {path}")
            else:
                if not stat.S_ISLNK(metadata.st_mode):
                    raise _fail(f"destination symlink type mismatch: {path}")
                _check_common_metadata(metadata, path=path, uid=uid, gid=gid, links=1)
                target = _readlink_at(root_fd, path)
                if target != item["target"]:
                    raise _fail(f"destination symlink target mismatch: {path}")
                payload = target.encode("utf-8")
                if hashlib.sha256(payload).hexdigest() != item["sha256"]:
                    raise _fail(f"destination symlink digest mismatch: {path}")
                if _git_object_digest(payload, len(item["blob_id"])) != item["blob_id"]:
                    raise _fail(f"destination symlink blob identity mismatch: {path}")

        first_snapshot = {
            ".": _metadata_fingerprint(root_metadata),
            **{
                path: _metadata_fingerprint(metadata)
                for path, metadata in discovered.items()
            },
        }
        final_root = os.fstat(root_fd)
        final_discovered = _walk_destination(root_fd)
        final_snapshot = {
            ".": _metadata_fingerprint(final_root),
            **{
                path: _metadata_fingerprint(metadata)
                for path, metadata in final_discovered.items()
            },
        }
        if final_snapshot != first_snapshot:
            raise _fail("destination changed during final exact-set recheck")
        for item in entries:
            path = item["path"]
            metadata = final_discovered[path]
            if item["kind"] == "file":
                payload, opened = _read_regular_at(root_fd, path, metadata.st_size)
                named_after = os.stat(
                    path, dir_fd=root_fd, follow_symlinks=False,
                )
                if (
                    _metadata_fingerprint(opened)
                    != _metadata_fingerprint(metadata)
                    or _metadata_fingerprint(named_after)
                    != _metadata_fingerprint(metadata)
                    or hashlib.sha256(payload).hexdigest() != item["sha256"]
                    or _git_object_digest(payload, len(item["blob_id"]))
                    != item["blob_id"]
                ):
                    raise _fail(f"destination file changed during final recheck: {path}")
            else:
                target = _readlink_at(root_fd, path)
                named_after = os.stat(
                    path, dir_fd=root_fd, follow_symlinks=False,
                )
                if (
                    target != item["target"]
                    or _metadata_fingerprint(named_after)
                    != _metadata_fingerprint(metadata)
                ):
                    raise _fail(f"destination symlink changed during final recheck: {path}")
        if _metadata_fingerprint(os.fstat(root_fd)) != _metadata_fingerprint(final_root):
            raise _fail("destination root changed after final recheck")
    except OSError as exc:
        raise _fail("destination verification failed closed") from exc
    finally:
        os.close(root_fd)


def hold_export(
    destination: os.PathLike[str] | str,
    manifest: bytes,
    *,
    expected_tree_id: str,
    required_uid: int,
    required_gid: int,
    require_readonly: bool,
) -> HeldExport:
    """Attest and retain one export identity for a complete consumer run.

    The descriptor, rather than the mutable pathname, is the continuing
    authority.  Consumers call :meth:`HeldExport.verify` both immediately
    before use and after the last use; authoritative root workflows also
    require that the descriptor names a read-only mount.
    """

    uid, gid = _validate_identity(required_uid, required_gid)
    tree_id = _validate_object_id(expected_tree_id, "expected tree ID")
    if not isinstance(require_readonly, bool):
        raise _fail("read-only export requirement is invalid")
    descriptor = _secure_absolute_directory(Path(destination))
    held = HeldExport(
        descriptor=descriptor,
        manifest=manifest,
        expected_tree_id=tree_id,
        required_uid=uid,
        required_gid=gid,
        readonly=require_readonly,
    )
    try:
        held.verify()
    except Exception:
        held.close()
        raise
    return held


def check_required_authority_tree(
    repo: os.PathLike[str] | str,
    tree_id: str,
) -> None:
    """Bind the clean checkout and require every root-proof executable leaf."""

    with _repository_scope(repo) as repository:
        accepted = require_clean_head_tree(repository, tree_id)
        by_path = {
            entry.path: entry for entry in read_tree(repository, accepted)
        }
        for path, expected_mode in REQUIRED_AUTHORITY_LEAVES.items():
            entry = by_path.get(path)
            if (
                entry is None
                or entry.git_mode != expected_mode
                or entry.kind != "file"
            ):
                raise _fail(
                    "required authority leaf is missing or has the wrong mode: "
                    f"{path}"
                )
            if entry.payload is None or not entry.payload:
                raise _fail(f"required authority leaf is empty: {path}")


def main(argv: Sequence[str] | None = None) -> int:
    """Run the one fixed pre-root check command used by the dedicated CI job."""

    arguments = tuple(sys.argv[1:] if argv is None else argv)
    if (
        len(arguments) != 5
        or arguments[0] != "check"
        or arguments[1] != "--repository"
        or arguments[3] != "--tree-id"
    ):
        sys.stderr.write("SOURCE-GUARD-FAIL\n")
        return 64
    try:
        check_required_authority_tree(arguments[2], arguments[4])
    except SourceGuardError:
        sys.stderr.write("SOURCE-GUARD-FAIL\n")
        return 1
    return 0


__all__ = [
    "HeldExport",
    "HeldRepository",
    "TRUSTED_GIT_PATH",
    "SourceGuardError",
    "TreeEntry",
    "REQUIRED_AUTHORITY_LEAVES",
    "check_required_authority_tree",
    "export_tree",
    "hold_export",
    "hold_repository",
    "parse_ls_tree_record",
    "read_tree",
    "require_clean_head_tree",
    "validate_entries",
    "verify_export",
]


if __name__ == "__main__":
    raise SystemExit(main())
