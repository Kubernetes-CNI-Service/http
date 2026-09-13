#!/usr/bin/env python3
"""Reconcile the fixed host-root and Docker-service Ed25519 identity pair."""

from __future__ import annotations

import argparse
import base64
import ctypes
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import stat
import subprocess
import sys
import time
from typing import Callable, Iterable, Mapping, Sequence


HOST_SSH_DIRECTORY = Path("/root/.ssh")
SERVICE_SSH_DIRECTORY = Path("/var/lib/http-ztp-container/ssh")
SSH_KEYGEN = Path("/usr/bin/ssh-keygen")
PRIVATE_NAME = "id_ed25519"
PUBLIC_NAME = "id_ed25519.pub"
DIRECTORY_MODE = 0o700
PRIVATE_MODE = 0o600
PUBLIC_MODE = 0o644
MAX_PRIVATE_KEY_BYTES = 64 * 1024
MAX_PUBLIC_KEY_BYTES = 64 * 1024
MAX_TOOL_OUTPUT_BYTES = 64 * 1024
SSH_KEYGEN_TIMEOUT_SECONDS = 10
STAGING_UMASK = 0o077
AT_EMPTY_PATH = 0x1000
_FINGERPRINT = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
_SAFE_ENVIRONMENT = {
    "HOME": "/root",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
    "PYTHONNOUSERSITE": "1",
    "PYTHONDONTWRITEBYTECODE": "1",
}


class ManagementKeyError(RuntimeError):
    """The fixed management identity is absent, invalid, or unstable."""


class ManagementKeyConflict(ManagementKeyError):
    """Both fixed endpoints are valid but carry different identities."""


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass
class HeldLeaf:
    descriptor: int
    name: str
    metadata: tuple[int, ...]
    payload: bytes

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


@dataclass
class HeldPair:
    private: HeldLeaf
    public: HeldLeaf
    identity: tuple[bytes, bytes]
    fingerprint: str

    def close(self) -> None:
        self.private.close()
        self.public.close()


@dataclass
class HeldDirectoryComponent:
    descriptor: int
    parent_descriptor: int | None
    name: str | None
    absolute_path: Path | None
    identity: tuple[int, ...]
    expected_uid: int
    expected_gid: int

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


@dataclass
class HeldSide:
    label: str
    directory: Path
    expected_uid: int
    expected_gid: int
    ancestors: list[HeldDirectoryComponent]
    parent_descriptor: int
    basename: str
    directory_descriptor: int | None
    directory_identity: tuple[int, ...] | None
    pair: HeldPair | None
    state: str

    def close(self) -> None:
        if self.pair is not None:
            self.pair.close()
            self.pair = None
        if self.directory_descriptor is not None:
            os.close(self.directory_descriptor)
            self.directory_descriptor = None
        for component in reversed(self.ancestors):
            component.close()
        self.ancestors.clear()


def _checkpoint(_stage: str) -> None:
    """Deterministic fault/race checkpoint used only by direct tests."""


def _metadata_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        getattr(metadata, "st_mtime_ns", int(metadata.st_mtime * 1_000_000_000)),
        getattr(metadata, "st_ctime_ns", int(metadata.st_ctime * 1_000_000_000)),
    )


def _directory_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        getattr(metadata, "st_mtime_ns", int(metadata.st_mtime * 1_000_000_000)),
        getattr(metadata, "st_ctime_ns", int(metadata.st_ctime * 1_000_000_000)),
    )


def _validate_leaf_metadata(
    metadata: os.stat_result,
    *,
    label: str,
    expected_mode: int,
    expected_uid: int,
    expected_gid: int,
) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise ManagementKeyError(f"{label} must be a regular file; special/FIFO/socket objects are unsafe")
    if metadata.st_nlink != 1:
        raise ManagementKeyError(f"{label} must be single-link")
    if metadata.st_uid != expected_uid or metadata.st_gid != expected_gid:
        raise ManagementKeyError(f"{label} owner uid/gid is unsafe")
    if stat.S_IMODE(metadata.st_mode) != expected_mode:
        raise ManagementKeyError(f"{label} mode must be {expected_mode:04o}")


def _validate_directory_metadata(
    metadata: os.stat_result, *, label: str, expected_uid: int, expected_gid: int,
) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        raise ManagementKeyError(f"{label} must be a directory")
    if metadata.st_uid != expected_uid or metadata.st_gid != expected_gid:
        raise ManagementKeyError(f"{label} owner uid/gid is unsafe")
    if stat.S_IMODE(metadata.st_mode) != DIRECTORY_MODE:
        raise ManagementKeyError(f"{label} mode must be 0700")


def _validate_component_metadata(
    metadata: os.stat_result, *, label: str, expected_uid: int, expected_gid: int,
) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        raise ManagementKeyError(f"{label} must be a directory")
    if metadata.st_uid != expected_uid or metadata.st_gid != expected_gid:
        raise ManagementKeyError(f"{label} owner uid/gid is unsafe")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise ManagementKeyError(f"{label} is group/world writable")


def _canonical_under(boundary: Path, path: Path, label: str) -> None:
    boundary_text = os.fspath(boundary)
    path_text = os.fspath(path)
    if not boundary.is_absolute() or os.path.normpath(boundary_text) != boundary_text:
        raise ManagementKeyError("authority boundary must be one canonical absolute path")
    if not path.is_absolute() or os.path.normpath(path_text) != path_text:
        raise ManagementKeyError(f"{label} must be one canonical absolute path")
    try:
        path.relative_to(boundary)
    except ValueError as exc:
        raise ManagementKeyError(f"{label} is outside the authority boundary") from exc


def _directory_flags() -> int:
    required = ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC")
    if any(not hasattr(os, name) for name in required):
        raise ManagementKeyError("platform lacks required directory NOFOLLOW primitives")
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _leaf_flags() -> int:
    required = ("O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC")
    if any(not hasattr(os, name) for name in required):
        raise ManagementKeyError("platform lacks required leaf NOFOLLOW primitives")
    return os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


def _component_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )


def _open_parent_chain(
    path: Path,
    *,
    authority_boundary: Path,
    expected_uid: int,
    expected_gid: int,
) -> list[HeldDirectoryComponent]:
    """Open every in-authority component and retain its name binding."""
    flags = _directory_flags()
    components: list[HeldDirectoryComponent] = []
    try:
        boundary_direct = os.lstat(authority_boundary)
        if stat.S_ISLNK(boundary_direct.st_mode):
            raise ManagementKeyError("authority boundary symlink is unsafe")
        _validate_component_metadata(
            boundary_direct,
            label="authority boundary",
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        descriptor = os.open(os.fspath(authority_boundary), flags)
        boundary_held = os.fstat(descriptor)
        if _component_identity(boundary_held) != _component_identity(boundary_direct):
            os.close(descriptor)
            raise ManagementKeyError("authority boundary changed during open")
        components.append(HeldDirectoryComponent(
            descriptor=descriptor,
            parent_descriptor=None,
            name=None,
            absolute_path=authority_boundary,
            identity=_component_identity(boundary_held),
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        ))
        relative = path.relative_to(authority_boundary)
        for component_name in relative.parts:
            direct = os.stat(component_name, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISLNK(direct.st_mode) or not stat.S_ISDIR(direct.st_mode):
                raise ManagementKeyError("canonical parent component is a symlink or non-directory")
            _validate_component_metadata(
                direct,
                label=f"canonical parent component {component_name}",
                expected_uid=expected_uid,
                expected_gid=expected_gid,
            )
            opened = os.open(component_name, flags, dir_fd=descriptor)
            held = os.fstat(opened)
            if _component_identity(held) != _component_identity(direct):
                os.close(opened)
                raise ManagementKeyError("canonical parent component changed during traversal")
            components.append(HeldDirectoryComponent(
                descriptor=opened,
                parent_descriptor=descriptor,
                name=component_name,
                absolute_path=None,
                identity=_component_identity(held),
                expected_uid=expected_uid,
                expected_gid=expected_gid,
            ))
            descriptor = opened
        return components
    except (OSError, ManagementKeyError) as exc:
        for component in reversed(components):
            component.close()
        if isinstance(exc, ManagementKeyError):
            raise
        raise ManagementKeyError(f"cannot traverse canonical parent component: {exc}") from exc


def _revalidate_parent_chain(side: HeldSide) -> None:
    try:
        for component in side.ancestors:
            held = os.fstat(component.descriptor)
            if component.parent_descriptor is None:
                assert component.absolute_path is not None
                rebound = os.lstat(component.absolute_path)
            else:
                assert component.name is not None
                rebound = os.stat(
                    component.name,
                    dir_fd=component.parent_descriptor,
                    follow_symlinks=False,
                )
            _validate_component_metadata(
                held,
                label="held authority component",
                expected_uid=component.expected_uid,
                expected_gid=component.expected_gid,
            )
            if _component_identity(held) != component.identity:
                raise ManagementKeyError("held authority component metadata changed")
            if _component_identity(rebound) != component.identity:
                raise ManagementKeyError("authority component canonical name was rebound")
    except OSError as exc:
        raise ManagementKeyError("authority component canonical identity disappeared") from exc


def _read_bounded(descriptor: int, limit: int, label: str) -> bytes:
    metadata = os.fstat(descriptor)
    if metadata.st_size <= 0:
        raise ManagementKeyError(f"{label} is empty")
    if metadata.st_size > limit:
        raise ManagementKeyError(f"{label} size is too large")
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(16384, limit + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            raise ManagementKeyError(f"{label} read exceeded size limit")
    payload = b"".join(chunks)
    if len(payload) != metadata.st_size:
        raise ManagementKeyError(f"{label} changed while being read")
    return payload


def _open_leaf(
    directory_descriptor: int,
    name: str,
    *,
    label: str,
    expected_mode: int,
    expected_uid: int,
    expected_gid: int,
    limit: int,
) -> HeldLeaf:
    descriptor = -1
    try:
        direct = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        if stat.S_ISLNK(direct.st_mode):
            raise ManagementKeyError(f"{label} symlink is rejected by NOFOLLOW policy")
        descriptor = os.open(name, _leaf_flags(), dir_fd=directory_descriptor)
        before = os.fstat(descriptor)
        _validate_leaf_metadata(
            before,
            label=label,
            expected_mode=expected_mode,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        if (direct.st_dev, direct.st_ino) != (before.st_dev, before.st_ino):
            raise ManagementKeyError(f"{label} identity changed during open")
        payload = _read_bounded(descriptor, limit, label)
        after = os.fstat(descriptor)
        rebound = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        identity = _metadata_identity(before)
        if identity != _metadata_identity(after):
            raise ManagementKeyError(f"{label} metadata changed during read")
        if _metadata_identity(rebound) != identity:
            raise ManagementKeyError(f"{label} canonical name was rebound")
        return HeldLeaf(descriptor, name, identity, payload)
    except (OSError, ManagementKeyError) as exc:
        if descriptor >= 0:
            os.close(descriptor)
        if isinstance(exc, ManagementKeyError):
            raise
        raise ManagementKeyError(f"cannot safely open {label}: {exc}") from exc


def _decode_public(payload: bytes, label: str) -> tuple[tuple[bytes, bytes], str]:
    if b"\0" in payload or b"\r" in payload or not payload.endswith(b"\n"):
        raise ManagementKeyError(f"{label} public key format is not canonical")
    if payload.count(b"\n") != 1:
        raise ManagementKeyError(f"{label} public key must contain exactly one line")
    line = payload[:-1]
    fields = line.split(None, 2)
    if len(fields) < 2 or fields[0] != b"ssh-ed25519":
        raise ManagementKeyError(f"{label} public key must be Ed25519")
    if any(byte < 0x20 or byte > 0x7E for byte in line):
        raise ManagementKeyError(f"{label} public key contains unsafe bytes")
    try:
        blob = base64.b64decode(fields[1], validate=True)
    except ValueError as exc:
        raise ManagementKeyError(f"{label} public key base64 is invalid") from exc
    if len(blob) != 51:
        raise ManagementKeyError(f"{label} public key blob length is invalid")
    algorithm_size = int.from_bytes(blob[:4], "big")
    algorithm = blob[4:4 + algorithm_size]
    offset = 4 + algorithm_size
    if offset + 4 > len(blob):
        raise ManagementKeyError(f"{label} public key blob is truncated")
    key_size = int.from_bytes(blob[offset:offset + 4], "big")
    key = blob[offset + 4:]
    if algorithm != b"ssh-ed25519" or key_size != 32 or len(key) != 32:
        raise ManagementKeyError(f"{label} public key blob is not Ed25519")
    digest = base64.b64encode(hashlib.sha256(blob).digest()).rstrip(b"=")
    fingerprint = "SHA256:" + digest.decode("ascii")
    if not _FINGERPRINT.fullmatch(fingerprint):
        raise ManagementKeyError(f"{label} fingerprint is invalid")
    return (fields[0], fields[1]), fingerprint


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired as exc:
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired as final:
            raise ManagementKeyError("bounded subprocess could not be reaped") from final


def _run_bounded_command(
    argv: Sequence[str],
    *,
    pass_fds: tuple[int, ...] = (),
    working_directory_fd: int | None = None,
    timeout: float = SSH_KEYGEN_TIMEOUT_SECONDS,
    max_stdout: int = MAX_TOOL_OUTPUT_BYTES,
    max_stderr: int = MAX_TOOL_OUTPUT_BYTES,
) -> CommandResult:
    if not argv or type(argv[0]) is not str or not argv[0] or any(
        type(item) is not str for item in argv[1:]
    ):
        raise ManagementKeyError("bounded command argv is invalid")
    if working_directory_fd is not None and working_directory_fd not in pass_fds:
        raise ManagementKeyError("held working-directory descriptor must be passed explicitly")

    def enter_held_working_directory() -> None:
        if working_directory_fd is not None:
            os.fchdir(working_directory_fd)

    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    owned_streams: list[object] = []
    streams: dict[int, tuple[str, object, bytearray, int]] = {}
    completed = False
    try:
        process = subprocess.Popen(
            list(argv),
            env=dict(_SAFE_ENVIRONMENT),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            pass_fds=pass_fds,
            start_new_session=True,
            preexec_fn=enter_held_working_directory if working_directory_fd is not None else None,
            bufsize=0,
        )
        if process.stdout is None or process.stderr is None:
            raise ManagementKeyError("bounded subprocess pipes are unavailable")
        owned_streams = [process.stdout, process.stderr]
        selector = selectors.DefaultSelector()
        stdout_descriptor = process.stdout.fileno()
        stderr_descriptor = process.stderr.fileno()
        os.set_blocking(stdout_descriptor, False)
        os.set_blocking(stderr_descriptor, False)
        streams = {
            stdout_descriptor: ("stdout", process.stdout, bytearray(), max_stdout),
            stderr_descriptor: ("stderr", process.stderr, bytearray(), max_stderr),
        }
        for descriptor in streams:
            selector.register(descriptor, selectors.EVENT_READ)
        deadline = time.monotonic() + float(timeout)
        failure = ""
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = "bounded command timeout"
                break
            events = selector.select(min(remaining, 0.1))
            for key, _mask in events:
                name, stream, payload, limit = streams[key.fd]
                try:
                    chunk = os.read(key.fd, min(16384, limit + 1 - len(payload)))
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fd)
                    stream.close()
                    continue
                payload.extend(chunk)
                if len(payload) > limit:
                    failure = f"bounded command {name} output exceeded limit"
                    break
            if failure:
                break
        if failure:
            raise ManagementKeyError(failure)
        remaining = max(0.01, deadline - time.monotonic())
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise ManagementKeyError("bounded command timeout") from exc
        result = CommandResult(
            returncode=int(returncode),
            stdout=bytes(streams[stdout_descriptor][2]),
            stderr=bytes(streams[stderr_descriptor][2]),
        )
        completed = True
        return result
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise ManagementKeyError(f"bounded command failed: {exc}") from exc
    finally:
        try:
            if process is not None and not completed:
                _terminate_process(process)
        finally:
            try:
                if selector is not None:
                    selector.close()
            finally:
                for stream in owned_streams:
                    try:
                        stream.close()
                    except (OSError, ValueError):
                        pass


def _fd_path(descriptor: int) -> str:
    if Path("/proc/self/fd").is_dir():
        return f"/proc/self/fd/{descriptor}"
    if Path("/dev/fd").is_dir():
        return f"/dev/fd/{descriptor}"
    raise ManagementKeyError("platform cannot expose one held private descriptor")


def _derive_private_identity(leaf: HeldLeaf, label: str) -> tuple[bytes, bytes]:
    os.lseek(leaf.descriptor, 0, os.SEEK_SET)
    result = _run_bounded_command(
        [os.fspath(SSH_KEYGEN), "-y", "-P", "", "-f", _fd_path(leaf.descriptor)],
        pass_fds=(leaf.descriptor,),
        timeout=SSH_KEYGEN_TIMEOUT_SECONDS,
        max_stdout=MAX_TOOL_OUTPUT_BYTES,
        max_stderr=MAX_TOOL_OUTPUT_BYTES,
    )
    if result.returncode != 0:
        raise ManagementKeyError(f"{label} private key is encrypted, invalid, or ssh-keygen failed")
    if result.stderr:
        raise ManagementKeyError(f"{label} ssh-keygen returned unexpected stderr output")
    os.lseek(leaf.descriptor, 0, os.SEEK_SET)
    if _read_bounded(leaf.descriptor, MAX_PRIVATE_KEY_BYTES, label + " private key") != leaf.payload:
        raise ManagementKeyError(f"{label} private key changed during ssh-keygen validation")
    if _metadata_identity(os.fstat(leaf.descriptor)) != leaf.metadata:
        raise ManagementKeyError(f"{label} private key metadata changed during validation")
    identity, _fingerprint = _decode_public(result.stdout, label + " derived")
    return identity


def _revalidate_leaf(directory_descriptor: int, leaf: HeldLeaf, label: str) -> None:
    current = os.fstat(leaf.descriptor)
    try:
        rebound = os.stat(leaf.name, dir_fd=directory_descriptor, follow_symlinks=False)
    except OSError as exc:
        raise ManagementKeyError(f"{label} canonical identity changed") from exc
    if _metadata_identity(current) != leaf.metadata or _metadata_identity(rebound) != leaf.metadata:
        raise ManagementKeyError(f"{label} metadata or canonical identity changed")
    payload = _read_bounded(
        leaf.descriptor,
        MAX_PRIVATE_KEY_BYTES if leaf.name == PRIVATE_NAME else MAX_PUBLIC_KEY_BYTES,
        label,
    )
    if payload != leaf.payload or _metadata_identity(os.fstat(leaf.descriptor)) != leaf.metadata:
        raise ManagementKeyError(f"{label} content changed after validation")


def _revalidate_directory(side: HeldSide) -> None:
    try:
        _revalidate_parent_chain(side)
        if side.directory_descriptor is None or side.directory_identity is None:
            raise ManagementKeyError(f"{side.label} directory is absent")
        held = os.fstat(side.directory_descriptor)
        rebound = os.stat(side.basename, dir_fd=side.parent_descriptor, follow_symlinks=False)
        if _directory_identity(held) != side.directory_identity:
            raise ManagementKeyError(f"{side.label} directory metadata changed")
        if _directory_identity(rebound) != side.directory_identity:
            raise ManagementKeyError(f"{side.label} directory canonical name was rebound")
    except OSError as exc:
        raise ManagementKeyError(f"{side.label} directory canonical identity disappeared") from exc


def _refresh_directory_identity(side: HeldSide) -> None:
    """Accept only timestamps caused by a verified mutation on our held dir."""
    try:
        _revalidate_parent_chain(side)
        if side.directory_descriptor is None or side.directory_identity is None:
            raise ManagementKeyError(f"{side.label} directory is absent")
        held = os.fstat(side.directory_descriptor)
        rebound = os.stat(side.basename, dir_fd=side.parent_descriptor, follow_symlinks=False)
        _validate_directory_metadata(
            held,
            label=f"{side.label} directory",
            expected_uid=side.expected_uid,
            expected_gid=side.expected_gid,
        )
        old_dev_ino = side.directory_identity[:2]
        if (held.st_dev, held.st_ino) != old_dev_ino:
            raise ManagementKeyError(f"{side.label} held directory identity changed")
        if _directory_identity(rebound) != _directory_identity(held):
            raise ManagementKeyError(f"{side.label} directory canonical name was rebound")
        side.directory_identity = _directory_identity(held)
    except OSError as exc:
        raise ManagementKeyError(f"{side.label} directory canonical identity disappeared") from exc


def _open_pair(side: HeldSide) -> HeldPair:
    assert side.directory_descriptor is not None
    private = _open_leaf(
        side.directory_descriptor,
        PRIVATE_NAME,
        label=f"{side.label} private key",
        expected_mode=PRIVATE_MODE,
        expected_uid=side.expected_uid,
        expected_gid=side.expected_gid,
        limit=MAX_PRIVATE_KEY_BYTES,
    )
    try:
        public = _open_leaf(
            side.directory_descriptor,
            PUBLIC_NAME,
            label=f"{side.label} public key",
            expected_mode=PUBLIC_MODE,
            expected_uid=side.expected_uid,
            expected_gid=side.expected_gid,
            limit=MAX_PUBLIC_KEY_BYTES,
        )
        public_identity, fingerprint = _decode_public(public.payload, side.label)
        private_identity = _derive_private_identity(private, side.label)
        if private_identity != public_identity:
            raise ManagementKeyError(f"{side.label} private/public pair does not match")
        return HeldPair(private, public, public_identity, fingerprint)
    except BaseException:
        private.close()
        try:
            public.close()  # type: ignore[possibly-undefined]
        except (NameError, UnboundLocalError):
            pass
        raise


def _name_present(directory_descriptor: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise ManagementKeyError(f"cannot inspect {name}: {exc}") from exc


def _observe_side(
    label: str,
    directory: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    authority_boundary: Path,
) -> HeldSide:
    _canonical_under(authority_boundary, directory, label)
    ancestors = _open_parent_chain(
        directory.parent,
        authority_boundary=authority_boundary,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    parent_descriptor = ancestors[-1].descriptor
    basename = directory.name
    side: HeldSide | None = None
    directory_descriptor: int | None = None
    try:
        try:
            direct = os.stat(basename, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return HeldSide(
                label, directory, expected_uid, expected_gid, ancestors,
                parent_descriptor, basename, None, None, None, "ABSENT",
            )
        if stat.S_ISLNK(direct.st_mode):
            raise ManagementKeyError(f"{label} directory symlink is rejected by NOFOLLOW policy")
        _validate_directory_metadata(
            direct, label=f"{label} directory",
            expected_uid=expected_uid, expected_gid=expected_gid,
        )
        directory_descriptor = os.open(basename, _directory_flags(), dir_fd=parent_descriptor)
        held = os.fstat(directory_descriptor)
        if _directory_identity(held) != _directory_identity(direct):
            os.close(directory_descriptor)
            raise ManagementKeyError(f"{label} directory changed during open")
        side = HeldSide(
            label, directory, expected_uid, expected_gid, ancestors,
            parent_descriptor, basename, directory_descriptor,
            _directory_identity(held), None, "ABSENT",
        )
        private_present = _name_present(directory_descriptor, PRIVATE_NAME)
        public_present = _name_present(directory_descriptor, PUBLIC_NAME)
        if private_present != public_present:
            raise ManagementKeyError(f"{label} key is a half/incomplete pair")
        if private_present:
            side.pair = _open_pair(side)
            side.state = "VALID"
        return side
    except BaseException:
        if side is not None:
            side.close()
        else:
            if directory_descriptor is not None:
                try:
                    os.close(directory_descriptor)
                except OSError:
                    pass
            for component in reversed(ancestors):
                try:
                    component.close()
                except OSError:
                    pass
        raise


def _ensure_side_directory(side: HeldSide) -> None:
    if side.directory_descriptor is not None:
        _revalidate_directory(side)
        return
    _revalidate_parent_chain(side)
    created_identity: tuple[int, int] | None = None
    descriptor: int | None = None
    try:
        previous_umask = os.umask(STAGING_UMASK)
        try:
            os.mkdir(side.basename, DIRECTORY_MODE, dir_fd=side.parent_descriptor)
        finally:
            os.umask(previous_umask)
        direct = os.stat(side.basename, dir_fd=side.parent_descriptor, follow_symlinks=False)
        created_identity = (direct.st_dev, direct.st_ino)
        _checkpoint(f"{side.label}-directory-created")
        descriptor = os.open(side.basename, _directory_flags(), dir_fd=side.parent_descriptor)
        held_before_initialization = os.fstat(descriptor)
        if (held_before_initialization.st_dev, held_before_initialization.st_ino) != created_identity:
            raise ManagementKeyError(f"{side.label} directory was rebound before held open")
        os.fchmod(descriptor, DIRECTORY_MODE)
        os.fchown(descriptor, side.expected_uid, side.expected_gid)
        os.fsync(descriptor)
        os.fsync(side.parent_descriptor)
        held = os.fstat(descriptor)
        _validate_directory_metadata(
            held, label=f"{side.label} directory",
            expected_uid=side.expected_uid, expected_gid=side.expected_gid,
        )
        rebound = os.stat(
            side.basename, dir_fd=side.parent_descriptor, follow_symlinks=False,
        )
        if (held.st_dev, held.st_ino) != created_identity:
            raise ManagementKeyError(f"{side.label} held directory identity changed")
        if _directory_identity(held) != _directory_identity(rebound):
            raise ManagementKeyError(f"{side.label} directory was rebound after creation")
        side.directory_descriptor = descriptor
        side.directory_identity = _directory_identity(held)
        descriptor = None
    except (OSError, ManagementKeyError) as exc:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        cleanup_failed = False
        if created_identity is not None:
            try:
                current = os.stat(
                    side.basename, dir_fd=side.parent_descriptor, follow_symlinks=False,
                )
                if (current.st_dev, current.st_ino) != created_identity:
                    cleanup_failed = True
                else:
                    os.rmdir(side.basename, dir_fd=side.parent_descriptor)
                    os.fsync(side.parent_descriptor)
            except OSError:
                cleanup_failed = True
        if cleanup_failed:
            raise ManagementKeyError(
                f"cannot initialize or safely remove {side.label} directory"
            ) from exc
        if isinstance(exc, ManagementKeyError):
            raise
        raise ManagementKeyError(f"cannot create safe {side.label} directory: {exc}") from exc


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise ManagementKeyError("candidate write made no progress")
        view = view[written:]


def _open_anonymous_candidate(directory_descriptor: int, mode: int) -> tuple[int, int]:
    if not sys.platform.startswith("linux") or not hasattr(os, "O_TMPFILE"):
        raise ManagementKeyError("Linux O_TMPFILE and linkat AT_EMPTY_PATH are required")
    try:
        descriptor = os.open(
            ".",
            os.O_RDWR | os.O_TMPFILE | os.O_CLOEXEC,
            mode,
            dir_fd=directory_descriptor,
        )
    except OSError as exc:
        raise ManagementKeyError(f"cannot create anonymous held candidate: {exc}") from exc
    return descriptor, 0


def _publish_held_inode(
    candidate_descriptor: int, directory_descriptor: int, target_name: str,
) -> None:
    if not sys.platform.startswith("linux"):
        raise ManagementKeyError("Linux linkat AT_EMPTY_PATH is required")
    libc = ctypes.CDLL(None, use_errno=True)
    linkat = libc.linkat
    linkat.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
    linkat.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = linkat(
        candidate_descriptor,
        b"",
        directory_descriptor,
        target_name.encode("ascii"),
        AT_EMPTY_PATH,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        raise ManagementKeyError(
            f"held no-replace linkat publication failed: {os.strerror(error_number)}"
        )


def _close_anonymous_candidate(descriptor: int) -> None:
    os.close(descriptor)


def _publish_leaf(
    side: HeldSide,
    name: str,
    payload: bytes,
    mode: int,
    *,
    source_revalidator: Callable[[], None] | None = None,
) -> HeldLeaf:
    assert side.directory_descriptor is not None
    _revalidate_directory(side)
    directory_descriptor = side.directory_descriptor
    descriptor = -1
    candidate_identity: tuple[int, int] | None = None
    published = False
    try:
        descriptor, expected_link_count = _open_anonymous_candidate(directory_descriptor, mode)
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, side.expected_uid, side.expected_gid)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ManagementKeyError(f"{side.label} held candidate must be regular")
        if metadata.st_nlink != expected_link_count:
            raise ManagementKeyError(f"{side.label} held candidate link count is unsafe")
        if metadata.st_uid != side.expected_uid or metadata.st_gid != side.expected_gid:
            raise ManagementKeyError(f"{side.label} held candidate owner is unsafe")
        if stat.S_IMODE(metadata.st_mode) != mode:
            raise ManagementKeyError(f"{side.label} held candidate mode is unsafe")
        if metadata.st_size != len(payload):
            raise ManagementKeyError(f"{side.label} candidate size changed")
        candidate_identity = (metadata.st_dev, metadata.st_ino)
        _checkpoint(f"{side.label}-{name}-candidate-ready")
        if source_revalidator is not None:
            source_revalidator()
        _revalidate_directory(side)
        _publish_held_inode(descriptor, directory_descriptor, name)
        published = True
        os.fsync(directory_descriptor)
        _refresh_directory_identity(side)
        _close_anonymous_candidate(descriptor)
        descriptor = -1
        held = _open_leaf(
            directory_descriptor,
            name,
            label=f"{side.label} {name}",
            expected_mode=mode,
            expected_uid=side.expected_uid,
            expected_gid=side.expected_gid,
            limit=MAX_PRIVATE_KEY_BYTES if name == PRIVATE_NAME else MAX_PUBLIC_KEY_BYTES,
        )
        if (held.metadata[0], held.metadata[1]) != candidate_identity:
            held.close()
            raise ManagementKeyError(f"{side.label} canonical leaf is not the held candidate inode")
        os.fsync(held.descriptor)
        return held
    except (OSError, ManagementKeyError) as exc:
        if descriptor >= 0:
            _close_anonymous_candidate(descriptor)
        phase = "post-publication" if published else "no-replace publication"
        if isinstance(exc, ManagementKeyError):
            raise ManagementKeyError(f"{side.label} {phase} failed: {exc}") from exc
        raise ManagementKeyError(f"{side.label} {phase} failed: {exc}") from exc


def _publish_pair(
    side: HeldSide,
    private_payload: bytes,
    public_payload: bytes,
    *,
    source_revalidator: Callable[[], None] | None = None,
) -> None:
    _ensure_side_directory(side)
    assert side.directory_descriptor is not None
    if source_revalidator is not None:
        source_revalidator()
    if _name_present(side.directory_descriptor, PRIVATE_NAME) or _name_present(
        side.directory_descriptor, PUBLIC_NAME,
    ):
        raise ManagementKeyError(f"{side.label} canonical key appeared; refusing overwrite")
    private = _publish_leaf(
        side,
        PRIVATE_NAME,
        private_payload,
        PRIVATE_MODE,
        source_revalidator=source_revalidator,
    )
    try:
        _checkpoint(f"{side.label}-private-published")
        if source_revalidator is not None:
            source_revalidator()
        public = _publish_leaf(
            side,
            PUBLIC_NAME,
            public_payload,
            PUBLIC_MODE,
            source_revalidator=source_revalidator,
        )
    except BaseException:
        private.close()
        raise
    side.pair = HeldPair(private, public, (b"", b""), "")
    _checkpoint(f"{side.label}-pair-published")
    private_identity = _derive_private_identity(private, side.label)
    public_identity, fingerprint = _decode_public(public.payload, side.label)
    if private_identity != public_identity:
        raise ManagementKeyError(f"{side.label} published private/public pair does not match")
    side.pair.identity = public_identity
    side.pair.fingerprint = fingerprint
    side.state = "VALID"


def _verify_pair_stable(side: HeldSide) -> None:
    _revalidate_directory(side)
    if side.pair is None or side.directory_descriptor is None:
        raise ManagementKeyError(f"{side.label} pair is absent")
    _revalidate_leaf(side.directory_descriptor, side.pair.private, f"{side.label} private key")
    _revalidate_leaf(side.directory_descriptor, side.pair.public, f"{side.label} public key")
    public_identity, fingerprint = _decode_public(side.pair.public.payload, side.label)
    private_identity = _derive_private_identity(side.pair.private, side.label)
    if private_identity != public_identity or public_identity != side.pair.identity:
        raise ManagementKeyError(f"{side.label} pair identity changed during revalidation")
    if fingerprint != side.pair.fingerprint:
        raise ManagementKeyError(f"{side.label} fingerprint changed during revalidation")


def _create_generation_stage(host: HeldSide) -> tuple[str, int]:
    _ensure_side_directory(host)
    assert host.directory_descriptor is not None
    _revalidate_directory(host)
    for _attempt in range(64):
        name = ".management-key-stage-" + secrets.token_hex(16)
        try:
            os.mkdir(name, DIRECTORY_MODE, dir_fd=host.directory_descriptor)
        except FileExistsError:
            continue
        os.fsync(host.directory_descriptor)
        _refresh_directory_identity(host)
        descriptor = os.open(name, _directory_flags(), dir_fd=host.directory_descriptor)
        metadata = os.fstat(descriptor)
        _validate_directory_metadata(
            metadata, label="host generation staging directory",
            expected_uid=host.expected_uid, expected_gid=host.expected_gid,
        )
        return name, descriptor
    raise ManagementKeyError("cannot allocate unique private generation staging")


def _cleanup_generation_stage(
    host: HeldSide,
    name: str,
    descriptor: int,
    created_leaf_identities: Mapping[str, tuple[int, ...]],
) -> None:
    assert host.directory_descriptor is not None
    remove_directory = False
    try:
        try:
            direct = os.stat(
                name, dir_fd=host.directory_descriptor, follow_symlinks=False,
            )
            held = os.fstat(descriptor)
            if (direct.st_dev, direct.st_ino) != (held.st_dev, held.st_ino):
                raise ManagementKeyError("generation staging directory identity changed")
            entries = sorted(os.listdir(descriptor))
            if set(entries) != set(created_leaf_identities):
                raise ManagementKeyError(
                    "generation staging contains an unexpected or unowned child"
                )
            observed: dict[str, tuple[int, ...]] = {}
            for entry in entries:
                metadata = os.stat(entry, dir_fd=descriptor, follow_symlinks=False)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise ManagementKeyError("generation staging child identity is unsafe")
                identity = _metadata_identity(metadata)
                if identity != created_leaf_identities[entry]:
                    raise ManagementKeyError(
                        "generation staging child identity changed; replacement preserved"
                    )
                observed[entry] = identity
            # The final check-to-unlink interval is safe only inside the agreed
            # root-owned, mode-0700, hostlock-serialized writer boundary.  A
            # non-cooperating concurrent root is explicitly outside that trust
            # boundary because Linux has no conditional unlink-by-inode API.
            for entry in entries:
                metadata = os.stat(entry, dir_fd=descriptor, follow_symlinks=False)
                if _metadata_identity(metadata) != observed[entry]:
                    raise ManagementKeyError(
                        "generation staging child changed before cleanup; replacement preserved"
                    )
                os.unlink(entry, dir_fd=descriptor)
            os.fsync(descriptor)
            remove_directory = True
        except (OSError, ManagementKeyError) as exc:
            raise ManagementKeyError(
                "generation staging cleanup failed; exact staging residue retained"
            ) from exc
    finally:
        os.close(descriptor)
    if remove_directory:
        try:
            os.rmdir(name, dir_fd=host.directory_descriptor)
            os.fsync(host.directory_descriptor)
            _refresh_directory_identity(host)
        except OSError as exc:
            raise ManagementKeyError(
                "generation staging directory cleanup failed; "
                "empty staging residue retained"
            ) from exc


def _revalidate_generation_source(
    stage: HeldSide,
    created_leaf_identities: Mapping[str, tuple[int, ...]],
) -> None:
    _revalidate_directory(stage)
    if stage.directory_descriptor is None or stage.pair is None:
        raise ManagementKeyError("generation staging source is no longer held")
    try:
        entries = sorted(os.listdir(stage.directory_descriptor))
    except OSError as exc:
        raise ManagementKeyError(
            f"generation staging source cannot be enumerated: {exc}"
        ) from exc
    if entries != [PRIVATE_NAME, PUBLIC_NAME]:
        raise ManagementKeyError("generation staging source exact set changed")
    for leaf, label in (
        (stage.pair.private, "generation staging private key"),
        (stage.pair.public, "generation staging public key"),
    ):
        if leaf.metadata != created_leaf_identities.get(leaf.name):
            raise ManagementKeyError(f"{label} is not invocation-owned")
        _revalidate_leaf(stage.directory_descriptor, leaf, label)


def _initialize_generated_leaf(
    directory_descriptor: int,
    name: str,
    *,
    mode: int,
    expected_uid: int,
    expected_gid: int,
) -> tuple[int, ...]:
    descriptor = -1
    try:
        descriptor = os.open(name, _leaf_flags(), dir_fd=directory_descriptor)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ManagementKeyError("ssh-keygen staging leaf has unsafe identity")
        if metadata.st_uid != expected_uid or metadata.st_gid != expected_gid:
            raise ManagementKeyError("ssh-keygen staging leaf has unsafe owner")
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, expected_uid, expected_gid)
        os.fsync(descriptor)
        final_metadata = os.fstat(descriptor)
        _validate_leaf_metadata(
            final_metadata,
            label=f"generated staging {name}",
            expected_mode=mode,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        return _metadata_identity(final_metadata)
    except OSError as exc:
        raise ManagementKeyError(f"cannot initialize generated staging leaf: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _generate_and_publish_host(host: HeldSide) -> None:
    previous_umask = os.umask(STAGING_UMASK)
    name = ""
    stage_descriptor = -1
    result: CommandResult | None = None
    stage_side: HeldSide | None = None
    created_leaf_identities: dict[str, tuple[int, ...]] = {}
    try:
        name, stage_descriptor = _create_generation_stage(host)
        stage_path = host.directory / name
        result = _run_bounded_command(
            [
                os.fspath(SSH_KEYGEN), "-q", "-t", "ed25519", "-N", "",
                "-C", "root@management-server", "-f", PRIVATE_NAME,
            ],
            pass_fds=(stage_descriptor,),
            working_directory_fd=stage_descriptor,
            timeout=SSH_KEYGEN_TIMEOUT_SECONDS,
            max_stdout=MAX_TOOL_OUTPUT_BYTES,
            max_stderr=MAX_TOOL_OUTPUT_BYTES,
        )
        if result.returncode != 0 or result.stdout or result.stderr:
            raise ManagementKeyError("ssh-keygen generation failed or returned unexpected output")
        if sorted(os.listdir(stage_descriptor)) != [PRIVATE_NAME, PUBLIC_NAME]:
            raise ManagementKeyError("ssh-keygen staging exact child set is invalid")
        created_leaf_identities[PRIVATE_NAME] = _initialize_generated_leaf(
            stage_descriptor,
            PRIVATE_NAME,
            mode=PRIVATE_MODE,
            expected_uid=host.expected_uid,
            expected_gid=host.expected_gid,
        )
        created_leaf_identities[PUBLIC_NAME] = _initialize_generated_leaf(
            stage_descriptor,
            PUBLIC_NAME,
            mode=PUBLIC_MODE,
            expected_uid=host.expected_uid,
            expected_gid=host.expected_gid,
        )
        os.fsync(stage_descriptor)
        stage_side = HeldSide(
            "generated-host", stage_path, host.expected_uid, host.expected_gid,
            [], host.directory_descriptor, name, stage_descriptor,
            _directory_identity(os.fstat(stage_descriptor)), None, "VALID",
        )
        _revalidate_directory(stage_side)
        _revalidate_directory(host)
        stage_side.pair = _open_pair(stage_side)
        _publish_pair(
            host,
            stage_side.pair.private.payload,
            stage_side.pair.public.payload,
            source_revalidator=lambda: _revalidate_generation_source(
                stage_side, created_leaf_identities,
            ),
        )
    finally:
        os.umask(previous_umask)
        if stage_side is not None and stage_side.pair is not None:
            stage_side.pair.close()
            stage_side.pair = None
        if name and stage_descriptor >= 0:
            try:
                _checkpoint("generation-stage-pre-cleanup")
            finally:
                _cleanup_generation_stage(
                    host, name, stage_descriptor, created_leaf_identities,
                )


def _open_both(
    *,
    host_home: Path,
    service_directory: Path,
    host_uid: int,
    host_gid: int,
    service_uid: int,
    service_gid: int,
    authority_boundary: Path,
) -> tuple[HeldSide, HeldSide]:
    host = _observe_side(
        "host", host_home / ".ssh",
        expected_uid=host_uid, expected_gid=host_gid,
        authority_boundary=authority_boundary,
    )
    try:
        service = _observe_side(
            "service", service_directory,
            expected_uid=service_uid, expected_gid=service_gid,
            authority_boundary=authority_boundary,
        )
    except BaseException:
        host.close()
        raise
    return host, service


def _operation_options(
    *,
    host_home: Path,
    service_directory: Path,
    host_uid: int,
    host_gid: int,
    service_uid: int,
    service_gid: int,
    authority_boundary: Path,
    keygen: Path,
) -> dict[str, object]:
    if Path(keygen) != SSH_KEYGEN:
        raise ManagementKeyError("ssh-keygen path must be exactly /usr/bin/ssh-keygen")
    for value, label in (
        (host_uid, "host uid"), (host_gid, "host gid"),
        (service_uid, "service uid"), (service_gid, "service gid"),
    ):
        if type(value) is not int or value < 0:
            raise ManagementKeyError(f"{label} is invalid")
    return {
        "host_home": Path(host_home),
        "service_directory": Path(service_directory),
        "host_uid": host_uid,
        "host_gid": host_gid,
        "service_uid": service_uid,
        "service_gid": service_gid,
        "authority_boundary": Path(authority_boundary),
    }


def synchronize_management_key(
    *,
    host_home: Path,
    service_directory: Path,
    host_uid: int,
    host_gid: int,
    service_uid: int,
    service_gid: int,
    authority_boundary: Path,
    keygen: Path = SSH_KEYGEN,
) -> dict[str, object]:
    options = _operation_options(
        host_home=host_home,
        service_directory=service_directory,
        host_uid=host_uid,
        host_gid=host_gid,
        service_uid=service_uid,
        service_gid=service_gid,
        authority_boundary=authority_boundary,
        keygen=keygen,
    )
    host, service = _open_both(**options)
    try:
        _checkpoint("authority-components-held")
        _revalidate_parent_chain(host)
        _revalidate_parent_chain(service)
        if host.state == "VALID":
            _checkpoint("host-source-pair-held")
            _verify_pair_stable(host)
        if service.state == "VALID":
            _checkpoint("service-source-pair-held")
            _verify_pair_stable(service)
        if host.state == "ABSENT" and service.state == "ABSENT":
            _generate_and_publish_host(host)
            assert host.pair is not None
            _publish_pair(service, host.pair.private.payload, host.pair.public.payload)
            action = "generated-host-and-copied-service"
        elif host.state == "VALID" and service.state == "ABSENT":
            assert host.pair is not None
            _publish_pair(service, host.pair.private.payload, host.pair.public.payload)
            action = "copied-host-to-service"
        elif host.state == "ABSENT" and service.state == "VALID":
            assert service.pair is not None
            _publish_pair(host, service.pair.private.payload, service.pair.public.payload)
            action = "copied-service-to-host"
        else:
            assert host.pair is not None and service.pair is not None
            if host.pair.identity != service.pair.identity:
                message = (
                    "valid management identities conflict; "
                    f"host_fingerprint={host.pair.fingerprint} "
                    f"service_fingerprint={service.pair.fingerprint}; "
                    "verify switch authorization and install one complete pair explicitly"
                )
                if len(message.encode("utf-8")) > 512:
                    raise ManagementKeyError("bounded conflict diagnostic overflow")
                raise ManagementKeyConflict(message)
            action = "preserved-identical"
        _verify_pair_stable(host)
        _verify_pair_stable(service)
        assert host.pair is not None and service.pair is not None
        if host.pair.identity != service.pair.identity:
            raise ManagementKeyError("final host/service identity mismatch")
        return {
            "action": action,
            "valid": True,
            "fingerprint": host.pair.fingerprint,
        }
    finally:
        service.close()
        host.close()


def check_management_key(
    *,
    host_home: Path,
    service_directory: Path,
    host_uid: int,
    host_gid: int,
    service_uid: int,
    service_gid: int,
    authority_boundary: Path,
    keygen: Path = SSH_KEYGEN,
) -> dict[str, object]:
    options = _operation_options(
        host_home=host_home,
        service_directory=service_directory,
        host_uid=host_uid,
        host_gid=host_gid,
        service_uid=service_uid,
        service_gid=service_gid,
        authority_boundary=authority_boundary,
        keygen=keygen,
    )
    host, service = _open_both(**options)
    try:
        _checkpoint("authority-components-held")
        _revalidate_parent_chain(host)
        _revalidate_parent_chain(service)
        if host.state == "VALID":
            _verify_pair_stable(host)
        if service.state == "VALID":
            _verify_pair_stable(service)
        if host.state == "ABSENT" and service.state == "ABSENT":
            return {"action": "generation-required", "valid": False, "fingerprint": None}
        if host.state == "VALID" and service.state == "ABSENT":
            assert host.pair is not None
            return {
                "action": "copy-host-to-service-required", "valid": False,
                "fingerprint": host.pair.fingerprint,
            }
        if host.state == "ABSENT" and service.state == "VALID":
            assert service.pair is not None
            return {
                "action": "copy-service-to-host-required", "valid": False,
                "fingerprint": service.pair.fingerprint,
            }
        assert host.pair is not None and service.pair is not None
        if host.pair.identity != service.pair.identity:
            message = (
                "valid management identities conflict; "
                f"host_fingerprint={host.pair.fingerprint} "
                f"service_fingerprint={service.pair.fingerprint}; resolve explicitly"
            )
            raise ManagementKeyConflict(message)
        return {
            "action": "preserved-identical", "valid": True,
            "fingerprint": host.pair.fingerprint,
        }
    finally:
        service.close()
        host.close()


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    result.add_argument("action", choices=("reconcile", "check"))
    return result


def _production_options() -> dict[str, object]:
    if os.geteuid() != 0 or os.getegid() != 0:
        raise ManagementKeyError("fixed management SSH authority requires root")
    return {
        "host_home": HOST_SSH_DIRECTORY.parent,
        "service_directory": SERVICE_SSH_DIRECTORY,
        "host_uid": 0,
        "host_gid": 0,
        "service_uid": 0,
        "service_gid": 0,
        "authority_boundary": Path("/"),
        "keygen": SSH_KEYGEN,
    }


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        if arguments.action == "reconcile":
            outcome = synchronize_management_key(**_production_options())
        else:
            outcome = check_management_key(**_production_options())
        payload = json.dumps(outcome, sort_keys=True, separators=(",", ":"))
        if len(payload.encode("ascii")) > 512:
            raise ManagementKeyError("status output exceeds fixed bound")
        print(payload)
        return 0
    except ManagementKeyError as exc:
        message = str(exc).replace("\n", " ")[:512]
        print(f"management-ssh-key: {message}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
