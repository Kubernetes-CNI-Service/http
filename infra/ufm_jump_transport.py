#!/usr/bin/env python3
"""Closed, key-only jump transport primitives for UFM orchestration.

This module intentionally does not define the Phase-C handoff, UFM release, or
remote certificate/licence/log paths.  Those values remain caller-owned until
their schema is frozen.  It does provide the portable transport and failure
evidence boundary that those callers must use.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
from typing import Callable, Mapping, Optional, Sequence, TypeVar


class TransportError(RuntimeError):
    """Raised before dispatch when a transport contract is not satisfied."""


_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_HOST_RE = re.compile(
    r"^(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
_REMOTE_COMPONENT_RE = re.compile(r"^[A-Za-z0-9._+-]+$")
_SAFE_EVENT_RE = re.compile(
    r"UFM_EVENT\|stage=(?:discovery|auth|bootstrap|upgrade|restart|ha|"
    r"license|collect)\|status=(?:started|succeeded|failed|interrupted|"
    r"timed_out)\|code=(?:none|invalid_input|identity_mismatch|auth_failed|"
    r"host_unreachable|remote_error|timeout|retrieval_failed)\n"
)


def typed_argv(argv: object, *, label: str) -> list[str]:
    """Return a defensive argv copy after rejecting scalar/control carriers."""
    if type(argv) is not list or not argv:
        raise TransportError(f"{label} must be a non-empty argv array")
    if any(type(item) is not str or not item for item in argv):
        raise TransportError(f"{label} must contain only non-empty string tokens")
    if any(re.search(r"[\x00-\x1f\x7f-\x9f]", item) for item in argv):
        raise TransportError(f"{label} contains a forbidden control character")
    return list(argv)


def _scalar(value: object, *, label: str, pattern: re.Pattern[str]) -> str:
    if type(value) is not str or not pattern.fullmatch(value):
        raise TransportError(f"invalid {label}")
    return value


def _host(value: object, *, label: str) -> str:
    if type(value) is not str or not value or value.startswith("-"):
        raise TransportError(f"invalid {label}")
    if re.search(r"[\x00-\x20\x7f-\x9f/@]", value):
        raise TransportError(f"invalid {label}")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if not _HOST_RE.fullmatch(value):
            raise TransportError(f"invalid {label}")
        return value.casefold()


def _absolute_local_path(value: Path, *, label: str) -> Path:
    if not isinstance(value, Path) or not value.is_absolute():
        raise TransportError(f"{label} must be an absolute local path")
    if any(part == ".." for part in value.parts):
        raise TransportError(f"{label} must not contain parent traversal")
    return value


def _remote_path(value: object, *, label: str) -> str:
    if type(value) is not str or not value.startswith("/"):
        raise TransportError(f"{label} must be an absolute remote path")
    if re.search(r"[\x00-\x20\x7f-\x9f]", value):
        raise TransportError(f"{label} contains whitespace or control characters")
    path = PurePosixPath(value)
    if ".." in path.parts or any(
        part not in {"/", ""} and not _REMOTE_COMPONENT_RE.fullmatch(part)
        for part in path.parts
    ):
        raise TransportError(f"{label} contains an unsafe component")
    return str(path)


def _timeout(value: object) -> int:
    if type(value) is not int or value < 1 or value > 600:
        raise TransportError("timeout must be an integer from 1 through 600")
    return value


@dataclass(frozen=True)
class JumpEndpoint:
    host: str
    user: str
    known_hosts: Path
    identity: Optional[Path] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "host", _host(self.host, label="jump host"))
        object.__setattr__(
            self, "user", _scalar(self.user, label="jump user", pattern=_TOKEN_RE)
        )
        object.__setattr__(
            self,
            "known_hosts",
            _absolute_local_path(self.known_hosts, label="known_hosts"),
        )
        if self.identity is not None:
            object.__setattr__(
                self,
                "identity",
                _absolute_local_path(self.identity, label="identity"),
            )

    @property
    def target(self) -> str:
        return f"{self.user}@{self.host}"


@dataclass(frozen=True)
class BoundFarEndpoint:
    host: str
    user: str
    identity_evidence: str
    jump: JumpEndpoint
    bind_interface: Optional[str] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "host", _host(self.host, label="far host"))
        object.__setattr__(
            self, "user", _scalar(self.user, label="far user", pattern=_TOKEN_RE)
        )
        if type(self.identity_evidence) is not str or not self.identity_evidence.strip():
            raise TransportError("far endpoint requires identity-bound evidence")
        if re.search(r"[\x00-\x1f\x7f-\x9f]", self.identity_evidence):
            raise TransportError("far endpoint evidence contains a control character")
        if self.bind_interface is not None:
            object.__setattr__(
                self,
                "bind_interface",
                _scalar(
                    self.bind_interface,
                    label="far bind interface",
                    pattern=_TOKEN_RE,
                ),
            )
            try:
                ipaddress.IPv6Address(self.host)
            except ValueError as exc:
                raise TransportError(
                    "bind interface is valid only for an IPv6 far endpoint"
                ) from exc

    @property
    def scoped_host(self) -> str:
        if self.bind_interface:
            return f"{self.host}%{self.bind_interface}"
        return self.host

    @property
    def target(self) -> str:
        return f"{self.user}@{self.scoped_host}"

    def scp_target(self, remote_path: str) -> str:
        host = self.scoped_host
        if ":" in host:
            host = f"[{host}]"
        return f"{self.user}@{host}:{remote_path}"


def _ssh_options(jump: JumpEndpoint, timeout: int) -> list[str]:
    timeout = _timeout(timeout)
    options = [
        "-o", "BatchMode=yes",
        "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no",
        "-o", "NumberOfPasswordPrompts=0",
        "-o", "ConnectionAttempts=1",
        "-o", f"ConnectTimeout={timeout}",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "UpdateHostKeys=no",
        "-o", f"UserKnownHostsFile={jump.known_hosts}",
    ]
    if jump.identity is not None:
        options.extend(["-i", str(jump.identity)])
    return options


def _read_argv(argv: object) -> list[str]:
    command = typed_argv(argv, label="jump_read command")
    exact = {
        ("hostname",),
        ("nv", "show", "interface"),
        ("nv", "config", "show"),
        ("ip", "-d", "link", "show"),
        ("bridge", "fdb", "show"),
        ("ip", "neighbor"),
    }
    if tuple(command) not in exact:
        raise TransportError("jump_read command is outside the closed allowlist")
    return command


def _proxy_option(jump: JumpEndpoint, timeout: int) -> str:
    """Render the internally built, fully pinned jump connection once."""
    proxy = [
        "ssh",
        *_ssh_options(jump, timeout),
        "-W", "%h:%p",
        jump.target,
    ]
    return "ProxyCommand=" + _join(proxy)


def jump_read(jump: JumpEndpoint, remote_argv: object, *, timeout: int) -> list[str]:
    """Build one read-only command on the jump host."""
    command = _read_argv(remote_argv)
    return ["ssh", *_ssh_options(jump, timeout), jump.target, _join(command)]


def jump_transit(
    jump: JumpEndpoint,
    far: BoundFarEndpoint,
    remote_argv: object,
    *,
    timeout: int,
) -> list[str]:
    """Build one far command whose only network path is the validated jump."""
    if far.jump != jump:
        raise TransportError("far endpoint jump binding does not match transport")
    command = typed_argv(remote_argv, label="jump_transit command")
    return [
        "ssh",
        *_ssh_options(jump, timeout),
        "-o", _proxy_option(jump, timeout),
        far.target,
        _join(command),
    ]


def _join(command: Sequence[str]) -> str:
    # Kept as one named boundary so tests can prove every typed vector is joined
    # once, and only once, immediately before the remote SSH argument.
    import shlex

    return shlex.join(command)


def jump_copy_to(
    jump: JumpEndpoint,
    far: BoundFarEndpoint,
    local_path: Path,
    remote_path: object,
    *,
    timeout: int,
) -> list[str]:
    if far.jump != jump:
        raise TransportError("far endpoint jump binding does not match transport")
    local = _absolute_local_path(local_path, label="copy-in source")
    remote = _remote_path(remote_path, label="copy-in destination")
    return [
        "scp", *_ssh_options(jump, timeout),
        "-o", _proxy_option(jump, timeout),
        "--", str(local), far.scp_target(remote),
    ]


def jump_copy_from(
    jump: JumpEndpoint,
    far: BoundFarEndpoint,
    remote_path: object,
    local_path: Path,
    *,
    timeout: int,
) -> list[str]:
    if far.jump != jump:
        raise TransportError("far endpoint jump binding does not match transport")
    remote = _remote_path(remote_path, label="copy-out source")
    local = _absolute_local_path(local_path, label="copy-out destination")
    return [
        "scp", *_ssh_options(jump, timeout),
        "-o", _proxy_option(jump, timeout),
        "--", far.scp_target(remote), str(local),
    ]


def plan_copy_inputs(
    jump: JumpEndpoint,
    far: BoundFarEndpoint,
    *,
    certificate: Path,
    certificate_remote: str,
    license_file: Path,
    license_remote: str,
    timeout: int,
) -> dict[str, list[str]]:
    """Build the two frozen UFM input classes without inventing their paths."""
    return {
        "certificate": jump_copy_to(
            jump, far, certificate, certificate_remote, timeout=timeout
        ),
        "license": jump_copy_to(
            jump, far, license_file, license_remote, timeout=timeout
        ),
    }


def bind_cluster_and_vip(
    node_jumps: Mapping[str, JumpEndpoint],
    *,
    vip_jump: Optional[JumpEndpoint] = None,
) -> JumpEndpoint:
    """Return the VIP binding only when every node has the same jump."""
    if not node_jumps:
        raise TransportError("UFM cluster has no node jump bindings")
    if any(type(name) is not str or not name for name in node_jumps):
        raise TransportError("UFM cluster contains an invalid node name")
    unique = set(node_jumps.values())
    if len(unique) != 1:
        raise TransportError("all UFM cluster nodes must resolve to the same jump")
    inherited = next(iter(unique))
    if vip_jump is not None and vip_jump != inherited:
        raise TransportError("explicit VIP jump conflicts with the inherited node jump")
    return inherited


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


Runner = Callable[[list[str]], CommandResult]
_MAX_RETRIEVED_LOG_BYTES = 16 * 1024 * 1024


def _default_runner(command: list[str], *, timeout: int) -> CommandResult:
    try:
        result = subprocess.run(
            command, text=True, capture_output=True, check=False,
            timeout=_timeout(timeout),
        )
    except subprocess.TimeoutExpired:
        raise TransportError("UFM transport process deadline exceeded") from None
    return CommandResult(result.returncode, result.stdout, result.stderr)


def _run(runner: Runner, command: list[str], *, timeout: int) -> CommandResult:
    # Synthetic test runners are one-argument callables. The production runner
    # always enforces the same total deadline promised by the public timeout.
    if runner is _default_runner:
        return _default_runner(command, timeout=timeout)
    return runner(command)


def redact_diagnostic(value: object) -> str:
    """Return value-free evidence for an untrusted diagnostic string."""
    payload = str(value).encode("utf-8", errors="replace")
    digest = hashlib.sha256(payload).hexdigest()
    return f"redacted-diagnostic[sha256={digest},bytes={len(payload)}]"


def redact_log_bytes(data: bytes) -> bytes:
    """Admit only our fixed-field operational events, never arbitrary raw logs.

    Free-form vendor stdout can contain unlabelled credentials. A keyword
    filter cannot establish that any arbitrary line is safe to publish.
    """
    if len(data) > _MAX_RETRIEVED_LOG_BYTES:
        raise TransportError("retrieved log exceeds the bounded redaction limit")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise TransportError("retrieved log is not valid UTF-8; redaction refused") from exc
    if not text or any(
        _SAFE_EVENT_RE.fullmatch(line) is None
        for line in text.splitlines(keepends=True)
    ):
        raise TransportError("retrieved log is not an approved structured UFM event stream")
    return data


def _cleanup_private_dir(path: Path) -> None:
    try:
        shutil.rmtree(path)
    except OSError as exc:
        raise TransportError(
            f"private UFM staging cleanup failed: {redact_diagnostic(exc)}"
        ) from exc


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short write while publishing retrieved log")
        view = view[written:]


def _read_regular_bytes(path: Path, *, label: str) -> bytes:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, os.O_RDONLY | nofollow)
    try:
        observed = os.fstat(fd)
        if not stat.S_ISREG(observed.st_mode):
            raise TransportError(f"{label} is not a regular file")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_RETRIEVED_LOG_BYTES:
                raise TransportError(f"{label} exceeds the bounded size limit")
            chunks.append(chunk)
        if total == 0:
            raise TransportError(f"{label} is empty")
        return b"".join(chunks)
    finally:
        os.close(fd)


def copy_to_verified(
    jump: JumpEndpoint,
    far: BoundFarEndpoint,
    local_path: Path,
    remote_path: str,
    *,
    timeout: int,
    runner: Runner = _default_runner,
) -> None:
    """Copy one sealed regular-file snapshot through the validated jump."""
    local_path = _absolute_local_path(local_path, label="copy-in source")
    try:
        payload = _read_regular_bytes(local_path, label="copy-in source")
    except (FileNotFoundError, OSError) as exc:
        raise TransportError(f"copy-in source is not a readable regular file: {exc}") from exc
    staging_dir = Path(tempfile.mkdtemp(prefix=".ufm-copy-in-"))
    os.chmod(staging_dir, 0o700)
    staged = staging_dir / "payload"
    try:
        fd = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            _write_all(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
        command = jump_copy_to(jump, far, staged, remote_path, timeout=timeout)
        result = _run(runner, command, timeout=timeout)
        if result.returncode != 0:
            detail = redact_diagnostic(result.stderr or result.stdout)
            raise TransportError(f"jump_copy_to failed: {detail}")
    finally:
        _cleanup_private_dir(staging_dir)


def copy_from_no_overwrite(
    jump: JumpEndpoint,
    far: BoundFarEndpoint,
    remote_path: str,
    destination: Path,
    *,
    timeout: int,
    runner: Runner = _default_runner,
) -> None:
    """Retrieve through the jump and atomically create a new 0600 log file."""
    destination = _absolute_local_path(destination, label="retrieval destination")
    parent = destination.parent
    if not parent.is_dir():
        raise TransportError(f"retrieval destination directory is missing: {parent}")
    if destination.exists() or destination.is_symlink():
        raise TransportError(f"retrieval destination already exists: {destination}")

    staging_dir = Path(tempfile.mkdtemp(prefix=".ufm-retrieval-", dir=str(parent)))
    os.chmod(staging_dir, 0o700)
    staged = staging_dir / "payload"
    source_fd: Optional[int] = None
    publication_fd: Optional[int] = None
    destination_created = False
    try:
        try:
            command = jump_copy_from(
                jump, far, remote_path, staged, timeout=timeout
            )
            result = _run(runner, command, timeout=timeout)
            if result.returncode != 0:
                detail = redact_diagnostic(result.stderr or result.stdout)
                raise TransportError(f"jump_copy_from failed: {detail}")
            nofollow = getattr(os, "O_NOFOLLOW", 0)
            source_fd = os.open(staged, os.O_RDONLY | nofollow)
            source_stat = os.fstat(source_fd)
            if not stat.S_ISREG(source_stat.st_mode):
                raise TransportError("retrieved log staging object is not a regular file")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(source_fd, 1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_RETRIEVED_LOG_BYTES:
                    raise TransportError("retrieved log exceeds the bounded redaction limit")
                chunks.append(chunk)
            payload = redact_log_bytes(b"".join(chunks))
            if not payload:
                raise TransportError("retrieved log is empty; no evidence can be published")
            publication = staging_dir / "sanitized"
            publication_fd = os.open(
                publication, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow, 0o600
            )
            _write_all(publication_fd, payload)
            os.fsync(publication_fd)
            os.close(publication_fd)
            publication_fd = None
            try:
                os.link(publication, destination, follow_symlinks=False)
            except FileExistsError as exc:
                raise TransportError(
                    f"retrieval destination appeared during publication: {destination}"
                ) from exc
            destination_created = True
            _fsync_directory(parent)
        finally:
            if source_fd is not None:
                os.close(source_fd)
                source_fd = None
            if publication_fd is not None:
                os.close(publication_fd)
                publication_fd = None
            _cleanup_private_dir(staging_dir)
            _fsync_directory(parent)
    except BaseException:
        if destination_created:
            try:
                destination.unlink()
            except FileNotFoundError:
                pass
            _fsync_directory(parent)
        raise


_MAX_COLLECTION_ARCHIVE_BYTES = 512 * 1024 * 1024
_MAX_COLLECTION_MEMBER_BYTES = 256 * 1024 * 1024


def _verified_collection_archive(path: Path, kind: str) -> str:
    """Validate every bounded member and return the complete byte digest."""
    try:
        observed = path.lstat()
        if (not stat.S_ISREG(observed.st_mode) or observed.st_size <= 0
                or observed.st_size > _MAX_COLLECTION_ARCHIVE_BYTES):
            raise TransportError("retrieved collection archive is not bounded regular data")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        files = 0
        names: list[str] = []
        seen_names: set[str] = set()
        total = 0
        with tarfile.open(path, mode="r:gz") as bundle:
            for member in bundle:
                name = member.name
                parts = PurePosixPath(name).parts
                if (not parts or parts[0] != "artifact" or
                        any(part in {"", ".", ".."} for part in parts) or
                        name.startswith("/") or "//" in name or
                        str(PurePosixPath(name)) != name.rstrip("/") or
                        not (member.isfile() or member.isdir())):
                    raise TransportError("retrieved collection archive has an unsafe member")
                if name in seen_names:
                    raise TransportError("retrieved collection archive repeats a member")
                seen_names.add(name)
                if member.size < 0 or member.size > _MAX_COLLECTION_MEMBER_BYTES:
                    raise TransportError("retrieved collection member exceeds size bound")
                names.append(name)
                if member.isfile():
                    source = bundle.extractfile(member)
                    if source is None:
                        raise TransportError("retrieved collection member is unreadable")
                    size = 0
                    with source:
                        while block := source.read(1024 * 1024):
                            size += len(block)
                            total += len(block)
                            if size > member.size or total > _MAX_COLLECTION_ARCHIVE_BYTES:
                                raise TransportError("retrieved collection member exceeds declared size")
                    if size != member.size:
                        raise TransportError("retrieved collection member is truncated")
                    if size:
                        files += 1
        if not files or (kind == "iblinkinfo" and names != ["artifact"]):
            raise TransportError("retrieved collection archive has no expected artifact")
        return digest.hexdigest()
    except (OSError, tarfile.TarError, EOFError) as exc:
        raise TransportError("retrieved collection archive is invalid") from None


def _collection_parent_still_bound(parent: Path, held_fd: int) -> bool:
    try:
        observed = parent.lstat()
        held = os.fstat(held_fd)
    except OSError:
        return False
    return (stat.S_ISDIR(observed.st_mode)
            and (observed.st_dev, observed.st_ino) == (held.st_dev, held.st_ino))


def _require_collection_binding(
    binding_check: Optional[Callable[[JumpEndpoint, BoundFarEndpoint, object], bool]],
    jump: JumpEndpoint, far: BoundFarEndpoint, plan: object,
) -> None:
    try:
        if binding_check is None or binding_check(jump, far, plan) is not True:
            raise TransportError("current UFM lease and SSH identity proof is missing")
    except TransportError:
        raise
    except Exception:
        raise TransportError("current UFM lease and SSH identity proof is unavailable") from None


def _open_collection_parent_no_follow(parent: Path, directory_flag: int,
                                      nofollow: int) -> int:
    """Hold every destination ancestor without following a caller-supplied link."""
    current = os.open("/", os.O_RDONLY | directory_flag)
    try:
        for part in parent.parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | directory_flag | nofollow,
                              dir_fd=current)
            os.close(current)
            current = next_fd
        return current
    except BaseException:
        os.close(current)
        raise


def _collection_remote_digest(
    jump: JumpEndpoint, far: BoundFarEndpoint, remote: str, *,
    timeout: int, runner: Runner,
) -> str:
    command = jump_transit(jump, far, ["sha256sum", "--", remote], timeout=timeout)
    result = _run(runner, command, timeout=timeout)
    if (type(result) is not CommandResult or type(result.returncode) is not int
            or result.returncode != 0 or type(result.stdout) is not str
            or type(result.stderr) is not str or result.stderr):
        raise TransportError("remote UFM collection digest failed")
    match = re.fullmatch(r"([0-9a-f]{64})  " + re.escape(remote) + r"\n?",
                         result.stdout)
    if match is None:
        raise TransportError("remote UFM collection digest is malformed")
    return match.group(1)


def retrieve_collection_archive(
    jump: JumpEndpoint,
    far: BoundFarEndpoint,
    plan: object,
    destination: Path,
    *,
    timeout: int,
    binding_check: Optional[Callable[[JumpEndpoint, BoundFarEndpoint, object], bool]] = None,
    expected_sha256: Optional[str] = None,
    runner: Runner = _default_runner,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> Path:
    """Wait for one exact remote final archive, then validate and publish once.

    The caller must supply an independently checked current lease/SSH identity
    binding; the endpoint's nonempty identity_evidence string alone is never
    treated as proof. No production caller is enabled by this primitive.
    """
    from tools.ufm_collection_contract import CollectionError, _validated_plan

    try:
        _validated_plan(plan)
    except CollectionError as exc:
        raise TransportError("noncanonical UFM collection plan") from None
    timeout = _timeout(timeout)
    destination = _absolute_local_path(destination, label="collection destination")
    if destination.name != plan.archive_name or far.jump != jump:
        raise TransportError("collection destination or jump binding does not match plan")
    if (expected_sha256 is not None
            and (type(expected_sha256) is not str
                 or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None)):
        raise TransportError("approved UFM producer digest is invalid")
    directory_flag = getattr(os, "O_DIRECTORY", None)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if (type(directory_flag) is not int or not directory_flag
            or type(nofollow) is not int or not nofollow):
        raise TransportError("platform cannot enforce no-follow archive publication")
    _require_collection_binding(binding_check, jump, far, plan)

    parent = destination.parent
    try:
        parent_fd = _open_collection_parent_no_follow(parent, directory_flag, nofollow)
    except OSError:
        raise TransportError("collection destination parent is unavailable") from None
    stage: Optional[Path] = None
    hidden: Optional[str] = None
    final_created = False
    final_inode: Optional[tuple[int, int]] = None
    completed = False
    try:
        try:
            os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise TransportError("collection destination already exists")

        remote = plan.ufm_remote_path
        deadline = clock() + timeout
        while True:
            remaining = deadline - clock()
            if remaining <= 0:
                raise TransportError("exact UFM collection archive wait timed out")
            probe_timeout = max(1, min(timeout, int(remaining)))
            probe = jump_transit(jump, far, ["test", "-f", remote], timeout=probe_timeout)
            result = _run(runner, probe, timeout=probe_timeout)
            if result.returncode == 0:
                break
            if result.returncode != 1:
                raise TransportError("exact UFM collection archive probe failed")
            sleep(min(1.0, max(0.0, deadline - clock())))

        remaining = deadline - clock()
        if remaining <= 0:
            raise TransportError("exact UFM collection archive wait timed out")
        command_timeout = max(1, min(timeout, int(remaining)))
        remote_digest = _collection_remote_digest(
            jump, far, remote, timeout=command_timeout, runner=runner)
        if expected_sha256 is not None and remote_digest != expected_sha256:
            raise TransportError("remote UFM digest differs from producer observation")

        stage = Path(tempfile.mkdtemp(prefix=".ufm-archive-retrieval-"))
        os.chmod(stage, 0o700)
        staged = stage / "payload"
        remaining = deadline - clock()
        if remaining <= 0:
            raise TransportError("exact UFM collection archive wait timed out")
        command_timeout = max(1, min(timeout, int(remaining)))
        copy = jump_copy_from(jump, far, remote, staged, timeout=command_timeout)
        copied = _run(runner, copy, timeout=command_timeout)
        if copied.returncode != 0:
            raise TransportError("exact UFM collection archive copy failed")
        if _verified_collection_archive(staged, plan.kind) != remote_digest:
            raise TransportError("UFM collection archive differs from remote digest")
        if expected_sha256 is not None:
            remaining = deadline - clock()
            if remaining <= 0:
                raise TransportError("exact UFM collection archive wait timed out")
            command_timeout = max(1, min(timeout, int(remaining)))
            if (_collection_remote_digest(jump, far, remote,
                                          timeout=command_timeout, runner=runner)
                    != expected_sha256):
                raise TransportError("remote UFM digest changed after exact copy")

        hidden = f".ufm-{secrets.token_hex(12)}.part"
        target_fd = os.open(hidden, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow,
                            0o600, dir_fd=parent_fd)
        source_fd: Optional[int] = None
        try:
            source_fd = os.open(staged, os.O_RDONLY | nofollow)
            while chunk := os.read(source_fd, 1024 * 1024):
                _write_all(target_fd, chunk)
            os.fsync(target_fd)
        finally:
            if source_fd is not None:
                os.close(source_fd)
            os.close(target_fd)
        os.fsync(parent_fd)
        _cleanup_private_dir(stage)
        stage = None
        if not _collection_parent_still_bound(parent, parent_fd):
            raise TransportError("collection destination parent was rebound")
        # The input/host-key/lease binding must still hold after a potentially
        # long remote copy, immediately before exposing the complete final name.
        _require_collection_binding(binding_check, jump, far, plan)
        try:
            os.link(hidden, destination.name, src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd, follow_symlinks=False)
        except FileExistsError:
            raise TransportError("collection destination appeared before publication") from None
        final_created = True
        published = os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
        final_inode = (published.st_dev, published.st_ino)
        os.fsync(parent_fd)
        os.unlink(hidden, dir_fd=parent_fd)
        hidden = None
        os.fsync(parent_fd)
        if not _collection_parent_still_bound(parent, parent_fd):
            raise TransportError("collection destination parent was rebound")
        completed = True
        return destination
    except (OSError, tarfile.TarError) as exc:
        raise TransportError("UFM collection archive retrieval failed") from None
    finally:
        cleanup_failure: Optional[BaseException] = None
        if final_created and not completed:
            try:
                current = os.stat(destination.name, dir_fd=parent_fd,
                                  follow_symlinks=False)
                if final_inode != (current.st_dev, current.st_ino):
                    raise TransportError("collection final changed before rollback")
                os.unlink(destination.name, dir_fd=parent_fd)
                os.fsync(parent_fd)
            except (OSError, TransportError) as exc:
                cleanup_failure = exc
        if hidden is not None:
            try:
                os.unlink(hidden, dir_fd=parent_fd)
                os.fsync(parent_fd)
            except OSError as exc:
                cleanup_failure = exc
        if stage is not None:
            try:
                _cleanup_private_dir(stage)
            except TransportError as exc:
                cleanup_failure = exc
        os.close(parent_fd)
        if cleanup_failure is not None:
            raise TransportError("UFM retrieval cleanup failed") from None


@dataclass(frozen=True)
class LogSource:
    endpoint: BoundFarEndpoint
    remote_path: str
    destination: Path
    provenance: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "remote_path",
            _remote_path(self.remote_path, label="log source"),
        )
        object.__setattr__(
            self,
            "destination",
            _absolute_local_path(self.destination, label="log destination"),
        )
        object.__setattr__(
            self,
            "provenance",
            _scalar(self.provenance, label="log provenance", pattern=_TOKEN_RE),
        )


@dataclass(frozen=True)
class RetrievalAttempt:
    endpoint: str
    provenance: str
    status: str
    detail: str


@dataclass(frozen=True)
class RetrievalOutcome:
    status: str
    attempts: tuple[RetrievalAttempt, ...]


class UfmOperationFailure(TransportError):
    def __init__(
        self,
        primary_failure: Optional[str],
        retrieval: RetrievalOutcome,
    ) -> None:
        self.primary_failure = primary_failure
        self.retrieval = retrieval
        primary = primary_failure or "none"
        attempts = "; ".join(
            f"{item.provenance}:{item.status}:{item.detail}"
            for item in retrieval.attempts
        ) or "none"
        super().__init__(
            f"UFM operation failed; primary={primary}; "
            f"retrieval={retrieval.status}; attempts={attempts}"
        )


class PrimaryFailureEvidence(TransportError):
    """A chainable primary cause without its untrusted exception value."""

    def __init__(self, exception_class: type[BaseException], detail: str) -> None:
        self.exception_class = exception_class
        self.detail = detail
        super().__init__(f"primary {exception_class.__name__}: {detail}")


T = TypeVar("T")


def run_with_mandatory_retrieval(
    action: Callable[[], T],
    sources: Sequence[LogSource],
    retrieve: Callable[[LogSource], None],
) -> T:
    """Run one action and attempt every safe log source on every exit path."""
    result: Optional[T] = None
    primary_failure: Optional[str] = None
    primary_cause: Optional[PrimaryFailureEvidence] = None
    try:
        result = action()
    except BaseException as exc:  # Retrieval is mandatory even on hard exits.
        primary_cause = PrimaryFailureEvidence(
            type(exc), redact_diagnostic(exc)
        )
        primary_failure = str(primary_cause)

    attempts: list[RetrievalAttempt] = []
    succeeded = 0
    failed = 0
    for source in sources:
        try:
            retrieve(source)
            succeeded += 1
            attempts.append(
                RetrievalAttempt(
                    endpoint=source.endpoint.host,
                    provenance=source.provenance,
                    status="retrieved",
                    detail="ok",
                )
            )
        except BaseException as exc:
            failed += 1
            attempts.append(
                RetrievalAttempt(
                    endpoint=source.endpoint.host,
                    provenance=source.provenance,
                    status="failed",
                    detail=redact_diagnostic(exc),
                )
            )

    if succeeded and not failed:
        status = "retrieved"
    elif succeeded:
        status = "log_retrieval_partial"
    else:
        status = "log_retrieval_unreachable"
    outcome = RetrievalOutcome(status=status, attempts=tuple(attempts))
    if primary_failure is not None or failed or not succeeded:
        failure = UfmOperationFailure(primary_failure, outcome)
        if primary_cause is not None:
            raise failure from primary_cause
        raise failure
    return result  # type: ignore[return-value]
