#!/usr/bin/env python3
"""Inactive, pinned UFM agent invocation and remote-final observation.

The caller owns every scope and approved installation digest. This module does
not install an agent, register a worker, retrieve an archive, or claim a
completed collection cycle. No real endpoint is configured by default.
"""

from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Callable

from infra.ufm_jump_transport import (
    BoundFarEndpoint, CommandResult, JumpEndpoint, _open_collection_parent_no_follow,
    _run, jump_transit,
)
from tools.ufm_collection_contract import (
    CollectionPlan, _open_held_leaf, _still_bound, _validated_plan,
)
from tools.ufm_identity_binding import (
    VerifiedManagementIdentity, retrieve_project_collection_archive,
    verify_project_management_identity,
)


class RemoteProducerError(ValueError):
    """The exact remote source or collection observation was not proved."""


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_PART = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]*\Z")


@dataclass(frozen=True)
class RemoteAgentInstall:
    """Explicit server-owned install intent; never inferred from remote data."""

    root: str
    python_path: str
    agent_sha256: str
    contract_sha256: str
    python_sha256: str

    @property
    def agent_path(self) -> str:
        return f"{self.root}/tools/ufm_collection_agent.py"

    @property
    def contract_path(self) -> str:
        return f"{self.root}/tools/ufm_collection_contract.py"


@dataclass(frozen=True)
class RemoteCollectionObservation:
    node: str
    run_id: str
    kind: str
    archive_path: str
    remote_sha256: str
    state: str = "remote-final-observed"


@dataclass(frozen=True)
class VerifiedRetrievedObservation:
    """Exact local bytes plus current node binding; not cycle completion."""

    remote: RemoteCollectionObservation
    local_path: Path
    local_sha256: str
    remote_sha256_before: str
    remote_sha256_after: str
    identity_before_sha256: str
    identity_after_sha256: str
    state: str = "verified-retrieved"


def _path(value: object) -> bool:
    return (type(value) is str and value.startswith("/")
            and value != "/" and not value.endswith("/")
            and all(part not in (".", "..") and _PART.fullmatch(part)
                    for part in value[1:].split("/")))


def _install(install: object) -> RemoteAgentInstall:
    if (type(install) is not RemoteAgentInstall
            or not _path(install.root) or not _path(install.python_path)
            or type(install.agent_sha256) is not str
            or _DIGEST.fullmatch(install.agent_sha256) is None
            or type(install.contract_sha256) is not str
            or _DIGEST.fullmatch(install.contract_sha256) is None
            or type(install.python_sha256) is not str
            or _DIGEST.fullmatch(install.python_sha256) is None):
        raise RemoteProducerError("approved remote UFM agent installation is missing")
    return install


def _now(clock: Callable[[], dt.datetime], previous: dt.datetime | None) -> dt.datetime:
    try:
        current = clock()
    except Exception:
        raise RemoteProducerError("remote UFM clock is unavailable") from None
    if (type(current) is not dt.datetime or current.tzinfo is None
            or current.utcoffset() is None
            or (previous is not None and current < previous)):
        raise RemoteProducerError("remote UFM clock is stale or invalid")
    return current


def _identity_key(identity: VerifiedManagementIdentity) -> tuple:
    return (identity.hostname, identity.address, identity.management_mac,
            identity.lease_ends, identity.known_hosts_sha256,
            identity.lease_sha256, identity.interface,
            identity.license_mac_verified)


def _identity_digest(identity: VerifiedManagementIdentity) -> str:
    """Digest verified stable identity fields, not mutable observation time."""
    stable = {
        "hostname": identity.hostname,
        "address": identity.address,
        "management_mac": identity.management_mac,
        "lease_ends": identity.lease_ends.isoformat(),
        "known_hosts_sha256": identity.known_hosts_sha256,
        "lease_sha256": identity.lease_sha256,
        "interface": identity.interface,
        "license_mac_verified": identity.license_mac_verified,
    }
    return hashlib.sha256(json.dumps(
        stable, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")).hexdigest()


def _destination_preflight(destination: object, plan: CollectionPlan) -> Path:
    if (not isinstance(destination, Path) or not destination.is_absolute()
            or ".." in destination.parts or destination.name != plan.archive_name):
        raise RemoteProducerError("UFM retrieval destination is not the exact archive name")
    directory_flag = getattr(os, "O_DIRECTORY", None)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if (type(directory_flag) is not int or not directory_flag
            or type(nofollow) is not int or not nofollow):
        raise RemoteProducerError("UFM retrieval destination lacks no-follow support")
    try:
        parent_fd = _open_collection_parent_no_follow(
            destination.parent, directory_flag, nofollow)
        try:
            try:
                os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise RemoteProducerError("UFM retrieval destination already exists")
        finally:
            os.close(parent_fd)
    except OSError:
        raise RemoteProducerError("UFM retrieval destination is unavailable") from None
    return destination


def _local_bound_digest(path: Path) -> str:
    """Hash the published file through no-follow descriptors, not a path reopen."""
    fd = _open_held_leaf(path, os.O_RDONLY)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_size <= 0
                or before.st_size > 512 * 1024 * 1024):
            raise RemoteProducerError("retrieved UFM archive is not bounded regular data")
        digest = hashlib.sha256()
        size = 0
        while chunk := os.read(fd, 1024 * 1024):
            size += len(chunk)
            if size > 512 * 1024 * 1024:
                raise RemoteProducerError("retrieved UFM archive exceeds the byte bound")
            digest.update(chunk)
        after = os.fstat(fd)
        if (size != before.st_size
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or not _still_bound(path, after)):
            raise RemoteProducerError("retrieved UFM archive changed during verification")
        return digest.hexdigest()
    finally:
        os.close(fd)


def _remote(jump: JumpEndpoint, far: BoundFarEndpoint, argv: list[str], *,
            runner: Callable[[list[str]], CommandResult], timeout: int) -> CommandResult:
    try:
        command = jump_transit(jump, far, argv, timeout=timeout)
        result = _run(runner, command, timeout=timeout)
    except Exception:
        raise RemoteProducerError("authenticated UFM remote command failed") from None
    if (type(result) is not CommandResult or type(result.returncode) is not int
            or type(result.stdout) is not str or type(result.stderr) is not str
            or len(result.stdout) > 4096 or len(result.stderr) > 4096):
        raise RemoteProducerError("authenticated UFM remote response is invalid")
    return result


def _source_status(install: RemoteAgentInstall,
                   jump: JumpEndpoint, far: BoundFarEndpoint, *,
                   runner: Callable[[list[str]], CommandResult], timeout: int) -> None:
    """Observe root-owned, non-group-writable path components and exact hashes.

    A protected, single-writer remote installation is a separate real-env
    precondition; these discrete observations do not defeat a root actor.
    """
    directories = []
    for origin in (install.root, install.python_path.rsplit("/", 1)[0]):
        parts = origin[1:].split("/")
        directories.extend("/" + "/".join(parts[:index])
                           for index in range(1, len(parts) + 1))
    directories.append(f"{install.root}/tools")
    files = (install.agent_path, install.contract_path, install.python_path)
    for path in (*dict.fromkeys(directories), *files):
        result = _remote(jump, far, ["stat", "-c", "%u:%a:%F", "--", path],
                         runner=runner, timeout=timeout)
        if result.returncode != 0 or result.stderr:
            raise RemoteProducerError("remote UFM agent source metadata is unavailable")
        match = re.fullmatch(r"0:([0-7]{3,4}):(directory|regular file)\n",
                             result.stdout)
        expected_kind = "regular file" if path in files else "directory"
        if (match is None or match.group(2) != expected_kind
                or int(match.group(1), 8) & 0o022):
            raise RemoteProducerError("remote UFM agent source has unsafe ownership or mode")
    for path, approved in ((install.python_path, install.python_sha256),
                           (install.agent_path, install.agent_sha256),
                           (install.contract_path, install.contract_sha256)):
        result = _remote(jump, far, ["sha256sum", "--", path],
                         runner=runner, timeout=timeout)
        if (result.returncode != 0 or result.stderr
                or result.stdout != f"{approved}  {path}\n"):
            raise RemoteProducerError("remote UFM agent source digest differs from approval")


def observe_remote_producer(
    plan: CollectionPlan, *, install: RemoteAgentInstall,
    project: Path, lease_path: Path, jump: JumpEndpoint, far: BoundFarEndpoint,
    known_hosts_pin: str, timeout: int,
    clock: Callable[[], dt.datetime],
    runner: Callable[[list[str]], CommandResult],
) -> RemoteCollectionObservation:
    """Invoke one explicitly pinned remote agent and observe its final name.

    This is *not* archive retrieval, a validated receipt, or a worker/REQ7
    same-cycle completion signal. Real activation requires the environment
    card's installation, credential, writer and cycle authority to be proved.
    """
    try:
        _validated_plan(plan)
    except Exception:
        raise RemoteProducerError("noncanonical UFM collection plan") from None
    approved = _install(install)
    if (plan.kind != "iblinkinfo" or not isinstance(project, Path)
            or not isinstance(lease_path, Path) or not project.is_absolute()
            or not lease_path.is_absolute() or ".." in project.parts
            or ".." in lease_path.parts or type(jump) is not JumpEndpoint
            or type(far) is not BoundFarEndpoint or far.jump != jump
            or type(known_hosts_pin) is not str
            or _DIGEST.fullmatch(known_hosts_pin) is None
            or type(timeout) is not int or not 1 <= timeout <= 300
            or not callable(clock) or not callable(runner)):
        raise RemoteProducerError("remote UFM producer scope is incomplete")

    prior_time: dt.datetime | None = None
    first_key: tuple | None = None

    def reverify() -> VerifiedManagementIdentity:
        nonlocal prior_time, first_key
        current = _now(clock, prior_time)
        prior_time = current
        try:
            identity = verify_project_management_identity(
                project, lease_path, jump, far, known_hosts_pin,
                timeout=timeout, now=current, runner=runner,
            )
        except Exception:
            raise RemoteProducerError("current UFM project/lease/SSH identity failed") from None
        if (type(identity) is not VerifiedManagementIdentity
                or identity.address != far.host
                or identity.observed_at > current or identity.lease_ends <= current
                or current - identity.observed_at > dt.timedelta(seconds=60)):
            raise RemoteProducerError("current UFM node identity is unavailable")
        key = _identity_key(identity)
        if first_key is None:
            first_key = key
        elif key != first_key:
            raise RemoteProducerError("UFM identity changed during remote production")
        return identity

    identity = reverify()
    _source_status(approved, jump, far, runner=runner, timeout=timeout)
    reverify()
    invocation = _remote(
        jump, far, [approved.python_path, "-I", "-S", "-B", approved.agent_path,
                    "--kind", plan.kind, "--run-id", plan.run_id],
        runner=runner, timeout=timeout,
    )
    if invocation.returncode != 0 or invocation.stdout or invocation.stderr:
        raise RemoteProducerError("remote UFM agent did not publish its final archive")
    reverify()
    # A source change detected after execution cannot become a success
    # observation. This is not an atomic defense against privileged rewrites
    # during execution; that remains a real-environment single-writer gate.
    _source_status(approved, jump, far, runner=runner, timeout=timeout)
    result = _remote(jump, far, ["sha256sum", "--", plan.ufm_remote_path],
                     runner=runner, timeout=timeout)
    match = re.fullmatch(r"([0-9a-f]{64})  " + re.escape(plan.ufm_remote_path)
                         + r"\n", result.stdout)
    if result.returncode != 0 or result.stderr or match is None:
        raise RemoteProducerError("remote UFM final archive has no exact digest")
    reverify()
    return RemoteCollectionObservation(
        node=identity.hostname, run_id=plan.run_id, kind=plan.kind,
        archive_path=plan.ufm_remote_path, remote_sha256=match.group(1),
    )


def observe_and_retrieve_remote_producer(
    plan: CollectionPlan, *, install: RemoteAgentInstall,
    project: Path, lease_path: Path, jump: JumpEndpoint, far: BoundFarEndpoint,
    known_hosts_pin: str, destination: Path, timeout: int,
    clock: Callable[[], dt.datetime],
    runner: Callable[[list[str]], CommandResult],
) -> VerifiedRetrievedObservation:
    """Observe an approved agent, then pin its SHA across formal retrieval.

    The returned object only proves a locally verified archive under the same
    observed project/lease/host-key identity. It is not a worker completion,
    analyzer receipt, panel publication, or REQ7 same-cycle artifact.
    """
    try:
        _validated_plan(plan)
    except Exception:
        raise RemoteProducerError("noncanonical UFM collection plan") from None
    _install(install)
    if (plan.kind != "iblinkinfo" or not callable(clock)
            or not callable(runner) or type(timeout) is not int
            or not 1 <= timeout <= 300):
        raise RemoteProducerError("UFM remote retrieval scope is incomplete")
    destination = _destination_preflight(destination, plan)

    previous: dt.datetime | None = None

    def fresh_clock() -> dt.datetime:
        nonlocal previous
        previous = _now(clock, previous)
        return previous

    try:
        initial = verify_project_management_identity(
            project, lease_path, jump, far, known_hosts_pin,
            timeout=timeout, now=fresh_clock(), runner=runner,
        )
        if type(initial) is not VerifiedManagementIdentity or initial.address != far.host:
            raise RemoteProducerError("initial UFM node identity is unavailable")
        remote = observe_remote_producer(
            plan, install=install, project=project, lease_path=lease_path,
            jump=jump, far=far, known_hosts_pin=known_hosts_pin,
            timeout=timeout, clock=fresh_clock, runner=runner,
        )
        if remote.node != initial.hostname:
            raise RemoteProducerError("UFM node changed before exact retrieval")
        retrieved = retrieve_project_collection_archive(
            project, lease_path, jump, far, known_hosts_pin,
            plan, destination, timeout=timeout, now=fresh_clock(),
            clock=fresh_clock, runner=runner,
            expected_sha256=remote.remote_sha256,
        )
        local_sha256 = _local_bound_digest(retrieved)
        if local_sha256 != remote.remote_sha256:
            raise RemoteProducerError("local UFM archive differs from producer observation")
        # A distinct post-copy remote observation is preserved for the worker's
        # durable completion attestation. The formal retrieval also checks its
        # own pre/post digests but does not expose those internal observations.
        after_result = _remote(
            jump, far, ["sha256sum", "--", plan.ufm_remote_path],
            runner=runner, timeout=timeout,
        )
        after_match = re.fullmatch(
            r"([0-9a-f]{64})  " + re.escape(plan.ufm_remote_path) + r"\n",
            after_result.stdout,
        )
        if (after_result.returncode != 0 or after_result.stderr
                or after_match is None
                or after_match.group(1) != remote.remote_sha256):
            raise RemoteProducerError("remote UFM archive changed after exact retrieval")
        final = verify_project_management_identity(
            project, lease_path, jump, far, known_hosts_pin,
            timeout=timeout, now=fresh_clock(), runner=runner,
        )
        if (type(final) is not VerifiedManagementIdentity
                or _identity_key(final) != _identity_key(initial)):
            raise RemoteProducerError("UFM node identity changed during exact retrieval")
        return VerifiedRetrievedObservation(
            remote=remote, local_path=retrieved, local_sha256=local_sha256,
            remote_sha256_before=remote.remote_sha256,
            remote_sha256_after=after_match.group(1),
            identity_before_sha256=_identity_digest(initial),
            identity_after_sha256=_identity_digest(final),
        )
    except RemoteProducerError:
        raise
    except Exception:
        raise RemoteProducerError("verified UFM archive retrieval is unavailable") from None


if __name__ == "__main__":
    raise SystemExit("UFM remote producer has no authorized runtime entrypoint")
