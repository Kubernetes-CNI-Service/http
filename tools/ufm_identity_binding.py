#!/usr/bin/env python3
"""Read-only D-64/D-68 management identity verification for a UFM node.

The owner-supplied known_hosts digest is an external trust anchor. DHCP leases
are discovery authority, not SSH authentication. Licence MAC membership is a
separate later check and is never inferred here.
"""

from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
from typing import Callable, Sequence

from infra.ufm_jump_transport import (
    BoundFarEndpoint, CommandResult, JumpEndpoint, TransportError,
    _default_runner, _run, jump_transit, retrieve_collection_archive,
)
from ztp.dhcp_runtime_inventory import bind_ufm_current_leases
from tools.project_contract import safe_load_global_yaml
from tools.ufm_input_contract import (
    UfmInputError, bind_ufm_inventory_text, parse_ufm_servers,
)


class IdentityBindingError(ValueError):
    """No remote mutation may follow an unbound management identity."""


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_INTERFACE = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}\Z")
_MAC = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\Z")
_MAX_LEASE_BYTES = 32 * 1024 * 1024
_MAX_KNOWN_BYTES = 256 * 1024
_MAX_REMOTE_BYTES = 16 * 1024
_MAX_PROJECT_SOURCE_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class VerifiedManagementIdentity:
    hostname: str
    address: str
    management_mac: str
    lease_ends: dt.datetime
    observed_at: dt.datetime
    known_hosts_sha256: str
    lease_sha256: str
    interface: str
    license_mac_verified: bool = False


def _read_regular_no_follow(path: Path, *, limit: int, private: bool) -> bytes:
    """Read via held directory descriptors; never resolve a symlink ancestor."""
    if not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts:
        raise IdentityBindingError("identity source must be a canonical absolute path")
    directory_flag = getattr(os, "O_DIRECTORY", None)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if (type(directory_flag) is not int or not directory_flag
            or type(nofollow) is not int or not nofollow):
        raise IdentityBindingError("platform cannot enforce no-follow identity reads")
    fds: list[int] = []
    try:
        parent = os.open("/", os.O_RDONLY | directory_flag)
        fds.append(parent)
        for part in path.parts[1:-1]:
            if part in ("", ".", ".."):
                raise IdentityBindingError("identity source has a noncanonical ancestor")
            parent = os.open(part, os.O_RDONLY | directory_flag | nofollow,
                             dir_fd=parent)
            fds.append(parent)
        fd = os.open(path.name, os.O_RDONLY | nofollow, dir_fd=parent)
        fds.append(fd)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise IdentityBindingError("identity source is not a bounded regular file")
        if before.st_uid not in {0, os.geteuid()} or before.st_mode & 0o022:
            raise IdentityBindingError("identity source has unsafe ownership or write mode")
        if private and before.st_mode & 0o077:
            raise IdentityBindingError("pinned known_hosts must be private")
        blocks = bytearray()
        while chunk := os.read(fd, min(1024 * 1024, limit + 1 - len(blocks))):
            blocks.extend(chunk)
            if len(blocks) > limit:
                raise IdentityBindingError("identity source exceeds its size bound")
        after = os.fstat(fd)
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            raise IdentityBindingError("identity source changed during read")
        return bytes(blocks)
    except OSError:
        raise IdentityBindingError("identity source is unavailable or symlinked") from None
    finally:
        for fd in reversed(fds):
            os.close(fd)


def _pinned_hosts(data: bytes, jump_host: str, far_host: str) -> None:
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeDecodeError:
        raise IdentityBindingError("pinned known_hosts has non-ASCII content") from None
    required = {jump_host, far_host}
    found: set[str] = set()
    for line in lines:
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 3 or parts[0].startswith("@"):
            continue
        if parts[1] not in {"ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384"}:
            continue
        for entry in parts[0].split(","):
            if entry in required:
                found.add(entry)
    if found != required:
        raise IdentityBindingError("pinned known_hosts lacks an exact endpoint entry")


def _remote_result(runner: Callable[[list[str]], CommandResult], command: list[str],
                   timeout: int) -> str:
    try:
        result = _run(runner, command, timeout=timeout)
    except Exception:
        raise IdentityBindingError("authenticated remote identity observation failed") from None
    if (type(result) is not CommandResult or result.returncode != 0
            or type(result.stdout) is not str or len(result.stdout) > _MAX_REMOTE_BYTES):
        raise IdentityBindingError("authenticated remote identity observation failed")
    return result.stdout


def _one_interface(raw: str, name: str) -> dict:
    try:
        value = json.loads(raw)
    except (ValueError, TypeError):
        raise IdentityBindingError("remote interface observation is invalid") from None
    if type(value) is not list or len(value) != 1 or type(value[0]) is not dict:
        raise IdentityBindingError("remote interface observation is ambiguous")
    interface = value[0]
    if interface.get("ifname") != name:
        raise IdentityBindingError("remote interface is not the declared alias target")
    return interface


def verify_management_identity(
    nodes: Sequence[object], lease_path: Path, jump: JumpEndpoint,
    far: BoundFarEndpoint, management_interface: str,
    expected_known_hosts_sha256: str, *, now: dt.datetime | None = None,
    runner: Callable[[list[str]], CommandResult] = _default_runner, timeout: int,
) -> VerifiedManagementIdentity:
    """Bind independent CSV+current lease intent to pinned-key SSH observations.

    `expected_known_hosts_sha256` must be obtained and approved out of band;
    deriving it from the file being checked would nullify the trust boundary.
    This function is a local contract; synthetic runners are not real evidence.
    """
    current = now or dt.datetime.now(dt.timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise IdentityBindingError("identity observation requires an aware clock")
    if (type(expected_known_hosts_sha256) is not str
            or not _DIGEST.fullmatch(expected_known_hosts_sha256)):
        raise IdentityBindingError("external known_hosts pin is missing")
    if type(management_interface) is not str or not _INTERFACE.fullmatch(management_interface):
        raise IdentityBindingError("management interface alias is invalid")
    if (not isinstance(jump, JumpEndpoint) or not isinstance(far, BoundFarEndpoint)
            or far.jump != jump):
        raise IdentityBindingError("jump and far endpoint are not bound")
    try:
        far_ip = str(ipaddress.IPv4Address(far.host))
    except ValueError:
        raise IdentityBindingError("UFM far endpoint must be a current IPv4 lease") from None
    lease_bytes = _read_regular_no_follow(Path(lease_path), limit=_MAX_LEASE_BYTES,
                                          private=False)
    try:
        bound = bind_ufm_current_leases(nodes, lease_bytes.decode("utf-8"), now=current)
    except (UnicodeError, ValueError):
        raise IdentityBindingError("current UFM lease does not bind declared nodes") from None
    selected = [item for item in bound if item.address == far_ip]
    if len(selected) != 1:
        raise IdentityBindingError("far endpoint is not a current UFM lease")
    known_bytes = _read_regular_no_follow(jump.known_hosts, limit=_MAX_KNOWN_BYTES,
                                          private=True)
    if hashlib.sha256(known_bytes).hexdigest() != expected_known_hosts_sha256:
        raise IdentityBindingError("known_hosts differs from the external pin")
    _pinned_hosts(known_bytes, jump.host, far.host)
    try:
        host_raw = _remote_result(runner, jump_transit(
            jump, far, ["hostname"], timeout=timeout), timeout)
    except TransportError:
        raise IdentityBindingError("pinned SSH identity observation failed") from None
    node = selected[0]
    if host_raw.strip().casefold() != node.hostname.casefold() or "\n" in host_raw.strip():
        raise IdentityBindingError("authenticated SSH hostname differs from declaration")
    try:
        link_raw = _remote_result(runner, jump_transit(
            jump, far, ["ip", "-j", "link", "show", "dev", management_interface],
            timeout=timeout), timeout)
    except TransportError:
        raise IdentityBindingError("pinned SSH interface observation failed") from None
    link = _one_interface(link_raw, management_interface)
    mac = link.get("address")
    if type(mac) is not str or not _MAC.fullmatch(mac.casefold()):
        raise IdentityBindingError("authenticated management MAC is invalid")
    if mac.casefold() != node.management_mac.casefold().replace("-", ":"):
        raise IdentityBindingError("authenticated management MAC differs from lease and CSV")
    try:
        address_raw = _remote_result(runner, jump_transit(
            jump, far, ["ip", "-j", "address", "show", "dev", management_interface],
            timeout=timeout), timeout)
    except TransportError:
        raise IdentityBindingError("pinned SSH address observation failed") from None
    address = _one_interface(address_raw, management_interface)
    info = address.get("addr_info")
    if type(info) is not list:
        raise IdentityBindingError("authenticated management address is absent")
    ipv4 = [entry.get("local") for entry in info
            if type(entry) is dict and entry.get("family") == "inet"]
    if ipv4 != [node.address]:
        raise IdentityBindingError("authenticated management address differs from lease")
    return VerifiedManagementIdentity(
        hostname=node.hostname, address=node.address,
        management_mac=node.management_mac, lease_ends=node.lease_ends,
        observed_at=current,
        known_hosts_sha256=expected_known_hosts_sha256,
        lease_sha256=hashlib.sha256(lease_bytes).hexdigest(),
        interface=management_interface,
    )


def _project_inputs(project: Path) -> tuple[tuple[object, ...], str,
                                             tuple[tuple[Path, str], ...]]:
    """Parse exact no-follow global/CSV snapshots, not caller-constructed nodes."""
    project = Path(project)
    if not project.is_absolute():
        raise IdentityBindingError("UFM project path must be absolute")
    source_paths = (project / "01-global.yaml", project / "02-devices_config.csv")
    raw = tuple(_read_regular_no_follow(path, limit=_MAX_PROJECT_SOURCE_BYTES,
                                         private=False) for path in source_paths)
    try:
        document = safe_load_global_yaml(io.StringIO(raw[0].decode("utf-8")))
        nodes = bind_ufm_inventory_text(document, raw[1].decode("utf-8-sig"))
        policy = parse_ufm_servers(document).get("ufm")
        if not nodes or policy is None:
            raise UfmInputError("UFM project has no declared nodes")
        management_interface = policy["interfaces"]["alias"]["eth0"]
    except Exception:
        # YAML parser diagnostics can echo customer input. This public boundary
        # reports the rejection without carrying that untrusted text forward.
        raise IdentityBindingError("UFM project input is not a valid bound snapshot") from None
    sources = tuple((path, hashlib.sha256(data).hexdigest())
                    for path, data in zip(source_paths, raw))
    return tuple(nodes), management_interface, sources


def verify_project_management_identity(
    project: Path, lease_path: Path, jump: JumpEndpoint, far: BoundFarEndpoint,
    expected_known_hosts_sha256: str, *, timeout: int,
    now: dt.datetime | None = None,
    runner: Callable[[list[str]], CommandResult] = _default_runner,
) -> VerifiedManagementIdentity:
    """Read actual project intent and current lease before pinned SSH checks."""
    nodes, interface, sources = _project_inputs(project)
    identity = verify_management_identity(
        nodes, lease_path, jump, far, interface, expected_known_hosts_sha256,
        timeout=timeout, now=now, runner=runner,
    )
    if not _project_sources_still_bound(sources):
        raise IdentityBindingError("UFM project sources changed during identity check")
    return identity


def _project_sources_still_bound(sources: tuple[tuple[Path, str], ...]) -> bool:
    for path, digest in sources:
        raw = _read_regular_no_follow(path, limit=_MAX_PROJECT_SOURCE_BYTES,
                                      private=False)
        if hashlib.sha256(raw).hexdigest() != digest:
            return False
    return True


def retrieve_bound_collection_archive(
    nodes: Sequence[object], lease_path: Path, jump: JumpEndpoint,
    far: BoundFarEndpoint, management_interface: str,
    expected_known_hosts_sha256: str, plan: object, destination: Path, *,
    timeout: int, now: dt.datetime | None = None,
    expected_sha256: str | None = None,
    clock: Callable[[], dt.datetime] | None = None,
    runner: Callable[[list[str]], CommandResult] = _default_runner,
    _project_sources: tuple[tuple[Path, str], ...] = (),
) -> Path:
    """Formal collection caller: verify current identity before any archive I/O.

    Unlike the lower-level transport primitive, this entry has no permissive
    callback input. `now` can seed a deterministic identity test, but every
    pre-copy/pre-publication lease check uses a fresh clock observation. Real
    use still requires an independently approved host-key pin and an authorized
    real-environment card; synthetic tests are not that.
    """
    if (expected_sha256 is not None
            and (type(expected_sha256) is not str
                 or _DIGEST.fullmatch(expected_sha256) is None)):
        raise IdentityBindingError("approved UFM producer digest is invalid")
    identity = verify_management_identity(
        nodes, lease_path, jump, far, management_interface,
        expected_known_hosts_sha256, now=now, runner=runner, timeout=timeout,
    )
    last_checked = identity.observed_at

    def checked_binding(check_jump: JumpEndpoint, check_far: BoundFarEndpoint,
                        check_plan: object) -> bool:
        nonlocal last_checked
        if (check_jump != jump or check_far != far or check_plan != plan
                or identity.address != far.host):
            return False
        current = clock() if clock is not None else dt.datetime.now(dt.timezone.utc)
        if (type(current) is not dt.datetime or current.tzinfo is None
                or current.utcoffset() is None or current < last_checked
                or current >= identity.lease_ends):
            return False
        last_checked = current
        lease_bytes = _read_regular_no_follow(Path(lease_path),
                                              limit=_MAX_LEASE_BYTES, private=False)
        known_bytes = _read_regular_no_follow(jump.known_hosts,
                                              limit=_MAX_KNOWN_BYTES, private=True)
        if (hashlib.sha256(lease_bytes).hexdigest() != identity.lease_sha256
                or hashlib.sha256(known_bytes).hexdigest() != identity.known_hosts_sha256
                or not _project_sources_still_bound(_project_sources)):
            return False
        if expected_sha256 is None:
            return True
        # A producer-pinned retrieval must reobserve the actual SSH node, not
        # merely reread a cached lease/key hash, immediately before exposure.
        fresh = verify_management_identity(
            nodes, lease_path, jump, far, management_interface,
            expected_known_hosts_sha256, now=current, runner=runner,
            timeout=timeout,
        )
        if ((fresh.hostname, fresh.address, fresh.management_mac,
             fresh.lease_ends, fresh.known_hosts_sha256, fresh.lease_sha256,
             fresh.interface, fresh.license_mac_verified)
                != (identity.hostname, identity.address, identity.management_mac,
                    identity.lease_ends, identity.known_hosts_sha256,
                    identity.lease_sha256, identity.interface,
                    identity.license_mac_verified)):
            return False
        current_after = clock() if clock is not None else dt.datetime.now(dt.timezone.utc)
        if (type(current_after) is not dt.datetime or current_after.tzinfo is None
                or current_after.utcoffset() is None or current_after < current
                or current_after >= identity.lease_ends):
            return False
        last_checked = current_after
        lease_after = _read_regular_no_follow(Path(lease_path),
                                              limit=_MAX_LEASE_BYTES, private=False)
        known_after = _read_regular_no_follow(jump.known_hosts,
                                              limit=_MAX_KNOWN_BYTES, private=True)
        return (hashlib.sha256(lease_after).hexdigest() == identity.lease_sha256
                and hashlib.sha256(known_after).hexdigest() == identity.known_hosts_sha256
                and _project_sources_still_bound(_project_sources))

    return retrieve_collection_archive(
        jump, far, plan, destination, timeout=timeout,
        binding_check=checked_binding, expected_sha256=expected_sha256,
        runner=runner,
    )


def retrieve_project_collection_archive(
    project: Path, lease_path: Path, jump: JumpEndpoint, far: BoundFarEndpoint,
    expected_known_hosts_sha256: str, plan: object, destination: Path, *,
    timeout: int, now: dt.datetime | None = None,
    expected_sha256: str | None = None,
    clock: Callable[[], dt.datetime] | None = None,
    runner: Callable[[list[str]], CommandResult] = _default_runner,
) -> Path:
    """Project-backed formal caller; never accepts a raw permissive callback."""
    nodes, interface, sources = _project_inputs(project)
    return retrieve_bound_collection_archive(
        nodes, lease_path, jump, far, interface, expected_known_hosts_sha256,
        plan, destination, timeout=timeout, now=now, runner=runner,
        clock=clock, expected_sha256=expected_sha256,
        _project_sources=sources,
    )
