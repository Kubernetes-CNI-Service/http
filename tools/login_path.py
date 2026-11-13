"""Pure SSH host-key change facts; callers own transport and any later edits."""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from pathlib import Path
import re
import shlex
import stat
import subprocess
from typing import Callable, Optional, Protocol


@dataclass(frozen=True)
class HostKeyChange:
    address: str
    key_type: str
    new_fingerprint: str
    known_hosts_path: str
    lines: tuple[int, ...]
    location: str
    jump: Optional[str]


def _host_key_address(address: str) -> bool:
    try:
        ipaddress.IPv4Address(address)
        return True
    except ipaddress.AddressValueError:
        pass
    host, separator, interface = address.partition("%")
    if not separator or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", interface):
        return False
    try:
        return ipaddress.IPv6Address(host).is_link_local
    except ipaddress.AddressValueError:
        return False


def parse_host_key_change(output: str, *, location: str = "local",
                          jump: Optional[str] = None) -> Optional[HostKeyChange]:
    """Parse complete OpenSSH facts without retaining raw warnings or touching files."""
    fingerprint = re.search(
        r"The fingerprint for the ([A-Za-z0-9-]+) key sent by the remote host is\s+"
        r"(SHA256:[A-Za-z0-9+/]{43})(?:\.|\s|$)", output)
    offending = re.findall(r"(?m)^Offending \S+ key in (.+):(\d+)\r?$", output)
    if fingerprint is None or not offending:
        return None
    paths = {path.rstrip("\r") for path, _ in offending}
    if len(paths) != 1:
        return None
    address = None
    for line in output.splitlines():
        if "ssh-keygen" not in line:
            continue
        try:
            words = shlex.split(line)
        except ValueError:
            continue
        if "-R" in words and words.index("-R") + 1 < len(words):
            address = words[words.index("-R") + 1]
            break
    if address is None:
        match = re.search(r"(?m)^Host key for (\S+) has changed\b", output)
        if match is not None:
            address = match.group(1)
    if address is None or not _host_key_address(address):
        return None
    return HostKeyChange(address, fingerprint.group(1), fingerprint.group(2),
                         next(iter(paths)), tuple(int(line) for _, line in offending),
                         location, jump)


@dataclass(frozen=True)
class RemovalReceipt:
    lines: tuple[int, ...]
    old_file: bool
    inode_before: Optional[int]
    inode_after: Optional[int]
    mode_before: Optional[int]
    mode_after: Optional[int]


class KnownHostsEditor(Protocol):
    def fingerprints(self, address: str) -> list[tuple[int, str, str]]: ...
    def remove(self, address: str) -> RemovalReceipt: ...


def parse_known_host_fingerprints(output: str) -> list[tuple[int, str, str]]:
    """The same OpenSSH -l -F facts for local and transported read-only output."""
    if not output.strip():
        return []
    rows, line = [], None
    for text in output.splitlines():
        found = re.search(r"^# Host .* found: line ([0-9]+)\s*$", text)
        if found:
            line = int(found.group(1))
            continue
        fingerprint = re.fullmatch(r"\S+\s+(\S+)\s+(SHA256:[A-Za-z0-9+/]{43})\s*", text)
        if fingerprint is not None and line is not None:
            rows.append((line, fingerprint.group(1), fingerprint.group(2)))
            line = None
    if not rows or line is not None:
        raise ValueError("host-key fingerprint output is unverified")
    return rows


class LocalKnownHostsEditor:
    """Only the caller's own known_hosts; OpenSSH owns matching and removal."""

    def __init__(self, path: Path, *, home: Path):
        path, home = Path(path), Path(home)
        if path.is_symlink() or path.resolve() != (home / ".ssh" / "known_hosts").resolve():
            raise ValueError("host-key file is not the operator's known_hosts")
        self.path = path.resolve()

    def fingerprints(self, address: str) -> list[tuple[int, str, str]]:
        if not _host_key_address(address):
            raise ValueError("invalid host-key address")
        result = subprocess.run(["ssh-keygen", "-l", "-F", address, "-f", str(self.path)],
                                capture_output=True, text=True, timeout=15, check=False)
        if result.returncode == 1 and not result.stdout.strip():
            return []  # OpenSSH's no-match result, not a failed removal.
        if result.returncode != 0:
            raise ValueError("host-key fingerprint lookup failed")
        if not result.stdout.strip():
            raise ValueError("host-key fingerprint output is unverified")
        return parse_known_host_fingerprints(result.stdout)

    def remove(self, address: str) -> RemovalReceipt:
        rows = self.fingerprints(address)
        before = self.path.stat()
        result = subprocess.run(["ssh-keygen", "-f", str(self.path), "-R", address],
                                capture_output=True, text=True, timeout=15, check=False)
        if result.returncode != 0:
            raise ValueError("host-key remove failed")
        after = self.path.stat()
        return RemovalReceipt(tuple(row[0] for row in rows), self.path.with_name(self.path.name + ".old").is_file(),
                              before.st_ino, after.st_ino, stat.S_IMODE(before.st_mode), stat.S_IMODE(after.st_mode))


@dataclass(frozen=True)
class HostKeyRefreshRecord:
    location: str
    jump: Optional[str]
    known_hosts_path: str
    lines: tuple[int, ...]
    address: str
    key_type: str
    old_fingerprints: tuple[str, ...]
    new_fingerprint: str
    verification: str
    result: str
    removal: Optional[RemovalReceipt]


def refresh_target_host_key(change: HostKeyChange, editor: KnownHostsEditor, *,
                            read_device_fingerprint: Optional[Callable[[str], Optional[str]]],
                            retry: Callable[[], object], operator_forced: bool,
                            before_remove: Optional[Callable[[], object]] = None) -> HostKeyRefreshRecord:
    """Verify, remove one address, retry once, and verify the accepted replacement."""
    expected = change.new_fingerprint
    if not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", expected):
        raise ValueError("invalid host-key fingerprint")
    if not operator_forced:
        try:
            verified = read_device_fingerprint(change.key_type) if read_device_fingerprint is not None else None
        except OSError:
            raise ValueError("host-key fingerprint cannot be read; use --refresh-host-key") from None
        if verified is None:
            raise ValueError("host-key fingerprint cannot be verified; use --refresh-host-key")
        if verified != expected:
            raise ValueError("host-key fingerprint differs from the authenticated device")
    previous = editor.fingerprints(change.address)
    if not set(change.lines).issubset({row[0] for row in previous}):
        raise ValueError("Offending host-key lines differ from lookup")
    if before_remove is not None:
        before_remove()  # Caller owns permission; the library owns no device/credential authority.
    removal = editor.remove(change.address)
    if editor.fingerprints(change.address):
        raise ValueError("host-key entries remain after removal")
    retry()
    current = editor.fingerprints(change.address)
    if not current or any(row[2] != expected for row in current):
        raise ValueError("post-retry host-key fingerprint differs")
    return HostKeyRefreshRecord(change.location, change.jump, change.known_hosts_path, removal.lines,
                                change.address, change.key_type, tuple(row[2] for row in previous), expected,
                                "operator-forced-unverified" if operator_forced else "verified",
                                "refreshed", removal)
