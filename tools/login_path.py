"""Pure SSH host-key change facts; callers own transport and any later edits."""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
from pathlib import Path
import re
import shlex
import stat
import subprocess
from typing import Callable, Optional, Protocol

from tools.device_identity import normalize_mac, eth1_follows_eth0
from tools.hostname_ranges import parse_selector, select, SelectorError


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


# I-037 / v315 WP1: transport-free shared facts. Callers own parsing inventory
# columns, P2P name resolution, local observations, reporting and all device I/O.
@dataclass(frozen=True)
class InputIssue:
    hostname: str
    field: str
    value: str
    problem: str
    blocking: bool


@dataclass(frozen=True)
class Eth0Plan:
    mac: str
    address: ipaddress.IPv4Interface
    gateway: str


@dataclass(frozen=True)
class Eth1Plan:
    mac: str
    address: Optional[ipaddress.IPv4Interface]
    gateway: str


@dataclass(frozen=True)
class JumpCandidate:
    address: str
    entry: str


@dataclass(frozen=True)
class Attachment:
    peer: str
    peer_type: str
    port: str


@dataclass(frozen=True)
class Route:
    hostname: str
    path: str
    reason: str
    jump: Optional[str]
    port: Optional[str]
    same_subnet: Optional[str]


@dataclass(frozen=True)
class LocalInterface:
    name: str
    ipv4: tuple[ipaddress.IPv4Interface, ...]
    link_local: bool


@dataclass(frozen=True)
class JumpTables:
    hostname: str
    links: str
    fdb: str
    vlans: str


@dataclass(frozen=True)
class CableCheck:
    hostname: str
    mac: str
    link_local: str
    expected: tuple[str, str]
    verdict: str
    actual: tuple[tuple[str, str], ...]
    extra_macs: tuple[str, ...]
    login_interface: Optional[str]
    after_ping: bool
    ping_ok: Optional[bool]


@dataclass(frozen=True)
class IdentityFacts:
    mac: str
    ipv4: tuple[ipaddress.IPv4Interface, ...]
    gateways: tuple[str, ...]


@dataclass(frozen=True)
class IdentityCheck:
    ok: bool
    mismatches: tuple[tuple[str, str, str], ...]


def is_jump_type(dev_type: str) -> bool:
    return dev_type.strip().casefold().endswith("jump")


def _present(value: str) -> bool:
    return value.strip().casefold() not in {"", "na", "n/a", "none", "null", "tbd", "-"}


def _input_address(hostname, address, netmask, prefix, blocking):
    if not _present(address):
        return None, [InputIssue(hostname, prefix + "_ip", address, "address is missing", blocking)]
    if "/" not in address:
        if not _present(netmask):
            return None, [InputIssue(hostname, "netmask", netmask, "netmask is missing", blocking)]
        try:
            ipaddress.IPv4Network("0.0.0.0/" + netmask)
        except ValueError:
            return None, [InputIssue(hostname, "netmask", netmask, "invalid netmask", blocking)]
    try:
        interface = ipaddress.IPv4Interface(address if "/" in address else address + "/" + netmask)
        if interface.network.prefixlen <= 30 and interface.ip in {
                interface.network.network_address, interface.network.broadcast_address}:
            raise ValueError("network/broadcast address")
    except ValueError:
        return None, [InputIssue(hostname, prefix + "_ip", address, "invalid host address", blocking)]
    return interface, []


def _input_gateway(hostname, gateway, address, prefix, blocking):
    if not _present(gateway):
        return "", [InputIssue(hostname, prefix + "_gw", gateway, "gateway is missing", blocking)]
    try:
        parsed = ipaddress.IPv4Address(gateway)
        if address is None or parsed not in address.network:
            raise ValueError("gateway is outside the address subnet")
        if address.network.prefixlen <= 30 and parsed in {
                address.network.network_address, address.network.broadcast_address}:
            raise ValueError("gateway is a network/broadcast address")
    except ValueError:
        return "", [InputIssue(hostname, prefix + "_gw", gateway, "invalid gateway for address subnet", blocking)]
    return str(parsed), []


def check_eth0_inputs(hostname, *, mac, address, netmask, gateway):
    issues = []
    try:
        normalized = normalize_mac(mac)
        if not normalized:
            raise ValueError("missing MAC")
    except ValueError:
        normalized = ""
        issues.append(InputIssue(hostname, "eth0_mac", mac, "MAC is missing or invalid", True))
    interface, address_issues = _input_address(hostname, address.strip(), netmask.strip(), "eth0", True)
    issues.extend(address_issues)
    gateway, gateway_issues = _input_gateway(hostname, gateway.strip(), interface, "eth0", True)
    issues.extend(gateway_issues)
    return (None if issues else Eth0Plan(normalized, interface, gateway)), tuple(issues)


def check_eth1_inputs(hostname, *, eth0_mac, mac, address, netmask, gateway):
    issues, normalized = [], ""
    try:
        normalized = normalize_mac(mac)
        follows = eth1_follows_eth0(eth0_mac, mac)
    except ValueError:
        follows = False
    if follows is not True and (_present(eth0_mac) or _present(mac)):
        issues.append(InputIssue(hostname, "eth1_mac", mac, "eth1_mac is not eth0_mac plus 1", False))
    interface = None
    if _present(address):
        interface, address_issues = _input_address(hostname, address.strip(), netmask.strip(), "eth1", False)
        issues.extend(address_issues)
    resolved_gateway = ""
    if _present(gateway) or interface is not None:
        resolved_gateway, gateway_issues = _input_gateway(hostname, gateway.strip(), interface, "eth1", False)
        issues.extend(gateway_issues)
    return Eth1Plan(normalized, interface, resolved_gateway), tuple(issues)


def jump_login_candidates(hostname, *, eth0_ip, vlan_groups):
    candidates, issues, seen = [], [], set()
    def candidate(value, mask, entry):
        try:
            parsed = (ipaddress.IPv4Interface(value if "/" in value else value + "/" + mask).ip
                      if "/" in value or _present(mask) else ipaddress.IPv4Address(value))
            if parsed.is_unspecified or parsed.is_loopback or parsed.is_multicast or str(parsed) == "255.255.255.255":
                raise ValueError("not a unicast login address")
            if ("/" in value or _present(mask)):
                address = ipaddress.IPv4Interface(value if "/" in value else value + "/" + mask)
                if address.network.prefixlen <= 30 and parsed in {
                        address.network.network_address, address.network.broadcast_address}:
                    raise ValueError("network/broadcast login address")
        except ValueError:
            issues.append(InputIssue(hostname, entry, value, "invalid login candidate", False))
            return
        text = str(parsed)
        if text not in seen:
            candidates.append(JumpCandidate(text, entry))
            seen.add(text)
    if _present(eth0_ip):
        candidate(eth0_ip.strip(), "", "JUMP_ETH0")
    for vlan, value, mask in vlan_groups:
        if not _present(value):
            continue
        if not re.fullmatch(r"[1-9][0-9]{0,3}", vlan.strip()) or not 1 <= int(vlan) <= 4094:
            issues.append(InputIssue(hostname, "vlan_id", vlan, "invalid login VLAN", False))
            continue
        candidate(value.strip(), mask.strip(), "JUMP_VLAN" + str(int(vlan)))
    if not candidates and not issues:
        issues.append(InputIssue(hostname, "login_address", "", "no login candidate", False))
    return tuple(candidates), tuple(issues)


def select_direct_access(text, hostnames):
    return frozenset(select(parse_selector(text, option="--direct-access", allow_all=True), hostnames))


def classify(devices, attachments, *, direct, same_subnet):
    rows = []
    for device in devices:
        name = device.hostname
        attachment = attachments.get(name)
        if name in direct:
            reason = "DIRECT_ACCESS"
        elif attachment is None:
            reason = "NO_MGMT_LINK"
        elif not is_jump_type(attachment.peer_type):
            reason = "PEER_NOT_JUMP"
        else:
            rows.append(Route(name, "jump", "JUMP_LINK", attachment.peer, attachment.port, None))
            continue
        rows.append(Route(name, "direct", reason, None, None, same_subnet.get(name)))
    return rows


def parse_local_interfaces(ip_json_text):
    rows = []
    for interface in json.loads(ip_json_text):
        addresses, ipv6 = [], False
        for fact in interface.get("addr_info", ()):
            if fact.get("family") == "inet":
                addresses.append(ipaddress.IPv4Interface(str(fact["local"]) + "/" + str(fact["prefixlen"])))
            elif fact.get("family") == "inet6" and ipaddress.IPv6Address(fact["local"]).is_link_local:
                ipv6 = True
        rows.append(LocalInterface(interface["ifname"], tuple(addresses), ipv6))
    return tuple(rows)


def same_subnet_interface(planned, local):
    planned = ipaddress.IPv4Interface(planned)
    for interface in local:
        if interface.link_local and any(address.ip in planned.network for address in interface.ipv4):
            return interface.name
    return None


def link_local_from_mac(mac):
    normalized = normalize_mac(mac)
    number = int(normalized.replace(":", ""), 16) if normalized else 0
    if not number or number & (1 << 40):
        raise ValueError("link-local requires a nonzero unicast MAC")
    raw = bytearray.fromhex(normalized.replace(":", ""))
    raw[0] ^= 2
    iid = int.from_bytes(raw[:3] + b"\xff\xfe" + raw[3:], "big")
    return str(ipaddress.IPv6Address((0xfe80 << 112) | iid))


def _route_links(text):
    blocks, current = {}, None
    for line in text.splitlines():
        start = re.match(r"^\d+:\s+([^:]+):", line)
        if start:
            full = start.group(1)
            current = full.split("@", 1)[0]
            blocks[current] = {"parent": full.split("@", 1)[1] if "@" in full else "", "lines": []}
        if current is not None:
            blocks[current]["lines"].append(line)
    for row in blocks.values():
        row["text"] = "\n".join(row["lines"])
        master = re.search(r"\bmaster\s+(\S+)", row["text"])
        row["master"] = master.group(1) if master else ""
    return blocks


def _login_interface_facts(links, vlans, port):
    blocks = _route_links(links)
    if port not in blocks:
        raise ValueError("expected port not found")
    selected = port
    master = blocks[selected]["master"]
    if master.startswith("bond"):
        selected, master = master, blocks.get(master, {}).get("master", "")
    if not master:
        return "", "", (port,)
    memberships, current = set(), ""
    for line in vlans.splitlines():
        words = line.split()
        if not words or words[0] == "port":
            continue
        if not line[0].isspace():
            current, words = words[0], words[1:]
        if current in {port, selected} and words:
            if not words[0].isdigit():
                raise ValueError("ambiguous port VLAN")
            memberships.add(int(words[0]))
    if len(memberships) != 1:
        raise ValueError("expected one login VLAN")
    vlan = next(iter(memberships))
    candidates = [name for name, row in blocks.items()
                  if row["parent"] == master and not name.endswith("-v0")
                  and re.search(r"\bvlan\s+(?:protocol\s+802\.1Q\s+)?id\s+" + str(vlan) + r"\b", row["text"])]
    return master, str(vlan), tuple(candidates)


def login_interface(links, vlans, port):
    _, _, candidates = _login_interface_facts(links, vlans, port)
    if len(candidates) != 1:
        raise ValueError("login VLAN has no unique real SVI")
    return candidates[0]


def check_cable(hostname, mac, expected, tables, *, cascade_ports, after_ping=False, ping_ok=None):
    mac = normalize_mac(mac)
    link_local = link_local_from_mac(mac)
    actual, extra, interface, expected_fdb_port = [], set(), None, expected[1]
    for table in tables:
        blocks = _route_links(table.links)
        cascades = {port for host, port in cascade_ports if host == table.hostname}
        cascades.update(blocks[port]["master"] for port in tuple(cascades)
                        if port in blocks and blocks[port]["master"].startswith("bond"))
        if table.hostname == expected[0]:
            master = blocks.get(expected[1], {}).get("master", "")
            if master.startswith("bond"):
                expected_fdb_port = master
            _, _, candidates = _login_interface_facts(table.links, table.vlans, expected[1])
            if len(candidates) > 1:
                raise ValueError("login VLAN has no unique real SVI")
            interface = candidates[0] if candidates else None
        for line in table.fdb.splitlines():
            words = line.split()
            if not words or "dev" not in words or any(word in words for word in ("permanent", "static", "self")):
                continue
            port = words[words.index("dev") + 1]
            if port in cascades:
                continue
            observed = normalize_mac(words[0])
            if observed == mac:
                location = (table.hostname, port)
                if location not in actual:
                    actual.append(location)
            elif table.hostname == expected[0] and port == expected_fdb_port:
                extra.add(observed)
    verdict = ("MATCH" if (expected[0], expected_fdb_port) in actual
               else "ELSEWHERE" if actual else "NOT_LEARNED")
    return CableCheck(hostname, mac, link_local, expected, verdict, tuple(actual), tuple(sorted(extra)),
                      interface, after_ping, ping_ok)


def ping_argv(vrf, link_local, interface):
    if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", vrf)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", interface)
            or not ipaddress.IPv6Address(link_local).is_link_local):
        raise ValueError("invalid scoped ping endpoint")
    return ["ip", "vrf", "exec", vrf, "ping", "-6", "-c", "2", "-W", "1", link_local + "%" + interface]


def ping_plan(checks):
    groups = {}
    for check in checks:
        if check.verdict == "NOT_LEARNED" and not check.after_ping:
            groups.setdefault(check.expected[0], []).append(check)
    return groups


def parse_ip_addr(text, ifname="eth0"):
    blocks = _route_links(text)
    block = blocks.get(ifname, {}).get("text", "")
    mac = re.search(r"\blink/ether\s+(\S+)", block)
    ipv4 = tuple(ipaddress.IPv4Interface(value) for value in re.findall(r"\binet\s+(\S+)", block))
    return IdentityFacts(normalize_mac(mac.group(1)) if mac else "", ipv4, ())


def parse_default_routes(text):
    return tuple(dict.fromkeys(str(ipaddress.IPv4Address(match.group(1)))
                 for match in re.finditer(r"(?m)^default\s+via\s+(\S+)", text)))


def neighbor_mac(ip_neigh_text, address):
    for line in ip_neigh_text.splitlines():
        words = line.split()
        if words and words[0] == address and "lladdr" in words:
            return normalize_mac(words[words.index("lladdr") + 1])
    return None


def check_identity(expected_mac, observed, *, via_ipv4, expected_ipv4=None, expected_gateway=None):
    expected, actual = normalize_mac(expected_mac), normalize_mac(observed.mac)
    mismatches = []
    if not expected or not actual or expected != actual:
        mismatches.append(("mac", expected, actual))
    if via_ipv4:
        ipv4 = ipaddress.IPv4Interface(expected_ipv4)
        if ipv4 not in observed.ipv4:
            mismatches.append(("ipv4", str(ipv4), ",".join(map(str, observed.ipv4))))
        if any(gateway != expected_gateway for gateway in observed.gateways):
            mismatches.append(("gateway", expected_gateway or "", ",".join(observed.gateways)))
    return IdentityCheck(not mismatches, tuple(mismatches))


def credential_order(path, *, key_available):
    return (("key", "project", "initial", "ask") if path == "direct" and key_available
            else ("project", "initial", "ask"))
