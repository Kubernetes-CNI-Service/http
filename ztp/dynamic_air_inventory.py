#!/usr/bin/env python3
"""Resolve AIR-only Cumulus nodes that receive dynamic DHCP addresses.

The static project inventory intentionally contains only devices whose address
can be inherited from a Production row.  AIR topology nodes without a
Production counterpart (for example a simulated firewall) remain DHCP known
hosts and obtain an address from the serving subnet's dynamic range.  This
module joins their topology hostname/MAC with the current ISC DHCP lease so all
runtime consumers use the same identity and address decision.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import ipaddress
import json
from pathlib import Path
import re
from typing import Iterable


SAFE_HOSTNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
LEASE_BLOCK = re.compile(r"(?ms)^lease\s+(\S+)\s*\{(.*?)^[ \t]*\}")


def normalize_mac(value: object) -> str:
    raw = re.sub(r"[^0-9a-f]", "", str(value or "").casefold())
    return raw if len(raw) == 12 else ""


def display_mac(value: object) -> str:
    raw = normalize_mac(value)
    return ":".join(raw[index:index + 2] for index in range(0, 12, 2)) if raw else ""


def _inventory_rows(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    with path.open(newline="", encoding="utf-8-sig", errors="replace") as stream:
        return [
            {str(key or "").strip(): str(value or "").strip() for key, value in row.items()}
            for row in csv.DictReader(stream)
        ]


def _valid_static_air_rows(rows: Iterable[dict[str, str]]) -> list[dict[str, str]]:
    """Return complete canonical AIR rows capable of dedicated provisioning."""
    result = []
    for row in rows:
        if str(row.get("type") or "").strip().casefold() != "air":
            continue
        if not str(row.get("hostname") or "").strip():
            continue
        if not str(row.get("template") or "").strip():
            continue
        if not normalize_mac(row.get("eth0_mac")):
            continue
        try:
            ipaddress.ip_address(str(row.get("eth0_ip") or "").strip())
        except ValueError:
            continue
        result.append(row)
    return result


def find_air_json(inventory: Path, explicit: Path | None = None) -> Path | None:
    """Return the AIR topology JSON associated with an inventory/project."""
    if explicit is not None:
        return explicit if explicit.is_file() else None
    output = inventory.parent / "99-output-p2p"
    candidates = [
        path for path in output.glob("*-air.json")
        if path.is_file() and path.name.casefold() != "air-template.json"
    ] if output.is_dir() else []
    if not candidates:
        return None
    return max(candidates, key=lambda path: (path.stat().st_mtime_ns, path.name))


def topology_nodes(path: Path | None) -> list[dict[str, str]]:
    """Read Cumulus network nodes and their eth0 identity from AIR JSON."""
    if path is None or not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return []
    container = data.get("content", data) if isinstance(data, dict) else {}
    nodes = container.get("nodes", {}) if isinstance(container, dict) else {}
    if not isinstance(nodes, dict):
        return []
    result = []
    for hostname, node in nodes.items():
        if not isinstance(node, dict):
            continue
        os_name = str(node.get("os") or "").strip().casefold()
        if not (os_name.startswith("cumulus") or os_name == "oob-mgmt-switch"):
            continue
        name = str(hostname or "").strip()
        if not SAFE_HOSTNAME.fullmatch(name):
            continue
        interfaces = node.get("management_interfaces")
        eth0 = interfaces.get("eth0", {}) if isinstance(interfaces, dict) else {}
        mac = display_mac(
            eth0.get("mac_address") or eth0.get("mac")
            if isinstance(eth0, dict) else ""
        )
        if not mac:
            continue
        template = "fw" if re.search(r"(?:^|[-_.])FW(?:[-_.]?\d+)?$", name, re.I) else ""
        result.append({
            "hostname": name,
            "type": "air",
            "template": template,
            "mac": mac,
            "mac_plain": normalize_mac(mac),
        })
    return result


def _lease_end(body: str) -> dt.datetime | None:
    """Return an ISC lease ``ends`` value as UTC, or ``None`` for ``never``.

    ISC stores lease timestamps in UTC.  ``binding state active`` alone is not
    sufficient after an unclean daemon/server stop: the final on-disk block can
    remain active after its end time and must not become a transport address.
    """
    match = re.search(
        r"(?mi)^\s*ends\s+\d+\s+"
        r"(\d{4}/\d\d/\d\d\s+\d\d:\d\d:\d\d)\s*;",
        body,
    )
    if not match:
        return None
    try:
        return dt.datetime.strptime(
            match.group(1), "%Y/%m/%d %H:%M:%S",
        ).replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None


def active_leases(
    path: Path | None, *, now: dt.datetime | None = None,
) -> dict[str, str]:
    """Return MAC -> IP for the final, unexpired active ISC lease blocks."""
    if path is None or not path.is_file():
        return {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    # ISC appends a new block whenever an address changes state.  Resolve the
    # final block by *address* first; otherwise an earlier active block for an
    # old client could survive after that address was released/reassigned.
    current = now or dt.datetime.now(dt.timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=dt.timezone.utc)
    else:
        current = current.astimezone(dt.timezone.utc)
    states_by_address: dict[str, tuple[int, str, str, dt.datetime | None]] = {}
    for sequence, match in enumerate(LEASE_BLOCK.finditer(text)):
        address, body = match.groups()
        mac_match = re.search(r"(?mi)^\s*hardware\s+ethernet\s+([^;\s]+)\s*;", body)
        state_match = re.search(r"(?mi)^\s*binding\s+state\s+([^;\s]+)\s*;", body)
        mac = normalize_mac(mac_match.group(1) if mac_match else "")
        try:
            ipaddress.ip_address(address)
        except ValueError:
            continue
        states_by_address[address] = (
            sequence,
            (state_match.group(1) if state_match else "").casefold(),
            mac,
            _lease_end(body),
        )
    result: dict[str, str] = {}
    for address, (_sequence, state, mac, lease_end) in sorted(
        states_by_address.items(), key=lambda item: item[1][0],
    ):
        if state == "active" and mac and (lease_end is None or lease_end > current):
            result[mac] = address
    return result


def dynamic_air_devices(
    inventory: Path,
    *,
    air_json: Path | None = None,
    leases: Path | None = Path("/var/lib/dhcp/dhcpd.leases"),
) -> list[dict[str, str]]:
    """Return AIR topology nodes absent from the static project inventory."""
    rows = _inventory_rows(inventory)
    canonical_air_rows = _valid_static_air_rows(rows)
    static_names = {
        str(row.get("hostname") or "").strip().casefold()
        for row in canonical_air_rows
    }
    static_macs = {
        normalize_mac(row.get("eth0_mac"))
        for row in canonical_air_rows
    }
    static_ips = {
        str(row.get("eth0_ip") or "").strip()
        for row in rows if str(row.get("eth0_ip") or "").strip()
    }
    lease_by_mac = active_leases(leases)
    source_json = find_air_json(inventory, air_json)
    devices = []
    used_addresses: dict[str, str] = {}
    for node in topology_nodes(source_json):
        # A device can receive its final canonical hostname when it is promoted
        # into the project inventory.  MAC therefore suppresses a stale AIR
        # topology alias as well as an exact hostname, preventing one physical
        # switch from appearing once as static and once as dynamic.
        if (node["hostname"].casefold() in static_names
                or node["mac_plain"] in static_macs):
            continue
        address = lease_by_mac.get(node["mac_plain"], "")
        issue = ""
        if address and address in static_ips:
            issue = f"lease address {address} conflicts with static inventory"
            address = ""
        if address and address in used_addresses:
            issue = f"lease address {address} also belongs to {used_addresses[address]}"
            address = ""
        if address:
            used_addresses[address] = node["hostname"]
        devices.append({
            **node,
            "ip": address,
            "address_source": "dhcp-lease" if address else "unresolved",
            "issue": issue,
            "air_json": str(source_json or ""),
            "dynamic_dhcp": "true",
        })
    return devices


def static_air_lease_fallbacks(
    inventory: Path,
    *,
    air_json: Path | None = None,
    leases: Path | None = Path("/var/lib/dhcp/dhcpd.leases"),
) -> list[dict[str, str]]:
    """Return old dynamic lease addresses for AIR nodes promoted to static.

    After a project gains the device's canonical row/MAC, newly generated ZTP
    data uses its configured address and dedicated YAML.  Before that YAML is
    applied, however, the running switch can still be reachable only through
    the previous dynamic lease.  Consumers use this address strictly as a
    temporary, MAC-verified fallback; it never changes the static inventory or
    the device's canonical classification.
    """
    rows = _inventory_rows(inventory)
    air_rows = _valid_static_air_rows(rows)
    by_name = {
        str(row.get("hostname") or "").strip().casefold(): row
        for row in air_rows
    }
    by_mac = {
        normalize_mac(row.get("eth0_mac")): row
        for row in air_rows if normalize_mac(row.get("eth0_mac"))
    }
    all_static_ips = {
        str(row.get("eth0_ip") or "").strip(): str(row.get("hostname") or "").strip()
        for row in rows if str(row.get("eth0_ip") or "").strip()
    }
    leases_by_mac = active_leases(leases)
    result = []
    source_json = find_air_json(inventory, air_json)
    for node in topology_nodes(source_json):
        row = by_name.get(node["hostname"].casefold()) or by_mac.get(node["mac_plain"])
        if row is None:
            continue
        static_mac = normalize_mac(row.get("eth0_mac"))
        if not static_mac or static_mac != node["mac_plain"]:
            continue
        lease_ip = leases_by_mac.get(static_mac, "")
        configured_ip = str(row.get("eth0_ip") or "").strip()
        if not lease_ip or lease_ip == configured_ip:
            continue
        conflict = all_static_ips.get(lease_ip, "")
        issue = (
            f"lease address {lease_ip} conflicts with static device {conflict}"
            if conflict and conflict.casefold()
            != str(row.get("hostname") or "").strip().casefold() else ""
        )
        if issue:
            lease_ip = ""
        result.append({
            "hostname": str(row.get("hostname") or "").strip(),
            "type": "air",
            "template": str(row.get("template") or "").strip(),
            "mac": display_mac(row.get("eth0_mac")),
            "mac_plain": static_mac,
            "ip": lease_ip,
            "configured_ip": configured_ip,
            "address_source": "dhcp-lease-transition" if lease_ip else "unresolved",
            "issue": issue,
            "air_json": str(source_json or ""),
            "dynamic_dhcp": "transition",
        })
    return result


def _pipe_rows(devices: Iterable[dict[str, str]]) -> str:
    return "\n".join(
        "|".join(str(device.get(field, "")).replace("|", " ") for field in (
            "hostname", "ip", "mac", "template", "address_source", "issue",
        ))
        for device in devices
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Resolve AIR-only Cumulus nodes through the current ISC DHCP lease",
    )
    result.add_argument("--inventory", type=Path, required=True)
    result.add_argument("--air-json", type=Path)
    result.add_argument(
        "--leases", type=Path, default=Path("/var/lib/dhcp/dhcpd.leases"),
    )
    result.add_argument("--format", choices=("pipe", "json"), default="pipe")
    result.add_argument("--resolved-only", action="store_true")
    result.add_argument(
        "--include-static-transitions", action="store_true",
        help="also emit promoted static AIR nodes still holding an old dynamic lease",
    )
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    devices = dynamic_air_devices(
        args.inventory, air_json=args.air_json, leases=args.leases,
    )
    if args.include_static_transitions:
        devices.extend(static_air_lease_fallbacks(
            args.inventory, air_json=args.air_json, leases=args.leases,
        ))
    if args.resolved_only:
        devices = [device for device in devices if device.get("ip")]
    if args.format == "json":
        print(json.dumps(devices, ensure_ascii=False, indent=2))
    else:
        output = _pipe_rows(devices)
        if output:
            print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
