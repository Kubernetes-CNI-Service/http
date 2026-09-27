#!/usr/bin/env python3
"""Fail-closed UFM input contract; execution is not enabled by this module."""

from __future__ import annotations

import copy
import csv
from dataclasses import dataclass
import io
import ipaddress
from pathlib import Path
import re

from project_contract import safe_load_global_yaml


class UfmInputError(ValueError):
    """Invalid or incomplete UFM intent."""


_FAMILY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
_INTERFACE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
_POLICY_KEYS = frozenset({
    "version", "vip", "cross-login", "sm-setup", "interfaces", "services",
})
_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
_MAC_RE = re.compile(r"^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.I)


@dataclass(frozen=True)
class UfmNode:
    hostname: str
    address: str
    management_mac: str
    network: str
    declared_gateway: str | None = None


@dataclass(frozen=True)
class UfmVipPlan:
    candidate: str | None
    source: str
    configured: bool = False


def _interfaces(value: object) -> None:
    if type(value) is not dict or not value:
        raise UfmInputError("UFM interfaces must be a nonempty mapping")
    if set(value) - {"alias", "ipoib"}:
        raise UfmInputError("UFM interfaces contains an unknown key")
    alias = value.get("alias")
    if type(alias) is not dict or "eth0" not in alias:
        raise UfmInputError("UFM alias must map logical eth0 to its device")
    targets: set[str] = set()
    for logical, device in alias.items():
        if type(logical) is not str or not _INTERFACE_RE.fullmatch(logical):
            raise UfmInputError("UFM alias has an invalid logical interface")
        if type(device) is not str or not _INTERFACE_RE.fullmatch(device):
            raise UfmInputError("UFM alias has an invalid device interface")
        key = device.casefold()
        if key in targets:
            raise UfmInputError("UFM alias targets the same interface twice")
        targets.add(key)
    ipoib = value.get("ipoib")
    if ipoib is not None:
        if type(ipoib) is not dict or set(ipoib) != {"primary", "secondary"}:
            raise UfmInputError("UFM ipoib requires primary and secondary labels")
        for label in ("primary", "secondary"):
            address = ipoib[label]
            if type(address) is not str or "/" not in address:
                raise UfmInputError(f"UFM ipoib {label} requires an IPv4 prefix")
            try:
                if not isinstance(ipaddress.ip_interface(address), ipaddress.IPv4Interface):
                    raise ValueError("not IPv4")
            except ValueError as exc:
                raise UfmInputError(f"UFM ipoib {label} is invalid") from exc


def parse_ufm_servers(document: object) -> dict[str, dict[str, object]]:
    """Validate D-75 top-level family intent without side effects."""
    if type(document) is not dict:
        raise UfmInputError("global YAML root must be a mapping")
    records = document.get("servers", [])
    if type(records) is not list:
        raise UfmInputError("top-level servers must be a list of single-key families")
    families: dict[str, dict[str, object]] = {}
    for record in records:
        if type(record) is not dict or len(record) != 1:
            raise UfmInputError("each server family must be a single-key mapping")
        family, policy = next(iter(record.items()))
        if type(family) is not str or not _FAMILY_RE.fullmatch(family):
            raise UfmInputError("invalid server family name")
        family_key = family.casefold()
        if family_key in families:
            raise UfmInputError(f"duplicate server family: {family_key}")
        if family_key != "ufm":
            raise UfmInputError(f"unsupported server family: {family_key}")
        if type(policy) is not dict:
            raise UfmInputError("UFM server family policy must be a mapping")
        if set(policy) - _POLICY_KEYS:
            raise UfmInputError("UFM policy contains an unknown key")
        if "version" in policy and (
            type(policy["version"]) is not str
            or not _VERSION_RE.fullmatch(policy["version"])
        ):
            raise UfmInputError("UFM version must be a nonempty string token")
        if "vip" in policy:
            try:
                if type(policy["vip"]) is not str or not isinstance(
                    ipaddress.ip_address(policy["vip"]), ipaddress.IPv4Address
                ):
                    raise ValueError("not an IPv4 address")
            except ValueError as exc:
                raise UfmInputError("UFM vip must be IPv4") from exc
        for key in ("cross-login", "sm-setup"):
            if key in policy and type(policy[key]) is not bool:
                raise UfmInputError(f"UFM {key} must be an explicit boolean")
        _interfaces(policy.get("interfaces"))
        if "services" in policy:
            services = policy["services"]
            if type(services) is not dict:
                raise UfmInputError("UFM services must be a mapping")
            if services:
                raise UfmInputError(
                    "UFM service paths require a separate trusted allowlist"
                )
        families[family_key] = copy.deepcopy(policy)
    return families


def load_ufm_servers(path: Path) -> dict[str, dict[str, object]]:
    """Read one global YAML document with duplicate-key rejection."""
    try:
        with Path(path).open(encoding="utf-8") as stream:
            document = safe_load_global_yaml(stream)
    except (OSError, ValueError) as exc:
        raise UfmInputError("global YAML could not be read or has duplicate keys") from exc
    except Exception as exc:
        raise UfmInputError("global YAML could not be parsed") from exc
    return parse_ufm_servers(document)


def plan_ufm_vip(document: object, nodes: tuple[UfmNode, ...]) -> UfmVipPlan:
    """Plan D-58 VIP intent, never a live occupancy or HA configuration proof."""
    policy = parse_ufm_servers(document).get("ufm")
    if policy is None or len(nodes) not in {1, 2}:
        raise UfmInputError("UFM vip planning requires one or two bound nodes")
    if len(nodes) == 1:
        if "vip" in policy:
            raise UfmInputError("single UFM must not declare a HA vip")
        return UfmVipPlan(None, "none")

    networks = {node.network for node in nodes}
    if len(networks) != 1:
        raise UfmInputError("UFM vip requires one common eth0 subnet")
    network = ipaddress.IPv4Network(next(iter(networks)))
    if network.num_addresses < 4:
        raise UfmInputError("UFM vip subnet has no usable address")
    node_addresses = {ipaddress.IPv4Address(node.address) for node in nodes}
    gateways = {
        ipaddress.IPv4Address(node.declared_gateway)
        for node in nodes if node.declared_gateway is not None
    }
    gateway_at_high_end = ipaddress.IPv4Address(int(network.broadcast_address) - 1)
    if "vip" in policy:
        candidate = ipaddress.IPv4Address(policy["vip"])
        source = "declared"
    else:
        highest = max(node_addresses)
        if highest == ipaddress.IPv4Address("255.255.255.255"):
            raise UfmInputError("UFM vip default exceeds IPv4 address space")
        candidate = ipaddress.IPv4Address(int(highest) + 1)
        source = "derived"
    if (
        candidate not in network
        or candidate in node_addresses
        or candidate in gateways
        or candidate == network.network_address
        or candidate == gateway_at_high_end
        or candidate == network.broadcast_address
    ):
        raise UfmInputError("UFM vip conflicts with node, gateway, or subnet boundary")
    return UfmVipPlan(str(candidate), source)


def bind_ufm_inventory(document: object, devices_file: Path) -> tuple[UfmNode, ...]:
    """Bind a two-node HA intent to static CSV identity without any writes.

    This does not prove live DHCP leases, SSH host keys, physical interfaces,
    licence MACs, or installation-time primary/secondary labels.
    """
    try:
        csv_text = Path(devices_file).read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError) as exc:
        raise UfmInputError("UFM CSV could not be read") from exc
    return bind_ufm_inventory_text(document, csv_text)


def bind_ufm_inventory_text(document: object, csv_text: str) -> tuple[UfmNode, ...]:
    """Bind the exact CSV bytes already captured by a no-follow caller."""
    families = parse_ufm_servers(document)
    if type(csv_text) is not str:
        raise UfmInputError("UFM CSV snapshot must be text")
    try:
        with io.StringIO(csv_text) as stream:
            reader = csv.reader(stream)
            header = [str(item or "").strip().casefold() for item in next(reader, [])]
            if tuple(header[:7]) != (
                "hostname", "type", "template", "eth0_ip", "netmask",
                "eth0_gw", "eth0_mac",
            ):
                raise UfmInputError("UFM CSV has no canonical management columns")
            rows = []
            for line, row in enumerate(reader, 2):
                if not any(str(item or "").strip() for item in row):
                    continue
                if len(row) != len(header):
                    raise UfmInputError(f"UFM CSV line {line} has wrong width")
                if str(row[1]).strip().casefold() == "ufm":
                    rows.append((line, row))
    except (UnicodeError, csv.Error) as exc:
        raise UfmInputError("UFM CSV could not be read") from exc

    policy = families.get("ufm")
    if not rows and policy is None:
        return ()
    if policy is None:
        raise UfmInputError("UFM CSV rows require top-level servers.ufm")
    if len(rows) not in {1, 2}:
        raise UfmInputError("UFM requires one node or exactly two HA nodes")
    if len(rows) == 1 and "vip" in policy:
        raise UfmInputError("single UFM must not declare a HA vip")
    alias = policy["interfaces"]["alias"]
    if len(rows) == 2 and "eth1" not in alias:
        raise UfmInputError("UFM HA requires eth0 and eth1 aliases")
    names: set[str] = set()
    addresses: set[str] = set()
    macs: set[str] = set()
    nodes: list[UfmNode] = []
    for line, row in rows:
        hostname = str(row[0]).strip()
        address_text = str(row[3]).strip()
        mask = str(row[4]).strip()
        mac = str(row[6]).strip().casefold().replace("-", ":")
        if not _HOST_RE.fullmatch(hostname):
            raise UfmInputError(f"UFM CSV line {line} has unsafe hostname")
        if not _MAC_RE.fullmatch(mac):
            raise UfmInputError(f"UFM CSV line {line} has invalid management MAC")
        try:
            interface = ipaddress.ip_interface(
                address_text if "/" in address_text else f"{address_text}/{mask}"
            )
            if not isinstance(interface, ipaddress.IPv4Interface):
                raise ValueError("not IPv4")
            declared = ipaddress.ip_network(f"0.0.0.0/{mask}")
            if interface.network.prefixlen != declared.prefixlen:
                raise ValueError("CIDR and netmask disagree")
            gateway_text = str(row[5]).strip()
            gateway = None if gateway_text.upper() in {"", "NA"} else ipaddress.IPv4Address(gateway_text)
            if gateway is not None and gateway not in interface.network:
                raise ValueError("gateway is outside eth0 subnet")
        except ValueError as exc:
            raise UfmInputError(f"UFM CSV line {line} has invalid eth0 network") from exc
        address = str(interface.ip)
        if hostname.casefold() in names or address in addresses or mac in macs:
            raise UfmInputError("UFM CSV contains duplicate node identity")
        names.add(hostname.casefold())
        addresses.add(address)
        macs.add(mac)
        nodes.append(UfmNode(
            hostname, address, mac, str(interface.network),
            str(gateway) if gateway is not None else None,
        ))
    bound = tuple(sorted(nodes, key=lambda node: node.hostname.casefold()))
    plan_ufm_vip(document, bound)
    return bound
