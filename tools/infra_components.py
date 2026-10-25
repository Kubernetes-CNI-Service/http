"""Closed presentation-free component data for the LOAD infra preparation call.

This module selects IDs, never package argv, installation authority or a skip
capability. Absence of a packet in the real callers retains their legacy path.
"""
from __future__ import annotations

COMPONENT_ORDER = (
    "load-core", "http", "dhcp", "ztp-runtime", "render-eth", "render-ib",
    "render-nvl", "validate-xlsx", "password-hash", "password-ssh", "docker",
    "nfs", "power-cycle", "analysis", "doca", "init-dns", "init-ntp",
    "init-timezone", "init-lldp",
)
_INITIALIZATION = ("init-dns", "init-ntp", "init-timezone", "init-lldp")
_FEATURES = ("password-hash", "password-ssh", "docker", "nfs",
             "power-cycle", "analysis", "doca")


def _checked_ids(value: object, allowed: tuple[str, ...]) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise ValueError("invalid LOAD component selection")
    seen: set[str] = set()
    for item in value:
        if type(item) is not str or item not in allowed or item in seen:
            raise ValueError("invalid LOAD component selection")
        seen.add(item)
    return value


def encode_load_components(components: tuple[str, ...]) -> str:
    selected = _checked_ids(components, COMPONENT_ORDER)
    if "load-core" not in selected or any(item not in selected for item in _INITIALIZATION):
        raise ValueError("invalid LOAD component selection")
    return ",".join(item for item in COMPONENT_ORDER if item in selected)


def parse_load_components(packet: str) -> tuple[str, ...]:
    if type(packet) is not str or not packet or not packet.isascii() or len(packet) > 512:
        raise ValueError("invalid LOAD component packet")
    selected = tuple(packet.split(","))
    if encode_load_components(selected) != packet:
        raise ValueError("invalid LOAD component packet")
    return selected


def select_load_components(
    *, http_enabled: bool, dhcp_enabled: bool, ztp_enabled: bool,
    device_types: tuple[str, ...], workbook_selected: bool,
    features: tuple[str, ...],
) -> tuple[str, ...]:
    if any(type(value) is not bool for value in (
        http_enabled, dhcp_enabled, ztp_enabled, workbook_selected,
    )):
        raise ValueError("unresolved LOAD component selection")
    families = _checked_ids(device_types, ("eth", "ib", "nvl"))
    chosen_features = _checked_ids(features, _FEATURES)
    selected = {"load-core", *_INITIALIZATION, *chosen_features}
    if http_enabled:
        selected.add("http")
    if dhcp_enabled:
        selected.add("dhcp")
    if ztp_enabled:
        selected.add("ztp-runtime")
    for family in families:
        selected.add("render-" + family)
    if workbook_selected:
        selected.add("validate-xlsx")
    return tuple(item for item in COMPONENT_ORDER if item in selected)
