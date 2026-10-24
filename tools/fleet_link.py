"""ztp-server egress link speed for switch fleet jobs (IB upgrade v2; reusable for nvl-sw; owner 2026-10-23).

Runs first, before any password prompt or device access. Reads local facts only:
`ip` output and /sys/class/net. The result picks how OS images reach the switches:
below 10G they relay switch to switch per OOB leaf; at 10G and above every switch
pulls from the server, staggered and capped. Anything that cannot be resolved to a
physical port counts as 1G (relay), which is the mode that is safe on any link.

The HTTP service may listen on several addresses, one per ztp-server network, and those
networks are normally not routed to each other (owner 2026-10-24). Each switch therefore
uses the configured address on the interface that `ip route get <switch>` leaves by: the
route's src when it is configured, else the only configured address on that interface.
Several without the src (ambiguous), none (no HTTP listener there) or no route at all
make that switch fail closed; it never falls back to an address on another network.
The distribution mode follows the slowest egress, and [LINK] lists every egress.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import math
from pathlib import Path
import re
import subprocess

SERVER_LINKS = {"1G": 1000, "2G": 2000, "10G": 10000, "20G": 20000, "25G": 25000, "40G": 40000,
                "50G": 50000, "100G": 100000, "200G": 200000, "400G": 400000}
_MAX_DEPTH = 8


@dataclass(frozen=True)
class Layer:
    name: str
    kind: str              # physical | bond | bridge | vlan | macvlan | virtual | missing
    speed_mbps: int | None
    detail: str = ""


@dataclass(frozen=True)
class LinkDecision:
    speed_mbps: int | None
    source: str            # detected | override | unknown
    mode: str              # relay | direct
    divisor: int | None    # stagger window divisor (16 or 32), direct mode only
    cap: int | None        # concurrent downloads, None = no cap
    egress: tuple[str, ...] = ()
    layers: tuple[Layer, ...] = ()
    warnings: tuple[str, ...] = field(default=())
    paths: tuple = ()      # (egress, speed Mb/s or None, switch count, HTTP addresses used), one per egress

    def window_seconds(self, count: int) -> int:
        """60 x ceil(N/16) at 10G-<100G, 60 x ceil(N/32) at 100G and above."""
        if self.mode != "direct" or count <= 0:
            return 0
        return 60 * math.ceil(count / self.divisor)

    def line(self) -> str:
        speed = "unknown" if self.speed_mbps is None else _label(self.speed_mbps)
        parts = ["[LINK]", "egress=" + (",".join(self.egress) or "-"), "speed=" + speed,
                 "source=" + self.source, "→", self.mode]
        if self.mode == "direct":
            parts.append(f"window=60*ceil(N/{self.divisor})")
            parts.append("cap=" + ("none" if self.cap is None else str(self.cap)))
        text = " ".join(parts)
        described = [layer for layer in self.layers if layer.detail]
        if described:
            text += " (" + "; ".join(layer.name + ": " + layer.detail for layer in described) + ")"
        for device, speed, count, addresses in self.paths:
            text += (f" · {device} {'unknown' if speed is None else _label(speed)} {count} switch(es) "
                     f"http {','.join(addresses) or 'none'}")
        return text


def _label(mbps: int) -> str:
    return f"{mbps // 1000}G" if mbps >= 1000 and mbps % 1000 == 0 else f"{mbps}M"


def decide(speed_mbps: int | None, *, source: str, egress=(), layers=(), warnings=(), paths=()) -> LinkDecision:
    if speed_mbps is None or speed_mbps < 10000:
        mode, divisor, cap = "relay", None, None
    elif speed_mbps < 100000:
        mode, divisor, cap = "direct", 16, max(1, int(speed_mbps * 0.8) // 1000)
    else:
        mode, divisor, cap = "direct", 32, None
    return LinkDecision(speed_mbps, source, mode, divisor, cap, tuple(egress), tuple(layers), tuple(warnings),
                        tuple(paths))


def from_override(value: str) -> LinkDecision:
    if value not in SERVER_LINKS:
        raise ValueError("--server-link must be one of " + ", ".join(SERVER_LINKS))
    return decide(SERVER_LINKS[value], source="override")


def _run(argv):
    done = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10)
    if done.returncode != 0:
        raise OSError(f"{' '.join(argv[:3])} exited {done.returncode}")
    return done.stdout


def local_addresses(run=_run) -> set[str]:
    found = set()
    for line in run(["ip", "-o", "addr", "show"]).splitlines():
        match = re.search(r"\binet6? ([0-9A-Fa-f.:]+)/\d+", line)
        if match:
            found.add(str(ipaddress.ip_address(match[1])))
    return found


def route_to(destination: str, run=_run) -> tuple[str, str | None, str | None]:
    """(device, next hop or None, src or None) of `ip route get <destination>` (no source address)."""
    text = run(["ip", "route", "get", destination])
    device = re.search(r"\bdev (\S+)", text)
    if device is None:
        raise ValueError("no egress device in route")
    via = re.search(r"\bvia (\S+)", text)
    src = re.search(r"\bsrc (\S+)", text)
    return device[1], (via[1] if via else None), (str(ipaddress.ip_address(src[1])) if src else None)


def device_addresses(device: str, run=_run) -> list[str]:
    """Addresses on one interface, primary first (`ip -o addr show dev <device>`)."""
    found = []
    for line in run(["ip", "-o", "addr", "show", "dev", device]).splitlines():
        match = re.search(r"\binet6? ([0-9A-Fa-f.:]+)/\d+", line)
        if match and str(ipaddress.ip_address(match[1])) not in found:
            found.append(str(ipaddress.ip_address(match[1])))
    return found


NO_ROUTE, NONE, AMBIGUOUS = ("HTTP_SERVICE_ADDRESS_NO_ROUTE", "HTTP_SERVICE_ADDRESS_NONE",
                             "HTTP_SERVICE_ADDRESS_AMBIGUOUS")


@dataclass(frozen=True)
class Service:
    """The HTTP address one switch downloads from, or why it has none (then it fails closed)."""
    switch: str
    device: str | None = None          # egress interface of `ip route get <switch>`
    via: str | None = None
    src: str | None = None
    address: str | None = None
    reason: str | None = None          # NO_ROUTE | NONE | AMBIGUOUS
    candidates: tuple[str, ...] = ()


def resolve_services(switch_addresses, configured, *, run=_run) -> dict:
    """{switch address: Service} for the configured HTTP addresses (several allowed, duplicates ignored)."""
    configured = tuple(dict.fromkeys(str(ipaddress.ip_address(value)) for value in configured))
    on_device, found = {}, {}
    for switch in switch_addresses:
        try:
            device, via, src = route_to(switch, run)
        except (OSError, ValueError, subprocess.SubprocessError):
            found[switch] = Service(switch, reason=NO_ROUTE)
            continue
        if device not in on_device:
            try:
                on_device[device] = device_addresses(device, run)
            except (OSError, ValueError, subprocess.SubprocessError):
                on_device[device] = []
        candidates = tuple(value for value in configured if value in on_device[device])
        if src in candidates:
            chosen, reason = src, None
        elif len(candidates) == 1:
            chosen, reason = candidates[0], None
        else:
            chosen, reason = None, (AMBIGUOUS if candidates else NONE)
        found[switch] = Service(switch, device, via, src, chosen, reason, candidates)
    return found


class _Sysfs:
    def __init__(self, root: Path):
        self.net = Path(root) / "class" / "net"

    def exists(self, name):
        return (self.net / name).exists()

    def read(self, name, *parts):
        try:
            return (self.net / name).joinpath(*parts).read_text(encoding="ascii").strip()
        except (OSError, UnicodeError):
            return None

    def devtype(self, name):
        text = self.read(name, "uevent") or ""
        match = re.search(r"(?m)^DEVTYPE=(\S+)$", text)
        return match[1] if match else None

    def is_dir(self, name, *parts):
        return (self.net / name).joinpath(*parts).is_dir()

    def entries(self, name, *parts):
        try:
            return sorted(path.name for path in (self.net / name).joinpath(*parts).iterdir())
        except OSError:
            return []

    def lower(self, name):
        found = [entry[len("lower_"):] for entry in self.entries(name) if entry.startswith("lower_")]
        return found[0] if len(found) == 1 else None

    def physical(self, name):
        return (self.net / name / "device").exists()


def _speed(sysfs, name):
    text = sysfs.read(name, "speed")
    try:
        value = int(text)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def resolve(sysfs, name, *, run=_run, next_hop=None, depth=0):
    """Effective speed (Mb/s or None) of an egress interface plus the layers walked."""
    if depth > _MAX_DEPTH:
        return None, [Layer(name, "virtual", None, "interface nesting too deep")], ["interface nesting too deep"]
    if not sysfs.exists(name):
        return None, [Layer(name, "missing", None, "not in /sys/class/net")], [f"{name}: not in /sys/class/net"]
    devtype = sysfs.devtype(name)
    if sysfs.is_dir(name, "bonding") or devtype == "bond":
        return _bond(sysfs, name, run=run, next_hop=next_hop, depth=depth)
    if sysfs.is_dir(name, "bridge") or devtype == "bridge":
        return _bridge(sysfs, name, run=run, next_hop=next_hop, depth=depth)
    if devtype in ("vlan", "macvlan", "ipvlan") or (not sysfs.physical(name) and sysfs.lower(name)):
        lower = sysfs.lower(name)
        if lower is None:
            return None, [Layer(name, devtype or "virtual", None, "no lower interface")], [f"{name}: no lower interface"]
        speed, layers, warnings = resolve(sysfs, lower, run=run, next_hop=next_hop, depth=depth + 1)
        return speed, [Layer(name, devtype or "vlan", speed, "on " + lower)] + layers, warnings
    if sysfs.physical(name):
        speed = _speed(sysfs, name)
        warnings = [] if speed else [f"{name}: speed unknown"]
        return speed, [Layer(name, "physical", speed)], warnings
    return None, [Layer(name, devtype or "virtual", None, "virtual interface without a physical port")], \
        [f"{name}: virtual interface ({devtype or 'unknown type'}) has no physical port"]


def _bond(sysfs, name, *, run, next_hop, depth):
    mode = (sysfs.read(name, "bonding", "mode") or "").split()
    slaves = (sysfs.read(name, "bonding", "slaves") or "").split()
    if mode and mode[0] == "active-backup":
        active = sysfs.read(name, "bonding", "active_slave")
        if not active:
            return None, [Layer(name, "bond", None, "active-backup without an active slave")], \
                [f"{name}: active-backup without an active slave"]
        speed, layers, warnings = resolve(sysfs, active, run=run, next_hop=next_hop, depth=depth + 1)
        return speed, [Layer(name, "bond", speed, "active-backup: " + active)] + layers, warnings
    total, layers, warnings, used = 0, [], [], []
    for slave in slaves:
        if (sysfs.read(slave, "operstate") or "up") != "up":
            continue
        speed, walked, notes = resolve(sysfs, slave, run=run, next_hop=next_hop, depth=depth + 1)
        layers += walked
        warnings += notes
        if speed:
            total += speed
            used.append(f"{slave} {_label(speed)}")
    if not total:
        return None, [Layer(name, "bond", None, "no active member with a known speed")] + layers, \
            warnings + [f"{name}: no active member with a known speed"]
    label = (mode[0] if mode else "bond") + ": " + " + ".join(used)
    return total, [Layer(name, "bond", total, label)] + layers, warnings


def _bridge(sysfs, name, *, run, next_hop, depth):
    # The bridge's own speed is unreliable (unknown, or the fastest member, which a
    # veth/tap member inflates to 10G). Walk the members that lead to a real port.
    candidates = []
    for member in sysfs.entries(name, "brif"):
        kind = sysfs.devtype(member)
        if sysfs.physical(member) or kind in ("bond", "vlan", "macvlan") or sysfs.is_dir(member, "bonding"):
            candidates.append(member)
    if not candidates:
        return None, [Layer(name, "bridge", None, "no physical member")], [f"{name}: bridge has no physical member"]
    chosen, note = None, ""
    if len(candidates) == 1:
        chosen = candidates[0]
    else:
        port = _fdb_port(name, next_hop, run) if next_hop else None
        if port in candidates:
            chosen, note = port, " (FDB)"
    if chosen is not None:
        speed, layers, warnings = resolve(sysfs, chosen, run=run, next_hop=next_hop, depth=depth + 1)
        return speed, [Layer(name, "bridge", speed, "member " + chosen + note)] + layers, warnings
    resolved = [resolve(sysfs, member, run=run, next_hop=next_hop, depth=depth + 1) for member in candidates]
    speeds = [speed for speed, _layers, _warnings in resolved if speed]
    layers = [layer for _speed, walked, _warnings in resolved for layer in walked]
    warnings = [note for _speed, _walked, notes in resolved for note in notes]
    if not speeds:
        return None, [Layer(name, "bridge", None, "no member with a known speed")] + layers, \
            warnings + [f"{name}: no member with a known speed"]
    slowest = min(speeds)
    return slowest, [Layer(name, "bridge", slowest, "slowest of " + ", ".join(candidates))] + layers, \
        warnings + [f"{name}: egress member not found in the FDB; using the slowest member"]


def _fdb_port(bridge, next_hop, run):
    try:
        neighbour = run(["ip", "neigh", "show", next_hop, "dev", bridge])
        mac = re.search(r"\blladdr ([0-9a-fA-F:]{17})\b", neighbour)
        if mac is None:
            return None
        for line in run(["bridge", "fdb", "show", "br", bridge]).splitlines():
            fields = line.split()
            if fields and fields[0].lower() == mac[1].lower() and "dev" in fields:
                return fields[fields.index("dev") + 1]
    except (OSError, ValueError, IndexError, subprocess.SubprocessError):
        return None
    return None


def detect(switch_addresses, server_addresses, *, run=_run, sysfs_root=Path("/sys"), override=None,
           services=None) -> LinkDecision:
    """Decide the distribution mode from the server's egress toward every switch.

    server_addresses: one address or a list (several HTTP addresses). services: resolve_services() already run
    for these switches, so the route lookups are not repeated."""
    if override is not None:
        return from_override(override)
    configured = [server_addresses] if isinstance(server_addresses, str) else list(server_addresses or ())
    try:
        configured = list(dict.fromkeys(str(ipaddress.ip_address(value)) for value in configured))
    except ValueError:
        return decide(None, source="unknown", warnings=[f"server address {server_addresses!r} is not an IP address"])
    if not configured:
        return decide(None, source="unknown", warnings=["no server address configured"])
    try:
        local = local_addresses(run)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        return decide(None, source="unknown", warnings=[f"cannot list local addresses: {error}"])
    foreign = [value for value in configured if value not in local]
    if len(foreign) == len(configured):
        return decide(None, source="unknown", warnings=[
            f"server address {', '.join(foreign)} is not on this host; run on the ztp-server or pass --server-link"])
    warnings = [f"server address {value} is not on this host; no switch can use it" for value in foreign]
    if services is None:
        services = resolve_services(switch_addresses, configured, run=run)
    sysfs = _Sysfs(sysfs_root)
    routes, per_device = {}, {}
    for address in switch_addresses:
        service = services[address]
        if service.device is None:
            warnings.append(f"no route to {address}; that switch fails closed ({NO_ROUTE})")
            continue
        routes.setdefault((service.device, service.via), []).append(service)
        per_device.setdefault(service.device, []).append(service)
    speeds, layers, egress, device_speed = [], [], [], {}
    for (device, next_hop) in sorted(routes, key=lambda item: (item[0], item[1] or "")):
        speed, walked, notes = resolve(sysfs, device, run=run, next_hop=next_hop)
        if device not in egress:
            egress.append(device)
        device_speed.setdefault(device, []).append(speed)
        layers += walked
        warnings += notes
        if any(item.address for item in routes[(device, next_hop)]):
            speeds.append(speed)          # switches that fail closed never download: they do not set the mode
    paths = []
    for device in egress:
        items = per_device[device]
        used = tuple(dict.fromkeys(item.address for item in items if item.address))
        known = device_speed[device]
        paths.append((device, None if None in known else min(known), len(items), used))
        lost = [item for item in items if item.reason]
        if lost and not used and all(item.reason == NONE for item in lost):
            warnings.append(f"{device}: no configured HTTP address on this interface; its {len(lost)} switch(es) "
                            f"fail closed ({NONE})")
        elif lost:
            warnings.append(f"{device}: {len(lost)} switch(es) without a usable HTTP address fail closed "
                            f"({', '.join(sorted({item.reason for item in lost}))})")
    if not speeds or any(speed is None for speed in speeds):
        return decide(None, source="unknown", egress=egress, layers=layers, paths=paths,
                      warnings=warnings + ["egress speed unknown; treating the server link as 1G (relay)"])
    if len(set(egress)) > 1:
        warnings.append("switches are reached through several interfaces; using the slowest")
    return decide(min(speeds), source="detected", egress=egress, layers=layers, warnings=warnings, paths=paths)
