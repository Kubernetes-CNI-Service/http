"""ztp-server egress link speed for switch fleet jobs (IB upgrade v2; reusable for nvl-sw; owner 2026-10-23).

Runs first, before any password prompt or device access. Reads local facts only:
`ip` output and /sys/class/net. The result picks how OS images reach the switches:
below 10G they relay switch to switch per OOB leaf; at 10G and above every switch
pulls from the server, staggered and capped. Anything that cannot be resolved to a
physical port counts as 1G (relay), which is the mode that is safe on any link.
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
        return text


def _label(mbps: int) -> str:
    return f"{mbps // 1000}G" if mbps >= 1000 and mbps % 1000 == 0 else f"{mbps}M"


def decide(speed_mbps: int | None, *, source: str, egress=(), layers=(), warnings=()) -> LinkDecision:
    if speed_mbps is None or speed_mbps < 10000:
        mode, divisor, cap = "relay", None, None
    elif speed_mbps < 100000:
        mode, divisor, cap = "direct", 16, max(1, int(speed_mbps * 0.8) // 1000)
    else:
        mode, divisor, cap = "direct", 32, None
    return LinkDecision(speed_mbps, source, mode, divisor, cap, tuple(egress), tuple(layers), tuple(warnings))


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


def route_egress(destination: str, source: str, run=_run) -> tuple[str, str | None]:
    """(device, next hop or None) of `ip route get <destination> from <source>`."""
    text = run(["ip", "route", "get", destination, "from", source])
    device = re.search(r"\bdev (\S+)", text)
    if device is None:
        raise ValueError("no egress device in route")
    via = re.search(r"\bvia (\S+)", text)
    return device[1], (via[1] if via else None)


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


def detect(switch_addresses, server_address, *, run=_run, sysfs_root=Path("/sys"), override=None) -> LinkDecision:
    """Decide the distribution mode from the server's egress toward every switch."""
    if override is not None:
        return from_override(override)
    try:
        server = str(ipaddress.ip_address(server_address))
    except ValueError:
        return decide(None, source="unknown", warnings=[f"server address {server_address!r} is not an IP address"])
    try:
        if server not in local_addresses(run):
            return decide(None, source="unknown", warnings=[
                f"server address {server} is not on this host; run on the ztp-server or pass --server-link"])
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        return decide(None, source="unknown", warnings=[f"cannot list local addresses: {error}"])
    sysfs = _Sysfs(sysfs_root)
    routes = {}
    for address in switch_addresses:
        try:
            routes.setdefault(route_egress(address, server, run), []).append(address)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            return decide(None, source="unknown", warnings=[f"no route from {server} to {address}: {error}"])
    speeds, layers, warnings, egress = [], [], [], []
    for (device, next_hop) in sorted(routes, key=lambda item: (item[0], item[1] or "")):
        speed, walked, notes = resolve(sysfs, device, run=run, next_hop=next_hop)
        if device not in egress:
            egress.append(device)
        layers += walked
        warnings += notes
        speeds.append(speed)
    if not speeds or any(speed is None for speed in speeds):
        return decide(None, source="unknown", egress=egress, layers=layers,
                      warnings=warnings + ["egress speed unknown; treating the server link as 1G (relay)"])
    if len(set(egress)) > 1:
        warnings.append("switches are reached through several interfaces; using the slowest")
    return decide(min(speeds), source="detected", egress=egress, layers=layers, warnings=warnings)
