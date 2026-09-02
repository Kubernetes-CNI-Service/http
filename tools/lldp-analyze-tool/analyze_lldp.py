#!/usr/bin/env python3
"""Compare expected LLDPq DOT links with the latest Ethernet collection archive."""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable


TOOL_DIR = Path(__file__).resolve().parent
WORKSPACE = TOOL_DIR.parent.parent
CUMULUS_P2P_DIR = WORKSPACE / "ztp" / "config" / "cumulus" / "template" / "P2P"


DOT_EDGE_RE = re.compile(
    r'^\s*"([^"]+)"\s*:\s*"([^"]+)"\s*--\s*'
    r'"([^"]+)"\s*:\s*"([^"]+)"'
)
COMMAND_RE = re.compile(r"^# Execute Command:\s*(.*?)\s*$", re.MULTILINE)
SUCCESS_STATUSES = {"CONFIRMED_BOTH_SIDE", "CONFIRMED_SW_SIDE"}
ARCHIVE_TIMESTAMP_RE = re.compile(
    r"^(?P<timestamp>\d{8}[-_]\d{4})(?:[^/]*)\.(?:tar\.gz|tgz)$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Endpoint:
    device: str
    interface: str


@dataclass(frozen=True)
class ExpectedLink:
    left: Endpoint
    right: Endpoint
    line: int


@dataclass(frozen=True)
class InterfaceState:
    name: str
    admin: str
    oper: str
    speed: str
    kind: str
    remote_host: str
    remote_port: str


@dataclass
class LinkResult:
    link_type: str
    status: str
    device_a: str
    interface_a: str
    device_b: str
    interface_b: str
    detail: str
    dot_line: int


@dataclass(frozen=True)
class UnexpectedLink:
    device_a: str
    interface_a: str
    device_b: str
    interface_b: str
    detail: str


def normalize_device(value: str) -> str:
    return value.strip().rstrip(".").split(".", 1)[0].casefold()


def normalize_interface(value: str) -> str:
    return value.strip().casefold()


def device_names_match(actual: str, expected: str) -> bool:
    """Match exact/short LLDP hostnames after case and domain normalization."""
    actual_name = normalize_device(actual)
    expected_name = normalize_device(expected)
    return bool(
        actual_name
        and expected_name
        and (actual_name in expected_name or expected_name in actual_name)
    )


def natural_key(value: str) -> tuple[tuple[int, object], ...]:
    """Case-insensitive natural key: swp2 sorts before swp10."""
    return tuple(
        (1, int(part)) if part.isdigit() else (0, part.casefold())
        for part in re.split(r"(\d+)", value)
        if part
    )


def endpoint_key(endpoint: Endpoint) -> tuple[str, str]:
    return normalize_device(endpoint.device), normalize_interface(endpoint.interface)


def canonical_link(a: Endpoint, b: Endpoint) -> tuple[tuple[str, str], tuple[str, str]]:
    return tuple(sorted((endpoint_key(a), endpoint_key(b))))  # type: ignore[return-value]


def parse_dot(path: Path) -> list[ExpectedLink]:
    links: list[ExpectedLink] = []
    seen: dict[tuple[tuple[str, str], tuple[str, str]], int] = {}
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = DOT_EDGE_RE.match(raw)
        if not match:
            continue
        link = ExpectedLink(
            Endpoint(match.group(1).strip(), match.group(2).strip()),
            Endpoint(match.group(3).strip(), match.group(4).strip()),
            lineno,
        )
        key = canonical_link(link.left, link.right)
        if key in seen:
            raise ValueError(
                f"duplicate DOT link at lines {seen[key]} and {lineno}: "
                f"{link.left.device}:{link.left.interface} -- "
                f"{link.right.device}:{link.right.interface}"
            )
        seen[key] = lineno
        links.append(link)
    if not links:
        raise ValueError(f"no LLDPq edges found in {path}")
    return links


def load_inventory(path: Path) -> tuple[dict[str, list[str]], list[str]]:
    patterns: dict[str, list[str]] = {}
    order: list[str] = []
    current: str | None = None
    in_meta = False
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            in_meta = False
            continue
        if line.startswith("#"):
            continue
        if line.startswith("[[") and line.endswith("]]" ):
            in_meta, current = True, None
            continue
        if line.startswith("[") and line.endswith("]"):
            if in_meta:
                continue
            current = line[1:-1].strip()
            if current not in patterns:
                patterns[current] = []
                order.append(current)
            continue
        if current is not None and not in_meta:
            patterns[current].append(line)
    return patterns, order


def device_type(name: str, patterns: dict[str, list[str]], order: list[str]) -> str:
    for kind in order:
        if any(fnmatch.fnmatch(name.casefold(), pattern.casefold())
               for pattern in patterns.get(kind, [])):
            return kind
    return "unknown"


def command_output(text: str, command: str) -> str:
    matches = list(COMMAND_RE.finditer(text))
    for index, match in enumerate(matches):
        if match.group(1).strip() == command:
            end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
            return text[match.end():end]
    raise ValueError(f"command section not found: {command}")


def parse_interface_table(text: str) -> dict[str, InterfaceState]:
    section = command_output(text, "nv show interface")
    lines = section.splitlines()
    header_index = next(
        (i for i, line in enumerate(lines)
         if "Interface" in line and "Admin Status" in line and "Oper Status" in line),
        None,
    )
    if header_index is None or header_index + 1 >= len(lines):
        raise ValueError("nv show interface table header not found")
    separator = lines[header_index + 1]
    spans = list(re.finditer(r"-+", separator))
    if len(spans) < 9:
        raise ValueError("nv show interface table has an unsupported column layout")
    starts = [span.start() for span in spans]

    def column(line: str, index: int) -> str:
        end = starts[index + 1] if index + 1 < len(starts) else len(line)
        return line[starts[index]:end].strip() if starts[index] < len(line) else ""

    states: dict[str, InterfaceState] = {}
    for line in lines[header_index + 2:]:
        if line.startswith("#"):
            break
        name = column(line, 0)
        if not name:
            continue
        # Link validation intentionally covers only physical Ethernet-facing
        # interfaces.  Ignore bonds, VLANs, VRFs, bridges, loopbacks and mgmt.
        if not normalize_interface(name).startswith(("eth", "swp")):
            continue
        state = InterfaceState(
            name=name,
            admin=column(line, 1),
            oper=column(line, 2),
            speed=column(line, 3),
            kind=column(line, 5),
            remote_host=column(line, 6),
            remote_port=column(line, 7),
        )
        states[normalize_interface(name)] = state
    if not states:
        raise ValueError("nv show interface table contains no interface rows")
    return states


def archive_snapshots(
    path: Path,
) -> tuple[dict[str, dict[str, InterfaceState]], dict[str, str], list[str]]:
    snapshots: dict[str, dict[str, InterfaceState]] = {}
    display_names: dict[str, str] = {}
    warnings: list[str] = []
    with tarfile.open(path, "r:gz") as archive:
        members = sorted(
            (member for member in archive.getmembers()
             if member.isfile() and member.name.casefold().endswith(".info")),
            key=lambda member: member.name.casefold(),
        )
        if not members:
            raise ValueError(f"no .info files found in {path}")
        for member in members:
            display_name = Path(member.name).stem
            key = normalize_device(display_name)
            if key in snapshots:
                raise ValueError(f"duplicate switch info for {display_name}")
            stream = archive.extractfile(member)
            if stream is None:
                warnings.append(f"cannot read {member.name}")
                continue
            text = stream.read().decode("utf-8", errors="replace")
            try:
                snapshots[key] = parse_interface_table(text)
                display_names[key] = display_name
            except ValueError as exc:
                warnings.append(f"{Path(member.name).name}: {exc}")
    return snapshots, display_names, warnings


def discover_latest_archive(directory: Path) -> Path:
    candidates = [
        path for pattern in ("*.tar.gz", "*.tgz")
        for path in directory.glob(pattern)
        if path.is_file() and not path.name.startswith("._")
    ]
    if not candidates:
        raise ValueError(
            f"no tar.gz/tgz archive found in {directory}. Collect Ethernet "
            f"switch data first with `bash {WORKSPACE / 'ethernet' / 'monitor' / 'cron.sh'} "
            "--type eth`, then rerun this command; or specify an existing archive "
            "with --archive"
        )
    timestamped = [
        (match.group("timestamp").replace("_", "-"), path)
        for path in candidates
        if (match := ARCHIVE_TIMESTAMP_RE.match(path.name)) is not None
    ]
    if timestamped:
        return max(timestamped, key=lambda item: (item[0], item[1].name))[1]
    return max(candidates, key=lambda path: (path.stat().st_mtime_ns, path.name))


def link_archive_input(source: Path, output_dir: Path) -> Path:
    """Create or reuse a relative output-p2p link to an Ethernet archive."""
    source = source.resolve(strict=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_dir = output_dir.resolve()
    destination = output_dir / source.name
    relative_target = Path(os.path.relpath(source, start=output_dir))

    if destination.is_symlink():
        try:
            current = destination.resolve(strict=True)
        except OSError as exc:
            raise ValueError(f"broken eth-info link in output directory: {destination}") from exc
        if current != source:
            raise ValueError(
                f"eth-info link points to a different file: {destination} -> {current}; "
                f"expected {source}"
            )
        if destination.readlink().is_absolute():
            temporary = destination.with_name(f".{destination.name}.relative-link.tmp")
            if temporary.exists() or temporary.is_symlink():
                raise ValueError(f"temporary link path already exists: {temporary}")
            temporary.symlink_to(relative_target)
            os.replace(temporary, destination)
            print(f"[RELINKED] {destination} -> {relative_target}")
        return destination

    if destination.exists():
        if destination.resolve() == source:
            return destination
        raise ValueError(
            f"cannot create eth-info link because path already exists: {destination}"
        )

    destination.symlink_to(relative_target)
    print(f"[LINKED] {destination} -> {relative_target}")
    return destination


def discover_dot(directory: Path) -> Path:
    candidates = [path for path in directory.glob("*-lldpq.dot") if path.is_file()]
    if not candidates:
        raise ValueError(f"no *-lldpq.dot found in {directory}")
    for input_file in (directory.parent / "p2p.xlsx", CUMULUS_P2P_DIR / "p2p.xlsx"):
        if input_file.is_file():
            expected = directory / f"{input_file.resolve().stem}-lldpq.dot"
            if expected.is_file():
                return expected
    if len(candidates) > 1:
        names = ", ".join(sorted(path.name for path in candidates))
        raise ValueError(f"multiple *-lldpq.dot files found; use --dot: {names}")
    return candidates[0]


def expected_peer_matches(state: InterfaceState, peer: Endpoint) -> bool:
    if not state.remote_host:
        return False
    return (
        device_names_match(state.remote_host, peer.device)
        and normalize_interface(state.remote_port) == normalize_interface(peer.interface)
    )


def analyze_link(
    link: ExpectedLink,
    snapshots: dict[str, dict[str, InterfaceState]],
    eth_names: set[str],
) -> LinkResult | None:
    left_is_switch = normalize_device(link.left.device) in eth_names
    right_is_switch = normalize_device(link.right.device) in eth_names
    if not left_is_switch and not right_is_switch:
        return None
    link_type = "SW-SW" if left_is_switch and right_is_switch else "SW-OTHER"
    checks: list[tuple[Endpoint, Endpoint, InterfaceState]] = []
    problems: list[tuple[str, str]] = []
    for local, peer in ((link.left, link.right), (link.right, link.left)):
        local_key = normalize_device(local.device)
        if local_key not in eth_names:
            continue
        if local_key not in snapshots:
            problems.append(("MISSING_DEVICE", f"no collected .info for {local.device}"))
            continue
        state = snapshots[local_key].get(normalize_interface(local.interface))
        if state is None:
            problems.append((
                "MISSING_INTERFACE",
                f"{local.device} has no interface {local.interface} in nv show interface",
            ))
            continue
        checks.append((local, peer, state))
        if state.oper.casefold() != "up":
            problems.append((
                "DOWN",
                f"{local.device}:{local.interface} oper={state.oper or 'unknown'} "
                f"admin={state.admin or 'unknown'}",
            ))
        elif not state.remote_host or not state.remote_port:
            problems.append((
                "NO_LLDP",
                f"{local.device}:{local.interface} is up but has no complete "
                "LLDP Remote Host/Port",
            ))
        elif link_type == "SW-SW" and not expected_peer_matches(state, peer):
            actual = f"{state.remote_host}:{state.remote_port or '?'}"
            expected = f"{peer.device}:{peer.interface}"
            problems.append((
                "WRONG_PEER",
                f"{local.device}:{local.interface} sees {actual}, expected {expected}",
            ))

    priority = [
        "WRONG_PEER", "DOWN", "NO_LLDP", "MISSING_INTERFACE", "MISSING_DEVICE",
    ]
    if problems:
        status = next(name for name in priority if any(p[0] == name for p in problems))
        detail = "; ".join(message for _, message in problems)
    elif link_type == "SW-SW":
        # Both switch endpoints reached this branch, therefore both interfaces
        # are Up and both LLDP records exactly match the opposite DOT endpoint.
        status = "CONFIRMED_BOTH_SIDE"
        detail = "; ".join(
            f"{local.device}:{local.interface} sees "
            f"{state.remote_host}:{state.remote_port}"
            for local, _peer, state in checks
        )
    else:
        # Only the switch-side observation exists for servers, BMCs, firewalls,
        # and similar peers.  An exact advertised identity confirms the switch
        # side; complete but different LLDP data is retained as a mismatch.
        local, peer, state = checks[0]
        status = (
            "CONFIRMED_SW_SIDE"
            if expected_peer_matches(state, peer)
            else "SW_LLDP_PRESENT"
        )
        detail = "; ".join(
            f"{local.device}:{local.interface} is up and reports "
            f"{state.remote_host}:{state.remote_port}"
            for local, _peer, state in checks
        )
    return LinkResult(
        link_type, status, link.left.device, link.left.interface,
        link.right.device, link.right.interface, detail, link.line,
    )


def unexpected_lldp(
    snapshots: dict[str, dict[str, InterfaceState]],
    expected: set[tuple[tuple[str, str], tuple[str, str]]],
    display_names: dict[str, str] | None = None,
) -> list[UnexpectedLink]:
    expected_local_endpoints = {
        endpoint for link in expected for endpoint in link
    }
    unexpected: dict[tuple[str, str], UnexpectedLink] = {}
    for device, interfaces in snapshots.items():
        for state in interfaces.values():
            local = Endpoint(device, state.name)
            if state.oper.casefold() != "up":
                continue
            # A planned local switch port connected to a server/BMC may report
            # aliases or MAC-based remote ports that cannot equal the P2P label.
            # It is still a planned physical port, not an unexpected link.
            if endpoint_key(local) not in expected_local_endpoints:
                display_device = (display_names or {}).get(device, device)
                key = endpoint_key(local)
                unexpected[key] = UnexpectedLink(
                    display_device,
                    state.name,
                    state.remote_host,
                    state.remote_port,
                    "local interface is Up but absent from the expected DOT",
                )
    return sorted(
        unexpected.values(),
        key=lambda item: (
            natural_key(item.device_a), natural_key(item.interface_a),
            natural_key(item.device_b), natural_key(item.interface_b),
        ),
    )


def write_report(
    output_dir: Path,
    archive: Path,
    dot: Path,
    results: list[LinkResult],
    unexpected: list[UnexpectedLink],
    warnings: list[str],
    links: list[ExpectedLink],
    snapshots: dict[str, dict[str, InterfaceState]],
    display_names: dict[str, str],
    eth_names: set[str],
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    archive_base = re.sub(r"\.tar\.gz$|\.tgz$", "", archive.name, flags=re.I)
    output_path = output_dir / f"{archive_base}-ethernet-topology-validation.xlsx"
    expected_endpoints = {
        endpoint_key(endpoint)
        for link in links for endpoint in (link.left, link.right)
    }
    interface_status = []
    for device in sorted(snapshots, key=lambda item: natural_key(display_names.get(item, item))):
        for interface in sorted(snapshots[device], key=natural_key):
            state = snapshots[device][interface]
            interface_status.append({
                "device": display_names.get(device, device),
                **asdict(state),
                "in_p2p": endpoint_key(Endpoint(device, state.name)) in expected_endpoints,
            })

    def endpoint_sort_key(endpoint: Endpoint) -> tuple[object, ...]:
        return natural_key(endpoint.device), natural_key(endpoint.interface)

    def ordered_pair(left: Endpoint, right: Endpoint) -> tuple[Endpoint, Endpoint]:
        if endpoint_sort_key(right) < endpoint_sort_key(left):
            return right, left
        return left, right

    def state_fields(endpoint: Endpoint) -> dict[str, str]:
        state = snapshots.get(normalize_device(endpoint.device), {}).get(
            normalize_interface(endpoint.interface)
        )
        return {
            "admin": state.admin if state else "",
            "oper": state.oper if state else "",
            "remote_host": state.remote_host if state else "",
            "remote_port": state.remote_port if state else "",
        }

    p2p_links = []
    for link in links:
        left, right = ordered_pair(link.left, link.right)
        p2p_links.append({"left": asdict(left), "right": asdict(right), "line": link.line})
    p2p_links.sort(key=lambda item: (
        natural_key(item["left"]["device"]), natural_key(item["left"]["interface"]),
        natural_key(item["right"]["device"]), natural_key(item["right"]["interface"]),
    ))

    result_records = []
    for result in results:
        left = Endpoint(result.device_a, result.interface_a)
        right = Endpoint(result.device_b, result.interface_b)
        if result.link_type == "SW-OTHER":
            if normalize_device(right.device) in eth_names:
                left, right = right, left
        else:
            left, right = ordered_pair(left, right)
        result_records.append({
            **asdict(result),
            "device_a": left.device,
            "interface_a": left.interface,
            "device_b": right.device,
            "interface_b": right.interface,
            "observation_a": state_fields(left),
            "observation_b": state_fields(right),
        })
    result_records.sort(key=lambda item: (
        natural_key(item["device_a"]), natural_key(item["interface_a"]),
        natural_key(item["device_b"]), natural_key(item["interface_b"]),
    ))
    payload = {
        "metadata": {
            "generated_local": datetime.now().astimezone().isoformat(timespec="seconds"),
            "expected_dot": str(dot),
            "collection_archive": str(archive),
            "output": str(output_path),
            "collected_ethernet_switches": len(snapshots),
        },
        "p2p_links": p2p_links,
        "interface_status": interface_status,
        "matching_links": [
            item for item in result_records if item["status"] in SUCCESS_STATUSES
        ],
        "miswired_links": [
            item for item in result_records
            if item["status"] in {"WRONG_PEER", "SW_LLDP_PRESENT", "NO_LLDP"}
        ],
        "missing_links": [
            item for item in result_records
            if item["status"] in {"DOWN", "MISSING_DEVICE", "MISSING_INTERFACE"}
        ],
        "undefined_links": [asdict(item) for item in unexpected],
        "warnings": warnings,
    }
    builder = Path(__file__).with_name("build_report.py")
    if not builder.is_file():
        raise ValueError(f"XLSX report builder not found: {builder}")
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", suffix=".json", delete=False
        ) as stream:
            json.dump(payload, stream, ensure_ascii=False)
            temp_path = Path(stream.name)
        completed = subprocess.run(
            [sys.executable, str(builder), str(temp_path), str(output_path)],
            text=True,
            capture_output=True,
            check=False,
        )
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise ValueError(f"XLSX generation failed: {detail}")
    if not output_path.is_file():
        raise ValueError(f"XLSX builder did not create: {output_path}")
    return output_path


def default_output_directory() -> Path:
    """Return the setup-managed project output link, with legacy fallback."""
    primary = TOOL_DIR / "99-output-p2p"
    legacy = TOOL_DIR / "output-p2p"
    return primary if primary.is_dir() or not legacy.is_dir() else legacy


def associated_archive_directory(output_directory: Path) -> Path:
    """Find the Ethernet collection directory belonging to an output tree."""
    output_directory = output_directory.expanduser().resolve()
    candidates = (
        output_directory.parent / "99-output-monitor" / "ethernet" / "eth-info",
        TOOL_DIR / "99-output-monitor" / "ethernet" / "eth-info",
        CUMULUS_P2P_DIR / "eth-info",
        TOOL_DIR / "eth-info",
    )
    return next((candidate for candidate in candidates if candidate.is_dir()), candidates[0])


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    output_directory = default_output_directory()
    parser = argparse.ArgumentParser(
        description="Compare an expected *-lldpq.dot with nv show interface data.",
    )
    parser.add_argument("--dot", type=Path,
                        help="expected LLDPq DOT (default: unique output-p2p/*-lldpq.dot)")
    parser.add_argument("--archive", type=Path,
                        help="collection tar.gz (default: latest file in eth-info)")
    parser.add_argument(
        "--archive-dir", "--eth-info", dest="archive_dir", type=Path,
        default=None,
        help=("directory containing Ethernet tar.gz snapshots "
              "(default: current project's setup-managed eth-info)"),
    )
    parser.add_argument("--inventory", type=Path, default=CUMULUS_P2P_DIR / "01-inventory.log",
                        help="inventory rules used to identify Eth-SW devices")
    parser.add_argument("--output-dir", type=Path,
                        default=output_directory,
                        help="report directory")
    parser.add_argument("--strict-lldp", action="store_true",
                        help=("deprecated compatibility option; SW-SW and SW-Other "
                              "validation now always require LLDP"))
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        output_dir = args.output_dir.resolve()
        dot = args.dot.resolve() if args.dot else discover_dot(output_dir).resolve()
        if args.archive:
            archive = args.archive.resolve()
        else:
            archive_dir = (
                args.archive_dir.resolve() if args.archive_dir
                else associated_archive_directory(output_dir)
            )
            latest_archive = discover_latest_archive(archive_dir)
            archive = link_archive_input(latest_archive, output_dir)
        inventory = args.inventory.resolve()
        for label, path in (("DOT", dot), ("archive", archive), ("inventory", inventory)):
            if not path.is_file():
                raise ValueError(f"{label} file not found: {path}")
        links = parse_dot(dot)
        snapshots, display_names, warnings = archive_snapshots(archive)
        patterns, order = load_inventory(inventory)
        eth_names = {
            normalize_device(endpoint.device)
            for link in links for endpoint in (link.left, link.right)
            if device_type(endpoint.device, patterns, order).casefold() == "eth-sw"
        }
        # A collected .info file is authoritative evidence that the endpoint is
        # an Ethernet switch, even when its name does not match inventory globs.
        eth_names.update(snapshots)
        results = [
            result for link in links
            if (result := analyze_link(link, snapshots, eth_names)) is not None
        ]
        expected = {canonical_link(link.left, link.right) for link in links}
        unexpected = unexpected_lldp(snapshots, expected, display_names)
        report_path = write_report(
            output_dir, archive, dot, results, unexpected, warnings,
            links, snapshots, display_names, eth_names,
        )
    except (OSError, ValueError, tarfile.TarError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    counts: dict[str, int] = {}
    for result in results:
        counts[result.status] = counts.get(result.status, 0) + 1
    print(f"Expected DOT: {dot}")
    print(f"Latest archive: {archive}")
    print(f"Collected switches: {len(snapshots)}; analyzed links: {len(results)}")
    print("Status: " + "  ".join(f"{key}={counts[key]}" for key in sorted(counts)))
    print(f"Unexpected LLDP links: {len(unexpected)}; collection warnings: {len(warnings)}")
    print(f"Generated: {report_path}")
    failed = any(result.status not in SUCCESS_STATUSES for result in results) or bool(unexpected)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
