#!/usr/bin/env python3
"""Determine whether this collector currently reaches Production or AIR.

Production and AIR may intentionally reuse management IP addresses.  Therefore
an IP address is only a transport endpoint, never an environment identifier.
For addresses present in both inventories this module reads the target's actual
hostname and eth0 MAC over key-authenticated SSH, then matches both values to
the inventory identities.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import re
import subprocess
import sys
from typing import Callable, Iterable, NamedTuple


class Identity(NamedTuple):
    hostname: str
    ip: str
    mac: str
    environment: str
    alternate_ips: tuple[str, ...] = ()


def _norm_hostname(value: str) -> str:
    return (value or "").strip().split(".", 1)[0].lower()


def _norm_mac(value: str) -> str:
    return (value or "").strip().lower().replace("-", ":")


def _valid_mac(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", _norm_mac(value)))


def load_inventory(path: str, environment: str) -> list[Identity]:
    records: list[Identity] = []
    with open(path, newline="", encoding="utf-8-sig") as handle:
        reader = csv.reader(handle)
        header = next(reader, [])
        normalized = [str(name).strip().lower() for name in header]
        fields = {name: index for index, name in enumerate(normalized)}
        required = {"hostname", "eth0_ip", "eth0_mac"}
        missing = sorted(required - fields.keys())
        if missing:
            raise ValueError(f"{path}: missing columns: {', '.join(missing)}")
        eth0_index = fields["eth0_ip"]
        if ("netmask" in normalized
                and (eth0_index + 1 >= len(normalized)
                     or normalized[eth0_index + 1] != "netmask")):
            raise ValueError(f"{path}: eth0_ip must be immediately followed by netmask")
        svi_columns = [index for index, name in enumerate(normalized) if name == "svi_ip"]

        def value(row, name):
            index = fields.get(name)
            return (row[index] if index is not None and index < len(row) else "").strip()

        for row in reader:
            hostname = value(row, "hostname")
            ip = value(row, "eth0_ip")
            mac = value(row, "eth0_mac")
            dev_type = value(row, "type").lower()
            if environment == "air" and dev_type not in {"", "air"}:
                continue
            if environment == "prod" and dev_type not in {"", "eth", "eth_spx", "spx"}:
                continue
            if hostname and ip and ip.upper() != "NA":
                alternates = []
                try:
                    prefix = (
                        row[eth0_index + 1].strip()
                        if eth0_index + 1 < len(row)
                        and normalized[eth0_index + 1] == "netmask"
                        else ""
                    )
                    eth0_network = ipaddress.ip_interface(f"{ip}/{prefix}").network
                except ValueError:
                    eth0_network = None
                if eth0_network is not None:
                    for index in svi_columns:
                        candidate = row[index].strip() if index < len(row) else ""
                        if not candidate or candidate.upper() == "NA":
                            continue
                        try:
                            address = ipaddress.ip_address(candidate)
                        except ValueError:
                            continue
                        if address in eth0_network and str(address) != ip:
                            alternates.append(str(address))
                records.append(Identity(
                    hostname, ip, mac, environment,
                    tuple(dict.fromkeys(alternates)),
                ))
    return records


def overlapping_pairs(prod: Iterable[Identity], air: Iterable[Identity]):
    def by_ip(records, label):
        result = {}
        for item in records:
            if item.ip in result:
                raise ValueError(
                    f"duplicate {label} eth0 IP {item.ip}: "
                    f"{result[item.ip].hostname}, {item.hostname}"
                )
            result[item.ip] = item
        return result
    prod_by_ip = by_ip(prod, "Production")
    air_by_ip = by_ip(air, "AIR")
    return [(prod_by_ip[ip], air_by_ip[ip]) for ip in sorted(prod_by_ip.keys() & air_by_ip.keys())]


def classify_identity(actual_hostname: str, actual_mac: str, prod: Identity, air: Identity):
    """Return air/prod/None; contradictory hostname and MAC are fatal."""
    actual_hn = _norm_hostname(actual_hostname)
    actual_mac = _norm_mac(actual_mac)
    signals: list[str] = []
    if actual_hn:
        hostname_matches = {
            environment for environment, value in (
                ("prod", prod.hostname), ("air", air.hostname)
            ) if actual_hn == _norm_hostname(value)
        }
        if len(hostname_matches) == 1:
            signals.extend(hostname_matches)
        elif not hostname_matches:
            raise RuntimeError(
                f"unknown hostname at {prod.ip}: {actual_hostname!r}"
            )
    expected_macs = {
        environment: _norm_mac(value) for environment, value in (
            ("prod", prod.mac), ("air", air.mac)
        ) if _valid_mac(value)
    }
    if expected_macs:
        if not _valid_mac(actual_mac):
            raise RuntimeError(f"cannot read a valid eth0 MAC at {prod.ip}: {actual_mac!r}")
        mac_matches = {
            environment for environment, value in expected_macs.items()
            if actual_mac == value
        }
        if len(mac_matches) == 1:
            signals.extend(mac_matches)
        elif not mac_matches:
            raise RuntimeError(f"unknown eth0 MAC at {prod.ip}: {actual_mac!r}")
    if len(set(signals)) > 1:
        raise RuntimeError(
            f"identity conflict at {prod.ip}: hostname={actual_hostname!r}, mac={actual_mac!r}"
        )
    return signals[0] if signals else None


def ssh_identity(ip: str, user: str = "cumulus", timeout: int = 5):
    command = [
        "ssh", "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
        "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR", "-o", f"ConnectTimeout={timeout}",
        f"{user}@{ip}",
        "hostname -s 2>/dev/null; cat /sys/class/net/eth0/address 2>/dev/null",
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout + 2)
    if result.returncode != 0:
        return None
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return (lines[0] if lines else "", lines[1] if len(lines) > 1 else "")


def detect_environment(
    inventory_path: str,
    user: str = "cumulus",
    timeout: int = 5,
    max_probes: int = 10,
    probe: Callable[[str, str, int], tuple[str, str] | None] = ssh_identity,
):
    pairs = overlapping_pairs(
        load_inventory(inventory_path, "prod"),
        load_inventory(inventory_path, "air"),
    )
    if not pairs:
        raise RuntimeError("Production/AIR inventories have no overlapping eth0 IP to probe")
    votes: list[str] = []
    details = []
    for prod, air in pairs[:max_probes]:
        # AIR rows intentionally omit generated configuration fields.  The
        # Production twin supplies same-subnet SVI transport fallbacks while
        # hostname/MAC remain the authoritative environment identity.
        transport_ip = None
        actual = None
        attempts = []
        for candidate in dict.fromkeys((prod.ip, *prod.alternate_ips, *air.alternate_ips)):
            actual = probe(candidate, user, timeout)
            attempts.append(candidate)
            if actual:
                transport_ip = candidate
                break
        if not actual:
            details.append({
                "ip": prod.ip, "attempts": attempts,
                "result": "unreachable-or-key-auth-failed",
            })
            continue
        environment = classify_identity(actual[0], actual[1], prod, air)
        details.append({
            "ip": prod.ip, "connected_ip": transport_ip,
            "hostname": actual[0], "eth0_mac": actual[1],
            "environment": environment or "unknown",
        })
        if environment:
            votes.append(environment)
    if not votes:
        raise RuntimeError("cannot identify environment: no probe matched hostname or eth0 MAC")
    if len(set(votes)) != 1:
        raise RuntimeError(f"inconsistent environment probe results: {votes}")
    return votes[0], details


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True, help="Unified devices_config CSV")
    parser.add_argument("--user", default="cumulus")
    parser.add_argument("--timeout", type=int, default=5)
    parser.add_argument("--max-probes", type=int, default=10)
    parser.add_argument("--json", action="store_true")
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--type", choices=("auto", "prod", "air"), dest="expected")
    selection.add_argument("--air", action="store_const", const="air", dest="expected")
    selection.add_argument("--prod", action="store_const", const="prod", dest="expected")
    parser.set_defaults(expected="auto")
    args = parser.parse_args(argv)
    try:
        environment, details = detect_environment(
            os.path.abspath(args.inventory), args.user, args.timeout, args.max_probes,
        )
        if args.expected != "auto" and environment != args.expected:
            raise RuntimeError(
                f"reachable environment is {environment}, not requested {args.expected}"
            )
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps({"environment": environment, "probes": details}, ensure_ascii=False))
    else:
        print(environment)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
