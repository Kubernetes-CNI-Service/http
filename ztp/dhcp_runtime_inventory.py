#!/usr/bin/env python3
"""Build a read-only inventory of DHCP clients not yet bound to project MACs.

The parser consumes ``ZTP_DHCP_EVENT_V1`` records emitted by
``config/isc-dhcp-server/c1-generate_dhcp.py`` plus the ISC DHCP lease file.
It never edits ``02-devices_config.csv`` and never assigns an observed MAC to a
planned hostname; that binding requires an operator's physical/topology check.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable, Optional


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_INVENTORY = SCRIPT_DIR / "config/isc-dhcp-server/02-devices_config.csv"
DEFAULT_LEASES = Path("/var/lib/dhcp/dhcpd.leases")
_EVENT_MARKER = "ZTP_DHCP_EVENT_V1 "
_MAC_RE = re.compile(r"^[0-9a-f]{12}$")
_LEASE_RE = re.compile(r"(?ms)^lease\s+(\S+)\s*\{(.*?)^[ \t]*\}")


def normalize_mac(value: str) -> Optional[str]:
    pieces = re.split(r"[:-]", (value or "").strip())
    if len(pieces) == 6 and all(re.fullmatch(r"[0-9A-Fa-f]{1,2}", item) for item in pieces):
        return ":".join(item.zfill(2).lower() for item in pieces)
    raw = re.sub(r"[^0-9A-Fa-f]", "", value or "").lower()
    if not _MAC_RE.fullmatch(raw):
        return None
    return ":".join(raw[index:index + 2] for index in range(0, 12, 2))


def _parse_timestamp(prefix: str, now: Optional[dt.datetime] = None) -> Optional[dt.datetime]:
    now = now or dt.datetime.now().astimezone()
    iso = re.search(r"(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?)", prefix)
    if iso:
        value = iso.group(1).replace(" ", "T", 1).replace("Z", "+00:00")
        try:
            parsed = dt.datetime.fromisoformat(value)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=now.tzinfo)
            return parsed
        except ValueError:
            pass
    traditional = re.search(
        r"(?:^|\s)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
        r"(\d{1,2})\s+(\d\d:\d\d:\d\d)", prefix,
    )
    if traditional:
        try:
            parsed = dt.datetime.strptime(
                f"{now.year} {' '.join(traditional.groups())}",
                "%Y %b %d %H:%M:%S",
            ).replace(tzinfo=now.tzinfo)
            # A December log parsed during early January belongs to last year.
            if parsed - now > dt.timedelta(days=2):
                parsed = parsed.replace(year=parsed.year - 1)
            return parsed
        except ValueError:
            pass
    return None


def _hex_option(value: str) -> str:
    """Decode colon-delimited ISC binary-to-ascii output as printable text."""
    if not value or value == "-":
        return ""
    pieces = value.split(":")
    try:
        payload = bytes(int(piece, 16) for piece in pieces if piece != "")
    except ValueError:
        return ""
    # Only expose printable text; binary client identifiers remain represented
    # by the safe hex field in the source log and are not copied into the JSON.
    text = payload.decode("utf-8", errors="replace")
    return "".join(char for char in text if char.isprintable()).strip()


def _normalize_user_class(value: str) -> str:
    if value.startswith("NVOS-ZTP"):
        return value
    # RFC 3004 user-class data can contain an initial one-byte string length.
    if len(value) > 1 and value[1:].startswith("NVOS-ZTP"):
        return value[1:]
    return value


def _platform(vendor60: str, client61: str, user77: str):
    if vendor60.casefold().startswith("cumulus"):
        return "cumulus", None, None
    if client61.startswith("NVOS##"):
        parts = client61.split("##")
        product = parts[1].strip() if len(parts) > 1 and parts[1].strip() else None
        serial = parts[2].strip() if len(parts) > 2 and parts[2].strip() else None
        return "nvos", product, serial
    if _normalize_user_class(user77).startswith("NVOS-ZTP"):
        return "nvos", None, None
    return "unknown", None, None


def _event_fields(line: str):
    if _EVENT_MARKER not in line:
        return None
    prefix, payload = line.split(_EVENT_MARKER, 1)
    fields = {}
    for token in payload.strip().split():
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        fields[key] = value
    mac = normalize_mac(fields.get("mac", ""))
    if not mac:
        return None
    fields["mac"] = mac
    fields["timestamp"] = _parse_timestamp(prefix)
    return fields


def parse_event_lines(lines: Iterable[str]):
    """Parse V1 event lines into the latest merged observation per MAC."""
    observations = {}
    sequence = 0
    for line in lines:
        event = _event_fields(line)
        if event is None:
            continue
        sequence += 1
        mac = event["mac"]
        observed = observations.setdefault(mac, {
            "mac": mac, "ip": None, "last_lease_ip": None, "known": None,
            "vendor60": "", "client61": "", "user77": "",
            "last_seen_dt": None, "lease_state": "observed", "sequence": 0,
        })
        timestamp = event.get("timestamp")
        newer = (
            observed["last_seen_dt"] is None or timestamp is None
            or timestamp >= observed["last_seen_dt"]
        )
        if not newer:
            continue
        observed["sequence"] = sequence
        if timestamp is not None:
            observed["last_seen_dt"] = timestamp
        ip = event.get("ip", "")
        normalized_ip = None
        if ip and ip != "-":
            try:
                normalized_ip = str(ipaddress.ip_address(ip))
            except ValueError:
                pass
        known = event.get("known")
        if known in {"0", "1"}:
            observed["known"] = known == "1"
        for field in ("vendor60", "client61", "user77"):
            decoded = _hex_option(event.get(f"{field}_hex", ""))
            if decoded:
                observed[field] = decoded
        state = event.get("lease_state")
        if state:
            observed["lease_state"] = state
            if state in {"released", "expired", "free", "abandoned", "backup"}:
                observed["last_lease_ip"] = (
                    normalized_ip or observed.get("ip") or observed.get("last_lease_ip")
                )
                observed["ip"] = None
            elif normalized_ip:
                observed["ip"] = normalized_ip
                observed["last_lease_ip"] = normalized_ip
        elif event.get("event") == "packet":
            observed["lease_state"] = observed.get("lease_state") or "observed"
            if normalized_ip:
                observed["ip"] = normalized_ip
                observed["last_lease_ip"] = normalized_ip
        elif normalized_ip:
            observed["ip"] = normalized_ip
            observed["last_lease_ip"] = normalized_ip
    return observations


def _lease_time(body: str, field: str, tzinfo) -> Optional[dt.datetime]:
    match = re.search(
        rf"(?m)^\s*{re.escape(field)}\s+\d+\s+(\d{{4}}/\d\d/\d\d\s+\d\d:\d\d:\d\d);",
        body,
    )
    if not match:
        return None
    try:
        # ISC lease timestamps are UTC unless configured otherwise.
        return dt.datetime.strptime(match.group(1), "%Y/%m/%d %H:%M:%S").replace(
            tzinfo=dt.timezone.utc
        ).astimezone(tzinfo)
    except ValueError:
        return None


def _lease_records_by_address(
    text: str, now: Optional[dt.datetime] = None,
) -> dict[str, tuple[int, dict]]:
    """Return the final ISC lease-file block for each address."""
    now = now or dt.datetime.now().astimezone()
    records_by_address = {}
    for sequence, match in enumerate(_LEASE_RE.finditer(text or "")):
        ip, body = match.groups()
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            continue
        hardware = re.search(r"(?mi)^\s*hardware\s+ethernet\s+([^;]+);", body)
        mac = normalize_mac(hardware.group(1)) if hardware else None
        state_match = re.search(r"(?mi)^\s*binding\s+state\s+(\S+);", body)
        state = state_match.group(1).casefold() if state_match else "unknown"
        starts = _lease_time(body, "starts", now.tzinfo)
        ends = _lease_time(body, "ends", now.tzinfo)
        if state == "active" and ends is not None and ends <= now:
            state = "expired"
        # Keep even a no-MAC/free final block so it invalidates an earlier
        # active owner of this address.  Such a block is filtered below.
        records_by_address[ip] = (sequence, {
            "mac": mac,
            "ip": ip,
            "lease_state": state,
            "last_seen_dt": starts or ends,
            "lease_ends_dt": ends,
        })
    return records_by_address


def parse_leases(text: str, now: Optional[dt.datetime] = None):
    """Return live/audit lease state without preserving a reassigned address.

    ISC appends state blocks by *address*.  Resolving by MAC first can leave an
    earlier client active after the same address has been released or assigned
    to another MAC.  Select the final block for each address first, then merge
    those final records by MAC in file order.
    """
    records_by_address = _lease_records_by_address(text, now)

    leases = {}
    for _sequence, record in sorted(records_by_address.values(), key=lambda item: item[0]):
        mac = record.get("mac")
        if mac:
            leases[mac] = record
    return leases


def inventory_macs(path: Optional[os.PathLike]):
    known = set()
    if not path:
        return known
    try:
        with open(path, newline="", encoding="utf-8-sig") as stream:
            reader = csv.DictReader(stream)
            for row in reader:
                for name, value in row.items():
                    if name and name.strip().casefold() in {"eth0_mac", "eth1_mac"}:
                        mac = normalize_mac(value or "")
                        if mac:
                            known.add(mac)
    except OSError:
        return known
    return known


def unknown_dhcp_devices(
    *, log_paths=(), lease_path=None, inventory_path=None, journal_text=None,
    include_known=False,
):
    """Return runtime DHCP observations, suppressing already-bound MACs.

    This function is intentionally read-only and returns no planned hostname.
    """
    lines = []
    for path in log_paths or ():
        try:
            with open(path, encoding="utf-8", errors="replace") as stream:
                lines.extend(stream)
        except OSError:
            continue
    if journal_text:
        lines.extend(journal_text.splitlines())
    observations = parse_event_lines(lines)
    lease_records = {}
    lease_address_records = {}
    if lease_path:
        try:
            lease_text = Path(lease_path).read_text(
                encoding="utf-8", errors="replace",
            )
            lease_address_records = _lease_records_by_address(lease_text)
            lease_records = parse_leases(lease_text)
        except OSError:
            pass

    # A final lease block is authoritative for its address even when it has no
    # hardware line (for example ``free``).  Invalidate older journal owners
    # before merging the final MAC records, so one reassigned IP can never stay
    # live under two identities.
    for address, (_sequence, address_record) in lease_address_records.items():
        owner = address_record.get("mac")
        state = str(address_record.get("lease_state") or "unknown").casefold()
        for mac, observed in observations.items():
            if observed.get("ip") != address:
                continue
            if state in {"active", "observed"} and mac == owner:
                continue
            observed["last_lease_ip"] = address
            observed["ip"] = None
            observed["lease_state"] = (
                "reassigned"
                if state in {"active", "observed"} and owner and mac != owner
                else state
            )
    for mac, lease in lease_records.items():
        current = observations.setdefault(mac, {
            "mac": mac, "ip": None, "last_lease_ip": None, "known": None,
            "vendor60": "", "client61": "", "user77": "",
            "last_seen_dt": None, "lease_state": "unknown", "sequence": 0,
        })
        lease_seen = lease.get("last_seen_dt")
        observation_seen = current.get("last_seen_dt")
        lease_is_authoritative = (
            observation_seen is None
            or (lease_seen is not None and lease_seen >= observation_seen)
        )
        if lease_is_authoritative:
            lease_state = str(lease.get("lease_state") or "unknown").casefold()
            lease_ip = lease.get("ip")
            if lease_seen is not None:
                current["last_seen_dt"] = lease_seen
            current["lease_state"] = lease_state
            current["lease_ends_dt"] = lease.get("lease_ends_dt")
            if lease_ip:
                current["last_lease_ip"] = lease_ip
            current["ip"] = (
                lease_ip if lease_state in {"active", "observed"} else None
            )
        elif not current.get("last_lease_ip") and lease.get("ip"):
            # Keep an old address only as audit context.  It is never a live
            # transport candidate when a newer journal observation exists.
            current["last_lease_ip"] = lease["ip"]

    bound_macs = inventory_macs(inventory_path)
    result = []
    for mac, item in observations.items():
        bound = mac in bound_macs or item.get("known") is True
        if bound and not include_known:
            continue
        platform, product, serial = _platform(
            item.get("vendor60", ""), item.get("client61", ""),
            item.get("user77", ""),
        )
        issues = []
        if platform == "unknown":
            issues.append("platform_unknown")
        if not item.get("ip"):
            issues.append("lease_ip_unknown")
        if item.get("lease_state") not in {"active", "observed"}:
            issues.append(f"lease_{item.get('lease_state') or 'unknown'}")
        last_seen = item.get("last_seen_dt")
        lease_ends = item.get("lease_ends_dt")
        result.append({
            "mac_plain": mac.replace(":", ""),
            "mac": mac,
            "ip": item.get("ip"),
            "last_lease_ip": item.get("last_lease_ip"),
            "platform": platform,
            "product": product,
            "serial": serial,
            "last_seen": last_seen.isoformat(timespec="seconds") if last_seen else None,
            "lease_state": item.get("lease_state") or "unknown",
            "lease_ends": lease_ends.isoformat(timespec="seconds") if lease_ends else None,
            "known": bound,
            "fingerprints": {
                "vendor60": item.get("vendor60") or None,
                "client61": item.get("client61") or None,
                "user77": _normalize_user_class(item.get("user77", "")) or None,
            },
            "issues": issues,
        })
    result.sort(key=lambda item: (item["last_seen"] or "", item["mac"]), reverse=True)
    return result


def _journal_text(since: str):
    command = [
        "journalctl", "--no-pager", "-o", "short-iso-precise",
        "-u", "isc-dhcp-server", "--since", since,
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        print(f"[WARN] journalctl 读取失败：{result.stderr.strip()}", file=sys.stderr)
        return ""
    return result.stdout


def _default_output():
    conf = SCRIPT_DIR / "config/isc-dhcp-server/dhcpd.conf"
    return Path(os.path.realpath(conf)).parent / "dhcp-runtime-inventory.json"


def _atomic_json(path: Path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dhcp-log", action="append", default=[], metavar="PATH")
    parser.add_argument("--journal", action="store_true", help="同时读取 isc-dhcp-server journal")
    parser.add_argument("--journal-since", default="-7 days")
    parser.add_argument("--leases", default=str(DEFAULT_LEASES))
    parser.add_argument("--inventory", default=str(DEFAULT_INVENTORY))
    parser.add_argument("--output", default=str(_default_output()))
    parser.add_argument("--include-known", action="store_true")
    parser.add_argument("--format", choices=("json",), default="json")
    parser.add_argument("--stdout", action="store_true")
    args = parser.parse_args(argv)

    log_paths = list(args.dhcp_log)
    if not log_paths:
        log_paths = [path for path in ("/var/log/syslog", "/var/log/daemon.log")
                     if os.path.isfile(path)]
    journal = _journal_text(args.journal_since) if args.journal else ""
    devices = unknown_dhcp_devices(
        log_paths=log_paths,
        lease_path=args.leases,
        inventory_path=args.inventory,
        journal_text=journal,
        include_known=args.include_known,
    )
    payload = {
        "schema_version": 1,
        "generated_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "source_contract": "ZTP_DHCP_EVENT_V1",
        "count": len(devices),
        "devices": devices,
    }
    if args.stdout:
        json.dump(payload, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        output = Path(args.output)
        _atomic_json(output, payload)
        print(f"[OK] 未绑定 DHCP 设备：{len(devices)} 台；{output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
