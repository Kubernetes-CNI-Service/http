"""Inventory consistency: is a network CSV the same as 02-devices_config.csv, or a subset of it (R-016; M4).

compare(subset_path, master_path) returns one Mismatch per difference, in the order of the subset file;
an empty list means consistent.  The rule is the owner's (需求文档 R-016, owner 2026-11-05, Codex RV31-16):
- the header (column names) is the same and has the hostname and type columns; otherwise one HEADER
  record and nothing else is compared;
- every subset row has a master row with the same host name (found by trimmed, casefolded name), and
  every column is equal; the host-name column itself is then compared as written, so a case change is
  reported;
- the only allowed difference: type eth_jump in the subset where the master has an Ethernet type
  (eth, eth_spx, spx; not air; P3b point 10, the same set as setup's _ETH_TYPES);
- cells are compared after trimming surrounding blanks only; eth0_mac and eth1_mac are compared after
  tools/device_identity.normalize_mac (an unrecognised MAC is a difference); other MAC-like columns
  such as bond_mac are compared as text;
- extra master rows are fine; a subset that is a link to the master passes because both are read.

Columns are compared by position (the template repeats netmask, vlan_id, svi_ip, ...); a repeated name
carries its occurrence, e.g. netmask#2.  Files are read as utf-8-sig and whole-blank rows are skipped;
line numbers are those of the subset file.

Library module: only a callee.  It reads the two files and returns records; the caller prints them and
exits 2 (bringup P1, initial-setup, upgrade v2, ufm-setup-upgrade).  Import it as tools.inventory_subset
with the repository root on sys.path.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Union

from tools.device_identity import normalize_mac

ETHERNET_TYPES = frozenset({"eth", "eth_spx", "spx"})
JUMP_TYPE = "eth_jump"
MAC_COLUMNS = frozenset({"eth0_mac", "eth1_mac"})
HEADER, NOT_IN_MASTER, DUPLICATE, VALUE, TYPE_NOT_ALLOWED = (
    "header", "not-in-master", "duplicate", "value", "type-not-allowed")


@dataclass(frozen=True)
class Mismatch:
    """One difference.  Row-level kinds (NOT_IN_MASTER, DUPLICATE) name the hostname column; HEADER gives
    both headers joined by commas and no host name, and names the missing columns when the headers are
    the same but lack hostname or type."""
    line: int
    hostname: str
    column: str
    subset_value: str
    master_value: str
    kind: str


def _rows(path: Union[str, Path]) -> list[tuple[int, list[str]]]:
    rows = []
    with open(path, encoding="utf-8-sig", newline="") as handle:
        reader = csv.reader(handle)
        for row in reader:
            cells = [cell.strip() for cell in row]
            if any(cells):
                rows.append((reader.line_num, cells))
    return rows


def compare(subset_path: Union[str, Path], master_path: Union[str, Path]) -> list[Mismatch]:
    subset, master = _rows(subset_path), _rows(master_path)
    header = subset[0][1] if subset else []
    master_header = master[0][1] if master else []
    if header != master_header:
        return [Mismatch(subset[0][0] if subset else 1, "", "", ",".join(header), ",".join(master_header), HEADER)]
    # The same header without the host-name or type column (two empty files included) is a header
    # problem too: one HEADER record naming the missing columns, never a bare exception (review A4).
    missing = [name for name in ("hostname", "type") if name not in header]
    if missing:
        return [Mismatch(subset[0][0] if subset else 1, "", ",".join(missing), ",".join(header),
                         ",".join(master_header), HEADER)]

    columns, seen_names = [], {}
    for name in header:
        seen_names[name] = seen_names.get(name, 0) + 1
        columns.append(name if seen_names[name] == 1 else f"{name}#{seen_names[name]}")
    host, kind = header.index("hostname"), header.index("type")
    by_host: dict[str, list[str]] = {}
    for _, cells in master[1:]:
        by_host.setdefault(cells[host].casefold(), cells)

    records, seen_hosts = [], set()
    for line, cells in subset[1:]:
        name = cells[host]
        if name.casefold() in seen_hosts:
            records.append(Mismatch(line, name, columns[host], name, "", DUPLICATE))
            continue
        seen_hosts.add(name.casefold())
        other = by_host.get(name.casefold())
        if other is None:
            records.append(Mismatch(line, name, columns[host], name, "", NOT_IN_MASTER))
            continue
        width = max(len(cells), len(other))
        cells, other = cells + [""] * (width - len(cells)), other + [""] * (width - len(other))
        for index, (mine, theirs) in enumerate(zip(cells, other)):
            if mine == theirs:
                continue
            column = columns[index] if index < len(columns) else f"#{index + 1}"
            found = VALUE
            if index == kind and mine == JUMP_TYPE:
                if theirs in ETHERNET_TYPES:
                    continue
                found = TYPE_NOT_ALLOWED
            elif index < len(header) and header[index] in MAC_COLUMNS:
                try:
                    if normalize_mac(mine) == normalize_mac(theirs):
                        continue
                except ValueError:
                    pass   # an unrecognised MAC is a difference
            records.append(Mismatch(line, name, column, mine, theirs, found))
    return records
