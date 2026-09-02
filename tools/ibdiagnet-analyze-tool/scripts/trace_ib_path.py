#!/usr/bin/env python3
"""
trace_ib_path.py — Trace a hop-by-hop InfiniBand path given a source HCA GUID
and a directed-route port-sequence string.

Usage:
    python scripts/trace_ib_path.py -s 0x946dae03000ec710 -p 0,1,23,18,25 -i <ibdiagnet_folder>

Output is printed to stdout; no Excel workbook is produced. See specification.MD §5
for full semantics (plane merging, bfill, N/A handling, etc.).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

# Allow running from repo root without installation.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.parsers.db_csv import extract_section, is_xdr
from lib.parsers.net_dump import parse_links
from lib.inventory import (
    NODE_TYPE_HCA,
    NODE_TYPE_SWITCH,
    _normalize_guid,
    build_node_type_map,
    split_hca_desc,
)
from lib.reporting import SEP


# ─── CLI ─────────────────────────────────────────────────────────────────────


def _parse_path(s: str) -> list[int]:
    """Parse '0,1,23,18,25' → [0, 1, 23, 18, 25] with validation."""
    try:
        tokens = [int(t.strip()) for t in s.split(",") if t.strip()]
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"--path tokens must be integers (got: {s!r})"
        ) from exc
    if len(tokens) < 2:
        raise argparse.ArgumentTypeError(
            f"--path must contain at least 2 tokens (got {len(tokens)}: {s!r})"
        )
    if tokens[0] != 0:
        raise argparse.ArgumentTypeError(
            f"--path token 0 must be literal 0 (got: {tokens[0]})"
        )
    if tokens[1] < 1:
        raise argparse.ArgumentTypeError(
            f"--path token 1 (HCA egress IB port) must be ≥ 1 (got: {tokens[1]})"
        )
    for i, tok in enumerate(tokens[2:], start=2):
        if tok < 1:
            raise argparse.ArgumentTypeError(
                f"--path token {i} (switch egress IB port) must be ≥ 1 (got: {tok})"
            )
    return tokens


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Trace a hop-by-hop InfiniBand path from a source HCA."
    )
    p.add_argument(
        "-s", "--src-guid", required=True, metavar="GUID",
        help="Source HCA Node GUID (e.g. 0x946dae03000ec710). Must be an HCA.",
    )
    p.add_argument(
        "-p", "--path", required=True, metavar="TOKENS", type=_parse_path,
        help="Directed-route port sequence (e.g. 0,1,23,18,25). "
             "Token 0 is literal 0 (source placeholder); token 1 is the HCA's "
             "egress IB port; remaining tokens are switch egress IB ports.",
    )
    p.add_argument(
        "-i", "--ibdiagnet", required=True, metavar="FOLDER",
        help="Path to ibdiagnet2 dump folder (NDR or XDR auto-detected).",
    )
    return p.parse_args()


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _strip_switch_hostname(desc: str) -> str:
    """'MF0;PG21A-R10-IB:Q3400_RA/U2' → 'PG21A-R10-IB'."""
    d = str(desc)
    if d.startswith("MF0;"):
        d = d[4:]
    colon = d.rfind(":")
    if colon > 0:
        d = d[:colon]
    return d


def _hca_display(desc: str) -> tuple[str, str]:
    """(display_device_name, phy_port_for_trace) — factory descriptors → phy port 'N/A'.

    Wraps `split_hca_desc()` (the canonical helper) and maps `None` port → 'N/A'
    for the CLI rendering layer.
    """
    dev, port = split_hca_desc(desc)
    return dev, (port if port is not None else "N/A")


# ─── Link-table construction ─────────────────────────────────────────────────


def build_trace_links(ibdiagnet_dir: Path, ntmap: dict[str, str]) -> pd.DataFrame:
    """Parse net_dump and produce a per-plane, bfilled, bidirectional link table
    suitable for plane-robust tracing.

    See specification.MD §5 (XDR handling — logical-link level with plane bfill)
    for the full pipeline.

    Returns an empty DataFrame if net_dump is missing or yields no rows.
    """
    net_dump_path = ibdiagnet_dir / "ibdiagnet2.net_dump"
    if not net_dump_path.exists():
        return pd.DataFrame()

    links = parse_links(net_dump_path)
    if links.empty:
        return pd.DataFrame()

    xdr = is_xdr(ibdiagnet_dir)

    # 1. Normalize this-side sw_guid to lowercase/padded 16-hex (raw per-ASIC GUID still).
    links["sw_guid_raw"] = links["sw_guid"].map(_normalize_guid)

    # 2. Build switch_hostname → {plane_N: asic_N_guid} from block headers.
    header_map: dict[str, dict[int, str]] = {}
    for _, r in links.drop_duplicates(subset=["hostname", "plane"]).iterrows():
        hn = r["hostname"]
        if not hn:
            continue
        pl = int(r["plane"]) if pd.notna(r["plane"]) else 0
        header_map.setdefault(hn, {})[pl] = r["sw_guid_raw"]

    def _u1_for(hn: str) -> str:
        """Canonical U1 GUID for a switch hostname — falls back to lowest-plane."""
        planes = header_map.get(hn)
        if not planes:
            return ""
        if 1 in planes:
            return planes[1]
        return planes[min(planes)]

    host_to_u1 = {hn: _u1_for(hn) for hn in header_map}

    # 3. Normalise this-side sw_guid per row → U1 canonical (via host_to_u1).
    links["sw_guid"] = links["hostname"].map(lambda hn: host_to_u1.get(hn, ""))

    # 4. Per-row canonical_neighbor_guid + neighbor_type + neighbor_hostname.
    def _nbr_fields(row):
        ng_raw = str(row.get("neighbor_guid", "")).strip()
        desc = str(row.get("neighbor_desc", "")).strip()
        if not ng_raw:
            return pd.NA, pd.NA, pd.NA
        ng_norm = _normalize_guid(ng_raw)
        nt = ntmap.get(ng_norm, "")
        if nt == NODE_TYPE_SWITCH:
            nbr_host = _strip_switch_hostname(desc) if desc else ""
            u1 = host_to_u1.get(nbr_host, ng_norm)
            return u1, "switch", nbr_host if nbr_host else pd.NA
        if nt == NODE_TYPE_HCA:
            # split_hca_desc() yields the full whitespace-normalised descriptor
            # for factory-default entries ("MT4131 ConnectX8   Mellanox Technologies")
            # and the hostname portion for personalised entries ("host mlx5_0" → "host").
            if not desc:
                return ng_norm, "HCA", pd.NA
            return ng_norm, "HCA", split_hca_desc(desc)[0]
        # Router / unknown — keep raw type string and raw neighbor name.
        return ng_norm, (nt if nt else pd.NA), desc if desc else pd.NA

    nbr = links.apply(_nbr_fields, axis=1, result_type="expand")
    nbr.columns = ["canonical_neighbor_guid", "neighbor_type", "neighbor_hostname"]
    links = pd.concat([links, nbr], axis=1)

    # Normalize empty strings / stray pandas NA markers for the bfill columns.
    links["neighbor_phys_port"] = links["neighbor_phys_port"].where(
        links["neighbor_phys_port"].astype(str).str.len() > 0, pd.NA
    )
    links["neighbor_desc"] = links["neighbor_desc"].where(
        links["neighbor_desc"].astype(str).str.len() > 0, pd.NA
    )

    # 5. Group by (hostname, phys_port) + bfill plane-invariant columns.
    bfill_cols = [
        "canonical_neighbor_guid", "neighbor_type",
        "neighbor_hostname", "neighbor_phys_port", "neighbor_desc",
    ]
    if xdr:
        links = links.sort_values(["hostname", "phys_port", "plane"]).reset_index(drop=True)
        with pd.option_context("future.no_silent_downcasting", True):
            links[bfill_cols] = (
                links.groupby(["hostname", "phys_port"])[bfill_cols]
                .transform(lambda g: g.bfill().ffill())
            )

    # 6. Derive neighbor_ib_port (AFTER bfill; see spec rule 7).
    # Reverse lookup: (sw_u1_guid, phys_port) → ib_port for switch-side lookups.
    # Since we've normalized sw_guid to U1 for every row, the first-seen pair
    # per (sw_u1_guid, phys_port) is sufficient (all planes agree on ib_port).
    sw_port_ib: dict[tuple[str, str], int] = {}
    for _, r in links.iterrows():
        key = (r["sw_guid"], r["phys_port"])
        if key not in sw_port_ib and pd.notna(r.get("ib_port")):
            sw_port_ib[key] = int(r["ib_port"])

    def _nbr_ib_port(row):
        nt = row.get("neighbor_type")
        if pd.isna(nt) or nt == "":
            return pd.NA
        if nt == "HCA":
            # HCA IB port = this row's plane number (NDR has plane=1 from /U1).
            pl = row.get("plane")
            try:
                return int(pl) if pd.notna(pl) and int(pl) > 0 else 1
            except (TypeError, ValueError):
                return 1
        if nt == "switch":
            nbr_u1 = row.get("canonical_neighbor_guid")
            nbr_pp = row.get("neighbor_phys_port")
            if pd.isna(nbr_u1) or pd.isna(nbr_pp):
                return pd.NA
            return sw_port_ib.get((nbr_u1, nbr_pp), pd.NA)
        # Router or unknown — best effort reverse lookup.
        nbr_u1 = row.get("canonical_neighbor_guid")
        nbr_pp = row.get("neighbor_phys_port")
        if pd.isna(nbr_u1) or pd.isna(nbr_pp):
            return pd.NA
        return sw_port_ib.get((nbr_u1, nbr_pp), pd.NA)

    links["neighbor_ib_port"] = links.apply(_nbr_ib_port, axis=1)

    # 7. Keep all plane rows (do NOT dedup to plane 1) — see spec rule 9.
    return links[[
        "sw_guid", "hostname", "ib_port", "phys_port", "plane",
        "sta", "phys_sta",
        "canonical_neighbor_guid", "neighbor_type",
        "neighbor_hostname", "neighbor_phys_port", "neighbor_ib_port",
        "neighbor_desc",
    ]].reset_index(drop=True)


# ─── Trace walk ──────────────────────────────────────────────────────────────


def walk_trace(
    src_guid: str,
    path_tokens: list[int],
    src_desc: str,
    links: pd.DataFrame,
) -> tuple[list[dict], str | None, str | None, str | None]:
    """Walk the directed-route path along the plane-merged link table.

    Returns:
        (rows, stop_msg, info_msg, error_msg)
        rows       — one dict per emitted hop
        stop_msg   — '⚠ Trace stopped at hop N: link is DOWN' or None
        info_msg   — advisory note (e.g. 'Trace ended at HCA on hop N;
                    remaining path tokens ignored') or None
        error_msg  — fatal error (egress port missing) — caller should print to
                    stderr and exit non-zero. When set, no rows are emitted.
    """
    src_device, src_phy = _hca_display(src_desc)
    num_hops = len(path_tokens) - 1

    # GUID + plane keyed index: (sw_U1_guid, ib_port, plane) → row.
    # Use a dict of dicts for O(1) lookup.
    idx: dict[tuple[str, int, int], pd.Series] = {}
    for _, r in links.iterrows():
        try:
            ibp = int(r["ib_port"])
            pl = int(r["plane"])
        except (TypeError, ValueError):
            continue
        key = (r["sw_guid"], ibp, pl)
        if key not in idx:
            idx[key] = r

    rows: list[dict] = []

    # ── Hop 0 — HCA → first switch
    egress = path_tokens[1]
    # Scan for canonical_neighbor_guid == src_guid AND neighbor_ib_port == egress.
    match = links[
        (links["canonical_neighbor_guid"] == src_guid)
        & (links["neighbor_ib_port"].apply(
            lambda v: pd.notna(v) and int(v) == egress
        ))
    ]

    if match.empty:
        # Cannot tell "HCA port doesn't exist" from "HCA port is DOWN" using
        # net_dump alone — both look like an empty match scan from the switch
        # side. Use wording that covers both cases.
        return [], None, None, (
            f"hop 0 — HCA {src_device} ({src_guid}) has no active link on "
            f"IB port {egress}"
        )

    first = match.iloc[0]
    rows.append({
        "hop": 0,
        "src_device": src_device, "src_guid": src_guid,
        "src_ib_port": egress, "src_phy_port": src_phy,
        "phys_status": str(first.get("phys_sta") or "N/A"),
        "logical_status": str(first.get("sta") or "N/A"),
        "dst_device": first["hostname"],
        "dst_guid": first["sw_guid"],
        "dst_ib_port": int(first["ib_port"]),
        "dst_phy_port": first["phys_port"],
    })

    # Capture current plane from the matched row — stays fixed for the rest of the trace.
    current_plane = int(first["plane"])
    current_guid = first["sw_guid"]
    current_device = first["hostname"]

    # ── Hops 1..num_hops-1 — switch-to-next
    info_msg: str | None = None
    for hop in range(1, num_hops):
        egress = path_tokens[hop + 1]
        key = (current_guid, egress, current_plane)
        entry = idx.get(key)

        # Egress port doesn't exist on this switch — fatal user error.
        if entry is None:
            return rows, None, None, (
                f"hop {hop} — IB port {egress} does not exist on switch "
                f"{current_device} ({current_guid})"
            )

        # Port exists but link is DOWN (no peer) — emit row with real status,
        # then stop.
        if pd.isna(entry.get("canonical_neighbor_guid")):
            rows.append({
                "hop": hop,
                "src_device": current_device, "src_guid": current_guid,
                "src_ib_port": egress, "src_phy_port": entry["phys_port"],
                "phys_status": str(entry.get("phys_sta") or "N/A"),
                "logical_status": str(entry.get("sta") or "N/A"),
                "dst_device": "N/A", "dst_guid": "N/A",
                "dst_ib_port": "N/A", "dst_phy_port": "N/A",
            })
            return rows, f"Trace stopped at hop {hop}: link is DOWN", None, None

        src_phy = entry["phys_port"]
        nt = entry.get("neighbor_type")
        nbr_desc = entry.get("neighbor_desc")
        nbr_desc_s = str(nbr_desc) if pd.notna(nbr_desc) else ""
        dst_device = entry.get("neighbor_hostname")
        dst_guid = entry.get("canonical_neighbor_guid")
        dst_ib = entry.get("neighbor_ib_port")
        dst_phy_raw = entry.get("neighbor_phys_port")

        if nt == "HCA":
            # split_hca_desc() returns (device, None) for factory-default descriptors
            # and (hostname, 'mlx5_X') for personalised ones.
            _, port = split_hca_desc(nbr_desc_s)
            dst_phy = port if port else "N/A"
        elif nt == "switch":
            dst_phy = dst_phy_raw if pd.notna(dst_phy_raw) else "N/A"
        else:
            dst_phy = dst_phy_raw if pd.notna(dst_phy_raw) else "N/A"

        dst_device_s = dst_device if pd.notna(dst_device) else "N/A"
        dst_guid_s = dst_guid if pd.notna(dst_guid) else "N/A"
        if pd.notna(dst_ib):
            try:
                dst_ib_s: int | str = int(dst_ib)
            except (TypeError, ValueError):
                dst_ib_s = "N/A"
        else:
            dst_ib_s = "N/A"

        rows.append({
            "hop": hop,
            "src_device": current_device, "src_guid": current_guid,
            "src_ib_port": egress, "src_phy_port": src_phy,
            "phys_status": str(entry.get("phys_sta") or "N/A"),
            "logical_status": str(entry.get("sta") or "N/A"),
            "dst_device": dst_device_s, "dst_guid": dst_guid_s,
            "dst_ib_port": dst_ib_s, "dst_phy_port": dst_phy,
        })

        # If neighbor is an HCA (or anything non-switch), we can't continue:
        # HCAs have no egress-port concept in net_dump.
        if nt != "switch":
            if hop + 1 < num_hops:
                info_msg = (
                    f"Trace terminated at {nt or 'non-switch'} on hop {hop}; "
                    f"{num_hops - hop - 1} remaining path token(s) ignored."
                )
            return rows, None, info_msg, None

        # Advance to next switch.
        current_guid = dst_guid_s
        current_device = dst_device_s

    return rows, None, info_msg, None


# ─── Rendering ───────────────────────────────────────────────────────────────


def _as_str(v) -> str:
    if v is None:
        return ""
    if isinstance(v, float) and pd.isna(v):
        return ""
    return str(v)


def render_trace(
    rows: list[dict],
    src_guid: str,
    path_str: str,
    num_hops: int,
    stop_msg: str | None,
    info_msg: str | None,
) -> None:
    print(SEP)
    print("  IB Path Trace")
    print(SEP)
    print(f"  Source GUID : {src_guid}")
    print(f"  Path        : {path_str}")
    print(f"  Total Hops  : {num_hops}")
    print()

    # Column widths: device shared across Src/Dst; phy shared across Src/Dst.
    all_devices = [_as_str(r["src_device"]) for r in rows] + [_as_str(r["dst_device"]) for r in rows]
    all_phys = [_as_str(r["src_phy_port"]) for r in rows] + [_as_str(r["dst_phy_port"]) for r in rows]
    all_phs = [_as_str(r.get("phys_status", "")) for r in rows]
    all_lgs = [_as_str(r.get("logical_status", "")) for r in rows]
    dev_w = max([20] + [len(d) for d in all_devices if d])
    phy_w = max([8] + [len(p) for p in all_phys if p])
    phs_w = max([11] + [len(p) for p in all_phs if p])
    lgs_w = max([14] + [len(p) for p in all_lgs if p])
    guid_w = 18
    ib_w = 6

    header = (
        f"{'Hop':<3}  "
        f"{'Src Device':<{dev_w}}  "
        f"{'Src GUID':<{guid_w}}  "
        f"{'Src IB':>{ib_w}}  "
        f"{'Src Phy':<{phy_w}}"
        f"  ->  "
        f"{'Phys Status':<{phs_w}}  "
        f"{'Logical Status':<{lgs_w}}"
        f"  ->  "
        f"{'Dst Device':<{dev_w}}  "
        f"{'Dst GUID':<{guid_w}}  "
        f"{'Dst IB':>{ib_w}}  "
        f"{'Dst Phy':<{phy_w}}"
    )
    sep_line = (
        f"{'-' * 3}  "
        f"{'-' * dev_w}  "
        f"{'-' * guid_w}  "
        f"{'-' * ib_w}  "
        f"{'-' * phy_w}"
        f"  --  "
        f"{'-' * phs_w}  "
        f"{'-' * lgs_w}"
        f"  --  "
        f"{'-' * dev_w}  "
        f"{'-' * guid_w}  "
        f"{'-' * ib_w}  "
        f"{'-' * phy_w}"
    )
    print(header)
    print(sep_line)

    for r in rows:
        print(
            f"{r['hop']:>3}  "
            f"{_as_str(r['src_device']):<{dev_w}}  "
            f"{_as_str(r['src_guid']):<{guid_w}}  "
            f"{_as_str(r['src_ib_port']):>{ib_w}}  "
            f"{_as_str(r['src_phy_port']):<{phy_w}}"
            f"  ->  "
            f"{_as_str(r.get('phys_status', '')):<{phs_w}}  "
            f"{_as_str(r.get('logical_status', '')):<{lgs_w}}"
            f"  ->  "
            f"{_as_str(r['dst_device']):<{dev_w}}  "
            f"{_as_str(r['dst_guid']):<{guid_w}}  "
            f"{_as_str(r['dst_ib_port']):>{ib_w}}  "
            f"{_as_str(r['dst_phy_port']):<{phy_w}}"
        )

    if stop_msg:
        print()
        print(f"  ⚠ {stop_msg}")
    if info_msg:
        print()
        print(f"  ℹ {info_msg}")


# ─── Validation / lookup helpers ─────────────────────────────────────────────


def _validate_src_guid(src_guid: str, ntmap: dict[str, str]) -> str | None:
    """Return an error message if `src_guid` isn't a valid HCA, else None."""
    if src_guid not in ntmap:
        return (
            f"Error: source GUID {src_guid} not found in ibdiagnet2.db_csv "
            f"NODES section."
        )
    if ntmap[src_guid] != NODE_TYPE_HCA:
        type_name = {"1": "HCA", "2": "Switch", "3": "Router"}.get(
            ntmap[src_guid], f"NodeType={ntmap[src_guid]}"
        )
        return (
            f"Error: source GUID {src_guid} is a {type_name}; "
            f"source must be an HCA."
        )
    return None


def _lookup_src_desc(src_guid: str, nodes: pd.DataFrame) -> str:
    """Return the source HCA's NodeDesc from a pre-loaded NODES DataFrame, or ''."""
    if nodes.empty or "NodeGUID" not in nodes.columns or "NodeDesc" not in nodes.columns:
        return ""
    mask = nodes["NodeGUID"].map(_normalize_guid) == src_guid
    if mask.any():
        return str(nodes.loc[mask, "NodeDesc"].iloc[0]).strip()
    return ""


# ─── Interactive prompts ─────────────────────────────────────────────────────


def _prompt_path() -> list[int] | None:
    """Prompt for a new path string; re-prompt on validation error.

    Returns the parsed token list, or None on EOF (Ctrl-D).
    """
    while True:
        try:
            line = input("Path: ").strip()
        except EOFError:
            print()  # newline after ^D
            return None
        if not line:
            continue
        try:
            return _parse_path(line)
        except argparse.ArgumentTypeError as exc:
            print(f"  ⚠ {exc}", file=sys.stderr)


def _prompt_continue() -> bool:
    """Ask 'Trace another path? [Y/n]: '. Return False for n/no/EOF, True otherwise."""
    try:
        ans = input("\nTrace another path? [Y/n]: ").strip().lower()
    except EOFError:
        print()
        return False
    return ans not in ("n", "no")


# ─── Main ────────────────────────────────────────────────────────────────────


def main() -> int:
    args = parse_args()
    ib_dir = Path(args.ibdiagnet)

    if not ib_dir.is_dir():
        print(f"Error: ibdiagnet folder does not exist: {ib_dir}", file=sys.stderr)
        return 2

    # ── ONE-TIME setup (cached for every iteration of the trace loop) ──
    ntmap = build_node_type_map(ib_dir)
    if not ntmap:
        print(
            f"Error: could not read NODES section from "
            f"{ib_dir / 'ibdiagnet2.db_csv'}",
            file=sys.stderr,
        )
        return 3

    src_guid = _normalize_guid(args.src_guid)
    err = _validate_src_guid(src_guid, ntmap)
    if err:
        print(err, file=sys.stderr)
        return 2

    nodes = extract_section("NODES", ib_dir / "ibdiagnet2.db_csv")
    src_desc = _lookup_src_desc(src_guid, nodes)

    links = build_trace_links(ib_dir, ntmap)
    if links.empty:
        print(
            f"Error: ibdiagnet2.net_dump at {ib_dir / 'ibdiagnet2.net_dump'} "
            f"produced no parseable links.",
            file=sys.stderr,
        )
        return 3

    # ── Interactive trace loop — first iteration uses the CLI --path ───
    path_tokens: list[int] | None = args.path

    while True:
        if path_tokens is None:
            path_tokens = _prompt_path()
            if path_tokens is None:
                return 0

        rows, stop_msg, info_msg, error_msg = walk_trace(
            src_guid, path_tokens, src_desc, links,
        )

        # Egress port doesn't exist — print error and exit non-zero. In
        # interactive sessions the same fate applies; we don't continue
        # prompting after a fatal user error in the path string.
        if error_msg is not None:
            print(f"Error: {error_msg}", file=sys.stderr)
            return 2

        path_str = ",".join(str(t) for t in path_tokens)
        render_trace(
            rows, src_guid, path_str, len(path_tokens) - 1, stop_msg, info_msg,
        )

        if not _prompt_continue():
            return 0
        path_tokens = None


if __name__ == "__main__":
    sys.exit(main())
