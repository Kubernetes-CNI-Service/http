"""
Shared connection table builders — reusable by all scripts.

Public API:
  build_link_table(ibdiagnet_dir, ntmap, keep_down=False) -> pd.DataFrame
  parse_cable_info(ibdiagnet_dir) -> pd.DataFrame
  parse_pm_counters(ibdiagnet_dir) -> pd.DataFrame
  parse_ber_data(ibdiagnet_dir) -> pd.DataFrame
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from lib.parsers.db_csv import extract_section, is_xdr
from lib.parsers.net_dump import parse_links
from lib.parsers.net_dump_ext import parse_links_ext
from lib.inventory import (
    _parse_switch_name_asic, _normalize_guid,
    is_switch_guid, NODE_TYPE_SWITCH, _hca_port_name, SHARP_AN,
    split_hca_desc,
)


# ─── Path helpers ────────────────────────────────────────────────────────────

def _db_csv(ibdiagnet_dir: Path) -> Path:
    return ibdiagnet_dir / "ibdiagnet2.db_csv"

def _net_dump(ibdiagnet_dir: Path) -> Path:
    return ibdiagnet_dir / "ibdiagnet2.net_dump"

def _net_dump_ext(ibdiagnet_dir: Path) -> Path:
    return ibdiagnet_dir / "ibdiagnet2.net_dump_ext"


def _is_fnm_label(label: str) -> bool:
    """True for internal/external FNM ports (FNMA1P146, FNM1, FNM1pl4, etc.)."""
    return str(label).upper().startswith("FNM")


# ─── parse_cable_info ────────────────────────────────────────────────────────


def parse_cable_info(ibdiagnet_dir: Path) -> pd.DataFrame:
    """Extract CABLE_INFO from db_csv, normalize GUIDs, strip temperature 'C', dedup.

    Columns: NodeGUID, IB Port, Vendor, PN, SN, Rev, FWVersion, Temperature
    """
    cable = extract_section("CABLE_INFO", _db_csv(ibdiagnet_dir))
    if cable.empty:
        return pd.DataFrame()

    cable_cols = ["NodeGuid", "PortNum", "Vendor", "PN", "SN", "Rev", "FWVersion", "Temperature"]
    for c in cable_cols:
        if c not in cable.columns:
            cable[c] = pd.NA
    cable = cable[cable_cols].copy()
    cable.rename(columns={"NodeGuid": "NodeGUID", "PortNum": "IB Port"}, inplace=True)

    cable["NodeGUID"] = cable["NodeGUID"].map(_normalize_guid)
    cable["IB Port"] = cable["IB Port"].astype(str).str.strip()
    cable["Temperature"] = pd.to_numeric(
        cable["Temperature"].astype(str).str.rstrip("C"), errors="coerce"
    )

    # Normalize ibdiagnet's blank / "NA" / "N/A" placeholders (used when the
    # transceiver EEPROM was unreadable or missing) to pandas NaN so downstream
    # code can use `.isna()` / `.notna()` uniformly.
    for col in ("Vendor", "PN", "SN", "Rev", "FWVersion"):
        stripped = cable[col].astype(str).str.strip()
        mask = stripped.eq("") | stripped.eq("NA") | stripped.eq("N/A") | stripped.eq("nan")
        cable.loc[mask, col] = pd.NA

    cable = cable.drop_duplicates(subset=["NodeGUID", "IB Port"], keep="first")
    return cable.reset_index(drop=True)


# ─── parse_pm_counters ──────────────────────────────────────────────────────


def parse_pm_counters(ibdiagnet_dir: Path) -> pd.DataFrame:
    """Extract PM_INFO counters from db_csv, normalize GUIDs.

    Columns: NodeGUID, PortNumber, LinkDowned, LinkErrorRecovery,
             PortRcvErrorsExt, PortXmitDiscardsExt, PortSwLifetimeLimitDiscards,
             PortSwHOQLifetimeLimitDiscards, PortXmitPktsExtended, PortXmitWaitExt
    """
    pm = extract_section("PM_INFO", _db_csv(ibdiagnet_dir))
    if pm.empty:
        return pd.DataFrame()

    col_map = {
        "LinkDownedCounterExt": "LinkDowned",
        "LinkErrorRecoveryCounterExt": "LinkErrorRecovery",
    }
    keep_cols = [
        "NodeGUID", "PortNumber",
        "LinkDownedCounterExt", "LinkErrorRecoveryCounterExt",
        "PortRcvErrorsExt", "PortXmitDiscardsExt",
        "PortSwLifetimeLimitDiscards", "PortSwHOQLifetimeLimitDiscards",
        "PortXmitPktsExtended", "PortXmitWaitExt",
    ]
    keep_cols = [c for c in keep_cols if c in pm.columns]
    pm = pm[keep_cols].copy()

    if "NodeGUID" in pm.columns:
        pm["NodeGUID"] = pm["NodeGUID"].map(_normalize_guid)
    if "PortNumber" in pm.columns:
        pm["PortNumber"] = pm["PortNumber"].astype(str).str.strip()

    pm.rename(columns=col_map, inplace=True)

    counter_cols = [c for c in [
        "LinkDowned", "LinkErrorRecovery", "PortRcvErrorsExt",
        "PortXmitDiscardsExt", "PortSwLifetimeLimitDiscards",
        "PortSwHOQLifetimeLimitDiscards", "PortXmitPktsExtended", "PortXmitWaitExt",
    ] if c in pm.columns]
    for col in counter_cols:
        pm[col] = pd.to_numeric(pm[col], errors="coerce")

    key_cols = [c for c in ["NodeGUID", "PortNumber"] if c in pm.columns]
    if key_cols:
        pm = pm.drop_duplicates(subset=key_cols, keep="first")

    return pm.reset_index(drop=True)


# ─── parse_ber_data ──────────────────────────────────────────────────────────


def parse_ber_data(ibdiagnet_dir: Path) -> pd.DataFrame:
    """Extract BER/FEC data from net_dump_ext, normalize GUIDs.

    Columns: guid, ib_port, fec_mode, raw_ber, eff_ber, sym_ber, sym_err, eff_err
    """
    path = _net_dump_ext(ibdiagnet_dir)
    if not path.exists():
        return pd.DataFrame()
    df = parse_links_ext(path)
    if df.empty:
        return pd.DataFrame()
    df["guid"] = df["guid"].map(_normalize_guid)
    return df[["guid", "ib_port", "fec_mode",
               "raw_ber", "eff_ber", "sym_ber", "sym_err", "eff_err"]]


# ─── build_link_table ────────────────────────────────────────────────────────


def build_link_table(
    ibdiagnet_dir: Path,
    ntmap: dict[str, str],
    keep_down: bool = False,
) -> pd.DataFrame:
    """Build deduplicated connection table from net_dump (unified NDR/XDR).

    Args:
        ibdiagnet_dir: Path to ibdiagnet2 directory.
        ntmap: NodeType map from build_node_type_map().
        keep_down: If True, keep individual DOWN planes (for link_errors).
                   If False, remove all DOWN rows (for cable inventory).

    Output columns: guid, src_port, ib_port, hostname, plane,
      neighbor_guid, dst_port, dst_ib_port, neighbor_desc,
      neighbor_name, sta, phys_sta, lwa, lsa, dst_plane, _nbr_is_sw
    """
    path = _net_dump(ibdiagnet_dir)
    if not path.exists():
        return pd.DataFrame()

    links = parse_links(path)
    if links.empty:
        return pd.DataFrame()

    links = links.rename(columns={"sw_guid": "guid"})
    links["src_port"] = links["phys_port"]

    # Classify neighbor via NodeType lookup
    links["_nbr_is_sw"] = links["neighbor_guid"].map(
        lambda g: ntmap.get(_normalize_guid(g), "") == NODE_TYPE_SWITCH
    )

    xdr = is_xdr(ibdiagnet_dir)

    # Filter: remove FNM ports and SHARP Aggregation Node connections only.
    # Do NOT use a loose "Mellanox Technologies" substring filter — it would
    # also drop legitimate "MT4131 ConnectX8   Mellanox Technologies" HCA
    # links (ConnectX-8 HCAs with unpersonalised factory-default descriptions).
    links = links[~links["phys_port"].map(_is_fnm_label)].copy()
    links = links[~links["neighbor_desc"].str.contains(SHARP_AN, na=False, regex=False)].copy()

    # XDR: remove a logical port only if ALL its planes are DOWN
    if xdr:
        all_down = (
            links.groupby(["hostname", "phys_port"])["sta"]
            .transform(lambda s: (s == "DOWN").all())
        )
        links = links[~all_down].copy()
        if not keep_down:
            links = links[links["sta"] != "DOWN"].copy()
    else:
        links = links[links["sta"] != "DOWN"].copy()

    if links.empty:
        return pd.DataFrame()

    # Helper: clean neighbor description → display hostname.
    # For personalised HCAs ("hostname mlx5_0") → "hostname".
    # For factory-default HCAs ("MT4131 ConnectX8   Mellanox Technologies") →
    # the full whitespace-normalised descriptor (so it isn't truncated to
    # "MT4131 ConnectX8   Mellanox" by a naive rsplit).
    def _clean_neighbor_name(guid: str, desc: str) -> str:
        d = str(desc).strip()
        if not d:
            return d
        if is_switch_guid(guid, ntmap):
            return _parse_switch_name_asic(d)[0]
        return split_hca_desc(d)[0]

    # XDR: propagate neighbor info from best non-DOWN plane to DOWN planes
    if xdr and keep_down:
        down_mask = links["sta"] == "DOWN"
        if down_mask.any():
            _sta_ord = {"ACT": 0, "ARM": 1, "INI": 2, "DOWN": 3}
            links["_sta_ord"] = links["sta"].map(lambda s: _sta_ord.get(s, 99))
            best = (
                links.sort_values(["hostname", "phys_port", "_sta_ord", "plane"])
                .drop_duplicates(subset=["hostname", "phys_port"], keep="first")
                .set_index(["hostname", "phys_port"])
            )
            for col in ["neighbor_guid", "neighbor_phys_port", "neighbor_desc"]:
                if col in best.columns:
                    best_map = best[col].to_dict()
                    fill_vals = links.apply(
                        lambda r: best_map.get((r["hostname"], r["phys_port"]), r[col]),
                        axis=1,
                    )
                    links.loc[down_mask, col] = fill_vals[down_mask]
            links.drop(columns=["_sta_ord"], inplace=True)
            # Re-classify _nbr_is_sw after propagation (DOWN planes now have valid neighbor_guid)
            links.loc[down_mask, "_nbr_is_sw"] = links.loc[down_mask, "neighbor_guid"].map(
                lambda g: ntmap.get(_normalize_guid(g), "") == NODE_TYPE_SWITCH
            )

    # Build dst_ib_port via reverse lookup
    port_lookup = links.set_index(["guid", "phys_port"])["ib_port"].to_dict()
    links["dst_ib_port"] = links.apply(
        lambda r: port_lookup.get((r["neighbor_guid"], r["neighbor_phys_port"])),
        axis=1,
    )

    links["dst_ib_port"] = (
        pd.to_numeric(links["dst_ib_port"], errors="coerce")
        .apply(lambda v: str(int(v)) if pd.notna(v) else "")
    )

    # Compute dst_port display value and fix dst_ib_port for HCAs.
    # Factory-default HCA descriptors have no usable port token — dst_port is
    # left as an empty string and dst_ib_port still uses the plane number so
    # downstream CABLE_INFO / PM joins can succeed.
    def _dst_port_info(row):
        desc = str(row.get("neighbor_desc", ""))
        if not desc:
            return "", "", False  # (dst_port, dst_ib_port, has_valid_neighbor)
        if row.get("_nbr_is_sw", False):
            return str(row.get("neighbor_phys_port", "")), row["dst_ib_port"], True
        # HCA neighbor
        port_name = _hca_port_name(desc)  # "" for factory-default descriptors
        plane = row.get("plane", 0)
        hca_ib_port = str(plane) if plane and int(plane) > 0 else "1"
        return port_name, hca_ib_port, True

    dst_info = links.apply(_dst_port_info, axis=1)
    links["dst_port"] = dst_info.map(lambda t: t[0])
    links["dst_ib_port"] = dst_info.map(lambda t: t[1])
    links["_has_neighbor"] = dst_info.map(lambda t: t[2])

    # Keep rows with a valid neighbor, even when dst_port is blank because the
    # neighbor is an unpersonalised HCA ("MT4131 ConnectX8 …") — these are real
    # links; dropping them would silently lose ~178 HCAs on the XDR fabric.
    links = links[links["_has_neighbor"]].copy()
    links.drop(columns=["_has_neighbor"], inplace=True)

    links["neighbor_name"] = links.apply(
        lambda r: _clean_neighbor_name(r["neighbor_guid"], r["neighbor_desc"]), axis=1
    )

    # Derive Dst Plane
    def _dst_plane(row):
        if row.get("_nbr_is_sw", False):
            _, asic = _parse_switch_name_asic(str(row.get("neighbor_desc", "")))
            if asic and asic.startswith("U") and asic[1:].isdigit():
                return int(asic[1:])
        return row["plane"]

    links["dst_plane"] = links.apply(_dst_plane, axis=1)

    # Undirected dedup keyed on (per-ASIC GUID, port) — hostname-based keys
    # collide for factory-default switches that share the same NodeDesc string
    # across distinct devices (e.g. multiple "Quantum-2 Mellanox Technologies").
    # GUIDs are unique per ASIC so this key is robust for both NDR and XDR.
    def _link_id(row):
        a = f"{row['guid']}|{row['src_port']}"
        n_guid = str(row.get("neighbor_guid", "") or "")
        dst = str(row.get("dst_port", "") or "")
        b = f"{n_guid}|{dst}" if dst else a
        return "|".join(sorted([a, b]))

    links["_link_id"] = links.apply(_link_id, axis=1)
    links = links.drop_duplicates(subset=["_link_id", "plane"]).drop(columns=["_link_id"])

    # Canonical direction: Src hostname < Dst hostname for SW-SW
    needs_swap = links["_nbr_is_sw"] & (links["hostname"] > links["neighbor_name"])
    if needs_swap.any():
        idx = needs_swap
        old = links.loc[idx].copy()
        links.loc[idx, "guid"] = old["neighbor_guid"].values
        links.loc[idx, "neighbor_guid"] = old["guid"].values
        links.loc[idx, "src_port"] = old["dst_port"].values
        links.loc[idx, "dst_port"] = old["src_port"].values
        links.loc[idx, "ib_port"] = pd.to_numeric(old["dst_ib_port"], errors="coerce").fillna(0).astype(int).values
        links.loc[idx, "dst_ib_port"] = old["ib_port"].astype(str).values
        links.loc[idx, "hostname"] = old["neighbor_name"].values
        links.loc[idx, "neighbor_name"] = old["hostname"].values
        links.loc[idx, "plane"] = old["dst_plane"].values
        links.loc[idx, "dst_plane"] = old["plane"].values

    # Normalize GUIDs for downstream joins
    links["guid"] = links["guid"].map(_normalize_guid)
    links["neighbor_guid"] = links["neighbor_guid"].map(
        lambda g: _normalize_guid(g) if g else ""
    )

    return links[[
        "guid", "src_port", "ib_port", "hostname", "plane",
        "neighbor_guid", "dst_port", "dst_ib_port", "neighbor_desc",
        "neighbor_name", "sta", "phys_sta", "lwa", "lsa", "dst_plane", "_nbr_is_sw",
    ]].reset_index(drop=True)
