"""
Build link-error DataFrames from ibdiagnet2 dump files.

Public API:
  build_all_links(ibdiagnet_dir, ...) -> pd.DataFrame
  build_flapped_links(all_links) -> pd.DataFrame
  build_high_ber_links(all_links, ...) -> pd.DataFrame
  build_high_temp_links(all_links, ...) -> pd.DataFrame
  build_ini_links(all_links) -> pd.DataFrame
  build_plane_faulty_links(all_links) -> pd.DataFrame        (XDR only)
  build_fnm_links(ibdiagnet_dir) -> pd.DataFrame             (XDR only)
  build_brief_links(df) -> pd.DataFrame
  compare_flapped(flapped_x, flapped_y) -> pd.DataFrame
  compare_high_ber(ber_x, ber_y) -> pd.DataFrame
"""

from __future__ import annotations

import re
from pathlib import Path

import pandas as pd

from lib.parsers.db_csv import extract_section, is_xdr
from lib.inventory import (
    SHARP_AN,
    bfill_transceiver, TRANSCEIVER_COLS,
    build_node_type_map, _normalize_guid,
)
from lib.connection import (
    build_link_table, parse_cable_info, parse_pm_counters, parse_ber_data,
    _is_fnm_label,
)
from lib.parsers.net_dump import parse_links

# ─── Thresholds ───────────────────────────────────────────────────────────────

RAW_BER_THRESHOLD = 1e-6
SYM_BER_THRESHOLD = 1e-14
EFF_BER_THRESHOLD = 1e-12
TEMP_THRESHOLD = 70
CONGESTION_THRESHOLD = 20
BER_CHANGE_FACTOR = 100
TEMP_CHANGE_DELTA = 10


def _db_csv(ibdiagnet_dir: Path) -> Path:
    return ibdiagnet_dir / "ibdiagnet2.db_csv"






def _parse_temp(v) -> float:
    """Parse '33C' or '33' or 33 → float. Returns NaN on failure."""
    if v is None or (not isinstance(v, str) and pd.isna(v)):
        return float("nan")
    s = str(v).strip().rstrip("C").strip()
    if not s or s.lower() in ("n/a", "na", "-", ""):
        return float("nan")
    try:
        return float(s)
    except ValueError:
        return float("nan")


# ─── Public builders ──────────────────────────────────────────────────────────


def build_all_links(
    ibdiagnet_dir: Path,
    raw_ber_threshold: float = RAW_BER_THRESHOLD,
    sym_ber_threshold: float = SYM_BER_THRESHOLD,
    eff_ber_threshold: float = EFF_BER_THRESHOLD,
    temp_threshold: float = TEMP_THRESHOLD,
) -> pd.DataFrame:
    """Build All-Links DataFrame.

    Steps:
    1. _link_topology() → base link table
    2. _ber_data() → join on (guid, ib_port)
    3. _pm_info() → join on (NodeGUID=guid, PortNumber=ib_port)
    4. Compute Congestion Index
    5. _cable_map() → join src transceiver on (guid, ib_port)
    6. _cable_map() → join dst transceiver on (neighbor_guid, dst_ib_port)
    7. Parse transceiver temperatures
    8. Compute High_BER flag
    9. Compute High_Temp flag
    10. Rename to final column names
    """
    ibdiagnet_dir = Path(ibdiagnet_dir)
    ntmap = build_node_type_map(ibdiagnet_dir)

    # Step 1: link topology (from shared connection module)
    links = build_link_table(ibdiagnet_dir, ntmap, keep_down=True)
    if links.empty:
        return pd.DataFrame()

    links["ib_port_str"] = links["ib_port"].astype(str)
    xdr = is_xdr(ibdiagnet_dir)

    _PM_COLS = [
        "LinkDowned", "LinkErrorRecovery", "PortRcvErrorsExt",
        "PortXmitDiscardsExt", "PortSwLifetimeLimitDiscards",
        "PortSwHOQLifetimeLimitDiscards", "PortXmitPktsExtended", "PortXmitWaitExt",
    ]

    # Step 2: BER — join on (guid, ib_port) using per-ASIC GUID (same for NDR and XDR)
    ber = parse_ber_data(ibdiagnet_dir)
    if not ber.empty:
        ber_s = ber.copy()
        ber_s["ib_port_str"] = ber_s["ib_port"].astype(str)
        links = links.merge(
            ber_s[["guid", "ib_port_str", "fec_mode", "raw_ber", "eff_ber",
                   "sym_ber", "sym_err", "eff_err"]],
            on=["guid", "ib_port_str"], how="left",
        )
        # Dst BER
        ber_d = ber.copy()
        ber_d["dst_ib_port"] = ber_d["ib_port"].astype(str)
        ber_d = ber_d.rename(columns={
            "guid": "neighbor_guid",
            "fec_mode": "dst_fec_mode", "raw_ber": "dst_raw_ber",
            "eff_ber": "dst_eff_ber", "sym_ber": "dst_sym_ber",
            "sym_err": "dst_sym_err", "eff_err": "dst_eff_err",
        })
        links = links.merge(
            ber_d[["neighbor_guid", "dst_ib_port",
                   "dst_fec_mode", "dst_raw_ber", "dst_eff_ber",
                   "dst_sym_ber", "dst_sym_err", "dst_eff_err"]],
            on=["neighbor_guid", "dst_ib_port"], how="left",
        )
    else:
        for col in ["fec_mode", "raw_ber", "eff_ber", "sym_ber", "sym_err", "eff_err",
                    "dst_fec_mode", "dst_raw_ber", "dst_eff_ber", "dst_sym_ber",
                    "dst_sym_err", "dst_eff_err"]:
            links[col] = float("nan") if "fec" not in col else ""

    # Step 3: PM — join on (guid, ib_port) using per-ASIC GUID (same for NDR and XDR)
    pm = parse_pm_counters(ibdiagnet_dir)
    if not pm.empty:
        pm_src = pm.rename(columns={"NodeGUID": "guid", "PortNumber": "ib_port_str"})
        links = links.merge(pm_src, on=["guid", "ib_port_str"], how="left")
        # Dst PM
        dst_pm_cols = {c: f"dst_{c}" for c in _PM_COLS}
        pm_dst = pm.rename(columns={"NodeGUID": "neighbor_guid",
                                     "PortNumber": "dst_ib_port"})
        pm_dst = pm_dst.rename(columns=dst_pm_cols)[
            ["neighbor_guid", "dst_ib_port"] + list(dst_pm_cols.values())
        ]
        links = links.merge(pm_dst, on=["neighbor_guid", "dst_ib_port"], how="left")

    # Step 4: Congestion Index for both sides
    def _ci(wait_col: str, pkts_col: str) -> "pd.Series":
        wait = pd.to_numeric(links[wait_col], errors="coerce") if wait_col in links.columns else pd.Series(float("nan"), index=links.index)
        pkts = pd.to_numeric(links[pkts_col], errors="coerce") if pkts_col in links.columns else pd.Series(float("nan"), index=links.index)
        valid = pkts.notna() & (pkts != 0) & (pkts != -1) & wait.notna() & (wait != -1)
        result = pd.Series(float("nan"), index=links.index)
        result[valid] = wait[valid] / pkts[valid]
        return result

    links["src_congestion"] = _ci("PortXmitWaitExt", "PortXmitPktsExtended")
    links["dst_congestion"] = _ci("dst_PortXmitWaitExt", "dst_PortXmitPktsExtended")

    # Steps 5 & 6: Cable transceiver data
    cable = parse_cable_info(ibdiagnet_dir)

    if not cable.empty:
        # Src transceiver
        cable_src = cable.rename(columns={
            "NodeGUID": "guid", "IB Port": "ib_port_str",
            "PN": "Src Transceiver PN", "SN": "Src Transceiver SN",
            "Rev": "Src Transceiver Rev", "FWVersion": "Src Transceiver FW",
            "Temperature": "Src Transceiver Temp.",
        })
        links = links.merge(
            cable_src[["guid", "ib_port_str",
                       "Src Transceiver PN", "Src Transceiver SN",
                       "Src Transceiver Rev", "Src Transceiver FW",
                       "Src Transceiver Temp."]],
            on=["guid", "ib_port_str"],
            how="left",
        )

        # Dst transceiver
        cable_dst = cable.rename(columns={
            "NodeGUID": "neighbor_guid", "IB Port": "dst_ib_port",
            "PN": "Dst Transceiver PN", "SN": "Dst Transceiver SN",
            "Rev": "Dst Transceiver Rev", "FWVersion": "Dst Transceiver FW",
            "Temperature": "Dst Transceiver Temp.",
        })
        links = links.merge(
            cable_dst[["neighbor_guid", "dst_ib_port",
                       "Dst Transceiver PN", "Dst Transceiver SN",
                       "Dst Transceiver Rev", "Dst Transceiver FW",
                       "Dst Transceiver Temp."]],
            on=["neighbor_guid", "dst_ib_port"],
            how="left",
        )

    # XDR: bfill transceiver data across planes within each logical link.
    if xdr:
        links = bfill_transceiver(links, ["hostname", "src_port"], sort_col="plane")

    # Do NOT cross-fill Src↔Dst: each cable end has its own distinct OSFP
    # module with its own SN. Unmatched rows keep NaN — Excel renders blank
    # and downstream filters use .isna() / .notna().
    for col in TRANSCEIVER_COLS:
        if col not in links.columns:
            links[col] = pd.NA

    # Step 7: Parse transceiver temperatures
    links["_src_temp_f"] = links["Src Transceiver Temp."].map(_parse_temp)
    links["_dst_temp_f"] = links["Dst Transceiver Temp."].map(_parse_temp)

    # Step 8: High_BER — flag if EITHER src OR dst BER exceeds threshold
    def _ber_exceeds(row, raw_t, eff_t, sym_t) -> str:
        for prefix in ("", "dst_"):
            # NOTE: Raw BER check disabled — not used for flagging for now
            # raw = row.get(f"{prefix}raw_ber")
            # if not pd.isna(raw) and raw > raw_t:
            #     return "Yes"
            eff = row.get(f"{prefix}eff_ber")
            sym = row.get(f"{prefix}sym_ber")
            if not pd.isna(eff) and eff > eff_t:
                return "Yes"
            if not pd.isna(sym) and sym > sym_t:
                return "Yes"
        return ""

    links["High_BER"] = links.apply(
        _ber_exceeds, axis=1,
        args=(raw_ber_threshold, eff_ber_threshold, sym_ber_threshold),
    )

    # Step 9: High_Temp — flag if EITHER src OR dst transceiver temp exceeds threshold
    def _high_temp(row) -> str:
        if not pd.isna(row["_src_temp_f"]) and row["_src_temp_f"] > temp_threshold:
            return "Yes"
        if not pd.isna(row["_dst_temp_f"]) and row["_dst_temp_f"] > temp_threshold:
            return "Yes"
        return ""

    links["High_Temp"] = links.apply(_high_temp, axis=1)

    # Step 10: Plane and Faulty columns.
    # XDR: plane 1-4 from /U<N>. NDR: always "" (single ASIC, no multi-plane concept).
    # Faulty: "Yes" only for DOWN planes.
    if xdr:
        links["_src_plane"] = links["plane"].apply(lambda p: str(p) if p > 0 else "")
        links["_dst_plane"] = links["dst_plane"].apply(lambda p: str(int(p)) if pd.notna(p) and p > 0 else "")
    else:
        links["_src_plane"] = ""
        links["_dst_plane"] = ""
    links["_faulty"] = links["sta"].map(lambda s: "Yes" if s == "DOWN" else "")

    # Step 11: Build final ordered DataFrame
    _all_internal = (
        ["hostname", "guid", "src_port", "_src_plane", "phys_sta", "sta", "lsa", "lwa"]
        + _PM_COLS
        + ["src_congestion", "fec_mode", "raw_ber", "eff_ber", "sym_ber", "sym_err", "eff_err"]
        + ["neighbor_name", "neighbor_guid", "dst_port", "_dst_plane"]
        + [f"dst_{c}" for c in _PM_COLS]
        + ["dst_congestion", "dst_raw_ber", "dst_eff_ber",
           "dst_sym_ber", "dst_sym_err", "dst_eff_err"]
        + ["Src Transceiver PN", "Src Transceiver SN", "Src Transceiver Rev",
           "Src Transceiver FW", "Src Transceiver Temp.",
           "Dst Transceiver PN", "Dst Transceiver SN", "Dst Transceiver Rev",
           "Dst Transceiver FW", "Dst Transceiver Temp."]
        + ["_faulty", "High_BER", "High_Temp"]
    )
    for col in _all_internal:
        if col not in links.columns:
            str_cols = {"hostname", "guid", "src_port", "_src_plane", "phys_sta", "sta",
                        "lsa", "lwa", "fec_mode", "neighbor_name", "neighbor_guid",
                        "dst_port", "_dst_plane", "_faulty", "High_BER", "High_Temp"}
            links[col] = "" if col in str_cols else float("nan")

    result = links[_all_internal].rename(columns={
        "hostname": "Src Device", "guid": "Src GUID", "src_port": "Src Port",
        "_src_plane": "Src Plane", "phys_sta": "Phys Status", "sta": "Logical Status",
        "lsa": "Link Speed", "lwa": "Link Width",
        "LinkDowned": "Src LinkDowned",
        "LinkErrorRecovery": "Src LinkErrorRecovery",
        "PortRcvErrorsExt": "Src PortRcvErrorsExt",
        "PortXmitDiscardsExt": "Src PortXmitDiscardsExt",
        "PortSwLifetimeLimitDiscards": "Src PortSwLifetimeLimitDiscards",
        "PortSwHOQLifetimeLimitDiscards": "Src PortSwHOQLifetimeLimitDiscards",
        "PortXmitPktsExtended": "Src PortXmitPktsExtended",
        "PortXmitWaitExt": "Src PortXmitWaitExt",
        "src_congestion": "Src Congestion Index",
        "fec_mode": "FEC Mode",
        "raw_ber": "Src Raw BER", "eff_ber": "Src Effective BER",
        "sym_ber": "Src Symbol BER", "sym_err": "Src Symbol Err",
        "eff_err": "Src Effective Err",
        "neighbor_name": "Dst Device", "neighbor_guid": "Dst GUID",
        "dst_port": "Dst Port", "_dst_plane": "Dst Plane",
        "dst_LinkDowned": "Dst LinkDowned",
        "dst_LinkErrorRecovery": "Dst LinkErrorRecovery",
        "dst_PortRcvErrorsExt": "Dst PortRcvErrorsExt",
        "dst_PortXmitDiscardsExt": "Dst PortXmitDiscardsExt",
        "dst_PortSwLifetimeLimitDiscards": "Dst PortSwLifetimeLimitDiscards",
        "dst_PortSwHOQLifetimeLimitDiscards": "Dst PortSwHOQLifetimeLimitDiscards",
        "dst_PortXmitPktsExtended": "Dst PortXmitPktsExtended",
        "dst_PortXmitWaitExt": "Dst PortXmitWaitExt",
        "dst_congestion": "Dst Congestion Index",
        "dst_raw_ber": "Dst Raw BER", "dst_eff_ber": "Dst Effective BER",
        "dst_sym_ber": "Dst Symbol BER", "dst_sym_err": "Dst Symbol Err",
        "dst_eff_err": "Dst Effective Err",
        "_faulty": "Faulty",
    }).reset_index(drop=True)

    # Reorder to the four-block readability layout — see specification.MD §2.1.
    result = result.reindex(columns=_OUTPUT_COLS)

    return result


# Final column order for `build_all_links` output and (by inheritance) every
# row-filtered subset DataFrame: Flapped_Links, High_BER_Links, High_Temp_Links,
# INI_Links, Plane_Faulty_Links. Brief sheets have their own custom layout and
# are exempt; FNM_Links has its own narrower schema (no counters/transceivers).
# See specification.MD §2.1 for the rationale and full per-column reference.
_OUTPUT_COLS = [
    # Block 1 — identity & link state
    "Src Device", "Src GUID", "Src Port", "Src Plane",
    "Phys Status", "Logical Status",
    "Link Speed", "Link Width", "FEC Mode",
    "Dst Device", "Dst GUID", "Dst Port", "Dst Plane",
    # Block 2 — counters, Src / Dst paired pair-by-pair
    "Src LinkDowned",                       "Dst LinkDowned",
    "Src LinkErrorRecovery",                "Dst LinkErrorRecovery",
    "Src PortRcvErrorsExt",                 "Dst PortRcvErrorsExt",
    "Src PortXmitDiscardsExt",              "Dst PortXmitDiscardsExt",
    "Src PortSwLifetimeLimitDiscards",      "Dst PortSwLifetimeLimitDiscards",
    "Src PortSwHOQLifetimeLimitDiscards",   "Dst PortSwHOQLifetimeLimitDiscards",
    "Src PortXmitPktsExtended",             "Dst PortXmitPktsExtended",
    "Src PortXmitWaitExt",                  "Dst PortXmitWaitExt",
    "Src Congestion Index",                 "Dst Congestion Index",
    "Src Raw BER",                          "Dst Raw BER",
    "Src Effective BER",                    "Dst Effective BER",
    "Src Symbol BER",                       "Dst Symbol BER",
    "Src Symbol Err",                       "Dst Symbol Err",
    "Src Effective Err",                    "Dst Effective Err",
    # Block 3 — transceivers, Src then Dst
    "Src Transceiver PN", "Src Transceiver SN", "Src Transceiver Rev",
    "Src Transceiver FW", "Src Transceiver Temp.",
    "Dst Transceiver PN", "Dst Transceiver SN", "Dst Transceiver Rev",
    "Dst Transceiver FW", "Dst Transceiver Temp.",
    # Block 4 — flags
    "Faulty", "High_BER", "High_Temp",
]


def _expand_to_all_planes(all_links: pd.DataFrame, mask: "pd.Series") -> pd.DataFrame:
    """Given a per-row boolean mask, expand to include ALL planes of any
    logical link where at least one plane matches.

    Logical link key: (Src Device, Src Port). If any plane in the group
    matches, include all planes of that group.
    Falls back to simple filtering if Src Device column is missing.
    """
    if not mask.any():
        return pd.DataFrame()
    if "Src Device" not in all_links.columns:
        return all_links[mask].reset_index(drop=True)
    hit_keys = set(
        zip(all_links.loc[mask, "Src Device"], all_links.loc[mask, "Src Port"])
    )
    full_mask = all_links.apply(
        lambda r: (r["Src Device"], r["Src Port"]) in hit_keys, axis=1
    )
    return all_links[full_mask].reset_index(drop=True)


def build_flapped_links(all_links: pd.DataFrame) -> pd.DataFrame:
    """Filter: Src OR Dst LinkDowned != 0 (and not -1/NaN)."""
    if all_links.empty:
        return pd.DataFrame()

    def _flapped(col: str) -> "pd.Series":
        if col not in all_links.columns:
            return pd.Series(False, index=all_links.index)
        s = pd.to_numeric(all_links[col], errors="coerce")
        return s.notna() & (s != 0) & (s != -1)

    mask = _flapped("Src LinkDowned") | _flapped("Dst LinkDowned")
    return _expand_to_all_planes(all_links, mask)


def build_high_ber_links(
    all_links: pd.DataFrame,
    raw_ber_threshold: float = RAW_BER_THRESHOLD,
    sym_ber_threshold: float = SYM_BER_THRESHOLD,
    eff_ber_threshold: float = EFF_BER_THRESHOLD,
) -> pd.DataFrame:
    """Filter: High_BER == 'Yes' (either src or dst BER exceeds threshold)."""
    if all_links.empty:
        return pd.DataFrame()

    mask = pd.Series(False, index=all_links.index)
    for prefix in ("Src ", "Dst "):
        # NOTE: Raw BER check disabled — not used for flagging for now
        # raw_col = f"{prefix}Raw BER"
        # if raw_col in all_links.columns:
        #     mask |= (all_links[raw_col].notna() & (all_links[raw_col] > raw_ber_threshold))
        eff_col = f"{prefix}Effective BER"
        sym_col = f"{prefix}Symbol BER"
        if eff_col in all_links.columns:
            mask |= (all_links[eff_col].notna() & (all_links[eff_col] > eff_ber_threshold))
        if sym_col in all_links.columns:
            mask |= (all_links[sym_col].notna() & (all_links[sym_col] > sym_ber_threshold))

    result = _expand_to_all_planes(all_links, mask)
    # Keep High_BER column — shows per-plane which planes triggered the threshold
    return result


def build_high_temp_links(
    all_links: pd.DataFrame,
    temp_threshold: float = TEMP_THRESHOLD,
) -> pd.DataFrame:
    """Filter: Src or Dst transceiver temp > threshold. Drops High_Temp column."""
    if all_links.empty:
        return pd.DataFrame()

    def _temp_high(temp_str) -> bool:
        t = _parse_temp(temp_str)
        return not pd.isna(t) and t > temp_threshold

    mask = pd.Series(False, index=all_links.index)
    for col in ("Src Transceiver Temp.", "Dst Transceiver Temp."):
        if col in all_links.columns:
            mask |= all_links[col].map(_temp_high)

    result = _expand_to_all_planes(all_links, mask)
    if not result.empty and "High_Temp" in result.columns:
        result = result.drop(columns=["High_Temp"])
    return result


def build_ini_links(all_links: pd.DataFrame) -> pd.DataFrame:
    """Filter: any plane has Logical Status == 'INI'. Returns all planes of matching links."""
    if all_links.empty or "Logical Status" not in all_links.columns:
        return pd.DataFrame()
    mask = all_links["Logical Status"] == "INI"
    return _expand_to_all_planes(all_links, mask)


def build_plane_faulty_links(ibdiagnet_dir: Path, all_links: pd.DataFrame) -> pd.DataFrame:
    """XDR only. Identify faulty links from ERRORS_APORT_SYMMETRY_CHECK,
    then pull full per-plane details from all_links.

    ERRORS_APORT_SYMMETRY_CHECK is the authoritative source for WHICH logical
    links have partial plane faults (e.g. [INI-DOWN-INI-INI]).  All_Links
    provides the complete plane rows (with PM counters, BER, transceiver info)
    for those links, including ACT planes that don't appear in the error table.

    Steps:
    1. Extract ERRORS_APORT_SYMMETRY_CHECK from db_csv.
    2. Parse (device, port_label) for switch entries only.
    3. Look up those ports in all_links (match on Src Device + Src Port).
    4. Return all planes of those links — Faulty flag already set per plane.
    5. Deduplicate SW-SW undirected links (keep one direction).
    """
    ibdiagnet_dir = Path(ibdiagnet_dir)
    if not is_xdr(ibdiagnet_dir):
        return pd.DataFrame()
    if all_links.empty:
        return pd.DataFrame()

    err_df = extract_section("ERRORS_APORT_SYMMETRY_CHECK", _db_csv(ibdiagnet_dir))
    if err_df.empty or "Summary" not in err_df.columns:
        return pd.DataFrame()

    # Parse plane states from Summary field:
    # "PG25B-R1-IBS3/sw6p1: APort's attribute ... [INI- INI- DOWN- INI]"
    _SUMMARY_RE = re.compile(r'"?([^/"]+)/([^:]+):.*\[(.+)\]')
    _SW_PORT_RE = re.compile(r"^sw\d+p\d+$")

    rows: list[dict] = []
    for summary in err_df["Summary"].dropna():
        m = _SUMMARY_RE.search(str(summary))
        if not m:
            continue
        device = m.group(1).strip()
        port_label = m.group(2).strip()
        # Skip HCA entries — only process switch ports (e.g. sw6p1)
        if not _SW_PORT_RE.match(port_label):
            continue
        states = [s.strip() for s in m.group(3).split("-")]

        # Look up link partner from all_links (faulty device may be on Src or Dst side)
        src_match = all_links[
            (all_links["Src Device"] == device) & (all_links["Src Port"] == port_label)
        ]
        dst_match = all_links[
            (all_links["Dst Device"] == device) & (all_links["Dst Port"] == port_label)
        ]

        # Align to All_Links canonical direction (switch always Src for SW-HCA;
        # alphabetically-smaller hostname as Src for SW-SW). If the error device
        # is found as the Dst side in all_links, swap the output so this row
        # matches the same (Src Device, Src Port) key as INI_Links / All_Links.
        # This also collapses same-link reports from both endpoints to one row
        # after drop_duplicates below — keeps Plane_Faulty_Links unidirectional.
        if not src_match.empty:
            ref = src_match.iloc[0]
            src_dev, src_port = device, port_label
            dst_dev, dst_port = ref["Dst Device"], ref["Dst Port"]
        elif not dst_match.empty:
            ref = dst_match.iloc[0]
            src_dev, src_port = ref["Src Device"], ref["Src Port"]
            dst_dev, dst_port = device, port_label
        else:
            src_dev, src_port = device, port_label
            dst_dev, dst_port = "", ""

        for plane_idx, sta in enumerate(states, start=1):
            rows.append({
                "Src Device": src_dev,
                "Src Port": src_port,
                "Src Plane": str(plane_idx),
                "Logical Status": sta,
                "Dst Device": dst_dev,
                "Dst Port": dst_port,
                "Faulty": "Yes" if sta == "DOWN" else "",
            })

    if not rows:
        return pd.DataFrame()

    return pd.DataFrame(rows).drop_duplicates().reset_index(drop=True)


def build_fnm_links(ibdiagnet_dir: Path) -> pd.DataFrame:
    """XDR only: extract FNM (intra-switch ASIC) link rows from net_dump_agg.

    FNM ports (labels starting with 'FNM') are internal switch-to-ASIC
    or ASIC-to-ASIC links within the same physical switch chassis.
    They are excluded from main error analysis but kept as a reference.

    Returns columns: Src Device, Src GUID, Src Port, Plane, Phys Status,
    Logical Status, Link Speed, Link Width, FEC Mode,
    Dst GUID, Dst Port.
    """
    ibdiagnet_dir = Path(ibdiagnet_dir)
    if not is_xdr(ibdiagnet_dir):
        return pd.DataFrame()

    path = ibdiagnet_dir / "ibdiagnet2.net_dump"
    if not path.exists():
        return pd.DataFrame()

    links = parse_links(path)
    if links.empty:
        return pd.DataFrame()

    # Filter to FNM labels only
    fnm = links[links["phys_port"].map(_is_fnm_label)].copy()
    if fnm.empty:
        return pd.DataFrame()

    result = pd.DataFrame({
        "Src Device": fnm["hostname"].values,
        "Src GUID": fnm["sw_guid"].values,
        "Src Port": fnm["phys_port"].values,
        "Src Plane": fnm["plane"].apply(lambda p: str(p) if p > 0 else "").values,
        "Phys Status": fnm["phys_sta"].values,
        "Logical Status": fnm["sta"].values,
        "Link Speed": fnm["lsa"].values,
        "Link Width": fnm["lwa"].values,
        "FEC Mode": fnm["fec_mode"].values,
        "Dst GUID": fnm["neighbor_guid"].values,
        "Dst Port": fnm["neighbor_phys_port"].values,
    })
    return result.reset_index(drop=True)


def build_brief_links(df: pd.DataFrame) -> pd.DataFrame:
    """Merge XDR planes into one row per logical link for a brief summary table.

    Groups by (Src GUID, Src Port). For each group:
    - Identity cols (Src/Dst Device, GUID, Port): take first (same for all planes)
    - Transceiver cols (PN, SN, Rev, FW, Temp.): take first (same per port)
    - Plane States (XDR only): build string like "[ACT-INI-DOWN-ACT]" sorted by Plane
    - Faulty Planes (XDR only): comma-separated list of faulty plane numbers

    Output columns:
    Src Device, Src GUID, Src Port,
    Dst Device, Dst GUID, Dst Port,
    Plane States,       <- XDR only; empty string for NDR
    Faulty Planes,      <- XDR only; comma-sep plane numbers with Faulty="Yes"
    Src Transceiver PN, Src Transceiver SN, Src Transceiver Rev,
    Src Transceiver FW, Src Transceiver Temp.,
    Dst Transceiver PN, Dst Transceiver SN, Dst Transceiver Rev,
    Dst Transceiver FW, Dst Transceiver Temp.

    If df is empty, returns empty DataFrame.
    For NDR (no Plane column or Plane is always ""), returns df with just the
    identity + transceiver columns (no Plane States / Faulty Planes).
    """
    if df.empty:
        return pd.DataFrame()

    has_planes = (
        "Src Plane" in df.columns
        and df["Src Plane"].astype(str).str.strip().ne("").any()
    )

    _id_cols = ["Src Device", "Src GUID", "Src Port", "Dst Device", "Dst GUID", "Dst Port"]
    _xcvr_cols = [
        "Src Transceiver PN", "Src Transceiver SN", "Src Transceiver Rev",
        "Src Transceiver FW", "Src Transceiver Temp.",
        "Dst Transceiver PN", "Dst Transceiver SN", "Dst Transceiver Rev",
        "Dst Transceiver FW", "Dst Transceiver Temp.",
    ]
    _first_cols = [c for c in _id_cols + _xcvr_cols if c in df.columns]

    # Group by (Src Device, Src Port) for XDR so all 4 planes of a logical link
    # are in the same group. For NDR, (Src Device, Src Port) also works.
    group_key = ["Src Device", "Src Port"]
    rows = []
    for (_, _), grp in df.groupby(group_key, sort=False):
        row: dict = {}

        if has_planes:
            # Sort planes numerically first — must happen before iloc[0] and bfill
            grp = grp.copy()
            grp["_plane_num"] = pd.to_numeric(grp["Src Plane"], errors="coerce")
            grp = grp.sort_values("_plane_num")

            # bfill identity and transceiver cols: if plane 1 is DOWN its cable-join
            # columns will be NaN; fill from plane 2/3/4 so the brief row is populated.
            fill_cols = [c for c in _first_cols if c in grp.columns]
            with pd.option_context("future.no_silent_downcasting", True):
                grp[fill_cols] = grp[fill_cols].bfill()

            states = grp["Logical Status"].tolist() if "Logical Status" in grp.columns else []
            row["Plane States"] = "[" + "-".join(str(s) for s in states) + "]" if states else ""

            if "Faulty" in grp.columns:
                faulty_planes = grp.loc[grp["Faulty"] == "Yes", "Src Plane"].tolist()
                row["Faulty Planes"] = ", ".join(str(p) for p in faulty_planes)
            else:
                row["Faulty Planes"] = ""

            # LinkDowned per plane: [N-N-N-N] format, NaN→0
            for ld_col in ("Src LinkDowned", "Dst LinkDowned"):
                if ld_col in grp.columns:
                    vals = pd.to_numeric(grp[ld_col], errors="coerce").fillna(0).astype(int)
                    row[ld_col] = "[" + "-".join(str(v) for v in vals) + "]"
                else:
                    row[ld_col] = ""

            # BER per plane: [N,N,N,N] in scientific notation
            for ber_col in ("Src Effective BER", "Src Symbol BER",
                            "Dst Effective BER", "Dst Symbol BER"):
                if ber_col in grp.columns:
                    vals = grp[ber_col].apply(
                        lambda v: f"{v:.1E}" if pd.notna(v) and isinstance(v, float) else "N/A"
                    )
                    row[ber_col] = "[" + ",".join(vals) + "]"

            # Err per plane: [N,N,N,N] in integer
            for err_col in ("Src Symbol Err", "Src Effective Err",
                            "Dst Symbol Err", "Dst Effective Err"):
                if err_col in grp.columns:
                    vals = grp[err_col].apply(
                        lambda v: str(int(v)) if pd.notna(v) and isinstance(v, float) else "N/A"
                    )
                    row[err_col] = "[" + ",".join(vals) + "]"

            # High_BER flag: Yes if any plane in group
            if "High_BER" in grp.columns:
                row["High_BER"] = "Yes" if (grp["High_BER"] == "Yes").any() else ""
        else:
            row["Plane States"] = ""
            row["Faulty Planes"] = ""
            # NDR: single values for BER (scientific) and Err (integer)
            for ber_col in ("Src Effective BER", "Src Symbol BER",
                            "Dst Effective BER", "Dst Symbol BER"):
                if ber_col in grp.columns:
                    v = grp[ber_col].iloc[0]
                    row[ber_col] = f"{v:.1E}" if pd.notna(v) and isinstance(v, float) else "N/A"
            for err_col in ("Src Symbol Err", "Src Effective Err",
                            "Dst Symbol Err", "Dst Effective Err"):
                if err_col in grp.columns:
                    v = grp[err_col].iloc[0]
                    row[err_col] = str(int(v)) if pd.notna(v) and isinstance(v, float) else "N/A"
            if "High_BER" in grp.columns:
                row["High_BER"] = "Yes" if (grp["High_BER"] == "Yes").any() else ""

        for col in _first_cols:
            if col in grp.columns:
                row[col] = grp[col].iloc[0]

        rows.append(row)

    if not rows:
        return pd.DataFrame()

    result = pd.DataFrame(rows)

    # Build output column order
    out_cols = [c for c in _id_cols if c in result.columns]
    if has_planes:
        out_cols += ["Plane States", "Faulty Planes", "Src LinkDowned", "Dst LinkDowned"]
    # BER columns (present when source had BER data)
    _ber_brief_cols = ["High_BER",
                       "Src Effective BER", "Src Symbol BER", "Src Symbol Err", "Src Effective Err",
                       "Dst Effective BER", "Dst Symbol BER", "Dst Symbol Err", "Dst Effective Err"]
    out_cols += [c for c in _ber_brief_cols if c in result.columns]
    out_cols += [c for c in _xcvr_cols if c in result.columns]

    out_cols = [c for c in out_cols if c in result.columns]
    return result[out_cols].reset_index(drop=True)


def compare_flapped(
    flapped_x: pd.DataFrame,
    flapped_y: pd.DataFrame,
) -> pd.DataFrame:
    """Links where LinkDowned_Y > LinkDowned_X (more flaps) or new in Y.

    Output mirrors §2.1's column layout (from flapped_y) plus a `Change`
    column and Src/Dst LinkDowned Diff columns. See specification.MD §2.2.
    """
    if flapped_y.empty:
        return pd.DataFrame()

    key = ["Src GUID", "Src Port"]
    ld_cols = ("Src LinkDowned", "Dst LinkDowned")

    # New in Y (X snapshot empty) — every Y row is "New"; Diff = Y - 0 = Y.
    if flapped_x.empty:
        result = flapped_y.copy()
        result["Change"] = "New"
        for c in ld_cols:
            if c in result.columns:
                result[f"{c} Diff"] = pd.to_numeric(result[c], errors="coerce")
        return _reorder_diff_cols(result, _FLAPPED_DIFF_INSERTS)

    # Build (key) → {col: x_value} lookup for the LinkDowned columns + Src
    # LinkDowned (used for the "More Flaps" change-detection criterion).
    cd_cols = list(ld_cols)
    x_maps = {
        c: flapped_x.set_index(key)[c].to_dict()
        for c in cd_cols if c in flapped_x.columns
    }

    rows = []
    src_ld = "Src LinkDowned"
    for _, r in flapped_y.iterrows():
        k = tuple(r[c] for c in key)

        in_x = src_ld in x_maps and k in x_maps[src_ld]
        # Decide Change category
        if not in_x:
            change = "New"
        else:
            x_src = x_maps[src_ld].get(k)
            y_src = r.get(src_ld)
            if pd.notna(y_src) and pd.notna(x_src) and float(y_src) > float(x_src):
                change = "More Flaps"
            else:
                continue

        # Compute deltas for both Src and Dst LinkDowned. Treat absent X as 0
        # for "New" rows so Diff = Y; otherwise Y - X.
        out = {**r.to_dict(), "Change": change}
        for c in ld_cols:
            if c not in r.index:
                continue
            y_val = pd.to_numeric(r.get(c), errors="coerce")
            x_val = pd.to_numeric(x_maps.get(c, {}).get(k), errors="coerce") if in_x else 0.0
            if pd.isna(y_val):
                out[f"{c} Diff"] = pd.NA
            else:
                xv = 0.0 if (not in_x or pd.isna(x_val)) else float(x_val)
                out[f"{c} Diff"] = int(float(y_val) - xv)
        rows.append(out)

    if not rows:
        return pd.DataFrame()
    return _reorder_diff_cols(
        pd.DataFrame(rows).reset_index(drop=True), _FLAPPED_DIFF_INSERTS,
    )


# Diff-column insertion specs: each tuple is (anchor_col, [diff_cols_to_insert
# immediately after the anchor]). The result column order is built by walking
# the source DataFrame's columns in order and emitting each diff column right
# after its anchor.
_FLAPPED_DIFF_INSERTS = [
    ("Dst LinkDowned", ["Src LinkDowned Diff", "Dst LinkDowned Diff"]),
]
_HIGH_BER_DIFF_INSERTS = [
    ("Dst LinkDowned",      ["Src LinkDowned Diff",      "Dst LinkDowned Diff"]),
    ("Dst Symbol Err",      ["Src Symbol Err Diff",      "Dst Symbol Err Diff"]),
    ("Dst Effective Err",   ["Src Effective Err Diff",   "Dst Effective Err Diff"]),
]


def _reorder_diff_cols(df: pd.DataFrame, inserts: list[tuple]) -> pd.DataFrame:
    """Reorder df so that each diff column sits immediately after its anchor.

    Diff columns missing from df are skipped (e.g. a counter not present in
    the input). `Change` always lands at the very end.
    """
    if df.empty:
        return df
    anchor_to_inserts = {a: [c for c in cs if c in df.columns] for a, cs in inserts}
    inserted = {c for cs in anchor_to_inserts.values() for c in cs}

    base = [c for c in df.columns if c != "Change" and c not in inserted]
    out: list[str] = []
    for col in base:
        out.append(col)
        if col in anchor_to_inserts:
            out.extend(anchor_to_inserts[col])
    if "Change" in df.columns:
        out.append("Change")
    return df[out]


def compare_high_ber(
    ber_x: pd.DataFrame,
    ber_y: pd.DataFrame,
) -> pd.DataFrame:
    """Links where BER worsened (any BER_Y/BER_X > 100 OR errors increased) or new in Y.

    Output mirrors §2.1's column layout (from ber_y) plus a `Change` column
    and Src/Dst Diff columns for LinkDowned, Symbol Err, Effective Err. See
    specification.MD §2.3.
    """
    if ber_y.empty:
        return pd.DataFrame()

    key = ["Src GUID", "Src Port"]

    # Counters that get a `<col> Diff` column emitted (Y - X; X=0 for new rows).
    diff_cols = [
        "Src LinkDowned",     "Dst LinkDowned",
        "Src Symbol Err",     "Dst Symbol Err",
        "Src Effective Err",  "Dst Effective Err",
    ]

    # New in Y (X snapshot empty) — every Y row is "New"; Diff = Y - 0 = Y.
    if ber_x.empty:
        result = ber_y.copy()
        result["Change"] = "New"
        for c in diff_cols:
            if c in result.columns:
                result[f"{c} Diff"] = pd.to_numeric(result[c], errors="coerce")
        return _reorder_diff_cols(result, _HIGH_BER_DIFF_INSERTS)

    # Check both Src and Dst sides for BER changes
    # NOTE: Raw BER excluded from change detection for now
    # _ber_check_cols = [
    #     "Src Raw BER", "Src Effective BER", "Src Symbol BER",
    #     "Dst Raw BER", "Dst Effective BER", "Dst Symbol BER",
    # ]
    _ber_check_cols = [
        "Src Effective BER", "Src Symbol BER",
        "Dst Effective BER", "Dst Symbol BER",
    ]
    _err_check_cols = [
        "Src Symbol Err", "Src Effective Err",
        "Dst Symbol Err", "Dst Effective Err",
    ]

    def _build_x_lookup(df, cols):
        return {c: df.set_index(key)[c].to_dict()
                for c in cols if c in df.columns}

    x_maps = _build_x_lookup(ber_x, _ber_check_cols + _err_check_cols + diff_cols)
    rows = []

    for _, r in ber_y.iterrows():
        k = tuple(r[c] for c in key)
        # Check if new (use first available BER column as presence indicator)
        first_ber = next((c for c in _ber_check_cols if c in x_maps), None)
        in_x = first_ber is not None and k in x_maps[first_ber]
        if not in_x:
            change = "New"
        else:
            worsened = False
            for col in _ber_check_cols:
                x_val = (x_maps.get(col) or {}).get(k)
                y_val = r.get(col)
                if pd.notna(x_val) and pd.notna(y_val) and float(x_val) > 0:
                    if float(y_val) / float(x_val) > BER_CHANGE_FACTOR:
                        worsened = True
                        break
            if not worsened:
                for col in _err_check_cols:
                    x_val = (x_maps.get(col) or {}).get(k)
                    y_val = r.get(col)
                    if pd.notna(x_val) and pd.notna(y_val) and float(y_val) > float(x_val):
                        worsened = True
                        break
            if not worsened:
                continue
            change = "Worsened"

        out = {**r.to_dict(), "Change": change}
        for c in diff_cols:
            if c not in r.index:
                continue
            y_val = pd.to_numeric(r.get(c), errors="coerce")
            x_val = pd.to_numeric((x_maps.get(c) or {}).get(k), errors="coerce") if in_x else 0.0
            if pd.isna(y_val):
                out[f"{c} Diff"] = pd.NA
            else:
                xv = 0.0 if (not in_x or pd.isna(x_val)) else float(x_val)
                out[f"{c} Diff"] = int(float(y_val) - xv)
        rows.append(out)

    if not rows:
        return pd.DataFrame()
    return _reorder_diff_cols(
        pd.DataFrame(rows).reset_index(drop=True), _HIGH_BER_DIFF_INSERTS,
    )
