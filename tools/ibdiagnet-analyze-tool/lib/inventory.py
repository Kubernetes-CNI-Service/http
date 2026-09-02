"""
Build inventory DataFrames from ibdiagnet2 dump files.

Each build_* function takes an ibdiagnet_dir (Path) and returns a DataFrame
with the columns specified in raw_requirements.MD.
"""

from __future__ import annotations

import re
from pathlib import Path

import pandas as pd

from lib.parsers.db_csv import extract_section, is_xdr
from lib.parsers.net_dump import parse_guid_lid_map, parse_links

# ─── Constants ───────────────────────────────────────────────────────────────

SHARP_AN = "Mellanox Technologies Aggregation Node"
MELLANOX_TECH = "Mellanox Technologies"  # factory-default descriptor marker


def _normalize_ws(s: str) -> str:
    """Collapse any run of whitespace (incl. multiple internal spaces) to a
    single space and strip ends. Used for canonicalising unpersonalised HCA
    descriptors like 'MT4131 ConnectX8   Mellanox Technologies'.
    """
    return re.sub(r"\s+", " ", str(s)).strip()


def is_factory_hca_desc(desc: str) -> bool:
    """True if an HCA NodeDesc has no hostname/port-name boundary — i.e. contains
    'Mellanox Technologies'. Covers both factory-default ConnectX descriptors and
    the SHARP Aggregation Node entry; both are unparseable by the personalised
    `hostname mlx5_X` convention.

    Examples:
        'MT4131 ConnectX8   Mellanox Technologies' → True  (unpersonalised HCA)
        'ConnectX7 Mellanox Technologies'          → True  (unpersonalised HCA)
        'Mellanox Technologies Aggregation Node'   → True  (SHARP AN — no port name)
        'pg21a-1-1-hpc mlx5_0'                     → False (personalised)

    Rationale: the `rsplit(" ", 1)` heuristic used for personalised HCAs would
    otherwise yield a spurious 'Technologies' / 'Node' port-name on these.
    Callers should treat such entries specially: display device = full
    whitespace-normalised descriptor, port name = blank.

    Note: this helper is orthogonal to the SHARP-AN *filter* (which uses the
    `SHARP_AN` constant directly). `show_ib_inventory.py` and
    `check_ib_link_errors.py` filter SHARP AN out before display; `trace_ib_path.py`
    keeps it — but in all cases this helper returns the right split shape.
    """
    d = str(desc).strip()
    if not d:
        return False
    return MELLANOX_TECH in d


def split_hca_desc(desc: str) -> tuple[str, str | None]:
    """Split an HCA NodeDesc into (display_device_name, port_name).

    For personalised descriptors ('hostname mlx5_0') the last whitespace-separated
    token is the port name. For factory-default descriptors
    ('MT4131 ConnectX8   Mellanox Technologies') the whole whitespace-normalised
    string is the device name and the port name is None (no personalised port
    label exists).

    Empty input returns ('', None).
    """
    d = str(desc).strip()
    if not d:
        return "", None
    if is_factory_hca_desc(d):
        return _normalize_ws(d), None
    parts = d.rsplit(" ", 1)
    if len(parts) == 1:
        return d, None
    return parts[0], parts[1]


def _parse_switch_name_asic(node_desc: str) -> tuple[str, str]:
    """Extract (switch_name, asic) from a switch NodeDesc.

    Format:  MF0;<switch_name>:<model>/U<N>
    Example: 'MF0;ib-410-g01u19-p1-slg1-lf-08:MQM9700/U1'
              → ('ib-410-g01u19-p1-slg1-lf-08', 'U1')
             'MF0;PG22B-R16-IB:Q3400_RA/U2'
              → ('PG22B-R16-IB', 'U2')

    Returns (node_desc, '') unchanged for non-standard formats.
    """
    desc = node_desc.strip()
    if desc.startswith("MF0;"):
        desc = desc[4:]
    colon = desc.find(":")
    if colon < 0:
        return desc, ""
    sw_name = desc[:colon]
    model_asic = desc[colon + 1 :]
    slash = model_asic.rfind("/")
    asic = model_asic[slash + 1 :] if slash >= 0 else ""
    return sw_name, asic


TEMP_BIN_SIZE = 10
TEMP_CHANGE_THRESHOLD = 5.0  # °C — minimum delta for a temp diff row to be flagged "Changed"


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _db_csv(ibdiagnet_dir: Path) -> Path:
    return ibdiagnet_dir / "ibdiagnet2.db_csv"


TRANSCEIVER_COLS = [
    "Src Transceiver Vendor", "Src Transceiver PN", "Src Transceiver SN",
    "Src Transceiver Rev", "Src Transceiver FW", "Src Transceiver Temp.",
    "Dst Transceiver Vendor", "Dst Transceiver PN", "Dst Transceiver SN",
    "Dst Transceiver Rev", "Dst Transceiver FW", "Dst Transceiver Temp.",
]


def bfill_transceiver(
    df: pd.DataFrame,
    group_cols: list[str],
    sort_col: str = "plane",
    xcvr_cols: list[str] | None = None,
) -> pd.DataFrame:
    """Backfill transceiver data within logical link groups.

    All planes of a logical port share the same physical transceiver, but
    CABLE_INFO may only have an entry for one ASIC GUID (typically U1).
    This fills NaN transceiver values from any plane that has data.

    Args:
        df: DataFrame with transceiver columns (NaN for missing data).
        group_cols: columns that identify a logical link (e.g. ['Src Device', 'Src Port']).
        sort_col: column to sort by within each group before filling (default 'plane').
        xcvr_cols: transceiver columns to fill (default: TRANSCEIVER_COLS).

    Returns:
        DataFrame with transceiver NaN values filled within each group.
    """
    if df.empty:
        return df
    if xcvr_cols is None:
        xcvr_cols = TRANSCEIVER_COLS
    avail = [c for c in xcvr_cols if c in df.columns]
    if not avail:
        return df
    if sort_col in df.columns:
        df = df.sort_values(group_cols + [sort_col])
    valid_group = [c for c in group_cols if c in df.columns]
    if valid_group:
        with pd.option_context("future.no_silent_downcasting", True):
            df[avail] = df.groupby(valid_group)[avail].transform(
                lambda g: g.bfill().ffill()
            )
    return df


def combine_transceivers(
    cable: pd.DataFrame,
    columns: tuple[str, ...] = ("Vendor", "PN", "SN", "Rev", "FW"),
    prefix: bool = False,
) -> pd.DataFrame:
    """Concatenate Src + Dst transceiver entries from a cable inventory and
    deduplicate by SN — one row per unique physical transceiver module.

    Used by `show_ib_inventory.py` for the CLI summary count, the Cable_Summary
    pivot, and the SN-keyed comparison-mode diff. Centralises a pattern that
    used to appear three times verbatim with slight column-list variations.

    Args:
        cable: DataFrame with `Src Transceiver <col>` / `Dst Transceiver <col>`
               column pairs for every name in `columns`. `"SN"` must be present.
        columns: bare attribute names to extract; output column order matches.
        prefix: if False (default), output columns are bare (`"Vendor"`, …).
                if True, output columns keep the `Src Transceiver <col>` prefix
                (used by the comparison diff which preserves the source schema).

    Returns:
        DataFrame deduplicated on SN (`"Src Transceiver SN"` when `prefix=True`,
        `"SN"` otherwise). Empty DataFrame with the expected output columns
        when input is empty or required column pairs are missing.
    """
    if "SN" not in columns:
        raise ValueError("'SN' must be in columns for SN-based dedup")

    src_cols = [f"Src Transceiver {c}" for c in columns]
    dst_cols = [f"Dst Transceiver {c}" for c in columns]
    out_cols = list(src_cols if prefix else columns)
    src_to_out = dict(zip(src_cols, out_cols))
    dst_to_out = dict(zip(dst_cols, out_cols))
    sn_out_col = "Src Transceiver SN" if prefix else "SN"

    if cable is None or cable.empty:
        return pd.DataFrame(columns=out_cols)

    frames: list[pd.DataFrame] = []
    if all(c in cable.columns for c in src_cols):
        mask = cable["Src Transceiver SN"].notna()
        df = cable.loc[mask, src_cols].rename(columns=src_to_out)
        frames.append(df)
    if all(c in cable.columns for c in dst_cols):
        mask = cable["Dst Transceiver SN"].notna()
        df = cable.loc[mask, dst_cols].rename(columns=dst_to_out)
        frames.append(df)

    if not frames:
        return pd.DataFrame(columns=out_cols)
    return (
        pd.concat(frames, ignore_index=True)
        .drop_duplicates(sn_out_col, keep="first")
        .reset_index(drop=True)
    )


def bin_temperatures(
    series: pd.Series,
    bin_size: int = TEMP_BIN_SIZE,
    lo: float | None = None,
    hi: float | None = None,
) -> pd.DataFrame:
    """Bucket a temperature Series into `bin_size`-degree bins.

    The lowest bin edge rounds down to the nearest `bin_size`; the highest
    rounds up. The last bin is right-inclusive so the maximum value is
    captured. Empty intermediate bins are kept (Qty=0) for a contiguous axis.

    `lo` and `hi` override the auto-detected range — used in compare mode to
    force a joint axis across the X and Y snapshots.

    Returns columns: [Bin Start, Bin End, Bin Label, Qty]. Empty input yields
    an empty DataFrame with the same column schema.
    """
    cols = ["Bin Start", "Bin End", "Bin Label", "Qty"]
    valid = pd.to_numeric(series, errors="coerce").dropna()
    if valid.empty and (lo is None or hi is None):
        return pd.DataFrame(columns=cols)

    if lo is None:
        lo = (int(valid.min()) // bin_size) * bin_size
        if valid.min() < lo:  # negatives — math.floor semantics
            lo -= bin_size
    if hi is None:
        hi_val = valid.max()
        hi = -(-int(hi_val) // bin_size) * bin_size  # ceil division
        if hi < hi_val:
            hi += bin_size
    lo, hi = int(lo), int(hi)
    if hi <= lo:
        hi = lo + bin_size

    edges = list(range(lo, hi + bin_size, bin_size))
    rows = []
    for i in range(len(edges) - 1):
        start, end = edges[i], edges[i + 1]
        is_last = i == len(edges) - 2
        if is_last:
            mask = (valid >= start) & (valid <= end)
        else:
            mask = (valid >= start) & (valid < end)
        rows.append({
            "Bin Start": start,
            "Bin End": end,
            "Bin Label": f"{start} – {end} °C",
            "Qty": int(mask.sum()),
        })
    return pd.DataFrame(rows, columns=cols)


def joint_temp_range(
    *serieses: pd.Series, bin_size: int = TEMP_BIN_SIZE,
) -> tuple[int, int] | tuple[None, None]:
    """Return (lo, hi) covering all valid values across the given Series.

    Used to align comparison-mode histograms on a shared bin axis. Returns
    (None, None) if every input is empty / all-NaN.
    """
    vals = []
    for s in serieses:
        v = pd.to_numeric(s, errors="coerce").dropna()
        if not v.empty:
            vals.append(v)
    if not vals:
        return None, None
    combined = pd.concat(vals, ignore_index=True)
    lo = (int(combined.min()) // bin_size) * bin_size
    if combined.min() < lo:
        lo -= bin_size
    hi_val = combined.max()
    hi = -(-int(hi_val) // bin_size) * bin_size
    if hi < hi_val:
        hi += bin_size
    return int(lo), int(hi)


def combine_transceiver_temps(cable: pd.DataFrame) -> pd.Series:
    """Combine Src + Dst transceiver temperatures into a single Series, one
    reading per unique physical module (deduplicated by SN).

    Uses the same Src+Dst combine + dedup-by-SN logic as `combine_transceivers()`,
    but returns just the numeric `Temp` Series (NaNs already dropped at the
    SN-grouping step). Empty input → empty Series.
    """
    combined = combine_transceivers(cable, columns=("SN", "Temp."))
    if combined.empty or "Temp." not in combined.columns:
        return pd.Series(dtype=float)
    return pd.to_numeric(combined["Temp."], errors="coerce").dropna().reset_index(drop=True)


NODE_TYPE_SWITCH = "2"
NODE_TYPE_HCA = "1"
NODE_TYPE_ROUTER = "3"


def _normalize_guid(guid: str) -> str:
    """Normalize GUID to lowercase with 16 hex chars after '0x'.

    NODES uses '0x04c5cd030081d200' (padded), net_dump uses '0x4c5cd030081d200'.
    Normalize both to '0x04c5cd030081d200'.
    """
    g = str(guid).strip().lower()
    if g.startswith("0x"):
        hex_part = g[2:].lstrip("0") or "0"
        return "0x" + hex_part.zfill(16)
    return g


def build_node_type_map(ibdiagnet_dir: Path) -> dict[str, str]:
    """Build {normalized_guid: NodeType} from NODES section of db_csv.

    NodeType: '1' = HCA, '2' = Switch, '3' = Router.
    GUIDs are normalized to 16 hex chars after '0x' for consistent matching.
    """
    nodes = extract_section("NODES", Path(ibdiagnet_dir) / "ibdiagnet2.db_csv")
    if nodes.empty:
        return {}
    result: dict[str, str] = {}
    for _, row in nodes.iterrows():
        guid = _normalize_guid(row.get("NodeGUID", ""))
        ntype = str(row.get("NodeType", "")).strip()
        if guid:
            result[guid] = ntype
    return result


def is_switch_guid(guid: str, node_type_map: dict[str, str]) -> bool:
    """Check if a GUID belongs to a switch via NodeType lookup."""
    return node_type_map.get(_normalize_guid(guid), "") == NODE_TYPE_SWITCH


def _system_image_guid_map(ibdiagnet_dir: Path) -> dict[str, str]:
    """Build {NodeGUID → SystemImageGUID} from NODES section of db_csv.

    SystemImageGUID is shared by all ASICs of a physical XDR switch (so it
    serves as the canonical per-physical-switch identifier when collapsing the
    4 plane-rows of a logical link); for NDR `SystemImageGUID == NodeGUID`.

    Returns an empty dict if the column is absent — callers should fall back
    to the per-ASIC GUID in that case.
    """
    nodes = extract_section("NODES", Path(ibdiagnet_dir) / "ibdiagnet2.db_csv")
    if nodes.empty or "SystemImageGUID" not in nodes.columns:
        return {}
    out: dict[str, str] = {}
    for _, row in nodes.iterrows():
        ng = _normalize_guid(str(row.get("NodeGUID", "")))
        sg = _normalize_guid(str(row.get("SystemImageGUID", "")))
        if ng:
            out[ng] = sg or ng
    return out


def _net_dump(ibdiagnet_dir: Path) -> Path:
    return ibdiagnet_dir / "ibdiagnet2.net_dump"


def _fw_version(major_hex: str, minor_hex: str, subminor_hex: str) -> str:
    """Convert three hex FW version fields to a 'X.Y.Z' decimal string."""
    try:
        return f"{int(major_hex, 16)}.{int(minor_hex, 16)}.{int(subminor_hex, 16)}"
    except (ValueError, TypeError):
        return "N/A"


def _nodes_info_fw(ibdiagnet_dir: Path) -> pd.DataFrame:
    """Return NODES merged with NODES_INFO, with a decoded FW version column."""
    nodes = extract_section("NODES", _db_csv(ibdiagnet_dir))
    if nodes.empty:
        return pd.DataFrame()
    nodes = nodes[["NodeGUID", "NodeDesc", "NodeType"]].copy()
    nodes["NodeType"] = nodes["NodeType"].str.strip()

    info = extract_section("NODES_INFO", _db_csv(ibdiagnet_dir))
    if not info.empty:
        # Detect whether the extended or legacy FW version column names are present.
        if "FWInfo_Extended_Major" in info.columns:
            major_col, minor_col, subminor_col = (
                "FWInfo_Extended_Major", "FWInfo_Extended_Minor", "FWInfo_Extended_SubMinor"
            )
        elif "FWInfo_Major" in info.columns:
            major_col, minor_col, subminor_col = (
                "FWInfo_Major", "FWInfo_Minor", "FWInfo_SubMinor"
            )
        else:
            major_col = minor_col = subminor_col = None

        keep_cols = ["NodeGUID", "FWInfo_PSID"]
        for c in [major_col, minor_col, subminor_col]:
            if c and c not in keep_cols:
                keep_cols.append(c)
        # Only keep columns that actually exist.
        keep_cols = [c for c in keep_cols if c in info.columns]
        info = info[keep_cols].copy()

        if major_col and major_col in info.columns:
            info["Firmware Version"] = info.apply(
                lambda r: _fw_version(
                    r.get(major_col, "N/A"),
                    r.get(minor_col, "N/A"),
                    r.get(subminor_col, "N/A"),
                ),
                axis=1,
            )
        else:
            info["Firmware Version"] = "N/A"

        info.rename(columns={"FWInfo_PSID": "PSID"}, inplace=True)
        info = info[["NodeGUID", "PSID", "Firmware Version"]]
        nodes = nodes.merge(info, on="NodeGUID", how="left")
    else:
        nodes["PSID"] = "N/A"
        nodes["Firmware Version"] = "N/A"

    return nodes


def _sys_info(ibdiagnet_dir: Path) -> pd.DataFrame:
    """Return SYSTEM_GENERAL_INFORMATION with normalised column names."""
    df = extract_section("SYSTEM_GENERAL_INFORMATION", _db_csv(ibdiagnet_dir))
    if df.empty:
        return pd.DataFrame()
    sys_cols = ["NodeGuid", "SerialNumber", "PartNumber", "Revision"]
    for c in sys_cols:
        if c not in df.columns:
            df[c] = "N/A"
    df = df[sys_cols].copy()
    df.rename(
        columns={
            "NodeGuid": "NodeGUID",
            "SerialNumber": "Serial Number",
            "PartNumber": "Part Number",
            "Revision": "Hardware Revision",
        },
        inplace=True,
    )
    return df


def _lid_map(ibdiagnet_dir: Path) -> dict[str, int]:
    """Build GUID→LID map from net_dump block headers."""
    path = _net_dump(ibdiagnet_dir)
    if not path.exists():
        return {}
    return parse_guid_lid_map(path)


# ─── Switch Inventory ─────────────────────────────────────────────────────────


def build_switch_inventory(ibdiagnet_dir: Path) -> pd.DataFrame:
    """IB Switch Inventory DataFrame.

    Columns: Node GUID, Switch Name, Part Number, Hardware Revision,
             Serial Number, PSID, Firmware Version, LID
    """
    nodes_fw = _nodes_info_fw(ibdiagnet_dir)
    if nodes_fw.empty:
        return pd.DataFrame()

    switches = extract_section("SWITCHES", _db_csv(ibdiagnet_dir))
    if switches.empty:
        return pd.DataFrame()

    switch_guids = set(switches["NodeGUID"].str.strip())
    sw = nodes_fw[nodes_fw["NodeGUID"].isin(switch_guids)].copy()

    sys = _sys_info(ibdiagnet_dir)
    if not sys.empty:
        sw = sw.merge(sys, on="NodeGUID", how="left")
    else:
        sw["Part Number"] = "N/A"
        sw["Hardware Revision"] = "N/A"
        sw["Serial Number"] = "N/A"

    lid_map = _lid_map(ibdiagnet_dir)
    sw["LID"] = sw["NodeGUID"].map(lambda g: lid_map.get(g.lower(), ""))

    parsed = sw["NodeDesc"].map(_parse_switch_name_asic)
    sw["Switch Name"] = parsed.map(lambda t: t[0])
    sw["ASIC"] = parsed.map(lambda t: t[1])
    sw.fillna("N/A", inplace=True)

    return sw[[
        "NodeGUID", "Switch Name", "ASIC", "Part Number", "Hardware Revision",
        "Serial Number", "PSID", "Firmware Version", "LID",
    ]].rename(columns={"NodeGUID": "Node GUID"}).reset_index(drop=True)


# ─── Router Inventory ─────────────────────────────────────────────────────────


def build_router_inventory(ibdiagnet_dir: Path) -> pd.DataFrame | None:
    """IB Router Inventory DataFrame. Returns None if no routers are present."""
    routers = extract_section("ROUTERS_INFO", _db_csv(ibdiagnet_dir))
    if routers.empty:
        return None

    nodes_fw = _nodes_info_fw(ibdiagnet_dir)
    if nodes_fw.empty:
        return None

    router_guids = set(routers["NodeGUID"].str.strip())
    rt = nodes_fw[nodes_fw["NodeGUID"].isin(router_guids)].copy()
    if rt.empty:
        return None

    sys = _sys_info(ibdiagnet_dir)
    if not sys.empty:
        rt = rt.merge(sys, on="NodeGUID", how="left")
    else:
        rt["Part Number"] = "N/A"
        rt["Hardware Revision"] = "N/A"
        rt["Serial Number"] = "N/A"

    lid_map = _lid_map(ibdiagnet_dir)
    rt["LID"] = rt["NodeGUID"].map(lambda g: lid_map.get(g.lower(), ""))

    rt.rename(columns={"NodeDesc": "Router Name"}, inplace=True)
    rt.fillna("N/A", inplace=True)

    return rt[[
        "NodeGUID", "Router Name", "Part Number", "Hardware Revision",
        "Serial Number", "PSID", "Firmware Version", "LID",
    ]].rename(columns={"NodeGUID": "Node GUID"}).reset_index(drop=True)


# ─── PSU Inventory ────────────────────────────────────────────────────────────


def build_psu_inventory(ibdiagnet_dir: Path) -> pd.DataFrame:
    """IB Switch PSU DataFrame.

    Columns: Node GUID, Switch Name, Part Number, PSU Index,
             PSU Present, PSU DC State, PSU Alert State, PSU Fan State
    """
    psu = extract_section("POWER_SUPPLIES", _db_csv(ibdiagnet_dir))
    if psu.empty:
        return pd.DataFrame()

    psu_cols = ["NodeGuid", "PSUIndex", "IsPresent", "DCState", "AlertState", "FanState"]
    for c in psu_cols:
        if c not in psu.columns:
            psu[c] = "N/A"
    psu = psu[psu_cols].copy()
    psu.rename(columns={"NodeGuid": "NodeGUID"}, inplace=True)

    nodes = extract_section("NODES", _db_csv(ibdiagnet_dir))
    if not nodes.empty:
        name_map = nodes.set_index("NodeGUID")["NodeDesc"].to_dict()
        raw_names = psu["NodeGUID"].map(name_map).fillna("N/A")
    else:
        raw_names = pd.Series("N/A", index=psu.index)

    parsed = raw_names.map(_parse_switch_name_asic)
    psu["Switch Name"] = parsed.map(lambda t: t[0])
    psu["ASIC"] = parsed.map(lambda t: t[1])

    sys = _sys_info(ibdiagnet_dir)
    if not sys.empty:
        psu = psu.merge(sys[["NodeGUID", "Part Number"]], on="NodeGUID", how="left")
    else:
        psu["Part Number"] = "N/A"

    psu.rename(columns={
        "PSUIndex": "PSU Index",
        "IsPresent": "PSU Present",
        "DCState": "PSU DC State",
        "AlertState": "PSU Alert State",
        "FanState": "PSU Fan State",
    }, inplace=True)

    psu.fillna("N/A", inplace=True)

    return psu[[
        "NodeGUID", "Switch Name", "ASIC", "Part Number", "PSU Index",
        "PSU Present", "PSU DC State", "PSU Alert State", "PSU Fan State",
    ]].rename(columns={"NodeGUID": "Node GUID"}).reset_index(drop=True)


# ─── Temperature Sensor Inventory ─────────────────────────────────────────────


def build_temp_inventory(ibdiagnet_dir: Path) -> pd.DataFrame:
    """IB Switch Temperature Sensor DataFrame.

    Every switch in the fabric is included. Current Temperature is sourced from
    TEMPERATURE_SENSORS (primary, one ASIC sensor per switch) with a fallback to
    TEMP_SENSING for switches not covered (e.g. XDR multi-plane fabrics where
    TEMPERATURE_SENSORS uses plane-level GUIDs instead of system GUIDs).

    Columns: Switch Name, Node GUID, Current Temperature, Max Temperature, Alert
    Alert values: '' | 'Warning' (Max Temp > 95) | 'Critical' (Max Temp > 105)
    """
    db = _db_csv(ibdiagnet_dir)

    # ── 1. Build the base switch list ─────────────────────────────────────────
    nodes = extract_section("NODES", db)
    switches = extract_section("SWITCHES", db)
    if switches.empty or nodes.empty:
        return pd.DataFrame()

    switch_guids = set(switches["NodeGUID"].str.strip())
    base = (
        nodes[nodes["NodeGUID"].isin(switch_guids)][["NodeGUID", "NodeDesc"]]
        .copy()
        .reset_index(drop=True)
    )
    parsed = base["NodeDesc"].map(_parse_switch_name_asic)
    base["Switch Name"] = parsed.map(lambda t: t[0])
    base["ASIC"] = parsed.map(lambda t: t[1])
    base = base.drop(columns=["NodeDesc"])
    base["Current Temperature"] = float("nan")
    base["Max Temperature"] = float("nan")

    # ── 2. Primary source: TEMPERATURE_SENSORS ────────────────────────────────
    ts = extract_section("TEMPERATURE_SENSORS", db)
    if not ts.empty:
        # Include SensorIndex in the selection so we can sort by it before dedup.
        ts_cols = ["NodeGuid", "SensorIndex", "Temperature", "MaxTemperature"]
        for c in ts_cols:
            if c not in ts.columns:
                ts[c] = float("nan")
        ts = ts[ts_cols].copy()
        ts.rename(columns={
            "NodeGuid": "NodeGUID",
            "Temperature": "Current Temperature",
            "MaxTemperature": "Max Temperature",
        }, inplace=True)
        ts["Current Temperature"] = pd.to_numeric(ts["Current Temperature"], errors="coerce")
        ts["Max Temperature"] = pd.to_numeric(ts["Max Temperature"], errors="coerce")
        # Sort by SensorIndex so SensorIndex 0 (ASIC sensor) is always first,
        # then keep only the first sensor per switch.
        ts["SensorIndex"] = pd.to_numeric(ts["SensorIndex"], errors="coerce")
        ts = ts.sort_values(["NodeGUID", "SensorIndex"])
        ts = ts.drop_duplicates(subset=["NodeGUID"], keep="first")
        # Update base rows where NodeGUID matches
        ts_indexed = ts.set_index("NodeGUID")
        matched = base["NodeGUID"].isin(ts_indexed.index)
        base.loc[matched, "Current Temperature"] = base.loc[matched, "NodeGUID"].map(
            ts_indexed["Current Temperature"]
        )
        base.loc[matched, "Max Temperature"] = base.loc[matched, "NodeGUID"].map(
            ts_indexed["Max Temperature"]
        )

    # ── 3. Fallback: TEMP_SENSING (NodeGUID = SystemGUID, no MaxTemperature) ──
    missing = base["Current Temperature"].isna()
    if missing.any():
        tss = extract_section("TEMP_SENSING", db)
        if not tss.empty:
            tss = tss[["NodeGUID", "CurrentTemperature"]].copy()
            tss["CurrentTemperature"] = pd.to_numeric(tss["CurrentTemperature"], errors="coerce")
            tss = tss.drop_duplicates(subset=["NodeGUID"], keep="first")
            tss_map = tss.set_index("NodeGUID")["CurrentTemperature"].to_dict()
            base.loc[missing, "Current Temperature"] = base.loc[missing, "NodeGUID"].map(tss_map)

    base["Switch Name"] = base["Switch Name"].fillna("N/A")
    base["ASIC"] = base["ASIC"].fillna("")

    return base[[
        "Switch Name", "ASIC", "NodeGUID", "Current Temperature", "Max Temperature",
    ]].rename(columns={"NodeGUID": "Node GUID"}).reset_index(drop=True)


# ─── HCA Inventory ────────────────────────────────────────────────────────────


def build_hca_inventory(ibdiagnet_dir: Path) -> pd.DataFrame:
    """IB HCA Inventory DataFrame.

    Columns: Node GUID, PSID, Firmware Version, Hostname, Port Name, LID,
             Current Temperature
    Current Temperature is sourced from TEMP_SENSING (NodeGUID → CurrentTemperature).
    """
    nodes_fw = _nodes_info_fw(ibdiagnet_dir)
    if nodes_fw.empty:
        return pd.DataFrame()

    # Keep NodeType == "1" (CA/HCA) only.
    hca = nodes_fw[nodes_fw["NodeType"] == "1"].copy()

    # Remove Mellanox Aggregation Nodes. Keep other NodeType=1 entries whose
    # NodeDesc contains "Mellanox Technologies" (e.g. unpersonalised
    # "MT4131 ConnectX8   Mellanox Technologies") — these are real HCAs.
    hca = hca[~hca["NodeDesc"].str.contains(SHARP_AN, na=False, regex=False)]

    if hca.empty:
        return pd.DataFrame()

    # Split NodeDesc → Hostname + Port Name.
    # For personalised descriptors ("hostname mlx5_0") the last token is the port.
    # For factory-default descriptors ("MT4131 ConnectX8   Mellanox Technologies")
    # the whole whitespace-normalised string is the hostname and port is blank.
    split = hca["NodeDesc"].map(split_hca_desc)
    hca["Hostname"] = split.map(lambda t: t[0])
    hca["Port Name"] = split.map(lambda t: t[1] if t[1] is not None else pd.NA)

    lid_map = _lid_map(ibdiagnet_dir)
    hca["LID"] = hca["NodeGUID"].map(lambda g: lid_map.get(g.lower(), ""))

    # Current Temperature from TEMP_SENSING.
    tss = extract_section("TEMP_SENSING", _db_csv(ibdiagnet_dir))
    if not tss.empty:
        tss = tss[["NodeGUID", "CurrentTemperature"]].copy()
        tss["CurrentTemperature"] = pd.to_numeric(tss["CurrentTemperature"], errors="coerce")
        tss = tss.drop_duplicates(subset=["NodeGUID"], keep="first")
        temp_map = tss.set_index("NodeGUID")["CurrentTemperature"].to_dict()
        hca["Current Temperature"] = hca["NodeGUID"].map(temp_map)
    else:
        hca["Current Temperature"] = float("nan")

    hca["Hostname"] = hca["Hostname"].fillna("N/A")
    hca["Port Name"] = hca["Port Name"].fillna("N/A")
    hca["PSID"] = hca["PSID"].fillna("N/A")
    hca["Firmware Version"] = hca["Firmware Version"].fillna("N/A")
    hca["LID"] = hca["LID"].fillna("N/A")

    return hca[[
        "NodeGUID", "PSID", "Firmware Version", "Hostname", "Port Name", "LID",
        "Current Temperature",
    ]].rename(columns={"NodeGUID": "Node GUID"}).sort_values(
        ["Hostname", "Port Name"]
    ).reset_index(drop=True)


# ─── Cable Inventory ──────────────────────────────────────────────────────────


def _hca_port_name(desc: str) -> str:
    """Extract the HCA port name (last token) from a neighbor description.

    "TAYQ065-JPI2-A-4-420B-L-L01 HCA-1"            → "HCA-1"
    "pg21a-1-1-hpc mlx5_0"                         → "mlx5_0"
    "MT4131 ConnectX8   Mellanox Technologies"     → ""   (factory-default; no port name)

    Returns an empty string for factory-default descriptors — the `rsplit` heuristic
    would otherwise produce a spurious "Technologies" as port name. Callers that
    need a sentinel in the output layer (e.g. "N/A") should convert as needed.
    """
    port = split_hca_desc(desc)[1]
    return port if port is not None else ""


def build_cable_inventory(ibdiagnet_dir: Path) -> pd.DataFrame:
    """IB Cable DataFrame.

    Columns: Src Device, Src Port, Src GUID, Src Transceiver Vendor/PN/SN/Rev/FW/Temp.,
             Dst Device, Dst Port, Dst GUID, Dst Transceiver Vendor/PN/SN/Rev/FW/Temp.

    Src Port: physical port name on the switch (e.g. "1/1/1" for NDR, "sw1p1" for XDR).
    Dst Port: if destination is a switch → N# from the link line;
              if destination is an HCA  → Port Name (last token of Neighbor Description,
              matching "Port Name" column in HCA_Inventory).
    """
    from lib.connection import build_link_table, parse_cable_info

    cable = parse_cable_info(ibdiagnet_dir)
    if cable.empty:
        return pd.DataFrame()

    # Remove entries with no SN (unreadable transceivers; already normalised
    # to NaN in parse_cable_info).
    cable = cable[cable["SN"].notna()]

    ntmap = build_node_type_map(ibdiagnet_dir)
    link_tbl = build_link_table(ibdiagnet_dir, ntmap, keep_down=False)
    if link_tbl.empty:
        cable.rename(columns={
            "NodeGUID": "Src GUID", "IB Port": "Src Port",
            "Vendor": "Src Transceiver Vendor", "PN": "Src Transceiver PN",
            "SN": "Src Transceiver SN", "Rev": "Src Transceiver Rev",
            "FWVersion": "Src Transceiver FW", "Temperature": "Src Transceiver Temp.",
        }, inplace=True)
        return cable

    # Rename src_port → src_phys_port for cable merge compatibility
    link_tbl = link_tbl.rename(columns={"src_port": "src_phys_port"})

    # Build device name lookup. `hostname` and `neighbor_name` are both already
    # cleaned and properly swapped by build_link_table()'s canonical-direction
    # step, so we use them directly. Re-parsing `neighbor_desc` would be wrong
    # because that field is *not* swapped — it still references the pre-swap
    # neighbor's NodeDesc. The first-pass (guid → hostname) value is preferred;
    # the second pass only fills entries the first pass didn't reach.
    name_lookup: dict[str, str] = {}
    for _, r in link_tbl.drop_duplicates("guid").iterrows():
        name_lookup[r["guid"]] = r["hostname"]
    for _, r in link_tbl.drop_duplicates("neighbor_guid").iterrows():
        g = r.get("neighbor_guid", "")
        if not g or g in name_lookup:
            continue
        desc = r.get("neighbor_desc", "")
        if not desc or SHARP_AN in str(desc):
            continue
        nbr_name = r.get("neighbor_name") or g
        name_lookup[g] = nbr_name

    link_tbl["ib_port"] = link_tbl["ib_port"].astype(str)

    # Dedup and canonical swap already done by build_link_table()

    # ── Build device-name columns ──────────────────────────────────────────────
    link_tbl["Src Device"] = link_tbl["guid"].map(
        lambda g: name_lookup.get(g, g)
    )
    link_tbl["Dst Device"] = link_tbl["neighbor_guid"].map(
        lambda g: name_lookup.get(g, g)
    )

    # ── Merge src cable data ───────────────────────────────────────────────────
    cable_src = cable.rename(columns={
        "NodeGUID": "guid", "IB Port": "ib_port",
        "Vendor": "Src Transceiver Vendor", "PN": "Src Transceiver PN",
        "SN": "Src Transceiver SN", "Rev": "Src Transceiver Rev",
        "FWVersion": "Src Transceiver FW", "Temperature": "Src Transceiver Temp.",
    })
    link_tbl = link_tbl.merge(
        cable_src[["guid", "ib_port",
                   "Src Transceiver Vendor", "Src Transceiver PN",
                   "Src Transceiver SN", "Src Transceiver Rev",
                   "Src Transceiver FW", "Src Transceiver Temp."]],
        on=["guid", "ib_port"],
        how="left",
    )

    # ── Merge dst cable data ───────────────────────────────────────────────────
    cable_dst = cable.rename(columns={
        "NodeGUID": "neighbor_guid", "IB Port": "dst_ib_port",
        "Vendor": "Dst Transceiver Vendor", "PN": "Dst Transceiver PN",
        "SN": "Dst Transceiver SN", "Rev": "Dst Transceiver Rev",
        "FWVersion": "Dst Transceiver FW", "Temperature": "Dst Transceiver Temp.",
    })
    link_tbl = link_tbl.merge(
        cable_dst[["neighbor_guid", "dst_ib_port",
                   "Dst Transceiver Vendor", "Dst Transceiver PN",
                   "Dst Transceiver SN", "Dst Transceiver Rev",
                   "Dst Transceiver FW", "Dst Transceiver Temp."]],
        on=["neighbor_guid", "dst_ib_port"],
        how="left",
    )

    # ── Per-physical-switch identifier for plane-merge dedup ──────────────────
    # SystemImageGUID is shared by all 4 ASICs of a physical XDR switch (so the
    # merge correctly collapses 4 plane-rows into 1) but unique across distinct
    # physical switches (so factory-default switches that share the same
    # NodeDesc don't collide). For NDR SystemImageGUID == NodeGUID. Falls back
    # to the per-ASIC GUID when SystemImageGUID is unavailable.
    sys_map = _system_image_guid_map(ibdiagnet_dir)
    link_tbl["_sys_id"] = link_tbl["guid"].map(lambda g: sys_map.get(g, g))

    # ── XDR: bfill transceiver data across planes within each logical link ─────
    link_tbl = bfill_transceiver(link_tbl, ["_sys_id", "src_phys_port"], sort_col="plane")

    # ── Do NOT cross-fill Src↔Dst transceivers ─────────────────────────────────
    # Each cable end has its own distinct OSFP module with its own SN
    # (CABLE_INFO reports each module per (NodeGuid, PortNum)). Unmatched
    # Src or Dst rows keep NaN — Excel renders as blank; use .isna() / .notna()
    # downstream to filter.
    for col in TRANSCEIVER_COLS:
        if col not in link_tbl.columns:
            link_tbl[col] = pd.NA

    # dst_plane already computed by build_link_table()

    # ── XDR: merge planes into one row per logical link ─────────────────────
    # After bfill, all planes share the same transceiver data. Dedup on
    # (_sys_id, src_phys_port) — keyed by SystemImageGUID rather than hostname
    # so factory-default switches (multiple devices with NodeDesc =
    # "Quantum-2 Mellanox Technologies") are kept apart, and each plane group
    # for a real XDR switch still correctly merges into one row.
    link_tbl = (
        link_tbl.sort_values(["_sys_id", "src_phys_port", "plane"])
        .drop_duplicates(subset=["_sys_id", "src_phys_port"], keep="first")
        .drop(columns=["_sys_id"])
    )

    # Capture matched (guid, ib_port) keys (Src + Dst sides) before the rename,
    # so the disconnected-cable augmentation below can find CABLE_INFO entries
    # not yet represented anywhere in the active-link table.
    def _key_strs(g, p) -> tuple[str, str]:
        return (str(g).strip(), str(p).strip())
    matched_src = {_key_strs(g, p) for g, p in zip(link_tbl["guid"], link_tbl["ib_port"])}
    matched_dst = {_key_strs(g, p) for g, p in zip(link_tbl["neighbor_guid"], link_tbl["dst_ib_port"])}
    matched_keys = matched_src | matched_dst

    # ── Assemble final output columns (no plane columns) ──────────────────────
    out_cols = [
        "Src Device", "src_phys_port", "guid",
        "Src Transceiver Vendor", "Src Transceiver PN", "Src Transceiver SN",
        "Src Transceiver Rev", "Src Transceiver FW", "Src Transceiver Temp.",
        "Dst Device", "dst_port", "neighbor_guid",
        "Dst Transceiver Vendor", "Dst Transceiver PN", "Dst Transceiver SN",
        "Dst Transceiver Rev", "Dst Transceiver FW", "Dst Transceiver Temp.",
    ]
    result = link_tbl[out_cols].rename(columns={
        "src_phys_port": "Src Port",
        "guid": "Src GUID",
        "dst_port": "Dst Port",
        "neighbor_guid": "Dst GUID",
    }).reset_index(drop=True)

    # ── A1: Disconnected-cable augmentation ───────────────────────────────────
    # CABLE_INFO entries that don't appear as Src or Dst above represent
    # transceivers that are physically inserted but whose link is not
    # negotiated (peer down / cable not connected). Emit them as extra rows
    # with Src populated and all Dst columns blank.
    matched_sns: set[str] = set()
    for col in ("Src Transceiver SN", "Dst Transceiver SN"):
        if col in result.columns:
            matched_sns.update(
                str(s) for s in result[col].dropna().tolist() if str(s).strip()
            )
    disc = _build_disconnected_cable_rows(
        ibdiagnet_dir, cable, matched_keys, matched_sns, ntmap,
    )
    if not disc.empty:
        result = pd.concat([result, disc], ignore_index=True)
        result = result.sort_values(["Src Device", "Src Port"]).reset_index(drop=True)

    return result if not result.empty else pd.DataFrame()


def _build_disconnected_cable_rows(
    ibdiagnet_dir: Path,
    cable: pd.DataFrame,
    matched_keys: set,
    matched_sns: set,
    ntmap: dict[str, str],
) -> pd.DataFrame:
    """One row per CABLE_INFO entry that isn't already represented as a Src or
    Dst in the active-link cable table — i.e. transceiver inserted but link
    DOWN. Local to `build_cable_inventory`; does not touch `build_link_table`.

    XDR exposes 4 CABLE_INFO entries per logical port (one per ASIC plane,
    same SN). The active-link table collapses planes via SystemImageGUID, so
    only the plane-1 ASIC's `(NodeGuid, PortNum)` matches via key. Filtering
    candidates also by SN against `matched_sns` avoids re-emitting the other
    three plane-ASIC rows for the same physical transceiver.
    """
    if cable is None or cable.empty:
        return pd.DataFrame()

    raw_links = parse_links(_net_dump(ibdiagnet_dir))
    if raw_links.empty:
        return pd.DataFrame()
    rl_guid = raw_links["sw_guid"].astype(str).map(_normalize_guid)
    rl_port = raw_links["ib_port"].astype(str).str.strip()
    rl_phys = raw_links["phys_port"].astype(str).str.strip()
    phys_map: dict[tuple[str, str], str] = {}
    for g, p, pp in zip(rl_guid, rl_port, rl_phys):
        # Skip empty cage / management slot labels and FNMA* (intra-switch
        # ASIC-to-ASIC, no OSFP cage). FNM1 (external UFM cage) is allowed
        # through — its CABLE_INFO entry at PortNum=145 represents a real
        # transceiver that should appear in Cable_Inventory.
        if not pp or pp == "N/A" or pp.upper().startswith("FNMA"):
            continue
        phys_map[(g, p)] = pp

    nodes = extract_section("NODES", _db_csv(ibdiagnet_dir))
    desc_map: dict[str, str] = {}
    if not nodes.empty:
        for g, d in zip(nodes["NodeGUID"], nodes["NodeDesc"]):
            desc_map[_normalize_guid(str(g))] = str(d).strip().strip('"')

    seen_sns: set[str] = set()
    rows: list[dict] = []
    for _, r in cable.iterrows():
        guid = _normalize_guid(str(r["NodeGUID"]))
        ib_port = str(r["IB Port"]).strip()
        sn = str(r.get("SN", "") or "").strip()
        if (guid, ib_port) in matched_keys:
            continue
        # Skip candidates whose SN is already represented in the active table
        # — XDR plane-ASIC duplicates of the same physical transceiver.
        if sn and sn in matched_sns:
            continue
        # Skip duplicates within the unmatched set itself (different ASIC
        # plane GUIDs, same physical transceiver).
        if sn:
            if sn in seen_sns:
                continue
            seen_sns.add(sn)
        phys = phys_map.get((guid, ib_port))
        if not phys:
            continue  # No phys label (empty cage / management port slot)
        desc = desc_map.get(guid, "")
        is_sw = ntmap.get(guid, "") == NODE_TYPE_SWITCH
        if is_sw:
            src_device = _parse_switch_name_asic(desc)[0] or desc
        else:
            src_device = split_hca_desc(desc)[0] or desc
        rows.append({
            "Src Device": src_device,
            "Src Port": phys,
            "Src GUID": guid,
            "Src Transceiver Vendor": r.get("Vendor", pd.NA),
            "Src Transceiver PN": r.get("PN", pd.NA),
            "Src Transceiver SN": r.get("SN", pd.NA),
            "Src Transceiver Rev": r.get("Rev", pd.NA),
            "Src Transceiver FW": r.get("FWVersion", pd.NA),
            "Src Transceiver Temp.": r.get("Temperature", pd.NA),
            "Dst Device": pd.NA,
            "Dst Port": pd.NA,
            "Dst GUID": pd.NA,
            "Dst Transceiver Vendor": pd.NA,
            "Dst Transceiver PN": pd.NA,
            "Dst Transceiver SN": pd.NA,
            "Dst Transceiver Rev": pd.NA,
            "Dst Transceiver FW": pd.NA,
            "Dst Transceiver Temp.": pd.NA,
        })
    return pd.DataFrame(rows)


# ─── Comparison Logic ──────────────────────────────────────────────────────────


def compare_dataframes(
    df_x: pd.DataFrame,
    df_y: pd.DataFrame,
    merge_keys: list[str],
    change_cols: list[str],
    new_col: str = "New",
    disappeared_col: str = "Disappeared",
) -> pd.DataFrame:
    """Outer-merge two DataFrames and flag new, disappeared, and changed rows.

    Rows where all change_cols are identical (or both absent) are dropped.
    Returns a DataFrame with _x / _y suffixed columns for changed fields, plus:
      - new_col: 'Yes' if only in Y
      - disappeared_col: 'Yes' if only in X
      - 'Changed': 'Yes' if any change_col differs between X and Y
    """
    if df_x.empty and df_y.empty:
        return pd.DataFrame()

    # Add indicator columns before merge so we can detect presence.
    df_x = df_x.copy()
    df_y = df_y.copy()
    df_x["_in_x"] = True
    df_y["_in_y"] = True

    merged = df_x.merge(df_y, on=merge_keys, how="outer", suffixes=("_x", "_y"))
    # Use .notna() instead of .fillna(False) to avoid pandas' object→bool
    # downcast FutureWarning. _in_x/_in_y start as True in their source
    # frames, so after outer merge they are either True or NaN.
    merged["_in_x"] = merged["_in_x"].notna()
    merged["_in_y"] = merged["_in_y"].notna()

    merged[new_col] = merged.apply(
        lambda r: "Yes" if not r["_in_x"] and r["_in_y"] else "", axis=1
    )
    merged[disappeared_col] = merged.apply(
        lambda r: "Yes" if r["_in_x"] and not r["_in_y"] else "", axis=1
    )

    # Determine which rows changed in any change_col.
    # Only meaningful for rows present in BOTH snapshots.
    def _vals_equal(a, b) -> bool:
        na_a = a is None or (not isinstance(a, str) and pd.isna(a))
        na_b = b is None or (not isinstance(b, str) and pd.isna(b))
        if na_a and na_b:
            return True
        if na_a or na_b:
            return False
        try:
            return float(a) == float(b)
        except (ValueError, TypeError):
            return str(a).strip() == str(b).strip()

    def _changed(row):
        if not row["_in_x"] or not row["_in_y"]:
            return ""
        for col in change_cols:
            cx, cy = f"{col}_x", f"{col}_y"
            if cx not in row.index or cy not in row.index:
                continue
            if not _vals_equal(row[cx], row[cy]):
                return "Yes"
        return ""

    merged["Changed"] = merged.apply(_changed, axis=1)

    # Drop rows where nothing changed (both present and all cols equal).
    keep = (
        merged[new_col].eq("Yes")
        | merged[disappeared_col].eq("Yes")
        | merged["Changed"].eq("Yes")
    )
    result = merged[keep].drop(columns=["_in_x", "_in_y"]).reset_index(drop=True)
    return result
