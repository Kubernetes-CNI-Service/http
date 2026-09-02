"""Topology-plan parsing, normalization, and comparison helpers.

The public API intentionally separates three concerns:

* :func:`build_actual_links` parses an ibdiagnet2 snapshot.
* :func:`parse_plan` accepts either the legacy P2P workbook schema or CVT.
* :func:`compare_links` compares normalized endpoint keys while preserving
  original display values for the report.
"""

from __future__ import annotations

import csv
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

from lib.inventory import (
    NODE_TYPE_SWITCH,
    SHARP_AN,
    _normalize_guid,
    _parse_switch_name_asic,
    build_node_type_map,
    split_hca_desc,
)
from lib.parsers.db_csv import is_xdr
from lib.parsers.net_dump import parse_links
from lib.parsers.iblinkinfo import parse_iblinkinfo


PLAN_COLUMNS = [
    "SrcDevice", "SrcPort_Alias", "SrcPort",
    "DstDevice", "DstPort_Alias", "DstPort",
    "SrcType", "DstType", "Source-Ref",
]
LINK_COLUMNS = ["SrcDevice", "SrcPort", "DstDevice", "DstPort"]
UNRESOLVED_COLUMNS = LINK_COLUMNS + [
    "NeighborGUID", "NeighborDescription", "Reason",
]


@dataclass
class PlanResult:
    format_name: str
    links: pd.DataFrame = field(default_factory=lambda: pd.DataFrame(columns=PLAN_COLUMNS))
    incomplete: pd.DataFrame = field(default_factory=pd.DataFrame)
    duplicates: pd.DataFrame = field(default_factory=pd.DataFrame)
    mapping_failed: pd.DataFrame = field(default_factory=pd.DataFrame)
    endpoint_conflicts: pd.DataFrame = field(default_factory=pd.DataFrame)
    raw_count: int = 0


@dataclass
class ActualResult:
    links: pd.DataFrame = field(default_factory=lambda: pd.DataFrame(columns=LINK_COLUMNS))
    plane_faulty: pd.DataFrame = field(default_factory=lambda: pd.DataFrame(columns=LINK_COLUMNS))
    unresolved: pd.DataFrame = field(
        default_factory=lambda: pd.DataFrame(columns=UNRESOLVED_COLUMNS)
    )


@dataclass
class CompareResult:
    matching: pd.DataFrame
    missing: pd.DataFrame
    undefined: pd.DataFrame
    miswired: pd.DataFrame
    actual_conflicts: pd.DataFrame


def clean_text(value: object) -> str:
    """Return a whitespace-normalized string without pandas NA markers."""
    if value is None or pd.isna(value):
        return ""
    return " ".join(unicodedata.normalize("NFKC", str(value)).strip().split())


def device_key(value: object) -> str:
    return clean_text(value).casefold()


_LOCATION_PREFIX_RE = re.compile(r"^[a-z]{2}\d{2}-(?=.)", re.IGNORECASE)


def _device_suffix_key(value: object) -> str:
    """Return a comparison-only key without an optional site/rack prefix.

    CVT names commonly include a prefix such as ``SITE01-`` while switch/HCA
    NodeDesc values may contain only the configured hostname.  The prefix is
    removed only for resolving an otherwise-unmatched live name, and only when
    it identifies exactly one planned device.
    """
    return _LOCATION_PREFIX_RE.sub("", device_key(value), count=1)


def _actual_device_key_resolver(planned: pd.DataFrame):
    planned_keys: set[str] = set()
    suffix_candidates: dict[str, set[str]] = {}
    for column in ("SrcDevice", "DstDevice"):
        if column not in planned.columns:
            continue
        for value in planned[column]:
            key = device_key(value)
            if not key:
                continue
            planned_keys.add(key)
            suffix_candidates.setdefault(_device_suffix_key(key), set()).add(key)

    unique_suffixes = {
        suffix: next(iter(keys))
        for suffix, keys in suffix_candidates.items()
        if len(keys) == 1
    }

    def resolve(value: object) -> str:
        key = device_key(value)
        if key in planned_keys:
            return key
        return unique_suffixes.get(_device_suffix_key(key), key)

    return resolve


def port_alias(value: object) -> str:
    """Normalize Excel text-prefixes and straight/curly quote accidents."""
    text = clean_text(value)
    while text and text[0] in "'\"‘’“”`":
        text = text[1:].lstrip()
    return text


def port_key(value: object) -> str:
    return port_alias(value).casefold()


def normalize_switch_port(value: object) -> str:
    """Translate common switch aliases to NVOS physical port names."""
    value = port_alias(value)
    lower = value.casefold()
    if lower == "fnm":
        return "FNM1"
    if lower == "fnm1":
        return "FNM1"
    match = re.fullmatch(r"(\d+)\s*/\s*(\d+)", value)
    if match:
        return f"sw{int(match.group(1))}p{int(match.group(2))}"
    match = re.fullmatch(r"sw(\d+)p(\d+)", lower)
    if match:
        return f"sw{int(match.group(1))}p{int(match.group(2))}"
    return value


def is_switch_type(value: object) -> bool:
    value = clean_text(value).casefold()
    return value == "switch" or value.endswith("-sw") or value in {"fw", "firewall"}


def is_host_type(value: object) -> bool:
    return clean_text(value).casefold() in {"host", "hca", "server"}


def _normalize_frame(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    out.columns = [clean_text(c) for c in out.columns]
    for col in out.columns:
        out[col] = out[col].map(clean_text)
    return out


def _canonical_link_key(row: pd.Series, columns: tuple[str, str, str, str]) -> tuple:
    a_dev, a_port, z_dev, z_port = columns
    a = (device_key(row[a_dev]), port_key(row[a_port]))
    z = (device_key(row[z_dev]), port_key(row[z_port]))
    return tuple(sorted((a, z)))


def _separate_duplicates(
    df: pd.DataFrame, columns: tuple[str, str, str, str]
) -> tuple[pd.DataFrame, pd.DataFrame]:
    if df.empty:
        return df.copy(), df.copy()
    keys = df.apply(lambda row: _canonical_link_key(row, columns), axis=1)
    duplicate_mask = keys.duplicated(keep="first")
    return df.loc[~duplicate_mask].copy(), df.loc[duplicate_mask].copy()


def _find_endpoint_conflicts(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Remove source endpoints mapped to multiple distinct destinations."""
    if df.empty:
        return df.copy(), pd.DataFrame(columns=list(df.columns) + ["ConflictReason"])
    work = df.copy()
    work["_src_key"] = [
        (device_key(d), port_key(p)) for d, p in zip(work["SrcDevice"], work["SrcPort"])
    ]
    work["_dst_key"] = [
        (device_key(d), port_key(p)) for d, p in zip(work["DstDevice"], work["DstPort"])
    ]
    counts = work.groupby("_src_key")["_dst_key"].nunique()
    bad_keys = set(counts[counts > 1].index)
    bad_mask = work["_src_key"].isin(bad_keys)
    conflicts = work.loc[bad_mask].drop(columns=["_src_key", "_dst_key"])
    if not conflicts.empty:
        conflicts = conflicts.copy()
        conflicts["ConflictReason"] = "same source endpoint has multiple destinations"
    valid = work.loc[~bad_mask].drop(columns=["_src_key", "_dst_key"])
    return valid.reset_index(drop=True), conflicts.reset_index(drop=True)


def load_profile_catalog(path: Path | None) -> list[dict[str, str]]:
    if path is None or not path.is_file():
        return []
    with path.open(newline="", encoding="utf-8-sig") as handle:
        return [
            {clean_text(k): clean_text(v) for k, v in row.items()}
            for row in csv.DictReader(handle)
        ]


def detect_plan_format(sheets: dict[str, pd.DataFrame]) -> str:
    names = {clean_text(name).casefold() for name in sheets}
    if {"nodes", "links"}.issubset(names):
        return "cvt"
    if {"legend", "port_mapping"}.issubset(names):
        return "legacy"
    raise ValueError(
        "unsupported P2P workbook: expected Nodes+Links (CVT) or "
        "Legend+Port_Mapping (legacy)"
    )


def parse_plan(path: Path, profile_catalog: Path | None = None) -> PlanResult:
    sheets = pd.read_excel(path, sheet_name=None, engine="openpyxl", dtype=str)
    format_name = detect_plan_format(sheets)
    if format_name == "cvt":
        return parse_cvt_plan(sheets, load_profile_catalog(profile_catalog))
    return parse_legacy_plan(sheets)


def parse_legacy_plan(sheets: dict[str, pd.DataFrame]) -> PlanResult:
    legend = _normalize_frame(sheets["Legend"])
    mapping = _normalize_frame(sheets["Port_Mapping"])
    alias_column = "Alias" if "Alias" in mapping.columns else "Aias"
    if alias_column not in mapping.columns:
        raise ValueError("Port_Mapping requires an Alias or legacy Aias column")

    port_map: dict[tuple[str, str], str] = {}
    for row in mapping.to_dict("records"):
        model = clean_text(row.get("Model"))
        alias = port_key(row.get(alias_column))
        physical = normalize_switch_port(row.get("Port"))
        if model and alias and physical:
            port_map[(model.casefold(), alias)] = physical

    rules: list[tuple[re.Pattern, str, str]] = []
    for index, row in enumerate(legend.to_dict("records"), start=2):
        pattern = clean_text(row.get("Name"))
        model = clean_text(row.get("Model"))
        node_type = clean_text(row.get("Type")).casefold()
        if not pattern or not model:
            continue
        try:
            rules.append((re.compile(pattern, re.IGNORECASE), model, node_type))
        except re.error as exc:
            raise ValueError(f"Legend row {index} has invalid regex {pattern!r}: {exc}") from exc

    required = ["SrcDevice", "SrcPort", "DstDevice", "DstPort"]
    frames = []
    for name, raw in sheets.items():
        if name in {"Legend", "Port_Mapping"}:
            continue
        df = _normalize_frame(raw)
        if set(required).issubset(df.columns):
            df = df[required].copy()
            df["Source-Ref"] = name
            frames.append(df)
    if not frames:
        raise ValueError("legacy P2P workbook has no link sheets with required columns")

    raw = pd.concat(frames, ignore_index=True)
    raw = raw[raw[required].apply(lambda row: any(clean_text(v) for v in row), axis=1)].copy()
    raw_count = len(raw)
    incomplete_mask = raw[required].apply(lambda row: any(not clean_text(v) for v in row), axis=1)
    incomplete = raw.loc[incomplete_mask].copy()
    complete = raw.loc[~incomplete_mask].copy()
    complete, duplicates = _separate_duplicates(
        complete, ("SrcDevice", "SrcPort", "DstDevice", "DstPort")
    )

    def classify(name: str) -> tuple[str, str]:
        for pattern, model, node_type in rules:
            if pattern.search(name):
                return model, node_type
        return "", ""

    output = []
    failures = []
    for _, row in complete.iterrows():
        src_device, dst_device = row["SrcDevice"], row["DstDevice"]
        src_alias, dst_alias = port_alias(row["SrcPort"]), port_alias(row["DstPort"])
        src_model, src_type = classify(src_device)
        dst_model, dst_type = classify(dst_device)
        if not is_switch_type(src_type) and is_switch_type(dst_type):
            src_device, dst_device = dst_device, src_device
            src_alias, dst_alias = dst_alias, src_alias
            src_model, dst_model = dst_model, src_model
            src_type, dst_type = dst_type, src_type

        src_phys = port_map.get((src_model.casefold(), port_key(src_alias)), "")
        dst_phys = port_map.get((dst_model.casefold(), port_key(dst_alias)), "")
        reason = []
        if not src_model:
            reason.append(f"unclassified source device {src_device}")
        elif not src_phys:
            reason.append(f"unmapped source port {src_model}/{src_alias}")
        if not dst_model:
            reason.append(f"unclassified destination device {dst_device}")
        elif not dst_phys:
            reason.append(f"unmapped destination port {dst_model}/{dst_alias}")
        record = {
            "SrcDevice": src_device, "SrcPort_Alias": src_alias, "SrcPort": src_phys,
            "DstDevice": dst_device, "DstPort_Alias": dst_alias, "DstPort": dst_phys,
            "SrcType": src_type, "DstType": dst_type, "Source-Ref": row["Source-Ref"],
        }
        if reason:
            record["Reason"] = "; ".join(reason)
            failures.append(record)
        else:
            output.append(record)

    links, conflicts = _find_endpoint_conflicts(pd.DataFrame(output, columns=PLAN_COLUMNS))
    return PlanResult(
        format_name="legacy", links=links, incomplete=incomplete,
        duplicates=duplicates,
        mapping_failed=pd.DataFrame(failures, columns=PLAN_COLUMNS + ["Reason"]),
        endpoint_conflicts=conflicts, raw_count=raw_count,
    )


def _catalog_port_map(
    catalog: list[dict[str, str]], node: str, node_type: str, profile: str
) -> dict[str, str]:
    result: dict[str, str] = {}
    for row in catalog:
        row_profile = clean_text(row.get("Profile"))
        row_type = clean_text(row.get("NodeType")).casefold()
        regex = clean_text(row.get("NodeRegex"))
        if row_profile and row_profile.casefold() != profile.casefold():
            continue
        if row_type and row_type != node_type.casefold():
            continue
        if regex and not re.search(regex, node, re.IGNORECASE):
            continue
        alias = clean_text(row.get("LinkPort"))
        physical = clean_text(row.get("PhysicalPort"))
        if alias and physical:
            result[port_key(alias)] = physical
    return result


def parse_cvt_plan(
    sheets: dict[str, pd.DataFrame], catalog: list[dict[str, str]]
) -> PlanResult:
    nodes = _normalize_frame(sheets["Nodes"])
    links_sheet = _normalize_frame(sheets["Links"])
    profiles = _normalize_frame(sheets.get("Server Profile", pd.DataFrame()))
    required_nodes = {"NodeName", "NodeType"}
    required_links = {"A-Node", "A-Port", "Z-Node", "Z-Port"}
    if not required_nodes.issubset(nodes.columns):
        raise ValueError(f"CVT Nodes missing columns: {sorted(required_nodes - set(nodes.columns))}")
    if not required_links.issubset(links_sheet.columns):
        raise ValueError(f"CVT Links missing columns: {sorted(required_links - set(links_sheet.columns))}")

    if "Protocol" in links_sheet.columns:
        links_sheet = links_sheet[links_sheet["Protocol"].str.casefold() == "ib"].copy()
    node_info: dict[str, dict[str, str]] = {}
    for row in nodes.to_dict("records"):
        name = clean_text(row.get("NodeName"))
        if name:
            node_info[device_key(name)] = {
                "name": name,
                "type": clean_text(row.get("NodeType")).casefold(),
                "model": clean_text(row.get("NodeModel")),
                "profile": clean_text(row.get("ServerProfile")),
            }

    workbook_profiles: dict[str, dict[str, str]] = {}
    if not profiles.empty and "ServerProfile" in profiles.columns:
        for row in profiles.to_dict("records"):
            profile = clean_text(row.get("ServerProfile"))
            rdma = clean_text(row.get("RDMAName"))
            if not profile or not rdma:
                continue
            aliases = {
                clean_text(row.get("PhysicalPort")), rdma,
                clean_text(row.get("NICOSName")), clean_text(row.get("CustomNICName")),
            }
            target = rdma
            for alias in aliases:
                if alias:
                    workbook_profiles.setdefault(profile.casefold(), {})[port_key(alias)] = target

    required = ["A-Node", "A-Port", "Z-Node", "Z-Port"]
    raw_count = len(links_sheet)
    incomplete_mask = links_sheet[required].apply(
        lambda row: any(not clean_text(value) for value in row), axis=1
    )
    incomplete = links_sheet.loc[incomplete_mask].copy()
    complete = links_sheet.loc[~incomplete_mask].copy()
    complete, duplicates = _separate_duplicates(
        complete, ("A-Node", "A-Port", "Z-Node", "Z-Port")
    )

    def translate(node: str, raw_port: str) -> tuple[str, str, str]:
        info = node_info.get(device_key(node))
        if info is None:
            return "", "", f"node {node} is absent from Nodes"
        node_type, profile = info["type"], info["profile"]
        if is_switch_type(node_type):
            physical = normalize_switch_port(raw_port)
            return physical, node_type, "" if physical else f"empty switch port for {node}"
        key = port_key(raw_port)
        if re.fullmatch(r"mlx5_\d+|hca-\d+", key, re.IGNORECASE):
            return port_alias(raw_port), node_type, ""
        mapping = dict(workbook_profiles.get(profile.casefold(), {}))
        mapping.update(_catalog_port_map(catalog, node, node_type, profile))
        physical = mapping.get(key, "")
        if physical:
            return physical, node_type, ""
        profile_label = profile or "<none>"
        return "", node_type, f"no RDMA mapping for {node}/{raw_port} (profile={profile_label})"

    output = []
    failures = []
    for excel_row, (_, row) in enumerate(complete.iterrows(), start=2):
        a_node, z_node = row["A-Node"], row["Z-Node"]
        a_alias, z_alias = port_alias(row["A-Port"]), port_alias(row["Z-Port"])
        a_port, a_type, a_error = translate(a_node, a_alias)
        z_port, z_type, z_error = translate(z_node, z_alias)
        if not is_switch_type(a_type) and is_switch_type(z_type):
            a_node, z_node = z_node, a_node
            a_alias, z_alias = z_alias, a_alias
            a_port, z_port = z_port, a_port
            a_type, z_type = z_type, a_type
            a_error, z_error = z_error, a_error
        source_ref = clean_text(row.get("Source-Ref")) or f"Links!{excel_row}"
        record = {
            "SrcDevice": a_node, "SrcPort_Alias": a_alias, "SrcPort": a_port,
            "DstDevice": z_node, "DstPort_Alias": z_alias, "DstPort": z_port,
            "SrcType": a_type, "DstType": z_type, "Source-Ref": source_ref,
        }
        errors = [message for message in (a_error, z_error) if message]
        if errors:
            record["Reason"] = "; ".join(errors)
            failures.append(record)
        else:
            output.append(record)

    links, conflicts = _find_endpoint_conflicts(pd.DataFrame(output, columns=PLAN_COLUMNS))
    return PlanResult(
        format_name="cvt", links=links, incomplete=incomplete,
        duplicates=duplicates,
        mapping_failed=pd.DataFrame(failures, columns=PLAN_COLUMNS + ["Reason"]),
        endpoint_conflicts=conflicts, raw_count=raw_count,
    )


def _collapse_xdr_groups(df: pd.DataFrame) -> pd.DataFrame:
    """Coalesce neighbor fields across planes, then select the best row."""
    if df.empty:
        return df.copy()
    order = {"ACT": 0, "ARM": 1, "INI": 2, "DOWN": 3}
    keys = ["hostname", "phys_port"]
    ordered = df.copy()
    ordered["_sta_ord"] = ordered["sta"].map(lambda value: order.get(value, 99))
    ordered.sort_values(keys + ["_sta_ord", "plane"], inplace=True)
    best = ordered.drop_duplicates(keys, keep="first").set_index(keys)
    for column in ["neighbor_guid", "neighbor_phys_port", "neighbor_desc"]:
        nonempty = ordered[column].map(clean_text).ne("")
        first_value = (
            ordered.loc[nonempty, keys + [column]]
            .drop_duplicates(keys, keep="first")
            .set_index(keys)[column]
        )
        best[column] = first_value.reindex(best.index).combine_first(best[column])
    return best.drop(columns=["_sta_ord"]).reset_index()


def build_actual_links(ibdiagnet_dir: Path) -> ActualResult:
    raw = parse_links(ibdiagnet_dir / "ibdiagnet2.net_dump")
    if raw.empty:
        return ActualResult()
    ntmap = build_node_type_map(ibdiagnet_dir)
    raw = raw[~raw["phys_port"].str.upper().str.startswith("FNMA")].copy()
    raw = raw[~raw["neighbor_desc"].str.contains(SHARP_AN, na=False, regex=False)].copy()
    xdr = is_xdr(ibdiagnet_dir)

    faulty_raw = pd.DataFrame(columns=raw.columns)
    if xdr:
        all_down = raw.groupby(["hostname", "phys_port"])["sta"].transform(
            lambda states: (states == "DOWN").all()
        )
        raw = raw.loc[~all_down].copy()
        any_down = raw.groupby(["hostname", "phys_port"])["sta"].transform(
            lambda states: (states == "DOWN").any()
        )
        faulty_raw = _collapse_xdr_groups(raw.loc[any_down])
        valid_raw = _collapse_xdr_groups(raw.loc[~any_down])
    else:
        valid_raw = raw.loc[raw["sta"] != "DOWN"].copy()

    def build(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
        rows, unresolved = [], []
        for _, row in df.iterrows():
            neighbor_guid = _normalize_guid(row.get("neighbor_guid", ""))
            neighbor_is_switch = ntmap.get(neighbor_guid, "") == NODE_TYPE_SWITCH
            desc = clean_text(row.get("neighbor_desc"))
            if neighbor_is_switch:
                dst_device = _parse_switch_name_asic(desc)[0]
                dst_port = normalize_switch_port(row.get("neighbor_phys_port"))
            else:
                dst_device, dst_port_value = split_hca_desc(desc)
                dst_port = clean_text(dst_port_value)
            record = {
                "SrcDevice": clean_text(row.get("hostname")),
                "SrcPort": normalize_switch_port(row.get("phys_port")),
                "DstDevice": dst_device,
                "DstPort": dst_port,
                "_dst_is_sw": neighbor_is_switch,
            }
            if not record["DstDevice"] or not record["DstPort"]:
                unresolved.append({
                    **record,
                    "NeighborGUID": neighbor_guid,
                    "NeighborDescription": desc,
                    "Reason": "neighbor hostname or physical port is unavailable",
                })
            else:
                rows.append(record)
        return (
            pd.DataFrame(rows),
            pd.DataFrame(unresolved, columns=UNRESOLVED_COLUMNS),
        )

    valid, unresolved = build(valid_raw)
    faulty, faulty_unresolved = build(faulty_raw)
    if not faulty_unresolved.empty:
        unresolved = pd.concat([unresolved, faulty_unresolved], ignore_index=True)
    if not valid.empty:
        valid.sort_values(["SrcDevice", "SrcPort"], inplace=True, ignore_index=True)
    return ActualResult(links=valid, plane_faulty=faulty, unresolved=unresolved)


def build_actual_links_from_iblinkinfo(path: Path) -> tuple[ActualResult, pd.DataFrame]:
    """Build the normalized actual topology from an ``iblinkinfo`` text log."""
    ports = parse_iblinkinfo(path)
    external = ports[~ports["InternalLink"] & ~ports["AggregationNode"]].copy()
    external["_active"] = (
        external["LogicalState"].str.casefold().eq("active")
        & external["PhysicalState"].str.casefold().eq("linkup")
    )

    valid_records: list[dict[str, object]] = []
    faulty_records: list[dict[str, object]] = []
    for (_device, _port), group in external.groupby(
        ["SrcDevice", "SrcPort"], sort=False
    ):
        active = group[group["_active"]]
        if active.empty:
            continue
        best = active.iloc[0].to_dict()
        if group["_active"].all():
            valid_records.append(best)
        else:
            best["FaultyPlanes"] = int((~group["_active"]).sum())
            faulty_records.append(best)

    def build(records: list[dict[str, object]]) -> tuple[pd.DataFrame, pd.DataFrame]:
        rows: list[dict[str, object]] = []
        unresolved: list[dict[str, object]] = []
        for record in records:
            link = {
                "SrcDevice": clean_text(record["SrcDevice"]),
                "SrcPort": normalize_switch_port(record["SrcPort"]),
                "DstDevice": clean_text(record["DstDevice"]),
                "DstPort": clean_text(record["DstPort"]),
                "_dst_is_sw": record["DstType"] == "switch",
            }
            if not link["DstDevice"] or not link["DstPort"]:
                unresolved.append({
                    **link,
                    "NeighborGUID": "",
                    "NeighborDescription": clean_text(record["DstDescription"]),
                    "Reason": (
                        "destination hostname or port is unavailable "
                        f"(line {record['LineNumber']})"
                    ),
                })
            else:
                rows.append(link)
        return (
            pd.DataFrame(rows),
            pd.DataFrame(unresolved, columns=UNRESOLVED_COLUMNS),
        )

    links, unresolved = build(valid_records)
    faulty, faulty_unresolved = build(faulty_records)
    if not faulty_unresolved.empty:
        unresolved = pd.concat([unresolved, faulty_unresolved], ignore_index=True)
    for frame in (links, faulty):
        if not frame.empty:
            frame.sort_values(["SrcDevice", "SrcPort"], inplace=True, ignore_index=True)
    return (
        ActualResult(
            links=links,
            plane_faulty=faulty,
            unresolved=unresolved,
        ),
        ports.drop(columns=["_active"], errors="ignore"),
    )


def compare_links(actual: pd.DataFrame, planned: pd.DataFrame) -> CompareResult:
    actual_valid, actual_conflicts = _find_endpoint_conflicts(actual)
    if planned.empty or actual_valid.empty:
        return CompareResult(
            matching=pd.DataFrame(), missing=planned.copy(), undefined=actual_valid.copy(),
            miswired=pd.DataFrame(), actual_conflicts=actual_conflicts,
        )

    left = planned.copy()
    right = actual_valid.drop(columns=["_dst_is_sw"], errors="ignore").copy()
    resolve_actual_device = _actual_device_key_resolver(left)
    left["_SrcDeviceKey"] = left["SrcDevice"].map(device_key)
    left["_SrcPortKey"] = left["SrcPort"].map(port_key)
    left["_DstDeviceKey"] = left["DstDevice"].map(device_key)
    left["_DstPortKey"] = left["DstPort"].map(port_key)
    right["_SrcDeviceKey"] = right["SrcDevice"].map(resolve_actual_device)
    right["_SrcPortKey"] = right["SrcPort"].map(port_key)
    right["_DstDeviceKey"] = right["DstDevice"].map(resolve_actual_device)
    right["_DstPortKey"] = right["DstPort"].map(port_key)
    right.rename(columns={
        "SrcDevice": "Actual_SrcDevice", "SrcPort": "Actual_SrcPort",
        "DstDevice": "Actual_DstDevice", "DstPort": "Actual_DstPort",
        "_DstDeviceKey": "_ActualDstDeviceKey", "_DstPortKey": "_ActualDstPortKey",
    }, inplace=True)

    merged = left.merge(
        right, on=["_SrcDeviceKey", "_SrcPortKey"], how="outer", indicator=True
    )
    match_mask = (
        (merged["_merge"] == "both")
        & (merged["_DstDeviceKey"] == merged["_ActualDstDeviceKey"])
        & (merged["_DstPortKey"] == merged["_ActualDstPortKey"])
    )
    matching = merged.loc[match_mask].copy()
    miswired = merged.loc[(merged["_merge"] == "both") & ~match_mask].copy()
    missing = merged.loc[merged["_merge"] == "left_only"].copy()
    undefined = merged.loc[merged["_merge"] == "right_only"].copy()

    # The live SW-SW table is bidirectional while a plan contains one physical
    # link row. Remove the reverse live row for both Matching and Miswired
    # source endpoints; otherwise every miswire is also counted as Undefined.
    paired_actual = merged.loc[merged["_merge"] == "both"]
    reverse_keys = {
        (
            row["_ActualDstDeviceKey"], row["_ActualDstPortKey"],
            row["_SrcDeviceKey"], row["_SrcPortKey"],
        )
        for _, row in paired_actual.iterrows()
    }
    if not undefined.empty:
        reverse_mask = undefined.apply(
            lambda row: (
                row["_SrcDeviceKey"], row["_SrcPortKey"],
                row["_ActualDstDeviceKey"], row["_ActualDstPortKey"],
            ) in reverse_keys,
            axis=1,
        )
        undefined = undefined.loc[~reverse_mask].copy()

    internal = [
        "_SrcDeviceKey", "_SrcPortKey", "_DstDeviceKey", "_DstPortKey",
        "_ActualDstDeviceKey", "_ActualDstPortKey", "_merge",
    ]
    actual_display = [
        "Actual_SrcDevice", "Actual_SrcPort", "Actual_DstDevice", "Actual_DstPort",
    ]
    matching.drop(columns=internal + actual_display, errors="ignore", inplace=True)
    missing.drop(columns=internal + actual_display, errors="ignore", inplace=True)
    missing.rename(columns={
        "DstDevice": "Expected_DstDevice", "DstPort_Alias": "Expected_DstPort_Alias",
        "DstPort": "Expected_DstPort",
    }, inplace=True)
    miswired.drop(columns=internal + ["Actual_SrcDevice", "Actual_SrcPort"], errors="ignore", inplace=True)
    miswired.rename(columns={
        "DstDevice": "Expected_DstDevice", "DstPort_Alias": "Expected_DstPort_Alias",
        "DstPort": "Expected_DstPort",
    }, inplace=True)
    undefined = undefined[["Actual_SrcDevice", "Actual_SrcPort", "Actual_DstDevice", "Actual_DstPort"]].rename(
        columns={
            "Actual_SrcDevice": "SrcDevice", "Actual_SrcPort": "SrcPort",
            "Actual_DstDevice": "DstDevice", "Actual_DstPort": "DstPort",
        }
    )
    return CompareResult(
        matching=matching.reset_index(drop=True), missing=missing.reset_index(drop=True),
        undefined=undefined.reset_index(drop=True), miswired=miswired.reset_index(drop=True),
        actual_conflicts=actual_conflicts.reset_index(drop=True),
    )
