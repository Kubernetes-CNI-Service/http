#!/usr/bin/env python3
"""Prepare the devices with a problem in one collection as rows of the online Issue Tracker's ETH&IB Switch sheet.

Owner 2026-10-23: CableTracker syncs only the two Cabling sheets today. The production ETH, IB and NVL switches
and the UFM servers (UFM belongs to IB) that have a problem are prepared now, in the ETH&IB Switch sheet's
columns and value lists, so CableTracker can sync them once it supports that sheet. This script never contacts
Google and never writes the sheet.

A device has a problem when (parsed by the monitor page's own functions, monitor/generate-monitor-html.py):
  - it was expected but returned no information in this collection (not collected);
  - a PSU or FAN reports a state other than ok;
  - an ASIC or PSU temperature sensor reports a state other than ok/normal, or reads at or above its Crit or Max
    threshold; a sensor without thresholds (a UFM HCA) counts from 85 C, where the page turns it red;
  - the system health is "not ok" (switch); for a UFM, the HA state read on the VIP holder is not ok, or without
    it the ufm-enterprise service is failed / not active (a warning that only repeats a PSU/FAN failure is not a
    second problem).
One row per device; several problems share it and it takes the highest priority:
  Critical  temperature state not ok or at/above Crit
  High      not collected, PSU or FAN not ok, temperature at/above Max (or 85 C without thresholds),
            health not ok, UFM HA error, ufm-enterprise failed
  Medium    UFM HA warning, ufm-enterprise not active
RU and Model are formulas in the sheet (looked up by Host Name); rows never carry them ("formula_columns").

    python3 monitor/issue-tracker/switch-status.py [--project-dir DIR] [--type eth|ib|ufm|nvl ...]
                                                   [--archive TAR | --no-archive] [--planned FILE]

Without --archive the newest production archive of each type is read and every device of that type in
02-devices_config.csv is expected; a type without any archive is skipped. cron.sh passes the exact archive of
the run (or --no-archive when the run collected nothing of that type) and --planned, the devices it planned
before any dropped out (one name per line; "name|host..." lines are read up to the first "|"), so a device
that dropped out is reported as not collected. --archive and --no-archive take exactly one --type.

Output: <project>/99-output-monitor/<network>/issue-tracker/<type>-switch-status.json (eth: ethernet, ib and
ufm: infiniband, nvl: nvlink), replaced whole; nothing is written for a type with no expected device. With
--planned, rows of devices of that type that this run did not plan (a run of one Ethernet sub-type) are kept
from the previous file, marked with the archive they came from.
Exit 0: written or nothing to do. Exit 2: usage or input error; nothing is written.
"""

from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import os
import re
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

BASE = Path(__file__).resolve().parent
HTTP_ROOT = BASE.parent.parent
PARSER = HTTP_ROOT / "monitor/generate-monitor-html.py"
PROJECT_ANCHOR = HTTP_ROOT / "monitor/01-global.yaml"   # setup's link into DAY0-Prepare/<project>/
OUTPUT_SUBDIR = "issue-tracker"
SCHEMA = "switch-status-v1"
SHEET = "ETH&IB Switch"
# The sheet's header row (row 2 of the standard Issue Tracker template), in order.
COLUMNS = (
    "Issue#", "Submit Date", "Submitor", "Rack", "RU", "Host Name", "OOB IP", "SN", "Model", "Fabric",
    "Priority", "Issue Description", "NVEX Case ID", "Status", "Owner", "Action Description", "P-Status",
    "Replacement SN", "Replacement ETH0 MAC", "Remark \n(Partner)", "Remark\n(NV)",
)
SUBMITOR = "CVT"
STATUS = "New"                                       # BasicData "HW - NV Status"
PRIORITY_ORDER = ("Critical", "High", "Medium", "Low")   # the sheet's Priority list
TYPES = {
    # inventory types are the production rows of 02-devices_config.csv (AIR is never reported)
    "eth": {"network": "ethernet", "info_dir": "eth-info", "inventory": {"eth", "eth_spx", "spx"}, "ufm": False},
    "ib": {"network": "infiniband", "info_dir": "ib-info", "inventory": {"ib"}, "ufm": False},
    "ufm": {"network": "infiniband", "info_dir": "ufm-info", "inventory": {"server_ufm"}, "ufm": True},
    "nvl": {"network": "nvlink", "info_dir": "nvsw-info", "inventory": {"nvl"}, "ufm": False},
}
FORMULA_COLUMNS = ("RU", "Model")                     # the sheet looks them up by Host Name
# Compute by type: IB, NVLink, the separate SPX network and the UFMs. eth and eth_spx are inband/OOB switches
# (ethernet/monitor/README.md), named by their Cumulus template families: border*, oob*, oobofoob* -> OOB,
# tan* -> Inband (ztp/config/cumulus/template/03-templates-j2/).
COMPUTE_TYPES = {"ib", "nvl", "spx", "server_ufm"}
FABRIC_PREFIXES = (("OOB", ("border", "oob")), ("Inband", ("tan",)), ("Storage", ("storage",)))
PAGE_RED_WITHOUT_THRESHOLD_C = 85.0                  # generate-monitor-html.py temperature_status_class
UFM_HA_ROLES = {"主": "primary", "备": "standby", "离线": "offline", "在线": "online", "不在集群": "not in cluster"}


class InputError(Exception):
    """A usage or input problem; nothing is written (exit 2)."""


def say(message: str) -> None:
    print(f"[SWITCH-STATUS] {message}", flush=True)


def monitor_parser():
    """The monitor page's parsing functions, loaded privately; the page's own log stays the page's."""
    neighbours = str(PARSER.resolve().parent)  # run as a script, the generator imports its neighbours
    if neighbours not in sys.path:
        sys.path.insert(0, neighbours)
    spec = importlib.util.spec_from_file_location("switch_status_monitor_parser", PARSER)
    if spec is None or spec.loader is None:
        raise InputError(f"cannot load {PARSER}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.log = lambda message: None
    return module


def project_directory(explicit: Path | None) -> Path:
    if explicit is not None:
        directory = explicit.expanduser().resolve()
    else:
        if not PROJECT_ANCHOR.is_symlink():
            raise InputError(f"{PROJECT_ANCHOR} is not a setup link; run DAY0-Prepare/01-a-setup.py "
                             "or pass --project-dir")
        directory = PROJECT_ANCHOR.resolve().parent
    if not (directory / "99-output-monitor").is_dir():
        raise InputError(f"{directory / '99-output-monitor'} is missing; rerun DAY0-Prepare/01-a-setup.py")
    return directory


def read_inventory(path: Path) -> list[dict]:
    if not path.is_file():
        raise InputError(f"device list not found: {path}")
    with path.open(newline="", encoding="utf-8-sig", errors="replace") as stream:
        rows = []
        for row in csv.DictReader(stream):
            row = {str(key or "").strip().lower(): str(value or "").strip() for key, value in row.items()}
            if row.get("hostname") and not row["hostname"].startswith("#"):
                rows.append(row)
    return rows


def read_planned(path: Path) -> set[str]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        raise InputError(f"cannot read planned devices {path}: {exc.strerror or exc}") from None
    names = set()
    for line in lines:
        name = line.split("|", 1)[0].strip()
        if name and not name.startswith("#"):
            names.add(name.casefold())
    return names


def fabric(device_type: str, template: str, hostname: str) -> str:
    """The sheet's Fabric: Compute by type, else OOB / Inband / Storage by the start of a word of the template,
    then of the hostname; empty when nothing says."""
    if device_type.strip().casefold() in COMPUTE_TYPES:
        return "Compute"
    for value in (template, hostname):
        words = [word for word in re.split(r"[^a-z0-9]+", value.casefold()) if word]
        for name, prefixes in FABRIC_PREFIXES:
            if any(word.startswith(prefix) for word in words for prefix in prefixes):
                return name
    return ""


def _number(value) -> float | None:
    try:
        return None if value is None else float(value)
    except (TypeError, ValueError):
        return None


def temperature_issue(sensor: dict) -> dict | None:
    name = str(sensor.get("name") or "sensor")
    current = _number(sensor.get("current"))
    maximum, critical = _number(sensor.get("maximum")), _number(sensor.get("critical"))
    state = str(sensor.get("state") or "").strip()
    limits = "".join(f" {label} {value:.1f}C" for label, value in (("Max", maximum), ("Crit", critical))
                      if value is not None)
    reading = f"{current:.1f}C" if current is not None else "no reading"
    evidence = dict(kind="temperature", component=name, state=state, current_c=current,
                    maximum_c=maximum, critical_c=critical)
    if state and state.casefold() not in {"ok", "normal"}:
        return dict(evidence, priority="Critical", text=f"{name}: {reading} state={state}")
    if current is not None and critical is not None and current >= critical:
        return dict(evidence, priority="Critical", text=f"{name}: {reading} >= Crit {critical:.1f}C")
    if current is not None and maximum is not None and current >= maximum:
        return dict(evidence, priority="High", text=f"{name}: {reading} >= Max {maximum:.1f}C ({limits.strip()})")
    if (current is not None and maximum is None and critical is None
            and current >= PAGE_RED_WITHOUT_THRESHOLD_C):
        return dict(evidence, priority="High",
                    text=f"{name}: {reading} >= {PAGE_RED_WITHOUT_THRESHOLD_C:.1f}C (no device threshold)")
    return None


def ufm_health_issue(info: dict, *, hardware: bool) -> dict | None:
    """The HA state read on the VIP holder decides when it was collected (a standby's inactive ufm-enterprise is
    normal); otherwise this UFM's own ufm-enterprise service does. The page turns a PSU/FAN failure into a
    warning; that warning alone is not a second problem."""
    health = str(info.get("health") or "").casefold()
    summary = str(info.get("ha_summary") or "")
    if summary and summary != "未就绪":                   # apply_ufm_ha_status ran for this UFM
        if info.get("ha_ok"):
            return None
        state = health if health in ("error", "warning") else "warning"
        role, _, online = summary.partition(" · ")
        text = f"UFM HA {state}: {UFM_HA_ROLES.get(role.strip(), role.strip())}"
        if online.strip():
            text += ", " + online.strip().replace("在线", "online")
        return dict(kind="ha", component="ufm-ha", state=state, priority="High" if state == "error" else "Medium",
                    text=text, detail=str(info.get("ha_detail") or ""))
    if health == "error":
        return dict(kind="health", component="ufm-enterprise", state=health, priority="High",
                    text="UFM service ufm-enterprise: failed")
    if health == "warning" and not hardware:
        return dict(kind="health", component="ufm-enterprise", state=health, priority="Medium",
                    text="UFM service ufm-enterprise: not active")
    return None


def device_issues(info: dict, *, ufm: bool) -> list[dict]:
    issues = []
    hardware = False
    for component in info.get("inventory_components") or []:
        kind = component.get("type")
        state = str(component.get("state") or "")
        if kind in ("psu", "fan") and state != "ok":
            hardware = True
            issues.append(dict(kind=kind, component=component.get("name", ""), state=state, priority="High",
                               text=f'{component.get("name", kind.upper())}: state={state}'))
    for sensor in list(info.get("asic_temperature_details") or []) + list(info.get("psu_temperature_details") or []):
        issue = temperature_issue(sensor)
        if issue is not None:
            issues.append(issue)
    health = str(info.get("health") or "").casefold()
    if ufm:
        issue = ufm_health_issue(info, hardware=hardware)
        if issue is not None:
            issues.append(issue)
    elif health == "not ok":
        issues.append(dict(kind="health", component="system", state=health, priority="High",
                           text="System health: not ok"))
    return issues


def newest_archive(parser, directory: Path, kind: str) -> Path | None:
    if not directory.is_dir():
        return None
    if kind == "eth":
        return parser.find_latest_eth_tars(directory).get("production")
    return parser.find_latest_tar(directory)


def collected(parser, archive: Path, *, ufm: bool) -> tuple[list[dict], datetime | None]:
    when = parser.parse_archive_time_utc(archive)
    try:
        texts = parser.extract_info_files(archive)
        devices = [(parser.parse_ufm_info_file if ufm else parser.parse_info_file)(name, text, when)
                   for name, text in sorted(texts.items())]
        if ufm:
            for _reporter, content in sorted(parser.extract_info_files(archive, ".ha").items()):
                parser.apply_ufm_ha_status(devices, content)
    except (OSError, EOFError, tarfile.TarError) as exc:
        raise InputError(f"cannot read {archive}: {exc}") from None
    return devices, when


def find_device(parser, host: str, devices: list[dict], inventory_names: set[str]) -> dict | None:
    """This host's snapshot: its exact name first; a rack-prefixed name (host_matched) only when that name is
    not itself a device of the list and exactly one such snapshot exists."""
    for device in devices:
        if str(device.get("hostname") or "").casefold() == host.casefold():
            return device
    candidates = [device for device in devices
                  if str(device.get("hostname") or "").casefold() not in inventory_names
                  and parser.host_matched(host, [device["hostname"]])]
    return candidates[0] if len(candidates) == 1 else None


def previous_reports(path: Path, kind: str) -> list[tuple[dict, dict]]:
    """(row, device) pairs of the last document of this type; nothing when it is absent or unreadable."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(document, dict) or document.get("schema") != SCHEMA or document.get("device_type") != kind:
        return []
    rows, devices = document.get("rows"), document.get("devices")
    if not isinstance(rows, list) or not isinstance(devices, list) or len(rows) != len(devices):
        return []
    archive = (document.get("source") or {}).get("archive")
    pairs = []
    for row, device in zip(rows, devices):
        if isinstance(row, dict) and isinstance(device, dict) and isinstance(row.get("Host Name"), str):
            device = dict(device)
            device.setdefault("carried_from", archive)
            pairs.append((row, device))
    return pairs


def build(parser, kind: str, *, inventory: list[dict], planned: set[str] | None, archive: Path | None,
          zone, previous: list[tuple[dict, dict]] = ()) -> dict | None:
    spec = TYPES[kind]
    of_type = [row for row in inventory if row.get("type", "").casefold() in spec["inventory"]]
    expected = [row for row in of_type if planned is None or row["hostname"].casefold() in planned]
    if not expected:
        return None
    devices, when = collected(parser, archive, ufm=spec["ufm"]) if archive is not None else ([], None)
    moment = when or datetime.now(timezone.utc)
    submit_date = moment.astimezone(zone).strftime("%Y-%m-%d")
    batch = moment.astimezone(zone).strftime("%Y-%m-%d %H:%M")
    inventory_names = {row["hostname"].casefold() for row in inventory}
    reports, found = [], 0
    for entry in expected:
        host = entry["hostname"]
        info = find_device(parser, host, devices, inventory_names)
        if info is None:
            reason = ("this collection returned no data for any device of this type" if archive is None
                      else "no device information was returned")
            issues = [dict(kind="not_collected", component="", state="", priority="High",
                           text=f"Not collected: {reason}", collection=batch)]
        else:
            found += 1
            issues = device_issues(info, ufm=spec["ufm"])
        if not issues:
            continue
        priority = min((issue["priority"] for issue in issues), key=PRIORITY_ORDER.index)
        row = {column: "" for column in COLUMNS if column not in FORMULA_COLUMNS}
        row.update({
            "Submit Date": submit_date, "Submitor": SUBMITOR, "Host Name": host,
            "OOB IP": entry.get("eth0_ip", ""), "SN": (info or {}).get("serial", "") or "",
            "Fabric": fabric(entry.get("type", ""), entry.get("template", ""), host),
            "Priority": priority, "Issue Description": "; ".join(issue["text"] for issue in issues),
            "Status": STATUS,
        })
        reports.append((row, dict(hostname=host, type=entry.get("type", ""), collected=info is not None,
                                  model=(info or {}).get("model", "") or "", issues=issues)))
    # a run that planned only part of this type (cron.sh --type eth_spx) keeps the others' last rows
    expected_names = {row["hostname"].casefold() for row in expected}
    unplanned = {row["hostname"].casefold() for row in of_type} - expected_names
    carried = [(row, device) for row, device in previous if row["Host Name"].casefold() in unplanned]
    reports = sorted(reports + carried, key=lambda pair: pair[0]["Host Name"].casefold())
    return {
        "schema": SCHEMA, "sheet": SHEET, "device_type": kind, "network": spec["network"],
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": {
            "archive": archive.name if archive is not None else None,
            "collected_at_utc": when.strftime("%Y-%m-%dT%H:%M:%SZ") if when else None,
            "planned": planned is not None,
        },
        "expected": len(expected), "collected": found, "with_problems": len(reports), "carried": len(carried),
        "columns": list(COLUMNS), "formula_columns": list(FORMULA_COLUMNS),
        "rows": [row for row, _device in reports],
        "devices": [device for _row, device in reports],
    }


def write_status_document(document: dict, destination: Path) -> None:
    """Replace the status file whole (temporary file in the same directory, then os.replace)."""
    destination.parent.mkdir(parents=False, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(document, handle, ensure_ascii=False, indent=1)
            handle.write("\n")
        os.replace(temporary, destination)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--project-dir", type=Path, help="DAY0-Prepare/<project> (default: setup's monitor link)")
    parser.add_argument("--type", dest="types", action="append", choices=sorted(TYPES),
                        help="device type; repeat for several (default: all)")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--archive", type=Path, help="this collection's exact archive (one --type)")
    source.add_argument("--no-archive", action="store_true",
                        help="this collection returned nothing of the type (one --type, needs --planned)")
    parser.add_argument("--planned", type=Path, help="devices planned for this collection, one name per line")
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    types = args.types or list(TYPES)
    try:
        if (args.archive is not None or args.no_archive) and len(types) != 1:
            raise InputError("--archive and --no-archive belong to exactly one --type")
        if args.no_archive and args.planned is None:
            raise InputError("--no-archive needs --planned")
        if args.archive is not None and not args.archive.is_file():
            raise InputError(f"archive not found: {args.archive}")
        project = project_directory(args.project_dir)
        inventory = read_inventory(project / "02-devices_config.csv")
        planned = read_planned(args.planned) if args.planned is not None else None
        parser = monitor_parser()
        zone = parser.load_display_timezone(project / "01-global.yaml")
        documents = []
        for kind in types:
            spec = TYPES[kind]
            if args.archive is not None:
                archive = args.archive
            elif args.no_archive:
                archive = None
            else:
                archive = newest_archive(parser, project / "99-output-monitor" / spec["network"] / spec["info_dir"],
                                         kind)
                if archive is None:
                    say(f"{kind}: no {spec['info_dir']} archive; skipped")
                    continue
            relative = Path("99-output-monitor") / spec["network"] / OUTPUT_SUBDIR / f"{kind}-switch-status.json"
            previous = previous_reports(project / relative, kind) if planned is not None else []
            document = build(parser, kind, inventory=inventory, planned=planned, archive=archive, zone=zone,
                             previous=previous)
            if document is None:
                say(f"{kind}: no device expected; nothing written")
                continue
            documents.append((relative, document))
        for relative, document in documents:
            write_status_document(document, project / relative)
            carried = f" ({document['carried']} kept from earlier runs)" if document["carried"] else ""
            say(f"{document['device_type']}: {document['expected']} expected, {document['collected']} collected, "
                f"{document['with_problems']} with problems{carried} -> {relative}")
    except InputError as exc:
        say(f"ERROR: {exc}")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
