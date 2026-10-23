#!/usr/bin/env python3
"""Sync the newest collected IB and ETH link results into the project's online Issue Tracker.

REQ7 (owner 2026-10-23): ./cabletracker/ is a byte-for-byte copy of the reference CableTracker sync
engine and is never edited here. This script only turns our own collected data into the two source
formats the engine reads, then runs the engine once per domain:

  IB : newest <run-id>_<node>_ibdiagnet2.tgz from the UFM + the project's *-cvt.xlsx
       -> cabletracker/ibdiagnet/generate_report.py -> ib-cvt.json        (engine --source-type cvt)
  ETH: newest eth-info/<YYYYMMDD-HHMM>-<env>.tar.gz + the expected *-lldpq.dot / *-air.dot
       -> tools/lldp-analyze-tool/analyze_lldp.py --payload-json -> eth-lldpq.json
                                                                           (engine --source-type lldpq)

Project inputs stay in DAY0-Prepare/<project>/ and are read there; they are never linked into the
web-served tree: 03-issue-tracker.json (spreadsheet ID and sheet names) and cre.json (the Google
service account key; only its path is passed to the engine, its content is never logged). Results,
the state of the last successful sync and this script's log are kept in
<project>/99-output-p2p/issue-tracker/.

A domain whose newest input is unchanged since its last successful sync is skipped (use --force to
send it again); a domain without any input is skipped with a note.

    python3 monitor/issue-tracker/issue-tracker-sync.py [--project-dir DIR] [--only ib|eth]
                                                         [--convert-only] [--force]

Before every engine run, format_precheck.py checks read-only that the document already has exactly the
worksheets and header rows the engine enforces (owner 2026-10-23: the online Issue Tracker is a standard
format; a sync fills rows and never changes the format); any difference stops the run before a write.

Exit 0: every enabled domain synced, was unchanged, or had no input. Exit 1: a conversion, the
engine or Google failed for a domain. Exit 2: configuration or input error, or the document's format
differs from the engine's; nothing was sent. Exit 75: another sync of the same project is running.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable


BASE = Path(__file__).resolve().parent
HTTP_ROOT = BASE.parent.parent
ENGINE_DIR = BASE / "cabletracker"
RUNNER = ENGINE_DIR / "cabletracker_runner.py"
MAPPING = ENGINE_DIR / "mapping_v4.json"
GENERATE_REPORT = ENGINE_DIR / "ibdiagnet/generate_report.py"
FORMAT_PRECHECK = BASE / "format_precheck.py"
LLDP_ANALYZER = HTTP_ROOT / "tools/lldp-analyze-tool/analyze_lldp.py"
IB_POST_COLLECT = HTTP_ROOT / "infiniband/monitor/post-collect.py"
ETH_POST_COLLECT = HTTP_ROOT / "ethernet/monitor/post-collect.py"
# setup link -> DAY0-Prepare/<project>/01-global.yaml; its directory is the project
PROJECT_ANCHOR = HTTP_ROOT / "monitor/01-global.yaml"
if str(HTTP_ROOT) not in sys.path:
    sys.path.insert(0, str(HTTP_ROOT))
from tools.log_rotation import rotate  # noqa: E402

CONFIG_NAME = "03-issue-tracker.json"
CREDENTIALS_NAME = "cre.json"
OUTPUT_SUBDIR = "issue-tracker"
CONFIG_SCHEMA = "issue-tracker-sync-v1"
STATE_SCHEMA = "issue-tracker-sync-state-v1"
LOG_NAME = "issue-tracker-sync.log"
SPREADSHEET_ID = re.compile(r"[A-Za-z0-9_-]{20,128}")
IB_INPUT = re.compile(
    r"^(?P<stem>(?P<run_id>(?P<minute>\d{8}-\d{4})-(?P<env>prod|air)-[0-9a-f]{16})"
    r"_(?P<node>[A-Za-z0-9][A-Za-z0-9-]*))_ibdiagnet2\.tgz$"
)
ETH_INPUT = re.compile(r"^(?P<minute>\d{8}-\d{4})-(?P<env>prod|air)\.(?:tar\.gz|tgz)$")
STEP_TIMEOUT = 1800
ENGINE_TIMEOUT = 3600
DOMAINS = ("ib", "eth")
DOMAIN_KEYS = frozenset({"enabled", "environment", "import_sheet", "cabling_sheet", "include_warnings"})
DOMAIN_DEFAULTS = {
    # the standard Issue Tracker template (owner 2026-10-23) imports into these two worksheets
    "ib": {"import_sheet": "CVT_Import_GS", "cabling_sheet": "IB Cabling"},
    "eth": {"import_sheet": "LLDPQ_Import_GS", "cabling_sheet": "ETH Cabling"},
}
# analyze_lldp statuses -> LLDPQ schema-v1 status and the A-side report text. The engine tags a
# report containing "wrong device" or "port mismatch" as Mis-wiring and one containing "link down"
# as Link Down; warning texts deliberately contain none of these markers.
SUCCESS_STATUSES = frozenset({"CONFIRMED_BOTH_SIDE", "CONFIRMED_SW_SIDE"})
LLDPQ_STATUS = {
    "CONFIRMED_BOTH_SIDE": ("SUCCESS", ""),
    "CONFIRMED_SW_SIDE": ("SUCCESS", ""),
    "DOWN": ("FAILED", "Link Down"),
    "MISSING_INTERFACE": ("FAILED", "Interface missing"),
    "SW_LLDP_PRESENT": ("WARNING", "LLDP neighbor not confirmed"),
    "NO_LLDP": ("WARNING", "No LLDP neighbor"),
    "MISSING_DEVICE": ("NO INFO", "Switch not collected"),
}
WRONG_PEER_SEGMENT = re.compile(
    r"(?P<local>\S+) sees (?P<host>[^:\s]*):(?P<port>\S*), expected (?P<device>[^:\s]+):(?P<interface>\S+)"
)


class SyncError(Exception):
    """A configuration or input problem; nothing has been sent (exit 2)."""


class StepError(Exception):
    """A conversion or engine run failed for one domain (exit 1)."""


@dataclass(frozen=True)
class Domain:
    name: str
    enabled: bool
    environment: str
    import_sheet: str
    cabling_sheet: str
    include_warnings: bool


@dataclass(frozen=True)
class Config:
    spreadsheet_id: str
    timezone: str
    domains: dict


class Log:
    """Timestamped lines to stdout and, once the output directory is known, to its own log."""

    def __init__(self) -> None:
        self.path: Path | None = None

    def attach(self, path: Path) -> None:
        self.path = path
        try:
            rotate(path)
        except OSError as exc:
            self("WARNING: log rotation failed: %s" % (exc.strerror or exc))

    def __call__(self, message: str) -> None:
        timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
        line = f"[{timestamp}] [ISSUE-TRACKER-SYNC] {message}"
        print(line, flush=True)
        if self.path is not None:
            try:
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
            except OSError:
                pass


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SyncError(f"{label} must be a non-empty string")
    return value.strip()


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise SyncError(f"{label} must be true or false")
    return value


def load_config(path: Path) -> Config:
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise SyncError(f"project configuration not found: {path} (see monitor/issue-tracker/README.md)") from None
    except OSError as exc:
        raise SyncError(f"cannot read {path}: {exc.strerror or exc}") from None
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise SyncError(f"{path.name} is not valid JSON: {exc}") from None
    if not isinstance(data, dict) or data.get("schema") != CONFIG_SCHEMA:
        raise SyncError(f'{path.name} must be a JSON object with "schema": "{CONFIG_SCHEMA}"')
    unknown = sorted(set(data) - {"schema", "spreadsheet_id", "timezone", *DOMAINS})
    if unknown:
        raise SyncError(f"{path.name} has unknown keys: {', '.join(unknown)}")
    spreadsheet_id = data.get("spreadsheet_id")
    if not isinstance(spreadsheet_id, str) or not SPREADSHEET_ID.fullmatch(spreadsheet_id):
        raise SyncError(f"{path.name}: spreadsheet_id must be the ID part of the Google Sheets URL")
    timezone = _string(data.get("timezone", "Asia/Shanghai"), f"{path.name}: timezone")
    domains = {}
    for name in DOMAINS:
        section = data.get(name, {})
        if not isinstance(section, dict):
            raise SyncError(f"{path.name}: {name} must be an object")
        unknown = sorted(set(section) - DOMAIN_KEYS)
        if unknown:
            raise SyncError(f"{path.name}: {name} has unknown keys: {', '.join(unknown)}")
        environment = section.get("environment", "prod")
        if environment not in ("prod", "air"):
            raise SyncError(f"{path.name}: {name}.environment must be prod or air")
        domains[name] = Domain(
            name=name,
            enabled=_boolean(section.get("enabled", True), f"{path.name}: {name}.enabled"),
            environment=environment,
            import_sheet=_string(section.get("import_sheet", DOMAIN_DEFAULTS[name]["import_sheet"]),
                                 f"{path.name}: {name}.import_sheet"),
            cabling_sheet=_string(section.get("cabling_sheet", DOMAIN_DEFAULTS[name]["cabling_sheet"]),
                                  f"{path.name}: {name}.cabling_sheet"),
            include_warnings=_boolean(section.get("include_warnings", False),
                                      f"{path.name}: {name}.include_warnings"),
        )
    # the engine keeps one import worksheet per source; two sources in one sheet would overwrite
    if domains["ib"].import_sheet.casefold() == domains["eth"].import_sheet.casefold():
        raise SyncError(f"{path.name}: ib and eth must import into different sheets")
    return Config(spreadsheet_id, timezone, domains)


def check_credentials(path: Path) -> None:
    """Shape and permission checks only; no value of the key is ever printed."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise SyncError(f"service account key not found: {path} (put cre.json in the project directory)") from None
    except OSError as exc:
        raise SyncError(f"cannot inspect {path}: {exc.strerror or exc}") from None
    if not stat.S_ISREG(info.st_mode):
        raise SyncError(f"{path} must be a regular file (not a link or directory)")
    if info.st_mode & 0o077:
        raise SyncError(f"{path} is readable by group or others; run: chmod 600 {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise SyncError(f"{path} is not a readable JSON key file") from None
    if (not isinstance(data, dict) or data.get("type") != "service_account"
            or not all(isinstance(data.get(key), str) and data.get(key)
                       for key in ("client_email", "private_key", "token_uri"))):
        raise SyncError(f"{path} is not a Google service account key "
                        "(type service_account with client_email, private_key and token_uri)")


def project_directory(explicit: Path | None) -> Path:
    if explicit is not None:
        directory = explicit.expanduser().resolve()
    else:
        if not PROJECT_ANCHOR.is_symlink():
            raise SyncError(f"{PROJECT_ANCHOR} is not a setup link; run DAY0-Prepare/01-a-setup.py "
                            "or pass --project-dir")
        directory = PROJECT_ANCHOR.resolve().parent
    if not directory.is_dir():
        raise SyncError(f"project directory does not exist: {directory}")
    return directory


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SyncError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _not_failed(done: Path) -> bool:
    """cron.sh publishes <...>_ibdiagnet2.tgz under its final name only after the UFM's completion
    record said result=ok and the sha256/size matched; it keeps that record beside the data as .done
    (runs collected before 2026-10-22 have none). A record that says anything but ok excludes it."""
    try:
        lines = done.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return True
    except OSError:
        return False
    fields = dict(line.split("=", 1) for line in lines if "=" in line)
    return fields.get("result", "").strip() == "ok"


def newest_ib_input(project: Path, environment: str) -> Path | None:
    directory = project / "99-output-monitor/infiniband/ufm-ibdiagnet"
    candidates = []
    if directory.is_dir():
        for path in directory.iterdir():
            named = IB_INPUT.fullmatch(path.name)
            if not named or named.group("env") != environment or not path.is_file():
                continue
            if not _not_failed(path.with_name(path.name[:-len(".tgz")] + ".done")):
                continue
            candidates.append((named.group("minute"), path.stat().st_mtime_ns, path.name, path))
    return max(candidates)[3] if candidates else None


def newest_eth_input(project: Path, environment: str) -> Path | None:
    directory = project / "99-output-monitor/ethernet/eth-info"
    candidates = []
    if directory.is_dir():
        for path in directory.iterdir():
            named = ETH_INPUT.fullmatch(path.name)
            if named and named.group("env") == environment and path.is_file():
                candidates.append((named.group("minute"), path.stat().st_mtime_ns, path.name, path))
    return max(candidates)[3] if candidates else None


def collected_epoch(archive: Path) -> float:
    """The collection minute in the archive name, as local time on this server."""
    minute = re.match(r"(\d{8}-\d{4})", archive.name)
    if minute is None:
        raise SyncError(f"cannot read the collection time from {archive.name}")
    return datetime.strptime(minute.group(1), "%Y%m%d-%H%M").astimezone().timestamp()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _miswire_kind(detail: str) -> str:
    """'wrong device' when an end sees another device, else 'port mismatch' (analyze_lldp names the
    ends that disagree; an end whose host matched only through an alias reads as a wrong device)."""
    for segment in WRONG_PEER_SEGMENT.finditer(detail or ""):
        if segment.group("host").casefold() != segment.group("device").casefold():
            return "wrong device"
    return "port mismatch" if WRONG_PEER_SEGMENT.search(detail or "") else "wrong device"


def _text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def lldpq_row(record: dict) -> dict:
    status = record.get("status")
    detail = str(record.get("detail") or "").strip()
    if status == "WRONG_PEER":
        lldpq_status, health = "FAILED", f"{_miswire_kind(detail)}: {detail}"
    elif status in LLDPQ_STATUS:
        lldpq_status, label = LLDPQ_STATUS[status]
        health = "" if status in SUCCESS_STATUSES else f"{label}: {detail}"
    else:
        raise StepError(f"unknown LLDP link status {status!r}")
    observed = record.get("observation_a") or {}
    for key in ("device_a", "interface_a", "device_b", "interface_b"):
        if not _text(record.get(key)):
            raise StepError(f"LLDP link result without {key}")
    return {
        "status": lldpq_status,
        "local_device": _text(record["device_a"]),
        "local_port": _text(record["interface_a"]),
        "expected_device": _text(record["device_b"]),
        "expected_port": _text(record["interface_b"]),
        "actual_device": _text(observed.get("remote_host")),
        "actual_port": _text(observed.get("remote_port")),
        "port_status": _text(observed.get("oper")),
        "connection_health": health,
        "lldp_status": status,
    }


def lldpq_document(payload: dict, collected_at: float) -> dict:
    """Project analyze_lldp's payload onto the engine's LLDPQ schema v1: one row per P2P link,
    the Ethernet switch end as local (A), the planned peer as expected (Z)."""
    records = []
    for key in ("matching_links", "miswired_links", "missing_links"):
        group = payload.get(key)
        if not isinstance(group, list):
            raise StepError(f"LLDP analysis result has no {key} list")
        records.extend(group)
    rows = sorted((lldpq_row(record) for record in records),
                  key=lambda row: (row["local_device"].casefold(), row["local_port"],
                                   row["expected_device"].casefold(), row["expected_port"]))
    identities = [(row["local_device"].casefold(), row["local_port"],
                   row["expected_device"].casefold(), row["expected_port"]) for row in rows]
    if len(set(identities)) != len(identities):
        raise StepError("LLDP analysis result repeats a planned link")
    return {
        "schema_version": 1,
        "domain": "lldp_results",
        "collection_status": "complete",
        "generated_at": collected_at,
        "row_count": len(rows),
        "rows": rows,
    }


def _write_json(document: object, destination: Path) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(document, handle, ensure_ascii=False, indent=1)
            handle.write("\n")
        os.replace(temporary, destination)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def _run(command: list, log: Log, timeout: int, cwd: Path | None = None, echo: bool = True) -> int:
    try:
        completed = subprocess.run(command, cwd=cwd, stdin=subprocess.DEVNULL, capture_output=True,
                                   text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise StepError(f"{Path(command[1]).name} did not finish within {timeout} s") from None
    except OSError as exc:
        raise StepError(f"cannot start {command[0]}: {exc.strerror or exc}") from None
    if echo or completed.returncode != 0:
        for stream, output in (("stdout", completed.stdout), ("stderr", completed.stderr)):
            for line in (output or "").splitlines():
                log(f"  [{Path(command[1]).name} {stream}] {line}")
    return completed.returncode


def convert_ib(tgz: Path, cvt: Path, destination: Path, log: Log) -> None:
    summary = destination.with_name(destination.name[:-len(".json")] + ".summary.json")
    command = [sys.executable, str(GENERATE_REPORT), "--p2p", str(cvt), "--ibdiagnet-tar", str(tgz),
               "--output", str(destination), "--summary-output", str(summary), "--force"]
    log(f"IB: converting {tgz.name} with {cvt.name}")
    # its summary JSON (stderr) is also written to the .summary.json; echoed only on failure
    returncode = _run(command, log, STEP_TIMEOUT, echo=False)
    if returncode != 0 or not destination.is_file():
        raise StepError(f"generate_report.py exited {returncode}")
    try:
        counts = json.loads(summary.read_text(encoding="utf-8"))
        log("IB: %s records (pass %s, fail %s, no report %s)" % (
            counts.get("records"), counts.get("pass"), counts.get("fail"), counts.get("no_report")))
    except (OSError, ValueError):
        log("IB: converted (no summary)")


def convert_eth(archive: Path, dot: Path, destination: Path, work: Path, log: Log) -> None:
    payload_path = work / "eth-payload.json"
    command = [sys.executable, str(LLDP_ANALYZER), "--archive", str(archive), "--dot", str(dot),
               "--output-dir", str(work), "--payload-json", str(payload_path)]
    log(f"ETH: analyzing {archive.name} against {dot.name}")
    returncode = _run(command, log, STEP_TIMEOUT)
    # analyze_lldp exits 1 when the report was written and shows mismatches
    if returncode not in (0, 1) or not payload_path.is_file():
        raise StepError(f"analyze_lldp.py exited {returncode}")
    try:
        payload = json.loads(payload_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise StepError(f"unreadable LLDP analysis result: {exc}") from None
    document = lldpq_document(payload, collected_epoch(archive))
    _write_json(document, destination)
    counts: dict = {}
    for row in document["rows"]:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    log("ETH: %d rows (%s)" % (document["row_count"],
                               ", ".join(f"{key} {counts[key]}" for key in sorted(counts)) or "none"))


def engine_command(python: str, config: Config, domain: Domain, source: Path,
                   credentials: Path) -> list:
    command = [python, str(RUNNER),
               "--credentials", str(credentials),
               "--spreadsheet-id", config.spreadsheet_id,
               "--timezone", config.timezone,
               "--mapping-config", str(MAPPING),
               "--source-type", "cvt" if domain.name == "ib" else "lldpq",
               "--source-transport", "file",
               "--source-file", str(source),
               "--cvt-sheet", domain.import_sheet,
               f"--{domain.name}-cabling-sheet", domain.cabling_sheet,
               "--operation", "both",
               "--max-runs", "1"]
    if domain.include_warnings:
        command += ["--include-warnings", "true"]
    return command


def format_gate(python: str, command: list, credentials: Path, work: Path, log: Log) -> None:
    """The online Issue Tracker is a standard format: the engine may only fill rows. Read-only check
    that this exact engine command would not create a worksheet or rewrite any header row."""
    command_file = work / "engine-command.json"
    command_file.write_text(json.dumps(command[2:]), encoding="utf-8")
    try:
        completed = subprocess.run(
            [python, str(FORMAT_PRECHECK), "--credentials", str(credentials),
             "--engine-command-json", str(command_file)],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=STEP_TIMEOUT, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise StepError(f"format pre-check could not run: {exc}") from None
    lines = (completed.stdout or "").strip().splitlines()
    try:
        report = json.loads(lines[-1]) if lines else {}
    except ValueError:
        report = {}
    if completed.returncode == 3:
        for change in report.get("changes", []):
            log(f"  format change refused: {change}")
        raise SyncError("the online document does not match the engine's format; nothing was written "
                        "(fix the document or the sheet names in 03-issue-tracker.json)")
    if completed.returncode != 0 or report.get("ok") is not True:
        for line in (completed.stderr or "").splitlines()[-5:]:
            log(f"  [format_precheck.py stderr] {line}")
        raise StepError(f"format pre-check failed: {report.get('error') or completed.returncode}")
    log("format pre-check: document matches the engine; only rows will be written")


def read_state(path: Path) -> dict:
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return state if isinstance(state, dict) and state.get("schema") == STATE_SCHEMA else {}


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=("Convert the newest collected IB (UFM ibdiagnet) and ETH (LLDP) results and sync "
                     "them into the project's online Issue Tracker with the CableTracker engine."),
    )
    parser.add_argument("--project-dir", type=Path,
                        help="DAY0-Prepare/<project> (default: the project linked by setup)")
    parser.add_argument("--only", choices=DOMAINS, help="handle only this domain")
    parser.add_argument("--convert-only", action="store_true",
                        help="write ib-cvt.json / eth-lldpq.json but do not contact Google")
    parser.add_argument("--force", action="store_true",
                        help="sync even when the newest input was already synced")
    parser.add_argument("--engine-python", default=sys.executable,
                        help="interpreter with the engine's Google libraries (default: this one)")
    return parser.parse_args(argv)


def handle_domain(domain: Domain, *, project: Path, output: Path, config: Config, credentials: Path,
                  state: dict, args: argparse.Namespace, log: Log) -> str:
    """Return 'synced', 'converted', 'unchanged' or 'no-input'; raise StepError on failure."""
    p2p = project / "99-output-p2p"
    if domain.name == "ib":
        source_input = newest_ib_input(project, domain.environment)
        if source_input is None:
            log(f"IB: no {domain.environment} ibdiagnet2.tgz in 99-output-monitor/infiniband/ufm-ibdiagnet")
            return "no-input"
        try:
            planned = _load_module(IB_POST_COLLECT, "ib_post_collect").select_cvt(p2p)
        except ValueError as exc:
            raise SyncError(f"IB: {exc}") from None
        destination = output / "ib-cvt.json"
    else:
        source_input = newest_eth_input(project, domain.environment)
        if source_input is None:
            log(f"ETH: no {domain.environment} archive in 99-output-monitor/ethernet/eth-info")
            return "no-input"
        try:
            planned = _load_module(ETH_POST_COLLECT, "eth_post_collect").select_expected_dot(
                p2p, domain.environment)
        except ValueError as exc:
            raise SyncError(f"ETH: {exc}") from None
        destination = output / "eth-lldpq.json"
    inputs = {"input": {"name": source_input.name, "sha256": sha256(source_input)},
              "planned": {"name": planned.name, "sha256": sha256(planned)}}
    target = {"spreadsheet_id": config.spreadsheet_id, "import_sheet": domain.import_sheet,
              "cabling_sheet": domain.cabling_sheet, "include_warnings": domain.include_warnings}
    previous = state.get(domain.name) or {}
    if (not args.force and not args.convert_only and previous.get("inputs") == inputs
            and previous.get("target") == target):
        log(f"{domain.name.upper()}: {source_input.name} already synced at {previous.get('synced_at')}; skipped")
        return "unchanged"
    with tempfile.TemporaryDirectory(prefix=".work-", dir=output) as work:
        if domain.name == "ib":
            convert_ib(source_input, planned, destination, log)
        else:
            convert_eth(source_input, planned, destination, Path(work), log)
    if args.convert_only:
        log(f"{domain.name.upper()}: wrote {destination.name} (no sync: --convert-only)")
        return "converted"
    log(f"{domain.name.upper()}: syncing into '{domain.import_sheet}' and '{domain.cabling_sheet}'")
    command = engine_command(args.engine_python, config, domain, destination, credentials)
    with tempfile.TemporaryDirectory(prefix=".engine-", dir=output) as engine_cwd:
        format_gate(args.engine_python, command, credentials, Path(engine_cwd), log)
        returncode = _run(command, log, ENGINE_TIMEOUT, cwd=Path(engine_cwd))
    if returncode != 0:
        raise StepError(f"cabletracker_runner.py exited {returncode}")
    state[domain.name] = {"inputs": inputs, "target": target,
                          "synced_at": datetime.now().astimezone().isoformat(timespec="seconds")}
    return "synced"


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    log = Log()
    try:
        project = project_directory(args.project_dir)
        config = load_config(project / CONFIG_NAME)
        credentials = project / CREDENTIALS_NAME
        if not args.convert_only:
            check_credentials(credentials)
        if not (project / "99-output-p2p").is_dir():
            raise SyncError(f"{project / '99-output-p2p'} is missing; rerun DAY0-Prepare/01-a-setup.py")
        output = project / "99-output-p2p" / OUTPUT_SUBDIR
        output.mkdir(mode=0o750, exist_ok=True)
    except SyncError as exc:
        log(f"ERROR: {exc}")
        return 2
    log.attach(output / LOG_NAME)
    lock = (output / ".sync.lock").open("a")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        log("another sync of this project is running; nothing done")
        lock.close()
        return 75
    try:
        state_path = output / "state.json"
        state = read_state(state_path)
        selected = [config.domains[name] for name in DOMAINS
                    if (args.only in (None, name)) and config.domains[name].enabled]
        if not selected:
            log("no enabled domain selected; nothing to do")
            return 0
        failed = False
        for domain in selected:
            try:
                outcome = handle_domain(domain, project=project, output=output, config=config,
                                        credentials=credentials, state=state, args=args, log=log)
            except SyncError as exc:
                log(f"ERROR: {exc}")
                return 2
            except StepError as exc:
                log(f"ERROR: {domain.name.upper()}: {exc}")
                failed = True
                continue
            if outcome == "no-input" and args.only == domain.name:
                log(f"ERROR: {domain.name.upper()}: no input to sync")
                return 2
            if outcome == "synced":
                _write_json({"schema": STATE_SCHEMA, **{k: v for k, v in state.items() if k in DOMAINS}},
                            state_path)
                log(f"{domain.name.upper()}: sync complete")
        return 1 if failed else 0
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        lock.close()


if __name__ == "__main__":
    raise SystemExit(main())
